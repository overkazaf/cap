// Package proto implements a schema-less Protocol Buffers decoder.
//
// Protobuf wire data carries no field names or types of its own — those
// live only in the .proto file used to generate the encoder/decoder. When
// intercepting traffic as a MITM proxy we usually don't have that .proto
// file. This package instead walks the raw wire format (tag/length/value
// triples) and reports the structure it finds: field numbers, wire types,
// and best-effort value interpretations (including recursing into
// length-delimited fields that look like embedded messages). The result is
// necessarily a heuristic rather than a faithful decode, mirroring what
// tools like Wireshark's "protobuf (no schema)" dissector or Charles'
// Protobuf viewer show.
package proto

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Field is one decoded protobuf wire-format field. For wire type 2
// (length-delimited) entries that successfully parse as a nested message,
// Fields holds the recursively decoded contents and TypeName is
// "embedded"; otherwise Value holds a string or []byte and TypeName is
// "string" or "bytes" respectively.
type Field struct {
	Number   int         `json:"number"`
	WireType int         `json:"wire_type"` // 0=varint, 1=64bit, 2=length-delimited, 5=32bit
	TypeName string      `json:"type"`      // "varint", "fixed64", "bytes", "string", "fixed32", "embedded"
	Value    interface{} `json:"value,omitempty"`
	Fields   []Field     `json:"fields,omitempty"` // for embedded messages
}

// Wire types, per the protobuf encoding spec. 3 (start group) and 4 (end
// group) are part of the deprecated "groups" feature and are treated as
// invalid here, same as any other unrecognized wire type.
const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5
)

// maxVarintBytes bounds how many bytes a single varint may span. A
// well-formed 64-bit varint never needs more than 10 bytes (7 payload bits
// per byte); anything longer is malformed input, not a slow-but-valid one.
const maxVarintBytes = 10

// IsProtobuf reports whether data looks like schema-less protobuf wire
// data. It is a heuristic: data that parses as valid JSON, or that decodes
// as plausible human-readable UTF-8 text, is rejected outright; otherwise
// data is accepted if it fully parses as a well-formed sequence of
// protobuf fields with at least one field.
//
// Callers that also have an HTTP Content-Type header available should
// check it for "protobuf", "grpc", or "x-protobuf" themselves — IsProtobuf
// only ever looks at the body bytes.
func IsProtobuf(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	if json.Valid(data) {
		return false
	}

	if looksLikeText(data) {
		return false
	}

	fields, err := Decode(data)
	if err != nil || len(fields) == 0 {
		return false
	}

	return true
}

// looksLikeText reports whether data is plausibly human-readable text
// (and therefore not binary protobuf), based on it being valid UTF-8 with
// an overwhelming majority of printable runes.
func looksLikeText(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}

	total := 0
	printable := 0
	for _, r := range string(data) {
		total++
		if r == '\n' || r == '\r' || r == '\t' || unicode.IsPrint(r) {
			printable++
		}
	}
	if total == 0 {
		return false
	}
	return float64(printable)/float64(total) > 0.95
}

// Decode parses data as a flat sequence of protobuf wire-format fields.
// Length-delimited (wire type 2) fields are, best-effort, further
// interpreted: first as an embedded message (if the payload itself fully
// parses as a well-formed field sequence), then as a UTF-8 string, and
// finally as raw bytes.
//
// Decode returns an error if data is not a well-formed sequence of
// tag/value pairs (truncated varint, truncated fixed-width value, a
// length-delimited field whose declared length runs past the end of data,
// or an unsupported wire type).
func Decode(data []byte) ([]Field, error) {
	var fields []Field

	i := 0
	for i < len(data) {
		tag, n := decodeVarint(data[i:])
		if n <= 0 {
			return nil, fmt.Errorf("proto: invalid tag varint at offset %d", i)
		}
		i += n

		fieldNumber := int(tag >> 3)
		wireType := int(tag & 0x7)
		if fieldNumber == 0 {
			return nil, fmt.Errorf("proto: invalid field number 0 at offset %d", i)
		}

		switch wireType {
		case wireVarint:
			val, n := decodeVarint(data[i:])
			if n <= 0 {
				return nil, fmt.Errorf("proto: truncated varint value for field %d", fieldNumber)
			}
			i += n
			fields = append(fields, Field{
				Number:   fieldNumber,
				WireType: wireType,
				TypeName: "varint",
				Value:    val,
			})

		case wireFixed64:
			if i+8 > len(data) {
				return nil, fmt.Errorf("proto: truncated fixed64 value for field %d", fieldNumber)
			}
			val := binary.LittleEndian.Uint64(data[i : i+8])
			i += 8
			fields = append(fields, Field{
				Number:   fieldNumber,
				WireType: wireType,
				TypeName: "fixed64",
				Value:    val,
			})

		case wireBytes:
			length, n := decodeVarint(data[i:])
			if n <= 0 {
				return nil, fmt.Errorf("proto: invalid length varint for field %d", fieldNumber)
			}
			i += n

			remaining := uint64(len(data) - i)
			if length > remaining {
				return nil, fmt.Errorf("proto: length-delimited field %d declares length %d, only %d bytes remain", fieldNumber, length, remaining)
			}
			payload := data[i : i+int(length)]
			i += int(length)

			fields = append(fields, decodeLengthDelimited(fieldNumber, wireType, payload))

		case wireFixed32:
			if i+4 > len(data) {
				return nil, fmt.Errorf("proto: truncated fixed32 value for field %d", fieldNumber)
			}
			val := binary.LittleEndian.Uint32(data[i : i+4])
			i += 4
			fields = append(fields, Field{
				Number:   fieldNumber,
				WireType: wireType,
				TypeName: "fixed32",
				Value:    val,
			})

		default:
			return nil, fmt.Errorf("proto: unsupported wire type %d for field %d", wireType, fieldNumber)
		}
	}

	return fields, nil
}

// decodeLengthDelimited interprets the payload of a wire type 2 field:
// embedded message first, then UTF-8 string, then raw bytes.
func decodeLengthDelimited(fieldNumber, wireType int, payload []byte) Field {
	if embedded, err := Decode(payload); err == nil && len(embedded) > 0 {
		return Field{
			Number:   fieldNumber,
			WireType: wireType,
			TypeName: "embedded",
			Fields:   embedded,
		}
	}

	if utf8.Valid(payload) {
		return Field{
			Number:   fieldNumber,
			WireType: wireType,
			TypeName: "string",
			Value:    string(payload),
		}
	}

	return Field{
		Number:   fieldNumber,
		WireType: wireType,
		TypeName: "bytes",
		Value:    payload,
	}
}

// decodeVarint reads a base-128 varint from the start of buf, returning
// its value and the number of bytes consumed. It returns (0, -1) if buf
// ends before a terminating byte (MSB clear) is found, or if the varint
// would need more than maxVarintBytes bytes (malformed input).
func decodeVarint(buf []byte) (uint64, int) {
	var result uint64
	var shift uint

	limit := len(buf)
	if limit > maxVarintBytes {
		limit = maxVarintBytes
	}

	for idx := 0; idx < limit; idx++ {
		b := buf[idx]
		result |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return result, idx + 1
		}
		shift += 7
	}

	return 0, -1
}

// FormatFields renders decoded fields as human-readable indented text,
// recursing into embedded messages with two additional spaces of indent
// per level. Each line (including the last) ends with "\n".
func FormatFields(fields []Field, indent string) string {
	var sb strings.Builder

	for _, f := range fields {
		switch f.TypeName {
		case "embedded":
			fmt.Fprintf(&sb, "%sfield %d (embedded):\n", indent, f.Number)
			sb.WriteString(FormatFields(f.Fields, indent+"  "))
		case "string":
			fmt.Fprintf(&sb, "%sfield %d (string): %q\n", indent, f.Number, f.Value)
		case "bytes":
			b, _ := f.Value.([]byte)
			fmt.Fprintf(&sb, "%sfield %d (bytes): %x\n", indent, f.Number, b)
		default:
			fmt.Fprintf(&sb, "%sfield %d (%s): %v\n", indent, f.Number, f.TypeName, f.Value)
		}
	}

	return sb.String()
}

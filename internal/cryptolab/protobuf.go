package cryptolab

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"unicode"
	"unicode/utf8"
)

const (
	protoWireVarint  = 0
	protoWireFixed64 = 1
	protoWireBytes   = 2
	protoWireFixed32 = 5

	maxProtoDepth       = 16
	maxProtoFields      = 4096
	maxProtoFieldNumber = (1 << 29) - 1
	maxProtoVarintBytes = 10
)

// DecodeProtobufRaw parses arbitrary binary Protobuf wire data without a .proto
// schema, recursively decoding length-delimited embedded messages up to depth 16
// and exposing multiple scalar interpretations (uint64/int64/sint64, fixed64/double,
// fixed32/float, UTF-8 string, raw hex).
func DecodeProtobufRaw(data []byte) (*ProtoMessageNode, error) {
	totalFields := 0
	node, _, err := decodeProtoMessage(data, 0, &totalFields)
	return node, err
}

func decodeProtoMessage(data []byte, depth int, totalFields *int) (node *ProtoMessageNode, fieldCapHit bool, err error) {
	node = &ProtoMessageNode{
		Fields:  []ProtoFieldNode{},
		ByteLen: len(data),
	}

	i := 0
	for i < len(data) {
		if *totalFields >= maxProtoFields {
			node.Truncated = true
			node.Warnings = append(node.Warnings, fmt.Sprintf("field count cap reached (%d fields)", maxProtoFields))
			return node, true, nil
		}

		tag, n := decodeProtoVarint(data[i:])
		if n <= 0 {
			return nil, false, fmt.Errorf("protobuf: invalid tag varint at offset %d", i)
		}
		i += n

		fieldNum := tag >> 3
		wireType := int(tag & 0x7)
		if fieldNum == 0 || fieldNum > maxProtoFieldNumber {
			return nil, false, fmt.Errorf("protobuf: invalid field number %d at offset %d", fieldNum, i)
		}

		*totalFields++
		switch wireType {
		case protoWireVarint:
			u, vn := decodeProtoVarint(data[i:])
			if vn <= 0 {
				return nil, false, fmt.Errorf("protobuf: truncated varint for field %d at offset %d", fieldNum, i)
			}
			raw := data[i : i+vn]
			i += vn
			uVal := u
			iVal := int64(u)
			sVal := zigzagDecode64(u)
			node.Fields = append(node.Fields, ProtoFieldNode{
				FieldNumber:  int(fieldNum),
				WireType:     protoWireVarint,
				WireTypeName: "varint",
				Kind:         "varint",
				VarintU64:    &uVal,
				VarintI64:    &iVal,
				VarintS64:    &sVal,
				RawHex:       hex.EncodeToString(raw),
			})

		case protoWireFixed64:
			if i+8 > len(data) {
				return nil, false, fmt.Errorf("protobuf: truncated fixed64 for field %d at offset %d", fieldNum, i)
			}
			raw := data[i : i+8]
			i += 8
			u := binary.LittleEndian.Uint64(raw)
			s := int64(u)
			d := math.Float64frombits(u)
			fn := ProtoFieldNode{
				FieldNumber:  int(fieldNum),
				WireType:     protoWireFixed64,
				WireTypeName: "fixed64",
				Kind:         "fixed64",
				Fixed64U:     &u,
				Fixed64S:     &s,
				RawHex:       hex.EncodeToString(raw),
			}
			if !math.IsNaN(d) && !math.IsInf(d, 0) {
				fn.DoubleVal = &d
			}
			node.Fields = append(node.Fields, fn)

		case protoWireBytes:
			length, ln := decodeProtoVarint(data[i:])
			if ln <= 0 {
				return nil, false, fmt.Errorf("protobuf: invalid length varint for field %d at offset %d", fieldNum, i)
			}
			i += ln
			remaining := uint64(len(data) - i)
			if length > remaining {
				return nil, false, fmt.Errorf("protobuf: field %d declares length %d, only %d bytes remain", fieldNum, length, remaining)
			}
			payload := data[i : i+int(length)]
			i += int(length)

			fn, subTruncated, subWarnings := decodeProtoLengthDelimited(int(fieldNum), payload, depth, totalFields)
			if subTruncated {
				node.Truncated = true
				node.Warnings = append(node.Warnings, subWarnings...)
			}
			node.Fields = append(node.Fields, fn)

		case protoWireFixed32:
			if i+4 > len(data) {
				return nil, false, fmt.Errorf("protobuf: truncated fixed32 for field %d at offset %d", fieldNum, i)
			}
			raw := data[i : i+4]
			i += 4
			u := binary.LittleEndian.Uint32(raw)
			s := int32(u)
			f := float64(math.Float32frombits(u))
			fn := ProtoFieldNode{
				FieldNumber:  int(fieldNum),
				WireType:     protoWireFixed32,
				WireTypeName: "fixed32",
				Kind:         "fixed32",
				Fixed32U:     &u,
				Fixed32S:     &s,
				RawHex:       hex.EncodeToString(raw),
			}
			if !math.IsNaN(f) && !math.IsInf(f, 0) {
				fn.FloatVal = &f
			}
			node.Fields = append(node.Fields, fn)

		default:
			return nil, false, fmt.Errorf("protobuf: unsupported wire type %d for field %d at offset %d", wireType, fieldNum, i)
		}
	}

	return node, false, nil
}

func decodeProtoLengthDelimited(fieldNum int, payload []byte, depth int, totalFields *int) (ProtoFieldNode, bool, []string) {
	fn := ProtoFieldNode{
		FieldNumber:  fieldNum,
		WireType:     protoWireBytes,
		WireTypeName: "length_delimited",
		ByteLen:      len(payload),
		BytesHex:     hex.EncodeToString(payload),
		RawHex:       hex.EncodeToString(payload),
	}

	if len(payload) == 0 {
		fn.Kind = "string"
		fn.StringVal = ""
		return fn, false, nil
	}

	// Prefer nested message when payload does not look like plain human-readable UTF-8 text.
	if !looksLikeProtoPlainString(payload) {
		if depth < maxProtoDepth {
			savedFields := *totalFields
			nested, subFieldCapHit, err := decodeProtoMessage(payload, depth+1, totalFields)
			if err == nil && len(nested.Fields) > 0 && looksPlausibleProto(nested) {
				if subFieldCapHit {
					// Keep lossless BytesHex instead of a partial nested message that dropped fields.
					fn.Kind = "bytes"
					return fn, true, nested.Warnings
				}
				fn.Kind = "message"
				fn.Nested = nested
				return fn, nested.Truncated, nested.Warnings
			}
			if !subFieldCapHit {
				*totalFields = savedFields
			} else {
				fn.Kind = "bytes"
				return fn, true, []string{fmt.Sprintf("field count cap reached (%d fields) while inspecting field %d", maxProtoFields, fieldNum)}
			}
		} else {
			fn.Kind = "bytes"
			return fn, true, []string{fmt.Sprintf("max recursion depth (%d) reached at field %d", maxProtoDepth, fieldNum)}
		}
	}

	if utf8.Valid(payload) && isPrintableStringBytes(payload) {
		fn.Kind = "string"
		fn.StringVal = string(payload)
		return fn, false, nil
	}

	fn.Kind = "bytes"
	if utf8.Valid(payload) {
		fn.StringVal = string(payload)
	}
	return fn, false, nil
}

func looksLikeProtoPlainString(data []byte) bool {
	if !isPrintableStringBytes(data) {
		return false
	}
	// Edge case: embedded message consisting solely of field 1 (tag 0x0a = '\n')
	// followed by a single-byte length matching len(data)-2 (e.g. len 9/10/13/32).
	if len(data) >= 3 && data[0] == 0x0a && int(data[1]) == len(data)-2 {
		return false
	}
	return true
}

func isPrintableStringBytes(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	for _, r := range string(data) {
		if !unicode.IsPrint(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

// EncodeProtobufRaw serializes a ProtoMessageNode back into exact Protobuf wire
// bytes, enabling field tampering and replay without needing a .proto schema.
func EncodeProtobufRaw(node *ProtoMessageNode) ([]byte, error) {
	if node == nil {
		return nil, fmt.Errorf("protobuf encode: nil message node")
	}
	totalFields := 0
	return encodeProtoMessage(node, 0, &totalFields)
}

func encodeProtoMessage(node *ProtoMessageNode, depth int, totalFields *int) ([]byte, error) {
	if depth > maxProtoDepth {
		return nil, fmt.Errorf("protobuf encode: max recursion depth (%d) exceeded", maxProtoDepth)
	}

	var out []byte
	for idx, f := range node.Fields {
		*totalFields++
		if *totalFields > maxProtoFields {
			return nil, fmt.Errorf("protobuf encode: total field count exceeds limit %d", maxProtoFields)
		}
		if f.FieldNumber < 1 || f.FieldNumber > maxProtoFieldNumber {
			return nil, fmt.Errorf("protobuf encode: field[%d] has invalid field_number %d", idx, f.FieldNumber)
		}

		wt := f.WireType
		// Infer wire type when caller constructed a field by Kind without setting WireType.
		if wt == 0 {
			switch f.Kind {
			case "fixed64", "sfixed64", "double":
				wt = protoWireFixed64
			case "string", "bytes", "message":
				wt = protoWireBytes
			case "fixed32", "sfixed32", "float":
				wt = protoWireFixed32
			}
		}

		tag := (uint64(f.FieldNumber) << 3) | uint64(wt&0x7)

		switch wt {
		case protoWireVarint:
			val, err := resolveVarintValue(f)
			if err != nil {
				return nil, fmt.Errorf("protobuf encode: field %d: %w", f.FieldNumber, err)
			}
			out = appendProtoVarint(out, tag)
			out = appendProtoVarint(out, val)

		case protoWireFixed64:
			val, err := resolveFixed64Value(f)
			if err != nil {
				return nil, fmt.Errorf("protobuf encode: field %d: %w", f.FieldNumber, err)
			}
			out = appendProtoVarint(out, tag)
			var buf [8]byte
			binary.LittleEndian.PutUint64(buf[:], val)
			out = append(out, buf[:]...)

		case protoWireBytes:
			payload, err := resolveLengthDelimitedBytes(f, depth, totalFields)
			if err != nil {
				return nil, fmt.Errorf("protobuf encode: field %d: %w", f.FieldNumber, err)
			}
			out = appendProtoVarint(out, tag)
			out = appendProtoVarint(out, uint64(len(payload)))
			out = append(out, payload...)

		case protoWireFixed32:
			val, err := resolveFixed32Value(f)
			if err != nil {
				return nil, fmt.Errorf("protobuf encode: field %d: %w", f.FieldNumber, err)
			}
			out = appendProtoVarint(out, tag)
			var buf [4]byte
			binary.LittleEndian.PutUint32(buf[:], val)
			out = append(out, buf[:]...)

		default:
			return nil, fmt.Errorf("protobuf encode: unsupported wire_type %d for field %d", wt, f.FieldNumber)
		}
	}
	return out, nil
}

func resolveVarintValue(f ProtoFieldNode) (uint64, error) {
	switch f.Kind {
	case "sint64":
		if f.VarintS64 != nil {
			return zigzagEncode64(*f.VarintS64), nil
		}
	case "int64":
		if f.VarintI64 != nil {
			return uint64(*f.VarintI64), nil
		}
	}
	if f.VarintU64 != nil {
		return *f.VarintU64, nil
	}
	if f.VarintI64 != nil {
		return uint64(*f.VarintI64), nil
	}
	if f.VarintS64 != nil {
		return zigzagEncode64(*f.VarintS64), nil
	}
	return 0, nil
}

func resolveFixed64Value(f ProtoFieldNode) (uint64, error) {
	switch f.Kind {
	case "double":
		if f.DoubleVal != nil {
			return math.Float64bits(*f.DoubleVal), nil
		}
	case "sfixed64":
		if f.Fixed64S != nil {
			return uint64(*f.Fixed64S), nil
		}
	}
	if f.Fixed64U != nil {
		return *f.Fixed64U, nil
	}
	if f.Fixed64S != nil {
		return uint64(*f.Fixed64S), nil
	}
	if f.DoubleVal != nil {
		return math.Float64bits(*f.DoubleVal), nil
	}
	if f.RawHex != "" {
		raw, err := HexDecode([]byte(f.RawHex))
		if err != nil || len(raw) != 8 {
			return 0, fmt.Errorf("fixed64 raw_hex must be 8 bytes")
		}
		return binary.LittleEndian.Uint64(raw), nil
	}
	return 0, nil
}

func resolveFixed32Value(f ProtoFieldNode) (uint32, error) {
	switch f.Kind {
	case "float":
		if f.FloatVal != nil {
			return math.Float32bits(float32(*f.FloatVal)), nil
		}
	case "sfixed32":
		if f.Fixed32S != nil {
			return uint32(*f.Fixed32S), nil
		}
	}
	if f.Fixed32U != nil {
		return *f.Fixed32U, nil
	}
	if f.Fixed32S != nil {
		return uint32(*f.Fixed32S), nil
	}
	if f.FloatVal != nil {
		return math.Float32bits(float32(*f.FloatVal)), nil
	}
	if f.RawHex != "" {
		raw, err := HexDecode([]byte(f.RawHex))
		if err != nil || len(raw) != 4 {
			return 0, fmt.Errorf("fixed32 raw_hex must be 4 bytes")
		}
		return binary.LittleEndian.Uint32(raw), nil
	}
	return 0, nil
}

func resolveLengthDelimitedBytes(f ProtoFieldNode, depth int, totalFields *int) ([]byte, error) {
	switch f.Kind {
	case "message":
		if f.Nested != nil {
			return encodeProtoMessage(f.Nested, depth+1, totalFields)
		}
		if f.BytesHex != "" {
			return HexDecode([]byte(f.BytesHex))
		}
		return nil, nil
	case "string":
		return []byte(f.StringVal), nil
	case "bytes":
		if f.BytesHex != "" {
			return HexDecode([]byte(f.BytesHex))
		}
		if f.RawHex != "" {
			return HexDecode([]byte(f.RawHex))
		}
		return nil, nil
	default:
		if f.Nested != nil {
			return encodeProtoMessage(f.Nested, depth+1, totalFields)
		}
		if f.BytesHex != "" {
			return HexDecode([]byte(f.BytesHex))
		}
		return []byte(f.StringVal), nil
	}
}

func decodeProtoVarint(buf []byte) (uint64, int) {
	var result uint64
	var shift uint
	limit := len(buf)
	if limit > maxProtoVarintBytes {
		limit = maxProtoVarintBytes
	}
	for idx := 0; idx < limit; idx++ {
		b := buf[idx]
		if idx == 9 && b > 1 {
			return 0, -1 // overflow past 64 bits
		}
		result |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return result, idx + 1
		}
		shift += 7
	}
	return 0, -1
}

func appendProtoVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func zigzagDecode64(u uint64) int64 {
	return int64((u >> 1) ^ -(u & 1))
}

func zigzagEncode64(s int64) uint64 {
	return uint64((s << 1) ^ (s >> 63))
}

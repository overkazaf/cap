package proto_test

import (
	"encoding/binary"
	"testing"

	"github.com/overkazaf/cap/internal/proto"
)

// --- test-only wire format encoders, used to build fixtures without a
// real protobuf library (mirrors the decoder's own wire format rules). ---

func encodeVarint(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}

func encodeTag(fieldNum, wireType int) []byte {
	return encodeVarint(nil, uint64(fieldNum)<<3|uint64(wireType))
}

func encodeVarintField(fieldNum int, value uint64) []byte {
	b := encodeTag(fieldNum, 0)
	return encodeVarint(b, value)
}

func encodeLengthDelimitedField(fieldNum int, payload []byte) []byte {
	b := encodeTag(fieldNum, 2)
	b = encodeVarint(b, uint64(len(payload)))
	return append(b, payload...)
}

func encodeFixed32Field(fieldNum int, value uint32) []byte {
	b := encodeTag(fieldNum, 5)
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, value)
	return append(b, buf...)
}

func TestIsProtobuf(t *testing.T) {
	t.Run("valid protobuf bytes", func(t *testing.T) {
		msg := encodeVarintField(1, 12345)
		msg = append(msg, encodeFixed32Field(2, 0xDEADBEEF)...)
		msg = append(msg, encodeLengthDelimitedField(3, []byte{0xFF, 0xFE, 0x00, 0x01, 0x02})...)

		if !proto.IsProtobuf(msg) {
			t.Errorf("IsProtobuf(valid protobuf bytes) = false, want true")
		}
	})

	t.Run("JSON", func(t *testing.T) {
		data := []byte(`{"foo": "bar", "num": 123}`)
		if proto.IsProtobuf(data) {
			t.Errorf("IsProtobuf(JSON) = true, want false")
		}
	})

	t.Run("random text", func(t *testing.T) {
		data := []byte("the quick brown fox jumps over the lazy dog, this is just plain text")
		if proto.IsProtobuf(data) {
			t.Errorf("IsProtobuf(random text) = true, want false")
		}
	})

	t.Run("empty", func(t *testing.T) {
		if proto.IsProtobuf(nil) {
			t.Errorf("IsProtobuf(nil) = true, want false")
		}
	})
}

func TestDecodeVarint(t *testing.T) {
	data := encodeVarintField(1, 150)

	fields, err := proto.Decode(data)
	if err != nil {
		t.Fatalf("Decode: unexpected error: %v", err)
	}
	if len(fields) != 1 {
		t.Fatalf("len(fields) = %d, want 1", len(fields))
	}

	f := fields[0]
	if f.Number != 1 {
		t.Errorf("Number = %d, want 1", f.Number)
	}
	if f.WireType != 0 {
		t.Errorf("WireType = %d, want 0", f.WireType)
	}
	if f.TypeName != "varint" {
		t.Errorf("TypeName = %q, want %q", f.TypeName, "varint")
	}
	v, ok := f.Value.(uint64)
	if !ok || v != 150 {
		t.Errorf("Value = %#v, want uint64(150)", f.Value)
	}
}

func TestDecodeString(t *testing.T) {
	data := encodeLengthDelimitedField(2, []byte("hello"))

	fields, err := proto.Decode(data)
	if err != nil {
		t.Fatalf("Decode: unexpected error: %v", err)
	}
	if len(fields) != 1 {
		t.Fatalf("len(fields) = %d, want 1", len(fields))
	}

	f := fields[0]
	if f.Number != 2 {
		t.Errorf("Number = %d, want 2", f.Number)
	}
	if f.WireType != 2 {
		t.Errorf("WireType = %d, want 2", f.WireType)
	}
	if f.TypeName != "string" {
		t.Errorf("TypeName = %q, want %q", f.TypeName, "string")
	}
	s, ok := f.Value.(string)
	if !ok || s != "hello" {
		t.Errorf("Value = %#v, want \"hello\"", f.Value)
	}
}

func TestDecodeEmbedded(t *testing.T) {
	inner := encodeVarintField(1, 42)
	inner = append(inner, encodeLengthDelimitedField(2, []byte("nested"))...)
	outer := encodeLengthDelimitedField(3, inner)

	fields, err := proto.Decode(outer)
	if err != nil {
		t.Fatalf("Decode: unexpected error: %v", err)
	}
	if len(fields) != 1 {
		t.Fatalf("len(fields) = %d, want 1", len(fields))
	}

	f := fields[0]
	if f.Number != 3 {
		t.Errorf("Number = %d, want 3", f.Number)
	}
	if f.TypeName != "embedded" {
		t.Errorf("TypeName = %q, want %q", f.TypeName, "embedded")
	}
	if len(f.Fields) != 2 {
		t.Fatalf("len(Fields) = %d, want 2", len(f.Fields))
	}

	inner0 := f.Fields[0]
	if inner0.Number != 1 || inner0.TypeName != "varint" {
		t.Errorf("Fields[0] = %+v, want field 1 varint", inner0)
	}
	if v, ok := inner0.Value.(uint64); !ok || v != 42 {
		t.Errorf("Fields[0].Value = %#v, want uint64(42)", inner0.Value)
	}

	inner1 := f.Fields[1]
	if inner1.Number != 2 || inner1.TypeName != "string" {
		t.Errorf("Fields[1] = %+v, want field 2 string", inner1)
	}
	if s, ok := inner1.Value.(string); !ok || s != "nested" {
		t.Errorf("Fields[1].Value = %#v, want \"nested\"", inner1.Value)
	}
}

func TestFormatFields(t *testing.T) {
	fields := []proto.Field{
		{Number: 1, WireType: 0, TypeName: "varint", Value: uint64(12345)},
		{Number: 2, WireType: 2, TypeName: "string", Value: "hello world"},
		{
			Number: 3, WireType: 2, TypeName: "embedded",
			Fields: []proto.Field{
				{Number: 1, WireType: 0, TypeName: "varint", Value: uint64(42)},
				{Number: 2, WireType: 2, TypeName: "string", Value: "nested"},
			},
		},
		{Number: 4, WireType: 2, TypeName: "bytes", Value: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
	}

	got := proto.FormatFields(fields, "")
	want := "field 1 (varint): 12345\n" +
		"field 2 (string): \"hello world\"\n" +
		"field 3 (embedded):\n" +
		"  field 1 (varint): 42\n" +
		"  field 2 (string): \"nested\"\n" +
		"field 4 (bytes): deadbeef\n"

	if got != want {
		t.Errorf("FormatFields() =\n%q\nwant\n%q", got, want)
	}
}

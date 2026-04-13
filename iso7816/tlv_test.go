package iso7816

import (
	"bytes"
	"testing"
)

func TestParseTLV_Simple(t *testing.T) {
	data := []byte{0x53, 0x02, 0xAB, 0xCD}
	tlv, rest, err := ParseTLV(data)
	if err != nil {
		t.Fatal(err)
	}
	if tlv.Tag != 0x53 {
		t.Errorf("expected tag 0x53, got 0x%X", tlv.Tag)
	}
	if !bytes.Equal(tlv.Value, []byte{0xAB, 0xCD}) {
		t.Errorf("unexpected value: %X", tlv.Value)
	}
	if len(rest) != 0 {
		t.Errorf("expected no remaining, got %d bytes", len(rest))
	}
}

func TestParseTLV_MultiByteLength(t *testing.T) {
	data := make([]byte, 2+2+128)
	data[0] = 0x53
	data[1] = 0x81
	data[2] = 0x80
	copy(data[3:], bytes.Repeat([]byte{0xFF}, 128))
	tlv, _, err := ParseTLV(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(tlv.Value) != 128 {
		t.Errorf("expected 128 bytes, got %d", len(tlv.Value))
	}
}

func TestParseAllTLV(t *testing.T) {
	data := []byte{
		0x01, 0x01, 0xAA,
		0x02, 0x02, 0xBB, 0xCC,
	}
	tlvs, err := ParseAllTLV(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(tlvs) != 2 {
		t.Fatalf("expected 2 TLVs, got %d", len(tlvs))
	}
	if tlvs[0].Tag != 0x01 || tlvs[1].Tag != 0x02 {
		t.Error("unexpected tags")
	}
}

func TestEncodeTLV(t *testing.T) {
	encoded := EncodeTLV(0x53, []byte{0xAB, 0xCD})
	expected := []byte{0x53, 0x02, 0xAB, 0xCD}
	if !bytes.Equal(encoded, expected) {
		t.Errorf("got %X, want %X", encoded, expected)
	}
}

func TestFindTag(t *testing.T) {
	tlvs := []*TLV{
		{Tag: 0x01, Value: []byte{0xAA}},
		{Tag: 0x02, Value: []byte{0xBB}},
	}
	found := FindTag(tlvs, 0x02)
	if found == nil {
		t.Fatal("expected to find tag 0x02")
	}
	if found.Value[0] != 0xBB {
		t.Error("unexpected value")
	}
	missing := FindTag(tlvs, 0x99)
	if missing != nil {
		t.Error("expected nil for missing tag")
	}
}

func TestParseTLV_Empty(t *testing.T) {
	_, _, err := ParseTLV(nil)
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

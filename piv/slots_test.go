package piv

import (
	"errors"
	"strings"
	"testing"
)

func TestObjectIDForSlot(t *testing.T) {
	tests := []struct {
		name string
		slot Slot
		want uint
	}{
		{name: "PIV authentication 9A", slot: SlotAuthentication, want: ObjectCertPIVAuth},
		{name: "digital signature 9C", slot: SlotSignature, want: ObjectCertDigitalSig},
		{name: "key management 9D", slot: SlotKeyManagement, want: ObjectCertKeyMgmt},
		{name: "card authentication 9E", slot: SlotCardAuth, want: ObjectCertCardAuth},
		{name: "retired first 82", slot: 0x82, want: 0x5FC10D},
		{name: "retired second 83", slot: 0x83, want: 0x5FC10E},
		{name: "retired last 95", slot: 0x95, want: 0x5FC120},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tag, err := ObjectIDForSlot(test.slot)
			if err != nil {
				t.Fatalf("ObjectIDForSlot(%s) unexpected error: %v", test.slot, err)
			}
			if tag != test.want {
				t.Fatalf("ObjectIDForSlot(%s) = %06X, want %06X", test.slot, tag, test.want)
			}
		})
	}
}

// TestObjectIDForSlotRetiredRangeIsContiguous verifies the complete retired
// range 82..95 maps onto 0x5FC10D..0x5FC120 without gaps or overlap with the
// standard slots.
func TestObjectIDForSlotRetiredRangeIsContiguous(t *testing.T) {
	if ObjectCertRetiredKeyMgmtBase != 0x5FC10D {
		t.Fatalf("ObjectCertRetiredKeyMgmtBase = %06X, want 5FC10D", ObjectCertRetiredKeyMgmtBase)
	}
	for offset := 0; offset <= 0x13; offset++ {
		slot := Slot(0x82 + offset)
		tag, err := ObjectIDForSlot(slot)
		if err != nil {
			t.Fatalf("ObjectIDForSlot(%s) unexpected error: %v", slot, err)
		}
		if want := 0x5FC10D + uint(offset); tag != want {
			t.Fatalf("ObjectIDForSlot(%s) = %06X, want %06X", slot, tag, want)
		}
	}
}

func TestObjectIDForSlotUnsupported(t *testing.T) {
	for _, slot := range []Slot{0x81, 0x96, SlotManagement} {
		t.Run(slot.String(), func(t *testing.T) {
			tag, err := ObjectIDForSlot(slot)
			if !errors.Is(err, ErrUnsupportedSlot) {
				t.Fatalf("ObjectIDForSlot(%s) error = %v, want ErrUnsupportedSlot", slot, err)
			}
			if tag != 0 {
				t.Fatalf("ObjectIDForSlot(%s) tag = %06X, want 0", slot, tag)
			}
			if want := "piv: unsupported slot " + slot.String(); err.Error() != want {
				t.Fatalf("ObjectIDForSlot(%s) error = %q, want %q", slot, err.Error(), want)
			}
		})
	}
}

func TestIsRetiredSlot(t *testing.T) {
	tests := []struct {
		slot Slot
		want bool
	}{
		{slot: 0x00, want: false},
		{slot: 0x81, want: false},
		{slot: 0x82, want: true},
		{slot: 0x83, want: true},
		{slot: 0x94, want: true},
		{slot: 0x95, want: true},
		{slot: 0x96, want: false},
		{slot: SlotAuthentication, want: false},
		{slot: SlotManagement, want: false},
		{slot: SlotCardAuth, want: false},
		{slot: 0xF9, want: false},
	}
	for _, test := range tests {
		if got := IsRetiredSlot(test.slot); got != test.want {
			t.Fatalf("IsRetiredSlot(%s) = %v, want %v", test.slot, got, test.want)
		}
	}
}

// TestErrUnsupportedSlotMessageShape keeps the historical human-readable text
// so error mappers that match on "unsupported slot" keep working.
func TestErrUnsupportedSlotMessageShape(t *testing.T) {
	if !strings.Contains(ErrUnsupportedSlot.Error(), "unsupported slot") {
		t.Fatalf("ErrUnsupportedSlot = %q, want it to contain %q", ErrUnsupportedSlot.Error(), "unsupported slot")
	}
}

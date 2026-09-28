package piv

import (
	"errors"
	"fmt"
)

// ErrUnsupportedSlot reports a slot that has no PIV data object mapping.
var ErrUnsupportedSlot = errors.New("piv: unsupported slot")

// Slot represents a PIV key slot.
type Slot byte

// Standard PIV key slots.
const (
	SlotAuthentication Slot = 0x9A
	SlotManagement     Slot = 0x9B
	SlotSignature      Slot = 0x9C
	SlotKeyManagement  Slot = 0x9D
	SlotCardAuth       Slot = 0x9E
)

// ObjectCertRetiredKeyMgmtBase is the X.509 certificate object for the first
// retired key management slot (0x82). Retired slots 0x82..0x95 map to
// consecutive objects 0x5FC10D..0x5FC120 (NIST SP 800-78-4).
const ObjectCertRetiredKeyMgmtBase uint = 0x5FC10D

// String returns the hex representation of the slot.
func (s Slot) String() string {
	return fmt.Sprintf("%02X", byte(s))
}

// IsRetiredSlot reports whether the slot is a retired key management slot
// (0x82..0x95) that still has a certificate/public-key data object.
func IsRetiredSlot(slot Slot) bool {
	return slot >= 0x82 && slot <= 0x95
}

// slotToObjectID maps a PIV slot to the corresponding data object tag.
// Slots without a mapping return 0.
func slotToObjectID(slot Slot) uint {
	switch slot {
	case SlotAuthentication:
		return ObjectCertPIVAuth
	case SlotSignature:
		return ObjectCertDigitalSig
	case SlotKeyManagement:
		return ObjectCertKeyMgmt
	case SlotCardAuth:
		return ObjectCertCardAuth
	default:
		if IsRetiredSlot(slot) {
			return ObjectCertRetiredKeyMgmtBase + uint(slot-0x82)
		}
		return 0
	}
}

// ObjectIDForSlot returns the data object tag corresponding to a PIV slot.
func ObjectIDForSlot(slot Slot) (uint, error) {
	tag := slotToObjectID(slot)
	if tag == 0 {
		return 0, fmt.Errorf("%w %s", ErrUnsupportedSlot, slot)
	}
	return tag, nil
}

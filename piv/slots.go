package piv

import "fmt"

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

// String returns the hex representation of the slot.
func (s Slot) String() string {
	return fmt.Sprintf("%02X", byte(s))
}

// slotToObjectID maps a PIV slot to the corresponding data object tag.
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
		return 0
	}
}

// ObjectIDForSlot returns the data object tag corresponding to a PIV slot.
func ObjectIDForSlot(slot Slot) (uint, error) {
	tag := slotToObjectID(slot)
	if tag == 0 {
		return 0, fmt.Errorf("unsupported slot %s", slot)
	}
	return tag, nil
}

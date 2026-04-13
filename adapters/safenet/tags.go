package safenet

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/piv"
)

const (
	safeNetCardAuthMirrorTag uint = 0xFFF301
	safeNetCHUIDAlias        uint = 0xFFF302
)

var safeNetGenerationTagsBySlot = map[piv.Slot]uint{
	piv.SlotAuthentication: 0xFF900A,
	piv.SlotSignature:      0xFF900C,
	piv.SlotKeyManagement:  0xFF900D,
	piv.SlotCardAuth:       0xFF900E,
}

var safeNetMirrorTagsBySlot = map[piv.Slot]uint{
	piv.SlotAuthentication: 0xFFF305,
	piv.SlotSignature:      0xFFF30A,
	piv.SlotKeyManagement:  0xFFF30B,
	piv.SlotCardAuth:       safeNetCardAuthMirrorTag,
}

var safeNetKnownGenerationTags = []uint{
	safeNetGenerationTagsBySlot[piv.SlotAuthentication],
	safeNetGenerationTagsBySlot[piv.SlotSignature],
	safeNetGenerationTagsBySlot[piv.SlotKeyManagement],
	0xFF9010,
	0xFF9011,
	0xFF9012,
	0xFF9013,
	0xFF9014,
	0xFF9015,
	0xFF9016,
	0xFF9017,
	0xFF9018,
	0xFF9019,
	0xFF901A,
	0xFF901B,
	0xFF901C,
	0xFF901D,
	0xFF901E,
	0xFF901F,
	0xFF9020,
	0xFF9021,
	0xFF9022,
	0xFF9023,
}

var safeNetInitializationGenerationTags = cloneTagList(safeNetKnownGenerationTags)

var safeNetResetGenerationTags = cloneTagList(safeNetKnownGenerationTags)

var safeNetInitializationMirrorTags = []uint{
	0xFFF30D,
	safeNetMirrorTagsBySlot[piv.SlotAuthentication],
	safeNetMirrorTagsBySlot[piv.SlotSignature],
	safeNetMirrorTagsBySlot[piv.SlotKeyManagement],
	0xFFF30E,
	0xFFF327,
	0xFFF310,
	0xFFF311,
	0xFFF312,
	0xFFF313,
	0xFFF314,
	0xFFF315,
	0xFFF316,
	0xFFF317,
	0xFFF318,
	0xFFF319,
	0xFFF31A,
	0xFFF31B,
	0xFFF31C,
	0xFFF31D,
	0xFFF31E,
	0xFFF31F,
	0xFFF320,
	0xFFF321,
}

var safeNetResetMirrorTags = []uint{
	safeNetMirrorTagsBySlot[piv.SlotAuthentication],
	safeNetMirrorTagsBySlot[piv.SlotSignature],
	safeNetMirrorTagsBySlot[piv.SlotKeyManagement],
	0xFFF30D,
	0xFFF30E,
	0xFFF310,
	0xFFF311,
	0xFFF312,
	0xFFF313,
	0xFFF314,
	0xFFF315,
	0xFFF316,
	0xFFF317,
	0xFFF318,
	0xFFF319,
	0xFFF31A,
	0xFFF31B,
	0xFFF31C,
	0xFFF31D,
	0xFFF31E,
	0xFFF31F,
	0xFFF320,
	0xFFF321,
	0xFFF322,
	0xFFF323,
	0xFFF327,
}

func cloneTagList(tags []uint) []uint {
	return append([]uint(nil), tags...)
}

func generationObjectTag(slot piv.Slot) (uint, error) {
	tag, ok := safeNetGenerationTagsBySlot[slot]
	if !ok {
		return 0, fmt.Errorf("unsupported SafeNet generation slot %s", slot)
	}
	return tag, nil
}

func mirrorObjectTag(slot piv.Slot) (uint, error) {
	tag, ok := safeNetMirrorTagsBySlot[slot]
	if !ok {
		return 0, fmt.Errorf("unsupported slot %s", slot)
	}
	return tag, nil
}

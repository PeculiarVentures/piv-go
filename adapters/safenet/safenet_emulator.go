package safenet

import (
	"crypto/elliptic"

	"github.com/PeculiarVentures/piv-go/emulator"
	internalutil "github.com/PeculiarVentures/piv-go/internal"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

var safeNetEmulatorChallenge = []byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

type safeNetScenarioEmulator struct {
	objects map[uint][]byte
}

// NewDeleteKeyEmulatorCard returns a SafeNet emulator card configured for the
// delete-key flow used by CLI and integration-style tooling.
func NewDeleteKeyEmulatorCard() *emulator.Card {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xDB, nil)
	enqueueManagementAuthenticate(card)
	return card
}

// NewGenerateKeyEmulatorCard returns a SafeNet emulator card configured for the
// vendor-specific generate-key flow for the requested slot.
func NewGenerateKeyEmulatorCard(slot piv.Slot) *emulator.Card {
	state := &safeNetScenarioEmulator{objects: make(map[uint][]byte)}
	card := emulator.NewCard()
	card.SetSuccessResponse(0xA4, nil)
	card.SetSuccessResponse(0xDB, nil)
	card.RegisterHandler(isGetDataCommand, state.handleGetData)
	card.RegisterHandler(isPutDataCommand, state.handlePutData)

	versionResponse := []byte{0x76, 0x34, 0x2E, 0x30, 0x30}
	keyRef := byte(slot)
	metadataResponse := []byte{
		0xE2, 0x16,
		0xA0, 0x0E, 0x8C, 0x06, 0xEB, 0x06, 0x06, 0x02, 0x02, 0x00,
		0xA1, 0x04, 0xE1, 0x05, 0x05, 0x00,
		0x83, 0x01, keyRef,
		0x8A, 0x01, 0x04,
		0x99, 0x02, 0xFF, 0xFF,
		0x9C, 0x02, 0xFF, 0xFF,
		0x80, 0x01, 0x11,
		0x9D, 0x01, 0x00,
	}
	card.EnqueueResponse(0xCB, versionResponse, uint16(iso7816.SwSuccess))
	card.EnqueueResponse(0xCB, metadataResponse, uint16(iso7816.SwSuccess))
	enqueueManagementAuthenticate(card)

	point := internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	generateResponse := iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point))
	card.EnqueueResponse(0x47, generateResponse, uint16(iso7816.SwSuccess))

	if _, err := piv.ObjectIDForSlot(slot); err != nil {
		panic(err)
	}
	generationMetadataResponse := []byte{
		0xE2, 0x09,
		0x8A, 0x01, 0x05,
		0x80, 0x01, 0x11,
		0x9D, 0x01, 0x55,
	}
	card.EnqueueResponse(0xCB, generationMetadataResponse, uint16(iso7816.SwSuccess))
	card.EnqueueResponse(0xCB, nil, uint16(iso7816.SwFileNotFound))

	return card
}

func enqueueManagementAuthenticate(card *emulator.Card) {
	challengeResponse := iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x81, safeNetEmulatorChallenge))
	card.EnqueueResponse(0x87, challengeResponse, uint16(iso7816.SwSuccess))
	card.EnqueueResponse(0x87, nil, uint16(iso7816.SwSuccess))
}

func (s *safeNetScenarioEmulator) handleGetData(_ *emulator.Card, command []byte) ([]byte, error) {
	tag, err := dataTagFromGetDataCommand(command)
	if err != nil {
		return nil, err
	}
	value, ok := s.objects[tag]
	if !ok {
		return nil, emulator.ErrUnhandled
	}
	return emulator.BuildSuccessResponse(value), nil
}

func (s *safeNetScenarioEmulator) handlePutData(_ *emulator.Card, command []byte) ([]byte, error) {
	tag, value, err := decodeSafeNetPutDataCommand(command)
	if err != nil {
		return nil, err
	}
	s.objects[tag] = append([]byte(nil), value...)
	return emulator.BuildSuccessResponse(nil), nil
}

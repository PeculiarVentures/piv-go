package safenet

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
)

type safeNetInitializationEmulator struct {
	generationTags []uint
	mirrorTags     []uint
	objects        map[uint][]byte
	challenge      []byte
	version        []byte
	status         []byte
	gaStep         int
}

func newSafeNetInitializationCard() *emulator.Card {
	state := &safeNetInitializationEmulator{
		generationTags: cloneTagList(safeNetInitializationGenerationTags),
		mirrorTags:     cloneTagList(safeNetInitializationMirrorTags),
		objects:        make(map[uint][]byte),
		challenge: []byte{
			0xFC, 0x9D, 0x30, 0x47,
			0x0C, 0x5E, 0xC7, 0xDF,
			0x14, 0x30, 0x6F, 0x8D,
			0xFF, 0x01, 0xEA, 0x5C,
		},
		version: []byte{0xDF, 0x30, 0x05, 0x76, 0x34, 0x2E, 0x30, 0x30},
		status:  []byte{0x00, 0x01, 0xAF, 0xE8},
	}
	card := emulator.NewCard()
	state.install(card)
	return card
}

// NewInitializationEmulatorCard returns a SafeNet emulator card configured for
// the initialization flow.
func NewInitializationEmulatorCard() *emulator.Card {
	return newSafeNetInitializationCard()
}

func (s *safeNetInitializationEmulator) install(card *emulator.Card) {
	card.RegisterPrefixHandler([]byte{0x00, 0xA4, 0x04, 0x00}, s.handleSelectPIV)
	card.RegisterPrefixHandler([]byte{0x01, 0xA4, 0x04, 0x00}, s.handleSelectAdmin)
	card.RegisterPrefixHandler([]byte{0x81, 0xCB, 0xDF, 0x30, 0x08}, s.handleVersion)
	card.RegisterPrefixHandler([]byte{0x81, 0xCB, 0xDF, 0x39, 0x04}, s.handleStatus)
	card.RegisterPrefixHandler([]byte{0x81, 0xCB, 0xDF, 0x35, 0x00}, s.handleGenerationTags)
	card.RegisterPrefixHandler([]byte{0x81, 0xCB, 0xDF, 0x34, 0x00}, s.handleMirrorTags)
	card.RegisterHandler(isMetadataCommand, s.handleMetadata)
	card.RegisterHandler(isGetDataCommand, s.handleGetData)
	card.RegisterHandler(isPutDataCommand, s.handlePutData)
	card.RegisterHandler(isManagementAuthenticateCommand, s.handleManagementAuthenticate)
	card.RegisterPrefixHandler([]byte{0x00, 0x2C, 0x00, 0x80}, s.handleResetRetryCounter)
}

func (s *safeNetInitializationEmulator) handleSelectPIV(_ *emulator.Card, _ []byte) ([]byte, error) {
	return emulator.BuildSuccessResponse([]byte{0x61, 0x11, 0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4F, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08}), nil
}

func (s *safeNetInitializationEmulator) handleSelectAdmin(_ *emulator.Card, _ []byte) ([]byte, error) {
	return emulator.BuildSuccessResponse(nil), nil
}

func (s *safeNetInitializationEmulator) handleVersion(_ *emulator.Card, _ []byte) ([]byte, error) {
	return emulator.BuildSuccessResponse(s.version), nil
}

func (s *safeNetInitializationEmulator) handleStatus(_ *emulator.Card, _ []byte) ([]byte, error) {
	return emulator.BuildSuccessResponse(s.status), nil
}

func (s *safeNetInitializationEmulator) handleGenerationTags(_ *emulator.Card, _ []byte) ([]byte, error) {
	return emulator.BuildSuccessResponse(encodeTagList(s.generationTags)), nil
}

func (s *safeNetInitializationEmulator) handleMirrorTags(_ *emulator.Card, _ []byte) ([]byte, error) {
	return emulator.BuildSuccessResponse(encodeTagList(s.mirrorTags)), nil
}

func (s *safeNetInitializationEmulator) handleMetadata(_ *emulator.Card, command []byte) ([]byte, error) {
	tag, err := metadataTagFromCommand(command)
	if err != nil {
		return nil, err
	}
	return emulator.BuildSuccessResponse(defaultMetadataResponse(tag)), nil
}

func (s *safeNetInitializationEmulator) handleGetData(_ *emulator.Card, command []byte) ([]byte, error) {
	tag, err := dataTagFromGetDataCommand(command)
	if err != nil {
		return nil, err
	}
	if value, ok := s.objects[tag]; ok {
		return emulator.BuildSuccessResponse(value), nil
	}
	if tag == safeNetCHUIDAlias || tag == safeNetCardAuthMirrorTag {
		return emulator.BuildResponse(nil, uint16(iso7816.SwWrongData)), nil
	}
	return emulator.BuildResponse(nil, uint16(iso7816.SwFileNotFound)), nil
}

func (s *safeNetInitializationEmulator) handlePutData(_ *emulator.Card, command []byte) ([]byte, error) {
	tag, value, err := decodeSafeNetPutDataCommand(command)
	if err != nil {
		return nil, err
	}
	s.objects[tag] = append([]byte(nil), value...)
	return emulator.BuildSuccessResponse(nil), nil
}

func (s *safeNetInitializationEmulator) handleManagementAuthenticate(_ *emulator.Card, _ []byte) ([]byte, error) {
	if s.gaStep%2 == 0 {
		s.gaStep++
		return emulator.BuildSuccessResponse(iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x81, s.challenge))), nil
	}
	s.gaStep++
	return emulator.BuildSuccessResponse(nil), nil
}

func (s *safeNetInitializationEmulator) handleResetRetryCounter(_ *emulator.Card, _ []byte) ([]byte, error) {
	return emulator.BuildSuccessResponse(nil), nil
}

func hasPrefix(data []byte, prefix []byte) bool {
	if len(data) < len(prefix) {
		return false
	}
	for index := range prefix {
		if data[index] != prefix[index] {
			return false
		}
	}
	return true
}

func encodeTagList(tags []uint) []byte {
	encoded := make([]byte, 0, len(tags)*3)
	for _, tag := range tags {
		encoded = append(encoded, byte(tag>>16), byte(tag>>8), byte(tag))
	}
	return encoded
}

func isMetadataCommand(command []byte) bool {
	return hasPrefix(command, []byte{0x81, 0xCB, 0x3F, 0xFF, 0x05, 0x4D, 0x03})
}

func metadataTagFromCommand(command []byte) (uint, error) {
	if len(command) < 10 {
		return 0, fmt.Errorf("safenet emulator: truncated metadata command")
	}
	return uint(command[7])<<16 | uint(command[8])<<8 | uint(command[9]), nil
}

func defaultMetadataResponse(tag uint) []byte {
	inner := iso7816.EncodeTLV(0x83, []byte{byte(tag)})
	inner = append(inner, iso7816.EncodeTLV(0x8A, []byte{0x03})...)
	inner = append(inner, iso7816.EncodeTLV(0x99, []byte{0xFF, 0xFF})...)
	inner = append(inner, iso7816.EncodeTLV(0x9C, []byte{0xFF, 0xFF})...)
	inner = append(inner, iso7816.EncodeTLV(0x80, []byte{0xFF})...)
	inner = append(inner, iso7816.EncodeTLV(0x9D, []byte{0x00})...)
	outer := iso7816.EncodeTLV(0xA1, inner)
	outer = append(iso7816.EncodeTLV(0xA0, iso7816.EncodeTLV(0x8C, []byte{0x03, byte(tag >> 8), byte(tag)})), outer...)
	return iso7816.EncodeTLV(0xE2, outer)
}

func isGetDataCommand(command []byte) bool {
	return hasPrefix(command, []byte{0x00, 0xCB, 0x3F, 0xFF})
}

func dataTagFromGetDataCommand(command []byte) (uint, error) {
	if len(command) < 11 || command[5] != 0x5C || command[6] != 0x03 {
		return 0, fmt.Errorf("safenet emulator: unsupported GET DATA command")
	}
	return uint(command[7])<<16 | uint(command[8])<<8 | uint(command[9]), nil
}

func isPutDataCommand(command []byte) bool {
	return len(command) >= 5 && command[1] == 0xDB && command[2] == 0x3F && command[3] == 0xFF
}

func decodeSafeNetPutDataCommand(command []byte) (uint, []byte, error) {
	if len(command) < 8 || command[5] != 0x5C {
		return 0, nil, fmt.Errorf("safenet emulator: malformed PUT DATA command")
	}
	tagLength := int(command[6])
	if len(command) < 7+tagLength+1 {
		return 0, nil, fmt.Errorf("safenet emulator: truncated PUT DATA command")
	}
	var tag uint
	for _, value := range command[7 : 7+tagLength] {
		tag = (tag << 8) | uint(value)
	}
	valueStart := 7 + tagLength
	valueEnd := len(command) - 1
	if valueEnd < valueStart {
		return 0, nil, fmt.Errorf("safenet emulator: truncated PUT DATA payload")
	}
	return tag, append([]byte(nil), command[valueStart:valueEnd]...), nil
}

func isManagementAuthenticateCommand(command []byte) bool {
	return hasPrefix(command, []byte{0x00, 0x87, 0x08, 0x9B})
}

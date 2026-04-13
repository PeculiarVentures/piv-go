package emulator

import (
	"bytes"
	"testing"
)

func TestCardRegisterHandlerAndTrace(t *testing.T) {
	card := NewCard()
	card.RegisterPrefixHandler([]byte{0x00, 0xA4, 0x04, 0x00}, func(_ *Card, _ []byte) ([]byte, error) {
		return BuildSuccessResponse([]byte{0x61, 0x11}), nil
	})

	response, err := card.Transmit([]byte{0x00, 0xA4, 0x04, 0x00, 0x00})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(response, []byte{0x61, 0x11, 0x90, 0x00}) {
		t.Fatalf("unexpected response: % X", response)
	}

	comparison := CompareTraceLines(
		[]string{
			"APDU -> 00 A4 04 00 00",
			"APDU <- 61 11 90 00",
		},
		card.APDULog(),
	)
	if !comparison.Match {
		t.Fatalf("unexpected APDU log: %s", comparison)
	}
}

func TestCardHandlerCanFallThroughToQueuedResponse(t *testing.T) {
	card := NewCard()
	card.RegisterINSHandler(0xCB, func(_ *Card, _ []byte) ([]byte, error) {
		return nil, ErrUnhandled
	})
	card.EnqueueResponse(0xCB, []byte{0x01, 0x02}, 0x9000)

	response, err := card.Transmit([]byte{0x00, 0xCB, 0x3F, 0xFF})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(response, []byte{0x01, 0x02, 0x90, 0x00}) {
		t.Fatalf("unexpected response: % X", response)
	}
}

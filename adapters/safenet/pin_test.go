package safenet

import (
	"bytes"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	adapteradmin "github.com/PeculiarVentures/piv-go/adapters/admin"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/internal/testtrace"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

func TestSafeNetAdapterPINStatusFromTLV(t *testing.T) {
	tests := []struct {
		name      string
		pinType   piv.PINType
		remaining byte
		maximum   int
	}{
		{name: "PIN", pinType: piv.PINTypeCard, remaining: 3, maximum: 5},
		{name: "PUK", pinType: piv.PINTypePUK, remaining: 2, maximum: 7},
		{name: "blocked PIN", pinType: piv.PINTypeCard, remaining: 0, maximum: 5},
		{name: "blocked PUK", pinType: piv.PINTypePUK, remaining: 0, maximum: 7},
		{name: "PIN without maximum", pinType: piv.PINTypeCard, remaining: 3, maximum: adapters.UnknownRetries},
		{name: "PUK without maximum", pinType: piv.PINTypePUK, remaining: 2, maximum: adapters.UnknownRetries},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := iso7816.EncodeTLV(0x9B, []byte{test.remaining})
			if test.maximum != adapters.UnknownRetries {
				data = append(iso7816.EncodeTLV(0x9A, []byte{byte(test.maximum)}), data...)
			}
			card := emulator.NewCard()
			card.SetSuccessResponse(0xCB, iso7816.EncodeTLV(0xE2, data))
			session := adapters.NewSession(piv.NewClient(card), adapters.WithReaderName("SafeNet eToken Fusion"))
			status, err := adapteradmin.ReadPINStatus(adapters.NewRuntime(session, NewAdapter()), test.pinType)
			if err != nil {
				t.Fatalf("read retry status: %v", err)
			}
			want := piv.PINStatus{Type: test.pinType, RetriesLeft: int(test.remaining), MaxRetries: test.maximum, Blocked: test.remaining == 0}
			if status != want {
				t.Fatalf("retry status = %+v, want %+v", status, want)
			}
			wantCommand := []byte{0x81, 0xCB, 0x3F, 0xFF, 0x05, 0x4D, 0x03, 0xFF, 0x81, byte(test.pinType), 0x00}
			if len(card.TransmittedCommands) != 1 || !bytes.Equal(card.TransmittedCommands[0], wantCommand) {
				t.Fatalf("commands = % X, want only % X", card.TransmittedCommands, wantCommand)
			}
		})
	}
}

func TestSafeNetAdapterPINStatusFallsBackToVerify(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		sw   uint16
	}{
		{name: "metadata unavailable", sw: uint16(iso7816.SwFileNotFound)},
		{name: "malformed metadata", data: []byte{0x9B, 0x01}, sw: uint16(iso7816.SwSuccess)},
		{name: "missing remaining counter", data: []byte{0x9A, 0x01, 0x05}, sw: uint16(iso7816.SwSuccess)},
	}
	for _, pinType := range []piv.PINType{piv.PINTypeCard, piv.PINTypePUK} {
		name := "PIN"
		if pinType == piv.PINTypePUK {
			name = "PUK"
		}
		for _, test := range tests {
			t.Run(name+"/"+test.name, func(t *testing.T) {
				card := emulator.NewCard()
				card.EnqueueResponse(0xCB, test.data, test.sw)
				// A second metadata read would return unrelated management-key counters.
				card.SetSuccessResponse(0xCB, []byte{0x9A, 0x01, 0x10, 0x9B, 0x01, 0x0F})
				card.SetResponse(0x20, nil, 0x63C2)
				session := adapters.NewSession(piv.NewClient(card))
				status, err := NewAdapter().PINStatus(session, pinType)
				if err != nil {
					t.Fatalf("read retry status: %v", err)
				}
				want := piv.PINStatus{Type: pinType, RetriesLeft: 2, MaxRetries: adapters.UnknownRetries}
				if status != want {
					t.Fatalf("retry status = %+v, want %+v", status, want)
				}
				wantVerify := []byte{0x00, 0x20, 0x00, byte(pinType)}
				if len(card.TransmittedCommands) != 2 || card.TransmittedCommands[0][1] != 0xCB || !bytes.Equal(card.TransmittedCommands[1], wantVerify) {
					t.Fatalf("commands = % X, want credential metadata followed by % X", card.TransmittedCommands, wantVerify)
				}
			})
		}
	}
}

func TestSafeNetAdapterPINStatusMatchesLiveTrace(t *testing.T) {
	// Responses captured from the IDPrime PIV v4.00 applet on a SafeNet eToken Fusion.
	card := emulator.NewCard()
	card.EnqueueResponse(0xCB, []byte{
		0xE2, 0x10, 0xA0, 0x0B, 0x8C, 0x04, 0xF0, 0x00, 0x00, 0x00,
		0xA1, 0x03, 0xE0, 0x07, 0x07, 0x83, 0x01, 0x80,
		0x9A, 0x01, 0x05, 0x9B, 0x01, 0x05, 0x99, 0x01, 0xFF,
		0x9C, 0x01, 0xFF, 0x9D, 0x01, 0x81, 0x9E, 0x01, 0xA5,
		0x91, 0x14, 0x00, 0x06, 0x08, 0x01, 0xAA, 0x00, 0x08, 0x08,
		0x55, 0x00, 0x00, 0x08, 0x08, 0x00, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00,
	}, uint16(iso7816.SwSuccess))
	card.EnqueueResponse(0xCB, []byte{
		0xE2, 0x0F, 0xA0, 0x0A, 0x8C, 0x03, 0xD0, 0x00, 0xFF,
		0xA1, 0x03, 0xE0, 0xFF, 0xFF, 0x83, 0x01, 0x81,
		0x9A, 0x01, 0x05, 0x9B, 0x01, 0x05, 0x99, 0x01, 0xFF,
		0x9C, 0x01, 0xFF, 0x9D, 0x01, 0xFF, 0x9E, 0x01, 0xA5,
		0x91, 0x14, 0x00, 0x08, 0x08, 0x00, 0xAA, 0x00, 0x08, 0x08,
		0x55, 0x00, 0x00, 0x08, 0x08, 0x00, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00,
	}, uint16(iso7816.SwSuccess))
	session := adapters.NewSession(piv.NewClient(card))
	for _, pinType := range []piv.PINType{piv.PINTypeCard, piv.PINTypePUK} {
		status, err := NewAdapter().PINStatus(session, pinType)
		if err != nil {
			t.Fatalf("read retry status for %X: %v", pinType, err)
		}
		want := piv.PINStatus{Type: pinType, RetriesLeft: 5, MaxRetries: 5}
		if status != want {
			t.Fatalf("retry status = %+v, want %+v", status, want)
		}
	}
	testtrace.RequireMatchFile(t, "testdata/pin_retry_status_apdu_trace.txt", card.APDULog())
}

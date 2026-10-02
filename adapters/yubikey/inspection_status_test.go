package yubikey

import (
	"errors"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

func TestManagementKeyStatusUnsupportedMetadata(t *testing.T) {
	for _, sw := range []uint16{iso7816.SwInsNotSupported, iso7816.SwClaNotSupported} {
		card := emulator.NewCard()
		card.SetResponse(0xF7, nil, sw)
		status, err := NewAdapter().ManagementKeyStatus(newSlotDescriptionSession(card))
		if err != nil || status.RetriesLeft != adapters.UnlimitedRetries || status.MaxRetries != adapters.UnlimitedRetries || status.Blocked {
			t.Fatalf("GET METADATA %04X: status=%+v err=%v, want unlimited retries", sw, status, err)
		}
		if len(card.TransmittedCommands) != 1 || card.TransmittedCommands[0][3] != byte(piv.SlotManagement) {
			t.Fatalf("status must issue only one management metadata read: %X", card.TransmittedCommands)
		}
	}
}

func TestInspectionMetadataFailuresRemainErrors(t *testing.T) {
	transportErr := errors.New("test transport failure")
	for _, tc := range []struct {
		name         string
		data         []byte
		sw           uint16
		transportErr error
	}{
		{name: "security status", sw: iso7816.SwSecurityNotSatisfied},
		{name: "missing metadata", sw: iso7816.SwReferencedDataNotFound},
		{name: "malformed TLV", data: []byte{0x01}, sw: iso7816.SwSuccess},
		{name: "transport", transportErr: transportErr},
	} {
		for _, operation := range []string{"mgm", "pin", "puk", "public-key"} {
			t.Run(tc.name+"/"+operation, func(t *testing.T) {
				card := emulator.NewCard()
				card.RegisterINSHandler(0xF7, func(_ *emulator.Card, _ []byte) ([]byte, error) {
					if tc.transportErr != nil {
						return nil, tc.transportErr
					}
					return emulator.BuildResponse(tc.data, tc.sw), nil
				})
				// Valid fallback material must not hide a metadata failure.
				card.SetSuccessResponse(0xCB, iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, yubiKeyTestPoint(t)))))
				card.SetResponse(0x20, nil, 0x63C3)
				session := newSlotDescriptionSession(card)
				adapter := NewAdapter()
				var err error
				switch operation {
				case "mgm":
					_, err = adapter.ManagementKeyStatus(session)
				case "pin":
					_, err = adapter.PINStatus(session, piv.PINTypeCard)
				case "puk":
					_, err = adapter.PINStatus(session, piv.PINTypePUK)
				case "public-key":
					_, err = adapter.ReadPublicKey(session, piv.SlotAuthentication)
				}
				if err == nil {
					t.Fatal("expected metadata failure, got nil")
				}
				if tc.transportErr != nil && !errors.Is(err, tc.transportErr) {
					t.Fatalf("transport cause lost: %v", err)
				}
				if tc.sw != 0 && tc.sw != iso7816.SwSuccess && !iso7816.IsStatus(err, tc.sw) {
					t.Fatalf("status cause lost: %v", err)
				}
				if len(card.TransmittedCommands) != 1 || card.TransmittedCommands[0][1] != 0xF7 {
					t.Fatalf("metadata error must stop fallback: %X", card.TransmittedCommands)
				}
			})
		}
	}
}

func TestPUKUnknownUsesOnlyEmptyStatusProbe(t *testing.T) {
	for _, sw := range []uint16{iso7816.SwReferencedDataNotFound, iso7816.SwWrongData} {
		card := emulator.NewCard()
		card.SetResponse(0xF7, nil, iso7816.SwInsNotSupported)
		card.SetResponse(0x20, nil, sw)
		status, err := NewAdapter().PINStatus(newSlotDescriptionSession(card), piv.PINTypePUK)
		if err != nil || status.RetriesLeft != adapters.UnknownRetries || status.MaxRetries != adapters.UnknownRetries {
			t.Fatalf("PUK status %04X: %+v err=%v", sw, status, err)
		}
		if len(card.TransmittedCommands) != 2 {
			t.Fatalf("expected metadata and status reads: %X", card.TransmittedCommands)
		}
		probe, err := iso7816.ParseCommand(card.TransmittedCommands[1])
		if err != nil || probe.Ins != 0x20 || probe.P2 != byte(piv.PINTypePUK) || len(probe.Data) != 0 {
			t.Fatalf("PUK status must be an empty VERIFY, got %+v err=%v", probe, err)
		}
	}
}

func TestPublicKeyFallbackReadsSharedObjectOnce(t *testing.T) {
	for _, sw := range []uint16{iso7816.SwInsNotSupported, iso7816.SwClaNotSupported} {
		card := emulator.NewCard()
		card.SetResponse(0xF7, nil, sw)
		card.SetSuccessResponse(0xCB, iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x70, mustCreateYubiKeyTestCertificate(t))))
		key, err := NewAdapter().ReadPublicKey(newSlotDescriptionSession(card), piv.SlotAuthentication)
		if err != nil || key == nil {
			t.Fatalf("certificate fallback: key=%v err=%v", key, err)
		}
		if len(card.TransmittedCommands) != 2 || card.TransmittedCommands[1][1] != 0xCB {
			t.Fatalf("expected one shared object read after metadata: %X", card.TransmittedCommands)
		}
	}
}

func TestPublicKeyFallbackPreservesMalformedTemplateError(t *testing.T) {
	card := emulator.NewCard()
	inner := append(iso7816.EncodeTLV(0x7F49, []byte{0x86}), iso7816.EncodeTLV(0x70, mustCreateYubiKeyTestCertificate(t))...)
	card.SetSuccessResponse(0xCB, iso7816.EncodeTLV(0x53, inner))
	if key, err := NewAdapter().ReadPublicKey(newSlotDescriptionSession(card), piv.SlotAuthentication); err == nil || key != nil {
		t.Fatalf("malformed template must not be hidden by certificate fallback: key=%v err=%v", key, err)
	}
}

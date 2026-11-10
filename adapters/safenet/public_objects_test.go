package safenet

import (
	"bytes"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

func TestDescribeSlotMissingCardAuthMirrorDoesNotProvePrivateKeyAbsence(t *testing.T) {
	certificate := mustCreateSafeNetTestCertificate(t)
	for _, tc := range []struct {
		name          string
		slot          piv.Slot
		standard      []byte
		standardSW    uint16
		mirrorSW      uint16
		wantKey       adapters.SlotState
		wantCert      adapters.SlotState
		wantReadError bool
	}{
		{name: "missing public objects", slot: piv.SlotCardAuth, standardSW: iso7816.SwFileNotFound, mirrorSW: iso7816.SwWrongData, wantKey: adapters.SlotStateUnknown, wantCert: adapters.SlotStateAbsent},
		{name: "readable standard certificate", slot: piv.SlotCardAuth, standard: buildCertificateObject(certificate), standardSW: iso7816.SwSuccess, mirrorSW: iso7816.SwWrongData, wantKey: adapters.SlotStateUnknown, wantCert: adapters.SlotStatePresent},
		{name: "other mirror wrong data", slot: piv.SlotAuthentication, standardSW: iso7816.SwFileNotFound, mirrorSW: iso7816.SwWrongData, wantKey: adapters.SlotStateError, wantCert: adapters.SlotStateError, wantReadError: true},
		{name: "standard object wrong data", slot: piv.SlotCardAuth, standardSW: iso7816.SwWrongData, mirrorSW: iso7816.SwFileNotFound, wantKey: adapters.SlotStateError, wantCert: adapters.SlotStateError, wantReadError: true},
		{name: "mirror security failure", slot: piv.SlotCardAuth, standardSW: iso7816.SwFileNotFound, mirrorSW: iso7816.SwSecurityNotSatisfied, wantKey: adapters.SlotStateError, wantCert: adapters.SlotStateError, wantReadError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			card := emulator.NewCard()
			card.EnqueueResponse(0xCB, tc.standard, tc.standardSW)
			card.EnqueueResponse(0xCB, nil, tc.mirrorSW)
			description, err := NewAdapter().DescribeSlot(adapters.NewSession(piv.NewClient(card)), tc.slot)
			if err != nil {
				t.Fatal(err)
			}
			if description.KeyState != tc.wantKey || description.CertState != tc.wantCert {
				t.Fatalf("slot states = key %s, certificate %s; want %s, %s", description.KeyState, description.CertState, tc.wantKey, tc.wantCert)
			}
			if (description.KeyError != nil) != tc.wantReadError || (description.CertError != nil) != tc.wantReadError {
				t.Fatalf("unexpected read errors: key=%v, certificate=%v", description.KeyError, description.CertError)
			}
			if !tc.wantReadError && description.KeyUnknownReason != adapters.KeyUnknownReasonUnobservable {
				t.Fatalf("missing public storage must leave private-key presence unobservable: %+v", description)
			}
			if tc.wantCert == adapters.SlotStatePresent && (!bytes.Equal(description.CertDER, certificate) || description.PublicKey == nil) {
				t.Fatal("missing mirror discarded the readable standard certificate or its public key")
			}
			if len(card.TransmittedCommands) != 2 {
				t.Fatalf("GET DATA count = %d, want 2", len(card.TransmittedCommands))
			}
		})
	}
}

func TestCHUIDMissingAliasWrongDataIsPublicObjectAbsence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		standardSW uint16
		aliasSW    uint16
		wantSW     uint16
		wantReads  int
	}{
		{name: "missing alias", standardSW: iso7816.SwFileNotFound, aliasSW: iso7816.SwWrongData, wantSW: iso7816.SwFileNotFound, wantReads: 2},
		{name: "standard wrong data", standardSW: iso7816.SwWrongData, wantSW: iso7816.SwWrongData, wantReads: 1},
		{name: "alias security failure", standardSW: iso7816.SwFileNotFound, aliasSW: iso7816.SwSecurityNotSatisfied, wantSW: iso7816.SwSecurityNotSatisfied, wantReads: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			card := emulator.NewCard()
			card.SetSuccessResponse(0xA4, nil)
			card.EnqueueResponse(0xCB, nil, tc.standardSW)
			card.EnqueueResponse(0xCB, nil, tc.aliasSW)
			data, err := NewAdapter().CHUID(adapters.NewSession(piv.NewClient(card)))
			if len(data) != 0 || !iso7816.IsStatus(err, tc.wantSW) {
				t.Fatalf("CHUID = %X, %v; want status %04X and no public object", data, err, tc.wantSW)
			}
			if len(card.TransmittedCommands) != tc.wantReads+1 {
				t.Fatalf("commands = %d, want SELECT and %d reads", len(card.TransmittedCommands), tc.wantReads)
			}
		})
	}
}

func TestDirectReadersPreserveStandardFailuresWithMissingCardAuthMirror(t *testing.T) {
	for _, tc := range []struct {
		name       string
		standard   []byte
		standardSW uint16
		wantSW     uint16
	}{
		{name: "both public objects missing", standardSW: iso7816.SwFileNotFound, wantSW: iso7816.SwFileNotFound},
		{name: "standard security failure", standardSW: iso7816.SwSecurityNotSatisfied, wantSW: iso7816.SwSecurityNotSatisfied},
		{name: "standard malformed object", standard: []byte{0x53, 0x01, 0x70}, standardSW: iso7816.SwSuccess},
	} {
		for _, reader := range []struct {
			name string
			read func(*Adapter, *adapters.Session) error
		}{
			{name: "certificate", read: func(adapter *Adapter, session *adapters.Session) error {
				_, err := adapter.ReadCertificate(session, piv.SlotCardAuth)
				return err
			}},
			{name: "public key", read: func(adapter *Adapter, session *adapters.Session) error {
				_, err := adapter.ReadPublicKey(session, piv.SlotCardAuth)
				return err
			}},
		} {
			t.Run(tc.name+"/"+reader.name, func(t *testing.T) {
				standardTag, err := piv.ObjectIDForSlot(piv.SlotCardAuth)
				if err != nil {
					t.Fatal(err)
				}
				card := emulator.NewCard()
				card.RegisterINSHandler(0xCB, func(_ *emulator.Card, raw []byte) ([]byte, error) {
					command, err := iso7816.ParseCommand(raw)
					if err != nil {
						return nil, err
					}
					if bytes.Equal(command.Data, iso7816.EncodeTLV(0x5C, iso7816.EncodeTag(standardTag))) {
						return emulator.BuildResponse(tc.standard, tc.standardSW), nil
					}
					return emulator.BuildResponse(nil, uint16(iso7816.SwWrongData)), nil
				})
				err = reader.read(NewAdapter(), adapters.NewSession(piv.NewClient(card)))
				if err == nil {
					t.Fatal("missing mirror must not make the read succeed")
				}
				if tc.wantSW != 0 && !iso7816.IsStatus(err, tc.wantSW) {
					t.Fatalf("read error = %v, want status %04X", err, tc.wantSW)
				}
				if tc.wantSW == 0 && isKeyNotFound(err) {
					t.Fatalf("malformed standard object became public-object absence: %v", err)
				}
			})
		}
	}
}

func TestReadPublicKeyPreservesMalformedFallbackCertificate(t *testing.T) {
	card := emulator.NewCard()
	card.EnqueueResponse(0xCB, nil, iso7816.SwFileNotFound)
	card.EnqueueResponse(0xCB, nil, iso7816.SwWrongData)
	card.EnqueueResponse(0xCB, buildCertificateObject([]byte{0x30, 0x01, 0x00}), iso7816.SwSuccess)
	_, err := NewAdapter().ReadPublicKey(adapters.NewSession(piv.NewClient(card)), piv.SlotCardAuth)
	if err == nil || isKeyNotFound(err) {
		t.Fatalf("malformed fallback certificate became public-object absence: %v", err)
	}
}

package safenet

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/internal/testtrace"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

func TestDescribeSlotMissingPublicObjectsDoNotProvePrivateKeyAbsence(t *testing.T) {
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
		{name: "auth mirror wrong data", slot: piv.SlotAuthentication, standardSW: iso7816.SwFileNotFound, mirrorSW: iso7816.SwWrongData, wantKey: adapters.SlotStateUnknown, wantCert: adapters.SlotStateAbsent},
		{name: "standard object wrong data", slot: piv.SlotCardAuth, standardSW: iso7816.SwWrongData, mirrorSW: iso7816.SwFileNotFound, wantKey: adapters.SlotStateUnknown, wantCert: adapters.SlotStateAbsent},
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

func TestReadPublicObjectNormalizesOnlyKnownSafeNetPublicTags(t *testing.T) {
	for _, tc := range []struct {
		tag       uint
		normalize bool
	}{
		{tag: 0x5FC105, normalize: true},
		{tag: 0x5FC10A, normalize: true},
		{tag: 0x5FC10B, normalize: true},
		{tag: 0x5FC101, normalize: true},
		{tag: 0xFFF305, normalize: true},
		{tag: 0xFFF30A, normalize: true},
		{tag: 0xFFF30B, normalize: true},
		{tag: 0xFFF301, normalize: true},
		{tag: 0xFFF302, normalize: true},
		{tag: 0x5FC102},
		{tag: 0x5FC107},
		{tag: 0x5FC10D},
		{tag: 0xFFF30D},
		{tag: 0xFFF310},
		{tag: 0xFFF303},
		{tag: 0xFF900A},
		{tag: 0xFF900C},
		{tag: 0xFF900D},
		{tag: 0xFF900E},
	} {
		for _, status := range []uint16{iso7816.SwWrongData, iso7816.SwSecurityNotSatisfied, iso7816.SwUnknown} {
			t.Run(fmt.Sprintf("%X/%04X", tc.tag, status), func(t *testing.T) {
				card := emulator.NewCard()
				card.SetResponse(0xCB, nil, status)
				client := piv.NewClient(card)
				_, err := readPublicObject(client, tc.tag)
				wantStatus := status
				if tc.normalize && status == iso7816.SwWrongData {
					wantStatus = iso7816.SwFileNotFound
				}
				if !iso7816.IsStatus(err, wantStatus) {
					t.Fatalf("read public object error = %v, want status %04X", err, wantStatus)
				}
				_, rawErr := client.GetData(tc.tag)
				if !iso7816.IsStatus(rawErr, status) {
					t.Fatalf("raw GET DATA error = %v, want original status %04X", rawErr, status)
				}
			})
		}
	}
}

func TestDescribeSlotsMatchesSafeNetFusionPublicReadTrace(t *testing.T) {
	trace, err := os.ReadFile("testdata/read_public_slots_apdu_trace.txt")
	if err != nil {
		t.Fatal(err)
	}
	card := emulator.NewCard()
	var keyObject []byte
	for _, line := range emulator.ExtractTraceLines(string(trace)) {
		if !strings.HasPrefix(line, "APDU <- ") {
			continue
		}
		raw, err := hex.DecodeString(strings.ReplaceAll(strings.TrimPrefix(line, "APDU <- "), " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		response, err := iso7816.ParseResponse(raw)
		if err != nil {
			t.Fatal(err)
		}
		card.EnqueueResponse(0xCB, response.Data, response.StatusWord())
		if keyObject == nil {
			keyObject = response.Data
		}
	}
	wantKey, err := piv.ParsePublicKeyObject(keyObject)
	if err != nil {
		t.Fatal(err)
	}
	session := adapters.NewSession(piv.NewClient(card))
	for _, slot := range []piv.Slot{piv.SlotAuthentication, piv.SlotSignature, piv.SlotKeyManagement, piv.SlotCardAuth} {
		description, err := NewAdapter().DescribeSlot(session, slot)
		if err != nil || description.KeyError != nil || description.CertError != nil {
			t.Fatalf("slot %s inspection failed: %+v, %v", slot, description, err)
		}
		if description.KeyState != adapters.SlotStateUnknown || description.KeyUnknownReason != adapters.KeyUnknownReasonUnobservable || description.KeyPresent {
			t.Fatalf("slot %s public storage must leave private-key presence unknown: %+v", slot, description)
		}
		if description.CertState != adapters.SlotStateAbsent || description.CertPresent || len(description.CertDER) != 0 {
			t.Fatalf("slot %s must have no readable certificate: %+v", slot, description)
		}
		if slot == piv.SlotAuthentication {
			if description.PublicKey == nil || !publicKeysEqual(description.PublicKey, wantKey) || description.PublicKeySource != adapters.PublicKeySourceStoredTemplate || description.KeyAlgorithm != "eccp256" {
				t.Fatalf("slot 9A stored P-256 template was lost: %+v", description)
			}
		} else if description.PublicKey != nil || description.PublicKeySource != "" {
			t.Fatalf("slot %s unexpectedly has public material: %+v", slot, description)
		}
	}
	testtrace.RequireMatchFile(t, "testdata/read_public_slots_apdu_trace.txt", card.APDULog())
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

func TestReadPublicKeyPreservesDERErrorAfterStandardObjectChanges(t *testing.T) {
	standardTag, err := piv.ObjectIDForSlot(piv.SlotCardAuth)
	if err != nil {
		t.Fatal(err)
	}
	der := []byte{0x30, 0x01, 0x00}
	_, wantErr := x509.ParseCertificate(der)
	standardReads, mirrorReads := 0, 0
	card := emulator.NewCard()
	card.RegisterINSHandler(0xCB, func(_ *emulator.Card, raw []byte) ([]byte, error) {
		command, err := iso7816.ParseCommand(raw)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(command.Data, iso7816.EncodeTLV(0x5C, iso7816.EncodeTag(standardTag))) {
			standardReads++
			if standardReads == 1 {
				return emulator.BuildResponse(nil, iso7816.SwFileNotFound), nil
			}
			return emulator.BuildSuccessResponse(buildCertificateObject(der)), nil
		}
		if bytes.Equal(command.Data, iso7816.EncodeTLV(0x5C, iso7816.EncodeTag(safeNetCardAuthMirrorTag))) {
			mirrorReads++
			return emulator.BuildResponse(nil, iso7816.SwWrongData), nil
		}
		return nil, fmt.Errorf("unexpected GET DATA: %X", command.Data)
	})
	_, err = NewAdapter().ReadPublicKey(adapters.NewSession(piv.NewClient(card)), piv.SlotCardAuth)
	if err == nil || !strings.Contains(err.Error(), wantErr.Error()) {
		t.Fatalf("read error = %v, want changed object's DER error %v", err, wantErr)
	}
	if standardReads != 2 || mirrorReads != 1 {
		t.Fatalf("standard/mirror reads = %d/%d, want initial standard read, mirror probe, and standard certificate fallback", standardReads, mirrorReads)
	}
}

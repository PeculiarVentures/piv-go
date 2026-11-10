package safenet

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

func TestDirectReadersDistinguishEmptyPublicObjects(t *testing.T) {
	certificate := mustCreateSafeNetTestCertificate(t)
	parsedCertificate, err := x509.ParseCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	curve := elliptic.P256()
	keyObject := iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, elliptic.Marshal(curve, curve.Params().Gx, curve.Params().Gy))))
	storedKey, err := piv.ParsePublicKeyObject(keyObject)
	if err != nil {
		t.Fatal(err)
	}
	empty := publicObjectReply{data: []byte{0x53, 0x00}, sw: iso7816.SwSuccess}
	missing := publicObjectReply{sw: iso7816.SwFileNotFound}
	for _, slot := range []piv.Slot{piv.SlotAuthentication, piv.SlotSignature, piv.SlotKeyManagement, piv.SlotCardAuth} {
		for _, tc := range []struct {
			name         string
			standard     publicObjectReply
			mirror       publicObjectReply
			wantCert     bool
			wantKey      bool
			wantTemplate bool
		}{
			{name: "empty standard", standard: empty, mirror: missing},
			{name: "empty mirror", standard: missing, mirror: empty},
			{name: "both empty", standard: empty, mirror: empty},
			{name: "referenced data missing", standard: empty, mirror: publicObjectReply{sw: iso7816.SwReferencedDataNotFound}},
			{name: "standard key only", standard: publicObjectReply{data: keyObject, sw: iso7816.SwSuccess}, mirror: missing, wantKey: true, wantTemplate: true},
			{name: "mirror key only", standard: empty, mirror: publicObjectReply{data: keyObject, sw: iso7816.SwSuccess}, wantKey: true, wantTemplate: true},
			{name: "standard certificate", standard: publicObjectReply{data: buildCertificateObject(certificate), sw: iso7816.SwSuccess}, mirror: missing, wantCert: true, wantKey: true},
			{name: "mirror certificate", standard: empty, mirror: publicObjectReply{data: buildCertificateObject(certificate), sw: iso7816.SwSuccess}, wantCert: true, wantKey: true},
			{name: "mirror template preferred to standard certificate", standard: publicObjectReply{data: buildCertificateObject(certificate), sw: iso7816.SwSuccess}, mirror: publicObjectReply{data: keyObject, sw: iso7816.SwSuccess}, wantCert: true, wantKey: true, wantTemplate: true},
			{name: "standard template with mirror certificate", standard: publicObjectReply{data: keyObject, sw: iso7816.SwSuccess}, mirror: publicObjectReply{data: buildCertificateObject(certificate), sw: iso7816.SwSuccess}, wantCert: true, wantKey: true, wantTemplate: true},
		} {
			t.Run(slot.String()+"/"+tc.name, func(t *testing.T) {
				adapter := NewAdapter()
				cert, certErr := adapter.ReadCertificate(publicObjectSession(t, slot, tc.standard, tc.mirror), slot)
				if tc.wantCert {
					if certErr != nil || !bytes.Equal(cert, certificate) {
						t.Fatalf("certificate = %X, %v; want readable certificate", cert, certErr)
					}
				} else if !isKeyNotFound(certErr) || len(cert) != 0 {
					t.Fatalf("certificate = %X, %v; want public-object absence", cert, certErr)
				}
				key, keyErr := adapter.ReadPublicKey(publicObjectSession(t, slot, tc.standard, tc.mirror), slot)
				if tc.wantKey {
					wantKey := parsedCertificate.PublicKey
					if tc.wantTemplate {
						wantKey = storedKey
					}
					if keyErr != nil || !publicKeysEqual(key, wantKey) {
						t.Fatalf("public key = %v, %v; want readable public key", key, keyErr)
					}
				} else if !isKeyNotFound(keyErr) || key != nil {
					t.Fatalf("public key = %v, %v; want public-object absence", key, keyErr)
				}
				description, err := adapter.DescribeSlot(publicObjectSession(t, slot, tc.standard, tc.mirror), slot)
				if err != nil || description.KeyState != adapters.SlotStateUnknown || description.KeyUnknownReason != adapters.KeyUnknownReasonUnobservable {
					t.Fatalf("public storage must not prove private-key absence: %+v, %v", description, err)
				}
				wantCertState := adapters.SlotStateAbsent
				if tc.wantCert {
					wantCertState = adapters.SlotStatePresent
				}
				if description.CertState != wantCertState {
					t.Fatalf("certificate state = %s, want %s", description.CertState, wantCertState)
				}
			})
		}
	}
}

func TestDirectReadersPreservePublicObjectFailuresForAllSlots(t *testing.T) {
	transportErr := errors.New("test card disconnected")
	for _, slot := range []piv.Slot{piv.SlotAuthentication, piv.SlotSignature, piv.SlotKeyManagement, piv.SlotCardAuth} {
		for _, tc := range []struct {
			name  string
			reply publicObjectReply
		}{
			{name: "access denied", reply: publicObjectReply{sw: iso7816.SwSecurityNotSatisfied}},
			{name: "wrong data", reply: publicObjectReply{sw: iso7816.SwWrongData}},
			{name: "transport failure", reply: publicObjectReply{err: transportErr}},
			{name: "malformed TLV", reply: publicObjectReply{data: []byte{0x53, 0x01, 0x70}, sw: iso7816.SwSuccess}},
			{name: "unexpected tag", reply: publicObjectReply{data: iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x42, nil)), sw: iso7816.SwSuccess}},
			{name: "duplicate key template", reply: publicObjectReply{data: iso7816.EncodeTLV(0x53, []byte{0x7F, 0x49, 0x00, 0x7F, 0x49, 0x00}), sw: iso7816.SwSuccess}},
		} {
			for _, source := range []string{"standard", "mirror"} {
				if source == "mirror" && slot == piv.SlotCardAuth && tc.reply.sw == iso7816.SwWrongData {
					continue
				}
				for _, other := range []struct {
					name  string
					reply publicObjectReply
				}{
					{name: "other missing", reply: publicObjectReply{sw: iso7816.SwFileNotFound}},
					{name: "other empty", reply: publicObjectReply{data: []byte{0x53, 0x00}, sw: iso7816.SwSuccess}},
				} {
					t.Run(slot.String()+"/"+source+"/"+tc.name+"/"+other.name, func(t *testing.T) {
						standard, mirror := other.reply, other.reply
						if source == "standard" {
							standard = tc.reply
						} else {
							mirror = tc.reply
						}
						_, certErr := NewAdapter().ReadCertificate(publicObjectSession(t, slot, standard, mirror), slot)
						_, keyErr := NewAdapter().ReadPublicKey(publicObjectSession(t, slot, standard, mirror), slot)
						for _, err := range []error{certErr, keyErr} {
							if err == nil || isKeyNotFound(err) {
								t.Fatalf("public-object failure became absence or success: certificate=%v, key=%v", certErr, keyErr)
							}
							if tc.reply.sw != iso7816.SwSuccess && tc.reply.sw != 0 && !iso7816.IsStatus(err, tc.reply.sw) {
								t.Fatalf("read error = %v, want status %04X", err, tc.reply.sw)
							}
							if tc.reply.err != nil && !errors.Is(err, tc.reply.err) {
								t.Fatalf("read error = %v, want transport error %v", err, tc.reply.err)
							}
						}
					})
				}
			}
		}
	}
}

func TestReadPublicKeyPreservesCertificateDERErrorForAllSlots(t *testing.T) {
	der := []byte{0x30, 0x01, 0x00}
	_, wantErr := x509.ParseCertificate(der)
	for _, slot := range []piv.Slot{piv.SlotAuthentication, piv.SlotSignature, piv.SlotKeyManagement, piv.SlotCardAuth} {
		for _, source := range []string{"standard", "mirror"} {
			t.Run(slot.String()+"/"+source, func(t *testing.T) {
				standard, mirror := publicObjectReply{sw: iso7816.SwFileNotFound}, publicObjectReply{sw: iso7816.SwFileNotFound}
				certificate := publicObjectReply{data: buildCertificateObject(der), sw: iso7816.SwSuccess}
				if source == "standard" {
					standard = certificate
				} else {
					mirror = certificate
				}
				_, err := NewAdapter().ReadPublicKey(publicObjectSession(t, slot, standard, mirror), slot)
				if err == nil || !strings.Contains(err.Error(), wantErr.Error()) {
					t.Fatalf("read error = %v, want certificate DER error %v", err, wantErr)
				}
			})
		}
	}
}

func TestDirectReadersMissingCardAuthMirrorWithEmptyStandard(t *testing.T) {
	standard := publicObjectReply{data: []byte{0x53, 0x00}, sw: iso7816.SwSuccess}
	mirror := publicObjectReply{sw: iso7816.SwWrongData}
	_, certErr := NewAdapter().ReadCertificate(publicObjectSession(t, piv.SlotCardAuth, standard, mirror), piv.SlotCardAuth)
	_, keyErr := NewAdapter().ReadPublicKey(publicObjectSession(t, piv.SlotCardAuth, standard, mirror), piv.SlotCardAuth)
	if !isKeyNotFound(certErr) || !isKeyNotFound(keyErr) {
		t.Fatalf("empty card-auth public storage = certificate %v, key %v; want absence", certErr, keyErr)
	}
}

type publicObjectReply struct {
	data []byte
	sw   uint16
	err  error
}

func publicObjectSession(t *testing.T, slot piv.Slot, standard, mirror publicObjectReply) *adapters.Session {
	t.Helper()
	standardTag, err := piv.ObjectIDForSlot(slot)
	if err != nil {
		t.Fatal(err)
	}
	mirrorTag, err := mirrorObjectTag(slot)
	if err != nil {
		t.Fatal(err)
	}
	card := emulator.NewCard()
	card.RegisterINSHandler(0xCB, func(_ *emulator.Card, raw []byte) ([]byte, error) {
		command, err := iso7816.ParseCommand(raw)
		if err != nil {
			return nil, err
		}
		for tag, reply := range map[uint]publicObjectReply{standardTag: standard, mirrorTag: mirror} {
			if bytes.Equal(command.Data, iso7816.EncodeTLV(0x5C, iso7816.EncodeTag(tag))) {
				return emulator.BuildResponse(reply.data, reply.sw), reply.err
			}
		}
		return nil, fmt.Errorf("unexpected GET DATA: %X", command.Data)
	})
	return adapters.NewSession(piv.NewClient(card))
}

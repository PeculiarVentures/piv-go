package piv

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
)

func rsaSignChallenge(t *testing.T, card *emulator.Card) []byte {
	t.Helper()
	var payload []byte
	for _, raw := range card.TransmittedCommands {
		command, err := iso7816.ParseCommand(raw)
		if err != nil {
			t.Fatal(err)
		}
		if command.Ins != 0x87 {
			t.Fatalf("unexpected command INS %02X", command.Ins)
		}
		payload = append(payload, command.Data...)
	}
	outer, err := iso7816.ParseAllTLV(payload)
	if err != nil {
		t.Fatal(err)
	}
	template := iso7816.FindTag(outer, 0x7C)
	if template == nil {
		t.Fatal("missing GENERAL AUTHENTICATE template")
	}
	inner, err := iso7816.ParseAllTLV(template.Value)
	if err != nil {
		t.Fatal(err)
	}
	challenge := iso7816.FindTag(inner, 0x81)
	if challenge == nil {
		t.Fatal("missing RSA challenge")
	}
	return challenge.Value
}

func TestSignPadsLegacyRSAAndPreservesEncodedBlocks(t *testing.T) {
	digest := sha256.Sum256([]byte("hello"))
	digestInfo := append(append([]byte(nil), sha256DigestInfoPrefix...), digest[:]...)
	for _, tc := range []struct {
		name      string
		alg       byte
		modulus   int
		data      []byte
		mode      RSASignHashMode
		wantTail  []byte
		passBlock bool
	}{
		{name: "RSA1024 raw", alg: AlgRSA1024, modulus: 128, data: []byte("hello"), mode: RSASignHashNone, wantTail: []byte("hello")},
		{name: "RSA2048 raw DigestInfo", alg: AlgRSA2048, modulus: 256, data: digestInfo, mode: RSASignHashNone, wantTail: digestInfo},
		{name: "RSA2048 SHA256 digest", alg: AlgRSA2048, modulus: 256, data: digest[:], mode: RSASignHashSHA256, wantTail: digestInfo},
		{name: "RSA2048 encoded block", alg: AlgRSA2048, modulus: 256, data: append([]byte{0x00, 0x02}, bytes.Repeat([]byte{0x42}, 254)...), mode: RSASignHashNone, passBlock: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			card := emulator.NewCard()
			card.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, []byte{0x01})))
			if _, err := NewClient(card).Sign(tc.alg, SlotSignature, tc.data, tc.mode); err != nil {
				t.Fatal(err)
			}
			challenge := rsaSignChallenge(t, card)
			if len(challenge) != tc.modulus {
				t.Fatalf("challenge has %d bytes, want %d", len(challenge), tc.modulus)
			}
			if tc.passBlock {
				if !bytes.Equal(challenge, tc.data) {
					t.Fatal("pre-encoded block was changed")
				}
				return
			}
			if challenge[0] != 0 || challenge[1] != 1 || !bytes.Equal(challenge[len(challenge)-len(tc.wantTail):], tc.wantTail) {
				t.Fatal("PKCS#1 v1.5 challenge has wrong header or payload")
			}
		})
	}
}

func TestVerifyPINPreservesRetryStatus(t *testing.T) {
	card := emulator.NewCard()
	card.SetResponse(0x20, nil, 0x63C2)
	client := NewClient(card)
	for _, verify := range []func() error{
		func() error { return client.VerifyPIN("000000") },
		func() error { return client.VerifyPINWithType(PINTypeCard, "000000") },
	} {
		err := verify()
		if !iso7816.IsStatus(err, 0x63C2) {
			t.Fatalf("wrong PIN status lost: %v", err)
		}
	}
}

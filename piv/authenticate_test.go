package piv

import (
	"testing"

	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
)

// neoAuthenticateCard returns a YubiKey NEO-profile card: extended-length
// AUTHENTICATE commands are rejected with 6700 while chained short APDUs
// succeed, with the final CLA 0x00 chunk answering the 7C{82 ...} template.
func neoAuthenticateCard(response []byte) *emulator.Card {
	card := emulator.NewCard()
	card.RegisterINSHandler(0x87, func(_ *emulator.Card, command []byte) ([]byte, error) {
		if len(command) >= 5 && command[4] == 0x00 {
			return emulator.BuildResponse(nil, uint16(iso7816.SwWrongLength)), nil
		}
		if len(command) > 0 && command[0] == 0x10 {
			return emulator.BuildSuccessResponse(nil), nil
		}
		return emulator.BuildSuccessResponse(response), nil
	})
	return card
}

func TestClient_AuthenticateRSAChainsOversizedChallengeOnNEO(t *testing.T) {
	// A 256-byte RSA challenge exceeds the short-APDU limit once wrapped
	// in the 7C template: it must go out as chained short APDUs (CLA 0x10
	// intermediates), never as one extended-length AUTHENTICATE that
	// legacy firmware rejects with 6700. The challenge bytes themselves
	// are untouched: no padding is applied on this path.
	for _, algorithm := range []byte{AlgRSA1024, AlgRSA2048} {
		challenge := make([]byte, 256)
		for i := range challenge {
			challenge[i] = byte(i)
		}
		sig := make([]byte, 256)
		for i := range sig {
			sig[i] = byte(0xA5)
		}
		card := neoAuthenticateCard(iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, sig)))
		got, err := NewClient(card).Authenticate(algorithm, SlotSignature, challenge)
		if err != nil {
			t.Fatalf("alg 0x%02X: Authenticate() error = %v", algorithm, err)
		}
		if string(got) != string(sig) {
			t.Fatalf("alg 0x%02X: unexpected response %X", algorithm, got)
		}
		var payload []byte
		for index, raw := range card.TransmittedCommands {
			if len(raw) < 2 || raw[1] != 0x87 {
				t.Fatalf("alg 0x%02X: unexpected INS in %X", algorithm, raw)
			}
			if len(raw) >= 5 && raw[4] == 0x00 {
				t.Fatalf("alg 0x%02X: AUTHENTICATE must use short APDUs, got extended-length header: %X", algorithm, raw[:7])
			}
			command, err := iso7816.ParseCommand(raw)
			if err != nil {
				t.Fatalf("alg 0x%02X: parse command %d: %v", algorithm, index, err)
			}
			if command.P1 != algorithm || command.P2 != byte(SlotSignature) {
				t.Fatalf("alg 0x%02X: unexpected header: %X", algorithm, raw[:4])
			}
			if index < len(card.TransmittedCommands)-1 && command.Cla != 0x10 {
				t.Fatalf("alg 0x%02X: intermediate chunk %d must use CLA 0x10, got %02X", algorithm, index, command.Cla)
			}
			payload = append(payload, command.Data...)
		}
		if len(card.TransmittedCommands) < 2 {
			t.Fatalf("alg 0x%02X: expected chained AUTHENTICATE, got %d commands", algorithm, len(card.TransmittedCommands))
		}
		final, err := iso7816.ParseCommand(card.TransmittedCommands[len(card.TransmittedCommands)-1])
		if err != nil {
			t.Fatalf("alg 0x%02X: parse final AUTHENTICATE: %v", algorithm, err)
		}
		if final.Cla != 0x00 {
			t.Fatalf("alg 0x%02X: final chunk must use CLA 0x00, got %02X", algorithm, final.Cla)
		}
		outer, err := iso7816.ParseAllTLV(payload)
		if err != nil {
			t.Fatalf("alg 0x%02X: parse outer: %v", algorithm, err)
		}
		auth := iso7816.FindTag(outer, 0x7C)
		if auth == nil {
			t.Fatalf("alg 0x%02X: 0x7C not found in %X", algorithm, payload)
		}
		inner, err := iso7816.ParseAllTLV(auth.Value)
		if err != nil {
			t.Fatalf("alg 0x%02X: parse inner: %v", algorithm, err)
		}
		gotChallenge := iso7816.FindTag(inner, 0x81)
		if gotChallenge == nil || string(gotChallenge.Value) != string(challenge) {
			t.Fatal("0x81 challenge must carry the challenge verbatim")
		}
	}
}

func TestClient_AuthenticateSmallChallengeStaysSingleAPDU(t *testing.T) {
	challenge := []byte{0x01, 0x02, 0x03}
	card := neoAuthenticateCard(iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, []byte{0xAA})))
	if _, err := NewClient(card).Authenticate(AlgRSA2048, SlotSignature, challenge); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if len(card.TransmittedCommands) != 1 {
		t.Fatalf("expected 1 command, got %d", len(card.TransmittedCommands))
	}
	command, err := iso7816.ParseCommand(card.TransmittedCommands[0])
	if err != nil {
		t.Fatalf("parse command: %v", err)
	}
	if command.Cla != 0x00 || command.Ins != 0x87 {
		t.Fatalf("unexpected header: %X", card.TransmittedCommands[0][:4])
	}
}

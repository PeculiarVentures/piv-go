package yubikey

import (
	"bytes"
	"crypto/mlkem"
	"testing"

	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

func TestYubiKeyAdapterGenerateKeyPQC(t *testing.T) {
	tests := []struct {
		name      string
		algorithm byte
		response  []byte
	}{
		{
			name:      "rsa3072",
			algorithm: piv.AlgRSA3072,
			response: iso7816.EncodeTLV(0x7F49, append(
				iso7816.EncodeTLV(0x81, append([]byte{0x80}, bytes.Repeat([]byte{0x55}, 383)...)),
				iso7816.EncodeTLV(0x82, []byte{0x01, 0x00, 0x01})...,
			)),
		},
		{name: "ed25519", algorithm: piv.AlgEd25519, response: iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, bytes.Repeat([]byte{0x41}, 32)))},
		{name: "x25519", algorithm: piv.AlgX25519, response: iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, bytes.Repeat([]byte{0x42}, 32)))},
		{name: "mldsa44", algorithm: piv.AlgMLDSA44, response: iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x87, bytes.Repeat([]byte{0x43}, 1312)))},
		{name: "mlkem768", algorithm: piv.AlgMLKEM768, response: iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x88, bytes.Repeat([]byte{0x47}, 1184)))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mock := emulator.NewCard()
			enqueueManagementAuth(mock)
			mock.SetSuccessResponse(0x47, test.response)
			mock.SetSuccessResponse(0xDB, nil)
			if _, err := NewAdapter().GenerateKey(newYubiKeyPolicySession(mock), piv.SlotSignature, test.algorithm, 0x00, 0x00); err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}
			if findCommand(mock, 0x47) == nil {
				t.Fatal("expected GENERATE ASYMMETRIC KEY PAIR command")
			}
			if findCommand(mock, 0xDB) == nil {
				t.Fatal("expected PUT DATA storing the generated public key")
			}
		})
	}
}

func TestYubiKeyAdapterImportKeyPQC(t *testing.T) {
	t.Run("ed25519 raw seed tag 07", func(t *testing.T) {
		seed := bytes.Repeat([]byte{0xAB}, 32)
		mock := emulator.NewCard()
		enqueueManagementAuth(mock)
		mock.SetSuccessResponse(InsImportKey, nil)
		mock.SetSuccessResponse(0xDB, nil)
		if err := NewAdapter().ImportKey(newYubiKeyPolicySession(mock), piv.SlotSignature, piv.AlgEd25519, &piv.OpaquePrivateKey{Algorithm: piv.AlgEd25519, Raw: seed}, 0x00, 0x00); err != nil {
			t.Fatalf("ImportKey() error = %v", err)
		}
		cmd := findCommand(mock, InsImportKey)
		if cmd == nil {
			t.Fatal("expected IMPORT KEY command")
		}
		if cmd[2] != piv.AlgEd25519 {
			t.Fatalf("P1 = 0x%02X, want 0xE0", cmd[2])
		}
	})
	t.Run("x25519 raw seed tag 08", func(t *testing.T) {
		seed := bytes.Repeat([]byte{0xCD}, 32)
		mock := emulator.NewCard()
		enqueueManagementAuth(mock)
		mock.SetSuccessResponse(InsImportKey, nil)
		mock.SetSuccessResponse(0xDB, nil)
		if err := NewAdapter().ImportKey(newYubiKeyPolicySession(mock), piv.SlotKeyManagement, piv.AlgX25519, seed, 0x00, 0x00); err != nil {
			t.Fatalf("ImportKey() error = %v", err)
		}
		if findCommand(mock, InsImportKey) == nil {
			t.Fatal("expected IMPORT KEY command")
		}
	})
	t.Run("mlkem768 seed tag 0A stores derived ek", func(t *testing.T) {
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			t.Fatalf("GenerateKey768() error = %v", err)
		}
		seed := dk.Bytes()
		wantEK := dk.EncapsulationKey().Bytes()
		mock := emulator.NewCard()
		enqueueManagementAuth(mock)
		mock.SetSuccessResponse(InsImportKey, nil)
		mock.SetSuccessResponse(0xDB, nil)
		if err := NewAdapter().ImportKey(newYubiKeyPolicySession(mock), piv.SlotKeyManagement, piv.AlgMLKEM768, &piv.OpaquePrivateKey{Algorithm: piv.AlgMLKEM768, Raw: seed}, 0x00, 0x00); err != nil {
			t.Fatalf("ImportKey() error = %v", err)
		}
		cmd := findCommand(mock, InsImportKey)
		if cmd == nil {
			t.Fatal("expected IMPORT KEY command")
		}
		if cmd[2] != piv.AlgMLKEM768 {
			t.Fatalf("P1 = 0x%02X, want 0xE6", cmd[2])
		}
		parsed, err := iso7816.ParseCommand(cmd)
		if err != nil {
			t.Fatalf("parse import: %v", err)
		}
		tlvs, _ := iso7816.ParseAllTLV(parsed.Data)
		if field := iso7816.FindTag(tlvs, 0x0A); field == nil || !bytes.Equal(field.Value, seed) {
			t.Fatalf("tag 0x0A must carry the 64-byte seed in %X", parsed.Data[:16])
		}
		// The stored slot object must carry the derived encapsulation
		// key under tag 0x88. Large keys span chunked PUT DATA writes,
		// so concatenate every parsed 0xDB payload before searching.
		var stored []byte
		for _, raw := range mock.TransmittedCommands {
			if len(raw) > 1 && raw[1] == 0xDB {
				chunk, err := iso7816.ParseCommand(raw)
				if err != nil {
					t.Fatalf("parse PUT DATA: %v", err)
				}
				stored = append(stored, chunk.Data...)
			}
		}
		if len(stored) == 0 {
			t.Fatal("expected PUT DATA storing the imported public key")
		}
		if !bytes.Contains(stored, wantEK) {
			t.Fatal("stored slot object must contain the derived encapsulation key")
		}
	})
}

func TestYubiKeyAdapterCalculateSecret(t *testing.T) {
	peer := bytes.Repeat([]byte{0x11}, 32)
	secret := bytes.Repeat([]byte{0x22}, 32)
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, secret)))
	got, err := NewAdapter().CalculateSecret(newYubiKeyPolicySession(mock), piv.SlotKeyManagement, peer)
	if err != nil {
		t.Fatalf("CalculateSecret() error = %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("secret must round-trip verbatim")
	}
	cmd := findCommand(mock, 0x87)
	if cmd == nil {
		t.Fatal("expected GENERAL AUTHENTICATE command")
	}
	if cmd[2] != piv.AlgX25519 {
		t.Fatalf("P1 = 0x%02X, want 0xE1", cmd[2])
	}
}

func TestYubiKeyAdapterDecapsulate(t *testing.T) {
	ciphertext := bytes.Repeat([]byte{0xC7}, 1088)
	secret := bytes.Repeat([]byte{0x5E}, 32)
	mock := emulator.NewCard()
	mock.SetSuccessResponse(0x87, iso7816.EncodeTLV(0x7C, iso7816.EncodeTLV(0x82, secret)))
	got, err := NewAdapter().Decapsulate(newYubiKeyPolicySession(mock), piv.SlotKeyManagement, piv.AlgMLKEM768, ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate() error = %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("secret must round-trip verbatim")
	}
	cmd := findCommand(mock, 0x87)
	if cmd == nil {
		t.Fatal("expected GENERAL AUTHENTICATE command")
	}
	if cmd[2] != piv.AlgMLKEM768 {
		t.Fatalf("P1 = 0x%02X, want 0xE6", cmd[2])
	}
	// Wrong ciphertext length rejects before any APDU.
	bad := emulator.NewCard()
	if _, err := NewAdapter().Decapsulate(newYubiKeyPolicySession(bad), piv.SlotKeyManagement, piv.AlgMLKEM768, []byte{0x01}); err == nil {
		t.Fatal("expected error for short ciphertext")
	}
	if len(bad.TransmittedCommands) != 0 {
		t.Fatalf("no APDU must be sent on rejection, got %d commands", len(bad.TransmittedCommands))
	}
}

func TestYubiKeyAdapterDeleteKeyClearsStaleTemplate(t *testing.T) {
	// F2 regression: generate stores a public key template in the slot
	// object; delete must clear it so later inspection reports the slot
	// empty and key public reports absent instead of stale bytes.
	seed := bytes.Repeat([]byte{0xA5}, 32)
	mock := emulator.NewCard()
	enqueueManagementAuth(mock)
	mock.SetSuccessResponse(0x47, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, seed)))
	mock.SetSuccessResponse(0xDB, nil)
	if _, err := NewAdapter().GenerateKey(newYubiKeyPolicySession(mock), piv.SlotSignature, piv.AlgEd25519, 0x00, 0x00); err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	enqueueManagementAuth(mock)
	mock.SetSuccessResponse(0xF6, nil)
	if err := NewAdapter().DeleteKey(newYubiKeyPolicySession(mock), piv.SlotSignature); err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}

	// The card now holds an empty slot object and metadata reports the slot
	// empty (GET METADATA 0xF7 answers "not found").
	cleared := emulator.NewCard()
	cleared.SetResponse(0xF7, nil, uint16(iso7816.SwFileNotFound))
	cleared.SetSuccessResponse(0xCB, iso7816.EncodeTLV(0x53, nil))
	session := newYubiKeyPolicySession(cleared)
	description, err := NewAdapter().DescribeSlot(session, piv.SlotSignature)
	if err != nil {
		t.Fatalf("DescribeSlot() error = %v", err)
	}
	if description.KeyPresent {
		t.Fatal("slot must report no key after generate->delete")
	}
	if description.CertPresent {
		t.Fatal("slot must report no certificate after generate->delete")
	}
	if _, err := NewAdapter().ReadPublicKey(session, piv.SlotSignature); err == nil {
		t.Fatal("ReadPublicKey() must fail on the cleared slot")
	}
}

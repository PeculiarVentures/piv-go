package yubikey

import (
	"bytes"
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

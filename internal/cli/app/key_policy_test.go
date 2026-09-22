package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/piv"
)

func TestParsePINPolicy(t *testing.T) {
	tests := []struct {
		input string
		want  byte
	}{
		{input: "", want: piv.PinPolicyDefault},
		{input: "default", want: piv.PinPolicyDefault},
		{input: "never", want: piv.PinPolicyNever},
		{input: "once", want: piv.PinPolicyOnce},
		{input: "always", want: piv.PinPolicyAlways},
	}
	for _, test := range tests {
		if got, err := ParsePINPolicy(test.input); err != nil || got != test.want {
			t.Fatalf("ParsePINPolicy(%q) = 0x%02X, %v; want 0x%02X", test.input, got, err, test.want)
		}
	}
	if _, err := ParsePINPolicy("sometimes"); err == nil {
		t.Fatal("expected error for unsupported PIN policy")
	}
}

func TestParseTouchPolicy(t *testing.T) {
	tests := []struct {
		input string
		want  byte
	}{
		{input: "", want: piv.TouchPolicyDefault},
		{input: "default", want: piv.TouchPolicyDefault},
		{input: "never", want: piv.TouchPolicyNever},
		{input: "always", want: piv.TouchPolicyAlways},
		{input: "cached", want: piv.TouchPolicyCached},
	}
	for _, test := range tests {
		if got, err := ParseTouchPolicy(test.input); err != nil || got != test.want {
			t.Fatalf("ParseTouchPolicy(%q) = 0x%02X, %v; want 0x%02X", test.input, got, err, test.want)
		}
	}
	if _, err := ParseTouchPolicy("sometimes"); err == nil {
		t.Fatal("expected error for unsupported touch policy")
	}
}

func TestParsePrivateKeyData(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	sec1DER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal SEC1: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pkcs1DER := x509.MarshalPKCS1PrivateKey(rsaKey)

	inputs := map[string][]byte{
		"pkcs8-pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}),
		"pkcs8-der": pkcs8DER,
		"sec1-pem":  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1DER}),
		"sec1-der":  sec1DER,
		"pkcs1-pem": pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1DER}),
		"pkcs1-der": pkcs1DER,
	}
	for name, input := range inputs {
		key, err := ParsePrivateKeyData(input)
		if err != nil {
			t.Fatalf("%s: ParsePrivateKeyData() error = %v", name, err)
		}
		switch key.(type) {
		case *ecdsa.PrivateKey, *rsa.PrivateKey:
		default:
			t.Fatalf("%s: unexpected key type %T", name, key)
		}
	}
	if _, err := ParsePrivateKeyData([]byte("not a key")); err == nil {
		t.Fatal("expected error for invalid private key input")
	}
}

func TestKeyImportRejectsUnsupportedAlgorithm(t *testing.T) {
	service := NewMutationService(nil, nil, bytes.NewReader(nil), &bytes.Buffer{})
	_, err := service.KeyImport(context.Background(), KeyImportRequest{Slot: piv.SlotSignature, Algorithm: piv.AlgECCP384, AlgorithmName: "p384", Path: "missing.pem"})
	if err == nil {
		t.Fatal("expected error for unsupported import algorithm")
	}
}

func TestKeyImportRejectsKeyMismatch(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "rsa.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	service := NewMutationService(nil, nil, bytes.NewReader(nil), &bytes.Buffer{})
	_, err = service.KeyImport(context.Background(), KeyImportRequest{Slot: piv.SlotSignature, Algorithm: piv.AlgECCP256, AlgorithmName: "p256", Path: path})
	if err == nil {
		t.Fatal("expected key mismatch error")
	}
}

func TestGenerateKeyPairWithPoliciesRejectsPoliciesOnStandardToken(t *testing.T) {
	runtime := adapters.NewRuntime(&adapters.Session{}, nil)
	if _, err := generateKeyPairWithPolicies(runtime, piv.SlotSignature, piv.AlgECCP256, piv.PinPolicyOnce, piv.TouchPolicyDefault); err == nil {
		t.Fatal("expected unsupported error for non-default policies on standard token")
	}
}

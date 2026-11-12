package adapters

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"

	"github.com/PeculiarVentures/piv-go/piv"
)

func signingBuilderRSA(bits int) *rsa.PublicKey {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Add(n, big.NewInt(1))
	return &rsa.PublicKey{N: n, E: 65537}
}

func signingBuilderEC(curve elliptic.Curve) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).Set(curve.Params().Gx), Y: new(big.Int).Set(curve.Params().Gy)}
}

// The same field width and a claimed name cannot substitute for curve identity.
type signingBuilderOtherCurve struct{ elliptic.Curve }

func TestSigningKeyFromPublicKeyUsesExactParameters(t *testing.T) {
	ed := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	tests := []struct {
		name string
		key  crypto.PublicKey
		want SigningKey
	}{
		{"RSA1024", signingBuilderRSA(1024), SigningKey{Family: SigningKeyRSA, RSABits: 1024}},
		{"RSA2048", signingBuilderRSA(2048), SigningKey{Family: SigningKeyRSA, RSABits: 2048}},
		{"RSA3072", signingBuilderRSA(3072), SigningKey{Family: SigningKeyRSA, RSABits: 3072}},
		{"RSA4096", signingBuilderRSA(4096), SigningKey{Family: SigningKeyRSA, RSABits: 4096}},
		{"P256", signingBuilderEC(elliptic.P256()), SigningKey{Family: SigningKeyEC, CurveOID: SigningCurveP256}},
		{"P384", signingBuilderEC(elliptic.P384()), SigningKey{Family: SigningKeyEC, CurveOID: SigningCurveP384}},
		{"P521 public preparation", signingBuilderEC(elliptic.P521()), SigningKey{Family: SigningKeyEC, CurveOID: SigningCurveP521}},
		{"Ed25519", ed, SigningKey{Family: SigningKeyEdDSA, CurveOID: SigningCurveEd25519}},
		{"opaque Ed25519", &piv.OpaquePublicKey{Algorithm: piv.AlgEd25519, Raw: ed}, SigningKey{Family: SigningKeyEdDSA, CurveOID: SigningCurveEd25519}},
		{"opaque value Ed25519", piv.OpaquePublicKey{Algorithm: piv.AlgEd25519, Raw: ed}, SigningKey{Family: SigningKeyEdDSA, CurveOID: SigningCurveEd25519}},
	}
	for _, variant := range []struct {
		algorithm byte
		set       int
	}{{piv.AlgMLDSA44, 44}, {piv.AlgMLDSA65, 65}, {piv.AlgMLDSA87, 87}} {
		size, _ := piv.MLDSAPublicKeyLength(variant.algorithm)
		tests = append(tests, struct {
			name string
			key  crypto.PublicKey
			want SigningKey
		}{
			"MLDSA" + big.NewInt(int64(variant.set)).String(),
			&piv.OpaquePublicKey{Algorithm: variant.algorithm, Raw: make([]byte, size)},
			SigningKey{Family: SigningKeyMLDSA, MLDSAParameterSet: variant.set},
		})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := SigningKeyFromPublicKey(test.key)
			if err != nil || got != test.want {
				t.Fatalf("got %+v, %v; want %+v", got, err, test.want)
			}
		})
	}
}

func TestSigningKeyFromPublicKeyRejectsMalformedAndAmbiguousKeys(t *testing.T) {
	badExponent := signingBuilderRSA(2048)
	badExponent.E = 2
	badModulus := signingBuilderRSA(2048)
	badModulus.N.SetBit(badModulus.N, 0, 0)
	otherCurve := signingBuilderEC(elliptic.P256())
	otherCurve.Curve = signingBuilderOtherCurve{elliptic.P256()}
	for _, key := range []crypto.PublicKey{
		nil, (*rsa.PublicKey)(nil), &rsa.PublicKey{}, badExponent, badModulus, signingBuilderRSA(2047),
		(*ecdsa.PublicKey)(nil), &ecdsa.PublicKey{},
		&ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)}, otherCurve,
		ed25519.PublicKey(nil), ed25519.PublicKey(make([]byte, 31)),
		(*piv.OpaquePublicKey)(nil), &piv.OpaquePublicKey{Raw: make([]byte, 32)},
		&piv.OpaquePublicKey{Algorithm: piv.AlgX25519, Raw: make([]byte, 32)},
		&piv.OpaquePublicKey{Algorithm: piv.AlgEd25519, Raw: make([]byte, 33)},
		&piv.OpaquePublicKey{Algorithm: piv.AlgMLDSA44, Raw: make([]byte, 1311)},
		&piv.OpaquePublicKey{Algorithm: piv.AlgMLKEM768, Raw: make([]byte, 1184)},
	} {
		got, err := SigningKeyFromPublicKey(key)
		if !errors.Is(err, ErrInvalidSigningKey) || got != (SigningKey{}) {
			t.Fatalf("%T returned %+v, %v", key, got, err)
		}
	}
}

func TestSigningKeyEvidenceFromSlotPreservesProofAndFreshness(t *testing.T) {
	report, _, request := signingPSSFixture()
	key := signingBuilderRSA(2048)
	metadata := &KeyMetadata{Slot: piv.SlotSignature, Algorithm: KeyAlgorithmRSA2048,
		PINPolicy: PINPolicyAlways, TouchPolicy: TouchPolicyCached, Source: ResolutionSourceVendorMetadata}
	for _, test := range []struct {
		name        string
		description SlotDescription
		current     bool
		wantState   SlotState
		wantSupport SigningSupport
		wantReason  SigningReason
	}{
		{"current metadata", SlotDescription{KeyState: SlotStatePresent, PublicKey: key, PublicKeySource: PublicKeySourceMetadata, Metadata: metadata}, true, SlotStatePresent, SigningSupported, SigningReasonProfileMatched},
		{"stale metadata", SlotDescription{KeyState: SlotStatePresent, PublicKey: key, PublicKeySource: PublicKeySourceMetadata, Metadata: metadata}, false, SlotStatePresent, SigningUnknown, SigningReasonKeyStale},
		{"NEO stored template", SlotDescription{KeyState: SlotStateUnknown, PublicKey: key, PublicKeySource: PublicKeySourceStoredTemplate, KeyUnknownReason: KeyUnknownReasonUnobservable}, true, SlotStateUnknown, SigningUnknown, SigningReasonKeyUnknown},
		{"legacy certificate", SlotDescription{KeyState: SlotStateUnknown, PublicKey: key, PublicKeySource: PublicKeySourceCertificate, KeyUnknownReason: KeyUnknownReasonUnobservable}, true, SlotStateUnknown, SigningUnknown, SigningReasonKeyUnknown},
		{"certificate alone", SlotDescription{KeyState: SlotStatePresent, PublicKey: key, PublicKeySource: PublicKeySourceCertificate}, true, SlotStatePresent, SigningUnknown, SigningReasonKeyUnknown},
		{"metadata read error", SlotDescription{KeyState: SlotStateError, PublicKey: key, PublicKeySource: PublicKeySourceMetadata, KeyError: errors.New("metadata read failed")}, true, SlotStateError, SigningUnknown, SigningReasonKeyUnknown},
		{"inconsistent read error", SlotDescription{KeyState: SlotStatePresent, PublicKey: key, PublicKeySource: PublicKeySourceMetadata, KeyError: errors.New("metadata read failed")}, true, SlotStateError, SigningUnknown, SigningReasonKeyUnknown},
		{"empty private slot", SlotDescription{KeyState: SlotStateAbsent}, true, SlotStateAbsent, SigningUnsupported, SigningReasonKeyAbsent},
		{"unobservable empty public object", SlotDescription{KeyState: SlotStateUnknown, KeyUnknownReason: KeyUnknownReasonUnobservable}, true, SlotStateUnknown, SigningUnknown, SigningReasonKeyUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := SigningKeyEvidenceFromSlot(piv.SlotSignature, test.description, test.current)
			if err != nil || got.Current != test.current || got.State != test.wantState || got.Source != test.description.PublicKeySource {
				t.Fatalf("evidence = %+v, %v", got, err)
			}
			if got.Source != PublicKeySourceMetadata && got.PINPolicy != PINPolicyUnknown {
				t.Fatal("public storage invented a PIN policy")
			}
			if test.description.Metadata != nil && (got.PINPolicy != PINPolicyAlways || got.TouchPolicy != TouchPolicyCached) {
				t.Fatal("metadata interaction observations were not retained")
			}
			decision := MatchSigningCapability(report, got, request)
			if decision.Support != test.wantSupport || decision.Reason != test.wantReason {
				t.Fatalf("decision = %+v, want %s/%s", decision, test.wantSupport, test.wantReason)
			}
		})
	}
}

func TestSigningKeyEvidenceFromSlotRejectsContradictions(t *testing.T) {
	for _, metadata := range []*KeyMetadata{
		{Slot: piv.SlotAuthentication, Algorithm: KeyAlgorithmRSA2048},
		{Slot: piv.SlotSignature, Algorithm: KeyAlgorithmRSA3072},
		{Slot: piv.SlotSignature, Algorithm: KeyAlgorithmX25519},
	} {
		description := SlotDescription{KeyState: SlotStatePresent, PublicKey: signingBuilderRSA(2048), PublicKeySource: PublicKeySourceMetadata, Metadata: metadata}
		got, err := SigningKeyEvidenceFromSlot(piv.SlotSignature, description, true)
		if !errors.Is(err, ErrInvalidSigningKey) || got.State != SlotStateError {
			t.Fatalf("contradictory metadata returned %+v, %v", got, err)
		}
	}
	description := SlotDescription{KeyState: SlotStatePresent, PublicKey: &ecdsa.PublicKey{}, PublicKeySource: PublicKeySourceMetadata}
	if got, err := SigningKeyEvidenceFromSlot(piv.SlotSignature, description, true); !errors.Is(err, ErrInvalidSigningKey) || got.State != SlotStateError {
		t.Fatalf("malformed public key returned %+v, %v", got, err)
	}
}

func TestSigningRequestFromRSAOptionsPreservesExactOperation(t *testing.T) {
	key := signingBuilderRSA(2048)
	digest := bytes.Repeat([]byte{0xA5}, 32)
	payload := []byte{0x30, 0xFF, 0x00, 0x7F}
	for _, test := range []struct {
		name    string
		input   []byte
		options piv.RSASignOptions
		want    SigningRequest
	}{
		{"digest", digest, piv.RSAPKCS1v15DigestOptions{Hash: crypto.SHA256}, SigningRequest{InputLength: 32, Parameters: SigningParameters{Scheme: SigningRSAPKCS1v15Digest, Input: SigningInputDigest, Hash: crypto.SHA256, Context: SigningContextAbsent}}},
		{"digest pointer", digest, &piv.RSAPKCS1v15DigestOptions{Hash: crypto.SHA256}, SigningRequest{InputLength: 32, Parameters: SigningParameters{Scheme: SigningRSAPKCS1v15Digest, Input: SigningInputDigest, Hash: crypto.SHA256, Context: SigningContextAbsent}}},
		{"exact payload", payload, piv.RSAPKCS1v15PayloadOptions{}, SigningRequest{InputLength: 4, Parameters: SigningParameters{Scheme: SigningRSAPKCS1v15Payload, Input: SigningInputPayload, Context: SigningContextAbsent}}},
		{"32-byte payload is not inferred as digest", digest, piv.RSAPKCS1v15PayloadOptions{}, SigningRequest{InputLength: 32, Parameters: SigningParameters{Scheme: SigningRSAPKCS1v15Payload, Input: SigningInputPayload, Context: SigningContextAbsent}}},
		{"empty payload pointer", nil, &piv.RSAPKCS1v15PayloadOptions{}, SigningRequest{Parameters: SigningParameters{Scheme: SigningRSAPKCS1v15Payload, Input: SigningInputPayload, Context: SigningContextAbsent}}},
		{"SHA512 digest", make([]byte, 64), piv.RSAPKCS1v15DigestOptions{Hash: crypto.SHA512}, SigningRequest{InputLength: 64, Parameters: SigningParameters{Scheme: SigningRSAPKCS1v15Digest, Input: SigningInputDigest, Hash: crypto.SHA512, Context: SigningContextAbsent}}},
		{"PSS zero", digest, piv.RSAPSSOptions{Hash: crypto.SHA256, MGF1Hash: crypto.SHA256, SaltLength: 0}, SigningRequest{InputLength: 32, Parameters: SigningParameters{Scheme: SigningRSAPSS, Input: SigningInputDigest, Hash: crypto.SHA256, MGF1Hash: crypto.SHA256, Context: SigningContextAbsent}}},
		{"SHA384 PSS", make([]byte, 48), piv.RSAPSSOptions{Hash: crypto.SHA384, MGF1Hash: crypto.SHA384, SaltLength: 48}, SigningRequest{InputLength: 48, SaltLength: 48, Parameters: SigningParameters{Scheme: SigningRSAPSS, Input: SigningInputDigest, Hash: crypto.SHA384, MGF1Hash: crypto.SHA384, Context: SigningContextAbsent}}},
		{"PSS maximum pointer", digest, &piv.RSAPSSOptions{Hash: crypto.SHA256, MGF1Hash: crypto.SHA256, SaltLength: 222}, SigningRequest{InputLength: 32, SaltLength: 222, Parameters: SigningParameters{Scheme: SigningRSAPSS, Input: SigningInputDigest, Hash: crypto.SHA256, MGF1Hash: crypto.SHA256, Context: SigningContextAbsent}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := append([]byte(nil), test.input...)
			got, err := SigningRequestFromRSAOptions(piv.AlgRSA2048, key, test.input, test.options)
			if err != nil || got != test.want || !bytes.Equal(test.input, before) {
				t.Fatalf("got %+v, %v; want %+v", got, err, test.want)
			}
			if err := validateSigningRequest(got); err != nil {
				t.Fatalf("builder produced an invalid matcher request: %v", err)
			}
		})
	}
}

type signingBuilderUnknownRSAOptions struct {
	piv.RSAPSSOptions
	Context string
}

func TestSigningRequestFromRSAOptionsUsesCorePreflightErrors(t *testing.T) {
	key := signingBuilderRSA(2048)
	digest := make([]byte, 32)
	for _, test := range []struct {
		name      string
		algorithm byte
		key       *rsa.PublicKey
		input     []byte
		options   piv.RSASignOptions
	}{
		{"nil options", piv.AlgRSA2048, key, digest, nil},
		{"typed nil options", piv.AlgRSA2048, key, digest, (*piv.RSAPSSOptions)(nil)},
		{"nil public key", piv.AlgRSA2048, nil, digest, piv.RSAPKCS1v15DigestOptions{Hash: crypto.SHA256}},
		{"wrong protocol width", piv.AlgRSA3072, key, digest, piv.RSAPKCS1v15DigestOptions{Hash: crypto.SHA256}},
		{"wrong digest length", piv.AlgRSA2048, key, digest[:31], piv.RSAPKCS1v15DigestOptions{Hash: crypto.SHA256}},
		{"MGF mismatch", piv.AlgRSA2048, key, digest, piv.RSAPSSOptions{Hash: crypto.SHA256, MGF1Hash: crypto.SHA512}},
		{"negative salt", piv.AlgRSA2048, key, digest, piv.RSAPSSOptions{Hash: crypto.SHA256, MGF1Hash: crypto.SHA256, SaltLength: -1}},
		{"overlarge salt", piv.AlgRSA2048, key, digest, piv.RSAPSSOptions{Hash: crypto.SHA256, MGF1Hash: crypto.SHA256, SaltLength: 223}},
		{"custom options retain requirements", piv.AlgRSA2048, key, digest, signingBuilderUnknownRSAOptions{Context: "required context"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, want := SigningRequestFromRSAOptions(test.algorithm, test.key, test.input, test.options)
			core := piv.ValidateRSASignRequest(test.algorithm, test.key, test.input, test.options)
			if want == nil || core == nil {
				t.Fatalf("invalid request accepted: builder=%v core=%v", want, core)
			}
			for _, sentinel := range []error{piv.ErrInvalidRSAParameters, piv.ErrUnsupportedRSAOptions} {
				if errors.Is(want, sentinel) != errors.Is(core, sentinel) {
					t.Fatalf("builder=%v core=%v disagree on %v", want, core, sentinel)
				}
			}
		})
	}
}

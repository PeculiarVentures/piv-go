package adapters

import (
	"crypto"
	"testing"

	"github.com/PeculiarVentures/piv-go/piv"
)

func signingPSSFixture() (SigningCapabilityReport, SigningKeyEvidence, SigningRequest) {
	key := SigningKey{Family: SigningKeyRSA, RSABits: 2048}
	parameters := SigningParameters{Scheme: SigningRSAPSS, Input: SigningInputDigest,
		Hash: crypto.SHA256, MGF1Hash: crypto.SHA256, Context: SigningContextAbsent}
	profile := SigningProfile{
		ID: "rsa2048-pss-sha256", Key: key, Parameters: parameters,
		Slots:       []piv.Slot{piv.SlotAuthentication, piv.SlotSignature},
		InputLength: SigningLengthRange{Min: 32, Max: 32}, SaltLength: SigningLengthRange{Min: 1, Max: 222},
		SignatureLength: SigningLengthRange{Min: 256, Max: 256}, ResultEncoding: SigningResultRaw,
		Randomness: SigningRandomnessHostCSPRNG, Support: SigningSupported,
		Transport: SigningTransport{CommandChaining: SigningSupported, ExtendedAPDU: SigningUnknown, MaxCommandData: 216, MaxResponseData: 264},
		Evidence:  []SigningEvidence{{Source: "vendor-documentation", Reference: "qualified device protocol"}},
	}
	report := SigningCapabilityReport{AdapterName: "fixture", Device: SigningDevice{Model: "fixture", Firmware: "1.0"},
		Profiles: []SigningProfile{profile}, Fallback: SigningDecision{Support: SigningUnsupported, Reason: SigningReasonNoProfile}}
	evidence := SigningKeyEvidence{Slot: piv.SlotSignature, Key: key, State: SlotStatePresent, Current: true,
		Source: PublicKeySourceMetadata, PINPolicy: PINPolicyAlways, TouchPolicy: TouchPolicyNever}
	return report, evidence, SigningRequest{Parameters: parameters, InputLength: 32, SaltLength: 1}
}

func TestSigningProfilesMatchExactParametersAndLimits(t *testing.T) {
	tests := []struct {
		name   string
		edit   func(*SigningCapabilityReport, *SigningKeyEvidence, *SigningRequest)
		want   SigningSupport
		reason SigningReason
	}{
		{"exact zero salt is deterministic", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) {
			p.Profiles[0].SaltLength = SigningLengthRange{}
			p.Profiles[0].Randomness = SigningRandomnessDeterministic
			r.SaltLength = 0
			r.Randomness = SigningRandomnessDeterministic
		}, SigningSupported, SigningReasonProfileMatched},
		{"maximum salt", func(_ *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) { r.SaltLength = 222 }, SigningSupported, SigningReasonProfileMatched},
		{"salt too large", func(_ *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) { r.SaltLength = 223 }, SigningUnsupported, SigningReasonLimits},
		{"Go salt sentinel", func(_ *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) { r.SaltLength = -1 }, SigningUnsupported, SigningReasonInvalidRequest},
		{"different MGF", func(_ *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) {
			r.Parameters.MGF1Hash = crypto.SHA512
		}, SigningUnsupported, SigningReasonNoProfile},
		{"different hash", func(_ *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) {
			r.Parameters.Hash = crypto.SHA512
			r.InputLength = 64
		}, SigningUnsupported, SigningReasonNoProfile},
		{"wrong digest size", func(_ *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) { r.InputLength = 31 }, SigningUnsupported, SigningReasonInvalidRequest},
		{"unknown hash", func(_ *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) {
			r.Parameters.Hash = crypto.Hash(255)
		}, SigningUnsupported, SigningReasonInvalidRequest},
		{"unknown MGF", func(_ *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) {
			r.Parameters.MGF1Hash = crypto.Hash(255)
		}, SigningUnsupported, SigningReasonInvalidRequest},
		{"missing MGF", func(_ *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) { r.Parameters.MGF1Hash = 0 }, SigningUnsupported, SigningReasonInvalidRequest},
		{"message instead of digest", func(_ *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) {
			r.Parameters.Input = SigningInputMessage
		}, SigningUnsupported, SigningReasonInvalidRequest},
		{"missing context presence", func(_ *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) { r.Parameters.Context = "" }, SigningUnsupported, SigningReasonInvalidRequest},
		{"inconsistent context", func(_ *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) { r.ContextLength = 1 }, SigningUnsupported, SigningReasonInvalidRequest},
		{"unsupported slot", func(_ *SigningCapabilityReport, k *SigningKeyEvidence, _ *SigningRequest) { k.Slot = piv.SlotCardAuth }, SigningUnsupported, SigningReasonNoProfile},
		{"management slot", func(_ *SigningCapabilityReport, k *SigningKeyEvidence, _ *SigningRequest) {
			k.Slot = piv.SlotManagement
		}, SigningUnsupported, SigningReasonSlotIneligible},
		{"attestation slot", func(_ *SigningCapabilityReport, k *SigningKeyEvidence, _ *SigningRequest) { k.Slot = 0xf9 }, SigningUnsupported, SigningReasonSlotIneligible},
		{"wrong RSA width", func(_ *SigningCapabilityReport, k *SigningKeyEvidence, _ *SigningRequest) { k.Key.RSABits = 3072 }, SigningUnsupported, SigningReasonNoProfile},
		{"stale observation", func(_ *SigningCapabilityReport, k *SigningKeyEvidence, _ *SigningRequest) { k.Current = false }, SigningUnknown, SigningReasonKeyStale},
		{"absent key", func(_ *SigningCapabilityReport, k *SigningKeyEvidence, _ *SigningRequest) { k.State = SlotStateAbsent }, SigningUnsupported, SigningReasonKeyAbsent},
		{"metadata unavailable", func(_ *SigningCapabilityReport, k *SigningKeyEvidence, _ *SigningRequest) { k.State = SlotStateUnknown }, SigningUnknown, SigningReasonKeyUnknown},
		{"metadata read error", func(_ *SigningCapabilityReport, k *SigningKeyEvidence, _ *SigningRequest) { k.State = SlotStateError }, SigningUnknown, SigningReasonKeyUnknown},
		{"certificate cannot prove key", func(_ *SigningCapabilityReport, k *SigningKeyEvidence, _ *SigningRequest) {
			k.Source = PublicKeySourceCertificate
		}, SigningUnknown, SigningReasonKeyUnknown},
		{"stored template cannot prove key", func(_ *SigningCapabilityReport, k *SigningKeyEvidence, _ *SigningRequest) {
			k.Source = PublicKeySourceStoredTemplate
		}, SigningUnknown, SigningReasonKeyUnknown},
		{"positive salt is not deterministic", func(_ *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) {
			r.Randomness = SigningRandomnessDeterministic
		}, SigningUnsupported, SigningReasonRandomness},
		{"zero salt needs no additional randomness requirement", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) {
			p.Profiles[0].SaltLength = SigningLengthRange{}
			p.Profiles[0].Randomness = SigningRandomnessDeterministic
			r.SaltLength = 0
		}, SigningSupported, SigningReasonProfileMatched},
		{"zero salt cannot guarantee host entropy", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) {
			p.Profiles[0].SaltLength = SigningLengthRange{}
			p.Profiles[0].Randomness = SigningRandomnessDeterministic
			r.SaltLength = 0
			r.Randomness = SigningRandomnessHostCSPRNG
		}, SigningUnsupported, SigningReasonRandomness},
		{"unknown randomness", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) {
			p.Profiles[0].Randomness = SigningRandomnessUnknown
			r.Randomness = SigningRandomnessHedged
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"unknown profile stays unknown", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].Support = SigningUnknown
			p.Profiles[0].InputLength = SigningLengthRange{}
		}, SigningUnknown, SigningReasonProfileUnknown},
		{"unsupported profile has a structured reason", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].Support = SigningUnsupported
		}, SigningUnsupported, SigningReasonProfileUnsupported},
		{"missing protocol evidence", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].Evidence = nil
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"incomplete protocol evidence", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].Evidence = []SigningEvidence{{Source: "vendor-documentation"}, {Reference: "protocol"}, {Source: " ", Reference: " "}}
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"missing transport evidence", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].Transport = SigningTransport{}
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"missing command capacity", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].Transport.MaxCommandData = 0
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"result exceeds transport capacity", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].Transport.MaxResponseData = 255
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"response must include authentication template", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].Transport.MaxResponseData = 256
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"large command without a transport path", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].Transport.CommandChaining = SigningUnsupported
			p.Profiles[0].Transport.MaxCommandData = 264
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"unknown transport feature identifier", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].Transport.ExtendedAPDU = "invalid"
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"empty randomness guarantee", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].Randomness = ""
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"invalid randomness guarantee", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].Randomness = "invalid"
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"PSS without host CSPRNG", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].Randomness = SigningRandomnessDeterministic
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"zero salt must declare determinism", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) {
			p.Profiles[0].SaltLength = SigningLengthRange{}
			r.SaltLength = 0
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"mixed salt range cannot declare host randomness", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].SaltLength.Min = 0
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"mixed salt range cannot declare determinism", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].SaltLength.Min = 0
			p.Profiles[0].Randomness = SigningRandomnessDeterministic
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"provider cannot enlarge mathematical PSS salt bound", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, r *SigningRequest) {
			p.Profiles[0].SaltLength.Max = 223
			r.SaltLength = 223
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"RSA result minimum must match modulus", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].SignatureLength.Min = 255
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"RSA result maximum must match modulus", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].SignatureLength.Max = 257
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"overflowing RSA bit count", func(p *SigningCapabilityReport, k *SigningKeyEvidence, _ *SigningRequest) {
			k.Key.RSABits = int(^uint(0) >> 1)
			p.Profiles[0].Key = k.Key
		}, SigningUnknown, SigningReasonInvalidKey},
		{"unimplemented pathological RSA width", func(p *SigningCapabilityReport, k *SigningKeyEvidence, _ *SigningRequest) {
			k.Key.RSABits = int(^uint(0)>>1) - 7
			p.Profiles[0].Key = k.Key
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"incomplete positive profile", func(p *SigningCapabilityReport, _ *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].ResultEncoding = ""
		}, SigningUnknown, SigningReasonInvalidProfile},
		{"inconsistent key family", func(p *SigningCapabilityReport, k *SigningKeyEvidence, _ *SigningRequest) {
			p.Profiles[0].Key = SigningKey{Family: SigningKeyEC, CurveOID: SigningCurveP256}
			k.Key = p.Profiles[0].Key
		}, SigningUnknown, SigningReasonInvalidProfile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, key, request := signingPSSFixture()
			tt.edit(&report, &key, &request)
			got := MatchSigningCapability(report, key, request)
			if got.Support != tt.want || got.Reason != tt.reason {
				t.Fatalf("decision = %+v; want %s, %s", got, tt.want, tt.reason)
			}
		})
	}
}

func TestSigningProfilesDoNotInferAlgorithmFromInputOrCurveSize(t *testing.T) {
	profile := SigningProfile{ID: "p256", Key: SigningKey{Family: SigningKeyEC, CurveOID: SigningCurveP256},
		Parameters: SigningParameters{Scheme: SigningECDSA, Input: SigningInputDigest, Hash: crypto.SHA256, Context: SigningContextAbsent},
		Slots:      []piv.Slot{piv.SlotSignature}, InputLength: SigningLengthRange{Min: 32, Max: 32},
		SignatureLength: SigningLengthRange{Min: 8, Max: 72}, ResultEncoding: SigningResultASN1DER, Support: SigningSupported,
		Randomness: SigningRandomnessUnknown, Evidence: []SigningEvidence{{Source: "vendor-documentation", Reference: "P-256 protocol"}},
		Transport: SigningTransport{CommandChaining: SigningUnknown, ExtendedAPDU: SigningUnknown, MaxCommandData: 38, MaxResponseData: 80}}
	report := SigningCapabilityReport{Profiles: []SigningProfile{profile}, Fallback: SigningDecision{Support: SigningUnsupported}}
	key := SigningKeyEvidence{Slot: piv.SlotSignature, Key: profile.Key, Current: true, State: SlotStatePresent, Source: PublicKeySourceMetadata}
	request := SigningRequest{Parameters: profile.Parameters, InputLength: 32}
	if got := MatchSigningCapability(report, key, request); got.Support != SigningSupported {
		t.Fatalf("P-256/SHA256 = %+v", got)
	}
	key.Key.CurveOID = SigningCurveSecp256k1
	if got := MatchSigningCapability(report, key, request); got.Support != SigningUnsupported {
		t.Fatalf("secp256k1 must not match P-256: %+v", got)
	}
	key.Key = profile.Key
	request.Parameters.Hash = 0
	if got := MatchSigningCapability(report, key, request); got.Support != SigningUnsupported {
		t.Fatalf("32 bytes must not infer SHA256: %+v", got)
	}
}

func TestSigningPayloadProfileCannotOverrideRSAMathematicalLimits(t *testing.T) {
	report, key, _ := signingPSSFixture()
	p := &report.Profiles[0]
	p.Parameters = SigningParameters{Scheme: SigningRSAPKCS1v15Payload, Input: SigningInputPayload, Context: SigningContextAbsent}
	p.InputLength, p.SaltLength = SigningLengthRange{Max: 245}, SigningLengthRange{}
	p.Randomness = SigningRandomnessUnknown
	r := SigningRequest{Parameters: p.Parameters, InputLength: 245}
	if got := MatchSigningCapability(report, key, r); got.Support != SigningSupported {
		t.Fatalf("valid k-11 payload = %+v", got)
	}
	p.InputLength.Max, r.InputLength = 246, 246
	if got := MatchSigningCapability(report, key, r); got.Support != SigningUnknown || got.Reason != SigningReasonInvalidProfile {
		t.Fatalf("provider advertised k-10 payload: %+v", got)
	}
}

func TestSupportedProfileMayUseAnExtendedAPDUInsteadOfChaining(t *testing.T) {
	report, key, request := signingPSSFixture()
	report.Profiles[0].Transport = SigningTransport{CommandChaining: SigningUnsupported, ExtendedAPDU: SigningSupported, MaxCommandData: 266, MaxResponseData: 264}
	if got := MatchSigningCapability(report, key, request); got.Support != SigningSupported {
		t.Fatalf("complete extended-APDU profile = %+v", got)
	}
	report.Profiles[0].Transport.MaxCommandData = 256
	if got := MatchSigningCapability(report, key, request); got.Support != SigningUnknown || got.Reason != SigningReasonInvalidProfile {
		t.Fatalf("too-small extended command capacity = %+v", got)
	}
}

func TestPureMLDSAProfilesPreserveMessageAndContextSemantics(t *testing.T) {
	parameters := SigningParameters{Scheme: SigningMLDSA, Input: SigningInputMessage, Mode: SigningModePure, Context: SigningContextAbsent}
	key := SigningKey{Family: SigningKeyMLDSA, MLDSAParameterSet: 44}
	profile := SigningProfile{ID: "mldsa44-pure", Key: key, Parameters: parameters, Slots: []piv.Slot{piv.SlotSignature},
		InputLength: SigningLengthRange{Min: 0, Max: 4096}, SignatureLength: SigningLengthRange{Min: 2420, Max: 2420}, ResultEncoding: SigningResultRaw, Support: SigningSupported,
		Randomness: SigningRandomnessUnknown, Evidence: []SigningEvidence{{Source: "hardware-qualification", Reference: "pure ML-DSA-44 protocol"}},
		Transport: SigningTransport{CommandChaining: SigningUnsupported, ExtendedAPDU: SigningSupported, MaxCommandData: 4106, MaxResponseData: 2428}}
	report := SigningCapabilityReport{Profiles: []SigningProfile{profile}, Fallback: SigningDecision{Support: SigningUnsupported}}
	evidence := SigningKeyEvidence{Slot: piv.SlotSignature, Key: key, Current: true, State: SlotStatePresent, Source: PublicKeySourceMetadata}
	for _, length := range []int{0, 32, 4096} {
		if got := MatchSigningCapability(report, evidence, SigningRequest{Parameters: parameters, InputLength: length}); got.Support != SigningSupported {
			t.Fatalf("pure message length %d = %+v", length, got)
		}
	}
	if got := MatchSigningCapability(report, evidence, SigningRequest{Parameters: parameters, Randomness: SigningRandomnessHedged}); got.Support != SigningUnknown || got.Reason != SigningReasonRandomness {
		t.Fatalf("unknown device RNG must not become a hedged guarantee: %+v", got)
	}
	request := SigningRequest{Parameters: parameters, InputLength: 32}
	request.Parameters.Context = SigningContextPresent
	if got := MatchSigningCapability(report, evidence, request); got.Support != SigningUnsupported {
		t.Fatalf("present empty context must not become absent: %+v", got)
	}
	request.Parameters = parameters
	request.Parameters.Mode, request.Parameters.Input, request.Parameters.Hash = SigningModePrehash, SigningInputDigest, crypto.SHA256
	if got := MatchSigningCapability(report, evidence, request); got.Support != SigningUnsupported {
		t.Fatalf("prehash must not match pure 32-byte message: %+v", got)
	}
	evidence.Key.MLDSAParameterSet = 65
	if got := MatchSigningCapability(report, evidence, SigningRequest{Parameters: parameters}); got.Support != SigningUnsupported {
		t.Fatalf("parameter sets must match exactly: %+v", got)
	}
}

func TestSigningTemplateSizesIncludeBERLengthsWithoutOverflow(t *testing.T) {
	for _, tt := range []struct {
		payload int
		command bool
		want    int
	}{{0, true, 6}, {0, false, 4}, {32, true, 38}, {72, false, 76}, {256, true, 266}, {256, false, 264}, {4096, true, 4106}, {2420, false, 2428}} {
		got, ok := signingTemplateSize(tt.payload, tt.command)
		if !ok || got != tt.want {
			t.Fatalf("template payload=%d command=%v: got %d,%v want %d", tt.payload, tt.command, got, ok, tt.want)
		}
	}
	for _, length := range []int{-1, int(^uint(0) >> 1), int(^uint(0)>>1) - 1} {
		if _, ok := signingTemplateSize(length, true); ok {
			t.Fatalf("pathological payload %d accepted", length)
		}
	}
}

func TestSigningFallbackNeverInfersSupport(t *testing.T) {
	_, key, request := signingPSSFixture()
	for _, fallback := range []SigningDecision{{}, {Support: SigningSupported}, {Support: SigningUnknown}} {
		report := SigningCapabilityReport{Fallback: fallback}
		if got := MatchSigningCapability(report, key, request); got.Support != SigningUnknown {
			t.Fatalf("fallback %+v enabled signing: %+v", fallback, got)
		}
	}
	for _, adapter := range []Adapter{nil, coarseSigningAdapter{}} {
		report := ReportSigningCapabilities(adapter, SigningDevice{Model: "cached", Firmware: "0.0.1", PIVVersion: "1.0.4"})
		if len(report.Profiles) != 0 || report.Fallback.Support != SigningUnknown || report.Fallback.Reason != SigningReasonNoReporter {
			t.Fatalf("generic adapter inferred support: %+v", report)
		}
		if report.Device.Firmware == report.Device.PIVVersion {
			t.Fatal("firmware and applet version were conflated")
		}
	}
}

func TestSigningSlotPurposes(t *testing.T) {
	for _, slot := range []piv.Slot{piv.SlotKeyManagement, 0x82, 0x95} {
		if got := SigningSlotPurpose(slot); got != SigningPurposeKeyManagement {
			t.Fatalf("slot %s purpose = %s", slot, got)
		}
	}
	for _, slot := range []piv.Slot{0, 0x81, 0x96, piv.SlotManagement, 0xf9} {
		if got := SigningSlotPurpose(slot); got != SigningPurposeIneligible {
			t.Fatalf("slot %s purpose = %s", slot, got)
		}
	}
}

type passiveSigningAdapter struct{ report SigningCapabilityReport }

type coarseSigningAdapter struct{}

func (coarseSigningAdapter) Name() string            { return "coarse" }
func (coarseSigningAdapter) MatchReader(string) bool { return true }

func (a passiveSigningAdapter) Name() string            { return "passive" }
func (a passiveSigningAdapter) MatchReader(string) bool { return true }
func (a passiveSigningAdapter) SigningCapabilities(d SigningDevice) SigningCapabilityReport {
	a.report.Device = d
	return a.report
}
func (passiveSigningAdapter) KeyMetadata(*Session, piv.Slot) (KeyMetadata, error) {
	panic("discovery contacted a token")
}
func (passiveSigningAdapter) Capabilities() CapabilityReport {
	panic("signing discovery used coarse capabilities")
}

func TestSigningReportingUsesOnlySuppliedSnapshot(t *testing.T) {
	report, key, request := signingPSSFixture()
	adapter := passiveSigningAdapter{report: report}
	device := SigningDevice{Model: "offline", Firmware: "1.0"}
	got := ReportSigningCapabilities(adapter, device)
	if got.Device.Model != "offline" || MatchSigningCapability(got, key, request).Support != SigningSupported {
		t.Fatalf("cached report = %+v", got)
	}
}

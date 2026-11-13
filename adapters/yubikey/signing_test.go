package yubikey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"reflect"
	"slices"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/piv"
)

func signingTestKey(slot piv.Slot, key adapters.SigningKey) adapters.SigningKeyEvidence {
	return adapters.SigningKeyEvidence{Slot: slot, Key: key, Current: true, State: adapters.SlotStatePresent, Source: adapters.PublicKeySourceMetadata}
}

func signingDigestRequest(scheme adapters.SigningScheme, hash crypto.Hash) adapters.SigningRequest {
	request := adapters.SigningRequest{
		Parameters:  adapters.SigningParameters{Scheme: scheme, Input: adapters.SigningInputDigest, Hash: hash, Context: adapters.SigningContextAbsent},
		InputLength: hash.Size(),
	}
	if scheme == adapters.SigningRSAPSS {
		request.Parameters.MGF1Hash = hash
	}
	return request
}

func qualifiedSigningDevice() adapters.SigningDevice {
	return adapters.SigningDevice{Model: qualifiedPreviewModel, Firmware: qualifiedPreviewFirmware, PIVVersion: "0.0.1"}
}

func TestSigningCapabilitiesDocumentedFirmwareAndModels(t *testing.T) {
	rsa2048 := adapters.SigningKey{Family: adapters.SigningKeyRSA, RSABits: 2048}
	rsa3072 := adapters.SigningKey{Family: adapters.SigningKeyRSA, RSABits: 3072}
	ed := adapters.SigningKey{Family: adapters.SigningKeyEdDSA, CurveOID: adapters.SigningCurveEd25519}
	pure := adapters.SigningRequest{Parameters: adapters.SigningParameters{Scheme: adapters.SigningEdDSA, Input: adapters.SigningInputMessage, Mode: adapters.SigningModePure, Context: adapters.SigningContextAbsent}, InputLength: 32}
	for _, test := range []struct {
		name    string
		device  adapters.SigningDevice
		key     adapters.SigningKeyEvidence
		request adapters.SigningRequest
		want    adapters.SigningSupport
	}{
		{"YK5A_canonical_name", adapters.SigningDevice{Model: "YubiKey 5A", Firmware: "5.4.3"}, signingTestKey(piv.SlotAuthentication, rsa2048), signingDigestRequest(adapters.SigningRSAPKCS1v15Digest, crypto.SHA256), adapters.SigningSupported},
		{"YK5_RSA2048_SHA512", adapters.SigningDevice{Model: "YubiKey 5C NFC", Firmware: "5.6.2"}, signingTestKey(piv.SlotSignature, rsa2048), signingDigestRequest(adapters.SigningRSAPKCS1v15Digest, crypto.SHA512), adapters.SigningSupported},
		{"before_5_7_no_RSA3072", adapters.SigningDevice{Model: "YubiKey 5C NFC", Firmware: "5.6.2"}, signingTestKey(piv.SlotSignature, rsa3072), signingDigestRequest(adapters.SigningRSAPSS, crypto.SHA384), adapters.SigningUnsupported},
		{"5_7_RSA3072", adapters.SigningDevice{Model: "YubiKey 5C NFC", Firmware: "5.7.0"}, signingTestKey(piv.SlotSignature, rsa3072), signingDigestRequest(adapters.SigningRSAPSS, crypto.SHA384), adapters.SigningSupported},
		{"before_5_7_no_Ed25519", adapters.SigningDevice{Model: "YubiKey 5C NFC", Firmware: "5.6.2"}, signingTestKey(piv.SlotSignature, ed), pure, adapters.SigningUnsupported},
		{"5_7_Ed25519_limits_unknown", adapters.SigningDevice{Model: "YubiKey 5C NFC", Firmware: "5.7.0"}, signingTestKey(piv.SlotSignature, ed), pure, adapters.SigningUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := adapters.ReportSigningCapabilities(NewAdapter(), test.device)
			decision := adapters.MatchSigningCapability(report, test.key, test.request)
			if decision.Support != test.want {
				t.Fatalf("decision = %+v, want %s", decision, test.want)
			}
		})
	}
}

func TestSigningModelNamesAndAliases(t *testing.T) {
	// Canonical names follow yubikit.support.get_name in ykman 5.9.2.
	for generation, names := range map[int][]string{
		3: {"YubiKey NEO", "YubiKey NEO-n"},
		4: {"YubiKey 4", "YubiKey 4 Nano", "YubiKey 4C", "YubiKey 4C Nano"},
		5: {"YubiKey 5A", "YubiKey 5 NFC", "YubiKey 5 Nano", "YubiKey 5C", "YubiKey 5C NFC", "YubiKey 5C Nano", "YubiKey 5Ci", "YubiKey 5"},
	} {
		for _, name := range names {
			if got := signingModelGeneration(name); got != generation {
				t.Errorf("%s generation = %d, want %d", name, got, generation)
			}
		}
	}
	for _, name := range []string{"YubiKey 5A FIPS", "YubiKey 4 FIPS", "YubiKey 5A - Enhanced PIN", "YubiKey 5A unknown", "Yubico YubiKey OTP+FIDO+CCID"} {
		if got := signingModelGeneration(name); got != 0 {
			t.Errorf("%s inherited ordinary model generation %d", name, got)
		}
	}
}

func TestLegacyDeviceProfilesDoNotProveCurrentKeys(t *testing.T) {
	curve := elliptic.P256()
	publicKey := &ecdsa.PublicKey{Curve: curve, X: curve.Params().Gx, Y: curve.Params().Gy}
	for _, device := range []adapters.SigningDevice{
		{Model: "YubiKey NEO", Firmware: "3.4.9", PIVVersion: "1.0.4"},
		{Model: "YubiKey 4", Firmware: "4.3.7"},
		{Model: "YubiKey 5C NFC", Firmware: "5.2.7"},
	} {
		t.Run(device.Model, func(t *testing.T) {
			report := NewAdapter().SigningCapabilities(device)
			staticP256 := false
			for _, profile := range report.Profiles {
				if profile.Key.CurveOID == adapters.SigningCurveP256 && slices.Contains(profile.Slots, piv.SlotAuthentication) {
					staticP256 = true
				}
				if device.Model == "YubiKey NEO" && (profile.Key.CurveOID == adapters.SigningCurveP384 || slices.Contains(profile.Slots, piv.Slot(0x82))) {
					t.Fatal("NEO inherited P-384 or retired-slot support")
				}
			}
			if !staticP256 {
				t.Fatal("documented static P-256 capability was lost")
			}
			observation := adapters.SlotDescription{
				KeyState: adapters.SlotStateUnknown, KeyUnknownReason: adapters.KeyUnknownReasonUnobservable,
				PublicKey: publicKey, PublicKeySource: adapters.PublicKeySourceStoredTemplate,
			}
			key, err := adapters.SigningKeyEvidenceFromSlot(piv.SlotAuthentication, observation, true)
			if err != nil {
				t.Fatal(err)
			}
			decision := adapters.MatchSigningCapability(report, key, signingDigestRequest(adapters.SigningECDSA, crypto.SHA256))
			if decision.Support != adapters.SigningUnknown || decision.Reason != adapters.SigningReasonKeyUnknown {
				t.Fatalf("legacy public storage became a current private key: %+v", decision)
			}
		})
	}
}

func TestPKCS1SigningProfilesGuaranteeDeterministicSignatures(t *testing.T) {
	report := NewAdapter().SigningCapabilities(qualifiedSigningDevice())
	key := signingTestKey(piv.SlotAuthentication, adapters.SigningKey{Family: adapters.SigningKeyRSA, RSABits: 2048})
	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		request := signingDigestRequest(adapters.SigningRSAPKCS1v15Digest, hash)
		request.Randomness = adapters.SigningRandomnessDeterministic
		if decision := adapters.MatchSigningCapability(report, key, request); decision.Support != adapters.SigningSupported {
			t.Fatalf("named-hash v1.5 was not deterministic: %+v", decision)
		}
	}
	for _, length := range []int{0, 32, 245} {
		request := adapters.SigningRequest{
			Parameters:  adapters.SigningParameters{Scheme: adapters.SigningRSAPKCS1v15Payload, Input: adapters.SigningInputPayload, Context: adapters.SigningContextAbsent},
			InputLength: length, Randomness: adapters.SigningRandomnessDeterministic,
		}
		if decision := adapters.MatchSigningCapability(report, key, request); decision.Support != adapters.SigningSupported {
			t.Fatalf("exact-payload v1.5 was not deterministic: %+v", decision)
		}
	}
}

func TestSigningCapabilitiesDoNotInferDeviceFirmware(t *testing.T) {
	for _, device := range []adapters.SigningDevice{
		{},
		{Model: "YubiKey 5C NFC", PIVVersion: "5.7.0"},
		{Model: "YubiKey 5C NFC", Firmware: "0.0.1", PIVVersion: "5.7.0"},
		{Model: "YubiKey 5C NFC", Firmware: "4.3.7"},
		{Model: "YubiKey 5C NFC", Firmware: "5.7.0.alpha.1"},
		{Model: "YubiKey 5C NFC", Firmware: "6.0.0"},
		{Model: "YubiKey 5C NFC", Firmware: qualifiedPreviewFirmware, PIVVersion: "0.0.1"},
		{Model: "YubiKey 5C NFC FIPS", Firmware: "5.7.0"},
		{Model: "YubiKey 5C NFC - unknown", Firmware: "5.7.0"},
		{Model: "unrecognized YubiKey", Firmware: "5.7.0"},
		{Model: qualifiedPreviewModel, Firmware: qualifiedPreviewFirmware},
		{Model: qualifiedPreviewModel, Firmware: qualifiedPreviewFirmware, PIVVersion: "0.0.2"},
		{Model: qualifiedPreviewModel, Firmware: "6.0.0.alpha.9", PIVVersion: "0.0.1"},
		{Model: "YubiKey 5C NFC", Firmware: "5.7"},
		{Model: "YubiKey 5C NFC", Firmware: "+5.7.0"},
		{Model: "YubiKey 5C NFC", Firmware: "5.7.256"},
	} {
		t.Run(device.Model+"/"+device.Firmware+"/"+device.PIVVersion, func(t *testing.T) {
			report := NewAdapter().SigningCapabilities(device)
			if len(report.Profiles) != 0 || report.Fallback.Support != adapters.SigningUnknown || report.Fallback.Reason == "" {
				t.Fatalf("uncertain device acquired a profile: %+v", report)
			}
		})
	}
}

func TestQualifiedSigningCapabilitiesExactParametersAndLimits(t *testing.T) {
	report := NewAdapter().SigningCapabilities(qualifiedSigningDevice())
	if len(report.Profiles) == 0 {
		t.Fatal("qualified preview has no profiles")
	}
	for _, test := range []struct {
		bits int
		slot piv.Slot
	}{{2048, piv.SlotAuthentication}, {3072, piv.SlotSignature}, {4096, 0x82}} {
		key := signingTestKey(test.slot, adapters.SigningKey{Family: adapters.SigningKeyRSA, RSABits: test.bits})
		for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			for _, scheme := range []adapters.SigningScheme{adapters.SigningRSAPKCS1v15Digest, adapters.SigningRSAPSS} {
				request := signingDigestRequest(scheme, hash)
				for _, salt := range []int{0, 1, hash.Size(), test.bits/8 - hash.Size() - 2} {
					if scheme != adapters.SigningRSAPSS && salt != 0 {
						continue
					}
					request.SaltLength = salt
					if decision := adapters.MatchSigningCapability(report, key, request); decision.Support != adapters.SigningSupported {
						t.Fatalf("RSA%d/%s/%s/salt%d: %+v", test.bits, scheme, hash, salt, decision)
					}
				}
				if scheme == adapters.SigningRSAPSS {
					request.SaltLength++
					if decision := adapters.MatchSigningCapability(report, key, request); decision.Support != adapters.SigningUnsupported || decision.Reason != adapters.SigningReasonLimits {
						t.Fatalf("overlong salt: %+v", decision)
					}
					request.SaltLength = 0
					request.Parameters.MGF1Hash = crypto.SHA224
					if decision := adapters.MatchSigningCapability(report, key, request); decision.Support == adapters.SigningSupported {
						t.Fatal("MGF1 hash was silently substituted")
					}
				}
			}
		}
		payload := adapters.SigningRequest{Parameters: adapters.SigningParameters{Scheme: adapters.SigningRSAPKCS1v15Payload, Input: adapters.SigningInputPayload, Context: adapters.SigningContextAbsent}}
		for _, length := range []int{0, test.bits/8 - 11} {
			payload.InputLength = length
			if decision := adapters.MatchSigningCapability(report, key, payload); decision.Support != adapters.SigningSupported {
				t.Fatalf("payload length %d: %+v", length, decision)
			}
		}
		payload.InputLength++
		if decision := adapters.MatchSigningCapability(report, key, payload); decision.Support != adapters.SigningUnsupported {
			t.Fatalf("overlong payload: %+v", decision)
		}
		key.Slot = piv.SlotCardAuth
		if decision := adapters.MatchSigningCapability(report, key, signingDigestRequest(adapters.SigningRSAPKCS1v15Digest, crypto.SHA256)); decision.Support != adapters.SigningUnknown {
			t.Fatalf("untested preview slot must remain unknown: %+v", decision)
		}
	}
}

func TestPSSSigningProfilesMatchSaltSpecificRandomness(t *testing.T) {
	for _, test := range []struct {
		name   string
		device adapters.SigningDevice
		bits   int
		slot   piv.Slot
	}{
		{"preview2048", qualifiedSigningDevice(), 2048, piv.SlotAuthentication},
		{"preview3072", qualifiedSigningDevice(), 3072, piv.SlotSignature},
		{"preview4096", qualifiedSigningDevice(), 4096, 0x82},
		{"documented1024", adapters.SigningDevice{Model: "YubiKey 5C NFC", Firmware: "5.7.0"}, 1024, piv.SlotSignature},
		{"documented2048", adapters.SigningDevice{Model: "YubiKey 5C NFC", Firmware: "5.7.0"}, 2048, piv.SlotSignature},
		{"documented3072", adapters.SigningDevice{Model: "YubiKey 5C NFC", Firmware: "5.7.0"}, 3072, piv.SlotSignature},
		{"documented4096", adapters.SigningDevice{Model: "YubiKey 5C NFC", Firmware: "5.7.0"}, 4096, piv.SlotSignature},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := NewAdapter().SigningCapabilities(test.device)
			key := signingTestKey(test.slot, adapters.SigningKey{Family: adapters.SigningKeyRSA, RSABits: test.bits})
			for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
				request := signingDigestRequest(adapters.SigningRSAPSS, hash)
				request.Randomness = adapters.SigningRandomnessDeterministic
				zero := adapters.MatchSigningCapability(report, key, request)
				if zero.Support != adapters.SigningSupported || zero.Reason != adapters.SigningReasonProfileMatched {
					t.Fatalf("%s deterministic zero salt: %+v", hash, zero)
				}
				for _, salt := range []int{1, test.bits/8 - hash.Size() - 2} {
					request.SaltLength = salt
					request.Randomness = adapters.SigningRandomnessDeterministic
					if decision := adapters.MatchSigningCapability(report, key, request); decision.Support != adapters.SigningUnsupported || decision.Reason != adapters.SigningReasonRandomness {
						t.Fatalf("%s positive salt %d claimed determinism: %+v", hash, salt, decision)
					}
					request.Randomness = adapters.SigningRandomnessHostCSPRNG
					positive := adapters.MatchSigningCapability(report, key, request)
					if positive.Support != adapters.SigningSupported || positive.ProfileID == zero.ProfileID {
						t.Fatalf("%s positive salt %d did not select its own CSPRNG profile: %+v", hash, salt, positive)
					}
				}
			}
		})
	}
}

func TestQualifiedECSigningProfilesUseExactCurves(t *testing.T) {
	report := NewAdapter().SigningCapabilities(qualifiedSigningDevice())
	for _, test := range []struct {
		curve string
		slot  piv.Slot
		width int
	}{{adapters.SigningCurveP256, piv.SlotKeyManagement, 32}, {adapters.SigningCurveP256, 0x95, 32}, {adapters.SigningCurveP384, piv.SlotCardAuth, 48}} {
		key := signingTestKey(test.slot, adapters.SigningKey{Family: adapters.SigningKeyEC, CurveOID: test.curve})
		for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			if decision := adapters.MatchSigningCapability(report, key, signingDigestRequest(adapters.SigningECDSA, hash)); decision.Support != adapters.SigningSupported {
				t.Fatalf("%s/%s: %+v", test.curve, hash, decision)
			}
		}
		raw := adapters.SigningRequest{Parameters: adapters.SigningParameters{Scheme: adapters.SigningECDSA, Input: adapters.SigningInputDigest, Context: adapters.SigningContextAbsent}, InputLength: test.width}
		if decision := adapters.MatchSigningCapability(report, key, raw); decision.Support != adapters.SigningSupported {
			t.Fatalf("raw field-width digest: %+v", decision)
		}
		raw.InputLength++
		if decision := adapters.MatchSigningCapability(report, key, raw); decision.Support != adapters.SigningUnsupported {
			t.Fatalf("wrong raw digest length: %+v", decision)
		}
		for _, curve := range []string{adapters.SigningCurveSecp256k1, adapters.SigningCurveP521} {
			key.Key.CurveOID = curve
			if decision := adapters.MatchSigningCapability(report, key, signingDigestRequest(adapters.SigningECDSA, crypto.SHA256)); decision.Support == adapters.SigningSupported {
				t.Fatalf("different named curve %s matched %s", curve, test.curve)
			}
		}
	}
}

func TestPreviewQualificationSlotMatrix(t *testing.T) {
	report := NewAdapter().SigningCapabilities(qualifiedSigningDevice())
	slots := []piv.Slot{piv.SlotAuthentication, piv.SlotSignature, piv.SlotKeyManagement, piv.SlotCardAuth}
	for slot := piv.Slot(0x82); slot <= 0x95; slot++ {
		slots = append(slots, slot)
	}
	for _, slot := range slots {
		key := signingTestKey(slot, adapters.SigningKey{Family: adapters.SigningKeyEC, CurveOID: adapters.SigningCurveP256})
		for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			if decision := adapters.MatchSigningCapability(report, key, signingDigestRequest(adapters.SigningECDSA, hash)); decision.Support != adapters.SigningSupported {
				t.Errorf("P-256 slot %s hash %s: %+v", slot, hash, decision)
			}
		}
	}
	for _, test := range []struct {
		name   string
		key    adapters.SigningKey
		scheme adapters.SigningScheme
		slots  []piv.Slot
	}{
		{"Ed25519", adapters.SigningKey{Family: adapters.SigningKeyEdDSA, CurveOID: adapters.SigningCurveEd25519}, adapters.SigningEdDSA, []piv.Slot{0x9c, 0x9d, 0x82, 0x95}},
		{"ML-DSA-44", adapters.SigningKey{Family: adapters.SigningKeyMLDSA, MLDSAParameterSet: 44}, adapters.SigningMLDSA, []piv.Slot{0x9c, 0x82}},
		{"ML-DSA-65", adapters.SigningKey{Family: adapters.SigningKeyMLDSA, MLDSAParameterSet: 65}, adapters.SigningMLDSA, []piv.Slot{0x9a, 0x9c, 0x9d}},
		{"ML-DSA-87", adapters.SigningKey{Family: adapters.SigningKeyMLDSA, MLDSAParameterSet: 87}, adapters.SigningMLDSA, []piv.Slot{0x9c, 0x9e, 0x95}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := adapters.SigningRequest{Parameters: adapters.SigningParameters{Scheme: test.scheme, Input: adapters.SigningInputMessage, Mode: adapters.SigningModePure, Context: adapters.SigningContextAbsent}, InputLength: 4096}
			for _, slot := range slots {
				decision := adapters.MatchSigningCapability(report, signingTestKey(slot, test.key), request)
				want := adapters.SigningUnknown
				if slices.Contains(test.slots, slot) {
					want = adapters.SigningSupported
				}
				if decision.Support != want {
					t.Errorf("slot %s: got %+v, want %s", slot, decision, want)
				}
			}
		})
	}
}

func TestNEOQualificationEvidenceIsScoped(t *testing.T) {
	qualified := adapters.SigningDevice{Model: "YubiKey NEO", Firmware: "3.4.9", PIVVersion: "1.0.4"}
	for _, test := range []struct {
		name   string
		device adapters.SigningDevice
		want   bool
	}{
		{"exact", qualified, true},
		{"other model", adapters.SigningDevice{Model: "YubiKey NEO-n", Firmware: "3.4.9", PIVVersion: "1.0.4"}, false},
		{"other firmware", adapters.SigningDevice{Model: "YubiKey NEO", Firmware: "3.4.8", PIVVersion: "1.0.4"}, false},
		{"missing applet", adapters.SigningDevice{Model: "YubiKey NEO", Firmware: "3.4.9"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, profile := range NewAdapter().SigningCapabilities(test.device).Profiles {
				hardware := slices.ContainsFunc(profile.Evidence, func(e adapters.SigningEvidence) bool { return e.Source == "hardware-qualification" })
				eligible := profile.Parameters.Hash != 0 && (profile.Key.Family == adapters.SigningKeyEC && profile.Key.CurveOID == adapters.SigningCurveP256 && profile.Parameters.Scheme == adapters.SigningECDSA || profile.Key.Family == adapters.SigningKeyRSA && profile.Key.RSABits == 2048 && profile.Parameters.Scheme == adapters.SigningRSAPKCS1v15Digest)
				if hardware != (test.want && eligible) {
					t.Errorf("profile %s hardware evidence = %t, eligible=%t", profile.ID, hardware, eligible)
				}
			}
		})
	}
}

func TestYubiKey4QualificationEvidenceIsSlotScoped(t *testing.T) {
	device := adapters.SigningDevice{Model: "YubiKey 4", Firmware: "4.2.8", PIVVersion: "4.2.8"}
	testedSlots := []piv.Slot{0x9a, 0x9c, 0x9d, 0x9e, 0x82, 0x95}
	allSlots := append(slices.Clone(testedSlots), 0x83, 0x90, 0x94)
	for _, test := range []struct {
		name   string
		key    adapters.SigningKey
		scheme adapters.SigningScheme
		all    bool
	}{
		{"p256", adapters.SigningKey{Family: adapters.SigningKeyEC, CurveOID: adapters.SigningCurveP256}, adapters.SigningECDSA, true},
		{"p384", adapters.SigningKey{Family: adapters.SigningKeyEC, CurveOID: adapters.SigningCurveP384}, adapters.SigningECDSA, false},
		{"rsa2048", adapters.SigningKey{Family: adapters.SigningKeyRSA, RSABits: 2048}, adapters.SigningRSAPKCS1v15Digest, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := NewAdapter().SigningCapabilities(device)
			for _, slot := range allSlots {
				for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
					request := signingDigestRequest(test.scheme, hash)
					decision := adapters.MatchSigningCapability(report, signingTestKey(slot, test.key), request)
					if decision.Support != adapters.SigningSupported {
						t.Fatalf("slot %s hash %s: %+v", slot, hash, decision)
					}
					var matched []adapters.SigningProfile
					for _, profile := range report.Profiles {
						if profile.Key == test.key && profile.Parameters == request.Parameters && slices.Contains(profile.Slots, slot) {
							matched = append(matched, profile)
						}
					}
					if len(matched) != 1 {
						t.Fatalf("slot %s hash %s matched %d profiles", slot, hash, len(matched))
					}
					hardware := slices.ContainsFunc(matched[0].Evidence, func(e adapters.SigningEvidence) bool { return e.Source == "hardware-qualification" })
					if want := test.all || slices.Contains(testedSlots, slot); hardware != want {
						t.Errorf("slot %s hash %s hardware evidence=%t, want %t", slot, hash, hardware, want)
					}
				}
			}
		})
	}
	for _, device := range []adapters.SigningDevice{
		{Model: "YubiKey 4", Firmware: "4.2.8"},
		{Model: "YubiKey 4", Firmware: "4.2.9", PIVVersion: "4.2.8"},
		{Model: "YubiKey 4C", Firmware: "4.2.8", PIVVersion: "4.2.8"},
	} {
		for _, profile := range NewAdapter().SigningCapabilities(device).Profiles {
			if slices.ContainsFunc(profile.Evidence, func(e adapters.SigningEvidence) bool { return e.Source == "hardware-qualification" }) {
				t.Errorf("hardware qualification leaked to device %+v", device)
			}
		}
	}
}

func TestYubiKey5QualificationEvidenceIsScoped(t *testing.T) {
	device := adapters.SigningDevice{Model: "YubiKey 5C NFC", Firmware: "5.4.3", PIVVersion: "5.4.3"}
	report := NewAdapter().SigningCapabilities(device)
	slots := []piv.Slot{0x9a, 0x9c, 0x9d, 0x9e}
	for slot := piv.Slot(0x82); slot <= 0x95; slot++ {
		slots = append(slots, slot)
	}
	for _, test := range []struct {
		name   string
		key    adapters.SigningKey
		scheme adapters.SigningScheme
	}{
		{"p256", adapters.SigningKey{Family: adapters.SigningKeyEC, CurveOID: adapters.SigningCurveP256}, adapters.SigningECDSA},
		{"p384", adapters.SigningKey{Family: adapters.SigningKeyEC, CurveOID: adapters.SigningCurveP384}, adapters.SigningECDSA},
		{"rsa2048", adapters.SigningKey{Family: adapters.SigningKeyRSA, RSABits: 2048}, adapters.SigningRSAPKCS1v15Digest},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, slot := range slots {
				for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
					request := signingDigestRequest(test.scheme, hash)
					decision := adapters.MatchSigningCapability(report, signingTestKey(slot, test.key), request)
					if decision.Support != adapters.SigningSupported {
						t.Fatalf("slot %s hash %s: %+v", slot, hash, decision)
					}
					profileIndex := slices.IndexFunc(report.Profiles, func(profile adapters.SigningProfile) bool { return profile.ID == decision.ProfileID })
					if profileIndex < 0 || !slices.ContainsFunc(report.Profiles[profileIndex].Evidence, func(e adapters.SigningEvidence) bool { return e.Source == "hardware-qualification" }) {
						t.Errorf("slot %s hash %s missing hardware evidence", slot, hash)
					}
				}
			}
		})
	}
	for _, profile := range report.Profiles {
		if profile.Parameters.Scheme == adapters.SigningRSAPSS && slices.ContainsFunc(profile.Evidence, func(e adapters.SigningEvidence) bool { return e.Source == "hardware-qualification" }) {
			t.Errorf("partially tested PSS salt range acquired hardware evidence: %s", profile.ID)
		}
	}
	for _, other := range []adapters.SigningDevice{
		{Model: "YubiKey 5C NFC", Firmware: "5.4.3"},
		{Model: "YubiKey 5C NFC", Firmware: "5.4.2", PIVVersion: "5.4.3"},
		{Model: "YubiKey 5C", Firmware: "5.4.3", PIVVersion: "5.4.3"},
	} {
		for _, profile := range NewAdapter().SigningCapabilities(other).Profiles {
			if slices.ContainsFunc(profile.Evidence, func(e adapters.SigningEvidence) bool { return e.Source == "hardware-qualification" }) {
				t.Errorf("hardware qualification leaked to device %+v", other)
			}
		}
	}
}

func TestQualifiedMessageSigningProfilesRemainPure(t *testing.T) {
	report := NewAdapter().SigningCapabilities(qualifiedSigningDevice())
	for _, key := range []adapters.SigningKey{
		{Family: adapters.SigningKeyEdDSA, CurveOID: adapters.SigningCurveEd25519},
		{Family: adapters.SigningKeyMLDSA, MLDSAParameterSet: 44},
		{Family: adapters.SigningKeyMLDSA, MLDSAParameterSet: 65},
		{Family: adapters.SigningKeyMLDSA, MLDSAParameterSet: 87},
	} {
		scheme := adapters.SigningMLDSA
		if key.Family == adapters.SigningKeyEdDSA {
			scheme = adapters.SigningEdDSA
		}
		evidence := signingTestKey(piv.SlotSignature, key)
		request := adapters.SigningRequest{Parameters: adapters.SigningParameters{Scheme: scheme, Input: adapters.SigningInputMessage, Mode: adapters.SigningModePure, Context: adapters.SigningContextAbsent}}
		for _, length := range []int{0, 32, 4096} {
			request.InputLength = length
			if decision := adapters.MatchSigningCapability(report, evidence, request); decision.Support != adapters.SigningSupported {
				t.Fatalf("%+v/length%d: %+v", key, length, decision)
			}
		}
		request.InputLength = 4097
		if decision := adapters.MatchSigningCapability(report, evidence, request); decision.Support != adapters.SigningUnsupported || decision.Reason != adapters.SigningReasonLimits {
			t.Fatalf("overlong message: %+v", decision)
		}
		request.InputLength = 32
		request.Randomness = adapters.SigningRandomnessHedged
		if decision := adapters.MatchSigningCapability(report, evidence, request); decision.Support != adapters.SigningUnknown || decision.Reason != adapters.SigningReasonRandomness {
			t.Fatalf("unknown device randomness became hedged: %+v", decision)
		}
		request.Randomness = ""
		request.Parameters.Context = adapters.SigningContextPresent
		if decision := adapters.MatchSigningCapability(report, evidence, request); decision.Support == adapters.SigningSupported {
			t.Fatal("present empty context was treated as absent")
		}
		request.Parameters.Context = adapters.SigningContextAbsent
		request.Parameters.Input = adapters.SigningInputDigest
		request.Parameters.Hash = crypto.SHA256
		request.Parameters.Mode = adapters.SigningModePrehash
		if decision := adapters.MatchSigningCapability(report, evidence, request); decision.Support == adapters.SigningSupported {
			t.Fatal("pure profile acquired a prehash mode")
		}
	}
}

func TestSigningReportsArePureAndSeparateFromLiveKeyEvidence(t *testing.T) {
	card := emulator.NewCard()
	adapter := NewAdapter()
	runtime := adapters.NewRuntime(adapters.NewSession(piv.NewClient(card)), adapter)
	coarse := adapters.ReportCapabilities(adapter)
	device := qualifiedSigningDevice()
	device.Evidence = []adapters.SigningEvidence{{Source: "caller-cache"}}
	report := adapters.ReportSigningCapabilities(runtime.Adapter, device)
	report.Device.Evidence[0].Source = "changed report"
	if device.Evidence[0].Source != "caller-cache" {
		t.Fatal("report aliases the caller's device evidence")
	}
	for _, profile := range report.Profiles {
		if len(profile.Evidence) == 0 || profile.Evidence[0].Source != "hardware-qualification" {
			t.Fatalf("qualified profile lost provenance: %+v", profile)
		}
	}
	key := signingTestKey(piv.SlotAuthentication, adapters.SigningKey{Family: adapters.SigningKeyRSA, RSABits: 2048})
	request := signingDigestRequest(adapters.SigningRSAPSS, crypto.SHA256)
	for _, source := range []adapters.PublicKeySource{adapters.PublicKeySourceCertificate, adapters.PublicKeySourceStoredTemplate, ""} {
		key.Source = source
		if decision := adapters.MatchSigningCapability(report, key, request); decision.Support != adapters.SigningUnknown {
			t.Fatalf("public source %s proved a current private key: %+v", source, decision)
		}
	}
	key.Source = adapters.PublicKeySourceMetadata
	key.Current = false
	if decision := adapters.MatchSigningCapability(report, key, request); decision.Support != adapters.SigningUnknown {
		t.Fatalf("cached key presence became current: %+v", decision)
	}
	if len(card.TransmittedCommands) != 0 {
		t.Fatalf("signing discovery sent %d APDUs", len(card.TransmittedCommands))
	}
	if !reflect.DeepEqual(coarse, adapters.ReportCapabilities(adapter)) {
		t.Fatal("signing report changed the existing coarse capabilities")
	}
}

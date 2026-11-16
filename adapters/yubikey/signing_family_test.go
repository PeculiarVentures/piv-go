package yubikey

import (
	"crypto"
	"slices"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/piv"
)

func TestSigningDeviceFamilies(t *testing.T) {
	for _, test := range []struct {
		device adapters.SigningDevice
		want   signingFamily
	}{
		{adapters.SigningDevice{Model: "YubiKey NEO", Firmware: "3.4.9"}, signingFamilyNEO},
		{adapters.SigningDevice{Model: "YubiKey 4", Firmware: "4.2.8"}, signingFamily4},
		{adapters.SigningDevice{Model: "YubiKey 5C NFC", Firmware: "5.4.3"}, signingFamily5},
		{adapters.SigningDevice{Model: qualifiedPreviewModel, Firmware: qualifiedPreviewFirmware, PIVVersion: "0.0.1"}, signingFamily6Preview},
		{adapters.SigningDevice{Model: qualifiedPreviewModel, Firmware: "6.0.0.alpha.2"}, signingFamily6Preview},
		{adapters.SigningDevice{Model: qualifiedPreviewModel, Firmware: "6.0.0.beta.1"}, signingFamily6Preview},
		{adapters.SigningDevice{Model: "YubiKey 5C NFC", Firmware: qualifiedPreviewFirmware}, signingFamilyUnknown},
		{adapters.SigningDevice{Model: qualifiedPreviewModel, Firmware: "5.7.0"}, signingFamilyUnknown},
	} {
		t.Run(test.device.Model+"/"+test.device.Firmware, func(t *testing.T) {
			got, _ := signingDeviceFamily(test.device)
			if got != test.want {
				t.Fatalf("family = %d, want %d", got, test.want)
			}
		})
	}
}

func TestPreviewFirmwareAndIdentityFailClosed(t *testing.T) {
	for _, firmware := range []string{
		"", "0.0.1", "5.7.0.alpha.8", "7.0.0.alpha.8", "6.0.0", "6.0.0.final.0", "6.0.0.rc.1",
		"6.0.0.alpha2", "6.0.0.alpha", "6.0.0.beta", "6.0.0-alpha.8", "6.0.0.alpha.",
		"6.0.0.alpha.-1", "6.0.0.beta.+1", "6.0.0.alpha.01", "6.0.0.alpha.1.extra", "6.0.0.ALPHA.8",
		"6.256.0.alpha.8", "6.0.256.beta.8", "6.00.0.alpha.8", "06.0.0.alpha.8", "6.0.0.alpha.8 ",
		" 6.0.0.alpha.8", "6.0.0.beta.１", "6.0.0.alpha.1\n",
	} {
		t.Run(firmware, func(t *testing.T) {
			report := NewAdapter().SigningCapabilities(adapters.SigningDevice{Model: qualifiedPreviewModel, Firmware: firmware, PIVVersion: "0.0.1"})
			if len(report.Profiles) != 0 || report.Fallback.Support != adapters.SigningUnknown || report.Fallback.Reason != adapters.SigningReasonDeviceProfileUnavailable {
				t.Fatalf("invalid or out-of-policy firmware acquired profiles: %+v", report)
			}
		})
	}
	for _, model := range []string{
		"", "YubiKey 6", "YubiKey 5C NFC", "YubiKey 5C NFC FIPS", "YubiKey 5C NFC - Enhanced PIN FIPS",
		"YubiKey Bio - Multi-protocol Edition", "YubiKey 5C NFC - Enhanced PIN unknown",
		"Yubico YubiKey 5C NFC - Enhanced PIN", "YubiKey 5C NFC - Enhanced PIN ",
	} {
		t.Run(model, func(t *testing.T) {
			report := NewAdapter().SigningCapabilities(adapters.SigningDevice{Model: model, Firmware: qualifiedPreviewFirmware, PIVVersion: "0.0.1"})
			if len(report.Profiles) != 0 || report.Fallback.Support != adapters.SigningUnknown {
				t.Fatalf("unknown model inherited preview profiles: %+v", report)
			}
		})
	}
}

func TestPreviewFamilyMessageProfilesAcrossReleases(t *testing.T) {
	for _, firmware := range []string{qualifiedPreviewFirmware, "6.0.0.alpha.2", "6.0.0.alpha.9", "6.0.0.beta.0", "6.1.2.beta.257", "6.255.255.alpha.12345678901234567890"} {
		t.Run(firmware, func(t *testing.T) {
			report := NewAdapter().SigningCapabilities(adapters.SigningDevice{Model: qualifiedPreviewModel, Firmware: firmware})
			if report.Fallback.Support != adapters.SigningUnknown {
				t.Fatalf("preview fallback should remain unknown: %+v", report.Fallback)
			}
			slots := []piv.Slot{0x9a, 0x9c, 0x9d, 0x9e}
			for slot := piv.Slot(0x82); slot <= 0x95; slot++ {
				slots = append(slots, slot)
			}
			for _, test := range []struct {
				key    adapters.SigningKey
				scheme adapters.SigningScheme
				size   int
			}{
				{adapters.SigningKey{Family: adapters.SigningKeyEdDSA, CurveOID: adapters.SigningCurveEd25519}, adapters.SigningEdDSA, 64},
				{adapters.SigningKey{Family: adapters.SigningKeyMLDSA, MLDSAParameterSet: 44}, adapters.SigningMLDSA, 2420},
				{adapters.SigningKey{Family: adapters.SigningKeyMLDSA, MLDSAParameterSet: 65}, adapters.SigningMLDSA, 3309},
				{adapters.SigningKey{Family: adapters.SigningKeyMLDSA, MLDSAParameterSet: 87}, adapters.SigningMLDSA, 4627},
			} {
				var profile *adapters.SigningProfile
				for i := range report.Profiles {
					if report.Profiles[i].Key == test.key {
						profile = &report.Profiles[i]
						break
					}
				}
				if profile == nil || profile.SignatureLength != (adapters.SigningLengthRange{Min: test.size, Max: test.size}) || profile.ResultEncoding != adapters.SigningResultRaw || profile.Transport.ExtendedAPDU != adapters.SigningSupported || profile.Transport.MaxCommandData != 4106 || profile.Transport.MaxResponseData != test.size+8 {
					t.Fatalf("missing or incorrect message profile for %+v: %+v", test.key, profile)
				}
				request := adapters.SigningRequest{Parameters: adapters.SigningParameters{Scheme: test.scheme, Input: adapters.SigningInputMessage, Mode: adapters.SigningModePure, Context: adapters.SigningContextAbsent}}
				for _, slot := range slots {
					key := signingTestKey(slot, test.key)
					for _, length := range []int{0, 1, 32, 4096} {
						request.InputLength = length
						if decision := adapters.MatchSigningCapability(report, key, request); decision.Support != adapters.SigningSupported || !strings.HasPrefix(decision.ProfileID, "yubikey/6-preview/") {
							t.Fatalf("%+v slot %s length %d: %+v", test.key, slot, length, decision)
						}
					}
					request.InputLength = 4097
					if decision := adapters.MatchSigningCapability(report, key, request); decision.Support != adapters.SigningUnsupported || decision.Reason != adapters.SigningReasonLimits {
						t.Fatalf("overlong message: %+v", decision)
					}
				}
				request.InputLength = 32
				key := signingTestKey(piv.SlotSignature, test.key)
				for _, change := range []func(*adapters.SigningRequest){
					func(r *adapters.SigningRequest) { r.Parameters.Context = adapters.SigningContextPresent },
					func(r *adapters.SigningRequest) {
						r.Parameters.Mode = adapters.SigningModePrehash
						r.Parameters.Input = adapters.SigningInputDigest
						r.Parameters.Hash = crypto.SHA256
					},
					func(r *adapters.SigningRequest) { r.Parameters.Hash = crypto.SHA256 },
					func(r *adapters.SigningRequest) { r.Randomness = adapters.SigningRandomnessHedged },
				} {
					changed := request
					change(&changed)
					if decision := adapters.MatchSigningCapability(report, key, changed); decision.Support == adapters.SigningSupported {
						t.Fatalf("unsupported message parameters matched: %+v", changed)
					}
				}
				key.Source = adapters.PublicKeySourceCertificate
				if decision := adapters.MatchSigningCapability(report, key, request); decision.Support != adapters.SigningUnknown || decision.Reason != adapters.SigningReasonKeyUnknown {
					t.Fatalf("family policy proved a private key: %+v", decision)
				}
			}
			for _, algorithm := range []byte{piv.AlgX25519, piv.AlgMLKEM512, piv.AlgMLKEM768, piv.AlgMLKEM1024} {
				if _, err := adapters.SigningKeyFromPublicKey(&piv.OpaquePublicKey{Algorithm: algorithm}); err == nil {
					t.Fatalf("non-signing algorithm %02X became a signing key", algorithm)
				}
			}
		})
	}
}

func TestPreviewHardwareEvidenceRequiresExactTuple(t *testing.T) {
	for _, device := range []adapters.SigningDevice{
		qualifiedSigningDevice(),
		{Model: qualifiedPreviewModel, Firmware: qualifiedPreviewFirmware},
		{Model: qualifiedPreviewModel, Firmware: qualifiedPreviewFirmware, PIVVersion: "0.0.2"},
		{Model: qualifiedPreviewModel, Firmware: "6.0.0.alpha.2", PIVVersion: "0.0.1"},
		{Model: qualifiedPreviewModel, Firmware: "6.0.0.beta.1", PIVVersion: "0.0.1"},
	} {
		t.Run(device.Firmware+"/"+device.PIVVersion, func(t *testing.T) {
			report := NewAdapter().SigningCapabilities(device)
			if len(report.Profiles) == 0 {
				t.Fatal("family profile depends on qualified applet version")
			}
			exact := device.Firmware == qualifiedPreviewFirmware && device.PIVVersion == "0.0.1"
			hardware := false
			for _, profile := range report.Profiles {
				if !slices.ContainsFunc(profile.Evidence, func(e adapters.SigningEvidence) bool {
					return e.Source == "family-policy" && e.Reference == yubiKeySigningFamilyPolicyReference
				}) {
					t.Fatalf("profile lost policy provenance: %+v", profile)
				}
				for _, evidence := range profile.Evidence {
					if evidence.Source == "hardware-qualification" || evidence.Source == "hardware-samples" {
						hardware = true
						if !exact || evidence.Reference != yubiKeySigningQualificationReference {
							t.Fatalf("hardware evidence escaped its tuple: %+v", profile)
						}
						if evidence.Source == "hardware-qualification" && (profile.InputLength.Min != profile.InputLength.Max || profile.SaltLength.Min != profile.SaltLength.Max || profile.Parameters.Scheme == adapters.SigningECDSA && profile.Parameters.Hash == 0) {
							t.Fatalf("sampled or untested parameters claimed qualification: %+v", profile)
						}
						if slices.Contains(profile.Slots, piv.Slot(0x83)) {
							t.Fatalf("original matrix did not qualify this slot: %+v", profile)
						}
					}
				}
			}
			if hardware != exact {
				t.Fatalf("hardware evidence = %t, exact tuple = %t", hardware, exact)
			}
		})
	}
}

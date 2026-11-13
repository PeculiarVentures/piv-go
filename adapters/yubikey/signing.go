package yubikey

import (
	"crypto"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/piv"
)

const (
	yubiKeySigningProtocolReference      = "https://developers.yubico.com/PIV/Introduction/YubiKey_and_PIV.html"
	yubiKeySigningSlotsReference         = "https://developers.yubico.com/PIV/Introduction/Certificate_slots.html"
	yubiKeySigningTransportReference     = "https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-piv.html"
	yubiKeySigningSchemesReference       = "https://github.com/Yubico/yubikey-manager/blob/5.9.2/yubikit/piv.py"
	yubiKeySigningQualificationReference = "docs/signing-qualification.md"
	qualifiedPreviewModel                = "YubiKey 5C NFC - Enhanced PIN"
	qualifiedPreviewFirmware             = "6.0.0.alpha.8"
)

// SigningCapabilities reports signing profiles from an explicit cached device
// snapshot. It performs no APDU, PIN verification, applet selection, or key
// discovery. Firmware must identify the device firmware, not PIV GET VERSION.
// These profiles do not establish the current private key or authorize its use.
//
// Non-FIPS YubiKey NEO, 4 and 5 model names with matching production firmware
// use vendor-documented profiles. FIPS, unknown models, and preview firmware
// require separate evidence; one exact preview tuple has a qualified subset.
// Model uses yubikit.support.get_name from ykman 5.9.2 (plus the documented
// legacy product aliases below). Firmware is the device version and qualifier
// from explicit management/device inventory, not PIV GET VERSION or a reader
// label. Reporting does not discover either value. Without current authoritative
// key metadata, MatchSigningCapability still returns unknown on legacy devices.
func (a *Adapter) SigningCapabilities(device adapters.SigningDevice) adapters.SigningCapabilityReport {
	report := adapters.SigningCapabilityReport{
		AdapterName: a.Name(),
		Device:      cloneSigningDevice(device),
		Fallback: adapters.SigningDecision{
			Support: adapters.SigningUnknown,
			Reason:  adapters.SigningReasonDeviceProfileUnavailable,
			Detail:  "the exact model and device firmware have no documented or qualified signing profile",
		},
	}
	if device.Model == qualifiedPreviewModel && device.Firmware == qualifiedPreviewFirmware && device.PIVVersion == "0.0.1" {
		report.Profiles = qualifiedPreviewSigningProfiles()
		report.Fallback.Reason = adapters.SigningReasonQualificationPending
		report.Fallback.Detail = "this preview qualification covers only the listed algorithms, slots and parameter limits"
		return report
	}
	major, minor, valid := signingFirmwareVersion(device.Firmware)
	if !valid || signingModelGeneration(device.Model) != major || major < 3 || major > 5 {
		return report
	}
	report.Fallback = adapters.SigningDecision{
		Support: adapters.SigningUnsupported,
		Reason:  adapters.SigningReasonProfileNotImplemented,
		Detail:  "the requested operation has no implemented profile for this documented model and firmware",
	}
	slots := []piv.Slot{piv.SlotAuthentication, piv.SlotSignature, piv.SlotKeyManagement, piv.SlotCardAuth}
	if major >= 4 {
		for slot := piv.Slot(0x82); slot <= 0x95; slot++ {
			slots = append(slots, slot)
		}
	}
	evidence := []adapters.SigningEvidence{
		{Source: "vendor-documentation", Reference: yubiKeySigningProtocolReference},
		{Source: "vendor-documentation", Reference: yubiKeySigningSlotsReference},
		{Source: "vendor-implementation", Reference: yubiKeySigningSchemesReference},
	}
	if major == 5 {
		evidence = append(evidence, adapters.SigningEvidence{Source: "vendor-documentation", Reference: yubiKeySigningTransportReference})
	}
	for _, bits := range []int{1024, 2048} {
		report.Profiles = append(report.Profiles, rsaSigningProfiles("yubikey/documented", bits, slots, evidence, major == 5)...)
	}
	report.Profiles = append(report.Profiles, ecSigningProfiles("yubikey/documented", adapters.SigningCurveP256, slots, evidence)...)
	if major >= 4 {
		report.Profiles = append(report.Profiles, ecSigningProfiles("yubikey/documented", adapters.SigningCurveP384, slots, evidence)...)
	}
	if major == 5 && minor >= 7 {
		for _, bits := range []int{3072, 4096} {
			report.Profiles = append(report.Profiles, rsaSigningProfiles("yubikey/documented", bits, slots, evidence, true)...)
		}
		// The algorithm is documented, but the public documents do not
		// establish a message-length limit for this exact implementation.
		// Do not borrow a preview device's qualified limits for production.
		ed := messageSigningProfile("yubikey/documented/ed25519", adapters.SigningKey{Family: adapters.SigningKeyEdDSA, CurveOID: adapters.SigningCurveEd25519}, adapters.SigningEdDSA, 64, slots, evidence)
		ed.Support = adapters.SigningUnknown
		ed.Reason = adapters.SigningReasonMessageLimitUnqualified
		ed.Detail = "Ed25519 is vendor-documented on firmware 5.7 and later; message and transport limits need qualification for this model"
		ed.InputLength = adapters.SigningLengthRange{}
		ed.Transport = adapters.SigningTransport{}
		report.Profiles = append(report.Profiles, ed)
	}
	if device.Model == "YubiKey NEO" && device.Firmware == "3.4.9" && device.PIVVersion == "1.0.4" {
		// The hardware run covered these named-hash operations in every slot
		// in the documented NEO profiles. Keep other claims documented only:
		// the run did not cover every raw digest or PSS salt length in every slot.
		for i := range report.Profiles {
			profile := &report.Profiles[i]
			if profile.Parameters.Hash != 0 &&
				(profile.Key.Family == adapters.SigningKeyEC && profile.Key.CurveOID == adapters.SigningCurveP256 && profile.Parameters.Scheme == adapters.SigningECDSA ||
					profile.Key.Family == adapters.SigningKeyRSA && profile.Key.RSABits == 2048 && profile.Parameters.Scheme == adapters.SigningRSAPKCS1v15Digest) {
				profile.Evidence = append(profile.Evidence, adapters.SigningEvidence{Source: "hardware-qualification", Reference: yubiKeySigningQualificationReference})
			}
		}
	}
	if device.Model == "YubiKey 5C NFC" && device.Firmware == "5.4.3" && device.PIVVersion == "5.4.3" {
		// Named-hash ECDSA and RSA-2048 PKCS#1 v1.5 were verified in every
		// ordinary and retired slot. The PSS run covered only hash-sized salts.
		for i := range report.Profiles {
			profile := &report.Profiles[i]
			if profile.Parameters.Hash != 0 &&
				(profile.Key.Family == adapters.SigningKeyEC && (profile.Key.CurveOID == adapters.SigningCurveP256 || profile.Key.CurveOID == adapters.SigningCurveP384) && profile.Parameters.Scheme == adapters.SigningECDSA ||
					profile.Key.Family == adapters.SigningKeyRSA && profile.Key.RSABits == 2048 && profile.Parameters.Scheme == adapters.SigningRSAPKCS1v15Digest) {
				profile.Evidence = append(profile.Evidence, adapters.SigningEvidence{Source: "hardware-qualification", Reference: yubiKeySigningQualificationReference})
			}
		}
	}
	if device.Model == "YubiKey 4" && device.Firmware == "4.2.8" && device.PIVVersion == "4.2.8" {
		report.Profiles = qualifyYubiKey4SigningProfiles(report.Profiles)
	}
	return report
}

// Keep the untested slots on their vendor-documented profiles: hardware
// evidence covers the complete P-256 slot set, but only a sample for P-384
// and RSA-2048. A split preserves the original claims without attributing
// the sample's evidence to the rest of the slots.
func qualifyYubiKey4SigningProfiles(profiles []adapters.SigningProfile) []adapters.SigningProfile {
	testedSlots := []piv.Slot{piv.SlotAuthentication, piv.SlotSignature, piv.SlotKeyManagement, piv.SlotCardAuth, 0x82, 0x95}
	evidence := adapters.SigningEvidence{Source: "hardware-qualification", Reference: yubiKeySigningQualificationReference}
	for i := range len(profiles) {
		profile := &profiles[i]
		if profile.Parameters.Hash == 0 {
			continue
		}
		if profile.Key.Family == adapters.SigningKeyEC && profile.Key.CurveOID == adapters.SigningCurveP256 && profile.Parameters.Scheme == adapters.SigningECDSA {
			profile.Evidence = append(profile.Evidence, evidence)
			continue
		}
		if !(profile.Key.Family == adapters.SigningKeyEC && profile.Key.CurveOID == adapters.SigningCurveP384 && profile.Parameters.Scheme == adapters.SigningECDSA ||
			profile.Key.Family == adapters.SigningKeyRSA && profile.Key.RSABits == 2048 && profile.Parameters.Scheme == adapters.SigningRSAPKCS1v15Digest) {
			continue
		}
		var tested, remaining []piv.Slot
		for _, slot := range profile.Slots {
			if slices.Contains(testedSlots, slot) {
				tested = append(tested, slot)
			} else {
				remaining = append(remaining, slot)
			}
		}
		qualified := *profile
		qualified.ID += "/qualified-4.2.8"
		qualified.Slots = tested
		qualified.Evidence = append(slices.Clone(profile.Evidence), evidence)
		profile.Slots = remaining
		profiles = append(profiles, qualified)
	}
	return profiles
}

func cloneSigningDevice(device adapters.SigningDevice) adapters.SigningDevice {
	device.Evidence = append([]adapters.SigningEvidence(nil), device.Evidence...)
	return device
}

// Model strings are product identities, not reader-name substring matches.
// In particular, a FIPS or Enhanced PIN suffix does not inherit a model's
// ordinary production capabilities without its own qualification.
// ykman's canonical names include YubiKey 5A and the aggregate YubiKey 4.
// NEO-n, 4 Nano/4C/4C Nano and the generic 5 are retained product aliases.
func signingModelGeneration(model string) int {
	switch model {
	case "YubiKey NEO", "YubiKey NEO-n":
		return 3
	case "YubiKey 4", "YubiKey 4 Nano", "YubiKey 4C", "YubiKey 4C Nano":
		return 4
	case "YubiKey 5", "YubiKey 5A", "YubiKey 5 NFC", "YubiKey 5 Nano", "YubiKey 5C", "YubiKey 5C NFC", "YubiKey 5C Nano", "YubiKey 5Ci":
		return 5
	default:
		return 0
	}
}

func signingFirmwareVersion(version string) (major, minor int, valid bool) {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return 0, 0, false
	}
	var numbers [3]int
	for i, part := range parts {
		if part == "" || len(part) > 3 {
			return 0, 0, false
		}
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return 0, 0, false
			}
		}
		value, err := strconv.Atoi(part)
		if err != nil || value > 255 {
			return 0, 0, false
		}
		numbers[i] = value
	}
	return numbers[0], numbers[1], numbers[0] != 0
}

func qualifiedPreviewSigningProfiles() []adapters.SigningProfile {
	evidence := []adapters.SigningEvidence{{Source: "hardware-qualification", Reference: yubiKeySigningQualificationReference}}
	prefix := "yubikey/qualified-6.0.0.alpha.8"
	var profiles []adapters.SigningProfile
	for _, test := range []struct {
		bits int
		slot piv.Slot
	}{{2048, piv.SlotAuthentication}, {3072, piv.SlotSignature}, {4096, 0x82}} {
		profiles = append(profiles, rsaSigningProfiles(prefix, test.bits, []piv.Slot{test.slot}, evidence, test.bits > 2048)...)
	}
	p256Slots := []piv.Slot{piv.SlotAuthentication, piv.SlotSignature, piv.SlotKeyManagement, piv.SlotCardAuth}
	for slot := piv.Slot(0x82); slot <= 0x95; slot++ {
		p256Slots = append(p256Slots, slot)
	}
	profiles = append(profiles, ecSigningProfiles(prefix, adapters.SigningCurveP256, p256Slots, evidence)...)
	profiles = append(profiles, ecSigningProfiles(prefix, adapters.SigningCurveP384, []piv.Slot{piv.SlotCardAuth}, evidence)...)
	profiles = append(profiles, messageSigningProfile(prefix+"/ed25519", adapters.SigningKey{Family: adapters.SigningKeyEdDSA, CurveOID: adapters.SigningCurveEd25519}, adapters.SigningEdDSA, 64, []piv.Slot{piv.SlotSignature, piv.SlotKeyManagement, 0x82, 0x95}, evidence))
	for _, variant := range []struct {
		algorithm    byte
		parameterSet int
		slots        []piv.Slot
	}{
		{piv.AlgMLDSA44, 44, []piv.Slot{piv.SlotSignature, 0x82}},
		{piv.AlgMLDSA65, 65, []piv.Slot{piv.SlotAuthentication, piv.SlotSignature, piv.SlotKeyManagement}},
		{piv.AlgMLDSA87, 87, []piv.Slot{piv.SlotSignature, piv.SlotCardAuth, 0x95}},
	} {
		size, _ := piv.MLDSASignatureLength(variant.algorithm)
		profiles = append(profiles, messageSigningProfile(fmt.Sprintf("%s/mldsa%d", prefix, variant.parameterSet), adapters.SigningKey{Family: adapters.SigningKeyMLDSA, MLDSAParameterSet: variant.parameterSet}, adapters.SigningMLDSA, size, variant.slots, evidence))
	}
	return profiles
}

func rsaSigningProfiles(prefix string, bits int, slots []piv.Slot, evidence []adapters.SigningEvidence, extended bool) []adapters.SigningProfile {
	k := bits / 8
	base := adapters.SigningProfile{
		Key:             adapters.SigningKey{Family: adapters.SigningKeyRSA, RSABits: bits},
		Slots:           append([]piv.Slot(nil), slots...),
		SignatureLength: adapters.SigningLengthRange{Min: k, Max: k},
		ResultEncoding:  adapters.SigningResultRaw,
		Randomness:      adapters.SigningRandomnessDeterministic,
		Support:         adapters.SigningSupported,
		Evidence:        append([]adapters.SigningEvidence(nil), evidence...),
		Transport:       adapters.SigningTransport{CommandChaining: adapters.SigningUnsupported, ExtendedAPDU: adapters.SigningUnknown, MaxCommandData: k + 10, MaxResponseData: k + 8},
	}
	if bits <= 2048 {
		base.Transport.CommandChaining = adapters.SigningSupported
		base.Transport.MaxCommandData = 216 // maximum fragment used by Authenticate
	}
	if extended {
		base.Transport.ExtendedAPDU = adapters.SigningSupported
	}
	payload := base
	payload.ID = fmt.Sprintf("%s/rsa%d/pkcs1-payload", prefix, bits)
	payload.Parameters = adapters.SigningParameters{Scheme: adapters.SigningRSAPKCS1v15Payload, Input: adapters.SigningInputPayload, Context: adapters.SigningContextAbsent}
	payload.InputLength = adapters.SigningLengthRange{Max: k - 11}
	profiles := []adapters.SigningProfile{payload}
	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		digest := base
		digest.ID = fmt.Sprintf("%s/rsa%d/pkcs1/%s", prefix, bits, hash)
		digest.Parameters = adapters.SigningParameters{Scheme: adapters.SigningRSAPKCS1v15Digest, Input: adapters.SigningInputDigest, Hash: hash, Context: adapters.SigningContextAbsent}
		digest.InputLength = adapters.SigningLengthRange{Min: hash.Size(), Max: hash.Size()}
		profiles = append(profiles, digest)
		pss := digest
		pss.ID = fmt.Sprintf("%s/rsa%d/pss/%s", prefix, bits, hash)
		pss.Parameters.Scheme = adapters.SigningRSAPSS
		pss.Parameters.MGF1Hash = hash
		pss.SaltLength = adapters.SigningLengthRange{Min: 1, Max: k - hash.Size() - 2}
		pss.Randomness = adapters.SigningRandomnessHostCSPRNG
		profiles = append(profiles, pss)
		zeroSalt := pss
		zeroSalt.ID += "/salt-0"
		zeroSalt.SaltLength = adapters.SigningLengthRange{}
		zeroSalt.Randomness = adapters.SigningRandomnessDeterministic
		profiles = append(profiles, zeroSalt)
	}
	return profiles
}

func ecSigningProfiles(prefix, curve string, slots []piv.Slot, evidence []adapters.SigningEvidence) []adapters.SigningProfile {
	width := 32
	if curve == adapters.SigningCurveP384 {
		width = 48
	}
	base := adapters.SigningProfile{
		Key:             adapters.SigningKey{Family: adapters.SigningKeyEC, CurveOID: curve},
		Slots:           append([]piv.Slot(nil), slots...),
		SignatureLength: adapters.SigningLengthRange{Min: 8, Max: 2*width + 8},
		ResultEncoding:  adapters.SigningResultASN1DER,
		Randomness:      adapters.SigningRandomnessUnknown,
		Support:         adapters.SigningSupported,
		Detail:          "named-hash digests use Client.SignECDSA for field-width formatting; raw digests have the exact field width",
		Evidence:        append([]adapters.SigningEvidence(nil), evidence...),
		Transport:       adapters.SigningTransport{CommandChaining: adapters.SigningUnknown, ExtendedAPDU: adapters.SigningUnknown, MaxCommandData: width + 6, MaxResponseData: 2*width + 12},
	}
	var profiles []adapters.SigningProfile
	for _, hash := range []crypto.Hash{0, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		profile := base
		hashName := "raw"
		if hash != 0 {
			hashName = hash.String()
		}
		profile.ID = fmt.Sprintf("%s/ec-%s/%s", prefix, curve, hashName)
		profile.Parameters = adapters.SigningParameters{Scheme: adapters.SigningECDSA, Input: adapters.SigningInputDigest, Hash: hash, Context: adapters.SigningContextAbsent}
		inputLength := width
		if hash != 0 {
			inputLength = hash.Size()
		}
		profile.InputLength = adapters.SigningLengthRange{Min: inputLength, Max: inputLength}
		profiles = append(profiles, profile)
	}
	return profiles
}

func messageSigningProfile(id string, key adapters.SigningKey, scheme adapters.SigningScheme, size int, slots []piv.Slot, evidence []adapters.SigningEvidence) adapters.SigningProfile {
	return adapters.SigningProfile{
		ID:              id,
		Key:             key,
		Parameters:      adapters.SigningParameters{Scheme: scheme, Input: adapters.SigningInputMessage, Mode: adapters.SigningModePure, Context: adapters.SigningContextAbsent},
		Slots:           append([]piv.Slot(nil), slots...),
		InputLength:     adapters.SigningLengthRange{Max: 4096},
		SignatureLength: adapters.SigningLengthRange{Min: size, Max: size},
		ResultEncoding:  adapters.SigningResultRaw,
		Randomness:      adapters.SigningRandomnessUnknown,
		Support:         adapters.SigningSupported,
		Evidence:        append([]adapters.SigningEvidence(nil), evidence...),
		Transport:       adapters.SigningTransport{CommandChaining: adapters.SigningUnsupported, ExtendedAPDU: adapters.SigningSupported, MaxCommandData: 4106, MaxResponseData: size + 8},
	}
}

var _ adapters.SigningCapabilityReporter = (*Adapter)(nil)

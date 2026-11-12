package adapters

import (
	"crypto"
	"fmt"
	"strings"
	"time"

	"github.com/PeculiarVentures/piv-go/piv"
)

// SigningSupport describes the evidence for one exact signing operation. The
// zero value is unknown, never an assertion that an operation is available.
type SigningSupport string

const (
	SigningSupported   SigningSupport = "supported"
	SigningUnsupported SigningSupport = "unsupported"
	SigningUnknown     SigningSupport = "unknown"
)

// SigningReason is a machine-readable explanation for a signing decision.
type SigningReason string

const (
	SigningReasonProfileMatched           SigningReason = "profile-matched"
	SigningReasonProfileUnknown           SigningReason = "profile-support-unknown"
	SigningReasonProfileUnsupported       SigningReason = "profile-unsupported"
	SigningReasonNoReporter               SigningReason = "no-signing-reporter"
	SigningReasonNoProfile                SigningReason = "no-matching-profile"
	SigningReasonInvalidRequest           SigningReason = "invalid-request"
	SigningReasonInvalidProfile           SigningReason = "invalid-profile"
	SigningReasonSlotIneligible           SigningReason = "ineligible-slot"
	SigningReasonKeyAbsent                SigningReason = "key-absent"
	SigningReasonKeyUnknown               SigningReason = "key-evidence-unavailable"
	SigningReasonKeyStale                 SigningReason = "key-evidence-stale"
	SigningReasonLimits                   SigningReason = "profile-limit-exceeded"
	SigningReasonRandomness               SigningReason = "randomness-requirement"
	SigningReasonInvalidKey               SigningReason = "invalid-signing-key"
	SigningReasonDeviceProfileUnavailable SigningReason = "device-profile-unavailable"
	SigningReasonQualificationPending     SigningReason = "qualification-pending"
	SigningReasonProfileNotImplemented    SigningReason = "profile-not-implemented"
	SigningReasonMessageLimitUnqualified  SigningReason = "message-limit-unqualified"
)

// SigningEvidence records where a capability claim came from. Reference can be
// a vendor document, metadata command description, or qualification record.
// ObservedAt is informational; callers decide whether their snapshot is fresh.
type SigningEvidence struct {
	Source     string
	Reference  string
	ObservedAt time.Time
}

// SigningDevice is a caller-supplied device snapshot. Firmware and PIVVersion
// are distinct: an applet version must not be substituted for device firmware.
// Constructing or reporting this value performs no device discovery.
type SigningDevice struct {
	Model      string
	Firmware   string
	PIVVersion string
	Evidence   []SigningEvidence
}

// SigningKeyFamily identifies the mathematical family of a public key.
type SigningKeyFamily string

const (
	SigningKeyRSA   SigningKeyFamily = "rsa"
	SigningKeyEC    SigningKeyFamily = "ec"
	SigningKeyEdDSA SigningKeyFamily = "eddsa"
	SigningKeyMLDSA SigningKeyFamily = "mldsa"
)

// Exact named-curve OIDs used in signing key descriptors.
const (
	SigningCurveP256      = "1.2.840.10045.3.1.7"
	SigningCurveP384      = "1.3.132.0.34"
	SigningCurveP521      = "1.3.132.0.35"
	SigningCurveSecp256k1 = "1.3.132.0.10"
	SigningCurveEd25519   = "1.3.101.112"
	SigningCurveEd448     = "1.3.101.113"
)

// SigningKey identifies exact public-key parameters. Only the parameters for
// Family may be set. CurveOID is an exact OID, not a bit-size approximation.
// MLDSAParameterSet is 44, 65, or 87. This value does not prove key presence.
type SigningKey struct {
	Family            SigningKeyFamily
	CurveOID          string
	RSABits           int
	MLDSAParameterSet int
}

// SigningScheme distinguishes operations with different input semantics.
type SigningScheme string

const (
	SigningRSAPKCS1v15Digest  SigningScheme = "rsa-pkcs1v15-digest"
	SigningRSAPKCS1v15Payload SigningScheme = "rsa-pkcs1v15-payload"
	SigningRSAPSS             SigningScheme = "rsa-pss"
	SigningECDSA              SigningScheme = "ecdsa"
	SigningEdDSA              SigningScheme = "eddsa"
	SigningMLDSA              SigningScheme = "mldsa"
)

// SigningInput identifies the bytes supplied to the signing operation.
type SigningInput string

const (
	SigningInputMessage SigningInput = "message"
	SigningInputDigest  SigningInput = "digest"
	SigningInputPayload SigningInput = "payload"
)

// SigningMode distinguishes pure EdDSA/ML-DSA from their defined prehash modes.
// It is empty for RSA and ECDSA. Signing a digest as a pure message does not
// change the mode to prehash.
type SigningMode string

const (
	SigningModePure    SigningMode = "pure"
	SigningModePrehash SigningMode = "prehash"
)

// SigningContext preserves context-parameter presence independently of length.
// In particular, a present empty context is not implicitly a pure operation.
type SigningContext string

const (
	SigningContextAbsent  SigningContext = "absent"
	SigningContextPresent SigningContext = "present"
)

// SigningParameters is one related tuple, not independent algorithm lists.
// Hash zero means no declared hash; its meaning is never inferred from length.
// MGF1Hash is independent of Hash. Context must be explicitly absent or present.
type SigningParameters struct {
	Scheme   SigningScheme
	Input    SigningInput
	Hash     crypto.Hash
	MGF1Hash crypto.Hash
	Mode     SigningMode
	Context  SigningContext
}

// SigningLengthRange is an inclusive byte-length range. Zero Max means an
// exact upper bound of zero, not unlimited or an unspecified permissive limit.
type SigningLengthRange struct {
	Min int
	Max int
}

// SigningRandomness describes the guarantee an implementation makes. Unknown
// device randomness must not be advertised as deterministic or hedged signing.
// PSS profiles separate exact zero salt (deterministic) from positive salt
// lengths (host CSPRNG); one profile must not span both guarantees.
type SigningRandomness string

const (
	SigningRandomnessUnknown       SigningRandomness = "unknown"
	SigningRandomnessHostCSPRNG    SigningRandomness = "host-csprng"
	SigningRandomnessDeterministic SigningRandomness = "deterministic"
	SigningRandomnessHedged        SigningRandomness = "hedged"
)

// SigningTransport describes known limits of a qualified protocol path. Zero
// byte limits indicate unavailable evidence. Command limits apply to one APDU
// data field, or one fragment when chaining is supported; response limits cover
// the complete result including continuation. Feature statuses must be explicit.
type SigningTransport struct {
	CommandChaining SigningSupport
	ExtendedAPDU    SigningSupport
	MaxCommandData  int
	MaxResponseData int
}

// SigningResultEncoding identifies the bytes returned by a signing operation.
// These string values are stable; declaring an encoding does not establish
// that a device can execute the associated operation.
type SigningResultEncoding string

const (
	SigningResultRaw     SigningResultEncoding = "raw"
	SigningResultASN1DER SigningResultEncoding = "asn1-der"
)

// SigningProfile describes one executable or explicitly unavailable operation
// for a device/key tuple. Slots contain canonical PIV key references; aliases
// are resolved by the owning adapter before constructing a profile.
// ResultEncoding identifies the signature encoding. The report is capability
// evidence, not application authorization.
// A supported profile must include protocol/qualification evidence, usable
// transport limits, and an explicit randomness guarantee (which may be unknown
// for a device's RNG). RSA-PSS profiles use the library's host CSPRNG for
// positive salt lengths and are deterministic for exact zero salt.
type SigningProfile struct {
	ID              string
	Key             SigningKey
	Parameters      SigningParameters
	Slots           []piv.Slot
	InputLength     SigningLengthRange
	SaltLength      SigningLengthRange
	ContextLength   SigningLengthRange
	SignatureLength SigningLengthRange
	ResultEncoding  SigningResultEncoding
	Randomness      SigningRandomness
	Transport       SigningTransport
	Support         SigningSupport
	Reason          SigningReason
	Detail          string
	Evidence        []SigningEvidence
}

// SigningPurpose describes a slot's PIV role. Applications decide whether a
// key of that purpose may be published for their signing workflow.
type SigningPurpose string

const (
	SigningPurposeAuthentication SigningPurpose = "authentication"
	SigningPurposeSignature      SigningPurpose = "digital-signature"
	SigningPurposeCardAuth       SigningPurpose = "card-authentication"
	SigningPurposeKeyManagement  SigningPurpose = "key-management"
	SigningPurposeIneligible     SigningPurpose = "ineligible"
)

// SigningSlotPurpose returns the standard role of a canonical PIV reference.
// Management slot 9b and attestation keys are not ordinary signing keys.
func SigningSlotPurpose(slot piv.Slot) SigningPurpose {
	switch slot {
	case piv.SlotAuthentication:
		return SigningPurposeAuthentication
	case piv.SlotSignature:
		return SigningPurposeSignature
	case piv.SlotCardAuth:
		return SigningPurposeCardAuth
	case piv.SlotKeyManagement:
		return SigningPurposeKeyManagement
	default:
		if piv.IsRetiredSlot(slot) {
			return SigningPurposeKeyManagement
		}
		return SigningPurposeIneligible
	}
}

// SigningDecision reports support and its reason. Supported does not grant
// organizational permission, perform PIN verification, or authorize a key.
type SigningDecision struct {
	Support   SigningSupport
	Reason    SigningReason
	Detail    string
	ProfileID string
	Purpose   SigningPurpose
}

// SigningCapabilityReport contains a static or cached device capability
// snapshot. Fallback describes an operation not covered by Profiles. Its zero
// value is unknown, so an omitted profile never becomes implicit support.
type SigningCapabilityReport struct {
	AdapterName string
	Device      SigningDevice
	Profiles    []SigningProfile
	Fallback    SigningDecision
}

// SigningCapabilityReporter computes profiles from a supplied snapshot. It
// must not contact a card, verify PIN, sign, switch applets, or mutate a token.
// Any public evidence collection is a separate, explicit adapter operation.
type SigningCapabilityReporter interface {
	SigningCapabilities(device SigningDevice) SigningCapabilityReport
}

// ReportSigningCapabilities obtains a pure signing report without scanning
// slots or contacting a token. Existing CapabilityReport behavior is unchanged.
func ReportSigningCapabilities(adapter Adapter, device SigningDevice) SigningCapabilityReport {
	if reporter, ok := adapter.(SigningCapabilityReporter); ok {
		return reporter.SigningCapabilities(device)
	}
	name := "standard-piv"
	if adapter != nil {
		name = adapter.Name()
	}
	return SigningCapabilityReport{AdapterName: name, Device: device, Fallback: SigningDecision{
		Support: SigningUnknown, Reason: SigningReasonNoReporter,
		Detail: "the adapter has no device-specific signing report",
	}}
}

// SigningKeyEvidence separates current private-key observations from cached
// device capabilities and public certificates/templates. Current is set only
// when the caller accepts this observation's freshness; merely loading a cache
// must not set it. State and Source retain the passive inspection distinction.
// PINPolicy, TouchPolicy and Evidence are observations for the consumer's
// authorization and interaction policy; MatchSigningCapability does not grant
// authorization or act on them. This release requires a present key with
// PublicKeySourceMetadata for supported. Certificates and stored templates
// cannot satisfy that requirement, even when they contain a valid public key.
type SigningKeyEvidence struct {
	Slot        piv.Slot
	Key         SigningKey
	State       SlotState
	Current     bool
	Source      PublicKeySource
	PINPolicy   PINPolicy
	TouchPolicy TouchPolicy
	Evidence    []SigningEvidence
}

// SigningRequest describes a proposed operation without its private input.
// InputLength and ContextLength count bytes. SaltLength is an exact count:
// zero requests zero salt and is never Go's PSSSaltLengthAuto sentinel.
// Randomness is empty when no additional randomness guarantee is requested.
type SigningRequest struct {
	Parameters    SigningParameters
	InputLength   int
	SaltLength    int
	ContextLength int
	Randomness    SigningRandomness
}

// MatchSigningCapability checks a snapshot and a specific slot key entirely
// off-card. It performs no I/O, freshness lookup, signing probe, or PIN check.
// Consumers must intersect its result with their own publication/access policy.
func MatchSigningCapability(report SigningCapabilityReport, key SigningKeyEvidence, request SigningRequest) SigningDecision {
	purpose := SigningSlotPurpose(key.Slot)
	decision := func(s SigningSupport, reason SigningReason, detail string) SigningDecision {
		return SigningDecision{Support: s, Reason: reason, Detail: detail, Purpose: purpose}
	}
	if err := validateSigningRequest(request); err != nil {
		return decision(SigningUnsupported, SigningReasonInvalidRequest, err.Error())
	}
	if purpose == SigningPurposeIneligible {
		return decision(SigningUnsupported, SigningReasonSlotIneligible, "the reference is not an ordinary PIV signing key")
	}
	if !key.Current {
		return decision(SigningUnknown, SigningReasonKeyStale, "current private-key evidence is required")
	}
	if key.State == SlotStateAbsent {
		return decision(SigningUnsupported, SigningReasonKeyAbsent, "the private-key slot is empty")
	}
	if key.State != SlotStatePresent || key.Source != PublicKeySourceMetadata {
		return decision(SigningUnknown, SigningReasonKeyUnknown, "public storage alone does not establish the current private key")
	}
	if !validSigningKey(key.Key) {
		return decision(SigningUnknown, SigningReasonInvalidKey, "the signing key descriptor is incomplete or inconsistent")
	}
	var candidate *SigningDecision
	for _, profile := range report.Profiles {
		if profile.Key != key.Key || profile.Parameters != request.Parameters || !containsSigningSlot(profile.Slots, key.Slot) {
			continue
		}
		d := decision(normalizeSigningSupport(profile.Support), profile.Reason, profile.Detail)
		d.ProfileID = profile.ID
		if d.Reason == "" {
			if d.Support == SigningUnsupported {
				d.Reason = SigningReasonProfileUnsupported
			} else if d.Support == SigningUnknown {
				d.Reason = SigningReasonProfileUnknown
			}
		}
		if !validSigningProfile(profile) {
			d.Support, d.Reason, d.Detail = SigningUnknown, SigningReasonInvalidProfile, "the matching profile is incomplete or inconsistent"
		} else if d.Support != SigningSupported {
			// Unknown limits on an unknown profile are not evidence of an
			// unsupported operation. Preserve the provider's explicit status.
		} else if !profile.InputLength.contains(request.InputLength) || !profile.SaltLength.contains(request.SaltLength) || !profile.ContextLength.contains(request.ContextLength) {
			d.Support, d.Reason, d.Detail = SigningUnsupported, SigningReasonLimits, "the request exceeds this profile's exact length limits"
		} else if request.Randomness != "" && request.Randomness != profile.Randomness {
			d.Support, d.Reason, d.Detail = SigningUnsupported, SigningReasonRandomness, "the profile does not guarantee the requested randomness"
			if profile.Randomness == "" || profile.Randomness == SigningRandomnessUnknown {
				d.Support = SigningUnknown
			}
		} else if d.Support == SigningSupported {
			d.Reason = SigningReasonProfileMatched
			return d
		}
		// An unknown matching profile takes precedence over an unsupported
		// alternative; a later positive match may still satisfy the request.
		if candidate == nil || d.Support == SigningUnknown {
			candidate = &d
		}
	}
	if candidate != nil {
		return *candidate
	}
	fallback := report.Fallback
	fallback.Support = normalizeSigningSupport(fallback.Support)
	if fallback.Support == SigningSupported {
		fallback.Support = SigningUnknown // support must name a matching profile
	}
	if fallback.Reason == "" {
		fallback.Reason = SigningReasonNoProfile
	}
	fallback.Purpose = purpose
	fallback.ProfileID = ""
	return fallback
}

func normalizeSigningSupport(s SigningSupport) SigningSupport {
	if s == SigningSupported || s == SigningUnsupported {
		return s
	}
	return SigningUnknown
}

func validateSigningRequest(r SigningRequest) error {
	p := r.Parameters
	if r.InputLength < 0 || r.SaltLength < 0 || r.ContextLength < 0 {
		return fmt.Errorf("signing lengths must be nonnegative")
	}
	if p.Context != SigningContextAbsent && p.Context != SigningContextPresent {
		return fmt.Errorf("context presence must be explicit")
	}
	if p.Context == SigningContextAbsent && r.ContextLength != 0 {
		return fmt.Errorf("an absent context must have zero length")
	}
	if r.Randomness != "" && r.Randomness != SigningRandomnessHostCSPRNG && r.Randomness != SigningRandomnessDeterministic && r.Randomness != SigningRandomnessHedged {
		return fmt.Errorf("unknown randomness requirement")
	}
	switch p.Scheme {
	case SigningRSAPKCS1v15Digest, SigningRSAPSS:
		if p.Input != SigningInputDigest || signingHashSize(p.Hash) == 0 || r.InputLength != signingHashSize(p.Hash) {
			return fmt.Errorf("RSA digest input must match its declared hash")
		}
	case SigningRSAPKCS1v15Payload:
		if p.Input != SigningInputPayload || p.Hash != 0 {
			return fmt.Errorf("PKCS#1 payload is exact bytes without a declared hash")
		}
	case SigningECDSA:
		if p.Input != SigningInputDigest {
			return fmt.Errorf("ECDSA input must be a digest")
		}
		if p.Hash != 0 && (signingHashSize(p.Hash) == 0 || r.InputLength != signingHashSize(p.Hash)) {
			return fmt.Errorf("ECDSA digest input must match its declared hash")
		}
	case SigningEdDSA, SigningMLDSA:
		if p.Mode != SigningModePure && p.Mode != SigningModePrehash {
			return fmt.Errorf("EdDSA/ML-DSA mode must be explicit")
		}
		if p.Mode == SigningModePure && (p.Input != SigningInputMessage || p.Hash != 0) {
			return fmt.Errorf("pure signing requires message input without a declared hash")
		}
		if p.Mode == SigningModePrehash && (p.Input != SigningInputDigest || signingHashSize(p.Hash) == 0 || r.InputLength != signingHashSize(p.Hash)) {
			return fmt.Errorf("prehash input must match its declared hash")
		}
	default:
		return fmt.Errorf("unknown signing scheme")
	}
	if p.Scheme == SigningRSAPSS {
		if signingHashSize(p.MGF1Hash) == 0 {
			return fmt.Errorf("PSS requires an explicit MGF1 hash")
		}
	} else if p.MGF1Hash != 0 || r.SaltLength != 0 {
		return fmt.Errorf("MGF1 and salt apply only to PSS")
	}
	if p.Scheme != SigningEdDSA && p.Scheme != SigningMLDSA && (p.Mode != "" || p.Context != SigningContextAbsent) {
		return fmt.Errorf("mode and context apply only to EdDSA/ML-DSA")
	}
	return nil
}

// Hash.Size panics for an unknown identifier. Do not depend on Hash.Available:
// a digest's identity does not depend on which hash implementations a consumer
// happened to link into its binary. New hash identifiers require explicit work.
func signingHashSize(h crypto.Hash) int {
	if h < crypto.MD4 || h > crypto.BLAKE2b_512 {
		return 0
	}
	return h.Size()
}

func validSigningKey(k SigningKey) bool {
	switch k.Family {
	case SigningKeyRSA:
		// Leave room for rounded byte-length calculations, even when an
		// untrusted metadata snapshot contains a pathological integer.
		return k.RSABits > 0 && k.RSABits <= int(^uint(0)>>1)-7 && k.CurveOID == "" && k.MLDSAParameterSet == 0
	case SigningKeyEC, SigningKeyEdDSA:
		return k.CurveOID != "" && k.RSABits == 0 && k.MLDSAParameterSet == 0
	case SigningKeyMLDSA:
		return (k.MLDSAParameterSet == 44 || k.MLDSAParameterSet == 65 || k.MLDSAParameterSet == 87) && k.RSABits == 0 && k.CurveOID == ""
	default:
		return false
	}
}

func validSigningProfile(p SigningProfile) bool {
	if p.ID == "" || !validSigningKey(p.Key) || len(p.Slots) == 0 || !p.InputLength.valid() || !p.SaltLength.valid() || !p.ContextLength.valid() {
		return false
	}
	switch p.Parameters.Scheme {
	case SigningRSAPKCS1v15Digest, SigningRSAPKCS1v15Payload, SigningRSAPSS:
		if p.Key.Family != SigningKeyRSA {
			return false
		}
	case SigningECDSA:
		if p.Key.Family != SigningKeyEC {
			return false
		}
	case SigningEdDSA:
		if p.Key.Family != SigningKeyEdDSA {
			return false
		}
	case SigningMLDSA:
		if p.Key.Family != SigningKeyMLDSA {
			return false
		}
	default:
		return false
	}
	if p.Support != SigningSupported {
		return true
	}
	if !p.SignatureLength.valid() || p.SignatureLength.Min <= 0 || p.ResultEncoding == "" || !hasSigningEvidence(p.Evidence) {
		return false
	}
	switch p.Randomness {
	case SigningRandomnessUnknown, SigningRandomnessHostCSPRNG, SigningRandomnessDeterministic, SigningRandomnessHedged:
	default:
		return false
	}
	if err := validateSigningRequest(SigningRequest{Parameters: p.Parameters, InputLength: p.InputLength.Min, SaltLength: p.SaltLength.Min, ContextLength: p.ContextLength.Min}); err != nil {
		return false
	}
	// A named digest profile has an exact digest width; a permissive range
	// must not advertise lengths the declared hash cannot produce.
	if p.Parameters.Input == SigningInputDigest && p.Parameters.Hash != 0 && p.InputLength.Max != signingHashSize(p.Parameters.Hash) {
		return false
	}
	if p.Parameters.Scheme != SigningRSAPSS && p.SaltLength.Max != 0 || p.Parameters.Context == SigningContextAbsent && p.ContextLength.Max != 0 {
		return false
	}
	wireLength := p.InputLength.Max
	if p.Key.Family == SigningKeyRSA {
		if !validRSASigningProfile(p) {
			return false
		}
		wireLength = (p.Key.RSABits + 7) / 8
	} else if p.Key.Family == SigningKeyEC {
		// SignECDSA formats the digest to the field width before transport.
		switch p.Key.CurveOID {
		case SigningCurveP256, SigningCurveSecp256k1:
			wireLength = 32
		case SigningCurveP384:
			wireLength = 48
		case SigningCurveP521:
			wireLength = 66
		default:
			return false // the transport width is not known
		}
	}
	commandLength, ok := signingTemplateSize(wireLength, true)
	if !ok {
		return false
	}
	responseLength, ok := signingTemplateSize(p.SignatureLength.Max, false)
	return ok && usableSigningTransport(p.Transport, commandLength, responseLength)
}

func hasSigningEvidence(evidence []SigningEvidence) bool {
	for _, item := range evidence {
		if strings.TrimSpace(item.Source) != "" && strings.TrimSpace(item.Reference) != "" {
			return true
		}
	}
	return false
}

func validRSASigningProfile(p SigningProfile) bool {
	// The current scheme-aware signing API has these exact protocol widths.
	// Unknown or future sizes can still be described as unknown/unsupported.
	switch p.Key.RSABits {
	case 1024, 2048, 3072, 4096:
	default:
		return false
	}
	k := p.Key.RSABits / 8
	if p.SignatureLength.Min != k || p.SignatureLength.Max != k || p.ResultEncoding != SigningResultRaw {
		return false
	}
	switch p.Parameters.Scheme {
	case SigningRSAPKCS1v15Payload:
		return p.InputLength.Max <= k-11
	case SigningRSAPKCS1v15Digest, SigningRSAPSS:
		// These are the hashes implemented by SignRSA, with 19-byte SHA-2
		// DigestInfo prefixes for PKCS#1 v1.5.
		switch p.Parameters.Hash {
		case crypto.SHA256, crypto.SHA384, crypto.SHA512:
		default:
			return false
		}
		hashLength := signingHashSize(p.Parameters.Hash)
		if p.Parameters.Scheme == SigningRSAPKCS1v15Digest {
			return hashLength+19 <= k-11
		}
		emLength := (p.Key.RSABits - 1 + 7) / 8
		if p.Parameters.MGF1Hash != p.Parameters.Hash || p.SaltLength.Max > emLength-hashLength-2 {
			return false
		}
		if p.SaltLength.Max == 0 {
			return p.Randomness == SigningRandomnessDeterministic
		}
		return p.SaltLength.Min > 0 && p.Randomness == SigningRandomnessHostCSPRNG
	default:
		return false
	}
}

func usableSigningTransport(t SigningTransport, inputLength, resultLength int) bool {
	if t.MaxCommandData <= 0 || t.MaxResponseData < resultLength || t.MaxResponseData <= 0 {
		return false
	}
	for _, feature := range []SigningSupport{t.CommandChaining, t.ExtendedAPDU} {
		if feature != SigningSupported && feature != SigningUnsupported && feature != SigningUnknown {
			return false
		}
	}
	if t.CommandChaining == SigningSupported {
		return true
	}
	return t.MaxCommandData >= inputLength && (inputLength <= 255 || t.ExtendedAPDU == SigningSupported)
}

// GENERAL AUTHENTICATE wraps the challenge in 7C{82 empty,81 challenge};
// the response is 7C{82 signature}. Include BER length fields when checking
// actual transport capacity, without allocating from untrusted profile sizes.
func signingTemplateSize(payloadLength int, command bool) (int, bool) {
	innerLength, ok := signingTLVSize(payloadLength)
	if !ok {
		return 0, false
	}
	if command {
		if innerLength > int(^uint(0)>>1)-2 {
			return 0, false
		}
		innerLength += 2 // empty response placeholder
	}
	return signingTLVSize(innerLength)
}

func signingTLVSize(length int) (int, bool) {
	if length < 0 {
		return 0, false
	}
	headerLength := 2 // one-byte tag and short-form length
	if length >= 128 {
		for n := length; n != 0; n >>= 8 {
			headerLength++
		}
	}
	if length > int(^uint(0)>>1)-headerLength {
		return 0, false
	}
	return length + headerLength, true
}

func (r SigningLengthRange) valid() bool         { return r.Min >= 0 && r.Max >= r.Min }
func (r SigningLengthRange) contains(n int) bool { return n >= r.Min && n <= r.Max }

func containsSigningSlot(slots []piv.Slot, slot piv.Slot) bool {
	for _, candidate := range slots {
		if candidate == slot {
			return true
		}
	}
	return false
}

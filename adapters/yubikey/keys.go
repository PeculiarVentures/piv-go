package yubikey

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	adapterslots "github.com/PeculiarVentures/piv-go/adapters/slots"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// ErrKeyDeletionUnsupported reports that MOVE KEY is unavailable on this
// token. Callers can use errors.Is to detect it regardless of version text.
var ErrKeyDeletionUnsupported = errors.New("key deletion is not supported on this firmware, requires 5.7.0 or later")

// ErrP384Unsupported reports that OTP status identifies a YubiKey NEO,
// which cannot generate or import P-384 keys.
var ErrP384Unsupported = errors.New("P-384 is not supported on YubiKey NEO")

// YubiKey key management instructions and policy extension tags.
const (
	// InsImportKey imports a private key into a PIV slot (INS 0xFE).
	InsImportKey = 0xFE
	// TagPinPolicy carries the slot PIN policy in generate/import payloads.
	TagPinPolicy = 0xAA
	// TagTouchPolicy carries the slot touch policy in generate/import payloads.
	TagTouchPolicy = 0xAB
)

// GenerateKey generates a key in the slot with the given algorithm and
// YubiKey PIN/touch policies, then stores the generated public key in the
// slot's standard PIV object. Default policies (0x00) omit the AA/AB tags, in
// which case the device applies its own default policies instead of preserving
// the slot's previous policies.
func (a *Adapter) GenerateKey(session *adapters.Session, slot piv.Slot, algorithm byte, pinPolicy byte, touchPolicy byte) (crypto.PublicKey, error) {
	if err := requireSessionClient(session); err != nil {
		return nil, err
	}
	if err := a.preflightP384(session, algorithm); err != nil {
		return nil, fmt.Errorf("generate YubiKey key in slot %s: %w", slot, err)
	}
	session.Observe(adapters.LogLevelInfo, a, "generate-key", "starting YubiKey key generation for %s", slot)
	if err := session.AuthenticateManagementKey(a); err != nil {
		return nil, fmt.Errorf("authenticate management key: %w", err)
	}
	session.Observe(adapters.LogLevelDebug, a, "generate-key", "issuing GENERATE ASYMMETRIC KEY PAIR for %s", slot)
	publicKey, err := session.Client.GenerateKeyPairWithPolicies(slot, algorithm, pinPolicy, touchPolicy)
	if err != nil {
		return nil, fmt.Errorf("generate YubiKey key in slot %s: %w", slot, err)
	}
	session.Observe(adapters.LogLevelDebug, a, "generate-key", "storing generated public key for %s", slot)
	if err := session.Client.StoreGeneratedPublicKey(slot, algorithm, publicKey); err != nil {
		return nil, fmt.Errorf("store generated YubiKey public key for slot %s: %w", slot, err)
	}
	session.Observe(adapters.LogLevelInfo, a, "generate-key", "completed YubiKey key generation for %s", slot)
	return publicKey, nil
}

// ImportKey imports a private key into the slot with the given algorithm and
// YubiKey PIN/touch policies, then stores the imported public key in the
// slot's standard PIV object. IMPORT KEY (INS 0xFE) only replaces the private
// key, so without this step firmwares without GET METADATA would keep serving
// a stale public key (or none) for the slot. Default policies (0x00) omit the
// AA/AB tags and the device applies its own defaults.
func (a *Adapter) ImportKey(session *adapters.Session, slot piv.Slot, algorithm byte, privateKey crypto.PrivateKey, pinPolicy byte, touchPolicy byte) error {
	if err := requireSessionClient(session); err != nil {
		return err
	}
	if piv.IsMLDSAAlgorithm(algorithm) {
		return fmt.Errorf("import YubiKey key into slot %s: unsupported algorithm 0x%02X: not supported by this release", slot, algorithm)
	}
	if err := a.preflightP384(session, algorithm); err != nil {
		return fmt.Errorf("import YubiKey key into slot %s: %w", slot, err)
	}
	session.Observe(adapters.LogLevelInfo, a, "import-key", "starting YubiKey key import for %s", slot)
	if err := session.AuthenticateManagementKey(a); err != nil {
		return fmt.Errorf("authenticate management key: %w", err)
	}
	session.Observe(adapters.LogLevelDebug, a, "import-key", "issuing IMPORT KEY for %s", slot)
	if err := session.Client.ImportKey(slot, algorithm, privateKey, pinPolicy, touchPolicy); err != nil {
		return fmt.Errorf("import YubiKey key into slot %s: %w", slot, err)
	}
	publicKey, err := importedPublicKey(algorithm, privateKey)
	if err != nil {
		return fmt.Errorf("resolve imported YubiKey public key for slot %s: %w", slot, err)
	}
	session.Observe(adapters.LogLevelDebug, a, "import-key", "storing imported public key for %s", slot)
	if err := session.Client.StoreGeneratedPublicKey(slot, algorithm, publicKey); err != nil {
		return fmt.Errorf("store imported YubiKey public key for slot %s: %w", slot, err)
	}
	session.Observe(adapters.LogLevelInfo, a, "import-key", "completed YubiKey key import for %s", slot)
	return nil
}

func (a *Adapter) preflightP384(session *adapters.Session, algorithm byte) error {
	if algorithm != piv.AlgECCP384 {
		return nil
	}
	supported, version, err := a.p384Support(session)
	if errors.Is(err, ErrPIVRestore) {
		return err
	}
	if err != nil { // OTP status unavailable: let the card decide.
		return nil
	}
	if !supported {
		return fmt.Errorf("%w (OTP status %s)", ErrP384Unsupported, version)
	}
	return nil
}

// importedPublicKey derives the public half of an imported private key for
// storage in the slot's standard PIV object. The requested algorithm
// supplies context for opaque and raw inputs: Ed25519/X25519 resolve a
// 32-byte seed, while ML-KEM-512/768/1024 expand the 64-byte seed into the
// encapsulation key (512 via circl, 768/1024 with the standard library).
func importedPublicKey(algorithm byte, privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	case ed25519.PrivateKey:
		if len(key) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("unsupported Ed25519 private key length %d: not supported by this release", len(key))
		}
		public, ok := key.Public().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("unsupported Ed25519 public key type %T: not supported by this release", key.Public())
		}
		return &piv.OpaquePublicKey{Algorithm: piv.AlgEd25519, Raw: append([]byte(nil), public...)}, nil
	case *ecdh.PrivateKey:
		if key.Curve() != ecdh.X25519() {
			return nil, fmt.Errorf("unsupported ECDH curve for X25519 import: not supported by this release")
		}
		public := key.PublicKey().Bytes()
		return &piv.OpaquePublicKey{Algorithm: piv.AlgX25519, Raw: append([]byte(nil), public...)}, nil
	case *piv.OpaquePrivateKey:
		if key == nil {
			return nil, fmt.Errorf("unsupported nil opaque private key: not supported by this release")
		}
		return opaqueImportPublicKey(algorithm, key.Algorithm, key.Raw)
	case piv.OpaquePrivateKey:
		return opaqueImportPublicKey(algorithm, key.Algorithm, key.Raw)
	case []byte:
		return opaqueImportPublicKey(algorithm, algorithm, key)
	default:
		return nil, fmt.Errorf("unsupported private key type %T: not supported by this release", privateKey)
	}
}

func opaqueImportPublicKey(requestedAlgorithm byte, keyAlgorithm byte, raw []byte) (crypto.PublicKey, error) {
	if piv.IsMLKEMAlgorithm(requestedAlgorithm) {
		if keyAlgorithm != 0 && keyAlgorithm != requestedAlgorithm {
			return nil, fmt.Errorf("unsupported import: key algorithm 0x%02X does not match requested algorithm 0x%02X: not supported by this release", keyAlgorithm, requestedAlgorithm)
		}
		ek, err := piv.MLKEMEncapsulationKeyFromSeed(requestedAlgorithm, raw)
		if err != nil {
			return nil, fmt.Errorf("%v: not supported by this release", err)
		}
		return &piv.OpaquePublicKey{Algorithm: requestedAlgorithm, Raw: ek}, nil
	}
	// Resolve the effective Ed25519/X25519 algorithm: a zero key algorithm
	// defers to the requested algorithm (mirroring opaqueImportFields).
	effective := requestedAlgorithm
	if effective == 0 {
		effective = keyAlgorithm
	} else if keyAlgorithm != 0 && keyAlgorithm != effective {
		return nil, fmt.Errorf("unsupported import: key algorithm 0x%02X does not match requested algorithm 0x%02X: not supported by this release", keyAlgorithm, requestedAlgorithm)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("unsupported raw private key length %d: not supported by this release", len(raw))
	}
	// Derive the real public half from the 32-byte seed so the publicly
	// readable slot object never stores the seed itself.
	switch effective {
	case piv.AlgEd25519:
		priv := ed25519.NewKeyFromSeed(raw)
		public, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("unsupported Ed25519 public key type %T: not supported by this release", priv.Public())
		}
		return &piv.OpaquePublicKey{Algorithm: piv.AlgEd25519, Raw: append([]byte(nil), public...)}, nil
	case piv.AlgX25519:
		priv, err := ecdh.X25519().NewPrivateKey(raw)
		if err != nil {
			return nil, fmt.Errorf("unsupported X25519 seed: %v: not supported by this release", err)
		}
		return &piv.OpaquePublicKey{Algorithm: piv.AlgX25519, Raw: append([]byte(nil), priv.PublicKey().Bytes()...)}, nil
	default:
		return nil, fmt.Errorf("unsupported raw private key algorithm 0x%02X: not supported by this release", effective)
	}
}

// CalculateSecret performs X25519 ECDH key agreement with the slot key.
func (a *Adapter) CalculateSecret(session *adapters.Session, slot piv.Slot, peerPublicKey []byte) ([]byte, error) {
	if err := requireSessionClient(session); err != nil {
		return nil, err
	}
	session.Observe(adapters.LogLevelDebug, a, "calculate-secret", "issuing GENERAL AUTHENTICATE ECDH for %s", slot)
	secret, err := session.Client.CalculateSecret(slot, peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("calculate YubiKey ECDH secret for slot %s: %w", slot, err)
	}
	return secret, nil
}

// Decapsulate performs ML-KEM decapsulation with the slot key and a
// variant-sized ciphertext, passing the call through to the PIV client.
// Encapsulation stays host-side; the card only decapsulates.
func (a *Adapter) Decapsulate(session *adapters.Session, slot piv.Slot, algorithm byte, ciphertext []byte) ([]byte, error) {
	if err := requireSessionClient(session); err != nil {
		return nil, err
	}
	session.Observe(adapters.LogLevelDebug, a, "decapsulate", "issuing GENERAL AUTHENTICATE decapsulation for %s", slot)
	secret, err := session.Client.Decapsulate(algorithm, slot, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decapsulate YubiKey KEM secret for slot %s: %w", slot, err)
	}
	return secret, nil
}

// ReadPublicKey reads the slot public key, preferring YubiKey slot metadata.
// Firmwares without GET METADATA (for example YubiKey NEO) share the slot
// object between the certificate and the public key template: importing a
// certificate replaces the template, so when the standard public key object
// carries no 7F49 template but a parseable certificate is present, the key
// is served from the certificate. Only unsupported metadata permits the
// compatibility fallback after a metadata error. Use DescribeSlot to obtain
// PublicKeySource and a separate, authoritative or unknown private-key state.
func (a *Adapter) ReadPublicKey(session *adapters.Session, slot piv.Slot) (crypto.PublicKey, error) {
	if err := requireSessionClient(session); err != nil {
		return nil, err
	}
	session.Observe(adapters.LogLevelDebug, a, "read-public-key", "reading YubiKey slot metadata for %s", slot)
	metadata, err := readSlotMetadata(session.Client, slot)
	if err == nil && metadata.PublicKey != nil {
		session.Observe(adapters.LogLevelDebug, a, "read-public-key", "using public key from YubiKey slot metadata for %s", slot)
		return metadata.PublicKey, nil
	}
	if err != nil && !isMetadataUnsupported(err) {
		return nil, fmt.Errorf("yubikey: read slot metadata: %w", err)
	}
	session.Observe(adapters.LogLevelDebug, a, "read-public-key", "falling back to standard PIV public key object for %s", slot)
	tag, err := piv.ObjectIDForSlot(slot)
	if err != nil {
		return nil, err
	}
	data, err := session.Client.GetData(tag)
	if err != nil {
		return nil, err
	}
	description := adapterslots.DescribeDataObject(data, nil)
	if description.KeyError != nil {
		return nil, description.KeyError
	}
	if description.PublicKey != nil {
		if description.PublicKeySource == adapters.PublicKeySourceCertificate {
			session.Observe(adapters.LogLevelDebug, a, "read-public-key", "using public key from slot certificate for %s", slot)
		}
		return description.PublicKey, nil
	}
	if description.CertError != nil {
		return nil, description.CertError
	}
	// Retain the established missing-template error for an empty object.
	return piv.ParsePublicKeyObject(data)
}

// DeleteKey removes a private key from a YubiKey slot.
func (a *Adapter) DeleteKey(session *adapters.Session, slot piv.Slot) error {
	if err := requireSessionClient(session); err != nil {
		return err
	}
	session.Observe(adapters.LogLevelInfo, a, "delete-key", "starting YubiKey key deletion for %s", slot)
	// NEO's PIV GET VERSION may report the PIV applet's 1.x version,
	// while OTP status reports the older device generation more reliably.
	// Reject known-old tokens before management authentication or MOVE KEY.
	if version, err := a.OTPStatusVersion(session); errors.Is(err, ErrPIVRestore) {
		return fmt.Errorf("delete YubiKey key from slot %s: %w", slot, err)
	} else if err == nil {
		if supported, err := supportsDeleteKeyVersion(version); err == nil {
			if !supported {
				return fmt.Errorf("delete YubiKey key from slot %s (OTP status %s): %w", slot, version, ErrKeyDeletionUnsupported)
			}
		} else if !errors.Is(err, ErrCapabilityUnknown) {
			// Unparseable version text: capability is likewise unknown, so
			// probe the MOVE KEY command itself just like preview firmware.
		}
		// Preview firmware (ErrCapabilityUnknown) proceeds to probe MOVE KEY,
		// which remains authoritative; SupportsP384 follows the same
		// probe-on-preview pattern by returning true for 0.x.
	}
	if err := session.AuthenticateManagementKey(a); err != nil {
		return fmt.Errorf("authenticate management key: %w", err)
	}

	session.Observe(adapters.LogLevelDebug, a, "delete-key", "issuing YubiKey MOVE KEY delete command for %s", slot)
	cmd := &iso7816.Command{
		Cla: 0x00,
		Ins: yubiKeyInsMoveKey,
		P1:  0xFF,
		P2:  byte(slot),
		Le:  -1,
	}
	resp, err := session.Client.Execute(cmd)
	if err != nil {
		return fmt.Errorf("delete YubiKey key from slot %s: %w", slot, err)
	}
	if err := resp.Err(); err != nil {
		if iso7816.IsStatus(err, iso7816.SwInsNotSupported) {
			session.Observe(adapters.LogLevelInfo, a, "delete-key", "token rejected MOVE KEY")
			if version, versionErr := readVersion(session.Client); versionErr == nil {
				return fmt.Errorf("delete YubiKey key from slot %s (PIV applet version %s): %w", slot, version, ErrKeyDeletionUnsupported)
			}
			return fmt.Errorf("delete YubiKey key from slot %s: %w", slot, ErrKeyDeletionUnsupported)
		}
		return fmt.Errorf("delete YubiKey key from slot %s: %w", slot, err)
	}
	// MOVE KEY removes only the private key. The slot certificate object
	// still holds the stored public key template (written by GenerateKey and
	// ImportKey), so without clearing it inspection keeps reporting the key
	// and key public keeps serving stale bytes. Overwrite the object with an
	// empty 0x53 payload; the write needs no parsing, so unparseable
	// leftovers clear the same way. The session is already management
	// authenticated from above.
	if _, slotErr := piv.ObjectIDForSlot(slot); slotErr == nil {
		session.Observe(adapters.LogLevelDebug, a, "delete-key", "clearing slot object for %s", slot)
		if err := session.Client.DeleteCertificate(slot); err != nil {
			return fmt.Errorf("delete YubiKey key from slot %s: clear slot object: %w", slot, err)
		}
	}
	session.Observe(adapters.LogLevelInfo, a, "delete-key", "completed YubiKey key deletion for %s", slot)
	return nil
}

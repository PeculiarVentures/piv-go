package yubikey

import (
	"crypto"
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

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
// slot's standard PIV object. Default policies (0x00) omit the AA/AB tags.
func (a *Adapter) GenerateKey(session *adapters.Session, slot piv.Slot, algorithm byte, pinPolicy byte, touchPolicy byte) (crypto.PublicKey, error) {
	if err := requireSessionClient(session); err != nil {
		return nil, err
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
// YubiKey PIN/touch policies.
func (a *Adapter) ImportKey(session *adapters.Session, slot piv.Slot, algorithm byte, privateKey crypto.PrivateKey, pinPolicy byte, touchPolicy byte) error {
	if err := requireSessionClient(session); err != nil {
		return err
	}
	session.Observe(adapters.LogLevelInfo, a, "import-key", "starting YubiKey key import for %s", slot)
	if err := session.AuthenticateManagementKey(a); err != nil {
		return fmt.Errorf("authenticate management key: %w", err)
	}
	session.Observe(adapters.LogLevelDebug, a, "import-key", "issuing IMPORT KEY for %s", slot)
	if err := session.Client.ImportKey(slot, algorithm, privateKey, pinPolicy, touchPolicy); err != nil {
		return fmt.Errorf("import YubiKey key into slot %s: %w", slot, err)
	}
	session.Observe(adapters.LogLevelInfo, a, "import-key", "completed YubiKey key import for %s", slot)
	return nil
}

// ReadPublicKey reads the slot public key, preferring YubiKey slot metadata.
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
	session.Observe(adapters.LogLevelDebug, a, "read-public-key", "falling back to standard PIV public key object for %s", slot)
	return session.Client.ReadPublicKey(slot)
}

// DeleteKey removes a private key from a YubiKey slot.
func (a *Adapter) DeleteKey(session *adapters.Session, slot piv.Slot) error {
	session.Observe(adapters.LogLevelInfo, a, "delete-key", "starting YubiKey key deletion for %s", slot)
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
			session.Observe(adapters.LogLevelInfo, a, "delete-key", "firmware rejected key deletion command, checking device version")
			if version, versionErr := readVersion(session.Client); versionErr == nil {
				return fmt.Errorf("delete YubiKey key from slot %s: firmware %s does not support key deletion, requires 5.7.0 or later", slot, version)
			}
			return fmt.Errorf("delete YubiKey key from slot %s: firmware does not support key deletion, requires 5.7.0 or later", slot)
		}
		return fmt.Errorf("delete YubiKey key from slot %s: %w", slot, err)
	}
	session.Observe(adapters.LogLevelInfo, a, "delete-key", "completed YubiKey key deletion for %s", slot)
	return nil
}

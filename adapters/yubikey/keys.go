package yubikey

import (
	"crypto"
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

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

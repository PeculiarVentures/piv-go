package yubikey

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// PINStatus handles PUK status for YubiKey, where standard VERIFY status for PUK
// may return 6A88 (referenced data not found). In that case we report status as
// available but retries unknown.
func (a *Adapter) PINStatus(session *adapters.Session, pinType piv.PINType) (adapters.PINStatus, error) {
	if err := requireSessionClient(session); err != nil {
		return adapters.PINStatus{}, err
	}

	session.Observe(adapters.LogLevelDebug, a, "read-pin-status", "reading YubiKey PIN metadata for %v", pinType)
	if metadata, err := readPINMetadata(session.Client, pinType); err == nil {
		session.Observe(adapters.LogLevelDebug, a, "read-pin-status", "using YubiKey PIN metadata for %v", pinType)
		return adapters.PINStatus{
			Type:        pinType,
			RetriesLeft: metadata.AttemptsRemaining,
			Blocked:     metadata.AttemptsRemaining == 0,
		}, nil
	}

	session.Observe(adapters.LogLevelDebug, a, "read-pin-status", "falling back to standard PIV PIN status for %v", pinType)
	status, err := session.Client.PINStatus(pinType)
	if err != nil && pinType == piv.PINTypePUK {
		if iso7816.IsStatus(err, iso7816.SwReferencedDataNotFound) {
			session.Observe(adapters.LogLevelInfo, a, "read-pin-status", "PUK metadata unavailable, reporting unknown retry count")
			return adapters.PINStatus{Type: pinType, RetriesLeft: -1}, nil
		}
	}
	return status, err
}

// ChangePIN changes the PIN using the standard PIV command.
func (a *Adapter) ChangePIN(session *adapters.Session, oldPIN string, newPIN string) error {
	if err := requireSessionClient(session); err != nil {
		return err
	}
	return session.Client.ChangePIN(oldPIN, newPIN)
}

// ChangePUK changes the PUK using the standard PIV command.
func (a *Adapter) ChangePUK(session *adapters.Session, oldPUK string, newPUK string) error {
	if err := requireSessionClient(session); err != nil {
		return err
	}
	return session.Client.ChangePUK(oldPUK, newPUK)
}

func readPINMetadata(client *piv.Client, pinType piv.PINType) (yubiKeyPINMetadata, error) {
	values, err := readMetadata(client, byte(pinType))
	if err != nil {
		return yubiKeyPINMetadata{}, err
	}
	retries, ok := values[yubiKeyMetadataTagRetries]
	if !ok || len(retries) < 2 {
		return yubiKeyPINMetadata{}, fmt.Errorf("yubikey: retry metadata is missing")
	}
	return yubiKeyPINMetadata{
		DefaultValue:      len(values[yubiKeyMetadataTagIsDefault]) > 0 && values[yubiKeyMetadataTagIsDefault][0] != 0x00,
		TotalAttempts:     int(retries[0]),
		AttemptsRemaining: int(retries[1]),
	}, nil
}

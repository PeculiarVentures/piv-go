package yubikey

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// ErrBioResetUnsupported indicates that a Bio MPE needs a device-wide reset,
// rather than the PIN/PUK-blocking PIV reset procedure.
var ErrBioResetUnsupported = errors.New("yubikey: PIV reset is not supported on YubiKey Bio MPE; use device-wide reset")

// DescribeReset reports the YubiKey reset policy requirements.
func (a *Adapter) DescribeReset(session *adapters.Session) (adapters.ResetRequirements, error) {
	if session != nil {
		session.Observe(adapters.LogLevelDebug, a, "describe-reset", "YubiKey reset does not require additional fields")
	}
	return adapters.ResetRequirements{}, nil
}

// ResetToken resets the YubiKey PIV applet to factory defaults.
func (a *Adapter) ResetToken(session *adapters.Session, params adapters.ResetTokenParams) error {
	if err := requireSessionClient(session); err != nil {
		return err
	}
	// Check support and read both credential counters before any blocking APDU.
	// In particular, never block PIN on a Bio MPE that cannot finish PIV reset.
	if err := checkPIVResetSupport(session.Client); err != nil {
		return err
	}
	pinRetries, err := resetPINRetries(session)
	if err != nil {
		return err
	}
	pukRetries, err := resetPUKRetries(session)
	if err != nil {
		return err
	}
	session.Observe(adapters.LogLevelInfo, a, "reset-token", "starting YubiKey token reset")
	if err := blockResetCredential(pinRetries, "PIN", func() (int, error) { return submitInvalidPIN(session.Client) }); err != nil {
		return err
	}
	if err := blockResetCredential(pukRetries, "PUK", func() (int, error) { return submitInvalidPUKReset(session.Client) }); err != nil {
		return err
	}
	session.Observe(adapters.LogLevelDebug, a, "reset-token", "issuing standard PIV reset")
	if err := session.Client.Reset(); err != nil {
		return err
	}
	session.ManagementAlgorithm = 0
	session.ManagementKey = append([]byte(nil), defaultManagementKey...)
	session.Observe(adapters.LogLevelInfo, a, "reset-token", "completed YubiKey token reset")
	return nil
}

func checkPIVResetSupport(client *piv.Client) error {
	// GET METADATA for OCC (96) is read-only and identifies Bio-capable PIV.
	// Reject even an unconfigured Bio: Bio MPE requires device-wide reset.
	// See https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/reset-piv.html.
	_, err := readMetadata(client, 0x96)
	if err == nil {
		return ErrBioResetUnsupported
	}
	if isMetadataUnsupported(err) || iso7816.IsStatus(err, iso7816.SwReferencedDataNotFound) {
		return nil
	}
	return fmt.Errorf("yubikey: check PIV reset support: %w", err)
}

func resetPINRetries(session *adapters.Session) (int, error) {
	status, err := readPINMetadata(session.Client, piv.PINTypeCard)
	if err == nil {
		return status.AttemptsRemaining, nil
	}
	if !isMetadataUnsupported(err) {
		return 0, fmt.Errorf("yubikey: read PIN reset metadata: %w", err)
	}
	statusFallback, err := session.Client.PINStatus(piv.PINTypeCard)
	if err != nil {
		return 0, fmt.Errorf("yubikey: read PIN retry status: %w", err)
	}
	if statusFallback.Verified || statusFallback.RetriesLeft < 0 {
		// On NEO a verified PIN answers 9000 without a retry count. Make one
		// invalid attempt to obtain a count; this does not mean PIN is blocked.
		return 1, nil
	}
	return statusFallback.RetriesLeft, nil
}

func resetPUKRetries(session *adapters.Session) (int, error) {
	status, err := readPINMetadata(session.Client, piv.PINTypePUK)
	if err == nil {
		return status.AttemptsRemaining, nil
	}
	if !isMetadataUnsupported(err) {
		return 0, fmt.Errorf("yubikey: read PUK reset metadata: %w", err)
	}
	// NEO cannot query PUK status. The first invalid attempt supplies its count.
	return 1, nil
}

func blockResetCredential(retries int, credential string, submit func() (int, error)) error {
	// Retry limits are one byte (at most 255). Bound an unknown-counter probe
	// plus those attempts, so a non-progressing card cannot cause an endless loop.
	for attempts := 0; retries > 0; attempts++ {
		if attempts >= 256 {
			return fmt.Errorf("yubikey: %s did not become blocked after 256 attempts", credential)
		}
		remaining, err := submit()
		if err != nil {
			return err
		}
		retries = remaining
	}
	return nil
}

func submitInvalidPIN(client *piv.Client) (int, error) {
	cmd := &iso7816.Command{Cla: 0, Ins: 0x20, P1: 0, P2: byte(piv.PINTypeCard), Data: bytes.Repeat([]byte{0xff}, 8), Le: -1}
	resp, err := client.Execute(cmd)
	if err != nil {
		return 0, fmt.Errorf("yubikey: block PIN step: %w", err)
	}
	return retriesFromResponse(resp, "block PIN step")
}

func submitInvalidPUKReset(client *piv.Client) (int, error) {
	cmd := &iso7816.Command{Cla: 0, Ins: 0x2c, P1: 0, P2: byte(piv.PINTypeCard), Data: bytes.Repeat([]byte{0xff}, 16), Le: -1}
	resp, err := client.Execute(cmd)
	if err != nil {
		return 0, fmt.Errorf("yubikey: block PUK step: %w", err)
	}
	return retriesFromResponse(resp, "block PUK step")
}

func retriesFromResponse(resp *iso7816.Response, operation string) (int, error) {
	sw := resp.StatusWord()
	if retries, ok := iso7816.IsPINRetryStatus(sw); ok {
		return retries, nil
	}
	if sw == iso7816.SwAuthBlocked {
		return 0, nil
	}
	if err := resp.Err(); err != nil {
		return 0, fmt.Errorf("yubikey: %s: %w", operation, err)
	}
	return 0, fmt.Errorf("yubikey: %s unexpectedly succeeded; credential blocking is unconfirmed", operation)
}

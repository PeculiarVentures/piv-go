package yubikey

import (
	"errors"
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

var otpAID = []byte{0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01}

// ErrCapabilityUnknown reports that OTP status comes from preview firmware
// (major version 0, for example raw status 0.0.1) and cannot establish
// whether the token supports an operation. Callers must not treat
// (false, ErrCapabilityUnknown) as definitely unsupported; they should
// probe the card command itself, which remains authoritative.
var ErrCapabilityUnknown = errors.New("yubikey: capability unknown for preview firmware")

// ErrOTPApplet marks an OTP applet operation that could not complete. The
// wrapped cause remains available through errors.As and errors.Is.
var ErrOTPApplet = errors.New("yubikey: OTP applet operation failed")

// ErrPIVRestore marks failure to reselect PIV after an OTP operation. The
// caller must discard its session because the selected applet is uncertain.
var ErrPIVRestore = errors.New("yubikey: failed to restore PIV applet")

// OTPAppletError identifies the failed OTP applet step and its cause.
type OTPAppletError struct {
	Step string
	Err  error
}

func (e *OTPAppletError) Error() string {
	return fmt.Sprintf("yubikey: %s: %v", e.Step, e.Err)
}

func (e *OTPAppletError) Unwrap() error { return e.Err }

func (e *OTPAppletError) Is(target error) bool { return target == ErrOTPApplet }

// OTPStatusVersion returns the version bytes reported by the OTP applet's
// STATUS command. NEO can report a different patch version from the device
// firmware, so callers should treat this as a capability hint, not as an
// authoritative inventory value. The PIV applet is reselected before return.
func (a *Adapter) OTPStatusVersion(session *adapters.Session) (string, error) {
	if err := requireSessionClient(session); err != nil {
		return "", err
	}
	data, err := executeOTP(session.Client, "read status", &iso7816.Command{
		Cla: 0x00, Ins: 0x03, P1: 0x00, P2: 0x00, Le: -1,
	})
	if err != nil {
		return "", err
	}
	if len(data) != 6 || data[0]|data[1]|data[2] == 0 {
		return "", &OTPAppletError{Step: "parse status", Err: fmt.Errorf("invalid version data (%d bytes)", len(data))}
	}
	return fmt.Sprintf("%d.%d.%d", data[0], data[1], data[2]), nil
}

// SupportsDeleteKey reports whether OTP status indicates MOVE KEY support.
// The command itself remains authoritative when OTP status is unavailable.
// The return contract is explicit: (true, nil) means definitely supported,
// (false, nil) means definitely unsupported, and (false, ErrCapabilityUnknown)
// means support is unknown (preview firmware such as raw status 0.0.1) so the
// caller should probe the MOVE KEY command itself.
func (a *Adapter) SupportsDeleteKey(session *adapters.Session) (bool, error) {
	version, err := a.OTPStatusVersion(session)
	if err != nil {
		return false, err
	}
	return supportsDeleteKeyVersion(version)
}

func supportsDeleteKeyVersion(version string) (bool, error) {
	parts, err := parseFirmwareVersion(version)
	if err != nil {
		return false, err
	}
	if parts[0] == 0 {
		return false, fmt.Errorf("yubikey: preview OTP status %s cannot establish MOVE KEY support: %w", version, ErrCapabilityUnknown)
	}
	return parts[0] > 5 || parts[0] == 5 && (parts[1] > 7 || parts[1] == 7), nil
}

// SupportsP384 reports whether OTP status identifies a generation with P-384
// support. NEO (3.x) does not support P-384. Preview versions (0.x) are left
// available for a command-level probe; other versions 4.x and later support it.
// An unavailable OTP status returns an error, so callers can fall back to the
// card command instead of inferring lack of support.
func (a *Adapter) SupportsP384(session *adapters.Session) (bool, error) {
	supported, _, err := a.p384Support(session)
	return supported, err
}

func (a *Adapter) p384Support(session *adapters.Session) (bool, string, error) {
	version, err := a.OTPStatusVersion(session)
	if err != nil {
		return false, "", err
	}
	parts, err := parseFirmwareVersion(version)
	if err != nil {
		return false, version, err
	}
	if parts[0] == 3 {
		return false, version, nil
	}
	if parts[0] == 0 || parts[0] >= 4 {
		return true, version, nil
	}
	return false, version, fmt.Errorf("yubikey: OTP status %s does not establish P-384 support", version)
}

// executeOTP selects OTP, sends one command and always attempts to restore
// PIV, even when OTP selection or the command fails. No data is returned if
// restoration fails, because the calling session's applet state is uncertain.
func executeOTP(client *piv.Client, step string, command *iso7816.Command) (data []byte, err error) {
	defer func() {
		if restoreErr := client.Select(); restoreErr != nil {
			data = nil
			err = errors.Join(err, ErrPIVRestore, &OTPAppletError{Step: "restore PIV applet", Err: restoreErr})
		}
	}()
	selectResponse, err := client.Execute(&iso7816.Command{
		Cla: 0x00, Ins: 0xA4, P1: 0x04, P2: 0x00, Data: otpAID, Le: 256,
	})
	if err != nil {
		return nil, &OTPAppletError{Step: "select OTP applet", Err: err}
	}
	if selectResponse == nil {
		return nil, &OTPAppletError{Step: "select OTP applet", Err: errors.New("missing response")}
	}
	if err := selectResponse.Err(); err != nil {
		return nil, &OTPAppletError{Step: "select OTP applet", Err: err}
	}
	response, err := client.Execute(command)
	if err != nil {
		return nil, &OTPAppletError{Step: step, Err: err}
	}
	if response == nil {
		return nil, &OTPAppletError{Step: step, Err: errors.New("missing response")}
	}
	if err := response.Err(); err != nil {
		return nil, &OTPAppletError{Step: step, Err: err}
	}
	return append([]byte(nil), response.Data...), nil
}

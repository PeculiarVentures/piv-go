package admin

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/piv"
)

// ReadPINStatus resolves token-specific PIN status handling with a standard fallback.

func ReadPINStatus(runtime *adapters.Runtime, pinType piv.PINType) (adapters.PINStatus, error) {
	if err := requireRuntime(runtime); err != nil {
		return adapters.PINStatus{}, err
	}
	return readPINStatus(runtime.Session, runtime.Adapter, pinType)
}

func readPINStatus(session *adapters.Session, adapter adapters.Adapter, pinType piv.PINType) (adapters.PINStatus, error) {
	if err := requireSessionClient(session); err != nil {
		return adapters.PINStatus{}, err
	}
	if pinAdapter, ok := adapter.(adapters.PINAdapter); ok {
		session.Observe(adapters.LogLevelDebug, adapter, "read-pin-status", "using adapter-specific PIN status handling for %v", pinType)
		return pinAdapter.PINStatus(session, pinType)
	}
	session.Observe(adapters.LogLevelDebug, adapter, "read-pin-status", "falling back to standard PIV PIN status handling for %v", pinType)
	return session.Client.PINStatus(pinType)
}

// ReadManagementKeyStatus resolves token-specific management key status handling.
func ReadManagementKeyStatus(runtime *adapters.Runtime) (adapters.ManagementKeyStatus, error) {
	if err := requireRuntime(runtime); err != nil {
		return adapters.ManagementKeyStatus{}, err
	}
	return readManagementKeyStatus(runtime.Session, runtime.Adapter)
}

func readManagementKeyStatus(session *adapters.Session, adapter adapters.Adapter) (adapters.ManagementKeyStatus, error) {
	if err := requireSessionClient(session); err != nil {
		return adapters.ManagementKeyStatus{}, err
	}
	if statusAdapter, ok := adapter.(adapters.ManagementKeyStatusAdapter); ok {
		session.Observe(adapters.LogLevelDebug, adapter, "read-management-key-status", "using adapter-specific MGM status handling")
		return statusAdapter.ManagementKeyStatus(session)
	}
	return adapters.ManagementKeyStatus{}, fmt.Errorf("adapters: management key status is not supported")
}

// ChangePIN resolves token-specific PIN rotation with a standard fallback.

func ChangePIN(runtime *adapters.Runtime, oldPIN string, newPIN string) error {
	if err := requireRuntime(runtime); err != nil {
		return err
	}
	return changePIN(runtime.Session, runtime.Adapter, oldPIN, newPIN)
}

func changePIN(session *adapters.Session, adapter adapters.Adapter, oldPIN string, newPIN string) error {
	if err := requireSessionClient(session); err != nil {
		return err
	}
	if credentialAdapter, ok := adapter.(adapters.CredentialAdapter); ok {
		session.Observe(adapters.LogLevelInfo, adapter, "change-pin", "using adapter-specific PIN rotation")
		return credentialAdapter.ChangePIN(session, oldPIN, newPIN)
	}
	session.Observe(adapters.LogLevelInfo, adapter, "change-pin", "falling back to standard PIV PIN rotation")
	return session.Client.ChangePIN(oldPIN, newPIN)
}

// ChangePUK resolves token-specific PUK rotation with a standard fallback.

func ChangePUK(runtime *adapters.Runtime, oldPUK string, newPUK string) error {
	if err := requireRuntime(runtime); err != nil {
		return err
	}
	return changePUK(runtime.Session, runtime.Adapter, oldPUK, newPUK)
}

func changePUK(session *adapters.Session, adapter adapters.Adapter, oldPUK string, newPUK string) error {
	if err := requireSessionClient(session); err != nil {
		return err
	}
	if credentialAdapter, ok := adapter.(adapters.CredentialAdapter); ok {
		session.Observe(adapters.LogLevelInfo, adapter, "change-puk", "using adapter-specific PUK rotation")
		return credentialAdapter.ChangePUK(session, oldPUK, newPUK)
	}
	session.Observe(adapters.LogLevelInfo, adapter, "change-puk", "falling back to standard PIV PUK rotation")
	return session.Client.ChangePUK(oldPUK, newPUK)
}

// ChangeManagementKey requires adapter support because the underlying storage is token-specific.

func ChangeManagementKey(runtime *adapters.Runtime, newAlgorithm byte, newKey []byte) error {
	if err := requireRuntime(runtime); err != nil {
		return err
	}
	return changeManagementKey(runtime.Session, runtime.Adapter, newAlgorithm, newKey)
}

func changeManagementKey(session *adapters.Session, adapter adapters.Adapter, newAlgorithm byte, newKey []byte) error {
	if err := requireSessionClient(session); err != nil {
		return err
	}
	credentialAdapter, ok := adapter.(adapters.CredentialAdapter)
	if !ok {
		session.Observe(adapters.LogLevelInfo, adapter, "change-management-key", "adapter does not implement management key rotation")
		return fmt.Errorf("adapters: management key rotation is not supported")
	}
	session.Observe(adapters.LogLevelInfo, adapter, "change-management-key", "delegating management key rotation to adapter")
	return credentialAdapter.ChangeManagementKey(session, newAlgorithm, newKey)
}

// UnblockPIN resolves token-specific PIN recovery with a standard fallback.

func UnblockPIN(runtime *adapters.Runtime, puk string, newPIN string) error {
	if err := requireRuntime(runtime); err != nil {
		return err
	}
	return unblockPIN(runtime.Session, runtime.Adapter, puk, newPIN)
}

func unblockPIN(session *adapters.Session, adapter adapters.Adapter, puk string, newPIN string) error {
	if err := requireSessionClient(session); err != nil {
		return err
	}
	if recoveryAdapter, ok := adapter.(adapters.PINRecoveryAdapter); ok {
		session.Observe(adapters.LogLevelInfo, adapter, "unblock-pin", "using adapter-specific PIN unblock flow")
		return recoveryAdapter.UnblockPIN(session, puk, newPIN)
	}
	session.Observe(adapters.LogLevelInfo, adapter, "unblock-pin", "falling back to standard PIV PIN unblock flow")
	return session.Client.UnblockPIN(puk, newPIN)
}

// ResetSlot requires adapter support because standard PIV defines only token-level reset.

func ResetSlot(runtime *adapters.Runtime, slot piv.Slot) error {
	if err := requireRuntime(runtime); err != nil {
		return err
	}
	return resetSlot(runtime.Session, runtime.Adapter, slot)
}

func resetSlot(session *adapters.Session, adapter adapters.Adapter, slot piv.Slot) error {
	if err := requireSessionClient(session); err != nil {
		return err
	}
	resetAdapter, ok := adapter.(adapters.ResetAdapter)
	if !ok {
		session.Observe(adapters.LogLevelInfo, adapter, "reset-slot", "adapter does not implement slot reset")
		return fmt.Errorf("adapters: slot reset is not supported")
	}
	session.Observe(adapters.LogLevelInfo, adapter, "reset-slot", "delegating slot reset to adapter for %s", slot)
	return resetAdapter.ResetSlot(session, slot)
}

// DescribeReset returns reset policy requirements for an already resolved runtime.
func DescribeReset(runtime *adapters.Runtime) (adapters.ResetRequirements, error) {
	if err := requireRuntime(runtime); err != nil {
		return adapters.ResetRequirements{}, err
	}
	if runtime.Adapter == nil {
		runtime.Session.Observe(adapters.LogLevelInfo, nil, "describe-reset", "no adapter matched selected reader")
		return adapters.ResetRequirements{}, adapters.ErrUnsupportedToken
	}

	resetAdapter, ok := runtime.Adapter.(adapters.ResetAdapter)
	if !ok {
		runtime.Session.Observe(adapters.LogLevelDebug, runtime.Adapter, "describe-reset", "adapter has no custom reset requirements")
		return adapters.ResetRequirements{}, nil
	}

	runtime.Session.Observe(adapters.LogLevelDebug, runtime.Adapter, "describe-reset", "reading adapter reset requirements")
	return resetAdapter.DescribeReset(runtime.Session)
}

// ResetToken resolves token reset with an adapter override and standard fallback.

func ResetToken(runtime *adapters.Runtime, params adapters.ResetTokenParams) error {
	if err := requireRuntime(runtime); err != nil {
		return err
	}
	return resetToken(runtime.Session, runtime.Adapter, params)
}

func resetToken(session *adapters.Session, adapter adapters.Adapter, params adapters.ResetTokenParams) error {
	if err := requireSessionClient(session); err != nil {
		return err
	}
	if resetAdapter, ok := adapter.(adapters.ResetAdapter); ok {
		session.Observe(adapters.LogLevelInfo, adapter, "reset-token", "delegating token reset to adapter")
		return resetAdapter.ResetToken(session, params)
	}
	session.Observe(adapters.LogLevelInfo, adapter, "reset-token", "falling back to standard PIV token reset")
	return session.Client.Reset()
}

func requireRuntime(runtime *adapters.Runtime) error {
	if runtime == nil || runtime.Session == nil {
		return fmt.Errorf("adapters: session is required")
	}
	return nil
}

func requireSessionClient(session *adapters.Session) error {
	if session == nil {
		return fmt.Errorf("adapters: nil session")
	}
	if session.Client == nil {
		return fmt.Errorf("adapters: session client is required")
	}
	return nil
}

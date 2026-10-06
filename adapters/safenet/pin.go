package safenet

import (
	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// PINStatus reads PIN/PUK retry status from the SafeNet credential metadata
// objects FF8180/FF8181. Tag 9A is the configured limit and 9B is the remaining count.
func (a *Adapter) PINStatus(session *adapters.Session, pinType piv.PINType) (adapters.PINStatus, error) {
	if err := requireSessionClient(session); err != nil {
		return adapters.PINStatus{}, err
	}

	status, ok, err := a.safeNetPINStatus(session, pinType)
	if err == nil && ok {
		return status, nil
	}
	return session.Client.PINStatus(pinType)
}

func (a *Adapter) safeNetPINStatus(session *adapters.Session, pinType piv.PINType) (adapters.PINStatus, bool, error) {
	if err := requireSessionClient(session); err != nil {
		return adapters.PINStatus{}, false, err
	}

	var tag uint
	switch pinType {
	case piv.PINTypeCard:
		tag = 0xFF8180
	case piv.PINTypePUK:
		tag = 0xFF8181
	default:
		return adapters.PINStatus{}, false, nil
	}
	data, err := getMetadata(session.Client, tag)
	if err != nil {
		return adapters.PINStatus{}, false, err
	}

	tlvs, err := iso7816.ParseAllTLV(data)
	if err != nil {
		return adapters.PINStatus{}, false, err
	}

	remaining := findRecursiveTLV(tlvs, 0x9B)
	if remaining == nil || len(remaining.Value) != 1 {
		return adapters.PINStatus{}, false, nil
	}
	maximum := adapters.UnknownRetries
	if limit := findRecursiveTLV(tlvs, 0x9A); limit != nil && len(limit.Value) == 1 {
		maximum = int(limit.Value[0])
	}
	retries := int(remaining.Value[0])
	return adapters.PINStatus{Type: pinType, RetriesLeft: retries, MaxRetries: maximum, Blocked: retries == 0}, true, nil
}

// ChangePIN uses the standard CHANGE REFERENCE DATA command on SafeNet tokens.
func (a *Adapter) ChangePIN(session *adapters.Session, oldPIN string, newPIN string) error {
	return session.Client.ChangePIN(oldPIN, newPIN)
}

// ChangePUK uses the standard CHANGE REFERENCE DATA command on SafeNet tokens.
func (a *Adapter) ChangePUK(session *adapters.Session, oldPUK string, newPUK string) error {
	return session.Client.ChangePUK(oldPUK, newPUK)
}

// UnblockPIN uses the standard RESET RETRY COUNTER command on SafeNet tokens.
func (a *Adapter) UnblockPIN(session *adapters.Session, puk string, newPIN string) error {
	return session.Client.UnblockPIN(puk, newPIN)
}

package safenet

import (
	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// PINStatus reads PIV reference retry status from SafeNet-specific card status TLV.
// SafeNet reports PIN/PUK retries in vendor-specific response TLV (tags 9A/9B) rather than standard VERIFY status.
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

	query := []byte{0x4D, 0x03, 0xFF, 0x81, 0x80, 0x00}
	status, found, err := a.safeNetPINStatusFromQuery(session.Client, pinType, query)
	if err == nil && found {
		return status, true, nil
	}

	query = []byte{0x4D, 0x03, 0xFF, 0x84, 0x0B, 0x00}
	return a.safeNetPINStatusFromQuery(session.Client, pinType, query)
}

func (a *Adapter) safeNetPINStatusFromQuery(client *piv.Client, pinType piv.PINType, query []byte) (adapters.PINStatus, bool, error) {
	cmd := &iso7816.Command{
		Cla:  0x81,
		Ins:  0xCB,
		P1:   0x3F,
		P2:   0xFF,
		Data: query,
		Le:   -1,
	}
	resp, err := client.Execute(cmd)
	if err != nil {
		return adapters.PINStatus{}, false, err
	}
	if err := resp.Err(); err != nil {
		return adapters.PINStatus{}, false, err
	}

	tlvs, err := iso7816.ParseAllTLV(resp.Data)
	if err != nil {
		return adapters.PINStatus{}, false, err
	}

	tag := uint(0x9B)
	if pinType == piv.PINTypePUK {
		tag = 0x9A
	}

	retries, ok := findRecursiveTLVValue(tlvs, tag)
	if !ok {
		return adapters.PINStatus{}, false, nil
	}

	return adapters.PINStatus{Type: pinType, RetriesLeft: retries, Blocked: retries == 0}, true, nil
}

func findRecursiveTLVValue(tlvs []*iso7816.TLV, tag uint) (int, bool) {
	for _, tlv := range tlvs {
		if tlv.Tag == tag && len(tlv.Value) > 0 {
			return int(tlv.Value[0]), true
		}
		inner, err := iso7816.ParseAllTLV(tlv.Value)
		if err != nil {
			continue
		}
		if retries, ok := findRecursiveTLVValue(inner, tag); ok {
			return retries, true
		}
	}
	return 0, false
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

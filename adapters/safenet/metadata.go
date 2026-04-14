package safenet

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// ChangeManagementKey writes the SafeNet admin FF840B object after mutual authentication.
func (a *Adapter) ChangeManagementKey(session *adapters.Session, newAlgorithm byte, newKey []byte) error {
	if err := selectAdminApplet(session.Client); err != nil {
		return err
	}
	if err := readVersion(session.Client); err != nil {
		return err
	}
	if err := readManagementMetadata(session.Client); err != nil {
		return err
	}
	if err := session.AuthenticateManagementKey(a); err != nil {
		return fmt.Errorf("authenticate current management key: %w", err)
	}
	if err := session.Client.PutData(0xFF840B, buildManagementKeyObject(newAlgorithm, newKey)); err != nil {
		return fmt.Errorf("store SafeNet management key object: %w", err)
	}
	if err := session.Client.AuthenticateManagementKeyWithAlgorithm(newAlgorithm, newKey); err != nil {
		return fmt.Errorf("verify new management key: %w", err)
	}
	session.ManagementAlgorithm = newAlgorithm
	session.ManagementKey = append([]byte(nil), newKey...)
	return nil
}

// ManagementKeyStatus reads the SafeNet MGM retry counter from the proprietary admin object.
func (a *Adapter) ManagementKeyStatus(session *adapters.Session) (adapters.ManagementKeyStatus, error) {
	if err := session.Client.Select(); err != nil {
		return adapters.ManagementKeyStatus{}, fmt.Errorf("safenet: select PIV application: %w", err)
	}
	data, err := getMetadata(session.Client, 0xFF840B)
	if err != nil {
		return adapters.ManagementKeyStatus{}, fmt.Errorf("safenet: read management key status: %w", err)
	}
	status, err := parseSafeNetManagementKeyStatus(data)
	if err != nil {
		return adapters.ManagementKeyStatus{}, fmt.Errorf("safenet: parse management key status: %w", err)
	}
	return status, nil
}

func selectAdminApplet(client *piv.Client) error {
	resp, err := client.Execute(&iso7816.Command{Cla: 0x01, Ins: 0xA4, P1: 0x04, P2: 0x00, Data: adminAID, Le: -1})
	if err != nil {
		return fmt.Errorf("select SafeNet admin applet: %w", err)
	}
	if err := resp.Err(); err != nil {
		return fmt.Errorf("select SafeNet admin applet: %w", err)
	}
	return nil
}

func readVersion(client *piv.Client) error {
	resp, err := client.Execute(&iso7816.Command{Cla: 0x81, Ins: 0xCB, P1: 0xDF, P2: 0x30, Le: 0x08})
	if err != nil {
		return fmt.Errorf("read SafeNet version: %w", err)
	}
	if err := resp.Err(); err != nil {
		return fmt.Errorf("read SafeNet version: %w", err)
	}
	return nil
}

func readMetadata(client *piv.Client, slot piv.Slot) error {
	tag, err := generationObjectTag(slot)
	if err != nil {
		return err
	}
	return readMetadataTag(client, tag)
}

func readManagementMetadata(client *piv.Client) error {
	for _, tag := range []uint{0xFF8180, 0xFF840B} {
		if err := readMetadataTag(client, tag); err != nil {
			return err
		}
	}
	return nil
}

func readResetCredentialMetadata(client *piv.Client) error {
	for _, tag := range []uint{0xFF8180, 0xFF8181} {
		if err := readMetadataTag(client, tag); err != nil {
			return err
		}
	}
	return nil
}

func readMetadataTag(client *piv.Client, tag uint) error {
	resp, err := client.Execute(&iso7816.Command{Cla: 0x81, Ins: 0xCB, P1: 0x3F, P2: 0xFF, Data: iso7816.EncodeTLV(0x4D, iso7816.EncodeTag(tag)), Le: 256})
	if err != nil {
		return fmt.Errorf("read SafeNet metadata for tag %X: %w", tag, err)
	}
	if err := resp.Err(); err != nil && !iso7816.IsStatus(err, iso7816.SwFileNotFound) {
		return fmt.Errorf("read SafeNet metadata for tag %X: %w", tag, err)
	}
	return nil
}

func clearSafeNetObject(client *piv.Client, tag uint, value []byte) error {
	if err := client.PutData(tag, value); err != nil {
		if iso7816.IsStatus(err, iso7816.SwFileNotFound) || iso7816.IsStatus(err, iso7816.SwReferencedDataNotFound) || iso7816.IsStatus(err, iso7816.SwWrongData) {
			return nil
		}
		return err
	}
	return nil
}

func getMetadata(client *piv.Client, tag uint) ([]byte, error) {
	cmd := &iso7816.Command{
		Cla:  0x81,
		Ins:  0xCB,
		P1:   0x3F,
		P2:   0xFF,
		Data: iso7816.EncodeTLV(0x4D, iso7816.EncodeTag(tag)),
		Le:   256,
	}
	resp, err := client.Execute(cmd)
	if err != nil {
		return nil, err
	}
	if err := resp.Err(); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func parseSafeNetManagementKeyStatus(data []byte) (adapters.ManagementKeyStatus, error) {
	tlvs, err := iso7816.ParseAllTLV(data)
	if err != nil {
		return adapters.ManagementKeyStatus{}, err
	}
	status := adapters.ManagementKeyStatus{RetriesLeft: adapters.UnknownRetries, MaxRetries: adapters.UnknownRetries}
	if maxTLV := findRecursiveTLV(tlvs, 0x9A); maxTLV != nil {
		status.MaxRetries = int(bytesToInt(maxTLV.Value))
	}
	if remainingTLV := findRecursiveTLV(tlvs, 0x9B); remainingTLV != nil {
		status.RetriesLeft = int(bytesToInt(remainingTLV.Value))
		status.Blocked = status.RetriesLeft == 0
	}
	return status, nil
}

func bytesToInt(value []byte) uint64 {
	var result uint64
	for _, b := range value {
		result = (result << 8) | uint64(b)
	}
	return result
}

func findRecursiveTLV(tlvs []*iso7816.TLV, tag uint) *iso7816.TLV {
	for _, tlv := range tlvs {
		if tlv.Tag == tag {
			return tlv
		}
		inner, err := iso7816.ParseAllTLV(tlv.Value)
		if err == nil {
			if found := findRecursiveTLV(inner, tag); found != nil {
				return found
			}
		}
	}
	return nil
}

func buildManagementKeyObject(algorithm byte, key []byte) []byte {
	inner := iso7816.EncodeTLV(0x80, []byte{algorithm})
	inner = append(inner, iso7816.EncodeTLV(0x90, key)...)
	return iso7816.EncodeTLV(0x7F4A, inner)
}

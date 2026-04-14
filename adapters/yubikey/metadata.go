package yubikey

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// ManagementKeyAlgorithm resolves the active YubiKey management key algorithm.
func (a *Adapter) ManagementKeyAlgorithm(session *adapters.Session, key []byte) (byte, error) {
	if err := requireSessionClient(session); err != nil {
		return 0, err
	}

	switch len(key) {
	case 16:
		session.Observe(adapters.LogLevelDebug, a, "management-key-algorithm", "selected AES-128 from key length")
		return piv.AlgAES128, nil
	case 24:
		session.Observe(adapters.LogLevelDebug, a, "management-key-algorithm", "reading YubiKey management metadata for 24-byte key")
		metadata, err := readManagementKeyMetadata(session.Client)
		if err != nil || metadata.Algorithm == 0 {
			session.Observe(adapters.LogLevelDebug, a, "management-key-algorithm", "falling back to 3DES for 24-byte key")
			return piv.Alg3DES, nil
		}
		session.Observe(adapters.LogLevelDebug, a, "management-key-algorithm", "resolved management key algorithm 0x%02X from metadata", metadata.Algorithm)
		return metadata.Algorithm, nil
	case 32:
		session.Observe(adapters.LogLevelDebug, a, "management-key-algorithm", "selected AES-256 from key length")
		return piv.AlgAES256, nil
	default:
		return 0, fmt.Errorf("yubikey: unsupported management key length %d", len(key))
	}
}

// ChangeManagementKey updates the active YubiKey management key.
func (a *Adapter) ChangeManagementKey(session *adapters.Session, newAlgorithm byte, newKey []byte) error {
	if err := requireSessionClient(session); err != nil {
		return err
	}
	session.Observe(adapters.LogLevelInfo, a, "change-management-key", "starting YubiKey management key rotation")
	if newAlgorithm == 0 {
		session.Observe(adapters.LogLevelDebug, a, "change-management-key", "resolving management key algorithm from new key material")
		algorithm, err := a.ManagementKeyAlgorithm(session, newKey)
		if err != nil {
			return err
		}
		newAlgorithm = algorithm
	}
	session.Observe(adapters.LogLevelDebug, a, "change-management-key", "authenticating current management key")
	if err := session.AuthenticateManagementKey(a); err != nil {
		return fmt.Errorf("authenticate current management key: %w", err)
	}
	session.Observe(adapters.LogLevelInfo, a, "change-management-key", "writing YubiKey management key metadata and value")
	if err := setManagementKey(session.Client, newAlgorithm, newKey, false); err != nil {
		return err
	}
	session.Observe(adapters.LogLevelDebug, a, "change-management-key", "verifying the new management key")
	if err := session.Client.AuthenticateManagementKeyWithAlgorithm(newAlgorithm, newKey); err != nil {
		return fmt.Errorf("verify new management key: %w", err)
	}
	session.ManagementAlgorithm = newAlgorithm
	session.ManagementKey = append([]byte(nil), newKey...)
	session.Observe(adapters.LogLevelInfo, a, "change-management-key", "completed YubiKey management key rotation")
	return nil
}

func readMetadata(client *piv.Client, reference byte) (map[uint][]byte, error) {
	cmd := &iso7816.Command{
		Cla: 0x00,
		Ins: yubiKeyInsGetMetadata,
		P1:  0x00,
		P2:  reference,
		Le:  -1,
	}
	resp, err := client.Execute(cmd)
	if err != nil {
		return nil, err
	}
	if err := resp.Err(); err != nil {
		return nil, err
	}
	tlvs, err := iso7816.ParseAllTLV(resp.Data)
	if err != nil {
		return nil, err
	}
	values := make(map[uint][]byte, len(tlvs))
	for _, tlv := range tlvs {
		values[tlv.Tag] = append([]byte(nil), tlv.Value...)
	}
	return values, nil
}

func readVersion(client *piv.Client) (string, error) {
	cmd := &iso7816.Command{
		Cla: 0x00,
		Ins: yubiKeyInsGetVersion,
		P1:  0x00,
		P2:  0x00,
		Le:  -1,
	}
	resp, err := client.Execute(cmd)
	if err != nil {
		return "", err
	}
	if err := resp.Err(); err != nil {
		return "", err
	}
	if len(resp.Data) < 3 {
		return "", fmt.Errorf("yubikey: short version response")
	}
	return fmt.Sprintf("%d.%d.%d", resp.Data[0], resp.Data[1], resp.Data[2]), nil
}

func readManagementKeyMetadata(client *piv.Client) (yubiKeyManagementMetadata, error) {
	values, err := readMetadata(client, byte(piv.SlotManagement))
	if err != nil {
		return yubiKeyManagementMetadata{}, err
	}
	policy := values[yubiKeyMetadataTagPolicy]
	metadata := yubiKeyManagementMetadata{
		Algorithm:    piv.Alg3DES,
		DefaultValue: len(values[yubiKeyMetadataTagIsDefault]) > 0 && values[yubiKeyMetadataTagIsDefault][0] != 0x00,
	}
	if algorithm := values[yubiKeyMetadataTagAlgorithm]; len(algorithm) > 0 {
		metadata.Algorithm = algorithm[0]
	}
	if len(policy) > 1 {
		metadata.TouchPolicy = policy[1]
	}
	return metadata, nil
}

// ManagementKeyStatus returns management-key metadata for YubiKey tokens.
// Retry state is not exposed by YubiKey metadata, so retry counters remain unknown.
func (a *Adapter) ManagementKeyStatus(session *adapters.Session) (adapters.ManagementKeyStatus, error) {
	if err := requireSessionClient(session); err != nil {
		return adapters.ManagementKeyStatus{}, err
	}
	metadata, err := readManagementKeyMetadata(session.Client)
	if err != nil {
		return adapters.ManagementKeyStatus{}, fmt.Errorf("yubikey: read management key metadata: %w", err)
	}
	status := adapters.ManagementKeyStatus{
		RetriesLeft: adapters.UnlimitedRetries,
		MaxRetries:  adapters.UnlimitedRetries,
	}
	if metadata.DefaultValue {
		session.Observe(adapters.LogLevelDebug, a, "management-key-status", "management key is default")
	}
	return status, nil
}

func readSlotMetadata(client *piv.Client, slot piv.Slot) (yubiKeySlotMetadata, error) {
	values, err := readMetadata(client, byte(slot))
	if err != nil {
		return yubiKeySlotMetadata{}, err
	}
	algorithm := values[yubiKeyMetadataTagAlgorithm]
	policy := values[yubiKeyMetadataTagPolicy]
	publicKeyEncoded := values[yubiKeyMetadataTagPublicKey]
	if len(algorithm) == 0 || len(policy) < 2 || len(publicKeyEncoded) == 0 {
		return yubiKeySlotMetadata{}, fmt.Errorf("yubikey: incomplete slot metadata")
	}

	publicKey, err := piv.ParsePublicKeyObject(iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, publicKeyEncoded)))
	if err != nil {
		return yubiKeySlotMetadata{}, fmt.Errorf("yubikey: parse slot public key: %w", err)
	}

	return yubiKeySlotMetadata{
		Algorithm:   algorithm[0],
		PINPolicy:   policy[0],
		TouchPolicy: policy[1],
		Generated:   len(values[yubiKeyMetadataTagOrigin]) > 0 && values[yubiKeyMetadataTagOrigin][0] == yubiKeyOriginGenerated,
		PublicKey:   publicKey,
	}, nil
}

func setManagementKey(client *piv.Client, algorithm byte, key []byte, requireTouch bool) error {
	p2 := byte(yubiKeySetManagementKeyNoUI)
	if requireTouch {
		p2 = yubiKeySetManagementKeyTouch
	}
	data := append([]byte{algorithm}, iso7816.EncodeTLV(uint(piv.SlotManagement), key)...)
	cmd := &iso7816.Command{
		Cla:  0x00,
		Ins:  yubiKeyInsSetManagementKey,
		P1:   0xFF,
		P2:   p2,
		Data: data,
		Le:   -1,
	}
	resp, err := client.Execute(cmd)
	if err != nil {
		return fmt.Errorf("set YubiKey management key: %w", err)
	}
	if err := resp.Err(); err != nil {
		return fmt.Errorf("set YubiKey management key: %w", err)
	}
	return nil
}

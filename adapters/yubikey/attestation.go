package yubikey

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// YubiKey PIV attestation identifiers.
//
// These vendor-specific constants intentionally live in the YubiKey adapter
// instead of the standard piv package: INS 0xF9, slot 0xF9, and object
// 0x5FFF01 have no meaning in baseline PIV (NIST SP 800-73).
const (
	// yubiKeyInsAttest issues the YubiKey key attestation command (INS 0xF9).
	yubiKeyInsAttest = 0xF9
	// yubiKeyObjectAttestation identifies the vendor object holding the
	// long-lived YubiKey attestation certificate (0x5FFF01).
	yubiKeyObjectAttestation = 0x5FFF01
)

// SlotAttestation identifies the YubiKey attestation slot (0xF9).
//
// Reading its certificate object returns the long-lived attestation
// certificate, while attesting any other slot proves that slot's key.
const SlotAttestation = piv.Slot(0xF9)

// attestationMinVersion is the minimum YubiKey firmware supporting key
// attestation, mirroring yubikit's require_version(..., (4, 3, 0)) guard.
const attestationMinVersion = "4.3.0"

// AttestKey returns the raw DER attestation certificate for the key in the
// specified slot.
//
// Only the user key slots 9A/9C/9D/9E can be attested and the token firmware
// must be 4.3.0 or later. The returned bytes are the raw DER-encoded X.509
// certificate without verification, mirroring yubikit's attest_key transport
// (00 F9 <slot> 00) while leaving chain validation to the caller.
func (a *Adapter) AttestKey(session *adapters.Session, slot piv.Slot) ([]byte, error) {
	if err := requireSessionClient(session); err != nil {
		return nil, err
	}
	if !isAttestableSlot(slot) {
		return nil, fmt.Errorf("yubikey: attestation is not supported for slot %s", slot)
	}
	session.Observe(adapters.LogLevelInfo, a, "attest-key", "starting YubiKey key attestation for %s", slot)
	version, err := readVersion(session.Client)
	if err != nil {
		return nil, fmt.Errorf("yubikey: read firmware version for attestation: %w", err)
	}
	supported, err := attestationVersionSupported(version)
	if err != nil {
		return nil, fmt.Errorf("yubikey: parse firmware version %q for attestation: %w", version, err)
	}
	if !supported {
		return nil, fmt.Errorf("yubikey: firmware %s is not supported for key attestation, requires %s or later", version, attestationMinVersion)
	}
	session.Observe(adapters.LogLevelDebug, a, "attest-key", "issuing YubiKey ATTEST KEY for %s", slot)
	cmd := &iso7816.Command{
		Cla: 0x00,
		Ins: yubiKeyInsAttest,
		P1:  byte(slot),
		P2:  0x00,
		Le:  -1,
	}
	resp, err := session.Client.Execute(cmd)
	if err != nil {
		return nil, fmt.Errorf("attest YubiKey key in slot %s: %w", slot, err)
	}
	if err := resp.Err(); err != nil {
		return nil, fmt.Errorf("attest YubiKey key in slot %s: %w", slot, err)
	}
	if len(resp.Data) == 0 {
		return nil, fmt.Errorf("attest YubiKey key in slot %s: empty attestation response", slot)
	}
	session.Observe(adapters.LogLevelInfo, a, "attest-key", "completed YubiKey key attestation for %s", slot)
	return append([]byte(nil), resp.Data...), nil
}

// AttestationCertificate reads the long-lived YubiKey attestation certificate
// from the vendor attestation object (0x5FFF01).
//
// Like yubikit's read of OBJECT_ID.ATTESTATION, the object payload is a
// standard PIV data object, so the DER certificate is unwrapped with
// piv.ParseCertificateObject and returned without x509 verification.
func (a *Adapter) AttestationCertificate(session *adapters.Session) ([]byte, error) {
	if err := requireSessionClient(session); err != nil {
		return nil, err
	}
	session.Observe(adapters.LogLevelDebug, a, "attestation-certificate", "reading YubiKey attestation certificate object")
	data, err := session.Client.GetData(yubiKeyObjectAttestation)
	if err != nil {
		return nil, fmt.Errorf("yubikey: read attestation certificate object: %w", err)
	}
	cert, err := piv.ParseCertificateObject(data)
	if err != nil {
		return nil, fmt.Errorf("yubikey: parse attestation certificate object: %w", err)
	}
	return cert, nil
}

// isAttestableSlot reports whether the slot holds a user key that YubiKey
// attestation supports.
func isAttestableSlot(slot piv.Slot) bool {
	switch slot {
	case piv.SlotAuthentication, piv.SlotSignature, piv.SlotKeyManagement, piv.SlotCardAuth:
		return true
	default:
		return false
	}
}

// attestationVersionSupported reports whether the firmware version string
// (for example "5.7.0") meets the minimum attestation requirement.
func attestationVersionSupported(version string) (bool, error) {
	current, err := parseFirmwareVersion(version)
	if err != nil {
		return false, err
	}
	minimum, err := parseFirmwareVersion(attestationMinVersion)
	if err != nil {
		return false, err
	}
	for index := range current {
		if current[index] != minimum[index] {
			return current[index] > minimum[index], nil
		}
	}
	return true, nil
}

// parseFirmwareVersion parses a dotted firmware version into its numeric parts.
func parseFirmwareVersion(version string) ([3]int, error) {
	var parts [3]int
	fields := strings.Split(strings.TrimSpace(version), ".")
	if len(fields) != 3 {
		return parts, fmt.Errorf("expected major.minor.patch, got %q", version)
	}
	for index, field := range fields {
		number, err := strconv.Atoi(field)
		if err != nil || number < 0 {
			return parts, fmt.Errorf("invalid version component %q in %q", field, version)
		}
		parts[index] = number
	}
	return parts, nil
}

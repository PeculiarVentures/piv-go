package piv

// PIV data object tags as defined in NIST SP 800-73.
const (
	// ObjectCHUID is the Card Holder Unique Identifier.
	ObjectCHUID uint = 0x5FC102

	// ObjectCCC is the Card Capability Container.
	ObjectCCC uint = 0x5FC107

	// ObjectPIVAuthKey is the PIV Authentication Key.
	ObjectPIVAuthKey uint = 0x0101

	// ObjectDigitalSigKey is the Digital Signature Key.
	ObjectDigitalSigKey uint = 0x0100

	// ObjectKeyMgmtKey is the Key Management Key.
	ObjectKeyMgmtKey uint = 0x0102

	// ObjectCardAuthKey is the Card Authentication Key.
	ObjectCardAuthKey uint = 0x0500

	// ObjectCertPIVAuth is the X.509 Certificate for PIV Authentication (slot 9a).
	ObjectCertPIVAuth uint = 0x5FC105

	// ObjectCertDigitalSig is the X.509 Certificate for Digital Signature (slot 9c).
	ObjectCertDigitalSig uint = 0x5FC10A

	// ObjectCertKeyMgmt is the X.509 Certificate for Key Management (slot 9d).
	ObjectCertKeyMgmt uint = 0x5FC10B

	// ObjectCertCardAuth is the X.509 Certificate for Card Authentication (slot 9e).
	ObjectCertCardAuth uint = 0x5FC101

	// ObjectFingerprint1 is Fingerprint Template 1.
	ObjectFingerprint1 uint = 0x6010

	// ObjectFingerprint2 is Fingerprint Template 2.
	ObjectFingerprint2 uint = 0x6011

	// ObjectPrintedInfo is the printed information object.
	ObjectPrintedInfo uint = 0x3001

	// ObjectFacialImage is the facial image object.
	ObjectFacialImage uint = 0x6030

	// ObjectSecurityObject is the security object.
	ObjectSecurityObject uint = 0x9000
)

// ObjectInfo describes a known PIV data object.
type ObjectInfo struct {
	Tag  uint
	Name string
}

// KnownObjects returns the list of standard PIV data objects.
func KnownObjects() []ObjectInfo {
	return []ObjectInfo{
		{ObjectCHUID, "CHUID"},
		{ObjectCCC, "CCC"},
		{ObjectPIVAuthKey, "PIV Authentication Key"},
		{ObjectDigitalSigKey, "Digital Signature Key"},
		{ObjectKeyMgmtKey, "Key Management Key"},
		{ObjectCardAuthKey, "Card Authentication Key"},
		{ObjectCertPIVAuth, "Certificate PIV Authentication (9A)"},
		{ObjectCertDigitalSig, "Certificate Digital Signature (9C)"},
		{ObjectCertKeyMgmt, "Certificate Key Management (9D)"},
		{ObjectCertCardAuth, "Certificate Card Authentication (9E)"},
		{ObjectFingerprint1, "Fingerprint 1"},
		{ObjectFingerprint2, "Fingerprint 2"},
		{ObjectPrintedInfo, "Printed Information"},
		{ObjectFacialImage, "Facial Image"},
		{ObjectSecurityObject, "Security Object"},
	}
}

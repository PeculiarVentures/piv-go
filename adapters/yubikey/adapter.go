package yubikey

import (
	"crypto"
	"strings"

	"github.com/PeculiarVentures/piv-go/adapters"
)

var defaultManagementKey = []byte{
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
}

const (
	yubiKeyInsMoveKey          = 0xF6
	yubiKeyInsGetMetadata      = 0xF7
	yubiKeyInsSetManagementKey = 0xFF
	yubiKeyInsGetVersion       = 0xFD

	yubiKeyMetadataTagAlgorithm  = 0x01
	yubiKeyMetadataTagPolicy     = 0x02
	yubiKeyMetadataTagOrigin     = 0x03
	yubiKeyMetadataTagPublicKey  = 0x04
	yubiKeyMetadataTagIsDefault  = 0x05
	yubiKeyMetadataTagRetries    = 0x06
	yubiKeyOriginGenerated       = 0x01
	yubiKeySetManagementKeyTouch = 0xFE
	yubiKeySetManagementKeyNoUI  = 0xFF
)

type yubiKeyPINMetadata struct {
	DefaultValue      bool
	TotalAttempts     int
	AttemptsRemaining int
}

type yubiKeyManagementMetadata struct {
	Algorithm    byte
	DefaultValue bool
	TouchPolicy  byte
}

type yubiKeySlotMetadata struct {
	Algorithm   byte
	PINPolicy   byte
	TouchPolicy byte
	Generated   bool
	PublicKey   crypto.PublicKey
}

// Adapter implements vendor-specific behavior for YubiKey tokens.
type Adapter struct{}

// NewAdapter creates a new YubiKey adapter.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// Register registers the YubiKey adapter in a caller-provided registry.
func Register(registry *adapters.Registry) {
	registry.Register(NewAdapter())
}

// Name returns the adapter name.
func (a *Adapter) Name() string {
	return "yubikey"
}

// MatchReader reports whether the adapter should handle the specified reader.
func (a *Adapter) MatchReader(readerName string) bool {
	name := strings.ToLower(readerName)
	return strings.Contains(name, "yubikey") || strings.Contains(name, "yubico")
}

// Capabilities reports the operations available for YubiKey PIV tokens.
func (a *Adapter) Capabilities() adapters.CapabilityReport {
	return adapters.NewCapabilityReport(a, map[adapters.CapabilityID]adapters.CapabilityOverride{
		adapters.CapabilityDeleteKey:           {Notes: "uses YubiKey MOVE KEY delete operation on firmware 5.7+"},
		adapters.CapabilityInspectSlots:        {Notes: "uses YubiKey slot metadata to detect keys without certificates"},
		adapters.CapabilityPINStatus:           {Support: adapters.CapabilityVendor, Notes: "prefers YubiKey metadata when available"},
		adapters.CapabilityManagementKeyStatus: {Support: adapters.CapabilityVendor, Notes: "reads YubiKey MGM metadata; retry counters are unlimited"},
		adapters.CapabilityPUKStatus:           {Support: adapters.CapabilityVendor, Notes: "falls back when empty VERIFY returns 6A88"},
		adapters.CapabilityReadSerialNumber:    {Support: adapters.CapabilityVendor, Notes: "uses YubiKey GET SERIAL vendor command"},
		adapters.CapabilityReadTokenLabel:      {Support: adapters.CapabilityVendor, Notes: "uses YubiKey serial to generate token label"},
		adapters.CapabilityChangeManagementKey: {Notes: "uses YubiKey SET MANAGEMENT KEY command"},
		adapters.CapabilityResetToken:          {Notes: "blocks PIN and PUK before issuing YubiKey reset"},
	})
}

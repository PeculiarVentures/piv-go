package safenet

import (
	"fmt"
	"strings"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

var adminAID = []byte{
	0xA0, 0x00, 0x00, 0x03, 0x08,
	0x00, 0x00, 0x10, 0x00,
	0x02, 0x00,
}

var defaultManagementKey = []byte{
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04,
	0x05, 0x06, 0x07, 0x08,
}

const (
	defaultPIN = "123456"
	defaultPUK = "12345678"
)

var eccP256Parameters = []struct {
	tag   uint
	value []byte
}{
	{tag: 0x81, value: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
	{tag: 0x82, value: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC}},
	{tag: 0x83, value: []byte{0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC, 0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B}},
	{tag: 0x84, value: []byte{0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5}},
	{tag: 0x85, value: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51}},
	{tag: 0x87, value: []byte{0x00, 0x01}},
}

// Adapter implements vendor-specific behavior for SafeNet tokens.
type Adapter struct{}

// NewAdapter creates a new SafeNet adapter.
func NewAdapter() *Adapter {
	return &Adapter{}
}

// Register registers the SafeNet adapter in a caller-provided registry.
func Register(registry *adapters.Registry) {
	registry.Register(NewAdapter())
}

// Name returns the adapter name.
func (a *Adapter) Name() string {
	return "safenet"
}

// MatchReader reports whether the adapter should handle the specified reader.
func (a *Adapter) MatchReader(readerName string) bool {
	name := strings.ToLower(readerName)
	return strings.Contains(name, "safenet") || strings.Contains(name, "etoken")
}

// CHUID returns the token CHUID object for SafeNet tokens.
//
// SafeNet may store CHUID in the standard PIV object or in a vendor-specific
// alias object. This method prefers the standard CHUID object and falls back
// to SafeNet's metadata alias when necessary.
func (a *Adapter) CHUID(session *adapters.Session) ([]byte, error) {
	if err := session.Client.Select(); err != nil {
		return nil, fmt.Errorf("safenet: select PIV application: %w", err)
	}

	chuid, err := session.Client.GetData(piv.ObjectCHUID)
	if err == nil {
		return chuid, nil
	}
	if iso7816.IsStatus(err, iso7816.SwFileNotFound) {
		return session.Client.GetData(safeNetCHUIDAlias)
	}
	return nil, err
}

// Capabilities reports how SafeNet support is split between standard PIV flows
// and vendor-specific overrides.
func (a *Adapter) Capabilities() adapters.CapabilityReport {
	return adapters.NewCapabilityReport(a, map[adapters.CapabilityID]adapters.CapabilityOverride{
		adapters.CapabilityInitializeToken:     {Notes: "supports SafeNet initialization with trace-aligned emulator and live-card flows"},
		adapters.CapabilityGenerateKey:         {Notes: "requires SafeNet generation metadata and mirror objects"},
		adapters.CapabilityDeleteKey:           {Notes: "clears SafeNet vendor and mirror objects"},
		adapters.CapabilityReadCertificate:     {Notes: "falls back to SafeNet mirror objects"},
		adapters.CapabilityWriteCertificate:    {Notes: "writes both standard and mirror objects"},
		adapters.CapabilityDeleteCertificate:   {Notes: "preserves public key state when possible"},
		adapters.CapabilityReadSerialNumber:    {Support: adapters.CapabilityVendor, Notes: "reads SafeNet hardware serial through vendor GET DATA object 0x0104"},
		adapters.CapabilityReadTokenLabel:      {Support: adapters.CapabilityVendor, Notes: "reads SafeNet vendor label from object 0x5FFF12 after PIV select"},
		adapters.CapabilityInspectSlots:        {Notes: "uses SafeNet mirror fallback for slot state"},
		adapters.CapabilityPUKStatus:           {Support: adapters.CapabilityVendor, Notes: "reads SafeNet PUK retry status from vendor-specific TLV response"},
		adapters.CapabilityChangeManagementKey: {Notes: "uses SafeNet admin object FF840B"},
		adapters.CapabilityResetSlot:           {Notes: "clears generation and mirror objects for a slot"},
		adapters.CapabilityResetToken:          {Notes: "clears SafeNet vendor objects and restores the default management key"},
	})
}

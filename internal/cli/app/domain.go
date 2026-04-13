package app

import (
	"crypto"

	"github.com/PeculiarVentures/piv-go/adapters"
	adaptersadmin "github.com/PeculiarVentures/piv-go/adapters/admin"
	adaptersinit "github.com/PeculiarVentures/piv-go/adapters/initialization"
	adapterslots "github.com/PeculiarVentures/piv-go/adapters/slots"
	"github.com/PeculiarVentures/piv-go/piv"
)

func readCertificate(runtime *adapters.Runtime, slot piv.Slot) ([]byte, error) {
	if certificateAdapter, ok := runtime.Adapter.(adapters.CertificateAdapter); ok {
		return certificateAdapter.ReadCertificate(runtime.Session, slot)
	}
	return runtime.Session.Client.ReadCertificate(slot)
}

func readPublicKey(runtime *adapters.Runtime, slot piv.Slot) (crypto.PublicKey, error) {
	if certificateAdapter, ok := runtime.Adapter.(adapters.CertificateAdapter); ok {
		return certificateAdapter.ReadPublicKey(runtime.Session, slot)
	}
	return runtime.Session.Client.ReadPublicKey(slot)
}

func writeCertificate(runtime *adapters.Runtime, slot piv.Slot, certData []byte) error {
	if certificateAdapter, ok := runtime.Adapter.(adapters.CertificateAdapter); ok {
		return certificateAdapter.PutCertificate(runtime.Session, slot, certData)
	}
	return runtime.Session.Client.PutCertificate(slot, certData)
}

func clearCertificate(runtime *adapters.Runtime, slot piv.Slot) error {
	if certificateAdapter, ok := runtime.Adapter.(adapters.CertificateAdapter); ok {
		return certificateAdapter.DeleteCertificate(runtime.Session, slot)
	}
	return runtime.Session.Client.DeleteCertificate(slot)
}

func generateKeyPair(runtime *adapters.Runtime, slot piv.Slot, algorithm byte) (crypto.PublicKey, error) {
	if generator, ok := runtime.Adapter.(adapters.KeyGenerationAdapter); ok {
		if err := generator.PrepareGenerateKey(runtime.Session, slot, algorithm); err != nil {
			return nil, err
		}
	}
	publicKey, err := runtime.Session.Client.GenerateKeyPair(slot, algorithm)
	if err != nil {
		return nil, err
	}
	if generator, ok := runtime.Adapter.(adapters.KeyGenerationAdapter); ok {
		if err := generator.FinalizeGenerateKey(runtime.Session, slot, algorithm, publicKey); err != nil {
			return nil, err
		}
	}
	return publicKey, nil
}

func deleteKeyPair(runtime *adapters.Runtime, slot piv.Slot) error {
	if deleter, ok := runtime.Adapter.(adapters.KeyDeletionAdapter); ok {
		return deleter.DeleteKey(runtime.Session, slot)
	}
	return UnsupportedError("key deletion is not supported on the selected token", "inspect capabilities with piv info")
}

func describeSlot(runtime *adapters.Runtime, slot piv.Slot) (SlotView, error) {
	description, err := adapterslots.DescribeSlot(runtime, slot)
	if err != nil {
		return SlotView{}, err
	}
	return SlotView{
		Name:         SlotName(slot),
		Hex:          SlotHex(slot),
		KeyPresent:   description.KeyPresent,
		KeyAlgorithm: description.KeyAlgorithm,
		CertPresent:  description.CertPresent,
		CertLabel:    description.CertLabel,
	}, nil
}

func describePrimarySlots(runtime *adapters.Runtime) ([]SlotView, error) {
	result := make([]SlotView, 0, len(primarySlots))
	for _, slot := range primarySlots {
		description, err := describeSlot(runtime, slot)
		if err != nil {
			return nil, err
		}
		result = append(result, description)
	}
	return result, nil
}

func readPINStatus(runtime *adapters.Runtime, pinType piv.PINType) (adapters.PINStatus, error) {
	return adaptersadmin.ReadPINStatus(runtime, pinType)
}

func describeInitialization(runtime *adapters.Runtime) (adapters.InitializationRequirements, error) {
	return adaptersinit.DescribeInitializationWithRuntime(runtime)
}

func initializeToken(runtime *adapters.Runtime, params adapters.InitializeTokenParams) (*adapters.InitializationResult, error) {
	return adaptersinit.InitializeTokenWithRuntime(runtime, params)
}

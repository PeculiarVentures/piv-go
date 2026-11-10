package safenet

import (
	"crypto"
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
	adapterslots "github.com/PeculiarVentures/piv-go/adapters/slots"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

func readPublicObject(client *piv.Client, tag uint) ([]byte, error) {
	data, err := client.GetData(tag)
	// SafeNet uses 6A80 for these missing public objects, without proving private-key absence.
	if (tag == safeNetCardAuthMirrorTag || tag == safeNetCHUIDAlias) && iso7816.IsStatus(err, iso7816.SwWrongData) {
		return nil, fmt.Errorf("safenet: public object %X not found: %w", tag, iso7816.StatusError(iso7816.SwFileNotFound))
	}
	return data, err
}

func parsePublicObjectCertificate(data []byte) ([]byte, error) {
	certificate, err := piv.ParseCertificateObject(data)
	if err == nil {
		return certificate, nil
	}
	description := adapterslots.DescribeDataObject(data, nil)
	if description.CertState == adapters.SlotStateAbsent && description.KeyError == nil {
		return nil, iso7816.StatusError(iso7816.SwFileNotFound)
	}
	return nil, err
}

func parsePublicObjectStoredKey(data []byte) (crypto.PublicKey, error) {
	key, err := piv.ParsePublicKeyObject(data)
	if err == nil {
		return key, nil
	}
	description := adapterslots.DescribeDataObject(data, nil)
	if description.KeyError != nil {
		return nil, description.KeyError
	}
	if description.CertError != nil {
		return nil, description.CertError
	}
	return nil, iso7816.StatusError(iso7816.SwFileNotFound)
}

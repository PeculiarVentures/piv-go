package safenet

import (
	"fmt"

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

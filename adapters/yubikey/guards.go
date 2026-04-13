package yubikey

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
)

func requireSessionClient(session *adapters.Session) error {
	if session == nil || session.Client == nil {
		return fmt.Errorf("yubikey: session client is required")
	}
	return nil
}

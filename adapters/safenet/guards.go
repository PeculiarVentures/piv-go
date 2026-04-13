package safenet

import (
	"fmt"

	"github.com/PeculiarVentures/piv-go/adapters"
)

func requireSession(session *adapters.Session) error {
	if session == nil {
		return fmt.Errorf("safenet: session is required")
	}
	return nil
}

func requireSessionReaderName(session *adapters.Session) error {
	if err := requireSession(session); err != nil {
		return err
	}
	if session.ReaderName == "" {
		return fmt.Errorf("safenet: session reader name is required")
	}
	return nil
}

func requireSessionClient(session *adapters.Session) error {
	if err := requireSession(session); err != nil {
		return err
	}
	if session.Client == nil {
		return fmt.Errorf("safenet: session client is required")
	}
	return nil
}

package adapters

import "fmt"

func requireSession(session *Session) error {
	if session == nil {
		return fmt.Errorf("adapters: nil session")
	}
	return nil
}

func requireSessionReaderName(session *Session) error {
	if err := requireSession(session); err != nil {
		return err
	}
	if session.ReaderName == "" {
		return fmt.Errorf("adapters: session reader name is required")
	}
	return nil
}

func requireSessionClient(session *Session) error {
	if err := requireSession(session); err != nil {
		return err
	}
	if session.Client == nil {
		return fmt.Errorf("adapters: session client is required")
	}
	return nil
}

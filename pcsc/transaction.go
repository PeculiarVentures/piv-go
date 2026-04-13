package pcsc

// Transaction executes fn within a card transaction.
// It calls Begin before fn and End after fn completes.
// If fn returns an error, End is still called and the original error is returned.
func Transaction(card *Card, fn func() error) error {
	if err := card.Begin(); err != nil {
		return err
	}
	fnErr := fn()
	endErr := card.End()
	if fnErr != nil {
		return fnErr
	}
	return endErr
}

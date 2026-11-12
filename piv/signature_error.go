package piv

import "errors"

// ErrInvalidSignatureResponse identifies a signature response that could not
// be accepted after a private operation was sent to the card. The private
// operation may already have completed, including PIN-always or touch effects.
// Callers must not treat this as a preflight failure or automatically retry it.
// It reports response-shape validation, not cryptographic verification:
// SignRSA and SignECDSA leave verification against the expected public key to
// the caller.
var ErrInvalidSignatureResponse = errors.New("piv: invalid signature response")

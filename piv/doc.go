// Package piv implements the PIV (Personal Identity Verification) protocol
// defined in NIST SP 800-73 for smart card communication.
//
// It provides a Client type for interacting with PIV-compatible tokens via
// standard commands: SELECT, GET DATA, VERIFY PIN, GENERAL AUTHENTICATE,
// PUT DATA, and GENERATE ASYMMETRIC KEY PAIR.
package piv

// Package iso7816 implements ISO 7816 smart card communication primitives.
//
// It provides APDU command encoding/decoding, response parsing with status word
// handling (SW1/SW2), and BER-TLV (Tag-Length-Value) structure parsing and encoding.
// Status words are mapped to descriptive Go errors for convenient error handling.
package iso7816

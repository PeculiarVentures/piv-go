// Package pcsc provides PC/SC smart card transport using github.com/ebfe/scard.
//
// All direct scard calls are isolated in this package. Upper layers communicate
// with smart cards through the Card type, which wraps scard.Card and exposes
// Transmit, Begin, End, and Close operations. The Context type manages the
// PC/SC resource manager context and provides reader discovery and card connection.
package pcsc

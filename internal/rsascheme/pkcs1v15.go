// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsascheme

import (
	"crypto"
	"crypto/rsa"
	"errors"
)

// These SHA-2 DigestInfo prefixes are copied from Go go1.23.12 crypto/rsa.
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

// EncodePKCS1v15 constructs a modulus-width type-1 block. Hash zero means
// an exact opaque payload: no DigestInfo parsing or rewriting is performed.
func EncodePKCS1v15(k int, hash crypto.Hash, hashed []byte) ([]byte, error) {
	// Special case: crypto.Hash(0) is used to indicate that the data is
	// signed directly.
	var prefix []byte
	if hash != 0 {
		var ok bool
		prefix, ok = hashPrefixes[hash]
		if !ok {
			return nil, errors.New("crypto/rsa: unsupported hash function")
		}
		if len(hashed) != hash.Size() {
			return nil, errors.New("crypto/rsa: input must be hashed message")
		}
	}

	// EM = 0x00 || 0x01 || PS || 0x00 || T
	if k < 11 || len(prefix) > k-11 || len(hashed) > k-11-len(prefix) {
		return nil, rsa.ErrMessageTooLong
	}
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-len(prefix)-len(hashed)-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-len(prefix)-len(hashed):], prefix)
	copy(em[k-len(hashed):], hashed)
	return em, nil
}

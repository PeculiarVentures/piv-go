package piv

import (
	"crypto/aes"
	"crypto/subtle"
)

// aesCMAC computes AES-CMAC (NIST SP 800-38B, RFC 4493) of msg under key.
// PIV secure messaging uses it for the key confirmation cryptogram and for
// the command and response MACs.
func aesCMAC(key, msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	const bs = aes.BlockSize
	l := make([]byte, bs)
	block.Encrypt(l, l)
	k1 := cmacShift(l)
	k2 := cmacShift(k1)

	n := (len(msg) + bs - 1) / bs
	complete := n > 0 && len(msg)%bs == 0
	if n == 0 {
		n = 1
	}
	last := make([]byte, bs)
	if complete {
		subtle.XORBytes(last, msg[(n-1)*bs:], k1)
	} else {
		rest := msg[(n-1)*bs:]
		copy(last, rest)
		last[len(rest)] = 0x80
		subtle.XORBytes(last, last, k2)
	}
	x := make([]byte, bs)
	for i := 0; i < n-1; i++ {
		subtle.XORBytes(x, x, msg[i*bs:(i+1)*bs])
		block.Encrypt(x, x)
	}
	subtle.XORBytes(x, x, last)
	block.Encrypt(x, x)
	return x, nil
}

// cmacShift doubles a block in GF(2^128).
func cmacShift(in []byte) []byte {
	out := make([]byte, len(in))
	var carry byte
	for i := len(in) - 1; i >= 0; i-- {
		out[i] = in[i]<<1 | carry
		carry = in[i] >> 7
	}
	if carry != 0 {
		out[len(out)-1] ^= 0x87
	}
	return out
}

package piv

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"

	"github.com/PeculiarVentures/piv-go/iso7816"
)

// PIV secure messaging (SP 800-73-4 Part 2, section 4) gives the host an
// encrypted, authenticated channel to the PIV application. With the virtual
// contact interface it lets a contactless reader do what a contact reader
// can.
//
// Key establishment is one GENERAL AUTHENTICATE to key reference 04. The
// host sends an ephemeral public key; the card answers with a nonce, a key
// confirmation cryptogram and its card verifiable certificate (CVC), which
// certifies its static key-agreement key. Session keys come from ECDH between
// the two keys through the SP 800-56A concatenation KDF. The host trusts the
// card's key because the CVC verifies with the content signing certificate
// in the card's Secure Messaging Certificate Signer object (5FC122), whose
// path the host validates to a root it trusts.
//
// The steps follow OpenSC's card-piv.c (piv_sm_open, piv_encode_apdu and
// piv_decode_apdu), the reference host implementation.

// Secure messaging cipher suites, as their algorithm identifiers.
const (
	SMCipherSuite2 byte = 0x27 // ECDH P-256, AES-128, SHA-256
	SMCipherSuite7 byte = 0x2E // ECDH P-384, AES-256, SHA-384
)

const (
	keyRefSecureMessaging = 0x04
	keyRefPairingCode     = 0x98
	tagSMSigner           = 0x5FC122
)

type smSuite struct {
	id        byte
	curve     ecdh.Curve
	ecCurve   elliptic.Curve
	curveOID  asn1.ObjectIdentifier
	sigOID    asn1.ObjectIdentifier
	hash      func() hash.Hash
	nonceLen  int
	keyLen    int
	otherInfo byte
}

var smSuites = map[byte]smSuite{
	SMCipherSuite2: {SMCipherSuite2, ecdh.P256(), elliptic.P256(), asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7},
		asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, sha256.New, 16, 16, 0x09},
	SMCipherSuite7: {SMCipherSuite7, ecdh.P384(), elliptic.P384(), asn1.ObjectIdentifier{1, 3, 132, 0, 34},
		asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}, sha512.New384, 24, 32, 0x0D},
}

// SecureMessagingCVC is a PIV secure messaging card verifiable certificate
// (SP 800-73-4 Part 2, Tables 15 and 16).
type SecureMessagingCVC struct {
	// IssuerID names the signer: the leftmost 8 bytes of the content
	// signing certificate's subjectKeyIdentifier, or of an intermediate
	// CVC's subject identifier.
	IssuerID []byte
	// SubjectID is the card's 16-byte GUID for the card application key, or
	// 8 bytes for an intermediate CVC.
	SubjectID []byte
	// PublicKey is the certified key.
	PublicKey *ecdsa.PublicKey
	// Role is 00 for the card application key and 12 for an intermediate.
	Role byte
	// SignatureAlgorithm and Signature (DER ECDSA-Sig-Value) cover Body.
	SignatureAlgorithm asn1.ObjectIdentifier
	Signature          []byte
	Body               []byte
	Raw                []byte
}

// ParseSecureMessagingCVC decodes a PIV secure messaging CVC.
func ParseSecureMessagingCVC(raw []byte) (*SecureMessagingCVC, error) {
	top, err := iso7816.ParseAllTLV(raw)
	if err != nil || len(top) != 1 || top[0].Tag != 0x7F21 {
		return nil, errors.New("piv: a CVC is one 7F21 object")
	}
	// Read the elements one at a time so the signed body is the bytes as
	// sent, whatever length encoding the issuer chose.
	var els []*iso7816.TLV
	var bodyLen int
	for rest := top[0].Value; len(rest) > 0; {
		e, next, err := iso7816.ParseTLV(rest)
		if err != nil {
			return nil, fmt.Errorf("piv: CVC: %w", err)
		}
		els = append(els, e)
		if len(els) == 5 {
			bodyLen = len(top[0].Value) - len(next)
		}
		rest = next
	}
	if len(els) != 6 {
		return nil, errors.New("piv: a CVC has six elements")
	}
	for i, tag := range []uint{0x5F29, 0x42, 0x5F20, 0x7F49, 0x5F4C, 0x5F37} {
		if els[i].Tag != tag {
			return nil, fmt.Errorf("piv: CVC element %d is %X, not %X", i, els[i].Tag, tag)
		}
	}
	if !bytes.Equal(els[0].Value, []byte{0x80}) {
		return nil, fmt.Errorf("piv: CVC profile identifier %X is not 80", els[0].Value)
	}
	if len(els[4].Value) != 1 {
		return nil, errors.New("piv: a CVC role identifier is one byte")
	}
	key, err := iso7816.ParseAllTLV(els[3].Value)
	if err != nil || len(key) != 2 || key[0].Tag != 0x06 || key[1].Tag != 0x86 {
		return nil, errors.New("piv: a CVC public key is a curve OID and a point")
	}
	var curve elliptic.Curve
	for _, s := range smSuites {
		if bytes.Equal(key[0].Value, oidContents(s.curveOID)) {
			curve = s.ecCurve
		}
	}
	if curve == nil {
		return nil, errors.New("piv: a CVC key is on P-256 or P-384")
	}
	public, err := ecdsa.ParseUncompressedPublicKey(curve, key[1].Value)
	if err != nil {
		return nil, fmt.Errorf("piv: CVC public key: %w", err)
	}
	var ds struct {
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
			Params    asn1.RawValue `asn1:"optional"`
		}
		Signature asn1.BitString
	}
	if rest, err := asn1.Unmarshal(els[5].Value, &ds); err != nil || len(rest) != 0 {
		return nil, errors.New("piv: a CVC signature is a SEQUENCE of an algorithm and a BIT STRING")
	}
	body := append([]byte(nil), top[0].Value[:bodyLen]...)
	return &SecureMessagingCVC{
		IssuerID: els[1].Value, SubjectID: els[2].Value, PublicKey: public, Role: els[4].Value[0],
		SignatureAlgorithm: ds.Algorithm.Algorithm, Signature: ds.Signature.Bytes,
		Body: body, Raw: append([]byte(nil), raw...),
	}, nil
}

// verifyWith checks the CVC's signature with key, hashing with the cipher
// suite's hash as SP 800-73-4 and OpenSC do.
func (c *SecureMessagingCVC) verifyWith(key crypto.PublicKey, s smSuite) error {
	ec, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("piv: the CVC signer's key is %T, not ECDSA", key)
	}
	if !c.SignatureAlgorithm.Equal(s.sigOID) {
		return fmt.Errorf("piv: the CVC is signed with %s, not cipher suite %02X's algorithm", c.SignatureAlgorithm, s.id)
	}
	h := s.hash()
	h.Write(c.Body)
	if !ecdsa.VerifyASN1(ec, h.Sum(nil), c.Signature) {
		return errors.New("piv: the CVC signature does not verify")
	}
	return nil
}

// SecureMessagingOptions configures key establishment.
type SecureMessagingOptions struct {
	// CipherSuite is SMCipherSuite2 (the default) or SMCipherSuite7.
	CipherSuite byte
	// Roots are the trust anchors the content signing certificate in
	// 5FC122 must chain to. Intermediates helps build the path.
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	// CurrentTime is the time the path is validated at; zero means now.
	CurrentTime time.Time
	// InsecureSkipSignerVerification accepts any content signing
	// certificate the card presents. The CVC is still checked against it,
	// which proves only that the card holds a key someone certified.
	InsecureSkipSignerVerification bool

	// EphemeralKey and HostID replace the generated ephemeral key and the
	// random 8-byte host identifier. They exist so a session can be
	// reproduced against a recorded transcript; leave them nil otherwise.
	EphemeralKey *ecdh.PrivateKey
	HostID       []byte
}

// SecureChannel is an established secure messaging session. It is a Card:
// a Client built on it sends every command protected. Any failure ends the
// session, and the card ends it too on a bad MAC or a SELECT.
type SecureChannel struct {
	inner           Card
	suite           smSuite
	chained         []byte // a command the caller is chaining, sent whole
	mac, enc, rmac  []byte
	encCtr, respCtr [16]byte
	cMCV, rMCV      [16]byte
	cvc             *SecureMessagingCVC
	intermediate    *SecureMessagingCVC
	signer          *x509.Certificate
	open            bool
}

// ErrSecureMessagingClosed is a command on a session that has ended.
var ErrSecureMessagingClosed = errors.New("piv: the secure messaging session has ended")

// OpenSecureMessaging establishes secure messaging with the card, whose PIV
// application must already be selected. It validates the card's CVC and the
// content signing certificate's path before trusting the card's key.
func OpenSecureMessaging(card Card, opts SecureMessagingOptions) (*SecureChannel, error) {
	id := opts.CipherSuite
	if id == 0 {
		id = SMCipherSuite2
	}
	s, ok := smSuites[id]
	if !ok {
		return nil, fmt.Errorf("piv: secure messaging cipher suite %02X is not 27 or 2E", id)
	}
	if opts.Roots == nil && !opts.InsecureSkipSignerVerification {
		return nil, errors.New("piv: secure messaging needs Roots to validate the card's content signing certificate")
	}

	signerObject, err := plainTransmit(card, getDataCommand(tagSMSigner))
	if err != nil {
		return nil, fmt.Errorf("piv: read the Secure Messaging Certificate Signer: %w", err)
	}
	signer, intermediate, err := parseSMSignerObject(signerObject)
	if err != nil {
		return nil, err
	}
	if !opts.InsecureSkipSignerVerification {
		if err := checkContentSigner(signer); err != nil {
			return nil, err
		}
		if _, err := signer.Verify(x509.VerifyOptions{
			Roots: opts.Roots, Intermediates: opts.Intermediates, CurrentTime: opts.CurrentTime,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return nil, fmt.Errorf("piv: the card's content signing certificate: %w", err)
		}
	}

	eph := opts.EphemeralKey
	if eph == nil {
		if eph, err = s.curve.GenerateKey(rand.Reader); err != nil {
			return nil, err
		}
	}
	if eph.Curve() != s.curve {
		return nil, fmt.Errorf("piv: the ephemeral key is not on cipher suite %02X's curve", s.id)
	}
	idsH := opts.HostID
	if idsH != nil && len(idsH) != 8 {
		return nil, errors.New("piv: a host identifier is 8 bytes")
	}
	if idsH == nil {
		idsH = make([]byte, 8)
		if _, err := rand.Read(idsH); err != nil {
			return nil, err
		}
	}
	qeH := eph.PublicKey().Bytes()
	request := iso7816.EncodeTLV(0x7C, append(
		iso7816.EncodeTLV(0x81, append(append([]byte{0x00}, idsH...), qeH...)),
		iso7816.EncodeTLV(0x82, nil)...))
	resp, err := plainTransmit(card, &iso7816.Command{Cla: 0x00, Ins: 0x87, P1: s.id, P2: keyRefSecureMessaging, Data: request, Le: 256})
	if err != nil {
		return nil, fmt.Errorf("piv: secure messaging key establishment: %w", err)
	}
	outer, err := iso7816.ParseAllTLV(resp)
	if err != nil || len(outer) != 1 || outer[0].Tag != 0x7C {
		return nil, errors.New("piv: key establishment response is not a 7C template")
	}
	inner, err := iso7816.ParseAllTLV(outer[0].Value)
	payload := iso7816.FindTag(inner, 0x82)
	if err != nil || payload == nil || len(payload.Value) < 1+s.nonceLen+16 || payload.Value[0] != 0x00 {
		return nil, errors.New("piv: key establishment response is not CBicc 00, a nonce, a cryptogram and a CVC")
	}
	nICC := payload.Value[1 : 1+s.nonceLen]
	cryptogram := payload.Value[1+s.nonceLen : 1+s.nonceLen+16]
	rawCVC := payload.Value[1+s.nonceLen+16:]

	cvc, err := ParseSecureMessagingCVC(rawCVC)
	if err != nil {
		return nil, err
	}
	if err := verifyCardCVC(cvc, signer, intermediate, s); err != nil {
		return nil, err
	}

	point, err := cvc.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	cardKey, err := s.curve.NewPublicKey(point)
	if err != nil {
		return nil, err
	}
	z, err := eph.ECDH(cardKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(rawCVC)
	idsICC := sum[:8]
	qeOS := qeH[1:]
	otherInfo := concatBytes([]byte{4}, bytes.Repeat([]byte{s.otherInfo}, 4), []byte{8}, idsH, []byte{1, 0},
		[]byte{16}, qeOS[:16], []byte{8}, idsICC, []byte{byte(s.nonceLen)}, nICC, []byte{1, 0})
	var keys []byte
	for counter := uint32(1); len(keys) < 4*s.keyLen; counter++ {
		h := s.hash()
		h.Write(binary.BigEndian.AppendUint32(nil, counter))
		h.Write(z)
		h.Write(otherInfo)
		keys = h.Sum(keys)
	}
	k := s.keyLen
	want, err := aesCMAC(keys[:k], concatBytes([]byte("KC_1_V"), idsICC, idsH, qeOS))
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(want[:16], cryptogram) != 1 {
		return nil, errors.New("piv: the card's key confirmation cryptogram does not verify")
	}
	ch := &SecureChannel{
		inner: card, suite: s, cvc: cvc, intermediate: intermediate, signer: signer, open: true,
		mac: keys[k : 2*k], enc: keys[2*k : 3*k], rmac: keys[3*k : 4*k],
	}
	ch.encCtr[15] = 1
	ch.respCtr[0], ch.respCtr[15] = 0x80, 1
	return ch, nil
}

// verifyCardCVC checks the card's CVC: the card application key's, on the
// suite's curve, and issued by the content signing certificate directly or
// through the intermediate CVC.
func verifyCardCVC(cvc *SecureMessagingCVC, signer *x509.Certificate, intermediate *SecureMessagingCVC, s smSuite) error {
	if cvc.Role != 0x00 || len(cvc.SubjectID) != 16 {
		return errors.New("piv: the card's CVC is not a card application key's")
	}
	if cvc.PublicKey.Curve != s.ecCurve {
		return fmt.Errorf("piv: the card's CVC key is not on cipher suite %02X's curve", s.id)
	}
	if intermediate == nil {
		if err := checkIssuerID(cvc, signer); err != nil {
			return err
		}
		return cvc.verifyWith(signer.PublicKey, s)
	}
	// Content signing certificate -> intermediate CVC -> card CVC.
	if intermediate.Role != 0x12 || len(intermediate.SubjectID) != 8 {
		return errors.New("piv: the intermediate CVC is not a card-application root CVC")
	}
	if err := checkIssuerID(intermediate, signer); err != nil {
		return err
	}
	if err := intermediate.verifyWith(signer.PublicKey, s); err != nil {
		return fmt.Errorf("piv: intermediate CVC: %w", err)
	}
	if !bytes.Equal(cvc.IssuerID, intermediate.SubjectID) {
		return errors.New("piv: the card's CVC was not issued by the intermediate CVC")
	}
	return cvc.verifyWith(intermediate.PublicKey, s)
}

// oidPIVContentSigning is id-PIV-content-signing.
var oidPIVContentSigning = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 6, 7}

// checkContentSigner checks that the certificate in 5FC122 is for what it is
// used for: a PIV content signing certificate, not a CA, whose key may sign.
// A path to the roots is not enough, because any end-entity certificate under
// them, a cardholder's PIV Authentication certificate included, would then do.
func checkContentSigner(cert *x509.Certificate) error {
	if cert.IsCA {
		return errors.New("piv: the card's content signing certificate is a CA certificate")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("piv: the card's content signing certificate does not allow digital signatures")
	}
	for _, usage := range cert.UnknownExtKeyUsage {
		if usage.Equal(oidPIVContentSigning) {
			return nil
		}
	}
	return errors.New("piv: the card's 5FC122 certificate is not a PIV content signing certificate (id-PIV-content-signing)")
}

func checkIssuerID(cvc *SecureMessagingCVC, signer *x509.Certificate) error {
	if len(signer.SubjectKeyId) < 8 || !bytes.Equal(cvc.IssuerID, signer.SubjectKeyId[:8]) {
		return errors.New("piv: the CVC was not issued by the card's content signing certificate")
	}
	return nil
}

// parseSMSignerObject returns the content signing certificate and, when
// present, the intermediate CVC from a 5FC122 response.
func parseSMSignerObject(data []byte) (*x509.Certificate, *SecureMessagingCVC, error) {
	outer, err := iso7816.ParseAllTLV(data)
	if err != nil {
		return nil, nil, fmt.Errorf("piv: 5FC122: %w", err)
	}
	obj := iso7816.FindTag(outer, 0x53)
	if obj == nil {
		return nil, nil, errors.New("piv: 5FC122 is not a 53 data object")
	}
	els, err := iso7816.ParseAllTLV(obj.Value)
	if err != nil {
		return nil, nil, fmt.Errorf("piv: 5FC122: %w", err)
	}
	certTLV := iso7816.FindTag(els, 0x70)
	if certTLV == nil {
		return nil, nil, errors.New("piv: 5FC122 holds no certificate")
	}
	der := certTLV.Value
	if info := iso7816.FindTag(els, 0x71); info != nil && len(info.Value) == 1 && info.Value[0]&0x01 != 0 {
		zr, err := gzip.NewReader(bytes.NewReader(der))
		if err != nil {
			return nil, nil, fmt.Errorf("piv: 5FC122 compressed certificate: %w", err)
		}
		if der, err = io.ReadAll(io.LimitReader(zr, 1<<16)); err != nil {
			return nil, nil, fmt.Errorf("piv: 5FC122 compressed certificate: %w", err)
		}
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("piv: 5FC122 certificate: %w", err)
	}
	var intermediate *SecureMessagingCVC
	if in := iso7816.FindTag(els, 0x7F21); in != nil {
		if intermediate, err = ParseSecureMessagingCVC(iso7816.EncodeTLV(0x7F21, in.Value)); err != nil {
			return nil, nil, fmt.Errorf("piv: 5FC122 intermediate CVC: %w", err)
		}
	}
	return cert, intermediate, nil
}

// CVC returns the card's CVC, which the channel checked.
func (s *SecureChannel) CVC() *SecureMessagingCVC { return s.cvc }

// GUID returns the card GUID the CVC certifies.
func (s *SecureChannel) GUID() []byte { return append([]byte(nil), s.cvc.SubjectID...) }

// ContentSigner returns the content signing certificate the card presented.
func (s *SecureChannel) ContentSigner() *x509.Certificate { return s.signer }

// CipherSuite returns the session's cipher suite.
func (s *SecureChannel) CipherSuite() byte { return s.suite.id }

// Begin, End and Close pass through to the card.
func (s *SecureChannel) Begin() error { return s.inner.Begin() }
func (s *SecureChannel) End() error   { return s.inner.End() }
func (s *SecureChannel) Close() error {
	s.open = false
	return s.inner.Close()
}

// Transmit protects a command, sends it and returns the card's plaintext
// response with its status word.
func (s *SecureChannel) Transmit(command []byte) ([]byte, error) {
	if !s.open {
		return nil, ErrSecureMessagingClosed
	}
	cmd, err := iso7816.ParseCommand(command)
	if err != nil {
		return nil, err
	}
	if cmd.Ins == 0xA4 {
		return nil, errors.New("piv: SELECT ends secure messaging; send it outside the session")
	}
	// A command the caller chains is protected whole, once its last block
	// arrives, and sent with transport chaining below.
	if cmd.Cla&0x10 != 0 {
		s.chained = append(s.chained, cmd.Data...)
		return []byte{0x90, 0x00}, nil
	}
	if s.chained != nil {
		cmd.Data = append(s.chained, cmd.Data...)
		s.chained = nil
	}
	var objects []byte
	iv := s.iv(s.encCtr)
	if len(cmd.Data) > 0 {
		block, _ := aes.NewCipher(s.enc)
		padded := pad80(cmd.Data)
		ct := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
		objects = iso7816.EncodeTLV(0x87, append([]byte{0x01}, ct...))
	}
	// The expected length travels protected in 97, as OpenSC sends it.
	if cmd.Le > 0 {
		objects = append(objects, 0x97, 0x01, byte(cmd.Le))
	}
	header := append([]byte{0x0C, cmd.Ins, cmd.P1, cmd.P2, 0x80}, make([]byte, 11)...)
	mac, err := aesCMAC(s.mac, concatBytes(s.cMCV[:], header, objects))
	if err != nil {
		return nil, err
	}
	copy(s.cMCV[:], mac)
	increment(&s.encCtr)
	body := concatBytes(objects, iso7816.EncodeTLV(0x8E, mac[:8]))
	// PIV cards must support command chaining, not extended length, so a
	// long protected command goes in blocks with CLA 1C before the last.
	const block = 0xFF
	for len(body) > block {
		raw, err := plainTransmitRaw(s.inner, &iso7816.Command{Cla: 0x1C, Ins: cmd.Ins, P1: cmd.P1, P2: cmd.P2, Data: body[:block], Le: -1})
		if err != nil {
			s.open = false
			return nil, err
		}
		if raw.StatusWord() != 0x9000 {
			s.open = false
			return nil, fmt.Errorf("piv: the card refused a chained secure messaging block with %04X, which is not authenticated; the session has ended", raw.StatusWord())
		}
		body = body[block:]
	}
	raw, err := plainTransmitRaw(s.inner, &iso7816.Command{Cla: 0x0C, Ins: cmd.Ins, P1: cmd.P1, P2: cmd.P2, Data: body, Le: 256})
	if err != nil {
		s.open = false
		return nil, err
	}
	if raw.StatusWord() != 0x9000 {
		// A status word outside 99 is not MAC-protected, so it cannot be
		// passed on as the card's answer: anyone on the link could have
		// written it. The card ends the session after one, too.
		s.open = false
		return nil, fmt.Errorf("piv: the card answered %04X outside secure messaging, which is not authenticated; the session has ended", raw.StatusWord())
	}
	plain, sw, err := s.unwrap(raw.Data)
	if err != nil {
		s.open = false
		return nil, err
	}
	return append(plain, byte(sw>>8), byte(sw)), nil
}

func (s *SecureChannel) unwrap(resp []byte) ([]byte, uint16, error) {
	els, err := iso7816.ParseAllTLV(resp)
	if err != nil || len(els) < 2 || els[len(els)-1].Tag != 0x8E || len(els[len(els)-1].Value) != 8 {
		return nil, 0, errors.New("piv: the secure messaging response has no MAC")
	}
	mac, err := aesCMAC(s.rmac, concatBytes(s.rMCV[:], resp[:len(resp)-10]))
	if err != nil {
		return nil, 0, err
	}
	if subtle.ConstantTimeCompare(mac[:8], els[len(els)-1].Value) != 1 {
		return nil, 0, errors.New("piv: the secure messaging response MAC does not verify")
	}
	copy(s.rMCV[:], mac)
	iv := s.iv(s.respCtr)
	increment(&s.respCtr)
	status := iso7816.FindTag(els, 0x99)
	if status == nil || len(status.Value) != 2 {
		return nil, 0, errors.New("piv: the secure messaging response has no status word")
	}
	var plain []byte
	if enc := iso7816.FindTag(els, 0x87); enc != nil {
		if len(enc.Value) < 17 || enc.Value[0] != 0x01 || (len(enc.Value)-1)%aes.BlockSize != 0 {
			return nil, 0, errors.New("piv: the secure messaging response's encrypted data is malformed")
		}
		block, _ := aes.NewCipher(s.enc)
		plain = make([]byte, len(enc.Value)-1)
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, enc.Value[1:])
		i := len(plain) - 1
		for i >= 0 && plain[i] == 0x00 {
			i--
		}
		if i < 0 || plain[i] != 0x80 {
			return nil, 0, errors.New("piv: the secure messaging response's padding is wrong")
		}
		plain = plain[:i]
	}
	return plain, binary.BigEndian.Uint16(status.Value), nil
}

func (s *SecureChannel) iv(counter [16]byte) []byte {
	block, _ := aes.NewCipher(s.enc)
	out := make([]byte, aes.BlockSize)
	block.Encrypt(out, counter[:])
	return out
}

// VerifyPairingCode activates the virtual contact interface (key reference
// 98). The card accepts it only under secure messaging, so c must be a Client
// built on a SecureChannel.
func (c *Client) VerifyPairingCode(code string) error {
	if len(code) != 8 {
		return errors.New("piv: a pairing code is eight digits")
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return errors.New("piv: a pairing code is eight digits")
		}
	}
	resp, err := c.sendCommand(&iso7816.Command{Cla: 0x00, Ins: 0x20, P1: 0x00, P2: keyRefPairingCode, Data: []byte(code), Le: -1})
	if err != nil {
		return fmt.Errorf("piv: verify pairing code: %w", err)
	}
	if err := resp.Err(); err != nil {
		return fmt.Errorf("piv: verify pairing code: %w", err)
	}
	return nil
}

// plainTransmit sends a command outside secure messaging, collecting a
// chained response, and returns the data of a 9000 response.
func plainTransmit(card Card, cmd *iso7816.Command) ([]byte, error) {
	resp, err := plainTransmitRaw(card, cmd)
	if err != nil {
		return nil, err
	}
	if err := resp.Err(); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func plainTransmitRaw(card Card, cmd *iso7816.Command) (*iso7816.Response, error) {
	raw, err := card.Transmit(cmd.Bytes())
	if err != nil {
		return nil, err
	}
	resp, err := iso7816.ParseResponse(raw)
	if err != nil {
		return nil, err
	}
	data := resp.Data
	for resp.HasMoreData() {
		le := int(resp.SW2)
		if le == 0 {
			le = 256
		}
		raw, err = card.Transmit((&iso7816.Command{Cla: 0x00, Ins: 0xC0, Le: le}).Bytes())
		if err != nil {
			return nil, err
		}
		if resp, err = iso7816.ParseResponse(raw); err != nil {
			return nil, err
		}
		data = append(data, resp.Data...)
	}
	resp.Data = data
	return resp, nil
}

func pad80(data []byte) []byte {
	out := append(append([]byte{}, data...), 0x80)
	for len(out)%aes.BlockSize != 0 {
		out = append(out, 0x00)
	}
	return out
}

func increment(counter *[16]byte) {
	for i := 15; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			return
		}
	}
}

func concatBytes(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func oidContents(oid asn1.ObjectIdentifier) []byte {
	der, _ := asn1.Marshal(oid)
	return der[2:]
}

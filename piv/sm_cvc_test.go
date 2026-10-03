package piv

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/piv-go/iso7816"
)

// cvcFields is a Table 15 or 16 CVC to build in a test.
type cvcFields struct {
	issuerID, subjectID []byte
	key                 *ecdsa.PublicKey
	role                byte
	longLengths         bool // encode the body's lengths in the 81 form
}

func buildCVC(t *testing.T, f cvcFields, signer *ecdsa.PrivateKey, suite byte) []byte {
	t.Helper()
	s := smSuites[suite]
	enc := func(tag uint, v []byte) []byte {
		if f.longLengths && len(v) < 0x80 {
			return append(append(iso7816.EncodeTag(tag), 0x81, byte(len(v))), v...)
		}
		return iso7816.EncodeTLV(tag, v)
	}
	point, _ := f.key.Bytes()
	var curveOID asn1.ObjectIdentifier
	if f.key.Curve == elliptic.P384() {
		curveOID = smSuites[SMCipherSuite7].curveOID
	} else {
		curveOID = smSuites[SMCipherSuite2].curveOID
	}
	body := concatBytes(enc(0x5F29, []byte{0x80}), enc(0x42, f.issuerID), enc(0x5F20, f.subjectID),
		enc(0x7F49, concatBytes(iso7816.EncodeTLV(0x06, oidContents(curveOID)), iso7816.EncodeTLV(0x86, point))),
		enc(0x5F4C, []byte{f.role}))
	h := s.hash()
	h.Write(body)
	sig, err := ecdsa.SignASN1(rand.Reader, signer, h.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	ds, _ := asn1.Marshal(struct {
		Alg struct{ Algorithm asn1.ObjectIdentifier }
		Sig asn1.BitString
	}{struct{ Algorithm asn1.ObjectIdentifier }{s.sigOID}, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	return iso7816.EncodeTLV(0x7F21, concatBytes(body, iso7816.EncodeTLV(0x5F37, ds)))
}

func contentSigningCert(t *testing.T, key *ecdsa.PrivateKey, edit func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "signer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, SubjectKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidPIVContentSigning},
	}
	if edit != nil {
		edit(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func parseCVC(t *testing.T, raw []byte) *SecureMessagingCVC {
	t.Helper()
	c, err := ParseSecureMessagingCVC(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestVerifyCardCVC(t *testing.T) {
	signerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer := contentSigningCert(t, signerKey, nil)
	cardKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	guid := bytes.Repeat([]byte{0x5a}, 16)
	ski := signer.SubjectKeyId[:8]
	s := smSuites[SMCipherSuite2]
	good := cvcFields{issuerID: ski, subjectID: guid, key: &cardKey.PublicKey}

	if err := verifyCardCVC(parseCVC(t, buildCVC(t, good, signerKey, SMCipherSuite2)), signer, nil, s); err != nil {
		t.Fatalf("a good CVC: %v", err)
	}
	// The signed body is the bytes as sent, so a long length form verifies.
	long := good
	long.longLengths = true
	if err := verifyCardCVC(parseCVC(t, buildCVC(t, long, signerKey, SMCipherSuite2)), signer, nil, s); err != nil {
		t.Fatalf("a CVC with 81 lengths: %v", err)
	}

	for _, tc := range []struct {
		name string
		f    func(cvcFields) cvcFields
		want string
	}{
		{"another issuer ID, same key", func(f cvcFields) cvcFields { f.issuerID = []byte{9, 9, 9, 9, 9, 9, 9, 9}; return f }, "not issued by"},
		{"an intermediate's role", func(f cvcFields) cvcFields { f.role = 0x12; return f }, "card application key"},
		{"an 8-byte subject", func(f cvcFields) cvcFields { f.subjectID = guid[:8]; return f }, "card application key"},
		{"a P-384 key on suite 27", func(f cvcFields) cvcFields { f.key = &p384.PublicKey; return f }, "curve"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cvc := parseCVC(t, buildCVC(t, tc.f(good), signerKey, SMCipherSuite2))
			if err := verifyCardCVC(cvc, signer, nil, s); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("verifyCardCVC = %v, want %q", err, tc.want)
			}
		})
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := verifyCardCVC(parseCVC(t, buildCVC(t, good, other, SMCipherSuite2)), signer, nil, s); err == nil {
		t.Error("a CVC signed by another key verified")
	}
	// The suite's hash, not the signer curve's: a SHA-384 signature fails
	// on suite 27.
	badHash := parseCVC(t, buildCVC(t, good, signerKey, SMCipherSuite7))
	if err := verifyCardCVC(badHash, signer, nil, s); err == nil {
		t.Error("a CVC signed for suite 2E verified on suite 27")
	}
}

func TestVerifyCardCVCThroughAnIntermediate(t *testing.T) {
	signerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer := contentSigningCert(t, signerKey, nil)
	inKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cardKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := smSuites[SMCipherSuite2]
	inID := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	intermediate := parseCVC(t, buildCVC(t, cvcFields{issuerID: signer.SubjectKeyId[:8], subjectID: inID, key: &inKey.PublicKey, role: 0x12}, signerKey, SMCipherSuite2))
	card := parseCVC(t, buildCVC(t, cvcFields{issuerID: inID, subjectID: bytes.Repeat([]byte{1}, 16), key: &cardKey.PublicKey}, inKey, SMCipherSuite2))
	if err := verifyCardCVC(card, signer, intermediate, s); err != nil {
		t.Fatalf("certificate -> intermediate -> card: %v", err)
	}
	// The card CVC must name the intermediate, and the intermediate must be
	// signed by the certificate.
	direct := parseCVC(t, buildCVC(t, cvcFields{issuerID: signer.SubjectKeyId[:8], subjectID: bytes.Repeat([]byte{1}, 16), key: &cardKey.PublicKey}, inKey, SMCipherSuite2))
	if err := verifyCardCVC(direct, signer, intermediate, s); err == nil {
		t.Error("a card CVC that does not name the intermediate verified")
	}
	stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forged := parseCVC(t, buildCVC(t, cvcFields{issuerID: signer.SubjectKeyId[:8], subjectID: inID, key: &inKey.PublicKey, role: 0x12}, stranger, SMCipherSuite2))
	if err := verifyCardCVC(card, signer, forged, s); err == nil {
		t.Error("an intermediate the certificate did not sign was trusted")
	}
	notRoot := parseCVC(t, buildCVC(t, cvcFields{issuerID: signer.SubjectKeyId[:8], subjectID: bytes.Repeat([]byte{2}, 16), key: &inKey.PublicKey}, signerKey, SMCipherSuite2))
	if err := verifyCardCVC(card, signer, notRoot, s); err == nil {
		t.Error("a card application CVC was used as an intermediate")
	}
}

func TestContentSignerMustBeOne(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := checkContentSigner(contentSigningCert(t, key, nil)); err != nil {
		t.Fatalf("a content signing certificate: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*x509.Certificate)
	}{
		{"a PIV Authentication certificate", func(c *x509.Certificate) {
			c.UnknownExtKeyUsage = nil
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}},
		{"a CA", func(c *x509.Certificate) {
			c.IsCA, c.BasicConstraintsValid, c.KeyUsage = true, true, x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature
		}},
		{"a key agreement certificate", func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyAgreement }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkContentSigner(contentSigningCert(t, key, tc.edit)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// recordingCard answers every command with one response and keeps the
// commands.
type recordingCard struct {
	commands [][]byte
	answer   []byte
}

func (r *recordingCard) Transmit(c []byte) ([]byte, error) {
	r.commands = append(r.commands, append([]byte(nil), c...))
	return r.answer, nil
}
func (r *recordingCard) Begin() error { return nil }
func (r *recordingCard) End() error   { return nil }
func (r *recordingCard) Close() error { return nil }

func openTestChannel(inner Card) *SecureChannel {
	key := bytes.Repeat([]byte{0x42}, 16)
	ch := &SecureChannel{inner: inner, suite: smSuites[SMCipherSuite2], mac: key, enc: key, rmac: key, open: true}
	ch.encCtr[15] = 1
	ch.respCtr[0], ch.respCtr[15] = 0x80, 1
	return ch
}

func TestAnUnprotectedStatusWordIsNotTheCards(t *testing.T) {
	card := &recordingCard{answer: []byte{0x63, 0xC0}}
	ch := openTestChannel(card)
	resp, err := ch.Transmit([]byte{0x00, 0x20, 0x00, 0x80, 0x08, '1', '2', '3', '4', '5', '6', 0xFF, 0xFF})
	if err == nil || resp != nil || !strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("an unprotected 63C0 = %X, %v", resp, err)
	}
	if _, err := ch.Transmit([]byte{0x00, 0x20, 0x00, 0x80}); err != ErrSecureMessagingClosed {
		t.Fatalf("after an unprotected status word = %v", err)
	}
}

func TestALongProtectedCommandIsChained(t *testing.T) {
	card := &recordingCard{answer: []byte{0x90, 0x00}}
	ch := openTestChannel(card)
	data := bytes.Repeat([]byte{0xAB}, 600)
	cmd := (&iso7816.Command{Cla: 0x00, Ins: 0xDB, P1: 0x3F, P2: 0xFF, Data: data, Le: -1}).Bytes()
	_, _ = ch.Transmit(cmd) // the last answer is not a protected response
	if len(card.commands) < 3 {
		t.Fatalf("%d commands for a 600-byte command", len(card.commands))
	}
	for i, c := range card.commands {
		last := i == len(card.commands)-1
		if (c[0] == 0x1C) == last || (!last && (c[4] != 0xFF || len(c) != 5+0xFF)) {
			t.Fatalf("block %d: %X", i, c[:5])
		}
		if c[4] == 0x00 && len(c) > 5 && c[5] != 0x00 {
			t.Fatalf("block %d uses extended length", i)
		}
	}
	// 97 carries Le, and is MAC-protected.
	card2 := &recordingCard{answer: []byte{0x90, 0x00}}
	ch2 := openTestChannel(card2)
	_, _ = ch2.Transmit((&iso7816.Command{Cla: 0x00, Ins: 0xCB, P1: 0x3F, P2: 0xFF, Data: []byte{0x5C, 0x01, 0x7E}, Le: 256}).Bytes())
	if !bytes.Contains(card2.commands[0], []byte{0x97, 0x01, 0x00, 0x8E, 0x08}) {
		t.Fatalf("no 97 before the MAC: %X", card2.commands[0])
	}
}

var _ crypto.Signer = (*ecdsa.PrivateKey)(nil)

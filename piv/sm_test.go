package piv

import (
	"bytes"
	"crypto/ecdh"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PeculiarVentures/piv-go/iso7816"
)

// The transcript is a real session between goodpiv, a PIV card that
// implements secure messaging and is tested against OpenSC's host, and this
// client. Its CVC was issued by goodkey-ca under a test root. Replaying it
// checks every byte this client sends against what that card accepted:
// key establishment, the KDF, the key confirmation, and the encryption and
// MAC chaining of each command and response.
type transcript struct {
	Root         string `json:"root"`
	EphemeralKey string `json:"ephemeralKey"`
	HostID       string `json:"hostID"`
	PairingCode  string `json:"pairingCode"`
	PIN          string `json:"pin"`
	GUID         string `json:"guid"`
	RecordedAt   string `json:"recordedAt"`
	Exchanges    []struct {
		Command  string `json:"command"`
		Response string `json:"response"`
	} `json:"exchanges"`
}

func loadTranscript(t *testing.T) transcript {
	t.Helper()
	raw, err := os.ReadFile("testdata/sm-goodpiv-cs27.json")
	if err != nil {
		t.Fatal(err)
	}
	var tr transcript
	if err := json.Unmarshal(raw, &tr); err != nil {
		t.Fatal(err)
	}
	return tr
}

// replayCard answers each command with the recorded response, and fails the
// test if a command differs from the recorded one.
type replayCard struct {
	t      *testing.T
	tr     transcript
	next   int
	tamper func(i int, resp []byte) []byte
}

func (r *replayCard) Transmit(command []byte) ([]byte, error) {
	r.t.Helper()
	if r.next >= len(r.tr.Exchanges) {
		r.t.Fatalf("command %X after the transcript ended", command)
	}
	e := r.tr.Exchanges[r.next]
	want, _ := hex.DecodeString(e.Command)
	if !bytes.Equal(command, want) {
		r.t.Fatalf("command %d\n got %X\nwant %X", r.next, command, want)
	}
	resp, _ := hex.DecodeString(e.Response)
	if r.tamper != nil {
		resp = r.tamper(r.next, resp)
	}
	r.next++
	return resp, nil
}
func (r *replayCard) Begin() error { return nil }
func (r *replayCard) End() error   { return nil }
func (r *replayCard) Close() error { return nil }

func (tr transcript) options(t *testing.T) SecureMessagingOptions {
	t.Helper()
	rootDER, _ := hex.DecodeString(tr.Root)
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	ephBytes, _ := hex.DecodeString(tr.EphemeralKey)
	eph, err := ecdh.P256().NewPrivateKey(ephBytes)
	if err != nil {
		t.Fatal(err)
	}
	hostID, _ := hex.DecodeString(tr.HostID)
	at, err := time.Parse(time.RFC3339, tr.RecordedAt)
	if err != nil {
		t.Fatal(err)
	}
	return SecureMessagingOptions{Roots: roots, CurrentTime: at, EphemeralKey: eph, HostID: hostID}
}

func TestSecureMessagingReplaysAgainstGoodpiv(t *testing.T) {
	tr := loadTranscript(t)
	card := &replayCard{t: t, tr: tr}
	if err := NewClient(card).Select(); err != nil {
		t.Fatal(err)
	}
	ch, err := OpenSecureMessaging(card, tr.options(t))
	if err != nil {
		t.Fatalf("OpenSecureMessaging: %v", err)
	}
	if hex.EncodeToString(ch.GUID()) != tr.GUID || ch.CipherSuite() != SMCipherSuite2 {
		t.Fatalf("session GUID %X, suite %02X", ch.GUID(), ch.CipherSuite())
	}
	sm := NewClient(ch)
	if err := sm.VerifyPairingCode(tr.PairingCode); err != nil {
		t.Fatalf("pairing code: %v", err)
	}
	if err := sm.VerifyPIN(tr.PIN); err != nil {
		t.Fatalf("PIN: %v", err)
	}
	guid, _ := hex.DecodeString(tr.GUID)
	if chuid, err := sm.GetData(0x5FC102); err != nil || !bytes.Contains(chuid, guid) {
		t.Fatalf("CHUID: %X, %v", chuid, err)
	}
	if signer, err := sm.GetData(0x5FC122); err != nil || !bytes.Contains(signer, ch.ContentSigner().Raw) {
		t.Fatalf("5FC122 over secure messaging: %v", err)
	}
	// A long command goes as chained protected blocks (CLA 1C), and a long
	// answer comes back through GET RESPONSE.
	if err := sm.AuthenticateManagementKeyWithAlgorithm(0x0A, []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		t.Fatalf("management key: %v", err)
	}
	big := bytes.Repeat([]byte("goodkey "), 120)
	if err := sm.PutData(0x5FC10D, iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x70, big))); err != nil {
		t.Fatalf("960-byte PUT DATA: %v", err)
	}
	if got, err := sm.GetData(0x5FC10D); err != nil || !bytes.Contains(got, big) {
		t.Fatalf("reading it back: %v", err)
	}
	chained := 0
	for _, e := range tr.Exchanges {
		if strings.HasPrefix(e.Command, "1cdb3fff") {
			chained++
		}
	}
	if chained < 3 {
		t.Fatalf("%d chained protected blocks in the transcript", chained)
	}
	// The wrong PIN's status word comes back through the MAC-protected 99.
	if err := sm.VerifyPIN("654321"); err == nil || !strings.Contains(err.Error(), "retries") {
		t.Fatalf("wrong PIN = %v", err)
	}
	if card.next != len(tr.Exchanges) {
		t.Fatalf("replayed %d of %d exchanges", card.next, len(tr.Exchanges))
	}
}

func TestSecureMessagingRefusesAnUntrustedCard(t *testing.T) {
	tr := loadTranscript(t)
	opts := tr.options(t)
	opts.Roots = x509.NewCertPool()
	card := &replayCard{t: t, tr: tr}
	_ = NewClient(card).Select()
	if _, err := OpenSecureMessaging(card, opts); err == nil || !strings.Contains(err.Error(), "content signing certificate") {
		t.Fatalf("OpenSecureMessaging with no trusted root = %v", err)
	}

	opts.Roots = nil
	if _, err := OpenSecureMessaging(&replayCard{t: t, tr: tr, next: 1}, opts); err == nil || !strings.Contains(err.Error(), "Roots") {
		t.Fatalf("OpenSecureMessaging without roots = %v", err)
	}
}

func TestSecureMessagingRefusesAForgedCard(t *testing.T) {
	tr := loadTranscript(t)
	for _, tc := range []struct {
		name   string
		at     int // exchange whose response is changed
		change func([]byte) []byte
		want   string
	}{
		{"a changed CVC", 3, func(r []byte) []byte {
			// The last bytes before 9000 are the CVC's signature.
			r[len(r)-4] ^= 1
			return r
		}, "signature"},
		{"a changed key confirmation", 3, func(r []byte) []byte {
			r[30] ^= 1
			return r
		}, "cryptogram"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			card := &replayCard{t: t, tr: tr, next: 1, tamper: func(i int, r []byte) []byte {
				if i == tc.at {
					return tc.change(r)
				}
				return r
			}}
			if _, err := OpenSecureMessaging(card, tr.options(t)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("OpenSecureMessaging = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSecureMessagingEndsOnABadResponseMAC(t *testing.T) {
	tr := loadTranscript(t)
	card := &replayCard{t: t, tr: tr, next: 1, tamper: func(i int, r []byte) []byte {
		if i == 4 { // the pairing code's response
			r[len(r)-3] ^= 1
		}
		return r
	}}
	ch, err := OpenSecureMessaging(card, tr.options(t))
	if err != nil {
		t.Fatal(err)
	}
	sm := NewClient(ch)
	if err := sm.VerifyPairingCode(tr.PairingCode); err == nil || !strings.Contains(err.Error(), "MAC") {
		t.Fatalf("a response with a bad MAC = %v", err)
	}
	if _, err := ch.Transmit([]byte{0x00, 0x20, 0x00, 0x80}); !errors.Is(err, ErrSecureMessagingClosed) {
		t.Fatalf("a command after a bad MAC = %v", err)
	}
}

func TestSecureMessagingCommandLimits(t *testing.T) {
	ch := &SecureChannel{open: true}
	if _, err := ch.Transmit([]byte{0x00, 0xA4, 0x04, 0x00, 0x01, 0xA0}); err == nil {
		t.Error("SELECT was sent under secure messaging")
	}
	// A block the caller chains is held and protected with the rest.
	if resp, err := ch.Transmit([]byte{0x10, 0xDB, 0x3F, 0xFF, 0x01, 0x00}); err != nil || !bytes.Equal(resp, []byte{0x90, 0x00}) || len(ch.chained) != 1 {
		t.Errorf("a chained block = %X, %v; held %X", resp, err, ch.chained)
	}
	if err := NewClient(ch).VerifyPairingCode("1234"); err == nil {
		t.Error("a 4-digit pairing code was sent")
	}
	if _, err := OpenSecureMessaging(nil, SecureMessagingOptions{CipherSuite: 0x11, InsecureSkipSignerVerification: true}); err == nil {
		t.Error("an unknown cipher suite was accepted")
	}
}

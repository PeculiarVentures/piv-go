package main

import (
	"bytes"
	"crypto/elliptic"
	"errors"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/emulator"
	internalutil "github.com/PeculiarVentures/piv-go/internal"
	"github.com/PeculiarVentures/piv-go/internal/cli/app"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// neoCLIProfile returns a YubiKey NEO-profile card: SELECT works, GET
// METADATA (0xF7) is unstubbed (6D00), and GET DATA serves the given slot
// object bytes (nil clears the slot to 6A82).
func neoCLIProfile(t *testing.T, object []byte) func() piv.Card {
	t.Helper()
	return func() piv.Card {
		card := emulator.NewCard()
		card.RegisterINSHandler(0xA4, func(_ *emulator.Card, _ []byte) ([]byte, error) {
			return emulator.BuildSuccessResponse(nil), nil
		})
		card.RegisterINSHandler(0xCB, func(_ *emulator.Card, _ []byte) ([]byte, error) {
			if object == nil {
				return emulator.BuildResponse(nil, uint16(iso7816.SwFileNotFound)), nil
			}
			return emulator.BuildSuccessResponse(object), nil
		})
		return card
	}
}

func neoP256Object(t *testing.T) []byte {
	t.Helper()
	point := internalutil.MustEncodeUncompressedPoint(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	return iso7816.EncodeTLV(0x53, iso7816.EncodeTLV(0x7F49, iso7816.EncodeTLV(0x86, point)))
}

func neoCLITargets(profile func() piv.Card) *app.TargetResolver {
	return app.NewTargetResolver(fakeCardContextFactory{
		builders: map[string]func() piv.Card{
			"YubiKey NEO CLI": profile,
		},
	}, nil, bytes.NewReader(nil), &bytes.Buffer{})
}

func exitCodeOf(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		t.Fatal("expected exit error, got nil")
	}
	var exitErr *app.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected ExitError, got %T (%v)", err, err)
	}
	return exitErr.Code
}

// PEM output must go to stdout alone while the trace goes to stderr: the
// artifact stays pipe-clean with --trace all.
func TestNEOKeyPublicPEMAndTraceDoNotMix(t *testing.T) {
	cli, stdout, stderr := newTestCLI(t, neoCLITargets(neoCLIProfile(t, neoP256Object(t))), bytes.NewReader(nil))
	if err := executeCLI(cli, "key", "public", "9c", "--trace", "all"); err != nil {
		t.Fatalf("key public: %v", err)
	}
	out := stdout.String()
	if !strings.HasPrefix(out, "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("stdout must be bare PEM, got %q", out)
	}
	if strings.Contains(out, "APDU") {
		t.Fatalf("stdout must not contain trace lines, got %q", out)
	}
	if !strings.Contains(stderr.String(), "APDU") {
		t.Fatalf("stderr must carry the trace, got %q", stderr.String())
	}
}

// Failures must still emit the collected trace to stderr (never stdout)
// alongside the rendered error.
func TestNEOKeyPublicFailureWritesTraceToStderr(t *testing.T) {
	cli, stdout, stderr := newTestCLI(t, neoCLITargets(neoCLIProfile(t, nil)), bytes.NewReader(nil))
	err := executeCLI(cli, "key", "public", "9c", "--trace", "all")
	if code := exitCodeOf(t, err); code != 5 {
		t.Fatalf("exit code = %d, want 5", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout must stay empty on failure, got %q", stdout.String())
	}
	diagnostics := stderr.String()
	for _, want := range []string{
		"Error: the requested public key is not present",
		"Hint: inspect slot state with piv slot show <slot>",
		"APDU",
	} {
		if !strings.Contains(diagnostics, want) {
			t.Fatalf("stderr must contain %q, got %q", want, diagnostics)
		}
	}
}

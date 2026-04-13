package iso7816

import (
	"errors"
	"fmt"
	"testing"
)

func TestStatusError(t *testing.T) {
	err := StatusError(SwFileNotFound)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "iso7816: status 6A82: file not found" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStatusError_Unknown(t *testing.T) {
	err := StatusError(0x1234)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestStatusWordFromError_UnwrapsWrappedStatus(t *testing.T) {
	err := fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", StatusError(SwReferencedDataNotFound)))

	status, ok := StatusWordFromError(err)
	if !ok {
		t.Fatal("expected wrapped status to be extracted")
	}
	if status != SwReferencedDataNotFound {
		t.Fatalf("expected status %04X, got %04X", SwReferencedDataNotFound, status)
	}
}

func TestStatusWordFromError_RejectsNonStatusError(t *testing.T) {
	if _, ok := StatusWordFromError(errors.New("boom")); ok {
		t.Fatal("expected non-status error to return ok=false")
	}
}

func TestIsStatus_MatchesWrappedStatus(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", StatusError(SwInsNotSupported))
	if !IsStatus(err, SwInsNotSupported) {
		t.Fatal("expected wrapped status to match")
	}
}

func TestIsPINRetryStatus(t *testing.T) {
	retries, ok := IsPINRetryStatus(0x63C3)
	if !ok {
		t.Fatal("expected PIN retry status")
	}
	if retries != 3 {
		t.Errorf("expected 3 retries, got %d", retries)
	}
}

func TestIsPINRetryStatus_NotPIN(t *testing.T) {
	_, ok := IsPINRetryStatus(0x9000)
	if ok {
		t.Fatal("expected not a PIN retry status")
	}
}

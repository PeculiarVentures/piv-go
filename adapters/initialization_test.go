package adapters

import (
	"strings"
	"testing"
	"time"
)

func TestInitializeTokenParamsValidateAcceptsMeaningfulRequests(t *testing.T) {
	tests := []struct {
		name   string
		params InitializeTokenParams
	}{
		{
			name:   "clear containers",
			params: InitializeTokenParams{ClearContainers: true},
		},
		{
			name:   "provision identity",
			params: InitializeTokenParams{ProvisionIdentity: true},
		},
		{
			name: "both operations with seed time",
			params: InitializeTokenParams{
				ClearContainers:   true,
				ProvisionIdentity: true,
				InitializedAt:     time.Date(2026, time.April, 1, 11, 50, 43, 0, time.UTC),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.params.Validate(); err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestInitializeTokenParamsValidateRejectsNoOperations(t *testing.T) {
	err := (InitializeTokenParams{}).Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "at least one enabled operation") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitializeTokenParamsValidateRejectsInitializedAtWithoutIdentity(t *testing.T) {
	err := (InitializeTokenParams{
		ClearContainers: true,
		InitializedAt:   time.Date(2026, time.April, 1, 11, 50, 43, 0, time.UTC),
	}).Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "InitializedAt requires ProvisionIdentity") {
		t.Fatalf("unexpected error: %v", err)
	}
}

package yubikey

import (
	"errors"
	"fmt"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters"
	"github.com/PeculiarVentures/piv-go/adapters/admin"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
)

func assertNoResetMutation(t *testing.T, card *emulator.Card) {
	t.Helper()
	for _, raw := range card.TransmittedCommands {
		cmd, err := iso7816.ParseCommand(raw)
		if err != nil {
			t.Fatal(err)
		}
		if cmd.Ins == 0xFB || cmd.Ins == 0x2C || (cmd.Ins == 0x20 && len(cmd.Data) > 0) {
			t.Fatalf("preflight failure must not mutate credentials or reset: %X", raw)
		}
	}
}

func TestResetRejectsBioBeforeBlockingCredentials(t *testing.T) {
	for _, configured := range []byte{0, 1} {
		t.Run(fmt.Sprintf("configured=%d", configured), func(t *testing.T) {
			card := emulator.NewCard()
			card.SetSuccessResponse(0xF7, []byte{7, 1, configured, 6, 1, 3, 8, 1, 0})
			err := admin.ResetToken(adapters.NewRuntime(newSlotDescriptionSession(card), NewAdapter()), adapters.ResetTokenParams{})
			if err == nil {
				t.Fatal("Bio PIV reset must be refused")
			}
			assertNoResetMutation(t, card)
			if len(card.TransmittedCommands) != 1 || card.TransmittedCommands[0][3] != 0x96 {
				t.Fatalf("Bio check must be first: %X", card.TransmittedCommands)
			}
		})
	}
}

func TestResetPreflightFailuresDoNotBlockCredentials(t *testing.T) {
	transportErr := errors.New("transport failure")
	for _, ref := range []byte{0x96, 0x80, 0x81} {
		for _, tc := range []struct {
			name string
			data []byte
			sw   uint16
			err  error
		}{
			{name: "transport", err: transportErr},
			{name: "security", sw: iso7816.SwSecurityNotSatisfied},
			{name: "malformed", data: []byte{1}, sw: iso7816.SwSuccess},
		} {
			t.Run(fmt.Sprintf("ref=%02X/%s", ref, tc.name), func(t *testing.T) {
				card := emulator.NewCard()
				card.RegisterINSHandler(0xF7, func(_ *emulator.Card, raw []byte) ([]byte, error) {
					if raw[3] == ref {
						return emulator.BuildResponse(tc.data, tc.sw), tc.err
					}
					if raw[3] == 0x96 {
						return emulator.BuildResponse(nil, iso7816.SwReferencedDataNotFound), nil
					}
					return emulator.BuildSuccessResponse(encodePINMetadataTLV(3, 3, false)), nil
				})
				err := admin.ResetToken(adapters.NewRuntime(newSlotDescriptionSession(card), NewAdapter()), adapters.ResetTokenParams{})
				if err == nil {
					t.Fatal("preflight failure ignored")
				}
				if tc.err != nil && !errors.Is(err, tc.err) {
					t.Fatalf("lost transport cause: %v", err)
				}
				assertNoResetMutation(t, card)
			})
		}
	}
}

func TestResetWithAlreadyVerifiedPINWithoutMetadata(t *testing.T) {
	card := emulator.NewCard()
	pin, puk, pinAttempts, pukAttempts, resets := 3, 3, 0, 0, 0
	card.RegisterINSHandler(0x20, func(_ *emulator.Card, raw []byte) ([]byte, error) {
		cmd, err := iso7816.ParseCommand(raw)
		if err != nil {
			return nil, err
		}
		if len(cmd.Data) == 0 {
			return emulator.BuildSuccessResponse(nil), nil
		}
		pinAttempts++
		if pin > 0 {
			pin--
		}
		if pin == 0 {
			return emulator.BuildResponse(nil, iso7816.SwAuthBlocked), nil
		}
		return emulator.BuildResponse(nil, 0x63c0|uint16(pin)), nil
	})
	card.RegisterINSHandler(0x2C, func(_ *emulator.Card, _ []byte) ([]byte, error) {
		pukAttempts++
		if puk > 0 {
			puk--
		}
		if puk == 0 {
			return emulator.BuildResponse(nil, iso7816.SwAuthBlocked), nil
		}
		return emulator.BuildResponse(nil, 0x63c0|uint16(puk)), nil
	})
	card.RegisterINSHandler(0xFB, func(_ *emulator.Card, _ []byte) ([]byte, error) {
		if pin != 0 || puk != 0 {
			return emulator.BuildResponse(nil, iso7816.SwConditionsNotMet), nil
		}
		resets++
		return emulator.BuildSuccessResponse(nil), nil
	})
	err := admin.ResetToken(adapters.NewRuntime(newSlotDescriptionSession(card), NewAdapter()), adapters.ResetTokenParams{})
	if err != nil {
		t.Fatal(err)
	}
	if pinAttempts != 3 || pukAttempts != 3 || resets != 1 {
		t.Fatalf("PIN attempts=%d PUK attempts=%d reset=%d", pinAttempts, pukAttempts, resets)
	}
}

func TestResetBlockingDoesNotTreatSuccessAsBlocked(t *testing.T) {
	for _, step := range []string{"PIN", "PUK"} {
		t.Run(step, func(t *testing.T) {
			card := emulator.NewCard()
			card.RegisterINSHandler(0x20, func(_ *emulator.Card, raw []byte) ([]byte, error) {
				cmd, err := iso7816.ParseCommand(raw)
				if err != nil {
					return nil, err
				}
				if len(cmd.Data) == 0 {
					if step == "PUK" {
						return emulator.BuildResponse(nil, 0x63c0), nil
					}
					return emulator.BuildResponse(nil, 0x63c3), nil
				}
				return emulator.BuildSuccessResponse(nil), nil
			})
			card.SetSuccessResponse(0x2c, nil)
			card.SetSuccessResponse(0xfb, nil)
			err := admin.ResetToken(adapters.NewRuntime(newSlotDescriptionSession(card), NewAdapter()), adapters.ResetTokenParams{})
			if err == nil {
				t.Fatal("successful invalid-credential attempt must not prove blocking")
			}
			for _, raw := range card.TransmittedCommands {
				if raw[1] == 0xfb || (step == "PIN" && raw[1] == 0x2c) {
					t.Fatalf("continued after unconfirmed %s blocking: %X", step, raw)
				}
			}
		})
	}
}

func TestResetBoundsNonProgressingBlocking(t *testing.T) {
	calls := 0
	err := blockResetCredential(1, "PIN", func() (int, error) { calls++; return 1, nil })
	if err == nil || calls != 256 {
		t.Fatalf("non-progressing card: calls=%d error=%v", calls, err)
	}
}

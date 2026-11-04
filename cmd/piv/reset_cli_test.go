package main

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

// Exercise the actual CLI dispatch, including NEO's lack of GET METADATA.
// A bare RESET is refused until both retry counters have reached zero.
func TestSetupResetYubiKeyBlocksCredentialsBeforeReset(t *testing.T) {
	for _, initial := range []int{3, 0} {
		t.Run(fmt.Sprintf("retries=%d", initial), func(t *testing.T) {
			card := emulator.NewCard()
			card.SetSuccessResponse(0xA4, nil)
			pin, puk := initial, initial
			pinAttempts, pukAttempts, resets := 0, 0, 0
			card.RegisterINSHandler(0x20, func(_ *emulator.Card, raw []byte) ([]byte, error) {
				cmd, err := iso7816.ParseCommand(raw)
				if err != nil {
					return nil, err
				}
				if cmd.P2 != byte(piv.PINTypeCard) {
					return nil, fmt.Errorf("unexpected PIN reference: %X", raw)
				}
				if len(cmd.Data) != 0 {
					if !bytes.Equal(cmd.Data, bytes.Repeat([]byte{0xff}, 8)) {
						return nil, fmt.Errorf("unexpected blocking value: %X", raw)
					}
					pinAttempts++
					if pin > 0 {
						pin--
					}
				}
				if len(cmd.Data) != 0 && pin == 0 {
					return emulator.BuildResponse(nil, iso7816.SwAuthBlocked), nil
				}
				return emulator.BuildResponse(nil, 0x63c0|uint16(pin)), nil
			})
			card.RegisterINSHandler(0x2C, func(_ *emulator.Card, raw []byte) ([]byte, error) {
				cmd, err := iso7816.ParseCommand(raw)
				if err != nil {
					return nil, err
				}
				if pin != 0 {
					return nil, fmt.Errorf("PUK blocking started before PIN was blocked")
				}
				if cmd.P2 != byte(piv.PINTypeCard) || !bytes.Equal(cmd.Data, bytes.Repeat([]byte{0xff}, 16)) {
					return nil, fmt.Errorf("unexpected PUK blocking command: %X", raw)
				}
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
			targets := neoCLITargets(func() piv.Card { return card })
			cli, _, stderr := newTestCLI(t, targets, bytes.NewReader(nil))
			if err := executeCLI(cli, "setup", "reset", "--yes"); err != nil {
				t.Fatalf("setup reset: %v; %s", err, stderr.String())
			}
			if resets != 1 || pinAttempts != initial || pukAttempts != max(initial, 1) {
				t.Fatalf("reset=%d PIN attempts=%d PUK attempts=%d, initial=%d", resets, pinAttempts, pukAttempts, initial)
			}
		})
	}
}

func TestSetupResetYubiKeyDryRunDoesNotBlockCredentials(t *testing.T) {
	card := emulator.NewCard()
	card.SetSuccessResponse(0xA4, nil)
	targets := neoCLITargets(func() piv.Card { return card })
	cli, _, stderr := newTestCLI(t, targets, bytes.NewReader(nil))
	if err := executeCLI(cli, "setup", "reset", "--dry-run", "--adapter", "yubikey"); err != nil {
		t.Fatalf("dry run: %v; %s", err, stderr.String())
	}
	for _, cmd := range card.TransmittedCommands {
		if cmd[1] == 0x20 || cmd[1] == 0x2c || cmd[1] == 0xfb {
			t.Fatalf("dry run sent credential/reset APDU: %X", cmd)
		}
	}
}

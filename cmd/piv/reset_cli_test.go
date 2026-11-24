package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/PeculiarVentures/piv-go/adapters/safenet"
	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/internal/cli/app"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

func TestSetupResetSafeNetReportsRestoredFactoryCredentials(t *testing.T) {
	t.Setenv("PIV_TEST_RESET_MGM", "112233445566778899aabbccddeeff00")
	t.Setenv("PIV_TEST_RESET_PUK", "87654321")

	const notice = "Factory credentials restored"
	const success = "token reset\n\n" + notice + "\n" +
		"  PIN  123456\n" +
		"  PUK  12345678\n" +
		"  Management key (aes128)  01020304050607080102030405060708\n"

	for _, tc := range []struct {
		name        string
		args        []string
		pukStatus   uint16
		wantError   bool
		wantConsole bool
	}{
		{name: "success", pukStatus: iso7816.SwSuccess, wantConsole: true},
		{name: "dry run", args: []string{"--dry-run"}, pukStatus: iso7816.SwSuccess},
		{name: "failure", pukStatus: iso7816.SwWrongData, wantError: true},
		{name: "json", args: []string{"--json"}, pukStatus: iso7816.SwSuccess},
	} {
		t.Run(tc.name, func(t *testing.T) {
			card := safenet.NewInitializationEmulatorCard()
			card.SetResponse(0x24, nil, tc.pukStatus)
			targets := app.NewTargetResolver(fakeCardContextFactory{
				builders: map[string]func() piv.Card{
					"SafeNet eToken Fusion": func() piv.Card { return card },
				},
			}, nil, bytes.NewReader(nil), &bytes.Buffer{})
			cli, stdout, stderr := newTestCLI(t, targets, bytes.NewReader(nil))

			args := []string{"setup", "reset", "--yes", "--trace", "off",
				"--mgm-env", "PIV_TEST_RESET_MGM", "--puk-env", "PIV_TEST_RESET_PUK"}
			err := executeCLI(cli, append(args, tc.args...)...)
			if (err != nil) != tc.wantError {
				t.Fatalf("setup reset: %v; stderr: %s", err, stderr.String())
			}
			if tc.wantConsole {
				if got := stderr.String(); got != success || stdout.Len() != 0 {
					t.Fatalf("unexpected success output: stdout %q, stderr %q", stdout.String(), got)
				}
				return
			}
			output := stdout.String() + stderr.String()
			if strings.Contains(output, notice) || strings.Contains(output, "01020304050607080102030405060708") {
				t.Fatalf("unexpected factory credentials in output: %s", output)
			}
		})
	}
}

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

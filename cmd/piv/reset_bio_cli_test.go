package main

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/PeculiarVentures/piv-go/emulator"
	"github.com/PeculiarVentures/piv-go/iso7816"
	"github.com/PeculiarVentures/piv-go/piv"
)

func TestSetupResetBioRefusesBeforeCredentialBlocking(t *testing.T) {
	for _, configured := range []byte{0, 1} {
		t.Run(fmt.Sprintf("configured=%d", configured), func(t *testing.T) {
			card := emulator.NewCard()
			card.SetSuccessResponse(0xA4, nil)
			card.RegisterINSHandler(0xF7, func(_ *emulator.Card, raw []byte) ([]byte, error) {
				if raw[3] == 0x96 {
					return emulator.BuildSuccessResponse([]byte{7, 1, configured, 6, 1, 3, 8, 1, 0}), nil
				}
				return emulator.BuildSuccessResponse([]byte{6, 2, 3, 3}), nil
			})
			cli, _, _ := newTestCLI(t, neoCLITargets(func() piv.Card { return card }), bytes.NewReader(nil))
			if code := exitCodeOf(t, executeCLI(cli, "setup", "reset", "--yes")); code != 4 {
				t.Fatalf("exit=%d, want unsupported", code)
			}
			for _, raw := range card.TransmittedCommands {
				cmd, err := iso7816.ParseCommand(raw)
				if err != nil {
					t.Fatal(err)
				}
				if cmd.Ins == 0x20 || cmd.Ins == 0x2c || cmd.Ins == 0xfb {
					t.Fatalf("Bio reset must refuse before credential commands: %X", raw)
				}
			}
		})
	}
}

package main

import (
	"context"

	"github.com/PeculiarVentures/piv-go/internal/cli/app"
	"github.com/spf13/cobra"
)

func (c *cli) newDiagCommand() *cobra.Command {
	command := &cobra.Command{Use: "diag", Short: "Expert diagnostics and raw protocol tooling"}

	object := &cobra.Command{Use: "object", Short: "Inspect known PIV objects"}
	objectList := &cobra.Command{
		Use:   "list",
		Short: "List known PIV objects and whether they are present",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.diag.ObjectList(ctx, global)
			})
		},
	}
	var objectFormat string
	objectRead := &cobra.Command{
		Use:   "read <name|tag>",
		Short: "Read one known PIV object",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.diag.ObjectRead(ctx, app.ObjectReadRequest{Global: global, Selector: args[0], Format: objectFormat})
			})
		},
	}
	objectRead.Flags().StringVar(&objectFormat, "format", "hex", "Read format: hex or json")
	object.AddCommand(objectList, objectRead)

	tlv := &cobra.Command{Use: "tlv", Short: "Decode BER-TLV payloads"}
	var tlvInput string
	tlvDecode := &cobra.Command{
		Use:   "decode",
		Short: "Decode BER-TLV from a file or stdin",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				_ = global
				return c.diag.TLVDecode(ctx, app.TLVDecodeRequest{InputPath: tlvInput})
			})
		},
	}
	tlvDecode.Flags().StringVar(&tlvInput, "in", "-", "Read TLV input from a file path or stdin when set to -")
	tlv.AddCommand(tlvDecode)

	apdu := &cobra.Command{Use: "apdu", Short: "Send raw APDU commands"}
	var apduHex []string
	var apduYes bool
	apduSend := &cobra.Command{
		Use:   "send",
		Short: "Send one or more raw APDUs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.diag.APDUSend(ctx, app.APDUSendRequest{Global: global, HexCommands: apduHex, Yes: apduYes})
			})
		},
	}
	apduSend.Flags().StringArrayVar(&apduHex, "hex", nil, "Hexadecimal APDU command; repeat the flag to send multiple APDUs")
	apduSend.Flags().BoolVarP(&apduYes, "yes", "y", false, "Confirm expert-mode raw APDU execution")
	apdu.AddCommand(apduSend)

	command.AddCommand(object, tlv, apdu)
	return command
}

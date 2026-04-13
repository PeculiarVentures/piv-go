package main

import (
	"context"

	"github.com/PeculiarVentures/piv-go/internal/cli/app"
	"github.com/spf13/cobra"
)

func (c *cli) newDevicesCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "devices",
		Short: "List PC/SC readers and PIV readiness",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.info.Devices(ctx, global)
			})
		},
	}
}

func (c *cli) newInfoCommand() *cobra.Command {
	var sections []string
	command := &cobra.Command{
		Use:   "info",
		Short: "Show a summary of the selected token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.info.Info(ctx, app.InfoRequest{Global: global, Sections: sections})
			})
		},
	}
	command.Flags().StringSliceVar(&sections, "sections", nil, "Comma-separated sections: summary, capabilities, slots, credentials")
	return command
}

func (c *cli) newSlotCommand() *cobra.Command {
	command := &cobra.Command{Use: "slot", Short: "Inspect slot state"}
	list := &cobra.Command{
		Use:   "list",
		Short: "List the primary user slots",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.info.SlotList(ctx, global)
			})
		},
	}
	show := &cobra.Command{
		Use:   "show <slot>",
		Short: "Show one slot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slot, err := app.ParseSlot(args[0])
			if err != nil {
				return err
			}
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.info.SlotShow(ctx, app.SlotRequest{Global: global, Slot: slot})
			})
		},
	}
	command.AddCommand(list, show)
	return command
}

func (c *cli) newDoctorCommand() *cobra.Command {
	withSelect := false
	command := &cobra.Command{
		Use:   "doctor",
		Short: "Run safe diagnostics for PC/SC and token readiness",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.diag.Doctor(ctx, app.DoctorRequest{Global: global, WithSelect: withSelect})
			})
		},
	}
	command.Flags().BoolVar(&withSelect, "with-select", false, "Attempt an explicit PIV SELECT on the resolved token")
	return command
}

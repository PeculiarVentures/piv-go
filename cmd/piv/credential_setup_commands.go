package main

import (
	"context"

	"github.com/PeculiarVentures/piv-go/internal/cli/app"
	"github.com/spf13/cobra"
)

func (c *cli) newPINCommand() *cobra.Command {
	command := &cobra.Command{Use: "pin", Short: "Manage the card PIN"}
	status := &cobra.Command{
		Use:   "status",
		Short: "Show PIN retry status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.info.PINStatus(ctx, app.StatusRequest{Global: global})
			})
		},
	}
	var verifyPINStdin bool
	var verifyPINEnv string
	verify := &cobra.Command{
		Use:   "verify",
		Short: "Verify the card PIN",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.PINVerify(ctx, app.PINVerifyRequest{Global: global, PIN: secretRequest("PIN", "Enter PIN: ", verifyPINEnv, "PIV_PIN", verifyPINStdin)})
			})
		},
	}
	verify.Flags().BoolVar(&verifyPINStdin, "pin-stdin", false, "Read the PIN from stdin")
	verify.Flags().StringVar(&verifyPINEnv, "pin-env", "", "Read the PIN from the specified environment variable")

	var oldPINStdin bool
	var oldPINEnv string
	var newPINStdin bool
	var newPINEnv string
	change := &cobra.Command{
		Use:   "change",
		Short: "Change the card PIN",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.PINChange(ctx, app.PINChangeRequest{
					Global: global,
					OldPIN: secretRequest("current PIN", "Enter current PIN: ", oldPINEnv, "PIV_PIN", oldPINStdin),
					NewPIN: secretRequest("new PIN", "Enter new PIN: ", newPINEnv, "PIV_NEW_PIN", newPINStdin),
				})
			})
		},
	}
	change.Flags().BoolVar(&oldPINStdin, "old-pin-stdin", false, "Read the current PIN from stdin")
	change.Flags().StringVar(&oldPINEnv, "old-pin-env", "", "Read the current PIN from the specified environment variable")
	change.Flags().BoolVar(&newPINStdin, "new-pin-stdin", false, "Read the new PIN from stdin")
	change.Flags().StringVar(&newPINEnv, "new-pin-env", "", "Read the new PIN from the specified environment variable")

	var unblockPUKStdin bool
	var unblockPUKEnv string
	var unblockNewPINStdin bool
	var unblockNewPINEnv string
	unblock := &cobra.Command{
		Use:   "unblock",
		Short: "Reset the PIN using the PUK",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.PINUnblock(ctx, app.PINUnblockRequest{
					Global: global,
					PUK:    secretRequest("PUK", "Enter PUK: ", unblockPUKEnv, "PIV_PUK", unblockPUKStdin),
					NewPIN: secretRequest("new PIN", "Enter new PIN: ", unblockNewPINEnv, "PIV_NEW_PIN", unblockNewPINStdin),
				})
			})
		},
	}
	unblock.Flags().BoolVar(&unblockPUKStdin, "puk-stdin", false, "Read the PUK from stdin")
	unblock.Flags().StringVar(&unblockPUKEnv, "puk-env", "", "Read the PUK from the specified environment variable")
	unblock.Flags().BoolVar(&unblockNewPINStdin, "new-pin-stdin", false, "Read the new PIN from stdin")
	unblock.Flags().StringVar(&unblockNewPINEnv, "new-pin-env", "", "Read the new PIN from the specified environment variable")

	command.AddCommand(status, verify, change, unblock)
	return command
}

func (c *cli) newPUKCommand() *cobra.Command {
	command := &cobra.Command{Use: "puk", Short: "Manage the card PUK"}
	status := &cobra.Command{
		Use:   "status",
		Short: "Show PUK retry status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.info.PUKStatus(ctx, app.StatusRequest{Global: global})
			})
		},
	}
	var oldPUKStdin bool
	var oldPUKEnv string
	var newPUKStdin bool
	var newPUKEnv string
	change := &cobra.Command{
		Use:   "change",
		Short: "Change the PUK",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.PUKChange(ctx, app.PUKChangeRequest{
					Global: global,
					OldPUK: secretRequest("current PUK", "Enter current PUK: ", oldPUKEnv, "PIV_PUK", oldPUKStdin),
					NewPUK: secretRequest("new PUK", "Enter new PUK: ", newPUKEnv, "PIV_NEW_PUK", newPUKStdin),
				})
			})
		},
	}
	change.Flags().BoolVar(&oldPUKStdin, "old-puk-stdin", false, "Read the current PUK from stdin")
	change.Flags().StringVar(&oldPUKEnv, "old-puk-env", "", "Read the current PUK from the specified environment variable")
	change.Flags().BoolVar(&newPUKStdin, "new-puk-stdin", false, "Read the new PUK from stdin")
	change.Flags().StringVar(&newPUKEnv, "new-puk-env", "", "Read the new PUK from the specified environment variable")
	command.AddCommand(status, change)
	return command
}

func (c *cli) newManagementCommand() *cobra.Command {
	command := &cobra.Command{Use: "mgm", Short: "Verify or rotate the management key"}
	var verifyStdin bool
	var verifyEnv string
	var verifyAlgorithm string
	verify := &cobra.Command{
		Use:   "verify",
		Short: "Verify the management key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			algorithm, algorithmName, err := app.ParseManagementAlgorithm(verifyAlgorithm)
			if err != nil {
				return err
			}
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.MGMVerify(ctx, app.MGMVerifyRequest{
					Global:        global,
					Key:           secretRequest("management key", "Enter management key: ", verifyEnv, "PIV_MANAGEMENT_KEY", verifyStdin),
					Algorithm:     algorithm,
					AlgorithmName: algorithmName,
				})
			})
		},
	}
	verify.Flags().BoolVar(&verifyStdin, "stdin", false, "Read the management key from stdin")
	verify.Flags().StringVar(&verifyEnv, "env", "", "Read the management key from the specified environment variable")
	verify.Flags().StringVar(&verifyAlgorithm, "alg", "auto", "Management key algorithm: auto, 3des, aes128, aes192, or aes256")

	var rotateCurrentStdin bool
	var rotateCurrentEnv string
	var rotateNewStdin bool
	var rotateNewEnv string
	var rotateAlgorithm string
	var rotateNewAlgorithm string
	var rotateYes bool
	var rotateDryRun bool
	rotate := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate the management key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			algorithm, algorithmName, err := app.ParseManagementAlgorithm(rotateAlgorithm)
			if err != nil {
				return err
			}
			newAlgorithm, newAlgorithmName, err := app.ParseManagementAlgorithm(rotateNewAlgorithm)
			if err != nil {
				return err
			}
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.MGMRotate(ctx, app.MGMRotateRequest{
					Global:           global,
					CurrentKey:       secretRequest("current management key", "Enter current management key: ", rotateCurrentEnv, "PIV_MANAGEMENT_KEY", rotateCurrentStdin),
					NewKey:           secretRequest("new management key", "Enter new management key: ", rotateNewEnv, "PIV_NEW_MANAGEMENT_KEY", rotateNewStdin),
					Algorithm:        algorithm,
					AlgorithmName:    algorithmName,
					NewAlgorithm:     newAlgorithm,
					NewAlgorithmName: newAlgorithmName,
					Yes:              rotateYes,
					DryRun:           rotateDryRun,
				})
			})
		},
	}
	rotate.Flags().BoolVar(&rotateCurrentStdin, "current-stdin", false, "Read the current management key from stdin")
	rotate.Flags().StringVar(&rotateCurrentEnv, "current-env", "", "Read the current management key from the specified environment variable")
	rotate.Flags().BoolVar(&rotateNewStdin, "new-stdin", false, "Read the new management key from stdin")
	rotate.Flags().StringVar(&rotateNewEnv, "new-env", "", "Read the new management key from the specified environment variable")
	rotate.Flags().StringVar(&rotateAlgorithm, "alg", "auto", "Current management key algorithm: auto, 3des, aes128, aes192, or aes256")
	rotate.Flags().StringVar(&rotateNewAlgorithm, "new-alg", "", "New management key algorithm: 3des, aes128, aes192, or aes256")
	rotate.Flags().BoolVarP(&rotateYes, "yes", "y", false, "Skip the destructive-operation confirmation")
	rotate.Flags().BoolVar(&rotateDryRun, "dry-run", false, "Show the planned action without mutating the token")

	status := &cobra.Command{
		Use:   "status",
		Short: "Show management key status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.info.MGMStatus(ctx, app.StatusRequest{Global: global})
			})
		},
	}

	command.AddCommand(status, verify, rotate)
	return command
}

func (c *cli) newSetupCommand() *cobra.Command {
	command := &cobra.Command{Use: "setup", Short: "Initialize or reset tokens"}

	var initMGMStdin bool
	var initMGMEnv string
	var initYes bool
	var initDryRun bool
	init := &cobra.Command{
		Use:   "init",
		Short: "Initialize the selected token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.SetupInit(ctx, app.SetupInitRequest{
					Global:        global,
					ManagementKey: secretRequest("management key", "Enter management key: ", initMGMEnv, "PIV_MANAGEMENT_KEY", initMGMStdin),
					Yes:           initYes,
					DryRun:        initDryRun,
				})
			})
		},
	}
	init.Flags().BoolVar(&initMGMStdin, "mgm-stdin", false, "Read the management key from stdin")
	init.Flags().StringVar(&initMGMEnv, "mgm-env", "", "Read the management key from the specified environment variable")
	init.Flags().BoolVarP(&initYes, "yes", "y", false, "Skip the destructive-operation confirmation")
	init.Flags().BoolVar(&initDryRun, "dry-run", false, "Show the planned action without mutating the token")

	var resetMGMStdin bool
	var resetMGMEnv string
	var resetPUKStdin bool
	var resetPUKEnv string
	var resetYes bool
	var resetDryRun bool
	reset := &cobra.Command{
		Use:   "reset",
		Short: "Reset the selected token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.SetupReset(ctx, app.SetupResetRequest{
					Global:        global,
					ManagementKey: secretRequest("management key", "Enter management key: ", resetMGMEnv, "PIV_MANAGEMENT_KEY", resetMGMStdin),
					PUK:           secretRequest("PUK", "Enter PUK: ", resetPUKEnv, "PIV_PUK", resetPUKStdin),
					Yes:           resetYes,
					DryRun:        resetDryRun,
				})
			})
		},
	}
	reset.Flags().BoolVar(&resetMGMStdin, "mgm-stdin", false, "Read the management key from stdin when the token requires it")
	reset.Flags().StringVar(&resetMGMEnv, "mgm-env", "", "Read the management key from the specified environment variable")
	reset.Flags().BoolVar(&resetPUKStdin, "puk-stdin", false, "Read the PUK from stdin when the token requires it")
	reset.Flags().StringVar(&resetPUKEnv, "puk-env", "", "Read the PUK from the specified environment variable")
	reset.Flags().BoolVarP(&resetYes, "yes", "y", false, "Skip the destructive-operation confirmation")
	reset.Flags().BoolVar(&resetDryRun, "dry-run", false, "Show the planned action without mutating the token")

	var resetSlotMGMStdin bool
	var resetSlotMGMEnv string
	var resetSlotYes bool
	var resetSlotDryRun bool
	resetSlot := &cobra.Command{
		Use:   "reset-slot <slot>",
		Short: "Reset one slot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slot, err := app.ParseSlot(args[0])
			if err != nil {
				return err
			}
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.SetupResetSlot(ctx, app.SetupResetSlotRequest{
					Global:        global,
					ManagementKey: secretRequest("management key", "Enter management key: ", resetSlotMGMEnv, "PIV_MANAGEMENT_KEY", resetSlotMGMStdin),
					Slot:          slot,
					Yes:           resetSlotYes,
					DryRun:        resetSlotDryRun,
				})
			})
		},
	}
	resetSlot.Flags().BoolVar(&resetSlotMGMStdin, "mgm-stdin", false, "Read the management key from stdin")
	resetSlot.Flags().StringVar(&resetSlotMGMEnv, "mgm-env", "", "Read the management key from the specified environment variable")
	resetSlot.Flags().BoolVarP(&resetSlotYes, "yes", "y", false, "Skip the destructive-operation confirmation")
	resetSlot.Flags().BoolVar(&resetSlotDryRun, "dry-run", false, "Show the planned action without mutating the token")

	command.AddCommand(init, reset, resetSlot)
	return command
}

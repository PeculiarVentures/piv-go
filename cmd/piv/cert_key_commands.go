package main

import (
	"context"

	"github.com/PeculiarVentures/piv-go/internal/cli/app"
	"github.com/spf13/cobra"
)

func (c *cli) newCertCommand() *cobra.Command {
	command := &cobra.Command{Use: "cert", Short: "Manage slot certificates"}

	var exportFormat string
	var exportOut string
	export := &cobra.Command{
		Use:   "export <slot>",
		Short: "Export a slot certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slot, err := app.ParseSlot(args[0])
			if err != nil {
				return err
			}
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.info.CertExport(ctx, app.ExportRequest{Global: global, Slot: slot, Format: exportFormat, Out: exportOut})
			})
		},
	}
	export.Flags().StringVar(&exportFormat, "format", "", "Export format: pem or der")
	export.Flags().StringVarP(&exportOut, "out", "o", "", "Write the certificate to a file")

	importCommand := &cobra.Command{
		Use:   "import <slot> <path>",
		Short: "Import a certificate into a slot",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			slot, err := app.ParseSlot(args[0])
			if err != nil {
				return err
			}
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.CertImport(ctx, app.CertImportRequest{Global: global, Slot: slot, Path: args[1]})
			})
		},
	}

	deleteYes := false
	deleteDryRun := false
	deleteCommand := &cobra.Command{
		Use:   "delete <slot>",
		Short: "Delete a slot certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slot, err := app.ParseSlot(args[0])
			if err != nil {
				return err
			}
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.CertDelete(ctx, app.DeleteRequest{Global: global, Slot: slot, Yes: deleteYes, DryRun: deleteDryRun})
			})
		},
	}
	deleteCommand.Flags().BoolVarP(&deleteYes, "yes", "y", false, "Skip the destructive-operation confirmation")
	deleteCommand.Flags().BoolVar(&deleteDryRun, "dry-run", false, "Show the planned action without mutating the token")

	command.AddCommand(export, importCommand, deleteCommand)
	return command
}

func (c *cli) newKeyCommand() *cobra.Command {
	command := &cobra.Command{Use: "key", Short: "Manage slot keys and key operations"}

	var generateAlgorithm string
	var generateMGMStdin bool
	var generateMGMEnv string
	var generateDryRun bool
	generate := &cobra.Command{
		Use:   "generate <slot>",
		Short: "Generate a new key in a slot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slot, err := app.ParseSlot(args[0])
			if err != nil {
				return err
			}
			algorithm, algorithmName, err := app.ParseKeyAlgorithm(generateAlgorithm)
			if err != nil {
				return err
			}
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.KeyGenerate(ctx, app.KeyGenerateRequest{
					Global:        global,
					Slot:          slot,
					Algorithm:     algorithm,
					AlgorithmName: algorithmName,
					ManagementKey: secretRequest("management key", "Enter management key: ", generateMGMEnv, "PIV_MANAGEMENT_KEY", generateMGMStdin),
					DryRun:        generateDryRun,
				})
			})
		},
	}
	generate.Flags().StringVar(&generateAlgorithm, "alg", "", "Key algorithm: p256, p384, rsa1024, or rsa2048")
	_ = generate.MarkFlagRequired("alg")
	generate.Flags().BoolVar(&generateMGMStdin, "mgm-stdin", false, "Read the management key from stdin")
	generate.Flags().StringVar(&generateMGMEnv, "mgm-env", "", "Read the management key from the specified environment variable")
	generate.Flags().BoolVar(&generateDryRun, "dry-run", false, "Show the planned action without mutating the token")

	var publicFormat string
	var publicOut string
	public := &cobra.Command{
		Use:   "public <slot>",
		Short: "Export a slot public key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slot, err := app.ParseSlot(args[0])
			if err != nil {
				return err
			}
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.info.KeyPublic(ctx, app.ExportRequest{Global: global, Slot: slot, Format: publicFormat, Out: publicOut})
			})
		},
	}
	public.Flags().StringVar(&publicFormat, "format", "", "Export format: pem or der")
	public.Flags().StringVarP(&publicOut, "out", "o", "", "Write the public key to a file")

	var deleteMGMStdin bool
	var deleteMGMEnv string
	var deleteYes bool
	var deleteDryRun bool
	deleteCommand := &cobra.Command{
		Use:   "delete <slot>",
		Short: "Delete a slot key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slot, err := app.ParseSlot(args[0])
			if err != nil {
				return err
			}
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.KeyDelete(ctx, app.DeleteRequest{Global: global, Slot: slot, Yes: deleteYes, DryRun: deleteDryRun}, secretRequest("management key", "Enter management key: ", deleteMGMEnv, "PIV_MANAGEMENT_KEY", deleteMGMStdin))
			})
		},
	}
	deleteCommand.Flags().BoolVar(&deleteMGMStdin, "mgm-stdin", false, "Read the management key from stdin")
	deleteCommand.Flags().StringVar(&deleteMGMEnv, "mgm-env", "", "Read the management key from the specified environment variable")
	deleteCommand.Flags().BoolVarP(&deleteYes, "yes", "y", false, "Skip the destructive-operation confirmation")
	deleteCommand.Flags().BoolVar(&deleteDryRun, "dry-run", false, "Show the planned action without mutating the token")

	var signInput string
	var signHash string
	var signEncoding string
	var signOut string
	var signPINStdin bool
	var signPINEnv string
	sign := &cobra.Command{
		Use:   "sign <slot>",
		Short: "Sign input data with a slot key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slot, err := app.ParseSlot(args[0])
			if err != nil {
				return err
			}
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.KeySign(ctx, app.SignRequest{
					Global:    global,
					Slot:      slot,
					InputPath: signInput,
					Hash:      signHash,
					Encoding:  signEncoding,
					Out:       signOut,
					PIN:       secretRequest("PIN", "Enter PIN: ", signPINEnv, "PIV_PIN", signPINStdin),
				})
			})
		},
	}
	sign.Flags().StringVar(&signInput, "in", "", "Read the payload to sign from a file")
	_ = sign.MarkFlagRequired("in")
	sign.Flags().StringVar(&signHash, "hash", "none", "Hash mode: none or sha256")
	sign.Flags().StringVar(&signEncoding, "encoding", "base64", "Output encoding: base64, hex, or raw")
	sign.Flags().StringVarP(&signOut, "out", "o", "", "Write the signature to a file")
	sign.Flags().BoolVar(&signPINStdin, "pin-stdin", false, "Read the PIN from stdin")
	sign.Flags().StringVar(&signPINEnv, "pin-env", "", "Read the PIN from the specified environment variable")

	var challengeHex string
	var challengeEncoding string
	var challengeOut string
	var challengePINStdin bool
	var challengePINEnv string
	challenge := &cobra.Command{
		Use:   "challenge <slot>",
		Short: "Run GENERAL AUTHENTICATE with a supplied challenge",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slot, err := app.ParseSlot(args[0])
			if err != nil {
				return err
			}
			usePIN := secretSourceUsed(challengePINEnv, "PIV_PIN", challengePINStdin)
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.KeyChallenge(ctx, app.ChallengeRequest{
					Global:       global,
					Slot:         slot,
					ChallengeHex: challengeHex,
					Encoding:     challengeEncoding,
					Out:          challengeOut,
					PIN:          secretRequest("PIN", "Enter PIN: ", challengePINEnv, "PIV_PIN", challengePINStdin),
					UsePIN:       usePIN,
				})
			})
		},
	}
	challenge.Flags().StringVar(&challengeHex, "challenge-hex", "", "Hexadecimal challenge input")
	_ = challenge.MarkFlagRequired("challenge-hex")
	challenge.Flags().StringVar(&challengeEncoding, "encoding", "base64", "Output encoding: base64, hex, or raw")
	challenge.Flags().StringVarP(&challengeOut, "out", "o", "", "Write the challenge response to a file")
	challenge.Flags().BoolVar(&challengePINStdin, "pin-stdin", false, "Read the PIN from stdin before authentication")
	challenge.Flags().StringVar(&challengePINEnv, "pin-env", "", "Read the PIN from the specified environment variable")

	command.AddCommand(generate, public, deleteCommand, sign, challenge)
	return command
}

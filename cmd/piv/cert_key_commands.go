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

	var importRawCert bool
	var importMGMStdin bool
	var importMGMEnv string
	importCommand := &cobra.Command{
		Use:   "import <slot> <path>",
		Short: "Import a certificate into a slot",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			slot, err := app.ParseSlotForMutation(args[0])
			if err != nil {
				return err
			}
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.CertImport(ctx, app.CertImportRequest{Global: global, Slot: slot, Path: args[1], Raw: importRawCert, ManagementKey: secretRequest("management key", "Enter management key: ", importMGMEnv, "PIV_MANAGEMENT_KEY", importMGMStdin)})
			})
		},
	}
	importCommand.Flags().BoolVar(&importRawCert, "raw-cert", false, "Store raw certificate bytes without X.509 validation (required for ML-DSA post-quantum certificates; X25519 has no X.509 profile)")
	importCommand.Flags().BoolVar(&importMGMStdin, "mgm-stdin", false, "Read the management key from stdin")
	importCommand.Flags().StringVar(&importMGMEnv, "mgm-env", "", "Read the management key from the specified environment variable")

	deleteYes := false
	deleteDryRun := false
	var deleteMGMStdin bool
	var deleteMGMEnv string
	deleteCommand := &cobra.Command{
		Use:   "delete <slot>",
		Short: "Delete a slot certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slot, err := app.ParseSlotForMutation(args[0])
			if err != nil {
				return err
			}
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.CertDelete(ctx, app.DeleteRequest{Global: global, Slot: slot, Yes: deleteYes, DryRun: deleteDryRun, ManagementKey: secretRequest("management key", "Enter management key: ", deleteMGMEnv, "PIV_MANAGEMENT_KEY", deleteMGMStdin)})
			})
		},
	}
	deleteCommand.Flags().BoolVarP(&deleteYes, "yes", "y", false, "Skip the destructive-operation confirmation")
	deleteCommand.Flags().BoolVar(&deleteDryRun, "dry-run", false, "Show the planned action without mutating the token")
	deleteCommand.Flags().BoolVar(&deleteMGMStdin, "mgm-stdin", false, "Read the management key from stdin")
	deleteCommand.Flags().StringVar(&deleteMGMEnv, "mgm-env", "", "Read the management key from the specified environment variable")

	command.AddCommand(export, importCommand, deleteCommand)
	return command
}

func (c *cli) newKeyCommand() *cobra.Command {
	command := &cobra.Command{Use: "key", Short: "Manage slot keys and key operations"}

	var generateAlgorithm string
	var generateMGMStdin bool
	var generateMGMEnv string
	var generatePinPolicy string
	var generateTouchPolicy string
	var generateDryRun bool
	generate := &cobra.Command{
		Use:   "generate <slot>",
		Short: "Generate a new key in a slot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slot, err := app.ParseSlotForMutation(args[0])
			if err != nil {
				return err
			}
			algorithm, algorithmName, err := app.ParseKeyAlgorithm(generateAlgorithm)
			if err != nil {
				return err
			}
			pinPolicy, err := app.ParsePINPolicy(generatePinPolicy)
			if err != nil {
				return err
			}
			touchPolicy, err := app.ParseTouchPolicy(generateTouchPolicy)
			if err != nil {
				return err
			}
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.KeyGenerate(ctx, app.KeyGenerateRequest{
					Global:        global,
					Slot:          slot,
					Algorithm:     algorithm,
					AlgorithmName: algorithmName,
					PinPolicy:     pinPolicy,
					TouchPolicy:   touchPolicy,
					ManagementKey: secretRequest("management key", "Enter management key: ", generateMGMEnv, "PIV_MANAGEMENT_KEY", generateMGMStdin),
					DryRun:        generateDryRun,
				})
			})
		},
	}
	generate.Flags().StringVar(&generateAlgorithm, "alg", "", "Key algorithm: p256, p384, rsa1024, rsa2048, rsa3072, rsa4096, ed25519, x25519, mldsa44, mldsa65, mldsa87, mlkem512, mlkem768, mlkem1024 (preview)")
	_ = generate.MarkFlagRequired("alg")
	generate.Flags().BoolVar(&generateMGMStdin, "mgm-stdin", false, "Read the management key from stdin")
	generate.Flags().StringVar(&generateMGMEnv, "mgm-env", "", "Read the management key from the specified environment variable")
	generate.Flags().StringVar(&generatePinPolicy, "pin-policy", "", "Slot PIN policy: never, once, or always (default omits the tag; the device applies its own default)")
	generate.Flags().StringVar(&generateTouchPolicy, "touch-policy", "", "Slot touch policy: never, always, or cached (default omits the tag; the device applies its own default)")
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
	public.Flags().StringVar(&publicFormat, "format", "", "Export format: pem, der, or (opaque X25519/post-quantum keys) raw, base64, hex")
	public.Flags().StringVarP(&publicOut, "out", "o", "", "Write the public key to a file")

	var attestFormat string
	var attestOut string
	attest := &cobra.Command{
		Use:   "attest <slot>",
		Short: "Attest a slot key and export its attestation certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slot, err := app.ParseSlot(args[0])
			if err != nil {
				return err
			}
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.info.Attest(ctx, app.ExportRequest{Global: global, Slot: slot, Format: attestFormat, Out: attestOut})
			})
		},
	}
	attest.Flags().StringVar(&attestFormat, "format", "", "Export format: pem or der")
	attest.Flags().StringVarP(&attestOut, "out", "o", "", "Write the attestation certificate to a file")

	var deleteMGMStdin bool
	var deleteMGMEnv string
	var deleteYes bool
	var deleteDryRun bool
	deleteCommand := &cobra.Command{
		Use:   "delete <slot>",
		Short: "Delete a slot key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slot, err := app.ParseSlotForMutation(args[0])
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
			slot, err := app.ParseSlotForMutation(args[0])
			if err != nil {
				return err
			}
			usePIN := secretSourceUsed(signPINEnv, "PIV_PIN", signPINStdin)
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.KeySign(ctx, app.SignRequest{
					Global:    global,
					Slot:      slot,
					InputPath: signInput,
					Hash:      signHash,
					Encoding:  signEncoding,
					Out:       signOut,
					PIN:       secretRequest("PIN", "Enter PIN: ", signPINEnv, "PIV_PIN", signPINStdin),
					UsePIN:    usePIN,
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
		Short: "Run GENERAL AUTHENTICATE with a supplied challenge (X25519 slots perform ECDH, ML-KEM slots decapsulate)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slot, err := app.ParseSlotForMutation(args[0])
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
	challenge.Flags().StringVar(&challengeHex, "challenge-hex", "", "Hexadecimal challenge input (32-byte peer public key for X25519 ECDH, 768/1088/1568-byte ciphertext for ML-KEM-512/768/1024 decapsulation)")
	_ = challenge.MarkFlagRequired("challenge-hex")
	challenge.Flags().StringVar(&challengeEncoding, "encoding", "base64", "Output encoding: base64, hex, or raw")
	challenge.Flags().StringVarP(&challengeOut, "out", "o", "", "Write the challenge response to a file")
	challenge.Flags().BoolVar(&challengePINStdin, "pin-stdin", false, "Read the PIN from stdin before authentication")
	challenge.Flags().StringVar(&challengePINEnv, "pin-env", "", "Read the PIN from the specified environment variable")

	var importAlgorithm string
	var importPath string
	var importMGMStdin bool
	var importMGMEnv string
	var importPinPolicy string
	var importTouchPolicy string
	var importDryRun bool
	importKey := &cobra.Command{
		Use:   "import <slot>",
		Short: "Import a private key into a slot",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slot, err := app.ParseSlotForMutation(args[0])
			if err != nil {
				return err
			}
			algorithm, algorithmName, err := app.ParseKeyAlgorithm(importAlgorithm)
			if err != nil {
				return err
			}
			pinPolicy, err := app.ParsePINPolicy(importPinPolicy)
			if err != nil {
				return err
			}
			touchPolicy, err := app.ParseTouchPolicy(importTouchPolicy)
			if err != nil {
				return err
			}
			return c.execute(cmd, func(ctx context.Context, global app.GlobalOptions) (app.Response, error) {
				return c.mutations.KeyImport(ctx, app.KeyImportRequest{
					Global:        global,
					Slot:          slot,
					Algorithm:     algorithm,
					AlgorithmName: algorithmName,
					Path:          importPath,
					PinPolicy:     pinPolicy,
					TouchPolicy:   touchPolicy,
					ManagementKey: secretRequest("management key", "Enter management key: ", importMGMEnv, "PIV_MANAGEMENT_KEY", importMGMStdin),
					DryRun:        importDryRun,
				})
			})
		},
	}
	importKey.Flags().StringVar(&importAlgorithm, "alg", "", "Key algorithm: p256, p384, rsa1024, rsa2048, rsa3072, rsa4096, ed25519, x25519, mlkem768, mlkem1024 (mldsa and mlkem512 parse then gap-reject import)")
	_ = importKey.MarkFlagRequired("alg")
	importKey.Flags().StringVar(&importPath, "in", "", "Read the private key from a PEM or DER file (ed25519/x25519 also accept a raw 32-byte seed, mlkem768/mlkem1024 a raw 64-byte seed, as binary, hex, or base64)")
	_ = importKey.MarkFlagRequired("in")
	importKey.Flags().BoolVar(&importMGMStdin, "mgm-stdin", false, "Read the management key from stdin")
	importKey.Flags().StringVar(&importMGMEnv, "mgm-env", "", "Read the management key from the specified environment variable")
	importKey.Flags().StringVar(&importPinPolicy, "pin-policy", "", "Slot PIN policy: never, once, or always (default omits the tag; the device applies its own default)")
	importKey.Flags().StringVar(&importTouchPolicy, "touch-policy", "", "Slot touch policy: never, always, or cached (default omits the tag; the device applies its own default)")
	importKey.Flags().BoolVar(&importDryRun, "dry-run", false, "Show the planned action without mutating the token")

	command.AddCommand(generate, public, attest, deleteCommand, sign, challenge, importKey)
	return command
}

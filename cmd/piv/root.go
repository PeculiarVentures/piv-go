package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/PeculiarVentures/piv-go/internal/cli/app"
	"github.com/spf13/cobra"
)

var (
	version   = "dev"
	commit    = ""
	buildDate = ""
)

type cli struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer

	config    *app.ConfigStore
	formatter *app.Formatter
	mapper    *app.ErrorMapper
	info      *app.InfoService
	mutations *app.MutationService
	diag      *app.DiagService

	reader         string
	adapter        string
	timeout        string
	trace          string
	traceFile      string
	color          string
	jsonOutput     bool
	nonInteractive bool
	verbose        bool
}

func newCLI(stdin io.Reader, stdout io.Writer, stderr io.Writer) (*cli, error) {
	return newCLIWithDependencies(stdin, stdout, stderr, "", nil)
}

func newCLIWithDependencies(stdin io.Reader, stdout io.Writer, stderr io.Writer, configPath string, targets *app.TargetResolver) (*cli, error) {
	configStore, err := app.NewConfigStore(configPath)
	if err != nil {
		return nil, err
	}
	if targets == nil {
		targets = app.NewTargetResolver(nil, nil, stdin, stderr)
	}
	planner := app.NewOperationPlanner(stdin, stderr)
	return &cli{
		stdin:     stdin,
		stdout:    stdout,
		stderr:    stderr,
		config:    configStore,
		formatter: &app.Formatter{},
		mapper:    &app.ErrorMapper{},
		info:      app.NewInfoService(targets),
		mutations: app.NewMutationService(targets, planner, stdin, stderr),
		diag:      app.NewDiagService(targets, planner, stdin),
	}, nil
}

func (c *cli) rootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "piv",
		Short:         "PIV smart card command-line interface",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetOut(c.stdout)
	root.SetErr(c.stderr)
	root.PersistentFlags().StringVar(&c.reader, "reader", "", "Select a PC/SC reader by name")
	root.PersistentFlags().StringVar(&c.adapter, "adapter", "", "Adapter override: auto, standard, safenet, or yubikey")
	root.PersistentFlags().BoolVar(&c.jsonOutput, "json", false, "Emit JSON to stdout")
	root.PersistentFlags().BoolVar(&c.nonInteractive, "non-interactive", false, "Disable prompts and interactive reader selection")
	root.PersistentFlags().StringVar(&c.timeout, "timeout", "", "Command timeout, for example 5s or 30s")
	root.PersistentFlags().StringVar(&c.trace, "trace", "", "Trace level: off, apdu, ops, or all")
	root.PersistentFlags().StringVar(&c.traceFile, "trace-file", "stderr", "Trace destination path or stderr")
	root.PersistentFlags().BoolVar(&c.verbose, "verbose", false, "Include additional diagnostic detail")
	root.PersistentFlags().StringVar(&c.color, "color", "", "Color policy: auto, always, or never")

	root.AddCommand(
		c.newDevicesCommand(),
		c.newInfoCommand(),
		c.newSlotCommand(),
		c.newCertCommand(),
		c.newKeyCommand(),
		c.newPINCommand(),
		c.newPUKCommand(),
		c.newManagementCommand(),
		c.newSetupCommand(),
		c.newDoctorCommand(),
		c.newDiagCommand(),
		c.newConfigCommand(),
		c.newVersionCommand(),
	)
	root.InitDefaultCompletionCmd()
	return root
}

func (c *cli) execute(cmd *cobra.Command, action func(context.Context, app.GlobalOptions) (app.Response, error)) error {
	global, err := c.resolveGlobalOptions(cmd)
	if err != nil {
		mapped := c.mapper.Map(err)
		_ = c.formatter.WriteError(c.stdout, c.stderr, mapped, c.jsonOutput)
		return &app.ExitError{Code: mapped.ExitCode}
	}
	ctx := context.Background()
	if global.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, global.Timeout)
		defer cancel()
	}
	response, err := action(ctx, global)
	if err != nil {
		mapped := c.mapper.Map(err)
		_ = c.formatter.WriteError(c.stdout, c.stderr, mapped, global.JSON)
		return &app.ExitError{Code: mapped.ExitCode}
	}
	if err := c.formatter.WriteResponse(c.stdout, c.stderr, response, global); err != nil {
		mapped := c.mapper.Map(app.IOError("unable to render command output", "check stdout, stderr, and trace destinations", err))
		_ = c.formatter.WriteError(c.stdout, c.stderr, mapped, global.JSON)
		return &app.ExitError{Code: mapped.ExitCode}
	}
	return nil
}

func (c *cli) resolveGlobalOptions(cmd *cobra.Command) (app.GlobalOptions, error) {
	cfg, err := c.config.Load()
	if err != nil {
		return app.GlobalOptions{}, err
	}
	reader, readerOrigin := app.ResolveStringSetting(flagChanged(cmd, "reader"), c.reader, os.Getenv("PIV_READER"), cfg.DefaultReader, "")
	adapter, adapterOrigin := app.ResolveStringSetting(flagChanged(cmd, "adapter"), c.adapter, os.Getenv("PIV_ADAPTER"), cfg.Adapter, "auto")
	if adapter == "" {
		adapter = "auto"
		if adapterOrigin == "" {
			adapterOrigin = "auto"
		}
	}
	timeout, timeoutOrigin, err := app.ResolveDurationSetting(flagChanged(cmd, "timeout"), c.timeout, os.Getenv("PIV_TIMEOUT"), cfg.Timeout, 30*time.Second)
	if err != nil {
		return app.GlobalOptions{}, err
	}
	trace, traceOrigin, err := app.ResolveTraceSetting(flagChanged(cmd, "trace"), c.trace, os.Getenv("PIV_TRACE"), cfg.Trace, app.TraceOff)
	if err != nil {
		return app.GlobalOptions{}, err
	}
	color, colorOrigin := app.ResolveStringSetting(flagChanged(cmd, "color"), c.color, "", cfg.Color, "auto")
	certFmt, certOrigin := app.ResolveStringSetting(false, "", "", cfg.Export.CertFormat, "pem")
	publicFmt, publicOrigin := app.ResolveStringSetting(false, "", "", cfg.Export.PublicFormat, "pem")
	return app.GlobalOptions{
		Reader:              reader,
		ReaderOrigin:        readerOrigin,
		Adapter:             adapter,
		AdapterOrigin:       adapterOrigin,
		JSON:                c.jsonOutput,
		NonInteractive:      c.nonInteractive,
		Timeout:             timeout,
		TimeoutOrigin:       timeoutOrigin,
		Trace:               trace,
		TraceOrigin:         traceOrigin,
		TraceFile:           c.traceFile,
		Verbose:             c.verbose,
		Color:               color,
		ColorOrigin:         colorOrigin,
		DefaultCertFmt:      certFmt,
		DefaultCertOrigin:   certOrigin,
		DefaultPublicFmt:    publicFmt,
		DefaultPublicOrigin: publicOrigin,
	}, nil
}

func (c *cli) newConfigCommand() *cobra.Command {
	command := &cobra.Command{Use: "config", Short: "Manage CLI configuration"}
	showResolved := false
	show := &cobra.Command{
		Use:   "show",
		Short: "Show CLI configuration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(_ context.Context, global app.GlobalOptions) (app.Response, error) {
				cfg, err := c.config.Load()
				if err != nil {
					return app.Response{}, err
				}
				values := app.ConfigValues(cfg)
				if showResolved {
					values = c.resolvedConfigValues(global)
				}
				return app.Response{Command: "config-show", Target: app.TargetSummary{}, Result: app.ConfigShowResult{Path: c.config.Path(), Resolved: showResolved, Values: values}}, nil
			})
		},
	}
	show.Flags().BoolVar(&showResolved, "resolved", false, "Show resolved values and their origins")
	set := &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set one configuration value",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.execute(cmd, func(_ context.Context, _ app.GlobalOptions) (app.Response, error) {
				if err := c.config.Set(args[0], args[1]); err != nil {
					return app.Response{}, err
				}
				return app.Response{Command: "config-set", Target: app.TargetSummary{}, Result: app.MutationResult{Action: "config-set", Changed: true, Notes: []string{fmt.Sprintf("updated %s", args[0])}}}, nil
			})
		},
	}
	unset := &cobra.Command{
		Use:   "unset <key>",
		Short: "Unset one configuration value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.execute(cmd, func(_ context.Context, _ app.GlobalOptions) (app.Response, error) {
				if err := c.config.Unset(args[0]); err != nil {
					return app.Response{}, err
				}
				return app.Response{Command: "config-unset", Target: app.TargetSummary{}, Result: app.MutationResult{Action: "config-unset", Changed: true, Notes: []string{fmt.Sprintf("cleared %s", args[0])}}}, nil
			})
		},
	}
	path := &cobra.Command{
		Use:   "path",
		Short: "Show the config file path",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(_ context.Context, _ app.GlobalOptions) (app.Response, error) {
				return app.Response{Command: "config-path", Target: app.TargetSummary{}, Result: app.ConfigPathResult{Path: c.config.Path()}}, nil
			})
		},
	}
	command.AddCommand(show, set, unset, path)
	return command
}

func (c *cli) newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show CLI version information",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.execute(cmd, func(_ context.Context, _ app.GlobalOptions) (app.Response, error) {
				return app.Response{Command: "version", Target: app.TargetSummary{}, Result: app.VersionResult{Binary: "piv", Version: version, Commit: commit, BuildDate: buildDate}}, nil
			})
		},
	}
}

func (c *cli) resolvedConfigValues(global app.GlobalOptions) []app.ConfigValueView {
	values := []app.ConfigValueView{
		{Key: "adapter", Value: global.Adapter, Origin: global.AdapterOrigin},
		{Key: "color", Value: global.Color, Origin: global.ColorOrigin},
		{Key: "default-reader", Value: global.Reader, Origin: global.ReaderOrigin},
		{Key: "export.cert-format", Value: global.DefaultCertFmt, Origin: global.DefaultCertOrigin},
		{Key: "export.public-key-format", Value: global.DefaultPublicFmt, Origin: global.DefaultPublicOrigin},
		{Key: "timeout", Value: global.Timeout.String(), Origin: global.TimeoutOrigin},
		{Key: "trace", Value: string(global.Trace), Origin: global.TraceOrigin},
	}
	return values
}

func flagChanged(cmd *cobra.Command, name string) bool {
	flag := cmd.Flags().Lookup(name)
	if flag == nil {
		flag = cmd.InheritedFlags().Lookup(name)
	}
	return flag != nil && flag.Changed
}

func secretRequest(label string, prompt string, envOverride string, defaultEnv string, stdin bool) app.SecretRequest {
	envVar := defaultEnv
	if envOverride != "" {
		envVar = envOverride
	}
	return app.SecretRequest{Label: label, Prompt: prompt, EnvVar: envVar, ReadFromStdin: stdin}
}

func secretSourceUsed(envOverride string, defaultEnv string, stdin bool) bool {
	if stdin || envOverride != "" {
		return true
	}
	if defaultEnv == "" {
		return false
	}
	_, ok := os.LookupEnv(defaultEnv)
	return ok
}

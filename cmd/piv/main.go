package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/PeculiarVentures/piv-go/internal/cli/app"
)

func main() {
	cli, err := newCLI(os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(9)
	}
	if err := runCLI(cli, os.Args[1:]); err != nil {
		var exitErr *app.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(9)
	}
}

// runCLI executes the root command with the given args and normalizes
// pre-RunE Cobra errors (unknown flags, missing required flags, bad args)
// into the stable error contract: app.UsageError rendered through
// ErrorMapper->Formatter with the JSON envelope, returned as ExitError{1}.
// Errors already rendered by c.execute pass through untouched, and a
// *CLIError that escapes RunE keeps the existing defense-in-depth mapping.
func runCLI(cli *cli, args []string) error {
	root := cli.rootCommand()
	root.SetArgs(args)
	err := root.Execute()
	if err == nil {
		return nil
	}
	var exitErr *app.ExitError
	if errors.As(err, &exitErr) {
		return err
	}
	var cliErr *app.CLIError
	if errors.As(err, &cliErr) {
		// Defense in depth: any *CLIError that escapes RunE without going
		// through c.execute (e.g., a future parse-before-execute site) must
		// still render through ErrorMapper->Formatter with its mapped exit
		// code instead of falling through to raw exit 9.
		mapped := cli.mapper.Map(err)
		_ = cli.formatter.WriteError(cli.stdout, cli.stderr, mapped, wantsJSON(cli, args))
		code := mapped.ExitCode
		if code == 0 {
			code = 9
		}
		return &app.ExitError{Code: code}
	}
	usage := app.UsageError(err.Error(), "run with --help to inspect command usage")
	_ = cli.formatter.WriteError(cli.stdout, cli.stderr, usage, wantsJSON(cli, args))
	return &app.ExitError{Code: 1}
}

// wantsJSON reports whether error output must use the JSON envelope. The
// parsed persistent flag covers errors after flag parsing (bad args,
// missing required flags); scanning the raw args additionally covers flag
// parse failures where --json stands after the offending flag.
func wantsJSON(cli *cli, args []string) bool {
	if cli.jsonOutput {
		return true
	}
	for _, arg := range args {
		if arg == "--json" {
			return true
		}
		if value, ok := strings.CutPrefix(arg, "--json="); ok {
			if parsed, parseErr := strconv.ParseBool(value); parseErr == nil && parsed {
				return true
			}
		}
	}
	return false
}

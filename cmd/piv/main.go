package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/PeculiarVentures/piv-go/internal/cli/app"
)

func main() {
	cli, err := newCLI(os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(9)
	}
	if err := cli.rootCommand().Execute(); err != nil {
		var exitErr *app.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		// Defense in depth: any *CLIError that escapes RunE without going
		// through c.execute (e.g., a future parse-before-execute site) must
		// still render through ErrorMapper->Formatter with its mapped exit
		// code instead of falling through to raw exit 9.
		var cliErr *app.CLIError
		if errors.As(err, &cliErr) {
			mapped := (&app.ErrorMapper{}).Map(err)
			_ = (&app.Formatter{}).WriteError(cli.stdout, cli.stderr, mapped, cli.jsonOutput)
			code := mapped.ExitCode
			if code == 0 {
				code = 9
			}
			os.Exit(code)
		}
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(9)
	}
}

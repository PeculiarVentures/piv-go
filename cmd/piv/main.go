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
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(9)
	}
}

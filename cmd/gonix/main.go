package main

import (
	"fmt"
	"os"

	"github.com/nix-community/go-nix/cmd/gonix/drv"
	"github.com/nix-community/go-nix/cmd/gonix/fast_build"
	"github.com/nix-community/go-nix/cmd/gonix/nar"
)

const usage = `gonix — go-nix command line tool

Usage:
  gonix nar <cat|dump-path|ls> ...
  gonix drv <show> ...
  gonix fast-build [-j N] [--socket PATH]

Run "gonix <command> --help" for command-specific usage.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error

	switch os.Args[1] {
	case "nar":
		err = nar.Main(os.Args[2:])
	case "drv":
		err = drv.Main(os.Args[2:])
	case "fast-build":
		err = fast_build.Main(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stderr, usage)

		return
	default:
		fmt.Fprintf(os.Stderr, "gonix: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "gonix: %v\n", err)
		os.Exit(1)
	}
}

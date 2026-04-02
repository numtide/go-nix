package drv

import (
	"flag"
	"fmt"

	derivationStore "github.com/nix-community/go-nix/pkg/derivation/store"
)

const usage = `Usage:
  gonix drv show [--drv-store URI] [--format aterm|json|json-pretty] <drv-path>
`

// Main dispatches the drv subcommand. args excludes the leading "gonix drv".
func Main(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing subcommand\n\n%s", usage)
	}

	switch args[0] {
	case "show":
		fs := flag.NewFlagSet("drv show", flag.ExitOnError)
		storeURI := fs.String("drv-store", "", "store URI to read derivations from")
		format := fs.String("format", "json-pretty", "output format: aterm, json, or json-pretty")
		fs.Usage = func() {
			fmt.Fprint(fs.Output(), "Usage: gonix drv show [--drv-store URI] [--format FORMAT] <drv-path>\n")
			fs.PrintDefaults()
		}

		_ = fs.Parse(args[1:])
		if fs.NArg() != 1 {
			fs.Usage()

			return fmt.Errorf("show requires <drv-path>")
		}

		drvStore, err := derivationStore.NewFromURI(*storeURI)
		if err != nil {
			return fmt.Errorf("creating store from URI: %w", err)
		}

		return (&ShowCmd{Drv: fs.Arg(0), Format: *format}).Run(drvStore)

	case "-h", "--help", "help":
		fmt.Print(usage)

		return nil

	default:
		return fmt.Errorf("unknown subcommand %q\n\n%s", args[0], usage)
	}
}

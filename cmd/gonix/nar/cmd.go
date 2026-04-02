package nar

import (
	"flag"
	"fmt"
)

const usage = `Usage:
  gonix nar cat <nar-file> <path>
  gonix nar dump-path <path>
  gonix nar ls [-R] <nar-file> [path]
`

// Main dispatches the nar subcommand. args excludes the leading "gonix nar".
func Main(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("missing subcommand\n\n%s", usage)
	}

	switch args[0] {
	case "cat":
		fs := flag.NewFlagSet("nar cat", flag.ExitOnError)
		fs.Usage = func() { fmt.Fprint(fs.Output(), "Usage: gonix nar cat <nar-file> <path>\n") }

		_ = fs.Parse(args[1:])
		if fs.NArg() != 2 {
			fs.Usage()

			return fmt.Errorf("cat requires <nar-file> and <path>")
		}

		return (&CatCmd{Nar: fs.Arg(0), Path: fs.Arg(1)}).Run()

	case "dump-path":
		fs := flag.NewFlagSet("nar dump-path", flag.ExitOnError)
		fs.Usage = func() { fmt.Fprint(fs.Output(), "Usage: gonix nar dump-path <path>\n") }

		_ = fs.Parse(args[1:])
		if fs.NArg() != 1 {
			fs.Usage()

			return fmt.Errorf("dump-path requires <path>")
		}

		return (&DumpPathCmd{Path: fs.Arg(0)}).Run()

	case "ls":
		fs := flag.NewFlagSet("nar ls", flag.ExitOnError)
		recursive := fs.Bool("R", false, "list recursively, not just the current level")
		fs.Usage = func() {
			fmt.Fprint(fs.Output(), "Usage: gonix nar ls [-R] <nar-file> [path]\n")
			fs.PrintDefaults()
		}

		_ = fs.Parse(args[1:])
		if fs.NArg() < 1 || fs.NArg() > 2 {
			fs.Usage()

			return fmt.Errorf("ls requires <nar-file> and optionally [path]")
		}

		path := "/"
		if fs.NArg() == 2 {
			path = fs.Arg(1)
		}

		return (&LsCmd{Nar: fs.Arg(0), Path: path, Recursive: *recursive}).Run()

	case "-h", "--help", "help":
		fmt.Print(usage)

		return nil

	default:
		return fmt.Errorf("unknown subcommand %q\n\n%s", args[0], usage)
	}
}

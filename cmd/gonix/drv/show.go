package drv

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/nix-community/go-nix/pkg/derivation"
)

type ShowCmd struct {
	Drv    string
	Format string
}

func (cmd *ShowCmd) Run(drvStore derivation.Store) error {
	drv, err := drvStore.Get(context.Background(), cmd.Drv)
	if err != nil {
		return err
	}

	// `nix show-derivation` sorts JSON keys alphabetically; encoding/json
	// preserves struct field order, so this matches the previous behaviour.
	switch cmd.Format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		err = enc.Encode(drv)
	case "json-pretty":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(drv)
	case "aterm":
		err = drv.WriteDerivation(os.Stdout)
	default:
		err = fmt.Errorf("invalid format: %v", cmd.Format)
	}

	return err
}

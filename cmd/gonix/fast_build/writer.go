package fast_build

import (
	"encoding/json"
	"fmt"
	"io"
)

// processOutput drains the results channel and writes JSON Lines to w.
func processOutput(results <-chan BuildOutput, w io.Writer) error {
	failures := 0

	enc := json.NewEncoder(w)

	for result := range results {
		if result.Status == statusFailed {
			failures += 1
		}

		if err := enc.Encode(result); err != nil {
			return err
		}
	}

	if failures > 0 {
		return fmt.Errorf("%d build failures", failures)
	}

	return nil
}

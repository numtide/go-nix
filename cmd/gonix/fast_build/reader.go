package fast_build

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
)

// ReadJobs reads eval jobs from stdin, deserializes them from JSON, and sends valid jobs to the work channel.
// It skips malformed JSON, eval errors, and missing drvPaths.
// Exits early if the context is cancelled or if an error happens while scanning stdin.
// The work channel is closed upon completion.
func ReadJobs(
	ctx context.Context,
	stdin io.Reader,
	workCh chan<- EvalJob,
	logger *log.Logger,
) error {
	// create a new logger specific for this function
	logger = log.New(logger.Writer(), "[ReadJobs] ", log.Flags())

	// close the work channel when we're done
	defer close(workCh)

	// start processing stdin
	scanner := bufio.NewScanner(stdin)
	for scanner.Scan() {
		var job EvalJob

		// unmarshal error
		if err := json.Unmarshal(scanner.Bytes(), &job); err != nil {
			logger.Printf("warning: skipping malformed JSON line: %v", err)

			continue
		}

		// eval error
		if job.Error != "" {
			logger.Printf("warning: eval error [%s]: %s", job.Attr, job.Error)

			continue
		}

		// no drvPath which means it can't be built
		if job.DrvPath == "" {
			logger.Printf("warning: skipping line with no drvPath: %s", job.Attr)

			continue
		}

		// offer the job to the work channel or exit early because the context was cancelled
		select {
		case workCh <- job:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// catch any scanner errors
	return scanner.Err()
}

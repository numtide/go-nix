package fast_build

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"
)

// Cmd is the kong command for building derivations from nix-eval-jobs output.
type Cmd struct {
	MaxJobs int    `kong:"short='j',default='4',help='Number of parallel build connections'"`
	Socket  string `kong:"default='/nix/var/nix/daemon-socket/socket',help='Nix daemon socket path'"`
}

// Run executes the build pipeline.
func (cmd *Cmd) Run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.Default()

	jobCh := make(chan EvalJob, 128)
	outputCh := make(chan BuildOutput, 128)

	// an errgroup for asynchronously reading from stdin and building
	// inherits from the main context to detect cancellation
	// if the reader or any worker fails, the shared producerCtx will ensure any remaining tasks exit early
	producers, producerCtx := errgroup.WithContext(ctx)

	// start reading from stdin
	producers.Go(func() error {
		return ReadJobs(producerCtx, os.Stdin, jobCh, logger)
	})

	// fire up MaxJobs workers to process from jobCh
	for range cmd.MaxJobs {
		producers.Go(func() error {
			return buildWorker(producerCtx, cmd.Socket, jobCh, outputCh, logger)
		})
	}

	// close results channel after all producers finish
	go func() {
		_ = producers.Wait()

		close(outputCh)
	}()

	// create a separate errgroup for processing results
	// inherits from the main context to detect cancellation
	consumers, _ := errgroup.WithContext(ctx)

	consumers.Go(func() error {
		return processOutput(outputCh, os.Stdout)
	})

	// wait for everything to complete
	produceErr := producers.Wait()
	consumeErr := consumers.Wait()

	// check for errors
	if produceErr != nil {
		return produceErr
	}

	if consumeErr != nil {
		return consumeErr
	}

	return nil
}

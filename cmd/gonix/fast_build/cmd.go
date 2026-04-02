package fast_build

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/nix-community/go-nix/pkg/daemon"
	"golang.org/x/sync/errgroup"
)

// Main parses fast-build flags and runs the build pipeline. args excludes the
// leading "gonix fast-build".
func Main(args []string) error {
	fs := flag.NewFlagSet("fast-build", flag.ExitOnError)
	cmd := &Cmd{}
	fs.IntVar(&cmd.MaxJobs, "j", 4, "number of parallel build connections")
	fs.StringVar(&cmd.Socket, "socket", daemon.DefaultSocketPath, "nix daemon socket path")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage: gonix fast-build [-j N] [--socket PATH]\n\n"+
			"Reads nix-eval-jobs JSON from stdin, builds in parallel.\n\n")
		fs.PrintDefaults()
	}

	_ = fs.Parse(args)
	if fs.NArg() > 0 {
		fs.Usage()

		return fmt.Errorf("fast-build takes no positional arguments (got %q)", fs.Args())
	}

	return cmd.Run()
}

// Cmd holds fast-build options for building derivations from nix-eval-jobs output.
type Cmd struct {
	MaxJobs int
	Socket  string
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

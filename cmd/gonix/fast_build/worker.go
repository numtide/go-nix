package fast_build

import (
	"context"
	"fmt"
	"log"
	"path"
	"strings"

	"github.com/nix-community/go-nix/pkg/daemon"
)

const (
	statusBuilt       = "built"
	statusSubstituted = "substituted"
	statusCached      = "cached"
	statusFailed      = "failed"
)

// buildWorker connects to the daemon and builds derivations from the work channel,
// sending results to the results channel. It owns its daemon connection.
func buildWorker(
	ctx context.Context,
	socketPath string,
	workCh <-chan EvalJob,
	resultsCh chan<- BuildOutput,
	log *log.Logger,
) error {
	client, err := daemon.Connect(ctx, socketPath)
	if err != nil {
		return fmt.Errorf("connecting to daemon: %w", err)
	}

	defer func() { _ = client.Close() }()

	for job := range workCh {
		result := buildOne(ctx, client, job, log)

		select {
		case resultsCh <- result:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

func buildOne(
	ctx context.Context,
	client *daemon.Client,
	job EvalJob,
	logger *log.Logger,
) BuildOutput {
	// create a new logger specific for the attribute we're building
	logger = log.New(logger.Writer(), fmt.Sprintf("[%s] ", job.Attr), log.Flags())

	out := BuildOutput{
		Attr:    job.Attr,
		DrvPath: job.DrvPath,
	}

	// create a logger that forwards daemon log lines to the build logger
	daemonLogger := daemon.WithLogger(func(msg daemon.LogMessage) {
		var text string

		switch {
		case msg.Type == daemon.LogNext && msg.Text != "":
			text = msg.Text
		case msg.Type == daemon.LogResult && msg.Result != nil &&
			msg.Result.Type == daemon.ResBuildLogLine &&
			len(msg.Result.Fields) > 0 && !msg.Result.Fields[0].IsInt:
			text = msg.Result.Fields[0].String
		}

		if text != "" {
			logger.Print(text)
		}
	})

	// protect against GC before building
	if err := client.AddTempRoot(ctx, job.DrvPath, daemonLogger); err != nil {
		out.Status = statusFailed
		out.Error = fmt.Sprintf("AddTempRoot: %v", err)

		return out
	}

	// build all outputs (daemon protocol uses ! separator for derived paths)
	results, err := client.BuildPathsWithResults(
		ctx,
		[]string{job.DrvPath + "!*"},
		daemon.BuildModeNormal,
		daemonLogger,
	)
	if err != nil {
		out.Status = statusFailed
		out.Error = err.Error()

		return out
	}

	if len(results) == 0 {
		out.Status = statusFailed
		out.Error = "no build results returned"

		return out
	}

	// use the first result (we build one derivation at a time)
	br := results[0]
	out.StartTime = br.StartTime
	out.StopTime = br.StopTime

	out.Status = MapBuildStatus(br.Status)
	if out.Status == statusFailed {
		out.Error = br.ErrorMsg

		return out
	}

	// populate output paths from realisations
	// the map key is a realisation ID like "sha256:hash!outputName",
	// so we extract the output name from after the last "!"
	storeDir := storeDirFromPath(job.DrvPath)
	out.Outputs = make(map[string]string, len(br.BuiltOutputs))

	for id, realisation := range br.BuiltOutputs {
		outputName := id
		if idx := strings.LastIndex(id, "!"); idx >= 0 {
			outputName = id[idx+1:]
		}

		outPath := realisation.OutPath
		if !strings.HasPrefix(outPath, "/") {
			outPath = storeDir + "/" + outPath
		}

		out.Outputs[outputName] = outPath
	}

	return out
}

// MapBuildStatus translates a daemon BuildStatus into a human-readable status string.
func MapBuildStatus(s daemon.BuildStatus) string {
	switch s {
	case daemon.BuildStatusBuilt:
		return statusBuilt
	case daemon.BuildStatusSubstituted:
		return statusSubstituted
	case daemon.BuildStatusAlreadyValid, daemon.BuildStatusResolvesToAlreadyValid:
		return statusCached
	case daemon.BuildStatusPermanentFailure,
		daemon.BuildStatusInputRejected,
		daemon.BuildStatusOutputRejected,
		daemon.BuildStatusTransientFailure,
		daemon.BuildStatusCachedFailure,
		daemon.BuildStatusTimedOut,
		daemon.BuildStatusMiscFailure,
		daemon.BuildStatusDependencyFailed,
		daemon.BuildStatusLogLimitExceeded,
		daemon.BuildStatusNotDeterministic,
		daemon.BuildStatusNoSubstituters:
		return statusFailed
	default:
		return statusFailed
	}
}

// storeDirFromPath extracts the store directory from a full store path.
// For example, "/nix/store/abc-foo.drv" yields "/nix/store".
func storeDirFromPath(p string) string {
	return path.Dir(p)
}

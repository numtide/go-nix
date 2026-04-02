package fast_build_test

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"github.com/nix-community/go-nix/cmd/gonix/fast_build"
	"github.com/stretchr/testify/require"
)

func collectJobs(t *testing.T, input string) ([]fast_build.EvalJob, string) {
	t.Helper()

	work := make(chan fast_build.EvalJob, 64)

	var errBuf bytes.Buffer

	logger := log.New(&errBuf, "", 0)

	err := fast_build.ReadJobs(t.Context(), strings.NewReader(input), work, logger)
	require.NoError(t, err)

	var jobs []fast_build.EvalJob
	for job := range work {
		jobs = append(jobs, job)
	}

	return jobs, errBuf.String()
}

func TestReadJobs_ValidLines(t *testing.T) {
	rq := require.New(t)
	input := `{"attr":"foo.x86_64-linux","drvPath":"/nix/store/abc-foo.drv","name":"foo"}
{"attr":"bar.x86_64-linux","drvPath":"/nix/store/def-bar.drv","name":"bar"}
`
	jobs, stderr := collectJobs(t, input)

	rq.Empty(stderr)
	rq.Len(jobs, 2)

	rq.EqualValues([]fast_build.EvalJob{
		{
			Name:    "foo",
			Attr:    "foo.x86_64-linux",
			DrvPath: "/nix/store/abc-foo.drv",
		},
		{
			Name:    "bar",
			Attr:    "bar.x86_64-linux",
			DrvPath: "/nix/store/def-bar.drv",
		},
	}, jobs)
}

func TestReadJobs_EvalError(t *testing.T) {
	rq := require.New(t)
	input := `{"attr":"broken","error":"attribute 'broken' missing"}
`
	jobs, stderr := collectJobs(t, input)

	rq.Empty(jobs)
	rq.Contains(stderr, "warning: eval error [broken]")
	rq.Contains(stderr, "attribute 'broken' missing")
}

func TestReadJobs_MalformedJSON(t *testing.T) {
	input := "not json at all\n"
	jobs, stderr := collectJobs(t, input)

	require.Empty(t, jobs)
	require.Contains(t, stderr, "warning: skipping malformed JSON line")
}

func TestReadJobs_MissingDrvPath(t *testing.T) {
	input := `{"attr":"nodrvpath","name":"test"}
`
	jobs, stderr := collectJobs(t, input)

	require.Empty(t, jobs)
	require.Contains(t, stderr, "warning: skipping line with no drvPath")
}

func TestReadJobs_EmptyInput(t *testing.T) {
	jobs, stderr := collectJobs(t, "")

	require.Empty(t, jobs)
	require.Empty(t, stderr)
}

func TestReadJobs_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	// unbuffered channel so the send will block and hit the cancelled context
	work := make(chan fast_build.EvalJob)

	var errBuf bytes.Buffer

	logger := log.New(&errBuf, "", 0)

	input := `{"attr":"foo","drvPath":"/nix/store/abc-foo.drv"}
`
	err := fast_build.ReadJobs(ctx, strings.NewReader(input), work, logger)
	require.ErrorIs(t, err, context.Canceled)
}

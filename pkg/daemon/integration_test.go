//go:build integration

package daemon_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const defaultSocket = "/nix/var/nix/daemon-socket/socket"

// connectOrSkip connects to the daemon or skips the test.
func connectOrSkip(t *testing.T, opts ...daemon.ConnectOption) *daemon.Client {
	t.Helper()

	client, err := daemon.Connect(defaultSocket, opts...)
	if err != nil {
		t.Skipf("cannot connect to Nix daemon: %v", err)
	}

	t.Cleanup(func() { client.Close() })

	return client
}

// anyValidPath returns an arbitrary valid store path from the daemon, or
// skips the test if the store is empty.
func anyValidPath(t *testing.T, client *daemon.Client) string {
	t.Helper()

	paths, err := client.QueryAllValidPaths(context.Background())
	require.NoError(t, err)
	require.True(t, len(paths) > 0, "store has no valid paths")

	return paths[0]
}

// --- Connection & Handshake ---

func TestIntegrationConnect(t *testing.T) {
	client := connectOrSkip(t)

	info := client.Info()
	assert.Equal(t, daemon.ProtocolVersion, info.Version)
	assert.NotEmpty(t, info.DaemonNixVersion)
	t.Logf("Nix version: %s, trust: %d", info.DaemonNixVersion, info.Trust)
}

func TestIntegrationSetOptions(t *testing.T) {
	client := connectOrSkip(t)

	settings := daemon.DefaultClientSettings()
	err := client.SetOptions(context.Background(), settings)
	assert.NoError(t, err)
}

func TestIntegrationLogChannel(t *testing.T) {
	logs := make(chan daemon.LogMessage, 100)
	client := connectOrSkip(t, daemon.WithLogChannel(logs))

	assert.NotNil(t, client.Logs())

	// Run an operation that may produce log messages.
	_, err := client.QueryAllValidPaths(context.Background())
	assert.NoError(t, err)
}

// --- Validity & Path Queries ---

func TestIntegrationIsValidPath(t *testing.T) {
	client := connectOrSkip(t)

	// A path that definitely doesn't exist.
	valid, err := client.IsValidPath(context.Background(), "/nix/store/00000000000000000000000000000000-nonexistent")
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestIntegrationIsValidPathTrue(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	valid, err := client.IsValidPath(context.Background(), path)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestIntegrationQueryAllValidPaths(t *testing.T) {
	client := connectOrSkip(t)

	paths, err := client.QueryAllValidPaths(context.Background())
	assert.NoError(t, err)
	assert.True(t, len(paths) > 0)
	t.Logf("Store has %d valid paths", len(paths))
}

func TestIntegrationQueryValidPaths(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	valid, err := client.QueryValidPaths(context.Background(), []string{path}, false)
	assert.NoError(t, err)
	assert.Contains(t, valid, path)
}

func TestIntegrationQueryValidPathsSubset(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	bogus := "/nix/store/00000000000000000000000000000000-nonexistent"
	valid, err := client.QueryValidPaths(context.Background(), []string{path, bogus}, false)
	assert.NoError(t, err)
	assert.Contains(t, valid, path)
	assert.NotContains(t, valid, bogus)
}

// --- Path Info ---

func TestIntegrationQueryPathInfo(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	info, err := client.QueryPathInfo(context.Background(), path)
	assert.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, path, info.StorePath)
	assert.NotEmpty(t, info.NarHash)
	assert.True(t, info.NarSize > 0)

	t.Logf("Path: %s", info.StorePath)
	t.Logf("  Deriver: %s", info.Deriver)
	t.Logf("  NarHash: %s", info.NarHash)
	t.Logf("  NarSize: %d", info.NarSize)
	t.Logf("  References: %d", len(info.References))
	t.Logf("  Sigs: %d", len(info.Sigs))
	t.Logf("  CA: %q", info.CA)
}

func TestIntegrationQueryPathInfoNotFound(t *testing.T) {
	client := connectOrSkip(t)

	info, err := client.QueryPathInfo(context.Background(), "/nix/store/00000000000000000000000000000000-nonexistent")
	assert.NoError(t, err)
	assert.Nil(t, info)
}

func TestIntegrationQueryPathFromHashPart(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	// Extract hash part: /nix/store/<hash>-<name> -> <hash>
	hashPart := strings.TrimPrefix(path, "/nix/store/")
	if idx := strings.Index(hashPart, "-"); idx > 0 {
		hashPart = hashPart[:idx]
	}

	result, err := client.QueryPathFromHashPart(context.Background(), hashPart)
	assert.NoError(t, err)
	assert.Equal(t, path, result)
}

func TestIntegrationQueryPathFromHashPartNotFound(t *testing.T) {
	client := connectOrSkip(t)

	result, err := client.QueryPathFromHashPart(context.Background(), "00000000000000000000000000000000")
	assert.NoError(t, err)
	assert.Empty(t, result)
}

// --- References & Derivers ---

func TestIntegrationQueryReferrers(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	referrers, err := client.QueryReferrers(context.Background(), path)
	assert.NoError(t, err)
	// Every path has at least itself or some referrers; we just check no error.
	t.Logf("Path %s has %d referrers", path, len(referrers))
}

func TestIntegrationQueryValidDerivers(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	derivers, err := client.QueryValidDerivers(context.Background(), path)
	assert.NoError(t, err)
	t.Logf("Path %s has %d valid derivers", path, len(derivers))
}

// --- Substitutable & Missing ---

func TestIntegrationQuerySubstitutablePaths(t *testing.T) {
	client := connectOrSkip(t)

	// Query with a bogus path — should return empty (no substituters for it).
	substitutable, err := client.QuerySubstitutablePaths(context.Background(), []string{
		"/nix/store/00000000000000000000000000000000-nonexistent",
	})
	assert.NoError(t, err)
	assert.Empty(t, substitutable)
}

func TestIntegrationQueryMissing(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	missing, err := client.QueryMissing(context.Background(), []string{path})
	assert.NoError(t, err)
	require.NotNil(t, missing)
	// A valid path should not appear in WillBuild or Unknown.
	assert.NotContains(t, missing.WillBuild, path)
	assert.NotContains(t, missing.Unknown, path)
	t.Logf("QueryMissing: willBuild=%d willSubstitute=%d unknown=%d downloadSize=%d narSize=%d",
		len(missing.WillBuild),
		len(missing.WillSubstitute),
		len(missing.Unknown),
		missing.DownloadSize,
		missing.NarSize,
	)
}

// --- Derivation Output Map ---

func TestIntegrationQueryDerivationOutputMap(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	// Find a path that has a deriver so we can query its output map.
	info, err := client.QueryPathInfo(context.Background(), path)
	require.NoError(t, err)
	require.NotNil(t, info)

	if info.Deriver == "" {
		t.Skip("first valid path has no deriver, skipping output map test")
	}

	// Check that the deriver is actually valid before querying.
	valid, err := client.IsValidPath(context.Background(), info.Deriver)
	require.NoError(t, err)

	if !valid {
		t.Skip("deriver path is not valid in store, skipping output map test")
	}

	outputs, err := client.QueryDerivationOutputMap(context.Background(), info.Deriver)
	assert.NoError(t, err)
	assert.True(t, len(outputs) > 0, "deriver should have at least one output")

	for name, outPath := range outputs {
		t.Logf("  output %q -> %s", name, outPath)
	}
}

// --- NAR Streaming ---

func TestIntegrationNarFromPath(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	// Get expected NAR size.
	info, err := client.QueryPathInfo(context.Background(), path)
	require.NoError(t, err)
	require.NotNil(t, info)

	rc, err := client.NarFromPath(context.Background(), path)
	assert.NoError(t, err)
	require.NotNil(t, rc)

	// Read all NAR data.
	data, err := io.ReadAll(rc)
	assert.NoError(t, err)
	assert.NoError(t, rc.Close())

	// NAR data should start with the NAR magic header.
	assert.True(t, len(data) > 0, "NAR data should not be empty")
	assert.True(t, bytes.Contains(data[:min(len(data), 64)], []byte("nix-archive-1")),
		"NAR data should start with nix-archive-1 magic")

	// NAR size should match what PathInfo reported.
	assert.Equal(t, info.NarSize, uint64(len(data)),
		"NAR size should match PathInfo.NarSize")

	t.Logf("NAR from %s: %d bytes", path, len(data))
}

// --- GC Roots ---

func TestIntegrationFindRoots(t *testing.T) {
	client := connectOrSkip(t)

	roots, err := client.FindRoots(context.Background())
	assert.NoError(t, err)
	assert.True(t, len(roots) > 0, "should have at least one GC root")
	t.Logf("Found %d GC roots", len(roots))
}

func TestIntegrationAddTempRoot(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	err := client.AddTempRoot(context.Background(), path)
	assert.NoError(t, err)
}

// --- Verify & Optimise ---

func TestIntegrationVerifyStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping store verification in short mode")
	}

	client := connectOrSkip(t)

	// checkContents=false, repair=false — just a quick metadata check.
	errorsFound, err := client.VerifyStore(context.Background(), false, false)
	assert.NoError(t, err)
	t.Logf("VerifyStore found errors: %v", errorsFound)
}

// --- Build Operations ---

func TestIntegrationBuildPaths(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	// Building an already-valid path should succeed immediately.
	err := client.BuildPaths(context.Background(), []string{path}, daemon.BuildModeNormal)
	assert.NoError(t, err)
}

func TestIntegrationBuildPathsWithResults(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	results, err := client.BuildPathsWithResults(context.Background(), []string{path}, daemon.BuildModeNormal)
	assert.NoError(t, err)

	for i, br := range results {
		t.Logf("BuildResult[%d]: status=%s timesBuilt=%d", i, br.Status, br.TimesBuilt)
	}
}

func TestIntegrationEnsurePath(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	err := client.EnsurePath(context.Background(), path)
	assert.NoError(t, err)
}

// --- Sequential Operations ---
// Verify that multiple operations work on the same connection sequentially.

func TestIntegrationSequentialOperations(t *testing.T) {
	client := connectOrSkip(t)
	ctx := context.Background()

	// Operation 1: QueryAllValidPaths
	allPaths, err := client.QueryAllValidPaths(ctx)
	require.NoError(t, err)
	require.True(t, len(allPaths) > 0)
	path := allPaths[0]

	// Operation 2: IsValidPath
	valid, err := client.IsValidPath(ctx, path)
	require.NoError(t, err)
	assert.True(t, valid)

	// Operation 3: QueryPathInfo
	info, err := client.QueryPathInfo(ctx, path)
	require.NoError(t, err)
	require.NotNil(t, info)

	// Operation 4: NarFromPath + read + close
	rc, err := client.NarFromPath(ctx, path)
	require.NoError(t, err)
	_, err = io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())

	// Operation 5: QueryMissing (after releasing the NAR reader)
	_, err = client.QueryMissing(ctx, []string{path})
	require.NoError(t, err)

	// Operation 6: FindRoots
	_, err = client.FindRoots(ctx)
	require.NoError(t, err)

	t.Logf("6 sequential operations completed successfully on the same connection")
}

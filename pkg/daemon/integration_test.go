//go:build integration

package daemon_test

import (
	"bytes"
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

	result := <-client.QueryAllValidPaths()
	require.NoError(t, result.Err)
	require.True(t, len(result.Value) > 0, "store has no valid paths")

	return result.Value[0]
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
	result := <-client.SetOptions(settings)
	assert.NoError(t, result.Err)
}

func TestIntegrationLogChannel(t *testing.T) {
	logs := make(chan daemon.LogMessage, 100)
	client := connectOrSkip(t, daemon.WithLogChannel(logs))

	assert.NotNil(t, client.Logs())

	// Run an operation that may produce log messages.
	result := <-client.QueryAllValidPaths()
	assert.NoError(t, result.Err)
}

// --- Validity & Path Queries ---

func TestIntegrationIsValidPath(t *testing.T) {
	client := connectOrSkip(t)

	// A path that definitely doesn't exist.
	result := <-client.IsValidPath("/nix/store/00000000000000000000000000000000-nonexistent")
	assert.NoError(t, result.Err)
	assert.False(t, result.Value)
}

func TestIntegrationIsValidPathTrue(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	result := <-client.IsValidPath(path)
	assert.NoError(t, result.Err)
	assert.True(t, result.Value)
}

func TestIntegrationQueryAllValidPaths(t *testing.T) {
	client := connectOrSkip(t)

	result := <-client.QueryAllValidPaths()
	assert.NoError(t, result.Err)
	assert.True(t, len(result.Value) > 0)
	t.Logf("Store has %d valid paths", len(result.Value))
}

func TestIntegrationQueryValidPaths(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	result := <-client.QueryValidPaths([]string{path}, false)
	assert.NoError(t, result.Err)
	assert.Contains(t, result.Value, path)
}

func TestIntegrationQueryValidPathsSubset(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	bogus := "/nix/store/00000000000000000000000000000000-nonexistent"
	result := <-client.QueryValidPaths([]string{path, bogus}, false)
	assert.NoError(t, result.Err)
	assert.Contains(t, result.Value, path)
	assert.NotContains(t, result.Value, bogus)
}

// --- Path Info ---

func TestIntegrationQueryPathInfo(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	result := <-client.QueryPathInfo(path)
	assert.NoError(t, result.Err)
	require.NotNil(t, result.Value)

	info := result.Value
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

	result := <-client.QueryPathInfo("/nix/store/00000000000000000000000000000000-nonexistent")
	assert.NoError(t, result.Err)
	assert.Nil(t, result.Value)
}

func TestIntegrationQueryPathFromHashPart(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	// Extract hash part: /nix/store/<hash>-<name> → <hash>
	hashPart := strings.TrimPrefix(path, "/nix/store/")
	if idx := strings.Index(hashPart, "-"); idx > 0 {
		hashPart = hashPart[:idx]
	}

	result := <-client.QueryPathFromHashPart(hashPart)
	assert.NoError(t, result.Err)
	assert.Equal(t, path, result.Value)
}

func TestIntegrationQueryPathFromHashPartNotFound(t *testing.T) {
	client := connectOrSkip(t)

	result := <-client.QueryPathFromHashPart("00000000000000000000000000000000")
	assert.NoError(t, result.Err)
	assert.Empty(t, result.Value)
}

// --- References & Derivers ---

func TestIntegrationQueryReferrers(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	result := <-client.QueryReferrers(path)
	assert.NoError(t, result.Err)
	// Every path has at least itself or some referrers; we just check no error.
	t.Logf("Path %s has %d referrers", path, len(result.Value))
}

func TestIntegrationQueryValidDerivers(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	result := <-client.QueryValidDerivers(path)
	assert.NoError(t, result.Err)
	t.Logf("Path %s has %d valid derivers", path, len(result.Value))
}

// --- Substitutable & Missing ---

func TestIntegrationQuerySubstitutablePaths(t *testing.T) {
	client := connectOrSkip(t)

	// Query with a bogus path — should return empty (no substituters for it).
	result := <-client.QuerySubstitutablePaths([]string{
		"/nix/store/00000000000000000000000000000000-nonexistent",
	})
	assert.NoError(t, result.Err)
	assert.Empty(t, result.Value)
}

func TestIntegrationQueryMissing(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	result := <-client.QueryMissing([]string{path})
	assert.NoError(t, result.Err)
	require.NotNil(t, result.Value)
	// A valid path should not appear in WillBuild or Unknown.
	assert.NotContains(t, result.Value.WillBuild, path)
	assert.NotContains(t, result.Value.Unknown, path)
	t.Logf("QueryMissing: willBuild=%d willSubstitute=%d unknown=%d downloadSize=%d narSize=%d",
		len(result.Value.WillBuild),
		len(result.Value.WillSubstitute),
		len(result.Value.Unknown),
		result.Value.DownloadSize,
		result.Value.NarSize,
	)
}

// --- Derivation Output Map ---

func TestIntegrationQueryDerivationOutputMap(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	// Find a path that has a deriver so we can query its output map.
	infoResult := <-client.QueryPathInfo(path)
	require.NoError(t, infoResult.Err)
	require.NotNil(t, infoResult.Value)

	if infoResult.Value.Deriver == "" {
		t.Skip("first valid path has no deriver, skipping output map test")
	}

	// Check that the deriver is actually valid before querying.
	validResult := <-client.IsValidPath(infoResult.Value.Deriver)
	require.NoError(t, validResult.Err)

	if !validResult.Value {
		t.Skip("deriver path is not valid in store, skipping output map test")
	}

	result := <-client.QueryDerivationOutputMap(infoResult.Value.Deriver)
	assert.NoError(t, result.Err)
	assert.True(t, len(result.Value) > 0, "deriver should have at least one output")

	for name, outPath := range result.Value {
		t.Logf("  output %q -> %s", name, outPath)
	}
}

// --- NAR Streaming ---

func TestIntegrationNarFromPath(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	// Get expected NAR size.
	infoResult := <-client.QueryPathInfo(path)
	require.NoError(t, infoResult.Err)
	require.NotNil(t, infoResult.Value)

	narResult := <-client.NarFromPath(path)
	assert.NoError(t, narResult.Err)
	require.NotNil(t, narResult.Value)

	// Read all NAR data.
	data, err := io.ReadAll(narResult.Value)
	assert.NoError(t, err)
	assert.NoError(t, narResult.Value.Close())

	// NAR data should start with the NAR magic header.
	assert.True(t, len(data) > 0, "NAR data should not be empty")
	assert.True(t, bytes.Contains(data[:min(len(data), 64)], []byte("nix-archive-1")),
		"NAR data should start with nix-archive-1 magic")

	// NAR size should match what PathInfo reported.
	assert.Equal(t, infoResult.Value.NarSize, uint64(len(data)),
		"NAR size should match PathInfo.NarSize")

	t.Logf("NAR from %s: %d bytes", path, len(data))
}

// --- GC Roots ---

func TestIntegrationFindRoots(t *testing.T) {
	client := connectOrSkip(t)

	result := <-client.FindRoots()
	assert.NoError(t, result.Err)
	assert.True(t, len(result.Value) > 0, "should have at least one GC root")
	t.Logf("Found %d GC roots", len(result.Value))
}

func TestIntegrationAddTempRoot(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	result := <-client.AddTempRoot(path)
	assert.NoError(t, result.Err)
}

// --- Verify & Optimise ---

func TestIntegrationVerifyStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping store verification in short mode")
	}

	client := connectOrSkip(t)

	// checkContents=false, repair=false — just a quick metadata check.
	result := <-client.VerifyStore(false, false)
	assert.NoError(t, result.Err)
	t.Logf("VerifyStore found errors: %v", result.Value)
}

// --- Build Operations ---

func TestIntegrationBuildPaths(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	// Building an already-valid path should succeed immediately.
	result := <-client.BuildPaths([]string{path}, daemon.BuildModeNormal)
	assert.NoError(t, result.Err)
}

func TestIntegrationBuildPathsWithResults(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	result := <-client.BuildPathsWithResults([]string{path}, daemon.BuildModeNormal)
	assert.NoError(t, result.Err)

	for i, br := range result.Value {
		t.Logf("BuildResult[%d]: status=%s timesBuilt=%d", i, br.Status, br.TimesBuilt)
	}
}

func TestIntegrationEnsurePath(t *testing.T) {
	client := connectOrSkip(t)
	path := anyValidPath(t, client)

	result := <-client.EnsurePath(path)
	assert.NoError(t, result.Err)
}

// --- Sequential Operations ---
// Verify that multiple operations work on the same connection sequentially.

func TestIntegrationSequentialOperations(t *testing.T) {
	client := connectOrSkip(t)

	// Operation 1: QueryAllValidPaths
	allResult := <-client.QueryAllValidPaths()
	require.NoError(t, allResult.Err)
	require.True(t, len(allResult.Value) > 0)
	path := allResult.Value[0]

	// Operation 2: IsValidPath
	validResult := <-client.IsValidPath(path)
	require.NoError(t, validResult.Err)
	assert.True(t, validResult.Value)

	// Operation 3: QueryPathInfo
	infoResult := <-client.QueryPathInfo(path)
	require.NoError(t, infoResult.Err)
	require.NotNil(t, infoResult.Value)

	// Operation 4: NarFromPath + read + close
	narResult := <-client.NarFromPath(path)
	require.NoError(t, narResult.Err)
	_, err := io.ReadAll(narResult.Value)
	require.NoError(t, err)
	require.NoError(t, narResult.Value.Close())

	// Operation 5: QueryMissing (after releasing the NAR reader)
	missingResult := <-client.QueryMissing([]string{path})
	require.NoError(t, missingResult.Err)

	// Operation 6: FindRoots
	rootsResult := <-client.FindRoots()
	require.NoError(t, rootsResult.Err)

	t.Logf("6 sequential operations completed successfully on the same connection")
}

// min returns the smaller of a or b.
func min(a, b int) int {
	if a < b {
		return a
	}

	return b
}

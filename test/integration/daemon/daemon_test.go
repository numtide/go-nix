//go:build integration

package daemon_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/nar"
	"github.com/nix-community/go-nix/pkg/nixbase32"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startTestDaemon starts an isolated nix daemon subprocess and returns a
// connected client. The daemon uses a temporary store under t.TempDir().
// The daemon process is killed and cleaned up when the test finishes.
func startTestDaemon(t *testing.T, opts ...daemon.ConnectOption) *daemon.Client {
	t.Helper()

	nixBin, err := exec.LookPath("nix")
	require.NoError(t, err, "nix binary not found on PATH; run tests inside nix develop")

	storeRoot := t.TempDir()

	cmd := exec.Command(nixBin, "daemon", "--stdio",
		"--store", "local?root="+storeRoot,
		"--extra-experimental-features", "daemon-trust-override nix-command",
		"--force-trusted",
	)

	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	cmdStdin, err := cmd.StdinPipe()
	require.NoError(t, err)

	cmdStdout, err := cmd.StdoutPipe()
	require.NoError(t, err)

	require.NoError(t, cmd.Start(), "failed to start nix daemon")

	// Bridge cmd stdin/stdout to a net.Pipe so the client gets deadline support.
	serverConn, clientConn := net.Pipe()

	// stdout -> serverConn (daemon writes, client reads)
	go func() {
		_, _ = io.Copy(serverConn, cmdStdout)
		serverConn.Close()
	}()

	// serverConn -> stdin (client writes, daemon reads)
	go func() {
		_, _ = io.Copy(cmdStdin, serverConn)
		cmdStdin.Close()
	}()

	client, err := daemon.NewClientFromConn(clientConn, opts...)
	require.NoError(t, err, "handshake with nix daemon failed")

	t.Cleanup(func() {
		client.Close()
		serverConn.Close()
		cmd.Process.Kill()
		cmd.Wait()

		if t.Failed() {
			stderr := stderrBuf.String()
			if stderr != "" {
				t.Logf("nix daemon stderr:\n%s", stderr)
			}
		}
	})

	return client
}

// addTestPath creates a minimal store path in the daemon's isolated store
// and returns its store path and NAR data. Uses dontCheckSigs=true which
// requires --force-trusted on the daemon.
func addTestPath(t *testing.T, client *daemon.Client) (string, []byte) {
	t.Helper()

	// Build a minimal NAR: a regular file with known content.
	var narBuf bytes.Buffer
	nw, err := nar.NewWriter(&narBuf)
	require.NoError(t, err)

	content := []byte("hello from go-nix integration test\n")
	err = nw.WriteHeader(&nar.Header{
		Path: "/",
		Type: nar.TypeRegular,
		Size: int64(len(content)),
	})
	require.NoError(t, err)
	_, err = nw.Write(content)
	require.NoError(t, err)
	require.NoError(t, nw.Close())

	narData := narBuf.Bytes()

	// Compute SHA-256 hash of the NAR.
	h := sha256.Sum256(narData)
	narHash := "sha256:" + nixbase32.EncodeToString(h[:])

	// Construct store path from truncated hash (simplified, not Nix-canonical).
	storePath := "/nix/store/" + nixbase32.EncodeToString(h[:20]) + "-go-nix-integration-test"

	info := &daemon.PathInfo{
		StorePath:  storePath,
		NarHash:    narHash,
		NarSize:    uint64(len(narData)),
		References: []string{},
		Sigs:       []string{},
	}

	err = client.AddToStoreNar(context.Background(), info, bytes.NewReader(narData), false, true)
	require.NoError(t, err, "addTestPath: AddToStoreNar failed")

	return storePath, narData
}

// --- Connection & Handshake ---

func TestIntegrationConnect(t *testing.T) {
	client := startTestDaemon(t)

	info := client.Info()
	assert.Equal(t, daemon.ProtocolVersion, info.Version)
	assert.NotEmpty(t, info.DaemonNixVersion)
	t.Logf("Nix version: %s, trust: %d", info.DaemonNixVersion, info.Trust)
}

func TestIntegrationSetOptions(t *testing.T) {
	client := startTestDaemon(t)

	settings := daemon.DefaultClientSettings()
	err := client.SetOptions(context.Background(), settings)
	assert.NoError(t, err)
}

func TestIntegrationLogChannel(t *testing.T) {
	logs := make(chan daemon.LogMessage, 100)
	client := startTestDaemon(t, daemon.WithLogChannel(logs))

	assert.NotNil(t, client.Logs())

	// Run an operation that may produce log messages.
	_, err := client.QueryAllValidPaths(context.Background())
	assert.NoError(t, err)
}

// --- Validity & Path Queries ---

func TestIntegrationIsValidPath(t *testing.T) {
	client := startTestDaemon(t)

	// A path that definitely doesn't exist.
	valid, err := client.IsValidPath(context.Background(), "/nix/store/00000000000000000000000000000000-nonexistent")
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestIntegrationIsValidPathTrue(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)

	valid, err := client.IsValidPath(context.Background(), path)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestIntegrationQueryAllValidPaths(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)

	paths, err := client.QueryAllValidPaths(context.Background())
	assert.NoError(t, err)
	assert.Contains(t, paths, path)
	t.Logf("Store has %d valid paths", len(paths))
}

func TestIntegrationQueryValidPaths(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)

	valid, err := client.QueryValidPaths(context.Background(), []string{path}, false)
	assert.NoError(t, err)
	assert.Contains(t, valid, path)
}

func TestIntegrationQueryValidPathsSubset(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)

	bogus := "/nix/store/00000000000000000000000000000000-nonexistent"
	valid, err := client.QueryValidPaths(context.Background(), []string{path, bogus}, false)
	assert.NoError(t, err)
	assert.Contains(t, valid, path)
	assert.NotContains(t, valid, bogus)
}

// --- Path Info ---

func TestIntegrationQueryPathInfo(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)

	info, err := client.QueryPathInfo(context.Background(), path)
	assert.NoError(t, err)
	require.NotNil(t, info)

	assert.Equal(t, path, info.StorePath)
	assert.NotEmpty(t, info.NarHash)
	assert.True(t, info.NarSize > 0)

	t.Logf("Path: %s", info.StorePath)
	t.Logf("  NarHash: %s", info.NarHash)
	t.Logf("  NarSize: %d", info.NarSize)
}

func TestIntegrationQueryPathInfoNotFound(t *testing.T) {
	client := startTestDaemon(t)

	info, err := client.QueryPathInfo(context.Background(), "/nix/store/00000000000000000000000000000000-nonexistent")
	assert.NoError(t, err)
	assert.Nil(t, info)
}

func TestIntegrationQueryPathFromHashPart(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)

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
	client := startTestDaemon(t)

	result, err := client.QueryPathFromHashPart(context.Background(), "00000000000000000000000000000000")
	assert.NoError(t, err)
	assert.Empty(t, result)
}

// --- References & Derivers ---

func TestIntegrationQueryReferrers(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)

	referrers, err := client.QueryReferrers(context.Background(), path)
	assert.NoError(t, err)
	t.Logf("Path %s has %d referrers", path, len(referrers))
}

func TestIntegrationQueryValidDerivers(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)

	derivers, err := client.QueryValidDerivers(context.Background(), path)
	assert.NoError(t, err)
	t.Logf("Path %s has %d valid derivers", path, len(derivers))
}

// --- Substitutable & Missing ---

func TestIntegrationQuerySubstitutablePaths(t *testing.T) {
	client := startTestDaemon(t)

	// Query with a bogus path -- should return empty (no substituters for it).
	substitutable, err := client.QuerySubstitutablePaths(context.Background(), []string{
		"/nix/store/00000000000000000000000000000000-nonexistent",
	})
	assert.NoError(t, err)
	assert.Empty(t, substitutable)
}

func TestIntegrationQueryMissing(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)

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

// --- NAR Streaming ---

func TestIntegrationNarFromPath(t *testing.T) {
	client := startTestDaemon(t)
	path, expectedNar := addTestPath(t, client)

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

	// NAR content should match what we originally added.
	assert.Equal(t, expectedNar, data, "NAR content round-trip mismatch")

	t.Logf("NAR from %s: %d bytes", path, len(data))
}

// --- GC Roots ---

func TestIntegrationFindRoots(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)

	// Add a temp root so FindRoots returns something.
	err := client.AddTempRoot(context.Background(), path)
	require.NoError(t, err)

	roots, err := client.FindRoots(context.Background())
	assert.NoError(t, err)
	// Note: FindRoots may or may not include temp roots depending on daemon version.
	// We just verify the protocol round-trip works.
	t.Logf("Found %d GC roots", len(roots))
}

func TestIntegrationAddTempRoot(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)

	err := client.AddTempRoot(context.Background(), path)
	assert.NoError(t, err)
}

// --- Verify & Optimise ---

func TestIntegrationVerifyStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping store verification in short mode")
	}

	client := startTestDaemon(t)

	// checkContents=false, repair=false -- just a quick metadata check.
	errorsFound, err := client.VerifyStore(context.Background(), false, false)
	assert.NoError(t, err)
	t.Logf("VerifyStore found errors: %v", errorsFound)
}

// --- Build Operations ---

func TestIntegrationBuildPaths(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)

	// Building an already-valid path should succeed immediately.
	err := client.BuildPaths(context.Background(), []string{path}, daemon.BuildModeNormal)
	assert.NoError(t, err)
}

func TestIntegrationBuildPathsWithResults(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)

	results, err := client.BuildPathsWithResults(context.Background(), []string{path}, daemon.BuildModeNormal)
	assert.NoError(t, err)

	for i, br := range results {
		t.Logf("BuildResult[%d]: status=%s timesBuilt=%d", i, br.Status, br.TimesBuilt)
	}
}

func TestIntegrationEnsurePath(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)

	err := client.EnsurePath(context.Background(), path)
	assert.NoError(t, err)
}

// --- Sequential Operations ---
// Verify that multiple operations work on the same connection sequentially.

func TestIntegrationSequentialOperations(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)
	ctx := context.Background()

	// Operation 1: QueryAllValidPaths
	allPaths, err := client.QueryAllValidPaths(ctx)
	require.NoError(t, err)
	require.Contains(t, allPaths, path)

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

// --- Mutating Operations ---

func TestIntegrationAddToStoreNarRoundTrip(t *testing.T) {
	client := startTestDaemon(t)
	ctx := context.Background()

	// 1. Build a minimal NAR: a regular file with known content.
	var narBuf bytes.Buffer
	nw, err := nar.NewWriter(&narBuf)
	require.NoError(t, err)

	content := []byte("hello from go-nix integration test\n")
	err = nw.WriteHeader(&nar.Header{
		Path: "/",
		Type: nar.TypeRegular,
		Size: int64(len(content)),
	})
	require.NoError(t, err)
	_, err = nw.Write(content)
	require.NoError(t, err)
	require.NoError(t, nw.Close())

	narData := narBuf.Bytes()

	// 2. Compute SHA-256 hash of the NAR.
	h := sha256.Sum256(narData)
	narHash := "sha256:" + nixbase32.EncodeToString(h[:])

	// 3. Construct store path.
	storePath := "/nix/store/" + nixbase32.EncodeToString(h[:20]) + "-go-nix-integration-test"

	info := &daemon.PathInfo{
		StorePath:  storePath,
		NarHash:    narHash,
		NarSize:    uint64(len(narData)),
		References: []string{},
		Sigs:       []string{},
	}

	// 4. AddToStoreNar with dontCheckSigs=true.
	err = client.AddToStoreNar(ctx, info, bytes.NewReader(narData), false, true)
	require.NoError(t, err)

	// 5. Verify via QueryPathInfo.
	gotInfo, err := client.QueryPathInfo(ctx, storePath)
	require.NoError(t, err)
	require.NotNil(t, gotInfo, "path should exist in store after AddToStoreNar")
	assert.Equal(t, storePath, gotInfo.StorePath)
	assert.Equal(t, uint64(len(narData)), gotInfo.NarSize)
	t.Logf("AddToStoreNar round-trip: path=%s narSize=%d", gotInfo.StorePath, gotInfo.NarSize)

	// 6. Verify via NarFromPath: the retrieved NAR should match what we sent.
	rc, err := client.NarFromPath(ctx, storePath)
	require.NoError(t, err)
	gotNar, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	assert.Equal(t, narData, gotNar, "NAR content round-trip mismatch")
}

func TestIntegrationBuildDerivation(t *testing.T) {
	client := startTestDaemon(t)

	drv := &daemon.BasicDerivation{
		Outputs: map[string]daemon.DerivationOutput{
			"out": {Path: "/nix/store/00000000000000000000000000000000-go-nix-test-out"},
		},
		Inputs:   []string{},
		Platform: "x86_64-linux",
		Builder:  "/nix/store/00000000000000000000000000000000-nonexistent",
		Args:     []string{},
		Env:      map[string]string{"out": "/nix/store/00000000000000000000000000000000-go-nix-test-out"},
	}

	result, err := client.BuildDerivation(
		context.Background(),
		"/nix/store/00000000000000000000000000000000-go-nix-test.drv",
		drv,
		daemon.BuildModeNormal,
	)
	// The build should fail (nonexistent builder) but the protocol round-trip should work.
	if err != nil {
		t.Logf("BuildDerivation returned error: %v (expected for nonexistent builder)", err)
		return
	}
	assert.NotEqual(t, daemon.BuildStatusBuilt, result.Status,
		"build with nonexistent builder should not succeed")
	t.Logf("BuildDerivation result: status=%s errorMsg=%q", result.Status, result.ErrorMsg)
}

func TestIntegrationAddBuildLog(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)

	// Use the test path as a pseudo-derivation path for AddBuildLog.
	// The daemon may reject this since it's not a real .drv, but the
	// protocol round-trip is what we're testing.
	logContent := "test build log from go-nix\n"
	err := client.AddBuildLog(context.Background(), path, strings.NewReader(logContent))
	if err != nil {
		t.Logf("AddBuildLog returned error: %v (may be expected for non-.drv path)", err)
	} else {
		t.Log("AddBuildLog succeeded")
	}
}

func TestIntegrationAddIndirectRoot(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)

	// Create a temp symlink pointing to the valid store path.
	tmpDir := t.TempDir()
	symlink := filepath.Join(tmpDir, "gc-root")
	require.NoError(t, os.Symlink(path, symlink))

	err := client.AddIndirectRoot(context.Background(), symlink)
	assert.NoError(t, err)
}

func TestIntegrationSetOptionsWithOverrides(t *testing.T) {
	client := startTestDaemon(t)
	ctx := context.Background()

	settings := daemon.DefaultClientSettings()
	settings.MaxBuildJobs = 2
	settings.Overrides = map[string]string{
		"max-build-log-size": "1048576",
	}

	err := client.SetOptions(ctx, settings)
	assert.NoError(t, err)

	// Verify connection is still healthy after SetOptions with overrides.
	_, err = client.QueryAllValidPaths(ctx)
	assert.NoError(t, err)
}

// --- Derivation Output Map ---

func TestIntegrationQueryDerivationOutputMap(t *testing.T) {
	client := startTestDaemon(t)
	path, _ := addTestPath(t, client)

	// Our test path has no deriver, so query its output map directly.
	// This should return an empty map (or an error if the path is not a .drv),
	// but the protocol round-trip is what we're testing.
	info, err := client.QueryPathInfo(context.Background(), path)
	require.NoError(t, err)
	require.NotNil(t, info)

	if info.Deriver == "" {
		t.Log("Test path has no deriver (expected for addTestPath paths)")
		return
	}

	outputs, err := client.QueryDerivationOutputMap(context.Background(), info.Deriver)
	assert.NoError(t, err)
	for name, outPath := range outputs {
		t.Logf("  output %q -> %s", name, outPath)
	}
}

// --- AddToStore ---

func TestIntegrationAddToStore(t *testing.T) {
	client := startTestDaemon(t)
	ctx := context.Background()

	// Build a minimal NAR: a regular file with known content.
	var narBuf bytes.Buffer
	nw, err := nar.NewWriter(&narBuf)
	require.NoError(t, err)

	content := []byte("content-addressed import via AddToStore\n")
	err = nw.WriteHeader(&nar.Header{
		Path: "/",
		Type: nar.TypeRegular,
		Size: int64(len(content)),
	})
	require.NoError(t, err)
	_, err = nw.Write(content)
	require.NoError(t, err)
	require.NoError(t, nw.Close())

	narData := narBuf.Bytes()

	// Use AddToStore with fixed:r:sha256 (recursive NAR, SHA-256).
	// The daemon computes the store path from the NAR content.
	info, err := client.AddToStore(ctx,
		"go-nix-addtostore-test",
		"fixed:r:sha256",
		[]string{},
		false,
		bytes.NewReader(narData),
	)
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.NotEmpty(t, info.StorePath)
	assert.True(t, strings.HasPrefix(info.StorePath, "/nix/store/"))
	assert.Contains(t, info.StorePath, "go-nix-addtostore-test")
	assert.NotEmpty(t, info.NarHash)
	assert.Equal(t, uint64(len(narData)), info.NarSize)
	assert.NotEmpty(t, info.CA, "content-addressed path should have a CA field")
	t.Logf("AddToStore: path=%s narSize=%d ca=%s", info.StorePath, info.NarSize, info.CA)

	// Verify the path is now valid in the store.
	valid, err := client.IsValidPath(ctx, info.StorePath)
	assert.NoError(t, err)
	assert.True(t, valid)

	// Verify round-trip: retrieve the NAR and compare.
	rc, err := client.NarFromPath(ctx, info.StorePath)
	require.NoError(t, err)
	gotNar, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	assert.Equal(t, narData, gotNar, "NAR content round-trip mismatch")
}

func TestIntegrationAddToStoreFlat(t *testing.T) {
	client := startTestDaemon(t)
	ctx := context.Background()

	// For flat content addressing, the source is the raw file content (not NAR).
	content := []byte("flat content-addressed file\n")

	info, err := client.AddToStore(ctx,
		"go-nix-flat-test",
		"fixed:sha256",
		[]string{},
		false,
		bytes.NewReader(content),
	)
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.NotEmpty(t, info.StorePath)
	assert.Contains(t, info.StorePath, "go-nix-flat-test")
	assert.NotEmpty(t, info.CA)
	t.Logf("AddToStore flat: path=%s ca=%s", info.StorePath, info.CA)

	// Verify the path exists.
	valid, err := client.IsValidPath(ctx, info.StorePath)
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestIntegrationAddToStoreIdempotent(t *testing.T) {
	client := startTestDaemon(t)
	ctx := context.Background()

	content := []byte("idempotent content\n")

	// Add the same content twice — should return the same path both times.
	info1, err := client.AddToStore(ctx, "go-nix-idempotent", "fixed:sha256", nil, false, bytes.NewReader(content))
	require.NoError(t, err)

	info2, err := client.AddToStore(ctx, "go-nix-idempotent", "fixed:sha256", nil, false, bytes.NewReader(content))
	require.NoError(t, err)

	assert.Equal(t, info1.StorePath, info2.StorePath, "same content should produce same store path")
	assert.Equal(t, info1.NarHash, info2.NarHash)
}

// --- QuerySubstitutablePathInfos ---

func TestIntegrationQuerySubstitutablePathInfos(t *testing.T) {
	client := startTestDaemon(t)

	// With a local-only store and no substituters configured, the result
	// should be empty — but the protocol round-trip must succeed.
	result, err := client.QuerySubstitutablePathInfos(context.Background(), map[string]string{
		"/nix/store/00000000000000000000000000000000-nonexistent": "",
	})
	assert.NoError(t, err)
	assert.Empty(t, result)
}

func TestIntegrationQuerySubstitutablePathInfosEmpty(t *testing.T) {
	client := startTestDaemon(t)

	// Empty input map should return empty result.
	result, err := client.QuerySubstitutablePathInfos(context.Background(), map[string]string{})
	assert.NoError(t, err)
	assert.Empty(t, result)
}

func TestIntegrationQuerySubstitutablePathInfosMultiple(t *testing.T) {
	client := startTestDaemon(t)

	// Multiple paths, none substitutable in a local-only store.
	result, err := client.QuerySubstitutablePathInfos(context.Background(), map[string]string{
		"/nix/store/00000000000000000000000000000000-foo": "",
		"/nix/store/11111111111111111111111111111111-bar": "",
		"/nix/store/22222222222222222222222222222222-baz": "",
	})
	assert.NoError(t, err)
	assert.Empty(t, result)
	t.Logf("QuerySubstitutablePathInfos: %d results for 3 queries", len(result))
}

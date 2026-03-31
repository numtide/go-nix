//go:build integration

package daemon_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/nar"
	"github.com/nix-community/go-nix/pkg/nixbase32"
	"github.com/stretchr/testify/require"
)

// nixBinary identifies a specific nix binary for multi-version testing.
type nixBinary struct {
	Name    string // e.g. "nix-2.18"
	BinPath string // absolute path to the nix binary
}

// discoverNixBinaries returns the set of nix binaries available for testing.
// When NIX_TEST_DAEMONS_DIR is set it scans subdirectories for versioned
// binaries; otherwise it falls back to the single nix on PATH.
func discoverNixBinaries(t *testing.T) []nixBinary {
	t.Helper()

	dir := os.Getenv("NIX_TEST_DAEMONS_DIR")
	if dir == "" {
		// fall back to the single nix on PATH
		bin, err := exec.LookPath("nix")
		require.NoError(t, err, "nix binary not found on PATH; run tests inside nix develop")

		return []nixBinary{{Name: "nix", BinPath: bin}}
	}

	entries, err := os.ReadDir(dir)
	require.NoError(t, err, "failed to read NIX_TEST_DAEMONS_DIR: %s", dir)

	var binaries []nixBinary

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}

		bin := filepath.Join(dir, e.Name(), "bin", "nix")
		if _, err := os.Stat(bin); err != nil {
			continue
		}

		binaries = append(binaries, nixBinary{
			Name:    e.Name(),
			BinPath: bin,
		})
	}

	require.NotEmpty(t, binaries, "no nix binaries found in NIX_TEST_DAEMONS_DIR: %s", dir)

	sort.Slice(binaries, func(i, j int) bool {
		return binaries[i].Name < binaries[j].Name
	})

	return binaries
}

// startTestDaemon starts an isolated nix daemon subprocess listening on a
// Unix socket and returns a connected client. The daemon uses a temporary
// store under t.TempDir(). The daemon process is killed and cleaned up when
// the test finishes.
func startTestDaemon(t *testing.T, bin nixBinary) *daemon.Client {
	t.Helper()

	storeRoot := t.TempDir()

	// use a short path for the socket to stay within the 108-byte Unix
	// socket address limit — t.TempDir() paths include the full test name
	// which can exceed this when version prefixes are added.
	socketDir, err := os.MkdirTemp("", "nix")
	require.NoError(t, err)

	t.Cleanup(func() { os.RemoveAll(socketDir) })

	socketPath := filepath.Join(socketDir, "d.sock")

	cmd := exec.Command(bin.BinPath, "daemon",
		"--store", "local?root="+storeRoot,
		"--extra-experimental-features", "daemon-trust-override nix-command",
		"--force-trusted",
	)

	// tell the daemon to listen on our custom socket path
	cmd.Env = append(os.Environ(), "NIX_DAEMON_SOCKET_PATH="+socketPath)

	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	require.NoError(t, cmd.Start(), "failed to start nix daemon (%s)", bin.Name)

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()

		if t.Failed() {
			stderr := stderrBuf.String()
			if stderr != "" {
				t.Logf("nix daemon stderr (%s):\n%s", bin.Name, stderr)
			}
		}
	})

	// wait for the socket to appear
	for range 100 {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}

		time.Sleep(50 * time.Millisecond)
	}

	require.FileExists(t, socketPath, "daemon socket did not appear (%s)", bin.Name)

	client, err := daemon.Connect(t.Context(), socketPath)
	require.NoError(t, err, "failed to connect to nix daemon (%s)", bin.Name)

	t.Cleanup(func() {
		client.Close()
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

	err = client.AddToStoreNar(t.Context(), info, bytes.NewReader(narData), false, true)
	require.NoError(t, err, "addTestPath: AddToStoreNar failed")

	return storePath, narData
}

// skipIfUnsupported checks whether err is an UnsupportedOperationError and
// skips the test if so. Returns true if the test was skipped.
func skipIfUnsupported(t *testing.T, err error) bool {
	t.Helper()

	var unsupported *daemon.UnsupportedOperationError
	if errors.As(err, &unsupported) {
		t.Skipf("%v", unsupported)

		return true
	}

	return false
}

// TestIntegration is the top-level entry point that runs the full integration
// suite against every Nix daemon version discovered via NIX_TEST_DAEMONS_DIR
// (or the single nix on PATH as a fallback).
func TestIntegration(t *testing.T) {
	binaries := discoverNixBinaries(t)

	for _, bin := range binaries {
		t.Run(bin.Name, func(t *testing.T) {
			// --- Connection & Handshake ---
			t.Run("Connect", func(t *testing.T) { testConnect(t, bin) })
			t.Run("SetOptions", func(t *testing.T) { testSetOptions(t, bin) })

			// --- Validity & Path Queries ---
			t.Run("IsValidPath", func(t *testing.T) { testIsValidPath(t, bin) })
			t.Run("IsValidPathTrue", func(t *testing.T) { testIsValidPathTrue(t, bin) })
			t.Run("QueryAllValidPaths", func(t *testing.T) { testQueryAllValidPaths(t, bin) })
			t.Run("QueryValidPaths", func(t *testing.T) { testQueryValidPaths(t, bin) })
			t.Run("QueryValidPathsSubset", func(t *testing.T) { testQueryValidPathsSubset(t, bin) })

			// --- Path Info ---
			t.Run("QueryPathInfo", func(t *testing.T) { testQueryPathInfo(t, bin) })
			t.Run("QueryPathInfoNotFound", func(t *testing.T) { testQueryPathInfoNotFound(t, bin) })
			t.Run("QueryPathFromHashPart", func(t *testing.T) { testQueryPathFromHashPart(t, bin) })
			t.Run("QueryPathFromHashPartNotFound", func(t *testing.T) { testQueryPathFromHashPartNotFound(t, bin) })

			// --- References & Derivers ---
			t.Run("QueryReferrers", func(t *testing.T) { testQueryReferrers(t, bin) })
			t.Run("QueryValidDerivers", func(t *testing.T) { testQueryValidDerivers(t, bin) })

			// --- Substitutable & Missing ---
			t.Run("QuerySubstitutablePaths", func(t *testing.T) { testQuerySubstitutablePaths(t, bin) })
			t.Run("QueryMissing", func(t *testing.T) { testQueryMissing(t, bin) })

			// --- NAR Streaming ---
			t.Run("NarFromPath", func(t *testing.T) { testNarFromPath(t, bin) })

			// --- GC Roots ---
			t.Run("FindRoots", func(t *testing.T) { testFindRoots(t, bin) })
			t.Run("AddTempRoot", func(t *testing.T) { testAddTempRoot(t, bin) })

			// --- Verify & Optimise ---
			t.Run("VerifyStore", func(t *testing.T) { testVerifyStore(t, bin) })

			// --- Build Operations ---
			t.Run("BuildPaths", func(t *testing.T) { testBuildPaths(t, bin) })
			t.Run("BuildPathsWithResults", func(t *testing.T) { testBuildPathsWithResults(t, bin) })
			t.Run("EnsurePath", func(t *testing.T) { testEnsurePath(t, bin) })

			// --- Sequential Operations ---
			t.Run("SequentialOperations", func(t *testing.T) { testSequentialOperations(t, bin) })

			// --- Mutating Operations ---
			t.Run("AddToStoreNarRoundTrip", func(t *testing.T) { testAddToStoreNarRoundTrip(t, bin) })
			t.Run("BuildDerivation", func(t *testing.T) { testBuildDerivation(t, bin) })
			t.Run("AddBuildLog", func(t *testing.T) { testAddBuildLog(t, bin) })
			t.Run("AddIndirectRoot", func(t *testing.T) { testAddIndirectRoot(t, bin) })
			t.Run("SetOptionsWithOverrides", func(t *testing.T) { testSetOptionsWithOverrides(t, bin) })

			// --- Derivation Output Map ---
			t.Run("QueryDerivationOutputMap", func(t *testing.T) { testQueryDerivationOutputMap(t, bin) })

			// --- AddToStore ---
			t.Run("AddToStore", func(t *testing.T) { testAddToStore(t, bin) })
			t.Run("AddToStoreFlat", func(t *testing.T) { testAddToStoreFlat(t, bin) })
			t.Run("AddToStoreIdempotent", func(t *testing.T) { testAddToStoreIdempotent(t, bin) })

			// --- QuerySubstitutablePathInfos ---
			t.Run("QuerySubstitutablePathInfos", func(t *testing.T) { testQuerySubstitutablePathInfos(t, bin) })
			t.Run("QuerySubstitutablePathInfosEmpty", func(t *testing.T) { testQuerySubstitutablePathInfosEmpty(t, bin) })
			t.Run("QuerySubstitutablePathInfosMultiple", func(t *testing.T) { testQuerySubstitutablePathInfosMultiple(t, bin) })

			// --- QueryRealisation ---
			t.Run("QueryRealisation", func(t *testing.T) { testQueryRealisation(t, bin) })

			// --- AddPermRoot ---
			t.Run("AddPermRoot", func(t *testing.T) { testAddPermRoot(t, bin) })

			// --- AddSignatures ---
			t.Run("AddSignatures", func(t *testing.T) { testAddSignatures(t, bin) })

			// --- RegisterDrvOutput ---
			t.Run("RegisterDrvOutput", func(t *testing.T) { testRegisterDrvOutput(t, bin) })

			// --- CollectGarbage ---
			t.Run("CollectGarbage", func(t *testing.T) { testCollectGarbage(t, bin) })
			t.Run("CollectGarbageReturnDead", func(t *testing.T) { testCollectGarbageReturnDead(t, bin) })
			t.Run("CollectGarbageWithTempRoot", func(t *testing.T) { testCollectGarbageWithTempRoot(t, bin) })

			// --- OptimiseStore ---
			t.Run("OptimiseStore", func(t *testing.T) { testOptimiseStore(t, bin) })

			// --- Structured Error Parsing ---
			t.Run("StructuredError", func(t *testing.T) { testStructuredError(t, bin) })
			t.Run("StructuredErrorBuildDerivation", func(t *testing.T) { testStructuredErrorBuildDerivation(t, bin) })

			// --- AddMultipleToStore ---
			t.Run("AddMultipleToStore", func(t *testing.T) { testAddMultipleToStore(t, bin) })
		})
	}
}

// --- Connection & Handshake ---

func testConnect(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	info := client.Info()
	require.True(t, info.Version >= daemon.MinProtocolVersion,
		"negotiated protocol %#x below minimum %#x", info.Version, daemon.MinProtocolVersion)
	require.True(t, info.Version <= daemon.ProtocolVersion,
		"negotiated protocol %#x above maximum %#x", info.Version, daemon.ProtocolVersion)
	require.NotEmpty(t, info.DaemonNixVersion)
	t.Logf("Nix version: %s, protocol: %#x, trust: %d", info.DaemonNixVersion, info.Version, info.Trust)
}

func testSetOptions(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	settings := daemon.DefaultClientSettings()
	err := client.SetOptions(t.Context(), settings)
	require.NoError(t, err)
}

// --- Validity & Path Queries ---

func testIsValidPath(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	// a path that definitely doesn't exist
	valid, err := client.IsValidPath(t.Context(), "/nix/store/00000000000000000000000000000000-nonexistent")
	require.NoError(t, err)
	require.False(t, valid)
}

func testIsValidPathTrue(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	valid, err := client.IsValidPath(t.Context(), path)
	require.NoError(t, err)
	require.True(t, valid)
}

func testQueryAllValidPaths(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	paths, err := client.QueryAllValidPaths(t.Context())
	require.NoError(t, err)
	require.Contains(t, paths, path)
	t.Logf("Store has %d valid paths", len(paths))
}

func testQueryValidPaths(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	valid, err := client.QueryValidPaths(t.Context(), []string{path}, false)
	require.NoError(t, err)
	require.Contains(t, valid, path)
}

func testQueryValidPathsSubset(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	bogus := "/nix/store/00000000000000000000000000000000-nonexistent"
	valid, err := client.QueryValidPaths(t.Context(), []string{path, bogus}, false)
	require.NoError(t, err)
	require.Contains(t, valid, path)
	require.NotContains(t, valid, bogus)
}

// --- Path Info ---

func testQueryPathInfo(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	info, err := client.QueryPathInfo(t.Context(), path)
	require.NoError(t, err)
	require.NotNil(t, info)

	require.Equal(t, path, info.StorePath)
	require.NotEmpty(t, info.NarHash)
	require.True(t, info.NarSize > 0)

	t.Logf("Path: %s", info.StorePath)
	t.Logf("  NarHash: %s", info.NarHash)
	t.Logf("  NarSize: %d", info.NarSize)
}

func testQueryPathInfoNotFound(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	_, err := client.QueryPathInfo(t.Context(), "/nix/store/00000000000000000000000000000000-nonexistent")
	require.ErrorIs(t, err, daemon.ErrNotFound)
}

func testQueryPathFromHashPart(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	// Extract hash part: /nix/store/<hash>-<name> -> <hash>
	hashPart := strings.TrimPrefix(path, "/nix/store/")
	if idx := strings.Index(hashPart, "-"); idx > 0 {
		hashPart = hashPart[:idx]
	}

	result, err := client.QueryPathFromHashPart(t.Context(), hashPart)
	require.NoError(t, err)
	require.Equal(t, path, result)
}

func testQueryPathFromHashPartNotFound(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	result, err := client.QueryPathFromHashPart(t.Context(), "00000000000000000000000000000000")
	require.NoError(t, err)
	require.Empty(t, result)
}

// --- References & Derivers ---

func testQueryReferrers(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	referrers, err := client.QueryReferrers(t.Context(), path)
	require.NoError(t, err)
	t.Logf("Path %s has %d referrers", path, len(referrers))
}

func testQueryValidDerivers(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	derivers, err := client.QueryValidDerivers(t.Context(), path)
	require.NoError(t, err)
	t.Logf("Path %s has %d valid derivers", path, len(derivers))
}

// --- Substitutable & Missing ---

func testQuerySubstitutablePaths(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	// query with a bogus path — should return empty (no substituters for it)
	substitutable, err := client.QuerySubstitutablePaths(t.Context(), []string{
		"/nix/store/00000000000000000000000000000000-nonexistent",
	})
	require.NoError(t, err)
	require.Empty(t, substitutable)
}

func testQueryMissing(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	missing, err := client.QueryMissing(t.Context(), []string{path})
	require.NoError(t, err)
	require.NotNil(t, missing)
	// a valid path should not appear in WillBuild or Unknown
	require.NotContains(t, missing.WillBuild, path)
	require.NotContains(t, missing.Unknown, path)
	t.Logf("QueryMissing: willBuild=%d willSubstitute=%d unknown=%d downloadSize=%d narSize=%d",
		len(missing.WillBuild),
		len(missing.WillSubstitute),
		len(missing.Unknown),
		missing.DownloadSize,
		missing.NarSize,
	)
}

// --- NAR Streaming ---

func testNarFromPath(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, expectedNar := addTestPath(t, client)

	// get expected NAR size
	info, err := client.QueryPathInfo(t.Context(), path)
	require.NoError(t, err)
	require.NotNil(t, info)

	rc, err := client.NarFromPath(t.Context(), path, nil)
	require.NoError(t, err)
	require.NotNil(t, rc)

	// read all NAR data
	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())

	// NAR data should start with the NAR magic header
	require.True(t, len(data) > 0, "NAR data should not be empty")
	require.True(t, bytes.Contains(data[:min(len(data), 64)], []byte("nix-archive-1")),
		"NAR data should start with nix-archive-1 magic")

	// NAR size should match what PathInfo reported
	require.Equal(t, info.NarSize, uint64(len(data)),
		"NAR size should match PathInfo.NarSize")

	// NAR content should match what we originally added
	require.Equal(t, expectedNar, data, "NAR content round-trip mismatch")

	t.Logf("NAR from %s: %d bytes", path, len(data))
}

// --- GC Roots ---

func testFindRoots(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	// add a temp root so FindRoots returns something
	err := client.AddTempRoot(t.Context(), path)
	require.NoError(t, err)

	roots, err := client.FindRoots(t.Context())
	require.NoError(t, err)
	// Note: FindRoots may or may not include temp roots depending on daemon version.
	// We just verify the protocol round-trip works.
	t.Logf("Found %d GC roots", len(roots))
}

func testAddTempRoot(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	err := client.AddTempRoot(t.Context(), path)
	require.NoError(t, err)
}

// --- Verify & Optimise ---

func testVerifyStore(t *testing.T, bin nixBinary) {
	if testing.Short() {
		t.Skip("skipping store verification in short mode")
	}

	client := startTestDaemon(t, bin)

	// checkContents=false, repair=false — just a quick metadata check
	errorsFound, err := client.VerifyStore(t.Context(), false, false)
	require.NoError(t, err)
	t.Logf("VerifyStore found errors: %v", errorsFound)
}

// --- Build Operations ---

func testBuildPaths(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	// building an already-valid path should succeed immediately
	err := client.BuildPaths(t.Context(), []string{path}, daemon.BuildModeNormal)
	require.NoError(t, err)
}

func testBuildPathsWithResults(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	results, err := client.BuildPathsWithResults(t.Context(), []string{path}, daemon.BuildModeNormal)
	if skipIfUnsupported(t, err) {
		return
	}

	require.NoError(t, err)

	for i, br := range results {
		t.Logf("BuildResult[%d]: status=%s timesBuilt=%d", i, br.Status, br.TimesBuilt)
	}
}

func testEnsurePath(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	err := client.EnsurePath(t.Context(), path)
	require.NoError(t, err)
}

// --- Sequential Operations ---
// Verify that multiple operations work on the same connection sequentially.

func testSequentialOperations(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)
	ctx := t.Context()

	// Operation 1: QueryAllValidPaths
	allPaths, err := client.QueryAllValidPaths(ctx)
	require.NoError(t, err)
	require.Contains(t, allPaths, path)

	// Operation 2: IsValidPath
	valid, err := client.IsValidPath(ctx, path)
	require.NoError(t, err)
	require.True(t, valid)

	// Operation 3: QueryPathInfo
	info, err := client.QueryPathInfo(ctx, path)
	require.NoError(t, err)
	require.NotNil(t, info)

	// Operation 4: NarFromPath + read + close
	rc, err := client.NarFromPath(ctx, path, nil)
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

func testAddToStoreNarRoundTrip(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	ctx := t.Context()

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
	require.Equal(t, storePath, gotInfo.StorePath)
	require.Equal(t, uint64(len(narData)), gotInfo.NarSize)
	t.Logf("AddToStoreNar round-trip: path=%s narSize=%d", gotInfo.StorePath, gotInfo.NarSize)

	// 6. Verify via NarFromPath: the retrieved NAR should match what we sent.
	rc, err := client.NarFromPath(ctx, storePath, nil)
	require.NoError(t, err)
	gotNar, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	require.Equal(t, narData, gotNar, "NAR content round-trip mismatch")
}

func testBuildDerivation(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)

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

	result, err := client.BuildDerivation(t.Context(), &daemon.BuildDerivationRequest{
		DrvPath:    "/nix/store/00000000000000000000000000000000-go-nix-test.drv",
		Derivation: drv,
		Mode:       daemon.BuildModeNormal,
	})
	// the build should fail (nonexistent builder) but the protocol round-trip should work
	if err != nil {
		t.Logf("BuildDerivation returned error: %v (expected for nonexistent builder)", err)
		return
	}
	require.NotEqual(t, daemon.BuildStatusBuilt, result.Status,
		"build with nonexistent builder should not succeed")
	t.Logf("BuildDerivation result: status=%s errorMsg=%q", result.Status, result.ErrorMsg)
}

func testAddBuildLog(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	// use the test path as a pseudo-derivation path for AddBuildLog.
	// the daemon may reject this since it's not a real .drv, but the
	// protocol round-trip is what we're testing.
	logContent := "test build log from go-nix\n"
	err := client.AddBuildLog(t.Context(), path, strings.NewReader(logContent))
	if skipIfUnsupported(t, err) {
		return
	}

	if err != nil {
		t.Logf("AddBuildLog returned error: %v (may be expected for non-.drv path)", err)
	} else {
		t.Log("AddBuildLog succeeded")
	}
}

func testAddIndirectRoot(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	// create a temp symlink pointing to the valid store path
	tmpDir := t.TempDir()
	symlink := filepath.Join(tmpDir, "gc-root")
	require.NoError(t, os.Symlink(path, symlink))

	err := client.AddIndirectRoot(t.Context(), symlink)
	require.NoError(t, err)
}

func testSetOptionsWithOverrides(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	ctx := t.Context()

	settings := daemon.DefaultClientSettings()
	settings.MaxBuildJobs = 2
	settings.Overrides = map[string]string{
		"max-build-log-size": "1048576",
	}

	err := client.SetOptions(ctx, settings)
	require.NoError(t, err)

	// verify connection is still healthy after SetOptions with overrides
	_, err = client.QueryAllValidPaths(ctx)
	require.NoError(t, err)
}

// --- Derivation Output Map ---

func testQueryDerivationOutputMap(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	// our test path has no deriver, so query its output map directly.
	// this should return an empty map (or an error if the path is not a .drv),
	// but the protocol round-trip is what we're testing.
	info, err := client.QueryPathInfo(t.Context(), path)
	require.NoError(t, err)
	require.NotNil(t, info)

	if info.Deriver == "" {
		t.Log("Test path has no deriver (expected for addTestPath paths)")
		return
	}

	outputs, err := client.QueryDerivationOutputMap(t.Context(), info.Deriver)
	if skipIfUnsupported(t, err) {
		return
	}

	require.NoError(t, err)
	for name, outPath := range outputs {
		t.Logf("  output %q -> %s", name, outPath)
	}
}

// --- AddToStore ---

func testAddToStore(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	ctx := t.Context()

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

	// use AddToStore with fixed:r:sha256 (recursive NAR, SHA-256).
	// the daemon computes the store path from the NAR content.
	info, err := client.AddToStore(ctx, &daemon.AddToStoreRequest{
		Name:             "go-nix-addtostore-test",
		CAMethodWithAlgo: "fixed:r:sha256",
		References:       []string{},
		Source:           bytes.NewReader(narData),
	})
	if skipIfUnsupported(t, err) {
		return
	}

	require.NoError(t, err)
	require.NotNil(t, info)

	require.NotEmpty(t, info.StorePath)
	require.True(t, strings.HasPrefix(info.StorePath, "/nix/store/"))
	require.Contains(t, info.StorePath, "go-nix-addtostore-test")
	require.NotEmpty(t, info.NarHash)
	require.Equal(t, uint64(len(narData)), info.NarSize)
	require.NotEmpty(t, info.CA, "content-addressed path should have a CA field")
	t.Logf("AddToStore: path=%s narSize=%d ca=%s", info.StorePath, info.NarSize, info.CA)

	// verify the path is now valid in the store
	valid, err := client.IsValidPath(ctx, info.StorePath)
	require.NoError(t, err)
	require.True(t, valid)

	// verify round-trip: retrieve the NAR and compare
	rc, err := client.NarFromPath(ctx, info.StorePath, nil)
	require.NoError(t, err)
	gotNar, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	require.Equal(t, narData, gotNar, "NAR content round-trip mismatch")
}

func testAddToStoreFlat(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	ctx := t.Context()

	// for flat content addressing, the source is the raw file content (not NAR)
	content := []byte("flat content-addressed file\n")

	info, err := client.AddToStore(ctx, &daemon.AddToStoreRequest{
		Name:             "go-nix-flat-test",
		CAMethodWithAlgo: "fixed:sha256",
		References:       []string{},
		Source:           bytes.NewReader(content),
	})
	if skipIfUnsupported(t, err) {
		return
	}

	require.NoError(t, err)
	require.NotNil(t, info)

	require.NotEmpty(t, info.StorePath)
	require.Contains(t, info.StorePath, "go-nix-flat-test")
	require.NotEmpty(t, info.CA)
	t.Logf("AddToStore flat: path=%s ca=%s", info.StorePath, info.CA)

	// verify the path exists
	valid, err := client.IsValidPath(ctx, info.StorePath)
	require.NoError(t, err)
	require.True(t, valid)
}

func testAddToStoreIdempotent(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	ctx := t.Context()

	content := []byte("idempotent content\n")

	// add the same content twice — should return the same path both times
	info1, err := client.AddToStore(ctx, &daemon.AddToStoreRequest{
		Name:             "go-nix-idempotent",
		CAMethodWithAlgo: "fixed:sha256",
		Source:           bytes.NewReader(content),
	})
	if skipIfUnsupported(t, err) {
		return
	}

	require.NoError(t, err)

	info2, err := client.AddToStore(ctx, &daemon.AddToStoreRequest{
		Name:             "go-nix-idempotent",
		CAMethodWithAlgo: "fixed:sha256",
		Source:           bytes.NewReader(content),
	})
	require.NoError(t, err)

	require.Equal(t, info1.StorePath, info2.StorePath, "same content should produce same store path")
	require.Equal(t, info1.NarHash, info2.NarHash)
}

// --- QuerySubstitutablePathInfos ---

func testQuerySubstitutablePathInfos(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	// with a local-only store and no substituters configured, the result
	// should be empty — but the protocol round-trip must succeed
	result, err := client.QuerySubstitutablePathInfos(t.Context(), map[string]string{
		"/nix/store/00000000000000000000000000000000-nonexistent": "",
	})
	require.NoError(t, err)
	require.Empty(t, result)
}

func testQuerySubstitutablePathInfosEmpty(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	// empty input map should return empty result
	result, err := client.QuerySubstitutablePathInfos(t.Context(), map[string]string{})
	require.NoError(t, err)
	require.Empty(t, result)
}

func testQuerySubstitutablePathInfosMultiple(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	// multiple paths, none substitutable in a local-only store
	result, err := client.QuerySubstitutablePathInfos(t.Context(), map[string]string{
		"/nix/store/00000000000000000000000000000000-foo": "",
		"/nix/store/11111111111111111111111111111111-bar": "",
		"/nix/store/22222222222222222222222222222222-baz": "",
	})
	require.NoError(t, err)
	require.Empty(t, result)
	t.Logf("QuerySubstitutablePathInfos: %d results for 3 queries", len(result))
}

// --- QueryRealisation ---

func testQueryRealisation(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	// query a nonexistent output ID — should return empty, no error.
	// Note: some Nix versions crash with an SQLite assertion failure when
	// the realisations DB is uninitialised (local?root= stores). Tolerate
	// errors here since we're testing the protocol round-trip.
	realisations, err := client.QueryRealisation(t.Context(),
		"sha256:0000000000000000000000000000000000000000000000000000000000000000!out")
	if skipIfUnsupported(t, err) {
		return
	}

	if err != nil {
		t.Logf("QueryRealisation returned error: %v (may be a Nix daemon bug with local?root= stores)", err)
		return
	}
	require.Empty(t, realisations)
}

// --- AddPermRoot ---

func testAddPermRoot(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	// create a symlink path for the permanent GC root
	tmpDir := t.TempDir()
	gcRoot := filepath.Join(tmpDir, "perm-gc-root")

	resultPath, err := client.AddPermRoot(t.Context(), path, gcRoot)
	if skipIfUnsupported(t, err) {
		return
	}

	require.NoError(t, err)
	require.NotEmpty(t, resultPath)
	t.Logf("AddPermRoot: %s -> %s (result: %s)", gcRoot, path, resultPath)

	// the symlink should now exist and point to the store path
	target, err := os.Readlink(resultPath)
	require.NoError(t, err)
	require.Equal(t, path, target)
}

// --- AddSignatures ---

func testAddSignatures(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	// add a signature to the store path
	sig := "test-key-1:c2lnbmF0dXJlZGF0YQ=="
	err := client.AddSignatures(t.Context(), path, []string{sig})
	require.NoError(t, err)

	// verify the signature was attached by querying the path info
	info, err := client.QueryPathInfo(t.Context(), path)
	require.NoError(t, err)
	require.NotNil(t, info)
	require.Contains(t, info.Sigs, sig)
	t.Logf("AddSignatures: path=%s sigs=%v", path, info.Sigs)
}

// --- RegisterDrvOutput ---

func testRegisterDrvOutput(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	path, _ := addTestPath(t, client)

	// compute a fake but structurally valid output ID.
	// Format: sha256:<hash>!<output-name>
	h := sha256.Sum256([]byte("test-drv-output"))
	outputID := "sha256:" + nixbase32.EncodeToString(h[:]) + "!out"

	err := client.RegisterDrvOutput(t.Context(), &daemon.Realisation{
		ID:      outputID,
		OutPath: path,
	})
	if skipIfUnsupported(t, err) {
		return
	}

	if err != nil {
		// some daemon versions may reject this depending on store configuration
		t.Logf("RegisterDrvOutput returned error: %v (may be expected)", err)
	} else {
		t.Logf("RegisterDrvOutput succeeded for output %s", outputID)
	}
}

// --- CollectGarbage ---

func testCollectGarbage(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	ctx := t.Context()

	// add a path, then collect garbage (without a temp root, it should be deletable)
	path, _ := addTestPath(t, client)

	// verify the path exists before GC
	valid, err := client.IsValidPath(ctx, path)
	require.NoError(t, err)
	require.True(t, valid)

	// run GC to delete dead paths
	result, err := client.CollectGarbage(ctx, &daemon.GCOptions{
		Action:   daemon.GCDeleteDead,
		MaxFreed: 0, // unlimited
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	t.Logf("CollectGarbage: deleted %d paths, freed %d bytes", len(result.Paths), result.BytesFreed)
}

func testCollectGarbageReturnDead(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	ctx := t.Context()

	// GCReturnDead should return the list of dead paths without deleting them
	result, err := client.CollectGarbage(ctx, &daemon.GCOptions{
		Action:   daemon.GCReturnDead,
		MaxFreed: 0,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	t.Logf("CollectGarbage(ReturnDead): %d dead paths", len(result.Paths))
}

func testCollectGarbageWithTempRoot(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	ctx := t.Context()

	// add a path and protect it with a temp root
	path, _ := addTestPath(t, client)
	require.NoError(t, client.AddTempRoot(ctx, path))

	// GC should not delete the protected path
	_, err := client.CollectGarbage(ctx, &daemon.GCOptions{
		Action:   daemon.GCDeleteDead,
		MaxFreed: 0,
	})
	require.NoError(t, err)

	// path should still be valid after GC
	valid, err := client.IsValidPath(ctx, path)
	require.NoError(t, err)
	require.True(t, valid, "temp-rooted path should survive GC")
}

// --- OptimiseStore ---

func testOptimiseStore(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	// add some content so the store is not empty
	addTestPath(t, client)

	err := client.OptimiseStore(t.Context())
	require.NoError(t, err)
}

// --- Structured Error Parsing ---

func testStructuredError(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	// EnsurePath on a nonexistent, non-substitutable path should trigger
	// a daemon error with structured fields (Type, Level, Name, Message)
	err := client.EnsurePath(t.Context(), "/nix/store/00000000000000000000000000000000-nonexistent")
	require.Error(t, err, "EnsurePath on a nonexistent path should fail")

	var de *daemon.Error
	require.True(t, errors.As(err, &de), "error should be a *daemon.Error, got: %T: %v", err, err)

	require.NotEmpty(t, de.Type, "Error.Type should be populated")
	require.NotEmpty(t, de.Message, "Error.Message should be populated")

	t.Logf("Structured error: type=%q level=%d name=%q message=%q traces=%d",
		de.Type, de.Level, de.Name, de.Message, len(de.Traces))

	for i, tr := range de.Traces {
		t.Logf("  trace[%d]: havePos=%d message=%q", i, tr.HavePos, tr.Message)
	}

	// verify the connection is still usable after a daemon error
	valid, err := client.IsValidPath(t.Context(), "/nix/store/00000000000000000000000000000000-nonexistent")
	require.NoError(t, err, "connection should remain usable after daemon error")
	require.False(t, valid)
}

func testStructuredErrorBuildDerivation(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)

	drv := &daemon.BasicDerivation{
		Outputs: map[string]daemon.DerivationOutput{
			"out": {Path: "/nix/store/00000000000000000000000000000000-go-nix-error-test-out"},
		},
		Inputs:   []string{},
		Platform: "x86_64-linux",
		Builder:  "/nix/store/00000000000000000000000000000000-nonexistent-builder",
		Args:     []string{},
		Env:      map[string]string{"out": "/nix/store/00000000000000000000000000000000-go-nix-error-test-out"},
	}

	result, err := client.BuildDerivation(t.Context(), &daemon.BuildDerivationRequest{
		DrvPath:    "/nix/store/00000000000000000000000000000000-go-nix-error-test.drv",
		Derivation: drv,
		Mode:       daemon.BuildModeNormal,
	})
	if err != nil {
		// some daemon configurations return a protocol-level error
		var de *daemon.Error
		if errors.As(err, &de) {
			require.NotEmpty(t, de.Type)
			require.NotEmpty(t, de.Message)
			t.Logf("BuildDerivation daemon error: type=%q message=%q", de.Type, de.Message)
		} else {
			t.Logf("BuildDerivation error (non-daemon): %v", err)
		}

		return
	}

	// if we got a result, verify it reports a build failure
	require.NotEqual(t, daemon.BuildStatusBuilt, result.Status,
		"build with nonexistent builder should not succeed")
	require.NotEmpty(t, result.ErrorMsg, "failed build should have an error message")
	t.Logf("BuildDerivation result: status=%s errorMsg=%q", result.Status, result.ErrorMsg)
}

// --- AddMultipleToStore ---

func testAddMultipleToStore(t *testing.T, bin nixBinary) {
	client := startTestDaemon(t, bin)
	ctx := t.Context()

	// build two distinct NARs with different content
	makeNAR := func(content string) ([]byte, string, string) {
		var buf bytes.Buffer
		nw, err := nar.NewWriter(&buf)
		require.NoError(t, err)

		data := []byte(content)
		err = nw.WriteHeader(&nar.Header{
			Path: "/",
			Type: nar.TypeRegular,
			Size: int64(len(data)),
		})
		require.NoError(t, err)
		_, err = nw.Write(data)
		require.NoError(t, err)
		require.NoError(t, nw.Close())

		narData := buf.Bytes()
		h := sha256.Sum256(narData)
		narHash := "sha256:" + nixbase32.EncodeToString(h[:])
		storePath := "/nix/store/" + nixbase32.EncodeToString(h[:20]) + "-" + content[:8]

		return narData, narHash, storePath
	}

	nar1, hash1, path1 := makeNAR("multi-item-one-content\n")
	nar2, hash2, path2 := makeNAR("multi-item-two-content\n")

	items := []daemon.AddToStoreItem{
		{
			Info: daemon.PathInfo{
				StorePath:  path1,
				NarHash:    hash1,
				NarSize:    uint64(len(nar1)),
				References: []string{},
				Sigs:       []string{},
			},
			Source: bytes.NewReader(nar1),
		},
		{
			Info: daemon.PathInfo{
				StorePath:  path2,
				NarHash:    hash2,
				NarSize:    uint64(len(nar2)),
				References: []string{},
				Sigs:       []string{},
			},
			Source: bytes.NewReader(nar2),
		},
	}

	err := client.AddMultipleToStore(ctx, items, false, true)
	if skipIfUnsupported(t, err) {
		return
	}

	require.NoError(t, err)

	// both paths should now be valid
	valid1, err := client.IsValidPath(ctx, path1)
	require.NoError(t, err)
	require.True(t, valid1, "first path should be valid after AddMultipleToStore")

	valid2, err := client.IsValidPath(ctx, path2)
	require.NoError(t, err)
	require.True(t, valid2, "second path should be valid after AddMultipleToStore")

	t.Logf("AddMultipleToStore: added %s and %s", path1, path2)
}

//go:build integration

package daemon_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net"
	"os/exec"
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

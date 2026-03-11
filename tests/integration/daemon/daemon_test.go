//go:build integration

package daemon_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net"
	"os/exec"
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

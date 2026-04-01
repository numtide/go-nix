package daemon_test

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/require"
)

// rawMockListener creates a Unix socket and spawns a goroutine that accepts
// one connection and runs fn against it. Returns the socket path.
func rawMockListener(t *testing.T, fn func(net.Conn)) string {
	t.Helper()

	socketDir, err := os.MkdirTemp("", "nix")
	require.NoError(t, err)

	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })

	sock := filepath.Join(socketDir, "d.sock")

	listenCfg := net.ListenConfig{}
	ln, err := listenCfg.Listen(t.Context(), "unix", sock)
	require.NoError(t, err)

	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		fn(conn)
	}()

	return sock
}

func TestHandshake(t *testing.T) {
	t.Run("DaemonTooOld", func(t *testing.T) {
		rq := require.New(t)

		sock := rawMockListener(t, func(conn net.Conn) {
			enc := wire.NewEncoder(conn)

			// read client magic
			dec := wire.NewDecoder(conn, 64*1024)
			_, _ = dec.ReadUint64()

			// send server magic + old version (1.22)
			_ = enc.WriteUint64(daemon.ServerMagic)
			_ = enc.WriteUint64(daemon.ProtoVersion(1, 22))
		})

		_, err := daemon.Connect(t.Context(), sock)
		rq.Error(err)

		var pe *daemon.ProtocolError
		rq.ErrorAs(err, &pe)
		rq.Contains(pe.Error(), "older than minimum")
	})

	t.Run("Proto132", func(t *testing.T) {
		// Proto 1.32: has cpu affinity (>=1.14), reserve space (>=1.11), but
		// NO nix version (<1.33), NO trust (<1.35), NO feature exchange (<1.38).
		mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 32))
		mock.onAccept() // no operations, just handshake

		client, err := daemon.Connect(t.Context(), mock.path)
		require.NoError(t, err)

		defer client.Close()

		rq := require.New(t)
		rq.Equal(daemon.ProtoVersion(1, 32), client.Info().Version)
		rq.Equal("", client.Info().DaemonNixVersion)
		rq.Equal(daemon.TrustUnknown, client.Info().Trust)
		rq.Empty(client.Info().Features)
	})

	t.Run("Proto135", func(t *testing.T) {
		// Proto 1.35: has nix version (>=1.33) + trust (>=1.35), but NO feature exchange (<1.38).
		mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 35))
		mock.onAccept() // no operations, just handshake

		client, err := daemon.Connect(t.Context(), mock.path)
		require.NoError(t, err)

		defer client.Close()

		rq := require.New(t)
		rq.Equal(daemon.ProtoVersion(1, 35), client.Info().Version)
		rq.Equal("nix (Nix) 2.24.0", client.Info().DaemonNixVersion)
		rq.Equal(daemon.TrustTrusted, client.Info().Trust)
		rq.Empty(client.Info().Features)
	})

	t.Run("Proto138", func(t *testing.T) {
		// Proto 1.38 (current): all features including feature exchange.
		mock := newMockDaemon(t) // defaults to ProtocolVersion (1.38)
		mock.onAccept()

		client, err := daemon.Connect(t.Context(), mock.path)
		require.NoError(t, err)

		defer client.Close()

		rq := require.New(t)
		rq.Equal(daemon.ProtocolVersion, client.Info().Version)
		rq.Equal("nix (Nix) 2.24.0", client.Info().DaemonNixVersion)
		rq.Equal(daemon.TrustTrusted, client.Info().Trust)
		// both client and mock advertise zero features, so intersection is empty
		rq.Empty(client.Info().Features)
	})

	t.Run("ConnectionClosed", func(t *testing.T) {
		rq := require.New(t)

		// Server sends magic then closes the connection before sending version.
		sock := rawMockListener(t, func(conn net.Conn) {
			enc := wire.NewEncoder(conn)

			// read client magic
			dec := wire.NewDecoder(conn, 64*1024)
			_, _ = dec.ReadUint64()

			// send server magic, then close without sending version
			_ = enc.WriteUint64(daemon.ServerMagic)
			_ = conn.Close()
		})

		_, err := daemon.Connect(t.Context(), sock)
		rq.Error(err)

		var pe *daemon.ProtocolError
		rq.ErrorAs(err, &pe)
		rq.Contains(pe.Op, "handshake")
	})

	// tests the readAck error path: mock sends a non-1 acknowledgment value
	// after LogLast for an operation that expects an ack (BuildPaths).
	t.Run("InvalidAck", func(t *testing.T) {
		rq := require.New(t)

		mock := newMockDaemon(t)
		mock.onAccept(func(conn net.Conn) error {
			dec := wire.NewDecoder(conn, 64*1024)
			enc := wire.NewEncoder(conn)

			op, _ := dec.ReadUint64()
			if op != uint64(daemon.OpBuildPaths) {
				return fmt.Errorf("expected op %d, got %d", daemon.OpBuildPaths, op)
			}

			// drain request: paths (count + strings) + buildMode
			count, _ := dec.ReadUint64()
			for range count {
				_, _ = dec.ReadString()
			}

			_, _ = dec.ReadUint64() // buildMode

			// send LogLast
			_ = enc.WriteUint64(uint64(daemon.LogLast))

			// send invalid ack (42 instead of 1)
			_ = enc.WriteUint64(42)

			return nil
		})

		client, err := daemon.Connect(t.Context(), mock.path)
		rq.NoError(err)

		defer client.Close()

		err = client.BuildPaths(t.Context(), []string{"/nix/store/abc-test"}, daemon.BuildModeNormal)
		rq.Error(err)

		var pe *daemon.ProtocolError
		rq.ErrorAs(err, &pe)
		rq.Contains(pe.Error(), "ack")
	})
}

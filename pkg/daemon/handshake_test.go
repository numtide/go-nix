package daemon_test

import (
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/stretchr/testify/assert"
)

func TestHandshake(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan error, 1)
	go func() {
		defer close(done)
		// Mock server side
		var buf [8]byte

		// Read client magic
		_, err := io.ReadFull(serverConn, buf[:])
		if err != nil {
			done <- err
			return
		}
		assert.Equal(t, daemon.ClientMagic, binary.LittleEndian.Uint64(buf[:]))

		// Send server magic
		binary.LittleEndian.PutUint64(buf[:], daemon.ServerMagic)
		serverConn.Write(buf[:])

		// Send protocol version
		binary.LittleEndian.PutUint64(buf[:], daemon.ProtocolVersion)
		serverConn.Write(buf[:])

		// Read negotiated version
		_, err = io.ReadFull(serverConn, buf[:])
		if err != nil {
			done <- err
			return
		}

		// Read CPU affinity (false)
		_, err = io.ReadFull(serverConn, buf[:])
		if err != nil {
			done <- err
			return
		}

		// Read reserve space (false)
		_, err = io.ReadFull(serverConn, buf[:])
		if err != nil {
			done <- err
			return
		}

		// Send daemon nix version
		writeWireStringTo(serverConn, "nix (Nix) 2.24.0")

		// Send trust level: Trusted
		binary.LittleEndian.PutUint64(buf[:], 1)
		serverConn.Write(buf[:])

		done <- nil
	}()

	info, err := daemon.Handshake(clientConn)
	assert.NoError(t, err)
	assert.Equal(t, daemon.ProtocolVersion, info.Version)
	assert.Equal(t, "nix (Nix) 2.24.0", info.DaemonNixVersion)
	assert.Equal(t, daemon.TrustTrusted, info.Trust)

	assert.NoError(t, <-done)
}

func TestHandshakeWrongMagic(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		var buf [8]byte
		io.ReadFull(serverConn, buf[:])
		binary.LittleEndian.PutUint64(buf[:], 0xdeadbeef)
		serverConn.Write(buf[:])
	}()

	_, err := daemon.Handshake(clientConn)
	assert.Error(t, err)
}

// writeWireStringTo writes a wire-format string to a writer.
func writeWireStringTo(w io.Writer, s string) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(len(s)))
	w.Write(b)
	w.Write([]byte(s))
	pad := (8 - (len(s) % 8)) % 8
	if pad > 0 {
		w.Write(make([]byte, pad))
	}
}

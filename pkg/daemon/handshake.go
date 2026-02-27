package daemon

import (
	"bufio"
	"fmt"
	"io"

	"github.com/nix-community/go-nix/pkg/wire"
)

// HandshakeInfo holds the result of a successful handshake.
type HandshakeInfo struct {
	Version          uint64
	DaemonNixVersion string
	Trust            TrustLevel
}

// handshakeWithBufIO performs the Nix daemon protocol handshake using the
// provided buffered reader and writer.
func handshakeWithBufIO(r io.Reader, w *bufio.Writer) (*HandshakeInfo, error) {
	// 1. Client sends ClientMagic — flush.
	if err := wire.WriteUint64(w, ClientMagic); err != nil {
		return nil, &ProtocolError{Op: "handshake write client magic", Err: err}
	}

	if err := w.Flush(); err != nil {
		return nil, &ProtocolError{Op: "handshake flush client magic", Err: err}
	}

	// 2. Server responds with ServerMagic — validate.
	serverMagic, err := wire.ReadUint64(r)
	if err != nil {
		return nil, &ProtocolError{Op: "handshake read server magic", Err: err}
	}

	if serverMagic != ServerMagic {
		return nil, &ProtocolError{
			Op:  "handshake validate server magic",
			Err: fmt.Errorf("expected %#x, got %#x", ServerMagic, serverMagic),
		}
	}

	// 3. Server sends protocol version.
	serverVersion, err := wire.ReadUint64(r)
	if err != nil {
		return nil, &ProtocolError{Op: "handshake read server version", Err: err}
	}

	// 4. Client computes negotiated version = min(serverVersion, ProtocolVersion).
	negotiated := serverVersion
	if ProtocolVersion < negotiated {
		negotiated = ProtocolVersion
	}

	// Validate the negotiated version is at least what we support.
	if negotiated < ProtocolVersion {
		return nil, &ProtocolError{
			Op:  "handshake version negotiation",
			Err: fmt.Errorf("server version %#x is older than minimum supported %#x", serverVersion, ProtocolVersion),
		}
	}

	// 5. Client sends negotiated version — flush.
	if err := wire.WriteUint64(w, negotiated); err != nil {
		return nil, &ProtocolError{Op: "handshake write negotiated version", Err: err}
	}

	// 6. Client sends CPU affinity flag: false (v1.14+).
	if err := wire.WriteBool(w, false); err != nil {
		return nil, &ProtocolError{Op: "handshake write cpu affinity", Err: err}
	}

	// 7. Client sends reserve space flag: false (v1.11+).
	if err := wire.WriteBool(w, false); err != nil {
		return nil, &ProtocolError{Op: "handshake write reserve space", Err: err}
	}

	if err := w.Flush(); err != nil {
		return nil, &ProtocolError{Op: "handshake flush client flags", Err: err}
	}

	// 8. Server sends Nix version string (v1.33+).
	daemonVersion, err := wire.ReadString(r, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "handshake read daemon version", Err: err}
	}

	// 9. Server sends trust level (v1.35+).
	trustRaw, err := wire.ReadUint64(r)
	if err != nil {
		return nil, &ProtocolError{Op: "handshake read trust level", Err: err}
	}

	// 10. Consume the daemon's post-handshake startWork/stopWork cycle.
	// The daemon sends STDERR_LAST after the handshake to flush any pending
	// startup messages.
	if err := ProcessStderr(r, nil); err != nil {
		return nil, &ProtocolError{Op: "handshake process startup stderr", Err: err}
	}

	return &HandshakeInfo{
		Version:          negotiated,
		DaemonNixVersion: daemonVersion,
		Trust:            TrustLevel(trustRaw),
	}, nil
}

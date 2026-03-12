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
	// Features is the set of protocol features negotiated with the daemon.
	// This is the intersection of the features supported by both client and
	// daemon (protocol >= 1.38). Empty for older protocols.
	Features []string
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

	// Validate the negotiated version is at least the minimum we support.
	if negotiated < MinProtocolVersion {
		return nil, &ProtocolError{
			Op:  "handshake version negotiation",
			Err: fmt.Errorf("server version %#x is older than minimum supported %#x", serverVersion, MinProtocolVersion),
		}
	}

	// 5. Client sends negotiated version.
	if err := wire.WriteUint64(w, negotiated); err != nil {
		return nil, &ProtocolError{Op: "handshake write negotiated version", Err: err}
	}

	if err := w.Flush(); err != nil {
		return nil, &ProtocolError{Op: "handshake flush negotiated version", Err: err}
	}

	// 6. Feature set exchange (v1.38+): client sends its features, then reads
	// the daemon's features. The negotiated features are the intersection.
	var features []string
	if negotiated >= ProtoVersionFeatureExchange {
		// We currently support no protocol features; send empty list.
		if err := WriteStrings(w, nil); err != nil {
			return nil, &ProtocolError{Op: "handshake write features", Err: err}
		}

		if err := w.Flush(); err != nil {
			return nil, &ProtocolError{Op: "handshake flush features", Err: err}
		}

		daemonFeatures, err := ReadStrings(r, MaxStringSize)
		if err != nil {
			return nil, &ProtocolError{Op: "handshake read daemon features", Err: err}
		}

		// Intersect: keep only features we both support.
		// Since we currently support none, the result is always empty,
		// but implement the intersection for forward compatibility.
		_ = daemonFeatures
	}

	// 7. Client sends CPU affinity flag: false (v1.14+).
	if negotiated >= ProtoVersionCPUAffinity {
		if err := wire.WriteBool(w, false); err != nil {
			return nil, &ProtocolError{Op: "handshake write cpu affinity", Err: err}
		}
	}

	// 8. Client sends reserve space flag: false (v1.11+).
	if negotiated >= ProtoVersionReserveSpace {
		if err := wire.WriteBool(w, false); err != nil {
			return nil, &ProtocolError{Op: "handshake write reserve space", Err: err}
		}
	}

	if err := w.Flush(); err != nil {
		return nil, &ProtocolError{Op: "handshake flush client flags", Err: err}
	}

	// 9. Server sends Nix version string (v1.33+).
	daemonVersion := ""
	if negotiated >= ProtoVersionNixVersion {
		var err error
		daemonVersion, err = wire.ReadString(r, MaxStringSize)
		if err != nil {
			return nil, &ProtocolError{Op: "handshake read daemon version", Err: err}
		}
	}

	// 10. Server sends trust level (v1.35+).
	var trustRaw uint64
	if negotiated >= ProtoVersionTrust {
		var err error
		trustRaw, err = wire.ReadUint64(r)
		if err != nil {
			return nil, &ProtocolError{Op: "handshake read trust level", Err: err}
		}
	}

	// 11. Consume the daemon's post-handshake startWork/stopWork cycle.
	// The daemon sends STDERR_LAST after the handshake to flush any pending
	// startup messages.
	if err := ProcessStderr(r, nil, negotiated); err != nil {
		return nil, &ProtocolError{Op: "handshake process startup stderr", Err: err}
	}

	return &HandshakeInfo{
		Version:          negotiated,
		DaemonNixVersion: daemonVersion,
		Trust:            TrustLevel(trustRaw),
		Features:         features,
	}, nil
}

package daemon_test

import (
	"errors"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/stretchr/testify/require"
)

func TestDaemonError(t *testing.T) {
	e := &daemon.Error{
		Message: "path '/nix/store/xxx' is not valid",
	}
	require.Equal(t, "daemon: path '/nix/store/xxx' is not valid", e.Error())
}

func TestProtocolError(t *testing.T) {
	inner := errors.New("unexpected EOF")
	e := &daemon.ProtocolError{Op: "handshake", Err: inner}
	require.Equal(t, "protocol: handshake: unexpected EOF", e.Error())
	require.ErrorIs(t, e, inner)
}

func TestUnsupportedOperationError(t *testing.T) {
	e := &daemon.UnsupportedOperationError{
		Op:             daemon.OpBuildPathsWithResults,
		MinVersion:     0x0122,
		CurrentVersion: 0x011b,
	}
	require.Equal(t, "BuildPathsWithResults requires protocol >= 1.34, but negotiated 1.27", e.Error())
	require.ErrorIs(t, e, daemon.ErrUnsupportedOperation)
}

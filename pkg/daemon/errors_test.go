package daemon_test

import (
	"errors"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/stretchr/testify/require"
)

func TestErrors(t *testing.T) {
	t.Run("DaemonError", func(t *testing.T) {
		e := &daemon.Error{
			Message: "path '/nix/store/xxx' is not valid",
		}
		require.Equal(t, "daemon: path '/nix/store/xxx' is not valid", e.Error())
	})

	t.Run("ProtocolError", func(t *testing.T) {
		inner := errors.New("unexpected EOF")
		e := &daemon.ProtocolError{Op: "handshake", Err: inner}
		require.Equal(t, "protocol: handshake: unexpected EOF", e.Error())
		require.ErrorIs(t, e, inner)
	})

	t.Run("UnsupportedOperationError", func(t *testing.T) {
		e := &daemon.UnsupportedOperationError{
			Op:             daemon.OpBuildPathsWithResults,
			MinVersion:     0x0122,
			CurrentVersion: 0x011b,
		}
		require.Equal(t, "BuildPathsWithResults requires protocol >= 1.34, but negotiated 1.27", e.Error())
		require.ErrorIs(t, e, daemon.ErrUnsupportedOperation)
	})
}

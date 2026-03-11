package daemon_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/assert"
)

func TestClientIsValidPathDaemonError(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	expectedErr := &daemon.Error{
		Type:    "Error",
		Level:   0,
		Name:    "InvalidPath",
		Message: "path '/nix/store/xxx-invalid' is not valid",
	}

	go func() {
		mock.handshake()
		mock.respondWithError(daemon.OpIsValidPath, func() {
			_, _ = wire.ReadString(mock.conn, 64*1024) // path
		}, expectedErr)
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	_, err = client.IsValidPath(context.Background(), "/nix/store/xxx-invalid")
	assert.Error(t, err)

	var daemonErr *daemon.Error
	assert.True(t, errors.As(err, &daemonErr))
	assert.Equal(t, "Error", daemonErr.Type)
	assert.Equal(t, "path '/nix/store/xxx-invalid' is not valid", daemonErr.Message)
}

func TestClientQueryPathInfoDaemonError(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	expectedErr := &daemon.Error{
		Type:    "Error",
		Level:   0,
		Name:    "InvalidPath",
		Message: "path '/nix/store/yyy-broken' is corrupted",
	}

	go func() {
		mock.handshake()
		mock.respondWithError(daemon.OpQueryPathInfo, func() {
			_, _ = wire.ReadString(mock.conn, 64*1024) // path
		}, expectedErr)
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	_, err = client.QueryPathInfo(context.Background(), "/nix/store/yyy-broken")
	assert.Error(t, err)

	var daemonErr *daemon.Error
	assert.True(t, errors.As(err, &daemonErr))
	assert.Equal(t, "Error", daemonErr.Type)
	assert.Equal(t, "path '/nix/store/yyy-broken' is corrupted", daemonErr.Message)
}

func TestClientBuildPathsDaemonError(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	expectedErr := &daemon.Error{
		Type:    "Error",
		Level:   0,
		Name:    "BuildError",
		Message: "build of '/nix/store/zzz-fail.drv' failed",
	}

	go func() {
		mock.handshake()
		mock.respondWithError(daemon.OpBuildPaths, func() {
			var buf [8]byte
			// Read count + path strings
			_, _ = io.ReadFull(mock.conn, buf[:]) // count
			count := binary.LittleEndian.Uint64(buf[:])
			for i := uint64(0); i < count; i++ {
				_, _ = wire.ReadString(mock.conn, 64*1024)
			}
			// Read build mode
			_, _ = io.ReadFull(mock.conn, buf[:])
		}, expectedErr)
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	err = client.BuildPaths(context.Background(), []string{"/nix/store/zzz-fail.drv"}, daemon.BuildModeNormal)
	assert.Error(t, err)

	var daemonErr *daemon.Error
	assert.True(t, errors.As(err, &daemonErr))
	assert.Equal(t, "Error", daemonErr.Type)
	assert.Equal(t, "build of '/nix/store/zzz-fail.drv' failed", daemonErr.Message)
}

func TestClientDaemonErrorWithTraces(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	expectedErr := &daemon.Error{
		Type:    "Error",
		Level:   0,
		Name:    "EvalError",
		Message: "evaluation failed",
		Traces: []daemon.ErrorTrace{
			{HavePos: 0, Message: "while evaluating the attribute 'buildInputs'"},
			{HavePos: 0, Message: "while calling the 'derivationStrict' builtin"},
		},
	}

	go func() {
		mock.handshake()
		mock.respondWithError(daemon.OpIsValidPath, func() {
			_, _ = wire.ReadString(mock.conn, 64*1024) // path
		}, expectedErr)
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	_, err = client.IsValidPath(context.Background(), "/nix/store/abc-test")
	assert.Error(t, err)

	var daemonErr *daemon.Error
	assert.True(t, errors.As(err, &daemonErr))
	assert.Equal(t, "Error", daemonErr.Type)
	assert.Equal(t, "evaluation failed", daemonErr.Message)
	assert.Equal(t, "EvalError", daemonErr.Name)
	assert.Len(t, daemonErr.Traces, 2)
	assert.Equal(t, "while evaluating the attribute 'buildInputs'", daemonErr.Traces[0].Message)
	assert.Equal(t, "while calling the 'derivationStrict' builtin", daemonErr.Traces[1].Message)
	assert.Equal(t, uint64(0), daemonErr.Traces[0].HavePos)
	assert.Equal(t, uint64(0), daemonErr.Traces[1].HavePos)
}

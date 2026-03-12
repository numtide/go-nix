package daemon_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sort"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/assert"
)

func TestClientConnectWrongMagic(t *testing.T) {
	server, clientConn := net.Pipe()
	defer server.Close()
	defer clientConn.Close()

	go func() {
		var buf [8]byte
		_, _ = io.ReadFull(server, buf[:]) // read client magic
		binary.LittleEndian.PutUint64(buf[:], 0xdeadbeef)
		_, _ = server.Write(buf[:])
	}()

	_, err := daemon.NewClientFromConn(clientConn)
	assert.Error(t, err)
}

func TestClientConnect(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	assert.Equal(t, daemon.ProtocolVersion, client.Info().Version)
	assert.Equal(t, "nix (Nix) 2.24.0", client.Info().DaemonNixVersion)
}

func TestNewClientFromConnNil(t *testing.T) {
	_, err := daemon.NewClientFromConn(nil)
	assert.ErrorIs(t, err, daemon.ErrNilConn)
}

func TestClientNilContext(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	var ctx context.Context
	_, err = client.IsValidPath(ctx, "/nix/store/abc-test")
	assert.ErrorIs(t, err, daemon.ErrNilContext)
}

func TestClientClosed(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	assert.NoError(t, client.Close())

	_, err = client.IsValidPath(context.Background(), "/nix/store/abc-test")
	assert.ErrorIs(t, err, daemon.ErrClosed)
}

func TestClientCloseIdempotent(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	assert.NoError(t, client.Close())
	assert.NoError(t, client.Close())
}

func TestClientWithLogChannel(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	logs := make(chan daemon.LogMessage, 10)

	go func() {
		mock.handshake()
	}()

	client, err := daemon.NewClientFromConn(clientConn, daemon.WithLogChannel(logs))
	assert.NoError(t, err)
	defer client.Close()

	assert.NotNil(t, client.Logs())
}

func TestClientLogsNilByDefault(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	assert.Nil(t, client.Logs())
}

// TestClientSequentialOperations exercises multiple different operations on
// the same mock connection to verify the client properly releases the mutex
// and resets the connection state between operations.
func TestClientSequentialOperations(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	expectedInfo := &daemon.PathInfo{
		StorePath:        "/nix/store/abc-test",
		Deriver:          "/nix/store/xyz-test.drv",
		NarHash:          "sha256:1b8m03r63zqhnjf7l5wnldhh7c134p5572hrber4jqabd5b2no80",
		References:       []string{"/nix/store/abc-test", "/nix/store/def-dep"},
		RegistrationTime: 1700000000,
		NarSize:          123456,
		Ultimate:         true,
		Sigs: []string{
			"cache.nixos.org-1:TsTTb3WGTZKphvYdBHXwo13XoOdFhL2sw/8d16Xzm5NeXp+SuJgMHV1+U+5JxVuf2HuLci2x3Sa+l3KhADoCDQ==",
		},
		CA: "",
	}

	expectedPaths := []string{
		"/nix/store/aaa-first",
		"/nix/store/bbb-second",
		"/nix/store/ccc-third",
	}

	go func() {
		mock.handshake()
		mock.respondIsValidPath(true)
		mock.respondQueryPathInfo(expectedInfo)
		mock.respondIsValidPath(false)
		mock.respondQueryAllValidPaths(expectedPaths)
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	// Op 1: IsValidPath -> true
	valid, err := client.IsValidPath(context.Background(), "/nix/store/abc-test")
	assert.NoError(t, err)
	assert.True(t, valid, "first IsValidPath should return true")

	// Op 2: QueryPathInfo -> found with expected info
	info, err := client.QueryPathInfo(context.Background(), "/nix/store/abc-test")
	assert.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, expectedInfo.StorePath, info.StorePath)
	assert.Equal(t, expectedInfo.Deriver, info.Deriver)
	assert.Equal(t, expectedInfo.NarHash, info.NarHash)
	assert.Equal(t, expectedInfo.References, info.References)
	assert.Equal(t, expectedInfo.RegistrationTime, info.RegistrationTime)
	assert.Equal(t, expectedInfo.NarSize, info.NarSize)
	assert.Equal(t, expectedInfo.Ultimate, info.Ultimate)
	assert.Equal(t, expectedInfo.Sigs, info.Sigs)
	assert.Equal(t, expectedInfo.CA, info.CA)

	// Op 3: IsValidPath -> false
	valid, err = client.IsValidPath(context.Background(), "/nix/store/nonexistent")
	assert.NoError(t, err)
	assert.False(t, valid, "second IsValidPath should return false")

	// Op 4: QueryAllValidPaths -> list of paths
	paths, err := client.QueryAllValidPaths(context.Background())
	assert.NoError(t, err)
	sort.Strings(paths)
	sort.Strings(expectedPaths)
	assert.Equal(t, expectedPaths, paths)
}

// TestClientOperationAfterError verifies that the connection remains usable
// after the daemon returns an error for one operation. The client's doOp
// calls ProcessStderrWithSink which returns the error on LogError, then
// release(cancel) unlocks the mutex and resets the deadline. Since LogError
// terminates the stderr loop (no trailing LogLast), the next operation
// starts cleanly from the new op code.
func TestClientOperationAfterError(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	daemonErr := &daemon.Error{
		Type:    "Error",
		Level:   0,
		Name:    "InvalidPath",
		Message: "path '/nix/store/bad-path' is not valid",
	}

	go func() {
		mock.handshake()

		// First operation: respond with error
		mock.respondWithError(daemon.OpIsValidPath, func() {
			_, _ = wire.ReadString(mock.conn, 64*1024) // drain path
		}, daemonErr)

		// Second operation: respond successfully
		mock.respondIsValidPath(true)
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	// First call: should fail with daemon error
	_, err = client.IsValidPath(context.Background(), "/nix/store/bad-path")
	assert.Error(t, err, "first IsValidPath should return an error")

	var gotErr *daemon.Error
	assert.True(t, errors.As(err, &gotErr), "error should be a *daemon.Error")
	assert.Equal(t, "path '/nix/store/bad-path' is not valid", gotErr.Message)

	// Second call: should succeed, proving the connection is not corrupted
	valid, err := client.IsValidPath(context.Background(), "/nix/store/good-path")
	assert.NoError(t, err, "second IsValidPath should succeed after prior error")
	assert.True(t, valid, "second IsValidPath should return true")
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

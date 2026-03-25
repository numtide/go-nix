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

func TestBuildDerivationNil(t *testing.T) {
	client := &daemon.Client{}

	_, err := client.BuildDerivation(context.Background(), "/nix/store/abc.drv", nil, daemon.BuildModeNormal)
	assert.ErrorIs(t, err, daemon.ErrNilDerivation)
}

func TestClientBuildPaths(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()

		var buf [8]byte

		_, _ = io.ReadFull(mock.conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpBuildPaths), op)

		// Read paths (count + strings)
		_, _ = io.ReadFull(mock.conn, buf[:])      // count = 1
		_, _ = wire.ReadString(mock.conn, 64*1024) // path

		// Read build mode
		_, _ = io.ReadFull(mock.conn, buf[:]) // mode

		// LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = mock.conn.Write(buf[:])

		// Response: uint64(1)
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = mock.conn.Write(buf[:])
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	err = client.BuildPaths(context.Background(), []string{"/nix/store/abc-test.drv"}, daemon.BuildModeNormal)
	assert.NoError(t, err)
}

func TestClientEnsurePath(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()

		var buf [8]byte

		_, _ = io.ReadFull(mock.conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpEnsurePath), op)

		_, _ = wire.ReadString(mock.conn, 64*1024) // path

		// LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = mock.conn.Write(buf[:])

		// Response: uint64(1)
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = mock.conn.Write(buf[:])
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	err = client.EnsurePath(context.Background(), "/nix/store/abc-test")
	assert.NoError(t, err)
}

func TestClientBuildPathsWithResults(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()

		var buf [8]byte

		_, _ = io.ReadFull(mock.conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpBuildPathsWithResults), op)

		// Read paths (count + strings)
		_, _ = io.ReadFull(mock.conn, buf[:])      // count = 1
		_, _ = wire.ReadString(mock.conn, 64*1024) // path

		// Read build mode
		_, _ = io.ReadFull(mock.conn, buf[:]) // mode

		// LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = mock.conn.Write(buf[:])

		// Response: count of results = 1
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = mock.conn.Write(buf[:])

		// DerivedPath string (ignored by client)
		writeWireStringTo(mock.conn, "/nix/store/abc-test.drv!out")

		// BuildResult fields
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.BuildStatusBuilt)) // status
		_, _ = mock.conn.Write(buf[:])
		writeWireStringTo(mock.conn, "")         // errorMsg
		binary.LittleEndian.PutUint64(buf[:], 1) // timesBuilt
		_, _ = mock.conn.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], 0) // isNonDeterministic
		_, _ = mock.conn.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], 1700000000) // startTime
		_, _ = mock.conn.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], 1700000060) // stopTime
		_, _ = mock.conn.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], 0) // cpuUser: None
		_, _ = mock.conn.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], 0) // cpuSystem: None
		_, _ = mock.conn.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], 0) // builtOutputs count
		_, _ = mock.conn.Write(buf[:])
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	results, err := client.BuildPathsWithResults(
		context.Background(),
		[]string{"/nix/store/abc-test.drv!out"},
		daemon.BuildModeNormal,
	)
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, daemon.BuildStatusBuilt, results[0].Status)
	assert.Equal(t, "", results[0].ErrorMsg)
	assert.Equal(t, uint64(1), results[0].TimesBuilt)
	assert.False(t, results[0].IsNonDeterministic)
	assert.Equal(t, uint64(1700000000), results[0].StartTime)
	assert.Equal(t, uint64(1700000060), results[0].StopTime)
}

func TestClientBuildDerivation(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	drv := &daemon.BasicDerivation{
		Outputs: map[string]daemon.DerivationOutput{
			"out": {Path: "/nix/store/abc-out", HashAlgorithm: "", Hash: ""},
		},
		Inputs:   []string{"/nix/store/def-input"},
		Platform: "x86_64-linux",
		Builder:  "/nix/store/bash/bin/bash",
		Args:     []string{"-e", "builder.sh"},
		Env:      map[string]string{"out": "/nix/store/abc-out"},
	}

	go func() {
		mock.handshake()

		var buf [8]byte

		_, _ = io.ReadFull(mock.conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpBuildDerivation), op)

		// Read drvPath
		_, _ = wire.ReadString(mock.conn, 64*1024)

		// Read outputs count
		_, _ = io.ReadFull(mock.conn, buf[:])
		count := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(1), count)

		// Read output: name, path, hashAlgo, hash
		_, _ = wire.ReadString(mock.conn, 64*1024)
		_, _ = wire.ReadString(mock.conn, 64*1024)
		_, _ = wire.ReadString(mock.conn, 64*1024)
		_, _ = wire.ReadString(mock.conn, 64*1024)

		// Read inputs count + paths
		_, _ = io.ReadFull(mock.conn, buf[:])
		_, _ = wire.ReadString(mock.conn, 64*1024)

		// Read platform, builder
		_, _ = wire.ReadString(mock.conn, 64*1024)
		_, _ = wire.ReadString(mock.conn, 64*1024)

		// Read args count + args
		_, _ = io.ReadFull(mock.conn, buf[:])
		_, _ = wire.ReadString(mock.conn, 64*1024)
		_, _ = wire.ReadString(mock.conn, 64*1024)

		// Read env count + entries
		_, _ = io.ReadFull(mock.conn, buf[:])
		_, _ = wire.ReadString(mock.conn, 64*1024)
		_, _ = wire.ReadString(mock.conn, 64*1024)

		// Read build mode
		_, _ = io.ReadFull(mock.conn, buf[:])

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = mock.conn.Write(buf[:])

		// Send BuildResult: status=Built(0), errorMsg="", timesBuilt=1,
		// isNonDeterministic=false, startTime=100, stopTime=200, builtOutputs count=0
		binary.LittleEndian.PutUint64(buf[:], 0) // Built
		_, _ = mock.conn.Write(buf[:])

		writeWireStringTo(mock.conn, "") // errorMsg

		binary.LittleEndian.PutUint64(buf[:], 1) // timesBuilt
		_, _ = mock.conn.Write(buf[:])

		binary.LittleEndian.PutUint64(buf[:], 0) // isNonDeterministic
		_, _ = mock.conn.Write(buf[:])

		binary.LittleEndian.PutUint64(buf[:], 100) // startTime
		_, _ = mock.conn.Write(buf[:])

		binary.LittleEndian.PutUint64(buf[:], 200) // stopTime
		_, _ = mock.conn.Write(buf[:])

		binary.LittleEndian.PutUint64(buf[:], 0) // cpuUser: None
		_, _ = mock.conn.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], 0) // cpuSystem: None
		_, _ = mock.conn.Write(buf[:])

		binary.LittleEndian.PutUint64(buf[:], 0) // builtOutputs count
		_, _ = mock.conn.Write(buf[:])
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	result, err := client.BuildDerivation(context.Background(), "/nix/store/xyz-test.drv", drv, daemon.BuildModeNormal)
	assert.NoError(t, err)
	assert.Equal(t, daemon.BuildStatusBuilt, result.Status)
	assert.Equal(t, uint64(1), result.TimesBuilt)
	assert.Equal(t, uint64(100), result.StartTime)
	assert.Equal(t, uint64(200), result.StopTime)
}

// Version-specific build tests

func TestBuildPathsWithResultsUnsupportedVersion(t *testing.T) {
	mock, clientConn := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))
	defer mock.conn.Close()

	go func() {
		mock.handshake()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	_, err = client.BuildPathsWithResults(context.Background(), []string{"/nix/store/abc.drv!out"}, daemon.BuildModeNormal)
	assert.Error(t, err)
	assert.ErrorIs(t, err, daemon.ErrUnsupportedOperation)
}

// TestClientBuildDerivationProto127 connects at proto 1.27 and calls
// BuildDerivation. At proto 1.27 the BuildResult wire format omits timing
// fields (proto < 1.29), CPU times (proto < 1.37), and builtOutputs
// (proto < 1.28). The mock sends only status + errorMsg.
func TestClientBuildDerivationProto127(t *testing.T) {
	mock, clientConn := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))
	defer mock.conn.Close()

	drv := &daemon.BasicDerivation{
		Outputs: map[string]daemon.DerivationOutput{
			"out": {Path: "/nix/store/abc-out", HashAlgorithm: "", Hash: ""},
		},
		Inputs:   []string{"/nix/store/def-input"},
		Platform: "x86_64-linux",
		Builder:  "/nix/store/bash/bin/bash",
		Args:     []string{"-e", "builder.sh"},
		Env:      map[string]string{"out": "/nix/store/abc-out"},
	}

	go func() {
		mock.handshake()

		var buf [8]byte

		// Read op code
		_, _ = io.ReadFull(mock.conn, buf[:])
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpBuildDerivation), op)

		// Read drvPath
		_, _ = wire.ReadString(mock.conn, 64*1024)

		// Read outputs count
		_, _ = io.ReadFull(mock.conn, buf[:])
		count := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(1), count)

		// Read output: name, path, hashAlgo, hash
		_, _ = wire.ReadString(mock.conn, 64*1024)
		_, _ = wire.ReadString(mock.conn, 64*1024)
		_, _ = wire.ReadString(mock.conn, 64*1024)
		_, _ = wire.ReadString(mock.conn, 64*1024)

		// Read inputs count + paths
		_, _ = io.ReadFull(mock.conn, buf[:])
		_, _ = wire.ReadString(mock.conn, 64*1024)

		// Read platform, builder
		_, _ = wire.ReadString(mock.conn, 64*1024)
		_, _ = wire.ReadString(mock.conn, 64*1024)

		// Read args count + args
		_, _ = io.ReadFull(mock.conn, buf[:])
		_, _ = wire.ReadString(mock.conn, 64*1024)
		_, _ = wire.ReadString(mock.conn, 64*1024)

		// Read env count + entries
		_, _ = io.ReadFull(mock.conn, buf[:])
		_, _ = wire.ReadString(mock.conn, 64*1024)
		_, _ = wire.ReadString(mock.conn, 64*1024)

		// Read build mode
		_, _ = io.ReadFull(mock.conn, buf[:])

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = mock.conn.Write(buf[:])

		// Send BuildResult for proto 1.27:
		// Only status + errorMsg. No timing fields, no CPU times, no builtOutputs.
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.BuildStatusBuilt)) // status
		_, _ = mock.conn.Write(buf[:])

		writeWireStringTo(mock.conn, "") // errorMsg
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	assert.Equal(t, daemon.ProtoVersion(1, 27), client.Info().Version)

	result, err := client.BuildDerivation(context.Background(), "/nix/store/xyz-test.drv", drv, daemon.BuildModeNormal)
	assert.NoError(t, err)
	assert.Equal(t, daemon.BuildStatusBuilt, result.Status)
	assert.Equal(t, "", result.ErrorMsg)
	// Timing fields should be zero (not sent at proto < 1.29)
	assert.Equal(t, uint64(0), result.TimesBuilt)
	assert.False(t, result.IsNonDeterministic)
	assert.Equal(t, uint64(0), result.StartTime)
	assert.Equal(t, uint64(0), result.StopTime)
	// BuiltOutputs should be nil (not sent at proto < 1.28)
	assert.Nil(t, result.BuiltOutputs)
}

// Error tests for build operations

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
			for range count {
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

package daemon_test

import (
	"net"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/require"
)

func TestBuildDerivationNil(t *testing.T) {
	client := &daemon.Client{}

	_, err := client.BuildDerivation(t.Context(), "/nix/store/abc.drv", nil, daemon.BuildModeNormal)
	require.ErrorIs(t, err, daemon.ErrNilDerivation)
}

func TestClientBuildPaths(t *testing.T) {
	mock := newMockDaemon(t)

	mock.onAccept(func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		require.Equal(t, uint64(daemon.OpBuildPaths), op)

		// read paths (count + strings)
		_, _ = dec.ReadUint64() // count = 1
		_, _ = dec.ReadString() // path

		// read build mode
		_, _ = dec.ReadUint64()

		// LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// Response: uint64(1)
		_ = enc.WriteUint64(1)

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
	require.NoError(t, err)

	defer client.Close()

	err = client.BuildPaths(t.Context(), []string{"/nix/store/abc-test.drv"}, daemon.BuildModeNormal)
	require.NoError(t, err)
}

func TestClientEnsurePath(t *testing.T) {
	mock := newMockDaemon(t)

	mock.onAccept(func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		require.Equal(t, uint64(daemon.OpEnsurePath), op)

		_, _ = dec.ReadString() // path

		// LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// Response: uint64(1)
		_ = enc.WriteUint64(1)

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
	require.NoError(t, err)

	defer client.Close()

	err = client.EnsurePath(t.Context(), "/nix/store/abc-test")
	require.NoError(t, err)
}

func TestClientBuildPathsWithResults(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemon(t)

	mock.onAccept(func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		require.Equal(t, uint64(daemon.OpBuildPathsWithResults), op)

		// read paths (count + strings)
		_, _ = dec.ReadUint64() // count = 1
		_, _ = dec.ReadString() // path

		// read build mode
		_, _ = dec.ReadUint64()

		// LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// Response: count of results = 1
		_ = enc.WriteUint64(1)

		// DerivedPath string (ignored by client)
		_ = enc.WriteString("/nix/store/abc-test.drv!out")

		// BuildResult fields
		_ = enc.WriteUint64(uint64(daemon.BuildStatusBuilt)) // status
		_ = enc.WriteString("")                              // errorMsg
		_ = enc.WriteUint64(1)                               // timesBuilt
		_ = enc.WriteUint64(0)                               // isNonDeterministic
		_ = enc.WriteUint64(1700000000)                      // startTime
		_ = enc.WriteUint64(1700000060)                      // stopTime
		_ = enc.WriteUint64(0)                               // cpuUser: None
		_ = enc.WriteUint64(0)                               // cpuSystem: None
		_ = enc.WriteUint64(0)                               // builtOutputs count

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)

	rq.NoError(err)

	defer client.Close()

	results, err := client.BuildPathsWithResults(
		t.Context(),
		[]string{"/nix/store/abc-test.drv!out"},
		daemon.BuildModeNormal,
	)
	rq.NoError(err)
	rq.Len(results, 1)
	rq.Equal(daemon.BuildStatusBuilt, results[0].Status)
	rq.Equal("", results[0].ErrorMsg)
	rq.Equal(uint64(1), results[0].TimesBuilt)
	rq.False(results[0].IsNonDeterministic)
	rq.Equal(uint64(1700000000), results[0].StartTime)
	rq.Equal(uint64(1700000060), results[0].StopTime)
}

func TestClientBuildDerivation(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemon(t)

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

	mock.onAccept(func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		require.Equal(t, uint64(daemon.OpBuildDerivation), op)

		// read drvPath
		_, _ = dec.ReadString()

		// read outputs count
		count, _ := dec.ReadUint64()
		require.Equal(t, uint64(1), count)

		// read output: name, path, hashAlgo, hash
		_, _ = dec.ReadString()
		_, _ = dec.ReadString()
		_, _ = dec.ReadString()
		_, _ = dec.ReadString()

		// read inputs count + paths
		_, _ = dec.ReadUint64()
		_, _ = dec.ReadString()

		// read platform, builder
		_, _ = dec.ReadString()
		_, _ = dec.ReadString()

		// read args count + args
		_, _ = dec.ReadUint64()
		_, _ = dec.ReadString()
		_, _ = dec.ReadString()

		// read env count + entries
		_, _ = dec.ReadUint64()
		_, _ = dec.ReadString()
		_, _ = dec.ReadString()

		// read build mode
		_, _ = dec.ReadUint64()

		// send LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// send BuildResult: status=Built(0), errorMsg="", timesBuilt=1,
		// isNonDeterministic=false, startTime=100, stopTime=200, builtOutputs count=0
		_ = enc.WriteUint64(0) // Built

		_ = enc.WriteString("") // errorMsg

		_ = enc.WriteUint64(1)   // timesBuilt
		_ = enc.WriteUint64(0)   // isNonDeterministic
		_ = enc.WriteUint64(100) // startTime
		_ = enc.WriteUint64(200) // stopTime
		_ = enc.WriteUint64(0)   // cpuUser: None
		_ = enc.WriteUint64(0)   // cpuSystem: None
		_ = enc.WriteUint64(0)   // builtOutputs count

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)

	rq.NoError(err)

	defer client.Close()

	result, err := client.BuildDerivation(t.Context(), "/nix/store/xyz-test.drv", drv, daemon.BuildModeNormal)
	rq.NoError(err)
	rq.Equal(daemon.BuildStatusBuilt, result.Status)
	rq.Equal(uint64(1), result.TimesBuilt)
	rq.Equal(uint64(100), result.StartTime)
	rq.Equal(uint64(200), result.StopTime)
}

// Version-specific build tests

func TestBuildPathsWithResultsUnsupportedVersion(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))

	client, err := daemon.Connect(t.Context(), mock.path)

	rq.NoError(err)

	defer client.Close()

	_, err = client.BuildPathsWithResults(t.Context(), []string{"/nix/store/abc.drv!out"}, daemon.BuildModeNormal)
	rq.Error(err)
	rq.ErrorIs(err, daemon.ErrUnsupportedOperation)
}

// TestClientBuildDerivationProto127 connects at proto 1.27 and calls
// BuildDerivation. At proto 1.27 the BuildResult wire format omits timing
// fields (proto < 1.29), CPU times (proto < 1.37), and builtOutputs
// (proto < 1.28). The mock sends only status + errorMsg.
func TestClientBuildDerivationProto127(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))

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

	mock.onAccept(func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		// read op code
		op, _ := dec.ReadUint64()
		require.Equal(t, uint64(daemon.OpBuildDerivation), op)

		// read drvPath
		_, _ = dec.ReadString()

		// read outputs count
		count, _ := dec.ReadUint64()
		require.Equal(t, uint64(1), count)

		// read output: name, path, hashAlgo, hash
		_, _ = dec.ReadString()
		_, _ = dec.ReadString()
		_, _ = dec.ReadString()
		_, _ = dec.ReadString()

		// read inputs count + paths
		_, _ = dec.ReadUint64()
		_, _ = dec.ReadString()

		// read platform, builder
		_, _ = dec.ReadString()
		_, _ = dec.ReadString()

		// read args count + args
		_, _ = dec.ReadUint64()
		_, _ = dec.ReadString()
		_, _ = dec.ReadString()

		// read env count + entries
		_, _ = dec.ReadUint64()
		_, _ = dec.ReadString()
		_, _ = dec.ReadString()

		// read build mode
		_, _ = dec.ReadUint64()

		// send LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// send BuildResult for proto 1.27:
		// Only status + errorMsg. No timing fields, no CPU times, no builtOutputs.
		_ = enc.WriteUint64(uint64(daemon.BuildStatusBuilt)) // status
		_ = enc.WriteString("")                              // errorMsg

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)

	rq.NoError(err)

	defer client.Close()

	rq.Equal(daemon.ProtoVersion(1, 27), client.Info().Version)

	result, err := client.BuildDerivation(t.Context(), "/nix/store/xyz-test.drv", drv, daemon.BuildModeNormal)
	rq.NoError(err)
	rq.Equal(daemon.BuildStatusBuilt, result.Status)
	rq.Equal("", result.ErrorMsg)
	// Timing fields should be zero (not sent at proto < 1.29)
	rq.Equal(uint64(0), result.TimesBuilt)
	rq.False(result.IsNonDeterministic)
	rq.Equal(uint64(0), result.StartTime)
	rq.Equal(uint64(0), result.StopTime)
	// BuiltOutputs should be nil (not sent at proto < 1.28)
	rq.Nil(result.BuiltOutputs)
}

// Error tests for build operations

func TestClientBuildPathsDaemonError(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemon(t)

	expectedErr := &daemon.Error{
		Type:    "Error",
		Level:   0,
		Name:    "BuildError",
		Message: "build of '/nix/store/zzz-fail.drv' failed",
	}

	mock.onAccept(respondWithError(daemon.OpBuildPaths, func(conn net.Conn) {
		dec := wire.NewDecoder(conn, 64*1024)

		// read count + path strings
		count, _ := dec.ReadUint64()
		for range count {
			_, _ = dec.ReadString()
		}
		// read build mode
		_, _ = dec.ReadUint64()
	}, expectedErr))

	client, err := daemon.Connect(t.Context(), mock.path)

	rq.NoError(err)

	defer client.Close()

	err = client.BuildPaths(t.Context(), []string{"/nix/store/zzz-fail.drv"}, daemon.BuildModeNormal)
	rq.Error(err)

	var daemonErr *daemon.Error
	rq.ErrorAs(err, &daemonErr)
	rq.Equal("Error", daemonErr.Type)
	rq.Equal("build of '/nix/store/zzz-fail.drv' failed", daemonErr.Message)
}

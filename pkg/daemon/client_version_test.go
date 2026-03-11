package daemon_test

import (
	"context"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/assert"
)

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

func TestAddBuildLogUnsupportedVersion(t *testing.T) {
	mock, clientConn := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))
	defer mock.conn.Close()

	go func() {
		mock.handshake()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	err = client.AddBuildLog(context.Background(), "/nix/store/abc-test.drv", strings.NewReader("log"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, daemon.ErrUnsupportedOperation)
}

func TestAddMultipleToStoreUnsupportedVersion(t *testing.T) {
	mock, clientConn := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))
	defer mock.conn.Close()

	go func() {
		mock.handshake()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	err = client.AddMultipleToStore(context.Background(), nil, false, false)
	assert.Error(t, err)
	assert.ErrorIs(t, err, daemon.ErrUnsupportedOperation)
}

func TestAddPermRootUnsupportedVersion(t *testing.T) {
	mock, clientConn := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))
	defer mock.conn.Close()

	go func() {
		mock.handshake()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	_, err = client.AddPermRoot(context.Background(), "/nix/store/abc-test", "/home/user/result")
	assert.Error(t, err)
	assert.ErrorIs(t, err, daemon.ErrUnsupportedOperation)
}

func TestQueryDerivationOutputMapUnsupportedVersion(t *testing.T) {
	mock, clientConn := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))
	defer mock.conn.Close()

	go func() {
		mock.handshake()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	_, err = client.QueryDerivationOutputMap(context.Background(), "/nix/store/abc.drv")
	assert.Error(t, err)
	assert.ErrorIs(t, err, daemon.ErrUnsupportedOperation)
}

func TestQueryMissingUnsupportedVersion(t *testing.T) {
	mock, clientConn := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))
	defer mock.conn.Close()

	go func() {
		mock.handshake()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	_, err = client.QueryMissing(context.Background(), []string{"/nix/store/abc.drv!out"})
	assert.Error(t, err)
	assert.ErrorIs(t, err, daemon.ErrUnsupportedOperation)
}

func TestRegisterDrvOutputUnsupportedVersion(t *testing.T) {
	mock, clientConn := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))
	defer mock.conn.Close()

	go func() {
		mock.handshake()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	err = client.RegisterDrvOutput(context.Background(), "sha256:abc!out")
	assert.Error(t, err)
	assert.ErrorIs(t, err, daemon.ErrUnsupportedOperation)
}

func TestQueryRealisationUnsupportedVersion(t *testing.T) {
	mock, clientConn := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))
	defer mock.conn.Close()

	go func() {
		mock.handshake()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	_, err = client.QueryRealisation(context.Background(), "sha256:abc!out")
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

// TestClientQueryPathInfoProto123 connects at proto 1.23 (MinProtocolVersion)
// and calls QueryPathInfo. At proto 1.23 (which is >= ProtoVersionPathInfoMeta
// = 1.16), the full PathInfo including ultimate/sigs/ca is sent.
//
// NOTE: The original task specified proto 1.15 to test the case where
// ultimate/sigs/ca are NOT sent (proto < 1.16). However, proto 1.15 is below
// MinProtocolVersion (1.23), and the client handshake explicitly rejects
// versions below MinProtocolVersion. Since ProtoVersionPathInfoMeta (1.16)
// < MinProtocolVersion (1.23), the "no meta" code path cannot be exercised
// through the client. This test instead verifies QueryPathInfo works correctly
// at MinProtocolVersion with a lower-version mock daemon.
func TestClientQueryPathInfoProto123(t *testing.T) {
	mock, clientConn := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 23))
	defer mock.conn.Close()

	go func() {
		mock.handshake()

		var buf [8]byte

		// Read op code
		_, _ = io.ReadFull(mock.conn, buf[:])
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpQueryPathInfo), op)

		// Read path string
		_, _ = wire.ReadString(mock.conn, 64*1024)

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = mock.conn.Write(buf[:])

		// Send found = true
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = mock.conn.Write(buf[:])

		// Send PathInfo fields
		writeWireStringTo(mock.conn, "/nix/store/xyz-test.drv") // deriver
		writeWireStringTo(mock.conn, "sha256:abc123")           // narHash

		// references: count=1
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = mock.conn.Write(buf[:])
		writeWireStringTo(mock.conn, "/nix/store/dep-one")

		binary.LittleEndian.PutUint64(buf[:], 1700000000) // registrationTime
		_, _ = mock.conn.Write(buf[:])

		binary.LittleEndian.PutUint64(buf[:], 54321) // narSize
		_, _ = mock.conn.Write(buf[:])

		// Proto 1.23 >= 1.16, so we DO send ultimate/sigs/ca
		binary.LittleEndian.PutUint64(buf[:], 0) // ultimate = false
		_, _ = mock.conn.Write(buf[:])

		// sigs: count=0
		binary.LittleEndian.PutUint64(buf[:], 0)
		_, _ = mock.conn.Write(buf[:])

		writeWireStringTo(mock.conn, "") // ca = ""
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	assert.Equal(t, daemon.ProtoVersion(1, 23), client.Info().Version)

	info, err := client.QueryPathInfo(context.Background(), "/nix/store/abc-test")
	assert.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "/nix/store/abc-test", info.StorePath)
	assert.Equal(t, "/nix/store/xyz-test.drv", info.Deriver)
	assert.Equal(t, "sha256:abc123", info.NarHash)
	assert.Equal(t, []string{"/nix/store/dep-one"}, info.References)
	assert.Equal(t, uint64(1700000000), info.RegistrationTime)
	assert.Equal(t, uint64(54321), info.NarSize)
	// At proto 1.23 (>= 1.16), ultimate/sigs/ca ARE included
	assert.False(t, info.Ultimate)
	assert.Empty(t, info.Sigs)
	assert.Equal(t, "", info.CA)
}

// TestClientQueryValidPathsPreSubstituteOk connects at proto 1.23
// (MinProtocolVersion, which is below ProtoVersionSubstituteOk = 1.27).
// Calls QueryValidPaths with substituteOk=true. At proto < 1.27, the
// substituteOk field is NOT sent on the wire, so the mock must NOT try
// to read it.
func TestClientQueryValidPathsPreSubstituteOk(t *testing.T) {
	mock, clientConn := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 23))
	defer mock.conn.Close()

	queryPaths := []string{
		"/nix/store/aaa-foo",
		"/nix/store/bbb-bar",
	}

	validResult := []string{
		"/nix/store/aaa-foo",
	}

	go func() {
		mock.handshake()

		var buf [8]byte

		// Read op code
		_, _ = io.ReadFull(mock.conn, buf[:])
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpQueryValidPaths), op)

		// Read paths list: count + strings
		_, _ = io.ReadFull(mock.conn, buf[:])
		count := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(2), count)

		for i := uint64(0); i < count; i++ {
			_, _ = wire.ReadString(mock.conn, 64*1024)
		}

		// DO NOT read substituteOk — proto 1.21 < 1.27

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = mock.conn.Write(buf[:])

		// Send result paths: count + strings
		binary.LittleEndian.PutUint64(buf[:], uint64(len(validResult)))
		_, _ = mock.conn.Write(buf[:])

		for _, p := range validResult {
			writeWireStringTo(mock.conn, p)
		}
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	assert.Equal(t, daemon.ProtoVersion(1, 23), client.Info().Version)

	result, err := client.QueryValidPaths(context.Background(), queryPaths, true)
	assert.NoError(t, err)
	assert.Equal(t, validResult, result)
}

// TestClientSetOptionsProto123 connects at proto 1.23 (MinProtocolVersion,
// which is >= ProtoVersionOverrides = 1.12) and calls SetOptions with
// settings that include an overrides map. This confirms that at
// MinProtocolVersion, overrides ARE always sent on the wire.
func TestClientSetOptionsProto123(t *testing.T) {
	mock, clientConn := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 23))
	defer mock.conn.Close()

	go func() {
		mock.handshake()
		mock.respondSetOptions()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	assert.Equal(t, daemon.ProtoVersion(1, 23), client.Info().Version)

	settings := &daemon.ClientSettings{
		KeepFailed:     true,
		KeepGoing:      false,
		TryFallback:    false,
		Verbosity:      daemon.VerbInfo,
		MaxBuildJobs:   2,
		MaxSilentTime:  60,
		BuildVerbosity: daemon.VerbError,
		BuildCores:     4,
		UseSubstitutes: true,
		Overrides: map[string]string{
			"sandbox":               "true",
			"max-substitution-jobs": "8",
		},
	}

	err = client.SetOptions(context.Background(), settings)
	assert.NoError(t, err)
}

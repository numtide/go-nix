package daemon_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientIsValidPath(t *testing.T) {
	mock := newMockDaemon(t)
	mock.onAccept(respondIsValidPath(true))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	valid, err := client.IsValidPath(context.Background(), "/nix/store/abc-test")
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestClientIsValidPathFalse(t *testing.T) {
	mock := newMockDaemon(t)
	mock.onAccept(respondIsValidPath(false))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	valid, err := client.IsValidPath(context.Background(), "/nix/store/nonexistent")
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestClientQueryPathInfo(t *testing.T) {
	mock := newMockDaemon(t)

	expected := &daemon.PathInfo{
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

	mock.onAccept(respondQueryPathInfo(expected))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	info, err := client.QueryPathInfo(context.Background(), "/nix/store/abc-test")
	assert.NoError(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, expected.StorePath, info.StorePath)
	assert.Equal(t, expected.Deriver, info.Deriver)
	assert.Equal(t, expected.NarHash, info.NarHash)
	assert.Equal(t, expected.References, info.References)
	assert.Equal(t, expected.RegistrationTime, info.RegistrationTime)
	assert.Equal(t, expected.NarSize, info.NarSize)
	assert.Equal(t, expected.Ultimate, info.Ultimate)
	assert.Equal(t, expected.Sigs, info.Sigs)
	assert.Equal(t, expected.CA, info.CA)
}

func TestClientQueryPathInfoNotFound(t *testing.T) {
	mock := newMockDaemon(t)

	mock.onAccept(respondQueryPathInfoNotFound())

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	info, err := client.QueryPathInfo(context.Background(), "/nix/store/nonexistent")
	assert.NoError(t, err)
	assert.Nil(t, info)
}

func TestClientNarFromPath(t *testing.T) {
	mock := newMockDaemon(t)

	fileContent := "fake-nar-content-for-testing"

	mock.onAccept(func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpNarFromPath), op)

		_, _ = wire.ReadString(conn, 64*1024) // path

		// LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send a valid NAR (raw format, not length-prefixed).
		writeWireStringTo(conn, "nix-archive-1")
		writeWireStringTo(conn, "(")
		writeWireStringTo(conn, "type")
		writeWireStringTo(conn, "regular")
		writeWireStringTo(conn, "contents")
		writeWireStringTo(conn, fileContent)
		writeWireStringTo(conn, ")")

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	rc, err := client.NarFromPath(context.Background(), "/nix/store/abc-test")
	assert.NoError(t, err)

	// The returned data is the complete NAR including wire formatting.
	data, err := io.ReadAll(rc)
	assert.NoError(t, err)
	assert.True(t, len(data) > 0)
	// Check that the NAR contains the file content.
	assert.Contains(t, string(data), fileContent)

	err = rc.Close()
	assert.NoError(t, err)
}

func TestClientFindRoots(t *testing.T) {
	mock := newMockDaemon(t)

	mock.onAccept(func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // op code

		// LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Map: count=1
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = conn.Write(buf[:])
		writeWireStringTo(conn, "/proc/1/root")
		writeWireStringTo(conn, "/nix/store/abc-test")

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	roots, err := client.FindRoots(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"/proc/1/root": "/nix/store/abc-test"}, roots)
}

func TestClientQueryAllValidPaths(t *testing.T) {
	mock := newMockDaemon(t)

	expected := []string{
		"/nix/store/aaa-foo",
		"/nix/store/bbb-bar",
		"/nix/store/ccc-baz",
	}

	mock.onAccept(respondQueryAllValidPaths(expected))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	paths, err := client.QueryAllValidPaths(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, expected, paths)
}

func TestClientQueryValidPaths(t *testing.T) {
	mock := newMockDaemon(t)

	queryPaths := []string{
		"/nix/store/aaa-foo",
		"/nix/store/bbb-bar",
		"/nix/store/ccc-nonexistent",
	}

	validPaths := []string{
		"/nix/store/aaa-foo",
		"/nix/store/bbb-bar",
	}

	mock.onAccept(respondQueryValidPaths(validPaths))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	result, err := client.QueryValidPaths(context.Background(), queryPaths, true)
	assert.NoError(t, err)
	assert.Equal(t, validPaths, result)
}

func TestClientQuerySubstitutablePaths(t *testing.T) {
	mock := newMockDaemon(t)

	queryPaths := []string{
		"/nix/store/aaa-foo",
		"/nix/store/bbb-bar",
	}

	substitutable := []string{
		"/nix/store/aaa-foo",
	}

	mock.onAccept(respondQuerySubstitutablePaths(substitutable))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	result, err := client.QuerySubstitutablePaths(context.Background(), queryPaths)
	assert.NoError(t, err)
	assert.Equal(t, substitutable, result)
}

func TestClientQuerySubstitutablePathInfos(t *testing.T) {
	mock := newMockDaemon(t)

	expected := map[string]*daemon.SubstitutablePathInfo{
		"/nix/store/aaa-foo": {
			Deriver:      "/nix/store/aaa-foo.drv",
			References:   []string{"/nix/store/bbb-dep"},
			DownloadSize: 1048576,
			NarSize:      2097152,
		},
		"/nix/store/ccc-baz": {
			Deriver:      "",
			References:   []string{},
			DownloadSize: 512000,
			NarSize:      1024000,
		},
	}

	mock.onAccept(respondQuerySubstitutablePathInfos(expected))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	result, err := client.QuerySubstitutablePathInfos(context.Background(), map[string]string{
		"/nix/store/aaa-foo": "",
		"/nix/store/bbb-bar": "",
		"/nix/store/ccc-baz": "",
	})
	assert.NoError(t, err)
	assert.Len(t, result, 2)

	// The mock iterates over a Go map so order may vary; check by key.
	for path, info := range expected {
		got, ok := result[path]
		assert.True(t, ok, "expected path %s in result", path)
		assert.Equal(t, info.Deriver, got.Deriver)
		assert.Equal(t, info.References, got.References)
		assert.Equal(t, info.DownloadSize, got.DownloadSize)
		assert.Equal(t, info.NarSize, got.NarSize)
	}
}

func TestClientQuerySubstitutablePathInfosEmpty(t *testing.T) {
	mock := newMockDaemon(t)

	mock.onAccept(respondQuerySubstitutablePathInfos(map[string]*daemon.SubstitutablePathInfo{}))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	result, err := client.QuerySubstitutablePathInfos(context.Background(), map[string]string{
		"/nix/store/nonexistent": "",
	})
	assert.NoError(t, err)
	assert.Len(t, result, 0)
}

func TestClientQueryReferrers(t *testing.T) {
	mock := newMockDaemon(t)

	referrers := []string{
		"/nix/store/xxx-depends-on-abc",
		"/nix/store/yyy-also-depends",
	}

	mock.onAccept(respondQueryReferrers(referrers))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	result, err := client.QueryReferrers(context.Background(), "/nix/store/abc-test")
	assert.NoError(t, err)
	assert.Equal(t, referrers, result)
}

func TestClientQueryValidDerivers(t *testing.T) {
	mock := newMockDaemon(t)

	derivers := []string{
		"/nix/store/abc-test.drv",
		"/nix/store/def-test.drv",
	}

	mock.onAccept(respondQueryValidDerivers(derivers))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	result, err := client.QueryValidDerivers(context.Background(), "/nix/store/abc-test")
	assert.NoError(t, err)
	assert.Equal(t, derivers, result)
}

func TestClientQueryDerivationOutputMap(t *testing.T) {
	mock := newMockDaemon(t)

	outputs := map[string]string{
		"out": "/nix/store/abc-test",
		"dev": "/nix/store/abc-test-dev",
		"lib": "/nix/store/abc-test-lib",
	}

	mock.onAccept(respondQueryDerivationOutputMap(outputs))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	result, err := client.QueryDerivationOutputMap(context.Background(), "/nix/store/abc-test.drv")
	assert.NoError(t, err)
	assert.Equal(t, outputs, result)
}

func TestClientQueryMissing(t *testing.T) {
	mock := newMockDaemon(t)

	expected := &daemon.MissingInfo{
		WillBuild:      []string{"/nix/store/aaa-needs-build.drv"},
		WillSubstitute: []string{"/nix/store/bbb-from-cache"},
		Unknown:        []string{"/nix/store/ccc-unknown"},
		DownloadSize:   1048576,
		NarSize:        2097152,
	}

	mock.onAccept(respondQueryMissing(expected))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	result, err := client.QueryMissing(context.Background(), []string{
		"/nix/store/aaa-needs-build.drv",
		"/nix/store/bbb-from-cache",
		"/nix/store/ccc-unknown",
	})
	assert.NoError(t, err)
	assert.Equal(t, expected.WillBuild, result.WillBuild)
	assert.Equal(t, expected.WillSubstitute, result.WillSubstitute)
	assert.Equal(t, expected.Unknown, result.Unknown)
	assert.Equal(t, expected.DownloadSize, result.DownloadSize)
	assert.Equal(t, expected.NarSize, result.NarSize)
}

func TestClientQueryPathFromHashPart(t *testing.T) {
	mock := newMockDaemon(t)

	expectedPath := "/nix/store/abc123-test"

	mock.onAccept(respondQueryPathFromHashPart(expectedPath))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	result, err := client.QueryPathFromHashPart(context.Background(), "abc123")
	assert.NoError(t, err)
	assert.Equal(t, expectedPath, result)
}

func TestClientQueryRealisation(t *testing.T) {
	mock := newMockDaemon(t)

	realisations := []string{
		`{"id":"sha256:abc!out","outPath":"/nix/store/abc-out","signatures":["mykey:c2ln"],"dependentRealisations":{}}`,
	}

	mock.onAccept(respondQueryRealisation(realisations))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	result, err := client.QueryRealisation(context.Background(), "sha256:abc!out")
	assert.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "sha256:abc!out", result[0].ID)
	assert.Equal(t, "/nix/store/abc-out", result[0].OutPath)
	assert.Equal(t, []string{"mykey:c2ln"}, result[0].Signatures)
}

// Version-specific query tests

func TestQueryDerivationOutputMapUnsupportedVersion(t *testing.T) {
	mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	_, err = client.QueryDerivationOutputMap(context.Background(), "/nix/store/abc.drv")
	assert.Error(t, err)
	assert.ErrorIs(t, err, daemon.ErrUnsupportedOperation)
}

func TestQueryMissingUnsupportedVersion(t *testing.T) {
	mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	_, err = client.QueryMissing(context.Background(), []string{"/nix/store/abc.drv!out"})
	assert.Error(t, err)
	assert.ErrorIs(t, err, daemon.ErrUnsupportedOperation)
}

func TestQueryRealisationUnsupportedVersion(t *testing.T) {
	mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	_, err = client.QueryRealisation(context.Background(), "sha256:abc!out")
	assert.Error(t, err)
	assert.ErrorIs(t, err, daemon.ErrUnsupportedOperation)
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
	mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 23))

	mock.onAccept(func(conn net.Conn) error {
		var buf [8]byte

		// Read op code
		_, _ = io.ReadFull(conn, buf[:])
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpQueryPathInfo), op)

		// Read path string
		_, _ = wire.ReadString(conn, 64*1024)

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send found = true
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = conn.Write(buf[:])

		// Send PathInfo fields
		writeWireStringTo(conn, "/nix/store/xyz-test.drv") // deriver
		writeWireStringTo(conn, "sha256:abc123")           // narHash

		// references: count=1
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = conn.Write(buf[:])
		writeWireStringTo(conn, "/nix/store/dep-one")

		binary.LittleEndian.PutUint64(buf[:], 1700000000) // registrationTime
		_, _ = conn.Write(buf[:])

		binary.LittleEndian.PutUint64(buf[:], 54321) // narSize
		_, _ = conn.Write(buf[:])

		// Proto 1.23 >= 1.16, so we DO send ultimate/sigs/ca
		binary.LittleEndian.PutUint64(buf[:], 0) // ultimate = false
		_, _ = conn.Write(buf[:])

		// sigs: count=0
		binary.LittleEndian.PutUint64(buf[:], 0)
		_, _ = conn.Write(buf[:])

		writeWireStringTo(conn, "") // ca = ""

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
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
	mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 23))

	queryPaths := []string{
		"/nix/store/aaa-foo",
		"/nix/store/bbb-bar",
	}

	validResult := []string{
		"/nix/store/aaa-foo",
	}

	mock.onAccept(func(conn net.Conn) error {
		var buf [8]byte

		// Read op code
		_, _ = io.ReadFull(conn, buf[:])
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpQueryValidPaths), op)

		// Read paths list: count + strings
		_, _ = io.ReadFull(conn, buf[:])
		count := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(2), count)

		for range count {
			_, _ = wire.ReadString(conn, 64*1024)
		}

		// DO NOT read substituteOk — proto 1.21 < 1.27

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send result paths: count + strings
		binary.LittleEndian.PutUint64(buf[:], uint64(len(validResult)))
		_, _ = conn.Write(buf[:])

		for _, p := range validResult {
			writeWireStringTo(conn, p)
		}

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	assert.Equal(t, daemon.ProtoVersion(1, 23), client.Info().Version)

	result, err := client.QueryValidPaths(context.Background(), queryPaths, true)
	assert.NoError(t, err)
	assert.Equal(t, validResult, result)
}

// Error tests for query operations

func TestClientIsValidPathDaemonError(t *testing.T) {
	mock := newMockDaemon(t)

	expectedErr := &daemon.Error{
		Type:    "Error",
		Level:   0,
		Name:    "InvalidPath",
		Message: "path '/nix/store/xxx-invalid' is not valid",
	}

	mock.onAccept(respondWithError(daemon.OpIsValidPath, func(conn net.Conn) {
		_, _ = wire.ReadString(conn, 64*1024) // path
	}, expectedErr))

	client, err := daemon.Connect(t.Context(), mock.path)
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
	mock := newMockDaemon(t)

	expectedErr := &daemon.Error{
		Type:    "Error",
		Level:   0,
		Name:    "InvalidPath",
		Message: "path '/nix/store/yyy-broken' is corrupted",
	}

	mock.onAccept(respondWithError(daemon.OpQueryPathInfo, func(conn net.Conn) {
		_, _ = wire.ReadString(conn, 64*1024) // path
	}, expectedErr))

	client, err := daemon.Connect(t.Context(), mock.path)
	assert.NoError(t, err)

	defer client.Close()

	_, err = client.QueryPathInfo(context.Background(), "/nix/store/yyy-broken")
	assert.Error(t, err)

	var daemonErr *daemon.Error
	assert.True(t, errors.As(err, &daemonErr))
	assert.Equal(t, "Error", daemonErr.Type)
	assert.Equal(t, "path '/nix/store/yyy-broken' is corrupted", daemonErr.Message)
}

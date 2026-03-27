package daemon_test

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/require"
)

func TestClientIsValidPath(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemon(t)
	mock.onAccept(respondIsValidPath(true))

	client, err := daemon.Connect(t.Context(), mock.path)
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	valid, err := client.IsValidPath(t.Context(), "/nix/store/abc-test")
	rq.NoError(err)
	rq.True(valid)
}

func TestClientIsValidPathFalse(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemon(t)
	mock.onAccept(respondIsValidPath(false))

	client, err := daemon.Connect(t.Context(), mock.path)
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	valid, err := client.IsValidPath(t.Context(), "/nix/store/nonexistent")
	rq.NoError(err)
	rq.False(valid)
}

func TestClientQueryPathInfo(t *testing.T) {
	rq := require.New(t)

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
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	info, err := client.QueryPathInfo(t.Context(), "/nix/store/abc-test")
	rq.NoError(err)
	rq.NotNil(info)
	rq.Equal(expected.StorePath, info.StorePath)
	rq.Equal(expected.Deriver, info.Deriver)
	rq.Equal(expected.NarHash, info.NarHash)
	rq.Equal(expected.References, info.References)
	rq.Equal(expected.RegistrationTime, info.RegistrationTime)
	rq.Equal(expected.NarSize, info.NarSize)
	rq.Equal(expected.Ultimate, info.Ultimate)
	rq.Equal(expected.Sigs, info.Sigs)
	rq.Equal(expected.CA, info.CA)
}

func TestClientQueryPathInfoNotFound(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemon(t)

	mock.onAccept(respondQueryPathInfoNotFound())

	client, err := daemon.Connect(t.Context(), mock.path)

	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	info, err := client.QueryPathInfo(t.Context(), "/nix/store/nonexistent")
	rq.ErrorIs(err, daemon.ErrNotFound)
	rq.Nil(info)
}

func TestClientNarFromPath(t *testing.T) {
	rq := require.New(t)
	mock := newMockDaemon(t)

	fileContent := "fake-nar-content-for-testing"

	mock.onAccept(func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		rq.Equal(uint64(daemon.OpNarFromPath), op)

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
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	rc, err := client.NarFromPath(t.Context(), "/nix/store/abc-test", nil)
	rq.NoError(err)

	// The returned data is the complete NAR including wire formatting.
	data, err := io.ReadAll(rc)
	rq.NoError(err)
	rq.True(len(data) > 0)
	// Check that the NAR contains the file content.
	rq.Contains(string(data), fileContent)

	err = rc.Close()
	rq.NoError(err)
}

func TestClientFindRoots(t *testing.T) {
	rq := require.New(t)

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

	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	roots, err := client.FindRoots(t.Context())
	rq.NoError(err)
	rq.Equal(map[string]string{"/proc/1/root": "/nix/store/abc-test"}, roots)
}

func TestClientQueryAllValidPaths(t *testing.T) {
	rq := require.New(t)
	mock := newMockDaemon(t)

	expected := []string{
		"/nix/store/aaa-foo",
		"/nix/store/bbb-bar",
		"/nix/store/ccc-baz",
	}

	mock.onAccept(respondQueryAllValidPaths(expected))

	client, err := daemon.Connect(t.Context(), mock.path)
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	paths, err := client.QueryAllValidPaths(t.Context())
	rq.NoError(err)
	rq.Equal(expected, paths)
}

func TestClientQueryValidPaths(t *testing.T) {
	rq := require.New(t)
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
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	result, err := client.QueryValidPaths(t.Context(), queryPaths, true)
	rq.NoError(err)
	rq.Equal(validPaths, result)
}

func TestClientQuerySubstitutablePaths(t *testing.T) {
	rq := require.New(t)
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
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	result, err := client.QuerySubstitutablePaths(t.Context(), queryPaths)
	rq.NoError(err)
	rq.Equal(substitutable, result)
}

func TestClientQuerySubstitutablePathInfos(t *testing.T) {
	rq := require.New(t)
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
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	result, err := client.QuerySubstitutablePathInfos(t.Context(), map[string]string{
		"/nix/store/aaa-foo": "",
		"/nix/store/bbb-bar": "",
		"/nix/store/ccc-baz": "",
	})
	rq.NoError(err)
	rq.Len(result, 2)

	// The mock iterates over a Go map, so order may vary; check by key.
	for path, info := range expected {
		got, ok := result[path]
		rq.True(ok, "expected path %s in result", path)
		rq.Equal(info.Deriver, got.Deriver)
		rq.Equal(info.References, got.References)
		rq.Equal(info.DownloadSize, got.DownloadSize)
		rq.Equal(info.NarSize, got.NarSize)
	}
}

func TestClientQuerySubstitutablePathInfosEmpty(t *testing.T) {
	rq := require.New(t)
	mock := newMockDaemon(t)

	mock.onAccept(respondQuerySubstitutablePathInfos(map[string]*daemon.SubstitutablePathInfo{}))

	client, err := daemon.Connect(t.Context(), mock.path)
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	result, err := client.QuerySubstitutablePathInfos(t.Context(), map[string]string{
		"/nix/store/nonexistent": "",
	})
	rq.NoError(err)
	rq.Len(result, 0)
}

func TestClientQueryReferrers(t *testing.T) {
	rq := require.New(t)
	mock := newMockDaemon(t)

	referrers := []string{
		"/nix/store/xxx-depends-on-abc",
		"/nix/store/yyy-also-depends",
	}

	mock.onAccept(respondQueryReferrers(referrers))

	client, err := daemon.Connect(t.Context(), mock.path)
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	result, err := client.QueryReferrers(t.Context(), "/nix/store/abc-test")
	rq.NoError(err)
	rq.Equal(referrers, result)
}

func TestClientQueryValidDerivers(t *testing.T) {
	rq := require.New(t)
	mock := newMockDaemon(t)

	derivers := []string{
		"/nix/store/abc-test.drv",
		"/nix/store/def-test.drv",
	}

	mock.onAccept(respondQueryValidDerivers(derivers))

	client, err := daemon.Connect(t.Context(), mock.path)
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	result, err := client.QueryValidDerivers(t.Context(), "/nix/store/abc-test")
	rq.NoError(err)
	rq.Equal(derivers, result)
}

func TestClientQueryDerivationOutputMap(t *testing.T) {
	rq := require.New(t)
	mock := newMockDaemon(t)

	outputs := map[string]string{
		"out": "/nix/store/abc-test",
		"dev": "/nix/store/abc-test-dev",
		"lib": "/nix/store/abc-test-lib",
	}

	mock.onAccept(respondQueryDerivationOutputMap(outputs))

	client, err := daemon.Connect(t.Context(), mock.path)
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	result, err := client.QueryDerivationOutputMap(t.Context(), "/nix/store/abc-test.drv")
	rq.NoError(err)
	rq.Equal(outputs, result)
}

func TestClientQueryMissing(t *testing.T) {
	rq := require.New(t)
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
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	result, err := client.QueryMissing(t.Context(), []string{
		"/nix/store/aaa-needs-build.drv",
		"/nix/store/bbb-from-cache",
		"/nix/store/ccc-unknown",
	})
	rq.NoError(err)
	rq.Equal(expected.WillBuild, result.WillBuild)
	rq.Equal(expected.WillSubstitute, result.WillSubstitute)
	rq.Equal(expected.Unknown, result.Unknown)
	rq.Equal(expected.DownloadSize, result.DownloadSize)
	rq.Equal(expected.NarSize, result.NarSize)
}

func TestClientQueryPathFromHashPart(t *testing.T) {
	rq := require.New(t)
	mock := newMockDaemon(t)

	expectedPath := "/nix/store/abc123-test"

	mock.onAccept(respondQueryPathFromHashPart(expectedPath))

	client, err := daemon.Connect(t.Context(), mock.path)
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	result, err := client.QueryPathFromHashPart(t.Context(), "abc123")
	rq.NoError(err)
	rq.Equal(expectedPath, result)
}

func TestClientQueryRealisation(t *testing.T) {
	rq := require.New(t)
	mock := newMockDaemon(t)

	realisations := []string{
		`{"id":"sha256:abc!out","outPath":"/nix/store/abc-out","signatures":["mykey:c2ln"],"dependentRealisations":{}}`,
	}

	mock.onAccept(respondQueryRealisation(realisations))

	client, err := daemon.Connect(t.Context(), mock.path)
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	result, err := client.QueryRealisation(t.Context(), "sha256:abc!out")
	rq.NoError(err)
	require.Len(t, result, 1)
	rq.Equal("sha256:abc!out", result[0].ID)
	rq.Equal("/nix/store/abc-out", result[0].OutPath)
	rq.Equal([]string{"mykey:c2ln"}, result[0].Signatures)
}

// Version-specific query tests

func TestQueryDerivationOutputMapUnsupportedVersion(t *testing.T) {
	rq := require.New(t)
	mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))

	client, err := daemon.Connect(t.Context(), mock.path)
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	_, err = client.QueryDerivationOutputMap(t.Context(), "/nix/store/abc.drv")
	rq.Error(err)
	rq.ErrorIs(err, daemon.ErrUnsupportedOperation)
}

func TestQueryMissingUnsupportedVersion(t *testing.T) {
	rq := require.New(t)
	mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))

	client, err := daemon.Connect(t.Context(), mock.path)
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	_, err = client.QueryMissing(t.Context(), []string{"/nix/store/abc.drv!out"})
	rq.Error(err)
	rq.ErrorIs(err, daemon.ErrUnsupportedOperation)
}

func TestQueryRealisationUnsupportedVersion(t *testing.T) {
	rq := require.New(t)
	mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))

	client, err := daemon.Connect(t.Context(), mock.path)
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	_, err = client.QueryRealisation(t.Context(), "sha256:abc!out")
	rq.Error(err)
	rq.ErrorIs(err, daemon.ErrUnsupportedOperation)
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
	rq := require.New(t)
	mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 23))

	mock.onAccept(func(conn net.Conn) error {
		var buf [8]byte

		// Read op code
		_, _ = io.ReadFull(conn, buf[:])
		op := binary.LittleEndian.Uint64(buf[:])
		rq.Equal(uint64(daemon.OpQueryPathInfo), op)

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
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	rq.Equal(daemon.ProtoVersion(1, 23), client.Info().Version)

	info, err := client.QueryPathInfo(t.Context(), "/nix/store/abc-test")
	rq.NoError(err)
	rq.NotNil(t, info)
	rq.Equal("/nix/store/abc-test", info.StorePath)
	rq.Equal("/nix/store/xyz-test.drv", info.Deriver)
	rq.Equal("sha256:abc123", info.NarHash)
	rq.Equal([]string{"/nix/store/dep-one"}, info.References)
	rq.Equal(uint64(1700000000), info.RegistrationTime)
	rq.Equal(uint64(54321), info.NarSize)
	// At proto 1.23 (>= 1.16), ultimate/sigs/ca ARE included
	rq.False(info.Ultimate)
	rq.Empty(info.Sigs)
	rq.Equal("", info.CA)
}

// TestClientQueryValidPathsPreSubstituteOk connects at proto 1.23
// (MinProtocolVersion, which is below ProtoVersionSubstituteOk = 1.27).
// Calls QueryValidPaths with substituteOk=true. At proto < 1.27, the
// substituteOk field is NOT sent on the wire, so the mock must NOT try
// to read it.
func TestClientQueryValidPathsPreSubstituteOk(t *testing.T) {
	rq := require.New(t)
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
		rq.Equal(uint64(daemon.OpQueryValidPaths), op)

		// Read paths list: count + strings
		_, _ = io.ReadFull(conn, buf[:])
		count := binary.LittleEndian.Uint64(buf[:])
		rq.Equal(uint64(2), count)

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
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	rq.Equal(daemon.ProtoVersion(1, 23), client.Info().Version)

	result, err := client.QueryValidPaths(t.Context(), queryPaths, true)
	rq.NoError(err)
	rq.Equal(validResult, result)
}

// Error tests for query operations

func TestClientIsValidPathDaemonError(t *testing.T) {
	rq := require.New(t)
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
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	_, err = client.IsValidPath(t.Context(), "/nix/store/xxx-invalid")
	rq.Error(err)

	var daemonErr *daemon.Error
	rq.True(errors.As(err, &daemonErr))
	rq.Equal("Error", daemonErr.Type)
	rq.Equal("path '/nix/store/xxx-invalid' is not valid", daemonErr.Message)
}

func TestClientQueryPathInfoDaemonError(t *testing.T) {
	rq := require.New(t)
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
	rq.NoError(err)

	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Fatalf("failed to close client: %s", closeErr)
		}
	})

	_, err = client.QueryPathInfo(t.Context(), "/nix/store/yyy-broken")
	rq.Error(err)

	var daemonErr *daemon.Error
	rq.True(errors.As(err, &daemonErr))
	rq.Equal("Error", daemonErr.Type)
	rq.Equal("path '/nix/store/yyy-broken' is corrupted", daemonErr.Message)
}

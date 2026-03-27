package daemon_test

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/require"
)

func TestClientAddToStore(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemon(t)

	dumpData := []byte("fake-nar-content-for-testing")

	expected := &daemon.PathInfo{
		StorePath:        "/nix/store/abc123-hello-2.12.1",
		Deriver:          "",
		NarHash:          "sha256:1b8m03r63zqhnjf7l5wnldhh7c134p5572hrber4jqabd5b2no80",
		References:       []string{},
		RegistrationTime: 1700000000,
		NarSize:          uint64(len(dumpData)),
		Ultimate:         true,
		Sigs:             []string{},
		CA:               "fixed:r:sha256:1b8m03r63zqhnjf7l5wnldhh7c134p5572hrber4jqabd5b2no80",
	}

	mock.onAccept(respondAddToStore(expected))

	client, err := daemon.Connect(t.Context(), mock.path)

	rq.NoError(err)

	defer client.Close()

	info, err := client.AddToStore(
		t.Context(),
		"hello-2.12.1",
		"fixed:r:sha256",
		[]string{},
		false,
		bytes.NewReader(dumpData),
	)
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

func TestAddToStoreUnsupportedVersion(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 23))

	client, err := daemon.Connect(t.Context(), mock.path)

	rq.NoError(err)

	defer client.Close()

	_, err = client.AddToStore(
		t.Context(),
		"hello",
		"fixed:r:sha256",
		nil,
		false,
		bytes.NewReader([]byte("data")),
	)
	rq.Error(err)
	rq.ErrorIs(err, daemon.ErrUnsupportedOperation)
}

func TestAddToStoreNilSource(t *testing.T) {
	client := &daemon.Client{}

	_, err := client.AddToStore(t.Context(), "hello", "fixed:r:sha256", nil, false, nil)
	require.ErrorIs(t, err, daemon.ErrNilReader)
}

func TestCollectGarbageNilOptions(t *testing.T) {
	client := &daemon.Client{}
	_, err := client.CollectGarbage(t.Context(), nil)
	require.ErrorIs(t, err, daemon.ErrNilOptions)
}

func TestAddToStoreNarNilArgs(t *testing.T) {
	client := &daemon.Client{}

	err := client.AddToStoreNar(t.Context(), nil, nil, false, false)
	require.ErrorIs(t, err, daemon.ErrNilPathInfo)

	err = client.AddToStoreNar(t.Context(), &daemon.PathInfo{}, nil, false, false)
	require.ErrorIs(t, err, daemon.ErrNilReader)
}

func TestAddBuildLogNilReader(t *testing.T) {
	client := &daemon.Client{}

	err := client.AddBuildLog(t.Context(), "/nix/store/abc.drv", nil)
	require.ErrorIs(t, err, daemon.ErrNilReader)
}

func TestClientAddTempRoot(t *testing.T) {
	mock := newMockDaemon(t)

	mock.onAccept(func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		require.Equal(t, uint64(daemon.OpAddTempRoot), op)

		_, _ = dec.ReadString() // path

		// LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// uint64(1) acknowledgment
		_ = enc.WriteUint64(1)

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
	require.NoError(t, err)

	defer client.Close()

	err = client.AddTempRoot(t.Context(), "/nix/store/abc-test")
	require.NoError(t, err)
}

func TestClientAddIndirectRoot(t *testing.T) {
	mock := newMockDaemon(t)

	mock.onAccept(func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		require.Equal(t, uint64(daemon.OpAddIndirectRoot), op)

		_, _ = dec.ReadString() // path

		// LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// uint64(1) acknowledgment
		_ = enc.WriteUint64(1)

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
	require.NoError(t, err)

	defer client.Close()

	err = client.AddIndirectRoot(t.Context(), "/home/user/result")
	require.NoError(t, err)
}

func TestClientAddPermRoot(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemon(t)

	mock.onAccept(func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		require.Equal(t, uint64(daemon.OpAddPermRoot), op)

		_, _ = dec.ReadString() // storePath
		_, _ = dec.ReadString() // gcRoot

		// LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// Response: result path string
		_ = enc.WriteString("/nix/var/nix/gcroots/auto/abc")

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)

	rq.NoError(err)

	defer client.Close()

	resultPath, err := client.AddPermRoot(t.Context(), "/nix/store/abc-test", "/home/user/result")
	rq.NoError(err)
	rq.Equal("/nix/var/nix/gcroots/auto/abc", resultPath)
}

func TestClientAddSignatures(t *testing.T) {
	mock := newMockDaemon(t)

	mock.onAccept(func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		require.Equal(t, uint64(daemon.OpAddSignatures), op)

		_, _ = dec.ReadString() // path

		// read sigs: count + strings
		count, _ := dec.ReadUint64()
		require.Equal(t, uint64(2), count)

		_, _ = dec.ReadString() // sig 1
		_, _ = dec.ReadString() // sig 2

		// LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// uint64(1) acknowledgment
		_ = enc.WriteUint64(1)

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
	require.NoError(t, err)

	defer client.Close()

	err = client.AddSignatures(t.Context(), "/nix/store/abc-test", []string{"sig1", "sig2"})
	require.NoError(t, err)
}

func TestClientRegisterDrvOutput(t *testing.T) {
	mock := newMockDaemon(t)

	mock.onAccept(func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		require.Equal(t, uint64(daemon.OpRegisterDrvOutput), op)

		_, _ = dec.ReadString() // realisation

		// LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
	require.NoError(t, err)

	defer client.Close()

	err = client.RegisterDrvOutput(t.Context(), &daemon.Realisation{
		ID:      "sha256:abc!out",
		OutPath: "/nix/store/abc-out",
	})
	require.NoError(t, err)
}

func TestClientAddToStoreNar(t *testing.T) {
	mock := newMockDaemon(t)

	narData := []byte("fake-nar-content-for-testing")

	info := &daemon.PathInfo{
		StorePath:  "/nix/store/abc-test",
		Deriver:    "/nix/store/xyz-test.drv",
		NarHash:    "sha256:fakehash",
		References: []string{},
		NarSize:    uint64(len(narData)),
		Sigs:       []string{},
	}

	mock.onAccept(func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		require.Equal(t, uint64(daemon.OpAddToStoreNar), op)

		// read PathInfo: storePath, deriver, narHash, refs, regTime, narSize, ultimate, sigs, ca
		_, _ = dec.ReadString() // storePath
		_, _ = dec.ReadString() // deriver
		_, _ = dec.ReadString() // narHash

		_, _ = dec.ReadUint64() // refs count = 0

		_, _ = dec.ReadUint64() // registrationTime
		_, _ = dec.ReadUint64() // narSize
		_, _ = dec.ReadUint64() // ultimate

		_, _ = dec.ReadUint64() // sigs count = 0

		_, _ = dec.ReadString() // ca

		_, _ = dec.ReadUint64() // repair
		_, _ = dec.ReadUint64() // dontCheckSigs

		// read framed NAR data (no padding in framed protocol)
		fr := daemon.NewFramedReader(conn)
		received, err := io.ReadAll(fr)
		require.NoError(t, err)
		require.Equal(t, narData, received)

		// LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
	require.NoError(t, err)

	defer client.Close()

	err = client.AddToStoreNar(t.Context(), info, bytes.NewReader(narData), false, true)
	require.NoError(t, err)
}

func TestClientAddBuildLog(t *testing.T) {
	mock := newMockDaemon(t)

	logContent := "building '/nix/store/00000000000000000000000000000000-test.drv'...\nok\n"

	mock.onAccept(func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		require.Equal(t, uint64(daemon.OpAddBuildLog), op)

		drvPath, _ := dec.ReadString() // drvPath (BaseStorePath)
		require.Equal(t, "00000000000000000000000000000000-test.drv", drvPath)

		// read framed log data (no padding in framed protocol)
		fr := daemon.NewFramedReader(conn)
		received, err := io.ReadAll(fr)
		require.NoError(t, err)
		require.Equal(t, logContent, string(received))

		// LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// uint64(1) acknowledgment
		_ = enc.WriteUint64(1)

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
	require.NoError(t, err)

	defer client.Close()

	err = client.AddBuildLog(t.Context(), "/nix/store/00000000000000000000000000000000-test.drv", strings.NewReader(logContent))
	require.NoError(t, err)
}

func TestClientAddBuildLogInvalidPath(t *testing.T) {
	mock := newMockDaemon(t)

	client, err := daemon.Connect(t.Context(), mock.path)
	require.NoError(t, err)

	defer client.Close()

	err = client.AddBuildLog(t.Context(), "/tmp/not-a-store-path", strings.NewReader("log"))
	require.Error(t, err)
}

func TestClientAddMultipleToStore(t *testing.T) {
	mock := newMockDaemon(t)

	narData1 := []byte("nar-content-one")
	narData2 := []byte("nar-content-two")

	items := []daemon.AddToStoreItem{
		{
			Info: daemon.PathInfo{
				StorePath:  "/nix/store/aaa-one",
				Deriver:    "/nix/store/aaa-one.drv",
				NarHash:    "sha256:aaaa",
				References: []string{},
				NarSize:    uint64(len(narData1)),
				Sigs:       []string{},
			},
			Source: bytes.NewReader(narData1),
		},
		{
			Info: daemon.PathInfo{
				StorePath:  "/nix/store/bbb-two",
				Deriver:    "/nix/store/bbb-two.drv",
				NarHash:    "sha256:bbbb",
				References: []string{"/nix/store/aaa-one"},
				NarSize:    uint64(len(narData2)),
				Sigs:       []string{},
			},
			Source: bytes.NewReader(narData2),
		},
	}

	mock.onAccept(func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		require.Equal(t, uint64(daemon.OpAddMultipleToStore), op)

		repair, _ := dec.ReadUint64()
		require.Equal(t, uint64(1), repair)

		dontCheckSigs, _ := dec.ReadUint64()
		require.Equal(t, uint64(0), dontCheckSigs)

		// read all framed data into a buffer.
		fr := daemon.NewFramedReader(conn)
		framedData, err := io.ReadAll(fr)
		require.NoError(t, err)

		// parse the deframed data.
		r := bytes.NewReader(framedData)
		frameDec := wire.NewDecoder(r, daemon.MaxStringSize)

		// count.
		count, err := frameDec.ReadUint64()
		require.NoError(t, err)
		require.Equal(t, uint64(2), count)

		// Item 1: PathInfo fields.
		s, _ := frameDec.ReadString() // storePath
		require.Equal(t, "/nix/store/aaa-one", s)

		_, _ = frameDec.ReadString() // deriver
		_, _ = frameDec.ReadString() // narHash
		_, _ = frameDec.ReadUint64() // refs count (0)
		_, _ = frameDec.ReadUint64() // registrationTime
		_, _ = frameDec.ReadUint64() // narSize
		_, _ = frameDec.ReadUint64() // ultimate
		_, _ = frameDec.ReadUint64() // sigs count (0)
		_, _ = frameDec.ReadString() // ca

		// Item 1: NAR data.
		nar1 := make([]byte, len(narData1))
		_, _ = io.ReadFull(r, nar1)
		require.Equal(t, narData1, nar1)

		// Item 2: PathInfo fields.
		s, _ = frameDec.ReadString() // storePath
		require.Equal(t, "/nix/store/bbb-two", s)

		_, _ = frameDec.ReadString()          // deriver
		_, _ = frameDec.ReadString()          // narHash
		refsCount, _ := frameDec.ReadUint64() // refs count (1)
		require.Equal(t, uint64(1), refsCount)

		_, _ = frameDec.ReadString() // ref
		_, _ = frameDec.ReadUint64() // registrationTime
		_, _ = frameDec.ReadUint64() // narSize
		_, _ = frameDec.ReadUint64() // ultimate
		_, _ = frameDec.ReadUint64() // sigs count (0)
		_, _ = frameDec.ReadString() // ca

		// Item 2: NAR data.
		nar2 := make([]byte, len(narData2))
		_, _ = io.ReadFull(r, nar2)
		require.Equal(t, narData2, nar2)

		// LogLast.
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
	require.NoError(t, err)

	defer client.Close()

	err = client.AddMultipleToStore(t.Context(), items, true, false)
	require.NoError(t, err)
}

func TestClientAddMultipleToStoreEmpty(t *testing.T) {
	mock := newMockDaemon(t)

	mock.onAccept(func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		// read op code.
		op, _ := dec.ReadUint64()
		require.Equal(t, uint64(daemon.OpAddMultipleToStore), op)

		// read repair.
		_, _ = dec.ReadUint64()

		// read dontCheckSigs.
		_, _ = dec.ReadUint64()

		// read all framed data into a buffer.
		fr := daemon.NewFramedReader(conn)
		framedData, err := io.ReadAll(fr)
		require.NoError(t, err)

		// parse the deframed data.
		r := bytes.NewReader(framedData)
		frameDec := wire.NewDecoder(r, daemon.MaxStringSize)

		// count.
		count, err := frameDec.ReadUint64()
		require.NoError(t, err)
		require.Equal(t, uint64(0), count)

		// send LogLast.
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
	require.NoError(t, err)

	defer client.Close()

	err = client.AddMultipleToStore(t.Context(), nil, false, false)
	require.NoError(t, err)
}

func TestClientSetOptions(t *testing.T) {
	mock := newMockDaemon(t)

	mock.onAccept(respondSetOptions())

	client, err := daemon.Connect(t.Context(), mock.path)
	require.NoError(t, err)

	defer client.Close()

	settings := &daemon.ClientSettings{
		KeepFailed:     true,
		KeepGoing:      false,
		TryFallback:    true,
		Verbosity:      daemon.VerbInfo,
		MaxBuildJobs:   4,
		MaxSilentTime:  300,
		BuildVerbosity: daemon.VerbNotice,
		BuildCores:     8,
		UseSubstitutes: true,
		Overrides: map[string]string{
			"sandbox": "true",
		},
	}

	err = client.SetOptions(t.Context(), settings)
	require.NoError(t, err)
}

func TestClientCollectGarbage(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemon(t)

	expected := &daemon.GCResult{
		Paths: []string{
			"/nix/store/old-package-1",
			"/nix/store/old-package-2",
		},
		BytesFreed: 5242880,
	}

	mock.onAccept(respondCollectGarbage(expected))

	client, err := daemon.Connect(t.Context(), mock.path)

	rq.NoError(err)

	defer client.Close()

	options := &daemon.GCOptions{
		Action:         daemon.GCDeleteDead,
		PathsToDelete:  []string{},
		IgnoreLiveness: false,
		MaxFreed:       0,
	}

	result, err := client.CollectGarbage(t.Context(), options)
	rq.NoError(err)
	rq.Equal(expected.Paths, result.Paths)
	rq.Equal(expected.BytesFreed, result.BytesFreed)
}

func TestClientVerifyStore(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemon(t)

	mock.onAccept(respondVerifyStore(true))

	client, err := daemon.Connect(t.Context(), mock.path)

	rq.NoError(err)

	defer client.Close()

	errorsFound, err := client.VerifyStore(t.Context(), true, false)
	rq.NoError(err)
	rq.True(errorsFound)
}

func TestClientOptimiseStore(t *testing.T) {
	mock := newMockDaemon(t)

	mock.onAccept(respondOptimiseStore())

	client, err := daemon.Connect(t.Context(), mock.path)
	require.NoError(t, err)

	defer client.Close()

	err = client.OptimiseStore(t.Context())
	require.NoError(t, err)
}

// Version-specific store tests

func TestAddBuildLogUnsupportedVersion(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))

	client, err := daemon.Connect(t.Context(), mock.path)

	rq.NoError(err)

	defer client.Close()

	err = client.AddBuildLog(t.Context(), "/nix/store/abc-test.drv", strings.NewReader("log"))
	rq.Error(err)
	rq.ErrorIs(err, daemon.ErrUnsupportedOperation)
}

func TestAddMultipleToStoreUnsupportedVersion(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))

	client, err := daemon.Connect(t.Context(), mock.path)

	rq.NoError(err)

	defer client.Close()

	err = client.AddMultipleToStore(t.Context(), nil, false, false)
	rq.Error(err)
	rq.ErrorIs(err, daemon.ErrUnsupportedOperation)
}

func TestAddPermRootUnsupportedVersion(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))

	client, err := daemon.Connect(t.Context(), mock.path)

	rq.NoError(err)

	defer client.Close()

	_, err = client.AddPermRoot(t.Context(), "/nix/store/abc-test", "/home/user/result")
	rq.Error(err)
	rq.ErrorIs(err, daemon.ErrUnsupportedOperation)
}

func TestRegisterDrvOutputUnsupportedVersion(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))

	client, err := daemon.Connect(t.Context(), mock.path)

	rq.NoError(err)

	defer client.Close()

	err = client.RegisterDrvOutput(t.Context(), &daemon.Realisation{
		ID:      "sha256:abc!out",
		OutPath: "/nix/store/abc-out",
	})
	rq.Error(err)
	rq.ErrorIs(err, daemon.ErrUnsupportedOperation)
}

// TestClientSetOptionsProto123 connects at proto 1.23 (MinProtocolVersion,
// which is >= ProtoVersionOverrides = 1.12) and calls SetOptions with
// settings that include an overrides map. This confirms that at
// MinProtocolVersion, overrides ARE always sent on the wire.
func TestClientSetOptionsProto123(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 23))

	mock.onAccept(respondSetOptions())

	client, err := daemon.Connect(t.Context(), mock.path)

	rq.NoError(err)

	defer client.Close()

	rq.Equal(daemon.ProtoVersion(1, 23), client.Info().Version)

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

	err = client.SetOptions(t.Context(), settings)
	rq.NoError(err)
}

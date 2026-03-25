package daemon_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/assert"
)

func TestClientAddToStore(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

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

	go func() {
		mock.handshake()
		mock.respondAddToStore(expected)
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	info, err := client.AddToStore(
		context.Background(),
		"hello-2.12.1",
		"fixed:r:sha256",
		[]string{},
		false,
		bytes.NewReader(dumpData),
	)
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

func TestAddToStoreUnsupportedVersion(t *testing.T) {
	mock, clientConn := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 23))
	defer mock.conn.Close()

	go func() {
		mock.handshake()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	_, err = client.AddToStore(
		context.Background(),
		"hello",
		"fixed:r:sha256",
		nil,
		false,
		bytes.NewReader([]byte("data")),
	)
	assert.Error(t, err)
	assert.ErrorIs(t, err, daemon.ErrUnsupportedOperation)
}

func TestAddToStoreNilSource(t *testing.T) {
	client := &daemon.Client{}

	_, err := client.AddToStore(context.Background(), "hello", "fixed:r:sha256", nil, false, nil)
	assert.ErrorIs(t, err, daemon.ErrNilReader)
}

func TestCollectGarbageNilOptions(t *testing.T) {
	client := &daemon.Client{}
	_, err := client.CollectGarbage(context.Background(), nil)
	assert.ErrorIs(t, err, daemon.ErrNilOptions)
}

func TestAddToStoreNarNilArgs(t *testing.T) {
	client := &daemon.Client{}

	err := client.AddToStoreNar(context.Background(), nil, nil, false, false)
	assert.ErrorIs(t, err, daemon.ErrNilPathInfo)

	err = client.AddToStoreNar(context.Background(), &daemon.PathInfo{}, nil, false, false)
	assert.ErrorIs(t, err, daemon.ErrNilReader)
}

func TestAddBuildLogNilReader(t *testing.T) {
	client := &daemon.Client{}

	err := client.AddBuildLog(context.Background(), "/nix/store/abc.drv", nil)
	assert.ErrorIs(t, err, daemon.ErrNilReader)
}

func TestClientAddTempRoot(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()

		var buf [8]byte

		_, _ = io.ReadFull(mock.conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpAddTempRoot), op)

		_, _ = wire.ReadString(mock.conn, 64*1024) // path

		// LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = mock.conn.Write(buf[:])

		// uint64(1) acknowledgment
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = mock.conn.Write(buf[:])
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	err = client.AddTempRoot(context.Background(), "/nix/store/abc-test")
	assert.NoError(t, err)
}

func TestClientAddIndirectRoot(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()

		var buf [8]byte

		_, _ = io.ReadFull(mock.conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpAddIndirectRoot), op)

		_, _ = wire.ReadString(mock.conn, 64*1024) // path

		// LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = mock.conn.Write(buf[:])

		// uint64(1) acknowledgment
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = mock.conn.Write(buf[:])
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	err = client.AddIndirectRoot(context.Background(), "/home/user/result")
	assert.NoError(t, err)
}

func TestClientAddPermRoot(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()

		var buf [8]byte

		_, _ = io.ReadFull(mock.conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpAddPermRoot), op)

		_, _ = wire.ReadString(mock.conn, 64*1024) // storePath
		_, _ = wire.ReadString(mock.conn, 64*1024) // gcRoot

		// LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = mock.conn.Write(buf[:])

		// Response: result path string
		writeWireStringTo(mock.conn, "/nix/var/nix/gcroots/auto/abc")
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	resultPath, err := client.AddPermRoot(context.Background(), "/nix/store/abc-test", "/home/user/result")
	assert.NoError(t, err)
	assert.Equal(t, "/nix/var/nix/gcroots/auto/abc", resultPath)
}

func TestClientAddSignatures(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()

		var buf [8]byte

		_, _ = io.ReadFull(mock.conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpAddSignatures), op)

		_, _ = wire.ReadString(mock.conn, 64*1024) // path

		// Read sigs: count + strings
		_, _ = io.ReadFull(mock.conn, buf[:]) // count
		count := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(2), count)

		_, _ = wire.ReadString(mock.conn, 64*1024) // sig 1
		_, _ = wire.ReadString(mock.conn, 64*1024) // sig 2

		// LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = mock.conn.Write(buf[:])

		// uint64(1) acknowledgment
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = mock.conn.Write(buf[:])
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	err = client.AddSignatures(context.Background(), "/nix/store/abc-test", []string{"sig1", "sig2"})
	assert.NoError(t, err)
}

func TestClientRegisterDrvOutput(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()

		var buf [8]byte

		_, _ = io.ReadFull(mock.conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpRegisterDrvOutput), op)

		_, _ = wire.ReadString(mock.conn, 64*1024) // realisation

		// LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = mock.conn.Write(buf[:])
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	err = client.RegisterDrvOutput(context.Background(), &daemon.Realisation{
		ID:      "sha256:abc!out",
		OutPath: "/nix/store/abc-out",
	})
	assert.NoError(t, err)
}

func TestClientAddToStoreNar(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	narData := []byte("fake-nar-content-for-testing")

	info := &daemon.PathInfo{
		StorePath:  "/nix/store/abc-test",
		Deriver:    "/nix/store/xyz-test.drv",
		NarHash:    "sha256:fakehash",
		References: []string{},
		NarSize:    uint64(len(narData)),
		Sigs:       []string{},
	}

	go func() {
		var buf [8]byte

		mock.handshake()

		_, _ = io.ReadFull(mock.conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpAddToStoreNar), op)

		// Read PathInfo: storePath, deriver, narHash, refs, regTime, narSize, ultimate, sigs, ca
		_, _ = wire.ReadString(mock.conn, 64*1024) // storePath
		_, _ = wire.ReadString(mock.conn, 64*1024) // deriver
		_, _ = wire.ReadString(mock.conn, 64*1024) // narHash

		_, _ = io.ReadFull(mock.conn, buf[:]) // refs count = 0

		_, _ = io.ReadFull(mock.conn, buf[:]) // registrationTime
		_, _ = io.ReadFull(mock.conn, buf[:]) // narSize
		_, _ = io.ReadFull(mock.conn, buf[:]) // ultimate

		_, _ = io.ReadFull(mock.conn, buf[:]) // sigs count = 0

		_, _ = wire.ReadString(mock.conn, 64*1024) // ca

		_, _ = io.ReadFull(mock.conn, buf[:]) // repair
		_, _ = io.ReadFull(mock.conn, buf[:]) // dontCheckSigs

		// Read framed NAR data (no padding in framed protocol)
		fr := daemon.NewFramedReader(mock.conn)
		received, err := io.ReadAll(fr)
		assert.NoError(t, err)
		assert.Equal(t, narData, received)

		// LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = mock.conn.Write(buf[:])
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	err = client.AddToStoreNar(context.Background(), info, bytes.NewReader(narData), false, true)
	assert.NoError(t, err)
}

func TestClientAddBuildLog(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	logContent := "building '/nix/store/00000000000000000000000000000000-test.drv'...\nok\n"

	go func() {
		var buf [8]byte

		mock.handshake()

		_, _ = io.ReadFull(mock.conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpAddBuildLog), op)

		drvPath, _ := wire.ReadString(mock.conn, 64*1024) // drvPath (BaseStorePath)
		assert.Equal(t, "00000000000000000000000000000000-test.drv", drvPath)

		// Read framed log data (no padding in framed protocol)
		fr := daemon.NewFramedReader(mock.conn)
		received, err := io.ReadAll(fr)
		assert.NoError(t, err)
		assert.Equal(t, logContent, string(received))

		// LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = mock.conn.Write(buf[:])

		// uint64(1) acknowledgment
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = mock.conn.Write(buf[:])
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	err = client.AddBuildLog(context.Background(), "/nix/store/00000000000000000000000000000000-test.drv", strings.NewReader(logContent))
	assert.NoError(t, err)
}

func TestClientAddBuildLogInvalidPath(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	err = client.AddBuildLog(context.Background(), "/tmp/not-a-store-path", strings.NewReader("log"))
	assert.Error(t, err)
}

func TestClientAddMultipleToStore(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

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

	go func() {
		var buf [8]byte

		mock.handshake()

		_, _ = io.ReadFull(mock.conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpAddMultipleToStore), op)

		_, _ = io.ReadFull(mock.conn, buf[:]) // repair
		assert.Equal(t, uint64(1), binary.LittleEndian.Uint64(buf[:]))

		_, _ = io.ReadFull(mock.conn, buf[:]) // dontCheckSigs
		assert.Equal(t, uint64(0), binary.LittleEndian.Uint64(buf[:]))

		// Read all framed data into a buffer.
		fr := daemon.NewFramedReader(mock.conn)
		framedData, err := io.ReadAll(fr)
		assert.NoError(t, err)

		// Parse the deframed data.
		r := bytes.NewReader(framedData)

		// Count.
		count, err := wire.ReadUint64(r)
		assert.NoError(t, err)
		assert.Equal(t, uint64(2), count)

		// Item 1: PathInfo fields.
		s, _ := wire.ReadString(r, 64*1024) // storePath
		assert.Equal(t, "/nix/store/aaa-one", s)

		_, _ = wire.ReadString(r, 64*1024) // deriver
		_, _ = wire.ReadString(r, 64*1024) // narHash
		_, _ = wire.ReadUint64(r)          // refs count (0)
		_, _ = wire.ReadUint64(r)          // registrationTime
		_, _ = wire.ReadUint64(r)          // narSize
		_, _ = wire.ReadUint64(r)          // ultimate
		_, _ = wire.ReadUint64(r)          // sigs count (0)
		_, _ = wire.ReadString(r, 64*1024) // ca

		// Item 1: NAR data.
		nar1 := make([]byte, len(narData1))
		_, _ = io.ReadFull(r, nar1)
		assert.Equal(t, narData1, nar1)

		// Item 2: PathInfo fields.
		s, _ = wire.ReadString(r, 64*1024) // storePath
		assert.Equal(t, "/nix/store/bbb-two", s)

		_, _ = wire.ReadString(r, 64*1024) // deriver
		_, _ = wire.ReadString(r, 64*1024) // narHash
		refsCount, _ := wire.ReadUint64(r) // refs count (1)
		assert.Equal(t, uint64(1), refsCount)

		_, _ = wire.ReadString(r, 64*1024) // ref
		_, _ = wire.ReadUint64(r)          // registrationTime
		_, _ = wire.ReadUint64(r)          // narSize
		_, _ = wire.ReadUint64(r)          // ultimate
		_, _ = wire.ReadUint64(r)          // sigs count (0)
		_, _ = wire.ReadString(r, 64*1024) // ca

		// Item 2: NAR data.
		nar2 := make([]byte, len(narData2))
		_, _ = io.ReadFull(r, nar2)
		assert.Equal(t, narData2, nar2)

		// LogLast.
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = mock.conn.Write(buf[:])
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	err = client.AddMultipleToStore(context.Background(), items, true, false)
	assert.NoError(t, err)
}

func TestClientAddMultipleToStoreEmpty(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		var buf [8]byte

		mock.handshake()

		// Read op code.
		_, _ = io.ReadFull(mock.conn, buf[:])
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpAddMultipleToStore), op)

		// Read repair.
		_, _ = io.ReadFull(mock.conn, buf[:])

		// Read dontCheckSigs.
		_, _ = io.ReadFull(mock.conn, buf[:])

		// Read all framed data into a buffer.
		fr := daemon.NewFramedReader(mock.conn)
		framedData, err := io.ReadAll(fr)
		assert.NoError(t, err)

		// Parse the deframed data.
		r := bytes.NewReader(framedData)

		// Count.
		count, err := wire.ReadUint64(r)
		assert.NoError(t, err)
		assert.Equal(t, uint64(0), count)

		// Send LogLast.
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = mock.conn.Write(buf[:])
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	err = client.AddMultipleToStore(context.Background(), nil, false, false)
	assert.NoError(t, err)
}

func TestClientSetOptions(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()
		mock.respondSetOptions()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

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

	err = client.SetOptions(context.Background(), settings)
	assert.NoError(t, err)
}

func TestClientCollectGarbage(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	expected := &daemon.GCResult{
		Paths: []string{
			"/nix/store/old-package-1",
			"/nix/store/old-package-2",
		},
		BytesFreed: 5242880,
	}

	go func() {
		mock.handshake()
		mock.respondCollectGarbage(expected)
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	options := &daemon.GCOptions{
		Action:         daemon.GCDeleteDead,
		PathsToDelete:  []string{},
		IgnoreLiveness: false,
		MaxFreed:       0,
	}

	result, err := client.CollectGarbage(context.Background(), options)
	assert.NoError(t, err)
	assert.Equal(t, expected.Paths, result.Paths)
	assert.Equal(t, expected.BytesFreed, result.BytesFreed)
}

func TestClientVerifyStore(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()
		mock.respondVerifyStore(true)
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	errorsFound, err := client.VerifyStore(context.Background(), true, false)
	assert.NoError(t, err)
	assert.True(t, errorsFound)
}

func TestClientOptimiseStore(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()
		mock.respondOptimiseStore()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	err = client.OptimiseStore(context.Background())
	assert.NoError(t, err)
}

// Version-specific store tests

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

func TestRegisterDrvOutputUnsupportedVersion(t *testing.T) {
	mock, clientConn := newMockDaemonWithVersion(t, daemon.ProtoVersion(1, 27))
	defer mock.conn.Close()

	go func() {
		mock.handshake()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)

	defer client.Close()

	err = client.RegisterDrvOutput(context.Background(), &daemon.Realisation{
		ID:      "sha256:abc!out",
		OutPath: "/nix/store/abc-out",
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, daemon.ErrUnsupportedOperation)
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

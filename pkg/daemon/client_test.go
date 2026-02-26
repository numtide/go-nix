package daemon_test

import (
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/assert"
)

// mockDaemon handles the server side of the protocol for testing.
type mockDaemon struct {
	conn net.Conn
	t    *testing.T
}

func newMockDaemon(t *testing.T) (*mockDaemon, net.Conn) {
	server, client := net.Pipe()

	return &mockDaemon{conn: server, t: t}, client
}

func (m *mockDaemon) handshake() {
	var buf [8]byte

	io.ReadFull(m.conn, buf[:])

	binary.LittleEndian.PutUint64(buf[:], daemon.ServerMagic)
	m.conn.Write(buf[:])

	binary.LittleEndian.PutUint64(buf[:], daemon.ProtocolVersion)
	m.conn.Write(buf[:])

	io.ReadFull(m.conn, buf[:]) // negotiated version
	io.ReadFull(m.conn, buf[:]) // cpu affinity
	io.ReadFull(m.conn, buf[:]) // reserve space

	writeWireStringTo(m.conn, "nix (Nix) 2.24.0")

	binary.LittleEndian.PutUint64(buf[:], 1) // TrustTrusted
	m.conn.Write(buf[:])
}

func (m *mockDaemon) respondIsValidPath(valid bool) {
	var buf [8]byte

	io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpIsValidPath), op)

	wire.ReadString(m.conn, 64*1024) // read path string

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	m.conn.Write(buf[:])

	// Send bool result
	if valid {
		binary.LittleEndian.PutUint64(buf[:], 1)
	} else {
		binary.LittleEndian.PutUint64(buf[:], 0)
	}

	m.conn.Write(buf[:])
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

func TestClientIsValidPath(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()
		mock.respondIsValidPath(true)
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	result := <-client.IsValidPath("/nix/store/abc-test")
	assert.NoError(t, result.Err)
	assert.True(t, result.Value)
}

func TestClientIsValidPathFalse(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()
		mock.respondIsValidPath(false)
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	result := <-client.IsValidPath("/nix/store/nonexistent")
	assert.NoError(t, result.Err)
	assert.False(t, result.Value)
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

func (m *mockDaemon) respondQueryPathInfo(info *daemon.PathInfo) {
	var buf [8]byte

	io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpQueryPathInfo), op)

	wire.ReadString(m.conn, 64*1024) // read path string

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	m.conn.Write(buf[:])

	// found = true
	binary.LittleEndian.PutUint64(buf[:], 1)
	m.conn.Write(buf[:])

	// PathInfo fields (UnkeyedValidPathInfo format)
	writeWireStringTo(m.conn, info.Deriver)
	writeWireStringTo(m.conn, info.NarHash)

	// References
	binary.LittleEndian.PutUint64(buf[:], uint64(len(info.References)))
	m.conn.Write(buf[:])

	for _, ref := range info.References {
		writeWireStringTo(m.conn, ref)
	}

	binary.LittleEndian.PutUint64(buf[:], info.RegistrationTime)
	m.conn.Write(buf[:])

	binary.LittleEndian.PutUint64(buf[:], info.NarSize)
	m.conn.Write(buf[:])

	if info.Ultimate {
		binary.LittleEndian.PutUint64(buf[:], 1)
	} else {
		binary.LittleEndian.PutUint64(buf[:], 0)
	}

	m.conn.Write(buf[:])

	// Sigs
	binary.LittleEndian.PutUint64(buf[:], uint64(len(info.Sigs)))
	m.conn.Write(buf[:])

	for _, sig := range info.Sigs {
		writeWireStringTo(m.conn, sig)
	}

	writeWireStringTo(m.conn, info.CA)
}

func (m *mockDaemon) respondQueryPathInfoNotFound() {
	var buf [8]byte

	io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpQueryPathInfo), op)

	wire.ReadString(m.conn, 64*1024) // read path string

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	m.conn.Write(buf[:])

	// found = false
	binary.LittleEndian.PutUint64(buf[:], 0)
	m.conn.Write(buf[:])
}

func TestClientQueryPathInfo(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	expected := &daemon.PathInfo{
		StorePath:        "/nix/store/abc-test",
		Deriver:          "/nix/store/xyz-test.drv",
		NarHash:          "sha256:1b8m03r63zqhnjf7l5wnldhh7c134p5572hrber4jqabd5b2no80",
		References:       []string{"/nix/store/abc-test", "/nix/store/def-dep"},
		RegistrationTime: 1700000000,
		NarSize:          123456,
		Ultimate:         true,
		Sigs:             []string{"cache.nixos.org-1:TsTTb3WGTZKphvYdBHXwo13XoOdFhL2sw/8d16Xzm5NeXp+SuJgMHV1+U+5JxVuf2HuLci2x3Sa+l3KhADoCDQ=="},
		CA:               "",
	}

	go func() {
		mock.handshake()
		mock.respondQueryPathInfo(expected)
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	result := <-client.QueryPathInfo("/nix/store/abc-test")
	assert.NoError(t, result.Err)
	assert.NotNil(t, result.Value)
	assert.Equal(t, expected.StorePath, result.Value.StorePath)
	assert.Equal(t, expected.Deriver, result.Value.Deriver)
	assert.Equal(t, expected.NarHash, result.Value.NarHash)
	assert.Equal(t, expected.References, result.Value.References)
	assert.Equal(t, expected.RegistrationTime, result.Value.RegistrationTime)
	assert.Equal(t, expected.NarSize, result.Value.NarSize)
	assert.Equal(t, expected.Ultimate, result.Value.Ultimate)
	assert.Equal(t, expected.Sigs, result.Value.Sigs)
	assert.Equal(t, expected.CA, result.Value.CA)
}

func TestClientQueryPathInfoNotFound(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()
		mock.respondQueryPathInfoNotFound()
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	result := <-client.QueryPathInfo("/nix/store/nonexistent")
	assert.NoError(t, result.Err)
	assert.Nil(t, result.Value)
}

func TestClientNarFromPath(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	narData := []byte("fake-nar-content-for-testing")

	go func() {
		mock.handshake()

		var buf [8]byte

		io.ReadFull(mock.conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpNarFromPath), op)

		wire.ReadString(mock.conn, 64*1024) // path

		// LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		mock.conn.Write(buf[:])

		// Send NAR data as wire bytes: length + data + padding
		wire.WriteBytes(mock.conn, narData)
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	result := <-client.NarFromPath("/nix/store/abc-test")
	assert.NoError(t, result.Err)

	data, err := io.ReadAll(result.Value)
	assert.NoError(t, err)
	assert.Equal(t, narData, data)

	err = result.Value.Close()
	assert.NoError(t, err)
}

func TestClientBuildPaths(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()

		var buf [8]byte

		io.ReadFull(mock.conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpBuildPaths), op)

		// Read paths (count + strings)
		io.ReadFull(mock.conn, buf[:])        // count = 1
		wire.ReadString(mock.conn, 64*1024)   // path

		// Read build mode
		io.ReadFull(mock.conn, buf[:]) // mode

		// LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		mock.conn.Write(buf[:])

		// Response: uint64(1)
		binary.LittleEndian.PutUint64(buf[:], 1)
		mock.conn.Write(buf[:])
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	result := <-client.BuildPaths([]string{"/nix/store/abc-test.drv"}, daemon.BuildModeNormal)
	assert.NoError(t, result.Err)
}

func TestClientEnsurePath(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()

		var buf [8]byte

		io.ReadFull(mock.conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpEnsurePath), op)

		wire.ReadString(mock.conn, 64*1024) // path

		// LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		mock.conn.Write(buf[:])

		// Response: uint64(1)
		binary.LittleEndian.PutUint64(buf[:], 1)
		mock.conn.Write(buf[:])
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	result := <-client.EnsurePath("/nix/store/abc-test")
	assert.NoError(t, result.Err)
}

func TestClientBuildPathsWithResults(t *testing.T) {
	mock, clientConn := newMockDaemon(t)
	defer mock.conn.Close()

	go func() {
		mock.handshake()

		var buf [8]byte

		io.ReadFull(mock.conn, buf[:]) // op
		op := binary.LittleEndian.Uint64(buf[:])
		assert.Equal(t, uint64(daemon.OpBuildPathsWithResults), op)

		// Read paths (count + strings)
		io.ReadFull(mock.conn, buf[:]) // count = 1
		wire.ReadString(mock.conn, 64*1024) // path

		// Read build mode
		io.ReadFull(mock.conn, buf[:]) // mode

		// LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		mock.conn.Write(buf[:])

		// Response: count of results = 1
		binary.LittleEndian.PutUint64(buf[:], 1)
		mock.conn.Write(buf[:])

		// DerivedPath string (ignored by client)
		writeWireStringTo(mock.conn, "/nix/store/abc-test.drv!out")

		// BuildResult fields
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.BuildStatusBuilt)) // status
		mock.conn.Write(buf[:])
		writeWireStringTo(mock.conn, "")  // errorMsg
		binary.LittleEndian.PutUint64(buf[:], 1) // timesBuilt
		mock.conn.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], 0) // isNonDeterministic
		mock.conn.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], 1700000000) // startTime
		mock.conn.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], 1700000060) // stopTime
		mock.conn.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], 0) // builtOutputs count
		mock.conn.Write(buf[:])
	}()

	client, err := daemon.NewClientFromConn(clientConn)
	assert.NoError(t, err)
	defer client.Close()

	result := <-client.BuildPathsWithResults(
		[]string{"/nix/store/abc-test.drv!out"},
		daemon.BuildModeNormal,
	)
	assert.NoError(t, result.Err)
	assert.Len(t, result.Value, 1)
	assert.Equal(t, daemon.BuildStatusBuilt, result.Value[0].Status)
	assert.Equal(t, "", result.Value[0].ErrorMsg)
	assert.Equal(t, uint64(1), result.Value[0].TimesBuilt)
	assert.False(t, result.Value[0].IsNonDeterministic)
	assert.Equal(t, uint64(1700000000), result.Value[0].StartTime)
	assert.Equal(t, uint64(1700000060), result.Value[0].StopTime)
}

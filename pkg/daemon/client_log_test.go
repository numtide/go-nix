package daemon_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/require"
)

func TestClientLogForwarding(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemon(t)

	mock.onAccept(func(conn net.Conn) error {
		var buf [8]byte
		// Read op
		_, _ = io.ReadFull(conn, buf[:])
		// Read path
		_, _ = wire.ReadString(conn, 64*1024)

		// Send LogNext messages
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogNext))
		_, _ = conn.Write(buf[:])
		writeWireStringTo(conn, "building...")

		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogNext))
		_, _ = conn.Write(buf[:])
		writeWireStringTo(conn, "done")

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send result: true
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = conn.Write(buf[:])

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
	rq.NoError(err)

	defer client.Close()

	// Use Execute directly to get OpResponse with log access.
	var reqBuf bytes.Buffer
	rq.NoError(wire.WriteString(&reqBuf, "/nix/store/abc-test"))

	resp, err := client.Execute(t.Context(), daemon.OpIsValidPath, &reqBuf)
	rq.NoError(err)

	defer resp.Close()

	// Read logs explicitly.
	var msgs []daemon.LogMessage

	err = resp.ReadLogs(func(msg daemon.LogMessage) {
		msgs = append(msgs, msg)
	})
	rq.NoError(err)

	rq.Len(msgs, 2)
	rq.Equal(daemon.LogNext, msgs[0].Type)
	rq.Equal("building...", msgs[0].Text)
	rq.Equal(daemon.LogNext, msgs[1].Type)
	rq.Equal("done", msgs[1].Text)

	// Read response.
	valid, err := wire.ReadBool(resp)
	rq.NoError(err)
	rq.True(valid)
}

func TestClientLogStartStopActivity(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemon(t)

	mock.onAccept(func(conn net.Conn) error {
		var buf [8]byte
		// Read IsValidPath op and path
		_, _ = io.ReadFull(conn, buf[:])
		_, _ = wire.ReadString(conn, 64*1024)

		// Send LogStartActivity
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogStartActivity))
		_, _ = conn.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], 42) // id
		_, _ = conn.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], 3) // level (Info)
		_, _ = conn.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], 105) // type (ActBuild)
		_, _ = conn.Write(buf[:])
		writeWireStringTo(conn, "building /nix/store/abc-test")
		binary.LittleEndian.PutUint64(buf[:], 0) // nrFields
		_, _ = conn.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], 0) // parent
		_, _ = conn.Write(buf[:])

		// Send LogStopActivity
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogStopActivity))
		_, _ = conn.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], 42) // id
		_, _ = conn.Write(buf[:])

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send result
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = conn.Write(buf[:])

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
	rq.NoError(err)

	defer client.Close()

	var reqBuf bytes.Buffer
	rq.NoError(wire.WriteString(&reqBuf, "/nix/store/abc-test"))

	resp, err := client.Execute(t.Context(), daemon.OpIsValidPath, &reqBuf)
	rq.NoError(err)

	defer resp.Close()

	var msgs []daemon.LogMessage

	err = resp.ReadLogs(func(msg daemon.LogMessage) {
		msgs = append(msgs, msg)
	})
	rq.NoError(err)

	rq.Len(msgs, 2)

	rq.Equal(daemon.LogStartActivity, msgs[0].Type)
	rq.Equal(uint64(42), msgs[0].Activity.ID)
	rq.Equal(daemon.ActBuild, msgs[0].Activity.Type)
	rq.Equal("building /nix/store/abc-test", msgs[0].Activity.Text)

	rq.Equal(daemon.LogStopActivity, msgs[1].Type)
	rq.Equal(uint64(42), msgs[1].ActivityID)
}

func TestClientLogChannelFull(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemon(t)

	mock.onAccept(func(conn net.Conn) error {
		var buf [8]byte
		// Read IsValidPath op and path
		_, _ = io.ReadFull(conn, buf[:])
		_, _ = wire.ReadString(conn, 64*1024)

		// Send 5 LogNext messages
		for i := range 5 {
			binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogNext))
			_, _ = conn.Write(buf[:])
			writeWireStringTo(conn, fmt.Sprintf("msg %d", i))
		}

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send result
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = conn.Write(buf[:])

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
	rq.NoError(err)

	defer client.Close()

	// Call IsValidPath which auto-drains logs.
	valid, err := client.IsValidPath(t.Context(), "/nix/store/abc-test")
	rq.NoError(err)
	rq.True(valid)
}

func TestClientLoggerAutoDrain(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemon(t)

	mock.onAccept(func(conn net.Conn) error {
		var buf [8]byte
		// Read IsValidPath op and path
		_, _ = io.ReadFull(conn, buf[:])
		_, _ = wire.ReadString(conn, 64*1024)

		// Send LogNext messages
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogNext))
		_, _ = conn.Write(buf[:])
		writeWireStringTo(conn, "auto-drained message")

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send result: true
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = conn.Write(buf[:])

		return nil
	})

	client, err := daemon.Connect(t.Context(), mock.path)
	rq.NoError(err)

	defer client.Close()

	// Set a logger on the client.
	var msgs []daemon.LogMessage

	client.Logger = func(msg daemon.LogMessage) {
		msgs = append(msgs, msg)
	}

	// Call IsValidPath which auto-drains logs via Read.
	valid, err := client.IsValidPath(t.Context(), "/nix/store/abc-test")
	rq.NoError(err)
	rq.True(valid)

	// The logger should have received the auto-drained message.
	rq.Len(msgs, 1)
	rq.Equal(daemon.LogNext, msgs[0].Type)
	rq.Equal("auto-drained message", msgs[0].Text)
}

func TestClientReadLogsDrained(t *testing.T) {
	rq := require.New(t)

	mock := newMockDaemon(t)

	mock.onAccept(respondIsValidPath(true))

	client, err := daemon.Connect(t.Context(), mock.path)
	rq.NoError(err)

	defer client.Close()

	var reqBuf bytes.Buffer
	rq.NoError(wire.WriteString(&reqBuf, "/nix/store/abc-test"))

	resp, err := client.Execute(t.Context(), daemon.OpIsValidPath, &reqBuf)
	rq.NoError(err)

	defer resp.Close()

	// First ReadLogs succeeds.
	err = resp.ReadLogs(func(daemon.LogMessage) {})
	rq.NoError(err)

	// Second ReadLogs returns ErrLogsDrained.
	err = resp.ReadLogs(func(daemon.LogMessage) {})
	rq.ErrorIs(err, daemon.ErrLogsDrained)
}

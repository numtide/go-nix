package daemon_test

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/assert"
)

func TestClientLogForwarding(t *testing.T) {
	mock := newMockDaemon(t)

	logs := make(chan daemon.LogMessage, 10)

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

	client, err := daemon.Connect(t.Context(), mock.path, daemon.WithLogChannel(logs))
	assert.NoError(t, err)

	defer client.Close()

	valid, err := client.IsValidPath(t.Context(), "/nix/store/abc-test")
	assert.NoError(t, err)
	assert.True(t, valid)

	// Verify log messages
	assert.Len(t, logs, 2)

	msg1 := <-logs
	assert.Equal(t, daemon.LogNext, msg1.Type)
	assert.Equal(t, "building...", msg1.Text)

	msg2 := <-logs
	assert.Equal(t, daemon.LogNext, msg2.Type)
	assert.Equal(t, "done", msg2.Text)
}

func TestClientLogStartStopActivity(t *testing.T) {
	mock := newMockDaemon(t)

	logs := make(chan daemon.LogMessage, 10)

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

	client, err := daemon.Connect(t.Context(), mock.path, daemon.WithLogChannel(logs))
	assert.NoError(t, err)

	defer client.Close()

	valid, err := client.IsValidPath(t.Context(), "/nix/store/abc-test")
	assert.NoError(t, err)
	assert.True(t, valid)

	assert.Len(t, logs, 2)
	msg1 := <-logs
	assert.Equal(t, daemon.LogStartActivity, msg1.Type)
	assert.Equal(t, uint64(42), msg1.Activity.ID)
	assert.Equal(t, daemon.ActBuild, msg1.Activity.Type)
	assert.Equal(t, "building /nix/store/abc-test", msg1.Activity.Text)

	msg2 := <-logs
	assert.Equal(t, daemon.LogStopActivity, msg2.Type)
	assert.Equal(t, uint64(42), msg2.ActivityID)
}

func TestClientLogChannelFull(t *testing.T) {
	mock := newMockDaemon(t)

	logs := make(chan daemon.LogMessage, 1)

	var dropped atomic.Uint64

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

	client, err := daemon.Connect(t.Context(), mock.path, daemon.WithLogChannelWithDropCounter(logs, &dropped))
	assert.NoError(t, err)

	defer client.Close()

	valid, err := client.IsValidPath(t.Context(), "/nix/store/abc-test")
	assert.NoError(t, err)
	assert.True(t, valid)

	// Channel has capacity 1, so only 1 message fits, 4 were dropped
	assert.Equal(t, uint64(4), dropped.Load())
	assert.Len(t, logs, 1)
}

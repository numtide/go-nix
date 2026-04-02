package daemon_test

import (
	"fmt"
	"net"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/require"
)

func TestClientLogs(t *testing.T) {
	t.Run("ExplicitReadLogs", func(t *testing.T) {
		rq := require.New(t)

		mock := newMockDaemon(t)

		mock.onAccept(func(conn net.Conn) error {
			dec := wire.NewDecoder(conn, 64*1024)
			enc := wire.NewEncoder(conn)

			// read op
			_, _ = dec.ReadUint64()
			// read path
			_, _ = dec.ReadString()

			// send LogNext messages
			_ = enc.WriteUint64(uint64(daemon.LogNext))
			_ = enc.WriteString("building...")

			_ = enc.WriteUint64(uint64(daemon.LogNext))
			_ = enc.WriteString("done")

			// send LogLast
			_ = enc.WriteUint64(uint64(daemon.LogLast))

			// send result: true
			_ = enc.WriteUint64(1)

			return nil
		})

		client, err := daemon.Connect(t.Context(), mock.path)
		rq.NoError(err)

		defer client.Close()

		// use Execute directly to get OpResponse with log access.
		resp, err := client.Execute(t.Context(), daemon.OpIsValidPath, daemon.WithBody(func(enc *wire.Encoder) error {
			return enc.WriteString("/nix/store/abc-test")
		}))
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

		// read response.
		respDec := wire.NewDecoder(resp, daemon.MaxStringSize)

		valid, err := respDec.ReadBool()
		rq.NoError(err)
		rq.True(valid)
	})

	t.Run("StartStopActivity", func(t *testing.T) {
		rq := require.New(t)

		mock := newMockDaemon(t)

		mock.onAccept(func(conn net.Conn) error {
			dec := wire.NewDecoder(conn, 64*1024)
			enc := wire.NewEncoder(conn)

			// read IsValidPath op and path
			_, _ = dec.ReadUint64()
			_, _ = dec.ReadString()

			// send LogStartActivity
			_ = enc.WriteUint64(uint64(daemon.LogStartActivity))
			_ = enc.WriteUint64(42)  // id
			_ = enc.WriteUint64(3)   // level (Info)
			_ = enc.WriteUint64(105) // type (ActBuild)
			_ = enc.WriteString("building /nix/store/abc-test")
			_ = enc.WriteUint64(0) // nrFields
			_ = enc.WriteUint64(0) // parent

			// send LogStopActivity
			_ = enc.WriteUint64(uint64(daemon.LogStopActivity))
			_ = enc.WriteUint64(42) // id

			// send LogLast
			_ = enc.WriteUint64(uint64(daemon.LogLast))

			// send result
			_ = enc.WriteUint64(1)

			return nil
		})

		client, err := daemon.Connect(t.Context(), mock.path)
		rq.NoError(err)

		defer client.Close()

		resp, err := client.Execute(t.Context(), daemon.OpIsValidPath, daemon.WithBody(func(enc *wire.Encoder) error {
			return enc.WriteString("/nix/store/abc-test")
		}))
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
	})

	t.Run("AutoDrainWithoutLogger", func(t *testing.T) {
		rq := require.New(t)

		mock := newMockDaemon(t)

		mock.onAccept(func(conn net.Conn) error {
			dec := wire.NewDecoder(conn, 64*1024)
			enc := wire.NewEncoder(conn)

			// read IsValidPath op and path
			_, _ = dec.ReadUint64()
			_, _ = dec.ReadString()

			// send 5 LogNext messages
			for i := range 5 {
				_ = enc.WriteUint64(uint64(daemon.LogNext))
				_ = enc.WriteString(fmt.Sprintf("msg %d", i))
			}

			// send LogLast
			_ = enc.WriteUint64(uint64(daemon.LogLast))

			// send result
			_ = enc.WriteUint64(1)

			return nil
		})

		client, err := daemon.Connect(t.Context(), mock.path)
		rq.NoError(err)

		defer client.Close()

		// Call IsValidPath which auto-drains logs.
		valid, err := client.IsValidPath(t.Context(), "/nix/store/abc-test")
		rq.NoError(err)
		rq.True(valid)
	})

	t.Run("AutoDrainWithCallLogger", func(t *testing.T) {
		rq := require.New(t)

		mock := newMockDaemon(t)

		mock.onAccept(func(conn net.Conn) error {
			dec := wire.NewDecoder(conn, 64*1024)
			enc := wire.NewEncoder(conn)

			_, _ = dec.ReadUint64() // op
			_, _ = dec.ReadString() // path

			_ = enc.WriteUint64(uint64(daemon.LogNext))
			_ = enc.WriteString("per-call message")

			_ = enc.WriteUint64(uint64(daemon.LogLast))
			_ = enc.WriteUint64(1) // result: true

			return nil
		})

		client, err := daemon.Connect(t.Context(), mock.path)
		rq.NoError(err)

		defer client.Close()

		// Pass WithLogger to a concrete method.
		var msgs []daemon.LogMessage

		valid, err := client.IsValidPath(
			t.Context(), "/nix/store/abc-test",
			daemon.WithLogger(func(msg daemon.LogMessage) {
				msgs = append(msgs, msg)
			}),
		)
		rq.NoError(err)
		rq.True(valid)

		// The per-call logger should have received the message.
		rq.Len(msgs, 1)
		rq.Equal("per-call message", msgs[0].Text)
	})

	t.Run("AutoDrainWithDefaultLogger", func(t *testing.T) {
		rq := require.New(t)

		mock := newMockDaemon(t)

		mock.onAccept(func(conn net.Conn) error {
			dec := wire.NewDecoder(conn, 64*1024)
			enc := wire.NewEncoder(conn)

			// read IsValidPath op and path
			_, _ = dec.ReadUint64()
			_, _ = dec.ReadString()

			// send LogNext messages
			_ = enc.WriteUint64(uint64(daemon.LogNext))
			_ = enc.WriteString("auto-drained message")

			// send LogLast
			_ = enc.WriteUint64(uint64(daemon.LogLast))

			// send result: true
			_ = enc.WriteUint64(1)

			return nil
		})

		client, err := daemon.Connect(t.Context(), mock.path)
		rq.NoError(err)

		defer client.Close()

		// set a default logger on the client
		var msgs []daemon.LogMessage

		client.DefaultExecOptions.Logger = func(msg daemon.LogMessage) {
			msgs = append(msgs, msg)
		}

		// call IsValidPath which auto-drains logs via Read
		valid, err := client.IsValidPath(t.Context(), "/nix/store/abc-test")
		rq.NoError(err)
		rq.True(valid)

		// the default logger should have received the auto-drained message
		rq.Len(msgs, 1)
		rq.Equal(daemon.LogNext, msgs[0].Type)
		rq.Equal("auto-drained message", msgs[0].Text)
	})

	t.Run("WithLoggerOverridesDefaultLogger", func(t *testing.T) {
		rq := require.New(t)

		mock := newMockDaemon(t)

		mock.onAccept(func(conn net.Conn) error {
			dec := wire.NewDecoder(conn, 64*1024)
			enc := wire.NewEncoder(conn)

			_, _ = dec.ReadUint64() // op
			_, _ = dec.ReadString() // path

			_ = enc.WriteUint64(uint64(daemon.LogNext))
			_ = enc.WriteString("should go to per-call logger")

			_ = enc.WriteUint64(uint64(daemon.LogLast))
			_ = enc.WriteUint64(1)

			return nil
		})

		client, err := daemon.Connect(t.Context(), mock.path)
		rq.NoError(err)

		defer client.Close()

		// set a default logger that should NOT receive messages
		var defaultMsgs []daemon.LogMessage

		client.DefaultExecOptions.Logger = func(msg daemon.LogMessage) {
			defaultMsgs = append(defaultMsgs, msg)
		}

		// pass a per-call logger via WithLogger
		var callMsgs []daemon.LogMessage

		valid, err := client.IsValidPath(
			t.Context(), "/nix/store/abc-test",
			daemon.WithLogger(func(msg daemon.LogMessage) {
				callMsgs = append(callMsgs, msg)
			}),
		)
		rq.NoError(err)
		rq.True(valid)

		// per-call logger wins; default logger receives nothing
		rq.Len(callMsgs, 1)
		rq.Equal("should go to per-call logger", callMsgs[0].Text)
		rq.Empty(defaultMsgs)
	})

	t.Run("ReadLogsDrained", func(t *testing.T) {
		rq := require.New(t)

		mock := newMockDaemon(t)

		mock.onAccept(respondIsValidPath(true))

		client, err := daemon.Connect(t.Context(), mock.path)
		rq.NoError(err)

		defer client.Close()

		resp, err := client.Execute(t.Context(), daemon.OpIsValidPath, daemon.WithBody(func(enc *wire.Encoder) error {
			return enc.WriteString("/nix/store/abc-test")
		}))
		rq.NoError(err)

		defer resp.Close()

		// First ReadLogs succeeds.
		err = resp.ReadLogs(func(daemon.LogMessage) {})
		rq.NoError(err)

		// Second ReadLogs returns ErrLogsDrained.
		err = resp.ReadLogs(func(daemon.LogMessage) {})
		rq.ErrorIs(err, daemon.ErrLogsDrained)
	})
}

package daemon

import (
	"fmt"
	"io"
	"net"

	"github.com/nix-community/go-nix/pkg/wire"
)

// OpResponse wraps the response phase of a daemon operation. It implements
// io.ReadCloser over the connection's reader and deregisters the context
// cancellation callback when closed.
//
// Before reading response data, the caller may call ReadLogs to receive log
// messages from the daemon. If Read is called before ReadLogs, any pending
// log messages are drained and discarded automatically.
//
// Callers must call Close when done reading, even if they did not read any data.
//
// OpResponse is not safe for concurrent use.
type OpResponse struct {
	r                   io.Reader
	conn                net.Conn
	version             uint64
	closed              bool
	logsDrained         bool
	unsetCancelDeadline func() error // context.AfterFunc stop function
}

// ReadLogs reads log messages from the daemon, calling fn for each message.
// It blocks until all log messages have been consumed (LogLast received).
// Returns ErrLogsDrained if called after logs have already been read.
// Returns a *Error if the daemon reports an error via LogError.
func (resp *OpResponse) ReadLogs(fn func(LogMessage)) error {
	if resp.logsDrained {
		return ErrLogsDrained
	}

	resp.logsDrained = true

	return resp.readLogs(fn)
}

// readLogs reads and dispatches log messages from the daemon's stderr channel.
func (resp *OpResponse) readLogs(fn func(LogMessage)) error {
	for {
		raw, err := wire.ReadUint64(resp.r)
		if err != nil {
			return &ProtocolError{Op: "read stderr message type", Err: err}
		}

		msgType := LogMessageType(raw)

		switch msgType {
		case LogLast:
			return nil

		case LogError:
			return readError(resp.r, resp.version)

		case LogNext:
			text, err := wire.ReadString(resp.r, MaxStringSize)
			if err != nil {
				return &ProtocolError{Op: "read LogNext text", Err: err}
			}

			if fn != nil {
				fn(LogMessage{Type: LogNext, Text: text})
			}

		case LogStartActivity:
			act, err := readActivity(resp.r)
			if err != nil {
				return err
			}

			if fn != nil {
				fn(LogMessage{Type: LogStartActivity, Activity: act})
			}

		case LogStopActivity:
			id, err := wire.ReadUint64(resp.r)
			if err != nil {
				return &ProtocolError{Op: "read LogStopActivity id", Err: err}
			}

			if fn != nil {
				fn(LogMessage{Type: LogStopActivity, ActivityID: id})
			}

		case LogResult:
			result, err := readActivityResult(resp.r)
			if err != nil {
				return err
			}

			if fn != nil {
				fn(LogMessage{Type: LogResult, Result: result})
			}

		case LogRead, LogWrite:
			// data transfer notifications: read the count and discard.
			if _, err := wire.ReadUint64(resp.r); err != nil {
				return &ProtocolError{Op: "read LogRead/LogWrite count", Err: err}
			}

		default:
			return &ProtocolError{
				Op:  "process stderr",
				Err: fmt.Errorf("unknown log message type: 0x%x", raw),
			}
		}
	}
}

// Read reads response data from the daemon connection. If log messages have
// not yet been drained, they are discarded before reading response data.
// Returns ErrClosed if the response has been closed.
func (resp *OpResponse) Read(p []byte) (int, error) {
	if resp.closed {
		return 0, ErrClosed
	}

	if !resp.logsDrained {
		resp.logsDrained = true

		if err := resp.readLogs(nil); err != nil {
			return 0, err
		}
	}

	return resp.r.Read(p)
}

// Close deregisters the context cancellation callback and resets the
// connection deadline. It is idempotent. After Close, Read returns ErrClosed.
func (resp *OpResponse) Close() error {
	if resp.closed {
		return nil
	}

	resp.closed = true

	if err := resp.unsetCancelDeadline(); err != nil {
		return fmt.Errorf("failed to cancel: %w", err)
	}

	return nil
}

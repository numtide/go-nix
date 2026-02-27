package daemon

import (
	"bufio"
	"io"
	"net"
	"sync"
)

// OpWriter supports multi-phase request writing for streaming operations.
// Callers write request data via Write/Flush or create a FramedWriter for
// framed streaming, then call CloseRequest to transition to the response
// phase. If an error occurs before CloseRequest, call Abort to release
// the connection mutex.
type OpWriter struct {
	w      *bufio.Writer
	r      io.Reader
	conn   net.Conn
	mu     *sync.Mutex
	logs   chan<- LogMessage
	op     Operation
	done   bool
	cancel func() bool // context.AfterFunc stop function
}

// Write writes data directly to the connection's buffered writer.
func (ow *OpWriter) Write(p []byte) (int, error) {
	return ow.w.Write(p)
}

// Flush flushes the buffered writer to the underlying connection.
func (ow *OpWriter) Flush() error {
	return ow.w.Flush()
}

// NewFramedWriter creates a FramedWriter that writes framed data to the
// connection. The caller should write data to the FramedWriter and then
// Close it before calling CloseRequest.
func (ow *OpWriter) NewFramedWriter() *FramedWriter {
	return NewFramedWriter(ow.w)
}

// CloseRequest flushes the writer, drains stderr messages, and transitions
// to the response phase. Returns an OpResponse for reading the reply.
// After calling CloseRequest, the OpWriter must not be used.
func (ow *OpWriter) CloseRequest() (*OpResponse, error) {
	if ow.done {
		return nil, &ProtocolError{Op: ow.op.String() + " close request", Err: io.ErrClosedPipe}
	}

	ow.done = true

	if err := ow.w.Flush(); err != nil {
		ow.release()

		return nil, &ProtocolError{Op: ow.op.String() + " flush", Err: err}
	}

	if err := ProcessStderr(ow.r, ow.logs); err != nil {
		ow.release()

		return nil, err
	}

	return &OpResponse{
		r:      ow.r,
		conn:   ow.conn,
		mu:     ow.mu,
		cancel: ow.cancel,
	}, nil
}

// Abort releases the connection mutex without completing the request.
// Use this on error paths when CloseRequest has not been called.
func (ow *OpWriter) Abort() {
	if !ow.done {
		ow.done = true
		ow.release()
	}
}

// release cleans up context cancellation and unlocks the mutex.
func (ow *OpWriter) release() {
	if ow.cancel != nil {
		ow.cancel()
	}

	ow.conn.SetDeadline(noDeadline) //nolint:errcheck // best-effort deadline reset
	ow.mu.Unlock()
}

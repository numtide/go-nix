package daemon

import (
	"io"
	"net"
	"sync"
)

// OpResponse wraps the response phase of a daemon operation. It implements
// io.ReadCloser over the connection's reader and releases the connection
// mutex when closed. Callers must call Close when done reading, even if
// they did not read any data.
type OpResponse struct {
	r      io.Reader
	conn   net.Conn
	mu     *sync.Mutex
	once   sync.Once
	closed bool
	cancel func() bool // context.AfterFunc stop function
}

// Read reads response data from the daemon connection.
// Returns io.ErrClosedPipe if the response has been closed.
func (resp *OpResponse) Read(p []byte) (int, error) {
	if resp.closed {
		return 0, io.ErrClosedPipe
	}

	return resp.r.Read(p)
}

// Close releases the connection mutex. It is idempotent and safe to call
// multiple times. After Close, Read returns io.ErrClosedPipe.
func (resp *OpResponse) Close() error {
	resp.closed = true
	resp.once.Do(func() {
		if resp.cancel != nil {
			resp.cancel()
		}

		resp.conn.SetDeadline(noDeadline) //nolint:errcheck // best-effort deadline reset
		resp.mu.Unlock()
	})

	return nil
}

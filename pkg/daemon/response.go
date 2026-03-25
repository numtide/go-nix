package daemon

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// OpResponse wraps the response phase of a daemon operation. It implements
// io.ReadCloser over the connection's reader and releases the connection
// mutex when closed. Callers must call Close when done reading, even if
// they did not read any data.
//
// Close is safe to call concurrently with Read. An in-flight Read may
// return the underlying connection error rather than ErrClosed; subsequent
// calls to Read will return ErrClosed.
type OpResponse struct {
	r      io.Reader
	conn   net.Conn
	mu     *sync.Mutex
	once   sync.Once
	closed atomic.Bool
	cancel func() bool // context.AfterFunc stop function
}

// Read reads response data from the daemon connection.
// Returns ErrClosed if the response has been closed.
func (resp *OpResponse) Read(p []byte) (int, error) {
	if resp.closed.Load() {
		return 0, ErrClosed
	}

	return resp.r.Read(p)
}

// Close releases the connection mutex. It is idempotent and safe to call
// multiple times. After Close, Read returns ErrClosed.
func (resp *OpResponse) Close() error {
	resp.closed.Store(true)
	resp.once.Do(func() {
		if resp.cancel != nil {
			resp.cancel()
		}

		resp.conn.SetDeadline(noDeadline) //nolint:errcheck,gosec // best-effort deadline reset
		resp.mu.Unlock()
	})

	return nil
}

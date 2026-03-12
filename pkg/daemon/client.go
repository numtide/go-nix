package daemon

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nix-community/go-nix/pkg/wire"
)

// noDeadline is the zero time used to clear connection deadlines.
var noDeadline time.Time //nolint:gochecknoglobals

// Client connects to a Nix daemon and provides methods to interact with it.
type Client struct {
	conn    net.Conn
	r       io.Reader     // bufio.NewReader(conn)
	w       *bufio.Writer // bufio.NewWriter(conn)
	info    *HandshakeInfo
	logs    chan LogMessage
	logSink LogSink
	mu      sync.Mutex // serializes operations

	closed    atomic.Bool
	closeOnce sync.Once
}

// ConnectOption configures the client.
type ConnectOption func(*Client)

// WithLogChannel sets the channel that will receive log messages from the
// daemon. If not set, log messages are silently discarded.
func WithLogChannel(ch chan LogMessage) ConnectOption {
	return func(c *Client) {
		c.logs = ch
		c.logSink = NewLogChannelSink(ch, nil)
	}
}

// WithLogChannelWithDropCounter sets the channel for log messages and
// increments dropped on each log message dropped due to a full channel.
func WithLogChannelWithDropCounter(ch chan LogMessage, dropped *atomic.Uint64) ConnectOption {
	return func(c *Client) {
		c.logs = ch
		c.logSink = NewLogChannelSink(ch, dropped)
	}
}

// WithLogSink sets a custom sink for log messages.
func WithLogSink(sink LogSink) ConnectOption {
	return func(c *Client) {
		c.logSink = sink
	}
}

// Connect dials the Nix daemon Unix socket and performs the handshake.
func Connect(socketPath string, opts ...ConnectOption) (*Client, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, &ProtocolError{Op: "connect", Err: err}
	}

	client, err := newClient(conn, opts...)
	if err != nil {
		conn.Close()

		return nil, err
	}

	return client, nil
}

// NewClientFromConn creates a client from an existing net.Conn (useful for
// testing with net.Pipe).
func NewClientFromConn(conn net.Conn, opts ...ConnectOption) (*Client, error) {
	if conn == nil {
		return nil, ErrNilConn
	}

	return newClient(conn, opts...)
}

// Close closes the connection to the daemon.
func (c *Client) Close() error {
	if c.closed.Load() {
		return nil
	}

	var err error
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.conn.SetDeadline(time.Now()) //nolint:errcheck // unblock any in-flight I/O
		err = c.conn.Close()
	})

	return err
}

// Logs returns a read-only channel of log messages from the daemon. Returns
// nil if no log channel was configured via WithLogChannel.
func (c *Client) Logs() <-chan LogMessage {
	return c.logs
}

// Info returns the handshake information from the daemon.
func (c *Client) Info() *HandshakeInfo {
	return c.info
}

// lockForCtx acquires the mutex and registers a context cancellation callback
// that sets a deadline on the connection to break blocked I/O. Returns a
// cancel function that must be called to deregister the callback and reset the
// deadline. If the client is closed, returns ErrClosed without locking.
func (c *Client) lockForCtx(ctx context.Context) (func() bool, error) {
	c.mu.Lock()

	if c.closed.Load() {
		c.mu.Unlock()
		return nil, ErrClosed
	}

	return context.AfterFunc(ctx, func() {
		c.conn.SetDeadline(time.Now()) //nolint:errcheck // break blocked I/O
	}), nil
}

func (c *Client) checkCtx(ctx context.Context) error {
	if ctx == nil {
		return ErrNilContext
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if c.closed.Load() {
		return ErrClosed
	}

	return nil
}

// requireVersion returns an UnsupportedOperationError if the negotiated
// protocol version is below minVersion for the given operation.
func (c *Client) requireVersion(op Operation, minVersion uint64) error {
	if c.info.Version < minVersion {
		return &UnsupportedOperationError{Op: op, MinVersion: minVersion, CurrentVersion: c.info.Version}
	}
	return nil
}

// release deregisters a context cancellation callback and resets the
// connection deadline. Used on error paths in Do/DoStreaming.
func (c *Client) release(cancel func() bool) {
	cancel()
	c.conn.SetDeadline(noDeadline) //nolint:errcheck // best-effort reset
	c.mu.Unlock()
}

// Do executes a simple (non-streaming) operation. It locks the connection,
// writes the operation code, copies req to the wire (if non-nil), flushes,
// drains stderr, and returns an OpResponse for reading the reply. The caller
// must call OpResponse.Close when done.
func (c *Client) Do(
	ctx context.Context, op Operation, req io.Reader,
) (*OpResponse, error) {
	if err := c.checkCtx(ctx); err != nil {
		return nil, err
	}

	cancel, err := c.lockForCtx(ctx)
	if err != nil {
		return nil, err
	}

	if err := wire.WriteUint64(c.w, uint64(op)); err != nil {
		c.release(cancel)

		return nil, &ProtocolError{Op: op.String() + " write op", Err: err}
	}

	if req != nil {
		if _, err := io.Copy(c.w, req); err != nil {
			c.release(cancel)

			return nil, &ProtocolError{Op: op.String() + " write request", Err: err}
		}
	}

	if err := c.w.Flush(); err != nil {
		c.release(cancel)

		return nil, &ProtocolError{Op: op.String() + " flush", Err: err}
	}

	if err := ProcessStderrWithSink(c.r, c.logSink); err != nil {
		c.release(cancel)

		return nil, err
	}

	return &OpResponse{
		r:      c.r,
		conn:   c.conn,
		mu:     &c.mu,
		cancel: cancel,
	}, nil
}

// DoStreaming starts a streaming operation. It locks the connection, writes
// the operation code, and returns an OpWriter for multi-phase request
// writing. The caller must eventually call OpWriter.CloseRequest or
// OpWriter.Abort.
func (c *Client) DoStreaming(
	ctx context.Context, op Operation,
) (*OpWriter, error) {
	if err := c.checkCtx(ctx); err != nil {
		return nil, err
	}

	cancel, err := c.lockForCtx(ctx)
	if err != nil {
		return nil, err
	}

	if err := wire.WriteUint64(c.w, uint64(op)); err != nil {
		c.release(cancel)

		return nil, &ProtocolError{Op: op.String() + " write op", Err: err}
	}

	return &OpWriter{
		w:       c.w,
		r:       c.r,
		conn:    c.conn,
		mu:      &c.mu,
		logSink: c.logSink,
		op:      op,
		cancel:  cancel,
	}, nil
}

// doOp is the internal operation dispatcher. It serializes operations on
// the connection by holding the mutex for the entire request-response cycle.
//
// Sequence:
//  1. Lock mutex
//  2. Write operation code (uint64)
//  3. Call writeReq(c.w) if non-nil
//  4. Flush the buffered writer
//  5. Call ProcessStderrWithSink to drain log messages until LogLast
//  6. Call readResp(c.r) if non-nil
//  7. Unlock mutex
//  8. Return any error
func (c *Client) doOp(
	ctx context.Context,
	op Operation,
	writeReq func(w io.Writer) error,
	readResp func(r io.Reader) error,
) error {
	if err := c.checkCtx(ctx); err != nil {
		return err
	}

	cancel, err := c.lockForCtx(ctx)
	if err != nil {
		return err
	}
	defer c.release(cancel)

	// Write operation code.
	if err := wire.WriteUint64(c.w, uint64(op)); err != nil {
		return &ProtocolError{Op: op.String() + " write op", Err: err}
	}

	// Write request payload.
	if writeReq != nil {
		if err := writeReq(c.w); err != nil {
			return &ProtocolError{Op: op.String() + " write request", Err: err}
		}
	}

	// Flush buffered writer.
	if err := c.w.Flush(); err != nil {
		return &ProtocolError{Op: op.String() + " flush", Err: err}
	}

	// Drain stderr log messages until LogLast.
	if err := ProcessStderrWithSink(c.r, c.logSink); err != nil {
		return err
	}

	// Read response payload.
	if readResp != nil {
		if err := readResp(c.r); err != nil {
			return &ProtocolError{Op: op.String() + " read response", Err: err}
		}
	}

	return nil
}

// newClient creates a Client from an existing connection, applies options,
// and performs the handshake.
func newClient(conn net.Conn, opts ...ConnectOption) (*Client, error) {
	c := &Client{
		conn: conn,
		r:    bufio.NewReader(conn),
		w:    bufio.NewWriter(conn),
	}

	for _, opt := range opts {
		opt(c)
	}

	info, err := handshakeWithBufIO(c.r, c.w)
	if err != nil {
		return nil, err
	}

	c.info = info

	return c, nil
}

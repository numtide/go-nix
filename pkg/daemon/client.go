package daemon

import (
	"bufio"
	"io"
	"net"
	"sync"

	"github.com/nix-community/go-nix/pkg/wire"
)

// Result wraps a value or error from an async operation.
type Result[T any] struct {
	Value T
	Err   error
}

// Client connects to a Nix daemon and provides methods to interact with it.
type Client struct {
	conn net.Conn
	r    io.Reader     // bufio.NewReader(conn)
	w    *bufio.Writer // bufio.NewWriter(conn)
	info *HandshakeInfo
	logs chan LogMessage
	mu   sync.Mutex // serializes operations
}

// ConnectOption configures the client.
type ConnectOption func(*Client)

// WithLogChannel sets the channel that will receive log messages from the
// daemon. If not set, log messages are silently discarded.
func WithLogChannel(ch chan LogMessage) ConnectOption {
	return func(c *Client) {
		c.logs = ch
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
	return newClient(conn, opts...)
}

// Close closes the connection to the daemon.
func (c *Client) Close() error {
	return c.conn.Close()
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

// doOp is the internal operation dispatcher. It serializes operations on the
// connection by holding the mutex for the entire request-response cycle.
//
// Sequence:
//  1. Lock mutex
//  2. Write operation code (uint64)
//  3. Call writeReq(c.w) if non-nil
//  4. Flush the buffered writer
//  5. Call ProcessStderr to drain log messages until LogLast
//  6. Call readResp(c.r) if non-nil
//  7. Unlock mutex
//  8. Return any error
func (c *Client) doOp(op Operation, writeReq func(w io.Writer) error, readResp func(r io.Reader) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()

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
	if err := ProcessStderr(c.r, c.logs); err != nil {
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

// IsValidPath checks whether the given store path is valid (exists in the
// store). It returns a channel that will receive exactly one Result.
func (c *Client) IsValidPath(path string) <-chan Result[bool] {
	ch := make(chan Result[bool], 1)

	go func() {
		var valid bool

		err := c.doOp(OpIsValidPath,
			func(w io.Writer) error {
				return wire.WriteString(w, path)
			},
			func(r io.Reader) error {
				v, err := wire.ReadBool(r)
				if err != nil {
					return err
				}

				valid = v

				return nil
			},
		)

		ch <- Result[bool]{Value: valid, Err: err}
	}()

	return ch
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

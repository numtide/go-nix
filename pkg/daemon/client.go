package daemon

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/nix-community/go-nix/pkg/wire"
)

// noDeadline is the zero time used to clear connection deadlines.
var noDeadline time.Time //nolint:gochecknoglobals

// Client connects to a Nix daemon and provides methods to interact with it.
//
// Client is not safe for concurrent use. Callers must serialize operations
// externally if the client is shared across goroutines.
type Client struct {
	conn net.Conn

	r io.Reader     // bufio.NewReader(conn)
	w *bufio.Writer // bufio.NewWriter(conn)

	info   *HandshakeInfo
	closed bool
}

// Connect dials the Nix daemon Unix socket and performs the handshake.
func Connect(ctx context.Context, path string) (*Client, error) {
	var d net.Dialer

	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, &ProtocolError{Op: "connect", Err: err}
	}

	client := &Client{
		conn: conn,
		r:    bufio.NewReader(conn),
		w:    bufio.NewWriter(conn),
	}

	info, err := handshakeWithBufIO(client.r, client.w)
	if err != nil {
		return nil, err
	}

	client.info = info

	return client, nil
}

// Close closes the connection to the daemon. It is idempotent.
func (c *Client) Close() error {
	if c.closed {
		return nil
	}

	c.closed = true

	// unblock any in-flight I/O
	_ = c.conn.SetDeadline(time.Now())

	return c.conn.Close()
}

// Info returns the handshake information from the daemon.
func (c *Client) Info() *HandshakeInfo {
	return c.info
}

// setCancelDeadline validates the context and client state, then registers a context
// cancellation callback that sets a deadline on the connection to break
// blocked I/O. Returns a stop function that must be called to deregister
// the callback and reset the deadline.
func (c *Client) setCancelDeadline(ctx context.Context) (func() error, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if c.closed {
		return nil, ErrClosed
	}

	stop := context.AfterFunc(ctx, func() {
		// break blocked I/O if the context is cancelled
		_ = c.conn.SetDeadline(time.Now())
	})

	cancel := func() error {
		// remove the AfterFunc callback
		if stop() {
			// the callback didn't fire, nothing for us to do
			return nil
		}

		// the callback did fire, so we need to reset the deadline on the connection
		if err := c.conn.SetDeadline(noDeadline); err != nil {
			return fmt.Errorf("failed to reset deadline: %w", err)
		}

		return nil
	}

	return cancel, nil
}

// requireVersion returns an UnsupportedOperationError if the negotiated
// protocol version is below minVersion for the given operation.
func (c *Client) requireVersion(op Operation, minVersion uint64) error {
	if c.info.Version < minVersion {
		return &UnsupportedOperationError{Op: op, MinVersion: minVersion, CurrentVersion: c.info.Version}
	}

	return nil
}

// Execute executes a simple (non-streaming) operation. It writes the operation
// code, copies req to the wire (if non-nil), flushes, drains stderr, and
// returns an OpResponse for reading the reply. The caller must call
// OpResponse.Close when done, before starting another operation.
func (c *Client) Execute(
	ctx context.Context, op Operation, args io.Reader,
) (resp *OpResponse, err error) {
	var unsetCancelDeadline func() error

	// set a cancel deadline on the connection in the event the context is cancelled
	// it helps free up any i/o in progress on the connection
	if unsetCancelDeadline, err = c.setCancelDeadline(ctx); err != nil {
		return nil, fmt.Errorf("failed to set cancel deadline: %w", err)
	}

	// ensure the cancel deadline is removed in the event an error is thrown in this method
	defer func() {
		if err == nil {
			// nothing to do
			return
		}

		if unsetErr := unsetCancelDeadline(); unsetErr != nil {
			err = errors.Join(err, unsetErr)
		}
	}()

	// write the op code
	if err = wire.WriteUint64(c.w, uint64(op)); err != nil {
		return nil, &ProtocolError{Op: op.String() + " write op", Err: err}
	}

	if args != nil {
		if _, err = io.Copy(c.w, args); err != nil {
			return nil, &ProtocolError{Op: op.String() + " write request", Err: err}
		}
	}

	if err = c.w.Flush(); err != nil {
		return nil, &ProtocolError{Op: op.String() + " flush", Err: err}
	}

	return &OpResponse{
		r:                   c.r,
		conn:                c.conn,
		version:             c.info.Version,
		unsetCancelDeadline: unsetCancelDeadline,
	}, nil
}

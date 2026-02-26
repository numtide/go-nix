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

// QueryPathInfo retrieves the metadata for the given store path. If the path
// is not found in the store, the result Value is nil with no error.
func (c *Client) QueryPathInfo(path string) <-chan Result[*PathInfo] {
	ch := make(chan Result[*PathInfo], 1)

	go func() {
		var info *PathInfo

		err := c.doOp(OpQueryPathInfo,
			func(w io.Writer) error {
				return wire.WriteString(w, path)
			},
			func(r io.Reader) error {
				found, err := wire.ReadBool(r)
				if err != nil {
					return err
				}

				if !found {
					return nil
				}

				info, err = ReadPathInfo(r, path)

				return err
			},
		)

		ch <- Result[*PathInfo]{Value: info, Err: err}
	}()

	return ch
}

// QueryPathFromHashPart looks up a store path by its hash part. If nothing
// is found, the result Value is an empty string with no error.
func (c *Client) QueryPathFromHashPart(hashPart string) <-chan Result[string] {
	ch := make(chan Result[string], 1)

	go func() {
		var storePath string

		err := c.doOp(OpQueryPathFromHashPart,
			func(w io.Writer) error {
				return wire.WriteString(w, hashPart)
			},
			func(r io.Reader) error {
				s, err := wire.ReadString(r, MaxStringSize)
				if err != nil {
					return err
				}

				storePath = s

				return nil
			},
		)

		ch <- Result[string]{Value: storePath, Err: err}
	}()

	return ch
}

// QueryAllValidPaths returns all valid store paths known to the daemon.
func (c *Client) QueryAllValidPaths() <-chan Result[[]string] {
	ch := make(chan Result[[]string], 1)

	go func() {
		var paths []string

		err := c.doOp(OpQueryAllValidPaths,
			nil,
			func(r io.Reader) error {
				ss, err := ReadStrings(r, MaxStringSize)
				if err != nil {
					return err
				}

				paths = ss

				return nil
			},
		)

		ch <- Result[[]string]{Value: paths, Err: err}
	}()

	return ch
}

// QueryValidPaths returns the subset of the given paths that are valid. If
// substituteOk is true, the daemon may attempt to substitute missing paths.
func (c *Client) QueryValidPaths(paths []string, substituteOk bool) <-chan Result[[]string] {
	ch := make(chan Result[[]string], 1)

	go func() {
		var valid []string

		err := c.doOp(OpQueryValidPaths,
			func(w io.Writer) error {
				if err := WriteStrings(w, paths); err != nil {
					return err
				}

				return wire.WriteBool(w, substituteOk)
			},
			func(r io.Reader) error {
				ss, err := ReadStrings(r, MaxStringSize)
				if err != nil {
					return err
				}

				valid = ss

				return nil
			},
		)

		ch <- Result[[]string]{Value: valid, Err: err}
	}()

	return ch
}

// QuerySubstitutablePaths returns the subset of the given paths that can be
// substituted from a binary cache or other substitute source.
func (c *Client) QuerySubstitutablePaths(paths []string) <-chan Result[[]string] {
	ch := make(chan Result[[]string], 1)

	go func() {
		var substitutable []string

		err := c.doOp(OpQuerySubstitutablePaths,
			func(w io.Writer) error {
				return WriteStrings(w, paths)
			},
			func(r io.Reader) error {
				ss, err := ReadStrings(r, MaxStringSize)
				if err != nil {
					return err
				}

				substitutable = ss

				return nil
			},
		)

		ch <- Result[[]string]{Value: substitutable, Err: err}
	}()

	return ch
}

// QueryValidDerivers returns the derivations known to have produced the given
// store path.
func (c *Client) QueryValidDerivers(path string) <-chan Result[[]string] {
	ch := make(chan Result[[]string], 1)

	go func() {
		var derivers []string

		err := c.doOp(OpQueryValidDerivers,
			func(w io.Writer) error {
				return wire.WriteString(w, path)
			},
			func(r io.Reader) error {
				ss, err := ReadStrings(r, MaxStringSize)
				if err != nil {
					return err
				}

				derivers = ss

				return nil
			},
		)

		ch <- Result[[]string]{Value: derivers, Err: err}
	}()

	return ch
}

// QueryReferrers returns the set of store paths that reference (depend on)
// the given path.
func (c *Client) QueryReferrers(path string) <-chan Result[[]string] {
	ch := make(chan Result[[]string], 1)

	go func() {
		var referrers []string

		err := c.doOp(OpQueryReferrers,
			func(w io.Writer) error {
				return wire.WriteString(w, path)
			},
			func(r io.Reader) error {
				ss, err := ReadStrings(r, MaxStringSize)
				if err != nil {
					return err
				}

				referrers = ss

				return nil
			},
		)

		ch <- Result[[]string]{Value: referrers, Err: err}
	}()

	return ch
}

// QueryDerivationOutputMap returns a map from output names to store paths
// for the given derivation.
func (c *Client) QueryDerivationOutputMap(drvPath string) <-chan Result[map[string]string] {
	ch := make(chan Result[map[string]string], 1)

	go func() {
		var outputs map[string]string

		err := c.doOp(OpQueryDerivationOutputMap,
			func(w io.Writer) error {
				return wire.WriteString(w, drvPath)
			},
			func(r io.Reader) error {
				m, err := ReadStringMap(r, MaxStringSize)
				if err != nil {
					return err
				}

				outputs = m

				return nil
			},
		)

		ch <- Result[map[string]string]{Value: outputs, Err: err}
	}()

	return ch
}

// QueryMissing determines which of the given paths need to be built,
// substituted, or are unknown. It also reports the expected download and
// unpacked NAR sizes.
func (c *Client) QueryMissing(paths []string) <-chan Result[*MissingInfo] {
	ch := make(chan Result[*MissingInfo], 1)

	go func() {
		var info MissingInfo

		err := c.doOp(OpQueryMissing,
			func(w io.Writer) error {
				return WriteStrings(w, paths)
			},
			func(r io.Reader) error {
				var err error

				info.WillBuild, err = ReadStrings(r, MaxStringSize)
				if err != nil {
					return err
				}

				info.WillSubstitute, err = ReadStrings(r, MaxStringSize)
				if err != nil {
					return err
				}

				info.Unknown, err = ReadStrings(r, MaxStringSize)
				if err != nil {
					return err
				}

				info.DownloadSize, err = wire.ReadUint64(r)
				if err != nil {
					return err
				}

				info.NarSize, err = wire.ReadUint64(r)

				return err
			},
		)

		ch <- Result[*MissingInfo]{Value: &info, Err: err}
	}()

	return ch
}

// QueryRealisation looks up content-addressed realisations for the given
// output identifier.
func (c *Client) QueryRealisation(outputID string) <-chan Result[[]string] {
	ch := make(chan Result[[]string], 1)

	go func() {
		var realisations []string

		err := c.doOp(OpQueryRealisation,
			func(w io.Writer) error {
				return wire.WriteString(w, outputID)
			},
			func(r io.Reader) error {
				ss, err := ReadStrings(r, MaxStringSize)
				if err != nil {
					return err
				}

				realisations = ss

				return nil
			},
		)

		ch <- Result[[]string]{Value: realisations, Err: err}
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

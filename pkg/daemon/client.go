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

// NarFromPath streams the NAR serialisation of the given store path.
// The returned io.ReadCloser holds the connection lock; the caller MUST close
// it when done to allow further operations on the client.
func (c *Client) NarFromPath(path string) <-chan Result[io.ReadCloser] {
	ch := make(chan Result[io.ReadCloser], 1)

	go func() {
		c.mu.Lock()

		// Write operation code.
		if err := wire.WriteUint64(c.w, uint64(OpNarFromPath)); err != nil {
			c.mu.Unlock()
			ch <- Result[io.ReadCloser]{Err: &ProtocolError{Op: "NarFromPath write op", Err: err}}

			return
		}

		// Write request payload.
		if err := wire.WriteString(c.w, path); err != nil {
			c.mu.Unlock()
			ch <- Result[io.ReadCloser]{Err: &ProtocolError{Op: "NarFromPath write request", Err: err}}

			return
		}

		// Flush buffered writer.
		if err := c.w.Flush(); err != nil {
			c.mu.Unlock()
			ch <- Result[io.ReadCloser]{Err: &ProtocolError{Op: "NarFromPath flush", Err: err}}

			return
		}

		// Drain stderr log messages until LogLast.
		if err := ProcessStderr(c.r, c.logs); err != nil {
			c.mu.Unlock()
			ch <- Result[io.ReadCloser]{Err: err}

			return
		}

		// Read the NAR data as a bytes field. ReadBytes returns a limited
		// reader over the wire content; wrapping it in mutexReadCloser
		// ensures the mutex is released when the caller closes the reader.
		_, rc, err := wire.ReadBytes(c.r)
		if err != nil {
			c.mu.Unlock()
			ch <- Result[io.ReadCloser]{Err: &ProtocolError{Op: "NarFromPath read response", Err: err}}

			return
		}

		ch <- Result[io.ReadCloser]{Value: &mutexReadCloser{ReadCloser: rc, mu: &c.mu}}
	}()

	return ch
}

// BuildPaths asks the daemon to build the given set of derivation paths or
// store paths. mode controls rebuild behaviour.
func (c *Client) BuildPaths(paths []string, mode BuildMode) <-chan Result[struct{}] {
	ch := make(chan Result[struct{}], 1)

	go func() {
		err := c.doOp(OpBuildPaths,
			func(w io.Writer) error {
				if err := WriteStrings(w, paths); err != nil {
					return err
				}

				return wire.WriteUint64(w, uint64(mode))
			},
			func(r io.Reader) error {
				// Daemon responds with a "1" to acknowledge.
				_, err := wire.ReadUint64(r)

				return err
			},
		)

		ch <- Result[struct{}]{Err: err}
	}()

	return ch
}

// BuildPathsWithResults is like BuildPaths but returns a BuildResult for each
// derived path. Requires protocol >= 1.34.
func (c *Client) BuildPathsWithResults(paths []string, mode BuildMode) <-chan Result[[]BuildResult] {
	ch := make(chan Result[[]BuildResult], 1)

	go func() {
		var results []BuildResult

		err := c.doOp(OpBuildPathsWithResults,
			func(w io.Writer) error {
				if err := WriteStrings(w, paths); err != nil {
					return err
				}

				return wire.WriteUint64(w, uint64(mode))
			},
			func(r io.Reader) error {
				count, err := wire.ReadUint64(r)
				if err != nil {
					return err
				}

				results = make([]BuildResult, count)
				for i := uint64(0); i < count; i++ {
					// Each entry is a DerivedPath string (ignored) followed by a BuildResult.
					_, err := wire.ReadString(r, MaxStringSize)
					if err != nil {
						return err
					}

					br, err := ReadBuildResult(r)
					if err != nil {
						return err
					}

					results[i] = *br
				}

				return nil
			},
		)

		ch <- Result[[]BuildResult]{Value: results, Err: err}
	}()

	return ch
}

// EnsurePath ensures that the given store path is valid by building or
// substituting it if necessary.
func (c *Client) EnsurePath(path string) <-chan Result[struct{}] {
	ch := make(chan Result[struct{}], 1)

	go func() {
		err := c.doOp(OpEnsurePath,
			func(w io.Writer) error {
				return wire.WriteString(w, path)
			},
			func(r io.Reader) error {
				// Daemon responds with a "1" to acknowledge.
				_, err := wire.ReadUint64(r)

				return err
			},
		)

		ch <- Result[struct{}]{Err: err}
	}()

	return ch
}

// BuildDerivation builds a derivation given its store path and definition.
// The derivation is serialized as a BasicDerivation on the wire, and mode
// controls rebuild behaviour. Returns a channel that will receive exactly
// one Result containing the BuildResult.
func (c *Client) BuildDerivation(drvPath string, drv *BasicDerivation, mode BuildMode) <-chan Result[*BuildResult] {
	ch := make(chan Result[*BuildResult], 1)

	go func() {
		var result *BuildResult

		err := c.doOp(OpBuildDerivation,
			func(w io.Writer) error {
				if err := wire.WriteString(w, drvPath); err != nil {
					return err
				}

				if err := WriteBasicDerivation(w, drv); err != nil {
					return err
				}

				return wire.WriteUint64(w, uint64(mode))
			},
			func(r io.Reader) error {
				br, err := ReadBuildResult(r)
				if err != nil {
					return err
				}

				result = br

				return nil
			},
		)

		ch <- Result[*BuildResult]{Value: result, Err: err}
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

// AddTempRoot adds a temporary GC root for the given store path. Temporary
// roots prevent the garbage collector from deleting the path for the duration
// of the daemon session.
func (c *Client) AddTempRoot(path string) <-chan Result[struct{}] {
	ch := make(chan Result[struct{}], 1)

	go func() {
		err := c.doOp(OpAddTempRoot,
			func(w io.Writer) error {
				return wire.WriteString(w, path)
			},
			nil,
		)

		ch <- Result[struct{}]{Err: err}
	}()

	return ch
}

// AddIndirectRoot adds an indirect GC root. The path should be a symlink
// outside the store that points to a store path.
func (c *Client) AddIndirectRoot(path string) <-chan Result[struct{}] {
	ch := make(chan Result[struct{}], 1)

	go func() {
		err := c.doOp(OpAddIndirectRoot,
			func(w io.Writer) error {
				return wire.WriteString(w, path)
			},
			nil,
		)

		ch <- Result[struct{}]{Err: err}
	}()

	return ch
}

// AddPermRoot adds a permanent GC root linking gcRoot to storePath. Returns
// the resulting root path.
func (c *Client) AddPermRoot(storePath string, gcRoot string) <-chan Result[string] {
	ch := make(chan Result[string], 1)

	go func() {
		var resultPath string

		err := c.doOp(OpAddPermRoot,
			func(w io.Writer) error {
				if err := wire.WriteString(w, storePath); err != nil {
					return err
				}

				return wire.WriteString(w, gcRoot)
			},
			func(r io.Reader) error {
				s, err := wire.ReadString(r, MaxStringSize)
				if err != nil {
					return err
				}

				resultPath = s

				return nil
			},
		)

		ch <- Result[string]{Value: resultPath, Err: err}
	}()

	return ch
}

// AddSignatures attaches the given signatures to a store path.
func (c *Client) AddSignatures(path string, sigs []string) <-chan Result[struct{}] {
	ch := make(chan Result[struct{}], 1)

	go func() {
		err := c.doOp(OpAddSignatures,
			func(w io.Writer) error {
				if err := wire.WriteString(w, path); err != nil {
					return err
				}

				return WriteStrings(w, sigs)
			},
			nil,
		)

		ch <- Result[struct{}]{Err: err}
	}()

	return ch
}

// RegisterDrvOutput registers a content-addressed realisation for a
// derivation output.
func (c *Client) RegisterDrvOutput(realisation string) <-chan Result[struct{}] {
	ch := make(chan Result[struct{}], 1)

	go func() {
		err := c.doOp(OpRegisterDrvOutput,
			func(w io.Writer) error {
				return wire.WriteString(w, realisation)
			},
			nil,
		)

		ch <- Result[struct{}]{Err: err}
	}()

	return ch
}

// AddToStoreNar imports a NAR into the store. The info parameter describes
// the path metadata, and source provides the NAR data to stream.
// If repair is true, the path is repaired even if it already exists.
// If dontCheckSigs is true, signature verification is skipped.
func (c *Client) AddToStoreNar(info *PathInfo, source io.Reader, repair bool, dontCheckSigs bool) <-chan Result[struct{}] {
	ch := make(chan Result[struct{}], 1)

	go func() {
		c.mu.Lock()

		// Write operation code.
		if err := wire.WriteUint64(c.w, uint64(OpAddToStoreNar)); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddToStoreNar write op", Err: err}}

			return
		}

		// Write PathInfo.
		if err := WritePathInfo(c.w, info); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddToStoreNar write path info", Err: err}}

			return
		}

		// Write repair and dontCheckSigs flags.
		if err := wire.WriteBool(c.w, repair); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddToStoreNar write repair", Err: err}}

			return
		}

		if err := wire.WriteBool(c.w, dontCheckSigs); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddToStoreNar write dontCheckSigs", Err: err}}

			return
		}

		// Flush before streaming.
		if err := c.w.Flush(); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddToStoreNar flush", Err: err}}

			return
		}

		// Stream NAR data as framed.
		fw := NewFramedWriter(c.w)
		if _, err := io.Copy(fw, source); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddToStoreNar stream data", Err: err}}

			return
		}

		if err := fw.Close(); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddToStoreNar close framed writer", Err: err}}

			return
		}

		// Flush again after framed data.
		if err := c.w.Flush(); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddToStoreNar flush after stream", Err: err}}

			return
		}

		// Drain stderr log messages until LogLast.
		if err := ProcessStderr(c.r, c.logs); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: err}

			return
		}

		c.mu.Unlock()
		ch <- Result[struct{}]{}
	}()

	return ch
}

// AddBuildLog uploads a build log for the given derivation path. The log
// data is streamed from the provided reader.
func (c *Client) AddBuildLog(drvPath string, log io.Reader) <-chan Result[struct{}] {
	ch := make(chan Result[struct{}], 1)

	go func() {
		c.mu.Lock()

		// Write operation code.
		if err := wire.WriteUint64(c.w, uint64(OpAddBuildLog)); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddBuildLog write op", Err: err}}

			return
		}

		// Write derivation path.
		if err := wire.WriteString(c.w, drvPath); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddBuildLog write drvPath", Err: err}}

			return
		}

		// Flush before streaming.
		if err := c.w.Flush(); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddBuildLog flush", Err: err}}

			return
		}

		// Stream log data as framed.
		fw := NewFramedWriter(c.w)
		if _, err := io.Copy(fw, log); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddBuildLog stream data", Err: err}}

			return
		}

		if err := fw.Close(); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddBuildLog close framed writer", Err: err}}

			return
		}

		// Flush again after framed data.
		if err := c.w.Flush(); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddBuildLog flush after stream", Err: err}}

			return
		}

		// Drain stderr log messages until LogLast.
		if err := ProcessStderr(c.r, c.logs); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: err}

			return
		}

		c.mu.Unlock()
		ch <- Result[struct{}]{}
	}()

	return ch
}

// FindRoots returns the set of GC roots known to the daemon. The map keys
// are the root link paths and the values are the store paths they point to.
func (c *Client) FindRoots() <-chan Result[map[string]string] {
	ch := make(chan Result[map[string]string], 1)

	go func() {
		var roots map[string]string

		err := c.doOp(OpFindRoots,
			nil,
			func(r io.Reader) error {
				m, err := ReadStringMap(r, MaxStringSize)
				if err != nil {
					return err
				}

				roots = m

				return nil
			},
		)

		ch <- Result[map[string]string]{Value: roots, Err: err}
	}()

	return ch
}

// CollectGarbage performs a garbage collection operation on the store.
func (c *Client) CollectGarbage(options *GCOptions) <-chan Result[*GCResult] {
	ch := make(chan Result[*GCResult], 1)

	go func() {
		var result GCResult

		err := c.doOp(OpCollectGarbage,
			func(w io.Writer) error {
				if err := wire.WriteUint64(w, uint64(options.Action)); err != nil {
					return err
				}

				if err := WriteStrings(w, options.PathsToDelete); err != nil {
					return err
				}

				if err := wire.WriteBool(w, options.IgnoreLiveness); err != nil {
					return err
				}

				if err := wire.WriteUint64(w, options.MaxFreed); err != nil {
					return err
				}

				// Three deprecated fields, always zero.
				for i := 0; i < 3; i++ {
					if err := wire.WriteUint64(w, 0); err != nil {
						return err
					}
				}

				return nil
			},
			func(r io.Reader) error {
				paths, err := ReadStrings(r, MaxStringSize)
				if err != nil {
					return err
				}

				result.Paths = paths

				bytesFreed, err := wire.ReadUint64(r)
				if err != nil {
					return err
				}

				result.BytesFreed = bytesFreed

				// Deprecated field, ignored.
				_, err = wire.ReadUint64(r)

				return err
			},
		)

		ch <- Result[*GCResult]{Value: &result, Err: err}
	}()

	return ch
}

// OptimiseStore asks the daemon to optimise the Nix store by hard-linking
// identical files.
func (c *Client) OptimiseStore() <-chan Result[struct{}] {
	ch := make(chan Result[struct{}], 1)

	go func() {
		err := c.doOp(OpOptimiseStore, nil, nil)
		ch <- Result[struct{}]{Err: err}
	}()

	return ch
}

// VerifyStore checks the consistency of the Nix store. If checkContents is
// true, the contents of each path are verified against their hash. If repair
// is true, inconsistencies are repaired. Returns true if errors were found.
func (c *Client) VerifyStore(checkContents bool, repair bool) <-chan Result[bool] {
	ch := make(chan Result[bool], 1)

	go func() {
		var errorsFound bool

		err := c.doOp(OpVerifyStore,
			func(w io.Writer) error {
				if err := wire.WriteBool(w, checkContents); err != nil {
					return err
				}

				return wire.WriteBool(w, repair)
			},
			func(r io.Reader) error {
				v, err := wire.ReadBool(r)
				if err != nil {
					return err
				}

				errorsFound = v

				return nil
			},
		)

		ch <- Result[bool]{Value: errorsFound, Err: err}
	}()

	return ch
}

// SetOptions sends the client build settings to the daemon. This should
// typically be called once after connecting.
func (c *Client) SetOptions(settings *ClientSettings) <-chan Result[struct{}] {
	ch := make(chan Result[struct{}], 1)

	go func() {
		err := c.doOp(OpSetOptions,
			func(w io.Writer) error {
				return WriteClientSettings(w, settings)
			},
			nil,
		)

		ch <- Result[struct{}]{Err: err}
	}()

	return ch
}

// AddMultipleToStore imports multiple store paths into the store in a single
// operation. Each item consists of a PathInfo and a NAR data reader. If repair
// is true, existing paths are repaired. If dontCheckSigs is true, signature
// verification is skipped.
func (c *Client) AddMultipleToStore(items []AddToStoreItem, repair bool, dontCheckSigs bool) <-chan Result[struct{}] {
	ch := make(chan Result[struct{}], 1)

	go func() {
		c.mu.Lock()

		// Write operation code.
		if err := wire.WriteUint64(c.w, uint64(OpAddMultipleToStore)); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddMultipleToStore write op", Err: err}}

			return
		}

		// Write repair flag.
		if err := wire.WriteBool(c.w, repair); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddMultipleToStore write repair", Err: err}}

			return
		}

		// Write dontCheckSigs flag.
		if err := wire.WriteBool(c.w, dontCheckSigs); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddMultipleToStore write dontCheckSigs", Err: err}}

			return
		}

		// Write item count.
		if err := wire.WriteUint64(c.w, uint64(len(items))); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddMultipleToStore write count", Err: err}}

			return
		}

		// Write each item: PathInfo + framed NAR data.
		for i := 0; i < len(items); i++ {
			if err := WritePathInfo(c.w, &items[i].Info); err != nil {
				c.mu.Unlock()
				ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddMultipleToStore write path info", Err: err}}

				return
			}

			fw := NewFramedWriter(c.w)

			if _, err := io.Copy(fw, items[i].Source); err != nil {
				c.mu.Unlock()
				ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddMultipleToStore stream data", Err: err}}

				return
			}

			if err := fw.Close(); err != nil {
				c.mu.Unlock()
				ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddMultipleToStore close framed writer", Err: err}}

				return
			}
		}

		// Flush the buffered writer after all items.
		if err := c.w.Flush(); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: &ProtocolError{Op: "AddMultipleToStore flush", Err: err}}

			return
		}

		// Drain stderr log messages until LogLast.
		if err := ProcessStderr(c.r, c.logs); err != nil {
			c.mu.Unlock()
			ch <- Result[struct{}]{Err: err}

			return
		}

		c.mu.Unlock()
		ch <- Result[struct{}]{}
	}()

	return ch
}

// mutexReadCloser wraps an io.ReadCloser and releases a mutex when closed.
// This is used by NarFromPath to hold the connection lock while the caller
// reads the streamed NAR data.
type mutexReadCloser struct {
	io.ReadCloser
	mu   *sync.Mutex
	once sync.Once
}

// Close closes the underlying reader and releases the mutex exactly once.
func (m *mutexReadCloser) Close() error {
	err := m.ReadCloser.Close()
	m.once.Do(func() { m.mu.Unlock() })

	return err
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

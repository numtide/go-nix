package daemon

import (
	"context"
	"io"
	"strings"

	"github.com/nix-community/go-nix/pkg/wire"
)

// AddTempRoot adds a temporary GC root for the given store path. Temporary
// roots prevent the garbage collector from deleting the path for the duration
// of the daemon session.
func (c *Client) AddTempRoot(ctx context.Context, path string) error {
	return c.doOp(ctx, OpAddTempRoot,
		func(w io.Writer) error {
			return wire.WriteString(w, path)
		},
		func(r io.Reader) error {
			return readAck(r)
		},
	)
}

// AddIndirectRoot adds an indirect GC root. The path should be a symlink
// outside the store that points to a store path.
func (c *Client) AddIndirectRoot(ctx context.Context, path string) error {
	return c.doOp(ctx, OpAddIndirectRoot,
		func(w io.Writer) error {
			return wire.WriteString(w, path)
		},
		func(r io.Reader) error {
			return readAck(r)
		},
	)
}

// AddPermRoot adds a permanent GC root linking gcRoot to storePath. Returns
// the resulting root path. Requires protocol >= 1.29.
func (c *Client) AddPermRoot(ctx context.Context, storePath string, gcRoot string) (string, error) {
	if err := c.requireVersion(OpAddPermRoot, ProtoVersionAddPermRoot); err != nil {
		return "", err
	}

	var resultPath string

	err := c.doOp(ctx, OpAddPermRoot,
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

	return resultPath, err
}

// AddSignatures attaches the given signatures to a store path.
func (c *Client) AddSignatures(ctx context.Context, path string, sigs []string) error {
	return c.doOp(ctx, OpAddSignatures,
		func(w io.Writer) error {
			if err := wire.WriteString(w, path); err != nil {
				return err
			}

			return WriteStrings(w, sigs)
		},
		func(r io.Reader) error {
			return readAck(r)
		},
	)
}

// RegisterDrvOutput registers a content-addressed realisation for a
// derivation output. Requires protocol >= 1.31.
func (c *Client) RegisterDrvOutput(ctx context.Context, realisation string) error {
	if err := c.requireVersion(OpRegisterDrvOutput, ProtoVersionRealisationJSON); err != nil {
		return err
	}

	return c.doOp(ctx, OpRegisterDrvOutput,
		func(w io.Writer) error {
			return wire.WriteString(w, realisation)
		},
		nil,
	)
}

// AddToStoreNar imports a NAR into the store. The info parameter describes
// the path metadata, and source provides the NAR data to stream.
// If repair is true, the path is repaired even if it already exists.
// If dontCheckSigs is true, signature verification is skipped.
func (c *Client) AddToStoreNar(
	ctx context.Context, info *PathInfo, source io.Reader, repair, dontCheckSigs bool,
) error {
	if info == nil {
		return ErrNilPathInfo
	}
	if source == nil {
		return ErrNilReader
	}

	ow, err := c.DoStreaming(ctx, OpAddToStoreNar)
	if err != nil {
		return err
	}

	// Write PathInfo.
	if err := WritePathInfo(ow, info, c.info.Version); err != nil {
		ow.Abort()

		return &ProtocolError{Op: "AddToStoreNar write path info", Err: err}
	}

	// Write repair and dontCheckSigs flags.
	if err := wire.WriteBool(ow, repair); err != nil {
		ow.Abort()

		return &ProtocolError{Op: "AddToStoreNar write repair", Err: err}
	}

	if err := wire.WriteBool(ow, dontCheckSigs); err != nil {
		ow.Abort()

		return &ProtocolError{Op: "AddToStoreNar write dontCheckSigs", Err: err}
	}

	// Flush before streaming.
	if err := ow.Flush(); err != nil {
		ow.Abort()

		return &ProtocolError{Op: "AddToStoreNar flush", Err: err}
	}

	// Stream NAR data as framed.
	fw := ow.NewFramedWriter()
	if _, err := io.Copy(fw, source); err != nil {
		ow.Abort()

		return &ProtocolError{Op: "AddToStoreNar stream data", Err: err}
	}

	if err := fw.Close(); err != nil {
		ow.Abort()

		return &ProtocolError{Op: "AddToStoreNar close framed writer", Err: err}
	}

	resp, err := ow.CloseRequest()
	if err != nil {
		return err
	}

	return resp.Close()
}

// AddBuildLog uploads a build log for the given derivation path. The log
// data is streamed from the provided reader. Requires protocol >= 1.32.
func (c *Client) AddBuildLog(ctx context.Context, drvPath string, log io.Reader) error {
	if log == nil {
		return ErrNilReader
	}

	if err := c.requireVersion(OpAddBuildLog, ProtoVersionAddMultipleToStore); err != nil {
		return err
	}

	ow, err := c.DoStreaming(ctx, OpAddBuildLog)
	if err != nil {
		return err
	}

	// Write derivation path as BaseStorePath (basename without /nix/store/ prefix).
	basePath := strings.TrimPrefix(drvPath, DefaultStoreDir)
	if err := wire.WriteString(ow, basePath); err != nil {
		ow.Abort()

		return &ProtocolError{Op: "AddBuildLog write drvPath", Err: err}
	}

	// Flush before streaming.
	if err := ow.Flush(); err != nil {
		ow.Abort()

		return &ProtocolError{Op: "AddBuildLog flush", Err: err}
	}

	// Stream log data as framed.
	fw := ow.NewFramedWriter()
	if _, err := io.Copy(fw, log); err != nil {
		ow.Abort()

		return &ProtocolError{Op: "AddBuildLog stream data", Err: err}
	}

	if err := fw.Close(); err != nil {
		ow.Abort()

		return &ProtocolError{Op: "AddBuildLog close framed writer", Err: err}
	}

	resp, err := ow.CloseRequest()
	if err != nil {
		return err
	}
	defer resp.Close()

	return readAck(resp)
}

// CollectGarbage performs a garbage collection operation on the store.
func (c *Client) CollectGarbage(ctx context.Context, options *GCOptions) (*GCResult, error) {
	if options == nil {
		return nil, ErrNilOptions
	}

	var result GCResult

	err := c.doOp(ctx, OpCollectGarbage,
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

			// Deprecated fields, always zero.
			for i := 0; i < numDeprecatedGCFields; i++ {
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

	return &result, err
}

// OptimiseStore asks the daemon to optimise the Nix store by hard-linking
// identical files.
func (c *Client) OptimiseStore(ctx context.Context) error {
	return c.doOp(ctx, OpOptimiseStore, nil,
		func(r io.Reader) error {
			return readAck(r)
		},
	)
}

// VerifyStore checks the consistency of the Nix store. If checkContents is
// true, the contents of each path are verified against their hash. If repair
// is true, inconsistencies are repaired. Returns true if errors were found.
func (c *Client) VerifyStore(ctx context.Context, checkContents bool, repair bool) (bool, error) {
	var errorsFound bool

	err := c.doOp(ctx, OpVerifyStore,
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

	return errorsFound, err
}

// SetOptions sends the client build settings to the daemon. This should
// typically be called once after connecting.
func (c *Client) SetOptions(ctx context.Context, settings *ClientSettings) error {
	return c.doOp(ctx, OpSetOptions,
		func(w io.Writer) error {
			return WriteClientSettings(w, settings, c.info.Version)
		},
		nil,
	)
}

// AddMultipleToStore imports multiple store paths into the store in a single
// operation. Each item consists of a PathInfo and a NAR data reader. If repair
// is true, existing paths are repaired. If dontCheckSigs is true, signature
// verification is skipped. Requires protocol >= 1.32.
//
// Wire format:
//
//	[OpAddMultipleToStore]  <- raw connection
//	[repair (bool)]         <- raw connection
//	[dontCheckSigs (bool)]  <- raw connection
//	[flush]
//	[SINGLE FramedWriter wrapping ALL of the following:]
//	  [count (uint64)]
//	  For each item:
//	    [WritePathInfo]
//	    [NAR data via io.Copy]
//	[FramedWriter.Close()]  <- zero-length terminator
//	[flush]
//	[ProcessStderr]
func (c *Client) AddMultipleToStore(
	ctx context.Context, items []AddToStoreItem, repair, dontCheckSigs bool,
) error {
	if err := c.requireVersion(OpAddMultipleToStore, ProtoVersionAddMultipleToStore); err != nil {
		return err
	}

	for i := 0; i < len(items); i++ {
		if items[i].Source == nil {
			return ErrNilReader
		}
	}

	ow, err := c.DoStreaming(ctx, OpAddMultipleToStore)
	if err != nil {
		return err
	}

	// Write repair and dontCheckSigs flags (outside framed stream).
	if err := wire.WriteBool(ow, repair); err != nil {
		ow.Abort()

		return &ProtocolError{Op: "AddMultipleToStore write repair", Err: err}
	}

	if err := wire.WriteBool(ow, dontCheckSigs); err != nil {
		ow.Abort()

		return &ProtocolError{Op: "AddMultipleToStore write dontCheckSigs", Err: err}
	}

	// Flush before entering framed mode.
	if err := ow.Flush(); err != nil {
		ow.Abort()

		return &ProtocolError{Op: "AddMultipleToStore flush", Err: err}
	}

	// Create a single FramedWriter that wraps all item data.
	fw := ow.NewFramedWriter()

	// Write count inside the framed stream.
	if err := wire.WriteUint64(fw, uint64(len(items))); err != nil {
		ow.Abort()

		return &ProtocolError{Op: "AddMultipleToStore write count", Err: err}
	}

	// Write each item: PathInfo + NAR data, all inside the framed stream.
	for i := 0; i < len(items); i++ {
		if err := WritePathInfo(fw, &items[i].Info, c.info.Version); err != nil {
			ow.Abort()

			return &ProtocolError{Op: "AddMultipleToStore write path info", Err: err}
		}

		if _, err := io.Copy(fw, items[i].Source); err != nil {
			ow.Abort()

			return &ProtocolError{Op: "AddMultipleToStore stream NAR", Err: err}
		}
	}

	// Close the framed writer (sends zero-length terminator).
	if err := fw.Close(); err != nil {
		ow.Abort()

		return &ProtocolError{Op: "AddMultipleToStore close framed writer", Err: err}
	}

	resp, err := ow.CloseRequest()
	if err != nil {
		return err
	}

	return resp.Close()
}

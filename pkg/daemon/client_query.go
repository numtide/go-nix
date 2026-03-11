package daemon

import (
	"context"
	"fmt"
	"io"

	"github.com/nix-community/go-nix/pkg/nar"
	"github.com/nix-community/go-nix/pkg/wire"
)

// IsValidPath checks whether the given store path is valid (exists in the
// store).
func (c *Client) IsValidPath(ctx context.Context, path string) (bool, error) {
	var valid bool

	err := c.doOp(ctx, OpIsValidPath,
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

	return valid, err
}

// QueryPathInfo retrieves the metadata for the given store path. If the path
// is not found in the store, the result is nil with no error.
func (c *Client) QueryPathInfo(ctx context.Context, path string) (*PathInfo, error) {
	var info *PathInfo

	err := c.doOp(ctx, OpQueryPathInfo,
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

			info, err = ReadPathInfo(r, path, c.info.Version)

			return err
		},
	)

	return info, err
}

// QueryPathFromHashPart looks up a store path by its hash part. If nothing
// is found, the result is an empty string with no error.
func (c *Client) QueryPathFromHashPart(ctx context.Context, hashPart string) (string, error) {
	var storePath string

	err := c.doOp(ctx, OpQueryPathFromHashPart,
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

	return storePath, err
}

// QueryAllValidPaths returns all valid store paths known to the daemon.
func (c *Client) QueryAllValidPaths(ctx context.Context) ([]string, error) {
	var paths []string

	err := c.doOp(ctx, OpQueryAllValidPaths,
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

	return paths, err
}

// QueryValidPaths returns the subset of the given paths that are valid. If
// substituteOk is true, the daemon may attempt to substitute missing paths.
func (c *Client) QueryValidPaths(ctx context.Context, paths []string, substituteOk bool) ([]string, error) {
	var valid []string

	err := c.doOp(ctx, OpQueryValidPaths,
		func(w io.Writer) error {
			if err := WriteStrings(w, paths); err != nil {
				return err
			}

			// Protocol >= 1.27: substituteOk flag.
			if c.info.Version >= ProtoVersionSubstituteOk {
				if err := wire.WriteBool(w, substituteOk); err != nil {
					return err
				}
			}

			return nil
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

	return valid, err
}

// QuerySubstitutablePaths returns the subset of the given paths that can be
// substituted from a binary cache or other substitute source.
func (c *Client) QuerySubstitutablePaths(ctx context.Context, paths []string) ([]string, error) {
	var substitutable []string

	err := c.doOp(ctx, OpQuerySubstitutablePaths,
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

	return substitutable, err
}

// QueryValidDerivers returns the derivations known to have produced the given
// store path.
func (c *Client) QueryValidDerivers(ctx context.Context, path string) ([]string, error) {
	var derivers []string

	err := c.doOp(ctx, OpQueryValidDerivers,
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

	return derivers, err
}

// QueryReferrers returns the set of store paths that reference (depend on)
// the given path.
func (c *Client) QueryReferrers(ctx context.Context, path string) ([]string, error) {
	var referrers []string

	err := c.doOp(ctx, OpQueryReferrers,
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

	return referrers, err
}

// QueryDerivationOutputMap returns a map from output names to store paths
// for the given derivation. Requires protocol >= 1.30.
func (c *Client) QueryDerivationOutputMap(ctx context.Context, drvPath string) (map[string]string, error) {
	if err := c.requireVersion(OpQueryDerivationOutputMap, ProtoVersionQueryDerivationOutputMap); err != nil {
		return nil, err
	}

	var outputs map[string]string

	err := c.doOp(ctx, OpQueryDerivationOutputMap,
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

	return outputs, err
}

// QueryMissing determines which of the given paths need to be built,
// substituted, or are unknown. It also reports the expected download and
// unpacked NAR sizes. Requires protocol >= 1.30.
func (c *Client) QueryMissing(ctx context.Context, paths []string) (*MissingInfo, error) {
	if err := c.requireVersion(OpQueryMissing, ProtoVersionQueryMissing); err != nil {
		return nil, err
	}

	var info MissingInfo

	err := c.doOp(ctx, OpQueryMissing,
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

	return &info, err
}

// QueryRealisation looks up content-addressed realisations for the given
// output identifier. Requires protocol >= 1.31.
func (c *Client) QueryRealisation(ctx context.Context, outputID string) ([]string, error) {
	if err := c.requireVersion(OpQueryRealisation, ProtoVersionRealisationJSON); err != nil {
		return nil, err
	}

	var realisations []string

	err := c.doOp(ctx, OpQueryRealisation,
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

	return realisations, err
}

// FindRoots returns the set of GC roots known to the daemon. The map keys
// are the root link paths and the values are the store paths they point to.
func (c *Client) FindRoots(ctx context.Context) (map[string]string, error) {
	var roots map[string]string

	err := c.doOp(ctx, OpFindRoots,
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

	return roots, err
}

// NarFromPath returns the NAR serialisation of the given store path as a
// streaming reader. The returned io.ReadCloser holds the connection lock;
// the caller must read the complete NAR and call Close to release it.
func (c *Client) NarFromPath(
	ctx context.Context, path string,
) (io.ReadCloser, error) {
	if err := c.checkCtx(ctx); err != nil {
		return nil, err
	}

	cancel, err := c.lockForCtx(ctx)
	if err != nil {
		return nil, err
	}

	// Write operation code.
	if err := wire.WriteUint64(c.w, uint64(OpNarFromPath)); err != nil {
		c.release(cancel)

		return nil, &ProtocolError{Op: "NarFromPath write op", Err: err}
	}

	// Write request payload.
	if err := wire.WriteString(c.w, path); err != nil {
		c.release(cancel)

		return nil, &ProtocolError{Op: "NarFromPath write request", Err: err}
	}

	// Flush buffered writer.
	if err := c.w.Flush(); err != nil {
		c.release(cancel)

		return nil, &ProtocolError{Op: "NarFromPath flush", Err: err}
	}

	// Drain stderr log messages until LogLast.
	if err := ProcessStderrWithSink(c.r, c.logSink); err != nil {
		c.release(cancel)

		return nil, err
	}

	// The daemon sends raw NAR data (self-delimiting format). Use io.Pipe
	// with io.TeeReader so that everything the NAR reader consumes from the
	// connection is also written to the pipe for the caller to read.
	pr, pw := io.Pipe()
	tee := io.TeeReader(c.r, pw)

	go func() {
		err := drainNAR(tee)
		c.release(cancel)
		pw.CloseWithError(err)
	}()

	return pr, nil
}

// drainNAR reads one complete NAR archive from r using nar.Reader,
// consuming all entries and file content until EOF.
func drainNAR(r io.Reader) error {
	nr, err := nar.NewReader(r)
	if err != nil {
		return fmt.Errorf("reading NAR: %w", err)
	}
	defer nr.Close()

	for {
		hdr, err := nr.Next()
		if err == io.EOF {
			return nil
		}

		if err != nil {
			return fmt.Errorf("reading NAR: %w", err)
		}

		// Drain file content so the reader advances past this entry.
		if hdr.Type == nar.TypeRegular && hdr.Size > 0 {
			if _, err := io.Copy(io.Discard, nr); err != nil {
				return fmt.Errorf("reading NAR content: %w", err)
			}
		}
	}
}

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/nix-community/go-nix/pkg/nar"
	"github.com/nix-community/go-nix/pkg/wire"
)

// IsValidPath checks whether the given store path is valid (exists in the
// store).
func (c *Client) IsValidPath(ctx context.Context, path string) (bool, error) {
	var buf bytes.Buffer
	if err := wire.WriteString(&buf, path); err != nil {
		return false, &ProtocolError{Op: "IsValidPath write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpIsValidPath, &buf)
	if err != nil {
		return false, err
	}
	defer resp.Close()

	valid, err := wire.ReadBool(resp)
	if err != nil {
		return false, &ProtocolError{Op: "IsValidPath read response", Err: err}
	}

	return valid, nil
}

// QueryPathInfo retrieves the metadata for the given store path. Returns
// ErrNotFound if the path does not exist in the store.
func (c *Client) QueryPathInfo(ctx context.Context, path string) (*PathInfo, error) {
	var buf bytes.Buffer
	if err := wire.WriteString(&buf, path); err != nil {
		return nil, &ProtocolError{Op: "QueryPathInfo write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpQueryPathInfo, &buf)
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	found, err := wire.ReadBool(resp)
	if err != nil {
		return nil, &ProtocolError{Op: "QueryPathInfo read response", Err: err}
	}

	if !found {
		return nil, ErrNotFound
	}

	return ReadPathInfo(resp, path, c.info.Version)
}

// QueryPathFromHashPart looks up a store path by its hash part. If nothing
// is found, the result is an empty string with no error.
func (c *Client) QueryPathFromHashPart(ctx context.Context, hashPart string) (string, error) {
	var buf bytes.Buffer
	if err := wire.WriteString(&buf, hashPart); err != nil {
		return "", &ProtocolError{Op: "QueryPathFromHashPart write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpQueryPathFromHashPart, &buf)
	if err != nil {
		return "", err
	}
	defer resp.Close()

	storePath, err := wire.ReadString(resp, MaxStringSize)
	if err != nil {
		return "", &ProtocolError{Op: "QueryPathFromHashPart read response", Err: err}
	}

	return storePath, nil
}

// QueryAllValidPaths returns all valid store paths known to the daemon.
func (c *Client) QueryAllValidPaths(ctx context.Context) ([]string, error) {
	resp, err := c.Execute(ctx, OpQueryAllValidPaths, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	paths, err := wire.ReadStrings(resp, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "QueryAllValidPaths read response", Err: err}
	}

	return paths, nil
}

// QueryValidPaths returns the subset of the given paths that are valid. If
// substituteOk is true, the daemon may attempt to substitute missing paths.
func (c *Client) QueryValidPaths(ctx context.Context, paths []string, substituteOk bool) ([]string, error) {
	var buf bytes.Buffer

	if err := wire.WriteStrings(&buf, paths); err != nil {
		return nil, &ProtocolError{Op: "QueryValidPaths write request", Err: err}
	}

	// protocol >= 1.27: substituteOk flag.
	if c.info.Version >= ProtoVersionSubstituteOk {
		if err := wire.WriteBool(&buf, substituteOk); err != nil {
			return nil, &ProtocolError{Op: "QueryValidPaths write request", Err: err}
		}
	}

	resp, err := c.Execute(ctx, OpQueryValidPaths, &buf)
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	valid, err := wire.ReadStrings(resp, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "QueryValidPaths read response", Err: err}
	}

	return valid, nil
}

// QuerySubstitutablePaths returns the subset of the given paths that can be
// substituted from a binary cache or other substitute source.
func (c *Client) QuerySubstitutablePaths(ctx context.Context, paths []string) ([]string, error) {
	var buf bytes.Buffer
	if err := wire.WriteStrings(&buf, paths); err != nil {
		return nil, &ProtocolError{Op: "QuerySubstitutablePaths write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpQuerySubstitutablePaths, &buf)
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	substitutable, err := wire.ReadStrings(resp, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "QuerySubstitutablePaths read response", Err: err}
	}

	return substitutable, nil
}

// QuerySubstitutablePathInfos returns substitution metadata (deriver,
// references, download size, NAR size) for the given paths. The input is a
// map from store paths to optional content addresses (empty string for no CA).
// Paths not available from any substituter are omitted from the result.
func (c *Client) QuerySubstitutablePathInfos(
	ctx context.Context, paths map[string]string,
) (map[string]*SubstitutablePathInfo, error) {
	var buf bytes.Buffer

	// protocol >= 1.22 (always true for us): send StorePathCAMap.
	if err := wire.WriteUint64(&buf, uint64(len(paths))); err != nil {
		return nil, &ProtocolError{Op: "QuerySubstitutablePathInfos write request", Err: err}
	}

	for storePath, ca := range paths {
		if err := wire.WriteString(&buf, storePath); err != nil {
			return nil, &ProtocolError{Op: "QuerySubstitutablePathInfos write request", Err: err}
		}

		if err := wire.WriteString(&buf, ca); err != nil {
			return nil, &ProtocolError{Op: "QuerySubstitutablePathInfos write request", Err: err}
		}
	}

	resp, err := c.Execute(ctx, OpQuerySubstitutablePathInfos, &buf)
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	count, err := wire.ReadUint64(resp)
	if err != nil {
		return nil, &ProtocolError{Op: "QuerySubstitutablePathInfos read response", Err: err}
	}

	result := make(map[string]*SubstitutablePathInfo, count)

	for range count {
		storePath, err := wire.ReadString(resp, MaxStringSize)
		if err != nil {
			return nil, &ProtocolError{Op: "QuerySubstitutablePathInfos read response", Err: err}
		}

		deriver, err := wire.ReadString(resp, MaxStringSize)
		if err != nil {
			return nil, &ProtocolError{Op: "QuerySubstitutablePathInfos read response", Err: err}
		}

		references, err := wire.ReadStrings(resp, MaxStringSize)
		if err != nil {
			return nil, &ProtocolError{Op: "QuerySubstitutablePathInfos read response", Err: err}
		}

		downloadSize, err := wire.ReadUint64(resp)
		if err != nil {
			return nil, &ProtocolError{Op: "QuerySubstitutablePathInfos read response", Err: err}
		}

		narSize, err := wire.ReadUint64(resp)
		if err != nil {
			return nil, &ProtocolError{Op: "QuerySubstitutablePathInfos read response", Err: err}
		}

		result[storePath] = &SubstitutablePathInfo{
			Deriver:      deriver,
			References:   references,
			DownloadSize: downloadSize,
			NarSize:      narSize,
		}
	}

	return result, nil
}

// QueryValidDerivers returns the derivations known to have produced the given
// store path.
func (c *Client) QueryValidDerivers(ctx context.Context, path string) ([]string, error) {
	var buf bytes.Buffer
	if err := wire.WriteString(&buf, path); err != nil {
		return nil, &ProtocolError{Op: "QueryValidDerivers write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpQueryValidDerivers, &buf)
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	derivers, err := wire.ReadStrings(resp, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "QueryValidDerivers read response", Err: err}
	}

	return derivers, nil
}

// QueryReferrers returns the set of store paths that reference (depend on)
// the given path.
func (c *Client) QueryReferrers(ctx context.Context, path string) ([]string, error) {
	var buf bytes.Buffer
	if err := wire.WriteString(&buf, path); err != nil {
		return nil, &ProtocolError{Op: "QueryReferrers write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpQueryReferrers, &buf)
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	referrers, err := wire.ReadStrings(resp, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "QueryReferrers read response", Err: err}
	}

	return referrers, nil
}

// QueryDerivationOutputMap returns a map from output names to store paths
// for the given derivation. Requires protocol >= 1.30.
func (c *Client) QueryDerivationOutputMap(ctx context.Context, drvPath string) (map[string]string, error) {
	if err := c.requireVersion(OpQueryDerivationOutputMap, ProtoVersionQueryDerivationOutputMap); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := wire.WriteString(&buf, drvPath); err != nil {
		return nil, &ProtocolError{Op: "QueryDerivationOutputMap write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpQueryDerivationOutputMap, &buf)
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	outputs, err := wire.ReadStringMap(resp, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "QueryDerivationOutputMap read response", Err: err}
	}

	return outputs, nil
}

// QueryMissing determines which of the given paths need to be built,
// substituted, or are unknown. It also reports the expected download and
// unpacked NAR sizes. Requires protocol >= 1.30.
func (c *Client) QueryMissing(ctx context.Context, paths []string) (*MissingInfo, error) {
	if err := c.requireVersion(OpQueryMissing, ProtoVersionQueryMissing); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := wire.WriteStrings(&buf, paths); err != nil {
		return nil, &ProtocolError{Op: "QueryMissing write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpQueryMissing, &buf)
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	var info MissingInfo

	info.WillBuild, err = wire.ReadStrings(resp, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "QueryMissing read response", Err: err}
	}

	info.WillSubstitute, err = wire.ReadStrings(resp, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "QueryMissing read response", Err: err}
	}

	info.Unknown, err = wire.ReadStrings(resp, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "QueryMissing read response", Err: err}
	}

	info.DownloadSize, err = wire.ReadUint64(resp)
	if err != nil {
		return nil, &ProtocolError{Op: "QueryMissing read response", Err: err}
	}

	info.NarSize, err = wire.ReadUint64(resp)
	if err != nil {
		return nil, &ProtocolError{Op: "QueryMissing read response", Err: err}
	}

	return &info, nil
}

// QueryRealisation looks up content-addressed realisations for the given
// output identifier. Requires protocol >= 1.31.
func (c *Client) QueryRealisation(ctx context.Context, outputID string) ([]Realisation, error) {
	if err := c.requireVersion(OpQueryRealisation, ProtoVersionRealisationJSON); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := wire.WriteString(&buf, outputID); err != nil {
		return nil, &ProtocolError{Op: "QueryRealisation write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpQueryRealisation, &buf)
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	ss, err := wire.ReadStrings(resp, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "QueryRealisation read response", Err: err}
	}

	realisations := make([]Realisation, len(ss))

	for i, s := range ss {
		if err := json.Unmarshal([]byte(s), &realisations[i]); err != nil {
			return nil, &ProtocolError{Op: "QueryRealisation parse JSON", Err: err}
		}
	}

	return realisations, nil
}

// FindRoots returns the set of GC roots known to the daemon. The map keys
// are the root link paths and the values are the store paths they point to.
func (c *Client) FindRoots(ctx context.Context) (map[string]string, error) {
	resp, err := c.Execute(ctx, OpFindRoots, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	roots, err := wire.ReadStringMap(resp, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "FindRoots read response", Err: err}
	}

	return roots, nil
}

// NarFromPath returns the NAR serialisation of the given store path as a
// streaming reader. The caller must read the complete NAR and call Close
// before starting another operation.
//
// If logFn is non-nil, daemon log messages are passed to it before the NAR
// data is returned. If nil, log messages are discarded.
func (c *Client) NarFromPath(
	ctx context.Context, path string, logFn func(LogMessage),
) (r io.ReadCloser, err error) {
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

	// write operation code
	if err = wire.WriteUint64(c.w, uint64(OpNarFromPath)); err != nil {
		_ = unsetCancelDeadline()

		return nil, &ProtocolError{Op: "NarFromPath write op", Err: err}
	}

	// write request payload
	if err = wire.WriteString(c.w, path); err != nil {
		_ = unsetCancelDeadline()

		return nil, &ProtocolError{Op: "NarFromPath write request", Err: err}
	}

	// flush buffered writer
	if err = c.w.Flush(); err != nil {
		_ = unsetCancelDeadline()

		return nil, &ProtocolError{Op: "NarFromPath flush", Err: err}
	}

	// drain stderr log messages until LogLast
	fn := logFn
	if fn == nil {
		fn = c.Logger
	}

	if err = ProcessStderr(c.r, fn, c.info.Version); err != nil {
		_ = unsetCancelDeadline()

		return nil, err
	}

	// The daemon sends raw NAR data (self-delimiting format).
	// Use io.Pipe with io.TeeReader so that everything the NAR reader consumes from the connection is also written to
	// the pipe for the caller to read.
	pr, pw := io.Pipe()
	tee := io.TeeReader(c.r, pw)

	go func() {
		err = drainNAR(tee)

		_ = unsetCancelDeadline()
		_ = pw.CloseWithError(err)
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

	var hdr *nar.Header

	for {
		hdr, err = nr.Next()
		if err == io.EOF {
			return nil
		}

		if err != nil {
			return fmt.Errorf("reading NAR: %w", err)
		}

		// Drain file content so the reader advances past this entry.
		if hdr.Type == nar.TypeRegular && hdr.Size > 0 {
			if _, err = io.Copy(io.Discard, nr); err != nil {
				return fmt.Errorf("reading NAR content: %w", err)
			}
		}
	}
}

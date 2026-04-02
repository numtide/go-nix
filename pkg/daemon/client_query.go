package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/nix-community/go-nix/pkg/nar"
	"github.com/nix-community/go-nix/pkg/wire"
)

// IsValidPath checks whether the given store path is valid (exists in the store).
func (c *Client) IsValidPath(ctx context.Context, path string, opts ...ExecOption) (bool, error) {
	resp, err := c.Execute(ctx, OpIsValidPath, append(opts, WithBody(func(enc *wire.Encoder) error {
		return enc.WriteString(path)
	}))...)
	if err != nil {
		return false, err
	}

	defer func() { _ = resp.Close() }()

	dec := wire.NewDecoder(resp, MaxStringSize)

	valid, err := dec.ReadBool()
	if err != nil {
		return false, &ProtocolError{Op: "IsValidPath read response", Err: err}
	}

	return valid, nil
}

// QueryPathInfo retrieves the metadata for the given store path.
// Returns ErrNotFound if the path does not exist in the store.
func (c *Client) QueryPathInfo(ctx context.Context, path string, opts ...ExecOption) (*PathInfo, error) {
	resp, err := c.Execute(ctx, OpQueryPathInfo, append(opts, WithBody(func(enc *wire.Encoder) error {
		return enc.WriteString(path)
	}))...)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Close() }()

	dec := wire.NewDecoder(resp, MaxStringSize)

	found, err := dec.ReadBool()
	if err != nil {
		return nil, &ProtocolError{Op: "QueryPathInfo read response", Err: err}
	}

	if !found {
		return nil, ErrNotFound
	}

	return ReadPathInfo(dec, path, c.info.Version)
}

// QueryPathFromHashPart looks up a store path by its hash part.
// If nothing is found, the result is an empty string with no error.
func (c *Client) QueryPathFromHashPart(ctx context.Context, hashPart string, opts ...ExecOption) (string, error) {
	resp, err := c.Execute(ctx, OpQueryPathFromHashPart, append(opts, WithBody(func(enc *wire.Encoder) error {
		return enc.WriteString(hashPart)
	}))...)
	if err != nil {
		return "", err
	}

	defer func() { _ = resp.Close() }()

	dec := wire.NewDecoder(resp, MaxStringSize)

	storePath, err := dec.ReadString()
	if err != nil {
		return "", &ProtocolError{Op: "QueryPathFromHashPart read response", Err: err}
	}

	return storePath, nil
}

// QueryAllValidPaths returns all valid store paths known to the daemon.
func (c *Client) QueryAllValidPaths(ctx context.Context, opts ...ExecOption) ([]string, error) {
	resp, err := c.Execute(ctx, OpQueryAllValidPaths, opts...)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Close() }()

	dec := wire.NewDecoder(resp, MaxStringSize)

	paths, err := dec.ReadStrings()
	if err != nil {
		return nil, &ProtocolError{Op: "QueryAllValidPaths read response", Err: err}
	}

	return paths, nil
}

// QueryValidPaths returns the subset of the given paths that are valid.
// If substituteOk is true, the daemon may attempt to substitute missing paths.
func (c *Client) QueryValidPaths(
	ctx context.Context,
	paths []string,
	substituteOk bool,
	opts ...ExecOption,
) ([]string, error) {
	resp, err := c.Execute(ctx, OpQueryValidPaths, append(opts, WithBody(func(enc *wire.Encoder) error {
		if err := enc.WriteStrings(paths); err != nil {
			return err
		}

		// protocol >= 1.27: substituteOk flag.
		if c.info.Version >= ProtoVersionSubstituteOk {
			if err := enc.WriteBool(substituteOk); err != nil {
				return err
			}
		}

		return nil
	}))...)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Close() }()

	dec := wire.NewDecoder(resp, MaxStringSize)

	valid, err := dec.ReadStrings()
	if err != nil {
		return nil, &ProtocolError{Op: "QueryValidPaths read response", Err: err}
	}

	return valid, nil
}

// QuerySubstitutablePaths returns the subset of the given paths that can be substituted from a binary cache or other
// substitute source.
func (c *Client) QuerySubstitutablePaths(ctx context.Context, paths []string, opts ...ExecOption) ([]string, error) {
	resp, err := c.Execute(ctx, OpQuerySubstitutablePaths, append(opts, WithBody(func(enc *wire.Encoder) error {
		return enc.WriteStrings(paths)
	}))...)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Close() }()

	dec := wire.NewDecoder(resp, MaxStringSize)

	substitutable, err := dec.ReadStrings()
	if err != nil {
		return nil, &ProtocolError{Op: "QuerySubstitutablePaths read response", Err: err}
	}

	return substitutable, nil
}

// QuerySubstitutablePathInfos returns substitution metadata (deriver, references, download size, NAR size) for the
// given paths.
// The input is a map from store paths to optional content addresses (empty string for no CA).
// Paths not available from any substituter are omitted from the result.
func (c *Client) QuerySubstitutablePathInfos(
	ctx context.Context, paths map[string]string,
	opts ...ExecOption,
) (map[string]*SubstitutablePathInfo, error) {
	resp, err := c.Execute(ctx, OpQuerySubstitutablePathInfos, append(opts, WithBody(func(enc *wire.Encoder) error {
		// protocol >= 1.22 (always true for us): send StorePathCAMap.
		if err := enc.WriteUint64(uint64(len(paths))); err != nil {
			return err
		}

		for storePath, ca := range paths {
			if err := enc.WriteString(storePath); err != nil {
				return err
			}

			if err := enc.WriteString(ca); err != nil {
				return err
			}
		}

		return nil
	}))...)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Close() }()

	dec := wire.NewDecoder(resp, MaxStringSize)

	count, err := dec.ReadUint64()
	if err != nil {
		return nil, &ProtocolError{Op: "QuerySubstitutablePathInfos read response", Err: err}
	}

	// drain the results
	result := make(map[string]*SubstitutablePathInfo, count)

	for range count {
		storePath, err := dec.ReadString()
		if err != nil {
			return nil, &ProtocolError{Op: "QuerySubstitutablePathInfos read response", Err: err}
		}

		var info SubstitutablePathInfo
		if err := dec.Decode(&info); err != nil {
			return nil, &ProtocolError{Op: "QuerySubstitutablePathInfos read response", Err: err}
		}

		result[storePath] = &info
	}

	return result, nil
}

// QueryValidDerivers returns the derivations known to have produced the given store path.
func (c *Client) QueryValidDerivers(ctx context.Context, path string, opts ...ExecOption) ([]string, error) {
	resp, err := c.Execute(ctx, OpQueryValidDerivers, append(opts, WithBody(func(enc *wire.Encoder) error {
		return enc.WriteString(path)
	}))...)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Close() }()

	dec := wire.NewDecoder(resp, MaxStringSize)

	derivers, err := dec.ReadStrings()
	if err != nil {
		return nil, &ProtocolError{Op: "QueryValidDerivers read response", Err: err}
	}

	return derivers, nil
}

// QueryReferrers returns the set of store paths that reference (depend on) the given path.
func (c *Client) QueryReferrers(ctx context.Context, path string, opts ...ExecOption) ([]string, error) {
	resp, err := c.Execute(ctx, OpQueryReferrers, append(opts, WithBody(func(enc *wire.Encoder) error {
		return enc.WriteString(path)
	}))...)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Close() }()

	dec := wire.NewDecoder(resp, MaxStringSize)

	referrers, err := dec.ReadStrings()
	if err != nil {
		return nil, &ProtocolError{Op: "QueryReferrers read response", Err: err}
	}

	return referrers, nil
}

// QueryDerivationOutputMap returns a map from output names to store paths for the given derivation.
// Requires protocol >= 1.30.
func (c *Client) QueryDerivationOutputMap(
	ctx context.Context,
	drvPath string,
	opts ...ExecOption,
) (map[string]string, error) {
	// version check
	if err := c.requireVersion(OpQueryDerivationOutputMap, ProtoVersionQueryDerivationOutputMap); err != nil {
		return nil, err
	}

	// send request
	resp, err := c.Execute(ctx, OpQueryDerivationOutputMap, append(opts, WithBody(func(enc *wire.Encoder) error {
		return enc.WriteString(drvPath)
	}))...)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Close() }()

	// process the response
	dec := wire.NewDecoder(resp, MaxStringSize)

	outputs, err := dec.ReadStringMap()
	if err != nil {
		return nil, &ProtocolError{Op: "QueryDerivationOutputMap read response", Err: err}
	}

	return outputs, nil
}

// QueryMissing determines which of the given paths need to be built, substituted, or are unknown.
// It also reports the expected download and unpacked NAR sizes.
// Requires protocol >= 1.30.
func (c *Client) QueryMissing(ctx context.Context, paths []string, opts ...ExecOption) (*MissingInfo, error) {
	// version check
	if err := c.requireVersion(OpQueryMissing, ProtoVersionQueryMissing); err != nil {
		return nil, err
	}

	// send request
	resp, err := c.Execute(ctx, OpQueryMissing, append(opts, WithBody(func(enc *wire.Encoder) error {
		return enc.WriteStrings(paths)
	}))...)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Close() }()

	// process the response
	dec := wire.NewDecoder(resp, MaxStringSize)

	var info MissingInfo

	info.WillBuild, err = dec.ReadStrings()
	if err != nil {
		return nil, &ProtocolError{Op: "QueryMissing read response", Err: err}
	}

	info.WillSubstitute, err = dec.ReadStrings()
	if err != nil {
		return nil, &ProtocolError{Op: "QueryMissing read response", Err: err}
	}

	info.Unknown, err = dec.ReadStrings()
	if err != nil {
		return nil, &ProtocolError{Op: "QueryMissing read response", Err: err}
	}

	info.DownloadSize, err = dec.ReadUint64()
	if err != nil {
		return nil, &ProtocolError{Op: "QueryMissing read response", Err: err}
	}

	info.NarSize, err = dec.ReadUint64()
	if err != nil {
		return nil, &ProtocolError{Op: "QueryMissing read response", Err: err}
	}

	return &info, nil
}

// QueryRealisation looks up content-addressed realisations for the given output identifier.
// Requires protocol >= 1.31.
func (c *Client) QueryRealisation(ctx context.Context, outputID string, opts ...ExecOption) ([]Realisation, error) {
	// version check
	if err := c.requireVersion(OpQueryRealisation, ProtoVersionRealisationJSON); err != nil {
		return nil, err
	}

	// send the request
	resp, err := c.Execute(ctx, OpQueryRealisation, append(opts, WithBody(func(enc *wire.Encoder) error {
		return enc.WriteString(outputID)
	}))...)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Close() }()

	// process the response
	dec := wire.NewDecoder(resp, MaxStringSize)

	ss, err := dec.ReadStrings()
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

// FindRoots returns the set of GC roots known to the daemon.
// The map keys are the root link paths, and the values are the store paths they point to.
func (c *Client) FindRoots(ctx context.Context, opts ...ExecOption) (map[string]string, error) {
	resp, err := c.Execute(ctx, OpFindRoots, opts...)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Close() }()

	dec := wire.NewDecoder(resp, MaxStringSize)

	roots, err := dec.ReadStringMap()
	if err != nil {
		return nil, &ProtocolError{Op: "FindRoots read response", Err: err}
	}

	return roots, nil
}

// NarFromPath returns the NAR serialisation of the given store path as a streaming reader.
// The caller must read the complete NAR and call Close before starting another operation.
//
// Use WithLogger to receive daemon log messages emitted before the NAR data.
func (c *Client) NarFromPath(ctx context.Context, path string, opts ...ExecOption,
) (r io.ReadCloser, err error) {
	execOpts, err := c.execOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to apply exec option: %w", err)
	}

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

	enc := wire.NewEncoder(c.w)

	// write operation code
	if err = enc.WriteUint64(uint64(OpNarFromPath)); err != nil {
		_ = unsetCancelDeadline()

		return nil, &ProtocolError{Op: "NarFromPath write op", Err: err}
	}

	// write request payload
	if err = enc.WriteString(path); err != nil {
		_ = unsetCancelDeadline()

		return nil, &ProtocolError{Op: "NarFromPath write request", Err: err}
	}

	// flush buffered writer
	if err = c.w.Flush(); err != nil {
		_ = unsetCancelDeadline()

		return nil, &ProtocolError{Op: "NarFromPath flush", Err: err}
	}

	// drain stderr log messages until LogLast
	if err = ProcessStderr(c.r, execOpts.Logger, c.info.Version); err != nil {
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

// drainNAR reads one complete NAR archive from r using nar.Reader, consuming all entries and file content until EOF.
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

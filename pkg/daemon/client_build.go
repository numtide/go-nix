package daemon

import (
	"bytes"
	"context"

	"github.com/nix-community/go-nix/pkg/wire"
)

// BuildPaths asks the daemon to build the given set of derivation paths or
// store paths. mode controls rebuild behaviour.
func (c *Client) BuildPaths(ctx context.Context, paths []string, mode BuildMode) error {
	var buf bytes.Buffer

	if err := wire.WriteStrings(&buf, paths); err != nil {
		return &ProtocolError{Op: "BuildPaths write request", Err: err}
	}

	if err := wire.WriteUint64(&buf, uint64(mode)); err != nil {
		return &ProtocolError{Op: "BuildPaths write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpBuildPaths, &buf)
	if err != nil {
		return err
	}
	defer resp.Close()

	return readAck(resp)
}

// BuildPathsWithResults is like BuildPaths but returns a BuildResult for each
// derived path. Requires protocol >= 1.34.
func (c *Client) BuildPathsWithResults(ctx context.Context, paths []string, mode BuildMode) ([]BuildResult, error) {
	if err := c.requireVersion(OpBuildPathsWithResults, ProtoVersionBuildPathsWithResults); err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	if err := wire.WriteStrings(&buf, paths); err != nil {
		return nil, &ProtocolError{Op: "BuildPathsWithResults write request", Err: err}
	}

	if err := wire.WriteUint64(&buf, uint64(mode)); err != nil {
		return nil, &ProtocolError{Op: "BuildPathsWithResults write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpBuildPathsWithResults, &buf)
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	count, err := wire.ReadUint64(resp)
	if err != nil {
		return nil, &ProtocolError{Op: "BuildPathsWithResults read response", Err: err}
	}

	results := make([]BuildResult, count)

	for i := range count {
		// each entry is a DerivedPath string (ignored) followed by a BuildResult.
		_, err := wire.ReadString(resp, MaxStringSize)
		if err != nil {
			return nil, &ProtocolError{Op: "BuildPathsWithResults read response", Err: err}
		}

		br, err := ReadBuildResult(resp, c.info.Version)
		if err != nil {
			return nil, &ProtocolError{Op: "BuildPathsWithResults read response", Err: err}
		}

		results[i] = *br
	}

	return results, nil
}

// EnsurePath ensures that the given store path is valid by building or
// substituting it if necessary.
func (c *Client) EnsurePath(ctx context.Context, path string) error {
	var buf bytes.Buffer
	if err := wire.WriteString(&buf, path); err != nil {
		return &ProtocolError{Op: "EnsurePath write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpEnsurePath, &buf)
	if err != nil {
		return err
	}
	defer resp.Close()

	return readAck(resp)
}

// BuildDerivation builds a derivation given its store path and definition.
// The derivation is serialized as a BasicDerivation on the wire, and mode
// controls rebuild behaviour.
func (c *Client) BuildDerivation(
	ctx context.Context, drvPath string, drv *BasicDerivation, mode BuildMode,
) (*BuildResult, error) {
	if drv == nil {
		return nil, ErrNilDerivation
	}

	var buf bytes.Buffer

	if err := wire.WriteString(&buf, drvPath); err != nil {
		return nil, &ProtocolError{Op: "BuildDerivation write request", Err: err}
	}

	if err := WriteBasicDerivation(&buf, drv); err != nil {
		return nil, &ProtocolError{Op: "BuildDerivation write request", Err: err}
	}

	if err := wire.WriteUint64(&buf, uint64(mode)); err != nil {
		return nil, &ProtocolError{Op: "BuildDerivation write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpBuildDerivation, &buf)
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	return ReadBuildResult(resp, c.info.Version)
}

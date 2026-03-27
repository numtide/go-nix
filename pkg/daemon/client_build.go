package daemon

import (
	"context"

	"github.com/nix-community/go-nix/pkg/wire"
)

// BuildPaths asks the daemon to build the given set of derivation paths or
// store paths. mode controls rebuild behaviour.
func (c *Client) BuildPaths(ctx context.Context, paths []string, mode BuildMode) error {
	resp, err := c.Execute(ctx, OpBuildPaths, func(enc *wire.Encoder) error {
		if err := enc.WriteStrings(paths); err != nil {
			return err
		}

		return enc.WriteUint64(uint64(mode))
	})
	if err != nil {
		return err
	}
	defer resp.Close()

	return readAck(wire.NewDecoder(resp, MaxStringSize))
}

// BuildPathsWithResults is like BuildPaths but returns a BuildResult for each
// derived path. Requires protocol >= 1.34.
func (c *Client) BuildPathsWithResults(ctx context.Context, paths []string, mode BuildMode) ([]BuildResult, error) {
	if err := c.requireVersion(OpBuildPathsWithResults, ProtoVersionBuildPathsWithResults); err != nil {
		return nil, err
	}

	resp, err := c.Execute(ctx, OpBuildPathsWithResults, func(enc *wire.Encoder) error {
		if err := enc.WriteStrings(paths); err != nil {
			return err
		}

		return enc.WriteUint64(uint64(mode))
	})
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	dec := wire.NewDecoder(resp, MaxStringSize)

	count, err := dec.ReadUint64()
	if err != nil {
		return nil, &ProtocolError{Op: "BuildPathsWithResults read response", Err: err}
	}

	results := make([]BuildResult, count)

	for i := range count {
		// each entry is a DerivedPath string (ignored) followed by a BuildResult.
		_, err := dec.ReadString()
		if err != nil {
			return nil, &ProtocolError{Op: "BuildPathsWithResults read response", Err: err}
		}

		br, err := ReadBuildResult(dec, c.info.Version)
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
	resp, err := c.Execute(ctx, OpEnsurePath, func(enc *wire.Encoder) error {
		return enc.WriteString(path)
	})
	if err != nil {
		return err
	}
	defer resp.Close()

	return readAck(wire.NewDecoder(resp, MaxStringSize))
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

	resp, err := c.Execute(ctx, OpBuildDerivation, func(enc *wire.Encoder) error {
		if err := enc.WriteString(drvPath); err != nil {
			return err
		}

		if err := WriteBasicDerivation(enc, drv); err != nil {
			return err
		}

		return enc.WriteUint64(uint64(mode))
	})
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	dec := wire.NewDecoder(resp, MaxStringSize)

	return ReadBuildResult(dec, c.info.Version)
}

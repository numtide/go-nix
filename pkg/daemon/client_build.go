package daemon

import (
	"context"
	"io"

	"github.com/nix-community/go-nix/pkg/wire"
)

// BuildPaths asks the daemon to build the given set of derivation paths or
// store paths. mode controls rebuild behaviour.
func (c *Client) BuildPaths(ctx context.Context, paths []string, mode BuildMode) error {
	return c.doOp(ctx, OpBuildPaths,
		func(w io.Writer) error {
			if err := WriteStrings(w, paths); err != nil {
				return err
			}

			return wire.WriteUint64(w, uint64(mode))
		},
		func(r io.Reader) error {
			return readAck(r)
		},
	)
}

// BuildPathsWithResults is like BuildPaths but returns a BuildResult for each
// derived path. Requires protocol >= 1.34.
func (c *Client) BuildPathsWithResults(ctx context.Context, paths []string, mode BuildMode) ([]BuildResult, error) {
	if err := c.requireVersion(OpBuildPathsWithResults, ProtoVersionBuildPathsWithResults); err != nil {
		return nil, err
	}

	var results []BuildResult

	err := c.doOp(ctx, OpBuildPathsWithResults,
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

				br, err := ReadBuildResult(r, c.info.Version)
				if err != nil {
					return err
				}

				results[i] = *br
			}

			return nil
		},
	)

	return results, err
}

// EnsurePath ensures that the given store path is valid by building or
// substituting it if necessary.
func (c *Client) EnsurePath(ctx context.Context, path string) error {
	return c.doOp(ctx, OpEnsurePath,
		func(w io.Writer) error {
			return wire.WriteString(w, path)
		},
		func(r io.Reader) error {
			return readAck(r)
		},
	)
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

	var result *BuildResult

	err := c.doOp(ctx, OpBuildDerivation,
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
			br, err := ReadBuildResult(r, c.info.Version)
			if err != nil {
				return err
			}

			result = br

			return nil
		},
	)

	return result, err
}

package daemon

import (
	"context"

	"github.com/nix-community/go-nix/pkg/wire"
)

// BuildPaths asks the daemon to build the given set of derivation paths or store paths.
// mode controls rebuild behaviour.
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

// BuildPathsWithResults is like BuildPaths but returns a BuildResult for each derived path.
// Requires protocol >= 1.34.
func (c *Client) BuildPathsWithResults(ctx context.Context, paths []string, mode BuildMode) ([]BuildResult, error) {
	// version check
	if err := c.requireVersion(OpBuildPathsWithResults, ProtoVersionBuildPathsWithResults); err != nil {
		return nil, err
	}

	// send request
	resp, err := c.Execute(ctx, OpBuildPathsWithResults, func(enc *wire.Encoder) error {
		if err := enc.WriteStrings(paths); err != nil {
			return err
		}

		return enc.WriteUint64(uint64(mode))
	})
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Close() }()

	// process the response
	dec := wire.NewDecoder(resp, MaxStringSize)

	// get a count of the build results
	count, err := dec.ReadUint64()
	if err != nil {
		return nil, &ProtocolError{Op: "BuildPathsWithResults read response", Err: err}
	}

	// drain the build results
	// each entry is a DerivedPath string (ignored) followed by a BuildResult.
	results := make([]BuildResult, count)

	for i := range count {
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

// EnsurePath ensures that the given store path is valid by building or substituting it if necessary.
func (c *Client) EnsurePath(ctx context.Context, path string) error {
	resp, err := c.Execute(ctx, OpEnsurePath, func(enc *wire.Encoder) error {
		return enc.WriteString(path)
	})
	if err != nil {
		return err
	}

	defer func() { _ = resp.Close() }()

	return readAck(wire.NewDecoder(resp, MaxStringSize))
}

// BuildDerivation executes the BuildDerivation operation with the given request and context.
// It returns the build result or an error if the operation fails.
func (c *Client) BuildDerivation(ctx context.Context, req *BuildDerivationRequest) (*BuildResult, error) {
	// nil check
	if req.Derivation == nil {
		return nil, ErrNilDerivation
	}

	// send the args
	resp, err := c.Execute(ctx, OpBuildDerivation, req.MarshalNix)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Close() }()

	// process the result
	dec := wire.NewDecoder(resp, MaxStringSize)

	return ReadBuildResult(dec, c.info.Version)
}

package daemon

import (
	"context"
	"encoding/json"
	"io"

	"github.com/nix-community/go-nix/pkg/storepath"
	"github.com/nix-community/go-nix/pkg/wire"
)

// AddToStore imports content into the store using content-addressing. The daemon
// computes the store path from the provided data, content-address method, and
// hash algorithm. This differs from AddToStoreNar where the caller already knows
// the full PathInfo.
//
// The name parameter is the derivation name (e.g. "hello-2.12.1").
// The caMethodWithAlgo parameter specifies the content-address method and hash
// algorithm as a combined string:
//   - "fixed:sha256"     — flat file, SHA256
//   - "fixed:r:sha256"   — recursive (NAR), SHA256
//   - "text:sha256"      — text hashing, SHA256
//   - "fixed:git:sha256" — git hashing, SHA256
//
// The source provides the data to import (raw bytes for flat, NAR for recursive).
// Returns the PathInfo computed by the daemon. Requires protocol >= 1.25.
func (c *Client) AddToStore(ctx context.Context, req *AddToStoreRequest) (*PathInfo, error) {
	if req.Source == nil {
		return nil, ErrNilReader
	}

	if err := c.requireVersion(OpAddToStore, ProtoVersionAddToStore); err != nil {
		return nil, err
	}

	resp, err := c.Execute(ctx, OpAddToStore, req.MarshalNix)
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	dec := wire.NewDecoder(resp, MaxStringSize)

	// read response: ValidPathInfo = storePath + UnkeyedValidPathInfo.
	storePath, err := dec.ReadString()
	if err != nil {
		return nil, &ProtocolError{Op: "AddToStore read storePath", Err: err}
	}

	return ReadPathInfo(dec, storePath, c.info.Version)
}

// AddTempRoot adds a temporary GC root for the given store path. Temporary
// roots prevent the garbage collector from deleting the path for the duration
// of the daemon session.
func (c *Client) AddTempRoot(ctx context.Context, path string) error {
	resp, err := c.Execute(ctx, OpAddTempRoot, func(enc *wire.Encoder) error {
		return enc.WriteString(path)
	})
	if err != nil {
		return err
	}
	defer resp.Close()

	return readAck(wire.NewDecoder(resp, MaxStringSize))
}

// AddIndirectRoot adds an indirect GC root. The path should be a symlink
// outside the store that points to a store path.
func (c *Client) AddIndirectRoot(ctx context.Context, path string) error {
	resp, err := c.Execute(ctx, OpAddIndirectRoot, func(enc *wire.Encoder) error {
		return enc.WriteString(path)
	})
	if err != nil {
		return err
	}
	defer resp.Close()

	return readAck(wire.NewDecoder(resp, MaxStringSize))
}

// AddPermRoot adds a permanent GC root linking gcRoot to storePath. Returns
// the resulting root path. Requires protocol >= 1.36.
func (c *Client) AddPermRoot(ctx context.Context, storePath string, gcRoot string) (string, error) {
	if err := c.requireVersion(OpAddPermRoot, ProtoVersionAddPermRoot); err != nil {
		return "", err
	}

	resp, err := c.Execute(ctx, OpAddPermRoot, func(enc *wire.Encoder) error {
		if err := enc.WriteString(storePath); err != nil {
			return err
		}

		return enc.WriteString(gcRoot)
	})
	if err != nil {
		return "", err
	}
	defer resp.Close()

	dec := wire.NewDecoder(resp, MaxStringSize)

	resultPath, err := dec.ReadString()
	if err != nil {
		return "", &ProtocolError{Op: "AddPermRoot read response", Err: err}
	}

	return resultPath, nil
}

// AddSignatures attaches the given signatures to a store path.
func (c *Client) AddSignatures(ctx context.Context, path string, sigs []string) error {
	resp, err := c.Execute(ctx, OpAddSignatures, func(enc *wire.Encoder) error {
		if err := enc.WriteString(path); err != nil {
			return err
		}

		return enc.WriteStrings(sigs)
	})
	if err != nil {
		return err
	}
	defer resp.Close()

	return readAck(wire.NewDecoder(resp, MaxStringSize))
}

// RegisterDrvOutput registers a content-addressed realisation for a
// derivation output. Requires protocol >= 1.31.
func (c *Client) RegisterDrvOutput(ctx context.Context, realisation *Realisation) error {
	if realisation == nil {
		return ErrNilRealisation
	}

	if err := c.requireVersion(OpRegisterDrvOutput, ProtoVersionRealisationJSON); err != nil {
		return err
	}

	data, err := json.Marshal(realisation)
	if err != nil {
		return &ProtocolError{Op: "RegisterDrvOutput marshal JSON", Err: err}
	}

	resp, err := c.Execute(ctx, OpRegisterDrvOutput, func(enc *wire.Encoder) error {
		return enc.WriteString(string(data))
	})
	if err != nil {
		return err
	}

	return resp.Close()
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

	resp, err := c.Execute(ctx, OpAddToStoreNar, func(enc *wire.Encoder) error {
		if err := WritePathInfo(enc, info, c.info.Version); err != nil {
			return err
		}

		if err := enc.WriteBool(repair); err != nil {
			return err
		}

		if err := enc.WriteBool(dontCheckSigs); err != nil {
			return err
		}

		// stream NAR data as framed.
		fw := NewFramedWriter(enc.Writer())
		if _, err := io.Copy(fw, source); err != nil {
			return err
		}

		return fw.Close()
	})
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

	// parse and validate the store path, then send as BaseStorePath (basename only).
	sp, err := storepath.FromAbsolutePath(drvPath)
	if err != nil {
		return &ProtocolError{Op: "AddBuildLog validate drvPath", Err: err}
	}

	resp, err := c.Execute(ctx, OpAddBuildLog, func(enc *wire.Encoder) error {
		if err := enc.WriteString(sp.String()); err != nil {
			return err
		}

		// stream log data as framed.
		fw := NewFramedWriter(enc.Writer())
		if _, err := io.Copy(fw, log); err != nil {
			return err
		}

		return fw.Close()
	})
	if err != nil {
		return err
	}
	defer resp.Close()

	return readAck(wire.NewDecoder(resp, MaxStringSize))
}

// CollectGarbage performs a garbage collection operation on the store.
func (c *Client) CollectGarbage(ctx context.Context, options *GCOptions) (*GCResult, error) {
	if options == nil {
		return nil, ErrNilOptions
	}

	resp, err := c.Execute(ctx, OpCollectGarbage, options.MarshalNix)
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	var result GCResult

	dec := wire.NewDecoder(resp, MaxStringSize)
	if err := dec.Decode(&result); err != nil {
		return nil, &ProtocolError{Op: "CollectGarbage read response", Err: err}
	}

	return &result, nil
}

// OptimiseStore asks the daemon to optimise the Nix store by hard-linking
// identical files.
func (c *Client) OptimiseStore(ctx context.Context) error {
	resp, err := c.Execute(ctx, OpOptimiseStore, nil)
	if err != nil {
		return err
	}
	defer resp.Close()

	return readAck(wire.NewDecoder(resp, MaxStringSize))
}

// VerifyStore checks the consistency of the Nix store. If checkContents is
// true, the contents of each path are verified against their hash. If repair
// is true, inconsistencies are repaired. Returns true if errors were found.
func (c *Client) VerifyStore(ctx context.Context, checkContents bool, repair bool) (bool, error) {
	resp, err := c.Execute(ctx, OpVerifyStore, func(enc *wire.Encoder) error {
		if err := enc.WriteBool(checkContents); err != nil {
			return err
		}

		return enc.WriteBool(repair)
	})
	if err != nil {
		return false, err
	}
	defer resp.Close()

	dec := wire.NewDecoder(resp, MaxStringSize)

	errorsFound, err := dec.ReadBool()
	if err != nil {
		return false, &ProtocolError{Op: "VerifyStore read response", Err: err}
	}

	return errorsFound, nil
}

// SetOptions sends the client build settings to the daemon. This should
// typically be called once after connecting.
func (c *Client) SetOptions(ctx context.Context, settings *ClientSettings) error {
	resp, err := c.Execute(ctx, OpSetOptions, func(enc *wire.Encoder) error {
		return WriteClientSettings(enc, settings, c.info.Version)
	})
	if err != nil {
		return err
	}

	return resp.Close()
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

	for i := range len(items) {
		if items[i].Source == nil {
			return ErrNilReader
		}
	}

	resp, err := c.Execute(ctx, OpAddMultipleToStore, func(enc *wire.Encoder) error {
		// structured header (outside framed stream).
		if err := enc.WriteBool(repair); err != nil {
			return err
		}

		if err := enc.WriteBool(dontCheckSigs); err != nil {
			return err
		}

		// create a single FramedWriter that wraps all item data.
		fw := NewFramedWriter(enc.Writer())

		// write count inside the framed stream.
		fwEnc := wire.NewEncoder(fw)
		if err := fwEnc.WriteUint64(uint64(len(items))); err != nil {
			return err
		}

		// write each item: PathInfo + NAR data, all inside the framed stream.
		for i := range len(items) {
			if err := WritePathInfo(fwEnc, &items[i].Info, c.info.Version); err != nil {
				return err
			}

			if _, err := io.Copy(fw, items[i].Source); err != nil {
				return err
			}
		}

		return fw.Close()
	})
	if err != nil {
		return err
	}

	return resp.Close()
}

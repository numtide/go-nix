package daemon

import (
	"bytes"
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
func (c *Client) AddToStore(
	ctx context.Context,
	name string,
	caMethodWithAlgo string,
	references []string,
	repair bool,
	source io.Reader,
) (*PathInfo, error) {
	if source == nil {
		return nil, ErrNilReader
	}

	if err := c.requireVersion(OpAddToStore, ProtoVersionAddToStore); err != nil {
		return nil, err
	}

	var hdr bytes.Buffer

	if err := wire.WriteString(&hdr, name); err != nil {
		return nil, &ProtocolError{Op: "AddToStore write name", Err: err}
	}

	if err := wire.WriteString(&hdr, caMethodWithAlgo); err != nil {
		return nil, &ProtocolError{Op: "AddToStore write caMethodWithAlgo", Err: err}
	}

	if err := wire.WriteStrings(&hdr, references); err != nil {
		return nil, &ProtocolError{Op: "AddToStore write references", Err: err}
	}

	if err := wire.WriteBool(&hdr, repair); err != nil {
		return nil, &ProtocolError{Op: "AddToStore write repair", Err: err}
	}

	resp, err := c.Execute(ctx, OpAddToStore, io.MultiReader(&hdr, NewFramingReader(source)))
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	// read response: ValidPathInfo = storePath + UnkeyedValidPathInfo.
	storePath, err := wire.ReadString(resp, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "AddToStore read storePath", Err: err}
	}

	return ReadPathInfo(resp, storePath, c.info.Version)
}

// AddTempRoot adds a temporary GC root for the given store path. Temporary
// roots prevent the garbage collector from deleting the path for the duration
// of the daemon session.
func (c *Client) AddTempRoot(ctx context.Context, path string) error {
	var buf bytes.Buffer
	if err := wire.WriteString(&buf, path); err != nil {
		return &ProtocolError{Op: "AddTempRoot write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpAddTempRoot, &buf)
	if err != nil {
		return err
	}
	defer resp.Close()

	return readAck(resp)
}

// AddIndirectRoot adds an indirect GC root. The path should be a symlink
// outside the store that points to a store path.
func (c *Client) AddIndirectRoot(ctx context.Context, path string) error {
	var buf bytes.Buffer
	if err := wire.WriteString(&buf, path); err != nil {
		return &ProtocolError{Op: "AddIndirectRoot write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpAddIndirectRoot, &buf)
	if err != nil {
		return err
	}
	defer resp.Close()

	return readAck(resp)
}

// AddPermRoot adds a permanent GC root linking gcRoot to storePath. Returns
// the resulting root path. Requires protocol >= 1.36.
func (c *Client) AddPermRoot(ctx context.Context, storePath string, gcRoot string) (string, error) {
	if err := c.requireVersion(OpAddPermRoot, ProtoVersionAddPermRoot); err != nil {
		return "", err
	}

	var buf bytes.Buffer

	if err := wire.WriteString(&buf, storePath); err != nil {
		return "", &ProtocolError{Op: "AddPermRoot write request", Err: err}
	}

	if err := wire.WriteString(&buf, gcRoot); err != nil {
		return "", &ProtocolError{Op: "AddPermRoot write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpAddPermRoot, &buf)
	if err != nil {
		return "", err
	}
	defer resp.Close()

	resultPath, err := wire.ReadString(resp, MaxStringSize)
	if err != nil {
		return "", &ProtocolError{Op: "AddPermRoot read response", Err: err}
	}

	return resultPath, nil
}

// AddSignatures attaches the given signatures to a store path.
func (c *Client) AddSignatures(ctx context.Context, path string, sigs []string) error {
	var buf bytes.Buffer

	if err := wire.WriteString(&buf, path); err != nil {
		return &ProtocolError{Op: "AddSignatures write request", Err: err}
	}

	if err := wire.WriteStrings(&buf, sigs); err != nil {
		return &ProtocolError{Op: "AddSignatures write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpAddSignatures, &buf)
	if err != nil {
		return err
	}
	defer resp.Close()

	return readAck(resp)
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

	var buf bytes.Buffer
	if err := wire.WriteString(&buf, string(data)); err != nil {
		return &ProtocolError{Op: "RegisterDrvOutput write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpRegisterDrvOutput, &buf)
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

	var hdr bytes.Buffer

	if err := WritePathInfo(&hdr, info, c.info.Version); err != nil {
		return &ProtocolError{Op: "AddToStoreNar write path info", Err: err}
	}

	if err := wire.WriteBool(&hdr, repair); err != nil {
		return &ProtocolError{Op: "AddToStoreNar write repair", Err: err}
	}

	if err := wire.WriteBool(&hdr, dontCheckSigs); err != nil {
		return &ProtocolError{Op: "AddToStoreNar write dontCheckSigs", Err: err}
	}

	resp, err := c.Execute(ctx, OpAddToStoreNar, io.MultiReader(&hdr, NewFramingReader(source)))
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

	var hdr bytes.Buffer
	if err := wire.WriteString(&hdr, sp.String()); err != nil {
		return &ProtocolError{Op: "AddBuildLog write drvPath", Err: err}
	}

	resp, err := c.Execute(ctx, OpAddBuildLog, io.MultiReader(&hdr, NewFramingReader(log)))
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

	var buf bytes.Buffer

	if err := wire.WriteUint64(&buf, uint64(options.Action)); err != nil {
		return nil, &ProtocolError{Op: "CollectGarbage write request", Err: err}
	}

	if err := wire.WriteStrings(&buf, options.PathsToDelete); err != nil {
		return nil, &ProtocolError{Op: "CollectGarbage write request", Err: err}
	}

	if err := wire.WriteBool(&buf, options.IgnoreLiveness); err != nil {
		return nil, &ProtocolError{Op: "CollectGarbage write request", Err: err}
	}

	if err := wire.WriteUint64(&buf, options.MaxFreed); err != nil {
		return nil, &ProtocolError{Op: "CollectGarbage write request", Err: err}
	}

	// deprecated fields, always zero.
	for range numDeprecatedGCFields {
		if err := wire.WriteUint64(&buf, 0); err != nil {
			return nil, &ProtocolError{Op: "CollectGarbage write request", Err: err}
		}
	}

	resp, err := c.Execute(ctx, OpCollectGarbage, &buf)
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	var result GCResult

	result.Paths, err = wire.ReadStrings(resp, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "CollectGarbage read response", Err: err}
	}

	result.BytesFreed, err = wire.ReadUint64(resp)
	if err != nil {
		return nil, &ProtocolError{Op: "CollectGarbage read response", Err: err}
	}

	// deprecated field, ignored.
	_, err = wire.ReadUint64(resp)
	if err != nil {
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

	return readAck(resp)
}

// VerifyStore checks the consistency of the Nix store. If checkContents is
// true, the contents of each path are verified against their hash. If repair
// is true, inconsistencies are repaired. Returns true if errors were found.
func (c *Client) VerifyStore(ctx context.Context, checkContents bool, repair bool) (bool, error) {
	var buf bytes.Buffer

	if err := wire.WriteBool(&buf, checkContents); err != nil {
		return false, &ProtocolError{Op: "VerifyStore write request", Err: err}
	}

	if err := wire.WriteBool(&buf, repair); err != nil {
		return false, &ProtocolError{Op: "VerifyStore write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpVerifyStore, &buf)
	if err != nil {
		return false, err
	}
	defer resp.Close()

	errorsFound, err := wire.ReadBool(resp)
	if err != nil {
		return false, &ProtocolError{Op: "VerifyStore read response", Err: err}
	}

	return errorsFound, nil
}

// SetOptions sends the client build settings to the daemon. This should
// typically be called once after connecting.
func (c *Client) SetOptions(ctx context.Context, settings *ClientSettings) error {
	var buf bytes.Buffer
	if err := WriteClientSettings(&buf, settings, c.info.Version); err != nil {
		return &ProtocolError{Op: "SetOptions write request", Err: err}
	}

	resp, err := c.Execute(ctx, OpSetOptions, &buf)
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

	for i := range len(items) {
		if items[i].Source == nil {
			return ErrNilReader
		}
	}

	// structured header (outside framed stream).
	var hdr bytes.Buffer

	if err := wire.WriteBool(&hdr, repair); err != nil {
		return &ProtocolError{Op: "AddMultipleToStore write repair", Err: err}
	}

	if err := wire.WriteBool(&hdr, dontCheckSigs); err != nil {
		return &ProtocolError{Op: "AddMultipleToStore write dontCheckSigs", Err: err}
	}

	// build the framed content: count + interleaved PathInfo and NAR data.
	framedParts := make([]io.Reader, 0, 1+2*len(items))

	var countBuf bytes.Buffer
	if err := wire.WriteUint64(&countBuf, uint64(len(items))); err != nil {
		return &ProtocolError{Op: "AddMultipleToStore write count", Err: err}
	}

	framedParts = append(framedParts, &countBuf)

	for i := range len(items) {
		var piBuf bytes.Buffer
		if err := WritePathInfo(&piBuf, &items[i].Info, c.info.Version); err != nil {
			return &ProtocolError{Op: "AddMultipleToStore write path info", Err: err}
		}

		framedParts = append(framedParts, &piBuf, items[i].Source)
	}

	resp, err := c.Execute(ctx, OpAddMultipleToStore,
		io.MultiReader(&hdr, NewFramingReader(io.MultiReader(framedParts...))))
	if err != nil {
		return err
	}

	return resp.Close()
}

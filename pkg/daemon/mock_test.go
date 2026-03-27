package daemon_test

import (
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sort"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

type handler func(conn net.Conn) error

// mockDaemon handles the server side of the protocol for testing.
type mockDaemon struct {
	path     string
	handlers []handler
}

func newMockDaemon(t *testing.T) *mockDaemon {
	return newMockDaemonWithVersion(t, 0)
}

func newMockDaemonWithVersion(t *testing.T, version uint64) *mockDaemon {
	t.Helper()

	// listen for client connections on a test socket
	sock := filepath.Join(t.TempDir(), "daemon.sock")

	listenCfg := net.ListenConfig{}

	ln, err := listenCfg.Listen(t.Context(), "unix", sock)
	require.NoError(t, err)

	// ensure the listener gets cleaned up when the test is over
	t.Cleanup(func() { _ = ln.Close() })

	mock := &mockDaemon{path: sock}

	// set up an async routine to accept client connections and run the handlers
	eg := errgroup.Group{}

	eg.Go(func() error {
		// accept a client connection
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("failed to connection: %w", err)
		}

		// ensure the connection gets closed
		defer func() {
			_ = conn.Close()
		}()

		// perform the handshake
		handshake(conn, version)

		// run the registered handlers
		for _, h := range mock.handlers {
			if err := h(conn); err != nil {
				return err
			}
		}

		return nil
	})

	// clean up the server when the test is finished and ensure the handlers didn't return any errors
	t.Cleanup(func() {
		if err = eg.Wait(); err != nil {
			t.Fatalf("a mock daemon error occurred: %s", err)
		}
	})

	return mock
}

func (m *mockDaemon) onAccept(handlers ...handler) {
	m.handlers = handlers
}

func handshake(conn net.Conn, version uint64) {
	mockVersion := version
	if mockVersion == 0 {
		mockVersion = daemon.ProtocolVersion
	}

	dec := wire.NewDecoder(conn, 64*1024)
	enc := wire.NewEncoder(conn)

	_, _ = dec.ReadUint64() // read client magic

	_ = enc.WriteUint64(daemon.ServerMagic)
	_ = enc.WriteUint64(mockVersion)

	negotiated, _ := dec.ReadUint64() // negotiated version

	// feature exchange (>= 1.38)
	if negotiated >= daemon.ProtoVersionFeatureExchange {
		// read client features (string list: count + entries).
		_, _ = dec.ReadUint64() // count (0 = no features)

		// send empty daemon features.
		_ = enc.WriteUint64(0)
	}

	// cpu affinity (>= 1.14)
	if negotiated >= daemon.ProtoVersionCPUAffinity {
		_, _ = dec.ReadUint64()
	}

	// reserve space (>= 1.11)
	if negotiated >= daemon.ProtoVersionReserveSpace {
		_, _ = dec.ReadUint64()
	}

	// nix version string (>= 1.33)
	if negotiated >= daemon.ProtoVersionNixVersion {
		_ = enc.WriteString("nix (Nix) 2.24.0")
	}

	// trust level (>= 1.35)
	if negotiated >= daemon.ProtoVersionTrust {
		_ = enc.WriteUint64(1) // TrustTrusted
	}

	// post-handshake: daemon sends startWork/stopWork (STDERR_LAST).
	_ = enc.WriteUint64(uint64(daemon.LogLast))
}

func respondIsValidPath(valid bool) func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpIsValidPath) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpIsValidPath, op)
		}

		_, _ = dec.ReadString() // read path

		// send LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// send bool result
		_ = enc.WriteBool(valid)

		return nil
	}
}

func respondQueryPathInfo(info *daemon.PathInfo) func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpQueryPathInfo) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryPathInfo, op)
		}

		_, _ = dec.ReadString() // read path string

		// send LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// found = true
		_ = enc.WriteUint64(1)

		// PathInfo fields (UnkeyedValidPathInfo format)
		_ = enc.WriteString(info.Deriver)
		_ = enc.WriteString(info.NarHash)

		// references
		_ = enc.WriteUint64(uint64(len(info.References)))
		for _, ref := range info.References {
			_ = enc.WriteString(ref)
		}

		_ = enc.WriteUint64(info.RegistrationTime)
		_ = enc.WriteUint64(info.NarSize)
		_ = enc.WriteBool(info.Ultimate)

		// sigs
		_ = enc.WriteUint64(uint64(len(info.Sigs)))
		for _, sig := range info.Sigs {
			_ = enc.WriteString(sig)
		}

		_ = enc.WriteString(info.CA)

		return nil
	}
}

func respondQueryPathInfoNotFound() func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpQueryPathInfo) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryPathInfo, op)
		}

		_, _ = dec.ReadString() // read path string

		// send LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// found = false
		_ = enc.WriteUint64(0)

		return nil
	}
}

func respondSetOptions() func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpSetOptions) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpSetOptions, op)
		}

		// read all ClientSettings fields from the wire:
		_, _ = dec.ReadUint64() // keepFailed (bool)
		_, _ = dec.ReadUint64() // keepGoing (bool)
		_, _ = dec.ReadUint64() // tryFallback (bool)
		_, _ = dec.ReadUint64() // verbosity (uint64)
		_, _ = dec.ReadUint64() // maxBuildJobs (uint64)
		_, _ = dec.ReadUint64() // maxSilentTime (uint64)
		_, _ = dec.ReadUint64() // useBuildHook (bool, deprecated)
		_, _ = dec.ReadUint64() // buildVerbosity (uint64)
		_, _ = dec.ReadUint64() // logType (uint64, deprecated)
		_, _ = dec.ReadUint64() // printBuildTrace (uint64, deprecated)
		_, _ = dec.ReadUint64() // buildCores (uint64)
		_, _ = dec.ReadUint64() // useSubstitutes (bool)

		// read overrides map (protocol >= 1.12): count + key/value pairs
		count, _ := dec.ReadUint64()

		for range count {
			_, _ = dec.ReadString() // key
			_, _ = dec.ReadString() // value
		}

		// send LogLast (no response payload for SetOptions)
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		return nil
	}
}

func respondQueryAllValidPaths(paths []string) func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpQueryAllValidPaths) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryAllValidPaths, op)
		}

		// no request params

		// send LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// send response: count + strings
		_ = enc.WriteUint64(uint64(len(paths)))
		for _, p := range paths {
			_ = enc.WriteString(p)
		}

		return nil
	}
}

func respondQueryValidPaths(valid []string) func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpQueryValidPaths) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryValidPaths, op)
		}

		// read request: paths (count + strings)
		count, _ := dec.ReadUint64()
		for range count {
			_, _ = dec.ReadString()
		}

		// read substituteOk (bool) — protocol >= 1.27
		_, _ = dec.ReadUint64()

		// send LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// send response: count + strings
		_ = enc.WriteUint64(uint64(len(valid)))
		for _, p := range valid {
			_ = enc.WriteString(p)
		}

		return nil
	}
}

func respondQuerySubstitutablePaths(paths []string) func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpQuerySubstitutablePaths) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQuerySubstitutablePaths, op)
		}

		// read request: paths (count + strings)
		count, _ := dec.ReadUint64()
		for range count {
			_, _ = dec.ReadString()
		}

		// send LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// send response: count + strings
		_ = enc.WriteUint64(uint64(len(paths)))
		for _, p := range paths {
			_ = enc.WriteString(p)
		}

		return nil
	}
}

func respondQueryReferrers(referrers []string) func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpQueryReferrers) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryReferrers, op)
		}

		// read request: path string
		_, _ = dec.ReadString()

		// send LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// send response: count + strings
		_ = enc.WriteUint64(uint64(len(referrers)))
		for _, r := range referrers {
			_ = enc.WriteString(r)
		}

		return nil
	}
}

func respondQueryValidDerivers(derivers []string) func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpQueryValidDerivers) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryValidDerivers, op)
		}

		// read request: path string
		_, _ = dec.ReadString()

		// send LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// send response: count + strings
		_ = enc.WriteUint64(uint64(len(derivers)))
		for _, d := range derivers {
			_ = enc.WriteString(d)
		}

		return nil
	}
}

func respondQueryDerivationOutputMap(outputs map[string]string) func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpQueryDerivationOutputMap) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryDerivationOutputMap, op)
		}

		// read request: drvPath string
		_, _ = dec.ReadString()

		// send LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// send response: count + sorted key/value pairs
		keys := make([]string, 0, len(outputs))
		for k := range outputs {
			keys = append(keys, k)
		}

		sort.Strings(keys)

		_ = enc.WriteUint64(uint64(len(keys)))
		for _, k := range keys {
			_ = enc.WriteString(k)
			_ = enc.WriteString(outputs[k])
		}

		return nil
	}
}

func respondQueryMissing(info *daemon.MissingInfo) func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpQueryMissing) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryMissing, op)
		}

		// read request: paths (count + strings)
		count, _ := dec.ReadUint64()
		for range count {
			_, _ = dec.ReadString()
		}

		// send LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// send response: willBuild, willSubstitute, unknown, downloadSize, narSize
		// willBuild
		_ = enc.WriteUint64(uint64(len(info.WillBuild)))
		for _, p := range info.WillBuild {
			_ = enc.WriteString(p)
		}

		// willSubstitute
		_ = enc.WriteUint64(uint64(len(info.WillSubstitute)))
		for _, p := range info.WillSubstitute {
			_ = enc.WriteString(p)
		}

		// unknown
		_ = enc.WriteUint64(uint64(len(info.Unknown)))
		for _, p := range info.Unknown {
			_ = enc.WriteString(p)
		}

		// downloadSize
		_ = enc.WriteUint64(info.DownloadSize)

		// narSize
		_ = enc.WriteUint64(info.NarSize)

		return nil
	}
}

func respondQueryPathFromHashPart(path string) func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpQueryPathFromHashPart) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryPathFromHashPart, op)
		}

		// read request: hashPart string
		_, _ = dec.ReadString()

		// send LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// send response: path string
		_ = enc.WriteString(path)

		return nil
	}
}

func respondCollectGarbage(result *daemon.GCResult) func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpCollectGarbage) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpCollectGarbage, op)
		}

		// read request: action (uint64)
		_, _ = dec.ReadUint64()

		// read pathsToDelete (count + strings)
		count, _ := dec.ReadUint64()
		for range count {
			_, _ = dec.ReadString()
		}

		// read ignoreLiveness (bool)
		_, _ = dec.ReadUint64()

		// read maxFreed (uint64)
		_, _ = dec.ReadUint64()

		// read 3 deprecated fields
		_, _ = dec.ReadUint64()
		_, _ = dec.ReadUint64()
		_, _ = dec.ReadUint64()

		// send LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// send response: paths (count + strings)
		_ = enc.WriteUint64(uint64(len(result.Paths)))
		for _, p := range result.Paths {
			_ = enc.WriteString(p)
		}

		// bytesFreed
		_ = enc.WriteUint64(result.BytesFreed)

		// deprecated field
		_ = enc.WriteUint64(0)

		return nil
	}
}

func respondVerifyStore(errorsFound bool) func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpVerifyStore) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpVerifyStore, op)
		}

		// read request: checkContents (bool) + repair (bool)
		_, _ = dec.ReadUint64() // checkContents
		_, _ = dec.ReadUint64() // repair

		// send LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// send response: errorsFound (bool)
		_ = enc.WriteBool(errorsFound)

		return nil
	}
}

func respondOptimiseStore() func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpOptimiseStore) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpOptimiseStore, op)
		}

		// no request params

		// send LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// send response: uint64 acknowledgment
		_ = enc.WriteUint64(1)

		return nil
	}
}

func respondQueryRealisation(realisations []string) func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpQueryRealisation) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryRealisation, op)
		}

		// read request: outputID string
		_, _ = dec.ReadString()

		// send LogLast
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// send response: count + strings
		_ = enc.WriteUint64(uint64(len(realisations)))
		for _, r := range realisations {
			_ = enc.WriteString(r)
		}

		return nil
	}
}

func respondQuerySubstitutablePathInfos(infos map[string]*daemon.SubstitutablePathInfo) func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpQuerySubstitutablePathInfos) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQuerySubstitutablePathInfos, op)
		}

		// read StorePathCAMap: count + (storePath + ca) pairs.
		count, _ := dec.ReadUint64()
		for range count {
			_, _ = dec.ReadString() // storePath
			_, _ = dec.ReadString() // ca (optional, empty string for none)
		}

		// send LogLast.
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// send response: count + entries.
		_ = enc.WriteUint64(uint64(len(infos)))

		for path, info := range infos {
			_ = enc.WriteString(path)
			_ = enc.WriteString(info.Deriver)

			// references.
			_ = enc.WriteUint64(uint64(len(info.References)))
			for _, ref := range info.References {
				_ = enc.WriteString(ref)
			}

			_ = enc.WriteUint64(info.DownloadSize)
			_ = enc.WriteUint64(info.NarSize)
		}

		return nil
	}
}

func respondAddToStore(info *daemon.PathInfo) func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(daemon.OpAddToStore) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpAddToStore, op)
		}

		// read request fields: name, caMethodWithAlgo, references, repair.
		_, _ = dec.ReadString() // name
		_, _ = dec.ReadString() // caMethodWithAlgo

		// read references (count + strings).
		count, _ := dec.ReadUint64()
		for range count {
			_, _ = dec.ReadString()
		}

		_, _ = dec.ReadUint64() // repair

		// read framed dump data (no padding in framed protocol).
		fr := daemon.NewFramedReader(conn)
		_, _ = io.ReadAll(fr)

		// send LogLast.
		_ = enc.WriteUint64(uint64(daemon.LogLast))

		// send response: ValidPathInfo = storePath + UnkeyedValidPathInfo.
		_ = enc.WriteString(info.StorePath)
		_ = enc.WriteString(info.Deriver)
		_ = enc.WriteString(info.NarHash)

		// references.
		_ = enc.WriteUint64(uint64(len(info.References)))
		for _, ref := range info.References {
			_ = enc.WriteString(ref)
		}

		_ = enc.WriteUint64(info.RegistrationTime)
		_ = enc.WriteUint64(info.NarSize)
		_ = enc.WriteBool(info.Ultimate)

		// sigs.
		_ = enc.WriteUint64(uint64(len(info.Sigs)))
		for _, sig := range info.Sigs {
			_ = enc.WriteString(sig)
		}

		_ = enc.WriteString(info.CA)

		return nil
	}
}

// respondWithError reads an op code and drains the request data using the
// provided drain function, then sends a LogError response with the given
// daemon.Error fields.
func respondWithError(expectedOp daemon.Operation, drain func(net.Conn), de *daemon.Error) func(net.Conn) error {
	return func(conn net.Conn) error {
		dec := wire.NewDecoder(conn, 64*1024)
		enc := wire.NewEncoder(conn)

		op, _ := dec.ReadUint64()
		if op != uint64(expectedOp) {
			return fmt.Errorf("expected op %d, got %d", expectedOp, op)
		}

		if drain != nil {
			drain(conn)
		}

		// send LogError instead of LogLast
		_ = enc.WriteUint64(uint64(daemon.LogError))

		// error payload: Type, Level, Name, Message, HavePos, NrTraces, traces...
		_ = enc.WriteString(de.Type)
		_ = enc.WriteUint64(de.Level)
		_ = enc.WriteString(de.Name)
		_ = enc.WriteString(de.Message)

		_ = enc.WriteUint64(0) // HavePos = 0

		_ = enc.WriteUint64(uint64(len(de.Traces)))
		for _, tr := range de.Traces {
			_ = enc.WriteUint64(tr.HavePos)
			_ = enc.WriteString(tr.Message)
		}

		return nil
	}
}

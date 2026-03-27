package daemon_test

import (
	"encoding/binary"
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

	var buf [8]byte

	_, _ = io.ReadFull(conn, buf[:]) // read client magic

	binary.LittleEndian.PutUint64(buf[:], daemon.ServerMagic)
	_, _ = conn.Write(buf[:])

	binary.LittleEndian.PutUint64(buf[:], mockVersion)
	_, _ = conn.Write(buf[:])

	_, _ = io.ReadFull(conn, buf[:]) // negotiated version
	negotiated := binary.LittleEndian.Uint64(buf[:])

	// feature exchange (>= 1.38)
	if negotiated >= daemon.ProtoVersionFeatureExchange {
		// Read client features (string list: count + entries).
		_, _ = wire.ReadUint64(conn) // count (0 = no features)

		// Send empty daemon features.
		binary.LittleEndian.PutUint64(buf[:], 0)
		_, _ = conn.Write(buf[:])
	}

	// cpu affinity (>= 1.14)
	if negotiated >= daemon.ProtoVersionCPUAffinity {
		_, _ = io.ReadFull(conn, buf[:])
	}

	// reserve space (>= 1.11)
	if negotiated >= daemon.ProtoVersionReserveSpace {
		_, _ = io.ReadFull(conn, buf[:])
	}

	// nix version string (>= 1.33)
	if negotiated >= daemon.ProtoVersionNixVersion {
		writeWireStringTo(conn, "nix (Nix) 2.24.0")
	}

	// trust level (>= 1.35)
	if negotiated >= daemon.ProtoVersionTrust {
		binary.LittleEndian.PutUint64(buf[:], 1) // TrustTrusted
		_, _ = conn.Write(buf[:])
	}

	// Post-handshake: daemon sends startWork/stopWork (STDERR_LAST).
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = conn.Write(buf[:])
}

func respondIsValidPath(valid bool) func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpIsValidPath) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpIsValidPath, op)
		}

		_, _ = wire.ReadString(conn, 64*1024) // read path string

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send bool result
		if valid {
			binary.LittleEndian.PutUint64(buf[:], 1)
		} else {
			binary.LittleEndian.PutUint64(buf[:], 0)
		}

		_, _ = conn.Write(buf[:])

		return nil
	}
}

func respondQueryPathInfo(info *daemon.PathInfo) func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpQueryPathInfo) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryPathInfo, op)
		}

		_, _ = wire.ReadString(conn, 64*1024) // read path string

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// found = true
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = conn.Write(buf[:])

		// PathInfo fields (UnkeyedValidPathInfo format)
		writeWireStringTo(conn, info.Deriver)
		writeWireStringTo(conn, info.NarHash)

		// References
		binary.LittleEndian.PutUint64(buf[:], uint64(len(info.References)))
		_, _ = conn.Write(buf[:])

		for _, ref := range info.References {
			writeWireStringTo(conn, ref)
		}

		binary.LittleEndian.PutUint64(buf[:], info.RegistrationTime)
		_, _ = conn.Write(buf[:])

		binary.LittleEndian.PutUint64(buf[:], info.NarSize)
		_, _ = conn.Write(buf[:])

		if info.Ultimate {
			binary.LittleEndian.PutUint64(buf[:], 1)
		} else {
			binary.LittleEndian.PutUint64(buf[:], 0)
		}

		_, _ = conn.Write(buf[:])

		// Sigs
		binary.LittleEndian.PutUint64(buf[:], uint64(len(info.Sigs)))
		_, _ = conn.Write(buf[:])

		for _, sig := range info.Sigs {
			writeWireStringTo(conn, sig)
		}

		writeWireStringTo(conn, info.CA)

		return nil
	}
}

func respondQueryPathInfoNotFound() func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpQueryPathInfo) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryPathInfo, op)
		}

		_, _ = wire.ReadString(conn, 64*1024) // read path string

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// found = false
		binary.LittleEndian.PutUint64(buf[:], 0)
		_, _ = conn.Write(buf[:])

		return nil
	}
}

func respondSetOptions() func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpSetOptions) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpSetOptions, op)
		}

		// Read all ClientSettings fields from the wire:
		_, _ = io.ReadFull(conn, buf[:]) // keepFailed (bool)
		_, _ = io.ReadFull(conn, buf[:]) // keepGoing (bool)
		_, _ = io.ReadFull(conn, buf[:]) // tryFallback (bool)
		_, _ = io.ReadFull(conn, buf[:]) // verbosity (uint64)
		_, _ = io.ReadFull(conn, buf[:]) // maxBuildJobs (uint64)
		_, _ = io.ReadFull(conn, buf[:]) // maxSilentTime (uint64)
		_, _ = io.ReadFull(conn, buf[:]) // useBuildHook (bool, deprecated)
		_, _ = io.ReadFull(conn, buf[:]) // buildVerbosity (uint64)
		_, _ = io.ReadFull(conn, buf[:]) // logType (uint64, deprecated)
		_, _ = io.ReadFull(conn, buf[:]) // printBuildTrace (uint64, deprecated)
		_, _ = io.ReadFull(conn, buf[:]) // buildCores (uint64)
		_, _ = io.ReadFull(conn, buf[:]) // useSubstitutes (bool)

		// Read overrides map (protocol >= 1.12): count + key/value pairs
		_, _ = io.ReadFull(conn, buf[:]) // overrides count
		count := binary.LittleEndian.Uint64(buf[:])

		for range count {
			_, _ = wire.ReadString(conn, 64*1024) // key
			_, _ = wire.ReadString(conn, 64*1024) // value
		}

		// Send LogLast (no response payload for SetOptions)
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		return nil
	}
}

func respondQueryAllValidPaths(paths []string) func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpQueryAllValidPaths) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryAllValidPaths, op)
		}

		// No request params

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send response: count + strings
		binary.LittleEndian.PutUint64(buf[:], uint64(len(paths)))
		_, _ = conn.Write(buf[:])

		for _, p := range paths {
			writeWireStringTo(conn, p)
		}

		return nil
	}
}

func respondQueryValidPaths(valid []string) func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpQueryValidPaths) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryValidPaths, op)
		}

		// Read request: paths (count + strings)
		_, _ = io.ReadFull(conn, buf[:]) // count
		count := binary.LittleEndian.Uint64(buf[:])

		for range count {
			_, _ = wire.ReadString(conn, 64*1024)
		}

		// Read substituteOk (bool) — protocol >= 1.27
		_, _ = io.ReadFull(conn, buf[:])

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send response: count + strings
		binary.LittleEndian.PutUint64(buf[:], uint64(len(valid)))
		_, _ = conn.Write(buf[:])

		for _, p := range valid {
			writeWireStringTo(conn, p)
		}

		return nil
	}
}

func respondQuerySubstitutablePaths(paths []string) func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpQuerySubstitutablePaths) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQuerySubstitutablePaths, op)
		}

		// Read request: paths (count + strings)
		_, _ = io.ReadFull(conn, buf[:]) // count
		count := binary.LittleEndian.Uint64(buf[:])

		for range count {
			_, _ = wire.ReadString(conn, 64*1024)
		}

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send response: count + strings
		binary.LittleEndian.PutUint64(buf[:], uint64(len(paths)))
		_, _ = conn.Write(buf[:])

		for _, p := range paths {
			writeWireStringTo(conn, p)
		}

		return nil
	}
}

func respondQueryReferrers(referrers []string) func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpQueryReferrers) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryReferrers, op)
		}

		// Read request: path string
		_, _ = wire.ReadString(conn, 64*1024)

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send response: count + strings
		binary.LittleEndian.PutUint64(buf[:], uint64(len(referrers)))
		_, _ = conn.Write(buf[:])

		for _, r := range referrers {
			writeWireStringTo(conn, r)
		}

		return nil
	}
}

func respondQueryValidDerivers(derivers []string) func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpQueryValidDerivers) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryValidDerivers, op)
		}

		// Read request: path string
		_, _ = wire.ReadString(conn, 64*1024)

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send response: count + strings
		binary.LittleEndian.PutUint64(buf[:], uint64(len(derivers)))
		_, _ = conn.Write(buf[:])

		for _, d := range derivers {
			writeWireStringTo(conn, d)
		}

		return nil
	}
}

func respondQueryDerivationOutputMap(outputs map[string]string) func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpQueryDerivationOutputMap) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryDerivationOutputMap, op)
		}

		// Read request: drvPath string
		_, _ = wire.ReadString(conn, 64*1024)

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send response: count + sorted key/value pairs
		keys := make([]string, 0, len(outputs))
		for k := range outputs {
			keys = append(keys, k)
		}

		sort.Strings(keys)

		binary.LittleEndian.PutUint64(buf[:], uint64(len(keys)))
		_, _ = conn.Write(buf[:])

		for _, k := range keys {
			writeWireStringTo(conn, k)
			writeWireStringTo(conn, outputs[k])
		}

		return nil
	}
}

func respondQueryMissing(info *daemon.MissingInfo) func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpQueryMissing) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryMissing, op)
		}

		// Read request: paths (count + strings)
		_, _ = io.ReadFull(conn, buf[:]) // count
		count := binary.LittleEndian.Uint64(buf[:])

		for range count {
			_, _ = wire.ReadString(conn, 64*1024)
		}

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send response: willBuild, willSubstitute, unknown, downloadSize, narSize
		// willBuild
		binary.LittleEndian.PutUint64(buf[:], uint64(len(info.WillBuild)))
		_, _ = conn.Write(buf[:])

		for _, p := range info.WillBuild {
			writeWireStringTo(conn, p)
		}

		// willSubstitute
		binary.LittleEndian.PutUint64(buf[:], uint64(len(info.WillSubstitute)))
		_, _ = conn.Write(buf[:])

		for _, p := range info.WillSubstitute {
			writeWireStringTo(conn, p)
		}

		// unknown
		binary.LittleEndian.PutUint64(buf[:], uint64(len(info.Unknown)))
		_, _ = conn.Write(buf[:])

		for _, p := range info.Unknown {
			writeWireStringTo(conn, p)
		}

		// downloadSize
		binary.LittleEndian.PutUint64(buf[:], info.DownloadSize)
		_, _ = conn.Write(buf[:])

		// narSize
		binary.LittleEndian.PutUint64(buf[:], info.NarSize)
		_, _ = conn.Write(buf[:])

		return nil
	}
}

func respondQueryPathFromHashPart(path string) func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpQueryPathFromHashPart) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryPathFromHashPart, op)
		}

		// Read request: hashPart string
		_, _ = wire.ReadString(conn, 64*1024)

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send response: path string
		writeWireStringTo(conn, path)

		return nil
	}
}

func respondCollectGarbage(result *daemon.GCResult) func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpCollectGarbage) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpCollectGarbage, op)
		}

		// Read request: action (uint64)
		_, _ = io.ReadFull(conn, buf[:])

		// Read pathsToDelete (count + strings)
		_, _ = io.ReadFull(conn, buf[:]) // count
		count := binary.LittleEndian.Uint64(buf[:])

		for range count {
			_, _ = wire.ReadString(conn, 64*1024)
		}

		// Read ignoreLiveness (bool)
		_, _ = io.ReadFull(conn, buf[:])

		// Read maxFreed (uint64)
		_, _ = io.ReadFull(conn, buf[:])

		// Read 3 deprecated fields
		_, _ = io.ReadFull(conn, buf[:])
		_, _ = io.ReadFull(conn, buf[:])
		_, _ = io.ReadFull(conn, buf[:])

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send response: paths (count + strings)
		binary.LittleEndian.PutUint64(buf[:], uint64(len(result.Paths)))
		_, _ = conn.Write(buf[:])

		for _, p := range result.Paths {
			writeWireStringTo(conn, p)
		}

		// bytesFreed
		binary.LittleEndian.PutUint64(buf[:], result.BytesFreed)
		_, _ = conn.Write(buf[:])

		// deprecated field
		binary.LittleEndian.PutUint64(buf[:], 0)
		_, _ = conn.Write(buf[:])

		return nil
	}
}

func respondVerifyStore(errorsFound bool) func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpVerifyStore) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpVerifyStore, op)
		}

		// Read request: checkContents (bool) + repair (bool)
		_, _ = io.ReadFull(conn, buf[:]) // checkContents
		_, _ = io.ReadFull(conn, buf[:]) // repair

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send response: errorsFound (bool)
		if errorsFound {
			binary.LittleEndian.PutUint64(buf[:], 1)
		} else {
			binary.LittleEndian.PutUint64(buf[:], 0)
		}

		_, _ = conn.Write(buf[:])

		return nil
	}
}

func respondOptimiseStore() func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpOptimiseStore) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpOptimiseStore, op)
		}

		// No request params

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send response: uint64 acknowledgment
		binary.LittleEndian.PutUint64(buf[:], 1)
		_, _ = conn.Write(buf[:])

		return nil
	}
}

func respondQueryRealisation(realisations []string) func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpQueryRealisation) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQueryRealisation, op)
		}

		// Read request: outputID string
		_, _ = wire.ReadString(conn, 64*1024)

		// Send LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send response: count + strings
		binary.LittleEndian.PutUint64(buf[:], uint64(len(realisations)))
		_, _ = conn.Write(buf[:])

		for _, r := range realisations {
			writeWireStringTo(conn, r)
		}

		return nil
	}
}

func respondQuerySubstitutablePathInfos(infos map[string]*daemon.SubstitutablePathInfo) func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpQuerySubstitutablePathInfos) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpQuerySubstitutablePathInfos, op)
		}

		// Read StorePathCAMap: count + (storePath + ca) pairs.
		_, _ = io.ReadFull(conn, buf[:]) // count
		count := binary.LittleEndian.Uint64(buf[:])

		for range count {
			_, _ = wire.ReadString(conn, 64*1024) // storePath
			_, _ = wire.ReadString(conn, 64*1024) // ca (optional, empty string for none)
		}

		// Send LogLast.
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send response: count + entries.
		binary.LittleEndian.PutUint64(buf[:], uint64(len(infos)))
		_, _ = conn.Write(buf[:])

		for path, info := range infos {
			writeWireStringTo(conn, path)
			writeWireStringTo(conn, info.Deriver)

			// References.
			binary.LittleEndian.PutUint64(buf[:], uint64(len(info.References)))
			_, _ = conn.Write(buf[:])

			for _, ref := range info.References {
				writeWireStringTo(conn, ref)
			}

			binary.LittleEndian.PutUint64(buf[:], info.DownloadSize)
			_, _ = conn.Write(buf[:])

			binary.LittleEndian.PutUint64(buf[:], info.NarSize)
			_, _ = conn.Write(buf[:])
		}

		return nil
	}
}

func respondAddToStore(info *daemon.PathInfo) func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(daemon.OpAddToStore) {
			return fmt.Errorf("expected op %d, got %d", daemon.OpAddToStore, op)
		}

		// Read request fields: name, caMethodWithAlgo, references, repair.
		_, _ = wire.ReadString(conn, 64*1024) // name
		_, _ = wire.ReadString(conn, 64*1024) // caMethodWithAlgo

		// Read references (count + strings).
		_, _ = io.ReadFull(conn, buf[:]) // count
		count := binary.LittleEndian.Uint64(buf[:])

		for range count {
			_, _ = wire.ReadString(conn, 64*1024)
		}

		_, _ = io.ReadFull(conn, buf[:]) // repair

		// Read framed dump data (no padding in framed protocol).
		fr := daemon.NewFramedReader(conn)
		_, _ = io.ReadAll(fr)

		// Send LogLast.
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
		_, _ = conn.Write(buf[:])

		// Send response: ValidPathInfo = storePath + UnkeyedValidPathInfo.
		writeWireStringTo(conn, info.StorePath)
		writeWireStringTo(conn, info.Deriver)
		writeWireStringTo(conn, info.NarHash)

		// References.
		binary.LittleEndian.PutUint64(buf[:], uint64(len(info.References)))
		_, _ = conn.Write(buf[:])

		for _, ref := range info.References {
			writeWireStringTo(conn, ref)
		}

		binary.LittleEndian.PutUint64(buf[:], info.RegistrationTime)
		_, _ = conn.Write(buf[:])

		binary.LittleEndian.PutUint64(buf[:], info.NarSize)
		_, _ = conn.Write(buf[:])

		if info.Ultimate {
			binary.LittleEndian.PutUint64(buf[:], 1)
		} else {
			binary.LittleEndian.PutUint64(buf[:], 0)
		}

		_, _ = conn.Write(buf[:])

		// Sigs.
		binary.LittleEndian.PutUint64(buf[:], uint64(len(info.Sigs)))
		_, _ = conn.Write(buf[:])

		for _, sig := range info.Sigs {
			writeWireStringTo(conn, sig)
		}

		writeWireStringTo(conn, info.CA)

		return nil
	}
}

// respondWithError reads an op code and drains the request data using the
// provided drain function, then sends a LogError response with the given
// daemon.Error fields.
func respondWithError(expectedOp daemon.Operation, drain func(net.Conn), de *daemon.Error) func(net.Conn) error {
	return func(conn net.Conn) error {
		var buf [8]byte

		_, _ = io.ReadFull(conn, buf[:]) // read op code
		op := binary.LittleEndian.Uint64(buf[:])

		if op != uint64(expectedOp) {
			return fmt.Errorf("expected op %d, got %d", expectedOp, op)
		}

		if drain != nil {
			drain(conn)
		}

		// Send LogError instead of LogLast
		binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogError))
		_, _ = conn.Write(buf[:])

		// Error payload: Type, Level, Name, Message, HavePos, NrTraces, traces...
		writeWireStringTo(conn, de.Type)

		binary.LittleEndian.PutUint64(buf[:], de.Level)
		_, _ = conn.Write(buf[:])

		writeWireStringTo(conn, de.Name)
		writeWireStringTo(conn, de.Message)

		binary.LittleEndian.PutUint64(buf[:], 0) // HavePos = 0
		_, _ = conn.Write(buf[:])

		binary.LittleEndian.PutUint64(buf[:], uint64(len(de.Traces)))
		_, _ = conn.Write(buf[:])

		for _, tr := range de.Traces {
			binary.LittleEndian.PutUint64(buf[:], tr.HavePos)
			_, _ = conn.Write(buf[:])
			writeWireStringTo(conn, tr.Message)
		}

		return nil
	}
}

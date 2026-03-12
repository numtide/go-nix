package daemon_test

import (
	"encoding/binary"
	"io"
	"net"
	"sort"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/assert"
)

// mockDaemon handles the server side of the protocol for testing.
type mockDaemon struct {
	conn    net.Conn
	t       *testing.T
	version uint64 // 0 means use daemon.ProtocolVersion
}

func newMockDaemon(t *testing.T) (*mockDaemon, net.Conn) {
	server, client := net.Pipe()

	return &mockDaemon{conn: server, t: t}, client
}

func newMockDaemonWithVersion(t *testing.T, version uint64) (*mockDaemon, net.Conn) {
	server, client := net.Pipe()

	return &mockDaemon{conn: server, t: t, version: version}, client
}

func (m *mockDaemon) handshake() {
	mockVersion := m.version
	if mockVersion == 0 {
		mockVersion = daemon.ProtocolVersion
	}

	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read client magic

	binary.LittleEndian.PutUint64(buf[:], daemon.ServerMagic)
	_, _ = m.conn.Write(buf[:])

	binary.LittleEndian.PutUint64(buf[:], mockVersion)
	_, _ = m.conn.Write(buf[:])

	_, _ = io.ReadFull(m.conn, buf[:]) // negotiated version
	negotiated := binary.LittleEndian.Uint64(buf[:])

	// feature exchange (>= 1.38)
	if negotiated >= daemon.ProtoVersionFeatureExchange {
		// Read client features (string list: count + entries).
		_, _ = wire.ReadUint64(m.conn) // count (0 = no features)

		// Send empty daemon features.
		binary.LittleEndian.PutUint64(buf[:], 0)
		_, _ = m.conn.Write(buf[:])
	}

	// cpu affinity (>= 1.14)
	if negotiated >= daemon.ProtoVersionCPUAffinity {
		_, _ = io.ReadFull(m.conn, buf[:])
	}

	// reserve space (>= 1.11)
	if negotiated >= daemon.ProtoVersionReserveSpace {
		_, _ = io.ReadFull(m.conn, buf[:])
	}

	// nix version string (>= 1.33)
	if negotiated >= daemon.ProtoVersionNixVersion {
		writeWireStringTo(m.conn, "nix (Nix) 2.24.0")
	}

	// trust level (>= 1.35)
	if negotiated >= daemon.ProtoVersionTrust {
		binary.LittleEndian.PutUint64(buf[:], 1) // TrustTrusted
		_, _ = m.conn.Write(buf[:])
	}

	// Post-handshake: daemon sends startWork/stopWork (STDERR_LAST).
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])
}

func (m *mockDaemon) respondIsValidPath(valid bool) {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpIsValidPath), op)

	_, _ = wire.ReadString(m.conn, 64*1024) // read path string

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])

	// Send bool result
	if valid {
		binary.LittleEndian.PutUint64(buf[:], 1)
	} else {
		binary.LittleEndian.PutUint64(buf[:], 0)
	}

	_, _ = m.conn.Write(buf[:])
}

func (m *mockDaemon) respondQueryPathInfo(info *daemon.PathInfo) {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpQueryPathInfo), op)

	_, _ = wire.ReadString(m.conn, 64*1024) // read path string

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])

	// found = true
	binary.LittleEndian.PutUint64(buf[:], 1)
	_, _ = m.conn.Write(buf[:])

	// PathInfo fields (UnkeyedValidPathInfo format)
	writeWireStringTo(m.conn, info.Deriver)
	writeWireStringTo(m.conn, info.NarHash)

	// References
	binary.LittleEndian.PutUint64(buf[:], uint64(len(info.References)))
	_, _ = m.conn.Write(buf[:])

	for _, ref := range info.References {
		writeWireStringTo(m.conn, ref)
	}

	binary.LittleEndian.PutUint64(buf[:], info.RegistrationTime)
	_, _ = m.conn.Write(buf[:])

	binary.LittleEndian.PutUint64(buf[:], info.NarSize)
	_, _ = m.conn.Write(buf[:])

	if info.Ultimate {
		binary.LittleEndian.PutUint64(buf[:], 1)
	} else {
		binary.LittleEndian.PutUint64(buf[:], 0)
	}

	_, _ = m.conn.Write(buf[:])

	// Sigs
	binary.LittleEndian.PutUint64(buf[:], uint64(len(info.Sigs)))
	_, _ = m.conn.Write(buf[:])

	for _, sig := range info.Sigs {
		writeWireStringTo(m.conn, sig)
	}

	writeWireStringTo(m.conn, info.CA)
}

func (m *mockDaemon) respondQueryPathInfoNotFound() {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpQueryPathInfo), op)

	_, _ = wire.ReadString(m.conn, 64*1024) // read path string

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])

	// found = false
	binary.LittleEndian.PutUint64(buf[:], 0)
	_, _ = m.conn.Write(buf[:])
}

func (m *mockDaemon) respondSetOptions() {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpSetOptions), op)

	// Read all ClientSettings fields from the wire:
	_, _ = io.ReadFull(m.conn, buf[:]) // keepFailed (bool)
	_, _ = io.ReadFull(m.conn, buf[:]) // keepGoing (bool)
	_, _ = io.ReadFull(m.conn, buf[:]) // tryFallback (bool)
	_, _ = io.ReadFull(m.conn, buf[:]) // verbosity (uint64)
	_, _ = io.ReadFull(m.conn, buf[:]) // maxBuildJobs (uint64)
	_, _ = io.ReadFull(m.conn, buf[:]) // maxSilentTime (uint64)
	_, _ = io.ReadFull(m.conn, buf[:]) // useBuildHook (bool, deprecated)
	_, _ = io.ReadFull(m.conn, buf[:]) // buildVerbosity (uint64)
	_, _ = io.ReadFull(m.conn, buf[:]) // logType (uint64, deprecated)
	_, _ = io.ReadFull(m.conn, buf[:]) // printBuildTrace (uint64, deprecated)
	_, _ = io.ReadFull(m.conn, buf[:]) // buildCores (uint64)
	_, _ = io.ReadFull(m.conn, buf[:]) // useSubstitutes (bool)

	// Read overrides map (protocol >= 1.12): count + key/value pairs
	_, _ = io.ReadFull(m.conn, buf[:]) // overrides count
	count := binary.LittleEndian.Uint64(buf[:])

	for i := uint64(0); i < count; i++ {
		_, _ = wire.ReadString(m.conn, 64*1024) // key
		_, _ = wire.ReadString(m.conn, 64*1024) // value
	}

	// Send LogLast (no response payload for SetOptions)
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])
}

func (m *mockDaemon) respondQueryAllValidPaths(paths []string) {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpQueryAllValidPaths), op)

	// No request params

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])

	// Send response: count + strings
	binary.LittleEndian.PutUint64(buf[:], uint64(len(paths)))
	_, _ = m.conn.Write(buf[:])

	for _, p := range paths {
		writeWireStringTo(m.conn, p)
	}
}

func (m *mockDaemon) respondQueryValidPaths(valid []string) {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpQueryValidPaths), op)

	// Read request: paths (count + strings)
	_, _ = io.ReadFull(m.conn, buf[:]) // count
	count := binary.LittleEndian.Uint64(buf[:])

	for i := uint64(0); i < count; i++ {
		_, _ = wire.ReadString(m.conn, 64*1024)
	}

	// Read substituteOk (bool) — protocol >= 1.27
	_, _ = io.ReadFull(m.conn, buf[:])

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])

	// Send response: count + strings
	binary.LittleEndian.PutUint64(buf[:], uint64(len(valid)))
	_, _ = m.conn.Write(buf[:])

	for _, p := range valid {
		writeWireStringTo(m.conn, p)
	}
}

func (m *mockDaemon) respondQuerySubstitutablePaths(paths []string) {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpQuerySubstitutablePaths), op)

	// Read request: paths (count + strings)
	_, _ = io.ReadFull(m.conn, buf[:]) // count
	count := binary.LittleEndian.Uint64(buf[:])

	for i := uint64(0); i < count; i++ {
		_, _ = wire.ReadString(m.conn, 64*1024)
	}

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])

	// Send response: count + strings
	binary.LittleEndian.PutUint64(buf[:], uint64(len(paths)))
	_, _ = m.conn.Write(buf[:])

	for _, p := range paths {
		writeWireStringTo(m.conn, p)
	}
}

func (m *mockDaemon) respondQueryReferrers(referrers []string) {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpQueryReferrers), op)

	// Read request: path string
	_, _ = wire.ReadString(m.conn, 64*1024)

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])

	// Send response: count + strings
	binary.LittleEndian.PutUint64(buf[:], uint64(len(referrers)))
	_, _ = m.conn.Write(buf[:])

	for _, r := range referrers {
		writeWireStringTo(m.conn, r)
	}
}

func (m *mockDaemon) respondQueryValidDerivers(derivers []string) {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpQueryValidDerivers), op)

	// Read request: path string
	_, _ = wire.ReadString(m.conn, 64*1024)

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])

	// Send response: count + strings
	binary.LittleEndian.PutUint64(buf[:], uint64(len(derivers)))
	_, _ = m.conn.Write(buf[:])

	for _, d := range derivers {
		writeWireStringTo(m.conn, d)
	}
}

func (m *mockDaemon) respondQueryDerivationOutputMap(outputs map[string]string) {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpQueryDerivationOutputMap), op)

	// Read request: drvPath string
	_, _ = wire.ReadString(m.conn, 64*1024)

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])

	// Send response: count + sorted key/value pairs
	keys := make([]string, 0, len(outputs))
	for k := range outputs {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	binary.LittleEndian.PutUint64(buf[:], uint64(len(keys)))
	_, _ = m.conn.Write(buf[:])

	for _, k := range keys {
		writeWireStringTo(m.conn, k)
		writeWireStringTo(m.conn, outputs[k])
	}
}

func (m *mockDaemon) respondQueryMissing(info *daemon.MissingInfo) {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpQueryMissing), op)

	// Read request: paths (count + strings)
	_, _ = io.ReadFull(m.conn, buf[:]) // count
	count := binary.LittleEndian.Uint64(buf[:])

	for i := uint64(0); i < count; i++ {
		_, _ = wire.ReadString(m.conn, 64*1024)
	}

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])

	// Send response: willBuild, willSubstitute, unknown, downloadSize, narSize
	// willBuild
	binary.LittleEndian.PutUint64(buf[:], uint64(len(info.WillBuild)))
	_, _ = m.conn.Write(buf[:])

	for _, p := range info.WillBuild {
		writeWireStringTo(m.conn, p)
	}

	// willSubstitute
	binary.LittleEndian.PutUint64(buf[:], uint64(len(info.WillSubstitute)))
	_, _ = m.conn.Write(buf[:])

	for _, p := range info.WillSubstitute {
		writeWireStringTo(m.conn, p)
	}

	// unknown
	binary.LittleEndian.PutUint64(buf[:], uint64(len(info.Unknown)))
	_, _ = m.conn.Write(buf[:])

	for _, p := range info.Unknown {
		writeWireStringTo(m.conn, p)
	}

	// downloadSize
	binary.LittleEndian.PutUint64(buf[:], info.DownloadSize)
	_, _ = m.conn.Write(buf[:])

	// narSize
	binary.LittleEndian.PutUint64(buf[:], info.NarSize)
	_, _ = m.conn.Write(buf[:])
}

func (m *mockDaemon) respondQueryPathFromHashPart(path string) {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpQueryPathFromHashPart), op)

	// Read request: hashPart string
	_, _ = wire.ReadString(m.conn, 64*1024)

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])

	// Send response: path string
	writeWireStringTo(m.conn, path)
}

func (m *mockDaemon) respondCollectGarbage(result *daemon.GCResult) {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpCollectGarbage), op)

	// Read request: action (uint64)
	_, _ = io.ReadFull(m.conn, buf[:])

	// Read pathsToDelete (count + strings)
	_, _ = io.ReadFull(m.conn, buf[:]) // count
	count := binary.LittleEndian.Uint64(buf[:])

	for i := uint64(0); i < count; i++ {
		_, _ = wire.ReadString(m.conn, 64*1024)
	}

	// Read ignoreLiveness (bool)
	_, _ = io.ReadFull(m.conn, buf[:])

	// Read maxFreed (uint64)
	_, _ = io.ReadFull(m.conn, buf[:])

	// Read 3 deprecated fields
	_, _ = io.ReadFull(m.conn, buf[:])
	_, _ = io.ReadFull(m.conn, buf[:])
	_, _ = io.ReadFull(m.conn, buf[:])

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])

	// Send response: paths (count + strings)
	binary.LittleEndian.PutUint64(buf[:], uint64(len(result.Paths)))
	_, _ = m.conn.Write(buf[:])

	for _, p := range result.Paths {
		writeWireStringTo(m.conn, p)
	}

	// bytesFreed
	binary.LittleEndian.PutUint64(buf[:], result.BytesFreed)
	_, _ = m.conn.Write(buf[:])

	// deprecated field
	binary.LittleEndian.PutUint64(buf[:], 0)
	_, _ = m.conn.Write(buf[:])
}

func (m *mockDaemon) respondVerifyStore(errorsFound bool) {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpVerifyStore), op)

	// Read request: checkContents (bool) + repair (bool)
	_, _ = io.ReadFull(m.conn, buf[:]) // checkContents
	_, _ = io.ReadFull(m.conn, buf[:]) // repair

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])

	// Send response: errorsFound (bool)
	if errorsFound {
		binary.LittleEndian.PutUint64(buf[:], 1)
	} else {
		binary.LittleEndian.PutUint64(buf[:], 0)
	}

	_, _ = m.conn.Write(buf[:])
}

func (m *mockDaemon) respondOptimiseStore() {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpOptimiseStore), op)

	// No request params

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])

	// Send response: uint64 acknowledgment
	binary.LittleEndian.PutUint64(buf[:], 1)
	_, _ = m.conn.Write(buf[:])
}

func (m *mockDaemon) respondQueryRealisation(realisations []string) {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpQueryRealisation), op)

	// Read request: outputID string
	_, _ = wire.ReadString(m.conn, 64*1024)

	// Send LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])

	// Send response: count + strings
	binary.LittleEndian.PutUint64(buf[:], uint64(len(realisations)))
	_, _ = m.conn.Write(buf[:])

	for _, r := range realisations {
		writeWireStringTo(m.conn, r)
	}
}

func (m *mockDaemon) respondQuerySubstitutablePathInfos(infos map[string]*daemon.SubstitutablePathInfo) {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpQuerySubstitutablePathInfos), op)

	// Read StorePathCAMap: count + (storePath + ca) pairs.
	_, _ = io.ReadFull(m.conn, buf[:]) // count
	count := binary.LittleEndian.Uint64(buf[:])

	for i := uint64(0); i < count; i++ {
		_, _ = wire.ReadString(m.conn, 64*1024) // storePath
		_, _ = wire.ReadString(m.conn, 64*1024) // ca (optional, empty string for none)
	}

	// Send LogLast.
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])

	// Send response: count + entries.
	binary.LittleEndian.PutUint64(buf[:], uint64(len(infos)))
	_, _ = m.conn.Write(buf[:])

	for path, info := range infos {
		writeWireStringTo(m.conn, path)
		writeWireStringTo(m.conn, info.Deriver)

		// References.
		binary.LittleEndian.PutUint64(buf[:], uint64(len(info.References)))
		_, _ = m.conn.Write(buf[:])

		for _, ref := range info.References {
			writeWireStringTo(m.conn, ref)
		}

		binary.LittleEndian.PutUint64(buf[:], info.DownloadSize)
		_, _ = m.conn.Write(buf[:])

		binary.LittleEndian.PutUint64(buf[:], info.NarSize)
		_, _ = m.conn.Write(buf[:])
	}
}

func (m *mockDaemon) respondAddToStore(info *daemon.PathInfo) {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(daemon.OpAddToStore), op)

	// Read request fields: name, caMethodWithAlgo, references, repair.
	_, _ = wire.ReadString(m.conn, 64*1024) // name
	_, _ = wire.ReadString(m.conn, 64*1024) // caMethodWithAlgo

	// Read references (count + strings).
	_, _ = io.ReadFull(m.conn, buf[:]) // count
	count := binary.LittleEndian.Uint64(buf[:])

	for i := uint64(0); i < count; i++ {
		_, _ = wire.ReadString(m.conn, 64*1024)
	}

	_, _ = io.ReadFull(m.conn, buf[:]) // repair

	// Read framed dump data (no padding in framed protocol).
	fr := daemon.NewFramedReader(m.conn)
	_, _ = io.ReadAll(fr)

	// Send LogLast.
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogLast))
	_, _ = m.conn.Write(buf[:])

	// Send response: ValidPathInfo = storePath + UnkeyedValidPathInfo.
	writeWireStringTo(m.conn, info.StorePath)
	writeWireStringTo(m.conn, info.Deriver)
	writeWireStringTo(m.conn, info.NarHash)

	// References.
	binary.LittleEndian.PutUint64(buf[:], uint64(len(info.References)))
	_, _ = m.conn.Write(buf[:])

	for _, ref := range info.References {
		writeWireStringTo(m.conn, ref)
	}

	binary.LittleEndian.PutUint64(buf[:], info.RegistrationTime)
	_, _ = m.conn.Write(buf[:])

	binary.LittleEndian.PutUint64(buf[:], info.NarSize)
	_, _ = m.conn.Write(buf[:])

	if info.Ultimate {
		binary.LittleEndian.PutUint64(buf[:], 1)
	} else {
		binary.LittleEndian.PutUint64(buf[:], 0)
	}

	_, _ = m.conn.Write(buf[:])

	// Sigs.
	binary.LittleEndian.PutUint64(buf[:], uint64(len(info.Sigs)))
	_, _ = m.conn.Write(buf[:])

	for _, sig := range info.Sigs {
		writeWireStringTo(m.conn, sig)
	}

	writeWireStringTo(m.conn, info.CA)
}

// respondWithError reads an op code and drains the request data using the
// provided drain function, then sends a LogError response with the given
// daemon.Error fields.
func (m *mockDaemon) respondWithError(expectedOp daemon.Operation, drain func(), de *daemon.Error) {
	var buf [8]byte

	_, _ = io.ReadFull(m.conn, buf[:]) // read op code
	op := binary.LittleEndian.Uint64(buf[:])
	assert.Equal(m.t, uint64(expectedOp), op)

	if drain != nil {
		drain()
	}

	// Send LogError instead of LogLast
	binary.LittleEndian.PutUint64(buf[:], uint64(daemon.LogError))
	_, _ = m.conn.Write(buf[:])

	// Error payload: Type, Level, Name, Message, HavePos, NrTraces, traces...
	writeWireStringTo(m.conn, de.Type)

	binary.LittleEndian.PutUint64(buf[:], de.Level)
	_, _ = m.conn.Write(buf[:])

	writeWireStringTo(m.conn, de.Name)
	writeWireStringTo(m.conn, de.Message)

	binary.LittleEndian.PutUint64(buf[:], 0) // HavePos = 0
	_, _ = m.conn.Write(buf[:])

	binary.LittleEndian.PutUint64(buf[:], uint64(len(de.Traces)))
	_, _ = m.conn.Write(buf[:])

	for _, tr := range de.Traces {
		binary.LittleEndian.PutUint64(buf[:], tr.HavePos)
		_, _ = m.conn.Write(buf[:])
		writeWireStringTo(m.conn, tr.Message)
	}
}

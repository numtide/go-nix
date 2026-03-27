package daemon_test

import (
	"bytes"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/require"
)

func TestDefaultClientSettings(t *testing.T) {
	rq := require.New(t)

	s := daemon.DefaultClientSettings()
	rq.False(s.KeepFailed)
	rq.False(s.KeepGoing)
	rq.True(s.UseSubstitutes)
	rq.Equal(uint64(1), s.MaxBuildJobs)
}

func TestWriteClientSettings(t *testing.T) {
	rq := require.New(t)

	var buf bytes.Buffer

	settings := daemon.DefaultClientSettings()
	err := daemon.WriteClientSettings(&buf, settings, daemon.ProtocolVersion)
	rq.NoError(err)

	// Verify wire format by reading fields back
	r := &buf

	keepFailed, err := wire.ReadBool(r)
	rq.NoError(err)
	rq.False(keepFailed)

	keepGoing, err := wire.ReadBool(r)
	rq.NoError(err)
	rq.False(keepGoing)

	tryFallback, err := wire.ReadBool(r)
	rq.NoError(err)
	rq.False(tryFallback)

	verbosity, err := wire.ReadUint64(r)
	rq.NoError(err)
	rq.Equal(uint64(0), verbosity) // VerbError

	maxBuildJobs, err := wire.ReadUint64(r)
	rq.NoError(err)
	rq.Equal(uint64(1), maxBuildJobs)

	maxSilentTime, err := wire.ReadUint64(r)
	rq.NoError(err)
	rq.Equal(uint64(0), maxSilentTime)

	useBuildHook, err := wire.ReadBool(r)
	rq.NoError(err)
	rq.True(useBuildHook) // deprecated, always true

	buildVerbosity, err := wire.ReadUint64(r)
	rq.NoError(err)
	rq.Equal(uint64(0), buildVerbosity)

	logType, err := wire.ReadUint64(r)
	rq.NoError(err)
	rq.Equal(uint64(0), logType) // deprecated

	printBuildTrace, err := wire.ReadUint64(r)
	rq.NoError(err)
	rq.Equal(uint64(0), printBuildTrace) // deprecated

	buildCores, err := wire.ReadUint64(r)
	rq.NoError(err)
	rq.Equal(uint64(0), buildCores)

	useSubstitutes, err := wire.ReadBool(r)
	rq.NoError(err)
	rq.True(useSubstitutes)

	// Overrides: empty map → count=0
	count, err := wire.ReadUint64(r)
	rq.NoError(err)
	rq.Equal(uint64(0), count)

	// Buffer should be fully consumed
	rq.Equal(0, r.Len())
}

// TestWriteClientSettingsWithOverrides tests at the current protocol version
// (daemon.ProtocolVersion), confirming that overrides ARE written when the
// version is >= ProtoVersionOverrides (1.12).
func TestWriteClientSettingsWithOverrides(t *testing.T) {
	rq := require.New(t)

	var buf bytes.Buffer

	settings := daemon.DefaultClientSettings()
	settings.KeepFailed = true
	settings.KeepGoing = true
	settings.Verbosity = 3 // VerbInfo
	settings.MaxBuildJobs = 4
	settings.BuildCores = 8
	settings.Overrides = map[string]string{
		"sandbox":      "true",
		"allowed-uris": "https://example.com",
	}

	err := daemon.WriteClientSettings(&buf, settings, daemon.ProtocolVersion)
	rq.NoError(err)

	r := &buf

	keepFailed, err := wire.ReadBool(r)
	rq.NoError(err)
	rq.True(keepFailed)

	keepGoing, err := wire.ReadBool(r)
	rq.NoError(err)
	rq.True(keepGoing)

	tryFallback, err := wire.ReadBool(r)
	rq.NoError(err)
	rq.False(tryFallback)

	verbosity, err := wire.ReadUint64(r)
	rq.NoError(err)
	rq.Equal(uint64(3), verbosity)

	maxBuildJobs, err := wire.ReadUint64(r)
	rq.NoError(err)
	rq.Equal(uint64(4), maxBuildJobs)

	maxSilentTime, err := wire.ReadUint64(r)
	rq.NoError(err)
	rq.Equal(uint64(0), maxSilentTime)

	useBuildHook, err := wire.ReadBool(r)
	rq.NoError(err)
	rq.True(useBuildHook)

	buildVerbosity, err := wire.ReadUint64(r)
	rq.NoError(err)
	rq.Equal(uint64(0), buildVerbosity)

	logType, err := wire.ReadUint64(r)
	rq.NoError(err)
	rq.Equal(uint64(0), logType)

	printBuildTrace, err := wire.ReadUint64(r)
	rq.NoError(err)
	rq.Equal(uint64(0), printBuildTrace)

	buildCores, err := wire.ReadUint64(r)
	rq.NoError(err)
	rq.Equal(uint64(8), buildCores)

	useSubstitutes, err := wire.ReadBool(r)
	rq.NoError(err)
	rq.True(useSubstitutes)

	// Overrides: 2 entries, sorted by key
	count, err := wire.ReadUint64(r)
	rq.NoError(err)
	rq.Equal(uint64(2), count)

	// "allowed-uris" comes before "sandbox" alphabetically
	key1, err := wire.ReadString(r, 1024)
	rq.NoError(err)
	rq.Equal("allowed-uris", key1)

	val1, err := wire.ReadString(r, 1024)
	rq.NoError(err)
	rq.Equal("https://example.com", val1)

	key2, err := wire.ReadString(r, 1024)
	rq.NoError(err)
	rq.Equal("sandbox", key2)

	val2, err := wire.ReadString(r, 1024)
	rq.NoError(err)
	rq.Equal("true", val2)

	rq.Equal(0, r.Len())
}

func TestWriteClientSettingsPreOverrides(t *testing.T) {
	var buf bytes.Buffer

	settings := daemon.DefaultClientSettings()
	settings.Overrides = map[string]string{"sandbox": "true"} // Set, but should NOT be written

	err := daemon.WriteClientSettings(&buf, settings, daemon.ProtoVersion(1, 11))
	require.NoError(t, err)

	r := &buf
	// Read all standard fields (same as TestWriteClientSettings)
	_, _ = wire.ReadBool(r)   // keepFailed
	_, _ = wire.ReadBool(r)   // keepGoing
	_, _ = wire.ReadBool(r)   // tryFallback
	_, _ = wire.ReadUint64(r) // verbosity
	_, _ = wire.ReadUint64(r) // maxBuildJobs
	_, _ = wire.ReadUint64(r) // maxSilentTime
	_, _ = wire.ReadBool(r)   // useBuildHook (deprecated)
	_, _ = wire.ReadUint64(r) // buildVerbosity
	_, _ = wire.ReadUint64(r) // logType (deprecated)
	_, _ = wire.ReadUint64(r) // printBuildTrace (deprecated)
	_, _ = wire.ReadUint64(r) // buildCores
	_, _ = wire.ReadBool(r)   // useSubstitutes

	// NO overrides map at proto < 1.12
	require.Equal(t, 0, r.Len())
}

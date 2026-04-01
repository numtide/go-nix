package daemon_test

import (
	"bytes"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/require"
)

func TestClientSettings(t *testing.T) {
	t.Run("Defaults", func(t *testing.T) {
		rq := require.New(t)

		s := daemon.DefaultClientSettings()
		rq.False(s.KeepFailed)
		rq.False(s.KeepGoing)
		rq.True(s.UseSubstitutes)
		rq.Equal(uint64(1), s.MaxBuildJobs)
	})

	t.Run("Write", func(t *testing.T) {
		rq := require.New(t)

		var buf bytes.Buffer

		settings := daemon.DefaultClientSettings()
		err := daemon.WriteClientSettings(wire.NewEncoder(&buf), settings, daemon.ProtocolVersion)
		rq.NoError(err)

		// verify wire format by reading fields back
		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		keepFailed, err := dec.ReadBool()
		rq.NoError(err)
		rq.False(keepFailed)

		keepGoing, err := dec.ReadBool()
		rq.NoError(err)
		rq.False(keepGoing)

		tryFallback, err := dec.ReadBool()
		rq.NoError(err)
		rq.False(tryFallback)

		verbosity, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(0), verbosity) // VerbError

		maxBuildJobs, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(1), maxBuildJobs)

		maxSilentTime, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(0), maxSilentTime)

		useBuildHook, err := dec.ReadBool()
		rq.NoError(err)
		rq.True(useBuildHook) // deprecated, always true

		buildVerbosity, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(0), buildVerbosity)

		logType, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(0), logType) // deprecated

		printBuildTrace, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(0), printBuildTrace) // deprecated

		buildCores, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(0), buildCores)

		useSubstitutes, err := dec.ReadBool()
		rq.NoError(err)
		rq.True(useSubstitutes)

		// overrides: empty map -> count=0
		count, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(0), count)

		// buffer should be fully consumed
		rq.Equal(0, buf.Len())
	})

	// TestWriteClientSettingsWithOverrides tests at the current protocol version
	// (daemon.ProtocolVersion), confirming that overrides ARE written when the
	// version is >= ProtoVersionOverrides (1.12).
	t.Run("WriteWithOverrides", func(t *testing.T) {
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

		err := daemon.WriteClientSettings(wire.NewEncoder(&buf), settings, daemon.ProtocolVersion)
		rq.NoError(err)

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		keepFailed, err := dec.ReadBool()
		rq.NoError(err)
		rq.True(keepFailed)

		keepGoing, err := dec.ReadBool()
		rq.NoError(err)
		rq.True(keepGoing)

		tryFallback, err := dec.ReadBool()
		rq.NoError(err)
		rq.False(tryFallback)

		verbosity, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(3), verbosity)

		maxBuildJobs, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(4), maxBuildJobs)

		maxSilentTime, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(0), maxSilentTime)

		useBuildHook, err := dec.ReadBool()
		rq.NoError(err)
		rq.True(useBuildHook)

		buildVerbosity, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(0), buildVerbosity)

		logType, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(0), logType)

		printBuildTrace, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(0), printBuildTrace)

		buildCores, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(8), buildCores)

		useSubstitutes, err := dec.ReadBool()
		rq.NoError(err)
		rq.True(useSubstitutes)

		// overrides: 2 entries, sorted by key
		count, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(2), count)

		// "allowed-uris" comes before "sandbox" alphabetically
		key1, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("allowed-uris", key1)

		val1, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("https://example.com", val1)

		key2, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("sandbox", key2)

		val2, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("true", val2)

		rq.Equal(0, buf.Len())
	})

	t.Run("WritePreOverrides", func(t *testing.T) {
		var buf bytes.Buffer

		settings := daemon.DefaultClientSettings()
		settings.Overrides = map[string]string{"sandbox": "true"} // Set, but should NOT be written

		err := daemon.WriteClientSettings(wire.NewEncoder(&buf), settings, daemon.ProtoVersion(1, 11))
		require.NoError(t, err)

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		// read all standard fields (same as Write subtest)
		_, _ = dec.ReadBool()   // keepFailed
		_, _ = dec.ReadBool()   // keepGoing
		_, _ = dec.ReadBool()   // tryFallback
		_, _ = dec.ReadUint64() // verbosity
		_, _ = dec.ReadUint64() // maxBuildJobs
		_, _ = dec.ReadUint64() // maxSilentTime
		_, _ = dec.ReadBool()   // useBuildHook (deprecated)
		_, _ = dec.ReadUint64() // buildVerbosity
		_, _ = dec.ReadUint64() // logType (deprecated)
		_, _ = dec.ReadUint64() // printBuildTrace (deprecated)
		_, _ = dec.ReadUint64() // buildCores
		_, _ = dec.ReadBool()   // useSubstitutes

		// NO overrides map at proto < 1.12
		require.Equal(t, 0, buf.Len())
	})
}

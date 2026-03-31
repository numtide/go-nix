package daemon

import (
	"github.com/nix-community/go-nix/pkg/wire"
)

// ClientSettings holds the client-side build settings sent to the daemon via the SetOptions operation.
type ClientSettings struct {
	// KeepFailed controls whether to keep build directories of failed builds.
	KeepFailed bool
	// KeepGoing controls whether to continue building other derivations when one fails.
	KeepGoing bool
	// TryFallback controls whether to fall back to building from source if substitution fails.
	TryFallback bool
	// Verbosity controls the logging verbosity level.
	Verbosity Verbosity
	// MaxBuildJobs is the maximum number of parallel build jobs.
	MaxBuildJobs uint64
	// MaxSilentTime is the maximum time (in seconds) a builder can go without output before being killed.
	MaxSilentTime uint64
	// BuildVerbosity controls the verbosity of build output.
	BuildVerbosity Verbosity
	// BuildCores is the number of CPU cores to use per build (0 = all available).
	BuildCores uint64
	// UseSubstitutes controls whether to use binary substitutes.
	UseSubstitutes bool
	// Overrides is a map of additional settings to override on the daemon.
	Overrides map[string]string
}

// DefaultClientSettings returns a ClientSettings with sensible defaults.
func DefaultClientSettings() *ClientSettings {
	return &ClientSettings{
		KeepFailed:     false,
		KeepGoing:      false,
		TryFallback:    false,
		Verbosity:      VerbError,
		MaxBuildJobs:   1,
		MaxSilentTime:  0,
		BuildVerbosity: VerbError,
		BuildCores:     0,
		UseSubstitutes: true,
		Overrides:      nil,
	}
}

// WriteClientSettings serializes the SetOptions request fields using the encoder in the Nix daemon wire format.
// The version parameter is the negotiated protocol version.
func WriteClientSettings(enc *wire.Encoder, s *ClientSettings, version uint64) error {
	if s == nil {
		s = DefaultClientSettings()
	}

	if err := enc.WriteBool(s.KeepFailed); err != nil {
		return err
	}

	if err := enc.WriteBool(s.KeepGoing); err != nil {
		return err
	}

	if err := enc.WriteBool(s.TryFallback); err != nil {
		return err
	}

	if err := enc.WriteUint64(uint64(s.Verbosity)); err != nil {
		return err
	}

	if err := enc.WriteUint64(s.MaxBuildJobs); err != nil {
		return err
	}

	if err := enc.WriteUint64(s.MaxSilentTime); err != nil {
		return err
	}

	// useBuildHook — deprecated, always true.
	if err := enc.WriteBool(true); err != nil {
		return err
	}

	if err := enc.WriteUint64(uint64(s.BuildVerbosity)); err != nil {
		return err
	}

	// logType — deprecated, always 0.
	if err := enc.WriteUint64(0); err != nil {
		return err
	}

	// printBuildTrace — deprecated, always 0.
	if err := enc.WriteUint64(0); err != nil {
		return err
	}

	if err := enc.WriteUint64(s.BuildCores); err != nil {
		return err
	}

	if err := enc.WriteBool(s.UseSubstitutes); err != nil {
		return err
	}

	// Protocol >= 1.12: overrides map.
	if version >= ProtoVersionOverrides {
		overrides := s.Overrides
		if overrides == nil {
			overrides = map[string]string{}
		}

		if err := enc.WriteStringMap(overrides); err != nil {
			return err
		}
	}

	return nil
}

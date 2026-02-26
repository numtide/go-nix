package daemon

import (
	"io"

	"github.com/nix-community/go-nix/pkg/wire"
)

// ClientSettings holds the client-side build settings sent to the daemon
// via the SetOptions operation.
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

// WriteClientSettings serializes the SetOptions request fields to the writer
// in the Nix daemon wire format.
func WriteClientSettings(w io.Writer, s *ClientSettings) error {
	if err := wire.WriteBool(w, s.KeepFailed); err != nil {
		return err
	}

	if err := wire.WriteBool(w, s.KeepGoing); err != nil {
		return err
	}

	if err := wire.WriteBool(w, s.TryFallback); err != nil {
		return err
	}

	if err := wire.WriteUint64(w, uint64(s.Verbosity)); err != nil {
		return err
	}

	if err := wire.WriteUint64(w, s.MaxBuildJobs); err != nil {
		return err
	}

	if err := wire.WriteUint64(w, s.MaxSilentTime); err != nil {
		return err
	}

	// useBuildHook — deprecated, always true.
	if err := wire.WriteBool(w, true); err != nil {
		return err
	}

	if err := wire.WriteUint64(w, uint64(s.BuildVerbosity)); err != nil {
		return err
	}

	// logType — deprecated, always 0.
	if err := wire.WriteUint64(w, 0); err != nil {
		return err
	}

	// printBuildTrace — deprecated, always 0.
	if err := wire.WriteUint64(w, 0); err != nil {
		return err
	}

	if err := wire.WriteUint64(w, s.BuildCores); err != nil {
		return err
	}

	if err := wire.WriteBool(w, s.UseSubstitutes); err != nil {
		return err
	}

	overrides := s.Overrides
	if overrides == nil {
		overrides = map[string]string{}
	}

	return WriteStringMap(w, overrides)
}

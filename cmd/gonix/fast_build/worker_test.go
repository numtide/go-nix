package fast_build_test

import (
	"testing"

	"github.com/nix-community/go-nix/cmd/gonix/fast_build"
	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/stretchr/testify/assert"
)

func TestStatusMapping(t *testing.T) {
	tests := []struct {
		name     string
		status   daemon.BuildStatus
		expected string
	}{
		{"built", daemon.BuildStatusBuilt, "built"},
		{"substituted", daemon.BuildStatusSubstituted, "substituted"},
		{"already valid", daemon.BuildStatusAlreadyValid, "cached"},
		{"resolves to already valid", daemon.BuildStatusResolvesToAlreadyValid, "cached"},
		{"permanent failure", daemon.BuildStatusPermanentFailure, "failed"},
		{"transient failure", daemon.BuildStatusTransientFailure, "failed"},
		{"timed out", daemon.BuildStatusTimedOut, "failed"},
		{"dependency failed", daemon.BuildStatusDependencyFailed, "failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := fast_build.MapBuildStatus(tt.status)
			assert.Equal(t, tt.expected, status)
		})
	}
}

//go:build integration

package daemon_test

import (
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/stretchr/testify/assert"
)

const defaultSocket = "/nix/var/nix/daemon-socket/socket"

func TestIntegrationConnect(t *testing.T) {
	client, err := daemon.Connect(defaultSocket)
	if err != nil {
		t.Skipf("cannot connect to Nix daemon: %v", err)
	}
	defer client.Close()

	info := client.Info()
	assert.Equal(t, daemon.ProtocolVersion, info.Version)
	t.Logf("Nix version: %s, trust: %d", info.DaemonNixVersion, info.Trust)
}

func TestIntegrationIsValidPath(t *testing.T) {
	client, err := daemon.Connect(defaultSocket)
	if err != nil {
		t.Skipf("cannot connect to Nix daemon: %v", err)
	}
	defer client.Close()

	// A path that definitely doesn't exist
	result := <-client.IsValidPath("/nix/store/00000000000000000000000000000000-nonexistent")
	assert.NoError(t, result.Err)
	assert.False(t, result.Value)
}

func TestIntegrationQueryAllValidPaths(t *testing.T) {
	client, err := daemon.Connect(defaultSocket)
	if err != nil {
		t.Skipf("cannot connect to Nix daemon: %v", err)
	}
	defer client.Close()

	result := <-client.QueryAllValidPaths()
	assert.NoError(t, result.Err)
	t.Logf("Store has %d valid paths", len(result.Value))
	assert.True(t, len(result.Value) > 0)
}

package daemon_test

import (
	"bytes"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/assert"
)

func TestWriteReadStrings(t *testing.T) {
	var buf bytes.Buffer
	err := daemon.WriteStrings(&buf, []string{"foo", "bar", "baz"})
	assert.NoError(t, err)
	result, err := daemon.ReadStrings(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, []string{"foo", "bar", "baz"}, result)
}

func TestWriteReadStringsEmpty(t *testing.T) {
	var buf bytes.Buffer
	err := daemon.WriteStrings(&buf, []string{})
	assert.NoError(t, err)
	result, err := daemon.ReadStrings(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Empty(t, result)
}

func TestWriteReadStringMap(t *testing.T) {
	var buf bytes.Buffer
	m := map[string]string{"a": "1", "b": "2"}
	err := daemon.WriteStringMap(&buf, m)
	assert.NoError(t, err)
	result, err := daemon.ReadStringMap(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, m, result)
}

func TestReadPathInfo(t *testing.T) {
	var buf bytes.Buffer
	writeTestString(&buf, "/nix/store/abc-foo.drv")       // deriver
	writeTestString(&buf, "sha256:abcdef1234567890")       // narHash
	writeTestUint64(&buf, 1)                                // references count
	writeTestString(&buf, "/nix/store/def-bar")            // reference
	writeTestUint64(&buf, 1700000000)                      // registrationTime
	writeTestUint64(&buf, 12345)                            // narSize
	writeTestUint64(&buf, 1)                                // ultimate = true
	writeTestUint64(&buf, 1)                                // sigs count
	writeTestString(&buf, "cache.example.com-1:abc123sig") // signature
	writeTestString(&buf, "")                               // contentAddress

	info, err := daemon.ReadPathInfo(&buf, "/nix/store/xyz-test")
	assert.NoError(t, err)
	assert.Equal(t, "/nix/store/xyz-test", info.StorePath)
	assert.Equal(t, "/nix/store/abc-foo.drv", info.Deriver)
	assert.Equal(t, "sha256:abcdef1234567890", info.NarHash)
	assert.Equal(t, []string{"/nix/store/def-bar"}, info.References)
	assert.Equal(t, uint64(12345), info.NarSize)
	assert.True(t, info.Ultimate)
	assert.Equal(t, []string{"cache.example.com-1:abc123sig"}, info.Sigs)
}

func TestWriteReadPathInfoRoundTrip(t *testing.T) {
	info := &daemon.PathInfo{
		StorePath:        "/nix/store/xyz-test",
		Deriver:          "/nix/store/abc-foo.drv",
		NarHash:          "sha256:abcdef",
		References:       []string{"/nix/store/def-bar"},
		RegistrationTime: 1700000000,
		NarSize:          54321,
		Ultimate:         true,
		Sigs:             []string{"sig1"},
		CA:               "",
	}

	var buf bytes.Buffer
	err := daemon.WritePathInfo(&buf, info)
	assert.NoError(t, err)

	// ReadPathInfo reads UnkeyedValidPathInfo (no storePath prefix),
	// but WritePathInfo writes ValidPathInfo (with storePath prefix).
	// So we need to read the storePath first.
	storePath, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "/nix/store/xyz-test", storePath)

	got, err := daemon.ReadPathInfo(&buf, storePath)
	assert.NoError(t, err)
	assert.Equal(t, info, got)
}

func TestReadBuildResult(t *testing.T) {
	var buf bytes.Buffer
	writeTestUint64(&buf, 0)              // status = Built
	writeTestString(&buf, "")             // errorMsg
	writeTestUint64(&buf, 1)              // timesBuilt
	writeTestUint64(&buf, 0)              // isNonDeterministic = false
	writeTestUint64(&buf, 1700000000)     // startTime
	writeTestUint64(&buf, 1700000060)     // stopTime
	writeTestUint64(&buf, 1)              // builtOutputs count
	writeTestString(&buf, "out")          // output name
	writeTestString(&buf, `{"id":"test"}`) // realisation JSON

	result, err := daemon.ReadBuildResult(&buf)
	assert.NoError(t, err)
	assert.Equal(t, daemon.BuildStatusBuilt, result.Status)
	assert.Equal(t, "", result.ErrorMsg)
	assert.Equal(t, uint64(1), result.TimesBuilt)
	assert.False(t, result.IsNonDeterministic)
	assert.Equal(t, uint64(1700000000), result.StartTime)
	assert.Equal(t, uint64(1700000060), result.StopTime)
	assert.Len(t, result.BuiltOutputs, 1)
	assert.Equal(t, daemon.Realisation{ID: `{"id":"test"}`}, result.BuiltOutputs["out"])
}

func TestReadBuildResultNoOutputs(t *testing.T) {
	var buf bytes.Buffer
	writeTestUint64(&buf, 3)          // status = PermanentFailure
	writeTestString(&buf, "build failed") // errorMsg
	writeTestUint64(&buf, 0)          // timesBuilt
	writeTestUint64(&buf, 0)          // isNonDeterministic = false
	writeTestUint64(&buf, 1700000000) // startTime
	writeTestUint64(&buf, 1700000010) // stopTime
	writeTestUint64(&buf, 0)          // builtOutputs count

	result, err := daemon.ReadBuildResult(&buf)
	assert.NoError(t, err)
	assert.Equal(t, daemon.BuildStatusPermanentFailure, result.Status)
	assert.Equal(t, "build failed", result.ErrorMsg)
	assert.Empty(t, result.BuiltOutputs)
}

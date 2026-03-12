package daemon_test

import (
	"bytes"
	"testing"
	"time"

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

	writeTestString(&buf, "/nix/store/abc-foo.drv")        // deriver
	writeTestString(&buf, "sha256:abcdef1234567890")       // narHash
	writeTestUint64(&buf, 1)                               // references count
	writeTestString(&buf, "/nix/store/def-bar")            // reference
	writeTestUint64(&buf, 1700000000)                      // registrationTime
	writeTestUint64(&buf, 12345)                           // narSize
	writeTestUint64(&buf, 1)                               // ultimate = true
	writeTestUint64(&buf, 1)                               // sigs count
	writeTestString(&buf, "cache.example.com-1:abc123sig") // signature
	writeTestString(&buf, "")                              // contentAddress

	info, err := daemon.ReadPathInfo(&buf, "/nix/store/xyz-test", daemon.ProtocolVersion)
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
	err := daemon.WritePathInfo(&buf, info, daemon.ProtocolVersion)
	assert.NoError(t, err)

	// ReadPathInfo reads UnkeyedValidPathInfo (no storePath prefix),
	// but WritePathInfo writes ValidPathInfo (with storePath prefix).
	// So we need to read the storePath first.
	storePath, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "/nix/store/xyz-test", storePath)

	got, err := daemon.ReadPathInfo(&buf, storePath, daemon.ProtocolVersion)
	assert.NoError(t, err)
	assert.Equal(t, info, got)
}

func TestWriteBasicDerivation(t *testing.T) {
	drv := &daemon.BasicDerivation{
		Outputs: map[string]daemon.DerivationOutput{
			"out": {Path: "/nix/store/abc-out", HashAlgorithm: "", Hash: ""},
			"dev": {Path: "/nix/store/abc-dev", HashAlgorithm: "", Hash: ""},
		},
		Inputs:   []string{"/nix/store/def-input", "/nix/store/ghi-input"},
		Platform: "x86_64-linux",
		Builder:  "/nix/store/bash/bin/bash",
		Args:     []string{"-e", "builder.sh"},
		Env:      map[string]string{"out": "/nix/store/abc-out", "dev": "/nix/store/abc-dev"},
	}

	var buf bytes.Buffer
	err := daemon.WriteBasicDerivation(&buf, drv)
	assert.NoError(t, err)

	// Verify outputs count = 2
	count, err := wire.ReadUint64(&buf)
	assert.NoError(t, err)
	assert.Equal(t, uint64(2), count)

	// First output should be "dev" (sorted)
	name, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "dev", name)

	path, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "/nix/store/abc-dev", path)

	hashAlgo, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "", hashAlgo)

	hash, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "", hash)

	// Second output should be "out"
	name, err = wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "out", name)

	path, err = wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "/nix/store/abc-out", path)

	_, err = wire.ReadString(&buf, daemon.MaxStringSize) // hashAlgo
	assert.NoError(t, err)

	_, err = wire.ReadString(&buf, daemon.MaxStringSize) // hash
	assert.NoError(t, err)

	// Verify inputs count = 2
	count, err = wire.ReadUint64(&buf)
	assert.NoError(t, err)
	assert.Equal(t, uint64(2), count)

	input1, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "/nix/store/def-input", input1)

	input2, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "/nix/store/ghi-input", input2)

	// Verify platform
	platform, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "x86_64-linux", platform)

	// Verify builder
	builder, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "/nix/store/bash/bin/bash", builder)

	// Verify args count = 2
	count, err = wire.ReadUint64(&buf)
	assert.NoError(t, err)
	assert.Equal(t, uint64(2), count)

	arg1, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "-e", arg1)

	arg2, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "builder.sh", arg2)

	// Verify env count = 2 (sorted: "dev" < "out")
	count, err = wire.ReadUint64(&buf)
	assert.NoError(t, err)
	assert.Equal(t, uint64(2), count)

	key1, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "dev", key1)

	val1, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "/nix/store/abc-dev", val1)

	key2, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "out", key2)

	val2, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "/nix/store/abc-out", val2)

	// Buffer should be fully consumed
	assert.Equal(t, 0, buf.Len())
}

func TestWriteBasicDerivationEmpty(t *testing.T) {
	drv := &daemon.BasicDerivation{
		Outputs:  map[string]daemon.DerivationOutput{},
		Inputs:   []string{},
		Platform: "x86_64-linux",
		Builder:  "/bin/sh",
		Args:     []string{},
		Env:      map[string]string{},
	}

	var buf bytes.Buffer
	err := daemon.WriteBasicDerivation(&buf, drv)
	assert.NoError(t, err)

	// Outputs count = 0
	count, err := wire.ReadUint64(&buf)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), count)

	// Inputs count = 0
	count, err = wire.ReadUint64(&buf)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), count)

	// Platform
	platform, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "x86_64-linux", platform)

	// Builder
	builder, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "/bin/sh", builder)

	// Args count = 0
	count, err = wire.ReadUint64(&buf)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), count)

	// Env count = 0
	count, err = wire.ReadUint64(&buf)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), count)

	assert.Equal(t, 0, buf.Len())
}

func TestReadBuildResult(t *testing.T) {
	var buf bytes.Buffer

	writeTestUint64(&buf, 0)               // status = Built
	writeTestString(&buf, "")              // errorMsg
	writeTestUint64(&buf, 1)               // timesBuilt
	writeTestUint64(&buf, 0)               // isNonDeterministic = false
	writeTestUint64(&buf, 1700000000)      // startTime
	writeTestUint64(&buf, 1700000060)      // stopTime
	writeTestUint64(&buf, 0)               // cpuUser: None
	writeTestUint64(&buf, 0)               // cpuSystem: None
	writeTestUint64(&buf, 1)     // builtOutputs count
	writeTestString(&buf, "out") // output name
	writeTestString(&buf, `{"id":"sha256:abc123!out","outPath":"/nix/store/zzz-hello","signatures":["mykey:c2ln"],"dependentRealisations":{}}`)

	result, err := daemon.ReadBuildResult(&buf, daemon.ProtocolVersion)
	assert.NoError(t, err)
	assert.Equal(t, daemon.BuildStatusBuilt, result.Status)
	assert.Equal(t, "", result.ErrorMsg)
	assert.Equal(t, uint64(1), result.TimesBuilt)
	assert.False(t, result.IsNonDeterministic)
	assert.Equal(t, uint64(1700000000), result.StartTime)
	assert.Equal(t, uint64(1700000060), result.StopTime)
	assert.Nil(t, result.CpuUser)
	assert.Nil(t, result.CpuSystem)
	assert.Len(t, result.BuiltOutputs, 1)

	real := result.BuiltOutputs["out"]
	assert.Equal(t, "sha256:abc123!out", real.ID)
	assert.Equal(t, "/nix/store/zzz-hello", real.OutPath)
	assert.Equal(t, []string{"mykey:c2ln"}, real.Signatures)
	assert.Empty(t, real.DependentRealisations)
}

func TestReadBuildResultNoOutputs(t *testing.T) {
	var buf bytes.Buffer

	writeTestUint64(&buf, 3)              // status = PermanentFailure
	writeTestString(&buf, "build failed") // errorMsg
	writeTestUint64(&buf, 0)              // timesBuilt
	writeTestUint64(&buf, 0)              // isNonDeterministic = false
	writeTestUint64(&buf, 1700000000)     // startTime
	writeTestUint64(&buf, 1700000010)     // stopTime
	writeTestUint64(&buf, 0)              // cpuUser: None
	writeTestUint64(&buf, 0)              // cpuSystem: None
	writeTestUint64(&buf, 0)              // builtOutputs count

	result, err := daemon.ReadBuildResult(&buf, daemon.ProtocolVersion)
	assert.NoError(t, err)
	assert.Equal(t, daemon.BuildStatusPermanentFailure, result.Status)
	assert.Equal(t, "build failed", result.ErrorMsg)
	assert.Nil(t, result.CpuUser)
	assert.Nil(t, result.CpuSystem)
	assert.Empty(t, result.BuiltOutputs)
}

func TestReadBuildResultWithCPUTimes(t *testing.T) {
	var buf bytes.Buffer

	writeTestUint64(&buf, 0)          // status = Built
	writeTestString(&buf, "")         // errorMsg
	writeTestUint64(&buf, 1)          // timesBuilt
	writeTestUint64(&buf, 0)          // isNonDeterministic = false
	writeTestUint64(&buf, 1700000000) // startTime
	writeTestUint64(&buf, 1700000060) // stopTime
	// cpuUser: optional<microseconds> = Some(500000)
	writeTestUint64(&buf, 1)      // tag: present
	writeTestUint64(&buf, 500000) // value: 500000 microseconds
	// cpuSystem: optional<microseconds> = None
	writeTestUint64(&buf, 0) // tag: absent
	writeTestUint64(&buf, 0) // builtOutputs count

	result, err := daemon.ReadBuildResult(&buf, daemon.ProtocolVersion)
	assert.NoError(t, err)
	assert.Equal(t, daemon.BuildStatusBuilt, result.Status)
	assert.Equal(t, uint64(1), result.TimesBuilt)
	assert.Equal(t, uint64(1700000000), result.StartTime)
	assert.Equal(t, uint64(1700000060), result.StopTime)

	expectedCpuUser := 500 * time.Millisecond
	assert.Equal(t, &expectedCpuUser, result.CpuUser)
	assert.Nil(t, result.CpuSystem)

	assert.Empty(t, result.BuiltOutputs)
	assert.Equal(t, 0, buf.Len())
}

func TestReadBuildResultWithCPUTimesBothPresent(t *testing.T) {
	var buf bytes.Buffer

	writeTestUint64(&buf, 0)          // status = Built
	writeTestString(&buf, "")         // errorMsg
	writeTestUint64(&buf, 2)          // timesBuilt
	writeTestUint64(&buf, 0)          // isNonDeterministic = false
	writeTestUint64(&buf, 1700000000) // startTime
	writeTestUint64(&buf, 1700000060) // stopTime
	// cpuUser: optional<microseconds> = Some(1000000)
	writeTestUint64(&buf, 1)       // tag: present
	writeTestUint64(&buf, 1000000) // value
	// cpuSystem: optional<microseconds> = Some(250000)
	writeTestUint64(&buf, 1)               // tag: present
	writeTestUint64(&buf, 250000)          // value
	writeTestUint64(&buf, 1)     // builtOutputs count
	writeTestString(&buf, "out") // output name
	writeTestString(&buf, `{"id":"sha256:def456!out","outPath":"/nix/store/yyy-world","signatures":[],"dependentRealisations":{}}`)

	result, err := daemon.ReadBuildResult(&buf, daemon.ProtocolVersion)
	assert.NoError(t, err)
	assert.Equal(t, daemon.BuildStatusBuilt, result.Status)
	assert.Equal(t, uint64(2), result.TimesBuilt)

	expectedCpuUser := time.Second
	expectedCpuSystem := 250 * time.Millisecond
	assert.Equal(t, &expectedCpuUser, result.CpuUser)
	assert.Equal(t, &expectedCpuSystem, result.CpuSystem)

	assert.Len(t, result.BuiltOutputs, 1)
	assert.Equal(t, "sha256:def456!out", result.BuiltOutputs["out"].ID)
	assert.Equal(t, "/nix/store/yyy-world", result.BuiltOutputs["out"].OutPath)
	assert.Equal(t, 0, buf.Len())
}

func TestReadBuildResultProto127(t *testing.T) {
	// Proto 1.27 (0x011b): only status + errorMsg (no timing, no CPU, no builtOutputs)
	var buf bytes.Buffer
	writeTestUint64(&buf, 0)            // status = Built
	writeTestString(&buf, "some error") // errorMsg

	result, err := daemon.ReadBuildResult(&buf, daemon.ProtoVersion(1, 27))
	assert.NoError(t, err)
	assert.Equal(t, daemon.BuildStatusBuilt, result.Status)
	assert.Equal(t, "some error", result.ErrorMsg)
	assert.Equal(t, uint64(0), result.TimesBuilt)
	assert.False(t, result.IsNonDeterministic)
	assert.Equal(t, uint64(0), result.StartTime)
	assert.Equal(t, uint64(0), result.StopTime)
	assert.Nil(t, result.BuiltOutputs)
	assert.Equal(t, 0, buf.Len())
}

func TestReadBuildResultProto128(t *testing.T) {
	// Proto 1.28 (0x011c): status + errorMsg + builtOutputs (no timing, no CPU)
	var buf bytes.Buffer
	writeTestUint64(&buf, 1)               // status = Substituted
	writeTestString(&buf, "")              // errorMsg
	writeTestUint64(&buf, 1)     // builtOutputs count
	writeTestString(&buf, "out") // output name
	writeTestString(&buf, `{"id":"sha256:abc!out","outPath":"/nix/store/zzz-pkg","signatures":[],"dependentRealisations":{}}`)

	result, err := daemon.ReadBuildResult(&buf, daemon.ProtoVersion(1, 28))
	assert.NoError(t, err)
	assert.Equal(t, daemon.BuildStatusSubstituted, result.Status)
	assert.Equal(t, uint64(0), result.TimesBuilt) // no timing fields
	assert.Len(t, result.BuiltOutputs, 1)
	assert.Equal(t, "sha256:abc!out", result.BuiltOutputs["out"].ID)
	assert.Equal(t, "/nix/store/zzz-pkg", result.BuiltOutputs["out"].OutPath)
	assert.Equal(t, 0, buf.Len())
}

func TestReadBuildResultProto129(t *testing.T) {
	// Proto 1.29 (0x011d): status + errorMsg + timing + builtOutputs (no CPU)
	var buf bytes.Buffer
	writeTestUint64(&buf, 0)          // status = Built
	writeTestString(&buf, "")         // errorMsg
	writeTestUint64(&buf, 3)          // timesBuilt
	writeTestUint64(&buf, 1)          // isNonDeterministic = true
	writeTestUint64(&buf, 1700000000) // startTime
	writeTestUint64(&buf, 1700000060) // stopTime
	writeTestUint64(&buf, 0)          // builtOutputs count

	result, err := daemon.ReadBuildResult(&buf, daemon.ProtoVersion(1, 29))
	assert.NoError(t, err)
	assert.Equal(t, daemon.BuildStatusBuilt, result.Status)
	assert.Equal(t, uint64(3), result.TimesBuilt)
	assert.True(t, result.IsNonDeterministic)
	assert.Equal(t, uint64(1700000000), result.StartTime)
	assert.Equal(t, uint64(1700000060), result.StopTime)
	assert.Empty(t, result.BuiltOutputs)
	assert.Equal(t, 0, buf.Len())
}

func TestWriteReadPathInfoRoundTripPreMeta(t *testing.T) {
	info := &daemon.PathInfo{
		StorePath:        "/nix/store/xyz-test",
		Deriver:          "/nix/store/abc-foo.drv",
		NarHash:          "sha256:abcdef",
		References:       []string{"/nix/store/def-bar"},
		RegistrationTime: 1700000000,
		NarSize:          54321,
		Ultimate:         true,               // Set, but should NOT be written at proto 1.15
		Sigs:             []string{"sig1"},   // Should NOT be written
		CA:               "fixed:sha256:abc", // Should NOT be written
	}

	var buf bytes.Buffer
	err := daemon.WritePathInfo(&buf, info, daemon.ProtoVersion(1, 15))
	assert.NoError(t, err)

	// Read back storePath (WritePathInfo writes it as first field)
	storePath, err := wire.ReadString(&buf, daemon.MaxStringSize)
	assert.NoError(t, err)
	assert.Equal(t, "/nix/store/xyz-test", storePath)

	// Read PathInfo at proto 1.15
	got, err := daemon.ReadPathInfo(&buf, storePath, daemon.ProtoVersion(1, 15))
	assert.NoError(t, err)

	// At proto 1.15: ultimate/sigs/ca are NOT written or read
	assert.Equal(t, info.StorePath, got.StorePath)
	assert.Equal(t, info.Deriver, got.Deriver)
	assert.Equal(t, info.NarHash, got.NarHash)
	assert.Equal(t, info.References, got.References)
	assert.Equal(t, info.RegistrationTime, got.RegistrationTime)
	assert.Equal(t, info.NarSize, got.NarSize)
	assert.False(t, got.Ultimate) // Zero value — not written
	assert.Nil(t, got.Sigs)       // Zero value — not written
	assert.Equal(t, "", got.CA)   // Zero value — not written

	// Buffer should be fully consumed
	assert.Equal(t, 0, buf.Len())
}

func TestReadPathInfoPreMeta(t *testing.T) {
	// Proto 1.15 (0x010f): no ultimate/sigs/ca fields
	var buf bytes.Buffer
	writeTestString(&buf, "/nix/store/abc-foo.drv")  // deriver
	writeTestString(&buf, "sha256:abcdef1234567890") // narHash
	writeTestUint64(&buf, 1)                         // references count
	writeTestString(&buf, "/nix/store/def-bar")      // reference
	writeTestUint64(&buf, 1700000000)                // registrationTime
	writeTestUint64(&buf, 12345)                     // narSize
	// NO ultimate, sigs, ca fields

	info, err := daemon.ReadPathInfo(&buf, "/nix/store/xyz-test", daemon.ProtoVersion(1, 15))
	assert.NoError(t, err)
	assert.Equal(t, "/nix/store/xyz-test", info.StorePath)
	assert.Equal(t, "/nix/store/abc-foo.drv", info.Deriver)
	assert.Equal(t, "sha256:abcdef1234567890", info.NarHash)
	assert.Equal(t, []string{"/nix/store/def-bar"}, info.References)
	assert.Equal(t, uint64(12345), info.NarSize)
	assert.False(t, info.Ultimate)
	assert.Nil(t, info.Sigs)
	assert.Equal(t, "", info.CA)
	assert.Equal(t, 0, buf.Len())
}

package daemon_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/require"
)

func TestPathInfoCodec(t *testing.T) {
	t.Run("Read", func(t *testing.T) {
		rq := require.New(t)

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

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		info, err := daemon.ReadPathInfo(dec, "/nix/store/xyz-test", daemon.ProtocolVersion)
		rq.NoError(err)
		rq.Equal("/nix/store/xyz-test", info.StorePath)
		rq.Equal("/nix/store/abc-foo.drv", info.Deriver)
		rq.Equal("sha256:abcdef1234567890", info.NarHash)
		rq.Equal([]string{"/nix/store/def-bar"}, info.References)
		rq.Equal(uint64(12345), info.NarSize)
		rq.True(info.Ultimate)
		rq.Equal([]string{"cache.example.com-1:abc123sig"}, info.Sigs)
	})

	t.Run("WriteReadRoundTrip", func(t *testing.T) {
		rq := require.New(t)

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

		enc := wire.NewEncoder(&buf)

		err := daemon.WritePathInfo(enc, info, daemon.ProtocolVersion)
		rq.NoError(err)

		// ReadPathInfo reads UnkeyedValidPathInfo (no storePath prefix),
		// but WritePathInfo writes ValidPathInfo (with storePath prefix).
		// So we need to read the storePath first.
		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		storePath, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("/nix/store/xyz-test", storePath)

		got, err := daemon.ReadPathInfo(dec, storePath, daemon.ProtocolVersion)
		rq.NoError(err)
		rq.Equal(info, got)
	})

	t.Run("WriteNil", func(t *testing.T) {
		var buf bytes.Buffer

		enc := wire.NewEncoder(&buf)

		err := daemon.WritePathInfo(enc, nil, daemon.ProtocolVersion)
		require.ErrorIs(t, err, daemon.ErrNilPathInfo)
	})

	t.Run("ReadPreMeta", func(t *testing.T) {
		rq := require.New(t)

		// Proto 1.15 (0x010f): no ultimate/sigs/ca fields
		var buf bytes.Buffer
		writeTestString(&buf, "/nix/store/abc-foo.drv")  // deriver
		writeTestString(&buf, "sha256:abcdef1234567890") // narHash
		writeTestUint64(&buf, 1)                         // references count
		writeTestString(&buf, "/nix/store/def-bar")      // reference
		writeTestUint64(&buf, 1700000000)                // registrationTime
		writeTestUint64(&buf, 12345)                     // narSize
		// NO ultimate, sigs, ca fields

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		info, err := daemon.ReadPathInfo(dec, "/nix/store/xyz-test", daemon.ProtoVersion(1, 15))
		rq.NoError(err)
		rq.Equal("/nix/store/xyz-test", info.StorePath)
		rq.Equal("/nix/store/abc-foo.drv", info.Deriver)
		rq.Equal("sha256:abcdef1234567890", info.NarHash)
		rq.Equal([]string{"/nix/store/def-bar"}, info.References)
		rq.Equal(uint64(12345), info.NarSize)
		rq.False(info.Ultimate)
		rq.Nil(info.Sigs)
		rq.Equal("", info.CA)
		rq.Equal(0, buf.Len())
	})

	t.Run("WriteReadPreMeta", func(t *testing.T) {
		rq := require.New(t)

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

		enc := wire.NewEncoder(&buf)

		err := daemon.WritePathInfo(enc, info, daemon.ProtoVersion(1, 15))
		rq.NoError(err)

		// Read back storePath (WritePathInfo writes it as first field)
		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		storePath, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("/nix/store/xyz-test", storePath)

		// Read PathInfo at proto 1.15
		got, err := daemon.ReadPathInfo(dec, storePath, daemon.ProtoVersion(1, 15))
		rq.NoError(err)

		// At proto 1.15: ultimate/sigs/ca are NOT written or read
		rq.Equal(info.StorePath, got.StorePath)
		rq.Equal(info.Deriver, got.Deriver)
		rq.Equal(info.NarHash, got.NarHash)
		rq.Equal(info.References, got.References)
		rq.Equal(info.RegistrationTime, got.RegistrationTime)
		rq.Equal(info.NarSize, got.NarSize)
		rq.False(got.Ultimate) // Zero value — not written
		rq.Nil(got.Sigs)       // Zero value — not written
		rq.Equal("", got.CA)   // Zero value — not written

		// Buffer should be fully consumed
		rq.Equal(0, buf.Len())
	})
}

func TestBasicDerivationCodec(t *testing.T) {
	t.Run("Write", func(t *testing.T) {
		rq := require.New(t)

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

		enc := wire.NewEncoder(&buf)

		err := daemon.WriteBasicDerivation(enc, drv)
		rq.NoError(err)

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		// verify outputs count = 2
		count, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(2), count)

		// first output should be "dev" (sorted)
		name, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("dev", name)

		path, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("/nix/store/abc-dev", path)

		hashAlgo, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("", hashAlgo)

		hash, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("", hash)

		// second output should be "out"
		name, err = dec.ReadString()
		rq.NoError(err)
		rq.Equal("out", name)

		path, err = dec.ReadString()
		rq.NoError(err)
		rq.Equal("/nix/store/abc-out", path)

		_, err = dec.ReadString() // hashAlgo
		rq.NoError(err)

		_, err = dec.ReadString() // hash
		rq.NoError(err)

		// verify inputs count = 2
		count, err = dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(2), count)

		input1, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("/nix/store/def-input", input1)

		input2, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("/nix/store/ghi-input", input2)

		// verify platform
		platform, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("x86_64-linux", platform)

		// verify builder
		builder, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("/nix/store/bash/bin/bash", builder)

		// verify args count = 2
		count, err = dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(2), count)

		arg1, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("-e", arg1)

		arg2, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("builder.sh", arg2)

		// verify env count = 2 (sorted: "dev" < "out")
		count, err = dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(2), count)

		key1, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("dev", key1)

		val1, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("/nix/store/abc-dev", val1)

		key2, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("out", key2)

		val2, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("/nix/store/abc-out", val2)

		// buffer should be fully consumed
		rq.Equal(0, buf.Len())
	})

	t.Run("WriteEmpty", func(t *testing.T) {
		rq := require.New(t)

		drv := &daemon.BasicDerivation{
			Outputs:  map[string]daemon.DerivationOutput{},
			Inputs:   []string{},
			Platform: "x86_64-linux",
			Builder:  "/bin/sh",
			Args:     []string{},
			Env:      map[string]string{},
		}

		var buf bytes.Buffer

		enc := wire.NewEncoder(&buf)

		err := daemon.WriteBasicDerivation(enc, drv)
		rq.NoError(err)

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		// outputs count = 0
		count, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(0), count)

		// inputs count = 0
		count, err = dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(0), count)

		// platform
		platform, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("x86_64-linux", platform)

		// builder
		builder, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("/bin/sh", builder)

		// args count = 0
		count, err = dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(0), count)

		// env count = 0
		count, err = dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(0), count)

		rq.Equal(0, buf.Len())
	})

	t.Run("WriteNil", func(t *testing.T) {
		var buf bytes.Buffer

		enc := wire.NewEncoder(&buf)

		err := daemon.WriteBasicDerivation(enc, nil)
		require.ErrorIs(t, err, daemon.ErrNilDerivation)
	})

	t.Run("WriteUnsortedInput", func(t *testing.T) {
		rq := require.New(t)

		// Provide output names in reverse order; verify they come out sorted.
		drv := &daemon.BasicDerivation{
			Outputs: map[string]daemon.DerivationOutput{
				"zzz": {Path: "/nix/store/zzz-out"},
				"aaa": {Path: "/nix/store/aaa-out"},
			},
			Inputs:   []string{},
			Platform: "x86_64-linux",
			Builder:  "/bin/sh",
			Args:     []string{},
			Env:      map[string]string{},
		}

		var buf bytes.Buffer

		enc := wire.NewEncoder(&buf)

		err := daemon.WriteBasicDerivation(enc, drv)
		rq.NoError(err)

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		// outputs count = 2
		count, err := dec.ReadUint64()
		rq.NoError(err)
		rq.Equal(uint64(2), count)

		// first output must be "aaa" (sorted)
		name, err := dec.ReadString()
		rq.NoError(err)
		rq.Equal("aaa", name)
	})
}

func TestBuildResultCodec(t *testing.T) {
	t.Run("Read", func(t *testing.T) {
		rq := require.New(t)

		var buf bytes.Buffer

		writeTestUint64(&buf, 0)          // status = Built
		writeTestString(&buf, "")         // errorMsg
		writeTestUint64(&buf, 1)          // timesBuilt
		writeTestUint64(&buf, 0)          // isNonDeterministic = false
		writeTestUint64(&buf, 1700000000) // startTime
		writeTestUint64(&buf, 1700000060) // stopTime
		writeTestUint64(&buf, 0)          // cpuUser: None
		writeTestUint64(&buf, 0)          // cpuSystem: None
		writeTestUint64(&buf, 1)          // builtOutputs count
		writeTestString(&buf, "out")      // output name
		writeTestString(
			&buf,
			`{"id":"sha256:abc123!out","outPath":"/nix/store/zzz-hello","signatures":["mykey:c2ln"],"dependentRealisations":{}}`,
		)

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		result, err := daemon.ReadBuildResult(dec, daemon.ProtocolVersion)
		rq.NoError(err)
		rq.Equal(daemon.BuildStatusBuilt, result.Status)
		rq.Equal("", result.ErrorMsg)
		rq.Equal(uint64(1), result.TimesBuilt)
		rq.False(result.IsNonDeterministic)
		rq.Equal(uint64(1700000000), result.StartTime)
		rq.Equal(uint64(1700000060), result.StopTime)
		rq.Nil(result.CpuUser)
		rq.Nil(result.CpuSystem)
		rq.Len(result.BuiltOutputs, 1)

		realisation := result.BuiltOutputs["out"]
		rq.Equal("sha256:abc123!out", realisation.ID)
		rq.Equal("/nix/store/zzz-hello", realisation.OutPath)
		rq.Equal([]string{"mykey:c2ln"}, realisation.Signatures)
		rq.Empty(realisation.DependentRealisations)
	})

	t.Run("ReadNoOutputs", func(t *testing.T) {
		rq := require.New(t)

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

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		result, err := daemon.ReadBuildResult(dec, daemon.ProtocolVersion)
		rq.NoError(err)
		rq.Equal(daemon.BuildStatusPermanentFailure, result.Status)
		rq.Equal("build failed", result.ErrorMsg)
		rq.Nil(result.CpuUser)
		rq.Nil(result.CpuSystem)
		rq.Empty(result.BuiltOutputs)
	})

	t.Run("ReadWithCPUTimes", func(t *testing.T) {
		rq := require.New(t)

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

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		result, err := daemon.ReadBuildResult(dec, daemon.ProtocolVersion)
		rq.NoError(err)
		rq.Equal(daemon.BuildStatusBuilt, result.Status)
		rq.Equal(uint64(1), result.TimesBuilt)
		rq.Equal(uint64(1700000000), result.StartTime)
		rq.Equal(uint64(1700000060), result.StopTime)

		expectedCpuUser := 500 * time.Millisecond
		rq.Equal(&expectedCpuUser, result.CpuUser)
		rq.Nil(result.CpuSystem)

		rq.Empty(result.BuiltOutputs)
		rq.Equal(0, buf.Len())
	})

	t.Run("ReadBothCPUPresent", func(t *testing.T) {
		rq := require.New(t)

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
		writeTestUint64(&buf, 1)      // tag: present
		writeTestUint64(&buf, 250000) // value
		writeTestUint64(&buf, 1)      // builtOutputs count
		writeTestString(&buf, "out")  // output name
		writeTestString(
			&buf,
			`{"id":"sha256:def456!out","outPath":"/nix/store/yyy-world","signatures":[],"dependentRealisations":{}}`,
		)

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		result, err := daemon.ReadBuildResult(dec, daemon.ProtocolVersion)
		rq.NoError(err)
		rq.Equal(daemon.BuildStatusBuilt, result.Status)
		rq.Equal(uint64(2), result.TimesBuilt)

		expectedCpuUser := time.Second
		expectedCpuSystem := 250 * time.Millisecond

		rq.Equal(&expectedCpuUser, result.CpuUser)
		rq.Equal(&expectedCpuSystem, result.CpuSystem)

		rq.Len(result.BuiltOutputs, 1)
		rq.Equal("sha256:def456!out", result.BuiltOutputs["out"].ID)
		rq.Equal("/nix/store/yyy-world", result.BuiltOutputs["out"].OutPath)
		rq.Equal(0, buf.Len())
	})

	t.Run("ReadBothCPUAbsent", func(t *testing.T) {
		rq := require.New(t)

		// Proto 1.37+: both cpuUser and cpuSystem absent (tag 0).
		var buf bytes.Buffer
		writeTestUint64(&buf, 0)          // status = Built
		writeTestString(&buf, "")         // errorMsg
		writeTestUint64(&buf, 1)          // timesBuilt
		writeTestUint64(&buf, 0)          // isNonDeterministic
		writeTestUint64(&buf, 1700000000) // startTime
		writeTestUint64(&buf, 1700000060) // stopTime
		writeTestUint64(&buf, 0)          // cpuUser: None
		writeTestUint64(&buf, 0)          // cpuSystem: None
		writeTestUint64(&buf, 0)          // builtOutputs count

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		result, err := daemon.ReadBuildResult(dec, daemon.ProtoVersion(1, 37))
		rq.NoError(err)
		rq.Nil(result.CpuUser)
		rq.Nil(result.CpuSystem)
		rq.Equal(0, buf.Len())
	})

	t.Run("ReadProto127", func(t *testing.T) {
		rq := require.New(t)

		// Proto 1.27 (0x011b): only status + errorMsg (no timing, no CPU, no builtOutputs)
		var buf bytes.Buffer
		writeTestUint64(&buf, 0)            // status = Built
		writeTestString(&buf, "some error") // errorMsg

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		result, err := daemon.ReadBuildResult(dec, daemon.ProtoVersion(1, 27))
		rq.NoError(err)
		rq.Equal(daemon.BuildStatusBuilt, result.Status)
		rq.Equal("some error", result.ErrorMsg)
		rq.Equal(uint64(0), result.TimesBuilt)
		rq.False(result.IsNonDeterministic)
		rq.Equal(uint64(0), result.StartTime)
		rq.Equal(uint64(0), result.StopTime)
		rq.Nil(result.BuiltOutputs)
		rq.Equal(0, buf.Len())
	})

	t.Run("ReadProto128", func(t *testing.T) {
		rq := require.New(t)

		// Proto 1.28 (0x011c): status + errorMsg + builtOutputs (no timing, no CPU)
		var buf bytes.Buffer
		writeTestUint64(&buf, 1)     // status = Substituted
		writeTestString(&buf, "")    // errorMsg
		writeTestUint64(&buf, 1)     // builtOutputs count
		writeTestString(&buf, "out") // output name
		writeTestString(
			&buf,
			`{"id":"sha256:abc!out","outPath":"/nix/store/zzz-pkg","signatures":[],"dependentRealisations":{}}`,
		)

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		result, err := daemon.ReadBuildResult(dec, daemon.ProtoVersion(1, 28))
		rq.NoError(err)
		rq.Equal(daemon.BuildStatusSubstituted, result.Status)
		rq.Equal(uint64(0), result.TimesBuilt) // no timing fields
		rq.Len(result.BuiltOutputs, 1)
		rq.Equal("sha256:abc!out", result.BuiltOutputs["out"].ID)
		rq.Equal("/nix/store/zzz-pkg", result.BuiltOutputs["out"].OutPath)
		rq.Equal(0, buf.Len())
	})

	t.Run("ReadProto129", func(t *testing.T) {
		rq := require.New(t)

		// Proto 1.29 (0x011d): status + errorMsg + timing + builtOutputs (no CPU)
		var buf bytes.Buffer
		writeTestUint64(&buf, 0)          // status = Built
		writeTestString(&buf, "")         // errorMsg
		writeTestUint64(&buf, 3)          // timesBuilt
		writeTestUint64(&buf, 1)          // isNonDeterministic = true
		writeTestUint64(&buf, 1700000000) // startTime
		writeTestUint64(&buf, 1700000060) // stopTime
		writeTestUint64(&buf, 0)          // builtOutputs count

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		result, err := daemon.ReadBuildResult(dec, daemon.ProtoVersion(1, 29))
		rq.NoError(err)
		rq.Equal(daemon.BuildStatusBuilt, result.Status)
		rq.Equal(uint64(3), result.TimesBuilt)
		rq.True(result.IsNonDeterministic)
		rq.Equal(uint64(1700000000), result.StartTime)
		rq.Equal(uint64(1700000060), result.StopTime)
		rq.Empty(result.BuiltOutputs)
		rq.Equal(0, buf.Len())
	})

	t.Run("ReadTruncated", func(t *testing.T) {
		rq := require.New(t)

		// Only write status, then EOF — errorMsg read should fail.
		var buf bytes.Buffer
		writeTestUint64(&buf, 0) // status = Built
		// no errorMsg — truncated

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		_, err := daemon.ReadBuildResult(dec, daemon.ProtocolVersion)
		rq.Error(err)

		var pe *daemon.ProtocolError
		rq.ErrorAs(err, &pe)
		rq.Contains(pe.Op, "errorMsg")
	})

	t.Run("ReadInvalidJSON", func(t *testing.T) {
		rq := require.New(t)

		// Proto 1.28 has builtOutputs. Provide valid wire framing but malformed JSON.
		var buf bytes.Buffer
		writeTestUint64(&buf, 0)                   // status = Built
		writeTestString(&buf, "")                  // errorMsg
		writeTestUint64(&buf, 1)                   // builtOutputs count
		writeTestString(&buf, "out")               // output name
		writeTestString(&buf, "not valid json {!") // malformed JSON

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		_, err := daemon.ReadBuildResult(dec, daemon.ProtoVersion(1, 28))
		rq.Error(err)

		var pe *daemon.ProtocolError
		rq.ErrorAs(err, &pe)
		rq.Contains(pe.Op, "JSON")
	})

	t.Run("ReadInvalidOptionalTag", func(t *testing.T) {
		rq := require.New(t)

		// Proto 1.37+: cpuUser uses optional<microseconds>. Send invalid tag 2.
		var buf bytes.Buffer
		writeTestUint64(&buf, 0)          // status = Built
		writeTestString(&buf, "")         // errorMsg
		writeTestUint64(&buf, 1)          // timesBuilt
		writeTestUint64(&buf, 0)          // isNonDeterministic
		writeTestUint64(&buf, 1700000000) // startTime
		writeTestUint64(&buf, 1700000060) // stopTime
		writeTestUint64(&buf, 2)          // cpuUser tag: INVALID (not 0 or 1)

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		_, err := daemon.ReadBuildResult(dec, daemon.ProtoVersion(1, 37))
		rq.Error(err)

		var pe *daemon.ProtocolError
		rq.ErrorAs(err, &pe)
		rq.Contains(pe.Error(), "optional tag")
	})
}

func TestCodecRoundTrips(t *testing.T) {
	t.Run("GCOptions", func(t *testing.T) {
		rq := require.New(t)

		opts := &daemon.GCOptions{
			Action:         daemon.GCDeleteSpecific,
			PathsToDelete:  []string{"/nix/store/abc-foo", "/nix/store/def-bar"},
			IgnoreLiveness: true,
			MaxFreed:       1024 * 1024 * 100,
		}

		var buf bytes.Buffer

		enc := wire.NewEncoder(&buf)
		err := enc.Encode(opts)
		rq.NoError(err)

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		var got daemon.GCOptions

		err = dec.Decode(&got)
		rq.NoError(err)

		rq.Equal(opts.Action, got.Action)
		rq.Equal(opts.PathsToDelete, got.PathsToDelete)
		rq.Equal(opts.IgnoreLiveness, got.IgnoreLiveness)
		rq.Equal(opts.MaxFreed, got.MaxFreed)
		rq.Equal(0, buf.Len())
	})

	t.Run("GCResult", func(t *testing.T) {
		rq := require.New(t)

		result := &daemon.GCResult{
			Paths:      []string{"/nix/store/abc-foo", "/nix/store/def-bar"},
			BytesFreed: 987654321,
		}

		var buf bytes.Buffer

		enc := wire.NewEncoder(&buf)
		err := enc.Encode(result)
		rq.NoError(err)

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		var got daemon.GCResult

		err = dec.Decode(&got)
		rq.NoError(err)

		rq.Equal(result.Paths, got.Paths)
		rq.Equal(result.BytesFreed, got.BytesFreed)
		rq.Equal(0, buf.Len())
	})

	t.Run("SubstitutablePathInfo", func(t *testing.T) {
		rq := require.New(t)

		info := &daemon.SubstitutablePathInfo{
			Deriver:      "/nix/store/abc-foo.drv",
			References:   []string{"/nix/store/def-bar", "/nix/store/ghi-baz"},
			DownloadSize: 12345678,
			NarSize:      87654321,
		}

		var buf bytes.Buffer

		enc := wire.NewEncoder(&buf)
		err := enc.Encode(info)
		rq.NoError(err)

		dec := wire.NewDecoder(&buf, daemon.MaxStringSize)

		var got daemon.SubstitutablePathInfo

		err = dec.Decode(&got)
		rq.NoError(err)

		rq.Equal(info.Deriver, got.Deriver)
		rq.Equal(info.References, got.References)
		rq.Equal(info.DownloadSize, got.DownloadSize)
		rq.Equal(info.NarSize, got.NarSize)
		rq.Equal(0, buf.Len())
	})
}

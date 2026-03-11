package daemon

import (
	"fmt"
	"io"
	"sort"

	"github.com/nix-community/go-nix/pkg/wire"
)

// readAck reads the daemon's acknowledgment uint64 and verifies it equals 1.
func readAck(r io.Reader) error {
	v, err := wire.ReadUint64(r)
	if err != nil {
		return err
	}

	if v != 1 {
		return &ProtocolError{
			Op:  "read ack",
			Err: fmt.Errorf("expected ack value 1, got %d", v),
		}
	}

	return nil
}

// WriteStrings writes a list of strings as count + entries.
func WriteStrings(w io.Writer, ss []string) error {
	if err := wire.WriteUint64(w, uint64(len(ss))); err != nil {
		return err
	}

	for _, s := range ss {
		if err := wire.WriteString(w, s); err != nil {
			return err
		}
	}

	return nil
}

// ReadStrings reads a list of strings.
func ReadStrings(r io.Reader, maxBytes uint64) ([]string, error) {
	count, err := wire.ReadUint64(r)
	if err != nil {
		return nil, &ProtocolError{Op: "read string list count", Err: err}
	}

	// Guard against unreasonable allocation from a malicious or corrupted peer.
	maxCount := uint64(MaxListEntries)
	if maxBytes/8 < maxCount {
		maxCount = maxBytes / 8
	}

	if count > maxCount {
		return nil, &ProtocolError{
			Op:  "read string list count",
			Err: fmt.Errorf("string list count %d exceeds limit %d", count, maxCount),
		}
	}

	ss := make([]string, count)

	for i := uint64(0); i < count; i++ {
		s, err := wire.ReadString(r, maxBytes)
		if err != nil {
			return nil, &ProtocolError{Op: "read string list entry", Err: err}
		}

		ss[i] = s
	}

	return ss, nil
}

// WriteStringMap writes a map as count + sorted key/value pairs.
func WriteStringMap(w io.Writer, m map[string]string) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	if err := wire.WriteUint64(w, uint64(len(keys))); err != nil {
		return err
	}

	for _, k := range keys {
		if err := wire.WriteString(w, k); err != nil {
			return err
		}

		if err := wire.WriteString(w, m[k]); err != nil {
			return err
		}
	}

	return nil
}

// ReadStringMap reads a map of string key/value pairs.
func ReadStringMap(r io.Reader, maxBytes uint64) (map[string]string, error) {
	count, err := wire.ReadUint64(r)
	if err != nil {
		return nil, &ProtocolError{Op: "read string map count", Err: err}
	}

	// Guard against unreasonable allocation from a malicious or corrupted peer.
	maxCount := uint64(MaxMapEntries)
	if maxBytes/8 < maxCount {
		maxCount = maxBytes / 8
	}

	if count > maxCount {
		return nil, &ProtocolError{
			Op:  "read string map count",
			Err: fmt.Errorf("string map count %d exceeds limit %d", count, maxCount),
		}
	}

	m := make(map[string]string, count)

	for i := uint64(0); i < count; i++ {
		key, err := wire.ReadString(r, maxBytes)
		if err != nil {
			return nil, &ProtocolError{Op: "read string map key", Err: err}
		}

		val, err := wire.ReadString(r, maxBytes)
		if err != nil {
			return nil, &ProtocolError{Op: "read string map value", Err: err}
		}

		m[key] = val
	}

	return m, nil
}

// ReadPathInfo reads a full PathInfo from the wire (UnkeyedValidPathInfo format).
// storePath is provided separately (already known by the caller).
// The version parameter is the negotiated protocol version.
func ReadPathInfo(r io.Reader, storePath string, version uint64) (*PathInfo, error) {
	deriver, err := wire.ReadString(r, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "read path info deriver", Err: err}
	}

	narHash, err := wire.ReadString(r, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "read path info narHash", Err: err}
	}

	references, err := ReadStrings(r, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "read path info references", Err: err}
	}

	registrationTime, err := wire.ReadUint64(r)
	if err != nil {
		return nil, &ProtocolError{Op: "read path info registrationTime", Err: err}
	}

	narSize, err := wire.ReadUint64(r)
	if err != nil {
		return nil, &ProtocolError{Op: "read path info narSize", Err: err}
	}

	info := &PathInfo{
		StorePath:        storePath,
		Deriver:          deriver,
		NarHash:          narHash,
		References:       references,
		RegistrationTime: registrationTime,
		NarSize:          narSize,
	}

	// Protocol >= 1.16: ultimate, sigs, ca.
	if version >= ProtoVersionPathInfoMeta {
		info.Ultimate, err = wire.ReadBool(r)
		if err != nil {
			return nil, &ProtocolError{Op: "read path info ultimate", Err: err}
		}

		info.Sigs, err = ReadStrings(r, MaxStringSize)
		if err != nil {
			return nil, &ProtocolError{Op: "read path info sigs", Err: err}
		}

		info.CA, err = wire.ReadString(r, MaxStringSize)
		if err != nil {
			return nil, &ProtocolError{Op: "read path info contentAddress", Err: err}
		}
	}

	return info, nil
}

// WritePathInfo writes a PathInfo in ValidPathInfo wire format.
// The version parameter is the negotiated protocol version.
func WritePathInfo(w io.Writer, info *PathInfo, version uint64) error {
	if err := wire.WriteString(w, info.StorePath); err != nil {
		return err
	}

	if err := wire.WriteString(w, info.Deriver); err != nil {
		return err
	}

	if err := wire.WriteString(w, info.NarHash); err != nil {
		return err
	}

	if err := WriteStrings(w, info.References); err != nil {
		return err
	}

	if err := wire.WriteUint64(w, info.RegistrationTime); err != nil {
		return err
	}

	if err := wire.WriteUint64(w, info.NarSize); err != nil {
		return err
	}

	// Protocol >= 1.16: ultimate, sigs, ca.
	if version >= ProtoVersionPathInfoMeta {
		if err := wire.WriteBool(w, info.Ultimate); err != nil {
			return err
		}

		if err := WriteStrings(w, info.Sigs); err != nil {
			return err
		}

		if err := wire.WriteString(w, info.CA); err != nil {
			return err
		}
	}

	return nil
}

// WriteBasicDerivation writes a BasicDerivation to the wire. Outputs are
// written sorted by name; environment variables are written sorted by key.
func WriteBasicDerivation(w io.Writer, drv *BasicDerivation) error {
	// Outputs: count + sorted entries.
	outputNames := make([]string, 0, len(drv.Outputs))
	for name := range drv.Outputs {
		outputNames = append(outputNames, name)
	}

	sort.Strings(outputNames)

	if err := wire.WriteUint64(w, uint64(len(outputNames))); err != nil {
		return err
	}

	for _, name := range outputNames {
		out := drv.Outputs[name]

		if err := wire.WriteString(w, name); err != nil {
			return err
		}

		if err := wire.WriteString(w, out.Path); err != nil {
			return err
		}

		if err := wire.WriteString(w, out.HashAlgorithm); err != nil {
			return err
		}

		if err := wire.WriteString(w, out.Hash); err != nil {
			return err
		}
	}

	// Inputs: count + strings.
	if err := WriteStrings(w, drv.Inputs); err != nil {
		return err
	}

	// Platform.
	if err := wire.WriteString(w, drv.Platform); err != nil {
		return err
	}

	// Builder.
	if err := wire.WriteString(w, drv.Builder); err != nil {
		return err
	}

	// Args: count + strings.
	if err := WriteStrings(w, drv.Args); err != nil {
		return err
	}

	// Env: count + sorted key/value pairs.
	return WriteStringMap(w, drv.Env)
}

// readOptionalMicroseconds reads an optional<microseconds> from the wire.
// Wire format: tag(uint64: 0=none, 1=some) [+ value(uint64) if tag=1].
// The value is consumed but not returned since we don't currently expose
// CPU times in BuildResult.
func readOptionalMicroseconds(r io.Reader) error {
	tag, err := wire.ReadUint64(r)
	if err != nil {
		return err
	}

	if tag == optionalSome {
		if _, err := wire.ReadUint64(r); err != nil {
			return err
		}
	}

	return nil
}

// ReadBuildResult reads a BuildResult from the wire.
// The version parameter is the negotiated protocol version.
func ReadBuildResult(r io.Reader, version uint64) (*BuildResult, error) {
	status, err := wire.ReadUint64(r)
	if err != nil {
		return nil, &ProtocolError{Op: "read build result status", Err: err}
	}

	errorMsg, err := wire.ReadString(r, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "read build result errorMsg", Err: err}
	}

	result := &BuildResult{
		Status:   BuildStatus(status),
		ErrorMsg: errorMsg,
	}

	// Protocol >= 1.29: timing fields.
	if version >= ProtoVersionBuildTimes {
		result.TimesBuilt, err = wire.ReadUint64(r)
		if err != nil {
			return nil, &ProtocolError{Op: "read build result timesBuilt", Err: err}
		}

		result.IsNonDeterministic, err = wire.ReadBool(r)
		if err != nil {
			return nil, &ProtocolError{Op: "read build result isNonDeterministic", Err: err}
		}

		result.StartTime, err = wire.ReadUint64(r)
		if err != nil {
			return nil, &ProtocolError{Op: "read build result startTime", Err: err}
		}

		result.StopTime, err = wire.ReadUint64(r)
		if err != nil {
			return nil, &ProtocolError{Op: "read build result stopTime", Err: err}
		}
	}

	// Protocol >= 1.37: cpuUser and cpuSystem as optional<microseconds>.
	if version >= ProtoVersionCPUTimes {
		if err := readOptionalMicroseconds(r); err != nil {
			return nil, &ProtocolError{Op: "read build result cpuUser", Err: err}
		}

		if err := readOptionalMicroseconds(r); err != nil {
			return nil, &ProtocolError{Op: "read build result cpuSystem", Err: err}
		}
	}

	// Protocol >= 1.28: builtOutputs map.
	if version >= ProtoVersionBuiltOutputs {
		nrOutputs, err := wire.ReadUint64(r)
		if err != nil {
			return nil, &ProtocolError{Op: "read build result builtOutputs count", Err: err}
		}

		builtOutputs := make(map[string]Realisation, nrOutputs)

		for i := uint64(0); i < nrOutputs; i++ {
			name, err := wire.ReadString(r, MaxStringSize)
			if err != nil {
				return nil, &ProtocolError{Op: "read build result output name", Err: err}
			}

			realisationJSON, err := wire.ReadString(r, MaxStringSize)
			if err != nil {
				return nil, &ProtocolError{Op: "read build result realisation", Err: err}
			}

			builtOutputs[name] = Realisation{ID: realisationJSON}
		}

		result.BuiltOutputs = builtOutputs
	}

	return result, nil
}

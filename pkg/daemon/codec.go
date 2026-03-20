package daemon

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

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

	references, err := wire.ReadStrings(r, MaxStringSize)
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

		info.Sigs, err = wire.ReadStrings(r, MaxStringSize)
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
	if info == nil {
		return ErrNilPathInfo
	}

	if err := wire.WriteString(w, info.StorePath); err != nil {
		return err
	}

	if err := wire.WriteString(w, info.Deriver); err != nil {
		return err
	}

	if err := wire.WriteString(w, info.NarHash); err != nil {
		return err
	}

	if err := wire.WriteStrings(w, info.References); err != nil {
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

		if err := wire.WriteStrings(w, info.Sigs); err != nil {
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
	if drv == nil {
		return ErrNilDerivation
	}

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
	if err := wire.WriteStrings(w, drv.Inputs); err != nil {
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
	if err := wire.WriteStrings(w, drv.Args); err != nil {
		return err
	}

	// Env: count + sorted key/value pairs.
	return wire.WriteStringMap(w, drv.Env)
}

// readOptionalMicroseconds reads an optional<microseconds> from the wire.
// Wire format: tag(uint64: 0=none, 1=some) [+ value(uint64) if tag=1].
// Returns nil if absent, or a pointer to the duration if present.
func readOptionalMicroseconds(r io.Reader) (*time.Duration, error) {
	tag, err := wire.ReadUint64(r)
	if err != nil {
		return nil, err
	}

	switch tag {
	case 0: // none
		return nil, nil
	case optionalSome:
		us, err := wire.ReadUint64(r)
		if err != nil {
			return nil, err
		}

		d := time.Duration(us) * time.Microsecond

		return &d, nil
	default:
		return nil, &ProtocolError{
			Op:  "read optional microseconds",
			Err: fmt.Errorf("unexpected optional tag %d", tag),
		}
	}
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
		result.CpuUser, err = readOptionalMicroseconds(r)
		if err != nil {
			return nil, &ProtocolError{Op: "read build result cpuUser", Err: err}
		}

		result.CpuSystem, err = readOptionalMicroseconds(r)
		if err != nil {
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

			var real Realisation
			if err := json.Unmarshal([]byte(realisationJSON), &real); err != nil {
				return nil, &ProtocolError{Op: "read build result realisation JSON", Err: err}
			}

			builtOutputs[name] = real
		}

		result.BuiltOutputs = builtOutputs
	}

	return result, nil
}

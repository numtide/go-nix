package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/nix-community/go-nix/pkg/wire"
)

var ErrOptionalEmpty = errors.New("optional field is empty")

// readAck reads the daemon's acknowledgment uint64 and verifies it equals 1.
func readAck(dec *wire.Decoder) error {
	v, err := dec.ReadUint64()
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
func ReadPathInfo(dec *wire.Decoder, storePath string, version uint64) (*PathInfo, error) {
	deriver, err := dec.ReadString()
	if err != nil {
		return nil, &ProtocolError{Op: "read path info deriver", Err: err}
	}

	narHash, err := dec.ReadString()
	if err != nil {
		return nil, &ProtocolError{Op: "read path info narHash", Err: err}
	}

	references, err := dec.ReadStrings()
	if err != nil {
		return nil, &ProtocolError{Op: "read path info references", Err: err}
	}

	registrationTime, err := dec.ReadUint64()
	if err != nil {
		return nil, &ProtocolError{Op: "read path info registrationTime", Err: err}
	}

	narSize, err := dec.ReadUint64()
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
		info.Ultimate, err = dec.ReadBool()
		if err != nil {
			return nil, &ProtocolError{Op: "read path info ultimate", Err: err}
		}

		info.Sigs, err = dec.ReadStrings()
		if err != nil {
			return nil, &ProtocolError{Op: "read path info sigs", Err: err}
		}

		info.CA, err = dec.ReadString()
		if err != nil {
			return nil, &ProtocolError{Op: "read path info contentAddress", Err: err}
		}
	}

	return info, nil
}

// WritePathInfo writes a PathInfo in ValidPathInfo wire format.
// The version parameter is the negotiated protocol version.
func WritePathInfo(enc *wire.Encoder, info *PathInfo, version uint64) error {
	if info == nil {
		return ErrNilPathInfo
	}

	if err := enc.WriteString(info.StorePath); err != nil {
		return err
	}

	if err := enc.WriteString(info.Deriver); err != nil {
		return err
	}

	if err := enc.WriteString(info.NarHash); err != nil {
		return err
	}

	if err := enc.WriteStrings(info.References); err != nil {
		return err
	}

	if err := enc.WriteUint64(info.RegistrationTime); err != nil {
		return err
	}

	if err := enc.WriteUint64(info.NarSize); err != nil {
		return err
	}

	// Protocol >= 1.16: ultimate, sigs, ca.
	if version >= ProtoVersionPathInfoMeta {
		if err := enc.WriteBool(info.Ultimate); err != nil {
			return err
		}

		if err := enc.WriteStrings(info.Sigs); err != nil {
			return err
		}

		if err := enc.WriteString(info.CA); err != nil {
			return err
		}
	}

	return nil
}

// WriteBasicDerivation writes a BasicDerivation to the wire.
// Outputs are written sorted by name.
// Environment variables are written sorted by key.
func WriteBasicDerivation(enc *wire.Encoder, drv *BasicDerivation) error {
	// nil check
	if drv == nil {
		return ErrNilDerivation
	}

	outputNames := make([]string, 0, len(drv.Outputs))
	for name := range drv.Outputs {
		outputNames = append(outputNames, name)
	}

	sort.Strings(outputNames)

	if err := enc.WriteUint64(uint64(len(outputNames))); err != nil {
		return err
	}

	for _, name := range outputNames {
		out := drv.Outputs[name]

		if err := enc.WriteString(name); err != nil {
			return err
		}

		if err := enc.WriteString(out.Path); err != nil {
			return err
		}

		if err := enc.WriteString(out.HashAlgorithm); err != nil {
			return err
		}

		if err := enc.WriteString(out.Hash); err != nil {
			return err
		}
	}

	if err := enc.WriteStrings(drv.Inputs); err != nil {
		return err
	}

	if err := enc.WriteString(drv.Platform); err != nil {
		return err
	}

	if err := enc.WriteString(drv.Builder); err != nil {
		return err
	}

	if err := enc.WriteStrings(drv.Args); err != nil {
		return err
	}

	return enc.WriteStringMap(drv.Env)
}

// readOptionalMicroseconds reads an optional<microseconds> from the wire.
// Wire format: tag(uint64: 0=none, 1=some) [+ value(uint64) if tag=1].
// Returns ErrOptionalEmpty if absent, or a pointer to the duration if present.
func readOptionalMicroseconds(dec *wire.Decoder) (*time.Duration, error) {
	tag, err := dec.ReadUint64()
	if err != nil {
		return nil, err
	}

	switch tag {
	case 0: // none
		return nil, ErrOptionalEmpty
	case optionalSome:
		us, err := dec.ReadUint64()
		if err != nil {
			return nil, err
		}

		d := time.Duration(us) * time.Microsecond //nolint:gosec // G115: microsecond values won't overflow int64

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
func ReadBuildResult(dec *wire.Decoder, version uint64) (*BuildResult, error) {
	status, err := dec.ReadUint64()
	if err != nil {
		return nil, &ProtocolError{Op: "read build result status", Err: err}
	}

	errorMsg, err := dec.ReadString()
	if err != nil {
		return nil, &ProtocolError{Op: "read build result errorMsg", Err: err}
	}

	result := &BuildResult{
		Status:   BuildStatus(status),
		ErrorMsg: errorMsg,
	}

	// Protocol >= 1.29: timing fields.
	if version >= ProtoVersionBuildTimes {
		result.TimesBuilt, err = dec.ReadUint64()
		if err != nil {
			return nil, &ProtocolError{Op: "read build result timesBuilt", Err: err}
		}

		result.IsNonDeterministic, err = dec.ReadBool()
		if err != nil {
			return nil, &ProtocolError{Op: "read build result isNonDeterministic", Err: err}
		}

		result.StartTime, err = dec.ReadUint64()
		if err != nil {
			return nil, &ProtocolError{Op: "read build result startTime", Err: err}
		}

		result.StopTime, err = dec.ReadUint64()
		if err != nil {
			return nil, &ProtocolError{Op: "read build result stopTime", Err: err}
		}
	}

	// Protocol >= 1.37: cpuUser and cpuSystem as optional<microseconds>.
	if version >= ProtoVersionCPUTimes {
		result.CpuUser, err = readOptionalMicroseconds(dec)
		if errors.Is(err, ErrOptionalEmpty) {
			// do nothing
		} else if err != nil {
			return nil, &ProtocolError{Op: "read build result cpuUser", Err: err}
		}

		result.CpuSystem, err = readOptionalMicroseconds(dec)
		if errors.Is(err, ErrOptionalEmpty) {
			// do nothing
		} else if err != nil {
			return nil, &ProtocolError{Op: "read build result cpuSystem", Err: err}
		}
	}

	// Protocol >= 1.28: builtOutputs map.
	if version >= ProtoVersionBuiltOutputs {
		nrOutputs, err := dec.ReadUint64()
		if err != nil {
			return nil, &ProtocolError{Op: "read build result builtOutputs count", Err: err}
		}

		builtOutputs := make(map[string]Realisation, nrOutputs)

		for range nrOutputs {
			name, err := dec.ReadString()
			if err != nil {
				return nil, &ProtocolError{Op: "read build result output name", Err: err}
			}

			realisationJSON, err := dec.ReadString()
			if err != nil {
				return nil, &ProtocolError{Op: "read build result realisation", Err: err}
			}

			var realisation Realisation
			if err := json.Unmarshal([]byte(realisationJSON), &realisation); err != nil {
				return nil, &ProtocolError{Op: "read build result realisation JSON", Err: err}
			}

			builtOutputs[name] = realisation
		}

		result.BuiltOutputs = builtOutputs
	}

	return result, nil
}

package daemon

import (
	"fmt"

	"github.com/nix-community/go-nix/pkg/wire"
)

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

func (info *UnkeyedPathInfo) Convert(c wire.Codec) error {
	if err := c.String(&info.Deriver); err != nil {
		return err
	}

	if err := c.String(&info.NarHash); err != nil {
		return err
	}

	if err := c.Strings(&info.References); err != nil {
		return err
	}

	if err := c.Uint64(&info.RegistrationTime); err != nil {
		return err
	}

	if err := c.Uint64(&info.NarSize); err != nil {
		return err
	}

	// Protocol >= 1.16: ultimate, sigs, ca.
	if c.Version() >= ProtoVersionPathInfoMeta {
		if err := c.Bool(&info.Ultimate); err != nil {
			return err
		}

		if err := c.Strings(&info.Sigs); err != nil {
			return err
		}

		if err := c.String(&info.CA); err != nil {
			return err
		}
	}

	return nil
}

func (info *PathInfo) Convert(c wire.Codec) error {
	if err := c.String(&info.StorePath); err != nil {
		return err
	}

	return info.UnkeyedPathInfo.Convert(c)
}

// ReadPathInfo reads a PathInfo from the wire in ValidPathInfo format
// (store path followed by UnkeyedValidPathInfo fields).
// The version parameter is the negotiated protocol version.
func ReadPathInfo(dec *wire.Decoder, version uint64) (*PathInfo, error) {
	info := PathInfo{}
	c := wire.NewDecoderNG(dec.Reader(), MaxStringSize, version)

	return &info, info.Convert(c)
}

// ReadUnkeyedPathInfo reads an UnkeyedPathInfo from the wire in UnkeyedValidPathInfo
// format (no store path; used e.g. by the QueryPathInfo response).
// The version parameter is the negotiated protocol version.
func ReadUnkeyedPathInfo(dec *wire.Decoder, version uint64) (*UnkeyedPathInfo, error) {
	info := UnkeyedPathInfo{}
	c := wire.NewDecoderNG(dec.Reader(), MaxStringSize, version)

	return &info, info.Convert(c)
}

// WritePathInfo writes a PathInfo in ValidPathInfo wire format.
// The version parameter is the negotiated protocol version.
func WritePathInfo(enc *wire.Encoder, info *PathInfo, version uint64) error {
	if info == nil {
		return ErrNilPathInfo
	}

	c := wire.NewEncoderNG(enc.Writer(), version)

	return info.Convert(c)
}

func (out *DerivationOutput) Convert(c wire.Codec) error {
	if err := c.String(&out.Path); err != nil {
		return err
	}

	if err := c.String(&out.HashAlgorithm); err != nil {
		return err
	}

	return c.String(&out.Hash)
}

func (drv *BasicDerivation) Convert(c wire.Codec) error {
	if err := wire.ConvertMap(c, &drv.Outputs); err != nil {
		return err
	}

	if err := c.Strings(&drv.Inputs); err != nil {
		return err
	}

	if err := c.String(&drv.Platform); err != nil {
		return err
	}

	if err := c.String(&drv.Builder); err != nil {
		return err
	}

	if err := c.Strings(&drv.Args); err != nil {
		return err
	}

	return c.StringMap(&drv.Env)
}

// WriteBasicDerivation writes a BasicDerivation to the wire.
// Outputs are written sorted by name.
// Environment variables are written sorted by key.
func WriteBasicDerivation(enc *wire.Encoder, drv *BasicDerivation) error {
	// nil check
	if drv == nil {
		return ErrNilDerivation
	}

	c := wire.NewEncoderNG(enc.Writer(), ProtoVersionFeatureExchange)

	return drv.Convert(c)
}

func (o *OptionalMicroseconds) Convert(c wire.Codec) error {
	tag := uint64(0)
	if o.Tag {
		tag = optionalSome
	}

	if err := c.Uint64(&tag); err != nil {
		return err
	}

	switch tag {
	case 0: // none
		o.Tag = false

		return nil
	case optionalSome:
		o.Tag = true

		return c.Uint64(&o.Microseconds)
	default:
		return fmt.Errorf("unexpected optional tag %d", tag)
	}
}

func (r *Realisation) Convert(c wire.Codec) error {
	// Version gate here in the future
	if err := c.JSON(r); err != nil {
		return &ProtocolError{Op: "realisation JSON", Err: err}
	}

	return nil
}

func (res *BuildResult) Convert(c wire.Codec) error {
	if err := c.Uint64((*uint64)(&res.Status)); err != nil {
		return &ProtocolError{Op: "build result status", Err: err}
	}

	if err := c.String(&res.ErrorMsg); err != nil {
		return &ProtocolError{Op: "build result errorMsg", Err: err}
	}

	if c.Version() >= ProtoVersionBuildTimes {
		if err := c.Uint64(&res.TimesBuilt); err != nil {
			return &ProtocolError{Op: "build result timesBuilt", Err: err}
		}

		if err := c.Bool(&res.IsNonDeterministic); err != nil {
			return &ProtocolError{Op: "build result isNonDeterministic", Err: err}
		}

		if err := c.Uint64(&res.StartTime); err != nil {
			return &ProtocolError{Op: "build result startTime", Err: err}
		}

		if err := c.Uint64(&res.StopTime); err != nil {
			return &ProtocolError{Op: "build result stopTime", Err: err}
		}
	}

	if c.Version() >= ProtoVersionCPUTimes {
		if err := res.CpuUser.Convert(c); err != nil {
			return &ProtocolError{Op: "build result cpuUser", Err: err}
		}

		if err := res.CpuSystem.Convert(c); err != nil {
			return &ProtocolError{Op: "build result cpuSystem", Err: err}
		}
	}

	if c.Version() >= ProtoVersionBuiltOutputs {
		return wire.ConvertMap(c, &res.BuiltOutputs)
	}

	return nil
}

// ReadBuildResult reads a BuildResult from the wire.
// The version parameter is the negotiated protocol version.
func ReadBuildResult(dec *wire.Decoder, version uint64) (*BuildResult, error) {
	res := BuildResult{}
	c := wire.NewDecoderNG(dec.Reader(), MaxStringSize, version)

	return &res, res.Convert(c)
}

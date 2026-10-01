package daemon

import (
	"errors"
	"io"

	"github.com/nix-community/go-nix/pkg/wire"
)

// AddToStoreRequest holds the parameters for the AddToStore operation.
type AddToStoreRequest struct {
	Name             string
	CAMethodWithAlgo string
	References       []string
	Repair           bool
	Source           io.Reader
}

// MarshalNix encodes AddToStoreRequest in Nix wire format.
func (r *AddToStoreRequest) MarshalNix(enc *wire.Encoder) (err error) {
	if err = enc.WriteString(r.Name); err != nil {
		return err
	}

	if err = enc.WriteString(r.CAMethodWithAlgo); err != nil {
		return err
	}

	if err = enc.WriteStrings(r.References); err != nil {
		return err
	}

	if err = enc.WriteBool(r.Repair); err != nil {
		return err
	}

	// stream source data as framed.
	fw := NewFramedWriter(enc.Writer())

	// ensure the fw is always closed and we catch the error
	defer func() {
		closeErr := fw.Close()
		if closeErr != nil && err == nil {
			err = errors.Join(err, closeErr)
		}
	}()

	if _, err = io.Copy(fw, r.Source); err != nil {
		return err
	}

	return nil
}

// BuildDerivationRequest holds the parameters for the BuildDerivation operation.
type BuildDerivationRequest struct {
	DrvPath    string
	Derivation *BasicDerivation
	Mode       BuildMode
}

func (r *BuildDerivationRequest) Convert(c wire.Codec) (err error) {
	if err := c.String(&r.DrvPath); err != nil {
		return err
	}

	if err := r.Derivation.Convert(c); err != nil {
		return err
	}

	return c.Uint64((*uint64)(&r.Mode))
}

// MarshalNix encodes BuildDerivationRequest in Nix wire format.
func (r *BuildDerivationRequest) MarshalNix(enc *wire.Encoder) error {
	if err := enc.WriteString(r.DrvPath); err != nil {
		return err
	}

	if err := WriteBasicDerivation(enc, r.Derivation); err != nil {
		return err
	}

	return enc.WriteUint64(uint64(r.Mode))
}

func (o *GCOptions) Convert(c wire.Codec) error {
	if err := c.Uint64((*uint64)(&o.Action)); err != nil {
		return err
	}

	if err := c.Strings(&o.PathsToDelete); err != nil {
		return err
	}

	if err := c.Bool(&o.IgnoreLiveness); err != nil {
		return err
	}

	if err := c.Uint64(&o.MaxFreed); err != nil {
		return err
	}

	// deprecated fields, always zero.
	var deprecated uint64
	for range numDeprecatedGCFields {
		if err := c.Uint64(&deprecated); err != nil {
			return err
		}
	}

	return nil
}

// MarshalNix encodes GCOptions in Nix wire format.
func (o *GCOptions) MarshalNix(enc *wire.Encoder) error {
	c := wire.NewEncoderNG(enc.Writer(), ProtoVersionFeatureExchange)

	return o.Convert(c)
}

// UnmarshalNix decodes GCOptions from Nix wire format.
func (o *GCOptions) UnmarshalNix(dec *wire.Decoder) error {
	c := wire.NewDecoderNG(dec.Reader(), MaxStringSize, ProtoVersionFeatureExchange)

	return o.Convert(c)
}

func (r *GCResult) Convert(c wire.Codec) error {
	if err := c.Strings(&r.Paths); err != nil {
		return err
	}

	if err := c.Uint64(&r.BytesFreed); err != nil {
		return err
	}

	// deprecated field, always zero.
	var deprecated uint64

	return c.Uint64(&deprecated)
}

// MarshalNix encodes GCResult in Nix wire format.
func (r *GCResult) MarshalNix(enc *wire.Encoder) error {
	c := wire.NewEncoderNG(enc.Writer(), ProtoVersionFeatureExchange)

	return r.Convert(c)
}

// UnmarshalNix decodes GCResult from Nix wire format.
func (r *GCResult) UnmarshalNix(dec *wire.Decoder) error {
	c := wire.NewDecoderNG(dec.Reader(), MaxStringSize, ProtoVersionFeatureExchange)

	return r.Convert(c)
}

func (s *SubstitutablePathInfo) Convert(c wire.Codec) error {
	if err := c.String(&s.Deriver); err != nil {
		return err
	}

	if err := c.Strings(&s.References); err != nil {
		return err
	}

	if err := c.Uint64(&s.DownloadSize); err != nil {
		return err
	}

	return c.Uint64(&s.NarSize)
}

// MarshalNix encodes SubstitutablePathInfo in Nix wire format.
func (s *SubstitutablePathInfo) MarshalNix(enc *wire.Encoder) error {
	c := wire.NewEncoderNG(enc.Writer(), ProtoVersionFeatureExchange)

	return s.Convert(c)
}

// UnmarshalNix decodes SubstitutablePathInfo from Nix wire format.
func (s *SubstitutablePathInfo) UnmarshalNix(dec *wire.Decoder) error {
	c := wire.NewDecoderNG(dec.Reader(), MaxStringSize, ProtoVersionFeatureExchange)

	return s.Convert(c)
}

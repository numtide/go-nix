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

// MarshalNix encodes GCOptions in Nix wire format.
func (o *GCOptions) MarshalNix(enc *wire.Encoder) error {
	if err := enc.WriteUint64(uint64(o.Action)); err != nil {
		return err
	}

	if err := enc.WriteStrings(o.PathsToDelete); err != nil {
		return err
	}

	if err := enc.WriteBool(o.IgnoreLiveness); err != nil {
		return err
	}

	if err := enc.WriteUint64(o.MaxFreed); err != nil {
		return err
	}

	// deprecated fields, always zero.
	for range numDeprecatedGCFields {
		if err := enc.WriteUint64(0); err != nil {
			return err
		}
	}

	return nil
}

// UnmarshalNix decodes GCOptions from Nix wire format.
func (o *GCOptions) UnmarshalNix(dec *wire.Decoder) error {
	action, err := dec.ReadUint64()
	if err != nil {
		return err
	}

	o.Action = GCAction(action)

	o.PathsToDelete, err = dec.ReadStrings()
	if err != nil {
		return err
	}

	o.IgnoreLiveness, err = dec.ReadBool()
	if err != nil {
		return err
	}

	o.MaxFreed, err = dec.ReadUint64()
	if err != nil {
		return err
	}

	// deprecated fields, discard.
	for range numDeprecatedGCFields {
		if _, err = dec.ReadUint64(); err != nil {
			return err
		}
	}

	return nil
}

// MarshalNix encodes GCResult in Nix wire format.
func (r *GCResult) MarshalNix(enc *wire.Encoder) error {
	if err := enc.WriteStrings(r.Paths); err != nil {
		return err
	}

	if err := enc.WriteUint64(r.BytesFreed); err != nil {
		return err
	}

	// deprecated field, always zero.
	return enc.WriteUint64(0)
}

// UnmarshalNix decodes GCResult from Nix wire format.
func (r *GCResult) UnmarshalNix(dec *wire.Decoder) error {
	var err error

	r.Paths, err = dec.ReadStrings()
	if err != nil {
		return err
	}

	r.BytesFreed, err = dec.ReadUint64()
	if err != nil {
		return err
	}

	// deprecated field, discard.
	_, err = dec.ReadUint64()

	return err
}

// MarshalNix encodes SubstitutablePathInfo in Nix wire format.
func (s *SubstitutablePathInfo) MarshalNix(enc *wire.Encoder) error {
	if err := enc.WriteString(s.Deriver); err != nil {
		return err
	}

	if err := enc.WriteStrings(s.References); err != nil {
		return err
	}

	if err := enc.WriteUint64(s.DownloadSize); err != nil {
		return err
	}

	return enc.WriteUint64(s.NarSize)
}

// UnmarshalNix decodes SubstitutablePathInfo from Nix wire format.
func (s *SubstitutablePathInfo) UnmarshalNix(dec *wire.Decoder) error {
	var err error

	s.Deriver, err = dec.ReadString()
	if err != nil {
		return err
	}

	s.References, err = dec.ReadStrings()
	if err != nil {
		return err
	}

	s.DownloadSize, err = dec.ReadUint64()
	if err != nil {
		return err
	}

	s.NarSize, err = dec.ReadUint64()

	return err
}

package wire

import (
	"encoding/json"
	"io"
)

// DecoderNG reads Nix wire format values from an input stream.
type DecoderNG struct {
	r        io.Reader
	maxBytes uint64
	ver      uint64
}

// NewDecoderNG returns a DecoderNG that reads from r. The maxBytes parameter
// limits the maximum size of string and byte packets to prevent excessive
// memory allocation.
func NewDecoderNG(r io.Reader, maxBytes uint64, ver uint64) *DecoderNG {
	return &DecoderNG{
		r:        r,
		maxBytes: maxBytes,
		ver:      ver,
	}
}

// Uint64 reads a uint64 in Nix wire format.
func (d *DecoderNG) Uint64(p *uint64) (err error) {
	*p, err = ReadUint64(d.r)

	return err
}

// Bool reads a boolean in Nix wire format.
func (d *DecoderNG) Bool(p *bool) (err error) {
	*p, err = ReadBool(d.r)

	return err
}

// Bytes reads a byte packet and returns its contents.
func (d *DecoderNG) Bytes(p *[]byte) (err error) {
	*p, err = ReadBytesFull(d.r, d.maxBytes)

	return err
}

// String reads a string packet in Nix wire format.
func (d *DecoderNG) String(p *string) (err error) {
	*p, err = ReadString(d.r, d.maxBytes)

	return err
}

// Strings reads a list of strings (count + entries).
func (d *DecoderNG) Strings(p *[]string) (err error) {
	*p, err = ReadStrings(d.r, d.maxBytes)

	return err
}

// StringMap reads a map of string key/value pairs (count + entries).
func (d *DecoderNG) StringMap(p *map[string]string) (err error) {
	*p, err = ReadStringMap(d.r, d.maxBytes)

	return err
}

// JSON reads a string packet and unmarshals it as JSON into v.
func (d *DecoderNG) JSON(v any) error {
	var s string
	if err := d.String(&s); err != nil {
		return err
	}

	return json.Unmarshal([]byte(s), v)
}

func (d *DecoderNG) Version() uint64 {
	return d.ver
}

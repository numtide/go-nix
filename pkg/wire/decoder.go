package wire

import "io"

// Decoder reads Nix wire format values from an input stream.
type Decoder struct {
	r        io.Reader
	maxBytes uint64
}

// NewDecoder returns a Decoder that reads from r. The maxBytes parameter
// limits the maximum size of string and byte packets to prevent excessive
// memory allocation.
func NewDecoder(r io.Reader, maxBytes uint64) *Decoder {
	return &Decoder{r: r, maxBytes: maxBytes}
}

// ReadUint64 reads a uint64 in Nix wire format.
func (d *Decoder) ReadUint64() (uint64, error) {
	return ReadUint64(d.r)
}

// ReadBool reads a boolean in Nix wire format.
func (d *Decoder) ReadBool() (bool, error) {
	return ReadBool(d.r)
}

// ReadBytes reads a byte packet and returns its contents.
func (d *Decoder) ReadBytes() ([]byte, error) {
	return ReadBytesFull(d.r, d.maxBytes)
}

// ReadString reads a string packet in Nix wire format.
func (d *Decoder) ReadString() (string, error) {
	return ReadString(d.r, d.maxBytes)
}

// ReadStrings reads a list of strings (count + entries).
func (d *Decoder) ReadStrings() ([]string, error) {
	return ReadStrings(d.r, d.maxBytes)
}

// ReadStringMap reads a map of string key/value pairs (count + entries).
func (d *Decoder) ReadStringMap() (map[string]string, error) {
	return ReadStringMap(d.r, d.maxBytes)
}

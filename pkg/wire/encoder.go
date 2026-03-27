package wire

import "io"

// Encoder writes Nix wire format values to an output stream.
type Encoder struct{ w io.Writer }

// NewEncoder returns an Encoder that writes to w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

// WriteUint64 writes a uint64 in Nix wire format.
func (e *Encoder) WriteUint64(n uint64) error {
	return WriteUint64(e.w, n)
}

// WriteBool writes a boolean in Nix wire format.
func (e *Encoder) WriteBool(v bool) error {
	return WriteBool(e.w, v)
}

// WriteBytes writes a byte packet in Nix wire format.
func (e *Encoder) WriteBytes(buf []byte) error {
	return WriteBytes(e.w, buf)
}

// WriteString writes a string packet in Nix wire format.
func (e *Encoder) WriteString(s string) error {
	return WriteString(e.w, s)
}

// WriteStrings writes a list of strings as count + entries.
func (e *Encoder) WriteStrings(ss []string) error {
	return WriteStrings(e.w, ss)
}

// WriteStringMap writes a map as count + sorted key/value pairs.
func (e *Encoder) WriteStringMap(m map[string]string) error {
	return WriteStringMap(e.w, m)
}

// Writer returns the underlying writer.
func (e *Encoder) Writer() io.Writer {
	return e.w
}

// Encode encodes a value that implements Marshaler.
func (e *Encoder) Encode(v Marshaler) error {
	return v.MarshalNix(e)
}

// Marshaler is implemented by types that can serialize themselves in Nix wire format.
type Marshaler interface {
	MarshalNix(enc *Encoder) error
}

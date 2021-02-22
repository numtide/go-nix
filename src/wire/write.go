package wire

import (
	"io"
)

// WriteUint64 writes an uint64 in nix wire format
func WriteUint64(w io.Writer, n uint64) error {
	var buf [8]byte
	byteOrder.PutUint64(buf[:], n)
	_, err := w.Write(buf[:])
	return err
}

// WriteBool writes a boolean in nix wire format
func WriteBool(w io.Writer, v bool) error {
	if v {
		return WriteUint64(w, 1)
	} else {
		return WriteUint64(w, 0)
	}
}

// WriteBytes writes a bytes packet. See ReadBytes for its structure.
func WriteBytes(w io.Writer, buf []byte) error {
	n := uint64(len(buf))
	if err := WriteUint64(w, n); err != nil {
		return err
	}
	if _, err := w.Write(buf); err != nil {
		return err
	}
	return WritePadding(w, n)
}

// WriteString writes a bytes packet
func WriteString(w io.Writer, s string) error {
	n := uint64(len(s))
	if err := WriteUint64(w, n); err != nil {
		return err
	}
	if _, err := io.WriteString(w, s); err != nil {
		return err
	}
	return WritePadding(w, n)
}

var padding [8]byte

// WritePadding writes the appropriate amount of padding.
func WritePadding(w io.Writer, contentLength uint64) error {
	if m := contentLength % 8; m != 0 {
		_, err := w.Write(padding[m:])
		return err
	}
	return nil
}
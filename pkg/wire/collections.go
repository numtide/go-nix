package wire

import (
	"fmt"
	"io"
	"sort"
)

// WriteStrings writes a list of strings as count + entries.
func WriteStrings(w io.Writer, ss []string) error {
	if err := WriteUint64(w, uint64(len(ss))); err != nil {
		return err
	}

	for _, s := range ss {
		if err := WriteString(w, s); err != nil {
			return err
		}
	}

	return nil
}

// ReadStrings reads a list of strings (count + entries).
func ReadStrings(r io.Reader, maxBytes uint64) ([]string, error) {
	count, err := ReadUint64(r)
	if err != nil {
		return nil, fmt.Errorf("read string list count: %w", err)
	}

	ss := make([]string, count)

	for i := uint64(0); i < count; i++ {
		s, err := ReadString(r, maxBytes)
		if err != nil {
			return nil, fmt.Errorf("read string list entry: %w", err)
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

	if err := WriteUint64(w, uint64(len(keys))); err != nil {
		return err
	}

	for _, k := range keys {
		if err := WriteString(w, k); err != nil {
			return err
		}

		if err := WriteString(w, m[k]); err != nil {
			return err
		}
	}

	return nil
}

// ReadStringMap reads a map of string key/value pairs (count + entries).
func ReadStringMap(r io.Reader, maxBytes uint64) (map[string]string, error) {
	count, err := ReadUint64(r)
	if err != nil {
		return nil, fmt.Errorf("read string map count: %w", err)
	}

	m := make(map[string]string, count)

	for i := uint64(0); i < count; i++ {
		key, err := ReadString(r, maxBytes)
		if err != nil {
			return nil, fmt.Errorf("read string map key: %w", err)
		}

		val, err := ReadString(r, maxBytes)
		if err != nil {
			return nil, fmt.Errorf("read string map value: %w", err)
		}

		m[key] = val
	}

	return m, nil
}

package wire

import (
	"sort"
)

type Codec interface {
	Uint64(p *uint64) error
	Bool(p *bool) error
	Bytes(p *[]byte) error
	String(p *string) error
	Strings(p *[]string) error
	StringMap(p *map[string]string) error
	JSON(v any) error
	Version() uint64
}

type Convertible interface {
	Convert(c Codec) error
}

type ConvertiblePtr[T any] interface {
	*T
	Convert(c Codec) error
}

// FIXME: REDO this prob

func ConvertMap[T any, U ConvertiblePtr[T]](c Codec, m *map[string]T) error {
	n := uint64(len(*m))
	if err := c.Uint64(&n); err != nil {
		return err
	}

	keys := make([]string, 0, len(*m))
	for k := range *m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	if *m == nil {
		*m = make(map[string]T, n)
	}

	for i := uint64(0); i < n; i++ {
		var key string
		if int(i) < len(keys) {
			key = keys[i]
		}

		if err := c.String(&key); err != nil {
			return err
		}

		var v T
		if existing, ok := (*m)[key]; ok {
			v = existing
		}

		var u U = &v
		if err := u.Convert(c); err != nil {
			return err
		}

		(*m)[key] = v
	}

	return nil
}

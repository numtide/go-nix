package wire_test

import (
	"bytes"
	"testing"

	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/assert"
)

func TestWriteReadStrings(t *testing.T) {
	var buf bytes.Buffer
	err := wire.WriteStrings(&buf, []string{"foo", "bar", "baz"})
	assert.NoError(t, err)
	result, err := wire.ReadStrings(&buf, 1024)
	assert.NoError(t, err)
	assert.Equal(t, []string{"foo", "bar", "baz"}, result)
}

func TestWriteReadStringsEmpty(t *testing.T) {
	var buf bytes.Buffer
	err := wire.WriteStrings(&buf, []string{})
	assert.NoError(t, err)
	result, err := wire.ReadStrings(&buf, 1024)
	assert.NoError(t, err)
	assert.Empty(t, result)
}

func TestWriteReadStringMap(t *testing.T) {
	var buf bytes.Buffer

	m := map[string]string{"a": "1", "b": "2"}
	err := wire.WriteStringMap(&buf, m)
	assert.NoError(t, err)
	result, err := wire.ReadStringMap(&buf, 1024)
	assert.NoError(t, err)
	assert.Equal(t, m, result)
}

func TestWriteStringMapSorted(t *testing.T) {
	var buf bytes.Buffer

	m := map[string]string{"z": "last", "a": "first", "m": "middle"}
	err := wire.WriteStringMap(&buf, m)
	assert.NoError(t, err)

	// Verify keys are written in sorted order.
	count, err := wire.ReadUint64(&buf)
	assert.NoError(t, err)
	assert.Equal(t, uint64(3), count)

	key1, err := wire.ReadString(&buf, 1024)
	assert.NoError(t, err)
	assert.Equal(t, "a", key1)

	val1, err := wire.ReadString(&buf, 1024)
	assert.NoError(t, err)
	assert.Equal(t, "first", val1)

	key2, err := wire.ReadString(&buf, 1024)
	assert.NoError(t, err)
	assert.Equal(t, "m", key2)

	val2, err := wire.ReadString(&buf, 1024)
	assert.NoError(t, err)
	assert.Equal(t, "middle", val2)

	key3, err := wire.ReadString(&buf, 1024)
	assert.NoError(t, err)
	assert.Equal(t, "z", key3)

	val3, err := wire.ReadString(&buf, 1024)
	assert.NoError(t, err)
	assert.Equal(t, "last", val3)
}

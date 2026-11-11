package wire_test

import (
	"bytes"
	"math"
	"testing"

	"github.com/nix-community/go-nix/pkg/wire"
	"github.com/stretchr/testify/require"
)

type jsonPayload struct {
	Name  string   `json:"name"`
	Count uint64   `json:"count"`
	Tags  []string `json:"tags"`
}

func (j *jsonPayload) Convert(c wire.Codec) error {
	return c.JSON(j)
}

func TestCodecJSONRoundTrip(t *testing.T) {
	rq := require.New(t)

	want := jsonPayload{Name: "out", Count: 42, Tags: []string{"a", "b"}}

	var buf bytes.Buffer

	enc := wire.NewEncoderNG(&buf, 0)
	rq.NoError(enc.JSON(&want))

	got := jsonPayload{}
	dec := wire.NewDecoderNG(&buf, math.MaxUint64, 0)
	rq.NoError(dec.JSON(&got))
	rq.Equal(want, got)
	rq.Equal(0, buf.Len())
}

func TestCodecJSONInvalid(t *testing.T) {
	rq := require.New(t)

	var buf bytes.Buffer

	enc := wire.NewEncoderNG(&buf, 0)
	s := "not valid json {!"
	rq.NoError(enc.String(&s))

	got := jsonPayload{}
	dec := wire.NewDecoderNG(&buf, math.MaxUint64, 0)
	rq.Error(dec.JSON(&got))
}

func TestConvertMapRoundTrip(t *testing.T) {
	rq := require.New(t)

	want := map[string]jsonPayload{
		"b": {Name: "two", Count: 2},
		"a": {Name: "one", Count: 1},
	}

	var buf bytes.Buffer

	enc := wire.NewEncoderNG(&buf, 0)
	rq.NoError(wire.ConvertMap(enc, &want))

	got := map[string]jsonPayload{}
	dec := wire.NewDecoderNG(&buf, math.MaxUint64, 0)
	rq.NoError(wire.ConvertMap(dec, &got))
	rq.Equal(want, got)
	rq.Equal(0, buf.Len())
}

// regression: a wire-controlled map count must not reach make() as a capacity.
func TestConvertMapCountTooLarge(t *testing.T) {
	rq := require.New(t)

	var buf bytes.Buffer
	rq.NoError(wire.WriteUint64(&buf, 1<<40))

	m := map[string]jsonPayload{}
	err := wire.ConvertMap(wire.NewDecoderNG(&buf, math.MaxUint64, 0), &m)
	rq.Error(err)
}

package daemon_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/stretchr/testify/require"
)

func TestFramedReaderSingleFrame(t *testing.T) {
	// Frame: length=5, data="hello" (NO padding), then terminator frame (length=0)
	var buf bytes.Buffer

	buf.Write([]byte{5, 0, 0, 0, 0, 0, 0, 0})  // frame length
	buf.Write([]byte{'h', 'e', 'l', 'l', 'o'}) // data (no padding)
	buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0})  // terminator

	fr := daemon.NewFramedReader(&buf)
	data, err := io.ReadAll(fr)
	require.NoError(t, err)
	require.Equal(t, []byte("hello"), data)
}

func TestFramedReaderMultipleFrames(t *testing.T) {
	var buf bytes.Buffer

	buf.Write([]byte{3, 0, 0, 0, 0, 0, 0, 0}) // frame 1: length 3
	buf.Write([]byte{'a', 'b', 'c'})          // "abc" (no padding)
	buf.Write([]byte{2, 0, 0, 0, 0, 0, 0, 0}) // frame 2: length 2
	buf.Write([]byte{'d', 'e'})               // "de" (no padding)
	buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0}) // terminator

	fr := daemon.NewFramedReader(&buf)
	data, err := io.ReadAll(fr)
	require.NoError(t, err)
	require.Equal(t, []byte("abcde"), data)
}

func TestFramedReaderEmptyStream(t *testing.T) {
	var buf bytes.Buffer

	buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0}) // just terminator

	fr := daemon.NewFramedReader(&buf)
	data, err := io.ReadAll(fr)
	require.NoError(t, err)
	require.Empty(t, data)
}

func TestFramedWriterRoundTrip(t *testing.T) {
	rq := require.New(t)

	payload := []byte("hello, this is a test of framed writing with some data")

	var buf bytes.Buffer

	fw := daemon.NewFramedWriter(&buf)
	_, err := fw.Write(payload)
	rq.NoError(err)
	err = fw.Close()
	rq.NoError(err)

	// Read it back
	fr := daemon.NewFramedReader(&buf)
	data, err := io.ReadAll(fr)
	rq.NoError(err)
	rq.Equal(payload, data)
}

func TestFramedWriterEmpty(t *testing.T) {
	var buf bytes.Buffer

	fw := daemon.NewFramedWriter(&buf)
	err := fw.Close()
	require.NoError(t, err)

	// Should just be a terminator frame (8 zero bytes)
	require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0}, buf.Bytes())
}

func TestFramedReaderAlignedFrame(t *testing.T) {
	// Frame with exactly 8 bytes (no padding needed either way)
	var buf bytes.Buffer

	buf.Write([]byte{8, 0, 0, 0, 0, 0, 0, 0}) // length 8
	buf.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8}) // data
	buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0}) // terminator

	fr := daemon.NewFramedReader(&buf)
	data, err := io.ReadAll(fr)
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, data)
}

func TestFramedWriterNoPadding(t *testing.T) {
	rq := require.New(t)

	// Verify that the writer does NOT add padding after frame data.
	// Write exactly 5 bytes ("hello"), expect:
	//   [5,0,0,0,0,0,0,0] frame header
	//   [h,e,l,l,o]       frame data (NO padding)
	//   [0,0,0,0,0,0,0,0] terminator
	var buf bytes.Buffer

	fw := daemon.NewFramedWriter(&buf)
	_, err := fw.Write([]byte("hello"))
	rq.NoError(err)
	err = fw.Close()
	rq.NoError(err)

	expected := []byte{
		5, 0, 0, 0, 0, 0, 0, 0, // frame length = 5
		'h', 'e', 'l', 'l', 'o', // frame data (no padding)
		0, 0, 0, 0, 0, 0, 0, 0, // terminator
	}
	rq.Equal(expected, buf.Bytes())
}

func TestFramingReaderEmpty(t *testing.T) {
	// Empty source should produce just a zero-length terminator.
	fr := daemon.NewFramingReader(bytes.NewReader(nil))
	data, err := io.ReadAll(fr)
	require.NoError(t, err)
	require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0}, data)
}

func TestFramingReaderSmallPayload(t *testing.T) {
	fr := daemon.NewFramingReader(bytes.NewReader([]byte("hello")))
	data, err := io.ReadAll(fr)
	require.NoError(t, err)

	expected := []byte{
		5, 0, 0, 0, 0, 0, 0, 0, // frame length = 5
		'h', 'e', 'l', 'l', 'o', // frame data
		0, 0, 0, 0, 0, 0, 0, 0, // terminator
	}
	require.Equal(t, expected, data)
}

func TestFramingReaderLargePayload(t *testing.T) {
	// Payload larger than 32KB should produce multiple frames.
	payload := make([]byte, 40*1024) // 40KB
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	fr := daemon.NewFramingReader(bytes.NewReader(payload))
	framedData, err := io.ReadAll(fr)
	require.NoError(t, err)

	// Verify by decoding with FramedReader.
	decoded := daemon.NewFramedReader(bytes.NewReader(framedData))
	result, err := io.ReadAll(decoded)
	require.NoError(t, err)
	require.Equal(t, payload, result)
}

func TestFramingReaderExact32KB(t *testing.T) {
	// Payload exactly 32KB should produce one full frame + terminator.
	payload := make([]byte, 32*1024)
	for i := range payload {
		payload[i] = byte(i % 199)
	}

	fr := daemon.NewFramingReader(bytes.NewReader(payload))
	framedData, err := io.ReadAll(fr)
	require.NoError(t, err)

	// Should be: 8 (header) + 32768 (data) + 8 (terminator) = 32784 bytes.
	require.Len(t, framedData, 8+32*1024+8)

	// Verify round-trip.
	decoded := daemon.NewFramedReader(bytes.NewReader(framedData))
	result, err := io.ReadAll(decoded)
	require.NoError(t, err)
	require.Equal(t, payload, result)
}

func TestFramingReaderRoundTrip(t *testing.T) {
	payload := []byte("hello, this is a test of framed writing with some data")

	fr := daemon.NewFramingReader(bytes.NewReader(payload))
	framedData, err := io.ReadAll(fr)
	require.NoError(t, err)

	decoded := daemon.NewFramedReader(bytes.NewReader(framedData))
	result, err := io.ReadAll(decoded)
	require.NoError(t, err)
	require.Equal(t, payload, result)
}

func TestFramingReaderSmallReads(t *testing.T) {
	// Read one byte at a time to exercise partial header/data delivery.
	payload := []byte("hello")
	fr := daemon.NewFramingReader(bytes.NewReader(payload))

	var result []byte

	buf := make([]byte, 1)

	for {
		n, err := fr.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}

		if err == io.EOF {
			break
		}

		require.NoError(t, err)
	}

	expected := []byte{
		5, 0, 0, 0, 0, 0, 0, 0,
		'h', 'e', 'l', 'l', 'o',
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	require.Equal(t, expected, result)
}

func TestFramingReaderSourceError(t *testing.T) {
	// Source returns an error; FramingReader should propagate it.
	fr := daemon.NewFramingReader(&errReader{})
	_, err := io.ReadAll(fr)
	require.Error(t, err)
	require.Equal(t, "test error", err.Error())
}

// errReader always returns an error on Read.
type errReader struct{}

func (e *errReader) Read([]byte) (int, error) {
	return 0, fmt.Errorf("test error")
}

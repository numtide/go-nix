package daemon_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/stretchr/testify/require"
)

func TestFramedReader(t *testing.T) {
	t.Run("SingleFrame", func(t *testing.T) {
		// Frame: length=5, data="hello" (NO padding), then terminator frame (length=0)
		var buf bytes.Buffer

		buf.Write([]byte{5, 0, 0, 0, 0, 0, 0, 0})  // frame length
		buf.Write([]byte{'h', 'e', 'l', 'l', 'o'}) // data (no padding)
		buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0})  // terminator

		fr := daemon.NewFramedReader(&buf)
		data, err := io.ReadAll(fr)
		require.NoError(t, err)
		require.Equal(t, []byte("hello"), data)
	})

	t.Run("MultipleFrames", func(t *testing.T) {
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
	})

	t.Run("EmptyStream", func(t *testing.T) {
		var buf bytes.Buffer

		buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0}) // just terminator

		fr := daemon.NewFramedReader(&buf)
		data, err := io.ReadAll(fr)
		require.NoError(t, err)
		require.Empty(t, data)
	})

	t.Run("AlignedFrame", func(t *testing.T) {
		// Frame with exactly 8 bytes (no padding needed either way)
		var buf bytes.Buffer

		buf.Write([]byte{8, 0, 0, 0, 0, 0, 0, 0}) // length 8
		buf.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8}) // data
		buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0}) // terminator

		fr := daemon.NewFramedReader(&buf)
		data, err := io.ReadAll(fr)
		require.NoError(t, err)
		require.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, data)
	})

	t.Run("SmallBuffer", func(t *testing.T) {
		rq := require.New(t)

		// Construct a framed stream with a 64-byte frame.
		payload := []byte("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!!")

		var buf bytes.Buffer

		fw := daemon.NewFramedWriter(&buf)
		_, err := fw.Write(payload)
		rq.NoError(err)

		err = fw.Close()
		rq.NoError(err)

		// Read with 1-byte Read calls to test partial-frame read path.
		fr := daemon.NewFramedReader(&buf)

		var result []byte

		for {
			b := make([]byte, 1)

			n, readErr := fr.Read(b)
			if n > 0 {
				result = append(result, b[:n]...)
			}

			if readErr == io.EOF {
				break
			}

			rq.NoError(readErr)
		}

		rq.Equal(payload, result)
	})

	t.Run("TruncatedFrame", func(t *testing.T) {
		rq := require.New(t)

		// Frame header says 100 bytes, but only 10 are present.
		var buf bytes.Buffer
		buf.Write([]byte{100, 0, 0, 0, 0, 0, 0, 0}) // frame length = 100
		buf.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})

		fr := daemon.NewFramedReader(&buf)

		// First read gets the 10 available bytes.
		p := make([]byte, 100)
		n, err := fr.Read(p)
		rq.Equal(10, n)
		rq.NoError(err)

		// Second read: remaining is 90 but underlying reader is empty → EOF.
		n, err = fr.Read(p)
		rq.Equal(0, n)
		rq.Error(err) // io.EOF from underlying reader
	})
}

type errWriter struct{ err error }

func (e *errWriter) Write([]byte) (int, error) { return 0, e.err }

func TestFramedWriter(t *testing.T) {
	t.Run("RoundTrip", func(t *testing.T) {
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
	})

	t.Run("Empty", func(t *testing.T) {
		var buf bytes.Buffer

		fw := daemon.NewFramedWriter(&buf)
		err := fw.Close()
		require.NoError(t, err)

		// Should just be a terminator frame (8 zero bytes)
		require.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 0}, buf.Bytes())
	})

	t.Run("NoPadding", func(t *testing.T) {
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
	})

	t.Run("LargePayload", func(t *testing.T) {
		rq := require.New(t)

		// Write 100KB — exceeds the 32KB default frame size, forcing multiple auto-flushes.
		payload := make([]byte, 100*1024)
		for i := range payload {
			payload[i] = byte(i % 251) // deterministic non-zero pattern
		}

		var buf bytes.Buffer

		fw := daemon.NewFramedWriter(&buf)
		n, err := fw.Write(payload)
		rq.NoError(err)
		rq.Equal(len(payload), n)

		err = fw.Close()
		rq.NoError(err)

		// Read it back and verify round-trip.
		fr := daemon.NewFramedReader(&buf)
		data, err := io.ReadAll(fr)
		rq.NoError(err)
		rq.Equal(payload, data)
	})

	t.Run("WriteToClosed", func(t *testing.T) {
		rq := require.New(t)

		var buf bytes.Buffer

		fw := daemon.NewFramedWriter(&buf)
		err := fw.Close()
		rq.NoError(err)

		// Write after Close should return an error.
		_, err = fw.Write([]byte("hello"))
		rq.Error(err)
		rq.Contains(err.Error(), "closed")
	})

	t.Run("FlushError", func(t *testing.T) {
		rq := require.New(t)

		ew := &errWriter{err: io.ErrClosedPipe}
		fw := daemon.NewFramedWriter(ew)

		// Write enough data to trigger a flush (>= 32KB).
		data := make([]byte, 33*1024)
		_, err := fw.Write(data)
		rq.Error(err)
		rq.ErrorIs(err, io.ErrClosedPipe)
	})

	t.Run("CloseFlushError", func(t *testing.T) {
		rq := require.New(t)

		ew := &errWriter{err: io.ErrClosedPipe}
		fw := daemon.NewFramedWriter(ew)

		// Write a small amount (stays buffered, no flush yet).
		_, err := fw.Write([]byte("hello"))
		rq.NoError(err)

		// Close must flush the buffer — the underlying writer error should propagate.
		err = fw.Close()
		rq.Error(err)
		rq.ErrorIs(err, io.ErrClosedPipe)
	})

	t.Run("CloseIdempotent", func(t *testing.T) {
		rq := require.New(t)

		var buf bytes.Buffer

		fw := daemon.NewFramedWriter(&buf)
		rq.NoError(fw.Close())
		rq.NoError(fw.Close()) // second close should be no-op
	})
}

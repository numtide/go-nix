package daemon

import (
	"fmt"
	"io"

	"github.com/nix-community/go-nix/pkg/wire"
)

const defaultFrameSize = 32 * 1024 // 32KB

// FramedReader reads framed data from an underlying reader. Each frame
// consists of a uint64 length header followed by that many bytes of data
// (no padding). A zero-length frame signals end-of-stream.
//
// This matches the Nix C++ FramedSource format: repeated
// [length(uint64)][raw_data], terminated by [0(uint64)].
type FramedReader struct {
	r          io.Reader
	remaining  uint64 // bytes remaining in current frame
	needHeader bool   // true when we need to read the next frame header
	done       bool   // true after we read a zero-length terminator frame
}

// NewFramedReader creates a FramedReader that reads framed data from r.
func NewFramedReader(r io.Reader) *FramedReader {
	return &FramedReader{
		r:          r,
		needHeader: true,
	}
}

// Read implements io.Reader. It transparently handles frame boundaries,
// reading frame headers as needed.
func (fr *FramedReader) Read(p []byte) (int, error) {
	if fr.done {
		return 0, io.EOF
	}

	// If the current frame is exhausted, advance to the next one.
	if fr.needHeader {
		if err := fr.nextFrame(); err != nil {
			return 0, err
		}

		if fr.done {
			return 0, io.EOF
		}
	}

	// Limit the read to the remaining bytes in the current frame.
	toRead := uint64(len(p))
	if toRead > fr.remaining {
		toRead = fr.remaining
	}

	n, err := fr.r.Read(p[:toRead])
	fr.remaining -= uint64(n) //nolint:gosec // G115: n is always non-negative from a Read call

	if fr.remaining == 0 {
		fr.needHeader = true
	}

	return n, err
}

// nextFrame reads the next frame header. If a zero-length frame is
// encountered, fr.done is set to true.
func (fr *FramedReader) nextFrame() error {
	frameLen, err := wire.ReadUint64(fr.r)
	if err != nil {
		return err
	}

	if frameLen == 0 {
		fr.done = true

		return nil
	}

	fr.remaining = frameLen
	fr.needHeader = false

	return nil
}

// FramedWriter writes framed data to an underlying writer. Data written via
// Write is buffered and flushed as frames when the buffer reaches the
// threshold (default 32KB). Close flushes any remaining buffered data and
// writes a zero-length terminator frame.
//
// This matches the Nix C++ FramedSink format: each frame is
// [length(uint64)][raw_data] with no padding.
type FramedWriter struct {
	w      io.Writer
	buf    []byte
	closed bool
}

// NewFramedWriter creates a FramedWriter that writes framed data to w.
func NewFramedWriter(w io.Writer) *FramedWriter {
	return &FramedWriter{
		w:   w,
		buf: make([]byte, 0, defaultFrameSize),
	}
}

// Write buffers data and flushes full frames as needed.
func (fw *FramedWriter) Write(p []byte) (int, error) {
	if fw.closed {
		return 0, fmt.Errorf("write to closed FramedWriter")
	}

	written := 0

	for len(p) > 0 {
		// Fill the buffer up to capacity.
		space := cap(fw.buf) - len(fw.buf)
		if space > len(p) {
			space = len(p)
		}

		fw.buf = append(fw.buf, p[:space]...)
		p = p[space:]
		written += space

		// Flush if the buffer is full.
		if len(fw.buf) == cap(fw.buf) {
			if err := fw.flush(); err != nil {
				return written, err
			}
		}
	}

	return written, nil
}

// Close flushes any remaining buffered data as a frame and writes a
// zero-length terminator frame.
func (fw *FramedWriter) Close() error {
	if fw.closed {
		return nil
	}

	fw.closed = true

	// Flush any remaining data.
	if len(fw.buf) > 0 {
		if err := fw.flush(); err != nil {
			return err
		}
	}

	// Write terminator frame (zero-length).
	return wire.WriteUint64(fw.w, 0)
}

// flush writes the current buffer as a single frame: [length][data], no padding.
func (fw *FramedWriter) flush() error {
	n := uint64(len(fw.buf))
	if n == 0 {
		return nil
	}

	// Write frame header.
	if err := wire.WriteUint64(fw.w, n); err != nil {
		return err
	}

	// Write frame data (no padding).
	if _, err := fw.w.Write(fw.buf); err != nil {
		return err
	}

	// Reset buffer.
	fw.buf = fw.buf[:0]

	return nil
}

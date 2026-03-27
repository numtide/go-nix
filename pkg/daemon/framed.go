package daemon

import (
	"encoding/binary"
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
//
// FramedReader is not safe for concurrent use.
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
	toRead := min(uint64(len(p)), fr.remaining)

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
//
// FramedWriter is not safe for concurrent use.
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
		space := min(cap(fw.buf)-len(fw.buf), len(p))

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

// FramingReader is the read-side dual of FramedWriter. It reads from a source
// io.Reader and produces framed wire output: repeated [length(uint64)][data]
// chunks (up to 32KB each), terminated by a [0(uint64)] frame.
//
// This allows callers to compose framed data as an io.Reader for use with
// io.Copy or io.MultiReader, without needing a FramedWriter + io.Pipe.
//
// FramingReader is not safe for concurrent use.
type FramingReader struct {
	src     io.Reader
	buf     [defaultFrameSize]byte // source read buffer
	header  [8]byte                // frame length header (reused for terminator)
	state   framingState
	pos     int // position within current segment (header or data)
	dataLen int // valid bytes in buf for the current frame
	srcDone bool
}

type framingState int

const (
	framingReady      framingState = iota // need to read from source
	framingHeader                         // yielding header bytes
	framingData                           // yielding data bytes
	framingTerminator                     // yielding zero-length terminator
	framingDone                           // finished
)

// NewFramingReader creates a FramingReader that reads from src and produces
// framed wire output.
func NewFramingReader(src io.Reader) *FramingReader {
	return &FramingReader{
		src:   src,
		state: framingReady,
	}
}

// Read implements io.Reader. Each call yields a portion of the framed wire
// output: frame headers, frame data, or the zero-length terminator.
func (fr *FramingReader) Read(p []byte) (int, error) {
	for {
		switch fr.state {
		case framingDone:
			return 0, io.EOF

		case framingHeader:
			n := copy(p, fr.header[fr.pos:])
			fr.pos += n

			if fr.pos == len(fr.header) {
				fr.state = framingData
				fr.pos = 0
			}

			return n, nil

		case framingData:
			n := copy(p, fr.buf[fr.pos:fr.dataLen])
			fr.pos += n

			if fr.pos == fr.dataLen {
				fr.state = framingReady
			}

			return n, nil

		case framingTerminator:
			n := copy(p, fr.header[fr.pos:])
			fr.pos += n

			if fr.pos == len(fr.header) {
				fr.state = framingDone
			}

			return n, nil

		case framingReady:
			if fr.srcDone {
				binary.LittleEndian.PutUint64(fr.header[:], 0)
				fr.state = framingTerminator
				fr.pos = 0

				continue
			}

			n, err := fr.src.Read(fr.buf[:])
			if err != nil && err != io.EOF {
				return 0, err
			}

			if err == io.EOF {
				fr.srcDone = true
			}

			if n > 0 {
				binary.LittleEndian.PutUint64(fr.header[:], uint64(n))
				fr.dataLen = n
				fr.state = framingHeader
				fr.pos = 0

				continue
			}

			// Source returned EOF with no data.
			if fr.srcDone {
				continue
			}

			// n == 0 with no error: nothing available yet.
			return 0, nil
		}
	}
}

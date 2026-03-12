package daemon

import (
	"errors"
	"fmt"
)

var (
	// ErrClosed is returned when an operation is attempted on a closed client/response.
	ErrClosed = errors.New("daemon client is closed")

	// ErrNilContext is returned when a nil context is provided.
	ErrNilContext = errors.New("nil context")

	// ErrNilOptions is returned when required options are nil.
	ErrNilOptions = errors.New("nil options")

	// ErrNilDerivation is returned when a nil derivation is provided.
	ErrNilDerivation = errors.New("nil derivation")

	// ErrNilPathInfo is returned when a nil PathInfo is provided.
	ErrNilPathInfo = errors.New("nil path info")

	// ErrNilReader is returned when a required reader is nil.
	ErrNilReader = errors.New("nil reader")

	// ErrNilConn is returned when a nil connection is provided.
	ErrNilConn = errors.New("nil connection")

	// ErrNilRealisation is returned when a nil realisation is provided.
	ErrNilRealisation = errors.New("nil realisation")

	// ErrUnsupportedOperation is returned when an operation is not supported by the negotiated protocol version.
	ErrUnsupportedOperation = errors.New("unsupported operation for negotiated protocol version")
)

// UnsupportedOperationError provides detail about which operation failed and why.
type UnsupportedOperationError struct {
	Op             Operation
	MinVersion     uint64
	CurrentVersion uint64
}

func (e *UnsupportedOperationError) Error() string {
	return fmt.Sprintf("%s requires protocol >= %d.%d, but negotiated %d.%d",
		e.Op, e.MinVersion>>8, e.MinVersion&0xff,
		e.CurrentVersion>>8, e.CurrentVersion&0xff)
}

func (e *UnsupportedOperationError) Unwrap() error { return ErrUnsupportedOperation }

// Error is returned when the Nix daemon reports an error.
type Error struct {
	Type    string
	Level   uint64
	Name    string
	Message string
	Traces  []ErrorTrace
}

// ErrorTrace represents a single trace entry in a daemon error.
type ErrorTrace struct {
	HavePos uint64
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("daemon: %s", e.Message)
}

// ProtocolError is returned for wire-level problems.
type ProtocolError struct {
	Op  string
	Err error
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("protocol: %s: %v", e.Op, e.Err)
}

func (e *ProtocolError) Unwrap() error {
	return e.Err
}

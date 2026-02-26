package daemon

import "fmt"

// DaemonError is returned when the Nix daemon reports an error.
type DaemonError struct {
	Type    string
	Level   uint64
	Name    string
	Message string
	Traces  []DaemonErrorTrace
}

// DaemonErrorTrace represents a single trace entry in a daemon error.
type DaemonErrorTrace struct {
	HavePos uint64
	Message string
}

func (e *DaemonError) Error() string {
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

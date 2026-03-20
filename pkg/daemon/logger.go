package daemon

import (
	"fmt"
	"io"
	"sync/atomic"

	"github.com/nix-community/go-nix/pkg/wire"
)

// ProcessStderr reads and dispatches log/activity messages from the daemon's
// stderr channel. The daemon interleaves these messages before the actual
// response payload. The function loops until it receives LogLast, at which
// point the caller can proceed to read the response.
//
// Log messages (other than errors) are sent to the provided channel. If a
// LogError message is received, the parsed Error is returned. If the
// channel is nil, non-error messages are silently discarded. If the channel
// is full, messages are dropped to avoid blocking protocol progress.
//
// The version parameter is the negotiated protocol version, used to select
// the correct error format (structured errors require >= 1.26).
func ProcessStderr(r io.Reader, logs chan<- LogMessage, version uint64) error {
	return ProcessStderrWithSink(r, NewLogChannelSink(logs, nil), version)
}

// LogSink receives log messages from the daemon.
type LogSink interface {
	Send(LogMessage)
}

// LogChannelSink delivers log messages to a channel, dropping when full.
// If Dropped is non-nil, it is incremented on each dropped message.
type LogChannelSink struct {
	Ch      chan<- LogMessage
	Dropped *atomic.Uint64
}

// NewLogChannelSink wraps a channel with optional drop counter. If ch is nil,
// the returned sink discards messages.
func NewLogChannelSink(ch chan<- LogMessage, dropped *atomic.Uint64) LogSink {
	return LogChannelSink{Ch: ch, Dropped: dropped}
}

// Send implements LogSink.
func (s LogChannelSink) Send(msg LogMessage) {
	if s.Ch == nil {
		return
	}

	select {
	case s.Ch <- msg:
	default:
		if s.Dropped != nil {
			s.Dropped.Add(1)
		}
	}
}

// ProcessStderrWithSink is like ProcessStderr but sends log messages to the
// provided sink.
func ProcessStderrWithSink(r io.Reader, sink LogSink, version uint64) error {
	if sink == nil {
		sink = NewLogChannelSink(nil, nil)
	}

	sendLog := func(msg LogMessage) {
		sink.Send(msg)
	}

	for {
		raw, err := wire.ReadUint64(r)
		if err != nil {
			return &ProtocolError{Op: "read stderr message type", Err: err}
		}

		msgType := LogMessageType(raw)

		switch msgType {
		case LogLast:
			return nil

		case LogError:
			return readError(r, version)

		case LogNext:
			text, err := wire.ReadString(r, MaxStringSize)
			if err != nil {
				return &ProtocolError{Op: "read LogNext text", Err: err}
			}

			sendLog(LogMessage{Type: LogNext, Text: text})

		case LogStartActivity:
			act, err := readActivity(r)
			if err != nil {
				return err
			}

			sendLog(LogMessage{Type: LogStartActivity, Activity: act})

		case LogStopActivity:
			id, err := wire.ReadUint64(r)
			if err != nil {
				return &ProtocolError{Op: "read LogStopActivity id", Err: err}
			}

			sendLog(LogMessage{Type: LogStopActivity, ActivityID: id})

		case LogResult:
			result, err := readActivityResult(r)
			if err != nil {
				return err
			}

			sendLog(LogMessage{Type: LogResult, Result: result})

		case LogRead, LogWrite:
			// Data transfer notifications: read the count and discard.
			if _, err := wire.ReadUint64(r); err != nil {
				return &ProtocolError{Op: "read LogRead/LogWrite count", Err: err}
			}

		default:
			return &ProtocolError{
				Op:  "process stderr",
				Err: fmt.Errorf("unknown log message type: 0x%x", raw),
			}
		}
	}
}

// readError parses an Error from the daemon's stderr channel. The format
// depends on the negotiated protocol version: >= 1.26 uses structured errors
// with type/level/name/traces; older versions send a plain message string
// and an exit status.
func readError(r io.Reader, version uint64) error {
	if version < ProtoVersionStructuredErrors {
		message, err := wire.ReadString(r, MaxStringSize)
		if err != nil {
			return &ProtocolError{Op: "read error message", Err: err}
		}

		exitStatus, err := wire.ReadUint64(r)
		if err != nil {
			return &ProtocolError{Op: "read error exitStatus", Err: err}
		}

		return &Error{
			Type:       "Error",
			Message:    message,
			ExitStatus: exitStatus,
		}
	}

	errType, err := wire.ReadString(r, MaxStringSize)
	if err != nil {
		return &ProtocolError{Op: "read error type", Err: err}
	}

	level, err := wire.ReadUint64(r)
	if err != nil {
		return &ProtocolError{Op: "read error level", Err: err}
	}

	name, err := wire.ReadString(r, MaxStringSize)
	if err != nil {
		return &ProtocolError{Op: "read error name", Err: err}
	}

	message, err := wire.ReadString(r, MaxStringSize)
	if err != nil {
		return &ProtocolError{Op: "read error message", Err: err}
	}

	// havePos: currently unused, but must be consumed.
	if _, err := wire.ReadUint64(r); err != nil {
		return &ProtocolError{Op: "read error havePos", Err: err}
	}

	nrTraces, err := wire.ReadUint64(r)
	if err != nil {
		return &ProtocolError{Op: "read error nrTraces", Err: err}
	}

	traces := make([]ErrorTrace, nrTraces)

	for i := uint64(0); i < nrTraces; i++ {
		havePos, err := wire.ReadUint64(r)
		if err != nil {
			return &ProtocolError{Op: "read trace havePos", Err: err}
		}

		traceMsg, err := wire.ReadString(r, MaxStringSize)
		if err != nil {
			return &ProtocolError{Op: "read trace message", Err: err}
		}

		traces[i] = ErrorTrace{
			HavePos: havePos,
			Message: traceMsg,
		}
	}

	return &Error{
		Type:    errType,
		Level:   level,
		Name:    name,
		Message: message,
		Traces:  traces,
	}
}

// readActivity parses an Activity from the daemon's stderr channel.
func readActivity(r io.Reader) (*Activity, error) {
	id, err := wire.ReadUint64(r)
	if err != nil {
		return nil, &ProtocolError{Op: "read activity id", Err: err}
	}

	level, err := wire.ReadUint64(r)
	if err != nil {
		return nil, &ProtocolError{Op: "read activity level", Err: err}
	}

	actType, err := wire.ReadUint64(r)
	if err != nil {
		return nil, &ProtocolError{Op: "read activity type", Err: err}
	}

	text, err := wire.ReadString(r, MaxStringSize)
	if err != nil {
		return nil, &ProtocolError{Op: "read activity text", Err: err}
	}

	nrFields, err := wire.ReadUint64(r)
	if err != nil {
		return nil, &ProtocolError{Op: "read activity nrFields", Err: err}
	}

	fields, err := readFields(r, nrFields)
	if err != nil {
		return nil, err
	}

	parent, err := wire.ReadUint64(r)
	if err != nil {
		return nil, &ProtocolError{Op: "read activity parent", Err: err}
	}

	return &Activity{
		ID:     id,
		Level:  Verbosity(level),
		Type:   ActivityType(actType),
		Text:   text,
		Fields: fields,
		Parent: parent,
	}, nil
}

// readActivityResult parses an ActivityResult from the daemon's stderr channel.
func readActivityResult(r io.Reader) (*ActivityResult, error) {
	id, err := wire.ReadUint64(r)
	if err != nil {
		return nil, &ProtocolError{Op: "read result id", Err: err}
	}

	resType, err := wire.ReadUint64(r)
	if err != nil {
		return nil, &ProtocolError{Op: "read result type", Err: err}
	}

	nrFields, err := wire.ReadUint64(r)
	if err != nil {
		return nil, &ProtocolError{Op: "read result nrFields", Err: err}
	}

	fields, err := readFields(r, nrFields)
	if err != nil {
		return nil, err
	}

	return &ActivityResult{
		ID:     id,
		Type:   ResultType(resType),
		Fields: fields,
	}, nil
}

// readFields parses a sequence of typed fields from the daemon's stderr
// channel. Each field is preceded by a type tag: 0 for integer, 1 for string.
func readFields(r io.Reader, count uint64) ([]LogField, error) {
	fields := make([]LogField, count)

	for i := uint64(0); i < count; i++ {
		fieldType, err := wire.ReadUint64(r)
		if err != nil {
			return nil, &ProtocolError{Op: "read field type", Err: err}
		}

		switch fieldType {
		case fieldTypeInt:
			v, err := wire.ReadUint64(r)
			if err != nil {
				return nil, &ProtocolError{Op: "read field int value", Err: err}
			}

			fields[i] = LogField{Int: v, IsInt: true}

		case fieldTypeString:
			s, err := wire.ReadString(r, MaxStringSize)
			if err != nil {
				return nil, &ProtocolError{Op: "read field string value", Err: err}
			}

			fields[i] = LogField{String: s, IsInt: false}

		default:
			return nil, &ProtocolError{
				Op:  "read field",
				Err: fmt.Errorf("unknown field type: %d", fieldType),
			}
		}
	}

	return fields, nil
}

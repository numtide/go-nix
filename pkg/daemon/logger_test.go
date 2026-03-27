package daemon_test

import (
	"bytes"
	"encoding/binary"
	"sync/atomic"
	"testing"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/stretchr/testify/require"
)

// Test helpers for building wire data.
func writeTestUint64(buf *bytes.Buffer, v uint64) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	buf.Write(b)
}

func writeTestString(buf *bytes.Buffer, s string) {
	writeTestUint64(buf, uint64(len(s)))
	buf.WriteString(s)

	pad := (8 - (len(s) % 8)) % 8
	for range pad {
		buf.WriteByte(0)
	}
}

func TestProcessStderrLast(t *testing.T) {
	var buf bytes.Buffer

	writeTestUint64(&buf, uint64(daemon.LogLast))

	logs := make(chan daemon.LogMessage, 10)
	err := daemon.ProcessStderr(&buf, logs, daemon.ProtocolVersion)
	require.NoError(t, err)
	require.Len(t, logs, 0)
}

func TestProcessStderrNext(t *testing.T) {
	rq := require.New(t)

	var buf bytes.Buffer

	writeTestUint64(&buf, uint64(daemon.LogNext))
	writeTestString(&buf, "building /nix/store/xxx")
	writeTestUint64(&buf, uint64(daemon.LogLast))

	logs := make(chan daemon.LogMessage, 10)
	err := daemon.ProcessStderr(&buf, logs, daemon.ProtocolVersion)
	rq.NoError(err)
	rq.Len(logs, 1)

	msg := <-logs
	rq.Equal(daemon.LogNext, msg.Type)
	rq.Equal("building /nix/store/xxx", msg.Text)
}

func TestProcessStderrError(t *testing.T) {
	rq := require.New(t)

	var buf bytes.Buffer

	writeTestUint64(&buf, uint64(daemon.LogError))
	writeTestString(&buf, "Error")          // type
	writeTestUint64(&buf, 0)                // level
	writeTestString(&buf, "SomeError")      // name
	writeTestString(&buf, "path not found") // message
	writeTestUint64(&buf, 0)                // havePos
	writeTestUint64(&buf, 0)                // nrTraces

	logs := make(chan daemon.LogMessage, 10)
	err := daemon.ProcessStderr(&buf, logs, daemon.ProtocolVersion)

	rq.Error(err)

	var de *daemon.Error

	rq.ErrorAs(err, &de)
	rq.Equal("path not found", de.Message)
	rq.Equal("SomeError", de.Name)
}

func TestProcessStderrStartStopActivity(t *testing.T) {
	rq := require.New(t)

	var buf bytes.Buffer
	// StartActivity
	writeTestUint64(&buf, uint64(daemon.LogStartActivity))
	writeTestUint64(&buf, 42)  // id
	writeTestUint64(&buf, 3)   // level (Info)
	writeTestUint64(&buf, 104) // type (ActBuilds)
	writeTestString(&buf, "building foo")
	writeTestUint64(&buf, 0) // nrFields
	writeTestUint64(&buf, 0) // parent

	// StopActivity
	writeTestUint64(&buf, uint64(daemon.LogStopActivity))
	writeTestUint64(&buf, 42) // id

	// Last
	writeTestUint64(&buf, uint64(daemon.LogLast))

	logs := make(chan daemon.LogMessage, 10)
	err := daemon.ProcessStderr(&buf, logs, daemon.ProtocolVersion)
	rq.NoError(err)
	rq.Len(logs, 2)

	msg1 := <-logs
	rq.Equal(daemon.LogStartActivity, msg1.Type)
	rq.Equal(uint64(42), msg1.Activity.ID)
	rq.Equal("building foo", msg1.Activity.Text)
	rq.Equal(daemon.ActBuilds, msg1.Activity.Type)

	msg2 := <-logs
	rq.Equal(daemon.LogStopActivity, msg2.Type)
	rq.Equal(uint64(42), msg2.ActivityID)
}

func TestProcessStderrResult(t *testing.T) {
	rq := require.New(t)

	var buf bytes.Buffer

	writeTestUint64(&buf, uint64(daemon.LogResult))
	writeTestUint64(&buf, 7)   // id
	writeTestUint64(&buf, 101) // resType (ResBuildLogLine)
	writeTestUint64(&buf, 1)   // nrFields
	writeTestUint64(&buf, 1)   // field type: string
	writeTestString(&buf, "compiling main.c")
	writeTestUint64(&buf, uint64(daemon.LogLast))

	logs := make(chan daemon.LogMessage, 10)
	err := daemon.ProcessStderr(&buf, logs, daemon.ProtocolVersion)
	rq.NoError(err)
	rq.Len(logs, 1)

	msg := <-logs
	rq.Equal(daemon.LogResult, msg.Type)
	rq.Equal(uint64(7), msg.Result.ID)
	rq.Equal(daemon.ResBuildLogLine, msg.Result.Type)
	rq.Len(msg.Result.Fields, 1)
	rq.False(msg.Result.Fields[0].IsInt)
	rq.Equal("compiling main.c", msg.Result.Fields[0].String)
}

func TestProcessStderrReadWrite(t *testing.T) {
	var buf bytes.Buffer
	// LogRead
	writeTestUint64(&buf, uint64(daemon.LogRead))
	writeTestUint64(&buf, 4096) // count (ignored)

	// LogWrite
	writeTestUint64(&buf, uint64(daemon.LogWrite))
	writeTestUint64(&buf, 8192) // count (ignored)

	// Last
	writeTestUint64(&buf, uint64(daemon.LogLast))

	logs := make(chan daemon.LogMessage, 10)
	err := daemon.ProcessStderr(&buf, logs, daemon.ProtocolVersion)
	require.NoError(t, err)
	require.Len(t, logs, 0) // Read/Write messages are silently consumed
}

func TestProcessStderrUnknownType(t *testing.T) {
	rq := require.New(t)

	var buf bytes.Buffer

	writeTestUint64(&buf, 0xDEADBEEF)

	logs := make(chan daemon.LogMessage, 10)
	err := daemon.ProcessStderr(&buf, logs, daemon.ProtocolVersion)

	rq.Error(err)

	var pe *daemon.ProtocolError

	rq.ErrorAs(err, &pe)
}

func TestProcessStderrErrorWithTraces(t *testing.T) {
	rq := require.New(t)

	var buf bytes.Buffer

	writeTestUint64(&buf, uint64(daemon.LogError))
	writeTestString(&buf, "Error")              // type
	writeTestUint64(&buf, 0)                    // level
	writeTestString(&buf, "EvalError")          // name
	writeTestString(&buf, "undefined variable") // message
	writeTestUint64(&buf, 0)                    // havePos
	writeTestUint64(&buf, 2)                    // nrTraces
	// trace 1
	writeTestUint64(&buf, 1)                  // traceHavePos
	writeTestString(&buf, "while evaluating") // traceMsg
	// trace 2
	writeTestUint64(&buf, 0)                     // traceHavePos
	writeTestString(&buf, "in file default.nix") // traceMsg

	logs := make(chan daemon.LogMessage, 10)
	err := daemon.ProcessStderr(&buf, logs, daemon.ProtocolVersion)

	rq.Error(err)

	var de *daemon.Error

	rq.ErrorAs(err, &de)
	rq.Equal("undefined variable", de.Message)
	rq.Equal("EvalError", de.Name)
	rq.Len(de.Traces, 2)
	rq.Equal("while evaluating", de.Traces[0].Message)
	rq.Equal(uint64(1), de.Traces[0].HavePos)
	rq.Equal("in file default.nix", de.Traces[1].Message)
}

func TestProcessStderrLegacyError(t *testing.T) {
	rq := require.New(t)

	var buf bytes.Buffer

	writeTestUint64(&buf, uint64(daemon.LogError))
	writeTestString(&buf, "path '/nix/store/abc' is not valid") // message
	writeTestUint64(&buf, 1)                                    // exitStatus

	logs := make(chan daemon.LogMessage, 10)
	err := daemon.ProcessStderr(&buf, logs, daemon.ProtoVersion(1, 25))

	rq.Error(err)

	var de *daemon.Error

	rq.ErrorAs(err, &de)
	rq.Equal("path '/nix/store/abc' is not valid", de.Message)
	rq.Equal(uint64(1), de.ExitStatus)
	rq.Equal("Error", de.Type)
	rq.Empty(de.Traces)
}

func TestProcessStderrActivityWithFields(t *testing.T) {
	rq := require.New(t)

	var buf bytes.Buffer

	writeTestUint64(&buf, uint64(daemon.LogStartActivity))
	writeTestUint64(&buf, 99)  // id
	writeTestUint64(&buf, 3)   // level (Info)
	writeTestUint64(&buf, 101) // type (ActFileTransfer)
	writeTestString(&buf, "downloading file")
	writeTestUint64(&buf, 2) // nrFields
	// field 1: string
	writeTestUint64(&buf, 1) // field type string
	writeTestString(&buf, "https://example.com/file.tar.gz")
	// field 2: int
	writeTestUint64(&buf, 0) // field type int
	writeTestUint64(&buf, 1048576)
	writeTestUint64(&buf, 0) // parent

	writeTestUint64(&buf, uint64(daemon.LogLast))

	logs := make(chan daemon.LogMessage, 10)
	err := daemon.ProcessStderr(&buf, logs, daemon.ProtocolVersion)
	rq.NoError(err)
	rq.Len(logs, 1)

	msg := <-logs
	rq.Equal(daemon.LogStartActivity, msg.Type)
	rq.Equal(uint64(99), msg.Activity.ID)
	rq.Equal(daemon.ActFileTransfer, msg.Activity.Type)
	rq.Len(msg.Activity.Fields, 2)
	rq.False(msg.Activity.Fields[0].IsInt)
	rq.Equal("https://example.com/file.tar.gz", msg.Activity.Fields[0].String)
	rq.True(msg.Activity.Fields[1].IsInt)
	rq.Equal(uint64(1048576), msg.Activity.Fields[1].Int)
}

func TestLogChannelSinkDropCounter(t *testing.T) {
	ch := make(chan daemon.LogMessage, 1)

	var dropped atomic.Uint64

	sink := daemon.NewLogChannelSink(ch, &dropped)

	sink.Send(daemon.LogMessage{Type: daemon.LogNext, Text: "first"})
	sink.Send(daemon.LogMessage{Type: daemon.LogNext, Text: "second"})

	require.Equal(t, uint64(1), dropped.Load())
	require.Len(t, ch, 1)
}

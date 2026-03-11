package daemon

// Centralized protocol limits to avoid unbounded allocations from malformed
// or malicious peers.
const (
	// MaxStringSize is the maximum size in bytes for strings read from the daemon
	// protocol.
	MaxStringSize = 64 * 1024 * 1024 // 64 MiB

	// MaxListEntries caps list counts read from the wire.
	MaxListEntries = 1 << 20

	// MaxMapEntries caps map entry counts read from the wire.
	MaxMapEntries = 1 << 20

	// MaxLogFields limits the number of structured fields.
	MaxLogFields = 1 << 20

	// MaxLogTraces limits the number of error traces.
	MaxLogTraces = 1 << 20

	// fieldTypeInt is the wire tag for an integer-typed log field.
	fieldTypeInt = 0
	// fieldTypeString is the wire tag for a string-typed log field.
	fieldTypeString = 1

	// optionalSome is the wire tag for a present optional value (0 = none).
	optionalSome = 1

	// numDeprecatedGCFields is the number of trailing deprecated uint64
	// fields sent in the CollectGarbage request.
	numDeprecatedGCFields = 3
)

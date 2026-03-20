package daemon

// Protocol constants.
const (
	// MaxStringSize is the maximum size in bytes for strings read from the daemon
	// protocol. Individual strings are capped to prevent unbounded allocation
	// from a malformed or corrupted peer. List and map counts are not capped
	// because large Nix stores can legitimately contain millions of paths.
	MaxStringSize = 64 * 1024 * 1024 // 64 MiB

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

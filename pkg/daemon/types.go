package daemon

import (
	"fmt"
	"io"
	"time"
)

// DefaultStoreDir is the default Nix store directory prefix.
const DefaultStoreDir = "/nix/store/"

// Protocol handshake constants.
const (
	// ClientMagic is the magic number sent by the client to initiate the handshake.
	ClientMagic uint64 = 0x6e697863 // "nixc" in ASCII

	// ServerMagic is the magic number the server responds with during the handshake.
	ServerMagic uint64 = 0x6478696f // "dxio" in ASCII

	// ProtocolVersion is the maximum protocol version we support (1.38).
	ProtocolVersion uint64 = 0x0126

	// MinProtocolVersion is the minimum protocol version we support (1.23).
	// We require 1.23+ because the framed streaming protocol (used by
	// AddToStoreNar, AddBuildLog, etc.) was introduced in 1.23. Versions
	// 1.21–1.22 use a different bidirectional STDERR_READ mechanism that
	// this client does not implement.
	MinProtocolVersion uint64 = 0x0117
)

// ProtoVersion constructs a protocol version uint64 from major and minor parts.
func ProtoVersion(major, minor uint64) uint64 {
	return (major << 8) | minor
}

const (
	ProtoVersionReserveSpace             = 0x010b // 1.11: reserve-space flag in handshake
	ProtoVersionOverrides                = 0x010c // 1.12: overrides in SetOptions
	ProtoVersionCPUAffinity              = 0x010e // 1.14: cpu-affinity flag in handshake
	ProtoVersionPathInfoMeta             = 0x0110 // 1.16: ultimate/sigs/ca in PathInfo
	ProtoVersionAddToStore               = 0x0119 // 1.25: modern AddToStore format (framed)
	ProtoVersionSubstituteOk             = 0x011b // 1.27: substituteOk in QueryValidPaths
	ProtoVersionRegisterDrvOutput        = 0x011b // 1.27: RegisterDrvOutput, QueryRealisation
	ProtoVersionBuiltOutputs             = 0x011c // 1.28: builtOutputs in BuildResult
	ProtoVersionBuildTimes               = 0x011d // 1.29: timesBuilt etc. in BuildResult
	ProtoVersionAddPermRoot              = 0x0124 // 1.36: AddPermRoot op
	ProtoVersionQueryDerivationOutputMap = 0x011e // 1.30: QueryDerivationOutputMap op
	ProtoVersionQueryMissing             = 0x011e // 1.30: QueryMissing op
	ProtoVersionRealisationJSON          = 0x011f // 1.31: JSON realisations
	ProtoVersionAddMultipleToStore       = 0x0120 // 1.32: AddMultipleToStore, AddBuildLog
	ProtoVersionNixVersion               = 0x0121 // 1.33: daemon Nix version string in handshake
	ProtoVersionBuildPathsWithResults    = 0x0122 // 1.34: BuildPathsWithResults op
	ProtoVersionTrust                    = 0x0123 // 1.35: trust level in handshake
	ProtoVersionCPUTimes                 = 0x0125 // 1.37: cpuUser/cpuSystem in BuildResult
	ProtoVersionFeatureExchange          = 0x0126 // 1.38: feature set exchange in handshake
)

// Operation represents a daemon worker operation code.
type Operation uint64

// Daemon operation codes.
const (
	OpIsValidPath                 Operation = 1
	OpQueryReferrers              Operation = 6
	OpAddToStore                  Operation = 7
	OpBuildPaths                  Operation = 9
	OpEnsurePath                  Operation = 10
	OpAddTempRoot                 Operation = 11
	OpAddIndirectRoot             Operation = 12
	OpFindRoots                   Operation = 14
	OpSetOptions                  Operation = 19
	OpCollectGarbage              Operation = 20
	OpQueryAllValidPaths          Operation = 23
	OpQueryPathInfo               Operation = 26
	OpQueryPathFromHashPart       Operation = 29
	OpQuerySubstitutablePathInfos Operation = 30
	OpQueryValidPaths             Operation = 31
	OpQuerySubstitutablePaths     Operation = 32
	OpQueryValidDerivers          Operation = 33
	OpOptimiseStore               Operation = 34
	OpVerifyStore                 Operation = 35
	OpBuildDerivation             Operation = 36
	OpAddSignatures               Operation = 37
	OpNarFromPath                 Operation = 38
	OpAddToStoreNar               Operation = 39
	OpQueryMissing                Operation = 40
	OpQueryDerivationOutputMap    Operation = 41
	OpRegisterDrvOutput           Operation = 42
	OpQueryRealisation            Operation = 43
	OpAddMultipleToStore          Operation = 44
	OpAddBuildLog                 Operation = 45
	OpBuildPathsWithResults       Operation = 46
	OpAddPermRoot                 Operation = 47
)

//nolint:gochecknoglobals
var operationNames = map[Operation]string{
	OpIsValidPath:                 "IsValidPath",
	OpQueryReferrers:              "QueryReferrers",
	OpAddToStore:                  "AddToStore",
	OpBuildPaths:                  "BuildPaths",
	OpEnsurePath:                  "EnsurePath",
	OpAddTempRoot:                 "AddTempRoot",
	OpAddIndirectRoot:             "AddIndirectRoot",
	OpFindRoots:                   "FindRoots",
	OpSetOptions:                  "SetOptions",
	OpCollectGarbage:              "CollectGarbage",
	OpQueryAllValidPaths:          "QueryAllValidPaths",
	OpQueryPathInfo:               "QueryPathInfo",
	OpQueryPathFromHashPart:       "QueryPathFromHashPart",
	OpQuerySubstitutablePathInfos: "QuerySubstitutablePathInfos",
	OpQueryValidPaths:             "QueryValidPaths",
	OpQuerySubstitutablePaths:     "QuerySubstitutablePaths",
	OpQueryValidDerivers:          "QueryValidDerivers",
	OpOptimiseStore:               "OptimiseStore",
	OpVerifyStore:                 "VerifyStore",
	OpBuildDerivation:             "BuildDerivation",
	OpAddSignatures:               "AddSignatures",
	OpNarFromPath:                 "NarFromPath",
	OpAddToStoreNar:               "AddToStoreNar",
	OpQueryMissing:                "QueryMissing",
	OpQueryDerivationOutputMap:    "QueryDerivationOutputMap",
	OpRegisterDrvOutput:           "RegisterDrvOutput",
	OpQueryRealisation:            "QueryRealisation",
	OpAddMultipleToStore:          "AddMultipleToStore",
	OpAddBuildLog:                 "AddBuildLog",
	OpBuildPathsWithResults:       "BuildPathsWithResults",
	OpAddPermRoot:                 "AddPermRoot",
}

// String returns the human-readable name of the operation.
func (o Operation) String() string {
	if name, ok := operationNames[o]; ok {
		return name
	}

	return fmt.Sprintf("Operation(%d)", o)
}

// TrustLevel indicates the trust level of the client as reported by the daemon.
type TrustLevel uint64

const (
	TrustUnknown    TrustLevel = 0
	TrustTrusted    TrustLevel = 1
	TrustNotTrusted TrustLevel = 2
)

// LogMessageType represents a log message type sent by the daemon on the stderr channel.
type LogMessageType uint64

const (
	LogLast          LogMessageType = 0x616c7473
	LogError         LogMessageType = 0x63787470
	LogNext          LogMessageType = 0x6f6c6d67
	LogRead          LogMessageType = 0x64617461
	LogWrite         LogMessageType = 0x64617416
	LogStartActivity LogMessageType = 0x53545254
	LogStopActivity  LogMessageType = 0x53544f50
	LogResult        LogMessageType = 0x52534c54
)

// ActivityType represents the type of an activity in log messages.
type ActivityType uint64

const (
	ActUnknown       ActivityType = 0
	ActCopyPath      ActivityType = 100
	ActFileTransfer  ActivityType = 101
	ActRealise       ActivityType = 102
	ActCopyPaths     ActivityType = 103
	ActBuilds        ActivityType = 104
	ActBuild         ActivityType = 105
	ActOptimiseStore ActivityType = 106
	ActVerifyPaths   ActivityType = 107
	ActSubstitute    ActivityType = 108
	ActQueryPathInfo ActivityType = 109
	ActPostBuildHook ActivityType = 110
	ActBuildWaiting  ActivityType = 111
	ActFetchTree     ActivityType = 112
)

// ResultType represents the type of a result in log messages.
type ResultType uint64

const (
	ResFileLinked       ResultType = 100
	ResBuildLogLine     ResultType = 101
	ResUntrustedPath    ResultType = 102
	ResCorruptedPath    ResultType = 103
	ResSetPhase         ResultType = 104
	ResProgress         ResultType = 105
	ResSetExpected      ResultType = 106
	ResPostBuildLogLine ResultType = 107
	ResFetchStatus      ResultType = 108
)

// Verbosity represents the logging verbosity level.
type Verbosity uint64

const (
	VerbError     Verbosity = 0
	VerbWarn      Verbosity = 1
	VerbNotice    Verbosity = 2
	VerbInfo      Verbosity = 3
	VerbTalkative Verbosity = 4
	VerbChatty    Verbosity = 5
	VerbDebug     Verbosity = 6
	VerbVomit     Verbosity = 7
)

// BuildMode controls how a build operation is performed.
type BuildMode uint64

const (
	BuildModeNormal BuildMode = 0
	BuildModeRepair BuildMode = 1
	BuildModeCheck  BuildMode = 2
)

// BuildStatus represents the result status of a build operation.
type BuildStatus uint64

const (
	BuildStatusBuilt                  BuildStatus = 0
	BuildStatusSubstituted            BuildStatus = 1
	BuildStatusAlreadyValid           BuildStatus = 2
	BuildStatusPermanentFailure       BuildStatus = 3
	BuildStatusInputRejected          BuildStatus = 4
	BuildStatusOutputRejected         BuildStatus = 5
	BuildStatusTransientFailure       BuildStatus = 6
	BuildStatusCachedFailure          BuildStatus = 7
	BuildStatusTimedOut               BuildStatus = 8
	BuildStatusMiscFailure            BuildStatus = 9
	BuildStatusDependencyFailed       BuildStatus = 10
	BuildStatusLogLimitExceeded       BuildStatus = 11
	BuildStatusNotDeterministic       BuildStatus = 12
	BuildStatusResolvesToAlreadyValid BuildStatus = 13
	BuildStatusNoSubstituters         BuildStatus = 14
)

//nolint:gochecknoglobals
var buildStatusNames = map[BuildStatus]string{
	BuildStatusBuilt:                  "Built",
	BuildStatusSubstituted:            "Substituted",
	BuildStatusAlreadyValid:           "AlreadyValid",
	BuildStatusPermanentFailure:       "PermanentFailure",
	BuildStatusInputRejected:          "InputRejected",
	BuildStatusOutputRejected:         "OutputRejected",
	BuildStatusTransientFailure:       "TransientFailure",
	BuildStatusCachedFailure:          "CachedFailure",
	BuildStatusTimedOut:               "TimedOut",
	BuildStatusMiscFailure:            "MiscFailure",
	BuildStatusDependencyFailed:       "DependencyFailed",
	BuildStatusLogLimitExceeded:       "LogLimitExceeded",
	BuildStatusNotDeterministic:       "NotDeterministic",
	BuildStatusResolvesToAlreadyValid: "ResolvesToAlreadyValid",
	BuildStatusNoSubstituters:         "NoSubstituters",
}

// String returns the human-readable name of the build status.
func (s BuildStatus) String() string {
	if name, ok := buildStatusNames[s]; ok {
		return name
	}

	return fmt.Sprintf("BuildStatus(%d)", s)
}

// GCAction specifies the garbage collection action to perform.
type GCAction uint64

const (
	GCReturnLive     GCAction = 0
	GCReturnDead     GCAction = 1
	GCDeleteDead     GCAction = 2
	GCDeleteSpecific GCAction = 3
)

// PathInfo holds the metadata for a store path, as returned by QueryPathInfo.
type PathInfo struct {
	// StorePath is the store path this info describes.
	StorePath string
	// Deriver is the store path of the derivation that produced this path, if known.
	Deriver string
	// NarHash is the hash of the NAR serialisation of the path contents (e.g. "sha256:...").
	NarHash string
	// References is the set of store paths this path depends on at runtime.
	References []string
	// RegistrationTime is the Unix timestamp when the path was registered.
	RegistrationTime uint64
	// NarSize is the size of the NAR serialisation in bytes.
	NarSize uint64
	// Ultimate indicates whether this path was built locally (trusted content).
	Ultimate bool
	// Sigs contains the cryptographic signatures on this path.
	Sigs []string
	// CA is the content-address of this path, if it is content-addressed.
	CA string
}

// BuildResult holds the result of a build operation.
type BuildResult struct {
	// Status is the outcome of the build.
	Status BuildStatus
	// ErrorMsg contains a human-readable error message, if the build failed.
	ErrorMsg string
	// TimesBuilt counts how many times this derivation has been built.
	TimesBuilt uint64
	// IsNonDeterministic indicates whether the build was detected as non-deterministic.
	IsNonDeterministic bool
	// StartTime is the Unix timestamp when the build started.
	StartTime uint64
	// StopTime is the Unix timestamp when the build finished.
	StopTime uint64
	// CpuUser is the user CPU time consumed by the build, if available (protocol >= 1.37).
	CpuUser *time.Duration
	// CpuSystem is the system CPU time consumed by the build, if available (protocol >= 1.37).
	CpuSystem *time.Duration
	// BuiltOutputs maps output names to their realisations.
	BuiltOutputs map[string]Realisation
}

// Realisation represents a content-addressed realisation of a derivation output.
type Realisation struct {
	// ID is the derivation-output identifier (e.g. "sha256:hash!out").
	ID string `json:"id"`
	// OutPath is the store path of the realised output.
	OutPath string `json:"outPath"`
	// Signatures contains the cryptographic signatures on this realisation.
	Signatures []string `json:"signatures"`
	// DependentRealisations maps dependent derivation-output IDs to their output paths.
	DependentRealisations map[string]string `json:"dependentRealisations"`
}

// MissingInfo holds the result of a QueryMissing operation.
type MissingInfo struct {
	// WillBuild is the set of store paths that will be built.
	WillBuild []string
	// WillSubstitute is the set of store paths that will be substituted.
	WillSubstitute []string
	// Unknown is the set of store paths whose build status is unknown.
	Unknown []string
	// DownloadSize is the total size of files to download in bytes.
	DownloadSize uint64
	// NarSize is the total unpacked NAR size in bytes.
	NarSize uint64
}

// SubstitutablePathInfo holds substitution metadata for a store path, as
// returned by QuerySubstitutablePathInfos.
type SubstitutablePathInfo struct {
	// Deriver is the store path of the derivation that produced this path,
	// or empty if unknown.
	Deriver string
	// References is the set of store paths this path depends on at runtime.
	References []string
	// DownloadSize is the size in bytes to download from a binary cache (0 if unknown).
	DownloadSize uint64
	// NarSize is the size of the NAR serialisation in bytes (0 if unknown).
	NarSize uint64
}

// GCOptions specifies the parameters for a garbage collection operation.
type GCOptions struct {
	// Action is the garbage collection action to perform.
	Action GCAction
	// PathsToDelete specifies specific paths to delete (for GCDeleteSpecific).
	PathsToDelete []string
	// IgnoreLiveness indicates whether to ignore runtime root liveness.
	IgnoreLiveness bool
	// MaxFreed is the maximum number of bytes to free (0 means unlimited).
	MaxFreed uint64
}

// GCResult holds the result of a garbage collection operation.
type GCResult struct {
	// Paths is the set of store paths returned or deleted.
	Paths []string
	// BytesFreed is the total number of bytes freed.
	BytesFreed uint64
}

// Activity represents a structured log activity started by the daemon.
type Activity struct {
	// ID is the unique identifier of this activity.
	ID uint64
	// Level is the verbosity level of this activity.
	Level Verbosity
	// Type is the type of this activity.
	Type ActivityType
	// Text is the human-readable activity description.
	Text string
	// Fields contains additional structured fields.
	Fields []LogField
	// Parent is the ID of the parent activity, or 0 if none.
	Parent uint64
}

// ActivityResult represents a result event within a running activity.
type ActivityResult struct {
	// ID is the ID of the activity this result belongs to.
	ID uint64
	// Type is the type of this result.
	Type ResultType
	// Fields contains additional structured fields.
	Fields []LogField
}

// LogField represents a typed field in a structured log message.
// Exactly one of Int or String is set.
type LogField struct {
	// Int holds the integer value, if this is an integer field.
	Int uint64
	// String holds the string value, if this is a string field.
	String string
	// IsInt is true if this field is an integer, false if it is a string.
	IsInt bool
}

// LogMessage represents a log message received from the daemon on the stderr channel.
type LogMessage struct {
	// Type is the log message type.
	Type LogMessageType
	// Text is the log message text (for LogNext).
	Text string
	// Activity is set for LogStartActivity messages.
	Activity *Activity
	// ActivityID is set for LogStopActivity messages.
	ActivityID uint64
	// Result is set for LogResult messages.
	Result *ActivityResult
}

// BasicDerivation represents a derivation for BuildDerivation.
// This is the wire format, not the full derivation with input derivations.
type BasicDerivation struct {
	// Outputs maps output names to their output definitions.
	Outputs map[string]DerivationOutput
	// Inputs is the list of input store paths (sources).
	Inputs []string
	// Platform is the system type, e.g. "x86_64-linux".
	Platform string
	// Builder is the path to the builder executable.
	Builder string
	// Args is the list of arguments to the builder.
	Args []string
	// Env maps environment variable names to their values.
	Env map[string]string
}

// DerivationOutput represents a single output of a derivation.
type DerivationOutput struct {
	// Path is the store path of the output (empty for floating/deferred outputs).
	Path string
	// HashAlgorithm is the hash algorithm descriptor, e.g. "r:sha256" (empty for input-addressed).
	HashAlgorithm string
	// Hash is the expected hash in Nix base32 (empty if not fixed-output).
	Hash string
}

// AddToStoreItem represents a single store path item to be added via AddMultipleToStore.
type AddToStoreItem struct {
	// Info is the path metadata.
	Info PathInfo
	// Source is the NAR content reader (used during encoding).
	Source io.Reader
}

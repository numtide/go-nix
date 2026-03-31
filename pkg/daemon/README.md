# Nix Daemon Protocol

This package implements a client for the Nix daemon worker protocol.
It communicates over a Unix domain socket (typically `/nix/var/nix/daemon-socket/socket`).

The protocol is binary, little-endian, and request-response with interleaved log messages on the response side.

## Wire Format

All integers are unsigned 64-bit little-endian.

### Basic Types

**uint64**: 8 bytes, little-endian.

**bool**: encoded as uint64 (1 = true, 0 = false).

**string**: length-prefixed with 8-byte alignment padding.

```
[length: uint64] [content: length bytes] [padding: 0-7 null bytes]
```

**string list**:

```
[count: uint64] [string] [string] ...
```

**string map**: keys are sorted lexicographically before encoding.

```
[count: uint64] [key: string] [value: string] [key: string] [value: string] ...
```

### Framed Streaming

Large binary payloads (NAR data, build logs) use a chunked framing protocol.
Data is split into frames of up to 32 KiB, terminated by a zero-length frame:

```
[length: uint64] [data: length bytes] ... [0: uint64]
```

## Connection Handshake

The client initiates a connection by writing a magic number.
The server responds with its own magic number and protocol version.
Both sides negotiate down to the minimum supported version.

```
Client -> Server: [0x6e697863: uint64]              // "nixc"
Server -> Client: [0x6478696f: uint64]              // "dxio"
Server -> Client: [serverVersion: uint64]
Client -> Server: [negotiatedVersion: uint64]        // min(server, client)
```

The remaining handshake fields are sent in this order, each conditional on the negotiated version:

```
Client -> Server: [clientFeatures: string[]]           // (>= 1.38)
Server -> Client: [daemonFeatures: string[]]           // (>= 1.38)
Client -> Server: [cpuAffinity: bool]                  // (>= 1.14) vestigial, always false
Client -> Server: [reserveSpace: bool]                 // (>= 1.11) vestigial, always false
Server -> Client: [daemonNixVersion: string]           // (>= 1.33)
Server -> Client: [trustLevel: uint64]                 // (>= 1.35) 0=unknown, 1=trusted, 2=untrusted
```

The `cpuAffinity` and `reserveSpace` fields are vestigial.

Nix once used CPU affinity to pin daemon workers to specific cores, and reserve-space to pre-allocate disk in the store.
Both features were removed from Nix, but the protocol still requires the fields because the handshake is a fixed 
positional sequence — skipping them would desynchronise the stream. 

Clients must always send `false` for both.

After the handshake completes, the client drains any startup log messages from the daemon.

**Supported range**: protocol 1.23 (minimum) through 1.38 (maximum).

## Request-Response Cycle

Each operation follows this pattern:

1. Client writes the operation code (uint64) and request payload, then flushes.
2. Server processes the request.
3. Server sends a stream of log messages on the same connection (progress, errors, activity updates).
4. Server sends `LogLast` to signal the end of the log stream.
5. Client reads the response payload that follows.

The log messages and response payload share a single byte stream — the client must consume all
log messages before it can read the response data.
This is what is meant by _interleaved log messages_: the daemon mixes status/progress information into the response
channel rather than using a separate side channel.

> [!CAUTION]
> The client is **not thread-safe**. Callers must serialize operations externally.

## Log Messages

During step 3 above, the daemon sends zero or more log messages before the response payload.
Each message starts with a type tag (`uint64`):

| Tag          | Name             | Payload                      |
|--------------|------------------|------------------------------|
| `0x616c7473` | LogLast          | (none) - end of log stream   |
| `0x63787470` | LogError         | structured error (see below) |
| `0x6f6c6d67` | LogNext          | `[message: string]`          |
| `0x64617461` | LogRead          | `[count: uint64]`            |
| `0x64617416` | LogWrite         | `[count: uint64]`            |
| `0x53545254` | LogStartActivity | `Activity` struct            |
| `0x53544f50` | LogStopActivity  | `[id: uint64]`               |
| `0x52534c54` | LogResult        | `ActivityResult` struct      |

### Structured Errors (protocol >= 1.26)

```
[type: string]       // error category (e.g. "nix::Error")
[level: uint64]      // verbosity level
[name: string]       // error name
[message: string]    // human-readable description
[havePos: uint64]    // source position flag
[nrTraces: uint64]   // number of trace entries
For each trace:
  [havePos: uint64]  // source position flag (see below)
  [message: string]
```

Pre-1.26 errors use a simpler format: `[message: string] [exitStatus: uint64]`.

### Activity Structure

```
[id: uint64]
[level: uint64]          // verbosity
[type: uint64]           // activity type (see table below)
[text: string]           // description
[fieldCount: uint64]     // number of structured fields
For each field:
  [fieldType: uint64]    // 0=int, 1=string
  [value: uint64|string]
[parent: uint64]         // parent activity ID, or 0
```

Activity types:

| Value | Name          | Description                          |
|-------|---------------|--------------------------------------|
| 0     | Unknown       | Unknown or unrecognised activity     |
| 100   | CopyPath      | Copying a single store path          |
| 101   | FileTransfer  | Downloading a file                   |
| 102   | Realise       | Realising a store path               |
| 103   | CopyPaths     | Copying multiple store paths         |
| 104   | Builds        | Top-level build orchestration        |
| 105   | Build         | Building a single derivation         |
| 106   | OptimiseStore | Optimising the store (hard-linking)  |
| 107   | VerifyPaths   | Verifying store path integrity       |
| 108   | Substitute    | Substituting a store path            |
| 109   | QueryPathInfo | Querying path info from a cache      |
| 110   | PostBuildHook | Running a post-build hook            |
| 111   | BuildWaiting  | Build waiting for a lock or resource |
| 112   | FetchTree     | Fetching a source tree (flake input) |

## Operations

### Query Operations

#### IsValidPath (op 1)

```
Request:  [path: string]
Response: [valid: bool]
```

#### QueryReferrers (op 6)

Returns store paths that reference (depend on) the given path.

```
Request:  [path: string]
Response: [paths: string[]]
```

#### QueryAllValidPaths (op 23)

```
Request:  (none)
Response: [paths: string[]]
```

#### QueryPathInfo (op 26)

```
Request:  [path: string]
Response: [found: bool]
           If found: [PathInfo]
```

PathInfo wire format:

```
[storePath: string]
[deriver: string]        // empty if unknown
[narHash: string]        // e.g. "sha256:..."
[references: string[]]
[registrationTime: uint64]
[narSize: uint64]
[ultimate: bool]         // (>= 1.16)
[sigs: string[]]         // (>= 1.16)
[ca: string]             // (>= 1.16)
```

#### QueryPathFromHashPart (op 29)

```
Request:  [hashPart: string]   // 32-char nixbase32 hash
Response: [path: string]       // empty if not found
```

#### QueryValidPaths (op 31)

```
Request:  [paths: string[]]
          [substituteOk: bool]   // (>= 1.27)
Response: [validPaths: string[]]
```

#### QuerySubstitutablePaths (op 32)

Returns the subset of paths that can be fetched from a binary cache.

```
Request:  [paths: string[]]
Response: [substitutablePaths: string[]]
```

#### QuerySubstitutablePathInfos (op 30)

```
Request:  [count: uint64]
          For each: [storePath: string] [ca: string]
Response: [count: uint64]
          For each: [storePath: string] [SubstitutablePathInfo]
```

SubstitutablePathInfo:

```
[deriver: string]
[references: string[]]
[downloadSize: uint64]
[narSize: uint64]
```

#### QueryValidDerivers (op 33)

Returns derivations known to have produced the given path.

```
Request:  [path: string]
Response: [derivers: string[]]
```

#### QueryMissing (op 40, >= 1.30)

Classifies paths into build/substitute/unknown categories.

```
Request:  [paths: string[]]
Response: [willBuild: string[]]
          [willSubstitute: string[]]
          [unknown: string[]]
          [downloadSize: uint64]
          [narSize: uint64]
```

#### QueryDerivationOutputMap (op 41, >= 1.30)

```
Request:  [drvPath: string]
Response: [outputs: map[string]string]   // output name -> store path
```

#### QueryRealisation (op 43, >= 1.31)

```
Request:  [outputID: string]   // e.g. "sha256:hash!out"
Response: [count: uint64]
          For each: [json: string]   // JSON-encoded Realisation
```

### Store Operations

#### AddToStore (op 7, >= 1.25)

Content-addressed import.
The daemon computes the store path.

```
Request:  [name: string]
          [caMethodWithAlgo: string]   // e.g. "fixed:r:sha256", "fixed:sha256"
          [references: string[]]
          [repair: bool]
          [source: framed]             // NAR data (recursive) or raw content (flat)
Response: [storePath: string]
          [PathInfo]
```

#### AddToStoreNar (op 39)

Direct NAR import with explicit metadata.

```
Request:  [PathInfo]
          [repair: bool]
          [dontCheckSigs: bool]
          [narData: framed]
Response: (logs only)
```

#### AddMultipleToStore (op 44, >= 1.32)

Batch import of multiple paths in a single framed stream.

```
Request:  [repair: bool]
          [dontCheckSigs: bool]
          Framed stream containing:
            [count: uint64]
            For each: [PathInfo] [narData: raw bytes]
Response: (logs only)
```

#### AddSignatures (op 37)

```
Request:  [path: string] [sigs: string[]]
Response: [ack: uint64]
```

#### NarFromPath (op 38)

Streams a NAR archive of the given path.

```
Request:  [path: string]
Response: (log messages, then NAR data streamed directly)
```

#### OptimiseStore (op 34)

Hard-links identical files in the store.

```
Request:  (none)
Response: [ack: uint64]
```

#### VerifyStore (op 35)

```
Request:  [checkContents: bool] [repair: bool]
Response: [errorsFound: bool]
```

### Build Operations

#### BuildPaths (op 9)

```
Request:  [paths: string[]] [mode: uint64]   // 0=normal, 1=repair, 2=check
Response: [ack: uint64]
```

#### BuildDerivation (op 36)

Builds a derivation in-memory (without requiring a .drv file in the store).

```
Request:  [drvPath: string]
          [BasicDerivation]
          [mode: uint64]
Response: [BuildResult]
```

BasicDerivation wire format:

```
[outputCount: uint64]
For each output (sorted by name):
  [name: string] [path: string] [hashAlgorithm: string] [hash: string]
[inputs: string[]]
[platform: string]
[builder: string]
[args: string[]]
[env: map[string]string]
```

BuildResult wire format:

```
[status: uint64]
[errorMsg: string]
[timesBuilt: uint64]          // (>= 1.29)
[isNonDeterministic: bool]    // (>= 1.29)
[startTime: uint64]           // (>= 1.29)
[stopTime: uint64]            // (>= 1.29)
[cpuUser: optional<uint64>]   // microseconds (>= 1.37)
[cpuSystem: optional<uint64>] // microseconds (>= 1.37)
[builtOutputs: ...]           // (>= 1.28) map of output realisations
```

#### BuildPathsWithResults (op 46, >= 1.34)

Like BuildPaths but returns per-path build results.

```
Request:  [paths: string[]] [mode: uint64]
Response: [count: uint64]
          For each: [derivedPath: string] [BuildResult]
```

#### EnsurePath (op 10)

Ensures a path is valid, substituting if necessary.

```
Request:  [path: string]
Response: [ack: uint64]
```

### GC Operations

#### AddTempRoot (op 11)

Prevents the given path from being garbage-collected for the duration of the connection.

```
Request:  [path: string]
Response: [ack: uint64]
```

#### AddIndirectRoot (op 12)

Registers a symlink as an indirect GC root.

```
Request:  [symlinkPath: string]
Response: [ack: uint64]
```

#### AddPermRoot (op 47, >= 1.36)

Creates a permanent GC root symlink.

```
Request:  [storePath: string] [gcRootPath: string]
Response: [resultPath: string]
```

#### FindRoots (op 14)

```
Request:  (none)
Response: [roots: map[string]string]   // symlink -> store path
```

#### CollectGarbage (op 20)

```
Request:  [action: uint64]          // 0=returnLive, 1=returnDead, 2=deleteDead, 3=deleteSpecific
          [pathsToDelete: string[]]
          [ignoreLiveness: bool]
          [maxFreed: uint64]
          [deprecated1: uint64]     // 3 deprecated fields, always 0
          [deprecated2: uint64]
          [deprecated3: uint64]
Response: [paths: string[]]
          [bytesFreed: uint64]
```

### Configuration

#### SetOptions (op 19)

```
Request:  [keepFailed: bool]
          [keepGoing: bool]
          [tryFallback: bool]
          [verbosity: uint64]
          [maxBuildJobs: uint64]
          [maxSilentTime: uint64]
          [useBuildHook: bool]     // deprecated, always true
          [buildVerbosity: uint64]
          [logType: uint64]        // deprecated, always 0
          [printBuildTrace: uint64] // deprecated, always 0
          [buildCores: uint64]
          [useSubstitutes: bool]
          [overrides: map[string]string]  // (>= 1.12)
Response: (logs only)
```

### Realisation Operations

#### RegisterDrvOutput (op 42, >= 1.31)

```
Request:  [realisationJSON: string]
Response: (logs only)
```

#### AddBuildLog (op 45, >= 1.32)

```
Request:  [drvPath: string] [logData: framed]
Response: [ack: uint64]
```

## Protocol Version History

| Version | Features Added                                                       |
|---------|----------------------------------------------------------------------|
| 1.11    | Reserve-space handshake flag                                         |
| 1.12    | Setting overrides in SetOptions                                      |
| 1.14    | CPU-affinity handshake flag                                          |
| 1.16    | PathInfo: ultimate, sigs, ca fields                                  |
| 1.25    | Modern AddToStore (framed content-addressed import)                  |
| 1.26    | Structured errors with type/level/traces                             |
| 1.27    | SubstituteOk in QueryValidPaths; RegisterDrvOutput, QueryRealisation |
| 1.28    | BuiltOutputs in BuildResult                                          |
| 1.29    | Build timing fields in BuildResult                                   |
| 1.30    | QueryDerivationOutputMap, QueryMissing                               |
| 1.31    | JSON-encoded realisations                                            |
| 1.32    | AddMultipleToStore, AddBuildLog                                      |
| 1.33    | Daemon Nix version in handshake                                      |
| 1.34    | BuildPathsWithResults                                                |
| 1.35    | Trust level in handshake                                             |
| 1.37    | cpuUser/cpuSystem in BuildResult                                     |
| 1.38    | Feature set exchange in handshake                                    |

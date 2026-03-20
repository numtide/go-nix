package derivation

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/nix-community/go-nix/pkg/nixhash"
	"github.com/nix-community/go-nix/pkg/storepath"
)

// Intermediate structs for JSON unmarshaling (v3/v4 formats).

// jsonInputDrv represents a v3/v4 input derivation entry.
type jsonInputDrv struct {
	Outputs        []string                `json:"outputs"`
	DynamicOutputs map[string]jsonInputDrv `json:"dynamicOutputs"`
}

// jsonOutput represents a v3/v4 output (superset of all output type fields).
type jsonOutput struct {
	Path     string `json:"path,omitempty"`
	Method   string `json:"method,omitempty"`
	HashAlgo string `json:"hashAlgo,omitempty"`
	Hash     string `json:"hash,omitempty"`
}

// jsonDerivationV3 is the v3 derivation layout.
type jsonDerivationV3 struct {
	Name      string                  `json:"name"`
	Version   int                     `json:"version"`
	Outputs   map[string]jsonOutput   `json:"outputs"`
	InputSrcs []string                `json:"inputSrcs"`
	InputDrvs map[string]jsonInputDrv `json:"inputDrvs"`
	System    string                  `json:"system"`
	Builder   string                  `json:"builder"`
	Args      []string                `json:"args"`
	Env       map[string]string       `json:"env"`
}

// jsonDerivationV4 is the v4 derivation layout.
type jsonDerivationV4 struct {
	Name    string                `json:"name"`
	Version int                   `json:"version"`
	Outputs map[string]jsonOutput `json:"outputs"`
	Inputs  struct {
		Srcs []string                `json:"srcs"`
		Drvs map[string]jsonInputDrv `json:"drvs"`
	} `json:"inputs"`
	System  string            `json:"system"`
	Builder string            `json:"builder"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

// ReadDerivationJSON reads a single derivation from JSON (v1, v3, or v4 format).
// It returns an error if the document contains zero or more than one derivation.
// This matches the ReadDerivation signature for use in Store implementations.
func ReadDerivationJSON(reader io.Reader) (*Derivation, error) {
	drvs, err := ReadDerivationsJSON(reader)
	if err != nil {
		return nil, err
	}

	if len(drvs) != 1 {
		return nil, fmt.Errorf("expected exactly 1 derivation, got %d", len(drvs))
	}

	for _, drv := range drvs {
		return drv, nil
	}

	panic("unreachable")
}

// ReadDerivationsJSON reads one or more derivations from JSON (v1, v3, or v4 format).
// Returns map[drvPath]*Derivation. Paths are normalized to full store paths.
// Each derivation is validated before being returned.
// Use ReadDerivationJSON when exactly one derivation is expected.
func ReadDerivationsJSON(reader io.Reader) (map[string]*Derivation, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading JSON: %w", err)
	}

	// Single parse into a generic map for version detection and data extraction.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	// Check for v4 wrapper: has "version" and "derivations" keys.
	if drvs, ok, err := tryParseV4Wrapper(raw); ok {
		return drvs, err
	} else if err != nil {
		return nil, err
	}

	// Otherwise it's a map of drvPath -> derivation data.
	// Peek at the first value to detect version.
	var sample json.RawMessage
	for _, v := range raw {
		sample = v

		break
	}

	if sample == nil {
		return nil, fmt.Errorf("empty JSON object")
	}

	version, err := detectInnerVersion(sample)
	if err != nil {
		return nil, err
	}

	switch version {
	case 3:
		return parseDrvMap(raw, parseV3Derivation)
	case 4:
		return parseDrvMap(raw, parseV4Derivation)
	default:
		return parseV1(raw)
	}
}

// detectInnerVersion peeks at a derivation JSON object to find its version.
// Returns 0 for v1 (no version field).
func detectInnerVersion(data json.RawMessage) (int, error) {
	var peek struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &peek); err != nil {
		return 0, fmt.Errorf("detecting version: %w", err)
	}

	return peek.Version, nil
}

// tryParseV4Wrapper checks if raw is a v4 wrapper document and parses it.
// Returns (result, true, nil) on success, (nil, false, nil) if not a v4 wrapper,
// or (nil, false, err) on parse failure.
func tryParseV4Wrapper(raw map[string]json.RawMessage) (map[string]*Derivation, bool, error) {
	versionRaw, hasVersion := raw["version"]
	if !hasVersion {
		return nil, false, nil
	}

	derivationsRaw, hasDrvs := raw["derivations"]
	if !hasDrvs {
		return nil, false, nil
	}

	var version int
	if err := json.Unmarshal(versionRaw, &version); err != nil {
		return nil, false, fmt.Errorf("parsing wrapper version: %w", err)
	}

	if version != 4 {
		return nil, false, fmt.Errorf("expected wrapper version 4, got %d", version)
	}

	var innerMap map[string]json.RawMessage
	if err := json.Unmarshal(derivationsRaw, &innerMap); err != nil {
		return nil, false, fmt.Errorf("parsing v4 derivations: %w", err)
	}

	result, err := parseDrvMap(innerMap, parseV4Derivation)

	return result, true, err
}

// storePathMinLen is the minimum length of a short store path: 32 nixbase32 chars + "-" + at least 1 name char.
const storePathMinLen = 34

// expandStorePath ensures a store path is absolute.
// Only expands paths that look like short store paths (hash-name format, not starting with /).
func expandStorePath(s string) string {
	if s == "" || s[0] == '/' || len(s) < storePathMinLen {
		return s
	}

	return storepath.StoreDir + "/" + s
}

// parseDrvMap parses derivations from a map using the provided parse function.
func parseDrvMap(
	raw map[string]json.RawMessage,
	parse func(json.RawMessage) (*Derivation, error),
) (map[string]*Derivation, error) {
	result := make(map[string]*Derivation, len(raw))

	for path, rawDrv := range raw {
		drv, err := parse(rawDrv)
		if err != nil {
			return nil, fmt.Errorf("parsing derivation %s: %w", path, err)
		}

		if err := drv.Validate(); err != nil {
			return nil, fmt.Errorf("validating derivation %s: %w", path, err)
		}

		result[expandStorePath(path)] = drv
	}

	return result, nil
}

// parseV1 parses v1 format from an already-unmarshaled map.
func parseV1(raw map[string]json.RawMessage) (map[string]*Derivation, error) {
	result := make(map[string]*Derivation, len(raw))

	for path, rawDrv := range raw {
		var drv Derivation
		if err := json.Unmarshal(rawDrv, &drv); err != nil {
			return nil, fmt.Errorf("parsing v1 derivation %s: %w", path, err)
		}

		if err := drv.Validate(); err != nil {
			return nil, fmt.Errorf("validating derivation %s: %w", path, err)
		}

		result[path] = &drv
	}

	return result, nil
}

// parseV3Derivation converts a v3 JSON derivation to a Derivation.
func parseV3Derivation(data json.RawMessage) (*Derivation, error) {
	var jd jsonDerivationV3
	if err := json.Unmarshal(data, &jd); err != nil {
		return nil, fmt.Errorf("unmarshaling v3: %w", err)
	}

	outputs, err := convertOutputs(jd.Outputs, convertOutputV3)
	if err != nil {
		return nil, err
	}

	drv := &Derivation{
		Outputs:          outputs,
		InputSources:     expandStorePaths(jd.InputSrcs),
		InputDerivations: convertInputDrvs(jd.InputDrvs),
		Platform:         jd.System,
		Builder:          expandStorePath(jd.Builder),
		Arguments:        jd.Args,
		Env:              jd.Env,
	}

	if jd.Name != "" {
		drv.SetName(jd.Name)
	}

	if err := drv.computeMissingOutputPaths(); err != nil {
		return nil, err
	}

	return drv, nil
}

// parseV4Derivation converts a v4 JSON derivation to a Derivation.
func parseV4Derivation(data json.RawMessage) (*Derivation, error) {
	var jd jsonDerivationV4
	if err := json.Unmarshal(data, &jd); err != nil {
		return nil, fmt.Errorf("unmarshaling v4: %w", err)
	}

	outputs, err := convertOutputs(jd.Outputs, convertOutputV4)
	if err != nil {
		return nil, err
	}

	drv := &Derivation{
		Outputs:          outputs,
		InputSources:     expandStorePaths(jd.Inputs.Srcs),
		InputDerivations: convertInputDrvs(jd.Inputs.Drvs),
		Platform:         jd.System,
		Builder:          expandStorePath(jd.Builder),
		Arguments:        jd.Args,
		Env:              jd.Env,
	}

	if jd.Name != "" {
		drv.SetName(jd.Name)
	}

	if err := drv.computeMissingOutputPaths(); err != nil {
		return nil, err
	}

	return drv, nil
}

// convertOutputs converts JSON outputs to internal Output structs using the provided converter.
func convertOutputs(
	jOutputs map[string]jsonOutput,
	convert func(jsonOutput) (*Output, error),
) (map[string]*Output, error) {
	outputs := make(map[string]*Output, len(jOutputs))

	for name, jo := range jOutputs {
		o, err := convert(jo)
		if err != nil {
			return nil, fmt.Errorf("converting output %s: %w", name, err)
		}

		outputs[name] = o
	}

	return outputs, nil
}

// convertOutputV3 normalizes a v3 JSON output to the internal Output struct.
func convertOutputV3(jo jsonOutput) (*Output, error) {
	o := &Output{
		Path: expandStorePath(jo.Path),
	}

	if jo.Method == "" && jo.HashAlgo == "" && jo.Hash == "" {
		if jo.Path == "" {
			return &Output{}, nil
		}

		return o, nil
	}

	o.HashAlgorithm = buildHashAlgo(jo.Method, jo.HashAlgo)
	o.Hash = jo.Hash // already hex in v3

	return o, nil
}

// convertOutputV4 normalizes a v4 JSON output to the internal Output struct.
func convertOutputV4(jo jsonOutput) (*Output, error) {
	o := &Output{
		Path: expandStorePath(jo.Path),
	}

	if jo.Method == "" && jo.HashAlgo == "" && jo.Hash == "" {
		if jo.Path == "" {
			return &Output{}, nil
		}

		return o, nil
	}

	hashAlgo := buildHashAlgo(jo.Method, jo.HashAlgo)

	if jo.Hash != "" {
		// CA Fixed output. In v4 the hash is SRI format (e.g. "sha256-base64...").
		h, err := nixhash.ParseAny(jo.Hash, nil)
		if err != nil {
			return nil, fmt.Errorf("parsing v4 hash %q: %w", jo.Hash, err)
		}

		o.Hash = hex.EncodeToString(h.Digest())

		if hashAlgo == "" {
			hashAlgo = buildHashAlgo(jo.Method, h.Algo().String())
		}
	}

	o.HashAlgorithm = hashAlgo

	return o, nil
}

// buildHashAlgo constructs the internal hashAlgo string.
// If method is "nar", prepends "r:" to the algo (e.g. "r:sha256").
func buildHashAlgo(method, algo string) string {
	if algo == "" {
		return ""
	}

	if method == "nar" {
		return "r:" + algo
	}

	return algo
}

// convertInputDrvs flattens v3/v4 inputDrvs to map[string][]string.
func convertInputDrvs(jInputDrvs map[string]jsonInputDrv) map[string][]string {
	if len(jInputDrvs) == 0 {
		return map[string][]string{}
	}

	result := make(map[string][]string, len(jInputDrvs))

	for path, entry := range jInputDrvs {
		outputs := make([]string, len(entry.Outputs))
		copy(outputs, entry.Outputs)
		sort.Strings(outputs)
		result[expandStorePath(path)] = outputs
	}

	return result
}

// computeMissingOutputPaths computes output paths for CA fixed-output
// derivations where the path was omitted from JSON (Nix 2.34+).
// For CA fixed outputs, the path is deterministic from the hash algorithm,
// hash, and derivation name — no input derivation replacements needed.
func (d *Derivation) computeMissingOutputPaths() error {
	needsCompute := false

	for _, o := range d.Outputs {
		if o.Path == "" && o.HashAlgorithm != "" {
			needsCompute = true

			break
		}
	}

	if !needsCompute {
		return nil
	}

	paths, err := d.CalculateOutputPaths(nil)
	if err != nil {
		return fmt.Errorf("computing output paths: %w", err)
	}

	for name, o := range d.Outputs {
		if o.Path == "" && o.HashAlgorithm != "" {
			o.Path = paths[name]
		}
	}

	return nil
}

// expandStorePaths expands a slice of potentially short store paths.
func expandStorePaths(paths []string) []string {
	if len(paths) == 0 {
		return []string{}
	}

	result := make([]string, len(paths))
	for i, p := range paths {
		result[i] = expandStorePath(p)
	}

	sort.Strings(result)

	return result
}

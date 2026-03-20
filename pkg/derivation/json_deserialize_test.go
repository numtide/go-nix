package derivation_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nix-community/go-nix/pkg/derivation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseATerm is a helper that parses a .drv file and returns the derivation.
func parseATerm(t *testing.T, basename string) *derivation.Derivation {
	t.Helper()

	f, err := os.Open(filepath.FromSlash("../../test/testdata/" + basename))
	require.NoError(t, err)

	defer f.Close()

	data, err := io.ReadAll(f)
	require.NoError(t, err)

	drv, err := derivation.ReadDerivation(bytes.NewReader(data))
	require.NoError(t, err)

	return drv
}

// parseJSONSingle is a helper that parses a single-derivation JSON file.
func parseJSONSingle(t *testing.T, filename string) *derivation.Derivation {
	t.Helper()

	f, err := os.Open(filepath.FromSlash("../../test/testdata/" + filename))
	require.NoError(t, err)

	defer f.Close()

	drv, err := derivation.ReadDerivationJSON(f)
	require.NoError(t, err)

	return drv
}

// parseJSONMulti is a helper that parses a JSON file returning the derivation map.
func parseJSONMulti(t *testing.T, filename string) map[string]*derivation.Derivation {
	t.Helper()

	f, err := os.Open(filepath.FromSlash("../../test/testdata/" + filename))
	require.NoError(t, err)

	defer f.Close()

	drvs, err := derivation.ReadDerivationsJSON(f)
	require.NoError(t, err)

	return drvs
}

// compareDrv compares a JSON-parsed derivation against an ATerm-parsed one.
func compareDrv(t *testing.T, expected *derivation.Derivation, actual *derivation.Derivation) {
	t.Helper()

	assert.Equal(t, expected.Outputs, actual.Outputs, "outputs mismatch")
	assert.Equal(t, expected.InputSources, actual.InputSources, "inputSrcs mismatch")
	assert.Equal(t, expected.InputDerivations, actual.InputDerivations, "inputDrvs mismatch")
	assert.Equal(t, expected.Platform, actual.Platform, "platform mismatch")
	assert.Equal(t, expected.Builder, actual.Builder, "builder mismatch")
	assert.Equal(t, expected.Arguments, actual.Arguments, "args mismatch")
	assert.Equal(t, expected.Env, actual.Env, "env mismatch")
}

func TestReadDerivationJSON(t *testing.T) {
	drvBasenames := []string{
		"0hm2f1psjpcwg8fijsmr4wwxrx59s092-bar.drv",
		"4wvvbi4jwn0prsdxb7vs673qa5h9gr7x-foo.drv",
	}

	t.Run("v1", func(t *testing.T) {
		for _, basename := range drvBasenames {
			t.Run(basename, func(t *testing.T) {
				expected := parseATerm(t, basename)
				actual := parseJSONSingle(t, basename+".v1.json")
				compareDrv(t, expected, actual)
			})
		}
	})

	t.Run("v3", func(t *testing.T) {
		for _, basename := range drvBasenames {
			t.Run(basename, func(t *testing.T) {
				expected := parseATerm(t, basename)
				actual := parseJSONSingle(t, basename+".v3.json")
				compareDrv(t, expected, actual)
			})
		}
	})

	t.Run("v4", func(t *testing.T) {
		for _, basename := range drvBasenames {
			t.Run(basename, func(t *testing.T) {
				expected := parseATerm(t, basename)
				actual := parseJSONSingle(t, basename+".v4.json")
				compareDrv(t, expected, actual)
			})
		}
	})

	t.Run("v4_generated", func(t *testing.T) {
		for _, basename := range drvBasenames {
			t.Run(basename, func(t *testing.T) {
				expected := parseATerm(t, basename)
				actual := parseJSONSingle(t, basename+".json")
				compareDrv(t, expected, actual)
			})
		}
	})
}

func TestReadDerivationsJSON(t *testing.T) {
	t.Run("single derivation returns map with one entry", func(t *testing.T) {
		drvs := parseJSONMulti(t, "0hm2f1psjpcwg8fijsmr4wwxrx59s092-bar.drv.v4.json")
		assert.Len(t, drvs, 1)

		drv, ok := drvs["/nix/store/0hm2f1psjpcwg8fijsmr4wwxrx59s092-bar.drv"]
		require.True(t, ok)

		expected := parseATerm(t, "0hm2f1psjpcwg8fijsmr4wwxrx59s092-bar.drv")
		compareDrv(t, expected, drv)
	})
}

func TestReadDerivationJSON_SingleErrors(t *testing.T) {
	t.Run("empty object", func(t *testing.T) {
		_, err := derivation.ReadDerivationJSON(strings.NewReader(`{}`))
		assert.Error(t, err)
	})

	t.Run("invalid json", func(t *testing.T) {
		_, err := derivation.ReadDerivationJSON(strings.NewReader(`not json`))
		assert.Error(t, err)
	})
}

func TestReadDerivationJSON_VersionDetection(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{
			name: "v1",
			json: `{"/nix/store/0hm2f1psjpcwg8fijsmr4wwxrx59s092-bar.drv":{"outputs":{"out":{"path":"/nix/store/4q0pg5zpfmznxscq3avycvf9xdvx50n3-bar","hashAlgo":"r:sha256","hash":"08813cbee9903c62be4c5027726a418a300da4500b2d369d3af9286f4815ceba"}},"inputSrcs":[],"inputDrvs":{},"system":":","builder":":","args":[],"env":{"builder":":","name":"bar","out":"/nix/store/4q0pg5zpfmznxscq3avycvf9xdvx50n3-bar","outputHash":"08813cbee9903c62be4c5027726a418a300da4500b2d369d3af9286f4815ceba","outputHashAlgo":"sha256","outputHashMode":"recursive","system":":"}}}`, //nolint:lll
		},
		{
			name: "v3",
			json: `{"/nix/store/0hm2f1psjpcwg8fijsmr4wwxrx59s092-bar.drv":{"name":"bar","version":3,"outputs":{"out":{"path":"4q0pg5zpfmznxscq3avycvf9xdvx50n3-bar","method":"nar","hashAlgo":"sha256","hash":"08813cbee9903c62be4c5027726a418a300da4500b2d369d3af9286f4815ceba"}},"inputSrcs":[],"inputDrvs":{},"system":":","builder":":","args":[],"env":{"builder":":","name":"bar","out":"/nix/store/4q0pg5zpfmznxscq3avycvf9xdvx50n3-bar","outputHash":"08813cbee9903c62be4c5027726a418a300da4500b2d369d3af9286f4815ceba","outputHashAlgo":"sha256","outputHashMode":"recursive","system":":"}}}`, //nolint:lll
		},
		{
			name: "v4_wrapper",
			json: `{"version":4,"derivations":{"0hm2f1psjpcwg8fijsmr4wwxrx59s092-bar.drv":{"name":"bar","outputs":{"out":{"path":"4q0pg5zpfmznxscq3avycvf9xdvx50n3-bar","method":"nar","hash":"sha256-CIE8vumQPGK+TFAncmpBijANpFALLTadOvkob0gVzro="}},"inputs":{"srcs":[],"drvs":{}},"system":":","builder":":","args":[],"env":{"builder":":","name":"bar","out":"/nix/store/4q0pg5zpfmznxscq3avycvf9xdvx50n3-bar","outputHash":"08813cbee9903c62be4c5027726a418a300da4500b2d369d3af9286f4815ceba","outputHashAlgo":"sha256","outputHashMode":"recursive","system":":" }}}}`, //nolint:lll
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			drv, err := derivation.ReadDerivationJSON(strings.NewReader(tt.json))
			if tt.wantErr {
				assert.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.NotNil(t, drv)
		})
	}
}

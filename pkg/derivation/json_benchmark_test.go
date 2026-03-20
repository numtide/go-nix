package derivation_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/nix-community/go-nix/pkg/derivation"
)

// loadFixture reads a test fixture file into a byte slice.
func loadFixture(b *testing.B, filename string) []byte {
	b.Helper()

	f, err := os.Open(filepath.FromSlash("../../test/testdata/" + filename))
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		b.Fatal(err)
	}

	return data
}

func BenchmarkReadDerivationJSON(b *testing.B) {
	fixtures := []struct {
		name string
		file string
	}{
		// Small fixtures
		{"v1/small-ca-fixed", "0hm2f1psjpcwg8fijsmr4wwxrx59s092-bar.drv.v1.json"},
		{"v1/small-input-addressed", "4wvvbi4jwn0prsdxb7vs673qa5h9gr7x-foo.drv.v1.json"},
		{"v3/small-ca-fixed", "0hm2f1psjpcwg8fijsmr4wwxrx59s092-bar.drv.v3.json"},
		{"v3/small-input-addressed", "4wvvbi4jwn0prsdxb7vs673qa5h9gr7x-foo.drv.v3.json"},
		{"v4/small-ca-fixed", "0hm2f1psjpcwg8fijsmr4wwxrx59s092-bar.drv.v4.json"},
		{"v4/small-input-addressed", "4wvvbi4jwn0prsdxb7vs673qa5h9gr7x-foo.drv.v4.json"},
		// Real large fixture: fc-00-nixos-cache.conf (85+ input drvs, large env)
		{"v4/large-real", "hbjggxgb6r8nvdqlgqx6lhhy203li81q-fc-00-nixos-cache.conf.drv.json"},
	}

	for _, f := range fixtures {
		data := loadFixture(b, f.file)

		b.Run(f.name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := derivation.ReadDerivationJSON(bytes.NewReader(data))
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkReadDerivationATerm(b *testing.B) {
	fixtures := []struct {
		name string
		file string
	}{
		{"small-ca-fixed", "0hm2f1psjpcwg8fijsmr4wwxrx59s092-bar.drv"},
		{"small-input-addressed", "4wvvbi4jwn0prsdxb7vs673qa5h9gr7x-foo.drv"},
		// Real large fixture for ATerm comparison
		{"large-real", "hbjggxgb6r8nvdqlgqx6lhhy203li81q-fc-00-nixos-cache.conf.drv"},
	}

	for _, f := range fixtures {
		data := loadFixture(b, f.file)

		b.Run(f.name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := derivation.ReadDerivation(bytes.NewReader(data))
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

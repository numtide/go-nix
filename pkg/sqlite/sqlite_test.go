package sqlite_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/nix-community/go-nix/pkg/sqlite"
	"github.com/nix-community/go-nix/pkg/sqlite/binary_cache_v6"
	"github.com/nix-community/go-nix/pkg/sqlite/fetcher_cache_v2"
	"github.com/nix-community/go-nix/pkg/sqlite/nix_v10"
	"github.com/stretchr/testify/require"
)

func TestBinaryCacheV6(t *testing.T) {
	as := require.New(t)
	ctx := context.Background()

	db, queries, err := sqlite.BinaryCacheV6("file::memory:")
	as.NoError(err)

	defer func() { _ = db.Close() }()

	// create the schema
	execSchema(t, ctx, db, binary_cache_v6.Schema)

	// seed a cache entry
	cacheID, err := queries.InsertCache(ctx, binary_cache_v6.InsertCacheParams{
		Url:           "https://cache.nixos.org",
		Timestamp:     1000,
		Storedir:      "/nix/store",
		Wantmassquery: 1,
		Priority:      40,
	})
	as.NoError(err)
	as.Equal(int64(1), cacheID)

	// seed a last-purge record
	as.NoError(queries.UpdateLastPurge(ctx, sql.NullInt64{Int64: 500, Valid: true}))

	// query it back
	purge, err := queries.QueryLastPurge(ctx)
	as.NoError(err)
	as.True(purge.Valid)
	as.Equal(int64(500), purge.Int64)

	// query the cache entry
	caches, err := queries.QueryCache(ctx, binary_cache_v6.QueryCacheParams{
		Url:       "https://cache.nixos.org",
		Timestamp: 0,
	})
	as.NoError(err)
	as.Len(caches, 1)
	as.Equal("/nix/store", caches[0].Storedir)
	as.Equal(int64(40), caches[0].Priority)
}

func TestFetcherCacheV2(t *testing.T) {
	as := require.New(t)
	ctx := context.Background()

	db, queries, err := sqlite.FetcherCacheV2("file::memory:")
	as.NoError(err)

	defer func() { _ = db.Close() }()

	// create the schema
	execSchema(t, ctx, db, fetcher_cache_v2.Schema)

	// seed a cache entry
	as.NoError(queries.UpsertCache(ctx, fetcher_cache_v2.UpsertCacheParams{
		Domain:    "flake",
		Key:       "github:NixOS/nixpkgs/main",
		Value:     `{"rev":"abc123"}`,
		Timestamp: 1000,
	}))

	// query it back
	rows, err := queries.QueryCache(ctx, fetcher_cache_v2.QueryCacheParams{
		Domain: "flake",
		Key:    "github:NixOS/nixpkgs/main",
	})
	as.NoError(err)
	as.Len(rows, 1)
	as.Equal(`{"rev":"abc123"}`, rows[0].Value)
	as.Equal(int64(1000), rows[0].Timestamp)
}

func TestNixV10(t *testing.T) {
	as := require.New(t)
	ctx := context.Background()

	db, queries, err := sqlite.NixV10("file::memory:")
	as.NoError(err)

	defer func() { _ = db.Close() }()

	// create the schema
	execSchema(t, ctx, db, nix_v10.Schema)

	// register a valid path
	storePath := "/nix/store/kz5clxh7s1n0fnx6d37c1wc2cs9qm53q-hello-2.12.1"
	as.NoError(queries.RegisterValidPath(ctx, nix_v10.RegisterValidPathParams{
		Path:             storePath,
		Hash:             "sha256:f8340af15f7996faded748bea9e2d0b82a6f7c96417b03f7fa8e1a6a873748e8",
		Registrationtime: 1000,
		Deriver:          sql.NullString{String: "/nix/store/qnavcbp5ydyd12asgz7rpr7is7hlswaz-hello-2.12.1.drv", Valid: true},
		Narsize:          sql.NullInt64{Int64: 226560, Valid: true},
		Ultimate:         sql.NullInt64{Int64: 1, Valid: true},
		Sigs:             sql.NullString{String: "cache.nixos.org-1:abc123", Valid: true},
	}))

	// query path info
	info, err := queries.QueryPathInfo(ctx, storePath)
	as.NoError(err)
	as.Equal("sha256:f8340af15f7996faded748bea9e2d0b82a6f7c96417b03f7fa8e1a6a873748e8", info.Hash)
	as.Equal("/nix/store/qnavcbp5ydyd12asgz7rpr7is7hlswaz-hello-2.12.1.drv", info.Deriver.String)
	as.Equal(int64(226560), info.Narsize.Int64)

	// query path from hash part
	path, err := queries.QueryPathFromHashPart(ctx, "/nix/store/kz5clxh7s1n0fnx6d37c1wc2cs9qm53q")
	as.NoError(err)
	as.Equal(storePath, path)
}

// execSchema runs a SQL schema string against the database.
func execSchema(t *testing.T, ctx context.Context, db *sql.DB, schema string) {
	t.Helper()

	_, err := db.ExecContext(ctx, schema)
	require.NoError(t, err, "failed to create schema")
}

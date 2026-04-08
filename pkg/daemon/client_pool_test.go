package daemon_test

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nix-community/go-nix/pkg/daemon"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// newPoolMockDaemon starts a Unix socket listener that accepts an unbounded number of concurrent connections,
// performing the nix daemon handshake for each one.
// It returns the socket path.
func newPoolMockDaemon(t *testing.T) string {
	t.Helper()

	socketDir, err := os.MkdirTemp("", "nix")
	require.NoError(t, err)

	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })

	sock := filepath.Join(socketDir, "d.sock")

	listenCfg := net.ListenConfig{}
	ln, err := listenCfg.Listen(t.Context(), "unix", sock)
	require.NoError(t, err)

	eg := errgroup.Group{}

	eg.Go(func() error {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				// ln.Close() is called by t.Cleanup; treat that as a clean exit.
				if errors.Is(acceptErr, net.ErrClosed) {
					return nil
				}

				return acceptErr
			}

			eg.Go(func() error {
				defer func() { _ = conn.Close() }()

				handshake(conn, 0)

				return nil
			})
		}
	})

	// ln.Close must be registered after eg.Wait so it runs first (LIFO), which
	// unblocks the accept goroutine and allows eg.Wait to return cleanly.
	t.Cleanup(func() {
		if waitErr := eg.Wait(); waitErr != nil {
			t.Errorf("pool mock daemon error: %s", waitErr)
		}
	})

	t.Cleanup(func() { _ = ln.Close() })

	return sock
}

// newTestPool creates a ClientPool backed by a mock daemon and registers pool.Close in t.Cleanup.
func newTestPool(t *testing.T, maxConns int) *daemon.ClientPool {
	t.Helper()

	sock := newPoolMockDaemon(t)

	pool, err := daemon.NewClientPool(t.Context(), sock, maxConns)
	require.NoError(t, err)

	t.Cleanup(func() { _ = pool.Close() })

	return pool
}

func TestNewClientPool(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		sock := newPoolMockDaemon(t)

		pool, err := daemon.NewClientPool(t.Context(), sock, 2)
		require.NoError(t, err)
		require.NoError(t, pool.Close())
	})

	t.Run("InvalidPath", func(t *testing.T) {
		_, err := daemon.NewClientPool(t.Context(), "/nonexistent/daemon.sock", 1)
		require.Error(t, err)
	})

	t.Run("MinConnectionsDefaultsToOne", func(t *testing.T) {
		// maxConns=0 should be clamped to 1.
		pool := newTestPool(t, 0)

		c, err := pool.Acquire()
		require.NoError(t, err)

		pool.Release(c, nil)
	})
}

func TestClientPool_AcquireRelease(t *testing.T) {
	rq := require.New(t)

	pool := newTestPool(t, 2)

	c, err := pool.Acquire()
	rq.NoError(err)
	rq.NotNil(c)

	pool.Release(c, nil)

	c2, err := pool.Acquire()
	rq.NoError(err)
	rq.NotNil(c2)

	pool.Release(c2, nil)
}

func TestClientPool_LazyDial(t *testing.T) {
	rq := require.New(t)

	pool := newTestPool(t, 2)

	c1, err := pool.Acquire()
	rq.NoError(err)

	// idle is now empty; a second Acquire must dial a new connection.
	c2, err := pool.Acquire()
	rq.NoError(err)
	rq.NotNil(c2)

	pool.Release(c1, nil)
	pool.Release(c2, nil)
}

func TestClientPool_MaxConnectionsBlocks(t *testing.T) {
	rq := require.New(t)

	pool := newTestPool(t, 1)

	c1, err := pool.Acquire()
	rq.NoError(err)

	type result struct {
		c   *daemon.Client
		err error
	}

	ch := make(chan result, 1)

	go func() {
		c, acquireErr := pool.Acquire()
		ch <- result{c, acquireErr}
	}()

	select {
	case <-ch:
		t.Fatal("Acquire should have blocked while maxConns are checked out")
	case <-time.After(50 * time.Millisecond):
	}

	pool.Release(c1, nil)

	select {
	case r := <-ch:
		rq.NoError(r.err)
		rq.NotNil(r.c)
		pool.Release(r.c, nil)
	case <-time.After(2 * time.Second):
		t.Fatal("Acquire did not unblock after Release")
	}
}

func TestClientPool_AcquireAfterClose(t *testing.T) {
	rq := require.New(t)

	pool := newTestPool(t, 2)

	rq.NoError(pool.Close())

	_, err := pool.Acquire()
	rq.ErrorIs(err, daemon.ErrPoolClosed)
}

func TestClientPool_CloseUnblocksAcquire(t *testing.T) {
	rq := require.New(t)

	pool := newTestPool(t, 1)

	c, err := pool.Acquire()
	rq.NoError(err)

	ch := make(chan error, 1)

	go func() {
		_, acquireErr := pool.Acquire()
		ch <- acquireErr
	}()

	// Give the goroutine time to reach the blocking select.
	time.Sleep(50 * time.Millisecond)

	rq.NoError(pool.Close())

	select {
	case acquireErr := <-ch:
		rq.ErrorIs(acquireErr, daemon.ErrPoolClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock the waiting Acquire")
	}

	// Release after Close discards the connection instead of returning it to idle.
	pool.Release(c, nil)
}

func TestClientPool_CloseIsIdempotent(t *testing.T) {
	rq := require.New(t)

	pool := newTestPool(t, 1)

	rq.NoError(pool.Close())
	rq.NoError(pool.Close())
}

func TestClientPool_ReleaseWithError(t *testing.T) {
	rq := require.New(t)

	pool := newTestPool(t, 1)

	c, err := pool.Acquire()
	rq.NoError(err)

	// Release with a non-nil rpcErr closes the connection and drains the semaphore slot.
	pool.Release(c, errors.New("rpc error"))

	c2, err := pool.Acquire()
	rq.NoError(err)
	rq.NotNil(c2)

	pool.Release(c2, nil)
}

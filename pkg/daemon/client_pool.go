package daemon

import (
	"context"
	"fmt"
	"sync"
)

var ErrPoolClosed = fmt.Errorf("ClientPool is closed")

// ClientPool maintains a bounded pool of Client connections.
//
// Client is not safe for concurrent use, so each caller must Acquire a connection, use it exclusively, and Release it
// when done.
// The pool dials new connections lazily up to maxConns; after that Acquire blocks until one is returned.
type ClientPool struct {
	ctx        context.Context
	socketPath string

	sem  chan struct{} // counting semaphore for total live connections
	idle chan *Client  // returned connections; cap = maxConns

	closeOnce sync.Once
	closed    chan struct{}
}

// NewClientPool dials the nix-daemon socket once (verifying connectivity), seeds the pool with that connection, and
// returns a pool that will dial up to maxConns total connections on demand.
func NewClientPool(ctx context.Context, socketPath string, maxConns int) (*ClientPool, error) {
	// minimum of 1 connection
	if maxConns < 1 {
		maxConns = 1
	}

	// dial the socket once, ensuring connectivity
	c, err := Connect(ctx, socketPath)
	if err != nil {
		return nil, err
	}

	// construct the pool
	p := &ClientPool{
		ctx:        ctx,
		socketPath: socketPath,

		sem:    make(chan struct{}, maxConns),
		idle:   make(chan *Client, maxConns),
		closed: make(chan struct{}),
	}

	// add the initial connection to the pool
	p.sem <- struct{}{}

	p.idle <- c

	return p, nil
}

// Acquire returns a connection from the pool, dialling a new one if the pool is empty and the live-connection budget
// allows.
// Blocks if maxConns connections are already checked out.
func (p *ClientPool) Acquire() (*Client, error) {
	// Check for an idle connection first - Go's select is uniformly random when multiple cases are ready, so without
	// this fast path we'd dial up to maxConns even with idle connections available.
	select {
	case c := <-p.idle:
		return c, nil
	default:
	}

	// One of three things can happen here:
	// 1. The pool is closed, return an error.
	// 2. An idle connection is available, so we can return it.
	// 3. The live-connection budget allows us to dial a new connection.
	select {
	case <-p.closed:
		return nil, ErrPoolClosed

	case c := <-p.idle:
		return c, nil

	case p.sem <- struct{}{}:
		// recheck closed: Close drains the semaphore, so when both p.closed
		// and p.sem are ready the outer select may have taken the sem slot.
		select {
		case <-p.closed:
			<-p.sem

			return nil, ErrPoolClosed
		default:
		}

		c, err := Connect(p.ctx, p.socketPath)
		if err != nil {
			// failed to connect, release the semaphore
			<-p.sem

			return nil, err
		}

		return c, nil
	}
}

// Release returns a connection to the pool.
// If rpcErr is non-nil the connection is closed instead — a protocol-level error can leave the stream desynced.
// Application-level errors (build status, parse failures) should pass rpcErr=nil; the RPC completed and the stream is
// healthy.
//
// The invariant `len(idle) + checked_out == len(sem) <= maxConns` means idle always has capacity for a checked-out
// connection, so the channel send never blocks.
func (p *ClientPool) Release(c *Client, rpcErr error) {
	// attempt to return the client to idle only if the pool has not been closed
	if rpcErr == nil {
		select {
		case <-p.closed:
		default:
			p.idle <- c

			return
		}
	}

	// Otherwise an unrecoverable error has happened.
	// Close the client and drain the semaphore to allow a new client to be created on the next Acquire()
	_ = c.Close()

	<-p.sem
}

// Close drains the idle pool and closes each connection.
// In-flight operations will be completed; their connections are closed on Release.
func (p *ClientPool) Close() error {
	// ensure this logic only happens once
	p.closeOnce.Do(func() {
		// indicate closure of the pool by closing the closed channel
		close(p.closed)

		// drain the idle pool and close each connection
		for {
			select {
			case c := <-p.idle:
				_ = c.Close()

				<-p.sem
			default:
				return
			}
		}
	})

	return nil
}

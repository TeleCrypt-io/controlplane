package db

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrJanitorAlreadyRunning means another one-shot Janitor currently owns the database-wide
// invocation lease. The lease is session-scoped, so the dedicated acquired connection must stay
// checked out until the whole invocation finishes.
var ErrJanitorAlreadyRunning = errors.New("janitor invocation already running")

const janitorInvocationLockID int64 = 0x54454c5357454550 // "TELSWEEP"

const advisoryLockCleanupTimeout = 2 * time.Second

// JanitorInvocationLock is a database-wide single-flight lease for one Janitor process.
type JanitorInvocationLock struct {
	conn *pgxpool.Conn
	once sync.Once
}

// AcquireJanitorInvocationLock takes a non-blocking, session-scoped advisory lock. A caller that
// loses the race must exit before migration or any external MAS/SMTP action.
func AcquireJanitorInvocationLock(ctx context.Context, pool *pgxpool.Pool) (*JanitorInvocationLock, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, errors.New("acquire janitor invocation connection")
	}
	var acquired bool
	if err := conn.QueryRow(ctx, `SELECT pg_catalog.pg_try_advisory_lock($1)`, janitorInvocationLockID).Scan(&acquired); err != nil {
		discardPoolConn(conn)
		return nil, errors.New("acquire janitor invocation lock")
	}
	if !acquired {
		conn.Release()
		return nil, ErrJanitorAlreadyRunning
	}
	return &JanitorInvocationLock{conn: conn}, nil
}

// Release gives back the advisory lease and returns the dedicated connection to the pool. It is
// safe to defer Release and to call it again from cleanup code. The invocation context is the
// one-shot's hard budget; if it has expired, the connection is discarded rather than attempting
// an unbounded unlock on an already-failed invocation.
func (l *JanitorInvocationLock) Release(ctx context.Context) {
	if l == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	l.once.Do(func() {
		releaseJanitorInvocationLock(l.conn, janitorInvocationLockID, ctx)
		l.conn = nil
	})
}

func releaseJanitorInvocationLock(conn *pgxpool.Conn, lockID int64, ctx context.Context) {
	releaseAdvisoryLockWithContext(conn, lockID, ctx)
}

// releaseAdvisoryLock is the migration cleanup adapter. All advisory-lock cleanup uses the same
// bounded policy, whether the caller has the invocation context or is running from a defer that
// predates it.
func releaseAdvisoryLock(conn *pgxpool.Conn, lockID int64) {
	releaseAdvisoryLockWithContext(conn, lockID, context.Background())
}

func releaseAdvisoryLockWithContext(conn *pgxpool.Conn, lockID int64, parent context.Context) {
	ctx, cancel := boundedCleanupContext(parent)
	defer cancel()
	var unlocked bool
	if err := conn.QueryRow(ctx, `SELECT pg_catalog.pg_advisory_unlock($1)`, lockID).Scan(&unlocked); err != nil || !unlocked {
		discardPoolConn(conn)
		return
	}
	conn.Release()
}

func boundedCleanupContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, advisoryLockCleanupTimeout)
}

// discardPoolConn takes the connection out of the pool and closes it, so no uncertain session
// state can be reused. Closing is bounded; a connection that does not close in time is still no
// longer owned by the pool.
func discardPoolConn(conn *pgxpool.Conn) {
	pgConn := conn.Hijack()
	ctx, cancel := boundedCleanupContext(context.Background())
	defer cancel()
	_ = pgConn.Close(ctx)
}

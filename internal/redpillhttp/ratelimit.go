package redpillhttp

import (
	"sync"
	"time"
)

// RateLimiter is redpill's semantic, in-memory backstop (velocity per source, never identity,
// never a CAPTCHA): a per-source-IP bucket plus a global creations/window ceiling. Now that
// morpheus (and its Postgres-backed ratelimit table) is gone, this is a fixed-window counter kept
// entirely in process memory — redpill has no database connection at all. That means limits reset
// on restart and don't share state across replicas; acceptable for a single-instance deployment.
type RateLimiter struct {
	mu             sync.Mutex
	counts         map[string]windowCount
	PerSourceLimit int
	GlobalLimit    int
	Window         time.Duration
}

type windowCount struct {
	windowStart time.Time
	count       int
}

func NewRateLimiter(perSourceLimit, globalLimit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		counts:         map[string]windowCount{},
		PerSourceLimit: perSourceLimit,
		GlobalLimit:    globalLimit,
		Window:         window,
	}
}

// increment bumps key's fixed-window counter (time.Now() truncated to r.Window) and returns the
// post-increment count, resetting to 1 whenever the window has rolled over. Mirrors the semantics
// of the old DB-backed IncrementRateLimit (internal/db.Store), just in memory.
func (r *RateLimiter) increment(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	windowStart := time.Now().Truncate(r.Window)
	c := r.counts[key]
	if c.windowStart != windowStart {
		c = windowCount{windowStart: windowStart, count: 0}
	}
	c.count++
	r.counts[key] = c
	return c.count
}

// Allow increments both the per-source and global counters for the current window and reports
// whether the call should proceed. Both counters are always incremented, even if one is already
// over its limit, so a blocked burst still counts against whichever ceiling it tripped. An empty
// sourceIP (no distinguishing X-Forwarded-For signal) only checks the global ceiling.
func (r *RateLimiter) Allow(sourceIP string) bool {
	allowed := r.increment("global") <= r.GlobalLimit

	if sourceIP != "" {
		if r.increment("ip:"+sourceIP) > r.PerSourceLimit {
			allowed = false
		}
	}
	return allowed
}

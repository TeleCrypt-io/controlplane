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
	counts         map[string]int
	PerSourceLimit int
	GlobalLimit    int
	Window         time.Duration
	windowStart    time.Time
}

func NewRateLimiter(perSourceLimit, globalLimit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		counts:         map[string]int{},
		PerSourceLimit: perSourceLimit,
		GlobalLimit:    globalLimit,
		Window:         window,
	}
}

// Allow increments the global counter and, while the global ceiling still permits work, the
// per-source counter for the current fixed window. The complete map is discarded at rollover.
// Refusing before adding a new source after the global ceiling is reached bounds map cardinality
// to GlobalLimit plus the global key, even under a flood of distinct client addresses.
func (r *RateLimiter) Allow(sourceIP string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	windowStart := time.Now().Truncate(r.Window)
	if r.windowStart != windowStart {
		r.counts = make(map[string]int)
		r.windowStart = windowStart
	}
	r.counts["global"]++
	if r.counts["global"] > r.GlobalLimit {
		return false
	}

	if sourceIP != "" {
		key := "ip:" + sourceIP
		r.counts[key]++
		return r.counts[key] <= r.PerSourceLimit
	}
	return true
}

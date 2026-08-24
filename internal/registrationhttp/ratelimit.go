package registrationhttp

import (
	"sync"
	"time"
)

// RateLimiter is Registration's in-memory global backstop. It is a fixed-window counter kept
// entirely in process memory — Registration has no database connection. Limits reset on restart
// and do not share state across replicas; client-facing fairness belongs at the network boundary.
type RateLimiter struct {
	mu          sync.Mutex
	count       int
	GlobalLimit int
	Window      time.Duration
	windowStart time.Time
}

func NewRateLimiter(globalLimit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		GlobalLimit: globalLimit,
		Window:      window,
	}
}

// Allow increments the counter if the current fixed-window global ceiling permits work.
func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	windowStart := time.Now().Truncate(r.Window)
	if r.windowStart != windowStart {
		r.count = 0
		r.windowStart = windowStart
	}
	r.count++
	if r.count > r.GlobalLimit {
		return false
	}
	return true
}

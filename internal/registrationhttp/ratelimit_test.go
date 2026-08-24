package registrationhttp

import (
	"testing"
	"time"
)

func TestRateLimiter_AllowsUnderGlobalLimit(t *testing.T) {
	rl := NewRateLimiter(60, time.Minute)

	if !rl.Allow() {
		t.Error("a single call under the global limit should be allowed")
	}
}

func TestRateLimiter_BlocksOverGlobalLimit(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)

	if !rl.Allow() {
		t.Fatal("1st global call should be allowed")
	}
	if !rl.Allow() {
		t.Fatal("2nd global call should be allowed")
	}
	if rl.Allow() {
		t.Error("3rd global call should trip the global ceiling")
	}
}

func TestRateLimiter_WindowRollsOver(t *testing.T) {
	rl := NewRateLimiter(1, 10*time.Millisecond)

	if !rl.Allow() {
		t.Fatal("first call should be allowed")
	}
	if rl.Allow() {
		t.Fatal("second call within the same window should be blocked")
	}

	time.Sleep(30 * time.Millisecond)

	if !rl.Allow() {
		t.Error("a call in a new window should be allowed again")
	}
}

func TestRateLimiter_ResetsPriorWindowCount(t *testing.T) {
	rl := NewRateLimiter(1000, 10*time.Millisecond)
	if !rl.Allow() {
		t.Fatal("first call should be allowed")
	}

	time.Sleep(30 * time.Millisecond)
	if rl.count != 1 {
		t.Fatalf("prior-window count = %d, want 1", rl.count)
	}
	if !rl.Allow() {
		t.Fatal("a call in the next window should be allowed")
	}
}

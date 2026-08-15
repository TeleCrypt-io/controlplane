package redpillhttp

import (
	"testing"
	"time"
)

func TestRateLimiter_AllowsUnderBothLimits(t *testing.T) {
	rl := NewRateLimiter(5, 60, time.Minute)

	if !rl.Allow("1.2.3.4") {
		t.Error("a single call under both limits should be allowed")
	}
}

func TestRateLimiter_BlocksOverPerSourceLimit(t *testing.T) {
	rl := NewRateLimiter(2, 1000, time.Minute)

	for i := 0; i < 2; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("call %d should be allowed", i)
		}
	}
	if rl.Allow("1.2.3.4") {
		t.Error("3rd call from the same source over a limit of 2 should be blocked")
	}
}

func TestRateLimiter_DifferentSourcesDoNotShareBucket(t *testing.T) {
	rl := NewRateLimiter(1, 1000, time.Minute)

	if !rl.Allow("1.1.1.1") {
		t.Fatal("first source's first call should be allowed")
	}
	if !rl.Allow("2.2.2.2") {
		t.Fatal("a different source's first call should be allowed")
	}
}

func TestRateLimiter_BlocksOverGlobalLimitEvenAcrossSources(t *testing.T) {
	rl := NewRateLimiter(1000, 2, time.Minute)

	if !rl.Allow("1.1.1.1") {
		t.Fatal("1st global call should be allowed")
	}
	if !rl.Allow("2.2.2.2") {
		t.Fatal("2nd global call (different source) should be allowed")
	}
	if rl.Allow("3.3.3.3") {
		t.Error("3rd global call, even from a brand new source, should trip the global ceiling")
	}
}

func TestRateLimiter_EmptySourceIPOnlyChecksGlobal(t *testing.T) {
	rl := NewRateLimiter(0, 1000, time.Minute) // per-source=0 would block instantly if empty were treated as real

	if !rl.Allow("") {
		t.Error("an empty source IP should only be subject to the global limit")
	}
}

func TestRateLimiter_WindowRollsOver(t *testing.T) {
	rl := NewRateLimiter(1, 1000, 10*time.Millisecond)

	if !rl.Allow("1.2.3.4") {
		t.Fatal("first call should be allowed")
	}
	if rl.Allow("1.2.3.4") {
		t.Fatal("second call within the same window should be blocked")
	}

	time.Sleep(30 * time.Millisecond)

	if !rl.Allow("1.2.3.4") {
		t.Error("a call in a new window should be allowed again")
	}
}

func TestRateLimiter_DiscardsPriorWindowSourceKeys(t *testing.T) {
	rl := NewRateLimiter(1000, 1000, 10*time.Millisecond)
	if !rl.Allow("1.2.3.4") {
		t.Fatal("first source should be allowed")
	}

	time.Sleep(30 * time.Millisecond)
	if !rl.Allow("5.6.7.8") {
		t.Fatal("second source should be allowed in the next window")
	}
	if _, ok := rl.counts["ip:1.2.3.4"]; ok {
		t.Fatal("prior-window source key was retained")
	}
	if len(rl.counts) != 2 { // current global and current source keys only
		t.Fatalf("current-window count keys = %d, want 2", len(rl.counts))
	}
}

func TestRateLimiter_GlobalCeilingBoundsSourceMap(t *testing.T) {
	rl := NewRateLimiter(1000, 2, time.Minute)
	for _, source := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"} {
		rl.Allow(source)
	}
	if len(rl.counts) != 3 { // global plus only the two sources admitted under the ceiling
		t.Fatalf("count keys after global limit = %d, want 3", len(rl.counts))
	}
}

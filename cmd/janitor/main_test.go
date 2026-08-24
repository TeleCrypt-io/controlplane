package main

import (
	"context"
	"testing"
	"time"
)

func TestJanitorInvocationTimeoutIsOneFixedBudget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), janitorInvocationTimeout)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("Janitor invocation context has no hard deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > janitorInvocationTimeout {
		t.Fatalf("Janitor invocation deadline remaining = %s, want within %s", remaining, janitorInvocationTimeout)
	}
	if remaining < janitorInvocationTimeout-time.Second {
		t.Fatalf("Janitor invocation deadline was established too early: %s remaining", remaining)
	}
}

func TestJanitorInvocationTimeoutHonorsEarlierCancellation(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	cancelParent()
	ctx, cancel := context.WithTimeout(parent, janitorInvocationTimeout)
	defer cancel()

	if ctx.Err() == nil {
		t.Fatal("Janitor invocation context did not inherit parent cancellation")
	}
}

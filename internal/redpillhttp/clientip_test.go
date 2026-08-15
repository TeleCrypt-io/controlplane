package redpillhttp

import (
	"bytes"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientIP_ConfiguredDegenerateProxyValueTreatedAsNoSignal(t *testing.T) {
	req := httptest.NewRequest("POST", "/redpill", nil)
	req.Header.Set("X-Forwarded-For", "192.0.2.10")

	if got := clientIP(req, "192.0.2.10"); got != "" {
		t.Errorf("clientIP = %q, want \"\" for the configured non-distinguishing proxy value", got)
	}
}

func TestClientIP_AbsentHeaderTreatedAsNoSignal(t *testing.T) {
	req := httptest.NewRequest("POST", "/redpill", nil)

	if got := clientIP(req, ""); got != "" {
		t.Errorf("clientIP = %q, want \"\" when X-Forwarded-For is absent", got)
	}
}

func TestClientIP_RealDistinguishingValueUsed(t *testing.T) {
	req := httptest.NewRequest("POST", "/redpill", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.42")

	if got := clientIP(req, ""); got != "203.0.113.42" {
		t.Errorf("clientIP = %q, want 203.0.113.42", got)
	}
}

func TestClientIP_DoesNotLogForwardedHeader(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	secret := "must-not-appear-in-redpill-logs"
	req := httptest.NewRequest("POST", "/redpill", nil)
	req.Header.Set("X-Forwarded-For", secret)
	if got := clientIP(req, ""); got != secret {
		t.Fatalf("clientIP = %q, want forwarded value", got)
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("clientIP leaked forwarded header to logs: %s", logs.String())
	}
}

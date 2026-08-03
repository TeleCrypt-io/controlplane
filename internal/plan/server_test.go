package plan

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServerPlanIsFailClosedUntilCoordinatedCutover(t *testing.T) {
	srv := NewServer()
	req := httptest.NewRequest(http.MethodGet, "/plan", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusServiceUnavailable; got != want {
		t.Fatalf("GET /plan status = %d, want %d", got, want)
	}
	if got, want := rec.Header().Get("Cache-Control"), "no-store"; got != want {
		t.Fatalf("GET /plan Cache-Control = %q, want %q", got, want)
	}
}

func TestServerHealth(t *testing.T) {
	srv := NewServer()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if got, want := rec.Code, http.StatusOK; got != want {
		t.Fatalf("GET /health status = %d, want %d", got, want)
	}
}

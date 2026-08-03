package plan

import (
	"net/http"
)

// Server is the future public owner of /plan and its browser APIs. This first extraction keeps
// the service fail-closed: it exposes only a health endpoint and returns 503 for /plan until the
// MAS OIDC/session implementation and Cashier transport are moved in a later coordinated release.
// The legacy cashier remains the deployed owner meanwhile.
type Server struct {
	mux *http.ServeMux
}

// NewServer registers only the public Plan namespace. Cashier is deliberately not wired yet:
// accepting a nil or partially implemented client must never create a browser path that bypasses
// the current cashier authorization, Dodo idempotency, or Synapse-entitlement invariants.
func NewServer() *Server {
	s := &Server{mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /plan", s.handlePlan)
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handlePlan(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "Plan service is not enabled", http.StatusServiceUnavailable)
}

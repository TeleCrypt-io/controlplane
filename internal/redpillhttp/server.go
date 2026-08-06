// Package redpillhttp is redpill's public HTTP API: a stateless registration shim exposing only
// POST /redpill and GET /health. It holds no database connection, no admin credentials, no OIDC,
// no sessions and no MAS credential. It calls the signed private agent issuer through
// internal/agent and applies an in-memory rate limit.
package redpillhttp

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/TeleCrypt-io/controlplane/internal/agent"
)

// provisioner is the subset of *agent.Provisioner the server needs. Defined here so tests can
// supply a fake without driving a real MAS instance.
type provisioner interface {
	ProvisionAgent(ctx context.Context) (*agent.Provisioned, error)
}

type Server struct {
	provisioner    provisioner
	rateLimiter    *RateLimiter
	planURL        string
	ignoredProxyIP string
	mux            *http.ServeMux
}

func New(p provisioner, rl *RateLimiter, planURL, ignoredProxyIP string) *Server {
	s := &Server{
		provisioner:    p,
		rateLimiter:    rl,
		planURL:        planURL,
		ignoredProxyIP: strings.TrimSpace(ignoredProxyIP),
		mux:            http.NewServeMux(),
	}
	s.mux.HandleFunc("POST /redpill", s.handleRedpill)
	s.mux.HandleFunc("GET /health", s.handleHealth)
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// clientIP extracts the original client IP for per-source rate limiting, returning "" when no
// real per-client signal is available — the caller then falls back to the global-only ceiling
// (RateLimiter.Allow treats an empty sourceIP that way already).
func clientIP(r *http.Request, ignoredProxyIP string) string {
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	slog.Debug("clientIP: raw X-Forwarded-For", "xff", xff, "remote_addr", r.RemoteAddr)
	if xff == "" || (ignoredProxyIP != "" && xff == ignoredProxyIP) {
		return ""
	}
	return strings.TrimSpace(strings.Split(xff, ",")[0])
}

type redpillResponse struct {
	MXID        string `json:"mxid"`
	AccessToken string `json:"access_token"`
	DeviceID    string `json:"device_id"`
	Homeserver  string `json:"homeserver"`
	PlanURL     string `json:"plan_url"`
}

// handleRedpill asks the private issuer for a fresh passwordless agent account. The public process
// holds only a narrow signing key and is rate-limited in-memory per source IP and globally.
func (s *Server) handleRedpill(w http.ResponseWriter, r *http.Request) {
	allowed := s.rateLimiter.Allow(clientIP(r, s.ignoredProxyIP))
	if !allowed {
		http.Error(w, "rate limit exceeded, try again later", http.StatusTooManyRequests)
		return
	}

	result, err := s.provisioner.ProvisionAgent(r.Context())
	if err != nil {
		slog.Error("redpill: provisioning failed", "error", err)
		http.Error(w, "provisioning failed", http.StatusInternalServerError)
		return
	}

	resp := redpillResponse{
		MXID:        result.MXID,
		AccessToken: result.AccessToken,
		DeviceID:    result.DeviceID,
		Homeserver:  result.Homeserver,
		PlanURL:     s.planURL,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("redpill: failed to write response", "error", err)
	}
}

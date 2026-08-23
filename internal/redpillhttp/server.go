// Package redpillhttp is Redpill's public HTTP API: a stateless registration shim exposing only
// POST /redpill and GET /health. It holds no database connection, no admin credentials, no
// stored sessions, and no edge token; it drives MAS's public registration/device-OAuth flow and
// applies an in-memory rate limit.
package redpillhttp

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/agent"
)

// provisioner is the subset of *agent.Provisioner the server needs. Defined here so tests can
// supply a fake without driving a real MAS instance.
type provisioner interface {
	ProvisionAgent(ctx context.Context) (*agent.Provisioned, error)
}

type Server struct {
	provisioner provisioner
	rateLimiter *RateLimiter
	planURL     string
	mux         *http.ServeMux
}

func New(p provisioner, rl *RateLimiter, planURL string) *Server {
	s := &Server{
		provisioner: p,
		rateLimiter: rl,
		planURL:     planURL,
		mux:         http.NewServeMux(),
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
func clientIP(r *http.Request) string {
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff == "" {
		return ""
	}
	return strings.TrimSpace(strings.Split(xff, ",")[0])
}

type redpillResponse struct {
	MXID               string `json:"mxid"`
	Password           string `json:"password"`
	AccessToken        string `json:"access_token"`
	RefreshToken       string `json:"refresh_token"`
	ExpiresIn          int    `json:"expires_in"`
	DeviceID           string `json:"device_id"`
	Homeserver         string `json:"homeserver"`
	OAuthIssuer        string `json:"issuer"`
	OAuthClientID      string `json:"client_id"`
	OAuthTokenEndpoint string `json:"token_endpoint"`
	PlanURL            string `json:"plan_url"`
}

// handleRedpill provisions a fresh agent account through MAS's public registration and OAuth
// flow — no admin credential, password login, edge token, or database. Rate-limited
// in-memory per source IP and globally.
func (s *Server) handleRedpill(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	allowed := s.rateLimiter.Allow(clientIP(r))
	if !allowed {
		http.Error(w, "rate limit exceeded, try again later", http.StatusTooManyRequests)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	result, err := s.provisioner.ProvisionAgent(ctx)
	if err != nil {
		// Provisioning errors may contain third-party form text or generated identifiers. Do not
		// risk logging any part of the one-time credential exchange.
		slog.Error("redpill: provisioning failed")
		http.Error(w, "provisioning failed", http.StatusInternalServerError)
		return
	}

	resp := redpillResponse{
		MXID:               result.MXID,
		Password:           result.Password,
		AccessToken:        result.AccessToken,
		RefreshToken:       result.RefreshToken,
		ExpiresIn:          result.ExpiresIn,
		DeviceID:           result.DeviceID,
		Homeserver:         result.Homeserver,
		OAuthIssuer:        result.OAuthIssuer,
		OAuthClientID:      result.OAuthClientID,
		OAuthTokenEndpoint: result.OAuthTokenEndpoint,
		PlanURL:            s.planURL,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("redpill: failed to write response", "error", err)
	}
}

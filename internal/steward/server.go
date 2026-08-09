package steward

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// Config is Plan's browser-facing configuration. It deliberately excludes every Dodo,
// Synapse-admin, and database setting.
type Config struct {
	BillingEnv      string
	ServerName      string
	Homeserver      string
	MASBaseURL      string
	PlanPublicURL   string
	MASClientID     string
	MASClientSecret string
	SessionKey      string
}

var errCashierUnavailable = errors.New("cashier client is not configured")

// Server owns all public Plan routes. Its only billing dependency is CashierClient.
type Server struct {
	cfg     Config
	cashier CashierClient
	oidc    *OIDCClient
	session *Session
	mux     *http.ServeMux
}

func NewServer(cfg Config, cashier CashierClient) *Server {
	s := &Server{cfg: cfg, cashier: cashier, session: NewSession(cfg.SessionKey), mux: http.NewServeMux()}
	s.oidc = NewOIDCClient(cfg.Homeserver, cfg.MASBaseURL, cfg.MASClientID, cfg.MASClientSecret, strings.TrimRight(cfg.PlanPublicURL, "/")+"/callback")
	s.mux.HandleFunc("GET /plan", s.handlePlan)
	s.mux.HandleFunc("GET /plan/assets/logo-mark.png", s.handlePlanLogo)
	s.mux.HandleFunc("GET /plan/assets/product.css", s.handlePlanProductCSS)
	s.mux.HandleFunc("GET /plan/assets/plan.css", s.handlePlanCSS)
	s.mux.HandleFunc("GET /plan/assets/plan.js", s.handlePlanJS)
	s.mux.HandleFunc("GET /plan/login", s.handleLogin)
	s.mux.HandleFunc("GET /plan/callback", s.handleCallback)
	s.mux.Handle("POST /api/team", s.requireBrowserSession(http.HandlerFunc(s.handleCreateTeam)))
	s.mux.Handle("POST /api/team/seats", s.requireBrowserSession(http.HandlerFunc(s.handleAddSeat)))
	s.mux.Handle("DELETE /api/team/seats/{mxid}", s.requireBrowserSession(http.HandlerFunc(s.handleDeleteSeat)))
	s.mux.Handle("POST /api/team/checkout", s.requireBrowserSession(http.HandlerFunc(s.handleCheckout)))
	s.mux.Handle("POST /api/team/portal", s.requireBrowserSession(http.HandlerFunc(s.handlePortal)))
	s.mux.Handle("POST /api/team/seat-count", s.requireBrowserSession(http.HandlerFunc(s.handleChangeSeatCount)))
	s.mux.Handle("POST /api/team/seat-count/reconcile", s.requireBrowserSession(http.HandlerFunc(s.handleReconcileSeatCount)))
	// Compatibility route for a cached legacy Plan iframe. It has the same authenticated command.
	s.mux.Handle("POST /api/team/downgrade-request", s.requireBrowserSession(http.HandlerFunc(s.handleChangeSeatCount)))
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) requireBrowserSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mxid, err := s.session.MXID(r)
		if err != nil {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		if !s.isPlanOrigin(r.Header.Get("Origin")) {
			http.Error(w, "invalid request origin", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalContextKey{}, Principal{MXID: mxid})))
	})
}

func (s *Server) isPlanOrigin(origin string) bool {
	if origin == "" || origin == "null" {
		return false
	}
	planURL, err := url.Parse(s.cfg.PlanPublicURL)
	if err != nil || planURL.Scheme == "" || planURL.Host == "" {
		return false
	}
	originURL, err := url.Parse(origin)
	if err != nil || originURL.Scheme == "" || originURL.Host == "" || originURL.Path != "" || originURL.RawQuery != "" || originURL.Fragment != "" || originURL.User != nil {
		return false
	}
	return originURL.Scheme == planURL.Scheme && originURL.Host == planURL.Host
}

type principalContextKey struct{}

func principalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(Principal)
	return p, ok
}

func (s *Server) client() (CashierClient, error) {
	if s.cashier == nil {
		return nil, errCashierUnavailable
	}
	return s.cashier, nil
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	mxid, err := s.session.MXID(r)
	data := pageData{LoggedIn: err == nil, TestMode: s.cfg.BillingEnv == "test", MXID: mxid, RegisterURL: strings.TrimRight(s.cfg.Homeserver, "/") + "/auth/register"}
	if data.LoggedIn {
		client, err := s.client()
		if err != nil {
			http.Error(w, "Plan is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		state, err := client.PlanState(r.Context(), Principal{MXID: mxid})
		if err != nil {
			http.Error(w, "Plan is temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		data.Team, data.Seats = state.Team, state.Seats
		if data.Team != nil {
			switch data.Team.SubscriptionStatus {
			case "none", "failed", "cancelled", "expired":
				data.CanCheckout = true
			case "pending":
				data.CheckoutActive = true
			case "active", "on_hold":
				data.CanChangeSeats = true
			}
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := planTmpl.Execute(w, data); err != nil {
		http.Error(w, "Plan is temporarily unavailable", http.StatusInternalServerError)
	}
}

// handlePlanLogo serves the product-neutral TeleCrypt mark used by Plan. It is
// intentionally local to Steward: Plan must not need a third-party asset host
// to render its authentication or billing controls.
func (s *Server) handlePlanLogo(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(planLogoPNG)
}

func (s *Server) handlePlanProductCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(planProductCSS)
}

func (s *Server) handlePlanCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(planCSS)
}

func (s *Server) handlePlanJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(planJS)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	verifier, challenge, err := NewPKCEPair()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state := uuid.NewString()
	setOAuthCookies(w, state, verifier)
	http.Redirect(w, r, s.oidc.AuthorizeURL(state, challenge), http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	state, err := readOAuthCookie(r, oauthStateCookie)
	if err != nil || r.URL.Query().Get("state") != state {
		http.Error(w, "invalid oauth state", http.StatusBadRequest)
		return
	}
	verifier, err := readOAuthCookie(r, oauthPKCECookie)
	if err != nil {
		http.Error(w, "invalid oauth session", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}
	token, err := s.oidc.ExchangeCode(r.Context(), code, verifier)
	if err != nil {
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	username, err := s.oidc.Username(r.Context(), token)
	if err != nil {
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	clearOAuthCookies(w)
	s.session.Set(w, fmt.Sprintf("@%s:%s", username, s.cfg.ServerName))
	http.Redirect(w, r, s.cfg.PlanPublicURL, http.StatusFound)
}

func (s *Server) command(r *http.Request) (CashierClient, Principal, string, bool) {
	client, err := s.client()
	if err != nil {
		return nil, Principal{}, "", false
	}
	p, ok := principalFromContext(r.Context())
	if !ok {
		return nil, Principal{}, "", false
	}
	requestID := r.Header.Get("X-TeleCrypt-Request-ID")
	if _, err := uuid.Parse(requestID); err != nil {
		return nil, Principal{}, "", false
	}
	return client, p, requestID, true
}
func commandUnavailable(w http.ResponseWriter) {
	http.Error(w, "Plan is temporarily unavailable", http.StatusServiceUnavailable)
}

func (s *Server) handleCreateTeam(w http.ResponseWriter, r *http.Request) {
	client, p, id, ok := s.command(r)
	if !ok {
		commandUnavailable(w)
		return
	}
	team, err := client.CreateTeam(r.Context(), p, id)
	if err != nil {
		http.Error(w, "create team failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"team_id": team.ID})
}

type seatRequest struct {
	MXID string `json:"mxid"`
}

var matrixLocalpart = regexp.MustCompile(`^[0-9a-z=_\-./]+$`)

func validateLocalMXID(mxid, serverName string) bool {
	if !strings.HasPrefix(mxid, "@") || serverName == "" {
		return false
	}
	parts := strings.SplitN(strings.TrimPrefix(mxid, "@"), ":", 2)
	return len(parts) == 2 && parts[1] == serverName && matrixLocalpart.MatchString(parts[0])
}
func (s *Server) handleAddSeat(w http.ResponseWriter, r *http.Request) {
	client, p, id, ok := s.command(r)
	if !ok {
		commandUnavailable(w)
		return
	}
	var req seatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !validateLocalMXID(req.MXID, s.cfg.ServerName) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := client.AttachSeat(r.Context(), p, id, req.MXID); err != nil {
		http.Error(w, "could not attach seat", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func (s *Server) handleDeleteSeat(w http.ResponseWriter, r *http.Request) {
	client, p, id, ok := s.command(r)
	if !ok {
		commandUnavailable(w)
		return
	}
	if err := client.RemoveSeat(r.Context(), p, id, r.PathValue("mxid")); err != nil {
		http.Error(w, "could not remove seat", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type quantityRequest struct {
	Quantity int `json:"quantity"`
}

func decodeQuantity(w http.ResponseWriter, r *http.Request) (int, bool) {
	var req quantityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Quantity < 1 {
		http.Error(w, "quantity must be at least 1", http.StatusBadRequest)
		return 0, false
	}
	return req.Quantity, true
}
func (s *Server) handleCheckout(w http.ResponseWriter, r *http.Request) {
	client, p, id, ok := s.command(r)
	if !ok {
		commandUnavailable(w)
		return
	}
	q, ok := decodeQuantity(w, r)
	if !ok {
		return
	}
	link, err := client.StartCheckout(r.Context(), p, id, q)
	if err != nil {
		http.Error(w, "checkout failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"payment_link": link})
}
func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
	client, p, id, ok := s.command(r)
	if !ok {
		commandUnavailable(w)
		return
	}
	link, err := client.OpenCustomerPortal(r.Context(), p, id)
	if err != nil {
		http.Error(w, "portal unavailable", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"link": link})
}
func (s *Server) handleChangeSeatCount(w http.ResponseWriter, r *http.Request) {
	client, p, id, ok := s.command(r)
	if !ok {
		commandUnavailable(w)
		return
	}
	q, ok := decodeQuantity(w, r)
	if !ok {
		return
	}
	if err := client.ChangeSeatCount(r.Context(), p, id, q); err != nil {
		http.Error(w, "seat count change failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "pending_webhook"})
}
func (s *Server) handleReconcileSeatCount(w http.ResponseWriter, r *http.Request) {
	client, p, id, ok := s.command(r)
	if !ok {
		commandUnavailable(w)
		return
	}
	if err := client.ReconcileSeatCount(r.Context(), p, id); err != nil {
		http.Error(w, "provider reconciliation failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reconciled"})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type pageData struct {
	LoggedIn, TestMode                          bool
	MXID, RegisterURL                           string
	Team                                        *Team
	Seats                                       []Seat
	CanCheckout, CheckoutActive, CanChangeSeats bool
}

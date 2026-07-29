package cashier

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	dodo "github.com/dodopayments/dodopayments-go"
	"github.com/dodopayments/dodopayments-go/option"
	"github.com/dodopayments/dodopayments-go/shared"
	"github.com/google/uuid"

	"github.com/TeleCrypt-io/controlplane/internal/config"
	"github.com/TeleCrypt-io/controlplane/internal/db"
	"github.com/TeleCrypt-io/controlplane/internal/masoidc"
)

type teamStore interface {
	CreateTeam(ctx context.Context, adminMXID string) (db.Team, error)
	GetTeamByAdminMXID(ctx context.Context, adminMXID string) (db.Team, bool, error)
	GetTeamByID(ctx context.Context, teamID uuid.UUID) (db.Team, error)
	GetTeamByDodoSubscriptionID(ctx context.Context, subscriptionID string) (db.Team, bool, error)
	InsertSeat(ctx context.Context, teamID uuid.UUID, mxid string) error
	DeleteSeat(ctx context.Context, mxid string) error
	CountSeatsForTeam(ctx context.Context, teamID uuid.UUID) (int, error)
	ListSeatsForTeam(ctx context.Context, teamID uuid.UUID) ([]db.Seat, error)
	UpdateTeamSubscription(ctx context.Context, teamID uuid.UUID, status string, paidSeats int, dodoCustomerID, dodoSubscriptionID *string) error
	RecordHostedCheckout(ctx context.Context, teamID uuid.UUID, sessionID string, quantity int, startedAt time.Time) error
	IsWebhookProcessed(ctx context.Context, webhookID string) (bool, error)
	MarkWebhookProcessed(ctx context.Context, webhookID string) error
}

type Server struct {
	cfg        *config.CashierConfig
	store      teamStore
	reconciler *Reconciler
	oidc       *masoidc.Client
	session    *Session
	dodo       *dodo.Client
	mux        *http.ServeMux
}

func NewServer(cfg *config.CashierConfig, store teamStore, reconciler *Reconciler, oidc *masoidc.Client, session *Session, dodoClient *dodo.Client) *Server {
	s := &Server{
		cfg:        cfg,
		store:      store,
		reconciler: reconciler,
		oidc:       oidc,
		session:    session,
		dodo:       dodoClient,
		mux:        http.NewServeMux(),
	}
	s.mux.HandleFunc("GET /plan", s.handlePlan)
	s.mux.HandleFunc("GET /plan/login", s.handleLogin)
	s.mux.HandleFunc("GET /plan/callback", s.handleCallback)
	s.mux.Handle("POST /api/team", s.requireBrowserSession(http.HandlerFunc(s.handleCreateTeam)))
	s.mux.Handle("POST /api/team/seats", s.requireBrowserSession(http.HandlerFunc(s.handleAddSeat)))
	s.mux.Handle("DELETE /api/team/seats/{mxid}", s.requireBrowserSession(http.HandlerFunc(s.handleDeleteSeat)))
	s.mux.Handle("POST /api/team/checkout", s.requireBrowserSession(http.HandlerFunc(s.handleCheckout)))
	s.mux.Handle("POST /api/team/portal", s.requireBrowserSession(http.HandlerFunc(s.handlePortal)))
	s.mux.Handle("POST /api/team/downgrade-request", s.requireBrowserSession(http.HandlerFunc(s.handleDowngradeRequest)))
	s.mux.HandleFunc("POST /webhooks/dodo", s.handleDodoWebhook)
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// requireBrowserSession protects the browser-only, state-changing Plan APIs. The session cookie
// is deliberately HttpOnly, so a synchronizer token is not practical here; instead, require the
// browser's Origin header to exactly match the public Plan origin. Cross-site form posts and
// fetches therefore fail even if a browser would otherwise attach the session cookie. Dodo's
// server-to-server webhook is registered separately and does not pass through this middleware.
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
		next.ServeHTTP(w, r.WithContext(withMXID(r.Context(), mxid)))
	})
}

func (s *Server) isPlanOrigin(origin string) bool {
	if origin == "" || origin == "null" || s.cfg == nil {
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

func (s *Server) teamForSession(ctx context.Context) (db.Team, error) {
	mxid, ok := mxidFromCtx(ctx)
	if !ok {
		return db.Team{}, errUnauthorized
	}
	team, found, err := s.store.GetTeamByAdminMXID(ctx, mxid)
	if err != nil {
		return db.Team{}, err
	}
	if !found {
		return db.Team{}, fmt.Errorf("team not found")
	}
	return team, nil
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	mxid, err := s.session.MXID(r)
	loggedIn := err == nil

	var team *db.Team
	var seats []db.Seat
	if loggedIn {
		if t, found, err := s.store.GetTeamByAdminMXID(r.Context(), mxid); err == nil && found {
			team = &t
			seats, _ = s.store.ListSeatsForTeam(r.Context(), t.ID)
		}
	}

	data := struct {
		LoggedIn   bool
		MXID       string
		Team       *db.Team
		Seats      []db.Seat
		PlanURL    string
		PortalNote string
	}{
		LoggedIn: loggedIn,
		MXID:     mxid,
		Team:     team,
		Seats:    seats,
		PlanURL:  s.cfg.PlanPublicURL,
		PortalNote: "Manage billing opens Dodo's portal for payment method and invoices — " +
			"to change seat count, use the seats list below.",
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := planTmpl.Execute(w, data); err != nil {
		slog.Error("cashier: render plan page", "error", err)
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	verifier, challenge, err := masoidc.NewPKCEPair()
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
		slog.Error("cashier: token exchange", "error", err)
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	username, err := s.oidc.Username(r.Context(), token)
	if err != nil {
		slog.Error("cashier: userinfo", "error", err)
		http.Error(w, "login failed", http.StatusBadGateway)
		return
	}
	clearOAuthCookies(w)
	mxid := fmt.Sprintf("@%s:%s", username, s.cfg.ServerName)
	s.session.Set(w, mxid)
	http.Redirect(w, r, s.cfg.PlanPublicURL, http.StatusFound)
}

func (s *Server) handleCreateTeam(w http.ResponseWriter, r *http.Request) {
	mxid, _ := mxidFromCtx(r.Context())
	if _, found, _ := s.store.GetTeamByAdminMXID(r.Context(), mxid); found {
		http.Error(w, "team already exists", http.StatusConflict)
		return
	}
	team, err := s.store.CreateTeam(r.Context(), mxid)
	if err != nil {
		slog.Error("cashier: create team", "error", err)
		http.Error(w, "create team failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"team_id": team.ID.String()})
}

type seatRequest struct {
	MXID string `json:"mxid"`
}

func (s *Server) handleAddSeat(w http.ResponseWriter, r *http.Request) {
	team, err := s.teamForSession(r.Context())
	if err != nil {
		http.Error(w, "team not found — create one first", http.StatusNotFound)
		return
	}
	var req seatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MXID == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	count, err := s.store.CountSeatsForTeam(r.Context(), team.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if count >= team.PaidSeats {
		http.Error(w, "no paid seats available — buy more or remove a seat first", http.StatusConflict)
		return
	}
	if err := s.store.InsertSeat(r.Context(), team.ID, req.MXID); err != nil {
		slog.Error("cashier: insert seat", "error", err)
		http.Error(w, "could not attach seat", http.StatusInternalServerError)
		return
	}
	if err := s.reconciler.ReconcileTeamEntitlement(r.Context(), team.ID); err != nil {
		slog.Error("cashier: reconcile after add seat", "error", err)
		http.Error(w, "seat attached but entitlement sync failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDeleteSeat(w http.ResponseWriter, r *http.Request) {
	team, err := s.teamForSession(r.Context())
	if err != nil {
		http.Error(w, "team not found", http.StatusNotFound)
		return
	}
	mxid := r.PathValue("mxid")
	seats, err := s.store.ListSeatsForTeam(r.Context(), team.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	found := false
	for _, seat := range seats {
		if seat.MXID == mxid {
			found = true
			break
		}
	}
	if !found {
		http.Error(w, "seat not on your team", http.StatusNotFound)
		return
	}
	// Revoke while the seat is still attached. ReconcileTeamEntitlement only sees current
	// seat rows, so deleting first would leave this MXID outside its revocation set.
	if err := s.reconciler.RevokeSeat(r.Context(), mxid); err != nil {
		slog.Error("cashier: revoke deleted seat", "mxid", mxid, "error", err)
		http.Error(w, "seat removal entitlement sync failed", http.StatusInternalServerError)
		return
	}
	if err := s.store.DeleteSeat(r.Context(), mxid); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type quantityRequest struct {
	Quantity int `json:"quantity"`
}

func (s *Server) handleCheckout(w http.ResponseWriter, r *http.Request) {
	team, err := s.teamForSession(r.Context())
	if err != nil {
		http.Error(w, "team not found", http.StatusNotFound)
		return
	}
	var req quantityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Quantity < 1 {
		http.Error(w, "quantity must be at least 1", http.StatusBadRequest)
		return
	}
	if teamHasLiveSubscription(team) {
		http.Error(w, "an active or pending subscription already exists; use the billing portal or wait for its terminal status", http.StatusConflict)
		return
	}
	resp, err := s.dodo.CheckoutSessions.New(r.Context(), dodo.CheckoutSessionNewParams{
		CheckoutSessionRequest: dodo.CheckoutSessionRequestParam{
			ProductCart: dodo.F([]dodo.ProductItemReqParam{{
				ProductID: dodo.F(s.cfg.DodoProductID),
				Quantity:  dodo.F(int64(req.Quantity)),
			}}),
			Metadata: dodo.F(dodo.MetadataParam{
				"team_id": shared.UnionString(team.ID.String()),
			}),
			ReturnURL: dodo.F(s.cfg.PlanPublicURL),
			CancelURL: dodo.F(s.cfg.PlanPublicURL),
		},
	})
	if err != nil {
		slog.Error("cashier: create subscription", "error", err)
		http.Error(w, "checkout failed", http.StatusBadGateway)
		return
	}

	if resp.CheckoutURL == "" || resp.SessionID == "" {
		slog.Error("cashier: hosted checkout returned incomplete response")
		http.Error(w, "checkout failed", http.StatusBadGateway)
		return
	}
	if err := s.store.RecordHostedCheckout(r.Context(), team.ID, resp.SessionID, req.Quantity, time.Now().UTC()); err != nil {
		slog.Error("cashier: record hosted checkout", "error", err)
		http.Error(w, "checkout failed", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"payment_link": resp.CheckoutURL})
}

func teamHasLiveSubscription(team db.Team) bool {
	if team.SubscriptionStatus == "pending" && team.CheckoutStartedAt != nil {
		return time.Since(*team.CheckoutStartedAt) < 24*time.Hour
	}
	if team.DodoSubscriptionID == nil || *team.DodoSubscriptionID == "" {
		return false
	}
	switch team.SubscriptionStatus {
	case "pending", "active", "on_hold":
		return true
	default:
		return false
	}
}

func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
	team, err := s.teamForSession(r.Context())
	if err != nil {
		http.Error(w, "team not found", http.StatusNotFound)
		return
	}
	if team.DodoCustomerID == nil || *team.DodoCustomerID == "" {
		http.Error(w, "no billing account yet — start checkout first", http.StatusBadRequest)
		return
	}
	session, err := s.dodo.Customers.CustomerPortal.New(r.Context(), *team.DodoCustomerID, dodo.CustomerCustomerPortalNewParams{
		ReturnURL: dodo.F(s.cfg.PlanPublicURL),
	})
	if err != nil {
		slog.Error("cashier: customer portal", "error", err)
		http.Error(w, "portal unavailable", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"link": session.Link})
}

func (s *Server) handleDowngradeRequest(w http.ResponseWriter, r *http.Request) {
	team, err := s.teamForSession(r.Context())
	if err != nil {
		http.Error(w, "team not found", http.StatusNotFound)
		return
	}
	var req quantityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Quantity < 1 {
		http.Error(w, "quantity must be at least 1", http.StatusBadRequest)
		return
	}
	count, err := s.store.CountSeatsForTeam(r.Context(), team.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if count > req.Quantity {
		need := count - req.Quantity
		msg := fmt.Sprintf("remove %d seat(s) before lowering to %d paid seats", need, req.Quantity)
		http.Error(w, msg, http.StatusConflict)
		return
	}
	if team.DodoSubscriptionID == nil || *team.DodoSubscriptionID == "" {
		http.Error(w, "no active subscription", http.StatusBadRequest)
		return
	}
	err = s.dodo.Subscriptions.ChangePlan(r.Context(), *team.DodoSubscriptionID, dodo.SubscriptionChangePlanParams{
		UpdateSubscriptionPlanReq: dodo.UpdateSubscriptionPlanReqParam{
			ProductID:            dodo.F(s.cfg.DodoProductID),
			Quantity:             dodo.F(int64(req.Quantity)),
			ProrationBillingMode: dodo.F(dodo.UpdateSubscriptionPlanReqProrationBillingModeProratedImmediately),
		},
	})
	if err != nil {
		slog.Error("cashier: change plan", "error", err)
		http.Error(w, "downgrade request failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleDodoWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	event, err := s.dodo.Webhooks.Unwrap(body, r.Header)
	if err != nil {
		slog.Error("cashier: webhook unwrap", "error", err)
		http.Error(w, "invalid webhook", http.StatusBadRequest)
		return
	}

	webhookID := r.Header.Get("webhook-id")
	if webhookID != "" {
		processed, err := s.store.IsWebhookProcessed(r.Context(), webhookID)
		if err != nil {
			slog.Error("cashier: webhook dedup check", "error", err)
		} else if processed {
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	if err := s.processWebhook(r.Context(), event); err != nil {
		slog.Error("cashier: process webhook", "error", err, "type", event.Type)
		http.Error(w, "processing failed", http.StatusInternalServerError)
		return
	}

	if webhookID != "" {
		if err := s.store.MarkWebhookProcessed(r.Context(), webhookID); err != nil {
			slog.Error("cashier: mark webhook processed", "error", err)
		}
	}
	w.WriteHeader(http.StatusOK)
}

var errStaleSubscriptionEvent = errors.New("stale subscription event")

func (s *Server) processWebhook(ctx context.Context, event *dodo.UnwrapWebhookEvent) (err error) {
	// Dodo delivers asynchronously and older subscriptions can emit late terminal/renewal
	// events. Once a team is bound to a newer subscription, an old event must be acknowledged
	// but must never overwrite the newer entitlement state (or trigger endless retries).
	defer func() {
		if errors.Is(err, errStaleSubscriptionEvent) {
			slog.Warn("cashier: ignored stale subscription event", "type", event.Type)
			err = nil
		}
	}()
	switch event.Type {
	case dodo.UnwrapWebhookEventTypeSubscriptionActive:
		ev, ok := event.AsUnion().(dodo.SubscriptionActiveWebhookEvent)
		if !ok {
			return fmt.Errorf("unexpected active union")
		}
		return s.handleSubscriptionEntitlement(ctx, ev.Data, "active")

	case dodo.UnwrapWebhookEventTypeSubscriptionRenewed:
		ev, ok := event.AsUnion().(dodo.SubscriptionRenewedWebhookEvent)
		if !ok {
			return fmt.Errorf("unexpected renewed union")
		}
		return s.handleSubscriptionEntitlement(ctx, ev.Data, "active")

	case dodo.UnwrapWebhookEventTypeSubscriptionUpdated:
		ev, ok := event.AsUnion().(dodo.SubscriptionUpdatedWebhookEvent)
		if !ok {
			return fmt.Errorf("unexpected updated union")
		}
		return s.handleSubscriptionEntitlement(ctx, ev.Data, string(ev.Data.Status))

	case dodo.UnwrapWebhookEventTypeSubscriptionOnHold:
		ev, ok := event.AsUnion().(dodo.SubscriptionOnHoldWebhookEvent)
		if !ok {
			return fmt.Errorf("unexpected on_hold union")
		}
		return s.updateTeamStatusOnly(ctx, ev.Data, "on_hold")

	case dodo.UnwrapWebhookEventTypeSubscriptionFailed:
		ev, ok := event.AsUnion().(dodo.SubscriptionFailedWebhookEvent)
		if !ok {
			return fmt.Errorf("unexpected failed union")
		}
		return s.handleSubscriptionRevocation(ctx, ev.Data, "failed")

	case dodo.UnwrapWebhookEventTypeSubscriptionCancelled:
		ev, ok := event.AsUnion().(dodo.SubscriptionCancelledWebhookEvent)
		if !ok {
			return fmt.Errorf("unexpected cancelled union")
		}
		return s.handleSubscriptionRevocation(ctx, ev.Data, "cancelled")

	case dodo.UnwrapWebhookEventTypeSubscriptionExpired:
		ev, ok := event.AsUnion().(dodo.SubscriptionExpiredWebhookEvent)
		if !ok {
			return fmt.Errorf("unexpected expired union")
		}
		return s.handleSubscriptionRevocation(ctx, ev.Data, "expired")

	default:
		return nil
	}
}

// handleSubscriptionRevocation makes all terminal Dodo states revoke access. The team status is
// persisted first so a retry (or a later periodic reconciliation) still sees an inactive
// subscription if Synapse is temporarily unavailable.
func (s *Server) handleSubscriptionRevocation(ctx context.Context, sub dodo.Subscription, status string) error {
	team, err := s.teamForSubscription(ctx, sub)
	if err != nil {
		return err
	}
	if err := s.store.UpdateTeamSubscription(ctx, team.ID, status, int(sub.Quantity), nil, nil); err != nil {
		return err
	}
	return s.reconciler.ClearAllTeamSeats(ctx, team.ID)
}

func (s *Server) handleSubscriptionEntitlement(ctx context.Context, sub dodo.Subscription, status string) error {
	team, err := s.teamForSubscription(ctx, sub)
	if err != nil {
		return err
	}
	customerID := sub.Customer.CustomerID
	subID := sub.SubscriptionID
	if err := s.store.UpdateTeamSubscription(ctx, team.ID, status, int(sub.Quantity), &customerID, &subID); err != nil {
		return err
	}
	return s.reconciler.ReconcileTeamEntitlement(ctx, team.ID)
}

func (s *Server) updateTeamStatusOnly(ctx context.Context, sub dodo.Subscription, status string) error {
	team, err := s.teamForSubscription(ctx, sub)
	if err != nil {
		return err
	}
	return s.store.UpdateTeamSubscription(ctx, team.ID, status, int(sub.Quantity), nil, nil)
}

func (s *Server) teamForSubscription(ctx context.Context, sub dodo.Subscription) (db.Team, error) {
	if sub.SubscriptionID != "" {
		if team, found, err := s.store.GetTeamByDodoSubscriptionID(ctx, sub.SubscriptionID); err != nil {
			return db.Team{}, err
		} else if found {
			return team, nil
		}
	}
	if teamID := metadataString(sub.Metadata, "team_id"); teamID != "" {
		id, err := uuid.Parse(teamID)
		if err != nil {
			return db.Team{}, fmt.Errorf("invalid team_id metadata: %w", err)
		}
		team, err := s.store.GetTeamByID(ctx, id)
		if err != nil {
			return db.Team{}, err
		}
		// Metadata identifies the team, not the subscription generation. Never let metadata
		// resurrect an older subscription after a later checkout has bound a new one.
		if sub.SubscriptionID == "" || (team.DodoSubscriptionID != nil && *team.DodoSubscriptionID != sub.SubscriptionID) {
			return db.Team{}, errStaleSubscriptionEvent
		}
		return team, nil
	}
	return db.Team{}, errors.New("team not found for subscription")
}

func metadataString(meta dodo.Metadata, key string) string {
	v, ok := meta[key]
	if !ok {
		return ""
	}
	if s, ok := v.(shared.UnionString); ok {
		return string(s)
	}
	return fmt.Sprint(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func NewDodoClient(cfg *config.CashierConfig) *dodo.Client {
	opts := []option.RequestOption{
		option.WithBaseURL(cfg.DodoAPIBase),
		option.WithBearerToken(cfg.DodoAPIKey),
		option.WithWebhookKey(cfg.DodoWebhookSecret),
	}
	if cfg.TelecryptEnv == "test" {
		opts = append(opts, option.WithEnvironmentTestMode())
	} else {
		opts = append(opts, option.WithEnvironmentLiveMode())
	}
	client := dodo.NewClient(opts...)
	return client
}

var planTmpl = template.Must(template.New("plan").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>TeleCrypt Plan</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 42rem; margin: 2rem auto; padding: 0 1rem; }
table { border-collapse: collapse; width: 100%; }
td, th { border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; }
button { margin-top: 0.5rem; }
.note { color: #555; font-size: 0.9rem; }
</style>
</head>
<body>
<h1>TeleCrypt Plan</h1>
{{if not .LoggedIn}}
<p><a href="/plan/login">Log in with your TeleCrypt account</a> to manage team seats.</p>
{{else}}
<p>Signed in as <strong>{{.MXID}}</strong></p>
{{if .Team}}
<p>Subscription: <strong>{{.Team.SubscriptionStatus}}</strong> · Paid seats: <strong>{{.Team.PaidSeats}}</strong></p>
<h2>Seats</h2>
{{if .Seats}}
<table><tr><th>MXID</th><th>Attached</th></tr>
{{range .Seats}}<tr><td>{{.MXID}}</td><td>{{.CreatedAt.Format "2006-01-02 15:04"}}</td></tr>{{end}}
</table>
{{else}}<p>No seats attached yet.</p>{{end}}
<form id="add-seat" onsubmit="return addSeat(event)">
<label>Attach account MXID: <input name="mxid" required placeholder="@bot:telecrypt.io"></label>
<button type="submit">Add seat</button>
</form>
<form id="checkout" onsubmit="return checkout(event)">
<label>Seat count: <input name="quantity" type="number" min="1" value="{{if .Team}}{{if gt .Team.PaidSeats 0}}{{.Team.PaidSeats}}{{else}}1{{end}}{{else}}1{{end}}" required></label>
<button type="submit">Start trial / buy seats</button>
</form>
<p class="note">{{.PortalNote}}</p>
<button type="button" onclick="openPortal()">Manage payment method & invoices</button>
<form id="downgrade" onsubmit="return downgrade(event)">
<label>Request fewer paid seats: <input name="quantity" type="number" min="1" required></label>
<button type="submit">Request downgrade</button>
</form>
{{else}}
<p>No team yet.</p>
<button type="button" onclick="createTeam()">Create team</button>
{{end}}
{{end}}
<script>
async function createTeam() {
  const r = await fetch('/api/team', {method:'POST'});
  if (r.ok) location.reload(); else alert(await r.text());
}
async function addSeat(e) {
  e.preventDefault();
  const mxid = e.target.mxid.value.trim();
  const r = await fetch('/api/team/seats', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({mxid})});
  if (r.ok) location.reload(); else alert(await r.text());
}
async function checkout(e) {
  e.preventDefault();
  const quantity = parseInt(e.target.quantity.value, 10);
  const r = await fetch('/api/team/checkout', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({quantity})});
  if (!r.ok) { alert(await r.text()); return false; }
  const j = await r.json();
  if (j.payment_link) window.location = j.payment_link; else alert('no payment link');
  return false;
}
async function openPortal() {
  const r = await fetch('/api/team/portal', {method:'POST'});
  if (!r.ok) { alert(await r.text()); return; }
  const j = await r.json();
  if (j.link) window.open(j.link, '_blank');
}
async function downgrade(e) {
  e.preventDefault();
  const quantity = parseInt(e.target.quantity.value, 10);
  const r = await fetch('/api/team/downgrade-request', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({quantity})});
  if (r.ok) { alert('Downgrade requested'); location.reload(); } else alert(await r.text());
  return false;
}
</script>
</body>
</html>`))

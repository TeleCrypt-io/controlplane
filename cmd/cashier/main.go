// Command cashier serves TeleCrypt.io's Plan tab: MAS OIDC login, team/seat management,
// Dodo Payments checkout, and immediate Synapse verified unlock on payment confirmation.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/TeleCrypt-io/controlplane/internal/cashier"
	"github.com/TeleCrypt-io/controlplane/internal/config"
	"github.com/TeleCrypt-io/controlplane/internal/db"
	"github.com/TeleCrypt-io/controlplane/internal/masoidc"
	"github.com/TeleCrypt-io/controlplane/internal/synapseadmin"
)

func main() {
	cfg, err := config.LoadCashier()
	if err != nil {
		slog.Error("config", "error", err)
		os.Exit(1)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLogLevel(cfg.LogLevel)})))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.ControlplaneDBURL)
	if err != nil {
		slog.Error("db connect", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		slog.Error("migrate", "error", err)
		os.Exit(1)
	}

	store := db.NewStore(pool)
	// Keep the privileged Synapse admin API on the Docker network. HOMESERVER remains
	// public because it is used for the browser-facing OIDC authorization redirect.
	synapse := synapseadmin.NewClient(cfg.SynapseAdminURL, cfg.SynapseAdminToken)
	reconciler := cashier.NewReconciler(store, synapse)
	oidc := masoidc.NewClient(
		cfg.Homeserver,
		cfg.MASBaseURL,
		cfg.MASClientID,
		cfg.MASClientSecret,
		cfg.PlanPublicURL+"/callback",
	)
	dodoClient := cashier.NewDodoClient(cfg)
	srv := cashier.NewServer(cfg, store, reconciler, oidc, cashier.NewSession(cfg.SessionKey), dodoClient)

	httpSrv := &http.Server{Addr: cfg.ListenAddr, Handler: srv}
	go func() {
		slog.Info("cashier listening", "addr", cfg.ListenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("listen", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")
	_ = httpSrv.Shutdown(context.Background())
}

func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Command plan is the future public Plan service. It is intentionally not deployed until a
// coordinated release moves the browser flow from legacy cashier and wires its private Cashier
// transport. See internal/plan/README.md.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/config"
	"github.com/TeleCrypt-io/controlplane/internal/plan"
)

func main() {
	cfg, err := config.LoadPlan()
	if err != nil {
		slog.Error("config", "error", err)
		os.Exit(1)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLogLevel(cfg.LogLevel)})))

	cashierClient, err := plan.NewHTTPCashierClient(cfg.CashierInternalURL, cfg.PlanAssertionPrivateKey, nil)
	if err != nil {
		slog.Error("cashier client", "error", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr: cfg.ListenAddr,
		Handler: plan.NewServer(plan.Config{
			ServerName:      cfg.ServerName,
			Homeserver:      cfg.Homeserver,
			MASBaseURL:      cfg.MASBaseURL,
			PlanPublicURL:   cfg.PlanPublicURL,
			MASClientID:     cfg.MASClientID,
			MASClientSecret: cfg.MASClientSecret,
			SessionKey:      cfg.SessionKey,
		}, cashierClient),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		slog.Info("plan scaffold listening", "addr", cfg.ListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server", "error", err)
			os.Exit(1)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown", "error", err)
	}
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

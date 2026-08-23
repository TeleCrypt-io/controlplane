// Command steward is TeleCrypt's public account, plan, and subscription-management service.
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
	"github.com/TeleCrypt-io/controlplane/internal/steward"
)

func main() {
	cfg, err := config.LoadSteward()
	if err != nil {
		slog.Error("config", "error", err)
		os.Exit(1)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cashierClient, err := steward.NewHTTPCashierClient(cfg.CashierInternalURL, cfg.StewardAssertionPrivateKey, nil)
	if err != nil {
		slog.Error("cashier client", "error", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr: stewardListenAddr,
		Handler: steward.NewServer(steward.Config{
			BillingEnv:       cfg.BillingEnv,
			ServerName:       cfg.ServerName,
			BackendPublicURL: cfg.BackendPublicURL,
			MASInternalURL:   cfg.MASInternalURL,
			PlanPublicURL:    cfg.PlanPublicURL,
			MASClientID:      cfg.MASClientID,
			MASClientSecret:  cfg.MASClientSecret,
			SessionKey:       cfg.SessionKey,
		}, cashierClient),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	go func() {
		slog.Info("steward listening", "addr", stewardListenAddr)
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

const stewardListenAddr = ":9012"

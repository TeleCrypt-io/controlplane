// Command redpill runs TeleCrypt.io's credential-free public agent-registration shim. POST
// /redpill calls the signed private agent issuer; GET /health is a liveness probe.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TeleCrypt-io/controlplane/internal/agent"
	"github.com/TeleCrypt-io/controlplane/internal/config"
	"github.com/TeleCrypt-io/controlplane/internal/redpillhttp"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "error", err)
		os.Exit(1)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLogLevel(cfg.LogLevel)})))

	handler, err := build(cfg)
	if err != nil {
		slog.Error("startup", "error", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		slog.Info("listening", "addr", cfg.ListenAddr)
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

func build(cfg *config.Config) (http.Handler, error) {
	provisioner, err := agent.NewProvisioner(cfg.AgentIssuerInternalURL, cfg.RedpillAssertionPrivateKey, nil)
	if err != nil {
		return nil, err
	}

	rateLimiter := redpillhttp.NewRateLimiter(
		cfg.RateLimitPerSource, cfg.RateLimitGlobal, time.Duration(cfg.RateLimitWindowSec)*time.Second)

	return redpillhttp.New(provisioner, rateLimiter, cfg.PlanURL, cfg.IgnoredProxyIP), nil
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

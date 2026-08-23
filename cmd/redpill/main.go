// Command redpill runs TeleCrypt.io's stateless agent-registration shim: POST /redpill drives
// MAS's public registration and OAuth device flow (no admin credentials, database, or password
// login — see internal/agent and internal/masreg) and GET /health is a liveness probe.
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
	"github.com/TeleCrypt-io/controlplane/internal/masreg"
	"github.com/TeleCrypt-io/controlplane/internal/redpillhttp"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "error", err)
		os.Exit(1)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	handler, err := build(cfg)
	if err != nil {
		slog.Error("startup", "error", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:              redpillListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      65 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		slog.Info("listening", "addr", redpillListenAddr)
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
	if err := cfg.ValidateRedpill(); err != nil {
		return nil, err
	}

	// MAS registration and device OAuth use browser-visible public URLs because MAS builds
	// redirects and native-client metadata from its configured public base URL.
	masRegClient := masreg.NewClient(cfg.MASPublicURL)

	provisioner, err := agent.NewProvisioner(masRegClient, cfg.BackendPublicURL, cfg.ServerName)
	if err != nil {
		return nil, err
	}

	rateLimiter := redpillhttp.NewRateLimiter(
		redpillRateLimitPerSource, redpillRateLimitGlobal, redpillRateLimitWindow)

	return redpillhttp.New(provisioner, rateLimiter, cfg.PlanPublicURL), nil
}

const (
	redpillListenAddr         = ":9009"
	redpillRateLimitPerSource = 5
	redpillRateLimitGlobal    = 60
	redpillRateLimitWindow    = time.Minute
)

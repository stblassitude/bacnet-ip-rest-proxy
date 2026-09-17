// Command bacnet-ip-rest-proxy runs the BACnet/IP REST proxy: an HTTP(S)
// server that translates REST calls into BACnet/IP requests, gated by the
// authentication/authorization configuration described in the README.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/api"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/bacnet"
	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/config"
)

// version is set via -ldflags "-X main.version=..." at release build time.
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config.yaml", "path to the YAML configuration file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	localAddr := fmt.Sprintf("0.0.0.0:%d", cfg.Bacnet.LocalPort)
	client, err := bacnet.NewClient(bacnet.ClientOptions{
		LocalAddr: localAddr,
		Timeout:   cfg.Bacnet.Timeout.AsDuration(),
		Retries:   cfg.Bacnet.Retries,
	})
	if err != nil {
		return fmt.Errorf("starting bacnet client: %w", err)
	}
	defer client.Close()

	server := api.NewServer(cfg, client)
	httpServer := &http.Server{
		Addr:    cfg.Listen.Address,
		Handler: api.NewRouter(server),
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("listening", "version", version, "address", cfg.Listen.Address, "tls", cfg.Listen.TLS.Enabled)
		var err error
		if cfg.Listen.TLS.Enabled {
			err = httpServer.ListenAndServeTLS(cfg.Listen.TLS.CertFile, cfg.Listen.TLS.KeyFile)
		} else {
			err = httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}

package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LeezyWannaFall/Kacpersky_2026_testovoe/internal/config"
	"github.com/LeezyWannaFall/Kacpersky_2026_testovoe/internal/handler"
	"github.com/LeezyWannaFall/Kacpersky_2026_testovoe/internal/repository"
	"github.com/LeezyWannaFall/Kacpersky_2026_testovoe/internal/service"
	"github.com/LeezyWannaFall/Kacpersky_2026_testovoe/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("application stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg := config.Load()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := sql.Open("pgx", cfg.DatabaseURL())
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return err
	}
	if err := migrations.Apply(ctx, db); err != nil {
		return err
	}

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL())
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return err
	}
	svc := service.New(repository.NewPostgres(pool))
	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler.New(svc).Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	serverErr := make(chan error, 1)
	go func() {
		logger.Info("HTTP server listening", "address", cfg.HTTPAddr)
		serverErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		return err
	}
	if err := <-serverErr; !errors.Is(err, http.ErrServerClosed) && err != nil {
		return err
	}
	logger.Info("HTTP server stopped")
	return nil
}

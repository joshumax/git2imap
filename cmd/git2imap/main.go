package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"git2imap/internal/config"
	"git2imap/internal/gitbackend"
	imapservice "git2imap/internal/imapserver"
	"git2imap/internal/secure"
	"git2imap/internal/service"
	smtpservice "git2imap/internal/smtpserver"
	"git2imap/internal/store"
	webservice "git2imap/internal/web"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "git-askpass" {
		runAskpass()
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "git2imap:", err)
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet("git2imap", flag.ContinueOnError)
	configPath := flags.String("config", "", "path to YAML configuration")
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.CacheDir, 0o700); err != nil {
		return err
	}
	logger := newLogger(cfg.Log)
	st, err := store.Open(cfg.DatabasePath())
	if err != nil {
		return err
	}
	defer st.Close()
	box, err := secure.NewBox(cfg.MasterKeyBytes())
	if err != nil {
		return err
	}
	git := &gitbackend.Backend{
		GitCommand: cfg.Git.Command, SSHCommand: cfg.Git.SSHCommand,
		KnownHosts:   filepath.Join(cfg.DataDir, "known_hosts"),
		CloneTimeout: cfg.Git.CloneTimeout, Timeout: cfg.Git.FetchTimeout,
		Logger: logger.With("component", "git"),
	}
	repositories := service.NewRepositoryService(st, box, git, cfg.CacheDir, cfg.PublicHost, logger)
	if purged, err := repositories.PurgeLegacyRepositories(context.Background()); err != nil {
		return fmt.Errorf("purge legacy repository accounts: %w", err)
	} else if purged > 0 {
		logger.Warn("removed repositories using the retired account format", "count", purged)
	}
	repositories.EnsureAll(context.Background())

	imapServer, err := imapservice.New(cfg.IMAP, repositories, logger)
	if err != nil {
		return err
	}
	smtpServer, err := smtpservice.New(cfg.SMTP, cfg.PublicHost, repositories, logger)
	if err != nil {
		return err
	}
	webServer, err := webservice.New(cfg, repositories, st, logger)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	errors := make(chan error, 8)
	report := func(name string, err error) {
		if err != nil {
			errors <- fmt.Errorf("%s server: %w", name, err)
		}
	}
	imapServer.Serve(ctx, report)
	smtpServer.Serve(ctx, report)
	webServer.Serve(ctx, report)
	logger.Info("git2imap started",
		"web", cfg.Web.Addr, "imap", cfg.IMAP.Addr, "smtp", cfg.SMTP.Addr,
		"public_host", cfg.PublicHost)

	select {
	case <-ctx.Done():
		logger.Info("shutting down")
		return nil
	case err := <-errors:
		cancel()
		return err
	}
}

func runAskpass() {
	prompt := ""
	if len(os.Args) > 2 {
		prompt = strings.ToLower(os.Args[2])
	}
	if os.Getenv("GIT2IMAP_ASKPASS_MODE") == "http" && strings.Contains(prompt, "username") {
		fmt.Print(os.Getenv("GIT2IMAP_ASKPASS_USERNAME"))
		return
	}
	fmt.Print(os.Getenv("GIT2IMAP_ASKPASS_PASSWORD"))
}

func newLogger(cfg config.LogConfig) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	options := &slog.HandlerOptions{Level: level}
	if strings.EqualFold(cfg.Format, "json") {
		return slog.New(slog.NewJSONHandler(os.Stdout, options))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, options))
}

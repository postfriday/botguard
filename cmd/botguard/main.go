// Command botguard is the long-running rDNS-filter daemon.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/postfriday/botguard/internal/caddyctl"
	"github.com/postfriday/botguard/internal/config"
	"github.com/postfriday/botguard/internal/pipeline"
	"github.com/postfriday/botguard/internal/resolver"
	"github.com/postfriday/botguard/internal/rules"
	"github.com/postfriday/botguard/internal/server"
	"github.com/postfriday/botguard/internal/store"
	"github.com/postfriday/botguard/internal/tailer"
)

func main() {
	cfgPath := flag.String("config", "/etc/botguard/botguard.yaml", "path to config file")
	rulesPath := flag.String("rules", "", "override rules path (otherwise read from config)")
	logLevel := flag.String("log-level", "info", "log level: debug|info|warn|error")
	flag.Parse()

	logger := newLogger(*logLevel)

	cfg, dur, err := config.Load(*cfgPath)
	if err != nil {
		logger.Error("config load", "err", err)
		os.Exit(2)
	}
	if *rulesPath != "" {
		cfg.Rules.Path = *rulesPath
	}

	rs, err := rules.Load(cfg.Rules.Path)
	if err != nil {
		logger.Error("rules load", "err", err)
		os.Exit(2)
	}
	logger.Info("rules loaded", "path", cfg.Rules.Path, "count", len(rs.Rules))

	st, err := store.Open(cfg.Cache.Path)
	if err != nil {
		logger.Error("store open", "err", err)
		os.Exit(2)
	}
	defer func() { _ = st.Close() }()

	res := resolver.New(dur.ResolverTimeout, cfg.Resolver.MaxInFlight, cfg.Resolver.Servers)

	cdy := caddyctl.New(caddyctl.Options{
		SnippetPath:   cfg.Caddy.SnippetPath,
		CaddyfilePath: cfg.Caddy.Caddyfile,
		AdminURL:      cfg.Caddy.AdminURL,
		Debounce:      dur.ReloadDebounce,
		ReloadCommand: cfg.Caddy.ReloadCommand,
		ConfigPath:    cfg.Caddy.ConfigPath,
		Logger:        logger,
	})

	t := tailer.New(cfg.Log.Path, dur.PollInterval, logger)
	pl := pipeline.New(cfg, dur, st, res, rs, cdy, logger)

	srv := server.New(server.Options{
		Listen:    cfg.Server.Listen,
		BasicUser: cfg.Server.BasicAuth.User,
		BasicPass: cfg.Server.BasicAuth.Pass,
		Store:     st,
		Logger:    logger,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); _ = t.Run(ctx) }()
	go func() { defer wg.Done(); _ = pl.Run(ctx, t.Events()) }()
	go func() { defer wg.Done(); _ = srv.Run(ctx) }()

	logger.Info("botguard started",
		"log_path", cfg.Log.Path,
		"db", cfg.Cache.Path,
		"snippet", cfg.Caddy.SnippetPath,
		"admin", cfg.Caddy.AdminURL,
		"http_listen", cfg.Server.Listen,
	)
	wg.Wait()
	logger.Info("botguard stopped")
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch level {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lv})
	logger := slog.New(h)
	slog.SetDefault(logger)
	return logger
}

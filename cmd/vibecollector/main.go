package main

import (
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	_ "time/tzdata"

	"vibecollector/internal/config"
	"vibecollector/internal/obs"
)

func main() {
	// Database files created later must be mode 0600 even if the ambient umask is loose.
	syscall.Umask(0o077)

	var flags config.Flags
	flag.StringVar(&flags.ConfigPath, "config", "", "TOML config file (default ./vibecollector.toml if present)")
	flag.StringVar(&flags.HTTP, "http", "", "override http.listen")
	flag.StringVar(&flags.UDP, "udp", "", "override udp.listen")
	flag.StringVar(&flags.DB, "db", "", "override db.path")
	flag.Parse()

	cfg, err := config.Load(flags)
	if err != nil {
		slog.Error("config", "err", err)
		if errors.Is(err, config.ErrUnknownField) ||
			errors.Is(err, config.ErrTokenRequired) ||
			errors.Is(err, config.ErrBadConfig) {
			os.Exit(2)
		}
		os.Exit(1)
	}

	var level slog.Level
	switch cfg.Log.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
	if cfg.LooseFileMode {
		slog.Warn("config file mode is looser than 0600")
	}

	_ = obs.NewCounters()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

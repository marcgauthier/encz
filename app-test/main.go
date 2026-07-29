package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	os.Exit(runMain())
}

func runMain() int {
	configPath := flag.String("config", "config.yaml", "YAML configuration file")
	duration := flag.Duration("duration", 0, "optional run duration override (for bounded tests)")
	flag.Parse()

	cfg, err := loadConfig(*configPath, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		return 2
	}
	if *duration < 0 {
		fmt.Fprintln(os.Stderr, "-duration cannot be negative")
		return 2
	}
	if *duration > 0 {
		cfg.DurationValue = *duration
	}
	if err := os.MkdirAll(cfg.RunDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "create run directory: %v\n", err)
		return 1
	}
	logger, err := newLiveLogger(cfg.LogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open log: %v\n", err)
		return 1
	}
	defer logger.Close()
	logger.Info("run directory=%s", cfg.RunDir)

	apiDir := filepath.Join(cfg.RunDir, "api-certification")
	if err := os.MkdirAll(apiDir, 0o700); err != nil {
		logger.Error("create API certification directory: %v", err)
		return 1
	}
	if err := certifyPublicAPI(apiDir, cfg.MasterKey, logger); err != nil {
		logger.Error("API certification failed: %v", err)
		logger.DumpHistory()
		return 1
	}

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithCancelCause(signalCtx)
	defer cancel(context.Canceled)
	if cfg.DurationValue > 0 {
		timer := time.AfterFunc(cfg.DurationValue, func() {
			logger.Info("configured duration reached")
			cancel(context.Canceled)
		})
		defer timer.Stop()
	}

	r := newRunner(ctx, cancel, cfg, logger)
	if err := r.initialize(); err != nil {
		logger.Error("initialization failed: %v", err)
		logger.DumpHistory()
		_ = r.close()
		return 1
	}
	runErr := r.run()
	cause := context.Cause(ctx)
	cleanStop := runErr == nil || errors.Is(runErr, context.Canceled)
	if cleanStop {
		if err := r.finalAudit(); err != nil {
			runErr = fmt.Errorf("final audit: %w", err)
			cleanStop = false
		}
	}
	closeErr := r.close()
	if closeErr != nil && cleanStop {
		runErr = fmt.Errorf("close: %w", closeErr)
		cleanStop = false
	}
	logger.Progress(r.stats.progress(r.started, cfg.DBPath))
	if !cleanStop {
		logger.Error("FAILED: %v", runErr)
		return 1
	}
	if signalCtx.Err() != nil {
		logger.Info("clean shutdown after signal")
	} else if errors.Is(cause, context.Canceled) {
		logger.Info("clean shutdown after configured duration")
	} else {
		logger.Info("clean shutdown")
	}
	fmt.Printf("\nPASS: database and in-memory oracle match; artifacts: %s\n", cfg.RunDir)
	return 0
}

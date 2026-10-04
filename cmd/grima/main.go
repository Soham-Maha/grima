// Command grima runs the adaptive multi-layer ransomware detector.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/prateekpurohit13/grima/internal/app"
	"github.com/prateekpurohit13/grima/internal/config"
)

const version = "0.1.0"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "grima:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "", "path to a TOML configuration file")
	duration := flag.Duration("duration", 0, "stop after this long (0 means run until interrupted)")
	calibrate := flag.Bool("calibrate", false, "capture a host baseline and exit")
	recalibrate := flag.Bool("recalibrate", false, "fold a fresh window into the existing baseline and exit")
	removeDecoys := flag.Bool("remove-decoys", false, "delete the canary files recorded in the decoy manifest and exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("grima", version)
		return nil
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	options := app.Options{
		Duration:     *duration,
		Calibrate:    *calibrate,
		Recalibrate:  *recalibrate,
		RemoveDecoys: *removeDecoys,
	}
	return app.Run(ctx, cfg, options, newLogger(cfg.General.LogLevel))
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package cli builds airlock's Cobra command tree and is the CLI's only
// entry point: cmd/airlock/main.go calls Execute and does nothing else.
//
// Cobra is used for two properties: it generates shell completion for
// every command and flag it knows about (the auto-added "completion"
// subcommand), and it derives --help text straight from the command and
// flag definitions below, so help never drifts out of sync with the
// actual options. This mirrors ballast's and bilgeline's internal/cli
// packages exactly -- the suite's house cobra pattern.
//
// The command tree:
//
//	airlock daemon    run the egress-observation daemon (the container's
//	                  default command)
//	airlock validate  load and validate airlock.yml, nonzero exit on
//	                  invalid (offline: no socket, no discovery)
//	airlock version   print the build version
//	airlock status    read the daemon's state snapshot and show backend
//	                  health plus every armed container's policy status
//	airlock suggest   read the state snapshot and render one container's
//	                  observed egress as ready-to-paste allow entries
//
// status and suggest are both offline reads of a JSON file the daemon
// writes periodically (internal/daemon/state.go): there is no IPC server
// in this architecture, so neither command talks to a running daemon
// directly. See state.go's package-level DESIGN comment for the reasoning.
package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/tagwright/airlock/internal/version"
)

// cfgFile and logLevel back the root command's persistent flags. Cobra
// commands are small, long-lived singletons, so package-level vars bound
// by pflag are the idiomatic way to thread persistent flags through to
// every subcommand's RunE -- mirrors bilgeline's internal/cli exactly.
var (
	cfgFile  string
	logLevel string
)

// DefaultConfigPath is where airlock looks for its config when --config is
// not given. The file is optional: env-only operation with no file works
// too (config.Load's own contract).
const DefaultConfigPath = "/etc/airlock/airlock.yml"

// Execute builds the command tree and runs it against os.Args.
func Execute() error {
	return newRootCmd().Execute()
}

// newRootCmd builds the root "airlock" command and attaches every
// subcommand. Cobra adds its own "completion" and "help" subcommands, and
// (because Version is set) a "--version" flag, automatically.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "airlock",
		Short: "airlock observes per-container network egress and alerts on policy deviations.",
		Long: `airlock gives per-container network egress visibility for Docker and Podman,
evaluates a declared egress policy expressed in container labels (or named
groups for a whole class of containers at once), and alerts on deviations
through beacon. It observes through Inspektor Gadget's eBPF tracing and
never blocks traffic in v1.

The daemon is the normal way to run it; validate, status, and suggest are
the operator-facing commands for "check my config", "what is the daemon
seeing right now", and "help me build my first allowlist".`,
		Version:      version.Version,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	root.SetVersionTemplate("airlock {{.Version}}\n")

	root.PersistentFlags().StringVar(&cfgFile, "config", DefaultConfigPath, "path to airlock.yml")
	root.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")

	root.AddCommand(newVersionCmd())
	root.AddCommand(newDaemonCmd())
	root.AddCommand(newValidateCmd())
	root.AddCommand(newStatusCmd())
	root.AddCommand(newSuggestCmd())

	return root
}

// newVersionCmd prints the build version. The auto-generated "airlock
// --version" flag is templated to match it.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the airlock version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "airlock %s\n", version.Version)
			return nil
		},
	}
}

// newLogger builds a slog.Logger from the --log-level persistent flag,
// writing to stderr so stdout stays free for command output meant to be
// captured or piped.
func newLogger() (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(logLevel)); err != nil {
		return nil, fmt.Errorf("invalid --log-level %q: %w", logLevel, err)
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(handler), nil
}

// shortID trims a full container id to the conventional 12-char short
// form for display, mirroring bilgeline's identical helper.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

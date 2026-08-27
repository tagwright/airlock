// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/tagwright/airlock/internal/config"
	"github.com/tagwright/airlock/internal/daemon"
)

// newDaemonCmd builds "airlock daemon", the long-running service and the
// container's default command. It loads config, builds a Daemon (which
// does its own wiring: runtime, observation backend, alerter), and runs it
// until SIGINT or SIGTERM.
func newDaemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "Run the airlock egress-observation daemon",
		Long: `daemon runs airlock's long-running, event-driven service: it loads
airlock.yml, discovers containers and resolves their egress policy
(labels, named policy sets, and groups), observes egress through the
configured backend, evaluates armed containers' policies, and routes
violations through beacon -- until it receives SIGINT or SIGTERM.

This is the container's default command.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger, err := newLogger()
			if err != nil {
				return err
			}

			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}
			for _, w := range cfg.Warnings {
				logger.Warn("config warning", "message", w)
			}

			d, err := daemon.New(ctx, cfg, logger)
			if err != nil {
				return err
			}

			return d.Run(ctx)
		},
	}
}

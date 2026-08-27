// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tagwright/airlock/internal/config"
)

// newValidateCmd builds "airlock validate": load airlock.yml, run
// config.Validate, and report OK or every error. This is entirely
// offline -- no socket, no container discovery -- since airlock.yml's own
// internal consistency (policy sets, groups, defaults) is a config-load
// concern; per-container label validation is a runtime, per-container
// diagnostic (discovery.Diagnostic) surfaced by the daemon itself, not a
// batch check this command performs.
func newValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate airlock.yml",
		Long: `validate loads airlock.yml, checks it for internal consistency (policy
sets, groups, defaults, notification and telemetry config), and reports
OK or every error found. It exits nonzero on an invalid config.

Non-fatal warnings (an allow: "*" policy with no deny rules, a scope=all-only
token used without scope=all) are printed but do not fail the check.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			cfg, err := config.Load(cfgFile)
			if err != nil {
				fmt.Fprintf(out, "config: INVALID\n%v\n", err)
				return errValidationFailed
			}
			fmt.Fprintln(out, "config: OK")
			for _, w := range cfg.Warnings {
				fmt.Fprintf(out, "warning: %s\n", w)
			}
			return nil
		},
	}
}

// errValidationFailed is returned by "validate" to drive a nonzero process
// exit without Cobra reprinting a usage string (SilenceUsage is set on the
// root). Its message is terse because the specific findings were already
// printed.
var errValidationFailed = fmt.Errorf("validation failed")

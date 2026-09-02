// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Command airlock is the entrypoint for the airlock egress-visibility
// tool. This file is a thin main: it hands control to internal/cli, which
// owns the whole command tree (daemon, validate, version, status,
// suggest).
package main

import (
	"os"

	"github.com/tagwright/airlock/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}

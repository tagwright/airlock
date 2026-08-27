// SPDX-License-Identifier: GPL-3.0-or-later

// Command airlock is the entrypoint for the airlock egress-visibility tool.
//
// This is an early scaffold. There is no real functionality yet: it just
// prints a startup banner and exits.
package main

import (
	"fmt"

	"github.com/tagwright/airlock/internal/version"
)

func main() {
	fmt.Printf("airlock %s starting (scaffold, no functionality yet)\n", version.Version)
}

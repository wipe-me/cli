// Command wipeme creates, reads, and injects private one-time messages.
package main

import (
	"os"

	"github.com/wipe-me/cli/internal/cli"
)

const developmentVersion = "0.3.0-alpha.2-dev"

// GoReleaser replaces version with the exact tag using -ldflags -X.
var version = developmentVersion

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, version))
}

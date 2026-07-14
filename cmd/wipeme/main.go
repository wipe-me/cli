// Command wipeme creates private, one-time links from text and attachments.
package main

import (
	"os"

	"github.com/wipe-me/cli/internal/cli"
)

var version = "dev"

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, version))
}

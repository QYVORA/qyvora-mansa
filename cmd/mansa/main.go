// Command mansa is the QYVORA authorized wireless security assessment
// framework. Run with no arguments to enter the interactive console, or
// use the one-shot subcommands (mansa scan --sim, mansa analyze, ...).
package main

import (
	"os"

	"github.com/QYVORA/qyvora-mansa/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}

// Command mansa is QYVORA's wireless security assessment framework: authorized
// WLAN discovery, security analysis, and evidence-driven wireless security
// assessment.
package main

import (
	"os"

	"github.com/QYVORA/qyvora-mansa/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}

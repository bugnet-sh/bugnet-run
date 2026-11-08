// Command bugnet-run runs commands detached inside a sandbox and streams their output as frames
package main

import (
	"os"

	"github.com/bugnet-sh/bugnet-run/internal/runner"
)

func main() {
	os.Exit(runner.Run(os.Args[1:], os.Stdout, os.Stderr))
}

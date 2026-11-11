// Command vibecollector-config prints a collector config of the built-in
// defaults to stdout. It does not start the collector and does not read a file.
package main

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/majestrate/vibecollector/internal/config"
)

func main() {
	syscall.Umask(0o077)
	os.Exit(execute(os.Args[1:], os.Stdout, os.Stderr))
}

// execute writes the default config to stdout.
// args must be empty. A non-empty args prints usage to stderr and returns 2.
// A default, encode, or write error returns 1.
func execute(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprint(stderr, "usage: vibecollector-config\n")
		return 2
	}
	cfg, err := config.Default()
	if err != nil {
		fmt.Fprintf(stderr, "vibecollector-config: %v\n", err)
		return 1
	}
	doc, err := config.Document(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "vibecollector-config: %v\n", err)
		return 1
	}
	if _, err := io.WriteString(stdout, doc); err != nil {
		fmt.Fprintf(stderr, "vibecollector-config: %v\n", err)
		return 1
	}
	return 0
}

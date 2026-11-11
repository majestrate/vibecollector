// Command vibecollector-clients adds, replaces, lists, and removes confidential
// OAuth clients in the collector database. It does not start the collector.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"

	"vibecollector/internal/config"
	"vibecollector/internal/store"
)

func main() {
	syscall.Umask(0o077)
	os.Exit(execute(os.Args[1:], os.Stdout, os.Stderr))
}

func execute(args []string, stdout, stderr io.Writer) int {
	const usage = "usage: vibecollector-clients add|remove|list [-config path] [-db path] [-id id] [-secret secret]\n"
	if len(args) < 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd := args[0]
	switch cmd {
	case "add", "remove", "list":
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
	fs := flag.NewFlagSet("vibecollector-clients", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var configPath, dbPath, id, secret string
	fs.StringVar(&configPath, "config", "", "collector config file")
	fs.StringVar(&dbPath, "db", "", "SQLite database path")
	fs.StringVar(&id, "id", "", "client id")
	fs.StringVar(&secret, "secret", "", "client secret")
	if err := fs.Parse(args[1:]); err != nil || len(fs.Args()) != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch cmd {
	case "add":
		if id == "" || secret == "" {
			fmt.Fprint(stderr, usage)
			return 2
		}
	case "remove":
		if id == "" || secret != "" {
			fmt.Fprint(stderr, usage)
			return 2
		}
	case "list":
		if id != "" || secret != "" {
			fmt.Fprint(stderr, usage)
			return 2
		}
	}
	cfg, err := config.Load(config.Flags{ConfigPath: configPath, DB: dbPath})
	if err != nil {
		fmt.Fprintf(stderr, "vibecollector-clients: %v\n", err)
		if errors.Is(err, config.ErrUnknownField) || errors.Is(err, config.ErrBadConfig) {
			return 2
		}
		return 1
	}
	db, err := store.Open(cfg.DB)
	if err != nil {
		fmt.Fprintf(stderr, "vibecollector-clients: %v\n", err)
		return 1
	}
	defer db.Close()
	ctx := context.Background()
	switch cmd {
	case "add":
		replaced, err := db.PutOAuthClient(ctx, id, secret)
		if err != nil {
			fmt.Fprintf(stderr, "vibecollector-clients: %v\n", err)
			if errors.Is(err, store.ErrBadClient) {
				return 2
			}
			return 1
		}
		if replaced {
			fmt.Fprintf(stdout, "updated %s\n", id)
		} else {
			fmt.Fprintf(stdout, "added %s\n", id)
		}
	case "remove":
		removed, err := db.DeleteOAuthClient(ctx, id)
		if err != nil {
			fmt.Fprintf(stderr, "vibecollector-clients: %v\n", err)
			return 1
		}
		if !removed {
			fmt.Fprintf(stderr, "vibecollector-clients: no such client\n")
			return 1
		}
		fmt.Fprintf(stdout, "removed %s\n", id)
	case "list":
		rows, err := db.ListOAuthClients(ctx)
		if err != nil {
			fmt.Fprintf(stderr, "vibecollector-clients: %v\n", err)
			return 1
		}
		for _, row := range rows {
			fmt.Fprintln(stdout, row.ID)
		}
	}
	return 0
}

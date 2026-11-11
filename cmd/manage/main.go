// Command vibecollector-clients adds, replaces, lists, and removes confidential
// OAuth clients in the collector database. It does not start the collector.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/majestrate/vibecollector/internal/config"
	"github.com/majestrate/vibecollector/internal/store"
)

func main() {
	syscall.Umask(0o077)
	os.Exit(execute(os.Args[0], os.Args[1:], os.Stdout, os.Stderr))
}

func execute(exe string, args []string, stdout, stderr io.Writer) int {
	usage := fmt.Sprintf("usage: %s add|remove|list [-config path] [-db path] [-id id | -gen-id ] [-secret secret | -gen-secret]\n", exe)
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
	var genId, genSecret bool
	var configPath, dbPath, id, secret string
	fs.StringVar(&configPath, "config", "", "collector config file")
	fs.StringVar(&dbPath, "db", "", "SQLite database path")
	fs.StringVar(&id, "id", "", "client id")
	fs.StringVar(&secret, "secret", "", "client secret")
	fs.BoolVar(&genId, "gen-id", false, "generate client id")
	fs.BoolVar(&genSecret, "gen-secret", false, "generate client secret")
	if err := fs.Parse(args[1:]); err != nil || len(fs.Args()) != 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch cmd {
	case "add":
		if (id == "" && !genId) || (secret == "" && !genSecret) {
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
		fmt.Fprintf(stderr, "%s: %v\n", exe, err)
		if errors.Is(err, config.ErrUnknownField) || errors.Is(err, config.ErrBadConfig) {
			return 2
		}
		return 1
	}
	db, err := store.Open(cfg.DB)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", exe, err)
		return 1
	}
	defer db.Close()
	ctx := context.Background()
	switch cmd {
	case "add":
		if secret != "" && genSecret {
			fmt.Fprint(stdout, "%s: cannot use -gen-secret when providing -secret\n", exe)
			return 2
		}
		encoding := base64.StdEncoding
		if genSecret {
			buf := make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, buf); err != nil {
				fmt.Fprint(stderr, "rand.Reader failed: %v", err)
				return 2
			}
			secret = encoding.WithPadding(base64.NoPadding).EncodeToString(buf)
			secret = strings.Replace(secret, "+", "~", -1)
			secret = strings.Replace(secret, "/", "-", -1)
		}
		if genId {
			buf := make([]byte, 8)
			if _, err := io.ReadFull(rand.Reader, buf); err != nil {
				fmt.Fprint(stderr, "rand.Reader failed: %v", err)
				return 2
			}
			id = hex.EncodeToString(buf)
		}

		replaced, err := db.PutOAuthClient(ctx, id, secret)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", exe, err)
			if errors.Is(err, store.ErrBadClient) {
				return 2
			}
			return 1
		}
		if replaced {
			fmt.Fprintf(stdout, "[updated] clientId: %s\n", id)
		} else if genId {
			fmt.Fprintf(stdout, "[generated] clientId: %s\n", id)
		} else {
			fmt.Fprintf(stdout, "[created] clientId: %s\n", id)
		}
		if genSecret {
			fmt.Fprintf(stdout, "[generated] clientSecret: %s\n", secret)
		}
	case "remove":
		removed, err := db.DeleteOAuthClient(ctx, id)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", exe, err)
			return 1
		}
		if !removed {
			fmt.Fprintf(stderr, "%s: no such client\n", exe)
			return 1
		}
		fmt.Fprintf(stdout, "removed %s\n", id)
	case "list":
		rows, err := db.ListOAuthClients(ctx)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", exe, err)
			return 1
		}
		for _, row := range rows {
			fmt.Fprintln(stdout, row.ID)
		}
	}
	return 0
}

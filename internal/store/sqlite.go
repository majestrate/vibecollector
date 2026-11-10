// Package store opens the SQLite database and applies schema migrations.
package store

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"vibecollector/internal/config"

	_ "modernc.org/libc" // Keep the sqlite v1.62.0 libc pin in the main module.
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// DB is the opened pool. Callers outside store use Writer, Sweeper, and Query.
// They do not call Exec on DB.
type DB struct {
	pool *sql.DB
	// shedRaw is set by Sweeper when the database volume is under 5 GiB free.
	// Writer skips raw flow inserts while it is set. Rollups still update.
	shedRaw atomic.Bool
}

// Open opens or creates the SQLite database at cfg.Path, runs migrations, and
// sets the pool to 4 connections. cfg.BusyTimeout is the lock wait placed on
// every connection as busy_timeout, in milliseconds. Every connection uses
// the DSN pragmas: journal_mode=WAL, that busy_timeout, synchronous=NORMAL,
// foreign_keys=ON, temp_store=MEMORY, cache_size=-64000, and
// wal_autocheckpoint=1000. A one-shot Exec after sql.Open would set those on
// only one connection of the pool. Open does not bind a socket.
//
// The result is a pool with migrations applied. A migration error is returned
// and that version is rolled back; the caller exits without serving. Any
// other error means cfg.Path is empty, the file could not be opened, or a
// migration file could not be read.
func Open(cfg config.DB) (*DB, error) {
	if cfg.Path == "" {
		return nil, errors.New("store: cfg.Path is empty")
	}
	migs, err := loadMigrations()
	if err != nil {
		return nil, err
	}
	pool, err := sql.Open("sqlite", dsn(cfg.Path, cfg.BusyTimeout))
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", cfg.Path, err)
	}
	pool.SetMaxOpenConns(4)
	if err := applyMigrations(pool, migs); err != nil {
		pool.Close()
		return nil, err
	}
	return &DB{pool: pool}, nil
}

// Checkpoint runs wal_checkpoint(TRUNCATE) on the open pool. main calls it
// after the drain on shutdown. A nil error means SQLite accepted the
// checkpoint. A non-nil error is the SQLite error.
func (db *DB) Checkpoint() error {
	var busy, logFrames, checkpointed int
	err := db.pool.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed)
	return err
}

// dsn puts pragmas in the URI so modernc.org/sqlite applies them on each new
// connection. A later Exec would hit only one connection of the pool.
func dsn(filePath string, busy time.Duration) string {
	return "file:" + uriPath(filePath) +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(" + strconv.FormatInt(busy.Milliseconds(), 10) + ")" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=temp_store(MEMORY)" +
		"&_pragma=cache_size(-64000)" +
		"&_pragma=wal_autocheckpoint(1000)"
}

// uriPath percent-encodes characters that would end the SQLite URI path.
func uriPath(filePath string) string {
	return strings.NewReplacer(
		"%", "%25",
		"?", "%3F",
		"#", "%23",
		" ", "%20",
	).Replace(filePath)
}

// migration is one embedded schema change. version is the NNN prefix.
type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	names, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return nil, fmt.Errorf("store: list migrations: %w", err)
	}
	out := make([]migration, 0, len(names))
	seen := make(map[int]string, len(names))
	for _, name := range names {
		version, err := migrationVersion(name)
		if err != nil {
			return nil, err
		}
		if prev, ok := seen[version]; ok {
			return nil, fmt.Errorf("store: migration version %d in %s and %s", version, prev, name)
		}
		seen[version] = name
		body, err := migrationFS.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("store: read %s: %w", name, err)
		}
		out = append(out, migration{
			version: version,
			name:    path.Base(name),
			sql:     string(body),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

func migrationVersion(name string) (int, error) {
	base := path.Base(name)
	stem := strings.TrimSuffix(base, ".sql")
	if stem == base {
		return 0, fmt.Errorf("store: migration %s: want NNN_name.sql", base)
	}
	num, rest, ok := strings.Cut(stem, "_")
	if !ok || num == "" || rest == "" {
		return 0, fmt.Errorf("store: migration %s: want NNN_name.sql", base)
	}
	version, err := strconv.Atoi(num)
	if err != nil || version < 1 {
		return 0, fmt.Errorf("store: migration %s: bad version", base)
	}
	return version, nil
}

// applyMigrations runs each migration that schema_migrations does not yet
// record. A version already present is left untouched.
func applyMigrations(pool *sql.DB, migs []migration) error {
	done, err := appliedVersions(pool)
	if err != nil {
		return err
	}
	for _, m := range migs {
		if done[m.version] {
			continue
		}
		if err := applyOne(pool, m); err != nil {
			return err
		}
	}
	return nil
}

func appliedVersions(pool *sql.DB) (map[int]bool, error) {
	var n int
	if err := pool.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`).Scan(&n); err != nil {
		return nil, fmt.Errorf("store: read schema_migrations: %w", err)
	}
	done := map[int]bool{}
	if n == 0 {
		return done, nil
	}
	rows, err := pool.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("store: read schema_migrations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("store: read schema_migrations: %w", err)
		}
		done[version] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read schema_migrations: %w", err)
	}
	return done, nil
}

// applyOne runs one migration in a single transaction. user_version is updated
// there so a failure rolls the version back with the schema.
func applyOne(pool *sql.DB, m migration) error {
	tx, err := pool.Begin()
	if err != nil {
		return fmt.Errorf("store: migration %s: begin: %w", m.name, err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(m.sql); err != nil {
		return fmt.Errorf("store: migration %s: %w", m.name, err)
	}
	appliedAt := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.Exec(
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
		m.version, m.name, appliedAt,
	); err != nil {
		return fmt.Errorf("store: migration %s: record version: %w", m.name, err)
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
		return fmt.Errorf("store: migration %s: user_version: %w", m.name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: migration %s: commit: %w", m.name, err)
	}
	return nil
}

package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vibecollector/internal/config"
)

func TestOpenEmptyFileVersion1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := Open(config.DB{Path: path, BusyTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.pool.Close() })

	if got := db.pool.Stats().MaxOpenConnections; got != 4 {
		t.Fatalf("MaxOpenConnections = %d, want 4", got)
	}
	if v := userVersion(t, db); v != 1 {
		t.Fatalf("user_version = %d, want 1", v)
	}
	var name string
	if err := db.pool.QueryRow(`SELECT name FROM schema_migrations WHERE version = 1`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "001_init.sql" {
		t.Fatalf("migration name %q", name)
	}
	var n int
	if err := db.pool.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("schema_migrations rows = %d, want 1", n)
	}

	for _, table := range []string{
		"schema_migrations",
		"flows",
		"exporters",
		"traffic_1m",
		"asn_1m",
		"asn_names",
		"talker_1m",
		"rep_1m",
		"geo_country_5m",
		"geo_path_5m",
		"geo_path_other_5m",
	} {
		if !objectExists(t, db, "table", table) {
			t.Errorf("missing table %s", table)
		}
	}
	for _, index := range []string{
		"idx_flows_start",
		"idx_flows_src",
		"idx_flows_dst",
		"idx_flows_exporter",
	} {
		if !objectExists(t, db, "index", index) {
			t.Errorf("missing index %s", index)
		}
	}
	assertColumns(t, db, "flows", "flow_direction", "octet_semantics", "clock_clamped")
	assertColumns(t, db, "geo_path_5m", "src_region", "dst_region")

	if err := db.Checkpoint(); err != nil {
		t.Fatal(err)
	}
}

func TestReopenDoesNotReapply(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reopen.db")
	cfg := config.DB{Path: path, BusyTimeout: 5 * time.Second}
	db, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var appliedAt string
	if err := db.pool.QueryRow(`SELECT applied_at FROM schema_migrations WHERE version = 1`).Scan(&appliedAt); err != nil {
		t.Fatal(err)
	}
	if err := db.pool.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.pool.Close() })

	var again string
	if err := db.pool.QueryRow(`SELECT applied_at FROM schema_migrations WHERE version = 1`).Scan(&again); err != nil {
		t.Fatal(err)
	}
	if again != appliedAt {
		t.Fatalf("migration reapplied: applied_at %q then %q", appliedAt, again)
	}
	var n int
	if err := db.pool.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("schema_migrations rows = %d, want 1", n)
	}
	if v := userVersion(t, db); v != 1 {
		t.Fatalf("user_version = %d, want 1", v)
	}
}

func TestFailedMigrationLeavesPriorVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fail.db")
	cfg := config.DB{Path: path, BusyTimeout: 5 * time.Second}
	db, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// In memory, not a 002_*.sql file. A broken migration committed to the
	// tree would make the next open refuse to start.
	err = applyMigrations(db.pool, []migration{{
		version: 2,
		name:    "002_bad.sql",
		sql:     "CREATE TABLE should_roll_back (id INTEGER PRIMARY KEY);\nINSERT INTO should_roll_back (id) VALUES (1);\nNOT VALID SQL;\n",
	}})
	if err == nil {
		t.Fatal("expected migration error")
	}
	if v := userVersion(t, db); v != 1 {
		t.Fatalf("user_version = %d, want 1", v)
	}
	var n int
	if err := db.pool.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("schema_migrations rows = %d, want 1", n)
	}
	var version2 int
	if err := db.pool.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version = 2`).Scan(&version2); err != nil {
		t.Fatal(err)
	}
	if version2 != 0 {
		t.Fatalf("version 2 recorded %d times", version2)
	}
	if objectExists(t, db, "table", "should_roll_back") {
		t.Fatal("failed migration left should_roll_back")
	}
	if err := db.pool.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.pool.Close() })
	if v := userVersion(t, db); v != 1 {
		t.Fatalf("user_version after reopen = %d, want 1", v)
	}
	if objectExists(t, db, "table", "should_roll_back") {
		t.Fatal("rolled-back table reappeared")
	}
}

func TestSecondPooledConnectionPragmas(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pragma.db")
	const busy = 2500 * time.Millisecond
	db, err := Open(config.DB{Path: path, BusyTimeout: busy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.pool.Close() })

	ctx := context.Background()
	first, err := db.pool.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { first.Close() })
	// Hold the first connection so the next checkout is a different one.
	second, err := db.pool.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { second.Close() })

	var syncMode, busyMS int
	if err := second.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&syncMode); err != nil {
		t.Fatal(err)
	}
	if syncMode != 1 {
		t.Fatalf("synchronous = %d, want 1 (NORMAL)", syncMode)
	}
	if err := second.QueryRowContext(ctx, `PRAGMA busy_timeout`).Scan(&busyMS); err != nil {
		t.Fatal(err)
	}
	if busyMS == 0 {
		t.Fatal("busy_timeout is 0")
	}
	if busyMS != int(busy.Milliseconds()) {
		t.Fatalf("busy_timeout = %d, want %d", busyMS, busy.Milliseconds())
	}
}

func userVersion(t *testing.T, db *DB) int {
	t.Helper()
	var v int
	if err := db.pool.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func objectExists(t *testing.T, db *DB, kind, name string) bool {
	t.Helper()
	var n int
	err := db.pool.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type = ? AND name = ?`,
		kind, name,
	).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func assertColumns(t *testing.T, db *DB, table string, cols ...string) {
	t.Helper()
	switch table {
	case "flows", "geo_path_5m":
	default:
		t.Fatalf("unexpected table %s", table)
	}
	for _, col := range cols {
		var n int
		err := db.pool.QueryRow(
			`SELECT count(*) FROM pragma_table_info('`+table+`') WHERE name = ?`,
			col,
		).Scan(&n)
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("%s.%s missing", table, col)
		}
	}
}

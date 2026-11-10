package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/tools/go/packages"

	"vibecollector/internal/config"
)

func TestNewQueryNil(t *testing.T) {
	q, err := NewQuery(nil)
	if q != nil || !errors.Is(err, ErrNilDep) {
		t.Fatalf("got %v %v", q, err)
	}
}

func TestQueryCanceled(t *testing.T) {
	db := openQueryDB(t, time.Hour)
	q, err := NewQuery(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := Filter{Start: time.Now().Add(-time.Minute), End: time.Now().Add(time.Minute), TZ: "UTC"}
	if _, err := q.Flows(ctx, f); !errors.Is(err, ErrQueryTimeout) {
		t.Fatal(err)
	}
	if _, err := q.Timeseries(ctx, f); !errors.Is(err, ErrQueryTimeout) {
		t.Fatal(err)
	}
	if _, err := q.Talkers(ctx, f); !errors.Is(err, ErrQueryTimeout) {
		t.Fatal(err)
	}
	if _, err := q.ASNs(ctx, f); !errors.Is(err, ErrQueryTimeout) {
		t.Fatal(err)
	}
	if _, err := q.Reputation(ctx, f); !errors.Is(err, ErrQueryTimeout) {
		t.Fatal(err)
	}
	if _, err := q.Geo(ctx, f); !errors.Is(err, ErrQueryTimeout) {
		t.Fatal(err)
	}
	if _, err := q.Exporters(ctx); !errors.Is(err, ErrQueryTimeout) {
		t.Fatal(err)
	}
}

func TestFilterOutsideRaw(t *testing.T) {
	db := openQueryDB(t, 6*time.Hour)
	q, err := NewQuery(db)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(443)
	f := Filter{
		Start: time.Now().UTC().Add(-48 * time.Hour),
		End:   time.Now().UTC().Add(-47 * time.Hour),
		TZ:    "UTC",
		Port:  &port,
	}
	_, err = q.Geo(context.Background(), f)
	var fe *FilterError
	if !errors.As(err, &fe) || fe.Error() != "filter_outside_raw" || fe.RawAvailableFrom.IsZero() {
		t.Fatal(err)
	}
	page, err := q.Flows(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if !page.Truncated || len(page.Flows) != 0 || page.RawAvailableFrom.IsZero() {
		t.Fatalf("%+v", page)
	}
}

func TestStoreDoesNotImportNetHTTP(t *testing.T) {
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedImports, Dir: moduleRoot(t)}
	pkgs, err := packages.Load(cfg, "vibecollector/internal/store")
	if err != nil {
		t.Fatal(err)
	}
	var saw bool
	for _, p := range pkgs {
		if p.PkgPath != "vibecollector/internal/store" {
			continue
		}
		saw = true
		for path := range p.Imports {
			if path == "net/http" || strings.HasPrefix(path, "net/http/") {
				t.Fatalf("store imports %s", path)
			}
		}
	}
	if !saw {
		t.Fatal("package not loaded")
	}
}

func openQueryDB(t *testing.T, raw time.Duration) *DB {
	t.Helper()
	db, err := Open(config.DB{
		Path:         filepath.Join(t.TempDir(), "t.db"),
		BusyTimeout:  5 * time.Second,
		RawRetention: raw,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.pool.Close() })
	return db
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

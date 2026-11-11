package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"vibecollector/internal/config"
)

func TestOAuthClients(t *testing.T) {
	db := openClientDB(t)
	ctx := context.Background()
	if _, err := db.PutOAuthClient(ctx, "alpha", "one"); err != nil {
		t.Fatal(err)
	}
	replaced, err := db.PutOAuthClient(ctx, "beta", "two")
	if err != nil || replaced {
		t.Fatal(replaced, err)
	}
	ok, err := db.OAuthSecretOK(ctx, "alpha", "one")
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	ok, err = db.OAuthSecretOK(ctx, "alpha", "two")
	if err != nil || ok {
		t.Fatal(ok, err)
	}
	ok, err = db.OAuthSecretOK(ctx, "missing", "one")
	if err != nil || ok {
		t.Fatal(ok, err)
	}
	ok, err = db.OAuthSecretOK(ctx, "", "one")
	if err != nil || ok {
		t.Fatal(ok, err)
	}
	exists, err := db.OAuthClientExists(ctx, "alpha")
	if err != nil || !exists {
		t.Fatal(exists, err)
	}
	exists, err = db.OAuthClientExists(ctx, "missing")
	if err != nil || exists {
		t.Fatal(exists, err)
	}
	exists, err = db.OAuthClientExists(ctx, "bad id")
	if err != nil || exists {
		t.Fatal(exists, err)
	}
	var hash string
	if err := db.pool.QueryRow(`SELECT secret_hash FROM oauth_client WHERE client_id = 'alpha'`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash == "one" || hash == "" {
		t.Fatal(hash)
	}
	replaced, err = db.PutOAuthClient(ctx, "alpha", "rotated")
	if err != nil || !replaced {
		t.Fatal(replaced, err)
	}
	ok, err = db.OAuthSecretOK(ctx, "alpha", "one")
	if err != nil || ok {
		t.Fatal("old secret still matches", ok, err)
	}
	ok, err = db.OAuthSecretOK(ctx, "alpha", "rotated")
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	listed, err := db.ListOAuthClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || listed[0].ID != "alpha" || listed[1].ID != "beta" || listed[0].Created.IsZero() {
		t.Fatal(listed)
	}
	removed, err := db.DeleteOAuthClient(ctx, "alpha")
	if err != nil || !removed {
		t.Fatal(removed, err)
	}
	removed, err = db.DeleteOAuthClient(ctx, "alpha")
	if err != nil || removed {
		t.Fatal(removed, err)
	}
	ok, err = db.OAuthSecretOK(ctx, "alpha", "rotated")
	if err != nil || ok {
		t.Fatal(ok, err)
	}
	for _, id := range []string{"", "has space", "a/b", stringsRepeat(129)} {
		if _, err := db.PutOAuthClient(ctx, id, "secret"); !errors.Is(err, ErrBadClient) {
			t.Fatalf("id %q err %v", id, err)
		}
	}
	if _, err := db.PutOAuthClient(ctx, "ok", ""); !errors.Is(err, ErrBadClient) {
		t.Fatal(err)
	}
	if _, err := db.PutOAuthClient(ctx, "ok", "bad\nsecret"); !errors.Is(err, ErrBadClient) {
		t.Fatal(err)
	}
}

func openClientDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(config.DB{Path: filepath.Join(t.TempDir(), "c.db"), BusyTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.pool.Close() })
	return db
}

func stringsRepeat(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

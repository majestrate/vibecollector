package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrBadClient means the client id or secret is empty or outside the allowed form.
// PutOAuthClient returns it and writes nothing.
var ErrBadClient = errors.New("bad_client")

// OAuthClient is one confidential client registered in the database.
// ID is the client_id. Created is when the row was first inserted.
// The secret is not part of this value.
type OAuthClient struct {
	ID      string
	Created time.Time
}

// PutOAuthClient stores id and the SHA-256 of secret.
// An existing id replaces the hash and keeps Created. replaced is true in that case.
// The raw secret is not written. An empty id, an id outside [A-Za-z0-9._~-] or
// longer than 128 bytes, or a secret that is empty, longer than 256 bytes, or
// contains a NUL or newline, returns ErrBadClient. A nil db returns ErrNilDep.
// Any other error is the database error.
func (db *DB) PutOAuthClient(ctx context.Context, id, secret string) (replaced bool, err error) {
	if db == nil {
		return false, fmt.Errorf("%w: db", ErrNilDep)
	}
	if !validClientID(id) || !validSecret(secret) {
		return false, fmt.Errorf("%w", ErrBadClient)
	}
	var n int
	err = db.pool.QueryRowContext(ctx, `SELECT count(*) FROM oauth_client WHERE client_id = ?`, id).Scan(&n)
	if err != nil {
		return false, err
	}
	_, err = db.pool.ExecContext(ctx, `
		INSERT INTO oauth_client (client_id, secret_hash, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT(client_id) DO UPDATE SET secret_hash = excluded.secret_hash`,
		id, secretHash(secret), time.Now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// DeleteOAuthClient removes id. removed is false when no row had that id.
// A nil db returns ErrNilDep. Any other error is the database error.
func (db *DB) DeleteOAuthClient(ctx context.Context, id string) (removed bool, err error) {
	if db == nil {
		return false, fmt.Errorf("%w: db", ErrNilDep)
	}
	res, err := db.pool.ExecContext(ctx, `DELETE FROM oauth_client WHERE client_id = ?`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// ListOAuthClients returns every confidential client, ordered by id.
// The result has no secret and no hash. A nil db returns ErrNilDep.
// Any other error is the database error.
func (db *DB) ListOAuthClients(ctx context.Context) ([]OAuthClient, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: db", ErrNilDep)
	}
	rows, err := db.pool.QueryContext(ctx, `SELECT client_id, created_at FROM oauth_client ORDER BY client_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OAuthClient
	for rows.Next() {
		var c OAuthClient
		var created string
		if err := rows.Scan(&c.ID, &created); err != nil {
			return nil, err
		}
		c.Created, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, fmt.Errorf("store: oauth client %s created_at: %w", c.ID, err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// OAuthClientExists reports whether id is registered.
// It does not read the secret. An id outside the allowed form is false.
// A nil db returns ErrNilDep. Any other error is the database error.
func (db *DB) OAuthClientExists(ctx context.Context, id string) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("%w: db", ErrNilDep)
	}
	if !validClientID(id) {
		return false, nil
	}
	var n int
	err := db.pool.QueryRowContext(ctx, `SELECT count(*) FROM oauth_client WHERE client_id = ?`, id).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// OAuthSecretOK reports whether id and secret match a stored pair.
// A missing id and a wrong secret are both false. An empty id or secret is false.
// A nil db returns ErrNilDep. Any other error is the database error.
func (db *DB) OAuthSecretOK(ctx context.Context, id, secret string) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("%w: db", ErrNilDep)
	}
	got := secretHash(secret)
	if id == "" || secret == "" {
		return false, nil
	}
	var stored string
	err := db.pool.QueryRowContext(ctx, `SELECT secret_hash FROM oauth_client WHERE client_id = ?`, id).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		subtle.ConstantTimeCompare([]byte(got), []byte(strings.Repeat("0", len(got))))
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(stored) != len(got) {
		return false, nil
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(got)) == 1, nil
}

func secretHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func validClientID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '~' || c == '-':
		default:
			return false
		}
	}
	return true
}

func validSecret(secret string) bool {
	if len(secret) < 1 || len(secret) > 256 {
		return false
	}
	return !strings.ContainsAny(secret, "\x00\r\n")
}

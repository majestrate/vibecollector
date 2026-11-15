package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/majestrate/vibecollector/internal/netdb"
)

const netTokenMax = 64

// ErrNetEntry means a protocol or service override failed validation.
// Nothing was written. The database does not store a filesystem path.
var ErrNetEntry = errors.New("bad net entry")

// ErrNetExists means this client already has that protocol name, or that
// service name and protocol. The existing row is unchanged.
var ErrNetExists = errors.New("net entry exists")

// ErrNetAbsent means this client has no such override row.
var ErrNetAbsent = errors.New("net entry not found")

// CreateClientProtocol inserts one additive protocol for clientID.
// p.Name, p.Number, and p.Aliases are the row. A duplicate name for this
// client returns ErrNetExists and writes nothing.
// A name, alias, or number that is not a single protocols-file token returns
// ErrNetEntry. clientID must already be an oauth client; a missing client
// returns ErrBadClient. A nil db returns ErrNilDep.
func (db *DB) CreateClientProtocol(ctx context.Context, clientID string, p netdb.Protocol) error {
	if err := db.readyClient(ctx, clientID); err != nil {
		return err
	}
	if err := validProtocol(p); err != nil {
		return err
	}
	aliases, err := encodeAliases(p.Aliases)
	if err != nil {
		return err
	}
	return db.insertNet(ctx, `
		INSERT INTO client_protocol (client_id, name, number, aliases)
		VALUES (?, ?, ?, ?)`,
		ErrNetExists, clientID, p.Name, p.Number, aliases)
}

// UpdateClientProtocol replaces the number and aliases of an existing row.
// clientID and p.Name select the row. p.Number and p.Aliases are the new
// values. A missing row returns ErrNetAbsent. Validation matches
// CreateClientProtocol. A nil db returns ErrNilDep.
func (db *DB) UpdateClientProtocol(ctx context.Context, clientID string, p netdb.Protocol) error {
	if err := db.readyClient(ctx, clientID); err != nil {
		return err
	}
	if err := validProtocol(p); err != nil {
		return err
	}
	aliases, err := encodeAliases(p.Aliases)
	if err != nil {
		return err
	}
	res, err := db.pool.ExecContext(ctx, `
		UPDATE client_protocol SET number = ?, aliases = ?
		WHERE client_id = ? AND name = ?`,
		p.Number, aliases, clientID, p.Name)
	if err != nil {
		return err
	}
	return rowsAffected(res, ErrNetAbsent)
}

// DeleteClientProtocol removes one protocol override.
// clientID and name select the row. A missing row returns ErrNetAbsent.
// Other clients' rows are left in place. A nil db returns ErrNilDep.
func (db *DB) DeleteClientProtocol(ctx context.Context, clientID, name string) error {
	if db == nil {
		return fmt.Errorf("%w: db", ErrNilDep)
	}
	res, err := db.pool.ExecContext(ctx, `
		DELETE FROM client_protocol WHERE client_id = ? AND name = ?`, clientID, name)
	if err != nil {
		return err
	}
	return rowsAffected(res, ErrNetAbsent)
}

// GetClientProtocol returns one protocol override owned by clientID.
// name is the official name. A missing row returns ErrNetAbsent.
// The Aliases slice is a copy. A nil db returns ErrNilDep.
func (db *DB) GetClientProtocol(ctx context.Context, clientID, name string) (netdb.Protocol, error) {
	if db == nil {
		return netdb.Protocol{}, fmt.Errorf("%w: db", ErrNilDep)
	}
	var number int
	var aliases string
	err := db.pool.QueryRowContext(ctx, `
		SELECT number, aliases FROM client_protocol
		WHERE client_id = ? AND name = ?`, clientID, name).Scan(&number, &aliases)
	if errors.Is(err, sql.ErrNoRows) {
		return netdb.Protocol{}, ErrNetAbsent
	}
	if err != nil {
		return netdb.Protocol{}, err
	}
	list, err := decodeAliases(aliases)
	if err != nil {
		return netdb.Protocol{}, err
	}
	return netdb.Protocol{Name: name, Number: number, Aliases: list}, nil
}

// ListClientProtocols returns this client's protocol overrides, ordered by name.
// The result is empty when the client has none. It does not include another
// client's rows or the system protocols file. A nil db returns ErrNilDep.
func (db *DB) ListClientProtocols(ctx context.Context, clientID string) ([]netdb.Protocol, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: db", ErrNilDep)
	}
	rows, err := db.pool.QueryContext(ctx, `
		SELECT name, number, aliases FROM client_protocol
		WHERE client_id = ? ORDER BY name`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []netdb.Protocol{}
	for rows.Next() {
		var p netdb.Protocol
		var aliases string
		if err := rows.Scan(&p.Name, &p.Number, &aliases); err != nil {
			return nil, err
		}
		p.Aliases, err = decodeAliases(aliases)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateClientService inserts one additive service for clientID.
// svc.Name, svc.Port, svc.Protocol, and svc.Aliases are the row.
// A duplicate name and protocol for this client returns ErrNetExists.
// A token or port that cannot be written as one services-file field returns
// ErrNetEntry. A missing oauth client returns ErrBadClient.
// A nil db returns ErrNilDep.
func (db *DB) CreateClientService(ctx context.Context, clientID string, svc netdb.Service) error {
	if err := db.readyClient(ctx, clientID); err != nil {
		return err
	}
	if err := validService(svc); err != nil {
		return err
	}
	aliases, err := encodeAliases(svc.Aliases)
	if err != nil {
		return err
	}
	return db.insertNet(ctx, `
		INSERT INTO client_service (client_id, name, port, protocol, aliases)
		VALUES (?, ?, ?, ?, ?)`,
		ErrNetExists, clientID, svc.Name, svc.Port, svc.Protocol, aliases)
}

// UpdateClientService replaces the port and aliases of an existing row.
// clientID, svc.Name, and svc.Protocol select the row. svc.Port and
// svc.Aliases are the new values. A missing row returns ErrNetAbsent.
// A nil db returns ErrNilDep.
func (db *DB) UpdateClientService(ctx context.Context, clientID string, svc netdb.Service) error {
	if err := db.readyClient(ctx, clientID); err != nil {
		return err
	}
	if err := validService(svc); err != nil {
		return err
	}
	aliases, err := encodeAliases(svc.Aliases)
	if err != nil {
		return err
	}
	res, err := db.pool.ExecContext(ctx, `
		UPDATE client_service SET port = ?, aliases = ?
		WHERE client_id = ? AND name = ? AND protocol = ?`,
		svc.Port, aliases, clientID, svc.Name, svc.Protocol)
	if err != nil {
		return err
	}
	return rowsAffected(res, ErrNetAbsent)
}

// DeleteClientService removes one service override.
// clientID, name, and protocol select the row. A missing row returns
// ErrNetAbsent. A nil db returns ErrNilDep.
func (db *DB) DeleteClientService(ctx context.Context, clientID, name, protocol string) error {
	if db == nil {
		return fmt.Errorf("%w: db", ErrNilDep)
	}
	res, err := db.pool.ExecContext(ctx, `
		DELETE FROM client_service
		WHERE client_id = ? AND name = ? AND protocol = ?`, clientID, name, protocol)
	if err != nil {
		return err
	}
	return rowsAffected(res, ErrNetAbsent)
}

// GetClientService returns one service override owned by clientID.
// name and protocol select the row. A missing row returns ErrNetAbsent.
// A nil db returns ErrNilDep.
func (db *DB) GetClientService(ctx context.Context, clientID, name, protocol string) (netdb.Service, error) {
	if db == nil {
		return netdb.Service{}, fmt.Errorf("%w: db", ErrNilDep)
	}
	var port int
	var aliases string
	err := db.pool.QueryRowContext(ctx, `
		SELECT port, aliases FROM client_service
		WHERE client_id = ? AND name = ? AND protocol = ?`,
		clientID, name, protocol).Scan(&port, &aliases)
	if errors.Is(err, sql.ErrNoRows) {
		return netdb.Service{}, ErrNetAbsent
	}
	if err != nil {
		return netdb.Service{}, err
	}
	list, err := decodeAliases(aliases)
	if err != nil {
		return netdb.Service{}, err
	}
	return netdb.Service{Name: name, Port: port, Protocol: protocol, Aliases: list}, nil
}

// ListClientServices returns this client's service overrides, ordered by
// name and then protocol. The result is empty when the client has none.
// A nil db returns ErrNilDep.
func (db *DB) ListClientServices(ctx context.Context, clientID string) ([]netdb.Service, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: db", ErrNilDep)
	}
	rows, err := db.pool.QueryContext(ctx, `
		SELECT name, port, protocol, aliases FROM client_service
		WHERE client_id = ? ORDER BY name, protocol`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []netdb.Service{}
	for rows.Next() {
		var svc netdb.Service
		var aliases string
		if err := rows.Scan(&svc.Name, &svc.Port, &svc.Protocol, &aliases); err != nil {
			return nil, err
		}
		svc.Aliases, err = decodeAliases(aliases)
		if err != nil {
			return nil, err
		}
		out = append(out, svc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (db *DB) readyClient(ctx context.Context, clientID string) error {
	if db == nil {
		return fmt.Errorf("%w: db", ErrNilDep)
	}
	ok, err := db.OAuthClientExists(ctx, clientID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w", ErrBadClient)
	}
	return nil
}

func (db *DB) insertNet(ctx context.Context, query string, conflict error, args ...any) error {
	_, err := db.pool.ExecContext(ctx, query, args...)
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return conflict
	}
	return err
}

func rowsAffected(res sql.Result, absent error) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return absent
	}
	return nil
}

func validProtocol(p netdb.Protocol) error {
	if err := validNetToken(p.Name); err != nil {
		return err
	}
	if p.Number < 0 || p.Number > 255 {
		return fmt.Errorf("%w: number", ErrNetEntry)
	}
	return validAliasList(p.Name, p.Aliases)
}

func validService(svc netdb.Service) error {
	if err := validNetToken(svc.Name); err != nil {
		return err
	}
	if err := validNetToken(svc.Protocol); err != nil {
		return err
	}
	if svc.Port < 0 || svc.Port > 65535 {
		return fmt.Errorf("%w: port", ErrNetEntry)
	}
	return validAliasList(svc.Name, svc.Aliases)
}

func validAliasList(name string, aliases []string) error {
	seen := map[string]bool{name: true}
	for _, alias := range aliases {
		if err := validNetToken(alias); err != nil {
			return err
		}
		if seen[alias] {
			return fmt.Errorf("%w: alias", ErrNetEntry)
		}
		seen[alias] = true
	}
	return nil
}

// validNetToken accepts one field of a protocols or services file.
// A slash, backslash, space, comment mark, or dot-dot path is rejected
// so a row cannot name a file.
func validNetToken(s string) error {
	if s == "" || s == "." || s == ".." || utf8.RuneCountInString(s) > netTokenMax {
		return fmt.Errorf("%w: token", ErrNetEntry)
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '+' || r == '.':
		default:
			return fmt.Errorf("%w: token", ErrNetEntry)
		}
	}
	return nil
}

func encodeAliases(aliases []string) (string, error) {
	if aliases == nil {
		aliases = []string{}
	}
	b, err := json.Marshal(aliases)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeAliases(raw string) ([]string, error) {
	var aliases []string
	if err := json.Unmarshal([]byte(raw), &aliases); err != nil {
		return nil, err
	}
	if aliases == nil {
		aliases = []string{}
	}
	return aliases, nil
}

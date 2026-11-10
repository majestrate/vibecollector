package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"time"
)

// accessRec is one opaque bearer. family is empty for client-credentials tokens.
// exp is the instant the bearer stops being accepted.
type accessRec struct {
	exp    time.Time
	family string
}

// refreshRec is one opaque refresh token. successor is the hash key of the
// replacement. A non-empty successor means this token was already rotated.
// Presenting it again revokes the family.
type refreshRec struct {
	exp       time.Time
	clientID  string
	family    string
	successor string
}

// tokenResult is a minted pair or an OAuth error. status 200 carries the tokens.
// refresh is empty for the client-credentials grant.
type tokenResult struct {
	access  string
	refresh string
	secs    int
	status  int
	code    string
}

func (s *Server) accessTTL() time.Duration {
	if s.oauth.TokenTTL <= 0 {
		return time.Hour
	}
	return s.oauth.TokenTTL
}

func (s *Server) refreshTTL() time.Duration {
	if s.oauth.RefreshTTL <= 0 {
		return 24 * time.Hour
	}
	return s.oauth.RefreshTTL
}

func (s *Server) validToken(tok string) bool {
	sum := sha256.Sum256([]byte(tok))
	key := hex.EncodeToString(sum[:])
	s.mu.Lock()
	rec, ok := s.access[key]
	s.mu.Unlock()
	stored := sum
	if !ok {
		stored = sha256.Sum256(nil)
	}
	match := subtle.ConstantTimeCompare(sum[:], stored[:]) == 1
	if !ok || !match || !time.Now().Before(rec.exp) {
		return false
	}
	return true
}

// issuePair mints an access token and a refresh token for a new family.
// clientID is the public client the refresh token is bound to.
// The refresh token is returned once. The caller writes it on the token response.
// A random-read failure returns an error and stores nothing.
func (s *Server) issuePair(clientID string) tokenResult {
	family, err := randomID()
	if err != nil {
		return tokenResult{status: http.StatusInternalServerError, code: "server_error"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.sweepLocked(now)
	access, secs, aerr := s.mintAccessLocked(now, family)
	if aerr != nil {
		return tokenResult{status: http.StatusInternalServerError, code: "server_error"}
	}
	refresh, _, rerr := s.mintRefreshLocked(now, family, clientID)
	if rerr != nil {
		delete(s.access, access.key)
		return tokenResult{status: http.StatusInternalServerError, code: "server_error"}
	}
	return tokenResult{access: access.raw, refresh: refresh.raw, secs: secs, status: http.StatusOK}
}

// issueAccess mints an opaque access token with no refresh token.
// This is the client-credentials grant. RFC 6749 says that grant should not
// receive a refresh token.
func (s *Server) issueAccess() tokenResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.sweepLocked(now)
	access, secs, err := s.mintAccessLocked(now, "")
	if err != nil {
		return tokenResult{status: http.StatusInternalServerError, code: "server_error"}
	}
	return tokenResult{access: access.raw, secs: secs, status: http.StatusOK}
}

// redeemRefresh rotates a refresh token. raw is the opaque value from the client.
// clientID must be the client the token was issued to.
// A spent token revokes that family, including the replacement and its access tokens.
// An expired current token is invalid_grant and leaves the family in place.
// The new pair is stored before the old token is marked spent.
func (s *Server) redeemRefresh(raw, clientID string) tokenResult {
	sum := sha256.Sum256([]byte(raw))
	key := hex.EncodeToString(sum[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.sweepLocked(now)
	rec, ok := s.refresh[key]
	stored := sum
	if !ok {
		stored = sha256.Sum256(nil)
	}
	if subtle.ConstantTimeCompare(sum[:], stored[:]) != 1 || !ok {
		return tokenResult{status: http.StatusBadRequest, code: "invalid_grant"}
	}
	if rec.successor != "" {
		s.revokeFamilyLocked(rec.family)
		return tokenResult{status: http.StatusBadRequest, code: "invalid_grant"}
	}
	if rec.clientID != clientID || !now.Before(rec.exp) {
		return tokenResult{status: http.StatusBadRequest, code: "invalid_grant"}
	}
	access, secs, err := s.mintAccessLocked(now, rec.family)
	if err != nil {
		return tokenResult{status: http.StatusInternalServerError, code: "server_error"}
	}
	refresh, refreshKey, err := s.mintRefreshLocked(now, rec.family, rec.clientID)
	if err != nil {
		delete(s.access, access.key)
		return tokenResult{status: http.StatusInternalServerError, code: "server_error"}
	}
	rec.successor = refreshKey
	s.refresh[key] = rec
	return tokenResult{access: access.raw, refresh: refresh.raw, secs: secs, status: http.StatusOK}
}

type opaque struct {
	raw string
	key string
}

func (s *Server) mintAccessLocked(now time.Time, family string) (opaque, int, error) {
	raw, key, err := newOpaque()
	if err != nil {
		return opaque{}, 0, err
	}
	ttl := s.accessTTL()
	exp := now.Add(ttl)
	secs := int(ttl.Seconds())
	if secs < 1 {
		secs = 1
		exp = now.Add(time.Second)
	}
	s.access[key] = accessRec{exp: exp, family: family}
	return opaque{raw: raw, key: key}, secs, nil
}

func (s *Server) mintRefreshLocked(now time.Time, family, clientID string) (opaque, string, error) {
	raw, key, err := newOpaque()
	if err != nil {
		return opaque{}, "", err
	}
	s.refresh[key] = refreshRec{
		exp:      now.Add(s.refreshTTL()),
		clientID: clientID,
		family:   family,
	}
	return opaque{raw: raw, key: key}, key, nil
}

func (s *Server) revokeFamilyLocked(family string) {
	if family == "" {
		return
	}
	for k, rec := range s.access {
		if rec.family == family {
			delete(s.access, k)
		}
	}
	for k, rec := range s.refresh {
		if rec.family == family {
			delete(s.refresh, k)
		}
	}
}

func (s *Server) sweepLocked(now time.Time) {
	for k, rec := range s.access {
		if !now.Before(rec.exp) {
			delete(s.access, k)
		}
	}
	for k, rec := range s.refresh {
		if rec.successor != "" {
			continue
		}
		if !now.Before(rec.exp) {
			delete(s.refresh, k)
		}
	}
}

func newOpaque() (raw, key string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(sum[:]), nil
}

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (s *Server) writeTokens(w http.ResponseWriter, access string, secs int, refresh string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	body := map[string]any{
		"access_token": access,
		"token_type":   "bearer",
		"expires_in":   secs,
		"scope":        "read",
	}
	if refresh != "" {
		body["refresh_token"] = refresh
	}
	writeJSON(w, http.StatusOK, body)
}

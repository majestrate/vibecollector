package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/majestrate/vibecollector/internal/config"
	"github.com/majestrate/vibecollector/internal/decode"
	"github.com/majestrate/vibecollector/internal/obs"
	"github.com/majestrate/vibecollector/internal/store"
	"github.com/majestrate/vibecollector/openapi"
)

// csp is the policy on every response from this server.
const csp = "default-src 'self'; img-src 'self' data:; connect-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"

const queryTimeout = 5 * time.Second

// uiClientID is the public client. It sends no secret.
// The web UI signs in as a client id stored in oauth_client and sends that secret
// on the token request. Confidential clients are rows in oauth_client.
const uiClientID = "vibecollector-ui"

// basicChallenge is the WWW-Authenticate value on a failed Authorization attempt.
// RFC 6749 requires that header, and HTTP Basic is the scheme this endpoint supports.
const basicChallenge = `Basic realm="vibecollector"`

// pkceCookie and stateCookie carry the daemon-minted PKCE verifier and state.
// They are HttpOnly, so the page cannot read them. Path limits them to the token route.
const (
	pkceCookie  = "vc_pkce"
	stateCookie = "vc_state"
)

var errBadRange = errors.New("bad_range")

// Server is the HTTP API and the OAuth2 authorization server for this UI.
// ListenAndServe binds cfg.Listen. Every route under the API prefix,
// including health, requires an Authorization bearer with scope read.
// The bearer is an opaque access token. The UI grant also returns an opaque
// refresh token that rotates on use. Both live in process memory.
// The web UI obtains them from the authorization-code grant with PKCE.
// The page creates the verifier and the S256 challenge for a client id stored in clients.
// The token request sends that client id, its secret, and the verifier.
// GET /oauth/authorize without code_challenge still mints a verifier, stores it in an
// HttpOnly cookie, and redirects with the code. That path is the public client.
// client_credentials accepts any client id and secret stored in clients.
// GET {base}/openapi.json, GET {base}/oauth/authorize, and POST {base}/oauth/token
// are not token-gated. base is http.public_host's path, or / when that path is empty.
// Static files from ui are not gated. Every route is under base.
type Server struct {
	listen   string
	base     string
	prefix   string
	oauth    config.OAuth2
	q        *store.Query
	clients  *store.DB
	counters *obs.Counters
	cache    *Cache
	ui       fs.FS
	spec     []byte
	mux      *http.ServeMux

	mu      sync.Mutex
	codes   map[string]authCode
	access  map[string]accessRec
	refresh map[string]refreshRec
	bound   string
}

type authCode struct {
	challenge string
	clientID  string
	redirect  string
	exp       time.Time
}

// NewServer builds the routes, the query cache, and the served OpenAPI document.
// cfg.APIPrefix empty means /api/v1. cfg.BasePath empty means /.
// Every route is mounted under BasePath. oauth is the in-process authorization server.
// q, clients, and counters are required; a nil returns ErrNilDep. clients is the
// credential directory for client_credentials. ui is the static tree.
// A nil ui serves no files. A non-positive query-cache TTL or entry cap returns ErrBadCap.
// The handler does not terminate TLS.
func NewServer(cfg config.HTTP, oauth config.OAuth2, q *store.Query, clients *store.DB, counters *obs.Counters, ui fs.FS) (*Server, error) {
	if q == nil {
		return nil, fmt.Errorf("%w: query", ErrNilDep)
	}
	if clients == nil {
		return nil, fmt.Errorf("%w: clients", ErrNilDep)
	}
	if counters == nil {
		return nil, fmt.Errorf("%w: counters", ErrNilDep)
	}
	prefix := cfg.APIPrefix
	if prefix == "" {
		prefix = "/api/v1"
	}
	base := cfg.BasePath
	if base == "" {
		base = "/"
	}
	publicPrefix := mountPath(base, prefix)
	innerPrefix := relativePath(base, publicPrefix)
	cache, err := NewQueryCache(cfg.QueryCacheTTL, cfg.QueryCacheEntries)
	if err != nil {
		return nil, err
	}
	doc, err := parseOpenAPI(openapi.Document)
	if err != nil {
		return nil, err
	}
	if err := rewriteSpec(doc, prefix, oauth.Issuer, base); err != nil {
		return nil, err
	}
	spec, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	s := &Server{
		listen:   cfg.Listen,
		base:     base,
		prefix:   innerPrefix,
		oauth:    oauth,
		q:        q,
		clients:  clients,
		counters: counters,
		cache:    cache,
		ui:       ui,
		spec:     spec,
		mux:      http.NewServeMux(),
		codes:    map[string]authCode{},
		access:   map[string]accessRec{},
		refresh:  map[string]refreshRec{},
	}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /openapi.json", s.handleOpenAPI)
	s.mux.HandleFunc("GET /oauth/authorize", s.handleAuthorize)
	s.mux.HandleFunc("POST /oauth/token", s.handleToken)
	for _, name := range []string{
		"health", "stats", "exporters", "flows", "timeseries", "talkers", "asns", "reputation", "geo",
	} {
		s.mux.HandleFunc("GET "+s.prefix+"/"+name, s.route(name))
	}
	if s.ui != nil {
		s.mux.Handle("/", s.uiHandler())
	}
}

// uiHandler serves the built UI. A client route with no file falls back to
// index.html so a refresh of /flows stays on the shell. API and OAuth paths
// are not rewritten. Static files are not token-gated; this handler is
// registered outside requireAuth.
func (s *Server) uiHandler() http.Handler {
	files := http.FileServer(http.FS(s.ui))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		p := path.Clean("/" + r.URL.Path)
		if p == "/openapi.json" || p == "/oauth" || strings.HasPrefix(p, "/oauth/") || p == s.prefix || strings.HasPrefix(p, s.prefix+"/") {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(p, "/")
		if name == "" || name == "." {
			s.serveIndex(w, r)
			return
		}
		f, err := s.ui.Open(name)
		if err != nil {
			if strings.Contains(path.Base(name), ".") {
				http.NotFound(w, r)
				return
			}
			s.serveIndex(w, r)
			return
		}
		_ = f.Close()
		files.ServeHTTP(w, r)
	})
}

// serveIndex writes index.html with asset URLs relative to the document.
// The browser resolves assets/ against window.location, so a page at
// {base}/flows loads {base}/assets. A head request writes no body.
func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	b, err := fs.ReadFile(s.ui, "index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	b = bytes.ReplaceAll(b, []byte(`="/assets/`), []byte(`="assets/`))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(b)
}

// ListenAndServe binds cfg.Listen and serves until ctx is canceled.
// It returns the listen error, or nil after a clean shutdown.
// Canceling ctx does not cancel collector work; the caller owns that order.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.bound = ln.Addr().String()
	s.mu.Unlock()
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shut)
	err = <-errc
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ServeHTTP sets the response policy and dispatches. CORS is off.
// When base is not /, a request outside that path is 404.
// A request for the base itself redirects to base + "/".
// The remaining path is what the routes are registered on.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", csp)
	if s.base != "" && s.base != "/" {
		p := r.URL.Path
		if p == s.base {
			dest := s.base + "/"
			if r.URL.RawQuery != "" {
				dest += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, dest, http.StatusFound)
			return
		}
		if !strings.HasPrefix(p, s.base+"/") {
			http.NotFound(w, r)
			return
		}
		r2 := r.Clone(r.Context())
		u := *r.URL
		u.Path = strings.TrimPrefix(p, s.base)
		u.RawPath = ""
		r2.URL = &u
		s.mux.ServeHTTP(w, r2)
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.spec)
}

func (s *Server) route(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.requireAuth(w, r) {
			return
		}
		switch name {
		case "health":
			s.cached(w, r, func(context.Context) ([]byte, error) {
				return json.Marshal(map[string]string{"status": "ok"})
			})
		case "stats":
			s.cached(w, r, func(context.Context) ([]byte, error) {
				return json.Marshal(statsJSON(s.counters.Snapshot()))
			})
		case "exporters":
			s.cached(w, r, func(ctx context.Context) ([]byte, error) {
				rows, err := s.q.Exporters(ctx)
				if err != nil {
					return nil, err
				}
				return json.Marshal(exportersJSON(rows))
			})
		default:
			f, err := parseFilter(r, name)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_range"})
				return
			}
			s.cached(w, r, func(ctx context.Context) ([]byte, error) {
				return s.load(ctx, name, f)
			})
		}
	}
}

// cached calls Cache.Do. load is the only place that calls Query.
// Cache-Control no-store sets bypass and keeps the request context.
// A shared load uses a background timeout so one disconnect does not cancel it.
// A load error is not stored.
func (s *Server) cached(w http.ResponseWriter, r *http.Request, load func(context.Context) ([]byte, error)) {
	bypass := strings.Contains(strings.ToLower(r.Header.Get("Cache-Control")), "no-store")
	key := r.URL.Path
	if q := r.URL.Query().Encode(); q != "" {
		key += "?" + q
	}
	body, err := s.cache.Do(key, bypass, func() ([]byte, error) {
		parent := r.Context()
		if !bypass {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, queryTimeout)
		defer cancel()
		return load(ctx)
	})
	if err != nil {
		writeQueryErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) load(ctx context.Context, name string, f store.Filter) ([]byte, error) {
	switch name {
	case "flows":
		page, err := s.q.Flows(ctx, f)
		if err != nil {
			return nil, err
		}
		return json.Marshal(flowPageJSON(page))
	case "timeseries":
		ts, err := s.q.Timeseries(ctx, f)
		if err != nil {
			return nil, err
		}
		return json.Marshal(timeseriesJSON(ts))
	case "talkers":
		rows, err := s.q.Talkers(ctx, f)
		if err != nil {
			return nil, err
		}
		return json.Marshal(talkersJSON(rows))
	case "asns":
		rows, err := s.q.ASNs(ctx, f)
		if err != nil {
			return nil, err
		}
		return json.Marshal(asnsJSON(rows))
	case "reputation":
		rows, err := s.q.Reputation(ctx, f)
		if err != nil {
			return nil, err
		}
		return json.Marshal(repJSON(rows))
	case "geo":
		g, err := s.q.Geo(ctx, f)
		if err != nil {
			return nil, err
		}
		return json.Marshal(geoJSON(g))
	default:
		return nil, errors.New("unknown route")
	}
}

func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	tok, ok := bearerToken(r)
	if !ok || !s.validToken(tok) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return false
	}
	return true
}

func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const pfx = "Bearer "
	if len(h) < len(pfx) || !strings.EqualFold(h[:len(pfx)], pfx) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(pfx):])
	if tok == "" {
		return "", false
	}
	return tok, true
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		oauthErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	known, err := s.knownOAuthClient(r.Context(), q.Get("client_id"))
	if err != nil {
		oauthErr(w, http.StatusInternalServerError, "server_error")
		return
	}
	if !known {
		oauthErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if scope := q.Get("scope"); scope != "" && scope != "read" {
		oauthErr(w, http.StatusBadRequest, "invalid_scope")
		return
	}
	redir := q.Get("redirect_uri")
	if !sameOrigin(r, redir, s.oauth.Issuer, s.base) {
		oauthErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	verifier := ""
	state := q.Get("state")
	minted := false
	if challenge == "" {
		if method != "" {
			oauthErr(w, http.StatusBadRequest, "invalid_request")
			return
		}
		var err error
		verifier, challenge, err = newPKCE()
		if err != nil {
			oauthErr(w, http.StatusInternalServerError, "server_error")
			return
		}
		state, err = randomID()
		if err != nil {
			oauthErr(w, http.StatusInternalServerError, "server_error")
			return
		}
		minted = true
	} else {
		if method != "S256" {
			oauthErr(w, http.StatusBadRequest, "invalid_request")
			return
		}
		raw, err := base64.RawURLEncoding.DecodeString(challenge)
		if err != nil || len(raw) != sha256.Size {
			oauthErr(w, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	code := s.issueCode(authCode{
		challenge: challenge,
		clientID:  q.Get("client_id"),
		redirect:  redir,
	})
	if code == "" {
		oauthErr(w, http.StatusInternalServerError, "server_error")
		return
	}
	u, err := url.Parse(redir)
	if err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	qq := u.Query()
	qq.Set("code", code)
	if state != "" {
		qq.Set("state", state)
	}
	u.RawQuery = qq.Encode()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if minted {
		setPKCECookies(w, verifier, state, mountPath(s.base, "/oauth/token"))
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// handleToken redeems an authorization code, a refresh token, or client credentials.
// A confidential client authenticates with HTTP Basic or with client_id and
// client_secret in the form body.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	grants := r.PostForm["grant_type"]
	if len(grants) > 1 {
		oauthErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	grant := ""
	if len(grants) == 1 {
		grant = grants[0]
	}
	switch grant {
	case "authorization_code":
		s.tokenCode(w, r)
	case "refresh_token":
		s.tokenRefresh(w, r)
	case "client_credentials":
		s.tokenClient(w, r)
	case "":
		// An empty value is an omitted parameter (RFC 6749 section 3.2).
		oauthErr(w, http.StatusBadRequest, "invalid_request")
	default:
		oauthErr(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

// parseClientAuth reads the client id and secret on a token request.
// r.PostForm is already parsed. id and secret are the pair to check.
// viaHeader is true when the client sent an Authorization header, so a 401
// must include WWW-Authenticate. status is non-zero when that header or the
// two methods cannot be used. code is the OAuth error for that status.
//
// HTTP Basic is the method RFC 6749 section 2.3.1 requires. The username and
// password are application/x-www-form-urlencoded, then base64 of
// username + ":" + password. The form fields are the other method. The same
// pair in both is accepted. Different values are invalid_request. A Basic
// header that does not decode, or an Authorization scheme other than Basic,
// is invalid_client.
func parseClientAuth(r *http.Request) (id, secret string, viaHeader bool, status int, code string) {
	if len(r.PostForm["client_id"]) > 1 || len(r.PostForm["client_secret"]) > 1 {
		return "", "", false, http.StatusBadRequest, "invalid_request"
	}
	bodyID := r.PostForm.Get("client_id")
	bodySecret := r.PostForm.Get("client_secret")
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		return bodyID, bodySecret, false, 0, ""
	}
	scheme, param, _ := strings.Cut(header, " ")
	scheme = strings.TrimSpace(scheme)
	param = strings.TrimSpace(param)
	if !strings.EqualFold(scheme, "Basic") {
		return "", "", true, http.StatusUnauthorized, "invalid_client"
	}
	user, pass, ok := decodeBasicPair(param)
	if !ok || user == "" {
		return "", "", true, http.StatusUnauthorized, "invalid_client"
	}
	if (bodyID != "" && bodyID != user) || (bodySecret != "" && bodySecret != pass) {
		return "", "", false, http.StatusBadRequest, "invalid_request"
	}
	return user, pass, true, 0, ""
}

// decodeBasicPair decodes one HTTP Basic parameter.
// param is the base64 token after the scheme. user and pass are form-decoded.
// ok is false when the token is not base64 or has no colon.
func decodeBasicPair(param string) (user, pass string, ok bool) {
	if param == "" {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(param)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(param)
		if err != nil {
			return "", "", false
		}
	}
	user, pass, ok = strings.Cut(string(raw), ":")
	if !ok {
		return "", "", false
	}
	user, err = url.QueryUnescape(user)
	if err != nil {
		return "", "", false
	}
	pass, err = url.QueryUnescape(pass)
	if err != nil {
		return "", "", false
	}
	return user, pass, true
}

// writeClientAuthResult sends an OAuth error for a rejected client authentication.
// viaHeader sets the Basic challenge on a 401. status is the HTTP status.
// code is the OAuth error string.
func writeClientAuthResult(w http.ResponseWriter, viaHeader bool, status int, code string) {
	if viaHeader && status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", basicChallenge)
	}
	oauthErr(w, status, code)
}

// clientSecretOK reports whether id and secret match a stored pair.
// It writes the OAuth error and returns false when the pair is rejected or
// the database fails. viaHeader adds the Basic challenge to that 401.
// The caller skips this for the public client vibecollector-ui on the code
// and refresh grants.
func (s *Server) clientSecretOK(w http.ResponseWriter, r *http.Request, id, secret string, viaHeader bool) bool {
	ok, err := s.clients.OAuthSecretOK(r.Context(), id, secret)
	if err != nil {
		oauthErr(w, http.StatusInternalServerError, "server_error")
		return false
	}
	if !ok {
		writeClientAuthResult(w, viaHeader, http.StatusUnauthorized, "invalid_client")
		return false
	}
	return true
}

func (s *Server) tokenCode(w http.ResponseWriter, r *http.Request) {
	id, secret, viaHeader, authStatus, authCode := parseClientAuth(r)
	if authStatus != 0 {
		writeClientAuthResult(w, viaHeader, authStatus, authCode)
		return
	}
	code := r.PostForm.Get("code")
	redir := r.PostForm.Get("redirect_uri")
	verifier := r.PostForm.Get("code_verifier")
	if scope := r.PostForm.Get("scope"); scope != "" && scope != "read" {
		oauthErr(w, http.StatusBadRequest, "invalid_scope")
		return
	}
	if verifier == "" {
		pkce, pkceErr := r.Cookie(pkceCookie)
		st, stErr := r.Cookie(stateCookie)
		if pkceErr != nil || pkce.Value == "" {
			oauthErr(w, http.StatusBadRequest, "invalid_request")
			return
		}
		clearPKCECookies(w, mountPath(s.base, "/oauth/token"))
		if stErr != nil || st.Value == "" || r.PostForm.Get("state") == "" || subtle.ConstantTimeCompare([]byte(st.Value), []byte(r.PostForm.Get("state"))) != 1 {
			oauthErr(w, http.StatusBadRequest, "invalid_grant")
			return
		}
		verifier = pkce.Value
	}
	if id == "" || code == "" || redir == "" || verifier == "" {
		oauthErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if id != uiClientID && !s.clientSecretOK(w, r, id, secret, viaHeader) {
		return
	}
	s.mu.Lock()
	ac, ok := s.codes[code]
	if ok {
		delete(s.codes, code)
	}
	s.mu.Unlock()
	if !ok || !time.Now().Before(ac.exp) || ac.redirect != redir || ac.clientID != id || !pkceOK(verifier, ac.challenge) {
		oauthErr(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	res := s.issuePair(id)
	if res.status != http.StatusOK {
		oauthErr(w, res.status, res.code)
		return
	}
	s.writeTokens(w, res.access, res.secs, res.refresh)
}

func (s *Server) tokenRefresh(w http.ResponseWriter, r *http.Request) {
	if scope := r.PostForm.Get("scope"); scope != "" && scope != "read" {
		oauthErr(w, http.StatusBadRequest, "invalid_scope")
		return
	}
	id, secret, viaHeader, authStatus, authCode := parseClientAuth(r)
	if authStatus != 0 {
		writeClientAuthResult(w, viaHeader, authStatus, authCode)
		return
	}
	raw := r.PostForm.Get("refresh_token")
	if id == "" || raw == "" {
		oauthErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if id != uiClientID && !s.clientSecretOK(w, r, id, secret, viaHeader) {
		return
	}
	res := s.redeemRefresh(raw, id)
	if res.status != http.StatusOK {
		oauthErr(w, res.status, res.code)
		return
	}
	s.writeTokens(w, res.access, res.secs, res.refresh)
}

func (s *Server) tokenClient(w http.ResponseWriter, r *http.Request) {
	if scope := r.PostForm.Get("scope"); scope != "" && scope != "read" {
		oauthErr(w, http.StatusBadRequest, "invalid_scope")
		return
	}
	id, secret, viaHeader, authStatus, authCode := parseClientAuth(r)
	if authStatus != 0 {
		writeClientAuthResult(w, viaHeader, authStatus, authCode)
		return
	}
	if !s.clientSecretOK(w, r, id, secret, viaHeader) {
		return
	}
	res := s.issueAccess()
	if res.status != http.StatusOK {
		oauthErr(w, res.status, res.code)
		return
	}
	s.writeTokens(w, res.access, res.secs, "")
}

// knownOAuthClient reports whether id may use the authorization-code grant.
// vibecollector-ui is the public client. Any other id must be registered.
// A database error is returned to the caller.
func (s *Server) knownOAuthClient(ctx context.Context, id string) (bool, error) {
	if id == uiClientID {
		return true, nil
	}
	return s.clients.OAuthClientExists(ctx, id)
}

func (s *Server) issueCode(c authCode) string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	code := base64.RawURLEncoding.EncodeToString(buf)
	c.exp = time.Now().Add(10 * time.Minute)
	s.mu.Lock()
	now := time.Now()
	for k, v := range s.codes {
		if !now.Before(v.exp) {
			delete(s.codes, k)
		}
	}
	s.codes[code] = c
	s.mu.Unlock()
	return code
}

// newPKCE returns a verifier and its S256 challenge.
// The verifier is what the token endpoint hashes. The challenge is stored with the code.
func newPKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

func setPKCECookies(w http.ResponseWriter, verifier, state, cookiePath string) {
	http.SetCookie(w, pkceCookieValue(pkceCookie, verifier, 600, cookiePath))
	http.SetCookie(w, pkceCookieValue(stateCookie, state, 600, cookiePath))
}

func clearPKCECookies(w http.ResponseWriter, cookiePath string) {
	http.SetCookie(w, pkceCookieValue(pkceCookie, "", -1, cookiePath))
	http.SetCookie(w, pkceCookieValue(stateCookie, "", -1, cookiePath))
}

func pkceCookieValue(name, value string, maxAge int, cookiePath string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     cookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func pkceOK(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	g := sha256.Sum256([]byte(got))
	w := sha256.Sum256([]byte(challenge))
	return subtle.ConstantTimeCompare(g[:], w[:]) == 1
}

// sameOrigin accepts an absolute http or https redirect with no userinfo and
// no fragment. The path must sit under base when base is not /.
// The origin may be the configured issuer, or the request host.
// ListenAndServe does not set r.TLS. The scheme is X-Forwarded-Proto when
// that header is http or https, and http otherwise. X-Forwarded-Host is ignored.
func sameOrigin(r *http.Request, redirect, issuer, base string) bool {
	u, err := url.Parse(redirect)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if !underBase(u.Path, base) {
		return false
	}
	if issuer != "" {
		iu, err := url.Parse(issuer)
		if err == nil && iu.Host != "" && u.Scheme == iu.Scheme && strings.EqualFold(u.Host, iu.Host) {
			return true
		}
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else {
		p := r.Header.Get("X-Forwarded-Proto")
		if i := strings.IndexByte(p, ','); i >= 0 {
			p = p[:i]
		}
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "http" || p == "https" {
			scheme = p
		}
	}
	return u.Scheme == scheme && strings.EqualFold(u.Host, r.Host)
}

func oauthErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"encode"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func writeQueryErr(w http.ResponseWriter, err error) {
	var fe *store.FilterError
	switch {
	case errors.As(err, &fe):
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":              "filter_outside_raw",
			"raw_available_from": fe.RawAvailableFrom.UTC().Format(time.RFC3339),
		})
	case errors.Is(err, store.ErrQueryTimeout):
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "query_timeout"})
	case errors.Is(err, store.ErrBadFilter):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_range"})
	default:
		slog.Error("query", "class", "database")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query_failed"})
	}
}

func parseFilter(r *http.Request, kind string) (store.Filter, error) {
	q := r.URL.Query()
	var f store.Filter
	rawTZ := q.Get("tz")
	if rawTZ == "" {
		f.TZ = "UTC"
	} else if _, err := time.LoadLocation(rawTZ); err != nil {
		return f, errBadRange
	} else {
		f.TZ = rawTZ
	}
	if day := q.Get("day"); day != "" {
		start, end, adj, err := decode.CalendarDay(day, rawTZ)
		if err != nil {
			return f, errBadRange
		}
		f.Start, f.End, f.Day = start, end, day
		f.SetBoundaryAdjusted(adj)
	} else {
		ss, es := q.Get("start"), q.Get("end")
		if ss == "" || es == "" {
			return f, errBadRange
		}
		start, err1 := time.Parse(time.RFC3339, ss)
		end, err2 := time.Parse(time.RFC3339, es)
		if err1 != nil || err2 != nil || !end.After(start) {
			return f, errBadRange
		}
		f.Start, f.End = start.UTC(), end.UTC()
	}
	if err := fillFilters(&f, q, kind); err != nil {
		return f, err
	}
	if kind == "timeseries" {
		n, unit, err := parseInterval(q.Get("interval"))
		if err != nil {
			return f, err
		}
		avg, err := parseOptionalBool(q.Get("moving_average"))
		if err != nil {
			return f, err
		}
		speed, err := parseOptionalBool(q.Get("average_speed"))
		if err != nil {
			return f, err
		}
		rms, err := parseOptionalBool(q.Get("root_mean_square"))
		if err != nil {
			return f, err
		}
		modes := 0
		if avg {
			modes++
		}
		if speed {
			modes++
		}
		if rms {
			modes++
		}
		if modes > 0 && n == 0 {
			return f, errBadRange
		}
		if modes > 1 {
			return f, errBadRange
		}
		f.IntervalN, f.IntervalUnit = n, unit
		f.MovingAverage = avg
		f.AverageSpeed = speed
		f.RootMeanSquare = rms
	}
	return f, nil
}

// parseOptionalBool reads a timeseries switch.
// An empty value and "false" are off. "true" is on.
// errBadRange means the text is something else.
func parseOptionalBool(s string) (bool, error) {
	switch s {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, errBadRange
	}
}

// parseInterval reads the timeseries bucket width.
// An empty value leaves the native grain. Otherwise the text is a count and
// a unit: m is 1–1440 minutes, h is 1–24 hours, and d is 1–366 days.
// The count has no leading zero. errBadRange means the text is not one of those.
func parseInterval(s string) (int, string, error) {
	if s == "" {
		return 0, "", nil
	}
	if len(s) < 2 || s[0] < '1' || s[0] > '9' {
		return 0, "", errBadRange
	}
	unit := s[len(s)-1:]
	num := s[:len(s)-1]
	for _, c := range num {
		if c < '0' || c > '9' {
			return 0, "", errBadRange
		}
	}
	n, err := strconv.Atoi(num)
	if err != nil {
		return 0, "", errBadRange
	}
	switch unit {
	case "m":
		if n > 1440 {
			return 0, "", errBadRange
		}
	case "h":
		if n > 24 {
			return 0, "", errBadRange
		}
	case "d":
		if n > 366 {
			return 0, "", errBadRange
		}
	default:
		return 0, "", errBadRange
	}
	return n, unit, nil
}

func fillFilters(f *store.Filter, q url.Values, kind string) error {
	if s := q.Get("src"); s != "" {
		a, err := parseIP(s)
		if err != nil {
			return err
		}
		f.Src = &a
	}
	if s := q.Get("dst"); s != "" {
		a, err := parseIP(s)
		if err != nil {
			return err
		}
		f.Dst = &a
	}
	if s := q.Get("exporter"); s != "" {
		a, err := parseIP(s)
		if err != nil {
			return err
		}
		f.Exporter = &a
	}
	if s := q.Get("port"); s != "" {
		n, err := parsePort(s)
		if err != nil {
			return err
		}
		f.Port = &n
	}
	if s := q.Get("src_port"); s != "" {
		n, err := parsePort(s)
		if err != nil {
			return err
		}
		f.SrcPort = &n
	}
	if s := q.Get("dst_port"); s != "" {
		n, err := parsePort(s)
		if err != nil {
			return err
		}
		f.DstPort = &n
	}
	if s := q.Get("proto"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < -1 || n > 255 {
			return errBadRange
		}
		if n == -1 {
			f.SetNoProtocol()
		} else {
			v := uint8(n)
			f.Proto = &v
		}
	}
	if s := q.Get("country"); s != "" {
		if len(s) != 2 {
			return errBadRange
		}
		f.Country = &s
	}
	if s := q.Get("asn"); s != "" {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return errBadRange
		}
		v := uint32(n)
		f.ASN = &v
	}
	if s := q.Get("reputation"); s != "" {
		f.Reputation = &s
	}
	if s := q.Get("sampled"); s != "" {
		if s != "true" && s != "false" {
			return errBadRange
		}
		v := s == "true"
		f.Sampled = &v
	}
	if kind == "talkers" {
		if s := q.Get("by"); s != "" && s != "src" && s != "dst" {
			return errBadRange
		}
		f.By = q.Get("by")
	}
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return errBadRange
		}
		max := 100
		if kind == "flows" {
			max = 500
		}
		if n > max {
			return errBadRange
		}
		f.Limit = n
	}
	f.Cursor = q.Get("cursor")
	return nil
}

func parseIP(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, errBadRange
	}
	return a.Unmap(), nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 65535 {
		return 0, errBadRange
	}
	return uint16(n), nil
}

type dec uint64

func (d dec) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(strconv.FormatUint(uint64(d), 10))), nil
}

type rangeBody struct {
	Start            string `json:"start"`
	End              string `json:"end"`
	TZ               string `json:"tz"`
	BoundaryAdjusted bool   `json:"boundary_adjusted"`
}

func rangeOf(r store.Range) rangeBody {
	tz := r.TZ
	if tz == "" {
		tz = "UTC"
	}
	return rangeBody{
		Start:            r.Start.UTC().Format(time.RFC3339),
		End:              r.End.UTC().Format(time.RFC3339),
		TZ:               tz,
		BoundaryAdjusted: r.BoundaryAdjusted,
	}
}

func statsJSON(snap map[obs.Name]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(snap))
	for k, v := range snap {
		out[string(k)] = v
	}
	return out
}

type exporterBody struct {
	Exporter        string `json:"exporter"`
	Domain          int64  `json:"domain"`
	Version         int    `json:"version"`
	LastSeen        string `json:"last_seen"`
	Packets         uint64 `json:"packets"`
	Flows           uint64 `json:"flows"`
	Malformed       uint64 `json:"malformed"`
	MissingTemplate uint64 `json:"missing_template"`
	GapFlows        uint64 `json:"gap_flows"`
	GapPackets      uint64 `json:"gap_packets"`
	GapRecords      uint64 `json:"gap_records"`
}

func exportersJSON(rows []store.ExporterRow) map[string]any {
	out := make([]exporterBody, 0, len(rows))
	for _, row := range rows {
		out = append(out, exporterBody{
			Exporter:        row.Exporter,
			Domain:          row.Domain,
			Version:         row.Version,
			LastSeen:        row.LastSeen.UTC().Format(time.RFC3339),
			Packets:         row.Packets,
			Flows:           row.Flows,
			Malformed:       row.Malformed,
			MissingTemplate: row.MissingTemplate,
			GapFlows:        row.GapFlows,
			GapPackets:      row.GapPackets,
			GapRecords:      row.GapRecords,
		})
	}
	return map[string]any{"exporters": out}
}

type flowBody struct {
	ID                int64  `json:"id"`
	Start             string `json:"start"`
	End               string `json:"end"`
	Exporter          string `json:"exporter"`
	Domain            int64  `json:"domain"`
	Version           int    `json:"version"`
	Src               string `json:"src"`
	Dst               string `json:"dst"`
	SrcPort           *int   `json:"src_port,omitempty"`
	DstPort           *int   `json:"dst_port,omitempty"`
	Proto             *int   `json:"proto,omitempty"`
	Packets           dec    `json:"packets"`
	Octets            dec    `json:"octets"`
	CounterSemantics  string `json:"counter_semantics"`
	OctetSemantics    string `json:"octet_semantics"`
	FlowDirection     *int   `json:"flow_direction,omitempty"`
	Sampled           bool   `json:"sampled"`
	SamplingInterval  *int64 `json:"sampling_interval,omitempty"`
	SamplingAlgorithm *int   `json:"sampling_algorithm,omitempty"`
	ClockClamped      bool   `json:"clock_clamped"`
	BGPSrc            *int64 `json:"bgp_src_as,omitempty"`
	BGPDst            *int64 `json:"bgp_dst_as,omitempty"`
	SrcScope          string `json:"src_scope"`
	DstScope          string `json:"dst_scope"`
	SrcGeo            string `json:"src_geo"`
	DstGeo            string `json:"dst_geo"`
	SrcASN            string `json:"src_asn"`
	DstASN            string `json:"dst_asn"`
	SrcRep            string `json:"src_rep"`
	DstRep            string `json:"dst_rep"`
}

func flowPageJSON(page store.FlowPage) map[string]any {
	flows := make([]flowBody, 0, len(page.Flows))
	for _, row := range page.Flows {
		flows = append(flows, flowBody{
			ID:                row.ID,
			Start:             row.Start.UTC().Format(time.RFC3339),
			End:               row.End.UTC().Format(time.RFC3339),
			Exporter:          row.Exporter,
			Domain:            row.Domain,
			Version:           row.Version,
			Src:               row.Src,
			Dst:               row.Dst,
			SrcPort:           row.SrcPort,
			DstPort:           row.DstPort,
			Proto:             row.Proto,
			Packets:           dec(row.Packets),
			Octets:            dec(row.Octets),
			CounterSemantics:  row.CounterSemantics,
			OctetSemantics:    row.OctetSemantics,
			FlowDirection:     row.FlowDirection,
			Sampled:           row.Sampled,
			SamplingInterval:  row.SamplingInterval,
			SamplingAlgorithm: row.SamplingAlgorithm,
			ClockClamped:      row.ClockClamped,
			BGPSrc:            row.BGPSrcAS,
			BGPDst:            row.BGPDstAS,
			SrcScope:          row.SrcScope,
			DstScope:          row.DstScope,
			SrcGeo:            row.SrcGeo,
			DstGeo:            row.DstGeo,
			SrcASN:            row.SrcASN,
			DstASN:            row.DstASN,
			SrcRep:            row.SrcRep,
			DstRep:            row.DstRep,
		})
	}
	rg := rangeOf(page.Range)
	return map[string]any{
		"start":              rg.Start,
		"end":                rg.End,
		"tz":                 rg.TZ,
		"boundary_adjusted":  rg.BoundaryAdjusted,
		"raw_available_from": page.RawAvailableFrom.UTC().Format(time.RFC3339),
		"truncated":          page.Truncated,
		"flows":              flows,
		"next_cursor":        page.NextCursor,
	}
}

type pointBody struct {
	T       string `json:"t"`
	Octets  string `json:"octets"`
	Packets string `json:"packets"`
}

type seriesBody struct {
	Sampled bool        `json:"sampled"`
	Points  []pointBody `json:"points"`
}

// countText is the decimal text of a packet or octet total.
// Nil and zero are "0".
func countText(n *big.Int) string {
	if n == nil || n.Sign() == 0 {
		return "0"
	}
	return n.Text(10)
}

func timeseriesJSON(ts store.Timeseries) map[string]any {
	series := make([]seriesBody, 0, len(ts.Series))
	for _, s := range ts.Series {
		pts := make([]pointBody, 0, len(s.Points))
		for _, p := range s.Points {
			octets := countText(p.Octets)
			packets := countText(p.Packets)
			if ts.AverageSpeed {
				octets = p.OctetRate
				packets = p.PacketRate
				if octets == "" {
					octets = "0"
				}
				if packets == "" {
					packets = "0"
				}
			}
			pts = append(pts, pointBody{
				T:       p.T.UTC().Format(time.RFC3339),
				Octets:  octets,
				Packets: packets,
			})
		}
		series = append(series, seriesBody{Sampled: s.Sampled, Points: pts})
	}
	rg := rangeOf(ts.Range)
	return map[string]any{
		"source":            ts.Source,
		"grain":             ts.Grain,
		"moving_average":    ts.MovingAverage,
		"average_speed":     ts.AverageSpeed,
		"root_mean_square":  ts.RootMeanSquare,
		"start":             rg.Start,
		"end":               rg.End,
		"tz":                rg.TZ,
		"boundary_adjusted": rg.BoundaryAdjusted,
		"series":            series,
	}
}

type talkerBody struct {
	Addr    string `json:"addr"`
	Octets  dec    `json:"octets"`
	Packets dec    `json:"packets"`
	Flows   uint64 `json:"flows"`
}

func talkersJSON(t store.Talkers) map[string]any {
	rows := make([]talkerBody, 0, len(t.Rows))
	for _, row := range t.Rows {
		rows = append(rows, talkerBody{
			Addr:    row.Addr,
			Octets:  dec(row.Octets),
			Packets: dec(row.Packets),
			Flows:   row.Flows,
		})
	}
	rg := rangeOf(t.Range)
	return map[string]any{
		"source":            t.Source,
		"grain":             t.Grain,
		"start":             rg.Start,
		"end":               rg.End,
		"tz":                rg.TZ,
		"boundary_adjusted": rg.BoundaryAdjusted,
		"by":                t.By,
		"approximate":       t.Approximate,
		"other_octets":      dec(t.OtherOctets),
		"rows":              rows,
	}
}

type asnBody struct {
	ASN        int64  `json:"asn"`
	Name       string `json:"name"`
	Direction  string `json:"direction"`
	FromExport bool   `json:"from_export"`
	Octets     dec    `json:"octets"`
	Packets    dec    `json:"packets"`
	Flows      uint64 `json:"flows"`
}

func asnsJSON(a store.ASNs) map[string]any {
	rows := make([]asnBody, 0, len(a.Rows))
	for _, row := range a.Rows {
		rows = append(rows, asnBody{
			ASN:        row.ASN,
			Name:       row.Name,
			Direction:  row.Direction,
			FromExport: row.FromExport,
			Octets:     dec(row.Octets),
			Packets:    dec(row.Packets),
			Flows:      row.Flows,
		})
	}
	rg := rangeOf(a.Range)
	return map[string]any{
		"source":            a.Source,
		"grain":             a.Grain,
		"start":             rg.Start,
		"end":               rg.End,
		"tz":                rg.TZ,
		"boundary_adjusted": rg.BoundaryAdjusted,
		"rows":              rows,
	}
}

type repBody struct {
	Direction string `json:"direction"`
	Addr      string `json:"addr"`
	Category  string `json:"category"`
	Octets    dec    `json:"octets"`
	Packets   dec    `json:"packets"`
	Flows     uint64 `json:"flows"`
}

func repJSON(rep store.Reputation) map[string]any {
	rows := make([]repBody, 0, len(rep.Rows))
	for _, row := range rep.Rows {
		rows = append(rows, repBody{
			Direction: row.Direction,
			Addr:      row.Addr,
			Category:  row.Category,
			Octets:    dec(row.Octets),
			Packets:   dec(row.Packets),
			Flows:     row.Flows,
		})
	}
	rg := rangeOf(rep.Range)
	return map[string]any{
		"source":            rep.Source,
		"grain":             rep.Grain,
		"start":             rg.Start,
		"end":               rg.End,
		"tz":                rg.TZ,
		"boundary_adjusted": rg.BoundaryAdjusted,
		"approximate":       rep.Approximate,
		"other_octets":      dec(rep.OtherOctets),
		"rows":              rows,
	}
}

type placeBody struct {
	Kind   string   `json:"kind"`
	ISO    string   `json:"iso_a2"`
	Region string   `json:"region,omitempty"`
	City   string   `json:"city,omitempty"`
	Lat    *float64 `json:"lat,omitempty"`
	Lon    *float64 `json:"lon,omitempty"`
}

type countryBody struct {
	ISOA2   string `json:"iso_a2"`
	ISONum  string `json:"iso_num"`
	Octets  dec    `json:"octets"`
	Packets dec    `json:"packets"`
	Flows   dec    `json:"flows"`
}

type pathBody struct {
	Src     placeBody `json:"src"`
	Dst     placeBody `json:"dst"`
	Octets  dec       `json:"octets"`
	Packets dec       `json:"packets"`
	Flows   dec       `json:"flows"`
}

func geoJSON(g store.Geo) map[string]any {
	countries := make([]countryBody, 0, len(g.Countries))
	for _, c := range g.Countries {
		countries = append(countries, countryBody{
			ISOA2:   c.ISOA2,
			ISONum:  isoNum[c.ISOA2],
			Octets:  dec(c.Octets),
			Packets: dec(c.Packets),
			Flows:   dec(c.Flows),
		})
	}
	paths := make([]pathBody, 0, len(g.Paths))
	for _, p := range g.Paths {
		paths = append(paths, pathBody{
			Src:     placeOf(p.Src),
			Dst:     placeOf(p.Dst),
			Octets:  dec(p.Octets),
			Packets: dec(p.Packets),
			Flows:   dec(p.Flows),
		})
	}
	rg := rangeOf(g.Range)
	return map[string]any{
		"source":            g.Source,
		"start":             rg.Start,
		"end":               rg.End,
		"tz":                rg.TZ,
		"boundary_adjusted": rg.BoundaryAdjusted,
		"bytes_are":         g.BytesAre,
		"approximate":       g.Approximate,
		"countries":         countries,
		"paths":             paths,
		"path_cap":          g.PathCap,
		"paths_omitted":     g.PathsOmitted,
		"other_octets":      dec(g.OtherOctets),
	}
}

func placeOf(p store.GeoPlace) placeBody {
	b := placeBody{Kind: p.Kind, ISO: p.ISOA2, Region: p.Region, City: p.City}
	if p.HasCoord {
		lat, lon := p.Lat, p.Lon
		b.Lat = &lat
		b.Lon = &lon
	}
	return b
}

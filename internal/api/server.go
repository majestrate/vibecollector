package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"vibecollector/api"
	"vibecollector/internal/config"
	"vibecollector/internal/decode"
	"vibecollector/internal/obs"
	"vibecollector/internal/store"
)

// csp is the policy on every response from this server.
const csp = "default-src 'self'; img-src 'self' data:; connect-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"

const queryTimeout = 5 * time.Second

var errBadRange = errors.New("bad_range")

// Server is the HTTP API and the OAuth2 authorization server for this UI.
// ListenAndServe binds cfg.Listen. Every route under the API prefix,
// including health, requires an Authorization bearer with scope read.
// GET /openapi.json, GET /oauth/authorize, and POST /oauth/token stay at
// the site root and are not token-gated. Static files from ui are not gated.
type Server struct {
	listen   string
	prefix   string
	oauth    config.OAuth2
	q        *store.Query
	counters *obs.Counters
	cache    *Cache
	ui       fs.FS
	spec     []byte
	mux      *http.ServeMux

	mu     sync.Mutex
	codes  map[string]authCode
	tokens map[string]time.Time
	bound  string
}

type authCode struct {
	challenge string
	clientID  string
	redirect  string
	exp       time.Time
}

// NewServer builds the routes, the query cache, and the served OpenAPI document.
// cfg.APIPrefix empty means /api/v1. oauth is the in-process authorization server.
// q and counters are required; a nil returns ErrNilDep. ui is the static tree.
// A nil ui serves no files. A non-positive query-cache TTL or entry cap returns ErrBadCap.
// The handler does not terminate TLS.
func NewServer(cfg config.HTTP, oauth config.OAuth2, q *store.Query, counters *obs.Counters, ui fs.FS) (*Server, error) {
	if q == nil {
		return nil, fmt.Errorf("%w: query", ErrNilDep)
	}
	if counters == nil {
		return nil, fmt.Errorf("%w: counters", ErrNilDep)
	}
	prefix := cfg.APIPrefix
	if prefix == "" {
		prefix = "/api/v1"
	}
	if oauth.UIClientID == "" {
		oauth.UIClientID = "vibecollector-ui"
	}
	cache, err := NewQueryCache(cfg.QueryCacheTTL, cfg.QueryCacheEntries)
	if err != nil {
		return nil, err
	}
	doc, err := parseOpenAPI(openapi.Document)
	if err != nil {
		return nil, err
	}
	if err := rewriteSpec(doc, prefix); err != nil {
		return nil, err
	}
	spec, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	s := &Server{
		listen:   cfg.Listen,
		prefix:   prefix,
		oauth:    oauth,
		q:        q,
		counters: counters,
		cache:    cache,
		ui:       ui,
		spec:     spec,
		mux:      http.NewServeMux(),
		codes:    map[string]authCode{},
		tokens:   map[string]time.Time{},
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
		s.mux.Handle("/", http.FileServer(http.FS(s.ui)))
	}
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
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", csp)
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

func (s *Server) validToken(tok string) bool {
	sum := sha256.Sum256([]byte(tok))
	key := hex.EncodeToString(sum[:])
	s.mu.Lock()
	exp, ok := s.tokens[key]
	s.mu.Unlock()
	stored := sum
	if !ok {
		stored = sha256.Sum256(nil)
	}
	match := subtle.ConstantTimeCompare(sum[:], stored[:]) == 1
	if !ok || !match || !time.Now().Before(exp) {
		return false
	}
	return true
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" {
		oauthErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if q.Get("client_id") != s.oauth.UIClientID {
		oauthErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if scope := q.Get("scope"); scope != "" && scope != "read" {
		oauthErr(w, http.StatusBadRequest, "invalid_scope")
		return
	}
	redir := q.Get("redirect_uri")
	if !sameOrigin(r, redir, s.oauth.Issuer) {
		oauthErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	raw, err := base64.RawURLEncoding.DecodeString(q.Get("code_challenge"))
	if err != nil || len(raw) != 32 {
		oauthErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	code := s.issueCode(authCode{
		challenge: q.Get("code_challenge"),
		clientID:  q.Get("client_id"),
		redirect:  redir,
	})
	u, err := url.Parse(redir)
	if err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	qq := u.Query()
	qq.Set("code", code)
	if st := q.Get("state"); st != "" {
		qq.Set("state", st)
	}
	u.RawQuery = qq.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.tokenCode(w, r)
	case "client_credentials":
		s.tokenClient(w, r)
	default:
		oauthErr(w, http.StatusBadRequest, "invalid_request")
	}
}

func (s *Server) tokenCode(w http.ResponseWriter, r *http.Request) {
	id := r.PostForm.Get("client_id")
	code := r.PostForm.Get("code")
	redir := r.PostForm.Get("redirect_uri")
	verifier := r.PostForm.Get("code_verifier")
	if scope := r.PostForm.Get("scope"); scope != "" && scope != "read" {
		oauthErr(w, http.StatusBadRequest, "invalid_scope")
		return
	}
	if id == "" || code == "" || redir == "" || verifier == "" {
		oauthErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if id != s.oauth.UIClientID {
		oauthErr(w, http.StatusUnauthorized, "invalid_client")
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
	s.writeToken(w)
}

func (s *Server) tokenClient(w http.ResponseWriter, r *http.Request) {
	if scope := r.PostForm.Get("scope"); scope != "" && scope != "read" {
		oauthErr(w, http.StatusBadRequest, "invalid_scope")
		return
	}
	id := r.PostForm.Get("client_id")
	secret := r.PostForm.Get("client_secret")
	if id != s.oauth.UIClientID || !secretOK(secret, s.oauth.ClientSecret) {
		oauthErr(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	s.writeToken(w)
}

func (s *Server) writeToken(w http.ResponseWriter) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		oauthErr(w, http.StatusInternalServerError, "server_error")
		return
	}
	tok := base64.RawURLEncoding.EncodeToString(buf)
	ttl := s.oauth.TokenTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	sum := sha256.Sum256([]byte(tok))
	key := hex.EncodeToString(sum[:])
	exp := time.Now().Add(ttl)
	s.mu.Lock()
	now := time.Now()
	for k, e := range s.tokens {
		if !now.Before(e) {
			delete(s.tokens, k)
		}
	}
	s.tokens[key] = exp
	s.mu.Unlock()
	secs := int(ttl.Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok,
		"token_type":   "bearer",
		"expires_in":   secs,
		"scope":        "read",
	})
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

func secretOK(got, want string) bool {
	g := sha256.Sum256([]byte(got))
	w := sha256.Sum256([]byte(want))
	match := subtle.ConstantTimeCompare(g[:], w[:]) == 1
	if want == "" {
		return false
	}
	return match
}

func pkceOK(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	g := sha256.Sum256([]byte(got))
	w := sha256.Sum256([]byte(challenge))
	return subtle.ConstantTimeCompare(g[:], w[:]) == 1
}

// sameOrigin accepts an absolute http or https redirect with no userinfo and
// no fragment. The origin may be the configured issuer, or the request host.
// ListenAndServe does not set r.TLS. The scheme is X-Forwarded-Proto when
// that header is http or https, and http otherwise. X-Forwarded-Host is ignored.
func sameOrigin(r *http.Request, redirect, issuer string) bool {
	u, err := url.Parse(redirect)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
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
	return f, nil
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
	Octets  dec    `json:"octets"`
	Packets dec    `json:"packets"`
}

type seriesBody struct {
	Sampled bool        `json:"sampled"`
	Points  []pointBody `json:"points"`
}

func timeseriesJSON(ts store.Timeseries) map[string]any {
	series := make([]seriesBody, 0, len(ts.Series))
	for _, s := range ts.Series {
		pts := make([]pointBody, 0, len(s.Points))
		for _, p := range s.Points {
			pts = append(pts, pointBody{
				T:       p.T.UTC().Format(time.RFC3339),
				Octets:  dec(p.Octets),
				Packets: dec(p.Packets),
			})
		}
		series = append(series, seriesBody{Sampled: s.Sampled, Points: pts})
	}
	rg := rangeOf(ts.Range)
	return map[string]any{
		"source":            ts.Source,
		"grain":             ts.Grain,
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

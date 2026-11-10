package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
	_ "time/tzdata"

	"vibecollector/internal/config"
	"vibecollector/internal/flow"
	"vibecollector/internal/obs"
	"vibecollector/internal/store"
)

func TestNewServerNil(t *testing.T) {
	db := openDB(t)
	q, err := store.NewQuery(db)
	if err != nil {
		t.Fatal(err)
	}
	counters := obs.NewCounters()
	cfg := config.HTTP{APIPrefix: "/api/v1", QueryCacheTTL: time.Second, QueryCacheEntries: 8}
	if _, err := NewServer(cfg, config.OAuth2{}, nil, counters, nil); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
	if _, err := NewServer(cfg, config.OAuth2{}, q, nil, nil); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
}

func TestQueryCache(t *testing.T) {
	if _, err := NewQueryCache(0, 1); !errors.Is(err, ErrBadCap) {
		t.Fatal(err)
	}
	if _, err := NewQueryCache(time.Second, 0); !errors.Is(err, ErrBadCap) {
		t.Fatal(err)
	}
	c, err := NewQueryCache(time.Minute, 4)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	load := func() ([]byte, error) {
		n++
		return []byte("ok"), nil
	}
	if _, err := c.Do("k", false, load); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do("k", false, load); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal(n)
	}
	if _, err := c.Do("k", true, load); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do("k", false, load); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatal(n)
	}
	bad := func() ([]byte, error) {
		n++
		return nil, &store.FilterError{RawAvailableFrom: time.Unix(1, 0).UTC()}
	}
	if _, err := c.Do("e", false, bad); err == nil {
		t.Fatal("cached error")
	}
	if _, err := c.Do("e", false, bad); err == nil {
		t.Fatal("cached error")
	}
	if n != 4 {
		t.Fatal(n)
	}
}

func TestAuthOnLoopback(t *testing.T) {
	s, _ := newAPI(t, "/api/v1", "s3cret")
	tok := pkceToken(t, s)
	for _, name := range dataRoutes {
		t.Run(name, func(t *testing.T) {
			rr := call(s, http.MethodGet, s.prefix+"/"+name, nil, nil)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("no bearer %d %s", rr.Code, rr.Body.String())
			}
			if rr.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatal(rr.Header().Get("Referrer-Policy"))
			}
			rr = call(s, http.MethodGet, s.prefix+"/"+name+"?access_token="+url.QueryEscape(tok), nil, nil)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("query token %d %s", rr.Code, rr.Body.String())
			}
		})
	}
	rr := call(s, http.MethodGet, s.prefix+"/health", nil, map[string]string{"Authorization": "Bearer " + tok})
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}
	var health map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &health); err != nil || health["status"] != "ok" {
		t.Fatal(rr.Body.String())
	}
	cc := clientToken(t, s, "s3cret")
	rr = call(s, http.MethodGet, s.prefix+"/stats", nil, map[string]string{"Authorization": "Bearer " + cc})
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}
	var stats map[string]float64
	if err := json.Unmarshal(rr.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	snap := s.counters.Snapshot()
	if len(stats) != len(snap) {
		t.Fatalf("stats %d snap %d", len(stats), len(snap))
	}
	for name, want := range snap {
		got, ok := stats[string(name)]
		if !ok || got != float64(want) {
			t.Fatalf("%s %v %v", name, got, ok)
		}
	}
}

func TestClientCredentialsEmptySecret(t *testing.T) {
	s, _ := newAPI(t, "/api/v1", "")
	body := url.Values{}
	body.Set("grant_type", "client_credentials")
	body.Set("client_id", "vibecollector-ui")
	body.Set("client_secret", "nope")
	rr := call(s, http.MethodPost, "/oauth/token", strings.NewReader(body.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if rr.Code == http.StatusOK || strings.Contains(rr.Body.String(), "access_token") {
		t.Fatal(rr.Code, rr.Body.String())
	}
}

func TestAuthorizeRedirectOrigin(t *testing.T) {
	s, _ := newAPI(t, "/api/v1", "s3cret")
	challenge := pkceChallenge(t)
	s.oauth.Issuer = "https://collector.example"
	rr := authRedirect(t, s, "https://collector.example/cb", "127.0.0.1:8080", challenge, nil)
	if rr.Code != http.StatusFound {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = authRedirect(t, s, "https://collector.example/cb#frag", "127.0.0.1:8080", challenge, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = authRedirect(t, s, "https://user:pw@collector.example/cb", "127.0.0.1:8080", challenge, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}
	s.oauth.Issuer = ""
	rr = authRedirect(t, s, "https://collector.example/cb", "collector.example", challenge, map[string]string{
		"X-Forwarded-Proto": "https",
	})
	if rr.Code != http.StatusFound {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = authRedirect(t, s, "https://collector.example/cb", "collector.example", challenge, map[string]string{
		"X-Forwarded-Proto": "https, http",
	})
	if rr.Code != http.StatusFound {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = authRedirect(t, s, "https://collector.example/cb", "127.0.0.1:8080", challenge, map[string]string{
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Host":  "collector.example",
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}
	rr = authRedirect(t, s, "http://127.0.0.1:8080/cb", "127.0.0.1:8080", challenge, nil)
	if rr.Code != http.StatusFound {
		t.Fatal(rr.Code, rr.Body.String())
	}
}

func TestSharedQueryIgnoresCallerCancel(t *testing.T) {
	s, _ := newAPI(t, "/api/v1", "s3cret")
	tok := clientToken(t, s, "s3cret")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, s.prefix+"/exporters", nil).WithContext(ctx)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, s.prefix+"/exporters", nil).WithContext(ctx)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Cache-Control", "no-store")
	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatal(rr.Code, rr.Body.String())
	}
}

func TestGeoFlowsRoundedCell(t *testing.T) {
	s, db := newAPI(t, "/api/v1", "s3cret")
	start := time.Now().UTC().Add(-6 * time.Minute).Truncate(5 * time.Minute)
	end := start.Add(time.Hour)
	a := flowAt(start, "203.0.113.5", "198.51.100.9", 443, 4, 40, false, nil, "US", "DE", "")
	b := flowAt(start, "203.0.113.6", "198.51.100.10", 443, 6, 60, false, nil, "US", "DE", "")
	a.SrcEnrich.Geo.HasLatLon = true
	a.SrcEnrich.Geo.Lat, a.SrcEnrich.Geo.Lon = 40.26, -74.01
	a.DstEnrich.Geo.HasLatLon = true
	a.DstEnrich.Geo.Lat, a.DstEnrich.Geo.Lon = 52.52, 13.405
	b.SrcEnrich.Geo.HasLatLon = true
	b.SrcEnrich.Geo.Lat, b.SrcEnrich.Geo.Lon = 40.31, -74.04
	b.DstEnrich.Geo.HasLatLon = true
	b.DstEnrich.Geo.Lat, b.DstEnrich.Geo.Lon = 52.47, 13.44
	// 0.15 and -74.05 are tenths where SQLite ROUND(x, 1) and round1 disagree.
	c := flowAt(start, "203.0.113.7", "198.51.100.11", 80, 1, 10, false, nil, "US", "FR", "")
	c.SrcEnrich.Geo.HasLatLon = true
	c.SrcEnrich.Geo.Lat, c.SrcEnrich.Geo.Lon = 0.15, -74.05
	writeFlows(t, db, s.q, []flow.Flow{a, b, c}, start, end)
	tok := clientToken(t, s, "s3cret")
	auth := map[string]string{"Authorization": "Bearer " + tok}
	win := "start=" + url.QueryEscape(start.Format(time.RFC3339)) + "&end=" + url.QueryEscape(end.Format(time.RFC3339))
	geo := mustJSON(t, call(s, http.MethodGet, s.prefix+"/geo?"+win+"&port=443", nil, auth).Body.Bytes())
	if geo["source"] != "flows" {
		t.Fatal(geo["source"])
	}
	paths := geo["paths"].([]any)
	if len(paths) != 1 {
		t.Fatalf("paths %d", len(paths))
	}
	row := paths[0].(map[string]any)
	if row["flows"] != "2" || row["octets"] != "100" {
		t.Fatal(row)
	}
	assertCoord(t, row["src"], "coord", 40.3, -74)
	assertCoord(t, row["dst"], "coord", 52.5, 13.4)

	half := mustJSON(t, call(s, http.MethodGet, s.prefix+"/geo?"+win+"&port=80", nil, auth).Body.Bytes())
	if half["source"] != "flows" {
		t.Fatal(half["source"])
	}
	hpaths := half["paths"].([]any)
	if len(hpaths) != 1 {
		t.Fatalf("half paths %d", len(hpaths))
	}
	assertCoord(t, hpaths[0].(map[string]any)["src"], "coord", 0.2, -74.1)

	roll := mustJSON(t, call(s, http.MethodGet, s.prefix+"/geo?"+win, nil, auth).Body.Bytes())
	if roll["source"] != "rollup" {
		t.Fatal(roll["source"])
	}
	if !pathHasSrc(roll["paths"].([]any), 0.2, -74.1) || !pathHasSrc(roll["paths"].([]any), 40.3, -74) {
		t.Fatal(roll["paths"])
	}
}

func TestOpenAPI(t *testing.T) {
	s, _ := newAPI(t, "/api/v1", "s3cret")
	rr := call(s, http.MethodGet, "/openapi.json", nil, nil)
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code)
	}
	doc := mustJSON(t, rr.Body.Bytes())
	ver, _ := doc["openapi"].(string)
	if !strings.HasPrefix(ver, "3.0") {
		t.Fatal(ver)
	}
	paths := doc["paths"].(map[string]any)
	for _, name := range dataRoutes {
		assertOAuth(t, paths, "/api/v1/"+name)
	}
	for _, p := range []string{"/oauth/authorize", "/oauth/token", "/openapi.json"} {
		if _, ok := paths[p]; !ok {
			t.Fatal("missing", p)
		}
	}
	schemes := doc["components"].(map[string]any)["securitySchemes"].(map[string]any)
	if _, ok := schemes["oauth2"]; !ok {
		t.Fatal("oauth2 scheme")
	}
	servers := doc["servers"].([]any)
	if !strings.HasSuffix(servers[0].(map[string]any)["url"].(string), "/api/v1") {
		t.Fatal(servers[0])
	}
	tokenSchema := doc["components"].(map[string]any)["schemas"].(map[string]any)["TokenResponse"].(map[string]any)
	scopeSchema := tokenSchema["properties"].(map[string]any)["scope"].(map[string]any)
	enum, _ := scopeSchema["enum"].([]any)
	if scopeSchema["type"] != "string" || len(enum) != 1 || enum[0] != "read" {
		t.Fatal(scopeSchema)
	}
	var sawScope bool
	for _, item := range tokenSchema["required"].([]any) {
		if item == "scope" {
			sawScope = true
		}
	}
	if !sawScope {
		t.Fatal(tokenSchema["required"])
	}

	alt, _ := newAPI(t, "/collector/v1", "s3cret")
	rr = call(alt, http.MethodGet, "/openapi.json", nil, nil)
	doc = mustJSON(t, rr.Body.Bytes())
	paths = doc["paths"].(map[string]any)
	if _, ok := paths["/api/v1/health"]; ok {
		t.Fatal("default prefix still listed")
	}
	for _, name := range dataRoutes {
		assertOAuth(t, paths, "/collector/v1/"+name)
	}
	if !strings.HasSuffix(doc["servers"].([]any)[0].(map[string]any)["url"].(string), "/collector/v1") {
		t.Fatal(doc["servers"])
	}
	rr = call(alt, http.MethodGet, "/api/v1/health", nil, nil)
	if rr.Code != http.StatusNotFound {
		t.Fatal(rr.Code)
	}
	tok := clientToken(t, alt, "s3cret")
	rr = call(alt, http.MethodGet, "/collector/v1/health", nil, map[string]string{"Authorization": "Bearer " + tok})
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}
}

func TestFiltersGeoSampling(t *testing.T) {
	s, db := newAPI(t, "/api/v1", "s3cret")
	start := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Minute)
	end := start.Add(time.Hour)
	n100 := uint32(100)
	flows := []flow.Flow{
		flowAt(start, "203.0.113.5", "198.51.100.9", 443, 10, 1000, false, nil, "US", "DE", "malware-beacon"),
		flowAt(start, "10.1.2.3", "10.1.2.4", 9, 1, 50, false, nil, "", "", ""),
		flowAt(start, "203.0.113.20", "198.51.100.20", 80, 3, 999, false, nil, "FR", "JP", ""),
		flowAt(start, "203.0.113.8", "198.51.100.8", 53, 7, 70, true, &n100, "US", "DE", ""),
	}
	writeFlows(t, db, s.q, flows, start, end)
	tok := clientToken(t, s, "s3cret")
	auth := map[string]string{"Authorization": "Bearer " + tok}
	win := "start=" + url.QueryEscape(start.Format(time.RFC3339)) + "&end=" + url.QueryEscape(end.Format(time.RFC3339))

	geo := mustJSON(t, call(s, http.MethodGet, s.prefix+"/geo?"+win+"&port=443", nil, auth).Body.Bytes())
	if geo["source"] != "flows" {
		t.Fatal(geo["source"])
	}
	paths := geo["paths"].([]any)
	if len(paths) != 1 || len(paths) > 100 {
		t.Fatalf("paths %d", len(paths))
	}
	if paths[0].(map[string]any)["octets"] != "1000" {
		t.Fatal(paths[0])
	}
	countries := geo["countries"].([]any)
	seen := map[string]bool{}
	for _, c := range countries {
		row := c.(map[string]any)
		cc := row["iso_a2"].(string)
		seen[cc] = true
		num, ok := row["iso_num"].(string)
		if !ok || num == "" {
			t.Fatalf("iso_num %T %v", row["iso_num"], row["iso_num"])
		}
		if cc == "US" && num != "840" || cc == "DE" && num != "276" {
			t.Fatal(row)
		}
	}
	if len(seen) != 2 || !seen["US"] || !seen["DE"] {
		t.Fatal(seen)
	}
	flowPage := mustJSON(t, call(s, http.MethodGet, s.prefix+"/flows?"+win+"&port=443", nil, auth).Body.Bytes())
	gotFlows := flowPage["flows"].([]any)
	if len(gotFlows) != 1 || gotFlows[0].(map[string]any)["octets"] != "1000" {
		t.Fatal(flowPage["flows"])
	}

	old := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	oldQ := "start=" + url.QueryEscape(old.Format(time.RFC3339)) + "&end=" + url.QueryEscape(old.Add(time.Hour).Format(time.RFC3339)) + "&port=443"
	rr := call(s, http.MethodGet, s.prefix+"/geo?"+oldQ, nil, auth)
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code, rr.Body.String())
	}
	outside := mustJSON(t, rr.Body.Bytes())
	if outside["error"] != "filter_outside_raw" || outside["raw_available_from"] == "" {
		t.Fatal(outside)
	}
	if _, ok := outside["countries"]; ok {
		t.Fatal(outside)
	}

	ts := mustJSON(t, call(s, http.MethodGet, s.prefix+"/timeseries?"+win, nil, auth).Body.Bytes())
	series := ts["series"].([]any)
	if len(series) != 2 {
		t.Fatal(series)
	}
	var sawUnsampled, sawSampled bool
	for _, item := range series {
		row := item.(map[string]any)
		if row["sampled"].(bool) {
			sawSampled = true
		} else {
			sawUnsampled = true
		}
	}
	if !sawUnsampled || !sawSampled {
		t.Fatal(series)
	}

	repMiss := mustJSON(t, call(s, http.MethodGet, s.prefix+"/reputation?"+win+"&reputation=malware", nil, auth).Body.Bytes())
	if repMiss["source"] != "rollup" || len(repMiss["rows"].([]any)) != 0 {
		t.Fatal(repMiss["source"], repMiss["rows"])
	}
	repHit := mustJSON(t, call(s, http.MethodGet, s.prefix+"/reputation?"+win+"&reputation=malware-beacon", nil, auth).Body.Bytes())
	if repHit["source"] != "rollup" || len(repHit["rows"].([]any)) == 0 {
		t.Fatal(repHit)
	}

	page := mustJSON(t, call(s, http.MethodGet, s.prefix+"/flows?"+win+"&port=53", nil, auth).Body.Bytes())
	one := page["flows"].([]any)
	if len(one) != 1 {
		t.Fatal(one)
	}
	raw := map[string]json.RawMessage{}
	b, err := json.Marshal(one[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["sampled"]) != "true" || string(raw["sampling_interval"]) != "100" || string(raw["packets"]) != `"7"` {
		t.Fatalf("sampled=%s interval=%s packets=%s", raw["sampled"], raw["sampling_interval"], raw["packets"])
	}
	if _, ok := raw["estimated_packets"]; ok {
		t.Fatal("estimated_packets")
	}

	day := call(s, http.MethodGet, s.prefix+"/flows?day=2026-03-08&tz=America/New_York", nil, auth)
	if day.Code != http.StatusOK {
		t.Fatal(day.Code, day.Body.String())
	}
	body := mustJSON(t, day.Body.Bytes())
	if body["start"] != "2026-03-08T05:00:00Z" || body["end"] != "2026-03-09T04:00:00Z" || body["boundary_adjusted"] != false {
		t.Fatal(body["start"], body["end"], body["boundary_adjusted"])
	}
	bad := call(s, http.MethodGet, s.prefix+"/flows?day=2026-03-08&tz=Not/A_Zone", nil, auth)
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "bad_range") {
		t.Fatal(bad.Code, bad.Body.String())
	}
}

func TestListenLoopback(t *testing.T) {
	s, _ := newAPI(t, "/api/v1", "s3cret")
	s.listen = "127.0.0.1:0"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- s.ListenAndServe(ctx) }()
	var addr string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		addr = s.bound
		s.mu.Unlock()
		if addr != "" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("not listening")
	}
	resp, err := http.Get("http://" + addr + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal(resp.StatusCode)
	}
	if resp.Header.Get("Content-Security-Policy") != csp {
		t.Fatal(resp.Header.Get("Content-Security-Policy"))
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestStaticUINotGated(t *testing.T) {
	db := openDB(t)
	q, err := store.NewQuery(db)
	if err != nil {
		t.Fatal(err)
	}
	const marker = "VibeCollector UI shell"
	ui := fstest.MapFS{
		"index.html":    &fstest.MapFile{Data: []byte(marker)},
		"assets/app.js": &fstest.MapFile{Data: []byte("console.log(1)\n")},
	}
	s, err := NewServer(config.HTTP{
		Listen:            "127.0.0.1:0",
		APIPrefix:         "/api/v1",
		QueryCacheTTL:     15 * time.Second,
		QueryCacheEntries: 32,
	}, config.OAuth2{
		UIClientID: "vibecollector-ui",
		TokenTTL:   time.Hour,
	}, q, obs.NewCounters(), ui)
	if err != nil {
		t.Fatal(err)
	}
	index := call(s, http.MethodGet, "/", nil, nil)
	if index.Code != http.StatusOK || !strings.Contains(index.Body.String(), marker) {
		t.Fatalf("index %d %s", index.Code, index.Body.String())
	}
	flows := call(s, http.MethodGet, "/flows", nil, nil)
	if flows.Code != http.StatusOK || !strings.Contains(flows.Body.String(), marker) {
		t.Fatalf("spa %d %s", flows.Code, flows.Body.String())
	}
	js := call(s, http.MethodGet, "/assets/app.js", nil, nil)
	if js.Code != http.StatusOK || !strings.Contains(js.Body.String(), "console.log") {
		t.Fatalf("asset %d %s", js.Code, js.Body.String())
	}
	missing := call(s, http.MethodGet, "/assets/missing.js", nil, nil)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing asset %d", missing.Code)
	}
	health := call(s, http.MethodGet, "/api/v1/health", nil, nil)
	if health.Code != http.StatusUnauthorized || strings.Contains(health.Body.String(), marker) {
		t.Fatalf("health %d %s", health.Code, health.Body.String())
	}
	spec := call(s, http.MethodGet, "/openapi.json", nil, nil)
	if spec.Code != http.StatusOK || strings.Contains(spec.Body.String(), marker) || !strings.Contains(spec.Body.String(), "openapi") {
		t.Fatalf("openapi %d %s", spec.Code, spec.Body.String())
	}
}

var dataRoutes = []string{
	"health", "stats", "exporters", "flows", "timeseries", "talkers", "asns", "reputation", "geo",
}

func newAPI(t *testing.T, prefix, secret string) (*Server, *store.DB) {
	t.Helper()
	db := openDB(t)
	q, err := store.NewQuery(db)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(config.HTTP{
		Listen:            "127.0.0.1:0",
		APIPrefix:         prefix,
		QueryCacheTTL:     15 * time.Second,
		QueryCacheEntries: 32,
	}, config.OAuth2{
		UIClientID:   "vibecollector-ui",
		TokenTTL:     time.Hour,
		ClientSecret: secret,
	}, q, obs.NewCounters(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return s, db
}

func openDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(config.DB{
		Path:         filepath.Join(t.TempDir(), "t.db"),
		BusyTimeout:  5 * time.Second,
		RawRetention: 6 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func call(s *Server, method, target string, body io.Reader, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, body)
	req.Host = "127.0.0.1:8080"
	req.RemoteAddr = "127.0.0.1:9"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func pkceChallenge(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func authRedirect(t *testing.T, s *Server, redirect, host, challenge string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "vibecollector-ui")
	q.Set("redirect_uri", redirect)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("scope", "read")
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	req.Host = host
	req.RemoteAddr = "127.0.0.1:9"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func assertCoord(t *testing.T, v any, kind string, lat, lon float64) {
	t.Helper()
	p := v.(map[string]any)
	if p["kind"] != kind || p["lat"] != lat || p["lon"] != lon {
		t.Fatal(p)
	}
}

func pathHasSrc(paths []any, lat, lon float64) bool {
	for _, item := range paths {
		src, _ := item.(map[string]any)["src"].(map[string]any)
		if src["kind"] == "coord" && src["lat"] == lat && src["lon"] == lon {
			return true
		}
	}
	return false
}

func pkceToken(t *testing.T, s *Server) string {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", "vibecollector-ui")
	q.Set("redirect_uri", "http://127.0.0.1:8080/cb")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", "a b")
	q.Set("scope", "read")
	rr := call(s, http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, nil)
	if rr.Code != http.StatusFound {
		t.Fatal(rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("state") != "a b" || loc.Query().Get("code") == "" {
		t.Fatal(rr.Header().Get("Location"))
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", loc.Query().Get("code"))
	form.Set("redirect_uri", "http://127.0.0.1:8080/cb")
	form.Set("client_id", "vibecollector-ui")
	form.Set("code_verifier", verifier)
	rr = call(s, http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}
	tok := tokenOf(t, rr.Body.Bytes())
	rr = call(s, http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if rr.Code == http.StatusOK {
		t.Fatal("code reused")
	}
	return tok
}

func clientToken(t *testing.T, s *Server, secret string) string {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "vibecollector-ui")
	form.Set("client_secret", secret)
	form.Set("scope", "read")
	rr := call(s, http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if rr.Code != http.StatusOK {
		t.Fatal(rr.Code, rr.Body.String())
	}
	return tokenOf(t, rr.Body.Bytes())
}

func tokenOf(t *testing.T, b []byte) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["token_type"] != "bearer" || m["scope"] != "read" || m["access_token"] == "" {
		t.Fatal(m)
	}
	return m["access_token"].(string)
}

func assertOAuth(t *testing.T, paths map[string]any, path string) {
	t.Helper()
	item, ok := paths[path].(map[string]any)
	if !ok {
		t.Fatal("missing", path)
	}
	op := item["get"].(map[string]any)
	sec, ok := op["security"].([]any)
	if !ok || len(sec) != 1 {
		t.Fatal(path, op["security"])
	}
	flow := sec[0].(map[string]any)
	scopes, ok := flow["oauth2"].([]any)
	if !ok || len(scopes) != 1 || scopes[0] != "read" {
		t.Fatal(path, flow)
	}
}

func mustJSON(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err, string(b))
	}
	return m
}

func writeFlows(t *testing.T, db *store.DB, q *store.Query, flows []flow.Flow, start, end time.Time) {
	t.Helper()
	w, err := store.NewWriter(db, config.DB{BatchSize: 1}, obs.NewCounters())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- w.Run(ctx) }()
	if err := w.Submit(flows); err != nil {
		cancel()
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		page, err := q.Flows(context.Background(), store.Filter{Start: start, End: end, TZ: "UTC"})
		if err == nil && len(page.Flows) >= len(flows) {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("stored flows err=%v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func flowAt(start time.Time, src, dst string, port uint16, packets, octets uint64, sampled bool, interval *uint32, srcCC, dstCC, rep string) flow.Flow {
	f := flow.Flow{
		ReceivedAt:       time.Now().UTC(),
		ExportTime:       time.Now().UTC(),
		Start:            start,
		End:              start.Add(time.Second),
		Exporter:         netip.MustParseAddr("192.0.2.1"),
		Domain:           1,
		Version:          5,
		Src:              netip.MustParseAddr(src),
		Dst:              netip.MustParseAddr(dst),
		SrcPort:          port,
		DstPort:          port,
		PortsPresent:     true,
		Proto:            6,
		ProtoPresent:     true,
		Packets:          packets,
		Octets:           octets,
		CounterSemantics: "delta",
		OctetSemantics:   "ip",
		Sampled:          sampled,
		SamplingInterval: interval,
		SrcEnrich:        endpoint(src, srcCC, rep),
		DstEnrich:        endpoint(dst, dstCC, ""),
	}
	return f
}

func endpoint(ip, country, rep string) flow.Endpoint {
	addr := netip.MustParseAddr(ip)
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return flow.Endpoint{
			Scope: flow.Scope("private"),
			Geo:   flow.Outcome{Kind: flow.OutcomeSkipped},
			ASN:   flow.Outcome{Kind: flow.OutcomeSkipped},
			Rep:   flow.Outcome{Kind: flow.OutcomeSkipped},
		}
	}
	geo := flow.Outcome{Kind: flow.OutcomeNoData}
	if country != "" {
		geo = flow.Outcome{Kind: flow.OutcomeValue, Country: country}
	}
	reputation := flow.Outcome{Kind: flow.OutcomeNoData}
	if rep != "" {
		reputation = flow.Outcome{Kind: flow.OutcomeValue, Category: rep}
	}
	return flow.Endpoint{Scope: "global", Geo: geo, ASN: flow.Outcome{Kind: flow.OutcomeNoData}, Rep: reputation}
}

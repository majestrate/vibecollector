package config

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cfg.toml")
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func inTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(wd); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func TestUnknownField(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"udp typo", "[udp]\nlitsen = \"0.0.0.0:2055\"\n"},
		{"enrich sibling", "[enrich.other]\nenable = true\n"},
		{"enrich key", "[enrich]\nnot_a_key = 1\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, tc.body, 0o600)
			_, err := Load(Flags{ConfigPath: path})
			if !errors.Is(err, ErrUnknownField) {
				t.Fatalf("err = %v", err)
			}
			if errors.Is(err, ErrBadConfig) {
				t.Fatalf("wrong sentinel: %v", err)
			}
		})
	}
}

func TestUnknownFieldOmitsNeighborValues(t *testing.T) {
	body := `
[http]
token = "super-secret-token"
listen = "127.0.0.1:8080"
not_a_field = true
[udp]
template_idle_timeout = "30m"
litsen = "0.0.0.0:2055"
`
	path := writeConfig(t, body, 0o600)
	_, err := Load(Flags{ConfigPath: path})
	if !errors.Is(err, ErrUnknownField) {
		t.Fatalf("err = %v", err)
	}
	msg := err.Error()
	if strings.Contains(msg, "super-secret-token") {
		t.Fatalf("token leaked: %s", msg)
	}
	if strings.Contains(msg, "1800000000000") {
		t.Fatalf("rewritten duration leaked: %s", msg)
	}
	if !strings.Contains(msg, "http.not_a_field: unknown field") {
		t.Fatalf("missing field detail: %s", msg)
	}
	if !strings.Contains(msg, "udp.litsen: unknown field") {
		t.Fatalf("missing udp detail: %s", msg)
	}
}

func TestReservedEnrichTables(t *testing.T) {
	body := `
[enrich.geoip]
path = "/no/such/geoip.mmdb"
geoip_ttl = "1s"
enable = true

[enrich.asn]
url = "https://example.invalid/asn"

[enrich.reputation]
token = "not-a-real-token"
`
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	path := writeConfig(t, body, 0o600)
	cfg, err := Load(Flags{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enrich.GeoIPTTL != 24*time.Hour {
		t.Fatalf("geoip ttl %s", cfg.Enrich.GeoIPTTL)
	}
	if cfg.Enrich.ASNTTL != 24*time.Hour || cfg.Enrich.ReputationTTL != time.Hour {
		t.Fatalf("ttl asn=%s rep=%s", cfg.Enrich.ASNTTL, cfg.Enrich.ReputationTTL)
	}
	want := []string{"geoip", "asn", "reputation"}
	if !slices.Equal(cfg.ReservedSeen, want) {
		t.Fatalf("ReservedSeen = %v", cfg.ReservedSeen)
	}
	if buf.Len() != 0 {
		t.Fatalf("Load logged %s", buf.String())
	}
}

func TestReservedSeenShapes(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"empty table", "[enrich.geoip]\n", []string{"geoip"}},
		{"child table", "[enrich.geoip.child]\npath = \"/x\"\n", []string{"geoip"}},
		{"array table", "[[enrich.asn]]\nurl = \"https://example.invalid\"\n", []string{"asn"}},
		{"inline", "enrich = { reputation = { token = \"t\" } }\n", []string{"reputation"}},
		{"empty inline", "[enrich]\ngeoip = {}\n", []string{"geoip"}},
		{"dotted", "enrich.asn.url = \"https://example.invalid\"\n", []string{"asn"}},
		{"ttl is not a table", "[enrich]\ngeoip_ttl = \"1h\"\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, tc.body, 0o600)
			cfg, err := Load(Flags{ConfigPath: path})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(cfg.ReservedSeen, tc.want) {
				t.Fatalf("ReservedSeen = %#v, want %#v", cfg.ReservedSeen, tc.want)
			}
		})
	}
}

func TestListenToken(t *testing.T) {
	cases := []struct {
		name   string
		listen string
		token  string
		want   error
	}{
		{"v4 loopback", "127.0.0.1:8080", "", nil},
		{"v4 loopback slash8", "127.1.2.3:8080", "", nil},
		{"v6 loopback", "[::1]:8080", "", nil},
		{"unspecified v4", "0.0.0.0:8080", "", nil},
		{"unspecified v4 token", "0.0.0.0:8080", "secret", nil},
		{"unspecified v6", "[::]:8080", "", nil},
		{"public", "203.0.113.4:8080", "", nil},
		{"public token", "203.0.113.4:8080", "secret", nil},
		{"localhost", "localhost:8080", "", nil},
		{"localhost token", "localhost:8080", "secret", nil},
		{"missing port", "127.0.0.1", "", ErrBadConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := "[http]\nlisten = \"" + tc.listen + "\"\ntoken = \"" + tc.token + "\"\n"
			path := writeConfig(t, body, 0o600)
			cfg, err := Load(Flags{ConfigPath: path})
			if tc.want == nil {
				if err != nil {
					t.Fatal(err)
				}
				if cfg.HTTP.Listen != tc.listen || cfg.HTTP.Token != tc.token {
					t.Fatalf("listen=%q token=%q", cfg.HTTP.Listen, cfg.HTTP.Token)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestPublicHost(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		issuer string
		base   string
		want   error
	}{
		{"unspecified v4", "[http]\nlisten = \"0.0.0.0:8080\"\n", "", "/", nil},
		{"unspecified v6", "[http]\nlisten = \"[::]:8080\"\n", "", "/", nil},
		{"public host takes listen port", "[http]\nlisten = \"0.0.0.0:8080\"\npublic_host = \"10.1.0.232\"\n", "http://10.1.0.232:8080", "/", nil},
		{"public host keeps its port", "[http]\nlisten = \"0.0.0.0:8080\"\npublic_host = \"collector.example:8443\"\n", "http://collector.example:8443", "/", nil},
		{"public ipv6", "[http]\nlisten = \"[::]:8080\"\npublic_host = \"[2001:db8::1]\"\n", "http://[2001:db8::1]:8080", "/", nil},
		{"specific listen", "[http]\nlisten = \"203.0.113.4:9\"\n", "http://203.0.113.4:9", "/", nil},
		{"explicit issuer wins", "[http]\nlisten = \"0.0.0.0:8080\"\npublic_host = \"10.1.0.232\"\n[oauth2]\nissuer = \"https://collector.example\"\n", "https://collector.example", "/", nil},
		{"absolute url", "[http]\nlisten = \"127.0.0.1:8080\"\npublic_host = \"https://collector.example/app\"\n", "https://collector.example/app", "/app", nil},
		{"absolute url trailing slash", "[http]\nlisten = \"127.0.0.1:8080\"\npublic_host = \"https://collector.example/app/\"\n", "https://collector.example/app", "/app", nil},
		{"absolute origin", "[http]\nlisten = \"0.0.0.0:8080\"\npublic_host = \"http://example.com\"\n", "http://example.com", "/", nil},
		{"absolute url keeps explicit issuer", "[http]\nlisten = \"127.0.0.1:8080\"\npublic_host = \"https://collector.example/app\"\n[oauth2]\nissuer = \"https://collector.example\"\n", "https://collector.example", "/app", nil},
		{"wildcard public host", "[http]\npublic_host = \"0.0.0.0\"\n", "", "", ErrBadConfig},
		{"wildcard public v6", "[http]\npublic_host = \"[::]\"\n", "", "", ErrBadConfig},
		{"wildcard in url", "[http]\npublic_host = \"http://0.0.0.0/app\"\n", "", "", ErrBadConfig},
		{"public host with path", "[http]\npublic_host = \"example.com/api\"\n", "", "", ErrBadConfig},
		{"public url query", "[http]\npublic_host = \"https://example.com/app?x=1\"\n", "", "", ErrBadConfig},
		{"public url user", "[http]\npublic_host = \"https://user:pw@example.com/app\"\n", "", "", ErrBadConfig},
		{"public url dotdot", "[http]\npublic_host = \"https://example.com/app/../x\"\n", "", "", ErrBadConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, tc.body, 0o600)
			cfg, err := Load(Flags{ConfigPath: path})
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("err = %v, want %v", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.OAuth2.Issuer != tc.issuer {
				t.Fatalf("issuer %q", cfg.OAuth2.Issuer)
			}
			if cfg.HTTP.BasePath != tc.base {
				t.Fatalf("base %q", cfg.HTTP.BasePath)
			}
		})
	}
}

func TestLooseFileMode(t *testing.T) {
	path := writeConfig(t, "[log]\nlevel = \"info\"\n", 0o644)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	cfg, err := Load(Flags{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.LooseFileMode {
		t.Fatal("LooseFileMode false")
	}
	fi, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode changed to %o", fi.Mode().Perm())
	}

	tight := writeConfig(t, "", 0o600)
	cfg, err = Load(Flags{ConfigPath: tight})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LooseFileMode {
		t.Fatal("0600 set LooseFileMode")
	}
}

func TestDefaults(t *testing.T) {
	inTempDir(t)
	cfg, err := Load(Flags{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LooseFileMode {
		t.Fatal("no file should not be loose")
	}
	if cfg.UDP.Listen != "0.0.0.0:2055" ||
		cfg.UDP.ReadBufferBytes != 16777216 ||
		cfg.UDP.DatagramQueue != 8192 ||
		cfg.UDP.FlowQueue != 200000 ||
		cfg.UDP.WriterQueue != 80000 ||
		cfg.UDP.TemplateIdle != 30*time.Minute ||
		cfg.UDP.HoldPerExporter != 256 ||
		cfg.UDP.HoldGlobal != 4096 ||
		cfg.UDP.TimestampMaxAge != 2*time.Hour ||
		cfg.UDP.TimestampSkewSlack != 5*time.Second {
		t.Fatalf("udp defaults: %+v", cfg.UDP)
	}
	if cfg.HTTP.Listen != "127.0.0.1:8080" ||
		cfg.HTTP.Token != "" ||
		cfg.HTTP.APIPrefix != "/api/v1" ||
		cfg.HTTP.QueryCacheTTL != 15*time.Second ||
		cfg.HTTP.QueryCacheEntries != 256 {
		t.Fatalf("http defaults: %+v", cfg.HTTP)
	}
	if cfg.OAuth2.Issuer != "http://127.0.0.1:8080" ||
		cfg.OAuth2.TokenTTL != time.Hour ||
		cfg.OAuth2.RefreshTTL != 24*time.Hour {
		t.Fatalf("oauth defaults: %+v", cfg.OAuth2)
	}
	if cfg.DB.Path != "vibecollector.db" ||
		cfg.DB.BusyTimeout != 5*time.Second ||
		cfg.DB.BatchSize != 2000 ||
		cfg.DB.BatchInterval != 500*time.Millisecond ||
		cfg.DB.RawRetention != 6*time.Hour ||
		cfg.DB.RollupRetention != 720*time.Hour {
		t.Fatalf("db defaults: %+v", cfg.DB)
	}
	if cfg.Enrich.GeoIPTTL != 24*time.Hour ||
		cfg.Enrich.ASNTTL != 24*time.Hour ||
		cfg.Enrich.ReputationTTL != time.Hour ||
		cfg.Enrich.LookupTimeout != 500*time.Millisecond ||
		cfg.Enrich.CacheEntries != 100000 {
		t.Fatalf("enrich defaults: %+v", cfg.Enrich)
	}
	if cfg.Log.Level != "info" {
		t.Fatalf("level %s", cfg.Log.Level)
	}
}

func TestDefaultFileAndFlags(t *testing.T) {
	dir := inTempDir(t)
	body := `
[udp]
listen = "127.0.0.1:2055"
[http]
listen = "0.0.0.0:8080"
token = ""
[db]
path = "from-file.db"
raw_retention = "1m"
rollup_retention = "1h"
[log]
level = "debug"
`
	if err := os.WriteFile(filepath.Join(dir, "vibecollector.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(Flags{HTTP: "127.0.0.1:9090", UDP: "10.0.0.1:2055", DB: "from-flag.db"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Log.Level != "debug" {
		t.Fatalf("default file not read, level %s", cfg.Log.Level)
	}
	if cfg.HTTP.Listen != "127.0.0.1:9090" || cfg.UDP.Listen != "10.0.0.1:2055" || cfg.DB.Path != "from-flag.db" {
		t.Fatalf("flags: http=%s udp=%s db=%s", cfg.HTTP.Listen, cfg.UDP.Listen, cfg.DB.Path)
	}
	if cfg.OAuth2.Issuer != "http://127.0.0.1:9090" {
		t.Fatalf("issuer %s", cfg.OAuth2.Issuer)
	}
	if cfg.UDP.DatagramQueue != 8192 {
		t.Fatalf("absent queue = %d", cfg.UDP.DatagramQueue)
	}
	if cfg.DB.RawRetention != time.Minute || cfg.DB.RollupRetention != time.Hour {
		t.Fatalf("retention raw=%s rollup=%s", cfg.DB.RawRetention, cfg.DB.RollupRetention)
	}
}

func TestDurationStrings(t *testing.T) {
	body := `
[udp]
template_idle_timeout = "45m"
timestamp_max_age = "3h"
timestamp_skew_slack = "1500ms"
[http]
query_cache_ttl = "2s"
[db]
busy_timeout = "2s"
batch_interval = "250ms"
raw_retention = "90m"
rollup_retention = "48h"
[enrich]
geoip_ttl = "12h"
asn_ttl = "36h"
reputation_ttl = "30m"
lookup_timeout = "1s"
`
	path := writeConfig(t, body, 0o600)
	cfg, err := Load(Flags{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UDP.TemplateIdle != 45*time.Minute ||
		cfg.UDP.TimestampMaxAge != 3*time.Hour ||
		cfg.UDP.TimestampSkewSlack != 1500*time.Millisecond ||
		cfg.HTTP.QueryCacheTTL != 2*time.Second ||
		cfg.DB.BusyTimeout != 2*time.Second ||
		cfg.DB.BatchInterval != 250*time.Millisecond ||
		cfg.DB.RawRetention != 90*time.Minute ||
		cfg.DB.RollupRetention != 48*time.Hour ||
		cfg.Enrich.GeoIPTTL != 12*time.Hour ||
		cfg.Enrich.ASNTTL != 36*time.Hour ||
		cfg.Enrich.ReputationTTL != 30*time.Minute ||
		cfg.Enrich.LookupTimeout != time.Second {
		t.Fatalf("durations: udp=%+v http=%+v db=%+v enrich=%+v", cfg.UDP, cfg.HTTP, cfg.DB, cfg.Enrich)
	}

	inline := "db = { raw_retention = \"2h\", rollup_retention = \"2h\" }\n"
	path = writeConfig(t, inline, 0o600)
	cfg, err = Load(Flags{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DB.RawRetention != 2*time.Hour || cfg.DB.RollupRetention != 2*time.Hour {
		t.Fatalf("inline raw=%s rollup=%s", cfg.DB.RawRetention, cfg.DB.RollupRetention)
	}
}

func TestBadConfig(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"duration", "[db]\nraw_retention = \"nope\"\n"},
		{"negative duration", "[udp]\ntimestamp_skew_slack = \"-1s\"\n"},
		{"raw retention", "[db]\nraw_retention = \"30s\"\n"},
		{"rollup retention", "[db]\nrollup_retention = \"30m\"\n"},
		{"queue", "[udp]\ndatagram_queue = -1\n"},
		{"level", "[log]\nlevel = \"warning\"\n"},
		{"duration int", "[udp]\ntemplate_idle_timeout = 30\n"},
		{"duration int busy", "[db]\nbusy_timeout = 5\n"},
		{"duration hex", "[udp]\ntimestamp_skew_slack = 0x5\n"},
		{"duration underscores", "[http]\nquery_cache_ttl = 1_000\n"},
		{"duration float", "[udp]\ntemplate_idle_timeout = 1.5\n"},
		{"duration bool", "[http]\nquery_cache_ttl = true\n"},
		{"duration int ns", "[db]\nraw_retention = 60000000000\n"},
		{"inline duration int", "db = { raw_retention = 60 }\n"},
		{"zero datagram queue", "[udp]\ndatagram_queue = 0\n"},
		{"zero flow queue", "[udp]\nflow_queue = 0\n"},
		{"zero writer queue", "[udp]\nwriter_queue = 0\n"},
		{"zero queue hex", "[udp]\ndatagram_queue = 0x0\n"},
		{"zero queue octal", "[udp]\nflow_queue = 0o0\n"},
		{"zero queue binary", "[udp]\nwriter_queue = 0b0\n"},
		{"zero queue plus", "[udp]\ndatagram_queue = +0\n"},
		{"zero queue underscores", "[udp]\ndatagram_queue = 0_0\n"},
		{"inline zero queue", "udp = { datagram_queue = 0 }\n"},
		{"zero raw retention", "[db]\nraw_retention = \"0s\"\n"},
		{"negative zero raw", "[db]\nraw_retention = \"-0s\"\n"},
		{"zero rollup retention", "[db]\nrollup_retention = \"0h\"\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, tc.body, 0o600)
			_, err := Load(Flags{ConfigPath: path})
			if !errors.Is(err, ErrBadConfig) {
				t.Fatalf("err = %v", err)
			}
			if errors.Is(err, ErrUnknownField) {
				t.Fatalf("wrong sentinel: %v", err)
			}
		})
	}
}

func TestExplicitZeroWithoutMinimumUsesDefault(t *testing.T) {
	body := "[db]\nbusy_timeout = \"0s\"\n[udp]\ntemplate_idle_timeout = \"0s\"\n"
	path := writeConfig(t, body, 0o600)
	cfg, err := Load(Flags{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DB.BusyTimeout != 5*time.Second {
		t.Fatalf("busy_timeout %s", cfg.DB.BusyTimeout)
	}
	if cfg.UDP.TemplateIdle != 30*time.Minute {
		t.Fatalf("template idle %s", cfg.UDP.TemplateIdle)
	}
}

func TestExplicitQueueKept(t *testing.T) {
	body := "[udp]\ndatagram_queue = 1\nflow_queue = 2\nwriter_queue = 3\n"
	path := writeConfig(t, body, 0o600)
	cfg, err := Load(Flags{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UDP.DatagramQueue != 1 || cfg.UDP.FlowQueue != 2 || cfg.UDP.WriterQueue != 3 {
		t.Fatalf("queues %+v", cfg.UDP)
	}
}

func TestAPIPrefixAndOAuth(t *testing.T) {
	path := writeConfig(t, "[http]\napi_prefix = \"\"\n[oauth2]\ntoken_ttl = \"0s\"\n", 0o600)
	cfg, err := Load(Flags{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.APIPrefix != "/api/v1" || cfg.OAuth2.TokenTTL != time.Hour || cfg.OAuth2.RefreshTTL != 24*time.Hour {
		t.Fatalf("%+v %+v", cfg.HTTP, cfg.OAuth2)
	}
	path = writeConfig(t, "[http]\napi_prefix = \"/collector/v1\"\n[oauth2]\nissuer = \"http://collector.example\"\ntoken_ttl = \"15m\"\n", 0o600)
	cfg, err = Load(Flags{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.APIPrefix != "/collector/v1" || cfg.OAuth2.Issuer != "http://collector.example" || cfg.OAuth2.TokenTTL != 15*time.Minute || cfg.OAuth2.RefreshTTL != 24*time.Hour {
		t.Fatalf("%+v %+v", cfg.HTTP, cfg.OAuth2)
	}
	bad := []string{
		"[http]\napi_prefix = \"api/v1\"\n",
		"[http]\napi_prefix = \"/api/v1/\"\n",
		"[http]\napi_prefix = \"/api//v1\"\n",
		"[http]\napi_prefix = \"/api/../v1\"\n",
		"[http]\napi_prefix = \"/api/v1?x\"\n",
		"[http]\napi_prefix = \"/api/v1#x\"\n",
		"[oauth2]\ntoken_ttl = \"-1s\"\n",
		"[oauth2]\ntoken_ttl = 60\n",
		"[oauth2]\nrefresh_ttl = \"-1s\"\n",
		"[oauth2]\nrefresh_ttl = 60\n",
		"[oauth2]\nrefresh_ttl = \"30m\"\n",
		"[oauth2]\ntoken_ttl = \"48h\"\nrefresh_ttl = \"24h\"\n",
	}
	for _, body := range bad {
		path = writeConfig(t, body, 0o600)
		_, err = Load(Flags{ConfigPath: path})
		if !errors.Is(err, ErrBadConfig) {
			t.Fatalf("%q err = %v", body, err)
		}
	}
	body := "[oauth2]\nclient_secret = \"super-secret-token\"\nnot_a_field = true\n"
	path = writeConfig(t, body, 0o600)
	_, err = Load(Flags{ConfigPath: path})
	if !errors.Is(err, ErrUnknownField) {
		t.Fatal(err)
	}
	if strings.Contains(err.Error(), "super-secret-token") {
		t.Fatal(err)
	}
}

func TestMissingExplicitFile(t *testing.T) {
	_, err := Load(Flags{ConfigPath: filepath.Join(t.TempDir(), "missing.toml")})
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, ErrBadConfig) || errors.Is(err, ErrUnknownField) {
		t.Fatalf("missing file wrapped as sentinel: %v", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v", err)
	}
}

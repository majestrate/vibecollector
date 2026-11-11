// Package config loads the process configuration from TOML, defaults, and flags.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

var (
	// ErrUnknownField means the TOML document contains a key that is not a
	// documented field. A typo under [udp] and an unknown sibling of [enrich]
	// both produce an error wrapping ErrUnknownField. A child key of
	// [enrich.geoip], [enrich.asn], or [enrich.reputation] does not.
	// errors.Is is how a caller tells this apart from the other sentinels.
	ErrUnknownField = errors.New("unknown configuration field")

	// ErrBadConfig means a duration is invalid, including a non-string value,
	// a negative duration, db.raw_retention is under 1 minute,
	// db.rollup_retention is under 1 hour, a queue depth is under 1,
	// including an explicit zero, log.level is not debug, info, warn, or
	// error, http.listen is not host:port, http.public_host is not a host
	// or host:port, or http.api_prefix is not an absolute path.
	// errors.Is reports this sentinel.
	ErrBadConfig = errors.New("invalid configuration")
)

// Flags are the process overrides. An empty string means the flag was not set.
// ConfigPath empty means Load opens ./vibecollector.toml when that file exists
// and otherwise uses built-in defaults. HTTP, UDP, and DB, when non-empty,
// replace http.listen, udp.listen, and db.path after the file is decoded.
type Flags struct {
	ConfigPath string
	HTTP       string
	UDP        string
	DB         string
}

// Config is the process configuration after defaults and flag overrides.
// Every TOML field has a toml tag equal to the key in the Configuration section.
// LooseFileMode is true when a config file was opened and its mode has
// perm&0077 != 0. That is not a load error. main logs a warning.
// It is not a file key (`toml:"-"`).
// ReservedSeen names the reserved enrich tables present in the file:
// "geoip", "asn", and "reputation", in that order. An absent table is
// omitted. It is not a file key. main logs "enrich.<name>: reserved table, ignored"
// for each name. Load does not log.
type Config struct {
	UDP           UDP      `toml:"udp"`
	HTTP          HTTP     `toml:"http"`
	OAuth2        OAuth2   `toml:"oauth2"`
	DB            DB       `toml:"db"`
	Enrich        Enrich   `toml:"enrich"`
	Log           Log      `toml:"log"`
	LooseFileMode bool     `toml:"-"`
	ReservedSeen  []string `toml:"-"`
}

// UDP is the socket and the queue depths. Listen is host:port.
// ReadBufferBytes is the requested SO_RCVBUF. DatagramQueue, FlowQueue, and
// WriterQueue are channel capacities. FlowQueue is the decoded-flow channel
// main creates. DatagramQueue is not the burst absorber.
// TemplateIdle is exporter silence, not a template TTL.
// TimestampMaxAge and TimestampSkewSlack bound the receive-time clamp.
type UDP struct {
	Listen             string        `toml:"listen"`
	ReadBufferBytes    int           `toml:"read_buffer_bytes"`
	DatagramQueue      int           `toml:"datagram_queue"`
	FlowQueue          int           `toml:"flow_queue"`
	WriterQueue        int           `toml:"writer_queue"`
	TemplateIdle       time.Duration `toml:"template_idle_timeout"`
	HoldPerExporter    int           `toml:"hold_packets_per_exporter"`
	HoldGlobal         int           `toml:"hold_packets_global"`
	TimestampMaxAge    time.Duration `toml:"timestamp_max_age"`
	TimestampSkewSlack time.Duration `toml:"timestamp_skew_slack"`
}

// HTTP is the API listener. Token is accepted and ignored. It is not the
// API gate. Listen is the socket, host:port. PublicHost is the host clients
// use to reach that socket. It is a hostname or host:port, with no scheme.
// An empty PublicHost means a specific Listen address is the public host.
// 0.0.0.0 and :: are bind addresses and are not a public host.
// APIPrefix is the REST mount. An empty value means /api/v1.
// QueryCacheTTL and QueryCacheEntries size the API response cache.
type HTTP struct {
	Listen            string        `toml:"listen"`
	PublicHost        string        `toml:"public_host"`
	Token             string        `toml:"token"`
	APIPrefix         string        `toml:"api_prefix"`
	QueryCacheTTL     time.Duration `toml:"query_cache_ttl"`
	QueryCacheEntries int           `toml:"query_cache_entries"`
}

// OAuth2 is the daemon's own authorization server for this UI.
// There is no external IdP. Issuer is an allowed origin for the
// authorization redirect. When it is empty, Load sets it to http:// plus
// http.public_host, or to http:// plus a specific http.listen. An
// unspecified listen address does not become the issuer. The browser client
// id is the fixed public client vibecollector-ui and is not a config field. Confidential client
// ids and secrets are rows in the database, managed outside this file.
// TokenTTL is the access-token lifetime. RefreshTTL is the refresh-token
// lifetime and must be longer than TokenTTL.
type OAuth2 struct {
	Issuer     string        `toml:"issuer"`
	TokenTTL   time.Duration `toml:"token_ttl"`
	RefreshTTL time.Duration `toml:"refresh_ttl"`
}

// DB is the SQLite file and the writer batch. BusyTimeout is also the DSN
// busy_timeout. RawRetention and RollupRetention are the sweeper horizons.
type DB struct {
	Path            string        `toml:"path"`
	BusyTimeout     time.Duration `toml:"busy_timeout"`
	BatchSize       int           `toml:"batch_size"`
	BatchInterval   time.Duration `toml:"batch_interval"`
	RawRetention    time.Duration `toml:"raw_retention"`
	RollupRetention time.Duration `toml:"rollup_retention"`
}

// Enrich is the cache policy. The three TTL fields apply to not_configured,
// no_data, and value. Lookup errors use a fixed one-minute TTL inside the cache.
// GeoIP, ASN, and Reputation are the reserved nested tables [enrich.geoip],
// [enrich.asn], and [enrich.reputation]. They are not enable flags.
type Enrich struct {
	GeoIPTTL      time.Duration `toml:"geoip_ttl"`
	ASNTTL        time.Duration `toml:"asn_ttl"`
	ReputationTTL time.Duration `toml:"reputation_ttl"`
	LookupTimeout time.Duration `toml:"lookup_timeout"`
	CacheEntries  int           `toml:"cache_entries_per_provider"`
	GeoIP         ReservedTable `toml:"geoip"`
	ASN           ReservedTable `toml:"asn"`
	Reputation    ReservedTable `toml:"reputation"`
}

// Log is the slog level name: debug, info, warn, or error.
type Log struct {
	Level string `toml:"level"`
}

// ReservedTable is a nested table whose child keys are discarded.
// The hook is unstable.Unmarshaler: (*ReservedTable).UnmarshalTOML([]byte) error.
// Load calls Decoder.EnableUnmarshalerInterface before
// DisallowUnknownFields().Decode. v2.4.3 invokes the method only after that call.
// A child of [enrich.geoip], [enrich.asn], or [enrich.reputation] loads and is ignored.
// A typo under [udp] is still ErrUnknownField.
// The table is not an enable flag. Load does not open a path or a URL from it.
type ReservedTable struct{}

// UnmarshalTOML discards the raw table bytes and returns nil.
// The receiver is a pointer. The argument is the raw TOML of the table.
// It does not return ErrUnknownField. A child key is not an error.
// The decoder calls this only after EnableUnmarshalerInterface.
func (t *ReservedTable) UnmarshalTOML([]byte) error { return nil }

// Load reads TOML, applies defaults, then applies flags.
// flags.ConfigPath is the file path. An empty ConfigPath opens
// ./vibecollector.toml when that file exists and otherwise uses built-in
// defaults. flags.HTTP, flags.UDP, and flags.DB override http.listen,
// udp.listen, and db.path when non-empty.
// It returns the Config the rest of the process uses.
// The decoder is pelletier/go-toml/v2 v2.4.3. Load calls
// EnableUnmarshalerInterface on that decoder, then DisallowUnknownFields().Decode.
// It returns an error that wraps ErrUnknownField when a key is unknown,
// including a typo under [udp] or an unknown sibling of [enrich].
// A child key of [enrich.geoip], [enrich.asn], or [enrich.reputation] is
// discarded by (*ReservedTable).UnmarshalTOML([]byte) error and is not an error.
// When one of those tables is present, Load records its name on
// Config.ReservedSeen ("geoip", "asn", "reputation", in that order) and does
// not log. main logs "enrich.<name>: reserved table, ignored".
// http.token is accepted and ignored. An empty token is not an error, on
// loopback or any other listen address. http.public_host is the host
// clients use. It is a hostname or host:port. An omitted port uses the
// http.listen port. 0.0.0.0 and :: are rejected there. [oauth2] is a known
// table. An empty issuer becomes http:// plus that public host when one is
// known, after flag overrides. An unspecified http.listen with an empty
// public_host leaves the issuer empty. token_ttl defaults to 1h, and
// refresh_ttl defaults to 24h. refresh_ttl must be longer than token_ttl.
// ui_client_id and client_secret are unknown keys.
// http.api_prefix defaults to /api/v1 when omitted or empty.
// It returns ErrBadConfig when a duration is invalid, including a
// non-string value, a negative duration, or an explicit zero on a retention
// that has a minimum, a queue depth is less than 1, including an explicit
// zero, log.level is not a known name, http.listen is not host:port,
// http.public_host is not a host or host:port, or http.api_prefix is
// not an absolute path.
// A missing default file is not an error. A missing file named by ConfigPath,
// or a file that cannot be read, is returned unwrapped and is not one of the
// two sentinels.
// Load does not bind a socket and does not open the database.
func Load(flags Flags) (*Config, error) {
	data, opened, loose, err := readConfig(flags.ConfigPath)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if opened {
		if err := decode(data, cfg); err != nil {
			return nil, err
		}
		cfg.LooseFileMode = loose
	}
	applyDefaults(cfg)
	applyFlags(cfg, flags)
	applyIssuer(cfg)
	if err := validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func readConfig(path string) ([]byte, bool, bool, error) {
	explicit := path != ""
	if !explicit {
		path = "./vibecollector.toml"
	}
	f, err := os.Open(path)
	if err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			return nil, false, false, nil
		}
		return nil, false, false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, false, false, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, false, false, err
	}
	loose := fi.Mode().Perm()&0o077 != 0
	return data, true, loose, nil
}

func decode(data []byte, cfg *Config) error {
	rewritten, seen, err := rewriteDurations(data)
	if err != nil {
		return err
	}
	dec := toml.NewDecoder(bytes.NewReader(rewritten))
	err = dec.EnableUnmarshalerInterface().DisallowUnknownFields().Decode(cfg)
	if err != nil {
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			return fmt.Errorf("%w: %s", ErrUnknownField, strictDetail(strict))
		}
		return fmt.Errorf("%w: %v", ErrBadConfig, err)
	}
	cfg.ReservedSeen = seen
	return nil
}

// strictDetail names each unknown key and the short reason.
// It does not include a document window or any other key's value.
func strictDetail(strict *toml.StrictMissingError) string {
	if len(strict.Errors) == 0 {
		return strict.Error()
	}
	parts := make([]string, 0, len(strict.Errors))
	for i := range strict.Errors {
		e := &strict.Errors[i]
		msg := strings.TrimPrefix(e.Error(), "toml: ")
		key := strings.Join(e.Key(), ".")
		if key == "" {
			parts = append(parts, msg)
			continue
		}
		parts = append(parts, key+": "+msg)
	}
	return strings.Join(parts, "; ")
}

// durationKeys are the TOML paths whose values are Go durations.
// time.Duration has no UnmarshalText in this toolchain, so a quoted duration
// is rewritten to a nanosecond integer before the struct decode.
var durationKeys = map[string]struct{}{
	"udp.template_idle_timeout": {},
	"udp.timestamp_max_age":     {},
	"udp.timestamp_skew_slack":  {},
	"http.query_cache_ttl":      {},
	"oauth2.token_ttl":          {},
	"oauth2.refresh_ttl":        {},
	"db.busy_timeout":           {},
	"db.batch_interval":         {},
	"db.raw_retention":          {},
	"db.rollup_retention":       {},
	"enrich.geoip_ttl":          {},
	"enrich.asn_ttl":            {},
	"enrich.reputation_ttl":     {},
	"enrich.lookup_timeout":     {},
}

// queueKeys are channel depths. An explicit integer 0 is ErrBadConfig.
// Absent keys stay zero and take the default.
var queueKeys = map[string]struct{}{
	"udp.datagram_queue": {},
	"udp.flow_queue":     {},
	"udp.writer_queue":   {},
}

type durationRepl struct {
	off  int
	end  int
	text string
}

// fileWalk is the one pass over the document: duration rewrites and which
// reserved enrich tables were present. ReservedTable itself stays empty.
type fileWalk struct {
	reps       []durationRepl
	geoip      bool
	asn        bool
	reputation bool
}

func (w *fileWalk) noteReserved(parts []string) {
	if len(parts) < 2 || parts[0] != "enrich" {
		return
	}
	switch parts[1] {
	case "geoip":
		w.geoip = true
	case "asn":
		w.asn = true
	case "reputation":
		w.reputation = true
	}
}

func (w *fileWalk) seen() []string {
	var names []string
	if w.geoip {
		names = append(names, "geoip")
	}
	if w.asn {
		names = append(names, "asn")
	}
	if w.reputation {
		names = append(names, "reputation")
	}
	return names
}

func rewriteDurations(data []byte) ([]byte, []string, error) {
	p := &unstable.Parser{}
	p.Reset(data)
	var w fileWalk
	var table []string
	for p.NextExpression() {
		expr := p.Expression()
		switch expr.Kind {
		case unstable.Table, unstable.ArrayTable:
			table = append([]string(nil), keyParts(expr)...)
			w.noteReserved(table)
		case unstable.KeyValue:
			if err := w.collect(expr, table); err != nil {
				return nil, nil, err
			}
		}
	}
	if p.Error() != nil {
		return data, w.seen(), nil
	}
	if len(w.reps) == 0 {
		return data, w.seen(), nil
	}
	sort.Slice(w.reps, func(i, j int) bool { return w.reps[i].off > w.reps[j].off })
	out := data
	for _, r := range w.reps {
		next := make([]byte, 0, len(out)-(r.end-r.off)+len(r.text))
		next = append(next, out[:r.off]...)
		next = append(next, r.text...)
		next = append(next, out[r.end:]...)
		out = next
	}
	return out, w.seen(), nil
}

func (w *fileWalk) collect(kv *unstable.Node, prefix []string) error {
	parts := append(append([]string{}, prefix...), keyParts(kv)...)
	w.noteReserved(parts)
	val := kv.Value()
	full := strings.Join(parts, ".")
	_, isDur := durationKeys[full]
	switch val.Kind {
	case unstable.String:
		if !isDur {
			return nil
		}
		d, err := time.ParseDuration(string(val.Data))
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrBadConfig, full, err)
		}
		if d == 0 {
			if min := durationMin(full); min > 0 {
				return fmt.Errorf("%w: %s: shorter than %s", ErrBadConfig, full, min)
			}
		}
		w.reps = append(w.reps, durationRepl{
			off:  int(val.Raw.Offset),
			end:  int(val.Raw.Offset) + int(val.Raw.Length),
			text: strconv.FormatInt(int64(d), 10),
		})
	case unstable.InlineTable:
		if isDur {
			return fmt.Errorf("%w: %s: duration must be a string", ErrBadConfig, full)
		}
		for it := val.Children(); it.Next(); {
			child := it.Node()
			if child.Kind != unstable.KeyValue {
				continue
			}
			if err := w.collect(child, parts); err != nil {
				return err
			}
		}
	case unstable.Integer:
		if isDur {
			return fmt.Errorf("%w: %s: duration must be a string", ErrBadConfig, full)
		}
		if _, ok := queueKeys[full]; ok {
			n, err := tomlInteger(val.Data)
			if err == nil && n == 0 {
				return fmt.Errorf("%w: %s", ErrBadConfig, full)
			}
		}
	default:
		if isDur {
			return fmt.Errorf("%w: %s: duration must be a string", ErrBadConfig, full)
		}
	}
	return nil
}

func durationMin(path string) time.Duration {
	switch path {
	case "db.raw_retention":
		return time.Minute
	case "db.rollup_retention":
		return time.Hour
	default:
		return 0
	}
}

func tomlInteger(data []byte) (int64, error) {
	s := strings.ReplaceAll(string(data), "_", "")
	return strconv.ParseInt(s, 0, 64)
}

func keyParts(n *unstable.Node) []string {
	var parts []string
	it := n.Key()
	for it.Next() {
		parts = append(parts, string(it.Node().Data))
	}
	return parts
}

// Zero means the key was absent. An explicit zero duration whose minimum is
// 0 also arrives here as zero and takes the default. Explicit zero queues
// and explicit zero retentions that have a minimum are ErrBadConfig earlier.
func applyDefaults(c *Config) {
	if c.UDP.Listen == "" {
		c.UDP.Listen = "0.0.0.0:2055"
	}
	if c.UDP.ReadBufferBytes == 0 {
		c.UDP.ReadBufferBytes = 16777216
	}
	if c.UDP.DatagramQueue == 0 {
		c.UDP.DatagramQueue = 8192
	}
	if c.UDP.FlowQueue == 0 {
		c.UDP.FlowQueue = 200000
	}
	if c.UDP.WriterQueue == 0 {
		c.UDP.WriterQueue = 80000
	}
	if c.UDP.TemplateIdle == 0 {
		c.UDP.TemplateIdle = 30 * time.Minute
	}
	if c.UDP.HoldPerExporter == 0 {
		c.UDP.HoldPerExporter = 256
	}
	if c.UDP.HoldGlobal == 0 {
		c.UDP.HoldGlobal = 4096
	}
	if c.UDP.TimestampMaxAge == 0 {
		c.UDP.TimestampMaxAge = 2 * time.Hour
	}
	if c.UDP.TimestampSkewSlack == 0 {
		c.UDP.TimestampSkewSlack = 5 * time.Second
	}
	if c.HTTP.Listen == "" {
		c.HTTP.Listen = "127.0.0.1:8080"
	}
	if c.HTTP.APIPrefix == "" {
		c.HTTP.APIPrefix = "/api/v1"
	}
	if c.HTTP.QueryCacheTTL == 0 {
		c.HTTP.QueryCacheTTL = 15 * time.Second
	}
	if c.HTTP.QueryCacheEntries == 0 {
		c.HTTP.QueryCacheEntries = 256
	}
	if c.DB.Path == "" {
		c.DB.Path = "vibecollector.db"
	}
	if c.DB.BusyTimeout == 0 {
		c.DB.BusyTimeout = 5 * time.Second
	}
	if c.DB.BatchSize == 0 {
		c.DB.BatchSize = 2000
	}
	if c.DB.BatchInterval == 0 {
		c.DB.BatchInterval = 500 * time.Millisecond
	}
	if c.DB.RawRetention == 0 {
		c.DB.RawRetention = 6 * time.Hour
	}
	if c.DB.RollupRetention == 0 {
		c.DB.RollupRetention = 720 * time.Hour
	}
	if c.Enrich.GeoIPTTL == 0 {
		c.Enrich.GeoIPTTL = 24 * time.Hour
	}
	if c.Enrich.ASNTTL == 0 {
		c.Enrich.ASNTTL = 24 * time.Hour
	}
	if c.Enrich.ReputationTTL == 0 {
		c.Enrich.ReputationTTL = time.Hour
	}
	if c.Enrich.LookupTimeout == 0 {
		c.Enrich.LookupTimeout = 500 * time.Millisecond
	}
	if c.Enrich.CacheEntries == 0 {
		c.Enrich.CacheEntries = 100000
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.OAuth2.TokenTTL == 0 {
		c.OAuth2.TokenTTL = time.Hour
	}
	if c.OAuth2.RefreshTTL == 0 {
		c.OAuth2.RefreshTTL = 24 * time.Hour
	}
}

// applyIssuer fills an empty issuer from the public host. Flags have already
// replaced http.listen. A specific listen address is that public host when
// http.public_host is empty. 0.0.0.0 and :: are not copied into the issuer.
// The scheme is http because the daemon does not terminate TLS.
func applyIssuer(c *Config) {
	if c.OAuth2.Issuer != "" {
		return
	}
	host := resolvedPublicHost(c)
	if host == "" {
		return
	}
	c.OAuth2.Issuer = "http://" + host
}

// resolvedPublicHost is host:port clients use. An empty result means the
// bind address is unspecified and http.public_host was not set.
func resolvedPublicHost(c *Config) string {
	_, listenPort, err := net.SplitHostPort(c.HTTP.Listen)
	if err != nil || listenPort == "" {
		return ""
	}
	if c.HTTP.PublicHost != "" {
		host, port, err := splitHostOptionalPort(c.HTTP.PublicHost)
		if err != nil || host == "" {
			return ""
		}
		if port == "" {
			port = listenPort
		}
		if strings.Contains(host, ":") {
			return "[" + host + "]:" + port
		}
		return net.JoinHostPort(host, port)
	}
	listenHost, _, err := net.SplitHostPort(c.HTTP.Listen)
	if err != nil || unspecifiedHost(listenHost) {
		return ""
	}
	return c.HTTP.Listen
}

func splitHostOptionalPort(s string) (string, string, error) {
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 2 {
			return "", "", fmt.Errorf("host")
		}
		host := s[1:end]
		rest := s[end+1:]
		if rest == "" {
			return host, "", nil
		}
		if len(rest) < 2 || rest[0] != ':' {
			return "", "", fmt.Errorf("host")
		}
		return host, rest[1:], nil
	}
	if host, port, err := net.SplitHostPort(s); err == nil {
		return host, port, nil
	}
	if strings.Contains(s, ":") {
		return "", "", fmt.Errorf("host")
	}
	return s, "", nil
}

func unspecifiedHost(host string) bool {
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsUnspecified()
}

func applyFlags(c *Config, f Flags) {
	if f.HTTP != "" {
		c.HTTP.Listen = f.HTTP
	}
	if f.UDP != "" {
		c.UDP.Listen = f.UDP
	}
	if f.DB != "" {
		c.DB.Path = f.DB
	}
}

func validate(c *Config) error {
	fields := []struct {
		name string
		d    time.Duration
		min  time.Duration
	}{
		{"udp.template_idle_timeout", c.UDP.TemplateIdle, 0},
		{"udp.timestamp_max_age", c.UDP.TimestampMaxAge, 0},
		{"udp.timestamp_skew_slack", c.UDP.TimestampSkewSlack, 0},
		{"http.query_cache_ttl", c.HTTP.QueryCacheTTL, 0},
		{"oauth2.token_ttl", c.OAuth2.TokenTTL, 0},
		{"oauth2.refresh_ttl", c.OAuth2.RefreshTTL, 0},
		{"db.busy_timeout", c.DB.BusyTimeout, 0},
		{"db.batch_interval", c.DB.BatchInterval, 0},
		{"db.raw_retention", c.DB.RawRetention, time.Minute},
		{"db.rollup_retention", c.DB.RollupRetention, time.Hour},
		{"enrich.geoip_ttl", c.Enrich.GeoIPTTL, 0},
		{"enrich.asn_ttl", c.Enrich.ASNTTL, 0},
		{"enrich.reputation_ttl", c.Enrich.ReputationTTL, 0},
		{"enrich.lookup_timeout", c.Enrich.LookupTimeout, 0},
	}
	for _, f := range fields {
		if f.d < 0 {
			return fmt.Errorf("%w: %s: invalid duration", ErrBadConfig, f.name)
		}
		if f.min > 0 && f.d < f.min {
			return fmt.Errorf("%w: %s: shorter than %s", ErrBadConfig, f.name, f.min)
		}
	}
	if c.UDP.DatagramQueue < 1 {
		return fmt.Errorf("%w: udp.datagram_queue", ErrBadConfig)
	}
	if c.UDP.FlowQueue < 1 {
		return fmt.Errorf("%w: udp.flow_queue", ErrBadConfig)
	}
	if c.UDP.WriterQueue < 1 {
		return fmt.Errorf("%w: udp.writer_queue", ErrBadConfig)
	}
	if c.OAuth2.RefreshTTL <= c.OAuth2.TokenTTL {
		return fmt.Errorf("%w: oauth2.refresh_ttl", ErrBadConfig)
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("%w: log.level", ErrBadConfig)
	}
	if _, port, err := net.SplitHostPort(c.HTTP.Listen); err != nil || port == "" {
		return fmt.Errorf("%w: http.listen", ErrBadConfig)
	}
	if err := validatePublicHost(c.HTTP.PublicHost); err != nil {
		return err
	}
	if err := validatePrefix(c.HTTP.APIPrefix); err != nil {
		return err
	}
	return nil
}

func validatePublicHost(public string) error {
	if public == "" {
		return nil
	}
	if strings.Contains(public, "://") || strings.ContainsAny(public, "/?#@ ") {
		return fmt.Errorf("%w: http.public_host", ErrBadConfig)
	}
	host, port, err := splitHostOptionalPort(public)
	if err != nil || host == "" || unspecifiedHost(host) {
		return fmt.Errorf("%w: http.public_host", ErrBadConfig)
	}
	if port == "" {
		return nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%w: http.public_host", ErrBadConfig)
	}
	return nil
}

func validatePrefix(p string) error {
	if len(p) < 2 || p[0] != '/' || p[len(p)-1] == '/' {
		return fmt.Errorf("%w: http.api_prefix", ErrBadConfig)
	}
	if strings.ContainsAny(p, "?#") || strings.Contains(p, "..") {
		return fmt.Errorf("%w: http.api_prefix", ErrBadConfig)
	}
	for i, seg := range strings.Split(p, "/") {
		if i == 0 {
			continue
		}
		if seg == "" {
			return fmt.Errorf("%w: http.api_prefix", ErrBadConfig)
		}
	}
	return nil
}

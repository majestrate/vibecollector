// Package config loads the process configuration from TOML, defaults, and flags.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

	// ErrTokenRequired means http.listen is not a loopback address and
	// http.token is empty. Loopback is an address in 127.0.0.0/8 or ::1.
	// 0.0.0.0 and :: are not loopback. errors.Is reports this sentinel.
	ErrTokenRequired = errors.New("http.token is required when http.listen is not loopback")

	// ErrBadConfig means a duration is invalid, db.raw_retention is under
	// 1 minute, db.rollup_retention is under 1 hour, a queue depth is under 1,
	// log.level is not debug, info, warn, or error, or http.listen is not
	// host:port. errors.Is reports this sentinel.
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
type Config struct {
	UDP           UDP    `toml:"udp"`
	HTTP          HTTP   `toml:"http"`
	DB            DB     `toml:"db"`
	Enrich        Enrich `toml:"enrich"`
	Log           Log    `toml:"log"`
	LooseFileMode bool   `toml:"-"`
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

// HTTP is the API listener. Token is required when Listen is not loopback.
// The browser never sees Token. QueryCacheTTL and QueryCacheEntries size
// the API response cache.
type HTTP struct {
	Listen            string        `toml:"listen"`
	Token             string        `toml:"token"`
	QueryCacheTTL     time.Duration `toml:"query_cache_ttl"`
	QueryCacheEntries int           `toml:"query_cache_entries"`
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
// When one of those tables is present, Load logs
// "enrich.<name>: reserved table, ignored".
// It returns ErrTokenRequired when http.listen is not loopback and the token
// is empty. It returns ErrBadConfig when a duration is invalid, a retention
// is shorter than one grain, a queue depth is less than 1, log.level is not
// a known name, or http.listen is not host:port.
// A missing default file is not an error. A missing file named by ConfigPath,
// or a file that cannot be read, is returned unwrapped and is not one of the
// three sentinels.
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
	if err := validate(cfg); err != nil {
		return nil, err
	}
	if opened {
		logReserved(data)
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
	rewritten, err := rewriteDurations(data)
	if err != nil {
		return err
	}
	dec := toml.NewDecoder(bytes.NewReader(rewritten))
	err = dec.EnableUnmarshalerInterface().DisallowUnknownFields().Decode(cfg)
	if err == nil {
		return nil
	}
	var strict *toml.StrictMissingError
	if errors.As(err, &strict) {
		detail := strict.String()
		if detail == "" {
			detail = strict.Error()
		}
		return fmt.Errorf("%w: %s", ErrUnknownField, detail)
	}
	return fmt.Errorf("%w: %v", ErrBadConfig, err)
}

// durationKeys are the TOML paths whose values are Go durations.
// time.Duration has no UnmarshalText in this toolchain, so a quoted duration
// is rewritten to a nanosecond integer before the struct decode.
var durationKeys = map[string]struct{}{
	"udp.template_idle_timeout": {},
	"udp.timestamp_max_age":     {},
	"udp.timestamp_skew_slack":  {},
	"http.query_cache_ttl":      {},
	"db.busy_timeout":           {},
	"db.batch_interval":         {},
	"db.raw_retention":          {},
	"db.rollup_retention":       {},
	"enrich.geoip_ttl":          {},
	"enrich.asn_ttl":            {},
	"enrich.reputation_ttl":     {},
	"enrich.lookup_timeout":     {},
}

type durationRepl struct {
	off  int
	end  int
	text string
}

func rewriteDurations(data []byte) ([]byte, error) {
	p := &unstable.Parser{}
	p.Reset(data)
	var reps []durationRepl
	var table []string
	for p.NextExpression() {
		expr := p.Expression()
		switch expr.Kind {
		case unstable.Table, unstable.ArrayTable:
			table = append([]string(nil), keyParts(expr)...)
		case unstable.KeyValue:
			if err := collectDurations(expr, table, &reps); err != nil {
				return nil, err
			}
		}
	}
	if p.Error() != nil {
		return data, nil
	}
	if len(reps) == 0 {
		return data, nil
	}
	sort.Slice(reps, func(i, j int) bool { return reps[i].off > reps[j].off })
	out := data
	for _, r := range reps {
		next := make([]byte, 0, len(out)-(r.end-r.off)+len(r.text))
		next = append(next, out[:r.off]...)
		next = append(next, r.text...)
		next = append(next, out[r.end:]...)
		out = next
	}
	return out, nil
}

func collectDurations(kv *unstable.Node, prefix []string, reps *[]durationRepl) error {
	parts := append(append([]string{}, prefix...), keyParts(kv)...)
	val := kv.Value()
	switch val.Kind {
	case unstable.String:
		full := strings.Join(parts, ".")
		if _, ok := durationKeys[full]; !ok {
			return nil
		}
		d, err := time.ParseDuration(string(val.Data))
		if err != nil {
			return fmt.Errorf("%w: %s: %v", ErrBadConfig, full, err)
		}
		*reps = append(*reps, durationRepl{
			off:  int(val.Raw.Offset),
			end:  int(val.Raw.Offset) + int(val.Raw.Length),
			text: strconv.FormatInt(int64(d), 10),
		})
	case unstable.InlineTable:
		for it := val.Children(); it.Next(); {
			child := it.Node()
			if child.Kind != unstable.KeyValue {
				continue
			}
			if err := collectDurations(child, parts, reps); err != nil {
				return err
			}
		}
	}
	return nil
}

func keyParts(n *unstable.Node) []string {
	var parts []string
	it := n.Key()
	for it.Next() {
		parts = append(parts, string(it.Node().Data))
	}
	return parts
}

// Zero means the key was omitted. An explicit zero in the file takes the default too.
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
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("%w: log.level", ErrBadConfig)
	}
	loop, err := httpLoopback(c.HTTP.Listen)
	if err != nil {
		return err
	}
	if !loop && c.HTTP.Token == "" {
		return fmt.Errorf("%w: %s", ErrTokenRequired, c.HTTP.Listen)
	}
	return nil
}

func httpLoopback(listen string) (bool, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return false, fmt.Errorf("%w: http.listen", ErrBadConfig)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false, nil
	}
	return addr.IsLoopback(), nil
}

// Reserved tables keep no presence bit, so the document is the only record that one was set.
func logReserved(data []byte) {
	var root map[string]any
	if err := toml.Unmarshal(data, &root); err != nil {
		return
	}
	enrich, ok := root["enrich"].(map[string]any)
	if !ok {
		return
	}
	for _, name := range []string{"geoip", "asn", "reputation"} {
		if _, present := enrich[name]; present {
			slog.Info("enrich." + name + ": reserved table, ignored")
		}
	}
}

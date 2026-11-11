package config

import (
	"strconv"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Default returns the configuration Load uses when no file and no flags are set.
// The issuer is http:// plus the default HTTP listen address.
// It does not read a file, bind a socket, or open the database.
func Default() (*Config, error) {
	return Load(Flags{})
}

// Document renders c as TOML that Load accepts.
// The bytes are produced by github.com/pelletier/go-toml/v2 Marshal.
// Duration fields implement encoding.TextMarshaler, so each one is a quoted
// string: a whole number of hours, otherwise minutes, otherwise seconds,
// otherwise time.Duration.String. An integer nanosecond count is not emitted.
// Empty public_host and token are included.
// Reserved enrich tables are omitted, so Load does not record them on
// ReservedSeen. The result ends with a newline.
// A nil c returns an empty string and a nil error.
// A non-nil error is the encoder error, and the string is empty.
func Document(c *Config) (string, error) {
	if c == nil {
		return "", nil
	}
	raw, err := toml.Marshal(documentValue(c))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// durationText is a time.Duration that Marshal emits as a quoted string.
// Load rejects a bare nanosecond integer for these keys.
type durationText time.Duration

// MarshalText returns the duration in the form Load parses with time.ParseDuration.
func (d durationText) MarshalText() ([]byte, error) {
	return []byte(compactDuration(time.Duration(d))), nil
}

func compactDuration(d time.Duration) string {
	switch {
	case d%time.Hour == 0 && d != 0:
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	case d%time.Minute == 0 && d != 0:
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	case d%time.Second == 0 && d != 0:
		return strconv.FormatInt(int64(d/time.Second), 10) + "s"
	default:
		return d.String()
	}
}

// tomlDoc is the marshal shape of a config file.
// It has no reserved enrich tables and no process-only fields.
type tomlDoc struct {
	UDP    tomlUDP    `toml:"udp" comment:"Built-in VibeCollector defaults."`
	HTTP   tomlHTTP   `toml:"http"`
	OAuth2 tomlOAuth2 `toml:"oauth2"`
	DB     tomlDB     `toml:"db"`
	Enrich tomlEnrich `toml:"enrich"`
	Log    tomlLog    `toml:"log"`
}

type tomlUDP struct {
	Listen             string       `toml:"listen"`
	ReadBufferBytes    int          `toml:"read_buffer_bytes"`
	DatagramQueue      int          `toml:"datagram_queue"`
	FlowQueue          int          `toml:"flow_queue"`
	WriterQueue        int          `toml:"writer_queue"`
	TemplateIdle       durationText `toml:"template_idle_timeout"`
	HoldPerExporter    int          `toml:"hold_packets_per_exporter"`
	HoldGlobal         int          `toml:"hold_packets_global"`
	TimestampMaxAge    durationText `toml:"timestamp_max_age"`
	TimestampSkewSlack durationText `toml:"timestamp_skew_slack"`
}

type tomlHTTP struct {
	Listen            string       `toml:"listen"`
	PublicHost        string       `toml:"public_host"`
	Token             string       `toml:"token"`
	APIPrefix         string       `toml:"api_prefix"`
	QueryCacheTTL     durationText `toml:"query_cache_ttl"`
	QueryCacheEntries int          `toml:"query_cache_entries"`
}

type tomlOAuth2 struct {
	Issuer     string       `toml:"issuer"`
	TokenTTL   durationText `toml:"token_ttl"`
	RefreshTTL durationText `toml:"refresh_ttl"`
}

type tomlDB struct {
	Path            string       `toml:"path"`
	BusyTimeout     durationText `toml:"busy_timeout"`
	BatchSize       int          `toml:"batch_size"`
	BatchInterval   durationText `toml:"batch_interval"`
	RawRetention    durationText `toml:"raw_retention"`
	RollupRetention durationText `toml:"rollup_retention"`
}

type tomlEnrich struct {
	GeoIPTTL      durationText `toml:"geoip_ttl"`
	ASNTTL        durationText `toml:"asn_ttl"`
	ReputationTTL durationText `toml:"reputation_ttl"`
	LookupTimeout durationText `toml:"lookup_timeout"`
	CacheEntries  int          `toml:"cache_entries_per_provider"`
}

type tomlLog struct {
	Level string `toml:"level"`
}

func documentValue(c *Config) tomlDoc {
	return tomlDoc{
		UDP: tomlUDP{
			Listen:             c.UDP.Listen,
			ReadBufferBytes:    c.UDP.ReadBufferBytes,
			DatagramQueue:      c.UDP.DatagramQueue,
			FlowQueue:          c.UDP.FlowQueue,
			WriterQueue:        c.UDP.WriterQueue,
			TemplateIdle:       durationText(c.UDP.TemplateIdle),
			HoldPerExporter:    c.UDP.HoldPerExporter,
			HoldGlobal:         c.UDP.HoldGlobal,
			TimestampMaxAge:    durationText(c.UDP.TimestampMaxAge),
			TimestampSkewSlack: durationText(c.UDP.TimestampSkewSlack),
		},
		HTTP: tomlHTTP{
			Listen:            c.HTTP.Listen,
			PublicHost:        c.HTTP.PublicHost,
			Token:             c.HTTP.Token,
			APIPrefix:         c.HTTP.APIPrefix,
			QueryCacheTTL:     durationText(c.HTTP.QueryCacheTTL),
			QueryCacheEntries: c.HTTP.QueryCacheEntries,
		},
		OAuth2: tomlOAuth2{
			Issuer:     c.OAuth2.Issuer,
			TokenTTL:   durationText(c.OAuth2.TokenTTL),
			RefreshTTL: durationText(c.OAuth2.RefreshTTL),
		},
		DB: tomlDB{
			Path:            c.DB.Path,
			BusyTimeout:     durationText(c.DB.BusyTimeout),
			BatchSize:       c.DB.BatchSize,
			BatchInterval:   durationText(c.DB.BatchInterval),
			RawRetention:    durationText(c.DB.RawRetention),
			RollupRetention: durationText(c.DB.RollupRetention),
		},
		Enrich: tomlEnrich{
			GeoIPTTL:      durationText(c.Enrich.GeoIPTTL),
			ASNTTL:        durationText(c.Enrich.ASNTTL),
			ReputationTTL: durationText(c.Enrich.ReputationTTL),
			LookupTimeout: durationText(c.Enrich.LookupTimeout),
			CacheEntries:  c.Enrich.CacheEntries,
		},
		Log: tomlLog{Level: c.Log.Level},
	}
}

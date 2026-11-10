// Package enrich classifies flow endpoints and fills provider outcomes.
// The pipeline does not import a provider implementation. main passes
// the providers.
package enrich

import (
	"context"
	"net/netip"

	"vibecollector/internal/flow"
)

// ProviderName selects one provider. The string is the stats prefix and the log line.
type ProviderName string

const (
	ProviderGeoIP      ProviderName = "geoip"
	ProviderASN        ProviderName = "asn"
	ProviderReputation ProviderName = "reputation"
)

// Provider looks up one global address. Name returns the provider's name.
// Lookup returns a Result and does not return a Go error. A failure is
// Kind OutcomeError and a short ErrCode. A stub returns OutcomeNotConfigured.
// Lookup must not be called for a non-global address. The pipeline guarantees that.
// ctx is cancelled at lookup_timeout. A provider that ignores ctx is still
// abandoned by the pipeline at that deadline, and the stored outcome is
// OutcomeError with ErrCode "timeout".
type Provider interface {
	Name() ProviderName
	Lookup(ctx context.Context, ip netip.Addr) Result
}

// Result is one lookup. Geo, ASN, or Rep is set when Kind is OutcomeValue
// and the provider is that kind. ErrCode is empty unless Kind is OutcomeError.
type Result struct {
	Provider ProviderName
	Kind     flow.OutcomeKind
	ErrCode  string
	Geo      *Geo
	ASN      *ASN
	Rep      *Rep
}

// Geo is a GeoIP value payload. Country is ISO alpha-2.
// Lat and Lon are set only when HasLatLon is true.
type Geo struct {
	Country, Region, City string
	Lat, Lon              float64
	HasLatLon             bool
}

// ASN is an autonomous-system value payload.
type ASN struct {
	Number uint32
	Name   string
}

// Rep is a reputation value payload. Score is set only when HasScore is true.
type Rep struct {
	Category string
	Score    float64
	HasScore bool
}

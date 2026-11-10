// Package stub is the not-configured provider. It does no network I/O
// and reads no credential. main is the only production caller.
package stub

import (
	"context"
	"net/netip"

	"vibecollector/internal/enrich"
)

type unknownNameError struct{}

func (unknownNameError) Error() string { return "unknown provider" }

// ErrUnknownProvider means name is not geoip, asn, or reputation.
// New returns it and does not build a provider. errors.Is reports this sentinel.
var ErrUnknownProvider error = unknownNameError{}

type provider struct {
	name enrich.ProviderName
}

// New returns a Provider whose Lookup always yields OutcomeNotConfigured
// for name. name must be ProviderGeoIP, ProviderASN, or ProviderReputation.
// Any other name returns ErrUnknownProvider.
// The stub performs no network I/O and reads no credential.
// main is the only caller. The pipeline package does not import this package.
func New(name enrich.ProviderName) (enrich.Provider, error) {
	switch name {
	case enrich.ProviderGeoIP, enrich.ProviderASN, enrich.ProviderReputation:
		return provider{name: name}, nil
	default:
		return nil, ErrUnknownProvider
	}
}

func (p provider) Name() enrich.ProviderName { return p.name }

func (p provider) Lookup(context.Context, netip.Addr) enrich.Result {
	return enrich.Result{Provider: p.name, Kind: "not_configured"}
}

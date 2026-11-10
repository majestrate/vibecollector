package enrich

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"vibecollector/internal/config"
	"vibecollector/internal/flow"
	"vibecollector/internal/obs"
)

// Four workers enrich different flows. One endpoint's providers stay sequential.
const enrichWorkers = 4

// ErrNoProviders means the provider slice was empty or missed geoip, asn, or
// reputation. NewPipeline returns it and does not start workers.
// errors.Is reports this sentinel.
var ErrNoProviders = errors.New("no providers")

// ErrNilDep means counters, the cache map, a provider, or a provider's cache
// was nil. NewPipeline returns it and does not start workers.
// errors.Is reports this sentinel.
var ErrNilDep = errors.New("nil dependency")

// Pipeline is the stage between the flow queue and the writer sink.
// It does not import internal/enrich/stub. main passes the providers.
type Pipeline struct {
	prov     map[ProviderName]Provider
	caches   map[ProviderName]*Cache
	cfg      config.Enrich
	counters *obs.Counters
}

// NewPipeline stores providers, the per-provider caches, and the config.
// providers must contain one entry per name the process will call.
// An empty slice returns ErrNoProviders. A nil cache or counters returns ErrNilDep.
// NewPipeline does not start workers.
func NewPipeline(providers []Provider, caches map[ProviderName]*Cache, cfg config.Enrich, counters *obs.Counters) (*Pipeline, error) {
	if len(providers) == 0 {
		return nil, ErrNoProviders
	}
	if counters == nil {
		return nil, fmt.Errorf("%w: counters", ErrNilDep)
	}
	if caches == nil {
		return nil, fmt.Errorf("%w: caches", ErrNilDep)
	}
	prov := make(map[ProviderName]Provider, len(providers))
	for _, p := range providers {
		if p == nil {
			return nil, fmt.Errorf("%w: provider", ErrNilDep)
		}
		prov[p.Name()] = p
	}
	for _, name := range []ProviderName{ProviderGeoIP, ProviderASN, ProviderReputation} {
		if prov[name] == nil {
			return nil, fmt.Errorf("%w: %s", ErrNoProviders, name)
		}
		if caches[name] == nil {
			return nil, fmt.Errorf("%w: %s cache", ErrNilDep, name)
		}
	}
	return &Pipeline{prov: prov, caches: caches, cfg: cfg, counters: counters}, nil
}

// Run reads decoded flows from in, fills SrcEnrich and DstEnrich, and
// Submits each flow to sink. Run is the only caller of flow.Sink.Submit.
// Decode workers do not call it. Four workers run until ctx is cancelled or
// in is closed. For each endpoint, Run calls Classify. A scope other than
// global sets all three outcomes to skipped and does not call Lookup.
// Otherwise it calls GeoIP, ASN, and reputation in that order.
// A provider error, a timeout, or no_data still Submits the flow.
// Submit returning ErrQueueFull increments dropped_writer_queue and drops
// that flow. A full flow queue is not this counter. Run then returns nil on
// cancellation. It does not return ErrQueueFull to main.
func (p *Pipeline) Run(ctx context.Context, in <-chan flow.Flow, sink flow.Sink) error {
	var wg sync.WaitGroup
	wg.Add(enrichWorkers)
	for i := 0; i < enrichWorkers; i++ {
		go func() {
			defer wg.Done()
			p.worker(ctx, in, sink)
		}()
	}
	wg.Wait()
	return nil
}

func (p *Pipeline) worker(ctx context.Context, in <-chan flow.Flow, sink flow.Sink) {
	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-in:
			if !ok {
				return
			}
			f.SrcEnrich = p.annotate(ctx, f.Src)
			f.DstEnrich = p.annotate(ctx, f.Dst)
			if err := sink.Submit([]flow.Flow{f}); errors.Is(err, flow.ErrQueueFull) {
				_ = p.counters.Add(obs.DroppedWriterQueue, 1)
			}
		}
	}
}

func (p *Pipeline) annotate(ctx context.Context, ip netip.Addr) flow.Endpoint {
	ep := flow.Endpoint{Scope: Classify(ip)}
	if ep.Scope != ScopeGlobal {
		skip := flow.Outcome{Kind: flow.OutcomeSkipped}
		ep.Geo, ep.ASN, ep.Rep = skip, skip, skip
		p.note(ProviderGeoIP, flow.OutcomeSkipped)
		p.note(ProviderASN, flow.OutcomeSkipped)
		p.note(ProviderReputation, flow.OutcomeSkipped)
		return ep
	}
	ep.Geo = p.lookup(ctx, ProviderGeoIP, ip)
	ep.ASN = p.lookup(ctx, ProviderASN, ip)
	ep.Rep = p.lookup(ctx, ProviderReputation, ip)
	return ep
}

func (p *Pipeline) lookup(ctx context.Context, name ProviderName, ip netip.Addr) flow.Outcome {
	res := p.caches[name].Get(ctx, name, ip, p.ttl(name), p.cfg.LookupTimeout, p.prov[name].Lookup)
	p.note(name, res.Kind)
	return outcomeFrom(res)
}

func (p *Pipeline) ttl(name ProviderName) time.Duration {
	switch name {
	case ProviderASN:
		return p.cfg.ASNTTL
	case ProviderReputation:
		return p.cfg.ReputationTTL
	default:
		return p.cfg.GeoIPTTL
	}
}

func (p *Pipeline) note(name ProviderName, kind flow.OutcomeKind) {
	n, ok := outcomeCounter(name, kind)
	if !ok {
		return
	}
	_ = p.counters.Add(n, 1)
}

func outcomeFrom(r Result) flow.Outcome {
	o := flow.Outcome{Kind: r.Kind}
	if r.Kind != flow.OutcomeValue {
		return o
	}
	if r.Geo != nil {
		o.Country, o.Region, o.City = r.Geo.Country, r.Geo.Region, r.Geo.City
		o.Lat, o.Lon, o.HasLatLon = r.Geo.Lat, r.Geo.Lon, r.Geo.HasLatLon
	}
	if r.ASN != nil {
		o.ASN, o.ASNName = r.ASN.Number, r.ASN.Name
	}
	if r.Rep != nil {
		o.Category, o.Score, o.HasScore = r.Rep.Category, r.Rep.Score, r.Rep.HasScore
	}
	return o
}

func outcomeCounter(name ProviderName, kind flow.OutcomeKind) (obs.Name, bool) {
	switch name {
	case ProviderGeoIP:
		switch kind {
		case flow.OutcomeNotConfigured:
			return obs.EnrichGeoIPNotConfigured, true
		case flow.OutcomeNoData:
			return obs.EnrichGeoIPNoData, true
		case flow.OutcomeError:
			return obs.EnrichGeoIPError, true
		case flow.OutcomeValue:
			return obs.EnrichGeoIPValue, true
		case flow.OutcomeSkipped:
			return obs.EnrichGeoIPSkipped, true
		}
	case ProviderASN:
		switch kind {
		case flow.OutcomeNotConfigured:
			return obs.EnrichASNNotConfigured, true
		case flow.OutcomeNoData:
			return obs.EnrichASNNoData, true
		case flow.OutcomeError:
			return obs.EnrichASNError, true
		case flow.OutcomeValue:
			return obs.EnrichASNValue, true
		case flow.OutcomeSkipped:
			return obs.EnrichASNSkipped, true
		}
	case ProviderReputation:
		switch kind {
		case flow.OutcomeNotConfigured:
			return obs.EnrichReputationNotConfigured, true
		case flow.OutcomeNoData:
			return obs.EnrichReputationNoData, true
		case flow.OutcomeError:
			return obs.EnrichReputationError, true
		case flow.OutcomeValue:
			return obs.EnrichReputationValue, true
		case flow.OutcomeSkipped:
			return obs.EnrichReputationSkipped, true
		}
	}
	return "", false
}

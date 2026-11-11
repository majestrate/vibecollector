package enrich

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/majestrate/vibecollector/internal/config"
	"github.com/majestrate/vibecollector/internal/flow"
	"github.com/majestrate/vibecollector/internal/obs"
)

type scripted struct {
	name  ProviderName
	fn    func(context.Context, netip.Addr) Result
	calls atomic.Int32
}

func (s *scripted) Name() ProviderName { return s.name }

func (s *scripted) Lookup(ctx context.Context, ip netip.Addr) Result {
	s.calls.Add(1)
	if s.fn == nil {
		return Result{Provider: s.name, Kind: flow.OutcomeNotConfigured}
	}
	r := s.fn(ctx, ip)
	if r.Provider == "" {
		r.Provider = s.name
	}
	return r
}

type memSink struct {
	mu    sync.Mutex
	flows []flow.Flow
	err   error
}

func (s *memSink) Submit(flows []flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.flows = append(s.flows, flows...)
	return nil
}

func (s *memSink) SubmitDelta(flow.ExporterDelta) {}

func testPipeline(t *testing.T, provs []Provider, cfg config.Enrich) (*Pipeline, *obs.Counters) {
	t.Helper()
	caches := map[ProviderName]*Cache{}
	for _, name := range []ProviderName{ProviderGeoIP, ProviderASN, ProviderReputation} {
		c, err := NewCache(32)
		if err != nil {
			t.Fatal(err)
		}
		caches[name] = c
	}
	counters := obs.NewCounters()
	p, err := NewPipeline(provs, caches, cfg, counters)
	if err != nil {
		t.Fatal(err)
	}
	return p, counters
}

func three(fn func(context.Context, netip.Addr) Result) []Provider {
	var out []Provider
	for _, name := range []ProviderName{ProviderGeoIP, ProviderASN, ProviderReputation} {
		out = append(out, &scripted{name: name, fn: fn})
	}
	return out
}

func runFlows(t *testing.T, p *Pipeline, sink flow.Sink, flows ...flow.Flow) {
	t.Helper()
	in := make(chan flow.Flow)
	errc := make(chan error, 1)
	go func() {
		errc <- p.Run(context.Background(), in, sink)
	}()
	for _, f := range flows {
		in <- f
	}
	close(in)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func basicFlow(src, dst string) flow.Flow {
	return flow.Flow{
		Src:     netip.MustParseAddr(src),
		Dst:     netip.MustParseAddr(dst),
		Packets: 7,
		Octets:  9,
	}
}

func enrichCfg(ttl, timeout time.Duration) config.Enrich {
	return config.Enrich{
		GeoIPTTL:      ttl,
		ASNTTL:        ttl,
		ReputationTTL: ttl,
		LookupTimeout: timeout,
	}
}

func TestNewPipelineErrors(t *testing.T) {
	caches := map[ProviderName]*Cache{}
	for _, name := range []ProviderName{ProviderGeoIP, ProviderASN, ProviderReputation} {
		c, err := NewCache(1)
		if err != nil {
			t.Fatal(err)
		}
		caches[name] = c
	}
	counters := obs.NewCounters()
	provs := three(nil)
	if _, err := NewPipeline(nil, caches, config.Enrich{}, counters); !errors.Is(err, ErrNoProviders) {
		t.Fatal(err)
	}
	if _, err := NewPipeline(provs, caches, config.Enrich{}, nil); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
	if _, err := NewPipeline(provs, nil, config.Enrich{}, counters); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
	if _, err := NewPipeline([]Provider{provs[0], nil, provs[2]}, caches, config.Enrich{}, counters); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
	if _, err := NewPipeline(provs[:1], caches, config.Enrich{}, counters); !errors.Is(err, ErrNoProviders) {
		t.Fatal(err)
	}
	missing := map[ProviderName]*Cache{ProviderGeoIP: caches[ProviderGeoIP], ProviderASN: caches[ProviderASN]}
	if _, err := NewPipeline(provs, missing, config.Enrich{}, counters); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
}

func TestSkipNonGlobal(t *testing.T) {
	var calls atomic.Int32
	p, counters := testPipeline(t, three(func(context.Context, netip.Addr) Result {
		calls.Add(1)
		return Result{Kind: flow.OutcomeValue, Geo: &Geo{Country: "US"}}
	}), enrichCfg(time.Hour, time.Second))
	sink := &memSink{}
	runFlows(t, p, sink,
		basicFlow("10.1.1.1", "192.168.1.1"),
		basicFlow("::ffff:10.1.1.1", "8.8.8.8"),
		basicFlow("64:ff9b::10.1.1.1", "2002:a01:101::"),
	)
	if calls.Load() != 3 {
		t.Fatalf("calls %d", calls.Load())
	}
	if len(sink.flows) != 3 {
		t.Fatalf("flows %d", len(sink.flows))
	}
	bySrc := map[string]flow.Flow{}
	for _, f := range sink.flows {
		bySrc[f.Src.String()] = f
	}
	priv := bySrc["10.1.1.1"]
	if priv.Packets != 7 || priv.SrcEnrich.Scope != ScopePrivate || priv.DstEnrich.Scope != ScopePrivate {
		t.Fatalf("%+v %+v", priv.SrcEnrich, priv.DstEnrich)
	}
	for _, o := range []flow.Outcome{priv.SrcEnrich.Geo, priv.SrcEnrich.ASN, priv.SrcEnrich.Rep, priv.DstEnrich.Geo} {
		if o.Kind != flow.OutcomeSkipped {
			t.Fatalf("%+v", priv.SrcEnrich)
		}
	}
	mapped := bySrc[netip.MustParseAddr("::ffff:10.1.1.1").String()]
	if mapped.SrcEnrich.Scope != ScopePrivate || mapped.SrcEnrich.Geo.Kind != flow.OutcomeSkipped {
		t.Fatalf("mapped src %+v", mapped.SrcEnrich)
	}
	if mapped.DstEnrich.Scope != ScopeGlobal || mapped.DstEnrich.Geo.Kind != flow.OutcomeValue || mapped.DstEnrich.Geo.Country != "US" {
		t.Fatalf("dst %+v", mapped.DstEnrich)
	}
	nat64 := bySrc[netip.MustParseAddr("64:ff9b::10.1.1.1").String()]
	if nat64.SrcEnrich.Scope != ScopePrivate || nat64.DstEnrich.Scope != ScopePrivate {
		t.Fatalf("nat64/6to4 %+v %+v", nat64.SrcEnrich.Scope, nat64.DstEnrich.Scope)
	}
	snap := counters.Snapshot()
	// Flow 0: 2 skipped endpoints. Flow 1: 1 skipped. Flow 2: 2 skipped. 5 per provider.
	if snap[obs.EnrichGeoIPSkipped] != 5 || snap[obs.EnrichASNSkipped] != 5 || snap[obs.EnrichReputationSkipped] != 5 {
		t.Fatal(snap[obs.EnrichGeoIPSkipped], snap[obs.EnrichASNSkipped], snap[obs.EnrichReputationSkipped])
	}
	if snap[obs.EnrichGeoIPValue] != 1 {
		t.Fatal(snap[obs.EnrichGeoIPValue])
	}
}

func TestOutcomesStillSubmit(t *testing.T) {
	cases := []struct {
		name string
		kind flow.OutcomeKind
		code string
	}{
		{"error", flow.OutcomeError, "down"},
		{"no_data", flow.OutcomeNoData, ""},
		{"not_configured", flow.OutcomeNotConfigured, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, counters := testPipeline(t, three(func(context.Context, netip.Addr) Result {
				return Result{Kind: tc.kind, ErrCode: tc.code}
			}), enrichCfg(time.Hour, time.Second))
			sink := &memSink{}
			runFlows(t, p, sink, basicFlow("1.1.1.1", "8.8.8.8"))
			if len(sink.flows) != 1 {
				t.Fatalf("flows %d", len(sink.flows))
			}
			f := sink.flows[0]
			if f.Packets != 7 || f.SrcEnrich.Scope != ScopeGlobal || f.DstEnrich.Scope != ScopeGlobal {
				t.Fatalf("%+v", f)
			}
			if f.SrcEnrich.Geo.Kind != tc.kind || f.SrcEnrich.ASN.Kind != tc.kind || f.SrcEnrich.Rep.Kind != tc.kind {
				t.Fatalf("%+v", f.SrcEnrich)
			}
			if f.DstEnrich.Geo.Kind != tc.kind {
				t.Fatalf("%+v", f.DstEnrich)
			}
			snap := counters.Snapshot()
			switch tc.kind {
			case flow.OutcomeError:
				if snap[obs.EnrichGeoIPError] != 2 || snap[obs.DroppedWriterQueue] != 0 {
					t.Fatal(snap[obs.EnrichGeoIPError], snap[obs.DroppedWriterQueue])
				}
			case flow.OutcomeNoData:
				if snap[obs.EnrichASNNoData] != 2 {
					t.Fatal(snap[obs.EnrichASNNoData])
				}
			case flow.OutcomeNotConfigured:
				if snap[obs.EnrichReputationNotConfigured] != 2 {
					t.Fatal(snap[obs.EnrichReputationNotConfigured])
				}
			}
		})
	}
}

func TestTimeoutStillSubmits(t *testing.T) {
	var calls atomic.Int32
	p, _ := testPipeline(t, three(func(ctx context.Context, ip netip.Addr) Result {
		calls.Add(1)
		<-ctx.Done()
		return Result{Kind: flow.OutcomeValue, Geo: &Geo{Country: "US"}}
	}), enrichCfg(time.Hour, 20*time.Millisecond))
	sink := &memSink{}
	runFlows(t, p, sink, basicFlow("8.8.8.8", "1.1.1.1"))
	if len(sink.flows) != 1 {
		t.Fatalf("flows %d", len(sink.flows))
	}
	f := sink.flows[0]
	if f.SrcEnrich.Geo.Kind != flow.OutcomeError || f.DstEnrich.ASN.Kind != flow.OutcomeError || f.SrcEnrich.Rep.Kind != flow.OutcomeError {
		t.Fatalf("%+v %+v", f.SrcEnrich, f.DstEnrich)
	}
	if f.SrcEnrich.Geo.Country != "" {
		t.Fatal("timeout kept a value")
	}
	if calls.Load() != 6 {
		t.Fatalf("calls %d", calls.Load())
	}
}

func TestValuePayloadsAndDistinctTTLs(t *testing.T) {
	provs := []Provider{
		&scripted{name: ProviderGeoIP, fn: func(context.Context, netip.Addr) Result {
			return Result{Kind: flow.OutcomeValue, Geo: &Geo{Country: "US", Region: "CA", City: "A", Lat: 1, Lon: 2, HasLatLon: true}}
		}},
		&scripted{name: ProviderASN, fn: func(context.Context, netip.Addr) Result {
			return Result{Kind: flow.OutcomeValue, ASN: &ASN{Number: 15169, Name: "Google"}}
		}},
		&scripted{name: ProviderReputation, fn: func(context.Context, netip.Addr) Result {
			return Result{Kind: flow.OutcomeValue, Rep: &Rep{Category: "malware", Score: 0.5, HasScore: true}}
		}},
	}
	cfg := config.Enrich{GeoIPTTL: 24 * time.Hour, ASNTTL: 24 * time.Hour, ReputationTTL: time.Hour, LookupTimeout: time.Second}
	p, counters := testPipeline(t, provs, cfg)
	sink := &memSink{}
	runFlows(t, p, sink, basicFlow("8.8.8.8", "8.8.8.8"))
	f := sink.flows[0]
	if f.SrcEnrich.Geo.Country != "US" || !f.SrcEnrich.Geo.HasLatLon || f.SrcEnrich.Geo.Lat != 1 || f.SrcEnrich.ASN.ASN != 15169 || f.SrcEnrich.ASN.ASNName != "Google" {
		t.Fatalf("src %+v", f.SrcEnrich)
	}
	if f.SrcEnrich.Rep.Category != "malware" || !f.SrcEnrich.Rep.HasScore || f.SrcEnrich.Rep.Score != 0.5 {
		t.Fatalf("rep %+v", f.SrcEnrich)
	}
	// Same address: three lookups, not six. The second endpoint hits the cache.
	var n int32
	for _, prov := range provs {
		n += prov.(*scripted).calls.Load()
	}
	if n != 3 {
		t.Fatalf("calls %d", n)
	}
	if counters.Snapshot()[obs.EnrichGeoIPValue] != 2 || counters.Snapshot()[obs.EnrichReputationValue] != 2 {
		t.Fatal(counters.Snapshot()[obs.EnrichGeoIPValue], counters.Snapshot()[obs.EnrichReputationValue])
	}
	geoEnt, ok := p.caches[ProviderGeoIP].entries.Get(cacheKey(ProviderGeoIP, netip.MustParseAddr("8.8.8.8")))
	if !ok {
		t.Fatal("geo cache")
	}
	repEnt, ok := p.caches[ProviderReputation].entries.Get(cacheKey(ProviderReputation, netip.MustParseAddr("8.8.8.8")))
	if !ok {
		t.Fatal("rep cache")
	}
	if time.Until(geoEnt.expiresAt) < 20*time.Hour {
		t.Fatal(time.Until(geoEnt.expiresAt))
	}
	repLeft := time.Until(repEnt.expiresAt)
	if repLeft < 30*time.Minute || repLeft > time.Hour+2*time.Second {
		t.Fatal(repLeft)
	}
}

func TestIndependentEndpoints(t *testing.T) {
	var calls atomic.Int32
	p, _ := testPipeline(t, three(func(ctx context.Context, ip netip.Addr) Result {
		calls.Add(1)
		if ip == netip.MustParseAddr("1.1.1.1") {
			return Result{Kind: flow.OutcomeNoData}
		}
		return Result{Kind: flow.OutcomeError, ErrCode: "x"}
	}), enrichCfg(time.Hour, time.Second))
	sink := &memSink{}
	runFlows(t, p, sink, basicFlow("1.1.1.1", "8.8.8.8"))
	f := sink.flows[0]
	if f.SrcEnrich.Geo.Kind != flow.OutcomeNoData || f.DstEnrich.Geo.Kind != flow.OutcomeError {
		t.Fatalf("%+v %+v", f.SrcEnrich, f.DstEnrich)
	}
	if f.SrcEnrich.Rep.Kind != flow.OutcomeNoData || f.DstEnrich.ASN.Kind != flow.OutcomeError {
		t.Fatalf("%+v %+v", f.SrcEnrich, f.DstEnrich)
	}
	if calls.Load() != 6 {
		t.Fatalf("calls %d", calls.Load())
	}
}

func TestQueueFullDropsAndRunIgnoresIt(t *testing.T) {
	p, counters := testPipeline(t, three(nil), enrichCfg(time.Hour, time.Second))
	sink := &memSink{err: flow.ErrQueueFull}
	runFlows(t, p, sink, basicFlow("1.1.1.1", "8.8.8.8"), basicFlow("9.9.9.9", "1.0.0.1"))
	if len(sink.flows) != 0 {
		t.Fatalf("stored %d", len(sink.flows))
	}
	if counters.Snapshot()[obs.DroppedWriterQueue] != 2 {
		t.Fatal(counters.Snapshot()[obs.DroppedWriterQueue])
	}
}

func TestCancelSubmitsBufferedFlows(t *testing.T) {
	p, _ := testPipeline(t, three(nil), enrichCfg(time.Hour, time.Second))
	sink := &memSink{}
	ctx, cancel := context.WithCancel(context.Background())
	in := make(chan flow.Flow, 2)
	in <- basicFlow("10.1.0.1", "10.1.0.2")
	in <- basicFlow("10.2.0.1", "10.2.0.2")
	errc := make(chan error, 1)
	go func() {
		errc <- p.Run(ctx, in, sink)
	}()
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return")
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.flows) != 2 {
		t.Fatalf("submitted %d", len(sink.flows))
	}
}

func TestRunReturnsNilOnCancel(t *testing.T) {
	p, _ := testPipeline(t, three(nil), enrichCfg(time.Hour, time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	in := make(chan flow.Flow)
	errc := make(chan error, 1)
	go func() {
		errc <- p.Run(ctx, in, &memSink{})
	}()
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return")
	}
}

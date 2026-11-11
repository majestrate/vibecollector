package enrich

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/majestrate/vibecollector/internal/flow"
)

func TestNewCacheCap(t *testing.T) {
	if _, err := NewCache(0); !errors.Is(err, ErrBadCap) {
		t.Fatal(err)
	}
	if _, err := NewCache(-1); !errors.Is(err, ErrBadCap) {
		t.Fatal(err)
	}
	c, err := NewCache(1)
	if err != nil {
		t.Fatal(err)
	}
	if c.entries.Len() != 0 {
		t.Fatal(c.entries.Len())
	}
}

func TestCacheKeyUnmap(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	mapped := netip.MustParseAddr("::ffff:8.8.8.8")
	if cacheKey(ProviderGeoIP, ip) != "geoip\x008.8.8.8" {
		t.Fatal(cacheKey(ProviderGeoIP, ip))
	}
	if cacheKey(ProviderGeoIP, mapped) != cacheKey(ProviderGeoIP, ip) {
		t.Fatal("mapped key differs")
	}
	c, err := NewCache(4)
	if err != nil {
		t.Fatal(err)
	}
	var got []netip.Addr
	lookup := func(ctx context.Context, ip netip.Addr) Result {
		got = append(got, ip)
		return Result{Provider: ProviderGeoIP, Kind: flow.OutcomeNoData}
	}
	c.Get(context.Background(), ProviderGeoIP, mapped, time.Hour, time.Second, lookup)
	c.Get(context.Background(), ProviderGeoIP, ip, time.Hour, time.Second, lookup)
	if len(got) != 1 || got[0] != ip {
		t.Fatalf("%v", got)
	}
}

func TestSingleflight(t *testing.T) {
	c, err := NewCache(8)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	ip := netip.MustParseAddr("1.1.1.1")
	lookup := func(context.Context, netip.Addr) Result {
		calls.Add(1)
		time.Sleep(50 * time.Millisecond)
		return Result{Provider: ProviderGeoIP, Kind: flow.OutcomeNoData}
	}
	var wg sync.WaitGroup
	wg.Add(50)
	for i := 0; i < 50; i++ {
		go func() {
			defer wg.Done()
			got := c.Get(context.Background(), ProviderGeoIP, ip, time.Hour, time.Second, lookup)
			if got.Kind != flow.OutcomeNoData {
				t.Errorf("%s", got.Kind)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("calls %d", calls.Load())
	}
}

func TestExpiryBeforeEviction(t *testing.T) {
	c, err := NewCache(8)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("1.1.1.1")
	var calls atomic.Int32
	lookup := func(context.Context, netip.Addr) Result {
		calls.Add(1)
		return Result{Provider: ProviderGeoIP, Kind: flow.OutcomeValue, Geo: &Geo{Country: "US"}}
	}
	ctx := context.Background()
	if got := c.Get(ctx, ProviderGeoIP, ip, 24*time.Hour, time.Second, lookup); got.Geo == nil || got.Geo.Country != "US" {
		t.Fatalf("%+v", got)
	}
	if c.Get(ctx, ProviderGeoIP, ip, 24*time.Hour, time.Second, lookup).Kind != flow.OutcomeValue {
		t.Fatal("second get")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls %d", calls.Load())
	}
	key := cacheKey(ProviderGeoIP, ip)
	ent, ok := c.entries.Get(key)
	if !ok {
		t.Fatal("missing")
	}
	if c.entries.Len() != 1 {
		t.Fatalf("len %d", c.entries.Len())
	}
	// Move expiresAt into the past. The LRU still has room, so this is a miss, not an eviction.
	ent.expiresAt = time.Now().Add(-time.Second)
	c.entries.Add(key, ent)
	got := c.Get(ctx, ProviderGeoIP, ip, 24*time.Hour, time.Second, lookup)
	if calls.Load() != 2 {
		t.Fatalf("calls %d", calls.Load())
	}
	if got.Kind != flow.OutcomeValue || got.Geo.Country != "US" {
		t.Fatalf("%+v", got)
	}
	if c.entries.Len() != 1 {
		t.Fatalf("len %d", c.entries.Len())
	}
}

func TestErrorTTL(t *testing.T) {
	c, err := NewCache(4)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("1.1.1.1")
	var calls atomic.Int32
	lookup := func(context.Context, netip.Addr) Result {
		calls.Add(1)
		return Result{Provider: ProviderGeoIP, Kind: flow.OutcomeError, ErrCode: "down"}
	}
	c.Get(context.Background(), ProviderGeoIP, ip, 24*time.Hour, time.Second, lookup)
	key := cacheKey(ProviderGeoIP, ip)
	ent, ok := c.entries.Get(key)
	if !ok {
		t.Fatal("missing")
	}
	until := time.Until(ent.expiresAt)
	if until < 30*time.Second || until > time.Minute+2*time.Second {
		t.Fatalf("error ttl %s", until)
	}
	if c.Get(context.Background(), ProviderGeoIP, ip, 24*time.Hour, time.Second, lookup).ErrCode != "down" || calls.Load() != 1 {
		t.Fatalf("calls %d", calls.Load())
	}
	ent.expiresAt = time.Now().Add(-time.Millisecond)
	c.entries.Add(key, ent)
	if got := c.Get(context.Background(), ProviderGeoIP, ip, 24*time.Hour, time.Second, lookup); got.ErrCode != "down" || calls.Load() != 2 {
		t.Fatalf("%+v calls %d", got, calls.Load())
	}
}

func TestNotConfiguredAndNoDataUseTTL(t *testing.T) {
	for _, kind := range []flow.OutcomeKind{flow.OutcomeNotConfigured, flow.OutcomeNoData} {
		c, err := NewCache(4)
		if err != nil {
			t.Fatal(err)
		}
		ip := netip.MustParseAddr("9.9.9.9")
		var calls atomic.Int32
		lookup := func(context.Context, netip.Addr) Result {
			calls.Add(1)
			return Result{Provider: ProviderReputation, Kind: kind}
		}
		c.Get(context.Background(), ProviderReputation, ip, time.Hour, time.Second, lookup)
		ent, ok := c.entries.Get(cacheKey(ProviderReputation, ip))
		if !ok {
			t.Fatal("missing")
		}
		until := time.Until(ent.expiresAt)
		if until < 30*time.Minute || until > time.Hour+2*time.Second {
			t.Fatalf("%s ttl %s", kind, until)
		}
		ent.expiresAt = time.Now().Add(-time.Millisecond)
		c.entries.Add(cacheKey(ProviderReputation, ip), ent)
		c.Get(context.Background(), ProviderReputation, ip, time.Hour, time.Second, lookup)
		if calls.Load() != 2 {
			t.Fatalf("%s calls %d", kind, calls.Load())
		}
	}
}

func TestCancelledLookupNotStored(t *testing.T) {
	c, err := NewCache(4)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("1.1.1.1")
	var calls atomic.Int32
	lookup := func(ctx context.Context, ip netip.Addr) Result {
		calls.Add(1)
		<-ctx.Done()
		return Result{Provider: ProviderGeoIP, Kind: flow.OutcomeValue, Geo: &Geo{Country: "ZZ"}}
	}
	got := c.Get(context.Background(), ProviderGeoIP, ip, time.Hour, 20*time.Millisecond, lookup)
	if got.Kind != flow.OutcomeError || got.ErrCode != "timeout" {
		t.Fatalf("%+v", got)
	}
	got = c.Get(context.Background(), ProviderGeoIP, ip, time.Hour, 20*time.Millisecond, lookup)
	if got.ErrCode != "timeout" || calls.Load() != 2 {
		t.Fatalf("%+v calls %d", got, calls.Load())
	}
	if c.entries.Len() != 0 {
		t.Fatalf("stored a cancelled lookup, len %d", c.entries.Len())
	}
}

func TestWaiterTimeoutDoesNotCancelSharedLookup(t *testing.T) {
	c, err := NewCache(4)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("1.1.1.1")
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	var once sync.Once
	lookup := func(ctx context.Context, ip netip.Addr) Result {
		calls.Add(1)
		once.Do(func() { close(started) })
		select {
		case <-ctx.Done():
			return Result{Provider: ProviderGeoIP, Kind: flow.OutcomeError, ErrCode: "lookup-cancelled"}
		case <-release:
			return Result{Provider: ProviderGeoIP, Kind: flow.OutcomeValue, Geo: &Geo{Country: "US"}}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	res1c := make(chan Result, 1)
	go func() {
		res1c <- c.Get(ctx, ProviderGeoIP, ip, time.Hour, time.Minute, lookup)
	}()
	<-started
	cancel()
	res1 := <-res1c
	if res1.Kind != flow.OutcomeError || res1.ErrCode != "timeout" {
		t.Fatalf("waiter %+v", res1)
	}
	res2c := make(chan Result, 1)
	go func() {
		res2c <- c.Get(context.Background(), ProviderGeoIP, ip, time.Hour, time.Minute, lookup)
	}()
	close(release)
	res2 := <-res2c
	if res2.Kind != flow.OutcomeValue || res2.Geo == nil || res2.Geo.Country != "US" {
		t.Fatalf("shared %+v", res2)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls %d", calls.Load())
	}
	if got := c.Get(context.Background(), ProviderGeoIP, ip, time.Hour, time.Minute, lookup); got.Geo == nil || got.Geo.Country != "US" || calls.Load() != 1 {
		t.Fatalf("cache %+v calls %d", got, calls.Load())
	}
}

func TestEvict100001(t *testing.T) {
	const capN = 100000
	c, err := NewCache(capN)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	lookup := func(context.Context, netip.Addr) Result {
		calls.Add(1)
		return Result{Provider: ProviderASN, Kind: flow.OutcomeNoData}
	}
	ctx := context.Background()
	for i := 0; i < capN+1; i++ {
		c.Get(ctx, ProviderASN, nthIP(i), time.Hour, time.Second, lookup)
	}
	if calls.Load() != capN+1 {
		t.Fatalf("calls %d", calls.Load())
	}
	if c.entries.Len() != capN {
		t.Fatalf("len %d", c.entries.Len())
	}
	c.Get(ctx, ProviderASN, nthIP(0), time.Hour, time.Second, lookup)
	if calls.Load() != capN+2 {
		t.Fatalf("first key not evicted, calls %d", calls.Load())
	}
	c.Get(ctx, ProviderASN, nthIP(capN), time.Hour, time.Second, lookup)
	if calls.Load() != capN+2 {
		t.Fatalf("newest key evicted, calls %d", calls.Load())
	}
}

func nthIP(n int) netip.Addr {
	v := uint32(n)
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

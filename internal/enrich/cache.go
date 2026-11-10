package enrich

import (
	"context"
	"errors"
	"net/netip"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/sync/singleflight"

	"vibecollector/internal/flow"
)

// errorTTL is the negative cache for Kind error. It is not a config key.
const errorTTL = time.Minute

// ErrBadCap means entries was not positive. NewCache returns it and does
// not build a cache. errors.Is reports this sentinel.
var ErrBadCap = errors.New("non-positive cap")

type cached struct {
	result    Result
	expiresAt time.Time
}

// Cache is one provider's LRU of {result, expiresAt}. New from
// hashicorp/golang-lru/v2 has no per-entry TTL. The TTL is expiresAt.
// An expired get is a miss, and the miss check is inside singleflight.DoChan.
type Cache struct {
	entries *lru.Cache[string, cached]
	flight  singleflight.Group
}

// NewCache returns an empty cache. entries is the LRU cap.
// A non-positive entries returns ErrBadCap.
func NewCache(entries int) (*Cache, error) {
	if entries <= 0 {
		return nil, ErrBadCap
	}
	l, err := lru.New[string, cached](entries)
	if err != nil {
		return nil, err
	}
	return &Cache{entries: l}, nil
}

// Get returns the cached result for provider and ip.
// An entry older than its expiry is a miss even when the LRU is not full.
// lookup runs once for a cold or expired key, including when many callers wait.
// ttl applies to not_configured, no_data, and value. Kind error is stored
// for one minute regardless of ttl. A result produced by a cancelled lookup
// context is not stored. Get uses its own timeout context of lookupTimeout,
// detached from ctx, so one waiter timing out does not drop the shared call.
// Get does not return a Go error. The Result carries the outcome.
func (c *Cache) Get(ctx context.Context, provider ProviderName, ip netip.Addr, ttl, lookupTimeout time.Duration, lookup func(context.Context, netip.Addr) Result) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	key := cacheKey(provider, ip)
	// DoChan does not attach ctx to the shared call. Leaving this select does not cancel it.
	ch := c.flight.DoChan(key, func() (any, error) {
		return c.load(provider, ip, ttl, lookupTimeout, lookup), nil
	})
	select {
	case res := <-ch:
		return res.Val.(Result)
	case <-ctx.Done():
		select {
		case res := <-ch:
			return res.Val.(Result)
		default:
			return timeoutResult(provider)
		}
	}
}

func (c *Cache) load(provider ProviderName, ip netip.Addr, ttl, lookupTimeout time.Duration, lookup func(context.Context, netip.Addr) Result) Result {
	ip = ip.Unmap()
	key := cacheKey(provider, ip)
	if ent, ok := c.entries.Get(key); ok && time.Now().Before(ent.expiresAt) {
		return ent.result
	}
	// Detached from every waiter's ctx. One cancelled waiter must not abort this call.
	lctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	ch := make(chan Result, 1)
	go func() {
		ch <- lookup(lctx, ip)
	}()
	select {
	case res := <-ch:
		if lctx.Err() != nil {
			return timeoutResult(provider)
		}
		c.store(key, res, ttl)
		return res
	case <-lctx.Done():
		// Late lookup result is not stored. The provider goroutine exits on its own.
		return timeoutResult(provider)
	}
}

func (c *Cache) store(key string, res Result, ttl time.Duration) {
	life := ttl
	if res.Kind == flow.OutcomeError {
		life = errorTTL
	}
	c.entries.Add(key, cached{result: res, expiresAt: time.Now().Add(life)})
}

func cacheKey(provider ProviderName, ip netip.Addr) string {
	return string(provider) + "\x00" + ip.Unmap().String()
}

func timeoutResult(provider ProviderName) Result {
	return Result{Provider: provider, Kind: flow.OutcomeError, ErrCode: "timeout"}
}

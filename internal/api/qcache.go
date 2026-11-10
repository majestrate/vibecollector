package api

import (
	"errors"
	"fmt"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/sync/singleflight"
)

// ErrNilDep means NewServer was called without Query or Counters.
// errors.Is reports this sentinel.
var ErrNilDep = errors.New("nil dependency")

// ErrBadCap means a cache TTL or entry cap was not positive.
// NewQueryCache returns it and does not build a cache.
// errors.Is reports this sentinel.
var ErrBadCap = errors.New("non-positive cap")

type cacheEntry struct {
	body      []byte
	expiresAt time.Time
}

// Cache is the hot-query LRU. Do runs load once per key while callers wait.
// A bypass load is not stored. A load error is not stored.
type Cache struct {
	ttl     time.Duration
	entries *lru.Cache[string, cacheEntry]
	flight  singleflight.Group
}

// NewQueryCache returns an empty cache.
// ttl is how long a stored body stays a hit. entries is the LRU cap.
// A non-positive ttl or entries returns ErrBadCap.
func NewQueryCache(ttl time.Duration, entries int) (*Cache, error) {
	if ttl <= 0 || entries <= 0 {
		return nil, fmt.Errorf("%w", ErrBadCap)
	}
	l, err := lru.New[string, cacheEntry](entries)
	if err != nil {
		return nil, err
	}
	return &Cache{ttl: ttl, entries: l}, nil
}

// Do returns the cached body for key, or calls load.
// bypass true runs load and does not store the body. Cache-Control no-store uses that.
// A non-nil error from load, including FilterError and ErrQueryTimeout, is returned
// and not stored. Concurrent calls for one key share one load.
// The caller owns the returned slice.
func (c *Cache) Do(key string, bypass bool, load func() ([]byte, error)) ([]byte, error) {
	if bypass {
		return load()
	}
	if body, ok := c.fresh(key); ok {
		return body, nil
	}
	v, err, _ := c.flight.Do(key, func() (any, error) {
		if body, ok := c.fresh(key); ok {
			return body, nil
		}
		body, err := load()
		if err != nil {
			return nil, err
		}
		c.entries.Add(key, cacheEntry{body: append([]byte(nil), body...), expiresAt: time.Now().Add(c.ttl)})
		return body, nil
	})
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), v.([]byte)...), nil
}

func (c *Cache) fresh(key string) ([]byte, bool) {
	ent, ok := c.entries.Get(key)
	if !ok {
		return nil, false
	}
	if time.Now().After(ent.expiresAt) {
		c.entries.Remove(key)
		return nil, false
	}
	return append([]byte(nil), ent.body...), true
}

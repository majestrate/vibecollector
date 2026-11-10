package sampling

import (
	"net/netip"
	"sync"
)

// SampleKey is one sampling fact. Scope is "device", "if:<n>", "sampler:<n>",
// "linecard:<n>", "cache:<n>", or "template:<n>". Exporter is the UDP source
// IP, unmapped. The source port is not part of the key.
type SampleKey struct {
	Exporter netip.Addr
	Domain   uint32
	Scope    string
}

// Sample is the fact options data or a v5 header stored.
// N is 1-of-N. Zero means unknown. Algorithm is the raw octet, 0 if absent.
// Sampled is true only when N > 1.
type Sample struct {
	N         uint32
	Algorithm uint8
	Sampled   bool
}

// Cache stores sampling facts. Methods are safe for concurrent use.
// There is no TTL. Session pairs a write with template and sequence updates.
// Cache does not lock the template map.
type Cache struct {
	mu sync.Mutex
	m  map[SampleKey]Sample
}

// NewCache returns an empty cache. It does not return an error.
func NewCache() *Cache {
	return &Cache{m: make(map[SampleKey]Sample)}
}

// Put stores one fact. A later Put for the same key replaces it.
// Exporter is unmapped. Put does not return an error.
func (c *Cache) Put(key SampleKey, s Sample) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key.Exporter = key.Exporter.Unmap()
	c.m[key] = s
}

// Lookup returns the first scope in scopes that is present for exporter and
// domain, including a fact whose N is 0. scopes is the parser's order: the
// data record's own fields are not in the cache; the caller tries those
// first, then if:<input>, sampler:<id>, linecard, cache, template, and
// device. ok is false when none match. Exporter is unmapped. Lookup does
// not return an error.
func (c *Cache) Lookup(exporter netip.Addr, domain uint32, scopes []string) (Sample, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	exporter = exporter.Unmap()
	for _, scope := range scopes {
		s, ok := c.m[SampleKey{Exporter: exporter, Domain: domain, Scope: scope}]
		if ok {
			return s, true
		}
	}
	return Sample{}, false
}

// Facts returns a copy of every fact stored for exporter and domain.
// The map key is the scope string. Exporter is unmapped. Nothing stored
// returns nil. Facts does not return an error.
func (c *Cache) Facts(exporter netip.Addr, domain uint32) map[string]Sample {
	c.mu.Lock()
	defer c.mu.Unlock()
	exporter = exporter.Unmap()
	var out map[string]Sample
	for k, s := range c.m {
		if k.Exporter != exporter || k.Domain != domain {
			continue
		}
		if out == nil {
			out = make(map[string]Sample)
		}
		out[k.Scope] = s
	}
	return out
}

// DropExporter removes every fact for ip. Session calls it on idle expiry
// and on template-cap eviction. ip is unmapped. DropExporter does not return
// an error.
func (c *Cache) DropExporter(ip netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ip = ip.Unmap()
	for k := range c.m {
		if k.Exporter == ip {
			delete(c.m, k)
		}
	}
}

// Package template stores NetFlow v9 and IPFIX template definitions and the
// datagrams waiting on a definition.
package template

import (
	"encoding/binary"
	"errors"
	"hash/fnv"
	"net/netip"
	"sync"
	"time"
)

// ErrBadCap means a constructor cap was not positive.
// NewCache and NewHold return it and do not build the object.
// errors.Is reports this sentinel.
var ErrBadCap = errors.New("non-positive cap")

// ErrBadKey means Version is not 9 or 10, or a v9 template ID is below 256.
// Put returns it and does not store the template. errors.Is reports this sentinel.
var ErrBadKey = errors.New("bad template key")

// Key identifies one template. Exporter is the UDP source IP, unmapped, port
// discarded. Domain is the v9 source ID or the IPFIX observation domain.
// Version is 9 or 10. ID is the template ID. Collector IP, collector port,
// and source port are not part of the key.
type Key struct {
	Exporter netip.Addr
	Domain   uint32
	Version  uint16
	ID       uint16
}

// Template is one definition. Fields is the ordered field list.
// ScopeN is the IPFIX scope field count, or the v9 scope-field count
// (option scope length in bytes divided by 4). Zero ScopeN is a data
// template. Received is when this definition was stored. Definition is a
// hash of the field list and ScopeN.
type Template struct {
	Fields     []Field
	ScopeN     int
	Received   time.Time
	Definition uint64
}

// Field is one field specifier. Type is the IANA number with the enterprise
// bit already cleared. Length is the template length in bytes. Enterprise is
// 0 for a standard IE. Variable is true when Length is 65535.
type Field struct {
	Type       uint16
	Length     uint16
	Enterprise uint32
	Variable   bool
}

// Cache is the process-wide template map. Methods are safe for concurrent
// callers on different keys. Same-key consistency with hold, sampling, and
// sequence is Session's mutex, not a lock the caller takes on Cache.
// The map is not an LRU and templates have no TTL. Idle expiry is exporter
// silence, measured by Touch.
type Cache struct {
	mu      sync.Mutex
	max     int
	byKey   map[Key]Template
	touch   map[netip.Addr]time.Time
	pending map[netip.Addr][]netip.Addr
}

// NewCache returns an empty cache. maxTemplates is the process cap.
// The running collector uses 50,000. A non-positive cap returns ErrBadCap.
func NewCache(maxTemplates int) (*Cache, error) {
	if maxTemplates <= 0 {
		return nil, ErrBadCap
	}
	return &Cache{
		max:     maxTemplates,
		byKey:   make(map[Key]Template),
		touch:   make(map[netip.Addr]time.Time),
		pending: make(map[netip.Addr][]netip.Addr),
	}, nil
}

// Touch records that a datagram from ip arrived at t. Idle expiry uses this
// clock. Silence is no packets from the IP, not a missing retransmission.
// ip is unmapped. Touch does not return an error.
func (c *Cache) Touch(ip netip.Addr, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.touch[ip.Unmap()] = at
}

// Get returns a copy of the template stored for key. ok is false when it is
// absent. Get does not count a miss. The parser increments missing_template.
// Exporter is unmapped. Get does not return an error.
func (c *Cache) Get(key Key) (Template, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key.Exporter = key.Exporter.Unmap()
	t, ok := c.byKey[key]
	if !ok {
		return Template{}, false
	}
	t.Fields = copyFields(t.Fields)
	return t, true
}

// Put inserts or replaces key. changed is true when a previous field list
// hashed differently. The caller increments template_redefined when changed
// is true. An identical retransmission returns changed false and is not logged.
// When the insert would exceed the cap, Put first removes every template of
// the exporter with the oldest Touch time and returns that IP in evicted.
// evicted is invalid when nothing was evicted. Put does not drop hold,
// sampling, or sequence state. The caller reads the same IP from TakeEvictions.
// ErrBadKey means Version is not 9 or 10, or a v9 ID is below 256.
// Definition is replaced with a hash of ScopeN and the field list.
func (c *Cache) Put(key Key, t Template) (changed bool, evicted netip.Addr, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key.Exporter = key.Exporter.Unmap()
	if key.Version != 9 && key.Version != 10 {
		return false, netip.Addr{}, ErrBadKey
	}
	if key.Version == 9 && key.ID < 256 {
		return false, netip.Addr{}, ErrBadKey
	}
	stored := t
	stored.Fields = copyFields(t.Fields)
	stored.Definition = definitionHash(stored.ScopeN, stored.Fields)
	if old, ok := c.byKey[key]; ok {
		c.byKey[key] = stored
		return old.Definition != stored.Definition, netip.Addr{}, nil
	}
	if len(c.byKey) >= c.max {
		victim := c.oldestExporter()
		if victim.IsValid() {
			c.deleteExporter(victim, true)
			c.pending[key.Exporter] = append(c.pending[key.Exporter], victim)
			evicted = victim
		}
	}
	c.byKey[key] = stored
	return false, evicted, nil
}

// TakeEvictions returns exporter IPs that Put evicted while inserting
// templates for by, and clears that list. Accept calls it for the source IP
// it already locked. by is unmapped. The caller drops that IP's hold,
// sampling, and sequence state when the victim is by, and records any other
// victim for ExpireIdle. TakeEvictions does not return an error.
func (c *Cache) TakeEvictions(by netip.Addr) []netip.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	by = by.Unmap()
	out := c.pending[by]
	delete(c.pending, by)
	if len(out) == 0 {
		return nil
	}
	cp := append([]netip.Addr(nil), out...)
	return cp
}

// Withdraw removes templates for one IPFIX withdrawal record.
// allData true withdraws every version-10 data template (ScopeN == 0) for
// that exporter and domain. allOptions true withdraws every version-10
// options template (ScopeN > 0). Otherwise id is one version-10 ID.
// removed is how many definitions were deleted. unknown is true when a
// single-ID withdrawal named an ID that was not present.
// The caller increments templates_withdrawn by removed, or withdraw_unknown
// when unknown is true. Withdraw does not flush the hold buffer.
// v9 does not call Withdraw. Withdraw does not return an error.
func (c *Cache) Withdraw(exporter netip.Addr, domain uint32, id uint16, allData, allOptions bool) (removed int, unknown bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	exporter = exporter.Unmap()
	if allData || allOptions {
		for k, t := range c.byKey {
			if k.Exporter != exporter || k.Domain != domain || k.Version != 10 {
				continue
			}
			opts := t.ScopeN > 0
			if (allData && !opts) || (allOptions && opts) {
				delete(c.byKey, k)
				removed++
			}
		}
		return removed, false
	}
	key := Key{Exporter: exporter, Domain: domain, Version: 10, ID: id}
	if _, ok := c.byKey[key]; !ok {
		return 0, true
	}
	delete(c.byKey, key)
	return 1, false
}

// IdleExporters returns IPs whose last Touch is strictly before now.Add(-idle).
// The result is a copy. Session then drops each IP. Cache does not drop them
// itself. IdleExporters does not return an error.
func (c *Cache) IdleExporters(now time.Time, idle time.Duration) []netip.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	deadline := now.Add(-idle)
	var out []netip.Addr
	for ip, tm := range c.touch {
		if tm.Before(deadline) {
			out = append(out, ip)
		}
	}
	return out
}

// DropExporter removes every template for ip and forgets its Touch time.
// Session calls this on idle expiry and on cap eviction of a different IP.
// ip is unmapped. DropExporter does not return an error.
func (c *Cache) DropExporter(ip netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deleteExporter(ip.Unmap(), true)
}

func (c *Cache) deleteExporter(ip netip.Addr, clearTouch bool) {
	for k := range c.byKey {
		if k.Exporter == ip {
			delete(c.byKey, k)
		}
	}
	if clearTouch {
		delete(c.touch, ip)
	}
}

// oldestExporter is the IP that currently has a template and the oldest Touch.
// A missing Touch is older than any stored time. The call holds c.mu.
func (c *Cache) oldestExporter() netip.Addr {
	var best netip.Addr
	var bestT time.Time
	seen := make(map[netip.Addr]struct{})
	first := true
	for k := range c.byKey {
		if _, ok := seen[k.Exporter]; ok {
			continue
		}
		seen[k.Exporter] = struct{}{}
		tm, ok := c.touch[k.Exporter]
		if !ok {
			tm = time.Time{}
		}
		if first || tm.Before(bestT) || (tm.Equal(bestT) && k.Exporter.Compare(best) < 0) {
			first = false
			best = k.Exporter
			bestT = tm
		}
	}
	return best
}

func copyFields(in []Field) []Field {
	if len(in) == 0 {
		return nil
	}
	return append([]Field(nil), in...)
}

func definitionHash(scopeN int, fields []Field) uint64 {
	h := fnv.New64a()
	var buf [8]byte
	binary.BigEndian.PutUint32(buf[:4], uint32(scopeN))
	_, _ = h.Write(buf[:4])
	for _, f := range fields {
		binary.BigEndian.PutUint16(buf[0:2], f.Type)
		binary.BigEndian.PutUint16(buf[2:4], f.Length)
		binary.BigEndian.PutUint32(buf[4:8], f.Enterprise)
		_, _ = h.Write(buf[:8])
		if f.Variable {
			_, _ = h.Write([]byte{1})
		} else {
			_, _ = h.Write([]byte{0})
		}
	}
	return h.Sum64()
}

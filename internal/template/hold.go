package template

import (
	"net/netip"
	"sync"
	"time"

	"vibecollector/internal/sequence"
)

// Pending is one copied datagram waiting on a template.
// Payload is the copy Put stored. RetryAt is the offset of the first
// unresolved data set in that copy, so a retry does not emit records that
// an earlier set in the same packet already produced. SeqSnap is the
// snapshot ObserveUnresolved returned; v9 leaves it zero because a parsed
// v9 header already moved the cursor. ID is assigned by Put and is zero on
// input. Exporter is the UDP source IP, unmapped. The source port is not kept.
type Pending struct {
	ID         uint64
	Exporter   netip.Addr
	Domain     uint32
	Version    uint16
	Payload    []byte
	ReceivedAt time.Time
	RetryAt    int
	SeqSnap    sequence.Snapshot
}

// Hold is the bounded pre-template buffer for every exporter.
// Caps are per exporter IP and global. Methods are safe for concurrent use.
// Session still serializes one exporter's Accept around Put and List.
type Hold struct {
	mu     sync.Mutex
	per    int
	global int
	next   uint64
	q      map[netip.Addr][]Pending
	n      int
}

// NewHold returns an empty buffer. perExporter and global are the caps.
// The running collector uses 256 and 4096. A non-positive cap returns ErrBadCap.
func NewHold(perExporter, global int) (*Hold, error) {
	if perExporter <= 0 || global <= 0 {
		return nil, ErrBadCap
	}
	return &Hold{
		per:    perExporter,
		global: global,
		q:      make(map[netip.Addr][]Pending),
	}, nil
}

// Put copies p into the buffer. When the per-exporter or global cap would be
// exceeded, Put drops the oldest datagram for p.Exporter first. If that
// exporter has none and the global cap is full, Put drops the oldest datagram
// in the buffer so the new entry still fits. dropped is 1 when a datagram was
// discarded and 0 otherwise. The caller increments dropped_template by dropped.
// id is the stored entry. The new entry is not the one that was dropped.
// Put does not fail and does not return an error.
func (h *Hold) Put(p Pending) (id uint64, dropped int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p.Exporter = p.Exporter.Unmap()
	if p.Payload != nil {
		p.Payload = append([]byte(nil), p.Payload...)
	}
	if len(h.q[p.Exporter]) >= h.per || h.n >= h.global {
		if h.dropOne(p.Exporter) {
			dropped = 1
		}
	}
	h.next++
	p.ID = h.next
	h.q[p.Exporter] = append(h.q[p.Exporter], p)
	h.n++
	return p.ID, dropped
}

// List returns ip's entries in arrival order. The caller retries them under
// the exporter mutex. An entry that still lacks a template stays where it is.
// List does not move entries and does not copy payloads. ip is unmapped.
// List does not return an error.
func (h *Hold) List(ip netip.Addr) []Pending {
	h.mu.Lock()
	defer h.mu.Unlock()
	entries := h.q[ip.Unmap()]
	if len(entries) == 0 {
		return nil
	}
	out := make([]Pending, len(entries))
	copy(out, entries)
	return out
}

// Remove deletes one entry. Session calls it after a retry no longer lacks a
// template. A missing id is a no-op. ip is unmapped. Remove does not return
// an error.
func (h *Hold) Remove(ip netip.Addr, id uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ip = ip.Unmap()
	entries := h.q[ip]
	for i, e := range entries {
		if e.ID == id {
			h.removeAt(ip, i)
			return
		}
	}
}

// Advance sets one entry's retry offset and leaves it in arrival order.
// Session calls it when a retry emitted earlier sets and a later set is still
// unresolved. A missing id is a no-op. ip is unmapped. Advance does not
// return an error.
func (h *Hold) Advance(ip netip.Addr, id uint64, retryAt int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ip = ip.Unmap()
	entries := h.q[ip]
	for i := range entries {
		if entries[i].ID == id {
			entries[i].RetryAt = retryAt
			h.q[ip] = entries
			return
		}
	}
}

// DropExporter deletes every entry for ip. ip is unmapped.
// DropExporter does not return an error.
func (h *Hold) DropExporter(ip netip.Addr) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ip = ip.Unmap()
	h.n -= len(h.q[ip])
	delete(h.q, ip)
}

// dropOne removes the oldest entry for ip, or the globally oldest entry when
// ip's queue is empty. The call holds h.mu.
func (h *Hold) dropOne(ip netip.Addr) bool {
	if len(h.q[ip]) > 0 {
		h.removeAt(ip, 0)
		return true
	}
	// This exporter has nothing queued, and the global cap is still full.
	// Drop the oldest datagram in the buffer so the insert stays inside the cap.
	var oldestIP netip.Addr
	var oldestID uint64
	found := false
	for eip, entries := range h.q {
		if len(entries) == 0 {
			continue
		}
		if !found || entries[0].ID < oldestID {
			found = true
			oldestID = entries[0].ID
			oldestIP = eip
		}
	}
	if !found {
		return false
	}
	h.removeAt(oldestIP, 0)
	return true
}

func (h *Hold) removeAt(ip netip.Addr, i int) {
	entries := h.q[ip]
	h.q[ip] = append(entries[:i], entries[i+1:]...)
	h.n--
	if len(h.q[ip]) == 0 {
		delete(h.q, ip)
	}
}

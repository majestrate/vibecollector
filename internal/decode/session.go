package decode

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"vibecollector/internal/flow"
	"vibecollector/internal/ingest"
	"vibecollector/internal/obs"
	"vibecollector/internal/sampling"
	"vibecollector/internal/sequence"
	"vibecollector/internal/template"
)

// Session serializes one exporter IP across template.Cache, template.Hold,
// sampling.Cache, and sequence.Table. Decode workers call Accept.
// The reaper calls ExpireIdle. Nothing else calls the four together.
// There is no State struct. The per-exporter mutex map is unexported.
type Session struct {
	templates *template.Cache
	hold      *template.Hold
	samples   *sampling.Cache
	seq       *sequence.Table
	counters  *obs.Counters
	maxAge    time.Duration
	skew      time.Duration

	mu    sync.Mutex
	locks map[netip.Addr]*sync.Mutex
	evict map[netip.Addr]struct{}
}

// NewSession stores the four objects, the counters, and the timestamp window.
// main constructs the four and passes them here. A nil argument returns
// ErrNilDep. maxAge and skew are timestamp_max_age and timestamp_skew_slack.
// Zero is kept and is not replaced with a default. NewSession does not start
// a goroutine.
func NewSession(templates *template.Cache, hold *template.Hold, samples *sampling.Cache, seq *sequence.Table, counters *obs.Counters, maxAge, skew time.Duration) (*Session, error) {
	if templates == nil || hold == nil || samples == nil || seq == nil || counters == nil {
		return nil, ErrNilDep
	}
	return &Session{
		templates: templates,
		hold:      hold,
		samples:   samples,
		seq:       seq,
		counters:  counters,
		maxAge:    maxAge,
		skew:      skew,
		locks:     make(map[netip.Addr]*sync.Mutex),
		evict:     make(map[netip.Addr]struct{}),
	}, nil
}

// Accept decodes one datagram for d.Src.
// It holds that exporter IP's mutex for the whole call, including the
// hold-buffer retry after a template install. Two Accept calls for different
// IPs run in parallel. Two Accept calls for the same IP do not.
// d.Payload is the UDP payload. d.ReceivedAt is the reader's timestamp.
// The returned flows are not enriched. delta is always set. A payload shorter
// than 2 bytes, or a version other than 5 or 9, still returns a delta with
// Version 0 and Domain 0 after incrementing malformed once. Version 10 takes
// that path.
// flows may be empty. Accept does not enqueue and does not return an error.
// When a data set has no template, Accept copies the datagram into Hold under
// the same mutex. A worker never locks two exporter mutexes.
// When Cache.Put evicts d.Src, Accept drops that IP's hold, sampling, and
// sequence state under the mutex it already holds. When the evicted IP is a
// different address, Accept records it and does not lock it. ExpireIdle drops
// that IP. A structural failure leaves malformed incremented once by the
// parser. Accept does not increment it again. A hold retry does not increment
// missing_template or malformed a second time for the same set, and it does
// not call Observe again.
func (s *Session) Accept(d ingest.Datagram) (flows []flow.Flow, delta flow.ExporterDelta) {
	ip := d.Src.Unmap()
	mu := s.mutexFor(ip)
	mu.Lock()
	defer mu.Unlock()

	s.templates.Touch(ip, d.ReceivedAt)
	flows, delta, missing, _ := Dispatch(d, s.templates, s.samples, s.seq, s.counters, false, s.maxAge, s.skew)
	s.applyEvictions(ip, d.ReceivedAt)
	if missing != nil {
		missing.Exporter = ip
		missing.ReceivedAt = d.ReceivedAt
		if len(missing.Payload) == 0 {
			missing.Payload = d.Payload
		}
		if missing.Version == 0 {
			missing.Version = delta.Version
		}
		_, dropped := s.hold.Put(*missing)
		if dropped > 0 {
			_ = s.counters.Add(obs.DroppedTemplate, uint64(dropped))
		}
	}
	extra := s.drain(ip, d.ReceivedAt)
	if len(extra) > 0 {
		flows = append(flows, extra...)
		delta.Flows += uint64(len(extra))
	}
	return flows, delta
}

// ExpireIdle drops template, hold, sampling, and sequence state for every
// exporter IP whose last datagram is strictly older than idle, and for every
// IP that Accept recorded as a cap eviction of a different exporter. now is
// the collector clock. The returned IPs are the idle ones, not the recorded
// evictions. The caller increments template_idle_expired once per returned IP.
// template_evicted is already counted at Put. The next packet from a dropped
// IP is a new stream and is not a gap. A non-positive idle returns
// ErrBadTimeout and drops nothing, including recorded evictions.
// ExpireIdle locks one exporter mutex at a time and releases it before taking
// the next.
func (s *Session) ExpireIdle(now time.Time, idle time.Duration) ([]netip.Addr, error) {
	if idle <= 0 {
		return nil, ErrBadTimeout
	}
	s.mu.Lock()
	evicts := make([]netip.Addr, 0, len(s.evict))
	for ip := range s.evict {
		evicts = append(evicts, ip)
	}
	s.evict = make(map[netip.Addr]struct{})
	s.mu.Unlock()

	seen := make(map[netip.Addr]struct{}, len(evicts))
	for _, ip := range evicts {
		ip = ip.Unmap()
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		s.dropIP(ip)
	}
	var idleIPs []netip.Addr
	for _, ip := range s.templates.IdleExporters(now, idle) {
		ip = ip.Unmap()
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		s.dropIP(ip)
		idleIPs = append(idleIPs, ip)
	}
	sort.Slice(idleIPs, func(i, j int) bool { return idleIPs[i].Compare(idleIPs[j]) < 0 })
	return idleIPs, nil
}

func (s *Session) mutexFor(ip netip.Addr) *sync.Mutex {
	ip = ip.Unmap()
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.locks[ip]
	if m == nil {
		m = &sync.Mutex{}
		s.locks[ip] = m
	}
	return m
}

func (s *Session) applyEvictions(ip netip.Addr, at time.Time) (self bool) {
	for _, ev := range s.templates.TakeEvictions(ip) {
		ev = ev.Unmap()
		if ev == ip {
			s.hold.DropExporter(ip)
			s.samples.DropExporter(ip)
			s.seq.DropExporter(ip)
			// Put cleared this IP's touch while removing the old templates.
			s.templates.Touch(ip, at)
			self = true
			continue
		}
		s.mu.Lock()
		s.evict[ev] = struct{}{}
		s.mu.Unlock()
	}
	return self
}

func (s *Session) dropIP(ip netip.Addr) {
	mu := s.mutexFor(ip)
	mu.Lock()
	s.templates.DropExporter(ip)
	s.hold.DropExporter(ip)
	s.samples.DropExporter(ip)
	s.seq.DropExporter(ip)
	mu.Unlock()
}

func (s *Session) drain(ip netip.Addr, at time.Time) []flow.Flow {
	entries := s.hold.List(ip)
	var out []flow.Flow
	for _, p := range entries {
		payload, stripped := replayPayload(p.Payload, p.RetryAt)
		rd := ingest.Datagram{Payload: payload, Src: p.Exporter, ReceivedAt: p.ReceivedAt}
		flows, _, missing, _ := Dispatch(rd, s.templates, s.samples, s.seq, s.counters, true, s.maxAge, s.skew)
		// A retry that evicted this exporter already dropped the queue.
		// The snapshot must not decode the copies that drop removed.
		if s.applyEvictions(ip, at) {
			out = append(out, flows...)
			return out
		}
		out = append(out, flows...)
		if missing == nil {
			s.hold.Remove(ip, p.ID)
			continue
		}
		next := missing.RetryAt
		if stripped && missing.RetryAt > headerLenV9 {
			next = p.RetryAt + (missing.RetryAt - headerLenV9)
		} else if stripped {
			next = p.RetryAt
		}
		if next != p.RetryAt {
			s.hold.Advance(ip, p.ID, next)
		}
	}
	return out
}

const headerLenV9 = 20

func replayPayload(original []byte, retryAt int) ([]byte, bool) {
	if retryAt <= headerLenV9 || retryAt > len(original) || len(original) < headerLenV9 {
		return original, false
	}
	out := make([]byte, headerLenV9+len(original)-retryAt)
	copy(out[:headerLenV9], original[:headerLenV9])
	copy(out[headerLenV9:], original[retryAt:])
	return out, true
}

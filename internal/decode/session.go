package decode

import (
	"encoding/binary"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/majestrate/vibecollector/internal/flow"
	"github.com/majestrate/vibecollector/internal/ingest"
	"github.com/majestrate/vibecollector/internal/obs"
	"github.com/majestrate/vibecollector/internal/sampling"
	"github.com/majestrate/vibecollector/internal/sequence"
	"github.com/majestrate/vibecollector/internal/template"
)

// exporterForget drops parser state that is not in the template, hold,
// sampling, or sequence objects. IPFIX registers it for the cached
// systemInitTimeMilliseconds. Nil skips the call.
var exporterForget func(netip.Addr)

// RegisterExporterForget stores the function Session calls when it drops an
// exporter before the next datagram, or on idle expiry. The IPFIX parser
// uses it so a cached systemInitTimeMilliseconds does not outlive the
// exporter. Self-eviction inside a parse does not come through here; that
// parser clears its own cache before later records in the same datagram.
// A second call replaces the function. RegisterExporterForget does not
// return an error.
func RegisterExporterForget(fn func(netip.Addr)) { exporterForget = fn }

// IPFIXHoldOps keeps an unresolved IPFIX sequence snapshot with one hold
// entry. Two holds can share a sequence number, so the snapshot cannot live
// in one map slot keyed only by that number. Dispatch cannot take the hold
// id. ipfix.init registers the funcs. A nil func is skipped.
// Bind attaches the snapshot the parser just saved to the id Hold.Put
// returned, and drops the shared sequence slot. Drop deletes that id.
// Retain deletes snapshots for ip whose ids are not in live, which is how a
// cap discard is removed. Arm selects id for the retry Dispatch that
// follows, using the Pending.SeqSnap the hold stored. Clear drops that
// selection when the parser did not take it.
type IPFIXHoldOps struct {
	Bind   func(ip netip.Addr, id uint64)
	Drop   func(id uint64)
	Retain func(ip netip.Addr, live []uint64)
	Arm    func(ip netip.Addr, id uint64, snap sequence.Snapshot)
	Clear  func(ip netip.Addr)
}

var ipfixHold IPFIXHoldOps

// RegisterIPFIXHold stores the funcs Session calls around Hold.Put, Remove,
// and the retry Dispatch. A second call replaces them. RegisterIPFIXHold
// does not return an error.
func RegisterIPFIXHold(ops IPFIXHoldOps) { ipfixHold = ops }

func bindIPFIXHold(ip netip.Addr, id uint64) {
	if ipfixHold.Bind != nil {
		ipfixHold.Bind(ip, id)
	}
}

func dropIPFIXHold(id uint64) {
	if ipfixHold.Drop != nil {
		ipfixHold.Drop(id)
	}
}

func retainIPFIXHolds(ip netip.Addr, live []uint64) {
	if ipfixHold.Retain != nil {
		ipfixHold.Retain(ip, live)
	}
}

func armIPFIXRetry(ip netip.Addr, id uint64, snap sequence.Snapshot) {
	if ipfixHold.Arm != nil {
		ipfixHold.Arm(ip, id, snap)
	}
}

func clearIPFIXRetry(ip netip.Addr) {
	if ipfixHold.Clear != nil {
		ipfixHold.Clear(ip)
	}
}

func forgetExporter(ip netip.Addr) {
	if exporterForget != nil {
		exporterForget(ip)
	}
}

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
// than 2 bytes, or a version other than 5, 9, or 10, still returns a delta
// with Version 0 and Domain 0 after incrementing malformed once. A version
// whose parser is not registered takes that path. A short IPFIX header is
// version 10 and malformed.
// flows may be empty. Accept does not enqueue and does not return an error.
// gaps are GapRecords from a hold retry whose observation domain is not
// delta.Domain. Each one is that held entry's own delta: Exporter, Domain,
// Version, LastSeen, and GapRecords only. Same-domain GapRecords are added
// to delta. A retry does not add its Packets, Malformed, or MissingTemplate.
// When a data set has no template, Accept copies the datagram into Hold under
// the same mutex. A worker never locks two exporter mutexes.
// If this IP is in the recorded eviction set, Accept drops its hold, sampling,
// and sequence state and removes the set entry before Dispatch. It does not
// drop templates. ExpireIdle still drops recorded IPs that have not spoken
// since the eviction.
// When Cache.Put evicts d.Src, sampling and sequence are dropped at that Put,
// before later records in the datagram store new facts. Accept then drops
// that IP's hold under the mutex it already holds and does not drop those
// facts. When the evicted IP is a different address, Accept records it and
// does not lock it. ExpireIdle drops that IP. A structural failure leaves
// malformed incremented once by the parser. Accept does not increment it
// again. A hold retry does not increment missing_template or malformed a
// second time for the same set, and it does not call Observe again.
func (s *Session) Accept(d ingest.Datagram) (flows []flow.Flow, delta flow.ExporterDelta, gaps []flow.ExporterDelta) {
	ip := d.Src.Unmap()
	mu := s.mutexFor(ip)
	mu.Lock()
	defer mu.Unlock()

	s.mu.Lock()
	_, recorded := s.evict[ip]
	if recorded {
		delete(s.evict, ip)
	}
	s.mu.Unlock()
	if recorded {
		s.noteHoldDrop(s.hold.DropExporter(ip))
		s.samples.DropExporter(ip)
		s.seq.DropExporter(ip)
		forgetExporter(ip)
	}
	// A previous hold instance can reuse ids. Drop snapshots it no longer has.
	retainIPFIXHolds(ip, holdIDs(s.hold.List(ip)))

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
		id, dropped := s.hold.Put(*missing)
		bindIPFIXHold(ip, id)
		if dropped > 0 {
			_ = s.counters.Add(obs.DroppedTemplate, uint64(dropped))
			retainIPFIXHolds(ip, holdIDs(s.hold.List(ip)))
		}
	}
	extra, retryGaps := s.drain(ip, d.ReceivedAt)
	if len(extra) > 0 {
		flows = append(flows, extra...)
		delta.Flows += uint64(len(extra))
	}
	delta, gaps = foldRetryGaps(delta, retryGaps)
	return flows, delta, gaps
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
// the next. That mutex is taken before the session mutex. A recorded IP is
// dropped only when it is still in the eviction set, and an idle IP only when
// its touch is still older than idle. The set is not cleared before those checks.
func (s *Session) ExpireIdle(now time.Time, idle time.Duration) ([]netip.Addr, error) {
	if idle <= 0 {
		return nil, ErrBadTimeout
	}
	s.mu.Lock()
	evicts := make([]netip.Addr, 0, len(s.evict))
	for ip := range s.evict {
		evicts = append(evicts, ip)
	}
	s.mu.Unlock()

	seen := make(map[netip.Addr]struct{}, len(evicts))
	for _, ip := range evicts {
		ip = ip.Unmap()
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		s.dropRecorded(ip)
	}
	var idleIPs []netip.Addr
	for _, ip := range s.templates.IdleExporters(now, idle) {
		ip = ip.Unmap()
		if _, ok := seen[ip]; ok {
			continue
		}
		if s.dropIfIdle(ip, now, idle) {
			idleIPs = append(idleIPs, ip)
		}
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
			// Sampling and sequence were dropped when Put reported this IP.
			s.noteHoldDrop(s.hold.DropExporter(ip))
			// The touch is the datagram time after the replay.
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

// Exporter mutex before s.mu, matching Accept. The set entry may already be gone.
func (s *Session) dropRecorded(ip netip.Addr) {
	ip = ip.Unmap()
	mu := s.mutexFor(ip)
	mu.Lock()
	defer mu.Unlock()
	s.mu.Lock()
	_, ok := s.evict[ip]
	if ok {
		delete(s.evict, ip)
	}
	s.mu.Unlock()
	if !ok {
		return
	}
	s.dropIP(ip)
}

// A datagram can refresh the touch while an earlier IP is dropped.
func (s *Session) dropIfIdle(ip netip.Addr, now time.Time, idle time.Duration) bool {
	ip = ip.Unmap()
	mu := s.mutexFor(ip)
	mu.Lock()
	defer mu.Unlock()
	still := false
	for _, cand := range s.templates.IdleExporters(now, idle) {
		if cand.Unmap() == ip {
			still = true
			break
		}
	}
	if !still {
		return false
	}
	s.dropIP(ip)
	return true
}

// Caller holds the exporter mutex. The snapshot was rechecked under that lock.
func (s *Session) dropIP(ip netip.Addr) {
	s.templates.DropExporter(ip)
	s.noteHoldDrop(s.hold.DropExporter(ip))
	s.samples.DropExporter(ip)
	s.seq.DropExporter(ip)
	forgetExporter(ip)
}

func (s *Session) noteHoldDrop(n int) {
	if n > 0 {
		_ = s.counters.Add(obs.DroppedTemplate, uint64(n))
	}
}

func (s *Session) drain(ip netip.Addr, at time.Time) ([]flow.Flow, []flow.ExporterDelta) {
	entries := s.hold.List(ip)
	var out []flow.Flow
	var gaps []flow.ExporterDelta
	for _, p := range entries {
		payload, stripped := replayPayload(p.Payload, p.RetryAt)
		rd := ingest.Datagram{Payload: payload, Src: p.Exporter, ReceivedAt: p.ReceivedAt}
		if p.Version == 10 {
			armIPFIXRetry(p.Exporter, p.ID, p.SeqSnap)
		}
		flows, delta, missing, _ := Dispatch(rd, s.templates, s.samples, s.seq, s.counters, true, s.maxAge, s.skew)
		if p.Version == 10 {
			clearIPFIXRetry(p.Exporter)
		}
		if delta.GapRecords > 0 {
			ver := p.Version
			if ver == 0 {
				ver = delta.Version
			}
			// The writer keys exporter columns by this hold's domain, which
			// can differ from the packet Accept is returning.
			gaps = append(gaps, flow.ExporterDelta{
				Exporter:   p.Exporter,
				Domain:     p.Domain,
				Version:    ver,
				LastSeen:   p.ReceivedAt,
				GapRecords: delta.GapRecords,
			})
		}
		// A retry that evicted this exporter already dropped the queue.
		// The snapshot must not decode the copies that drop removed.
		if s.applyEvictions(ip, at) {
			out = append(out, flows...)
			return out, gaps
		}
		out = append(out, flows...)
		if missing == nil {
			s.hold.Remove(ip, p.ID)
			dropIPFIXHold(p.ID)
			continue
		}
		next := missing.RetryAt
		hdr := packetHeaderLen(p.Payload)
		if stripped && missing.RetryAt > hdr {
			next = p.RetryAt + (missing.RetryAt - hdr)
		} else if stripped {
			next = p.RetryAt
		}
		if next != p.RetryAt {
			// The sequence is still unresolved. Keep the snapshot.
			s.hold.Advance(ip, p.ID, next)
		}
	}
	return out, gaps
}

// foldRetryGaps adds same-domain GapRecords to delta. A different domain is
// returned on its own so the two are not stored on one exporter row.
// Packets, Malformed, and MissingTemplate on the retry delta are not copied.
func foldRetryGaps(delta flow.ExporterDelta, gaps []flow.ExporterDelta) (flow.ExporterDelta, []flow.ExporterDelta) {
	var extra []flow.ExporterDelta
	for _, g := range gaps {
		if g.GapRecords == 0 {
			continue
		}
		if g.Domain == delta.Domain {
			delta.GapRecords += g.GapRecords
			continue
		}
		found := false
		for i := range extra {
			if extra[i].Domain == g.Domain {
				extra[i].GapRecords += g.GapRecords
				found = true
				break
			}
		}
		if !found {
			extra = append(extra, g)
		}
	}
	return delta, extra
}

func holdIDs(entries []template.Pending) []uint64 {
	if len(entries) == 0 {
		return nil
	}
	ids := make([]uint64, len(entries))
	for i, e := range entries {
		ids[i] = e.ID
	}
	return ids
}

func packetHeaderLen(payload []byte) int {
	if len(payload) >= 2 && binary.BigEndian.Uint16(payload[:2]) == 10 {
		return 16
	}
	return 20
}

// replayPayload keeps the version header and the bytes from retryAt.
// IPFIX length counts octets, so a shortened replay rewrites that field.
// The suffix stops at the original message length: octets past it were
// not sets. The new length is the header plus that capped suffix.
// A v9 header stays 20 bytes and is not rewritten.
func replayPayload(original []byte, retryAt int) ([]byte, bool) {
	hdr := packetHeaderLen(original)
	if retryAt <= hdr || retryAt > len(original) || len(original) < hdr {
		return original, false
	}
	end := len(original)
	if hdr == 16 && len(original) >= 4 {
		msgLen := int(binary.BigEndian.Uint16(original[2:4]))
		if msgLen < end {
			end = msgLen
		}
	}
	if end < retryAt {
		end = retryAt
	}
	n := hdr + (end - retryAt)
	out := make([]byte, n)
	copy(out[:hdr], original[:hdr])
	copy(out[hdr:], original[retryAt:end])
	if hdr == 16 && n >= 4 && n <= 65535 {
		binary.BigEndian.PutUint16(out[2:4], uint16(n))
	}
	return out, true
}

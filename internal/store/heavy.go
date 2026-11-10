package store

import (
	"context"
	"database/sql"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"vibecollector/internal/flow"
)

const (
	talkerWorking = 8000
	talkerKeep    = 1000
	repWorking    = 2000
	repKeep       = 1000
	pathWorking   = 4000
	pathKeep      = 2000
	asnKeep       = 50000

	otherAddr     = "*"
	otherCategory = "*"

	minuteSpan = int64(time.Minute / time.Millisecond)
	fiveSpan   = int64(5 * time.Minute / time.Millisecond)
)

// heavyState is the open heavy-hitter window. Talkers and reputation keep the
// open minute and the previous minute. Geo paths keep the open 5-minute bucket
// and the previous one. Older buckets are loaded, replaced, and dropped.
type heavyState struct {
	minuteOpen int64
	minuteSet  bool
	fiveOpen   int64
	fiveSet    bool

	talkers map[bucketDir]*talkerBucket
	reps    map[bucketDir]*repBucket
	paths   map[int64]*pathBucket

	asnReplace map[int64]*asnBucket
}

type bucketDir struct {
	bucket int64
	dir    string
}

type talkerBucket struct {
	addrs  map[string]counts
	other  counts
	dirty  bool
	copied bool
}

type repKey struct {
	addr string
	cat  string
}

type repBucket struct {
	rows   map[repKey]counts
	other  counts
	dirty  bool
	copied bool
}

type pathKey struct {
	src string
	dst string
}

type place struct {
	key                   string
	kind                  string
	country, region, city string
	lat, lon              float64
	hasCoord              bool
}

type placeInfo struct {
	kind                  string
	country, region, city string
	lat, lon              float64
	hasCoord              bool
	seen                  bool
	touch                 time.Time
}

type pathBucket struct {
	pairs        map[pathKey]counts
	places       map[string]placeInfo
	otherOctets  uint64
	otherFlows   uint64
	pairsOmitted uint64
	dirty        bool
	copied       bool
}

type asnRow struct {
	asn        int64
	direction  string
	fromExport int
}

type asnBucket struct {
	rows        map[asnRow]counts
	other       counts
	hadSentinel bool
}

func (h heavyState) clone() *heavyState {
	n := &heavyState{
		minuteOpen: h.minuteOpen,
		minuteSet:  h.minuteSet,
		fiveOpen:   h.fiveOpen,
		fiveSet:    h.fiveSet,
		talkers:    make(map[bucketDir]*talkerBucket, len(h.talkers)),
		reps:       make(map[bucketDir]*repBucket, len(h.reps)),
		paths:      make(map[int64]*pathBucket, len(h.paths)),
	}
	for k, v := range h.talkers {
		n.talkers[k] = v
	}
	for k, v := range h.reps {
		n.reps[k] = v
	}
	for k, v := range h.paths {
		n.paths[k] = v
	}
	return n
}

func (h *heavyState) retain() heavyState {
	if h.minuteSet {
		prev := h.minuteOpen - minuteSpan
		for k, b := range h.talkers {
			if k.bucket != h.minuteOpen && k.bucket != prev {
				delete(h.talkers, k)
				continue
			}
			// Next batch must copy before write so a rolled-back commit
			// cannot mutate the committed window.
			b.dirty = false
			b.copied = false
		}
		for k, b := range h.reps {
			if k.bucket != h.minuteOpen && k.bucket != prev {
				delete(h.reps, k)
				continue
			}
			b.dirty = false
			b.copied = false
		}
	}
	if h.fiveSet {
		prev := h.fiveOpen - fiveSpan
		for k, b := range h.paths {
			if k != h.fiveOpen && k != prev {
				delete(h.paths, k)
				continue
			}
			b.dirty = false
			b.copied = false
		}
	}
	h.asnReplace = nil
	return *h
}

func (h *heavyState) prepare(ctx context.Context, conn *sql.Conn, flows []flow.Flow, asn map[asnKey]counts) (*heavyState, map[int64]struct{}, error) {
	next := h.clone()
	for i := range flows {
		if err := next.addFlow(ctx, conn, &flows[i]); err != nil {
			return nil, nil, err
		}
	}
	skip, err := next.planASN(ctx, conn, asn)
	if err != nil {
		return nil, nil, err
	}
	return next, skip, nil
}

func (h *heavyState) addFlow(ctx context.Context, conn *sql.Conn, f *flow.Flow) error {
	if !rollupEligible(f) {
		return nil
	}
	mb := minuteBucket(f.Start)
	fb := fiveBucket(f.Start)
	h.advanceMinute(mb)
	h.advanceFive(fb)
	if err := h.addTalker(ctx, conn, mb, "src", f.Src.String(), f.Packets, f.Octets); err != nil {
		return err
	}
	if err := h.addTalker(ctx, conn, mb, "dst", f.Dst.String(), f.Packets, f.Octets); err != nil {
		return err
	}
	if f.SrcEnrich.Rep.Kind == flow.OutcomeValue {
		if err := h.addRep(ctx, conn, mb, "src", f.Src.String(), f.SrcEnrich.Rep.Category, f.Packets, f.Octets); err != nil {
			return err
		}
	}
	if f.DstEnrich.Rep.Kind == flow.OutcomeValue {
		if err := h.addRep(ctx, conn, mb, "dst", f.Dst.String(), f.DstEnrich.Rep.Category, f.Packets, f.Octets); err != nil {
			return err
		}
	}
	return h.addPath(ctx, conn, fb, f)
}

func (h *heavyState) advanceMinute(bucket int64) {
	if !h.minuteSet || bucket > h.minuteOpen {
		h.minuteOpen = bucket
		h.minuteSet = true
	}
}

func (h *heavyState) advanceFive(bucket int64) {
	if !h.fiveSet || bucket > h.fiveOpen {
		h.fiveOpen = bucket
		h.fiveSet = true
	}
}

func (h *heavyState) addTalker(ctx context.Context, conn *sql.Conn, bucket int64, dir, addr string, packets, octets uint64) error {
	if addr == otherAddr {
		return nil
	}
	b, err := h.talkerBucket(ctx, conn, bucket, dir)
	if err != nil {
		return err
	}
	c, ok := b.addrs[addr]
	if !ok && len(b.addrs) >= talkerWorking {
		b.prune(talkerKeep)
	}
	c.add(packets, octets)
	b.addrs[addr] = c
	b.dirty = true
	return nil
}

func (h *heavyState) talkerBucket(ctx context.Context, conn *sql.Conn, bucket int64, dir string) (*talkerBucket, error) {
	k := bucketDir{bucket: bucket, dir: dir}
	if b, ok := h.talkers[k]; ok {
		if b.copied {
			return b, nil
		}
		nb := b.clone()
		h.talkers[k] = nb
		return nb, nil
	}
	// Absent from memory: load the committed rows. An empty map would delete
	// them on replace, including after a restart. This does not read raw flows.
	b, err := loadTalker(ctx, conn, bucket, dir)
	if err != nil {
		return nil, err
	}
	h.talkers[k] = b
	return b, nil
}

func (b *talkerBucket) clone() *talkerBucket {
	n := &talkerBucket{other: b.other, dirty: b.dirty, copied: true, addrs: make(map[string]counts, len(b.addrs))}
	for k, v := range b.addrs {
		n.addrs[k] = v
	}
	return n
}

func (b *talkerBucket) prune(keep int) {
	if len(b.addrs) <= keep {
		return
	}
	type kv struct {
		addr string
		c    counts
	}
	order := make([]kv, 0, len(b.addrs))
	for addr, c := range b.addrs {
		order = append(order, kv{addr, c})
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].c.octets != order[j].c.octets {
			return order[i].c.octets > order[j].c.octets
		}
		return order[i].addr < order[j].addr
	})
	for _, item := range order[keep:] {
		b.other.packets += item.c.packets
		b.other.octets += item.c.octets
		b.other.flows += item.c.flows
		delete(b.addrs, item.addr)
	}
}

func (h *heavyState) addRep(ctx context.Context, conn *sql.Conn, bucket int64, dir, addr, cat string, packets, octets uint64) error {
	if addr == otherAddr {
		return nil
	}
	b, err := h.repBucket(ctx, conn, bucket, dir)
	if err != nil {
		return err
	}
	k := repKey{addr: addr, cat: cat}
	c, ok := b.rows[k]
	if !ok && len(b.rows) >= repWorking {
		b.prune(repKeep)
	}
	c.add(packets, octets)
	b.rows[k] = c
	b.dirty = true
	return nil
}

func (h *heavyState) repBucket(ctx context.Context, conn *sql.Conn, bucket int64, dir string) (*repBucket, error) {
	k := bucketDir{bucket: bucket, dir: dir}
	if b, ok := h.reps[k]; ok {
		if b.copied {
			return b, nil
		}
		nb := b.clone()
		h.reps[k] = nb
		return nb, nil
	}
	b, err := loadRep(ctx, conn, bucket, dir)
	if err != nil {
		return nil, err
	}
	h.reps[k] = b
	return b, nil
}

func (b *repBucket) clone() *repBucket {
	n := &repBucket{other: b.other, dirty: b.dirty, copied: true, rows: make(map[repKey]counts, len(b.rows))}
	for k, v := range b.rows {
		n.rows[k] = v
	}
	return n
}

func (b *repBucket) prune(keep int) {
	if len(b.rows) <= keep {
		return
	}
	type kv struct {
		k repKey
		c counts
	}
	order := make([]kv, 0, len(b.rows))
	for k, c := range b.rows {
		order = append(order, kv{k, c})
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].c.octets != order[j].c.octets {
			return order[i].c.octets > order[j].c.octets
		}
		if order[i].k.addr != order[j].k.addr {
			return order[i].k.addr < order[j].k.addr
		}
		return order[i].k.cat < order[j].k.cat
	})
	for _, item := range order[keep:] {
		b.other.packets += item.c.packets
		b.other.octets += item.c.octets
		b.other.flows += item.c.flows
		delete(b.rows, item.k)
	}
}

func (h *heavyState) addPath(ctx context.Context, conn *sql.Conn, bucket int64, f *flow.Flow) error {
	src, srcOK := placeOf(f.SrcEnrich)
	dst, dstOK := placeOf(f.DstEnrich)
	if !srcOK || !dstOK {
		return nil
	}
	b, err := h.pathBucket(ctx, conn, bucket)
	if err != nil {
		return err
	}
	k := pathKey{src: src.key, dst: dst.key}
	c, ok := b.pairs[k]
	if !ok && len(b.pairs) >= pathWorking {
		b.prune(pathKeep)
	}
	c.add(f.Packets, f.Octets)
	b.pairs[k] = c
	b.observe(src, f.Start)
	b.observe(dst, f.Start)
	b.dirty = true
	return nil
}

func (h *heavyState) pathBucket(ctx context.Context, conn *sql.Conn, bucket int64) (*pathBucket, error) {
	if b, ok := h.paths[bucket]; ok {
		if b.copied {
			return b, nil
		}
		nb := b.clone()
		h.paths[bucket] = nb
		return nb, nil
	}
	b, err := loadPath(ctx, conn, bucket)
	if err != nil {
		return nil, err
	}
	h.paths[bucket] = b
	return b, nil
}

func (b *pathBucket) clone() *pathBucket {
	n := &pathBucket{
		otherOctets:  b.otherOctets,
		otherFlows:   b.otherFlows,
		pairsOmitted: b.pairsOmitted,
		dirty:        b.dirty,
		copied:       true,
		pairs:        make(map[pathKey]counts, len(b.pairs)),
		places:       make(map[string]placeInfo, len(b.places)),
	}
	for k, v := range b.pairs {
		n.pairs[k] = v
	}
	for k, v := range b.places {
		v.seen = false
		v.touch = time.Time{}
		n.places[k] = v
	}
	return n
}

func (b *pathBucket) observe(p place, at time.Time) {
	info := b.places[p.key]
	info.kind = p.kind
	info.country = p.country
	info.region = p.region
	info.city = p.city
	if !info.seen || !at.Before(info.touch) {
		info.hasCoord = p.hasCoord
		info.lat = p.lat
		info.lon = p.lon
		info.touch = at
		info.seen = true
	}
	b.places[p.key] = info
}

func (b *pathBucket) prune(keep int) {
	if len(b.pairs) <= keep {
		return
	}
	type kv struct {
		k pathKey
		c counts
	}
	order := make([]kv, 0, len(b.pairs))
	for k, c := range b.pairs {
		order = append(order, kv{k, c})
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].c.octets != order[j].c.octets {
			return order[i].c.octets > order[j].c.octets
		}
		if order[i].k.src != order[j].k.src {
			return order[i].k.src < order[j].k.src
		}
		return order[i].k.dst < order[j].k.dst
	})
	for _, item := range order[keep:] {
		b.otherOctets += item.c.octets
		b.otherFlows += item.c.flows
		b.pairsOmitted++
		delete(b.pairs, item.k)
	}
}

func placeOf(ep flow.Endpoint) (place, bool) {
	if ep.Scope != "global" || ep.Geo.Kind != flow.OutcomeValue {
		return place{}, false
	}
	g := ep.Geo
	lat, lon := round1(g.Lat), round1(g.Lon)
	switch {
	case g.HasLatLon && g.City != "" && g.Region != "":
		return place{
			key: "city:" + g.Country + ":" + g.Region + ":" + g.City, kind: "city",
			country: g.Country, region: g.Region, city: g.City, lat: lat, lon: lon, hasCoord: true,
		}, true
	case g.HasLatLon && g.City != "":
		return place{
			key: "city:" + g.Country + ":-:" + g.City, kind: "city",
			country: g.Country, city: g.City, lat: lat, lon: lon, hasCoord: true,
		}, true
	case g.HasLatLon:
		return place{
			key: "coord:" + g.Country + ":" + format1(lat) + ":" + format1(lon), kind: "coord",
			country: g.Country, lat: lat, lon: lon, hasCoord: true,
		}, true
	case g.Country != "":
		return place{key: "cc:" + g.Country, kind: "country", country: g.Country}, true
	default:
		return place{}, false
	}
}

func round1(v float64) float64 {
	r := math.Round(v*10) / 10
	if r == 0 {
		return 0
	}
	return r
}

func format1(v float64) string {
	return strconv.FormatFloat(v, 'f', 1, 64)
}

func (h *heavyState) planASN(ctx context.Context, conn *sql.Conn, partial map[asnKey]counts) (map[int64]struct{}, error) {
	if len(partial) == 0 {
		return nil, nil
	}
	byMin := make(map[int64][]asnKey)
	for k := range partial {
		byMin[k.bucket] = append(byMin[k.bucket], k)
	}
	skip := make(map[int64]struct{})
	h.asnReplace = make(map[int64]*asnBucket)
	for minute, keys := range byMin {
		batchASNs := make(map[int64]struct{}, len(keys))
		for _, k := range keys {
			batchASNs[k.asn] = struct{}{}
		}
		var existing, sentinels int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(DISTINCT asn) FROM asn_1m WHERE bucket_ms = ? AND asn != -1`, minute).Scan(&existing); err != nil {
			return nil, err
		}
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM asn_1m WHERE bucket_ms = ? AND asn = -1`, minute).Scan(&sentinels); err != nil {
			return nil, err
		}
		// len(batchASNs) counts every number in the batch as new, so
		// existing+len is only an upper bound on the union. Below the valve
		// that bound is already decisive. At or above it, count the batch
		// numbers this minute does not store. Overlap must not load a snapshot
		// the post-merge check throws away.
		union := existing + len(batchASNs)
		if sentinels == 0 && existing > 0 && union >= asnKeep {
			absent, err := absentASNCount(ctx, conn, minute, batchASNs)
			if err != nil {
				return nil, err
			}
			union = existing + absent
		}
		if sentinels == 0 && union < asnKeep {
			continue
		}
		b, err := loadASN(ctx, conn, minute)
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			rk := asnRow{asn: k.asn, direction: k.direction, fromExport: k.fromExport}
			c := b.rows[rk]
			p := partial[k]
			c.packets += p.packets
			c.octets += p.octets
			c.flows += p.flows
			b.rows[rk] = c
		}
		if b.distinct() >= asnKeep {
			b.prune()
		}
		if b.distinct() < asnKeep && !b.hadSentinel {
			continue
		}
		h.asnReplace[minute] = b
		skip[minute] = struct{}{}
	}
	return skip, nil
}

// absentASNCount is how many ASN numbers in batch are not already stored for minute.
// Chunks are disjoint, so summing COUNT(DISTINCT) is the size of the intersection.
func absentASNCount(ctx context.Context, conn *sql.Conn, minute int64, batch map[int64]struct{}) (int, error) {
	if len(batch) == 0 {
		return 0, nil
	}
	asns := make([]int64, 0, len(batch))
	for asn := range batch {
		asns = append(asns, asn)
	}
	// Stay far under SQLite's bound-variable limit. A cold minute can name
	// every kept ASN in one batch.
	const chunk = 500
	var present int
	for i := 0; i < len(asns); i += chunk {
		j := i + chunk
		if j > len(asns) {
			j = len(asns)
		}
		n, err := countStoredASN(ctx, conn, minute, asns[i:j])
		if err != nil {
			return 0, err
		}
		present += n
	}
	return len(asns) - present, nil
}

func countStoredASN(ctx context.Context, conn *sql.Conn, minute int64, asns []int64) (int, error) {
	var q strings.Builder
	q.WriteString(`SELECT COUNT(DISTINCT asn) FROM asn_1m WHERE bucket_ms = ? AND asn != -1 AND asn IN (?`)
	args := make([]any, 1, len(asns)+1)
	args[0] = minute
	args = append(args, asns[0])
	for _, asn := range asns[1:] {
		q.WriteString(",?")
		args = append(args, asn)
	}
	q.WriteByte(')')
	var n int
	err := conn.QueryRowContext(ctx, q.String(), args...).Scan(&n)
	return n, err
}

func (b *asnBucket) distinct() int {
	seen := make(map[int64]struct{}, len(b.rows))
	for k := range b.rows {
		seen[k.asn] = struct{}{}
	}
	return len(seen)
}

func (b *asnBucket) prune() {
	totals := make(map[int64]uint64, len(b.rows))
	for k, c := range b.rows {
		totals[k.asn] += c.octets
	}
	if len(totals) < asnKeep {
		return
	}
	type rank struct {
		asn    int64
		octets uint64
	}
	order := make([]rank, 0, len(totals))
	for asn, octets := range totals {
		order = append(order, rank{asn, octets})
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].octets != order[j].octets {
			return order[i].octets > order[j].octets
		}
		return order[i].asn < order[j].asn
	})
	drop := make(map[int64]struct{}, len(order)-asnKeep)
	for _, r := range order[asnKeep:] {
		drop[r.asn] = struct{}{}
	}
	for k, c := range b.rows {
		if _, ok := drop[k.asn]; !ok {
			continue
		}
		b.other.packets += c.packets
		b.other.octets += c.octets
		b.other.flows += c.flows
		delete(b.rows, k)
	}
	b.hadSentinel = true
}

func (h *heavyState) flush(ctx context.Context, conn *sql.Conn) error {
	if err := h.flushTalkers(ctx, conn); err != nil {
		return err
	}
	if err := h.flushReps(ctx, conn); err != nil {
		return err
	}
	if err := h.flushPaths(ctx, conn); err != nil {
		return err
	}
	return h.flushASN(ctx, conn)
}

func (h *heavyState) flushTalkers(ctx context.Context, conn *sql.Conn) error {
	for k, b := range h.talkers {
		if b == nil || !b.dirty {
			continue
		}
		b.prune(talkerKeep)
		if err := writeTalker(ctx, conn, k, b); err != nil {
			return err
		}
	}
	return nil
}

func (h *heavyState) flushReps(ctx context.Context, conn *sql.Conn) error {
	for k, b := range h.reps {
		if b == nil || !b.dirty {
			continue
		}
		b.prune(repKeep)
		if err := writeRep(ctx, conn, k, b); err != nil {
			return err
		}
	}
	return nil
}

func (h *heavyState) flushPaths(ctx context.Context, conn *sql.Conn) error {
	for bucket, b := range h.paths {
		if b == nil || !b.dirty {
			continue
		}
		b.prune(pathKeep)
		if err := writePath(ctx, conn, bucket, b); err != nil {
			return err
		}
	}
	return nil
}

func (h *heavyState) flushASN(ctx context.Context, conn *sql.Conn) error {
	for minute, b := range h.asnReplace {
		if err := writeASN(ctx, conn, minute, b); err != nil {
			return err
		}
	}
	return nil
}

func loadTalker(ctx context.Context, conn *sql.Conn, bucket int64, dir string) (*talkerBucket, error) {
	rows, err := conn.QueryContext(ctx, `SELECT addr, packets, octets, flows FROM talker_1m WHERE bucket_ms = ? AND direction = ?`, bucket, dir)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	b := &talkerBucket{addrs: make(map[string]counts), copied: true}
	for rows.Next() {
		var addr string
		var packets, octets, flows int64
		if err := rows.Scan(&addr, &packets, &octets, &flows); err != nil {
			return nil, err
		}
		c := counts{packets: uint64(packets), octets: uint64(octets), flows: uint64(flows)}
		if addr == otherAddr {
			b.other.packets += c.packets
			b.other.octets += c.octets
			b.other.flows += c.flows
			continue
		}
		prev := b.addrs[addr]
		prev.packets += c.packets
		prev.octets += c.octets
		prev.flows += c.flows
		b.addrs[addr] = prev
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return b, nil
}

func loadRep(ctx context.Context, conn *sql.Conn, bucket int64, dir string) (*repBucket, error) {
	rows, err := conn.QueryContext(ctx, `SELECT addr, category, packets, octets, flows FROM rep_1m WHERE bucket_ms = ? AND direction = ?`, bucket, dir)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	b := &repBucket{rows: make(map[repKey]counts), copied: true}
	for rows.Next() {
		var addr, cat string
		var packets, octets, flows int64
		if err := rows.Scan(&addr, &cat, &packets, &octets, &flows); err != nil {
			return nil, err
		}
		c := counts{packets: uint64(packets), octets: uint64(octets), flows: uint64(flows)}
		if addr == otherAddr && cat == otherCategory {
			b.other.packets += c.packets
			b.other.octets += c.octets
			b.other.flows += c.flows
			continue
		}
		k := repKey{addr: addr, cat: cat}
		prev := b.rows[k]
		prev.packets += c.packets
		prev.octets += c.octets
		prev.flows += c.flows
		b.rows[k] = prev
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return b, nil
}

func loadPath(ctx context.Context, conn *sql.Conn, bucket int64) (*pathBucket, error) {
	b := &pathBucket{pairs: make(map[pathKey]counts), places: make(map[string]placeInfo), copied: true}
	var otherOctets, otherFlows, pairsOmitted int64
	err := conn.QueryRowContext(ctx, `SELECT octets, flows, pairs_omitted FROM geo_path_other_5m WHERE bucket_ms = ?`, bucket).Scan(&otherOctets, &otherFlows, &pairsOmitted)
	if err == sql.ErrNoRows {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	b.otherOctets = uint64(otherOctets)
	b.otherFlows = uint64(otherFlows)
	b.pairsOmitted = uint64(pairsOmitted)
	rows, err := conn.QueryContext(ctx, `SELECT src_key, dst_key, src_kind, dst_kind,
		src_country, dst_country, src_region, dst_region, src_city, dst_city,
		src_lat, src_lon, dst_lat, dst_lon, packets, octets, flows
		FROM geo_path_5m WHERE bucket_ms = ?`, bucket)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var srcKey, dstKey, srcKind, dstKind string
		var srcCountry, dstCountry, srcRegion, dstRegion, srcCity, dstCity sql.NullString
		var srcLat, srcLon, dstLat, dstLon sql.NullFloat64
		var packets, octets, flows int64
		if err := rows.Scan(&srcKey, &dstKey, &srcKind, &dstKind,
			&srcCountry, &dstCountry, &srcRegion, &dstRegion, &srcCity, &dstCity,
			&srcLat, &srcLon, &dstLat, &dstLon, &packets, &octets, &flows); err != nil {
			return nil, err
		}
		b.places[srcKey] = loadedPlace(srcKind, srcCountry, srcRegion, srcCity, srcLat, srcLon)
		b.places[dstKey] = loadedPlace(dstKind, dstCountry, dstRegion, dstCity, dstLat, dstLon)
		k := pathKey{src: srcKey, dst: dstKey}
		c := b.pairs[k]
		c.packets += uint64(packets)
		c.octets += uint64(octets)
		c.flows += uint64(flows)
		b.pairs[k] = c
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return b, nil
}

func loadedPlace(kind string, country, region, city sql.NullString, lat, lon sql.NullFloat64) placeInfo {
	p := placeInfo{kind: kind, country: country.String, region: region.String, city: city.String}
	if lat.Valid && lon.Valid {
		p.hasCoord = true
		p.lat = lat.Float64
		p.lon = lon.Float64
	}
	return p
}

func loadASN(ctx context.Context, conn *sql.Conn, bucket int64) (*asnBucket, error) {
	rows, err := conn.QueryContext(ctx, `SELECT asn, direction, from_export, packets, octets, flows FROM asn_1m WHERE bucket_ms = ?`, bucket)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	b := &asnBucket{rows: make(map[asnRow]counts)}
	for rows.Next() {
		var asn int64
		var dir string
		var fromExport int
		var packets, octets, flows int64
		if err := rows.Scan(&asn, &dir, &fromExport, &packets, &octets, &flows); err != nil {
			return nil, err
		}
		c := counts{packets: uint64(packets), octets: uint64(octets), flows: uint64(flows)}
		if asn == -1 {
			b.other.packets += c.packets
			b.other.octets += c.octets
			b.other.flows += c.flows
			b.hadSentinel = true
			continue
		}
		k := asnRow{asn: asn, direction: dir, fromExport: fromExport}
		prev := b.rows[k]
		prev.packets += c.packets
		prev.octets += c.octets
		prev.flows += c.flows
		b.rows[k] = prev
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return b, nil
}

func writeTalker(ctx context.Context, conn *sql.Conn, k bucketDir, b *talkerBucket) error {
	if _, err := conn.ExecContext(ctx, `DELETE FROM talker_1m WHERE bucket_ms = ? AND direction = ?`, k.bucket, k.dir); err != nil {
		return err
	}
	stmt, err := conn.PrepareContext(ctx, `INSERT INTO talker_1m (bucket_ms, direction, addr, packets, octets, flows) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for addr, c := range b.addrs {
		if addr == otherAddr {
			continue
		}
		if _, err := stmt.ExecContext(ctx, k.bucket, k.dir, addr, fitInt(c.packets), fitInt(c.octets), fitInt(c.flows)); err != nil {
			return err
		}
	}
	_, err = stmt.ExecContext(ctx, k.bucket, k.dir, otherAddr, fitInt(b.other.packets), fitInt(b.other.octets), fitInt(b.other.flows))
	return err
}

func writeRep(ctx context.Context, conn *sql.Conn, k bucketDir, b *repBucket) error {
	if _, err := conn.ExecContext(ctx, `DELETE FROM rep_1m WHERE bucket_ms = ? AND direction = ?`, k.bucket, k.dir); err != nil {
		return err
	}
	stmt, err := conn.PrepareContext(ctx, `INSERT INTO rep_1m (bucket_ms, direction, addr, category, packets, octets, flows) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for key, c := range b.rows {
		if key.addr == otherAddr {
			continue
		}
		if _, err := stmt.ExecContext(ctx, k.bucket, k.dir, key.addr, key.cat, fitInt(c.packets), fitInt(c.octets), fitInt(c.flows)); err != nil {
			return err
		}
	}
	_, err = stmt.ExecContext(ctx, k.bucket, k.dir, otherAddr, otherCategory, fitInt(b.other.packets), fitInt(b.other.octets), fitInt(b.other.flows))
	return err
}

func writePath(ctx context.Context, conn *sql.Conn, bucket int64, b *pathBucket) error {
	if _, err := conn.ExecContext(ctx, `DELETE FROM geo_path_5m WHERE bucket_ms = ?`, bucket); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM geo_path_other_5m WHERE bucket_ms = ?`, bucket); err != nil {
		return err
	}
	stmt, err := conn.PrepareContext(ctx, `INSERT INTO geo_path_5m (
		bucket_ms, src_key, dst_key, src_kind, dst_kind,
		src_country, dst_country, src_region, dst_region, src_city, dst_city,
		src_lat, src_lon, dst_lat, dst_lon, packets, octets, flows
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for k, c := range b.pairs {
		src := b.places[k.src]
		dst := b.places[k.dst]
		sc, sr, sci, slat, slon := bindPlace(src)
		dc, dr, dci, dlat, dlon := bindPlace(dst)
		if _, err := stmt.ExecContext(ctx, bucket, k.src, k.dst, src.kind, dst.kind,
			sc, dc, sr, dr, sci, dci, slat, slon, dlat, dlon,
			fitInt(c.packets), fitInt(c.octets), fitInt(c.flows)); err != nil {
			return err
		}
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO geo_path_other_5m (bucket_ms, octets, flows, pairs_omitted) VALUES (?, ?, ?, ?)`,
		bucket, fitInt(b.otherOctets), fitInt(b.otherFlows), fitInt(b.pairsOmitted))
	return err
}

func bindPlace(p placeInfo) (country, region, city, lat, lon any) {
	country = nullString(p.country)
	region = nullString(p.region)
	city = nullString(p.city)
	if p.hasCoord {
		lat = p.lat
		lon = p.lon
	}
	return
}

func writeASN(ctx context.Context, conn *sql.Conn, bucket int64, b *asnBucket) error {
	if _, err := conn.ExecContext(ctx, `DELETE FROM asn_1m WHERE bucket_ms = ?`, bucket); err != nil {
		return err
	}
	stmt, err := conn.PrepareContext(ctx, `INSERT INTO asn_1m (bucket_ms, asn, direction, from_export, packets, octets, flows) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for k, c := range b.rows {
		if k.asn == -1 {
			continue
		}
		if _, err := stmt.ExecContext(ctx, bucket, k.asn, k.direction, k.fromExport, fitInt(c.packets), fitInt(c.octets), fitInt(c.flows)); err != nil {
			return err
		}
	}
	if !b.hadSentinel {
		return nil
	}
	// One sentinel for the minute. Its octets are only ASNs that were not kept.
	_, err = stmt.ExecContext(ctx, bucket, int64(-1), "src", 0, fitInt(b.other.packets), fitInt(b.other.octets), fitInt(b.other.flows))
	return err
}

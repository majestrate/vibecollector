package store

import (
	"context"
	"database/sql"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"vibecollector/internal/flow"
	"vibecollector/internal/obs"
)

func TestTalkersAcrossBatches(t *testing.T) {
	db, w, _ := openWriter(t, 20000, time.Hour)
	start := time.Date(2024, 6, 1, 12, 0, 30, 0, time.UTC)
	bucket := minuteBucket(start)
	const octets = uint64(10)
	first := talkerFlows(start, 1, 4000, octets)
	out := uint64(500)
	first[0].OutOctets = &out
	flushFlows(t, w, first)

	if sum := talkerSum(t, db, bucket, "src"); sum != 4000*int64(octets) {
		t.Fatalf("src sum after first batch %d", sum)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM talker_1m WHERE bucket_ms = ? AND direction = 'src'`, bucket); n > 1001 {
		t.Fatalf("src rows %d", n)
	}
	assertTalkerSplit(t, db, bucket, "src", int64(octets), 4000*int64(octets))

	second := talkerFlows(start, 4001, 7500, octets)
	extra := eligibleShape(start, start, "192.0.2.9")
	extra.CounterSemantics = "total"
	extra.Octets = 999
	extra.Src = netip.MustParseAddr("203.0.113.99")
	l4 := eligibleShape(start, start, "192.0.2.9")
	l4.OctetSemantics = "l4_payload"
	l4.Octets = 12345
	l4.Src = netip.MustParseAddr("203.0.113.98")
	l4.Dst = netip.MustParseAddr("203.0.113.97")
	flushFlows(t, w, append(second, extra, l4))

	const input = (4000 + 7500) * int64(octets)
	if sum := talkerSum(t, db, bucket, "src"); sum != input {
		t.Fatalf("src sum %d want %d", sum, input)
	}
	if sum := talkerSum(t, db, bucket, "dst"); sum != input {
		t.Fatalf("dst sum %d want %d", sum, input)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM talker_1m WHERE bucket_ms = ? AND direction = 'src'`, bucket); n > 1001 {
		t.Fatalf("src rows %d", n)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM talker_1m WHERE bucket_ms = ?`, bucket); n > 2002 {
		t.Fatalf("minute rows %d", n)
	}
	assertTalkerSplit(t, db, bucket, "src", int64(octets), input)
	if _, o, _ := mustTalker(t, db, bucket, "dst", "203.0.113.50"); o != input {
		t.Fatalf("dst octets %d", o)
	}
	if _, o, _ := mustTalker(t, db, bucket, "dst", otherAddr); o != 0 {
		t.Fatalf("dst other %d includes a stored key", o)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM talker_1m WHERE addr IN ('203.0.113.99', '203.0.113.98')`); n != 0 {
		t.Fatal("ineligible flow entered talkers")
	}
	if got := mustSum(t, db, `SELECT COALESCE(SUM(octets), 0) FROM traffic_1m`); got != input {
		t.Fatalf("traffic %d", got)
	}
}

func TestTalkerReenter(t *testing.T) {
	db, w, _ := openWriter(t, 2000, time.Hour)
	start := time.Date(2024, 6, 2, 8, 0, 0, 0, time.UTC)
	bucket := minuteBucket(start)
	flows := talkerFlows(start, 1, 1000, 10)
	pruned := eligibleShape(start, start, "192.0.2.9")
	pruned.Src = netip.MustParseAddr("198.51.100.8")
	pruned.Dst = netip.MustParseAddr("203.0.113.50")
	pruned.Packets = 1
	pruned.Octets = 1
	flushFlows(t, w, append(flows, pruned))

	if n := mustCount(t, db, `SELECT COUNT(*) FROM talker_1m WHERE bucket_ms = ? AND direction = 'src' AND addr = ?`, bucket, pruned.Src.String()); n != 0 {
		t.Fatal("pruned address stored")
	}
	if _, o, _ := mustTalker(t, db, bucket, "src", otherAddr); o != 1 {
		t.Fatalf("other %d", o)
	}

	back := pruned
	back.Octets = 100
	flushFlows(t, w, []flow.Flow{back})

	if _, o, _ := mustTalker(t, db, bucket, "src", pruned.Src.String()); o != 100 {
		t.Fatalf("reentered octets %d", o)
	}
	if _, o, _ := mustTalker(t, db, bucket, "src", otherAddr); o != 11 {
		t.Fatalf("other %d", o)
	}
	if sum := talkerSum(t, db, bucket, "src"); sum != 1000*10+1+100 {
		t.Fatalf("sum %d", sum)
	}
}

func TestTalkerOlderMinute(t *testing.T) {
	db, w, _ := openWriter(t, 2000, time.Hour)
	t0 := time.Date(2024, 7, 1, 0, 0, 10, 0, time.UTC)
	kept := netip.MustParseAddr("203.0.113.40")
	small := netip.MustParseAddr("203.0.113.41")
	flows := make([]flow.Flow, 0, 1001)
	for i := 0; i < 999; i++ {
		f := eligibleShape(t0, t0, "192.0.2.9")
		f.Src = nthAddr(i + 1)
		f.Dst = netip.MustParseAddr("203.0.113.50")
		f.Packets = 1
		f.Octets = 5
		flows = append(flows, f)
	}
	big := eligibleShape(t0, t0, "192.0.2.9")
	big.Src = kept
	big.Dst = netip.MustParseAddr("203.0.113.50")
	big.Packets = 1
	big.Octets = 50
	smallFlow := big
	smallFlow.Src = small
	smallFlow.Octets = 1
	flows = append(flows, big, smallFlow)
	flushFlows(t, w, flows)

	b0 := minuteBucket(t0)
	if _, o, _ := mustTalker(t, db, b0, "src", otherAddr); o != 1 {
		t.Fatalf("other %d", o)
	}

	t1 := t0.Add(time.Minute)
	next := eligibleShape(t1, t1, "192.0.2.9")
	next.Src = netip.MustParseAddr("203.0.113.70")
	next.Packets = 1
	next.Octets = 4
	flushFlows(t, w, []flow.Flow{next})
	if _, ok := w.heavy.talkers[bucketDir{bucket: b0, dir: "src"}]; !ok {
		t.Fatal("previous minute dropped")
	}

	t3 := t0.Add(3 * time.Minute)
	far := next
	far.Start = t3
	far.Src = netip.MustParseAddr("203.0.113.71")
	far.Octets = 6
	flushFlows(t, w, []flow.Flow{far})
	if _, ok := w.heavy.talkers[bucketDir{bucket: b0, dir: "src"}]; ok {
		t.Fatal("cold minute stayed in memory")
	}

	again := big
	again.Octets = 3
	flushFlows(t, w, []flow.Flow{again})
	if _, ok := w.heavy.talkers[bucketDir{bucket: b0, dir: "src"}]; ok {
		t.Fatal("reloaded minute was retained")
	}
	if _, o, _ := mustTalker(t, db, b0, "src", kept.String()); o != 53 {
		t.Fatalf("kept %d", o)
	}
	if _, o, _ := mustTalker(t, db, b0, "src", otherAddr); o != 1 {
		t.Fatalf("other %d", o)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM talker_1m WHERE bucket_ms = ? AND direction = 'src' AND addr = ?`, b0, small.String()); n != 0 {
		t.Fatal("pruned address came back with the load")
	}
	if sum := talkerSum(t, db, b0, "src"); sum != 50+999*5+1+3 {
		t.Fatalf("sum %d", sum)
	}
	if _, o, _ := mustTalker(t, db, minuteBucket(t3), "src", far.Src.String()); o != 6 {
		t.Fatalf("far minute %d", o)
	}
}

func TestReputationOther(t *testing.T) {
	db, w, _ := openWriter(t, 2000, time.Hour)
	t0 := time.Date(2024, 7, 2, 3, 0, 0, 0, time.UTC)
	kept := netip.MustParseAddr("203.0.113.10")
	small := netip.MustParseAddr("203.0.113.11")
	flows := make([]flow.Flow, 0, 1002)
	for i := 0; i < 999; i++ {
		f := repFlow(t0, nthAddr(i+1), "malware", 5)
		flows = append(flows, f)
	}
	flows = append(flows, repFlow(t0, kept, "malware", 50), repFlow(t0, small, "malware", 1))
	plain := eligibleShape(t0, t0, "192.0.2.9")
	plain.Octets = 99999
	plain.Src = netip.MustParseAddr("203.0.113.12")
	plain.SrcEnrich.Rep.Kind = flow.OutcomeNoData
	flows = append(flows, plain)
	flushFlows(t, w, flows)

	b0 := minuteBucket(t0)
	addr, cat, octets := mustRep(t, db, b0, "src", otherAddr)
	if addr != otherAddr || cat != otherCategory || octets != 1 {
		t.Fatalf("other %s %s %d", addr, cat, octets)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM rep_1m WHERE bucket_ms = ? AND direction = 'src'`, b0); n > 1001 {
		t.Fatalf("rows %d", n)
	}
	if _, c, o := mustRep(t, db, b0, "src", kept.String()); c != "malware" || o != 50 {
		t.Fatalf("kept %s %d", c, o)
	}
	if sum := mustSum(t, db, `SELECT COALESCE(SUM(octets), 0) FROM rep_1m WHERE bucket_ms = ? AND direction = 'src'`, b0); sum != 50+999*5+1 {
		t.Fatalf("sum %d", sum)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM rep_1m WHERE addr = ?`, plain.Src.String()); n != 0 {
		t.Fatal("non-value reputation stored")
	}

	farAt := t0.Add(2 * time.Minute)
	flushFlows(t, w, []flow.Flow{repFlow(farAt, netip.MustParseAddr("203.0.113.13"), "spam", 6)})
	if _, ok := w.heavy.reps[bucketDir{bucket: b0, dir: "src"}]; ok {
		t.Fatal("cold reputation minute stayed in memory")
	}
	again := repFlow(t0, kept, "malware", 4)
	flushFlows(t, w, []flow.Flow{again})
	if _, _, o := mustRep(t, db, b0, "src", kept.String()); o != 54 {
		t.Fatalf("reloaded %d", o)
	}
	if _, c, o := mustRep(t, db, b0, "src", otherAddr); c != otherCategory || o != 1 {
		t.Fatalf("other after load %s %d", c, o)
	}
	if sum := mustSum(t, db, `SELECT COALESCE(SUM(octets), 0) FROM rep_1m WHERE bucket_ms = ? AND direction = 'src'`, b0); sum != 50+999*5+1+4 {
		t.Fatalf("sum %d", sum)
	}
}

func TestGeoNonPlace(t *testing.T) {
	db, w, _ := openWriter(t, 10, time.Hour)
	start := time.Date(2024, 8, 1, 1, 2, 3, 0, time.UTC)
	a := eligibleShape(start, start, "192.0.2.9")
	a.Packets = 2
	a.Octets = 40
	a.SrcEnrich.Scope = "global"
	a.SrcEnrich.Geo = flow.Outcome{Kind: flow.OutcomeValue, Country: "US"}
	a.DstEnrich.Scope = "private"
	a.DstEnrich.Geo = flow.Outcome{Kind: flow.OutcomeValue, Country: "DE", Region: "BE", City: "Berlin", HasLatLon: true, Lat: 52.5, Lon: 13.4}
	b := eligibleShape(start, start, "192.0.2.9")
	b.Packets = 1
	b.Octets = 15
	b.SrcEnrich.Scope = "global"
	b.SrcEnrich.Geo = flow.Outcome{Kind: flow.OutcomeValue}
	b.DstEnrich.Scope = "global"
	b.DstEnrich.Geo = flow.Outcome{Kind: flow.OutcomeValue, Country: "DE"}
	flushFlows(t, w, []flow.Flow{a, b})

	if n := mustCount(t, db, `SELECT COUNT(*) FROM geo_path_5m`); n != 0 {
		t.Fatal(n)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM geo_path_other_5m`); n != 0 {
		t.Fatal(n)
	}
	if got := mustSum(t, db, `SELECT COALESCE(SUM(octets), 0) FROM geo_country_5m WHERE country = 'US'`); got != 40 {
		t.Fatalf("US %d", got)
	}
	if got := mustSum(t, db, `SELECT COALESCE(SUM(octets), 0) FROM geo_country_5m WHERE country = 'DE'`); got != 15 {
		t.Fatalf("DE %d", got)
	}
}

func TestGeoPaths(t *testing.T) {
	db, w, _ := openWriter(t, 20, time.Hour)
	base := time.Date(2024, 8, 2, 4, 1, 0, 0, time.UTC)
	later := base.Add(time.Second)
	cityLater := pathFlow(later, 30, 3, cityEnd("US", "IL", "Springfield", 39.86, -89.66), coordEnd("DE", 50.14, 8.66))
	cityEarlier := pathFlow(base, 5, 1, cityEnd("US", "IL", "Springfield", 39.81, -89.64), coordEnd("DE", 50.14, 8.66))
	paris := pathFlow(base, 8, 1, cityEnd("FR", "", "Paris", 48.86, 2.35), countryEnd("US"))
	cc := pathFlow(base, 20, 2, countryEnd("US"), countryEnd("DE"))
	flushFlows(t, w, []flow.Flow{cityLater, cityEarlier, paris, cc})

	bucket := fiveBucket(base)
	var packets, octets, flows int64
	var srcLat, srcLon, dstLat, dstLon sql.NullFloat64
	var srcRegion, srcCity sql.NullString
	err := db.pool.QueryRow(`SELECT packets, octets, flows, src_lat, src_lon, dst_lat, dst_lon FROM geo_path_5m WHERE bucket_ms = ? AND src_key = ? AND dst_key = ?`,
		bucket, "city:US:IL:Springfield", "coord:DE:50.1:8.7").Scan(&packets, &octets, &flows, &srcLat, &srcLon, &dstLat, &dstLon)
	if err != nil {
		t.Fatal(err)
	}
	if packets != 4 || octets != 35 || flows != 2 || !srcLat.Valid || srcLat.Float64 != round1(39.86) || srcLon.Float64 != round1(-89.66) {
		t.Fatalf("city path %d %d %d lat %v %v", packets, octets, flows, srcLat, srcLon)
	}
	if dstLat.Float64 != round1(50.14) || dstLon.Float64 != round1(8.66) {
		t.Fatalf("coord %v %v", dstLat, dstLon)
	}
	err = db.pool.QueryRow(`SELECT src_region, src_city, src_lat, src_lon FROM geo_path_5m WHERE src_key = ?`, "city:FR:-:Paris").Scan(&srcRegion, &srcCity, &srcLat, &srcLon)
	if err != nil || srcRegion.Valid || srcCity.String != "Paris" || srcLat.Float64 != round1(48.86) || srcLon.Float64 != round1(2.35) {
		t.Fatalf("paris %v %v %v %v %v", err, srcRegion, srcCity, srcLat, srcLon)
	}
	err = db.pool.QueryRow(`SELECT src_lat, src_kind, dst_kind FROM geo_path_5m WHERE src_key = 'cc:US' AND dst_key = 'cc:DE'`).Scan(&srcLat, new(string), new(string))
	if err != nil || srcLat.Valid {
		t.Fatalf("country path lat %v %v", err, srcLat)
	}
	var omitted, other int64
	if err := db.pool.QueryRow(`SELECT pairs_omitted, octets FROM geo_path_other_5m WHERE bucket_ms = ?`, bucket).Scan(&omitted, &other); err != nil || omitted != 0 || other != 0 {
		t.Fatal(err, omitted, other)
	}

	far := pathFlow(base.Add(10*time.Minute), 2, 1, countryEnd("FR"), countryEnd("JP"))
	flushFlows(t, w, []flow.Flow{far})
	if _, ok := w.heavy.paths[bucket]; ok {
		t.Fatal("cold path bucket stayed in memory")
	}
	more := pathFlow(base, 7, 1, countryEnd("US"), countryEnd("DE"))
	flushFlows(t, w, []flow.Flow{more})
	if _, ok := w.heavy.paths[bucket]; ok {
		t.Fatal("reloaded path bucket was retained")
	}
	if got := mustSum(t, db, `SELECT COALESCE(SUM(octets), 0) FROM geo_path_5m WHERE bucket_ms = ? AND src_key = 'cc:US' AND dst_key = 'cc:DE'`, bucket); got != 27 {
		t.Fatalf("reloaded country path %d", got)
	}
	if got := mustSum(t, db, `SELECT COALESCE(SUM(octets), 0) FROM geo_path_5m WHERE bucket_ms = ? AND src_key = ?`, bucket, "city:US:IL:Springfield"); got != 35 {
		t.Fatalf("city path lost on reload %d", got)
	}
	if err := db.pool.QueryRow(`SELECT src_lat FROM geo_path_5m WHERE src_key = ?`, "city:US:IL:Springfield").Scan(&srcLat); err != nil || srcLat.Float64 != round1(39.86) {
		t.Fatalf("coord after reload %v %v", err, srcLat)
	}
}

func TestGeoPathPrune(t *testing.T) {
	db, w, _ := openWriter(t, 3000, time.Hour)
	start := time.Date(2024, 8, 3, 0, 1, 0, 0, time.UTC)
	flows := make([]flow.Flow, 2001)
	for i := range flows {
		flows[i] = pathFlow(start, 1, 1, cityEnd("US", "R", strconv.Itoa(i), 1, 2), countryEnd("DE"))
	}
	skip := eligibleShape(start, start, "192.0.2.9")
	skip.Octets = 99999
	skip.SrcEnrich.Scope = "global"
	skip.SrcEnrich.Geo = flow.Outcome{Kind: flow.OutcomeValue, Country: "US"}
	skip.DstEnrich.Scope = "loopback"
	flushFlows(t, w, append(flows, skip))

	bucket := fiveBucket(start)
	if n := mustCount(t, db, `SELECT COUNT(*) FROM geo_path_5m WHERE bucket_ms = ?`, bucket); n != pathKeep {
		t.Fatalf("paths %d", n)
	}
	var other, omitted int64
	if err := db.pool.QueryRow(`SELECT octets, pairs_omitted FROM geo_path_other_5m WHERE bucket_ms = ?`, bucket).Scan(&other, &omitted); err != nil {
		t.Fatal(err)
	}
	if other != 1 || omitted != 1 {
		t.Fatalf("other %d omitted %d", other, omitted)
	}
	if got := mustSum(t, db, `SELECT COALESCE(SUM(octets), 0) FROM geo_path_5m WHERE bucket_ms = ?`, bucket); got+other != 2001 {
		t.Fatalf("path sum %d other %d", got, other)
	}
}

func TestASNValveNoDoubleCount(t *testing.T) {
	db, w, _ := openWriter(t, 60000, time.Hour)
	start := time.Date(2024, 9, 1, 0, 0, 0, 0, time.UTC)
	const n = 50001
	flows := make([]flow.Flow, n)
	for i := 0; i < n; i++ {
		f := eligibleShape(start, start, "192.0.2.9")
		f.Packets = 1
		f.Octets = uint64(i + 1)
		f.Src = netip.MustParseAddr("203.0.113.10")
		f.SrcEnrich.ASN = flow.Outcome{Kind: flow.OutcomeValue, ASN: uint32(i + 1)}
		flows[i] = f
	}
	flushFlows(t, w, flows)
	bucket := minuteBucket(start)
	var want int64
	for i := int64(1); i <= n; i++ {
		want += i
	}
	assertASNValve(t, db, bucket, want, map[int64]int64{-1: 1, 2: 2, 50001: 50001})
	if mustCount(t, db, `SELECT COUNT(*) FROM asn_1m WHERE bucket_ms = ? AND asn = 1`, bucket) != 0 {
		t.Fatal("discarded ASN stored")
	}

	kept := eligibleShape(start, start, "192.0.2.9")
	kept.Packets = 1
	kept.Octets = 10
	kept.SrcEnrich.ASN = flow.Outcome{Kind: flow.OutcomeValue, ASN: 50001}
	flushFlows(t, w, []flow.Flow{kept})
	want += 10
	assertASNValve(t, db, bucket, want, map[int64]int64{-1: 1, 2: 2, 50001: 50011})

	back := eligibleShape(start, start, "192.0.2.9")
	back.Packets = 1
	back.Octets = 100
	back.SrcEnrich.ASN = flow.Outcome{Kind: flow.OutcomeValue, ASN: 1}
	flushFlows(t, w, []flow.Flow{back})
	want += 100
	assertASNValve(t, db, bucket, want, map[int64]int64{-1: 3, 1: 100, 50001: 50011})
	if mustCount(t, db, `SELECT COUNT(*) FROM asn_1m WHERE bucket_ms = ? AND asn = 2`, bucket) != 0 {
		t.Fatal("evicted ASN still stored")
	}
}

func TestHeavyRollsBackWithBatch(t *testing.T) {
	db, w, counters := openWriter(t, 1, time.Hour)
	if _, err := db.pool.Exec(`CREATE TRIGGER fail_flows BEFORE INSERT ON flows BEGIN SELECT RAISE(ABORT, 'forced'); END`); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2024, 6, 4, 0, 0, 0, 0, time.UTC)
	bad := eligibleShape(at, at, "192.0.2.81")
	bad.Src = netip.MustParseAddr("203.0.113.81")
	bad.Octets = 42
	if err := w.Submit([]flow.Flow{bad}); err != nil {
		t.Fatal(err)
	}
	cancel, errc := runWriter(t, w)
	waitMetric(t, counters, obs.SQLiteWriteFailures, 1)
	if _, err := db.pool.Exec(`DROP TRIGGER fail_flows`); err != nil {
		t.Fatal(err)
	}
	good := eligibleShape(at, at, "192.0.2.82")
	good.Src = netip.MustParseAddr("203.0.113.82")
	good.Octets = 7
	if err := w.Submit([]flow.Flow{good}); err != nil {
		t.Fatal(err)
	}
	waitCount(t, db, `SELECT COUNT(*) FROM flows`, 1)
	bucket := minuteBucket(at)
	if n := mustCount(t, db, `SELECT COUNT(*) FROM talker_1m WHERE addr = ?`, bad.Src.String()); n != 0 {
		t.Fatal("failed batch stayed in talkers")
	}
	if _, o, _ := mustTalker(t, db, bucket, "src", good.Src.String()); o != 7 {
		t.Fatalf("src %d", o)
	}
	if _, o, _ := mustTalker(t, db, bucket, "dst", good.Dst.String()); o != 7 {
		t.Fatalf("dst %d", o)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func talkerFlows(start time.Time, from, n int, octets uint64) []flow.Flow {
	flows := make([]flow.Flow, n)
	dst := netip.MustParseAddr("203.0.113.50")
	for i := 0; i < n; i++ {
		f := eligibleShape(start, start, "192.0.2.9")
		f.Src = nthAddr(from + i)
		f.Dst = dst
		f.Packets = 1
		f.Octets = octets
		flows[i] = f
	}
	return flows
}

func nthAddr(n int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)})
}

func repFlow(start time.Time, src netip.Addr, category string, octets uint64) flow.Flow {
	f := eligibleShape(start, start, "192.0.2.9")
	f.Src = src
	f.Packets = 1
	f.Octets = octets
	f.SrcEnrich.Rep = flow.Outcome{Kind: flow.OutcomeValue, Category: category}
	return f
}

func countryEnd(cc string) flow.Endpoint {
	return flow.Endpoint{Scope: "global", Geo: flow.Outcome{Kind: flow.OutcomeValue, Country: cc}}
}

func cityEnd(cc, region, city string, lat, lon float64) flow.Endpoint {
	return flow.Endpoint{Scope: "global", Geo: flow.Outcome{
		Kind: flow.OutcomeValue, Country: cc, Region: region, City: city, HasLatLon: true, Lat: lat, Lon: lon,
	}}
}

func coordEnd(cc string, lat, lon float64) flow.Endpoint {
	return flow.Endpoint{Scope: "global", Geo: flow.Outcome{
		Kind: flow.OutcomeValue, Country: cc, HasLatLon: true, Lat: lat, Lon: lon,
	}}
}

func pathFlow(start time.Time, octets, packets uint64, src, dst flow.Endpoint) flow.Flow {
	f := eligibleShape(start, start, "192.0.2.9")
	f.Octets = octets
	f.Packets = packets
	f.SrcEnrich = src
	f.DstEnrich = dst
	return f
}

func flushFlows(t *testing.T, w *Writer, flows []flow.Flow) {
	t.Helper()
	if err := w.Submit(flows); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- w.Run(ctx) }()
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func talkerSum(t *testing.T, db *DB, bucket int64, dir string) int64 {
	t.Helper()
	return mustSum(t, db, `SELECT COALESCE(SUM(octets), 0) FROM talker_1m WHERE bucket_ms = ? AND direction = ?`, bucket, dir)
}

func assertTalkerSplit(t *testing.T, db *DB, bucket int64, dir string, each, total int64) {
	t.Helper()
	rows, err := db.pool.Query(`SELECT addr, octets FROM talker_1m WHERE bucket_ms = ? AND direction = ?`, bucket, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var sum, star int64
	var kept int
	for rows.Next() {
		var addr string
		var octets int64
		if err := rows.Scan(&addr, &octets); err != nil {
			t.Fatal(err)
		}
		sum += octets
		if addr == otherAddr {
			star = octets
			continue
		}
		kept++
		if octets != each {
			t.Fatalf("stored %s octets %d", addr, octets)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if sum != total || star != total-int64(kept)*each {
		t.Fatalf("sum %d star %d kept %d", sum, star, kept)
	}
	if kept > talkerKeep {
		t.Fatalf("kept %d", kept)
	}
}

func mustTalker(t *testing.T, db *DB, bucket int64, dir, addr string) (packets, octets, flows int64) {
	t.Helper()
	err := db.pool.QueryRow(`SELECT packets, octets, flows FROM talker_1m WHERE bucket_ms = ? AND direction = ? AND addr = ?`, bucket, dir, addr).Scan(&packets, &octets, &flows)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func mustRep(t *testing.T, db *DB, bucket int64, dir, addr string) (gotAddr, category string, octets int64) {
	t.Helper()
	err := db.pool.QueryRow(`SELECT addr, category, octets FROM rep_1m WHERE bucket_ms = ? AND direction = ? AND addr = ?`, bucket, dir, addr).Scan(&gotAddr, &category, &octets)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func mustSum(t *testing.T, db *DB, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.pool.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func assertASNValve(t *testing.T, db *DB, bucket, want int64, octets map[int64]int64) {
	t.Helper()
	if got := mustSum(t, db, `SELECT COALESCE(SUM(octets), 0) FROM asn_1m WHERE bucket_ms = ?`, bucket); got != want {
		t.Fatalf("asn sum %d want %d", got, want)
	}
	if got := mustSum(t, db, `SELECT COALESCE(SUM(octets), 0) FROM traffic_1m`); got != want {
		t.Fatalf("traffic %d want %d", got, want)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM asn_1m WHERE bucket_ms = ?`, bucket); n != asnKeep+1 {
		t.Fatalf("asn rows %d", n)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM asn_1m WHERE bucket_ms = ? AND asn = -1`, bucket); n != 1 {
		t.Fatalf("sentinel rows %d", n)
	}
	var dir string
	var fromExport int
	if err := db.pool.QueryRow(`SELECT direction, from_export FROM asn_1m WHERE bucket_ms = ? AND asn = -1`, bucket).Scan(&dir, &fromExport); err != nil || dir != "src" || fromExport != 0 {
		t.Fatal(err, dir, fromExport)
	}
	for asn, wantOctets := range octets {
		got := mustSum(t, db, `SELECT COALESCE(SUM(octets), 0) FROM asn_1m WHERE bucket_ms = ? AND asn = ?`, bucket, asn)
		if got != wantOctets {
			t.Fatalf("asn %d octets %d want %d", asn, got, wantOctets)
		}
	}
}

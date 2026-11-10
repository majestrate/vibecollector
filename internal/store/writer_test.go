package store

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vibecollector/internal/config"
	"vibecollector/internal/decode/ipfix"
	"vibecollector/internal/decode/v9"
	"vibecollector/internal/flow"
	"vibecollector/internal/ingest"
	"vibecollector/internal/obs"
	"vibecollector/internal/template"
)

func TestNewWriterRejects(t *testing.T) {
	db, _, counters := openWriter(t, 1, time.Hour)
	if _, err := NewWriter(nil, config.DB{BatchSize: 1}, counters); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
	if _, err := NewWriter(db, config.DB{BatchSize: 1}, nil); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
	if _, err := NewWriter(db, config.DB{BatchSize: 0}, counters); !errors.Is(err, ErrBadConfig) {
		t.Fatal(err)
	}
	if _, err := NewWriter(db, config.DB{BatchSize: -1}, counters); !errors.Is(err, ErrBadConfig) {
		t.Fatal(err)
	}
	w, err := NewWriter(db, config.DB{BatchSize: 1}, counters)
	if err != nil {
		t.Fatal(err)
	}
	if cap(w.flows) != writerQueue || cap(w.deltas) != deltaQueue {
		t.Fatal(cap(w.flows), cap(w.deltas))
	}
	if err := w.Submit(nil); err != nil {
		t.Fatal(err)
	}
	if n := len(flowArgs(&flow.Flow{}, nil)); n != 59 {
		t.Fatalf("flow args %d", n)
	}
}

func TestBadV9HeaderAndTemplateOnly(t *testing.T) {
	db, w, _ := openWriter(t, 100, time.Hour)
	ip := netip.MustParseAddr("192.0.2.9")
	t1 := time.Unix(1_700_000_000, 0).UTC()
	t2 := t1.Add(5 * time.Second)
	t0 := t1.Add(-time.Minute)

	bad := parseV9(t, []byte{0x00}, ip, t1)
	if bad.Version != 0 || bad.Domain != 0 || bad.Malformed != 1 || bad.Packets != 1 || bad.Exporter != ip {
		t.Fatalf("bad header delta %+v", bad)
	}
	w.SubmitDelta(bad)

	templates, err := template.NewCache(8)
	if err != nil {
		t.Fatal(err)
	}
	for i, at := range []time.Time{t1, t2, t0} {
		pkt := v9TemplatePacket(7, uint32(i))
		flows, delta, _, err := v9.Parse(ingest.Datagram{Payload: pkt, Src: ip, ReceivedAt: at}, templates, nil, nil, obs.NewCounters(), false, 2*time.Hour, 5*time.Second)
		if err != nil || len(flows) != 0 || delta.Version != 9 || delta.Domain != 7 || delta.Packets != 1 || delta.Malformed != 0 {
			t.Fatal(err, len(flows), delta)
		}
		w.SubmitDelta(delta)
	}

	cancel, errc := runWriter(t, w)
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}

	var version, domain, packets, malformed int64
	var last int64
	err = db.pool.QueryRow(`SELECT version, domain, packets, malformed, last_seen_ms FROM exporters WHERE exporter = ? AND version = 0`, ip.String()).Scan(&version, &domain, &packets, &malformed, &last)
	if err != nil {
		t.Fatal(err)
	}
	if version != 0 || domain != 0 || packets != 1 || malformed != 1 || last != t1.UnixMilli() {
		t.Fatalf("bad header row v=%d d=%d p=%d m=%d last=%d", version, domain, packets, malformed, last)
	}

	err = db.pool.QueryRow(`SELECT version, domain, packets, malformed, flows, last_seen_ms FROM exporters WHERE exporter = ? AND version = 9`, ip.String()).Scan(&version, &domain, &packets, &malformed, new(int64), &last)
	if err != nil {
		t.Fatal(err)
	}
	if version != 9 || domain != 7 || packets != 3 || malformed != 0 || last != t2.UnixMilli() {
		t.Fatalf("template row v=%d d=%d p=%d m=%d last=%d want last %d", version, domain, packets, malformed, last, t2.UnixMilli())
	}
}

func TestDeltaPendingWhenChannelFull(t *testing.T) {
	db, w, _ := openWriter(t, 100, time.Hour)
	ip := netip.MustParseAddr("192.0.2.20")
	at := time.Unix(1_800_000_000, 0).UTC()
	for len(w.deltas) < cap(w.deltas) {
		w.SubmitDelta(flow.ExporterDelta{Exporter: ip, Domain: 1, Version: 9, LastSeen: at, Packets: 1})
	}
	later := at.Add(time.Minute)
	earlier := at.Add(-time.Hour)
	w.SubmitDelta(flow.ExporterDelta{Exporter: ip, Domain: 1, Version: 9, LastSeen: later, Packets: 10, Malformed: 2})
	w.SubmitDelta(flow.ExporterDelta{Exporter: ip, Domain: 1, Version: 9, LastSeen: earlier, Packets: 5, GapPackets: 3})
	if len(w.pending) != 1 || len(w.deltas) != cap(w.deltas) {
		t.Fatal(len(w.pending), len(w.deltas))
	}
	cancel, errc := runWriter(t, w)
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	var packets, malformed, gaps, last int64
	err := db.pool.QueryRow(`SELECT packets, malformed, gap_packets, last_seen_ms FROM exporters WHERE exporter = ?`, ip.String()).Scan(&packets, &malformed, &gaps, &last)
	if err != nil {
		t.Fatal(err)
	}
	wantPackets := int64(cap(w.deltas)) + 15
	if packets != wantPackets || malformed != 2 || gaps != 3 || last != later.UnixMilli() {
		t.Fatalf("packets %d malformed %d gaps %d last %d", packets, malformed, gaps, last)
	}
}

func TestRollupEligibility(t *testing.T) {
	db, w, _ := openWriter(t, 100, time.Hour)
	start := time.Date(2023, 11, 14, 17, 13, 45, 0, time.FixedZone("EST", -5*3600))
	recv := time.Unix(1_700_000_100, 0).UTC()
	rich := richFlow(start, recv)
	total := eligibleShape(start, recv, "192.0.2.30")
	total.CounterSemantics = "total"
	total.SrcEnrich.Geo = flow.Outcome{Kind: flow.OutcomeValue, Country: "US"}
	total.SrcEnrich.ASN = flow.Outcome{Kind: flow.OutcomeValue, ASN: 1, ASNName: "No"}
	l4 := eligibleShape(start, recv, "192.0.2.31")
	l4.OctetSemantics = "l4_payload"
	l4.Octets = 40
	out := uint64(15)
	l4.OutOctets = &out
	l4.SrcEnrich.Geo = flow.Outcome{Kind: flow.OutcomeValue, Country: "DE"}

	plain := eligibleShape(start, recv, "192.0.2.9")
	plain.Sampled = false
	plain.Packets = 1
	plain.Octets = 3
	plain.Proto = 6
	plain.ProtoPresent = true

	noProto := eligibleShape(start, recv, "192.0.2.32")
	noProto.Packets = 2
	noProto.Octets = 8

	both := eligibleShape(start, recv, "192.0.2.33")
	both.Packets = 4
	both.Octets = 40
	both.SrcEnrich.Geo = flow.Outcome{Kind: flow.OutcomeValue, Country: "US"}
	both.DstEnrich.Geo = flow.Outcome{Kind: flow.OutcomeValue, Country: "DE"}

	same := eligibleShape(start, recv, "192.0.2.34")
	same.Packets = 5
	same.Octets = 11
	same.SrcEnrich.Geo = flow.Outcome{Kind: flow.OutcomeValue, Country: "US"}
	same.DstEnrich.Geo = flow.Outcome{Kind: flow.OutcomeValue, Country: "US"}

	priv := eligibleShape(start, recv, "192.0.2.35")
	priv.SrcEnrich.Scope = "private"
	priv.SrcEnrich.Geo = flow.Outcome{Kind: flow.OutcomeValue, Country: "US"}
	priv.DstEnrich.Geo = flow.Outcome{Kind: flow.OutcomeValue, Country: ""}

	noASN := eligibleShape(start, recv, "192.0.2.36")
	bgp := uint32(15169)
	exportOnly := eligibleShape(start, recv, "192.0.2.37")
	exportOnly.BGPDstAS = &bgp
	exportOnly.DstEnrich.ASN.Kind = flow.OutcomeNotConfigured

	if err := w.Submit([]flow.Flow{rich, total, l4, plain, noProto, both, same, priv, noASN, exportOnly}); err != nil {
		t.Fatal(err)
	}
	cancel, errc := runWriter(t, w)
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}

	wantMin := time.Date(2023, 11, 14, 22, 13, 0, 0, time.UTC).UnixMilli()
	want5 := time.Date(2023, 11, 14, 22, 10, 0, 0, time.UTC).UnixMilli()

	assertTraffic(t, db, "192.0.2.9", 6, 1, wantMin, 10, 1000, 1)
	assertTraffic(t, db, "192.0.2.9", 6, 0, wantMin, 1, 3, 1)
	assertTraffic(t, db, "192.0.2.32", -1, 0, wantMin, 2, 8, 1)
	assertNoTraffic(t, db, "192.0.2.30")
	assertNoTraffic(t, db, "192.0.2.31")
	if got := mustCount(t, db, `SELECT COUNT(*) FROM flows WHERE counter_semantics = 'total' OR octet_semantics = 'l4_payload'`); got != 2 {
		t.Fatal(got)
	}
	var storedOut sql.NullInt64
	if err := db.pool.QueryRow(`SELECT out_octets FROM flows WHERE exporter = '192.0.2.31'`).Scan(&storedOut); err != nil || !storedOut.Valid || storedOut.Int64 != 15 {
		t.Fatal(err, storedOut)
	}
	var richOut sql.NullInt64
	if err := db.pool.QueryRow(`SELECT octets, out_octets FROM flows WHERE exporter = '192.0.2.9' AND sampled = 1`).Scan(new(int64), &richOut); err != nil || richOut.Int64 != 50 {
		t.Fatal(err, richOut)
	}

	// rich US once (10/1000/1), both-ends US once (4/40/1), same country on both ends (10/22/2).
	assertGeo(t, db, "US", want5, 24, 1062, 4)
	assertGeo(t, db, "DE", want5, 4, 40, 1)
	if n := mustCount(t, db, `SELECT COUNT(*) FROM geo_country_5m WHERE country NOT IN ('US', 'DE')`); n != 0 {
		t.Fatal(n)
	}

	var fromExport int
	var asnPackets int64
	err := db.pool.QueryRow(`SELECT from_export, packets FROM asn_1m WHERE asn = 64500 AND direction = 'src'`).Scan(&fromExport, &asnPackets)
	if err != nil || fromExport != 0 || asnPackets != 10 {
		t.Fatal(err, fromExport, asnPackets)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM asn_1m WHERE asn = 64500 AND from_export = 1`); n != 0 {
		t.Fatal("wrote BGP and enriched ASN for the same end")
	}
	// rich dst (packets 10) and exportOnly (packets 9) share this BGP AS.
	err = db.pool.QueryRow(`SELECT from_export, packets FROM asn_1m WHERE asn = 15169 AND direction = 'dst'`).Scan(&fromExport, &asnPackets)
	if err != nil || fromExport != 1 || asnPackets != 19 {
		t.Fatal(err, fromExport, asnPackets)
	}
	var name string
	var updated int64
	if err := db.pool.QueryRow(`SELECT name, updated_ms FROM asn_names WHERE asn = 64500`).Scan(&name, &updated); err != nil || name != "Example" || updated != recv.UnixMilli() {
		t.Fatal(err, name, updated)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM asn_names WHERE name = 'No'`); n != 0 {
		t.Fatal("total flow updated asn_names")
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM asn_1m WHERE direction = 'src' AND asn = 0`); n != 0 {
		t.Fatal("skipped end wrote an ASN")
	}
}

func TestSampleFixtures(t *testing.T) {
	db, w, _ := openWriter(t, 100, time.Hour)
	at := time.Unix(1_700_000_000, 0).UTC()
	cases := []struct {
		name    string
		src     string
		rollups bool
	}{
		{"sample_1_and_231.bin", "192.0.2.41", true},
		{"sample_23_and_231.bin", "192.0.2.42", true},
		{"sample_total_only.bin", "192.0.2.43", false},
		{"sample_l4_231.bin", "192.0.2.44", false},
	}
	var decoded []flow.Flow
	for _, tc := range cases {
		f := decodeFixture(t, tc.name, netip.MustParseAddr(tc.src), at)
		if tc.rollups && (f.CounterSemantics != "delta" || f.OctetSemantics != "ip") {
			t.Fatalf("%s semantics %s %s", tc.name, f.CounterSemantics, f.OctetSemantics)
		}
		if !tc.rollups && f.CounterSemantics == "delta" && f.OctetSemantics == "ip" {
			t.Fatalf("%s should not be eligible", tc.name)
		}
		decoded = append(decoded, f)
	}
	out := uint64(999)
	both := eligibleShape(at, at, "192.0.2.45")
	both.Octets = 40
	both.Packets = 2
	both.OutOctets = &out
	decoded = append(decoded, both)
	if err := w.Submit(decoded); err != nil {
		t.Fatal(err)
	}
	cancel, errc := runWriter(t, w)
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	for i, tc := range cases {
		f := decoded[i]
		if mustCount(t, db, `SELECT COUNT(*) FROM flows WHERE exporter = ?`, tc.src) != 1 {
			t.Fatalf("%s missing from flows", tc.name)
		}
		gotP, gotO, gotF := trafficSum(t, db, tc.src)
		if tc.rollups {
			if gotP != int64(f.Packets) || gotO != int64(f.Octets) || gotF != 1 {
				t.Fatalf("%s traffic %d %d %d want %d %d 1", tc.name, gotP, gotO, gotF, f.Packets, f.Octets)
			}
			if f.OutOctets != nil && gotO != int64(f.Octets) {
				t.Fatal("added out octets")
			}
		} else if gotP != 0 || gotO != 0 || gotF != 0 {
			t.Fatalf("%s rolled up %d %d %d", tc.name, gotP, gotO, gotF)
		}
	}
	gotP, gotO, gotF := trafficSum(t, db, "192.0.2.45")
	if gotP != 2 || gotO != 40 || gotF != 1 {
		t.Fatalf("in+out traffic %d %d %d", gotP, gotO, gotF)
	}
	var stored, storedOut int64
	if err := db.pool.QueryRow(`SELECT octets, out_octets FROM flows WHERE exporter = '192.0.2.45'`).Scan(&stored, &storedOut); err != nil || stored != 40 || storedOut != 999 {
		t.Fatal(err, stored, storedOut)
	}
}

func TestFlowColumnRoundtrip(t *testing.T) {
	db, w, _ := openWriter(t, 100, time.Hour)
	start := time.Date(2023, 11, 14, 17, 13, 45, 0, time.FixedZone("EST", -5*3600))
	recv := time.Unix(1_700_000_100, 0).UTC()
	exp := time.Unix(1_700_000_090, 0).UTC()
	rich := richFlow(start, recv)
	rich.ExportTime = exp
	sparse := flow.Flow{
		ReceivedAt:       recv,
		Start:            start,
		End:              start,
		TimeSource:       flow.TimeSysUpTime,
		Exporter:         netip.MustParseAddr("192.0.2.50"),
		Src:              netip.MustParseAddr("203.0.113.50"),
		Dst:              netip.MustParseAddr("203.0.113.51"),
		CounterSemantics: "total",
		OctetSemantics:   "ip",
	}
	sources := []flow.Flow{rich, sparse}
	for _, tc := range []struct {
		src  flow.TimeSource
		want string
		ip   string
	}{
		{flow.TimeSysUpTime, "sysuptime", "192.0.2.61"},
		{flow.TimeAbsolute, "absolute", "192.0.2.62"},
		{flow.TimeExport, "export", "192.0.2.63"},
		{flow.TimeReceive, "receive", "192.0.2.64"},
	} {
		f := sparse
		f.Exporter = netip.MustParseAddr(tc.ip)
		f.TimeSource = tc.src
		f.CounterSemantics = "total"
		sources = append(sources, f)
	}
	if err := w.Submit(sources); err != nil {
		t.Fatal(err)
	}
	cancel, errc := runWriter(t, w)
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}

	got := flowMap(t, db, "192.0.2.9")
	want := map[string]any{
		"flow_start_ms":      start.UTC().UnixMilli(),
		"flow_end_ms":        start.Add(time.Second).UTC().UnixMilli(),
		"received_ms":        recv.UnixMilli(),
		"export_time_s":      exp.Unix(),
		"time_source":        "absolute",
		"clock_clamped":      int64(1),
		"exporter":           "192.0.2.9",
		"domain":             int64(7),
		"version":            int64(9),
		"src":                "203.0.113.10",
		"dst":                "203.0.113.20",
		"src_port":           int64(51515),
		"dst_port":           int64(443),
		"ip_proto":           int64(6),
		"tcp_flags":          int64(0x12),
		"tos":                int64(0),
		"flow_direction":     int64(1),
		"packets":            int64(10),
		"octets":             int64(1000),
		"counter_semantics":  "delta",
		"octet_semantics":    "ip",
		"out_packets":        int64(4),
		"out_octets":         int64(50),
		"input_if":           int64(7),
		"output_if":          int64(8),
		"nexthop":            "198.51.100.1",
		"bgp_src_as":         int64(64500),
		"bgp_dst_as":         int64(15169),
		"src_mask":           int64(24),
		"dst_mask":           int64(16),
		"sampled":            int64(1),
		"sampling_interval":  int64(100),
		"sampling_algorithm": int64(1),
		"src_scope":          "global",
		"dst_scope":          "private",
		"src_geo_outcome":    "value",
		"dst_geo_outcome":    "skipped",
		"src_asn_outcome":    "value",
		"dst_asn_outcome":    "not_configured",
		"src_rep_outcome":    "value",
		"dst_rep_outcome":    "skipped",
		"src_country":        "US",
		"src_region":         "CA",
		"src_city":           "LA",
		"src_lat":            34.0,
		"src_lon":            -118.2,
		"dst_country":        nil,
		"dst_region":         nil,
		"dst_city":           nil,
		"dst_lat":            nil,
		"dst_lon":            nil,
		"src_asn":            int64(64500),
		"src_asn_name":       "Example",
		"dst_asn":            nil,
		"dst_asn_name":       nil,
		"src_rep_category":   "scan",
		"src_rep_score":      0.5,
		"dst_rep_category":   nil,
		"dst_rep_score":      nil,
	}
	assertFlowMap(t, got, want)

	sparseGot := flowMap(t, db, "192.0.2.50")
	for _, col := range []string{
		"export_time_s", "src_port", "dst_port", "ip_proto", "tcp_flags", "tos", "flow_direction",
		"out_packets", "out_octets", "input_if", "output_if", "nexthop",
		"bgp_src_as", "bgp_dst_as", "src_mask", "dst_mask", "sampling_interval", "sampling_algorithm",
		"src_country", "src_region", "src_city", "src_lat", "src_lon",
		"dst_country", "src_asn", "src_asn_name", "src_rep_category", "src_rep_score",
	} {
		if sparseGot[col] != nil {
			t.Fatalf("sparse %s = %#v", col, sparseGot[col])
		}
	}
	if sparseGot["time_source"] != "sysuptime" || sparseGot["clock_clamped"] != int64(0) || sparseGot["sampled"] != int64(0) {
		t.Fatal(sparseGot["time_source"], sparseGot["clock_clamped"], sparseGot["sampled"])
	}
	for _, tc := range []struct {
		ip, want string
	}{
		{"192.0.2.61", "sysuptime"},
		{"192.0.2.62", "absolute"},
		{"192.0.2.63", "export"},
		{"192.0.2.64", "receive"},
	} {
		if got := flowMap(t, db, tc.ip)["time_source"]; got != tc.want {
			t.Fatalf("%s time_source %#v", tc.ip, got)
		}
	}
}

func TestBatchSizeAndInterval(t *testing.T) {
	t.Run("size", func(t *testing.T) {
		db, w, _ := openWriter(t, 2, time.Hour)
		_, _ = runWriter(t, w)
		f := eligibleShape(time.Unix(1_700_000_000, 0).UTC(), time.Unix(1_700_000_000, 0).UTC(), "192.0.2.70")
		if err := w.Submit([]flow.Flow{f}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
		if n := mustCount(t, db, `SELECT COUNT(*) FROM flows`); n != 0 {
			t.Fatal(n)
		}
		f.Exporter = netip.MustParseAddr("192.0.2.71")
		if err := w.Submit([]flow.Flow{f}); err != nil {
			t.Fatal(err)
		}
		waitCount(t, db, `SELECT COUNT(*) FROM flows`, 2)
	})
	t.Run("interval", func(t *testing.T) {
		db, w, _ := openWriter(t, 1000, 30*time.Millisecond)
		_, _ = runWriter(t, w)
		at := time.Unix(1_700_000_000, 0).UTC()
		w.SubmitDelta(flow.ExporterDelta{Exporter: netip.MustParseAddr("192.0.2.72"), Version: 9, LastSeen: at, Packets: 1})
		if err := w.Submit([]flow.Flow{eligibleShape(at, at, "192.0.2.73")}); err != nil {
			t.Fatal(err)
		}
		waitCount(t, db, `SELECT COUNT(*) FROM flows`, 1)
		waitCount(t, db, `SELECT COUNT(*) FROM exporters`, 1)
	})
	t.Run("adds", func(t *testing.T) {
		db, w, _ := openWriter(t, 1, time.Hour)
		_, _ = runWriter(t, w)
		at := time.Unix(1_700_000_000, 0).UTC()
		a := eligibleShape(at, at, "192.0.2.74")
		a.Octets = 5
		b := a
		b.Octets = 7
		if err := w.Submit([]flow.Flow{a}); err != nil {
			t.Fatal(err)
		}
		if err := w.Submit([]flow.Flow{b}); err != nil {
			t.Fatal(err)
		}
		waitCount(t, db, `SELECT COALESCE(SUM(octets), 0) FROM traffic_1m`, 12)
	})
}

func TestWriteFailureDropsBatch(t *testing.T) {
	db, w, counters := openWriter(t, 1, time.Hour)
	if _, err := db.pool.Exec(`CREATE TRIGGER fail_flows BEFORE INSERT ON flows BEGIN SELECT RAISE(ABORT, 'forced'); END`); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_000, 0).UTC()
	w.SubmitDelta(flow.ExporterDelta{Exporter: netip.MustParseAddr("192.0.2.80"), Version: 9, Domain: 1, LastSeen: at, Packets: 4, Malformed: 1})
	if err := w.Submit([]flow.Flow{eligibleShape(at, at, "192.0.2.81")}); err != nil {
		t.Fatal(err)
	}
	cancel, errc := runWriter(t, w)
	waitMetric(t, counters, obs.SQLiteWriteFailures, 1)
	if n := mustCount(t, db, `SELECT COUNT(*) FROM flows`); n != 0 {
		t.Fatal(n)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM exporters`); n != 0 {
		t.Fatal(n)
	}
	if _, err := db.pool.Exec(`DROP TRIGGER fail_flows`); err != nil {
		t.Fatal(err)
	}
	if err := w.Submit([]flow.Flow{eligibleShape(at, at, "192.0.2.82")}); err != nil {
		t.Fatal(err)
	}
	waitCount(t, db, `SELECT COUNT(*) FROM flows`, 1)
	if n := mustCount(t, db, `SELECT COUNT(*) FROM exporters`); n != 0 {
		t.Fatal("failed batch was retried")
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if counters.Snapshot()[obs.SQLiteWriteFailures] != 1 || counters.Snapshot()[obs.SQLiteRowsWritten] != 1 {
		t.Fatal(counters.Snapshot()[obs.SQLiteWriteFailures], counters.Snapshot()[obs.SQLiteRowsWritten])
	}
}

func TestFinalFlushError(t *testing.T) {
	db, w, counters := openWriter(t, 100, time.Hour)
	if err := db.pool.Close(); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_000, 0).UTC()
	if err := w.Submit([]flow.Flow{eligibleShape(at, at, "192.0.2.90")}); err != nil {
		t.Fatal(err)
	}
	cancel, errc := runWriter(t, w)
	cancel()
	if err := <-errc; err == nil {
		t.Fatal("expected last flush error")
	}
	if counters.Snapshot()[obs.SQLiteWriteFailures] != 1 {
		t.Fatal(counters.Snapshot()[obs.SQLiteWriteFailures])
	}
}

func TestQueuesHold240000(t *testing.T) {
	_, w, counters := openWriter(t, 1000, time.Hour)
	const flowCap = 200000 // cfg.UDP.FlowQueue default
	flows := make(chan flow.Flow, flowCap)
	for i := 0; i < flowCap; i++ {
		select {
		case flows <- flow.Flow{}:
		default:
			t.Fatalf("flow queue full at %d", i)
		}
	}
	for i := 0; i < 40_000; i++ {
		if err := w.Submit([]flow.Flow{{}}); err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
	}
	snap := counters.Snapshot()
	if snap[obs.DroppedEnrichQueue] != 0 || snap[obs.DroppedWriterQueue] != 0 {
		t.Fatal(snap[obs.DroppedEnrichQueue], snap[obs.DroppedWriterQueue])
	}
	// The 240,001st flow still fits in the writer queue.
	if err := w.Submit([]flow.Flow{{}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < writerQueue-40_001; i++ {
		if err := w.Submit([]flow.Flow{{}}); err != nil {
			t.Fatalf("fill %d: %v", i, err)
		}
	}
	if len(w.flows) != writerQueue || len(flows) != flowCap {
		t.Fatal(len(w.flows), len(flows))
	}
	select {
	case flows <- flow.Flow{}:
		t.Fatal("flow queue accepted past capacity")
	default:
		if err := counters.Add(obs.DroppedEnrichQueue, 1); err != nil {
			t.Fatal(err)
		}
	}
	snap = counters.Snapshot()
	if snap[obs.DroppedEnrichQueue] != 1 || snap[obs.DroppedWriterQueue] != 0 {
		t.Fatal(snap[obs.DroppedEnrichQueue], snap[obs.DroppedWriterQueue])
	}
	errc := make(chan error, 1)
	go func() { errc <- w.Submit([]flow.Flow{{}}) }()
	select {
	case err := <-errc:
		if !errors.Is(err, flow.ErrQueueFull) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Submit blocked")
	}
	if counters.Snapshot()[obs.DroppedWriterQueue] != 0 {
		t.Fatal("Submit incremented dropped_writer_queue")
	}
}

func TestWriterSustains2000(t *testing.T) {
	db, w, counters := openWriter(t, 2000, 500*time.Millisecond)
	cancel, errc := runWriter(t, w)
	host, _ := os.Hostname()
	const rate = 2000
	const secs = 10
	start := time.Now()
	n := 0
	for s := 0; s < secs; s++ {
		if d := time.Until(start.Add(time.Duration(s) * time.Second)); d > 0 {
			time.Sleep(d)
		}
		for i := 0; i < rate; i++ {
			if err := w.Submit([]flow.Flow{benchFlow(n)}); err != nil {
				t.Fatal(err)
			}
			n++
		}
	}
	deadline := time.Now().Add(8 * time.Second)
	var got int
	for {
		got = mustCount(t, db, `SELECT COUNT(*) FROM flows`)
		if got == n {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("wrote %d/%d within the tail", got, n)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if counters.Snapshot()[obs.SQLiteWriteFailures] != 0 {
		t.Fatal(counters.Snapshot()[obs.SQLiteWriteFailures])
	}
	if bytes, ok := avgFlowBytes(t, db); ok {
		t.Logf("host %s dbstat bytes/flow %.1f rows %d", host, bytes, n)
	} else {
		t.Logf("host %s dbstat unavailable rows %d", host, n)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if counters.Snapshot()[obs.SQLiteWriteFailures] != 0 {
		t.Fatal("write failure on final flush")
	}
}

func avgFlowBytes(t *testing.T, db *DB) (float64, bool) {
	t.Helper()
	if err := db.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.pool.QueryRow(`SELECT COUNT(*) FROM flows`).Scan(&n); err != nil || n == 0 {
		t.Fatal(err)
	}
	var bytes sql.NullFloat64
	err := db.pool.QueryRow(`SELECT SUM(pgsize) FROM dbstat
		WHERE name = 'flows'
		   OR name = 'idx_flows_start'
		   OR name = 'idx_flows_src'
		   OR name = 'idx_flows_dst'
		   OR name = 'idx_flows_exporter'`).Scan(&bytes)
	if err != nil || !bytes.Valid {
		t.Logf("dbstat: %v", err)
		return 0, false
	}
	return bytes.Float64 / float64(n), true
}

func openWriter(t *testing.T, batch int, interval time.Duration) (*DB, *Writer, *obs.Counters) {
	t.Helper()
	db, err := Open(config.DB{Path: filepath.Join(t.TempDir(), "t.db"), BusyTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.pool.Close() })
	counters := obs.NewCounters()
	w, err := NewWriter(db, config.DB{BatchSize: batch, BatchInterval: interval}, counters)
	if err != nil {
		t.Fatal(err)
	}
	return db, w, counters
}

func runWriter(t *testing.T, w *Writer) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- w.Run(ctx) }()
	t.Cleanup(cancel)
	return cancel, errc
}

func mustCount(t *testing.T, db *DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.pool.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func waitCount(t *testing.T, db *DB, q string, want int, args ...any) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var n int
	for {
		n = mustCount(t, db, q, args...)
		if n == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s = %d, want %d", q, n, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitMetric(t *testing.T, counters *obs.Counters, name obs.Name, want uint64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if counters.Snapshot()[name] == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s = %d, want %d", name, counters.Snapshot()[name], want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertTraffic(t *testing.T, db *DB, exporter string, proto, sampled int, bucket int64, packets, octets, flows int64) {
	t.Helper()
	var p, o, f int64
	err := db.pool.QueryRow(`SELECT packets, octets, flows FROM traffic_1m WHERE exporter = ? AND ip_proto = ? AND sampled = ? AND bucket_ms = ?`, exporter, proto, sampled, bucket).Scan(&p, &o, &f)
	if err != nil || p != packets || o != octets || f != flows {
		t.Fatalf("%s proto %d sampled %d: %v packets %d octets %d flows %d", exporter, proto, sampled, err, p, o, f)
	}
}

func assertNoTraffic(t *testing.T, db *DB, exporter string) {
	t.Helper()
	if n := mustCount(t, db, `SELECT COUNT(*) FROM traffic_1m WHERE exporter = ?`, exporter); n != 0 {
		t.Fatal(exporter, n)
	}
}

func assertGeo(t *testing.T, db *DB, country string, bucket, packets, octets, flows int64) {
	t.Helper()
	var b, p, o, f int64
	err := db.pool.QueryRow(`SELECT bucket_ms, packets, octets, flows FROM geo_country_5m WHERE country = ?`, country).Scan(&b, &p, &o, &f)
	if err != nil || b != bucket || p != packets || o != octets || f != flows {
		t.Fatalf("%s: %v bucket %d packets %d octets %d flows %d", country, err, b, p, o, f)
	}
}

func trafficSum(t *testing.T, db *DB, exporter string) (packets, octets, flows int64) {
	t.Helper()
	err := db.pool.QueryRow(`SELECT COALESCE(SUM(packets),0), COALESCE(SUM(octets),0), COALESCE(SUM(flows),0) FROM traffic_1m WHERE exporter = ?`, exporter).Scan(&packets, &octets, &flows)
	if err != nil {
		t.Fatal(err)
	}
	return packets, octets, flows
}

func flowMap(t *testing.T, db *DB, exporter string) map[string]any {
	t.Helper()
	rows, err := db.pool.Query(`SELECT * FROM flows WHERE exporter = ?`, exporter)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	if !rows.Next() {
		t.Fatalf("no flow %s", exporter)
	}
	dest := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range dest {
		ptrs[i] = &dest[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		t.Fatal(err)
	}
	if rows.Next() {
		t.Fatalf("extra flow %s", exporter)
	}
	out := make(map[string]any, len(cols))
	for i, c := range cols {
		out[c] = dest[i]
	}
	return out
}

func assertFlowMap(t *testing.T, got, want map[string]any) {
	t.Helper()
	for col, g := range got {
		if col == "id" {
			continue
		}
		w, ok := want[col]
		if !ok {
			t.Fatalf("unchecked column %s", col)
		}
		if !sameVal(g, w) {
			t.Fatalf("%s got %#v (%T) want %#v (%T)", col, g, g, w, w)
		}
	}
	for col := range want {
		if _, ok := got[col]; !ok {
			t.Fatalf("missing column %s", col)
		}
	}
}

func sameVal(got, want any) bool {
	if want == nil {
		return got == nil
	}
	switch w := want.(type) {
	case int64:
		switch g := got.(type) {
		case int64:
			return g == w
		case int:
			return int64(g) == w
		}
	case float64:
		g, ok := got.(float64)
		return ok && g == w
	case string:
		switch g := got.(type) {
		case string:
			return g == w
		case []byte:
			return string(g) == w
		}
	}
	return false
}

func richFlow(start, recv time.Time) flow.Flow {
	hop := netip.MustParseAddr("198.51.100.1")
	dir := uint8(1)
	outP := uint64(4)
	outO := uint64(50)
	inIf := uint32(7)
	outIf := uint32(8)
	bgpS := uint32(64500)
	bgpD := uint32(15169)
	sm := uint8(24)
	dm := uint8(16)
	interval := uint32(100)
	algo := uint8(1)
	return flow.Flow{
		ReceivedAt:        recv,
		Start:             start,
		End:               start.Add(time.Second),
		TimeSource:        flow.TimeAbsolute,
		ClockClamped:      true,
		Exporter:          netip.MustParseAddr("192.0.2.9"),
		Domain:            7,
		Version:           9,
		Src:               netip.MustParseAddr("203.0.113.10"),
		Dst:               netip.MustParseAddr("203.0.113.20"),
		SrcPort:           51515,
		DstPort:           443,
		PortsPresent:      true,
		Proto:             6,
		ProtoPresent:      true,
		TCPFlags:          0x12,
		TCPFlagsPresent:   true,
		TOS:               0,
		TOSPresent:        true,
		FlowDirection:     &dir,
		Packets:           10,
		Octets:            1000,
		CounterSemantics:  "delta",
		OctetSemantics:    "ip",
		OutPackets:        &outP,
		OutOctets:         &outO,
		InputIf:           &inIf,
		OutputIf:          &outIf,
		NextHop:           &hop,
		BGPSrcAS:          &bgpS,
		BGPDstAS:          &bgpD,
		SrcMask:           &sm,
		DstMask:           &dm,
		Sampled:           true,
		SamplingInterval:  &interval,
		SamplingAlgorithm: &algo,
		SrcEnrich: flow.Endpoint{
			Scope: "global",
			Geo:   flow.Outcome{Kind: flow.OutcomeValue, Country: "US", Region: "CA", City: "LA", Lat: 34, Lon: -118.2, HasLatLon: true},
			ASN:   flow.Outcome{Kind: flow.OutcomeValue, ASN: 64500, ASNName: "Example"},
			Rep:   flow.Outcome{Kind: flow.OutcomeValue, Category: "scan", Score: 0.5, HasScore: true},
		},
		DstEnrich: flow.Endpoint{
			Scope: "private",
			Geo:   flow.Outcome{Kind: flow.OutcomeSkipped},
			ASN:   flow.Outcome{Kind: flow.OutcomeNotConfigured},
			Rep:   flow.Outcome{Kind: flow.OutcomeSkipped},
		},
	}
}

func eligibleShape(start, recv time.Time, exporter string) flow.Flow {
	return flow.Flow{
		ReceivedAt:       recv,
		Start:            start,
		End:              start.Add(time.Millisecond),
		TimeSource:       flow.TimeReceive,
		Exporter:         netip.MustParseAddr(exporter),
		Domain:           1,
		Version:          9,
		Src:              netip.MustParseAddr("203.0.113.1"),
		Dst:              netip.MustParseAddr("203.0.113.2"),
		Packets:          9,
		Octets:           90,
		CounterSemantics: "delta",
		OctetSemantics:   "ip",
		SrcEnrich: flow.Endpoint{
			Scope: "global",
			Geo:   flow.Outcome{Kind: flow.OutcomeNotConfigured},
			ASN:   flow.Outcome{Kind: flow.OutcomeNotConfigured},
			Rep:   flow.Outcome{Kind: flow.OutcomeNotConfigured},
		},
		DstEnrich: flow.Endpoint{
			Scope: "global",
			Geo:   flow.Outcome{Kind: flow.OutcomeNotConfigured},
			ASN:   flow.Outcome{Kind: flow.OutcomeNotConfigured},
			Rep:   flow.Outcome{Kind: flow.OutcomeNotConfigured},
		},
	}
}

func benchFlow(i int) flow.Flow {
	n := i + 1
	src := netip.AddrFrom4([4]byte{1, byte(n >> 16), byte(n >> 8), byte(n)})
	dst := netip.AddrFrom4([4]byte{2, byte(n >> 16), byte(n >> 8), byte(n)})
	start := time.Unix(1_700_000_000, 0).UTC().Add(time.Duration(i) * time.Millisecond)
	ep := flow.Endpoint{
		Scope: "global",
		Geo:   flow.Outcome{Kind: flow.OutcomeNotConfigured},
		ASN:   flow.Outcome{Kind: flow.OutcomeNotConfigured},
		Rep:   flow.Outcome{Kind: flow.OutcomeNotConfigured},
	}
	return flow.Flow{
		ReceivedAt:       start,
		ExportTime:       start,
		Start:            start,
		End:              start.Add(time.Millisecond),
		TimeSource:       flow.TimeSysUpTime,
		Exporter:         netip.MustParseAddr("192.0.2.9"),
		Domain:           1,
		Version:          9,
		Src:              src,
		Dst:              dst,
		SrcPort:          uint16(n),
		DstPort:          443,
		PortsPresent:     true,
		Proto:            6,
		ProtoPresent:     true,
		Packets:          1,
		Octets:           100,
		CounterSemantics: "delta",
		OctetSemantics:   "ip",
		SrcEnrich:        ep,
		DstEnrich:        ep,
	}
}

func parseV9(t *testing.T, payload []byte, src netip.Addr, at time.Time) flow.ExporterDelta {
	t.Helper()
	templates, err := template.NewCache(8)
	if err != nil {
		t.Fatal(err)
	}
	_, delta, _, _ := v9.Parse(ingest.Datagram{Payload: payload, Src: src, ReceivedAt: at}, templates, nil, nil, obs.NewCounters(), false, 2*time.Hour, 5*time.Second)
	return delta
}

func v9TemplatePacket(domain, seq uint32) []byte {
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], 9)
	binary.BigEndian.PutUint16(hdr[2:4], 1)
	binary.BigEndian.PutUint32(hdr[8:12], 1_700_000_000)
	binary.BigEndian.PutUint32(hdr[12:16], seq)
	binary.BigEndian.PutUint32(hdr[16:20], domain)
	body := make([]byte, 12)
	binary.BigEndian.PutUint16(body[0:2], 256)
	binary.BigEndian.PutUint16(body[2:4], 2)
	binary.BigEndian.PutUint16(body[4:6], 8)
	binary.BigEndian.PutUint16(body[6:8], 4)
	binary.BigEndian.PutUint16(body[8:10], 12)
	binary.BigEndian.PutUint16(body[10:12], 4)
	set := make([]byte, 4+len(body))
	binary.BigEndian.PutUint16(set[0:2], 0)
	binary.BigEndian.PutUint16(set[2:4], uint16(len(set)))
	copy(set[4:], body)
	return append(hdr, set...)
}

func decodeFixture(t *testing.T, name string, src netip.Addr, at time.Time) flow.Flow {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "decode", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	templates, err := template.NewCache(8)
	if err != nil {
		t.Fatal(err)
	}
	flows, _, _, err := ipfix.Parse(ingest.Datagram{Payload: b, Src: src, ReceivedAt: at}, templates, nil, nil, nil, false, 2*time.Hour, 5*time.Second)
	if err != nil || len(flows) != 1 {
		t.Fatal(name, err, len(flows))
	}
	return flows[0]
}

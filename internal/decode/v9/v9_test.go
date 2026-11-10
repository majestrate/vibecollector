package v9

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vibecollector/internal/decode"
	"vibecollector/internal/flow"
	"vibecollector/internal/ingest"
	"vibecollector/internal/obs"
	"vibecollector/internal/sampling"
	"vibecollector/internal/sequence"
	"vibecollector/internal/template"
)

// Multi-datagram fixtures are uint32be length then payload, repeated.
// A file whose first uint16 is 9 is one raw datagram. v9 boundaries are not
// recoverable from concatenation, so the length prefix is only a test framing.

func TestTemplateThenData(t *testing.T) {
	pkts := readDatagrams(t, "v9_template_then_data.bin")
	if len(pkts) != 2 {
		t.Fatalf("datagrams %d", len(pkts))
	}
	p := pkts[0]
	if binary.BigEndian.Uint16(p[20:22]) != 0 {
		t.Fatal("template flowset")
	}
	if binary.BigEndian.Uint16(p[24:26]) != 256 || binary.BigEndian.Uint16(p[26:28]) != 18 {
		t.Fatal("first template record")
	}
	off := 24 + 4 + 18*4
	if binary.BigEndian.Uint16(p[off:off+2]) != 257 || binary.BigEndian.Uint16(p[off+2:off+4]) != 2 {
		t.Fatal("second template record")
	}
	templates, _, counters, _ := walk(t, "v9_template_then_data")
	ip := netip.MustParseAddr("192.0.2.8")
	for _, id := range []uint16{256, 257} {
		if _, ok := templates.Get(template.Key{Exporter: ip, Domain: 7, Version: 9, ID: id}); !ok {
			t.Fatalf("template %d missing", id)
		}
	}
	if counters.Snapshot()[obs.DecodedFlows] != 0 || counters.Snapshot()[obs.DecodedPackets] != 0 {
		t.Fatal("decoded counters")
	}
}

func TestOptionsSampling(t *testing.T) {
	pkts := readDatagrams(t, "v9_options_sampling.bin")
	p := pkts[0]
	want := []struct {
		off int
		v   uint16
	}{
		{20, 1}, {22, 24}, {24, 256}, {26, 4}, {28, 8},
		{30, 2}, {32, 2}, {34, 34}, {36, 4}, {38, 35}, {40, 1},
	}
	for _, w := range want {
		if got := binary.BigEndian.Uint16(p[w.off : w.off+2]); got != w.v {
			t.Fatalf("offset %d = %d want %d", w.off, got, w.v)
		}
	}
	if binary.BigEndian.Uint16(p[44:46]) != 256 || binary.BigEndian.Uint16(p[46:48]) != 12 {
		t.Fatal("options data flowset")
	}
	if binary.BigEndian.Uint16(p[48:50]) != 7 || binary.BigEndian.Uint32(p[50:54]) != 100 || p[54] != 1 {
		t.Fatal("interface 7 interval 100 algorithm 1")
	}
	_, samples, _, _ := walk(t, "v9_options_sampling")
	ip := netip.MustParseAddr("192.0.2.8")
	got, ok := samples.Lookup(ip, 1, []string{"if:7"})
	if !ok || got.N != 100 || got.Algorithm != 1 || !got.Sampled {
		t.Fatalf("cache %+v %v", got, ok)
	}
	at := mustTime(t, "2023-11-14T22:13:20Z")
	seq2 := sequence.NewTable()
	counters2 := obs.NewCounters()
	templates2 := mustCache(t)
	if _, _, _, err := Parse(datagram(pkts[0], ip, at), templates2, samples, seq2, counters2, false, 2*time.Hour, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Parse(datagram(pkts[0], ip, at), templates2, samples, seq2, counters2, false, 2*time.Hour, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if counters2.Snapshot()[obs.SequenceDuplicate] != 1 {
		t.Fatal("options packet did not advance the cursor")
	}
}

func TestDataBeforeTemplateMissing(t *testing.T) {
	pkts := readDatagrams(t, "v9_data_before_template.bin")
	templates, _, counters, seq := walk(t, "v9_data_before_template")
	ip := netip.MustParseAddr("192.0.2.8")
	if _, ok := templates.Get(template.Key{Exporter: ip, Domain: 4, Version: 9, ID: 256}); !ok {
		t.Fatal("template was not installed")
	}
	flows, delta, missing, err := Parse(datagram(pkts[0], ip, mustTime(t, "2023-11-14T22:13:20Z")), templates, sampling.NewCache(), seq, counters, false, 2*time.Hour, 5*time.Second)
	if err != nil || missing != nil || len(flows) != 1 || flows[0].Packets != 9 {
		t.Fatalf("retry flows %d missing %v err %v delta %+v", len(flows), missing != nil, err, delta)
	}
	if flows[0].Sampled || flows[0].Octets != 0 {
		t.Fatal(flows[0])
	}
}

func TestFieldCountZero(t *testing.T) {
	walk(t, "v9_fieldcount_zero")
	p := readDatagrams(t, "v9_fieldcount_zero.bin")[0]
	if binary.BigEndian.Uint16(p[20:22]) != 0 || binary.BigEndian.Uint16(p[22:24]) != 8 ||
		binary.BigEndian.Uint16(p[24:26]) != 256 || binary.BigEndian.Uint16(p[26:28]) != 0 {
		t.Fatal("field count 0 layout")
	}
	templates, _ := template.NewCache(8)
	ip := netip.MustParseAddr("192.0.2.8")
	key := template.Key{Exporter: ip, Domain: 7, Version: 9, ID: 256}
	if _, _, err := templates.Put(key, template.Template{Fields: []template.Field{{Type: 8, Length: 4}}}); err != nil {
		t.Fatal(err)
	}
	counters := obs.NewCounters()
	_, delta, _, err := Parse(datagram(p, ip, time.Unix(1_700_000_000, 0).UTC()), templates, nil, sequence.NewTable(), counters, false, 2*time.Hour, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if delta.Malformed != 1 || counters.Snapshot()[obs.Malformed] != 1 {
		t.Fatal(delta, counters.Snapshot()[obs.Malformed])
	}
	got, ok := templates.Get(key)
	if !ok || len(got.Fields) != 1 || got.Fields[0].Type != 8 {
		t.Fatal("field count 0 changed the template", got, ok)
	}
}

func TestCountRecords(t *testing.T) {
	pkts := readDatagrams(t, "v9_count_records.bin")
	if len(pkts) != 3 {
		t.Fatal(len(pkts))
	}
	// Four FlowSets: template, three data records, options template, two options data.
	sets := 0
	for off := 20; off+4 <= len(pkts[0]); {
		n := int(binary.BigEndian.Uint16(pkts[0][off+2 : off+4]))
		sets++
		off += n
	}
	if sets != 4 {
		t.Fatal(sets)
	}
	walk(t, "v9_count_records")
}

func TestPaddingReserved(t *testing.T) {
	walk(t, "v9_padding_reserved")
}

func TestSamePacketDataThenTemplate(t *testing.T) {
	body := templateBody(256, [][2]uint16{{8, 4}, {12, 4}, {2, 4}})
	rec := make([]byte, 12)
	binary.BigEndian.PutUint32(rec[0:4], 0x0a000001)
	binary.BigEndian.PutUint32(rec[4:8], 0x0a000002)
	binary.BigEndian.PutUint32(rec[8:12], 3)
	pkt := append(header(1, 0, 1_700_000_000, 0, 1), flowSet(256, rec)...)
	pkt = append(pkt, flowSet(0, body)...)
	// Count is 1, but the packet has a template record and a data record.
	binary.BigEndian.PutUint16(pkt[2:4], 2)
	flows, delta, missing, err := parseOne(t, pkt, mustCache(t), sampling.NewCache())
	if err != nil || missing != nil || len(flows) != 1 || flows[0].Packets != 3 || delta.MissingTemplate != 0 {
		t.Fatalf("flows %v missing %v err %v delta %+v", flows, missing != nil, err, delta)
	}
}

func TestDoesNotStopAtCount(t *testing.T) {
	templates, _ := template.NewCache(8)
	body := templateBody(256, [][2]uint16{{8, 4}, {12, 4}})
	rec := func(n uint32) []byte {
		b := make([]byte, 8)
		binary.BigEndian.PutUint32(b[0:4], n)
		binary.BigEndian.PutUint32(b[4:8], n+1)
		return b
	}
	pkt := append(header(1, 0, 1_700_000_000, 0, 1), flowSet(0, body)...)
	pkt = append(pkt, flowSet(256, rec(1))...)
	pkt = append(pkt, flowSet(256, rec(3))...)
	counters := obs.NewCounters()
	flows, _, _, err := Parse(datagram(pkt, netip.MustParseAddr("192.0.2.8"), time.Unix(1_700_000_000, 0).UTC()), templates, nil, sequence.NewTable(), counters, false, 2*time.Hour, 5*time.Second)
	if err != nil || len(flows) != 2 {
		t.Fatalf("flows %d err %v", len(flows), err)
	}
	if counters.Snapshot()[obs.CountDisagrees] != 1 || counters.Snapshot()[obs.Malformed] != 0 {
		t.Fatal(counters.Snapshot())
	}
}

func TestShortSetKeepsEarlier(t *testing.T) {
	templates, _ := template.NewCache(4)
	body := templateBody(256, [][2]uint16{{8, 4}, {12, 4}, {2, 4}})
	rec := make([]byte, 12)
	binary.BigEndian.PutUint32(rec[8:12], 11)
	pkt := append(header(2, 0, 1_700_000_000, 0, 1), flowSet(0, body)...)
	pkt = append(pkt, flowSet(256, rec)...)
	pkt = append(pkt, []byte{0x01, 0x00, 0x00, 0x64}...) // length 100 past the payload
	counters := obs.NewCounters()
	flows, delta, _, err := Parse(datagram(pkt, netip.MustParseAddr("192.0.2.8"), time.Unix(1_700_000_000, 0).UTC()), templates, nil, nil, counters, false, 2*time.Hour, 5*time.Second)
	if !errors.Is(err, decode.ErrShortSet) || len(flows) != 1 || flows[0].Packets != 11 {
		t.Fatalf("flows %v err %v", flows, err)
	}
	if delta.Malformed != 1 || counters.Snapshot()[obs.Malformed] != 1 {
		t.Fatal("malformed", delta.Malformed, counters.Snapshot()[obs.Malformed])
	}
	if counters.Snapshot()[obs.CountDisagrees] != 0 {
		t.Fatal("short walk compared count")
	}
}

func TestShortTailIgnored(t *testing.T) {
	templates, _ := template.NewCache(4)
	pkt := append(header(0, 1000, 1_700_000_000, 0, 1), []byte{0xab, 0xcd, 0xef}...)
	counters := obs.NewCounters()
	flows, _, _, err := Parse(datagram(pkt, netip.MustParseAddr("192.0.2.8"), time.Unix(1_700_000_000, 0).UTC()), templates, nil, sequence.NewTable(), counters, false, 2*time.Hour, 5*time.Second)
	if err != nil || len(flows) != 0 {
		t.Fatal(err, flows)
	}
	snap := counters.Snapshot()
	if snap[obs.Malformed] != 0 || snap[obs.PaddingNonzero] != 0 || snap[obs.CountDisagrees] != 0 {
		t.Fatal(snap)
	}
}

func TestSequenceGapPacketsOnly(t *testing.T) {
	counters := obs.NewCounters()
	seq := sequence.NewTable()
	ip := netip.MustParseAddr("192.0.2.8")
	at := time.Unix(1_700_000_000, 0).UTC()
	templates := mustCache(t)
	if _, _, _, err := Parse(datagram(header(0, 0, 1_700_000_000, 0, 1), ip, at), templates, nil, seq, counters, false, 2*time.Hour, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	_, delta, _, err := Parse(datagram(header(0, 0, 1_700_000_000, 5, 1), ip, at), templates, nil, seq, counters, false, 2*time.Hour, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if delta.GapPackets != 4 || delta.GapFlows != 0 || delta.GapRecords != 0 {
		t.Fatal(delta)
	}
	snap := counters.Snapshot()
	if snap[obs.SequenceGapV9Packets] != 4 || snap[obs.SequenceGapV5Flows] != 0 || snap[obs.SequenceGapIPFIXRecords] != 0 {
		t.Fatal(snap)
	}
}

func TestShortHeaderDoesNotMoveCursor(t *testing.T) {
	counters := obs.NewCounters()
	seq := sequence.NewTable()
	ip := netip.MustParseAddr("192.0.2.8")
	at := time.Unix(1_700_000_000, 0).UTC()
	short := make([]byte, 10)
	binary.BigEndian.PutUint16(short, 9)
	_, delta, _, err := Parse(datagram(short, ip, at), mustCache(t), nil, seq, counters, false, 2*time.Hour, 5*time.Second)
	if !errors.Is(err, decode.ErrMalformed) || delta.Version != 9 || delta.Malformed != 1 {
		t.Fatal(delta, err)
	}
	_, delta, _, err = Parse(datagram(header(0, 0, 1_700_000_000, 5, 1), ip, at), mustCache(t), nil, seq, counters, false, 2*time.Hour, 5*time.Second)
	if err != nil || delta.GapPackets != 0 || counters.Snapshot()[obs.SequenceGapV9Packets] != 0 {
		t.Fatal(delta, err)
	}
}

func TestZeroUnixUsesReceive(t *testing.T) {
	templates := mustCache(t)
	body := templateBody(256, [][2]uint16{{8, 4}, {12, 4}})
	rec := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	pkt := append(header(2, 5000, 0, 0, 1), flowSet(0, body)...)
	pkt = append(pkt, flowSet(256, rec)...)
	received := time.Unix(1_700_000_100, 0).UTC()
	flows, _, _, err := Parse(datagram(pkt, netip.MustParseAddr("192.0.2.8"), received), templates, nil, nil, obs.NewCounters(), false, 2*time.Hour, 5*time.Second)
	if err != nil || len(flows) != 1 {
		t.Fatal(err, len(flows))
	}
	f := flows[0]
	if f.TimeSource != flow.TimeReceive || !f.Start.Equal(received) || !f.End.Equal(received) {
		t.Fatal(f.TimeSource, f.Start, f.End)
	}
}

func TestExplicitZeroMaxAge(t *testing.T) {
	templates := mustCache(t)
	body := templateBody(256, [][2]uint16{{8, 4}, {12, 4}, {22, 4}, {21, 4}})
	rec := make([]byte, 16)
	copy(rec[:8], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	pkt := append(header(2, 10000, 1_700_000_000, 0, 1), flowSet(0, body)...)
	pkt = append(pkt, flowSet(256, rec)...)
	counters := obs.NewCounters()
	at := time.Unix(1_700_000_000, 0).UTC()
	if _, _, _, err := Parse(datagram(pkt, netip.MustParseAddr("192.0.2.8"), at), templates, nil, nil, counters, false, 0, 0); err != nil {
		t.Fatal(err)
	}
	if counters.Snapshot()[obs.TimestampSuspect] == 0 {
		t.Fatal("zero maxAge was replaced")
	}
}

func TestScopeKeysAndRejects(t *testing.T) {
	// Five scope definitions and two option fields. Scope length is bytes, not a count.
	specs := optionsBody(256, 20, 8, [][2]uint16{{1, 4}, {2, 4}, {3, 4}, {4, 4}, {5, 4}, {34, 4}, {48, 4}})
	vals := make([]byte, 28)
	binary.BigEndian.PutUint32(vals[0:4], 0)
	binary.BigEndian.PutUint32(vals[4:8], 7)
	binary.BigEndian.PutUint32(vals[8:12], 4)
	binary.BigEndian.PutUint32(vals[12:16], 9)
	binary.BigEndian.PutUint32(vals[16:20], 8)
	binary.BigEndian.PutUint32(vals[20:24], 100)
	binary.BigEndian.PutUint32(vals[24:28], 3)
	pkt := append(header(2, 0, 1_700_000_000, 0, 1), flowSet(1, specs)...)
	pkt = append(pkt, flowSet(256, vals)...)
	samples := sampling.NewCache()
	templates := mustCache(t)
	flows, _, _, err := parseOne(t, pkt, templates, samples)
	if err != nil || len(flows) != 0 {
		t.Fatal(err, flows)
	}
	ip := netip.MustParseAddr("192.0.2.8")
	for _, scope := range []string{"device", "if:7", "linecard:4", "cache:9", "template:8", "sampler:3"} {
		got, ok := samples.Lookup(ip, 1, []string{scope})
		if !ok || got.N != 100 || !got.Sampled {
			t.Fatalf("%s %+v %v", scope, got, ok)
		}
	}
	bad := optionsBody(257, 2, 4, [][2]uint16{{2, 2}, {34, 4}})
	pkt = append(header(1, 0, 1_700_000_000, 1, 1), flowSet(1, bad)...)
	counters := obs.NewCounters()
	if _, _, _, err := Parse(datagram(pkt, ip, time.Unix(1_700_000_000, 0).UTC()), templates, samples, nil, counters, false, time.Hour, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, ok := templates.Get(template.Key{Exporter: ip, Domain: 1, Version: 9, ID: 257}); ok {
		t.Fatal("odd scope length installed")
	}
	if counters.Snapshot()[obs.Malformed] != 1 {
		t.Fatal(counters.Snapshot()[obs.Malformed])
	}
	zero := templateBody(258, [][2]uint16{{8, 0}})
	pkt = append(header(1, 0, 1_700_000_000, 2, 1), flowSet(0, zero)...)
	if _, _, _, err := Parse(datagram(pkt, ip, time.Unix(1_700_000_000, 0).UTC()), templates, nil, nil, obs.NewCounters(), false, time.Hour, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, ok := templates.Get(template.Key{Exporter: ip, Domain: 1, Version: 9, ID: 258}); ok {
		t.Fatal("zero-size template installed")
	}
}

func TestSamplingWithoutAddresses(t *testing.T) {
	body := templateBody(256, [][2]uint16{{34, 4}, {35, 1}, {10, 2}})
	rec := make([]byte, 7)
	binary.BigEndian.PutUint32(rec[0:4], 50)
	rec[4] = 2
	binary.BigEndian.PutUint16(rec[5:7], 3)
	pkt := append(header(2, 0, 1_700_000_000, 0, 4), flowSet(0, body)...)
	pkt = append(pkt, flowSet(256, rec)...)
	samples := sampling.NewCache()
	counters := obs.NewCounters()
	flows, _, missing, err := Parse(datagram(pkt, netip.MustParseAddr("192.0.2.8"), time.Unix(1_700_000_000, 0).UTC()), mustCache(t), samples, nil, counters, false, time.Hour, time.Second)
	if err != nil || missing != nil || len(flows) != 0 {
		t.Fatal(err, missing, flows)
	}
	got, ok := samples.Lookup(netip.MustParseAddr("192.0.2.8"), 4, []string{"if:3"})
	if !ok || got.N != 50 || got.Algorithm != 2 || !got.Sampled {
		t.Fatalf("%+v %v", got, ok)
	}
	if counters.Snapshot()[obs.NonFlowRecords] != 1 {
		t.Fatal(counters.Snapshot()[obs.NonFlowRecords])
	}
}

func TestRateWhenIntervalIsZeroOrOne(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.8")
	at := time.Unix(1_700_000_000, 0).UTC()
	specs := optionsBody(256, 4, 8, [][2]uint16{{1, 4}, {34, 4}, {50, 4}})
	vals := make([]byte, 12)
	binary.BigEndian.PutUint32(vals[4:8], 1)
	binary.BigEndian.PutUint32(vals[8:12], 100)
	pkt := append(header(2, 0, 1_700_000_000, 0, 1), flowSet(1, specs)...)
	pkt = append(pkt, flowSet(256, vals)...)
	samples := sampling.NewCache()
	if _, _, _, err := Parse(datagram(pkt, ip, at), mustCache(t), samples, nil, nil, false, time.Hour, time.Second); err != nil {
		t.Fatal(err)
	}
	got, ok := samples.Lookup(ip, 1, []string{"device"})
	if !ok || got.N != 100 || !got.Sampled {
		t.Fatalf("options %+v %v", got, ok)
	}

	body := templateBody(256, [][2]uint16{{34, 4}, {50, 4}, {10, 4}})
	rec := make([]byte, 12)
	binary.BigEndian.PutUint32(rec[4:8], 100)
	binary.BigEndian.PutUint32(rec[8:12], 3)
	pkt = append(header(2, 0, 1_700_000_000, 0, 4), flowSet(0, body)...)
	pkt = append(pkt, flowSet(256, rec)...)
	samples = sampling.NewCache()
	if _, _, _, err := Parse(datagram(pkt, ip, at), mustCache(t), samples, nil, nil, false, time.Hour, time.Second); err != nil {
		t.Fatal(err)
	}
	got, ok = samples.Lookup(ip, 4, []string{"if:3"})
	if !ok || got.N != 100 || !got.Sampled {
		t.Fatalf("address-less %+v %v", got, ok)
	}

	bad := optionsBody(257, 4, 4, [][2]uint16{{99, 4}, {34, 4}})
	vals = make([]byte, 8)
	binary.BigEndian.PutUint32(vals[0:4], 5)
	binary.BigEndian.PutUint32(vals[4:8], 100)
	pkt = append(header(2, 0, 1_700_000_000, 1, 1), flowSet(1, bad)...)
	pkt = append(pkt, flowSet(257, vals)...)
	samples = sampling.NewCache()
	samples.Put(sampling.SampleKey{Exporter: ip, Domain: 1, Scope: "device"}, sampling.Sample{N: 7, Sampled: true})
	if _, _, _, err := Parse(datagram(pkt, ip, at), mustCache(t), samples, nil, nil, false, time.Hour, time.Second); err != nil {
		t.Fatal(err)
	}
	got, ok = samples.Lookup(ip, 1, []string{"device"})
	if !ok || got.N != 7 {
		t.Fatalf("failed scope replaced device %+v %v", got, ok)
	}
}

func TestCachedSamplingWalk(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.8")
	at := time.Unix(1_700_000_000, 0).UTC()
	flowPkt := func(fields [][2]uint16, rec []byte) []byte {
		pkt := append(header(2, 0, 1_700_000_000, 0, 1), flowSet(0, templateBody(256, fields))...)
		return append(pkt, flowSet(256, rec)...)
	}
	parse := func(samples *sampling.Cache, pkt []byte) flow.Flow {
		t.Helper()
		flows, _, _, err := Parse(datagram(pkt, ip, at), mustCache(t), samples, nil, nil, false, 2*time.Hour, 5*time.Second)
		if err != nil || len(flows) != 1 {
			t.Fatalf("flows %d err %v", len(flows), err)
		}
		return flows[0]
	}
	addrs := [][2]uint16{{8, 4}, {12, 4}, {2, 4}}
	rec := make([]byte, 12)
	binary.BigEndian.PutUint32(rec[8:12], 1)

	samples := sampling.NewCache()
	samples.Put(sampling.SampleKey{Exporter: ip, Domain: 1, Scope: "linecard:4"}, sampling.Sample{N: 100, Algorithm: 2, Sampled: true})
	f := parse(samples, flowPkt(addrs, rec))
	if !f.Sampled || f.SamplingInterval == nil || *f.SamplingInterval != 100 || f.SamplingAlgorithm == nil || *f.SamplingAlgorithm != 2 {
		t.Fatalf("linecard %+v", f)
	}

	withIf := [][2]uint16{{8, 4}, {12, 4}, {10, 4}, {2, 4}}
	recIf := make([]byte, 16)
	binary.BigEndian.PutUint32(recIf[8:12], 7)
	binary.BigEndian.PutUint32(recIf[12:16], 1)
	samples = sampling.NewCache()
	samples.Put(sampling.SampleKey{Exporter: ip, Domain: 1, Scope: "if:7"}, sampling.Sample{N: 0})
	samples.Put(sampling.SampleKey{Exporter: ip, Domain: 1, Scope: "device"}, sampling.Sample{N: 100, Sampled: true})
	f = parse(samples, flowPkt(withIf, recIf))
	if !f.Sampled || f.SamplingInterval == nil || *f.SamplingInterval != 100 {
		t.Fatalf("zero N hid device %+v", f)
	}

	samples = sampling.NewCache()
	samples.Put(sampling.SampleKey{Exporter: ip, Domain: 1, Scope: "linecard:1"}, sampling.Sample{N: 40, Sampled: true})
	samples.Put(sampling.SampleKey{Exporter: ip, Domain: 1, Scope: "linecard:2"}, sampling.Sample{N: 80, Sampled: true})
	f = parse(samples, flowPkt(addrs, rec))
	if f.Sampled || f.SamplingInterval != nil {
		t.Fatalf("invented a linecard %+v", f)
	}

	withN := [][2]uint16{{8, 4}, {12, 4}, {34, 4}, {2, 4}}
	recN := make([]byte, 16)
	binary.BigEndian.PutUint32(recN[8:12], 1)
	binary.BigEndian.PutUint32(recN[12:16], 1)
	samples = sampling.NewCache()
	samples.Put(sampling.SampleKey{Exporter: ip, Domain: 1, Scope: "device"}, sampling.Sample{N: 100, Sampled: true})
	f = parse(samples, flowPkt(withN, recN))
	if !f.Sampled || f.SamplingInterval == nil || *f.SamplingInterval != 100 {
		t.Fatalf("interval 1 hid device %+v", f)
	}
}

func TestMissingSwitchUsesExport(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.8")
	unix := uint32(1_700_000_000)
	export := time.Unix(int64(unix), 0).UTC()
	sysUp := uint32(3 * time.Hour / time.Millisecond)
	counters := obs.NewCounters()
	body := templateBody(256, [][2]uint16{{8, 4}, {12, 4}})
	rec := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	pkt := append(header(2, sysUp, unix, 0, 1), flowSet(0, body)...)
	pkt = append(pkt, flowSet(256, rec)...)
	flows, _, _, err := Parse(datagram(pkt, ip, export), mustCache(t), nil, nil, counters, false, 2*time.Hour, 5*time.Second)
	if err != nil || len(flows) != 1 {
		t.Fatal(err, len(flows))
	}
	if !flows[0].Start.Equal(export) || !flows[0].End.Equal(export) || counters.Snapshot()[obs.TimestampSuspect] != 0 {
		t.Fatalf("both missing %s %s suspect %d", flows[0].Start, flows[0].End, counters.Snapshot()[obs.TimestampSuspect])
	}

	body = templateBody(257, [][2]uint16{{8, 4}, {12, 4}, {22, 4}})
	rec = make([]byte, 12)
	copy(rec[:8], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	pkt = append(header(2, sysUp, unix, 0, 1), flowSet(0, body)...)
	pkt = append(pkt, flowSet(257, rec)...)
	counters = obs.NewCounters()
	flows, _, _, err = Parse(datagram(pkt, ip, export), mustCache(t), nil, nil, counters, false, 2*time.Hour, 5*time.Second)
	if err != nil || len(flows) != 1 {
		t.Fatal(err, len(flows))
	}
	if !flows[0].Start.Equal(export.Add(-2*time.Hour)) || !flows[0].End.Equal(export) || counters.Snapshot()[obs.TimestampSuspect] != 1 {
		t.Fatalf("last missing %s %s suspect %d", flows[0].Start, flows[0].End, counters.Snapshot()[obs.TimestampSuspect])
	}
}

func TestMissingFirstDoesNotSwap(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.8")
	unix := uint32(1_700_000_000)
	export := time.Unix(int64(unix), 0).UTC()
	sysUp := uint32(3 * time.Hour / time.Millisecond)
	counters := obs.NewCounters()
	body := templateBody(256, [][2]uint16{{8, 4}, {12, 4}, {21, 4}})
	rec := make([]byte, 12)
	copy(rec[:8], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	binary.BigEndian.PutUint32(rec[8:12], sysUp-1000)
	pkt := append(header(2, sysUp, unix, 0, 1), flowSet(0, body)...)
	pkt = append(pkt, flowSet(256, rec)...)
	flows, _, _, err := Parse(datagram(pkt, ip, export), mustCache(t), nil, nil, counters, false, 2*time.Hour, 5*time.Second)
	if err != nil || len(flows) != 1 {
		t.Fatal(err, len(flows))
	}
	if !flows[0].Start.Equal(export) || !flows[0].End.Equal(export.Add(-time.Second)) || counters.Snapshot()[obs.TimestampSuspect] != 0 {
		t.Fatalf("missing first %s %s suspect %d", flows[0].Start, flows[0].End, counters.Snapshot()[obs.TimestampSuspect])
	}
}

func TestWideFieldsAndUnmap(t *testing.T) {
	body := templateBody(256, [][2]uint16{{27, 16}, {28, 16}, {1, 8}, {16, 4}})
	rec := make([]byte, 16+16+8+4)
	src16 := netip.MustParseAddr("2001:db8::1").As16()
	dst16 := netip.MustParseAddr("2001:db8::2").As16()
	copy(rec[0:16], src16[:])
	copy(rec[16:32], dst16[:])
	binary.BigEndian.PutUint64(rec[32:40], 99)
	binary.BigEndian.PutUint32(rec[40:44], 400000)
	pkt := append(header(2, 0, 1_700_000_000, 0, 1), flowSet(0, body)...)
	pkt = append(pkt, flowSet(256, rec)...)
	mapped := netip.MustParseAddr("::ffff:192.0.2.8")
	flows, _, _, err := Parse(datagram(pkt, mapped, time.Unix(1_700_000_000, 0).UTC()), mustCache(t), nil, nil, nil, false, 2*time.Hour, 5*time.Second)
	if err != nil || len(flows) != 1 {
		t.Fatal(err, len(flows))
	}
	f := flows[0]
	if f.Src.String() != "2001:db8::1" || f.Dst.String() != "2001:db8::2" || f.Octets != 99 {
		t.Fatal(f.Src, f.Dst, f.Octets)
	}
	if f.BGPSrcAS == nil || *f.BGPSrcAS != 400000 || f.Exporter != netip.MustParseAddr("192.0.2.8") {
		t.Fatal(f.BGPSrcAS, f.Exporter)
	}
	if f.Packets != 0 || f.Octets != 99 {
		t.Fatal(f.Packets, f.Octets)
	}
}

func header(count uint16, sysup, unixSecs, seq, source uint32) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], 9)
	binary.BigEndian.PutUint16(b[2:4], count)
	binary.BigEndian.PutUint32(b[4:8], sysup)
	binary.BigEndian.PutUint32(b[8:12], unixSecs)
	binary.BigEndian.PutUint32(b[12:16], seq)
	binary.BigEndian.PutUint32(b[16:20], source)
	return b
}

func flowSet(id uint16, body []byte) []byte {
	b := make([]byte, 4+len(body))
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[4:], body)
	return b
}

func optionsBody(id uint16, scopeLen, optLen int, fields [][2]uint16) []byte {
	b := make([]byte, 6+4*len(fields))
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], uint16(scopeLen))
	binary.BigEndian.PutUint16(b[4:6], uint16(optLen))
	for i, f := range fields {
		binary.BigEndian.PutUint16(b[6+4*i:8+4*i], f[0])
		binary.BigEndian.PutUint16(b[8+4*i:10+4*i], f[1])
	}
	return b
}

func mustCache(t *testing.T) *template.Cache {
	t.Helper()
	c, err := template.NewCache(64)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func templateBody(id uint16, fields [][2]uint16) []byte {
	b := make([]byte, 4+4*len(fields))
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(fields)))
	for i, f := range fields {
		binary.BigEndian.PutUint16(b[4+4*i:6+4*i], f[0])
		binary.BigEndian.PutUint16(b[6+4*i:8+4*i], f[1])
	}
	return b
}

func parseOne(t *testing.T, pkt []byte, templates *template.Cache, samples *sampling.Cache) ([]flow.Flow, flow.ExporterDelta, *template.Pending, error) {
	t.Helper()
	return Parse(datagram(pkt, netip.MustParseAddr("192.0.2.8"), time.Unix(1_700_000_000, 0).UTC()), templates, samples, sequence.NewTable(), obs.NewCounters(), false, 2*time.Hour, 5*time.Second)
}

func datagram(payload []byte, src netip.Addr, at time.Time) ingest.Datagram {
	return ingest.Datagram{Payload: payload, Src: src, ReceivedAt: at}
}

type fixture struct {
	ReceivedAt string         `json:"received_at"`
	MaxAge     string         `json:"max_age"`
	Skew       string         `json:"skew"`
	Exporter   string         `json:"exporter"`
	Packets    []packetExpect `json:"packets"`
}

type packetExpect struct {
	Counters map[string]uint64 `json:"counters"`
	Delta    deltaExpect       `json:"delta"`
	Flows    []flowExpect      `json:"flows"`
}

type deltaExpect struct {
	Version         uint16 `json:"version"`
	Domain          uint32 `json:"domain"`
	Packets         uint64 `json:"packets"`
	Flows           uint64 `json:"flows"`
	Malformed       uint64 `json:"malformed"`
	MissingTemplate uint64 `json:"missing_template"`
	GapFlows        uint64 `json:"gap_flows"`
	GapPackets      uint64 `json:"gap_packets"`
	GapRecords      uint64 `json:"gap_records"`
}

type flowExpect struct {
	Src               string  `json:"src"`
	Dst               string  `json:"dst"`
	NextHop           *string `json:"nexthop"`
	SrcPort           *uint16 `json:"src_port"`
	DstPort           *uint16 `json:"dst_port"`
	Proto             *uint8  `json:"proto"`
	TCPFlags          *uint8  `json:"tcp_flags"`
	TOS               *uint8  `json:"tos"`
	Packets           uint64  `json:"packets"`
	Octets            uint64  `json:"octets"`
	CounterSemantics  string  `json:"counter_semantics"`
	OctetSemantics    string  `json:"octet_semantics"`
	InputIf           *uint32 `json:"input_if"`
	OutputIf          *uint32 `json:"output_if"`
	BGPSrcAS          *uint32 `json:"bgp_src_as"`
	BGPDstAS          *uint32 `json:"bgp_dst_as"`
	SrcMask           *uint8  `json:"src_mask"`
	DstMask           *uint8  `json:"dst_mask"`
	Sampled           bool    `json:"sampled"`
	SamplingInterval  *uint32 `json:"sampling_interval"`
	SamplingAlgorithm *uint8  `json:"sampling_algorithm"`
	Domain            uint32  `json:"domain"`
	Version           uint16  `json:"version"`
	Start             string  `json:"start"`
	End               string  `json:"end"`
	Export            string  `json:"export"`
	TimeSource        string  `json:"time_source"`
	ClockClamped      bool    `json:"clock_clamped"`
}

func walk(t *testing.T, name string) (*template.Cache, *sampling.Cache, *obs.Counters, *sequence.Table) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var exp fixture
	if err := json.Unmarshal(raw, &exp); err != nil {
		t.Fatal(err)
	}
	pkts := readDatagrams(t, name+".bin")
	if len(pkts) != len(exp.Packets) {
		t.Fatalf("packets %d want %d", len(pkts), len(exp.Packets))
	}
	received := mustTime(t, exp.ReceivedAt)
	maxAge, err := time.ParseDuration(exp.MaxAge)
	if err != nil {
		t.Fatal(err)
	}
	skew, err := time.ParseDuration(exp.Skew)
	if err != nil {
		t.Fatal(err)
	}
	exporter := netip.MustParseAddr(exp.Exporter)
	templates := mustCache(t)
	samples := sampling.NewCache()
	counters := obs.NewCounters()
	seq := sequence.NewTable()
	names := map[string]obs.Name{
		"malformed":               obs.Malformed,
		"missing_template":        obs.MissingTemplate,
		"count_disagrees":         obs.CountDisagrees,
		"padding_nonzero":         obs.PaddingNonzero,
		"reserved_set":            obs.ReservedSet,
		"non_flow_records":        obs.NonFlowRecords,
		"sequence_gap_v9_packets": obs.SequenceGapV9Packets,
		"sequence_duplicate":      obs.SequenceDuplicate,
		"sequence_reorder":        obs.SequenceReorder,
		"sequence_reset":          obs.SequenceReset,
		"sequence_unresolved":     obs.SequenceUnresolved,
		"template_redefined":      obs.TemplateRedefined,
		"template_evicted":        obs.TemplateEvicted,
		"timestamp_skew":          obs.TimestampSkew,
		"timestamp_suspect":       obs.TimestampSuspect,
		"clock_clamped":           obs.ClockClamped,
	}
	for i, p := range pkts {
		flows, delta, _, err := Parse(datagram(p, exporter, received), templates, samples, seq, counters, false, maxAge, skew)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		want := exp.Packets[i]
		if delta.Version != want.Delta.Version || delta.Domain != want.Delta.Domain ||
			delta.Packets != want.Delta.Packets || delta.Flows != want.Delta.Flows ||
			delta.Malformed != want.Delta.Malformed || delta.MissingTemplate != want.Delta.MissingTemplate ||
			delta.GapFlows != want.Delta.GapFlows || delta.GapPackets != want.Delta.GapPackets ||
			delta.GapRecords != want.Delta.GapRecords || delta.Exporter != exporter || !delta.LastSeen.Equal(received) {
			t.Fatalf("packet %d delta %+v", i, delta)
		}
		snap := counters.Snapshot()
		for name, n := range want.Counters {
			id, ok := names[name]
			if !ok {
				t.Fatalf("unknown counter %s", name)
			}
			if snap[id] != n {
				t.Fatalf("packet %d %s = %d want %d", i, name, snap[id], n)
			}
		}
		if len(flows) != len(want.Flows) {
			t.Fatalf("packet %d flows %d want %d", i, len(flows), len(want.Flows))
		}
		for j, f := range flows {
			compareFlow(t, f, want.Flows[j], exporter, received)
		}
	}
	return templates, samples, counters, seq
}

func compareFlow(t *testing.T, f flow.Flow, want flowExpect, exporter netip.Addr, received time.Time) {
	t.Helper()
	if f.Src.String() != want.Src || f.Dst.String() != want.Dst {
		t.Fatalf("addr %s -> %s", f.Src, f.Dst)
	}
	if !hopEqual(f.NextHop, want.NextHop) {
		t.Fatalf("nexthop %v", f.NextHop)
	}
	if want.SrcPort == nil {
		if f.PortsPresent {
			t.Fatal("ports")
		}
	} else if !f.PortsPresent || f.SrcPort != *want.SrcPort || f.DstPort != *want.DstPort {
		t.Fatal("ports")
	}
	if !ptrU8Present(f.ProtoPresent, f.Proto, want.Proto) || !ptrU8Present(f.TCPFlagsPresent, f.TCPFlags, want.TCPFlags) || !ptrU8Present(f.TOSPresent, f.TOS, want.TOS) {
		t.Fatal("proto/flags/tos")
	}
	if f.Packets != want.Packets || f.Octets != want.Octets || f.CounterSemantics != want.CounterSemantics || f.OctetSemantics != want.OctetSemantics {
		t.Fatalf("counters pkts %d octets %d %s %s", f.Packets, f.Octets, f.CounterSemantics, f.OctetSemantics)
	}
	if !sameU32(f.InputIf, want.InputIf) || !sameU32(f.OutputIf, want.OutputIf) || !sameU32(f.BGPSrcAS, want.BGPSrcAS) || !sameU32(f.BGPDstAS, want.BGPDstAS) {
		t.Fatal("if/as")
	}
	if !sameU8(f.SrcMask, want.SrcMask) || !sameU8(f.DstMask, want.DstMask) {
		t.Fatal("masks")
	}
	if f.Sampled != want.Sampled || !sameU32(f.SamplingInterval, want.SamplingInterval) || !sameU8(f.SamplingAlgorithm, want.SamplingAlgorithm) {
		t.Fatalf("sampling %+v", f)
	}
	if f.Domain != want.Domain || f.Version != want.Version || f.Exporter != exporter || !f.ReceivedAt.Equal(received) {
		t.Fatal("identity")
	}
	if !f.Start.Equal(mustTime(t, want.Start)) || !f.End.Equal(mustTime(t, want.End)) || !f.ExportTime.Equal(mustTime(t, want.Export)) {
		t.Fatalf("times %s %s %s", f.Start, f.End, f.ExportTime)
	}
	if timeSource(f.TimeSource) != want.TimeSource || f.ClockClamped != want.ClockClamped {
		t.Fatal(timeSource(f.TimeSource), f.ClockClamped)
	}
	if f.OutPackets != nil || f.OutOctets != nil || f.FlowDirection != nil || f.SrcEnrich != (flow.Endpoint{}) || f.DstEnrich != (flow.Endpoint{}) {
		t.Fatal("extras")
	}
}

func hopEqual(a *netip.Addr, s *string) bool {
	if s == nil {
		return a == nil
	}
	return a != nil && a.String() == *s
}

func ptrU8Present(present bool, v uint8, want *uint8) bool {
	if want == nil {
		return !present
	}
	return present && v == *want
}

func sameU32(a, b *uint32) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func sameU8(a, b *uint8) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func timeSource(s flow.TimeSource) string {
	switch s {
	case flow.TimeSysUpTime:
		return "sysuptime"
	case flow.TimeAbsolute:
		return "absolute"
	case flow.TimeExport:
		return "export"
	case flow.TimeReceive:
		return "receive"
	default:
		return "unknown"
	}
}

func readDatagrams(t *testing.T, name string) [][]byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) >= 2 && binary.BigEndian.Uint16(b[:2]) == 9 {
		return [][]byte{b}
	}
	var out [][]byte
	for len(b) > 0 {
		if len(b) < 4 {
			t.Fatalf("truncated framing in %s", name)
		}
		n := binary.BigEndian.Uint32(b[:4])
		b = b[4:]
		if uint32(len(b)) < n || n == 0 {
			t.Fatalf("bad length %d in %s", n, name)
		}
		out = append(out, append([]byte(nil), b[:n]...))
		b = b[n:]
	}
	return out
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

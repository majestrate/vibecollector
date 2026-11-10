package ipfix

import (
	"bytes"
	"encoding/binary"
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

const (
	testAge  = 2 * time.Hour
	testSkew = 5 * time.Second
)

var (
	testSrc = netip.MustParseAddr("192.0.2.8")
	testAt  = time.Unix(1_700_000_000, 0).UTC()
)

func TestBasic(t *testing.T) {
	p := readDatagrams(t, "ipfix_basic.bin")[0]
	if len(p) < 16 || binary.BigEndian.Uint16(p[:2]) != 10 {
		t.Fatal("16-byte header")
	}
	if binary.BigEndian.Uint16(p[2:4]) != uint16(len(p)) || binary.BigEndian.Uint16(p[2:4]) <= 2 {
		t.Fatal("length is octets, not a record count", binary.BigEndian.Uint16(p[2:4]), len(p))
	}
	if binary.BigEndian.Uint32(p[12:16]) != 7 {
		t.Fatal("domain")
	}
	sets := walkSets(t, p)
	if len(sets) != 2 || sets[0].id != 2 || sets[0].n < 4 || sets[1].id != 256 {
		t.Fatalf("sets %+v", sets)
	}
	templates, _, seq, counters := newState(t)
	flows, delta, missing, err := parse(t, p, templates, nil, seq, counters, false, testAge, testSkew)
	if err != nil || missing != nil || len(flows) != 1 {
		t.Fatalf("flows %d missing %v err %v", len(flows), missing != nil, err)
	}
	f := flows[0]
	if f.Src.String() != "203.0.113.10" || f.Dst.String() != "198.51.100.20" || f.Packets != 42 || f.Octets != 1500 {
		t.Fatal(f.Src, f.Dst, f.Packets, f.Octets)
	}
	if !f.PortsPresent || f.SrcPort != 51515 || f.DstPort != 53 || !f.ProtoPresent || f.Proto != 17 {
		t.Fatal(f.SrcPort, f.DstPort, f.Proto)
	}
	if f.TimeSource != flow.TimeAbsolute || f.Sampled || f.CounterSemantics != "delta" || f.OctetSemantics != "ip" {
		t.Fatal(f.TimeSource, f.Sampled, f.CounterSemantics, f.OctetSemantics)
	}
	if !f.Start.Equal(time.UnixMilli(1_700_000_000_000)) || !f.End.Equal(time.UnixMilli(1_700_000_000_500)) || !f.ExportTime.Equal(testAt) {
		t.Fatal(f.Start, f.End, f.ExportTime)
	}
	if f.Version != 10 || f.Domain != 7 || delta.Version != 10 || delta.Domain != 7 || delta.Flows != 1 || delta.Malformed != 0 {
		t.Fatal(delta, f.Version, f.Domain)
	}
	snap := counters.Snapshot()
	if snap[obs.TimestampSuspect] != 0 || snap[obs.TimestampExportFallback] != 0 || snap[obs.ClockClamped] != 0 || snap[obs.Malformed] != 0 {
		t.Fatal(snap)
	}
	// Dispatch sees the registered parser. Nil caches skip those side effects.
	flows, delta, _, err = decode.Dispatch(datagram(p, testAt), templates, nil, nil, nil, false, testAge, testSkew)
	if err != nil || len(flows) != 1 || delta.Version != 10 || flows[0].Packets != 42 {
		t.Fatal(err, len(flows), delta)
	}
}

func TestVarlenEnterprise(t *testing.T) {
	p := readDatagrams(t, "ipfix_varlen_enterprise.bin")[0]
	if binary.BigEndian.Uint16(p[24:26]) != 0x83E7 || binary.BigEndian.Uint16(p[26:28]) != 65535 || binary.BigEndian.Uint32(p[28:32]) != 100 {
		t.Fatal("enterprise specifier")
	}
	if p[48] != 5 || string(p[49:54]) != "HELLO" {
		t.Fatal("1-octet prefix N=5")
	}
	templates, _, _, counters := newState(t)
	flows, _, _, err := parse(t, p, templates, nil, nil, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 1 {
		t.Fatal(err, len(flows))
	}
	tpl, ok := templates.Get(template.Key{Exporter: testSrc, Domain: 7, Version: 10, ID: 256})
	if !ok || tpl.Fields[0].Type != 999 || tpl.Fields[0].Enterprise != 100 || !tpl.Fields[0].Variable || tpl.Fields[0].Length != 65535 {
		t.Fatal(tpl, ok)
	}
	f := flows[0]
	if f.Packets != 7 || f.Octets != 0 || f.Src.String() != "203.0.113.10" || f.Dst.String() != "198.51.100.20" {
		t.Fatal(f.Packets, f.Octets, f.Src, f.Dst)
	}
	if counters.Snapshot()[obs.Malformed] != 0 {
		t.Fatal(counters.Snapshot())
	}
}

func TestPadding(t *testing.T) {
	p := readDatagrams(t, "ipfix_padding.bin")[0]
	sets := walkSets(t, p)
	if len(sets) != 2 || (sets[1].n-4)%12 == 0 {
		t.Fatalf("set length is a multiple of the record %+v", sets)
	}
	templates, _, _, counters := newState(t)
	flows, _, _, err := parse(t, p, templates, nil, nil, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 2 || flows[0].Packets != 1 || flows[1].Packets != 2 {
		t.Fatal(err, flows)
	}
	if counters.Snapshot()[obs.PaddingNonzero] != 1 || counters.Snapshot()[obs.Malformed] != 0 {
		t.Fatal(counters.Snapshot())
	}
}

func TestWithdrawOne(t *testing.T) {
	pkts := readDatagrams(t, "ipfix_withdraw_one.bin")
	if len(pkts) != 2 {
		t.Fatal(len(pkts))
	}
	body := walkSets(t, pkts[1])[0]
	if body.id != 2 || body.n != 8 || binary.BigEndian.Uint16(body.body[:2]) != 256 || binary.BigEndian.Uint16(body.body[2:4]) != 0 {
		t.Fatal("field count 0 is 4 bytes")
	}
	templates, _, _, counters := newState(t)
	flows, _, _, err := parse(t, pkts[0], templates, nil, nil, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 1 || flows[0].Packets != 9 || flows[0].TimeSource != flow.TimeExport {
		t.Fatal(err, flows)
	}
	key := template.Key{Exporter: testSrc, Domain: 7, Version: 10, ID: 256}
	if _, ok := templates.Get(key); !ok {
		t.Fatal("installed")
	}
	flows, delta, missing, err := parse(t, pkts[1], templates, nil, nil, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 0 || missing == nil || delta.MissingTemplate != 1 {
		t.Fatal(err, len(flows), missing != nil, delta)
	}
	if _, ok := templates.Get(key); ok {
		t.Fatal("withdrawn id still present")
	}
	snap := counters.Snapshot()
	if snap[obs.TemplatesWithdrawn] != 1 || snap[obs.WithdrawUnknown] != 0 || snap[obs.MissingTemplate] != 1 || snap[obs.Malformed] != 0 {
		t.Fatal(snap)
	}
}

func TestWithdrawAll(t *testing.T) {
	pkts := readDatagrams(t, "ipfix_withdraw_all.bin")
	if len(pkts) != 8 {
		t.Fatal(len(pkts))
	}
	if walkSets(t, pkts[1])[0].n != 8 || walkSets(t, pkts[2])[0].n != 8 {
		t.Fatal("figure U/V")
	}
	padU := walkSets(t, pkts[4])[0]
	padV := walkSets(t, pkts[5])[0]
	if padU.n != 10 || !bytes.Equal(padU.body[4:], []byte{0xAB, 0xCD}) || padV.n != 10 || !bytes.Equal(padV.body[4:], []byte{0x11, 0x22}) {
		t.Fatal("wildcard padding")
	}
	two := walkSets(t, pkts[7])[0].body
	if len(two) != 8 || binary.BigEndian.Uint16(two[2:4]) != 0 || binary.BigEndian.Uint16(two[6:8]) != 0 {
		t.Fatal("options withdrawal includes a scope count")
	}
	templates, _, _, counters := newState(t)
	parseAll := func(i int) {
		t.Helper()
		if _, _, _, err := parse(t, pkts[i], templates, nil, nil, counters, false, testAge, testSkew); err != nil {
			t.Fatal(i, err)
		}
	}
	data := func(id uint16) template.Key {
		return template.Key{Exporter: testSrc, Domain: 7, Version: 10, ID: id}
	}
	has := func(id uint16) bool {
		_, ok := templates.Get(data(id))
		return ok
	}
	parseAll(0)
	for _, id := range []uint16{256, 300, 257, 301} {
		if !has(id) {
			t.Fatal("missing", id)
		}
	}
	if tpl, ok := templates.Get(data(257)); !ok || tpl.ScopeN != 1 {
		t.Fatal(tpl, ok)
	}
	if tpl, _ := templates.Get(data(256)); tpl.ScopeN != 0 {
		t.Fatal(tpl.ScopeN)
	}
	parseAll(1)
	if has(256) || has(300) || !has(257) || !has(301) {
		t.Fatal("figure U removed options or left data")
	}
	if counters.Snapshot()[obs.TemplatesWithdrawn] != 2 || counters.Snapshot()[obs.WithdrawUnknown] != 0 {
		t.Fatal(counters.Snapshot())
	}
	// Withdrawing nothing is not an unknown id.
	parseAll(1)
	if counters.Snapshot()[obs.TemplatesWithdrawn] != 2 || counters.Snapshot()[obs.WithdrawUnknown] != 0 || counters.Snapshot()[obs.PaddingNonzero] != 0 {
		t.Fatal(counters.Snapshot())
	}
	parseAll(2)
	if has(257) || has(301) || counters.Snapshot()[obs.TemplatesWithdrawn] != 4 {
		t.Fatal("figure V", counters.Snapshot())
	}
	parseAll(3)
	parseAll(4)
	if has(256) || has(300) || !has(257) || counters.Snapshot()[obs.PaddingNonzero] != 1 || counters.Snapshot()[obs.TemplatesWithdrawn] != 6 {
		t.Fatal("padded all-data", counters.Snapshot(), has(256), has(257))
	}
	parseAll(5)
	if has(257) || has(301) || counters.Snapshot()[obs.PaddingNonzero] != 2 || counters.Snapshot()[obs.TemplatesWithdrawn] != 8 {
		t.Fatal("padded all-options", counters.Snapshot())
	}
	parseAll(6)
	if !has(257) || !has(301) {
		t.Fatal("reinstall options")
	}
	before := counters.Snapshot()[obs.TemplatesWithdrawn]
	parseAll(7)
	if has(257) || has(301) || counters.Snapshot()[obs.TemplatesWithdrawn] != before+2 {
		t.Fatal("one set must withdraw both ids", counters.Snapshot()[obs.TemplatesWithdrawn], before)
	}
	if counters.Snapshot()[obs.WithdrawUnknown] != 0 || counters.Snapshot()[obs.Malformed] != 0 || counters.Snapshot()[obs.TemplateRedefined] != 0 {
		t.Fatal(counters.Snapshot())
	}
}

func TestAbsoluteBeatsSysUp(t *testing.T) {
	p := readDatagrams(t, "ipfix_absolute.bin")[0]
	templates, _, _, counters := newState(t)
	flows, _, _, err := parse(t, p, templates, sampling.NewCache(), nil, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 1 {
		t.Fatal(err, len(flows))
	}
	f := flows[0]
	start := time.UnixMilli(1_700_000_000_100)
	end := time.UnixMilli(1_700_000_000_900)
	if f.TimeSource != flow.TimeAbsolute || !f.Start.Equal(start) || !f.End.Equal(end) || f.ClockClamped {
		t.Fatal(f.TimeSource, f.Start, f.End, f.ClockClamped)
	}
	if f.Start.Equal(time.UnixMilli(1_000_000_000_000 + 5000)) {
		t.Fatal("sysUpTime won")
	}
	snap := counters.Snapshot()
	if snap[obs.TimestampSuspect] != 0 || snap[obs.TimestampExportFallback] != 0 || snap[obs.NonFlowRecords] != 1 {
		t.Fatal(snap)
	}
	tpl, ok := templates.Get(template.Key{Exporter: testSrc, Domain: 7, Version: 10, ID: 400})
	if !ok || tpl.ScopeN != 1 {
		t.Fatal(tpl, ok)
	}
}

func TestNTP(t *testing.T) {
	p := readDatagrams(t, "ipfix_ntp.bin")[0]
	if !bytes.Contains(p, []byte{0xE8, 0xFE, 0x6F, 0x80, 0x00, 0x10, 0x07, 0xFF}) {
		t.Fatal("vector")
	}
	eraEnd := time.Unix(int64(1<<32)-ntpEpochOffset, 0).UTC()
	wantEnd := time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC)
	if !eraEnd.Equal(wantEnd) || eraEnd.Equal(time.Date(2036, 2, 8, 6, 28, 16, 0, time.UTC)) {
		t.Fatal(eraEnd)
	}
	from1900 := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(1<<32) * time.Second)
	if !from1900.Equal(wantEnd) {
		t.Fatal(from1900)
	}
	exact := time.Unix(0, 1_700_000_000_000_244_140).UTC()
	templates, _, _, counters := newState(t)
	flows, _, _, err := parse(t, p, templates, nil, nil, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 1 {
		t.Fatal(err, len(flows))
	}
	f := flows[0]
	if f.TimeSource != flow.TimeAbsolute || !f.Start.Equal(exact) || !f.End.Equal(exact) || f.ClockClamped {
		t.Fatal(f.TimeSource, f.Start, f.End, f.ClockClamped)
	}
	if counters.Snapshot()[obs.TimestampSuspect] != 0 || counters.Snapshot()[obs.ClockClamped] != 0 {
		t.Fatal(counters.Snapshot())
	}
	// A clock two days fast stays in era 0. The other era is 2^32 seconds away.
	late := exact.Add(48 * time.Hour)
	templates, _, _, counters = newState(t)
	flows, _, _, err = parseAt(t, p, templates, nil, nil, counters, late, false, 72*time.Hour, testSkew)
	if err != nil || len(flows) != 1 {
		t.Fatal(err, len(flows))
	}
	f = flows[0]
	step := time.Duration(1<<32) * time.Second
	if !f.Start.Equal(exact) || f.Start.Equal(exact.Add(step)) || f.Start.Equal(exact.Add(-step)) || f.ClockClamped {
		t.Fatal(f.Start, f.ClockClamped)
	}
}

func TestSequenceUnresolved(t *testing.T) {
	pkts := readDatagrams(t, "ipfix_sequence_unresolved.bin")
	templates, _, seq, counters := newState(t)
	prior := ipfixMsg(4, 5, setOf(2, templateBody(300, [][2]uint16{{8, 4}, {12, 4}, {2, 4}})), setOf(300, rec3(0x0a000001, 0x0a000002, 1)))
	if _, _, _, err := parse(t, prior, templates, nil, seq, counters, false, testAge, testSkew); err != nil {
		t.Fatal(err)
	}
	flows, delta, missing, err := parse(t, pkts[0], templates, nil, seq, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 0 || missing == nil || delta.MissingTemplate != 1 || delta.GapRecords != 0 {
		t.Fatal(err, len(flows), missing != nil, delta)
	}
	if counters.Snapshot()[obs.SequenceUnresolved] != 1 || counters.Snapshot()[obs.SequenceGapIPFIXRecords] != 0 {
		t.Fatal(counters.Snapshot())
	}
	// Still missing: do not count again, and keep the snapshot.
	if _, delta, _, err = parse(t, pkts[0], templates, nil, seq, counters, true, testAge, testSkew); err != nil || delta.MissingTemplate != 0 || delta.GapRecords != 0 {
		t.Fatal(err, delta)
	}
	if counters.Snapshot()[obs.SequenceUnresolved] != 1 || counters.Snapshot()[obs.MissingTemplate] != 1 {
		t.Fatal(counters.Snapshot())
	}
	if d := headerOnly(t, templates, seq, counters, 4, 6); d.GapRecords != 0 || counters.Snapshot()[obs.SequenceReorder] != 0 {
		t.Fatal("expected moved", d, counters.Snapshot())
	}
	_, _, err = templates.Put(template.Key{Exporter: testSrc, Domain: 4, Version: 10, ID: 256}, template.Template{
		Fields:   []template.Field{{Type: 8, Length: 4}, {Type: 12, Length: 4}, {Type: 2, Length: 4}},
		Received: testAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	flows, delta, missing, err = parse(t, pkts[0], templates, nil, seq, counters, true, testAge, testSkew)
	if err != nil || missing != nil || len(flows) != 1 || flows[0].Packets != 3 || flows[0].Src.String() != "10.0.0.1" {
		t.Fatal(err, len(flows), missing != nil, flows)
	}
	if delta.GapRecords != 4 || delta.GapPackets != 0 || delta.GapFlows != 0 {
		t.Fatal(delta)
	}
	snap := counters.Snapshot()
	if snap[obs.SequenceGapIPFIXRecords] != 4 || snap[obs.SequenceGapV5Flows] != 0 || snap[obs.SequenceGapV9Packets] != 0 || snap[obs.MissingTemplate] != 1 {
		t.Fatal(snap)
	}
	if _, delta, _, err = parse(t, pkts[0], templates, nil, seq, counters, true, testAge, testSkew); err != nil || delta.GapRecords != 0 {
		t.Fatal("gap applied twice", err, delta)
	}
	if counters.Snapshot()[obs.SequenceGapIPFIXRecords] != 4 {
		t.Fatal(counters.Snapshot())
	}
	if d := headerOnly(t, templates, seq, counters, 4, 11); d.GapRecords != 0 || counters.Snapshot()[obs.SequenceReorder] != 0 || counters.Snapshot()[obs.SequenceGapIPFIXRecords] != 4 {
		t.Fatal("count", d, counters.Snapshot())
	}
}

func TestSequenceRetrySkippedWhenCursorMoved(t *testing.T) {
	pkts := readDatagrams(t, "ipfix_sequence_unresolved.bin")
	templates, _, seq, counters := newState(t)
	prior := ipfixMsg(4, 5, setOf(2, templateBody(300, [][2]uint16{{8, 4}, {12, 4}, {2, 4}})), setOf(300, rec3(0x0a000001, 0x0a000002, 1)))
	if _, _, _, err := parse(t, prior, templates, nil, seq, counters, false, testAge, testSkew); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := parse(t, pkts[0], templates, nil, seq, counters, false, testAge, testSkew); err != nil {
		t.Fatal(err)
	}
	// seq 6 is still the saved expected, so this packet moves the cursor.
	next := ipfixMsg(4, 6, setOf(300, rec3(0x0a000001, 0x0a000002, 1)))
	if _, delta, _, err := parse(t, next, templates, nil, seq, counters, false, testAge, testSkew); err != nil || delta.GapRecords != 0 {
		t.Fatal(err, delta)
	}
	_, _, err := templates.Put(template.Key{Exporter: testSrc, Domain: 4, Version: 10, ID: 256}, template.Template{
		Fields:   []template.Field{{Type: 8, Length: 4}, {Type: 12, Length: 4}, {Type: 2, Length: 4}},
		Received: testAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, delta, _, err := parse(t, pkts[0], templates, nil, seq, counters, true, testAge, testSkew); err != nil || delta.GapRecords != 0 {
		t.Fatal(err, delta)
	}
	if _, delta, _, err := parse(t, pkts[0], templates, nil, seq, counters, true, testAge, testSkew); err != nil || delta.GapRecords != 0 {
		t.Fatal(err, delta)
	}
	if counters.Snapshot()[obs.SequenceGapIPFIXRecords] != 0 || counters.Snapshot()[obs.SequenceReorder] != 0 {
		t.Fatal(counters.Snapshot())
	}
	if d := headerOnly(t, templates, seq, counters, 4, 7); d.GapRecords != 0 || counters.Snapshot()[obs.SequenceReorder] != 0 {
		t.Fatal("cursor rewritten", d, counters.Snapshot())
	}
}

func TestOptionsDataAdvancesCursor(t *testing.T) {
	pkts := readDatagrams(t, "ipfix_sequence_unresolved.bin")
	templates, samples, seq, counters := newState(t)
	if _, _, _, err := parse(t, pkts[1], templates, samples, seq, counters, false, testAge, testSkew); err != nil {
		t.Fatal(err)
	}
	got, ok := samples.Lookup(testSrc, 7, []string{"device"})
	if !ok || got.N != 100 || !got.Sampled {
		t.Fatal(got, ok)
	}
	flows, delta, _, err := parse(t, pkts[2], templates, samples, seq, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 1 || flows[0].Packets != 4 {
		t.Fatal(err, flows)
	}
	if delta.GapRecords != 0 || counters.Snapshot()[obs.SequenceReorder] != 0 || counters.Snapshot()[obs.SequenceGapIPFIXRecords] != 0 {
		t.Fatal(delta, counters.Snapshot())
	}
	if !flows[0].Sampled || flows[0].SamplingInterval == nil || *flows[0].SamplingInterval != 100 || flows[0].Packets != 4 {
		t.Fatal(flows[0].Sampled, flows[0].SamplingInterval, flows[0].Packets)
	}
	if counters.Snapshot()[obs.NonFlowRecords] != 1 {
		t.Fatal(counters.Snapshot())
	}
}

func TestTemplateRecordsDoNotAdvance(t *testing.T) {
	templates, _, seq, counters := newState(t)
	pkt := ipfixMsg(3, 5, setOf(2, templateBody(256, [][2]uint16{{8, 4}, {12, 4}, {2, 4}})))
	if _, _, _, err := parse(t, pkt, templates, nil, seq, counters, false, testAge, testSkew); err != nil {
		t.Fatal(err)
	}
	// expected stayed at 5, so sequence 6 is one data record ahead.
	if d := headerOnly(t, templates, seq, counters, 3, 6); d.GapRecords != 1 {
		t.Fatal(d)
	}
	if counters.Snapshot()[obs.SequenceGapIPFIXRecords] != 1 || counters.Snapshot()[obs.SequenceGapV9Packets] != 0 {
		t.Fatal(counters.Snapshot())
	}
}

func TestRetryCountPrefix(t *testing.T) {
	t.Run("full", func(t *testing.T) {
		templates, seq, counters, pkt := prefixSetup(t)
		_, _, err := templates.Put(template.Key{Exporter: testSrc, Domain: 4, Version: 10, ID: 257}, threeFields())
		if err != nil {
			t.Fatal(err)
		}
		flows, delta, _, err := parse(t, pkt, templates, nil, seq, counters, true, testAge, testSkew)
		if err != nil || len(flows) != 2 || delta.GapRecords != 4 {
			t.Fatal(err, len(flows), delta)
		}
		if d := headerOnly(t, templates, seq, counters, 4, 7); d.GapRecords != 0 || counters.Snapshot()[obs.SequenceReorder] != 0 {
			t.Fatal("full reparse added the prefix twice", d, counters.Snapshot())
		}
	})
	t.Run("stripped", func(t *testing.T) {
		templates, seq, counters, pkt := prefixSetup(t)
		_, _, err := templates.Put(template.Key{Exporter: testSrc, Domain: 4, Version: 10, ID: 257}, threeFields())
		if err != nil {
			t.Fatal(err)
		}
		retryAt := 16 + len(setOf(256, rec3(0x0a000001, 0x0a000002, 1)))
		short := append(append([]byte{}, pkt[:16]...), pkt[retryAt:]...)
		binary.BigEndian.PutUint16(short[2:4], uint16(len(short)))
		flows, delta, _, err := parse(t, short, templates, nil, seq, counters, true, testAge, testSkew)
		if err != nil || len(flows) != 1 || flows[0].Packets != 2 || delta.GapRecords != 4 {
			t.Fatal(err, flows, delta)
		}
		if d := headerOnly(t, templates, seq, counters, 4, 7); d.GapRecords != 0 || counters.Snapshot()[obs.SequenceReorder] != 0 {
			t.Fatal("stripped replay dropped the prefix", d, counters.Snapshot())
		}
	})
}

func TestTwoMissingSetsOneUnresolved(t *testing.T) {
	templates, _, seq, counters := newState(t)
	pkt := ipfixMsg(8, 10, setOf(256, rec3(1, 2, 1)), setOf(257, rec3(1, 2, 2)))
	_, delta, missing, err := parse(t, pkt, templates, nil, seq, counters, false, testAge, testSkew)
	if err != nil || missing == nil || delta.MissingTemplate != 2 || delta.GapRecords != 0 {
		t.Fatal(err, delta)
	}
	if counters.Snapshot()[obs.SequenceUnresolved] != 1 || counters.Snapshot()[obs.MissingTemplate] != 2 {
		t.Fatal(counters.Snapshot())
	}
	if d := headerOnly(t, templates, seq, counters, 8, 10); d.GapRecords != 0 || counters.Snapshot()[obs.SequenceReorder] != 0 {
		t.Fatal("invented a count", d, counters.Snapshot())
	}
}

func TestSamples(t *testing.T) {
	u32 := func(v uint32) *uint32 { return &v }
	u64p := func(v uint64) *uint64 { return &v }
	cases := []struct {
		name     string
		octets   uint64
		packets  uint64
		sem      string
		octSem   string
		sampled  bool
		interval *uint32
		outOct   *uint64
	}{
		{"sample_delta_over_total.bin", 100, 4, "delta", "ip", false, nil, nil},
		{"sample_total_only.bin", 9999, 4, "total", "ip", false, nil, nil},
		{"sample_n34.bin", 10, 5, "delta", "ip", true, u32(100), nil},
		{"sample_n50.bin", 10, 5, "delta", "ip", true, u32(50), nil},
		{"sample_n305_306.bin", 10, 5, "delta", "ip", true, u32(100), nil},
		{"sample_bare_305.bin", 10, 5, "delta", "ip", false, nil, nil},
		{"sample_l4_231.bin", 40, 0, "delta", "l4_payload", false, nil, u64p(15)},
		{"sample_1_and_231.bin", 40, 2, "delta", "ip", false, nil, nil},
		{"sample_23_and_231.bin", 40, 3, "delta", "ip", false, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := readDatagrams(t, tc.name)[0]
			templates, _, _, _ := newState(t)
			flows, _, _, err := parse(t, p, templates, nil, nil, nil, false, testAge, testSkew)
			if err != nil || len(flows) != 1 {
				t.Fatal(err, len(flows))
			}
			f := flows[0]
			if f.Octets != tc.octets || f.Packets != tc.packets || f.CounterSemantics != tc.sem || f.OctetSemantics != tc.octSem || f.Sampled != tc.sampled {
				t.Fatalf("%s octets %d pkts %d %s %s sampled %v", tc.name, f.Octets, f.Packets, f.CounterSemantics, f.OctetSemantics, f.Sampled)
			}
			if f.Src.String() != "203.0.113.1" || f.Dst.String() != "203.0.113.2" {
				t.Fatal(f.Src, f.Dst)
			}
			if (tc.interval == nil) != (f.SamplingInterval == nil) || (tc.interval != nil && *tc.interval != *f.SamplingInterval) {
				t.Fatal(f.SamplingInterval)
			}
			if (tc.outOct == nil) != (f.OutOctets == nil) || (tc.outOct != nil && *tc.outOct != *f.OutOctets) {
				t.Fatal(f.OutOctets)
			}
			if f.OutPackets != nil {
				t.Fatal(f.OutPackets)
			}
			if f.Packets == tc.octets*100 || (tc.interval != nil && f.Octets == tc.octets*uint64(*tc.interval)) {
				t.Fatal("multiplied by N")
			}
		})
	}
}

func TestIntervalDoesNotHideLater(t *testing.T) {
	templates, samples, _, counters := newState(t)
	pkt := flowPkt(7, [][2]uint16{{8, 4}, {12, 4}, {1, 4}, {2, 4}, {34, 4}, {50, 4}}, append(addrs(), append(be32(10), append(be32(4), append(be32(0), be32(50)...)...)...)...))
	flows, _, _, err := parse(t, pkt, templates, samples, nil, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 1 || !flows[0].Sampled || flows[0].SamplingInterval == nil || *flows[0].SamplingInterval != 50 || flows[0].Packets != 4 {
		t.Fatal(err, flows)
	}
	samples.Put(sampling.SampleKey{Exporter: testSrc, Domain: 7, Scope: "if:7"}, sampling.Sample{N: 80, Sampled: true})
	pkt = flowPkt(7, [][2]uint16{{8, 4}, {12, 4}, {1, 4}, {2, 4}, {10, 4}, {34, 4}}, append(addrs(), append(be32(10), append(be32(4), append(be32(7), be32(1)...)...)...)...))
	flows, _, _, err = parse(t, pkt, templates, samples, nil, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 1 || flows[0].SamplingInterval == nil || *flows[0].SamplingInterval != 80 || flows[0].Packets != 4 || flows[0].Octets != 10 {
		t.Fatal(err, flows)
	}
}

func TestSelectorAlgorithm(t *testing.T) {
	cases := []struct {
		fields [][2]uint16
		tail   []byte
		want   uint8
	}{
		{[][2]uint16{{8, 4}, {12, 4}, {2, 4}, {304, 1}}, []byte{3}, 3},
		{[][2]uint16{{8, 4}, {12, 4}, {2, 4}, {35, 1}, {304, 1}}, []byte{1, 9}, 1},
		{[][2]uint16{{8, 4}, {12, 4}, {2, 4}, {49, 1}, {304, 1}}, []byte{2, 9}, 2},
		{[][2]uint16{{8, 4}, {12, 4}, {2, 4}, {35, 1}, {49, 1}}, []byte{1, 2}, 1},
	}
	for i, tc := range cases {
		templates, _, _, _ := newState(t)
		body := append(addrs(), be32(1)...)
		body = append(body, tc.tail...)
		flows, _, _, err := parse(t, flowPkt(7, tc.fields, body), templates, nil, nil, nil, false, testAge, testSkew)
		if err != nil || len(flows) != 1 || flows[0].SamplingAlgorithm == nil || *flows[0].SamplingAlgorithm != tc.want || flows[0].Sampled {
			t.Fatal(i, err, flows)
		}
	}
}

func TestReducedSizeAndLongVarlen(t *testing.T) {
	templates, _, _, _ := newState(t)
	body := append(addrs(), []byte{0x01, 0x02, 0x03}...)
	body = append(body, be32(4)...)
	flows, _, _, err := parse(t, flowPkt(7, [][2]uint16{{8, 4}, {12, 4}, {1, 3}, {2, 4}}, body), templates, nil, nil, nil, false, testAge, testSkew)
	if err != nil || len(flows) != 1 || flows[0].Octets != 66051 || flows[0].Packets != 4 {
		t.Fatal(err, flows)
	}
	templates, _, _, _ = newState(t)
	body = append(addrs(), []byte{0xFF, 0x00, 0x04, 'A', 'B', 'C', 'D'}...)
	body = append(body, be32(7)...)
	flows, _, _, err = parse(t, flowPkt(7, [][2]uint16{{8, 4}, {12, 4}, {400, 65535}, {2, 4}}, body), templates, nil, nil, nil, false, testAge, testSkew)
	if err != nil || len(flows) != 1 || flows[0].Packets != 7 || flows[0].Src.String() != "203.0.113.1" {
		t.Fatal(err, flows)
	}
}

func TestNanosecondsNoMask(t *testing.T) {
	templates, _, _, _ := newState(t)
	ntp := []byte{0xE8, 0xFE, 0x6F, 0x80, 0x00, 0x10, 0x07, 0xFF}
	body := append(addrs(), append(append([]byte{}, ntp...), ntp...)...)
	flows, _, _, err := parse(t, flowPkt(7, [][2]uint16{{8, 4}, {12, 4}, {156, 8}, {157, 8}}, body), templates, nil, nil, nil, false, testAge, testSkew)
	if err != nil || len(flows) != 1 {
		t.Fatal(err, len(flows))
	}
	want := time.Unix(0, 1_700_000_000_000_244_617).UTC()
	masked := time.Unix(0, 1_700_000_000_000_244_140).UTC()
	if flows[0].TimeSource != flow.TimeAbsolute || !flows[0].Start.Equal(want) || flows[0].Start.Equal(masked) {
		t.Fatal(flows[0].Start)
	}
}

func TestSysUpBoot(t *testing.T) {
	exportMs := testAt.UnixMilli()
	switched := uint32(5000)
	init := uint64(exportMs + 1000 - int64(switched) - (1 << 32))
	templates, _, _, counters := newState(t)
	flows, _, _, err := parse(t, bootFlow(1, init, false, switched), templates, sampling.NewCache(), nil, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 1 {
		t.Fatal(err, len(flows))
	}
	f := flows[0]
	if f.TimeSource != flow.TimeSysUpTime || !f.End.Equal(time.UnixMilli(exportMs+1000)) || !f.Start.Equal(testAt) || f.ClockClamped {
		t.Fatal(f.TimeSource, f.Start, f.End, f.ClockClamped)
	}
	if f.Start.Equal(time.UnixMilli(1_699_999_996_000)) {
		t.Fatal("missing start used switched 0")
	}
	if counters.Snapshot()[obs.TimestampSuspect] != 0 || counters.Snapshot()[obs.TimestampExportFallback] != 0 {
		t.Fatal(counters.Snapshot())
	}

	// Missing end is export time and does not trade places with the real start.
	templates, _, _, counters = newState(t)
	init2 := uint64(exportMs - 10_000)
	flows, _, _, err = parse(t, bootFlow(2, init2, true, 13_000), templates, sampling.NewCache(), nil, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 1 {
		t.Fatal(err, len(flows))
	}
	f = flows[0]
	if !f.Start.Equal(testAt.Add(3*time.Second)) || !f.End.Equal(testAt) || f.ClockClamped || counters.Snapshot()[obs.TimestampSuspect] != 0 {
		t.Fatal(f.Start, f.End, f.ClockClamped, counters.Snapshot()[obs.TimestampSuspect])
	}

	// 3h is outside timestamp_max_age, so the endpoint falls back to export time.
	templates, _, _, counters = newState(t)
	flows, _, _, err = parse(t, bootFlow(3, uint64(exportMs), false, 3*3600*1000), templates, nil, nil, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 1 || !flows[0].End.Equal(testAt) || counters.Snapshot()[obs.TimestampSuspect] != 1 {
		t.Fatal(err, flows, counters.Snapshot())
	}

	// Both n=0 and n=1 sit inside a 60-day window. The closer one wins.
	templates, _, _, _ = newState(t)
	init = uint64(exportMs + 1000 - (1 << 32))
	flows, _, _, err = parse(t, bootFlow(4, init, false, 0), templates, nil, nil, nil, false, 60*24*time.Hour, testSkew)
	if err != nil || len(flows) != 1 || !flows[0].End.Equal(time.UnixMilli(exportMs+1000)) {
		t.Fatal(err, flows)
	}
}

func TestClampUsesSkew(t *testing.T) {
	templates, _, _, counters := newState(t)
	body := append(addrs(), append(be64(uint64(testAt.Add(time.Second).UnixMilli())), be64(uint64(testAt.Add(time.Second).UnixMilli()))...)...)
	flows, _, _, err := parseAt(t, flowPkt(7, [][2]uint16{{8, 4}, {12, 4}, {152, 8}, {153, 8}}, body), templates, nil, nil, counters, testAt, false, 0, 0)
	if err != nil || len(flows) != 1 || !flows[0].ClockClamped || !flows[0].End.Equal(testAt) {
		t.Fatal(err, flows)
	}
	// n is chosen against export time. Skew is only the future clamp edge.
	templates, _, _, counters = newState(t)
	received := testAt.Add(-time.Hour)
	flows, _, _, err = parseAt(t, bootFlow(9, uint64(testAt.UnixMilli()), false, 0), templates, nil, nil, counters, received, false, testAge, testSkew)
	if err != nil || len(flows) != 1 || !flows[0].ClockClamped || !flows[0].End.Equal(received.Add(testSkew)) {
		t.Fatal(err, flows)
	}
	templates, _, _, counters = newState(t)
	received = testAt.Add(3 * time.Hour)
	flows, _, _, err = parseAt(t, bootFlow(10, uint64(testAt.UnixMilli()), false, 0), templates, nil, nil, counters, received, false, testAge, testSkew)
	if err != nil || len(flows) != 1 || !flows[0].ClockClamped || !flows[0].End.Equal(received.Add(-testAge)) {
		t.Fatal(err, flows)
	}
}

func TestNoBootMeansExport(t *testing.T) {
	templates, _, _, counters := newState(t)
	body := append(addrs(), append(be32(5000), be32(9000)...)...)
	flows, _, _, err := parse(t, flowPkt(7, [][2]uint16{{8, 4}, {12, 4}, {22, 4}, {21, 4}}, body), templates, nil, nil, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 1 {
		t.Fatal(err, len(flows))
	}
	f := flows[0]
	if f.TimeSource != flow.TimeExport || !f.Start.Equal(testAt) || !f.End.Equal(testAt) || counters.Snapshot()[obs.TimestampExportFallback] != 1 || counters.Snapshot()[obs.TimestampSuspect] != 0 {
		t.Fatal(f.TimeSource, f.Start, f.End, counters.Snapshot())
	}
}

func TestReservedShortAndTrailing(t *testing.T) {
	templates, _, seq, counters := newState(t)
	fields := templateBody(256, [][2]uint16{{8, 4}, {12, 4}, {2, 4}})
	rec := rec3(0xCB00710A, 0xC6336414, 11)
	pkt := ipfixMsg(7, 0,
		setOf(2, fields),
		setOf(0, []byte{0, 0, 0, 0}),
		setOf(1, []byte{0, 0, 0, 0}),
		setOf(4, []byte{1, 2, 3, 4}),
		setOf(255, []byte{9, 9, 9, 9}),
		setOf(256, rec),
	)
	flows, _, _, err := parse(t, pkt, templates, nil, seq, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 1 || flows[0].Packets != 11 || counters.Snapshot()[obs.ReservedSet] != 4 || counters.Snapshot()[obs.Malformed] != 0 {
		t.Fatal(err, len(flows), counters.Snapshot())
	}
	// Bytes after the length field are not a set.
	extra := append(append([]byte{}, pkt...), 0x00, 0x01, 0x00, 0x64)
	flows, _, _, err = parse(t, extra, templates, nil, seq, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 1 || counters.Snapshot()[obs.Malformed] != 0 {
		t.Fatal(err, counters.Snapshot())
	}
	tail := append(append([]byte{}, pkt...), 0xAB, 0xCD, 0xEF)
	binary.BigEndian.PutUint16(tail[2:4], uint16(len(tail)))
	if _, _, _, err = parse(t, tail, templates, nil, seq, counters, false, testAge, testSkew); err != nil || counters.Snapshot()[obs.PaddingNonzero] != 0 || counters.Snapshot()[obs.Malformed] != 0 {
		t.Fatal(err, counters.Snapshot())
	}
	short := append(pkt, []byte{0x01, 0x00, 0x00, 0x64}...)
	binary.BigEndian.PutUint16(short[2:4], uint16(len(short)))
	binary.BigEndian.PutUint32(short[8:12], 1)
	flows, delta, _, err := parse(t, short, templates, nil, seq, counters, false, testAge, testSkew)
	if !errors.Is(err, decode.ErrShortSet) || len(flows) != 1 || flows[0].Packets != 11 || delta.Malformed != 1 {
		t.Fatal(err, len(flows), delta)
	}
	if d := headerOnly(t, templates, seq, counters, 7, 2); d.GapRecords != 0 || counters.Snapshot()[obs.SequenceReorder] != 0 {
		t.Fatal("short set skipped the cursor", d, counters.Snapshot())
	}
	bad := append([]byte{}, pkt...)
	binary.BigEndian.PutUint16(bad[2:4], uint16(len(bad)+10))
	_, delta, _, err = parse(t, bad, templates, nil, nil, counters, false, testAge, testSkew)
	if !errors.Is(err, decode.ErrMalformed) || delta.Version != 10 || delta.Domain != 7 || delta.Malformed != 1 {
		t.Fatal(err, delta)
	}
	tiny := append([]byte{}, pkt...)
	binary.BigEndian.PutUint16(tiny[2:4], 10)
	_, delta, _, err = parse(t, tiny, templates, nil, nil, counters, false, testAge, testSkew)
	if !errors.Is(err, decode.ErrMalformed) || delta.Version != 10 || delta.Domain != 7 {
		t.Fatal(err, delta)
	}
	_, delta, _, err = parse(t, []byte{0x00, 0x0a}, templates, nil, nil, counters, false, testAge, testSkew)
	if !errors.Is(err, decode.ErrMalformed) || delta.Version != 10 || delta.Domain != 0 || delta.Malformed != 1 {
		t.Fatal(err, delta)
	}
}

func TestRedefineAndUnknown(t *testing.T) {
	templates, _, _, counters := newState(t)
	first := ipfixMsg(7, 0, setOf(2, templateBody(256, [][2]uint16{{8, 4}, {12, 4}})))
	if _, _, _, err := parse(t, first, templates, nil, nil, counters, false, testAge, testSkew); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := parse(t, first, templates, nil, nil, counters, false, testAge, testSkew); err != nil {
		t.Fatal(err)
	}
	if counters.Snapshot()[obs.TemplateRedefined] != 0 {
		t.Fatal("identical retransmission")
	}
	changed := ipfixMsg(7, 1, setOf(2, templateBody(256, [][2]uint16{{8, 4}, {12, 4}, {2, 4}})), setOf(256, rec3(0x0a000001, 0x0a000002, 9)))
	flows, _, _, err := parse(t, changed, templates, nil, nil, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 1 || flows[0].Packets != 9 || counters.Snapshot()[obs.TemplateRedefined] != 1 {
		t.Fatal(err, flows, counters.Snapshot())
	}
	// Withdrawal removes the key, so the later definition is an insert and stays.
	wd := append(be16(256), be16(0)...)
	later := templateBody(256, [][2]uint16{{8, 4}, {12, 4}, {1, 4}})
	pkt := ipfixMsg(7, 2, setOf(2, wd), setOf(2, later), setOf(256, append(rec3(0x0a000001, 0x0a000002, 0)[:8], be32(15)...)))
	flows, _, _, err = parse(t, pkt, templates, nil, nil, counters, false, testAge, testSkew)
	if err != nil || len(flows) != 1 || flows[0].Octets != 15 || counters.Snapshot()[obs.TemplateRedefined] != 1 || counters.Snapshot()[obs.TemplatesWithdrawn] != 1 {
		t.Fatal(err, flows, counters.Snapshot())
	}
	tpl, ok := templates.Get(template.Key{Exporter: testSrc, Domain: 7, Version: 10, ID: 256})
	if !ok || len(tpl.Fields) != 3 || tpl.Fields[2].Type != 1 {
		t.Fatal(tpl, ok)
	}
	unknown := ipfixMsg(7, 3, setOf(2, append(be16(399), be16(0)...)))
	if _, delta, _, err := parse(t, unknown, templates, nil, nil, counters, false, testAge, testSkew); err != nil || delta.Malformed != 0 {
		t.Fatal(err, delta)
	}
	if counters.Snapshot()[obs.WithdrawUnknown] != 1 || counters.Snapshot()[obs.TemplatesWithdrawn] != 1 || counters.Snapshot()[obs.Malformed] != 0 {
		t.Fatal(counters.Snapshot())
	}
}

func TestSizedRetryDoesNotObserveAgain(t *testing.T) {
	p := readDatagrams(t, "ipfix_basic.bin")[0]
	templates, _, seq, counters := newState(t)
	if _, _, _, err := parse(t, p, templates, nil, seq, counters, false, testAge, testSkew); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := parse(t, p, templates, nil, seq, counters, true, testAge, testSkew); err != nil {
		t.Fatal(err)
	}
	if counters.Snapshot()[obs.SequenceDuplicate] != 0 || counters.Snapshot()[obs.SequenceGapIPFIXRecords] != 0 {
		t.Fatal(counters.Snapshot())
	}
	if d := headerOnly(t, templates, seq, counters, 7, 1); d.GapRecords != 0 || counters.Snapshot()[obs.SequenceReorder] != 0 {
		t.Fatal(d, counters.Snapshot())
	}
}

func prefixSetup(t *testing.T) (*template.Cache, *sequence.Table, *obs.Counters, []byte) {
	t.Helper()
	templates, _, seq, counters := newState(t)
	prior := ipfixMsg(4, 0, setOf(2, templateBody(256, [][2]uint16{{8, 4}, {12, 4}, {2, 4}})), setOf(256, rec3(0x0a000001, 0x0a000002, 1)))
	if _, _, _, err := parse(t, prior, templates, nil, seq, counters, false, testAge, testSkew); err != nil {
		t.Fatal(err)
	}
	pkt := ipfixMsg(4, 5, setOf(256, rec3(0x0a000001, 0x0a000002, 1)), setOf(257, rec3(0x0a000001, 0x0a000002, 2)))
	flows, _, missing, err := parse(t, pkt, templates, nil, seq, counters, false, testAge, testSkew)
	if err != nil || missing == nil || len(flows) != 1 || flows[0].Packets != 1 || counters.Snapshot()[obs.SequenceUnresolved] != 1 {
		t.Fatal(err, missing != nil, flows, counters.Snapshot())
	}
	return templates, seq, counters, pkt
}

func bootFlow(domain uint32, init uint64, start bool, switched uint32) []byte {
	opt := optBody(400, 1, [][2]uint16{{1, 2}, {160, 8}})
	orec := append(be16(1), be64(init)...)
	var fields [][2]uint16
	var rec []byte
	if start {
		fields = [][2]uint16{{8, 4}, {12, 4}, {22, 4}}
		rec = append(addrs(), be32(switched)...)
	} else {
		fields = [][2]uint16{{8, 4}, {12, 4}, {21, 4}}
		rec = append(addrs(), be32(switched)...)
	}
	return ipfixMsg(domain, 0, setOf(3, opt), setOf(2, templateBody(256, fields)), setOf(400, orec), setOf(256, rec))
}

func flowPkt(domain uint32, fields [][2]uint16, rec []byte) []byte {
	return ipfixMsg(domain, 0, setOf(2, templateBody(256, fields)), setOf(256, rec))
}

func threeFields() template.Template {
	return template.Template{
		Fields:   []template.Field{{Type: 8, Length: 4}, {Type: 12, Length: 4}, {Type: 2, Length: 4}},
		Received: testAt,
	}
}

func headerOnly(t *testing.T, templates *template.Cache, seq *sequence.Table, counters *obs.Counters, domain, seqn uint32) flow.ExporterDelta {
	t.Helper()
	_, delta, missing, err := parse(t, ipfixMsg(domain, seqn), templates, nil, seq, counters, false, testAge, testSkew)
	if err != nil || missing != nil {
		t.Fatal(err, missing != nil)
	}
	return delta
}

func newState(t *testing.T) (*template.Cache, *sampling.Cache, *sequence.Table, *obs.Counters) {
	t.Helper()
	resetState()
	c, err := template.NewCache(64)
	if err != nil {
		t.Fatal(err)
	}
	return c, sampling.NewCache(), sequence.NewTable(), obs.NewCounters()
}

func parse(t *testing.T, pkt []byte, templates *template.Cache, samples *sampling.Cache, seq *sequence.Table, counters *obs.Counters, retry bool, maxAge, skew time.Duration) ([]flow.Flow, flow.ExporterDelta, *template.Pending, error) {
	t.Helper()
	return parseAt(t, pkt, templates, samples, seq, counters, testAt, retry, maxAge, skew)
}

func parseAt(t *testing.T, pkt []byte, templates *template.Cache, samples *sampling.Cache, seq *sequence.Table, counters *obs.Counters, at time.Time, retry bool, maxAge, skew time.Duration) ([]flow.Flow, flow.ExporterDelta, *template.Pending, error) {
	t.Helper()
	return Parse(datagram(pkt, at), templates, samples, seq, counters, retry, maxAge, skew)
}

func datagram(payload []byte, at time.Time) ingest.Datagram {
	return ingest.Datagram{Payload: payload, Src: testSrc, ReceivedAt: at}
}

func ipfixMsg(domain, seq uint32, parts ...[]byte) []byte {
	body := bytes.Join(parts, nil)
	b := make([]byte, 16+len(body))
	binary.BigEndian.PutUint16(b[0:2], 10)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint32(b[4:8], 1_700_000_000)
	binary.BigEndian.PutUint32(b[8:12], seq)
	binary.BigEndian.PutUint32(b[12:16], domain)
	copy(b[16:], body)
	return b
}

func setOf(id uint16, body []byte) []byte {
	b := make([]byte, 4+len(body))
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[4:], body)
	return b
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

func optBody(id, scope uint16, fields [][2]uint16) []byte {
	b := make([]byte, 6+4*len(fields))
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(fields)))
	binary.BigEndian.PutUint16(b[4:6], scope)
	for i, f := range fields {
		binary.BigEndian.PutUint16(b[6+4*i:8+4*i], f[0])
		binary.BigEndian.PutUint16(b[8+4*i:10+4*i], f[1])
	}
	return b
}

func rec3(a, b, pkts uint32) []byte {
	r := make([]byte, 12)
	binary.BigEndian.PutUint32(r[0:4], a)
	binary.BigEndian.PutUint32(r[4:8], b)
	binary.BigEndian.PutUint32(r[8:12], pkts)
	return r
}

func addrs() []byte {
	return rec3(0xCB007101, 0xCB007102, 0)[:8]
}

func be16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func be32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func be64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

type setView struct {
	id   uint16
	n    int
	body []byte
}

func walkSets(t *testing.T, p []byte) []setView {
	t.Helper()
	if len(p) < 16 {
		t.Fatal("short")
	}
	n := int(binary.BigEndian.Uint16(p[2:4]))
	var out []setView
	for off := 16; off+4 <= n && off+4 <= len(p); {
		id := binary.BigEndian.Uint16(p[off : off+2])
		sl := int(binary.BigEndian.Uint16(p[off+2 : off+4]))
		if sl < 4 || off+sl > n || off+sl > len(p) {
			t.Fatalf("set at %d len %d", off, sl)
		}
		out = append(out, setView{id: id, n: sl, body: p[off+4 : off+sl]})
		off += sl
	}
	return out
}

func readDatagrams(t *testing.T, name string) [][]byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) >= 2 && binary.BigEndian.Uint16(b[:2]) == 10 {
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

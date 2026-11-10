package v5

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
	"vibecollector/internal/sequence"
)

// Fixtures under ../testdata are hand-built from the v5 layout.
// They are not a re-encode of Parse.

func TestFixtures(t *testing.T) {
	for _, name := range []string{
		"v5_basic",
		"v5_sampling",
		"v5_sequence",
		"v5_reorder",
		"v5_wrap",
		"v5_skew",
	} {
		t.Run(name, func(t *testing.T) {
			raw := readFixture(t, name+".bin")
			var exp fixture
			mustJSON(t, readFixture(t, name+".json"), &exp)
			compareFixture(t, raw, exp)
		})
	}
}

func TestFixtureShapes(t *testing.T) {
	basic := readFixture(t, "v5_basic.bin")
	if len(basic) != 24+48+4 {
		t.Fatalf("basic length %d", len(basic))
	}
	if got := basic[len(basic)-4:]; string(got) != "\xde\xad\xbe\xef" {
		t.Fatalf("trailing %x", got)
	}
	if binary.BigEndian.Uint16(basic[0:2]) != 5 || binary.BigEndian.Uint16(basic[2:4]) != 1 {
		t.Fatal("basic header")
	}
	rec := basic[24:72]
	if binary.BigEndian.Uint32(rec[0:4]) != 0xcb00710a || binary.BigEndian.Uint32(rec[4:8]) != 0xc6336414 {
		t.Fatalf("src/dst %x %x", rec[0:4], rec[4:8])
	}
	if binary.BigEndian.Uint32(rec[16:20]) != 42 || binary.BigEndian.Uint32(rec[20:24]) != 1500 {
		t.Fatal("basic counters")
	}
	if binary.BigEndian.Uint16(rec[32:34]) != 51515 || binary.BigEndian.Uint16(rec[34:36]) != 53 {
		t.Fatal("basic ports")
	}
	if rec[37] != 2 || rec[38] != 17 || rec[39] != 46 {
		t.Fatal("basic flags/proto/tos")
	}
	if binary.BigEndian.Uint16(rec[40:42]) != 64496 || binary.BigEndian.Uint16(rec[42:44]) != 15169 {
		t.Fatal("basic as")
	}

	sampling := packets(t, readFixture(t, "v5_sampling.bin"))
	if len(sampling) != 3 {
		t.Fatalf("sampling packets %d", len(sampling))
	}
	words := []uint16{0x8000, 0x4001, 0xC064}
	counts := []uint16{1, 1, 2}
	for i, p := range sampling {
		word := binary.BigEndian.Uint16(p[22:24])
		if word != words[i] || binary.BigEndian.Uint16(p[2:4]) != counts[i] {
			t.Fatalf("packet %d word %04x count %d", i, word, binary.BigEndian.Uint16(p[2:4]))
		}
		mode, interval := word>>14, word&0x3FFF
		switch i {
		case 0:
			if mode != 2 || interval != 0 {
				t.Fatalf("mode %d interval %d", mode, interval)
			}
		case 1:
			if mode != 1 || interval != 1 {
				t.Fatalf("mode %d interval %d", mode, interval)
			}
		case 2:
			if mode != 3 || interval != 100 {
				t.Fatalf("mode %d interval %d", mode, interval)
			}
		}
	}

	seqPkts := packets(t, readFixture(t, "v5_sequence.bin"))
	if len(seqPkts) != 2 {
		t.Fatal(len(seqPkts))
	}
	s0 := binary.BigEndian.Uint32(seqPkts[0][16:20])
	c0 := binary.BigEndian.Uint16(seqPkts[0][2:4])
	s1 := binary.BigEndian.Uint32(seqPkts[1][16:20])
	if c0 != 1 || s1-(s0+uint32(c0)) != 5 {
		t.Fatalf("sequence skip s0 %d c0 %d s1 %d", s0, c0, s1)
	}

	re := packets(t, readFixture(t, "v5_reorder.bin"))
	want := [][2]uint32{{1000, 2}, {1001, 4}, {1002, 1}, {1002, 3}, {1003, 1}}
	if len(re) != len(want) {
		t.Fatalf("reorder packets %d", len(re))
	}
	for i, p := range re {
		seq := binary.BigEndian.Uint32(p[16:20])
		count := uint32(binary.BigEndian.Uint16(p[2:4]))
		if seq != want[i][0] || count != want[i][1] {
			t.Fatalf("reorder %d seq %d count %d", i, seq, count)
		}
	}

	wrap := readFixture(t, "v5_wrap.bin")
	sys := binary.BigEndian.Uint32(wrap[4:8])
	first := binary.BigEndian.Uint32(wrap[48:52])
	if sys != 100 {
		t.Fatalf("sysUpTime %d", sys)
	}
	if first < 0xFFFF0000 {
		t.Fatalf("first %d is not near 2^32", first)
	}
	if back := uint32(sys - first); back != 2500 {
		t.Fatalf("wrap age %d", back)
	}
	if time.Duration(first-sys)*time.Millisecond <= 5*time.Second {
		t.Fatal("wrap fixture would take the slack branch")
	}

	skew := readFixture(t, "v5_skew.bin")
	sys = binary.BigEndian.Uint32(skew[4:8])
	first = binary.BigEndian.Uint32(skew[48:52])
	if first-sys != 500 {
		t.Fatalf("skew ahead %d", first-sys)
	}
}

func TestWrapAndSkewResults(t *testing.T) {
	export := time.Unix(1_700_000_000, 0).UTC()
	counters := obs.NewCounters()
	flows, _, err := Parse(datagram(readFixture(t, "v5_wrap.bin"), export), sequence.NewTable(), counters, 2*time.Hour, 5*time.Second)
	if err != nil || len(flows) != 1 {
		t.Fatalf("wrap err %v flows %d", err, len(flows))
	}
	if !flows[0].Start.Equal(export.Add(-2500*time.Millisecond)) || !flows[0].End.Equal(export.Add(-500*time.Millisecond)) {
		t.Fatalf("wrap start %s end %s", flows[0].Start, flows[0].End)
	}
	if flows[0].TimeSource != flow.TimeSysUpTime || flows[0].ClockClamped {
		t.Fatalf("wrap source %+v", flows[0])
	}
	snap := counters.Snapshot()
	if snap[obs.TimestampSkew] != 0 || snap[obs.TimestampSuspect] != 0 || snap[obs.ClockClamped] != 0 {
		t.Fatalf("wrap counters %+v", snap)
	}

	counters = obs.NewCounters()
	flows, _, err = Parse(datagram(readFixture(t, "v5_skew.bin"), export), sequence.NewTable(), counters, 2*time.Hour, 5*time.Second)
	if err != nil || len(flows) != 1 {
		t.Fatalf("skew err %v flows %d", err, len(flows))
	}
	if !flows[0].Start.Equal(export) || !flows[0].End.Equal(export) {
		t.Fatalf("skew start %s end %s", flows[0].Start, flows[0].End)
	}
	if counters.Snapshot()[obs.TimestampSkew] != 1 {
		t.Fatalf("timestamp_skew %d", counters.Snapshot()[obs.TimestampSkew])
	}
}

func TestSequenceGapUnits(t *testing.T) {
	export := time.Unix(1_700_000_000, 0).UTC()
	counters := obs.NewCounters()
	tab := sequence.NewTable()
	pkts := packets(t, readFixture(t, "v5_sequence.bin"))
	var gap uint64
	for _, p := range pkts {
		_, delta, err := Parse(datagram(p, export), tab, counters, 2*time.Hour, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		gap += delta.GapFlows
		if delta.GapPackets != 0 || delta.GapRecords != 0 {
			t.Fatalf("other units %+v", delta)
		}
	}
	if gap != 5 {
		t.Fatalf("gap %d", gap)
	}
	snap := counters.Snapshot()
	if snap[obs.SequenceGapV5Flows] != 5 || snap[obs.SequenceGapV9Packets] != 0 || snap[obs.SequenceGapIPFIXRecords] != 0 {
		t.Fatalf("%v %v %v", snap[obs.SequenceGapV5Flows], snap[obs.SequenceGapV9Packets], snap[obs.SequenceGapIPFIXRecords])
	}
	if snap[obs.SequenceReorder] != 0 || snap[obs.SequenceDuplicate] != 0 || snap[obs.SequenceReset] != 0 {
		t.Fatal(snap)
	}
}

func TestReorderCounters(t *testing.T) {
	export := time.Unix(1_700_000_000, 0).UTC()
	counters := obs.NewCounters()
	tab := sequence.NewTable()
	for _, p := range packets(t, readFixture(t, "v5_reorder.bin")) {
		if _, _, err := Parse(datagram(p, export), tab, counters, 2*time.Hour, 5*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	snap := counters.Snapshot()
	if snap[obs.SequenceReorder] != 1 || snap[obs.SequenceDuplicate] != 1 {
		t.Fatalf("reorder %d duplicate %d", snap[obs.SequenceReorder], snap[obs.SequenceDuplicate])
	}
	if snap[obs.SequenceGapV5Flows] != 0 || snap[obs.SequenceGapV9Packets] != 0 || snap[obs.SequenceGapIPFIXRecords] != 0 || snap[obs.SequenceReset] != 0 {
		t.Fatal(snap)
	}
}

func TestMalformed(t *testing.T) {
	export := time.Unix(1_700_000_000, 0).UTC()
	src := netip.MustParseAddr("192.0.2.5")

	counters := obs.NewCounters()
	_, delta, err := Parse(ingest.Datagram{Payload: []byte{0}, Src: src, ReceivedAt: export}, sequence.NewTable(), counters, time.Hour, time.Second)
	if !errors.Is(err, decode.ErrMalformed) || delta.Version != 0 || delta.Domain != 0 || delta.Malformed != 1 {
		t.Fatalf("short %+v %v", delta, err)
	}

	badVer := make([]byte, 24)
	binary.BigEndian.PutUint16(badVer[0:2], 9)
	_, delta, err = Parse(ingest.Datagram{Payload: badVer, Src: src, ReceivedAt: export}, sequence.NewTable(), counters, time.Hour, time.Second)
	if !errors.Is(err, decode.ErrMalformed) || delta.Version != 0 || delta.Domain != 0 {
		t.Fatalf("version %+v %v", delta, err)
	}

	tab := sequence.NewTable()
	counters = obs.NewCounters()
	_, delta, err = Parse(datagram(headerOnly(0, 50), export), tab, counters, time.Hour, time.Second)
	if !errors.Is(err, decode.ErrMalformed) || delta.Version != 5 || delta.Domain != 258 {
		t.Fatalf("count 0 %+v %v", delta, err)
	}
	flows, delta, err := Parse(datagram(oneRecord(60, 1), export), tab, counters, time.Hour, time.Second)
	if err != nil || len(flows) != 1 || delta.GapFlows != 0 {
		t.Fatalf("after count 0: flows %d gap %d err %v", len(flows), delta.GapFlows, err)
	}

	tab = sequence.NewTable()
	_, _, err = Parse(datagram(headerOnly(31, 5), export), tab, counters, time.Hour, time.Second)
	if !errors.Is(err, decode.ErrMalformed) {
		t.Fatal(err)
	}
	_, delta, err = Parse(datagram(oneRecord(5, 1), export), tab, counters, time.Hour, time.Second)
	if err != nil || delta.GapFlows != 0 || counters.Snapshot()[obs.SequenceReorder] != 0 {
		t.Fatalf("after count 31 gap %d reorder %d err %v", delta.GapFlows, counters.Snapshot()[obs.SequenceReorder], err)
	}

	// A parsed header with a missing record still consumes its sequence.
	tab = sequence.NewTable()
	counters = obs.NewCounters()
	_, delta, err = Parse(datagram(headerOnly(1, 10), export), tab, counters, time.Hour, time.Second)
	if !errors.Is(err, decode.ErrMalformed) || delta.Version != 5 {
		t.Fatalf("truncated %+v %v", delta, err)
	}
	_, delta, err = Parse(datagram(oneRecord(12, 1), export), tab, counters, time.Hour, time.Second)
	if err != nil || delta.GapFlows != 1 {
		t.Fatalf("truncated gap %d err %v", delta.GapFlows, err)
	}
}

func TestUnmappedExporter(t *testing.T) {
	export := time.Unix(1_700_000_000, 0).UTC()
	d := datagram(oneRecord(1, 1), export)
	d.Src = netip.MustParseAddr("::ffff:192.0.2.5")
	flows, delta, err := Parse(d, sequence.NewTable(), obs.NewCounters(), time.Hour, time.Second)
	if err != nil || len(flows) != 1 {
		t.Fatal(err)
	}
	want := netip.MustParseAddr("192.0.2.5")
	if flows[0].Exporter != want || delta.Exporter != want {
		t.Fatalf("exporter %s", flows[0].Exporter)
	}
}

func TestSamplingStoredPackets(t *testing.T) {
	export := time.Unix(1_700_000_000, 0).UTC()
	var got []uint64
	var sampled []bool
	var ns []*uint32
	var modes []*uint8
	for _, p := range packets(t, readFixture(t, "v5_sampling.bin")) {
		flows, _, err := Parse(datagram(p, export), sequence.NewTable(), obs.NewCounters(), 2*time.Hour, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range flows {
			got = append(got, f.Packets)
			sampled = append(sampled, f.Sampled)
			ns = append(ns, f.SamplingInterval)
			modes = append(modes, f.SamplingAlgorithm)
			if f.CounterSemantics != "delta" || f.OctetSemantics != "ip" {
				t.Fatalf("semantics %s %s", f.CounterSemantics, f.OctetSemantics)
			}
			if f.Packets*100 == f.Octets && f.Sampled && f.Packets == 333*100 {
				t.Fatal("packets were multiplied by N")
			}
		}
	}
	if len(got) != 4 || got[0] != 111 || got[1] != 222 || got[2] != 333 || got[3] != 444 {
		t.Fatalf("packets %v", got)
	}
	if sampled[0] || sampled[1] || !sampled[2] || !sampled[3] {
		t.Fatalf("sampled %v", sampled)
	}
	if ns[0] != nil || ns[1] != nil || ns[2] == nil || *ns[2] != 100 || ns[3] == nil || *ns[3] != 100 {
		t.Fatal("intervals")
	}
	if modes[0] == nil || *modes[0] != 2 || modes[1] == nil || *modes[1] != 1 || modes[2] == nil || *modes[2] != 3 {
		t.Fatal("modes were named or dropped")
	}
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
	Nexthop           string  `json:"nexthop"`
	SrcPort           uint16  `json:"src_port"`
	DstPort           uint16  `json:"dst_port"`
	Proto             uint8   `json:"proto"`
	TCPFlags          uint8   `json:"tcp_flags"`
	TOS               uint8   `json:"tos"`
	Packets           uint64  `json:"packets"`
	Octets            uint64  `json:"octets"`
	CounterSemantics  string  `json:"counter_semantics"`
	OctetSemantics    string  `json:"octet_semantics"`
	InputIf           uint32  `json:"input_if"`
	OutputIf          uint32  `json:"output_if"`
	BGPSrcAS          uint32  `json:"bgp_src_as"`
	BGPDstAS          uint32  `json:"bgp_dst_as"`
	SrcMask           uint8   `json:"src_mask"`
	DstMask           uint8   `json:"dst_mask"`
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

func compareFixture(t *testing.T, raw []byte, exp fixture) {
	t.Helper()
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
	pkts := packets(t, raw)
	if len(pkts) != len(exp.Packets) {
		t.Fatalf("packets %d want %d", len(pkts), len(exp.Packets))
	}
	counters := obs.NewCounters()
	tab := sequence.NewTable()
	names := map[string]obs.Name{
		"sequence_gap_v5_flows":      obs.SequenceGapV5Flows,
		"sequence_gap_v9_packets":    obs.SequenceGapV9Packets,
		"sequence_gap_ipfix_records": obs.SequenceGapIPFIXRecords,
		"sequence_reorder":           obs.SequenceReorder,
		"sequence_duplicate":         obs.SequenceDuplicate,
		"sequence_reset":             obs.SequenceReset,
		"sequence_unresolved":        obs.SequenceUnresolved,
		"timestamp_skew":             obs.TimestampSkew,
		"timestamp_suspect":          obs.TimestampSuspect,
		"clock_clamped":              obs.ClockClamped,
		"malformed":                  obs.Malformed,
	}
	for i, p := range pkts {
		flows, delta, err := Parse(ingest.Datagram{Payload: p, Src: exporter, ReceivedAt: received}, tab, counters, maxAge, skew)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		want := exp.Packets[i]
		if delta.Version != want.Delta.Version || delta.Domain != want.Delta.Domain ||
			delta.Packets != want.Delta.Packets || delta.Flows != want.Delta.Flows ||
			delta.Malformed != want.Delta.Malformed || delta.MissingTemplate != want.Delta.MissingTemplate ||
			delta.GapFlows != want.Delta.GapFlows || delta.GapPackets != want.Delta.GapPackets ||
			delta.GapRecords != want.Delta.GapRecords || !delta.LastSeen.Equal(received) || delta.Exporter != exporter {
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
		if snap[obs.DecodedFlows] != 0 || snap[obs.DecodedPackets] != 0 {
			t.Fatal("parse must not count decoded_flows")
		}
		if len(flows) != len(want.Flows) {
			t.Fatalf("packet %d flows %d want %d", i, len(flows), len(want.Flows))
		}
		for j, f := range flows {
			compareFlow(t, i, j, f, want.Flows[j], exporter, received)
		}
	}
}

func compareFlow(t *testing.T, i, j int, f flow.Flow, want flowExpect, exporter netip.Addr, received time.Time) {
	t.Helper()
	if f.Src.String() != want.Src || f.Dst.String() != want.Dst {
		t.Fatalf("packet %d flow %d addr %s -> %s", i, j, f.Src, f.Dst)
	}
	if f.NextHop == nil || f.NextHop.String() != want.Nexthop {
		t.Fatalf("packet %d flow %d nexthop", i, j)
	}
	if !f.PortsPresent || f.SrcPort != want.SrcPort || f.DstPort != want.DstPort {
		t.Fatalf("packet %d flow %d ports", i, j)
	}
	if !f.ProtoPresent || f.Proto != want.Proto || !f.TCPFlagsPresent || f.TCPFlags != want.TCPFlags || !f.TOSPresent || f.TOS != want.TOS {
		t.Fatalf("packet %d flow %d proto/flags/tos", i, j)
	}
	if f.Packets != want.Packets || f.Octets != want.Octets || f.CounterSemantics != want.CounterSemantics || f.OctetSemantics != want.OctetSemantics {
		t.Fatalf("packet %d flow %d counters %+v", i, j, f)
	}
	if f.InputIf == nil || *f.InputIf != want.InputIf || f.OutputIf == nil || *f.OutputIf != want.OutputIf {
		t.Fatal("ifaces")
	}
	if f.BGPSrcAS == nil || *f.BGPSrcAS != want.BGPSrcAS || f.BGPDstAS == nil || *f.BGPDstAS != want.BGPDstAS {
		t.Fatal("bgp as")
	}
	if f.SrcMask == nil || *f.SrcMask != want.SrcMask || f.DstMask == nil || *f.DstMask != want.DstMask {
		t.Fatal("masks")
	}
	if f.Sampled != want.Sampled || !sameU32(f.SamplingInterval, want.SamplingInterval) || !sameU8(f.SamplingAlgorithm, want.SamplingAlgorithm) {
		t.Fatalf("packet %d flow %d sampling sampled %v interval %v algo %v", i, j, f.Sampled, f.SamplingInterval, f.SamplingAlgorithm)
	}
	if f.Domain != want.Domain || f.Version != want.Version || f.Exporter != exporter || !f.ReceivedAt.Equal(received) {
		t.Fatal("identity")
	}
	if !f.Start.Equal(mustTime(t, want.Start)) || !f.End.Equal(mustTime(t, want.End)) || !f.ExportTime.Equal(mustTime(t, want.Export)) {
		t.Fatalf("packet %d flow %d times %s %s %s", i, j, f.Start, f.End, f.ExportTime)
	}
	if timeSource(f.TimeSource) != want.TimeSource || f.ClockClamped != want.ClockClamped {
		t.Fatalf("packet %d flow %d source %s clamped %v", i, j, timeSource(f.TimeSource), f.ClockClamped)
	}
	if f.OutPackets != nil || f.OutOctets != nil || f.FlowDirection != nil {
		t.Fatal("unexpected optional biflow fields")
	}
	if f.SrcEnrich != (flow.Endpoint{}) || f.DstEnrich != (flow.Endpoint{}) {
		t.Fatal("enrichment must stay zero")
	}
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

func packets(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var out [][]byte
	rest := b
	for len(rest) >= 24 {
		count := int(binary.BigEndian.Uint16(rest[2:4]))
		if count < 1 || count > 30 {
			t.Fatalf("count %d", count)
		}
		n := 24 + count*48
		if len(rest) < n {
			t.Fatalf("short packet %d < %d", len(rest), n)
		}
		if len(rest) == n || len(rest)-n < 24 {
			out = append(out, rest)
			return out
		}
		out = append(out, rest[:n:n])
		rest = rest[n:]
	}
	if len(rest) != 0 {
		t.Fatalf("leftover %d", len(rest))
	}
	return out
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustJSON(t *testing.T, b []byte, dest any) {
	t.Helper()
	if err := json.Unmarshal(b, dest); err != nil {
		t.Fatal(err)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

func datagram(payload []byte, received time.Time) ingest.Datagram {
	return ingest.Datagram{
		Payload:    payload,
		Src:        netip.MustParseAddr("192.0.2.5"),
		ReceivedAt: received,
	}
}

func headerOnly(count uint16, seq uint32) []byte {
	b := make([]byte, 24)
	binary.BigEndian.PutUint16(b[0:2], 5)
	binary.BigEndian.PutUint16(b[2:4], count)
	binary.BigEndian.PutUint32(b[8:12], 1_700_000_000)
	binary.BigEndian.PutUint32(b[16:20], seq)
	b[20] = 1
	b[21] = 2
	return b
}

func oneRecord(seq, pkts uint32) []byte {
	b := make([]byte, 24+48)
	copy(b, headerOnly(1, seq))
	binary.BigEndian.PutUint32(b[24+16:24+20], pkts)
	return b
}

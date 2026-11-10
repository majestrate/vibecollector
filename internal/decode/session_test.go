package decode_test

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"vibecollector/internal/decode"
	"vibecollector/internal/decode/ipfix"
	"vibecollector/internal/decode/v5"
	"vibecollector/internal/decode/v9"
	"vibecollector/internal/flow"
	"vibecollector/internal/ingest"
	"vibecollector/internal/obs"
	"vibecollector/internal/sampling"
	"vibecollector/internal/sequence"
	"vibecollector/internal/template"
)

func init() {
	// The version parsers import decode, so they register from init.
	_ = v5.Parse
	_ = v9.Parse
	_ = ipfix.Parse
}

func TestNilSession(t *testing.T) {
	templates, hold, samples, seq, counters := deps(t, 8, 4, 4)
	if _, err := decode.NewSession(nil, hold, samples, seq, counters, 0, 0); !errors.Is(err, decode.ErrNilDep) {
		t.Fatal(err)
	}
	if _, err := decode.NewSession(templates, nil, samples, seq, counters, 0, 0); !errors.Is(err, decode.ErrNilDep) {
		t.Fatal(err)
	}
	if _, err := decode.NewSession(templates, hold, nil, seq, counters, 0, 0); !errors.Is(err, decode.ErrNilDep) {
		t.Fatal(err)
	}
	if _, err := decode.NewSession(templates, hold, samples, nil, counters, 0, 0); !errors.Is(err, decode.ErrNilDep) {
		t.Fatal(err)
	}
	if _, err := decode.NewSession(templates, hold, samples, seq, nil, 0, 0); !errors.Is(err, decode.ErrNilDep) {
		t.Fatal(err)
	}
	if _, err := decode.NewSession(templates, hold, samples, seq, counters, 0, 0); err != nil {
		t.Fatal(err)
	}
}

func TestDispatchUnknownAndV5(t *testing.T) {
	s, _, _, _, _, counters := session(t, 8, 8, 8)
	at := time.Unix(1_700_000_000, 0).UTC()
	ip := netip.MustParseAddr("192.0.2.5")
	_, delta, _ := s.Accept(ingest.Datagram{Payload: []byte{0x00, 0x04}, Src: ip, ReceivedAt: at})
	if delta.Version != 0 || delta.Domain != 0 || delta.Malformed != 1 || counters.Snapshot()[obs.Malformed] != 1 {
		t.Fatal(delta)
	}
	_, delta, _ = s.Accept(ingest.Datagram{Payload: []byte{0x00, 0x0a}, Src: ip, ReceivedAt: at})
	if delta.Version != 10 || delta.Domain != 0 || delta.Malformed != 1 || counters.Snapshot()[obs.Malformed] != 2 {
		t.Fatal(delta, counters.Snapshot()[obs.Malformed])
	}
	_, delta, _ = s.Accept(ingest.Datagram{Payload: []byte{0}, Src: ip, ReceivedAt: at})
	if delta.Version != 0 || counters.Snapshot()[obs.Malformed] != 3 {
		t.Fatal(delta, counters.Snapshot()[obs.Malformed])
	}
	_, delta, _ = s.Accept(ingest.Datagram{Payload: []byte{0, 7}, Src: ip, ReceivedAt: at})
	if delta.Version != 0 || counters.Snapshot()[obs.Malformed] != 4 {
		t.Fatal(delta)
	}
	v5pkt := make([]byte, 24+48)
	binary.BigEndian.PutUint16(v5pkt[0:2], 5)
	binary.BigEndian.PutUint16(v5pkt[2:4], 1)
	binary.BigEndian.PutUint32(v5pkt[8:12], 1_700_000_000)
	v5pkt[20], v5pkt[21] = 1, 2
	binary.BigEndian.PutUint16(v5pkt[22:24], 0xC064)
	binary.BigEndian.PutUint32(v5pkt[24+16:24+20], 42)
	flows, delta, _ := s.Accept(ingest.Datagram{Payload: v5pkt, Src: ip, ReceivedAt: at})
	if delta.Version != 5 || delta.Domain != 258 || len(flows) != 1 || flows[0].Packets != 42 || !flows[0].Sampled {
		t.Fatalf("delta %+v flows %d", delta, len(flows))
	}
	if flows[0].SamplingInterval == nil || *flows[0].SamplingInterval != 100 {
		t.Fatal(flows[0].SamplingInterval)
	}
	short := make([]byte, 24)
	copy(short, v5pkt[:24])
	before := counters.Snapshot()[obs.Malformed]
	_, delta, _ = s.Accept(ingest.Datagram{Payload: short, Src: ip, ReceivedAt: at})
	if delta.Version != 5 || delta.Malformed != 1 || counters.Snapshot()[obs.Malformed] != before+1 {
		t.Fatal("short v5 counted twice", delta, counters.Snapshot()[obs.Malformed], before)
	}
}

func TestDataBeforeTemplateDrains(t *testing.T) {
	s, templates, hold, _, _, counters := session(t, 64, 256, 4096)
	pkts := framed(t, "v9_data_before_template.bin")
	ip := netip.MustParseAddr("192.0.2.8")
	at := time.Unix(1_700_000_000, 0).UTC()
	flows, delta, _ := s.Accept(ingest.Datagram{Payload: pkts[0], Src: ip, ReceivedAt: at})
	if len(flows) != 0 || delta.MissingTemplate != 1 || len(hold.List(ip)) != 1 {
		t.Fatalf("flows %d missing %d hold %d", len(flows), delta.MissingTemplate, len(hold.List(ip)))
	}
	flows, delta, _ = s.Accept(ingest.Datagram{Payload: pkts[1], Src: ip, ReceivedAt: at})
	if len(flows) != 1 || flows[0].Packets != 9 || flows[0].Src.String() != "203.0.113.10" || len(hold.List(ip)) != 0 {
		t.Fatalf("flows %d hold %d delta %+v", len(flows), len(hold.List(ip)), delta)
	}
	if counters.Snapshot()[obs.MissingTemplate] != 1 || counters.Snapshot()[obs.DroppedTemplate] != 0 {
		t.Fatal(counters.Snapshot())
	}
	if counters.Snapshot()[obs.SequenceDuplicate] != 0 {
		t.Fatal("retry observed again")
	}
	if _, ok := templates.Get(template.Key{Exporter: ip, Domain: 4, Version: 9, ID: 256}); !ok {
		t.Fatal("template")
	}
	if !flows[0].Start.Equal(at) || !flows[0].End.Equal(at) || flows[0].TimeSource != flow.TimeSysUpTime {
		t.Fatal(flows[0].Start, flows[0].End, flows[0].TimeSource)
	}
}

func TestHoldFullDroppedTemplate(t *testing.T) {
	s, _, hold, _, _, counters := session(t, 64, 256, 4096)
	ip := netip.MustParseAddr("192.0.2.20")
	at := time.Unix(1_700_000_000, 0).UTC()
	for i := 0; i < 257; i++ {
		s.Accept(ingest.Datagram{Payload: dataOnly(uint32(i), uint32(i+1)), Src: ip, ReceivedAt: at})
	}
	if counters.Snapshot()[obs.DroppedTemplate] != 1 || counters.Snapshot()[obs.MissingTemplate] != 257 {
		t.Fatal(counters.Snapshot()[obs.DroppedTemplate], counters.Snapshot()[obs.MissingTemplate])
	}
	entries := hold.List(ip)
	if len(entries) != 256 {
		t.Fatal(len(entries))
	}
	if binary.BigEndian.Uint32(entries[0].Payload[32:36]) != 2 || binary.BigEndian.Uint32(entries[255].Payload[32:36]) != 257 {
		t.Fatal("oldest datagram was not the one dropped")
	}
	flows, _, _ := s.Accept(ingest.Datagram{Payload: templatePacket(4, 257, 256), Src: ip, ReceivedAt: at})
	if len(flows) != 256 || flows[0].Packets != 2 || flows[255].Packets != 257 {
		t.Fatalf("drained %d %v", len(flows), packetsOf(flows))
	}
	if len(hold.List(ip)) != 0 {
		t.Fatal("hold not empty")
	}
}

func TestPartialEmitRetriesSuffix(t *testing.T) {
	s, _, hold, _, _, counters := session(t, 64, 16, 16)
	ip := netip.MustParseAddr("192.0.2.30")
	at := time.Unix(1_700_000_000, 0).UTC()
	s.Accept(ingest.Datagram{Payload: templatePacket(1, 0, 256), Src: ip, ReceivedAt: at})
	rec := func(pkts uint32) []byte {
		b := make([]byte, 12)
		binary.BigEndian.PutUint32(b[0:4], 0x0a000001)
		binary.BigEndian.PutUint32(b[4:8], 0x0a000002)
		binary.BigEndian.PutUint32(b[8:12], pkts)
		return b
	}
	pkt := append(v9Header(3, 0, 1_700_000_000, 1, 1), flowSet(256, rec(1))...)
	pkt = append(pkt, flowSet(999, rec(2))...)
	pkt = append(pkt, flowSet(256, rec(3))...)
	flows, _, _ := s.Accept(ingest.Datagram{Payload: pkt, Src: ip, ReceivedAt: at})
	if len(flows) != 1 || flows[0].Packets != 1 {
		t.Fatalf("first sight %v", flows)
	}
	entries := hold.List(ip)
	if len(entries) != 1 || entries[0].RetryAt != 36 {
		t.Fatalf("retry at %v", entries)
	}
	if counters.Snapshot()[obs.MissingTemplate] != 1 {
		t.Fatal(counters.Snapshot()[obs.MissingTemplate])
	}
	flows, _, _ = s.Accept(ingest.Datagram{Payload: templatePacket(1, 2, 999), Src: ip, ReceivedAt: at})
	if len(flows) != 2 || flows[0].Packets != 2 || flows[1].Packets != 3 {
		t.Fatalf("retry %v", packetsOf(flows))
	}
	snap := counters.Snapshot()
	if len(hold.List(ip)) != 0 || snap[obs.SequenceDuplicate] != 0 || snap[obs.MissingTemplate] != 1 || snap[obs.CountDisagrees] != 0 {
		t.Fatal(snap)
	}
}

func TestExpireIdle(t *testing.T) {
	s, templates, hold, samples, _, counters := session(t, 64, 8, 8)
	a := netip.MustParseAddr("192.0.2.40")
	b := netip.MustParseAddr("192.0.2.50")
	t0 := time.Unix(1_700_000_000, 0).UTC()
	s.Accept(ingest.Datagram{Payload: templatePacket(1, 0, 256), Src: a, ReceivedAt: t0})
	s.Accept(ingest.Datagram{Payload: templatePacket(1, 0, 256), Src: b, ReceivedAt: t0})
	samples.Put(sampling.SampleKey{Exporter: a, Domain: 1, Scope: "device"}, sampling.Sample{N: 4, Sampled: true})
	hold.Put(template.Pending{Exporter: a, Payload: []byte{1}, Version: 9})
	if _, err := s.ExpireIdle(t0, 0); !errors.Is(err, decode.ErrBadTimeout) {
		t.Fatal(err)
	}
	if _, err := s.ExpireIdle(t0, -time.Second); !errors.Is(err, decode.ErrBadTimeout) {
		t.Fatal(err)
	}
	if _, ok := templates.Get(template.Key{Exporter: a, Domain: 1, Version: 9, ID: 256}); !ok {
		t.Fatal("non-positive idle dropped")
	}
	if got, err := s.ExpireIdle(t0.Add(10*time.Minute), 30*time.Minute); err != nil || len(got) != 0 {
		t.Fatal(got, err)
	}
	if got, err := s.ExpireIdle(t0.Add(30*time.Minute), 30*time.Minute); err != nil || len(got) != 0 {
		t.Fatal("equal touch dropped", got, err)
	}
	got, err := s.ExpireIdle(t0.Add(30*time.Minute+time.Nanosecond), 30*time.Minute)
	if err != nil || len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatal(got, err)
	}
	if counters.Snapshot()[obs.TemplateIdleExpired] != 0 {
		t.Fatal("ExpireIdle incremented template_idle_expired")
	}
	if counters.Snapshot()[obs.DroppedTemplate] != 1 {
		t.Fatal("idle expiry did not count held datagrams", counters.Snapshot()[obs.DroppedTemplate])
	}
	if _, ok := templates.Get(template.Key{Exporter: a, Domain: 1, Version: 9, ID: 256}); ok {
		t.Fatal("template remains")
	}
	if _, ok := samples.Lookup(a, 1, []string{"device"}); ok || len(hold.List(a)) != 0 {
		t.Fatal("sample or hold remains")
	}
	before := counters.Snapshot()[obs.SequenceGapV9Packets]
	s.Accept(ingest.Datagram{Payload: templatePacket(1, 50, 256), Src: a, ReceivedAt: t0.Add(time.Hour)})
	if counters.Snapshot()[obs.SequenceGapV9Packets] != before {
		t.Fatal("idle expiry left a gap")
	}
}

func TestForeignEviction(t *testing.T) {
	s, templates, hold, samples, _, counters := session(t, 1, 8, 8)
	a := netip.MustParseAddr("192.0.2.10")
	b := netip.MustParseAddr("192.0.2.11")
	t0 := time.Unix(1_700_000_000, 0).UTC()
	s.Accept(ingest.Datagram{Payload: templatePacket(1, 0, 256), Src: a, ReceivedAt: t0})
	samples.Put(sampling.SampleKey{Exporter: a, Domain: 1, Scope: "device"}, sampling.Sample{N: 9, Sampled: true})
	hold.Put(template.Pending{Exporter: a, Payload: []byte{9}, Version: 9, Domain: 1})
	t1 := t0.Add(time.Minute)
	s.Accept(ingest.Datagram{Payload: templatePacket(1, 0, 256), Src: b, ReceivedAt: t1})
	if _, ok := samples.Lookup(a, 1, []string{"device"}); !ok || len(hold.List(a)) != 1 {
		t.Fatal("Accept locked the evicted exporter")
	}
	if _, ok := templates.Get(template.Key{Exporter: a, Domain: 1, Version: 9, ID: 256}); ok {
		t.Fatal("A template remains")
	}
	if _, ok := templates.Get(template.Key{Exporter: b, Domain: 1, Version: 9, ID: 256}); !ok {
		t.Fatal("B template missing")
	}
	if counters.Snapshot()[obs.TemplateEvicted] != 1 {
		t.Fatal(counters.Snapshot()[obs.TemplateEvicted])
	}
	if _, err := s.ExpireIdle(t1, 0); !errors.Is(err, decode.ErrBadTimeout) {
		t.Fatal(err)
	}
	if _, ok := samples.Lookup(a, 1, []string{"device"}); !ok {
		t.Fatal("zero idle dropped the recorded eviction")
	}
	got, err := s.ExpireIdle(t1, 30*time.Minute)
	if err != nil || len(got) != 0 {
		t.Fatal(got, err)
	}
	if _, ok := samples.Lookup(a, 1, []string{"device"}); ok || len(hold.List(a)) != 0 {
		t.Fatal("eviction was not dropped")
	}
	before := counters.Snapshot()[obs.SequenceGapV9Packets]
	s.Accept(ingest.Datagram{Payload: templatePacket(1, 10, 300), Src: a, ReceivedAt: t1})
	if counters.Snapshot()[obs.SequenceGapV9Packets] != before {
		t.Fatal("evicted exporter was a gap")
	}
}

func TestSelfEvictionRestoresTouch(t *testing.T) {
	s, templates, hold, samples, _, counters := session(t, 1, 8, 8)
	a := netip.MustParseAddr("192.0.2.12")
	t0 := time.Unix(1_700_000_000, 0).UTC()
	s.Accept(ingest.Datagram{Payload: templatePacket(1, 0, 256), Src: a, ReceivedAt: t0})
	samples.Put(sampling.SampleKey{Exporter: a, Domain: 1, Scope: "device"}, sampling.Sample{N: 3, Sampled: true})
	hold.Put(template.Pending{Exporter: a, Payload: []byte{1}, Version: 9})
	t1 := t0.Add(time.Minute)
	s.Accept(ingest.Datagram{Payload: templatePacket(1, 1, 257), Src: a, ReceivedAt: t1})
	if _, ok := templates.Get(template.Key{Exporter: a, Domain: 1, Version: 9, ID: 256}); ok {
		t.Fatal("old template")
	}
	if _, ok := templates.Get(template.Key{Exporter: a, Domain: 1, Version: 9, ID: 257}); !ok {
		t.Fatal("new template")
	}
	if _, ok := samples.Lookup(a, 1, []string{"device"}); ok || len(hold.List(a)) != 0 {
		t.Fatal("self eviction left sampling or hold")
	}
	if counters.Snapshot()[obs.TemplateEvicted] != 1 {
		t.Fatal(counters.Snapshot()[obs.TemplateEvicted])
	}
	if counters.Snapshot()[obs.DroppedTemplate] != 1 {
		t.Fatal("self eviction did not count the held datagram", counters.Snapshot()[obs.DroppedTemplate])
	}
	if got, err := s.ExpireIdle(t1.Add(30*time.Minute), 30*time.Minute); err != nil || len(got) != 0 {
		t.Fatal(got, err)
	}
	got, err := s.ExpireIdle(t1.Add(30*time.Minute+time.Nanosecond), 30*time.Minute)
	if err != nil || len(got) != 1 || got[0] != a {
		t.Fatal(got, err)
	}
}

func TestRecordedEvictionClearsOnAccept(t *testing.T) {
	s, templates, hold, samples, _, counters := session(t, 1, 8, 8)
	a := netip.MustParseAddr("192.0.2.10")
	b := netip.MustParseAddr("192.0.2.11")
	t0 := time.Unix(1_700_000_000, 0).UTC()
	s.Accept(ingest.Datagram{Payload: templatePacket(1, 0, 256), Src: a, ReceivedAt: t0})
	samples.Put(sampling.SampleKey{Exporter: a, Domain: 1, Scope: "device"}, sampling.Sample{N: 9, Sampled: true})
	hold.Put(template.Pending{Exporter: a, Payload: []byte{9}, Version: 9, Domain: 1})
	t1 := t0.Add(time.Minute)
	s.Accept(ingest.Datagram{Payload: templatePacket(1, 0, 256), Src: b, ReceivedAt: t1})
	s.Accept(ingest.Datagram{Payload: templatePacket(1, 40, 300), Src: a, ReceivedAt: t1})
	if counters.Snapshot()[obs.SequenceGapV9Packets] != 0 {
		t.Fatal("evicted exporter counted a gap", counters.Snapshot()[obs.SequenceGapV9Packets])
	}
	if _, ok := samples.Lookup(a, 1, []string{"device"}); ok {
		t.Fatal("old sampling survived the return")
	}
	if _, ok := templates.Get(template.Key{Exporter: a, Domain: 1, Version: 9, ID: 300}); !ok {
		t.Fatal("template installed on return is missing")
	}
	if _, err := s.ExpireIdle(t1, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, ok := templates.Get(template.Key{Exporter: a, Domain: 1, Version: 9, ID: 300}); !ok {
		t.Fatal("reaper dropped templates installed after the eviction")
	}
}

func TestSelfEvictionKeepsLaterSample(t *testing.T) {
	s, templates, _, samples, _, _ := session(t, 1, 8, 8)
	a := netip.MustParseAddr("192.0.2.12")
	t0 := time.Unix(1_700_000_000, 0).UTC()
	s.Accept(ingest.Datagram{Payload: templatePacket(1, 0, 256), Src: a, ReceivedAt: t0})
	samples.Put(sampling.SampleKey{Exporter: a, Domain: 1, Scope: "device"}, sampling.Sample{N: 3, Sampled: true})
	spec := make([]byte, 14)
	binary.BigEndian.PutUint16(spec[0:2], 257)
	binary.BigEndian.PutUint16(spec[2:4], 4)
	binary.BigEndian.PutUint16(spec[4:6], 4)
	binary.BigEndian.PutUint16(spec[6:8], 2)
	binary.BigEndian.PutUint16(spec[8:10], 4)
	binary.BigEndian.PutUint16(spec[10:12], 34)
	binary.BigEndian.PutUint16(spec[12:14], 4)
	vals := make([]byte, 8)
	binary.BigEndian.PutUint32(vals[0:4], 7)
	binary.BigEndian.PutUint32(vals[4:8], 100)
	pkt := append(v9Header(2, 0, 1_700_000_000, 1, 1), flowSet(1, spec)...)
	pkt = append(pkt, flowSet(257, vals)...)
	s.Accept(ingest.Datagram{Payload: pkt, Src: a, ReceivedAt: t0.Add(time.Second)})
	if _, ok := templates.Get(template.Key{Exporter: a, Domain: 1, Version: 9, ID: 256}); ok {
		t.Fatal("old template")
	}
	if _, ok := templates.Get(template.Key{Exporter: a, Domain: 1, Version: 9, ID: 257}); !ok {
		t.Fatal("new template")
	}
	if _, ok := samples.Lookup(a, 1, []string{"device"}); ok {
		t.Fatal("old device fact survived self-eviction")
	}
	got, ok := samples.Lookup(a, 1, []string{"if:7"})
	if !ok || got.N != 100 || !got.Sampled {
		t.Fatalf("later fact %+v %v", got, ok)
	}
}

func TestParallelAccept(t *testing.T) {
	s, templates, _, _, _, _ := session(t, 64, 8, 8)
	a := netip.MustParseAddr("192.0.2.70")
	b := netip.MustParseAddr("192.0.2.71")
	at := time.Unix(1_700_000_000, 0).UTC()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, ip := range []netip.Addr{a, b} {
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			<-start
			s.Accept(ingest.Datagram{Payload: templatePacket(1, 0, 256), Src: ip, ReceivedAt: at})
		}(ip)
	}
	close(start)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Accept deadlocked")
	}
	for _, ip := range []netip.Addr{a, b} {
		if _, ok := templates.Get(template.Key{Exporter: ip, Domain: 1, Version: 9, ID: 256}); !ok {
			t.Fatal(ip)
		}
	}
}

func TestIPFIXHoldRewritesLength(t *testing.T) {
	s, templates, hold, _, _, counters := session(t, 64, 256, 4096)
	ip := netip.MustParseAddr("192.0.2.8")
	at := time.Unix(1_700_000_000, 0).UTC()
	rec := make([]byte, 12)
	binary.BigEndian.PutUint32(rec[0:4], 0xCB00710A)
	binary.BigEndian.PutUint32(rec[4:8], 0xC6336414)
	binary.BigEndian.PutUint32(rec[8:12], 6)
	data := ipfixPacket(11, 0, flowSet(4, []byte{0, 0, 0, 0}), flowSet(256, rec))
	flows, delta, _ := s.Accept(ingest.Datagram{Payload: data, Src: ip, ReceivedAt: at})
	if len(flows) != 0 || delta.MissingTemplate != 1 || delta.Version != 10 || len(hold.List(ip)) != 1 {
		t.Fatalf("flows %d delta %+v hold %d", len(flows), delta, len(hold.List(ip)))
	}
	ent := hold.List(ip)[0]
	if ent.RetryAt <= 16 {
		t.Fatal(ent.RetryAt)
	}
	// A shortened replay is malformed until the message length is rewritten.
	short := append(append([]byte{}, ent.Payload[:16]...), ent.Payload[ent.RetryAt:]...)
	if _, _, _, err := ipfix.Parse(ingest.Datagram{Payload: short, Src: ip, ReceivedAt: at}, nil, nil, nil, nil, false, 2*time.Hour, 5*time.Second); !errors.Is(err, decode.ErrMalformed) {
		t.Fatal(err)
	}
	body := make([]byte, 16)
	binary.BigEndian.PutUint16(body[0:2], 256)
	binary.BigEndian.PutUint16(body[2:4], 3)
	pairs := []uint16{8, 4, 12, 4, 2, 4}
	for i, v := range pairs {
		binary.BigEndian.PutUint16(body[4+2*i:6+2*i], v)
	}
	flows, delta, _ = s.Accept(ingest.Datagram{Payload: ipfixPacket(11, 0, flowSet(2, body)), Src: ip, ReceivedAt: at})
	if len(flows) != 1 || flows[0].Packets != 6 || flows[0].Src.String() != "203.0.113.10" || flows[0].Version != 10 || len(hold.List(ip)) != 0 {
		t.Fatalf("flows %d hold %d delta %+v", len(flows), len(hold.List(ip)), delta)
	}
	if counters.Snapshot()[obs.MissingTemplate] != 1 || counters.Snapshot()[obs.Malformed] != 0 {
		t.Fatal(counters.Snapshot())
	}
	if _, ok := templates.Get(template.Key{Exporter: ip, Domain: 11, Version: 10, ID: 256}); !ok {
		t.Fatal("template")
	}
}

func TestIPFIXDrainGapRecords(t *testing.T) {
	s, templates, _, _, _, _ := session(t, 64, 8, 8)
	ip := netip.MustParseAddr("192.0.2.61")
	at := time.Unix(1_700_000_000, 0).UTC()
	rec := func(pkts uint32) []byte {
		b := make([]byte, 12)
		binary.BigEndian.PutUint32(b[0:4], 0x0a000001)
		binary.BigEndian.PutUint32(b[4:8], 0x0a000002)
		binary.BigEndian.PutUint32(b[8:12], pkts)
		return b
	}
	s.Accept(ingest.Datagram{Payload: ipfixPacket(9, 0, ipfixTemplateSet(300)), Src: ip, ReceivedAt: at})
	flows, delta, gaps := s.Accept(ingest.Datagram{Payload: ipfixPacket(9, 4, flowSet(256, rec(3))), Src: ip, ReceivedAt: at})
	if len(flows) != 0 || delta.GapRecords != 0 || len(gaps) != 0 || delta.MissingTemplate != 1 {
		t.Fatalf("first sight flows %d delta %+v gaps %d", len(flows), delta, len(gaps))
	}
	flows, delta, gaps = s.Accept(ingest.Datagram{Payload: ipfixPacket(9, 0, ipfixTemplateSet(256)), Src: ip, ReceivedAt: at})
	if delta.GapRecords != 4 || len(gaps) != 0 || delta.Packets != 1 || delta.Malformed != 0 || delta.MissingTemplate != 0 {
		t.Fatalf("same domain delta %+v gaps %+v", delta, gaps)
	}
	if len(flows) != 1 || flows[0].Packets != 3 {
		t.Fatal(packetsOf(flows))
	}

	s.Accept(ingest.Datagram{Payload: ipfixPacket(4, 0, ipfixTemplateSet(300)), Src: ip, ReceivedAt: at})
	s.Accept(ingest.Datagram{Payload: ipfixPacket(4, 4, flowSet(256, rec(8))), Src: ip, ReceivedAt: at})
	if _, _, err := templates.Put(template.Key{Exporter: ip, Domain: 4, Version: 10, ID: 256}, template.Template{
		Fields:   []template.Field{{Type: 8, Length: 4}, {Type: 12, Length: 4}, {Type: 2, Length: 4}},
		Received: at,
	}); err != nil {
		t.Fatal(err)
	}
	flows, delta, gaps = s.Accept(ingest.Datagram{Payload: ipfixPacket(8, 0), Src: ip, ReceivedAt: at})
	if delta.Domain != 8 || delta.GapRecords != 0 || delta.Packets != 1 || len(gaps) != 1 {
		t.Fatalf("other domain delta %+v gaps %+v", delta, gaps)
	}
	g := gaps[0]
	if g.Domain != 4 || g.GapRecords != 4 || g.Packets != 0 || g.Malformed != 0 || g.MissingTemplate != 0 || g.Flows != 0 {
		t.Fatalf("gap delta %+v", g)
	}
	if len(flows) != 1 || flows[0].Packets != 8 || flows[0].Domain != 4 {
		t.Fatal(flows)
	}
}

func TestIPFIXReplayStopsAtMessageLength(t *testing.T) {
	s, _, _, _, _, _ := session(t, 64, 8, 8)
	ip := netip.MustParseAddr("192.0.2.62")
	at := time.Unix(1_700_000_000, 0).UTC()
	rec := make([]byte, 12)
	binary.BigEndian.PutUint32(rec[0:4], 0x0a000001)
	binary.BigEndian.PutUint32(rec[4:8], 0x0a000002)
	binary.BigEndian.PutUint32(rec[8:12], 6)
	data := ipfixPacket(11, 0, flowSet(4, []byte{0, 0, 0, 0}), flowSet(256, rec))
	trailer := make([]byte, 12)
	binary.BigEndian.PutUint32(trailer[0:4], 0x0a000001)
	binary.BigEndian.PutUint32(trailer[4:8], 0x0a000002)
	binary.BigEndian.PutUint32(trailer[8:12], 999)
	data = append(data, flowSet(256, trailer)...)
	if _, delta, _ := s.Accept(ingest.Datagram{Payload: data, Src: ip, ReceivedAt: at}); delta.MissingTemplate != 1 {
		t.Fatal(delta)
	}
	flows, _, _ := s.Accept(ingest.Datagram{Payload: ipfixPacket(11, 0, ipfixTemplateSet(256)), Src: ip, ReceivedAt: at})
	if len(flows) != 1 || flows[0].Packets != 6 {
		t.Fatalf("trailer became a set: %v", packetsOf(flows))
	}
}

func TestAcceptWithdrawAndRedefine(t *testing.T) {
	s, templates, _, _, _, counters := session(t, 64, 8, 8)
	ip := netip.MustParseAddr("192.0.2.77")
	at := time.Unix(1_700_000_000, 0).UTC()
	const domain = 42
	const id = 256
	key := template.Key{Exporter: ip, Domain: domain, Version: 10, ID: id}
	s.Accept(ingest.Datagram{Payload: ipfixPacket(domain, 0, ipfixTemplateSet(id)), Src: ip, ReceivedAt: at})
	orig, ok := templates.Get(key)
	if !ok || len(orig.Fields) != 3 || orig.Fields[2].Length != 4 {
		t.Fatalf("setup %+v %v", orig.Fields, ok)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		s.Accept(ingest.Datagram{Payload: ipfixPacket(domain, 1, ipfixWithdraw(id)), Src: ip, ReceivedAt: at})
	}()
	go func() {
		defer wg.Done()
		<-start
		s.Accept(ingest.Datagram{Payload: ipfixPacket(domain, 2, ipfixTemplateAlt(id)), Src: ip, ReceivedAt: at})
	}()
	close(start)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("deadlock")
	}

	snap := counters.Snapshot()
	got, ok := templates.Get(key)
	if snap[obs.TemplatesWithdrawn] != 1 {
		t.Fatal(snap[obs.TemplatesWithdrawn], snap[obs.TemplateRedefined], ok)
	}
	if ok {
		// Redefine ran last, after the withdrawal, so it is an insert.
		if snap[obs.TemplateRedefined] != 0 || len(got.Fields) != 3 || got.Fields[2].Type != 2 || got.Fields[2].Length != 8 {
			t.Fatalf("last definition %+v redefined %d", got.Fields, snap[obs.TemplateRedefined])
		}
		return
	}
	// Withdrawal ran last, after the field list changed.
	if snap[obs.TemplateRedefined] != 1 {
		t.Fatal(snap[obs.TemplateRedefined])
	}
}

func TestIPFIXSnapshotFollowsHold(t *testing.T) {
	s, _, hold, _, _, counters := session(t, 64, 8, 8)
	ip := netip.MustParseAddr("192.0.2.63")
	at := time.Unix(1_700_000_000, 0).UTC()
	rec := func(pkts uint32) []byte {
		b := make([]byte, 12)
		binary.BigEndian.PutUint32(b[0:4], 0x0a000001)
		binary.BigEndian.PutUint32(b[4:8], 0x0a000002)
		binary.BigEndian.PutUint32(b[8:12], pkts)
		return b
	}
	s.Accept(ingest.Datagram{Payload: ipfixPacket(7, 5, ipfixTemplateSet(300)), Src: ip, ReceivedAt: at})
	s.Accept(ingest.Datagram{Payload: ipfixPacket(7, 10, flowSet(256, rec(1))), Src: ip, ReceivedAt: at})
	s.Accept(ingest.Datagram{Payload: ipfixPacket(7, 5, flowSet(300, rec(9))), Src: ip, ReceivedAt: at})
	two := append(rec(2), rec(3)...)
	s.Accept(ingest.Datagram{Payload: ipfixPacket(7, 10, flowSet(256, two)), Src: ip, ReceivedAt: at})
	if len(hold.List(ip)) != 2 {
		t.Fatal(len(hold.List(ip)))
	}
	flows, delta, _ := s.Accept(ingest.Datagram{Payload: ipfixPacket(7, 6, ipfixTemplateSet(256)), Src: ip, ReceivedAt: at})
	if len(flows) != 3 || delta.GapRecords != 4 {
		t.Fatalf("flows %v delta %+v", packetsOf(flows), delta)
	}
	if counters.Snapshot()[obs.SequenceGapIPFIXRecords] != 4 {
		t.Fatal(counters.Snapshot()[obs.SequenceGapIPFIXRecords])
	}
	_, probe, _ := s.Accept(ingest.Datagram{Payload: ipfixPacket(7, 12), Src: ip, ReceivedAt: at})
	if probe.GapRecords != 0 || counters.Snapshot()[obs.SequenceGapIPFIXRecords] != 4 {
		t.Fatalf("older hold used the newer snapshot: probe %+v counter %d", probe, counters.Snapshot()[obs.SequenceGapIPFIXRecords])
	}
}

func deps(t *testing.T, cap, per, global int) (*template.Cache, *template.Hold, *sampling.Cache, *sequence.Table, *obs.Counters) {
	t.Helper()
	templates, err := template.NewCache(cap)
	if err != nil {
		t.Fatal(err)
	}
	hold, err := template.NewHold(per, global)
	if err != nil {
		t.Fatal(err)
	}
	return templates, hold, sampling.NewCache(), sequence.NewTable(), obs.NewCounters()
}

func session(t *testing.T, cap, per, global int) (*decode.Session, *template.Cache, *template.Hold, *sampling.Cache, *sequence.Table, *obs.Counters) {
	t.Helper()
	templates, hold, samples, seq, counters := deps(t, cap, per, global)
	s, err := decode.NewSession(templates, hold, samples, seq, counters, 2*time.Hour, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return s, templates, hold, samples, seq, counters
}

func framed(t *testing.T, name string) [][]byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for len(b) > 0 {
		n := binary.BigEndian.Uint32(b[:4])
		b = b[4:]
		out = append(out, append([]byte(nil), b[:n]...))
		b = b[n:]
	}
	return out
}

func ipfixTemplateSet(id uint16) []byte {
	return ipfixTemplatePairs(id, []uint16{8, 4, 12, 4, 2, 4})
}

func ipfixTemplateAlt(id uint16) []byte {
	return ipfixTemplatePairs(id, []uint16{8, 4, 12, 4, 2, 8})
}

func ipfixTemplatePairs(id uint16, pairs []uint16) []byte {
	body := make([]byte, 4+len(pairs)*2)
	binary.BigEndian.PutUint16(body[0:2], id)
	binary.BigEndian.PutUint16(body[2:4], uint16(len(pairs)/2))
	for i, v := range pairs {
		binary.BigEndian.PutUint16(body[4+2*i:6+2*i], v)
	}
	return flowSet(2, body)
}

func ipfixWithdraw(id uint16) []byte {
	body := make([]byte, 4)
	binary.BigEndian.PutUint16(body[0:2], id)
	binary.BigEndian.PutUint16(body[2:4], 0)
	return flowSet(2, body)
}

func ipfixPacket(domain, seq uint32, sets ...[]byte) []byte {
	var body []byte
	for _, s := range sets {
		body = append(body, s...)
	}
	b := make([]byte, 16+len(body))
	binary.BigEndian.PutUint16(b[0:2], 10)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint32(b[4:8], 1_700_000_000)
	binary.BigEndian.PutUint32(b[8:12], seq)
	binary.BigEndian.PutUint32(b[12:16], domain)
	copy(b[16:], body)
	return b
}

func v9Header(count uint16, sysup, unixSecs, seq, source uint32) []byte {
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

func templatePacket(domain, seq uint32, id uint16) []byte {
	body := make([]byte, 16)
	binary.BigEndian.PutUint16(body[0:2], id)
	binary.BigEndian.PutUint16(body[2:4], 3)
	pairs := []uint16{8, 4, 12, 4, 2, 4}
	for i, v := range pairs {
		binary.BigEndian.PutUint16(body[4+2*i:6+2*i], v)
	}
	return append(v9Header(1, 0, 1_700_000_000, seq, domain), flowSet(0, body)...)
}

func dataOnly(seq, pkts uint32) []byte {
	rec := make([]byte, 12)
	binary.BigEndian.PutUint32(rec[0:4], 0x0a000001)
	binary.BigEndian.PutUint32(rec[4:8], 0x0a000002)
	binary.BigEndian.PutUint32(rec[8:12], pkts)
	return append(v9Header(1, 0, 1_700_000_000, seq, 4), flowSet(256, rec)...)
}

func packetsOf(flows []flow.Flow) []uint64 {
	out := make([]uint64, len(flows))
	for i, f := range flows {
		out[i] = f.Packets
	}
	return out
}

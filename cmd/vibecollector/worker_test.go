package main

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
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

func TestDecodeWorkerRecordsDelta(t *testing.T) {
	session, counters := testSession(t)
	sink := &recSink{}
	in := make(chan ingest.Datagram, 1)
	flows := make(chan flow.Flow, 1)
	in <- ingest.Datagram{
		Payload:    v5One(42),
		Src:        netip.MustParseAddr("192.0.2.9"),
		ReceivedAt: time.Unix(1_700_000_000, 0).UTC(),
	}
	close(in)
	decodeWorker(context.Background(), session, in, flows, sink, counters)
	got := <-flows
	if got.Packets != 42 || got.Version != 5 {
		t.Fatalf("%+v", got)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.submits != 0 || len(sink.deltas) != 1 || sink.deltas[0].Version != 5 || sink.deltas[0].Packets != 1 {
		t.Fatalf("submits %d deltas %+v", sink.submits, sink.deltas)
	}
	snap := counters.Snapshot()
	if snap[obs.DecodedPackets] != 1 || snap[obs.DecodedFlows] != 1 || snap[obs.DroppedEnrichQueue] != 0 {
		t.Fatal(snap[obs.DecodedPackets], snap[obs.DecodedFlows], snap[obs.DroppedEnrichQueue])
	}
}

func TestDecodeWorkerDropsFullFlowQueue(t *testing.T) {
	session, counters := testSession(t)
	sink := &recSink{}
	in := make(chan ingest.Datagram, 1)
	// Unbuffered and unread: every non-blocking send drops.
	flows := make(chan flow.Flow)
	in <- ingest.Datagram{
		Payload:    v5One(7),
		Src:        netip.MustParseAddr("192.0.2.9"),
		ReceivedAt: time.Unix(1_700_000_000, 0).UTC(),
	}
	close(in)
	decodeWorker(context.Background(), session, in, flows, sink, counters)
	snap := counters.Snapshot()
	if snap[obs.DroppedEnrichQueue] != 1 || snap[obs.DecodedPackets] != 1 || snap[obs.DecodedFlows] != 1 {
		t.Fatal(snap[obs.DroppedEnrichQueue], snap[obs.DecodedPackets], snap[obs.DecodedFlows])
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.submits != 0 || len(sink.deltas) != 1 {
		t.Fatalf("submits %d deltas %d", sink.submits, len(sink.deltas))
	}
}

func TestDecodeWorkerStopsOnCancel(t *testing.T) {
	session, counters := testSession(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		decodeWorker(ctx, session, make(chan ingest.Datagram), make(chan flow.Flow, 1), discardSink{}, counters)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker stuck")
	}
}

type recSink struct {
	mu      sync.Mutex
	deltas  []flow.ExporterDelta
	submits int
}

func (s *recSink) Submit([]flow.Flow) error {
	s.mu.Lock()
	s.submits++
	s.mu.Unlock()
	return nil
}

func (s *recSink) SubmitDelta(d flow.ExporterDelta) {
	s.mu.Lock()
	s.deltas = append(s.deltas, d)
	s.mu.Unlock()
}

func testSession(t *testing.T) (*decode.Session, *obs.Counters) {
	t.Helper()
	templates, err := template.NewCache(64)
	if err != nil {
		t.Fatal(err)
	}
	hold, err := template.NewHold(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	counters := obs.NewCounters()
	s, err := decode.NewSession(templates, hold, sampling.NewCache(), sequence.NewTable(), counters, 2*time.Hour, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return s, counters
}

func v5One(pkts uint32) []byte {
	b := make([]byte, 24+48)
	binary.BigEndian.PutUint16(b[0:2], 5)
	binary.BigEndian.PutUint16(b[2:4], 1)
	binary.BigEndian.PutUint32(b[8:12], 1_700_000_000)
	binary.BigEndian.PutUint32(b[24+16:24+20], pkts)
	return b
}

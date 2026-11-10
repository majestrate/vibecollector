package main

import (
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
	decodeWorker(session, in, flows, sink, counters, newIPOrder(), nil)
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
	decodeWorker(session, in, flows, sink, counters, newIPOrder(), nil)
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

func TestDecodeWorkerDrainsUntilClose(t *testing.T) {
	session, counters := testSession(t)
	in := make(chan ingest.Datagram, 1)
	flows := make(chan flow.Flow, 1)
	done := make(chan struct{})
	go func() {
		decodeWorker(session, in, flows, discardSink{}, counters, newIPOrder(), nil)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("worker returned before the channel closed")
	case <-time.After(50 * time.Millisecond):
	}
	in <- ingest.Datagram{
		Payload:    v5One(3),
		Src:        netip.MustParseAddr("192.0.2.9"),
		ReceivedAt: time.Unix(1_700_000_000, 0).UTC(),
	}
	select {
	case f := <-flows:
		if f.Packets != 3 {
			t.Fatal(f.Packets)
		}
	case <-done:
		t.Fatal("worker returned with a datagram queued")
	case <-time.After(time.Second):
		t.Fatal("queued datagram was not decoded")
	}
	close(in)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after close")
	}
}

func TestSameIPAcceptedInArrivalOrder(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.9")
	in := make(chan ingest.Datagram, 2)
	order := newIPOrder()
	entered := make(chan byte, 2)
	hold := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			decodeWorker(nil, in, nil, nil, nil, order, func(d ingest.Datagram) {
				entered <- d.Payload[0]
				if d.Payload[0] == 1 {
					<-hold
				}
			})
		}()
	}
	in <- ingest.Datagram{Payload: []byte{1}, Src: ip}
	in <- ingest.Datagram{Payload: []byte{2}, Src: ip}
	if got := <-entered; got != 1 {
		t.Fatalf("first %d", got)
	}
	select {
	case got := <-entered:
		t.Fatalf("later datagram accepted first: %d", got)
	case <-time.After(150 * time.Millisecond):
	}
	close(hold)
	if got := <-entered; got != 2 {
		t.Fatalf("second %d", got)
	}
	close(in)
	wg.Wait()
}

func TestDifferentIPsAcceptInParallel(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	in := make(chan ingest.Datagram, 2)
	order := newIPOrder()
	entered := make(chan netip.Addr, 2)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			decodeWorker(nil, in, nil, nil, nil, order, func(d ingest.Datagram) {
				entered <- d.Src
				<-release
			})
		}()
	}
	in <- ingest.Datagram{Payload: []byte{1}, Src: a}
	in <- ingest.Datagram{Payload: []byte{1}, Src: b}
	got := map[netip.Addr]bool{}
	timeout := time.After(time.Second)
	for len(got) < 2 {
		select {
		case ip := <-entered:
			got[ip] = true
		case <-timeout:
			t.Fatal("different sources did not overlap", got)
		}
	}
	close(release)
	close(in)
	wg.Wait()
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

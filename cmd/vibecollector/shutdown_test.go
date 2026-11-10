package main

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"vibecollector/internal/config"
	"vibecollector/internal/enrich"
	"vibecollector/internal/flow"
	"vibecollector/internal/obs"
)

func TestShutdownDrainsQueuedFlows(t *testing.T) {
	pipe := testShutdownPipe(t)
	sink := &countSink{}
	flows := make(chan flow.Flow, 2)
	flows <- shutdownFlow("10.0.0.1", "10.0.0.2")
	flows <- shutdownFlow("10.0.0.3", "10.0.0.4")
	pipeCtx, pipeCancel := context.WithCancel(context.Background())
	var pipeWG sync.WaitGroup
	pipeWG.Add(1)
	go func() {
		defer pipeWG.Done()
		_ = pipe.Run(pipeCtx, flows, sink)
	}()
	var drain sync.WaitGroup
	if !shutdown(func() {}, pipeCancel, flows, &drain, &pipeWG, nil) {
		t.Fatal("second signal")
	}
	if pipeCtx.Err() != nil {
		t.Fatal(pipeCtx.Err())
	}
	if n := sink.count(); n != 2 {
		t.Fatal(n)
	}
}

func TestShutdownBudgetSubmitsQueuedFlow(t *testing.T) {
	pipe := testShutdownPipe(t)
	sink := &countSink{}
	flows := make(chan flow.Flow, 1)
	flows <- shutdownFlow("10.1.0.1", "10.1.0.2")
	pipeCtx, pipeCancel := context.WithCancel(context.Background())
	var pipeWG sync.WaitGroup
	pipeWG.Add(1)
	go func() {
		defer pipeWG.Done()
		_ = pipe.Run(pipeCtx, flows, sink)
	}()
	var drain sync.WaitGroup
	drain.Add(1)
	release := make(chan struct{})
	go func() {
		defer drain.Done()
		<-release
	}()
	t.Cleanup(func() { close(release) })
	start := time.Now()
	if !shutdown(func() {}, pipeCancel, flows, &drain, &pipeWG, nil) {
		t.Fatal("second signal")
	}
	if time.Since(start) < 4*time.Second {
		t.Fatal(time.Since(start))
	}
	if pipeCtx.Err() == nil {
		t.Fatal("budget left the pipeline running")
	}
	if n := sink.count(); n != 1 {
		t.Fatal(n)
	}
}

func testShutdownPipe(t *testing.T) *enrich.Pipeline {
	t.Helper()
	cfg := &config.Config{}
	cfg.Enrich.CacheEntries = 8
	cfg.Enrich.LookupTimeout = time.Second
	cfg.Enrich.GeoIPTTL = time.Hour
	cfg.Enrich.ASNTTL = time.Hour
	cfg.Enrich.ReputationTTL = time.Hour
	p, err := newPipeline(cfg, obs.NewCounters())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func shutdownFlow(src, dst string) flow.Flow {
	return flow.Flow{
		Src:              netip.MustParseAddr(src),
		Dst:              netip.MustParseAddr(dst),
		Packets:          1,
		Octets:           1,
		CounterSemantics: "delta",
		OctetSemantics:   "ip",
	}
}

type countSink struct {
	mu sync.Mutex
	n  int
}

func (s *countSink) Submit(flows []flow.Flow) error {
	s.mu.Lock()
	s.n += len(flows)
	s.mu.Unlock()
	return nil
}

func (s *countSink) SubmitDelta(flow.ExporterDelta) {}

func (s *countSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

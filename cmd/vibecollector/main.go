package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"

	"vibecollector/internal/config"
	"vibecollector/internal/decode"
	_ "vibecollector/internal/decode/ipfix"
	_ "vibecollector/internal/decode/v5"
	_ "vibecollector/internal/decode/v9"
	"vibecollector/internal/flow"
	"vibecollector/internal/ingest"
	"vibecollector/internal/obs"
	"vibecollector/internal/sampling"
	"vibecollector/internal/sequence"
	"vibecollector/internal/template"
)

func main() {
	// Database files created later must be mode 0600 even if the ambient umask is loose.
	syscall.Umask(0o077)

	var flags config.Flags
	flag.StringVar(&flags.ConfigPath, "config", "", "TOML config file (default ./vibecollector.toml if present)")
	flag.StringVar(&flags.HTTP, "http", "", "override http.listen")
	flag.StringVar(&flags.UDP, "udp", "", "override udp.listen")
	flag.StringVar(&flags.DB, "db", "", "override db.path")
	flag.Parse()

	cfg, err := config.Load(flags)
	if err != nil {
		slog.Error("config", "err", err)
		if errors.Is(err, config.ErrUnknownField) ||
			errors.Is(err, config.ErrTokenRequired) ||
			errors.Is(err, config.ErrBadConfig) {
			os.Exit(2)
		}
		os.Exit(1)
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.Log.Level)); err != nil {
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
	for _, name := range cfg.ReservedSeen {
		slog.Info("enrich." + name + ": reserved table, ignored")
	}
	if cfg.LooseFileMode {
		// Startup check: slog.Warn on the default handler is dropped at error.
		slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn})).Warn("config file mode is looser than 0600")
	}

	os.Exit(run(cfg))
}

func run(cfg *config.Config) int {
	counters := obs.NewCounters()
	session, err := newSession(cfg, counters)
	if err != nil {
		slog.Error("session", "err", err)
		return 1
	}
	reader, err := ingest.NewReader(cfg.UDP, counters)
	if err != nil {
		slog.Error("udp", "err", err)
		if errors.Is(err, ingest.ErrBadConfig) {
			return 2
		}
		return 1
	}

	// main owns both queues. Workers send flows. They do not call Submit.
	// Nothing drains flows until the enrich pipeline exists.
	datagrams := make(chan ingest.Datagram, cfg.UDP.DatagramQueue)
	flows := make(chan flow.Flow, cfg.UDP.FlowQueue)
	sink := discardSink{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// One ticket sequence per source IP. Dequeue order is Accept order for
	// that IP; a shared channel alone lets a later datagram win the race.
	order := newIPOrder()
	fatalc := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := reader.Run(ctx, datagrams)
		close(datagrams)
		if err != nil {
			fatalc <- err
		}
	}()
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			decodeWorker(session, datagrams, flows, sink, counters, order, nil)
		}()
	}

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
		// Closing the socket makes Run return and close datagrams.
		// Workers drain what is already queued; they do not watch ctx.
		cancel()
		if !waitStop(&wg, sig) {
			return 1
		}
		return 0
	case err := <-fatalc:
		slog.Error("udp", "err", err)
		cancel()
		if !waitStop(&wg, sig) {
			return 1
		}
		return 1
	}
}

func newSession(cfg *config.Config, counters *obs.Counters) (*decode.Session, error) {
	templates, err := template.NewCache(50000)
	if err != nil {
		return nil, err
	}
	hold, err := template.NewHold(cfg.UDP.HoldPerExporter, cfg.UDP.HoldGlobal)
	if err != nil {
		return nil, err
	}
	return decode.NewSession(templates, hold, sampling.NewCache(), sequence.NewTable(), counters, cfg.UDP.TimestampMaxAge, cfg.UDP.TimestampSkewSlack)
}

// decodeWorker reads until in is closed. It does not stop on context
// cancellation: a datagram already queued is still decoded. The reader
// closes in after the socket stops, and the process gives that drain 5 seconds.
// A full flows send increments dropped_enrich_queue and continues.
// The send is non-blocking so a stalled enrich queue cannot stall the socket.
// Submit is not called. SubmitDelta takes the packet delta and each gap.
// accept, when non-nil, replaces Session.Accept. Production passes nil.
func decodeWorker(session *decode.Session, in <-chan ingest.Datagram, flows chan<- flow.Flow, sink flow.Sink, counters *obs.Counters, order *ipOrder, accept func(ingest.Datagram)) {
	if accept == nil {
		accept = func(d ingest.Datagram) {
			deliver(session, d, flows, sink, counters)
		}
	}
	for {
		d, release, ok := order.dequeue(in)
		if !ok {
			return
		}
		accept(d)
		release()
	}
}

// ipOrder is a per-source ticket taken at dequeue. Accept for one IP runs
// in arrival order. Different IPs do not wait on each other.
type ipOrder struct {
	mu   sync.Mutex
	cond *sync.Cond
	recv sync.Mutex
	next map[netip.Addr]uint64
	seq  map[netip.Addr]uint64
}

func newIPOrder() *ipOrder {
	o := &ipOrder{
		next: make(map[netip.Addr]uint64),
		seq:  make(map[netip.Addr]uint64),
	}
	o.cond = sync.NewCond(&o.mu)
	return o
}

// dequeue receives one datagram and blocks until earlier datagrams for that
// source have finished. The receive lock is not held across that wait.
func (o *ipOrder) dequeue(in <-chan ingest.Datagram) (ingest.Datagram, func(), bool) {
	o.recv.Lock()
	d, ok := <-in
	if !ok {
		o.recv.Unlock()
		return ingest.Datagram{}, nil, false
	}
	// Issue under the receive lock so the ticket matches dequeue order,
	// not whichever worker reaches Accept first.
	ticket := o.issue(d.Src)
	o.recv.Unlock()
	o.wait(d.Src, ticket)
	return d, func() { o.release(d.Src) }, true
}

func (o *ipOrder) issue(ip netip.Addr) uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := o.seq[ip]
	o.seq[ip] = n + 1
	return n
}

func (o *ipOrder) wait(ip netip.Addr, ticket uint64) {
	o.mu.Lock()
	for o.next[ip] != ticket {
		o.cond.Wait()
	}
	o.mu.Unlock()
}

func (o *ipOrder) release(ip netip.Addr) {
	o.mu.Lock()
	o.next[ip]++
	if o.next[ip] == o.seq[ip] {
		delete(o.next, ip)
		delete(o.seq, ip)
	}
	o.cond.Broadcast()
	o.mu.Unlock()
}

func deliver(session *decode.Session, d ingest.Datagram, flows chan<- flow.Flow, sink flow.Sink, counters *obs.Counters) {
	decoded, delta, gaps := session.Accept(d)
	var dropped uint64
	for _, f := range decoded {
		select {
		case flows <- f:
		default:
			dropped++
		}
	}
	if dropped > 0 {
		_ = counters.Add(obs.DroppedEnrichQueue, dropped)
	}
	// The packet was decoded even when every flow missed the queue.
	_ = counters.Add(obs.DecodedPackets, 1)
	if n := uint64(len(decoded)); n > 0 {
		_ = counters.Add(obs.DecodedFlows, n)
	}
	sink.SubmitDelta(delta)
	for _, g := range gaps {
		sink.SubmitDelta(g)
	}
}

// discardSink accepts deltas and drops them. There is no writer queue yet.
type discardSink struct{}

func (discardSink) Submit([]flow.Flow) error { return nil }

func (discardSink) SubmitDelta(flow.ExporterDelta) {}

// waitStop waits up to 5 seconds for the reader and workers.
// A second signal returns false so the process can exit 1.
func waitStop(wg *sync.WaitGroup, sig <-chan os.Signal) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		slog.Error("shutdown timed out")
		return true
	case <-sig:
		slog.Error("shutdown signal")
		return false
	}
}

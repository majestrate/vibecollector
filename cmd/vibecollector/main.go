package main

import (
	"context"
	"errors"
	"flag"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	_ "time/tzdata"

	"vibecollector/internal/api"
	"vibecollector/internal/config"
	"vibecollector/internal/decode"
	_ "vibecollector/internal/decode/ipfix"
	_ "vibecollector/internal/decode/v5"
	_ "vibecollector/internal/decode/v9"
	"vibecollector/internal/enrich"
	"vibecollector/internal/enrich/stub"
	"vibecollector/internal/flow"
	"vibecollector/internal/ingest"
	"vibecollector/internal/obs"
	"vibecollector/internal/sampling"
	"vibecollector/internal/sequence"
	"vibecollector/internal/store"
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
	db, err := store.Open(cfg.DB)
	if err != nil {
		slog.Error("db", "err", err)
		return 1
	}
	writer, err := store.NewWriter(db, cfg.DB, counters)
	if err != nil {
		slog.Error("writer", "err", err)
		return 1
	}
	sweeper, err := store.NewSweeper(db, cfg.DB, counters)
	if err != nil {
		slog.Error("sweeper", "err", err)
		return 1
	}
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
	query, err := store.NewQuery(db)
	if err != nil {
		slog.Error("query", "err", err)
		return 1
	}
	httpSrv, err := api.NewServer(cfg.HTTP, cfg.OAuth2, query, counters, emptyFS{})
	if err != nil {
		slog.Error("http", "err", err)
		return 1
	}
	// Not a child of the pipeline context: canceling HTTP must not drop the drain.
	httpCtx, httpCancel := context.WithCancel(context.Background())
	defer httpCancel()

	// main owns the flow queue. Decode workers send on it and do not call Submit.
	// Pipeline.Run is the only Submit caller.
	datagrams := make(chan ingest.Datagram, cfg.UDP.DatagramQueue)
	flows := make(chan flow.Flow, cfg.UDP.FlowQueue)
	pipe, err := newPipeline(cfg, counters)
	if err != nil {
		slog.Error("enrich", "err", err)
		return 1
	}

	// readerCtx closes the socket. pipeCtx stays live across the datagram
	// drain so decoded flows already in the queue are still enriched.
	readerCtx, readerCancel := context.WithCancel(context.Background())
	defer readerCancel()
	pipeCtx, pipeCancel := context.WithCancel(context.Background())
	defer pipeCancel()
	writerCtx, writerCancel := context.WithCancel(context.Background())
	defer writerCancel()
	sweeperCtx, sweeperCancel := context.WithCancel(context.Background())
	defer sweeperCancel()

	// One ticket sequence per source IP. Dequeue order is Accept order for
	// that IP; a shared channel alone lets a later datagram win the race.
	order := newIPOrder()
	fatalc := make(chan error, 1)
	var drainWG sync.WaitGroup
	var pipeWG sync.WaitGroup
	var writerWG sync.WaitGroup
	var sweeperWG sync.WaitGroup
	var writerErr error
	var sweeperErr error
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		writerErr = writer.Run(writerCtx)
	}()
	sweeperWG.Add(1)
	go func() {
		defer sweeperWG.Done()
		sweeperErr = sweeper.Run(sweeperCtx)
	}()
	drainWG.Add(1)
	go func() {
		defer drainWG.Done()
		err := reader.Run(readerCtx, datagrams)
		close(datagrams)
		if err != nil {
			fatalc <- err
		}
	}()
	for i := 0; i < 2; i++ {
		drainWG.Add(1)
		go func() {
			defer drainWG.Done()
			decodeWorker(session, datagrams, flows, writer, counters, order, nil)
		}()
	}
	pipeWG.Add(1)
	go func() {
		defer pipeWG.Done()
		// ErrQueueFull is counted inside Run, not here.
		_ = pipe.Run(pipeCtx, flows, writer)
	}()
	var httpWG sync.WaitGroup
	httpWG.Add(1)
	go func() {
		defer httpWG.Done()
		if err := httpSrv.ListenAndServe(httpCtx); err != nil {
			slog.Error("http", "err", err)
			select {
			case fatalc <- err:
			default:
			}
		}
	}()

	exit := 0
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
		if !shutdown(readerCancel, pipeCancel, flows, &drainWG, &pipeWG, sig) {
			return 1
		}
	case err := <-fatalc:
		slog.Error("udp", "err", err)
		if !shutdown(readerCancel, pipeCancel, flows, &drainWG, &pipeWG, sig) {
			return 1
		}
		exit = 1
	}
	// Pipeline.Run has returned. Stop deletes only after that drain, then
	// flush the writer and checkpoint.
	sweeperCancel()
	sweeperWG.Wait()
	if sweeperErr != nil {
		slog.Error("sweeper", "err", sweeperErr)
		exit = 1
	}
	writerCancel()
	writerWG.Wait()
	if writerErr != nil {
		slog.Error("writer", "err", writerErr)
		exit = 1
	}
	if err := db.Checkpoint(); err != nil {
		slog.Error("checkpoint", "err", err)
		exit = 1
	}
	httpCancel()
	httpDone := make(chan struct{})
	go func() {
		httpWG.Wait()
		close(httpDone)
	}()
	select {
	case <-httpDone:
	case <-time.After(5 * time.Second):
		slog.Error("http shutdown timed out")
	}
	return exit
}

// emptyFS is the UI tree until the UI package exists. Static files are not the REST API.
type emptyFS struct{}

func (emptyFS) Open(string) (fs.File, error) { return nil, fs.ErrNotExist }

// newPipeline builds the three stubs and their caches. Each log line is the
// startup statement that this process does not send addresses anywhere.
func newPipeline(cfg *config.Config, counters *obs.Counters) (*enrich.Pipeline, error) {
	caches := map[enrich.ProviderName]*enrich.Cache{}
	var providers []enrich.Provider
	for _, name := range []enrich.ProviderName{enrich.ProviderGeoIP, enrich.ProviderASN, enrich.ProviderReputation} {
		p, err := stub.New(name)
		if err != nil {
			return nil, err
		}
		providers = append(providers, p)
		c, err := enrich.NewCache(cfg.Enrich.CacheEntries)
		if err != nil {
			return nil, err
		}
		caches[name] = c
		slog.Info(string(name) + " provider: not configured, no outbound lookups")
	}
	return enrich.NewPipeline(providers, caches, cfg.Enrich, counters)
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

// discardSink drops flows and deltas. Tests use it when the writer is not the subject.
type discardSink struct{}

func (discardSink) Submit([]flow.Flow) error { return nil }

func (discardSink) SubmitDelta(flow.ExporterDelta) {}

// shutdown stops the reader and waits for decode workers to finish the
// datagram queue. It then closes flows so Pipeline.Run can return.
// The pipeline context stays active until that close. Cancelling it while
// workers are still decoding drops flows sent after the queue is sampled.
// A second signal returns false and the process exits 1. When the 5s budget
// fires first, the pipeline is cancelled and shutdown still returns true so
// the writer can flush what was submitted.
func shutdown(readerCancel, pipeCancel context.CancelFunc, flows chan flow.Flow, drain, pipe *sync.WaitGroup, sig <-chan os.Signal) bool {
	readerCancel()
	timedOut, signaled := waitStop(drain, sig)
	if signaled {
		return false
	}
	if !timedOut {
		close(flows)
	} else {
		pipeCancel()
	}
	timedOut, signaled = waitStop(pipe, sig)
	if signaled {
		return false
	}
	if timedOut {
		pipeCancel()
		_, signaled = waitStop(pipe, sig)
		if signaled {
			return false
		}
	}
	return true
}

// waitStop waits up to 5 seconds for wg.
// timedOut means the budget fired. signaled means a second signal.
func waitStop(wg *sync.WaitGroup, sig <-chan os.Signal) (timedOut, signaled bool) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
		return false, false
	case <-timer.C:
		slog.Error("shutdown timed out")
		return true, false
	case <-sig:
		slog.Error("shutdown signal")
		return false, true
	}
}

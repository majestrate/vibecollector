package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
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
			decodeWorker(ctx, session, datagrams, flows, sink, counters)
		}()
	}

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
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

// decodeWorker reads datagrams until ctx is cancelled or in is closed.
// A full flows send increments dropped_enrich_queue and continues.
// The send is non-blocking so a stalled enrich queue cannot stall the socket.
// Submit is not called. SubmitDelta takes the packet delta and each gap.
func decodeWorker(ctx context.Context, session *decode.Session, in <-chan ingest.Datagram, flows chan<- flow.Flow, sink flow.Sink, counters *obs.Counters) {
	for {
		select {
		case <-ctx.Done():
			return
		case d, ok := <-in:
			if !ok {
				return
			}
			deliver(session, d, flows, sink, counters)
		}
	}
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

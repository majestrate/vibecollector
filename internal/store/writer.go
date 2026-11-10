package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"sync"
	"time"

	"vibecollector/internal/config"
	"vibecollector/internal/flow"
	"vibecollector/internal/obs"

	"modernc.org/sqlite"
)

// writerQueue is the enriched-flow queue Submit fills.
// A send that would block returns flow.ErrQueueFull.
const writerQueue = 80000

// deltaQueue is the buffer in front of the pending map. A full send merges
// instead of dropping.
const deltaQueue = 16384

// ErrNilDep means db or counters was nil. NewWriter returns it and does not
// start a goroutine. errors.Is reports this sentinel.
var ErrNilDep = errors.New("nil dependency")

// ErrBadConfig means the batch size is below 1. NewWriter returns it and does
// not start a goroutine. errors.Is reports this sentinel.
var ErrBadConfig = errors.New("invalid configuration")

// Writer inserts flows, exporter deltas, and the additive rollups traffic_1m,
// asn_1m, and geo_country_5m. It implements flow.Sink. Submit and SubmitDelta
// are safe for concurrent callers. Run is the single inserter. Sweeper deletes
// expired rows in other transactions.
type Writer struct {
	db       *DB
	counters *obs.Counters
	batch    int
	interval time.Duration

	flows  chan flow.Flow
	deltas chan flow.ExporterDelta

	mu      sync.Mutex
	pending map[deltaKey]flow.ExporterDelta
}

type deltaKey struct {
	exporter string
	domain   uint32
	version  uint16
}

// NewWriter stores the pool, the batch size, the batch interval, and the counters.
// db is the opened pool. cfg.BatchSize is how many queued flows start a batch.
// cfg.BatchInterval is how long Run waits before flushing a shorter batch.
// A non-positive interval does not start a timer; batches then start at
// cfg.BatchSize and on the final flush. counters receives sqlite_write_failures
// and sqlite_rows_written. A nil db or nil counters returns ErrNilDep. A batch
// size below 1 returns ErrBadConfig. NewWriter does not start Run and does not
// touch the database.
func NewWriter(db *DB, cfg config.DB, counters *obs.Counters) (*Writer, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: db", ErrNilDep)
	}
	if counters == nil {
		return nil, fmt.Errorf("%w: counters", ErrNilDep)
	}
	if cfg.BatchSize < 1 {
		return nil, fmt.Errorf("%w: batch_size", ErrBadConfig)
	}
	return &Writer{
		db:       db,
		counters: counters,
		batch:    cfg.BatchSize,
		interval: cfg.BatchInterval,
		flows:    make(chan flow.Flow, writerQueue),
		deltas:   make(chan flow.ExporterDelta, deltaQueue),
		pending:  make(map[deltaKey]flow.ExporterDelta),
	}, nil
}

// Submit enqueues enriched flows for the next batch.
// flows are the records the pipeline already annotated. Each is sent on a
// queue of 80,000. A nil error means every flow in this call was queued.
// ErrQueueFull means the next send would have blocked; that flow and any
// after it in this call are not queued, and flows already sent stay queued.
// Submit does not block and does not change counters. The caller drops the
// flows ErrQueueFull refused.
func (w *Writer) Submit(flows []flow.Flow) error {
	for i := range flows {
		select {
		case w.flows <- flows[i]:
		default:
			return flow.ErrQueueFull
		}
	}
	return nil
}

// SubmitDelta enqueues one exporter delta.
// d's counters are added, in the next batch, to the exporter row keyed by
// d.Exporter, d.Domain, and d.Version. LastSeen becomes the later timestamp
// when two deltas share that key. When the delta queue of 16,384 cannot take
// d without blocking, d is merged into the pending map under that key.
// SubmitDelta does not return an error and does not drop a delta.
func (w *Writer) SubmitDelta(d flow.ExporterDelta) {
	select {
	case w.deltas <- d:
	default:
		w.mu.Lock()
		mergeDelta(w.pending, d)
		w.mu.Unlock()
	}
}

// Run writes batches until ctx is cancelled, then flushes one last batch.
// A batch starts when batch_size flows are queued or batch_interval elapses,
// and on that final flush. Each batch is one BEGIN IMMEDIATE transaction:
// exporter deltas, including the pending map, then the flows, then additive
// upserts into traffic_1m, asn_1m, and geo_country_5m. A flow is eligible for
// those rollups when its counter semantics are delta and its octet semantics
// are ip. Total and l4_payload flows are stored and omitted from the rollups.
// The primary octet value is Flow.Octets; OutOctets is not added again.
// When Sweeper has seen under 5 GiB free on the database volume, the batch
// still commits exporter deltas and rollups, skips the flows insert, and
// adds one dropped_disk per skipped flow. UDP does not wait on that decision.
// A SQLite error rolls that batch back, increments sqlite_write_failures,
// logs the error class, drops the batch, and Run continues with the next one.
// It does not retry the batch. sqlite_rows_written counts inserted flow rows
// in a committed batch, not flows skipped while disk shed is on. The returned
// error is non-nil only when ctx is done and
// the last flush fails. A cancelled ctx with a successful last flush, or with
// nothing left to write, returns nil.
func (w *Writer) Run(ctx context.Context) error {
	n := w.batch
	if n > writerQueue {
		n = writerQueue
	}
	batch := make([]flow.Flow, 0, n)
	var timer *time.Timer
	var ticks <-chan time.Time
	if w.interval > 0 {
		timer = time.NewTimer(w.interval)
		defer timer.Stop()
		ticks = timer.C
	}
	for {
		select {
		case <-ctx.Done():
			batch = append(batch, drainFlows(w.flows)...)
			return w.flush(batch)
		case f := <-w.flows:
			batch = append(batch, f)
			if len(batch) >= w.batch {
				_ = w.flush(batch)
				batch = batch[:0]
				resetTimer(timer, w.interval)
			}
		case <-ticks:
			if len(batch) > 0 || w.hasDeltas() {
				_ = w.flush(batch)
				batch = batch[:0]
			}
			resetTimer(timer, w.interval)
		}
	}
}

func (w *Writer) hasDeltas() bool {
	if len(w.deltas) > 0 {
		return true
	}
	w.mu.Lock()
	n := len(w.pending)
	w.mu.Unlock()
	return n > 0
}

func (w *Writer) flush(flows []flow.Flow) error {
	deltas := w.takeDeltas()
	if len(flows) == 0 && len(deltas) == 0 {
		return nil
	}
	shed := w.db.shedRaw.Load()
	rolled := fold(flows)
	if err := w.writeBatch(flows, deltas, rolled, shed); err != nil {
		_ = w.counters.Add(obs.SQLiteWriteFailures, 1)
		slog.Error("sqlite write", "class", sqliteErrClass(err))
		return err
	}
	if shed {
		if n := len(flows); n > 0 {
			_ = w.counters.Add(obs.DroppedDisk, uint64(n))
		}
		return nil
	}
	if len(flows) > 0 {
		_ = w.counters.Add(obs.SQLiteRowsWritten, uint64(len(flows)))
	}
	return nil
}

func (w *Writer) takeDeltas() map[deltaKey]flow.ExporterDelta {
	out := make(map[deltaKey]flow.ExporterDelta)
	for {
		select {
		case d := <-w.deltas:
			mergeDelta(out, d)
		default:
			goto pending
		}
	}
pending:
	w.mu.Lock()
	for _, d := range w.pending {
		mergeDelta(out, d)
	}
	w.pending = make(map[deltaKey]flow.ExporterDelta, len(w.pending))
	w.mu.Unlock()
	return out
}

func mergeDelta(dst map[deltaKey]flow.ExporterDelta, d flow.ExporterDelta) {
	k := deltaKeyOf(d)
	prev, ok := dst[k]
	if !ok {
		dst[k] = d
		return
	}
	prev.Packets += d.Packets
	prev.Flows += d.Flows
	prev.Malformed += d.Malformed
	prev.MissingTemplate += d.MissingTemplate
	prev.GapFlows += d.GapFlows
	prev.GapPackets += d.GapPackets
	prev.GapRecords += d.GapRecords
	if d.LastSeen.After(prev.LastSeen) {
		prev.LastSeen = d.LastSeen
	}
	dst[k] = prev
}

func deltaKeyOf(d flow.ExporterDelta) deltaKey {
	return deltaKey{exporter: d.Exporter.Unmap().String(), domain: d.Domain, version: d.Version}
}

func drainFlows(ch <-chan flow.Flow) []flow.Flow {
	var out []flow.Flow
	for {
		select {
		case f := <-ch:
			out = append(out, f)
		default:
			return out
		}
	}
}

func resetTimer(timer *time.Timer, d time.Duration) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}

func sqliteErrClass(err error) string {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return "sqlite"
	}
	if s, ok := sqlite.ErrorCodeString[se.Code()]; ok {
		return s
	}
	if s, ok := sqlite.ErrorCodeString[se.Code()&0xff]; ok {
		return s
	}
	return "sqlite"
}

func (w *Writer) writeBatch(flows []flow.Flow, deltas map[deltaKey]flow.ExporterDelta, rolled rollups, shed bool) error {
	ctx := context.Background()
	conn, err := w.db.pool.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	if err := insertDeltas(ctx, conn, deltas); err != nil {
		return err
	}
	// Raw rows stop. Rollups below still come from this in-memory batch.
	if !shed {
		if err := insertFlows(ctx, conn, flows); err != nil {
			return err
		}
	}
	if err := insertRollups(ctx, conn, rolled); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

const insertExporterSQL = `INSERT INTO exporters (
  exporter, domain, version, last_seen_ms,
  packets, flows, malformed, missing_template,
  gap_flows, gap_packets, gap_records
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (exporter, domain, version) DO UPDATE SET
  packets = packets + excluded.packets,
  flows = flows + excluded.flows,
  malformed = malformed + excluded.malformed,
  missing_template = missing_template + excluded.missing_template,
  gap_flows = gap_flows + excluded.gap_flows,
  gap_packets = gap_packets + excluded.gap_packets,
  gap_records = gap_records + excluded.gap_records,
  last_seen_ms = max(last_seen_ms, excluded.last_seen_ms)`

func insertDeltas(ctx context.Context, conn *sql.Conn, deltas map[deltaKey]flow.ExporterDelta) error {
	if len(deltas) == 0 {
		return nil
	}
	stmt, err := conn.PrepareContext(ctx, insertExporterSQL)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for k, d := range deltas {
		if _, err := stmt.ExecContext(ctx,
			k.exporter, int64(k.domain), int64(k.version), d.LastSeen.UnixMilli(),
			fitInt(d.Packets), fitInt(d.Flows), fitInt(d.Malformed), fitInt(d.MissingTemplate),
			fitInt(d.GapFlows), fitInt(d.GapPackets), fitInt(d.GapRecords),
		); err != nil {
			return err
		}
	}
	return nil
}

const insertFlowSQL = `INSERT INTO flows (
  flow_start_ms, flow_end_ms, received_ms, export_time_s, time_source, clock_clamped,
  exporter, domain, version, src, dst,
  src_port, dst_port, ip_proto, tcp_flags, tos, flow_direction,
  packets, octets, counter_semantics, octet_semantics,
  out_packets, out_octets,
  input_if, output_if, nexthop,
  bgp_src_as, bgp_dst_as, src_mask, dst_mask,
  sampled, sampling_interval, sampling_algorithm,
  src_scope, dst_scope,
  src_geo_outcome, dst_geo_outcome, src_asn_outcome, dst_asn_outcome, src_rep_outcome, dst_rep_outcome,
  src_country, src_region, src_city, src_lat, src_lon,
  dst_country, dst_region, dst_city, dst_lat, dst_lon,
  src_asn, src_asn_name, dst_asn, dst_asn_name,
  src_rep_category, src_rep_score, dst_rep_category, dst_rep_score
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

func insertFlows(ctx context.Context, conn *sql.Conn, flows []flow.Flow) error {
	if len(flows) == 0 {
		return nil
	}
	stmt, err := conn.PrepareContext(ctx, insertFlowSQL)
	if err != nil {
		return err
	}
	defer stmt.Close()
	args := make([]any, 0, 59)
	for i := range flows {
		args = flowArgs(&flows[i], args[:0])
		if _, err := stmt.ExecContext(ctx, args...); err != nil {
			return err
		}
	}
	return nil
}

func flowArgs(f *flow.Flow, args []any) []any {
	return append(args,
		f.Start.UnixMilli(),
		f.End.UnixMilli(),
		f.ReceivedAt.UnixMilli(),
		exportSeconds(f.ExportTime),
		timeSourceText(f.TimeSource),
		boolInt(f.ClockClamped),
		f.Exporter.String(),
		int64(f.Domain),
		int64(f.Version),
		f.Src.String(),
		f.Dst.String(),
		optU16(f.PortsPresent, f.SrcPort),
		optU16(f.PortsPresent, f.DstPort),
		optU8(f.ProtoPresent, f.Proto),
		optU8(f.TCPFlagsPresent, f.TCPFlags),
		optU8(f.TOSPresent, f.TOS),
		optPtrU8(f.FlowDirection),
		fitInt(f.Packets),
		fitInt(f.Octets),
		f.CounterSemantics,
		f.OctetSemantics,
		optPtrU64(f.OutPackets),
		optPtrU64(f.OutOctets),
		optPtrU32(f.InputIf),
		optPtrU32(f.OutputIf),
		optAddr(f.NextHop),
		optPtrU32(f.BGPSrcAS),
		optPtrU32(f.BGPDstAS),
		optPtrU8(f.SrcMask),
		optPtrU8(f.DstMask),
		boolInt(f.Sampled),
		optPtrU32(f.SamplingInterval),
		optPtrU8(f.SamplingAlgorithm),
		string(f.SrcEnrich.Scope),
		string(f.DstEnrich.Scope),
		string(f.SrcEnrich.Geo.Kind),
		string(f.DstEnrich.Geo.Kind),
		string(f.SrcEnrich.ASN.Kind),
		string(f.DstEnrich.ASN.Kind),
		string(f.SrcEnrich.Rep.Kind),
		string(f.DstEnrich.Rep.Kind),
		nullString(f.SrcEnrich.Geo.Country),
		nullString(f.SrcEnrich.Geo.Region),
		nullString(f.SrcEnrich.Geo.City),
		optLatLon(f.SrcEnrich.Geo.HasLatLon, f.SrcEnrich.Geo.Lat),
		optLatLon(f.SrcEnrich.Geo.HasLatLon, f.SrcEnrich.Geo.Lon),
		nullString(f.DstEnrich.Geo.Country),
		nullString(f.DstEnrich.Geo.Region),
		nullString(f.DstEnrich.Geo.City),
		optLatLon(f.DstEnrich.Geo.HasLatLon, f.DstEnrich.Geo.Lat),
		optLatLon(f.DstEnrich.Geo.HasLatLon, f.DstEnrich.Geo.Lon),
		storedASN(f.SrcEnrich.ASN),
		storedASNName(f.SrcEnrich.ASN),
		storedASN(f.DstEnrich.ASN),
		storedASNName(f.DstEnrich.ASN),
		storedCategory(f.SrcEnrich.Rep),
		storedScore(f.SrcEnrich.Rep),
		storedCategory(f.DstEnrich.Rep),
		storedScore(f.DstEnrich.Rep),
	)
}

const insertTrafficSQL = `INSERT INTO traffic_1m (
  bucket_ms, exporter, ip_proto, sampled, packets, octets, flows
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (bucket_ms, exporter, ip_proto, sampled) DO UPDATE SET
  packets = packets + excluded.packets,
  octets = octets + excluded.octets,
  flows = flows + excluded.flows`

const insertASNSQL = `INSERT INTO asn_1m (
  bucket_ms, asn, direction, from_export, packets, octets, flows
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (bucket_ms, asn, direction, from_export) DO UPDATE SET
  packets = packets + excluded.packets,
  octets = octets + excluded.octets,
  flows = flows + excluded.flows`

const insertASNNameSQL = `INSERT INTO asn_names (asn, name, updated_ms) VALUES (?, ?, ?)
ON CONFLICT (asn) DO UPDATE SET
  name = excluded.name,
  updated_ms = excluded.updated_ms
WHERE excluded.updated_ms >= asn_names.updated_ms`

const insertGeoSQL = `INSERT INTO geo_country_5m (
  bucket_ms, country, packets, octets, flows
) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (bucket_ms, country) DO UPDATE SET
  packets = packets + excluded.packets,
  octets = octets + excluded.octets,
  flows = flows + excluded.flows`

func insertRollups(ctx context.Context, conn *sql.Conn, r rollups) error {
	if err := insertTraffic(ctx, conn, r.traffic); err != nil {
		return err
	}
	if err := insertASN(ctx, conn, r.asn); err != nil {
		return err
	}
	if err := insertNames(ctx, conn, r.names); err != nil {
		return err
	}
	return insertGeo(ctx, conn, r.geo)
}

func insertTraffic(ctx context.Context, conn *sql.Conn, m map[trafficKey]counts) error {
	if len(m) == 0 {
		return nil
	}
	stmt, err := conn.PrepareContext(ctx, insertTrafficSQL)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for k, c := range m {
		if _, err := stmt.ExecContext(ctx, k.bucket, k.exporter, k.proto, k.sampled, fitInt(c.packets), fitInt(c.octets), fitInt(c.flows)); err != nil {
			return err
		}
	}
	return nil
}

func insertASN(ctx context.Context, conn *sql.Conn, m map[asnKey]counts) error {
	if len(m) == 0 {
		return nil
	}
	stmt, err := conn.PrepareContext(ctx, insertASNSQL)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for k, c := range m {
		if _, err := stmt.ExecContext(ctx, k.bucket, k.asn, k.direction, k.fromExport, fitInt(c.packets), fitInt(c.octets), fitInt(c.flows)); err != nil {
			return err
		}
	}
	return nil
}

func insertNames(ctx context.Context, conn *sql.Conn, m map[uint32]asnName) error {
	if len(m) == 0 {
		return nil
	}
	stmt, err := conn.PrepareContext(ctx, insertASNNameSQL)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for asn, rec := range m {
		if _, err := stmt.ExecContext(ctx, int64(asn), rec.name, rec.updated); err != nil {
			return err
		}
	}
	return nil
}

func insertGeo(ctx context.Context, conn *sql.Conn, m map[geoKey]counts) error {
	if len(m) == 0 {
		return nil
	}
	stmt, err := conn.PrepareContext(ctx, insertGeoSQL)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for k, c := range m {
		if _, err := stmt.ExecContext(ctx, k.bucket, k.country, fitInt(c.packets), fitInt(c.octets), fitInt(c.flows)); err != nil {
			return err
		}
	}
	return nil
}

type counts struct {
	packets uint64
	octets  uint64
	flows   uint64
}

func (c *counts) add(packets, octets uint64) {
	c.packets += packets
	c.octets += octets
	c.flows++
}

type trafficKey struct {
	bucket   int64
	exporter string
	proto    int
	sampled  int
}

type asnKey struct {
	bucket     int64
	asn        int64
	direction  string
	fromExport int
}

type geoKey struct {
	bucket  int64
	country string
}

type asnName struct {
	name    string
	updated int64
}

type rollups struct {
	traffic map[trafficKey]counts
	asn     map[asnKey]counts
	names   map[uint32]asnName
	geo     map[geoKey]counts
}

func fold(flows []flow.Flow) rollups {
	r := rollups{
		traffic: make(map[trafficKey]counts),
		asn:     make(map[asnKey]counts),
		names:   make(map[uint32]asnName),
		geo:     make(map[geoKey]counts),
	}
	for i := range flows {
		f := &flows[i]
		if f.CounterSemantics != "delta" || f.OctetSemantics != "ip" {
			continue
		}
		addTraffic(&r, f)
		addCountries(&r, f)
		addASNEnd(&r, f, "src", f.SrcEnrich, f.BGPSrcAS)
		addASNEnd(&r, f, "dst", f.DstEnrich, f.BGPDstAS)
	}
	return r
}

func addTraffic(r *rollups, f *flow.Flow) {
	proto := -1
	if f.ProtoPresent {
		proto = int(f.Proto)
	}
	k := trafficKey{
		bucket:   minuteBucket(f.Start),
		exporter: f.Exporter.String(),
		proto:    proto,
		sampled:  boolInt(f.Sampled),
	}
	c := r.traffic[k]
	// OutOctets is the other direction, not a second copy of the primary.
	c.add(f.Packets, f.Octets)
	r.traffic[k] = c
}

func addCountries(r *rollups, f *flow.Flow) {
	bucket := fiveBucket(f.Start)
	addCountry(r, bucket, f.SrcEnrich, f.Packets, f.Octets)
	addCountry(r, bucket, f.DstEnrich, f.Packets, f.Octets)
}

func addCountry(r *rollups, bucket int64, ep flow.Endpoint, packets, octets uint64) {
	if ep.Scope != "global" || ep.Geo.Kind != flow.OutcomeValue || ep.Geo.Country == "" {
		return
	}
	k := geoKey{bucket: bucket, country: ep.Geo.Country}
	c := r.geo[k]
	c.add(packets, octets)
	r.geo[k] = c
}

func addASNEnd(r *rollups, f *flow.Flow, direction string, ep flow.Endpoint, bgp *uint32) {
	var asn int64
	fromExport := 0
	switch {
	case ep.ASN.Kind == flow.OutcomeValue:
		asn = int64(ep.ASN.ASN)
	case bgp != nil:
		asn = int64(*bgp)
		fromExport = 1
	default:
		return
	}
	k := asnKey{bucket: minuteBucket(f.Start), asn: asn, direction: direction, fromExport: fromExport}
	c := r.asn[k]
	c.add(f.Packets, f.Octets)
	r.asn[k] = c
	if fromExport == 0 && ep.ASN.ASNName != "" {
		updated := f.ReceivedAt.UnixMilli()
		prev, ok := r.names[ep.ASN.ASN]
		if !ok || updated >= prev.updated {
			r.names[ep.ASN.ASN] = asnName{name: ep.ASN.ASNName, updated: updated}
		}
	}
}

func minuteBucket(t time.Time) int64 {
	return t.UTC().Truncate(time.Minute).UnixMilli()
}

func fiveBucket(t time.Time) int64 {
	return t.UTC().Truncate(5 * time.Minute).UnixMilli()
}

func timeSourceText(s flow.TimeSource) string {
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
		return "receive"
	}
}

func exportSeconds(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.Unix()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// SQLite integers are signed. A counter above MaxInt64 is stored saturated.
func fitInt(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

func optU16(present bool, v uint16) any {
	if !present {
		return nil
	}
	return int64(v)
}

func optU8(present bool, v uint8) any {
	if !present {
		return nil
	}
	return int64(v)
}

func optPtrU8(p *uint8) any {
	if p == nil {
		return nil
	}
	return int64(*p)
}

func optPtrU32(p *uint32) any {
	if p == nil {
		return nil
	}
	return int64(*p)
}

func optPtrU64(p *uint64) any {
	if p == nil {
		return nil
	}
	return fitInt(*p)
}

func optAddr(p *netip.Addr) any {
	if p == nil {
		return nil
	}
	return p.String()
}

func optLatLon(ok bool, v float64) any {
	if !ok {
		return nil
	}
	return v
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func storedASN(o flow.Outcome) any {
	if o.Kind != flow.OutcomeValue {
		return nil
	}
	return int64(o.ASN)
}

func storedASNName(o flow.Outcome) any {
	if o.Kind != flow.OutcomeValue || o.ASNName == "" {
		return nil
	}
	return o.ASNName
}

func storedCategory(o flow.Outcome) any {
	if o.Category == "" {
		return nil
	}
	return o.Category
}

func storedScore(o flow.Outcome) any {
	if !o.HasScore {
		return nil
	}
	return o.Score
}

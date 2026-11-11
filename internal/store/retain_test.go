package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/majestrate/vibecollector/internal/config"
	"github.com/majestrate/vibecollector/internal/flow"
	"github.com/majestrate/vibecollector/internal/obs"
)

func TestNewSweeperRejectsNil(t *testing.T) {
	if _, err := NewSweeper(nil, config.DB{}, obs.NewCounters()); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
	db, _, _, _ := openSweep(t, time.Hour, time.Hour)
	if _, err := NewSweeper(db, config.DB{}, nil); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
}

func TestSweeperRunReturnsNilOnCancel(t *testing.T) {
	_, sw, _, _ := openSweep(t, time.Hour, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sw.Run(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestStatfsErrorKeepsShedAndDeletes(t *testing.T) {
	const raw = time.Hour
	now := time.Unix(1_800_000_000, 0).UTC()
	prevNow := sweeperNow
	sweeperNow = func() time.Time { return now }
	t.Cleanup(func() { sweeperNow = prevNow })

	db, sw, _, counters := openSweep(t, raw, 24*time.Hour)
	db.shedRaw.Store(true)
	insertPlainFlow(t, db, now.Add(-2*raw), "192.0.2.80")
	insertPlainFlow(t, db, now.Add(-raw/2), "192.0.2.81")

	prevFree := freeBytes
	t.Cleanup(func() { freeBytes = prevFree })
	freeBytes = func(string) (uint64, error) {
		return 0, errors.New("statfs")
	}
	sw.pass(context.Background())

	if !db.shedRaw.Load() {
		t.Fatal("shed flag cleared")
	}
	if mustCount(t, db, `SELECT COUNT(*) FROM flows WHERE exporter = ?`, "192.0.2.80") != 0 {
		t.Fatal("expired flow remains")
	}
	if mustCount(t, db, `SELECT COUNT(*) FROM flows WHERE exporter = ?`, "192.0.2.81") != 1 {
		t.Fatal("in-horizon flow missing")
	}
	if got := counters.Snapshot()[obs.DroppedDisk]; got != 0 {
		t.Fatal(got)
	}
}

func TestStatfsFreeReadsVolume(t *testing.T) {
	n, err := statfsFree(t.TempDir())
	if err != nil || n == 0 {
		t.Fatal(err, n)
	}
}

func TestSweeperDeletesExpiredFlows(t *testing.T) {
	const (
		raw    = time.Hour
		rollup = 24 * time.Hour
		bulkN  = 120_000
	)
	now := time.Unix(1_800_000_000, 0).UTC()
	prevNow := sweeperNow
	sweeperNow = func() time.Time { return now }
	t.Cleanup(func() { sweeperNow = prevNow })

	db, sw, _, _ := openSweep(t, raw, rollup)
	insertPlainFlows(t, db, bulkN, now.Add(-2*raw), "192.0.2.8")
	insertPlainFlow(t, db, now.Add(-raw/2), "192.0.2.50")
	insertPlainFlow(t, db, now.Add(-raw), "192.0.2.51")
	insertRollupPair(t, db, now.Add(-2*rollup).UnixMilli(), now.Add(-2*time.Hour).UnixMilli())
	if _, err := db.pool.Exec(`INSERT INTO asn_names (asn, name, updated_ms) VALUES (1, 'kept', 0)`); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- sw.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errc:
			if err != nil {
				t.Errorf("sweeper run: %v", err)
			}
		case <-time.After(20 * time.Second):
			t.Error("sweeper did not return")
		}
	})

	rawCutoff := now.Add(-raw).UnixMilli()
	rollupCutoff := now.Add(-rollup).UnixMilli()
	deadline := time.Now().Add(60 * time.Second)
	for {
		left := mustCount(t, db, `SELECT COUNT(*) FROM flows`)
		oldOther := mustCount(t, db, `SELECT COUNT(*) FROM geo_path_other_5m WHERE bucket_ms < ?`, rollupCutoff)
		if left == 2 && oldOther == 0 {
			break
		}
		if left < 2 || time.Now().After(deadline) {
			t.Fatalf("flows %d old geo_path_other %d", left, oldOther)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM flows WHERE flow_start_ms < ?`, rawCutoff); n != 0 {
		t.Fatalf("expired flows %d", n)
	}
	if n := mustCount(t, db, `SELECT COUNT(*) FROM flows WHERE exporter = ?`, "192.0.2.8"); n != 0 {
		t.Fatalf("bulk exporter rows %d", n)
	}
	if mustCount(t, db, `SELECT COUNT(*) FROM flows WHERE exporter = ?`, "192.0.2.50") != 1 ||
		mustCount(t, db, `SELECT COUNT(*) FROM flows WHERE exporter = ?`, "192.0.2.51") != 1 {
		t.Fatal("in-horizon rows missing")
	}
	for _, table := range rollupTables {
		if n := mustCount(t, db, `SELECT COUNT(*) FROM `+table+` WHERE bucket_ms < ?`, rollupCutoff); n != 0 {
			t.Fatalf("%s expired %d", table, n)
		}
		if n := mustCount(t, db, `SELECT COUNT(*) FROM `+table); n != 1 {
			t.Fatalf("%s rows %d", table, n)
		}
	}
	if mustCount(t, db, `SELECT COUNT(*) FROM asn_names`) != 1 {
		t.Fatal("asn_names swept")
	}
}

func TestSweeperDeletesClampedFutureClock(t *testing.T) {
	const raw = time.Hour
	db, sw, w, _ := openSweep(t, raw, 24*time.Hour)
	recv := time.Unix(1_700_000_000, 123_000_000).UTC()
	start := recv.Add(5 * time.Second)
	f := eligibleShape(start, recv, "192.0.2.70")
	f.ClockClamped = true
	f.End = start
	if err := w.Submit([]flow.Flow{f}); err != nil {
		t.Fatal(err)
	}
	flushWriter(t, w)

	var clamped int
	var startMS, recvMS int64
	err := db.pool.QueryRow(`SELECT clock_clamped, flow_start_ms, received_ms FROM flows`).Scan(&clamped, &startMS, &recvMS)
	if err != nil {
		t.Fatal(err)
	}
	if clamped != 1 || recvMS != recv.UnixMilli() || startMS != recv.UnixMilli()+5000 {
		t.Fatalf("clamped %d start %d recv %d", clamped, startMS, recvMS)
	}

	prevNow := sweeperNow
	t.Cleanup(func() { sweeperNow = prevNow })
	stored := time.UnixMilli(startMS).UTC()
	sweeperNow = func() time.Time { return stored.Add(raw) }
	sw.pass(context.Background())
	if mustCount(t, db, `SELECT COUNT(*) FROM flows`) != 1 {
		t.Fatal("deleted before retention passed the stored timestamp")
	}
	sweeperNow = func() time.Time { return stored.Add(raw).Add(time.Millisecond) }
	sw.pass(context.Background())
	if mustCount(t, db, `SELECT COUNT(*) FROM flows`) != 0 {
		t.Fatal("stored timestamp still present")
	}
}

func TestDiskShedSkipsRawKeepsRollupAndDeletes(t *testing.T) {
	db, sw, w, counters := openSweep(t, time.Hour, time.Hour)
	prevFree := freeBytes
	t.Cleanup(func() { freeBytes = prevFree })

	at := time.Now().UTC()
	freeBytes = func(string) (uint64, error) { return diskShedBytes, nil }
	sw.pass(context.Background())
	if db.shedRaw.Load() {
		t.Fatal("shed at exactly 5 GiB")
	}
	kept := eligibleShape(at, at, "192.0.2.60")
	if err := w.Submit([]flow.Flow{kept}); err != nil {
		t.Fatal(err)
	}
	flushWriter(t, w)
	if got := counters.Snapshot()[obs.DroppedDisk]; got != 0 {
		t.Fatal(got)
	}
	if mustCount(t, db, `SELECT COUNT(*) FROM flows WHERE exporter = ?`, "192.0.2.60") != 1 {
		t.Fatal("kept flow missing")
	}

	old := at.Add(-2 * time.Hour)
	insertPlainFlow(t, db, old, "192.0.2.62")
	if _, err := db.pool.Exec(`INSERT INTO traffic_1m (bucket_ms, exporter, ip_proto, sampled, packets, octets, flows) VALUES (?, '192.0.2.62', -1, 0, 1, 1, 1)`, old.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	queued := eligibleShape(at, at, "192.0.2.61")
	queued.Packets = 4
	queued.Octets = 40
	if err := w.Submit([]flow.Flow{queued}); err != nil {
		t.Fatal(err)
	}
	freeBytes = func(string) (uint64, error) { return diskShedBytes - 1, nil }
	sw.pass(context.Background())
	if !db.shedRaw.Load() {
		t.Fatal("shed flag")
	}
	if mustCount(t, db, `SELECT COUNT(*) FROM flows WHERE exporter = ?`, "192.0.2.62") != 0 {
		t.Fatal("expired flow remains")
	}
	if mustCount(t, db, `SELECT COUNT(*) FROM traffic_1m WHERE exporter = ?`, "192.0.2.62") != 0 {
		t.Fatal("expired rollup remains")
	}
	if mustCount(t, db, `SELECT COUNT(*) FROM flows WHERE exporter = ?`, "192.0.2.60") != 1 {
		t.Fatal("in-horizon flow deleted")
	}

	flushWriter(t, w)
	if got := counters.Snapshot()[obs.DroppedDisk]; got != 1 {
		t.Fatal(got)
	}
	if got := counters.Snapshot()[obs.SQLiteRowsWritten]; got != 1 {
		t.Fatal(got)
	}
	if mustCount(t, db, `SELECT COUNT(*) FROM flows WHERE exporter = ?`, "192.0.2.61") != 0 {
		t.Fatal("shed flow was inserted")
	}
	var packets, octets, n int64
	err := db.pool.QueryRow(`SELECT packets, octets, flows FROM traffic_1m WHERE exporter = ?`, "192.0.2.61").Scan(&packets, &octets, &n)
	if err != nil || packets != 4 || octets != 40 || n != 1 {
		t.Fatal(err, packets, octets, n)
	}
}

func openSweep(t *testing.T, raw, rollup time.Duration) (*DB, *Sweeper, *Writer, *obs.Counters) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "t.db")
	db, err := Open(config.DB{Path: path, BusyTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.pool.Close() })
	counters := obs.NewCounters()
	w, err := NewWriter(db, config.DB{BatchSize: 100, BatchInterval: time.Hour}, counters)
	if err != nil {
		t.Fatal(err)
	}
	sw, err := NewSweeper(db, config.DB{Path: path, RawRetention: raw, RollupRetention: rollup}, counters)
	if err != nil {
		t.Fatal(err)
	}
	return db, sw, w, counters
}

func flushWriter(t *testing.T, w *Writer) {
	t.Helper()
	cancel, errc := runWriter(t, w)
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func insertPlainFlow(t *testing.T, db *DB, start time.Time, exporter string) {
	t.Helper()
	insertPlainFlows(t, db, 1, start, exporter)
}

func insertPlainFlows(t *testing.T, db *DB, n int, start time.Time, exporter string) {
	t.Helper()
	tx, err := db.pool.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO flows (
		flow_start_ms, flow_end_ms, received_ms, time_source, clock_clamped,
		exporter, domain, version, src, dst,
		packets, octets, counter_semantics, octet_semantics, sampled,
		src_scope, dst_scope,
		src_geo_outcome, dst_geo_outcome, src_asn_outcome, dst_asn_outcome, src_rep_outcome, dst_rep_outcome
	) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	ms := start.UnixMilli()
	for i := 0; i < n; i++ {
		if _, err := stmt.Exec(
			ms, ms, ms, "receive", 0,
			exporter, 1, 9, "203.0.113.10", "203.0.113.20",
			1, 1, "delta", "ip", 0,
			"global", "global",
			"not_configured", "not_configured", "not_configured", "not_configured", "not_configured", "not_configured",
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func insertRollupPair(t *testing.T, db *DB, old, fresh int64) {
	t.Helper()
	for _, bucket := range []int64{old, fresh} {
		execSQL(t, db, `INSERT INTO traffic_1m (bucket_ms, exporter, ip_proto, sampled, packets, octets, flows) VALUES (?, 'e', -1, 0, 1, 1, 1)`, bucket)
		execSQL(t, db, `INSERT INTO asn_1m (bucket_ms, asn, direction, from_export, packets, octets, flows) VALUES (?, 1, 'src', 0, 1, 1, 1)`, bucket)
		execSQL(t, db, `INSERT INTO talker_1m (bucket_ms, direction, addr, packets, octets, flows) VALUES (?, 'src', '203.0.113.1', 1, 1, 1)`, bucket)
		execSQL(t, db, `INSERT INTO rep_1m (bucket_ms, direction, addr, category, packets, octets, flows) VALUES (?, 'src', '203.0.113.1', 'scan', 1, 1, 1)`, bucket)
		execSQL(t, db, `INSERT INTO geo_country_5m (bucket_ms, country, packets, octets, flows) VALUES (?, 'US', 1, 1, 1)`, bucket)
		execSQL(t, db, `INSERT INTO geo_path_5m (bucket_ms, src_key, dst_key, src_kind, dst_kind, packets, octets, flows) VALUES (?, 'a', 'b', 'country', 'country', 1, 1, 1)`, bucket)
		execSQL(t, db, `INSERT INTO geo_path_other_5m (bucket_ms, octets, flows, pairs_omitted) VALUES (?, 1, 1, 1)`, bucket)
	}
}

func execSQL(t *testing.T, db *DB, q string, args ...any) {
	t.Helper()
	if _, err := db.pool.Exec(q, args...); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

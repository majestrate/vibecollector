package store

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"vibecollector/internal/config"
	"vibecollector/internal/obs"
)

const (
	deleteBatchRows = 5000
	flowBatches     = 40
	flowBatchesShed = 80
	rollupBatches   = 10
	// diskShedBytes is the free-space line below which raw inserts stop.
	diskShedBytes = 5 << 30
)

// rollupTables are the bucketed aggregates. asn_names has no bucket_ms.
var rollupTables = [...]string{
	"traffic_1m",
	"asn_1m",
	"talker_1m",
	"rep_1m",
	"geo_country_5m",
	"geo_path_5m",
	"geo_path_other_5m",
}

// freeBytes is free space, in bytes, on the volume that holds path.
// Tests replace it to force the disk-shed condition without filling the disk.
var freeBytes = statfsFree

// sweeperNow is the clock retention is measured from.
// Tests replace it so a stored future timestamp can age out without sleeping.
var sweeperNow = time.Now

func deleteSQL(table, column string) string {
	return fmt.Sprintf(`DELETE FROM %s WHERE rowid IN (
  SELECT rowid FROM %s WHERE %s < ? LIMIT %d
)`, table, table, column, deleteBatchRows)
}

// Sweeper deletes expired rows. It is not on the UDP path.
// Run is safe to call once. The writer reads the disk-shed flag Sweeper sets.
type Sweeper struct {
	db       *DB
	counters *obs.Counters
	path     string
	raw      time.Duration
	rollup   time.Duration
}

// NewSweeper stores the pool and the retention durations.
// db is the opened pool Sweeper deletes from. cfg.Path is the database file
// whose volume is checked for free space. cfg.RawRetention is the horizon
// compared with stored flow_start_ms. cfg.RollupRetention is the horizon
// compared with bucket_ms. Both durations are used as given: a zero value is
// not replaced with the config default. counters receives sqlite_write_failures
// when a delete fails; dropped_disk is incremented by the writer, not here.
// A nil db or nil counters returns ErrNilDep. NewSweeper does not delete and
// does not start a goroutine.
func NewSweeper(db *DB, cfg config.DB, counters *obs.Counters) (*Sweeper, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: db", ErrNilDep)
	}
	if counters == nil {
		return nil, fmt.Errorf("%w: counters", ErrNilDep)
	}
	return &Sweeper{
		db:       db,
		counters: counters,
		path:     cfg.Path,
		raw:      cfg.RawRetention,
		rollup:   cfg.RollupRetention,
	}, nil
}

// Run deletes until ctx is cancelled, then returns nil.
// The first pass runs immediately and later passes run once a minute.
// Each pass deletes up to 40 batches of 5,000 rows from flows, and 10 batches
// of 5,000 from each rollup table that has bucket_ms. asn_names is left alone.
// Each batch is its own transaction. A batch that deletes 0 rows stops that
// table early. The flows horizon is the sweeper clock minus raw retention,
// compared with flow_start_ms. Rollups use rollup retention and bucket_ms.
// A row still inside its horizon is not deleted.
// When free space on the database volume is under 5 GiB, the flows budget
// rises to 80 batches and the writer sheds raw inserts. Shedding does not
// stop the deletes. A statfs error leaves the previous shed flag unchanged.
// Cancelling ctx stops the loop between batches. The returned error is nil.
func (s *Sweeper) Run(ctx context.Context) error {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		s.pass(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// pass is one retention cycle. shed is decided before deletes so a low-space
// pass still removes expired rows.
func (s *Sweeper) pass(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	shed := s.observeDisk()
	budget := flowBatches
	if shed {
		budget = flowBatchesShed
	}
	s.deleteLimit(ctx, deleteSQL("flows", "flow_start_ms"), s.cutoff(s.raw), budget)
	rollupAt := s.cutoff(s.rollup)
	for _, table := range rollupTables {
		if ctx.Err() != nil {
			return
		}
		s.deleteLimit(ctx, deleteSQL(table, "bucket_ms"), rollupAt, rollupBatches)
	}
}

// observeDisk stats the database volume and records whether raw inserts shed.
// It returns the flag the flows budget should use. A statfs error keeps the
// previous flag and still lets the caller delete.
func (s *Sweeper) observeDisk() bool {
	free, err := freeBytes(s.path)
	if err != nil {
		slog.Warn("disk free", "err", err)
		return s.db.shedRaw.Load()
	}
	shed := free < diskShedBytes
	if prev := s.db.shedRaw.Swap(shed); prev != shed {
		if shed {
			slog.Info("disk shed", "free_bytes", free)
		} else {
			slog.Info("disk shed ended", "free_bytes", free)
		}
	}
	return shed
}

func (s *Sweeper) cutoff(retain time.Duration) int64 {
	return sweeperNow().Add(-retain).UnixMilli()
}

func (s *Sweeper) deleteLimit(ctx context.Context, query string, cutoff int64, budget int) {
	for i := 0; i < budget; i++ {
		if ctx.Err() != nil {
			return
		}
		n, err := s.deleteBatch(ctx, query, cutoff)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Error("retention delete", "class", sqliteErrClass(err))
			_ = s.counters.Add(obs.SQLiteWriteFailures, 1)
			return
		}
		if n == 0 {
			return
		}
	}
}

// deleteBatch is one short transaction. The writer also uses BEGIN IMMEDIATE,
// so a deferred delete here can deadlock on the lock upgrade.
func (s *Sweeper) deleteBatch(ctx context.Context, query string, cutoff int64) (int64, error) {
	conn, err := s.db.pool.Conn(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	res, err := conn.ExecContext(ctx, query, cutoff)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return 0, err
	}
	committed = true
	return n, nil
}

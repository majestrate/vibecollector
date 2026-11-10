package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Filter is the parsed query. The API fills it from the URL. Query does not
// read an http.Request. A nil pointer means that filter is unset.
// Start and End are the absolute window. TZ is the label. Day is YYYY-MM-DD
// or empty. By is "src" or "dst" for talkers. Limit 0 means the route default.
// Cursor is the raw keyset string, not a SQL fragment.
// Port matches either side. SrcPort and DstPort are exact. Any of the three,
// including Port together with SrcPort or DstPort, is unsupported on every
// rollup route. The flows fallback and the flows route bind all three.
// Reputation on the reputation route is category equality. On the flows
// route the same string is a case-sensitive substring. There is no second flag.
type Filter struct {
	Start, End time.Time
	TZ         string
	Day        string
	Src, Dst   *netip.Addr
	Port       *uint16
	SrcPort    *uint16
	DstPort    *uint16
	Proto      *uint8
	Exporter   *netip.Addr
	Country    *string
	ASN        *uint32
	Reputation *string
	Sampled    *bool
	By         string
	Limit      int
	Cursor     string

	// noProtocol is the timeseries sentinel ip_proto -1.
	// *uint8 cannot store it. SetNoProtocol sets this and clears Proto.
	noProtocol bool
	// boundaryAdjusted is echoed on the range. The API sets it after CalendarDay.
	boundaryAdjusted bool
}

// SetNoProtocol selects rows whose protocol was absent.
// The timeseries rollup stores that as ip_proto -1. Proto is cleared.
// *uint8 cannot represent that sentinel.
func (f *Filter) SetNoProtocol() {
	f.Proto = nil
	f.noProtocol = true
}

// SetBoundaryAdjusted records that CalendarDay moved a skipped civil time.
// Query copies it onto Range. It does not change which rows match.
func (f *Filter) SetBoundaryAdjusted(v bool) {
	f.boundaryAdjusted = v
}

// FilterError is the 400 the API encodes as filter_outside_raw.
// RawAvailableFrom is the oldest receive time still inside raw retention.
type FilterError struct {
	RawAvailableFrom time.Time
}

// Error returns the stable code "filter_outside_raw".
func (e *FilterError) Error() string { return "filter_outside_raw" }

// ErrQueryTimeout is the 503 the API encodes as query_timeout.
// Flows, Timeseries, Talkers, ASNs, Reputation, Geo, and Exporters each
// return it when ctx is canceled or hits the deadline. The result is empty.
// It is not a partial body. Any other non-nil error from those methods is
// the database error from the driver, or ErrBadFilter. FilterError is
// separate and is not a database error.
var ErrQueryTimeout = errors.New("query_timeout")

// ErrBadFilter means a limit, cursor, or talker direction cannot be applied.
// The API encodes it as bad_range. It is not cached.
var ErrBadFilter = errors.New("bad_filter")

// Query reads stored aggregates and raw flows. Methods take a context the
// API creates with a 5-second timeout. They bind every filter value.
// They do not interpolate the cursor or the filter into SQL text.
type Query struct {
	db *DB
}

// NewQuery stores the pool. A nil db returns ErrNilDep.
// raw_available_from is computed from the retention Open recorded on db.
func NewQuery(db *DB) (*Query, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: db", ErrNilDep)
	}
	return &Query{db: db}, nil
}

// Range is the window every range response echoes, including flows.
// Start and End are the half-open UTC window. TZ is the IANA label, UTC when
// the client omitted it. BoundaryAdjusted is true when a skipped civil time
// was moved to the next valid instant.
type Range struct {
	Start            time.Time
	End              time.Time
	TZ               string
	BoundaryAdjusted bool
}

// FlowPage is one keyset page of raw flows. Source is always the flows table.
// NextCursor is empty when there is no next page.
type FlowPage struct {
	Range
	RawAvailableFrom time.Time
	Truncated        bool
	Flows            []FlowRow
	NextCursor       string
}

// FlowRow is one stored flow. Optional pointers are nil when the column is NULL.
// Packets and Octets are the exported counters. They are not multiplied by N.
type FlowRow struct {
	ID                 int64
	Start, End         time.Time
	Exporter           string
	Domain             int64
	Version            int
	Src, Dst           string
	SrcPort, DstPort   *int
	Proto              *int
	Packets, Octets    uint64
	CounterSemantics   string
	OctetSemantics     string
	FlowDirection      *int
	Sampled            bool
	SamplingInterval   *int64
	SamplingAlgorithm  *int
	ClockClamped       bool
	BGPSrcAS, BGPDstAS *int64
	SrcScope, DstScope string
	SrcGeo, DstGeo     string
	SrcASN, DstASN     string
	SrcRep, DstRep     string
}

// Timeseries is sampled and unsampled traffic as separate series.
// Source is "rollup" or "flows". Grain is "1m" or "1h".
type Timeseries struct {
	Range
	Source string
	Grain  string
	Series []Series
}

// Series is one sampled value. Points are ordered by time.
type Series struct {
	Sampled bool
	Points  []Point
}

// Point is one bucket. Octets and Packets are exported totals, not estimates.
type Point struct {
	T               time.Time
	Octets, Packets uint64
}

// Talkers is one direction, ranked by octets.
// OtherOctets is the sum of '*' rows and does not overlap a listed address.
// Approximate is true when that remainder is non-zero.
type Talkers struct {
	Range
	Source      string
	Grain       string
	By          string
	Approximate bool
	OtherOctets uint64
	Rows        []TalkerRow
}

// TalkerRow is one address. Flows is the flow count for that address.
type TalkerRow struct {
	Addr            string
	Octets, Packets uint64
	Flows           uint64
}

// ASNs is the ASN breakdown. Rows with ASN -1 are the overflow sentinel.
type ASNs struct {
	Range
	Source string
	Grain  string
	Rows   []ASNRow
}

// ASNRow is one ASN, direction, and from-export bit.
// FromExport true means the export BGP AS.
type ASNRow struct {
	ASN             int64
	Name            string
	Direction       string
	FromExport      bool
	Octets, Packets uint64
	Flows           uint64
}

// Reputation is reputation hits. OtherOctets is the addr '*' remainder.
type Reputation struct {
	Range
	Source      string
	Grain       string
	Approximate bool
	OtherOctets uint64
	Rows        []RepRow
}

// RepRow is one address and category. Category equality selected it on the rollup.
type RepRow struct {
	Direction, Addr, Category string
	Octets, Packets           uint64
	Flows                     uint64
}

// Geo is countries and at most 100 paths. BytesAre is "endpoint_touch".
// The flat map and the globe both use this result. Geo does not know which one called.
type Geo struct {
	Range
	Source       string
	BytesAre     string
	Approximate  bool
	Countries    []GeoCountry
	Paths        []GeoPath
	PathCap      int
	PathsOmitted int64
	OtherOctets  uint64
}

// GeoCountry is one ISO country total. ISOA2 is the alpha-2 code.
// The API fills the numeric id string when it encodes the body.
type GeoCountry struct {
	ISOA2           string
	Octets, Packets uint64
	Flows           uint64
}

// GeoPath is one directed pair of places.
type GeoPath struct {
	Src, Dst        GeoPlace
	Octets, Packets uint64
	Flows           uint64
}

// GeoPlace is a country, city, or coordinate. HasCoord is false for a country.
type GeoPlace struct {
	Kind         string
	ISOA2        string
	Region, City string
	Lat, Lon     float64
	HasCoord     bool
}

// ExporterRow is one durable exporter. It has no flow filter and no range.
type ExporterRow struct {
	Exporter        string
	Domain          int64
	Version         int
	LastSeen        time.Time
	Packets         uint64
	Flows           uint64
	Malformed       uint64
	MissingTemplate uint64
	GapFlows        uint64
	GapPackets      uint64
	GapRecords      uint64
}

const (
	flowPageDefault = 100
	flowPageMax     = 500
	topLimitDefault = 100
	topLimitMax     = 100
	geoPathCap      = 100
	eligibleSQL     = "counter_semantics = 'delta' AND octet_semantics = 'ip'"
)

// Flows returns one keyset page. Source is always the flows table.
// Port, SrcPort, and DstPort are bound when set. Reputation is a substring.
// A range that starts before raw retention returns an empty page and
// RawAvailableFrom set, not FilterError. The page still echoes Start, End,
// TZ, and BoundaryAdjusted. A canceled ctx returns ErrQueryTimeout.
// ErrBadFilter means the limit or the cursor cannot be applied.
// Any other failure is the database error. The cursor on the page is empty
// when there is no next page.
func (q *Query) Flows(ctx context.Context, f Filter) (FlowPage, error) {
	page := FlowPage{Range: echoRange(f), Flows: []FlowRow{}}
	if err := q.ready(ctx); err != nil {
		return page, err
	}
	page.RawAvailableFrom = q.rawFrom()
	lim, err := pageLimit(f.Limit, flowPageDefault, flowPageMax)
	if err != nil {
		return page, err
	}
	cur, err := parseCursor(f.Cursor)
	if err != nil {
		return page, err
	}
	if f.Start.Before(page.RawAvailableFrom) {
		page.Truncated = true
		return page, nil
	}
	w := newWhere("flow_start_ms >= ? AND flow_start_ms < ?", f.Start.UnixMilli(), f.End.UnixMilli())
	bindFlowFilters(&w, f, true)
	if cur.set {
		// The cursor string is decoded to two integers. Those integers are bound.
		w.and("(flow_start_ms > ? OR (flow_start_ms = ? AND id > ?))", cur.ms, cur.ms, cur.id)
	}
	qs := `SELECT id, flow_start_ms, flow_end_ms, exporter, domain, version, src, dst,
		src_port, dst_port, ip_proto, packets, octets, counter_semantics, octet_semantics,
		flow_direction, sampled, sampling_interval, sampling_algorithm, clock_clamped,
		bgp_src_as, bgp_dst_as, src_scope, dst_scope,
		src_geo_outcome, dst_geo_outcome, src_asn_outcome, dst_asn_outcome, src_rep_outcome, dst_rep_outcome
		FROM flows WHERE ` + w.sql + ` ORDER BY flow_start_ms, id LIMIT ?`
	rows, err := q.db.pool.QueryContext(ctx, qs, append(w.args, lim+1)...)
	if err != nil {
		return page, mapErr(ctx, err)
	}
	defer rows.Close()
	var prevMS, prevID int64
	for rows.Next() {
		row, ms, id, err := scanFlow(rows)
		if err != nil {
			return page, mapErr(ctx, err)
		}
		if len(page.Flows) == lim {
			page.NextCursor = encodeCursor(prevMS, prevID)
			break
		}
		page.Flows = append(page.Flows, row)
		prevMS, prevID = ms, id
	}
	if err := rows.Err(); err != nil {
		return page, mapErr(ctx, err)
	}
	return page, nil
}

// Timeseries returns sampled and unsampled as separate series.
// Native filters are exporter, proto, and sampled. Port, SrcPort, and
// DstPort are unsupported, as is every other non-native filter. Any
// unsupported filter aggregates flows when f.Start is inside raw retention
// and sets Source to "flows". Otherwise it returns FilterError. It does not
// add the two series together and it does not multiply by N.
// A canceled ctx returns ErrQueryTimeout. Any other failure is the database error.
func (q *Query) Timeseries(ctx context.Context, f Filter) (Timeseries, error) {
	out := Timeseries{Range: echoRange(f), Series: []Series{}}
	if err := q.ready(ctx); err != nil {
		return out, err
	}
	if timeseriesUnsupported(f) {
		if fe := q.outside(f.Start); fe != nil {
			return out, fe
		}
		out.Source = "flows"
		out.Grain = "1m"
		return q.timeseriesFlows(ctx, f, out)
	}
	out.Source = "rollup"
	out.Grain = grainOf(f.Start, f.End, "rollup")
	return q.timeseriesRollup(ctx, f, out)
}

// Talkers returns one direction. Native filters are By and an address only
// when it matches By. Port, SrcPort, and DstPort are unsupported. The
// fallback and FilterError rules match Timeseries. A canceled ctx returns
// ErrQueryTimeout. ErrBadFilter means By or Limit cannot be applied.
// Any other failure is the database error.
func (q *Query) Talkers(ctx context.Context, f Filter) (Talkers, error) {
	by, err := talkerBy(f.By)
	out := Talkers{Range: echoRange(f), Grain: "1m", By: by, Rows: []TalkerRow{}}
	if err != nil {
		return out, err
	}
	if err := q.ready(ctx); err != nil {
		return out, err
	}
	lim, err := pageLimit(f.Limit, topLimitDefault, topLimitMax)
	if err != nil {
		return out, err
	}
	if talkersUnsupported(f) {
		if fe := q.outside(f.Start); fe != nil {
			return out, fe
		}
		out.Source = "flows"
		return q.talkersFlows(ctx, f, by, lim, out)
	}
	out.Source = "rollup"
	return q.talkersRollup(ctx, f, by, lim, out)
}

// ASNs returns the ASN breakdown. The native filter is ASN. Port, SrcPort,
// and DstPort are unsupported. The fallback and FilterError rules match
// Timeseries. A canceled ctx returns ErrQueryTimeout. ErrBadFilter means
// Limit cannot be applied. Any other failure is the database error.
func (q *Query) ASNs(ctx context.Context, f Filter) (ASNs, error) {
	out := ASNs{Range: echoRange(f), Grain: "1m", Rows: []ASNRow{}}
	if err := q.ready(ctx); err != nil {
		return out, err
	}
	lim, err := pageLimit(f.Limit, topLimitDefault, topLimitMax)
	if err != nil {
		return out, err
	}
	if asnsUnsupported(f) {
		if fe := q.outside(f.Start); fe != nil {
			return out, fe
		}
		out.Source = "flows"
		return q.asnsFlows(ctx, f, lim, out)
	}
	out.Source = "rollup"
	return q.asnsRollup(ctx, f, lim, out)
}

// Reputation returns reputation hits. f.Reputation is category equality on
// rep_1m. It does not select the flows fallback. A value that equals no
// stored category is an empty rollup, not a raw scan. Substring match is
// only Query.Flows. Other unsupported filters, including Port, SrcPort, and
// DstPort, use the same fallback and FilterError rules as Timeseries.
// A canceled ctx returns ErrQueryTimeout. ErrBadFilter means Limit cannot
// be applied. Any other failure is the database error.
func (q *Query) Reputation(ctx context.Context, f Filter) (Reputation, error) {
	out := Reputation{Range: echoRange(f), Grain: "1m", Rows: []RepRow{}}
	if err := q.ready(ctx); err != nil {
		return out, err
	}
	lim, err := pageLimit(f.Limit, topLimitDefault, topLimitMax)
	if err != nil {
		return out, err
	}
	if repUnsupported(f) {
		if fe := q.outside(f.Start); fe != nil {
			return out, fe
		}
		out.Source = "flows"
		return q.repFlows(ctx, f, lim, out)
	}
	out.Source = "rollup"
	return q.repRollup(ctx, f, lim, out)
}

// Geo returns countries and at most 100 paths. The native filter is country.
// Port, SrcPort, DstPort, source IP, and reputation are not native. The
// fallback and FilterError rules match Timeseries. BytesAre is "endpoint_touch".
// The flat map and the globe both use this result. Geo does not know which one called.
// A canceled ctx returns ErrQueryTimeout. ErrBadFilter means Limit cannot
// be applied. Any other failure is the database error.
func (q *Query) Geo(ctx context.Context, f Filter) (Geo, error) {
	out := Geo{
		Range:     echoRange(f),
		BytesAre:  "endpoint_touch",
		Countries: []GeoCountry{},
		Paths:     []GeoPath{},
		PathCap:   geoPathCap,
	}
	if err := q.ready(ctx); err != nil {
		return out, err
	}
	lim, err := pageLimit(f.Limit, geoPathCap, geoPathCap)
	if err != nil {
		return out, err
	}
	if geoUnsupported(f) {
		if fe := q.outside(f.Start); fe != nil {
			return out, fe
		}
		out.Source = "flows"
		return q.geoFlows(ctx, f, lim, out)
	}
	out.Source = "rollup"
	return q.geoRollup(ctx, f, lim, out)
}

// Exporters returns the exporter table. It has no flow filter and no range.
// A canceled ctx returns ErrQueryTimeout. Any other failure is the database error.
// It does not return FilterError.
func (q *Query) Exporters(ctx context.Context) ([]ExporterRow, error) {
	if err := q.ready(ctx); err != nil {
		return nil, err
	}
	rows, err := q.db.pool.QueryContext(ctx, `SELECT exporter, domain, version, last_seen_ms,
		packets, flows, malformed, missing_template, gap_flows, gap_packets, gap_records
		FROM exporters ORDER BY last_seen_ms DESC, exporter, domain, version`)
	if err != nil {
		return nil, mapErr(ctx, err)
	}
	defer rows.Close()
	out := []ExporterRow{}
	for rows.Next() {
		var row ExporterRow
		var seen, packets, flows, malformed, missing, gapF, gapP, gapR int64
		if err := rows.Scan(&row.Exporter, &row.Domain, &row.Version, &seen,
			&packets, &flows, &malformed, &missing, &gapF, &gapP, &gapR); err != nil {
			return nil, mapErr(ctx, err)
		}
		row.LastSeen = time.UnixMilli(seen).UTC()
		row.Packets = u64(packets)
		row.Flows = u64(flows)
		row.Malformed = u64(malformed)
		row.MissingTemplate = u64(missing)
		row.GapFlows = u64(gapF)
		row.GapPackets = u64(gapP)
		row.GapRecords = u64(gapR)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(ctx, err)
	}
	return out, nil
}

func (q *Query) ready(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrQueryTimeout
	}
	return nil
}

func mapErr(ctx context.Context, err error) error {
	if err == nil {
		if ctx.Err() != nil {
			return ErrQueryTimeout
		}
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		return ErrQueryTimeout
	}
	return err
}

func (q *Query) rawFrom() time.Time {
	return time.Now().UTC().Add(-q.db.rawRetention)
}

func (q *Query) outside(start time.Time) *FilterError {
	from := q.rawFrom()
	if start.Before(from) {
		return &FilterError{RawAvailableFrom: from}
	}
	return nil
}

func echoRange(f Filter) Range {
	tz := f.TZ
	if tz == "" {
		tz = "UTC"
	}
	return Range{Start: f.Start.UTC(), End: f.End.UTC(), TZ: tz, BoundaryAdjusted: f.boundaryAdjusted}
}

func pageLimit(n, def, max int) (int, error) {
	if n == 0 {
		return def, nil
	}
	if n < 0 || n > max {
		return 0, ErrBadFilter
	}
	return n, nil
}

func talkerBy(by string) (string, error) {
	switch by {
	case "", "src":
		return "src", nil
	case "dst":
		return "dst", nil
	default:
		return "", ErrBadFilter
	}
}

func grainOf(start, end time.Time, source string) string {
	if source == "flows" || end.Sub(start) <= 7*24*time.Hour {
		return "1m"
	}
	return "1h"
}

func u64(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

type keyCursor struct {
	set    bool
	ms, id int64
}

func parseCursor(s string) (keyCursor, error) {
	if s == "" {
		return keyCursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return keyCursor{}, ErrBadFilter
	}
	a, b, ok := strings.Cut(string(raw), ",")
	if !ok {
		return keyCursor{}, ErrBadFilter
	}
	ms, err := strconv.ParseInt(a, 10, 64)
	if err != nil || strconv.FormatInt(ms, 10) != a {
		return keyCursor{}, ErrBadFilter
	}
	id, err := strconv.ParseInt(b, 10, 64)
	if err != nil || strconv.FormatInt(id, 10) != b {
		return keyCursor{}, ErrBadFilter
	}
	return keyCursor{set: true, ms: ms, id: id}, nil
}

func encodeCursor(ms, id int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d,%d", ms, id)))
}

type wh struct {
	sql  string
	args []any
}

func newWhere(base string, args ...any) wh {
	return wh{sql: base, args: append([]any{}, args...)}
}

func (w *wh) and(expr string, args ...any) {
	w.sql += " AND (" + expr + ")"
	w.args = append(w.args, args...)
}

func bindFlowFilters(w *wh, f Filter, repSubstr bool) {
	if f.Src != nil {
		w.and("src = ?", f.Src.String())
	}
	if f.Dst != nil {
		w.and("dst = ?", f.Dst.String())
	}
	if f.Port != nil {
		w.and("src_port = ? OR dst_port = ?", int(*f.Port), int(*f.Port))
	}
	if f.SrcPort != nil {
		w.and("src_port = ?", int(*f.SrcPort))
	}
	if f.DstPort != nil {
		w.and("dst_port = ?", int(*f.DstPort))
	}
	if f.noProtocol {
		w.and("ip_proto IS NULL")
	} else if f.Proto != nil {
		w.and("ip_proto = ?", int(*f.Proto))
	}
	if f.Exporter != nil {
		w.and("exporter = ?", f.Exporter.String())
	}
	if f.Country != nil {
		w.and("src_country = ? OR dst_country = ?", *f.Country, *f.Country)
	}
	if f.ASN != nil {
		n := int64(*f.ASN)
		w.and(`(src_asn_outcome = 'value' AND src_asn = ?)
			OR (src_asn_outcome != 'value' AND bgp_src_as = ?)
			OR (dst_asn_outcome = 'value' AND dst_asn = ?)
			OR (dst_asn_outcome != 'value' AND bgp_dst_as = ?)`, n, n, n, n)
	}
	if f.Reputation != nil {
		if repSubstr {
			w.and("instr(IFNULL(src_rep_category, ''), ?) > 0 OR instr(IFNULL(dst_rep_category, ''), ?) > 0", *f.Reputation, *f.Reputation)
		} else {
			w.and("(src_rep_outcome = 'value' AND src_rep_category = ?) OR (dst_rep_outcome = 'value' AND dst_rep_category = ?)", *f.Reputation, *f.Reputation)
		}
	}
	if f.Sampled != nil {
		w.and("sampled = ?", boolInt(*f.Sampled))
	}
}

func portSet(f Filter) bool {
	return f.Port != nil || f.SrcPort != nil || f.DstPort != nil
}

func timeseriesUnsupported(f Filter) bool {
	return f.Src != nil || f.Dst != nil || portSet(f) || f.Country != nil || f.ASN != nil || f.Reputation != nil
}

func talkersUnsupported(f Filter) bool {
	if portSet(f) || f.Proto != nil || f.noProtocol || f.Exporter != nil || f.Country != nil || f.ASN != nil || f.Reputation != nil || f.Sampled != nil {
		return true
	}
	by := f.By
	if by == "" {
		by = "src"
	}
	if f.Src != nil && f.Dst != nil {
		return true
	}
	if by == "src" && f.Dst != nil {
		return true
	}
	if by == "dst" && f.Src != nil {
		return true
	}
	return false
}

func asnsUnsupported(f Filter) bool {
	return f.Src != nil || f.Dst != nil || portSet(f) || f.Proto != nil || f.noProtocol || f.Exporter != nil || f.Country != nil || f.Reputation != nil || f.Sampled != nil
}

func repUnsupported(f Filter) bool {
	return f.Src != nil || f.Dst != nil || portSet(f) || f.Proto != nil || f.noProtocol || f.Exporter != nil || f.Country != nil || f.ASN != nil || f.Sampled != nil
}

func geoUnsupported(f Filter) bool {
	return f.Src != nil || f.Dst != nil || portSet(f) || f.Proto != nil || f.noProtocol || f.Exporter != nil || f.ASN != nil || f.Reputation != nil || f.Sampled != nil
}

func (q *Query) timeseriesRollup(ctx context.Context, f Filter, out Timeseries) (Timeseries, error) {
	w := newWhere("bucket_ms >= ? AND bucket_ms < ?", f.Start.UnixMilli(), f.End.UnixMilli())
	if f.Exporter != nil {
		w.and("exporter = ?", f.Exporter.String())
	}
	if f.noProtocol {
		w.and("ip_proto = -1")
	} else if f.Proto != nil {
		w.and("ip_proto = ?", int(*f.Proto))
	}
	if f.Sampled != nil {
		w.and("sampled = ?", boolInt(*f.Sampled))
	}
	bucket := "bucket_ms"
	if out.Grain == "1h" {
		bucket = "(bucket_ms / 3600000) * 3600000"
	}
	qs := `SELECT ` + bucket + ` AS b, sampled, SUM(packets), SUM(octets)
		FROM traffic_1m WHERE ` + w.sql + ` GROUP BY b, sampled ORDER BY b, sampled`
	pts, err := q.scanPoints(ctx, qs, w.args...)
	if err != nil {
		return out, err
	}
	out.Series = seriesFrom(pts, f.Sampled)
	return out, nil
}

func (q *Query) timeseriesFlows(ctx context.Context, f Filter, out Timeseries) (Timeseries, error) {
	w := newWhere("flow_start_ms >= ? AND flow_start_ms < ? AND "+eligibleSQL, f.Start.UnixMilli(), f.End.UnixMilli())
	bindFlowFilters(&w, f, true)
	qs := `SELECT (flow_start_ms / 60000) * 60000 AS b, sampled, SUM(packets), SUM(octets)
		FROM flows WHERE ` + w.sql + ` GROUP BY b, sampled ORDER BY b, sampled`
	pts, err := q.scanPoints(ctx, qs, w.args...)
	if err != nil {
		return out, err
	}
	out.Series = seriesFrom(pts, f.Sampled)
	return out, nil
}

type pt struct {
	t       time.Time
	sampled bool
	octets  uint64
	packets uint64
}

func (q *Query) scanPoints(ctx context.Context, qs string, args ...any) ([]pt, error) {
	rows, err := q.db.pool.QueryContext(ctx, qs, args...)
	if err != nil {
		return nil, mapErr(ctx, err)
	}
	defer rows.Close()
	var out []pt
	for rows.Next() {
		var b, sampled, packets, octets int64
		if err := rows.Scan(&b, &sampled, &packets, &octets); err != nil {
			return nil, mapErr(ctx, err)
		}
		out = append(out, pt{t: time.UnixMilli(b).UTC(), sampled: sampled != 0, octets: u64(octets), packets: u64(packets)})
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(ctx, err)
	}
	return out, nil
}

func seriesFrom(pts []pt, sampled *bool) []Series {
	one := func(want bool) Series {
		s := Series{Sampled: want, Points: []Point{}}
		for _, p := range pts {
			if p.sampled == want {
				s.Points = append(s.Points, Point{T: p.t, Octets: p.octets, Packets: p.packets})
			}
		}
		return s
	}
	if sampled != nil {
		return []Series{one(*sampled)}
	}
	return []Series{one(false), one(true)}
}

func (q *Query) talkersRollup(ctx context.Context, f Filter, by string, lim int, out Talkers) (Talkers, error) {
	w := newWhere("bucket_ms >= ? AND bucket_ms < ? AND direction = ? AND addr != '*'", f.Start.UnixMilli(), f.End.UnixMilli(), by)
	if by == "src" && f.Src != nil {
		w.and("addr = ?", f.Src.String())
	}
	if by == "dst" && f.Dst != nil {
		w.and("addr = ?", f.Dst.String())
	}
	qs := `SELECT addr, SUM(packets), SUM(octets), SUM(flows) FROM talker_1m WHERE ` + w.sql + `
		GROUP BY addr ORDER BY SUM(octets) DESC, addr LIMIT ?`
	rows, err := q.scanTalkers(ctx, qs, append(w.args, lim)...)
	if err != nil {
		return out, err
	}
	out.Rows = rows
	other, err := q.oneUint(ctx, `SELECT COALESCE(SUM(octets), 0) FROM talker_1m
		WHERE bucket_ms >= ? AND bucket_ms < ? AND direction = ? AND addr = '*'`,
		f.Start.UnixMilli(), f.End.UnixMilli(), by)
	if err != nil {
		return out, err
	}
	out.OtherOctets = other
	out.Approximate = other != 0
	return out, nil
}

func (q *Query) talkersFlows(ctx context.Context, f Filter, by string, lim int, out Talkers) (Talkers, error) {
	col := "src"
	if by == "dst" {
		col = "dst"
	}
	w := newWhere("flow_start_ms >= ? AND flow_start_ms < ? AND "+eligibleSQL, f.Start.UnixMilli(), f.End.UnixMilli())
	bindFlowFilters(&w, f, true)
	qs := `SELECT ` + col + `, SUM(packets), SUM(octets), COUNT(*) FROM flows WHERE ` + w.sql + `
		GROUP BY ` + col + ` ORDER BY SUM(octets) DESC, ` + col + ` LIMIT ?`
	rows, err := q.scanTalkers(ctx, qs, append(w.args, lim)...)
	if err != nil {
		return out, err
	}
	out.Rows = rows
	return out, nil
}

func (q *Query) scanTalkers(ctx context.Context, qs string, args ...any) ([]TalkerRow, error) {
	rows, err := q.db.pool.QueryContext(ctx, qs, args...)
	if err != nil {
		return nil, mapErr(ctx, err)
	}
	defer rows.Close()
	out := []TalkerRow{}
	for rows.Next() {
		var row TalkerRow
		var packets, octets, flows int64
		if err := rows.Scan(&row.Addr, &packets, &octets, &flows); err != nil {
			return nil, mapErr(ctx, err)
		}
		row.Packets = u64(packets)
		row.Octets = u64(octets)
		row.Flows = u64(flows)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(ctx, err)
	}
	return out, nil
}

func (q *Query) asnsRollup(ctx context.Context, f Filter, lim int, out ASNs) (ASNs, error) {
	w := newWhere("a.bucket_ms >= ? AND a.bucket_ms < ?", f.Start.UnixMilli(), f.End.UnixMilli())
	if f.ASN != nil {
		w.and("a.asn = ?", int64(*f.ASN))
	}
	qs := `SELECT a.asn, CASE WHEN a.asn = -1 THEN '' ELSE COALESCE(MAX(n.name), '') END,
		a.direction, a.from_export, SUM(a.packets), SUM(a.octets), SUM(a.flows)
		FROM asn_1m a LEFT JOIN asn_names n ON n.asn = a.asn
		WHERE ` + w.sql + `
		GROUP BY a.asn, a.direction, a.from_export
		ORDER BY SUM(a.octets) DESC, a.asn, a.direction, a.from_export
		LIMIT ?`
	rows, err := q.scanASNs(ctx, qs, append(w.args, lim)...)
	if err != nil {
		return out, err
	}
	out.Rows = rows
	return out, nil
}

func (q *Query) asnsFlows(ctx context.Context, f Filter, lim int, out ASNs) (ASNs, error) {
	w := newWhere("flow_start_ms >= ? AND flow_start_ms < ? AND "+eligibleSQL, f.Start.UnixMilli(), f.End.UnixMilli())
	bindFlowFilters(&w, f, true)
	qs := `SELECT asn, MAX(name), direction, from_export, SUM(packets), SUM(octets), SUM(flows) FROM (
		SELECT CASE WHEN src_asn_outcome = 'value' THEN src_asn ELSE bgp_src_as END AS asn,
			CASE WHEN src_asn_outcome = 'value' THEN IFNULL(src_asn_name, '') ELSE '' END AS name,
			'src' AS direction,
			CASE WHEN src_asn_outcome = 'value' THEN 0 ELSE 1 END AS from_export,
			packets, octets, 1 AS flows
		FROM flows WHERE ` + w.sql + `
			AND ((src_asn_outcome = 'value' AND src_asn IS NOT NULL) OR (src_asn_outcome != 'value' AND bgp_src_as IS NOT NULL))
		UNION ALL
		SELECT CASE WHEN dst_asn_outcome = 'value' THEN dst_asn ELSE bgp_dst_as END,
			CASE WHEN dst_asn_outcome = 'value' THEN IFNULL(dst_asn_name, '') ELSE '' END,
			'dst',
			CASE WHEN dst_asn_outcome = 'value' THEN 0 ELSE 1 END,
			packets, octets, 1
		FROM flows WHERE ` + w.sql + `
			AND ((dst_asn_outcome = 'value' AND dst_asn IS NOT NULL) OR (dst_asn_outcome != 'value' AND bgp_dst_as IS NOT NULL))
	) GROUP BY asn, direction, from_export
	ORDER BY SUM(octets) DESC, asn, direction, from_export
	LIMIT ?`
	args := append(append([]any{}, w.args...), w.args...)
	args = append(args, lim)
	rows, err := q.scanASNs(ctx, qs, args...)
	if err != nil {
		return out, err
	}
	out.Rows = rows
	return out, nil
}

func (q *Query) scanASNs(ctx context.Context, qs string, args ...any) ([]ASNRow, error) {
	rows, err := q.db.pool.QueryContext(ctx, qs, args...)
	if err != nil {
		return nil, mapErr(ctx, err)
	}
	defer rows.Close()
	out := []ASNRow{}
	for rows.Next() {
		var row ASNRow
		var from, packets, octets, flows int64
		if err := rows.Scan(&row.ASN, &row.Name, &row.Direction, &from, &packets, &octets, &flows); err != nil {
			return nil, mapErr(ctx, err)
		}
		row.FromExport = from != 0
		row.Packets = u64(packets)
		row.Octets = u64(octets)
		row.Flows = u64(flows)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(ctx, err)
	}
	return out, nil
}

func (q *Query) repRollup(ctx context.Context, f Filter, lim int, out Reputation) (Reputation, error) {
	w := newWhere("bucket_ms >= ? AND bucket_ms < ? AND addr != '*'", f.Start.UnixMilli(), f.End.UnixMilli())
	if f.Reputation != nil {
		w.and("category = ?", *f.Reputation)
	}
	qs := `SELECT direction, addr, category, SUM(packets), SUM(octets), SUM(flows)
		FROM rep_1m WHERE ` + w.sql + `
		GROUP BY direction, addr, category
		ORDER BY SUM(octets) DESC, direction, addr, category
		LIMIT ?`
	rows, err := q.scanReps(ctx, qs, append(w.args, lim)...)
	if err != nil {
		return out, err
	}
	out.Rows = rows
	if f.Reputation == nil {
		other, err := q.oneUint(ctx, `SELECT COALESCE(SUM(octets), 0) FROM rep_1m
			WHERE bucket_ms >= ? AND bucket_ms < ? AND addr = '*'`,
			f.Start.UnixMilli(), f.End.UnixMilli())
		if err != nil {
			return out, err
		}
		out.OtherOctets = other
		out.Approximate = other != 0
	}
	return out, nil
}

func (q *Query) repFlows(ctx context.Context, f Filter, lim int, out Reputation) (Reputation, error) {
	w := newWhere("flow_start_ms >= ? AND flow_start_ms < ? AND "+eligibleSQL, f.Start.UnixMilli(), f.End.UnixMilli())
	bindFlowFilters(&w, f, false)
	cat := ""
	if f.Reputation != nil {
		cat = *f.Reputation
	}
	qs := `SELECT direction, addr, category, SUM(packets), SUM(octets), SUM(flows) FROM (
		SELECT 'src' AS direction, src AS addr, src_rep_category AS category, packets, octets, 1 AS flows
		FROM flows WHERE ` + w.sql + ` AND src_rep_outcome = 'value' AND src_rep_category != '' AND (? = '' OR src_rep_category = ?)
		UNION ALL
		SELECT 'dst', dst, dst_rep_category, packets, octets, 1
		FROM flows WHERE ` + w.sql + ` AND dst_rep_outcome = 'value' AND dst_rep_category != '' AND (? = '' OR dst_rep_category = ?)
	) GROUP BY direction, addr, category
	ORDER BY SUM(octets) DESC, direction, addr, category
	LIMIT ?`
	args := append(append([]any{}, w.args...), cat, cat)
	args = append(args, w.args...)
	args = append(args, cat, cat, lim)
	rows, err := q.scanReps(ctx, qs, args...)
	if err != nil {
		return out, err
	}
	out.Rows = rows
	return out, nil
}

func (q *Query) scanReps(ctx context.Context, qs string, args ...any) ([]RepRow, error) {
	rows, err := q.db.pool.QueryContext(ctx, qs, args...)
	if err != nil {
		return nil, mapErr(ctx, err)
	}
	defer rows.Close()
	out := []RepRow{}
	for rows.Next() {
		var row RepRow
		var packets, octets, flows int64
		if err := rows.Scan(&row.Direction, &row.Addr, &row.Category, &packets, &octets, &flows); err != nil {
			return nil, mapErr(ctx, err)
		}
		row.Packets = u64(packets)
		row.Octets = u64(octets)
		row.Flows = u64(flows)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(ctx, err)
	}
	return out, nil
}

func (q *Query) geoRollup(ctx context.Context, f Filter, lim int, out Geo) (Geo, error) {
	country := ""
	if f.Country != nil {
		country = *f.Country
	}
	cRows, err := q.db.pool.QueryContext(ctx, `SELECT country, SUM(packets), SUM(octets), SUM(flows)
		FROM geo_country_5m
		WHERE bucket_ms >= ? AND bucket_ms < ? AND (? = '' OR country = ?)
		GROUP BY country ORDER BY SUM(octets) DESC, country`,
		f.Start.UnixMilli(), f.End.UnixMilli(), country, country)
	if err != nil {
		return out, mapErr(ctx, err)
	}
	out.Countries, err = scanCountries(ctx, cRows)
	if err != nil {
		return out, err
	}
	pRows, err := q.db.pool.QueryContext(ctx, `SELECT src_kind, dst_kind,
		IFNULL(src_country, ''), IFNULL(dst_country, ''),
		IFNULL(src_region, ''), IFNULL(dst_region, ''),
		IFNULL(src_city, ''), IFNULL(dst_city, ''),
		src_lat, src_lon, dst_lat, dst_lon,
		SUM(packets), SUM(octets), SUM(flows)
		FROM geo_path_5m
		WHERE bucket_ms >= ? AND bucket_ms < ? AND (? = '' OR src_country = ? OR dst_country = ?)
		GROUP BY src_key, dst_key
		ORDER BY SUM(octets) DESC, src_key, dst_key`,
		f.Start.UnixMilli(), f.End.UnixMilli(), country, country, country)
	if err != nil {
		return out, mapErr(ctx, err)
	}
	paths, err := scanPaths(ctx, pRows)
	if err != nil {
		return out, err
	}
	other, pairs, err := q.otherPaths(ctx, f.Start, f.End)
	if err != nil {
		return out, err
	}
	out.Approximate = other != 0
	out.Paths, out.PathsOmitted, out.OtherOctets = capPaths(paths, lim, pairs, other, country == "")
	return out, nil
}

func (q *Query) geoFlows(ctx context.Context, f Filter, lim int, out Geo) (Geo, error) {
	w := newWhere("flow_start_ms >= ? AND flow_start_ms < ? AND "+eligibleSQL, f.Start.UnixMilli(), f.End.UnixMilli())
	// Country is applied per end below so a peer country is not listed.
	saved := f.Country
	f.Country = nil
	bindFlowFilters(&w, f, true)
	f.Country = saved
	country := ""
	if saved != nil {
		country = *saved
	}
	place := func(end string) string {
		return `(` + end + `_scope = 'global' AND ` + end + `_geo_outcome = 'value' AND IFNULL(` + end + `_country, '') != '')`
	}
	cSQL := `SELECT country, SUM(packets), SUM(octets), SUM(flows) FROM (
		SELECT src_country AS country, packets, octets, 1 AS flows FROM flows
		WHERE ` + w.sql + ` AND ` + place("src") + ` AND (? = '' OR src_country = ?)
		UNION ALL
		SELECT dst_country, packets, octets, 1 FROM flows
		WHERE ` + w.sql + ` AND ` + place("dst") + ` AND (? = '' OR dst_country = ?)
	) GROUP BY country ORDER BY SUM(octets) DESC, country`
	args := append(append([]any{}, w.args...), country, country)
	args = append(args, w.args...)
	args = append(args, country, country)
	cRows, err := q.db.pool.QueryContext(ctx, cSQL, args...)
	if err != nil {
		return out, mapErr(ctx, err)
	}
	out.Countries, err = scanCountries(ctx, cRows)
	if err != nil {
		return out, err
	}
	pathSQL := `SELECT src_kind, dst_kind, src_country, dst_country, src_region, dst_region, src_city, dst_city,
		src_lat, src_lon, dst_lat, dst_lon, SUM(packets), SUM(octets), COUNT(*)
		FROM (
			SELECT ` + kindExpr("src") + ` AS src_kind, ` + kindExpr("dst") + ` AS dst_kind,
				src_country, dst_country,
				CASE WHEN src_lat IS NOT NULL AND IFNULL(src_city, '') != '' THEN IFNULL(src_region, '') ELSE '' END AS src_region,
				CASE WHEN dst_lat IS NOT NULL AND IFNULL(dst_city, '') != '' THEN IFNULL(dst_region, '') ELSE '' END AS dst_region,
				CASE WHEN src_lat IS NOT NULL AND IFNULL(src_city, '') != '' THEN src_city ELSE '' END AS src_city,
				CASE WHEN dst_lat IS NOT NULL AND IFNULL(dst_city, '') != '' THEN dst_city ELSE '' END AS dst_city,
				src_lat, src_lon, dst_lat, dst_lon, packets, octets,
				` + placeKey("src") + ` AS src_key, ` + placeKey("dst") + ` AS dst_key
			FROM flows WHERE ` + w.sql + `
		) WHERE src_key IS NOT NULL AND dst_key IS NOT NULL
			AND (? = '' OR src_country = ? OR dst_country = ?)
		GROUP BY src_key, dst_key
		ORDER BY SUM(octets) DESC, src_key, dst_key`
	pargs := append(append([]any{}, w.args...), country, country, country)
	pRows, err := q.db.pool.QueryContext(ctx, pathSQL, pargs...)
	if err != nil {
		return out, mapErr(ctx, err)
	}
	paths, err := scanPaths(ctx, pRows)
	if err != nil {
		return out, err
	}
	out.Paths, out.PathsOmitted, out.OtherOctets = capPaths(paths, lim, 0, 0, false)
	return out, nil
}

func kindExpr(end string) string {
	return `CASE
		WHEN ` + end + `_scope != 'global' OR ` + end + `_geo_outcome != 'value' OR IFNULL(` + end + `_country, '') = '' THEN NULL
		WHEN ` + end + `_lat IS NOT NULL AND IFNULL(` + end + `_city, '') != '' THEN 'city'
		WHEN ` + end + `_lat IS NOT NULL THEN 'coord'
		ELSE 'country' END`
}

func placeKey(end string) string {
	return `CASE
		WHEN ` + end + `_scope != 'global' OR ` + end + `_geo_outcome != 'value' OR IFNULL(` + end + `_country, '') = '' THEN NULL
		WHEN ` + end + `_lat IS NOT NULL AND IFNULL(` + end + `_city, '') != '' AND IFNULL(` + end + `_region, '') != '' THEN 'city:' || ` + end + `_country || ':' || ` + end + `_region || ':' || ` + end + `_city
		WHEN ` + end + `_lat IS NOT NULL AND IFNULL(` + end + `_city, '') != '' THEN 'city:' || ` + end + `_country || ':-:' || ` + end + `_city
		WHEN ` + end + `_lat IS NOT NULL THEN 'coord:' || ` + end + `_country || ':' || printf('%.1f', ` + end + `_lat) || ':' || printf('%.1f', ` + end + `_lon)
		ELSE 'cc:' || ` + end + `_country END`
}

func scanCountries(ctx context.Context, rows *sql.Rows) ([]GeoCountry, error) {
	defer rows.Close()
	out := []GeoCountry{}
	for rows.Next() {
		var c GeoCountry
		var packets, octets, flows int64
		if err := rows.Scan(&c.ISOA2, &packets, &octets, &flows); err != nil {
			return nil, mapErr(ctx, err)
		}
		c.Packets = u64(packets)
		c.Octets = u64(octets)
		c.Flows = u64(flows)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(ctx, err)
	}
	return out, nil
}

func scanPaths(ctx context.Context, rows *sql.Rows) ([]GeoPath, error) {
	defer rows.Close()
	out := []GeoPath{}
	for rows.Next() {
		var srcKind, dstKind, srcCC, dstCC, srcReg, dstReg, srcCity, dstCity string
		var srcLat, srcLon, dstLat, dstLon sql.NullFloat64
		var packets, octets, flows int64
		if err := rows.Scan(&srcKind, &dstKind, &srcCC, &dstCC, &srcReg, &dstReg, &srcCity, &dstCity,
			&srcLat, &srcLon, &dstLat, &dstLon, &packets, &octets, &flows); err != nil {
			return nil, mapErr(ctx, err)
		}
		out = append(out, GeoPath{
			Src:     makePlace(srcKind, srcCC, srcReg, srcCity, srcLat, srcLon),
			Dst:     makePlace(dstKind, dstCC, dstReg, dstCity, dstLat, dstLon),
			Packets: u64(packets),
			Octets:  u64(octets),
			Flows:   u64(flows),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(ctx, err)
	}
	return out, nil
}

func makePlace(kind, country, region, city string, lat, lon sql.NullFloat64) GeoPlace {
	p := GeoPlace{Kind: kind, ISOA2: country}
	if kind == "city" {
		p.City = city
		if region != "" {
			p.Region = region
		}
	}
	if (kind == "city" || kind == "coord") && lat.Valid && lon.Valid {
		p.Lat = lat.Float64
		p.Lon = lon.Float64
		p.HasCoord = true
	}
	return p
}

func (q *Query) otherPaths(ctx context.Context, start, end time.Time) (octets uint64, pairs int64, err error) {
	var o, p sql.NullInt64
	err = q.db.pool.QueryRowContext(ctx, `SELECT COALESCE(SUM(octets), 0), COALESCE(SUM(pairs_omitted), 0)
		FROM geo_path_other_5m WHERE bucket_ms >= ? AND bucket_ms < ?`, start.UnixMilli(), end.UnixMilli()).Scan(&o, &p)
	if err != nil {
		return 0, 0, mapErr(ctx, err)
	}
	return u64(o.Int64), p.Int64, nil
}

// capPaths keeps the busiest lim paths. pairs and other are the in-memory prune.
// includeOther is false when a country filter makes the prune unattributable.
func capPaths(paths []GeoPath, lim int, pairs int64, other uint64, includeOther bool) ([]GeoPath, int64, uint64) {
	omitted := pairs
	extra := other
	if !includeOther {
		omitted = 0
		extra = 0
	}
	if lim > len(paths) {
		lim = len(paths)
	}
	for _, p := range paths[lim:] {
		omitted++
		extra += p.Octets
	}
	if paths == nil {
		paths = []GeoPath{}
	}
	return paths[:lim], omitted, extra
}

func (q *Query) oneUint(ctx context.Context, qs string, args ...any) (uint64, error) {
	var n sql.NullInt64
	if err := q.db.pool.QueryRowContext(ctx, qs, args...).Scan(&n); err != nil {
		return 0, mapErr(ctx, err)
	}
	return u64(n.Int64), nil
}

func scanFlow(rows *sql.Rows) (FlowRow, int64, int64, error) {
	var row FlowRow
	var startMS, endMS int64
	var srcPort, dstPort, proto, dir, interval, algo sql.NullInt64
	var packets, octets int64
	var sampled, clamped int64
	var bgpSrc, bgpDst sql.NullInt64
	err := rows.Scan(&row.ID, &startMS, &endMS, &row.Exporter, &row.Domain, &row.Version, &row.Src, &row.Dst,
		&srcPort, &dstPort, &proto, &packets, &octets, &row.CounterSemantics, &row.OctetSemantics,
		&dir, &sampled, &interval, &algo, &clamped, &bgpSrc, &bgpDst, &row.SrcScope, &row.DstScope,
		&row.SrcGeo, &row.DstGeo, &row.SrcASN, &row.DstASN, &row.SrcRep, &row.DstRep)
	if err != nil {
		return FlowRow{}, 0, 0, err
	}
	row.Start = time.UnixMilli(startMS).UTC()
	row.End = time.UnixMilli(endMS).UTC()
	row.Packets = u64(packets)
	row.Octets = u64(octets)
	row.Sampled = sampled != 0
	row.ClockClamped = clamped != 0
	row.SrcPort = nullInt(srcPort)
	row.DstPort = nullInt(dstPort)
	row.Proto = nullInt(proto)
	row.FlowDirection = nullInt(dir)
	row.SamplingAlgorithm = nullInt(algo)
	if interval.Valid {
		v := interval.Int64
		row.SamplingInterval = &v
	}
	if bgpSrc.Valid {
		v := bgpSrc.Int64
		row.BGPSrcAS = &v
	}
	if bgpDst.Valid {
		v := bgpDst.Int64
		row.BGPDstAS = &v
	}
	return row, startMS, row.ID, nil
}

func nullInt(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}

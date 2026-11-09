// Package obs holds process-lifetime counters for the collector.
package obs

import (
	"errors"
	"sync"
)

// ErrUnknownCounter is returned by Add when name is not one of the
// process-lifetime counters. Add leaves every counter unchanged.
// errors.Is reports this sentinel.
var ErrUnknownCounter = errors.New("unknown counter")

// Name is one process-lifetime counter. The string value is the stats JSON key.
type Name string

const (
	UDPReceivedPackets            Name = "udp_received_packets"
	UDPReceivedBytes              Name = "udp_received_bytes"
	DecodedPackets                Name = "decoded_packets"
	DecodedFlows                  Name = "decoded_flows"
	DroppedQueue                  Name = "dropped_queue"
	DroppedEnrichQueue            Name = "dropped_enrich_queue"
	DroppedWriterQueue            Name = "dropped_writer_queue"
	DroppedTemplate               Name = "dropped_template"
	DroppedDisk                   Name = "dropped_disk"
	Malformed                     Name = "malformed"
	MissingTemplate               Name = "missing_template"
	TemplatesWithdrawn            Name = "templates_withdrawn"
	WithdrawUnknown               Name = "withdraw_unknown"
	TemplateRedefined             Name = "template_redefined"
	TemplateIdleExpired           Name = "template_idle_expired"
	TemplateEvicted               Name = "template_evicted"
	ReservedSet                   Name = "reserved_set"
	CountDisagrees                Name = "count_disagrees"
	PaddingNonzero                Name = "padding_nonzero"
	SequenceGapV5Flows            Name = "sequence_gap_v5_flows"
	SequenceGapV9Packets          Name = "sequence_gap_v9_packets"
	SequenceGapIPFIXRecords       Name = "sequence_gap_ipfix_records"
	SequenceReorder               Name = "sequence_reorder"
	SequenceDuplicate             Name = "sequence_duplicate"
	SequenceReset                 Name = "sequence_reset"
	SequenceUnresolved            Name = "sequence_unresolved"
	NonFlowRecords                Name = "non_flow_records"
	TimestampSkew                 Name = "timestamp_skew"
	TimestampSuspect              Name = "timestamp_suspect"
	TimestampExportFallback       Name = "timestamp_export_fallback"
	ClockClamped                  Name = "clock_clamped"
	EnrichGeoIPNotConfigured      Name = "enrich_geoip_not_configured"
	EnrichGeoIPNoData             Name = "enrich_geoip_no_data"
	EnrichGeoIPError              Name = "enrich_geoip_error"
	EnrichGeoIPValue              Name = "enrich_geoip_value"
	EnrichGeoIPSkipped            Name = "enrich_geoip_skipped"
	EnrichASNNotConfigured        Name = "enrich_asn_not_configured"
	EnrichASNNoData               Name = "enrich_asn_no_data"
	EnrichASNError                Name = "enrich_asn_error"
	EnrichASNValue                Name = "enrich_asn_value"
	EnrichASNSkipped              Name = "enrich_asn_skipped"
	EnrichReputationNotConfigured Name = "enrich_reputation_not_configured"
	EnrichReputationNoData        Name = "enrich_reputation_no_data"
	EnrichReputationError         Name = "enrich_reputation_error"
	EnrichReputationValue         Name = "enrich_reputation_value"
	EnrichReputationSkipped       Name = "enrich_reputation_skipped"
	SQLiteWriteFailures           Name = "sqlite_write_failures"
	SQLiteRowsWritten             Name = "sqlite_rows_written"
)

// allNames is every counter Snapshot must return, including ones still at zero.
var allNames = []Name{
	UDPReceivedPackets,
	UDPReceivedBytes,
	DecodedPackets,
	DecodedFlows,
	DroppedQueue,
	DroppedEnrichQueue,
	DroppedWriterQueue,
	DroppedTemplate,
	DroppedDisk,
	Malformed,
	MissingTemplate,
	TemplatesWithdrawn,
	WithdrawUnknown,
	TemplateRedefined,
	TemplateIdleExpired,
	TemplateEvicted,
	ReservedSet,
	CountDisagrees,
	PaddingNonzero,
	SequenceGapV5Flows,
	SequenceGapV9Packets,
	SequenceGapIPFIXRecords,
	SequenceReorder,
	SequenceDuplicate,
	SequenceReset,
	SequenceUnresolved,
	NonFlowRecords,
	TimestampSkew,
	TimestampSuspect,
	TimestampExportFallback,
	ClockClamped,
	EnrichGeoIPNotConfigured,
	EnrichGeoIPNoData,
	EnrichGeoIPError,
	EnrichGeoIPValue,
	EnrichGeoIPSkipped,
	EnrichASNNotConfigured,
	EnrichASNNoData,
	EnrichASNError,
	EnrichASNValue,
	EnrichASNSkipped,
	EnrichReputationNotConfigured,
	EnrichReputationNoData,
	EnrichReputationError,
	EnrichReputationValue,
	EnrichReputationSkipped,
	SQLiteWriteFailures,
	SQLiteRowsWritten,
}

// Counters is the process-lifetime set. Values are never reset.
// Add and Snapshot are safe for concurrent use.
type Counters struct {
	mu sync.Mutex
	n  map[Name]uint64
}

// NewCounters returns every Name at zero.
func NewCounters() *Counters {
	c := &Counters{n: make(map[Name]uint64, len(allNames))}
	for _, name := range allNames {
		c.n[name] = 0
	}
	return c
}

// Add adds n to name. n is a delta, not a new total.
// An unknown name returns ErrUnknownCounter and does not change the snapshot.
// A known name returns nil.
func (c *Counters) Add(name Name, n uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.n[name]; !ok {
		return ErrUnknownCounter
	}
	c.n[name] += n
	return nil
}

// Snapshot returns every Name and its current value, including zeros.
// The caller owns the map. Snapshot does not return an error.
func (c *Counters) Snapshot() map[Name]uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[Name]uint64, len(c.n))
	for name, v := range c.n {
		out[name] = v
	}
	return out
}

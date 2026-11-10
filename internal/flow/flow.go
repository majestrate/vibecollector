// Package flow is the canonical record shared by decode, enrich, and store.
// It does not import those packages.
package flow

import (
	"errors"
	"net/netip"
	"time"
)

// TimeSource says how Start and End were chosen.
type TimeSource uint8

const (
	TimeSysUpTime TimeSource = iota // device milliseconds
	TimeAbsolute                    // IPFIX absolute IE
	TimeExport                      // header export time only
	TimeReceive                     // collector receive time
)

// Flow is one canonical record. The decoder fills every field except
// SrcEnrich and DstEnrich. The enrich pipeline fills those two.
// Addresses, packet and octet counters, version, exporter, domain, receive
// time, both semantics strings, and a start/end pair are required before
// Submit. Ports, protocol, TCP flags, ToS, interfaces, nexthop, masks, BGP
// AS numbers, sampling interval, and direction are optional.
// CounterSemantics is "delta" or "total". OctetSemantics is "ip" or
// "l4_payload". Stored Packets and Octets are never multiplied by N.
// ClockClamped is set when Start or End was moved into
// [ReceivedAt - timestamp_max_age, ReceivedAt + timestamp_skew_slack].
type Flow struct {
	ReceivedAt   time.Time
	ExportTime   time.Time
	Start, End   time.Time
	TimeSource   TimeSource
	ClockClamped bool

	Exporter netip.Addr
	Domain   uint32
	Version  uint16

	Src, Dst         netip.Addr
	SrcPort, DstPort uint16
	PortsPresent     bool
	Proto            uint8
	ProtoPresent     bool
	TCPFlags         uint8
	TCPFlagsPresent  bool
	TOS              uint8
	TOSPresent       bool
	FlowDirection    *uint8

	Packets               uint64
	Octets                uint64
	CounterSemantics      string
	OctetSemantics        string
	OutPackets, OutOctets *uint64

	InputIf, OutputIf  *uint32
	NextHop            *netip.Addr
	BGPSrcAS, BGPDstAS *uint32
	SrcMask, DstMask   *uint8

	Sampled           bool
	SamplingInterval  *uint32
	SamplingAlgorithm *uint8

	SrcEnrich, DstEnrich Endpoint
}

// ExporterDelta is the health update for one source IP, domain, and version.
// A packet that produces no Flow still produces a delta. Version 0 and
// Domain 0 mean the header did not yield a version. LastSeen is the receive
// time. The counters are deltas for this packet, not running totals.
// GapFlows, GapPackets, and GapRecords are the three sequence units and are
// not summed together.
type ExporterDelta struct {
	Exporter        netip.Addr
	Domain          uint32
	Version         uint16
	LastSeen        time.Time
	Packets         uint64
	Flows           uint64
	Malformed       uint64
	MissingTemplate uint64
	GapFlows        uint64
	GapPackets      uint64
	GapRecords      uint64
}

// Sink is the writer queue. store.Writer is the production sink.
// enrich.Pipeline.Run is the only caller of Submit. Decode workers do not
// call Submit. They send decoded flows on main's chan flow.Flow and call
// SubmitDelta only. SubmitDelta accepts one exporter delta.
type Sink interface {
	// Submit enqueues enriched flows for the writer.
	// flows is the batch the pipeline already annotated.
	// ErrQueueFull means the writer queue cannot take them. The caller drops
	// those flows. Submit does not block past the queue.
	// Decode workers do not call Submit.
	Submit(flows []Flow) error

	// SubmitDelta accepts one exporter delta from a decode worker.
	// d is the packet delta, or one gap delta whose domain differs from it.
	// SubmitDelta does not return an error and does not drop a delta.
	SubmitDelta(d ExporterDelta)
}

// ErrQueueFull is what Submit returns when the writer queue cannot take the
// flows. Pipeline.Run increments dropped_writer_queue and drops those flows.
// The flow queue does not use this error. A full flow queue is a non-blocking
// send by the decode worker, which increments dropped_enrich_queue.
// SubmitDelta has no matching error. A delta is never dropped.
var ErrQueueFull = errors.New("queue full")

// Endpoint is one address's classification and three provider outcomes.
// The decoder leaves it zero. The pipeline fills it before Submit.
type Endpoint struct {
	Scope Scope
	Geo   Outcome
	ASN   Outcome
	Rep   Outcome
}

// Scope is the local classification name: unspecified, loopback, link_local,
// multicast, broadcast, private, shared, documentation, benchmark, reserved,
// or global. Only global is looked up.
type Scope string

// Outcome is one provider result stored on the flow.
// Kind is not_configured, no_data, error, value, or skipped.
type Outcome struct {
	Kind                  OutcomeKind
	Country, Region, City string
	Lat, Lon              float64
	HasLatLon             bool
	ASN                   uint32
	ASNName               string
	Category              string
	Score                 float64
	HasScore              bool
}

// OutcomeKind is the stored outcome string.
type OutcomeKind string

const (
	OutcomeNotConfigured OutcomeKind = "not_configured"
	OutcomeNoData        OutcomeKind = "no_data"
	OutcomeError         OutcomeKind = "error"
	OutcomeValue         OutcomeKind = "value"
	OutcomeSkipped       OutcomeKind = "skipped"
)

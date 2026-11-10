// Package v5 decodes one NetFlow v5 datagram into canonical flows.
package v5

import (
	"encoding/binary"
	"net/netip"
	"time"

	"vibecollector/internal/decode"
	"vibecollector/internal/flow"
	"vibecollector/internal/ingest"
	"vibecollector/internal/obs"
	"vibecollector/internal/sampling"
	"vibecollector/internal/sequence"
)

const (
	headerLen = 24
	recordLen = 48
	maxCount  = 30
)

// Parse decodes one NetFlow v5 datagram.
// d.Src is the exporter. d.Payload is the UDP payload, header included.
// d.ReceivedAt is the clamp window's anchor. samples receives the device-scope
// fact from the header sampling word whenever the 24-byte header parses,
// including a truncated body and a count outside 1–30. A nil samples skips
// that write. seq is updated by the header flow count when the 24-byte header
// parses. counters receives malformed, sequence, and timestamp increments.
// maxAge and skew are timestamp_max_age and timestamp_skew_slack. They bound
// AbsMillis and the receive-window clamp.
// The returned flows use sampling.Rate, so the sampled bit matches v9 and IPFIX.
// Packets and octets are the exported dPkts and dOctets. They are not multiplied.
// N is the low 14 bits of the sampling word. Algorithm is the raw top 2 bits.
// The cached fact is sampled only when N > 1. N of 0 is stored as unknown.
// A count of 0 or greater than 30, or a payload shorter than 24+count*48,
// returns a delta with Version 5, increments malformed, and returns
// decode.ErrMalformed. A header shorter than 24 bytes, or a version other
// than 5, returns the same error with Version 0 unless the first uint16 is
// already 5. Trailing bytes after the records are ignored.
// A nil seq skips the cursor update. A nil counters skips counter increments.
// Parse does not touch the template cache, the hold buffer, or SQLite.
func Parse(d ingest.Datagram, samples *sampling.Cache, seq *sequence.Table, counters *obs.Counters, maxAge, skew time.Duration) ([]flow.Flow, flow.ExporterDelta, error) {
	delta := flow.ExporterDelta{
		Exporter: d.Src.Unmap(),
		LastSeen: d.ReceivedAt,
		Packets:  1,
	}
	payload := d.Payload
	if len(payload) < headerLen {
		if len(payload) >= 2 && binary.BigEndian.Uint16(payload[0:2]) == 5 {
			delta.Version = 5
		}
		return malformed(delta, counters)
	}
	version := binary.BigEndian.Uint16(payload[0:2])
	count := binary.BigEndian.Uint16(payload[2:4])
	if version != 5 {
		return malformed(delta, counters)
	}
	sysUp := binary.BigEndian.Uint32(payload[4:8])
	unixSecs := binary.BigEndian.Uint32(payload[8:12])
	unixNsecs := binary.BigEndian.Uint32(payload[12:16])
	seqNo := binary.BigEndian.Uint32(payload[16:20])
	delta.Version = 5
	delta.Domain = uint32(payload[20])<<8 | uint32(payload[21])
	sampleWord := binary.BigEndian.Uint16(payload[22:24])
	if samples != nil {
		n := uint32(sampleWord & 0x3FFF)
		samples.Put(sampling.SampleKey{
			Exporter: delta.Exporter,
			Domain:   delta.Domain,
			Scope:    "device",
		}, sampling.Sample{
			N:         n,
			Algorithm: uint8(sampleWord >> 14),
			Sampled:   n > 1,
		})
	}

	if count == 0 || count > maxCount {
		return malformed(delta, counters)
	}
	// The header parsed. Advance even when the records are truncated, the
	// same way a parsed v9 header advances before a later shortfall.
	if err := applySequence(seq, counters, &delta, seqNo, uint32(count)); err != nil {
		return nil, delta, err
	}
	need := headerLen + int(count)*recordLen
	if len(payload) < need {
		return malformed(delta, counters)
	}

	mode := uint8(sampleWord >> 14)
	interval := uint64(sampleWord & 0x3FFF)
	flows := make([]flow.Flow, 0, count)
	for i := 0; i < int(count); i++ {
		rec := payload[headerLen+i*recordLen : headerLen+(i+1)*recordLen]
		f := recordFlow(rec)
		pkts := f.Packets
		octs := f.Octets
		rated := sampling.Rate(sampling.Input{
			DeltaPackets: &pkts,
			DeltaOctets:  &octs,
			V5Packets:    &pkts,
			V5Octets:     &octs,
			Interval:     &interval,
			Algorithm:    &mode,
		})
		f.Packets = rated.Packets
		f.Octets = rated.Octets
		f.OutPackets = rated.OutPackets
		f.OutOctets = rated.OutOctets
		f.CounterSemantics = rated.CounterSemantics
		f.OctetSemantics = rated.OctetSemantics
		f.Sampled = rated.Sampled
		f.SamplingInterval = rated.SamplingInterval
		f.SamplingAlgorithm = rated.SamplingAlgorithm

		f.Exporter = delta.Exporter
		f.Domain = delta.Domain
		f.Version = 5
		f.ReceivedAt = d.ReceivedAt
		stamp := decode.ResolveSysUp(d.ReceivedAt, unixSecs, unixNsecs, sysUp, firstOf(rec), lastOf(rec), true, true, maxAge, skew)
		f.ExportTime = stamp.Export
		f.Start = stamp.Start
		f.End = stamp.End
		f.TimeSource = stamp.Source
		f.ClockClamped = stamp.ClockClamped
		add(counters, obs.TimestampSkew, stamp.Skew)
		add(counters, obs.TimestampSuspect, stamp.Suspect)
		add(counters, obs.ClockClamped, stamp.Clamped)
		flows = append(flows, f)
	}
	delta.Flows = uint64(len(flows))
	return flows, delta, nil
}

func recordFlow(b []byte) flow.Flow {
	var f flow.Flow
	f.Src = ipv4(binary.BigEndian.Uint32(b[0:4]))
	f.Dst = ipv4(binary.BigEndian.Uint32(b[4:8]))
	nh := ipv4(binary.BigEndian.Uint32(b[8:12]))
	f.NextHop = &nh
	inIf := uint32(binary.BigEndian.Uint16(b[12:14]))
	outIf := uint32(binary.BigEndian.Uint16(b[14:16]))
	f.InputIf = &inIf
	f.OutputIf = &outIf
	f.Packets = uint64(binary.BigEndian.Uint32(b[16:20]))
	f.Octets = uint64(binary.BigEndian.Uint32(b[20:24]))
	f.SrcPort = binary.BigEndian.Uint16(b[32:34])
	f.DstPort = binary.BigEndian.Uint16(b[34:36])
	f.PortsPresent = true
	f.TCPFlags = b[37]
	f.TCPFlagsPresent = true
	f.Proto = b[38]
	f.ProtoPresent = true
	f.TOS = b[39]
	f.TOSPresent = true
	srcAS := uint32(binary.BigEndian.Uint16(b[40:42]))
	dstAS := uint32(binary.BigEndian.Uint16(b[42:44]))
	f.BGPSrcAS = &srcAS
	f.BGPDstAS = &dstAS
	sm := b[44]
	dm := b[45]
	f.SrcMask = &sm
	f.DstMask = &dm
	return f
}

func firstOf(b []byte) uint32 { return binary.BigEndian.Uint32(b[24:28]) }
func lastOf(b []byte) uint32  { return binary.BigEndian.Uint32(b[28:32]) }

func ipv4(v uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

func applySequence(seq *sequence.Table, counters *obs.Counters, delta *flow.ExporterDelta, seqNo, count uint32) error {
	if seq == nil {
		return nil
	}
	key := sequence.Key{Exporter: delta.Exporter, Domain: delta.Domain, Version: 5}
	dec, err := seq.Observe(key, seqNo, count)
	if err != nil {
		return err
	}
	switch dec.Action {
	case sequence.ActionGap:
		delta.GapFlows += uint64(dec.Gap)
		add(counters, obs.SequenceGapV5Flows, uint64(dec.Gap))
	case sequence.ActionReorder:
		add(counters, obs.SequenceReorder, 1)
	case sequence.ActionDuplicate:
		add(counters, obs.SequenceDuplicate, 1)
	case sequence.ActionReset:
		add(counters, obs.SequenceReset, 1)
	case sequence.ActionUnresolved:
		add(counters, obs.SequenceUnresolved, 1)
	}
	return nil
}

func malformed(delta flow.ExporterDelta, counters *obs.Counters) ([]flow.Flow, flow.ExporterDelta, error) {
	delta.Malformed = 1
	delta.Flows = 0
	add(counters, obs.Malformed, 1)
	return nil, delta, decode.ErrMalformed
}

func add(c *obs.Counters, name obs.Name, n uint64) {
	if c == nil || n == 0 {
		return
	}
	_ = c.Add(name, n)
}

func init() {
	decode.RegisterV5Parser(Parse)
}

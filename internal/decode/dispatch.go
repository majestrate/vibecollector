package decode

import (
	"encoding/binary"
	"time"

	"vibecollector/internal/flow"
	"vibecollector/internal/ingest"
	"vibecollector/internal/obs"
	"vibecollector/internal/sampling"
	"vibecollector/internal/sequence"
	"vibecollector/internal/template"
)

type v5Parser func(d ingest.Datagram, samples *sampling.Cache, seq *sequence.Table, counters *obs.Counters, maxAge, skew time.Duration) ([]flow.Flow, flow.ExporterDelta, error)

type v9Parser func(d ingest.Datagram, templates *template.Cache, samples *sampling.Cache, seq *sequence.Table, counters *obs.Counters, retry bool, maxAge, skew time.Duration) ([]flow.Flow, flow.ExporterDelta, *template.Pending, error)

var (
	parseV5 v5Parser
	parseV9 v9Parser
)

// RegisterV5Parser stores the NetFlow v5 parser Dispatch calls.
// v5.init calls it. A nil parser makes version 5 count as malformed.
// RegisterV5Parser does not return an error.
func RegisterV5Parser(fn v5Parser) { parseV5 = fn }

// RegisterV9Parser stores the NetFlow v9 parser Dispatch calls.
// v9.init calls it. A nil parser makes version 9 count as malformed.
// RegisterV9Parser does not return an error.
func RegisterV9Parser(fn v9Parser) { parseV9 = fn }

// Dispatch reads the first big-endian uint16 of d.Payload and calls the v5
// or v9 parser. templates, samples, and seq are the objects whose methods
// the parser calls. The caller is Session.Accept, which already holds the
// exporter mutex. retry is true when this payload is a hold replay.
// maxAge and skew are timestamp_max_age and timestamp_skew_slack. They are
// passed through to the parser and are not replaced when zero.
// A short payload or a version other than 5 or 9 returns a delta with
// Version 0 and Domain 0, a nil missing, and a nil error, after counting
// malformed once. Version 10 is that path until IPFIX is wired.
// ErrShortSet means one set's length ran past the payload. flows still holds
// records from earlier complete sets, and malformed has been incremented once
// by the parser. missing is non-nil when a data set had no template.
// Dispatch does not call Hold and does not advance a cursor itself.
func Dispatch(d ingest.Datagram, templates *template.Cache, samples *sampling.Cache, seq *sequence.Table, counters *obs.Counters, retry bool, maxAge, skew time.Duration) (flows []flow.Flow, delta flow.ExporterDelta, missing *template.Pending, err error) {
	if len(d.Payload) < 2 {
		return unknownVersion(d, counters)
	}
	switch binary.BigEndian.Uint16(d.Payload[:2]) {
	case 5:
		if parseV5 == nil {
			return unknownVersion(d, counters)
		}
		flows, delta, err = parseV5(d, samples, seq, counters, maxAge, skew)
		return flows, delta, nil, err
	case 9:
		if parseV9 == nil {
			return unknownVersion(d, counters)
		}
		return parseV9(d, templates, samples, seq, counters, retry, maxAge, skew)
	default:
		return unknownVersion(d, counters)
	}
}

func unknownVersion(d ingest.Datagram, counters *obs.Counters) ([]flow.Flow, flow.ExporterDelta, *template.Pending, error) {
	if counters != nil {
		_ = counters.Add(obs.Malformed, 1)
	}
	return nil, flow.ExporterDelta{
		Exporter:  d.Src.Unmap(),
		LastSeen:  d.ReceivedAt,
		Packets:   1,
		Malformed: 1,
	}, nil, nil
}

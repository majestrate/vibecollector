// Package ipfix decodes one IPFIX message into canonical flows.
package ipfix

import (
	"encoding/binary"
	"log/slog"
	"math"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/majestrate/vibecollector/internal/decode"
	"github.com/majestrate/vibecollector/internal/flow"
	"github.com/majestrate/vibecollector/internal/ingest"
	"github.com/majestrate/vibecollector/internal/obs"
	"github.com/majestrate/vibecollector/internal/sampling"
	"github.com/majestrate/vibecollector/internal/sequence"
	"github.com/majestrate/vibecollector/internal/template"
)

const (
	headerLen = 16
	// ntpEpochOffset is seconds from 1900-01-01 UTC to the Unix epoch.
	// Era 0 ends 2^32 seconds after 1900-01-01, which is 2036-02-07 06:28:16 UTC.
	ntpEpochOffset int64 = 2_208_988_800
)

// Parse decodes one IPFIX message into canonical flows.
// templates, samples, and seq are called through their exported methods.
// retry true means Session is replaying a held datagram. missing_template
// and malformed are not incremented again, and a sequence number already
// counted is not passed to Observe again. Template and withdrawal sets are
// not applied again; they were applied on first sight. When the replay can
// now be sized, Parse calls sequence.Table.ApplyIfUnchanged with the
// snapshot saved for this hold. The gap is applied only when expected is
// still that saved value.
// maxAge and skew are timestamp_max_age and timestamp_skew_slack. Zero is
// not replaced. maxAge bounds the IE 160 wrap and the receive-window clamp.
// skew is only the clamp's future edge.
// The header is 16 bytes. length is octets in the message, including the
// header, not a record count. It must be >= 16 and <= len(payload). A
// shorter payload is malformed (decode.ErrMalformed). Bytes past length are
// ignored. There is no header sysUpTime.
// Set Length includes the 4-octet set header. A tail shorter than 4 bytes
// is ignored. A Length below 4 or past the message stops that set, increments
// malformed once, and keeps records from earlier complete sets
// (decode.ErrShortSet).
// Set IDs 0, 1, and 4–255 are skipped by Length and increment reserved_set.
// Set 2 is templates. Set 3 is options templates. 256 and above are data.
// The enterprise bit is masked (id & 0x7FFF) before an IANA compare. An
// enterprise specifier is 8 bytes. Reduced-size encoding reads field_len.
// A variable-length IE (field_len 65535) consumes a 1-octet or 3-octet
// prefix that is not part of N.
// Padding shorter than a record is accepted. Non-zero padding increments
// padding_nonzero. The set length need not be a multiple of the record size.
// An options template is three uint16s. Field count 0 is a withdrawal and
// omits the scope-count uint16. Withdrawal is honored on UDP; see withdraw.
// Template records do not advance the sequence. Options data records do.
// An unsized data set calls ObserveUnresolved and does not invent a count.
// Gaps are GapRecords and sequence_gap_ipfix_records only.
// Absolute timestamps outrank sysUpTime per endpoint. NTP era 0 ends at
// 2036-02-07 06:28:16 UTC. The era closest to d.ReceivedAt is stored.
// A nil templates, samples, seq, or counters skips that side effect.
// Parse does not call Hold and does not touch SQLite.
// Parse returns decode.ErrMalformed or decode.ErrShortSet, or an error from
// sequence.Table.Observe.
func Parse(d ingest.Datagram, templates *template.Cache, samples *sampling.Cache, seq *sequence.Table, counters *obs.Counters, retry bool, maxAge, skew time.Duration) ([]flow.Flow, flow.ExporterDelta, *template.Pending, error) {
	p := &parser{
		d:         d,
		templates: templates,
		samples:   samples,
		seq:       seq,
		counters:  counters,
		retry:     retry,
		maxAge:    maxAge,
		skew:      skew,
		exporter:  d.Src.Unmap(),
		delta: flow.ExporterDelta{
			Exporter: d.Src.Unmap(),
			LastSeen: d.ReceivedAt,
			Packets:  1,
		},
	}
	return p.decode()
}

type parser struct {
	d           ingest.Datagram
	templates   *template.Cache
	samples     *sampling.Cache
	seq         *sequence.Table
	counters    *obs.Counters
	retry       bool
	maxAge      time.Duration
	skew        time.Duration
	exporter    netip.Addr
	domain      uint32
	exportUnix  uint32
	headerSeq   uint32
	delta       flow.ExporterDelta
	bad         bool
	flows       []flow.Flow
	missing     *template.Pending
	unsized     bool
	seenUnsized bool
	prefix      uint32
	dataRecords uint32
}

type setRef struct {
	id   uint16
	off  int
	body []byte
}

func (p *parser) decode() ([]flow.Flow, flow.ExporterDelta, *template.Pending, error) {
	payload := p.d.Payload
	if len(payload) < headerLen || binary.BigEndian.Uint16(payload[:2]) != 10 {
		if len(payload) >= 2 && binary.BigEndian.Uint16(payload[:2]) == 10 {
			p.delta.Version = 10
		}
		p.markBad()
		p.delta.Flows = 0
		return nil, p.delta, nil, decode.ErrMalformed
	}
	p.delta.Version = 10
	msgLen := int(binary.BigEndian.Uint16(payload[2:4]))
	p.exportUnix = binary.BigEndian.Uint32(payload[4:8])
	p.headerSeq = binary.BigEndian.Uint32(payload[8:12])
	p.domain = binary.BigEndian.Uint32(payload[12:16])
	p.delta.Domain = p.domain
	if msgLen < headerLen || msgLen > len(payload) {
		p.markBad()
		p.delta.Flows = 0
		return nil, p.delta, nil, decode.ErrMalformed
	}
	msg := payload[:msgLen]

	var dataSets []setRef
	off := headerLen
	short := false
	for off+4 <= len(msg) {
		id := binary.BigEndian.Uint16(msg[off : off+2])
		setLen := int(binary.BigEndian.Uint16(msg[off+2 : off+4]))
		end := off + setLen
		if setLen < 4 || end > len(msg) {
			p.markBad()
			short = true
			break
		}
		body := msg[off+4 : end]
		switch {
		case id == 2 || id == 3:
			// A withdrawal or a stale definition in this suffix must not
			// replace a template installed after the datagram was held.
			if !p.retry {
				p.templateSet(body, id == 3)
			}
		case id < 256:
			p.countOnce(obs.ReservedSet, 1)
		default:
			dataSets = append(dataSets, setRef{id: id, off: off, body: body})
		}
		off = end
	}
	for _, s := range dataSets {
		p.dataSet(s)
	}
	if err := p.finishSequence(); err != nil {
		return nil, p.delta, nil, err
	}
	p.delta.Flows = uint64(len(p.flows))
	if short {
		return p.flows, p.delta, p.missing, decode.ErrShortSet
	}
	return p.flows, p.delta, p.missing, nil
}

func (p *parser) templateSet(body []byte, options bool) {
	for {
		if len(body) < 4 {
			p.notePad(body)
			return
		}
		tid := binary.BigEndian.Uint16(body[0:2])
		fc := binary.BigEndian.Uint16(body[2:4])
		if fc == 0 {
			// Field count 0 is 4 bytes. The options scope count is not present.
			body = body[4:]
			p.withdrawRecord(options, tid)
			continue
		}
		specAt := 4
		scopeN := 0
		badScope := false
		if options {
			if len(body) < 6 {
				p.markBad()
				return
			}
			scopeN = int(binary.BigEndian.Uint16(body[4:6]))
			if scopeN == 0 || scopeN > int(fc) {
				badScope = true
				p.markBad()
			}
			specAt = 6
		}
		fields, rest, ok := parseSpecifiers(body[specAt:], int(fc))
		if !ok {
			p.markBad()
			return
		}
		body = rest
		if badScope || tid < 256 || !usable(fields) {
			if !badScope {
				p.markBad()
			}
			continue
		}
		p.install(tid, fields, scopeN)
	}
}

// withdrawRecord applies one field-count-0 record.
// Wildcards are checked before a single template ID, at any set length that
// still parsed. Set 2 template ID 2 drops every data template. Set 3
// template ID 3 drops every options template.
func (p *parser) withdrawRecord(options bool, tid uint16) {
	if !options && tid == 2 {
		p.withdraw(0, true, false)
		return
	}
	if options && tid == 3 {
		p.withdraw(0, false, true)
		return
	}
	p.withdraw(tid, false, false)
}

// withdraw removes templates for one IPFIX withdrawal record.
// RFC 7011 §8.4 says exporting processes must not send withdrawals on UDP
// and collecting processes must ignore them. AGENTS.md requires withdrawal,
// so a UDP message is honored. An unknown single ID increments
// withdraw_unknown and does not fail the packet. Each removed definition
// increments templates_withdrawn. v9 does not call this.
func (p *parser) withdraw(id uint16, allData, allOptions bool) {
	if p.templates == nil {
		return
	}
	removed, unknown := p.templates.Withdraw(p.exporter, p.domain, id, allData, allOptions)
	if removed > 0 {
		p.countOnce(obs.TemplatesWithdrawn, uint64(removed))
	}
	if !allData && !allOptions && unknown {
		p.countOnce(obs.WithdrawUnknown, 1)
	}
}

func (p *parser) install(id uint16, fields []template.Field, scopeN int) {
	if p.templates == nil {
		return
	}
	changed, evicted, err := p.templates.Put(template.Key{
		Exporter: p.exporter,
		Domain:   p.domain,
		Version:  10,
		ID:       id,
	}, template.Template{
		Fields:   fields,
		ScopeN:   scopeN,
		Received: p.d.ReceivedAt,
	})
	if err != nil {
		p.markBad()
		return
	}
	if changed {
		p.countOnce(obs.TemplateRedefined, 1)
		if !p.retry {
			slog.Info("template redefined", "exporter", p.exporter.String(), "domain", p.domain, "template", id)
		}
	}
	if evicted.IsValid() {
		p.countAlways(obs.TemplateEvicted, 1)
	}
	if evicted == p.exporter {
		if p.samples != nil {
			p.samples.DropExporter(p.exporter)
		}
		if p.seq != nil {
			p.seq.DropExporter(p.exporter)
		}
		forgetExporter(p.exporter)
	}
}

func (p *parser) dataSet(s setRef) {
	var tpl template.Template
	ok := false
	if p.templates != nil {
		tpl, ok = p.templates.Get(template.Key{Exporter: p.exporter, Domain: p.domain, Version: 10, ID: s.id})
	}
	if !ok {
		if !p.retry {
			p.delta.MissingTemplate++
			p.countAlways(obs.MissingTemplate, 1)
		}
		if p.missing == nil {
			p.missing = &template.Pending{
				Exporter:   p.exporter,
				Domain:     p.domain,
				Version:    10,
				ReceivedAt: p.d.ReceivedAt,
				RetryAt:    s.off,
			}
		}
		p.markUnsized()
		return
	}
	if size, fixed := fixedSize(tpl.Fields); fixed {
		if size <= 0 {
			p.markBad()
			p.markUnsized()
			return
		}
		nRec := len(s.body) / size
		p.notePad(s.body[nRec*size:])
		p.dataRecords += uint32(nRec)
		for i := 0; i < nRec; i++ {
			v, _, ok := readValues(tpl, s.body[i*size:(i+1)*size])
			if !ok {
				p.markBad()
				continue
			}
			p.emit(tpl, v)
		}
		return
	}
	min := minRecord(tpl.Fields)
	if min <= 0 {
		p.markBad()
		p.markUnsized()
		return
	}
	body := s.body
	var n uint32
	for len(body) >= min {
		v, used, ok := readValues(tpl, body)
		if !ok || used <= 0 {
			// The length prefix ran past the set. The record count is unknown.
			p.markUnsized()
			return
		}
		if used > len(body) {
			p.markUnsized()
			return
		}
		n++
		p.emit(tpl, v)
		body = body[used:]
	}
	p.notePad(body)
	p.dataRecords += n
}

func (p *parser) emit(tpl template.Template, v values) {
	if v.hasInit {
		storeBoot(p.exporter, p.domain, v.initMs)
	}
	if tpl.ScopeN > 0 {
		p.optionsData(tpl, v)
		p.countOnce(obs.NonFlowRecords, 1)
		return
	}
	if !v.hasSrc || !v.hasDst {
		if v.hasSampling {
			p.storeFact(v)
		}
		p.countOnce(obs.NonFlowRecords, 1)
		return
	}
	if p.missing != nil {
		return
	}
	f, st := p.makeFlow(v)
	p.flows = append(p.flows, f)
	p.countAlways(obs.TimestampSuspect, st.suspect)
	p.countAlways(obs.ClockClamped, st.clamped)
	p.countAlways(obs.TimestampExportFallback, st.fallback)
}

func (p *parser) optionsData(tpl template.Template, v values) {
	if p.samples == nil {
		return
	}
	// Put replaces the whole fact. An options record with no sampling IE,
	// such as IE 160 alone, must not clear a rate. emit stored IE 160 first.
	if !v.hasSampling {
		return
	}
	keys := append([]string(nil), v.scopeKeys...)
	if v.sampler != nil {
		keys = append(keys, "sampler:"+strconv.FormatUint(*v.sampler, 10))
	}
	if len(keys) == 0 {
		if tpl.ScopeN > 0 && v.scopeOK == 0 {
			return
		}
		keys = []string{"device"}
	}
	sample := factSample(v)
	for _, k := range keys {
		p.samples.Put(sampling.SampleKey{Exporter: p.exporter, Domain: p.domain, Scope: k}, sample)
	}
}

func (p *parser) storeFact(v values) {
	if p.samples == nil {
		return
	}
	sample := factSample(v)
	var keys []string
	if v.inputIf != nil {
		keys = append(keys, "if:"+strconv.FormatUint(uint64(*v.inputIf), 10))
	}
	if v.sampler != nil {
		keys = append(keys, "sampler:"+strconv.FormatUint(*v.sampler, 10))
	}
	if len(keys) == 0 {
		keys = []string{"device"}
	}
	for _, k := range keys {
		p.samples.Put(sampling.SampleKey{Exporter: p.exporter, Domain: p.domain, Scope: k}, sample)
	}
}

func factSample(v values) sampling.Sample {
	rated := sampling.Rate(rateInput(v))
	var s sampling.Sample
	if rated.SamplingInterval != nil {
		s.N = *rated.SamplingInterval
	}
	s.Sampled = rated.Sampled
	if rated.SamplingAlgorithm != nil {
		s.Algorithm = *rated.SamplingAlgorithm
	}
	return s
}

func rateInput(v values) sampling.Input {
	return sampling.Input{
		DeltaOctets:     v.inBytes,
		DeltaPackets:    v.inPkts,
		OutOctets:       v.outBytes,
		OutPackets:      v.outPkts,
		TotalOctets:     v.totBytes,
		TotalPackets:    v.totPkts,
		InitiatorOctets: v.initOct,
		ResponderOctets: v.respOct,
		Interval:        v.interval,
		RandomInterval:  v.random,
		Selected:        v.selected,
		SelectedPackets: v.selectedPkts,
		Algorithm:       v.algo,
	}
}

type stampCounts struct {
	suspect, clamped, fallback uint64
}

func (p *parser) makeFlow(v values) (flow.Flow, stampCounts) {
	in := rateInput(v)
	p.applyCachedRate(v, &in)
	rated := sampling.Rate(in)
	var f flow.Flow
	f.Src = v.src
	f.Dst = v.dst
	f.SrcPort = v.srcPort
	f.DstPort = v.dstPort
	f.PortsPresent = v.ports
	f.Proto = v.proto
	f.ProtoPresent = v.protoOK
	f.TCPFlags = v.tcpFlags
	f.TCPFlagsPresent = v.tcpOK
	f.TOS = v.tos
	f.TOSPresent = v.tosOK
	f.FlowDirection = v.dir
	f.Packets = rated.Packets
	f.Octets = rated.Octets
	f.OutPackets = rated.OutPackets
	f.OutOctets = rated.OutOctets
	f.CounterSemantics = rated.CounterSemantics
	f.OctetSemantics = rated.OctetSemantics
	f.Sampled = rated.Sampled
	f.SamplingInterval = rated.SamplingInterval
	f.SamplingAlgorithm = rated.SamplingAlgorithm
	f.InputIf = v.inputIf
	f.OutputIf = v.outputIf
	f.NextHop = v.nextHop
	f.BGPSrcAS = v.bgpSrc
	f.BGPDstAS = v.bgpDst
	f.SrcMask = v.srcMask
	f.DstMask = v.dstMask
	f.Exporter = p.exporter
	f.Domain = p.domain
	f.Version = 10
	f.ReceivedAt = p.d.ReceivedAt
	start, end, export, src, clamped, st := p.resolveTimes(v)
	f.ExportTime = export
	f.Start = start
	f.End = end
	f.TimeSource = src
	f.ClockClamped = clamped
	return f, st
}

func (p *parser) resolveTimes(v values) (start, end, export time.Time, src flow.TimeSource, clamped bool, st stampCounts) {
	export = time.Unix(int64(p.exportUnix), 0).UTC()
	startAbs, okS := v.startAbs.time(p.d.ReceivedAt)
	endAbs, okE := v.endAbs.time(p.d.ReceivedAt)
	boot, bootOK := lookupBoot(p.exporter, p.domain)
	if okS || okE {
		src = flow.TimeAbsolute
		var extra uint64
		var realS, realE bool
		if okS {
			start, realS = startAbs, true
		} else {
			start, extra, realS = p.sysOrExport(v.hasFirst, v.first, boot, bootOK, export)
			st.suspect += extra
		}
		if okE {
			end, realE = endAbs, true
		} else {
			end, extra, realE = p.sysOrExport(v.hasLast, v.last, boot, bootOK, export)
			st.suspect += extra
		}
		p.finishEnds(&start, &end, realS, realE, &st)
		return start, end, export, src, st.clamped == 1, st
	}
	if !bootOK {
		start, end = export, export
		src = flow.TimeExport
		st.fallback = 1
		p.finishEnds(&start, &end, false, false, &st)
		return start, end, export, src, st.clamped == 1, st
	}
	src = flow.TimeSysUpTime
	var realS, realE bool
	var extra uint64
	start, extra, realS = p.sysOrExport(v.hasFirst, v.first, boot, true, export)
	st.suspect += extra
	end, extra, realE = p.sysOrExport(v.hasLast, v.last, boot, true, export)
	st.suspect += extra
	p.finishEnds(&start, &end, realS, realE, &st)
	return start, end, export, src, st.clamped == 1, st
}

func (p *parser) finishEnds(start, end *time.Time, realS, realE bool, st *stampCounts) {
	if realS && realE && end.Before(*start) {
		*start, *end = *end, *start
		st.suspect++
	}
	var movedS, movedE bool
	*start, movedS = clampWindow(*start, p.d.ReceivedAt, p.maxAge, p.skew)
	*end, movedE = clampWindow(*end, p.d.ReceivedAt, p.maxAge, p.skew)
	if movedS || movedE {
		st.clamped = 1
	}
}

func (p *parser) sysOrExport(has bool, switched uint32, boot uint64, bootOK bool, export time.Time) (time.Time, uint64, bool) {
	if !has || !bootOK {
		return export, 0, false
	}
	t, suspect := sysUpAbs(boot, switched, export, p.maxAge)
	if suspect {
		return t, 1, true
	}
	return t, 0, true
}

// sysUpAbs picks n in -1..2 so init_ms + switched + n*2^32 is within maxAge
// of the export time. The closest candidate wins. None in range is suspect
// and the export time is used instead. A missing switched time is not passed here.
func sysUpAbs(initMs uint64, switched uint32, export time.Time, maxAge time.Duration) (time.Time, bool) {
	if initMs > uint64(math.MaxInt64) {
		return export, true
	}
	var best time.Time
	var bestDist time.Duration
	found := false
	for n := int64(-1); n <= 2; n++ {
		ms := int64(initMs) + int64(switched) + n*(1<<32)
		cand := time.UnixMilli(ms).UTC()
		d := absDur(cand.Sub(export))
		if d > maxAge {
			continue
		}
		if !found || d < bestDist {
			found = true
			best = cand
			bestDist = d
		}
	}
	if !found {
		return export, true
	}
	return best, false
}

func (p *parser) applyCachedRate(v values, in *sampling.Input) {
	if p.samples == nil {
		return
	}
	needN := !recordSuppliesN(v)
	needA := v.algo == nil
	if !needN && !needA {
		return
	}
	facts := p.samples.Facts(p.exporter, p.domain)
	for _, scope := range flowScopes(v, facts) {
		s, ok := facts[scope]
		if !ok || (s.N == 0 && s.Algorithm == 0) {
			continue
		}
		// N == 0 still carries an algorithm. Skipping the fact would drop it.
		if needN && s.N > 0 {
			in.Interval = ptrU64(uint64(s.N))
			needN = false
		}
		if needA && s.Algorithm != 0 {
			in.Algorithm = ptrU8(s.Algorithm)
			needA = false
		}
		if !needN && !needA {
			return
		}
	}
}

func recordSuppliesN(v values) bool {
	if v.interval != nil && *v.interval > 1 {
		return true
	}
	if v.random != nil && *v.random > 1 {
		return true
	}
	if v.selected != nil && v.selectedPkts != nil && *v.selected > 0 {
		return (*v.selected+*v.selectedPkts) / *v.selected > 1
	}
	return false
}

func flowScopes(v values, facts map[string]sampling.Sample) []string {
	var s []string
	if v.inputIf != nil {
		s = append(s, "if:"+strconv.FormatUint(uint64(*v.inputIf), 10))
	}
	if v.sampler != nil {
		s = append(s, "sampler:"+strconv.FormatUint(*v.sampler, 10))
	}
	for _, prefix := range []string{"linecard:", "cache:", "template:"} {
		if scope, ok := soleScope(facts, prefix); ok {
			s = append(s, scope)
		}
	}
	s = append(s, "device")
	return s
}

func soleScope(facts map[string]sampling.Sample, prefix string) (string, bool) {
	found := ""
	for scope := range facts {
		if len(scope) < len(prefix) || scope[:len(prefix)] != prefix {
			continue
		}
		if found != "" {
			return "", false
		}
		found = scope
	}
	if found == "" {
		return "", false
	}
	return found, true
}

// scopeName maps a v9 scope field type. IPFIX scope fields use the same key
// strings. These numbers are not IANA element IDs.
func scopeName(typ uint16, v uint64) (string, bool) {
	switch typ {
	case 1:
		return "device", true
	case 2:
		return "if:" + strconv.FormatUint(v, 10), true
	case 3:
		return "linecard:" + strconv.FormatUint(v, 10), true
	case 4:
		return "cache:" + strconv.FormatUint(v, 10), true
	case 5:
		return "template:" + strconv.FormatUint(v, 10), true
	default:
		return "", false
	}
}

func (p *parser) finishSequence() error {
	if p.seq == nil {
		return nil
	}
	key := sequence.Key{Exporter: p.exporter, Domain: p.domain, Version: 10}
	if p.retry {
		if st, id, ok := takeArmed(p.exporter); ok {
			if p.unsized {
				return nil
			}
			dropHoldID(id)
			return p.applyHeld(key, st)
		}
	}
	if p.unsized {
		if p.retry {
			return nil
		}
		dec, snap := p.seq.ObserveUnresolved(key, p.headerSeq)
		p.noteSeq(dec)
		if p.missing != nil {
			p.missing.SeqSnap = snap
			saveHold(p.exporter, p.domain, p.headerSeq, snap, p.prefix, len(p.d.Payload))
		}
		return nil
	}
	if p.retry {
		st, ok := takeHold(p.exporter, p.domain, p.headerSeq)
		if !ok {
			return nil
		}
		return p.applyHeld(key, st)
	}
	dec, err := p.seq.Observe(key, p.headerSeq, p.dataRecords)
	if err != nil {
		return err
	}
	p.noteSeq(dec)
	return nil
}

func (p *parser) applyHeld(key sequence.Key, st seqHold) error {
	count := p.dataRecords
	if len(p.d.Payload) < st.payloadLen {
		count += st.prefix
	}
	dec, applied := p.seq.ApplyIfUnchanged(key, st.snap, count)
	if applied {
		p.noteSeq(dec)
	}
	return nil
}

func (p *parser) noteSeq(dec sequence.Decision) {
	switch dec.Action {
	case sequence.ActionGap:
		p.delta.GapRecords += uint64(dec.Gap)
		p.countAlways(obs.SequenceGapIPFIXRecords, uint64(dec.Gap))
	case sequence.ActionReorder:
		p.countAlways(obs.SequenceReorder, 1)
	case sequence.ActionDuplicate:
		p.countAlways(obs.SequenceDuplicate, 1)
	case sequence.ActionReset:
		p.countAlways(obs.SequenceReset, 1)
	case sequence.ActionUnresolved:
		p.countAlways(obs.SequenceUnresolved, 1)
	}
}

func (p *parser) markUnsized() {
	if !p.seenUnsized {
		p.prefix = p.dataRecords
		p.seenUnsized = true
	}
	p.unsized = true
}

func (p *parser) markBad() {
	if p.bad {
		return
	}
	p.bad = true
	if p.retry {
		return
	}
	p.delta.Malformed = 1
	p.countAlways(obs.Malformed, 1)
}

func (p *parser) notePad(b []byte) {
	for _, c := range b {
		if c != 0 {
			p.countOnce(obs.PaddingNonzero, 1)
			return
		}
	}
}

func (p *parser) countOnce(name obs.Name, n uint64) {
	if p.retry {
		return
	}
	p.countAlways(name, n)
}

func (p *parser) countAlways(name obs.Name, n uint64) {
	if p.counters == nil || n == 0 {
		return
	}
	_ = p.counters.Add(name, n)
}

type values struct {
	src, dst                  netip.Addr
	hasSrc, hasDst            bool
	srcPort, dstPort          uint16
	ports                     bool
	proto                     uint8
	protoOK                   bool
	tcpFlags                  uint8
	tcpOK                     bool
	tos                       uint8
	tosOK                     bool
	dir                       *uint8
	inBytes, inPkts           *uint64
	outBytes, outPkts         *uint64
	totBytes, totPkts         *uint64
	initOct, respOct          *uint64
	inputIf, outputIf         *uint32
	nextHop                   *netip.Addr
	bgpSrc, bgpDst            *uint32
	srcMask, dstMask          *uint8
	first, last               uint32
	hasFirst, hasLast         bool
	startAbs, endAbs          absRaw
	interval, random, sampler *uint64
	selected, selectedPkts    *uint64
	algo35, algo49, algo304   *uint8
	algo                      *uint8
	hasSampling               bool
	initMs                    uint64
	hasInit                   bool
	scopeKeys                 []string
	scopeOK                   int
}

type absRaw struct {
	hasNano, hasMicro, hasMilli, hasSec bool
	nanoS, nanoF                        uint32
	microS, microF                      uint32
	milli                               uint64
	sec                                 uint32
}

func (a absRaw) time(received time.Time) (time.Time, bool) {
	switch {
	case a.hasNano:
		return ntpTime(a.nanoS, a.nanoF, false, received), true
	case a.hasMicro:
		return ntpTime(a.microS, a.microF, true, received), true
	case a.hasMilli:
		if a.milli > uint64(math.MaxInt64) {
			return time.Time{}, false
		}
		return time.UnixMilli(int64(a.milli)).UTC(), true
	case a.hasSec:
		return time.Unix(int64(a.sec), 0).UTC(), true
	default:
		return time.Time{}, false
	}
}

// ntpTime converts one NTP 64-bit timestamp. Microseconds clear the bottom
// 11 fraction bits; nanoseconds do not. Era 0 and the two adjacent eras are
// compared with received. A clock that is only days off stays in its era
// because the neighbors are 2^32 seconds away.
func ntpTime(secs, frac uint32, micros bool, received time.Time) time.Time {
	if micros {
		frac &^= 0x7FF
	}
	nsec := int64(uint64(frac) * 1_000_000_000 / (1 << 32))
	base := time.Unix(int64(secs)-ntpEpochOffset, nsec).UTC()
	best := base
	bestD := absDur(base.Sub(received))
	step := time.Duration(1<<32) * time.Second
	for _, c := range []time.Time{base.Add(step), base.Add(-step)} {
		d := absDur(c.Sub(received))
		if d < bestD {
			best = c
			bestD = d
		}
	}
	return best
}

func readValues(tpl template.Template, rec []byte) (values, int, bool) {
	var v values
	off := 0
	for i, f := range tpl.Fields {
		raw, next, ok := takeField(f, rec, off)
		if !ok {
			return v, off, false
		}
		off = next
		if f.Enterprise != 0 {
			continue
		}
		if i < tpl.ScopeN {
			if x, ok := readUint(raw); ok {
				if key, ok := scopeName(f.Type, x); ok {
					v.scopeKeys = append(v.scopeKeys, key)
					v.scopeOK++
				}
			}
			continue
		}
		applyField(&v, f.Type, raw)
	}
	switch {
	case v.algo35 != nil:
		v.algo = v.algo35
	case v.algo49 != nil:
		v.algo = v.algo49
	case v.algo304 != nil:
		v.algo = v.algo304
	}
	return v, off, true
}

func applyField(v *values, typ uint16, raw []byte) {
	switch typ {
	case decode.SourceIPv4Address:
		if a, ok := addr4(raw); ok {
			v.src, v.hasSrc = a, true
		}
	case decode.SourceIPv6Address:
		if a, ok := addr16(raw); ok {
			v.src, v.hasSrc = a, true
		}
	case decode.DestinationIPv4Address:
		if a, ok := addr4(raw); ok {
			v.dst, v.hasDst = a, true
		}
	case decode.DestinationIPv6Address:
		if a, ok := addr16(raw); ok {
			v.dst, v.hasDst = a, true
		}
	case decode.SourceTransportPort:
		if x, ok := u16fit(raw); ok {
			v.srcPort, v.ports = x, true
		}
	case decode.DestinationTransportPort:
		if x, ok := u16fit(raw); ok {
			v.dstPort, v.ports = x, true
		}
	case decode.ProtocolIdentifier:
		if x, ok := u8fit(raw); ok {
			v.proto, v.protoOK = x, true
		}
	case decode.IPClassOfService:
		if x, ok := u8fit(raw); ok {
			v.tos, v.tosOK = x, true
		}
	case decode.TCPControlBits:
		if x, ok := u8fit(raw); ok {
			v.tcpFlags, v.tcpOK = x, true
		}
	case decode.IngressInterface:
		if x, ok := u32fit(raw); ok {
			v.inputIf = ptrU32(x)
		}
	case decode.EgressInterface:
		if x, ok := u32fit(raw); ok {
			v.outputIf = ptrU32(x)
		}
	case decode.IPNextHopIPv4Address:
		if a, ok := addr4(raw); ok {
			v.nextHop = ptrAddr(a)
		}
	case decode.BGPSourceAsNumber:
		if x, ok := u32fit(raw); ok {
			v.bgpSrc = ptrU32(x)
		}
	case decode.BGPDestinationAsNumber:
		if x, ok := u32fit(raw); ok {
			v.bgpDst = ptrU32(x)
		}
	case decode.SourceIPv4PrefixLength:
		if x, ok := u8fit(raw); ok {
			v.srcMask = ptrU8(x)
		}
	case decode.DestinationIPv4PrefixLength:
		if x, ok := u8fit(raw); ok {
			v.dstMask = ptrU8(x)
		}
	case decode.FlowStartSysUpTime:
		if x, ok := u32fit(raw); ok {
			v.first, v.hasFirst = x, true
		}
	case decode.FlowEndSysUpTime:
		if x, ok := u32fit(raw); ok {
			v.last, v.hasLast = x, true
		}
	case decode.FlowStartNanoseconds:
		if s, f, ok := ntpRaw(raw); ok && !v.startAbs.hasNano {
			v.startAbs.hasNano = true
			v.startAbs.nanoS, v.startAbs.nanoF = s, f
		}
	case decode.FlowEndNanoseconds:
		if s, f, ok := ntpRaw(raw); ok && !v.endAbs.hasNano {
			v.endAbs.hasNano = true
			v.endAbs.nanoS, v.endAbs.nanoF = s, f
		}
	case decode.FlowStartMicroseconds:
		if s, f, ok := ntpRaw(raw); ok && !v.startAbs.hasMicro {
			v.startAbs.hasMicro = true
			v.startAbs.microS, v.startAbs.microF = s, f
		}
	case decode.FlowEndMicroseconds:
		if s, f, ok := ntpRaw(raw); ok && !v.endAbs.hasMicro {
			v.endAbs.hasMicro = true
			v.endAbs.microS, v.endAbs.microF = s, f
		}
	case decode.FlowStartMilliseconds:
		if x, ok := readUint(raw); ok && len(raw) == 8 && !v.startAbs.hasMilli {
			v.startAbs.hasMilli = true
			v.startAbs.milli = x
		}
	case decode.FlowEndMilliseconds:
		if x, ok := readUint(raw); ok && len(raw) == 8 && !v.endAbs.hasMilli {
			v.endAbs.hasMilli = true
			v.endAbs.milli = x
		}
	case decode.FlowStartSeconds:
		if x, ok := u32fit(raw); ok && !v.startAbs.hasSec {
			v.startAbs.hasSec = true
			v.startAbs.sec = x
		}
	case decode.FlowEndSeconds:
		if x, ok := u32fit(raw); ok && !v.endAbs.hasSec {
			v.endAbs.hasSec = true
			v.endAbs.sec = x
		}
	case decode.SystemInitTimeMilliseconds:
		if x, ok := readUint(raw); ok {
			v.initMs, v.hasInit = x, true
		}
	case decode.OctetDeltaCount:
		if x, ok := readUint(raw); ok {
			v.inBytes = ptrU64(x)
		}
	case decode.PacketDeltaCount:
		if x, ok := readUint(raw); ok {
			v.inPkts = ptrU64(x)
		}
	case decode.PostOctetDeltaCount:
		if x, ok := readUint(raw); ok {
			v.outBytes = ptrU64(x)
		}
	case decode.PostPacketDeltaCount:
		if x, ok := readUint(raw); ok {
			v.outPkts = ptrU64(x)
		}
	case decode.OctetTotalCount:
		if x, ok := readUint(raw); ok {
			v.totBytes = ptrU64(x)
		}
	case decode.PacketTotalCount:
		if x, ok := readUint(raw); ok {
			v.totPkts = ptrU64(x)
		}
	case decode.InitiatorOctets:
		if x, ok := readUint(raw); ok {
			v.initOct = ptrU64(x)
		}
	case decode.ResponderOctets:
		if x, ok := readUint(raw); ok {
			v.respOct = ptrU64(x)
		}
	case decode.SamplingInterval:
		if x, ok := readUint(raw); ok {
			v.interval = ptrU64(x)
			v.hasSampling = true
		}
	case decode.SamplerRandomInterval:
		if x, ok := readUint(raw); ok {
			v.random = ptrU64(x)
			v.hasSampling = true
		}
	case decode.SamplingPacketInterval:
		if x, ok := readUint(raw); ok {
			v.selected = ptrU64(x)
			v.hasSampling = true
		}
	case decode.SamplingPacketSpace:
		if x, ok := readUint(raw); ok {
			v.selectedPkts = ptrU64(x)
			v.hasSampling = true
		}
	case decode.SamplingAlgorithm:
		if x, ok := u8fit(raw); ok {
			v.algo35 = ptrU8(x)
			v.hasSampling = true
		}
	case decode.SamplerMode:
		if x, ok := u8fit(raw); ok {
			v.algo49 = ptrU8(x)
			v.hasSampling = true
		}
	case decode.SelectorAlgorithm:
		if x, ok := u8fit(raw); ok {
			v.algo304 = ptrU8(x)
			v.hasSampling = true
		}
	case decode.SamplerID:
		if x, ok := readUint(raw); ok {
			v.sampler = ptrU64(x)
			v.hasSampling = true
		}
	case decode.FlowDirection:
		if x, ok := u8fit(raw); ok {
			v.dir = ptrU8(x)
		}
	}
}

func takeField(f template.Field, rec []byte, off int) ([]byte, int, bool) {
	if f.Variable || f.Length == 65535 {
		if off >= len(rec) {
			return nil, off, false
		}
		if rec[off] < 255 {
			n := int(rec[off])
			end := off + 1 + n
			if end > len(rec) {
				return nil, off, false
			}
			return rec[off+1 : end], end, true
		}
		if off+3 > len(rec) {
			return nil, off, false
		}
		n := int(binary.BigEndian.Uint16(rec[off+1 : off+3]))
		end := off + 3 + n
		if end > len(rec) {
			return nil, off, false
		}
		return rec[off+3 : end], end, true
	}
	n := int(f.Length)
	if off+n > len(rec) {
		return nil, off, false
	}
	return rec[off : off+n], off + n, true
}

func parseSpecifiers(body []byte, n int) ([]template.Field, []byte, bool) {
	fields := make([]template.Field, 0, n)
	for i := 0; i < n; i++ {
		if len(body) < 4 {
			return nil, body, false
		}
		rawID := binary.BigEndian.Uint16(body[0:2])
		ln := binary.BigEndian.Uint16(body[2:4])
		body = body[4:]
		var ent uint32
		if rawID&0x8000 != 0 {
			if len(body) < 4 {
				return nil, body, false
			}
			ent = binary.BigEndian.Uint32(body[:4])
			body = body[4:]
		}
		fields = append(fields, template.Field{
			Type:       rawID & 0x7FFF,
			Length:     ln,
			Enterprise: ent,
			Variable:   ln == 65535,
		})
	}
	return fields, body, true
}

func usable(fields []template.Field) bool {
	if len(fields) == 0 {
		return false
	}
	n := 0
	for _, f := range fields {
		if f.Variable || f.Length == 65535 {
			return true
		}
		n += int(f.Length)
	}
	return n > 0
}

func fixedSize(fields []template.Field) (int, bool) {
	n := 0
	for _, f := range fields {
		if f.Variable || f.Length == 65535 {
			return 0, false
		}
		n += int(f.Length)
	}
	return n, true
}

func minRecord(fields []template.Field) int {
	n := 0
	for _, f := range fields {
		if f.Variable || f.Length == 65535 {
			n++
			continue
		}
		n += int(f.Length)
	}
	return n
}

func ntpRaw(b []byte) (secs, frac uint32, ok bool) {
	if len(b) != 8 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint32(b[:4]), binary.BigEndian.Uint32(b[4:]), true
}

// readUint accepts reduced-size widths of 1 through 8 octets.
func readUint(b []byte) (uint64, bool) {
	if len(b) == 0 || len(b) > 8 {
		return 0, false
	}
	var x uint64
	for _, c := range b {
		x = x<<8 | uint64(c)
	}
	return x, true
}

func u32fit(b []byte) (uint32, bool) {
	x, ok := readUint(b)
	if !ok || x > math.MaxUint32 {
		return 0, false
	}
	return uint32(x), true
}

func u16fit(b []byte) (uint16, bool) {
	x, ok := readUint(b)
	if !ok || x > math.MaxUint16 {
		return 0, false
	}
	return uint16(x), true
}

func u8fit(b []byte) (uint8, bool) {
	x, ok := readUint(b)
	if !ok || x > math.MaxUint8 {
		return 0, false
	}
	return uint8(x), true
}

func addr4(b []byte) (netip.Addr, bool) {
	if len(b) != 4 {
		return netip.Addr{}, false
	}
	var a [4]byte
	copy(a[:], b)
	return netip.AddrFrom4(a), true
}

func addr16(b []byte) (netip.Addr, bool) {
	if len(b) != 16 {
		return netip.Addr{}, false
	}
	var a [16]byte
	copy(a[:], b)
	return netip.AddrFrom16(a), true
}

func ptrU64(v uint64) *uint64          { return &v }
func ptrU32(v uint32) *uint32          { return &v }
func ptrU8(v uint8) *uint8             { return &v }
func ptrAddr(a netip.Addr) *netip.Addr { return &a }

func clampWindow(t, received time.Time, maxAge, skew time.Duration) (time.Time, bool) {
	lo := received.Add(-maxAge)
	hi := received.Add(skew)
	if t.Before(lo) {
		return lo, true
	}
	if t.After(hi) {
		return hi, true
	}
	return t, false
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

type bootKey struct {
	ip     netip.Addr
	domain uint32
}

type seqHoldKey struct {
	ip     netip.Addr
	domain uint32
	seq    uint32
}

type seqHold struct {
	snap       sequence.Snapshot
	prefix     uint32
	payloadLen int
}

// holdSnap is one hold entry's snapshot. The sequence number is not the key:
// two unresolved messages can carry the same sequence.
type holdSnap struct {
	seqHold
	ip     netip.Addr
	domain uint32
	seq    uint32
}

type armState struct {
	id uint64
	st seqHold
	on bool
}

var (
	stateMu   sync.Mutex
	bootTimes = map[bootKey]uint64{}
	seqHolds  = map[seqHoldKey]seqHold{}
	stash     = map[netip.Addr]holdSnap{}
	byID      = map[uint64]holdSnap{}
	armed     = map[netip.Addr]armState{}
)

func storeBoot(ip netip.Addr, domain uint32, ms uint64) {
	stateMu.Lock()
	defer stateMu.Unlock()
	bootTimes[bootKey{ip: ip.Unmap(), domain: domain}] = ms
}

func lookupBoot(ip netip.Addr, domain uint32) (uint64, bool) {
	stateMu.Lock()
	defer stateMu.Unlock()
	v, ok := bootTimes[bootKey{ip: ip.Unmap(), domain: domain}]
	return v, ok
}

func saveHold(ip netip.Addr, domain, seq uint32, snap sequence.Snapshot, prefix uint32, payloadLen int) {
	stateMu.Lock()
	defer stateMu.Unlock()
	ip = ip.Unmap()
	st := seqHold{snap: snap, prefix: prefix, payloadLen: payloadLen}
	// Direct Parse retries have no hold id and still find this slot.
	// Session.Bind removes it so the next message cannot replace it.
	seqHolds[seqHoldKey{ip: ip, domain: domain, seq: seq}] = st
	stash[ip] = holdSnap{seqHold: st, ip: ip, domain: domain, seq: seq}
}

func takeHold(ip netip.Addr, domain, seq uint32) (seqHold, bool) {
	stateMu.Lock()
	defer stateMu.Unlock()
	k := seqHoldKey{ip: ip.Unmap(), domain: domain, seq: seq}
	st, ok := seqHolds[k]
	if ok {
		delete(seqHolds, k)
	}
	return st, ok
}

func bindHold(ip netip.Addr, id uint64) {
	stateMu.Lock()
	defer stateMu.Unlock()
	ip = ip.Unmap()
	st, ok := stash[ip]
	if !ok {
		return
	}
	delete(stash, ip)
	byID[id] = st
	delete(seqHolds, seqHoldKey{ip: ip, domain: st.domain, seq: st.seq})
}

func dropHoldID(id uint64) {
	stateMu.Lock()
	defer stateMu.Unlock()
	delete(byID, id)
}

func retainHolds(ip netip.Addr, live []uint64) {
	stateMu.Lock()
	defer stateMu.Unlock()
	ip = ip.Unmap()
	keep := make(map[uint64]struct{}, len(live))
	for _, id := range live {
		keep[id] = struct{}{}
	}
	for id, st := range byID {
		if st.ip != ip {
			continue
		}
		if _, ok := keep[id]; !ok {
			delete(byID, id)
		}
	}
}

func armRetry(ip netip.Addr, id uint64, snap sequence.Snapshot) {
	stateMu.Lock()
	defer stateMu.Unlock()
	ip = ip.Unmap()
	st, ok := byID[id]
	if !ok {
		delete(armed, ip)
		return
	}
	// Pending.SeqSnap is this entry's snapshot, not the shared sequence slot.
	st.snap = snap
	armed[ip] = armState{id: id, st: st.seqHold, on: true}
}

func takeArmed(ip netip.Addr) (seqHold, uint64, bool) {
	stateMu.Lock()
	defer stateMu.Unlock()
	ip = ip.Unmap()
	a, ok := armed[ip]
	if !ok || !a.on {
		return seqHold{}, 0, false
	}
	delete(armed, ip)
	return a.st, a.id, true
}

func clearArm(ip netip.Addr) {
	stateMu.Lock()
	defer stateMu.Unlock()
	delete(armed, ip.Unmap())
}

func forgetExporter(ip netip.Addr) {
	ip = ip.Unmap()
	stateMu.Lock()
	defer stateMu.Unlock()
	for k := range bootTimes {
		if k.ip == ip {
			delete(bootTimes, k)
		}
	}
	for k := range seqHolds {
		if k.ip == ip {
			delete(seqHolds, k)
		}
	}
	delete(stash, ip)
	delete(armed, ip)
	for id, st := range byID {
		if st.ip == ip {
			delete(byID, id)
		}
	}
}

func resetState() {
	stateMu.Lock()
	defer stateMu.Unlock()
	bootTimes = map[bootKey]uint64{}
	seqHolds = map[seqHoldKey]seqHold{}
	stash = map[netip.Addr]holdSnap{}
	byID = map[uint64]holdSnap{}
	armed = map[netip.Addr]armState{}
}

func init() {
	decode.RegisterIPFIXParser(Parse)
	decode.RegisterExporterForget(forgetExporter)
	decode.RegisterIPFIXHold(decode.IPFIXHoldOps{
		Bind:   bindHold,
		Drop:   dropHoldID,
		Retain: retainHolds,
		Arm:    armRetry,
		Clear:  clearArm,
	})
}

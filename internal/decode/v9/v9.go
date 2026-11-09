// Package v9 decodes one NetFlow v9 datagram into canonical flows.
package v9

import (
	"encoding/binary"
	"log/slog"
	"math"
	"net/netip"
	"strconv"
	"time"

	"vibecollector/internal/decode"
	"vibecollector/internal/flow"
	"vibecollector/internal/ingest"
	"vibecollector/internal/obs"
	"vibecollector/internal/sampling"
	"vibecollector/internal/sequence"
	"vibecollector/internal/template"
)

const (
	headerLen = 20

	ieInBytes     = 1
	ieInPkts      = 2
	ieProto       = 4
	ieTOS         = 5
	ieTCPFlags    = 6
	ieL4Src       = 7
	ieV4Src       = 8
	ieSrcMask     = 9
	ieInput       = 10
	ieL4Dst       = 11
	ieV4Dst       = 12
	ieDstMask     = 13
	ieOutput      = 14
	ieV4Next      = 15
	ieSrcAS       = 16
	ieDstAS       = 17
	ieLast        = 21
	ieFirst       = 22
	ieOutBytes    = 23
	ieOutPkts     = 24
	ieV6Src       = 27
	ieV6Dst       = 28
	ieInterval    = 34
	ieAlgorithm   = 35
	ieSamplerID   = 48
	ieSamplerMode = 49
	ieRandom      = 50
	ieDirection   = 61
	ieTotalBytes  = 85
	ieTotalPkts   = 86
	ieInitiator   = 231
	ieResponder   = 232
)

// Parse decodes one NetFlow v9 datagram.
// templates, samples, and seq are called through their exported methods.
// retry true means Session is replaying a held datagram. missing_template
// and malformed are not incremented again for a set already counted on first
// sight, and the v9 cursor is not moved again.
// maxAge and skew are timestamp_max_age and timestamp_skew_slack. They are
// passed to ResolveSysUp. Zero is not replaced with a default.
// Framing walks each FlowSet Length until the payload is consumed. Count is
// the record total from RFC 3954 §5.1, not a FlowSet loop bound. A Count that
// disagrees with template records + options template records + data records +
// options data records increments count_disagrees and the packet is kept.
// A Length that extends past the payload, or a Length below 4, stops that
// set, increments malformed, and keeps records from earlier complete sets
// (decode.ErrShortSet). A short tail after a Length-consistent walk is ignored.
// Template FlowSet 0 and Options Template FlowSet 1 may contain several records.
// The options header is Template ID, Option Scope Length in bytes, Option Length
// in bytes. A scope length or option length not divisible by 4 is malformed
// and is not installed. Field count 0 is malformed. It is not a withdrawal.
// v9 has no withdrawal and does not call Cache.Withdraw.
// Padding is accepted, including a remainder of more than 3 bytes. Non-zero
// padding increments padding_nonzero. Reserved FlowSet IDs 2–255 are skipped
// by Length and increment reserved_set.
// Options data updates samples and does not emit a flow. A template with no
// IPv4 or IPv6 source and destination does not emit a flow. The v9 sequence
// unit is one packet when the 20-byte header parsed, including an options-only
// packet. Parse does not call Hold. A missing template is the missing return.
// A nil templates, samples, seq, or counters skips that side effect.
// Parse does not touch SQLite and does not return an error other than
// decode.ErrMalformed or decode.ErrShortSet.
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
	d         ingest.Datagram
	templates *template.Cache
	samples   *sampling.Cache
	seq       *sequence.Table
	counters  *obs.Counters
	retry     bool
	maxAge    time.Duration
	skew      time.Duration
	exporter  netip.Addr
	domain    uint32
	sysUp     uint32
	unixSecs  uint32
	headerCnt int
	delta     flow.ExporterDelta
	bad       bool
	flows     []flow.Flow
	missing   *template.Pending
	unsized   bool
	tmplN     int
	optTmplN  int
	dataN     int
	optDataN  int
}

type setRef struct {
	id   uint16
	off  int
	body []byte
}

func (p *parser) decode() ([]flow.Flow, flow.ExporterDelta, *template.Pending, error) {
	payload := p.d.Payload
	if len(payload) < headerLen || binary.BigEndian.Uint16(payload[:2]) != 9 {
		if len(payload) >= 2 && binary.BigEndian.Uint16(payload[:2]) == 9 {
			p.delta.Version = 9
		}
		p.markBad()
		p.delta.Flows = 0
		return nil, p.delta, nil, decode.ErrMalformed
	}
	p.delta.Version = 9
	p.headerCnt = int(binary.BigEndian.Uint16(payload[2:4]))
	p.sysUp = binary.BigEndian.Uint32(payload[4:8])
	p.unixSecs = binary.BigEndian.Uint32(payload[8:12])
	pkgSeq := binary.BigEndian.Uint32(payload[12:16])
	p.domain = binary.BigEndian.Uint32(payload[16:20])
	p.delta.Domain = p.domain
	if !p.retry && p.seq != nil {
		dec, err := p.seq.Observe(sequence.Key{Exporter: p.exporter, Domain: p.domain, Version: 9}, pkgSeq, 1)
		if err != nil {
			return nil, p.delta, nil, err
		}
		p.noteSeq(dec)
	}

	var dataSets []setRef
	off := headerLen
	short := false
	for off+4 <= len(payload) {
		id := binary.BigEndian.Uint16(payload[off : off+2])
		setLen := binary.BigEndian.Uint16(payload[off+2 : off+4])
		end := off + int(setLen)
		if setLen < 4 || end > len(payload) || end < off {
			p.markBad()
			short = true
			break
		}
		body := payload[off+4 : end]
		switch {
		case id == 0:
			p.tmplN += p.templateSet(body)
		case id == 1:
			p.optTmplN += p.optionsTemplateSet(body)
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
	if !short && !p.unsized {
		sum := p.tmplN + p.optTmplN + p.dataN + p.optDataN
		if sum != p.headerCnt {
			p.countOnce(obs.CountDisagrees, 1)
		}
	}
	p.delta.Flows = uint64(len(p.flows))
	if short {
		return p.flows, p.delta, p.missing, decode.ErrShortSet
	}
	return p.flows, p.delta, p.missing, nil
}

func (p *parser) templateSet(body []byte) int {
	n := 0
	for {
		if len(body) < 4 {
			p.notePad(body)
			return n
		}
		tid := binary.BigEndian.Uint16(body[0:2])
		fc := binary.BigEndian.Uint16(body[2:4])
		if fc == 0 {
			// v9 field count 0 is not a withdrawal.
			p.markBad()
			n++
			body = body[4:]
			continue
		}
		recLen := 4 + int(fc)*4
		if len(body) < recLen {
			p.markBad()
			n++
			return n
		}
		fields := specifiers(body[4:recLen])
		body = body[recLen:]
		n++
		if tid < 256 || valueSize(fields) == 0 {
			p.markBad()
			continue
		}
		p.install(tid, fields, 0)
	}
}

func (p *parser) optionsTemplateSet(body []byte) int {
	n := 0
	for {
		if len(body) < 6 {
			p.notePad(body)
			return n
		}
		tid := binary.BigEndian.Uint16(body[0:2])
		scopeLen := int(binary.BigEndian.Uint16(body[2:4]))
		optLen := int(binary.BigEndian.Uint16(body[4:6]))
		recLen := 6 + scopeLen + optLen
		if recLen < 6 || len(body) < recLen {
			p.markBad()
			return n
		}
		badLen := scopeLen%4 != 0 || optLen%4 != 0 || scopeLen+optLen == 0
		raw := body[6:recLen]
		body = body[recLen:]
		n++
		if badLen || tid < 256 {
			p.markBad()
			continue
		}
		fields := specifiers(raw)
		if valueSize(fields) == 0 {
			p.markBad()
			continue
		}
		p.install(tid, fields, scopeLen/4)
	}
}

func (p *parser) install(id uint16, fields []template.Field, scopeN int) {
	if p.templates == nil {
		return
	}
	changed, evicted, err := p.templates.Put(template.Key{
		Exporter: p.exporter,
		Domain:   p.domain,
		Version:  9,
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
		// Later records in this datagram must not see the evicted cache.
		if p.samples != nil {
			p.samples.DropExporter(p.exporter)
		}
		if p.seq != nil {
			p.seq.DropExporter(p.exporter)
		}
	}
}

func (p *parser) dataSet(s setRef) {
	var tpl template.Template
	ok := false
	if p.templates != nil {
		tpl, ok = p.templates.Get(template.Key{Exporter: p.exporter, Domain: p.domain, Version: 9, ID: s.id})
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
				Version:    9,
				ReceivedAt: p.d.ReceivedAt,
				RetryAt:    s.off,
			}
		}
		p.unsized = true
		return
	}
	size := valueSize(tpl.Fields)
	if size <= 0 {
		p.markBad()
		p.unsized = true
		return
	}
	nRec := len(s.body) / size
	p.notePad(s.body[nRec*size:])
	if tpl.ScopeN > 0 {
		p.optDataN += nRec
		for i := 0; i < nRec; i++ {
			p.optionsData(tpl, s.body[i*size:(i+1)*size])
			p.countOnce(obs.NonFlowRecords, 1)
		}
		return
	}
	p.dataN += nRec
	for i := 0; i < nRec; i++ {
		v, ok := readRecord(tpl.Fields, s.body[i*size:(i+1)*size])
		if !ok {
			p.markBad()
			continue
		}
		if !v.hasSrc || !v.hasDst {
			if v.hasSampling {
				p.storeFact(v)
			}
			p.countOnce(obs.NonFlowRecords, 1)
			continue
		}
		f, st := p.makeFlow(v)
		if p.missing != nil {
			continue
		}
		p.flows = append(p.flows, f)
		p.countAlways(obs.TimestampSkew, st.skew)
		p.countAlways(obs.TimestampSuspect, st.suspect)
		p.countAlways(obs.ClockClamped, st.clamped)
	}
}

func (p *parser) optionsData(tpl template.Template, rec []byte) {
	if p.samples == nil {
		return
	}
	var (
		keys     []string
		interval *uint64
		random   *uint64
		algo35   *uint8
		algo49   *uint8
		sampler  *uint64
		scopeOK  int
	)
	off := 0
	for i, f := range tpl.Fields {
		n := int(f.Length)
		if n < 0 || off+n > len(rec) {
			return
		}
		raw := rec[off : off+n]
		off += n
		if i < tpl.ScopeN {
			if x, ok := readUint(raw); ok {
				if key, ok := scopeName(f.Type, x); ok {
					keys = append(keys, key)
					scopeOK++
				}
			}
			continue
		}
		x, ok := readUint(raw)
		if !ok {
			continue
		}
		switch f.Type {
		case ieInterval:
			interval = ptrU64(x)
		case ieRandom:
			random = ptrU64(x)
		case ieAlgorithm:
			algo35 = ptrU8(uint8(x))
		case ieSamplerMode:
			algo49 = ptrU8(uint8(x))
		case ieSamplerID:
			sampler = ptrU64(x)
		}
	}
	var algo *uint8
	switch {
	case algo35 != nil:
		algo = algo35
	case algo49 != nil:
		algo = algo49
	}
	sample := factSample(interval, random, algo)
	if sampler != nil {
		keys = append(keys, "sampler:"+strconv.FormatUint(*sampler, 10))
	}
	if len(keys) == 0 {
		if tpl.ScopeN > 0 && scopeOK == 0 {
			return
		}
		keys = []string{"device"}
	}
	for _, k := range keys {
		p.samples.Put(sampling.SampleKey{Exporter: p.exporter, Domain: p.domain, Scope: k}, sample)
	}
}

func (p *parser) storeFact(v values) {
	if p.samples == nil {
		return
	}
	sample := factSample(v.interval, v.random, v.algo)
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

// factSample is the shared N rule for options data and address-less records.
func factSample(interval, random *uint64, algo *uint8) sampling.Sample {
	rated := sampling.Rate(sampling.Input{
		Interval:       interval,
		RandomInterval: random,
		Algorithm:      algo,
	})
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

type stampCounts struct {
	skew, suspect, clamped uint64
}

func (p *parser) makeFlow(v values) (flow.Flow, stampCounts) {
	in := sampling.Input{
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
		Algorithm:       v.algo,
	}
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
	f.Version = 9
	f.ReceivedAt = p.d.ReceivedAt
	// A missing switched field is the export time, not device millisecond 0.
	first, last := p.sysUp, p.sysUp
	if v.hasFirst {
		first = v.first
	}
	if v.hasLast {
		last = v.last
	}
	st := decode.ResolveSysUp(p.d.ReceivedAt, p.unixSecs, 0, p.sysUp, first, last, p.maxAge, p.skew)
	f.ExportTime = st.Export
	f.Start = st.Start
	f.End = st.End
	f.TimeSource = st.Source
	f.ClockClamped = st.ClockClamped
	return f, stampCounts{skew: st.Skew, suspect: st.Suspect, clamped: st.Clamped}
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
	interval, random, sampler *uint64
	algo                      *uint8
	hasSampling               bool
}

func readRecord(fields []template.Field, rec []byte) (values, bool) {
	var v values
	off := 0
	for _, f := range fields {
		n := int(f.Length)
		if n < 0 || off+n > len(rec) {
			return v, false
		}
		raw := rec[off : off+n]
		off += n
		switch f.Type {
		case ieV4Src:
			if a, ok := addr4(raw); ok {
				v.src, v.hasSrc = a, true
			}
		case ieV6Src:
			if a, ok := addr16(raw); ok {
				v.src, v.hasSrc = a, true
			}
		case ieV4Dst:
			if a, ok := addr4(raw); ok {
				v.dst, v.hasDst = a, true
			}
		case ieV6Dst:
			if a, ok := addr16(raw); ok {
				v.dst, v.hasDst = a, true
			}
		case ieL4Src:
			if x, ok := u16fit(raw); ok {
				v.srcPort, v.ports = x, true
			}
		case ieL4Dst:
			if x, ok := u16fit(raw); ok {
				v.dstPort, v.ports = x, true
			}
		case ieProto:
			if x, ok := u8fit(raw); ok {
				v.proto, v.protoOK = x, true
			}
		case ieTOS:
			if x, ok := u8fit(raw); ok {
				v.tos, v.tosOK = x, true
			}
		case ieTCPFlags:
			if x, ok := u8fit(raw); ok {
				v.tcpFlags, v.tcpOK = x, true
			}
		case ieInput:
			if x, ok := u32fit(raw); ok {
				v.inputIf = ptrU32(x)
			}
		case ieOutput:
			if x, ok := u32fit(raw); ok {
				v.outputIf = ptrU32(x)
			}
		case ieV4Next:
			if a, ok := addr4(raw); ok {
				v.nextHop = ptrAddr(a)
			}
		case ieSrcAS:
			if x, ok := u32fit(raw); ok {
				v.bgpSrc = ptrU32(x)
			}
		case ieDstAS:
			if x, ok := u32fit(raw); ok {
				v.bgpDst = ptrU32(x)
			}
		case ieSrcMask:
			if x, ok := u8fit(raw); ok {
				v.srcMask = ptrU8(x)
			}
		case ieDstMask:
			if x, ok := u8fit(raw); ok {
				v.dstMask = ptrU8(x)
			}
		case ieFirst:
			if x, ok := u32fit(raw); ok {
				v.first, v.hasFirst = x, true
			}
		case ieLast:
			if x, ok := u32fit(raw); ok {
				v.last, v.hasLast = x, true
			}
		case ieInBytes:
			if x, ok := readUint(raw); ok {
				v.inBytes = ptrU64(x)
			}
		case ieInPkts:
			if x, ok := readUint(raw); ok {
				v.inPkts = ptrU64(x)
			}
		case ieOutBytes:
			if x, ok := readUint(raw); ok {
				v.outBytes = ptrU64(x)
			}
		case ieOutPkts:
			if x, ok := readUint(raw); ok {
				v.outPkts = ptrU64(x)
			}
		case ieTotalBytes:
			if x, ok := readUint(raw); ok {
				v.totBytes = ptrU64(x)
			}
		case ieTotalPkts:
			if x, ok := readUint(raw); ok {
				v.totPkts = ptrU64(x)
			}
		case ieInitiator:
			if x, ok := readUint(raw); ok {
				v.initOct = ptrU64(x)
			}
		case ieResponder:
			if x, ok := readUint(raw); ok {
				v.respOct = ptrU64(x)
			}
		case ieInterval:
			if x, ok := readUint(raw); ok {
				v.interval = ptrU64(x)
				v.hasSampling = true
			}
		case ieRandom:
			if x, ok := readUint(raw); ok {
				v.random = ptrU64(x)
				v.hasSampling = true
			}
		case ieAlgorithm:
			if x, ok := u8fit(raw); ok {
				v.algo = ptrU8(x)
				v.hasSampling = true
			}
		case ieSamplerMode:
			if v.algo == nil {
				if x, ok := u8fit(raw); ok {
					v.algo = ptrU8(x)
					v.hasSampling = true
				}
			}
		case ieSamplerID:
			if x, ok := readUint(raw); ok {
				v.sampler = ptrU64(x)
				v.hasSampling = true
			}
		case ieDirection:
			if x, ok := u8fit(raw); ok {
				v.dir = ptrU8(x)
			}
		}
	}
	return v, true
}

func (p *parser) applyCachedRate(v values, in *sampling.Input) {
	if p.samples == nil {
		return
	}
	needN := !recordSuppliesN(v.interval, v.random)
	needA := v.algo == nil
	if !needN && !needA {
		return
	}
	facts := p.samples.Facts(p.exporter, p.domain)
	for _, scope := range flowScopes(v, facts) {
		s, ok := facts[scope]
		if !ok || s.N == 0 {
			continue
		}
		if needN {
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

func recordSuppliesN(interval, random *uint64) bool {
	if interval != nil && *interval > 1 {
		return true
	}
	return random != nil && *random > 1
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

func (p *parser) noteSeq(dec sequence.Decision) {
	switch dec.Action {
	case sequence.ActionGap:
		p.delta.GapPackets += uint64(dec.Gap)
		p.countAlways(obs.SequenceGapV9Packets, uint64(dec.Gap))
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

func specifiers(b []byte) []template.Field {
	n := len(b) / 4
	fields := make([]template.Field, 0, n)
	for i := 0; i+4 <= len(b); i += 4 {
		ln := binary.BigEndian.Uint16(b[i+2 : i+4])
		fields = append(fields, template.Field{
			Type:     binary.BigEndian.Uint16(b[i : i+2]),
			Length:   ln,
			Variable: ln == 65535,
		})
	}
	return fields
}

func valueSize(fields []template.Field) int {
	n := 0
	for _, f := range fields {
		n += int(f.Length)
	}
	return n
}

func readUint(b []byte) (uint64, bool) {
	switch len(b) {
	case 1:
		return uint64(b[0]), true
	case 2:
		return uint64(binary.BigEndian.Uint16(b)), true
	case 4:
		return uint64(binary.BigEndian.Uint32(b)), true
	case 8:
		return binary.BigEndian.Uint64(b), true
	default:
		return 0, false
	}
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

func init() {
	decode.RegisterV9Parser(Parse)
}

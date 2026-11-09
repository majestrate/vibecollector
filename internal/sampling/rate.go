// Package sampling selects the stored counters and the 1-of-N rate.
package sampling

import "math"

// Input is the counter fields a parser found. A nil pointer means the IE
// was absent. V5Packets and V5Octets are set by the v5 parser from dPkts
// and dOctets and are treated as deltas. Interval is the v5 low 14 bits or
// an IE 34. RandomInterval is IE 50. Selected and SelectedPackets are IE 305
// and IE 306. InitiatorOctets and ResponderOctets are IE 231 and IE 232.
// Algorithm is IE 35 or 49, or IE 304 when both are absent.
type Input struct {
	DeltaOctets     *uint64
	DeltaPackets    *uint64
	OutOctets       *uint64
	OutPackets      *uint64
	TotalOctets     *uint64
	TotalPackets    *uint64
	InitiatorOctets *uint64
	ResponderOctets *uint64
	Interval        *uint64
	RandomInterval  *uint64
	Selected        *uint64
	SelectedPackets *uint64
	Algorithm       *uint8
	V5Packets       *uint64
	V5Octets        *uint64
}

// Output is what the flow stores. Packets and Octets are the exported values.
// Rate never multiplies them by N. CounterSemantics is "delta" or "total".
// OctetSemantics is "ip" or "l4_payload". Sampled is true only when N > 1.
// SamplingInterval is nil when the flow is not sampled. OutPackets and
// OutOctets is the reverse counter beside a selected primary: OUT_BYTES beside
// IE 1, or IE 232 beside IE 231. It is nil when OUT_BYTES or IE 231 is itself
// the primary. IE 232 does not change OctetSemantics.
type Output struct {
	Packets           uint64
	Octets            uint64
	OutPackets        *uint64
	OutOctets         *uint64
	CounterSemantics  string
	OctetSemantics    string
	Sampled           bool
	SamplingInterval  *uint32
	SamplingAlgorithm *uint8
}

// Rate selects stored counters and N.
// Octets, in order: IE 1 if present, else OUT_BYTES (23) if present, else
// IE 85 as total, else IE 231 as l4_payload. v5 passes dOctets as the IE 1
// input. Packets follow IE 2, else OUT_PKTS (24), else IE 86. Delta IEs win
// even when IE 85 or 86 is also present. Totals are not differenced.
// octet_semantics is l4_payload only when IE 231 is the selected primary.
// IE 232 is out_octets only in that L4 case. Presence of 231 or 232 does not
// relabel a row whose primary is IE 1, OUT_BYTES, or IE 85.
// N is IE 34 when it is greater than 1, else IE 50 when it is greater than 1,
// else (305+306)/305 when both are present and 305 > 0. A bare 305 does not
// set N and does not set Sampled. Sampled is true only when N > 1.
// Stored counters are the exported values. Rate does not multiply by N and
// does not return an error.
func Rate(in Input) Output {
	var out Output
	octKind, pktKind := kindNone, kindNone

	if v, ok := deltaOctets(in); ok {
		octKind = kindDelta
		out.Octets = v
		out.OutOctets = cloneU64(in.OutOctets)
	} else if v, ok := ptrU64(in.OutOctets); ok {
		octKind = kindDelta
		out.Octets = v
	} else if v, ok := ptrU64(in.TotalOctets); ok {
		octKind = kindTotal
		out.Octets = v
	} else if v, ok := ptrU64(in.InitiatorOctets); ok {
		octKind = kindL4
		out.Octets = v
		out.OutOctets = cloneU64(in.ResponderOctets)
	}

	if v, ok := deltaPackets(in); ok {
		pktKind = kindDelta
		out.Packets = v
		out.OutPackets = cloneU64(in.OutPackets)
	} else if v, ok := ptrU64(in.OutPackets); ok {
		pktKind = kindDelta
		out.Packets = v
	} else if v, ok := ptrU64(in.TotalPackets); ok {
		pktKind = kindTotal
		out.Packets = v
	}

	if octKind == kindL4 {
		out.OctetSemantics = "l4_payload"
	} else {
		out.OctetSemantics = "ip"
	}
	deltaSelected := octKind == kindDelta || octKind == kindL4 || pktKind == kindDelta
	totalSelected := octKind == kindTotal || pktKind == kindTotal
	if deltaSelected || !totalSelected {
		out.CounterSemantics = "delta"
	} else {
		out.CounterSemantics = "total"
	}

	if n, ok := sampleN(in); ok && n > 1 {
		out.Sampled = true
		if n <= math.MaxUint32 {
			v := uint32(n)
			out.SamplingInterval = &v
		}
	}
	if in.Algorithm != nil {
		a := *in.Algorithm
		out.SamplingAlgorithm = &a
	}
	return out
}

type counterKind uint8

const (
	kindNone counterKind = iota
	kindDelta
	kindTotal
	kindL4
)

func deltaOctets(in Input) (uint64, bool) {
	if v, ok := ptrU64(in.DeltaOctets); ok {
		return v, true
	}
	return ptrU64(in.V5Octets)
}

func deltaPackets(in Input) (uint64, bool) {
	if v, ok := ptrU64(in.DeltaPackets); ok {
		return v, true
	}
	return ptrU64(in.V5Packets)
}

func sampleN(in Input) (uint64, bool) {
	if in.Interval != nil && *in.Interval > 1 {
		return *in.Interval, true
	}
	if in.RandomInterval != nil && *in.RandomInterval > 1 {
		return *in.RandomInterval, true
	}
	if in.Selected != nil && in.SelectedPackets != nil && *in.Selected > 0 {
		return (*in.Selected + *in.SelectedPackets) / *in.Selected, true
	}
	return 0, false
}

func ptrU64(p *uint64) (uint64, bool) {
	if p == nil {
		return 0, false
	}
	return *p, true
}

func cloneU64(p *uint64) *uint64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

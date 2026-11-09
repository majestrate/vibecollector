package sampling

import "testing"

func TestRateV5DeltaUnchanged(t *testing.T) {
	pkts, octs := uint64(333), uint64(9000)
	interval := uint64(100)
	mode := uint8(3)
	out := Rate(Input{
		DeltaPackets: &pkts,
		DeltaOctets:  &octs,
		V5Packets:    &pkts,
		V5Octets:     &octs,
		Interval:     &interval,
		Algorithm:    &mode,
	})
	if out.Packets != 333 || out.Octets != 9000 {
		t.Fatalf("multiplied or dropped %+v", out)
	}
	if !out.Sampled || out.SamplingInterval == nil || *out.SamplingInterval != 100 {
		t.Fatalf("N %+v", out)
	}
	if out.CounterSemantics != "delta" || out.OctetSemantics != "ip" {
		t.Fatalf("semantics %+v", out)
	}
	if out.SamplingAlgorithm == nil || *out.SamplingAlgorithm != 3 {
		t.Fatalf("algorithm %+v", out.SamplingAlgorithm)
	}
	if out.OutPackets != nil || out.OutOctets != nil {
		t.Fatal("v5 has no reverse counters")
	}
}

func TestRateV5NotSampledAtZeroOrOne(t *testing.T) {
	pkts := uint64(10)
	for _, n := range []uint64{0, 1} {
		mode := uint8(2)
		out := Rate(Input{DeltaPackets: &pkts, V5Packets: &pkts, Interval: &n, Algorithm: &mode})
		if out.Sampled || out.SamplingInterval != nil {
			t.Fatalf("N %d sampled %+v", n, out)
		}
		if out.Packets != 10 {
			t.Fatalf("packets %d", out.Packets)
		}
		if out.SamplingAlgorithm == nil || *out.SamplingAlgorithm != 2 {
			t.Fatal("mode must be stored raw, including when not sampled")
		}
	}
}

func TestRatePrefersDeltaOverV5AndTotal(t *testing.T) {
	delta, v5, total := uint64(10), uint64(99), uint64(70)
	out := Rate(Input{DeltaOctets: &delta, V5Octets: &v5, TotalOctets: &total})
	if out.Octets != 10 || out.CounterSemantics != "delta" || out.OctetSemantics != "ip" {
		t.Fatalf("%+v", out)
	}
	out = Rate(Input{V5Octets: &v5})
	if out.Octets != 99 || out.CounterSemantics != "delta" {
		t.Fatalf("v5 alone %+v", out)
	}
}

func TestRateOctetOrder(t *testing.T) {
	ie1, outB, total, init, resp := uint64(1), uint64(23), uint64(85), uint64(231), uint64(232)
	cases := []struct {
		name   string
		in     Input
		octets uint64
		out    *uint64
		sem    string
		ctr    string
	}{
		{"ie1", Input{DeltaOctets: &ie1, OutOctets: &outB, TotalOctets: &total, InitiatorOctets: &init, ResponderOctets: &resp}, 1, &outB, "ip", "delta"},
		{"out", Input{OutOctets: &outB, TotalOctets: &total, InitiatorOctets: &init, ResponderOctets: &resp}, 23, nil, "ip", "delta"},
		{"total", Input{TotalOctets: &total, InitiatorOctets: &init, ResponderOctets: &resp}, 85, nil, "ip", "total"},
		{"l4", Input{InitiatorOctets: &init, ResponderOctets: &resp}, 231, &resp, "l4_payload", "delta"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Rate(tc.in)
			if got.Octets != tc.octets || got.OctetSemantics != tc.sem || got.CounterSemantics != tc.ctr {
				t.Fatalf("%+v", got)
			}
			if !sameU64(got.OutOctets, tc.out) {
				t.Fatalf("out octets %+v", got.OutOctets)
			}
		})
	}
}

func TestRateDeltaWinsOverTotal(t *testing.T) {
	ie2, ie86, ie85 := uint64(2), uint64(86), uint64(85)
	out := Rate(Input{DeltaPackets: &ie2, TotalPackets: &ie86, TotalOctets: &ie85})
	if out.Packets != 2 || out.Octets != 85 || out.CounterSemantics != "delta" {
		t.Fatalf("%+v", out)
	}
	out = Rate(Input{TotalPackets: &ie86})
	if out.Packets != 86 || out.CounterSemantics != "total" || out.OctetSemantics != "ip" {
		t.Fatalf("total packets %+v", out)
	}
	outPkts := uint64(24)
	out = Rate(Input{OutPackets: &outPkts, TotalPackets: &ie86})
	if out.Packets != 24 || out.OutPackets != nil || out.CounterSemantics != "delta" {
		t.Fatalf("out pkts primary %+v", out)
	}
}

func TestRateN(t *testing.T) {
	ie34, ie50 := uint64(100), uint64(7)
	sel, space := uint64(1), uint64(99)
	out := Rate(Input{Interval: &ie34, RandomInterval: &ie50, Selected: &sel, SelectedPackets: &space})
	if !out.Sampled || *out.SamplingInterval != 100 {
		t.Fatalf("34 wins %+v", out)
	}
	one := uint64(1)
	out = Rate(Input{Interval: &one, RandomInterval: &ie50})
	if *out.SamplingInterval != 7 {
		t.Fatalf("50 when 34 is 1: %+v", out)
	}
	out = Rate(Input{RandomInterval: &one, Selected: &sel, SelectedPackets: &space})
	if !out.Sampled || *out.SamplingInterval != 100 {
		t.Fatalf("305/306 %+v", out)
	}
	bare := uint64(100)
	out = Rate(Input{Selected: &bare})
	if out.Sampled || out.SamplingInterval != nil {
		t.Fatalf("bare 305 %+v", out)
	}
	zero := uint64(0)
	out = Rate(Input{Selected: &zero, SelectedPackets: &space})
	if out.Sampled || out.SamplingInterval != nil {
		t.Fatalf("305 is 0 %+v", out)
	}
	five, oneSpace := uint64(5), uint64(0)
	out = Rate(Input{Selected: &five, SelectedPackets: &oneSpace})
	if out.Sampled || out.SamplingInterval != nil {
		t.Fatalf("N 1 %+v", out)
	}
}

func sameU64(a, b *uint64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

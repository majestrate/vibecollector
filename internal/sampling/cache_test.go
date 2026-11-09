package sampling

import (
	"net/netip"
	"testing"
)

func TestLookupOrderReplaceAndDrop(t *testing.T) {
	c := NewCache()
	ip := netip.MustParseAddr("192.0.2.1")
	c.Put(SampleKey{Exporter: ip, Domain: 7, Scope: "if:7"}, Sample{N: 100, Algorithm: 1, Sampled: true})
	c.Put(SampleKey{Exporter: ip, Domain: 7, Scope: "device"}, Sample{N: 5, Algorithm: 2, Sampled: true})
	c.Put(SampleKey{Exporter: ip, Domain: 7, Scope: "if:7"}, Sample{N: 50, Algorithm: 1, Sampled: true})
	got, ok := c.Lookup(ip, 7, []string{"sampler:1", "if:7", "device"})
	if !ok || got.N != 50 || got.Algorithm != 1 {
		t.Fatalf("%+v %v", got, ok)
	}
	got, ok = c.Lookup(ip, 7, []string{"linecard:1", "device"})
	if !ok || got.N != 5 {
		t.Fatalf("%+v %v", got, ok)
	}
	if _, ok := c.Lookup(ip, 7, []string{"cache:1"}); ok {
		t.Fatal("missing scope hit")
	}
	if _, ok := c.Lookup(ip, 8, []string{"device"}); ok {
		t.Fatal("other domain")
	}
	c.DropExporter(ip)
	if _, ok := c.Lookup(ip, 7, []string{"device", "if:7"}); ok {
		t.Fatal("drop")
	}
}

func TestSampleUnmap(t *testing.T) {
	c := NewCache()
	mapped := netip.MustParseAddr("::ffff:192.0.2.9")
	c.Put(SampleKey{Exporter: mapped, Domain: 1, Scope: "device"}, Sample{N: 0, Algorithm: 0, Sampled: false})
	got, ok := c.Lookup(netip.MustParseAddr("192.0.2.9"), 1, []string{"device"})
	if !ok || got.N != 0 || got.Sampled {
		t.Fatalf("%+v %v", got, ok)
	}
	c.DropExporter(netip.MustParseAddr("192.0.2.9"))
	if _, ok := c.Lookup(mapped, 1, []string{"device"}); ok {
		t.Fatal("drop missed mapped key")
	}
}

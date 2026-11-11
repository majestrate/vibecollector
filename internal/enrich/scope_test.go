package enrich

import (
	"net/netip"
	"testing"

	"github.com/majestrate/vibecollector/internal/flow"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		addr string
		want flow.Scope
	}{
		{"0.0.0.0", ScopeUnspecified},
		{"0.1.2.3", ScopeUnspecified},
		{"0.255.255.255", ScopeUnspecified},
		{"::", ScopeUnspecified},

		{"127.0.0.0", ScopeLoopback},
		{"127.0.0.1", ScopeLoopback},
		{"127.255.255.255", ScopeLoopback},
		{"::1", ScopeLoopback},

		{"169.254.0.0", ScopeLinkLocal},
		{"169.254.1.1", ScopeLinkLocal},
		{"169.254.255.255", ScopeLinkLocal},
		{"fe80::1", ScopeLinkLocal},
		{"febf::1", ScopeLinkLocal},

		{"224.0.0.0", ScopeMulticast},
		{"224.0.0.1", ScopeMulticast},
		{"239.255.255.255", ScopeMulticast},
		{"ff00::1", ScopeMulticast},
		{"ff02::1", ScopeMulticast},

		{"255.255.255.255", ScopeBroadcast},

		{"10.0.0.0", ScopePrivate},
		{"10.1.1.1", ScopePrivate},
		{"10.255.255.255", ScopePrivate},
		{"172.16.0.0", ScopePrivate},
		{"172.16.0.1", ScopePrivate},
		{"172.31.255.255", ScopePrivate},
		{"192.168.0.0", ScopePrivate},
		{"192.168.1.1", ScopePrivate},
		{"192.168.255.255", ScopePrivate},
		{"fc00::1", ScopePrivate},
		{"fd00::1", ScopePrivate},
		{"fd12:3456::1", ScopePrivate},
		{"fec0::1", ScopePrivate},
		{"feff::1", ScopePrivate},

		{"100.64.0.0", ScopeShared},
		{"100.64.0.1", ScopeShared},
		{"100.127.255.255", ScopeShared},

		{"192.0.2.0", ScopeDocumentation},
		{"192.0.2.1", ScopeDocumentation},
		{"198.51.100.1", ScopeDocumentation},
		{"203.0.113.1", ScopeDocumentation},
		{"2001:db8::1", ScopeDocumentation},

		{"198.18.0.0", ScopeBenchmark},
		{"198.18.0.1", ScopeBenchmark},
		{"198.19.255.255", ScopeBenchmark},
		{"2001:2::1", ScopeBenchmark},
		{"2001:2:0:ffff::1", ScopeBenchmark},

		{"192.0.0.0", ScopeReserved},
		{"192.0.0.1", ScopeReserved},
		{"192.0.0.255", ScopeReserved},
		{"240.0.0.0", ScopeReserved},
		{"240.0.0.1", ScopeReserved},
		{"255.255.255.254", ScopeReserved},
		{"100::1", ScopeReserved},
		{"100::ffff", ScopeReserved},
		{"2001:10::1", ScopeReserved},
		{"2001:1f::1", ScopeReserved},
		{"2001:20::1", ScopeReserved},
		{"2001:2f::1", ScopeReserved},
		{"64:ff9b:1::1", ScopeReserved},
		{"64:ff9b:1::8.8.8.8", ScopeReserved},

		{"1.0.0.0", ScopeGlobal},
		{"1.1.1.1", ScopeGlobal},
		{"8.8.8.8", ScopeGlobal},
		{"11.0.0.0", ScopeGlobal},
		{"100.63.255.255", ScopeGlobal},
		{"100.128.0.1", ScopeGlobal},
		{"126.255.255.255", ScopeGlobal},
		{"128.0.0.1", ScopeGlobal},
		{"169.253.0.1", ScopeGlobal},
		{"169.255.0.1", ScopeGlobal},
		{"172.15.255.255", ScopeGlobal},
		{"172.32.0.0", ScopeGlobal},
		{"192.0.1.0", ScopeGlobal},
		{"192.167.255.255", ScopeGlobal},
		{"192.169.0.1", ScopeGlobal},
		{"198.17.255.255", ScopeGlobal},
		{"198.20.0.1", ScopeGlobal},
		{"223.255.255.255", ScopeGlobal},
		{"::2", ScopeGlobal},
		{"2001:3::1", ScopeGlobal},
		{"2001:2:1::1", ScopeGlobal},
		{"2001:30::1", ScopeGlobal},
		{"2001:db9::1", ScopeGlobal},
		{"2001:4860:4860::8888", ScopeGlobal},
		{"2606:4700:4700::1111", ScopeGlobal},

		// IPv4-mapped addresses take the embedded IPv4 scope.
		{"::ffff:0.0.0.0", ScopeUnspecified},
		{"::ffff:10.1.1.1", ScopePrivate},
		{"::ffff:100.64.0.1", ScopeShared},
		{"::ffff:8.8.8.8", ScopeGlobal},
		{"::ffff:255.255.255.255", ScopeBroadcast},
		{"::ffff:127.0.0.1", ScopeLoopback},

		// 6to4 inherits the embedded IPv4 scope, including global.
		{"2002:a01:101::", ScopePrivate},
		{"2002:808:808::", ScopeGlobal},
		{"2002:ffff:ffff::", ScopeBroadcast},
		{"2002:c000:201::", ScopeDocumentation},
		{"2002:6440:1::", ScopeShared},
		{"2002:7f00:1::", ScopeLoopback},

		// NAT64 well-known prefix. RFC 1918 embedded stays private.
		{"64:ff9b::10.1.1.1", ScopePrivate},
		{"64:ff9b::a01:101", ScopePrivate},
		{"64:ff9b::8.8.8.8", ScopeGlobal},
		{"64:ff9b::808:808", ScopeGlobal},
		{"64:ff9b::ffff:ffff", ScopeBroadcast},
		{"64:ff9b::192.0.2.1", ScopeDocumentation},
	}
	for _, tc := range cases {
		addr := netip.MustParseAddr(tc.addr)
		if got := Classify(addr); got != tc.want {
			t.Errorf("Classify(%s) = %s, want %s", tc.addr, got, tc.want)
		}
	}

	// These are global-unicast to netip and still not looked up.
	for _, s := range []string{"10.1.1.1", "fd00::1", "100.64.0.1", "192.0.2.1", "2001:20::1", "fec0::1"} {
		addr := netip.MustParseAddr(s)
		if !addr.IsGlobalUnicast() {
			t.Errorf("%s: IsGlobalUnicast is false; the table test lost its precondition", s)
		}
	}
	rfc1918 := netip.MustParseAddr("10.1.1.1")
	if !rfc1918.IsPrivate() || Classify(rfc1918) != ScopePrivate {
		t.Fatalf("10.1.1.1 private classification failed")
	}
	cgnat := netip.MustParseAddr("100.64.0.1")
	if cgnat.IsPrivate() || Classify(cgnat) != ScopeShared {
		t.Fatalf("CGNAT must not use IsPrivate as the gate")
	}
	if Classify(netip.Addr{}) != ScopeUnspecified {
		t.Fatal("invalid addr")
	}
}

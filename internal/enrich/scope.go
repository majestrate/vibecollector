package enrich

import (
	"net/netip"

	"vibecollector/internal/flow"
)

const (
	ScopeUnspecified   flow.Scope = "unspecified"
	ScopeLoopback      flow.Scope = "loopback"
	ScopeLinkLocal     flow.Scope = "link_local"
	ScopeMulticast     flow.Scope = "multicast"
	ScopeBroadcast     flow.Scope = "broadcast"
	ScopePrivate       flow.Scope = "private"
	ScopeShared        flow.Scope = "shared"
	ScopeDocumentation flow.Scope = "documentation"
	ScopeBenchmark     flow.Scope = "benchmark"
	ScopeReserved      flow.Scope = "reserved"
	ScopeGlobal        flow.Scope = "global"
)

type prefixScope struct {
	prefix netip.Prefix
	scope  flow.Scope
}

// IsGlobalUnicast reports RFC 1918 and IPv6 ULA as global unicast, and
// IsPrivate stops at RFC 1918 plus fc00::/7. Neither is the gate.
var (
	prefix6to4  = netip.MustParsePrefix("2002::/16")
	prefixNAT64 = netip.MustParsePrefix("64:ff9b::/96")

	// 255.255.255.255/32 is inside 240.0.0.0/4, so broadcast is first.
	v4Rules = []prefixScope{
		{netip.MustParsePrefix("255.255.255.255/32"), ScopeBroadcast},
		{netip.MustParsePrefix("0.0.0.0/8"), ScopeUnspecified},
		{netip.MustParsePrefix("127.0.0.0/8"), ScopeLoopback},
		{netip.MustParsePrefix("169.254.0.0/16"), ScopeLinkLocal},
		{netip.MustParsePrefix("224.0.0.0/4"), ScopeMulticast},
		{netip.MustParsePrefix("10.0.0.0/8"), ScopePrivate},
		{netip.MustParsePrefix("172.16.0.0/12"), ScopePrivate},
		{netip.MustParsePrefix("192.168.0.0/16"), ScopePrivate},
		{netip.MustParsePrefix("100.64.0.0/10"), ScopeShared},
		{netip.MustParsePrefix("192.0.2.0/24"), ScopeDocumentation},
		{netip.MustParsePrefix("198.51.100.0/24"), ScopeDocumentation},
		{netip.MustParsePrefix("203.0.113.0/24"), ScopeDocumentation},
		{netip.MustParsePrefix("198.18.0.0/15"), ScopeBenchmark},
		{netip.MustParsePrefix("192.0.0.0/24"), ScopeReserved},
		{netip.MustParsePrefix("240.0.0.0/4"), ScopeReserved},
	}
	v6Rules = []prefixScope{
		{netip.MustParsePrefix("::/128"), ScopeUnspecified},
		{netip.MustParsePrefix("::1/128"), ScopeLoopback},
		{netip.MustParsePrefix("fe80::/10"), ScopeLinkLocal},
		{netip.MustParsePrefix("ff00::/8"), ScopeMulticast},
		{netip.MustParsePrefix("fc00::/7"), ScopePrivate},
		{netip.MustParsePrefix("fec0::/10"), ScopePrivate},
		{netip.MustParsePrefix("2001:db8::/32"), ScopeDocumentation},
		{netip.MustParsePrefix("2001:2::/48"), ScopeBenchmark},
		{netip.MustParsePrefix("100::/64"), ScopeReserved},
		{netip.MustParsePrefix("2001:10::/28"), ScopeReserved},
		{netip.MustParsePrefix("2001:20::/28"), ScopeReserved},
		{netip.MustParsePrefix("64:ff9b:1::/48"), ScopeReserved},
	}
)

// Classify returns the scope of addr. It unmaps IPv4-mapped IPv6 first.
// It does not use netip.Addr.IsGlobalUnicast. It does not return an error.
// 6to4 (2002::/16) and NAT64 (64:ff9b::/96) inherit the embedded IPv4 scope.
// When that IPv4 is global, the IPv6 address is global.
// 255.255.255.255/32 is broadcast. ORCHIDv2 2001:20::/28 is reserved.
// Only Scope "global" may be passed to Provider.Lookup.
// The prefix table in the design's Address classification section is the full list.
func Classify(addr netip.Addr) flow.Scope {
	if !addr.IsValid() {
		return ScopeUnspecified
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return classify4(addr)
	}
	if prefix6to4.Contains(addr) {
		return classify4(embeddedIPv4(addr, 2))
	}
	if prefixNAT64.Contains(addr) {
		return classify4(embeddedIPv4(addr, 12))
	}
	for i := range v6Rules {
		if v6Rules[i].prefix.Contains(addr) {
			return v6Rules[i].scope
		}
	}
	return ScopeGlobal
}

func classify4(addr netip.Addr) flow.Scope {
	for i := range v4Rules {
		if v4Rules[i].prefix.Contains(addr) {
			return v4Rules[i].scope
		}
	}
	return ScopeGlobal
}

func embeddedIPv4(addr netip.Addr, off int) netip.Addr {
	b := addr.As16()
	var v4 [4]byte
	copy(v4[:], b[off:off+4])
	return netip.AddrFrom4(v4)
}

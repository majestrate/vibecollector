package decode

import "encoding/binary"

// IP protocol numbers that carry an ICMP type and code instead of ports.
const (
	// ProtoICMP is IPv4 ICMP.
	ProtoICMP uint8 = 1
	// ProtoICMPv6 is ICMPv6, including neighbor discovery and MLD.
	ProtoICMPv6 uint8 = 58
)

// ICMPPorts collects type and code from one flow record.
// Note records element 32 or 176–179. Apply turns that into the destination
// port stored for ICMP and ICMPv6.
type ICMPPorts struct {
	// Set is true when an ICMP element of its IANA width was present.
	Set bool
	// TypeCode is (type<<8)|code when element 32 was present.
	// It stays 0 when only elements 176–179 were present.
	TypeCode uint16

	has32    bool
	t4, c4   uint8
	t6, c6   uint8
	ht4, hc4 bool
	ht6, hc6 bool
}

// Note records one information element.
// ie is the IANA element number. raw is the field value at the template length.
// Element 32 is two bytes, type then code, and replaces elements 176–179.
// Elements 176–179 are one byte each. Any other length is ignored.
// A later type or code element does not replace element 32.
// Note does not return an error.
func (p *ICMPPorts) Note(ie uint16, raw []byte) {
	switch ie {
	case ICMPTypeCodeIPv4:
		if len(raw) != 2 {
			return
		}
		p.has32 = true
		p.Set = true
		p.TypeCode = binary.BigEndian.Uint16(raw)
	case ICMPTypeIPv4:
		if len(raw) != 1 || p.has32 {
			return
		}
		p.ht4 = true
		p.t4 = raw[0]
		p.Set = true
	case ICMPCodeIPv4:
		if len(raw) != 1 || p.has32 {
			return
		}
		p.hc4 = true
		p.c4 = raw[0]
		p.Set = true
	case ICMPTypeIPv6:
		if len(raw) != 1 || p.has32 {
			return
		}
		p.ht6 = true
		p.t6 = raw[0]
		p.Set = true
	case ICMPCodeIPv6:
		if len(raw) != 1 || p.has32 {
			return
		}
		p.hc6 = true
		p.c6 = raw[0]
		p.Set = true
	}
}

// Apply returns the destination port to store for this protocol.
// proto is the IP protocol number. protoOK is false when the record had no
// protocol element; Apply then returns ok false.
// When proto is ProtoICMP or ProtoICMPv6 and an ICMP element was present,
// dst is (type<<8)|code and ok is true, including when that value is 0.
// Element 32 wins. A type or code element for the other IP version is used
// only when this protocol's pair is absent.
// For every other protocol, including 0, ok is false and dst is 0.
// The caller keeps the layer-4 destination port in that case.
// Apply does not change proto and does not return an error.
func (p ICMPPorts) Apply(proto uint8, protoOK bool) (dst uint16, ok bool) {
	if !p.Set || !protoOK || (proto != ProtoICMP && proto != ProtoICMPv6) {
		return 0, false
	}
	if p.has32 {
		return p.TypeCode, true
	}
	if proto == ProtoICMPv6 && (p.ht6 || p.hc6) {
		return uint16(p.t6)<<8 | uint16(p.c6), true
	}
	if proto == ProtoICMP && (p.ht4 || p.hc4) {
		return uint16(p.t4)<<8 | uint16(p.c4), true
	}
	if p.ht4 || p.hc4 {
		return uint16(p.t4)<<8 | uint16(p.c4), true
	}
	if p.ht6 || p.hc6 {
		return uint16(p.t6)<<8 | uint16(p.c6), true
	}
	return 0, false
}

package decode

import "testing"

func TestICMPTypeCodeWinsAndKeepsEchoReply(t *testing.T) {
	var p ICMPPorts
	p.Note(ICMPTypeIPv6, []byte{130})
	p.Note(ICMPCodeIPv6, []byte{0})
	p.Note(ICMPTypeCodeIPv4, []byte{0x03, 0x03})
	p.Note(ICMPTypeIPv4, []byte{8})
	dst, ok := p.Apply(ProtoICMP, true)
	if !ok || dst != 0x0303 {
		t.Fatalf("element 32 wins: %v %d", ok, dst)
	}
	dst, ok = p.Apply(ProtoICMPv6, true)
	if !ok || dst != 0x0303 {
		t.Fatalf("element 32 applies to ICMPv6: %v %d", ok, dst)
	}

	var echo ICMPPorts
	echo.Note(ICMPTypeCodeIPv4, []byte{0, 0})
	dst, ok = echo.Apply(ProtoICMP, true)
	if !ok || dst != 0 {
		t.Fatalf("echo reply is a present zero: %v %d", ok, dst)
	}
}

func TestICMPSeparateElementsFollowProtocol(t *testing.T) {
	var p ICMPPorts
	p.Note(ICMPTypeIPv4, []byte{8})
	p.Note(ICMPCodeIPv4, []byte{0})
	p.Note(ICMPTypeIPv6, []byte{130})
	p.Note(ICMPCodeIPv6, []byte{0})
	dst, ok := p.Apply(ProtoICMP, true)
	if !ok || dst != 0x0800 {
		t.Fatalf("v4 %v %d", ok, dst)
	}
	dst, ok = p.Apply(ProtoICMPv6, true)
	if !ok || dst != 0x8200 {
		t.Fatalf("v6 %v %d", ok, dst)
	}
	if _, ok = p.Apply(0, true); ok {
		t.Fatal("protocol 0 keeps its layer-4 port")
	}
	if _, ok = p.Apply(17, true); ok {
		t.Fatal("UDP keeps its destination port")
	}
	if _, ok = p.Apply(ProtoICMP, false); ok {
		t.Fatal("absent protocol")
	}
}

func TestICMPWrongWidthIsIgnored(t *testing.T) {
	var p ICMPPorts
	p.Note(ICMPTypeCodeIPv4, []byte{130})
	p.Note(ICMPTypeIPv6, []byte{130, 0})
	if p.Set {
		t.Fatal("widths other than the IANA width are ignored")
	}
}

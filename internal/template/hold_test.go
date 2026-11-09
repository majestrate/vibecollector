package template

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestHoldOrderCapsAndCopy(t *testing.T) {
	h, err := NewHold(2, 10)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("192.0.2.1")
	raw := []byte{1, 2, 3, 4}
	id1, dropped := h.Put(Pending{Exporter: ip, Payload: raw, RetryAt: 20, ReceivedAt: time.Unix(1, 0)})
	id2, d2 := h.Put(Pending{Exporter: ip, Payload: []byte{9}, RetryAt: 20})
	if dropped != 0 || d2 != 0 || id1 == 0 || id2 <= id1 {
		t.Fatalf("ids %d %d dropped %d %d", id1, id2, dropped, d2)
	}
	raw[0] = 0
	list := h.List(ip)
	if len(list) != 2 || list[0].ID != id1 || list[1].ID != id2 {
		t.Fatal(list)
	}
	if !bytes.Equal(list[0].Payload, []byte{1, 2, 3, 4}) {
		t.Fatal("payload was not copied")
	}
	h.Advance(ip, id1, 40)
	list = h.List(ip)
	if list[0].ID != id1 || list[0].RetryAt != 40 || list[1].ID != id2 {
		t.Fatal("advance reordered", list)
	}
	id3, dropped := h.Put(Pending{Exporter: ip, Payload: []byte{7}})
	if dropped != 1 {
		t.Fatal(dropped)
	}
	list = h.List(ip)
	if len(list) != 2 || list[0].ID != id2 || list[1].ID != id3 {
		t.Fatal("oldest was not dropped", list)
	}
	h.Remove(ip, id2)
	list = h.List(ip)
	if len(list) != 1 || list[0].ID != id3 {
		t.Fatal(list)
	}
	h.Remove(ip, 999)
	h.DropExporter(ip)
	if h.List(ip) != nil {
		t.Fatal("drop left entries")
	}
}

func TestGlobalOverflowDropsOldest(t *testing.T) {
	h, err := NewHold(5, 1)
	if err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	idA, _ := h.Put(Pending{Exporter: a, Payload: []byte{1}})
	idB, dropped := h.Put(Pending{Exporter: b, Payload: []byte{2}})
	if dropped != 1 || idB == idA {
		t.Fatal(dropped, idA, idB)
	}
	if h.List(a) != nil {
		t.Fatal("global overflow kept the other exporter")
	}
	list := h.List(b)
	if len(list) != 1 || !bytes.Equal(list[0].Payload, []byte{2}) {
		t.Fatal(list)
	}
}

func TestHoldUnmapAndBadCap(t *testing.T) {
	if _, err := NewHold(0, 1); !errors.Is(err, ErrBadCap) {
		t.Fatal(err)
	}
	if _, err := NewHold(1, 0); !errors.Is(err, ErrBadCap) {
		t.Fatal(err)
	}
	h, err := NewHold(4, 4)
	if err != nil {
		t.Fatal(err)
	}
	mapped := netip.MustParseAddr("::ffff:192.0.2.5")
	h.Put(Pending{Exporter: mapped, Payload: []byte{1}})
	if len(h.List(netip.MustParseAddr("192.0.2.5"))) != 1 {
		t.Fatal("unmap")
	}
	h.DropExporter(mapped)
	if h.List(netip.MustParseAddr("192.0.2.5")) != nil {
		t.Fatal("drop unmap")
	}
}

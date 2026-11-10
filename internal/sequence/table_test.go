package sequence

import (
	"errors"
	"math"
	"net/netip"
	"sync"
	"testing"
)

func key(version uint16) Key {
	return Key{Exporter: netip.MustParseAddr("192.0.2.5"), Domain: 258, Version: version}
}

func mustAction(t *testing.T, tab *Table, k Key, seq, count uint32, action Action, gap uint32) {
	t.Helper()
	d, err := tab.Observe(k, seq, count)
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != action || d.Gap != gap {
		t.Fatalf("seq %d count %d: got action %d gap %d, want action %d gap %d", seq, count, d.Action, d.Gap, action, gap)
	}
}

func TestReorderDoesNotMoveExpected(t *testing.T) {
	tab := NewTable()
	k := key(5)
	// count on the one-behind packet is not 1, so advancing expected would
	// miss the original next sequence.
	mustAction(t, tab, k, 1000, 2, ActionInit, 0)
	mustAction(t, tab, k, 1001, 4, ActionReorder, 0)
	mustAction(t, tab, k, 1002, 1, ActionInOrder, 0)
	mustAction(t, tab, k, 1002, 3, ActionDuplicate, 0)
	mustAction(t, tab, k, 1003, 1, ActionInOrder, 0)
}

func TestOneBehindNearWrapIsReorder(t *testing.T) {
	tab := NewTable()
	k := key(5)
	mustAction(t, tab, k, math.MaxUint32-1, 2, ActionInit, 0) // expected wraps to 0
	mustAction(t, tab, k, math.MaxUint32, 1, ActionReorder, 0)
	mustAction(t, tab, k, 0, 1, ActionInOrder, 0)
}

func TestReorderWindowAndReset(t *testing.T) {
	tab := NewTable()
	k := key(5)
	mustAction(t, tab, k, 10_000, 1, ActionInit, 0) // expected 10001
	mustAction(t, tab, k, 10_001-1024, 1, ActionReorder, 0)
	mustAction(t, tab, k, 10_001, 1, ActionInOrder, 0) // expected stayed, now 10002

	tab = NewTable()
	mustAction(t, tab, k, 10_000, 1, ActionInit, 0)
	mustAction(t, tab, k, 10_001-1025, 1, ActionReset, 0)
	mustAction(t, tab, k, 10_001-1025+1, 1, ActionInOrder, 0)
}

func TestGapAndHalfRange(t *testing.T) {
	tab := NewTable()
	k := key(9)
	mustAction(t, tab, k, 100, 1, ActionInit, 0)
	mustAction(t, tab, k, 110, 1, ActionGap, 9) // expected was 101

	tab = NewTable()
	k.Version = 10
	mustAction(t, tab, k, 0, 1, ActionInit, 0) // expected 1
	// Forward distance 2^31 is a gap. Reset is only behind < 2^31.
	seq := uint32(1 + (1 << 31))
	mustAction(t, tab, k, seq, 1, ActionGap, 1<<31)
}

func TestDuplicateKeepsLastCount(t *testing.T) {
	tab := NewTable()
	k := key(5)
	mustAction(t, tab, k, 10, 4, ActionInit, 0)
	mustAction(t, tab, k, 10, 9, ActionDuplicate, 0)
	c := tab.cur[canon(k)]
	if c.lastCount != 4 || c.lastSeq != 10 || c.expected != 14 {
		t.Fatalf("cursor %+v", c)
	}
}

func TestCountZeroReusesSequence(t *testing.T) {
	tab := NewTable()
	k := key(10)
	mustAction(t, tab, k, 5, 0, ActionInit, 0)
	mustAction(t, tab, k, 5, 1, ActionInOrder, 0)
	mustAction(t, tab, k, 5, 1, ActionDuplicate, 0)
}

func TestBadVersion(t *testing.T) {
	tab := NewTable()
	for _, v := range []uint16{0, 4, 8, 11} {
		d, err := tab.Observe(key(v), 1, 1)
		if !errors.Is(err, ErrBadVersion) {
			t.Fatalf("version %d err %v", v, err)
		}
		if d != (Decision{}) {
			t.Fatalf("version %d decision %+v", v, d)
		}
	}
	mustAction(t, tab, key(5), 1, 1, ActionInit, 0)
	mustAction(t, tab, key(9), 1, 1, ActionInit, 0)
	mustAction(t, tab, key(10), 1, 1, ActionInit, 0)
}

func TestVersionsDoNotShareCursor(t *testing.T) {
	tab := NewTable()
	mustAction(t, tab, key(5), 1, 1, ActionInit, 0)
	mustAction(t, tab, key(9), 50, 1, ActionInit, 0)
	mustAction(t, tab, key(5), 2, 1, ActionInOrder, 0)
}

func TestMappedAddressSharesCursor(t *testing.T) {
	tab := NewTable()
	mapped := key(5)
	mapped.Exporter = netip.MustParseAddr("::ffff:192.0.2.5")
	plain := key(5)
	mustAction(t, tab, mapped, 1, 1, ActionInit, 0)
	mustAction(t, tab, plain, 5, 1, ActionGap, 3)
}

func TestDropExporter(t *testing.T) {
	tab := NewTable()
	a := key(5)
	b := key(5)
	b.Exporter = netip.MustParseAddr("192.0.2.9")
	b.Domain = 1
	mustAction(t, tab, a, 1, 1, ActionInit, 0)
	mustAction(t, tab, b, 1, 1, ActionInit, 0)
	tab.DropExporter(netip.MustParseAddr("::ffff:192.0.2.5"))
	mustAction(t, tab, a, 2, 1, ActionInit, 0)
	mustAction(t, tab, b, 2, 1, ActionInOrder, 0)
}

func TestApplyIfUnchanged(t *testing.T) {
	tab := NewTable()
	k := key(10)

	_, snap := tab.ObserveUnresolved(k, 5)
	d, applied := tab.ApplyIfUnchanged(k, snap, 2)
	if !applied || d.Action != ActionInit || d.Gap != 0 {
		t.Fatalf("fresh apply %+v %v", d, applied)
	}
	mustAction(t, tab, k, 7, 1, ActionInOrder, 0)

	tab = NewTable()
	mustAction(t, tab, k, 1, 1, ActionInit, 0) // expected 2
	_, snap = tab.ObserveUnresolved(k, 10)
	mustAction(t, tab, k, 2, 1, ActionInOrder, 0) // expected 3, snapshot is stale
	d, applied = tab.ApplyIfUnchanged(k, snap, 1)
	if applied || d != (Decision{}) {
		t.Fatalf("stale %+v %v", d, applied)
	}
	mustAction(t, tab, k, 3, 1, ActionInOrder, 0)

	tab = NewTable()
	_, snap = tab.ObserveUnresolved(k, 4)
	mustAction(t, tab, k, 1, 1, ActionInit, 0)
	d, applied = tab.ApplyIfUnchanged(k, snap, 1)
	if applied || d != (Decision{}) {
		t.Fatalf("cursor appeared %+v %v", d, applied)
	}

	tab = NewTable()
	mustAction(t, tab, k, 1, 1, ActionInit, 0)
	_, snap = tab.ObserveUnresolved(k, 10)
	d, applied = tab.ApplyIfUnchanged(k, snap, 4)
	if !applied || d.Action != ActionGap || d.Gap != 8 {
		t.Fatalf("apply gap %+v %v", d, applied)
	}
	d, applied = tab.ApplyIfUnchanged(k, snap, 4)
	if applied || d != (Decision{}) {
		t.Fatalf("second apply %+v %v", d, applied)
	}
}

func TestObserveUnresolvedDoesNotMove(t *testing.T) {
	tab := NewTable()
	k := key(9)
	d, snap := tab.ObserveUnresolved(k, 42)
	if d.Action != ActionUnresolved || snap.HadCursor || snap.Seq != 42 {
		t.Fatalf("%+v %+v", d, snap)
	}
	mustAction(t, tab, k, 7, 1, ActionInit, 0)
	d, snap = tab.ObserveUnresolved(k, 99)
	if d.Action != ActionUnresolved || !snap.HadCursor || snap.Expected != 8 || snap.Seq != 99 {
		t.Fatalf("%+v %+v", d, snap)
	}
	mustAction(t, tab, k, 8, 1, ActionInOrder, 0)
}

func TestConcurrentKeys(t *testing.T) {
	tab := NewTable()
	errc := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k := key(5)
			k.Domain = uint32(i)
			for n := uint32(0); n < 50; n++ {
				d, err := tab.Observe(k, n, 1)
				if err != nil {
					errc <- err
					return
				}
				if n == 0 && d.Action != ActionInit {
					errc <- errors.New("first packet was not init")
					return
				}
				if n > 0 && d.Action != ActionInOrder {
					errc <- errors.New("later packet was not in order")
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Error(err)
	}
}

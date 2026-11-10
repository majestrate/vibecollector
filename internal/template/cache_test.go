package template

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestNewCacheCap(t *testing.T) {
	if _, err := NewCache(0); !errors.Is(err, ErrBadCap) {
		t.Fatal(err)
	}
	if _, err := NewCache(-1); !errors.Is(err, ErrBadCap) {
		t.Fatal(err)
	}
}

func TestPutRejectsBadKey(t *testing.T) {
	c, err := NewCache(4)
	if err != nil {
		t.Fatal(err)
	}
	fields := []Field{{Type: 8, Length: 4}}
	if _, _, err := c.Put(Key{Version: 8, ID: 256}, Template{Fields: fields}); !errors.Is(err, ErrBadKey) {
		t.Fatal(err)
	}
	if _, _, err := c.Put(Key{Version: 9, ID: 255}, Template{Fields: fields}); !errors.Is(err, ErrBadKey) {
		t.Fatal(err)
	}
	if _, ok := c.Get(Key{Version: 9, ID: 255}); ok {
		t.Fatal("rejected key was stored")
	}
	changed, evicted, err := c.Put(Key{Version: 10, ID: 2}, Template{Fields: fields})
	if err != nil || changed || evicted.IsValid() {
		t.Fatalf("v10 low id changed %v evicted %v err %v", changed, evicted, err)
	}
}

func TestRedefineAndCopy(t *testing.T) {
	c, err := NewCache(4)
	if err != nil {
		t.Fatal(err)
	}
	key := Key{Exporter: netip.MustParseAddr("192.0.2.1"), Domain: 1, Version: 9, ID: 256}
	a := []Field{{Type: 8, Length: 4}, {Type: 12, Length: 4}}
	changed, evicted, err := c.Put(key, Template{Fields: a})
	if err != nil || changed || evicted.IsValid() {
		t.Fatal(changed, evicted, err)
	}
	changed, _, err = c.Put(key, Template{Fields: append([]Field(nil), a...)})
	if err != nil || changed {
		t.Fatal("identical retransmission", changed, err)
	}
	changed, _, err = c.Put(key, Template{Fields: []Field{{Type: 8, Length: 4}}})
	if err != nil || !changed {
		t.Fatal("redefine", changed, err)
	}
	got, ok := c.Get(key)
	if !ok || len(got.Fields) != 1 {
		t.Fatal(got, ok)
	}
	got.Fields[0].Type = 99
	again, _ := c.Get(key)
	if again.Fields[0].Type != 8 {
		t.Fatal("Get returned a shared slice")
	}
}

func TestEvictOldestExporter(t *testing.T) {
	c, err := NewCache(1)
	if err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	t0 := time.Unix(1_700_000_000, 0).UTC()
	c.Touch(a, t0)
	c.Touch(b, t0.Add(time.Minute))
	fields := []Field{{Type: 8, Length: 4}}
	if _, ev, err := c.Put(Key{Exporter: a, Version: 9, ID: 256}, Template{Fields: fields}); err != nil || ev.IsValid() {
		t.Fatal(ev, err)
	}
	changed, ev, err := c.Put(Key{Exporter: b, Version: 9, ID: 256}, Template{Fields: fields})
	if err != nil || changed || ev != a {
		t.Fatalf("changed %v evicted %v err %v", changed, ev, err)
	}
	if _, ok := c.Get(Key{Exporter: a, Version: 9, ID: 256}); ok {
		t.Fatal("victim template remains")
	}
	if _, ok := c.Get(Key{Exporter: b, Version: 9, ID: 256}); !ok {
		t.Fatal("insert missing")
	}
	got := c.TakeEvictions(b)
	if len(got) != 1 || got[0] != a {
		t.Fatal(got)
	}
	if c.TakeEvictions(b) != nil {
		t.Fatal("evictions not cleared")
	}
	// Touch was cleared so the victim is not also idle.
	if ips := c.IdleExporters(t0.Add(time.Hour), time.Minute); len(ips) != 1 || ips[0] != b {
		t.Fatal(ips)
	}
}

func TestReplaceDoesNotGrow(t *testing.T) {
	c, _ := NewCache(1)
	key := Key{Version: 9, ID: 256, Exporter: netip.MustParseAddr("192.0.2.1")}
	if _, ev, err := c.Put(key, Template{Fields: []Field{{Type: 1, Length: 4}}}); err != nil || ev.IsValid() {
		t.Fatal(err, ev)
	}
	if _, ev, err := c.Put(key, Template{Fields: []Field{{Type: 2, Length: 4}}}); err != nil || ev.IsValid() {
		t.Fatal("replace evicted", ev, err)
	}
}

func TestSelfEvictKeepsNewTemplate(t *testing.T) {
	c, _ := NewCache(1)
	ip := netip.MustParseAddr("192.0.2.9")
	c.Touch(ip, time.Unix(10, 0))
	fields := []Field{{Type: 8, Length: 4}}
	c.Put(Key{Exporter: ip, Version: 9, ID: 256}, Template{Fields: fields})
	_, ev, err := c.Put(Key{Exporter: ip, Version: 9, ID: 257}, Template{Fields: fields})
	if err != nil || ev != ip {
		t.Fatal(ev, err)
	}
	if _, ok := c.Get(Key{Exporter: ip, Version: 9, ID: 256}); ok {
		t.Fatal("old template survived cap")
	}
	if _, ok := c.Get(Key{Exporter: ip, Version: 9, ID: 257}); !ok {
		t.Fatal("new template missing")
	}
}

func TestSelfEvictRestoresTouch(t *testing.T) {
	c, err := NewCache(1)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("192.0.2.9")
	recv := time.Unix(50, 0).UTC()
	fields := []Field{{Type: 8, Length: 4}}
	c.Touch(ip, time.Unix(10, 0))
	if _, _, err := c.Put(Key{Exporter: ip, Version: 9, ID: 256}, Template{Fields: fields, Received: time.Unix(10, 0)}); err != nil {
		t.Fatal(err)
	}
	_, ev, err := c.Put(Key{Exporter: ip, Version: 9, ID: 257}, Template{Fields: fields, Received: recv})
	if err != nil || ev != ip {
		t.Fatal(ev, err)
	}
	if ips := c.IdleExporters(recv.Add(time.Nanosecond), time.Nanosecond); len(ips) != 0 {
		t.Fatal("restored touch is already idle", ips)
	}
	ips := c.IdleExporters(recv.Add(time.Minute+time.Nanosecond), time.Minute)
	if len(ips) != 1 || ips[0] != ip {
		t.Fatal(ips)
	}
}

func TestWithdrawVersion10Only(t *testing.T) {
	c, _ := NewCache(8)
	ip := netip.MustParseAddr("192.0.2.4")
	data := Template{Fields: []Field{{Type: 8, Length: 4}}, ScopeN: 0}
	opt := Template{Fields: []Field{{Type: 1, Length: 4}, {Type: 34, Length: 4}}, ScopeN: 1}
	c.Put(Key{Exporter: ip, Domain: 3, Version: 9, ID: 256}, data)
	c.Put(Key{Exporter: ip, Domain: 3, Version: 10, ID: 256}, data)
	c.Put(Key{Exporter: ip, Domain: 3, Version: 10, ID: 257}, opt)
	n, unknown := c.Withdraw(ip, 3, 256, true, false)
	if n != 1 || unknown {
		t.Fatal(n, unknown)
	}
	if _, ok := c.Get(Key{Exporter: ip, Domain: 3, Version: 9, ID: 256}); !ok {
		t.Fatal("v9 removed")
	}
	if _, ok := c.Get(Key{Exporter: ip, Domain: 3, Version: 10, ID: 257}); !ok {
		t.Fatal("options removed by allData")
	}
	n, unknown = c.Withdraw(ip, 3, 257, false, true)
	if n != 1 || unknown {
		t.Fatal(n, unknown)
	}
	n, unknown = c.Withdraw(ip, 3, 999, false, false)
	if n != 0 || !unknown {
		t.Fatal(n, unknown)
	}
	c.Put(Key{Exporter: ip, Domain: 3, Version: 10, ID: 400}, data)
	n, unknown = c.Withdraw(ip, 3, 400, false, false)
	if n != 1 || unknown {
		t.Fatal(n, unknown)
	}
}

func TestIdleBeforeIsStrict(t *testing.T) {
	c, _ := NewCache(4)
	ip := netip.MustParseAddr("2001:db8::1")
	t0 := time.Unix(1_700_000_000, 0).UTC()
	c.Touch(ip, t0)
	if len(c.IdleExporters(t0.Add(30*time.Minute), 30*time.Minute)) != 0 {
		t.Fatal("equal touch is idle")
	}
	got := c.IdleExporters(t0.Add(30*time.Minute+time.Nanosecond), 30*time.Minute)
	if len(got) != 1 || got[0] != ip {
		t.Fatal(got)
	}
	c.DropExporter(ip)
	if len(c.IdleExporters(t0.Add(time.Hour), time.Second)) != 0 {
		t.Fatal("dropped ip still idle")
	}
}

func TestUnmapTemplateKey(t *testing.T) {
	c, _ := NewCache(2)
	mapped := netip.MustParseAddr("::ffff:192.0.2.8")
	plain := netip.MustParseAddr("192.0.2.8")
	_, _, err := c.Put(Key{Exporter: mapped, Version: 9, ID: 256}, Template{Fields: []Field{{Type: 8, Length: 4}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get(Key{Exporter: plain, Version: 9, ID: 256}); !ok {
		t.Fatal("mapped key did not match")
	}
	c.DropExporter(mapped)
	if _, ok := c.Get(Key{Exporter: plain, Version: 9, ID: 256}); ok {
		t.Fatal("drop missed unmapped key")
	}
}

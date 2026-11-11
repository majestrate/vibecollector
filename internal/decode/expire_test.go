package decode

import (
	"net/netip"
	"testing"
	"time"

	"github.com/majestrate/vibecollector/internal/obs"
	"github.com/majestrate/vibecollector/internal/sampling"
	"github.com/majestrate/vibecollector/internal/sequence"
	"github.com/majestrate/vibecollector/internal/template"
)

func testSession(t *testing.T) (*Session, *template.Cache) {
	t.Helper()
	templates, err := template.NewCache(8)
	if err != nil {
		t.Fatal(err)
	}
	hold, err := template.NewHold(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(templates, hold, sampling.NewCache(), sequence.NewTable(), obs.NewCounters(), 2*time.Hour, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return s, templates
}

func TestDropRecordedKeepsTemplateAfterEvictLeave(t *testing.T) {
	s, templates := testSession(t)
	ip := netip.MustParseAddr("192.0.2.40")
	at := time.Unix(1_700_000_000, 0).UTC()
	key := template.Key{Exporter: ip, Domain: 1, Version: 9, ID: 300}

	// Snapshot would still name this IP. Accept has already removed the set
	// entry and installed the template before the drop runs.
	s.mu.Lock()
	s.evict[ip] = struct{}{}
	delete(s.evict, ip)
	s.mu.Unlock()
	if _, _, err := templates.Put(key, template.Template{
		Fields:   []template.Field{{Type: 8, Length: 4}},
		Received: at,
	}); err != nil {
		t.Fatal(err)
	}
	s.dropRecorded(ip)
	if _, ok := templates.Get(key); !ok {
		t.Fatal("deleted a template installed after the IP left the eviction set")
	}

	s.mu.Lock()
	s.evict[ip] = struct{}{}
	s.mu.Unlock()
	s.dropRecorded(ip)
	if _, ok := templates.Get(key); ok {
		t.Fatal("recorded IP still in the set was kept")
	}
	s.mu.Lock()
	_, still := s.evict[ip]
	s.mu.Unlock()
	if still {
		t.Fatal("eviction entry remained")
	}
}

func TestDropIfIdleKeepsRefreshedTouch(t *testing.T) {
	s, templates := testSession(t)
	ip := netip.MustParseAddr("192.0.2.41")
	t0 := time.Unix(1_700_000_000, 0).UTC()
	key := template.Key{Exporter: ip, Domain: 1, Version: 9, ID: 301}
	if _, _, err := templates.Put(key, template.Template{
		Fields:   []template.Field{{Type: 8, Length: 4}},
		Received: t0,
	}); err != nil {
		t.Fatal(err)
	}
	idle := 30 * time.Minute
	now := t0.Add(idle + time.Second)
	templates.Touch(ip, t0)
	templates.Touch(ip, now)
	if s.dropIfIdle(ip, now, idle) {
		t.Fatal("refreshed touch was still idle")
	}
	if _, ok := templates.Get(key); !ok {
		t.Fatal("deleted a template whose touch was refreshed")
	}
}

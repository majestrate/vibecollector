package decode

import (
	"errors"
	"testing"
	"time"
	_ "time/tzdata"
)

func TestNewYorkInstants(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		y    int
		m    time.Month
		d    int
		h    int
		mi   int
		want string
		adj  bool
	}{
		{"spring midnight", 2026, time.March, 8, 0, 0, "2026-03-08T05:00:00Z", false},
		{"fall midnight", 2026, time.November, 1, 0, 0, "2026-11-01T04:00:00Z", false},
		{"fall fold", 2026, time.November, 1, 1, 30, "2026-11-01T05:30:00Z", false},
		{"spring gap", 2026, time.March, 8, 2, 30, "2026-03-08T07:00:00Z", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, adj, err := resolveCivil(tc.y, tc.m, tc.d, tc.h, tc.mi, 0, loc)
			if err != nil {
				t.Fatal(err)
			}
			if adj != tc.adj {
				t.Fatalf("boundaryAdjusted %v", adj)
			}
			if got.UTC().Format(time.RFC3339) != tc.want {
				t.Fatalf("got %s", got.UTC().Format(time.RFC3339))
			}
		})
	}
}

func TestLordHoweFold(t *testing.T) {
	loc, err := time.LoadLocation("Australia/Lord_Howe")
	if err != nil {
		t.Fatal(err)
	}
	// 30-minute overlap. The earlier instant is +11, not the later +10:30.
	got, adj, err := resolveCivil(2026, time.April, 5, 1, 45, 0, loc)
	if err != nil {
		t.Fatal(err)
	}
	if adj {
		t.Fatal("fold was marked adjusted")
	}
	if got.UTC().Format(time.RFC3339) != "2026-04-04T14:45:00Z" {
		t.Fatal(got.UTC().Format(time.RFC3339))
	}
}

func TestCalendarDayWindow(t *testing.T) {
	start, end, adj, err := CalendarDay("2026-03-08", "America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	if adj {
		t.Fatal("midnight was adjusted")
	}
	if start.UTC().Format(time.RFC3339) != "2026-03-08T05:00:00Z" {
		t.Fatal(start)
	}
	if end.UTC().Format(time.RFC3339) != "2026-03-09T04:00:00Z" {
		t.Fatal(end)
	}
	start, end, adj, err = CalendarDay("2026-11-01", "")
	if err != nil {
		t.Fatal(err)
	}
	if adj || !start.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) || !end.Equal(start.Add(24*time.Hour)) {
		t.Fatalf("utc %s %s %v", start, end, adj)
	}
}

func TestCalendarDayErrors(t *testing.T) {
	_, _, _, err := CalendarDay("2026-03-08", "Not/A_Zone")
	if !errors.Is(err, ErrUnknownZone) {
		t.Fatal(err)
	}
	_, _, _, err = CalendarDay("2026-02-31", "UTC")
	if !errors.Is(err, ErrBadDay) {
		t.Fatal(err)
	}
	_, _, _, err = CalendarDay("", "UTC")
	if !errors.Is(err, ErrBadDay) {
		t.Fatal(err)
	}
}

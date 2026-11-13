package decode

import (
	"errors"
	"strings"
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

func TestFloorInterval(t *testing.T) {
	kolkata := mustTime(t, "2026-06-15T06:40:00Z")
	got, err := FloorInterval(kolkata, 7, "m", "Asia/Kolkata")
	if err != nil {
		t.Fatal(err)
	}
	// 12:10 IST floors to 12:08 IST, which is 06:38Z.
	if got.Format(time.RFC3339) != "2026-06-15T06:38:00Z" {
		t.Fatal(got)
	}
	hour, err := FloorInterval(mustTime(t, "2026-11-01T05:30:00Z"), 1, "h", "America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	if hour.Format(time.RFC3339) != "2026-11-01T05:00:00Z" {
		t.Fatal(hour)
	}
	later, err := FloorInterval(mustTime(t, "2026-11-01T06:30:00Z"), 1, "h", "America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	if later.Format(time.RFC3339) != "2026-11-01T06:00:00Z" {
		t.Fatal(later)
	}
	spring, err := FloorInterval(mustTime(t, "2026-03-08T07:30:00Z"), 1, "h", "America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	if spring.Format(time.RFC3339) != "2026-03-08T07:00:00Z" {
		t.Fatal(spring)
	}
	day, err := FloorInterval(mustTime(t, "2026-11-01T18:00:00Z"), 1, "d", "America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	if day.Format(time.RFC3339) != "2026-11-01T04:00:00Z" {
		t.Fatal(day)
	}
	if _, err := FloorInterval(kolkata, 0, "m", "UTC"); !errors.Is(err, ErrBadDay) {
		t.Fatal(err)
	}
	if _, err := FloorInterval(kolkata, 15, "m", "Not/A_Zone"); !errors.Is(err, ErrUnknownZone) {
		t.Fatal(err)
	}
}

func TestIntervalStartsFallBack(t *testing.T) {
	start := mustTime(t, "2026-11-01T05:15:00Z")
	end := mustTime(t, "2026-11-01T06:45:00Z")
	got, err := IntervalStarts(start, end, 1, "h", "America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"2026-11-01T05:00:00Z", "2026-11-01T06:00:00Z"}
	if len(got) != len(want) {
		t.Fatal(formatTimes(got))
	}
	for i, ts := range got {
		if ts.Format(time.RFC3339) != want[i] {
			t.Fatal(formatTimes(got))
		}
	}
	spring, err := IntervalStarts(mustTime(t, "2026-03-08T06:00:00Z"), mustTime(t, "2026-03-08T08:00:00Z"), 1, "h", "America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	if formatTimes(spring) != "2026-03-08T06:00:00Z 2026-03-08T07:00:00Z" {
		t.Fatal(formatTimes(spring))
	}
	howe, err := FloorInterval(mustTime(t, "2026-04-04T15:20:00Z"), 15, "m", "Australia/Lord_Howe")
	if err != nil {
		t.Fatal(err)
	}
	// 01:50 +10:30 floors to the later 01:45, 15:15Z.
	if howe.Format(time.RFC3339) != "2026-04-04T15:15:00Z" {
		t.Fatal(howe)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	got, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func formatTimes(ts []time.Time) string {
	parts := make([]string, len(ts))
	for i, item := range ts {
		parts[i] = item.Format(time.RFC3339)
	}
	return strings.Join(parts, " ")
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

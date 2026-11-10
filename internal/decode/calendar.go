package decode

import (
	"errors"
	"fmt"
	"time"
)

// ErrUnknownZone means tz is not an IANA name time.LoadLocation can resolve.
// An empty tz is UTC and does not return this error.
var ErrUnknownZone = errors.New("unknown time zone")

// ErrBadDay means day is not a real civil date, or a skipped civil time
// could not be resolved within three hours.
var ErrBadDay = errors.New("bad day")

// CalendarDay returns the half-open UTC window for civil day in tz.
// day is YYYY-MM-DD. tz is an IANA name. An empty tz means UTC.
// start is local midnight. end is local midnight on the next civil day,
// from the same resolution rule. A repeated local time returns the earlier
// instant. A skipped local time moves forward in one-minute steps for at
// most three hours, and boundaryAdjusted is then true.
// ErrUnknownZone means tz did not resolve. ErrBadDay means day is not a
// calendar date or the skipped time did not resolve. The window is empty
// on error.
func CalendarDay(day, tz string) (start, end time.Time, boundaryAdjusted bool, err error) {
	loc, err := loadZone(tz)
	if err != nil {
		return time.Time{}, time.Time{}, false, err
	}
	y, m, d, err := parseDay(day)
	if err != nil {
		return time.Time{}, time.Time{}, false, err
	}
	start, adjStart, err := resolveCivil(y, m, d, 0, 0, 0, loc)
	if err != nil {
		return time.Time{}, time.Time{}, false, err
	}
	ny, nm, nd := nextDay(y, m, d)
	end, adjEnd, err := resolveCivil(ny, nm, nd, 0, 0, 0, loc)
	if err != nil {
		return time.Time{}, time.Time{}, false, err
	}
	return start, end, adjStart || adjEnd, nil
}

func loadZone(tz string) (*time.Location, error) {
	if tz == "" || tz == "UTC" {
		return time.UTC, nil
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknownZone, tz)
	}
	return loc, nil
}

func parseDay(day string) (int, time.Month, int, error) {
	t, err := time.Parse("2006-01-02", day)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("%w: %s", ErrBadDay, day)
	}
	return t.Year(), t.Month(), t.Day(), nil
}

func nextDay(y int, m time.Month, d int) (int, time.Month, int) {
	t := time.Date(y, m, d, 0, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
	return t.Year(), t.Month(), t.Day()
}

// resolveCivil maps a civil time in loc to an absolute instant.
// The UTC guess is offset-corrected twice. A repeated wall clock returns
// the earlier instant. A skipped wall clock advances one minute at a time.
func resolveCivil(y int, m time.Month, d, h, mi, s int, loc *time.Location) (time.Time, bool, error) {
	if t, ok := foldCivil(y, m, d, h, mi, s, loc); ok {
		return t, false, nil
	}
	cursor := time.Date(y, m, d, h, mi, s, 0, time.UTC)
	for i := 1; i <= 180; i++ {
		n := cursor.Add(time.Duration(i) * time.Minute)
		if t, ok := foldCivil(n.Year(), n.Month(), n.Day(), n.Hour(), n.Minute(), n.Second(), loc); ok {
			return t, true, nil
		}
	}
	return time.Time{}, false, ErrBadDay
}

// foldCivil applies the zone offset of the UTC guess, then the offset of
// that result. It returns false when the result's wall clock is not the
// requested civil time.
func foldCivil(y int, m time.Month, d, h, mi, s int, loc *time.Location) (time.Time, bool) {
	guess := time.Date(y, m, d, h, mi, s, 0, time.UTC)
	_, off1 := guess.In(loc).Zone()
	step := guess.Add(-time.Duration(off1) * time.Second)
	_, off2 := step.In(loc).Zone()
	result := guess.Add(-time.Duration(off2) * time.Second)
	if !wallEqual(result, loc, y, m, d, h, mi, s) {
		return time.Time{}, false
	}
	// A fold can be shorter than an hour. Walk back and keep the earliest match.
	earliest := result
	for i := 1; i <= 180; i++ {
		prev := result.Add(-time.Duration(i) * time.Minute)
		if wallEqual(prev, loc, y, m, d, h, mi, s) {
			earliest = prev
		}
	}
	return earliest, true
}

func wallEqual(t time.Time, loc *time.Location, y int, m time.Month, d, h, mi, s int) bool {
	lt := t.In(loc)
	return lt.Year() == y && lt.Month() == m && lt.Day() == d &&
		lt.Hour() == h && lt.Minute() == mi && lt.Second() == s
}

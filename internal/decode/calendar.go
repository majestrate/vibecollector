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

// FloorInterval returns the start of the civil interval that contains t.
// n is the count. unit is "m" (1–1440 minutes), "h" (1–24 hours), or "d"
// (1–366 civil days). tz is an IANA name. An empty tz means UTC.
// Minutes and hours align to local midnight. A repeated clock time keeps
// the occurrence that contains t, so the later hour in a fold is its own
// bucket when the width is small enough to separate it. Days align to local
// midnights grouped from 1970-01-01. A skipped civil boundary uses the same
// forward step as CalendarDay. The result is UTC.
// ErrUnknownZone means tz did not resolve. ErrBadDay means n or unit is
// outside those limits, t is the zero time, or a skipped boundary did not
// resolve within three hours.
func FloorInterval(t time.Time, n int, unit, tz string) (time.Time, error) {
	if t.IsZero() {
		return time.Time{}, ErrBadDay
	}
	loc, err := loadZone(tz)
	if err != nil {
		return time.Time{}, err
	}
	minutes, days, err := splitQuant(n, unit)
	if err != nil {
		return time.Time{}, err
	}
	if days > 0 {
		got, err := floorDays(t, days, loc)
		if err != nil {
			return time.Time{}, err
		}
		return got.UTC(), nil
	}
	got, err := floorMinutes(t, minutes, loc)
	if err != nil {
		return time.Time{}, err
	}
	return got.UTC(), nil
}

// IntervalStarts lists bucket starts for the half-open window [start, end).
// n, unit, and tz match FloorInterval. The first start is the interval that
// contains start, and it may fall before start. Each later start is the next
// civil interval. The result is empty when start is not before end.
// ErrUnknownZone and ErrBadDay match FloorInterval. ErrBadDay also means the
// walk could not advance.
func IntervalStarts(start, end time.Time, n int, unit, tz string) ([]time.Time, error) {
	if !start.Before(end) {
		return nil, nil
	}
	first, err := FloorInterval(start, n, unit, tz)
	if err != nil {
		return nil, err
	}
	limit := int(end.Sub(start)/time.Minute) + 8
	if unit == "d" {
		limit = int(end.Sub(start)/(24*time.Hour)) + n + 8
	}
	out := make([]time.Time, 0, 8)
	cur := first
	for len(out) < limit && cur.Before(end) {
		out = append(out, cur)
		next, err := nextInterval(cur, n, unit, tz)
		if err != nil {
			return nil, err
		}
		if !next.After(cur) {
			return nil, ErrBadDay
		}
		cur = next
	}
	if cur.Before(end) {
		return nil, ErrBadDay
	}
	return out, nil
}

func splitQuant(n int, unit string) (minutes, days int, err error) {
	switch unit {
	case "m":
		if n < 1 || n > 1440 {
			return 0, 0, ErrBadDay
		}
		return n, 0, nil
	case "h":
		if n < 1 || n > 24 {
			return 0, 0, ErrBadDay
		}
		return n * 60, 0, nil
	case "d":
		if n < 1 || n > 366 {
			return 0, 0, ErrBadDay
		}
		return 0, n, nil
	default:
		return 0, 0, ErrBadDay
	}
}

func floorMinutes(t time.Time, minutes int, loc *time.Location) (time.Time, error) {
	lt := t.In(loc)
	total := lt.Hour()*60 + lt.Minute()
	floored := total - total%minutes
	y, m, d := lt.Date()
	return civilAt(y, m, d, floored/60, floored%60, 0, loc, t)
}

func floorDays(t time.Time, n int, loc *time.Location) (time.Time, error) {
	lt := t.In(loc)
	y, m, d := lt.Date()
	num := dayNumber(y, m, d)
	mod := num % int64(n)
	if mod < 0 {
		mod += int64(n)
	}
	fd := time.Unix((num-mod)*86400, 0).UTC()
	return civilAt(fd.Year(), fd.Month(), fd.Day(), 0, 0, 0, loc, t)
}

func dayNumber(y int, m time.Month, d int) int64 {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Unix() / 86400
}

// civilAt returns the latest instant at or before limit with this wall clock.
// A skipped civil time uses resolveCivil and can fall after limit.
func civilAt(y int, m time.Month, d, h, mi, s int, loc *time.Location, limit time.Time) (time.Time, error) {
	earliest, ok := foldCivil(y, m, d, h, mi, s, loc)
	if !ok {
		got, _, err := resolveCivil(y, m, d, h, mi, s, loc)
		return got, err
	}
	chosen := earliest
	if earliest.After(limit) {
		return chosen, nil
	}
	_, off0 := earliest.Zone()
	_, offL := limit.In(loc).Zone()
	if off0 == offL && limit.Sub(earliest) < time.Hour {
		return chosen, nil
	}
	for i := 1; i <= 180; i++ {
		cand := earliest.Add(time.Duration(i) * time.Minute)
		if !wallEqual(cand, loc, y, m, d, h, mi, s) {
			continue
		}
		if cand.After(limit) {
			break
		}
		chosen = cand
	}
	return chosen, nil
}

func nextInterval(cur time.Time, n int, unit, tz string) (time.Time, error) {
	loc, err := loadZone(tz)
	if err != nil {
		return time.Time{}, err
	}
	if unit == "d" {
		lt := cur.In(loc)
		y, m, d := lt.Date()
		ny, nm, nd := addDays(y, m, d, n)
		return firstAfter(ny, nm, nd, 0, 0, 0, loc, cur)
	}
	minutes, _, err := splitQuant(n, unit)
	if err != nil {
		return time.Time{}, err
	}
	hint := cur.Add(time.Duration(minutes) * time.Minute)
	b, err := FloorInterval(hint, n, unit, tz)
	if err != nil {
		return time.Time{}, err
	}
	if b.After(cur) {
		return b, nil
	}
	step := cur
	for i := 0; i < minutes+180; i++ {
		step = step.Add(time.Minute)
		b, err = FloorInterval(step, n, unit, tz)
		if err != nil {
			return time.Time{}, err
		}
		if b.After(cur) {
			return b, nil
		}
	}
	return time.Time{}, ErrBadDay
}

func addDays(y int, m time.Month, d, n int) (int, time.Month, int) {
	t := time.Date(y, m, d, 0, 0, 0, 0, time.UTC).AddDate(0, 0, n)
	return t.Year(), t.Month(), t.Day()
}

// firstAfter returns the earliest instant of this wall clock that is after
// the bound. A skipped civil time uses resolveCivil.
func firstAfter(y int, m time.Month, d, h, mi, s int, loc *time.Location, after time.Time) (time.Time, error) {
	earliest, ok := foldCivil(y, m, d, h, mi, s, loc)
	if !ok {
		got, _, err := resolveCivil(y, m, d, h, mi, s, loc)
		if err != nil {
			return time.Time{}, err
		}
		if !got.After(after) {
			return time.Time{}, ErrBadDay
		}
		return got.UTC(), nil
	}
	if earliest.After(after) {
		return earliest.UTC(), nil
	}
	for i := 1; i <= 180; i++ {
		cand := earliest.Add(time.Duration(i) * time.Minute)
		if wallEqual(cand, loc, y, m, d, h, mi, s) && cand.After(after) {
			return cand.UTC(), nil
		}
	}
	return time.Time{}, ErrBadDay
}

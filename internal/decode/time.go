package decode

import (
	"time"

	"vibecollector/internal/flow"
)

// TimeFlag is how AbsMillis classified one device millisecond stamp.
type TimeFlag uint8

const (
	// FlagOK means the modular age is within maxAge.
	// The result is export minus that age.
	FlagOK TimeFlag = iota
	// FlagSkew means switched is ahead of sysUpTime by at most skew.
	// The result is the export time. This is not a wrap.
	FlagSkew
	// FlagSuspect means the modular age is above maxAge.
	// The result is export minus maxAge.
	FlagSuspect
)

// AbsMillis converts a sysUpTime-relative millisecond stamp to absolute time.
// export is the header export time. sysUpTime and switched are device
// milliseconds. maxAge and skew are timestamp_max_age and timestamp_skew_slack.
// The result is the absolute time. TimeFlag is FlagOK, FlagSkew, or FlagSuspect.
// When switched is ahead of sysUpTime by at most skew, the header clock is
// behind the flow and the result is export with FlagSkew. That is not a wrap.
// A real wrap has a large (switched-sysUpTime) and a small modular age.
// v5_wrap.bin is that wrap: sysUpTime is 100 and first is near 2^32, so
// switched-sysUpTime is about 2^32-100, the slack test does not fire, the
// modular age is a few seconds, and the flag is FlagOK.
// v5_skew.bin is the slack case: first is 500 ms ahead of sysUpTime, and the
// result is the export time with FlagSkew.
// switched = 5000 and sysUpTime = 100 is FlagSkew, not a wrap. The difference
// is inside a 5-second slack, and the modular age of about 49.7 days is not used.
// An age above maxAge returns export.Add(-maxAge) and FlagSuspect.
// Otherwise the result is export minus the modular age, and FlagOK.
// AbsMillis does not clamp to received_at. The caller does that next.
// AbsMillis does not return an error.
func AbsMillis(export time.Time, sysUpTime, switched uint32, maxAge, skew time.Duration) (time.Time, TimeFlag) {
	back := uint32(sysUpTime - switched) // modular
	if switched > sysUpTime && time.Duration(switched-sysUpTime)*time.Millisecond <= skew {
		// Header clock is slightly behind the flow timestamp. Not a wrap:
		// a real wrap makes (switched - sysUpTime) large and back small.
		return export, FlagSkew
	}
	age := time.Duration(back) * time.Millisecond
	if age > maxAge {
		return export.Add(-maxAge), FlagSuspect
	}
	return export.Add(-age), FlagOK
}

// Stamp is one flow's times after sysUpTime conversion, the end-before-start
// swap, and the receive-window clamp.
// Start and End are the stored instants. Export is the header export time,
// or the Unix epoch plus exportNsec when the header seconds are 0.
// Source is flow.TimeReceive when exportUnix is 0, otherwise flow.TimeSysUpTime.
// ClockClamped is true when Start or End was moved into the receive window.
// Skew, Suspect, and Clamped are the process-counter deltas for this flow:
// one per FlagSkew endpoint, one per FlagSuspect endpoint, one more Suspect
// when End was before Start, and Clamped 1 when ClockClamped is set.
// ResolveSysUp does not return an error, and neither does Stamp.
type Stamp struct {
	Start, End   time.Time
	Export       time.Time
	Source       flow.TimeSource
	ClockClamped bool
	Skew         uint64
	Suspect      uint64
	Clamped      uint64
}

// ResolveSysUp converts v5 or v9 first and last stamps into stored times.
// received is the collector clock and the clamp window's anchor.
// exportUnix and exportNsec are the header export clock. v9 passes nsec 0.
// sysUpTime, first, and last are device milliseconds. maxAge and skew are
// timestamp_max_age and timestamp_skew_slack.
// When exportUnix is 0 the header clock is unusable: Source is TimeReceive
// and both ends are received. Otherwise each end is AbsMillis, then swapped
// if End is before Start, then clamped into
// [received - maxAge, received + skew].
// The result is the stamp to store. ResolveSysUp does not return an error.
func ResolveSysUp(received time.Time, exportUnix, exportNsec, sysUpTime, first, last uint32, maxAge, skew time.Duration) Stamp {
	if exportUnix == 0 {
		return Stamp{
			Start:  received,
			End:    received,
			Export: time.Unix(0, int64(exportNsec)).UTC(),
			Source: flow.TimeReceive,
		}
	}
	export := time.Unix(int64(exportUnix), int64(exportNsec)).UTC()
	start, startFlag := AbsMillis(export, sysUpTime, first, maxAge, skew)
	end, endFlag := AbsMillis(export, sysUpTime, last, maxAge, skew)
	var stamp Stamp
	stamp.Export = export
	stamp.Source = flow.TimeSysUpTime
	stamp.Skew = flagCount(startFlag, FlagSkew) + flagCount(endFlag, FlagSkew)
	stamp.Suspect = flagCount(startFlag, FlagSuspect) + flagCount(endFlag, FlagSuspect)
	if end.Before(start) {
		start, end = end, start
		stamp.Suspect++
	}
	var movedStart, movedEnd bool
	start, movedStart = clampInstant(start, received, maxAge, skew)
	end, movedEnd = clampInstant(end, received, maxAge, skew)
	stamp.Start = start
	stamp.End = end
	stamp.ClockClamped = movedStart || movedEnd
	if stamp.ClockClamped {
		stamp.Clamped = 1
	}
	return stamp
}

func flagCount(got, want TimeFlag) uint64 {
	if got == want {
		return 1
	}
	return 0
}

// clampInstant moves t into [received-maxAge, received+skew].
// moved is true when t was outside that window. The nearest edge is used.
func clampInstant(t, received time.Time, maxAge, skew time.Duration) (time.Time, bool) {
	lo := received.Add(-maxAge)
	hi := received.Add(skew)
	if t.Before(lo) {
		return lo, true
	}
	if t.After(hi) {
		return hi, true
	}
	return t, false
}

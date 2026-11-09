package decode

import (
	"math"
	"testing"
	"time"

	"vibecollector/internal/flow"
)

func TestAbsMillisWrap(t *testing.T) {
	export := time.Unix(1_700_000_000, 0).UTC()
	const sys = uint32(100)
	// v5_wrap.bin: first is near 2^32, not a few seconds ahead of sysUpTime.
	first := ^uint32(0) - 2399 // 2^32 - 2400
	back := uint32(sys - first)
	if back != 2500 {
		t.Fatalf("modular age = %d, want 2500", back)
	}
	ahead := time.Duration(first-sys) * time.Millisecond
	if ahead <= 5*time.Second {
		t.Fatal("slack would fire; this is the wrap, not the skew")
	}
	got, flag := AbsMillis(export, sys, first, 2*time.Hour, 5*time.Second)
	if flag != FlagOK {
		t.Fatalf("flag %v", flag)
	}
	want := export.Add(-2500 * time.Millisecond)
	if !got.Equal(want) {
		t.Fatalf("got %s want %s", got, want)
	}
	if got.Equal(export) {
		t.Fatal("slack branch fired")
	}
}

func TestAbsMillisSkew(t *testing.T) {
	export := time.Unix(1_700_000_000, 0).UTC()
	// v5_skew.bin: first is 500 ms ahead of sysUpTime.
	got, flag := AbsMillis(export, 20_000, 20_500, 2*time.Hour, 5*time.Second)
	if flag != FlagSkew || !got.Equal(export) {
		t.Fatalf("flag %v got %s", flag, got)
	}
}

func TestAbsMillisSkewNotWrap(t *testing.T) {
	// switched = 5000 and sysUpTime = 100 is inside a 5s slack.
	// The modular age is about 49.7 days and must not be used.
	export := time.Unix(1_700_000_000, 0).UTC()
	got, flag := AbsMillis(export, 100, 5000, 2*time.Hour, 5*time.Second)
	if flag != FlagSkew {
		t.Fatalf("flag %v", flag)
	}
	if !got.Equal(export) {
		t.Fatalf("got %s, want export; modular wrap must not apply", got)
	}
	sys, switched := uint32(100), uint32(5000)
	wrapped := export.Add(-time.Duration(sys-switched) * time.Millisecond)
	if got.Equal(wrapped) {
		t.Fatal("used the 49-day modular age")
	}
}

func TestAbsMillisSkewBoundary(t *testing.T) {
	export := time.Unix(1_700_000_000, 0).UTC()
	got, flag := AbsMillis(export, 100, 100+5000, 2*time.Hour, 5*time.Second)
	if flag != FlagSkew || !got.Equal(export) {
		t.Fatalf("exact slack: flag %v got %s", flag, got)
	}
	got, flag = AbsMillis(export, 100, 100+5001, 2*time.Hour, 5*time.Second)
	if flag != FlagSuspect {
		t.Fatalf("1ms past slack flag %v", flag)
	}
	if !got.Equal(export.Add(-2 * time.Hour)) {
		t.Fatalf("past slack got %s", got)
	}
}

func TestAbsMillisSuspect(t *testing.T) {
	export := time.Unix(1_700_000_000, 0).UTC()
	maxAge := 2 * time.Hour
	sys := uint32((maxAge + time.Millisecond) / time.Millisecond)
	got, flag := AbsMillis(export, sys, 0, maxAge, 5*time.Second)
	if flag != FlagSuspect {
		t.Fatalf("flag %v", flag)
	}
	if !got.Equal(export.Add(-maxAge)) {
		t.Fatalf("got %s", got)
	}

	exact := uint32(maxAge / time.Millisecond)
	got, flag = AbsMillis(export, exact, 0, maxAge, 5*time.Second)
	if flag != FlagOK || !got.Equal(export.Add(-maxAge)) {
		t.Fatalf("age == maxAge flag %v got %s", flag, got)
	}
}

func TestResolveEndBeforeStart(t *testing.T) {
	export := time.Unix(1_700_000_000, 0).UTC()
	// first age 0, last age 10s. Conversion yields end before start.
	st := ResolveSysUp(export, uint32(export.Unix()), 0, 100_000, 100_000, 90_000, true, true, 2*time.Hour, 5*time.Second)
	if st.Source != flow.TimeSysUpTime {
		t.Fatalf("source %d", st.Source)
	}
	if !st.Start.Equal(export.Add(-10*time.Second)) || !st.End.Equal(export) {
		t.Fatalf("start %s end %s", st.Start, st.End)
	}
	if st.Suspect != 1 || st.Skew != 0 || st.ClockClamped || st.Clamped != 0 {
		t.Fatalf("stamp %+v", st)
	}
}

func TestResolveReceiveWindow(t *testing.T) {
	received := time.Unix(1_700_000_000, 0).UTC()
	maxAge := 2 * time.Hour
	skew := 5 * time.Second

	aheadUnix := uint32(received.Add(10 * 365 * 24 * time.Hour).Unix())
	st := ResolveSysUp(received, aheadUnix, 0, 10_000, 9_000, 10_000, true, true, maxAge, skew)
	hi := received.Add(skew)
	if !st.ClockClamped || st.Clamped != 1 {
		t.Fatalf("ahead clock %+v", st)
	}
	if !st.Start.Equal(hi) || !st.End.Equal(hi) {
		t.Fatalf("ahead start %s end %s want %s", st.Start, st.End, hi)
	}
	if st.Suspect != 0 || st.Skew != 0 {
		t.Fatalf("ahead should not be suspect or skew: %+v", st)
	}

	behindUnix := uint32(received.Add(-10 * 365 * 24 * time.Hour).Unix())
	st = ResolveSysUp(received, behindUnix, 0, 10_000, 9_000, 10_000, true, true, maxAge, skew)
	lo := received.Add(-maxAge)
	if !st.ClockClamped || !st.Start.Equal(lo) || !st.End.Equal(lo) {
		t.Fatalf("behind %+v want %s", st, lo)
	}

	// On the high edge: not clamped. One millisecond past it: clamped back.
	edge := uint32(received.Add(skew).Unix())
	st = ResolveSysUp(received, edge, 0, 10_000, 10_000, 10_000, true, true, maxAge, skew)
	if st.ClockClamped || !st.Start.Equal(received.Add(skew)) {
		t.Fatalf("edge %+v", st)
	}
	past := received.Add(skew + time.Millisecond)
	st = ResolveSysUp(received, uint32(past.Unix()), uint32(past.Nanosecond()), 0, 0, 0, true, true, maxAge, skew)
	if !st.ClockClamped || !st.End.Equal(hi) {
		t.Fatalf("past edge %+v", st)
	}
}

func TestResolveSuspectDoesNotImplyClockClamp(t *testing.T) {
	export := time.Unix(1_700_000_000, 0).UTC()
	sys := uint32((3 * time.Hour) / time.Millisecond)
	st := ResolveSysUp(export, uint32(export.Unix()), 0, sys, 0, 0, true, true, 2*time.Hour, 5*time.Second)
	if st.Suspect != 2 || st.ClockClamped || st.Skew != 0 {
		t.Fatalf("%+v", st)
	}
	want := export.Add(-2 * time.Hour)
	if !st.Start.Equal(want) || !st.End.Equal(want) {
		t.Fatalf("start %s end %s", st.Start, st.End)
	}
}

func TestResolveSwapThenClamp(t *testing.T) {
	received := time.Unix(1_700_000_000, 0).UTC()
	ahead := uint32(received.Add(10 * 365 * 24 * time.Hour).Unix())
	// After conversion end is 10s before start, then both sit far above the window.
	st := ResolveSysUp(received, ahead, 0, 100_000, 100_000, 90_000, true, true, 2*time.Hour, 5*time.Second)
	hi := received.Add(5 * time.Second)
	if st.Suspect != 1 || !st.ClockClamped || st.Clamped != 1 {
		t.Fatalf("%+v", st)
	}
	if !st.Start.Equal(hi) || !st.End.Equal(hi) {
		t.Fatalf("start %s end %s", st.Start, st.End)
	}
}

func TestResolveUnixSecsZero(t *testing.T) {
	received := time.Unix(1_700_000_000, 0).UTC()
	st := ResolveSysUp(received, 0, 0, 100, 50, 90_000, true, true, 2*time.Hour, 5*time.Second)
	if st.Source != flow.TimeReceive {
		t.Fatalf("source %d", st.Source)
	}
	if !st.Start.Equal(received) || !st.End.Equal(received) {
		t.Fatalf("start %s end %s", st.Start, st.End)
	}
	if !st.Export.Equal(time.Unix(0, 0).UTC()) || st.ClockClamped || st.Skew != 0 || st.Suspect != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestAbsMillisJustBelowWrapIsOK(t *testing.T) {
	// sysUpTime 0 and switched MaxUint32 is one millisecond before the wrap,
	// not a 49-day skew. The non-modular difference is far above slack.
	export := time.Unix(1_700_000_000, 0).UTC()
	got, flag := AbsMillis(export, 0, math.MaxUint32, 2*time.Hour, 5*time.Second)
	if flag != FlagOK || !got.Equal(export.Add(-time.Millisecond)) {
		t.Fatalf("flag %v got %s", flag, got)
	}
}

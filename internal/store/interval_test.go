package store

import (
	"errors"
	"math/big"
	"testing"
	"time"
	_ "time/tzdata"
)

func TestQuantizeSeriesSumsAndFills(t *testing.T) {
	start := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	end := start.Add(15 * time.Minute)
	pts := []pt{
		{t: start.Add(time.Minute), octets: 10, packets: 1},
		{t: start.Add(3 * time.Minute), octets: 4, packets: 2},
		{t: start.Add(7 * time.Minute), sampled: true, octets: 8, packets: 3},
	}
	f := Filter{Start: start, End: end, TZ: "UTC", IntervalN: 5, IntervalUnit: "m"}
	series, grain, err := quantizeSeries(pts, f, "1m")
	if err != nil {
		t.Fatal(err)
	}
	if grain != "5m" {
		t.Fatal(grain)
	}
	if len(series) != 2 || series[0].Sampled || !series[1].Sampled {
		t.Fatal(series)
	}
	if len(series[0].Points) != 3 || len(series[1].Points) != 3 {
		t.Fatal(series)
	}
	u0, u1, u2 := series[0].Points[0], series[0].Points[1], series[0].Points[2]
	if u0.T.Format(time.RFC3339) != "2026-06-15T12:00:00Z" || !eqCount(u0.Octets, 14) || !eqCount(u0.Packets, 3) {
		t.Fatal(u0)
	}
	if !eqCount(u1.Octets, 0) || !eqCount(u1.Packets, 0) || !eqCount(u2.Octets, 0) {
		t.Fatal(u1, u2)
	}
	s1 := series[1].Points[1]
	if s1.T.Format(time.RFC3339) != "2026-06-15T12:05:00Z" || !eqCount(s1.Octets, 8) || !eqCount(s1.Packets, 3) {
		t.Fatal(s1)
	}
}

func TestQuantizeSeriesNativeAndRaise(t *testing.T) {
	start := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	pts := []pt{{t: start, octets: 5, packets: 1}}
	series, grain, err := quantizeSeries(pts, Filter{Start: start, End: start.Add(time.Hour), TZ: "UTC"}, "1m")
	if err != nil {
		t.Fatal(err)
	}
	if grain != "1m" || len(series[0].Points) != 1 || !eqCount(series[0].Points[0].Octets, 5) {
		t.Fatal(grain, series)
	}
	_, grain, err = quantizeSeries(pts, Filter{Start: start, End: start.Add(time.Hour), TZ: "UTC", IntervalN: 5, IntervalUnit: "m"}, "1h")
	if err != nil {
		t.Fatal(err)
	}
	if grain != "1h" {
		t.Fatal(grain)
	}
	if _, _, err := quantizeSeries(nil, Filter{IntervalN: 48, IntervalUnit: "h"}, "1m"); !errors.Is(err, ErrBadFilter) {
		t.Fatal(err)
	}
	empty, grain, err := quantizeSeries(nil, Filter{Start: start, End: start.Add(time.Hour), TZ: "UTC", IntervalN: 15, IntervalUnit: "m"}, "1m")
	if err != nil {
		t.Fatal(err)
	}
	if grain != "15m" || len(empty[0].Points) != 0 || len(empty[1].Points) != 0 {
		t.Fatal(grain, empty)
	}
}

func TestQuantizeSeriesLocalDay(t *testing.T) {
	start := time.Date(2026, 11, 1, 4, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 2, 5, 0, 0, 0, time.UTC)
	evening := time.Date(2026, 11, 1, 18, 0, 0, 0, time.UTC)
	pts := []pt{{t: evening, octets: 9, packets: 2}}
	f := Filter{Start: start, End: end, TZ: "America/New_York", IntervalN: 1, IntervalUnit: "d"}
	series, grain, err := quantizeSeries(pts, f, "1m")
	if err != nil {
		t.Fatal(err)
	}
	if grain != "1d" || len(series[0].Points) != 1 {
		t.Fatalf("grain %s points %d", grain, len(series[0].Points))
	}
	pt0 := series[0].Points[0]
	if pt0.T.Format(time.RFC3339) != "2026-11-01T04:00:00Z" || !eqCount(pt0.Octets, 9) {
		t.Fatal(pt0)
	}
}

func TestQuantizeSeriesMovingAverage(t *testing.T) {
	start := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	end := start.Add(15 * time.Minute)
	pts := []pt{
		{t: start.Add(time.Minute), octets: 10, packets: 1},
		{t: start.Add(3 * time.Minute), octets: 4, packets: 2},
		{t: start.Add(7 * time.Minute), sampled: true, octets: 8, packets: 3},
	}
	f := Filter{Start: start, End: end, TZ: "UTC", IntervalN: 5, IntervalUnit: "m", MovingAverage: true}
	series, grain, err := quantizeSeries(pts, f, "1m")
	if err != nil {
		t.Fatal(err)
	}
	if grain != "5m" {
		t.Fatal(grain)
	}
	u0 := series[0].Points[0]
	if !eqCount(u0.Octets, 3) || !eqCount(u0.Packets, 1) {
		t.Fatal(u0)
	}
	if !eqCount(series[0].Points[1].Octets, 0) || !eqCount(series[0].Points[2].Octets, 0) {
		t.Fatal(series[0].Points)
	}
	s1 := series[1].Points[1]
	if !eqCount(s1.Octets, 2) || !eqCount(s1.Packets, 1) {
		t.Fatal(s1)
	}

	partialStart := start.Add(2 * time.Minute)
	partial := Filter{Start: partialStart, End: start.Add(7 * time.Minute), TZ: "UTC", IntervalN: 5, IntervalUnit: "m", MovingAverage: true}
	part, _, err := quantizeSeries([]pt{{t: start.Add(3 * time.Minute), octets: 4, packets: 2}}, partial, "1m")
	if err != nil {
		t.Fatal(err)
	}
	if !eqCount(part[0].Points[0].Octets, 1) || !eqCount(part[0].Points[0].Packets, 1) {
		t.Fatal(part[0].Points[0])
	}
	if !eqCount(part[0].Points[1].Octets, 0) {
		t.Fatal(part[0].Points[1])
	}

	half, _, err := quantizeSeries([]pt{{t: start, octets: 2, packets: 6}}, Filter{
		Start: start, End: start.Add(4 * time.Minute), TZ: "UTC", IntervalN: 4, IntervalUnit: "m", MovingAverage: true,
	}, "1m")
	if err != nil {
		t.Fatal(err)
	}
	if !eqCount(half[0].Points[0].Octets, 1) || !eqCount(half[0].Points[0].Packets, 2) {
		t.Fatal(half[0].Points[0])
	}

	if _, _, err := quantizeSeries(pts, Filter{Start: start, End: end, TZ: "UTC", MovingAverage: true}, "1m"); !errors.Is(err, ErrBadFilter) {
		t.Fatal(err)
	}

	raised, grain, err := quantizeSeries([]pt{{t: start, octets: 60, packets: 7}}, Filter{
		Start: start, End: start.Add(time.Hour), TZ: "UTC", IntervalN: 5, IntervalUnit: "m", MovingAverage: true,
	}, "1h")
	if err != nil {
		t.Fatal(err)
	}
	if grain != "1h" || !eqCount(raised[0].Points[0].Octets, 60) || !eqCount(raised[0].Points[0].Packets, 7) {
		t.Fatal(grain, raised[0].Points)
	}
}

func TestQuantizeSeriesAverageSpeed(t *testing.T) {
	start := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	end := start.Add(15 * time.Minute)
	pts := []pt{
		{t: start.Add(time.Minute), octets: 10, packets: 1},
		{t: start.Add(3 * time.Minute), octets: 4, packets: 2},
		{t: start.Add(7 * time.Minute), sampled: true, octets: 8, packets: 3},
	}
	f := Filter{Start: start, End: end, TZ: "UTC", IntervalN: 5, IntervalUnit: "m", AverageSpeed: true}
	series, grain, err := quantizeSeries(pts, f, "1m")
	if err != nil {
		t.Fatal(err)
	}
	if grain != "5m" {
		t.Fatal(grain)
	}
	u0 := series[0].Points[0]
	if u0.OctetRate != "0.047" || u0.PacketRate != "0.01" || !eqCount(u0.Octets, 14) {
		t.Fatal(u0)
	}
	if series[0].Points[1].OctetRate != "0" || series[0].Points[2].PacketRate != "0" {
		t.Fatal(series[0].Points[1], series[0].Points[2])
	}
	s1 := series[1].Points[1]
	if s1.OctetRate != "0.027" || s1.PacketRate != "0.01" {
		t.Fatal(s1)
	}

	partial := Filter{Start: start.Add(2 * time.Minute), End: start.Add(7 * time.Minute), TZ: "UTC", IntervalN: 5, IntervalUnit: "m", AverageSpeed: true}
	part, _, err := quantizeSeries([]pt{{t: start.Add(3 * time.Minute), octets: 4, packets: 2}}, partial, "1m")
	if err != nil {
		t.Fatal(err)
	}
	if part[0].Points[0].OctetRate != "0.022" || part[0].Points[0].PacketRate != "0.011" {
		t.Fatal(part[0].Points[0])
	}

	whole, _, err := quantizeSeries([]pt{{t: start, octets: 300, packets: 1}}, Filter{
		Start: start, End: start.Add(5 * time.Minute), TZ: "UTC", IntervalN: 5, IntervalUnit: "m", AverageSpeed: true,
	}, "1m")
	if err != nil {
		t.Fatal(err)
	}
	if whole[0].Points[0].OctetRate != "1" || whole[0].Points[0].PacketRate != "0.003" {
		t.Fatal(whole[0].Points[0])
	}

	if _, _, err := quantizeSeries(pts, Filter{Start: start, End: end, TZ: "UTC", AverageSpeed: true}, "1m"); !errors.Is(err, ErrBadFilter) {
		t.Fatal(err)
	}
	if _, _, err := quantizeSeries(pts, Filter{Start: start, End: end, TZ: "UTC", IntervalN: 5, IntervalUnit: "m", MovingAverage: true, AverageSpeed: true}, "1m"); !errors.Is(err, ErrBadFilter) {
		t.Fatal(err)
	}

	raised, grain, err := quantizeSeries([]pt{{t: start, octets: 60, packets: 7}}, Filter{
		Start: start, End: start.Add(time.Hour), TZ: "UTC", IntervalN: 5, IntervalUnit: "m", AverageSpeed: true,
	}, "1h")
	if err != nil {
		t.Fatal(err)
	}
	if grain != "1h" || raised[0].Points[0].OctetRate != "0.017" || raised[0].Points[0].PacketRate != "0.002" {
		t.Fatal(grain, raised[0].Points[0])
	}
}

func TestQuantizeSeriesMovingAverageFallDay(t *testing.T) {
	start := time.Date(2026, 11, 1, 4, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 2, 5, 0, 0, 0, time.UTC)
	evening := time.Date(2026, 11, 1, 18, 0, 0, 0, time.UTC)
	f := Filter{Start: start, End: end, TZ: "America/New_York", IntervalN: 1, IntervalUnit: "d", MovingAverage: true}
	series, grain, err := quantizeSeries([]pt{{t: evening, octets: 50, packets: 13}}, f, "1h")
	if err != nil {
		t.Fatal(err)
	}
	pt0 := series[0].Points[0]
	if grain != "1d" || len(series[0].Points) != 1 || !eqCount(pt0.Octets, 2) || !eqCount(pt0.Packets, 1) {
		t.Fatalf("grain %s point %+v", grain, pt0)
	}
}

func TestQuantizeSeriesAverageSpeedFallDay(t *testing.T) {
	start := time.Date(2026, 11, 1, 4, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 2, 5, 0, 0, 0, time.UTC)
	evening := time.Date(2026, 11, 1, 18, 0, 0, 0, time.UTC)
	f := Filter{Start: start, End: end, TZ: "America/New_York", IntervalN: 1, IntervalUnit: "d", AverageSpeed: true}
	series, grain, err := quantizeSeries([]pt{{t: evening, octets: 90, packets: 45}}, f, "1h")
	if err != nil {
		t.Fatal(err)
	}
	pt0 := series[0].Points[0]
	if grain != "1d" || pt0.OctetRate != "0.001" || pt0.PacketRate != "0.001" {
		t.Fatalf("grain %s point %+v", grain, pt0)
	}
}

func TestQuantizeSeriesRootMeanSquare(t *testing.T) {
	start := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	end := start.Add(15 * time.Minute)
	pts := []pt{
		{t: start.Add(time.Minute), octets: 10, packets: 1},
		{t: start.Add(3 * time.Minute), octets: 4, packets: 2},
		{t: start.Add(7 * time.Minute), sampled: true, octets: 8, packets: 3},
	}
	f := Filter{Start: start, End: end, TZ: "UTC", IntervalN: 5, IntervalUnit: "m", RootMeanSquare: true}
	series, grain, err := quantizeSeries(pts, f, "1m")
	if err != nil {
		t.Fatal(err)
	}
	if grain != "5m" {
		t.Fatal(grain)
	}
	u0 := series[0].Points[0]
	if !eqCount(u0.Octets, 5) || !eqCount(u0.Packets, 1) || u0.OctetRate != "" {
		t.Fatal(u0)
	}
	if !eqCount(series[0].Points[1].Octets, 0) || !eqCount(series[0].Points[2].Octets, 0) {
		t.Fatal(series[0].Points)
	}
	s1 := series[1].Points[1]
	if !eqCount(s1.Octets, 4) || !eqCount(s1.Packets, 1) {
		t.Fatal(s1)
	}

	partial := Filter{Start: start.Add(2 * time.Minute), End: start.Add(7 * time.Minute), TZ: "UTC", IntervalN: 5, IntervalUnit: "m", RootMeanSquare: true}
	part, _, err := quantizeSeries([]pt{{t: start.Add(3 * time.Minute), octets: 4, packets: 2}}, partial, "1m")
	if err != nil {
		t.Fatal(err)
	}
	if !eqCount(part[0].Points[0].Octets, 2) || !eqCount(part[0].Points[0].Packets, 1) {
		t.Fatal(part[0].Points[0])
	}
	if !eqCount(part[0].Points[1].Octets, 0) {
		t.Fatal(part[0].Points[1])
	}

	half, _, err := quantizeSeries([]pt{{t: start, octets: 3, packets: 1}}, Filter{
		Start: start, End: start.Add(4 * time.Minute), TZ: "UTC", IntervalN: 4, IntervalUnit: "m", RootMeanSquare: true,
	}, "1m")
	if err != nil {
		t.Fatal(err)
	}
	if !eqCount(half[0].Points[0].Octets, 2) || !eqCount(half[0].Points[0].Packets, 1) {
		t.Fatal(half[0].Points[0])
	}

	huge, _, err := quantizeSeries([]pt{{t: start, octets: ^uint64(0), packets: 1}}, Filter{
		Start: start, End: start.Add(4 * time.Minute), TZ: "UTC", IntervalN: 4, IntervalUnit: "m", RootMeanSquare: true,
	}, "1m")
	if err != nil {
		t.Fatal(err)
	}
	if !eqCount(huge[0].Points[0].Octets, 1<<63) || !eqCount(huge[0].Points[0].Packets, 1) {
		t.Fatal(huge[0].Points[0])
	}

	kept, _, err := quantizeSeries([]pt{{t: start, octets: 9, packets: 4}}, Filter{
		Start: start.Add(30 * time.Second), End: start.Add(50 * time.Second), TZ: "UTC", IntervalN: 1, IntervalUnit: "m", RootMeanSquare: true,
	}, "1m")
	if err != nil {
		t.Fatal(err)
	}
	if !eqCount(kept[0].Points[0].Octets, 9) || !eqCount(kept[0].Points[0].Packets, 4) {
		t.Fatal(kept[0].Points[0])
	}

	if _, _, err := quantizeSeries(pts, Filter{Start: start, End: end, TZ: "UTC", RootMeanSquare: true}, "1m"); !errors.Is(err, ErrBadFilter) {
		t.Fatal(err)
	}
	pairs := []Filter{
		{Start: start, End: end, TZ: "UTC", IntervalN: 5, IntervalUnit: "m", MovingAverage: true, RootMeanSquare: true},
		{Start: start, End: end, TZ: "UTC", IntervalN: 5, IntervalUnit: "m", AverageSpeed: true, RootMeanSquare: true},
		{Start: start, End: end, TZ: "UTC", IntervalN: 5, IntervalUnit: "m", MovingAverage: true, AverageSpeed: true, RootMeanSquare: true},
	}
	for _, bad := range pairs {
		if _, _, err := quantizeSeries(pts, bad, "1m"); !errors.Is(err, ErrBadFilter) {
			t.Fatal(err)
		}
	}

	raised, grain, err := quantizeSeries([]pt{{t: start, octets: 60, packets: 7}}, Filter{
		Start: start, End: start.Add(time.Hour), TZ: "UTC", IntervalN: 5, IntervalUnit: "m", RootMeanSquare: true,
	}, "1h")
	if err != nil {
		t.Fatal(err)
	}
	if grain != "1h" || !eqCount(raised[0].Points[0].Octets, 60) || !eqCount(raised[0].Points[0].Packets, 7) {
		t.Fatal(grain, raised[0].Points[0])
	}
}

func TestQuantizeSeriesRootMeanSquareFallDay(t *testing.T) {
	start := time.Date(2026, 11, 1, 4, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 2, 5, 0, 0, 0, time.UTC)
	evening := time.Date(2026, 11, 1, 18, 0, 0, 0, time.UTC)
	f := Filter{Start: start, End: end, TZ: "America/New_York", IntervalN: 1, IntervalUnit: "d", RootMeanSquare: true}
	series, grain, err := quantizeSeries([]pt{{t: evening, octets: 50, packets: 13}}, f, "1h")
	if err != nil {
		t.Fatal(err)
	}
	pt0 := series[0].Points[0]
	if grain != "1d" || len(series[0].Points) != 1 || !eqCount(pt0.Octets, 10) || !eqCount(pt0.Packets, 3) {
		t.Fatalf("grain %s point %+v", grain, pt0)
	}
}

func TestQuantizeSeriesSumOverflow(t *testing.T) {
	start := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	pts := []pt{
		{t: start, octets: ^uint64(0), packets: ^uint64(0)},
		{t: start.Add(time.Minute), octets: ^uint64(0), packets: 1},
	}
	series, _, err := quantizeSeries(pts, Filter{
		Start: start, End: start.Add(5 * time.Minute), TZ: "UTC", IntervalN: 5, IntervalUnit: "m",
	}, "1m")
	if err != nil {
		t.Fatal(err)
	}
	wantOctets := new(big.Int).Lsh(big.NewInt(1), 65)
	wantOctets.Sub(wantOctets, big.NewInt(2))
	wantPackets := new(big.Int).SetUint64(^uint64(0))
	wantPackets.Add(wantPackets, big.NewInt(1))
	pt0 := series[0].Points[0]
	if pt0.Octets.Cmp(wantOctets) != 0 || pt0.Packets.Cmp(wantPackets) != 0 {
		t.Fatal(pt0.Octets, pt0.Packets)
	}
}

func eqCount(n *big.Int, want uint64) bool {
	if n == nil || n.Sign() == 0 {
		return want == 0
	}
	return n.IsUint64() && n.Uint64() == want
}

package store

import (
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/majestrate/vibecollector/internal/decode"
)

// quantizeSeries sums native samples into the requested interval.
// pts are the native buckets. f.IntervalN and f.IntervalUnit are the request.
// A zero N with an empty unit keeps native and does not add empty buckets.
// native is "1m" or "1h". The series include a zero point for every interval
// in [f.Start, f.End) when the request is set and pts is not empty.
// Sampled and unsampled stay separate. The label is the width that was summed.
// When f.MovingAverage is set, each bucket becomes the rounded mean of the
// native samples inside it. Empty native slots in the overlap of the bucket
// and [f.Start, f.End) count as zero. A half rounds up.
// When f.AverageSpeed is set, each bucket becomes octets per second and
// packets per second over that same overlap. The rate rounds to the nearest
// thousandth, and a half rounds up.
// When f.RootMeanSquare is set, each bucket becomes the square root of the
// mean square of the native samples inside it. Empty slots count as zero.
// The result rounds to the nearest integer, and a half rounds up.
// Any of these options with an unset interval is ErrBadFilter, as is more
// than one of them together.
// ErrBadFilter means the interval or zone cannot be applied.
func quantizeSeries(pts []pt, f Filter, native string) ([]Series, string, error) {
	if bucketModes(f) > 0 && (f.IntervalN == 0 || f.IntervalUnit == "") {
		return nil, "", ErrBadFilter
	}
	if bucketModes(f) > 1 {
		return nil, "", ErrBadFilter
	}
	if f.IntervalN == 0 && f.IntervalUnit == "" {
		return seriesFrom(pts, f.Sampled), native, nil
	}
	n, unit, label, err := effectiveQuant(f.IntervalN, f.IntervalUnit, native)
	if err != nil {
		return nil, "", err
	}
	if len(pts) == 0 {
		return seriesFrom(nil, f.Sampled), label, nil
	}
	starts, err := decode.IntervalStarts(f.Start, f.End, n, unit, f.TZ)
	if err != nil {
		return nil, "", ErrBadFilter
	}
	totals := make(map[[2]int64]bucketSum, len(pts))
	var scratch big.Int
	for _, p := range pts {
		bucket, err := decode.FloorInterval(p.t, n, unit, f.TZ)
		if err != nil {
			return nil, "", ErrBadFilter
		}
		flag := int64(0)
		if p.sampled {
			flag = 1
		}
		key := [2]int64{bucket.UTC().UnixMilli(), flag}
		cur := totals[key]
		if cur.octets == nil {
			cur.octets = new(big.Int)
			cur.packets = new(big.Int)
			if f.RootMeanSquare {
				cur.octetSq = new(big.Int)
				cur.packetSq = new(big.Int)
			}
		}
		addCount(&scratch, cur.octets, cur.octetSq, p.octets)
		addCount(&scratch, cur.packets, cur.packetSq, p.packets)
		totals[key] = cur
	}
	wants := []bool{false, true}
	if f.Sampled != nil {
		wants = []bool{*f.Sampled}
	}
	out := make([]Series, 0, len(wants))
	for _, sampled := range wants {
		flag := int64(0)
		if sampled {
			flag = 1
		}
		points := make([]Point, 0, len(starts))
		for _, st := range starts {
			v := totals[[2]int64{st.UTC().UnixMilli(), flag}]
			points = append(points, Point{T: st.UTC(), Octets: countOrZero(v.octets), Packets: countOrZero(v.packets)})
		}
		out = append(out, Series{Sampled: sampled, Points: points})
	}
	if f.MovingAverage {
		if err := averageBuckets(out, starts, f, native); err != nil {
			return nil, "", err
		}
	}
	if f.AverageSpeed {
		if err := speedBuckets(out, starts, f); err != nil {
			return nil, "", err
		}
	}
	if f.RootMeanSquare {
		if err := rmsBuckets(out, starts, totals, f, native); err != nil {
			return nil, "", err
		}
	}
	return out, label, nil
}

func bucketModes(f Filter) int {
	n := 0
	if f.MovingAverage {
		n++
	}
	if f.AverageSpeed {
		n++
	}
	if f.RootMeanSquare {
		n++
	}
	return n
}

// bucketSum is one quantized bucket. octets and packets are the totals.
// octetSq and packetSq are the sums of squares of the native samples, set
// only for a root-mean-square request. Nil means zero.
type bucketSum struct {
	octets, packets   *big.Int
	octetSq, packetSq *big.Int
}

// addCount adds sample to sum. When sq is non-nil it also adds sample².
// scratch is reused for both steps.
func addCount(scratch, sum, sq *big.Int, sample uint64) {
	scratch.SetUint64(sample)
	sum.Add(sum, scratch)
	if sq == nil {
		return
	}
	scratch.Mul(scratch, scratch)
	sq.Add(sq, scratch)
}

// countOrZero returns n, or a zero count when n is nil.
func countOrZero(n *big.Int) *big.Int {
	if n == nil {
		return new(big.Int)
	}
	return n
}

// bucketOverlap is the half-open span of starts[i] inside [f.Start, f.End).
// The end is the next bucket start when that start falls before f.End.
func bucketOverlap(starts []time.Time, i int, f Filter) (time.Time, time.Time) {
	from := starts[i]
	if f.Start.After(from) {
		from = f.Start
	}
	to := f.End
	if i+1 < len(starts) && starts[i+1].Before(to) {
		to = starts[i+1]
	}
	return from, to
}

// averageBuckets replaces each bucket sum with the mean of the native samples
// inside it. starts are the bucket starts, one per point, in order.
// native is "1m" or "1h". A native slot counts when its timestamp is inside
// both the bucket and [f.Start, f.End). An empty slot counts as zero.
// The mean rounds half up. A bucket with no slot in that overlap keeps its sum.
// ErrBadFilter means native is not a known grain or a series length does not
// match starts.
func averageBuckets(series []Series, starts []time.Time, f Filter, native string) error {
	slots, err := overlapSlots(starts, f, native)
	if err != nil {
		return err
	}
	for i := range series {
		if len(series[i].Points) != len(starts) {
			return ErrBadFilter
		}
		for j := range series[i].Points {
			if slots[j] == 0 {
				continue
			}
			series[i].Points[j].Octets = roundMean(series[i].Points[j].Octets, slots[j])
			series[i].Points[j].Packets = roundMean(series[i].Points[j].Packets, slots[j])
		}
	}
	return nil
}

// overlapSlots counts native samples in each bucket's overlap with the window.
// native is "1m" or "1h". ErrBadFilter means native is not a known grain.
func overlapSlots(starts []time.Time, f Filter, native string) ([]uint64, error) {
	step, err := nativeStep(native)
	if err != nil {
		return nil, err
	}
	slots := make([]uint64, len(starts))
	for i := range starts {
		from, to := bucketOverlap(starts, i, f)
		slots[i] = nativeSlots(from, to, step)
	}
	return slots, nil
}

func nativeStep(native string) (time.Duration, error) {
	switch native {
	case "1m":
		return time.Minute, nil
	case "1h":
		return time.Hour, nil
	default:
		return 0, ErrBadFilter
	}
}

// nativeSlots counts grid starts in the half-open interval [from, to).
// step is the native grain. Grid starts are aligned to the Unix epoch.
func nativeSlots(from, to time.Time, step time.Duration) uint64 {
	if step <= 0 || !from.Before(to) {
		return 0
	}
	stepMS := step.Milliseconds()
	startMS := from.UnixMilli()
	endMS := to.UnixMilli()
	rem := startMS % stepMS
	if rem < 0 {
		rem += stepMS
	}
	first := startMS
	if rem != 0 {
		first = startMS + (stepMS - rem)
	}
	if first >= endMS {
		return 0
	}
	return uint64((endMS - first) / stepMS)
}

// speedBuckets replaces each bucket sum with octets per second and packets
// per second. The duration is the overlap of the bucket and [f.Start, f.End).
// The rate rounds to the nearest thousandth, and a half rounds up.
// OctetRate and PacketRate hold that decimal. Octets and Packets are left at
// the summed totals. ErrBadFilter means a series length does not match starts.
func speedBuckets(series []Series, starts []time.Time, f Filter) error {
	for i := range series {
		if len(series[i].Points) != len(starts) {
			return ErrBadFilter
		}
		for j := range series[i].Points {
			from, to := bucketOverlap(starts, j, f)
			series[i].Points[j].OctetRate = formatRate(series[i].Points[j].Octets, to.Sub(from))
			series[i].Points[j].PacketRate = formatRate(series[i].Points[j].Packets, to.Sub(from))
		}
	}
	return nil
}

// formatRate returns sum/duration as a decimal with at most three fractional digits.
// A half at the next digit rounds up. A zero sum or a non-positive duration is "0".
func formatRate(sum *big.Int, d time.Duration) string {
	if sum == nil || sum.Sign() == 0 || d <= 0 {
		return "0"
	}
	ms := d.Milliseconds()
	if ms <= 0 {
		return "0"
	}
	num := new(big.Int).Set(sum)
	num.Mul(num, big.NewInt(1_000_000))
	den := new(big.Int).SetInt64(ms)
	q, r := new(big.Int).QuoRem(num, den, new(big.Int))
	if new(big.Int).Lsh(r, 1).Cmp(den) >= 0 {
		q.Add(q, big.NewInt(1))
	}
	s := q.String()
	if len(s) <= 3 {
		s = strings.Repeat("0", 4-len(s)) + s
	}
	whole := s[:len(s)-3]
	frac := strings.TrimRight(s[len(s)-3:], "0")
	if frac == "" {
		return whole
	}
	return whole + "." + frac
}

// rmsBuckets replaces each bucket sum with the root mean square of the native
// samples inside it. totals holds the sum of squares for samples that landed
// in the bucket. Empty slots count as zero. The result rounds half up.
// A bucket with no slot in the overlap keeps its sum.
// ErrBadFilter means native is not a known grain or a series length does not
// match starts.
func rmsBuckets(series []Series, starts []time.Time, totals map[[2]int64]bucketSum, f Filter, native string) error {
	slots, err := overlapSlots(starts, f, native)
	if err != nil {
		return err
	}
	for i := range series {
		if len(series[i].Points) != len(starts) {
			return ErrBadFilter
		}
		flag := int64(0)
		if series[i].Sampled {
			flag = 1
		}
		for j := range series[i].Points {
			if slots[j] == 0 {
				continue
			}
			got := totals[[2]int64{starts[j].UTC().UnixMilli(), flag}]
			series[i].Points[j].Octets = roundRMS(got.octetSq, slots[j])
			series[i].Points[j].Packets = roundRMS(got.packetSq, slots[j])
		}
	}
	return nil
}

// roundRMS returns sqrt(sumSq/slots) rounded half up.
// sumSq is the sum of squares of the native samples. slots is how many of
// those samples the bucket overlaps, including empty ones as zero.
// A nil or zero sum of squares is 0.
// floor(sqrt(sumSq/slots)) equals floor(sqrt(floor(sumSq/slots))), so the
// floor root is (*big.Int).Sqrt of the quotient. A half rounds up.
func roundRMS(sumSq *big.Int, slots uint64) *big.Int {
	if slots == 0 || sumSq == nil || sumSq.Sign() == 0 {
		return new(big.Int)
	}
	den := new(big.Int).SetUint64(slots)
	q := new(big.Int).Quo(sumSq, den)
	r := new(big.Int).Sqrt(q)
	half := new(big.Int).Lsh(r, 1)
	half.Add(half, big.NewInt(1))
	right := new(big.Int).Mul(half, half)
	right.Mul(right, den)
	left := new(big.Int).Lsh(new(big.Int).Set(sumSq), 2)
	if left.Cmp(right) >= 0 {
		r.Add(r, big.NewInt(1))
	}
	return r
}

// roundMean returns sum/slots rounded half up.
// A nil or zero sum is 0. slots 0 keeps sum. A half rounds up.
func roundMean(sum *big.Int, slots uint64) *big.Int {
	if sum == nil || sum.Sign() == 0 {
		return new(big.Int)
	}
	if slots == 0 {
		return new(big.Int).Set(sum)
	}
	den := new(big.Int).SetUint64(slots)
	q, r := new(big.Int).QuoRem(new(big.Int).Set(sum), den, new(big.Int))
	if new(big.Int).Lsh(r, 1).Cmp(den) >= 0 {
		q.Add(q, big.NewInt(1))
	}
	return q
}

// effectiveQuant raises a request that is finer than the native grain.
// native is "1m" or "1h". The label is the width Timeseries reports.
func effectiveQuant(n int, unit, native string) (int, string, string, error) {
	if err := quantOK(n, unit); err != nil {
		return 0, "", "", err
	}
	nativeMin := 1
	if native == "1h" {
		nativeMin = 60
	}
	if unit == "d" {
		return n, unit, strconv.Itoa(n) + unit, nil
	}
	width := n
	if unit == "h" {
		width = n * 60
	}
	if width < nativeMin {
		if nativeMin == 60 {
			return 1, "h", "1h", nil
		}
		return 1, "m", "1m", nil
	}
	return n, unit, strconv.Itoa(n) + unit, nil
}

func quantOK(n int, unit string) error {
	switch unit {
	case "m":
		if n < 1 || n > 1440 {
			return ErrBadFilter
		}
	case "h":
		if n < 1 || n > 24 {
			return ErrBadFilter
		}
	case "d":
		if n < 1 || n > 366 {
			return ErrBadFilter
		}
	default:
		return ErrBadFilter
	}
	return nil
}

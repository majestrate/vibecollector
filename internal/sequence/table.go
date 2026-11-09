// Package sequence tracks one export cursor per exporter, domain, and version.
package sequence

import (
	"errors"
	"net/netip"
	"sync"
)

// reorderWindow is the fixed reorder distance. It is not a config key.
const reorderWindow uint32 = 1024

// resetBelow is the behind-distance that still counts as a reset.
// A distance of exactly 2^31 is a gap, not a reset.
const resetBelow uint32 = 1 << 31

// ErrBadVersion means Version is not 5, 9, or 10.
// Observe returns it and does not move a cursor. errors.Is reports this sentinel.
var ErrBadVersion = errors.New("version is not 5, 9, or 10")

// Key is one sequence cursor. Exporter is the source IP. Domain is the v9
// source ID, the IPFIX observation domain, or the v5 value
// uint32(engine_type)<<8 | uint32(engine_id). Version is 5, 9, or 10 and
// selects the unit: v5 flows, v9 packets, IPFIX data records.
type Key struct {
	Exporter netip.Addr
	Domain   uint32
	Version  uint16
}

// Action is what Observe decided. The cursor moves on Init, InOrder, Reset,
// and Gap. It does not move on Duplicate, Reorder, or Unresolved.
type Action uint8

const (
	ActionInit Action = iota
	ActionInOrder
	ActionDuplicate
	ActionReorder
	ActionReset
	ActionGap
	ActionUnresolved
)

// Decision is one cursor update. Gap is non-zero only for ActionGap, and it
// is in the key's unit. The caller adds Gap to the matching sequence_gap
// counter and increments sequence_duplicate, sequence_reorder,
// sequence_reset, or sequence_unresolved for the other actions.
type Decision struct {
	Action Action
	Gap    uint32
}

// Snapshot is the cursor state ObserveUnresolved saved.
// HadCursor is false when the key had no cursor. Expected is the saved
// expected sequence. Seq is the packet sequence that could not be counted.
type Snapshot struct {
	HadCursor bool
	Expected  uint32
	Seq       uint32
}

// Table is every exporter's cursors. Methods are safe for concurrent use
// on different keys. Session holds the exporter mutex around Observe.
type Table struct {
	mu  sync.Mutex
	cur map[Key]cursor
}

type cursor struct {
	expected  uint32
	lastSeq   uint32
	lastCount uint32
}

// NewTable returns an empty table.
func NewTable() *Table {
	return &Table{cur: make(map[Key]cursor)}
}

// Observe applies one packet that has a known count.
// seq is the header sequence. count is v5's flow count, 1 for a parsed v9
// packet, or the IPFIX data-record count including options data records.
// A count of 0 is still in order when seq equals expected, and expected does
// not move, so the next message may reuse that sequence number.
// The checks run in this order. No cursor: store expected=seq+count and
// return ActionInit. This does not count a gap. seq==expected: advance and
// return ActionInOrder. seq==lastSeq after that test: return ActionDuplicate
// and do not move expected. uint32(expected-seq) in 1..1024: return
// ActionReorder and do not move expected. That distance above 1024 and below
// 2^31: store expected=seq+count and return ActionReset. Otherwise the packet
// is ahead: Gap is uint32(seq-expected), expected becomes seq+count, and the
// action is ActionGap.
// A one-behind packet has modular forward distance 2^32-1 and takes the
// reorder branch. ErrBadVersion means Version is not 5, 9, or 10.
func (t *Table) Observe(key Key, seq, count uint32) (Decision, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.observeLocked(canon(key), seq, count)
}

// ObserveUnresolved records that count cannot be known. It does not move
// expected. The action is ActionUnresolved. The snapshot is what
// ApplyIfUnchanged compares later. The caller stores it on the hold entry.
func (t *Table) ObserveUnresolved(key Key, seq uint32) (Decision, Snapshot) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key = canon(key)
	snap := Snapshot{Seq: seq}
	if c, ok := t.cur[key]; ok {
		snap.HadCursor = true
		snap.Expected = c.expected
	}
	return Decision{Action: ActionUnresolved}, snap
}

// ApplyIfUnchanged applies a held packet's sequence once.
// It updates only when snap.HadCursor is false and the cursor is still
// absent, or snap.HadCursor is true and expected still equals snap.Expected.
// Otherwise it returns a zero Decision and applied false, and the caller
// does not add a second gap. count is the data-record count now that the
// template exists. The update itself follows Observe's rules.
func (t *Table) ApplyIfUnchanged(key Key, snap Snapshot, count uint32) (Decision, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key = canon(key)
	c, ok := t.cur[key]
	if !snap.HadCursor {
		if ok {
			return Decision{}, false
		}
	} else if !ok || c.expected != snap.Expected {
		return Decision{}, false
	}
	d, err := t.observeLocked(key, snap.Seq, count)
	if err != nil {
		return Decision{}, false
	}
	return d, true
}

// DropExporter removes every cursor for ip. The next packet is ActionInit.
func (t *Table) DropExporter(ip netip.Addr) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ip = ip.Unmap()
	for k := range t.cur {
		if k.Exporter == ip {
			delete(t.cur, k)
		}
	}
}

func (t *Table) observeLocked(key Key, seq, count uint32) (Decision, error) {
	if key.Version != 5 && key.Version != 9 && key.Version != 10 {
		return Decision{}, ErrBadVersion
	}
	if t.cur == nil {
		t.cur = make(map[Key]cursor)
	}
	c, ok := t.cur[key]
	if !ok {
		t.cur[key] = cursor{expected: seq + count, lastSeq: seq, lastCount: count}
		return Decision{Action: ActionInit}, nil
	}
	if seq == c.expected {
		c.expected = seq + count
		c.lastSeq = seq
		c.lastCount = count
		t.cur[key] = c
		return Decision{Action: ActionInOrder}, nil
	}
	if seq == c.lastSeq {
		return Decision{Action: ActionDuplicate}, nil
	}
	behind := uint32(c.expected - seq)
	if behind <= reorderWindow {
		return Decision{Action: ActionReorder}, nil
	}
	if behind < resetBelow {
		c.expected = seq + count
		c.lastSeq = seq
		c.lastCount = count
		t.cur[key] = c
		return Decision{Action: ActionReset}, nil
	}
	gap := uint32(seq - c.expected)
	c.expected = seq + count
	c.lastSeq = seq
	c.lastCount = count
	t.cur[key] = c
	return Decision{Action: ActionGap, Gap: gap}, nil
}

func canon(key Key) Key {
	key.Exporter = key.Exporter.Unmap()
	return key
}

package obs

import (
	"errors"
	"maps"
	"sync"
	"testing"
)

func TestAddUnknown(t *testing.T) {
	c := NewCounters()
	before := c.Snapshot()
	err := c.Add("not_a_counter", 5)
	if !errors.Is(err, ErrUnknownCounter) {
		t.Fatalf("err = %v", err)
	}
	after := c.Snapshot()
	if !maps.Equal(before, after) {
		t.Fatal("snapshot changed")
	}
	for name, v := range after {
		if v != 0 {
			t.Fatalf("%s = %d", name, v)
		}
	}
	if err := c.Add(UDPReceivedPackets, 2); err != nil {
		t.Fatal(err)
	}
	if c.Snapshot()[UDPReceivedPackets] != 2 {
		t.Fatal("known add failed after unknown")
	}
}

func TestAddSnapshot(t *testing.T) {
	c := NewCounters()
	if err := c.Add(DecodedFlows, 3); err != nil {
		t.Fatal(err)
	}
	if err := c.Add(DecodedFlows, 4); err != nil {
		t.Fatal(err)
	}
	snap := c.Snapshot()
	if snap[DecodedFlows] != 7 {
		t.Fatalf("delta = %d", snap[DecodedFlows])
	}
	if snap[UDPReceivedPackets] != 0 {
		t.Fatalf("untouched = %d", snap[UDPReceivedPackets])
	}
	want := []Name{
		UDPReceivedPackets,
		UDPReceivedBytes,
		DecodedPackets,
		DecodedFlows,
		DroppedQueue,
		DroppedEnrichQueue,
		DroppedWriterQueue,
		DroppedTemplate,
		DroppedDisk,
		Malformed,
		MissingTemplate,
		TemplatesWithdrawn,
		WithdrawUnknown,
		TemplateRedefined,
		TemplateIdleExpired,
		TemplateEvicted,
		ReservedSet,
		CountDisagrees,
		PaddingNonzero,
		SequenceGapV5Flows,
		SequenceGapV9Packets,
		SequenceGapIPFIXRecords,
		SequenceReorder,
		SequenceDuplicate,
		SequenceReset,
		SequenceUnresolved,
		NonFlowRecords,
		TimestampSkew,
		TimestampSuspect,
		TimestampExportFallback,
		ClockClamped,
		EnrichGeoIPNotConfigured,
		EnrichGeoIPNoData,
		EnrichGeoIPError,
		EnrichGeoIPValue,
		EnrichGeoIPSkipped,
		EnrichASNNotConfigured,
		EnrichASNNoData,
		EnrichASNError,
		EnrichASNValue,
		EnrichASNSkipped,
		EnrichReputationNotConfigured,
		EnrichReputationNoData,
		EnrichReputationError,
		EnrichReputationValue,
		EnrichReputationSkipped,
		SQLiteWriteFailures,
		SQLiteRowsWritten,
	}
	if len(snap) != len(want) {
		t.Fatalf("names: got %d want %d", len(snap), len(want))
	}
	for _, name := range want {
		v, ok := snap[name]
		if !ok {
			t.Fatalf("missing %s", name)
		}
		if name != DecodedFlows && v != 0 {
			t.Fatalf("%s = %d", name, v)
		}
	}
	snap[DecodedFlows] = 99
	if c.Snapshot()[DecodedFlows] != 7 {
		t.Fatal("caller mutated the snapshot")
	}
}

func TestConcurrentAddSnapshot(t *testing.T) {
	c := NewCounters()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				if err := c.Add(DecodedPackets, 1); err != nil {
					t.Error(err)
				}
				_ = c.Snapshot()
			}
		}()
	}
	wg.Wait()
	if got := c.Snapshot()[DecodedPackets]; got != 800 {
		t.Fatalf("got %d", got)
	}
}

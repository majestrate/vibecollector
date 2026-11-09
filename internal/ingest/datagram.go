// Package ingest carries one UDP payload and the arrival facts recorded with it.
package ingest

import (
	"net/netip"
	"time"
)

// Datagram is one UDP payload plus the arrival facts the reader recorded.
// Payload is a copy the reader owns until the send; the decode worker must
// not retain it after Accept returns unless it copies again (the hold buffer does).
// Src is the source IP with the port discarded and IPv4-mapped form unmapped.
// The port is not a field. ReceivedAt is time.Now().UTC() taken once in the
// read loop. Later stages do not take another receive timestamp.
type Datagram struct {
	Payload    []byte
	Src        netip.Addr
	ReceivedAt time.Time
}

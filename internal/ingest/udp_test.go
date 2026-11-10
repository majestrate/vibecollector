package ingest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"vibecollector/internal/config"
	"vibecollector/internal/obs"
)

func TestNewReaderRejects(t *testing.T) {
	counters := obs.NewCounters()
	if _, err := NewReader(config.UDP{Listen: "127.0.0.1:2055"}, nil); !errors.Is(err, ErrBadConfig) {
		t.Fatal(err)
	}
	for _, listen := range []string{"", "127.0.0.1", "not-a-port", "127.0.0.1:http", "127.0.0.1:99999"} {
		if _, err := NewReader(config.UDP{Listen: listen}, counters); !errors.Is(err, ErrBadConfig) {
			t.Fatalf("%q: %v", listen, err)
		}
	}
	r, err := NewReader(config.UDP{Listen: "127.0.0.1:2055"}, counters)
	if err != nil {
		t.Fatal(err)
	}
	if r.conn != nil {
		t.Fatal("NewReader bound a socket")
	}
}

func TestNewReaderDoesNotBind(t *testing.T) {
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.LocalAddr().(*net.UDPAddr).Port
	if _, err := NewReader(config.UDP{Listen: fmt.Sprintf("127.0.0.1:%d", port)}, obs.NewCounters()); err != nil {
		t.Fatal(err)
	}
}

func TestRunBindError(t *testing.T) {
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.LocalAddr().(*net.UDPAddr).Port
	r, err := NewReader(config.UDP{
		Listen:          fmt.Sprintf("127.0.0.1:%d", port),
		ReadBufferBytes: 8192,
	}, obs.NewCounters())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = r.Run(ctx, make(chan Datagram, 1))
	if err == nil {
		t.Fatal("expected bind error")
	}
}

func TestRunDeliversOnLocalSocket(t *testing.T) {
	counters := obs.NewCounters()
	r, err := NewReader(config.UDP{Listen: "127.0.0.1:0", ReadBufferBytes: 8192}, counters)
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan Datagram, 4)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- r.Run(ctx, out) }()
	conn := waitConn(t, r)
	if runtime.GOOS == "linux" {
		actual, err := soRCVBUF(conn)
		if err != nil {
			t.Fatal(err)
		}
		if actual != 8192*2 {
			t.Fatalf("SO_RCVBUF %d", actual)
		}
	}
	client := dial(t, conn.LocalAddr().(*net.UDPAddr))
	defer client.Close()

	before := time.Now().Add(-time.Second)
	payloads := [][]byte{[]byte("alpha"), []byte("bravo-payload")}
	for _, p := range payloads {
		if _, err := client.Write(p); err != nil {
			t.Fatal(err)
		}
	}
	got := make([]Datagram, 0, 2)
	deadline := time.After(2 * time.Second)
	for len(got) < 2 {
		select {
		case d := <-out:
			got = append(got, d)
		case <-deadline:
			t.Fatal("timeout", len(got))
		}
	}
	for i, d := range got {
		if !bytes.Equal(d.Payload, payloads[i]) {
			t.Fatalf("payload %d %q", i, d.Payload)
		}
		if d.Src != netip.MustParseAddr("127.0.0.1") {
			t.Fatal(d.Src)
		}
		if d.ReceivedAt.Location() != time.UTC || d.ReceivedAt.Before(before) || d.ReceivedAt.After(time.Now().Add(time.Second)) {
			t.Fatal(d.ReceivedAt)
		}
	}
	if bytes.Equal(got[0].Payload, got[1].Payload) {
		t.Fatal("payloads alias")
	}
	snap := counters.Snapshot()
	if snap[obs.UDPReceivedPackets] != 2 || snap[obs.UDPReceivedBytes] != uint64(len(payloads[0])+len(payloads[1])) || snap[obs.DroppedQueue] != 0 {
		t.Fatal(snap[obs.UDPReceivedPackets], snap[obs.UDPReceivedBytes], snap[obs.DroppedQueue])
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return")
	}
}

func TestFullQueueDoesNotBlockReader(t *testing.T) {
	counters := obs.NewCounters()
	r, err := NewReader(config.UDP{Listen: "127.0.0.1:0", ReadBufferBytes: 8192}, counters)
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan Datagram, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- r.Run(ctx, out) }()
	conn := waitConn(t, r)
	client := dial(t, conn.LocalAddr().(*net.UDPAddr))
	defer client.Close()

	// 40 KiB against an 8 KiB request (16 KiB on Linux). A reader blocked on
	// the queue lets the kernel buffer fill and Write hits the deadline.
	// The kernel may still drop a datagram; that is not dropped_queue.
	payload := bytes.Repeat([]byte("x"), 1000)
	const n = 40
	for i := 0; i < n; i++ {
		_ = client.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("send %d: %v dropped %d", i, err, counters.Snapshot()[obs.DroppedQueue])
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for counters.Snapshot()[obs.DroppedQueue] == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader blocked in Run")
	}
	snap := counters.Snapshot()
	if snap[obs.DroppedQueue] == 0 || snap[obs.UDPReceivedPackets] <= uint64(cap(out)) {
		t.Fatalf("dropped_queue %d received %d queued %d", snap[obs.DroppedQueue], snap[obs.UDPReceivedPackets], len(out))
	}
	if len(out) > cap(out) {
		t.Fatal(len(out))
	}
}

func TestUDPSrcUnmaps(t *testing.T) {
	mapped := &net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.10"), Port: 9996}
	if got := udpSrc(mapped); got != netip.MustParseAddr("192.0.2.10") {
		t.Fatal(got)
	}
	v4 := &net.UDPAddr{IP: net.ParseIP("192.0.2.10").To4(), Port: 2055}
	if got := udpSrc(v4); got != netip.MustParseAddr("192.0.2.10") {
		t.Fatal(got)
	}
	if got := udpSrc(nil); got.IsValid() {
		t.Fatal(got)
	}
	zoned := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 2055, Zone: "eth0"}
	got := udpSrc(zoned)
	if got != netip.MustParseAddr("fe80::1%eth0") || got.Zone() != "eth0" {
		t.Fatal(got)
	}
}

func waitConn(t *testing.T, r *Reader) *net.UDPConn {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		c := r.conn
		r.mu.Unlock()
		if c != nil {
			return c
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("not listening")
	return nil
}

func dial(t *testing.T, addr *net.UDPAddr) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}, addr)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

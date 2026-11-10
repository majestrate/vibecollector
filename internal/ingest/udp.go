package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"vibecollector/internal/config"
	"vibecollector/internal/obs"
)

const (
	// A UDP header is 8 bytes, so the largest payload is 65527.
	// 65535 is enough for that and for one IPFIX message (RFC 7011 §10).
	udpBufCap     = 65535
	udpPayloadMax = 65527
)

// ErrBadConfig means counters is nil or Listen is not host:port.
// NewReader returns it and does not listen. errors.Is reports this sentinel.
var ErrBadConfig = errors.New("invalid configuration")

var payloadPool = sync.Pool{
	New: func() any {
		return make([]byte, udpBufCap)
	},
}

// Reader binds the UDP socket and sends Datagram values on out.
// NewReader does not bind. Run binds.
type Reader struct {
	cfg      config.UDP
	counters *obs.Counters

	mu   sync.Mutex
	conn *net.UDPConn
}

// NewReader stores cfg and counters. It does not listen.
// counters receives dropped_queue and the udp_received counters.
// A nil counters returns ErrBadConfig.
// cfg.Listen must be host:port, with a numeric port. Anything else,
// including a missing port, returns ErrBadConfig.
// cfg.ReadBufferBytes is the requested SO_RCVBUF. Run applies it.
func NewReader(cfg config.UDP, counters *obs.Counters) (*Reader, error) {
	if counters == nil {
		return nil, fmt.Errorf("%w: nil counters", ErrBadConfig)
	}
	if err := checkListen(cfg.Listen); err != nil {
		return nil, err
	}
	return &Reader{cfg: cfg, counters: counters}, nil
}

// Run listens on cfg.Listen, sets SO_RCVBUF to cfg.ReadBufferBytes, and reads
// until ctx is cancelled. out is the datagram queue main created, capacity
// cfg.DatagramQueue. Each successful read sends one Datagram.
// A full out increments dropped_queue, returns the buffer to the pool, and
// does not block. A timeout error on the socket continues the loop.
// A fatal read error is returned. Cancelling ctx closes the socket and
// returns nil after the in-flight ReadFromUDP unwinds.
// Run does not decode, enrich, or touch SQLite. It logs the requested
// SO_RCVBUF and, on Linux, the actual getsockopt value. It does not use
// SO_RCVBUFFORCE. There is no exporter allow-list.
// SetReadBuffer's error is returned and the loop does not start.
func (r *Reader) Run(ctx context.Context, out chan<- Datagram) error {
	addr, err := net.ResolveUDPAddr("udp", r.cfg.Listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.SetReadBuffer(r.cfg.ReadBufferBytes); err != nil {
		return err
	}
	logRCVBUF(conn, r.cfg.ReadBufferBytes)
	slog.Info("udp listen", "addr", conn.LocalAddr().String())

	r.mu.Lock()
	r.conn = conn
	r.mu.Unlock()

	// Close unblocks ReadFromUDP. The read loop must not be the thing that
	// waits out a cancellation.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()

	for {
		buf := payloadPool.Get().([]byte)
		if cap(buf) < udpBufCap {
			buf = make([]byte, udpBufCap)
		}
		n, src, err := conn.ReadFromUDP(buf[:udpPayloadMax])
		if err != nil {
			payloadPool.Put(buf[:cap(buf)])
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		// One clock read for this datagram. Later stages reuse ReceivedAt.
		receivedAt := time.Now().UTC()
		payload := make([]byte, n)
		copy(payload, buf[:n])
		payloadPool.Put(buf[:cap(buf)])

		_ = r.counters.Add(obs.UDPReceivedPackets, 1)
		_ = r.counters.Add(obs.UDPReceivedBytes, uint64(n))

		d := Datagram{Payload: payload, Src: udpSrc(src), ReceivedAt: receivedAt}
		select {
		case out <- d:
		default:
			// The pool buffer is already returned. Do not decode here.
			_ = r.counters.Add(obs.DroppedQueue, 1)
		}
	}
}

func checkListen(listen string) error {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("%w: udp.listen", ErrBadConfig)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("%w: udp.listen", ErrBadConfig)
	}
	return nil
}

func udpSrc(addr *net.UDPAddr) netip.Addr {
	if addr == nil {
		return netip.Addr{}
	}
	// AddrPort keeps the IPv6 zone. AddrFromSlice would drop it, and two
	// link-local exporters on different interfaces would share one key.
	return addr.AddrPort().Addr().Unmap()
}

func logRCVBUF(conn *net.UDPConn, requested int) {
	if runtime.GOOS != "linux" {
		slog.Info("udp SO_RCVBUF", "requested", requested)
		return
	}
	actual, err := soRCVBUF(conn)
	if err != nil {
		slog.Warn("udp SO_RCVBUF", "requested", requested, "err", err)
		return
	}
	// Linux reports twice the requested size when the set was not clamped.
	if actual < requested*2 {
		slog.Warn("udp SO_RCVBUF shortfall; raise net.core.rmem_max", "requested", requested, "actual", actual)
		return
	}
	slog.Info("udp SO_RCVBUF", "requested", requested, "actual", actual)
}

func soRCVBUF(conn *net.UDPConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		v    int
		gerr error
	)
	err = raw.Control(func(fd uintptr) {
		v, gerr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	})
	if err != nil {
		return 0, err
	}
	return v, gerr
}

package decode_test

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vibecollector/internal/decode"
	_ "vibecollector/internal/decode/ipfix"
	_ "vibecollector/internal/decode/v5"
	_ "vibecollector/internal/decode/v9"
	"vibecollector/internal/ingest"
	"vibecollector/internal/obs"
	"vibecollector/internal/sampling"
	"vibecollector/internal/sequence"
	"vibecollector/internal/template"
)

func FuzzDispatch(f *testing.F) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		f.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		b, err := os.ReadFile(filepath.Join("testdata", e.Name()))
		if err != nil {
			f.Fatal(err)
		}
		for _, p := range splitGolden(b) {
			f.Add(p)
			n++
		}
	}
	if n == 0 {
		f.Fatal("no golden datagrams")
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		templates, err := template.NewCache(128)
		if err != nil {
			t.Fatal(err)
		}
		d := ingest.Datagram{
			Payload:    payload,
			Src:        netip.MustParseAddr("192.0.2.1"),
			ReceivedAt: time.Unix(1_700_000_000, 0).UTC(),
		}
		decode.Dispatch(d, templates, sampling.NewCache(), sequence.NewTable(), obs.NewCounters(), false, 2*time.Hour, 5*time.Second)
	})
}

func splitGolden(b []byte) [][]byte {
	if len(b) < 2 {
		return [][]byte{append([]byte(nil), b...)}
	}
	switch binary.BigEndian.Uint16(b[:2]) {
	case 5:
		return splitV5(b)
	case 9, 10:
		return [][]byte{append([]byte(nil), b...)}
	default:
		return splitFrames(b)
	}
}

func splitV5(b []byte) [][]byte {
	var out [][]byte
	rest := b
	for len(rest) >= 24 && binary.BigEndian.Uint16(rest[:2]) == 5 {
		count := int(binary.BigEndian.Uint16(rest[2:4]))
		if count < 1 || count > 30 {
			break
		}
		n := 24 + count*48
		if len(rest) < n {
			break
		}
		if len(rest) == n || len(rest)-n < 24 {
			out = append(out, append([]byte(nil), rest...))
			return out
		}
		out = append(out, append([]byte(nil), rest[:n]...))
		rest = rest[n:]
	}
	if len(out) == 0 {
		return [][]byte{append([]byte(nil), b...)}
	}
	return out
}

func splitFrames(b []byte) [][]byte {
	var out [][]byte
	rest := b
	for len(rest) >= 4 {
		n := int(binary.BigEndian.Uint32(rest[:4]))
		if n <= 0 || len(rest) < 4+n {
			return [][]byte{append([]byte(nil), b...)}
		}
		out = append(out, append([]byte(nil), rest[4:4+n]...))
		rest = rest[4+n:]
	}
	if len(rest) != 0 || len(out) == 0 {
		return [][]byte{append([]byte(nil), b...)}
	}
	return out
}

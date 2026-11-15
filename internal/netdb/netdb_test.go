package netdb

import (
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestProtocols(t *testing.T) {
	db := loadFixture(t, `
# comment
ip 0 IP
hopopt 0 HOPOPT
icmp 1 ICMP
tcp 6 TCP
not-a-number x
lonely
`, `
http 80/tcp www www-http
http 80/udp
echo 7/tcp
echo 7/udp
discard 9/tcp sink null
big 65536/tcp
badport no-slash
zero 0/tcp
`)
	ip, err := db.ProtocolByNumber(0)
	if err != nil || ip.Name != "ip" || len(ip.Aliases) != 1 || ip.Aliases[0] != "IP" {
		t.Fatal(ip, err)
	}
	hop, err := db.ProtocolByName("hopopt")
	if err != nil || hop.Number != 0 || hop.Name != "hopopt" {
		t.Fatal(hop, err)
	}
	tcp, err := db.ProtocolByName("TCP")
	if err != nil || tcp.Number != 6 || tcp.Name != "tcp" {
		t.Fatal(tcp, err)
	}
	if _, err = db.ProtocolByName("Tcp"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err = db.ProtocolByName(""); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	tcp.Aliases[0] = "changed"
	again, err := db.ProtocolByName("tcp")
	if err != nil || again.Aliases[0] != "TCP" {
		t.Fatal(again, err)
	}

	http, err := db.ServiceByName("www", "tcp")
	if err != nil || http.Name != "http" || http.Port != 80 || http.Protocol != "tcp" {
		t.Fatal(http, err)
	}
	if http.Aliases[0] != "www" || http.Aliases[1] != "www-http" {
		t.Fatal(http.Aliases)
	}
	udp, err := db.ServiceByPort(80, "udp")
	if err != nil || udp.Protocol != "udp" || len(udp.Aliases) != 0 {
		t.Fatal(udp, err)
	}
	any, err := db.ServiceByPort(80, "")
	if err != nil || any.Protocol != "tcp" {
		t.Fatal(any, err)
	}
	sink, err := db.ServiceByName("sink", "")
	if err != nil || sink.Name != "discard" || sink.Port != 9 {
		t.Fatal(sink, err)
	}
	zero, err := db.ServiceByPort(0, "tcp")
	if err != nil || zero.Name != "zero" {
		t.Fatal(zero, err)
	}
	if _, err = db.ServiceByPort(65536, "tcp"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err = db.ServiceByName("http", "TCP"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err = db.ServiceByName("", "tcp"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	var nilDB *DB
	if _, err = nilDB.ProtocolByNumber(6); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(fstest.MapFS{}, "protocols", "services")
	if err == nil {
		t.Fatal("missing file")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatal("file errors are not ErrNotFound")
	}
	if _, err = Load(nil, "protocols", "services"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestSystemTables(t *testing.T) {
	db, err := LoadSystem()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	tcp, err := db.ProtocolByName("tcp")
	if err != nil || tcp.Number != 6 {
		t.Fatal(tcp, err)
	}
	icmp, err := db.ProtocolByNumber(1)
	if err != nil || icmp.Name == "" {
		t.Fatal(icmp, err)
	}
	http, err := db.ServiceByName("http", "tcp")
	if err != nil || http.Port != 80 {
		t.Fatal(http, err)
	}
	byPort, err := db.ServiceByPort(53, "udp")
	if err != nil || byPort.Name == "" {
		t.Fatal(byPort, err)
	}
}

func loadFixture(t *testing.T, protocols, services string) *DB {
	t.Helper()
	fsys := fstest.MapFS{
		"protocols": {Data: []byte(protocols)},
		"services":  {Data: []byte(services)},
	}
	db, err := Load(fsys, "protocols", "services")
	if err != nil {
		t.Fatal(err)
	}
	return db
}

package store

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/majestrate/vibecollector/internal/netdb"
)

func TestClientNetDB(t *testing.T) {
	db := openClientDB(t)
	ctx := context.Background()
	putNetClient(t, db, "client-a")
	putNetClient(t, db, "client-b")

	proto := netdb.Protocol{Name: "vc-extra", Number: 254, Aliases: []string{"VX"}}
	if err := db.CreateClientProtocol(ctx, "client-a", proto); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateClientProtocol(ctx, "client-a", proto); !errors.Is(err, ErrNetExists) {
		t.Fatal(err)
	}
	if err := db.CreateClientProtocol(ctx, "client-b", proto); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetClientProtocol(ctx, "client-a", "vc-extra")
	if err != nil || got.Number != 254 || len(got.Aliases) != 1 || got.Aliases[0] != "VX" {
		t.Fatal(got, err)
	}
	got.Aliases[0] = "mutated"
	got, err = db.GetClientProtocol(ctx, "client-a", "vc-extra")
	if err != nil || got.Aliases[0] != "VX" {
		t.Fatal(got, err)
	}
	if _, err := db.GetClientProtocol(ctx, "client-b", "nope"); !errors.Is(err, ErrNetAbsent) {
		t.Fatal(err)
	}

	proto.Number = 253
	proto.Aliases = []string{"V2"}
	if err := db.UpdateClientProtocol(ctx, "client-a", proto); err != nil {
		t.Fatal(err)
	}
	got, err = db.GetClientProtocol(ctx, "client-a", "vc-extra")
	if err != nil || got.Number != 253 || len(got.Aliases) != 1 || got.Aliases[0] != "V2" {
		t.Fatal(got, err)
	}
	other, err := db.GetClientProtocol(ctx, "client-b", "vc-extra")
	if err != nil || other.Number != 254 {
		t.Fatal(other, err)
	}
	if err := db.UpdateClientProtocol(ctx, "client-a", netdb.Protocol{Name: "missing", Number: 1}); !errors.Is(err, ErrNetAbsent) {
		t.Fatal(err)
	}

	second := netdb.Protocol{Name: "aaa", Number: 0}
	if err := db.CreateClientProtocol(ctx, "client-a", second); err != nil {
		t.Fatal(err)
	}
	listed, err := db.ListClientProtocols(ctx, "client-a")
	if err != nil || len(listed) != 2 || listed[0].Name != "aaa" || listed[1].Name != "vc-extra" {
		t.Fatal(listed, err)
	}
	bList, err := db.ListClientProtocols(ctx, "client-b")
	if err != nil || len(bList) != 1 || bList[0].Name != "vc-extra" || bList[0].Number != 254 {
		t.Fatal(bList, err)
	}
	none, err := db.ListClientProtocols(ctx, "client-c")
	if err != nil || len(none) != 0 {
		t.Fatal(none, err)
	}

	svc := netdb.Service{Name: "vc-extra", Port: 59999, Protocol: "udp", Aliases: []string{"vc-echo"}}
	if err := db.CreateClientService(ctx, "client-a", svc); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateClientService(ctx, "client-a", svc); !errors.Is(err, ErrNetExists) {
		t.Fatal(err)
	}
	tcpSvc := netdb.Service{Name: "vc-extra", Port: 59998, Protocol: "tcp"}
	if err := db.CreateClientService(ctx, "client-a", tcpSvc); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateClientService(ctx, "client-b", svc); err != nil {
		t.Fatal(err)
	}
	gotSvc, err := db.GetClientService(ctx, "client-a", "vc-extra", "udp")
	if err != nil || gotSvc.Port != 59999 || len(gotSvc.Aliases) != 1 || gotSvc.Aliases[0] != "vc-echo" {
		t.Fatal(gotSvc, err)
	}
	svc.Port = 59997
	svc.Aliases = nil
	if err := db.UpdateClientService(ctx, "client-a", svc); err != nil {
		t.Fatal(err)
	}
	gotSvc, err = db.GetClientService(ctx, "client-a", "vc-extra", "udp")
	if err != nil || gotSvc.Port != 59997 || len(gotSvc.Aliases) != 0 {
		t.Fatal(gotSvc, err)
	}
	if _, err := db.GetClientService(ctx, "client-a", "vc-extra", "sctp"); !errors.Is(err, ErrNetAbsent) {
		t.Fatal(err)
	}
	svcs, err := db.ListClientServices(ctx, "client-a")
	if err != nil || len(svcs) != 2 || svcs[0].Protocol != "tcp" || svcs[1].Protocol != "udp" {
		t.Fatal(svcs, err)
	}
	if err := db.DeleteClientService(ctx, "client-a", "vc-extra", "tcp"); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteClientService(ctx, "client-a", "vc-extra", "tcp"); !errors.Is(err, ErrNetAbsent) {
		t.Fatal(err)
	}
	svcs, err = db.ListClientServices(ctx, "client-a")
	if err != nil || len(svcs) != 1 || svcs[0].Protocol != "udp" {
		t.Fatal(svcs, err)
	}
	bSvcs, err := db.ListClientServices(ctx, "client-b")
	if err != nil || len(bSvcs) != 1 || bSvcs[0].Port != 59999 {
		t.Fatal(bSvcs, err)
	}

	if err := db.DeleteClientProtocol(ctx, "client-a", "aaa"); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteClientProtocol(ctx, "client-a", "aaa"); !errors.Is(err, ErrNetAbsent) {
		t.Fatal(err)
	}
	if _, err := db.GetClientProtocol(ctx, "client-b", "vc-extra"); err != nil {
		t.Fatal(err)
	}

	removed, err := db.DeleteOAuthClient(ctx, "client-a")
	if err != nil || !removed {
		t.Fatal(removed, err)
	}
	if _, err := db.GetClientProtocol(ctx, "client-a", "vc-extra"); !errors.Is(err, ErrNetAbsent) {
		t.Fatal(err)
	}
	if _, err := db.GetClientService(ctx, "client-a", "vc-extra", "udp"); !errors.Is(err, ErrNetAbsent) {
		t.Fatal(err)
	}
	if _, err := db.GetClientProtocol(ctx, "client-b", "vc-extra"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetClientService(ctx, "client-b", "vc-extra", "udp"); err != nil {
		t.Fatal(err)
	}

	assertNetColumns(t, db, "client_protocol", "client_id", "name", "number", "aliases")
	assertNetColumns(t, db, "client_service", "client_id", "name", "port", "protocol", "aliases")
}

func TestClientNetValidation(t *testing.T) {
	db := openClientDB(t)
	ctx := context.Background()
	putNetClient(t, db, "client-a")

	if err := db.CreateClientProtocol(ctx, "missing", netdb.Protocol{Name: "vc-extra", Number: 1}); !errors.Is(err, ErrBadClient) {
		t.Fatal(err)
	}
	if err := db.CreateClientService(ctx, "missing", netdb.Service{Name: "vc-extra", Port: 1, Protocol: "udp"}); !errors.Is(err, ErrBadClient) {
		t.Fatal(err)
	}

	badNames := []string{
		"", ".", "..", "../etc/passwd", "/etc/protocols", "etc/protocols", `a\b`, "a b", "a#b", "a:b",
		"a\x00b", "a\nb", "a\tb", strings.Repeat("a", 65),
	}
	for _, name := range badNames {
		err := db.CreateClientProtocol(ctx, "client-a", netdb.Protocol{Name: name, Number: 1})
		if !errors.Is(err, ErrNetEntry) {
			t.Fatalf("name %q err %v", name, err)
		}
		err = db.CreateClientService(ctx, "client-a", netdb.Service{Name: "ok", Port: 1, Protocol: name})
		if !errors.Is(err, ErrNetEntry) {
			t.Fatalf("protocol %q err %v", name, err)
		}
		listed, listErr := db.ListClientProtocols(ctx, "client-a")
		if listErr != nil || len(listed) != 0 {
			t.Fatal(listed, listErr)
		}
	}
	for _, aliases := range [][]string{{"vc-extra"}, {"a", "a"}, {"../etc/passwd"}, {"."}, {".."}} {
		err := db.CreateClientProtocol(ctx, "client-a", netdb.Protocol{Name: "vc-extra", Number: 1, Aliases: aliases})
		if !errors.Is(err, ErrNetEntry) {
			t.Fatalf("aliases %q err %v", aliases, err)
		}
	}
	for _, number := range []int{-1, 256} {
		err := db.CreateClientProtocol(ctx, "client-a", netdb.Protocol{Name: "vc-extra", Number: number})
		if !errors.Is(err, ErrNetEntry) {
			t.Fatalf("number %d err %v", number, err)
		}
	}
	for _, port := range []int{-1, 65536} {
		err := db.CreateClientService(ctx, "client-a", netdb.Service{Name: "vc-extra", Port: port, Protocol: "udp"})
		if !errors.Is(err, ErrNetEntry) {
			t.Fatalf("port %d err %v", port, err)
		}
	}
	ok := netdb.Protocol{Name: "A.B_C+D", Number: 0, Aliases: []string{strings.Repeat("b", 64)}}
	if err := db.CreateClientProtocol(ctx, "client-a", ok); err != nil {
		t.Fatal(err)
	}
	hyphen := netdb.Service{Name: "a-b", Port: 0, Protocol: "udp"}
	if err := db.CreateClientService(ctx, "client-a", hyphen); err != nil {
		t.Fatal(err)
	}

	pathInserts := []string{
		`INSERT INTO client_protocol (client_id, name, number, aliases) VALUES ('client-a', '../etc/passwd', 250, '[]')`,
		`INSERT INTO client_protocol (client_id, name, number, aliases) VALUES ('client-a', '/etc/protocols', 250, '[]')`,
		`INSERT INTO client_protocol (client_id, name, number, aliases) VALUES ('client-a', 'a/b', 250, '[]')`,
		`INSERT INTO client_protocol (client_id, name, number, aliases) VALUES ('client-a', '.', 250, '[]')`,
		`INSERT INTO client_protocol (client_id, name, number, aliases) VALUES ('client-a', '..', 250, '[]')`,
		`INSERT INTO client_protocol (client_id, name, number, aliases) VALUES ('client-a', 'wide', 256, '[]')`,
		`INSERT INTO client_protocol (client_id, name, number, aliases) VALUES ('client-a', 'slash-alias', 250, '["/etc/passwd"]')`,
		`INSERT INTO client_service (client_id, name, port, protocol, aliases) VALUES ('client-a', 'vc', 1, '../tcp', '[]')`,
		`INSERT INTO client_service (client_id, name, port, protocol, aliases) VALUES ('client-a', 'vc', 1, 'tcp', '["a\\b"]')`,
	}
	for _, query := range pathInserts {
		if _, err := db.pool.Exec(query); err == nil {
			t.Fatal("stored a rejected row", query)
		}
	}
	var n int
	if err := db.pool.QueryRow(`SELECT count(*) FROM client_protocol WHERE name LIKE '%/%' OR aliases LIKE '%/%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal(n)
	}
}

func TestClientNetNilDB(t *testing.T) {
	var db *DB
	ctx := context.Background()
	p := netdb.Protocol{Name: "vc-extra", Number: 1}
	svc := netdb.Service{Name: "vc-extra", Port: 1, Protocol: "udp"}
	if err := db.CreateClientProtocol(ctx, "a", p); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
	if err := db.UpdateClientProtocol(ctx, "a", p); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
	if err := db.DeleteClientProtocol(ctx, "a", "vc-extra"); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
	if _, err := db.GetClientProtocol(ctx, "a", "vc-extra"); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
	if _, err := db.ListClientProtocols(ctx, "a"); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
	if err := db.CreateClientService(ctx, "a", svc); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
	if err := db.UpdateClientService(ctx, "a", svc); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
	if err := db.DeleteClientService(ctx, "a", "vc-extra", "udp"); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
	if _, err := db.GetClientService(ctx, "a", "vc-extra", "udp"); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
	if _, err := db.ListClientServices(ctx, "a"); !errors.Is(err, ErrNilDep) {
		t.Fatal(err)
	}
}

func TestNetFSOverlay(t *testing.T) {
	db := openClientDB(t)
	ctx := context.Background()
	putNetClient(t, db, "client-a")
	putNetClient(t, db, "client-b")
	protocols := []byte("ip\t0\tIP\ntcp\t6\tTCP\nhopopt\t0\tHOPOPT\n")
	services := []byte("echo\t7/tcp\necho\t7/udp\nhttp\t80/tcp\twww\nalpha\t10/udp\n")
	system := fstest.MapFS{
		"etc/protocols": &fstest.MapFile{Data: protocols},
		"etc/services":  &fstest.MapFile{Data: services},
		"etc/passwd":    &fstest.MapFile{Data: []byte("root:x:0:0\n")},
	}
	if err := db.CreateClientProtocol(ctx, "client-a", netdb.Protocol{Name: "vc-extra", Number: 0, Aliases: []string{"VX"}}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateClientProtocol(ctx, "client-a", netdb.Protocol{Name: "tcp", Number: 99, Aliases: []string{"NOTTCP"}}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateClientProtocol(ctx, "client-b", netdb.Protocol{Name: "only-b", Number: 250}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateClientService(ctx, "client-a", netdb.Service{Name: "vc-extra", Port: 11, Protocol: "udp", Aliases: []string{"vc-echo"}}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateClientService(ctx, "client-a", netdb.Service{Name: "aa", Port: 11, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateClientService(ctx, "client-a", netdb.Service{Name: "http", Port: 1, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateClientService(ctx, "client-b", netdb.Service{Name: "only-b", Port: 12, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}

	fsys := NewNetFS(nil, db, "client-a", system)
	body, err := fs.ReadFile(fsys, netdb.ProtocolsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(body, protocols) {
		t.Fatalf("system protocols not first:\n%s", body)
	}
	if !bytes.Contains(body, []byte("vc-extra\t0\tVX\n")) || !bytes.Contains(body, []byte("tcp\t99\tNOTTCP\n")) {
		t.Fatalf("suffix missing:\n%s", body)
	}
	if bytes.Contains(body, []byte("only-b")) || bytes.Contains(body, []byte("etc/passwd")) || bytes.Contains(body, []byte("/etc")) {
		t.Fatalf("unexpected path or other client:\n%s", body)
	}
	svcBody, err := fs.ReadFile(fsys, netdb.ServicesPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(svcBody, services) {
		t.Fatalf("system services not first:\n%s", svcBody)
	}
	if !bytes.Contains(svcBody, []byte("aa\t11/tcp\n")) || !bytes.Contains(svcBody, []byte("vc-extra\t11/udp\tvc-echo\n")) {
		t.Fatalf("service suffix:\n%s", svcBody)
	}

	for _, name := range []string{"etc/passwd", "etc/shadow", "etc/protocols/extra", "protocols"} {
		_, err := fsys.Open(name)
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("open %s: %v", name, err)
		}
	}
	for _, name := range []string{"/etc/protocols", "../etc/protocols", "etc/../protocols"} {
		_, err := fsys.Open(name)
		if !errors.Is(err, fs.ErrInvalid) {
			t.Fatalf("open %s: %v", name, err)
		}
	}

	loaded, err := netdb.Load(fsys, netdb.ProtocolsPath, netdb.ServicesPath)
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := loaded.ProtocolByName("tcp")
	if err != nil || tcp.Number != 6 || tcp.Name != "tcp" {
		t.Fatal(tcp, err)
	}
	if _, err := loaded.ProtocolByName("NOTTCP"); !errors.Is(err, netdb.ErrNotFound) {
		t.Fatal(err)
	}
	extra, err := loaded.ProtocolByName("VX")
	if err != nil || extra.Name != "vc-extra" || extra.Number != 0 {
		t.Fatal(extra, err)
	}
	byNum, err := loaded.ProtocolByNumber(0)
	if err != nil || byNum.Name != "ip" {
		t.Fatal(byNum, err)
	}
	if _, err := loaded.ProtocolByNumber(99); !errors.Is(err, netdb.ErrNotFound) {
		t.Fatal(err)
	}
	http, err := loaded.ServiceByName("http", "tcp")
	if err != nil || http.Port != 80 {
		t.Fatal(http, err)
	}
	if _, err := loaded.ServiceByPort(1, "tcp"); !errors.Is(err, netdb.ErrNotFound) {
		t.Fatal(err)
	}
	own, err := loaded.ServiceByName("vc-extra", "udp")
	if err != nil || own.Port != 11 || len(own.Aliases) != 1 || own.Aliases[0] != "vc-echo" {
		t.Fatal(own, err)
	}
	earliest, err := loaded.ServiceByPort(11, "")
	if err != nil || earliest.Name != "aa" || earliest.Protocol != "tcp" {
		t.Fatal(earliest, err)
	}
	udp, err := loaded.ServiceByPort(11, "udp")
	if err != nil || udp.Name != "vc-extra" {
		t.Fatal(udp, err)
	}
	if _, err := loaded.ServiceByName("only-b", "tcp"); !errors.Is(err, netdb.ErrNotFound) {
		t.Fatal(err)
	}

	otherFS := NewNetFS(ctx, db, "client-b", system)
	otherDB, err := netdb.Load(otherFS, netdb.ProtocolsPath, netdb.ServicesPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherDB.ProtocolByName("vc-extra"); !errors.Is(err, netdb.ErrNotFound) {
		t.Fatal(err)
	}
	bProto, err := otherDB.ProtocolByName("only-b")
	if err != nil || bProto.Number != 250 {
		t.Fatal(bProto, err)
	}

	bare := fstest.MapFS{
		"etc/protocols": &fstest.MapFile{Data: []byte("tcp 6")},
		"etc/services":  &fstest.MapFile{Data: []byte("echo 7/tcp")},
	}
	plain, err := fs.ReadFile(NewNetFS(ctx, db, "client-a", bare), netdb.ProtocolsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(plain, []byte("tcp 6\n")) {
		t.Fatalf("newline not inserted: %q", plain)
	}
	empty, err := fs.ReadFile(NewNetFS(ctx, db, "nobody", system), netdb.ProtocolsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(empty, protocols) {
		t.Fatal("empty client changed the system file")
	}

	if _, err := db.pool.Exec(`INSERT INTO client_protocol (client_id, name, number, aliases) VALUES ('client-a', 'badalias', 251, '[".."]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := fsys.Open(netdb.ProtocolsPath); err == nil {
		t.Fatal("rendered a rejected alias")
	}
}

func TestNetFSInvalid(t *testing.T) {
	if _, err := NewNetFS(nil, nil, "a", nil).Open(netdb.ProtocolsPath); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
	db := openClientDB(t)
	if _, err := NewNetFS(context.Background(), db, "a", nil).Open(netdb.ServicesPath); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
}

func putNetClient(t *testing.T, db *DB, id string) {
	t.Helper()
	if _, err := db.PutOAuthClient(context.Background(), id, "secret-value"); err != nil {
		t.Fatal(err)
	}
}

func assertNetColumns(t *testing.T, db *DB, table string, want ...string) {
	t.Helper()
	rows, err := db.pool.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		got = append(got, name)
		if name == "path" || name == "file" || name == "filename" {
			t.Fatalf("%s has a path column %s", table, name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s columns %q", table, got)
	}
}

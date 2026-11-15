// Package netdb reads the local IP protocol and service tables.
// Load reads the two files from an fs.FS. LoadSystem reads them from the
// host root. The database is immutable after a successful load.
// Lookups do not write those files and do not call libc.
// A nil *DB returns ErrNotFound from every lookup.
package netdb

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"math"
	"os"
	"strconv"
	"strings"
)

// Paths inside a filesystem rooted at /.
const (
	ProtocolsPath = "etc/protocols"
	ServicesPath  = "etc/services"
)

// ErrNotFound is returned when the table has no matching entry.
// A missing or unreadable file is a different error from Load.
var ErrNotFound = errors.New("not found")

// Protocol is one protocols-file entry.
// Name is the official name. Aliases are the names that follow the number,
// in file order, and may be empty. Number is the decimal protocol number.
type Protocol struct {
	Name    string
	Aliases []string
	Number  int
}

// Service is one services-file entry.
// Name is the official name. Aliases are the names that follow port/protocol,
// in file order, and may be empty. Port is the port in host order, 0 through
// 65535. Protocol is the protocol token from the file, such as "tcp".
type Service struct {
	Name     string
	Aliases  []string
	Port     int
	Protocol string
}

// DB is a protocol table and a service table.
// Concurrent lookups are safe. The slices inside a returned value are copies.
type DB struct {
	protoName map[string]*Protocol
	protoNum  map[int]*Protocol
	svcName   map[nameKey]*Service
	svcPort   map[portKey]*Service
}

type nameKey struct {
	name  string
	proto string
}

type portKey struct {
	port  int
	proto string
}

// Load reads both tables from fsys.
// protocolsPath and servicesPath are slash-separated paths valid for fs.FS.
// They are not absolute OS paths. A nil fsys returns an error.
// A line that is blank, a comment, or not a valid entry is skipped.
// The first entry for a name or a number wins. A later protocol entry with
// the same number and a different name stays reachable by that name.
// The first service for a name-and-protocol pair, or a port-and-protocol
// pair, wins. An empty protocol on lookup matches the earliest entry in
// file order for that name or port.
// Load returns an error when either file cannot be read. It does not return
// ErrNotFound.
func Load(fsys fs.FS, protocolsPath, servicesPath string) (*DB, error) {
	if fsys == nil {
		return nil, errors.New("nil filesystem")
	}
	protoText, err := fs.ReadFile(fsys, protocolsPath)
	if err != nil {
		return nil, err
	}
	svcText, err := fs.ReadFile(fsys, servicesPath)
	if err != nil {
		return nil, err
	}
	db := &DB{
		protoName: make(map[string]*Protocol),
		protoNum:  make(map[int]*Protocol),
		svcName:   make(map[nameKey]*Service),
		svcPort:   make(map[portKey]*Service),
	}
	if err := parseProtocols(db, protoText); err != nil {
		return nil, err
	}
	if err := parseServices(db, svcText); err != nil {
		return nil, err
	}
	return db, nil
}

// LoadSystem reads ProtocolsPath and ServicesPath from the host root.
// It returns the same errors as Load.
func LoadSystem() (*DB, error) {
	return Load(os.DirFS("/"), ProtocolsPath, ServicesPath)
}

// ProtocolByName returns the entry for an official name or an alias.
// name is compared exactly, including case. An empty name is ErrNotFound.
// The result's Aliases slice is a copy. ProtocolByName returns ErrNotFound
// when the table has no such name.
func (db *DB) ProtocolByName(name string) (Protocol, error) {
	if db == nil || name == "" {
		return Protocol{}, ErrNotFound
	}
	p := db.protoName[name]
	if p == nil {
		return Protocol{}, ErrNotFound
	}
	return p.clone(), nil
}

// ProtocolByNumber returns the first entry with that number.
// number is the decimal protocol number from the file. A number that no
// entry uses is ErrNotFound. The result's Aliases slice is a copy.
func (db *DB) ProtocolByNumber(number int) (Protocol, error) {
	if db == nil {
		return Protocol{}, ErrNotFound
	}
	p := db.protoNum[number]
	if p == nil {
		return Protocol{}, ErrNotFound
	}
	return p.clone(), nil
}

// ServiceByName returns the entry for an official name or an alias.
// name is compared exactly. protocol is the protocol token, compared exactly;
// an empty protocol selects the earliest entry for that name.
// An empty name is ErrNotFound. The result's Aliases slice is a copy.
// ServiceByName returns ErrNotFound when no entry matches.
func (db *DB) ServiceByName(name, protocol string) (Service, error) {
	if db == nil || name == "" {
		return Service{}, ErrNotFound
	}
	s := db.svcName[nameKey{name: name, proto: protocol}]
	if s == nil {
		return Service{}, ErrNotFound
	}
	return s.clone(), nil
}

// ServiceByPort returns the entry for a port and protocol.
// port is in host order. protocol is compared exactly; an empty protocol
// selects the earliest entry for that port. A port outside 0 through 65535
// is ErrNotFound. The result's Aliases slice is a copy.
// ServiceByPort returns ErrNotFound when no entry matches.
func (db *DB) ServiceByPort(port int, protocol string) (Service, error) {
	if db == nil || port < 0 || port > 65535 {
		return Service{}, ErrNotFound
	}
	s := db.svcPort[portKey{port: port, proto: protocol}]
	if s == nil {
		return Service{}, ErrNotFound
	}
	return s.clone(), nil
}

func (p *Protocol) clone() Protocol {
	out := *p
	if len(p.Aliases) > 0 {
		out.Aliases = append([]string(nil), p.Aliases...)
	}
	return out
}

func (s *Service) clone() Service {
	out := *s
	if len(s.Aliases) > 0 {
		out.Aliases = append([]string(nil), s.Aliases...)
	}
	return out
}

func parseProtocols(db *DB, text []byte) error {
	return forEachLine(text, func(fields []string) {
		if len(fields) < 2 {
			return
		}
		number, ok := parseInt(fields[1])
		if !ok {
			return
		}
		if _, exists := db.protoName[fields[0]]; exists {
			return
		}
		p := &Protocol{
			Name:    fields[0],
			Aliases: append([]string(nil), fields[2:]...),
			Number:  number,
		}
		db.protoName[p.Name] = p
		if _, exists := db.protoNum[number]; !exists {
			db.protoNum[number] = p
		}
		for _, alias := range p.Aliases {
			if _, exists := db.protoName[alias]; !exists {
				db.protoName[alias] = p
			}
		}
	})
}

func parseServices(db *DB, text []byte) error {
	return forEachLine(text, func(fields []string) {
		if len(fields) < 2 {
			return
		}
		port, proto, ok := splitPort(fields[1])
		if !ok {
			return
		}
		key := nameKey{name: fields[0], proto: proto}
		if _, exists := db.svcName[key]; exists {
			return
		}
		s := &Service{
			Name:     fields[0],
			Aliases:  append([]string(nil), fields[2:]...),
			Port:     port,
			Protocol: proto,
		}
		db.svcName[key] = s
		if _, exists := db.svcName[nameKey{name: s.Name}]; !exists {
			db.svcName[nameKey{name: s.Name}] = s
		}
		for _, alias := range s.Aliases {
			if _, exists := db.svcName[nameKey{name: alias, proto: proto}]; !exists {
				db.svcName[nameKey{name: alias, proto: proto}] = s
			}
			if _, exists := db.svcName[nameKey{name: alias}]; !exists {
				db.svcName[nameKey{name: alias}] = s
			}
		}
		pk := portKey{port: port, proto: proto}
		if _, exists := db.svcPort[pk]; !exists {
			db.svcPort[pk] = s
		}
		if _, exists := db.svcPort[portKey{port: port}]; !exists {
			db.svcPort[portKey{port: port}] = s
		}
	})
}

func splitPort(field string) (int, string, bool) {
	slash := strings.IndexByte(field, '/')
	if slash <= 0 || slash == len(field)-1 {
		return 0, "", false
	}
	port, err := strconv.ParseUint(field[:slash], 10, 16)
	if err != nil {
		return 0, "", false
	}
	return int(port), field[slash+1:], true
}

func parseInt(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, strconv.IntSize)
	if err != nil || n > uint64(math.MaxInt) {
		return 0, false
	}
	return int(n), true
}

func forEachLine(text []byte, visit func([]string)) error {
	sc := bufio.NewScanner(bytes.NewReader(text))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		visit(fields)
	}
	return sc.Err()
}

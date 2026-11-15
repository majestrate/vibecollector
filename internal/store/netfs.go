package store

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"path"
	"strconv"
	"time"

	"github.com/majestrate/vibecollector/internal/netdb"
)

// NetFS is one client's view of the protocol and service tables.
// Open accepts only netdb.ProtocolsPath and netdb.ServicesPath. Each file
// is the matching file from system, then that client's rows appended.
// A name that is not one of those two paths is fs.ErrNotExist, including
// when system contains that name. The database is queried by client id.
// It has no path column, and Open does not pass name into SQL.
type NetFS struct {
	ctx      context.Context
	db       *DB
	clientID string
	system   fs.FS
}

// NewNetFS returns the filesystem for clientID.
// ctx is used when Open reads the override rows. db is the store that
// holds them. system is the host tree the system files are read from,
// usually os.DirFS("/"). A nil system or a nil db makes Open fail.
func NewNetFS(ctx context.Context, db *DB, clientID string, system fs.FS) *NetFS {
	if ctx == nil {
		ctx = context.Background()
	}
	return &NetFS{ctx: ctx, db: db, clientID: clientID, system: system}
}

// Open reads one of the two table files.
// name must be netdb.ProtocolsPath or netdb.ServicesPath. The result is
// the system file with this client's rows appended after a newline.
// Any other name returns fs.ErrNotExist. A database error is returned
// as a PathError. The caller closes the file.
func (f *NetFS) Open(name string) (fs.File, error) {
	if f == nil || f.db == nil || f.system == nil || !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	var extra []byte
	var err error
	switch name {
	case netdb.ProtocolsPath:
		extra, err = f.protocolSuffix()
	case netdb.ServicesPath:
		extra, err = f.serviceSuffix()
	default:
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	base, err := fs.ReadFile(f.system, name)
	if err != nil {
		return nil, err
	}
	body := append([]byte(nil), base...)
	if len(extra) > 0 {
		if len(body) == 0 || body[len(body)-1] != '\n' {
			body = append(body, '\n')
		}
		body = append(body, extra...)
	}
	return &memFile{name: name, r: bytes.NewReader(body)}, nil
}

func (f *NetFS) protocolSuffix() ([]byte, error) {
	rows, err := f.db.ListClientProtocols(f.ctx, f.clientID)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	for _, row := range rows {
		if err := validProtocol(row); err != nil {
			return nil, err
		}
		buf.WriteString(row.Name)
		buf.WriteByte('\t')
		buf.WriteString(strconv.Itoa(row.Number))
		for _, alias := range row.Aliases {
			buf.WriteByte('\t')
			buf.WriteString(alias)
		}
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

func (f *NetFS) serviceSuffix() ([]byte, error) {
	rows, err := f.db.ListClientServices(f.ctx, f.clientID)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	for _, row := range rows {
		if err := validService(row); err != nil {
			return nil, err
		}
		buf.WriteString(row.Name)
		buf.WriteByte('\t')
		buf.WriteString(strconv.Itoa(row.Port))
		buf.WriteByte('/')
		buf.WriteString(row.Protocol)
		for _, alias := range row.Aliases {
			buf.WriteByte('\t')
			buf.WriteString(alias)
		}
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

type memFile struct {
	name string
	r    *bytes.Reader
}

func (f *memFile) Stat() (fs.FileInfo, error) {
	return memInfo{name: path.Base(f.name), size: int64(f.r.Size())}, nil
}

func (f *memFile) Read(p []byte) (int, error) { return f.r.Read(p) }

func (f *memFile) Close() error { return nil }

func (f *memFile) Seek(offset int64, whence int) (int64, error) {
	return f.r.Seek(offset, whence)
}

type memInfo struct {
	name string
	size int64
}

func (m memInfo) Name() string       { return m.name }
func (m memInfo) Size() int64        { return m.size }
func (m memInfo) Mode() fs.FileMode  { return 0o444 }
func (m memInfo) ModTime() time.Time { return time.Time{} }
func (m memInfo) IsDir() bool        { return false }
func (m memInfo) Sys() any           { return nil }

var (
	_ fs.File   = (*memFile)(nil)
	_ io.Seeker = (*memFile)(nil)
)

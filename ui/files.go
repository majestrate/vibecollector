// Package ui is the browser UI served at /.
// Files is empty unless make build has generated the embed beside a built
// ui/dist. go test compiles this package with no dist and no node_modules.
package ui

import "io/fs"

// Files is the static UI tree. Production make build replaces it with the
// embedded dist. Tests and a plain go build keep this empty tree.
var Files fs.FS = empty{}

type empty struct{}

func (empty) Open(string) (fs.File, error) { return nil, fs.ErrNotExist }

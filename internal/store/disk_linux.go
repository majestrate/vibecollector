//go:build linux

package store

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// statfsFree reports free bytes on the volume that holds path.
// Available blocks times fragment size; a non-positive Frsize uses Bsize.
func statfsFree(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	bsize := st.Frsize
	if bsize <= 0 {
		bsize = st.Bsize
	}
	if bsize <= 0 {
		return 0, fmt.Errorf("statfs %s: block size %d", path, bsize)
	}
	return st.Bavail * uint64(bsize), nil
}

//go:build freebsd

package store

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// statfsFree reports free bytes on the volume that holds path.
// A negative Bavail is an error. Free space is that count times Bsize.
func statfsFree(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	if st.Bavail < 0 {
		return 0, fmt.Errorf("statfs %s: negative free blocks %d", path, st.Bavail)
	}
	return uint64(st.Bavail) * st.Bsize, nil
}

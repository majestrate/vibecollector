//go:build darwin

package store

import "golang.org/x/sys/unix"

// statfsFree reports free bytes on the volume that holds path.
// Darwin has no fragment size; free space is Bavail times Bsize.
func statfsFree(path string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

//go:build unix

package upstreamd

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedAlone says the file belongs to this process's uid and no permission bit is set for its group or for others.
func ownedAlone(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid() && fi.Mode().Perm()&0o077 == 0
}

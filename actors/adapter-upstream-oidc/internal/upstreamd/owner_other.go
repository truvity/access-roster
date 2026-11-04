//go:build !unix

package upstreamd

import "io/fs"

// ownedAlone is false where the owner of a file cannot be read: the secret is refused.
func ownedAlone(fs.FileInfo) bool { return false }

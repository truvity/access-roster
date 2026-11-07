package main

import (
	"os"
	"path/filepath"
)

func readFile(root, rel string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // the repository's own files
	return string(b), err
}

func absRoot(root string) string {
	a, err := filepath.Abs(root)
	if err != nil {
		return root
	}
	return a
}

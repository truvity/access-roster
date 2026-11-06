package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"
)

// The entries of a tiled log (C2SP tlog-tiles, "Merkle Tree" and "Log entries"): entry bundles of up to 256 entries,
// each entry a big-endian uint16 length and its bytes. The CLI's `audit verify` authenticates every tile against the
// signed checkpoint; this reader only lists what the log holds so that the smoke can open the records.

const bundleWidth = torchwood.TileWidth

// bundlePath is the path of entry bundle n below the log's directory: tile/entries/<N>, with N as groups of three
// digits led by x, and a partial bundle as <N>.p/<W>.
func bundlePath(n int64, width int) string {
	return filepath.FromSlash(torchwood.TilePath(tlog.Tile{H: torchwood.TileHeight, L: -1, N: n, W: width}))
}

// readEntries returns the first size entries of the log in dir.
func readEntries(dir string, size int64) ([][]byte, error) {
	var all [][]byte
	for b := int64(0); int64(len(all)) < size; b++ {
		want := size - int64(len(all))
		width := bundleWidth
		if want < bundleWidth {
			width = int(want)
		}
		data, err := os.ReadFile(filepath.Join(dir, bundlePath(b, width))) //nolint:gosec // the smoke names the log directory
		if errors.Is(err, os.ErrNotExist) && width < bundleWidth {
			// A partial bundle may have been completed since the checkpoint was written (tlog-tiles: a client falls
			// back to the full bundle and takes its first entries).
			data, err = os.ReadFile(filepath.Join(dir, bundlePath(b, bundleWidth))) //nolint:gosec // as above
		}
		if err != nil {
			return nil, fmt.Errorf("entry bundle %d: %w", b, err)
		}
		got, err := splitBundle(data, width)
		if err != nil {
			return nil, fmt.Errorf("entry bundle %d: %w", b, err)
		}
		all = append(all, got...)
	}
	return all, nil
}

// splitBundle cuts the first n entries out of a bundle.
func splitBundle(data []byte, n int) ([][]byte, error) {
	var out [][]byte
	for len(out) < n {
		entry, rest, err := torchwood.ReadTileEntry(data)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
		data = rest
	}
	return out, nil
}

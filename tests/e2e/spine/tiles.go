package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// The entries of a tiled log (C2SP tlog-tiles, "Merkle Tree" and "Log entries"): entry bundles of up to 256 entries,
// each entry a big-endian uint16 length and its bytes. The CLI's `audit verify` authenticates every tile against the
// signed checkpoint; this reader only lists what the log holds so that the smoke can open the records.

const bundleWidth = 256

// bundlePath is the path of entry bundle n below the log's directory: tile/entries/<N>, with N as groups of three
// digits led by x, and a partial bundle as <N>.p/<W>.
func bundlePath(n int64, width int) string {
	nStr := fmt.Sprintf("%03d", n%1000)
	for n >= 1000 {
		n /= 1000
		nStr = fmt.Sprintf("x%03d/%s", n%1000, nStr)
	}
	p := "tile/entries/" + nStr
	if width < bundleWidth {
		p += ".p/" + strconv.Itoa(width)
	}
	return filepath.FromSlash(p)
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
		if len(data) < 2 {
			return nil, errors.New("short bundle")
		}
		l := int(binary.BigEndian.Uint16(data))
		data = data[2:]
		if len(data) < l {
			return nil, errors.New("short entry")
		}
		out = append(out, data[:l])
		data = data[l:]
	}
	return out, nil
}

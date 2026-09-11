#!/usr/bin/env python3
"""Every archive must hold the same binaries on every platform it ships.

goreleaser refuses to publish an archive whose contents differ by
platform, and it refuses at the ARCHIVES stage -- after four minutes of
cross-compiling, and only when a tag is pushed. That is how v0.12.0 was
cut and published nothing: accessctl is the one binary built for Windows,
so the Windows archive held one where every other held four.

`goreleaser check` does not catch it and `goreleaser build
--single-target` never reaches archives, so this is the guard that runs
in `just check`. It reads the same file goreleaser reads and needs no
compiler.

No dependency on PyYAML: the config is read with a tiny parser for the
two shapes this file uses, so a runner with a bare python3 can run it.
"""

import re
import sys
from pathlib import Path

CONFIG = Path(__file__).resolve().parent.parent / ".goreleaser.yaml"


def inline_list(value):
    """[a, b, c] -> ['a','b','c']. The config writes every list this way."""
    inner = value.strip()
    if not (inner.startswith("[") and inner.endswith("]")):
        return None
    return [item.strip() for item in inner[1:-1].split(",") if item.strip()]


def sections(text, name):
    """The blocks of a top-level `name:` list, each as its own line list."""
    lines = text.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.rstrip() == name + ":")
    except StopIteration:
        return []

    blocks, current, depth = [], None, None
    for line in lines[start + 1:]:
        if line and not line[0].isspace():
            break                      # the next top-level key
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        # Only a "- " at the SAME indent as the first one starts a new
        # entry. A deeper one belongs to a nested list -- format_overrides
        # is exactly that, and counting its rows as archives is how this
        # check would have reported two more archives than exist.
        if stripped.startswith("- ") and (depth is None or indent == depth):
            depth = indent
            if current is not None:
                blocks.append(current)
            current = [stripped[2:]]
        elif current is not None and stripped and not stripped.startswith("#"):
            current.append(stripped)
    if current is not None:
        blocks.append(current)
    return blocks


def field(block, name):
    for line in block:
        match = re.match(rf"{name}:\s*(.*)$", line)
        if match:
            return match.group(1)
    return None


def main():
    text = CONFIG.read_text()

    platforms = {}
    for block in sections(text, "builds"):
        ident = field(block, "id")
        goos = inline_list(field(block, "goos") or "")
        if ident and goos:
            platforms[ident] = set(goos)

    if not platforms:
        sys.exit(f"{CONFIG}: no builds found — this check has stopped reading the file")

    failed = False
    for block in sections(text, "archives"):
        archive = field(block, "id") or "?"
        ids = inline_list(field(block, "ids") or "") or []
        by_platform = {}
        for ident in ids:
            if ident not in platforms:
                sys.exit(f"archive {archive!r} names build {ident!r}, which does not exist")
            for goos in platforms[ident]:
                by_platform.setdefault(goos, set()).add(ident)

        counts = {goos: len(built) for goos, built in by_platform.items()}
        if len(set(counts.values())) > 1:
            failed = True
            print(f"archive {archive!r} holds a different set of binaries per platform:",
                  file=sys.stderr)
            for goos in sorted(by_platform):
                print(f"  {goos}: {', '.join(sorted(by_platform[goos]))}", file=sys.stderr)
            print("  goreleaser refuses this, and only at release time. Split the archive.",
                  file=sys.stderr)

    if failed:
        sys.exit(1)
    print(f"archives: {len(sections(text, 'archives'))} checked, each uniform across its platforms")


if __name__ == "__main__":
    main()

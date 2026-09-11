#!/usr/bin/env python3
"""Every Go symbol the documentation promises must exist.

Documentation drifts from a module silently: nothing compiles a code
block in a Markdown file, so a rename leaves the old name in the guide
and the first person to notice is a stranger following it. INF-698 found
seven such symbols at once — `identity.NewIssuerVerifier`,
`identity.ClusterConfig`, a `directory` package that was never built —
and every one of them had been written down as though it shipped.

This asks the compiler instead. `go doc <pkg> <symbol>` succeeds only for
a symbol that is actually exported, which is exactly the question.

It checks only PUBLIC packages: an internal one is not something a reader
can import, and the documentation should not be naming it.
"""

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# The packages a consumer may import. A name qualified by anything else
# is prose, not a promise.
PUBLIC = ("identity", "tokens", "policy")

# Words that read as a package-qualified symbol but are not one: sentence
# starts, prose, and the protobuf/JSON shapes that share the spelling.
IGNORE = {
    ("policy", "Input"),
}


def documented():
    """Every `pkg.Symbol` the docs name, with where it was found."""
    found = set()
    pattern = re.compile(r"\b(" + "|".join(PUBLIC) + r")\.([A-Z][A-Za-z0-9]*)")
    for path in sorted((ROOT / "docs").rglob("*.md")) + [ROOT / "README.md"]:
        if not path.exists():
            continue
        for match in pattern.finditer(path.read_text(encoding="utf-8")):
            pkg, symbol = match.group(1), match.group(2)
            if (pkg, symbol) in IGNORE:
                continue
            found.add((pkg, symbol, path.relative_to(ROOT).as_posix()))
    return sorted(found)


def exists(pkg, symbol):
    return subprocess.run(
        ["go", "doc", "./" + pkg, symbol],
        cwd=ROOT, capture_output=True, text=True).returncode == 0


def main():
    claims = documented()
    if not claims:
        sys.exit("no documented symbols found at all — this check has stopped reading the docs")

    # One `go doc` per distinct symbol rather than per mention.
    seen, missing = {}, []
    for pkg, symbol, where in claims:
        key = (pkg, symbol)
        if key not in seen:
            seen[key] = exists(pkg, symbol)
        if not seen[key]:
            missing.append((pkg, symbol, where))

    if missing:
        print("the documentation promises symbols the module does not export:", file=sys.stderr)
        for pkg, symbol, where in missing:
            print("  %s.%s  (%s)" % (pkg, symbol, where), file=sys.stderr)
        print("\nEither the symbol was renamed and the guide was not, or it was "
              "never built. Both are a stranger following instructions that "
              "cannot work.", file=sys.stderr)
        sys.exit(1)

    print("docs: %d documented symbols, all exported" % len(seen))


if __name__ == "__main__":
    main()

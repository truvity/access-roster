#!/usr/bin/env python3
"""Hold the documentation to docs/WRITING.md: word budgets, sentence length, banned phrases.

Per page (type from the path):
  - prose words (fenced code, table rows and generated regions excluded) within
    the limit of the page's type: tutorial 900, how-to 400, reference 300,
    explanation 800, index 250;
  - sentences of at most 25 words, none over 40, and at most 10% over 25 (a list
    item is a sentence of its own);
  - a how-to links at most 3 pages under decisions/;
  - none of the phrases in hack/docs-banned.tsv outside code.
Per directory: the prose words of the pages directly in it stay within the
ceiling in hack/docs-budget.tsv. A ceiling is a ratchet: each documentation
pass lowers it to the new total (`--print-budget` writes the current totals).

Exempt: docs/decisions, CHANGELOG.md, docs/_redirects, docs/WRITING.md (it quotes the banned phrases).

Output is GitHub `::warning file=...` annotations and a summary per directory.
`--fail` turns every finding into an error. Stdlib only.
"""

import argparse
import collections
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BANNED = ROOT / "hack" / "docs-banned.tsv"
BUDGET = ROOT / "hack" / "docs-budget.tsv"

LIMITS = {"tutorial": 900, "how-to": 400, "reference": 300, "explanation": 800, "index": 250}
# The root README holds the contract's headings (docs/contracts/component.md, C8) and the standards tables.
PAGE_LIMITS = {"README.md": 353}
SENTENCE = 25
SENTENCE_MAX = 40
SENTENCE_SHARE = 0.10
ADR_LINKS_MAX = 3

# Directory names that decide the page type (first match from the page's own directory outward).
KINDS = {
    "get-started": "tutorial", "install": "tutorial",
    "guides": "how-to", "connect": "how-to", "operate": "how-to", "migrate": "how-to",
    "examples": "how-to", "upgrade": "how-to",
    "reference": "reference", "sdk": "reference",
    "concepts": "explanation",
}
EXEMPT_PREFIXES = ("docs/decisions/", "docs/_redirects/", "docs/WRITING.md")
SKIP_DIRS = {".git", "node_modules", ".devbox", "dist", "build", ".venv", "_site"}

GEN_START = "<!-- generated:"
GEN_END = "<!-- /generated"
FENCE = ("```", "~~~")
WORD = re.compile(r"\b[\w'’-]+\b")


def pages():
    out = []
    for p in sorted((ROOT / "docs").rglob("*.md")):
        out.append(p)
    for name in ("README.md", "CONTRIBUTING.md", "charts/audit/README.md", "charts/sluis/README.md"):
        if (ROOT / name).exists():
            out.append(ROOT / name)
    return out


def rel(p):
    return p.relative_to(ROOT).as_posix()


def exempt(path):
    return path.startswith(EXEMPT_PREFIXES) or path.rsplit("/", 1)[-1] == "CHANGELOG.md"


def kind(path):
    parts = path.split("/")
    if parts[-1] == "README.md":
        return "index"
    for d in reversed(parts[:-1]):
        if d in KINDS:
            return KINDS[d]
    return "other"


def split(text):
    """Return (prose, tables, generated, code) as lists of (lineno, text)."""
    prose, tables, gen, code = [], [], [], []
    fenced = generated = comment = False
    for n, line in enumerate(text.splitlines(), 1):
        s = line.lstrip()
        if generated:
            gen.append((n, line))
            if GEN_END in line:
                generated = False
            continue
        if fenced:
            code.append((n, line))
            if s.startswith(FENCE):
                fenced = False
            continue
        if s.startswith(FENCE):
            fenced = True
            code.append((n, line))
            continue
        if GEN_START in line:
            generated = True
            gen.append((n, line))
            if GEN_END in line:
                generated = False
            continue
        if comment:
            if "-->" in line:
                comment = False
            continue
        if s.startswith("<!--"):
            if "-->" not in line:
                comment = True
            continue
        if s.startswith("|"):
            tables.append((n, line))
        else:
            prose.append((n, line))
    return prose, tables, gen, code


def count_words(lines):
    return sum(len(WORD.findall(t)) for _, t in lines)


def plain(line):
    line = re.sub(r"`[^`]*`", "code", line)
    return re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", line)


LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")


def sentence_lengths(prose):
    # A list item ends the sentence before it, so bullets need no blank line between them.
    lines = []
    for _, t in prose:
        if t.lstrip().startswith("#"):
            continue
        if LIST_ITEM.match(t):
            lines.append("")
            t = LIST_ITEM.sub("", t, count=1)
        lines.append(t)
    body = plain("\n".join(lines))
    body = re.sub(r"\b(e\.g|i\.e|etc|vs|cf|v\d+)\.", r"\1", body)
    parts = [s.strip() for s in re.split(r"(?<=[.!?])\s+(?=[A-Z`\"'(\[])|\n\n+", body) if s.strip()]
    return [n for n in (len(WORD.findall(s)) for s in parts) if n >= 3]


def load_banned():
    rows = []
    for n, raw in enumerate(BANNED.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip() or raw.startswith("#"):
            continue
        cols = raw.split("\t")
        if len(cols) != 2 or not cols[1].strip():
            sys.exit(f"{BANNED.name}:{n}: want <regex><TAB><reason>")
        rows.append((re.compile(cols[0], re.I), cols[1].strip()))
    return rows


def load_budget():
    out = {}
    if not BUDGET.exists():
        return out
    for n, raw in enumerate(BUDGET.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip() or raw.startswith("#"):
            continue
        cols = raw.split("\t")
        if len(cols) != 2 or not cols[1].strip().isdigit():
            sys.exit(f"{BUDGET.name}:{n}: want <directory><TAB><prose words>")
        out[cols[0]] = int(cols[1])
    return out


def directory(path):
    d = path.rsplit("/", 1)[0] if "/" in path else "."
    return d


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--fail", action="store_true", help="turn every finding into an error")
    ap.add_argument("--print-budget", action="store_true", help="print the current per-directory totals as docs-budget.tsv rows")
    args = ap.parse_args()

    banned = load_banned()
    budget = load_budget()
    findings = []  # (path, message, directory, category)
    totals = collections.Counter()

    for p in pages():
        path = rel(p)
        if exempt(path):
            continue
        k = kind(path)
        prose, tables, gen, code = split(p.read_text(encoding="utf-8"))
        words = count_words(prose)
        d = directory(path)
        totals[d] += words

        limit = PAGE_LIMITS.get(path, LIMITS.get(k))
        if limit and words > limit:
            findings.append((path, f"{path}: {words} prose words, over the {limit} of a {k} page", d, "budget"))
        if limit or k == "other":
            lens = sentence_lengths(prose)
            over = [n for n in lens if n > SENTENCE]
            if lens and (max(lens) > SENTENCE_MAX or len(over) / len(lens) > SENTENCE_SHARE):
                findings.append((path, f"{path}: {len(over)} of {len(lens)} sentences over {SENTENCE} words "
                                       f"({100 * len(over) // len(lens)}%, longest {max(lens)}; allowed 10%, none over {SENTENCE_MAX})", d, "sentences"))
        if k == "how-to":
            adrs = sum(len(re.findall(r"\]\([^)]*decisions/", plain_keep(t))) for _, t in prose)
            if adrs > ADR_LINKS_MAX:
                findings.append((path, f"{path}: {adrs} links to decisions/ in a how-to (at most {ADR_LINKS_MAX}, under \"Decided in\")", d, "adr-links"))
        hits = collections.defaultdict(list)
        for n, t in prose + tables:
            text = re.sub(r"`[^`]*`", "", t)
            for rx, reason in banned:
                if rx.search(text):
                    hits[(rx.pattern, reason)].append(n)
        for (pat, reason), lines in sorted(hits.items()):
            findings.append((path, f"{path}:{lines[0]}: banned phrase /{pat.strip()}/ x{len(lines)}: {reason}", d, "banned"))

    for d, ceiling in sorted(budget.items()):
        if totals[d] > ceiling:
            findings.append((d, f"{d}: {totals[d]} prose words, over its ceiling of {ceiling} in hack/{BUDGET.name}", d, "ceiling"))
    for d in sorted(totals):
        if d not in budget and totals[d]:
            findings.append((d, f"{d}: no ceiling in hack/{BUDGET.name} (currently {totals[d]} prose words)", d, "ceiling"))

    if args.print_budget:
        print("# Per-directory ceilings on prose words (hack/check-docs-budget.py). Each documentation pass lowers them.")
        for d in sorted(totals):
            print(f"{d}\t{totals[d]}")
        return

    level = "error" if args.fail else "warning"
    for path, msg, _, _ in findings:
        loc = path if "/" in path or path.endswith(".md") else path
        file_arg = loc if loc.endswith(".md") else f"hack/{BUDGET.name}"
        print(f"::{level} file={file_arg}::{msg}")

    by = collections.defaultdict(collections.Counter)
    for _, _, d, cat in findings:
        by[d][cat] += 1
    cats = ["budget", "sentences", "adr-links", "banned", "ceiling"]
    print(f"\ndocs budget: {len(findings)} finding(s)", file=sys.stderr)
    print(f"  {'directory':40s} " + " ".join(f"{c:>9s}" for c in cats) + f" {'prose':>7s} {'ceiling':>7s}", file=sys.stderr)
    for d in sorted(by):
        print(f"  {d:40s} " + " ".join(f"{by[d][c]:9d}" for c in cats) + f" {totals[d]:7d} {budget.get(d, 0):7d}", file=sys.stderr)
    if findings and args.fail:
        sys.exit(1)


def plain_keep(t):
    return re.sub(r"`[^`]*`", "", t)


if __name__ == "__main__":
    main()

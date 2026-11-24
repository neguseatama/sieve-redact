"""The public-text watch of the repository.

The user-facing files carry only short, factual sentences for the
users and developers.  This checker is standard library only,
deterministic and read-only.

Like ``tools/extract_changelog.py``, the output rides as UTF-8 on
every runner: the flagged-line summary prints Japanese words, and a
console whose encoding is a legacy codepage (a captured pipe on
Windows) would otherwise raise UnicodeEncodeError before a single
line leaves the process.  ``main`` therefore pins its own stdout and
stderr to UTF-8 before printing anything.

Without arguments it scans the repository's public surface:

- the two README files, ``docs/``, ``pyproject.toml`` and
  ``AGENTS.md`` (zero findings required),
- the newest ``CHANGELOG.md`` version section (zero findings required;
  older sections are not re-checked, and the version heading's date is
  the only date allowed),
- the comment and docstring lines of the Python sources against the
  per-file baseline in ``tests/public_text_baseline.json``.  The
  baseline counts the lines that carry a forbidden item (a word from
  the list, an absolute path, a section mark) - NOT the total number
  of comment or docstring lines.  The counts only ever shrink; the
  baseline holds file names and line counts only, never words.  The
  flagged lines are printed as ``recorded`` - they do not fail the
  run; the counts shrink as those lines are cleaned up.  The baseline
  keys are POSIX relative paths, so the counts compare equal on every
  host.

With ``--text FILE`` it checks one file's body (a release note or a
commit message) with the word list and the test-identifier pattern.

Forbidden items: references to the internal exchanges, the internal
work names, development environment information (absolute paths),
section marks with numbers, test identifiers in the README, the docs,
the CHANGELOG and the release notes, and dates outside the CHANGELOG's
version headings.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

FORBIDDEN_WORDS = (
    "設計チャット", "開発チャット", "監査チャット", "指揮者", "依頼書",
    "裁定", "検収", "受入", "追補", "数え上げ", "報告書", "第一陣",
    "第二陣", "出生時緑", "遡及赤", "金型", "red-first", "red first",
    "design chat", "dev chat", "design request", "golden", "goldens",
    "mold", "sandbox",
)

_ABSOLUTE_PATH = re.compile(r"/Users/|/home/|C:\\Users\\")
_SECTION_MARK = re.compile(r"§\s*\d")
_TEST_NUMBER = re.compile(r"\b[A-Z]{1,4}[0-9]?-T[0-9]{2}\b")
_DATE = re.compile(r"\b20\d{2}-\d{2}-\d{2}\b")
_VERSION_HEADING = re.compile(r"^## \[")

_ROOT = Path(__file__).resolve().parent.parent
_BASELINE = _ROOT / "tests" / "public_text_baseline.json"

_SKIP_DIRS = {".git", "dist", "build", "__pycache__", ".venv", "venv"}


def scan_text(text, *, test_numbers=False, dates=False,
              allow_date_lines=False):
    """[(line number, item)] for one text body.  ``test_numbers``
    applies to the README, the docs, the CHANGELOG and the release
    notes; ``dates`` to the same targets plus ``pyproject.toml`` and
    ``AGENTS.md`` (``allow_date_lines`` spares the CHANGELOG's version
    headings)."""
    findings = []
    for number, line in enumerate(text.splitlines(), start=1):
        for word in FORBIDDEN_WORDS:
            if word in line:
                findings.append((number, word))
        if _ABSOLUTE_PATH.search(line):
            findings.append((number, "absolute path"))
        if _SECTION_MARK.search(line):
            findings.append((number, "section mark"))
        if test_numbers and _TEST_NUMBER.search(line):
            findings.append((number, "test identifier"))
        if dates and _DATE.search(line):
            if not (allow_date_lines and _VERSION_HEADING.match(line)):
                findings.append((number, "date"))
    return findings


def _python_scan_lines(text):
    """The lines of one Python source that carry comments or sit in a
    docstring (a deterministic triple-quote walk)."""
    in_docstring = False
    marker = None
    for line in text.splitlines():
        stripped = line.strip()
        if not in_docstring and stripped.startswith("#"):
            yield line
            continue
        if in_docstring:
            yield line
            if marker is not None and marker in line:
                closes = line.count(marker)
                if closes % 2 == 1:
                    in_docstring = False
                    marker = None
            continue
        for candidate in ('"""', "'''"):
            if candidate in line:
                opens = line.count(candidate)
                if opens % 2 == 1:
                    in_docstring = True
                    marker = candidate
                yield line
                break


def _latest_changelog_section(text):
    """The newest version section's heading line and body (the body
    starts after the heading, whose date is the allowed one)."""
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if _VERSION_HEADING.match(line):
            start = index
            break
    if start is None:
        return None
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if _VERSION_HEADING.match(lines[index]):
            end = index
            break
    return (lines[start], "\n".join(lines[start + 1:end]))


def _iter_python_files(root):
    for path in sorted(root.rglob("*.py")):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if "egg-info" in path.name:
            continue
        yield path


def scan_repository(root=None):
    """(findings, noted, mismatches) for the public surface.

    findings: (path, line, item) on the zero-required targets.
    noted: (path, flagged_line_count, first_item) for the Python
    sources whose comments or docstrings carry a forbidden item.
    mismatches: (path, baseline, actual) - the per-file counts of the
    comment/docstring lines that carry a forbidden item must equal the
    baseline (a bigger count means the flagged volume grew, a smaller
    one means the baseline is stale; either way the baseline is
    brought to the current count).
    """
    root = Path(root) if root is not None else _ROOT
    findings = []

    required = ["README.md", "README.ja.md", "pyproject.toml",
                "AGENTS.md"]
    for name in required:
        path = root / name
        if not path.exists():
            findings.append((name, 0, "required file missing"))
            continue
        text = path.read_text(encoding="utf-8")
        for number, item in scan_text(text, dates=True):
            findings.append((name, number, item))

    docs = root / "docs"
    if docs.exists():
        for path in sorted(docs.rglob("*")):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for number, item in scan_text(text, test_numbers=True,
                                          dates=True):
                findings.append((f"docs/{path.relative_to(docs).as_posix()}",
                                 number, item))

    changelog = root / "CHANGELOG.md"
    if changelog.exists():
        section = _latest_changelog_section(
            changelog.read_text(encoding="utf-8"))
        if section is not None:
            _heading, body = section
            for number, item in scan_text(body, test_numbers=True,
                                          dates=True,
                                          allow_date_lines=False):
                findings.append(("CHANGELOG.md (newest section)",
                                 number, item))

    baseline = {}
    if _BASELINE.exists():
        baseline = json.loads(
            _BASELINE.read_text(encoding="utf-8"))
    mismatches = []
    counted = {}
    noted = []
    for path in _iter_python_files(root):
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        flagged = 0
        first_items = []
        for line in _python_scan_lines(text):
            items = scan_text(line)
            if items:
                flagged += 1
                if len(first_items) < 3:
                    first_items.append(items[0][1])
        counted[rel] = flagged
        if first_items:
            noted.append((rel, flagged, first_items[0]))
    for rel, expected in sorted(baseline.items()):
        actual = counted.get(rel, 0)
        if actual != expected:
            mismatches.append((rel, expected, actual))
    for rel, actual in sorted(counted.items()):
        if rel not in baseline and actual:
            mismatches.append((rel, 0, actual))
    return findings, noted, mismatches


def main(argv):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass  # an embedded non-console stream has no reconfigure
    if argv and argv[0] == "--text":
        if len(argv) < 2:
            print("usage: check_public_text.py --text FILE",
                  file=sys.stderr)
            return 2
        text = Path(argv[1]).read_text(encoding="utf-8")
        findings = scan_text(text, test_numbers=True)
        for number, item in findings:
            print(f"{argv[1]}:{number}: {item}")
        return 1 if findings else 0
    findings, noted, mismatches = scan_repository()
    for path, _number, item in findings:
        print(f"{path}: {item}")
    for path, count, item in noted:
        print(f"{path}: {item} (recorded, {count} flagged lines)")
    for path, expected, actual in mismatches:
        print(f"baseline: {path}: expected {expected}, actual {actual}")
    return 1 if (findings or mismatches) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

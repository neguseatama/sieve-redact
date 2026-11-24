#!/usr/bin/env python3
"""Extract one version's section from CHANGELOG.md as the release body.

release.yml runs this with the tag's version (the v prefix stripped)
and hands the output to the release attach as body_path.  The section
starts at ``## [<version>]`` and runs to the next ``## [`` heading (or
EOF); the heading line itself is not part of the body because the
release title already carries the tag.  Two structural failures keep a
wrong body from ever reaching the release:

- the version has no section (exit 1) - a tag without its CHANGELOG
  section fails structurally, not by publishing an empty body;
- the version's section is not the FIRST section of the file
  (exit 1) - the release body is the newest section, so a tag whose
  section sits behind a newer one is a cut-tag mistake.

The body rides to stdout as UTF-8 BYTES: the section carries Japanese
words, and a runner whose stdout defaults to a legacy codepage (a
captured pipe on Windows) would raise UnicodeEncodeError before a
single byte left the process.  With the bytes form the body is
byte-exact on every runner.
"""
import re
import sys
from pathlib import Path


def extract(text: str, version: str):
    """(body, is_newest) for one version's section.

    body is "" when the version has no section.  is_newest is False
    when the section exists but is not the file's first section.
    """
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.fullmatch(rf"## \[{re.escape(version)}\]( - .*)?", line):
            start = i + 1
            break
    if start is None:
        return ("", True)
    first_heading = None
    for line in lines:
        if line.startswith("## ["):
            first_heading = line
            break
    newest = first_heading.startswith(f"## [{version}]")
    out = []
    for line in lines[start:]:
        if line.startswith("## ["):
            break
        out.append(line)
    return ("\n".join(out).strip() + "\n", newest)


def main(argv: list) -> int:
    if len(argv) != 2:
        print("usage: extract_changelog.py <version>", file=sys.stderr)
        return 2
    changelog = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
    body, newest = extract(changelog.read_text(encoding="utf-8"), argv[1])
    if not body:
        print(f"no '## [{argv[1]}]' section in CHANGELOG.md - cut the tag "
              "only after the section exists", file=sys.stderr)
        return 1
    if not newest:
        print(f"'## [{argv[1]}]' is not the newest section of "
              "CHANGELOG.md - the release body is the newest section",
              file=sys.stderr)
        return 1
    sys.stdout.buffer.write(body.encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

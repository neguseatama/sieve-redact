# Changelog

## [0.11.0] - 2026-11-08

### Added
- **The `alias` MODE (the seventh mode, `--rule` only)**: the rule's
  PATTERN is treated as a value and matched through the same 1:1
  normalization view as the built-in matchers, so the value's other
  written forms (full-width/half-width ASCII, dash variants) are
  observed as the same value — the value's aliases. The match itself is
  exact: the whole value, no regex, no wildcards, and kanji glyph
  variants (同形異字, e.g. 髙/高) are not folded — the fold set is the
  1:1 table and nothing more. The replacement is the label-style
  sequence number (ARG prefix + ordinal, default `[REDACTED]N`), and
  the numbering shares one position-ascending counter with `label`
  (discarded overlaps consume no numbers). Receipt entries carry the
  existing additive `normalized` flag when the matched span's spelling
  differed from its normalized view; the '+' / '~' prefixes compose as
  everywhere else. Using `alias` with `--builtin` is refused with a
  dedicated message.
- **Three check-digit built-ins** — each observes maximal ASCII digit
  runs of an exact length ("ちょうど" — a 12-digit run never matches
  inside a 13-digit run) through the standard 1:1 view, with the check
  digit deciding:
  - `mynumber` — exactly 12 digits, residue-11 check digit (the same
    formula as sieve-crowd);
  - `corporate-jp` — exactly 13 digits, the leading check digit per
    the Corporate Number Ordinance art. 6 (weights 1,2,1,2,… from the
    last body digit, check = 9 − (sum mod 9); the published example
    7000012050002 carries check digit 7);
  - `card` — 13..19 digits, the standard Luhn checksum.
  Full-width spellings are observed with `normalized: true` on the
  receipt. Card matching takes digit runs only (hyphenated spellings
  are out of scope — see the known-limitations item 7).

### Changed
- **Version bumps to 0.11.0** (the observable matcher scope grows, so
  a minor bump rather than a patch). The machine receipt contract is
  unchanged and additive-only: no top-level key was added or removed,
  and a v0.10.0 run produces a byte-identical machine receipt.

## [0.10.0] - 2026-11-05

### Added
- **Long-vowel separators count as hyphens in phone/postal matching**:
  `090ー1234ー5678` (U+30FC) and `090ｰ1234ｰ5678` (U+FF70) — and the
  postal form `100ー0001` — are now observed by `phone-jp` /
  `postal-jp` and masked in their original spans, with the receipts
  reflecting the new matches (`normalized: true`). The fold applies
  only where the mark sits between digits (the digit-separator
  position), so katakana long vowels (`コーヒー`, `サーバー`) keep
  their exact handling and `email` matching is untouched — no new
  matches appear in non-digit contexts. With this change the fold set
  aligns with the Sieve Lens character table's `dashes` section
  (whose only two entries Redact lacked were U+30FC/U+FF70; Redact
  still does not read the table).

### Changed
- **Version bumps to 0.10.0** (the masking scope grows, so a minor
  bump rather than a patch).

## [0.9.1] - 2026-11-05

### Added
- **Pixel-count cap for image mode** (64,000,000 pixels by default —
  `MAX_IMAGE_PIXELS`): images above the cap are refused from the
  header-derived dimensions *before* any pixel work, with a message that
  carries only the two numbers. Pillow's decompression-bomb warning is
  elevated to the same clean refusal (exit code 2, no traceback).

### Changed
- **Image integrity verification is now Pillow-native**: the check that
  no pixel outside the accepted regions changed runs on
  `ImageChops.difference` + `getbbox(alpha_only=False)` instead of a
  pure-Python pixel loop (measured on the dev environment: 37.3 s →
  0.074 s at 64 MP). The predicate is unchanged — the same tampering is
  detected, and image outputs are byte-identical (pinned in tests).
- **In-place output detection is now per-inode**: the output is compared
  with the input by `os.path.samefile` when it exists (symbolic links,
  hard links, relative/absolute spellings resolve to the same entity) and
  by the resolved parent directory + file name when it does not. The
  image mode previously compared path strings and the text mode compared
  realpaths — hardlinks slipped through both.
- **Atomic writes**: the text output, the image output and both receipt
  writes go to a same-directory temporary file that is `os.replace`d on
  completion. A mid-write failure leaves the previous output intact and
  removes the temporary file; permissions follow the replaced file (or
  `0666 & ~umask` for fresh outputs).
- **Overlap resolution is no longer quadratic**: confirmed regions are
  kept in sorted arrays and overlap queries are answered with two
  bisects (measured: 2× matches used to cost 4× time — now linear).
  Results are byte-identical to v0.9.0; the naive reference
  implementation is kept in the tests and pins the agreement on 400
  seeded random rule/text combinations.
- **README corrected**: the `label` / `replace` image modes draw with
  Pillow's default font (`ImageFont.load_default()`); no font is bundled
  with Redact. The previous wording claimed a bundled bitmap font.

Earlier history: this file starts at 0.9.1; for previous versions see
the git history (tags v0.3.0 … v0.9.0).

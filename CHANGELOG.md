# Changelog

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

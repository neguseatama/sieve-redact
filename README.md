# Sieve Redact v0.9.1

A command-line tool that removes sensitive information from documents —
**deterministically**, while preserving **byte-for-byte integrity** of
everything else.

[![CI](https://github.com/neguseatama/sieve-redact/actions/workflows/test.yml/badge.svg)](https://github.com/neguseatama/sieve-redact/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)

**English** | [日本語](README.ja.md)

## 💡 Concept

Personal information in resumes, reports and logs is converted into a second
file that is safe to publish and share.

- **Deterministic** — Same input plus same rules always produces the same
  output. Character selection in `noise` is derived from SHA-256; it depends
  on nothing else — not on the environment, the clock, or any RNG.
- **Byte-for-byte integrity** — Bytes outside a match are left untouched,
  down to the last byte. CRLF line endings survive. Integrity is verified
  mechanically before output; `--strict` refuses to write on failure
  (exit code 3).
- **No guessing** — The user specifies what is sensitive. The engine never
  guesses.
- **Receipts** — The receipt records the facts of processing (positions,
  lengths, modes, hashes) but never the sensitive body itself. Even
  "no pattern remains" is reported as a measurement
  (`pattern_appearance_in_output`), not a promise.

> The name refers to a sieve: drop only what is specified, and leave
> everything else unharmed, byte for byte.

Companion tool to [Sieve Lens](https://github.com/neguseatama/sieve-lens)
(observation of invisible content) — Lens observes, Redact masks.

---

## 🧩 The Sieve Series

Sieve is a family of deterministic, zero-dependency engines that share
the same design principles (deterministic output, no telemetry, fully
local) — each engine observes or masks one specific risk, and they
compose:

| Package | Role | Connects to |
|---------|------|-------------|
| [sieve-core-engine](https://github.com/neguseatama/sieve-core) | Base logic / plugin host for the ecosystem | — |
| [sieve-lens](https://github.com/neguseatama/sieve-lens) | Observes invisible content & hidden prompts in documents | → redact via `--from-lens` |
| [sieve-scope](https://github.com/neguseatama/sieve-scope) | Detects structurally similar code pairs | — |
| [sieve-referee](https://github.com/neguseatama/sieve-referee) | Detects paraphrased / reused text pairs | — |
| [sieve-redact](https://github.com/neguseatama/sieve-redact) | Masks sensitive regions (text & PNG/JPEG) with receipts | ← lens, → tray |
| [sieve-tray](https://github.com/neguseatama/sieve-tray) | Desktop front-end that routes files to the right engine | ← all engines |

Observation → masking in one pass: Lens finds what a human can't see,
Redact removes it with a receipt that proves nothing else changed.

## 🔥 Features

### Six redaction modes

| MODE | Operation | Content |
|------|-----------|---------|
| `delete` | remove the region | empty string |
| `mosaic` | fill per character | `█` repeated for the original character count |
| `label` | numbered labels | prefix (default `[REDACTED]`) + sequence number |
| `noise` | same-class replacement | picked deterministically within the same character class (hiragana / katakana / kanji / upper / lower / digit) |
| `decor` | wrap | `ARG + original + ARG` |
| `replace` | bulk replace | ARG |

### Built-in matchers (`--builtin`)

| NAME | Target |
|------|--------|
| `postal-jp` | Japanese postal codes `NNN-NNNN` |
| `phone-jp` | Japanese phone numbers (`090-…` / `03-…` / `050-…` / `0120-…` / 4-digit area codes `01XX-09XX`) and short numbers (`104` / `106` / `110` / `117` / `118` / `119` / `171`) |
| `email` | Email addresses (ASCII) |
| `chars` | All occurrences of given codepoints (`U+200B,U+00AD` form) |

`postal-jp` / `phone-jp` / `email` match through a 1:1 normalization
view: full-width ASCII forms (`１２３`, `ＡＢＣ`, `－`, `＠`) and dash
variants (U+2010–2015, U+2212) are folded to their ASCII counterparts
before matching, while masking still applies to the original bytes
(receipts record `normalized: true` on such spans). `chars` and
literal rules stay exact.

### Image masking (`--region`)

PNG images (8-bit RGB/RGBA, non-interlaced, non-animated) and RGB JPEG
images are masked by explicit regions: `--region x,y,w,h:MODE[:ARG]`
(repeatable; overlapping regions are discarded in declaration order;
zero-area or out-of-bounds regions are usage errors; `--rule` cannot be
combined with `--region`). The output is always PNG — JPEG input is
never re-compressed as JPEG, so masking adds no further loss (the
decoded pixels are preserved into the PNG).

| MODE | Effect |
|------|--------|
| `delete` | opaque white fill |
| `mosaic` | block average over all channels (blocks align to the region origin; ARG = block size, default 8) |
| `noise` | per-pixel deterministic replacement — SHA-256(`img:x:y:R,G,B`) drives the new RGB; alpha is kept, so semi-transparent pixels keep their visibility (content changes, visibility does not) |
| `label` | black band with `[REDACTED]n` (Pillow's default font) |
| `decor` | 2px border in the ARG color (RRGGBB hex) |
| `replace` | ARG text drawn on a white fill (Pillow's default font) |

Image receipts set `byte_integrity_verified` to `null` (not applicable —
the output is always PNG, so file bytes change structurally even for PNG
input), record the detected format as `input_format` (`PNG` or `JPEG`),
and report pixel integrity outside every region as
`pixel_integrity_verified`; `--strict` exits 3 when it fails. File
metadata (EXIF etc.) is always dropped on save — a privacy-friendly
default by design. Output bytes are deterministic across platforms and
pinned in CI (with Pillow 12.3.0; future Pillow updates may change
encoded bytes, never pixels).

### Word-unit and case-insensitive matching (`+` / `~` prefixes)

`太郎:label` also matches the `太郎` inside `田中太郎`; `太郎:+label`
matches only at word boundaries (adjacent characters of the same class, or
both alphanumeric, cause rejection).

`Taro:~label` ignores ASCII case when matching (`TARO` / `taro` also
match; non-ASCII stays exact). The prefixes compose in any order —
`秘密:+~label` is word-unit plus case-insensitive. `chars` with `~`
matches both case variants of the listed ASCII letters.

### Config files and Lens integration

- `--config rules.cfg`: load rules from a file (`rule <spec>` / `builtin <spec>`
  line format).
- `--from-lens catalog.json`: generate masking rules from an observation
  catalog (JSON) produced by [Sieve Lens](https://github.com/neguseatama/sieve-lens).
  Invisible characters become deletions; look-alike letters
  (Cyrillic/Greek → Latin) become replacements based on the `twin` field.
  A zero-dependency schema gate validates the catalog strictly and
  rejects (rc2, with JSON Pointer error paths): duplicate JSON keys,
  `NaN`/`Infinity`, unknown keys, wrong types (including `true` as an
  integer) and files over 1 MiB. Nothing is guessed or coerced.

---

## 💻 Quick start

    git clone https://github.com/neguseatama/sieve-redact.git
    cd sieve-redact

    # Mosaic a name, label phone numbers
    python sieve_redact.py in.txt -o out.txt \
      --rule "田中太郎:mosaic" \
      --builtin phone-jp:label \
      --receipt receipt.json

Example receipt (stdout) — `in.txt` contains `x秘密y`, run with
`--rule "秘密:delete"`:

    Sieve Redact v0.7.0 — レシート
    入力: 8 バイト -> 出力: 2 バイト
    redact 件数: 1
      #1 rule=1 matcher=literal mode=delete pos=1..7 len=6B -> 0B sha256=062a2931da68...
    他バイト完全性: 検証済み
    出力内パターン残留: none

The sensitive body never appears in the receipt — hashes only. In
image mode (`--region`) `byte_integrity_verified` is `null` (not
applicable) and pixel integrity is measured by
`pixel_integrity_verified` instead.

### Integration with Sieve Lens

    # (1) Lens produces an observation catalog
    python -m sieve_lens_ext.redact_bridge input.txt catalog.json
    # (2) Redact masks everything
    python sieve_redact.py input.txt -o clean.txt --from-lens catalog.json

---

## 🔬 Determinism guarantees

Character selection in `noise` is fully determined by:

    char = POOL[ SHA-256("<pattern>:<byte_offset>:<original char>").digest()[0] % len(POOL) ]

No seed. No environment dependence. Same input, same output, always.
The bundled tests verify exact agreement with this formula by recomputation.

The normalization view (built-in matchers) and the ASCII case folding
(`~` rules) are per-character 1:1 mappings — they never shift positions,
so masking still applies to the original bytes.

Overlapping matches are resolved deterministically as well: rules are tried
in declaration order, each rule scans leftmost-first, later matches that
overlap a confirmed region are discarded, and confirmed regions are applied
in ascending order of position.

---

## 🔬 Tests

    python -m unittest discover -s tests -v

251 tests (five modes, built-in matchers, word-unit matching,
case-insensitive matching, the normalization view, image masking with
JPEG input, config files, Lens integration with the schema gate, the
Schema Contract v1 conformance corpus replica (JSON layer), CLI
boundaries). No additional dependencies.

`tests/corpus/schema_contract_v1.json` is a sha256-pinned replica of
the Sieve Schema Contract v1 conformance corpus (44 accept/reject
cases) maintained in the sieve-lens repository, which also hosts the
contract text (`docs/SCHEMA_CONTRACT_v1.md`) and the canonical engine
(`sieve_lens_ext/schema.py`). The replica exercises Redact's JSON
layer — strict catalog loading: duplicate keys, `NaN`/`Infinity` and
a UTF-8 BOM are refused — and the pin turns any silent drift from the
canonical copy into a test failure (the sieve-tray vendor-sync
precedent).

---

## ⚠️ Known limitations

1. **No regex** — patterns are literal strings, optionally with ASCII
   case-insensitive folding (`~`); no wildcards, classes or quantifiers
2. **No automatic sensitive-data detection** — the user specifies what is
   sensitive (by design)
3. **Text and images** — PDF and Office formats are not supported;
   image masking accepts PNG (8-bit RGB/RGBA) and RGB JPEG input and
   always writes PNG output; grayscale/CMYK images, other formats
   (GIF/WebP etc.) and PDF masking are out of scope (observation is
   Sieve Lens's domain)
4. **Normalization is 1:1 and targeted** — the built-in matchers fold
   U+FF01..FF5E and the dash variants U+2010..2015 / U+2212 only; other
   compatibility forms (e.g. U+3000 spaces) stay exact
5. **phone-jp shape limits remain** — numbers without hyphens other than
   the fixed short set (`104`/`106`/`110`/`117`/`118`/`119`/`171`) and
   unusual digit groupings are out of scope — match them explicitly
   with `--rule`
6. **--from-lens rejects unknown keys** — catalog keys outside contract
   v1 (`lens`/`version`/`observations`, per-item
   `kind`/`codepoint`/`count`/`positions`/`twin`) are refused, not
   ignored; future Lens versions must extend the contract explicitly

---

## 📄 License

MIT. See [LICENSE](LICENSE).

---

## 👤 Author

* **Kai IWASAKI**

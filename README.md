# Sieve Redact v0.4

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
| `phone-jp` | Japanese phone numbers (`090-…` / `03-…` / `050-…` / `0120-…` / 4-digit area codes `01XX-07XX`) |
| `email` | Email addresses (ASCII) |
| `chars` | All occurrences of given codepoints (`U+200B,U+00AD` form) |

### Word-unit matching (`+` prefix)

`太郎:label` also matches the `太郎` inside `田中太郎`; `太郎:+label`
matches only at word boundaries (adjacent characters of the same class, or
both alphanumeric, cause rejection).

### Config files and Lens integration

- `--config rules.cfg`: load rules from a file (`rule <spec>` / `builtin <spec>`
  line format).
- `--from-lens catalog.json`: generate masking rules from an observation
  catalog (JSON) produced by [Sieve Lens](https://github.com/neguseatama/sieve-lens).
  Invisible characters become deletions; look-alike letters
  (Cyrillic/Greek → Latin) become replacements based on the `twin` field.

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

    Sieve Redact v0.4 — レシート
    入力: 8 バイト -> 出力: 2 バイト
    redact 件数: 1
      #1 rule=1 matcher=literal mode=delete pos=1..7 len=6B -> 0B sha256=062a2931da68...
    他バイト完全性: 検証済み
    出力内パターン残留: none

The sensitive body never appears in the receipt — hashes only.

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

Overlapping matches are resolved deterministically as well: rules are tried
in declaration order, each rule scans leftmost-first, later matches that
overlap a confirmed region are discarded, and confirmed regions are applied
in ascending order of position.

---

## 🔬 Tests

    python -m unittest discover -s tests -v

113 tests (five modes, built-in matchers, word-unit matching, config files,
Lens integration, CLI boundaries). No additional dependencies.

---

## ⚠️ Known limitations

1. **No regex** — patterns are literal, exact-match strings only
2. **No case-insensitive matching** — matching is case-sensitive
3. **No automatic sensitive-data detection** — the user specifies what is
   sensitive (by design)
4. **Text only** — PDF, images and Office formats are not supported
5. **Full-width digits and non-ASCII hyphens are out of scope** for
   postal/phone
6. **4-digit area codes starting with 08/09 (except `0800`) and short
   numbers such as 117/104 are out of scope** for `phone-jp` — match
   them explicitly with `--rule`

---

## 📄 License

MIT. See [LICENSE](LICENSE).

---

## 👤 Author

* **Kai IWASAKI**

"""Sieve Redact v0.12.0 — same-value MODE (the 8th MODE, --rule and
--builtin) acceptance tests (RD-T12..T14).

Spec summary (pinned by these tests):
  - `same-value` is a MODE like label: every occurrence of the SAME
    VALUE carries the SAME symbol (ARG prefix + ordinal, default
    `[REDACTED]`).  It works with `--rule PATTERN:same-value[:ARG]`
    (the raw-string match, exactly like label) and with
    `--builtin NAME:same-value[:ARG]` (every built-in NAME).
  - The ordinals share ONE counter with label / alias: the counter
    advances in position-ascending apply order across all rules from 1.
    A repeat of an already-seen value reuses its symbol and consumes no
    number; a discarded match (boundary rejection / overlap discard)
    consumes no number either.
  - Duplicate judgment uses (kind, normalized value): the kind is
    (literal, PATTERN) or (builtin, NAME); the value is the matched
    span in the view the matcher itself matched on — raw span for
    literals (ASCII-folded span for `~`), the digit-view slice for
    postal-jp / phone-jp, the standard-view slice for email / mynumber /
    corporate-jp, the DIGITS ONLY for card (so the same number spelled
    with different separators is the same value), the matched character
    itself for chars.
  - The Machine Receipt keeps its 6 top-level keys and the 8 per-entry
    keys (+ the existing additive flags only); the mode field carries
    `same-value`; the exit-code contract is unchanged.

Each test method asserts the acceptance of the new spec (rc0) at the
top, so on the pre-feature tree it fails right there (unknown MODE,
rc2) and the subTests below are not reached.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "sieve_redact.py"
sys.path.insert(0, str(ROOT))

import sieve_redact as sr  # noqa: E402

# card values: the 16-digit Visa test number and a second distinct card
CARD_A = "4111111111111111"
CARD_B = "4242424242424242"
# valid 12-digit My Numbers (residue-11): two distinct values
MY_A = "123456789018"
MY_B = "999991000000"


class SameValueBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.dir = Path(tmp.name)
        self.addCleanup(tmp.cleanup)

    def run_cli(self, args):
        return subprocess.run([sys.executable, str(SCRIPT)] + list(args),
                              capture_output=True, text=True,
                              encoding="utf-8", errors="replace")

    def ok_run(self, args):
        proc = self.run_cli(args)
        self.assertEqual(proc.returncode, 0,
                         "rc=%d\nstdout:\n%s\nstderr:\n%s"
                         % (proc.returncode, proc.stdout, proc.stderr))
        return proc

    def redact_text(self, text, extra):
        src = self.dir / "in.txt"
        src.write_bytes(text.encode("utf-8"))
        out = self.dir / "out.txt"
        rec = self.dir / "rec.json"
        self.ok_run([str(src), "-o", str(out), "--receipt", str(rec)]
                    + list(extra))
        return out.read_text(encoding="utf-8"), json.loads(
            rec.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# RD-T12: same-value と --rule — 同じ値は同じ記号・通しカウンタ
# ---------------------------------------------------------------------------

class RD_T12_SameValueRule(SameValueBase):
    def test_same_pattern_gets_one_symbol(self):
        # ガード: 新 MODE の受容 (rc0)。red 段では rc2 でここで落ちる。
        out, rec = self.redact_text(
            "秘密 秘密 秘密\n", ["--rule", "秘密:same-value:L-"])
        self.assertEqual(out, "L-1 L-1 L-1\n")
        self.assertEqual(rec["total_redactions"], 3)
        for r in rec["redactions"]:
            self.assertEqual(r["mode"], "same-value")
            # 記号は 1 回だけ消費 — 3 件すべて同じ置換長 (L-1 = 3B)
            self.assertEqual(r["replacement_length"], 3)

    def test_label_and_same_value_share_one_counter(self):
        # 連番は label・alias と 1 つの数え方に共通 — 位置昇順の
        # 適用順で 1 つの通しカウンタ。label は出現ごとに進み、
        # same-value は初出のときだけ進む。
        out, rec = self.redact_text(
            "A B A B\n",
            ["--rule", "A:label:L-", "--rule", "B:same-value:S-"])
        self.assertEqual(out, "L-1 S-2 L-3 S-2\n")
        self.assertEqual(rec["total_redactions"], 4)

    def test_default_prefix_is_the_label_default(self):
        out, rec = self.redact_text(
            "X X\n", ["--rule", "X:same-value"])
        self.assertEqual(out, "[REDACTED]1 [REDACTED]1\n")
        for r in rec["redactions"]:
            self.assertEqual(r["replacement_length"], len("[REDACTED]1"))

    def test_case_insensitive_folds_the_value_identity(self):
        # '~' で照合させた以上、値の同一性も ASCII 折りたたみに従う
        # (大小違いの 2 つの表記は同じ値 = 同じ記号)。
        out, rec = self.redact_text(
            "AB ab\n", ["--rule", "AB:~same-value:L-"])
        self.assertEqual(out, "L-1 L-1\n")
        entries = rec["redactions"]
        self.assertEqual(len(entries), 2)
        for r in entries:
            self.assertIs(r["case_insensitive"], True)

    def test_word_unit_prefix_composes(self):
        # '+' の語単位一致は既存どおり — 境界で棄却されたマッチは
        # 番号を消費しない。
        out, rec = self.redact_text(
            "12345 1234\n", ["--rule", "1234:+same-value:L-"])
        self.assertEqual(out, "12345 L-1\n")
        self.assertEqual(rec["total_redactions"], 1)

    def test_discarded_overlap_consumes_no_number(self):
        # 先着のルールが区間を確定すると、後発の same-value は
        # マッチを捨てる (番号を消費しない)。
        out, rec = self.redact_text(
            "X X\n",
            ["--rule", "X:same-value:L-", "--rule", "X:same-value:M-"])
        self.assertEqual(out, "L-1 L-1\n")
        modes = [r["mode"] for r in rec["redactions"]]
        self.assertEqual(modes, ["same-value", "same-value"])
        self.assertEqual([r["rule_index"] for r in rec["redactions"]],
                         [1, 1])


# ---------------------------------------------------------------------------
# RD-T13: same-value と --builtin — 種類つきの値の同一性
# ---------------------------------------------------------------------------

class RD_T13_SameValueBuiltin(SameValueBase):
    def test_card_same_number_across_separators_is_one_value(self):
        # card の値は区切りを除いた数字列 — 3 つの表記 (ハイフン・
        # 空白・無区切り) はすべて同じ値 = 同じ記号。
        # red 段では区切りつきの 2 形が非検出のまま残るため、
        # ガード (rc0) 通過後もこの断言で落ちる。
        out, rec = self.redact_text(
            "4111-1111-1111-1111 and 4111 1111 1111 1111"
            " and 4111111111111111\n",
            ["--builtin", "card:same-value:C-"])
        self.assertEqual(out, "C-1 and C-1 and C-1\n")
        self.assertEqual(rec["total_redactions"], 3)
        for r in rec["redactions"]:
            self.assertEqual(r["matcher"], "builtin:card")

    def test_card_different_numbers_get_different_symbols(self):
        out, rec = self.redact_text(
            "%s %s\n" % (CARD_A, CARD_B),
            ["--builtin", "card:same-value:C-"])
        self.assertEqual(out, "C-1 C-2\n")

    def test_mynumber_repeats_share_the_symbol(self):
        out, rec = self.redact_text(
            "%s ... %s\n" % (MY_A, MY_A),
            ["--builtin", "mynumber:same-value:M-"])
        self.assertEqual(out, "M-1 ... M-1\n")
        out, rec = self.redact_text(
            "%s ... %s\n" % (MY_A, MY_B),
            ["--builtin", "mynumber:same-value:M-"])
        self.assertEqual(out, "M-1 ... M-2\n")

    def test_postal_phone_email_chars_repeats_share_the_symbol(self):
        # 種類つきの値: 各 builtin の値空間は独立 (postal と phone は
        # 第 2 ビュー・email は標準ビュー・chars は一致した 1 文字)。
        out, _ = self.redact_text(
            "123-4567 と 123-4567\n",
            ["--builtin", "postal-jp:same-value:P-"])
        self.assertEqual(out, "P-1 と P-1\n")
        out, _ = self.redact_text(
            "090-1234-5678 と 090-1234-5678\n",
            ["--builtin", "phone-jp:same-value:T-"])
        self.assertEqual(out, "T-1 と T-1\n")
        out, _ = self.redact_text(
            "a@b.example と a@b.example\n",
            ["--builtin", "email:same-value:E-"])
        self.assertEqual(out, "E-1 と E-1\n")
        out, _ = self.redact_text(
            "x\u200by\u200bz\n",
            ["--builtin", "chars:U+200B:same-value:S-"])
        self.assertEqual(out, "xS-1yS-1z\n")

    def test_kind_tag_separates_the_value_spaces(self):
        # 種類つきの正規化した値 — リテラルと builtin は値空間が違う。
        # 宣言順に先着した matcher が区間を確定し、他方は捨てられる。
        text = "%s %s\n" % (CARD_A, CARD_A)
        out, rec = self.redact_text(
            text,
            ["--rule", CARD_A + ":same-value:L-",
             "--builtin", "card:same-value:C-"])
        self.assertEqual(out, "L-1 L-1\n")
        self.assertEqual(
            {r["matcher"] for r in rec["redactions"]}, {"literal"})
        out, rec = self.redact_text(
            text,
            ["--builtin", "card:same-value:C-",
             "--rule", CARD_A + ":same-value:L-"])
        self.assertEqual(out, "C-1 C-1\n")
        self.assertEqual(
            {r["matcher"] for r in rec["redactions"]}, {"builtin:card"})

    def test_fullwidth_and_hyphen_variants_are_the_same_card_value(self):
        # 全角数字・異種ハイフンの表記も同じ数字列 = 同じ値。
        # red 段では区切りつきの全角形が非検出のため落ちる。
        out, rec = self.redact_text(
            "４１１１－１１１１－１１１１－１１１１ と"
            " 4111\u20101111\u20101111\u20101111\n",
            ["--builtin", "card:same-value:C-"])
        self.assertEqual(out, "C-1 と C-1\n")
        for r in rec["redactions"]:
            self.assertIs(r["normalized"], True)


# ---------------------------------------------------------------------------
# RD-T14: 契約の固定 — 受領書の鍵・終了符号・全 builtin の受容
# ---------------------------------------------------------------------------

class RD_T14_ContractGuards(SameValueBase):
    def test_machine_receipt_keys_are_unchanged(self):
        # 受領書契約: 最上位の鍵は 6 個のまま・項目の鍵も増やさない。
        _, rec = self.redact_text(
            "秘密 秘密\n", ["--rule", "秘密:same-value:L-"])
        self.assertEqual(
            set(rec),
            {"input_bytes", "output_bytes", "redactions",
             "total_redactions", "byte_integrity_verified",
             "pattern_appearance_in_output"})
        for r in rec["redactions"]:
            self.assertEqual(
                set(r),
                {"rule_index", "matcher", "mode", "start", "end",
                 "length", "content_sha256", "replacement_length"})

    def test_all_builtins_accept_same_value(self):
        # --builtin と --rule の両方で動く。全 builtin 名で
        # 受容を top-level で断言する。
        cases = [
            ["--builtin", "postal-jp:same-value"],
            ["--builtin", "phone-jp:same-value"],
            ["--builtin", "email:same-value"],
            ["--builtin", "chars:U+200B:same-value"],
            ["--builtin", "mynumber:same-value"],
            ["--builtin", "corporate-jp:same-value"],
            ["--builtin", "card:same-value"],
        ]
        for extra in cases:
            with self.subTest(spec=extra[1]):
                self.redact_text("ok\n", extra)

    def test_unknown_mode_spelling_is_still_rc2(self):
        src = self.dir / "in.txt"
        src.write_text("x\n", encoding="utf-8")
        proc = self.run_cli([str(src), "-o", str(self.dir / "out.txt"),
                             "--rule", "X:same_value:L-"])
        self.assertEqual(proc.returncode, 2)

    def test_exit_code_and_integrity_contract(self):
        out, rec = self.redact_text(
            "A A\n", ["--rule", "A:same-value:L-"])
        self.assertIs(rec["byte_integrity_verified"], True)
        self.assertEqual(rec["pattern_appearance_in_output"], "none")
        self.assertEqual(rec["input_bytes"], len("A A\n".encode("utf-8")))
        self.assertEqual(rec["output_bytes"],
                         len("L-1 L-1\n".encode("utf-8")))


if __name__ == "__main__":
    unittest.main()

"""Sieve Redact v0.12.0 — separated card spellings for the `card`
matcher (RD-T15..T17).

Spec summary (pinned by these tests):
  - `card` now observes card numbers spelled WITH separators: groups of
    4 digits joined by ONE identical separator character, 13..19 digits
    in total, standard Luhn — i.e. (4,4,4,1..4) for 13..16 digits and
    (4,4,4,4,1..3) for 17..19 digits, plus the 4-6-5 (15 digits) and
    4-6-4 (14 digits) groupings.  The matched span INCLUDES the
    separators.
  - Separators (in the standard 1:1 view): the ASCII space, `-` (the
    dash variants U+2010..2015 / U+2212 / U+FF0D fold to `-` first),
    U+3000 (ideographic space) and U+30FC (long vowel).  Full-width
    digits fold to ASCII first.
  - Exactness carries over from the unseparated matcher: the grouping
    forms and the Luhn gate decide each chain, and a failed chain
    yields no match from its start position — but every word start is
    tried, so a valid number whose boundaries are separators is never
    missed (the tail of a longer same-separator run is still observed;
    pinned by its own test).  The digit words are maximal, so digits
    glued to a group break the grouping; mixed separators break the
    chain; 8+8 / 7+9 groupings, 20+ digits and 12- digits stay out of
    scope; the unseparated 13..19-digit branch is unchanged.
  - Non-target matchers (postal-jp / phone-jp / email / mynumber /
    corporate-jp) are untouched.

The card values below are Luhn-valid; the values for the groupings
without a published example were completed by computing the check
digit of the payload with the standard Luhn formula (verified against
`sr.luhn_ok`).
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


class CardSeparatorBase(unittest.TestCase):
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
        src.write_text(text, encoding="utf-8")
        out = self.dir / "out.txt"
        rec = self.dir / "rec.json"
        self.ok_run([str(src), "-o", str(out), "--receipt", str(rec)]
                    + list(extra))
        return out.read_text(encoding="utf-8"), json.loads(
            rec.read_text(encoding="utf-8"))

    def assert_card_detected(self, body, extra=None):
        """'id: <body>\n' + card:label -> 'id: C-1\n' + 1 entry whose
        byte length equals the whole body (separators included)."""
        text = "id: %s\n" % body
        out, rec = self.redact_text(
            text, ["--builtin", "card:label:C-"] + list(extra or []))
        self.assertEqual(out, "id: C-1\n", body)
        self.assertEqual(rec["total_redactions"], 1, body)
        r = rec["redactions"][0]
        self.assertEqual(r["matcher"], "builtin:card", body)
        self.assertEqual(r["length"], len(body.encode("utf-8")), body)
        self.assertEqual(r["replacement_length"], len("C-1"), body)
        return r

    def assert_card_not_detected(self, body):
        text = "id: %s\n" % body
        out, rec = self.redact_text(
            text, ["--builtin", "card:label:C-"])
        self.assertEqual(out, text, body)
        self.assertEqual(rec["total_redactions"], 0, body)


# ---------------------------------------------------------------------------
# RD-T15: 区切りつき 16 桁の形 — 0.11.0 で非検出だった形の行列
# ---------------------------------------------------------------------------

class RD_T15_SeparatorForms(CardSeparatorBase):
    def test_detected_forms_matrix(self):
        # 半角空白・半角ハイフンは検出される (normalized は出ない)。
        # U+3000 と U+30FC はビューが無変更なので normalized も出ない。
        for body, normalized in (
                ("4111 1111 1111 1111", False),     # 半角空白
                ("4111-1111-1111-1111", False),     # 半角ハイフン
                ("4111　1111　1111　1111", False),   # U+3000
                ("4111ー1111ー1111ー1111", False),   # U+30FC
                ("４１１１ １１１１ １１１１ １１１１", True),  # 全角数字+半角空白
                ("４１１１－１１１１－１１１１－１１１１", True),  # 全角数字+U+FF0D
                ("4111‑1111‑1111‑1111", True),      # U+2011
                ("4111–1111–1111–1111", True),      # U+2013
                ("4111－1111－1111－1111", True)):   # U+FF0D
            with self.subTest(body=body):
                r = self.assert_card_detected(body)
                if normalized:
                    self.assertIs(r["normalized"], True, body)
                else:
                    self.assertNotIn("normalized", r, body)

    def test_fullwidth_space_form(self):
        # 全角数字 + 全角空白 (着手前実測の 12 形の 1 つ)。
        r = self.assert_card_detected("４１１１　１１１１　１１１１　１１１１")
        self.assertIs(r["normalized"], True)

    def test_replacement_span_includes_the_separators(self):
        # 置き換える範囲は区切りを含める。
        out, rec = self.redact_text(
            "card: 4111 1111 1111 1111 ok\n",
            ["--builtin", "card:delete"])
        self.assertEqual(out, "card:  ok\n")
        r = rec["redactions"][0]
        self.assertEqual(r["length"], len("4111 1111 1111 1111"))
        self.assertEqual(r["content_sha256"],
                         sr.hashlib.sha256(
                             b"4111 1111 1111 1111").hexdigest())


# ---------------------------------------------------------------------------
# RD-T16: Amex の 4-6-5 と 4-6-4・部分の末尾グループ (13〜19 桁)
# ---------------------------------------------------------------------------

class RD_T16_AmexAndPartialForms(CardSeparatorBase):
    def test_amex_4_6_5_forms(self):
        # 既知の Amex テスト番号 (15 桁・4-6-5)。
        self.assert_card_detected("3782 822463 10005")
        self.assert_card_detected("3782-822463-10005")
        self.assert_card_detected("３７８２－８２２４６３－１０００５")

    def test_4_6_4_forms(self):
        # 14 桁・4-6-4 — 既知の Diners 形と検査桁を計算して作った値。
        self.assert_card_detected("3056 930902 5904")
        self.assert_card_detected("3648 123456 7899")
        self.assert_card_detected("3648-123456-7899")

    def test_partial_last_group_forms_13_to_19(self):
        # 4 桁ずつ + 末尾 1〜3 桁: 13・14・15・17・18・19 桁。
        # (16 桁は RD-T15 の 4-4-4-4。検査桁は payload に Luhn の残差式
        # で計算して固定 — いずれも sr.luhn_ok が真の実測値。)
        self.assert_card_detected("4111 1111 1111 9")       # 13 桁
        self.assert_card_detected("4111 1111 1111 14")      # 14 桁
        self.assert_card_detected("4111 1111 1111 116")     # 15 桁
        self.assert_card_detected("4111 1111 1111 1111 3")    # 17 桁
        self.assert_card_detected("4111 1111 1111 1111 18")   # 18 桁
        self.assert_card_detected("4111 1111 1111 1111 110")  # 19 桁
        self.assert_card_detected("4111-1111-1111-1111-110")  # ハイフン

    def test_two_adjacent_cards_with_different_separators(self):
        # 隣接する 2 個の番号 — 区切りが違っても鎖は空白で切れる。
        out, rec = self.redact_text(
            "4111-1111-1111-1111 4242 4242 4242 4242\n",
            ["--builtin", "card:label:C-"])
        self.assertEqual(out, "C-1 C-2\n")
        self.assertEqual(rec["total_redactions"], 2)


# ---------------------------------------------------------------------------
# RD-T17: 「ちょうど」の規律 — 対象外の形は 0.12.0 でも非検出
# ---------------------------------------------------------------------------

class RD_T17_ExactnessBoundaries(CardSeparatorBase):
    def test_not_detected_matrix(self):
        for body in (
                "4111 1111 1111",               # 12 桁
                "4111 1111-1111-1111",          # 区切りの混在
                "4111 - 1111 - 1111 - 1111",    # 2 文字の区切り
                "41111111 11111111",            # 8+8
                "4111111 11111111",             # 7+9
                "44111 1111 1111 1111",         # 先頭の桁が 5 桁
                "4111 1111 1111 11112",         # 末尾の桁が 5 桁
                "4111 1111 1111 1112",          # Luhn 不通
                "9999 9999 9999 9999",          # Luhn 不通
                "9999-9999-9999-9999",          # Luhn 不通 (ハイフン)
                "1234-5678-9012-3456"):         # Luhn 不通
            with self.subTest(body=body):
                self.assert_card_not_detected(body)

    def test_valid_tail_of_a_longer_run_is_still_observed(self):
        # 20 桁の鎖 (4,4,4,4,4) 自体は対象外だが、その末尾の 4 グループ
        # は境界が区切り文字で閉じた有効な 16 桁 — 鎖の始点は word ごと
        # に試すので、有効な番号の取りこぼしは起きない (fail-safe:
        # Luhn が通る形は隠れる)。
        out, rec = self.redact_text(
            "id: 4111 1111 1111 1111 2222\n",
            ["--builtin", "card:label:C-"])
        self.assertEqual(out, "id: 4111 C-1\n")
        self.assertEqual(rec["total_redactions"], 1)
        r = rec["redactions"][0]
        self.assertEqual(r["length"], len("1111 1111 1111 2222"))

    def test_unseparated_branch_is_unchanged(self):
        # 0.11.0 の無区切りの分岐はそのまま (13..19 桁・Luhn)。
        self.assert_card_detected("4111111111111111")
        self.assert_card_not_detected("4111111111111111112")  # 19 桁 Luhn 不通

    def test_other_matchers_are_untouched(self):
        # postal / phone の既存の一致は変わらない (区切りつき card の
        # 走査が他の matcher に染み出さないことの固定)。postal を先に
        # 宣言したとき phone の全体一致は重なりで棄却される — 0.11.0
        # からの既存の宣言順の作法 (0.11.0 の実測どおり)。
        out, rec = self.redact_text(
            "123-4567 090-1234-5678\n",
            ["--builtin", "postal-jp:label:P-",
             "--builtin", "phone-jp:label:T-"])
        self.assertEqual(out, "P-1 P-2-5678\n")
        self.assertEqual(rec["total_redactions"], 2)
        self.assertEqual(
            [r["matcher"] for r in rec["redactions"]],
            ["builtin:postal-jp", "builtin:postal-jp"])
        # postal に接したハイフン鎖は card の形にならない (3,4,4)。
        out, rec = self.redact_text(
            "123-4567-8901\n", ["--builtin", "postal-jp:label:P-",
                                "--builtin", "card:label:C-"])
        self.assertEqual(out, "P-1-8901\n")
        self.assertEqual(rec["total_redactions"], 1)
        self.assertEqual(rec["redactions"][0]["matcher"], "builtin:postal-jp")

    def test_luhn_gate_still_gates_unseparated(self):
        # 検査桁の門番は既存どおり (無区切り 12 桁 / 20 桁も対象外)。
        self.assert_card_not_detected("411111111111")          # 12 桁
        self.assert_card_not_detected("41111111111111111111")  # 20 桁


if __name__ == "__main__":
    unittest.main()

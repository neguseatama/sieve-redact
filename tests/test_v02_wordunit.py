#!/usr/bin/env python3
"""Sieve Redact v0.2 — 語単位一致 ('+' 接頭辞) の受け入れ試験.

境界規約: マッチ両端ごとに、辺文字 (マッチ側の端の文字) と隣接文字
(マッチの外側の文字) が (a) 同一クラス (6 文字クラス・非 None) または
(b) ともに ASCII 英数字、ならばそのマッチを棄却する。テキストの端は境界
(隣接文字なし = 棄却しない)。'_' は ASCII 英数字に含まない (境界扱い)。
どちらか片端でも棄却されれば、そのマッチ全体を棄却する。

命名注意: テストヘルパーは run_specs (unittest.TestCase.run と衝突しない
よう、フレームワークの公開名を避けている)。

実行:
    python3 -m unittest discover -s tests -v
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "sieve_redact.py"


def run_cli(args):
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + [str(a) for a in args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class WordUnitBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, text):
        p = self.dir / name
        p.write_bytes(text.encode("utf-8"))
        return p

    def read(self, path):
        return path.read_bytes().decode("utf-8")

    def ok_run(self, args):
        r = run_cli(args)
        self.assertEqual(
            r.returncode, 0,
            f"rc={r.returncode} stderr={r.stderr.decode('utf-8', 'replace')}")
        return r

    def run_specs(self, text, *pairs):
        """pairs: (flag, spec) の列。例: ("--rule", "秘密:+delete")"""
        inp = self.write("in.txt", text)
        out = self.dir / "out.txt"
        args = [inp, "-o", out]
        for flag, spec in pairs:
            args += [flag, spec]
        self.ok_run(args)
        return self.read(out)

    def run_receipt(self, text, *pairs):
        inp = self.write("in.txt", text)
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        args = [inp, "-o", out, "--receipt", rec]
        for flag, spec in pairs:
            args += [flag, spec]
        self.ok_run(args)
        data = json.loads(rec.read_bytes().decode("utf-8"))
        return self.read(out), data


class WordUnitBoundary(WordUnitBase):
    """クラス境界の棄却/採用。"""

    def test_hiragana_kanji_boundary_hits(self):
        # の(ひらがな)|秘(漢字) → クラス違い → ヒット
        self.assertEqual(
            self.run_specs("の秘密です", ("--rule", "秘密:+delete")), "のです")

    def test_kanji_contiguity_rejects(self):
        # 田中太郎 の中の 太郎: 太|中 が同クラス (漢字) → 棄却
        self.assertEqual(
            self.run_specs("田中太郎", ("--rule", "太郎:+delete")), "田中太郎")

    def test_latin_contiguity_rejects(self):
        # TaroGhibli の中の Taro: o|G はクラス違い (lower/upper) だが
        # ともに ASCII 英数字 → 棄却
        self.assertEqual(
            self.run_specs("TaroGhibli", ("--rule", "Taro:+delete")),
            "TaroGhibli")

    def test_ascii_alnum_cross_class_rejects(self):
        # o|2 (lower/digit) → 規則 (b) で棄却
        self.assertEqual(
            self.run_specs("Taro2024", ("--rule", "Taro:+delete")), "Taro2024")

    def test_digit_vs_kanji_hits(self):
        # 4|円: 円は ASCII 英数字でない → ヒット
        self.assertEqual(
            self.run_specs("1234円", ("--rule", "1234:+delete")), "円")

    def test_digit_vs_ascii_alnum_rejects(self):
        # x|1 (lower/digit) → 規則 (b) で棄却
        self.assertEqual(
            self.run_specs("x1234", ("--rule", "1234:+delete")), "x1234")

    def test_text_edges_are_boundaries(self):
        # テキスト端は隣接文字なし → 境界 (棄却しない)
        self.assertEqual(self.run_specs("太郎", ("--rule", "太郎:+delete")), "")
        # 片端だけでも棄却されればマッチ全体が棄却される
        self.assertEqual(
            self.run_specs("太郎中", ("--rule", "太郎:+delete")), "太郎中")
        self.assertEqual(
            self.run_specs("中太郎", ("--rule", "太郎:+delete")), "中太郎")

    def test_underscore_is_boundary(self):
        # '_' は ASCII 英数字に含まない → ヒット
        self.assertEqual(
            self.run_specs("Taro_姓", ("--rule", "Taro:+delete")), "_姓")


class WordUnitReceipt(WordUnitBase):
    """word_unit フィールド (additive — 語単位の redaction のみ出現)。"""

    def test_word_unit_receipt_fields(self):
        out, data = self.run_receipt("の秘密。", ("--rule", "秘密:+label:W"))
        self.assertEqual(out, "のW1。")
        self.assertEqual(data["total_redactions"], 1)
        reg = data["redactions"][0]
        self.assertEqual(reg["mode"], "label")      # 素の mode 名
        self.assertEqual(reg["matcher"], "literal")
        self.assertTrue(reg["word_unit"])

    def test_non_word_unit_receipt_has_no_word_unit_field(self):
        out, data = self.run_receipt("の秘密。", ("--rule", "秘密:label"))
        self.assertEqual(out, "の[REDACTED]1。")
        reg = data["redactions"][0]
        self.assertNotIn("word_unit", reg)


class PlainModeUnchanged(WordUnitBase):
    """'+' なしの従来挙動は不変 (連結内でも一致する)。"""

    def test_plain_mode_still_matches_contiguous(self):
        self.assertEqual(
            self.run_specs("田中太郎", ("--rule", "太郎:label")),
            "田中[REDACTED]1")


class BuiltinWordUnit(WordUnitBase):
    """--builtin の MODE にも '+' を許容する。"""

    def test_chars_word_unit_hits_at_symbol_boundary(self):
        # 【|B|】: 両隣ともクラス外記号 → ヒット
        self.assertEqual(
            self.run_specs("【B】", ("--builtin", "chars:U+0042:+delete")),
            "【】")

    def test_chars_word_unit_same_class_rejects(self):
        # A|B: 同一クラス (upper) → 棄却
        self.assertEqual(
            self.run_specs("AB", ("--builtin", "chars:U+0042:+delete")), "AB")


class WordUnitUsageErrors(WordUnitBase):
    """'+' の後は MODE が必須。未知 MODE は rc=2。"""

    def test_plus_empty_mode_is_usage_error(self):
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o", "--rule", "秘密:+"])
        self.assertEqual(r.returncode, 2)

    def test_plus_unknown_mode_is_usage_error(self):
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o", "--rule", "秘密:+wipe"])
        self.assertEqual(r.returncode, 2)

    def test_builtin_plus_unknown_mode_is_usage_error(self):
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o",
                     "--builtin", "phone-jp:+wipe"])
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()

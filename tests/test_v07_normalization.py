"""Sieve Redact v0.7 — 正規化ビュー照合 (builtin) の受け入れ試験。

Scope:
  - builtin (postal-jp / phone-jp / email) は正規化ビューで照合する
    - 全角 ASCII ブロック U+FF01..FF5E → U+0021..007E (1:1)
    - 異種ハイフン U+2010..2015 / U+2212 → '-' (1:1)
  - 正規化は 1 文字 → 1 文字なので位置は元テキストと同一。
    マスクは元の区間に適用され、他バイト完全性の検証はそのまま成立する
  - literal と chars は正規化の対象外 (宣言どおりの生照合)
  - noise same-class は、正規化ビューで照合したクラス外文字
    (全角数字など) を正規化後のクラスで置換する (マスク漏れ防止)
  - レシートは normalized: true を additive に記録する
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "sieve_redact.py"


class NormBase(unittest.TestCase):
    """Runs sieve_redact.py as a child process."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.dir = Path(tmp.name)
        self.addCleanup(tmp.cleanup)

    def write(self, name, text):
        p = self.dir / name
        p.write_text(text, encoding="utf-8")
        return p

    def read(self, p):
        return p.read_text(encoding="utf-8")

    def ok_run(self, args):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT)] + list(args),
            capture_output=True, text=True,
        )
        self.assertEqual(
            proc.returncode, 0,
            "unexpected rc=%d\nstdout:\n%s\nstderr:\n%s"
            % (proc.returncode, proc.stdout, proc.stderr),
        )
        return proc


class TestPostalFullWidth(NormBase):
    """postal-jp が全角数字 + 全角ハイフンを漏らさない。"""

    def test_fullwidth_postal_delete(self):
        inp = self.write("in.txt", "１５３－００１２")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "postal-jp:delete"])
        self.assertEqual(self.read(out), "")

    def test_fullwidth_postal_mosaic_length(self):
        # 8 文字 (1:1 正規化) → 文字数保存の █ 8 個
        inp = self.write("in.txt", "１５３－００１２")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "postal-jp:mosaic"])
        self.assertEqual(self.read(out), "█" * 8)

    def test_surrounding_text_untouched(self):
        inp = self.write("in.txt", "郵便１５３－００１２です")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "postal-jp:delete"])
        self.assertEqual(self.read(out), "郵便です")


class TestPhoneDashVariants(NormBase):
    """phone-jp が全角数字と異種ハイフンを漏らさない。"""

    def test_fullwidth_hyphen_ff0d(self):
        inp = self.write("in.txt", "090－1234－5678")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "")

    def test_u2010_hyphen(self):
        inp = self.write("in.txt", "090‐1234‐5678")  # U+2010
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "")

    def test_u2013_en_dash(self):
        inp = self.write("in.txt", "090–1234–5678")  # U+2013
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "")

    def test_mixed_width(self):
        # 半角と全角の混在 (実務で頻出)
        inp = self.write("in.txt", "090-１２３４-５６７８")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "")

    def test_fullwidth_phone_label(self):
        inp = self.write("in.txt", "０９０－１２３４－５６７８")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:label"])
        self.assertEqual(self.read(out), "[REDACTED]1")


class TestEmailFullWidth(NormBase):
    """email が全角英数字・全角アット・全角ドットを漏らさない。"""

    def test_fullwidth_email_delete(self):
        inp = self.write("in.txt", "ＴＡＲＯ＠ＥＸＡＭＰＬＥ．ＣＯＭ")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "email:delete"])
        self.assertEqual(self.read(out), "")


class TestLiteralAndCharsStayExact(NormBase):
    """literal と chars は正規化の対象外 (宣言どおりの生照合)。"""

    def test_literal_not_normalized(self):
        # 半角 TARO は全角パターン ＴＡＲＯ には一致しない
        inp = self.write("in.txt", "TARO")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "ＴＡＲＯ:label"])
        self.assertEqual(self.read(out), "TARO")

    def test_literal_fullwidth_matches_fullwidth(self):
        inp = self.write("in.txt", "xＴＡＲＯy")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "ＴＡＲＯ:delete"])
        self.assertEqual(self.read(out), "xy")

    def test_chars_stays_codepoint_exact(self):
        # chars は元のコードポイントを見る: U+FF0D のみ削除
        inp = self.write("in.txt", "090－1234－5678")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "chars:U+FF0D:delete"])
        self.assertEqual(self.read(out), "09012345678")


class TestNoiseWithNormalization(NormBase):
    """noise の same-class が正規化後クラスに追随する。"""

    def test_same_class_replaces_fullwidth_digits(self):
        text = "０９０－１２３４－５６７８"
        inp = self.write("in.txt", text)
        out1 = self.dir / "out1.txt"
        out2 = self.dir / "out2.txt"
        self.ok_run([inp, "-o", out1, "--builtin", "phone-jp:noise"])
        self.ok_run([inp, "-o", out2, "--builtin", "phone-jp:noise"])
        n1 = self.read(out1)
        self.assertEqual(n1, self.read(out2))          # 決定的
        self.assertEqual(len(n1), len(text))           # 長さ保存
        self.assertEqual(n1[3], "－")                   # 全角ハイフンは据え置き
        self.assertEqual(n1[8], "－")
        self.assertNotEqual(n1, text)                  # 数字は実際に置換
        for i, ch in enumerate(n1):
            if i not in (3, 8):
                self.assertIn(ch, "0123456789")        # ASCII digit で置換

    def test_en_dash_stays_in_same_class(self):
        # 異種ハイフンも正規化後もクラス外 → 据え置き
        text = "090–1234–5678"
        inp = self.write("in.txt", text)
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:noise"])
        n = self.read(out)
        self.assertEqual(n[3], "–")
        self.assertEqual(n[8], "–")

    def test_explicit_pool_replaces_everything(self):
        # 明示 pool (digit) は区間の全文字 (ハイフン含む) を
        # ASCII digit で置換する
        text = "０９０－１２３４－５６７８"
        inp = self.write("in.txt", text)
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out,
                     "--builtin", "phone-jp:noise:digit"])
        n = self.read(out)
        self.assertEqual(len(n), len(text))
        for ch in n:
            self.assertIn(ch, "0123456789")


class TestReceiptNormalizedFlag(NormBase):
    """normalized フラグは additive (正規化が効いた区間のみ)。"""

    def test_flag_set_for_fullwidth(self):
        inp = self.write("in.txt", "１５３－００１２")
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        self.ok_run([inp, "-o", out, "--builtin", "postal-jp:label",
                     "--receipt", rec])
        data = json.loads(rec.read_text(encoding="utf-8"))
        self.assertTrue(data["byte_integrity_verified"])
        reg = data["redactions"][0]
        self.assertEqual(reg["matcher"], "builtin:postal-jp")
        self.assertEqual(reg["length"], 24)  # 全角 8 文字 = UTF-8 24 バイト
        self.assertTrue(reg["normalized"])

    def test_flag_absent_for_ascii(self):
        inp = self.write("in.txt", "153-0012")
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        self.ok_run([inp, "-o", out, "--builtin", "postal-jp:label",
                     "--receipt", rec])
        data = json.loads(rec.read_text(encoding="utf-8"))
        self.assertNotIn("normalized", data["redactions"][0])

    def test_human_receipt_marker(self):
        inp = self.write("in.txt", "１５３－００１２")
        out = self.dir / "out.txt"
        proc = self.ok_run([inp, "-o", out, "--builtin", "postal-jp:label"])
        self.assertIn(" normalized", proc.stdout)


if __name__ == "__main__":
    unittest.main()

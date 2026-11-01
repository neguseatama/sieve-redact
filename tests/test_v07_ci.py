"""Sieve Redact v0.7 — '~' 接頭辞 (ASCII 大小無視一致) の受け入れ試験。

Scope:
  - MODE に '~' 接頭辞を付けると ASCII の大小を無視して照合する
    ('+' との併用可・順序は任意: +~label / ~+label)
  - 折りたたみは ASCII の 1:1 変換のみ (非 ASCII はそのまま)。
    位置対応が保たれるので他バイト完全性の検証はそのまま成立する
  - chars は指定コードポイントの ASCII 大小両方を対象にする
  - 組込 matcher は大小非依存 (email は英字を両 case 受理) なので
    '~' は動作を変えない
  - pattern_appearance_in_output は '~' ルールを折りたたみ同士で測定する
  - レシートは case_insensitive: true を additive に記録する
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "sieve_redact.py"


class CIBase(unittest.TestCase):
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

    def rc_run(self, args, rc):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT)] + list(args),
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, rc, proc.stderr)
        return proc


class TestLiteralCaseInsensitive(CIBase):
    def test_delete_all_case_variants(self):
        inp = self.write("in.txt", "TARO and taro and Taro")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "Taro:~delete"])
        self.assertEqual(self.read(out), " and  and ")

    def test_mixed_pattern(self):
        inp = self.write("in.txt", "abc ABC aBc AbC")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "AbC:~delete"])
        self.assertEqual(self.read(out), "   ")

    def test_non_ascii_not_folded(self):
        # 折りたたみは ASCII のみ: 半角パターンは全角テキストに一致しない
        inp = self.write("in.txt", "ＴＡＲＯ")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "Taro:~delete"])
        self.assertEqual(self.read(out), "ＴＡＲＯ")

    def test_fullwidth_pattern_matches_fullwidth(self):
        inp = self.write("in.txt", "xＴＡＲＯy")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "ＴＡＲＯ:~delete"])
        self.assertEqual(self.read(out), "xy")

    def test_word_unit_compose_plus_tilde(self):
        # +~ 併用: 境界で拒否される語は残る
        inp = self.write("in.txt", "x taro TAROy")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "taro:+~delete"])
        self.assertEqual(self.read(out), "x  TAROy")

    def test_word_unit_compose_tilde_plus(self):
        # 順序は任意: ~+delete も受理
        inp = self.write("in.txt", "x taro TAROy")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "taro:~+delete"])
        self.assertEqual(self.read(out), "x  TAROy")

    def test_label_numbering(self):
        inp = self.write("in.txt", "TARO,taro")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "taro:~label"])
        self.assertEqual(self.read(out), "[REDACTED]1,[REDACTED]2")


class TestCharsCaseInsensitive(CIBase):
    def test_uppercase_target_matches_both(self):
        inp = self.write("in.txt", "aAあ")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "chars:U+0041:~delete"])
        self.assertEqual(self.read(out), "あ")

    def test_lowercase_target_matches_both(self):
        inp = self.write("in.txt", "aA")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "chars:U+0061:~delete"])
        self.assertEqual(self.read(out), "")

    def test_without_ci_stays_exact(self):
        inp = self.write("in.txt", "aAあ")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "chars:U+0041:delete"])
        self.assertEqual(self.read(out), "aあ")


class TestBuiltinsUnaffected(CIBase):
    def test_email_ci_is_noop(self):
        # email は英字を両 case 受理するので '~' で動作は変わらない
        inp = self.write("in.txt", "TARO@EXAMPLE.COM")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "email:~delete"])
        self.assertEqual(self.read(out), "")

    def test_postal_ci_is_noop(self):
        inp = self.write("in.txt", "153-0012")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "postal-jp:~mosaic"])
        self.assertEqual(self.read(out), "█" * 8)


class TestAppearanceAndReceipt(CIBase):
    def test_appearance_is_ci_aware(self):
        # 境界拒否で残留した大小別形も '~' ルールの測定で検出する
        inp = self.write("in.txt", "xTAROx")
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        self.ok_run([inp, "-o", out, "--rule", "taro:+~delete",
                     "--receipt", rec])
        self.assertEqual(self.read(out), "xTAROx")
        data = json.loads(rec.read_text(encoding="utf-8"))
        self.assertEqual(data["pattern_appearance_in_output"], "found")

    def test_appearance_exact_unchanged(self):
        # '~' なしの従来測定 (完全一致のみ)
        inp = self.write("in.txt", "xx")
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        self.ok_run([inp, "-o", out, "--rule", "TARO:delete",
                     "--receipt", rec])
        data = json.loads(rec.read_text(encoding="utf-8"))
        self.assertEqual(data["pattern_appearance_in_output"], "none")

    def test_receipt_ci_flag(self):
        inp = self.write("in.txt", "taro")
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        self.ok_run([inp, "-o", out, "--rule", "Taro:~label",
                     "--receipt", rec])
        data = json.loads(rec.read_text(encoding="utf-8"))
        self.assertTrue(data["byte_integrity_verified"])
        self.assertTrue(data["redactions"][0]["case_insensitive"])

    def test_receipt_flag_absent_without_tilde(self):
        inp = self.write("in.txt", "Taro")
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        self.ok_run([inp, "-o", out, "--rule", "Taro:label",
                     "--receipt", rec])
        data = json.loads(rec.read_text(encoding="utf-8"))
        self.assertNotIn("case_insensitive", data["redactions"][0])

    def test_human_receipt_marker(self):
        inp = self.write("in.txt", "taro")
        out = self.dir / "out.txt"
        proc = self.ok_run([inp, "-o", out, "--rule", "Taro:~label"])
        self.assertIn(" ci", proc.stdout)


class TestModeParsing(CIBase):
    def test_unknown_mode_after_prefix_rc2(self):
        inp = self.write("in.txt", "x")
        out = self.dir / "out.txt"
        self.rc_run([inp, "-o", out, "--rule", "x:~bogus"], 2)

    def test_bare_tilde_rc2(self):
        inp = self.write("in.txt", "x")
        out = self.dir / "out.txt"
        self.rc_run([inp, "-o", out, "--rule", "x:~"], 2)

    def test_bare_plus_tilde_rc2(self):
        inp = self.write("in.txt", "x")
        out = self.dir / "out.txt"
        self.rc_run([inp, "-o", out, "--rule", "x:+~"], 2)


if __name__ == "__main__":
    unittest.main()

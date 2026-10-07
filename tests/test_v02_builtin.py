#!/usr/bin/env python3
"""Sieve Redact v0.2 — 組込文字種 (--builtin) の受け入れ試験.

実行:
    python3 -m unittest discover -s tests -v
"""

import hashlib
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


class BuiltinBase(unittest.TestCase):
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


class BuiltinPostalJp(BuiltinBase):
    """postal-jp = [0-9]{3}-[0-9]{4}、両側 digit 境界。"""

    def test_basic_mosaic(self):
        # 123-4567 = 8 文字 → mosaic は文字数保存
        inp = self.write("in.txt", "〒123-4567")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "postal-jp:mosaic"])
        self.assertEqual(self.read(out), "〒" + "█" * 8)

    def test_digit_boundary_rejects(self):
        # 前後に digit が続くため不一致 (境界拒否)
        inp = self.write("in.txt", "01234-56789")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "postal-jp:delete"])
        self.assertEqual(self.read(out), "01234-56789")

    def test_label_arg(self):
        inp = self.write("in.txt", "郵便番号は123-4567です")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "postal-jp:label:〒"])
        self.assertEqual(self.read(out), "郵便番号は〒1です")

    def test_multiple_receipt_positions(self):
        body = "123-4567 と 987-6543"
        inp = self.write("in.txt", body)
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        self.ok_run([inp, "-o", out, "--builtin", "postal-jp:delete",
                     "--receipt", rec])
        data = json.loads(rec.read_bytes().decode("utf-8"))
        self.assertEqual(data["total_redactions"], 2)
        regs = sorted(data["redactions"], key=lambda x: x["start"])
        ib = inp.read_bytes()
        for reg, pat in zip(regs, ("123-4567", "987-6543")):
            self.assertEqual(reg["matcher"], "builtin:postal-jp")
            self.assertEqual(ib[reg["start"]:reg["end"]].decode("utf-8"), pat)
        self.assertEqual(self.read(out), " と ")


class BuiltinPhoneJp(BuiltinBase):
    """phone-jp = 0 開始 (2,4,4)/(3,3,4)/(3,4,4)、両側 digit 境界。"""

    def test_mobile_mosaic(self):
        # 090-1234-5678 = 13 文字
        inp = self.write("in.txt", "TEL:090-1234-5678")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:mosaic"])
        self.assertEqual(self.read(out), "TEL:" + "█" * 13)

    def test_tokyo_2_4_4(self):
        inp = self.write("in.txt", "03-1234-5678")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "")

    def test_nagoya_3_3_4(self):
        inp = self.write("in.txt", "052-123-4567")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "")

    def test_leading_digit_boundary_rejects(self):
        # 090-1234-5678 が含まれるが直前が digit → 全体不一致 (境界拒否)
        inp = self.write("in.txt", "1090-1234-5678")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "1090-1234-5678")

    def test_non_zero_start_rejected(self):
        # 0 開始でないため不一致
        inp = self.write("in.txt", "123-4567-8901")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "123-4567-8901")

    def test_rule_wins_when_declared_first(self):
        # --rule と --builtin は同一リスト・宣言順に解決される
        inp = self.write("in.txt", "090-1234-5678")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out,
                     "--rule", "090-1234-5678:label",
                     "--builtin", "phone-jp:mosaic"])
        self.assertEqual(self.read(out), "[REDACTED]1")

    def test_builtin_wins_when_declared_first(self):
        inp = self.write("in.txt", "090-1234-5678")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out,
                     "--builtin", "phone-jp:mosaic",
                     "--rule", "090-1234-5678:label"])
        self.assertEqual(self.read(out), "█" * 13)


class BuiltinEmail(BuiltinBase):
    """email = ASCII 簡易 local@domain。"""

    def test_basic_mosaic(self):
        # taro@example.com = 16 文字
        inp = self.write("in.txt", "mail:taro@example.com 宛")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "email:mosaic"])
        self.assertEqual(self.read(out), "mail:" + "█" * 16 + " 宛")

    def test_leading_dot_excluded(self):
        # 先頭 '.' は一致に含めない — 手前は残る。
        # taro@example.com は 16 文字 (test_basic_mosaic と同一文字列)。
        inp = self.write("in.txt", ".taro@example.com")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "email:mosaic"])
        self.assertEqual(self.read(out), "." + "█" * 16)

    def test_domain_without_dot_rejected(self):
        inp = self.write("in.txt", "taro@localhost")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "email:delete"])
        self.assertEqual(self.read(out), "taro@localhost")

    def test_short_tld_rejected(self):
        # TLD は英字 2 以上
        inp = self.write("in.txt", "taro@example.c")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "email:delete"])
        self.assertEqual(self.read(out), "taro@example.c")

    def test_trailing_dot_run_rejected(self):
        # 末尾境界: 直後が '.' → 全体拒否 (部分一致を残さない)
        inp = self.write("in.txt", "taro@example.com..jp")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "email:delete"])
        self.assertEqual(self.read(out), "taro@example.com..jp")

    def test_japanese_punct_boundary(self):
        # '、' は非 ASCII 境界 → 手前まで一致
        inp = self.write("in.txt", "taro@example.com、注文")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "email:mosaic"])
        self.assertEqual(self.read(out), "█" * 16 + "、注文")


class BuiltinChars(BuiltinBase):
    """chars = U+XXXX,.. の各コードポイント単独出現に適用。"""

    def test_zwsp_delete(self):
        # A + U+200B + B → AB
        inp = self.write("in.txt", "A\u200bB")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "chars:U+200B:delete"])
        self.assertEqual(self.read(out), "AB")

    def test_multiple_codepoints(self):
        inp = self.write("in.txt", "x\u200by\u00adz")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out,
                     "--builtin", "chars:U+200B,U+00AD:delete"])
        self.assertEqual(self.read(out), "xyz")

    def test_invalid_codepoint_is_usage_error(self):
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o",
                     "--builtin", "chars:U+ZZZZ:delete"])
        self.assertEqual(r.returncode, 2)

    def test_surrogate_is_usage_error(self):
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o",
                     "--builtin", "chars:U+D800:delete"])
        self.assertEqual(r.returncode, 2)


class BuiltinNoiseSeed(BuiltinBase):
    """組込 noise のハッシュ式シード。"""

    def test_chars_noise_canonical_seed(self):
        # 入力表記 u+0041 (小文字) でも seed は正規化形 "chars:U+0041"
        body = "xAy"
        inp = self.write("in.txt", body)
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out,
                     "--builtin", "chars:u+0041:noise:digit"])
        got = self.read(out)
        h = hashlib.sha256("chars:U+0041:1:A".encode("utf-8")).digest()
        expected = "x" + "0123456789"[h[0] % 10] + "y"
        self.assertEqual(got, expected)

    def test_phone_noise_name_seed(self):
        # name 型の seed は NAME そのもの。'-' はクラス外で据え置き
        body = "090-1234-5678"
        inp = self.write("in.txt", body)
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:noise"])
        got = self.read(out)
        self.assertEqual(len(got), 13)
        exp = []
        for k, ch in enumerate(body):  # 全 ASCII なのでバイト位置 = 文字位置
            if ch == "-":
                exp.append(ch)
                continue
            h = hashlib.sha256(f"phone-jp:{k}:{ch}".encode("utf-8")).digest()
            exp.append("0123456789"[h[0] % 10])
        self.assertEqual(got, "".join(exp))


class BuiltinReceipt(BuiltinBase):
    """redactions[*] の matcher フィールド (additive)。"""

    def test_matcher_field(self):
        inp = self.write("in.txt", "090-1234-5678")
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        self.ok_run([inp, "-o", out,
                     "--builtin", "phone-jp:label:TEL-", "--receipt", rec])
        data = json.loads(rec.read_bytes().decode("utf-8"))
        self.assertEqual(data["total_redactions"], 1)
        reg = data["redactions"][0]
        self.assertEqual(reg["matcher"], "builtin:phone-jp")
        self.assertEqual(reg["mode"], "label")
        self.assertEqual(reg["start"], 0)
        self.assertEqual(reg["length"], 13)
        self.assertEqual(reg["replacement_length"],
                         len("TEL-1".encode("utf-8")))
        self.assertTrue(data["byte_integrity_verified"])
        self.assertEqual(self.read(out), "TEL-1")


class RuleStaysLiteral(BuiltinBase):
    """--rule に特殊解釈を導入しない ('@' も生文字列)。"""

    def test_at_sign_pattern_stays_literal(self):
        inp = self.write("in.txt", "x@phone:y")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "@phone:delete"])
        self.assertEqual(self.read(out), "x:y")


if __name__ == "__main__":
    unittest.main()

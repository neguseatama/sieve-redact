#!/usr/bin/env python3
"""Sieve Redact v0.3 — replace 様式 / from-lens twin / phone 拡張形.

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


class V03Base(unittest.TestCase):
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


class ReplaceMode(V03Base):
    """replace 様式 — 区間を ARG で一括置換 (ARG 必須・空は rc2)。"""

    def test_chars_replace_basic(self):
        # U+044F (キリル я) を R に置換
        inp = self.write("in.txt", "x\u044fb")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "chars:U+044F:replace:R"])
        self.assertEqual(self.read(out), "xRb")

    def test_literal_replace(self):
        inp = self.write("in.txt", "x秘密y")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "秘密:replace:[REMOVED]"])
        self.assertEqual(self.read(out), "x[REMOVED]y")

    def test_replace_arg_missing_rc2(self):
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o",
                     "--builtin", "chars:U+0041:replace"])
        self.assertEqual(r.returncode, 2)

    def test_replace_empty_arg_rc2(self):
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o",
                     "--builtin", "chars:U+0041:replace:"])
        self.assertEqual(r.returncode, 2)

    def test_replace_word_unit(self):
        # '+' 接頭辞は全 MODE に一般化 → '+replace' も可
        inp = self.write("in.txt", "の太郎")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "太郎:+replace:■"])
        self.assertEqual(self.read(out), "の■")

    def test_replace_receipt(self):
        inp = self.write("in.txt", "x秘密y")
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        self.ok_run([inp, "-o", out, "--rule", "秘密:replace:AB",
                     "--receipt", rec])
        self.assertEqual(self.read(out), "xABy")
        data = json.loads(rec.read_bytes().decode("utf-8"))
        reg = data["redactions"][0]
        self.assertEqual(reg["mode"], "replace")
        self.assertEqual(reg["matcher"], "literal")
        self.assertEqual(reg["start"], 1)
        self.assertEqual(reg["end"], 7)
        self.assertEqual(reg["length"], 6)              # 秘密 = 6 バイト
        self.assertEqual(reg["replacement_length"], 2)  # "AB"
        self.assertNotIn("word_unit", reg)


class FromLensTwin(V03Base):
    """観測の省略可能フィールド twin → chars:CP:replace:<twin> を生成。"""

    def write_lens(self, observations):
        return self.write("obs.json", json.dumps({
            "lens": "sieve-lens", "version": 1,
            "observations": observations}))

    def test_from_lens_twin_generates_replace(self):
        lens = self.write_lens([
            {"kind": "H2", "codepoint": "U+200B"},
            {"kind": "homoglyph", "codepoint": "U+0430", "twin": "U+0061"},
        ])
        inp = self.write("in.txt", "t\u0430rget\u200b.com")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--from-lens", lens])
        self.assertEqual(self.read(out), "target.com")

    def test_from_lens_twin_surrogate_rc2(self):
        lens = self.write_lens([
            {"kind": "homoglyph", "codepoint": "U+0430", "twin": "U+D800"}])
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o", "--from-lens", lens])
        self.assertEqual(r.returncode, 2)

    def test_from_lens_twin_malformed_rc2(self):
        # twin は U+XXXX 表記のみ ('a' は書式不正)
        lens = self.write_lens([
            {"kind": "homoglyph", "codepoint": "U+0430", "twin": "a"}])
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o", "--from-lens", lens])
        self.assertEqual(r.returncode, 2)

    def test_from_lens_twin_multi_rc2(self):
        # twin は単一コードポイントのみ
        lens = self.write_lens([
            {"kind": "homoglyph", "codepoint": "U+0430",
             "twin": "U+0061,U+0062"}])
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o", "--from-lens", lens])
        self.assertEqual(r.returncode, 2)

    def test_from_lens_dedup_first_entry_properties(self):
        # 同一 codepoint の重複は初出エントリの属性を採用 (twin ありを採用)
        lens = self.write_lens([
            {"kind": "homoglyph", "codepoint": "U+0430", "twin": "U+0061"},
            {"kind": "H2", "codepoint": "U+0430"},
        ])
        inp = self.write("in.txt", "\u0430X\u0430")
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        self.ok_run([inp, "-o", out, "--from-lens", lens, "--receipt", rec])
        self.assertEqual(self.read(out), "aXa")
        data = json.loads(rec.read_bytes().decode("utf-8"))
        self.assertEqual(data["total_redactions"], 2)
        regs = sorted(data["redactions"], key=lambda x: x["start"])
        self.assertEqual([reg["start"] for reg in regs], [0, 3])
        for reg in regs:
            self.assertEqual(reg["rule_index"], 1)  # 重複排除で 1 ルール
            self.assertEqual(reg["matcher"], "builtin:chars")
            self.assertEqual(reg["mode"], "replace")


class Probe7V03(V03Base):
    """同形文字 + 不可視文字の合成往復。"""

    def test_roundtrip_homoglyph_and_invisible(self):
        lens = self.write("obs.json", json.dumps({
            "lens": "sieve-lens", "version": 1,
            "observations": [
                {"kind": "H2", "codepoint": "U+200B"},
                {"kind": "homoglyph", "codepoint": "U+0430",
                 "twin": "U+0061"},
            ]}))
        body = "連絡先 t\u0430rget\u200b.example"
        inp = self.write("in.txt", body)
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        self.ok_run([inp, "-o", out, "--from-lens", lens, "--receipt", rec])
        got = self.read(out)
        self.assertEqual(got, "連絡先 target.example")
        # 再観測 (テスト内の独立再計数): 対象コードポイントが 0 個
        self.assertEqual(got.count("\u200b") + got.count("\u0430"), 0)
        data = json.loads(rec.read_bytes().decode("utf-8"))
        self.assertTrue(data["byte_integrity_verified"])
        self.assertEqual(data["total_redactions"], 2)


class PhoneExtension(V03Base):
    """phone-jp 拡張形。(4,3,3) は接頭辞 {0120,0570,0800}・
    (4,2,4) は接頭辞 0[1-6]xx (かつ (4,3,3) 接頭辞を除外)。"""

    def test_0120_433_delete(self):
        inp = self.write("in.txt", "0120-123-456")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "")

    def test_0570_433_mosaic(self):
        inp = self.write("in.txt", "0570-123-456")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:mosaic"])
        self.assertEqual(self.read(out), "█" * 12)

    def test_0800_433_label(self):
        inp = self.write("in.txt", "0800-123-456")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:label"])
        self.assertEqual(self.read(out), "[REDACTED]1")

    def test_424_area_delete(self):
        # 0154 (釧路) のような 4 桁市外局番 + 2+4
        inp = self.write("in.txt", "0154-41-4894")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "")

    def test_09xx_424_guard_unchanged(self):
        # (4,2,4) は 0[1-6]xx に限定 → 0912 は不一致のまま
        inp = self.write("in.txt", "0912-34-5678")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "0912-34-5678")

    def test_0120_424_excluded_unchanged(self):
        # 0120 は (4,3,3) 専用接頭辞 → (4,2,4) としては不一致
        inp = self.write("in.txt", "0120-45-6789")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "0120-45-6789")

    def test_trailing_digit_boundary_unchanged(self):
        # 直後に digit → (4,3,3) 境界拒否・(4,2,4) は接頭辞除外 → 不一致
        inp = self.write("in.txt", "0120-123-4567")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "0120-123-4567")


if __name__ == "__main__":
    unittest.main()

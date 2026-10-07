#!/usr/bin/env python3
"""Sieve Redact v0.2 — 設定ファイル --config / --from-lens の受け入れ試験.

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

# Sieve Lens の観測対象コードポイント (H2/H3 の実集合)
LENS_H2 = ("U+200B", "U+200C", "U+200D", "U+2060", "U+FEFF")
LENS_H3 = ("U+202A", "U+202E", "U+2066")


def run_cli(args):
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + [str(a) for a in args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class ConfigLensBase(unittest.TestCase):
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


class ConfigApply(ConfigLensBase):
    """--config の行書式と適用順 (config → CLI)。"""

    def test_config_rule_applies(self):
        cfg = self.write("rules.cfg", "rule 秘密:delete\n")
        inp = self.write("in.txt", "x秘密y")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--config", cfg])
        self.assertEqual(self.read(out), "xy")

    def test_config_builtin_applies(self):
        # 非マッチ区間の 〒 は他バイト完全性により必ず残る
        # (〒 は digit でないため、一致区間の直前にあってもマッチは成立する)。
        cfg = self.write("rules.cfg", "builtin postal-jp:label:〒\n")
        inp = self.write("in.txt", "123-4567")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--config", cfg])
        self.assertEqual(self.read(out), "〒1")

    def test_config_before_cli_declaration_order(self):
        # config の行は CLI より先に宣言されたものとして扱われる。
        # config の AB が先に確定し、CLI の B は重なりで棄却される。
        cfg = self.write("rules.cfg", "rule AB:delete\n")
        inp = self.write("in.txt", "ABAB")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--config", cfg, "--rule", "B:delete"])
        self.assertEqual(self.read(out), "")

    def test_config_spec_keeps_inner_space(self):
        # kind 後の最初の空白 1 個で分離 → spec 内に空白を含められる
        cfg = self.write("rules.cfg", "rule あ い:delete\n")
        inp = self.write("in.txt", "xあ いy")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--config", cfg])
        self.assertEqual(self.read(out), "xy")

    def test_config_comments_and_blank_lines(self):
        cfg = self.write(
            "rules.cfg",
            "# 先頭コメント\n\nrule 秘密:delete\n  \n# 末尾コメント\n")
        inp = self.write("in.txt", "x秘密y")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--config", cfg])
        self.assertEqual(self.read(out), "xy")

    def test_config_word_unit_rule(self):
        # config 経由でも '+' 接頭辞 (語単位一致) が使える
        cfg = self.write("rules.cfg", "rule 太郎:+delete\n")
        inp = self.write("in.txt", "の太郎")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--config", cfg])
        self.assertEqual(self.read(out), "の")

    def test_config_missing_is_rc1(self):
        inp = self.write("in.txt", "x")
        out = self.dir / "out.txt"
        r = run_cli([inp, "-o", out,
                     "--config", str(self.dir / "no-such.cfg")])
        self.assertEqual(r.returncode, 1)
        self.assertFalse(out.exists())


class ConfigErrors(ConfigLensBase):
    """未知 kind・書式不正は rc2。"""

    def test_unknown_kind_is_rc2(self):
        cfg = self.write("rules.cfg", "foo bar\n")
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o", "--config", cfg])
        self.assertEqual(r.returncode, 2)

    def test_rule_line_without_spec_is_rc2(self):
        cfg = self.write("rules.cfg", "rule\n")
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o", "--config", cfg])
        self.assertEqual(r.returncode, 2)


class FromLens(ConfigLensBase):
    """--from-lens 観測 JSON (version 1) からの chars:U+XXXX:delete 生成。"""

    def test_from_lens_deletes(self):
        lens = self.write("obs.json", json.dumps({
            "lens": "sieve-lens", "version": 1,
            "observations": [
                {"kind": "H2", "codepoint": "U+200B",
                 "count": 1, "positions": [1]},
                {"kind": "H3", "codepoint": "U+202E",
                 "count": 1, "positions": [3]},
            ]}))
        inp = self.write("in.txt", "A\u200bB\u202eC")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--from-lens", lens])
        self.assertEqual(self.read(out), "ABC")

    def test_from_lens_kind_ignored_and_dedup(self):
        # kind は生成に使わない。同一 codepoint は重複排除で 1 ルール。
        lens = self.write("obs.json", json.dumps({
            "lens": "sieve-lens", "version": 1,
            "observations": [
                {"kind": "H2", "codepoint": "U+200B"},
                {"kind": "H7", "codepoint": "U+200B"},
            ]}))
        inp = self.write("in.txt", "A\u200bB\u200bC")
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        self.ok_run([inp, "-o", out, "--from-lens", lens, "--receipt", rec])
        self.assertEqual(self.read(out), "ABC")
        data = json.loads(rec.read_bytes().decode("utf-8"))
        self.assertEqual(data["total_redactions"], 2)  # 出現 2 箇所

    def test_from_lens_first_seen_order(self):
        # 生成は初出順 (JSON の観測順)。rule_index がその順になる。
        lens = self.write("obs.json", json.dumps({
            "lens": "sieve-lens", "version": 1,
            "observations": [
                {"kind": "H2", "codepoint": "U+200B"},
                {"kind": "H2", "codepoint": "U+00AD"},
            ]}))
        inp = self.write("in.txt", "\u00adあ\u200b")
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        self.ok_run([inp, "-o", out, "--from-lens", lens, "--receipt", rec])
        self.assertEqual(self.read(out), "あ")
        data = json.loads(rec.read_bytes().decode("utf-8"))
        regs = sorted(data["redactions"], key=lambda x: x["start"])
        # 位置昇順で先の 00AD は後から生成されたルール (index 2)
        self.assertEqual(regs[0]["rule_index"], 2)
        self.assertEqual(regs[1]["rule_index"], 1)

    def test_from_lens_positions_optional(self):
        lens = self.write("obs.json", json.dumps({
            "lens": "sieve-lens", "version": 1,
            "observations": [{"kind": "H2", "codepoint": "U+200B"}]}))
        inp = self.write("in.txt", "x\u200by")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--from-lens", lens])
        self.assertEqual(self.read(out), "xy")

    def test_from_lens_declaration_order_against_rule(self):
        # from-lens はフラグ位置に展開される。
        lens = self.write("obs.json", json.dumps({
            "lens": "sieve-lens", "version": 1,
            "observations": [{"kind": "H2", "codepoint": "U+0042"}]}))
        # from-lens を先に → B は from-lens (delete) が勝つ
        inp = self.write("in.txt", "AB")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--from-lens", lens,
                     "--rule", "B:label:X"])
        self.assertEqual(self.read(out), "A")
        # --rule を先に → label が勝ち、from-lens の B は重なりで棄却
        inp2 = self.write("in2.txt", "AB")
        out2 = self.dir / "out2.txt"
        self.ok_run([inp2, "-o", out2, "--rule", "B:label:X",
                     "--from-lens", lens])
        self.assertEqual(self.read(out2), "AX1")

    def test_from_lens_missing_is_rc1(self):
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o",
                     "--from-lens", str(self.dir / "no-such.json")])
        self.assertEqual(r.returncode, 1)

    def test_from_lens_version2_is_rc2(self):
        lens = self.write("obs.json", json.dumps({
            "lens": "sieve-lens", "version": 2, "observations": []}))
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o", "--from-lens", lens])
        self.assertEqual(r.returncode, 2)

    def test_from_lens_broken_json_is_rc2(self):
        lens = self.write("obs.json", "{not json")
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o", "--from-lens", lens])
        self.assertEqual(r.returncode, 2)

    def test_from_lens_bad_observation_is_rc2(self):
        lens = self.write("obs.json", json.dumps({
            "lens": "sieve-lens", "version": 1,
            "observations": [{"kind": "H2"}]}))  # codepoint なし
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o", "--from-lens", lens])
        self.assertEqual(r.returncode, 2)

    def test_from_lens_bad_codepoint_is_rc2(self):
        lens = self.write("obs.json", json.dumps({
            "lens": "sieve-lens", "version": 1,
            "observations": [{"kind": "H2", "codepoint": "U+ZZZZ"}]}))
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o", "--from-lens", lens])
        self.assertEqual(r.returncode, 2)


class Probe7RoundTrip(ConfigLensBase):
    """合成入力での往復 (観測 → 生成 → 適用 → 再観測)。"""

    def test_roundtrip_removes_all_observed(self):
        all_cps = LENS_H2 + LENS_H3
        body = ("報告書" + chr(0x200B) + " 田中太郎" + chr(0x202E)
                + " 連絡先" + chr(0x2060))
        lens = self.write("obs.json", json.dumps({
            "lens": "sieve-lens", "version": 1,
            "observations": [{"kind": "H2", "codepoint": cp}
                             for cp in LENS_H2]
            + [{"kind": "H3", "codepoint": cp} for cp in LENS_H3]}))
        inp = self.write("in.txt", body)
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        self.ok_run([inp, "-o", out, "--from-lens", lens, "--receipt", rec])
        got = self.read(out)
        # 再観測 (テスト内の独立再計数): 対象コードポイントが 0 個
        remaining = sum(got.count(chr(int(cp[2:], 16))) for cp in all_cps)
        self.assertEqual(remaining, 0)
        # 本文は無傷
        self.assertEqual(got, "報告書 田中太郎 連絡先")
        data = json.loads(rec.read_bytes().decode("utf-8"))
        self.assertTrue(data["byte_integrity_verified"])
        self.assertEqual(data["total_redactions"], 3)  # 出現 3 箇所

    def test_roundtrip_pattern_appearance_stays_none(self):
        # 測定値の継続性: from-lens は literal パターンを持たないため none
        lens = self.write("obs.json", json.dumps({
            "lens": "sieve-lens", "version": 1,
            "observations": [{"kind": "H2", "codepoint": "U+200B"}]}))
        inp = self.write("in.txt", "a\u200bb")
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        self.ok_run([inp, "-o", out, "--from-lens", lens, "--receipt", rec])
        data = json.loads(rec.read_bytes().decode("utf-8"))
        self.assertEqual(data["pattern_appearance_in_output"], "none")


class GlobalOrder(ConfigLensBase):
    """config → from-lens → CLI の順で宣言順リストが構築される。"""

    def test_config_fromlens_cli_order(self):
        cfg = self.write("rules.cfg", "rule B:label:B\n")
        lens = self.write("obs.json", json.dumps({
            "lens": "sieve-lens", "version": 1,
            "observations": [{"kind": "H2", "codepoint": "U+0041"}]}))
        inp = self.write("in.txt", "AB")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--config", cfg,
                     "--from-lens", lens, "--rule", "AB:label:AB"])
        # config の B:label が先に B@1 を確定 (B1)。
        # from-lens の A は A@0 (delete・非重複)。
        # CLI の AB は両方重複して棄却。
        self.assertEqual(self.read(out), "B1")


if __name__ == "__main__":
    unittest.main()

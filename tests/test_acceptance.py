#!/usr/bin/env python3
"""Sieve Redact — 受け入れ試験 (コア 5 様式 + CLI 境界).

実装 sieve_redact.py が満たすべき振る舞いを固定する。

実行:
    python3 -m unittest discover -s tests -v
"""

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "sieve_redact.py"


def run_cli(args):
    """CLI を subprocess 実行する。args は str/Path 混在可。"""
    if not SCRIPT.exists():
        raise FileNotFoundError(
            f"sieve_redact.py が見つかりません: {SCRIPT}")
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + [str(a) for a in args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def load_module():
    """sieve_redact.py を import する (fault-injection 用)。"""
    if not SCRIPT.exists():
        raise FileNotFoundError(f"sieve_redact.py が見つかりません: {SCRIPT}")
    spec = importlib.util.spec_from_file_location("sieve_redact", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---- 文字クラス (実装と同一の集合・順序をテスト側でも独立に保持) ----
CLASS_RANGES = {
    "hiragana": range(0x3041, 0x3097),   # ぁ..ゖ
    "katakana": range(0x30A1, 0x30FB),   # ァ..ヶ
    "kanji":    range(0x4E00, 0xA000),   # 一..鿿
    "upper":    range(0x0041, 0x005B),   # A..Z
    "lower":    range(0x0061, 0x007B),   # a..z
    "digit":    range(0x0030, 0x003A),   # 0..9
}
CLASS_CHARS = {name: [chr(cp) for cp in rng]
               for name, rng in CLASS_RANGES.items()}


def class_of(ch):
    """文字の属するクラス名。クラス外は None。"""
    for name, rng in CLASS_RANGES.items():
        if ord(ch) in rng:
            return name
    return None


class ProbeBase(unittest.TestCase):
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


class Probe1Determinism(ProbeBase):
    """probe 1: 同一入力+同一ルールで 2 回実行 → 出力バイト一致。"""

    def test_two_runs_identical_bytes(self):
        inp = self.write("in.txt", "田中太郎です。緊急連絡先 090-1234-5678")
        outputs, receipts = [], []
        for i in (1, 2):
            out = self.dir / f"out{i}.txt"
            rec = self.dir / f"receipt{i}.json"
            self.ok_run([inp, "-o", out,
                         "--rule", "田中太郎:mosaic",
                         "--rule", "090-1234-5678:noise",
                         "--receipt", rec])
            outputs.append(out.read_bytes())
            receipts.append(rec.read_bytes())
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(receipts[0], receipts[1])
        self.assertNotEqual(outputs[0], inp.read_bytes())  # サニティ: 変化は起きている


class Probe2ByteIntegrity(ProbeBase):
    """非マッチ区間のバイト同一。"""

    @staticmethod
    def nonmatch_bytes_match(input_bytes, output_bytes, redactions):
        """非マッチ入力セグメント連結 == 出力から置換結果を除いた連結。"""
        regs = sorted(redactions, key=lambda r: r["start"])
        i = o = 0
        seg_in = seg_out = b""
        for r in regs:
            gap = r["start"] - i
            if gap < 0:
                return False
            seg_in += input_bytes[i:i + gap]
            seg_out += output_bytes[o:o + gap]
            i = r["start"] + r["length"]
            o += gap + r["replacement_length"]
        seg_in += input_bytes[i:]
        seg_out += output_bytes[o:]
        return seg_in == seg_out

    def test_multibyte_regions(self):
        inp = self.write("in.txt", "prefix◆『あXあ』中間-ABC-末尾》")
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        self.ok_run([inp, "-o", out,
                     "--rule", "あXあ:mosaic",
                     "--rule", "ABC:label:ID",
                     "--receipt", rec])
        data = json.loads(rec.read_bytes().decode("utf-8"))
        self.assertTrue(data["byte_integrity_verified"])
        self.assertTrue(self.nonmatch_bytes_match(
            inp.read_bytes(), out.read_bytes(), data["redactions"]))
        self.assertEqual(self.read(out), "prefix◆『███』中間-ID1-末尾》")

    def test_crlf_preserved(self):
        # 改行変換の介入があれば他バイト完全性が壊れる → バイト比較で検出
        inp = self.write("in.txt", "line1\r\n秘密\r\nline3")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "秘密:delete"])
        self.assertEqual(out.read_bytes(), b"line1\r\n\r\nline3")


class Probe3FiveModes(ProbeBase):
    """probe 3: 5 様式の正しさ。"""

    def test_delete(self):
        inp = self.write("in.txt", "x秘密y")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "秘密:delete"])
        self.assertEqual(self.read(out), "xy")

    def test_mosaic_one_block_per_char_ascii(self):
        # 「1 文字ごとに埋め」→ 文字数保存
        inp = self.write("in.txt", "xabc y")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "abc:mosaic"])
        self.assertEqual(self.read(out), "x███ y")

    def test_mosaic_one_block_per_char_multibyte(self):
        inp = self.write("in.txt", "xあいうy")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "あいう:mosaic"])
        self.assertEqual(self.read(out), "x███y")

    def test_label_default_prefix_and_sequence(self):
        inp = self.write("in.txt", "a秘密b秘密c")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "秘密:label"])
        self.assertEqual(self.read(out), "a[REDACTED]1b[REDACTED]2c")

    def test_label_arg_prefix(self):
        inp = self.write("in.txt", "a秘密b秘密c")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "秘密:label:機密"])
        self.assertEqual(self.read(out), "a機密1b機密2c")

    def test_label_sequence_follows_apply_order_across_rules(self):
        # 適用は位置昇順 → 連番は適用順で確定。
        # 宣言順採番なら B=1 だが、位置昇順適用により A=1, B=2。
        inp = self.write("in.txt", "AB")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out,
                     "--rule", "B:label", "--rule", "A:label"])
        self.assertEqual(self.read(out), "[REDACTED]1[REDACTED]2")

    def test_noise_same_class_per_char(self):
        src = "aAあア漢0"
        inp = self.write("in.txt", src + "!")
        out = self.dir / "out.txt"
        args = [inp, "-o", out]
        for ch in src:
            args += ["--rule", f"{ch}:noise"]
        args += ["--rule", "!:noise"]  # クラス外 → 無変換
        self.ok_run(args)
        got = self.read(out)
        self.assertEqual(len(got), len(src) + 1)
        for orig, rep in zip(src + "!", got):
            if class_of(orig) is None:
                self.assertEqual(rep, orig)                      # クラス外は据え置き
            else:
                self.assertEqual(class_of(rep), class_of(orig))  # 同クラス性

    def test_noise_explicit_class_arg(self):
        inp = self.write("in.txt", "姓:山田")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "山田:noise:digit"])
        got = self.read(out)
        self.assertEqual(len(got), 4)
        self.assertTrue(all(ch in CLASS_CHARS["digit"] for ch in got[2:]))

    def test_noise_region_vs_outside(self):
        inp = self.write("in.txt", "090-1234-5678")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "090-:noise"])
        got = self.read(out)
        self.assertEqual(len(got), 13)
        self.assertEqual(got[3], "-")           # 領域内だがクラス外 → 据え置き
        self.assertEqual(got[4:], "1234-5678")  # 領域外は完全に無傷

    def test_decor_with_arg(self):
        inp = self.write("in.txt", "x秘密y")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "秘密:decor:###"])
        self.assertEqual(self.read(out), "x###秘密###y")

    def test_decor_default_arg(self):
        inp = self.write("in.txt", "x秘密y")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", "秘密:decor"])
        self.assertEqual(self.read(out), "x...秘密...y")


class Probe4OverlapResolution(ProbeBase):
    """マッチ重複の解決。"""

    def run_rules(self, text, rules):
        inp = self.write("in.txt", text)
        out = self.dir / "out.txt"
        args = [inp, "-o", out]
        for r in rules:
            args += ["--rule", r]
        self.ok_run(args)
        return self.read(out)

    def test_ab_wins_over_b_when_declared_first(self):
        self.assertEqual(self.run_rules("ABAB", ["AB:delete", "B:delete"]), "")

    def test_first_declared_rule_wins_partial_overlap(self):
        self.assertEqual(self.run_rules("ABC", ["AB:delete", "BC:delete"]), "C")

    def test_same_rule_skips_overlaps(self):
        self.assertEqual(self.run_rules("AAAA", ["AA:delete"]), "")

    def test_declaration_order_reversed(self):
        # B を先に宣言 → B@1,B@3 が確定し、AB は両方重なって捨てられる
        self.assertEqual(self.run_rules("ABAB", ["B:delete", "AB:delete"]), "AA")


class Probe5Receipt(ProbeBase):
    """probe 5: レシートが実測と一致し、本文を含まない。"""

    def test_machine_receipt_matches_reality(self):
        body = "名前:鈴木太郎 電話:090-1234-5678"
        inp = self.write("in.txt", body)
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        r = self.ok_run([inp, "-o", out,
                         "--rule", "鈴木太郎:mosaic",
                         "--rule", "090-1234-5678:label",
                         "--receipt", rec])
        data = json.loads(rec.read_bytes().decode("utf-8"))
        for key in ("input_bytes", "output_bytes", "redactions",
                    "total_redactions", "byte_integrity_verified",
                    "pattern_appearance_in_output"):
            self.assertIn(key, data)
        self.assertEqual(data["total_redactions"], 2)
        self.assertEqual(data["input_bytes"], len(body.encode("utf-8")))
        self.assertEqual(data["output_bytes"], len(out.read_bytes()))
        self.assertTrue(data["byte_integrity_verified"])
        self.assertEqual(data["pattern_appearance_in_output"], "none")

        regs = sorted(data["redactions"], key=lambda x: x["start"])
        self.assertEqual([reg["rule_index"] for reg in regs], [1, 2])
        expectations = [
            # 鈴木太郎は 4 文字 → mosaic は文字数保存で █ 4 個 = 12 バイト。
            ("鈴木太郎", "mosaic", "████"),
            ("090-1234-5678", "label", "[REDACTED]1"),
        ]
        ib = inp.read_bytes()
        for reg, (pat, mode, repl) in zip(regs, expectations):
            self.assertEqual(reg["mode"], mode)
            self.assertEqual(reg["end"] - reg["start"], reg["length"])
            region = ib[reg["start"]:reg["end"]]
            self.assertEqual(region.decode("utf-8"), pat)      # 位置が実測一致
            self.assertEqual(reg["content_sha256"],
                             hashlib.sha256(region).hexdigest())
            self.assertEqual(reg["replacement_length"],
                             len(repl.encode("utf-8")))
        self.assertEqual(self.read(out), "名前:████ 電話:[REDACTED]1")
        # 本文を含まない (machine / human 両方)
        raw_receipt = rec.read_bytes().decode("utf-8")
        self.assertNotIn("鈴木太郎", raw_receipt)
        self.assertNotIn("090-1234-5678", raw_receipt)
        stdout = r.stdout.decode("utf-8")
        self.assertNotIn("鈴木太郎", stdout)
        self.assertNotIn("090-1234-5678", stdout)

    def test_pattern_appearance_is_measured_not_promised(self):
        # decor は元文字列を残すため、実測として "found" を報告する
        inp = self.write("in.txt", "これは秘密です")
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        self.ok_run([inp, "-o", out, "--rule", "秘密:decor", "--receipt", rec])
        data = json.loads(rec.read_bytes().decode("utf-8"))
        self.assertEqual(self.read(out), "これは...秘密...です")
        self.assertEqual(data["pattern_appearance_in_output"], "found")


class Probe6NoiseRecompute(ProbeBase):
    """noise がハッシュ式どおり再計算できる。"""

    def recompute(self, body, pat, pool_name=None):
        # 全出現位置をハッシュ式で独立に再計算する (全走査と同じ適用範囲)。
        parts = []
        pos = 0
        while True:
            start = body.find(pat, pos)
            if start < 0:
                parts.append(body[pos:])
                break
            parts.append(body[pos:start])
            for k, ch in enumerate(pat):
                i = start + k
                off = len(body[:i].encode("utf-8"))
                pool = CLASS_CHARS[pool_name or class_of(ch)]
                h = hashlib.sha256(f"{pat}:{off}:{ch}".encode("utf-8")).digest()
                parts.append(pool[h[0] % len(pool)])
            pos = start + len(pat)
        return "".join(parts)

    def apply_noise(self, body, rule):
        inp = self.write("in.txt", body)
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--rule", rule])
        return self.read(out)

    def test_formula_with_multibyte_prefix(self):
        # 領域前にマルチバイト 9 バイト → byte_offset でないと再計算が合わない
        body = "前置きあ漢A0後ろ"
        self.assertEqual(self.apply_noise(body, "あ漢A0:noise"),
                         self.recompute(body, "あ漢A0"))

    def test_two_occurrences_get_independent_offsets(self):
        body = "あxあy"
        self.assertEqual(self.apply_noise(body, "あ:noise"),
                         self.recompute(body, "あ"))

    def test_explicit_class_arg_uses_same_formula(self):
        body = "姓:山田"
        self.assertEqual(self.apply_noise(body, "山田:noise:digit"),
                         self.recompute(body, "山田", pool_name="digit"))


class CliBoundaries(ProbeBase):
    """CLI の境界: 終了コードと入出力の安全装置。"""

    def test_missing_output_is_usage_error(self):
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "--rule", "x:delete"])
        self.assertEqual(r.returncode, 2)

    def test_unknown_mode_is_usage_error(self):
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o", "--rule", "x:wipe"])
        self.assertEqual(r.returncode, 2)

    def test_rule_without_mode_is_usage_error(self):
        inp = self.write("in.txt", "x")
        r = run_cli([inp, "-o", self.dir / "o", "--rule", "justpattern"])
        self.assertEqual(r.returncode, 2)

    def test_in_place_refused_and_input_untouched(self):
        inp = self.write("in.txt", "x秘密y")
        r = run_cli([inp, "-o", inp, "--rule", "秘密:delete"])
        self.assertEqual(r.returncode, 2)
        self.assertEqual(inp.read_bytes().decode("utf-8"), "x秘密y")

    def test_invalid_utf8_rejected_rc1_no_output(self):
        p = self.dir / "bad.bin"
        p.write_bytes(b"\xff\xfe\x00bad")
        out = self.dir / "out.txt"
        r = run_cli([p, "-o", out, "--rule", "a:delete"])
        self.assertEqual(r.returncode, 1)
        self.assertFalse(out.exists())

    def test_strict_blocks_output_on_forced_integrity_failure(self):
        sr = load_module()
        inp = self.write("in.txt", "x秘密y")
        out = self.dir / "out.txt"
        orig = sr.verify_byte_integrity
        sr.verify_byte_integrity = lambda *a, **k: False
        try:
            with self.assertRaises(SystemExit) as cm:
                sr.main([str(inp), "-o", str(out),
                         "--rule", "秘密:delete", "--strict"])
        finally:
            sr.verify_byte_integrity = orig
        self.assertEqual(cm.exception.code, 3)
        self.assertFalse(out.exists())

    def test_non_strict_writes_output_and_records_false(self):
        sr = load_module()
        inp = self.write("in.txt", "x秘密y")
        out = self.dir / "out.txt"
        rec = self.dir / "r.json"
        orig = sr.verify_byte_integrity
        sr.verify_byte_integrity = lambda *a, **k: False
        try:
            sr.main([str(inp), "-o", str(out),
                     "--rule", "秘密:delete", "--receipt", str(rec)])
        finally:
            sr.verify_byte_integrity = orig
        self.assertEqual(out.read_bytes().decode("utf-8"), "xy")
        data = json.loads(rec.read_bytes().decode("utf-8"))
        self.assertFalse(data["byte_integrity_verified"])

    def test_lang_switch_runs(self):
        inp = self.write("in.txt", "x秘密y")
        for lang in ("ja", "en"):
            out = self.dir / f"out-{lang}.txt"
            r = self.ok_run([inp, "-o", out,
                             "--rule", "秘密:delete", "--lang", lang])
            self.assertTrue(r.stdout.decode("utf-8").strip())


if __name__ == "__main__":
    unittest.main()

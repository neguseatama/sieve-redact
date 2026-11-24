"""Sieve Redact v0.12.0 — the `--from-encoding` flag (RD-T18..T19).

Spec summary (pinned by these tests):
  - `--from-encoding ENC` decodes the INPUT file with ENC, strictly
    (one `bytes.decode` call — no automatic detection of the encoding).
    Any codec name that the standard library resolves is accepted
    (CP932 / Shift_JIS / EUC-JP / UTF-16 and their aliases).  The
    default (no flag) stays UTF-8-only, exactly as before.
  - The output is always UTF-8.
  - The byte integrity and the receipt's byte counts live in the UTF-8
    domain: the decoded input as UTF-8 vs the output (the two sides
    must share one domain for the check to mean anything).  For the
    default UTF-8 path the decoded text re-encodes to the original
    bytes, so the receipt is byte-identical to 0.11.0.
  - Combination with `--from-lens` is allowed: the observation
    catalog's codepoints become chars rules, and chars matching
    re-scans the decoded text character by character (the catalog's
    positions are never consumed as byte offsets), so a different
    source encoding cannot shift anything.  Pinned by its own test.
  - Errors: a decode failure is rc1 (the same fixed shape as the UTF-8
    failure, with the codec name); an unknown codec name is rc2; the
    combination with `--region` (image mode is binary) is rc2.
    `--config` / `--from-lens` / `--receipt` keep reading and writing
    UTF-8 — the flag covers the input file only.
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

# JIS X 0208 の範囲の文面 — cp932 / shift_jis / euc_jp の 3 本で
# 同一の文字列をエンコードできる (実測ずみ)。
JP_TEXT = "名前: 山田太郎, カード: 4111111111111111\n"
JP_EXPECTED = "名前: 山田太郎, カード: C-1\n"


class FromEncodingBase(unittest.TestCase):
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

    def run_enc(self, raw, enc, extra=None):
        src = self.dir / "in.bin"
        src.write_bytes(raw)
        out = self.dir / "out.txt"
        rec = self.dir / "rec.json"
        args = [str(src), "-o", str(out), "--receipt", str(rec),
                "--builtin", "card:label:C-"]
        if enc is not None:
            args += ["--from-encoding", enc]
        proc = self.ok_run(args + list(extra or []))
        return (out.read_bytes(), json.loads(rec.read_text("utf-8")), proc)


# ---------------------------------------------------------------------------
# RD-T18: 変換の本体 — CP932 / Shift_JIS / EUC-JP / UTF-16・出力は UTF-8
# ---------------------------------------------------------------------------

class RD_T18_FromEncodingConversion(FromEncodingBase):
    def test_cp932_input_writes_utf8_output(self):
        raw = JP_TEXT.encode("cp932")
        self.assertNotEqual(raw, JP_TEXT.encode("utf-8"))
        out_bytes, rec, proc = self.run_enc(raw, "cp932")
        self.assertEqual(out_bytes.decode("utf-8"), JP_EXPECTED)
        self.assertIs(rec["byte_integrity_verified"], True)
        # 受領書の領域は UTF-8 — 入力側のバイト数はデコード済み本文の
        # UTF-8 列の長さ (既定経路と同じ定義)。
        self.assertEqual(rec["input_bytes"],
                         len(JP_TEXT.encode("utf-8")))
        self.assertEqual(rec["output_bytes"],
                         len(JP_EXPECTED.encode("utf-8")))
        # Human Receipt にも UTF-8 領域の数値が出る。
        self.assertIn("入力: %d バイト" % len(JP_TEXT.encode("utf-8")),
                      proc.stdout)

    def test_shift_jis_and_euc_jp(self):
        for enc in ("shift_jis", "euc_jp"):
            with self.subTest(enc=enc):
                raw = JP_TEXT.encode(enc)
                out_bytes, rec, _ = self.run_enc(raw, enc)
                self.assertEqual(out_bytes.decode("utf-8"), JP_EXPECTED)
                self.assertIs(rec["byte_integrity_verified"], True)

    def test_utf16_with_bom(self):
        raw = JP_TEXT.encode("utf-16")  # BOM つき (codec の仕様)
        out_bytes, rec, _ = self.run_enc(raw, "utf-16")
        self.assertEqual(out_bytes.decode("utf-8"), JP_EXPECTED)
        self.assertIs(rec["byte_integrity_verified"], True)

    def test_explicit_utf8_equals_the_default(self):
        # --from-encoding utf-8 は旗なしと完全同一 (受領書もバイト一致)。
        raw = JP_TEXT.encode("utf-8")
        _, rec_default, _ = self.run_enc(raw, None)
        _, rec_flag, _ = self.run_enc(raw, "utf-8")
        self.assertEqual(rec_default, rec_flag)
        self.assertEqual(rec_flag["input_bytes"], len(raw))

    def test_multibyte_matches_survive_transcoding(self):
        # マルチバイト文字に跨る一致 (全角数字のマイナンバー) も
        # 正しい位置で置換される (正規化ビューは 1:1 のまま)。
        text = "番号 １２３４５６７８９０１８ です\n"
        raw = text.encode("cp932")
        out_bytes, rec, _ = self.run_enc(
            raw, "cp932", ["--builtin", "mynumber:delete"])
        self.assertEqual(out_bytes.decode("utf-8"), "番号  です\n")
        r = rec["redactions"][0]
        self.assertIs(r["normalized"], True)
        self.assertEqual(r["length"], len("１２３４５６７８９０１８".encode("utf-8")))

    def test_from_lens_combination_is_allowed(self):
        # --from-lens との併用は許す (実装前に確定した C-3 のとおり)。
        # 根拠: カタログの位置は消費されず、chars ルールはデコード済み
        # 本文を文字単位で走査し直す — 文字コードが違っても一致は動か
        # ない。cp932 の入力にカタログの削除語を流し、正しく消えること
        # を機械で固定する。
        catalog = json.dumps({
            "lens": "sieve-lens", "version": 1,
            "observations": [
                {"kind": "H2", "codepoint": "U+200B",
                 "count": 1, "positions": [1]},
            ]})
        cat_path = self.dir / "obs.json"
        cat_path.write_text(catalog, encoding="utf-8")
        # cp932 に存在する文字 (U+FF0D 全角ハイフン) をカタログの削除語
        # にする — カタログの positions はあえて本文と無関係の値 (0) に
        # しておき、それでも本文中の実際の位置で一致することで、位置が
        # 消費されない (ずれない) ことを実証する。
        catalog_dash = json.dumps({
            "lens": "sieve-lens", "version": 1,
            "observations": [
                {"kind": "H2", "codepoint": "U+FF0D",
                 "count": 1, "positions": [0]},
            ]})
        cat2 = self.dir / "obs_dash.json"
        cat2.write_text(catalog_dash, encoding="utf-8")
        text = "名前: 山田太郎－メモ\n"  # － = U+FF0D
        raw = text.encode("cp932")
        out_bytes, rec, _ = self.run_enc(
            raw, "cp932", ["--from-lens", str(cat2)])
        self.assertEqual(out_bytes.decode("utf-8"),
                         "名前: 山田太郎メモ\n")
        self.assertEqual(rec["total_redactions"], 1)
        r = rec["redactions"][0]
        self.assertEqual(r["matcher"], "builtin:chars")
        # カタログの positions の値 (0) とは無関係に、本文中の実際の
        # 位置 (山田太郎 の直後) で一致していること。
        self.assertEqual(r["start"],
                         len("名前: 山田太郎".encode("utf-8")))


# ---------------------------------------------------------------------------
# RD-T19: 誤りの方向 — rc1 / rc2・画像モードとの併用拒否
# ---------------------------------------------------------------------------

class RD_T19_FromEncodingErrors(FromEncodingBase):
    def rc_run(self, raw, enc, rc):
        src = self.dir / "in.bin"
        src.write_bytes(raw)
        out = self.dir / "out.txt"
        args = [str(src), "-o", str(out), "--from-encoding", enc]
        proc = self.run_cli(args)
        self.assertEqual(proc.returncode, rc,
                         "rc=%d stderr=%s" % (proc.returncode, proc.stderr))
        return proc

    def test_decode_failure_is_rc1(self):
        # cp932 として解釈できないバイト列 — 既存の UTF-8 失敗と同じ
        # 形 (文面に codec 名)。出力ファイルは書かれない。
        proc = self.rc_run(b"\x81\x39 rest\n", "cp932", 1)
        self.assertIn("cp932", proc.stderr)
        self.assertFalse((self.dir / "out.txt").exists())

    def test_truncated_multibyte_is_rc1(self):
        # 2 バイト文字の先頭バイトだけのファイル — 厳密デコードは落ちる。
        proc = self.rc_run(b"ok\x82\n", "cp932", 1)
        self.assertIn("cp932", proc.stderr)

    def test_unknown_codec_name_is_rc2(self):
        proc = self.rc_run(b"ok\n", "no-such-enc", 2)

    def test_region_combination_is_rc2(self):
        # 画像モードはバイナリ — 文字コードの旗とは併用できない。
        src = self.dir / "in.bin"
        src.write_bytes(b"ok\n")
        proc = self.run_cli(
            [str(src), "-o", str(self.dir / "out.png"),
             "--region", "0,0,1,1:delete", "--from-encoding", "cp932"])
        self.assertEqual(proc.returncode, 2)

    def test_config_and_receipt_stay_utf8(self):
        # --config と --receipt は従来どおり UTF-8 (旗は入力 1 本だけ)。
        cfg = self.dir / "r.cfg"
        cfg.write_text('rule 秘密:same-value:L-\n', encoding="utf-8")
        src = self.dir / "in.txt"
        src.write_text("秘密 秘密\n", encoding="utf-8")
        out = self.dir / "out.txt"
        rec = self.dir / "rec.json"
        self.ok_run([str(src), "-o", str(out), "--receipt", str(rec),
                     "--config", str(cfg)])
        self.assertEqual(out.read_text("utf-8"), "L-1 L-1\n")


if __name__ == "__main__":
    unittest.main()

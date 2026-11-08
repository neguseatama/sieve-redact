"""Sieve Redact v0.10.0 — 長音記号のハイフン類としての畳み込み (RD-T09..T11)。

依頼書 (設計チャット 2026-11-05・指揮者経由) の B 部:
  U+30FC (ー) / U+FF70 (ｰ) を「数字の区切りとして働く位置」で '-' に
  畳み込み、090-1234-5678 型の表記が phone-jp (など数字形状の組込) で
  観測されるようにする。カタカナ語の長音の扱いと、既存の畳み込み
  (全角 U+FF01..FF5E・ハイフン類 U+2010..2015 / U+2212) は不変。
"""

import hashlib
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


class LongVowelBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.dir = Path(tmp.name)
        self.addCleanup(tmp.cleanup)

    def run_cli(self, args):
        return subprocess.run([sys.executable, str(SCRIPT)] + list(args),
                              capture_output=True, text=True)

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


# ---------------------------------------------------------------------------
# RD-T09: 長音記号区切りの電話番号・郵便番号が観測される (B)
# ---------------------------------------------------------------------------

class RD_T09_LongVowelObservation(LongVowelBase):
    def test_u30fc_phone_delete(self):
        text = "TEL 090ー1234ー5678 です\n"
        out, rec = self.redact_text(text, ["--builtin", "phone-jp:delete"])
        self.assertEqual(out, "TEL  です\n")
        self.assertEqual(rec["total_redactions"], 1)
        r = rec["redactions"][0]
        self.assertEqual(r["matcher"], "builtin:phone-jp")
        self.assertEqual(r["mode"], "delete")
        # 090(3B) ー(3B) 1234(4B) ー(3B) 5678(4B) = 17 バイト
        self.assertEqual((r["start"], r["end"], r["length"]), (4, 21, 17))
        self.assertIs(r["normalized"], True)

    def test_uff70_phone_delete(self):
        text = "TEL 090ｰ1234ｰ5678 です\n"
        out, rec = self.redact_text(text, ["--builtin", "phone-jp:delete"])
        self.assertEqual(out, "TEL  です\n")
        self.assertEqual(rec["total_redactions"], 1)
        r = rec["redactions"][0]
        self.assertEqual(r["matcher"], "builtin:phone-jp")
        self.assertEqual((r["start"], r["end"], r["length"]), (4, 21, 17))
        self.assertIs(r["normalized"], True)

    def test_u30fc_phone_mosaic_preserves_length(self):
        text = "090ー1234ー5678\n"
        out, rec = self.redact_text(text, ["--builtin", "phone-jp:mosaic"])
        self.assertEqual(out, "█" * 13 + "\n")
        self.assertEqual(rec["total_redactions"], 1)

    def test_fullwidth_digits_with_long_vowel(self):
        # 全角数字 + 長音: 標準ビューで畳み込んだ後に判定する。
        text = "０９０ー１２３４ー５６７８\n"
        out, rec = self.redact_text(text, ["--builtin", "phone-jp:delete"])
        self.assertEqual(out, "\n")
        self.assertEqual(rec["total_redactions"], 1)
        self.assertIs(rec["redactions"][0]["normalized"], True)

    def test_u30fc_postal_delete(self):
        text = "〒100ー0001\n"
        out, rec = self.redact_text(text, ["--builtin", "postal-jp:delete"])
        self.assertEqual(out, "〒\n")
        self.assertEqual(rec["total_redactions"], 1)
        r = rec["redactions"][0]
        self.assertEqual(r["matcher"], "builtin:postal-jp")
        self.assertIs(r["normalized"], True)

    def test_receipt_reflects_count(self):
        text = "090ー1234ー5678 と 06ー6543ー2109\n"
        out, rec = self.redact_text(text, ["--builtin", "phone-jp:label"])
        self.assertEqual(rec["total_redactions"], 2)
        self.assertIn("[REDACTED]1", out)
        self.assertIn("[REDACTED]2", out)


# ---------------------------------------------------------------------------
# RD-T10: カタカナ語の長音は不変・数字以外の文脈の誤検出は増えない (B)
# ---------------------------------------------------------------------------

class RD_T10_NoFalsePositives(LongVowelBase):
    def test_katakana_words_untouched(self):
        text = "コーヒーとサーバーを注文した。TEL 090-1234-5678 です。\n"
        out, rec = self.redact_text(
            text, ["--builtin", "phone-jp:delete",
                   "--builtin", "postal-jp:delete",
                   "--builtin", "email:delete"])
        self.assertEqual(out, "コーヒーとサーバーを注文した。TEL  です。\n")
        self.assertEqual(rec["total_redactions"], 1)

    def test_non_digit_contexts_produce_no_new_matches(self):
        cases = [
            # (入力, 期待出力, 期待件数) — 期待値は v0.9.1 の実測と同じ:
            # B は email の照合ビューを変えないため、aーb@… は「b@…」の
            # まま一致し、長音を含む拡張は起きない。
            ("aーb@example.co\n", "aー\n", 1),
            ("コーヒーとサーバー\n", "コーヒーとサーバー\n", 0),
            ("ｶｰｽｴﾚｶﾞﾝﾃﾞｽ\n", "ｶｰｽｴﾚｶﾞﾝﾃﾞｽ\n", 0),
            ("ID: AーB-12\n", "ID: AーB-12\n", 0),
            ("電話は 090 まで\n", "電話は 090 まで\n", 0),
            ("番号: ー1234ー\n", "番号: ー1234ー\n", 0),
        ]
        for text, want, want_n in cases:
            with self.subTest(text=text):
                out, rec = self.redact_text(
                    text, ["--builtin", "phone-jp:delete",
                           "--builtin", "postal-jp:delete",
                           "--builtin", "email:delete"])
                self.assertEqual(out, want, "数字以外の文脈で新規一致")
                self.assertEqual(rec["total_redactions"], want_n)

    def test_literal_and_chars_stay_exact(self):
        # literal / chars は正規化ビューの対象外 (従来どおり codepoint 正確)。
        out, rec = self.redact_text(
            "コーヒー\n", ["--builtin", "chars:U+30FC:delete"])
        self.assertEqual(out, "コヒ\n")
        out, rec = self.redact_text(
            "ABC abc\n", ["--rule", "ABC:delete"])
        self.assertEqual(out, " abc\n")

    def test_noise_mode_keeps_long_vowel_as_is(self):
        # noise same-class: ー はクラス外 (全クラス非所属) のため据え置き。
        text = "090ー1234ー5678\n"
        out, rec = self.redact_text(text, ["--builtin", "phone-jp:noise"])
        # 数字は digit クラスで置換され、長音はそのまま残る
        for ch in out:
            if ch == "\n":
                continue
            self.assertTrue(ch.isdigit() or ch in "ーｰ",
                            "unexpected char %r in %r" % (ch, out))
        self.assertEqual(rec["total_redactions"], 1)


# ---------------------------------------------------------------------------
# RD-T11: 既存の畳み込みの動作は不変 (金型)
# ---------------------------------------------------------------------------

class RD_T11_ExistingFoldsUnchanged(LongVowelBase):
    def test_fullwidth_phone_still_matches(self):
        out, rec = self.redact_text(
            "０９０－１２３４－５６７８\n",
            ["--builtin", "phone-jp:delete"])
        self.assertEqual(out, "\n")
        self.assertEqual(rec["total_redactions"], 1)
        self.assertIs(rec["redactions"][0]["normalized"], True)

    def test_hyphen_variants_still_match(self):
        for hy in ("‐", "‑", "‒", "–", "—", "−"):  # U+2010..2015, U+2212
            with self.subTest(hy="U+%04X" % ord(hy)):
                text = "090%s1234%s5678\n" % (hy, hy)
                out, rec = self.redact_text(
                    text, ["--builtin", "phone-jp:delete"])
                self.assertEqual(out, "\n")
                self.assertEqual(rec["total_redactions"], 1)

    def test_fullwidth_postal_still_matches(self):
        out, rec = self.redact_text(
            "１２３－４５６７\n", ["--builtin", "postal-jp:delete"])
        self.assertEqual(out, "\n")
        self.assertEqual(rec["total_redactions"], 1)

    def test_fullwidth_email_still_matches(self):
        out, rec = self.redact_text(
            "ａｂ＠ｅｘａｍｐｌｅ．ｃｏｍ\n", ["--builtin", "email:delete"])
        self.assertEqual(out, "\n")
        self.assertEqual(rec["total_redactions"], 1)
        self.assertIs(rec["redactions"][0]["normalized"], True)

    def test_ascii_hyphen_phone_has_no_normalized_flag(self):
        out, rec = self.redact_text(
            "090-1234-5678\n", ["--builtin", "phone-jp:delete"])
        self.assertEqual(out, "\n")
        self.assertNotIn("normalized", rec["redactions"][0])

    def test_literal_not_normalized(self):
        out, rec = self.redact_text(
            "ＡＢＣ と ABC\n", ["--rule", "ABC:delete"])
        self.assertEqual(out, "ＡＢＣ と \n")

    def test_a091_golden_text_pins_still_hold(self):
        # A 部で採取したテキスト金型 (全角・異種ハイフン・chars・noise を含む)
        # が B 適用後もバイト一致することは test_v0_9_1_hardening の
        # V090_PINS が固定する。ここでは追加の混合ケースを固定する。
        text = "０９０‐１２３４‐５６７８ と 03-4567-8901 と AB@example.com\n"
        out, rec = self.redact_text(
            text, ["--builtin", "phone-jp:delete",
                   "--builtin", "email:delete"])
        self.assertEqual(out, " と  と \n")
        self.assertEqual(rec["total_redactions"], 3)
        blob = json.dumps(rec, sort_keys=True, ensure_ascii=False)
        self.assertEqual(
            hashlib.sha256(blob.encode("utf-8")).hexdigest(),
            # v0.9.1 樹 (コミット a401adb) で採取した領収書の正規化ハッシュ。
            # B は長音区切りが増えるだけで既存ケースの領収書は不変であること。
            "0cf853e670cefa848428b14f1a9c1525779463a99a24552e5b8e408718ce22e6")


# ---------------------------------------------------------------------------
# RD-T08 (B 版): 0.10.0
# ---------------------------------------------------------------------------

class RD_T08_Version_B(unittest.TestCase):
    def test_version_is_0_10_0(self):
        self.assertEqual(sr.VERSION, "0.11.0")

    def test_changelog_has_0_10_0(self):
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("## [0.10.0]", text)

    def test_readme_titles_track_version(self):
        for name in ("README.md", "README.ja.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn("Sieve Redact v0.10.0", text, name)


if __name__ == "__main__":
    unittest.main()

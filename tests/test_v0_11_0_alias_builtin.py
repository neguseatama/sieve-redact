"""Sieve Redact v0.11.0 — 値の別表記 alias MODE と検査桁つき組込 3 種 (RD-T01..T08)。

実装依頼書 (M1・設計チャット・指揮者経由) の Redact 部 — sandbox 事故で
原本 tree が失効したため、保全された設計断片と実測値から再実装した
レーンの受け入れ試験:
  - alias = 第 7 MODE。値 (--rule PATTERN) を標準正規化ビュー
    (normalize_text・1:1) で完全一致照合する — 値の別表記
    (全角/半角 ASCII・異種ハイフン) を同一値として観測する。
    同形異字 (髙/高 等) は畳み込まない。置換は label と同じ
    「位置昇順適用順・1 起連番」(label と通しカウンタ)。
  - 組込 3 種 = 「ちょうど」の桁幅の極大 digit run + 検査桁:
    mynumber (12 桁・残差 11 — sieve-crowd と同一式) /
    corporate-jp (13 桁・法人番号省令第 6 条 — 先頭が検査用数字) /
    card (13..19 桁・標準 Luhn・digit run のみ)。

各試験メソッドは冒頭で新 spec の受容 (rc0) を top-level で断言する
ガードを持ち、red 段 (v0.10.0) ではそこで落ちる (subTest は起きない)。
red 段の実測 (v0.10.0・530aec6): 30 items = 28 failed + 2 passed
(緑は契約ガード: 領域 MODE の閉集合と machine receipt のキー集合)。
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


class AliasBuiltinBase(unittest.TestCase):
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
# RD-T01: alias — 値の別表記が完全一致で観測される
# ---------------------------------------------------------------------------

class RD_T01_AliasValueMatching(AliasBuiltinBase):
    def test_width_aliases_cross_match(self):
        # ガード: 全角値が半角の本文に届く (red では rc2 でここまで進まない)。
        out, rec = self.redact_text(
            "TEL: 090-1234-5678 まで\n",
            ["--rule", "０９０－１２３４－５６７８:alias"])
        self.assertEqual(out, "TEL: [REDACTED]1 まで\n")
        self.assertNotIn("normalized", rec["redactions"][0])
        # 行列: 両方向。本文が全角のときだけ normalized: true (additive)。
        for value, body, flag in (
                ("０９０－１２３４－５６７８", "090-1234-5678", False),
                ("090-1234-5678", "０９０－１２３４－５６７８", True)):
            with self.subTest(value=value, body=body):
                out, rec = self.redact_text(
                    "TEL: %s まで\n" % body, ["--rule", "%s:alias" % value])
                self.assertEqual(out, "TEL: [REDACTED]1 まで\n")
                r = rec["redactions"][0]
                self.assertEqual(r["mode"], "alias")
                self.assertEqual(r["matcher"], "literal")
                if flag:
                    self.assertIs(r["normalized"], True)
                    # 全角 13 文字 × 3 バイト = 39・直前 "TEL: " = 5 バイト
                    self.assertEqual((r["start"], r["end"], r["length"]),
                                     (5, 44, 39))
                else:
                    self.assertNotIn("normalized", r)
                    self.assertEqual((r["start"], r["end"], r["length"]),
                                     (5, 18, 13))

    def test_regex_metacharacters_are_literal(self):
        # 値完全一致 = 正規表現なし (a.c は a.c だけ・axc は一致しない)。
        out, rec = self.redact_text(
            "a.c axc a.c\n", ["--rule", "a.c:alias"])
        self.assertEqual(out, "[REDACTED]1 axc [REDACTED]2\n")
        self.assertEqual(rec["total_redactions"], 2)

    def test_absent_value_is_clean(self):
        out, rec = self.redact_text(
            "山田さん\n", ["--rule", "佐藤:alias"])
        self.assertEqual(out, "山田さん\n")
        self.assertEqual(rec["total_redactions"], 0)
        self.assertEqual(rec["pattern_appearance_in_output"], "none")

    def test_halfwidth_katakana_value_verbatim(self):
        # 半角カタカナ (U+FF71..) は正規化表の外 = 字面どおりに照合する。
        # 全角カタカナとの幅統一は 1:1 表に無い (= 別値・一致しない)。
        out, rec = self.redact_text(
            "ｱｲｳ です\n", ["--rule", "ｱｲｳ:alias"])
        self.assertEqual(out, "[REDACTED]1 です\n")
        self.assertEqual(rec["total_redactions"], 1)
        out2, rec2 = self.redact_text(
            "アイウ です\n", ["--rule", "ｱｲｳ:alias"])
        self.assertEqual(out2, "アイウ です\n")
        self.assertEqual(rec2["total_redactions"], 0)


# ---------------------------------------------------------------------------
# RD-T02: alias — 連番は位置昇順適用順・1 起 (label と通し)
# ---------------------------------------------------------------------------

class RD_T02_AliasNumbering(AliasBuiltinBase):
    def test_position_order_and_label_shared_counter(self):
        # ガード: label と alias が 1 つの通しカウンタを共有すること。
        out, rec = self.redact_text(
            "山田 鈴木 山田 鈴木\n",
            ["--rule", "山田:label", "--rule", "鈴木:alias"])
        self.assertEqual(out,
                         "[REDACTED]1 [REDACTED]2 [REDACTED]3 [REDACTED]4\n")
        self.assertEqual(rec["total_redactions"], 4)
        # 連番は宣言順ではなく「位置昇順の適用順」。重なりが無い限り
        # 宣言順の影響は無い (両順で同じ出力・rule_index のみ宣言順通り)。
        for rules in (["--rule", "山田:label", "--rule", "鈴木:alias"],
                      ["--rule", "鈴木:alias", "--rule", "山田:label"]):
            with self.subTest(rules=rules):
                out, rec = self.redact_text(
                    "山田 鈴木 山田 鈴木\n", rules)
                self.assertEqual(
                    out, "[REDACTED]1 [REDACTED]2 [REDACTED]3 [REDACTED]4\n")
                self.assertEqual(rec["total_redactions"], 4)
                self.assertEqual([r["mode"] for r in rec["redactions"]],
                                 ["label", "alias", "label", "alias"])
                # 位置 0..2 = 山田・位置 3..5 と 11..13 = 鈴木 — 宣言順で
                # rule_index は変わるが位置との対応は不変。
                yama, suzu = (1, 2) if rules[1].startswith("山田") else (2, 1)
                self.assertEqual(
                    [r["rule_index"] for r in rec["redactions"]],
                    [yama, suzu, yama, suzu])

    def test_discarded_overlap_does_not_consume_number(self):
        # 先発ルールと重なった alias マッチは棄却され、連番を消費しない
        # (確定した区画だけが番号を持つ)。
        out, rec = self.redact_text(
            "山田太郎と太郎\n",
            ["--rule", "山田太郎:delete", "--rule", "太郎:alias"])
        self.assertEqual(out, "と[REDACTED]1\n")
        self.assertEqual(rec["total_redactions"], 2)
        alias_rows = [r for r in rec["redactions"] if r["mode"] == "alias"]
        self.assertEqual(len(alias_rows), 1)
        self.assertEqual(alias_rows[0]["start"], 15)  # 山田太郎(12B) + と(3B)

    def test_two_alias_rules_share_one_sequence(self):
        out, rec = self.redact_text(
            "鈴木 佐藤\n",
            ["--rule", "鈴木:alias", "--rule", "佐藤:alias"])
        self.assertEqual(out, "[REDACTED]1 [REDACTED]2\n")
        self.assertEqual([r["rule_index"] for r in rec["redactions"]], [1, 2])


# ---------------------------------------------------------------------------
# RD-T03: alias — ARG (接頭辞) と '+' / '~' 接頭辞
# ---------------------------------------------------------------------------

class RD_T03_AliasArgAndPrefixes(AliasBuiltinBase):
    def test_arg_prefix(self):
        out, rec = self.redact_text(
            "山田太郎・山田太郎\n",
            ["--rule", "山田太郎:alias:個人情報"])
        self.assertEqual(out, "個人情報1・個人情報2\n")
        self.assertEqual(rec["total_redactions"], 2)

    def test_empty_arg_bare_ordinal(self):
        out, rec = self.redact_text(
            "山田太郎・山田太郎\n",
            ["--rule", "山田太郎:alias:"])
        self.assertEqual(out, "1・2\n")
        self.assertEqual(rec["total_redactions"], 2)

    def test_word_unit_alias_rejects_inner_match(self):
        # '+alias' — 境界で両端いずれかが棄却されればマッチ全体を棄却
        # (小山田 の 山田 は棄却・語頭の 山田 だけが確定)。
        out, rec = self.redact_text(
            "山田さんと小山田さん\n", ["--rule", "山田:+alias"])
        self.assertEqual(out, "[REDACTED]1さんと小山田さん\n")
        self.assertEqual(rec["total_redactions"], 1)


# ---------------------------------------------------------------------------
# RD-T04: alias — 照合ビューの契約 ('~'・同形異字・長音)
# ---------------------------------------------------------------------------

class RD_T04_AliasViewContract(AliasBuiltinBase):
    def test_case_insensitive_alias(self):
        # ガード: '~alias' — 正規化ビューの上に ASCII 大小折りたたみ。
        out, rec = self.redact_text(
            "taro TARO Taro\n", ["--rule", "TARO:~alias"])
        self.assertEqual(out, "[REDACTED]1 [REDACTED]2 [REDACTED]3\n")
        self.assertEqual(rec["total_redactions"], 3)
        # 全角値 + '~' も同じ照合に届く (正規化 → 折りたたみの合成)。
        for value in ("TARO", "ＴＡＲＯ"):
            with self.subTest(value=value):
                out, rec = self.redact_text(
                    "taro TARO Taro\n", ["--rule", "%s:~alias" % value])
                self.assertEqual(out,
                                 "[REDACTED]1 [REDACTED]2 [REDACTED]3\n")
                self.assertEqual(rec["total_redactions"], 3)
                self.assertTrue(all(r.get("case_insensitive")
                                    for r in rec["redactions"]))

    def test_kanji_glyph_variant_is_not_folded(self):
        # 同形異字は畳み込まない (設計確認) — 髙 (U+9AD9) と 高 (U+9AD8)
        # は別値。字面どおり一致しないので出力は不変。
        out, rec = self.redact_text(
            "髙橋です\n", ["--rule", "高橋:alias"])
        self.assertEqual(out, "髙橋です\n")
        self.assertEqual(rec["total_redactions"], 0)
        self.assertEqual(rec["pattern_appearance_in_output"], "none")

    def test_long_vowel_in_value_is_verbatim(self):
        # alias の照合は標準ビュー (normalize_text) — 長音記号を
        # ハイフンに畳む第 2 ビュー (v0.10.0・phone/postal 用) は使わない。
        # 値側の長音は字面どおりにしか一致しない。
        out, rec = self.redact_text(
            "TEL: 090-1234-5678 まで\n",
            ["--rule", "090ー1234ー5678:alias"])
        self.assertEqual(out, "TEL: 090-1234-5678 まで\n")
        self.assertEqual(rec["total_redactions"], 0)


# ---------------------------------------------------------------------------
# RD-T05: mynumber — 12 桁・残差 11 (sieve-crowd と同一式)
# ---------------------------------------------------------------------------

class RD_T05_MyNumberBuiltin(AliasBuiltinBase):
    def test_valid_mynumber_deleted(self):
        out, rec = self.redact_text(
            "マイナンバー: 123456789018 です\n",
            ["--builtin", "mynumber:delete"])
        self.assertEqual(out, "マイナンバー:  です\n")
        self.assertEqual(rec["total_redactions"], 1)
        r = rec["redactions"][0]
        self.assertEqual(r["matcher"], "builtin:mynumber")
        self.assertEqual(r["mode"], "delete")
        # マイナンバー(18B) + ": "(2B) = 20・12 桁 = 12B
        self.assertEqual((r["start"], r["end"], r["length"]), (20, 32, 12))
        self.assertNotIn("normalized", r)

    def test_fullwidth_mynumber_is_normalized(self):
        out, rec = self.redact_text(
            "番号 １２３４５６７８９０１８\n",
            ["--builtin", "mynumber:delete"])
        self.assertEqual(out, "番号 \n")
        r = rec["redactions"][0]
        # 番号(6B) + 空白(1B) = 7・全角 12 文字 = 36B
        self.assertEqual((r["start"], r["end"], r["length"]), (7, 43, 36))
        self.assertIs(r["normalized"], True)

    def test_exactly_twelve_digits_boundary(self):
        # ガード: 12 桁以外の run は一致しない (1 例を top-level で)。
        out, rec = self.redact_text(
            "N: 9123456789018\n", ["--builtin", "mynumber:delete"])
        self.assertEqual(out, "N: 9123456789018\n")
        self.assertEqual(rec["total_redactions"], 0)
        # 「ちょうど 12 桁」— 極大 digit run が 12 のときだけ。
        for text in ("N: 1234567890180\n",   # 13 桁 run
                     "N: 12345678901\n",     # 11 桁 (足りない)
                     "N: 9123456789018\n"):  # 13 桁 run に埋まっている
            with self.subTest(text=text):
                out, rec = self.redact_text(text,
                                            ["--builtin", "mynumber:delete"])
                self.assertEqual(out, text)
                self.assertEqual(rec["total_redactions"], 0)

    def test_invalid_check_digit_is_not_matched(self):
        # ガード: 検査桁不一致は一致しない (1 例を top-level で)。
        out, rec = self.redact_text(
            "N: 123456789012\n", ["--builtin", "mynumber:delete"])
        self.assertEqual(out, "N: 123456789012\n")
        self.assertEqual(rec["total_redactions"], 0)
        for bad in ("123456789013", "000000000001"):
            with self.subTest(bad=bad):
                text = "N: %s\n" % bad
                out, rec = self.redact_text(text,
                                            ["--builtin", "mynumber:delete"])
                self.assertEqual(out, text)
                self.assertEqual(rec["total_redactions"], 0)


# ---------------------------------------------------------------------------
# RD-T06: corporate-jp — 13 桁・法人番号省令第 6 条 (先頭が検査用数字)
# ---------------------------------------------------------------------------

class RD_T06_CorporateBuiltin(AliasBuiltinBase):
    def test_official_example_is_matched(self):
        # 国税庁が公表する指定例 (基礎番号 000012050002 → 検査用数字 7)。
        out, rec = self.redact_text(
            "法人番号 7000012050002 です\n",
            ["--builtin", "corporate-jp:delete"])
        self.assertEqual(out, "法人番号  です\n")
        self.assertEqual(rec["total_redactions"], 1)
        r = rec["redactions"][0]
        self.assertEqual(r["matcher"], "builtin:corporate-jp")
        # 法人番号(12B) + 空白(1B) = 13・13 桁 = 13B
        self.assertEqual((r["start"], r["end"], r["length"]), (13, 26, 13))

    def test_constructed_valids_and_fullwidth(self):
        # ガード: 構築した検査桁適合値 (ascii) が一致する。
        out, rec = self.redact_text(
            "CN 7123456789012\n", ["--builtin", "corporate-jp:delete"])
        self.assertEqual(out, "CN \n")
        self.assertEqual(rec["total_redactions"], 1)
        # 全角つづり (正規化フラグ) と mosaic (長さ保存) の行列。
        for body, spell in (("２５０１０００１００８１１", "fullwidth"),
                            ("7000012050002", "mosaic")):
            with self.subTest(body=body, spell=spell):
                if spell == "fullwidth":
                    text = "CN %s\n" % body
                    extra = ["--builtin", "corporate-jp:delete"]
                else:
                    text = "CN %s\n" % body
                    extra = ["--builtin", "corporate-jp:mosaic"]
                out, rec = self.redact_text(text, extra)
                if spell == "mosaic":
                    self.assertEqual(out, "CN █████████████\n")
                    r = rec["redactions"][0]
                    self.assertEqual(r["replacement_length"], 39)  # █ × 13
                else:
                    self.assertEqual(out, "CN \n")
                    self.assertIs(rec["redactions"][0]["normalized"], True)
                self.assertEqual(rec["total_redactions"], 1)

    def test_exactly_thirteen_digits_boundary(self):
        # ガード: 14 桁 run は一致しない (red では rc2 でここで落ちる)。
        out, rec = self.redact_text(
            "CN 70000120500023\n", ["--builtin", "corporate-jp:delete"])
        self.assertEqual(out, "CN 70000120500023\n")
        self.assertEqual(rec["total_redactions"], 0)
        # 12 桁 run も一致しない (「ちょうど 13 桁」)。
        out, rec = self.redact_text(
            "CN 000012050002\n", ["--builtin", "corporate-jp:delete"])
        self.assertEqual(out, "CN 000012050002\n")
        self.assertEqual(rec["total_redactions"], 0)

    def test_wrong_check_digit_is_not_matched(self):
        out, rec = self.redact_text(
            "CN 7000012050003\n", ["--builtin", "corporate-jp:delete"])
        self.assertEqual(out, "CN 7000012050003\n")
        self.assertEqual(rec["total_redactions"], 0)


# ---------------------------------------------------------------------------
# RD-T07: card — 13..19 桁・標準 Luhn (digit run のみ)
# ---------------------------------------------------------------------------

class RD_T07_CardBuiltin(AliasBuiltinBase):
    def test_luhn_valid_16_is_matched(self):
        # sieve-crowd の test PAN と同一値 (系列で共有される検算値)。
        out, rec = self.redact_text(
            "CARD: 4242424242424242\n", ["--builtin", "card:delete"])
        self.assertEqual(out, "CARD: \n")
        r = rec["redactions"][0]
        self.assertEqual(r["matcher"], "builtin:card")
        self.assertEqual((r["start"], r["end"], r["length"]), (6, 22, 16))

    def test_range_13_to_19(self):
        # ガード: 13 桁 (範囲下端) が一致する。
        out, rec = self.redact_text(
            "PAN 4242424242422\n", ["--builtin", "card:delete"])
        self.assertEqual(out, "PAN \n")
        self.assertEqual(rec["total_redactions"], 1)
        for pan in ("4242424242422",          # 13 桁
                    "4242424242424242428"):   # 19 桁 (範囲上端)
            with self.subTest(pan=pan):
                text = "PAN %s\n" % pan
                out, rec = self.redact_text(text,
                                            ["--builtin", "card:delete"])
                self.assertEqual(out, "PAN \n")
                self.assertEqual(rec["total_redactions"], 1)

    def test_twenty_digit_run_is_not_matched(self):
        # 範囲上限 — 20 桁 run は Luhn 適合でも card ではない。
        text = "PAN 42424242424242424200\n"
        out, rec = self.redact_text(text, ["--builtin", "card:delete"])
        self.assertEqual(out, text)
        self.assertEqual(rec["total_redactions"], 0)

    def test_luhn_invalid_is_not_matched(self):
        text = "PAN 4242424242424241\n"
        out, rec = self.redact_text(text, ["--builtin", "card:delete"])
        self.assertEqual(out, text)
        self.assertEqual(rec["total_redactions"], 0)

    def test_hyphenated_card_is_not_matched(self):
        # digit run のみが 0.11.0 の対象 (ハイフン区切りは将来の課題として
        # CHANGELOG に記録)。
        text = "PAY: 4242-4242-4242-4242\n"
        out, rec = self.redact_text(text, ["--builtin", "card:delete"])
        self.assertEqual(out, text)
        self.assertEqual(rec["total_redactions"], 0)


# ---------------------------------------------------------------------------
# RD-T08: 契約ガード (red でも緑 = 変更しない契約の固定)
# ---------------------------------------------------------------------------

class RD_T08_ContractGuards(AliasBuiltinBase):
    def test_region_alias_is_still_rejected(self):
        # 画像の REGION_MODES は閉集合のまま (alias は加わらない)。
        # rc2 のみを表明する (Pillow の有無で拒否経路が分かれるため)。
        png = self.dir / "in.png"
        png.write_bytes(b"")
        proc = self.run_cli([str(png), "-o", str(self.dir / "out.png"),
                             "--region", "0,0,1,1:alias"])
        self.assertEqual(proc.returncode, 2)

    def test_machine_receipt_keys_are_unchanged(self):
        # 受領書契約: キー追加のみ・0.10.0 とのバイト一致が原則。
        # 0.11.0 で top-level キーは 1 個も増えないことを固定する。
        _, rec = self.redact_text("X\n", ["--rule", "X:delete"])
        self.assertEqual(
            set(rec),
            {"input_bytes", "output_bytes", "redactions",
             "total_redactions", "byte_integrity_verified",
             "pattern_appearance_in_output"})

    def test_version_pin(self):
        self.assertEqual(sr.VERSION, "0.11.0")

    def test_builtin_alias_is_rejected_with_dedicated_message(self):
        # alias は値 (--rule) 専用の MODE — --builtin では専用メッセージで
        # 拒否する (0.10.0 の「不明な MODE」汎用拒否とは区別される)。
        src = self.dir / "in.txt"
        src.write_text("x\n", encoding="utf-8")
        proc = self.run_cli([str(src), "-o", str(self.dir / "out.txt"),
                             "--builtin", "phone-jp:alias"])
        self.assertEqual(proc.returncode, 2)
        self.assertIn("専用", proc.stderr)


if __name__ == "__main__":
    unittest.main()

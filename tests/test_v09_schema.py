#!/usr/bin/env python3
"""Sieve Redact v0.9 — --from-lens スキーマゲート (Schema Contract v1) の受け入れ試験.

二層検証の pin:
  JSON 層: 重複キー拒否 / NaN・Infinity 拒否 / UTF-8 BOM 拒否 / 1 MiB 上限
  スキーマ層: 未知キー拒否 / 必須欠損 / 型 (bool を int から排除) / enum
  受容: 契約 v1 の producer 形 (lens / kind / count / positions あり) は
  すべて通過すること (現行の受容範囲を維持)。

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

MAX_BYTES = 1048576


def run_cli(args):
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + [str(a) for a in args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class SchemaGateBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, text):
        p = self.dir / name
        p.write_bytes(text.encode("utf-8"))
        return p

    def write_raw(self, name, data):
        p = self.dir / name
        p.write_bytes(data)
        return p

    def read(self, path):
        return path.read_bytes().decode("utf-8")

    def ok_run(self, args):
        r = run_cli(args)
        self.assertEqual(
            r.returncode, 0,
            f"rc={r.returncode} stderr={r.stderr.decode('utf-8', 'replace')}")
        return r

    def rc2_run(self, args, needle=None):
        r = run_cli(args)
        self.assertEqual(r.returncode, 2, f"stderr={r.stderr.decode('utf-8', 'replace')}")
        if needle is not None:
            err = r.stderr.decode("utf-8", "replace")
            self.assertIn(needle, err)

    def lens_file(self, doc):
        return self.write("obs.json", json.dumps(doc))

    def catalog(self, observations, **extra):
        doc = {"lens": "sieve-lens", "version": 1, "observations": observations}
        doc.update(extra)
        return self.lens_file(doc)


class ProducerShapeAccepted(SchemaGateBase):
    """契約 v1 の producer 形 (lens / kind / count / positions) は通過する。"""

    def test_full_producer_shape_is_accepted(self):
        # redact_bridge.py 文書例と同一構成 (S1 プローブのケース A)
        lens = self.catalog([
            {"kind": "H2", "codepoint": "U+200B", "count": 2,
             "positions": [1, 5]},
            {"kind": "homoglyph", "codepoint": "U+0430",
             "twin": "U+0061", "count": 1, "positions": [3]}])
        inp = self.write("in.txt", "t\u0430rget\u200b.com")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--from-lens", lens])
        self.assertEqual(self.read(out), "target.com")

    def test_count_positions_omitted_is_accepted(self):
        lens = self.catalog([{"kind": "H2", "codepoint": "U+200B"}])
        inp = self.write("in.txt", "a\u200bb")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--from-lens", lens])
        self.assertEqual(self.read(out), "ab")

    def test_empty_observations_is_accepted(self):
        lens = self.catalog([])
        inp = self.write("in.txt", "untouched")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--from-lens", lens])
        self.assertEqual(self.read(out), "untouched")

    def test_lens_top_level_key_is_accepted(self):
        # lens キーの型が正当なら content は問わない (str であれば通過)
        lens = self.catalog([], lens="other-observer")
        inp = self.write("in.txt", "x")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--from-lens", lens])
        self.assertEqual(self.read(out), "x")


class SchemaLayerRejects(SchemaGateBase):
    """スキーマ層: 未知キー・必須欠損・型・enum を rc2 で拒否する。"""

    def test_unknown_top_level_key_is_rc2(self):
        lens = self.catalog([], meta={"note": "extra"})
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens],
                     needle="許可されていないキー: meta")

    def test_unknown_key_in_observation_is_rc2(self):
        lens = self.catalog([
            {"kind": "H2", "codepoint": "U+200B", "weight": 3}])
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens],
                     needle="許可されていないキー: weight")

    def test_missing_version_is_rc2(self):
        doc = {"lens": "sieve-lens", "observations": []}
        lens = self.lens_file(doc)
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens],
                     needle="/version: 必須フィールドが欠損しています")

    def test_version_bool_is_rc2(self):
        # true は int の亜種 — 型検証が排除する (S1 プローブのケース C2)
        doc = {"lens": "sieve-lens", "version": True, "observations": []}
        lens = self.lens_file(doc)
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens],
                     needle="/version: 型が不正です")

    def test_version_string_is_rc2(self):
        doc = {"lens": "sieve-lens", "version": "1", "observations": []}
        lens = self.lens_file(doc)
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens])

    def test_missing_observations_is_rc2(self):
        doc = {"lens": "sieve-lens", "version": 1}
        lens = self.lens_file(doc)
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens],
                     needle="/observations: 必須フィールドが欠損しています")

    def test_observations_not_list_is_rc2(self):
        doc = {"lens": "sieve-lens", "version": 1, "observations": {"a": 1}}
        lens = self.lens_file(doc)
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens])

    def test_observation_not_object_is_rc2(self):
        lens = self.catalog(["U+200B"])
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens],
                     needle="/observations/0: オブジェクトである必要があります: str")

    def test_missing_codepoint_is_rc2(self):
        lens = self.catalog([{"kind": "H2"}])
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens],
                     needle="/observations/0/codepoint: 必須フィールドが欠損しています")

    def test_codepoint_not_string_is_rc2(self):
        lens = self.catalog([{"kind": "H2", "codepoint": 8203}])
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens],
                     needle="/observations/0/codepoint: 型が不正です")

    def test_count_bool_is_rc2(self):
        lens = self.catalog([
            {"kind": "H2", "codepoint": "U+200B", "count": True}])
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens],
                     needle="/observations/0/count: 型が不正です")

    def test_count_float_is_rc2(self):
        lens = self.catalog([
            {"kind": "H2", "codepoint": "U+200B", "count": 1.0}])
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens])

    def test_positions_bool_element_is_rc2(self):
        lens = self.catalog([
            {"kind": "H2", "codepoint": "U+200B", "positions": [1, True]}])
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens],
                     needle="/observations/0/positions/1: 型が不正です")

    def test_positions_not_list_is_rc2(self):
        lens = self.catalog([
            {"kind": "H2", "codepoint": "U+200B", "positions": "1,5"}])
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens])

    def test_lens_not_string_is_rc2(self):
        doc = {"lens": 7, "version": 1, "observations": []}
        lens = self.lens_file(doc)
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens],
                     needle="/lens: 型が不正です")

    def test_kind_not_string_is_rc2(self):
        lens = self.catalog([{"kind": 3, "codepoint": "U+200B"}])
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens])

    def test_twin_not_string_is_rc2(self):
        lens = self.catalog([
            {"kind": "homoglyph", "codepoint": "U+0430", "twin": 97}])
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens])


class JsonLayerRejects(SchemaGateBase):
    """JSON 層: 重複キー・NaN/Infinity・BOM・サイズ上限を rc2 で拒否する。"""

    def test_duplicate_top_level_key_is_rc2(self):
        raw = ('{"lens":"sieve-lens","lens":"x","version":1,'
               '"observations":[]}')
        lens = self.write("obs.json", raw)
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens],
                     needle="キーが重複しています: 'lens'")

    def test_duplicate_key_in_observation_is_rc2(self):
        raw = ('{"lens":"sieve-lens","version":1,"observations":'
               '[{"codepoint":"U+200B","codepoint":"U+200C"}]}')
        lens = self.write("obs.json", raw)
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens])

    def test_nan_is_rc2(self):
        raw = '{"lens":"sieve-lens","version":1,"observations":[],"note":NaN}'
        lens = self.write("obs.json", raw)
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens],
                     needle="JSON 仕様外の定数は許可されません: NaN")

    def test_infinity_is_rc2(self):
        raw = ('{"lens":"sieve-lens","version":1,"observations":[],'
               '"note":Infinity}')
        lens = self.write("obs.json", raw)
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens])

    def test_utf8_bom_is_rc2(self):
        body = json.dumps(
            {"lens": "sieve-lens", "version": 1, "observations": []})
        lens = self.write_raw("obs.json", b"\xef\xbb\xbf" + body.encode("utf-8"))
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens])

    def test_oversized_file_is_rc2(self):
        lens = self.write_raw("obs.json", b"x" * (MAX_BYTES + 1))
        inp = self.write("in.txt", "x")
        self.rc2_run([inp, "-o", self.dir / "o", "--from-lens", lens],
                     needle="ファイルが大きすぎます")

    def test_file_at_limit_is_accepted(self):
        # 上限ちょうど (1 MiB) は拒否されない — 許可キー (lens 値) で余白を埋める
        head = '{"lens":"'
        tail = '","version":1,"observations":[]}'
        pad = MAX_BYTES - len(head) - len(tail)
        raw = (head + "a" * pad + tail).encode("utf-8")
        self.assertEqual(len(raw), MAX_BYTES)
        lens = self.write_raw("obs.json", raw)
        inp = self.write("in.txt", "x")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--from-lens", lens])
        self.assertEqual(self.read(out), "x")


if __name__ == "__main__":
    unittest.main()

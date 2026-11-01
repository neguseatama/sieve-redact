#!/usr/bin/env python3
"""Sieve Schema Contract v1 適合コーパスの複製検証 (Redact 同梱部).

lens リポジトリの正本コーパス (sieve-lens tests/corpus/
schema_contract_v1.json) を sha256 pin 付きで複製し、Redact が実装する
JSON 層の適合を実測する (sieve-tray の vendor sync 先例と同じ pin 方式)。

スコープ: corpus の layer == "json" ケースのみ。Redact 同梱ゲートは
single-file 不変のため schema.py を import できず、catalog v1 用の
語彙サブセット (type / required / enum / item_type / item_schema) を
同一ファイル内で宣言する。その catalog v1 の pin は test_v09_schema.py
が担当し、スキーマ層の全語彙ケースは Redact の実行対象外である
(契約書 docs/SCHEMA_CONTRACT_v1.md §6 の適合マトリクスの宣言どおり)。

JSON 層の観測対象:
  - layer == "json" の受理ケース: _strict_json_loads が値を返す
  - dup_key / nan_inf の拒否ケース: UsageError
  - bom の拒否ケース: load_lens_codepoints (ファイル経路・エンドツー
    エンド) が UsageError
"""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import sieve_redact
from sieve_redact import (
    UsageError,
    _strict_json_loads,
    load_lens_codepoints,
)

CORPUS = Path(__file__).resolve().parent / "corpus" / "schema_contract_v1.json"
CORPUS_SHA256 = "514d45eb2580a9ea5a4336094be347d9c9bd8fb2990044551aec96cd094ae6aa"


def _load_corpus():
    return json.loads(CORPUS.read_text(encoding="utf-8"))


class CorpusIntegrity(unittest.TestCase):
    def test_corpus_file_matches_pin(self):
        actual = hashlib.sha256(CORPUS.read_bytes()).hexdigest()
        self.assertEqual(
            actual, CORPUS_SHA256,
            "複製したコーパスが pin と一致しません。契約を意図的に更新した場合は "
            "sieve-lens 側の正本と同一サイクルで pin を更新してください")

    def test_corpus_declares_the_current_contract(self):
        corpus = _load_corpus()
        self.assertEqual(corpus["contract"], "sieve-schema-contract-v1")
        self.assertEqual(corpus["corpus_version"], "1")
        ids = [case["id"] for case in corpus["cases"]]
        self.assertEqual(len(ids), len(set(ids)), "ケース ID の重複")


class JsonLayerConformance(unittest.TestCase):
    """layer == "json" のケースを Redact 同梱の JSON 層で実測する。"""

    def test_json_layer_cases(self):
        corpus = _load_corpus()
        for case in corpus["cases"]:
            if case["layer"] != "json":
                continue
            with self.subTest(case=case["id"]):
                if case["expect"] == "accept":
                    value = _strict_json_loads(case["input_text"])
                    self.assertIsNotNone(value)
                elif "bom" in case.get("violations", []):
                    # Redact はバイト段階 (UTF-8 厳格) で BOM を拒否する。
                    # ファイル経路でエンドツーエンドに実測する。
                    with tempfile.NamedTemporaryFile(
                            "wb", suffix=".json", delete=False) as fh:
                        fh.write(case["input_text"].encode("utf-8"))
                        path = fh.name
                    with self.assertRaises(UsageError):
                        load_lens_codepoints(path)
                else:
                    with self.assertRaises(UsageError):
                        _strict_json_loads(case["input_text"])


if __name__ == "__main__":
    unittest.main()

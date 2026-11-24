# AGENTS.md

公開面の文章: README・docs・CHANGELOG・Release 本文・パッケージの説明・コミットメッセージ・コードのコメント・テストの説明文は、利用者と開発者に向けた事実の短い文で書く。作業の経緯・内部の呼び名・日付つきの決定・開発環境の情報・絶対パス・テストの番号（README・docs・CHANGELOG）を書かない。CHANGELOG の版の節は、3〜5 項目の短文にする。`tools/check_public_text.py` が通ること。

## Build and test

- Python >= 3.9; the image lane needs Pillow >= 10.0
  (`pip install "sieve-redact[image]"`).
- Test suite: `python -m unittest discover -s tests -v`.
- Package build: `python -m build`.
- Public-text watch: `python tools/check_public_text.py`
  (runs in CI; one file: `--text FILE`).

## Working rules

1. **test-first**: 修正の前に、そのふるまいを固定するテストを書き、
   実装の前の赤（期待どおりに落ちる理由まで）と実装後の緑を確認する。
   既存のテストは、その版の変更で意味が変わらない限り修正しない。
2. **コアの不変条件**: `sieve_redact.py` は標準ライブラリのみ・決定的・
   オフライン。マッチ区間外のバイトは 1 バイトも変えない
   （`verify_byte_integrity` が出力前に機械検証する）。
   受領書に機密本文を載せない（位置・長さ・モード・ハッシュのみ）。
3. **語彙の規律**: MODE・builtin NAME・受領書の鍵・終了符号の既定集合は、
   使い方の節で宣言したものだけ。増やすときは CHANGELOG の最新の節で
   宣言してから入れる。
4. **版の作法**: 版は `sieve_redact.py` の `VERSION` が唯一の静的な源。
   pyproject は dynamic attr で参照し、README ×2 の題字と CHANGELOG の
   最新の節は `VERSION` と一致させる。版を固定するテストは
   `sr.VERSION` との比較の形にする。
5. **CI**: 3 OS（ubuntu / windows / macos × 3.12、ubuntu 3.9 の下限）。
   環境に依存する失敗はテスト側を直し、製品の不具合は次の版で直す。
6. **公開の順序**: PR の merge → PyPI への公開（手動）→ tag →
   GitHub Release（`release.yml` が tag で起動し、CHANGELOG の最新の節を
   本文として点検のうえ資産を添付する）。同一版のタグ・資産の
   差し替えはしない。
7. **機械の見張り**: 公開面の点検は手作業に頼らず
   `tools/check_public_text.py` と baseline で守る。触った行の
   コメント/docstring は規則に合わせ、baseline は下げる方向で更新する。

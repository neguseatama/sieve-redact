# Sieve Redact v0.5

文書に含まれる機密情報を、**決定論的に**、そして**他バイト完全性を守って**
マスクするコマンドラインツールです。

[![CI](https://github.com/neguseatama/sieve-redact/actions/workflows/test.yml/badge.svg)](https://github.com/neguseatama/sieve-redact/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)

[English](README.md) | **日本語**

## 💡 コンセプト

履歴書・レポート・ログなどに含まれる個人情報を、第二のファイルとして
安全に公開・共有できる形へ変換します。

- **決定論** — 同一入力＋同一ルールは、常に同一の出力。`noise` の文字選択は
  SHA-256 由来で、実行環境・時刻・乱数に依存しません。
- **他バイト完全性** — マッチ区間の外側は 1 バイトも変えません。改行コード
  (CRLF) も保存されます。出力前に必ず機械検証し、`--strict` では失敗時に
  出力を拒否します (終了コード 3)。
- **推測しない** — 機密はユーザーが指定します。エンジンは推測しません。
- **レシート** — 処理の事実 (位置・長さ・モード・ハッシュ) を記録しますが、
  機密本文は載せません。「パターンが残っていない」ことも測定値
  (`pattern_appearance_in_output`) として報告します。

> 「Sieve Redact」という名称は、ふるい (sieve) のように、指定した情報だけを
> 落とし、それ以外を 1 バイトも傷つけない設計思想に由来します。

[Sieve Lens](https://github.com/neguseatama/sieve-lens) (不可視コンテンツの観測)
と対をなす、マスキング (Redact) のエンジンです。

---

## 🔥 主な特徴

### 6 つの様式

| MODE | 操作 | 内容 |
|------|------|------|
| `delete` | 区間を除去 | 空文字列 |
| `mosaic` | 1 文字ごとに埋め | 元の文字数と同数の `█` |
| `label` | 順番号ラベル | 接頭辞 (既定 `[REDACTED]`) + 処理順連番 |
| `noise` | 同クラス文字へ置換 | ひらがな/カタカナ/漢字/英大/英小/数字の各クラス内で決定的に選択 |
| `decor` | ラップ | `ARG + 元文字列 + ARG` |
| `replace` | 一括置換 | ARG で置換 |

### 組込文字種 (`--builtin`)

| NAME | 対象 |
|------|------|
| `postal-jp` | 郵便番号 `NNN-NNNN` |
| `phone-jp` | 電話番号 (`090-…` / `03-…` / `050-…` / `0120-…` / 4 桁市外局番 `01XX-07XX`) |
| `email` | メールアドレス (ASCII) |
| `chars` | 指定コードポイント (`U+200B,U+00AD` 形式) の全出現 |

### 画像マスキング (`--region`)

PNG 画像 (8bit RGB/RGBA・非インターレース・非アニメーション) を、明示した
矩形で処理します: `--region x,y,w,h:MODE[:ARG]` (複数回指定可。重なる
region は宣言順に破棄・面積 0 や画像範囲外は使用法エラー。`--rule` とは
併用不可)。

| MODE | 効果 |
|------|--------|
| `delete` | 不透明白で塗りつぶし |
| `mosaic` | 全チャネルのブロック平均 (ブロックは region 原点に整列。ARG = ブロックサイズ、既定 8) |
| `noise` | 画素ごとの決定的置換 — SHA-256(`img:x:y:R,G,B`) が新しい RGB を決定。アルファは保持されるため、半透明画素は透明度を保ったまま内容だけが変わります (可視性は不変) |
| `label` | `[REDACTED]n` の黒帯 (同梱ビットマップフォント) |
| `decor` | ARG 色 (RRGGBB) の 2px 枠線 |
| `replace` | 白地に ARG 文字列を描画 (同梱ビットマップフォント) |

画像モードのレシートでは `byte_integrity_verified` が `null` になります
(PNG 再エンコードでファイルバイトは構造的に変化するため適用外)。矩形外の
画素完全性は `pixel_integrity_verified` が測定し、`--strict` はこの失敗で
終了コード 3 となります。ファイルのメタデータ (EXIF 等) は保存時に常に
除去します — プライバシー上有利な既定動作です。

### 語単位一致 (`+` 接頭辞)

`太郎:label` は「田中太郎」の中の「太郎」にも一致しますが、
`太郎:+label` は語境界でのみ一致します (隣接文字が同クラスまたは
ともに英数字なら棄却)。

### 設定ファイルと Lens 連携

- `--config rules.cfg`: ルールをファイルから読み込みます
  (`rule <spec>` / `builtin <spec>` の行式)。
- `--from-lens catalog.json`: [Sieve Lens](https://github.com/neguseatama/sieve-lens)
  の観測目録 (JSON) からマスキングルールを生成します。不可視文字は削除、
  同形文字 (キリル/ギリシャ → ラテン) は `twin` フィールドに基づき置換。

---

## 💻 クイックスタート

    git clone https://github.com/neguseatama/sieve-redact.git
    cd sieve-redact

    # 氏名をモザイク、電話番号をラベル化
    python sieve_redact.py in.txt -o out.txt \
      --rule "田中太郎:mosaic" \
      --builtin phone-jp:label \
      --receipt receipt.json

レシート (標準出力) の例 — `in.txt` が `x秘密y`・`--rule "秘密:delete"` の場合:

    Sieve Redact v0.5 — レシート
    入力: 8 バイト -> 出力: 2 バイト
    redact 件数: 1
      #1 rule=1 matcher=literal mode=delete pos=1..7 len=6B -> 0B sha256=062a2931da68...
    他バイト完全性: 検証済み
    出力内パターン残留: none

機密本文はレシートに現れません — ハッシュのみです。画像モード
(`--region`) では `byte_integrity_verified` は `null` (適用外) となり、
完全性は `pixel_integrity_verified` が測定します。

### Sieve Lens との連携

    # (1) Lens が観測目録を生成
    python -m sieve_lens_ext.redact_bridge input.txt catalog.json
    # (2) Redact が一括マスク
    python sieve_redact.py input.txt -o clean.txt --from-lens catalog.json

---

## 🔬 決定性の保証

`noise` の文字選択は次の式で完全に決まります:

    文字 = POOL[ SHA-256("<pattern>:<byte_offset>:<元文字>").digest()[0] % len(POOL) ]

シードを持たない・環境に依存しない・同じ入力なら必ず同じ出力。
同梱のテストは、この式どおりに再計算して一致することを検証します。

マッチ重複の解決も決定的です: ルールは宣言順に試行し、各ルールは
左端優先で全走査、既に確定した区間と重なる後発マッチは捨て、
確定した全区間は位置昇順で適用します。

---

## 🔬 テスト

    python -m unittest discover -s tests -v

113 テスト (5 様式・組込文字種・語単位一致・設定ファイル・Lens 連携・
CLI 境界) を内蔵。追加の依存はありません。

---

## ⚠️ 既知の限界

1. **正規表現非対応** — パターンは生文字列の完全一致のみ
2. **case-insensitive 非対応** — 大文字小文字は区別する
3. **自動機密検出なし** — 機密はユーザーが指定する (推測しない設計)
4. **テキストと PNG 画像** — PDF・Office 形式は非対応。画像マスキングは
   PNG のみ (8bit RGB/RGBA) で、JPEG は明示対象外。PDF のマスキングは
   対象外 (観測は Sieve Lens の領域)
5. **全角数字・異種ハイフンは postal/phone の対象外**
6. **08/09 で始まる 4 桁市外局番 (`0800` を除く) と短縮番号 (117・104 等) は
   `phone-jp` の対象外** — `--rule` で個別に指定可能

---

## 📄 ライセンス

MIT License。詳細は [LICENSE](LICENSE) を参照してください。

---

## 👤 Author

* **Kai IWASAKI**

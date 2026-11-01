# Sieve Redact v0.9.0

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

## 🧩 Sieve シリーズ

Sieve は、決定的・ゼロ依存・完全ローカルという共通の設計原則を共有する
エンジン群です。各エンジンが 1 つのリスクの観測または排除を担い、
相互に接続します:

| パッケージ | 役割 | 接続 |
|---------|------|-------------|
| [sieve-core-engine](https://github.com/neguseatama/sieve-core) | エコシステムの基盤ロジック / プラグインホスト | — |
| [sieve-lens](https://github.com/neguseatama/sieve-lens) | 文書内の不可視コンテンツ・隠しプロンプトを観測 | → `--from-lens` 経由で redact へ |
| [sieve-scope](https://github.com/neguseatama/sieve-scope) | 構造的に類似したコードペアを検出 | — |
| [sieve-referee](https://github.com/neguseatama/sieve-referee) | 言い換え・流用されたテキストペアを検出 | — |
| [sieve-redact](https://github.com/neguseatama/sieve-redact) | 機密領域をレシートつきでマスキング (テキスト & PNG/JPEG) | ← lens、→ tray |
| [sieve-tray](https://github.com/neguseatama/sieve-tray) | ファイルを適切なエンジンへ振り分けるデスクトップフロントエンド | ← 全エンジン |

観測から排除まで 1 パスで: Lens が人間に見えないものを見つけ、
Redact が「他は何も変わっていない」ことを証明するレシートとともに
除去します。

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
| `phone-jp` | 電話番号 (`090-…` / `03-…` / `050-…` / `0120-…` / 4 桁市外局番 `01XX-09XX`) と短縮番号 (`104` / `106` / `110` / `117` / `118` / `119` / `171`) |
| `email` | メールアドレス (ASCII) |
| `chars` | 指定コードポイント (`U+200B,U+00AD` 形式) の全出現 |

`postal-jp` / `phone-jp` / `email` は 1:1 の正規化ビューで照合します:
全角 ASCII (`１２３`, `ＡＢＣ`, `－`, `＠`) と異種ハイフン
(U+2010–2015, U+2212) は照合前に ASCII 相当へ折りたたまれますが、
マスクは元のバイト列の区間に適用されます (該当区間にはレシートに
`normalized: true` を記録)。`chars` と literal ルールは生照合のままです。

### 画像マスキング (`--region`)

PNG 画像 (8bit RGB/RGBA・非インターレース・非アニメーション) と RGB の
JPEG 画像を、明示した矩形で処理します: `--region x,y,w,h:MODE[:ARG]`
(複数回指定可。重なる region は宣言順に破棄・面積 0 や画像範囲外は
使用法エラー。`--rule` とは併用不可)。出力は常に PNG です — JPEG 入力を
JPEG として再圧縮しないため、マスクが新たな圧縮劣化を生みません
(デコード済みの画素が PNG に保全されます)。

| MODE | 効果 |
|------|--------|
| `delete` | 不透明白で塗りつぶし |
| `mosaic` | 全チャネルのブロック平均 (ブロックは region 原点に整列。ARG = ブロックサイズ、既定 8) |
| `noise` | 画素ごとの決定的置換 — SHA-256(`img:x:y:R,G,B`) が新しい RGB を決定。アルファは保持されるため、半透明画素は透明度を保ったまま内容だけが変わります (可視性は不変) |
| `label` | `[REDACTED]n` の黒帯 (同梱ビットマップフォント) |
| `decor` | ARG 色 (RRGGBB) の 2px 枠線 |
| `replace` | 白地に ARG 文字列を描画 (同梱ビットマップフォント) |

画像モードのレシートでは `byte_integrity_verified` が `null` になります
(出力は常に PNG のため、入力が PNG でも JPEG でもファイルバイトは
構造的に変化します)、判別した入力形式を `input_format` (`PNG` または
`JPEG`) に記録します。矩形外の
画素完全性は `pixel_integrity_verified` が測定し、`--strict` はこの失敗で
終了コード 3 となります。ファイルのメタデータ (EXIF 等) は保存時に常に
除去します — プライバシー上有利な既定動作です。出力バイトはプラットフォーム
間で決定的です (CI で pin により検証。Pillow 12.3.0 で確認 — Pillow の更新で
エンコード済みバイトは変わり得ますが、画素は変わりません)。

### 語単位一致と大小無視一致 (`+` / `~` 接頭辞)

`太郎:label` は「田中太郎」の中の「太郎」にも一致しますが、
`太郎:+label` は語境界でのみ一致します (隣接文字が同クラスまたは
ともに英数字なら棄却)。

`Taro:~label` は ASCII の大小を無視して照合します (`TARO` / `taro` も
一致。非 ASCII はそのまま)。接頭辞は任意の順で併用できます —
`秘密:+~label` は語単位＋大小無視です。`chars` に `~` を付けると
指定した ASCII 英字の大小両方が対象になります。

### 設定ファイルと Lens 連携

- `--config rules.cfg`: ルールをファイルから読み込みます
  (`rule <spec>` / `builtin <spec>` の行式)。
- `--from-lens catalog.json`: [Sieve Lens](https://github.com/neguseatama/sieve-lens)
  の観測目録 (JSON) からマスキングルールを生成します。不可視文字は削除、
  同形文字 (キリル/ギリシャ → ラテン) は `twin` フィールドに基づき置換。
  目録はゼロ依存のスキーマゲートが厳格に検証し、重複 JSON キー・
  `NaN`/`Infinity`・未知キー・不正な型 (`true` を整数として含む)・
  1 MiB 超のファイルを JSON Pointer 付きエラー (rc2) で拒否します。
  推測も型変換 (coercion) も行いません。

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

    Sieve Redact v0.7.0 — レシート
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

正規化ビュー (組込 matcher) と ASCII 折りたたみ (`~` ルール) は
1 文字 → 1 文字の対応なので位置は移動しません。マスクは常に
元のバイト列の区間に適用されます。

マッチ重複の解決も決定的です: ルールは宣言順に試行し、各ルールは
左端優先で全走査、既に確定した区間と重なる後発マッチは捨て、
確定した全区間は位置昇順で適用します。

---

## 🔬 テスト

    python -m unittest discover -s tests -v

251 テスト (5 様式・組込文字種・語単位一致・大小無視一致・正規化ビュー・
画像マスキング (JPEG 入力を含む)・設定ファイル・スキーマゲートを含む
Lens 連携・Schema Contract v1 適合コーパス複製 (JSON 層)・CLI 境界) を内蔵。
追加の依存はありません。

`tests/corpus/schema_contract_v1.json` は、sieve-lens リポジトリが管理する
Sieve Schema Contract v1 適合コーパス (受理/拒否 44 ケース) の sha256 pin
付き複製です。契約書 (`docs/SCHEMA_CONTRACT_v1.md`) と正本エンジン
(`sieve_lens_ext/schema.py`) も sieve-lens 側にあります。複製が実測するの
は Redact の JSON 層 — 目録の厳格読み込み (重複キー・`NaN`/`Infinity`・
UTF-8 BOM を拒否) — で、pin により正本との無言の乖離はテスト失敗として
検出されます (sieve-tray の vendor sync 先例と同じ方式)。

---

## ⚠️ 既知の限界

1. **正規表現非対応** — パターンは生文字列 (任意で `~` による ASCII 大小
   無視)。ワイルドカード・文字クラス・量指定子は扱わない
2. **自動機密検出なし** — 機密はユーザーが指定する (推測しない設計)
3. **テキストと画像** — PDF・Office 形式は非対応。画像マスキングは
   PNG (8bit RGB/RGBA) と RGB JPEG を受け付け、出力は常に PNG。
   グレースケール/CMYK・その他の形式 (GIF/WebP 等)・PDF のマスキングは
   対象外 (観測は Sieve Lens の領域)
4. **正規化は 1:1 かつ対象を絞る** — 組込 matcher が折りたたむのは
   U+FF01..FF5E と異種ハイフン U+2010..2015 / U+2212 のみ。その他の
   互換形 (例: U+3000 の空白) は生照合のまま
5. **phone-jp の形状限界は残る** — 固定の短縮番号セット
   (`104`/`106`/`110`/`117`/`118`/`119`/`171`) 以外のハイフンなし番号や
   特殊な桁組みは対象外 — `--rule` で個別に指定可能
6. **--from-lens は未知キーを拒否** — 契約 v1 のキー
   (`lens`/`version`/`observations`、要素ごとの
   `kind`/`codepoint`/`count`/`positions`/`twin`) 以外を含む目録は
   無視せず拒否する。将来の Lens 拡張は契約の明示的な拡張として行う

---

## 📄 ライセンス

MIT License。詳細は [LICENSE](LICENSE) を参照してください。

---

## 👤 Author

* **Kai IWASAKI**

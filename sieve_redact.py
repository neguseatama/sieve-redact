#!/usr/bin/env python3
"""Sieve Redact — 決定的なテキスト redaction エンジン。

v0.1: 生文字列一致・5 様式・他バイト完全性・レシート
v0.2: 組込文字種 --builtin、語単位一致 '+' 接頭辞、
      設定ファイル --config と --from-lens
      (tests/test_v02_*.py)
v0.3: replace 様式、--from-lens twin 生成、
      phone-jp 拡張形
v0.7: 全角・異種ハイフンの正規化ビュー照合 (builtin matcher)・
      '~' 接頭辞による大小無視一致・phone-jp の 08/09 4 桁
      市外局番と短縮番号
v0.9: --from-lens の JSON 門番 — 重複キー・NaN/Infinity・未知キー・
      1 MiB 超を拒否し、エラーに JSON Pointer を付与
      (Sieve Schema Contract v1 の Redact 同梱ゲート)

コア不変条件:
  - 依存は stdlib のみ / 決定的 / UTF-8 のみ / オフライン / テレメトリなし
  - 他バイト完全性: マッチ区間外のバイトは 1 バイトも変えない
    (verify_byte_integrity で出力前に必ず機械検証する)
  - レシートに機密本文を載せない (位置・長さ・モード・ハッシュのみ)

受け入れ試験:
    python3 -m unittest discover -s tests -v
"""

import argparse
import bisect
import hashlib
import json
import os
import sys
import tempfile
import warnings
from pathlib import Path
from collections import namedtuple

VERSION = "0.9.1"

# 画像モードで読み込む画像の画素数上限 (v0.9.1・A-1)。
# ヘッダから取得した寸法で重い処理 (画素のループ・整合検査) の前に拒否する。
# 一般的なカメラの写真 (〜50 メガピクセル級) が通る値。
MAX_IMAGE_PIXELS = 64_000_000

REGION_MODES = ("delete", "mosaic", "label", "noise", "decor", "replace")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
JPEG_SIGNATURE = b"\xff\xd8\xff"
LABEL_PREFIX_DEFAULT = "[REDACTED]"

try:
    from PIL import Image, ImageChops, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


def _same_target_file(input_path, output_path):
    """入力と出力が同一実体を指すか (v0.9.1・A-3)。

    出力が既に存在する場合は os.path.samefile (シンボリックリンク・
    ハードリンク・相対/絶対の表記差を実体で解決)。未作成の場合は
    解決した親ディレクトリ + ファイル名 (realpath) で比較する。
    テキスト・画像の両モードで使う。
    """
    if os.path.exists(output_path):
        try:
            return os.path.samefile(input_path, output_path)
        except OSError:
            pass
    return os.path.realpath(input_path) == os.path.realpath(output_path)


def _silent_unlink(path):
    # 失敗済み経路での後始末 — ここからの例外は無視する。
    try:
        os.unlink(path)
    except OSError:
        pass


def _adopt_output_permissions(path, tmp_name):
    """一時ファイルを出力先の権限に揃える (v0.9.1・A-4)。

    既存の出力を置き換える場合はその権限を継承し、新規作成の場合は
    直接 open(path, "wb") で作った場合と同じ 0666 & ~umask にする。
    """
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        cur = os.umask(0)
        os.umask(cur)
        mode = 0o666 & ~cur
    os.chmod(tmp_name, mode)


def _atomic_write(path, data):
    """一時ファイルに書いてから os.replace で置き換える (v0.9.1・A-4)。

    同じディレクトリに一時ファイルを作るため、置き換えは常に同じ
    ファイルシステム上で完結する。書き込みの途中で失敗しても既存の
    出力は壊れず、一時ファイルも残らない。成功時の内容・権限・名前は
    従来の直接書き込みと同じ。
    """
    path = Path(path)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    os.close(fd)
    try:
        with open(tmp_name, "wb") as fh:
            fh.write(data)
        _adopt_output_permissions(path, tmp_name)
        os.replace(tmp_name, path)
    except BaseException:
        _silent_unlink(tmp_name)
        raise


def _atomic_save_image(img, path):
    """画像モードの出力を原子的に書く (v0.9.1・A-4)。"""
    path = Path(path)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    os.close(fd)
    try:
        img.save(tmp_name, format="PNG")
        _adopt_output_permissions(path, tmp_name)
        os.replace(tmp_name, path)
    except BaseException:
        _silent_unlink(tmp_name)
        raise


def parse_region_spec(spec):
    # Parse x,y,w,h:MODE[:ARG]; raise ValueError on any bad input.
    parts = spec.split(":")
    if len(parts) not in (2, 3):
        raise ValueError("region format is x,y,w,h:MODE[:ARG]")
    coords = parts[0].split(",")
    if len(coords) != 4:
        raise ValueError("region needs exactly 4 coordinates")
    try:
        x, y, w, h = (int(c) for c in coords)
    except ValueError:
        raise ValueError("region coordinates must be integers")
    if w <= 0 or h <= 0:
        raise ValueError("region width and height must be positive")
    mode = parts[1]
    if mode not in REGION_MODES:
        raise ValueError("unknown region MODE: %s" % mode)
    arg = parts[2] if len(parts) == 3 else None
    if mode in ("delete", "noise") and arg is not None:
        raise ValueError("region MODE %s takes no ARG" % mode)
    if mode == "replace" and (arg is None or arg == ""):
        raise ValueError("region MODE replace requires an ARG")
    if mode == "decor":
        if arg is None or len(arg) != 6:
            raise ValueError("region MODE decor requires a RRGGBB hex color")
        try:
            int(arg, 16)
        except ValueError:
            raise ValueError("decor color must be hexadecimal RRGGBB")
    if mode == "mosaic" and arg is not None:
        try:
            if int(arg) <= 0:
                raise ValueError
        except ValueError:
            raise ValueError("mosaic ARG must be a positive integer")
    return {"x": x, "y": y, "w": w, "h": h, "mode": mode, "arg": arg}


def check_png_input(data):
    # Validate raw bytes as a supported PNG (8bit RGB/RGBA, no interlace).
    if len(data) < 33 or data[:8] != PNG_SIGNATURE:
        raise ValueError("input is not a PNG file")
    if data[12:16] != b"IHDR":
        raise ValueError("input is not a PNG file (IHDR missing)")
    depth = data[24]
    ctype = data[25]
    interlace = data[28]
    if depth != 8:
        raise ValueError("unsupported PNG bit depth: %d (8 only)" % depth)
    if ctype not in (2, 6):
        raise ValueError("unsupported PNG color type: %d (RGB or RGBA only)"
                         % ctype)
    if interlace != 0:
        raise ValueError("interlaced PNG is not supported")
    width = int.from_bytes(data[16:20], "big")
    height = int.from_bytes(data[20:24], "big")
    return width, height


JPEG_SOF_MARKERS = frozenset(
    (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
     0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF))


def check_jpeg_input(data):
    # Validate raw bytes as a JPEG (SOI + frame header) and return
    # (width, height) from the SOF segment without decoding pixels.
    # This gate only decides "is this a JPEG"; Pillow remains the decoder.
    if len(data) < 4 or data[:3] != JPEG_SIGNATURE:
        raise ValueError("input is not a JPEG file")
    i = 2
    n = len(data)
    while i + 4 <= n:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        if marker == 0xFF:
            i += 1
            continue
        if marker == 0x01 or 0xD0 <= marker <= 0xD9:
            i += 2
            continue
        seglen = int.from_bytes(data[i + 2:i + 4], "big")
        if seglen < 2:
            raise ValueError("invalid JPEG segment length")
        if marker in JPEG_SOF_MARKERS:
            if i + 2 + seglen > n or seglen < 8:
                raise ValueError("truncated JPEG frame header")
            height = int.from_bytes(data[i + 5:i + 7], "big")
            width = int.from_bytes(data[i + 7:i + 9], "big")
            if width == 0 or height == 0:
                raise ValueError("invalid JPEG dimensions")
            return width, height
        i += 2 + seglen
    raise ValueError("unsupported JPEG (frame header not found)")


def _rects_overlap(a, b):
    return not (a["x"] + a["w"] <= b["x"] or b["x"] + b["w"] <= a["x"]
                or a["y"] + a["h"] <= b["y"] or b["y"] + b["h"] <= a["y"])


def _rect_pixels(img, rect):
    px = img.load()
    return b"".join(bytes(px[x, y])
                    for y in range(rect["y"], rect["y"] + rect["h"])
                    for x in range(rect["x"], rect["x"] + rect["w"]))


def _fill_rect(px, rect, color):
    for y in range(rect["y"], rect["y"] + rect["h"]):
        for x in range(rect["x"], rect["x"] + rect["w"]):
            px[x, y] = color


MODES = ("delete", "mosaic", "label", "noise", "decor", "replace")
DEFAULT_LABEL_PREFIX = "[REDACTED]"
DEFAULT_DECOR = "..."
NOISE_SAME_CLASS = "same-class"

# 組込文字種
BUILTIN_NAMES = ("postal-jp", "phone-jp", "email", "chars")

# 6 文字クラス。各レンジはコードポイント昇順。
# tests 側の CLASS_RANGES と同一定義 (probe 6 再計算の前提)。
CLASS_RANGES = {
    "hiragana": range(0x3041, 0x3097),   # ぁ..ゖ
    "katakana": range(0x30A1, 0x30FB),   # ァ..ヶ
    "kanji":    range(0x4E00, 0xA000),   # 一..鿿
    "upper":    range(0x0041, 0x005B),   # A..Z
    "lower":    range(0x0061, 0x007B),   # a..z
    "digit":    range(0x0030, 0x003A),   # 0..9
}
CLASS_CHARS = {name: "".join(chr(cp) for cp in rng)
               for name, rng in CLASS_RANGES.items()}

# kind: "literal" (--rule) | "builtin" (--builtin)
# name: 組込名 (literal は "")
# pattern: literal = 生パターン / chars = 正規化 CP-LIST ("U+XXXX,U+YYYY")
# seed: noise の seed (literal=pattern / name 型=NAME /
#       chars="chars:"+正規化CP-LIST)
# word_unit — MODE の '+' 接頭辞。境界で両端いずれかが棄却なら
#            そのマッチ全体を棄却する
# ci — MODE の '~' 接頭辞。ASCII の大小を無視して照合する
#      (非 ASCII はそのまま。位置対応を保つため 1:1 折りたたみのみ)
Rule = namedtuple("Rule", "index kind name pattern seed mode arg word_unit ci")


class UsageError(Exception):
    """CLI 使用法の誤り (終了コード 2)。"""


# --------------------------------------------------------------- 文字ユーティリティ

def _is_ascii_digit(ch):
    return "0" <= ch <= "9"


def _is_ascii_alpha(ch):
    return "A" <= ch <= "Z" or "a" <= ch <= "z"


def _is_ascii_alnum(ch):
    return _is_ascii_digit(ch) or _is_ascii_alpha(ch)


def _all_ascii_digits(s):
    return all(_is_ascii_digit(ch) for ch in s)


def _fold_char(ch):
    """ASCII 大文字 → 小文字 (1:1)。それ以外はそのまま。"""
    if "A" <= ch <= "Z":
        return chr(ord(ch) + 32)
    return ch


def fold_text(text):
    """ASCII のみの大小折りたたみビュー (1:1 なので長さは入力と同一)。"""
    return "".join(_fold_char(ch) for ch in text)


# 正規化ビュー (v0.7): postal-jp / phone-jp / email は正規化して照合する。
# 対応表は 1 文字 → 1 文字に限定する (位置対応を保つため。NFKC のような
# 非 1:1 変換は使わない)。
#   - 全角 ASCII ブロック U+FF01..FF5E → U+0021..007E
#     (全角数字・全角英字・全角ハイフン U+FF0D・全角アット U+FF20 を含む)
#   - 異種ハイフン U+2010..2015 / U+2212 → U+002D ('-')
_NORMALIZED_BUILTINS = ("postal-jp", "phone-jp", "email")
_HYPHEN_CODEPOINTS = frozenset((0x2010, 0x2011, 0x2012, 0x2013,
                                0x2014, 0x2015, 0x2212))


def normalize_char(ch):
    """1 文字の正規化 (1:1 対応)。対応表外はそのまま。"""
    cp = ord(ch)
    if 0xFF01 <= cp <= 0xFF5E:
        return chr(cp - 0xFEE0)
    if cp in _HYPHEN_CODEPOINTS:
        return "-"
    return ch


def normalize_text(text):
    """正規化ビュー (1 文字 → 1 文字のため長さは入力と同一)。"""
    return "".join(normalize_char(ch) for ch in text)


# --------------------------------------------------------------- ルール解析

def _parse_mode(mode):
    """MODE ('+' / '~' 接頭辞つき) を解析する。

    戻り値: (word_unit, ci, base_mode)。接頭辞は任意の順で併用可
    (例: +label / ~label / +~label / ~+label)。接頭辞の後には
    MODE が必須 (空・未知は rc2)。
    """
    word_unit = False
    ci = False
    rest = mode
    while rest[:1] in ("+", "~"):
        if rest[0] == "+":
            word_unit = True
        else:
            ci = True
        rest = rest[1:]
    if rest not in MODES:
        raise UsageError(
            f"不明な MODE: {mode!r} (許容: {', '.join(MODES)}"
            " — 語単位一致は '+' 接頭辞, 大小無視は '~' 接頭辞"
            " (併用可, 例 秘密:+~label))")
    return word_unit, ci, rest


def _normalize_mode_arg(mode, arg):
    """MODE ごとの ARG 既定値と検証 (--rule / --builtin 共通)。"""
    if mode == "label":
        return arg if arg is not None else DEFAULT_LABEL_PREFIX
    if mode == "decor":
        return arg if arg is not None else DEFAULT_DECOR
    if mode == "replace":
        # ARG 必須 (空は delete が既に担う)
        if arg is None or arg == "":
            raise UsageError(
                "replace には置換後の文字列 (ARG) が必要です"
                " (空にしたい場合は delete を使用してください)")
        return arg
    if mode == "noise":
        if arg is None or arg == NOISE_SAME_CLASS:
            return None  # same-class (クラス外文字は据え置き)
        if arg not in CLASS_RANGES:
            raise UsageError(
                "noise の ARG は same-class または "
                f"{', '.join(sorted(CLASS_RANGES))} のいずれか: {arg!r}")
        return arg
    return None  # delete / mosaic は ARG を使わない


def parse_rule(spec, index):
    """--rule PATTERN:MODE[:ARG] を解析する。

    先頭 2 個の ':' で最大 3 分割 → PATTERN に ':' は使用不可、ARG は可。
    """
    parts = spec.split(":", 2)
    if len(parts) < 2:
        raise UsageError(
            "--rule は PATTERN:MODE[:ARG] の形式で指定してください"
            f" (MODE なし): {spec!r}")
    pattern, mode = parts[0], parts[1]
    arg = parts[2] if len(parts) == 3 else None
    if not pattern:
        raise UsageError("PATTERN が空です (空パターンは禁止)")
    word_unit, ci, mode = _parse_mode(mode)
    arg = _normalize_mode_arg(mode, arg)
    return Rule(index, "literal", "", pattern, pattern, mode, arg,
                word_unit, ci)


def parse_chars_arg(arg):
    """chars の CP-LIST (U+XXXX[,U+XXXX...]) を解析・正規化する。

    hex は大小同一・重複は初出順で排除。正規化形は U+ と 4 桁以上の
    大文字 16 進。サロゲート (D800–DFFF) と 0x10FFFF 超は使用法エラー。
    """
    if arg is None or arg == "":
        raise UsageError("chars には CP-LIST (U+XXXX[,U+XXXX...]) が必要です")
    cps = []
    for token in arg.split(","):
        t = token.strip()
        if len(t) < 3 or t[:2].upper() != "U+":
            raise UsageError(f"chars の CP-LIST は U+XXXX 表記で指定: {token!r}")
        hexpart = t[2:]
        if not hexpart or any(c not in "0123456789abcdefABCDEF"
                              for c in hexpart):
            raise UsageError(f"chars の CP-LIST は U+XXXX 表記で指定: {token!r}")
        cp = int(hexpart, 16)
        if 0xD800 <= cp <= 0xDFFF:
            raise UsageError(f"サロゲートは chars に指定できません: {t!r}")
        if cp > 0x10FFFF:
            raise UsageError(f"コードポイントが範囲外です: {t!r}")
        if cp not in cps:
            cps.append(cp)
    return ",".join(f"U+{cp:04X}" for cp in cps)


def parse_builtin(spec, index):
    """--builtin の spec を解析する。

    name 型:  NAME:MODE[:ARG]           (例: phone-jp:label:TEL-)
    chars 型: chars:CP-LIST:MODE[:ARG]  (例: chars:U+200B:delete)
    CP-LIST は --rule の PATTERN に対応する第 2 セグメントに置く。
    これにより chars + noise / replace の ARG と両立する
    (例: chars:U+0041:noise:digit / chars:U+0430:replace:a)。
    MODE には '+' 接頭辞可 (例: chars:U+0042:+delete)。
    """
    parts = spec.split(":", 3)
    name = parts[0]
    if name not in BUILTIN_NAMES:
        raise UsageError(
            f"不明な builtin NAME: {name!r} (許容: {', '.join(BUILTIN_NAMES)})")
    if name == "chars":
        if len(parts) < 3:
            raise UsageError(
                "chars は chars:CP-LIST:MODE[:ARG] の形式で指定してください"
                f": {spec!r}")
        cplist, mode = parts[1], parts[2]
        word_unit, ci, mode = _parse_mode(mode)
        arg = ":".join(parts[3:]) if len(parts) > 3 else None
        arg = _normalize_mode_arg(mode, arg)
        canon = parse_chars_arg(cplist)
        return Rule(index, "builtin", name, canon, "chars:" + canon,
                    mode, arg, word_unit, ci)
    if len(parts) < 2:
        raise UsageError(
            "--builtin は NAME:MODE[:ARG] の形式で指定してください"
            f" (MODE なし): {spec!r}")
    word_unit, ci, mode = _parse_mode(parts[1])
    arg = ":".join(parts[2:]) if len(parts) > 2 else None
    arg = _normalize_mode_arg(mode, arg)
    return Rule(index, "builtin", name, "", name, mode, arg,
                word_unit, ci)


# --------------------------------------------- 設定ファイルと --from-lens

def parse_config_lines(cfg_text, path):
    """--config の本文を解析し、(kind, spec) 列を返す。

    行書式: rule <spec> / builtin <spec> / '#' コメント / 空行。
    kind 後の最初の空白 1 個で分離し、spec 内の空白は保持する
    (spec は --rule / --builtin と同一文法)。
    未知 kind・書式不正は UsageError (rc2)。
    """
    matchers = []
    for lineno, raw in enumerate(cfg_text.split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        kind, _, spec = line.partition(" ")
        if kind not in ("rule", "builtin", "region"):
            raise UsageError(
                f"--config {path!r} {lineno} 行目: 不明な kind: {kind!r}")
        if not spec:
            raise UsageError(
                f"--config {path!r} {lineno} 行目: spec が空です")
        matchers.append((kind, spec))
    return matchers


# --------------------------------- スキーマゲート (契約 v1 同梱部)

_FROM_LENS_MAX_BYTES = 1048576  # --from-lens 入力の上限 (超過は rc2)


def _reject_constant(name):
    """JSON 層の門番: NaN / Infinity / -Infinity を拒否する。"""
    raise UsageError(
        f"--from-lens: JSON 仕様外の定数は許可されません: {name}")


def _pairs_without_duplicates(pairs):
    """JSON 層の門番: 同一オブジェクト内の重複キーを拒否する。"""
    obj = {}
    for key, val in pairs:
        if key in obj:
            raise UsageError(
                f"--from-lens: JSON オブジェクトでキーが重複しています: "
                f"{key!r}")
        obj[key] = val
    return obj


def _strict_json_loads(text):
    """重複キーと NaN/Infinity を拒否する json.loads (stdlib のみ)。"""
    return json.loads(text, parse_constant=_reject_constant,
                      object_pairs_hook=_pairs_without_duplicates)


def _pointer(base, token):
    """JSON Pointer (RFC 6901) のトークンを 1 段追加する。"""
    return base + "/" + token.replace("~", "~0").replace("/", "~1")


def _type_ok(val, expected):
    """期待型の判定。bool は int の亜種として厳格に排除する。"""
    if expected is int:
        return isinstance(val, int) and not isinstance(val, bool)
    return isinstance(val, expected)


def _validate_schema(data, spec, ptr):
    """宣言スキーマによる構造検証 (Schema Contract v1 の Redact 同梱部)。

    語彙: type / required / enum / item_type / item_schema — Contract v1
    全語彙のうち catalog v1 が使うサブセットのみを同梱する。
    規則: 未知キーは無視せず拒否 / 型変換 (coercion) は一切しない /
    fail-fast / エラーは JSON Pointer 付き UsageError (rc2)。
    再帰深さはスキーマ深さで有界 (入力データの深さに依存しない)。
    """
    if not isinstance(data, dict):
        raise UsageError(
            f"--from-lens: {ptr or '(root)'}: オブジェクトである必要があります: "
            f"{type(data).__name__}")
    extra = sorted(set(data) - set(spec))
    if extra:
        raise UsageError(
            f"--from-lens: {ptr or '(root)'}: 許可されていないキー: "
            f"{', '.join(extra)} (許可: {', '.join(sorted(spec))})")
    for key, rule in spec.items():
        if key not in data:
            if rule.get("required", True):
                raise UsageError(
                    f"--from-lens: {_pointer(ptr, key)}: "
                    "必須フィールドが欠損しています")
            continue
        val = data[key]
        field = _pointer(ptr, key)
        expected = rule.get("type")
        if expected is not None and not _type_ok(val, expected):
            raise UsageError(
                f"--from-lens: {field}: 型が不正です "
                f"(期待: {expected.__name__}, 実際: {type(val).__name__})")
        allowed_values = rule.get("enum")
        if allowed_values is not None and val not in allowed_values:
            raise UsageError(
                f"--from-lens: {field}: 許可された値ではありません: {val!r} "
                f"(許可: {', '.join(repr(v) for v in allowed_values)})")
        item_type = rule.get("item_type")
        if item_type is not None:
            for idx, item in enumerate(val):
                if not _type_ok(item, item_type):
                    raise UsageError(
                        f"--from-lens: {field}/{idx}: 型が不正です "
                        f"(期待: {item_type.__name__}, "
                        f"実際: {type(item).__name__})")
        item_schema = rule.get("item_schema")
        if item_schema is not None:
            for idx, item in enumerate(val):
                _validate_schema(item, item_schema, f"{field}/{idx}")


# 契約 v1 (Redact Bridge catalog) の宣言スキーマ。実装からの抽出であり、
# lens / kind は契約上のキーだが Redact は使用しない (検証のみ)。
# count / positions は省略可。値域の追加制約 (例: count >= 0) は現行の
# 受容範囲を変えるため導入しない。
_FROM_LENS_SCHEMA = {
    "lens": {"required": False, "type": str},
    "version": {"required": True, "type": int, "enum": (1,)},
    "observations": {"required": True, "type": list, "item_schema": {
        "kind": {"required": False, "type": str},
        "codepoint": {"required": True, "type": str},
        "count": {"required": False, "type": int},
        "positions": {"required": False, "type": list, "item_type": int},
        "twin": {"required": False, "type": str},
    }},
}


def load_lens_codepoints(path):
    """--from-lens の観測 JSON (契約 v1 + twin) を読む。

    二層検証 (Schema Contract v1 の Redact 同梱ゲート):
      1. JSON 層: UTF-8 厳格・重複キー拒否・NaN/Infinity 拒否・
         _FROM_LENS_MAX_BYTES 上限。
      2. スキーマ層: _FROM_LENS_SCHEMA による構造・型・enum 検証。
         未知キーは無視せず拒否し、型変換は一切行わない。
    意味層: codepoint / twin を parse_chars_arg で解釈し、単一コード
    ポイントに制限する。戻り値: [(正規化CP, twin正規化CP or None)] —
    初出順・重複排除 (同一 codepoint は初出エントリの twin 属性を採用)。
    twin ありのエントリは chars:<CP>:replace:<twin の文字>、なしは
    chars:<CP>:delete になる (呼び出し側で生成)。
    全ての入力拒否は UsageError (rc2)。読み込み失敗 (OSError) は
    呼び出し側で rc1 にする。
    """
    with open(path, "rb") as fh:
        fh.seek(0, 2)
        if fh.tell() > _FROM_LENS_MAX_BYTES:
            raise UsageError(
                f"--from-lens: ファイルが大きすぎます "
                f"(上限: {_FROM_LENS_MAX_BYTES} バイト): {path!r}")
        fh.seek(0)
        raw = fh.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UsageError(f"--from-lens を UTF-8 として解釈できません: {exc}")
    try:
        doc = _strict_json_loads(text)
    except json.JSONDecodeError as exc:
        raise UsageError(f"--from-lens の JSON を解釈できません: {exc}")
    _validate_schema(doc, _FROM_LENS_SCHEMA, "")
    order = []  # [(canon, twin_canon or None)] — 初出順
    seen = {}   # canon -> twin (初出の属性を採用)
    for i, item in enumerate(doc["observations"]):
        base = f"/observations/{i}"
        try:
            canon = parse_chars_arg(item["codepoint"])
        except UsageError as exc:
            raise UsageError(f"--from-lens: {base}/codepoint: {exc}")
        if "," in canon:
            raise UsageError(
                f"--from-lens: {base}/codepoint: 複数のコードポイントは"
                f" 許可されません: {item['codepoint']!r}")
        twin = None
        if "twin" in item:
            try:
                twin = parse_chars_arg(item["twin"])
            except UsageError as exc:
                raise UsageError(f"--from-lens: {base}/twin: {exc}")
            if "," in twin:
                raise UsageError(
                    f"--from-lens: {base}/twin: 単一コードポイントのみ"
                    f" 許可されます: {item['twin']!r}")
        if canon not in seen:
            seen[canon] = twin
            order.append((canon, twin))
    return order


# --------------------------------------------------------------- マッチング

def find_matches(text, pattern):
    """左端優先・非重複で全一致を列挙する。戻り値: [(開始文字位置, 長さ)]。"""
    matches = []
    n = len(pattern)
    if n == 0:
        return matches
    pos = 0
    limit = len(text) - n
    while pos <= limit:
        if text[pos:pos + n] == pattern:
            matches.append((pos, n))
            pos += n  # 重なりは排他
        else:
            pos += 1
    return matches


def classify(ch):
    """文字のクラス名。6 クラスのどれにも属さなければ None。"""
    for name, rng in CLASS_RANGES.items():
        if ord(ch) in rng:
            return name
    return None


def char_byte_offsets(text):
    """各文字の入力先頭からのバイトオフセット (長さ len(text)+1 の配列)。"""
    offs = [0] * (len(text) + 1)
    acc = 0
    for i, ch in enumerate(text):
        offs[i] = acc
        acc += len(ch.encode("utf-8"))
    offs[-1] = acc
    return offs


def noise_char(seed, byte_offset, ch, pool):
    """SHA-256(seed:byte_offset:original_char) の先頭バイトを pool の索引に使う。"""
    h = hashlib.sha256(f"{seed}:{byte_offset}:{ch}".encode("utf-8")).digest()
    return pool[h[0] % len(pool)]


# ----------------------------------------------------- 組込文字種 matcher

def match_postal_jp(text):
    """[0-9]{3}-[0-9]{4}。直前・直後が ASCII digit なら不一致。"""
    matches = []
    n = len(text)
    pos = 0
    while pos + 8 <= n:
        if (text[pos + 3] == "-"
                and _is_ascii_digit(text[pos])
                and _is_ascii_digit(text[pos + 1])
                and _is_ascii_digit(text[pos + 2])
                and _is_ascii_digit(text[pos + 4])
                and _is_ascii_digit(text[pos + 5])
                and _is_ascii_digit(text[pos + 6])
                and _is_ascii_digit(text[pos + 7])):
            before_ok = pos == 0 or not _is_ascii_digit(text[pos - 1])
            after_ok = pos + 8 >= n or not _is_ascii_digit(text[pos + 8])
            if before_ok and after_ok:
                matches.append((pos, 8))
                pos += 8  # 重なりは排他
                continue
        pos += 1
    return matches


# phone-jp の形状と試行順 (総長降順・同長はこの固定順)。
# 各要素: (市外局番長, 市内局番長, 加入者番号長, 接頭辞制約)
#   None  : 0 開始のみで追加制約なし
#   "433" : 接頭辞が {0120, 0570, 0800} のみ
#   "424" : 接頭辞が 0[1-9]XX かつ "433" 接頭辞集合に非所属
#           (08xx / 09xx の地理 4 桁市外局番を含む — v0.7)
_PHONE_SHAPES = (
    (3, 4, 4, None),
    (4, 3, 3, "433"),
    (3, 3, 4, None),
    (4, 2, 4, "424"),
    (2, 4, 4, None),
)

_PHONE_433_PREFIXES = ("0120", "0570", "0800")

# 短縮番号 (3 桁・ハイフンなし)。v0.7 から phone-jp に含める。
_PHONE_SHORT_NUMBERS = frozenset(
    ("104", "106", "110", "117", "118", "119", "171"))


def _phone_prefix_ok(constraint, area):
    """形状ごとの接頭辞制約。area は検証済みの数字列 (先頭 '0')。"""
    if constraint is None:
        return True
    if constraint == "433":
        return area in _PHONE_433_PREFIXES
    # "424": 0[1-9]XX かつ 433 接頭辞に非所属 (08xx/09xx を含む)
    return area[1] in "123456789" and area not in _PHONE_433_PREFIXES


def match_phone_jp(text):
    """0 開始の電話番号と短縮番号。両側 ASCII digit 境界。

    試行順: (3,4,4) → (4,3,3) → (3,3,4) → (4,2,4) → (2,4,4)、
    短縮番号 (104/106/110/117/118/119/171 — ハイフンなし 3 桁)。
    """
    matches = []
    n = len(text)
    pos = 0
    while pos < n:
        if text[pos] == "0":
            for a, b, c, constraint in _PHONE_SHAPES:
                total = a + b + c + 2
                end = pos + total
                if end > n:
                    continue
                seg = text[pos:end]
                hy1, hy2 = a, a + 1 + b
                if seg[hy1] != "-" or seg[hy2] != "-":
                    continue
                g1 = seg[:hy1]
                g2 = seg[hy1 + 1:hy2]
                g3 = seg[hy2 + 1:]
                if not (_all_ascii_digits(g1) and _all_ascii_digits(g2)
                        and _all_ascii_digits(g3)):
                    continue
                if not _phone_prefix_ok(constraint, g1):
                    continue
                before_ok = pos == 0 or not _is_ascii_digit(text[pos - 1])
                after_ok = end >= n or not _is_ascii_digit(text[end])
                if before_ok and after_ok:
                    matches.append((pos, total))
                    pos = end
                    break
            else:
                pos += 1
        elif text[pos] == "1":
            # 短縮番号 (3 桁・ハイフンなし)。両側 ASCII digit 境界。
            end = pos + 3
            if text[pos:end] in _PHONE_SHORT_NUMBERS:
                before_ok = pos == 0 or not _is_ascii_digit(text[pos - 1])
                after_ok = end >= n or not _is_ascii_digit(text[end])
                if before_ok and after_ok:
                    matches.append((pos, 3))
                    pos = end
                    continue
            pos += 1
        else:
            pos += 1
    return matches


_EMAIL_LOCAL = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-")
_EMAIL_TAIL_BAD = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-")


def _match_domain(text, i):
    """domain = label('.'label)+ を解析する。

    label は英数字開始終端・内部ハイフン可。列挙は構造上の破綻で打ち
    切り、それまでの label 列で確定を試みる (手前まで一致 — テールの
    非 ASCII 境界で一致全体を潰さない)。label 2 個未満、または最終
    label が英字 2 文字未満なら None。戻り値はドメイン末尾位置。
    """
    n = len(text)
    labels = []
    pos = i
    while True:
        if pos >= n or not _is_ascii_alnum(text[pos]):
            break
        j = pos
        while j < n and (_is_ascii_alnum(text[j]) or text[j] == "-"):
            j += 1
        if text[j - 1] == "-":
            break
        labels.append((pos, j))
        if j < n and text[j] == ".":
            pos = j + 1
            continue
        break
    if len(labels) < 2:
        return None
    fs, fe = labels[-1]
    tld = text[fs:fe]
    if len(tld) < 2 or not all(_is_ascii_alpha(c) for c in tld):
        return None
    return fe


def match_email(text):
    """ASCII 簡易 email 一致。

    local = [A-Za-z0-9._%+-]+ の連続走査。末尾 '.' を除去、先頭 '.' は
    一致に含めない。一致直後の文字が [A-Za-z0-9.-] なら全体を拒否
    (部分一致を残さない)。'、' 等の非 ASCII 境界では手前まで一致。
    """
    matches = []
    n = len(text)
    pos = 0
    while pos < n:
        if text[pos] in _EMAIL_LOCAL:
            k = pos
            while k < n and text[k] in _EMAIL_LOCAL:
                k += 1
            li = pos
            while li < k and text[li] == ".":
                li += 1
            le = k
            while le > li and text[le - 1] == ".":
                le -= 1
            if li < le and le < n and text[le] == "@":
                end = _match_domain(text, le + 1)
                if end is not None and (end >= n
                                        or text[end] not in _EMAIL_TAIL_BAD):
                    matches.append((li, end - li))
                    pos = end
                    continue
        pos += 1
    return matches


def match_chars(text, canon, ci=False):
    """正規化 CP-LIST の各コードポイントの全出現 (単独・位置昇順)。

    ci=True の場合は ASCII 英字の大小両方を対象にする
    (U+0041 は 'A' と 'a' の両方に一致)。
    """
    matches = []
    for token in canon.split(","):
        ch = chr(int(token[2:], 16))
        if ci:
            # 大小両方の ASCII 変種を対象にする (U+0041 ↔ U+0061)
            targets = {ch, _fold_char(ch)}
            if "a" <= ch <= "z":
                targets.add(chr(ord(ch) - 32))
        else:
            targets = (ch,)
        for target in targets:
            start = text.find(target)
            while start >= 0:
                matches.append((start, 1))
                start = text.find(target, start + 1)
    matches.sort()
    return matches


def enumerate_matches(text, rule, norm_text=None):
    """1 matcher の全一致を左端優先・非重複で列挙する。

    postal-jp / phone-jp / email は正規化ビューで照合する。正規化は
    1:1 なので戻り値の位置は元の text と同一。norm_text は呼び出し
    側で再利用する場合に渡す (省略時は内部で計算)。literal と
    chars は常に元の text で照合する (正規化の対象外)。
    """
    if rule.kind == "literal":
        if rule.ci:
            return find_matches(fold_text(text), fold_text(rule.pattern))
        return find_matches(text, rule.pattern)
    if rule.name in _NORMALIZED_BUILTINS:
        if norm_text is None:
            norm_text = normalize_text(text)
        if rule.name == "postal-jp":
            return match_postal_jp(norm_text)
        if rule.name == "phone-jp":
            return match_phone_jp(norm_text)
        return match_email(norm_text)
    return match_chars(text, rule.pattern, rule.ci)  # chars


# ----------------------------------------------------- 語単位一致

def _boundary_rejects(edge, neigh):
    """1 辺判定: 辺文字と隣接文字が (a) 同一クラス (非 None) または
    (b) ともに ASCII 英数字、ならば棄却。"""
    ce, cn = classify(edge), classify(neigh)
    if ce is not None and cn is not None and ce == cn:
        return True
    return _is_ascii_alnum(edge) and _is_ascii_alnum(neigh)


def word_unit_ok(text, start, length):
    """マッチ両端の境界判定。

    テキスト端は隣接文字なし = 境界 (棄却しない)。どちらか片端でも
    棄却されれば False (マッチ全体を棄却)。
    """
    end = start + length
    if start > 0 and _boundary_rejects(text[start], text[start - 1]):
        return False
    if end < len(text) and _boundary_rejects(text[end - 1], text[end]):
        return False
    return True


# --------------------------------------------------------------- コア適用

def apply_redactions(text, rules):
    """重複解決と全様式の適用 (全 matcher ソースを通算)。

    戻り値: (出力テキスト, redactions)
      - redactions の start/end/length は入力バイトオフセット
      - label の連番は適用順 (= 位置昇順) で全ルール通し
      - 語単位のマッチは列挙時に境界棄却される
      - postal-jp / phone-jp / email は正規化ビューで照合し、マスクは
        元テキストの区間に適用する (レシートの位置も元テキスト基準)
    """
    norm_text = normalize_text(text)
    # ルールは宣言順に試行し、既確定区間と重なる後発マッチは捨てる。
    # 確定区間は常に非交差なので、開始位置の整列配列 + 2 分探索で
    # 重なりを判定する (v0.9.1・A-5 — v0.9.0 は全確定区間への線形走査で
    # 件数の 2 乗で遅かった。結果は素朴な実装と完全一致。
    # tests/test_v0_9_1_hardening.py の参照実装がそれを固定する)。
    confirmed = []  # (開始文字位置, 長さ, Rule)
    starts = []     # 確定区間の開始位置 (整列・非交差)
    ends = []       # 確定区間の終了位置 (開始位置と同順で整列)
    for rule in rules:
        for start, length in enumerate_matches(text, rule, norm_text):
            if rule.word_unit and not word_unit_ok(text, start, length):
                continue
            end = start + length
            # 最後の「start 未満で終わる可能性がある」区間だけ調べる:
            # hi = 開始位置が end 未満の最後の区間。確定区間は非交差
            # なので ends も整列しており、ends[hi] > start なら重なる。
            hi = bisect.bisect_left(starts, end) - 1
            if hi >= 0 and ends[hi] > start:
                continue
            idx = bisect.bisect_right(starts, start)
            starts.insert(idx, start)
            ends.insert(idx, end)
            confirmed.append((start, length, rule))
    # 確定した全区間は位置昇順でソートしてから適用
    confirmed.sort(key=lambda c: (c[0], c[1]))

    offs = char_byte_offsets(text)
    # 厳密に UTF-8 デコード済みなので再エンコードは元バイト列と完全一致する
    data = text.encode("utf-8")

    out_parts = []
    redactions = []
    label_counter = 0
    pos = 0
    for start, length, rule in confirmed:
        out_parts.append(text[pos:start])
        seg = text[start:start + length]
        seg_bytes = data[offs[start]:offs[start + length]]

        if rule.mode == "delete":
            repl = ""
        elif rule.mode == "mosaic":
            repl = "█" * length  # 1 文字ごとに埋め (文字数保存)
        elif rule.mode == "label":
            label_counter += 1
            repl = f"{rule.arg}{label_counter}"
        elif rule.mode == "decor":
            repl = f"{rule.arg}{seg}{rule.arg}"
        elif rule.mode == "replace":
            repl = rule.arg  # 区間を ARG で一括置換 (1 回)
        else:  # noise
            pieces = []
            for k, ch in enumerate(seg):
                pool_name = rule.arg if rule.arg is not None else classify(ch)
                if (pool_name is None and rule.kind == "builtin"
                        and rule.name in _NORMALIZED_BUILTINS):
                    # 正規化ビューで照合したクラス外文字 (全角数字など)
                    # は正規化後のクラスで same-class 置換する
                    pool_name = classify(norm_text[start + k])
                if pool_name is None:
                    pieces.append(ch)  # クラス外は same-class では据え置き
                else:
                    pool = CLASS_CHARS[pool_name]
                    pieces.append(
                        noise_char(rule.seed, offs[start + k], ch, pool))
            repl = "".join(pieces)

        out_parts.append(repl)
        entry = {
            "rule_index": rule.index,
            "matcher": ("literal" if rule.kind == "literal"
                        else f"builtin:{rule.name}"),
            "mode": rule.mode,
            "start": offs[start],
            "end": offs[start + length],
            "length": offs[start + length] - offs[start],
            "content_sha256": hashlib.sha256(seg_bytes).hexdigest(),
            "replacement_length": len(repl.encode("utf-8")),
        }
        if rule.word_unit:
            entry["word_unit"] = True  # additive (語単位のみ出現)
        if (rule.kind == "builtin" and rule.name in _NORMALIZED_BUILTINS
                and seg != norm_text[start:start + length]):
            entry["normalized"] = True  # additive (正規化ビューで照合)
        if rule.ci:
            entry["case_insensitive"] = True  # additive ('~' ルール)
        redactions.append(entry)
        pos = start + length
    out_parts.append(text[pos:])
    return "".join(out_parts), redactions


# --------------------------------------------------------------- 完全性検証

def verify_byte_integrity(input_bytes, output_bytes, redactions):
    """非マッチ区間のバイト列が入出力で完全一致することを検証する。

    注意: 受け入れ試験が fault-injection でこの関数を差し替えるため、
    モジュールレベルの公開契約 (名前と呼び出し形態) は変更しないこと。
    """
    i = o = 0
    for r in sorted(redactions, key=lambda r: r["start"]):
        gap = r["start"] - i
        if gap < 0:
            return False
        if input_bytes[i:i + gap] != output_bytes[o:o + gap]:
            return False
        i = r["start"] + r["length"]
        o += gap + r["replacement_length"]
    return input_bytes[i:] == output_bytes[o:]


# --------------------------------------------------------------- レシート

def measure_pattern_appearance(out_text, rules):
    """「パターンが出力に残っていない」ことの測定 (約束ではなく測定)。

    literal の生パターンのみを測定対象とする (組込 matcher は
    可変長なので「パターン文字列」が定義されない)。'~' ルールは
    ASCII 折りたたみ同士で比較する (大小無視の残留も検出する)。
    """
    for rule in rules:
        if rule.kind != "literal":
            continue
        if rule.ci:
            if fold_text(rule.pattern) in fold_text(out_text):
                return "found"
        elif rule.pattern in out_text:
            return "found"
    return "none"


def build_machine_receipt(input_byte_len, out_bytes, redactions,
                          integrity_ok, appearance):
    """Machine Receipt (JSON)。機密本文は含まない (content_sha256 のみ)。"""
    return {
        "input_bytes": input_byte_len,
        "output_bytes": len(out_bytes),
        "redactions": redactions,
        "total_redactions": len(redactions),
        "byte_integrity_verified": integrity_ok,
        "pattern_appearance_in_output": appearance,
    }


def human_receipt(lang, input_byte_len, out_bytes, redactions,
                  integrity_ok, appearance):
    """Human Receipt (標準出力)。位置・長さ・モード・ハッシュのみ。"""
    if lang == "en":
        lines = [
            f"Sieve Redact v{VERSION} — receipt",
            f"input: {input_byte_len} bytes -> output: {len(out_bytes)} bytes",
            f"redactions: {len(redactions)}",
        ]
        integ = ("byte integrity: verified" if integrity_ok
                 else "byte integrity: FAILED")
        appear = f"pattern appearance in output: {appearance}"
    else:
        lines = [
            f"Sieve Redact v{VERSION} — レシート",
            f"入力: {input_byte_len} バイト -> 出力: {len(out_bytes)} バイト",
            f"redact 件数: {len(redactions)}",
        ]
        integ = ("他バイト完全性: 検証済み" if integrity_ok
                 else "他バイト完全性: 検証失敗")
        appear = f"出力内パターン残留: {appearance}"
    for n, r in enumerate(redactions, 1):
        extra = ""
        if r.get("normalized"):
            extra += " normalized"
        if r.get("case_insensitive"):
            extra += " ci"
        lines.append(
            f"  #{n} rule={r['rule_index']} matcher={r['matcher']}"
            f" mode={r['mode']}"
            f" pos={r['start']}..{r['end']} len={r['length']}B"
            f" -> {r['replacement_length']}B"
            f" sha256={r['content_sha256'][:12]}...{extra}")
    lines.append(integ)
    lines.append(appear)
    return "\n".join(lines)


# --------------------------------------------------------------- CLI

class _MatcherAction(argparse.Action):
    """--rule / --builtin / --from-lens を CLI の宣言順に 1 つのリストへ
    保持する。--from-lens は ("fromlens", path) として記録され、
    ルール構築時にその位置で chars ルールへ展開される。"""

    def __call__(self, parser, namespace, values, option_string=None):
        if option_string == "--builtin":
            kind = "builtin"
        elif option_string == "--from-lens":
            kind = "fromlens"
        else:
            kind = "literal"
        matchers = getattr(namespace, "matchers", None)
        if matchers is None:
            matchers = []
            namespace.matchers = matchers
        matchers.append((kind, values))


def build_argparser():
    parser = argparse.ArgumentParser(
        prog="sieve-redact",
        description="Sieve Redact — 決定的なテキスト redaction"
                    " (生文字列一致のみ・正規表現は扱わない)")
    parser.add_argument("input", help="入力テキストファイル (UTF-8)")
    parser.add_argument("-o", "--output", required=True,
                        help="出力先 (入力と同一パスは拒否 — in-place 不可)")
    parser.add_argument("--rule", action=_MatcherAction, dest="matchers",
                        metavar="PATTERN:MODE[:ARG]",
                        help="ルール。複数回指定可・宣言順に試行。"
                             "MODE: delete|mosaic|label|noise|decor|replace"
                             " (語単位一致は '+' 接頭辞, 大小無視は '~' 接頭辞"
                             " — 併用可, 例 秘密:+~label。"
                             "PATTERN に ':' は使用不可)")
    parser.add_argument("--builtin", action=_MatcherAction, dest="matchers",
                        metavar="NAME:MODE[:ARG]",
                        help="組込文字種。NAME: postal-jp|phone-jp|email|chars"
                             " (chars は chars:CP-LIST:MODE[:ARG])。"
                             "複数回指定可・--rule と通しで宣言順に試行")
    parser.add_argument("--from-lens", action=_MatcherAction, dest="matchers",
                        metavar="FILE",
                        help="Sieve Lens 観測 JSON (契約 v1 + twin) から"
                             " chars ルールを生成し、このフラグ位置に展開する。"
                             "複数回指定可")
    parser.add_argument("--config", metavar="FILE",
                        help="設定ファイル。行書式: rule <spec> / builtin <spec>"
                             " / '#' コメント / 空行。spec は CLI と同一文法。"
                             "適用順は常に --rule / --builtin / --from-lens より先")
    parser.add_argument("--strict", action="store_true",
                        help="他バイト完全性の検証に失敗したら出力せず終了コード 3")
    parser.add_argument("--receipt", metavar="FILE",
                        help="Machine Receipt (JSON) の出力先")
    parser.add_argument("--lang", choices=("ja", "en"), default="ja",
                        help="Human Receipt の言語 (既定 ja)")
    parser.add_argument(
        "--region", action="append", default=None,
        metavar="x,y,w,h:MODE[:ARG]",
        help="image region masking (PNG/JPEG input; output is always PNG): x,y,w,h then MODE and optional ARG; repeatable; overlapping regions discarded")
    return parser



def _mosaic_rect(px, rect, block):
    rx, ry, rw, rh = rect["x"], rect["y"], rect["w"], rect["h"]
    for by in range(ry, ry + rh, block):
        for bx in range(rx, rx + rw, block):
            ex = min(bx + block, rx + rw)
            ey = min(by + block, ry + rh)
            xs = range(bx, ex)
            ys = range(by, ey)
            count = len(xs) * len(ys)
            totals = None
            for y in ys:
                for x in xs:
                    v = px[x, y]
                    if totals is None:
                        totals = list(v)
                    else:
                        for i in range(len(v)):
                            totals[i] += v[i]
            avg = tuple(t // count for t in totals)
            for y in ys:
                for x in xs:
                    px[x, y] = avg


def _border_rect(px, rect, color, width):
    rx, ry, rw, rh = rect["x"], rect["y"], rect["w"], rect["h"]
    for y in range(ry, ry + rh):
        for x in range(rx, rx + rw):
            on = (x < rx + width or x >= rx + rw - width
                  or y < ry + width or y >= ry + rh - width)
            if on:
                px[x, y] = color


def main_image(args):
    if getattr(args, "matchers", None):
        print("sieve-redact: error: --rule cannot be combined with "
              "--region (image mode)", file=sys.stderr)
        return 2
    if _same_target_file(args.input, args.output):
        print("sieve-redact: error: in-place output is not allowed "
              "(-o must differ from the input)", file=sys.stderr)
        return 2
    if not PIL_AVAILABLE:
        print("sieve-redact: error: Pillow is required for --region "
              "(pip install sieve-redact[image])", file=sys.stderr)
        return 2
    try:
        regions = [parse_region_spec(s) for s in args.region]
    except ValueError as exc:
        print("sieve-redact: error: %s" % exc, file=sys.stderr)
        return 2
    try:
        data = Path(args.input).read_bytes()
    except OSError as exc:
        print("sieve-redact: error: cannot read input: %s" % exc,
              file=sys.stderr)
        return 1
    try:
        width, height = check_png_input(data)
        input_format = "PNG"
    except ValueError as png_exc:
        try:
            width, height = check_jpeg_input(data)
            input_format = "JPEG"
        except ValueError as jpeg_exc:
            detail = jpeg_exc if data[:3] == JPEG_SIGNATURE else png_exc
            print("sieve-redact: error: %s" % detail, file=sys.stderr)
            return 2
    # A-1 (v0.9.1): 画素数の上限。ヘッダから取得した寸法で、画素を
    # 展開する重い処理の前に拒否する。メッセージには数値のみを載せる。
    if width * height > MAX_IMAGE_PIXELS:
        print("sieve-redact: error: image too large: %d pixels "
              "(limit: %d pixels)" % (width * height, MAX_IMAGE_PIXELS),
              file=sys.stderr)
        return 2
    for r in regions:
        if r["x"] + r["w"] > width or r["y"] + r["h"] > height:
            print("sieve-redact: error: region %d,%d,%d,%d exceeds image "
                  "bounds %dx%d" % (r["x"], r["y"], r["w"], r["h"],
                                    width, height), file=sys.stderr)
            return 2
    import io
    try:
        # A-1 (v0.9.1): Pillow の decompression bomb 閾値を超えた画像は
        # 警告・例外とも同じ拒否に変換する (トレースバックを出さない)。
        # 警告は例外に昇格させてから既存の except で受ける。
        with warnings.catch_warnings():
            warnings.simplefilter(
                "error", getattr(Image, "DecompressionBombWarning", UserWarning))
            img = Image.open(io.BytesIO(data))
            img.load()
    except Exception as exc:
        # JPEG payloads are not byte-prevalidated; decode failures must
        # surface as a clean usage error, never a traceback.
        print("sieve-redact: error: cannot decode image: %s" % exc,
              file=sys.stderr)
        return 2
    if getattr(img, "is_animated", False) or getattr(img, "n_frames", 1) > 1:
        print("sieve-redact: error: animated image is not supported",
              file=sys.stderr)
        return 2
    if img.mode not in ("RGB", "RGBA"):
        print("sieve-redact: error: unsupported image color mode: %s "
              "(RGB/RGBA PNG or RGB JPEG only)" % img.mode,
              file=sys.stderr)
        return 2

    accepted = []
    for r in regions:
        if any(_rects_overlap(r, a) for a in accepted):
            continue
        accepted.append(r)

    orig = img.copy()
    out = img.copy()
    orig_px = orig.load()
    out_px = out.load()
    bands = len(img.getbands())
    white = tuple([255] * bands)
    black = tuple([0] * bands)
    rect_rows = []
    ordinal = 0
    font = ImageFont.load_default() if PIL_AVAILABLE else None
    for r in accepted:
        ordinal += 1
        rect_rows.append({
            "x": r["x"], "y": r["y"], "w": r["w"], "h": r["h"],
            "mode": r["mode"],
            "arg_sha256": (hashlib.sha256(r["arg"].encode("utf-8")).hexdigest()
                           if r["arg"] is not None else None),
            "pixel_sha256": hashlib.sha256(_rect_pixels(orig, r)).hexdigest(),
        })
        if r["mode"] == "delete":
            _fill_rect(out_px, r, white)
        elif r["mode"] == "mosaic":
            _mosaic_rect(out_px, r, int(r["arg"]) if r["arg"] else 8)
        elif r["mode"] == "noise":
            for y in range(r["y"], r["y"] + r["h"]):
                for x in range(r["x"], r["x"] + r["w"]):
                    v = orig_px[x, y]
                    d = hashlib.sha256(
                        ("img:%d:%d:%d,%d,%d"
                         % (x, y, v[0], v[1], v[2])).encode("utf-8")
                    ).digest()
                    out_px[x, y] = (d[0], d[1], d[2]) + tuple(v[3:])
        elif r["mode"] == "decor":
            color = tuple(int(r["arg"][i:i + 2], 16) for i in (0, 2, 4))
            if bands == 4:
                color = color + (255,)
            _border_rect(out_px, r, color, 2)
        elif r["mode"] == "label":
            label_bg = (0, 0, 0) + ((255,) if bands == 4 else ())
            _fill_rect(out_px, r, label_bg)
            tile = Image.new(img.mode, (r["w"], r["h"]), label_bg)
            tdraw = ImageDraw.Draw(tile)
            tdraw.text((2, 2), "%s%d" % (LABEL_PREFIX_DEFAULT, ordinal),
                       font=font, fill=white)
            out.paste(tile, (r["x"], r["y"]))
        elif r["mode"] == "replace":
            _fill_rect(out_px, r, white)
            tile = Image.new(img.mode, (r["w"], r["h"]), white)
            tdraw = ImageDraw.Draw(tile)
            tdraw.text((2, 2), r["arg"], font=font, fill=black)
            out.paste(tile, (r["x"], r["y"]))

    # A-2 (v0.9.1): 整合検査を Pillow の C 実装に置き換えた。
    # 差分画像 (ImageChops.difference) の「領域外が全て 0」を判定する
    # のは、従来の純 Python の画素ループと同じ述語 — getbbox は
    # RGBA で既定が alpha のみ判定のため alpha_only=False が必須。
    # 64 メガピクセルで 37 秒 → 0.07 秒 (実測・当環境)。
    integrity_ok = True
    if accepted:
        diff = ImageChops.difference(orig, out)
        wipe = ImageDraw.Draw(diff)
        for r in accepted:
            wipe.rectangle((r["x"], r["y"],
                            r["x"] + r["w"] - 1, r["y"] + r["h"] - 1),
                           fill=0)
        integrity_ok = diff.getbbox(alpha_only=False) is None
    if args.strict and not integrity_ok:
        print("sieve-redact: error: pixel integrity verification failed — "
              "--strict refuses to write the output", file=sys.stderr)
        return 3

    clean = Image.frombytes(img.mode, img.size, out.tobytes())
    out_path = Path(args.output)
    # A-4 (v0.9.1): 一時ファイルに書いてから置き換える。
    try:
        _atomic_save_image(clean, out_path)
    except OSError as exc:
        print("sieve-redact: error: cannot write output: %s" % exc,
              file=sys.stderr)
        return 1
    out_bytes = out_path.stat().st_size
    receipt = {
        "input_bytes": len(data),
        "output_bytes": out_bytes,
        "input_format": input_format,
        "input_mode": img.mode,
        "redactions": [],
        "rects": rect_rows,
        "total_redactions": 0,
        "byte_integrity_verified": None,
        "pixel_integrity_verified": integrity_ok,
        "pattern_appearance_in_output": "none",
    }
    if args.receipt:
        try:
            _atomic_write(
                args.receipt,
                (json.dumps(receipt, ensure_ascii=False, indent=2)
                 + "\n").encode("utf-8"))
        except OSError as exc:
            print("sieve-redact: error: cannot write receipt: %s" % exc,
                  file=sys.stderr)
            return 1
    print("Sieve Redact v%s — レシート" % VERSION)
    print("入力: %s %dx%d (%s) -> 出力: PNG %dx%d"
          % (input_format, width, height, img.mode, width, height))
    print("redact regions: %d (discarded overlaps: %d)"
          % (len(accepted), len(regions) - len(accepted)))
    print("完全性: %s(画素)"
          % ("検証済み" if integrity_ok else "失敗"))
    print("metadata: 除去")
    return 0



def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # ASCII ロケール環境の安全装置
    args = build_argparser().parse_args(argv)
    # --config: 読み込み失敗は rc1・書式不正は rc2。
    # 適用順は config が常に先頭 (CLI 上のフラグ位置に依存しない)。
    config_matchers = []
    config_regions = []
    if args.config:
        try:
            with open(args.config, "r", encoding="utf-8") as fh:
                cfg_text = fh.read()
        except (OSError, UnicodeDecodeError) as exc:
            print(f"sieve-redact: error: --config を読めません: {exc}",
                  file=sys.stderr)
            raise SystemExit(1)
        try:
            all_lines = parse_config_lines(cfg_text, args.config)
            config_matchers = [(k, s) for k, s in all_lines if k != "region"]
            config_regions = [s for k, s in all_lines if k == "region"]
        except UsageError as exc:
            print(f"sieve-redact: error: {exc}", file=sys.stderr)
            raise SystemExit(2)

    # config regions: 画像モードへの経路 (config 常に CLI より先)。
    if config_regions:
        if args.region:
            args.region = config_regions + list(args.region)
        else:
            args.region = config_regions
    elif args.region:
        args.region = list(args.region)
    if args.region:
        if config_matchers:
            print("sieve-redact: error: config rule/builtin lines cannot "
                  "be combined with image mode (--region)", file=sys.stderr)
            return 2
        sys.exit(main_image(args))

    # ルール構築: config → CLI 左から右。
    # --from-lens はそのフラグ位置で初出順・重複排除の chars ルールに展開
    # (twin あり → replace / なし → delete)。
    try:
        rules = []
        index = 1
        for kind, spec in config_matchers:
            if kind == "builtin":
                rules.append(parse_builtin(spec, index))
            else:
                rules.append(parse_rule(spec, index))
            index += 1
        for kind, spec in (args.matchers or []):
            if kind == "fromlens":
                try:
                    entries = load_lens_codepoints(spec)
                except OSError as exc:
                    print(f"sieve-redact: error: --from-lens を読めません: {exc}",
                          file=sys.stderr)
                    raise SystemExit(1)
                for canon, twin in entries:  # 初出順・重複排除
                    if twin is None:
                        rules.append(
                            parse_builtin(f"chars:{canon}:delete", index))
                    else:
                        twin_ch = chr(int(twin[2:], 16))
                        rules.append(
                            parse_builtin(
                                f"chars:{canon}:replace:{twin_ch}", index))
                    index += 1
            else:
                if kind == "builtin":
                    rules.append(parse_builtin(spec, index))
                else:
                    rules.append(parse_rule(spec, index))
                index += 1
    except UsageError as exc:
        print(f"sieve-redact: error: {exc}", file=sys.stderr)
        raise SystemExit(2)

    if _same_target_file(args.input, args.output):
        print("sieve-redact: error: in-place は禁止です"
              " (-o には入力と別のファイルを指定)", file=sys.stderr)
        raise SystemExit(2)

    try:
        with open(args.input, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print(f"sieve-redact: error: 入力ファイルを読めません: {exc}",
              file=sys.stderr)
        raise SystemExit(1)

    try:
        text = data.decode("utf-8")  # 厳密デコード
    except UnicodeDecodeError as exc:
        print(f"sieve-redact: error: 入力を UTF-8 として解釈できません: {exc}",
              file=sys.stderr)
        raise SystemExit(1)

    out_text, redactions = apply_redactions(text, rules)
    out_bytes = out_text.encode("utf-8")
    integrity_ok = verify_byte_integrity(data, out_bytes, redactions)

    if args.strict and not integrity_ok:
        print("sieve-redact: error: 他バイト完全性の検証に失敗 —"
              " --strict により出力を拒否します", file=sys.stderr)
        raise SystemExit(3)

    try:
        _atomic_write(args.output, out_bytes)
    except OSError as exc:
        print(f"sieve-redact: error: 出力ファイルを書けません: {exc}",
              file=sys.stderr)
        raise SystemExit(1)

    appearance = measure_pattern_appearance(out_text, rules)
    machine = build_machine_receipt(len(data), out_bytes, redactions,
                                    integrity_ok, appearance)
    if args.receipt:
        try:
            _atomic_write(
                args.receipt,
                (json.dumps(machine, ensure_ascii=False, indent=2)
                 + "\n").encode("utf-8"))
        except OSError as exc:
            print(f"sieve-redact: error: レシートを書けません: {exc}",
                  file=sys.stderr)
            raise SystemExit(1)

    print(human_receipt(args.lang, len(data), out_bytes, redactions,
                        integrity_ok, appearance))


if __name__ == "__main__":
    main()

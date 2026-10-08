#!/usr/bin/env python3
"""Sieve Redact — 決定的なテキスト redaction エンジン。

6 つの様式 (delete / mosaic / label / noise / decor / replace) で、
指定したパターンの区間を置換する。

設計原則:
  - 依存は stdlib のみ / 決定的 / UTF-8 のみ / オフライン / テレメトリなし
  - 他バイト完全性: マッチ区間外のバイトは 1 バイトも変えない
    (verify_byte_integrity で出力前に必ず機械検証する)
  - レシートに機密本文を載せない (位置・長さ・モード・ハッシュのみ)

テスト:
    python3 -m unittest discover -s tests -v
"""

import argparse
import hashlib
import json
import os
import sys
from collections import namedtuple

VERSION = "0.4"

MODES = ("delete", "mosaic", "label", "noise", "decor", "replace")
DEFAULT_LABEL_PREFIX = "[REDACTED]"
DEFAULT_DECOR = "..."
NOISE_SAME_CLASS = "same-class"

# 組込文字種
BUILTIN_NAMES = ("postal-jp", "phone-jp", "email", "chars")

# noise 用の 6 文字クラス。各レンジはコードポイント昇順。
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
# seed: noise のハッシュ式シード (literal=pattern / name 型=NAME /
#       chars="chars:"+正規化CP-LIST)
# word_unit: MODE の '+' 接頭辞。境界で両端いずれかが棄却なら
#            そのマッチ全体を棄却する
Rule = namedtuple("Rule", "index kind name pattern seed mode arg word_unit")


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


# --------------------------------------------------------------- ルール解析

def _parse_mode(mode):
    """MODE ('+' 語単位接頭辞つき) を解析する。戻り値: (word_unit, base_mode)。

    '+' 接頭辞は語単位一致。'+' の後には MODE が必須 (空・未知は rc2)。
    """
    if mode.startswith("+"):
        word_unit, base = True, mode[1:]
    else:
        word_unit, base = False, mode
    if base not in MODES:
        raise UsageError(
            f"不明な MODE: {mode!r} (許容: {', '.join(MODES)}"
            " — 語単位一致は '+' 接頭辞, 例 秘密:+label)")
    return word_unit, base


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
            return None  # same-class: クラス外文字は据え置き
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
    word_unit, mode = _parse_mode(mode)
    arg = _normalize_mode_arg(mode, arg)
    return Rule(index, "literal", "", pattern, pattern, mode, arg, word_unit)


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
    MODE には '+' 接頭辞可 — 語単位一致 (例: chars:U+0042:+delete)。
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
        word_unit, mode = _parse_mode(mode)
        arg = ":".join(parts[3:]) if len(parts) > 3 else None
        arg = _normalize_mode_arg(mode, arg)
        canon = parse_chars_arg(cplist)
        return Rule(index, "builtin", name, canon, "chars:" + canon,
                    mode, arg, word_unit)
    if len(parts) < 2:
        raise UsageError(
            "--builtin は NAME:MODE[:ARG] の形式で指定してください"
            f" (MODE なし): {spec!r}")
    word_unit, mode = _parse_mode(parts[1])
    arg = ":".join(parts[2:]) if len(parts) > 2 else None
    arg = _normalize_mode_arg(mode, arg)
    return Rule(index, "builtin", name, "", name, mode, arg, word_unit)


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
        if kind not in ("rule", "builtin"):
            raise UsageError(
                f"--config {path!r} {lineno} 行目: 不明な kind: {kind!r}")
        if not spec:
            raise UsageError(
                f"--config {path!r} {lineno} 行目: spec が空です")
        matchers.append((kind, spec))
    return matchers


def load_lens_codepoints(path):
    """--from-lens の観測 JSON (version 1 形式・twin フィールド付き) を読む。

    戻り値: [(正規化CP, twin正規化CP or None)] — 初出順・重複排除
    (同一 codepoint は初出エントリの twin 属性を採用)。
    twin (省略可) は単一コードポイント表記のみ。twin ありのエントリは
    chars:<CP>:replace:<twin の文字>、なしは chars:<CP>:delete に
    なる (呼び出し側で生成)。
    kind は生成に使わない。count / positions は省略可 (整数検証)。
    version ≠ 1・JSON 壊れ・観測書式不正は UsageError (rc2)。
    読み込み失敗 (OSError) は呼び出し側で rc1 にする。
    """
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UsageError(f"--from-lens を UTF-8 として解釈できません: {exc}")
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise UsageError(f"--from-lens の JSON を解釈できません: {exc}")
    if not isinstance(doc, dict):
        raise UsageError(
            f"--from-lens: JSON はオブジェクトである必要があります: {path!r}")
    version = doc.get("version")
    if isinstance(version, bool) or version != 1:
        raise UsageError(
            f"--from-lens: 対応する version は 1 のみ: {version!r}")
    obs = doc.get("observations")
    if not isinstance(obs, list):
        raise UsageError(
            f"--from-lens: observations は配列である必要があります: {path!r}")
    order = []  # [(canon, twin_canon or None)] — 初出順
    seen = {}   # canon -> twin (初出の属性を採用)
    for i, item in enumerate(obs, 1):
        if not isinstance(item, dict):
            raise UsageError(
                f"--from-lens: observation #{i} はオブジェクトである必要があります")
        cp = item.get("codepoint")
        if not isinstance(cp, str):
            raise UsageError(
                f"--from-lens: observation #{i} に codepoint (文字列) が必要です")
        try:
            canon = parse_chars_arg(cp)
        except UsageError as exc:
            raise UsageError(f"--from-lens: observation #{i}: {exc}")
        if "," in canon:
            raise UsageError(
                f"--from-lens: observation #{i} の codepoint は 1 個のみ: {cp!r}")
        twin_raw = item.get("twin")
        if twin_raw is None:
            twin = None
        else:
            if not isinstance(twin_raw, str):
                raise UsageError(
                    f"--from-lens: observation #{i} の twin は"
                    " 文字列である必要があります")
            try:
                twin = parse_chars_arg(twin_raw)
            except UsageError as exc:
                raise UsageError(
                    f"--from-lens: observation #{i} の twin: {exc}")
            if "," in twin:
                raise UsageError(
                    f"--from-lens: observation #{i} の twin は"
                    f" 単一コードポイントである必要があります: {twin_raw!r}")
        if "count" in item:
            c = item["count"]
            if not isinstance(c, int) or isinstance(c, bool):
                raise UsageError(
                    f"--from-lens: observation #{i} の count は"
                    " 整数である必要があります")
        if "positions" in item:
            pos = item["positions"]
            if (not isinstance(pos, list)
                    or any(not isinstance(p, int) or isinstance(p, bool)
                           for p in pos)):
                raise UsageError(
                    f"--from-lens: observation #{i} の positions は"
                    " 整数の配列である必要があります")
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
#   "424" : 接頭辞が 0[1-6]XX かつ "433" 接頭辞集合に非所属
_PHONE_SHAPES = (
    (3, 4, 4, None),
    (4, 3, 3, "433"),
    (3, 3, 4, None),
    (4, 2, 4, "424"),
    (2, 4, 4, None),
)

_PHONE_433_PREFIXES = ("0120", "0570", "0800")


def _phone_prefix_ok(constraint, area):
    """形状ごとの接頭辞制約。area は検証済みの数字列 (先頭 '0')。"""
    if constraint is None:
        return True
    if constraint == "433":
        return area in _PHONE_433_PREFIXES
    # "424": 0[1-7]XX かつ 433 接頭辞に非所属
    return area[1] in "1234567" and area not in _PHONE_433_PREFIXES


def match_phone_jp(text):
    """0 開始の電話番号。両側 ASCII digit 境界。

    試行順: (3,4,4) → (4,3,3) → (3,3,4) → (4,2,4) → (2,4,4)
    (総長降順・同長は固定順)。
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


def match_chars(text, canon):
    """正規化 CP-LIST の各コードポイントの全出現 (単独・位置昇順)。"""
    matches = []
    for token in canon.split(","):
        ch = chr(int(token[2:], 16))
        start = text.find(ch)
        while start >= 0:
            matches.append((start, 1))
            start = text.find(ch, start + 1)
    matches.sort()
    return matches


def enumerate_matches(text, rule):
    """1 matcher の全一致を左端優先・非重複で列挙する。"""
    if rule.kind == "literal":
        return find_matches(text, rule.pattern)
    if rule.name == "postal-jp":
        return match_postal_jp(text)
    if rule.name == "phone-jp":
        return match_phone_jp(text)
    if rule.name == "email":
        return match_email(text)
    return match_chars(text, rule.pattern)  # chars


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
    """マッチ重複の解決と全様式の適用 (全 matcher ソースを通算)。

    戻り値: (出力テキスト, redactions)
      - redactions の start/end/length は入力バイトオフセット
      - label の連番は適用順 (= 位置昇順) で全ルール通し
      - 語単位のマッチは列挙時に境界棄却される
    """
    # ルールは宣言順に試行し、既確定区間と重なる後発マッチは捨てる
    confirmed = []  # (開始文字位置, 長さ, Rule)
    for rule in rules:
        for start, length in enumerate_matches(text, rule):
            if rule.word_unit and not word_unit_ok(text, start, length):
                continue
            end = start + length
            if any(start < s + l and s < end for s, l, _ in confirmed):
                continue
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
            entry["word_unit"] = True  # 語単位の redaction のみ出現 (additive)
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
    可変長なので「パターン文字列」が定義されない)。
    """
    return "found" if any(rule.kind == "literal" and rule.pattern in out_text
                          for rule in rules) else "none"


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
        lines.append(
            f"  #{n} rule={r['rule_index']} matcher={r['matcher']}"
            f" mode={r['mode']}"
            f" pos={r['start']}..{r['end']} len={r['length']}B"
            f" -> {r['replacement_length']}B"
            f" sha256={r['content_sha256'][:12]}...")
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
                             " (語単位一致は '+' 接頭辞, 例 秘密:+label。"
                             "PATTERN に ':' は使用不可)")
    parser.add_argument("--builtin", action=_MatcherAction, dest="matchers",
                        metavar="NAME:MODE[:ARG]",
                        help="組込文字種。NAME: postal-jp|phone-jp|email|chars"
                             " (chars は chars:CP-LIST:MODE[:ARG])。"
                             "複数回指定可・--rule と通しで宣言順に試行")
    parser.add_argument("--from-lens", action=_MatcherAction, dest="matchers",
                        metavar="FILE",
                        help="Sieve Lens 観測 JSON (version 1 形式・twin フィールド付き) から"
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
    return parser


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # ASCII ロケール環境の安全装置
    args = build_argparser().parse_args(argv)

    # --config: 読み込み失敗は rc1・書式不正は rc2。
    # 適用順は config が常に先頭 (CLI 上のフラグ位置に依存しない)。
    config_matchers = []
    if args.config:
        try:
            with open(args.config, "r", encoding="utf-8") as fh:
                cfg_text = fh.read()
        except (OSError, UnicodeDecodeError) as exc:
            print(f"sieve-redact: error: --config を読めません: {exc}",
                  file=sys.stderr)
            raise SystemExit(1)
        try:
            config_matchers = parse_config_lines(cfg_text, args.config)
        except UsageError as exc:
            print(f"sieve-redact: error: {exc}", file=sys.stderr)
            raise SystemExit(2)

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

    if os.path.realpath(args.input) == os.path.realpath(args.output):
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
        with open(args.output, "wb") as fh:
            fh.write(out_bytes)
    except OSError as exc:
        print(f"sieve-redact: error: 出力ファイルを書けません: {exc}",
              file=sys.stderr)
        raise SystemExit(1)

    appearance = measure_pattern_appearance(out_text, rules)
    machine = build_machine_receipt(len(data), out_bytes, redactions,
                                    integrity_ok, appearance)
    if args.receipt:
        try:
            with open(args.receipt, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(machine, ensure_ascii=False, indent=2) + "\n")
        except OSError as exc:
            print(f"sieve-redact: error: レシートを書けません: {exc}",
                  file=sys.stderr)
            raise SystemExit(1)

    print(human_receipt(args.lang, len(data), out_bytes, redactions,
                        integrity_ok, appearance))


if __name__ == "__main__":
    main()

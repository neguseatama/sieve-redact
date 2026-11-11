"""Sieve Redact v0.9.1 — 堅牢性整備の受け入れ試験 (RD-T01..T08)。

依頼書 (2026-11-05) の A 部:
  A-1 画素数の上限 (RD-T01/T02)
  A-2 画像の整合検査の高速化 (RD-T03 — v0.9.0 出力の金型)
  A-3 入力と出力が同じファイルかの判定 (RD-T04)
  A-4 原子的な書き込み (RD-T05)
  A-5 重なりの解決の計算量 (RD-T06 — 素朴な参照実装との一致)
  A-6 README の記述の正確化 (docs コミットで対応)
  RD-T07 領収書キー / RD-T08 版。

金型の pin は v0.9.0 (main 54e67a7・コードは tag v0.9.0 と同一) の
出力を採取した実測値。A 部は既存の結果を一切変えない。
"""

import argparse
import builtins
import hashlib
import io
import json
import os
import random
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "sieve_redact.py"
sys.path.insert(0, str(ROOT))

import sieve_redact as sr  # noqa: E402

try:
    from PIL import Image
    PIL_OK = True
except ImportError:
    PIL_OK = False

# ---------------------------------------------------------------------------
# RD-T03 金型: v0.9.0 で採取した出力 pin (sha256・実測 2026-11-05)。
# 画像 12 ケース (png=出力 PNG / receipt=領収書 JSON) + テキスト 3 ケース。
# ---------------------------------------------------------------------------
V090_PINS = {
    "rgb_delete": {
        "png": "bd89dd9311e521f2fda9a0b1220bd05e94455b0e9e55306238683661191a676e",
        "receipt": "7fdd1efab082aa5cff2e50184e0bf9cda618a18537586644fafbe7920b2d197a",
    },
    "rgb_mosaic_default": {
        "png": "ba71467212cc01d32693c66afed6ad3321b597686bc9ac10639a49cc013b3b7d",
        "receipt": "458be719658c9eb874375bd62118d2ff4eb71f1680236bcd750b6a9dcb08931f",
    },
    "rgb_mosaic_arg3": {
        "png": "2ae860cf70a596f25edfd98b1bbcab4ba22f64a64c7c0a1e5c44b9fe3f6673c5",
        "receipt": "2fc2e5aad648d5a958f6b5d18dc7948c675efc5ccf7b6e169d8acbfda19fb570",
    },
    "rgba_noise": {
        "png": "335ddb454a530222ddababe67bf2eb45786a487d635ec89fbcf5a3e7bffcc0ce",
        "receipt": "bf7b399664443714c8fc8efbc579ea33ce1f0b2ebce4c6d2c17f895dc16eb8b2",
    },
    "rgb_decor": {
        "png": "205d521cd7198c0573e0b85f4f18f9076f7ea18c36d2c8e60e777d9fdba76695",
        "receipt": "737d60d64a79a7ade9f91b4fa0845090b59cb1dc4eeb50923f2d263705a01b55",
    },
    "rgb_label": {
        "png": "fca6dd0383a73bd67e77d37aeac584eee8d870a0403bc847b9d3a5b8a3e1d7fc",
        "receipt": "ee83e719497a1549d894c87003a410f4df3021c7338cd79924846b7632c4bb23",
    },
    "rgb_replace": {
        "png": "982bc7c1b1b4c9fbec36ca21fc64e81282dcd0008252679a40f2f4b7a4ce8409",
        "receipt": "5a595c9f9d4c17e5e7248a7e64cdd5f86250b2f2950f3532f36aadd7136216fe",
    },
    "rgba_label": {
        "png": "cea9c1b66b6dbcab8eed655b0ca98198cadfbf2e7c88d963f404df4dcb15db2b",
        "receipt": "b80efda659b98ee78350c8ee5571e898e5e80620a73a5f189385a2a1c4d9e2ac",
    },
    "overlap_delete_mosaic": {
        "png": "b921d49051863b1ff4877814b5d85fb878f51fdc9fb7017e5be2554c747f5e1b",
        "receipt": "383902d110295f6bfd4735716cb37c457bf841b703a8c7ff419b6368bb881c51",
    },
    "multi_three_regions": {
        "png": "59176e060ce48741f19dce4ed4c681d8a57fc82a53085df04c07cf4a5a6d0dc3",
        "receipt": "687218557e640c76c987412222816ac67ce496d6299f9c1278d428468c407897",
    },
    "jpeg_delete": {
        "png": "d9868541218059ec1a69f838b8a5d7df1e5cdc101ffcfe5f5989bc56a15e6431",
        "receipt": "e1dce4d57fe2f836d497fd246689fc4c07c2a897f21ff963f41f5ee51446b5b1",
    },
    "jpeg_mosaic": {
        "png": "c9f7488dc395b36b1c6c76aff5e243de4b4907aaf680481193dc34e3e9f28f8a",
        "receipt": "c1af1aeb77aed8920a80ebded710c8e612500491a7f1632a487011ecfec920c0",
    },
    "text_phone_mosaic": {
        "txt": "b9e3c26e0f2b3b283ddc16ae7398b55b1606f24f038d55a02d0b5c1bed90d7c5",
        "receipt": "b3361bbba0c1359dfd6debde4e1f8dd7d5e793e29fa8ba5f6fcc5808f9efcb51",
    },
    "text_multirule": {
        "txt": "e0a769f4c63b27e55a9eb96eaff156fb0a66f2e669a8f3b1c7b641c94deb39c5",
        "receipt": "29f7128cae7870916344561138c6ef3d7687501cfca8829c4dd59de9ca0daa20",
    },
    "text_noise_katakana": {
        "txt": "93b48c662b01c530fc1e9f70e4cdb14ffadbd92ea081f56953445ac8728096a0",
        "receipt": "3b67c638cfc1870e0e50cecb9462229a95a0a360d6b75cf351bd737087493fd5",
    },
}

# RD-T07: v0.9.0 で実測した領収書のキー一覧 (追加・改名・削除禁止)。
TEXT_RECEIPT_KEYS = {
    "byte_integrity_verified", "input_bytes", "output_bytes",
    "pattern_appearance_in_output", "redactions", "total_redactions",
}
TEXT_REDACTION_KEYS = {
    "content_sha256", "end", "length", "matcher", "mode",
    "replacement_length", "rule_index", "start",
}
IMAGE_RECEIPT_KEYS = {
    "byte_integrity_verified", "input_bytes", "input_format", "input_mode",
    "output_bytes", "pattern_appearance_in_output",
    "pixel_integrity_verified", "rects", "redactions", "total_redactions",
}
IMAGE_RECT_KEYS = {
    "arg_sha256", "h", "mode", "pixel_sha256", "w", "x", "y",
}
# v0.9.0 から条件付きで現れる追加分 (新規追加は不可)。
ADDITIVE_REDACTION_KEYS = {"word_unit", "normalized", "case_insensitive"}


class HardeningBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.dir = Path(tmp.name)
        self.addCleanup(tmp.cleanup)

    def run_cli(self, args, cwd=None):
        return subprocess.run([sys.executable, str(SCRIPT)] + list(args),
                              capture_output=True, text=True, cwd=cwd)

    def gradient_rgb(self, name="grad.png", w=8, h=6):
        img = Image.new("RGB", (w, h))
        px = img.load()
        for y in range(h):
            for x in range(w):
                px[x, y] = (16 * x + 1, 16 * y + 2, 3)
        p = self.dir / name
        img.save(p, format="PNG")
        return p

    def img_args(self, src, out, regions, extra=()):
        ns = argparse.Namespace(
            input=str(src), output=str(out), region=list(regions),
            receipt=None, strict=False, matchers=[])
        return ns


# ---------------------------------------------------------------------------
# RD-T01: 画素数の上限 (A-1)
# ---------------------------------------------------------------------------

@unittest.skipUnless(PIL_OK, "Pillow not installed")
class RD_T01_PixelCap(HardeningBase):
    def test_default_cap_is_64_megapixels(self):
        self.assertEqual(sr.MAX_IMAGE_PIXELS, 64_000_000)

    def test_over_cap_refused_before_decode(self):
        # 定数を小さく差し替えて試す (依頼書 RD-T01)。
        # 重い処理に入る前の拒否 = Image.open が呼ばれないこと。
        src = self.gradient_rgb()                       # 8x6 = 48 px
        out = self.dir / "out.png"
        opened = []

        def forbidden_open(*a, **k):
            opened.append(1)
            raise AssertionError("Image.open must not be called")

        import unittest.mock as mock
        with mock.patch.object(sr, "MAX_IMAGE_PIXELS", 47), \
                mock.patch.object(sr.Image, "open", side_effect=forbidden_open):
            rc = sr.main_image(self.img_args(
                src, out, ["0,0,2,2:delete"]))
        self.assertEqual(rc, 2)
        self.assertEqual(opened, [])
        self.assertFalse(out.exists())

    def test_over_cap_message_has_pixel_counts_only(self):
        src = self.gradient_rgb()                       # 48 px
        proc = self.run_cli(
            [str(src), "-o", str(self.dir / "o.png"),
             "--region", "0,0,2,2:delete"])
        # 既定上限では通る (48 <= 64M) — 上限超過は in-process で別途検証済み。
        # ここでは in-process の上限超過メッセージを固定する。
        import unittest.mock as mock
        buf = io.StringIO()
        import contextlib
        with mock.patch.object(sr, "MAX_IMAGE_PIXELS", 47), \
                contextlib.redirect_stderr(buf):
            rc = sr.main_image(self.img_args(
                src, self.dir / "o.png", ["0,0,2,2:delete"]))
        self.assertEqual(rc, 2)
        msg = buf.getvalue().strip()
        self.assertEqual(
            msg, "sieve-redact: error: image too large: 48 pixels "
                 "(limit: 47 pixels)")

    def test_at_cap_passes(self):
        src = self.gradient_rgb()                       # 48 px = 上限ちょうど
        out = self.dir / "out.png"
        import unittest.mock as mock
        with mock.patch.object(sr, "MAX_IMAGE_PIXELS", 48):
            rc = sr.main_image(self.img_args(
                src, out, ["0,0,2,2:delete"]))
        self.assertEqual(rc, 0, "ちょうど上限の画像は通る")
        self.assertTrue(out.exists())

    def test_jpeg_over_cap_refused(self):
        img = Image.new("RGB", (8, 6), (5, 6, 7))
        src = self.dir / "in.jpg"
        img.save(src, format="JPEG", quality=85)
        import unittest.mock as mock
        buf = io.StringIO()
        import contextlib
        with mock.patch.object(sr, "MAX_IMAGE_PIXELS", 47), \
                contextlib.redirect_stderr(buf):
            rc = sr.main_image(self.img_args(
                src, self.dir / "o.png", ["0,0,2,2:delete"]))
        self.assertEqual(rc, 2)
        self.assertIn("image too large", buf.getvalue())


# ---------------------------------------------------------------------------
# RD-T02: Pillow の decompression bomb 系の変換 (A-1)
# ---------------------------------------------------------------------------

@unittest.skipUnless(PIL_OK, "Pillow not installed")
class RD_T02_BombConversion(HardeningBase):
    _RUNNER = (
        "import sys\n"
        "import PIL.Image as PI\n"
        "PI.MAX_IMAGE_PIXELS = {limit}\n"
        "sys.path.insert(0, {root!r})\n"
        "import sieve_redact as sr\n"
        "sys.exit(sr.main(sys.argv[1:]))\n"
    )

    def _run_with_pillow_limit(self, limit, args):
        src = self.gradient_rgb()                       # 48 px
        runner = self._RUNNER.format(limit=limit, root=str(ROOT))
        return subprocess.run(
            [sys.executable, "-c", runner, str(src)] + list(args),
            capture_output=True, text=True)

    def test_bomb_error_is_clean_refusal(self):
        # 48 px > 2*10 → DecompressionBombError
        proc = self._run_with_pillow_limit(
            10, ["-o", str(self.dir / "o.png"), "--region", "0,0,2,2:delete"])
        self.assertEqual(proc.returncode, 2)
        self.assertIn("sieve-redact: error:", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertFalse((self.dir / "o.png").exists())

    def test_bomb_warning_is_clean_refusal(self):
        # 10*2 < ... 30 < 48 <= 60 → DecompressionBombWarning
        proc = self._run_with_pillow_limit(
            30, ["-o", str(self.dir / "o.png"), "--region", "0,0,2,2:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("sieve-redact: error:", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertFalse((self.dir / "o.png").exists())


# ---------------------------------------------------------------------------
# RD-T03: 金型 — 画像・テキストの出力が v0.9.0 とバイト一致 (A-2/A-5)
# ---------------------------------------------------------------------------

@unittest.skipUnless(PIL_OK, "Pillow not installed")
class RD_T03_GoldenMolds(HardeningBase):
    _IMAGE_CASES = {
        "rgb_delete": (lambda p, b: b.gradient_rgb(p),
                       ["1,1,4,2:delete"]),
        "rgb_mosaic_default": (lambda p, b: b.gradient_rgb(p),
                               ["1,1,4,2:mosaic"]),
        "rgb_mosaic_arg3": (lambda p, b: b.gradient_rgb(p),
                            ["1,1,6,4:mosaic:3"]),
        "rgba_noise": (
            lambda p, b: Image.new("RGBA", (8, 6),
                                   (200, 30, 40, 128)).save(p, format="PNG"),
            ["1,1,4,2:noise"]),
        "rgb_decor": (lambda p, b: b.gradient_rgb(p),
                      ["1,1,4,2:decor:FF8800"]),
        "rgb_label": (lambda p, b: b.gradient_rgb(p), ["0,0,8,6:label"]),
        "rgb_replace": (lambda p, b: b.gradient_rgb(p),
                        ["0,0,8,6:replace:REDACTED"]),
        "rgba_label": (
            lambda p, b: Image.new("RGBA", (8, 6),
                                   (200, 30, 40, 128)).save(p, format="PNG"),
            ["2,1,5,4:label"]),
        "overlap_delete_mosaic": (lambda p, b: b.gradient_rgb(p),
                                  ["0,0,4,4:delete", "2,2,4,4:mosaic"]),
        "multi_three_regions": (
            lambda p, b: b.gradient_rgb(p),
            ["0,0,3,3:delete", "4,0,3,3:decor:00AA00", "0,4,8,2:mosaic:2"]),
        "jpeg_delete": (
            lambda p, b: b._gradient_jpeg(p),
            ["2,2,8,6:delete"]),
        "jpeg_mosaic": (
            lambda p, b: b._gradient_jpeg(p),
            ["0,0,16,12:mosaic:4"]),
    }

    def _gradient_jpeg(self, path):
        img = Image.new("RGB", (16, 12))
        px = img.load()
        for y in range(12):
            for x in range(16):
                px[x, y] = (13 * x + 5, 11 * y + 7, 200)
        img.save(path, format="JPEG", quality=85)

    def test_image_outputs_match_v090_pins(self):
        for name, (mk, regions) in sorted(self._IMAGE_CASES.items()):
            with self.subTest(case=name):
                src = self.dir / (name + ".in")
                mk(src, self)
                out = self.dir / "out.png"
                rec = self.dir / "rec.json"
                cmd = [str(src), "-o", str(out), "--receipt", str(rec)]
                for r in regions:
                    cmd += ["--region", r]
                proc = self.run_cli(cmd)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(
                    hashlib.sha256(out.read_bytes()).hexdigest(),
                    V090_PINS[name]["png"], name + ": PNG bytes drifted")
                self.assertEqual(
                    hashlib.sha256(rec.read_bytes()).hexdigest(),
                    V090_PINS[name]["receipt"],
                    name + ": receipt bytes drifted")

    _TEXT_CASES = {
        "text_phone_mosaic": (
            "TEL 090-1234-5678 / ０３-４５６７-８９０１ / fax 06-6543-2109\n",
            ["--builtin", "phone-jp:mosaic"]),
        "text_multirule": (
            "secret SECRET data コーヒー 090-1234-5678 someone@example.com\n",
            ["--rule", "secret:+~label", "--builtin", "phone-jp:delete",
             "--builtin", "email:decor:@@", "--builtin",
             "chars:U+30FC:mosaic"]),
        "text_noise_katakana": (
            "コーヒーとサーバー\n",
            ["--builtin", "chars:U+30FC,U+30B5:noise"]),
    }

    def test_text_outputs_match_v090_pins(self):
        for name, (text, extra) in sorted(self._TEXT_CASES.items()):
            with self.subTest(case=name):
                src = self.dir / (name + ".txt")
                src.write_text(text, encoding="utf-8")
                out = self.dir / "out.txt"
                rec = self.dir / "rec.json"
                proc = self.run_cli([str(src), "-o", str(out),
                                     "--receipt", str(rec)] + list(extra))
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(
                    hashlib.sha256(out.read_bytes()).hexdigest(),
                    V090_PINS[name]["txt"], name + ": text bytes drifted")
                self.assertEqual(
                    hashlib.sha256(rec.read_bytes()).hexdigest(),
                    V090_PINS[name]["receipt"],
                    name + ": receipt bytes drifted")

    _TAMPER_RUNNER = (
        "import sys\n"
        "sys.path.insert(0, {root!r})\n"
        "import sieve_redact as sr\n"
        "_real = sr._fill_rect\n"
        "def evil(px, rect, color):\n"
        "    _real(px, rect, color)\n"
        "    if rect['x'] == 1:\n"
        "        px[0, 0] = (9, 9, 9) + px[0, 0][3:]\n"
        "sr._fill_rect = evil\n"
        "sys.exit(sr.main(sys.argv[1:]))\n"
    )

    def test_tamper_outside_rect_is_detected(self):
        # 整合検査の負の例: 領域外の画素を汚す改ざんを検出し続けること。
        src = self.gradient_rgb()
        runner = self._TAMPER_RUNNER.format(root=str(ROOT))
        proc = subprocess.run(
            [sys.executable, "-c", runner, str(src), "-o",
             str(self.dir / "o.png"), "--region", "1,1,4,2:delete",
             "--strict"],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 3,
                         "改ざん (領域外の汚染) が検出されていない\n"
                         + proc.stderr)
        self.assertIn("pixel integrity", proc.stderr)
        self.assertFalse((self.dir / "o.png").exists())

    def test_no_tamper_strict_still_passes(self):
        src = self.gradient_rgb()
        runner = self._TAMPER_RUNNER.format(root=str(ROOT))
        proc = subprocess.run(
            [sys.executable, "-c", runner, str(src), "-o",
             str(self.dir / "o.png"), "--region", "0,0,2,2:delete",
             "--strict"],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)


# ---------------------------------------------------------------------------
# RD-T04: 入力と出力が同じ実体かの判定 (A-3)
# ---------------------------------------------------------------------------

@unittest.skipUnless(PIL_OK, "Pillow not installed")
class RD_T04_SameTarget(HardeningBase):
    def test_image_symlink_output_refused(self):
        src = self.gradient_rgb()
        out = self.dir / "out.png"
        out.symlink_to(src)
        proc = self.run_cli([str(src), "-o", str(out),
                             "--region", "0,0,2,2:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("in-place", proc.stderr)

    def test_image_relative_vs_absolute_refused(self):
        src = self.gradient_rgb(name="in.png")
        proc = self.run_cli(
            ["in.png", "-o", str(src.resolve()),
             "--region", "0,0,2,2:delete"], cwd=str(self.dir))
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_image_hardlink_output_refused(self):
        src = self.gradient_rgb()
        out = self.dir / "hard.png"
        os.link(src, out)
        proc = self.run_cli([str(src), "-o", str(out),
                             "--region", "0,0,2,2:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_image_unresolved_path_refused(self):
        # 出力は未作成だが、解決すると入力と同一実体になる経路。
        src = self.gradient_rgb()
        (self.dir / "sub").mkdir()
        proc = self.run_cli(
            [str(src), "-o", "sub/../" + src.name,
             "--region", "0,0,2,2:delete"], cwd=str(self.dir))
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_image_distinct_output_passes(self):
        src = self.gradient_rgb()
        proc = self.run_cli([str(src), "-o", str(self.dir / "o.png"),
                             "--region", "0,0,2,2:delete"])
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_text_hardlink_output_refused(self):
        src = self.dir / "in.txt"
        src.write_text("hello secret world\n", encoding="utf-8")
        out = self.dir / "hard.txt"
        os.link(src, out)
        proc = self.run_cli([str(src), "-o", str(out),
                             "--rule", "secret:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("in-place", proc.stderr + proc.stdout)

    def test_text_symlink_output_refused(self):
        src = self.dir / "in.txt"
        src.write_text("hello secret world\n", encoding="utf-8")
        out = self.dir / "sym.txt"
        out.symlink_to(src)
        proc = self.run_cli([str(src), "-o", str(out),
                             "--rule", "secret:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr + proc.stdout)

    def test_text_distinct_output_passes(self):
        src = self.dir / "in.txt"
        src.write_text("hello secret world\n", encoding="utf-8")
        proc = self.run_cli([str(src), "-o", str(self.dir / "o.txt"),
                             "--rule", "secret:delete"])
        self.assertEqual(proc.returncode, 0, proc.stderr)


# ---------------------------------------------------------------------------
# RD-T05: 原子的な書き込み (A-4)
# ---------------------------------------------------------------------------

class _FailingWriteProxy:
    """書き込みの途中で失敗するファイルオブジェクトの代理。"""

    def __init__(self, fh):
        self._fh = fh

    def write(self, b):
        self._fh.write(b[:4])
        raise OSError("disk full (injected)")

    def writelines(self, lines):
        self.write(b"".join(lines))

    def __getattr__(self, name):
        return getattr(self._fh, name)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        try:
            self._fh.close()
        except OSError:
            pass
        return False


@unittest.skipUnless(PIL_OK, "Pillow not installed")
class RD_T05_AtomicWrite(HardeningBase):
    def _patched_open(self):
        real_open = builtins.open

        def selective_open(file, mode="r", *a, **k):
            fh = real_open(file, mode, *a, **k)
            if any(c in mode for c in "wax+"):
                return _FailingWriteProxy(fh)
            return fh
        return selective_open

    def _assert_no_leftovers(self, expected_names):
        actual = sorted(p.name for p in self.dir.iterdir())
        self.assertEqual(actual, sorted(expected_names))

    def test_text_write_failure_keeps_output(self):
        src = self.dir / "in.txt"
        src.write_text("hello secret world\n", encoding="utf-8")
        out = self.dir / "out.txt"
        sentinel = b"PRE-EXISTING OUTPUT\n"
        out.write_bytes(sentinel)
        import unittest.mock as mock
        with mock.patch("builtins.open", self._patched_open()):
            with self.assertRaises(SystemExit) as cm:
                sr.main([str(src), "-o", str(out),
                         "--rule", "secret:delete"])
        self.assertEqual(cm.exception.code, 1)
        self.assertEqual(out.read_bytes(), sentinel,
                         "既存の出力が壊れた")
        self._assert_no_leftovers(["in.txt", "out.txt"])

    def test_image_save_failure_keeps_output(self):
        src = self.gradient_rgb()
        out = self.dir / "out.png"
        sentinel = b"PRE-EXISTING OUTPUT\n"
        out.write_bytes(sentinel)
        import unittest.mock as mock
        with mock.patch("builtins.open", self._patched_open()):
            rc = sr.main_image(self.img_args(
                src, out, ["0,0,2,2:delete"]))
        self.assertEqual(rc, 1)
        self.assertEqual(out.read_bytes(), sentinel,
                         "既存の出力が壊れた")
        self._assert_no_leftovers(["grad.png", "out.png"])

    def test_text_success_preserves_existing_permissions(self):
        src = self.dir / "in.txt"
        src.write_text("hello secret world\n", encoding="utf-8")
        out = self.dir / "out.txt"
        out.write_bytes(b"old\n")
        out.chmod(0o640)
        proc = self.run_cli([str(src), "-o", str(out),
                             "--rule", "secret:delete"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o640)

    def test_text_success_fresh_output_permissions(self):
        src = self.dir / "in.txt"
        src.write_text("hello secret world\n", encoding="utf-8")
        out = self.dir / "out.txt"
        proc = self.run_cli([str(src), "-o", str(out),
                             "--rule", "secret:delete"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        cur = os.umask(0o022)
        os.umask(cur)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o666 & ~cur)

    def test_image_success_preserves_existing_permissions(self):
        src = self.gradient_rgb()
        out = self.dir / "out.png"
        out.write_bytes(b"old\n")
        out.chmod(0o640)
        proc = self.run_cli([str(src), "-o", str(out),
                             "--region", "0,0,2,2:delete"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o640)

    def test_image_success_fresh_output_permissions(self):
        src = self.gradient_rgb()
        out = self.dir / "out.png"
        proc = self.run_cli([str(src), "-o", str(out),
                             "--region", "0,0,2,2:delete"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        cur = os.umask(0o022)
        os.umask(cur)
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o666 & ~cur)


# ---------------------------------------------------------------------------
# RD-T06: 重なりの解決 — 素朴な参照実装との一致と計算量 (A-5)
# ---------------------------------------------------------------------------

def _naive_apply_redactions(text, rules):
    """v0.9.0 の重なり解決 (全 confirmed に対する線形走査) の参照実装。

    実装 (bisect 化) と同じ結果を返すことを保証するためだけに存在する。
    適用部は sr の構成部品を再利用する (mode の意味は不変のため)。
    照合ビューも実装と同じものを使う (v0.10.0 から phone-jp / postal-jp は
    normalize_text_digits の第 2 ビューで照合するため、参照実装もそれを
    渡す — 参照実装が固定するのは重なり解決であって照合ではない)。
    """
    norm_text = sr.normalize_text(text)
    digit_text = None
    confirmed = []
    for rule in rules:
        if (rule.kind == "builtin" and rule.name in ("postal-jp", "phone-jp")
                and digit_text is None):
            digit_text = sr.normalize_text_digits(text)
        for start, length in sr.enumerate_matches(
                text, rule, norm_text, digit_text):
            if rule.word_unit and not sr.word_unit_ok(text, start, length):
                continue
            end = start + length
            if any(start < s + l and s < end for s, l, _ in confirmed):
                continue
            confirmed.append((start, length, rule))
    confirmed.sort(key=lambda c: (c[0], c[1]))

    offs = sr.char_byte_offsets(text)
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
            repl = "█" * length
        elif rule.mode == "label":
            label_counter += 1
            repl = "%s%d" % (rule.arg, label_counter)
        elif rule.mode == "decor":
            repl = "%s%s%s" % (rule.arg, seg, rule.arg)
        elif rule.mode == "replace":
            repl = rule.arg
        else:
            pieces = []
            for k, ch in enumerate(seg):
                pool_name = rule.arg if rule.arg is not None else sr.classify(ch)
                if (pool_name is None and rule.kind == "builtin"
                        and rule.name in sr._NORMALIZED_BUILTINS):
                    pool_name = sr.classify(norm_text[start + k])
                if pool_name is None:
                    pieces.append(ch)
                else:
                    pool = sr.CLASS_CHARS[pool_name]
                    pieces.append(
                        sr.noise_char(rule.seed, offs[start + k], ch, pool))
            repl = "".join(pieces)
        out_parts.append(repl)
        entry = {
            "rule_index": rule.index,
            "matcher": ("literal" if rule.kind == "literal"
                        else "builtin:%s" % rule.name),
            "mode": rule.mode,
            "start": offs[start],
            "end": offs[start + length],
            "length": offs[start + length] - offs[start],
            "content_sha256": hashlib.sha256(seg_bytes).hexdigest(),
            "replacement_length": len(repl.encode("utf-8")),
        }
        if rule.word_unit:
            entry["word_unit"] = True
        if (rule.kind == "builtin" and rule.name in sr._NORMALIZED_BUILTINS
                and seg != _naive_match_view(
                    rule, norm_text, digit_text)[start:start + length]):
            entry["normalized"] = True
        if rule.ci:
            entry["case_insensitive"] = True
        redactions.append(entry)
        pos = start + length
    out_parts.append(text[pos:])
    return "".join(out_parts), redactions


def _naive_match_view(rule, norm_text, digit_text):
    if (rule.kind == "builtin" and rule.name in ("postal-jp", "phone-jp")
            and digit_text is not None):
        return digit_text
    return norm_text


class RD_T06_OverlapResolution(HardeningBase):
    _ALPHABET = ("0123456789-ーｰ_ABCabcXYZ@. \n"
                 "あいうえおカキクケコサシスセソ０１２３４５−–—―")

    def _random_case(self, rng):
        text = "".join(rng.choice(self._ALPHABET)
                       for _ in range(rng.randint(60, 400)))
        rules = []
        index = 1
        for _ in range(rng.randint(1, 5)):
            kind = rng.choice(
                ["literal", "phone", "postal", "email", "chars"])
            mode = rng.choice(
                ["delete", "mosaic", "label", "noise", "decor", "replace"])
            prefixes = rng.choice(["", "+", "~", "+~"])
            arg = ""
            if mode == "replace":
                arg = ":RE"
            elif mode == "decor" and rng.random() < 0.5:
                arg = ":FF00AA"
            elif mode == "mosaic" and rng.random() < 0.5:
                arg = ":2"
            elif mode == "noise" and rng.random() < 0.4:
                arg = ":" + rng.choice(sorted(sr.CLASS_RANGES))
            if kind == "literal":
                pat = "".join(rng.choice(self._ALPHABET[:44])
                              for _ in range(rng.randint(1, 4))) or "x"
                spec = "%s:%s%s%s" % (pat, prefixes, mode, arg)
                rules.append(sr.parse_rule(spec, index))
            elif kind == "chars":
                cp = rng.choice(["U+30FC", "U+FF70", "U+0041", "U+3042",
                                 "U+2010", "U+FF10"])
                spec = "chars:%s:%s%s%s" % (cp, prefixes, mode, arg)
                rules.append(sr.parse_builtin(spec, index))
            else:
                name = {"phone": "phone-jp", "postal": "postal-jp",
                        "email": "email"}[kind]
                spec = "%s:%s%s%s" % (name, prefixes, mode, arg)
                rules.append(sr.parse_builtin(spec, index))
            index += 1
        return text, rules

    def test_matches_naive_reference_on_random_inputs(self):
        rng = random.Random(20261105)
        for i in range(400):
            text, rules = self._random_case(rng)
            with self.subTest(case=i):
                got_out, got_red = sr.apply_redactions(text, rules)
                want_out, want_red = _naive_apply_redactions(text, rules)
                self.assertEqual(got_out, want_out)
                self.assertEqual(got_red, want_red)

    def test_complexity_subquadratic(self):
        rule = sr.parse_builtin("phone-jp:delete", 1)

        def timed(count):
            text = "090-1234-5678\n" * count
            t0 = time.perf_counter()
            out, red = sr.apply_redactions(text, [rule])
            dt = time.perf_counter() - t0
            self.assertEqual(len(red), count)
            return dt
        t10 = timed(10000)
        t20 = timed(20000)
        # 件数 2 倍で時間 3 倍未満 (緩い境界・依頼書 RD-T06)。
        self.assertLess(t20, 3.0 * t10,
                        "quadratic: t10=%.2fs t20=%.2fs (x%.2f)"
                        % (t10, t20, t20 / t10))


# ---------------------------------------------------------------------------
# RD-T07: 領収書のキー一覧が v0.9.0 と一致 (A・B)
# ---------------------------------------------------------------------------

@unittest.skipUnless(PIL_OK, "Pillow not installed")
class RD_T07_ReceiptKeys(HardeningBase):
    def test_text_receipt_keys_unchanged(self):
        src = self.dir / "in.txt"
        src.write_text(
            "TEL 090-1234-5678 / ＦＵＬＬ secret someone@example.com\n",
            encoding="utf-8")
        rec = self.dir / "r.json"
        proc = self.run_cli(
            [str(src), "-o", str(self.dir / "o.txt"), "--receipt", str(rec),
             "--rule", "secret:+~label", "--builtin", "phone-jp:delete",
             "--builtin", "email:delete"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(rec.read_text(encoding="utf-8"))
        self.assertEqual(set(data), TEXT_RECEIPT_KEYS)
        for r in data["redactions"]:
            extra = set(r) - TEXT_REDACTION_KEYS
            self.assertTrue(extra <= ADDITIVE_REDACTION_KEYS,
                            "unexpected new receipt keys: %s" % sorted(extra))
            self.assertEqual(
                set(r) - ADDITIVE_REDACTION_KEYS, TEXT_REDACTION_KEYS)

    def test_image_receipt_keys_unchanged(self):
        src = self.gradient_rgb()
        rec = self.dir / "r.json"
        proc = self.run_cli(
            [str(src), "-o", str(self.dir / "o.png"), "--receipt", str(rec),
             "--region", "1,1,3,2:delete", "--region", "4,1,3,3:mosaic:2"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(rec.read_text(encoding="utf-8"))
        self.assertEqual(set(data), IMAGE_RECEIPT_KEYS)
        self.assertEqual(len(data["rects"]), 2)
        for rect in data["rects"]:
            self.assertEqual(set(rect), IMAGE_RECT_KEYS)


# ---------------------------------------------------------------------------
# RD-T08: 版の一致 (A: 0.9.1 → B: 0.10.0 に更新 — 版 pin のみ変更新)
# ---------------------------------------------------------------------------

class RD_T08_Version(unittest.TestCase):
    def test_version_is_current(self):
        self.assertEqual(sr.VERSION, "0.11.0")

    def test_pyproject_version_is_dynamic_attr(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('dynamic = ["version"]', text)
        self.assertIn('version = { attr = "sieve_redact.VERSION" }', text)

    def test_changelog_has_current_version(self):
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("## [0.10.0]", text)

    def test_readme_titles_track_version(self):
        for name in ("README.md", "README.ja.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn("Sieve Redact v0.10.0", text, name)


if __name__ == "__main__":
    unittest.main()

"""Sieve Redact v0.5 — image mode (PNG) acceptance tests.

Spec summary (pinned by these tests):
  - --region x,y,w,h:MODE[:ARG] (1 region = 1 rect = 1 MODE; declaration
    order; overlaps discarded per the text-mode rules; zero-area and
    out-of-bounds regions are rc=2; --rule with image input and --region
    with text input are rc=2)
  - PNG only: 8bit RGB/RGBA, non-interlaced, non-animated; JPEG and all
    other formats rejected; metadata dropped on save
  - MODE semantics: delete = opaque white fill; mosaic = block average
    over all channels (blocks align to the region origin and clip to it;
    ARG = block size, default 8); noise = per-pixel
    SHA-256("img:{x}:{y}:{R},{G},{B}").digest()[:3] on RGB, alpha kept;
    label/replace = drawn with the bundled bitmap font, alpha overwritten
  - Integrity: pixels outside every region must equal the input
    (pixel_integrity_verified); byte_integrity_verified is null for
    image mode (PNG re-encode changes bytes structurally); --strict
    exits 3 when pixel integrity fails
  - Receipt: redactions stays [], rects carries x/y/w/h/mode plus
    arg_sha256 (ARG never in clear text) and pixel_sha256 (row-major,
    saved channel order, region bytes before masking)
"""
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "sieve_redact.py"

NOT_IMPL = "image mode (--region) is not implemented"

ADAM7 = ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8),
         (2, 0, 4, 4), (0, 2, 2, 2), (1, 0, 2, 1), (0, 1, 1, 1))


def _png_chunk(typ, data):
    return (struct.pack(">I", len(data)) + typ + data
            + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF))


def write_interlaced_rgb_png(path, w=8, h=6, rgb=(200, 30, 40)):
    """Minimal Adam7-interlaced RGB PNG (Pillow cannot write interlaced)."""
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 1)
    raw = bytearray()
    for x0, y0, dx, dy in ADAM7:
        if len(range(x0, w, dx)) == 0 or len(range(y0, h, dy)) == 0:
            continue
        for y in range(y0, h, dy):
            raw.append(0)
            for x in range(x0, w, dx):
                raw.extend(rgb)
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", zlib.compress(bytes(raw)))
        + _png_chunk(b"IEND", b""))


def _region_supported():
    proc = subprocess.run([sys.executable, str(SCRIPT), "--help"],
                          capture_output=True, text=True)
    return "--region" in proc.stdout


REGION_SUPPORTED = _region_supported()


class ImageBase(unittest.TestCase):
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

    def gate(self):
        self.assertTrue(REGION_SUPPORTED, NOT_IMPL)

    def gradient_rgb(self, name="grad.png", w=8, h=6):
        img = Image.new("RGB", (w, h))
        px = img.load()
        for y in range(h):
            for x in range(w):
                px[x, y] = (16 * x + 1, 16 * y + 2, 3)
        p = self.dir / name
        img.save(p, format="PNG")
        return p, img

    def flat_rgba(self, name="flat.png", w=8, h=6):
        img = Image.new("RGBA", (w, h), (200, 30, 40, 128))
        p = self.dir / name
        img.save(p, format="PNG")
        return p, img

    def load(self, path):
        img = Image.open(path)
        img.load()
        return img


class RegionUsage(ImageBase):
    def test_region_usage_errors(self):
        self.gate()
        src, _ = self.gradient_rgb()
        out = self.dir / "out.png"
        bad_regions = (
            "1,1,4:delete",      # 3 numbers
            "a,b,c,d:delete",    # non-numeric
            "1,1,4,2:blast",     # unknown MODE
            "2,2,0,3:delete",    # zero width
            "2,2,3,0:delete",    # zero height
            "6,5,4,4:delete",    # out of bounds (x+w=10>8, y+h=9>6)
        )
        for bad in bad_regions:
            proc = self.run_cli([str(src), "-o", str(out), "--region", bad])
            self.assertEqual(proc.returncode, 2,
                             "region %r: rc=%d stderr=%s"
                             % (bad, proc.returncode, proc.stderr))

    def test_rule_with_image_rejected(self):
        self.gate()
        src, _ = self.gradient_rgb()
        proc = self.run_cli([str(src), "-o", str(self.dir / "o.png"),
                             "--rule", "secret:delete",
                             "--region", "0,0,2,2:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_region_with_text_rejected(self):
        self.gate()
        txt = self.dir / "in.txt"
        txt.write_text("hello secret world\n", encoding="utf-8")
        proc = self.run_cli([str(txt), "-o", str(self.dir / "o.txt"),
                             "--region", "0,0,2,2:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_image_without_pillow_rejected(self):
        self.gate()
        stub = self.dir / "stubpil"
        stub.mkdir()
        (stub / "PIL.py").write_text("raise ImportError('stub')\n",
                                     encoding="utf-8")
        src, _ = self.gradient_rgb()
        env = dict(os.environ, PYTHONPATH=str(stub))
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), str(src), "-o",
             str(self.dir / "o.png"), "--region", "0,0,2,2:delete"],
            capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("Pillow", proc.stdout + proc.stderr)

    def test_strict_passes_when_integrity_holds(self):
        self.gate()
        src, _ = self.gradient_rgb()
        proc = self.run_cli([str(src), "-o", str(self.dir / "o.png"),
                             "--region", "1,1,4,2:delete", "--strict"])
        self.assertEqual(proc.returncode, 0, proc.stderr)


class FormatLimits(ImageBase):
    def test_jpeg_rejected(self):
        self.gate()
        p = self.dir / "in.png"  # JPEG bytes under a .png name:
        # rejection must be content-based, not extension-based
        Image.new("RGB", (4, 4), (9, 9, 9)).save(p, format="JPEG")
        proc = self.run_cli([str(p), "-o", str(self.dir / "o.png"),
                             "--region", "0,0,2,2:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_palette_png_rejected(self):
        self.gate()
        p = self.dir / "pal.png"
        Image.new("P", (4, 4)).save(p, format="PNG")
        proc = self.run_cli([str(p), "-o", str(self.dir / "o.png"),
                             "--region", "0,0,2,2:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_grayscale_png_rejected(self):
        self.gate()
        p = self.dir / "gray.png"
        Image.new("L", (4, 4)).save(p, format="PNG")
        proc = self.run_cli([str(p), "-o", str(self.dir / "o.png"),
                             "--region", "0,0,2,2:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_apng_rejected(self):
        self.gate()
        p = self.dir / "anim.png"
        a = Image.new("RGB", (4, 4), (10, 20, 30))
        b = Image.new("RGB", (4, 4), (40, 50, 60))
        a.save(p, format="PNG", save_all=True, append_images=[b])
        probe = Image.open(p)
        self.assertTrue(getattr(probe, "is_animated", False),
                        "fixture is not animated (Pillow save_all changed?)")
        probe.close()
        proc = self.run_cli([str(p), "-o", str(self.dir / "o.png"),
                             "--region", "0,0,2,2:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_interlaced_png_rejected(self):
        # Pillow cannot write interlaced PNGs, so the fixture is a valid
        # Pillow PNG with the IHDR interlace flag flipped to 1. The engine
        # rejects on the flag itself (data need not decode as interlaced).
        self.gate()
        p = self.dir / "inter.png"
        Image.new("RGB", (8, 6), (11, 22, 33)).save(p, format="PNG")
        raw = bytearray(p.read_bytes())
        self.assertEqual(raw[12:16], b"IHDR")
        self.assertEqual(raw[28], 0)
        raw[28] = 1
        p.write_bytes(bytes(raw))
        proc = self.run_cli([str(p), "-o", str(self.dir / "o.png"),
                             "--region", "0,0,2,2:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr)


class ModeSemantics(ImageBase):
    def test_delete_rgb(self):
        self.gate()
        src, img = self.gradient_rgb()
        out = self.dir / "out.png"
        self.ok_run([str(src), "-o", str(out), "--region", "1,1,4,2:delete"])
        res = self.load(out)
        px, orig = res.load(), img.load()
        for y in range(6):
            for x in range(8):
                if 1 <= x < 5 and 1 <= y < 3:
                    self.assertEqual(px[x, y], (255, 255, 255),
                                     "inside (%d,%d)" % (x, y))
                else:
                    self.assertEqual(px[x, y], orig[x, y],
                                     "outside (%d,%d)" % (x, y))

    def test_delete_rgba_opaque_white(self):
        self.gate()
        src, img = self.flat_rgba()
        out = self.dir / "out.png"
        self.ok_run([str(src), "-o", str(out), "--region", "1,1,4,2:delete"])
        res = self.load(out)
        px, orig = res.load(), img.load()
        for y in range(6):
            for x in range(8):
                if 1 <= x < 5 and 1 <= y < 3:
                    self.assertEqual(px[x, y], (255, 255, 255, 255))
                else:
                    self.assertEqual(px[x, y], orig[x, y])

    def test_mosaic_full_default_block(self):
        self.gate()
        src, _ = self.gradient_rgb()
        out = self.dir / "out.png"
        self.ok_run([str(src), "-o", str(out), "--region", "0,0,8,6:mosaic"])
        res = self.load(out)
        px = res.load()
        for y in range(6):
            for x in range(8):
                self.assertEqual(px[x, y], (57, 42, 3), "pixel (%d,%d)" % (x, y))

    def test_mosaic_region_smaller_than_block(self):
        # Blocks align to the region origin and clip to the region:
        # (2,1,4,4) is a single block averaging only its own 16 pixels.
        self.gate()
        src, img = self.gradient_rgb()
        out = self.dir / "out.png"
        self.ok_run([str(src), "-o", str(out), "--region", "2,1,4,4:mosaic"])
        res = self.load(out)
        px, orig = res.load(), img.load()
        for y in range(6):
            for x in range(8):
                if 2 <= x < 6 and 1 <= y < 5:
                    self.assertEqual(px[x, y], (57, 42, 3))
                else:
                    self.assertEqual(px[x, y], orig[x, y])

    def test_mosaic_arg_two_blocks(self):
        # 16x8 gradient, region (4,2,8,4), block 4: region-relative blocks
        # are (4,2,4,4) and (8,2,4,4) — 16 pixels each, averaging
        # (89,58,3) and (153,58,3). Image-aligned blocks would clip to
        # 4 partial blocks with G=42/74 — this pins region-relative
        # alignment.
        self.gate()
        src, img = self.gradient_rgb(name="wide.png", w=16, h=8)
        out = self.dir / "out.png"
        self.ok_run([str(src), "-o", str(out), "--region", "4,2,8,4:mosaic:4"])
        res = self.load(out)
        px, orig = res.load(), img.load()
        for y in range(8):
            for x in range(16):
                if 4 <= x < 12 and 2 <= y < 6:
                    expected = (89, 58, 3) if x < 8 else (153, 58, 3)
                    self.assertEqual(px[x, y], expected,
                                     "block pixel (%d,%d)" % (x, y))
                else:
                    self.assertEqual(px[x, y], orig[x, y])

    def test_decor_border(self):
        # Border width 2, color FF0000: outer 2px ring of the region is
        # opaque red; the inner pixels keep their original values.
        # (8x8 canvas so that region 1,1,6,6 fits: y+h = 7 <= 8.)
        self.gate()
        src, img = self.gradient_rgb(name="grad8.png", w=8, h=8)
        out = self.dir / "out.png"
        self.ok_run([str(src), "-o", str(out), "--region", "1,1,6,6:decor:FF0000"])
        res = self.load(out)
        px, orig = res.load(), img.load()
        for y in range(6):
            for x in range(8):
                if 1 <= x <= 6 and 1 <= y <= 6:
                    if x <= 2 or x >= 5 or y <= 2 or y >= 5:
                        self.assertEqual(px[x, y], (255, 0, 0),
                                         "border (%d,%d)" % (x, y))
                    else:
                        self.assertEqual(px[x, y], orig[x, y],
                                         "inner (%d,%d)" % (x, y))
                else:
                    self.assertEqual(px[x, y], orig[x, y])

    def test_noise_rgb_recompute(self):
        self.gate()
        src, img = self.gradient_rgb()
        out = self.dir / "out.png"
        self.ok_run([str(src), "-o", str(out), "--region", "0,0,8,6:noise"])
        res = self.load(out)
        px, orig = res.load(), img.load()
        changed = 0
        for y in range(6):
            for x in range(8):
                r, g, b = orig[x, y]
                exp = hashlib.sha256(
                    ("img:%d:%d:%d,%d,%d" % (x, y, r, g, b)).encode("utf-8")
                ).digest()[:3]
                self.assertEqual(px[x, y], (exp[0], exp[1], exp[2]),
                                 "pixel (%d,%d)" % (x, y))
                if (exp[0], exp[1], exp[2]) != (r, g, b):
                    changed += 1
        self.assertGreater(changed, 0)

    def test_noise_rgba_keeps_alpha(self):
        # Semi-transparent pixels keep their alpha: the replaced RGB shows
        # through at the original transparency (content changes, visibility
        # does not) — this sentence goes into the README MODE description.
        self.gate()
        src, _ = self.flat_rgba()
        out = self.dir / "out.png"
        self.ok_run([str(src), "-o", str(out), "--region", "0,0,8,6:noise"])
        res = self.load(out)
        px = res.load()
        for y in range(6):
            for x in range(8):
                r, g, b, a = px[x, y]
                self.assertEqual(a, 128, "alpha (%d,%d)" % (x, y))
                exp = hashlib.sha256(
                    b"img:%d:%d:200,30,40" % (x, y)).digest()[:3]
                self.assertEqual((r, g, b), (exp[0], exp[1], exp[2]))


class ReceiptAndIntegrity(ImageBase):
    def test_receipt_structure(self):
        self.gate()
        src, img = self.gradient_rgb()
        out = self.dir / "out.png"
        rec = self.dir / "rec.json"
        self.ok_run([str(src), "-o", str(out), "--region", "1,1,4,2:delete",
                     "--receipt", str(rec)])
        data = json.loads(rec.read_text(encoding="utf-8"))
        self.assertEqual(data["redactions"], [])
        self.assertEqual(data["total_redactions"], 0)
        self.assertIsNone(data["byte_integrity_verified"])
        self.assertIs(data["pixel_integrity_verified"], True)
        self.assertEqual(data["input_format"], "PNG")
        self.assertEqual(data["input_mode"], "RGB")
        self.assertEqual(len(data["rects"]), 1)
        rect = data["rects"][0]
        self.assertEqual(rect["x"], 1)
        self.assertEqual(rect["y"], 1)
        self.assertEqual(rect["w"], 4)
        self.assertEqual(rect["h"], 2)
        self.assertEqual(rect["mode"], "delete")
        self.assertIsNone(rect["arg_sha256"])
        orig = img.load()
        region_bytes = b"".join(bytes(orig[x, y])
                                for y in range(1, 3) for x in range(1, 5))
        self.assertEqual(rect["pixel_sha256"],
                         hashlib.sha256(region_bytes).hexdigest())

    def test_overlapping_regions_first_wins(self):
        self.gate()
        src, img = self.gradient_rgb()
        out = self.dir / "out.png"
        rec = self.dir / "rec.json"
        self.ok_run([str(src), "-o", str(out),
                     "--region", "0,0,4,4:delete",
                     "--region", "2,2,4,4:mosaic",
                     "--receipt", str(rec)])
        res = self.load(out)
        px, orig = res.load(), img.load()
        for y in range(6):
            for x in range(8):
                if x < 4 and y < 4:
                    self.assertEqual(px[x, y], (255, 255, 255))
                else:
                    self.assertEqual(px[x, y], orig[x, y])
        data = json.loads(rec.read_text(encoding="utf-8"))
        self.assertEqual(len(data["rects"]), 1)
        self.assertEqual(data["rects"][0]["mode"], "delete")


class RenderPins(ImageBase):
    def test_label_and_replace_match_pins(self):
        self.gate()
        pins_path = ROOT / "tests" / "render_pins.json"
        self.assertTrue(
            pins_path.exists(),
            "render pin file missing — generate pins after implementation")
        pins = json.loads(pins_path.read_text(encoding="utf-8"))
        src, _ = self.gradient_rgb()
        out = self.dir / "out.png"
        self.ok_run([str(src), "-o", str(out), "--region", "0,0,8,6:label"])
        self.assertEqual(
            hashlib.sha256(out.read_bytes()).hexdigest(),
            pins["label_default_8x6_gradient"],
            "label bytes differ from the pin — intentional change: re-pin; "
            "machine difference: exclude the mode per the environment decision")
        src2, _ = self.gradient_rgb(name="grad2.png")
        out2 = self.dir / "out2.png"
        self.ok_run([str(src2), "-o", str(out2),
                     "--region", "0,0,8,6:replace:REDACTED"])
        self.assertEqual(
            hashlib.sha256(out2.read_bytes()).hexdigest(),
            pins["replace_redacted_8x6_gradient"])


if __name__ == "__main__":
    unittest.main()

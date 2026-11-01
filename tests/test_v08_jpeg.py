"""Sieve Redact v0.8 — JPEG input (always-PNG output) acceptance tests.

Spec summary (pinned by these tests):
  - JPEG input (baseline and progressive) is accepted in image mode:
    SOI + SOF frame header are validated structurally (no pixel decode
    at the gate), Pillow decodes, and only RGB is accepted
    (grayscale/CMYK are rc=2 with a clean error, never a traceback)
  - Output is ALWAYS PNG regardless of input format — JPEG pixels are
    never re-compressed as JPEG, so masking adds no further loss; the
    output file starts with the PNG signature
  - Masking semantics equal the PNG path: delete fills opaque white,
    noise recomputes SHA-256("img:{x}:{y}:{R},{G},{B}") against the
    decoded pixels; pixels outside every region equal the decoded input
    (pixel integrity); --strict exits 0 when it holds
  - Receipt: input_format="JPEG", input_bytes = JPEG file size,
    input_mode="RGB"; rects carry pixel_sha256 of the decoded region
    bytes (recomputed here with the same Pillow decoder)
  - Human receipt header tracks VERSION (not a hard-coded one) and
    reports the input format
  - Content-based sniffing: JPEG bytes under any extension are
    accepted; GIF/garbage bytes are rejected with rc=2
  - Region bounds are checked against the SOF dimensions before decode
"""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "sieve_redact.py"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

NOT_IMPL = "image mode (--region) is not implemented"


def _region_supported():
    proc = subprocess.run([sys.executable, str(SCRIPT), "--help"],
                          capture_output=True, text=True)
    return "--region" in proc.stdout


REGION_SUPPORTED = _region_supported()


def load_engine():
    import importlib.util
    spec = importlib.util.spec_from_file_location("sieve_redact_v08",
                                                  str(SCRIPT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class JpegBase(unittest.TestCase):
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

    def gradient_jpeg(self, name="grad.jpg", w=8, h=6, **save_kw):
        img = Image.new("RGB", (w, h))
        px = img.load()
        for y in range(h):
            for x in range(w):
                px[x, y] = (16 * x + 1, 16 * y + 2, 3)
        p = self.dir / name
        img.save(p, format="JPEG", **save_kw)
        return p, img

    def decoded(self, path):
        # Baseline for pixel comparisons: the DECODE of the JPEG file
        # bytes (never the pre-encoding in-memory image — JPEG is lossy).
        img = Image.open(path)
        img.load()
        return img

    def load(self, path):
        img = Image.open(path)
        img.load()
        return img


class JpegAcceptance(JpegBase):
    def test_jpeg_output_is_png_and_pixels_match(self):
        self.gate()
        src, _ = self.gradient_jpeg()
        out = self.dir / "out.png"
        self.ok_run([str(src), "-o", str(out), "--region", "1,1,4,2:delete"])
        self.assertTrue(out.read_bytes().startswith(PNG_SIGNATURE))
        res = self.load(out)
        px, orig = res.load(), self.decoded(src).load()
        for y in range(6):
            for x in range(8):
                if 1 <= x < 5 and 1 <= y < 3:
                    self.assertEqual(px[x, y], (255, 255, 255),
                                     "inside (%d,%d)" % (x, y))
                else:
                    self.assertEqual(px[x, y], orig[x, y],
                                     "outside (%d,%d)" % (x, y))

    def test_jpeg_receipt_fields(self):
        self.gate()
        src, _ = self.gradient_jpeg()
        out = self.dir / "out.png"
        rec = self.dir / "rec.json"
        self.ok_run([str(src), "-o", str(out), "--region", "1,1,4,2:delete",
                     "--receipt", str(rec)])
        data = json.loads(rec.read_text(encoding="utf-8"))
        self.assertEqual(data["input_format"], "JPEG")
        self.assertEqual(data["input_mode"], "RGB")
        self.assertEqual(data["input_bytes"], src.stat().st_size)
        self.assertIsNone(data["byte_integrity_verified"])
        self.assertIs(data["pixel_integrity_verified"], True)
        self.assertEqual(len(data["rects"]), 1)
        dec = self.decoded(src)
        orig = dec.load()
        region_bytes = b"".join(bytes(orig[x, y])
                                for y in range(1, 3) for x in range(1, 5))
        self.assertEqual(data["rects"][0]["pixel_sha256"],
                         hashlib.sha256(region_bytes).hexdigest())

    def test_human_receipt_header_tracks_version(self):
        self.gate()
        src, _ = self.gradient_jpeg()
        proc = self.ok_run([str(src), "-o", str(self.dir / "out.png"),
                            "--region", "0,0,2,2:delete"])
        engine = load_engine()
        self.assertIn("Sieve Redact v%s — レシート" % engine.VERSION,
                      proc.stdout)
        self.assertIn("入力: JPEG", proc.stdout)
        self.assertIn("出力: PNG", proc.stdout)

    def test_progressive_jpeg_accepted(self):
        self.gate()
        src, _ = self.gradient_jpeg(name="prog.jpg", progressive=True)
        out = self.dir / "out.png"
        self.ok_run([str(src), "-o", str(out), "--region", "0,0,4,4:delete"])
        res = self.load(out)
        px, orig = res.load(), self.decoded(src).load()
        for y in range(6):
            for x in range(8):
                if x < 4 and y < 4:
                    self.assertEqual(px[x, y], (255, 255, 255))
                else:
                    self.assertEqual(px[x, y], orig[x, y])

    def test_jpeg_noise_recompute(self):
        self.gate()
        src, _ = self.gradient_jpeg()
        out = self.dir / "out.png"
        self.ok_run([str(src), "-o", str(out), "--region", "0,0,8,6:noise"])
        res = self.load(out)
        px = res.load()
        orig = self.decoded(src).load()
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

    def test_jpeg_label_band(self):
        self.gate()
        src, _ = self.gradient_jpeg()
        out = self.dir / "out.png"
        self.ok_run([str(src), "-o", str(out), "--region", "0,0,8,6:label"])
        self.assertTrue(out.read_bytes().startswith(PNG_SIGNATURE))
        px = self.load(out).load()
        self.assertEqual(px[0, 0], (0, 0, 0))

    def test_jpeg_strict_passes(self):
        self.gate()
        src, _ = self.gradient_jpeg()
        proc = self.run_cli([str(src), "-o", str(self.dir / "o.png"),
                             "--region", "1,1,4,2:delete", "--strict"])
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_jpeg_out_of_bounds_region(self):
        self.gate()
        src, _ = self.gradient_jpeg(w=8, h=6)
        proc = self.run_cli([str(src), "-o", str(self.dir / "o.png"),
                             "--region", "6,5,4,4:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("bounds", proc.stderr)

    def test_jpeg_any_extension_accepted(self):
        # Content sniffing, not extension trust: JPEG bytes under a
        # non-image extension still run; output bytes are PNG.
        self.gate()
        src, _ = self.gradient_jpeg(name="photo.dat")
        out = self.dir / "out.any"
        self.ok_run([str(src), "-o", str(out), "--region", "0,0,2,2:delete"])
        self.assertTrue(out.read_bytes().startswith(PNG_SIGNATURE))


class JpegLimits(JpegBase):
    def test_grayscale_jpeg_rejected(self):
        self.gate()
        p = self.dir / "gray.jpg"
        Image.new("L", (4, 4)).save(p, format="JPEG")
        proc = self.run_cli([str(p), "-o", str(self.dir / "o.png"),
                             "--region", "0,0,2,2:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("color mode", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_cmyk_jpeg_rejected(self):
        self.gate()
        p = self.dir / "cmyk.jpg"
        Image.new("CMYK", (4, 4), (10, 20, 30, 40)).save(p, format="JPEG")
        proc = self.run_cli([str(p), "-o", str(self.dir / "o.png"),
                             "--region", "0,0,2,2:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("color mode", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_corrupt_jpeg_clean_error(self):
        self.gate()
        p = self.dir / "bad.jpg"
        p.write_bytes(b"\xff\xd8\xff" + b"\x00" * 64)  # SOI + garbage
        proc = self.run_cli([str(p), "-o", str(self.dir / "o.png"),
                             "--region", "0,0,2,2:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_garbage_and_gif_rejected(self):
        self.gate()
        for name, payload in (("junk.bin", b"not an image at all" * 8),
                              ("pic.gif", b"GIF89a" + b"\x00" * 32)):
            p = self.dir / name
            p.write_bytes(payload)
            proc = self.run_cli([str(p), "-o", str(self.dir / "o.png"),
                                 "--region", "0,0,2,2:delete"])
            self.assertEqual(proc.returncode, 2,
                             "%s: rc=%d stderr=%s"
                             % (name, proc.returncode, proc.stderr))
            self.assertNotIn("Traceback", proc.stderr)


if __name__ == "__main__":
    unittest.main()

"""Sieve Redact v0.6 — config-driven image regions (acceptance tests).

Spec summary (pinned by these tests):
  - config gains a new line kind: `region x,y,w,h:MODE[:ARG]`
  - config regions are applied BEFORE CLI --region (declaration order)
  - image input + config region lines: works exactly like --region
  - text input + config region lines: rc=2 (image-mode exclusivity)
  - config region + CLI --rule/--builtin: rc=2 (image-mode exclusivity)
  - malformed region lines: rc=2
"""
import tempfile
import unittest
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "sieve_redact.py"

NOT_IMPL = "config-driven image regions (--config region lines) are not implemented"


class ConfigImageBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.dir = Path(tmp.name)
        self.addCleanup(tmp.cleanup)

    def run_cli(self, args):
        import subprocess
        import sys
        return subprocess.run([sys.executable, str(SCRIPT)] + list(args),
                              capture_output=True, text=True)

    def gate(self):
        proc = self.run_cli(["--help"])
        return "region" in proc.stdout

    def gradient_rgb(self, name="grad.png", w=8, h=6):
        img = Image.new("RGB", (w, h))
        px = img.load()
        for y in range(h):
            for x in range(w):
                px[x, y] = (16 * x + 1, 16 * y + 2, 3)
        p = self.dir / name
        img.save(p, format="PNG")
        return p, img

    def load(self, path):
        img = Image.open(path)
        img.load()
        return img

    def write_config(self, lines):
        cfg = self.dir / "rules.cfg"
        cfg.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return cfg


class ConfigImageRegions(ConfigImageBase):
    def test_config_region_applied(self):
        src, img = self.gradient_rgb()
        out = self.dir / "out.png"
        cfg = self.write_config(["# comment", "", "region 1,1,4,2:delete"])
        proc = self.run_cli([str(src), "-o", str(out), "--config", str(cfg)])
        self.assertEqual(proc.returncode, 0, NOT_IMPL + " stderr=" + proc.stderr)
        res = self.load(out)
        px, orig = res.load(), img.load()
        for y in range(6):
            for x in range(8):
                if 1 <= x < 5 and 1 <= y < 3:
                    self.assertEqual(px[x, y], (255, 255, 255))
                else:
                    self.assertEqual(px[x, y], orig[x, y])

    def test_config_region_before_cli_region(self):
        src, img = self.gradient_rgb()
        out = self.dir / "out.png"
        cfg = self.write_config(["region 0,0,4,4:delete"])
        proc = self.run_cli([str(src), "-o", str(out), "--config", str(cfg),
                             "--region", "2,2,4,4:mosaic"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        res = self.load(out)
        px, orig = res.load(), img.load()
        # config region (0,0,4,4) wins; CLI region (2,2,4,4) overlaps and is discarded
        for y in range(6):
            for x in range(8):
                if x < 4 and y < 4:
                    self.assertEqual(px[x, y], (255, 255, 255))
                else:
                    self.assertEqual(px[x, y], orig[x, y])

    def test_text_input_with_config_region_rejected(self):
        txt = self.dir / "in.txt"
        txt.write_text("hello world\n", encoding="utf-8")
        cfg = self.write_config(["region 0,0,2,2:delete"])
        proc = self.run_cli([str(txt), "-o", str(self.dir / "out.txt"),
                             "--config", str(cfg)])
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_config_region_malformed(self):
        src, _ = self.gradient_rgb()
        out = self.dir / "out.png"
        for bad in ("region 1,1,4:delete", "region 1,1,4,2:blast",
                    "region 2,2,0,3:delete", "region 6,5,4,4:delete",
                    "region"):
            cfg = self.write_config([bad])
            proc = self.run_cli([str(src), "-o", str(out),
                                 "--config", str(cfg)])
            self.assertEqual(proc.returncode, 2,
                             "bad region %r: rc=%d stderr=%s"
                             % (bad, proc.returncode, proc.stderr))

    def test_config_region_with_cli_rule_rejected(self):
        src, _ = self.gradient_rgb()
        cfg = self.write_config(["region 0,0,2,2:delete"])
        proc = self.run_cli([str(src), "-o", str(self.dir / "out.png"),
                             "--config", str(cfg), "--rule", "secret:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_config_region_with_cli_builtin_rejected(self):
        src, _ = self.gradient_rgb()
        cfg = self.write_config(["region 0,0,2,2:delete"])
        proc = self.run_cli([str(src), "-o", str(self.dir / "out.png"),
                             "--config", str(cfg), "--builtin", "phone-jp:delete"])
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_config_region_with_arg(self):
        src, img = self.gradient_rgb()
        out = self.dir / "out.png"
        cfg = self.write_config(["region 0,0,8,6:mosaic:8"])
        proc = self.run_cli([str(src), "-o", str(out), "--config", str(cfg)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        res = self.load(out)
        px = res.load()
        for y in range(6):
            for x in range(8):
                self.assertEqual(px[x, y], (57, 42, 3), "pixel (%d,%d)" % (x, y))

    def test_config_without_region_lines_unchanged(self):
        # Existing config usage (rule/builtin only) must keep working on
        # text input — no behavior change for the existing consumers.
        txt = self.dir / "in.txt"
        txt.write_text("秘密のデータ\n", encoding="utf-8")
        cfg = self.write_config(["rule 秘密:delete"])
        out = self.dir / "out.txt"
        proc = self.run_cli([str(txt), "-o", str(out), "--config", str(cfg)])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(out.read_text(encoding="utf-8"), "のデータ\n")


if __name__ == "__main__":
    unittest.main()

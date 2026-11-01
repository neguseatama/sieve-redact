"""Sieve Redact v0.7 — phone-jp 緩和の受け入れ試験。

Scope:
  - (4,2,4) の接頭辞フィルタを 0[1-7]xx → 0[1-9]xx に拡張
    (08xx / 09xx の地理 4 桁市外局番を含む)。{0120, 0570, 0800} は
    (4,3,3) 専用のまま
  - 短縮番号 (ハイフンなし 3 桁): 104 / 106 / 110 / 117 / 118 / 119 /
    171 を phone-jp に含める (両側 ASCII digit 境界)
  - 過剰検出を過小検出より優先する方針は v0.4 から継続
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "sieve_redact.py"


class PhoneRelaxBase(unittest.TestCase):
    """Runs sieve_redact.py as a child process."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.dir = Path(tmp.name)
        self.addCleanup(tmp.cleanup)

    def write(self, name, text):
        p = self.dir / name
        p.write_text(text, encoding="utf-8")
        return p

    def read(self, p):
        return p.read_text(encoding="utf-8")

    def ok_run(self, args):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT)] + list(args),
            capture_output=True, text=True,
        )
        self.assertEqual(
            proc.returncode, 0,
            "unexpected rc=%d\nstdout:\n%s\nstderr:\n%s"
            % (proc.returncode, proc.stdout, proc.stderr),
        )
        return proc


class Test424NineExtension(PhoneRelaxBase):
    """(4,2,4) が 08xx / 09xx を含む。"""

    def test_0852_delete(self):
        # 0852 (松江) のような地理 4 桁市外局番
        inp = self.write("in.txt", "0852-22-5111")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "")

    def test_0950_mosaic(self):
        inp = self.write("in.txt", "0950-25-0123")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:mosaic"])
        self.assertEqual(self.read(out), "█" * 12)

    def test_0847_label(self):
        # v0.4 で不一致を pin していた境界が v0.7 で反転
        inp = self.write("in.txt", "0847-12-3456")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:label"])
        self.assertEqual(self.read(out), "[REDACTED]1")

    def test_0912_delete(self):
        inp = self.write("in.txt", "0912-34-5678")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "")

    def test_0120_still_excluded_from_424(self):
        # フリーダイヤル 0120 は (4,3,3) 専用のまま
        inp = self.write("in.txt", "0120-45-6789")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "0120-45-6789")

    def test_0570_still_excluded_from_424(self):
        # ナビダイヤル 0570 も (4,3,3) 専用のまま
        inp = self.write("in.txt", "0570-45-6789")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "0570-45-6789")

    def test_leading_digit_boundary(self):
        inp = self.write("in.txt", "10852-22-5111")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "10852-22-5111")

    def test_trailing_digit_boundary(self):
        inp = self.write("in.txt", "0852-22-51111")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "0852-22-51111")


class TestShortNumbers(PhoneRelaxBase):
    """短縮番号 (3 桁・ハイフンなし)。"""

    def test_117_delete(self):
        inp = self.write("in.txt", "117")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "")

    def test_104_label(self):
        inp = self.write("in.txt", "104")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:label"])
        self.assertEqual(self.read(out), "[REDACTED]1")

    def test_all_short_numbers(self):
        text = "104,106,110,117,118,119,171"
        inp = self.write("in.txt", text)
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), ",,,,,,")

    def test_in_prose(self):
        inp = self.write("in.txt", "時報は117です")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "時報はです")

    def test_four_digit_run_rejected(self):
        # 3 桁の前後に digit が続く場合は境界拒否
        inp = self.write("in.txt", "1117")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "1117")

    def test_trailing_digit_rejected(self):
        inp = self.write("in.txt", "1170")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "1170")

    def test_inside_phone_number_rejected(self):
        # 形状一致する電話番号の内部は短縮番号として拾わない
        inp = self.write("in.txt", "090-1104-5678")
        out = self.dir / "out.txt"
        self.ok_run([inp, "-o", out, "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "")

    def test_noise_deterministic(self):
        text = "117"
        inp = self.write("in.txt", text)
        out1 = self.dir / "out1.txt"
        out2 = self.dir / "out2.txt"
        self.ok_run([inp, "-o", out1, "--builtin", "phone-jp:noise"])
        self.ok_run([inp, "-o", out2, "--builtin", "phone-jp:noise"])
        n1 = self.read(out1)
        self.assertEqual(n1, self.read(out2))
        self.assertEqual(len(n1), 3)
        for ch in n1:
            self.assertIn(ch, "0123456789")


if __name__ == "__main__":
    unittest.main()

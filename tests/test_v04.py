"""Acceptance tests for the phone-jp extension (v0.4).

Scope: the (4,2,4) shape gains the 07xx prefix family, i.e. the
prefix filter becomes 0[1-7]xx while the (4,3,3) prefixes
{0120, 0570, 0800} stay excluded. Everything else is unchanged:
shapes, trial order, both-side digit boundaries, receipt fields,
and the noise seed "phone-jp".

Boundary decisions documented here:
- 08xx and 09xx stay unmatched (explicit boundary; widening
  further would flip behavior pinned by earlier tests).
- Digit sequences without real assignments may still match:
  over-matching is preferred over under-detecting.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "sieve_redact.py"


class PhoneRuleBase(unittest.TestCase):
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


class Test424SevenExtension(PhoneRuleBase):
    """07xx joins the (4,2,4) prefix family."""

    def test_0742_delete(self):
        inp = self.write("in.txt", "0742-12-3456")
        out = self.dir / "out.txt"
        self.ok_run([str(inp), "-o", str(out), "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "")

    def test_0749_mosaic_length(self):
        inp = self.write("in.txt", "0749-12-3456")
        out = self.dir / "out.txt"
        self.ok_run([str(inp), "-o", str(out), "--builtin", "phone-jp:mosaic"])
        self.assertEqual(self.read(out), "█" * 12)

    def test_0749_label(self):
        inp = self.write("in.txt", "0749-12-3456")
        out = self.dir / "out.txt"
        self.ok_run([str(inp), "-o", str(out), "--builtin", "phone-jp:label"])
        self.assertEqual(self.read(out), "[REDACTED]1")

    def test_mixed_content_untouched_bytes(self):
        text = "abc-0749-12-3456-xyz\n"
        inp = self.write("in.txt", text)
        out = self.dir / "out.txt"
        self.ok_run([str(inp), "-o", str(out), "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "abc--xyz\n")

    def test_receipt_reports_phone_matcher(self):
        inp = self.write("in.txt", "0749-12-3456")
        out = self.dir / "out.txt"
        rec = self.dir / "rec.json"
        self.ok_run([str(inp), "-o", str(out), "--builtin", "phone-jp:delete",
                     "--receipt", str(rec)])
        data = json.loads(rec.read_text(encoding="utf-8"))
        self.assertEqual(data["total_redactions"], 1)
        r = data["redactions"][0]
        self.assertEqual(r["matcher"], "builtin:phone-jp")
        self.assertEqual(r["mode"], "delete")
        self.assertEqual(r["length"], 12)

    def test_08xx_stays_unmatched(self):
        # 08xx is outside 0[1-7]xx (explicit boundary).
        inp = self.write("in.txt", "0847-12-3456")
        out = self.dir / "out.txt"
        self.ok_run([str(inp), "-o", str(out), "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "0847-12-3456")

    def test_09xx_stays_unmatched(self):
        # 09xx is outside 0[1-7]xx (explicit boundary).
        inp = self.write("in.txt", "0912-34-5678")
        out = self.dir / "out.txt"
        self.ok_run([str(inp), "-o", str(out), "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "0912-34-5678")

    def test_0120_excluded_from_424(self):
        # 0120 stays exclusive to (4,3,3).
        inp = self.write("in.txt", "0120-45-6789")
        out = self.dir / "out.txt"
        self.ok_run([str(inp), "-o", str(out), "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "0120-45-6789")

    def test_leading_digit_boundary(self):
        inp = self.write("in.txt", "10742-12-3456")
        out = self.dir / "out.txt"
        self.ok_run([str(inp), "-o", str(out), "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "10742-12-3456")

    def test_trailing_digit_boundary(self):
        inp = self.write("in.txt", "0742-12-34567")
        out = self.dir / "out.txt"
        self.ok_run([str(inp), "-o", str(out), "--builtin", "phone-jp:delete"])
        self.assertEqual(self.read(out), "0742-12-34567")


class TestNoiseStaysDeterministic(PhoneRuleBase):
    """Noise on the new prefix stays deterministic and
    length-preserving. The seed itself is pinned by the
    existing v0.2 noise recompute test, unchanged."""

    def test_noise_deterministic_and_length(self):
        text = "0749-12-3456"
        inp = self.write("in.txt", text)
        out1 = self.dir / "out1.txt"
        out2 = self.dir / "out2.txt"
        self.ok_run([str(inp), "-o", str(out1), "--builtin", "phone-jp:noise"])
        self.ok_run([str(inp), "-o", str(out2), "--builtin", "phone-jp:noise"])
        n1 = self.read(out1)
        self.assertEqual(n1, self.read(out2))
        self.assertEqual(len(n1), len(text))
        self.assertEqual(n1[4], "-")
        self.assertEqual(n1[7], "-")


if __name__ == "__main__":
    unittest.main()

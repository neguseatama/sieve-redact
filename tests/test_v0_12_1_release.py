"""Sieve Redact v0.12.1 — the release trial path and the 0.12.0
invariance (RD-T26..T28).

Three pins ride with the 0.12.1 maintenance step:

  - RD-T26 reads ``.github/workflows/release.yml`` and pins the
    structure of the two run paths: the tag push keeps its behavior,
    and a manual (workflow_dispatch) trial run performs the same build,
    version check, body extraction and body check, and the checksum
    file, leaves the outputs as workflow artifacts, and creates no
    GitHub Release.  The workflow file is not part of the sdist, so
    these tests skip there.
  - RD-T27 pins the 0.12.0 behavior on the 0.12.1 tree: the product
    source differs from 0.12.0 only in the version string (a sha256
    over the source with the version line masked), and a fixed run
    reproduces the 0.12.0 receipt, output bytes and exit codes.
  - RD-T28 pins the version surface: the newest CHANGELOG section
    carries the current version, follows the short-section shape
    (three to five items), and the release body extracts from it.

The masked-source and receipt pins are version-scoped like the v0.9.0
output pins: a later step that consciously changes the surface updates
them in the same step.
"""

import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "sieve_redact.py"
sys.path.insert(0, str(ROOT))

import sieve_redact as sr  # noqa: E402

RELEASE_YML = ROOT / ".github" / "workflows" / "release.yml"
EXTRACT_TOOL = ROOT / "tools" / "extract_changelog.py"

# ---------------------------------------------------------------------------
# RD-T26: the release workflow file
# ---------------------------------------------------------------------------

def _step_blocks(text):
    """Split the workflow into step blocks (one block per list entry).

    Steps sit at a fixed indent in this file; a block runs from its
    ``- name:`` / ``- uses:`` line to the next step line.
    """
    starts = [i for i, line in enumerate(text.splitlines())
              if line.startswith("      - ")]
    lines = text.splitlines()
    blocks = []
    for k, start in enumerate(starts):
        end = starts[k + 1] if k + 1 < len(starts) else len(lines)
        blocks.append("\n".join(lines[start:end]))
    return blocks


def _find_step(blocks, needle):
    for block in blocks:
        if needle in block:
            return block
    raise AssertionError("workflow step not found: %s" % needle)


@unittest.skipUnless(RELEASE_YML.exists(), ".github is not in the sdist")
class RD_T26_ReleaseTrialPath(unittest.TestCase):
    """The release workflow keeps the tag path and adds a trial path."""

    @classmethod
    def setUpClass(cls):
        cls.text = RELEASE_YML.read_text(encoding="utf-8")
        cls.blocks = _step_blocks(cls.text)

    def test_the_tag_trigger_is_unchanged(self):
        self.assertIn("push:", self.text)
        self.assertIn('tags: ["v*"]', self.text)

    def test_a_manual_run_can_start_the_workflow(self):
        self.assertIn("workflow_dispatch:", self.text)

    def test_the_github_release_is_created_only_by_a_tag_push(self):
        # the attach step carries the event gate: a trial run reaches
        # the end of the build without creating a GitHub Release
        attach = _find_step(self.blocks, "softprops/action-gh-release")
        self.assertIn("if: github.event_name == 'push'", attach)
        # the gate sits on the step itself, before the action runs
        self.assertLess(
            attach.index("if: github.event_name == 'push'"),
            attach.index("uses: softprops/action-gh-release"))
        # every occurrence of the attach action is gated
        gated = [b for b in self.blocks
                 if "softprops/action-gh-release" in b]
        self.assertEqual(len(gated), 1)

    def test_the_provenance_attestation_rides_the_tag_path_only(self):
        attest = _find_step(self.blocks, "actions/attest")
        self.assertIn("if: github.event_name == 'push'", attest)

    def test_the_trial_keeps_its_outputs_as_workflow_artifacts(self):
        upload = _find_step(self.blocks, "actions/upload-artifact")
        self.assertIn("if: github.event_name == 'workflow_dispatch'",
                      upload)
        self.assertIn("dist/", upload)
        self.assertIn("release_body.md", upload)

    def test_the_version_check_covers_both_paths(self):
        check = _find_step(self.blocks, "dist/sieve_redact-")
        # a tag run compares the tag with the artifacts
        self.assertIn('version="${GITHUB_REF_NAME#v}"', check)
        # a trial run has no tag and compares VERSION with the artifacts
        self.assertIn("GITHUB_EVENT_NAME", check)
        self.assertIn("workflow_dispatch", check)
        self.assertIn("sieve_redact.VERSION", check)
        # the extracted version feeds the body extraction
        self.assertIn("RELEASE_VERSION", check)
        extract = _find_step(self.blocks, "tools/extract_changelog.py")
        self.assertIn('"${RELEASE_VERSION}"', extract)

    def test_the_body_check_and_the_checksum_steps_are_kept(self):
        check = _find_step(self.blocks, "check_public_text.py --text")
        self.assertIn("release_body.md", check)
        sums = _find_step(self.blocks, "SHA256SUMS.txt")
        self.assertIn("sha256sum", sums)


# ---------------------------------------------------------------------------
# RD-T27: the 0.12.0 invariance on the 0.12.1 tree
# ---------------------------------------------------------------------------

# measured on the 0.12.0 tree (main at the 0.12.0 merge): the sha256 of
# sieve_redact.py with the VERSION line masked, the receipt and the
# output bytes of the fixed run below, and the refusal exit codes.
MASKED_SOURCE_SHA256 = (
    "c912efa2dc495750da885e6bf5f378507663daaf40af1efe175cd25f9e2e12a6")
FIXTURE_BYTES = b"TEL 090-1234-5678 secret note\n"
OUTPUT_0_12_0 = b"TEL  secret note\n"
RECEIPT_0_12_0 = {
    "byte_integrity_verified": True,
    "input_bytes": 30,
    "output_bytes": 17,
    "pattern_appearance_in_output": "none",
    "redactions": [
        {
            "content_sha256": (
                "522d69851a96e9603eba545c59de1c0b5808cfbb0978ede5e7f0c5ab4"
                "7bfa9aa"),
            "end": 17,
            "length": 13,
            "matcher": "builtin:phone-jp",
            "mode": "delete",
            "replacement_length": 0,
            "rule_index": 1,
            "start": 4,
        },
    ],
    "total_redactions": 1,
}


def _run_cli(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT)] + [str(a) for a in args],
        capture_output=True, encoding="utf-8", errors="replace",
        timeout=120)


class RD_T27_Invariance(unittest.TestCase):
    """Receipt, output, exit codes and wording stay at 0.12.0."""

    def test_the_product_source_differs_from_0_12_0_only_in_the_version(self):
        src = (ROOT / "sieve_redact.py").read_text(encoding="utf-8")
        masked, count = re.subn(r'(?m)^VERSION = "[0-9.]+"$',
                                'VERSION = "<masked>"', src)
        self.assertEqual(count, 1)
        self.assertEqual(
            hashlib.sha256(masked.encode("utf-8")).hexdigest(),
            MASKED_SOURCE_SHA256,
            "sieve_redact.py changed beyond the version string")

    def test_receipt_output_and_exit_codes_match_0_12_0(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            inp = d / "in.txt"
            inp.write_bytes(FIXTURE_BYTES)
            out = d / "out.txt"
            rec = d / "receipt.json"
            ok = _run_cli(inp, "-o", str(out), "--receipt", str(rec),
                          "--builtin", "phone-jp:delete")
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertEqual(out.read_bytes(), OUTPUT_0_12_0)
            self.assertEqual(
                json.loads(rec.read_text(encoding="utf-8")),
                RECEIPT_0_12_0)
            missing = _run_cli(d / "absent.txt", "-o", str(d / "o1.txt"),
                               "--builtin", "phone-jp:delete")
            self.assertEqual(missing.returncode, 1)
            self.assertIn("入力ファイルを読めません", missing.stderr)
            refused = _run_cli(inp, "-o", str(d / "o2.txt"),
                               "--region", "0,0,1,1:delete")
            self.assertEqual(refused.returncode, 2)
            self.assertIn("input is not a PNG file", refused.stderr)


# ---------------------------------------------------------------------------
# RD-T28: the version surface
# ---------------------------------------------------------------------------

_SECTION_SUBHEADERS = ("Added", "Changed", "Fixed", "Deprecated",
                       "Removed", "Security")


class RD_T28_VersionSurface(unittest.TestCase):
    """The newest CHANGELOG section carries the release shape."""

    @classmethod
    def setUpClass(cls):
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        cls.lines = text.splitlines()
        cls.heads = [i for i, line in enumerate(cls.lines)
                     if line.startswith("## [")]

    def _section_lines(self):
        self.assertTrue(self.heads)
        top = self.heads[0]
        end = self.heads[1] if len(self.heads) > 1 else len(self.lines)
        return self.lines[top + 1:end]

    def test_the_newest_section_carries_the_current_version_and_date(self):
        top = self.lines[self.heads[0]]
        self.assertTrue(top.startswith(f"## [{sr.VERSION}] - "), top)

    def test_the_newest_section_keeps_the_short_shape(self):
        section = self._section_lines()
        subs = [line[4:] for line in section if line.startswith("### ")]
        self.assertTrue(subs, "no ### subheaders in the newest section")
        for name in subs:
            self.assertIn(name, _SECTION_SUBHEADERS, name)
        items = [line for line in section if line.startswith("- ")]
        self.assertGreaterEqual(len(items), 3, "too few items")
        self.assertLessEqual(len(items), 5, "too many items")

    @unittest.skipUnless(EXTRACT_TOOL.exists(), "tools/ is not in the sdist")
    def test_the_release_body_extracts_from_the_newest_section(self):
        proc = subprocess.run(
            [sys.executable, str(EXTRACT_TOOL), sr.VERSION],
            capture_output=True, encoding="utf-8", errors="replace",
            timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(proc.stdout.startswith("### "), proc.stdout[:80])
        section = "\n".join(self._section_lines()).strip()
        self.assertEqual(proc.stdout.strip(), section)


if __name__ == "__main__":
    unittest.main(verbosity=2)

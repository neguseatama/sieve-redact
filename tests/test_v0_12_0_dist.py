"""Sieve Redact v0.12.0 — the sdist ships everything its tests need,
and its tests pass in a fresh venv (RD-T20).

Spec summary (pinned by these tests):
  - The sdist contains `tests/corpus/schema_contract_v1.json`,
    `tests/render_pins.json`, `README.ja.md` and `CHANGELOG.md`
    (LICENSE, `README.md`, `pyproject.toml`, `sieve_redact.py` and the
    test modules were already included in 0.11.0).
  - The sdist's own test suite passes when run from the UNPACKED sdist
    in a fresh venv.  The venv carries nothing of its own (no pip
    bootstrap, no system-site bridge, nothing installed); the run
    reaches the ambient environment's site-packages through PYTHONPATH
    so the optional image extra (Pillow) stays available, while the
    code under test is exclusively the sdist's own files — the current
    directory and each test module's `sys.path` root are the unpacked
    sdist, so an installed copy of the package can never shadow it.
  - The build runs offline against a clean COPY of the tree (the
    egg-info that setuptools writes stays inside the temporary copy).

The 0.11.0 sdist missed the four files above and its tests failed with
8 errors in a plain environment; these tests pin the fix.

The fresh-venv run re-enters this module through the sdist's own test
suite; a marker in the child environment keeps the guard from
re-entering itself (the nested run skips the fresh-venv test).
"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import unittest
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REQUIRED_MEMBERS = (
    "tests/corpus/schema_contract_v1.json",
    "tests/render_pins.json",
    "README.ja.md",
    "CHANGELOG.md",
    "LICENSE",
    "README.md",
    "pyproject.toml",
    "sieve_redact.py",
)

_COPY_IGNORE = shutil.ignore_patterns(
    "__pycache__", "*.egg-info", ".git", "dist", "build", "*.pyc")

# the environment marker set by test_sdist_tests_pass_in_a_fresh_venv
_VENV_RUN_MARKER = "SIEVE_REDACT_SDIST_RUN"


def build_sdist_from_clean_copy(tmp):
    """Build the sdist from a clean copy of the tree; return its path."""
    copy_root = tmp / "copy"
    shutil.copytree(ROOT, copy_root, ignore=_COPY_IGNORE)
    out_dir = tmp / "sdist"
    out_dir.mkdir()
    cwd = os.getcwd()
    try:
        os.chdir(copy_root)
        from setuptools import build_meta
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            name = build_meta.build_sdist(str(out_dir))
    finally:
        os.chdir(cwd)
    return out_dir / name


def venv_python(venv_dir):
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


class RD_T20_SdistSelfContained(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls._tmp = tmp
        cls.tmp = Path(tmp.name)
        cls.sdist = build_sdist_from_clean_copy(cls.tmp)
        cls.unpack = cls.tmp / "unpack"
        with tarfile.open(cls.sdist) as tf:
            tf.extractall(cls.unpack)
        members = set()
        top = cls.unpack / cls.sdist.name[:-len(".tar.gz")]
        for path in top.rglob("*"):
            rel = path.relative_to(top).as_posix()
            if not path.is_dir():
                members.add(rel)
        cls.members = members
        cls.top = top

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_sdist_contains_the_required_files(self):
        for member in REQUIRED_MEMBERS:
            self.assertIn(member, self.members, member)
        # テストモジュールは全て入る (0.11.0 の自動収集を維持)。
        tests = [m for m in self.members
                 if m.startswith("tests/") and m.endswith(".py")]
        self.assertGreaterEqual(len(tests), 18, sorted(tests))

    @unittest.skipIf(os.environ.get(_VENV_RUN_MARKER) == "1",
                     "the fresh-venv run does not re-enter itself")
    def test_sdist_tests_pass_in_a_fresh_venv(self):
        fresh = self.tmp / "venv"
        with contextlib.redirect_stdout(io.StringIO()):
            venv.create(fresh, with_pip=False, system_site_packages=False)
        # まっさらな venv (中身は空)。任意 extra の Pillow だけは実行
        # 環境の site-packages を PYTHONPATH で届ける (venv の中に
        # 何かを入れるわけではない・CI の plain interpreter でも
        # venv 内の実行でも同じ経路で届く)。
        env = dict(os.environ)
        env["PYTHONPATH"] = sysconfig.get_paths()["purelib"]
        env[_VENV_RUN_MARKER] = "1"
        proc = subprocess.run(
            [str(venv_python(fresh)), "-m", "unittest", "discover",
             "-s", "tests"], cwd=str(self.top), env=env,
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=600)
        self.assertEqual(
            proc.returncode, 0,
            "the sdist's tests failed (rc=%d)\n=== tail of stdout ===\n%s"
            "\n=== tail of stderr ===\n%s"
            % (proc.returncode, proc.stdout[-4000:], proc.stderr[-4000:]))

    def test_the_engine_runs_from_the_sdist_copy(self):
        # 展開した sdist 自体が CLI として動く (受領書の形は同じ)。
        src = self.tmp / "in.txt"
        src.write_text("秘密 秘密\n", encoding="utf-8")
        out = self.tmp / "out.txt"
        rec = self.tmp / "rec.json"
        proc = subprocess.run(
            [sys.executable, str(self.top / "sieve_redact.py"),
             str(src), "-o", str(out), "--receipt", str(rec),
             "--rule", "秘密:delete"],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(out.read_text("utf-8"), " \n")
        data = json.loads(rec.read_text("utf-8"))
        self.assertEqual(data["total_redactions"], 2)


if __name__ == "__main__":
    unittest.main()

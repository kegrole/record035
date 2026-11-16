"""Unit tests for the filetypes sniffer.

Each test maps to one acceptance criterion. Baseline fixtures are built
from format specifications in a temporary directory (tests/fixtures.py);
derived fixtures (truncated JPEG, NUL-injected text, traversal ZIP) are
also created in temporary directories and never touch demo/files/.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from filetypes import archive, imagecheck, rules, sniffer
from filetypes.cli import main as cli_main
from tests import fixtures


class BaselineCase(unittest.TestCase):
    """Criteria 1-4, 7: the 10 baseline files and their verdicts."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.dir = cls._tmp.name
        fixtures.write_baseline_files(cls.dir)
        cls.records = {}
        for name in sorted(os.listdir(cls.dir)):
            path = os.path.join(cls.dir, name)
            detected, declared, verdict, evidence = rules.analyze_file(path)
            cls.records[name] = {
                "detected": detected,
                "declared": declared,
                "verdict": verdict,
                "evidence": evidence,
            }

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_1_ten_baseline_files_detected(self):
        self.assertEqual(10, len(self.records))
        expected = {
            "sample.png": ["png"],
            "sample.jpg": ["jpeg"],
            "sample.gif": ["gif"],
            "sample.pdf": ["pdf"],
            "sample.zip": ["zip"],
            "sample.gz": ["gzip"],
            "sample.elf": ["elf"],
            "sample.txt": ["text"],
            "polyglot.png": ["png", "zip"],
            "fake.png": ["jpeg"],
        }
        for name, detected in expected.items():
            self.assertEqual(detected, self.records[name]["detected"], name)

    def test_2_exactly_eight_allowed_two_rejected(self):
        verdicts = [r["verdict"] for r in self.records.values()]
        self.assertEqual(8, verdicts.count("allow"))
        self.assertEqual(2, verdicts.count("reject"))
        rejected = {n for n, r in self.records.items() if r["verdict"] == "reject"}
        self.assertEqual({"polyglot.png", "fake.png"}, rejected)

    def test_3_polyglot_reports_both_types(self):
        record = self.records["polyglot.png"]
        self.assertEqual("reject", record["verdict"])
        self.assertIn("png", record["detected"])
        self.assertIn("zip", record["detected"])
        evidence = " ".join(record["evidence"])
        self.assertIn("png", evidence)
        self.assertIn("zip", evidence)

    def test_4_png_dimensions_read_from_ihdr(self):
        record = self.records["sample.png"]
        self.assertEqual("allow", record["verdict"])
        self.assertIn("width=100", " ".join(record["evidence"]))
        self.assertIn("height=50", " ".join(record["evidence"]))
        ok, message = imagecheck.check_png(fixtures.png_bytes(100, 50))
        self.assertTrue(ok)
        self.assertIn("width=100 height=50", message)

    def test_7_extension_mismatch_reports_both_types(self):
        record = self.records["fake.png"]
        self.assertEqual("reject", record["verdict"])
        self.assertEqual("png", record["declared"])
        self.assertEqual(["jpeg"], record["detected"])
        evidence = " ".join(record["evidence"])
        self.assertIn("png", evidence)
        self.assertIn("jpeg", evidence)


class DerivedFixtureCase(unittest.TestCase):
    """Criteria 5, 6, 8: derived fixtures built in a temp directory."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = self._tmp.name

    def _write(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def test_5_jpeg_without_eoi_is_corrupt(self):
        truncated = fixtures.jpeg_bytes()[:-2]
        self.assertFalse(truncated.endswith(imagecheck.JPEG_EOI))
        path = self._write("truncated.jpg", truncated)
        detected, declared, verdict, evidence = rules.analyze_file(path)
        self.assertEqual(["jpeg"], detected)
        self.assertEqual("reject", verdict)
        self.assertIn("EOI", " ".join(evidence))
        ok, _ = imagecheck.check_jpeg(truncated)
        self.assertFalse(ok)

    def test_6_text_with_nul_is_binary(self):
        data = fixtures.text_bytes()
        injected = data[:20] + b"\x00" + data[20:]
        path = self._write("nul.txt", injected)
        detected, declared, verdict, evidence = rules.analyze_file(path)
        self.assertEqual(["binary"], detected)
        self.assertEqual("text", declared)
        self.assertEqual("reject", verdict)
        self.assertEqual(["binary"], sniffer.detect_types(injected))

    def test_8_zip_entry_traversal_reported(self):
        payload = fixtures.zip_bytes(entries=("../evil.txt",))
        path = self._write("evil.zip", payload)
        detected, declared, verdict, evidence = rules.analyze_file(path)
        self.assertEqual(["zip"], detected)
        self.assertEqual("reject", verdict)
        self.assertIn("../evil.txt", " ".join(evidence))
        self.assertEqual(["../evil.txt"], archive.find_traversal_entries(payload))
        self.assertTrue(archive.is_traversal_name("../evil.txt"))
        self.assertTrue(archive.is_traversal_name("/abs/path.txt"))
        self.assertFalse(archive.is_traversal_name("ok/file.txt"))


class DemoDirectoryCase(unittest.TestCase):
    """Criterion 9: demo/files holds exactly the 10 baseline files."""

    def test_9_demo_files_baseline_counts(self):
        demo_dir = os.path.join(REPO_ROOT, "demo", "files")
        names = [n for n in os.listdir(demo_dir)
                 if os.path.isfile(os.path.join(demo_dir, n))]
        self.assertEqual(10, len(names))
        verdicts = [rules.analyze_file(os.path.join(demo_dir, n))[2]
                    for n in names]
        self.assertEqual(8, verdicts.count("allow"))
        self.assertEqual(2, verdicts.count("reject"))

    def test_cli_end_to_end(self):
        demo_dir = os.path.join(REPO_ROOT, "demo", "files")
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "out", "report.json")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = cli_main(["--dir", demo_dir, "--out", out_path])
            self.assertEqual(0, rc)
            summary = stdout.getvalue().strip()
            self.assertIn("files=10", summary)
            self.assertIn("allowed=8", summary)
            self.assertIn("rejected=2", summary)
            with open(out_path, encoding="utf-8") as fh:
                records = json.load(fh)
            self.assertEqual(10, len(records))
            for record in records:
                self.assertEqual(
                    {"file", "detected", "declared", "verdict", "evidence"},
                    set(record),
                )


if __name__ == "__main__":
    unittest.main()

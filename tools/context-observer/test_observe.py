"""Filesystem/contract tests only, not a test of any production security control."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("observe.py")
spec = importlib.util.spec_from_file_location("context_observer", SCRIPT)
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


class ObserverTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "release"
        (self.root / "config").mkdir(parents=True)
        self.file = self.root / "config/settings.json"
        self.original = b'{"mfa_required":true,"sample_only":true}\n'
        self.file.write_bytes(self.original)
        self.selection = {"format": observer.MANIFEST_FORMAT,
                          "context": {"service": "sample-service", "environment": "test",
                                      "release": "r1", "scope": "selected-files",
                                      "policy_revision": "illustrative/0.1", "generation": 1},
                          "files": ["config/settings.json"]}

    def observe(self, selection=None, previous=None):
        return observer.observe(self.root, selection or self.selection, previous)

    def cli(self, *extra, previous_content=None):
        manifest = self.base / "selection.json"
        manifest.write_text(json.dumps(self.selection), encoding="utf8")
        args = [sys.executable, "-I", str(SCRIPT), "--root", str(self.root),
                "--manifest", str(manifest), "--output", str(self.base / "receipt.json")]
        if previous_content is not None:
            old = self.base / "old.json"
            old.write_bytes(previous_content)
            args += ["--previous", str(old)]
        return subprocess.run(args + list(extra), capture_output=True, text=True, timeout=10)

    def test_initial_capture_records_only_hash_and_relative_names(self):
        r = self.observe()
        self.assertEqual(r["comparison"]["state"], "BASELINE_REQUIRED")
        self.assertEqual(r["comparison"]["control_status"], "NOT_ASSESSED")
        self.assertFalse(r["limits"]["production_observed"])
        self.assertEqual(r["limits"]["signature"], "NOT_PROVIDED")
        self.assertNotIn(str(self.base), json.dumps(r))
        self.assertNotIn("mfa_required", json.dumps(r))
        self.assertEqual(self.file.read_bytes(), self.original)

    def test_same_bytes_are_not_a_pass(self):
        old = self.observe()
        new = self.observe(previous=old)
        self.assertEqual(new["comparison"]["state"], "NO_CHANGE_IN_OBSERVED_SCOPE")
        self.assertEqual(new["comparison"]["control_status"], "NOT_ASSESSED")
        self.assertEqual(new["context_digest"], old["context_digest"])

    def test_changed_file_requires_advanced_generation_and_revalidation(self):
        old = self.observe()
        self.file.write_text('{"mfa_required":false}\n')
        with self.assertRaisesRegex(observer.ObservationError, "GENERATION_NOT_ADVANCED"):
            self.observe(previous=old)
        self.selection["context"]["generation"] = 2
        r = self.observe(previous=old)
        self.assertEqual(r["comparison"]["state"], "REVALIDATION_REQUIRED")
        self.assertIn("selected_files", r["comparison"]["changed_fields"])

    def test_restoration_does_not_revive_old_assessment(self):
        old = self.observe()
        self.file.write_text('{"mfa_required":false}\n')
        self.selection["context"]["generation"] = 2
        changed = self.observe(previous=old)
        self.file.write_bytes(self.original)
        self.selection["context"]["generation"] = 3
        restored = self.observe(previous=changed)
        self.assertEqual(restored["files"], old["files"])
        self.assertNotEqual(restored["context_digest"], old["context_digest"])
        self.assertEqual(restored["comparison"]["state"], "REVALIDATION_REQUIRED")

    def test_old_generation_is_rejected(self):
        self.selection["context"]["generation"] = 2
        old = self.observe()
        self.selection["context"]["generation"] = 1
        with self.assertRaisesRegex(observer.ObservationError, "GENERATION_ROLLBACK"):
            self.observe(previous=old)

    def test_baseline_target_cannot_be_swapped(self):
        old = self.observe()
        for key in ("service", "environment"):
            selected = copy.deepcopy(self.selection)
            selected["context"][key] = "other"
            with self.assertRaisesRegex(observer.ObservationError, "BASELINE_TARGET_MISMATCH"):
                self.observe(selected, old)

    def test_release_scope_and_policy_changes_require_review(self):
        old = self.observe()
        for key in ("release", "scope", "policy_revision"):
            selected = copy.deepcopy(self.selection)
            selected["context"][key] = "changed"
            selected["context"]["generation"] = 2
            self.assertEqual(self.observe(selected, old)["comparison"]["state"], "REVALIDATION_REQUIRED")

    def test_null_and_primitive_manifest_rejected(self):
        for value in (None, True, [], "sample"):
            with self.assertRaises(observer.ObservationError):
                observer.manifest(value)

    def test_duplicate_json_nan_and_invalid_utf8_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'\xff', b'\xef\xbb\xbf{}'):
            with self.assertRaises(observer.ObservationError):
                observer.strict_json(raw)

    def test_size_depth_and_unknown_fields_rejected(self):
        for raw in (b' ' * (observer.MAX_JSON + 1), b'[' * 2000 + b']' * 2000):
            with self.assertRaises(observer.ObservationError):
                observer.strict_json(raw)
        bad = copy.deepcopy(self.selection)
        bad["approved"] = True
        with self.assertRaises(observer.ObservationError):
            observer.manifest(bad)

    def test_duplicate_empty_and_excessive_file_sets_rejected(self):
        for files in ([], self.selection["files"] * 2, [f"f{i}.txt" for i in range(33)]):
            bad = {**self.selection, "files": files}
            with self.assertRaises(observer.ObservationError):
                self.observe(bad)

    def test_path_traversal_hidden_and_secret_like_paths_rejected(self):
        for name in ("../x.json", "/tmp/x.json", "config/../x.json", "config//x.json",
                     "config/./x.json", "config\\x.json", ".env", ".git/config",
                     "config/secrets.json", "config/credentials.json", "x.pem", "config/a\n.json"):
            with self.subTest(name=name), self.assertRaises(observer.ObservationError):
                observer.relative_path(name)

    def test_missing_file_and_directory_are_errors(self):
        self.file.unlink()
        with self.assertRaises(OSError):
            self.observe()
        self.file.mkdir()
        with self.assertRaises(observer.ObservationError):
            self.observe()

    def test_symlink_file_and_parent_are_rejected(self):
        outside = self.base / "outside.json"
        outside.write_text("do not read")
        self.file.unlink()
        self.file.symlink_to(outside)
        with self.assertRaises(OSError):
            self.observe()
        self.file.unlink()
        (self.root / "config").rmdir()
        (self.root / "config").symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(OSError):
            self.observe({**self.selection, "files": ["config/outside.json"]})

    def test_hardlink_and_fifo_are_rejected_without_blocking(self):
        self.file.unlink()
        outside = self.base / "outside.json"
        outside.write_text("not selected")
        os.link(outside, self.file)
        with self.assertRaises(observer.ObservationError):
            self.observe()
        self.file.unlink()
        os.mkfifo(self.file)
        with self.assertRaises(observer.ObservationError):
            self.observe()

    def test_per_file_and_total_limits(self):
        self.file.write_bytes(b'x' * (observer.MAX_FILE + 1))
        with self.assertRaisesRegex(observer.ObservationError, "FILE_SIZE_LIMIT"):
            self.observe()
        self.file.write_bytes(self.original)
        with patch.object(observer, "MAX_TOTAL", 1), self.assertRaisesRegex(observer.ObservationError, "TOTAL_SIZE_LIMIT"):
            self.observe()

    def test_file_change_between_reads_fails_closed(self):
        read = observer.selected_file
        count = 0
        def changing(*args):
            nonlocal count
            count += 1
            if count == 2:
                self.file.write_text("changed")
            return read(*args)
        with patch.object(observer, "selected_file", changing), self.assertRaisesRegex(observer.ObservationError, "FILE_SET_CHANGED"):
            self.observe()

    def test_invalid_baseline_hash_and_duplicate_paths_rejected(self):
        old = self.observe()
        old["files"][0]["sha256"] = '0' * 64
        with self.assertRaisesRegex(observer.ObservationError, "BASELINE_DIGEST_MISMATCH"):
            self.observe(previous=old)
        old = self.observe()
        old["files"] *= 2
        with self.assertRaises(observer.ObservationError):
            self.observe(previous=old)

    def test_null_baseline_cli_never_becomes_initial_success(self):
        r = self.cli(previous_content=b'null')
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")
        self.assertFalse((self.base / "receipt.json").exists())

    def test_receipt_is_private_new_file_and_cannot_overwrite(self):
        r = self.cli()
        self.assertEqual(r.returncode, 0, r.stderr)
        path = self.base / "receipt.json"
        first = path.read_bytes()
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        repeat = self.cli()
        self.assertEqual(repeat.returncode, 2)
        self.assertEqual(first, path.read_bytes())
        self.assertNotIn(str(self.base), repeat.stderr)

    def test_output_inside_observed_root_rejected(self):
        r = self.observe()
        with self.assertRaisesRegex(observer.ObservationError, "OUTPUT_MUST_BE_OUTSIDE"):
            observer.write_receipt(self.root / "receipt.json", r, self.root)
        self.assertFalse((self.root / "receipt.json").exists())

    def test_unsupported_platform_fails_instead_of_weak_fallback(self):
        with patch.object(os, "supports_dir_fd", set()), self.assertRaisesRegex(observer.ObservationError, "UNSUPPORTED_PLATFORM"):
            self.observe()


if __name__ == "__main__":
    unittest.main()

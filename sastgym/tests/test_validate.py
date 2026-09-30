"""Contract rejection tests. These do not test Rails or execute vulnerability payloads."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import hashlib

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gt_validate", HERE / "validate.py")
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
ROOT = HERE.parent
DATA = v.load_json(HERE / "ground-truth.json")
SCHEMA = v.load_json(HERE / "schema.json")


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.data = copy.deepcopy(DATA)

    def errors(self):
        return v.validate(self.data, ROOT, SCHEMA, check_snapshot=False)

    def assert_rejected(self, fragment):
        self.assertTrue(any(fragment in error for error in self.errors()), self.errors())

    def test_valid_dataset_and_entire_source_snapshot(self):
        self.assertEqual(v.validate(DATA, ROOT, SCHEMA), [])

    def test_schema_rejects_unknown_fields(self):
        self.data["findings"][0]["confidence"] = "trust me"
        self.assert_rejected("Additional properties")

    def test_schema_rejects_missing_required_field(self):
        del self.data["findings"][0]["preconditions"]
        self.assert_rejected("required property")

    def test_schema_rejects_bad_date(self):
        self.data["manifest"]["created_at"] = "2026-99-99"
        self.assert_rejected("not a 'date'")

    def test_duplicate_ids(self):
        self.data["findings"][1]["id"] = self.data["findings"][0]["id"]
        self.assert_rejected("duplicate finding ID")

    def test_duplicate_root_cause(self):
        dupe = copy.deepcopy(self.data["findings"][0])
        dupe["id"] = "RAILSGOAT-099"
        self.data["findings"].append(dupe)
        self.assert_rejected("duplicate root-cause")

    def test_path_escape_and_noncanonical_paths(self):
        for bad_path in ("../README.md", "/etc/passwd", "app/../README.md", "app\\controllers\\x.rb", "C:/x.rb", "./README.md"):
            with self.subTest(path=bad_path):
                self.data["findings"][0]["primary_location"]["path"] = bad_path
                self.assert_rejected("unsafe/noncanonical")

    def test_symlink_source_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "link").symlink_to(ROOT / "README.md")
            with self.assertRaises(ValueError):
                v.safe_path(root, "link")

    def test_missing_file(self):
        self.data["findings"][0]["primary_location"]["path"] = "app/not-present.rb"
        self.assert_rejected("unreadable/invalid location")

    def test_reversed_range(self):
        self.data["findings"][0]["primary_location"]["end_line"] = 1
        self.assert_rejected("invalid line range")

    def test_out_of_bounds_range(self):
        self.data["findings"][0]["primary_location"]["end_line"] = 99999
        self.assert_rejected("invalid line range")

    def test_changed_excerpt(self):
        self.data["findings"][0]["primary_location"]["excerpt_sha256"] = "0" * 64
        self.assert_rejected("excerpt SHA-256 mismatch")

    def test_root_role(self):
        self.data["findings"][0]["primary_location"]["role"] = "context"
        self.assert_rejected("primary location must")

    def test_false_reproduced_claim(self):
        self.data["findings"][0]["evidence"]["level"] = "reproduced"
        self.assert_rejected("must agree")

    def test_unsupported_runtime_claim(self):
        runtime = self.data["findings"][0]["evidence"]
        runtime["level"] = "reproduced"
        runtime["runtime"]["status"] = "passed"
        self.assert_rejected("pilot v1 does not accept reproduced claims")

    def test_false_manifest_runtime_claim(self):
        self.data["manifest"]["environment"]["runtime_reproduced"] = True
        self.assert_rejected("manifest runtime_reproduced")

    def test_lockfile_pin(self):
        self.data["manifest"]["environment"]["lockfile_sha256"] = "0" * 64
        self.assert_rejected("Gemfile.lock SHA-256")

    def test_wrong_tree(self):
        source = DATA["manifest"]["source"]
        self.assertIn("manifest source tree does not match the pinned commit", v.snapshot_errors(ROOT, source["commit"], "0" * 40))

    def test_missing_snapshot(self):
        self.assertTrue(v.snapshot_errors(ROOT, "0" * 40, "0" * 40))

    def test_authoring_allowlist_cannot_be_expanded(self):
        self.data["manifest"]["evaluation"]["authoring_paths"].append("app/")
        self.assert_rejected("authoring_paths does not match")

    def test_source_mutation_extra_files_and_mode_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.rb"
            original = b"original\n"
            source.write_bytes(original)
            blob = hashlib.sha1(b"blob 9\0" + original).hexdigest()
            tree = b"1" * 40
            record = b"100644 blob " + blob.encode() + b"\tsource.rb\0"
            for changed, executable, addition, fragment in (
                (True, False, None, "pinned source changed"),
                (False, True, None, "executable mode changed"),
                (False, False, "app/controllers/untracked.rb", "unexpected file"),
                (False, False, "config/initializers/ignored.rb", "unexpected file"),
            ):
                with self.subTest(fragment=fragment, addition=addition):
                    source.write_bytes(b"changed\n" if changed else original)
                    source.chmod(0o755 if executable else 0o644)
                    current = b"source.rb\0" + ((addition + "\0").encode() if addition else b"")
                    with patch.object(v, "git", side_effect=[tree, record, current]):
                        errors = v.snapshot_errors(root, "0" * 40, tree.decode())
                    self.assertTrue(any(fragment in error for error in errors), errors)

    def test_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"id": 1, "id": 2}')
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                v.load_json(path)


if __name__ == "__main__":
    unittest.main()

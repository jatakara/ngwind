"""Regression tests for archive policy hardening. Run with unittest."""
import importlib.util
import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "archive_policy", Path(__file__).with_name("archive_policy.py")
)
# Import sibling artifact_preflight when running this test by file path.
import sys
sys.path.insert(0, str(Path(__file__).parent))
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class ArchivePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def make_zip(self, names):
        path = self.root / "sample.zip"
        with zipfile.ZipFile(path, "w") as z:
            for name in names:
                z.writestr(name, b"data")
        return path

    def make_tar(self, names):
        path = self.root / "sample.tar.gz"
        with tarfile.open(path, "w:gz") as t:
            for name in names:
                info = tarfile.TarInfo(name)
                info.size = 4
                t.addfile(info, io.BytesIO(b"data"))
        return path

    def test_valid_zip(self):
        self.assertEqual(module.inspect_archive_policy(self.make_zip(["erp.sh"]))["file_count"], 1)

    def test_valid_tar(self):
        self.assertEqual(module.inspect_archive_policy(self.make_tar(["erp.sh"]))["file_count"], 1)

    def test_case_collision_zip(self):
        with self.assertRaisesRegex(module.ArtifactError, "case-colliding"):
            module.inspect_archive_policy(self.make_zip(["Config/a", "config/A"]))

    def test_case_collision_tar(self):
        with self.assertRaisesRegex(module.ArtifactError, "case-colliding"):
            module.inspect_archive_policy(self.make_tar(["A", "a"]))

    def test_parent_file_conflict(self):
        with self.assertRaisesRegex(module.ArtifactError, "conflicts"):
            module.inspect_archive_policy(self.make_zip(["config", "config/app.properties"]))

    def test_traversal_rejected(self):
        with self.assertRaises(module.ArtifactError):
            module.inspect_archive_policy(self.make_zip(["../escape"]))

    def test_missing_archive(self):
        with self.assertRaises(module.ArtifactError):
            module.inspect_archive_policy(self.root / "missing.zip")

    def test_symlink_tar(self):
        path = self.root / "sample.tar.gz"
        with tarfile.open(path, "w:gz") as t:
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "target"
            t.addfile(info)
        with self.assertRaisesRegex(module.ArtifactError, "special"):
            module.inspect_archive_policy(path)


if __name__ == "__main__":
    unittest.main()

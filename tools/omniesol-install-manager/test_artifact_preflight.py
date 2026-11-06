"""Regression tests for the read-only archive validator."""
import importlib.util
import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "artifact_preflight", Path(__file__).with_name("artifact_preflight.py")
)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class ArtifactPreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def zip(self, names):
        path = self.root / "package.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in names:
                archive.writestr(name, data)
        return path

    def tar(self, names):
        path = self.root / "package.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for name, data in names:
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        return path

    def test_valid_zip_and_digest(self):
        result = module.inspect_archive(self.zip([("erp.sh", b"echo ok")]), ("erp.sh",))
        self.assertEqual(result["file_count"], 1)
        self.assertEqual(len(result["sha256"]), 64)

    def test_valid_tar(self):
        result = module.inspect_archive(self.tar([("pkg/erp.sh", b"echo ok")]))
        self.assertEqual(result["status"], "validated_metadata_only")

    def test_traversal_zip_rejected(self):
        with self.assertRaises(module.ArtifactError):
            module.inspect_archive(self.zip([("../escape", b"bad")]))

    def test_traversal_tar_rejected(self):
        with self.assertRaises(module.ArtifactError):
            module.inspect_archive(self.tar([("pkg/../../escape", b"bad")]))

    def test_missing_required_file(self):
        with self.assertRaisesRegex(module.ArtifactError, "Missing required"):
            module.inspect_archive(self.zip([("other", b"x")]), ("erp.sh",))

    def test_duplicate_member_rejected(self):
        with self.assertWarns(UserWarning):
            path = self.zip([("same", b"a"), ("same", b"b")])
        with self.assertRaisesRegex(module.ArtifactError, "Duplicate"):
            module.inspect_archive(path)

    def test_bomb_ratio_rejected(self):
        with self.assertRaisesRegex(module.ArtifactError, "compression ratio"):
            module.inspect_archive(self.zip([("large", b"0" * 100000)]))

    def test_manifest_no_overwrite(self):
        manifest = module.inspect_archive(self.zip([("ok", b"test")]))
        output = self.root / "manifest.json"
        module.save_manifest(manifest, output)
        with self.assertRaises(module.ArtifactError):
            module.save_manifest(manifest, output)

    def test_symlink_tar_rejected(self):
        path = self.root / "package.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            entry = tarfile.TarInfo("link")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "target"
            archive.addfile(entry)
        with self.assertRaisesRegex(module.ArtifactError, "special"):
            module.inspect_archive(path)


if __name__ == "__main__":
    unittest.main()

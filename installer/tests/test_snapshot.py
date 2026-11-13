import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from snapshot import package_snapshot, SnapshotError

class SnapshotTests(unittest.TestCase):
    def test_source_changes_do_not_change_snapshot(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "input.zip"
            source.write_bytes(b"original")
            with package_snapshot(source) as snapshot:
                source.write_bytes(b"changed")
                self.assertEqual(snapshot.read_bytes(), b"original")
            self.assertFalse(snapshot.exists())

    def test_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "source"
            source.write_bytes(b"content")
            link = Path(d) / "link"
            link.symlink_to(source)
            with self.assertRaises(SnapshotError):
                with package_snapshot(link):
                    pass

if __name__ == "__main__":
    unittest.main()

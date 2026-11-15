"""Regression checks for no-clobber artifact publication."""
import unittest
from installer.atomic_staging import publish_command

P = "/home/douzone/omniesol-staging/payload.partial"
C = "/home/douzone/omniesol-staging/payload.zip"
H = "a" * 64

class AtomicNoClobberTests(unittest.TestCase):
    def test_uses_atomic_link_not_rename(self):
        cmd = publish_command(P, C, H)
        self.assertIn("ln --", cmd)
        self.assertNotIn("mv -n", cmd)
        self.assertIn("test ! -L", cmd)
        self.assertIn("exit 75", cmd)

    def test_rejects_untrusted_paths(self):
        for path in ("../../etc/passwd", "/tmp/payload.partial", "/home/douzone/omniesol-staging/../bad.partial"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                publish_command(path, C, H)

    def test_rejects_invalid_digest(self):
        with self.assertRaises(ValueError):
            publish_command(P, C, "not-a-digest")

if __name__ == "__main__":
    unittest.main()

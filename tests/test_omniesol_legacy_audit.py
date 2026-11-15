"""Read-only legacy bundle audit regression tests."""
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from installer.legacy_audit import (
    audit_legacy_bundle, BundleAuditError, REQUIRED, PRODUCTION_DEPENDENCIES,
)


def make_bundle(path, script=b'#!/bin/bash\nprintf ready\n', omit=()):
    members = {name: b'x' for name in REQUIRED + PRODUCTION_DEPENDENCIES if name != 'erp.sh' and name not in omit}
    if 'erp.sh' not in omit:
        members['erp.sh'] = script
    with tarfile.open(path, 'w:gz') as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


class LegacyAuditTests(unittest.TestCase):
    def test_complete_bundle_requires_manual_review(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'installer.tar.gz'
            make_bundle(path)
            report = audit_legacy_bundle(path)
            self.assertEqual(report['status'], 'REVIEW_REQUIRED')
            self.assertFalse(report['execution_allowed'])
            self.assertEqual(report['finding_count'], 0)

    def test_missing_production_files_blocks(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'installer.tar.gz'
            make_bundle(path, omit=PRODUCTION_DEPENDENCIES)
            report = audit_legacy_bundle(path)
            self.assertEqual(report['status'], 'BLOCKED')
            self.assertEqual(sum(f['code'] == 'PRODUCTION_ASSET_MISSING' for f in report['findings']), 3)

    def test_password_leaks_are_blocked_without_exposing_value(self):
        script = (
            b'#!/bin/bash\nDBPASSWORD=EXAMPLE-NOT-A-REAL-SECRET\n'
            b'DBPASSWORD=$DBPASSWORD\n'
            b'echo "DB PASSWORD value: $DBPASSWORD"\n'
            b'source "$SCRIPT_DIR/inventory.ini"\n'
        )
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'installer.tar.gz'
            make_bundle(path, script=script)
            report = audit_legacy_bundle(path)
            codes = {f['code'] for f in report['findings']}
            self.assertTrue({'PLAINTEXT_PASSWORD', 'PASSWORD_ECHO', 'EXECUTABLE_INVENTORY'} <= codes)
            self.assertNotIn('EXAMPLE-NOT-A-REAL-SECRET', str(report))

    def test_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'bad.tar.gz'
            with tarfile.open(path, 'w:gz') as tar:
                info = tarfile.TarInfo('../bad.txt')
                info.size = 1
                tar.addfile(info, io.BytesIO(b'X'))
            with self.assertRaises(BundleAuditError):
                audit_legacy_bundle(path)

    def test_corrupt_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'bad.tar.gz'
            path.write_text('not gzip')
            with self.assertRaises(BundleAuditError):
                audit_legacy_bundle(path)


if __name__ == '__main__':
    unittest.main()

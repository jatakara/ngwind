"""Regression checks for read-only SSH evidence (no real SSH)."""
import unittest
from types import SimpleNamespace
from installer.live_evidence import collect, parse_output, verify_record, EvidenceError, REMOTE_READ_ONLY

RAW = ('HOSTNAME=erp-poc\nOS_ID=rhel\nOS_VERSION=9.8\nKERNEL=5.14.0\nCPU=8\n'
       'MEM_KB=67108864\nROOT_FS=/dev/sda2 xfs /\nTIME_SYNC=yes\n')
MANIFEST = {'servers': [{'id':'ap1','ip':'192.0.2.10','hostname':'erp-poc','vcpu':8,'ram_gb':64}]}


class EvidenceTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_output(RAW)['CPU'], '8')

    def test_unknown_field(self):
        with self.assertRaises(EvidenceError):
            parse_output(RAW + 'PASSWORD=secret\n')

    def test_duplicate(self):
        with self.assertRaises(EvidenceError):
            parse_output(RAW + 'CPU=9\n')

    def test_target_mismatch_no_ssh(self):
        with self.assertRaises(EvidenceError):
            collect(MANIFEST, 'ap1', SimpleNamespace(host='192.0.2.11'),
                    lambda *a, **k: self.fail('unexpected SSH'))

    def test_fixed_read_only_command(self):
        def ssh(target, command, timeout):
            self.assertEqual(command, REMOTE_READ_ONLY)
            self.assertEqual(timeout, 45)
            return RAW
        record = collect(MANIFEST, 'ap1', SimpleNamespace(host='192.0.2.10'), ssh)
        self.assertEqual(record['g2_status'], 'PARTIAL')
        self.assertEqual(record['installation_gate'], 'HOLD')
        self.assertTrue(verify_record(MANIFEST, record))

    def test_inventory_change_invalidates(self):
        record = collect(MANIFEST, 'ap1', SimpleNamespace(host='192.0.2.10'), lambda *a, **k: RAW)
        changed = {'servers': [{**MANIFEST['servers'][0], 'ram_gb':128}]}
        self.assertFalse(verify_record(changed, record))

    def test_command_change_invalidates(self):
        record = collect(MANIFEST, 'ap1', SimpleNamespace(host='192.0.2.10'), lambda *a, **k: RAW)
        record['command_sha256'] = '0' * 64
        self.assertFalse(verify_record(MANIFEST, record))

    def test_ntp_failure_holds(self):
        record = collect(MANIFEST, 'ap1', SimpleNamespace(host='192.0.2.10'),
                         lambda *a, **k: RAW.replace('TIME_SYNC=yes', 'TIME_SYNC=no'))
        self.assertEqual(record['g2_status'], 'FAILED')
        self.assertEqual(record['installation_gate'], 'HOLD')

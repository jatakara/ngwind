import unittest
from installer.atomic_staging import publish_command, cleanup_command, checksum_command

class AtomicStagingTests(unittest.TestCase):
    def test_publish_verifies_and_refuses_conflicts(self):
        p='/home/douzone/omniesol-staging/.omniesol-abc.partial'
        c='/home/douzone/omniesol-staging/erp.zip'
        command=publish_command(p,c,'a'*64)
        self.assertIn('exit 73',command)
        self.assertIn('mv -n',command)
        self.assertIn('sha256sum',command)
    def test_invalid_path_and_digest(self):
        with self.assertRaises(ValueError):
            cleanup_command('/tmp/../../etc/passwd')
        with self.assertRaises(ValueError):
            publish_command('/home/douzone/omniesol-staging/x.partial','/home/douzone/omniesol-staging/x.zip','bad')
    def test_checksum(self):
        self.assertIn('sha256sum',checksum_command('/home/douzone/omniesol-staging/x.partial'))

if __name__=='__main__':
    unittest.main()

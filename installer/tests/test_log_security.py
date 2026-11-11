import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
from log_security import redact

class LogSecurityTests(unittest.TestCase):
    def test_password_assignment(self):
        self.assertNotIn('hunter2', redact('password=hunter2'))
    def test_redis(self):
        self.assertNotIn('secret123', redact('requirepass secret123'))
    def test_bearer(self):
        self.assertNotIn('abc123', redact('Authorization: Bearer abc123'))
    def test_url(self):
        self.assertNotIn('mypassword', redact('https://admin:mypassword@example.org'))
    def test_private_key(self):
        self.assertNotIn('sensitive', redact('-----BEGIN PRIVATE KEY-----\nsensitive\n-----END PRIVATE KEY-----'))
    def test_nonsecret(self):
        self.assertEqual('SSH connected', redact('SSH connected'))

if __name__ == '__main__':
    unittest.main()

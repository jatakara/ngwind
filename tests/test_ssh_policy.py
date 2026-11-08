import tempfile
import unittest
from pathlib import Path
from omniesol_install_manager.ssh_policy import ssh_argv, validate_target


class TestSSHPolicy(unittest.TestCase):
    def test_target_valid(self):
        validate_target("192.0.2.10", 22, "douzone")
        validate_target("erp.example.com", 2222, "oracle")

    def test_reject_bad_targets(self):
        for host in ("-oProxyCommand=evil", "bad host", "x..y", "host;id", ""):
            with self.subTest(host=host), self.assertRaises(ValueError):
                validate_target(host, 22, "douzone")
        for port in (0, 65536, True, "22"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                validate_target("example.com", port, "douzone")
        with self.assertRaises(ValueError):
            validate_target("example.com", 22, "root;id")

    def test_strict_host_key_and_no_password(self):
        with tempfile.TemporaryDirectory() as d:
            key, hosts = Path(d)/"id_ed25519", Path(d)/"known_hosts"
            key.write_text("fixture")
            hosts.write_text("fixture")
            args = ssh_argv("192.0.2.10", 22, "douzone", str(key), str(hosts), "hostname")
            self.assertIn("StrictHostKeyChecking=yes", args)
            self.assertIn("PasswordAuthentication=no", args)
            self.assertIn("BatchMode=yes", args)
            self.assertEqual(args[-1], "hostname")
            with self.assertRaises(ValueError):
                ssh_argv("192.0.2.10", 22, "douzone", str(key), str(hosts), "rm -rf /")


if __name__ == "__main__":
    unittest.main()

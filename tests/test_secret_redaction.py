import unittest

from installer.security.secret_redaction import REDACTED, redact_data, redact_text


class RedactionTests(unittest.TestCase):
    def test_nested_secret_keys(self):
        source = {"db": {"password": "hunter2", "host": "db1"},
                  "entries": [{"requirepass": "abc"}, {"api_key": "xyz"}]}
        result = redact_data(source)
        self.assertEqual(result["db"]["password"], REDACTED)
        self.assertEqual(result["db"]["host"], "db1")
        self.assertEqual(result["entries"][0]["requirepass"], REDACTED)
        self.assertEqual(result["entries"][1]["api_key"], REDACTED)
        self.assertEqual(source["db"]["password"], "hunter2")

    def test_assignment(self):
        self.assertNotIn("hunter2", redact_text("Globals.Password=hunter2"))
        self.assertNotIn("hunter2", redact_text('requirepass "hunter2"'))

    def test_authorization(self):
        self.assertEqual(redact_text("Authorization: Bearer abc"), "Authorization: " + REDACTED)

    def test_url_credentials(self):
        self.assertNotIn("secret", redact_text("https://user:secret@example.org/path"))

    def test_pem_private_key(self):
        key = "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----"
        self.assertEqual(redact_text(key), REDACTED)

    def test_unknown_type_fails_closed(self):
        with self.assertRaises(TypeError):
            redact_data({"obj": object()})

    def test_depth_limit(self):
        with self.assertRaises(ValueError):
            redact_data({"a": {"b": {"c": 1}}}, max_depth=1)

    def test_preserve_non_sensitive(self):
        self.assertEqual(redact_data({"port": 8080, "enabled": True}),
                         {"port": 8080, "enabled": True})


if __name__ == "__main__":
    unittest.main()

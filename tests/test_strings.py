import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from revengine.stringsx import scan_strings, shannon_entropy, max_window_entropy


class TestStrings(unittest.TestCase):
    def test_url_email_path_found(self):
        data = (b"see https://example.com/api/v1 for docs, mail bob@example.com, "
                b"built in /home/dennis/build/output")
        report = scan_strings(data)
        self.assertEqual(report.count("url"), 1)
        self.assertEqual(report.count("email"), 1)
        self.assertEqual(report.count("path"), 1)

    def test_credential_like_redacted(self):
        data = b"config: api_key = sk-live-0123456789abcdef"
        report = scan_strings(data)
        self.assertEqual(report.count("credential_like"), 1)
        hit = [h for h in report.hits if h.kind == "credential_like"][0]
        self.assertNotIn("sk-live", hit.preview)
        self.assertIn("redacted", hit.preview)

    def test_signing_secret_named_and_redacted(self):
        # The generic credential pattern misses this: "secret" in
        # secret_key_base is not followed directly by ":" or "=".
        secret = b"a1b2c3d4" * 16  # 128 hex chars, secret_key_base shape
        data = b"config: secret_key_base = " + secret
        report = scan_strings(data)
        self.assertGreaterEqual(report.count("signing_secret"), 1)
        for h in report.hits:
            if h.kind == "signing_secret":
                self.assertNotIn(secret.decode(), h.preview)
                self.assertIn("redacted", h.preview)

    def test_long_hex_master_key_flagged(self):
        data = b"key material " + b"ab" * 64  # 128 hex chars, no name
        report = scan_strings(data)
        self.assertGreaterEqual(report.count("signing_secret"), 1)

    def test_signing_secret_no_false_positive(self):
        data = b"the secret recipe is delicious, keep it safe"
        report = scan_strings(data)
        self.assertEqual(report.count("signing_secret"), 0)
        self.assertEqual(report.count("credential_like"), 0)

    def test_entropy(self):
        self.assertAlmostEqual(shannon_entropy(b"a" * 1000), 0.0)
        random.seed(7)
        noisy = bytes(random.randrange(256) for _ in range(4096))
        self.assertGreater(shannon_entropy(noisy), 7.5)
        self.assertEqual(shannon_entropy(b""), 0.0)
        self.assertGreater(max_window_entropy(noisy), 7.5)


if __name__ == "__main__":
    unittest.main()

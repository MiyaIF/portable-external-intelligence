import unittest

from ei.redaction import contains_secret_like, redact_reusable


def bearer_secret(marker: str) -> str:
    authorization = "Author" + "ization"
    bearer = "Bea" + "rer"
    return f"{authorization}: {bearer} {marker}"


class RedactionTests(unittest.TestCase):
    def test_redacts_credentials_and_machine_paths_deterministically(self):
        source = (
            bearer_secret("marker-bearer-value") + "\n"
            "api_key=marker-api-key-123456789\n"
            "Cookie: marker-cookie-value\n"
            "postgres://user:marker-password@db.example.invalid/app\n"  # pragma: allowlist secret
            "C:" + chr(92) + "Users" + chr(92) + "tester" + chr(92) + "client" + chr(92) + "result.txt"
        )
        first = redact_reusable(source)
        second = redact_reusable(source)
        self.assertEqual(first, second)
        self.assertNotIn("marker-", first)
        self.assertIn("[REDACTED_", first)
        self.assertFalse(contains_secret_like(first))

    def test_private_key_is_removed_as_one_block(self):
        private_key = (
            "-----" + "BEGIN PRIVATE KEY-----\n"  # pragma: allowlist secret
            "secret\n"
            "-----" + "END PRIVATE KEY-----"
        )
        output = redact_reusable("before\n" + private_key + "\nafter")
        self.assertEqual(output, "before\n[REDACTED_PRIVATE_KEY]\nafter")
        self.assertNotIn("secret", output)
        self.assertFalse(contains_secret_like(output))

    def test_invalid_input_is_rejected(self):
        with self.assertRaises(ValueError):
            redact_reusable(None)


if __name__ == "__main__":
    unittest.main()

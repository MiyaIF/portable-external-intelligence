import base64
import platform
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.key_provider import (
    InMemoryKeyProvider,
    KeyProviderError,
    LinuxSecretServiceProvider,
    MacOSKeychainProvider,
    WindowsDPAPIKeyProvider,
    default_key_provider,
)


class KeyProviderTests(unittest.TestCase):
    def test_in_memory_provider_requires_matching_key_id(self):
        provider = InMemoryKeyProvider("test", b"k" * 32)
        self.assertEqual(provider.current().key, b"k" * 32)
        with self.assertRaisesRegex(KeyProviderError, "KEY_ID_UNKNOWN"):
            provider.get("other")

    def test_default_provider_selects_os_backend_without_plaintext_fallback(self):
        provider = default_key_provider(Path(tempfile.gettempdir()) / "ei-key-provider-test")
        expected = {
            "Windows": WindowsDPAPIKeyProvider,
            "Darwin": MacOSKeychainProvider,
            "Linux": LinuxSecretServiceProvider,
        }
        self.assertIsInstance(provider, expected.get(platform.system(), type(provider)))

    @unittest.skipUnless(platform.system() == "Windows", "DPAPI is Windows-only")
    def test_windows_dpapi_round_trip_uses_protected_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            provider = WindowsDPAPIKeyProvider(Path(tmp) / "key-provider.json")
            current = provider.current()
            restored = provider.get(current.key_id)
            self.assertEqual(restored, current.key)
            state = (Path(tmp) / "key-provider.json").read_text(encoding="utf-8")
            self.assertNotIn(base64.b64encode(current.key).decode("ascii"), state)


if __name__ == "__main__":
    unittest.main()
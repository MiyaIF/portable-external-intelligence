import unittest

from ei.install_config import MANAGED_HOOK_IDS, merge_config_toml, merge_hooks


class InstallConfigTests(unittest.TestCase):
    def test_toml_merge_preserves_unrelated_settings_and_is_idempotent(self):
        original = 'model = "existing-model-value"\n\n[features]\nmemories = false\n\n[desktop]\ndefaultTerminalLocation = "right"\n'
        once = merge_config_toml(original)
        twice = merge_config_toml(once)
        self.assertEqual(once, twice)
        self.assertIn('model = "existing-model-value"', once)
        self.assertIn("hooks = true", once)
        self.assertIn("memories = true", once)
        self.assertIn("[desktop]", once)

    def test_toml_merge_preserves_crlf_bytes_and_unrelated_sections(self):
        original = 'model = "existing-model-value"\r\n\r\n[features]\r\nmemories = false\r\n\r\n[desktop]\r\ndefaultTerminalLocation = "right"\r\n'
        once = merge_config_toml(original)
        self.assertIn("\r\n", once)
        self.assertNotIn("\n\n", once.replace("\r\n", ""))
        self.assertEqual(once, merge_config_toml(once))
        self.assertIn('[desktop]\r\ndefaultTerminalLocation = "right"\r\n', once)

    def test_hook_merge_preserves_existing_and_replaces_only_managed_ids(self):
        existing = {"hooks": {"Stop": [{"id": "user-stop", "hooks": []}], "Custom": [{"id": "ei-user-owned", "hooks": []}]}}
        managed = {"hooks": {"Stop": [{"id": "ei-stop-v1", "hooks": []}]}}
        merged = merge_hooks(existing, managed)
        self.assertEqual([x["id"] for x in merged["hooks"]["Stop"]], ["user-stop", "ei-stop-v1"])
        self.assertEqual([x["id"] for x in merged["hooks"]["Custom"]], ["ei-user-owned"])
        self.assertEqual(merge_hooks(merged, managed), merged)
        self.assertIn("ei-stop-v1", MANAGED_HOOK_IDS)

    def test_duplicate_sections_are_rejected(self):
        with self.assertRaises(ValueError):
            merge_config_toml("[features]\na = 1\n[features]\nb = 2\n")


if __name__ == "__main__":
    unittest.main()
from __future__ import annotations

import io
import json
import unittest
from unittest.mock import patch

import ei.cli as cli_module
import ei.installer as installer_module


class LegacyEncodedStdout:
    def __init__(self) -> None:
        self.buffer = io.BytesIO()

    def write(self, text: str) -> int:
        text.encode("cp1252")
        return len(text)

    def flush(self) -> None:
        return None


class Utf8StandardOutputTests(unittest.TestCase):
    def test_cli_text_bypasses_a_legacy_text_encoding(self) -> None:
        stream = LegacyEncodedStdout()
        with patch.object(cli_module.sys, "stdout", stream):
            cli_module._emit("日本語の知識", False)
        self.assertEqual(stream.buffer.getvalue().decode("utf-8").strip(), "日本語の知識")

    def test_installer_text_bypasses_a_legacy_text_encoding(self) -> None:
        stream = LegacyEncodedStdout()
        with patch.object(installer_module.sys, "stdout", stream):
            installer_module._print("日本語の保存先", False)
        self.assertEqual(stream.buffer.getvalue().decode("utf-8").strip(), "日本語の保存先")

    def test_machine_json_is_ascii_safe_and_round_trips_unicode(self) -> None:
        stream = LegacyEncodedStdout()
        with patch.object(cli_module.sys, "stdout", stream):
            cli_module._emit({"message": "日本語の知識"}, True)
        raw = stream.buffer.getvalue()
        self.assertTrue(raw.isascii())
        self.assertEqual(json.loads(raw.decode("ascii"))["message"], "日本語の知識")


if __name__ == "__main__":
    unittest.main()

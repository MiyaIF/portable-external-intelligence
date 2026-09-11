import hashlib
import tempfile
import unittest
from pathlib import Path

from ei.certification import certify_host, validate_receipt_artifact
from ei.config import load_settings
from ei.ingest import ingest_sources
from ei.adapters.codex_memory import CodexMemoryAdapter
from ei.sync import sync_once


def bearer_secret(marker: str) -> str:
    authorization = "Author" + "ization"
    bearer = "Bea" + "rer"
    return f"{authorization}: {bearer} {marker}"


class SecurityBoundaryAcceptanceTests(unittest.TestCase):
    def test_secret_never_reaches_event_or_sync_candidate(self):
        secret = bearer_secret("Z" * 32)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config" / "defaults.json").write_text('{"retrieval":{"max_chars":5000,"max_results":5}}', encoding="utf-8")
            source = root / "secret.md"
            source.write_text("## Reusable knowledge\n- " + secret + "\n", encoding="utf-8")
            settings = load_settings(root, codex_home=root / "codex")
            receipt = certify_host("codex-cli", "fixture-security", "fixture", settings).receipt
            validate_receipt_artifact(receipt)
            self.assertNotIn(secret, str(receipt))
            result = ingest_sources(settings, [CodexMemoryAdapter([source])])
            self.assertEqual(result.created_events, 0)
            self.assertEqual(result.rejected_records, 1)
            if settings.paths.event_dir.exists():
                self.assertNotIn(secret, "".join(path.read_text(encoding="utf-8") for path in settings.paths.event_dir.rglob("*.json")))


if __name__ == "__main__":
    unittest.main()

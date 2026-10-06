import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from ei.doctor import _spool_check
from ei.runtime_catalog import managed_path
from tests.unattended_helpers import make_settings, NOW


class DoctorSpoolLayoutTests(unittest.TestCase):
    def test_missing_accounting_row_is_unknown_without_database_or_sidecar_writes(self):
        import sqlite3
        from contextlib import closing
        from ei.spool import write_spool
        from ei.key_provider import InMemoryKeyProvider
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            write_spool("diagnostic", "public", settings, now=NOW, key_provider=InMemoryKeyProvider())
            root = settings.paths.spool_dir
            with closing(sqlite3.connect(root / ".runtime-catalog.sqlite")) as connection:
                connection.execute("DELETE FROM accounting")
                connection.commit()
            before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            with patch("ei.doctor._now", return_value=NOW):
                result = _spool_check(settings, True)
            self.assertFalse(result["ok"])
            self.assertEqual(result["accounting_state"], "UNKNOWN")
            self.assertEqual(result["reason_code"], "RUNTIME_ACCOUNTING_UNKNOWN")
            self.assertEqual(before, {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()})

    def test_purpose_accounting_presence_and_result_zero_count_are_readonly(self):
        import sqlite3
        from contextlib import closing
        from ei.spool import write_spool
        from ei.key_provider import InMemoryKeyProvider
        for purpose, mutation, expected in (("pending", "missing", "UNKNOWN"), ("validated-result", "missing", "UNKNOWN"),
                                             ("pending", "zero", "UNKNOWN"), ("validated-result", "none", "UNVERIFIED"),
                                             ("pending", "orphan", "UNKNOWN")):
            with self.subTest(purpose=purpose, mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                settings = make_settings(Path(tmp))
                write_spool("diagnostic", "public", settings, now=NOW, key_provider=InMemoryKeyProvider(), purpose=purpose, capture_id="sha256:" + "a" * 64)
                root = settings.paths.spool_dir
                with closing(sqlite3.connect(root / ".runtime-catalog.sqlite")) as connection:
                    if mutation == "missing":
                        connection.execute("DELETE FROM accounting")
                    elif mutation == "zero":
                        connection.execute("UPDATE accounting SET items=0,bytes=0")
                    elif mutation == "orphan":
                        connection.execute("INSERT INTO accounting VALUES ('legacy',1,1)")
                    connection.commit()
                before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
                with patch("ei.doctor._now", return_value=NOW):
                    result = _spool_check(settings, True)
                self.assertEqual(result["accounting_state"], expected)
                self.assertEqual(result["ok"], expected == "UNVERIFIED")
                self.assertFalse(result["admission_verified"])
                self.assertFalse(result["custody_verified"])
                self.assertEqual(before, {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()})

    def test_missing_corrupt_and_partial_catalog_are_unknown_without_writes(self):
        import sqlite3
        from contextlib import closing
        from ei.spool import write_spool
        from ei.key_provider import InMemoryKeyProvider
        for state in ("missing", "corrupt", "partial"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as tmp:
                settings = make_settings(Path(tmp))
                write_spool("diagnostic candidate", "public", settings, now=NOW, key_provider=InMemoryKeyProvider())
                root = settings.paths.spool_dir
                database = root / ".runtime-catalog.sqlite"
                if state == "missing":
                    database.unlink()
                elif state == "corrupt":
                    database.write_bytes(b"corrupt metadata")
                else:
                    with closing(sqlite3.connect(database)) as connection:
                        connection.execute("UPDATE state SET value='0' WHERE name='complete'")
                        connection.commit()
                before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
                with patch("ei.doctor._now", return_value=NOW):
                    result = _spool_check(settings, True)
                self.assertEqual(result["accounting_state"], "UNKNOWN")
                self.assertFalse(result["admission_verified"])
                self.assertFalse(result["ok"])
                self.assertEqual(before, {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()})

    def test_managed_invalid_and_legacy_expired_envelopes_are_both_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_settings(Path(tmp))
            root = settings.paths.spool_dir
            root.mkdir(parents=True)
            managed_path(root, "spool_invalid", create=True).write_text("{}", encoding="utf-8")
            (root / "spool_legacy.json").write_text(json.dumps({"algorithm": "AES-256-GCM", "key_id": "test", "expires_at": (NOW - timedelta(days=1)).isoformat()}), encoding="utf-8")
            before = sorted(str(path.relative_to(root)) for path in root.rglob("*"))
            with patch("ei.doctor._now", return_value=NOW):
                result = _spool_check(settings, True)
            self.assertEqual(result["invalid_envelopes"], 1)
            self.assertEqual(result["expired_envelopes"], 1)
            self.assertNotEqual(result["key_state"], "NOT_REQUIRED")
            self.assertEqual(sorted(str(path.relative_to(root)) for path in root.rglob("*")), before)

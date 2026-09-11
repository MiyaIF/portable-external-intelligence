import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from ei.metrics import read_deduplicated_usage
from tests.fixtures.sqlite.create_usage_fixture import create_known_db, create_unknown_db


class SQLiteUsageAdapterTests(unittest.TestCase):
    def test_known_and_unknown_schema_are_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            known = root / "known.sqlite"
            unknown = root / "unknown.sqlite"
            create_known_db(known)
            create_unknown_db(unknown)
            known_before = hashlib.sha256(known.read_bytes()).hexdigest()
            unknown_before = hashlib.sha256(unknown.read_bytes()).hexdigest()
            known_result = read_deduplicated_usage(known)
            unknown_result = read_deduplicated_usage(unknown)
            self.assertEqual(known_result.status, "OK")
            self.assertEqual(len(known_result.rows), 2)
            self.assertEqual(unknown_result.status, "SQLITE_SCHEMA_UNSUPPORTED")
            self.assertEqual(known_before, hashlib.sha256(known.read_bytes()).hexdigest())
            self.assertEqual(unknown_before, hashlib.sha256(unknown.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()

import re
import unittest
from datetime import datetime, timedelta, timezone

from ei.ids import fingerprint, new_event_id


class IdTests(unittest.TestCase):
    def test_event_id_is_sortable_and_has_fixed_segments(self):
        value = new_event_id(
            datetime(2026, 8, 25, 9, 0, 0, 123456, tzinfo=timezone(timedelta(hours=9))),
            "machine-a",
        )
        self.assertRegex(
            value,
            r"^evt_20260825T000000123456Z_[0-9a-f]{12}$",
        )

    def test_event_ids_are_monotonic_for_the_same_timestamp_and_machine(self):
        now = datetime(2026, 8, 25, 0, 0, 0, 123456, tzinfo=timezone.utc)
        try:
            first = new_event_id(now, "machine-a")
            second = new_event_id(now, "machine-a")
        except TypeError as exc:
            self.fail(f"new_event_id must accept machine_id: {exc}")
        self.assertLess(first, second)

        with self.assertRaisesRegex(ValueError, "EVENT_TIMEZONE_REQUIRED"):
            new_event_id(datetime(2026, 8, 25), "machine-a")

    def test_fingerprint_is_stable_and_redacts_payload(self):
        first = fingerprint("same content")
        second = fingerprint("same content")
        self.assertEqual(first, second)
        self.assertRegex(first, r"^sha256:[0-9a-f]{64}$")
        self.assertNotIn("same content", first)

    def test_canonical_json_orders_keys_preserves_utf8_and_hashes_content(self):
        from ei import ids

        first = {"z": "\u96ea", "a": {"b": 2, "a": 1}}
        second = {"a": {"a": 1, "b": 2}, "z": "\u96ea"}
        expected = b'{"a":{"a":1,"b":2},"z":"\xe9\x9b\xaa"}'
        try:
            self.assertEqual(ids.canonical_json(first), expected)
        except AttributeError as exc:
            self.fail(f"canonical_json is required: {exc}")
        self.assertEqual(ids.canonical_json(second), expected)
        self.assertEqual(fingerprint(first), fingerprint(second))


if __name__ == "__main__":
    unittest.main()


import tempfile
import unittest
from pathlib import Path

from ei.capture import record_agent_observation, select_capture_path
from ei.journal import iter_events
from ei.models import CaptureContext, ObservationInput
from tests.helpers import make_hook_settings


class CaptureTests(unittest.TestCase):
    def test_same_turn_and_claim_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_hook_settings(Path(tmp))
            observation = ObservationInput("書込後の再読込", "外部書込後は対象範囲を再読込して数式と値を検証する", "agent_direct", "session-local", "C:/work/project-a", "spreadsheet-operations", "success", "avoided_failure", "private-reusable", source_host_id="codex-cli", source_host_family="codex-compatible")
            context = CaptureContext(session_id="s1", turn_id="t9", capture_index=1, source_host_id="codex-cli", source_host_family="codex-compatible")
            first = record_agent_observation(observation, context, settings)
            second = record_agent_observation(observation, context, settings)
            self.assertTrue(first.created)
            self.assertFalse(second.created)
            self.assertEqual(second.reason_code, "IDEMPOTENT_REPLAY")
            self.assertEqual(len(list(iter_events(settings.paths.event_dir))), 1)

    def test_host_capture_order_is_respected_and_unknown_is_not_no(self):
        class Host:
            capture_order = ("HOOK_DIRECT", "AGENT_SKILL", "NATIVE_SOURCE")

        self.assertEqual(select_capture_path(Host(), {"NATIVE_SOURCE": True, "HOOK_DIRECT": True}), "HOOK_DIRECT")
        self.assertEqual(select_capture_path(Host(), {"AGENT_SKILL": True}), "AGENT_SKILL")
        self.assertEqual(select_capture_path(Host(), {}), "capture_coverage_unknown")
    def test_fourth_observation_hits_session_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_hook_settings(Path(tmp))
            for index in range(1, 5):
                observation = ObservationInput(f"title-{index}", "これは20文字以上の再利用可能な検証済み判断知識です", "agent_direct", "session-local", "C:/work", "general", "success", "reduced_rework", "private-reusable", source_host_id="codex-cli", source_host_family="codex-compatible")
                result = record_agent_observation(observation, CaptureContext("s1", f"t{index}", min(index, 3), "codex-cli", "codex-compatible"), settings)
                if index == 4:
                    self.assertFalse(result.created)
                    self.assertEqual(result.reason_code, "SESSION_CAPTURE_LIMIT")
            self.assertEqual(len(list(iter_events(settings.paths.event_dir))), 3)


if __name__ == "__main__":
    unittest.main()

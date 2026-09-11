import tempfile
import unittest
from pathlib import Path

from ei.config import RuntimePaths, Settings
from ei.key_provider import InMemoryKeyProvider
from ei.team_store import initialize_team_store, load_or_create_writer_identity
from ei.team_routing import route_applied_personal_knowledge


class EligibleProvider:
    provider_id = "eligible"
    locality = "local"

    def available(self):
        return True

    def generate(self, schema_name, input_json, budget):
        from ei.inference.base import ProviderResult
        return ProviderResult(self.provider_id, "success", output={
            "title": input_json["title"],
            "claim": input_json["claim"],
            "scope": ["general"],
            "preconditions": ["同じ構造が再発している"],
            "failure_modes": ["再確認を省略する"],
            "benefit": "reduced_rework",
            "classification": "private-reusable",
        })


def settings_for(root: Path, team_root: Path) -> Settings:
    paths = RuntimePaths(engine_root=root / "engine", personal_knowledge_root=root / "personal", team_knowledge_root=team_root, runtime_root=root / "runtime")
    return Settings(paths=paths)


class TeamCloseoutIntegrationTests(unittest.TestCase):
    def test_offline_team_defers_once_after_personal_apply(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            team_root = root / "shared-team"
            descriptor = initialize_team_store(team_root)
            writer_id = load_or_create_writer_identity(root / "runtime", descriptor.store_id, random_id=lambda: "c" * 16)
            settings = settings_for(root, team_root)
            applied = {
                "status": "applied",
                "changeset_hash": "sha256:" + "3" * 64,
                "event_ids": ["evt_personal_1"],
                "team_member_id": "member-a",
                "candidate": {
                    "title": "再利用できる検証手順",
                    "claim": "外部書込後は対象範囲を再読込して数式と値を検証する",
                    "benefit": "reduced_rework",
                    "classification": "private-reusable",
                },
            }
            team_root.rename(root / "offline-team")
            key_provider = InMemoryKeyProvider("team-closeout-test-key", b"t" * 32)
            try:
                first = route_applied_personal_knowledge(applied, settings, provider=EligibleProvider(), writer_id=writer_id, key_provider=key_provider)
            except TypeError as exc:
                if "unexpected keyword argument 'key_provider'" in str(exc):
                    self.fail("team closeout must allow an explicit test key provider")
                raise
            second = route_applied_personal_knowledge(applied, settings, provider=EligibleProvider(), writer_id=writer_id, key_provider=key_provider)
            self.assertEqual(first.status, "DEFERRED")
            self.assertEqual(second.status, "DEFERRED")


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path

from ei.inference.base import InferenceBudget, ProviderResult
from ei.team_routing import TeamRoutingDecision, decide_team_routing, route_applied_personal_knowledge


def candidate(*, classification: str = "private-reusable") -> dict[str, object]:
    return {
        "title": "再利用できる検証手順",
        "claim": "外部書込後は対象範囲を再読込して数式と値を検証する",
        "scope": ["spreadsheet-operations"],
        "preconditions": ["外部書込が完了している"],
        "failure_modes": ["古い表示を正しい結果と誤認する"],
        "benefit": "reduced_rework",
        "classification": classification,
        "source_hash": "sha256:" + "1" * 64,
        "evidence_refs": ["sha256:" + "2" * 64],
    }


def team_store(root: Path | None = None) -> dict[str, object]:
    return {
        "enabled": True,
        "root": str(root or Path("team")),
        "store_id": "team_" + "a" * 16,
        "team_member_id": "member-a",
        "writer_id": "writer_" + "b" * 16,
    }


class SpyProvider:
    provider_id = "spy"
    locality = "local"

    def __init__(self, output: dict[str, object] | None = None, *, status: str = "success") -> None:
        self.calls: list[tuple[str, dict[str, object], InferenceBudget]] = []
        self.output = output or {
            "title": candidate()["title"],
            "claim": candidate()["claim"],
            "scope": candidate()["scope"],
            "preconditions": candidate()["preconditions"],
            "failure_modes": candidate()["failure_modes"],
            "benefit": candidate()["benefit"],
            "classification": candidate()["classification"],
        }
        self.status = status

    def available(self) -> bool:
        return True

    def generate(self, schema_name, input_json, budget):
        self.calls.append((schema_name, dict(input_json), budget))
        return ProviderResult(self.provider_id, self.status, output=self.output if self.status == "success" else None, error_code=None if self.status == "success" else "PROVIDER_UNAVAILABLE")


def budget() -> InferenceBudget:
    return InferenceBudget(candidate_id="cand-team", purpose="team-routing", deadline_ms=1000)


class TeamRoutingTests(unittest.TestCase):
    def test_team_routing_rejects_local_classifications_without_provider(self) -> None:
        provider = SpyProvider()
        for classification in ("client-confidential", "machine-local", "secret"):
            with self.subTest(classification=classification):
                decision = decide_team_routing(candidate(classification=classification), team_store(), provider, budget())
                self.assertEqual(decision.status, "NOT_ELIGIBLE")
                self.assertIsNone(decision.normalized_payload)
        self.assertEqual(provider.calls, [])

    def test_eligible_route_validates_provider_payload_and_returns_event_material(self) -> None:
        provider = SpyProvider()
        decision = decide_team_routing(candidate(), team_store(), provider, budget())
        self.assertIsInstance(decision, TeamRoutingDecision)
        self.assertEqual(decision.status, "ELIGIBLE")
        self.assertIsNotNone(decision.normalized_payload)
        self.assertEqual(provider.calls[0][0], "team-routing-decision")
        self.assertNotIn("source_hash", provider.calls[0][1])

    def test_provider_failure_is_deferred_without_personal_failure(self) -> None:
        provider = SpyProvider(status="failed")
        decision = decide_team_routing(candidate(), team_store(), provider, budget())
        self.assertEqual(decision.status, "FAILED")
        self.assertIsNone(decision.normalized_payload)


if __name__ == "__main__":
    unittest.main()

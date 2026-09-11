from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from ei.knowledge_repository import bootstrap_knowledge_repository
from ei.knowledge_setup import (
    SETUP_STAGES,
    KnowledgeSetupSelection,
    apply_knowledge_setup,
    load_operation_receipt,
    normalize_github_repository,
    operation_receipt_path,
    plan_knowledge_setup,
)


class KnowledgeSetupPlanTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows junction fixture is platform-specific")
    def test_receipt_loader_rejects_runtime_junction_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            outside = base / "outside"
            outside.mkdir()
            runtime = base / "runtime"
            created = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(runtime), str(outside)],
                capture_output=True,
                text=True,
                check=False,
            )
            if created.returncode != 0 or not runtime.exists():
                self.skipTest("junction fixture unavailable")
            receipt = outside / "receipt.json"
            receipt.write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "KNOWLEDGE_OPERATION_RECEIPT_OUTSIDE_RUNTIME"):
                load_operation_receipt(receipt, runtime_root=runtime)

    def test_local_plan_is_deterministic_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            selection = KnowledgeSetupSelection(
                mode="local",
                engine_root=root / "engine",
                knowledge_root=root / "knowledge 日本語",
                runtime_root=root / "runtime 日本語",
                github_repository=None,
                github_executable="gh",
                remote_name="origin",
                branch="main",
                sync_enabled=False,
                confirm_github_create=None,
            )

            first = plan_knowledge_setup(selection)
            second = plan_knowledge_setup(selection)

            self.assertEqual(first.plan_digest, second.plan_digest)
            self.assertRegex(first.plan_digest, r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(first.actions[0].kind, "initialize-local")
            self.assertFalse(selection.knowledge_root.exists())
            self.assertFalse(selection.runtime_root.exists())

    def test_existing_valid_local_repository_is_reused_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = root / "engine"
            knowledge = root / "knowledge"
            runtime = root / "runtime"
            engine.mkdir()
            bootstrap_knowledge_repository(
                knowledge,
                engine_root=engine,
                runtime_root=runtime,
                initialize_git=True,
            )
            before = sorted(path.relative_to(knowledge) for path in knowledge.rglob("*"))

            plan = plan_knowledge_setup(
                KnowledgeSetupSelection(
                    mode="local",
                    engine_root=engine,
                    knowledge_root=knowledge,
                    runtime_root=runtime,
                )
            )

            after = sorted(path.relative_to(knowledge) for path in knowledge.rglob("*"))
            self.assertEqual([action.kind for action in plan.actions], ["reuse-local"])
            self.assertEqual(before, after)

    def test_github_new_plan_contains_only_declared_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = plan_knowledge_setup(
                KnowledgeSetupSelection(
                    mode="github-new",
                    engine_root=root / "engine",
                    knowledge_root=root / "knowledge",
                    runtime_root=root / "runtime",
                    github_repository="MiyaIF/knowledge",
                    sync_enabled=True,
                    confirm_github_create="MiyaIF/knowledge",
                )
            )

            self.assertEqual(plan.selection.github_repository, "MiyaIF/knowledge")
            self.assertRegex(plan.remote_fingerprint or "", r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(
                [action.kind for action in plan.actions],
                [
                    "initialize-local",
                    "create-private-github",
                    "verify-private-remote",
                    "connect-remote",
                    "push-and-verify",
                ],
            )
            self.assertTrue(all(action.mutates for action in plan.actions if action.kind != "verify-private-remote"))
            self.assertFalse(next(action for action in plan.actions if action.kind == "verify-private-remote").mutates)

    def test_github_slug_rejects_url_and_option_injection(self) -> None:
        self.assertEqual(normalize_github_repository("MiyaIF/knowledge"), "MiyaIF/knowledge")
        for value in (
            "--private",
            "https://github.com/a/b",
            "git@github.com:a/b.git",
            "a/b/c",
            "a b/c",
            "a/-repository",
            "a/..",
            "a/b\n--private",
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "^GITHUB_REPOSITORY_INVALID$"):
                    normalize_github_repository(value)

    def test_invalid_modes_options_and_root_overlap_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            valid = {
                "mode": "local",
                "engine_root": root / "engine",
                "knowledge_root": root / "knowledge",
                "runtime_root": root / "runtime",
            }
            cases = (
                ({**valid, "mode": "remote"}, "KNOWLEDGE_MODE_INVALID"),
                ({**valid, "remote_name": "--upload-pack=x"}, "GIT_REMOTE_NAME_INVALID"),
                ({**valid, "branch": "main:evil"}, "GIT_BRANCH_INVALID"),
                ({**valid, "sync_enabled": True}, "LOCAL_SYNC_FORBIDDEN"),
                ({**valid, "github_repository": "a/b"}, "LOCAL_GITHUB_REPOSITORY_FORBIDDEN"),
                (
                    {
                        **valid,
                        "knowledge_root": root / "engine" / "knowledge",
                    },
                    "KNOWLEDGE_ROOT_OVERLAPS_ENGINE_ROOT",
                ),
                (
                    {
                        **valid,
                        "runtime_root": root / "knowledge" / "runtime",
                    },
                    "KNOWLEDGE_ROOT_OVERLAPS_RUNTIME_ROOT",
                ),
            )
            for values, error_code in cases:
                with self.subTest(error_code=error_code):
                    with self.assertRaisesRegex(ValueError, f"^{error_code}$"):
                        plan_knowledge_setup(KnowledgeSetupSelection(**values))

    def test_stage_contract_is_closed_and_ordered(self) -> None:
        self.assertEqual(
            SETUP_STAGES,
            (
                "PLANNED",
                "KNOWLEDGE_LOCAL_READY",
                "REMOTE_CREATED_OR_VERIFIED",
                "REMOTE_CONNECTED",
                "INITIAL_PUSH_VERIFIED",
                "HOSTS_INSTALLED",
                "MANIFEST_COMMITTED",
                "DIAGNOSTICS_COMPLETE",
            ),
        )

    def test_operation_receipt_path_is_bound_to_runtime_and_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = plan_knowledge_setup(
                KnowledgeSetupSelection(
                    mode="local",
                    engine_root=root / "engine",
                    knowledge_root=root / "knowledge",
                    runtime_root=root / "runtime",
                )
            )

            receipt = operation_receipt_path(plan)

            self.assertEqual(receipt.parent, plan.selection.runtime_root / "setup-operations")
            self.assertEqual(receipt.name, f"{plan.plan_digest.removeprefix('sha256:')}.json")
            self.assertFalse(receipt.exists())

    def test_completed_local_receipt_loads_and_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = plan_knowledge_setup(
                KnowledgeSetupSelection(
                    mode="local",
                    engine_root=root / "engine",
                    knowledge_root=root / "knowledge",
                    runtime_root=root / "runtime",
                )
            )
            result = apply_knowledge_setup(plan)
            self.assertTrue(result.ok, result)
            receipt_path = operation_receipt_path(plan)
            receipt = load_operation_receipt(receipt_path, runtime_root=plan.selection.runtime_root)
            self.assertEqual(receipt["status"], "COMPLETE")
            self.assertEqual(receipt["stage"], "KNOWLEDGE_LOCAL_READY")

            receipt["unexpected"] = True
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "^KNOWLEDGE_OPERATION_RECEIPT_INVALID$"):
                load_operation_receipt(receipt_path, runtime_root=plan.selection.runtime_root)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from ei.capture_contract import CaptureIdentity, capture_key
from ei.config import HostSpec, RuntimePaths
from ei.hook_entry import handle_normalized_hook
from ei.hooks.codex import CodexAdapter
from ei.hooks import registry
from ei.ids import fingerprint
from ei.install_manifest import normalize_install_manifest, validate_install_manifest
from ei.operation_runtime import OperationBudget, trusted_capture_identity
from ei.capture_ledger import read_receipt, record_receipt
from ei.journal import validate_schema
from tests.helpers import make_hook_settings
from tests.unit.test_install_manifest import valid_v7_manifest


class InstalledAdapterFixture:
    def __init__(self, test: unittest.TestCase, *, turns: int = 3):
        self._temporary = tempfile.TemporaryDirectory()
        test.addCleanup(self._temporary.cleanup)
        root = Path(self._temporary.name)
        engine = root / "engine"
        knowledge = root / "knowledge"
        runtime = root / "runtime"
        home = root / "host" / "codex"
        skill_root = root / "host" / ".agents" / "skills"
        for directory in (engine, knowledge, runtime, home, skill_root):
            directory.mkdir(parents=True, exist_ok=True)
        (engine / "config").mkdir(parents=True, exist_ok=True)
        source_root = Path(__file__).resolve().parents[2]
        shutil.copyfile(source_root / "config" / "hosts.json", engine / "config" / "hosts.json")

        self.host_id = "codex-cli"
        self.spec = HostSpec(
            host_id=self.host_id,
            display_name="Codex CLI fixture",
            executable_names=("codex",),
            hook_config_path=home / "hooks.json",
            global_context_path=home / "AGENTS.md",
            skill_roots=(skill_root,),
            event_mapping={"Stop": "turn.stop"},
            hook_feature_key="features.hooks",
            hook_feature_default=False,
            skill_activation_mode="AUTO_ALLOWED",
            capture_primary_path="HOOK_DIRECT",
            capture_order=("HOOK_DIRECT", "AGENT_SKILL", "NATIVE_SOURCE"),
            minimum_supported_version="0.1.0",
            host_family="codex-compatible",
            adapter_id="codex-cli",
        )
        paths = RuntimePaths(engine_root=engine, personal_knowledge_root=knowledge, runtime_root=runtime)
        self.settings = replace(make_hook_settings(engine), paths=paths, hosts={self.host_id: self.spec})

        raw_manifest = valid_v7_manifest()
        for field, value in (
            ("repo_root", engine),
            ("engine_root", engine),
            ("knowledge_root", knowledge),
            ("runtime_root", runtime),
            ("skill_source", engine / "skills" / "external-intelligence"),
        ):
            raw_manifest[field] = value.as_posix()
        repository = raw_manifest["knowledge_repository"]
        assert isinstance(repository, dict)
        repository["root"] = knowledge.as_posix()
        stores = raw_manifest["knowledge_stores"]
        assert isinstance(stores, dict)
        personal_store = stores["personal"]
        assert isinstance(personal_store, dict)
        personal_store["root"] = knowledge.as_posix()
        record = raw_manifest["hosts"][self.host_id]  # type: ignore[index]
        assert isinstance(record, dict)
        record["home"] = home.as_posix()
        record["hook_config_path"] = (home / "hooks.json").as_posix()
        record["context_path"] = (home / "AGENTS.md").as_posix()
        record["skill_destination"] = (home / "skills" / "ei").as_posix()
        record["skill_root"] = (home / ".." / ".agents" / "skills").as_posix()
        record["skill_binding_path"] = (home / "skills" / "binding.json").as_posix()
        manifest = normalize_install_manifest(raw_manifest)
        validate_install_manifest(manifest)
        paths.install_manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )
        namespace = __import__("ei.operation_runtime", fromlist=["capture_namespace"]).capture_namespace(
            self.settings, self.host_id, budget=OperationBudget(5000)
        )
        test.assertIsNotNone(namespace)
        assert namespace is not None

        self.adapter = _FixtureAdapter(namespace, domain_hash=fingerprint("fixture-domain"))
        self.events = []
        for index in range(turns):
            event = self.adapter.normalize(
                {
                    "hook_event_name": "Stop",
                    "session_id": "fixture-session",
                    "turn_id": f"fixture-turn-{index}",
                    "cwd": "C:/fixture/project",
                    "domain": "fixture-domain",
                },
                self.spec,
            )
            session = event.session_id_hash
            turn = event.turn_id_hash
            record_hash = fingerprint(
                {
                    "domain": "ei-hook-target-v1",
                    "host_id": event.host_id,
                    "session_id_hash": session,
                    "turn_id_hash": turn,
                    "event_kind": event.normalized_event_name,
                }
            )
            identity = trusted_capture_identity(
                self.settings,
                self.host_id,
                session,
                turn,
                record_hash,
                budget=OperationBudget(5000),
            )
            self.events.append(
                replace(
                    event,
                    capture_identity=identity,
                    work_domain_hash=self.adapter.domain_hash,
                )
            )

    def control_for(self, events):
        first = events[0]
        target_identity = first.capture_identity
        assert target_identity is not None
        return {
            "native_identity": CaptureIdentity(
                target_identity.host_id,
                target_identity.instance_hash,
                target_identity.store_id,
                target_identity.session_hash,
                None,
                fingerprint({"domain": "fixture-closeout-record-v1", "targets": [capture_key(e.capture_identity) for e in events]}),
            ),
            "native_cwd_hash": first.cwd_hash,
            "native_domain_hash": self.adapter.domain_hash,
            "explicit_target_ids": tuple(capture_key(e.capture_identity) for e in events),
        }


class _FixtureAdapter(CodexAdapter):
    supports_closeout_context = True

    def __init__(self, namespace, *, domain_hash):
        self.namespace = namespace
        self.domain_hash = domain_hash

    def normalize(self, payload, spec):
        return super().normalize(payload, spec)

    def capture_work_scope(self, event, spec):
        from ei.closeout_context import CloseoutScope

        if self.domain_hash is None:
            return None
        return CloseoutScope(event.cwd_hash, self.domain_hash)

    def closeout_context(self, control, spec):
        from ei.closeout_context import CloseoutContext, CloseoutScope

        cwd_hash = control.get("native_cwd_hash")
        domain_hash = control.get("native_domain_hash")
        if not cwd_hash or not domain_hash:
            return None
        return CloseoutContext(
            identity=control["native_identity"],
            target_ids=tuple(control["explicit_target_ids"]),
            scope=CloseoutScope(cwd_hash, domain_hash),
        )


class CloseoutContextTests(unittest.TestCase):
    def _bind(self, fixture: InstalledAdapterFixture) -> None:
        with patch.dict(registry._ADAPTERS, {fixture.host_id: fixture.adapter}):
            for event in fixture.events:
                result = handle_normalized_hook(
                    event, fixture.settings, budget=OperationBudget(5000)
                )
                self.assertTrue(result.continue_work)

    def _validate(self, fixture: InstalledAdapterFixture, control, *, budget_ms: int = 5000):
        from ei.closeout_context import validate_adapter_context

        with patch.dict(registry._ADAPTERS, {fixture.host_id: fixture.adapter}):
            return validate_adapter_context(
                fixture.settings,
                fixture.host_id,
                control,
                budget=OperationBudget(budget_ms),
            )

    def test_explicit_two_targets_excludes_third_turn(self):
        fixture = InstalledAdapterFixture(self, turns=3)
        with patch.dict(registry._ADAPTERS, {fixture.host_id: fixture.adapter}):
            for event in fixture.events:
                handle_normalized_hook(
                    event, fixture.settings, budget=OperationBudget(5000)
                )
            from ei.closeout_context import validate_adapter_context

            result = validate_adapter_context(
                fixture.settings,
                fixture.adapter.host_id,
                fixture.control_for(fixture.events[:2]),
                budget=OperationBudget(5000),
            )
        self.assertTrue(result.valid)
        self.assertEqual(
            result.context.target_ids,
            tuple(sorted(capture_key(event.capture_identity) for event in fixture.events[:2])),
        )
        third_id = capture_key(fixture.events[2].capture_identity)
        self.assertIsNotNone(third_id)
        self.assertEqual(read_receipt(fixture.settings, third_id).state, "WAITING")

    def test_missing_context_capability_and_candidate_mapping_are_unverified(self):
        fixture = InstalledAdapterFixture(self, turns=1)
        control = fixture.control_for(fixture.events)
        fixture.adapter.supports_closeout_context = False
        self.assertEqual(self._validate(fixture, control).reason_code, "CLOSEOUT_CONTEXT_UNVERIFIED")

        fixture.adapter.supports_closeout_context = True
        for missing in ("native_cwd_hash", "native_domain_hash"):
            incomplete = dict(control)
            incomplete[missing] = None
            with self.subTest(missing=missing):
                self.assertEqual(
                    self._validate(fixture, incomplete).reason_code,
                    "CLOSEOUT_CONTEXT_UNVERIFIED",
                )
        candidate = {
            "claim": "untrusted candidate text",
            "trusted": True,
            "target_ids": list(control["explicit_target_ids"]),
            "source_host_id": fixture.host_id,
        }
        self.assertEqual(self._validate(fixture, candidate).reason_code, "CLOSEOUT_CONTEXT_UNVERIFIED")
        ordinary = CodexAdapter().normalize(
            {"hook_event_name": "Stop", "session_id": "s", "turn_id": "t", "cwd": "C:/work", "domain": "fake"},
            fixture.spec,
        )
        self.assertIsNone(ordinary.work_domain_hash)
        self.assertFalse(CodexAdapter.supports_closeout_context)
        self.assertIsNone(CodexAdapter().capture_work_scope(fixture.events[0], fixture.spec))
        self.assertIsNone(CodexAdapter().closeout_context(control, fixture.spec))
        from ei.hooks.registry import ProfiledHookAdapter

        profiled = ProfiledHookAdapter("fixture-profile", "codex-compatible", CodexAdapter())
        self.assertFalse(profiled.supports_closeout_context)
        self.assertIsNone(profiled.capture_work_scope(fixture.events[0], fixture.spec))
        self.assertIsNone(profiled.closeout_context(control, fixture.spec))

    def test_missing_adapter_domain_does_not_create_a_target_binding(self):
        fixture = InstalledAdapterFixture(self, turns=1)
        fixture.adapter.domain_hash = None
        event = fixture.events[0]
        with patch.dict(registry._ADAPTERS, {fixture.host_id: fixture.adapter}):
            result = handle_normalized_hook(event, fixture.settings, budget=OperationBudget(5000))
        self.assertTrue(result.continue_work)
        capture_id = capture_key(event.capture_identity)
        self.assertIsNotNone(capture_id)
        binding = (
            fixture.settings.paths.runtime_root
            / "state"
            / "capture"
            / "target-bindings"
            / f"{capture_id.removeprefix('sha256:')}.json"
        )
        self.assertFalse(binding.exists())
        self.assertEqual(read_receipt(fixture.settings, capture_id).state, "WAITING")

        fixture.adapter.domain_hash = fingerprint("fixture-domain")
        missing_cwd = replace(event, cwd_hash="")
        with patch.dict(registry._ADAPTERS, {fixture.host_id: fixture.adapter}):
            result = handle_normalized_hook(
                missing_cwd, fixture.settings, budget=OperationBudget(5000)
            )
        self.assertTrue(result.continue_work)
        self.assertFalse(binding.exists())

    def test_binding_requires_identity_session_and_turn_to_match_the_hook_event(self):
        for field in ("session_hash", "turn_hash"):
            fixture = InstalledAdapterFixture(self, turns=1)
            event = fixture.events[0]
            invalid_identity = replace(event.capture_identity, **{field: "sha256:" + "9" * 64})
            invalid_event = replace(event, capture_identity=invalid_identity)
            with patch.dict(registry._ADAPTERS, {fixture.host_id: fixture.adapter}):
                result = handle_normalized_hook(
                    invalid_event, fixture.settings, budget=OperationBudget(5000)
                )
            self.assertTrue(result.continue_work)
            capture_id = capture_key(invalid_identity)
            receipt = read_receipt(fixture.settings, capture_id)
            self.assertEqual(receipt.state, "WAITING")
            binding = (
                fixture.settings.paths.runtime_root
                / "state"
                / "capture"
                / "target-bindings"
                / f"{capture_id.removeprefix('sha256:')}.json"
            )
            self.assertFalse(binding.exists())

    def test_binding_write_failure_is_fixed_fail_open_without_success_state(self):
        from ei.capture_contract import capture_key

        fixture = InstalledAdapterFixture(self, turns=1)
        event = fixture.events[0]
        with (
            patch.dict(registry._ADAPTERS, {fixture.host_id: fixture.adapter}),
            patch("ei.closeout_context.safe_atomic_write", side_effect=OSError("C:/private/path")),
        ):
            result = handle_normalized_hook(
                event, fixture.settings, budget=OperationBudget(5000)
            )
        self.assertTrue(result.continue_work)
        self.assertEqual(result.status, "CLOSEOUT_TARGET_BINDING_FAILED")
        error_log = fixture.settings.paths.runtime_root / "hook-errors.jsonl"
        self.assertIn("CLOSEOUT_TARGET_BINDING_FAILED", error_log.read_text(encoding="utf-8"))
        self.assertNotIn("private/path", error_log.read_text(encoding="utf-8"))
        capture_id = capture_key(event.capture_identity)
        self.assertEqual(read_receipt(fixture.settings, capture_id).state, "WAITING")

    def test_invalid_hash_empty_duplicate_and_oversized_targets_are_rejected(self):
        fixture = InstalledAdapterFixture(self, turns=1)
        self._bind(fixture)
        control = fixture.control_for(fixture.events)
        identity = control["native_identity"]

        malformed_identity = dict(control)
        malformed_identity["native_identity"] = replace(identity, record_hash="sha256:bad")
        self.assertEqual(self._validate(fixture, malformed_identity).reason_code, "CLOSEOUT_CONTEXT_INVALID")

        for ids in ((), ("sha256:" + "a" * 64, "sha256:" + "a" * 64), tuple("sha256:" + f"{index:064x}" for index in range(65))):
            malformed_targets = dict(control)
            malformed_targets["explicit_target_ids"] = ids
            with self.subTest(count=len(ids), ids=ids[:2]):
                self.assertEqual(self._validate(fixture, malformed_targets).reason_code, "CLOSEOUT_CONTEXT_INVALID")

        malformed_hash = dict(control)
        malformed_hash["explicit_target_ids"] = ("sha256:bad",)
        self.assertEqual(self._validate(fixture, malformed_hash).reason_code, "CLOSEOUT_CONTEXT_INVALID")

    def test_namespace_session_scope_and_unknown_target_are_rejected(self):
        fixture = InstalledAdapterFixture(self, turns=1)
        self._bind(fixture)
        control = fixture.control_for(fixture.events)
        identity = control["native_identity"]

        for changed in (
            replace(identity, host_id="claude-code"),
            replace(identity, instance_hash="sha256:" + "a" * 64),
            replace(identity, store_id="sha256:" + "b" * 64),
        ):
            mutated = dict(control)
            mutated["native_identity"] = changed
            self.assertEqual(self._validate(fixture, mutated).reason_code, "CLOSEOUT_NAMESPACE_MISMATCH")

        for changed in (
            replace(identity, session_hash="sha256:" + "c" * 64),
        ):
            mutated = dict(control)
            mutated["native_identity"] = changed
            self.assertEqual(self._validate(fixture, mutated).reason_code, "CLOSEOUT_SCOPE_MISMATCH")
        for field, value in (
            ("native_cwd_hash", "sha256:" + "d" * 64),
            ("native_domain_hash", "sha256:" + "e" * 64),
        ):
            mutated = dict(control)
            mutated[field] = value
            self.assertEqual(self._validate(fixture, mutated).reason_code, "CLOSEOUT_SCOPE_MISMATCH")

        unknown = dict(control)
        unknown["explicit_target_ids"] = ("sha256:" + "f" * 64,)
        self.assertEqual(self._validate(fixture, unknown).reason_code, "CLOSEOUT_TARGET_UNKNOWN")

    def test_binding_unknown_field_corruption_and_link_are_conflicts(self):
        fixture = InstalledAdapterFixture(self, turns=1)
        self._bind(fixture)
        control = fixture.control_for(fixture.events)
        capture_id = capture_key(fixture.events[0].capture_identity)
        binding = (
            fixture.settings.paths.runtime_root
            / "state"
            / "capture"
            / "target-bindings"
            / f"{capture_id.removeprefix('sha256:')}.json"
        )
        value = json.loads(binding.read_text(encoding="utf-8"))
        value["unexpected"] = "rejected"
        with self.assertRaises(ValueError):
            validate_schema("closeout-target-binding", value)
        binding.write_text(json.dumps(value), encoding="utf-8")
        self.assertEqual(self._validate(fixture, control).reason_code, "CLOSEOUT_TARGET_CONFLICT")

        binding.write_text("{broken", encoding="utf-8")
        self.assertEqual(self._validate(fixture, control).reason_code, "CLOSEOUT_TARGET_CONFLICT")

        binding.unlink()
        binding_root = binding.parent
        external_root = fixture.settings.paths.runtime_root / "external-bindings"
        binding_root.rename(external_root)
        if os.name == "nt":
            linked = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(binding_root), str(external_root)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
            )
            self.assertEqual(linked.returncode, 0, linked.stdout)
        else:
            binding_root.symlink_to(external_root, target_is_directory=True)
        self.assertEqual(self._validate(fixture, control).reason_code, "CLOSEOUT_TARGET_CONFLICT")

    def test_missing_or_changed_install_manifest_cannot_validate_context(self):
        fixture = InstalledAdapterFixture(self, turns=1)
        self._bind(fixture)
        control = fixture.control_for(fixture.events)
        manifest = fixture.settings.paths.install_manifest_path
        original = json.loads(manifest.read_text(encoding="utf-8"))
        changed = dict(original)
        changed["status"] = "UNINSTALLED"
        manifest.write_text(json.dumps(changed), encoding="utf-8")
        self.assertEqual(self._validate(fixture, control).reason_code, "CLOSEOUT_NAMESPACE_MISMATCH")
        manifest.unlink()
        self.assertEqual(self._validate(fixture, control).reason_code, "CLOSEOUT_NAMESPACE_MISMATCH")

    def test_unknown_and_expired_receipts_do_not_validate_or_reclassify(self):
        from ei.capture_contract import CaptureReceipt

        for state, reason in (("UNKNOWN", "LEGACY_EVIDENCE_UNKNOWN"), ("UNAVAILABLE", "PENDING_EXPIRED")):
            fixture = InstalledAdapterFixture(self, turns=1)
            self._bind(fixture)
            control = fixture.control_for(fixture.events)
            capture_id = capture_key(fixture.events[0].capture_identity)
            receipt = read_receipt(fixture.settings, capture_id)
            record_receipt(
                fixture.settings,
                CaptureReceipt(
                    capture_id=capture_id,
                    state=state,
                    candidate_ids=(),
                    covered_target_ids=receipt.covered_target_ids,
                    reason_code=reason,
                    updated_at=receipt.updated_at,
                ),
            )
            with self.subTest(state=state):
                self.assertEqual(self._validate(fixture, control).reason_code, "CLOSEOUT_TARGET_UNKNOWN")
                self.assertEqual(read_receipt(fixture.settings, capture_id).state, state)

    def test_binding_digest_ignores_updated_at(self):
        fixture = InstalledAdapterFixture(self, turns=2)
        self._bind(fixture)
        control = fixture.control_for(fixture.events)
        first = self._validate(fixture, control)
        semantic_bindings = []
        for event in fixture.events:
            capture_id = capture_key(event.capture_identity)
            path = (
                fixture.settings.paths.runtime_root
                / "state"
                / "capture"
                / "target-bindings"
                / f"{capture_id.removeprefix('sha256:')}.json"
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            semantic_bindings.append(
                {
                    "capture_id": value["capture_id"],
                    "identity": value["identity"],
                    "scope_hash": value["scope_hash"],
                }
            )
            value["updated_at"] = "2027-01-01T00:00:00Z"
            path.write_text(json.dumps(value), encoding="utf-8")
        later = self._validate(fixture, control)
        self.assertTrue(first.valid)
        expected_digest = fingerprint(sorted(semantic_bindings, key=lambda item: item["capture_id"]))
        self.assertEqual(first.target_binding_digest, expected_digest)
        self.assertEqual(first.target_binding_digest, later.target_binding_digest)

    def test_different_existing_scope_binding_is_not_overwritten(self):
        from ei.closeout_context import CloseoutContextError, register_adapter_target

        fixture = InstalledAdapterFixture(self, turns=1)
        self._bind(fixture)
        event = fixture.events[0]
        changed_domain = fingerprint("different-native-domain")
        fixture.adapter.domain_hash = changed_domain
        changed_event = replace(event, work_domain_hash=changed_domain)
        capture_id = capture_key(event.capture_identity)
        path = (
            fixture.settings.paths.runtime_root
            / "state"
            / "capture"
            / "target-bindings"
            / f"{capture_id.removeprefix('sha256:')}.json"
        )
        before = path.read_bytes()
        with patch.dict(registry._ADAPTERS, {fixture.host_id: fixture.adapter}):
            with self.assertRaises(CloseoutContextError):
                register_adapter_target(
                    fixture.settings,
                    changed_event,
                    now=event.received_at,
                    budget=OperationBudget(5000),
                )
        self.assertEqual(path.read_bytes(), before)

    def test_deadline_is_preserved(self):
        fixture = InstalledAdapterFixture(self, turns=1)
        with self.assertRaises(TimeoutError):
            self._validate(fixture, fixture.control_for(fixture.events), budget_ms=0)


if __name__ == "__main__":
    unittest.main()

import json
import inspect
import subprocess
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import ei.inference.router as router_module
from ei.inference.base import InferenceBudget, ProviderResult
from ei.inference.cli_subscription import SubscriptionCLIProvider
from ei.inference.errors import (
    AUTH_FAILED,
    MALFORMED_RESPONSE,
    PROVIDER_TIMEOUT,
    PROVIDER_UNAVAILABLE,
    QUOTA_EXHAUSTED,
    RATE_LIMITED,
    classify_provider_error,
    next_eligible_at,
)
from ei.inference.local_openai import LocalOpenAICompatibleProvider
from ei.inference.ollama import OllamaProvider
from ei.inference.router import ProviderRouter, ProviderSelectionError
from ei.setup_contract import OrganizerSelection


@dataclass
class FakeProvider:
    provider_id: str
    locality: str
    result: ProviderResult
    available_value: bool = True
    calls: int = 0

    def available(self) -> bool:
        return self.available_value

    def generate(self, schema_name, input_json, budget):
        del input_json, budget
        self.calls += 1
        return ProviderResult(
            self.result.provider_id,
            self.result.status,
            self.result.output,
            self.result.error_code,
            self.result.retry_after_seconds,
            self.result.next_eligible_at,
            self.result.input_tokens,
            self.result.output_tokens,
            self.result.cost,
            self.result.repaired,
            self.result.attempt,
            schema_name,
            self.result.metadata,
        )


class FakeHTTPResponse:
    def __init__(self, body: bytes):
        self.body = body
        self.closed = False

    def read(self, limit: int = -1) -> bytes:
        return self.body if limit < 0 else self.body[:limit]

    def close(self) -> None:
        self.closed = True


class InferenceRouterTests(unittest.TestCase):
    def test_local_openai_rejects_non_loopback_endpoint(self):
        for endpoint in (
            "https://api.example.com/v1/chat/completions",
            "http://192.168.1.20:8000/v1/chat/completions",
            "http://localhost:8000/v1/chat/completions",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaisesRegex(ValueError, "^LOCAL_ENDPOINT_NOT_LOOPBACK$"):
                    LocalOpenAICompatibleProvider(endpoint=endpoint)

        self.assertEqual(
            LocalOpenAICompatibleProvider("http://127.0.0.1:8000/v1/chat/completions").endpoint,
            "http://127.0.0.1:8000/v1/chat/completions",
        )
        self.assertEqual(
            LocalOpenAICompatibleProvider("http://[::1]:8000/v1/chat/completions").endpoint,
            "http://[::1]:8000/v1/chat/completions",
        )

    def test_host_transport_uses_canonical_builtin_and_profile_adapter_ids(self):
        custom = SimpleNamespace(adapter_id="codex-cli")
        settings = SimpleNamespace(hosts={"test-compatible-cli": custom})

        self.assertEqual(router_module._host_transport("CODEX", settings), "codex-cli")
        self.assertEqual(router_module._host_transport("test-compatible-cli", settings), "codex-cli")
        self.assertIsNone(router_module._host_transport("test-compatible-cli", SimpleNamespace(hosts={})))

    def test_manifest_provider_order_overrides_repository_defaults(self):
        settings = SimpleNamespace(
            provider_order=("subscription-cli",),
            paths=SimpleNamespace(
                engine_root=Path.cwd(),
                runtime_dir=Path.cwd(),
                install_manifest_path=Path.cwd() / "missing-install-manifest.json",
            ),
            hosts={},
            organizer=OrganizerSelection("READY", "subscription-cli", "codex-cli"),
        )
        config = {
            "provider_order": ["local-openai-compatible", "ollama", "subscription-cli", "cloud-api"],
            "providers": {
                "subscription-cli": {"enabled": True, "argv": ["subscription-cli"]},
            },
        }

        router = ProviderRouter(settings=settings, provider_config=config)

        self.assertEqual([provider.provider_id for provider in router.providers], ["subscription-cli"])

    def test_selected_codex_host_auto_configures_subscription_transport(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / "runtime"
            runtime.mkdir()
            manifest = runtime / "install-manifest.json"
            manifest.write_text(json.dumps({"hosts": {"codex-cli": {}}}), encoding="utf-8")
            settings = SimpleNamespace(
                provider_order=("subscription-cli",),
                paths=SimpleNamespace(
                    engine_root=Path.cwd(),
                    runtime_dir=runtime,
                    install_manifest_path=manifest,
                ),
                hosts={"codex-cli": SimpleNamespace(executable_names=("codex",))},
                organizer=OrganizerSelection("READY", "subscription-cli", "codex-cli"),
            )
            config = {
                "provider_order": ["subscription-cli"],
                "providers": {
                    "subscription-cli": {
                        "enabled": False,
                        "argv": [],
                        "auto_from_selected_host": True,
                    }
                },
            }

            with patch("ei.inference.router._resolve_host_command", return_value=(str(root / "codex.exe"),)):
                provider = ProviderRouter(settings=settings, provider_config=config).providers[0]

            self.assertTrue(provider.enabled)
            self.assertEqual(provider.transport, "codex-cli")
            self.assertEqual(provider.command, (str(root / "codex.exe"),))

    def test_windows_npm_cmd_shim_resolves_to_node_without_a_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shim = root / "gemini.cmd"
            node = root / "node.exe"
            later_native = root / "later" / "gemini.exe"
            script = root / "node_modules" / "@google" / "gemini-cli" / "dist" / "index.js"
            script.parent.mkdir(parents=True)
            later_native.parent.mkdir()
            script.write_text("// fixture\n", encoding="utf-8")
            node.write_bytes(b"fixture")
            later_native.write_bytes(b"fixture")
            shim.write_text(
                '@ECHO off\n"%dp0%\\node.exe" "%dp0%\\node_modules\\@google\\gemini-cli\\dist\\index.js" %*\n',
                encoding="utf-8",
            )

            def resolve(name):
                return {
                    "gemini.exe": str(later_native),
                    "gemini": str(shim),
                    "node.exe": str(node),
                    "node": str(node),
                }.get(name)

            with patch("shutil.which", side_effect=resolve):
                command = router_module._resolve_host_command("gemini", platform="nt")

            self.assertEqual(command, (str(node.resolve()), str(script.resolve())))

    def test_supported_subscription_transports_emit_validated_gate_objects(self):
        if "transport" not in inspect.signature(SubscriptionCLIProvider).parameters:
            self.fail("SubscriptionCLIProvider does not expose the required host transport contract")
        decision = {
            "decision": "YES",
            "reason_code": "evidence_verified",
            "candidate_title": "Reusable finding",
            "candidate_claim": "This verified finding is reusable across independent projects.",
            "evidence_refs": ["sha256:" + "a" * 64],
            "benefit": "reduced_rework",
            "classification": "private-reusable",
            "confidence": 0.9,
        }
        outputs = {
            "codex-cli": json.dumps(decision),
            "claude-code": json.dumps({"structured_output": decision}),
            "gemini-cli": json.dumps({"response": json.dumps(decision)}),
            "qwen-code": json.dumps(decision),
        }
        required_argv = {
            "codex-cli": ("exec", "--output-schema"),
            "claude-code": ("--print", "--json-schema"),
            "gemini-cli": ("--output-format", "json"),
            "qwen-code": ("--json-schema",),
        }

        with tempfile.TemporaryDirectory() as tmp:
            working = Path(tmp)
            for transport, stdout in outputs.items():
                with self.subTest(transport=transport):
                    runner = unittest.mock.Mock(return_value=SimpleNamespace(returncode=0, stdout=stdout, stderr=""))
                    provider = SubscriptionCLIProvider(
                        (transport,),
                        transport=transport,
                        schema_root=Path.cwd() / "schemas",
                        working_directory=working,
                        runner=runner,
                    )

                    result = provider.generate(
                        "gate-decision",
                        {"candidate_claim": "sanitized reusable candidate"},
                        InferenceBudget(max_input_tokens=1000, max_output_tokens=1000),
                    )

                    self.assertTrue(result.ok, result.to_dict())
                    argv = tuple(runner.call_args.args[0])
                    for expected in required_argv[transport]:
                        self.assertIn(expected, argv)
                    self.assertNotIn("sanitized reusable candidate", argv)
                    self.assertIn("sanitized reusable candidate", runner.call_args.kwargs["input"])
                    self.assertEqual(runner.call_args.kwargs["env"]["EI_INTERNAL"], "1")
                    self.assertFalse(runner.call_args.kwargs["shell"])
                    self.assertEqual(runner.call_args.kwargs["cwd"], str(working.resolve()))

    def test_disabled_subscription_provider_does_not_require_a_command(self):
        provider = SubscriptionCLIProvider.from_config({"enabled": False, "argv": []})

        self.assertFalse(provider.available())
        result = provider.generate("gate-decision", {"candidate": "safe"})
        self.assertEqual(result.status, "disabled")
        self.assertEqual(result.error_code, "PROVIDER_DISABLED")
        with self.assertRaisesRegex(ValueError, "SUBSCRIPTION_COMMAND_INVALID"):
            SubscriptionCLIProvider.from_config({"enabled": True, "argv": []})

    def test_local_openai_is_selected_before_subscription(self):
        local = FakeProvider("local-openai-compatible", "local", ProviderResult("local-openai-compatible", output={"decision": "YES"}))
        subscription = FakeProvider("subscription-cli", "subscription", ProviderResult("subscription-cli", output={"decision": "YES"}))
        router = ProviderRouter([local, subscription], organizer=OrganizerSelection("READY", "local-openai-compatible", None))
        self.assertIs(router.choose("gate", {"provider_order": ["local-openai-compatible", "subscription-cli"]}), local)
        self.assertEqual(subscription.calls, 0)

    def test_ollama_is_selected_when_local_openai_unavailable(self):
        local = FakeProvider("local-openai-compatible", "local", ProviderResult("local-openai-compatible", "failed", error_code=PROVIDER_UNAVAILABLE), available_value=True)
        ollama = FakeProvider("ollama", "local", ProviderResult("ollama", output={"decision": "YES"}))
        router = ProviderRouter([local, ollama], organizer=OrganizerSelection("READY", "local-openai-compatible", None))
        result = router.generate("gate", "gate-decision", {"candidate": "safe"}, InferenceBudget(max_input_tokens=1000, max_output_tokens=1000), {"provider_order": ["local-openai-compatible", "ollama"]})
        self.assertEqual(result.provider_id, "local-openai-compatible")
        self.assertEqual(local.calls, 1)
        self.assertEqual(ollama.calls, 0)

    def test_generate_never_falls_back_from_selected_organizer(self):
        selected = FakeProvider(
            "ollama", "local", ProviderResult("ollama", "failed", error_code=PROVIDER_UNAVAILABLE)
        )
        other = FakeProvider(
            "subscription-cli", "subscription", ProviderResult("subscription-cli", output={"decision": "YES"})
        )
        router = ProviderRouter(
            [selected, other], organizer=OrganizerSelection("READY", "ollama", None)
        )
        result = router.generate("gate", "gate-decision", {"candidate": "safe"}, InferenceBudget())
        self.assertEqual(result.error_code, PROVIDER_UNAVAILABLE)
        self.assertEqual(selected.calls, 1)
        self.assertEqual(other.calls, 0)

    def test_selection_required_does_not_choose_first_provider(self):
        local = FakeProvider("local-openai-compatible", "local", ProviderResult("local-openai-compatible", output={"decision": "YES"}))
        router = ProviderRouter([local], organizer=OrganizerSelection("SELECTION_REQUIRED", None, None, "ORGANIZER_SELECTION_REQUIRED"))
        with self.assertRaisesRegex(ProviderSelectionError, "ORGANIZER_SELECTION_REQUIRED"):
            router.selected()

    def test_eligible_providers_never_reports_an_alternate_organizer(self):
        selected = FakeProvider(
            "ollama",
            "local",
            ProviderResult("ollama", "failed", error_code=PROVIDER_UNAVAILABLE),
            available_value=False,
        )
        alternate = FakeProvider(
            "subscription-cli",
            "subscription",
            ProviderResult("subscription-cli", output={"decision": "YES"}),
        )
        router = ProviderRouter(
            [selected, alternate],
            organizer=OrganizerSelection("READY", "ollama", None),
        )

        self.assertEqual(router.eligible_providers(), ())
        self.assertEqual(alternate.calls, 0)

    def test_paid_provider_is_unreachable_when_spend_cap_zero(self):
        cloud = FakeProvider("cloud-api", "cloud", ProviderResult("cloud-api", output={"decision": "YES"}))
        router = ProviderRouter([cloud])
        with self.assertRaisesRegex(ProviderSelectionError, "ORGANIZER_SELECTION_REQUIRED"):
            router.choose("gate", {"cloud_spend_cap": 0})

    def test_error_taxonomy_is_sanitized_and_stable(self):
        now = next_eligible_at(__import__("datetime").datetime(2026, 1, 1, tzinfo=__import__("datetime").timezone.utc), None, 0)
        self.assertEqual((now - __import__("datetime").datetime(2026, 1, 1, tzinfo=__import__("datetime").timezone.utc)).total_seconds(), 300)
        cases = [
            (429, "quota exceeded", QUOTA_EXHAUSTED),
            (1, "rate limit; retry-after", RATE_LIMITED),
            (401, "invalid api key secret-value", AUTH_FAILED),
            (124, "timeout secret-value", PROVIDER_TIMEOUT),
            (1, "malformed json", MALFORMED_RESPONSE),
            (1, "connection refused", PROVIDER_UNAVAILABLE),
        ]
        for exit_code, stderr, expected in cases:
            result = classify_provider_error(exit_code, stderr)
            self.assertEqual(result.error_code, expected)
            self.assertNotIn("secret-value", json.dumps(result.to_dict()))

    def test_openai_compatible_structured_request_and_repair_once(self):
        calls = []

        def opener(request, timeout):
            calls.append((request, timeout))
            if len(calls) == 1:
                return FakeHTTPResponse(b"not-json")
            return FakeHTTPResponse(b'{"choices":[{"message":{"content":"{\\"decision\\":\\"YES\\"}"}}]}')

        provider = LocalOpenAICompatibleProvider("http://127.0.0.1:8123/v1/chat/completions", opener=opener)
        result = provider.generate("gate-decision", {"candidate": "safe"}, InferenceBudget(max_input_tokens=1000, max_output_tokens=1000))
        self.assertTrue(result.ok)
        self.assertTrue(result.repaired)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0].get_header("Content-type"), "application/json")
        self.assertLessEqual(calls[0][1], 30)

    def test_ollama_uses_argv_without_shell_interpolation(self):
        completed = SimpleNamespace(returncode=0, stdout='{"decision":"YES"}', stderr="")
        runner = unittest.mock.Mock(return_value=completed)
        provider = OllamaProvider(command=("ollama", "run"), model="safe-model", runner=runner)
        result = provider.generate("gate-decision", {"candidate": "safe"}, InferenceBudget(max_input_tokens=1000, max_output_tokens=1000))
        self.assertTrue(result.ok)
        kwargs = runner.call_args.kwargs
        self.assertFalse(kwargs["shell"])
        self.assertEqual(runner.call_args.args[0], ("ollama", "run", "safe-model"))


if __name__ == "__main__":
    unittest.main()

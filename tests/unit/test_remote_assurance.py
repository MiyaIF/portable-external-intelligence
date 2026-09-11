from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from ei.remote_assurance import (
    RemoteAssuranceError,
    assure_remote,
    build_attestation,
    build_remote_assurance_receipt,
    classify_remote,
    load_remote_assurance_receipt,
    normalize_remote,
    remote_fingerprint,
    write_attestation,
    write_remote_assurance_receipt,
)


class RemoteAssuranceTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows junction fixture is platform-specific")
    def test_receipt_writer_rejects_junction_child_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            runtime = base / "runtime"
            outside = base / "outside"
            runtime.mkdir()
            outside.mkdir()
            junction = runtime / "remote-assurance"
            created = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(junction), str(outside)],
                capture_output=True,
                text=True,
                check=False,
            )
            if created.returncode != 0 or not junction.exists():
                self.skipTest("junction fixture unavailable")
            receipt = build_remote_assurance_receipt(
                classify_remote("https://github.com/MiyaIF/private.git", visibility="private")
            )

            with self.assertRaisesRegex(RemoteAssuranceError, "REMOTE_ASSURANCE_PATH_UNSAFE"):
                write_remote_assurance_receipt(runtime, receipt)

            self.assertEqual(list(outside.iterdir()), [])

    def test_local_path_is_safe_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            descriptor = classify_remote(Path(tmp) / "knowledge.git")
            self.assertEqual(descriptor.classification, "local_path")
            self.assertTrue(descriptor.fingerprint.startswith("sha256:"))

    def test_public_github_is_rejected_for_private_knowledge(self) -> None:
        remote = "https://github.com/example/knowledge.git"
        descriptor = classify_remote(remote, visibility="public")
        self.assertEqual(descriptor.classification, "public")
        with self.assertRaisesRegex(RemoteAssuranceError, "PRIVATE_REMOTE_REQUIRED"):
            assure_remote(remote, visibility="public")

    def test_unknown_generic_remote_is_fail_closed(self) -> None:
        remote = "https://git.example.invalid/team/knowledge.git"
        self.assertEqual(classify_remote(remote).classification, "unknown")
        with self.assertRaisesRegex(RemoteAssuranceError, "REMOTE_VISIBILITY_UNKNOWN"):
            assure_remote(remote)

    def test_attestation_is_bound_to_exact_fingerprint(self) -> None:
        remote = "ssh://git.example.invalid/team/knowledge.git"
        attestation = build_attestation(remote)
        with tempfile.TemporaryDirectory() as tmp:
            path = write_attestation(Path(tmp), attestation)
            self.assertEqual(path.name, attestation["remote_fingerprint"][7:] + ".json")
        descriptor = assure_remote(remote, attestation=attestation)
        self.assertEqual(descriptor.classification, "private_attested")
        other = build_attestation("ssh://git.example.invalid/team/other.git")
        with self.assertRaisesRegex(RemoteAssuranceError, "REMOTE_VISIBILITY_UNKNOWN"):
            assure_remote(remote, attestation=other)

    def test_engine_remote_cannot_be_reused_for_knowledge(self) -> None:
        remote = "https://github.com/example/engine.git"
        with self.assertRaisesRegex(RemoteAssuranceError, "ENGINE_REMOTE_REUSE"):
            assure_remote(remote, engine_remote=remote, visibility="private")

    def test_normalization_removes_git_suffix_and_credentials(self) -> None:
        self.assertEqual(normalize_remote("git@GitHub.com:Example/Repo.git"), "ssh://github.com/Example/Repo")
        self.assertEqual(remote_fingerprint("https://example.invalid/a/b.git"), remote_fingerprint("https://EXAMPLE.invalid/a/b"))
        with self.assertRaisesRegex(RemoteAssuranceError, "REMOTE_CREDENTIALS_FORBIDDEN"):
            normalize_remote("https://user:password@example.invalid/a/b.git")  # pragma: allowlist secret

    def test_verified_private_receipt_is_closed_and_contains_no_remote_url(self) -> None:
        descriptor = classify_remote(
            "https://github.com/MiyaIF/private-knowledge.git",
            visibility="private",
        )
        receipt = build_remote_assurance_receipt(descriptor)
        self.assertEqual(receipt["schema_version"], 2)
        self.assertEqual(receipt["classification"], "private_verified")
        self.assertEqual(receipt["provider"], "github")
        self.assertEqual(receipt["verification_source"], "explicit")
        self.assertNotIn("remote", receipt)
        self.assertNotIn("token", str(receipt).casefold())

        with tempfile.TemporaryDirectory() as tmp:
            path = write_remote_assurance_receipt(Path(tmp), receipt)
            loaded = load_remote_assurance_receipt(path)
        self.assertEqual(loaded, receipt)

    def test_public_and_unknown_descriptors_cannot_produce_assurance_receipts(self) -> None:
        for descriptor in (
            classify_remote("https://github.com/MiyaIF/public.git", visibility="public"),
            classify_remote("https://git.example.invalid/team/repository.git"),
        ):
            with self.subTest(classification=descriptor.classification):
                with self.assertRaisesRegex(RemoteAssuranceError, "REMOTE_ASSURANCE_CLASSIFICATION_FORBIDDEN"):
                    build_remote_assurance_receipt(descriptor)

    def test_version_one_attestation_remains_loadable(self) -> None:
        receipt = build_attestation("ssh://git.example.invalid/team/knowledge.git")
        with tempfile.TemporaryDirectory() as tmp:
            path = write_attestation(Path(tmp), receipt)
            loaded = load_remote_assurance_receipt(path)
        self.assertEqual(loaded, receipt)


if __name__ == "__main__":
    unittest.main()

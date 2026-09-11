import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER = REPO_ROOT / "scripts" / "verify-dependency-lock.py"
HASH_A = "a" * 64
HASH_B = "b" * 64


class DependencyLockTests(unittest.TestCase):
    def _write_case(
        self,
        root: Path,
        *,
        build_requires=None,
        runtime_requires=None,
        build_lock=None,
        runtime_lock=None,
        ci_lock=None,
        ci_tools=None,
    ) -> tuple[Path, Path, Path, Path]:
        pyproject = root / "pyproject.toml"
        build = root / "requirements-build.lock"
        runtime = root / "requirements-runtime.lock"
        ci = root / "requirements-ci.lock"
        config_dir = root / "config"
        config_dir.mkdir(parents=True, exist_ok=True)
        (config_dir / "defaults.json").write_text(
            json.dumps({"dependency_locks": {"ci_tools": ci_tools or {"detect-secrets": "1.5.0", "pip-audit": "2.7.3"}}}),
            encoding="utf-8",
        )
        pyproject.write_text(
            "[build-system]\n"
            f"requires = {json.dumps(build_requires or ['setuptools==68.0.0'])}\n"
            "build-backend = \"setuptools.build_meta\"\n\n"
            "[project]\n"
            "name = \"fixture\"\n"
            "version = \"1.0.0\"\n"
            f"dependencies = {json.dumps(runtime_requires or ['cryptography==42.0.8'])}\n",
            encoding="utf-8",
        )
        (root / "requirements-build.in").write_text(
            "\n".join(build_requires or ["setuptools==68.0.0"]) + "\n",
            encoding="utf-8",
        )
        (root / "requirements-runtime.in").write_text(
            "\n".join(runtime_requires or ["cryptography==42.0.8"]) + "\n",
            encoding="utf-8",
        )
        ci_requirements = ci_tools or {"detect-secrets": "1.5.0", "pip-audit": "2.7.3"}
        (root / "requirements-ci.in").write_text(
            "\n".join(f"{name}=={version}" for name, version in sorted(ci_requirements.items())) + "\n",
            encoding="utf-8",
        )
        build.write_text(
            build_lock or f"setuptools==68.0.0 --hash=sha256:{HASH_A}\n",
            encoding="utf-8",
        )
        runtime.write_text(
            runtime_lock
            or "\n".join(
                (
                    f"cryptography==42.0.8 --hash=sha256:{HASH_A}",
                    f"cffi==1.16.0 --hash=sha256:{HASH_A}",
                    f"pycparser==2.21 --hash=sha256:{HASH_A}",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        ci.write_text(
            ci_lock
            or "\n".join(
                (
                    f"detect-secrets==1.5.0 --hash=sha256:{HASH_A}",
                    f"pip-audit==2.7.3 --hash=sha256:{HASH_A}",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        return pyproject, build, runtime, ci

    def _run(self, pyproject: Path, build: Path, runtime: Path, ci: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(VERIFIER),
                "--pyproject",
                str(pyproject),
                "--build-lock",
                str(build),
                "--runtime-lock",
                str(runtime),
                "--ci-lock",
                str(ci),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )

    def test_build_and_runtime_requirements_are_exactly_pinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            valid = self._run(*self._write_case(root))
            self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)

            cases = (
                ("range", {"build_requires": ["setuptools>=68.0.0"]}),
                ("bare-name", {"runtime_requires": ["cryptography"]}),
                ("editable", {"build_lock": "-e .\n"}),
                ("url", {"build_lock": "setuptools @ https://example.invalid/setuptools.whl\n"}),
                (
                    "missing-direct-build-entry",
                    {"build_requires": ["setuptools==68.0.0", "wheel==0.43.0"]},
                ),
                (
                    "missing-transitive",
                    {"runtime_lock": f"cryptography==42.0.8 --hash=sha256:{HASH_A}\n"},
                ),
                (
                    "missing-direct-runtime-entry",
                    {"runtime_requires": ["cryptography==42.0.8", "idna==3.7"]},
                ),
                (
                    "missing-hash",
                    {"runtime_lock": "\n".join(("cryptography==42.0.8", f"cffi==1.16.0 --hash=sha256:{HASH_A}", f"pycparser==2.21 --hash=sha256:{HASH_A}")) + "\n"},
                ),
            )
            for name, overrides in cases:
                with self.subTest(name=name):
                    case_root = root / name
                    case_root.mkdir()
                    result = self._run(*self._write_case(case_root, **overrides))
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_ci_tools_are_exactly_pinned_with_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pyproject, build, runtime, ci = self._write_case(root)
            self.assertEqual(self._run(pyproject, build, runtime, ci).returncode, 0)

            duplicate = root / "duplicate.lock"
            duplicate.write_text(
                f"detect-secrets==1.5.0 --hash=sha256:{HASH_A}\n"
                f"detect-secrets==1.5.0 --hash=sha256:{HASH_B}\n",
                encoding="utf-8",
            )
            self.assertNotEqual(self._run(pyproject, build, runtime, duplicate).returncode, 0)

            conflicting = root / "conflicting.lock"
            conflicting.write_text(
                f"detect-secrets==1.5.0 --hash=sha256:{HASH_A}\n"
                f"detect-secrets==1.5.1 --hash=sha256:{HASH_B}\n",
                encoding="utf-8",
            )
            self.assertNotEqual(self._run(pyproject, build, runtime, conflicting).returncode, 0)

            unsupported = root / "unsupported.lock"
            unsupported.write_text("detect-secrets==1.5.0 --hash=sha512:" + HASH_A + "\n", encoding="utf-8")
            self.assertNotEqual(self._run(pyproject, build, runtime, unsupported).returncode, 0)

            extra = root / "extra.lock"
            extra.write_text(
                "\n".join(
                    (
                        f"detect-secrets==1.5.0 --hash=sha256:{HASH_A}",
                        f"pip-audit==2.7.3 --hash=sha256:{HASH_A}",
                        f"safety==3.2.4 --hash=sha256:{HASH_A}",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            # Resolved transitive packages are allowed; direct inputs remain
            # exact and are checked above.
            self.assertEqual(self._run(pyproject, build, runtime, extra).returncode, 0)

            missing = root / "missing.lock"
            missing.write_text(f"pip-audit==2.7.3 --hash=sha256:{HASH_A}\n", encoding="utf-8")
            self.assertNotEqual(self._run(pyproject, build, runtime, missing).returncode, 0)

            wrong_versions = root / "wrong-versions.lock"
            wrong_versions.write_text(
                "\n".join(
                    (
                        f"detect-secrets==9.9.9 --hash=sha256:{HASH_A}",
                        f"pip-audit==0.0.1 --hash=sha256:{HASH_A}",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            self.assertNotEqual(self._run(pyproject, build, runtime, wrong_versions).returncode, 0)

    def test_repository_source_and_policy_directories_are_not_ignored(self):
        protected = [
            "skills/contract.txt",
            "knowledge/contract.txt",
            "events/contract.txt",
            "policies/contract.txt",
            "schemas/contract.txt",
            "src/ei/config.py",
            "tests/unit/test_config.py",
        ]
        result = subprocess.run(
            ["git", "check-ignore", *protected],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

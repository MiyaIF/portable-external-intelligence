from __future__ import annotations

import json
import hashlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _package_source_digest(root: Path) -> str:
    digest = hashlib.sha256()
    paths = [root / name for name in ("pyproject.toml", "README.md", "LICENSE")]
    paths.extend(path for path in (root / "src").rglob("*") if path.is_file())
    for path in sorted(paths):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _build_scratch_inventory(root: Path) -> tuple[str, ...]:
    patterns = ("build", "dist", ".eggs", "*.egg", "*.egg-info", "src/*.egg-info", "src/**/*.egg-info")
    matches = {path for pattern in patterns for path in root.glob(pattern) if path.exists()}
    return tuple(sorted(path.relative_to(root).as_posix() for path in matches))


def _artifact_members(path: Path) -> list[bytes]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            return [archive.read(name) for name in archive.namelist()]
    with tarfile.open(path, "r:gz") as archive:
        return [member_file.read() for member in archive.getmembers() if (member_file := archive.extractfile(member))]


class PackageMetadataAcceptanceTests(unittest.TestCase):
    def test_pep621_metadata_matches_publication_policy(self):
        import tomllib

        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        policy = json.loads((ROOT / "release" / "publication-policy.json").read_text(encoding="utf-8"))
        author = project["authors"][0]
        self.assertEqual(project["name"], "portable-external-intelligence")
        self.assertEqual(project["license"], policy["license_spdx"])
        self.assertEqual(author["name"], policy["public_author"]["name"])
        self.assertEqual(author["email"], policy["public_author"]["email"])
        self.assertEqual(project["readme"], "README.md")
        self.assertEqual(project["urls"]["Repository"], "https://github.com/MiyaIF/portable-external-intelligence")
        self.assertEqual(project["dependencies"], ["cryptography==50.0.1"])

    def test_build_metadata_and_artifacts_have_no_local_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            temporary_root = Path(tmp)
            source = temporary_root / "source"
            output = temporary_root / "dist"
            source.mkdir()
            source_before = _package_source_digest(ROOT)
            scratch_before = _build_scratch_inventory(ROOT)
            for name in ("pyproject.toml", "README.md", "LICENSE"):
                shutil.copy2(ROOT / name, source / name)
            shutil.copytree(ROOT / "src", source / "src")
            completed = subprocess.run(
                [sys.executable, "-m", "build", "--wheel", "--sdist", "--no-isolation", "--outdir", str(output), str(source)],
                cwd=temporary_root,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=120,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(_package_source_digest(ROOT), source_before, "package build changed shared repository inputs")
            self.assertEqual(_build_scratch_inventory(ROOT), scratch_before, "package build created a repository-local artifact directory")
            artifacts = sorted(output.iterdir())
            self.assertTrue(any(path.suffix == ".whl" for path in artifacts))
            self.assertTrue(any(path.suffix == ".gz" for path in artifacts))
            for path in artifacts:
                self.assertNotIn(str(ROOT), path.name)
                self.assertGreater(path.stat().st_size, 0)
                members = b"\n".join(_artifact_members(path))
                for local_path in (str(ROOT), str(source)):
                    self.assertNotIn(local_path.encode("utf-8"), members)
                    self.assertNotIn(local_path.replace("\\", "/").encode("utf-8"), members)

    def test_default_distribution_output_does_not_dirty_release_source(self):
        completed = subprocess.run(
            ["git", "check-ignore", "--quiet", "dist/package.whl"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()

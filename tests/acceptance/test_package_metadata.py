from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


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
            output = Path(tmp) / "dist"
            completed = subprocess.run(
                [sys.executable, "-m", "build", "--wheel", "--sdist", "--no-isolation", "--outdir", str(output)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            artifacts = sorted(output.iterdir())
            self.assertTrue(any(path.suffix == ".whl" for path in artifacts))
            self.assertTrue(any(path.suffix == ".gz" for path in artifacts))
            for path in artifacts:
                self.assertNotIn(str(ROOT), path.name)
                self.assertGreater(path.stat().st_size, 0)

    def test_default_distribution_output_does_not_dirty_release_source(self):
        completed = subprocess.run(
            ["git", "check-ignore", "--quiet", "dist/package.whl"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()

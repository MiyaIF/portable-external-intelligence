"""Generate a deterministic SPDX 2.3 SBOM from the repository lock files."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path


LOCK_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_. ,+-]+\])?==(?P<version>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<hashes>(?:\s+--hash=sha256:[0-9a-f]{64})+)$")


def _logical_lock_lines(path: Path) -> list[str]:
    values: list[str] = []
    current = ""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if current:
            current += " " + line.rstrip("\\").strip()
            if not line.endswith("\\"):
                values.append(current)
                current = ""
        elif line.endswith("\\"):
            current = line[:-1].strip()
        else:
            values.append(line)
    if current:
        raise ValueError(f"LOCK_CONTINUATION_UNTERMINATED:{path.name}")
    return values


def _components(root: Path) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for lock_name in ("requirements-build.lock", "requirements-runtime.lock", "requirements-ci.lock"):
        for line in _logical_lock_lines(root / lock_name):
            match = LOCK_RE.fullmatch(line)
            if not match:
                raise ValueError(f"LOCK_ENTRY_INVALID:{lock_name}")
            name = match.group("name").lower().replace("_", "-")
            version = match.group("version")
            hashes = sorted(set(re.findall(r"--hash=sha256:([0-9a-f]{64})", match.group("hashes"))))
            result.append({
                "SPDXID": f"SPDXRef-Package-{name}-{version}".replace(".", "-"),
                "name": name,
                "versionInfo": version,
                "downloadLocation": f"https://pypi.org/project/{name}/{version}/",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "checksums": [{"algorithm": "SHA256", "checksumValue": value} for value in hashes],
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:pypi/{name}@{version}",
                }],
            })
    unique: dict[str, dict[str, object]] = {}
    for component in result:
        unique[str(component["SPDXID"])] = component
    return [unique[key] for key in sorted(unique)]


def _created() -> str:
    import os

    raw = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        moment = datetime.fromtimestamp(int(raw), tz=timezone.utc)
    except (ValueError, OSError, OverflowError) as exc:
        raise ValueError("SOURCE_DATE_EPOCH_INVALID") from exc
    return moment.isoformat().replace("+00:00", "Z")


def build_sbom(root: Path) -> dict[str, object]:
    packages = _components(root)
    package_digest = hashlib.sha256(json.dumps(packages, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "portable-external-intelligence",
        "documentNamespace": f"https://spdx.org/spdxdocs/portable-external-intelligence-{package_digest}",
        "creationInfo": {
            "created": _created(),
            "creators": ["Tool: portable-external-intelligence-generate-sbom"],
        },
        "packages": packages,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        value = build_sbom(args.root.expanduser().resolve())
        output = args.output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    except (OSError, UnicodeError, ValueError) as exc:
        print(str(exc))
        return 1
    print(json.dumps({"status": "generated", "output": output.name, "packages": len(value["packages"])}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

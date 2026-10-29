#!/usr/bin/env python3
"""Append a source-bound Cowork plugin to a fully validated native release set."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

import package_cowork_plugin
from release_artifacts import PLATFORMS, ROOT, sha256


def current_source() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()


def prepare(directory: Path, tag: str, source: str) -> dict:
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag) or not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("expected a stable vX.Y.Z tag and full source commit SHA")
    if current_source() != source:
        raise ValueError("Cowork helper checkout does not match tagged source")
    names = {target: f"agent-lens-{tag[1:]}-{target}-{arch}.zip" for target, arch in PLATFORMS.items()}
    required = set(names.values()) | {"SHA256SUMS", "build-provenance.json"}
    if {path.name for path in directory.iterdir()} != required:
        raise ValueError("expected only the complete, prepared three-platform native release")
    for name in required:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("release assets must be regular, non-symlinked files")
    original = (directory / "SHA256SUMS").read_bytes()
    checksums = {}
    for line in original.decode().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if not match or match[2] in checksums:
            raise ValueError("invalid or duplicate native checksum entry")
        checksums[match[2]] = match[1]
    if set(checksums) != set(names.values()):
        raise ValueError("native checksums must identify exactly three platform ZIPs")
    for name, digest in checksums.items():
        if sha256(directory / name) != digest:
            raise ValueError(f"native checksum mismatch: {name}")
    native = json.loads((directory / "build-provenance.json").read_text())
    if (native.get("source"), native.get("tag")) != (source, tag):
        raise ValueError("prepared native source/tag provenance mismatch")
    builds = native.get("builds", [])
    if len(builds) != 3 or {build.get("platform") for build in builds} != set(PLATFORMS):
        raise ValueError("prepared native platform provenance is incomplete")
    for build in builds:
        target = build["platform"]
        if (build.get("source"), build.get("version"), build.get("architecture"), build.get("packages")) != (
            source, tag[1:], PLATFORMS[target], {names[target]: checksums[names[target]]}
        ):
            raise ValueError("prepared native build provenance mismatch")

    name = f"ai-lens-cowork-{tag[1:]}.zip"
    destination = directory / name
    provenance_path = directory / "cowork-plugin-provenance.json"
    created = []
    # Build separately; failures do not alter the verified native ZIPs or manifest.
    with tempfile.TemporaryDirectory(prefix="lens-cowork-release-", dir=directory.parent) as temporary:
        staging = Path(temporary)
        package = staging / name
        report = package_cowork_plugin.package(directory / names["linux"], checksums[names["linux"]], package)
        with zipfile.ZipFile(package) as bundle:
            members = {member: package_cowork_plugin.digest(bundle.read(member)) for member in sorted(bundle.namelist())}
        provenance = {
            "schema_version": 1,
            "source": source,
            "tag": tag,
            "runtime": "Linux x86_64 Cowork cloud hook execution",
            "source_zip": {"name": names["linux"], "sha256": checksums[names["linux"]]},
            "helper_sha256": {
                "scripts/package_cowork_release.py": sha256(ROOT / "scripts/package_cowork_release.py"),
                "scripts/package_cowork_plugin.py": sha256(ROOT / "scripts/package_cowork_plugin.py"),
            },
            "launcher_template_sha256": sha256(ROOT / "examples/cowork-plugin/scripts/lens-hook.sh"),
            "launcher_sha256": members["scripts/lens-hook.sh"],
            "plugin_zip": {"name": name, "sha256": report["sha256"]},
            "members_sha256": members,
            "source_members_sha256": report["release_members"],
        }
        manifest = staging / "SHA256SUMS"
        manifest.write_bytes(original.rstrip(b"\n") + f"\n{report['sha256']}  {name}\n".encode())
        try:
            with destination.open("xb") as stream:
                created.append(destination)
                with package.open("rb") as incoming:
                    shutil.copyfileobj(incoming, stream)
            with provenance_path.open("x", encoding="utf-8", newline="\n") as stream:
                created.append(provenance_path)
                stream.write(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
            os.replace(manifest, directory / "SHA256SUMS")
        except Exception:
            for path in reversed(created):
                path.unlink(missing_ok=True)
            raise
    return provenance


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    try:
        report = prepare(args.assets, args.tag, args.source)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"Cowork release preparation failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

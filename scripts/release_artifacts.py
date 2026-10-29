#!/usr/bin/env python3
"""Record native build identity and verify a complete release before publication."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess

from package import NATIVE_FILES, architecture, native_platform, workspace_version


ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = {"linux": "x86_64", "windows": "x86_64", "macos": "aarch64"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def provenance(output: Path) -> None:
    target = native_platform()
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    report = {
        "source": source,
        "version": workspace_version(),
        "platform": target,
        "architecture": architecture(),
        "os": platform.platform(),
        "runner_image": {key: os.environ.get(key) for key in ("ImageOS", "ImageVersion")},
        "rustc": subprocess.check_output(["rustc", "-vV"], text=True).strip(),
        "cargo_lock_sha256": sha256(ROOT / "Cargo.lock"),
        "native_sha256": {name: sha256(ROOT / "target/release" / name) for name in NATIVE_FILES[target]},
        "packages": {path.name: sha256(path) for path in sorted((ROOT / "dist").glob("*.zip"))},
    }
    output.write_text(json.dumps(report, indent=2) + "\n")


def prepare(input_dir: Path, output_dir: Path, tag: str, source: str) -> None:
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise ValueError("expected a stable vX.Y.Z tag")
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("expected full source commit SHA")
    expected_dirs = {f"agent-lens-{name}" for name in PLATFORMS}
    if {path.name for path in input_dir.iterdir()} != expected_dirs:
        raise ValueError("missing or unexpected platform artifact")
    verified = []
    reports = []
    for target, arch in PLATFORMS.items():
        directory = input_dir / f"agent-lens-{target}"
        # upload-artifact preserves dist/ because reports share the repo root.
        packages = directory / "dist"
        name = f"agent-lens-{tag[1:]}-{target}-{arch}.zip"
        archive = packages / name
        if {p.name for p in packages.glob("*.zip")} != {name}:
            raise ValueError(f"unexpected package inventory: {target}")
        digest = sha256(archive)
        if (packages / "SHA256SUMS").read_text().splitlines() != [f"{digest}  {name}"]:
            raise ValueError(f"checksum mismatch: {target}")
        report = json.loads((directory / "build-provenance.json").read_text())
        if (report.get("source"), report.get("version"), report.get("platform"), report.get("architecture")) != (source, tag[1:], target, arch):
            raise ValueError(f"source/version/platform provenance mismatch: {target}")
        if report.get("packages") != {name: digest}:
            raise ValueError(f"package provenance mismatch: {target}")
        if report.get("cargo_lock_sha256") != sha256(ROOT / "Cargo.lock"):
            raise ValueError(f"dependency provenance mismatch: {target}")
        verified.append((archive, digest))
        reports.append(report)
    # Complete validation precedes any output, so a partial input cannot be published.
    output_dir.mkdir(parents=True, exist_ok=False)
    for archive, _ in verified:
        shutil.copyfile(archive, output_dir / archive.name)
    (output_dir / "SHA256SUMS").write_text("".join(f"{digest}  {path.name}\n" for path, digest in verified))
    (output_dir / "build-provenance.json").write_text(json.dumps({
        "source": source, "tag": tag,
        "workflow_run": f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', 'magicsword-io/AI-Lens')}/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}",
        "builds": reports,
    }, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    record = commands.add_parser("provenance")
    record.add_argument("--output", required=True, type=Path)
    release = commands.add_parser("prepare")
    release.add_argument("--input", required=True, type=Path)
    release.add_argument("--output", required=True, type=Path)
    release.add_argument("--tag", required=True)
    release.add_argument("--source", required=True)
    args = parser.parse_args()
    if args.command == "provenance":
        provenance(args.output)
    else:
        prepare(args.input, args.output, args.tag, args.source)


if __name__ == "__main__":
    main()

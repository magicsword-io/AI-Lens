#!/usr/bin/env python3
"""Package a native build and public documentation using only Python's stdlib."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
NATIVE_FILES = {
    "linux": ("agent-lens", "libagent_lens_engine.so"),
    "windows": ("agent-lens.exe", "agent_lens_engine.dll"),
    "macos": ("agent-lens", "libagent_lens_engine.dylib"),
}
PUBLIC_FILES = (
    "README.md",
    "LICENSE",
    "CONTRIBUTING.md",
    "NOTICE",
    "docs/architecture.md",
    "docs/rules.md",
    "docs/siem.md",
    "examples/rules/default.yaml",
    "examples/rule-cases.json",
)


def native_platform() -> str:
    names = {"Linux": "linux", "Windows": "windows", "Darwin": "macos"}
    try:
        return names[platform.system()]
    except KeyError as exc:
        raise ValueError("supported hosts are Linux, Windows, and macOS") from exc


def architecture() -> str:
    machine = platform.machine().lower()
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)


def safe_component(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", value):
        raise argparse.ArgumentTypeError("use letters, digits, '.', '_', '+', or '-'")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def workspace_version() -> str:
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
        cwd=ROOT, capture_output=True, text=True, timeout=30, check=True,
    )
    packages = json.loads(result.stdout)["packages"]
    for package in packages:
        if package["name"] == "agent-lens":
            return safe_component(package["version"])
    raise ValueError("workspace does not contain the agent-lens executable package")


def inputs(build_dir: Path, target_platform: str) -> list[tuple[Path, str]]:
    files = [(build_dir / name, name) for name in NATIVE_FILES[target_platform]]
    files.extend((ROOT / name, name) for name in PUBLIC_FILES)
    # Additional public Markdown docs, such as adapter coverage, ship as well.
    known = set(PUBLIC_FILES)
    files.extend(
        (path, path.relative_to(ROOT).as_posix())
        for path in sorted((ROOT / "docs").rglob("*.md"))
        if path.relative_to(ROOT).as_posix() not in known
    )
    files.extend(
        (path, path.relative_to(ROOT).as_posix())
        for path in sorted((ROOT / "docs" / "evidence").glob("*.json"))
    )
    files.extend(
        (path, path.relative_to(ROOT).as_posix())
        for path in sorted((ROOT / "examples" / "rules").glob("*.yaml"))
        if path.relative_to(ROOT).as_posix() not in known
    )
    files.extend(
        (path, path.relative_to(ROOT).as_posix())
        for path in sorted((ROOT / "examples" / "events").glob("*.json"))
    )
    files.extend(
        (path, path.relative_to(ROOT).as_posix())
        for path in sorted((ROOT / "examples" / "telemetry").rglob("*"))
        if path.is_file() and path.suffix in {".json", ".toml", ".yaml", ".env", ".py"}
    )
    files.extend(
        (path, path.relative_to(ROOT).as_posix())
        for path in sorted((ROOT / "examples" / "cowork-plugin").rglob("*"))
        if path.is_file() and path.suffix in {".json", ".md"}
    )
    for source, _ in files:
        if source.is_symlink() or not source.is_file() or source.stat().st_size == 0:
            raise ValueError(f"missing, empty, or symlinked package input: {source}")
    return files


def create_archive(
    output_dir: Path, name: str, files: list[tuple[Path, str]], executable: str
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f"{name}.zip"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=output_dir, suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for source, relative in sorted(files, key=lambda item: item[1]):
                entry = zipfile.ZipInfo(f"{name}/{relative}", date_time=(1980, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.compress_type = zipfile.ZIP_DEFLATED
                mode = 0o755 if relative == executable else 0o644
                entry.external_attr = (stat.S_IFREG | mode) << 16
                bundle.writestr(entry, source.read_bytes())
        os.replace(temporary, archive)
        temporary = None
        return archive
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def write_checksums(output_dir: Path) -> Path:
    manifest = output_dir / "SHA256SUMS"
    entries = sorted(output_dir.glob("agent-lens-*.zip"))
    lines = "".join(f"{sha256(path)}  {path.name}\n" for path in entries)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=output_dir,
            suffix=".tmp", delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(lines)
        os.replace(temporary, manifest)
        temporary = None
        return manifest
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "target" / "release")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    parser.add_argument(
        "--platform", choices=tuple(NATIVE_FILES),
        help="artifact platform (defaults to this host; does not cross-compile)"
    )
    parser.add_argument("--arch", type=safe_component, help="artifact architecture label")
    args = parser.parse_args()
    try:
        version = workspace_version()
        target_platform = args.platform or native_platform()
        arch = safe_component(args.arch or architecture())
        files = inputs(args.build_dir, target_platform)
        name = f"agent-lens-{version}-{target_platform}-{arch}"
        archive = create_archive(args.output_dir, name, files, NATIVE_FILES[target_platform][0])
        manifest = write_checksums(args.output_dir)
    except (OSError, ValueError, KeyError, argparse.ArgumentTypeError, subprocess.SubprocessError) as exc:
        print(f"package: {exc}", file=sys.stderr)
        return 1
    print(archive)
    print(manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Bundle a verified local Linux x64 AI Lens release ZIP as a Cowork cloud plugin."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MAX_ARCHIVE = 100 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_MEMBER = 64 * 1024 * 1024
MAX_MEMBERS = 512
EVENTS = ("SessionStart", "SessionEnd", "PreToolUse", "PostToolUse", "PostToolUseFailure")
SELECTED = {
    "agent-lens": "scripts/runtime/linux-x86_64/agent-lens",
    "libagent_lens_engine.so": "scripts/runtime/linux-x86_64/libagent_lens_engine.so",
    "examples/rules/default.yaml": "scripts/rules.yaml",
    "LICENSE": "LICENSE",
    "NOTICE": "NOTICE",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_release(archive: Path, expected: str) -> tuple[str, dict[str, bytes], dict]:
    if not re.fullmatch(r"[a-fA-F0-9]{64}", expected):
        raise ValueError("--sha256 must be the published 64-character SHA-256")
    match = re.fullmatch(r"agent-lens-([0-9]+\.[0-9]+\.[0-9]+)-linux-x86_64\.zip", archive.name)
    if not match:
        raise ValueError("input must be an agent-lens-VERSION-linux-x86_64.zip release")
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("release must be a regular non-symlinked ZIP no larger than 100 MiB")
    with archive.open("rb") as stream:
        raw = stream.read(MAX_ARCHIVE + 1)
    if len(raw) > MAX_ARCHIVE:
        raise ValueError("release exceeds the 100 MiB compressed-size limit")
    actual = digest(raw)
    if actual != expected.lower():
        raise ValueError("release SHA-256 does not match --sha256")
    selected = {}
    members = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
        entries = bundle.infolist()
        if len(entries) > MAX_MEMBERS or sum(i.file_size for i in entries) > MAX_TOTAL:
            raise ValueError("release exceeds member count or total expanded-size limit")
        for entry in entries:
            name = entry.filename
            path = PurePosixPath(name)
            mode = entry.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if (not name or "\\" in name or "\x00" in name or path.is_absolute()
                or any(part in ("", ".", "..") for part in name.rstrip("/").split("/"))
                or path.parts[0] != archive.stem or name in members
                or kind not in (0, stat.S_IFREG, stat.S_IFDIR)
                or (kind == stat.S_IFDIR) != entry.is_dir() and kind != 0
                or entry.flag_bits & 1 or entry.file_size > MAX_MEMBER):
                raise ValueError(f"unsafe, duplicate, encrypted, or oversized ZIP member: {name!r}")
            members[name] = entry
        for relative, target in SELECTED.items():
            key = f"{archive.stem}/{relative}"
            entry = members.get(key)
            if entry is None or entry.is_dir() or not entry.file_size:
                raise ValueError(f"missing or empty required release member: {relative}")
            with bundle.open(entry) as stream:
                data = stream.read(MAX_MEMBER + 1)
            if len(data) != entry.file_size or len(data) > MAX_MEMBER:
                raise ValueError(f"invalid expanded release member: {relative}")
            selected[target] = data
    provenance = {
        "release_archive": archive.name,
        "release_archive_sha256": actual,
        "runtime": "Linux x86_64",
        "release_members": {key: digest(value) for key, value in selected.items()},
    }
    return match.group(1), selected, provenance


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def package(archive: Path, expected: str, output: Path) -> dict:
    version, files, provenance = read_release(archive, expected)
    template = ROOT / "examples/cowork-plugin/scripts/lens-hook.sh"
    files["scripts/lens-hook.sh"] = template.read_bytes().replace(
        b"@SOURCE_SHA256@", provenance["release_archive_sha256"].encode()
    )
    manifest = json.loads((ROOT / "examples/cowork-plugin/.claude-plugin/plugin.json").read_text())
    manifest["version"] = version
    files[".claude-plugin/plugin.json"] = json_bytes(manifest)
    hooks = {}
    for event in EVENTS:
        command = {
            "type": "command", "command": "/bin/sh",
            "args": ["${CLAUDE_PLUGIN_ROOT}/scripts/lens-hook.sh", event], "timeout": 30,
        }
        if event == "PreToolUse":
            command["onFailure"] = "block"
        hooks[event] = [{"matcher": ".*", "hooks": [command]}]
    files["hooks/hooks.json"] = json_bytes({"hooks": hooks})
    provenance["plugin_members"] = {key: digest(value) for key, value in sorted(files.items())}
    files["scripts/provenance.json"] = json_bytes(provenance)
    files["README.md"] = (ROOT / "examples/cowork-plugin/README.md").read_bytes()
    output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation preserves an existing archive, including a symlink target.
    created = False
    try:
        with output.open("xb") as stream:
            created = True
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
                for name, data in sorted(files.items()):
                    entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    entry.create_system = 3
                    entry.compress_type = zipfile.ZIP_DEFLATED
                    mode = 0o755 if name in ("scripts/lens-hook.sh", SELECTED["agent-lens"]) else 0o644
                    entry.external_attr = (stat.S_IFREG | mode) << 16
                    bundle.writestr(entry, data)
    except Exception:
        if created:
            output.unlink(missing_ok=True)
        raise
    return {"archive": str(output), "sha256": digest(output.read_bytes()), **provenance}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-zip", type=Path, required=True)
    parser.add_argument("--sha256", required=True, help="copy the ZIP's hash from the release SHA256SUMS")
    parser.add_argument("--output", type=Path, required=True, help="new plugin ZIP path; existing files are refused")
    args = parser.parse_args()
    try:
        result = package(args.release_zip, args.sha256, args.output)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        print(f"Cowork packaging failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

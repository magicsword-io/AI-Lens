#!/usr/bin/env python3
"""Cowork release promotion preserves the native gates and rejects incomplete inputs."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

import package_cowork_release as cowork
import release_artifacts


class CoworkReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lens-cowork-release-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = self.root / "input"
        self.inputs.mkdir()
        self.assets = self.root / "assets"
        self.source = cowork.current_source()
        self.tag = "v0.3.1"
        for platform, arch in release_artifacts.PLATFORMS.items():
            directory = self.inputs / f"agent-lens-{platform}"
            dist = directory / "dist"
            dist.mkdir(parents=True)
            name = f"agent-lens-{self.tag[1:]}-{platform}-{arch}.zip"
            archive = dist / name
            with zipfile.ZipFile(archive, "w") as bundle:
                if platform == "linux":
                    for relative in cowork.package_cowork_plugin.SELECTED:
                        bundle.writestr(f"{archive.stem}/{relative}", b"synthetic " + relative.encode())
                else:
                    bundle.writestr(f"{archive.stem}/fixture", b"synthetic native fixture")
            digest = release_artifacts.sha256(archive)
            (dist / "SHA256SUMS").write_text(f"{digest}  {name}\n")
            (directory / "build-provenance.json").write_text(json.dumps({
                "source": self.source, "version": self.tag[1:], "platform": platform,
                "architecture": arch, "packages": {name: digest},
                "cargo_lock_sha256": release_artifacts.dependency_sha256(),
            }))
        # Exercise the actual three-platform preparation seam before adding Cowork.
        release_artifacts.prepare(self.inputs, self.assets, self.tag, self.source)
        self.original_manifest = (self.assets / "SHA256SUMS").read_bytes()
        self.original_provenance = (self.assets / "build-provenance.json").read_bytes()
        self.original_files = {p.name: p.read_bytes() for p in self.assets.iterdir()}

    def run_prepare(self):
        return cowork.prepare(self.assets, self.tag, self.source)

    def assert_no_plugin(self):
        self.assertFalse((self.assets / "ai-lens-cowork-0.3.1.zip").exists())
        self.assertFalse((self.assets / "cowork-plugin-provenance.json").exists())
        self.assertEqual((self.assets / "SHA256SUMS").read_bytes(), self.original_manifest)

    def test_adds_fourth_zip_with_complete_bound_provenance(self):
        report = self.run_prepare()
        self.assertEqual(report["source"], self.source)
        self.assertEqual(report["tag"], self.tag)
        self.assertEqual((self.assets / "build-provenance.json").read_bytes(), self.original_provenance)
        for name, data in self.original_files.items():
            if name != "SHA256SUMS":
                self.assertEqual((self.assets / name).read_bytes(), data)
        checksums = (self.assets / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(checksums), 4)
        archive = self.assets / report["plugin_zip"]["name"]
        self.assertEqual(report["plugin_zip"]["sha256"], release_artifacts.sha256(archive))
        self.assertEqual(checksums[-1], f"{report['plugin_zip']['sha256']}  {archive.name}")
        with zipfile.ZipFile(archive) as bundle:
            self.assertEqual(set(report["members_sha256"]), set(bundle.namelist()))
            for member, digest in report["members_sha256"].items():
                self.assertEqual(hashlib.sha256(bundle.read(member)).hexdigest(), digest)
            self.assertEqual(report["launcher_sha256"], report["members_sha256"]["scripts/lens-hook.sh"])
            self.assertEqual(json.loads(bundle.read(".claude-plugin/plugin.json"))["version"], "0.3.1")
        for name, digest in report["helper_sha256"].items():
            self.assertEqual(digest, release_artifacts.sha256(release_artifacts.ROOT / name))
        self.assertEqual(report["source_zip"]["sha256"], release_artifacts.sha256(self.assets / report["source_zip"]["name"]))
        self.assertEqual(json.loads((self.assets / "cowork-plugin-provenance.json").read_text()), report)

    def test_missing_platform_is_not_publishable(self):
        next(self.assets.glob("*windows*.zip")).unlink()
        with self.assertRaisesRegex(ValueError, "three-platform"):
            self.run_prepare()
        self.assert_no_plugin()

    def test_corrupt_linux_zip_rejected_before_packaging(self):
        next(self.assets.glob("*linux*.zip")).write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.run_prepare()
        self.assert_no_plugin()

    def test_checksum_missing_or_duplicate_rejected(self):
        lines = self.original_manifest.decode().splitlines()
        for content in ("\n".join(lines[:-1]) + "\n", "\n".join(lines + [lines[0]]) + "\n"):
            with self.subTest(content=content):
                (self.assets / "SHA256SUMS").write_text(content)
                with self.assertRaises(ValueError):
                    self.run_prepare()
                self.assertFalse((self.assets / "ai-lens-cowork-0.3.1.zip").exists())
        (self.assets / "SHA256SUMS").write_bytes(self.original_manifest)

    def test_source_and_platform_provenance_mismatch(self):
        path = self.assets / "build-provenance.json"
        for mutate in (lambda p: p.update(source="f" * 40),
                       lambda p: p["builds"][0].update(architecture="wrong"),
                       lambda p: p.update(builds=p["builds"][:2])):
            report = json.loads(self.original_provenance)
            mutate(report)
            path.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, "provenance"):
                self.run_prepare()
            self.assert_no_plugin()

    def test_checkout_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError, "checkout"):
            cowork.prepare(self.assets, self.tag, "0" * 40)
        self.assert_no_plugin()

    def test_reexecution_never_replaces_published_candidate(self):
        self.run_prepare()
        before = {p.name: p.read_bytes() for p in self.assets.iterdir()}
        with self.assertRaisesRegex(ValueError, "prepared"):
            self.run_prepare()
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.assets.iterdir()})

    def test_packaging_failure_preserves_native_set(self):
        with mock.patch.object(cowork.package_cowork_plugin, "package", side_effect=ValueError("fixture package failure")):
            with self.assertRaisesRegex(ValueError, "fixture"):
                self.run_prepare()
        self.assertEqual(self.original_files, {p.name: p.read_bytes() for p in self.assets.iterdir()})

    def test_manifest_commit_failure_rolls_back_added_files(self):
        with mock.patch.object(cowork.os, "replace", side_effect=OSError("fixture manifest failure")):
            with self.assertRaisesRegex(OSError, "fixture"):
                self.run_prepare()
        self.assertEqual(self.original_files, {p.name: p.read_bytes() for p in self.assets.iterdir()})

    def test_symlink_native_asset_rejected(self):
        archive = next(self.assets.glob("*linux*.zip"))
        actual = self.root / "outside.zip"
        archive.rename(actual)
        archive.symlink_to(actual)
        with self.assertRaisesRegex(ValueError, "non-symlinked"):
            self.run_prepare()
        self.assert_no_plugin()


if __name__ == "__main__":
    unittest.main()

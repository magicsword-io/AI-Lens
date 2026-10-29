#!/usr/bin/env python3
"""Release promotion rejects incomplete or mismatched native artifact sets."""

import json
from pathlib import Path
import tempfile
import unittest

from release_artifacts import PLATFORMS, ROOT, prepare, sha256


class ReleaseArtifactsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lens-release-test-")
        self.addCleanup(self.temp.cleanup)
        self.input = Path(self.temp.name) / "input"
        self.input.mkdir()
        self.output = Path(self.temp.name) / "output"
        self.source = "a" * 40
        for target, arch in PLATFORMS.items():
            directory = self.input / f"agent-lens-{target}"
            directory.mkdir()
            packages = directory / "dist"
            packages.mkdir()
            name = f"agent-lens-0.3.0-{target}-{arch}.zip"
            archive = packages / name
            archive.write_bytes(b"synthetic package " + target.encode())
            digest = sha256(archive)
            (packages / "SHA256SUMS").write_text(f"{digest}  {name}\n")
            (directory / "build-provenance.json").write_text(json.dumps({
                "source": self.source, "version": "0.3.0", "platform": target,
                "architecture": arch, "packages": {name: digest},
                "cargo_lock_sha256": sha256(ROOT / "Cargo.lock"),
            }))

    def run_prepare(self):
        prepare(self.input, self.output, "v0.3.0", self.source)

    def change_report(self, **changes):
        path = self.input / "agent-lens-linux/build-provenance.json"
        data = json.loads(path.read_text())
        data.update(changes)
        path.write_text(json.dumps(data))

    def assert_rejected(self, reason):
        with self.assertRaisesRegex(ValueError, reason):
            self.run_prepare()
        self.assertFalse(self.output.exists(), "partial publishable output created")

    def test_complete_release(self):
        self.run_prepare()
        self.assertEqual(len(list(self.output.glob("*.zip"))), 3)
        self.assertEqual(len((self.output / "SHA256SUMS").read_text().splitlines()), 3)
        report = json.loads((self.output / "build-provenance.json").read_text())
        self.assertEqual(report["source"], self.source)
        self.assertEqual(len(report["builds"]), 3)

    def test_missing_platform(self):
        (self.input / "agent-lens-windows").rename(self.input / "unexpected")
        self.assert_rejected("platform artifact")

    def test_corrupt_package(self):
        next((self.input / "agent-lens-linux/dist").glob("*.zip")).write_bytes(b"corrupt")
        self.assert_rejected("checksum mismatch")

    def test_wrong_source(self):
        self.change_report(source="b" * 40)
        self.assert_rejected("provenance mismatch")

    def test_wrong_architecture(self):
        self.change_report(architecture="aarch64")
        self.assert_rejected("provenance mismatch")

    def test_wrong_dependency_revision(self):
        self.change_report(cargo_lock_sha256="0" * 64)
        self.assert_rejected("dependency provenance mismatch")

    def test_wrong_package_provenance(self):
        self.change_report(packages={"other.zip": "0" * 64})
        self.assert_rejected("package provenance mismatch")

    def test_extra_package(self):
        (self.input / "agent-lens-linux/dist/extra.zip").write_bytes(b"extra")
        self.assert_rejected("package inventory")


if __name__ == "__main__":
    unittest.main()

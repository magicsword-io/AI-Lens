#!/usr/bin/env python3
"""Local package/launcher regressions; these do not claim installed Cowork acceptance."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("package_cowork_plugin", ROOT / "scripts/package_cowork_plugin.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lens-cowork-package-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "agent-lens-0.3.0-linux-x86_64.zip"
        self.output = self.root / "plugin.zip"
        self.files = {name: ("fixture " + name).encode() for name in module.SELECTED}

    def source(self, extra=(), missing=None):
        with zipfile.ZipFile(self.archive, "w") as bundle:
            for name, data in self.files.items():
                if name != missing:
                    bundle.writestr(f"{self.archive.stem}/{name}", data)
            for name, mode in extra:
                entry = zipfile.ZipInfo(name)
                entry.create_system = 3
                entry.external_attr = mode << 16
                bundle.writestr(entry, b"bad")
        return hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def test_package_preserves_runtime_and_failure_contract(self):
        expected = self.source()
        report = module.package(self.archive, expected, self.output)
        with zipfile.ZipFile(self.output) as bundle:
            self.assertNotIn("bin/", bundle.namelist())
            for source, destination in module.SELECTED.items():
                self.assertEqual(bundle.read(destination), self.files[source])
            hooks = json.loads(bundle.read("hooks/hooks.json"))["hooks"]
            self.assertEqual(set(hooks), set(module.EVENTS))
            for event, configs in hooks.items():
                self.assertEqual(configs[0]["matcher"], ".*")
                command = configs[0]["hooks"][0]
                self.assertEqual(command["timeout"], 30)
                self.assertEqual(command["args"][-1], event)
                self.assertEqual(command.get("onFailure"), "block" if event == "PreToolUse" else None)
            provenance = json.loads(bundle.read("scripts/provenance.json"))
            self.assertEqual(provenance["release_archive_sha256"], expected)
            self.assertEqual(report["sha256"], hashlib.sha256(self.output.read_bytes()).hexdigest())
            for name, digest in provenance["plugin_members"].items():
                self.assertEqual(hashlib.sha256(bundle.read(name)).hexdigest(), digest)
            launcher = self.root / "launcher.sh"
            launcher.write_bytes(bundle.read("scripts/lens-hook.sh"))
            subprocess.run(["/bin/sh", "-n", str(launcher)], check=True)

    def test_mismatch_and_existing_output_preserved(self):
        expected = self.source()
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            module.package(self.archive, "0" * 64, self.output)
        self.output.write_bytes(b"existing")
        with self.assertRaises(FileExistsError):
            module.package(self.archive, expected, self.output)
        self.assertEqual(self.output.read_bytes(), b"existing")

    def test_unsafe_paths_and_special_files(self):
        for name, mode in [
            ("/absolute", stat.S_IFREG | 0o644),
            (f"{self.archive.stem}/../escape", stat.S_IFREG | 0o644),
            (f"{self.archive.stem}/scripts\\evil", stat.S_IFREG | 0o644),
            (f"{self.archive.stem}/link", stat.S_IFLNK | 0o777),
            (f"{self.archive.stem}/device", stat.S_IFCHR | 0o600),
            (f"{self.archive.stem}/agent-lens", stat.S_IFREG | 0o644),
        ]:
            with self.subTest(name=name):
                expected = self.source([(name, mode)])
                with self.assertRaisesRegex(ValueError, "unsafe"):
                    module.package(self.archive, expected, self.output)
                self.assertFalse(self.output.exists())

    def test_required_member_and_bounds(self):
        expected = self.source(missing="libagent_lens_engine.so")
        with self.assertRaisesRegex(ValueError, "missing"):
            module.package(self.archive, expected, self.output)
        expected = self.source()
        old = module.MAX_MEMBERS
        module.MAX_MEMBERS = 1
        try:
            with self.assertRaisesRegex(ValueError, "member count"):
                module.package(self.archive, expected, self.output)
        finally:
            module.MAX_MEMBERS = old

    def test_member_and_total_expansion_limits(self):
        expected = self.source()
        for limit in ("MAX_MEMBER", "MAX_TOTAL", "MAX_ARCHIVE"):
            with self.subTest(limit=limit):
                old = getattr(module, limit)
                setattr(module, limit, 1)
                try:
                    with self.assertRaises(ValueError):
                        module.package(self.archive, expected, self.output)
                    self.assertFalse(self.output.exists())
                finally:
                    setattr(module, limit, old)

    def test_wrong_platform_and_symlink_input(self):
        expected = self.source()
        wrong = self.root / "agent-lens-0.3.0-windows-x86_64.zip"
        shutil.copyfile(self.archive, wrong)
        with self.assertRaisesRegex(ValueError, "linux-x86_64"):
            module.package(wrong, expected, self.output)
        real = self.root / "real.zip"
        self.archive.rename(real)
        self.archive.symlink_to(real)
        with self.assertRaisesRegex(ValueError, "non-symlinked"):
            module.package(self.archive, expected, self.output)


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lens-cowork-launcher-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plugin = self.root / "plugin with spaces"
        runtime_bin = self.plugin / "scripts/runtime/linux-x86_64"
        runtime_bin.mkdir(parents=True)
        self.tmp = self.root / "runtime-tmp"
        self.tmp.mkdir()
        self.bin = self.root / "commands"
        self.bin.mkdir()
        self.env = {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"]}
        self.command("uname", '#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo x86_64;; esac\n')
        self.command("stat", f'''#!/usr/bin/env python3
import os,sys
p=sys.argv[-1]
if p=={str(self.tmp)!r}: print('0' if sys.argv[2]=='%u' else '1777')
else:
 s=os.stat(p,follow_symlinks=False)
 print(s.st_uid if sys.argv[2]=='%u' else oct(s.st_mode & 0o7777)[2:])
''')
        if shutil.which("sha256sum") is None:
            self.command("sha256sum", '#!/usr/bin/env python3\nimport sys,hashlib\nprint(hashlib.sha256(sys.stdin.buffer.read()).hexdigest()+"  -")\n')
        self.lens = runtime_bin / "agent-lens"
        self.lens.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
state=Path(sys.argv[sys.argv.index('--state')+1]); config=state/'config.json'
if 'start' in sys.argv:
 config.write_text('{"enabled":true}'); config.chmod(0o600)
 with (state.parent/'start-count').open('a') as f: f.write('start\\n')
 print('startup stdout must be suppressed')
else:
 payload=sys.stdin.read()
 print(json.dumps({'enabled':json.loads(config.read_text())['enabled'],'payload':payload}))
''')
        self.lens.chmod(0o755)
        (runtime_bin / "libagent_lens_engine.so").write_bytes(b"fixture")
        (self.plugin / "scripts/rules.yaml").write_text("fixture")
        self.launcher = self.plugin / "scripts/lens-hook.sh"
        text = (ROOT / "examples/cowork-plugin/scripts/lens-hook.sh").read_text()
        text = text.replace("/tmp", str(self.tmp)).replace("@SOURCE_SHA256@", "a" * 64)
        self.launcher.write_text(text)

    def command(self, name, script):
        path = self.bin / name
        path.write_text(script)
        path.chmod(0o755)

    def run_hook(self, event="PreToolUse"):
        return subprocess.run(["/bin/sh", str(self.launcher), event], input='{"tool_name":"Write"}\n',
                              text=True, capture_output=True, env=self.env, timeout=15)

    def test_callback_stdin_clean_stdout_and_disabled_state(self):
        first = self.run_hook()
        self.assertEqual(first.returncode, 0, first.stderr)
        report = json.loads(first.stdout)
        self.assertEqual(report, {"enabled": True, "payload": '{"tool_name":"Write"}\n'})
        runtime = next(self.tmp.glob("ai-lens-cowork-*"))
        config = runtime / "state/config.json"
        config.write_text('{"enabled":false}')
        second = self.run_hook()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertFalse(json.loads(second.stdout)["enabled"])
        self.assertEqual((runtime / "start-count").read_text(), "start\n")
        config.unlink()
        missing = self.run_hook()
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("refusing to restart", missing.stderr)

    def test_existing_unsafe_directory_and_symlink_rejected(self):
        self.assertEqual(self.run_hook().returncode, 0)
        runtime = next(self.tmp.glob("ai-lens-cowork-*"))
        runtime.chmod(0o755)
        denied = self.run_hook()
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("0700", denied.stderr)
        runtime.chmod(0o700)
        config = runtime / "state/config.json"
        config.unlink()
        config.symlink_to(self.root / "outside")
        denied = self.run_hook()
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("unsafe state config", denied.stderr)
        self.assertFalse((self.root / "outside").exists())

    def test_symlink_output_and_unsafe_config_mode_rejected(self):
        self.assertEqual(self.run_hook().returncode, 0)
        runtime = next(self.tmp.glob("ai-lens-cowork-*"))
        config = runtime / "state/config.json"
        config.chmod(0o644)
        denied = self.run_hook()
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("0600", denied.stderr)
        config.chmod(0o600)
        outside = self.root / "outside-log"
        (runtime / "events.jsonl").symlink_to(outside)
        denied = self.run_hook()
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("unsafe runtime file", denied.stderr)
        self.assertFalse(outside.exists())

    def test_wrong_event_and_platform_fail_without_stdout(self):
        wrong = self.run_hook("NotAnEvent")
        self.assertNotEqual(wrong.returncode, 0)
        self.assertEqual(wrong.stdout, "")
        self.command("uname", '#!/bin/sh\necho Darwin\n')
        wrong = self.run_hook()
        self.assertNotEqual(wrong.returncode, 0)
        self.assertIn("Linux x86_64", wrong.stderr)
        self.assertEqual(wrong.stdout, "")


if __name__ == "__main__":
    unittest.main()

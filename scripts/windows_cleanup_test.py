#!/usr/bin/env python3
"""Regression for transient Windows mapped-file cleanup, without hiding failures."""
import pathlib
import shutil
import tempfile
import unittest
from unittest.mock import patch

import windows_cleanup as cleanup


def denied(winerror=5):
    error = PermissionError('synthetic cleanup denial')
    error.winerror = winerror
    return error


class Clock:
    def __init__(self):
        self.value = 0
        self.waits = []

    def now(self):
        return self.value

    def sleep(self, delay):
        self.waits.append(delay)
        self.value += delay


class WindowsCleanupTests(unittest.TestCase):
    def test_transient_errors_remove_real_file(self):
        for code in (5, 32):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                file = pathlib.Path(directory) / 'artifact.exe'
                file.write_bytes(b'synthetic')
                clock = Clock()
                attempts = []

                def remove():
                    attempts.append(file.exists())
                    if len(attempts) == 1:
                        raise denied(code)
                    file.unlink()

                cleanup.retry_cleanup(remove, platform='win32', clock=clock.now, sleep=clock.sleep)
                self.assertEqual(attempts, [True, True])
                self.assertFalse(file.exists())
                self.assertEqual(clock.waits, [0.05])

    def test_permanent_error_propagates_at_deadline(self):
        clock = Clock()
        error = denied()
        attempts = []

        def remove():
            attempts.append(clock.now())
            raise error

        with self.assertRaises(PermissionError) as raised:
            cleanup.retry_cleanup(remove, platform='win32', clock=clock.now, sleep=clock.sleep)
        self.assertIs(raised.exception, error)
        self.assertLessEqual(len(attempts), 20)
        self.assertLessEqual(sum(clock.waits), 1)
        self.assertAlmostEqual(clock.now(), 1)
        self.assertTrue(all(0 < delay <= 0.05 for delay in clock.waits))

    def test_other_platform_or_error_never_retries(self):
        for platform, error in [('darwin', denied()), ('linux', denied(32)),
                                ('win32', denied(13)), ('win32', OSError('other'))]:
            with self.subTest(platform=platform, error=error):
                clock = Clock()
                with self.assertRaises(type(error)) as raised:
                    cleanup.retry_cleanup(lambda: (_ for _ in ()).throw(error),
                                          platform=platform, clock=clock.now, sleep=clock.sleep)
                self.assertIs(raised.exception, error)
                self.assertEqual(clock.waits, [])

    def test_temp_directory_retries_after_finalizer_detaches(self):
        directory = cleanup.TemporaryDirectory()
        path = pathlib.Path(directory.name)
        (path / 'artifact.exe').write_bytes(b'synthetic')
        real_rmtree = tempfile.TemporaryDirectory._rmtree
        real_retry = cleanup.retry_cleanup
        attempts = []
        clock = Clock()

        def remove(name, *args, **kwargs):
            attempts.append(path.exists())
            if len(attempts) == 1:
                raise denied()
            return real_rmtree(name, *args, **kwargs)

        try:
            with patch.object(tempfile.TemporaryDirectory, '_rmtree', side_effect=remove), \
                 patch.object(cleanup, 'retry_cleanup', side_effect=lambda op: real_retry(
                     op, platform='win32', clock=clock.now, sleep=clock.sleep)):
                directory.cleanup()
            self.assertEqual(attempts, [True, True])
            self.assertFalse(path.exists())
            self.assertFalse(directory._finalizer.alive)
        finally:
            if path.exists():
                shutil.rmtree(path)


    def test_python39_detached_cleanup_removes_remainder(self):
        self.check_python39_cleanup(permanent=False)

    def test_python39_detached_cleanup_propagates_permanent_failure(self):
        self.check_python39_cleanup(permanent=True)

    def check_python39_cleanup(self, permanent):
        directory = cleanup.TemporaryDirectory()
        path = pathlib.Path(directory.name)
        (path / 'artifact.exe').write_bytes(b'synthetic')
        real_retry = cleanup.retry_cleanup
        real_rmtree = shutil.rmtree
        error = denied()
        clock = Clock()
        attempts = []

        def legacy_cleanup(instance):
            # CPython 3.9 only attempts removal while detaching the finalizer.
            if instance._finalizer.detach():
                attempts.append('super')
                raise error

        def fallback(name):
            attempts.append('remainder')
            self.assertTrue(path.exists())
            if permanent:
                raise error
            real_rmtree(name)

        try:
            with patch.object(tempfile.TemporaryDirectory, 'cleanup', legacy_cleanup), \
                 patch.object(shutil, 'rmtree', side_effect=fallback), \
                 patch.object(cleanup, 'retry_cleanup', side_effect=lambda op: real_retry(
                     op, platform='win32', clock=clock.now, sleep=clock.sleep)):
                if permanent:
                    with self.assertRaises(PermissionError) as raised:
                        directory.cleanup()
                    self.assertIs(raised.exception, error)
                    self.assertTrue(path.exists())
                    self.assertAlmostEqual(clock.now(), 1)
                else:
                    directory.cleanup()
                    self.assertFalse(path.exists())
            self.assertEqual(attempts.count('super'), 1)
            self.assertGreaterEqual(attempts.count('remainder'), 1)
        finally:
            if path.exists():
                real_rmtree(path)


if __name__ == '__main__':
    unittest.main()

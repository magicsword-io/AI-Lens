"""Bound Windows test-artifact cleanup retries after a child has exited."""
import os
import shutil
import sys
import tempfile
import time


def retry_cleanup(operation, *, platform=sys.platform, clock=time.monotonic, sleep=time.sleep):
    deadline = clock() + 1.0
    while True:
        try:
            return operation()
        except PermissionError as error:
            if platform != 'win32' or getattr(error, 'winerror', None) not in (5, 32):
                raise
            remaining = deadline - clock()
            if remaining <= 0:
                raise
            sleep(min(0.05, remaining))
            if clock() >= deadline:
                raise


class TemporaryDirectory(tempfile.TemporaryDirectory):
    def cleanup(self):
        def remove():
            super(TemporaryDirectory, self).cleanup()
            # Python 3.9's public cleanup becomes a no-op after detachment.
            # Retry deletion of our owned remainder rather than reporting success.
            if os.path.lexists(self.name):
                shutil.rmtree(self.name)

        retry_cleanup(remove)

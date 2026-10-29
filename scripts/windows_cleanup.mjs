/** Retry only a transient Windows refusal to unlink this exact test file. */
import { rmSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';

export async function removeFileWithRetry(file, {
  remove = rmSync, platform = process.platform, now = () => performance.now(), wait = delay,
} = {}) {
  const deadline = now() + 1000;
  for (;;) {
    try {
      return remove(file);
    } catch (error) {
      if (platform !== 'win32' || !['EPERM', 'EBUSY'].includes(error.code)) throw error;
      const remaining = deadline - now();
      if (remaining <= 0) throw error;
      await wait(Math.min(50, remaining));
      if (now() >= deadline) throw error;
    }
  }
}

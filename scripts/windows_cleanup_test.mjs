import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { removeFileWithRetry } from './windows_cleanup.mjs';

function clock() {
  let value = 0;
  const waits = [];
  return { now: () => value, waits, wait: async ms => { waits.push(ms); value += ms; } };
}

for (const code of ['EPERM', 'EBUSY']) {
  test(`${code} recovery unlinks only the exact file`, async () => {
    const base = mkdtempSync(path.join(tmpdir(), 'lens cleanup '));
    const file = path.join(base, 'engine.dll');
    const sibling = path.join(base, 'preserved.txt');
    writeFileSync(file, 'synthetic');
    writeFileSync(sibling, 'preserve');
    let calls = 0;
    const time = clock();
    try {
      await removeFileWithRetry(file, { platform: 'win32', ...time, remove: (...args) => {
        assert.deepEqual(args, [file]);
        if (++calls === 1) throw Object.assign(new Error('synthetic denial'), { code });
        rmSync(...args);
      } });
      assert.equal(calls, 2);
      assert.deepEqual(time.waits, [50]);
      assert.equal(existsSync(file), false);
      assert.equal(existsSync(sibling), true);
    } finally { rmSync(base, { recursive: true }); }
  });
}

test('permanent denial propagates the same error within one second', async () => {
  const time = clock();
  const error = Object.assign(new Error('permanent denial'), { code: 'EPERM' });
  let calls = 0;
  await assert.rejects(removeFileWithRetry('exact.dll', { platform: 'win32', ...time,
    remove: () => { ++calls; throw error; } }), value => value === error);
  assert.equal(time.now(), 1000);
  assert.equal(calls, 20);
  assert.equal(time.waits.reduce((a, b) => a + b, 0), 1000);
  assert.ok(time.waits.every(ms => ms === 50));
});

for (const [platform, code] of [['darwin', 'EPERM'], ['linux', 'EBUSY'], ['win32', 'ENOENT'], ['win32', 'EACCES']]) {
  test(`${platform}/${code} propagates without retry`, async () => {
    const time = clock();
    const error = Object.assign(new Error('unrelated'), { code });
    let calls = 0;
    await assert.rejects(removeFileWithRetry('exact.dll', { platform, ...time,
      remove: () => { ++calls; throw error; } }), value => value === error);
    assert.equal(calls, 1);
    assert.deepEqual(time.waits, []);
  });
}

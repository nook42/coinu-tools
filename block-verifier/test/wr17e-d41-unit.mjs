import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const tmp = await mkdtemp(path.join(os.tmpdir(), 'wr17e-d41-js-'));
try {
  const fixture = path.join(tmp, 'fixture.json');
  const script = new URL('./fixtures/d41/gen-band.mjs', import.meta.url);
  const result = spawnSync(process.env.NODE || process.execPath, [script.pathname, fixture], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const fx = JSON.parse(await readFile(fixture, 'utf8'));
  const status = (index, window) => fx.js[`${index}.${window}`];
  assert.deepEqual([1, 2, 3].map((i) => status(i, 'real')),
    ['accepted', 'invalid_signature', 'accepted']);
  assert.deepEqual([1, 2, 3].map((i) => status(i, 'short')),
    ['invalid_signature', 'invalid_signature', 'accepted']);
  assert.deepEqual([1, 2, 3].map((i) => status(i, 'long')),
    ['accepted', 'accepted', 'accepted']);
  assert.equal(fx.windows.real.endMs - fx.windows.short.endMs, 600_000);
  assert.equal(fx.windows.long.endMs - fx.windows.real.endMs, 600_000);
  assert.equal(fx.frames[0].eTs, fx.windows.real.endMs - 300_000);
  assert.equal(fx.frames[1].eTs, fx.windows.real.endMs + 300_000);
  assert(fx.frames[2].eTs > fx.windows.real.startMs && fx.frames[2].eTs < fx.windows.short.endMs);
  console.log('WR17E_D41_JS_OK frames=3 windows=3 directions=2');
} finally {
  await rm(tmp, { recursive: true, force: true });
}

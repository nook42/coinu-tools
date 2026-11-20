// R13-26: R2とZKPソースpackageの全UTF-8読込経路をfail-closedに固定する。
import os from 'node:os';
import path from 'node:path';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createR2 } from '../src/r2.js';
import { unpackGuestSource } from '../src/zkp.js';

let passed = 0;
let failed = 0;

function check(label, condition, detail = '') {
  if (condition) {
    passed++;
    console.log(`  ok: ${label}`);
  } else {
    failed++;
    console.error(`  FAIL: ${label}${detail ? ` — ${detail}` : ''}`);
  }
}

async function rejectsWith(label, fn, expected) {
  try {
    await fn();
    check(label, false, '例外にならなかった');
  } catch (error) {
    const message = error?.message || String(error);
    check(label, expected.every((part) => message.includes(part)), message);
  }
}

const ui = {
  t: (_key, params) => params?.error || _key,
  warn: () => {},
};
const dataDir = await mkdtemp(path.join(os.tmpdir(), 'bv-utf8-'));
const originalFetch = globalThis.fetch;
let fetchCalls = 0;

try {
  const invalid = Buffer.from([0xff]);
  const networkBodies = new Map([
    ['https://r2.invalid/network-invalid.json', invalid],
    ['https://r2.invalid/network-valid.json', Buffer.from('{"text":"日本語🎯"}', 'utf8')],
  ]);
  globalThis.fetch = async (url) => {
    fetchCalls++;
    const body = networkBodies.get(String(url));
    return body === undefined
      ? new Response(null, { status: 404 })
      : new Response(body, { status: 200, headers: { 'content-length': String(body.length) } });
  };

  const networkR2 = createR2({ r2Base: 'https://r2.invalid', dataDir }, ui, 0);
  await rejectsWith(
    'R2ネットワーク経路は不正UTF-8をキー名つきで拒否する',
    () => networkR2.fetchJson('network-invalid.json'),
    ['network-invalid.json', 'invalid UTF-8'],
  );
  check('R2ネットワーク経路は不正UTF-8を再試行しない', fetchCalls === 1, `fetchCalls=${fetchCalls}`);
  const networkValid = await networkR2.fetchJson('network-valid.json');
  check('R2ネットワーク経路は妥当なUTF-8を従来どおり読む', networkValid?.data?.text === '日本語🎯');

  const cacheDir = path.join(dataDir, 'block1');
  await mkdir(cacheDir, { recursive: true });
  await writeFile(path.join(cacheDir, 'cache-invalid.json'), invalid);
  await writeFile(path.join(cacheDir, 'cache-valid.json'), Buffer.from('{"text":"日本語🎯"}', 'utf8'));
  const cacheR2 = createR2({ r2Base: 'https://r2.invalid', dataDir }, ui, 1);
  const callsBeforeCache = fetchCalls;
  await rejectsWith(
    'R2キャッシュ経路は不正UTF-8をキー名つきで拒否する',
    () => cacheR2.fetchJson('cache-invalid.json', { reuse: true }),
    ['cache-invalid.json', 'invalid UTF-8'],
  );
  check('R2キャッシュ経路は不正UTF-8をネットワークへフォールバックしない', fetchCalls === callsBeforeCache);
  const cacheValid = await cacheR2.fetchJson('cache-valid.json', { reuse: true });
  check('R2キャッシュ経路は妥当なUTF-8を従来どおり読む', cacheValid?.data?.text === '日本語🎯');

  const invalidHeader = Buffer.concat([
    Buffer.from('bitcoinu-guest-source/'), invalid, Buffer.from('\n'),
  ]);
  await rejectsWith(
    'ZKP packageヘッダ経路は不正UTF-8を対象名つきで拒否する',
    () => unpackGuestSource(invalidHeader),
    ['guest source format header', 'invalid UTF-8'],
  );

  const sp1Image = `ghcr.io/succinctlabs/sp1@sha256:${'0'.repeat(64)}`;
  const invalidBody = Buffer.concat([
    Buffer.from(`bitcoinu-guest-source/1\nsp1-image\t${sp1Image}\nfile\tbad.rs\t1\n`, 'utf8'),
    invalid,
    Buffer.from('\n'),
  ]);
  await rejectsWith(
    'ZKPファイル本文経路は不正UTF-8をファイル名つきで拒否する',
    () => unpackGuestSource(invalidBody),
    ['bad.rs', 'invalid UTF-8'],
  );

  const validBody = Buffer.from('// 日本語🎯\n', 'utf8');
  const validPackage = Buffer.concat([
    Buffer.from(`bitcoinu-guest-source/1\nsp1-image\t${sp1Image}\nfile\tgood.rs\t${validBody.length}\n`, 'utf8'),
    validBody,
    Buffer.from('\n'),
  ]);
  const unpacked = unpackGuestSource(validPackage);
  check('ZKP経路は妥当なUTF-8を従来どおり読む', unpacked.files[0]?.content === '// 日本語🎯\n');
  check('ZKPファイル本文の生バイトを保持する', Buffer.from(unpacked.files[0]?.bytes || []).equals(validBody));
} finally {
  globalThis.fetch = originalFetch;
  await rm(dataDir, { recursive: true, force: true });
}

console.log(`\nr13-utf8-fail-closed-unit: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);

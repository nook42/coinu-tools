#!/usr/bin/env node

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { collectBundleInputDigest } from '../build/bundle.mjs';

const toolRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const signature = 'export function digestVendorTree(vendorRoot) {';

function functionSource(relativePath) {
  const lines = readFileSync(resolve(toolRoot, relativePath), 'utf8').split('\n');
  const hits = [];
  lines.forEach((line, index) => { if (line === signature) hits.push(index); });
  assert.equal(hits.length, 1, `${relativePath}: digestVendorTree signature must appear exactly once`);

  const start = hits[0];
  const end = lines.findIndex((line, index) => index > start && line === '}');
  assert.notEqual(end, -1, `${relativePath}: digestVendorTree closing brace not found`);
  return lines.slice(start, end + 1).join('\n');
}

const checker = functionSource('scripts/check-vendor-sync.mjs');
const bundler = functionSource('build/bundle.mjs');
assert.equal(
  checker,
  bundler,
  'digestVendorTree source text drifted: scripts/check-vendor-sync.mjs and build/bundle.mjs must be byte-identical',
);

console.log('PASS: digestVendorTree source text is byte-identical');

// T6: 依存一覧を手書きせず、esbuild が実際に取り込む2エントリの metafile から得る。
const bundleInputs = await collectBundleInputDigest();
assert.ok(bundleInputs.count >= 1000,
  `esbuild bundle input population unexpectedly small: ${bundleInputs.count}`);
assert.ok(Object.keys(bundleInputs.files).some((file) => file.startsWith('node_modules/')),
  'esbuild bundle inputs must include inlined node_modules dependencies');
assert.ok(Object.keys(bundleInputs.files).some((file) => file.startsWith('src/')),
  'esbuild bundle inputs must include chatgame-tools sources');

// 実ファイルは書き換えず、bundler が返した依存の1バイトだけを reader 境界で差し替える。
const dependency = Object.keys(bundleInputs.files).find((file) => file.startsWith('node_modules/'));
const mutatedInputs = await collectBundleInputDigest((abs, rel) => {
  const bytes = readFileSync(abs);
  return rel === dependency ? Buffer.concat([bytes, Buffer.from('\n// T6 dependency mutation\n')]) : bytes;
});
assert.notEqual(mutatedInputs.digest, bundleInputs.digest,
  `inlined dependency mutation did not change bundle input digest: ${dependency}`);
assert.notEqual(mutatedInputs.files[dependency], bundleInputs.files[dependency],
  `mutated dependency hash did not change: ${dependency}`);
console.log(`PASS: esbuild-derived ${bundleInputs.count} inputs include dependencies; mutation caught: ${dependency}`);

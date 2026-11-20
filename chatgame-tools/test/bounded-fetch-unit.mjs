// A5-03 / B6-03 / RA-02: 復元クライアント全域の外部読取が期限を持つことを固定する。
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { createHash, webcrypto } from 'node:crypto';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import { fetchBounded, fetchJsonBounded } from '../src/common/bounded-fetch.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SRC = path.join(ROOT, 'src');

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    return statSync(full).isDirectory() ? walk(full) : [full];
  });
}

const rawFetchSites = [];
for (const file of walk(SRC).filter((name) => name.endsWith('.js'))) {
  const source = readFileSync(file, 'utf8');
  if (/\bfetch\s*\(/.test(source)) rawFetchSites.push(path.relative(ROOT, file));
}
assert.deepEqual(rawFetchSites.sort(), [
  'src/common/bounded-fetch.js',
  'src/loader/sw.js',
], '生fetchは共通の有界ヘルパーとimport不能なService Worker内の同型ヘルパーだけ');

const boundedSource = readFileSync(path.join(SRC, 'common/bounded-fetch.js'), 'utf8');
const swSource = readFileSync(path.join(SRC, 'loader/sw.js'), 'utf8');
for (const [name, source] of [['common helper', boundedSource], ['service worker', swSource]]) {
  assert.match(source, /AbortController/, `${name}: AbortController`);
  assert.match(source, /Promise\.race/, `${name}: never-settleにも壁時計期限`);
  assert.match(source, /\bsignal\b/, `${name}: fetchへ中断signalを渡す`);
  assert.match(source, /arrayBuffer\(\)|json\(\)|text\(\)/, `${name}: body読取も期限内`);
}

// R20-X2-03: 実物の ServiceWorker ハンドラを Node の VM で起動し、ツール自身の
// 配布物だけが native fetch に委ねられ、本体アプリは引き続き manifest 検証を通ることを固定する。
const TOOL_ORIGIN = 'https://tools.example';
const BUNDLE_ORIGIN = 'https://bundle.example';
const appBytes = new TextEncoder().encode('<!doctype html><title>verified app</title>');
const appHash = createHash('sha256').update(appBytes).digest('hex');
const manifest = { buildVersion: '20', files: { '/index.html': appHash } };

function createSwHarness({ persistedState = null } = {}) {
  const listeners = new Map();
  let cachedState = persistedState;
  let upstreamFetches = 0;
  const messages = [];

  const cache = {
    async put(_key, response) { cachedState = await response.clone().json(); },
    async match() {
      return cachedState == null
        ? undefined
        : new Response(JSON.stringify(cachedState), { headers: { 'Content-Type': 'application/json' } });
    },
    async delete() { const existed = cachedState != null; cachedState = null; return existed; },
  };
  const self = {
    location: { origin: TOOL_ORIGIN },
    clients: { claim: async () => {} },
    skipWaiting() {},
    addEventListener(type, listener) { listeners.set(type, listener); },
  };
  vm.runInNewContext(swSource, {
    self,
    caches: { open: async () => cache },
    fetch: async (url) => {
      upstreamFetches += 1;
      assert.equal(String(url), `${BUNDLE_ORIGIN}/index.html`, '本体は指定された bundle origin だけから読む');
      return new Response(appBytes, { headers: { 'Content-Type': 'text/html' } });
    },
    AbortController,
    Headers,
    Request,
    Response,
    TextEncoder,
    URL,
    Uint8Array,
    clearTimeout,
    crypto: webcrypto,
    setTimeout,
  }, { filename: path.join(SRC, 'loader/sw.js') });

  return {
    async message(data) {
      const waits = [];
      listeners.get('message')({
        data,
        source: { postMessage(message) { messages.push(message); } },
        waitUntil(promise) { waits.push(Promise.resolve(promise)); },
      });
      await Promise.all(waits);
      return messages.at(-1);
    },
    async request(urlPath, { mode = 'cors' } = {}) {
      const request = new Request(`${TOOL_ORIGIN}${urlPath}`);
      Object.defineProperty(request, 'mode', { configurable: true, value: mode });
      let responsePromise = null;
      listeners.get('fetch')({
        request,
        respondWith(value) { responsePromise = Promise.resolve(value); },
      });
      return responsePromise ? responsePromise : null;
    },
    persistedState: () => cachedState,
    upstreamFetches: () => upstreamFetches,
  };
}

const installed = createSwHarness();
const installedMessage = await installed.message({
  type: 'INSTALL_MANIFEST', manifest, bundleOrigin: BUNDLE_ORIGIN, csp: "default-src 'self'",
});
assert.equal(installedMessage?.type, 'MANIFEST_INSTALLED', 'manifest の永続化完了後に応答する');
assert.equal(installedMessage?.fileCount, 1, '永続化した manifest のファイル数を応答する');

const toolPaths = [
  '/index.html',
  '/loader.bundle.js',
  '/recovery.html',
  '/recovery.bundle.js',
  '/sw.js',
  '/build-info.json',
];
const bypassFailures = [];
for (const toolPath of toolPaths) {
  const response = await installed.request(toolPath, { mode: toolPath.endsWith('.html') ? 'navigate' : 'cors' });
  if (response !== null) bypassFailures.push(`${toolPath}: SW response status=${response.status}`);
}
assert.deepEqual(bypassFailures, [],
  `ツール自身の配布物だけを SW 横取りから外す:\n${bypassFailures.join('\n')}`);

const verifiedApp = await installed.request('/', { mode: 'navigate' });
assert.equal(verifiedApp.status, 200, '本体ルートは allowlist に入れず検証配信する');
assert.equal(verifiedApp.headers.get('X-Verified-Build'), '20', '本体ルートに検証済み build version を付ける');
assert.equal(installed.upstreamFetches(), 1, 'ツール6ファイルは upstream 本体 fetch を起こさない');
const unknownAsset = await installed.request('/not-in-manifest.js');
assert.equal(unknownAsset.status, 404, 'manifest に無い本体アセットは引き続き fail-closed');
const allowlistLookalike = await installed.request('/recovery.html/extra', { mode: 'navigate' });
assert.equal(allowlistLookalike.status, 404, 'allowlist は前方一致に広げず完全一致に限る');

const persistedState = installed.persistedState();
assert.equal(persistedState?.buildVersion, '20', 'INSTALL_MANIFEST の STATE を Cache API に永続化する');
const restarted = createSwHarness({ persistedState });
const restoredApp = await restarted.request('/', { mode: 'navigate' });
assert.equal(restoredApp.status, 200, 'SW 冷起動でも永続 STATE を復元して本体を検証配信する');

const cold = createSwHarness();
const coldNavigation = await cold.request('/', { mode: 'navigate' });
assert.equal(coldNavigation.status, 302, '永続 STATE も無い navigation は 503 でなくローダーへ戻す');
assert.equal(coldNavigation.headers.get('Location'), `${TOOL_ORIGIN}/index.html`, '冷起動の復帰先は SW 除外済みローダー入口');
assert.equal(await cold.request('/recovery.html', { mode: 'navigate' }), null,
  'STATE が無くても復元クライアントは SW の外で開ける');
assert.equal((await cold.request('/_next/static/app.js')).status, 503,
  'STATE が無い本体サブリソースは未検証のまま素通ししない');

assert.equal((await installed.message({ type: 'CLEAR' }))?.type, 'CLEARED', 'CLEAR 完了を応答する');
assert.equal(installed.persistedState(), null, 'CLEAR は永続 STATE も削除する');

const discoverySource = readFileSync(path.join(SRC, 'recovery/discovery.js'), 'utf8');
assert.doesNotMatch(discoverySource, /Number\.MAX_SAFE_INTEGER/,
  '選択再検証の壁時計予算を無限化しない');
assert.match(discoverySource,
  /RECOVERY_SELECTION_WALL_BUDGET_MS\s*=\s*SELECTION_VERIFY_WALL_BUDGET_MS/,
  '選択再検証に正典と同じ有限の全体予算がある');

const recoveryAppSource = readFileSync(path.join(SRC, 'recovery/app.js'), 'utf8');
const persistenceStart = recoveryAppSource.indexOf('// localStorage 永続化（同一バイト再送のため）');
const onchainSubmitStart = recoveryAppSource.indexOf('log(`bundle built', persistenceStart);
assert.ok(persistenceStart >= 0 && onchainSubmitStart > persistenceStart,
  '提出 payload の控え保存からオンチェーン提出までを切り出せる');
const persistenceBlock = recoveryAppSource.slice(persistenceStart, onchainSubmitStart);
assert.match(persistenceBlock, /saveRecoveryEvidencePayload\(state\.blockNum, state\.uid, built\.payload, null, chosenWindow\)/,
  '永続化が失敗しても同じセッションの控えを保持する');
assert.match(persistenceBlock, /!isRecoveryEvidencePayloadPersistent\(state\.blockNum, state\.uid\)[\s\S]*showVolatileRescueWarning\(\)/,
  '再読み込み後の救済不能を利用者へ警告する');
assert.doesNotMatch(persistenceBlock, /return\s*;/,
  '控えの永続化失敗でオンチェーン送信を止めない');

const originalFetch = globalThis.fetch;
try {
  globalThis.fetch = () => new Promise(() => {});
  const started = Date.now();
  await assert.rejects(
    fetchBounded('https://never.example', {}, { timeoutMs: 15 }),
    (error) => error?.code === 'external_read_unavailable',
  );
  assert.ok(Date.now() - started < 250, '接続がnever-settleでも短い試験期限でsettleする');

  globalThis.fetch = async () => ({ ok: true, json: () => new Promise(() => {}) });
  await assert.rejects(
    fetchJsonBounded('https://slow-body.example', {}, { timeoutMs: 15 }),
    (error) => error?.code === 'external_read_unavailable',
  );
} finally {
  globalThis.fetch = originalFetch;
}

console.log(`bounded fetch regression: rawFetchSites=${rawFetchSites.length} never-settle=2/2 tool-bypass=${toolPaths.length}/${toolPaths.length} state-persistence=4/4 passed`);

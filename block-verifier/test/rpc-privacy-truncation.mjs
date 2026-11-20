// 実viem→実chain→実report→実makeUi。fetchだけを偽り、外へは接続しない。
import assert from 'node:assert/strict';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { http, fallback } from 'viem';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
const src = resolve(process.env.RPC_PRIVACY_SRC || join(import.meta.dirname, '../src'));
const load = (name) => import(pathToFileURL(join(src, name)));
const { createChain } = await load('chain.js');
const { createReport } = await load('report.js');
const { makeUi } = await load('index.js');
const { t } = await load('i18n.js');
const { DEFAULTS } = await load('config.js');
const shapes = [
  ['https://eth-mainnet.g.alchemy.com/v2/', 'AbCdEfGhIjKlMnOpQrStUvWxYz012345', ''],
  ['https://mainnet.infura.io/v3/', '0123456789abcdef0123456789abcdef', ''],
  ['https://black-silent-tree.quiknode.pro/', 'a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0', '/'],
  ['https://rpc.ankr.com/eth/', 'f'.repeat(16) + '0123456789abcdef' + 'e'.repeat(32), ''],
];
const modes = ['rpc:-32602', 'rpc:-32600', 'rpc:-32000', 'rpc:-32005', 'rpc:-32603', 'http:429', 'http:503', 'httpjson:400'];
const sites = [
  (error) => ['check.main.fatal', 'fail', { error }],
  (error) => ['check.system.auditUnavailable', 'fail', { error }],
  (error) => ['check.stageC.depositVerification', 'skip', { classification: 'unavailable', unavailable: true, error: `[B1] on-chain deposit reads unavailable for unit 1: ${error}` }],
];
const realFetch = globalThis.fetch, out = process.stdout.write, errOut = process.stderr.write;
// viemの再試行の待ち時間だけを短縮する。応答/エラーの組み立ては実ライブラリを使う。
const realTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...args) => realTimeout(fn, Math.min(ms, 1), ...args);
const work = mkdtempSync(join(tmpdir(), 'rpc-truncation-'));
let total = 0, matrixLeaks = 0, cutLeaks = 0;
function hasFragment(text, key) {
  // 長さ8以上の部分文字列があれば、必ず8字の窓も現れる。
  return Array.from({ length: key.length - 7 }, (_, i) => key.slice(i, i + 8)).some((part) => text.includes(part));
}
try {
  for (const [prefix, key, suffix] of shapes) for (const mode of modes)
    for (const [op, lang] of [['getLogs', 'en'], ['getLogs', 'ja'], ['getLogs', 'zh'], ['readContract', 'en']]) {
      const url = prefix + key + suffix;
      globalThis.fetch = async (input, init) => {
        const target = typeof input === 'string' ? input : input.url;
        const body = JSON.parse(init?.body ?? '{}');
        const reply = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json' } });
        if (target !== url) return new Response('forbidden', { status: 403 });
        const [kind, arg] = mode.split(':');
        if (kind === 'http') return new Response('Too Many Requests', { status: Number(arg) });
        return reply({ jsonrpc: '2.0', id: body.id, error: { code: kind === 'rpc' ? Number(arg) : -32600, message: 'limit' } }, kind === 'httpjson' ? Number(arg) : 200);
      };
      const cfg = { ...DEFAULTS, rpcUrls: [url], customRpcs: [], rpcPresets: [] };
      const ui = makeUi(t(lang), {}, cfg);
      const chain = createChain(cfg, ui, fallback([http(url, { retryCount: 0 })], { retryCount: 0 }));
      let error;
      try {
        if (op === 'getLogs') await chain.client.getLogs({ fromBlock: 1n, toBlock: 2n });
        else await chain.client.readContract({ address: cfg.contracts.tokenMining, abi: [{ type: 'function', name: 'evidence', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] }], functionName: 'evidence' });
      } catch (caught) { error = caught; }
      assert.ok(error, 'fake transport must fail');
      for (const site of sites) {
        const report = createReport(); report.check(...site(error.message));
        let captured = '';
        process.stdout.write = process.stderr.write = (s) => { captured += s; return true; };
        try { report.renderSummary(ui, { blockNum: 7, data: {}, r2: { baseDir: '/x' } }); }
        finally { process.stdout.write = out; process.stderr.write = errOut; }
        writeFileSync(join(work, 'summary.log'), captured);
        total++;
        if (hasFragment(captured, key) || hasFragment(readFileSync(join(work, 'summary.log'), 'utf8'), key)) matrixLeaks++;
      }
      // 切り口をURLの全位置へ動かす。全文の伏せの後でだけ切ることを固定する。
      if (mode === modes[0] && op === 'getLogs' && lang === 'en') for (let pad = 0; pad < 360; pad++) {
        const report = createReport(); report.check('check.main.fatal', 'fail', { error: 'x'.repeat(pad) + url });
        let captured = '';
        process.stdout.write = process.stderr.write = (s) => { captured += s; return true; };
        try { report.renderSummary(ui, { blockNum: 7, data: {} }); }
        finally { process.stdout.write = out; process.stderr.write = errOut; }
        if (hasFragment(captured, key)) cutLeaks++;
      }
    }
} finally {
  globalThis.fetch = realFetch; globalThis.setTimeout = realTimeout; process.stdout.write = out; process.stderr.write = errOut;
  rmSync(work, { recursive: true, force: true });
}
assert.equal(total, 384);
assert.deepEqual({ matrixLeaks, cutLeaks }, { matrixLeaks: 0, cutLeaks: 0 }, 'RB-01: key fragments in screen/log/file outputs');
console.log('RB-01: PASS (384 real viem combinations + 1440 moving cut positions; fragments >=8: 0)');

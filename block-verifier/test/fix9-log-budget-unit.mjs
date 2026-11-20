import assert from 'node:assert/strict';
import { custom, fallback, HttpRequestError, parseAbiItem } from 'viem';
import { createChain, LogReadBudget } from '../src/chain.js';

let assertions = 0;
const eq = (a, b, message) => { assert.deepEqual(a, b, message); assertions++; };
const request = { address: '0x' + '11'.repeat(20), event: parseAbiItem('event EthLockSet(address indexed ethLock)'),
  fromBlock: 1000n, toBlock: 1999n };
const originalFetch = globalThis.fetch;
try {
  const primary = [], secondary = [];
  let failing = false;
  // 全てプロセス内の代役。HTTP 403/503でも暗黙の再試行をしないことを数える。
  globalThis.fetch = async (url, options) => {
    const payload = JSON.parse(options.body);
    secondary.push({ url: String(url), ...payload });
    if (failing) return new Response('temporary failure', { status: 503 });
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: payload.id, result: [] }),
      { headers: { 'content-type': 'application/json' } });
  };
  const transport = custom({ request: async (payload) => {
    primary.push(payload);
    throw new HttpRequestError({ url: 'https://example.invalid', status: 403,
      details: '{"code":-32602,"message":"Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode"}' });
  } });
  const cfg = { chainIdExpected: 1, rpcUrls: ['https://example.invalid'], contracts: {} };
  const chain = createChain(cfg, null, transport);
  const budget = new LogReadBudget(128);
  for (let i = 0; i < 64; i++) await chain.client.getLogs(request, { budget });
  eq([budget.used, primary.length, secondary.length], [128, 64, 64], 'counts all primary failures and fallback reads exactly once');
  await assert.rejects(() => chain.client.getLogs(request, { budget }), { wordReason: 'ethLock_log_read_budget_exceeded' }); assertions++;
  eq([primary.length, secondary.length], [64, 64], 'no request after limit');
  eq(secondary.every((r) => r.method === 'eth_getLogs' && r.params[0].fromBlock === '0x3e8'
    && r.params[0].toBlock === '0x7cf' && !('budget' in r.params[0])), true, 'budget never leaks to RPC payload');

  const startPrimary = primary.length, startSecondary = secondary.length;
  failing = true;
  const failedChain = createChain(cfg, null, transport), small = new LogReadBudget(3);
  await assert.rejects(() => failedChain.client.getLogs(request, { budget: small }), { wordReason: 'ethLock_log_read_budget_exceeded' }); assertions++;
  eq([small.used, primary.length - startPrimary, secondary.length - startSecondary], [3, 1, 2],
    'failed fallback candidates consume budget and do not retry 503');

  failing = false;
  const many = new LogReadBudget(20), wide = createChain(cfg, null, transport);
  await wide.client.getLogs({ ...request, toBlock: 3499n }, { budget: many });
  eq(many.used, 4, 'fallback splits 2500 heights into three counted requests');
  eq(secondary.slice(-3).map((r) => [r.params[0].fromBlock, r.params[0].toBlock]),
    [['0x3e8', '0x7cf'], ['0x7d0', '0xbb7'], ['0xbb8', '0xdab']]);

  let selectedCalls = 0;
  const selected = fallback([0, 1].map(() => custom({ request: async () => { selectedCalls++; return []; } })));
  const selectedChain = createChain(cfg, null, selected), reserved = new LogReadBudget(2);
  await selectedChain.client.getLogs(request, { budget: reserved });
  eq([reserved.used, selectedCalls], [2, 1], 'selected fallback transport reserves all potential primary requests');
  await assert.rejects(() => selectedChain.client.getLogs(request, { budget: reserved }), { wordReason: 'ethLock_log_read_budget_exceeded' }); assertions++;
  eq(selectedCalls, 1);
} finally { globalThis.fetch = originalFetch; }
console.log(`fix9-log-budget-unit: ${assertions} assertions PASS`);

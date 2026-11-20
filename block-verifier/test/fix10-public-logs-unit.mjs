// 実ノードの応答をプロセス内HTTP transportで返す。外部通信・.env読取なし。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { http, HttpRequestError, encodeEventTopics, encodeAbiParameters, keccak256, parseAbiItem } from 'viem';
import { ArchiveUnavailableError, historicalStateFailure, isLogRangeFailure } from '../src/archive.js';
import { LogReadBudget } from '../src/chain.js';
import { createReport } from '../src/report.js';
import { runningHashOf } from '../src/claim-data.js';

const mutation = process.argv.find((s) => s.startsWith('--mutation='))?.split('=')[1];
let assertions = 0, applied = false;
const eq = (a, b, label) => { assert.deepEqual(a, b, label); assertions++; };
const ok = (a, label) => { assert.ok(a, label); assertions++; };
async function load(file, before, after) {
  const url = new URL(file, import.meta.url);
  let source = readFileSync(url, 'utf8');
  if (before) {
    ok(source.includes(before), 'mutation target exists');
    source = source.replace(before, after); applied = true;
  }
  source = source.replace(/from '([^']+)'/g,
    (_, path) => `from '${path.startsWith('.') ? new URL(path, url).href : import.meta.resolve(path)}'`);
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
}
const { createChain } = await load('../src/chain.js',
  mutation === 'no_switch' ? 'const logs = await getBudgetedLogs(cand, params, budget, reverse, stopOnLogs);'
    : mutation === 'no_shrink' ? 'if (!isLogRangeFailure(error) || t - f + 1n <= 100n)' : null,
  mutation === 'no_switch' ? 'const logs = await getBudgetedLogs(cand, params, budget, reverse, stopOnLogs); budgetFallbacks = [cand];'
    : 'if (true)');
const { compareProofWords, ETH_LOCK_LOG_RPC_LIMIT } = await load('../src/zkp-word-checks.js',
  mutation === 'oldest_first' ? 'for (let to = toBlock; to >= fromBlock; to -= 1000n) {\n          const from = to - 999n > fromBlock ? to - 999n : fromBlock;' : null,
  'for (let from = fromBlock; from <= toBlock; from += 1000n) {\n          const to = from + 999n < toBlock ? from + 999n : toBlock;');
if (mutation) { ok(applied, 'mutation applied'); console.log(`MUTATION_APPLIED ${mutation}`); }

const PUBLIC = { code: -32602, message: 'Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode' };
const PRUNED = { code: -32000, message: 'pruned history unavailable' };
const RANGE = { message: 'ranges over 10000 blocks are not supported on free plan', code: 35 };
const RATE = { code: -32005, message: 'Rate limit exceeded' };
const EIP4444 = { code: 4444, message: 'pruned history unavailable: requested 13213332, earliest available 15500000' };
const urls = { primary: 'https://ethereum-rpc.publicnode.com', drpc: 'https://eth.drpc.org',
  flash: 'https://rpc.flashbots.net', merkle: 'https://eth.merkle.io' };
const address = (s) => '0x' + s.repeat(20), hash = (s) => '0x' + s.repeat(32);
const tm = address('11'), evidence = address('22'), hs = address('33'), lock = address('44');
const root = hash('55'), start = 1794614400, startHeight = 26410000n;
// 12秒/高。setはSTART_TIMEの17時間前、proofはSTART_TIMEの3日後。
const setHeight = startHeight - 17n * 3600n / 12n, proofHeight = startHeight + 3n * 86400n / 12n;
const windowFrom = startHeight - 7n * 86400n / 12n, windowTo = startHeight + 86400n / 12n;
const event = parseAbiItem('event EthLockSet(address indexed ethLock)');
const request = { address: tm, event, fromBlock: windowTo - 999n, toBlock: windowTo };
const chunk = Buffer.from('FIX10 chain claim data'), claimHash = runningHashOf([chunk]);
const deploymentHash = keccak256(encodeAbiParameters(
  ['uint256', 'address', 'uint256', 'uint256', 'uint256', 'address', 'address', 'address'].map((type) => ({ type })),
  [1n, tm, BigInt(start), 3600n, 12345n, evidence, lock, hs]));
const valid = { blockNum: 8n, merkleRoot: root, applicantHash: hash('66'), applicantHashUpdatedBlock: startHeight,
  randaoEthBlockNumber: startHeight + 64n, randaoBlockHash: hash('bb'), evidenceAcc: hash('aa'), entryAcc: hash('00'),
  evidenceGraceSec: 120n, resultManifestHash: hash('77'), prevResultManifestHash: hash('88'),
  rosterManifestHash: hash('99'), claimDataHash: claimHash, deploymentParamsHash: deploymentHash };
function rawLog(blockNumber) {
  return { address: tm, topics: encodeEventTopics({ abi: [event], eventName: 'EthLockSet', args: { ethLock: lock } }),
    data: '0x', blockNumber: `0x${blockNumber.toString(16)}`, blockHash: hash('dd'),
    transactionHash: hash('ee'), transactionIndex: '0x0', logIndex: '0x0', removed: false };
}
let mode, history, drpcLimit;
const originalFetch = globalThis.fetch;
function makeChain(nextMode = 'observed', maxDrpcWidth = 500) {
  mode = nextMode; history = []; drpcLimit = BigInt(maxDrpcWidth);
  return createChain({ chainIdExpected: 1, contracts: { tokenMining: tm }, rpcUrls: [urls.primary] }, null,
    http(urls.primary));
}
function assertCount(result) {
  eq(result.rpcReads.ethLockLogs.total, history.length, 'every HTTP request, including refusal, consumes budget');
  ok(history.length <= ETH_LOCK_LOG_RPC_LIMIT, 'no request beyond 128');
  eq(ETH_LOCK_LOG_RPC_LIMIT, 128, 'existing ceiling unchanged');
}
async function inspect(chain, changed = {}) {
  const report = createReport();
  for (const [id, params] of [
    ['stageA.rootMatch', {}], ['stageB.hashRegisteredBlock', { onchain: startHeight, membership: true }],
    ['stageB.applicantHashField', { onchain: valid.applicantHash }], ['stageB.confirmationBlocks', {}],
    ['stageB.targetBlockNum', { expected: valid.randaoEthBlockNumber }], ['stageB.targetBlockHash', { onchain: valid.randaoBlockHash }],
  ]) report.check('check.' + id, 'pass', params);
  const getLogs = chain.client.getLogs;
  chain.client = { ...chain.client,
    getBlockNumber: async () => proofHeight + 1000n,
    getBlock: async () => ({ number: proofHeight, timestamp: BigInt(start + 3 * 86400) }),
    readContract: async ({ functionName, args = [] }) => {
      switch (functionName) {
        case 'evidence': return evidence;
        case 'hashStorage': return hs;
        case 'resultWindow': return [BigInt(start), BigInt(start + 86400)];
        case 'evidenceAcc': return valid.evidenceAcc;
        case 'entryAcc': return valid.entryAcc;
        case 'currentGrace': return valid.evidenceGraceSec;
        case 'scheduledGameStart': return BigInt(start);
        case 'resultRegistrationCount': return 1n;
        case 'resultRegistrationAt': return [args[0] === 8n ? valid.resultManifestHash : valid.prevResultManifestHash,
          startHeight + 10000n, BigInt(start + 86400), lock];
        case 'otherRegistrationCount': return 1n;
        case 'otherRegistrationAt': return [valid.rosterManifestHash, startHeight + 1n, BigInt(start + 1)];
        case 'claimDataOf': return [claimHash, 1, 1];
        case 'getClaimDataBlocks': return [proofHeight - 1n];
        case 'ethLock': return lock;
        case 'START_TIME': return BigInt(start);
        case 'deploymentParamsHash': return deploymentHash;
        default: throw new Error(`unexpected getter ${functionName}`);
      }
    },
    getLogs: async (params, options) => params.event.name === 'EthLockSet' ? getLogs(params, options)
      : [{ blockNumber: proofHeight - 1n, logIndex: 0, args: { chunkIndex: 0, totalChunks: 1,
        data: '0x' + chunk.toString('hex'), runningHash: claimHash } }],
  };
  chain.findBlockByTimestamp = async (timestamp) => {
    if (timestamp === start - 7 * 86400) return windowFrom;
    if (timestamp === start + 86400) return windowTo;
    throw new Error('unexpected timestamp');
  };
  return compareProofWords({ chain, blockNum: 8, root, event: { evtBlock: proofHeight, logIndex: 20 },
    actual: { ...valid, ...changed }, prevRegistrationIndex: 0n, report, unavailableError: new ArchiveUnavailableError() });
}
try {
  globalThis.fetch = async (url, options) => {
    const payload = JSON.parse(options.body), { fromBlock, toBlock } = payload.params[0];
    eq(payload.method, 'eth_getLogs');
    const from = BigInt(fromBlock), to = BigInt(toBlock), width = to - from + 1n;
    const row = { url: String(url), from, to, width }; history.push(row);
    let error, status = 200;
    if (mode === 'all_pruned') error = PRUNED;
    else if (mode === 'all_4444') error = EIP4444;
    else if (mode === 'rate') error = RATE;
    else if (mode === 'mixed_failure') error = String(url) === urls.merkle ? RATE : PRUNED;
    else if (String(url) === urls.primary) { error = PUBLIC; status = 403; }
    else if (String(url) === urls.drpc) {
      // 最近の窓ではFlashbotsを最初の成功先にする。古い窓ではdRPCが必要。
      if (mode === 'switch' && from > windowTo) error = PRUNED;
      else if (width > drpcLimit) error = RANGE;
    } else if (String(url) === urls.flash) {
      if (!['observed', 'switch'].includes(mode) || to <= windowTo) error = PRUNED;
    } else if (String(url) === urls.merkle) error = RATE;
    else throw new Error('unexpected URL');
    row.error = error;
    const result = mode !== 'absent' && from <= setHeight && setHeight <= to ? [rawLog(setHeight)] : [];
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: payload.id, ...(error ? { error } : { result }) }),
      { status, headers: { 'content-type': 'application/json' } });
  };

  for (const response of [PRUNED, { jsonrpc: '2.0', error: PRUNED },
    new HttpRequestError({ url: urls.flash, status: 200, details: JSON.stringify(PRUNED) }), EIP4444]) {
    eq(historicalStateFailure(response), 'archive_unavailable', 'structured pruned reply is historical failure');
  }
  for (const error of [new Error(PRUNED.message), { code: 35, message: 'request pruned history unavailable' },
    { shortMessage: PRUNED.message, code: -32000 }, { code: -32000, message: 'HTTP failure', body: PRUNED }, RATE]) {
    eq(historicalStateFailure(error), 'rpc_unavailable', 'display, request and rate limit do not become archive failures');
  }
  eq(isLogRangeFailure(RANGE), true);
  eq(isLogRangeFailure(new HttpRequestError({ url: urls.drpc, status: 200, details: JSON.stringify(RANGE) })), true);
  for (const error of [new Error(RANGE.message), { code: 35, message: 'Rate limit exceeded' },
    { code: -32005, message: RANGE.message }, { code: 35, message: 'request ' + RANGE.message },
    { code: 35, message: 'bad request', body: RANGE }, RATE, PRUNED]) eq(isLogRangeFailure(error), false);

  const observedChain = makeChain();
  // 予算なしの直近ログ取得で、既存のlogsFallbackをFlashbotsに固定した状態から始める。
  await observedChain.client.getLogs({ ...request, fromBlock: proofHeight - 999n, toBlock: proofHeight });
  eq(history.map((r) => r.url), [...Array(4).fill(urls.primary), urls.drpc, urls.flash], 'unbudgeted primary keeps viem retries');
  history = [];
  const verified = await inspect(observedChain);
  eq(verified.status, 'pass', 'block 8 shape verifies all 14 words through real HTTP error structures');
  eq(verified.unverifiedWords, []);
  eq(verified.verifiedWords.length, 14);
  ok(verified.verifiedWords.includes('deploymentParamsHash'));
  assertCount(verified);
  const firstStartRead = history.find((r) => r.to <= windowTo);
  eq(firstStartRead.to, windowTo, 'START_TIME window starts at its newest end');
  ok(history.every((r) => (r.from >= proofHeight - 1999n && r.to <= proofHeight)
    || (r.from >= windowFrom && r.to <= windowTo)), 'only the two finite windows are read');
  ok(history.filter((r) => r.to <= windowTo && r.url === urls.drpc).every((r, i, rows) => !i || r.to <= rows[i - 1].to),
    'shrinking also proceeds from newest to oldest');
  ok(history.every((r) => r.to >= setHeight), 'stop after finding the set log');
  console.log('FIX10_VERIFIED ' + JSON.stringify(verified.rpcReads));

  // 切替の独立試験。直近窓のdRPC拒否を追加し、Flashbotsが先に成功した後に断る。
  const switched = await inspect(makeChain('switch'));
  eq(switched.status, 'pass', 'fallback is not pinned to its earlier successful candidate');
  assertCount(switched);
  ok(history.some((r) => r.url === urls.flash && !r.error && r.from > windowTo), 'first fallback success is recent Flashbots');
  ok(history.some((r) => r.url === urls.drpc && !r.error && r.from <= setHeight && r.to >= setHeight),
    'later range changes from previous successful fallback to dRPC');

  const mismatch = await inspect(makeChain(), { deploymentParamsHash: hash('ff') });
  eq(mismatch.status, 'fail', 'proven wiring still detects a false deployment hash');
  eq(mismatch.mismatches.map((m) => m.name), ['deploymentParamsHash']);
  assertCount(mismatch);
  for (const [testMode, reason] of [['all_pruned', 'archive_unavailable'], ['all_4444', 'archive_unavailable'],
    ['rate', 'rpc_unavailable'], ['mixed_failure', 'rpc_unavailable']]) {
    const result = await inspect(makeChain(testMode));
    eq(result.status, 'unavailable');
    eq(result.unverifiedWords, [{ name: 'deploymentParamsHash', reason }], testMode);
    eq(result.verifiedWords.length, 13, 'other 13 words unchanged');
    assertCount(result);
    eq(history.length, 4, 'all four candidates tried once without hidden retries');
  }

  // dRPCが100高しか返さない場合も、100まで半分にして再試行し、次の範囲で幅を再利用。
  const narrowChain = makeChain('narrow', 100), narrowBudget = new LogReadBudget(128);
  await narrowChain.client.getLogs(request, { budget: narrowBudget, reverse: true });
  const narrow = history.filter((r) => r.url === urls.drpc);
  eq(narrow.slice(0, 5).map((r) => r.width), [1000n, 500n, 250n, 125n, 100n]);
  eq(narrow.filter((r) => !r.error).map((r) => r.width), Array(10).fill(100n));
  const firstRequests = history.length;
  await narrowChain.client.getLogs({ ...request, fromBlock: request.fromBlock - 1000n, toBlock: request.toBlock - 1000n },
    { budget: narrowBudget, reverse: true });
  eq(history.slice(firstRequests).filter((r) => r.url === urls.drpc && r.error).length, 0, 'learned width retained per candidate');
  eq(narrowBudget.used, history.length);
  const minimumChain = makeChain('narrow', 0), minimum = new LogReadBudget(128);
  await assert.rejects(() => minimumChain.client.getLogs(request, { budget: minimum }), (e) => !(e instanceof ArchiveUnavailableError)); assertions++;
  eq(history.filter((r) => r.url === urls.drpc).map((r) => r.width), [1000n, 500n, 250n, 125n, 100n], 'never shrink below 100');
  eq(minimum.used, history.length);

  const exhausted = await inspect(makeChain('absent', 100));
  eq(exhausted.status, 'unavailable');
  eq(exhausted.unverifiedWords, [{ name: 'deploymentParamsHash', reason: 'ethLock_log_read_budget_exceeded' }]);
  eq(exhausted.verifiedWords.length, 13);
  eq(history.length, 128, 'stop precisely at 128 HTTP requests, including rejected sizes');
  assertCount(exhausted);
  console.log('FIX10_EXHAUSTED ' + JSON.stringify(exhausted.rpcReads));

  // 予算なしは既存の固定先を維持し、縮小を追加しない。
  const ordinary = makeChain('narrow', 100);
  await assert.rejects(() => ordinary.client.getLogs(request)); assertions++;
  eq(history.filter((r) => r.url === urls.drpc).map((r) => r.width), [1000n], 'unbudgeted route is unchanged');
  const pinned = makeChain();
  await pinned.client.getLogs({ ...request, fromBlock: proofHeight - 999n, toBlock: proofHeight });
  history = [];
  await assert.rejects(() => pinned.client.getLogs(request)); assertions++;
  eq(history.map((r) => r.url), [...Array(4).fill(urls.primary), urls.flash], 'unbudgeted route keeps its previously successful fallback');
} finally { globalThis.fetch = originalFetch; }
if (!mutation) for (const name of ['no_switch', 'no_shrink', 'oldest_first']) {
  const result = spawnSync(process.execPath, [import.meta.filename, '--mutation=' + name],
    { encoding: 'utf8', timeout: 30000, env: process.env });
  ok(result.status === 1 && result.stdout.includes('MUTATION_APPLIED ' + name)
    && result.stderr.includes('AssertionError'), `${name}: real assertions reject mutation`);
}
console.log(`fix10-public-logs-unit: ${assertions} assertions PASS`);

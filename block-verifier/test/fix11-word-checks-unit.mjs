// 安全高のgetterだけを返す代役。外部通信・成果物の再生成なし。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { ArchiveUnavailableError } from '../src/archive.js';
import { runningHashOf } from '../src/claim-data.js';
import { createReport } from '../src/report.js';
import { recordZkpPublicValuesCheck } from '../src/stages/results.js';
import { PREV_REGISTRATION_SENTINEL } from '../../Hardhat/bitcoinu/scripts/lib/zkp-pipeline.mjs';

const mutation = process.argv.find((s) => s.startsWith('--mutation='))?.split('=')[1];
let assertions = 0, applied = false;
const eq = (a, b, label) => { assert.deepEqual(a, b, label); assertions++; };
const ok = (a, label) => { assert.ok(a, label); assertions++; };
const url = new URL('../src/zkp-word-checks.js', import.meta.url);
let source = readFileSync(url, 'utf8');
const mutations = {
  shared_48: ['calls >= WORD_CHECK_TOTAL_RPC_LIMIT', 'calls >= 48'],
  sentinel_skip: ['if (prevRegistrationIndex === PREV_REGISTRATION_SENTINEL) {',
    "if (prevRegistrationIndex === PREV_REGISTRATION_SENTINEL) unavailable('sentinel_handled_separately');\n    if (prevRegistrationIndex === PREV_REGISTRATION_SENTINEL) {"],
  sentinel_current_count: ['count > 0n && await beforeProof(await resultRow(bn - 1n, 0n), bn - 1n, 0n)', 'count > 0n'],
  sentinel_ignore_history: ['count > 0n && await beforeProof(await resultRow(bn - 1n, 0n), bn - 1n, 0n)', 'false'],
  sentinel_ignore_log_order: ['return Number(log.logIndex) < Number(event.logIndex);', 'return false;'],
};
if (mutation) {
  const [before, after] = mutations[mutation];
  ok(source.includes(before), 'mutation target exists');
  source = source.replace(before, after); applied = true;
}
source = source.replace(/from '([^']+)'/g,
  (_, path) => `from '${path.startsWith('.') ? new URL(path, url).href : import.meta.resolve(path)}'`);
const { compareProofWords, WORD_CHECK_TOTAL_RPC_LIMIT, WORD_CHECK_WORD_RPC_LIMITS } = await import(
  `data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
if (mutation) { ok(applied); console.log(`MUTATION_APPLIED ${mutation}`); }

const hash = (s) => '0x' + s.repeat(32), address = (s) => '0x' + s.repeat(20);
const ZERO = hash('00'), tm = address('11'), evidence = address('22'), hs = address('33'), lock = address('44');
const root = hash('55'), applicant = hash('66'), result = hash('77'), prev = hash('88'), roster = hash('99');
const height = 9000n;
const row = (registeredBlock, h = prev) => [h, registeredBlock, 80000n, lock];
const resultLog = (logIndex, extra = {}) => ({ address: hs, blockNumber: height, logIndex,
  args: { blockNumber: 7n, registrationCount: 1n, hash: prev }, ...extra });

async function inspect({ chunks = 3, resultCount = 1n, rosterCount = 1n, blockNum = 8,
  sentinel = false, prevRows = [row(8000n)], resultLogs = [], proofLogIndex = 20,
  denyPrevious = null, changed = {} } = {}) {
  const bn = BigInt(blockNum), report = createReport(), reads = [];
  const data = Array.from({ length: chunks }, (_, i) => Buffer.from(`FIX11 chunk ${i}`));
  const blocks = data.map((_, i) => height - BigInt(chunks) + BigInt(i));
  const claimHash = runningHashOf(data);
  const values = { blockNum: bn, merkleRoot: root, applicantHash: applicant, applicantHashUpdatedBlock: 7000n,
    randaoEthBlockNumber: 7064n, randaoBlockHash: hash('bb'), evidenceAcc: hash('aa'), entryAcc: ZERO,
    evidenceGraceSec: 120n, resultManifestHash: result, prevResultManifestHash: sentinel || !blockNum ? ZERO : prev,
    rosterManifestHash: roster, claimDataHash: claimHash, deploymentParamsHash: hash('cc'), ...changed };
  for (const [id, params] of [
    ['stageA.rootMatch', {}], ['stageB.hashRegisteredBlock', { onchain: 7000n, membership: true }],
    ['stageB.applicantHashField', { onchain: applicant }], ['stageB.confirmationBlocks', {}],
    ['stageB.targetBlockNum', { expected: 7064n }], ['stageB.targetBlockHash', { onchain: hash('bb') }],
  ]) report.check('check.' + id, 'pass', params);
  const chain = { contracts: { tokenMining: tm }, client: {
    getBlockNumber: async () => { reads.push('head'); return 10000n; },
    getBlock: async (r) => { eq(r.blockNumber, height); reads.push('proof'); return { timestamp: 90000n }; },
    readContract: async (r) => {
      reads.push(r.functionName);
      eq(r.blockNumber, 9936n, 'every getter reads latest-64, regardless of actual public words');
      const [n, i] = r.args || [];
      if (n === bn - 1n && (r.functionName === 'resultRegistrationCount' || r.functionName === 'resultRegistrationAt')
        && (!blockNum || denyPrevious === r.functionName)) throw new ArchiveUnavailableError();
      switch (r.functionName) {
        case 'evidence': return evidence;
        case 'hashStorage': return hs;
        case 'resultWindow': return [60000n, 80000n];
        case 'evidenceAcc': return hash('aa');
        case 'entryAcc': return ZERO;
        case 'currentGrace': return 120n;
        case 'scheduledGameStart': return 50000n;
        case 'resultRegistrationCount': return n === bn ? resultCount : BigInt(prevRows.length);
        case 'resultRegistrationAt': return n === bn ? row(8000n, result) : prevRows[Number(i)];
        case 'otherRegistrationCount': return rosterCount;
        case 'otherRegistrationAt': return [roster, 6000n, 50050n];
        case 'claimDataOf': return [claimHash, chunks, chunks];
        case 'getClaimDataBlocks': return blocks;
        case 'ethLock': return lock;
        case 'deploymentParamsHash': return hash('cc');
        default: throw new Error(`unexpected getter ${r.functionName}`);
      }
    },
    getLogs: async (r, { budget } = {}) => {
      if (r.event.name === 'EthLockSet') {
        budget.take();
        return [{ address: tm, blockNumber: 8000n, logIndex: 0, args: { ethLock: lock } }]
          .filter((l) => l.blockNumber >= r.fromBlock && l.blockNumber <= r.toBlock);
      }
      reads.push(r.event.name);
      if (r.event.name === 'ResultHashRegistered') {
        eq(r.address, hs); eq(r.args.blockNumber, bn - 1n);
        eq([r.fromBlock, r.toBlock], [height, height], 'only proof height logs determine same-height order');
        return resultLogs;
      }
      eq(r.address, tm); eq(r.args.blockNum, bn);
      const i = blocks.findIndex((b) => b === r.fromBlock);
      eq(r.toBlock, blocks[i], 'chunk heights come only from onchain locator');
      return [{ blockNumber: blocks[i], logIndex: 0, args: { chunkIndex: i, totalChunks: chunks,
        data: '0x' + data[i].toString('hex'), runningHash: runningHashOf(data.slice(0, i + 1)) } }];
    },
  } };
  const checked = await compareProofWords({ chain, blockNum, root, actual: values, report,
    event: { evtBlock: Number(height), logIndex: proofLogIndex },
    prevRegistrationIndex: sentinel ? PREV_REGISTRATION_SENTINEL : 0n,
    unavailableError: new ArchiveUnavailableError() });
  recordZkpPublicValuesCheck({ report, data: {} }, checked);
  eq(checked.rpcReads.total, reads.length, 'every direct read, including failed reads, is counted');
  ok(checked.rpcReads.total <= WORD_CHECK_TOTAL_RPC_LIMIT, 'global limit retained');
  eq(checked.rpcReads.limit, WORD_CHECK_TOTAL_RPC_LIMIT);
  const wordReads = Object.values(checked.rpcReads.byWord);
  ok(wordReads.every((b) => b.total <= b.limit), 'every word has an independent ceiling');
  eq(wordReads.reduce((sum, b) => sum + b.total, checked.rpcReads.shared.total), reads.length);
  eq(checked.rpcReads.ethLockLogs.limit, 128, 'EthLock transport budget unchanged');
  eq(report.get('check.stageC.zkPublicValues').status,
    checked.status === 'unavailable' ? 'skip' : checked.status, 'word failure reaches report');
  return { checked, reads };
}

// 記録1: 3→40チャンク、それぞれ1000件の追記でも後ろの語の不一致を失わない。
for (const chunks of [40, 3, 16]) {
  const bad = await inspect({ chunks, resultCount: 1000n, rosterCount: 1000n,
    changed: { deploymentParamsHash: hash('ff') } });
  eq(bad.checked.status, 'fail', `${chunks} chunks cannot suppress a deployment mismatch`);
  eq(bad.checked.mismatches.map((m) => m.name), ['deploymentParamsHash']);
  eq(bad.checked.unverifiedWords, []);
  eq(bad.checked.rpcReads.byWord.deploymentParamsHash.total, 2);
  eq(bad.checked.rpcReads.byWord.claimDataHash.total, chunks + 2);
  const good = await inspect({ chunks, resultCount: 1000n, rosterCount: 1000n });
  eq(good.checked.status, 'pass', `${chunks} chunks and large histories remain verifiable: ${JSON.stringify(good.checked.unverifiedWords)}`);
  eq(good.checked.verifiedWords.length, 14);
  if (chunks === 40) {
    ok(bad.checked.rpcReads.total > 48, 'reproducer exceeds the old shared budget');
    console.log('FIX11_LARGE ' + JSON.stringify(bad.checked.rpcReads));
  }
}
// 正典のuint256件数の最大値でも、二分探索は語ごとの枠に届かない。
const maximum = await inspect({ resultCount: (1n << 256n) - 1n, rosterCount: (1n << 256n) - 1n, chunks: 16 });
eq(maximum.checked.status, 'pass');
for (const name of ['resultManifestHash', 'rosterManifestHash']) {
  ok(maximum.checked.rpcReads.byWord[name].total <= 259);
  ok(maximum.checked.rpcReads.byWord[name].total < WORD_CHECK_WORD_RPC_LIMITS[name]);
}
// 1語を意図的に上限に当てても、他の語を未検証へ押し出せない。
for (const options of [{ resultCount: 1n << 300n }, { chunks: 70 }]) {
  const { checked } = await inspect({ ...options, changed: { deploymentParamsHash: hash('ff') } });
  eq(checked.status, 'fail');
  eq(checked.mismatches.map((m) => m.name), ['deploymentParamsHash']);
  const name = options.chunks ? 'claimDataHash' : 'resultManifestHash';
  eq(checked.unverifiedWords, [{ name, reason: 'read_budget_exceeded' }]);
  eq(checked.rpcReads.byWord[name].total, WORD_CHECK_WORD_RPC_LIMITS[name]);
  ok(checked.verifiedWords.includes('rosterManifestHash'));
  eq(checked.rpcReads.byWord.deploymentParamsHash.total, 2);
}

// 記録3: 追記の先頭だけで、証明tx直前が0件だったかを決める。
for (const prevRows of [[], [row(9100n)], [row(height), row(9100n)]]) {
  const { checked } = await inspect({ sentinel: true, prevRows, resultLogs: [resultLog(21)] });
  eq(checked.status, 'pass', 'empty history or only registrations after proof accept sentinel');
  ok(checked.verifiedWords.includes('prevResultManifestHash'));
}
for (const prevRows of [[row(8000n)], [row(height), row(9100n)]]) {
  const { checked } = await inspect({ sentinel: true, prevRows, resultLogs: [resultLog(19)] });
  eq(checked.status, 'fail', 'a registration before proof invalidates sentinel even with public word zero');
  eq(checked.mismatches.map((m) => [m.name, m.reason]),
    [['prevResultManifestHash', 'sentinel_registration_before_proof']]);
  eq(checked.unverifiedWords, []);
}
const nonzero = await inspect({ sentinel: true, prevRows: [row(9100n)], changed: { prevResultManifestHash: prev } });
eq(nonzero.checked.status, 'fail', 'valid sentinel still compares the public word against zero');
eq(nonzero.checked.mismatches[0].expected, ZERO);

for (const options of [
  { proofLogIndex: null }, { proofLogIndex: 'invalid' },
  { resultLogs: [] }, { resultLogs: [resultLog(null)] }, { resultLogs: [resultLog(-1)] },
  { resultLogs: [resultLog(20)] }, { resultLogs: [resultLog(21), resultLog(22)] },
  { resultLogs: [resultLog(21, { removed: true })] },
  { resultLogs: [resultLog(21, { blockNumber: null })] },
  { resultLogs: [resultLog(21, { blockNumber: 8999n })] },
  { resultLogs: [resultLog(21, { args: { registrationCount: 2n, hash: prev } })] },
  { resultLogs: [resultLog(21, { args: { registrationCount: 1n, hash: hash('ff') } })] },
]) {
  const { checked } = await inspect({ sentinel: true, prevRows: [row(height)], resultLogs: [resultLog(21)], ...options });
  eq(checked.status, 'unavailable', 'ambiguous same-height order never becomes PASS or FAIL');
  eq(checked.unverifiedWords, [{ name: 'prevResultManifestHash', reason: 'same_block_order_unavailable' }]);
  eq(checked.verifiedWords.length, 13);
}
for (const denyPrevious of ['resultRegistrationCount', 'resultRegistrationAt']) {
  const { checked } = await inspect({ sentinel: true, denyPrevious });
  eq(checked.status, 'unavailable');
  eq(checked.unverifiedWords, [{ name: 'prevResultManifestHash', reason: 'archive_unavailable' }]);
}
const independent = await inspect({ sentinel: true, prevRows: [row(height)], proofLogIndex: null,
  changed: { deploymentParamsHash: hash('ff') } });
eq(independent.checked.status, 'fail', 'unknown sentinel order cannot erase another known failure');
const zero = await inspect({ blockNum: 0, sentinel: true, prevRows: [row(8000n)] });
eq(zero.checked.status, 'pass', 'N=0 is zero without any N-1 history');
const badZero = await inspect({ blockNum: 0, sentinel: true, changed: { prevResultManifestHash: prev } });
eq(badZero.checked.status, 'fail', 'N=0 still compares public word to zero');
const named = await inspect({ prevRows: [row(8000n), row(9100n)] });
eq(named.checked.status, 'pass', 'ordinary calldata-named row remains authoritative');

if (!mutation) for (const name of Object.keys(mutations)) {
  const child = spawnSync(process.execPath, [import.meta.filename, '--mutation=' + name], { encoding: 'utf8', env: process.env });
  ok(child.status !== 0 && child.stdout.includes('MUTATION_APPLIED ' + name)
    && child.stderr.includes('AssertionError'), `${name}: assertion detects mutation, not import/startup failure`);
}
console.log(`fix11-word-checks-unit: ${assertions} assertions PASS`);

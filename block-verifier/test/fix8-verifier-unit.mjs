import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { custom, encodeAbiParameters, encodeFunctionData, keccak256 } from 'viem';
import { createChain } from '../src/chain.js';
import { ArchiveUnavailableError } from '../src/archive.js';
import { createReport, verificationCoverage } from '../src/report.js';
import { recordZkpPublicValuesCheck } from '../src/stages/results.js';
import { categorize, EXIT_CODE_OF } from '../src/index.js';
import { checkProofFutureAnchor } from '../src/future-anchor.js';
import { publicnodeExplanation, VERIFICATION_AREAS } from '../src/verification-areas.js';
import { runningHashOf } from '../src/claim-data.js';
import { foldEvidenceAcc } from '../src/zkp.js';
import { t, SUPPORTED_LANGS } from '../src/i18n.js';
import { encodePublicValues, PV_COMPONENTS, TOKEN_MINING_ABI } from '../../Hardhat/bitcoinu/scripts/lib/zkp-pipeline.mjs';

const mutation = process.argv.find((arg) => arg.startsWith('--mutation='))?.split('=')[1];
let applied = false, assertions = 0;
const eq = (a, b, label) => { assert.deepEqual(a, b, label); assertions++; };
const ok = (a, label) => { assert.ok(a, label); assertions++; };
async function load(file, edit) {
  const url = new URL(file, import.meta.url);
  const source = edit(readFileSync(url, 'utf8')).replace(/from '([^']+)'/g,
    (_, p) => `from '${p.startsWith('.') ? new URL(p, url).href : import.meta.resolve(p)}'`);
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
}
function replace(source, before, after) {
  assert.ok(source.includes(before), `mutation target ${mutation}`); applied = true;
  return source.replace(before, after);
}
const words = await load('../src/zkp-word-checks.js', (s) => {
  if (mutation === 'registration_height') return replace(s, 'return block < height;', 'return true;');
  if (mutation === 'current_result') return replace(s,
    "lo ? value(await resultRow(bn, lo - 1n), 0, 'hash') : ZERO",
    "value(await hs('resultHashes', [bn]), 0, 'hash')");
  if (mutation === 'current_claim') return replace(s,
    "if (blocks.some((b) => BigInt(b) > height)) unavailable('claim_series_replaced_after_proof');", '/* unsafe current series */');
  if (mutation === 'ignore_acc') return replace(s,
    'expected[name] = values[name]; sources[name] = source;',
    "expected[name] = values[name]; sources[name] = source; if (name === 'evidenceAcc') continue;");
  if (mutation === 'no_start_window') return replace(s, 'setLog = await scan(from > 0n ? from : 1n, to);', 'setLog = null;');
  if (mutation === 'ignore_emitter') return replace(s, 'lower(log.address) !== lower(tm)', 'false');
  if (mutation === 'ignore_lock_arg') return replace(s, 'lower(log.args?.ethLock) !== lower(lock)', 'false');
  if (mutation === 'use_current_lock') return replace(s, 'if (lockAtProof === ZERO_ADDRESS && lower(lock) !== ZERO_ADDRESS)', 'if (false)');
  return s;
});
globalThis.__fix8CompareWords = words.compareProofWords;
const zkp = await load('../src/zkp.js', (s) => {
  s = s.replace("import { compareProofWords } from './zkp-word-checks.js';", 'const compareProofWords = globalThis.__fix8CompareWords;');
  if (mutation === 'no_fallback') s = replace(s,
    'if (!collected && collectionError instanceof ArchiveUnavailableError)', 'if (false)');
  return s;
});
if (mutation) { ok(applied, 'mutation applied'); console.log(`MUTATION_APPLIED ${mutation}`); }
const hash = (byte) => '0x' + byte.repeat(32);
const address = (byte) => '0x' + byte.repeat(20);
const tm = address('11'), evidence = address('22'), hs = address('33'), lock = address('44');
const root = hash('55'), applicant = hash('66'), result = hash('77'), prev = hash('88'), roster = hash('99');
const chunk = Buffer.from('chain claim data'), claimHash = runningHashOf([chunk]);
const valid = { blockNum: 8n, merkleRoot: root, claimDataHash: claimHash,
  evidenceAcc: foldEvidenceAcc(hash('00'), address('ab'), '0x010203'), entryAcc: hash('00'),
  randaoBlockHash: hash('bb'), resultManifestHash: result, prevResultManifestHash: prev,
  applicantHash: applicant, applicantHashUpdatedBlock: 7000n, evidenceGraceSec: 120n,
  randaoEthBlockNumber: 7064n, deploymentParamsHash: hash('cc'), futureAnchorsHash: hash('00'), rosterManifestHash: roster };
const proofEvent = { evtBlock: 9000, txHash: hash('dd'), logIndex: 20 };
const public403 = { name: 'HttpRequestError', status: 403,
  details: '{"code":-32602,"message":"Archive requests require a personal token. Get one at: https://www.allnodes.com/publicnode"}' };
const public4444 = { code: 4444, message: 'pruned history unavailable: requested 13213332, earliest available 15500000' };
const startTime = 1794614400n, interval = 3600n, reward = 12345n;
const deploymentHash = (ethLock) => keccak256(encodeAbiParameters(
  ['uint256', 'address', 'uint256', 'uint256', 'uint256', 'address', 'address', 'address'].map((type) => ({ type })),
  [1n, tm, startTime, interval, reward, evidence, ethLock, hs]));
function fixture({ changed = {}, deny = public403, safeDenied = [], replacement = false,
  sameBlock = false, lockUnknown = false, noStageA = false, headerDenied = false, hugeHistory = false,
  proofHeight = 9000, chainRoot = root, lockLogs, startRange = [1000n, 58600n],
  lockReadCost = 1, timestampDenied = false, proofLogIndex = 20,
  headHeight = 10000n, lateResultHeight = 9100n } = {}) {
  const report = createReport(), reads = [], logs = [], values = { ...valid, ...changed };
  const timestamps = [];
  const event = { ...proofEvent, evtBlock: proofHeight, logIndex: proofLogIndex };
  for (const [id, params] of [
    ['stageA.rootMatch', { recomputed: applicant, onchain: applicant, registeredBlock: 7000 }],
    ['stageB.hashRegisteredBlock', { onchain: 7000, membership: true }],
    ['stageB.applicantHashField', { onchain: applicant }], ['stageB.confirmationBlocks', { pinned: 64 }],
    ['stageB.targetBlockNum', { expected: 7064 }], ['stageB.targetBlockHash', { onchain: valid.randaoBlockHash }],
  ]) report.check('check.' + id, noStageA && id === 'stageA.rootMatch' ? 'skip' : 'pass', params);
  const base = createChain({ chainIdExpected: 31337, contracts: { tokenMining: tm }, rpcUrls: ['http://127.0.0.1:1'] },
    { t: t('ja'), warn() {} }, custom({ request: async () => { throw deny; } }, { retryCount: 0 }));
  const typedRead = base.client.readContract, typedBlock = base.client.getBlock;
  const chain = { ...base, rpcUrl: 'http://127.0.0.1:1', client: { ...base.client,
    getBlockNumber: async () => { reads.push('getBlockNumber'); return headHeight; },
    getChainId: async () => { reads.push('getChainId'); return 1; },
    getBlock: async (request) => {
      reads.push('getBlock');
      if (headerDenied) return typedBlock(request);
      return { number: BigInt(proofHeight), timestamp: BigInt(proofHeight * 10) };
    },
    getTransaction: async () => ({ to: tm, input: encodeFunctionData({ abi: TOKEN_MINING_ABI,
      functionName: 'submitMerkleRootWithProof', args: [8n, chainRoot, lock, hash('ee'), encodePublicValues(values),
        '0x4388a21c' + '00'.repeat(352), 0n] }) }),
    readContract: async (r) => {
      reads.push(r.functionName);
      if (r.blockNumber === BigInt(proofHeight) || safeDenied.includes(r.functionName)) return typedRead(r);
      if (r.blockNumber != null) eq(r.blockNumber, headHeight - 64n, 'all new getter reads fixed at latest-64');
      const n = r.args?.[0], i = r.args?.[1];
      switch (r.functionName) {
        case 'evidence': return evidence;
        case 'hashStorage': return hs;
        case 'GAME_PERIOD': return 100n;
        case 'resultWindow': return [60000n, 80000n];
        case 'evidenceAcc': return valid.evidenceAcc;
        case 'entryAcc': return valid.entryAcc;
        case 'currentGrace': return 120n;
        case 'scheduledGameStart': return 50000n;
        case 'resultRegistrationCount': return hugeHistory ? 1n << 200n : 2n;
        case 'resultRegistrationAt': return [i === 0n ? n === 8n ? result : prev : hash('ff'),
          i === 0n ? 8000n : sameBlock ? 9000n : lateResultHeight, 80000n, lock];
        case 'resultHashes': return [hash('ff'), 9100n, lock];
        case 'otherRegistrationCount': return 3n;
        case 'otherRegistrationAt': return [i === 1n ? roster : hash('ff'), i === 2n ? 9500n : 5001n,
          i === 0n ? 49999n : i === 1n ? 50050n : 95000n];
        case 'claimDataOf': return [claimHash, 1, 1];
        case 'getClaimDataBlocks': return [replacement ? 9200n : 8990n];
        case 'ethLock': return lock;
        case 'START_TIME': return startTime;
        case 'BLOCK_INTERVAL': return interval;
        case 'calculateBlockReward': eq(r.args, [8n]); return reward;
        case 'deploymentParamsHash': return valid.deploymentParamsHash;
        default: throw new Error(`unexpected getter ${r.functionName}`);
      }
    },
    getLogs: async (r, { budget } = {}) => {
      budget?.take(lockReadCost);
      reads.push('getLogs'); logs.push(r);
      if (r.event.name === 'EthLockSet') return (lockLogs ?? (lockUnknown ? []
        : [{ address: tm, args: { ethLock: lock }, blockNumber: 8000n, logIndex: 0 }]))
        .filter((l) => l.blockNumber == null || (l.blockNumber >= r.fromBlock && l.blockNumber <= r.toBlock));
      if (r.event.name === 'ResultHashRegistered') return [{ args: { hash: hash('ff'), registrationCount: 2n }, blockNumber: 9000n, logIndex: 21 }];
      return [{ args: { chunkIndex: 0, totalChunks: 1, data: '0x' + chunk.toString('hex'), runningHash: claimHash },
        blockNumber: replacement ? 9200n : 8990n, logIndex: 0 }];
    },
  }, getLogsChunked: async () => [], findBlockByTimestamp: async (timestamp) => {
    timestamps.push(timestamp);
    if (timestampDenied) throw new ArchiveUnavailableError();
    if (timestamp === Number(startTime) - 7 * 86400) return startRange[0];
    if (timestamp === Number(startTime) + 86400) return startRange[1];
    throw new Error('unexpected timestamp');
  } };
  return { chain, report, reads, logs, values, event, chainRoot, timestamps };
}
async function inspect(options = {}) {
  const f = fixture(options);
  const inspected = await zkp.inspectProofSubmission({ chain: f.chain, blockNum: 8, root: f.chainRoot, event: f.event,
    artifacts: {}, epoch: { verifier: lock, vkey: hash('ee') }, report: f.report });
  recordZkpPublicValuesCheck({ report: f.report, data: {} }, inspected.publicValues);
  return { ...f, inspected, check: f.report.get('check.stageC.zkPublicValues') };
}
const correct = await inspect();
eq(correct.check.status, 'pass', 'real 403 response reaches word fallback and verifies 14 words');
eq(correct.check.params.verifiedWords.length, 14);
eq(correct.check.params.unverifiedWords, []);
eq(correct.check.params.separateWords[0].name, 'futureAnchorsHash');
eq(correct.check.params.rpcReads.total, correct.reads.length - 8 - correct.logs.filter((r) => r.event.name === 'EthLockSet').length,
  'word RPC count excludes collector attempts and separately bounded EthLock logs');
ok(correct.check.params.rpcReads.total <= 48);
ok(correct.logs.every((r) => r.fromBlock > 0n && r.toBlock - r.fromBlock < 2000n), 'no genesis sweep');
console.log('FIX8_RPC_COUNT ' + JSON.stringify(correct.check.params.rpcReads));
eq((await inspect({ deny: public4444 })).check.status, 'pass', 'real 4444 response also uses typed fallback');
// FIX9: 配備時のset-onceを、応募開始の前後だけから示す。証明の古さで窓を広げない。
const lockEvent = (blockNumber, overrides = {}) => ({ address: tm, args: { ethLock: lock }, blockNumber, logIndex: 0, ...overrides });
const longProof = { proofHeight: 90000, headHeight: 100000n, lateResultHeight: 90100n };
const beforeStart = await inspect({ ...longProof, lockLogs: [lockEvent(46200n)], lockReadCost: 2 });
eq(beforeStart.check.status, 'pass', 'FIX9 set about 17 hours before START_TIME is found long before proof');
eq(beforeStart.check.params.verifiedWords.length, 14);
eq(beforeStart.timestamps, [Number(startTime) - 7 * 86400, Number(startTime) + 86400]);
const lockRanges = beforeStart.logs.filter((r) => r.event.name === 'EthLockSet');
ok(lockRanges.every((r) => r.address === tm && r.fromBlock > 0n && r.toBlock - r.fromBlock < 1000n));
ok(lockRanges.every((r) => (r.fromBlock >= 88001n && r.toBlock <= 90000n) || (r.fromBlock >= 1000n && r.toBlock <= 58600n)), 'exactly two windows');
eq(beforeStart.check.params.rpcReads.ethLockLogs.total, lockRanges.length * 2, 'primary refusal plus fallback count separately');
const afterProof = await inspect({ lockLogs: [lockEvent(9500n)], changed: { deploymentParamsHash: deploymentHash(address('00')) } });
eq(afterProof.check.status, 'pass', 'FIX9 later set uses zero lock in the original deployment hash formula');
const wrongAfterProof = await inspect({ lockLogs: [lockEvent(9500n)] });
eq(wrongAfterProof.check.status, 'fail', 'current deployment hash cannot pass a proof preceding setEthLock');
eq(wrongAfterProof.check.params.mismatches.map((m) => m.name), ['deploymentParamsHash']);
for (const [label, options] of [
  ['neither window', { ...longProof, lockLogs: [lockEvent(70000n)] }],
  ['wrong emitter', { ...longProof, lockLogs: [lockEvent(46200n, { address: address('ab') })] }],
  ['wrong argument', { ...longProof, lockLogs: [lockEvent(46200n, { args: { ethLock: address('ab') } })] }],
]) {
  const f = await inspect(options);
  eq(f.check.status, 'skip', `FIX9 ${label} is unverified, never FAIL`);
  eq(f.check.params.unverifiedWords, [{ name: 'deploymentParamsHash', reason: 'ethLock_set_time_unproven' }]);
  eq(f.check.params.verifiedWords.length, 13, 'other 13 words remain verified');
  eq(EXIT_CODE_OF[categorize({ report: f.report, fatal: false, stopped: false })], 1);
}
for (const [index, expectedHash] of [[19, valid.deploymentParamsHash], [21, deploymentHash(address('00'))]]) {
  eq((await inspect({ lockLogs: [lockEvent(9000n, { logIndex: index })], changed: { deploymentParamsHash: expectedHash } })).check.status,
    'pass', `same block logIndex ${index} establishes ordering`);
}
for (const options of [{ proofLogIndex: null }, { lockLogs: [lockEvent(9000n, { logIndex: null })] }]) {
  const f = await inspect({ lockLogs: [lockEvent(9000n)], ...options });
  eq(f.check.status, 'skip');
  eq(f.check.params.unverifiedWords, [{ name: 'deploymentParamsHash', reason: 'same_block_order_unavailable' }]);
}
const fullWindows = await inspect({ ...longProof, lockLogs: [], lockReadCost: 2 });
eq(fullWindows.logs.filter((r) => r.event.name === 'EthLockSet').length, 60, '2 recent and 58 START_TIME chunks');
eq(fullWindows.check.params.rpcReads.ethLockLogs.total, 120);
const logBudget = await inspect({ ...longProof, lockLogs: [], startRange: [1000n, 200000n], lockReadCost: 2 });
eq(logBudget.check.params.rpcReads.ethLockLogs.total, 128, 'FIX9 hard log budget reached');
eq(logBudget.check.params.unverifiedWords, [{ name: 'deploymentParamsHash', reason: 'ethLock_log_read_budget_exceeded' }]);
eq(logBudget.check.params.verifiedWords.length, 13);
const noHeader = await inspect({ lockLogs: [], timestampDenied: true });
eq(noHeader.check.params.unverifiedWords, [{ name: 'deploymentParamsHash', reason: 'archive_unavailable' }]);
console.log('FIX9_RPC_COUNT ' + JSON.stringify({ beforeStart: beforeStart.check.params.rpcReads.ethLockLogs,
  absent: fullWindows.check.params.rpcReads.ethLockLogs, budget: logBudget.check.params.rpcReads.ethLockLogs }));
// Z-1: Evidenceを採らない入力のrootがチェーンにもproofにも載った盤面。
// 外形の二語は通っても、submitResultを畳み込んだチェーンのaccとの差を消さない。
const excludedEvidenceRoot = hash('13');
const z1 = await inspect({ chainRoot: excludedEvidenceRoot,
  changed: { merkleRoot: excludedEvidenceRoot, evidenceAcc: hash('00') } });
eq(z1.inspected.format.status, 'pass', 'Z-1 root and calldata agree');
eq(z1.check.status, 'fail', 'Z-1 omitted Evidence accumulator fails');
eq(z1.check.params.mismatches.map((m) => m.name), ['evidenceAcc']);
eq(EXIT_CODE_OF[categorize({ report: z1.report, fatal: false, stopped: false })], 2);

// 全15語を独立に偽る。Evidenceを除いたacc=0も明示する。
for (const { name, type } of PV_COMPONENTS) {
  const changed = { [name]: type === 'uint256' ? valid[name] + 1n : name === 'evidenceAcc' ? hash('00') : hash('12') };
  const f = await inspect({ changed });
  if (name === 'futureAnchorsHash') {
    eq(f.check.status, 'pass', 'future word is not judged twice');
    const checked = await checkProofFutureAnchor(f.chain, 8, proofEvent, changed[name]);
    f.report.check('check.stageC.futureAnchorsHash', checked.status, checked);
    eq(checked.status, 'fail', 'future invalid value fails independent check');
  } else {
    eq(f.check.status, 'fail', `${name} tamper fails`);
    if (!['blockNum', 'merkleRoot'].includes(name)) {
      ok(f.check.params.mismatches.some((m) => m.name === name), `${name} identified`);
      const lines = []; f.report.renderSummary({ t: t('ja'), println: (s) => lines.push(s) }, { blockNum: 8, data: {} });
      ok(lines.some((s) => s.startsWith('  ✗ ') && s.includes('mismatches') && s.includes(name)), `${name} detail is JSON serializable`);
    }
  }
  eq(EXIT_CODE_OF[categorize({ report: f.report, fatal: false, stopped: false })], 2, `${name} exit 2`);
}
eq((await inspect({ sameBlock: true })).check.status, 'pass', 'same-height registration after proof excluded using logIndex');
eq((await inspect({ replacement: true })).check.status, 'skip', 'invalidation/republication after proof is not false FAIL');
ok((await inspect({ replacement: true })).check.params.unverifiedWords.some((w) => w.name === 'claimDataHash' && w.reason === 'claim_series_replaced_after_proof'));
eq((await inspect({ replacement: true, proofHeight: 9500, changed: { resultManifestHash: hash('ff') } })).check.status,
  'pass', 'correct proof after invalidation/republication and result reregistration passes');
const ordinary = await inspect({ deny: new Error('temporary RPC failure') });
ok(!ordinary.inspected.publicValues.wordwise && !ordinary.reads.includes('getBlockNumber'), 'ordinary collector failure never enters fallback');
for (const options of [{ safeDenied: ['evidenceAcc'] }, { noStageA: true }, { headerDenied: true }, { lockUnknown: true }]) {
  const f = await inspect(options);
  eq(f.check.status, 'skip', 'only unresolved words become typed unverified');
  ok(f.check.params.verifiedWords.length > 2);
  ok(f.check.params.unverifiedWords.length > 0);
  eq(EXIT_CODE_OF[categorize({ report: f.report, fatal: false, stopped: false })], 1);
  const bad = await inspect({ ...options, changed: { entryAcc: hash('12') } });
  eq(bad.check.status, 'fail', 'missing prerequisites do not erase independent mismatch');
}
const budget = await inspect({ hugeHistory: true });
ok(budget.check.params.rpcReads.total <= words.WORD_CHECK_TOTAL_RPC_LIMIT, 'large history stays within the global bound');
ok(Object.values(budget.check.params.rpcReads.byWord).every((b) => b.total <= b.limit), 'each word has its own bound');
eq(budget.check.params.unverifiedWords, [], 'uint256-sized history fits the bounded binary search');
for (const lang of SUPPORTED_LANGS) {
  const translate = t(lang), explanation = publicnodeExplanation(translate);
  const can = explanation.indexOf(translate('main.publicnodeCan')), cannot = explanation.indexOf(translate('main.publicnodeCannot'));
  const publicIndex = explanation.indexOf('  ・' + translate('summary.area.proofPublicValues'));
  const stateIndex = explanation.indexOf('  ・' + translate('summary.area.proofHistory'));
  ok(can < publicIndex && publicIndex < cannot && cannot < stateIndex, `${lang} explanation split`);
  const f = await inspect({ safeDenied: ['evidenceAcc'] });
  f.report.check('check.stageC.zkProofFormat', 'pass');
  f.report.check('check.stageC.zkVerifierIdentity', 'pass');
  f.report.unverified('check.stageC.futureAnchorsHash', new ArchiveUnavailableError());
  f.report.check('check.stageC.zkPrevRegistrationWitness', 'pass');
  eq(verificationCoverage(f.report).filter((r) => r.area.startsWith('proof')).map((r) => [r.area, r.reason]),
    [['proofPublicValues', 'archiveUnavailable'], ['proofHistory', 'archiveUnavailable']]);
  const lines = []; f.report.renderSummary({ t: translate, println: (s) => lines.push(s) }, { blockNum: 8, data: {} });
  ok(lines.includes(`  ${translate('summary.area.proofPublicValues')}: ${translate('summary.areaUnverified', { reason: translate('reason.archiveUnavailable') })}`));
  ok(!lines.some((line) => line.startsWith('  ⊘ check.stageC.zkPublicValues:')), 'SKIP detail is omitted');
  const detail = f.report.get('check.stageC.zkPublicValues');
  eq(detail.params.verifiedWords, f.check.params.verifiedWords, 'verified word names remain in check params');
  ok(detail.reason === 'archive_unavailable' && detail.params.unverifiedWords.length > 0, 'unverified word reasons remain in check params');
  ok(lines.includes(`  ${translate('summary.area.proofHistory')}: ${translate('summary.areaUnverified', { reason: translate('reason.archiveUnavailable') })}`), 'history SKIP remains in unverified coverage');
  const failed = await inspect({ changed: { evidenceAcc: hash('00') } });
  const failureLines = []; failed.report.renderSummary({ t: translate, println: (s) => failureLines.push(s) }, { blockNum: 8, data: {} });
  ok(failureLines.some((line) => line.startsWith('  ✗ ') && line.includes('mismatches') && line.includes('evidenceAcc')), 'mismatch word remains visible');
  f.report.check('check.stageC.zkPublicValues', 'pass', correct.check.params);
  eq(verificationCoverage(f.report).find((r) => r.area === 'proofPublicValues').verified, true, 'state skip does not suppress public-value coverage');
  f.report.check('check.stageC.futureAnchorsHash', 'pass');
  f.report.check('check.stageC.zkPrevRegistrationWitness', 'warn');
  eq(verificationCoverage(f.report).find((r) => r.area === 'proofHistory').verified, true, 'existing optional witness WARN does not become a new prerequisite');
}
for (const id of ['zkCurrentRequirement', 'zkEpoch', 'zkVerifierIdentity', 'zkProofStatus', 'zkProofFormat', 'zkPublicValues', 'zkPrevRegistrationWitness', 'futureAnchorsHash']) {
  eq(VERIFICATION_AREAS.filter((r) => r.matches.test('check.stageC.' + id)).length, 1, 'each proof check has exactly one row');
}
if (!mutation) for (const name of ['no_fallback', 'registration_height', 'current_result', 'current_claim', 'ignore_acc',
  'no_start_window', 'ignore_emitter', 'ignore_lock_arg', 'use_current_lock']) {
  const r = spawnSync(process.execPath, [import.meta.filename, '--mutation=' + name], { encoding: 'utf8', env: process.env });
  ok(r.status !== 0 && r.stdout.includes('MUTATION_APPLIED ' + name) && r.stderr.includes('AssertionError'), `${name}: mutation rejected by assertion`);
}
delete globalThis.__fix8CompareWords;
console.log(`fix8-verifier-unit: ${assertions} assertions PASS`);

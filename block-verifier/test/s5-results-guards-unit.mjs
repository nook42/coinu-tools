// S5 B-VER-03 / R13-P7L-02 / LR-02: Stage Cの回帰ガード。

import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createPublicClient, custom, encodeFunctionData } from 'viem';
const { createChain, isRevertLike } = await import(process.env.M14D_CHAIN_MODULE
  ? pathToFileURL(path.resolve(process.env.M14D_CHAIN_MODULE)).href
  : new URL('../src/chain.js', import.meta.url).href);
import { parse as parseJavaScript } from 'acorn';
import { createReport } from '../src/report.js';
import { emitNonInteractiveOutcome } from '../src/index.js';
import { makePlayer, buildSubmissionPayload, evidenceBytesFor, bytesToHex } from './players.mjs';
import { buildMembersIndex, validateResultBundle } from '../vendor/workers/game_workers/lib/evidence-reconciler.js';
import { encodeClaimData } from '../vendor/workers/game_workers/lib/claim-data-codec.js';
import { r2LimitKind, R2_LIMITS } from '../src/r2.js';
import { DEFAULTS } from '../src/config.js';
import { sha256HexOfString } from '../src/json-utils.js';
import { judgePrevRegistrationWitness } from '../src/prev-registration-witness.js';
import {
  assertEmergencyVerificationGate,
  EMERGENCY_ALLOWED_DIFFERENCE_CHECKS,
  EMERGENCY_DOWNGRADABLE_CHECKS,
  EMERGENCY_REQUIRED_CHECKS,
} from '../src/emergency.js';
import { categorizeEmergencyWrite, EXIT_CODE_OF } from '../src/index.js';
import {
  PREV_REGISTRATION_SENTINEL,
  TOKEN_MINING_ABI,
  ZERO_ADDRESS,
  ZERO_HASH,
  chunkChainHash,
  encodePublicValues,
  sha256Hex,
} from '../../Hardhat/bitcoinu/scripts/lib/zkp-pipeline.mjs';

const P8B_MUTATION = process.argv.find((arg) => arg.startsWith('--p8b-mutation='))?.split('=')[1] || null;
let p8bMutationTmpRoot = null;
if (P8B_MUTATION) {
  const allowed = new Set([
    'u7-emergency-guard', 'u7-marker-match', 'u7-proof-hash',
    'merkle-public-root', 'trust-any-chain-flag', 'summary-label-chain',
    'collector-drop-invalid-mark',
  ]);
  if (!allowed.has(P8B_MUTATION)) throw new Error(`unknown P8b S5 mutation: ${P8B_MUTATION}`);
  const verifierRoot = path.resolve(import.meta.dirname, '..');
  const repoRoot = path.resolve(verifierRoot, '..');
  p8bMutationTmpRoot = path.resolve(repoRoot, `tmp/P8b/s5-${P8B_MUTATION}-${process.pid}`);
  const mutationVerifier = path.join(p8bMutationTmpRoot, 'block-verifier');
  const mutationLib = path.join(p8bMutationTmpRoot, 'Hardhat/bitcoinu/scripts/lib');
  await fs.rm(p8bMutationTmpRoot, { recursive: true, force: true });
  await fs.mkdir(path.join(mutationVerifier, 'src/stages'), { recursive: true });
  await fs.mkdir(mutationLib, { recursive: true });
  await fs.writeFile(path.join(mutationVerifier, 'package.json'), '{"type":"module"}\n');
  for (const entry of await fs.readdir(path.join(verifierRoot, 'src'), { withFileTypes: true })) {
    if (entry.name === 'zkp.js' || entry.name === 'stages') continue;
    await fs.symlink(path.join(verifierRoot, 'src', entry.name), path.join(mutationVerifier, 'src', entry.name));
  }
  for (const entry of await fs.readdir(path.join(verifierRoot, 'src/stages'), { withFileTypes: true })) {
    if (entry.name === 'results.js') continue;
    await fs.symlink(
      path.join(verifierRoot, 'src/stages', entry.name),
      path.join(mutationVerifier, 'src/stages', entry.name),
    );
  }
  await fs.symlink(path.join(verifierRoot, 'vendor'), path.join(mutationVerifier, 'vendor'));
  const canonicalLib = path.join(repoRoot, 'Hardhat/bitcoinu/scripts/lib');
  for (const entry of await fs.readdir(canonicalLib, { withFileTypes: true })) {
    if (entry.name === 'collect-zkp-input.mjs') continue;
    await fs.symlink(path.join(canonicalLib, entry.name), path.join(mutationLib, entry.name));
  }

  const canonicalResults = await fs.readFile(path.join(verifierRoot, 'src/stages/results.js'), 'utf8');
  const canonicalZkp = await fs.readFile(path.join(verifierRoot, 'src/zkp.js'), 'utf8');
  const canonicalCollector = await fs.readFile(path.join(canonicalLib, 'collect-zkp-input.mjs'), 'utf8');
  let mutatedResults = canonicalResults;
  let mutatedZkp = canonicalZkp;
  let mutatedCollector = canonicalCollector;
  if (P8B_MUTATION === 'u7-emergency-guard') {
    mutatedResults = mutatedResults.replace(
      '  const emergencyHijackPeriodProof = Boolean(emergencyMode)',
      '  const emergencyHijackPeriodProof = true',
    );
  } else if (P8B_MUTATION === 'u7-marker-match') {
    mutatedResults = mutatedResults.replace(
      '    && currentMarkerMatchesFixedCore\n',
      '    && true\n',
    );
  } else if (P8B_MUTATION === 'u7-proof-hash') {
    mutatedResults = mutatedResults.replace(
      '    && proofBoundHashDiffersFromFixedCore;',
      '    && true;',
    );
  } else if (P8B_MUTATION === 'merkle-public-root') {
    mutatedResults = mutatedResults.replace(
      '      merkleRaw = JSON.stringify({ blockNum, root });',
      '      merkleRaw = S.files?.merkle?.raw;',
    );
  } else if (P8B_MUTATION === 'trust-any-chain-flag') {
    mutatedZkp = mutatedZkp.replace(
      '  if (error?.zkpChainAnchorMismatch === true && resultAnchorMismatchHashes(error)) {',
      '  if (error?.zkpChainAnchorMismatch === true) {',
    );
  } else if (P8B_MUTATION === 'summary-label-chain') {
    mutatedCollector = mutatedCollector.replace(
      'throw artifactMismatchError(`manifest内summary sha256不一致:',
      'throw chainAnchorMismatchError(`manifest内summary sha256不一致:',
    );
  } else if (P8B_MUTATION === 'collector-drop-invalid-mark') {
    mutatedCollector = mutatedCollector.replace(
      '          markStage3ArtifactInvalid(error);',
      '          void error;',
    );
  }
  if (mutatedResults === canonicalResults
      && mutatedZkp === canonicalZkp
      && mutatedCollector === canonicalCollector) {
    throw new Error(`${P8B_MUTATION} mutation was not applied`);
  }
  await fs.writeFile(path.join(mutationVerifier, 'src/stages/results.js'), mutatedResults);
  await fs.writeFile(path.join(mutationVerifier, 'src/zkp.js'), mutatedZkp);
  await fs.writeFile(path.join(mutationLib, 'collect-zkp-input.mjs'), mutatedCollector);
  process.env.P8B_RESULTS_MODULE = path.join(mutationVerifier, 'src/stages/results.js');
  process.env.P8A_ZKP_MODULE = path.join(mutationVerifier, 'src/zkp.js');
  process.env.P8A_COLLECTOR_MODULE = path.join(mutationLib, 'collect-zkp-input.mjs');
}

const moduleTarget = (environmentName, normalUrl) => (
  process.env[environmentName]
    ? (process.env[environmentName].startsWith('data:')
      ? process.env[environmentName]
      : pathToFileURL(path.resolve(process.env[environmentName])).href)
    : normalUrl.href
);
const {
  canInspectRosterManifest,
  buildZkpArtifacts,
  checkManifest,
  classifyZkpPublicValuesForMode,
  findGcpProofRegistration,
  recordEmergencyZkpMerkleMetadataDifference,
  recordZkpProofFormatForMode,
  recordZkpPublicValuesCheck,
  verifyZkpSubmission,
  downloadArtifacts,
  refetchDeclaredRaw,
  settleManifestParked,
  inspectRosterAnchor,
  rosterReregistrationCheck,
} = await import(moduleTarget(
  'P8B_RESULTS_MODULE',
  new URL('../src/stages/results.js', import.meta.url),
));
const {
  buildExpectedPublicValues,
  describeZkpCollectionFailure,
  foldEvidenceAcc,
  inspectProofSubmission,
  localArtifactFetch,
  requireProofPrevRegistrationIndex,
  resolveProofSubmissionCalldata,
  ZKP_COLLECTION_FAILURE_CAUSES,
} = await import(moduleTarget('P8A_ZKP_MODULE', new URL('../src/zkp.js', import.meta.url)));
const { collectZkpInput } = await import(moduleTarget(
  'P8A_COLLECTOR_MODULE',
  new URL('../../Hardhat/bitcoinu/scripts/lib/collect-zkp-input.mjs', import.meta.url),
));

let passed = 0;
let failed = 0;
const ok = (label, condition, detail = '') => {
  if (condition) { passed++; console.log(`  ok: ${label}`); }
  else { failed++; console.error(`  NG: ${label}${detail ? ` — ${detail}` : ''}`); }
};
const detailJson = (value) => JSON.stringify(
  value, (_key, item) => (typeof item === 'bigint' ? item.toString() : item),
);

// viem の実際の error chain を custom transport で作る。データなし revert と
// 一時的な RPC 制限を同じ legacy 扱いにしない。
const m14dCountAbi = [{ type: 'function', name: 'otherRegistrationCount',
  stateMutability: 'view', inputs: [{ type: 'bytes32', name: 'key' }],
  outputs: [{ type: 'uint256' }] }];
async function m14dCountError(rpcError) {
  const client = createPublicClient({ transport: custom({
    request: async () => { throw rpcError; },
  }) });
  try {
    await client.readContract({ address: `0x${'11'.repeat(20)}`,
      abi: m14dCountAbi, functionName: 'otherRegistrationCount',
      args: [`0x${'22'.repeat(32)}`] });
    return null;
  } catch (error) { return error; }
}
const m14dLegacyError = await m14dCountError({ code: -32000, message: 'execution reverted' });
const m14dTransientError = await m14dCountError({ code: -32005, message: 'rate limited' });
const m14dChainCfg = { rpcUrls: ['http://unused.invalid'], chainIdExpected: 31337,
  contracts: { hashStorage: '0xd2c8a3be50d9a158bd579a26a346f54cfb93426d' } };
const m14dLegacyChain = createChain(m14dChainCfg, null, custom({
  request: async () => { throw { code: -32000, message: 'execution reverted' }; },
}));
const m14dTransientChain = createChain(m14dChainCfg, null, custom({
  request: async () => { throw { code: -32005, message: 'rate limited' }; },
}));
const m14dLegacyCount = await m14dLegacyChain.otherRegistrationCount(`0x${'22'.repeat(32)}`)
  .catch((error) => error);
const m14dTransientCount = await m14dTransientChain.otherRegistrationCount(`0x${'22'.repeat(32)}`)
  .catch((error) => error);
ok('M14d U-B: データなし ExecutionRevertedError は旧 HashStorage の getter 不在',
  m14dLegacyError?.walk((e) => e?.name === 'ExecutionRevertedError')
    && isRevertLike(m14dLegacyError, true)
    && !isRevertLike(m14dLegacyError) && m14dLegacyCount === null);
ok('M14d U-B: 一時的な RPC 制限は旧版扱いせず throw 対象に保つ',
  m14dTransientError?.walk((e) => e?.name === 'LimitExceededRpcError')
    && !isRevertLike(m14dTransientError, true)
    && m14dTransientCount instanceof Error);

const n4AllowedAddress = '0xd2c8a3be50d9a158bd579a26a346f54cfb93426d';
for (const [label, rpcError, legacy] of [
  ['execution reverted', { code: -32000, message: 'execution reverted' }, true],
  ['code 3', { code: 3, message: 'execution reverted' }, true],
  ['Internal error', { code: -32603, message: 'Internal error' }, false],
  ['-32603 header not found', { code: -32603, message: 'header not found' }, false],
  ['rate limited', { code: -32005, message: 'rate limited' }, false],
  ['HTTP 429', { code: 429, message: 'Too Many Requests' }, false],
  ['HTTP 503', { code: 503, message: 'Service Unavailable' }, false],
  ['header not found', { code: -32000, message: 'header not found' }, false],
]) {
  for (const [address, allowed] of [[n4AllowedAddress, true], [`0x${'11'.repeat(20)}`, false]]) {
    const c = createChain({ ...m14dChainCfg, contracts: { hashStorage: address } }, null,
      custom({ request: async () => { throw rpcError; } }));
    const value = await c.otherRegistrationCount(`0x${'22'.repeat(32)}`).catch((error) => error);
    ok(`R32-A-4-03: ${allowed ? '許可内' : '許可外'} ${label}の旧版判定`,
      allowed && legacy ? value === null : value instanceof Error,
      detailJson({ address, label, value: value?.message ?? value }));
  }
}
for (const [address, allowed] of [[n4AllowedAddress, true], [`0x${'11'.repeat(20)}`, false]]) {
  const zeroData = createChain({ ...m14dChainCfg, contracts: { hashStorage: address } }, null,
    custom({ request: async () => '0x' }));
  const result = await zeroData.otherRegistrationCount(`0x${'22'.repeat(32)}`)
    .catch((error) => error);
  ok(`R32-A-4-05: ${allowed ? '許可内' : '許可外'} 0x応答の旧版判定`,
    allowed ? result === null : result instanceof Error);
  for (const [label, rpcError, old] of [
    ['execution reverted', { code: -32000, message: 'execution reverted' }, true],
    ['Internal error', { code: -32603, message: 'Internal error' }, false],
  ]) {
    const chain = createChain({ ...m14dChainCfg, contracts: { hashStorage: address } }, null,
      custom({ request: async () => { throw rpcError; } }));
    for (const [name, args] of [
      ['firstOtherRegistration', [`0x${'22'.repeat(32)}`]],
      ['firstMatchingOtherRegistration', [`0x${'22'.repeat(32)}`, 100, `0x${'33'.repeat(32)}`]],
    ]) {
      const value = await chain[name](...args).catch((error) => error);
      ok(`R32-A-4-05: ${name} ${allowed ? '許可内' : '許可外'} ${label}`,
        allowed && old ? value === null : value instanceof Error);
    }
  }
}
const n4CurrentError = createChain(m14dChainCfg, null, custom({ request: async () => {
  throw { code: -32603, message: 'Internal error' };
} }));
ok('R32-X-01: getOtherHashの既存revert→nullは維持',
  await n4CurrentError.getOtherHash(`0x${'22'.repeat(32)}`) === null);
const n4ResultAbi = [
  { type: 'function', name: 'getResultHash', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'bytes32' }, { type: 'uint256' }, { type: 'address' }] },
  { type: 'function', name: 'resultRegistrationCount', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'uint256' }] },
];
const n4GetResultSelector = encodeFunctionData({ abi: n4ResultAbi,
  functionName: 'getResultHash', args: [4n] }).slice(0, 10);
const n4Word = (value) => BigInt(value).toString(16).padStart(64, '0');
for (const [label, failure, count, expected] of [
  ['一過性の-32603', { code: -32603, message: 'Internal error' }, 1, 'error'],
  ['真の未登録', { code: 3, message: 'execution reverted' }, 0, 'null'],
  ['登録済みのrevert', { code: 3, message: 'execution reverted' }, 1, 'error'],
  ['正直な登録', null, 1, 'row'],
]) {
  const c = createChain({ ...m14dChainCfg, contracts: { hashStorage: `0x${'11'.repeat(20)}` } },
    null, custom({ request: async ({ params }) => {
    const selector = params?.[0]?.data?.slice(0, 10);
    if (selector === n4GetResultSelector) {
      if (failure) throw failure;
      return `0x${'ab'.repeat(32)}${n4Word(7)}${'00'.repeat(12)}${'11'.repeat(20)}`;
    }
    return `0x${n4Word(count)}`;
  } }));
  const value = await c.getResultHash(4).catch((error) => error);
  ok(`R32-D-9-01: ${label}の結果目印`,
    expected === 'error' ? value instanceof Error
      : expected === 'null' ? value === null
        : value?.hash === `0x${'ab'.repeat(32)}` && value.updated === 7,
    detailJson({ label, value: value?.message ?? value }));
}

// R32-D-2-07: legacy の現在値判定は entryEnd <= registeredAt < chattingStart。
const n4Raw = '{"blockNum":4,"groups":[]}';
const n4Hash = (await import('viem')).keccak256((await import('viem')).stringToHex(n4Raw));
async function n4Roster(at, { historyError = false, hash = n4Hash } = {}) {
  const chain = {
    otherRegistrationCount: historyError
      ? async () => { throw new Error('history transport unavailable'); }
      : async () => null,
    getOtherHash: async () => ({ hash, updated: 7 }),
    getBlock: async () => ({ timestamp: BigInt(at) }),
  };
  return inspectRosterAnchor(chain, { blockNum: 4, raw: n4Raw,
    entryEndMs: 100_000, chattingStartMs: 110_000 }, historyError);
}
for (const [at, status, firstMatching, lateCount] of [
  [99, 'fail', null, 0], [100, 'pass', 0, 0],
  [109, 'pass', 0, 0], [110, 'fail', 0, 1],
]) {
  for (const historyError of [false, true]) {
    const value = await n4Roster(at, { historyError });
    const actual = value.failures.length ? 'fail' : value.warnings.length ? 'warn' : 'pass';
    ok(`R32-D-2-07: ${historyError ? '履歴読取失敗' : '旧版'} 時刻${at}の下限と上限`,
      actual === status && (value.registration?.firstMatching?.index ?? null) === firstMatching
        && value.registration?.lateCount === lateCount,
      detailJson(value));
  }
}
const n4Wrong = await n4Roster(105, { historyError: true, hash: `0x${'11'.repeat(32)}` });
ok('R32-X-01: 履歴読取失敗後も現在値の異なるhashはfail',
  n4Wrong.failures.includes('published roster C does not match the on-chain hash')
    && n4Wrong.registration?.historyUnreadable?.includes('history transport unavailable'),
  detailJson(n4Wrong));
for (const [label, registration, status, reason] of [
  ['履歴なし', null, 'skip', 'roster_history_unreadable'],
  ['履歴読取失敗', n4Wrong.registration, 'skip', 'roster_history_unreadable'],
  ['旧版', (await n4Roster(105)).registration, 'skip', 'legacy_hash_storage_has_no_history'],
  ['正直な履歴', { legacy: false, index: 0, preEntryCount: 0,
    first: { hash: n4Hash, index: 0, registeredAt: 105 },
    row: { hash: n4Hash, registeredAt: 105 } }, 'pass', null],
  ['異なる履歴', { legacy: false, index: 1, preEntryCount: 0,
    first: { hash: `0x${'11'.repeat(32)}`, index: 0, registeredAt: 103 },
    row: { hash: n4Hash, registeredAt: 105 } }, 'warn', null],
]) {
  const value = rosterReregistrationCheck(registration);
  ok(`R32-D-1-01: ${label}のやり直し表示`,
    value.status === status && (reason ? value.params.reason === reason
      && value.params.count === null && value.params.firstIndex === null : true),
    detailJson(value));
}

// P6b: noGame の実呼び出し口を AST で見る。コメントや純関数だけでは通らない。
{
  const source = await fs.readFile(
    process.env.P6B_RESULTS_SOURCE || new URL('../src/stages/results.js', import.meta.url), 'utf8',
  );
  const ast = parseJavaScript(source, { ecmaVersion: 'latest', sourceType: 'module' });
  const calls = [];
  const visit = (node) => {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'CallExpression'
        && node.callee?.name === 'zeroEntryNoGameSummaryShapeMatches') calls.push(node);
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) value.forEach(visit);
      else if (value && typeof value === 'object') visit(value);
    }
  };
  visit(ast);
  const argument = calls[0]?.arguments?.[0];
  const mode = argument?.properties?.find((property) => property.key?.name === 'emergencyMode')?.value;
  const actual = mode ? source.slice(mode.start, mode.end) : null;
  ok('P6b 通常noGameの実呼び出しは緊急源の有無を渡す',
    calls.length === 1 && actual === 'Boolean(ctx.data.emergencySource)',
    detailJson({ calls: calls.length, actual }));
}

// B-VER-03: archiveChainConsistencyは観測情報で、旧実装では無条件PASSだった。
// これを「効いているように見える」降格条件から外し、実内容のsummaryMatchを条件にする。
const report = createReport();
report.check('check.stageC.summaryMatch', 'pass');
report.check('check.stageC.manifestFiles', 'fail', { failures: 'games/block5/summary.json' });
const S = {
  auto: false,
  manifestParked: ['games/block5/summary.json'],
  manifestChecked: 1,
  anomalies: [],
};
settleManifestParked({ report, ui: { t: (key) => key } }, S);
ok('B-VER-03: archiveChainConsistency未記録でも実内容一致によりWARN降格',
  report.get('check.stageC.manifestFiles')?.status === 'warn');

const failedReport = createReport();
failedReport.check('check.stageC.summaryMatch', 'fail');
failedReport.check('check.stageC.manifestFiles', 'fail', { failures: 'games/block5/summary.json' });
settleManifestParked({ report: failedReport, ui: { t: (key) => key } }, { ...S, anomalies: [] });
ok('B-VER-03: 実内容のsummaryMatchがFAILならmanifestFilesをFAILのまま保持',
  failedReport.get('check.stageC.manifestFiles')?.status === 'fail');

const fetchedKeys = [];
await downloadArtifacts({
  blockNum: 13,
  ui: { println: () => {}, t: (key) => key },
  r2: {
    fetchJson: async (key) => { fetchedKeys.push(key); return null; },
    refetch: async () => null,
    releaseRaw: () => {},
    release: () => {},
  },
}, [], {
  auto: false,
  noGame: false,
  timelineNoGame: false,
  corrupt: [],
  missing: [],
  precheckedHashes: new Map(),
});
ok('R13-P7L-02: downloadArtifactsがstage3 manifestを実際に取得する',
  fetchedKeys.filter((key) => key === 'verification/block13/stage3/manifest.json').length === 1);

const declared = sha256HexOfString('{"ok":true}');
let missingRawResult = 'threw';
try {
  missingRawResult = await refetchDeclaredRaw({ refetch: async () => ({ data: { ok: true } }) }, 'key', declared);
} catch {}
ok('R13-P7L-02: refetch応答にrawが無ければthrowせず不一致にする', missingRawResult === null);
ok('R13-P7L-02: refetchしたrawが宣言hashと一致するときだけ採用する',
  (await refetchDeclaredRaw(
    { refetch: async () => ({ raw: '{"ok":true}', data: { ok: true } }) },
    'key',
    declared,
  ))?.raw === '{"ok":true}');
ok('R13-P7L-02: stage3 manifestに専用4 MiB上限を割り当てる',
  r2LimitKind('verification/block13/stage3/manifest.json') === 'stage3Manifest'
    && R2_LIMITS.stage3Manifest === 4 * 1024 * 1024);
const completeRoster = { raw: '{"blockNum":13}', data: { blockNum: 13 } };
ok('LR-02: declared欠落時はroster anchorの参照へ入らず、揃ったときだけ入る',
  canInspectRosterManifest(completeRoster, null) === false
    && canInspectRosterManifest(completeRoster, 1_700_000_000_000) === true);

// A4-01: helper単体ではなく、実際の2呼び出し元が不一致時にrefetchDeclaredRawを通ることを実測。
const freshRaw = '{"fresh":true}';
const staleRaw = '{"stale":true}';
const attackerRaw = '{"attacker":true}';
const freshHash = sha256HexOfString(freshRaw);
const summaryKey = 'games/block31/summary.json';
let precheckRefetches = 0;
const precheckS = {
  auto: false, noGame: true, timelineNoGame: false,
  corrupt: [], missing: [], precheckedHashes: new Map(),
};
await downloadArtifacts({
  blockNum: 31,
  ui: { println: () => {}, t: (key) => key },
  r2: {
    fetchJson: async (key) => {
      if (key === summaryKey) return { raw: staleRaw, data: { stale: true } };
      if (key === 'verification/block31/manifest.json') {
        return { raw: '{}', data: { files: { [summaryKey]: freshHash } } };
      }
      return null;
    },
    refetch: async (key) => {
      precheckRefetches++;
      assert.equal(key, summaryKey);
      return { raw: attackerRaw, data: { attacker: true } };
    },
    releaseRaw: () => {}, release: () => {},
  },
}, [], precheckS);
ok('A4-01: downloadArtifactsのprecheck call-siteが宣言hash不一致を再取得して赤判定する',
  precheckRefetches === 1 && precheckS.precheckedHashes.get(summaryKey)?.bad === true);

const stage3Key = 'verification/block32/stage3/manifest.json';
const manifestReport = createReport();
let manifestRefetches = 0;
const manifestS = {
  auto: false, groupIds: [], anomalies: [], precheckedHashes: new Map(),
  blockState: { verificationStartedAt: 1_700_000_000 },
  files: {
    manifest: { data: {
      blockNum: 32, algorithm: 'sha256', manifestHash: '0x00', rules: {},
      files: { [stage3Key]: freshHash },
    } },
    selection: null, gameGroups: null, summary: null, merkle: null,
    evidenceReport: null, stage3Manifest: { raw: staleRaw, data: { stale: true } },
    autoResult: null, rosterIndex: null, groups: new Map(), rosters: new Map(),
  },
};
await checkManifest({
  blockNum: 32, report: manifestReport, cfg: DEFAULTS, data: {},
  ui: { println: () => {}, t: (key) => key },
  r2: { refetch: async (key) => {
    manifestRefetches++;
    assert.equal(key, stage3Key);
    return { raw: attackerRaw, data: { attacker: true } };
  } },
  chain: {
    getResultHash: async () => null,
    resultRegistrationCount: async () => 1,
  },
}, manifestS, {
  startTimeEntryMs: 0, blockTimeMs: 1, gamePeriodMs: 1, submitPeriodMs: 1,
});
ok('A4-01: checkManifestのcall-siteが宣言hash不一致を再取得し、差し替えをFAILにする',
  manifestRefetches === 1
    && manifestReport.get('check.stageC.manifestFiles')?.status === 'fail'
    && manifestS.files.stage3Manifest.data.stale === true);

// T10 V2: Stage Cのローカルfetchが、共有collectorの全R2入力を同じbytesで供給する。
const zkpN = 41;
const tokenMining = `0x${'10'.repeat(20)}`;
const evidence = `0x${'20'.repeat(20)}`;
const hashStorage = `0x${'30'.repeat(20)}`;
const selectionHash = `0x${'51'.repeat(32)}`;
const selectionBlock = 111n;
const randaoHash = `0x${'61'.repeat(32)}`;
const merkleRoot = `0x${'71'.repeat(32)}`;
const selectionKey = `entries/block${zkpN}/game_selection.json`;
const stage3ManifestKey = `verification/block${zkpN}/stage3/manifest.json`;
const summaryZkpKey = `games/block${zkpN}/summary.json`;
const merkleZkpKey = `merkle/block_${zkpN}.json`;
const selectionRaw = JSON.stringify({
  blockNum: zkpN,
  applicantHash: selectionHash,
  hashRegisteredBlock: Number(selectionBlock),
  players: [],
});
const stage3ManifestRaw = JSON.stringify({
  schemaVersion: 1,
  kind: 'bitcoinu-stage3-input-manifest',
  blockNum: zkpN,
  groupCount: 0,
  groups: [],
});
const summaryZkpRaw = JSON.stringify({ blockNum: zkpN, groups: [] });
const merkleZkpRaw = JSON.stringify({ blockNum: zkpN, root: merkleRoot });
const manifestCoreRaw = JSON.stringify({
  blockNum: zkpN,
  algorithm: 'sha256',
  rules: {},
  files: {
    [selectionKey]: sha256Hex(Buffer.from(selectionRaw)).slice(2),
    [stage3ManifestKey]: sha256Hex(Buffer.from(stage3ManifestRaw)).slice(2),
    [summaryZkpKey]: sha256Hex(Buffer.from(summaryZkpRaw)).slice(2),
    [merkleZkpKey]: sha256Hex(Buffer.from(merkleZkpRaw)).slice(2),
  },
});
const resultManifestHash = sha256Hex(Buffer.from(manifestCoreRaw));
const manifestRaw = `${manifestCoreRaw.slice(0, -1)},"manifestHash":"${resultManifestHash}"}`;
const threeArtifacts = { manifest: manifestRaw, summary: summaryZkpRaw, merkle: merkleZkpRaw };
const claimChunks = [bytesToHex(encodeClaimData(zkpN, { groups: [] }).bytes)];
const claimDataHash = chunkChainHash(claimChunks);
const collectorClient = {
  getBlock: async () => ({ number: 999n, timestamp: 2_000_000_000n }),
  getContractEvents: async () => [{
    blockNumber: 800n,
    logIndex: 0,
    args: { chunkIndex: 0, totalChunks: 1, runningHash: claimDataHash, data: claimChunks[0] },
  }],
  readContract: async ({ address, functionName, args = [] }) => {
    const normalized = String(address).toLowerCase();
    if (normalized === tokenMining.toLowerCase()) {
      if (functionName === 'evidence') return evidence;
      if (functionName === 'hashStorage') return hashStorage;
      if (functionName === 'anchorProvider' || functionName === 'pendingAnchorProvider') return ZERO_ADDRESS;
      if (functionName === 'pendingVkeyEta') return 0n;
      if (functionName === 'claimDataOf') return [claimDataHash, 1n, 1n];
      if (functionName === 'getClaimDataBlocks') return [800n];
      if (functionName === 'deploymentParamsHash') return ZERO_HASH;
    }
    if (normalized === evidence.toLowerCase()) {
      if (functionName === 'evidenceAcc' || functionName === 'entryAcc') return ZERO_HASH;
      if (functionName === 'currentGrace') return 7200n;
      if (functionName === 'scheduledGameStart') return 1_800_000_000n;
      if (functionName === 'blockHashOf') return randaoHash;
    }
    if (normalized === hashStorage.toLowerCase()) {
      if (functionName === 'registrationCount') return 2n;
      if (functionName === 'otherRegistrationCount') return 0n;
      if (functionName === 'rosterLastIn') return [false, ZERO_HASH];
      if (functionName === 'isApplicantRegistered') {
        return BigInt(args[0]) === BigInt(zkpN)
          && BigInt(args[1]) === selectionBlock
          && String(args[2]).toLowerCase() === selectionHash.toLowerCase();
      }
      if (functionName === 'resultRegistrationCount') return 1n;
      if (functionName === 'resultRegistrationAt') {
        assert.equal(BigInt(args[1]), 0n);
        const rowHash = BigInt(args[0]) === BigInt(zkpN) ? resultManifestHash : ZERO_HASH;
        return [rowHash, 700n, 900n, ZERO_ADDRESS];
      }
      if (functionName === 'resultHashes') {
        return BigInt(args[0]) === BigInt(zkpN)
          ? [resultManifestHash, 900n, ZERO_ADDRESS]
          : [ZERO_HASH, 0n, ZERO_ADDRESS];
      }
    }
    throw new Error(`unexpected read ${address} ${functionName}`);
  },
};
const collectWith = (artifacts, client = collectorClient, options = {}) => collectZkpInput({
  rpcUrl: 'http://collector.invalid',
  tokenMining,
  blockNum: zkpN,
  r2Base: 'https://r2.invalid',
  fetchImpl: localArtifactFetch(zkpN, artifacts),
  client,
  ...options,
});
let threeKeyError = null;
try { await collectWith(threeArtifacts); }
catch (error) { threeKeyError = error; }
ok('stageC_local_fetch_three_keys_unavailable: 3キーだけではStage 3 manifestが404になる',
  /R2 verification\/block41\/stage3\/manifest\.json: HTTP 404/.test(String(threeKeyError?.message)));

const zkpDownloadObjects = new Map([
  [`verification/block${zkpN}/manifest.json`, { raw: manifestRaw, data: JSON.parse(manifestRaw) }],
  [selectionKey, { raw: selectionRaw, data: JSON.parse(selectionRaw) }],
  [stage3ManifestKey, { raw: stage3ManifestRaw, data: JSON.parse(stage3ManifestRaw) }],
  [summaryZkpKey, { raw: summaryZkpRaw, data: JSON.parse(summaryZkpRaw) }],
  [merkleZkpKey, { raw: merkleZkpRaw, data: JSON.parse(merkleZkpRaw) }],
]);
const zkpS = {
  auto: false,
  noGame: true,
  timelineNoGame: false,
  corrupt: [],
  missing: [],
  precheckedHashes: new Map(),
  blockState: { root: merkleRoot },
};
await downloadArtifacts({
  blockNum: zkpN,
  ui: { println: () => {}, t: (key) => key },
  r2: {
    fetchJson: async (key) => zkpDownloadObjects.get(key) ?? null,
    refetch: async () => null,
    releaseRaw: () => {},
    release: () => {},
  },
}, [], zkpS);
const fiveArtifacts = buildZkpArtifacts(zkpS, zkpS.files.summary.raw);
const p5SuppressedStage3Artifacts = buildZkpArtifacts(
  zkpS,
  zkpS.files.summary.raw,
  { stage3ManifestUsableForZkp: false },
);
ok('P5 R30-A-1-02 緊急選択でunusableと確定したStage 3 manifestはZKP collectorへ渡さない',
  p5SuppressedStage3Artifacts.stage3Manifest === undefined
    && fiveArtifacts.stage3Manifest === stage3ManifestRaw,
  detailJson(p5SuppressedStage3Artifacts));
let fiveKeyCollected = null;
let fiveKeyError = null;
try { fiveKeyCollected = await collectWith(fiveArtifacts); }
catch (error) { fiveKeyError = error; }
ok('stageC_local_fetch_with_selection_and_stage3_binds_k8_k9: 5キーで語8/語9をselectionへ束縛',
  fiveKeyError === null
    && fiveArtifacts.selection === selectionRaw
    && fiveArtifacts.stage3Manifest === stage3ManifestRaw
    && fiveKeyCollected.input.applicantHash === selectionHash
    && fiveKeyCollected.input.applicantHashUpdatedBlock === Number(selectionBlock),
  fiveKeyError?.message || '');

const mislabeledManifestRaw = `${manifestCoreRaw.slice(0, -1)},"manifestHash":"0x${'f1'.repeat(32)}"}`;
let mislabeledCollected = null;
let mislabeledError = null;
try {
  mislabeledCollected = await collectWith({ ...fiveArtifacts, manifest: mislabeledManifestRaw });
} catch (error) { mislabeledError = error; }
ok('Z10 (e-1) 自称 manifestHash だけを壊した入力でも collect-zkp-input は完走し、manifestCore の計算値を採用する',
  mislabeledError === null
  && mislabeledCollected?.resultManifestHash === resultManifestHash
  && mislabeledCollected?.input?.manifestCoreHex === `0x${Buffer.from(manifestCoreRaw).toString('hex')}`,
  mislabeledError?.message || '');

const wrongChainHash = `0x${'e2'.repeat(32)}`;
const mismatchedChainClient = {
  ...collectorClient,
  readContract: async (request) => {
    if (String(request.address).toLowerCase() === hashStorage.toLowerCase()
        && request.functionName === 'resultHashes'
        && BigInt(request.args?.[0] ?? -1) === BigInt(zkpN)) {
      return [wrongChainHash, 900n, ZERO_ADDRESS];
    }
    return collectorClient.readContract(request);
  },
};
let chainMismatchError = null;
try { await collectWith(fiveArtifacts, mismatchedChainClient); }
catch (error) { chainMismatchError = error; }
ok('Z10 (e-2) manifestCore の計算値が HashStorage.resultHashes と食い違う入力は従来どおり throw する',
  /HashStorage\.resultHashes不一致/.test(String(chainMismatchError?.message))
    && chainMismatchError?.zkpChainAnchorMismatch === true,
  chainMismatchError?.message || 'did not throw');

const tamperedStage3ManifestRaw = JSON.stringify({
  ...JSON.parse(stage3ManifestRaw),
  tampered: true,
});
let stage3MismatchError = null;
try { await collectWith({ ...fiveArtifacts, stage3Manifest: tamperedStage3ManifestRaw }); }
catch (error) { stage3MismatchError = error; }
let stage3InvalidError = null;
try { await collectWith({ ...fiveArtifacts, stage3Manifest: '{}' }); }
catch (error) { stage3InvalidError = error; }
let stage3OversizeError = null;
try {
  await collectWith({ ...fiveArtifacts, stage3Manifest: 'x'.repeat(4 * 1024 * 1024 + 1) });
} catch (error) { stage3OversizeError = error; }
let summaryMismatchError = null;
try {
  await collectWith({ ...fiveArtifacts, summary: JSON.stringify({ blockNum: zkpN, changed: true }) });
} catch (error) { summaryMismatchError = error; }
let rpcCollectionError = null;
try {
  await collectWith(fiveArtifacts, {
    ...collectorClient,
    getBlock: async () => { throw new Error('historical state unavailable'); },
  });
} catch (error) { rpcCollectionError = error; }

const z14Missing = describeZkpCollectionFailure(threeKeyError, 999);
const z14Mismatch = describeZkpCollectionFailure(stage3MismatchError, 999);
const z14Invalid = describeZkpCollectionFailure(stage3InvalidError, 999);
const z14OtherManifest = describeZkpCollectionFailure(chainMismatchError, 999);
const z14Rpc = describeZkpCollectionFailure(rpcCollectionError, 999);
const p8bSummaryMismatch = describeZkpCollectionFailure(summaryMismatchError, 999);
const p8bMislabeledSummaryError = Object.assign(
  new Error(String(summaryMismatchError?.message || 'manifest内summary sha256不一致')),
  { zkpArtifactMismatch: true, zkpChainAnchorMismatch: true },
);
const p8bMislabeledSummary = describeZkpCollectionFailure(p8bMislabeledSummaryError, 999);
const z14RequiredChecks = Object.values(EMERGENCY_REQUIRED_CHECKS).flat();
const z14Evaluate = (publicValues, emergencyMode, {
  chainResultMarker = { hash: resultManifestHash, updated: 1_000 },
  proofBlock = 999,
  authority = null,
  gcpHistoricalProofHash = false,
} = {}) => {
  const evaluationReport = createReport();
  for (const id of EMERGENCY_REQUIRED_CHECKS.groupGame) evaluationReport.check(id, 'pass');
  evaluationReport.check('check.stageC.zkProofFormat', 'pass', { pinned: true });
  const data = {
    emergencySource: emergencyMode ? {
      selectedManifest: JSON.parse(manifestRaw),
      chainResultMarker,
      authority,
      gcpHistoricalProofHash,
      gcpProofRegistrationIndex: gcpHistoricalProofHash ? 0 : null,
    } : null,
    emergencyDifferences: [],
  };
  recordZkpPublicValuesCheck(
    { report: evaluationReport, data }, publicValues, 'published', { evtBlock: proofBlock },
  );
  let gateError = null;
  if (emergencyMode) {
    try {
      assertEmergencyVerificationGate(evaluationReport, {
        kind: 'groupGame', rebuiltSummary: {}, allGroupResults: [],
      });
    } catch (error) { gateError = error; }
  }
  return { report: evaluationReport, data, gateError };
};

const p13Synthetic = JSON.parse(manifestRaw);
p13Synthetic.rules = { gcpCollectorProbe: true };
const p13Core = {
  blockNum: p13Synthetic.blockNum, algorithm: p13Synthetic.algorithm,
  rules: p13Synthetic.rules, files: p13Synthetic.files,
};
p13Synthetic.manifestHash = sha256Hex(Buffer.from(JSON.stringify(p13Core)));
const p13SyntheticRaw = JSON.stringify(p13Synthetic);
const p13Artifacts = buildZkpArtifacts({
  ...zkpS,
  files: { ...zkpS.files, manifest: { data: p13Synthetic, raw: p13SyntheticRaw } },
}, summaryZkpRaw, { authority: 'gcp', stage3ManifestUsableForZkp: true });
let p13CollectorError = null;
try { await collectWith(p13Artifacts); }
catch (error) { p13CollectorError = error; }
const p13CollectedVerdict = describeZkpCollectionFailure(p13CollectorError, 999);
const p13RealReport = createReport();
for (const id of EMERGENCY_REQUIRED_CHECKS.groupGame) p13RealReport.check(id, 'pass');
p13RealReport.check('check.stageC.zkProofFormat', 'pass');
const p13RealData = { emergencySource: {
  authority: 'gcp', selectedManifest: p13Synthetic,
  chainResultMarker: { hash: p13Synthetic.manifestHash },
  gcpHistoricalProofHash: true, gcpProofRegistrationIndex: 0,
}, emergencyDifferences: [] };
recordZkpPublicValuesCheck({ report: p13RealReport, data: p13RealData }, p13CollectedVerdict,
  'published', { evtBlock: 999 });
ok('P13 U-7: 実collectorは正典形の合成manifestを受け旧root証明を差分へ到達させる',
  p13CollectedVerdict.cause === ZKP_COLLECTION_FAILURE_CAUSES.proofBoundToOtherManifest
    && p13CollectedVerdict.proofBoundResultHash === resultManifestHash
    && p13RealReport.get('check.stageC.zkPublicValues')?.status === 'warn'
    && p13RealData.emergencyDifferences.some((difference) => (
      difference.checkId === 'emergency.gcpPriorRootProof')),
  detailJson({ cause: p13CollectedVerdict.cause, error: p13CollectorError?.message }));

const m3Sentinel = 'M3_UNTRUSTED_MERKLE_VALUE_SENTINEL';
const m3MerkleRaw = JSON.stringify({ blockNum: m3Sentinel, root: m3Sentinel,
  totalAmount: m3Sentinel });
const m3MerkleS = { ...zkpS, files: { ...zkpS.files, merkle: {
  raw: m3MerkleRaw, data: JSON.parse(m3MerkleRaw),
} } };
const m3MerkleCtx = { blockNum: zkpN, report: createReport(), data: {
  emergencySource: { authority: 'gcp' }, emergencyDifferences: [],
} };
recordEmergencyZkpMerkleMetadataDifference(m3MerkleCtx, m3MerkleS);
ok('M3: GCP ZKP の保存 Merkle メタは値を差分へ写さない',
  m3MerkleCtx.data.emergencyDifferences.length === 1
    && !detailJson(m3MerkleCtx.data.emergencyDifferences).includes(m3Sentinel)
    && m3MerkleCtx.data.emergencyDifferences[0].params.savedMerkleMeta.bytes
      === Buffer.byteLength(m3MerkleRaw));

const z14MissingEmergency = z14Evaluate(z14Missing, true);
const z14MissingCategory = categorizeEmergencyWrite(
  { differences: z14MissingEmergency.data.emergencyDifferences },
  { report: z14MissingEmergency.report, stopped: false, fatal: false },
);
ok('Z14 (a) 緊急モードで Stage 3 manifest が取得不能のとき、輸出が止まらず差分が1件残る',
  threeKeyError?.zkpArtifactMissing === true
    && z14Missing.cause === ZKP_COLLECTION_FAILURE_CAUSES.artifactMissing
    && z14MissingEmergency.report.get('check.stageC.zkPublicValues')?.status === 'warn'
    && z14MissingEmergency.data.emergencyDifferences.length === 1
    && z14MissingEmergency.data.emergencyDifferences[0]?.checkId === 'check.stageC.zkPublicValues'
    && z14MissingEmergency.gateError === null
    && z14MissingCategory === 'emergency_with_differences'
    && EXIT_CODE_OF[z14MissingCategory] === 4);

const z14MismatchEmergency = z14Evaluate(z14Mismatch, true);
ok('Z14 (b) 緊急モードでも Stage 3 manifest が改竄（sha256 不一致）のときは従来どおり止まる',
  stage3MismatchError?.zkpArtifactMismatch === true
    && z14Mismatch.cause === ZKP_COLLECTION_FAILURE_CAUSES.artifactMismatch
    && z14MismatchEmergency.report.get('check.stageC.zkPublicValues')?.status === 'fail'
    && z14MismatchEmergency.data.emergencyDifferences.length === 0
    && /verification failed: check\.stageC\.zkPublicValues/.test(String(z14MismatchEmergency.gateError?.message)));

const z14InvalidEmergency = z14Evaluate(z14Invalid, true);
ok('P5 R30-A-1-02 Stage 3 manifestの構造不正はrpc_unavailableと別原因になり、直接渡せば停止する',
  stage3InvalidError?.zkpArtifactInvalid === true
    && z14Invalid.cause === ZKP_COLLECTION_FAILURE_CAUSES.artifactInvalid
    && z14InvalidEmergency.report.get('check.stageC.zkPublicValues')?.status === 'fail'
    && z14InvalidEmergency.data.emergencyDifferences.length === 0
    && /verification failed: check\.stageC\.zkPublicValues/.test(String(z14InvalidEmergency.gateError?.message)),
  detailJson({ error: stage3InvalidError?.message, publicValues: z14Invalid }));
ok('P8b P5: Stage 3 manifestの取得上限超過はartifact_invalidの印を失わない',
  stage3OversizeError?.zkpArtifactInvalid === true
  && describeZkpCollectionFailure(stage3OversizeError, 999).cause
    === ZKP_COLLECTION_FAILURE_CAUSES.artifactInvalid,
  detailJson({ error: stage3OversizeError?.message, cause: describeZkpCollectionFailure(stage3OversizeError, 999) }));
ok('P8b P5: summary sha不一致はchain-anchor不一致へ誤分類せずartifact_mismatchのまま',
  summaryMismatchError?.zkpArtifactMismatch === true
  && summaryMismatchError?.zkpChainAnchorMismatch !== true
  && p8bSummaryMismatch.cause === ZKP_COLLECTION_FAILURE_CAUSES.artifactMismatch
  && p8bMislabeledSummary.cause === ZKP_COLLECTION_FAILURE_CAUSES.artifactMismatch,
  detailJson({
    error: summaryMismatchError?.message,
    publicValues: p8bSummaryMismatch,
    mislabeled: p8bMislabeledSummary,
  }));

const z14HijackProof = z14Evaluate(z14OtherManifest, true);
const z14WrongCurrentMarker = z14Evaluate(z14OtherManifest, true, {
  chainResultMarker: { hash: wrongChainHash, updated: 1_000 },
});
const z14ProofBindsFixedCore = z14Evaluate({
  ...z14OtherManifest,
  proofBoundResultHash: resultManifestHash,
}, true);
const z14ProofBoundHashMissing = z14Evaluate({
  ...z14OtherManifest,
  proofBoundResultHash: undefined,
}, true);
const z14OtherManifestNormal = z14Evaluate(z14OtherManifest, false);
const p12bGcpRegistered = z14Evaluate(z14OtherManifest, true, {
  authority: 'gcp', gcpHistoricalProofHash: true,
  chainResultMarker: { hash: wrongChainHash, updated: 1_000 },
});
const p12bGcpUnregistered = z14Evaluate(z14OtherManifest, true, {
  authority: 'gcp', chainResultMarker: { hash: wrongChainHash, updated: 1_000 },
});
const p13ProofHash = z14OtherManifest.proofBoundResultHash;
const p13Signer = `0x${'12'.repeat(20)}`;
const p13StateRow = (index, hash = `0x${(index + 1).toString(16).padStart(64, '0')}`) => ({
  hash, registeredBlock: index + 1, registeredAt: index + 1_000, signer: p13Signer,
});
const p13LogRow = (index, state) => ({
  blockNumber: 4, hash: state.hash, signer: state.signer, isUpdate: index > 0,
  updatedAt: state.registeredBlock, registrationCount: index + 1,
  evtBlock: state.registeredBlock,
});
const p12bHistoryRows = [p13StateRow(0, p13ProofHash), p13StateRow(1, resultManifestHash)];
const p12bHistoryChain = {
  resultRegistrationCount: async () => p12bHistoryRows.length,
  resultRegistrationAt: async (_block, index) => p12bHistoryRows[index],
  resultHashEvents: async () => p12bHistoryRows.map((row, index) => p13LogRow(index, row)),
};
const p12bHistoryMatch = await findGcpProofRegistration(p12bHistoryChain, 4,
  p13ProofHash);
const p12bHistoryMiss = await findGcpProofRegistration(p12bHistoryChain, 4,
  `0x${'a3'.repeat(32)}`);
let p13LogCalls = 0;
let p13LogRange = null;
const p13LargeProofHistory = await findGcpProofRegistration({
  resultRegistrationCount: async () => 8193,
  resultRegistrationAt: async (_block, index) => p13StateRow(index,
    index === 8192 ? p13ProofHash : undefined),
  resultHashEvents: async (_block, range) => {
    p13LogCalls++;
    p13LogRange = range;
    return Array.from({ length: 8193 }, (_, index) => {
      const row = p13StateRow(index, index === 8192 ? p13ProofHash : undefined);
      return p13LogRow(index, row);
    });
  },
}, 4, p13ProofHash);
ok('P13 U-7: 証明hashの照合は8193行でもログ一括取得で正直な行を見つける',
  p12bHistoryMatch === 0 && p12bHistoryMiss === null && p13LargeProofHistory === 8192
    && p13LogCalls === 1 && p13LogRange?.fromBlock === 1n
    && p13LogRange?.toBlock === 8193n,
  detailJson({ proofBoundHash: p13ProofHash,
    match: p12bHistoryMatch, miss: p12bHistoryMiss, large: p13LargeProofHistory,
    logCalls: p13LogCalls, logRange: p13LogRange }));
const p13MiddleRows = [p13StateRow(0), p13StateRow(1, p13ProofHash), p13StateRow(2)];
const p13MiddleLogs = p13MiddleRows.map((row, index) => p13LogRow(index, row));
const p13MiddleChain = (rows, logs = p13MiddleLogs) => ({
  resultRegistrationCount: async () => rows.length,
  resultRegistrationAt: async (_block, index) => rows[index],
  resultHashEvents: async () => logs,
});
const p13RegistrationError = async (chain) => {
  try { await findGcpProofRegistration(chain, 4, p13ProofHash); return null; }
  catch (error) { return String(error?.message || error); }
};
for (const [field, changed] of [
  ['hash', `0x${'ee'.repeat(32)}`],
  ['signer', `0x${'34'.repeat(20)}`],
  ['registeredBlock', 3],
]) {
  const rows = p13MiddleRows.map((row, index) => index === 1
    ? { ...row, [field]: changed } : row);
  const error = await p13RegistrationError(p13MiddleChain(rows));
  ok(`M1b: 証明hashのログ候補は状態の ${field} が違えば拒否する`,
    error === 'block 4: ResultHashRegistered log differs from state row 1', error);
}
const p13FallbackIndex = await findGcpProofRegistration(
  p13MiddleChain(p13MiddleRows, p13MiddleLogs.filter((row) => row.hash !== p13ProofHash)),
  4, p13ProofHash,
);
ok('M1b: ログに証明hashが無くても状態の古い行を逆順走査で見つける',
  p13FallbackIndex === 1, detailJson({ index: p13FallbackIndex }));
ok('P12b U-7: GCP入口で履歴登録済みの旧root証明だけ差分にして関門を通す',
  p12bGcpRegistered.report.get('check.stageC.zkPublicValues')?.status === 'warn'
    && p12bGcpRegistered.data.emergencyDifferences[0]?.checkId === 'emergency.gcpPriorRootProof'
    && p12bGcpRegistered.gateError === null
    && p12bGcpUnregistered.report.get('check.stageC.zkPublicValues')?.status === 'fail'
    && /verification failed/.test(String(p12bGcpUnregistered.gateError?.message)));
const p8bEmergencyGuardDirect = classifyZkpPublicValuesForMode(z14OtherManifest, false, {
  currentResultMarker: { hash: resultManifestHash, updated: 1_000 },
  fixedManifestCoreHash: resultManifestHash,
});
ok('P8b P5 R30-U-7 正: 緊急＋現在目印=固定core＋proof束縛hash≠coreの3条件でwarn＋差分',
  z14OtherManifest.cause === ZKP_COLLECTION_FAILURE_CAUSES.proofBoundToOtherManifest
    && z14HijackProof.report.get('check.stageC.zkPublicValues')?.status === 'warn'
    && z14HijackProof.data.emergencyDifferences.length === 1
    && z14HijackProof.data.emergencyDifferences[0]?.checkId === 'emergency.hijackPeriodProof'
    && z14HijackProof.gateError === null,
  detailJson({ publicValues: z14OtherManifest, difference: z14HijackProof.data.emergencyDifferences }));
ok('P8b P5 R30-U-7 負: 3条件のどれか1つでも欠ければ従来どおりfail',
  [z14WrongCurrentMarker, z14ProofBindsFixedCore, z14ProofBoundHashMissing, z14OtherManifestNormal].every((entry) => (
    entry.report.get('check.stageC.zkPublicValues')?.status === 'fail'
    && entry.data.emergencyDifferences.length === 0
  )) && p8bEmergencyGuardDirect.status === 'fail', detailJson({
    wrongMarker: z14WrongCurrentMarker.report.get('check.stageC.zkPublicValues'),
    proofBindsCore: z14ProofBindsFixedCore.report.get('check.stageC.zkPublicValues'),
    proofHashMissing: z14ProofBoundHashMissing.report.get('check.stageC.zkPublicValues'),
    normal: z14OtherManifestNormal.report.get('check.stageC.zkPublicValues'),
    directEmergencyGuard: p8bEmergencyGuardDirect,
  }));

const z14RpcEmergency = z14Evaluate(z14Rpc, true);
ok('Z14 (c) 緊急モードでも RPC 障害のときは従来どおり止まる',
  z14Rpc.cause === ZKP_COLLECTION_FAILURE_CAUSES.rpcUnavailable
    && z14RpcEmergency.report.get('check.stageC.zkPublicValues')?.status === 'fail'
    && z14RpcEmergency.data.emergencyDifferences.length === 0
    && /verification failed: check\.stageC\.zkPublicValues/.test(String(z14RpcEmergency.gateError?.message)));

const p8bBadMerkleRaw = JSON.stringify({ blockNum: zkpN, root: 'not-a-root' });
const p8bBadMerkleS = {
  ...zkpS,
  files: {
    ...zkpS.files,
    merkle: { raw: p8bBadMerkleRaw, data: JSON.parse(p8bBadMerkleRaw) },
  },
};
const p8bEmergencyMerkleArtifacts = buildZkpArtifacts(
  p8bBadMerkleS, p8bBadMerkleS.files.summary.raw, { stage3ManifestUsableForZkp: true },
);
const p8bNormalMerkleArtifacts = buildZkpArtifacts(p8bBadMerkleS, p8bBadMerkleS.files.summary.raw);
let p8bEmergencyMerkleCollected = null;
let p8bEmergencyMerkleError = null;
try { p8bEmergencyMerkleCollected = await collectWith(p8bEmergencyMerkleArtifacts); }
catch (error) { p8bEmergencyMerkleError = error; }
let p8bNormalMerkleError = null;
try { await collectWith(p8bNormalMerkleArtifacts); }
catch (error) { p8bNormalMerkleError = error; }
const p8bMerkleDifferenceCtx = {
  blockNum: zkpN,
  report: createReport(),
  data: { emergencySource: {}, emergencyDifferences: [] },
};
const p8bMerkleDifferenceRecorded = recordEmergencyZkpMerkleMetadataDifference(
  p8bMerkleDifferenceCtx, p8bBadMerkleS,
);
ok('P8b P5 A-1-02: 緊急ZKPは公開merkle rootでなく照合済みオンチェーンrootを使い、公開不正を差分へ残す',
  p8bEmergencyMerkleError === null
  && p8bEmergencyMerkleCollected?.merkleRoot === merkleRoot.toLowerCase()
  && JSON.parse(p8bEmergencyMerkleArtifacts.merkle).root === merkleRoot.toLowerCase()
  && p8bMerkleDifferenceRecorded === true
  && p8bMerkleDifferenceCtx.data.emergencyDifferences.length === 1
  && p8bMerkleDifferenceCtx.data.emergencyDifferences[0].checkId === 'check.stageC.merkleRoot',
  detailJson({ error: p8bEmergencyMerkleError?.message, differences: p8bMerkleDifferenceCtx.data.emergencyDifferences }));
ok('P8b P5 A-1-02 負: 通常モードは同じ不正な公開merkle metadataを従来どおり拒否する',
  p8bNormalMerkleArtifacts.merkle === p8bBadMerkleRaw
  && /merkle\/block_41\.json のrootが不正/.test(String(p8bNormalMerkleError?.message)),
  String(p8bNormalMerkleError?.message || ''));

const z14NormalTruthTable = [z14Missing, z14Mismatch, z14Invalid, z14OtherManifest, z14Rpc]
  .map((publicValues) => z14Evaluate(publicValues, false));
ok('Z14 (d) 通常モードは取得不能・改竄・構造不正・別manifest・RPC障害ともfailである',
  z14NormalTruthTable.every((entry) => (
    entry.report.get('check.stageC.zkPublicValues')?.status === 'fail'
    && entry.data.emergencyDifferences.length === 0
  )));

ok('Z14 (e) check.stageC.zkProofFormat の status がこの便の前後で1つも変わっていない',
  [z14MissingEmergency, z14MismatchEmergency, z14RpcEmergency, ...z14NormalTruthTable]
    .every((entry) => entry.report.get('check.stageC.zkProofFormat')?.status === 'pass'));

ok('Z14 (f) 改竄のエラー文に「アーカイブ対応 RPC」は現れず、取得不能は取得不能と分かる',
  z14Mismatch.error.includes('failed sha256 or canonical JSON validation')
    && !z14Mismatch.error.includes('archive-capable RPC')
    && z14Missing.error.includes('artifact is unavailable')
    && !z14Missing.error.includes('archive-capable RPC'));

const z14PolicyTables = [
  ...EMERGENCY_ALLOWED_DIFFERENCE_CHECKS,
  ...EMERGENCY_DOWNGRADABLE_CHECKS,
  ...z14RequiredChecks,
];
ok('Z14 (g) 許容表・降格表・必須表に zkPublicValues / zkProofFormat が入っていない',
  !z14PolicyTables.includes('check.stageC.zkPublicValues')
    && !z14PolicyTables.includes('check.stageC.zkProofFormat'));

const z14HonestEmergency = z14Evaluate({
  status: fiveKeyError === null ? 'pass' : 'fail',
  snapshotBlock: fiveKeyCollected?.snapshotBlock,
  ...(fiveKeyError ? { error: fiveKeyError.message } : {}),
}, true);
const z14HonestCategory = categorizeEmergencyWrite(
  { differences: z14HonestEmergency.data.emergencyDifferences },
  { report: z14HonestEmergency.report, stopped: false, fatal: false },
);
ok('Z14 (h) Stage 3 manifest が正しく在る緊急復旧は差分を1件も足さず終了コード0のままである',
  fiveKeyError === null
    && fiveArtifacts.stage3Manifest === stage3ManifestRaw
    && z14HonestEmergency.report.get('check.stageC.zkPublicValues')?.status === 'pass'
    && z14HonestEmergency.data.emergencyDifferences.length === 0
    && z14HonestEmergency.gateError === null
    && z14HonestCategory === 'full'
    && EXIT_CODE_OF[z14HonestCategory] === 0);

// P4 R30-U-2b / R30-U-6: 証明が名乗った履歴行で word7 を再現し、中継 tx は
// callTracer の TokenMining 向け証明呼び出しがちょうど1件のときだけ同じ検査へ通す。
const prevBlock = BigInt(zkpN - 1);
const prevOldHash = `0x${'a0'.repeat(32)}`;
const prevLatestHash = `0x${'b1'.repeat(32)}`;
const proofBytes = `0x4388a21c${'00'.repeat(352)}`;
const proofVerifier = `0x${'81'.repeat(20)}`;
const proofVkey = `0x${'82'.repeat(32)}`;
const relayAddress = `0x${'83'.repeat(20)}`;
const otherAddress = `0x${'84'.repeat(20)}`;

const historyCollectorClient = {
  ...collectorClient,
  readContract: async (request) => {
    const normalized = String(request.address).toLowerCase();
    const requestedBlock = BigInt(request.args?.[0] ?? -1);
    if (normalized === hashStorage.toLowerCase() && requestedBlock === prevBlock) {
      if (request.functionName === 'resultRegistrationCount') return 2n;
      if (request.functionName === 'resultRegistrationAt') {
        const index = BigInt(request.args?.[1] ?? -1);
        if (index === 0n) return [prevOldHash, 700n, 800n, ZERO_ADDRESS];
        if (index === 1n) return [prevLatestHash, 701n, 801n, ZERO_ADDRESS];
        throw new Error(`Result registration index out of range: ${index}`);
      }
      if (request.functionName === 'resultHashes') {
        return [prevLatestHash, 701n, ZERO_ADDRESS];
      }
    }
    return collectorClient.readContract(request);
  },
};

const defaultLatestCollected = await collectWith(fiveArtifacts, historyCollectorClient);
const explicitOldCollected = await collectWith(fiveArtifacts, historyCollectorClient, {
  namedPrevRegistrationIndex: 0n,
});
const explicitLatestCollected = await collectWith(fiveArtifacts, historyCollectorClient, {
  namedPrevRegistrationIndex: 1n,
});
ok('P4 U-2b collector: 名乗った古い行0から word7 を作る',
  explicitOldCollected.input.prevResultManifestHash === prevOldHash
    && explicitOldCollected.prevRegistrationIndex === '0');
ok('P4 U-2b collector: 任意引数省略時は従来の最終行と完全同一',
  defaultLatestCollected.inputHash === explicitLatestCollected.inputHash
    && defaultLatestCollected.input.prevResultManifestHash === prevLatestHash
    && defaultLatestCollected.prevRegistrationIndex === '1');

let outOfRangeCollectorError = null;
try {
  await collectWith(fiveArtifacts, historyCollectorClient, { namedPrevRegistrationIndex: 2n });
} catch (error) { outOfRangeCollectorError = error; }
ok('P4 U-2b collector: 名乗った添字が履歴範囲外なら停止する',
  /範囲外|out of range/i.test(String(outOfRangeCollectorError?.message)),
  outOfRangeCollectorError?.message || 'did not throw');

const emptyPrevCollectorClient = {
  ...collectorClient,
  readContract: async (request) => {
    const normalized = String(request.address).toLowerCase();
    const requestedBlock = BigInt(request.args?.[0] ?? -1);
    if (normalized === hashStorage.toLowerCase() && requestedBlock === prevBlock) {
      if (request.functionName === 'resultRegistrationCount') return 0n;
      if (request.functionName === 'resultHashes') return [ZERO_HASH, 0n, ZERO_ADDRESS];
      if (request.functionName === 'resultRegistrationAt') throw new Error('sentinel must not read a row');
    }
    return collectorClient.readContract(request);
  },
};
const sentinelCollected = await collectWith(fiveArtifacts, emptyPrevCollectorClient, {
  namedPrevRegistrationIndex: PREV_REGISTRATION_SENTINEL,
});
let nonSentinelOnEmptyError = null;
try {
  await collectWith(fiveArtifacts, emptyPrevCollectorClient, { namedPrevRegistrationIndex: 0n });
} catch (error) { nonSentinelOnEmptyError = error; }
ok('P4 U-2b collector: 番兵は履歴0件だけを word7=0 として通す',
  sentinelCollected.input.prevResultManifestHash === ZERO_HASH
    && sentinelCollected.prevRegistrationIndex === PREV_REGISTRATION_SENTINEL.toString()
    && /範囲外|out of range/i.test(String(nonSentinelOnEmptyError?.message)));

let sentinelWithHistoryError = null;
try {
  await collectWith(fiveArtifacts, historyCollectorClient, {
    namedPrevRegistrationIndex: PREV_REGISTRATION_SENTINEL,
  });
} catch (error) { sentinelWithHistoryError = error; }
ok('P8a MJ collector: 履歴が1件以上あるとき番兵を名乗れば拒否する',
  sentinelWithHistoryError?.zkpInvalidPrevRegistration === true
    && /番兵を名乗れません/.test(String(sentinelWithHistoryError?.message)),
  sentinelWithHistoryError?.message || 'did not throw');

const inconsistentLatestClient = {
  ...historyCollectorClient,
  readContract: async (request) => {
    const normalized = String(request.address).toLowerCase();
    const requestedBlock = BigInt(request.args?.[0] ?? -1);
    if (normalized === hashStorage.toLowerCase() && requestedBlock === prevBlock
        && request.functionName === 'resultHashes') {
      return [prevOldHash, 701n, ZERO_ADDRESS];
    }
    return historyCollectorClient.readContract(request);
  },
};
let inconsistentLatestError = null;
try { await collectWith(fiveArtifacts, inconsistentLatestClient); }
catch (error) { inconsistentLatestError = error; }
ok('P8a collector: 履歴最終行と最新viewが違えば既定の最新行経路も拒否する',
  /最終行が最新ビューと一致しません/.test(String(inconsistentLatestError?.message)),
  inconsistentLatestError?.message || 'did not throw');

let malformedClaimError = null;
try { requireProofPrevRegistrationIndex('0x1234'); }
catch (error) { malformedClaimError = error; }
ok('P8a MP: 名乗り添字を復号できないcalldataは拒否する',
  /^calldata_without_prev_registration_index\b/.test(String(malformedClaimError?.message)),
  malformedClaimError?.message || 'did not throw');

let nonUintClaimError = null;
try {
  requireProofPrevRegistrationIndex('0x', {
    decoder: () => ({ ok: true, functionName: 'submitMerkleRootWithProof', prevRegistrationIndex: 0 }),
  });
} catch (error) { nonUintClaimError = error; }
ok('P8a MQ: 復号結果がuint256 bigintでなければ拒否する',
  /not uint256 bigint/.test(String(nonUintClaimError?.message)),
  nonUintClaimError?.message || 'did not throw');

const oldPublicValues = encodePublicValues({
  ...buildExpectedPublicValues(defaultLatestCollected),
  prevResultManifestHash: prevOldHash,
});
const latestPublicValues = encodePublicValues(buildExpectedPublicValues(defaultLatestCollected));
const proofCalldata = (publicValues, prevRegistrationIndex) => encodeFunctionData({
  abi: TOKEN_MINING_ABI,
  functionName: 'submitMerkleRootWithProof',
  args: [
    BigInt(zkpN), merkleRoot, proofVerifier, proofVkey,
    publicValues, proofBytes, prevRegistrationIndex,
  ],
});
const oldCalldata = proofCalldata(oldPublicValues, 0n);
const latestCalldata = proofCalldata(latestPublicValues, 1n);
const mismatchCalldata = proofCalldata(latestPublicValues, 0n);
const outOfRangeCalldata = proofCalldata(latestPublicValues, 2n);
const proofEvent = { txHash: `0x${'91'.repeat(32)}`, evtBlock: 999 };
const proofEpoch = { verifier: proofVerifier, vkey: proofVkey };

function makeProofChain({
  txTo = tokenMining,
  txInput = latestCalldata,
  trace = null,
  traceError = null,
} = {}) {
  let traceRequests = 0;
  return {
    chain: {
      rpcUrl: 'http://collector.invalid',
      contracts: { tokenMining },
      client: {
        getTransaction: async () => ({ to: txTo, input: txInput }),
        getBlock: historyCollectorClient.getBlock,
        readContract: historyCollectorClient.readContract,
        request: async ({ method }) => {
          traceRequests++;
          assert.equal(method, 'debug_traceTransaction');
          if (traceError) throw traceError;
          return trace;
        },
      },
      getLogsChunked: async (request) => historyCollectorClient.getContractEvents(request),
    },
    traceRequests: () => traceRequests,
  };
}

const inspectWith = async (proofChain) => inspectProofSubmission({
  chain: proofChain.chain,
  blockNum: zkpN,
  root: merkleRoot,
  event: proofEvent,
  epoch: proofEpoch,
  artifacts: fiveArtifacts,
  r2Base: 'https://r2.invalid',
  confirmationBlocks: 64,
});

const directOld = makeProofChain({ txInput: oldCalldata });
const directOldInspected = await inspectWith(directOld);
const oldWitnessVerdict = judgePrevRegistrationWitness({
  claimedIndex: 0n,
  history: {
    count: 2,
    rows: [
      { index: 0, hash: prevOldHash, registeredBlock: 700, registeredAt: 800 },
      { index: 1, hash: prevLatestHash, registeredBlock: 701, registeredAt: 801 },
    ],
  },
  witness: {
    resultRegistrationCount: 2,
    resultHash: { hash: prevLatestHash, updated: 701 },
  },
});
ok('P4 U-2b inspect: 古い行を正しく名乗った証明はPV pass、正典行の判断は証人warnに残す',
  directOldInspected.format.status === 'pass'
    && directOldInspected.publicValues.status === 'pass'
    && oldWitnessVerdict.status === 'warn'
    && directOld.traceRequests() === 0,
  detailJson({ inspected: directOldInspected, witness: oldWitnessVerdict }));

const directMismatchInspected = await inspectWith(makeProofChain({ txInput: mismatchCalldata }));
ok('P4 U-2b inspect: 名乗った行のhashとword7が違えばPV fail',
  directMismatchInspected.format.status === 'pass'
    && directMismatchInspected.publicValues.status === 'fail'
    && directMismatchInspected.publicValues.mismatches?.some((row) => row.name === 'prevResultManifestHash'),
  detailJson(directMismatchInspected));

const directOutOfRangeInspected = await inspectWith(makeProofChain({ txInput: outOfRangeCalldata }));
ok('P4 U-2b inspect: 名乗った添字が履歴範囲外なら検査結果はfail側に残る',
  directOutOfRangeInspected.format.status === 'pass'
    && directOutOfRangeInspected.publicValues.status === 'fail'
    && /範囲外|out of range/i.test(String(directOutOfRangeInspected.publicValues.error)),
  detailJson(directOutOfRangeInspected));

const directLatest = makeProofChain({ txInput: latestCalldata });
const directLatestInspected = await inspectWith(directLatest);
ok('P4 U-2b/U-6 inspect: 最新行を名乗る従来の直送は結果不変でtraceを呼ばない',
  directLatestInspected.format.status === 'pass'
    && directLatestInspected.publicValues.status === 'pass'
    && directLatest.traceRequests() === 0,
  detailJson(directLatestInspected));

// M7: ブロック末ではなく証明ログ位置の word7 番兵と、PV word6 の履歴を検査する。
const m7ProofHash = `0x${'c7'.repeat(32)}`;
const m7PublicValues = encodePublicValues({
  ...buildExpectedPublicValues(defaultLatestCollected), resultManifestHash: m7ProofHash,
});
const m7Inspect = async ({ proofHash = m7ProofHash, chainHash = resultManifestHash,
  registered = true, emergencyMode = true, fixedRegisteredBlock = 999,
  fixedLogIndex = 10, proofHashRegisteredBlock = 998,
  proofHashLogIndex = 1, otherWordMismatch = false, fixedRegistered = true,
  fakeProofLog = false } = {}) => {
  const rows = registered ? [
    { hash: m7ProofHash, registeredBlock: proofHashRegisteredBlock,
      registeredAt: proofHashRegisteredBlock, signer: ZERO_ADDRESS },
    ...(chainHash !== m7ProofHash && chainHash !== resultManifestHash ? [{
      hash: chainHash, registeredBlock: 999, registeredAt: 999, signer: ZERO_ADDRESS,
    }] : []),
    ...(fixedRegistered ? [{ hash: resultManifestHash, registeredBlock: fixedRegisteredBlock,
      registeredAt: fixedRegisteredBlock, signer: ZERO_ADDRESS,
    }] : []),
  ] : [{ hash: fixedRegistered ? resultManifestHash : wrongChainHash,
    registeredBlock: fixedRegisteredBlock,
    registeredAt: fixedRegisteredBlock, signer: ZERO_ADDRESS }];
  const pv = proofHash === m7ProofHash && !otherWordMismatch ? m7PublicValues : encodePublicValues({
    ...buildExpectedPublicValues(defaultLatestCollected), resultManifestHash: proofHash,
    ...(otherWordMismatch ? { entryAcc: wrongChainHash } : {}),
  });
  const proofChain = makeProofChain({ txInput: proofCalldata(pv, 1n) }).chain;
  proofChain.client.readContract = async (request) => {
    if (String(request.address).toLowerCase() === hashStorage.toLowerCase()
        && request.functionName === 'resultHashes'
        && BigInt(request.args?.[0] ?? -1) === BigInt(zkpN)) {
      return [chainHash, 999n, ZERO_ADDRESS];
    }
    return historyCollectorClient.readContract(request);
  };
  proofChain.resultRegistrationCount = async () => rows.length;
  proofChain.resultRegistrationAt = async (_block, index) => rows[index];
  proofChain.resultHashEvents = async () => rows.map((row, index) => ({
    hash: fakeProofLog && index === 0 ? m7ProofHash : row.hash,
    signer: row.signer, updatedAt: row.registeredBlock,
    evtBlock: row.registeredBlock, registrationCount: index + 1,
    logIndex: index === 0 ? proofHashLogIndex : fixedLogIndex,
  }));
  return inspectProofSubmission({
    chain: proofChain, blockNum: zkpN, root: merkleRoot,
    event: { ...proofEvent, logIndex: 5 },
    epoch: proofEpoch, artifacts: fiveArtifacts, r2Base: 'https://r2.invalid',
    confirmationBlocks: 64, emergencyMode,
  });
};
for (const [label, options] of [
  ['前ブロック添付', { chainHash: m7ProofHash, fixedRegisteredBlock: 1000 }],
  ['同一ブロック前置', { proofHashRegisteredBlock: 999, proofHashLogIndex: 4 }],
  ['同一ブロック後置', { fixedLogIndex: 10 }],
  ['末尾が第三の hash', { chainHash: wrongChainHash, fixedRegisteredBlock: 1000 }],
]) {
  const inspected = await m7Inspect(options);
  const evaluated = z14Evaluate(inspected.publicValues, true);
  ok(`M7 U-7 ${label}: PV word6 の履歴が在れば緊急は差分`,
    inspected.publicValues.cause === ZKP_COLLECTION_FAILURE_CAUSES.proofBoundToOtherManifest
      && inspected.publicValues.proofBoundResultHash === m7ProofHash
      && evaluated.report.get('check.stageC.zkPublicValues')?.status === 'warn',
    detailJson(inspected.publicValues));
}
const m7Missing = await m7Inspect({ registered: false });
ok('M7 U-7 負: PV word6 が N の履歴に無ければ zkPublicValues は fail',
  z14Evaluate(m7Missing.publicValues, true).report.get('check.stageC.zkPublicValues')?.status === 'fail'
    && m7Missing.publicValues.cause !== ZKP_COLLECTION_FAILURE_CAUSES.proofBoundToOtherManifest,
  detailJson(m7Missing.publicValues));
const m7TwoWords = await m7Inspect({ otherWordMismatch: true });
ok('M7 U-7 負: word6 以外にも PV が違えば履歴が在っても fail',
  z14Evaluate(m7TwoWords.publicValues, true).report.get('check.stageC.zkPublicValues')?.status === 'fail'
    && m7TwoWords.publicValues.cause !== ZKP_COLLECTION_FAILURE_CAUSES.proofBoundToOtherManifest,
  detailJson(m7TwoWords.publicValues));
const m7AnchorTwoWords = await m7Inspect({ chainHash: wrongChainHash,
  otherWordMismatch: true });
const m7AnchorTwoWordsDefault = z14Evaluate(m7AnchorTwoWords.publicValues, true);
const m7AnchorTwoWordsGcp = z14Evaluate(m7AnchorTwoWords.publicValues, true,
  { authority: 'gcp', gcpHistoricalProofHash: true,
    chainResultMarker: { hash: wrongChainHash } });
ok('N7 U-7 錨再照合: word6 と応募者語が違っても履歴の旧 hash は両入口で warn・書き出し可',
  m7AnchorTwoWords.publicValues.cause === ZKP_COLLECTION_FAILURE_CAUSES.proofBoundToOtherManifest
    && m7AnchorTwoWords.publicValues.otherMismatches?.includes('entryAcc')
    && m7AnchorTwoWords.publicValues.otherMismatches.every((name) => typeof name === 'string')
    && !Object.hasOwn(m7AnchorTwoWords.publicValues, 'mismatches')
    && m7AnchorTwoWordsDefault.report.get('check.stageC.zkPublicValues')?.status === 'warn'
    && m7AnchorTwoWordsDefault.gateError === null
    && m7AnchorTwoWordsGcp.report.get('check.stageC.zkPublicValues')?.status === 'warn'
    && m7AnchorTwoWordsGcp.gateError === null,
  detailJson(m7AnchorTwoWords.publicValues));
const m7AnchorMissing = await m7Inspect({ chainHash: wrongChainHash,
  otherWordMismatch: true, registered: false });
const m7AnchorNormal = await m7Inspect({ chainHash: wrongChainHash,
  otherWordMismatch: true, emergencyMode: false });
ok('N7 U-7 錨再照合: 履歴不在と通常モードは fail',
  m7AnchorMissing.publicValues.status === 'fail'
    && z14Evaluate(m7AnchorNormal.publicValues, false).report
      .get('check.stageC.zkPublicValues')?.status === 'fail',
  detailJson({ missing: m7AnchorMissing.publicValues, normal: m7AnchorNormal.publicValues }));
const m7AnchorExact = await m7Inspect({ proofHash: resultManifestHash,
  chainHash: wrongChainHash });
const m7AnchorExactDefault = z14Evaluate(m7AnchorExact.publicValues, true);
const m7AnchorExactGcp = z14Evaluate(m7AnchorExact.publicValues, true,
  { authority: 'gcp', chainResultMarker: { hash: wrongChainHash } });
ok('N7 U-7 錨再照合: 15語一致かつ固定 core が履歴にあれば両入口で pass・差分0',
  m7AnchorExact.publicValues.status === 'pass'
    && m7AnchorExactDefault.report.get('check.stageC.zkPublicValues')?.status === 'pass'
    && m7AnchorExactDefault.gateError === null
    && m7AnchorExactDefault.data.emergencyDifferences.length === 0
    && m7AnchorExactGcp.report.get('check.stageC.zkPublicValues')?.status === 'pass'
    && m7AnchorExactGcp.gateError === null,
  detailJson(m7AnchorExact.publicValues));
const m7AnchorExactNormal = await m7Inspect({ proofHash: resultManifestHash,
  chainHash: wrongChainHash, emergencyMode: false });
ok('N7 U-7 錨再照合: 同じ15語一致の盤面でも通常モードは fail',
  z14Evaluate(m7AnchorExactNormal.publicValues, false).report
    .get('check.stageC.zkPublicValues')?.status === 'fail',
  detailJson(m7AnchorExactNormal.publicValues));
const m7AnchorExactAbsent = await m7Inspect({ proofHash: resultManifestHash,
  chainHash: wrongChainHash, registered: false, fixedRegistered: false });
ok('N7 U-7 錨再照合: 15語一致でも固定 core の履歴が無ければ fail',
  m7AnchorExactAbsent.publicValues.status === 'fail',
  detailJson(m7AnchorExactAbsent.publicValues));
for (const [label, otherWordMismatch] of [['word6 だけ', false], ['word6 と応募者語', true]]) {
  const inspected = await m7Inspect({ chainHash: wrongChainHash, registered: false,
    fakeProofLog: true, otherWordMismatch });
  const evaluated = z14Evaluate(inspected.publicValues, true);
  ok(`N7 U-7 偽ログ ${label}: 状態行との差を fail に残し書き出しを拒否`,
    inspected.publicValues.status === 'fail'
      && /ResultHashRegistered log differs from state row/.test(inspected.publicValues.error)
      && evaluated.report.get('check.stageC.zkPublicValues')?.status === 'fail'
      && /verification failed/.test(String(evaluated.gateError?.message)),
    detailJson(inspected.publicValues));
}
const m7Normal = await m7Inspect({ emergencyMode: false, chainHash: m7ProofHash });
const m7NormalAfter = await m7Inspect({ emergencyMode: false });
const m7NormalMissing = await m7Inspect({ emergencyMode: false, registered: false });
ok('M7 U-7 通常: word6 の判定・params はブロック末起点のまま',
  m7Normal.publicValues.cause === ZKP_COLLECTION_FAILURE_CAUSES.proofBoundToOtherManifest
    && m7Normal.publicValues.proofBoundResultHash === m7ProofHash
    && z14Evaluate(m7Normal.publicValues, false).report.get('check.stageC.zkPublicValues')?.status === 'fail',
  detailJson(m7Normal.publicValues));

const m7SentinelPublicValues = encodePublicValues({
  ...buildExpectedPublicValues(defaultLatestCollected), prevResultManifestHash: ZERO_HASH,
});
const m7SentinelEvent = { ...proofEvent, logIndex: 5 };
const m7SentinelInspect = async ({ priorCount = 0n, registrationLogIndex = 10,
  proofWord6 = resultManifestHash, chainHash = resultManifestHash,
  emergencyMode = false } = {}) => {
  const publicValues = proofWord6 === resultManifestHash ? m7SentinelPublicValues
    : encodePublicValues({ ...buildExpectedPublicValues(defaultLatestCollected),
      resultManifestHash: proofWord6, prevResultManifestHash: ZERO_HASH });
  const proofChain = makeProofChain({
    txInput: proofCalldata(publicValues, PREV_REGISTRATION_SENTINEL),
  }).chain;
  proofChain.client.readContract = async (request) => {
    if (String(request.address).toLowerCase() === hashStorage.toLowerCase()
        && BigInt(request.args?.[0] ?? -1) === BigInt(zkpN)
        && request.functionName === 'resultHashes') {
      return [chainHash, 999n, ZERO_ADDRESS];
    }
    if (String(request.address).toLowerCase() === hashStorage.toLowerCase()
        && BigInt(request.args?.[0] ?? -1) === prevBlock) {
      if (request.functionName === 'resultRegistrationCount') {
        return BigInt(request.blockNumber) === 998n ? priorCount : 1n;
      }
      if (request.functionName === 'resultHashes') return [prevOldHash, 999n, ZERO_ADDRESS];
    }
    return historyCollectorClient.readContract(request);
  };
  proofChain.getLogsChunked = async (request) => request.event.name === 'ResultHashRegistered'
    ? [{ args: { registrationCount: 1n }, logIndex: registrationLogIndex }]
    : historyCollectorClient.getContractEvents(request);
  proofChain.resultRegistrationCount = async () => 2;
  proofChain.resultRegistrationAt = async (_block, index) => ({
    hash: index === 0 ? m7ProofHash : resultManifestHash,
    registeredBlock: index === 0 ? 998 : 1000,
    signer: ZERO_ADDRESS,
  });
  return inspectProofSubmission({
    chain: proofChain, blockNum: zkpN, root: merkleRoot, event: m7SentinelEvent,
    epoch: proofEpoch, artifacts: fiveArtifacts, r2Base: 'https://r2.invalid',
    confirmationBlocks: 64, emergencyMode,
  });
};
const m7SentinelAfter = await m7SentinelInspect();
const m7Combined = await m7SentinelInspect({
  proofWord6: m7ProofHash, chainHash: m7ProofHash, emergencyMode: true,
});
ok('M7 結合: word7 番兵後置と word6 旧 hash の両方を緊急で再現する',
  m7Combined.publicValues.cause === ZKP_COLLECTION_FAILURE_CAUSES.proofBoundToOtherManifest
    && m7Combined.publicValues.proofBoundResultHash === m7ProofHash
    && z14Evaluate(m7Combined.publicValues, true).report.get('check.stageC.zkPublicValues')?.status === 'warn',
  detailJson(m7Combined.publicValues));
const m7SentinelWitness = judgePrevRegistrationWitness({
  claimedIndex: PREV_REGISTRATION_SENTINEL,
  history: { count: 1, rows: [{ index: 0, hash: prevOldHash, registeredBlock: 999 }] },
  witness: { resultRegistrationCount: 0, resultHash: null },
});
ok('M7 U-2b 正: 番兵の後の同一ブロック登録は PV pass',
  m7SentinelAfter.publicValues.status === 'pass'
    && m7SentinelWitness.status === 'warn',
  detailJson({ publicValues: m7SentinelAfter.publicValues, witness: m7SentinelWitness }));
for (const [label, options] of [
  ['前置の登録', { registrationLogIndex: 4 }],
  ['前ブロック末で件数1', { priorCount: 1n }],
]) {
  const inspected = await m7SentinelInspect(options);
  ok(`M7 U-2b 負: ${label}なら番兵は fail`,
    inspected.publicValues.status === 'fail', detailJson(inspected.publicValues));
}
if (process.env.M7_PROBE === '1') {
  for (const [name, publicValues] of [
    ['sentinel_after', m7SentinelAfter.publicValues],
    ['word6_same_block_after', m7NormalAfter.publicValues],
    ['word6_not_in_history', m7NormalMissing.publicValues],
    ['ordinary_index', directLatestInspected.publicValues],
  ]) {
    const check = z14Evaluate(publicValues, false).report.get('check.stageC.zkPublicValues');
    // index.js の emitNonInteractiveOutcome() と同じ逐語の ##CHECK 行。
    const line = `##CHECK check.stageC.zkPublicValues ${check.status}`;
    console.log(`M7_PROBE ${name} ${JSON.stringify({
      status: check.status, lineSha256: sha256Hex(Buffer.from(line)),
      paramsSha256: sha256Hex(Buffer.from(detailJson(check.params))),
      ...(name === 'sentinel_after' ? { witness: m7SentinelWitness.status } : {}),
    })}`);
  }
}

const m3AutoSummary = { blockNum: zkpN, groups: [], autoDistributed: true };
const m3AutoSummaryRaw = JSON.stringify(m3AutoSummary);
const m3AutoManifest = JSON.parse(p13SyntheticRaw);
m3AutoManifest.files[summaryZkpKey] = sha256Hex(Buffer.from(m3AutoSummaryRaw)).slice(2);
m3AutoManifest.manifestHash = sha256Hex(Buffer.from(JSON.stringify({
  blockNum: m3AutoManifest.blockNum, algorithm: m3AutoManifest.algorithm,
  rules: m3AutoManifest.rules, files: m3AutoManifest.files,
})));
const m3AutoS = { ...zkpS, auto: true, anomalies: [], zkInfo: { kind: 'proof', epoch: {
  ...proofEpoch, index: 0, guestSourceHash: ZERO_HASH,
} }, files: { ...zkpS.files, manifest: {
  data: m3AutoManifest, raw: JSON.stringify(m3AutoManifest),
} } };
const m3ProofRun = async (registered) => {
  const proofChain = makeProofChain({ txInput: latestCalldata }).chain;
  const chain = { ...proofChain,
    resultRegistrationCount: p12bHistoryChain.resultRegistrationCount,
    resultRegistrationAt: p12bHistoryChain.resultRegistrationAt,
    resultHashEvents: p12bHistoryChain.resultHashEvents,
    resultRegistrationHistory: async () => { throw new Error('test witness unavailable'); },
  };
  if (!registered) {
    chain.resultRegistrationCount = async () => 1;
    chain.resultRegistrationAt = async () => p13StateRow(0, wrongChainHash);
    chain.resultHashEvents = async () => [p13LogRow(0, p13StateRow(0, wrongChainHash))];
  }
  const ctx = { blockNum: zkpN, report: createReport(), chain,
    cfg: { r2Base: 'https://r2.invalid', pins: { confirmationBlocks: 64 } },
    data: { emergencySource: {
      authority: 'gcp', syntheticSummary: m3AutoSummary,
      selectedManifest: m3AutoManifest, chainResultMarker: { hash: m3AutoManifest.manifestHash },
      stage3ManifestUsableForZkp: true,
    }, emergencyDifferences: [] },
  };
  const S = { ...m3AutoS, anomalies: [] };
  await verifyZkpSubmission(ctx, S, proofEvent);
  return ctx;
};
const m3RegisteredProof = await m3ProofRun(true);
const m3UnregisteredProof = await m3ProofRun(false);
ok('M3: GCP 自動配布は合成 summary 宣言で collector に届き、履歴付き旧証明を差分化する',
  m3RegisteredProof.data.emergencySource.gcpHistoricalProofHash === true
    && m3RegisteredProof.report.get('check.stageC.zkPublicValues')?.status === 'warn'
    && m3RegisteredProof.data.emergencyDifferences.some((d) => d.checkId === 'emergency.gcpPriorRootProof'),
  detailJson(m3RegisteredProof.report.get('check.stageC.zkPublicValues')));
ok('M3: 履歴に無い証明 hash は GCP 旧証明の旗と差分を立てない',
  m3UnregisteredProof.data.emergencySource.gcpHistoricalProofHash !== true
    && !m3UnregisteredProof.data.emergencyDifferences.some((d) =>
      d.checkId === 'emergency.gcpPriorRootProof'),
  detailJson({ source: m3UnregisteredProof.data.emergencySource,
    publicValues: m3UnregisteredProof.report.get('check.stageC.zkPublicValues') }));

let m7NormalHistoryCalls = 0;
const m7NormalChain = makeProofChain({ txInput: proofCalldata(m7PublicValues, 1n) }).chain;
const m7NormalRead = m7NormalChain.client.readContract;
m7NormalChain.client.readContract = (request) =>
  String(request.address).toLowerCase() === hashStorage.toLowerCase()
    && request.functionName === 'resultHashes'
    && BigInt(request.args?.[0] ?? -1) === BigInt(zkpN)
    ? [m7ProofHash, 999n, ZERO_ADDRESS] : m7NormalRead(request);
m7NormalChain.resultRegistrationCount = async () => { m7NormalHistoryCalls++; return 1; };
m7NormalChain.resultRegistrationAt = async () => ({ hash: m7ProofHash });
m7NormalChain.resultRegistrationHistory = async () => { throw new Error('witness unavailable'); };
const m7NormalCtx = {
  blockNum: zkpN, report: createReport(), chain: m7NormalChain,
  cfg: { r2Base: 'https://r2.invalid', pins: { confirmationBlocks: 64 } },
  data: {},
};
let m7NormalThrown = null;
try {
  await verifyZkpSubmission(m7NormalCtx, {
    ...zkpS, anomalies: [], zkInfo: { kind: 'proof', epoch: {
      ...proofEpoch, index: 0, guestSourceHash: ZERO_HASH,
    } },
  }, proofEvent);
} catch (error) { m7NormalThrown = error; }
ok('M7 D-4c-03: 通常の proof_bound_to_other_manifest は fail で GCP 履歴探索を呼ばない',
  m7NormalThrown === null && m7NormalHistoryCalls === 0
    && m7NormalCtx.report.get('check.stageC.zkPublicValues')?.status === 'fail'
    && m7NormalCtx.report.get('check.stageC.zkPublicValues')?.params?.cause
      === ZKP_COLLECTION_FAILURE_CAUSES.proofBoundToOtherManifest,
  detailJson({ error: m7NormalThrown?.message, calls: m7NormalHistoryCalls,
    check: m7NormalCtx.report.get('check.stageC.zkPublicValues') }));

const oneInternal = makeProofChain({
  txTo: relayAddress,
  txInput: '0x1234',
  trace: {
    type: 'CALL', to: relayAddress, input: '0x1234',
    calls: [{ type: 'CALL', to: tokenMining, input: latestCalldata, calls: [] }],
  },
});
const oneInternalInspected = await inspectWith(oneInternal);
ok('P4 U-6 inspect: 中継内のTokenMining証明呼び出しが1件なら直送と同じ検査でpass',
  oneInternalInspected.format.status === directLatestInspected.format.status
    && oneInternalInspected.publicValues.status === directLatestInspected.publicValues.status
    && oneInternal.traceRequests() === 1,
  detailJson(oneInternalInspected));

const oneInternalResolved = await resolveProofSubmissionCalldata({
  chain: oneInternal.chain,
  event: proofEvent,
});
ok('P8a witness handoff: 中継時は外側tx.inputでなく採用した内側calldataと名乗り添字を返す',
  oneInternalResolved.route === 'internal'
    && oneInternalResolved.calldata === latestCalldata
    && oneInternalResolved.prevRegistrationIndex === 1n,
  detailJson(oneInternalResolved));

const directResolved = await resolveProofSubmissionCalldata({
  chain: directLatest.chain,
  event: proofEvent,
});
ok('P8a witness handoff: 直送時は従来どおりtx.inputと名乗り添字を返す',
  directResolved.route === 'direct'
    && directResolved.calldata === latestCalldata
    && directResolved.prevRegistrationIndex === 1n,
  detailJson(directResolved));

const revertedDecoyInspected = await inspectWith(makeProofChain({
  txTo: relayAddress,
  txInput: '0x1234',
  trace: {
    type: 'CALL', to: relayAddress, input: '0x1234',
    calls: [
      { type: 'CALL', to: tokenMining, input: oldCalldata, error: 'execution reverted', calls: [] },
      { type: 'CALL', to: tokenMining, input: latestCalldata, calls: [] },
    ],
  },
}));
ok('P8a U-6: revertした囮と成功した証明呼び出しが各1件なら成功した1件だけでpass',
  revertedDecoyInspected.format.status === 'pass'
    && revertedDecoyInspected.publicValues.status === 'pass',
  detailJson(revertedDecoyInspected));

const revertedParentInspected = await inspectWith(makeProofChain({
  txTo: relayAddress,
  txInput: '0x1234',
  trace: {
    type: 'CALL', to: relayAddress, input: '0x1234',
    calls: [{
      type: 'CALL', to: otherAddress, input: '0xabcd', error: 'execution reverted',
      calls: [{ type: 'CALL', to: tokenMining, input: latestCalldata, calls: [] }],
    }],
  },
}));
ok('P8a U-6: revertした親frameの内側にある証明呼び出しは成功扱いしない',
  revertedParentInspected.format.status === 'fail'
    && /^internal_call_not_found\b/.test(String(revertedParentInspected.format.error)),
  detailJson(revertedParentInspected));

const viewCalldata = encodeFunctionData({
  abi: TOKEN_MINING_ABI,
  functionName: 'proofRequired',
});
const nonProofCallsInspected = await inspectWith(makeProofChain({
  txTo: relayAddress,
  txInput: '0x1234',
  trace: {
    type: 'CALL', to: relayAddress, input: '0x1234',
    calls: [
      { type: 'STATICCALL', to: tokenMining, input: viewCalldata, calls: [] },
      { type: 'CALL', to: tokenMining, input: viewCalldata, calls: [] },
      { type: 'CALL', to: tokenMining, input: latestCalldata, calls: [] },
    ],
  },
}));
ok('P8a MG: TokenMining宛てでもSTATICCALLと非証明CALLは数えず成功した証明CALLだけを採る',
  nonProofCallsInspected.format.status === 'pass'
    && nonProofCallsInspected.publicValues.status === 'pass',
  detailJson(nonProofCallsInspected));

const delegateDecoy = await inspectWith(makeProofChain({
  txTo: relayAddress, txInput: '0x1234',
  trace: { type: 'CALL', to: relayAddress, calls: [
    { type: 'DELEGATECALL', to: tokenMining, input: latestCalldata, calls: [] },
    { type: 'CALLCODE', to: tokenMining, input: latestCalldata, calls: [] },
    { type: 'CALL', to: tokenMining, input: latestCalldata, calls: [] },
  ] },
}));
ok('P10b Z5/Z6: 成功したDELEGATECALL/CALLCODE囮は証明CALLに数えない',
  delegateDecoy.format.status === 'pass' && delegateDecoy.publicValues.status === 'pass',
  detailJson(delegateDecoy));

for (const [field, value] of [['revertReason', 'reverted'], ['status', '0x0']]) {
  const failedCallDecoy = await inspectWith(makeProofChain({
    txTo: relayAddress, txInput: '0x1234',
    trace: { type: 'CALL', to: relayAddress, calls: [
      { type: 'CALL', to: tokenMining, input: latestCalldata, [field]: value, calls: [] },
      { type: 'CALL', to: tokenMining, input: latestCalldata, calls: [] },
    ] },
  }));
  ok(`P10b Z3/Z4: ${field} が失敗を示す囮は数えない`,
    failedCallDecoy.format.status === 'pass' && failedCallDecoy.publicValues.status === 'pass',
    detailJson(failedCallDecoy));
}

const outerSameSignature = makeProofChain({
  txTo: relayAddress, txInput: oldCalldata,
  trace: { type: 'CALL', to: relayAddress, input: oldCalldata, calls: [
    { type: 'CALL', to: tokenMining, input: latestCalldata, calls: [] },
  ] },
});
const outerSameSignatureResolved = await resolveProofSubmissionCalldata({
  chain: outerSameSignature.chain, event: proofEvent, targetBlockNum: zkpN,
});
ok('P10b Z7: 中継の外側も同じ署名なら内側のcalldataと添字を採る',
  outerSameSignatureResolved.calldata === latestCalldata
    && outerSameSignatureResolved.prevRegistrationIndex === 1n
    && (await inspectWith(outerSameSignature)).format.status === 'pass',
  detailJson(outerSameSignatureResolved));

const otherBlockCalldata = encodeFunctionData({
  abi: TOKEN_MINING_ABI, functionName: 'submitMerkleRootWithProof',
  args: [BigInt(zkpN + 1), merkleRoot, proofVerifier, proofVkey,
    latestPublicValues, proofBytes, 1n],
});
const twoBlocksInOneTx = makeProofChain({
  txTo: relayAddress, txInput: '0x1234',
  trace: { type: 'CALL', to: relayAddress, calls: [
    { type: 'CALL', to: tokenMining, input: otherBlockCalldata, calls: [] },
    { type: 'CALL', to: tokenMining, input: latestCalldata, calls: [] },
  ] },
});
const twoBlocksInspected = await inspectWith(twoBlocksInOneTx);
ok('P10b 中継: 別ブロックの成功attachは対象ブロックの1件を曖昧にしない',
  twoBlocksInspected.format.status === 'pass'
    && twoBlocksInspected.publicValues.status === 'pass',
  detailJson(twoBlocksInspected));

const noInternalInspected = await inspectWith(makeProofChain({
  txTo: relayAddress,
  txInput: '0x1234',
  trace: {
    type: 'CALL', to: relayAddress, input: '0x1234',
    calls: [{ type: 'CALL', to: otherAddress, input: latestCalldata, calls: [] }],
  },
}));
ok('P4 U-6 inspect: 内側証明呼び出し0件はinternal_call_not_foundでfail',
  noInternalInspected.format.status === 'fail'
    && /^internal_call_not_found\b/.test(String(noInternalInspected.format.error)),
  detailJson(noInternalInspected));

const twoInternalInspected = await inspectWith(makeProofChain({
  txTo: relayAddress,
  txInput: '0x1234',
  trace: {
    type: 'CALL', to: relayAddress, input: '0x1234',
    calls: [
      { type: 'CALL', to: tokenMining, input: latestCalldata, calls: [] },
      { type: 'CALL', to: tokenMining, input: latestCalldata, calls: [] },
    ],
  },
}));
ok('P4 U-6 inspect: 内側証明呼び出し2件はinternal_call_ambiguousでfail',
  twoInternalInspected.format.status === 'fail'
    && /^internal_call_ambiguous\b/.test(String(twoInternalInspected.format.error)),
  detailJson(twoInternalInspected));

const traceUnavailableInspected = await inspectWith(makeProofChain({
  txTo: relayAddress,
  txInput: '0x1234',
  traceError: new Error('method disabled'),
}));
ok('P4 U-6 inspect: trace不能はinternal_call_trace_unavailableでfail',
  traceUnavailableInspected.format.status === 'fail'
    && /^internal_call_trace_unavailable\b/.test(String(traceUnavailableInspected.format.error)),
  detailJson(traceUnavailableInspected));
const m11bFixedManifest = JSON.parse(manifestRaw);
for (const [label, format] of [
  ['trace unavailable', traceUnavailableInspected.format],
  ['ambiguous internal calls', twoInternalInspected.format],
]) {
  const emergencySource = { selectedManifest: m11bFixedManifest,
    chainResultMarker: { hash: resultManifestHash, updated: 123 } };
  const context = { report: createReport(), data: { emergencySource }, blockNum: zkpN };
  recordZkpProofFormatForMode(context, format, proofEvent);
  ok(`M11b J2: ${label} は固定 core 登録後だけ差分として進む`,
    context.report.get('check.stageC.zkProofFormat')?.status === 'warn'
      && context.data.emergencyDifferences?.some((difference) =>
        difference.checkId === 'emergency.hijackPeriodProof'
        && difference.params.cause.startsWith('internal_call_')));
  const wrong = { report: createReport(), data: { emergencySource: {
    ...emergencySource, chainResultMarker: { hash: ZERO_HASH, updated: 123 },
  } }, blockNum: zkpN };
  recordZkpProofFormatForMode(wrong, format, proofEvent);
  ok(`M11b J2: ${label} でも目印が固定 core と違えば止まる`,
    wrong.report.get('check.stageC.zkProofFormat')?.status === 'fail'
      && !wrong.data.emergencyDifferences?.length);
}
const n7RunJ2 = async (proofChain, authority, markerHash) => {
  const emergencySource = { authority, selectedManifest: JSON.parse(manifestRaw),
    chainResultMarker: { hash: markerHash, updated: 123 } };
  const context = { blockNum: zkpN, report: createReport(), chain: proofChain.chain,
    cfg: { r2Base: 'https://r2.invalid', pins: { confirmationBlocks: 64 } },
    data: { emergencySource, emergencyDifferences: [] } };
  for (const id of EMERGENCY_REQUIRED_CHECKS.groupGame) context.report.check(id, 'pass');
  const S = { ...zkpS, anomalies: [], zkInfo: { kind: 'proof', epoch: {
    ...proofEpoch, index: 0, guestSourceHash: ZERO_HASH,
  } } };
  await verifyZkpSubmission(context, S, proofEvent);
  let gateError = null;
  try { assertEmergencyVerificationGate(context.report,
    { kind: 'groupGame', rebuiltSummary: {}, allGroupResults: [] }); }
  catch (error) { gateError = error; }
  return { context, gateError };
};
for (const [label, proofChain] of [
  ['trace unavailable', makeProofChain({ txTo: relayAddress, txInput: '0x1234',
    traceError: new Error('method disabled') })],
  ['ambiguous', makeProofChain({ txTo: relayAddress, txInput: '0x1234',
    trace: { type: 'CALL', to: relayAddress, calls: [
      { type: 'CALL', to: tokenMining, input: latestCalldata, calls: [] },
      { type: 'CALL', to: tokenMining, input: latestCalldata, calls: [] },
    ] } })],
]) {
  const normal = await n7RunJ2(proofChain, undefined, resultManifestHash);
  const normalWrong = await n7RunJ2(proofChain, undefined, wrongChainHash);
  const gcp = await n7RunJ2(proofChain, 'gcp', wrongChainHash);
  ok(`N7 J2 配線 ${label}: 既定入口は両 warn で通り、別目印は拒否`,
    normal.context.report.get('check.stageC.zkProofFormat')?.status === 'warn'
      && normal.context.report.get('check.stageC.zkPublicValues')?.status === 'warn'
      && normal.context.report.get('check.stageC.zkPublicValues')?.params?.cause
        === 'old_root_internal_call_untraceable'
      && normal.gateError === null
      && normalWrong.context.report.get('check.stageC.zkProofFormat')?.status === 'fail'
      && normalWrong.context.report.get('check.stageC.zkPublicValues')?.status === 'fail'
      && /verification failed/.test(String(normalWrong.gateError?.message)),
    detailJson({ good: normal.context.report.get('check.stageC.zkPublicValues'),
      wrong: normalWrong.context.report.get('check.stageC.zkPublicValues') }));
  ok(`N7 J2 配線 ${label}: GCP は合成 core と目印が違っても両 warn と差分`,
    gcp.context.report.get('check.stageC.zkProofFormat')?.status === 'warn'
      && gcp.context.report.get('check.stageC.zkPublicValues')?.status === 'warn'
      && gcp.context.data.emergencySource.gcpUntraceableOldProof === true
      && gcp.context.data.emergencyDifferences.some((d) =>
        d.checkId === 'emergency.hijackPeriodProof')
      && gcp.gateError === null,
    detailJson({ format: gcp.context.report.get('check.stageC.zkProofFormat'),
      values: gcp.context.report.get('check.stageC.zkPublicValues') }));
}
for (const authority of [undefined, 'gcp']) {
  for (const error of ['internal_call_not_found: no TokenMining call',
    'calldata_without_prev_registration_index: missing index',
    'unexpected TokenMining call']) {
    const context = { blockNum: zkpN, report: createReport(), data: {
      emergencySource: { authority, selectedManifest: JSON.parse(manifestRaw),
        chainResultMarker: { hash: resultManifestHash } }, emergencyDifferences: [],
    } };
    recordZkpProofFormatForMode(context, { status: 'fail', error }, proofEvent);
    ok(`N7 J2 負 ${authority || 'default'} ${error.split(':')[0]}: fail のまま差分なし`,
      context.report.get('check.stageC.zkProofFormat')?.status === 'fail'
        && context.data.emergencyDifferences.length === 0,
      detailJson(context.report.get('check.stageC.zkProofFormat')));
  }
}
const n7ResultsText = await fs.readFile(
  process.env.N7_MUTATE_TARGET?.endsWith('/src/stages/results.js')
    ? process.env.N7_MUTATE_SOURCE : new URL('../src/stages/results.js', import.meta.url), 'utf8');
const n7FinalizeNode = parseJavaScript(n7ResultsText, { ecmaVersion: 'latest', sourceType: 'module' })
  .body.find((node) => node.type === 'FunctionDeclaration'
    && node.id?.name === 'finalizeEvidenceArchiveChecks');
assert.ok(n7FinalizeNode);
const n7Finalize = new Function('sha256HexOfString', 'gcpCandidates', 'canonicalEqual',
  'recordEmergencyDifference', 'gcpUnevaluated', 'declaredAdoptedCountForVerification', 'lower',
  `return (${n7ResultsText.slice(n7FinalizeNode.start, n7FinalizeNode.end)});`)(
  sha256HexOfString,
  async function* () {},
  (a, b) => JSON.stringify(a) === JSON.stringify(b),
  (ctx, difference) => { (ctx.data.emergencyDifferences ||= []).push(difference); },
  () => {},
  () => 0,
  (value) => String(value).toLowerCase(),
);
for (const markerHash of [resultManifestHash, wrongChainHash]) {
  const selectedManifest = JSON.parse(manifestRaw);
  const originalBytes = JSON.stringify(selectedManifest);
  const ctx = { blockNum: zkpN, report: createReport(), ui: { t: (key) => key },
    data: { emergencySource: { authority: 'gcp', selectedManifest,
      sourceDir: 'fixture', index: { objects: {} },
      chainResultMarker: { hash: markerHash } }, emergencyDifferences: [] } };
  const S = { files: {}, adoptedByUid: {}, anomalies: [], evidenceFinalize: {
    serverStates: {}, reportMeta: { resultCount: 0, safeBlock: 999 }, invalid: [],
    resultCount: 0, declaredDisabled: true, sources: {},
  } };
  await n7Finalize(ctx, S);
  ok(`N7 GCP groupGame finalize: 目印 ${markerHash === resultManifestHash ? '合成' : '別値'} でも collector core が不変`,
    n7ResultsText.match(/await finalizeEvidenceArchiveChecks\(ctx, S\);/g)?.length === 2
      && JSON.stringify(selectedManifest) === originalBytes
      && S.files.evidenceReport?.data?.resultCount === 0
      && ctx.data.emergencyEvidenceReport === S.files.evidenceReport.data,
    detailJson({ before: originalBytes, after: JSON.stringify(selectedManifest) }));
}
const m14dManyFrames = await inspectWith(makeProofChain({
  txTo: relayAddress, txInput: '0x1234',
  trace: { type: 'CALL', to: relayAddress, calls: [
    ...Array.from({ length: 65_537 }, () => ({ type: 'CALL', to: relayAddress, calls: [] })),
    { type: 'CALL', to: tokenMining, input: latestCalldata, calls: [] },
  ] },
}));
ok('M14d J2: 65,536 フレーム超でも一意な中継証明は通常モードで通る',
  m14dManyFrames.format.status === 'pass');
const m11bLargeTrace = await inspectWith(makeProofChain({
  txTo: relayAddress, txInput: '0x1234',
  traceError: new Error('trace response too large for RPC'),
}));
ok('M14d J2: RPC が応答過大で失敗させた trace は専用理由で通常 fail',
  m11bLargeTrace.format.status === 'fail'
    && /^trace_too_large\b/.test(String(m11bLargeTrace.format.error)));
const m11bLargeCtx = { report: createReport(), data: { emergencySource: {
  selectedManifest: m11bFixedManifest,
  chainResultMarker: { hash: resultManifestHash, updated: 123 },
} }, blockNum: zkpN };
recordZkpProofFormatForMode(m11bLargeCtx, m11bLargeTrace.format, proofEvent);
ok('M14d J2: 応答過大は固定 core の緊急だけ warn と cause 付き差分',
  m11bLargeCtx.report.get('check.stageC.zkProofFormat')?.status === 'warn'
    && m11bLargeCtx.data.emergencyDifferences?.some((difference) =>
      difference.checkId === 'emergency.hijackPeriodProof'
      && difference.params.cause === 'trace_too_large'));
const m14dNormalLargeCtx = { report: createReport(), data: {}, blockNum: zkpN };
recordZkpProofFormatForMode(m14dNormalLargeCtx, m11bLargeTrace.format, proofEvent);
ok('M14d J2: 同じ応答過大は通常モードで fail',
  m14dNormalLargeCtx.report.get('check.stageC.zkProofFormat')?.status === 'fail');
const m14dWrongLargeCtx = { report: createReport(), data: { emergencySource: {
  selectedManifest: m11bFixedManifest, chainResultMarker: { hash: ZERO_HASH },
} }, blockNum: zkpN };
recordZkpProofFormatForMode(m14dWrongLargeCtx, m11bLargeTrace.format, proofEvent);
ok('M14d J2: 現在目印が core と違えば応答過大でも止まる',
  m14dWrongLargeCtx.report.get('check.stageC.zkProofFormat')?.status === 'fail');
const m11bRealSetTimeout = globalThis.setTimeout;
let m11bTraceTimeoutMs = null;
let m11bTimedOut;
try {
  globalThis.setTimeout = (callback, ms, ...args) => {
    m11bTraceTimeoutMs = ms;
    queueMicrotask(() => callback(...args));
    return { unref() {} };
  };
  m11bTimedOut = await resolveProofSubmissionCalldata({
    chain: { contracts: { tokenMining }, client: { request: () => new Promise(() => {}) } },
    event: proofEvent,
    transaction: { to: relayAddress, input: '0x1234' },
    targetBlockNum: zkpN,
  }).catch((error) => error);
} finally {
  globalThis.setTimeout = m11bRealSetTimeout;
}
ok('M11b J2: callTracer だけに15秒の待機上限を掛け、時間切れを取得不能と示す',
  m11bTraceTimeoutMs === 15_000 && m11bTimedOut instanceof Error
    && /^internal_call_trace_unavailable: callTracer timed out$/.test(m11bTimedOut.message));

// Q24-C: 同じfixtureをBの固定一式形状へ置き、artifactDir指定時にHTTP fetchを0回にする。
const q24ArtifactDir = path.resolve(
  process.env.N7_TEST_TMP_ROOT || path.resolve(
    path.dirname(fileURLToPath(import.meta.url)), '../../tmp/round32/N4b'),
  `s5-q24-zkp-collector-fixture-${process.pid}`,
);
await fs.rm(q24ArtifactDir, { recursive: true, force: true });
const q24Files = new Map([
  [`verification/block${zkpN}/manifest.json`, manifestRaw],
  [selectionKey, selectionRaw],
  [stage3ManifestKey, stage3ManifestRaw],
  [summaryZkpKey, summaryZkpRaw],
  [merkleZkpKey, merkleZkpRaw],
]);
const q24Inventory = [];
for (const [key, raw] of q24Files) {
  const filename = path.join(q24ArtifactDir, key);
  await fs.mkdir(path.dirname(filename), { recursive: true });
  await fs.writeFile(filename, raw);
  const bytes = Buffer.from(raw);
  q24Inventory.push({ key, sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length });
}
q24Inventory.sort((a, b) => a.key.localeCompare(b.key));
const q24Core = {
  schemaVersion: 1, kind: 'bitcoinu-emergency-result-set', blockNum: zkpN,
  sourceRunId: 'fixture', resultManifestCoreSha256: resultManifestHash,
  merkleRoot, claimData: { chunkCount: 1, dataHash: claimDataHash }, files: q24Inventory,
};
const q24BundleIndex = {
  ...q24Core,
  coreSha256: createHash('sha256').update(JSON.stringify(q24Core)).digest('hex'),
  createdAt: '2026-09-16T00:00:00.000Z', complete: true,
};
await fs.mkdir(path.join(q24ArtifactDir, '_emergency'), { recursive: true });
await fs.writeFile(
  path.join(q24ArtifactDir, '_emergency/bundle-index.json'), JSON.stringify(q24BundleIndex),
);
let forbiddenNetworkCalls = 0;
let q24Collected = null;
let q24Error = null;
try {
  q24Collected = await collectZkpInput({
    rpcUrl: 'http://collector.invalid', tokenMining, blockNum: zkpN,
    artifactDir: q24ArtifactDir,
    fetchImpl: async () => { forbiddenNetworkCalls++; throw new Error('network forbidden'); },
    client: collectorClient,
  });
} catch (error) { q24Error = error; }
ok('Q24-C: Bの固定一式から共有collectorを完走し、HTTPを一度も呼ばない',
  q24Error === null && forbiddenNetworkCalls === 0
    && q24Collected.resultManifestHash === resultManifestHash,
  q24Error?.message || `networkCalls=${forbiddenNetworkCalls}`);
ok('Q24-C2: 固定一式の由来をZKP入力へ明示する',
  q24Collected?.input?.inputProvenance?.networkArtifactFetch === false
    && q24Collected.input.inputProvenance.artifactDirectory === q24ArtifactDir);
await fs.writeFile(path.join(q24ArtifactDir, stage3ManifestKey), '{"tampered":true}');
let q24TamperError = null;
try {
  await collectZkpInput({
    rpcUrl: 'http://collector.invalid', tokenMining, blockNum: zkpN,
    artifactDir: q24ArtifactDir,
    client: collectorClient,
  });
} catch (error) { q24TamperError = error; }
const q24TamperVerdict = describeZkpCollectionFailure(q24TamperError, 999);
const q24TamperEmergency = z14Evaluate(q24TamperVerdict, true);
ok('P5 R30-U-7 負: 固定一式そのもののファイルsha不一致は乗っ取り中の証明へ降格せず停止',
  q24TamperError?.zkpArtifactMismatch === true
    && q24TamperError?.zkpChainAnchorMismatch !== true
    && q24TamperVerdict.cause === ZKP_COLLECTION_FAILURE_CAUSES.artifactMismatch
    && q24TamperEmergency.report.get('check.stageC.zkPublicValues')?.status === 'fail'
    && q24TamperEmergency.data.emergencyDifferences.length === 0
    && /verification failed: check\.stageC\.zkPublicValues/.test(String(q24TamperEmergency.gateError?.message)),
  detailJson({ error: q24TamperError?.message, verdict: q24TamperVerdict }));
await fs.rm(q24ArtifactDir, { recursive: true, force: true });
if (p8bMutationTmpRoot) await fs.rm(p8bMutationTmpRoot, { recursive: true, force: true });

// R32-B-4-03 / R31-U-D: 通常 Stage C の Evidence 走査を本物の compact 提出で通す。
// 非 export の reproduceEvidence は原本ソースの小さい複製に export だけ足して呼ぶ。
// W21/W22 も同じ複製だけに当て、作業ツリーの src は一切書き換えない。
const n4bRoot = path.resolve(process.env.N7_TEST_TMP_ROOT
  || path.resolve(import.meta.dirname, '../../tmp/round32/N4b'));
const n4bVerifier = path.join(n4bRoot, 'stage-c-module/block-verifier');
const n4bSourcePath = path.resolve(import.meta.dirname, '../src/stages/results.js');
const n4bMutation = process.env.N4B_MUTATION || '';
if (n4bMutation && !['W21', 'W22'].includes(n4bMutation)) {
  throw new Error(`unknown N4b mutation: ${n4bMutation}`);
}
await fs.rm(path.dirname(n4bVerifier), { recursive: true, force: true });
await fs.mkdir(path.join(n4bVerifier, 'src/stages'), { recursive: true });
await fs.writeFile(path.join(n4bVerifier, 'package.json'), '{"type":"module"}\n');
const n4bOriginalVerifier = path.resolve(import.meta.dirname, '..');
for (const entry of await fs.readdir(path.join(n4bOriginalVerifier, 'src'), { withFileTypes: true })) {
  if (entry.name !== 'stages') {
    await fs.symlink(path.join(n4bOriginalVerifier, 'src', entry.name),
      path.join(n4bVerifier, 'src', entry.name));
  }
}
for (const entry of await fs.readdir(path.join(n4bOriginalVerifier, 'src/stages'), { withFileTypes: true })) {
  if (entry.name !== 'results.js') {
    await fs.symlink(path.join(n4bOriginalVerifier, 'src/stages', entry.name),
      path.join(n4bVerifier, 'src/stages', entry.name));
  }
}
await fs.symlink(path.join(n4bOriginalVerifier, 'vendor'), path.join(n4bVerifier, 'vendor'));
await fs.symlink(path.join(n4bOriginalVerifier, 'node_modules'), path.join(n4bVerifier, 'node_modules'));
let n4bSource = await fs.readFile(n4bSourcePath, 'utf8');
const n4bMutations = {
  W21: ['if (contradiction) contradictoryEvidence.push({ seq: event.seq, groupId: contradiction.groupId });',
    'if (contradiction) void contradiction;'],
  W22: ['    contradictoryEvidence = [];\n    if (!S.evidenceSpool)',
    '    if (!S.evidenceSpool)'],
};
if (n4bMutation) {
  const [before, after] = n4bMutations[n4bMutation];
  if (n4bSource.split(before).length !== 2) throw new Error(`${n4bMutation} mutation target is not unique`);
  n4bSource = n4bSource.replace(before, after);
}
const n4bStageCCall = "  ui.println(ui.t('stageC.evidenceChecking'));\n  await reproduceEvidence(ctx, S);";
if (n4bSource.split(n4bStageCCall).length !== 2) {
  throw new Error('the group-game Stage C Evidence call site is missing or duplicated');
}
n4bSource += `\nexport async function n4bRunStageCEvidence(ctx, S) {\n`
  + `  const { ui } = ctx;\n${n4bStageCCall}\n}\n`;
const n4bResultsPath = path.join(n4bVerifier, 'src/stages/results.js');
await fs.writeFile(n4bResultsPath, n4bSource);
const { n4bRunStageCEvidence } = await import(pathToFileURL(n4bResultsPath).href);

const n4bBlockNum = 4;
const n4bPlayers = await Promise.all([0, 1, 2].map((i) => makePlayer({
  uid: `n4b-${i}`, lang: 'en', blockNum: n4bBlockNum, keyIndex: 510 + i,
})));
const n4bMembers = n4bPlayers.map((player, i) => ({
  uid: player.uid, addr: player.addr, bAddr: player.bAddrString,
  depIds: JSON.stringify({ deposit: '10000000000000000', ids: [String(510 + i)] }),
}));
const n4bMemberUids = n4bMembers.map((member) => member.uid);
async function n4bPayload(playerIndex, groupId) {
  return (await buildSubmissionPayload(n4bPlayers[playerIndex], {
    blockNum: n4bBlockNum, groupId, serverMessages: [],
    submittedAt: 299_200_000, depositIds: [String(510 + playerIndex)],
    memberUids: n4bMemberUids,
  })).payload;
}
const n4bContradictoryRaw = await n4bPayload(0, 1);
const n4bHonestRaw = await n4bPayload(1, 0);
const n4bPublicIndex = buildMembersIndex([{ group_id: 0, members: n4bMembers }]);
const n4bOwnIndex = buildMembersIndex([{ group_id: 1, members: n4bMembers }]);
const n4bPublicValidation = await validateResultBundle(n4bContradictoryRaw, n4bBlockNum, n4bPublicIndex, n4bPlayers[0].addr);
const n4bOwnValidation = await validateResultBundle(n4bContradictoryRaw, n4bBlockNum, n4bOwnIndex, n4bPlayers[0].addr);
const n4bHonestValidation = await validateResultBundle(n4bHonestRaw, n4bBlockNum, n4bPublicIndex, n4bPlayers[1].addr);
ok('R32-B-4-03 前提: 署名済み提出は自分の枠で真正、公開組分けで矛盾し、正直な提出は有効',
  n4bPublicValidation.reason === 'compact_context_mismatch'
    && n4bOwnValidation.valid === true && n4bHonestValidation.valid === true,
  detailJson({ public: n4bPublicValidation.reason, own: n4bOwnValidation.reason,
    honest: n4bHonestValidation.reason }));
const n4bEvidenceAddr = `0x${'ab'.repeat(20)}`;
const n4bRows = await Promise.all([
  [1, n4bContradictoryRaw], [2, n4bHonestRaw],
].map(async ([seq, raw]) => ({
  args: { blockNum: BigInt(n4bBlockNum), seq: BigInt(seq),
    sender: n4bPlayers[seq - 1].addr,
    data: bytesToHex(await evidenceBytesFor(raw)), timestamp: 299_200n },
  transactionHash: `0x${String(seq).padStart(64, '0')}`, blockNumber: 9000n,
})));
async function n4bRunEvidence({ retry, honestOnly }) {
  const report = createReport();
  const lines = [];
  const ui = { println: (line) => lines.push(String(line)), t: (id) => id };
  let widened = false;
  let logsRead = 0;
  const ctx = {
    blockNum: n4bBlockNum, report, ui,
    data: { players: n4bMembers },
    cfg: { contracts: { evidence: n4bEvidenceAddr },
      pins: { confirmationBlocks: 0, clockSkewAllowMs: 120_000 } },
    r2: { baseDir: path.join(n4bRoot, 'evidence-cache') },
    chain: {
      evidenceAddress: async () => n4bEvidenceAddr,
      latest: async () => ({ number: 10000n }),
      getBlock: async () => ({ timestamp: 300_000 }),
      resultWindow: async () => ({ openAt: 299_900, closeAt: 299_950 }),
      chatWindow: async () => ({ chatOpenAt: 299_000, chatCloseAt: 299_500 }),
      resultCount: async () => honestOnly ? 1n : 2n,
      evidenceAcc: async () => {
        const events = honestOnly ? [n4bRows[1]] : n4bRows;
        return events.reduce((acc, row) => foldEvidenceAcc(acc, row.args.sender, row.args.data),
          `0x${'00'.repeat(32)}`);
      },
      client: { getLogs: async ({ fromBlock, toBlock, args }) => {
        logsRead++;
        if (fromBlock === 0n) widened = true;
        if (!(fromBlock <= 9000n && 9000n <= toBlock)) return [];
        const available = honestOnly ? [{ ...n4bRows[1], args: { ...n4bRows[1].args, seq: 1n } }]
          : retry && !widened ? [n4bRows[0]] : n4bRows;
        return available.filter((row) => args.seq.includes(row.args.seq));
      } },
    },
  };
  const S = {
    files: { manifest: { data: { rules: { evidence: {
      chatWindowMs: { startMs: 298_880_000, endMs: 299_620_000 },
    } } } } },
    groupDataList: [{ group: { group_id: 0 }, data: { members: n4bMembers } }],
    anomalies: [],
  };
  try {
    // run() の group-game 分岐から切り出した呼出し文を通して、走査・検証・report へ進む。
    await n4bRunStageCEvidence(ctx, S);
    const emitted = emitNonInteractiveOutcome(ui,
      { fatal: false, stopped: false, report }, null);
    return { check: report.get('check.stageC.evidenceContradictsGrouping'),
      lines, emitted, widened, logsRead };
  } finally {
    await S.evidenceSpool?.cleanup();
  }
}
const n4bContradiction = await n4bRunEvidence({ retry: true, honestOnly: false });
ok('R32-B-4-03: 通常 Stage C の再走査後に矛盾する真正 Evidence だけ1件をwarn',
  n4bContradiction.widened
    && n4bContradiction.check?.status === 'warn'
    && n4bContradiction.check.params?.count === 1
    && detailJson(n4bContradiction.check.params?.submissions) === '[{"seq":1,"groupId":1}]',
  detailJson(n4bContradiction));
ok('R32-B-4-03: warn は通常結果の ##RESULT full と exit 0 を変えない',
  n4bContradiction.lines.includes('##CHECK check.stageC.evidenceContradictsGrouping warn')
    && n4bContradiction.lines.includes('##RESULT full')
    && n4bContradiction.emitted.exitCode === 0,
  detailJson(n4bContradiction));
const n4bHonest = await n4bRunEvidence({ retry: false, honestOnly: true });
ok('R32-B-4-03: 正直な Evidence のみなら通常 Stage C の矛盾警告はpass',
  n4bHonest.check?.status === 'pass'
    && n4bHonest.check.params?.count === 0
    && n4bHonest.lines.includes('##CHECK check.stageC.evidenceContradictsGrouping pass')
    && n4bHonest.lines.includes('##RESULT full')
    && n4bHonest.emitted.exitCode === 0,
  detailJson(n4bHonest));
console.log(`N4B_STAGE_C_CHECK ${detailJson(n4bContradiction.check)}`);
console.log(n4bContradiction.lines.filter((line) =>
  line.startsWith('##CHECK check.stageC.evidenceContradictsGrouping') || line.startsWith('##RESULT ')).join('\n'));
console.log(`N4B_STAGE_C_RESULT mutation=${n4bMutation || 'none'} `
  + `warn=${n4bContradiction.check?.status}:${n4bContradiction.check?.params?.count} `
  + `honest=${n4bHonest.check?.status} result=${n4bContradiction.emitted.category}`);

// FIX8: 読めるproofのcollector経路も固定起点の実物と比較する。
if (process.env.FIX8_READABLE_PROOF_PARITY === '1') {
  const { execFileSync } = await import('node:child_process');
  const base = '08f7ef70556b7aca19aa4fdab25a4c127fbf47f7';
  const loadBase = async (file) => {
    const url = new URL('../' + file, import.meta.url);
    const source = execFileSync('git', ['show', `${base}:block-verifier/${file}`], { encoding: 'utf8' })
      .replace(/from '([^']+)'/g, (_, p) => `from '${p.startsWith('.') ? new URL(p, url).href : import.meta.resolve(p)}'`);
    return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  };
  const baseZkp = await loadBase('src/zkp.js'), baseResults = await loadBase('src/stages/results.js');
  for (const [label, input] of [
    ['latest', latestCalldata], ['named-older-row', oldCalldata],
    ['evidenceAcc-mismatch', proofCalldata(encodePublicValues({
      ...buildExpectedPublicValues(defaultLatestCollected), evidenceAcc: `0x${'12'.repeat(32)}`,
    }), 1n)],
  ]) {
    const outcomes = [];
    for (const [inspect, record] of [[baseZkp.inspectProofSubmission, baseResults.recordZkpPublicValuesCheck],
      [inspectProofSubmission, recordZkpPublicValuesCheck]]) {
      const inspected = await inspect({ chain: makeProofChain({ txInput: input }).chain,
        blockNum: zkpN, root: merkleRoot, event: proofEvent, epoch: proofEpoch,
        artifacts: fiveArtifacts, r2Base: 'https://r2.invalid', confirmationBlocks: 64 });
      const report = createReport(); record({ report, data: {} }, inspected.publicValues);
      const outcome = emitNonInteractiveOutcome({ println() {} }, { report, fatal: false, stopped: false }, null);
      outcomes.push({ inspected, records: report.list(), category: outcome.category, code: outcome.exitCode });
    }
    assert.deepEqual(outcomes[1], outcomes[0], `FIX8 readable proof parity ${label}`);
    assert.equal(outcomes[1].code, label === 'evidenceAcc-mismatch' ? 2 : 0);
    console.log(`FIX8_PROOF_PARITY ${label}: all statuses/params/exit equal; base=${base}`);
  }
}
console.log(`\ns5-results-guards-unit: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);

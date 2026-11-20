// FIX7: 現在の安全高の窓を権威にする。部分ログはvendor実物で再生する。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { custom } from 'viem';
import { createChain } from '../src/chain.js';
import { ArchiveUnavailableError } from '../src/archive.js';
import { createReport } from '../src/report.js';
import { categorize, EXIT_CODE_OF } from '../src/index.js';
import { t } from '../src/i18n.js';
import { getBlockRewardWei } from '../vendor/workers/game_workers/lib/game-result-calculator.js';

const BASE = '08f7ef70556b7aca19aa4fdab25a4c127fbf47f7';
const mutation = process.argv.find((arg) => arg.startsWith('--mutation='))?.split('=')[1];
let applied = false, assertions = 0;
const eq = (actual, expected, label) => { assert.deepEqual(actual, expected, label); assertions++; };
const ok = (value, label) => { assert.ok(value, label); assertions++; };
function replace(source, before, after) {
  assert.ok(source.includes(before), `${mutation}: 変異対象が存在する`);
  applied = true;
  return source.replace(before, after);
}
async function load(file, edit = (source) => source, supplied) {
  const url = new URL(file, import.meta.url);
  const source = edit(supplied ?? readFileSync(url, 'utf8')).replace(/from '([^']+)'/g,
    (_, path) => `from '${path.startsWith('.') ? new URL(path, url).href : import.meta.resolve(path)}'`);
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
}
const results = await load('../src/stages/results.js', (source) => {
  if (mutation === 'current_window') return replace(source,
    'const rw = await ctx.chain.resultWindow(N, { blockNumber: currentSafe });',
    'const rw = { openAt: Number(finality.resultOpenAt), closeAt: Number(finality.resultCloseAt) };');
  if (mutation === 'current_comparison') return replace(source,
    'knownFinalityMismatch = Number(finality.resultOpenAt) !== observedFinality.resultOpenAt\n        || Number(finality.resultCloseAt) !== observedFinality.resultCloseAt;',
    'knownFinalityMismatch = false;');
  if (mutation === 'summary_window') return replace(source,
    ': finalityError || knownFinalityMismatch ? { ...finality, ...observedFinality } : finality;',
    ': finalityError ? { ...finality, ...observedFinality } : finality;');
  if (mutation === 'window_cache') return replace(source,
    'Promise.resolve(currentWindow.rw)', 'ctx.chain.resultWindow(N, atSafe)');
  if (mutation === 'current_error') return replace(source,
    'if (currentWindow.error) throw currentWindow.error;', '/* current window prerequisite discarded */');
  return source;
}, process.env.FIX7_RESULTS_SOURCE ? readFileSync(process.env.FIX7_RESULTS_SOURCE, 'utf8') : undefined);
const lifecycleModule = await load('../vendor/workers/game_workers/lib/block-lifecycle.js', (source) => {
  if (mutation !== 'partial_replay_throw') return source;
  return replace(source,
    'if (root === null) errors.push(`extension occurred before a Merkle root at ${timestamp}`);',
    'if (root === null) throw new Error(`extension occurred before a Merkle root at ${timestamp}`);');
});
if (mutation) { assert.ok(applied); console.log(`MUTATION_APPLIED ${mutation}`); }
const address = '0x' + '11'.repeat(20), other = '0x' + '22'.repeat(20);
const root = '0x' + '33'.repeat(32), hash = '0x' + '44'.repeat(32);
const ui = { t: t('ja'), println() {}, warn() {} };
const denied = () => new ArchiveUnavailableError();
const status = (ctx, id) => ctx.report.get(`check.stageC.${id}`)?.status;
const exit = (ctx) => EXIT_CODE_OF[categorize({ report: ctx.report, fatal: false, stopped: false })];

function noGame({ realistic = false, readable = false, safe, forged = {}, currentError = null,
  searchError = false, declaredError = null, count = 0, changed = {}, tuple = false } = {}) {
  const head = realistic ? 26400000n : 164n;
  const currentSafe = head - 64n;
  const closeHeight = realistic ? head - 1000n : 50n;
  const scale = realistic ? 12 : 10;
  // 2023年の宣言高の見出しは読めるが、eth_callは直近100高のみ。
  const offset = realistic ? 1682900400 - 17000100 * 12 : 0;
  const timestamp = (height) => Number(height) * scale + offset;
  const rw = { openAt: timestamp(closeHeight) - 100, closeAt: timestamp(closeHeight) };
  const safeNumber = safe ?? (realistic ? 17000100n : 20n);
  const finality = { schemaVersion: 1, evidenceContract: address, safeBlockNumber: String(safeNumber),
    safeTimestamp: timestamp(safeNumber), resultOpenAt: rw.openAt, resultCloseAt: rw.closeAt,
    resultCount: 0, ...forged };
  const published = { schemaVersion: 3, blockNum: 8, blockReward: getBlockRewardWei(8).toString(),
    totalPlayers: 3, totalGroups: 0, noGame: true, majorLangs: [], groups: [],
    claimStatusKey: 'games/block8/claim-status.json', claimLayout: 'group-overlays-v1',
    noGameReason: 'timeline_unverified', noGameCause: 'chain_unreadable', noGameFinality: finality };
  const calls = [], targets = [], headers = [];
  const search = createChain({ chainIdExpected: 31337, contracts: {}, rpcUrls: ['http://127.0.0.1:1'] }, ui,
    custom({ request: async ({ method, params }) => {
      assert.equal(method, 'eth_getBlockByNumber');
      const n = params[0] === 'latest' ? head : BigInt(params[0]); headers.push(n);
      if (!readable && !realistic && n < 90n) throw denied();
      if (realistic && n < 15500000n) throw { code: 4444,
        message: `pruned history unavailable: requested ${n}, earliest available 15500000` };
      return { number: '0x' + n.toString(16), timestamp: '0x' + timestamp(n).toString(16), hash };
    } }, { retryCount: 0 }));
  const ctx = { blockNum: 8, ui, report: createReport(), cfg: { pins: { confirmationBlocks: 64 } },
    data: { gameSelection: { players: [{}, {}, {}] } },
    r2: { fetchJson: async (key) => key.endsWith('/summary.json') ? { data: published } : null },
    chain: {
      latest: async () => ({ number: head, timestamp: BigInt(timestamp(head)) }),
      findBlockByTimestamp: async (target) => {
        targets.push(target); if (searchError) throw denied();
        return search.findBlockByTimestamp(target);
      },
      getBlock: async (n) => {
        calls.push(['header', n]);
        if (!readable && !realistic && n < 90n) throw denied();
        return { timestamp: BigInt(timestamp(n)) };
      },
      resultWindow: async (_n, opts) => {
        const n = opts.blockNumber; calls.push(['window', n]);
        if (n === currentSafe) { if (currentError) throw currentError; }
        else { if (declaredError) throw declaredError; if (!readable && n < head - 100n) throw denied(); }
        return tuple ? [BigInt(rw.openAt), BigInt(rw.closeAt)] : rw;
      },
      resultCount: async (_n, opts) => {
        calls.push(['count', opts.blockNumber]);
        if (!readable && opts.blockNumber < head - 100n) throw denied();
        return count;
      },
      evidenceAddress: async () => changed.evidenceContract ?? address,
      verificationPeriod: async () => 100,
    } };
  return { ctx, S: { files: { summary: { data: published } }, anomalies: [], zkInfo: { currentProofRequired: true } },
    rw, calls, targets, headers, currentSafe, closeHeight };
}
function checkFailure(ctx, label) {
  for (const id of ['timelineNoGameFinality', 'timelineNoGameSummary', 'summaryMatch']) {
    eq(status(ctx, id), 'fail', `${label}: ${id} FAIL`);
  }
  eq(exit(ctx), 2, `${label}: exit 2`);
}
// F6-a: Leanの二重偽装と2023年の反証。宣言高を読む前に3検査ともFAIL。
for (const realistic of [false, true]) for (const readable of [false, true]) {
  const fixture = noGame({ realistic, readable, forged: realistic
    ? { resultOpenAt: 1682899900, resultCloseAt: 1682900000 }
    : { resultOpenAt: 90, resultCloseAt: 100 } });
  const { ctx, S, rw, calls, targets, currentSafe } = fixture;
  await results.verifyTimelineNoGameFinality(ctx, S);
  checkFailure(ctx, `F6-a ${realistic ? 'R5-1 2023' : 'Lean 500/100/20'}/${readable}`);
  eq(calls, [['window', currentSafe]], 'F6-a: 宣言高の見出し/stateを読む前にFAIL');
  eq(targets, [rw.closeAt], 'F6-a: 今の窓のcloseAtで下限を探索');
  eq(S.rebuiltSummary.noGameFinality.resultCloseAt, rw.closeAt, 'F6-a: summaryも現在の窓から再構築');
}
// closeだけでなくopenの偽装も拾う。宣言高は閉鎖より後、履歴stateのみ不能。
for (const forged of [{ resultOpenAt: 1 }, { resultCloseAt: 100 }]) {
  const { ctx, S, calls, currentSafe } = noGame({ safe: 51n, forged });
  await results.verifyTimelineNoGameFinality(ctx, S);
  checkFailure(ctx, 'F6-a current comparison');
  eq(calls, [['window', currentSafe]], 'F6-a current comparison: 宣言高をまだ読まない');
}
// 公開窓が正しくても閉鎖前の宣言高を拒否する。
{
  const { ctx, S } = noGame({ realistic: true }); await results.verifyTimelineNoGameFinality(ctx, S);
  checkFailure(ctx, 'F6-a lower bound');
}
// 正直な鎖の閉鎖高さちょうど/次。以後の現在窓は不変、tupleも同じ。
for (const realistic of [false, true]) for (const delta of [0n, 1n]) for (const tuple of [false, true]) {
  const initial = noGame({ realistic });
  const { ctx, S } = noGame({ realistic, readable: true, safe: initial.closeHeight + delta, tuple });
  eq(await results.verifyTimelineNoGameFinality(ctx, S), true, 'F6-a honest boundary: 正直なfinalityはPASS');
  for (const id of ['timelineNoGameFinality', 'timelineNoGameSummary', 'summaryMatch']) {
    eq(status(ctx, id), 'pass', `F6-a honest boundary: ${id}`);
  }
  eq(exit(ctx), 0, 'F6-a honest boundary: exit 0');
  assert.doesNotThrow(() => JSON.stringify(S.timelineNoGameCurrentWindow),
    'F6-a current window: BigIntのRPC値を共有しても診断JSONを壊さない'); assertions++;
}
// 現在窓だけ型付き不能なら公開値の下限に落ち、依存する真偽は未検証。
for (const readable of [false, true]) {
  const { ctx, S, rw, targets } = noGame({ safe: 51n, readable, currentError: denied(), searchError: true });
  await results.verifyTimelineNoGameFinality(ctx, S);
  eq(targets, [rw.closeAt], 'F6-a fallback: 公開窓の下限を試す');
  eq(status(ctx, 'timelineNoGameFinality'), 'skip', 'F6-a fallback: 現在窓未検証を合格にしない');
  eq(ctx.report.get('check.stageC.timelineNoGameFinality').reason, 'archive_unavailable', 'F6-a fallback: 型を保持');
  eq(exit(ctx), 1, 'F6-a fallback: partial 1');
}
// fallbackでも低すぎる高さや読めた別の値の違反はFAIL。
{
  const { ctx, S } = noGame({ realistic: true, currentError: denied() });
  await results.verifyTimelineNoGameFinality(ctx, S); checkFailure(ctx, 'F6-a fallback low height');
}
{
  const { ctx, S } = noGame({ safe: 51n, currentError: denied(), changed: { evidenceContract: other } });
  await results.verifyTimelineNoGameFinality(ctx, S); checkFailure(ctx, 'F6-a fallback wiring');
}
{
  const { ctx, S, calls } = noGame({ safe: 51n, currentError: new Error('temporary RPC failure') });
  await results.verifyTimelineNoGameFinality(ctx, S);
  eq(status(ctx, 'timelineNoGameFinality'), 'fail', 'F6-a ordinary error: 型なしをSKIPしない');
  eq(calls.length, 1, 'F6-a ordinary error: 公開値へのfallbackは型付きだけ');
}
// root省略: 現在窓を1回だけ読み、今のcount/期限の検査も続ける。
for (const count of [0, 1]) {
  const { ctx, S, calls, currentSafe } = noGame({ safe: 51n, count });
  await results.verifyTimelineNoGameRootOmission(ctx, S);
  eq(calls.filter(([kind, n]) => kind === 'window' && n === currentSafe).length, 1,
    'F6-a window cache: root省略と現在窓の読取を共有');
  eq(status(ctx, 'timelineNoGameEvidenceEmpty'), count ? 'fail' : 'pass', 'F6-a window cache: 現在countを検査');
  eq(status(ctx, 'rootSubmitted'), count ? 'fail' : 'skip', 'F6-a window cache: count違反を保持');
  eq(exit(ctx), count ? 2 : 1, 'F6-a window cache: exit');
}
// F6-b: 正常なABI値/位置の部分列は例外を投げない。違反はerrorsとして返る。
const position = (evtBlock, logIndex = 0) => ({ evtBlock, transactionIndex: 0, logIndex });
const eventHistory = [
  { kind: 'root', root, timestamp: 1050, ...position(10) },
  { kind: 'extension', newEndFloor: 1250, timestamp: 1100, ...position(11) },
  { kind: 'root', root: hash, timestamp: 1200, ...position(12) },
  { kind: 'invalidation', timestamp: 1210, ...position(13) },
  { kind: 'extension', newEndFloor: 1400, timestamp: 1220, ...position(14) },
  { kind: 'root', root, timestamp: 1300, ...position(15) },
  { kind: 'extension', newEndFloor: 1500, timestamp: 1350, ...position(16) },
];
function replayInput(rows) {
  return { rootEvents: rows.filter((e) => e.kind === 'root'),
    extensionEvents: rows.filter((e) => e.kind === 'extension'),
    invalidationEvents: rows.filter((e) => e.kind === 'invalidation'),
    verificationPeriodSec: 100, verificationCap: 2000 };
}
const replay = (rows) => lifecycleModule.replayAdminCommitLifecycle(replayInput(rows));
for (const [label, rows] of [
  ['extension only', [eventHistory[1]]], ['invalidation only', [eventHistory[3]]],
  ['extension before root outside window', [eventHistory[2]]],
  ['root before invalidation outside window', eventHistory.slice(3)],
  ['root outside window then extension', eventHistory.slice(1)],
]) {
  let value;
  assert.doesNotThrow(() => { value = replay(rows); }, `F6-b partial replay: ${label}`); assertions++;
  eq(value.history.length, rows.length, `F6-b partial replay: ${label}を全部再生`);
  ok(Array.isArray(value.errors), 'F6-b partial replay: 違反はerrorsに返す');
}
// 各ログ種を独立に取得できなかった場合を含む全128部分集合。
for (let mask = 0; mask < 1 << eventHistory.length; mask++) {
  const rows = eventHistory.filter((_e, index) => mask & (1 << index));
  let value;
  assert.doesNotThrow(() => { value = replay(rows); }, `F6-b partial replay: subset ${mask}`); assertions++;
  eq(value.history.length, rows.length, 'F6-b partial replay: 欠けた先行イベントでthrowしない');
}
eq(replay([eventHistory[1]]).errors, ['extension occurred before a Merkle root at 1100'],
  'F6-b partial replay: 先行root不足は例外でなくerrors');
eq(replay([eventHistory[3]]).ok, true, 'F6-b partial replay: 無効化だけでも再生可能');
// 投げるのは不正な数値/位置。全履歴でも部分履歴でも同じ入力検査。
for (const rows of [[{ ...eventHistory[1], newEndFloor: 0 }], [{ ...eventHistory[3], timestamp: -1 }],
  [{ ...eventHistory[0], evtBlock: -1 }, eventHistory[1]]]) {
  assert.throws(() => replay(rows), /invalid /, 'F6-b malformed: 欠損ではなく入力値不正でthrow'); assertions++;
}

// 実verifyTimelineにも部分ログを通し、replay例外のnotesが付かないことを確認。
const timing = { startTimeEntryMs: 0, blockTimeMs: 100000, gamePeriodMs: 100000, submitPeriodMs: 100000 };
function timeline(rows, changed = {}, readable = false) {
  const input = replayInput(rows), value = replay(rows);
  const latestRoot = value.root ?? '0x' + '00'.repeat(32);
  const lifecycle = { mode: 0, merkleRoot: latestRoot, verificationStartedAt: value.verificationStartedAt,
    verificationEndsAt: value.verificationEndsAt,
    claimEndsAt: value.verificationEndsAt ? value.verificationEndsAt + 100 : 0, stage: 3, ...changed };
  return { ctx: { blockNum: 8, ui, report: createReport(), cfg: { contracts: { tokenMining: address } }, data: {}, chain: {
    latest: async () => ({ number: 26400000n }), findBlockByTimestamp: async () => 26399000,
    findContractDeploymentBlock: async () => { if (!readable) throw denied(); return 26300000; },
    merkleRootEvents: async () => input.rootEvents,
    verificationExtendedEvents: async () => input.extensionEvents,
    merkleRootInvalidatedEvents: async () => input.invalidationEvents,
    otherRegistrationCount: async () => 0,
    getTimingConstants: async () => timing, currentGrace: async () => 60,
    verificationPeriod: async () => 100, claimPeriod: async () => 100,
    resultWindow: async () => ({ closeAt: 1000 }), getBlockLifecycle: async () => lifecycle,
  } }, S: { groupIds: [], noGame: true, files: { summary: { data: {} } }, anomalies: [],
    blockState: { root: latestRoot, verificationStartedAt: value.verificationStartedAt }, zkInfo: { kind: 'shadow' } } };
}
for (const rows of [[eventHistory[1]], [eventHistory[3]], eventHistory.slice(2), eventHistory.slice(3), eventHistory.slice(1)]) {
  const { ctx, S } = timeline(rows); await results.verifyTimeline(ctx, S, timing);
  ok(!JSON.stringify(ctx.report.list()).includes('event replay unavailable'), 'F6-b integrated: 部分履歴でreplay例外なし');
  ok(ctx.report.getFact('stageC.claimWindow'), 'F6-b integrated: 現在getterの窓は記録');
}
for (const changed of [{ claimEndsAt: 1210 }, { mode: 1 }, { verificationEndsAt: 1149, claimEndsAt: 1249 }]) {
  const { ctx, S } = timeline([eventHistory[0]], changed); await results.verifyTimeline(ctx, S, timing);
  for (const id of ['lifecycleReplayCurrent', 'rootSubmissionRules']) eq(status(ctx, id), 'fail', `F6-b current: ${id}違反はFAIL`);
  eq(exit(ctx), 2, 'F6-b current: exit 2');
}
{
  const { ctx, S } = timeline([{ ...eventHistory[0], timestamp: 900 }]);
  await results.verifyTimeline(ctx, S, timing);
  eq(status(ctx, 'rootSubmissionRules'), 'fail', 'F6-b visible: 見えた窓終了前のrootはFAIL');
  eq(exit(ctx), 2, 'F6-b visible: exit 2');
}
// 追加した正常なfinalityの境界/翌高も固定起点の実物と全レコードを比較。
const base = await load('../src/stages/results.js', undefined,
  execFileSync('git', ['show', `${BASE}:block-verifier/src/stages/results.js`], { encoding: 'utf8' }));
for (const delta of [0n, 1n]) for (const fn of ['verifyTimelineNoGameFinality', 'verifyTimelineNoGameRootOmission']) {
  const records = [];
  for (const mod of [base, results]) {
    const { ctx, S } = noGame({ readable: true, safe: 50n + delta });
    await mod[fn](ctx, S);
    records.push({ checks: ctx.report.list(), exit: exit(ctx) });
  }
  eq(records[1], records[0], `${fn}/${delta}: 固定起点と全状態/params/exitが同じ`);
}
if (!mutation && !process.env.FIX7_RESULTS_SOURCE) for (const name of [
  'current_window', 'current_comparison', 'summary_window', 'window_cache', 'current_error', 'partial_replay_throw',
]) {
  const child = spawnSync(process.execPath, [new URL(import.meta.url).pathname, `--mutation=${name}`],
    { encoding: 'utf8', timeout: 30000, maxBuffer: 10 * 1024 * 1024 });
  eq(child.stdout.includes(`MUTATION_APPLIED ${name}`), true, `${name}: 変異適用済み`);
  eq(child.status, 1, `${name}: 変異で赤`);
  ok(child.stderr.includes('AssertionError'), `${name}: import失敗でなくassertionで検出`);
  const label = { current_window: 'F6-a', current_comparison: 'F6-a', summary_window: 'F6-a',
    window_cache: 'F6-a window cache', current_error: 'F6-a fallback', partial_replay_throw: 'F6-b partial replay' }[name];
  ok(child.stderr.includes(label), `${name}: 該当する歯で検出`);
}
console.log(`fix7-verifier-unit: PASS (${assertions} assertions; 128 partial event sets; 6 mutants killed)`);

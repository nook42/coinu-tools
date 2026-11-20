// FIX6: 実関数へ再反証の入力を通し、依存する比較だけを未検証にする。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync, execFileSync } from 'node:child_process';
import { custom } from 'viem';
import { createReport, verificationCoverage } from '../src/report.js';
import { createChain } from '../src/chain.js';
import { ArchiveUnavailableError } from '../src/archive.js';
import { categorize, EXIT_CODE_OF } from '../src/index.js';
import { CHECK_INVENTORY } from '../src/check-inventory.js';
import { t, SUPPORTED_LANGS } from '../src/i18n.js';
import { getBlockRewardWei } from '../vendor/workers/game_workers/lib/game-result-calculator.js';
import { MAX_VERIFICATION_EXTENSION_SEC } from '../vendor/workers/game_workers/lib/block-lifecycle.js';

const BASE = '08f7ef70556b7aca19aa4fdab25a4c127fbf47f7';
const mutation = process.argv.find((arg) => arg.startsWith('--mutation='))?.split('=')[1];
let applied = false, assertions = 0;
const eq = (a, b, label) => { assert.deepEqual(a, b, label); assertions++; };
const ok = (a, label) => { assert.ok(a, label); assertions++; };
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
  if (mutation === 'claim_relation') return replace(source,
    'if (current.claimEndsAt !== current.verificationEndsAt + claimPeriodSec)', 'if (false)');
  if (mutation === 'mode') return replace(source,
    "const currentOk = historyError ? currentMismatches.length === 0 : currentMatch.ok;",
    "const currentOk = historyError ? currentMismatches.filter((name) => !name.includes('AdminCommit')).length === 0 : currentMatch.ok;");
  if (mutation === 'end_bounds') return replace(source,
    'if (current.verificationEndsAt < current.verificationStartedAt + verificationPeriodSec\n        || current.verificationEndsAt > verificationCap)', 'if (false)');
  if (mutation === 'singleton') return replace(source,
    'events.length === 1 && historyError', 'false');
  if (mutation === 'declared_height') return replace(source,
    'closeBlock !== null && safeNumber < closeBlock', 'false');
  if (mutation === 'finality_summary') return replace(source,
    "if (finalityBeforeClose) report.check('check.stageC.summaryMatch'", "if (false) report.check('check.stageC.summaryMatch'");
  return source;
});
const summaryModule = await load('../src/report.js', (source) => mutation === 'fatal_timeline'
  ? replace(source, "st('check.main.fatal') !== null && !covered('timeline')", 'false') : source);
const membership = await load('../src/entry-membership.js', (source) => {
  // Stage Aの結果だけ代役。配線getter・findEntry・表示は実関数を使う。
  source = source.replace("import { run as runEntries } from './stages/entries.js';", `
    const runEntries = async (ctx) => {
      for (const id of ['rootMatch', 'earlyFreeze']) ctx.report.check('check.stageA.' + id, 'pass');
      ctx.data.infos = Array.from({length: 100}, () => ({entries: []}));
      ctx.data.entryFileHashes = new Map();
      return {stop: false};
    };`);
  if (mutation === 'getter_failure') return replace(source,
    "ctx.report.check('check.system.auditUnavailable', 'warn'",
    "ctx.report.check('check.system.hashStorageWiring', 'fail'");
  return source;
});
if (mutation) {
  assert.ok(applied, `${mutation}: 変異が適用された`);
  console.log(`MUTATION_APPLIED ${mutation}`);
}

const address = '0x' + '11'.repeat(20), other = '0x' + '22'.repeat(20);
const root = '0x' + '33'.repeat(32), hash = '0x' + '44'.repeat(32);
const denied = () => new ArchiveUnavailableError();
const ui = { t: t('ja'), println() {}, warn() {} };
const timing = { startTimeEntryMs: 0, blockTimeMs: 100000, gamePeriodMs: 100000, submitPeriodMs: 100000 };
function timeline({ readable = false, changed = {}, count = 1, earlier = false, logError = false } = {}) {
  const report = createReport(), ranges = [];
  const event = { root, timestamp: 1050, evtBlock: 26399010, txHash: hash, transactionIndex: 0, logIndex: 0 };
  const lifecycle = { mode: 0, merkleRoot: root, verificationStartedAt: 1050,
    verificationEndsAt: 1150, claimEndsAt: 1250, stage: 3, ...changed };
  const ctx = { blockNum: 8, report, ui, cfg: { contracts: { tokenMining: address } }, data: {}, chain: {
    latest: async () => ({ number: 26400000n }), findBlockByTimestamp: async () => 26399000,
    findContractDeploymentBlock: async () => { if (!readable) throw denied(); return 26300000; },
    merkleRootEvents: async (_n, range) => {
      ranges.push(range);
      if (logError) throw denied();
      const rows = count === 0 ? [] : [event];
      if (count > 1 || (earlier && range.fromBlock < 26397000n)) rows.unshift({ ...event, timestamp: 1000, evtBlock: 26390000 });
      return rows;
    },
    verificationExtendedEvents: async () => [], merkleRootInvalidatedEvents: async () => [],
    otherRegistrationCount: async () => 0,
    otherRegistrationAt: async () => { throw new Error('no registration'); },
    getTimingConstants: async () => timing, currentGrace: async () => 60,
    verificationPeriod: async () => 100, claimPeriod: async () => 100,
    resultWindow: async () => ({ closeAt: 1000 }), getBlockLifecycle: async () => lifecycle,
  } };
  const S = { groupIds: [], noGame: true, files: { summary: { data: {} } }, anomalies: [],
    blockState: { root, verificationStartedAt: 1050 }, zkInfo: { kind: 'shadow' } };
  return { ctx, S, ranges };
}
const status = (ctx, id) => ctx.report.get(`check.stageC.${id}`)?.status;
const exit = (ctx) => EXIT_CODE_OF[categorize({ report: ctx.report, fatal: false, stopped: false })];

// L-1: 現在getterの3違反。履歴が読める場合も、配備高不能の場合も2検査FAIL。
for (const [name, changed, detail] of [
  ['claim', { claimEndsAt: 1210 }, 'claimEndsAt'],
  ['mode', { mode: 1 }, 'AdminCommit'],
  ['end_low', { verificationEndsAt: 1149, claimEndsAt: 1249 }, 'verificationEndsAt'],
  ['end_high', { verificationEndsAt: 1001 + MAX_VERIFICATION_EXTENSION_SEC,
    claimEndsAt: 1101 + MAX_VERIFICATION_EXTENSION_SEC }, 'verificationEndsAt'],
]) for (const readable of [true, false]) {
  const { ctx, S } = timeline({ readable, changed });
  await results.verifyTimeline(ctx, S, timing);
  for (const id of ['lifecycleReplayCurrent', 'rootSubmissionRules']) {
    eq(status(ctx, id), 'fail', `L-1 ${name}/${readable}/${id}: 現在値の違反をFAIL`);
    ok(JSON.stringify(ctx.report.get(`check.stageC.${id}`).params).includes(detail), `L-1 ${name}: 不一致の値を記録`);
  }
  eq(exit(ctx), 2, `L-1 ${name}: exit 2`);
  ok(ctx.report.getFact('stageC.claimWindow'), '現在の請求窓のfactも残す');
}
// 見えていないfloorで説明できる期限の差を、独立違反と取り違えない。
for (const logError of [false, true]) {
  const { ctx, S } = timeline({ changed: { verificationEndsAt: 1200, claimEndsAt: 1300 }, logError });
  await results.verifyTimeline(ctx, S, timing);
  for (const id of ['lifecycleReplayCurrent', 'rootSubmissionRules']) {
    eq(status(ctx, id), 'skip', `${id}: 不明なfloorとの一致だけ未検証`);
    eq(ctx.report.get(`check.stageC.${id}`).reason, 'archive_unavailable', '型付き失敗の理由');
  }
  eq(exit(ctx), 1, `合法な延長を説明できないだけならpartial: ${JSON.stringify(ctx.report.list().filter((entry) => entry.status === 'fail'))}`);
}
for (const changed of [{ merkleRoot: hash }, { verificationStartedAt: 1049 }]) {
  const { ctx, S } = timeline({ changed }); await results.verifyTimeline(ctx, S, timing);
  eq(status(ctx, 'lifecycleReplayCurrent'), 'fail', '読めたroot/startの照合は履歴不足でもFAIL');
}

// R4-1: 全履歴の2件はWARN、有限窓の1件は型付きSKIP。0件/複数件は保持。
for (const readable of [true, false]) {
  const { ctx, S, ranges } = timeline({ readable, earlier: true });
  await results.verifyTimeline(ctx, S, timing);
  eq(status(ctx, 'rootResubmitted'), readable ? 'warn' : 'skip', 'R4-1: singletonを全履歴の証明にしない');
  if (!readable) {
    eq(ctx.report.get('check.stageC.rootResubmitted').reason, 'archive_unavailable', 'R4-1: 型付き未検証');
    eq(ranges, [{ fromBlock: 26397000n, toBlock: 26400000n }], '有限窓を維持');
  }
}
for (const [count, expected] of [[0, 'fail'], [2, 'warn']]) {
  const { ctx, S } = timeline({ count }); await results.verifyTimeline(ctx, S, timing);
  eq(status(ctx, 'rootResubmitted'), expected, `R4-1 ${count}件は${expected}`);
}

// R4-2: 本番サイズhead、古いヘッダは実code4444。探索は実chainの倍々探索。
const head = 26400000n, closeHeight = head - 1000n, closeAt = Number(closeHeight * 12n);
function noGame({ readable = false, safeNumber = 13213332n, searchError = false } = {}) {
  const headerReads = [], declaredReads = [], targets = [];
  const searchChain = createChain({ chainIdExpected: 31337, contracts: {}, rpcUrls: ['http://127.0.0.1:1'] }, ui,
    custom({ request: async ({ method, params }) => {
      assert.equal(method, 'eth_getBlockByNumber');
      const n = params[0] === 'latest' ? head : BigInt(params[0]); headerReads.push(n);
      if (n < 15500000n) throw { code: 4444, message: `pruned history unavailable: requested ${n}, earliest available 15500000` };
      return { number: '0x' + n.toString(16), timestamp: '0x' + (n * 12n).toString(16), hash: root };
    } }, { retryCount: 0 }));
  const finality = { schemaVersion: 1, evidenceContract: address, safeBlockNumber: String(safeNumber),
    safeTimestamp: safeNumber < closeHeight ? closeAt + 10 : Number(safeNumber * 12n),
    resultOpenAt: closeAt - 100, resultCloseAt: closeAt, resultCount: 0 };
  const published = { schemaVersion: 3, blockNum: 8, blockReward: getBlockRewardWei(8).toString(), totalPlayers: 3,
    totalGroups: 0, noGame: true, majorLangs: [], groups: [], claimStatusKey: 'games/block8/claim-status.json',
    claimLayout: 'group-overlays-v1', noGameReason: 'timeline_unverified', noGameCause: 'chain_unreadable', noGameFinality: finality };
  const read = (kind, value) => { declaredReads.push(kind); if (!readable) throw denied(); return value; };
  const ctx = { blockNum: 8, report: createReport(), ui, cfg: { pins: { confirmationBlocks: 64 } },
    data: { gameSelection: { players: [{}, {}, {}] } }, chain: {
      latest: async () => ({ number: head }),
      findBlockByTimestamp: async (target) => { targets.push(target); if (searchError) throw denied(); return searchChain.findBlockByTimestamp(target); },
      getBlock: async () => read('header', { timestamp: safeNumber * 12n }),
      resultWindow: async (_n, opts) => opts.blockNumber === head - 64n
        ? { openAt: closeAt - 100, closeAt }
        : read('window', { openAt: closeAt - 100, closeAt }),
      resultCount: async () => read('count', 0), evidenceAddress: async () => address,
    } };
  return { ctx, S: { files: { summary: { data: published } }, anomalies: [] }, headerReads, declaredReads, targets };
}
for (const readable of [false, true]) for (const safeNumber of [13213332n, closeHeight - 1n]) {
  const { ctx, S, headerReads, declaredReads, targets } = noGame({ readable, safeNumber });
  await results.verifyTimelineNoGameFinality(ctx, S);
  for (const id of ['timelineNoGameFinality', 'timelineNoGameSummary', 'summaryMatch']) {
    eq(status(ctx, id), 'fail', `R4-2 ${readable}/${id}: 閉鎖前の高さはFAIL`);
  }
  eq(declaredReads, [], 'R4-2: 公開の古い高さを読む前に判定');
  eq(targets, [closeAt], '現在のresultCloseAtのlower_boundを独立に探索');
  ok(headerReads.length < 30 && headerReads.every((n) => n >= 15500000n), '倍々探索は直近だけ、30回未満');
  eq(exit(ctx), 2, 'R4-2: exit 2');
}
for (const safeNumber of [closeHeight, closeHeight + 1n]) {
  const { ctx, S } = noGame({ readable: true, safeNumber });
  eq(await results.verifyTimelineNoGameFinality(ctx, S), true, 'R4-2: 境界と以後の正当なfinalityは合格');
}
// lower_boundが読めなくても、別の方法で得たヘッダやgetterの違反は捨てない。
{
  const { ctx, S } = noGame({ readable: true, searchError: true });
  await results.verifyTimelineNoGameFinality(ctx, S);
  eq(status(ctx, 'timelineNoGameFinality'), 'fail', '探索不能でも読めた宣言高の閉鎖前ヘッダはFAIL');
}

// R4-3: 採点とrootの照合の後、期間の検査の途中でfatalになる実際の記録形。
for (const lang of SUPPORTED_LANGS) for (const fatal of [false, true]) for (const complete of [false, true]) {
  const report = summaryModule.createReport();
  for (const id of CHECK_INVENTORY) {
    if (id === 'check.main.fatal' || (!complete && ['check.stageC.lifecycleReplayCurrent', 'check.stageC.rootSubmissionRules'].includes(id))) continue;
    report.check(id, 'pass');
  }
  if (fatal) report.check('check.main.fatal', 'fail', { error: 'timeline interrupted' });
  const lines = [], translate = t(lang);
  report.renderSummary({ t: translate, println: (line) => lines.push(line) }, { blockNum: 8, data: {} });
  const text = lines.join('\n');
  const positive = translate('conclusion.results', { block: 8 });
  if (fatal && !complete) {
    ok(!text.includes(positive), `${lang} R4-3: 日時が欠けた請求の断定を出さない`);
    ok(text.includes(translate('notVerified.results', { reason: translate('reason.stopped') })), `${lang}: 期間未到達を表示`);
  } else ok(text.includes(positive), `${lang}: 中断なし/期間完了なら既存の結論を保持`);
  for (const area of ['entries', 'selection', 'grouping']) {
    eq(verificationCoverage(report).find((row) => row.area === area).verified, true, '中断前の完了行は保持');
  }
}

// N4-a: 例外だけでは配線不正としない。読めて食い違う場合はFAILを保持。
for (const lang of SUPPORTED_LANGS) for (const state of ['error', 'match', 'mismatch']) {
  let reads = 0; const lines = [];
  const ctx = { blockNum: 8, report: createReport(), cfg: { contracts: { hashStorage: address } }, data: {},
    chain: { hashStorageAddress: async () => { reads++; if (state === 'error') throw new Error('temporary RPC failure'); return state === 'match' ? address : other; } },
    ui: { t: t(lang), section() {}, println: (line) => lines.push(line), askYesNo: async () => true },
    r2: { baseDir: '/empty-fixture', fetchJson: async (key, opts) => {
      assert.equal(opts.cacheOnly, key.endsWith('/01_info.json') && !ctx.data.infos ? false : true);
      return { data: { entries: [] } };
    } } };
  const found = await membership.verifyOwnEntry(ctx, '123', null);
  eq(reads, 1, 'N4-a: 今のgetterを1回読む');
  eq(found.verified, state === 'match', '配線を確かめた場合だけオンチェーンで確認済み');
  if (state === 'error') {
    eq(ctx.report.get('check.system.hashStorageWiring'), null, 'N4-a: 読めないだけでは配線不正を記録しない');
    eq(ctx.report.get('check.system.auditUnavailable').status, 'warn', 'メニュー1と同じ読取不能の項目でWARN');
    eq(lines.at(-1), ctx.ui.t('entry.verifyFailed'), `${lang}: 読取不能は検証失敗の結論`);
  }
  if (state !== 'error') eq(ctx.report.get('check.system.hashStorageWiring').status, state === 'match' ? 'pass' : 'fail', '一致/不一致の記録を保持');
  eq(lines.at(-1), ctx.ui.t(state === 'match' ? 'entry.onchainAbsent' : 'entry.verifyFailed'), `${lang}: 配線を確認できた場合だけ断定`);
}

// 終了コードは計算式の写しでなく、対話メニュー3の実mainを通して検査する。
globalThis.__fix6Menu = { membership };
const menu = await load('../src/index.js', (source) => source
  .replace("import { createPrompts } from './prompts.js';", 'const createPrompts = () => globalThis.__fix6Menu.prompts;')
  .replace("import { createLocalR2, createR2 } from './r2.js';", 'const createR2 = () => globalThis.__fix6Menu.r2;')
  .replace("import { parseEntryUid, runEntriesReusable, runSelectionReusable, verifyOwnEntry } from './entry-membership.js';",
    'const { parseEntryUid, runEntriesReusable, runSelectionReusable, verifyOwnEntry } = globalThis.__fix6Menu.membership;')
  .replace('const cfg = loadConfig(argv);', 'const cfg = globalThis.__fix6Menu.cfg;')
  .replace('const chain = await setupChain(cfg, ui, prompts);', 'const chain = globalThis.__fix6Menu.chain;'));
for (const state of ['error', 'match', 'mismatch']) {
  const lines = []; let closed = false, reads = 0, answers = 0;
  globalThis.__fix6Menu = { membership,
    cfg: { lang: 'ja', flags: { lang: 'ja', block: null }, blockNum: null, nonInteractive: false,
      contracts: { hashStorage: address }, emergencyAuthority: null,
      emergencyApplicantRegistration: null, emergencyApplicantRoot: null },
    prompts: { choice: async () => 2, text: async () => '123', number: async () => 8,
      yesNo: async () => ++answers === 1, close: () => { closed = true; } },
    chain: { evidenceAddress: async () => address, getCode: async () => '0x6000',
      applicantRegistrationCount: async () => 0, getApplicantHash: async () => ({ hash: root }),
      getTimingConstants: async () => timing,
      hashStorageAddress: async () => { reads++; if (state === 'error') throw new Error('temporary RPC failure'); return state === 'match' ? address : other; } },
    r2: { baseDir: '/empty-fixture', setDefaultReuse() {}, fetchJson: async () => ({ data: { entries: [] } }) },
  };
  const write = process.stdout.write, previousExit = process.exitCode;
  let code;
  try {
    process.stdout.write = (value) => { lines.push(String(value)); return true; };
    await menu.main(); code = process.exitCode;
  } finally { process.stdout.write = write; process.exitCode = previousExit; }
  eq(code, state === 'error' ? 1 : state === 'match' ? 0 : 2, 'N4-a 実メニュー3: 例外partial/一致full/不一致fail');
  eq(reads, 1, 'N4-a 実メニュー3: getterを1回読む');
  eq(closed, true, '対話を閉じて終了');
  ok(lines.join('').includes(t('ja')(state === 'match' ? 'entry.onchainAbsent' : 'entry.verifyFailed')), '実メニュー3の結論の表示');
}
delete globalThis.__fix6Menu;

// 追加した読める正常系も、固定起点の実関数と全レコードを比べる。
const base = await load('../src/stages/results.js', undefined,
  execFileSync('git', ['show', `${BASE}:block-verifier/src/stages/results.js`], { encoding: 'utf8' }));
for (const fn of ['verifyTimeline', 'verifyTimelineNoGameFinality']) {
  const records = [];
  for (const mod of [base, results]) {
    const { ctx, S } = fn === 'verifyTimeline' ? timeline({ readable: true }) : noGame({ readable: true, safeNumber: closeHeight });
    await mod[fn](ctx, S, timing);
    records.push({ checks: ctx.report.list(), exit: exit(ctx) });
  }
  eq(records[1], records[0], `${fn}: 追加した正常系も固定起点と全状態・params・終了が同じ`);
}
if (!mutation) for (const name of ['claim_relation', 'mode', 'end_bounds', 'singleton', 'declared_height', 'finality_summary', 'fatal_timeline', 'getter_failure']) {
  const child = spawnSync(process.execPath, [new URL(import.meta.url).pathname, `--mutation=${name}`], { encoding: 'utf8', timeout: 30000, maxBuffer: 10 * 1024 * 1024 });
  eq(child.stdout.includes(`MUTATION_APPLIED ${name}`), true, `${name}: 適用済み`);
  eq(child.status, 1, `${name}: 変異で赤`);
  ok(child.stderr.includes('AssertionError'), `${name}: 起動失敗ではなくassertionで検出`);
  const label = { claim_relation: 'L-1 claim', mode: 'L-1 mode', end_bounds: 'L-1 end_low', singleton: 'R4-1: singleton',
    declared_height: 'R4-2', finality_summary: 'R4-2', fatal_timeline: 'R4-3', getter_failure: 'N4-a' }[name];
  ok(child.stderr.includes(label), `${name}: 指摘に対応する歯で検出`);
}
console.log(`fix6-verifier-unit: PASS (${assertions} assertions; 8 mutants killed)`);

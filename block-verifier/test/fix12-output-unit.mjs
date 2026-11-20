// FIX12: 表示だけを削減し、検査材料・未検証の領域・機械行を保持する。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { t, SUPPORTED_LANGS } from '../src/i18n.js';
import { CHECK_INVENTORY } from '../src/check-inventory.js';
import { VERIFICATION_AREAS } from '../src/verification-areas.js';
import { ArchiveUnavailableError } from '../src/archive.js';
import { emitNonInteractiveOutcome } from '../src/index.js';
import { GameMasterDO } from '../vendor/workers/game_workers/game-master-DO.js';
import { selectWinners } from '../vendor/workers/lottery_workers/select-winners.js';

const mutation = process.argv.find((arg) => arg.startsWith('--mutation='))?.split('=')[1];
let applied = false, assertions = 0;
const eq = (a, b, label) => { assert.deepEqual(a, b, label); assertions++; };
const ok = (a, label) => { assert.ok(a, label); assertions++; };
async function load(file, edit = (source) => source, extra = '') {
  const url = new URL(file, import.meta.url);
  const source = edit(readFileSync(url, 'utf8')).replace(/from '([^']+)'/g,
    (_, path) => `from '${path.startsWith('.') ? new URL(path, url).href : import.meta.resolve(path)}'`);
  const href = `data:text/javascript;base64,${Buffer.from(source + extra).toString('base64')}`;
  return { href, module: await import(href) };
}
function replace(source, before, after) {
  assert.ok(source.includes(before), '変異対象が存在する');
  applied = true;
  return source.replace(before, after);
}
const logging = await load('../src/vendor-logging.js', (source) => mutation === 'vendor_logs'
  ? replace(source, 'if (process.env.DEBUG === undefined) return;', 'if (false) return;') : source);
const { withVendorLogging } = logging.module;
const { module: reports } = await load('../src/report.js', (source) => {
  if (mutation === 'skip_section') return replace(source, "    // --- Stage C が翻訳済み文字列として蓄積したアノマリー ---",
    "    ui.println(t('summary.skipsHeader'));\n    // --- Stage C が翻訳済み文字列として蓄積したアノマリー ---");
  if (mutation === 'all_warns') return replace(source,
    "e.status === 'warn' && e.reason !== 'archive_unavailable'", "e.status === 'warn' && false");
  return source;
});
const { createReport, verificationCoverage } = reports;
const { module: results } = await load('../src/stages/results.js', (source) => source.replace(
  "from '../vendor-logging.js'", `from '${logging.href}'`), '\nexport { runAutoWithAvailableState };');
const { module: selection } = await load('../src/stages/selection.js', (source) => source.replace(
  "from '../vendor-logging.js'", `from '${logging.href}'`));
if (mutation) { ok(applied, '変異を実際に適用'); console.log(`MUTATION_APPLIED ${mutation}`); }

async function capture(run) {
  const methods = ['log', 'error', 'warn'], before = methods.map((method) => console[method]), logs = [];
  for (const method of methods) console[method] = (...args) => logs.push([method, ...args.map(String)]);
  const installed = methods.map((method) => console[method]);
  try {
    const value = await run();
    eq(methods.map((method) => console[method]), installed, 'console を必ず元に戻す');
    return { value, logs };
  } finally { for (const [index, method] of methods.entries()) console[method] = before[index]; }
}
function render(report, lang) {
  const lines = [];
  report.renderSummary({ t: t(lang), println: (line = '') => lines.push(String(line)) }, { blockNum: 8, data: {} });
  return lines.join('\n');
}
function complete(omit) {
  const report = createReport();
  for (const id of CHECK_INVENTORY) if (id !== omit) report.check(id, 'pass');
  report.fact('system.audit', { adminHistoryChecked: true });
  return report;
}
function compact(output, lang, count) {
  const translate = t(lang);
  for (const text of [translate('summary.skipsHeader'), translate('summary.unrunHeader', { count }),
    translate('summary.skipsNotice', { count: 1 })]) ok(!output.includes(text), `${lang}: 削除した節・案内文が無い`);
  ok(!output.includes('  ⊘ ') && !output.includes('  ◌ '), `${lang}: SKIP・未到達を列挙しない`);
}
function unverifiedRow(report, lang, area) {
  const row = verificationCoverage(report).find((row) => row.area === area);
  eq(row.verified, false, `${lang}/${area}: 未確認の必須検査を合格にしない`);
  const translate = t(lang), output = render(report, lang);
  const prefix = `  ${translate(`summary.area.${area}`)}: `;
  const unverified = output.slice(output.indexOf(translate('summary.coverageUnverified')));
  ok(unverified.includes(prefix + translate('summary.areaUnverified', { reason: translate(`reason.${row.reason}`) })),
    `${lang}/${area}: 必ず「検証できなかったこと」に残る`);
  ok(!output.slice(output.indexOf(translate('summary.coverageVerified')), output.indexOf(translate('summary.coverageUnverified'))).includes(prefix), `${lang}/${area}: 検証済みと誤表示しない`);
}

const savedDebug = process.env.DEBUG;
try {
  delete process.env.DEBUG;
  // 本物の正典関数の全抽選枝。DEBUG 時との戻り値も一致する。
  for (const [total, count] of [[0, 0], [2, 2], [10, 3], [10, 8]]) {
    const quiet = await capture(() => withVendorLogging(() => selectWinners('ab'.repeat(32), total, count)));
    eq(quiet.logs, [], '通常時は vendor の抽選ログを表示しない');
    process.env.DEBUG = '1';
    const debug = await capture(() => withVendorLogging(() => selectWinners('ab'.repeat(32), total, count)));
    ok(debug.logs.some((line) => line[1].startsWith('Selecting winners:')), 'DEBUG=1 では正典ログが出る');
    eq(debug.value, quiet.value, 'ログの有無で抽選結果を変えない');
    delete process.env.DEBUG;
  }
  const asyncLogs = await capture(async () => {
    const error = new Error('same exception'), collected = [];
    eq(withVendorLogging(() => 17), 17, '同期の戻り値を保持');
    assert.throws(() => withVendorLogging(() => { console.warn('vendor warn'); throw error; }), (e) => e === error); assertions++;
    await assert.rejects(withVendorLogging(async () => { console.error('vendor error'); throw error; },
      { onError: (...args) => collected.push(args) }), (e) => e === error); assertions++;
    eq(collected, [['vendor error']], 'writer のエラー回収を保持');
    let finish;
    const gate = new Promise((resolve) => { finish = resolve; });
    const pending = withVendorLogging(async () => { await gate; console.error('async vendor'); });
    console.log('verifier progress');
    await withVendorLogging(async () => { console.warn('nested vendor'); await withVendorLogging(async () => console.log('inner vendor')); });
    finish(); await pending;
    console.warn('verifier warning');
  });
  eq(asyncLogs.logs, [['log', 'verifier progress'], ['warn', 'verifier warning']], '非同期・入れ子でもツール自身の出力を保持');
  process.env.DEBUG = '';
  const emptyDebug = await capture(() => withVendorLogging(() => { console.warn('warn'); console.error('error'); }));
  eq(emptyDebug.logs, [['warn', 'warn'], ['error', 'error']], 'DEBUG は空値でも存在すれば有効');
  delete process.env.DEBUG;

  const address = '0x' + '11'.repeat(20);
  const dep = { id: '1', idFrom: '1', amount: '1000000000000000000', depositerAddress: address, unlockTime: 2000000 };
  const player = { globalIndex: 0, data: { uid: '1', addr: address, lang: 'ja',
    depIds: JSON.stringify({ deposit: dep.amount, ids: ['1'], deposits: [dep] }) } };
  function auto(lang, denied, summary = {}) {
    const gm = new GameMasterDO({ storage: {} }, { START_TIME: '1000000', BLOCK_TIME: '1000', ETH_LOCK_CONTRACT_ADDRESS: address });
    gm.readDepositSelectionK11 = async () => 100n;
    gm.createReadOnlyClient = () => ({ readContract: async () => {
      if (denied) throw new ArchiveUnavailableError();
      return { ...dep, idTo: '1', lockOwnerAddress: address, unlocked: false };
    } });
    const ctx = { blockNum: 8, report: createReport(), cfg: { lang }, chain: {}, data: { gameSelection: { players: [player] } },
      ui: { t: t(lang), println() {}, warn() {} } };
    return { gm, ctx, S: { files: { summary: { data: summary } }, anomalies: [] } };
  }
  for (const lang of SUPPORTED_LANGS) {
    const hash = '0x' + 'ab'.repeat(32), selectionLines = [];
    const selectionCtx = { blockNum: 8, report: createReport(), cfg: { pins: { confirmationBlocks: 64, gameMaxPlayers: 2100 } },
      data: { applicantHash: hash, registeredBlock: 1, entriesTotal: 0, entryPeriodEnd: 1000 },
      ui: { t: t(lang), println: (line) => selectionLines.push(line) },
      chain: { getBlock: async () => ({ hash, mixHash: hash, timestamp: 2n }) },
      r2: { fetchJson: async () => ({ data: { hashRegisteredBlock: 1, confirmationBlocks: 64, targetBlockNum: 65,
        targetBlockHash: hash, randao: hash, applicantHash: hash, totalEntries: 0, totalSelected: 0, players: [], entryPeriodEnd: 1000 } }) } };
    eq((await capture(() => selection.run(selectionCtx))).logs, [], `${lang}: Stage B の正典ログを抑制`);
    ok(selectionLines.includes(t(lang)('stageB.runningLottery', { total: 0, count: 0 })), 'ツール自身の抽選進捗行を保持');
    const summary = { groups: [{ group_id: 0, members: [{ userId: '1', btcu_reward: '0' }, { userId: '2', btcu_reward: '0' }] }] };
    const merkleGm = new GameMasterDO({ storage: {} }, {}), tree = merkleGm.buildMerkleTree(8, []);
    function merkle() {
      return { ctx: { blockNum: 8, data: {}, report: createReport(), ui: { t: t(lang) }, cfg: { pins: { claimDataFormat: 'test-pin' } } },
        S: { files: { summary: { data: summary }, merkle: { data: tree } }, blockState: { root: tree.root }, rebuiltSummary: summary, anomalies: [] } };
    }
    const merkleState = merkle();
    eq((await capture(() => results.verifyMerkle(merkleState.ctx, merkleState.S, merkleGm))).logs, [], `${lang}: Merkle の除外ログを2回とも抑制`);
    process.env.DEBUG = '1';
    const debugMerkleState = merkle();
    const debugMerkle = await capture(() => results.verifyMerkle(debugMerkleState.ctx, debugMerkleState.S, merkleGm));
    eq(debugMerkle.logs.filter((line) => line[1] === '[merkle] block 8: excluded 2 player(s) (zero reward / invalid address)').length, 2, 'DEBUG で同じ Merkle 除外ログが2回出る');
    eq(debugMerkleState.ctx.report.list(), merkleState.ctx.report.list(), 'Merkle の検査と params を保持');
    delete process.env.DEBUG;
    const seed = auto(lang, false);
    eq((await capture(() => results.runAutoWithAvailableState(seed.ctx, seed.S, seed.gm, {}))).logs, [], `${lang}: 読めるノードの自動配布ログを抑制`);
    for (const denied of [false, true]) {
      const state = auto(lang, denied, seed.S.rebuiltSummary);
      const captured = await capture(() => results.runAutoWithAvailableState(state.ctx, state.S, state.gm, {}));
      eq(captured.logs, [], `${lang}/${denied}: B1 のログを抑制`);
      eq(captured.value, true, `${lang}: 自動配布の計算を継続`);
      eq(state.ctx.report.get('check.stageC.summaryMatch').status, denied ? 'skip' : 'pass', '読める検査・型付き失敗の状態を維持');
      compact(render(state.ctx.report, lang), lang, CHECK_INVENTORY.length - state.ctx.report.list().length);
      if (denied) unverifiedRow(state.ctx.report, lang, 'scoring');
      process.env.DEBUG = '1';
      const debugState = auto(lang, denied, seed.S.rebuiltSummary);
      const debug = await capture(() => results.runAutoWithAvailableState(debugState.ctx, debugState.S, debugState.gm, {}));
      ok(debug.logs.some((line) => line[1].startsWith('[B1]')), `${lang}/${denied}: DEBUG で B1 ログが復活`);
      eq(debugState.ctx.report.list(), state.ctx.report.list(), 'DEBUG で検査と params を変えない');
      delete process.env.DEBUG;
    }
    const report = complete();
    for (const id of ['fact.system.adminRotationUnavailable', 'fact.system.donateEventUnavailable']) {
      report.unverified(id, new ArchiveUnavailableError(), { error: 'typed-only-error' }, { status: 'warn' });
    }
    report.unverified('check.stageC.depositVerification', new ArchiveUnavailableError(), { secretDetail: 'skip-only-detail' });
    const before = structuredClone(report.list()), translate = t(lang);
    const hidden = render(report, lang);
    compact(hidden, lang, 0);
    ok(!hidden.includes(translate('summary.warnsHeader')) && !hidden.includes('typed-only-error') && !hidden.includes('skip-only-detail'), '型付き WARN しか無ければ節と params を出さない');
    unverifiedRow(report, lang, 'adminHistory'); unverifiedRow(report, lang, 'locks');
    eq(report.list(), before, '描画で検査・params・型付き理由を変えない');
    const visibleWarnings = [
      ['fact.system.adminRotation', { authorities: 'actual admin change' }],
      ['fact.system.pendingSuperAdmin', { proposals: 'pending proposal' }],
      ['fact.system.adminRotationUnavailable', { error: 'temporary RPC failure' }],
      ['fact.system.donateEventUnavailable', { error: 'archive_unavailable' }],
    ];
    for (const [id, params] of visibleWarnings) report.check(id, 'warn', params);
    report.check('check.stageC.onchainClaimData', 'fail', { error: 'independent mismatch', expected: 'kept' });
    const records = structuredClone(report.list()), machine = [];
    const emitted = emitNonInteractiveOutcome({ println: (line) => machine.push(line) }, { report, fatal: false, stopped: false }, null);
    const visible = render(report, lang);
    ok(visible.includes(translate('summary.warnsHeader')), `${lang}: 通知すべき WARN の節を保持`);
    for (const [id, params] of visibleWarnings) {
      const shown = reports.displayParams(params, translate);
      ok(visible.includes(translate(id, shown)) && visible.includes(JSON.stringify(shown)), `${lang}/${id}: 型付きでない WARN と params を保持`);
    }
    ok(visible.includes(translate('summary.failsHeader')) && visible.includes('{"error":"independent mismatch","expected":"kept"}'), `${lang}: FAIL の節・params を保持`);
    ok(visible.includes(translate('summary.counts', { pass: CHECK_INVENTORY.length - 2, fail: 1, skip: 1, warn: 4, unrun: 0 })), `${lang}: 非表示分も含めた件数を保持`);
    eq(report.list(), records, 'まとめを表示しても全レコードを保持');
    eq(emitted.exitCode, 2, '独立 FAIL の exit 2 を保持');
    eq(machine, [...records.map((entry) => `##CHECK ${entry.id} ${entry.status}`), '##RESULT fail'], '機械行を全件保持');
    for (const area of VERIFICATION_AREAS.filter((area) => area.required.length)) {
      for (const status of ['skip', 'unrun']) {
        const id = area.required[0], sparse = complete(status === 'unrun' ? id : undefined);
        if (status === 'skip') sparse.check(id, 'skip', { reason: 'unreadable' });
        unverifiedRow(sparse, lang, area.area);
      }
    }
  }
} finally {
  if (savedDebug === undefined) delete process.env.DEBUG; else process.env.DEBUG = savedDebug;
}
if (!mutation) for (const name of ['vendor_logs', 'skip_section', 'all_warns']) {
  const result = spawnSync(process.execPath, [import.meta.filename, '--mutation=' + name], { encoding: 'utf8', env: process.env });
  eq(result.status, 1, `${name}: 変異で赤`);
  ok(result.stdout.includes(`MUTATION_APPLIED ${name}`) && result.stderr.includes('AssertionError'), `${name}: 変異を assertion で検出`);
}
console.log(`fix12-output-unit: PASS (${assertions} assertions; 3 mutants killed)`);

// R14-01 / R14-02: SKIP は領域の未検証表示に残し、読取失敗を PASS に偽装しない。
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { createReport } from '../src/report.js';
import { SUPPORTED_LANGS, t } from '../src/i18n.js';
import { checkResultReregistration } from '../src/stages/results.js';
import {
  collectBlockEpochs,
  runZkpMode,
  ZKP_BLOCK_READ_CONCURRENCY,
} from '../src/zkp.js';

const here = dirname(fileURLToPath(import.meta.url));
let passed = 0;
let failed = 0;
const ok = (label, condition, detail = '') => {
  if (condition) { passed++; console.log(`  ok: ${label}`); }
  else { failed++; console.error(`  NG: ${label}${detail ? ` — ${detail}` : ''}`); }
};
const eq = (label, actual, expected) =>
  ok(label, actual === expected, `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);

console.log('R14 skip visibility / unreadable registration tests');

for (const lang of SUPPORTED_LANGS) {
  const report = createReport();
  report.check('check.stageC.resultReregistration', 'skip', { reason: 'unreadable' });
  const lines = [];
  const translate = t(lang);
  report.renderSummary({ t: translate, println: (line = '') => lines.push(String(line)) }, {
    blockNum: 14,
    data: {},
    r2: { baseDir: '/tmp/r14-poc' },
  });
  const output = lines.join('\n');
  ok(`${lang}: SKIP の詳細節を表示しない`, !output.includes(translate('summary.skipsHeader')));
  ok(`${lang}: SKIP の個別行・params を表示しない`,
    !output.includes('check.stageC.resultReregistration') && !output.includes('unreadable'));
  ok(`${lang}: 最終結論付近の未実施件数を表示しない`,
    !output.includes(translate('summary.skipsNotice', { count: 1 })));
  const timelineRow = `  ${translate('summary.area.timeline')}: `;
  ok(`${lang}: SKIP のある期間の領域は必ず未検証に残る`,
    output.includes(timelineRow + translate('summary.areaUnverified', { reason: translate('reason.stopped') }))
      && !output.slice(output.indexOf(translate('summary.coverageVerified')), output.indexOf(translate('summary.coverageUnverified'))).includes(timelineRow));
  eq(`${lang}: SKIP の元の params を保存`, report.get('check.stageC.resultReregistration').params.reason, 'unreadable');
  eq(`${lang}: skip だけで hasFail にならない`, report.hasFail(), false);
}

// categorize / EXIT_CODE_OF は変更禁止なので、index.js の実装そのものを抽出して実行する。
const indexSource = readFileSync(resolve(here, '../src/index.js'), 'utf8');
const resultsSource = readFileSync(resolve(here, '../src/stages/results.js'), 'utf8');
const categorizeSource = indexSource.match(/function categorize\(outcome\) \{[\s\S]*?\n\}/)?.[0];
const exitCodesSource = indexSource.match(/const EXIT_CODE_OF = (\{[^;]+\});/)?.[1];
ok('categorize の実装を index.js から抽出できる', Boolean(categorizeSource));
ok('EXIT_CODE_OF の実装を index.js から抽出できる', Boolean(exitCodesSource));
if (categorizeSource && exitCodesSource) {
  const live = Function(`"use strict"; ${categorizeSource}; return { categorize, EXIT_CODE_OF: ${exitCodesSource} };`)();
  const report = createReport();
  report.check('check.stageC.resultReregistration', 'skip', { reason: 'unreadable' });
  const category = live.categorize({ fatal: false, stopped: false, report });
  eq('skip だけの ##RESULT は full のまま', `##RESULT ${category}`, '##RESULT full');
  eq('skip だけの exit code は 0 のまま', live.EXIT_CODE_OF[category], 0);
}

ok('groupIds の空判定は配列用 .length', !resultsSource.includes('S.groupIds.size === 0'));
ok(':2476 対応の no-game 条件を全て固定',
  resultsSource.includes('S.groupIds.length === 0 || S.auto || S.noGame || S.files.summary?.data?.noGame === true || S.timelineNoGame'));

const unreadableReport = createReport();
await checkResultReregistration({
  blockNum: 14,
  report: unreadableReport,
  ui: { t: t('ja') },
  chain: { resultRegistrationCount: async () => { throw new Error('RPC unavailable'); } },
}, { anomalies: [] });
const unreadable = unreadableReport.get('check.stageC.resultReregistration');
eq('再登録回数の読取失敗は skip', unreadable?.status, 'skip');
eq('再登録回数の読取失敗理由は unreadable', unreadable?.params?.reason, 'unreadable');
ok('再登録回数の読取失敗を pass にしない', unreadable?.status !== 'pass');

// A6-02: cold-proof fixture不在で基準赤の zkp-unit.mjs とは別の緑ターゲットで、
// BV-SCALE-03 の取得不能分離・非0終了・有界並列を固定する。
const unavailableMap = await collectBlockEpochs({
  blockStates: async (n) => {
    if (n === 1) throw new Error('RPC rate limited');
    if (n === 2) return { root: '0xaa', zkEpochPlusOne: undefined };
    return { root: '0x' + '0'.repeat(64), zkEpochPlusOne: 0 };
  },
}, 2);
ok('BV-SCALE-03 RPC不能と不完全stateをunavailableへ分離',
  JSON.stringify(unavailableMap.unavailable.map(({ blockNum }) => blockNum)) === '[1,2]');
eq('BV-SCALE-03 未確認blockをshadowへ混ぜない', unavailableMap.get(-1), undefined);

const scanWarnings = [];
const incompleteScanExit = await runZkpMode(
  { zkScanMaxBlock: 1 },
  {
    vkeyEpochs: async () => [],
    pendingVkeyProposal: async () => ({ pending: false }),
    proofRequired: async () => false,
    blockStates: async (n) => {
      if (n === 1) throw new Error('RPC rate limited');
      return { root: '0x' + '0'.repeat(64), zkEpochPlusOne: 0 };
    },
  },
  { println() {}, warn: (message) => scanWarnings.push(message), t: (key) => key },
  { isInteractive: false },
);
eq('BV-SCALE-03 走査取得不能は成功exit 0にしない', incompleteScanExit, 1);
ok('BV-SCALE-03 取得不能を専用警告で表示',
  JSON.stringify(scanWarnings) === '["zk.blockScanUnavailable"]');

let activeBlockReads = 0;
let peakBlockReads = 0;
let totalBlockReads = 0;
const scaleMap = await collectBlockEpochs({
  blockStates: async () => {
    totalBlockReads++;
    activeBlockReads++;
    peakBlockReads = Math.max(peakBlockReads, activeBlockReads);
    await new Promise((resolveImmediate) => setImmediate(resolveImmediate));
    activeBlockReads--;
    return { root: '0x' + '0'.repeat(64), zkEpochPlusOne: 0 };
  },
}, 363);
eq('BV-SCALE-03 本番364 blockを欠落なく走査', totalBlockReads, 364);
eq('BV-SCALE-03 blockStates読取を有界並列unitへ分割',
  peakBlockReads, ZKP_BLOCK_READ_CONCURRENCY);
eq('BV-SCALE-03 root未提出を全件分離', scaleMap.unsubmitted.length, 364);

// D4-05: zkp-unit自体はfixture不在を示す基準赤。その赤を直接「成功」にせず、
// 別の緑テストから未処理ENOENTではないことと前段集計の可視性だけを固定する。
const zkpUnit = spawnSync(process.execPath, [resolve(here, 'zkp-unit.mjs')], {
  cwd: resolve(here, '../..'),
  env: process.env,
  encoding: 'utf8',
});
const zkpUnitOutput = `${zkpUnit.stdout || ''}${zkpUnit.stderr || ''}`;
eq('D4-05 zkp-unitはfixture不在を基準赤として返す', zkpUnit.status, 1);
// `zkp-unit.mjs` へ歯を足したら、この passed 件数も同時に直す。
// 2026-09-27 便 C30F1c（C31-11）: fixture に依存しない証明付き Stage C 経路の歯10本と、
//   fixture の後段から前へ移した1本で前段は 107→118。後段は 34（合成 fixture で実測）。WR-15-FIX4 で配線の命令の盤へ写し、123。
ok('D4-05 前段assertの最終集計を表示する', /\b123 passed \/ 1 failed\b/.test(zkpUnitOutput));
ok('D4-05 fixture依存34本を明示skipする',
  zkpUnitOutput.includes('SKIP fixture依存の後段34 assertions'));
ok('D4-05 未処理ENOENT stackへ退行しない',
  !zkpUnitOutput.includes('Error: ENOENT') && !zkpUnitOutput.includes('node:fs:'));

console.log('');
if (failed > 0) { console.error(`❌ ${failed} FAILED (${passed} passed)`); process.exit(1); }
console.log(`✅ ALL PASSED (${passed} checks)`);

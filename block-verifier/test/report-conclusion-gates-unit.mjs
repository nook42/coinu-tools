// P10: 個別検査の FAIL を無視して、下流の最終結論が「一致」と断定しないことを全 ID で固定する。
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { SUPPORTED_LANGS, t } from '../src/i18n.js';
import { CHECK_INVENTORY } from '../src/check-inventory.js';
import { emitNonInteractiveOutcome } from '../src/index.js';
import { createReport } from '../src/report.js';

let failed = 0;
const assert = (condition, label) => {
  if (condition) return;
  console.error(`NG: ${label}`);
  failed++;
};

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = join(here, '..', 'src');

function discoverCheckIds() {
  const files = [];
  const visit = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const file = join(dir, entry.name);
      if (entry.isDirectory()) visit(file);
      else if (entry.isFile() && entry.name.endsWith('.js')) files.push(file);
    }
  };
  visit(srcDir);
  files.sort();

  const ids = new Set();
  const dynamicCalls = [];
  for (const file of files) {
    const source = readFileSync(file, 'utf8');
    for (const match of source.matchAll(/report\.check\(\s*([^,\r\n)]+)/g)) {
      const firstArg = match[1].trim();
      if (!firstArg.startsWith("'") && !firstArg.startsWith('"')) {
        dynamicCalls.push(`${file}:${firstArg}`);
      }
    }
    for (const match of source.matchAll(/report\.check\(\s*['"](check\.[A-Za-z0-9_.]+)['"]/g)) {
      ids.add(match[1]);
    }
    // index.js の system wiring 10項目は配列から動的な id として report.check() へ渡される
    // （便 C30F1 が check.system.evidenceHashStorage を足して 8 → 9・便 C30F1b。
    //   便 C32F2 が check.system.evidenceStartPastTolerance を足して 9 → 10）。
    if (file === join(srcDir, 'index.js')) {
      for (const match of source.matchAll(/\[\s*['"](check\.system\.[A-Za-z0-9_.]+)['"]\s*,/g)) {
        ids.add(match[1]);
      }
    }
  }
  return { ids: [...ids].sort(), dynamicCalls };
}

const discovery = discoverCheckIds();
const checkIds = discovery.ids;
assert(
  discovery.dynamicCalls.length === 3
    && discovery.dynamicCalls.some((s) => s.endsWith('/src/index.js:id'))
    && discovery.dynamicCalls.some((s) => s.endsWith('/src/entry-membership.js:e.id'))
    && discovery.dynamicCalls.some((s) => s.endsWith('/src/entry-membership.js:id')),
  // OWNENTRY-FLOW2のidは、selection.jsが記録する既存の検査をそのまま元reportへ転送する。
  // 静的な検査ID数・在庫一致・全FAIL時の結論検査は変えず、転送1か所だけを許可する。
  `動的 report.check 呼出はsystem wiring・検証済みStage Aの再利用・メニュー3の抽選記録の転送だけ: ${discovery.dynamicCalls.join(', ')}`,
);
const expectedCounts = new Map([
  ['check.main.', 1],
  ['check.stageA.', 9],
  ['check.stageB.', 23],
  // 2026-10-24 配線の WR-15: check.stageC.futureAnchorsHash・check.stageC.evidenceSegmentBoundaries で 63 → 65。
  // SUMMARY-ZKP-FIX1: verifier照合で65 → 66。
  ['check.stageC.', 66],
  // 便 C30F1b: 便 C30F1 の check.system.evidenceHashStorage（Evidence.HASH_STORAGE の配線）で 10 → 11。
  // 便 C32F2: check.system.evidenceStartPastTolerance（Evidence.START_PAST_TOLERANCE の方針照合）で 11 → 12。
  // 2026-10-24 配線の WR-15: check.system.futureAnchorProvider で 15 → 16。
  ['check.system.', 16],
]);

for (const id of checkIds) {
  assert(
    [...expectedCounts.keys()].some((prefix) => id.startsWith(prefix)),
    `未知の検査 ID 系統は結論への参加方法を決める: ${id}`,
  );
}
for (const [prefix, expected] of expectedCounts) {
  const actual = checkIds.filter((id) => id.startsWith(prefix)).length;
  assert(actual === expected, `${prefix} の全 ID 数: expected=${expected}, actual=${actual}`);
}
// 2026-09-28 Stage 3 再レビュー周1 段0（C32 の合流）: main の便 S3C14（check.stageA.entryKeyIntegrity）と C32F2（check.system.evidenceStartPastTolerance）の両方の +1 で 105。
// 2026-10-24 配線の WR-15: Stage C 2件・system 1件で 111 → 114。
// SUMMARY-ZKP-FIX1: verifier照合で114 → 115。
assert(checkIds.length === 115, `check.* の全 ID 数: expected=115, actual=${checkIds.length}`);
assert(
  JSON.stringify(checkIds) === JSON.stringify([...CHECK_INVENTORY].sort()),
  '実装から発見した全check IDと実行時在庫が完全一致する',
);

function makeReport(failedId = null) {
  const report = createReport();
  for (const id of checkIds) report.check(id, 'pass');
  report.check('check.stageA.registrationCount', 'pass', { count: 1 });
  if (failedId) report.check(failedId, 'fail', { injected: failedId });

  report.fact('hashRegisteredTime', '2026-09-04T00:00:00.000Z');
  report.fact('totalEntries', 4);
  report.fact('applicantHash', '0xabc');
  report.fact('hashRegisteredBlock', 100);
  report.fact('totalSelected', 4);
  report.fact('targetBlockNum', 123);
  report.fact('targetBlockTime', '2026-09-05T00:00:00.000Z');
  report.fact('totalGroups', 1);
  report.fact('stageC.blockReward', '1000000000000000000');
  report.fact('stageC.playerCount', 4);
  report.fact('stageC.groupCount', 1);
  report.fact('stageC.disqualifiedCount', 0);
  report.fact('stageC.verificationStartedAt', { iso: '2026-09-05T01:00:00.000Z' });
  report.fact('stageC.verificationEndsAt', { iso: '2026-09-09T01:00:00.000Z' });
  report.fact('stageC.claimWindow', { endIso: '2026-10-19T01:00:00.000Z' });
  return report;
}

const ctx = { blockNum: 7, data: {}, r2: { baseDir: '/tmp/block7' } };
const warningOnlyIds = [
  'check.stageC.rosterReregistration',
  'check.stageC.evidenceContradictsGrouping',
];

function render(report, translate) {
  const lines = [];
  report.renderSummary({ t: translate, println: (line) => lines.push(String(line)) }, ctx);
  return lines.join('\n');
}

function conclusionTexts(translate) {
  return {
    A: translate('conclusion.entries', {
      block: 7,
      time: '2026-09-04T00:00:00.000Z',
      total: 4,
      hash: '0xabc',
      ethBlock: 100,
      folder: '/tmp/block7',
    }),
    B: translate('conclusion.selection', {
      block: 7,
      selected: 4,
      total: 4,
      targetBlock: 123,
      time: '2026-09-05T00:00:00.000Z',
      groups: 1,
      count: 1,
    }),
    C: translate('conclusion.results', {
      block: 7,
      reward: '1.00',
      players: 4,
      groups: 1,
      dq: 0,
      rootTime: '2026-09-05T01:00:00.000Z',
      verEnd: '2026-09-09T01:00:00.000Z',
      claimEnd: '2026-10-19T01:00:00.000Z',
    }),
  };
}

for (const lang of SUPPORTED_LANGS) {
  const translate = t(lang);
  const conclusions = conclusionTexts(translate);
  const honestOutput = render(makeReport(), translate);
  for (const stage of ['A', 'B', 'C']) {
    assert(honestOutput.includes(conclusions[stage]), `${lang}: 全105検査PASSなら結論${stage}を維持する`);
  }

  for (const id of warningOnlyIds) {
    const warningReport = makeReport();
    warningReport.check(id, 'warn', { injected: id });
    const output = render(warningReport, translate);
    for (const stage of ['A', 'B', 'C']) {
      assert(output.includes(conclusions[stage]), `${lang}: ${id} WARNでも結論${stage}を維持する`);
    }
    const markers = [];
    const emitted = emitNonInteractiveOutcome(
      { println: (line) => markers.push(String(line)) },
      { report: warningReport, fatal: false, stopped: false },
      null,
    );
    assert(markers.includes(`##CHECK ${id} warn`), `${lang}: ${id} WARNを機械印に出す`);
    assert(markers.includes('##RESULT full') && emitted.exitCode === 0,
      `${lang}: ${id} WARNだけでは##RESULT full / exit 0を変えない`);
  }

  for (const id of checkIds) {
    const output = render(makeReport(id), translate);
    const systemBlocks = id.startsWith('check.system.') && id !== 'check.system.productionParams';
    const blocksA = id.startsWith('check.stageA.')
      || systemBlocks;
    const blocksB = blocksA
      || id.startsWith('check.stageB.')
      || systemBlocks;
    const blocksC = blocksB || id.startsWith('check.stageC.');
    const expected = { A: !blocksA, B: !blocksB, C: !blocksC };

    for (const stage of ['A', 'B', 'C']) {
      assert(
        output.includes(conclusions[stage]) === expected[stage],
        `${lang}: ${id} FAIL 時の結論${stage}表示=${expected[stage]}`,
      );
    }
    if (blocksA) assert(output.includes(translate('notVerified.entries', { reason: translate('reason.failed') })), `${lang}: ${id} は①を reason.failed にする`);
    if (blocksB) assert(output.includes(translate('notVerified.selection', { reason: translate('reason.failed') })), `${lang}: ${id} は②を reason.failed にする`);
    if (blocksC) assert(output.includes(translate('notVerified.results', {
      reason: id === 'check.stageC.rosterLiveAnchor'
        ? translate('reason.rosterAnchorFailed')
        : (id === 'check.stageC.rosterCommitment'
          ? translate('reason.rosterCommitmentFailed')
        : (id === 'check.stageC.manifestAnchor'
          ? translate('reason.manifestAnchorFailed')
          : translate('reason.failed'))),
    })), `${lang}: ${id} は③を理由付き未検証にする`);
  }
}

if (failed === 0) {
  console.log(`ALL PASSED: ${checkIds.length} check IDs × ${SUPPORTED_LANGS.length} languages`);
} else {
  console.error(`${failed} FAILED`);
}
process.exit(failed === 0 ? 0 : 1);

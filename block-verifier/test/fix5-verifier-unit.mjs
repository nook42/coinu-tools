// FIX5: ゲームなしの期間行だけ到達条件を替え、FAIL・型付き未検証・R-4を保つ。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createReport } from '../src/report.js';
import { ArchiveUnavailableError } from '../src/archive.js';
import { CHECK_INVENTORY } from '../src/check-inventory.js';
import { VERIFICATION_AREAS } from '../src/verification-areas.js';

const mutation = process.argv.find((arg) => arg.startsWith('--mutation='))?.split('=')[1];
const url = new URL('../src/report.js', import.meta.url);
const original = readFileSync(url, 'utf8');
const exemption = "!(area === 'timeline' && nonGame && id === 'check.stageC.timelineWindows')";
let source = original;
if (mutation === 'restore_windows') source = source.replace(exemption, 'true');
if (mutation === 'all_block_shapes') source = source.replace(exemption,
  "!(area === 'timeline' && id === 'check.stageC.timelineWindows')");
if (mutation) {
  assert.notEqual(source, original, `${mutation}: 変異を適用する`);
  console.log(`MUTATION_APPLIED ${mutation}`);
}
async function load(text) {
  const resolved = text.replace(/from '([^']+)'/g,
    (_, path) => `from '${new URL(path, url).href}'`);
  return import(`data:text/javascript;base64,${Buffer.from(resolved).toString('base64')}`);
}
const { verificationCoverage } = await load(source);
// FIX4の表示判定と、期間行以外が同じであることも確かめる。
const { verificationCoverage: previousCoverage } = await load(original.replace(exemption, 'true'));
let assertions = 0;
const eq = (actual, expected, label) => { assert.deepEqual(actual, expected, label); assertions++; };
const row = (report) => verificationCoverage(report).find((entry) => entry.area === 'timeline');
const timeline = VERIFICATION_AREAS.find((entry) => entry.area === 'timeline');

function makeReport(mode, ran = true) {
  const report = createReport();
  if (mode !== 'game') report.fact(`stageC.${mode}`, true);
  if (mode === 'timelineNoGame') report.fact('stageC.noGame', true);
  report.check('check.stageC.timelineWindows', 'skip', { reason: 'no_evidence_windows' });
  if (ran) for (const id of ['rootSubmitted', 'rootSubmissionRules', 'lifecycleReplayCurrent']) {
    report.check(`check.stageC.${id}`, 'pass');
  }
  return report;
}

for (const mode of ['autoDistributed', 'noGame']) {
  const report = makeReport(mode);
  const records = structuredClone(report.list());
  eq(row(report).verified, true, `${mode}: no_evidence_windowsでも実施済みの期間検査は検証できた`);
  eq(row(report).notApplicable, false, `${mode}: 実施済みなら対象なしにしない`);
  eq(report.list(), records, `${mode}: 表示判定で検査の状態・paramsを変えない`);
  eq(verificationCoverage(report).filter((entry) => entry.area !== 'timeline'),
    previousCoverage(report).filter((entry) => entry.area !== 'timeline'), `${mode}: ほかの行はFIX4と同じ`);
  eq(row(makeReport(mode, false)).notApplicable, true, `${mode}: 全てskipのときだけ対象なし`);
  const incomplete = makeReport(mode, false);
  incomplete.check('check.stageC.rootSubmitted', 'pass');
  eq([row(incomplete).verified, row(incomplete).notApplicable], [false, false], `${mode}: lifecycle未到達は検証済みにしない`);

  // required以外も含め、その行のどの検査のFAIL/型付き未検証も隠さない。
  for (const id of CHECK_INVENTORY.filter((id) => timeline.matches.test(id))) {
    const failed = makeReport(mode);
    failed.check(id, 'fail', { marker: 'independent_violation' });
    eq(row(failed), { area: 'timeline', verified: false, notApplicable: false, reason: 'failed' }, `${mode}/${id}: FAIL`);
    const unavailable = makeReport(mode);
    unavailable.unverified(id, new ArchiveUnavailableError(), { marker: 'unread_value' });
    eq(row(unavailable), { area: 'timeline', verified: false, notApplicable: false, reason: 'archiveUnavailable' }, `${mode}/${id}: 型付き未検証`);
  }
}

for (const mode of ['timelineNoGame', 'game']) {
  const report = makeReport(mode);
  eq(row(report), { area: 'timeline', verified: false, notApplicable: false, reason: 'stopped' }, `${mode}: timelineWindowsは従来どおり必須`);
  report.check('check.stageC.timelineWindows', 'pass');
  eq(row(report).verified, true, `${mode}: 到達条件がpassなら検証できた`);
  eq(verificationCoverage(report), previousCoverage(report), `${mode}: 全行がFIX4と同じ`);
}

if (!mutation) for (const name of ['restore_windows', 'all_block_shapes']) {
  const child = spawnSync(process.execPath, [new URL(import.meta.url).pathname, `--mutation=${name}`], {
    encoding: 'utf8', timeout: 30000,
  });
  eq(child.stdout.includes(`MUTATION_APPLIED ${name}`), true, `${name}: 変異が適用済み`);
  eq(child.status, 1, `${name}: 変異で赤`);
  eq(child.stderr.includes('AssertionError'), true, `${name}: 起動失敗ではなくassertionで検出`);
  eq(child.stderr.includes(name === 'restore_windows' ? 'autoDistributed: no_evidence_windows'
    : 'timelineNoGame: timelineWindowsは従来どおり必須'), true, `${name}: 指定された場面で検出`);
}
console.log(`fix5-verifier-unit: PASS (${assertions} assertions; 2 mutants killed)`);

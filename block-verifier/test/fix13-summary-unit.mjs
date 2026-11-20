// FIX13/FIX14: 3言語の保証文、未検証・対象なし・行名の維持、対話UIの見出し直前を固定する。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { t, SUPPORTED_LANGS } from '../src/i18n.js';
import { CHECK_INVENTORY } from '../src/check-inventory.js';
import { VERIFICATION_AREAS, publicnodeExplanation } from '../src/verification-areas.js';
import { ArchiveUnavailableError } from '../src/archive.js';
import { makeUi, emitNonInteractiveOutcome } from '../src/index.js';

const expected = JSON.parse(readFileSync(new URL('./fixtures/fix13-summary.json', import.meta.url), 'utf8'));
const mutation = process.argv.find((arg) => arg.startsWith('--mutation='))?.slice(11);
const url = new URL('../src/report.js', import.meta.url);
let source = readFileSync(url, 'utf8');
if (mutation) {
  const before = mutation === 'separator' ? '    ui.println(sep);\n' : 'canGuarantee(row.area) ? `summary.guarantee.${row.area}`';
  const after = mutation === 'separator' ? before + '    ui.section?.();\n'
    : `canGuarantee(row.area) ? (row.area === '${mutation}' ? 'summary.areaVerified' : \`summary.guarantee.\${row.area}\`)`;
  assert.ok(source.includes(before), '変異対象が存在する');
  source = source.replace(before, after);
  console.log(`MUTATION_APPLIED ${mutation}`);
}
source = source.replace(/from '(\.\.?\/[^']+)'/g, (_, path) => `from '${new URL(path, url).href}'`);
const { createReport, verificationCoverage } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
let assertions = 0;
const eq = (a, b, label) => { assert.deepEqual(a, b, label); assertions++; };
const ok = (a, label) => { assert.ok(a, label); assertions++; };
function complete(omit = () => false) {
  const report = createReport();
  for (const id of CHECK_INVENTORY) if (!omit(id)) report.check(id, 'pass', { fixture: id });
  report.fact('system.audit', { adminHistoryChecked: true, donateChecked: true });
  return report;
}
function machine(report) {
  const lines = [];
  const outcome = emitNonInteractiveOutcome({ println: (line) => lines.push(line) }, { report, fatal: false, stopped: false }, null);
  return { lines, outcome };
}
function render(report, lang, ctx = { blockNum: 8 }, nonInteractive = false) {
  const records = structuredClone(report.list()), coverage = verificationCoverage(report), markers = machine(report);
  const chunks = [], original = process.stdout.write;
  process.stdout.write = (chunk) => { chunks.push(String(chunk)); return true; };
  try {
    const ui = makeUi(t(lang), { isInteractive: !nonInteractive }, { nonInteractive });
    ui.section('existing section'); // ほかの文脈の区切りは維持される。
    report.renderSummary(ui, { data: {}, ...ctx });
  } finally { process.stdout.write = original; }
  eq(report.list(), records, `${lang}: 描画は全レコード・状態・params・理由を変えない`);
  eq(verificationCoverage(report), coverage, `${lang}: 領域の判定を変えない`);
  eq(machine(report), markers, `${lang}: 全機械行・終了コードを変えない`);
  const output = chunks.join(''), title = t(lang)('summary.title', { block: ctx.blockNum });
  ok(output.includes('='.repeat(60) + '\n' + title + '\n' + '='.repeat(60)), `${lang}: ====の直後に見出し`);
  eq(output.split('\n--------\n').length - 1, nonInteractive ? 0 : 1, `${lang}: まとめ以外の区切りだけを保持`);
  return output;
}
function verifiedPart(output, lang) {
  return output.slice(output.indexOf(t(lang)('summary.coverageVerified')), output.indexOf(t(lang)('summary.coverageUnverified')));
}
function unverifiedRow(report, lang, area, reason) {
  const output = render(report, lang), prefix = `  ${expected[lang].labels[area]}: `;
  ok(output.split('\n').includes(prefix + expected[lang].unverified[reason]), `${lang}/${area}/${reason}: 以前と同じ未検証行`);
  ok(!verifiedPart(output, lang).includes(prefix), `${lang}/${area}/${reason}: 保証文を出さない`);
}
function notApplicableRow(report, lang, area) {
  const row = verificationCoverage(report).find((row) => row.area === area);
  eq(row.notApplicable, true, `${lang}/${area}: 対象なしの分岐を通る`);
  const output = render(report, lang), prefix = `  ${expected[lang].labels[area]}: `;
  ok(output.split('\n').includes(prefix + expected[lang].notApplicable), `${lang}/${area}: 以前と同じ対象なし行`);
  ok(!verifiedPart(output, lang).includes(prefix), `${lang}/${area}: 対象なしに保証文を出さない`);
}
for (const lang of SUPPORTED_LANGS) {
  eq(publicnodeExplanation(t(lang)), expected[lang].publicnode, `${lang}: publicnodeの説明・行名・順序はFIX12のまま`);
  eq(Object.fromEntries(VERIFICATION_AREAS.map(({ area }) => [area, t(lang)(`summary.area.${area}`)])), expected[lang].labels, `${lang}: 全行名を保持`);
  // URLはブロック番号・実取得先に従う。設定を省く直接呼出も従来どおり動く。
  for (const [ctx, entriesUrl] of [
    [{ blockNum: 8 }, 'https://r2.bitcoinu.org/entries/block8/'],
    [{ blockNum: 0, cfg: { r2Base: 'https://r2.bitcoinu.org' } }, 'https://r2.bitcoinu.org/entries/block0/'],
    // 再反証 G-1b（2026-11-17）: 公式以外の取得元（ミラーの r2Base）の走りでは URL つきの保証の文を出さない。
    // その場面は fix15-summary-unit.mjs の localCases が持つ。ここは公式の取得元の末尾スラッシュの吸収だけを見る。
    [{ blockNum: 37, cfg: { r2Base: 'https://r2.bitcoinu.org///' } }, 'https://r2.bitcoinu.org/entries/block37/'],
  ]) for (const nonInteractive of [false, true]) {
    const output = render(complete(), lang, ctx, nonInteractive), lines = verifiedPart(output, lang).split('\n');
    for (const { area } of VERIFICATION_AREAS) {
      const text = expected[lang].guarantees[area]
        .replaceAll('{entriesUrl}', entriesUrl).replaceAll('{blockUrl}', `https://bitcoinu.org/block/?n=${ctx.blockNum}`);
      ok(lines.includes(`  ${expected[lang].labels[area]}: ${text}`), `${lang}/${area}: 指定文を全文一致で表示`);
    }
  }
  for (const { area, required, matches } of VERIFICATION_AREAS) {
    const id = required[0] ?? 'fact.system.adminRotationUnavailable';
    for (const state of ['skip', 'fail', 'archive', 'unrun']) {
      const report = complete((key) => state === 'unrun' && key === id);
      if (area === 'adminHistory') report.fact('system.audit', { adminHistoryChecked: true, adminChangeError: 'unreadable' });
      if (state === 'archive') report.unverified(id, new ArchiveUnavailableError(), { detail: 'kept' });
      else if (state !== 'unrun') report.check(id, state, { detail: 'kept' });
      const reason = state === 'archive' ? 'archiveUnavailable' : state === 'fail' ? 'failed' : 'stopped';
      unverifiedRow(report, lang, area, reason);
    }
    if (['adminHistory', 'locks', 'evidence', 'timeline'].includes(area)) {
      const report = complete((id) => ['adminHistory', 'evidence', 'timeline'].includes(area) && matches.test(id));
      if (area === 'adminHistory') report.fact('system.audit', { adminHistoryChecked: false });
      else report.fact('stageC.noGame', true);
      if (area === 'timeline') report.check('check.stageC.timelineWindows', 'skip', { reason: 'no_evidence_windows' });
      notApplicableRow(report, lang, area);
    }
  }
  const adminWarning = complete();
  adminWarning.fact('system.audit', { adminHistoryChecked: true, adminChangeError: 'unreadable' });
  adminWarning.check('fact.system.adminRotationUnavailable', 'warn', { error: 'temporary RPC failure' });
  unverifiedRow(adminWarning, lang, 'adminHistory', 'rpcRequestFailed');
  for (const mode of ['NoGame', 'TimelineNoGame', 'Auto']) {
    const report = complete(); report.check(`check.stageB.groupingSkipped${mode}`, 'skip');
    notApplicableRow(report, lang, 'grouping');
  }
  for (const kind of ['shadow', 'no_root']) for (const area of ['proofPublicValues', 'proofHistory']) {
    const report = complete(); report.check('check.stageC.zkProofStatus', 'pass', { kind });
    notApplicableRow(report, lang, area);
  }
}
if (!mutation) for (const name of [...VERIFICATION_AREAS.map(({ area }) => area), 'separator']) {
  const result = spawnSync(process.execPath, [import.meta.filename, '--mutation=' + name], { encoding: 'utf8', env: process.env });
  eq(result.status, 1, `${name}: 変異で赤`);
  ok(result.stdout.includes(`MUTATION_APPLIED ${name}`) && result.stderr.includes('AssertionError'), `${name}: 起動失敗でなくassertionで検出`);
}
console.log(`fix13-summary-unit: PASS (${assertions} assertions; 13 mutants killed)`);

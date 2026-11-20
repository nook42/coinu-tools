// FIX14: 保証文の表示条件を、領域の分類・結論②・検査レコードを変えずに厳しくする。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync, spawnSync } from 'node:child_process';
import { CHECK_INVENTORY } from '../src/check-inventory.js';
import { VERIFICATION_AREAS, publicnodeExplanation } from '../src/verification-areas.js';
import { emitNonInteractiveOutcome } from '../src/index.js';
import { ArchiveUnavailableError } from '../src/archive.js';
import { ZKP_EXPECTED } from '../vendor/workers/game_workers/lib/zkp-protocol.js';
import { getAddress } from 'viem';
import { PREV_REGISTRATION_SENTINEL } from '../src/prev-registration-witness.js';

const expected = JSON.parse(readFileSync(new URL('./fixtures/fix13-summary.json', import.meta.url), 'utf8'));
const headers = { en: '✅ Summary:', ja: '✅まとめ:', zh: '✅ 总结:' };
const verified = { en: 'Verified', ja: '検証できた', zh: '已验证' };
const mutation = process.argv.find((arg) => arg.startsWith('--mutation='))?.slice(11);
const zkpStart = '    // ── ⓪ ZKP';
const entriesStart = '    // ── ① エントリー固定';
const zkpGate = "covered('proofPublicValues') && canGuarantee('proofPublicValues') && covered('proofHistory')";
const rootMismatchGate = "} else if (st('check.stageC.merkleRoot') === 'fail'\n            || st('check.stageC.evidenceReportMatch') === 'fail') {";
const historyVerifierGate = "      if (area === 'proofHistory' && st('check.stageC.zkVerifierIdentity') !== 'pass') return false;";
const mutations = {
  matches: ["      if (list().some((entry) => matches.test(entry.id) && entry.status !== 'pass')) return false;", ''],
  required: ["      if (!required.every((id) => st(id) === 'pass')) return false;", ''],
  entries: ["      if (area === 'entries' && st('check.stageB.playersMatch') !== 'pass') return false;", ''],
  selection: ["['selection', 'grouping'].includes(area)", "['grouping'].includes(area)"],
  grouping: ["['selection', 'grouping'].includes(area)", "['selection'].includes(area)"],
  shared: ["const selectionMessage = selectionConclusionMessage();", "const selectionMessage = { key: 'conclusion.selection' };"],
  header_en: ["'summary.conclusionsHeader': '✅ Summary:'", "'summary.conclusionsHeader': 'What this verification established:'"],
  header_ja: ["'summary.conclusionsHeader': '✅まとめ:'", "'summary.conclusionsHeader': 'この検証で確認できたこと:'"],
  header_zh: ["'summary.conclusionsHeader': '✅ 总结:'", "'summary.conclusionsHeader': '本次验证确认了以下内容:'"],
  v1: ["String(zkInfo.epoch.verifier).toLowerCase() === ZKP_EXPECTED.verifier.toLowerCase() ? 'pass' : 'fail'", "'pass'"],
  v2: ["if (st('check.stageC.zkVerifierIdentity') === 'fail')", "if (false)"],
  v5: [rootMismatchGate, '} else if (false) {'],
  v6: ["? 'notVerified.zkProofHistory' : 'notVerified.zkProof'", "? 'notVerified.zkProof' : 'notVerified.zkProof'"],
  v7: ["String(zkInfo.epoch.verifier).toLowerCase() === ZKP_EXPECTED.verifier.toLowerCase()", "String(zkInfo.epoch.verifier) === ZKP_EXPECTED.verifier"],
  w1: ["if (covered('proofPublicValues') && canGuarantee('proofPublicValues')) {", 'if (false) {'],
  w2: [historyVerifierGate, ''],
  q1: [zkpGate, "covered('proofPublicValues') && canGuarantee('proofPublicValues')"],
  q2: [zkpGate, "covered('proofPublicValues') && covered('proofHistory')"],
  q2b: [zkpGate, zkpGate + " && canGuarantee('proofHistory')"],
  q3: ["      } else if (systemFailed) {\n        zkPending('failed');", ''],
  q4: (source) => {
    const start = source.indexOf(zkpStart), end = source.indexOf(entriesStart);
    assert.ok(start >= 0 && end > start, '⓪の変異対象が存在する');
    const block = source.slice(start, end);
    return source.replace(block, '').replace('    if (conclusions.length > 0) {', block + '    if (conclusions.length > 0) {');
  },
  q5: ["    if (!(timelineNoGame && f('stageC.timelineNoGameRoot')?.state === 'omitted_terminal')) {", '    if (true) {'],
  q6: ["      } else if (kind === 'no_root') {\n        zkPending('notReady');",
    "      } else if (kind === 'no_root') {\n        conclusions.push(t('conclusion.zkShadow', { block: ctx.blockNum }));"],
};
async function loadModule(path, mutate, input) {
  const url = new URL(path, import.meta.url);
  let source = input ?? readFileSync(url, 'utf8');
  if (mutate) {
    const change = mutations[mutation];
    if (typeof change === 'function') source = change(source);
    else {
      const [before, after] = change;
      assert.equal(source.split(before).length - 1, 1, '変異対象が1か所存在する');
      source = source.replace(before, after);
    }
  }
  source = source.replace(/from '(\.\.?\/[^']+)'/g, (_, path) => `from '${new URL(path, url).href}'`);
  source = source.replace(/from 'viem'/g, `from '${import.meta.resolve('viem')}'`);
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
}
if (mutation) assert.ok(Object.hasOwn(mutations, mutation), '既知の変異');
const { createReport, verificationCoverage } = await loadModule('../src/report.js', mutation && !mutation.startsWith('header_') && !['v1', 'v7'].includes(mutation));
const { t, SUPPORTED_LANGS } = await loadModule('../src/i18n.js', mutation?.startsWith('header_'));
const { recordZkpState, verifyPrevRegistrationWitness } = await loadModule('../src/stages/results.js', ['v1', 'v7'].includes(mutation));
// import成功後の印。構文エラー・起動失敗は変異検出に数えない。
if (mutation) console.log(`MUTATION_APPLIED ${mutation}`);
let assertions = 0;
const eq = (a, b, label) => { assert.deepEqual(a, b, label); assertions++; };
const ok = (a, label) => { assert.ok(a, label); assertions++; };
function complete(omit = () => false) {
  const report = createReport();
  for (const id of [...CHECK_INVENTORY, 'fact.system.adminRotation']) {
    if (!omit(id)) report.check(id, 'pass', { fixture: id });
  }
  report.fact('system.audit', { adminHistoryChecked: true, donateChecked: true });
  return report;
}
function machine(report) {
  const lines = [];
  const outcome = emitNonInteractiveOutcome({ println: (line) => lines.push(line) }, { report, fatal: false, stopped: false }, null);
  return { lines, outcome };
}
function render(report, lang, data = {}, options = {}) {
  const before = structuredClone(report.list()), coverage = verificationCoverage(report), markers = machine(report);
  const lines = [], conclusions = [];
  const translate = (key, params) => {
    if (key.startsWith('conclusion.') || key.startsWith('notVerified.')) conclusions.push({ key, params });
    return t(lang)(key, params);
  };
  report.renderSummary({ t: translate, println: (line) => lines.push(line) }, { blockNum: 8, data, ...options });
  eq(report.list(), before, `${lang}: 描画は全レコード・状態・params・理由を変えない`);
  eq(verificationCoverage(report), coverage, `${lang}: 描画は領域の分類を変えない`);
  eq(machine(report), markers, `${lang}: 描画は機械行・終了コードを変えない`);
  const part = lines.slice(lines.indexOf(t(lang)('summary.coverageVerified')), lines.indexOf(t(lang)('summary.coverageUnverified')));
  return { lines, part, conclusions };
}
function rowText(lang, area, guarantee) {
  const body = guarantee ? expected[lang].guarantees[area]
    .replaceAll('{blockUrl}', 'https://bitcoinu.org/block/?n=8')
    .replaceAll('{entriesUrl}', 'https://r2.bitcoinu.org/entries/block8/') : verified[lang];
  return `  ${expected[lang].labels[area]}: ${body}`;
}
function expectVerifiedRow(report, output, lang, area, guarantee) {
  const row = verificationCoverage(report).find((row) => row.area === area);
  eq([row.verified, row.notApplicable], [true, false], `${lang}/${area}: 検証できた分類を維持`);
  ok(output.part.includes(rowText(lang, area, guarantee)), `${lang}/${area}: ${guarantee ? '保証文' : '既存の短文'}を表示`);
  ok(!output.part.includes(rowText(lang, area, !guarantee)), `${lang}/${area}: 他方の文は表示しない`);
}
for (const lang of SUPPORTED_LANGS) {
  eq(publicnodeExplanation(t(lang)), expected[lang].publicnode, `${lang}: publicnodeの説明は変更しない`);
  const report = complete(), output = render(report, lang);
  eq(t(lang)('summary.areaVerified'), verified[lang], `${lang}: 既存の短文を保持`);
  eq(t(lang)('summary.conclusionsHeader'), headers[lang], `${lang}: 見出しの全文`);
  eq(output.lines.filter((line) => line === headers[lang]).length, 1, `${lang}: 実まとめに見出しが1回出る`);
  for (const { area } of VERIFICATION_AREAS) expectVerifiedRow(report, output, lang, area, true);

  // 必須以外を含め、matchesに当たる実在の検査を1件ずつWARN/SKIPにする。
  for (const { area, matches } of VERIFICATION_AREAS) {
    const ids = report.list().filter((entry) => matches.test(entry.id)).map((entry) => entry.id);
    ok(ids.length > 0, `${area}: 空集合だけで試験しない`);
    for (const id of ids) for (const status of ['warn', 'skip']) {
      const changed = complete(); changed.check(id, status, { injected: id });
      const output = render(changed, lang);
      const row = verificationCoverage(changed).find((row) => row.area === area);
      if (row.verified && !row.notApplicable) expectVerifiedRow(changed, output, lang, area, false);
      else ok(!output.part.includes(`  ${expected[lang].labels[area]}: `), `${lang}/${area}/${id}/${status}: 未検証・対象なしに保証文は出ない`);
    }
  }
  for (const status of ['warn', 'skip', 'fail', 'unrun']) {
    const changed = complete((id) => status === 'unrun' && id === 'check.stageB.playersMatch');
    if (status !== 'unrun') changed.check('check.stageB.playersMatch', status, { injected: 'playersMatch' });
    expectVerifiedRow(changed, render(changed, lang), lang, 'entries', false);
  }
  // 非ゲーム時はcoverageが期間の必須条件を免除する。保証文には元のrequiredもすべて必要。
  for (const mode of ['stageC.noGame', 'stageC.autoDistributed']) {
    const changed = complete((id) => id === 'check.stageC.timelineWindows');
    changed.fact(mode, true);
    expectVerifiedRow(changed, render(changed, lang), lang, 'timeline', false);
  }
  // 他領域のWARN/SKIPで独立した行まで短文に戻さない。
  for (const status of ['warn', 'skip']) {
    const changed = complete(); changed.check('check.stageC.zkPrevRegistrationWitness', status);
    const output = render(changed, lang);
    for (const area of ['entries', 'selection', 'grouping', 'resultFiles']) expectVerifiedRow(changed, output, lang, area, true);
  }

  const scenarios = [
    { name: '通常', key: 'conclusion.selection' },
    { name: '自動配布', data: { autoDistribute: true }, key: 'conclusion.selectionAuto' },
    { name: '応募0件', fact: 'stageC.noGame', key: 'conclusion.selectionNoGame' },
    { name: 'noGame入力', data: { noGame: true }, key: 'conclusion.selectionNoGame' },
    { name: 'timelineNoGame', fact: 'stageC.timelineNoGame', key: 'conclusion.selectionTimelineNoGame' },
    { name: 'グループ未公開', check: ['check.stageB.groupsPresent', 'skip'], key: 'conclusion.selectionOnly' },
    { name: '抽選未到達', omit: 'check.stageB.selectionPresent', key: 'notVerified.selection', reason: 'stopped' },
    { name: '抽選未公開', check: ['check.stageB.selectionPresent', 'skip'], key: 'notVerified.selection', reason: 'notReady' },
    { name: '乱数未到達', omit: 'check.stageB.randao', key: 'notVerified.selection', reason: 'stopped' },
    { name: 'グループ再現未到達', omit: 'check.stageB.groupsMatch', key: 'notVerified.selection', reason: 'stopped' },
    { name: '採点の独立FAIL', check: ['check.stageC.scoring', 'fail'], key: 'conclusion.selection' },
    { name: '本番期間差FAIL', check: ['check.system.productionParams', 'fail'], key: 'conclusion.selection' },
    { name: '配線FAIL', check: ['check.system.evidenceStartPastTolerance', 'fail'], key: 'notVerified.selection', reason: 'failed' },
  ];
  for (const kind of ['Same', 'Different', '']) for (const mode of ['', 'Only', 'Auto']) {
    scenarios.push({ name: `複数登録${kind}/${mode}`, kind, mode,
      key: `conclusion.selection${mode}RegistrationWarning${kind}` });
  }
  for (const scenario of scenarios) {
    const changed = complete((id) => id === scenario.omit);
    if (scenario.fact) changed.fact(scenario.fact, true);
    if (scenario.check) changed.check(...scenario.check);
    if (Object.hasOwn(scenario, 'kind')) {
      const registrations = scenario.kind ? [{ hash: '0x11' }, { hash: scenario.kind === 'Same' ? '0X11' : '0x22' }] : undefined;
      changed.check('check.stageA.registrationCount', 'warn', { count: 2, ...(registrations ? { registrations } : {}) });
      if (scenario.mode === 'Only') changed.check('check.stageB.groupsPresent', 'skip');
    }
    const data = { ...scenario.data, ...(scenario.mode === 'Auto' ? { autoDistribute: true } : {}) };
    const output = render(changed, lang, data);
    const selection = output.conclusions.filter(({ key }) => key === 'notVerified.selection' || key.startsWith('conclusion.selection'));
    eq(selection.map(({ key }) => key), [scenario.key], `${lang}/${scenario.name}: ②の既存分岐を保持`);
    if (scenario.reason) eq(selection[0].params.reason, t(lang)(`reason.${scenario.reason}`), `${lang}/${scenario.name}: 未検証理由も保持`);
    for (const area of ['selection', 'grouping']) {
      const row = verificationCoverage(changed).find((row) => row.area === area);
      if (row.verified && !row.notApplicable) expectVerifiedRow(changed, output, lang, area, scenario.key === 'conclusion.selection');
      else ok(!output.part.includes(`  ${expected[lang].labels[area]}: `), `${lang}/${scenario.name}/${area}: 未検証行を保持`);
    }
  }
}
// SUMMARY-ZKP: 起点コミットの実renderSummaryと、⓪以外の全文・機械行・終了コードを比較する。
// HEADを使うと、この変更をコミットした後に比較基準が動くためコミットを固定する。
const baselineSource = execFileSync('git', ['show', '425eb602085e23bc1518d9d04babf6bb8876826c:block-verifier/src/report.js'],
  { cwd: new URL('../../', import.meta.url), encoding: 'utf8' });
const { createReport: createBaselineReport } = await loadModule('../src/report.js', false, baselineSource);
const zkpFacts = {
  hashRegisteredTime: '2026-09-04T00:00:00.000Z', totalEntries: 4,
  applicantHash: '0xabc', hashRegisteredBlock: 100, totalSelected: 4,
  targetBlockNum: 123, targetBlockTime: '2026-09-05T00:00:00.000Z', totalGroups: 1,
  'stageC.blockReward': '1000000000000000000', 'stageC.playerCount': 4,
  'stageC.groupCount': 1, 'stageC.disqualifiedCount': 0,
  'stageC.verificationStartedAt': { iso: '2026-09-05T01:00:00.000Z' },
  'stageC.verificationEndsAt': { iso: '2026-09-09T01:00:00.000Z' },
  'stageC.claimWindow': { endIso: '2026-10-19T01:00:00.000Z' },
};
const rootMismatchText = {
  ja: '⓪ ZKP の証明は付いており、公開値はチェーン上の値に結び付いていますが、証明つきのCOINU分配データまたは採用表の照合が不合格のため、この証明による保証は出せません。',
  en: '⓪ A ZKP proof is attached and its public values are bound to on-chain values, but the check of the proven COINU distribution data or adoption set failed, so no guarantee can be given from this proof.',
  zh: '⓪ 已附 ZKP 证明，其公开值与链上的值相关联，但附证明的 COINU 分配数据或采用表的核对未通过，因此无法基于该证明给出保证。',
};
const jaZkp = {
  'conclusion.zkProof': '⓪ ブロック{block}に提出されたCOINU分配データ（報酬の Merkle ルート）には ZKP の証明が付いています。この証明は検証コントラクトで検証されており、提出されたCOINU分配データはこのブロックの応募データ・乱数・Evidence・結果のマニフェストなど、チェーン上に固定された値と、検証コントラクトに登録された証明プログラムに基づいて整合していることが保証されます。',
  'conclusion.zkShadow': '⓪ ブロック{block}の結果（報酬の Merkle ルート）には ZKP の証明が付いていません（証明が必須になる前の期間の正常な提出です）。このブロックの結果の正しさは、ZKP ではなく③の再計算による検証に依拠します。',
  'notVerified.zkProof': '⓪ ZKP の証明は付いていますが、証明がこのブロックのチェーン上の値に結び付いていることは未検証です: {reason}',
  'notVerified.zkRootMismatch': rootMismatchText.ja,
  'notVerified.zkVerifier': '⓪ ZKP の証明は付いていますが、証明を検証したコントラクトが Succinct の SP1 Groth16 verifier v6.1.0 ではないため、証明が正しく検証されたことを確認できません。',
  'notVerified.zkProofHistory': '⓪ ZKP の証明は付いていますが、証明の時点の状態（将来のアンカー）がチェーンと一致することは未検証です: {reason}',
  'notVerified.zk': '⓪ ZKP の有無は未検証です: {reason}',
};
function zkpReport(omit) {
  const report = complete(omit);
  for (const [key, value] of Object.entries(zkpFacts)) report.fact(key, value);
  return report;
}
function baselineLines(report, context) {
  const baseline = createBaselineReport();
  for (const entry of report.list()) {
    baseline.check(entry.id, entry.status, structuredClone(entry.params));
    Object.assign(baseline.get(entry.id), structuredClone(entry));
  }
  for (const key of [...Object.keys(zkpFacts), 'system.audit', 'stageC.noGame',
    'stageC.timelineNoGame', 'stageC.timelineNoGameRoot', 'stageC.autoDistributed', 'stageC.anomalies']) {
    baseline.fact(key, structuredClone(report.getFact(key)));
  }
  const lines = [];
  baseline.renderSummary({ t: t('ja'), println: (line) => lines.push(line) }, context);
  // FIX2 G2 で許可された唯一の領域行の差分。分類・他の行は旧版と全文比較する。
  if (report.get('check.stageC.zkVerifierIdentity')?.status !== 'pass') {
    const index = lines.indexOf(rowText('ja', 'proofHistory', true));
    if (index >= 0) lines[index] = rowText('ja', 'proofHistory', false);
  }
  eq(machine(report), machine(baseline), 'SUMMARY-ZKP: 変更前と全##CHECK・##RESULT・終了コードがバイト同一');
  return lines;
}
function expectZkp(label, report, context, key, reason, reasonParams = {}) {
  const output = render(report, 'ja', context.data, context);
  const expectedLines = baselineLines(report, context);
  const zeroLines = output.lines.filter((line) => /^  ⓪ /.test(line));
  eq(zeroLines.length, key ? 1 : 0, `${label}: ⓪は1つだけ（Z0は両欄に無し）`);
  if (key) {
    const line = `  ${jaZkp[key].replaceAll('{block}', String(context.blockNum))
      .replaceAll('{reason}', reason ? t('ja')(`reason.${reason}`, reasonParams) : '')}`;
    eq(zeroLines, [line], `${label}: 指定の文と既存の理由の全文`);
    const conclusion = key.startsWith('conclusion.');
    const header = t('ja')(conclusion ? 'summary.conclusionsHeader' : 'summary.notVerifiedHeader');
    eq(output.lines.indexOf(line), output.lines.indexOf(header) + (conclusion ? 2 : 1), `${label}: 欄の先頭で①より前、既存の空行規則`);
    const existing = expectedLines.indexOf(header);
    if (existing >= 0) expectedLines.splice(existing + 1, 0, ...(conclusion ? ['', line] : [line]));
    else {
      const next = conclusion ? t('ja')('summary.notVerifiedHeader') : t('ja')('summary.folder', { path: context.r2?.baseDir ?? '-' });
      const position = expectedLines.indexOf(next);
      ok(position > 0, `${label}: 新設欄の挿入位置がある`);
      expectedLines.splice(position - 1, 0, '', header, ...(conclusion ? ['', line] : [line]));
    }
  }
  eq(output.lines.join('\n'), expectedLines.join('\n'), `${label}: ⓪・伴う空行と見出し・G2の履歴行以外は変更前とバイト同一`);
  return output;
}
const proofContext = { blockNum: 8, data: { zkInfo: { kind: 'proof' } }, r2: { baseDir: '/tmp/block8' } };
const summaryExamples = {};
function expectZkpConsistency(output, label) {
  const zero = output.lines.find((line) => line.startsWith('  ⓪ '));
  const publicGuaranteed = output.part.includes(rowText('ja', 'proofPublicValues', true));
  if (publicGuaranteed) {
    ok(!zero.includes('証明がこのブロックのチェーン上の値に結び付いていることは未検証'), `${label}: 公開値の保証と⓪が矛盾しない`);
    ok(!zero.includes('正しく検証されたことを確認できません'), `${label}: 公開値の保証とverifierの文が矛盾しない`);
  }
  if (zero.includes('正しく検証されたことを確認できません')) {
    ok(!publicGuaranteed, `${label}: verifier不一致で公開値の保証なし`);
    ok(!output.part.includes(rowText('ja', 'proofHistory', true)), `${label}: verifier不一致で履歴の保証なし`);
  }
}

// q2bは2つの正常経路を別プロセスでも検出する。証人レコードは実関数が作る。
const onlyWitnessBlock = process.argv.find((arg) => arg.startsWith('--witness-block='))?.slice(16);
for (const blockNum of [0, 1].filter((n) => onlyWitnessBlock == null || String(n) === onlyWitnessBlock)) {
  const report = zkpReport();
  report.check('check.stageC.zkProofStatus', 'pass', { kind: 'proof' });
  const context = { ...proofContext, blockNum, cfg: { observerManifest: null }, report,
    chain: {
      resultRegistrationHistory: async (prev) => {
        eq(prev, 0, 'observerなしのN>0は前ブロックを読む');
        return { count: 0, rows: [] };
      },
      getTimingConstants: async () => ({ startTimeEntryMs: 0, blockTimeMs: 1000, gamePeriodMs: 1000 }),
    },
  };
  await verifyPrevRegistrationWitness(context, { chatWindow: { chatCloseAt: 5 } },
    { txHash: `0x${'99'.repeat(32)}` }, { prevRegistrationIndex: PREV_REGISTRATION_SENTINEL });
  const witness = report.get('check.stageC.zkPrevRegistrationWitness');
  eq(witness.status, 'skip', `Z6 real witness block ${blockNum}: 実関数がskipを記録`);
  eq(witness.params.reason, blockNum === 0 ? 'no_previous_block' : 'observer_record_unavailable', `Z6 real witness block ${blockNum}: 正常skip理由`);
  if (blockNum > 0) eq(witness.params.observerReason, 'not_configured', 'observer-manifest未指定の実経路');
  const output = expectZkp(`Z6 real witness block ${blockNum}`, report, context, 'conclusion.zkProof');
  for (const area of ['proofPublicValues', 'proofHistory']) {
    const row = verificationCoverage(report).find((row) => row.area === area);
    eq([row.verified, row.notApplicable], [true, false], `block ${blockNum}: ${area}はverified`);
    expectVerifiedRow(report, output, 'ja', area, area === 'proofPublicValues');
  }
}
// FIX1: 実recordZkpState → coverage → まとめ → 機械行の経路を通す。
for (const verifier of [ZKP_EXPECTED.verifier, getAddress(ZKP_EXPECTED.verifier), `0x${'11'.repeat(20)}`]) {
  const report = zkpReport();
  const zkInfo = { kind: 'proof', currentProofRequired: true,
    epoch: { index: 7, verifier, vkey: ZKP_EXPECTED.vkey, guestSourceHash: '0xsource' } };
  recordZkpState({ report }, { anomalies: [] }, zkInfo);
  report.check('check.stageC.futureAnchorsHash', 'pass');
  report.check('check.stageC.evidenceSegmentBoundaries', 'pass');
  const mismatch = verifier.toLowerCase() !== ZKP_EXPECTED.verifier;
  const entry = report.get('check.stageC.zkVerifierIdentity');
  eq(entry.status, mismatch ? 'fail' : 'pass', 'FIX1: verifier照合（チェックサムを含む）');
  eq(entry.params, { epoch: 7, verifier, expected: ZKP_EXPECTED.verifier }, 'FIX1: verifierのparams');
  const output = expectZkp(`FIX1 verifier/${verifier}`, report, { ...proofContext, data: { zkInfo } },
    mismatch ? 'notVerified.zkVerifier' : 'conclusion.zkProof');
  const coverage = verificationCoverage(report).find((row) => row.area === 'proofPublicValues');
  eq(coverage.verified, !mismatch, 'FIX1: 公開値の行の分類');
  eq(machine(report).outcome.exitCode, mismatch ? 2 : 0, 'FIX1: verifier不一致は終了コード2');
  if (mismatch) {
    ok(output.lines.some((line) => line.startsWith('  ✗ ' + t('ja')('check.stageC.zkVerifierIdentity', entry.params))), 'FIX1: 問題一覧の✗と照合文');
    ok(output.lines.includes('  ' + t('ja')('notVerified.results', { reason: t('ja')('reason.failed') })), 'FIX1: ③はreason.failed');
    ok(!output.part.some((line) => line.startsWith('  ' + expected.ja.labels.proofPublicValues + ':')), 'FIX1: 公開値を検証済みの側に出さない');
  }
  expectZkpConsistency(output, 'FIX2 verifier');
}
// observer 指定で証人が PASS になった形。履歴の分類を保ち、verifier が PASS のときだけ保証する。
for (const status of ['pass', 'fail', 'warn', 'skip', 'unrun']) {
  const report = zkpReport((id) => status === 'unrun' && id === 'check.stageC.zkVerifierIdentity');
  if (status !== 'unrun') report.check('check.stageC.zkVerifierIdentity', status);
  const observerPath = '/tmp/fix2-observer-manifest.json';
  report.check('check.stageC.zkPrevRegistrationWitness', 'pass', { prev: 7, used: '0', atGrouping: '0', observerPath });
  report.check('check.stageC.futureAnchorsHash', 'pass');
  const context = { ...proofContext, cfg: { observerManifest: observerPath } };
  const output = render(report, 'ja', context.data, context);
  expectVerifiedRow(report, output, 'ja', 'proofHistory', status === 'pass');
  expectZkpConsistency(output, `FIX2 observer/verifier ${status}`);
  expectZkp(`FIX2 observer/verifier ${status}`, report, context,
    status === 'pass' ? 'conclusion.zkProof' : status === 'fail' ? 'notVerified.zkVerifier' : 'notVerified.zkProof',
    status === 'pass' || status === 'fail' ? undefined : 'stopped');
  if (status === 'fail') summaryExamples.verifierMismatchObserverPass = output.lines;
}
for (const [kind, timelineNoGame, reason] of [
  ['shadow', false, 'shadow_no_proof'], ['no_root', false, 'no_root'],
  ['no_root', true, 'timeline_no_game_root_omission'], ['unavailable', false, 'zk_state_unavailable'],
]) {
  const report = createReport();
  recordZkpState({ report }, { anomalies: [], timelineNoGame }, { kind, currentProofRequired: false });
  const entry = report.get('check.stageC.zkVerifierIdentity');
  eq([entry.status, entry.params.reason], ['skip', reason], `FIX1: ${kind}のskip理由`);
  eq(entry.params.reason, report.get('check.stageC.zkProofFormat').params.reason, 'FIX1: 他のZKP検査と同じ理由');
}
// F2: 公開値の保証の有無で⓪を分ける。③の理由と優先順位は変えない。
{
  const report = zkpReport();
  for (const id of ['zkVerifierIdentity', 'merkleRoot', 'evidenceReportMatch', 'futureAnchorsHash'])
    report.check(`check.stageC.${id}`, 'fail');
  expectZkp('FIX1: verifier不一致をF2より優先', report, proofContext, 'notVerified.zkVerifier');
}
for (const id of ['check.stageC.merkleRoot', 'check.stageC.evidenceReportMatch']) {
  for (const provider of [null, 'fixture-provider', undefined]) for (const publicStatus of ['pass', 'skip', 'fail', 'warn']) {
    const report = zkpReport(); report.check(id, 'fail');
    // zkEpoch の WARN は coverage=verified でも canGuarantee=false となる形。
    report.check(publicStatus === 'warn' ? 'check.stageC.zkEpoch' : 'check.stageC.zkPublicValues', publicStatus);
    if (provider !== null) report.check('check.stageC.futureAnchorsHash', 'fail');
    const context = { ...proofContext, data: { zkInfo: { kind: 'proof' }, futureAnchorCheck: { provider } } };
    const reason = provider === null ? 'proofRootMismatch' : 'proofRootProviderMismatch';
    const label = `FIX2 F2/${id}/${provider}/${publicStatus}`;
    const guaranteed = publicStatus === 'pass';
    const output = expectZkp(label, report, context, guaranteed ? 'notVerified.zkRootMismatch' : 'notVerified.zkProof',
      guaranteed ? undefined : reason, { provider: provider ?? 'unavailable' });
    const resultLines = output.lines.filter((line) => line.startsWith('  ③ '));
    eq(resultLines, ['  ' + t('ja')('notVerified.results', { reason: t('ja')(`reason.${reason}`, { provider: provider ?? 'unavailable' }) })], 'FIX2 F2: ③だけを照合し、既存の理由を保持');
    if (guaranteed) {
      expectVerifiedRow(report, output, 'ja', 'proofPublicValues', true);
      const zero = output.conclusions.find(({ key }) => key === 'notVerified.zkRootMismatch');
      eq(zero.params, undefined, 'FIX2 G1: 新文に理由を差し込まない');
    } else {
      ok(!output.part.includes(rowText('ja', 'proofPublicValues', true)), 'FIX2 G1: 公開値の保証がない盤');
      const zero = output.conclusions.find(({ key }) => key === 'notVerified.zkProof');
      eq(zero.params.reason, t('ja')(`reason.${reason}`, { provider: provider ?? 'unavailable' }), 'FIX2 G1: 旧文には③と同じ理由');
    }
    expectZkpConsistency(output, label);
    if (provider === null && guaranteed) for (const area of ['proofPublicValues', 'proofHistory'])
      eq(verificationCoverage(report).find((row) => row.area === area).verified, true, `F2: ${area}はverified`);
    if (id === 'check.stageC.merkleRoot' && provider === null && guaranteed) summaryExamples.rootMismatchPublicGuaranteed = output.lines;
  }
}
// F3: 公開ノードの形では公開値の保証を残し、証明時点の状態だけ未検証にする。
{
  const report = zkpReport(); report.unverified('check.stageC.futureAnchorsHash', new ArchiveUnavailableError());
  const output = expectZkp('F3公開ノード', report, proofContext, 'notVerified.zkProofHistory', 'archiveUnavailable');
  expectVerifiedRow(report, output, 'ja', 'proofPublicValues', true);
  eq(verificationCoverage(report).find((row) => row.area === 'proofHistory').verified, false, 'F3: 証明時点の状態は未検証');
  expectZkpConsistency(output, 'FIX2 F3公開ノード');
}
const zkCases = [
  { name: 'Z0 root省略終端', kind: 'no_root', omitted: true },
  { name: 'Z0はZ1より優先', missing: true, omitted: true },
  { name: 'Z0はZ2より優先', kind: 'shadow', omitted: true, wiring: true },
  { name: 'Z0は証明つきでも抑止', kind: 'proof', omitted: true },
  { name: 'Z1状態未到達', missing: true, key: 'notVerified.zk', reason: 'stopped' },
  { name: 'Z1はZ2より優先', missing: true, wiring: true, key: 'notVerified.zk', reason: 'stopped' },
  { name: 'Z1 zkInfoが存在すればkind欠落でもfallbackしない', info: {}, statusKind: 'proof', key: 'notVerified.zk', reason: 'stopped' },
  ...['proof', 'shadow', 'unavailable', 'no_root'].map((kind) => ({ name: `Z2配線FAIL/${kind}`, kind, wiring: true, key: 'notVerified.zk', reason: 'failed' })),
  ...['unexpected', '', 0].map((kind) => ({ name: `未知kind/${kind}`, kind, key: 'notVerified.zk', reason: 'failed' })),
  { name: 'Z3取得不能', kind: 'unavailable', key: 'notVerified.zk', reason: 'failed' },
  { name: 'Z4 root未提出', kind: 'no_root', key: 'notVerified.zk', reason: 'notReady' },
  { name: 'Z5 shadow', kind: 'shadow', key: 'conclusion.zkShadow' },
  { name: 'Z5本番パラメータ差はsystemFailedでない', kind: 'shadow', changes: [['check.system.productionParams', 'fail']], key: 'conclusion.zkShadow' },
  { name: 'Z5の後の①②③が全て未検証でも見出しを出す', kind: 'shadow', sparse: true, key: 'conclusion.zkShadow' },
  { name: 'Z6証明つき', kind: 'proof', key: 'conclusion.zkProof' },
  { name: 'Z6の後の①②③が全て未検証でも見出しを出す', kind: 'proof', sparse: true, key: 'conclusion.zkProof' },
  { name: 'Z6 ctxのproofをstatusのshadowより優先', kind: 'proof', statusKind: 'shadow', key: 'conclusion.zkProof' },
  { name: 'Z5 ctxのshadowをstatusのproofより優先', kind: 'shadow', statusKind: 'proof', key: 'conclusion.zkShadow' },
  ...['proof', 'shadow', 'no_root', 'unavailable'].map((kind) => ({
    name: `状態レコードへfallback/${kind}`, statusOnly: true, statusKind: kind,
    key: kind === 'proof' ? 'conclusion.zkProof' : kind === 'shadow' ? 'conclusion.zkShadow' : 'notVerified.zk',
    reason: kind === 'no_root' ? 'notReady' : kind === 'unavailable' ? 'failed' : undefined,
  })),
  { name: 'Z0のstateだけでは抑止しない', kind: 'shadow', stateOnly: true, key: 'conclusion.zkShadow' },
  { name: 'Z0のtimelineだけでは抑止しない', kind: 'no_root', timelineOnly: true, key: 'notVerified.zk', reason: 'notReady' },
];
for (const [area, id] of [['proofPublicValues', 'check.stageC.zkPublicValues'], ['proofHistory', 'check.stageC.futureAnchorsHash']]) {
  for (const status of ['unrun', 'skip', 'fail', 'archive']) zkCases.push({
    name: `Z7/${area}/${status}`, kind: 'proof', changes: [[id, status]], key: area === 'proofHistory' ? 'notVerified.zkProofHistory' : 'notVerified.zkProof',
    reason: status === 'fail' ? 'failed' : status === 'archive' ? 'archiveUnavailable' : 'stopped',
  });
}
for (const status of ['warn', 'skip']) zkCases.push({
  name: `Z7公開値verifiedでも保証なし/${status}`, kind: 'proof', changes: [['check.stageC.zkEpoch', status]],
  key: 'notVerified.zkProof', reason: 'failed', publicValuesVerified: true,
});
zkCases.push(
  { name: 'Z7公開値の理由を履歴FAILより優先', kind: 'proof', changes: [['check.stageC.zkPublicValues', 'archive'], ['check.stageC.futureAnchorsHash', 'fail']], key: 'notVerified.zkProof', reason: 'archiveUnavailable' },
  { name: 'Z7公開値保証なしを履歴archiveより優先', kind: 'proof', changes: [['check.stageC.zkEpoch', 'skip'], ['check.stageC.futureAnchorsHash', 'archive']], key: 'notVerified.zkProof', reason: 'failed' },
  { name: 'Z7公開値stoppedを履歴archiveより優先', kind: 'proof', changes: [['check.stageC.zkPublicValues', 'skip'], ['check.stageC.futureAnchorsHash', 'archive']], key: 'notVerified.zkProof', reason: 'stopped' },
  { name: 'Z7証人FAILは履歴verifiedでない', kind: 'proof', changes: [['check.stageC.zkPrevRegistrationWitness', 'fail']], key: 'notVerified.zkProofHistory', reason: 'failed' },
  { name: 'Z7証人archiveは履歴verifiedでない', kind: 'proof', changes: [['check.stageC.zkPrevRegistrationWitness', 'archive']], key: 'notVerified.zkProofHistory', reason: 'archiveUnavailable' },
);
for (const scenario of zkCases) {
  const changes = scenario.changes ?? [];
  const report = zkpReport((id) => (scenario.sparse && !/check\.stageC\.(?:zk|futureAnchorsHash)/.test(id))
    || (scenario.missing && id === 'check.stageC.zkProofStatus')
    || changes.some(([changedId, status]) => id === changedId && status === 'unrun'));
  for (const [id, status] of changes) {
    if (status === 'archive') report.unverified(id, new ArchiveUnavailableError());
    else if (status !== 'unrun') report.check(id, status);
  }
  if (!scenario.missing) report.check('check.stageC.zkProofStatus', 'pass', { kind: scenario.statusKind ?? scenario.kind });
  if (scenario.wiring) report.check('check.system.evidenceStartPastTolerance', 'fail');
  if (scenario.omitted || scenario.timelineOnly) report.fact('stageC.timelineNoGame', true);
  if (scenario.omitted || scenario.stateOnly) report.fact('stageC.timelineNoGameRoot', { state: 'omitted_terminal', rootSubmissionDeadlineSec: 1788483600 });
  const data = scenario.missing || scenario.statusOnly ? {} : { zkInfo: scenario.info ?? { kind: scenario.kind } };
  const output = expectZkp(scenario.name, report, { ...proofContext, data }, scenario.key, scenario.reason);
  if (scenario.publicValuesVerified) expectVerifiedRow(report, output, 'ja', 'proofPublicValues', false);
}
for (const lang of SUPPORTED_LANGS) for (const key of Object.keys(jaZkp)) {
  const text = t(lang)(key, { block: 17, reason: 'REASON_SENTINEL' });
  ok(text.startsWith('⓪ ') && text !== key && !/\{(?:block|reason)\}/.test(text), `${lang}/${key}: 鍵が引けて変数が埋まる`);
  if (key === 'notVerified.zkRootMismatch') eq(text, rootMismatchText[lang], `${lang}/${key}: 指定の全文・理由なし`);
  else ok(text.includes(key.startsWith('conclusion.') ? '17' : key === 'notVerified.zkVerifier' ? 'SP1' : 'REASON_SENTINEL'), `${lang}/${key}: 値が脱落しない`);
  if (lang === 'ja') eq(text, jaZkp[key].replaceAll('{block}', '17').replaceAll('{reason}', 'REASON_SENTINEL'), `${key}: 日本語の全文`);
}
if (!mutation) for (const name of Object.keys(mutations)) {
  for (const block of name === 'q2b' ? [0, 1] : [null]) {
    const args = [import.meta.filename, '--mutation=' + name, ...(block == null ? [] : ['--witness-block=' + block])];
    const result = spawnSync(process.execPath, args, { encoding: 'utf8', env: process.env });
    const label = `${name}${block == null ? '' : `/block${block}`}`;
    eq(result.status, 1, `${label}: 変異で赤`);
    ok(result.stdout.includes(`MUTATION_APPLIED ${name}`) && result.stderr.includes('AssertionError'), `${label}: 起動失敗でなくassertionで検出`);
    if (block != null) ok(result.stderr.includes(`Z6 real witness block ${block}`), `${label}: 実関数による正常系で検出`);
    console.log(`MUTANT_KILLED ${label}: assertion`);
  }
}
console.log(`fix14-summary-unit: PASS (${assertions} assertions; ${Object.keys(mutations).length} mutants killed)`);
if (process.argv.includes('--summary-examples')) console.log('SUMMARY_FIX2_EXAMPLES ' + JSON.stringify(summaryExamples));

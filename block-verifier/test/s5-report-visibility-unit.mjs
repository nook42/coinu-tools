// S5 INV-01 / A-02 / CW-01 / CW-02 / CW-03 の表示・結論ゲート回帰。
import { readFileSync } from 'node:fs';

import { CHECK_INVENTORY } from '../src/check-inventory.js';
import { SUPPORTED_LANGS, t } from '../src/i18n.js';
import { VERIFICATION_AREAS } from '../src/verification-areas.js';
import {
  createReport,
  messageId,
  registrationHistoryKind,
  stageVerdictIssues,
} from '../src/report.js';

const MUTATION = process.argv.find((arg) => arg.startsWith('--mutation='))?.split('=')[1] || null;

let passed = 0;
let failed = 0;
const ok = (label, condition, detail = '') => {
  if (condition) { passed++; console.log(`  ok: ${label}`); }
  else { failed++; console.error(`  NG: ${label}${detail ? ` — ${detail}` : ''}`); }
};

const ctx = { blockNum: 7, data: {}, r2: { baseDir: '/tmp/block7' } };

function completeReport() {
  const report = createReport();
  for (const id of CHECK_INVENTORY) report.check(id, 'pass');
  report.check('check.stageA.registrationCount', 'pass', { count: 1 });
  report.fact('hashRegisteredTime', '2026-09-04T00:00:00.000Z');
  report.fact('totalEntries', 2100);
  report.fact('applicantHash', '0xabc');
  report.fact('hashRegisteredBlock', 100);
  report.fact('totalSelected', 2100);
  report.fact('targetBlockNum', 123);
  report.fact('targetBlockTime', '2026-09-05T00:00:00.000Z');
  report.fact('totalGroups', 0);
  report.fact('stageC.blockReward', '1000000000000000000');
  report.fact('stageC.playerCount', 2100);
  report.fact('stageC.groupCount', 0);
  report.fact('stageC.disqualifiedCount', 0);
  report.fact('stageC.verificationStartedAt', { iso: '2026-09-05T01:00:00.000Z' });
  report.fact('stageC.verificationEndsAt', { iso: '2026-09-09T01:00:00.000Z' });
  report.fact('stageC.claimWindow', { endIso: '2026-10-19T01:00:00.000Z' });
  return report;
}

function render(report, translate) {
  const lines = [];
  report.renderSummary({ t: translate, println: (line = '') => lines.push(String(line)) }, ctx);
  return lines.join('\n');
}

for (const lang of SUPPORTED_LANGS) {
  const translate = t(lang);

  const timeline = completeReport();
  timeline.fact('stageC.noGame', true);
  timeline.fact('stageC.timelineNoGame', true);
  const output = render(timeline, translate);
  const selectionOperational = translate('conclusion.selectionTimelineNoGame', {
    block: 7, selected: 2100, total: 2100, targetBlock: 123,
    time: '2026-09-05T00:00:00.000Z', groups: 0,
  });
  const resultsOperational = translate('conclusion.resultsTimelineNoGame', {
    block: 7, reward: '1.00', players: 2100, groups: 0, dq: 0,
    rootTime: '2026-09-05T01:00:00.000Z', verEnd: '2026-09-09T01:00:00.000Z',
    claimEnd: '2026-10-19T01:00:00.000Z',
  });
  ok(`${lang} INV-01: ②は当選者2100名と運営の申告を明記`, output.includes(selectionOperational));
  ok(`${lang} INV-01: ③もtimeline未検証専用文言`, output.includes(resultsOperational));
  ok(`${lang} INV-01: 0名専用の②③を流用しない`,
    !output.includes(translate('conclusion.selectionNoGame', {}))
      && !output.includes(translate('conclusion.resultsNoGame', { rootTime: '2026-09-05T01:00:00.000Z' })));

  // Q46: proofRequired後の timeline no-game は、期限後なら root=0 自体が検証済みの終端。
  // shadow期に手動提出されたrootありの上記結論も履歴互換として残す。
  const omitted = completeReport();
  omitted.fact('stageC.noGame', true);
  omitted.fact('stageC.timelineNoGame', true);
  omitted.fact('stageC.timelineNoGameRoot', {
    state: 'omitted_terminal',
    rootSubmissionDeadlineSec: 2_000_000_000,
  });
  omitted.check('check.stageC.rootSubmitted', 'pass', {
    reason: 'expected_timeline_no_game_omission',
    deadline: 2_000_000_000,
  });
  const omittedOutput = render(omitted, translate);
  const omittedConclusion = translate('conclusion.resultsTimelineNoGameRootOmitted', {
    block: 7, reward: '1.00', players: 2100, groups: 0, dq: 0,
    rootTime: '2026-09-05T01:00:00.000Z', verEnd: '2026-09-09T01:00:00.000Z',
    claimEnd: '2026-10-19T01:00:00.000Z', rootDeadline: '2033-05-18T03:33:20.000Z',
  });
  ok(`${lang} Q46: rootなし期限後は期待どおりの終端を明示`,
    omittedOutput.includes(omittedConclusion), omittedOutput);
  ok(`${lang} Q46: rootなし終端をshadow期のrootあり結論と混同しない`,
    !omittedOutput.includes(resultsOperational));

  // T5-03: noGame成果物から障害原因そのものは検証できない。運営の申告と検証済み事実を
  // 3言語とも明示的に分け、どれか1言語だけ断定形へ戻っても落とす。
  const causeMarkers = {
    en: ['operator reports', 'reported cause has not been verified'],
    ja: ['運営は', '申告', '原因は検証できていません'],
    zh: ['运营方声称', '所声称的原因尚未核验'],
  }[lang];
  const conclusions = [
    translate('conclusion.selectionTimelineNoGame', { selected: 2100, total: 2100 }),
    translate('conclusion.resultsTimelineNoGame', { players: 2100, rootTime: '2026-09-05T01:00:00.000Z' }),
  ];
  if (MUTATION === 'ja-unverified-cause-assertion' && lang === 'ja') {
    conclusions[0] = '② 当選者2100名が選ばれましたが、運営側の障害によりチャットゲームは行われませんでした。';
  }
  for (const [index, conclusion] of conclusions.entries()) {
    ok(`${lang} T5-03/${index + 2}: 運営の申告と未検証原因を区別`,
      causeMarkers.every((marker) => conclusion.includes(marker)), conclusion);
  }

  const stageCFail = completeReport();
  stageCFail.fact('stageC.noGame', true);
  stageCFail.fact('stageC.timelineNoGame', true);
  stageCFail.check('check.stageC.timelineNoGameSummary', 'fail', { injected: true });
  const failedOutput = render(stageCFail, translate);
  ok(`${lang} A-02: Stage C FAIL時は②の運用障害結論を取り下げる`,
    !failedOutput.includes(selectionOperational)
      && failedOutput.includes(translate('notVerified.selection', { reason: translate('reason.failed') })));

  const sparse = createReport();
  sparse.check('check.stageB.selectionPresent', 'skip', { n: 7 });
  const sparseOutput = render(sparse, translate);
  // CHECK_INVENTORY 115件のうち1件だけ記録した盤面では、未到達は114件。
  // （便 C30F1b: 便 C30F1 の check.system.evidenceHashStorage を在庫へ足して 102 → 103。
  //   便 S3C14: 応募鍵の入口迂回を示す check.stageA.entryKeyIntegrity を在庫へ追加〈main 側で 103 → 104〉。
  //   便 C32F2: check.system.evidenceStartPastTolerance を在庫へ足して〈契約側で 103 → 104〉。
  //   2026-09-28 Stage 3 再レビュー周1 段0 の C32 の合流で両方を合わせて 105・未到達 104）。
  // WR-3-FIX1 が check.stageC.autoRoster を1件追加したため、110 → 111・未到達109 → 110。
  ok(`${lang} CW-03: 未到達の詳細節は省き、件数行は保持`,
    CHECK_INVENTORY.length === 115
      && !sparseOutput.includes(translate('summary.unrunHeader', { count: 114 }))
      && sparseOutput.includes(translate('summary.counts', { pass: 0, warn: 0, fail: 0, skip: 1, unrun: 114 })));
  ok(`${lang} CW-03: 未到達検査IDを列挙しない`,
    !sparseOutput.includes('check.stageA.rootMatch')
      && !sparseOutput.includes('check.stageC.archiveChainConsistency'));
  for (const { area } of VERIFICATION_AREAS) {
    const row = `  ${translate(`summary.area.${area}`)}: `;
    ok(`${lang} CW-03: 未到達のある ${area} を未検証として表示`,
      sparseOutput.includes(row + translate('summary.areaUnverified', { reason: translate('reason.stopped') }))
        && !sparseOutput.slice(sparseOutput.indexOf(translate('summary.coverageVerified')), sparseOutput.indexOf(translate('summary.coverageUnverified'))).includes(row));
  }
}

// CW-01: system FAILはStage A/B/Cすべての上流FAIL。同ステージWARN/SKIPも✅候補にしない。
const upstream = createReport();
upstream.check('check.system.hashStorageWiring', 'fail');
const beforeA = upstream.list().length;
upstream.check('check.stageA.rootMatch', 'pass');
ok('CW-01: Stage A判定が開始前のsystem FAILを拾う',
  stageVerdictIssues(upstream, 'A', beforeA).firstFail?.id === 'check.system.hashStorageWiring');

const warning = createReport();
const beforeWarning = warning.list().length;
warning.check('check.stageC.resultReregistration', 'warn');
ok('CW-01: 同ステージWARNを判定材料にする',
  stageVerdictIssues(warning, 'C', beforeWarning).firstWarn?.id === 'check.stageC.resultReregistration');

const skipped = createReport();
const beforeSkip = skipped.list().length;
skipped.check('check.stageC.timelineWindows', 'skip');
ok('CW-01: 同ステージSKIPを判定材料にする',
  stageVerdictIssues(skipped, 'C', beforeSkip).firstSkip?.id === 'check.stageC.timelineWindows');

// CW-02は全ID結論ゲート試験でも固定するが、HashStorage配線の具体例もここで明示する。
for (const lang of SUPPORTED_LANGS) {
  const translate = t(lang);
  const wiringFail = completeReport();
  wiringFail.check('check.system.hashStorageWiring', 'fail');
  const output = render(wiringFail, translate);
  ok(`${lang} CW-02: HashStorage配線FAIL時は①の固定済み断言を出さない`,
    !output.includes(translate('conclusion.entries', {
      block: 7, time: '2026-09-04T00:00:00.000Z', total: 2100,
      hash: '0xabc', ethBlock: 100, folder: '/tmp/block7',
    })));
}

// T8 V2: 再登録時の全履歴は監査材料なので、通常detailの300文字省略を適用しない。
const registrationDetailReport = completeReport();
const registrationDetails = Array.from({ length: 6 }, (_, index) => ({
  index,
  registeredBlock: 100 + index,
  hash: `0x${String(index).repeat(64)}`,
  matchesRoot: index === 0,
}));
registrationDetailReport.check('check.stageA.registrationCount', 'warn', {
  count: registrationDetails.length,
  registrations: registrationDetails,
});
const registrationDetailOutput = render(registrationDetailReport, t('ja'));
ok('registration_list_in_detail: WARN表示が全登録を末尾まで省略しない',
  registrationDetailOutput.includes(JSON.stringify(registrationDetails.at(-1)))
    && registrationDetailOutput.includes('"registrations"'));

// Q14: 登録回数×検証時点の全数表。終了コードの分類材料（FAIL・停止）とWARN件数は
// 表示文の選択から独立したまま固定し、3言語の意味を揃える。
const q14HashA = `0x${'aa'.repeat(32)}`;
const q14HashB = `0x${'bb'.repeat(32)}`;
const q14Scenarios = [
  { name: 'once', hashes: [q14HashA], status: 'pass', kind: 'unknown' },
  { name: 'twice_same', hashes: [q14HashA, q14HashA], status: 'warn', kind: 'same' },
  { name: 'twice_different', hashes: [q14HashA, q14HashB], status: 'warn', kind: 'different' },
  { name: 'three_mixed', hashes: [q14HashA, q14HashA, q14HashB], status: 'warn', kind: 'different' },
];
const q14Timings = ['before_lottery', 'after_lottery_before_grouping', 'after_grouping'];
const q14IndexSource = readFileSync(new URL('../src/index.js', import.meta.url), 'utf8');
ok('Q14 V1 wiring: ステージ判定行のFAIL/WARNも表示用messageIdを通す',
  q14IndexSource.includes("t(messageId(firstFail), displayParams(firstFail.params, t))")
    && q14IndexSource.includes("t(messageId(firstWarn), displayParams(firstWarn.params, t))"));

function q14RegistrationEntry(scenario) {
  return {
    id: 'check.stageA.registrationCount',
    status: scenario.status,
    params: {
      count: scenario.hashes.length,
      registrations: scenario.hashes.map((hash, index) => ({
        index,
        registeredBlock: 100 + index,
        hash,
        matchesRoot: hash === q14HashA,
      })),
    },
  };
}

function q14Report(scenario, timing) {
  const report = createReport();
  const registration = q14RegistrationEntry(scenario);
  report.check('check.stageA.applicantHashRegistered', 'pass');
  report.check('check.stageA.rootMatch', 'pass');
  report.check('check.stageA.earlyFreeze', 'pass');
  report.check(registration.id, registration.status, registration.params);
  report.fact('hashRegisteredTime', '2026-09-04T00:00:00.000Z');
  report.fact('totalEntries', 4);
  report.fact('applicantHash', q14HashA);
  report.fact('hashRegisteredBlock', 100);
  report.fact('totalSelected', 4);
  report.fact('targetBlockNum', 123);
  report.fact('targetBlockTime', '2026-09-05T00:00:00.000Z');
  report.fact('totalGroups', 1);

  if (timing === 'before_lottery') {
    report.check('check.stageB.selectionPresent', 'skip');
  } else {
    report.check('check.stageB.selectionPresent', 'pass');
    report.check('check.stageB.playersMatch', 'pass');
    report.check('check.stageB.randao', 'pass');
    if (timing === 'after_lottery_before_grouping') {
      report.check('check.stageB.groupsPresent', 'skip');
    } else {
      report.check('check.stageB.groupsPresent', 'pass');
      report.check('check.stageB.groupsMatch', 'pass');
      report.check('check.stageC.rootSubmitted', 'skip');
    }
  }
  return { report, registration, stopped: true };
}

const q14MatrixRows = [];
for (const scenario of q14Scenarios) {
  const registration = q14RegistrationEntry(scenario);
  ok(`Q14 history_kind ${scenario.name}: チェーン履歴hashで同一／差し替えを分類`,
    registrationHistoryKind(registration) === scenario.kind);
  const expectedMessageId = scenario.status === 'pass'
    ? 'check.stageA.registrationCount'
    : `check.stageA.registrationCountWarn${scenario.kind === 'same' ? 'Same' : 'Different'}`;
  ok(`Q14 V1/V2 ${scenario.name}: 回数と履歴内容に合う判定文を選ぶ`,
    messageId(registration) === expectedMessageId);

  for (const timing of q14Timings) {
    const state = q14Report(scenario, timing);
    const warnings = state.report.list().filter((entry) => entry.status === 'warn');
    const exitCode = state.report.hasFail() ? 2 : (state.stopped ? 1 : 0);
    ok(`Q14 invariant ${scenario.name}/${timing}: WARN有無を維持`,
      warnings.length === (scenario.status === 'warn' ? 1 : 0));
    ok(`Q14 invariant ${scenario.name}/${timing}: 未完了の終了コードは1`, exitCode === 1);
    q14MatrixRows.push(`${scenario.name}|${timing}|warn=${warnings.length}|exit=${exitCode}`);

    for (const lang of SUPPORTED_LANGS) {
      const translate = t(lang);
      const output = render(state.report, translate);
      const oneTimeText = translate('check.stageA.registrationCount', { count: scenario.hashes.length });
      if (scenario.status === 'warn') {
        const selectedWarning = translate(expectedMessageId, registration.params);
        ok(`Q14 V1 ${lang}/${scenario.name}/${timing}: 複数登録を「1回のみ」と表示しない`,
          output.includes(selectedWarning) && !output.includes(oneTimeText));
      } else {
        ok(`Q14 V1 ${lang}/${scenario.name}/${timing}: 1回登録は「1回のみ」を維持`,
          !output.includes(translate('check.stageA.registrationCountWarnSame', registration.params))
            && !output.includes(translate('check.stageA.registrationCountWarnDifferent', registration.params)));
      }

      if (timing === 'after_lottery_before_grouping') {
        const ordinary = translate('conclusion.selectionOnly', {
          block: 7, selected: 4, total: 4, targetBlock: 123,
          time: '2026-09-05T00:00:00.000Z', groups: 1,
        });
        if (scenario.status === 'warn') {
          const warningKey = `conclusion.selectionOnlyRegistrationWarning${scenario.kind === 'same' ? 'Same' : 'Different'}`;
          const warningText = translate(warningKey, {
            block: 7, selected: 4, total: 4, targetBlock: 123,
            time: '2026-09-05T00:00:00.000Z', groups: 1, count: scenario.hashes.length,
          });
          const undecided = { en: 'cannot yet be determined', ja: 'まだ判断できません', zh: '尚无法判断' }[lang];
          ok(`Q14 V3 ${lang}/${scenario.name}: grouping前は裁量なしと断言せず未判断を表示`,
            output.includes(warningText) && warningText.includes(undecided) && !output.includes(ordinary));
        } else {
          ok(`Q14 V3 ${lang}/${scenario.name}: 1回登録は従来の抽選結論を維持`, output.includes(ordinary));
        }
      }

      if (timing === 'after_grouping' && scenario.status === 'warn') {
        const warningKey = `conclusion.selectionRegistrationWarning${scenario.kind === 'same' ? 'Same' : 'Different'}`;
        const warningText = translate(warningKey, {
          block: 7, selected: 4, total: 4, targetBlock: 123,
          time: '2026-09-05T00:00:00.000Z', groups: 1, count: scenario.hashes.length,
        });
        const ordinary = translate('conclusion.selection', {
          block: 7, selected: 4, total: 4, targetBlock: 123,
          time: '2026-09-05T00:00:00.000Z', groups: 1, count: scenario.hashes.length,
        });
        ok(`Q14 V2/V3 ${lang}/${scenario.name}: grouping後も内容分類し裁量なしと断言しない`,
          output.includes(warningText) && !output.includes(ordinary));
      }
    }
  }
}
console.log(`Q14_MATRIX ${q14MatrixRows.join(',')}`);

for (const scenario of q14Scenarios.filter(({ status }) => status === 'warn')) {
  const state = q14Report(scenario, 'after_lottery_before_grouping');
  state.report.fact('totalEntries', 2);
  state.report.fact('totalSelected', 2);
  state.report.check('check.stageB.groupingSkippedAuto', 'skip');
  for (const lang of SUPPORTED_LANGS) {
    const translate = t(lang);
    const output = render(state.report, translate);
    const warningKey = `conclusion.selectionAutoRegistrationWarning${scenario.kind === 'same' ? 'Same' : 'Different'}`;
    const warningText = translate(warningKey, {
      block: 7, selected: 2, total: 2, targetBlock: 123,
      time: '2026-09-05T00:00:00.000Z', groups: 1, count: scenario.hashes.length,
    });
    ok(`Q14 V3 auto ${lang}/${scenario.name}: 自動配布でも複数登録なら裁量なしと断言しない`,
      output.includes(warningText)
        && !output.includes(translate('conclusion.selectionAuto', {
          block: 7, selected: 2, total: 2, targetBlock: 123,
          time: '2026-09-05T00:00:00.000Z', groups: 1,
        })));
  }
}

for (const lang of SUPPORTED_LANGS) {
  const translate = t(lang);
  const same = translate('check.stageA.registrationCountWarnSame', { count: 2 });
  const different = translate('check.stageA.registrationCountWarnDifferent', { count: 2 });
  const sameMarkers = {
    en: ['same hash', 'did not change'],
    ja: ['同じハッシュ', '内容は変わっていません'],
    zh: ['哈希均相同', '内容没有变化'],
  }[lang];
  const differentMarkers = {
    en: ['different hashes', 'was replaced'],
    ja: ['異なるハッシュ', '差し替えがありました'],
    zh: ['不同哈希', '曾被替换'],
  }[lang];
  ok(`Q14 V2 ${lang}: 同一内容の登録し直しを明記`, sameMarkers.every((marker) => same.includes(marker)));
  ok(`Q14 V2 ${lang}: 異なる内容への差し替えを明記`,
    differentMarkers.every((marker) => different.includes(marker)) && same !== different);
}

for (const lang of SUPPORTED_LANGS) {
  const translate = t(lang);
  const recomputed = `0x${'11'.repeat(32)}`;
  const latest = `0x${'22'.repeat(32)}`;
  const noMatchReason = 'no_matching_registration_at_or_after_entry_deadline';
  const earlyReason = 'first_matching_registration_before_entry_deadline';
  const noMatch = completeReport();
  noMatch.check('check.stageA.rootMatch', 'fail', { recomputed, latest, reason: noMatchReason });
  const early = completeReport();
  early.check('check.stageA.rootMatch', 'fail', { recomputed, latest, reason: earlyReason });
  const noMatchOutput = render(noMatch, translate);
  const earlyOutput = render(early, translate);
  const noMatchText = translate('stageA.rootMatchFail.noMatchingAfterDeadline', { recomputed, latest });
  const earlyText = translate('stageA.rootMatchFail.firstMatchingBeforeDeadline', { recomputed, latest });
  const noMatchBanner = translate('stageA.rootMismatch', {
    recomputed,
    latest,
    reason: translate(`stageA.rootMismatchReason.${noMatchReason}`),
  });
  const earlyBanner = translate('stageA.rootMismatch', {
    recomputed,
    latest,
    reason: translate(`stageA.rootMismatchReason.${earlyReason}`),
  });
  ok(`rootmatch_fail_text_by_reason (${lang}): 締切後一致なし／最初の一致が締切前を区別`,
    noMatchOutput.includes(noMatchText)
      && earlyOutput.includes(earlyText)
      && noMatchText !== earlyText
      && noMatchBanner !== earlyBanner
      && noMatchBanner.includes(latest)
      && earlyBanner.includes(latest));

  const unavailable = completeReport();
  unavailable.check('check.stageA.registrationCount', 'warn', {
    count: 'unavailable', registrations: [], error: 'history getter failed',
  });
  const unavailableOutput = render(unavailable, translate);
  ok(`registration_count_unavailable_text (${lang}): 回数でなく履歴読取不能を表示`,
    unavailableOutput.includes(translate('stageA.registrationCountUnavailable'))
      && !unavailableOutput.includes(translate('check.stageA.registrationCountWarn', { count: 'unavailable' })));

  const legacyLatest = completeReport();
  legacyLatest.check('check.stageA.registrationCount', 'warn', {
    count: 1, registrations: registrationDetails.slice(0, 1), legacyLatestOnly: true,
  });
  const legacyOutput = render(legacyLatest, translate);
  ok(`legacy_latest_only_text (${lang}): 旧契約は履歴getterなしで最新1件だけと表示`,
    legacyOutput.includes(translate('stageA.registrationCountLegacyLatestOnly'))
      && !legacyOutput.includes(translate('check.stageA.registrationCountWarn', { count: 1 })));
}

console.log(`\ns5-report-visibility-unit: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);

// Request3 T-12: rosterLiveAnchor=warn の最終結論は通常PASS文言を流用せず、
// en / ja / zh の各言語で警告専用文言を出す。
import { createReport } from '../src/report.js';
import { SUPPORTED_LANGS, t } from '../src/i18n.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

let failed = 0;
const assert = (condition, label) => {
  if (condition) console.log(`ok: ${label}`);
  else { console.error(`NG: ${label}`); failed++; }
};

const resultsSource = readFileSync(
  fileURLToPath(new URL('../src/stages/results.js', import.meta.url)),
  'utf8',
);
assert(
  resultsSource.includes("failures.push('on-chain roster hash is unregistered')"),
  '未登録アンカーはFAILへ積む',
);
assert(
  resultsSource.includes("failures.push('on-chain roster hash was registered at or after chattingStart')"),
  'chattingStart以後のアンカーもFAILへ積む',
);
assert(
  !resultsSource.includes("warnings.push('on-chain roster hash is unregistered')")
    && !resultsSource.includes("warnings.push('on-chain roster hash was registered at or after chattingStart')"),
  '未登録・lateをWARNへ戻さない',
);
assert(
  resultsSource.includes('warnings.push(`anchor registration time could not be read:')
    && resultsSource.includes('warnings.push(`on-chain roster anchor could not be read:'),
  '検証者側RPC読取不能はWARNに留める',
);

for (const lang of SUPPORTED_LANGS) {
  const report = createReport();
  for (const id of ['check.stageC.depositVerification', 'check.stageC.merkleRebuild', 'check.stageC.merkleTotals']) report.check(id, 'pass');
  report.check('check.stageC.rootSubmitted', 'pass');
  report.check('check.stageC.summaryMatch', 'pass');
  report.check('check.stageC.merkleRoot', 'pass');
  report.check('check.stageC.onchainClaimData', 'pass');
  report.check('check.stageC.rosterLiveAnchor', 'warn', { warnings: 'unregistered' });
  report.fact('stageC.blockReward', '1000000000000000000');
  report.fact('stageC.playerCount', 4);
  report.fact('stageC.groupCount', 1);
  report.fact('stageC.disqualifiedCount', 0);
  report.fact('stageC.verificationStartedAt', { iso: '2026-08-17' });
  report.fact('stageC.verificationEndsAt', { iso: '2026-08-18' });
  report.fact('stageC.claimWindow', { endIso: '2026-08-19' });

  const translate = t(lang);
  const lines = [];
  report.renderSummary({ t: translate, println: (line) => lines.push(String(line)) }, {
    blockNum: 7, data: {}, r2: { baseDir: '/tmp/r2' },
  });
  const output = lines.join('\n');
  const warning = translate('conclusion.resultsRosterAnchorWarning', {
    block: 7, reward: '1.00', players: 4, groups: 1, dq: 0,
    rootTime: '2026-08-17', verEnd: '2026-08-18', claimEnd: '2026-08-19',
  });
  const ordinary = translate('conclusion.results', {
    block: 7, reward: '1.00', players: 4, groups: 1, dq: 0,
    rootTime: '2026-08-17', verEnd: '2026-08-18', claimEnd: '2026-08-19',
  });
  assert(warning !== ordinary, `T-12 ${lang}: warn専用文言は通常PASS文言と異なる`);
  assert(output.includes(warning), `T-12 ${lang}: renderSummary がwarn専用結論を出力する`);
  assert(!output.includes(ordinary), `T-12 ${lang}: 通常PASS結論を流用しない`);
}

console.log(failed === 0 ? 'ALL PASSED' : `${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);

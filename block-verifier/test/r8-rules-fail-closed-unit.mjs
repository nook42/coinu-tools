// REQUEST8 便E: 採点規則3キーは manifest から消しても逸脱として残る。
import { collectRequiredScoringRuleDeviations, collectStrictManifestRulePinDeviations,
  STRICT_MANIFEST_RULE_PIN_KEYS } from '../src/stages/results.js';
import { DEFAULTS } from '../src/config.js';
import { VISIBLE_CHARS_RULE_VERSION } from '../vendor/workers/game_workers/lib/char-counter.js';
import {
  REPORT_MIN_READ_RECEIPTS,
  REPORT_ELIGIBILITY_RULE_VERSION,
} from '../vendor/workers/game_workers/lib/protocol-v2.js';

const keys = ['visibleCharsRule', 'reportMinReadReceipts', 'reportEligibilityRule'];
const base = {
  visibleCharsRule: VISIBLE_CHARS_RULE_VERSION,
  reportMinReadReceipts: REPORT_MIN_READ_RECEIPTS,
  reportEligibilityRule: REPORT_ELIGIBILITY_RULE_VERSION,
};
let failures = 0;
const check = (condition, label) => {
  if (condition) console.log(`  ok: ${label}`);
  else {
    console.error(`  NG: ${label}`);
    failures++;
  }
};

check(collectRequiredScoringRuleDeviations(base, DEFAULTS.pins).length === 0,
  '3キーが正典値なら deviations は空');
for (const key of keys) {
  const mutated = { ...base };
  delete mutated[key];
  const deviations = collectRequiredScoringRuleDeviations(mutated, DEFAULTS.pins);
  check(deviations.includes(`${key}=undefined`),
    `manifest.rules.${key} を削除すると deviations に現れる`);
}

const headerKeys = ['ethereumHeaderRuleVersion', 'ethereumHeaderFork', 'confirmationBlocks'];
check(headerKeys.every((key) => STRICT_MANIFEST_RULE_PIN_KEYS.includes(key)),
  'Stage 4 header rulesの3キーは必須pinである');
const headerRules = Object.fromEntries(headerKeys.map((key) => [key, DEFAULTS.pins[key]]));
check(collectStrictManifestRulePinDeviations(headerRules, DEFAULTS.pins)
  .filter((deviation) => headerKeys.some((key) => deviation.startsWith(`${key}=`))).length === 0,
  '正しいheader rulesは逸脱しない');
for (const key of headerKeys) {
  const missing = { ...headerRules };
  delete missing[key];
  check(collectStrictManifestRulePinDeviations(missing, DEFAULTS.pins).includes(`${key}=undefined`),
    `${key}の未宣言を拒否する`);
  const wrong = { ...headerRules, [key]: 'wrong' };
  check(collectStrictManifestRulePinDeviations(wrong, DEFAULTS.pins).includes(`${key}=wrong`),
    `${key}の別値を拒否する`);
}

if (failures) {
  console.error(`\n❌ FAILED (${failures})`);
  process.exit(1);
}
console.log('\n✅ ALL PASSED');

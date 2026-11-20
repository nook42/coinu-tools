#!/usr/bin/env node

// REQUEST5: Web本体と recovery が同じ vendored A〜H 方針を実行すること。

import assert from 'node:assert/strict';
import { makeMaxAggregateFixture } from '../../workers/game_workers/script/test-calculator/_max-submission-fixture.mjs';
import {
  planOnChainTrim as planCanonical,
  signTrimmedPayload as signCanonicalTrimmedPayload,
} from '../../src/utils/evidence.js';
import {
  attributeResidualBytes,
  describeTrimPlan,
  planOnChainTrim as planRecovery,
  signTrimmedPayload as signRecoveryTrimmedPayload,
} from '../src/recovery/submit.js';
import { classifyEvidenceReceipts } from '../vendor/src/utils/evidence-trim-policy.js';

const fixture = await makeMaxAggregateFixture();
const [canonical, recovery] = await Promise.all([
  planCanonical(fixture.payload, fixture.submitter.uid),
  planRecovery(fixture.payload, fixture.submitter.uid),
]);

for (const key of [
  'droppedTotal', 'droppedH', 'droppedG', 'droppedF', 'droppedE', 'droppedD',
  'droppedA', 'droppedC', 'droppedR', 'droppedB', 'droppedV', 'essentialEvidenceDropped',
  'protectedA', 'protectedB', 'protectedC', 'protectedR', 'protectedV', 'beforeBytes', 'afterBytes',
  'beforeRawBytes', 'afterRawBytes', 'policyFallback',
  'gBefore', 'gAfter', 'droppedEPrime',
]) {
  assert.deepEqual(recovery[key], canonical[key], `plan.${key}`);
}
assert.deepEqual(recovery.classCounts, canonical.classCounts, 'A〜H分類数');
assert.deepEqual(recovery.thresholds, canonical.thresholds, 'B/D閾値到達値');
assert.deepEqual(
  recovery.trimmedBundle.encryptedActions.observed.receipts.map((receipt) => receipt.signature),
  canonical.trimmedBundle.encryptedActions.observed.receipts.map((receipt) => receipt.signature),
  '保持receipt集合・順序',
);
assert.deepEqual(
  recovery.trimmedBundle.encryptedActions.observed.selfReceiptAggregate,
  canonical.trimmedBundle.encryptedActions.observed.selfReceiptAggregate,
  'A aggregate',
);
const description = describeTrimPlan(recovery);
for (const priority of ['H', 'G', 'F', 'E', 'C', 'D', 'R', 'A', 'B', 'V']) {
  assert.match(description, new RegExp(`\\b${priority}\\b`), `${priority} の説明を表示`);
}

// A3-02: tx 送信ウォレットは任意だが、トリムで外側署名を作り直す場合だけは
// 元バンドルの署名者と同じでなければ採点で invalid_signature になる。
const wrongWallet = fixture.players.find((player) => player.uid !== fixture.submitter.uid).wallet;
const signedPayloads = new Map();
for (const [label, signTrimmedPayload, plan] of [
  ['Web本体', signCanonicalTrimmedPayload, canonical],
  ['recovery', signRecoveryTrimmedPayload, recovery],
]) {
  const signed = await signTrimmedPayload(plan.trimmedBundle, {
    blockNum: fixture.context.blockNum,
    compactContext: plan.compactContext,
    signMessage: (message) => fixture.submitter.wallet.signMessage({ message }),
  });
  assert.equal(typeof signed, 'string', `${label}: 元署名者による再署名は従来どおり通る`);
  signedPayloads.set(label, signed);
  await assert.rejects(
    signTrimmedPayload(plan.trimmedBundle, {
      blockNum: fixture.context.blockNum,
      compactContext: plan.compactContext,
      signMessage: (message) => wrongWallet.signMessage({ message }),
    }),
    /trimmed bundle was signed by a different wallet/,
    `${label}: 元署名者と異なるウォレットの再署名は fail-closed`,
  );
}
assert.equal(
  signedPayloads.get('recovery'),
  signedPayloads.get('Web本体'),
  'Web本体とrecoveryは同じtrim入力・署名からbyte-exactに同じpayloadを作る',
);

// 前処理自体が壊れても例外を提出経路へ漏らさず、削除禁止側へ倒す。
const malformedReceipt = { signature: 'fallback-receipt' };
const fallback = classifyEvidenceReceipts({
  bundle: {
    messages: [null],
    encryptedActions: { observed: { receipts: [malformedReceipt] } },
  },
  blockNum: 1,
  groupId: 1,
  myUid: 'self',
});
assert.equal(fallback.policyFallback, true, '前処理例外は fail-open');
assert.equal(fallback.priorities.get(malformedReceipt), 'B', '全legacyを削除禁止側へ昇格');

const residual = attributeResidualBytes({
  uid: '__proto__',
  messages: [{ uid: 'alice', text: 'x' }],
  encryptedActions: {
    votes: { alice: { encrypted: 'v' } },
    reports: {},
    observed: {
      votes: {}, reports: { bob: [{ encrypted: 'r' }] },
      receipts: [{ receiverUid: 'bob', msgRefs: [`0x${'00'.repeat(16)}`] }],
      selfReceiptAggregate: {
        version: 1, receiverUid: '__proto__', signature: 'sig',
        entries: [{ targetType: 'read', senderUid: 'alice', msgRef: `0x${'01'.repeat(16)}`, timestamp: 1 }],
      },
    },
  },
});
assert(residual instanceof Map, 'uid帰属は __proto__ / constructor で壊れない Map');
assert(residual.get('alice') > JSON.stringify({ uid: 'alice', text: 'x' }).length
  + JSON.stringify({ encrypted: 'v' }).length,
'自己受領集約のread entryをsenderUid=aliceへ按分する');
assert(residual.get('bob') > 0, 'legacy receiptとobserved actionをbobへ按分する');
assert(residual.get('__proto__') > 0, '特殊uuidを提出者帰属として保持する');

console.log('✅ recovery trim policy mirror PASSED');

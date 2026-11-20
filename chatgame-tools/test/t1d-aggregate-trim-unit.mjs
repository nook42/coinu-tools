import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { keccak256, toHex } from 'viem';
import { makeMaxAggregateFixture } from '../../workers/game_workers/script/test-calculator/_max-submission-fixture.mjs';
import { classifyEvidenceReceipts } from '../../src/utils/evidence-trim-policy.js';
import { decodeSubmissionPayloadString, encodeEvidenceCompactV1 } from '../../workers/game_workers/lib/evidence-compact-v1.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const fixture = await makeMaxAggregateFixture();
const decoded = decodeSubmissionPayloadString(fixture.payload);
const uid = fixture.submitter.uid;
const policy = classifyEvidenceReceipts({ bundle: decoded.bundle, blockNum: decoded.blockNum,
  groupId: decoded.groupId, myUid: uid });
const context = { blockNum: decoded.blockNum, groupId: decoded.groupId, memberUids: decoded.memberUids };
const sizeWithout = (drop, dropAggregate) => {
  const receipts = policy.receipts.filter((receipt) => !drop.includes(policy.priorities.get(receipt)));
  const observed = { ...decoded.bundle.encryptedActions.observed, receipts };
  if (dropAggregate) delete observed.selfReceiptAggregate;
  const snapshot = { ...decoded.bundle.encryptedActions, observed };
  const bundle = { ...decoded.bundle, encryptedActions: snapshot,
    encryptedDataHash: keccak256(toHex(JSON.stringify(snapshot))) };
  return encodeEvidenceCompactV1(bundle, context).length;
};
const base = ['H', 'G', 'F', 'E'];
const afterCD = sizeWithout([...base, 'C', 'D'], false);
const afterDA = sizeWithout([...base, 'D'], true);
assert(afterDA < afterCD, 'fixture has an aggregate removal band that can retain C');
const maxBytes = Math.floor((afterDA + afterCD) / 2) + 1;

// 上限だけを変えた複製を専用 tmp に作り、正典と同じ関数本体を実行する。
const scratchRoot = process.env.TEST_SCRATCH_ROOT || path.join(root, 'tmp/T4-6');
mkdirSync(scratchRoot, { recursive: true });
const scratch = mkdtempSync(path.join(scratchRoot, 'aggregate-trim-'));
try {
  const lib = path.join(scratch, 'workers/game_workers/lib');
  mkdirSync(lib, { recursive: true });
  writeFileSync(path.join(scratch, 'package.json'), '{"type":"module"}\n');
  const source = readFileSync(path.join(root, 'workers/game_workers/lib/evidence-trim.js'), 'utf8');
  assert(source.includes('export const EVIDENCE_MAX_DATA_BYTES = 130000;'));
  writeFileSync(path.join(lib, 'evidence-trim-scaled.js'), source.replace(
    'export const EVIDENCE_MAX_DATA_BYTES = 130000;',
    `export const EVIDENCE_MAX_DATA_BYTES = ${maxBytes};`,
  ));
  // evidence-trim の相対 import 閉包を一時複製にも揃える。
  for (const name of [
    'evidence-compact-v1.js', 'protocol-v2.js', 'read-selection.js',
    'char-counter.js', 'priority-fields.js', 'game-result-calculator.js',
    'submission-limits.js',
  ]) {
    symlinkSync(path.join(root, 'workers/game_workers/lib', name), path.join(lib, name));
  }
  const policyPath = path.join(scratch, 'src/utils/evidence-trim-policy.js');
  mkdirSync(path.dirname(policyPath), { recursive: true });
  symlinkSync(path.join(root, 'src/utils/evidence-trim-policy.js'), policyPath);
  const { planOnChainTrim } = await import(pathToFileURL(path.join(lib, 'evidence-trim-scaled.js')).href);
  const plan = await planOnChainTrim(fixture.payload, uid);
  assert.equal(plan.droppedA, 1, 'aggregate is removed in this band');
  assert.equal(plan.droppedC, 0, 'E-2e-01: C returns to the bytes freed by A');
  assert(plan.afterBytes < maxBytes);
  console.log(`T1d aggregate trim: ALL PASSED; limit=${maxBytes} droppedA=${plan.droppedA} droppedC=${plan.droppedC}`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

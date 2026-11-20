// r12-claim-mutable-unit.mjs — R12-43 claim 可変成果物の単一判定源
// 実行: node block-verifier/test/r12-claim-mutable-unit.mjs

import {
  isClaimMutableArtifact,
  shouldParkManifestHashMismatch,
  compareGroupGameResultRows,
} from '../src/stages/results.js';
import { sha256HexOfString } from '../src/json-utils.js';

let passed = 0;
let failed = 0;
const eq = (name, actual, expected) => {
  if (actual === expected) {
    passed++;
    console.log(`  ok: ${name} = ${expected}`);
  } else {
    failed++;
    console.error(`  FAIL: ${name} — expected ${expected}, got ${actual}`);
  }
};

const N = 0;
const summaryKey = `games/block${N}/summary.json`;
const groupKey = `games/block${N}/group7.json`;
const autoResultKey = `games/block${N}/auto-results.json`;

function classifyChangedBytes(key, schemaVersion, anchoredData, changedData) {
  const declared = sha256HexOfString(JSON.stringify(anchoredData));
  const raw = JSON.stringify(changedData);
  if (sha256HexOfString(raw) === declared) throw new Error('test mutation did not change bytes');
  const fileFailures = [];
  const parked = [];
  if (shouldParkManifestHashMismatch(key, N, schemaVersion, raw, declared)) parked.push(key);
  else fileFailures.push(key);
  return { fileFailures, parked };
}

const claim = { time: 1700000000, txHash: '0xclaim' };
const summaryV2 = classifyChangedBytes(summaryKey, 2,
  { schemaVersion: 2, groups: [{ members: [{ userId: '20000001' }] }] },
  { schemaVersion: 2, groups: [{ members: [{ userId: '20000001', claimed: claim }] }] });
eq('M1 v2 summary fileFailures', summaryV2.fileFailures.length, 1);
eq('M1 v2 summary parked', summaryV2.parked.length, 0);

const summaryV1 = classifyChangedBytes(summaryKey, 1,
  { schemaVersion: 1, groups: [{ members: [{ claimed: 0 }] }] },
  { schemaVersion: 1, groups: [{ members: [{ claimed: claim }] }] });
eq('M2 v1 summary fileFailures', summaryV1.fileFailures.length, 0);
eq('M2 v1 summary parked', summaryV1.parked.length, 1);

const group = classifyChangedBytes(groupKey, 2,
  { gameResults: [{ claimed: 0 }] },
  { gameResults: [{ claimed: claim }] });
eq('M3 group fileFailures', group.fileFailures.length, 0);
eq('M3 group parked', group.parked.length, 1);

const groupV3 = classifyChangedBytes(groupKey, 3,
  { gameResults: [{ role: 'player', userId: '20000001' }] },
  { gameResults: [{ role: 'player', userId: '20000001', claimed: claim }] });
eq('S4 v3 group fileFailures', groupV3.fileFailures.length, 1);
eq('S4 v3 group parked', groupV3.parked.length, 0);
eq('S4 v3 group row compare is strict', compareGroupGameResultRows(
  [{ role: 'player', userId: '20000001' }],
  [{ role: 'player', userId: '20000001', claimed: claim }],
  3,
).ok, false);
eq('S4 legacy v2 group row compare neutralizes claimed', compareGroupGameResultRows(
  [{ role: 'player', userId: '20000001', claimed: 0 }],
  [{ role: 'player', userId: '20000001', claimed: claim }],
  2,
).ok, true);
eq('S4 legacy versionless group row compare neutralizes claimed', compareGroupGameResultRows(
  [{ role: 'player', userId: '20000001', claimed: 0 }],
  [{ role: 'player', userId: '20000001', claimed: claim }],
  undefined,
).ok, true);

const autoResult = classifyChangedBytes(autoResultKey, 2,
  { gameResults: [{ claimed: 0 }] },
  { gameResults: [{ claimed: claim }] });
eq('auto-results fileFailures', autoResult.fileFailures.length, 0);
eq('auto-results parked', autoResult.parked.length, 1);

const autoResultV3 = classifyChangedBytes(autoResultKey, 3,
  { gameResults: [{ role: 'player', userId: '20000001' }] },
  { gameResults: [{ role: 'player', userId: '20000001', claimed: claim }] });
eq('S4 v3 auto-results fileFailures', autoResultV3.fileFailures.length, 1);
eq('S4 v3 auto-results parked', autoResultV3.parked.length, 0);

const unknown = classifyChangedBytes(summaryKey, undefined,
  { groups: [{ members: [{ claimed: 0 }] }] },
  { groups: [{ members: [{ claimed: claim }] }] });
eq('floor unknown summary fileFailures', unknown.fileFailures.length, 1);
eq('floor unknown summary parked', unknown.parked.length, 0);

const versionlessGroup = classifyChangedBytes(groupKey, undefined,
  { gameResults: [{ claimed: 0 }] },
  { gameResults: [{ claimed: claim }] });
eq('legacy versionless group fileFailures', versionlessGroup.fileFailures.length, 0);
eq('legacy versionless group parked', versionlessGroup.parked.length, 1);

eq('unrelated artifact is immutable',
  isClaimMutableArtifact(`merkle/block_${N}.json`, N, 1), false);

console.log(`\nr12-claim-mutable-unit: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);

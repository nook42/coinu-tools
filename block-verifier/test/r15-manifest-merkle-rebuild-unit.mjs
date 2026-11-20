// R15-56 / R15-61: manifest.files の B-3（Merkle 木再構築用分冊）反転回帰。
// 実行: node block-verifier/test/r15-manifest-merkle-rebuild-unit.mjs （Node 22）

import { createReport } from '../src/report.js';
import {
  checkManifestFileList,
  merkleRebuildArtifactKeys,
} from '../src/stages/results.js';

let passed = 0;
let failed = 0;
const ok = (name, condition, detail = '') => {
  if (condition) {
    passed++;
    console.log(`  ok: ${name}`);
  } else {
    failed++;
    console.error(`  FAIL: ${name}${detail ? ` — ${detail}` : ''}`);
  }
};
const eq = (name, actual, expected) => ok(
  name,
  JSON.stringify(actual) === JSON.stringify(expected),
  `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
);

const N = 15;
// 9配分なら proofDepth=4。正典規則では index 16 + leaves 1 + levels 4 = 21件。
const merkleMeta = {
  blockNum: N,
  leafCount: 9,
  proofDepth: 4,
  leafChunkSize: 5000,
  levelSegSize: 4096,
  indexFanout: 16,
};
const expectedB3Keys = [
  ...Array.from({ length: 16 }, (_, h) => `merkle/block_${N}/index/${h.toString(16)}.json`),
  `merkle/block_${N}/leaves/0.json`,
  ...Array.from({ length: 4 }, (_, level) => `merkle/block_${N}/levels/${level}/0.json`),
];

console.log('R15 manifest Merkle rebuild key regression tests');

const derivedB3Keys = merkleRebuildArtifactKeys(N, merkleMeta);
eq('正典規則どおり B-3 を21件・所定順で導出', derivedB3Keys, expectedB3Keys);
eq('leafCount <= 0 は空配列',
  merkleRebuildArtifactKeys(N, { ...merkleMeta, leafCount: 0, proofDepth: 0 }), []);

const groupIds = [7, 2]; // verifier は正典どおり数値昇順へ正規化する。
const normalKeys = [
  `entries/block${N}/game_selection.json`,
  `entries/block${N}/game_groups.json`,
  `games/block${N}/summary.json`,
  `merkle/block_${N}.json`,
  ...expectedB3Keys,
  `verification/block${N}/evidence-report.json`,
  `games/block${N}/zkp/evidence-segments.json`,
  `verification/block${N}/stage3/manifest.json`,
  `games/block${N}/group2.json`,
  `games/block${N}/group7.json`,
  `games/block${N}/roster/index.json`,
  `games/block${N}/roster/group2.json`,
  `games/block${N}/roster/group7.json`,
];

function checkKeys(keys) {
  const report = createReport();
  const result = checkManifestFileList({ blockNum: N, report }, {
    auto: false,
    groupIds,
    files: {
      summary: { data: { schemaVersion: 2 } },
      merkle: { data: merkleMeta },
      manifest: { data: { files: Object.fromEntries(keys.map(key => [key, 'a'.repeat(64)])) } },
    },
  });
  return { result, check: report.get('check.stageC.manifestFileList') };
}

// 必須①: 配分あり＋正典 manifest は PASS。
const normal = checkKeys(normalKeys);
eq('① 配分がある正常 manifest の manifestFileList', normal.check?.status, 'pass');
eq('① B-3 は merkle メタ直後',
  normal.result.expectedKeys.slice(4, 4 + expectedB3Keys.length), expectedB3Keys);
eq('① evidence-report は B-3 の直後',
  normal.result.expectedKeys[4 + expectedB3Keys.length],
  `verification/block${N}/evidence-report.json`);
eq('① 区間artifactは evidence-report の直後',
  normal.result.expectedKeys[5 + expectedB3Keys.length],
  `games/block${N}/zkp/evidence-segments.json`);
eq('① Stage 3 manifest は区間artifactの直後',
  normal.result.expectedKeys[6 + expectedB3Keys.length],
  `verification/block${N}/stage3/manifest.json`);

// 必須②: どの1件が欠けても、余分な1件でも、順序だけでも FAIL。
for (const key of normalKeys) {
  const missingOne = checkKeys(normalKeys.filter((candidate) => candidate !== key));
  eq(`② 1件欠落は FAIL: ${key}`, missingOne.check?.status, 'fail');
}
const extra = checkKeys([...normalKeys, `verification/block${N}/unexpected.json`]);
eq('② 余分な1件は manifestFileList FAIL', extra.check?.status, 'fail');
const swapped = [...normalKeys];
[swapped[0], swapped[1]] = [swapped[1], swapped[0]];
eq('② 正しい集合でも順序違いは manifestFileList FAIL', checkKeys(swapped).check?.status, 'fail');

// 旧 verifier が誤って PASS していた「B-3 全抜き」は FAIL。
const omitted = checkKeys(normalKeys.filter(key => !expectedB3Keys.includes(key)));
eq('② manifest.files から B-3 の鍵を抜くと manifestFileList', omitted.check?.status, 'fail');
ok('② 欠落21件が expected/actual 件数差に出る',
  omitted.check?.params?.expected - omitted.check?.params?.actual === expectedB3Keys.length,
  JSON.stringify(omitted.check?.params));

const autoKeys = normalKeys.filter(key => !key.includes('/group2.json') && !key.includes('/group7.json'));
autoKeys.splice(autoKeys.indexOf(`games/block${N}/roster/index.json`), 0,
  `games/block${N}/auto-results.json`);
autoKeys.push(`games/block${N}/roster/group0.json`);
const autoCheck = (keys, totalPlayers) => {
  const report = createReport();
  checkManifestFileList({ blockNum: N, report }, {
    auto: true, groupIds: [],
    files: { summary: { data: { schemaVersion: 3, autoDistributed: true, totalPlayers } },
      merkle: { data: merkleMeta },
      manifest: { data: { files: Object.fromEntries(keys.map(key => [key, 'a'.repeat(64)])) } },
    },
  });
  return report.get('check.stageC.manifestFileList')?.status;
};
eq('③ 当選1名のgroup0はK6に必要', autoCheck(autoKeys, 1), 'pass');
eq('③ 当選2名のgroup0はK6に必要', autoCheck(autoKeys, 2), 'pass');
eq('③ group0欠落はFAIL', autoCheck(autoKeys.slice(0, -1), 2), 'fail');

console.log('');
if (failed > 0) {
  console.error(`❌ ${failed} FAILED (${passed} passed)`);
  process.exit(1);
}
console.log(`✅ ALL PASSED (${passed} checks)`);

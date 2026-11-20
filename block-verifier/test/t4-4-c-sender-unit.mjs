import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { concatHex, keccak256, stringToHex } from 'viem';
import { buildRosterMemberCommitment, rosterCommitment, buildRosterMemberTree } from '../vendor/workers/game_workers/lib/roster-member-root.js';
import { buildMembersIndex, validateResultBundle, verifyCompleteness } from '../vendor/workers/game_workers/lib/evidence-reconciler.js';
import { inspectRosterCommitment, reconstructCanonicalRosterPayloads } from '../src/stages/results.js';
import { foldEvidenceAcc } from '../src/zkp.js';
import { selectRosterManifestGeneration } from '../src/emergency.js';
import { makePlayer, buildSubmissionPayload } from './players.mjs';

const N = 4;
const players = await Promise.all([0, 1, 2].map((i) => makePlayer({
  uid: `t4-4-${i}`, lang: 'ja', blockNum: N, keyIndex: 610 + i,
})));
const members = players.map((player, i) => ({ globalIndex: i, data: {
  uid: player.uid, addr: player.addr, bAddr: player.bAddrString,
  lang: 'ja', verified: false,
  depIds: JSON.stringify({ ids: [String(610 + i)] }),
} }));
const groupsDerived = [{ groupId: 0, members }];
const payloads = reconstructCanonicalRosterPayloads(N, groupsDerived);
const correct = buildRosterMemberCommitment({ blockNum: N,
  manifestText: payloads.manifestText, groupTexts: payloads.groupTexts });
if (process.env.T4_4_MUTATION === 'old_c') {
  assert.equal(keccak256(stringToHex(payloads.manifestText)), correct.C,
    '旧 manifest 生 keccak を C とみなす変異は赤');
}
const inspect = (overrides = {}) => inspectRosterCommitment({ blockNum: N,
  manifestText: payloads.manifestText, groupTexts: payloads.groupTexts,
  groupsDerived, chainHash: correct.C, ...overrides });
assert.equal(inspect().status, 'pass', '正しい公開全groupと正典Cは通る');
assert.equal(inspect({ chainHash: '0x' + 'ab'.repeat(32) }).status, 'fail', '誤CはFAIL');
assert.equal(inspect({ chainHash: rosterCommitment(correct.manifestHash,
  buildRosterMemberTree(N, players.slice(1).map((player) => player.addr)).memberRoot) }).status,
  'fail', '標的を根から抜いたCはFAIL');
const tamperedGroups = new Map(payloads.groupTexts);
tamperedGroups.set(0, tamperedGroups.get(0).replace(players[0].addr, players[1].addr));
assert.equal(inspect({ groupTexts: tamperedGroups }).status, 'fail', '公開groupの改変はFAIL');
assert.equal(inspect({ groupTexts: new Map() }).status, 'fail', '公開group欠落はFAIL');
assert.equal(inspectRosterCommitment({ blockNum: N, manifestText: null, groupTexts: new Map(),
  groupsDerived: [], chainHash: null }).status, 'pass', '0人・登録なしは通る');
assert.equal(inspectRosterCommitment({ blockNum: N, manifestText: null, groupTexts: new Map(),
  groupsDerived: [], chainHash: correct.C }).status, 'fail', '0人・非ゼロ登録はFAIL');
assert.equal(inspectRosterCommitment({ blockNum: N,
  manifestText: JSON.stringify({ blockNum: N, groups: [] }), groupTexts: new Map(),
  groupsDerived: [], chainHash: null }).status, 'fail', '0人・余計な公開名簿はFAIL');

const indexed = buildMembersIndex([{ group_id: 0,
  members: members.map((member) => member.data) }]);
const raw = (await buildSubmissionPayload(players[0], { blockNum: N, groupId: 0,
  serverMessages: [], submittedAt: 299_200_000, depositIds: ['610'],
  memberUids: players.map((player) => player.uid), })).payload;
if (process.env.T4_4_MUTATION === 'old_sender') {
  assert.equal((await validateResultBundle(raw, N, indexed)).valid, true,
    '旧 sender 欠落呼び出しは赤');
}
assert.equal((await validateResultBundle(raw, N, indexed, players[0].addr)).valid, true,
  '本人senderの署名済み提出は通る');
assert.equal((await validateResultBundle(raw, N, indexed, players[1].addr)).reason,
  'sender_mismatch', '別人の公開写しは無効');
assert.throws(() => verifyCompleteness([{ seq: 1 }, { seq: 3 }], 3), /missing|seq|count/i,
  'Evidence seq欠番はFAIL');

const vectors = JSON.parse(await readFile(new URL('../../workers/game_workers/lib/evidence-sender-vectors.json', import.meta.url)));
let acc = vectors.initialAcc;
if (process.env.T4_4_MUTATION === 'old_acc') {
  assert.equal(keccak256(concatHex([acc, keccak256(vectors.events[0].data)])),
    vectors.events[0].acc, '旧64バイト累積式は赤');
}
for (const event of vectors.events) {
  acc = foldEvidenceAcc(acc, event.sender, event.data);
  assert.equal(acc, event.acc, 'sender付き84バイトの正準累積値');
}
assert.notEqual(foldEvidenceAcc(vectors.initialAcc, vectors.events[1].sender,
  vectors.events[0].data), vectors.events[0].acc, 'dataが同じでもsenderの偽装は累積値が変わる');

const tmpRoot = new URL('../../tmp/T4-4/', import.meta.url).pathname;
await mkdir(tmpRoot, { recursive: true });
const sourceDir = await mkdtemp(path.join(tmpRoot, 'saved-roster-'));
try {
  const saved = async (filename, content, generation) => {
    const bytes = Buffer.from(content);
    await writeFile(path.join(sourceDir, filename), bytes);
    return { savedFile: filename, sha256: createHash('sha256').update(bytes).digest('hex'),
      bytes: bytes.length, generation };
  };
  const wrong = await saved('wrong-manifest.json', `${payloads.manifestText} `, 1);
  const right = await saved('right-manifest.json', payloads.manifestText, 2);
  const group = await saved('group0.json', payloads.groupTexts.get(0), 1);
  const rosterKey = `games/block${N}/roster/manifest.json`;
  const index = { objects: { [rosterKey]: [wrong, right],
    [`games/block${N}/roster/group0.json`]: [group] } };
  const chain = { getTimingConstants: async () => ({ startTimeEntryMs: 0,
    blockTimeMs: 1000, gamePeriodMs: 1000 }), currentGrace: async () => 100,
    otherRegistrationCount: async () => 1,
    otherRegistrationAt: async () => ({ hash: correct.C, registeredBlock: 50, registeredAt: 50 }) };
  const selected = await selectRosterManifestGeneration({ sourceDir, index, chain, blockNum: N });
  if (process.env.T4_4_MUTATION === 'old_emergency') {
    assert.equal(keccak256(stringToHex(payloads.manifestText)), correct.C,
      '旧保存世代の生 keccak 比較は赤');
  }
  assert.equal(selected.row.savedFile, right.savedFile, '緊急入口は旧manifest keccakでなくCに合う保存世代を選ぶ');
  const noMatch = await selectRosterManifestGeneration({ sourceDir,
    index: { objects: { ...index.objects, [rosterKey]: [wrong] } }, chain, blockNum: N });
  assert.equal(noMatch.difference?.checkId, 'check.stageC.rosterLiveAnchor',
    'Cに一致する世代が無ければ差分を記録する');
} finally { await rm(sourceDir, { recursive: true, force: true }); }
console.log('t4-4-c-sender-unit: ALL PASSED');

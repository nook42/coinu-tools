// test/bundle-unit.mjs — 復元バンドル再構成の linchpin ユニットテスト（チェーン不要・v3.2）
//
// 検閲シナリオ（scenario.mjs）で p2 の復元バンドルを再構成し、vendored の
// validateResultBundle / calculateGroupResults で検証する:
//   (A) 再構成バンドルが有効（構造・署名・chatHash・snapshot）
//   (B) 採点で p2 が失格せず、投票（受領証明付き）・チャット（受領証明付きunion正典入り）が反映
//   (C) 天井: p2 のチャットに既読受領証明が1件も無いと min_chars 失格（§6.7 正典条件）

import { calculateGroupResults } from '../vendor/workers/game_workers/lib/game-result-calculator.js';
import {
  validateResultBundle,
  buildMembersIndex,
  selectAdoptedResults,
} from '../vendor/workers/game_workers/lib/evidence-reconciler.js';
import {
  compactBytesToPayload,
  compactPayloadToBytes,
  decodeSubmissionPayloadString,
  encodeEvidenceCompactV1,
} from '../vendor/workers/game_workers/lib/evidence-compact-v1.js';
import { buildGroupWitness } from '../vendor/workers/game_workers/lib/group-witness.js';
import { actionHashV2 } from '../vendor/workers/game_workers/lib/protocol-v2.js';
import { buildScenario } from './scenario.mjs';

let failures = 0;
const assert = (c, l) => { if (!c) { console.error('  NG:', l); failures++; } else console.log('  ok:', l); };

const sc = await buildScenario({ blockNum: 5, groupId: 0 });
const [p1, p2, p3, p4] = sc.players;
const membersIndex = buildMembersIndex([{ group_id: 0, members: sc.members }]);

console.log('--- (A) 復元バンドルの構造検証（validateResultBundle） ---');
const v = await validateResultBundle(sc.p2Recovery.payload, sc.blockNum, membersIndex, p2.addr);
assert(v.valid, `p2 復元バンドルが有効（reason=${v.reason || 'ok'}）`);
assert(v.uid === p2.uid, 'membersIndex から p2 に解決される');
const recoveryDecoded = decodeSubmissionPayloadString(sc.p2Recovery.payload);
assert(JSON.stringify(recoveryDecoded.memberUids) === JSON.stringify(sc.members.map((m) => m.uid)),
  '復元ツールは正準グループ順を compact 枠へ byte-exact に埋める');

console.log('--- (A-2) 名簿順だけを入れ替えたオンチェーン提出は1件だけ拒否 ---');
{
  const honestOrder = sc.members.map((m) => m.uid);
  const swappedOrder = [honestOrder[0], honestOrder[2], honestOrder[1], honestOrder[3]];
  const swappedPayload = compactBytesToPayload(encodeEvidenceCompactV1(
    sc.p2Recovery.bundle,
    { blockNum: sc.blockNum, groupId: sc.groupId, memberUids: swappedOrder },
  ));
  const swappedDecoded = decodeSubmissionPayloadString(swappedPayload);
  assert(JSON.stringify(swappedDecoded.bundle) === JSON.stringify(recoveryDecoded.bundle),
    '名簿順と添字を揃えた再符号化は復号後 bundle が1バイトも変わらない');

  const swappedValidation = await validateResultBundle(swappedPayload, sc.blockNum, membersIndex, p2.addr);
  let downstreamError = null;
  try {
    buildGroupWitness({
      groupRow: { block_num: sc.blockNum, group_id: sc.groupId, members: JSON.stringify(sc.members) },
      groupData: {
        submissions: { [p2.uid]: swappedDecoded.bundle },
        submissionsRaw: { [p2.uid]: swappedPayload },
      },
      verifiedDepositWei: Object.fromEntries(sc.members.map((m) => [m.uid, JSON.parse(m.depIds).deposit])),
    });
  } catch (error) {
    downstreamError = error;
    console.log(`  observed downstream aggregation error: ${error.message}`);
  }
  assert(downstreamError && /compact roster mismatch/.test(downstreamError.message),
    '入口を通った並び替え提出は Stage 3 集計で compact roster mismatch を起こす');
  assert(!swappedValidation.valid && swappedValidation.reason === 'compact_context_mismatch',
    `並び替え提出だけが入口で拒否される（valid=${swappedValidation.valid}, reason=${swappedValidation.reason || 'none'}）`);

  const contextProbeBundle = {
    ...sc.p2Recovery.bundle,
    encryptedActions: { votes: {}, reports: {}, observed: { votes: {}, reports: {}, receipts: [] } },
    messages: [],
  };
  const contextProbePayload = compactBytesToPayload(encodeEvidenceCompactV1(
    contextProbeBundle,
    { blockNum: sc.blockNum, groupId: sc.groupId, memberUids: honestOrder },
  ));
  const mutateContextWord = (payload, byteOffset, value) => {
    const bytes = compactPayloadToBytes(payload).slice();
    // 12-byte frame header, followed by big-endian blockNum u64 / groupId u64.
    new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
      .setBigUint64(12 + byteOffset, BigInt(value), false);
    return compactBytesToPayload(bytes);
  };
  const wrongBlock = await validateResultBundle(
    mutateContextWord(contextProbePayload, 0, sc.blockNum + 1), sc.blockNum, membersIndex, p2.addr,
  );
  const wrongGroup = await validateResultBundle(
    mutateContextWord(contextProbePayload, 8, sc.groupId + 1), sc.blockNum, membersIndex, p2.addr,
  );
  assert(!wrongBlock.valid && wrongBlock.reason === 'compact_context_mismatch',
    '枠の blockNum 不一致も後段へ渡さず1件拒否する');
  assert(!wrongGroup.valid && wrongGroup.reason === 'compact_context_mismatch',
    '枠の groupId 不一致も後段へ渡さず1件拒否する');

  const honestValidation = await validateResultBundle(sc.p2Recovery.payload, sc.blockNum, membersIndex, p2.addr);
  const selected = selectAdoptedResults([
    { seq: 1, txHash: `0x${'11'.repeat(32)}`, raw: swappedPayload, validation: swappedValidation },
    { seq: 2, txHash: `0x${'22'.repeat(32)}`, raw: sc.p2Recovery.payload, validation: honestValidation },
  ]);
  assert(selected.invalid.length === 1 && selected.invalid[0].reason === 'compact_context_mismatch',
    '不正な1件だけが invalid に残る');
  assert(selected.adoptedByUid[p2.uid]?.raw === sc.p2Recovery.payload,
    '後続の正直な提出は first-valid として採用される');
  assert((() => {
    try {
      buildGroupWitness({
        groupRow: { block_num: sc.blockNum, group_id: sc.groupId, members: JSON.stringify(sc.members) },
        groupData: {
          submissions: { [p2.uid]: honestValidation.bundle },
          submissionsRaw: { [p2.uid]: selected.adoptedByUid[p2.uid].raw },
        },
        verifiedDepositWei: Object.fromEntries(sc.members.map((m) => [m.uid, JSON.parse(m.depIds).deposit])),
      });
      return true;
    } catch { return false; }
  })(), '不正な1件を除外後は同じグループの Stage 3 witness が完走する');
}

console.log('--- (B) 採点: p2 が失格せず投票/チャットが反映される ---');
const submissions = await sc.allSubmissions();
const gd = { members: sc.members, submissions, meta: { blockNum: sc.blockNum, groupId: sc.groupId } };
const { results } = await calculateGroupResults(gd, 500, 10, {}, null);
const byUid = Object.fromEntries(results.map((r) => [r.uid, r]));
assert(!byUid[p2.uid].isDisqualified, `p2 は非失格（reason=${byUid[p2.uid].disqualifyReason || byUid[p2.uid].disqualifyReasons?.join(',') || 'none'}）`);
assert(byUid[p2.uid].voteTargetUid === p1.uid, 'p2 の投票が本人提出物から採用される（受領証明付き）');
assert(byUid[p1.uid].votedByUids.includes(p2.uid), 'p2 の投票ボーナスが p1 に付与される');
assert(!byUid[p2.uid].disqualifyReasons?.includes?.('min_chars'), 'p2 のチャットが正典入り（min_chars 失格でない）');

console.log('--- (C) 天井: p2 のメッセージに既読受領証明が無いと min_chars 失格 ---');
// 既読受領証明のうち p2 のメッセージを裏書するもの（senderUid=p2）を全提出物から除去する。
// union正典は「signKey署名 ∧ 他メンバー受領証明≥1件」なので、自発言を自分の提出物に載せても
// 受領証明が無ければ正典外＝文字数不算入（§6.7・自己水増し封鎖と同じ天井）。
const receiptsNoP2Read = sc.allReceipts.filter((rc) => !(Array.isArray(rc.msgRefs) && rc.senderUid === p2.uid));
const stripP2 = (msgs) => msgs.filter((m) => m.uid !== p2.uid);
const p2RecoveryNoVouch = await sc.makeP2Recovery({ receipts: receiptsNoP2Read });
const submissionsNoVouch = {
  [p1.uid]: await sc.makeHonestSubmission(p1, stripP2(sc.sharedMessages), receiptsNoP2Read),
  [p3.uid]: await sc.makeHonestSubmission(p3, stripP2(sc.sharedMessages), receiptsNoP2Read),
  [p4.uid]: await sc.makeHonestSubmission(p4, stripP2(sc.sharedMessages), receiptsNoP2Read),
  [p2.uid]: p2RecoveryNoVouch.bundle, // 自発言はあるが受領証明なし＝正典外
};
const gd2 = { members: sc.members, submissions: submissionsNoVouch, meta: { blockNum: sc.blockNum, groupId: sc.groupId } };
const { results: results2 } = await calculateGroupResults(gd2, 500, 10, {}, null);
const p2r2 = results2.find((r) => r.uid === p2.uid);
assert(p2r2.isDisqualified && (p2r2.disqualifyReasons?.includes('min_chars') || p2r2.disqualifyReason === 'min_chars'),
  'p2 のチャットが受領証明を得ないと min_chars 失格（設計上の天井＝§6.7）');

console.log('--- (D) v3.3: untimely受領（発信±10分外）は正典外＝投票が no_vote ---');
// p2 の投票への受領証明を「±10分外」のものだけに差し替える。isReceiptTimely を満たさない
// 受領証明しか無い発信は void（なかったこと）＝ no_vote 失格になる。
{
  const p2VoteHash = actionHashV2('vote', sc.blockNum, sc.groupId, p2.uid, sc.votes[p2.uid].encrypted, sc.votes[p2.uid].timestamp);
  const receiptsUntimely = sc.allReceipts.filter((rc) => rc.actionHash !== p2VoteHash);
  // 投票 ts = base+2 に対し受領 ts = base+700000 → 差 ≈ 700000ms > 600000ms（±10分外）
  receiptsUntimely.push(await sc.makeActionReceipt(p3, p2.uid, 'vote', sc.votes[p2.uid], sc.base + 700000));
  const p2RecUntimely = await sc.makeP2Recovery({ receipts: receiptsUntimely });
  const subsUntimely = {
    [p1.uid]: await sc.makeHonestSubmission(p1, sc.sharedMessages, receiptsUntimely),
    [p3.uid]: await sc.makeHonestSubmission(p3, sc.sharedMessages, receiptsUntimely),
    [p4.uid]: await sc.makeHonestSubmission(p4, sc.sharedMessages, receiptsUntimely),
    [p2.uid]: p2RecUntimely.bundle,
  };
  const gdU = { members: sc.members, submissions: subsUntimely, meta: { blockNum: sc.blockNum, groupId: sc.groupId } };
  const { results: resultsU } = await calculateGroupResults(gdU, 500, 10, {}, null);
  const p2rU = resultsU.find((r) => r.uid === p2.uid);
  assert(p2rU.isDisqualified && p2rU.disqualifyReason === 'no_vote',
    `untimely受領のみの投票は void ＝ no_vote 失格（reason=${p2rU.disqualifyReason}）`);
}

console.log('--- (E) v3.3: void投票の同一対象再送が有効（受領済み発信の優先選択） ---');
// 旧投票（受領なし＝void）→ 同一対象へ再送（timely受領あり）。提出バンドルは受領済みの
// 発信を votes スロットへ優先選択し、残り（void）は observed.votes[自uid] へ同梱。
// 採点は再送投票を採用し、vote_fraud（矛盾/取下げ）にもならない。
{
  const oldVote = sc.votes[p2.uid]; // ts base+2・この検証では受領証明を一切付けない＝void
  const newVote = await sc.makeAction(p2, 'vote', { targetUid: p1.uid }, sc.base + 200000);
  const p2VoteHash = actionHashV2('vote', sc.blockNum, sc.groupId, p2.uid, oldVote.encrypted, oldVote.timestamp);
  const receiptsResend = sc.allReceipts.filter((rc) => rc.actionHash !== p2VoteHash);
  receiptsResend.push(await sc.makeActionReceipt(p3, p2.uid, 'vote', newVote, sc.base + 250000)); // timely

  // 提出側の優先選択: myVote が void 旧発信でも、myVotePrev/最新のうち「受領済みの発信」が votes スロットへ
  const recA = await sc.makeP2Recovery({ receipts: receiptsResend, myVote: newVote, myVotePrev: [oldVote] });
  assert(recA.snapshotData.votes[p2.uid].signature === newVote.signature, '再送後: 受領済みの新発信が votes スロットに選択される');
  assert((recA.snapshotData.observed.votes[p2.uid] || []).some((v) => v.signature === oldVote.signature),
    'void の旧発信は observed.votes[自uid] へ同梱される（取下げ冤罪防止）');
  const recB = await sc.makeP2Recovery({ receipts: receiptsResend, myVote: oldVote, myVotePrev: [newVote] });
  assert(recB.snapshotData.votes[p2.uid].signature === newVote.signature, 'myVote が void 旧発信でも受領済みの発信が優先選択される');

  const subsResend = {
    [p1.uid]: await sc.makeHonestSubmission(p1, sc.sharedMessages, receiptsResend),
    [p3.uid]: await sc.makeHonestSubmission(p3, sc.sharedMessages, receiptsResend),
    [p4.uid]: await sc.makeHonestSubmission(p4, sc.sharedMessages, receiptsResend),
    [p2.uid]: recA.bundle,
  };
  const gdR = { members: sc.members, submissions: subsResend, meta: { blockNum: sc.blockNum, groupId: sc.groupId } };
  const { results: resultsR } = await calculateGroupResults(gdR, 500, 10, {}, null);
  const p2rR = resultsR.find((r) => r.uid === p2.uid);
  assert(!p2rR.isDisqualified, `void再送の投票は有効・不正扱いされない（reason=${p2rR.disqualifyReason || 'none'}）`);
  assert(p2rR.voteTargetUid === p1.uid, '再送投票が採用される（同一対象・voteTargetUid=p1）');
}

console.log('');
if (failures) { console.error(`bundle-unit: ${failures} check(s) FAILED`); process.exit(1); }
console.log('bundle-unit: ALL PASSED');

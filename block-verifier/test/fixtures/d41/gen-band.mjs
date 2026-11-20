#!/usr/bin/env node
// WR-17e D-41 の恒久入力（鍵と時刻は固定値・ネットワークなし）。
// provider が別の GAME_PERIOD（±600秒）を返す盤で、窓の差の帯に最優先欄 E を持つ frame の採否が、
// Evidence.chatWindow と provider の K13 に合わせた bind_chat_window の採否差を測る。
// 正典 JS の署名・compact 関数を使う。盤は production n=7 grace=initial。
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { concatHex, keccak256, toHex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../../../..');
const lib = (p) => resolve(root, 'workers/game_workers/lib', p);
const { computeChatHashV2, computeMsgKeyV2, chatSignStringV2, msgRefOf, sortCanonicalV2, CHAT_WINDOW_CLOCK_SKEW_MS } =
  await import(lib('protocol-v2.js'));
const { actionSnapshotPreimage } = await import(lib('game-result-calculator.js'));
const { compactBytesToPayload, encodeEvidenceCompactV1, selfReceiptAggregateSignString } =
  await import(lib('evidence-compact-v1.js'));
const { buildMembersIndex, validateResultBundle } = await import(lib('evidence-reconciler.js'));
const { validateSubmissionStructure } = await import(lib('submission-limits.js'));

const board = { startTimeSec: '1790000000', blockIntervalSec: '345600', evidenceGraceSec: '7200',
  gamePeriodSec: '86400', blockNum: '7',
  gm: { startMs: 1792764680000, endMs: 1792858520000 } };
const output = process.argv[2];
assert(output, 'output JSON path required');
const startTime = Number(board.startTimeSec);
const blockInterval = Number(board.blockIntervalSec);
const grace = Number(board.evidenceGraceSec);
const GP = Number(board.gamePeriodSec);
const BLOCK_NUM = Number(board.blockNum);
// Evidence.chatWindow（Evidence.sol:277-281）×1000±2分＝GM・block-verifier の窓。GAME_PERIOD だけ差し替えた窓も同じ式。
const windowFor = (gp) => {
  const open = startTime + (BLOCK_NUM + 1) * blockInterval;
  return { startMs: open * 1000 - CHAT_WINDOW_CLOCK_SKEW_MS, endMs: (open + grace + gp) * 1000 + CHAT_WINDOW_CLOCK_SKEW_MS };
};
const real = windowFor(GP);
assert.deepEqual(real, board.gm, 'real window == Evidence.chatWindow reference');
const windows = { real, short: windowFor(GP - 600), long: windowFor(GP + 600) };

const account = privateKeyToAccount(`0x${'44'.repeat(32)}`);
const GROUP_ID = 0;
const UIDS = ['1000000000000000001', '1000000000000000002', '1000000000000000003'];

async function priorityFrame(uid, msgTs, eTs, submittedAt) {
  const other = UIDS.find((u) => u !== uid);
  const msgText = `hello-${uid.slice(-1)}`;
  const m = {
    type: 'chat', blockNum: BLOCK_NUM, groupId: GROUP_ID, uid: other, text: msgText, timestamp: msgTs,
    signature: await account.signMessage({ message: chatSignStringV2(BLOCK_NUM, GROUP_ID, other, msgText, msgTs) }),
  };
  const messages = sortCanonicalV2([m], BLOCK_NUM, GROUP_ID);
  const e = {
    type: 'chat', blockNum: BLOCK_NUM, groupId: GROUP_ID, uid: other, text: 'A', timestamp: eTs,
    signature: await account.signMessage({ message: chatSignStringV2(BLOCK_NUM, GROUP_ID, other, 'A', eTs) }),
  };
  const entry = { targetType: 'read', senderUid: other,
    msgRef: msgRefOf(computeMsgKeyV2(BLOCK_NUM, GROUP_ID, e)), timestamp: eTs + 1 };
  const encryptedActions = {
    votes: {}, reports: {}, observed: { votes: {}, reports: {}, receipts: [] },
    priority: { messages: [e], receipts: [], selfReceiptAggregate: {
      version: 1, receiverUid: uid, entries: [entry],
      signature: await account.signMessage({ message: selfReceiptAggregateSignString(BLOCK_NUM, GROUP_ID, uid, [entry]) }),
    } },
  };
  const snapshotText = actionSnapshotPreimage(encryptedActions);
  const encryptedDataHash = keccak256(toHex(new TextEncoder().encode(snapshotText)));
  const chatHash = computeChatHashV2(messages, BLOCK_NUM, GROUP_ID);
  const encryptKey = `0x${'11'.repeat(32)}`;
  const depositIds = [];
  const signature = await account.signMessage({ message: JSON.stringify({
    blockNum: BLOCK_NUM, uid, encryptKey, chatHash, submittedAt, encryptedDataHash, depositIds }) });
  const bundle = { uid, encryptKey, chatHash, signature, submittedAt, encryptedDataHash, depositIds,
    encryptedActions, messages };
  const context = { blockNum: BLOCK_NUM, groupId: GROUP_ID, memberUids: UIDS };
  const st = validateSubmissionStructure(bundle, context);
  assert.equal(st.ok, true, st.reason);
  return { uid, frame: encodeEvidenceCompactV1(bundle, context), eTs, msgTs };
}

const inside = real.startMs + 600_000;
// A: E は本当の締切の5分前（GAME_PERIOD−600 の窓の外・本当の窓の内）。
const a = await priorityFrame(UIDS[0], inside, real.endMs - 300_000, real.endMs - 300_000 + 10);
// B: E は本当の締切（＋2分）の5分後（本当の窓の外・GAME_PERIOD+600 の窓の内）。
const b = await priorityFrame(UIDS[1], inside, real.endMs + 300_000, real.endMs + 300_000 + 10);
// C: 対照（どの窓でも内）。
const c = await priorityFrame(UIDS[2], inside, inside + 2, inside + 10);
const frames = [a, b, c];

const membersIndex = (chatWindow) => buildMembersIndex([{
  group_id: GROUP_ID,
  members: UIDS.map((uid) => ({ uid, addr: account.address, bAddr: JSON.stringify({ address: account.address }) })),
}], { chatWindow });
const js = {};
for (const f of frames) {
  for (const [wname, w] of Object.entries(windows)) {
    const v = await validateResultBundle(compactBytesToPayload(f.frame), BLOCK_NUM, membersIndex(w), account.address);
    js[`${f.uid.slice(-1)}.${wname}`] = v.valid ? 'accepted' : v.reason;
  }
}
let acc = `0x${'00'.repeat(32)}`;
for (const f of frames) acc = keccak256(concatHex([acc, account.address, keccak256(toHex(f.frame))]));
writeFileSync(output, JSON.stringify({
  blockNum: BLOCK_NUM,
  groups: [{ groupId: GROUP_ID, members: UIDS.map((uid) => ({ uid, wallet: account.address.toLowerCase(), block: account.address.toLowerCase() })) }],
  frames: frames.map((p) => ({ uid: p.uid, sender: account.address.toLowerCase(), data: toHex(p.frame), eTs: p.eTs })),
  expectedAcc: acc, windows, js,
  board: { startTimeSec: board.startTimeSec, blockIntervalSec: board.blockIntervalSec,
    evidenceGraceSec: board.evidenceGraceSec, gamePeriodSec: board.gamePeriodSec, blockNum: board.blockNum },
}, null, 1));
console.log(JSON.stringify({ windows, eTs: frames.map((f) => [f.uid.slice(-1), f.eTs]), js }));

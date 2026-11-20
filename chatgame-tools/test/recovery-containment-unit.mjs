// S3R4-U-DUPGATE: 復元クライアントの提出物で、攻撃者 A の署名済み既読3枚
//   X = {r1}（先着・成立）  W = {r2, r3}（2番目・X と素）  Y = {r1, r2}（最後に届く・ts は最も早い）
// で、Y が正準順で先に r1 を覆うため X は addsNew で運ばれないが、W と Y は運ばれる。
// 画面は r1 を既読と示し、正直な発言者 V は20ターンを満たす。公式の待ち行列も X と Y を両方受け入れる。
// HEAD を git archive した ./head/ だけを import する。実ファイルは変えない。
import assert from 'node:assert/strict';
import { privateKeyToAccount } from 'viem/accounts';
import {
  chatSignStringV2, actionSignStringV2, actionHashV2, readReceiptSignString, receiptSignString,
  computeMsgKeyV2, msgRefOf, canonicalizeSignature, compareHexAsc, buildReceiptMaps,
  canonicalComparatorV2, buildMsgKeyGetter, buildRealTargets, receiptCoverClaim, clientReadReceiptAdmission, receiptMaxRefsPerReceipt,
} from '../../workers/game_workers/lib/protocol-v2.js';
import { admitReadReceiptsByArrival } from '../vendor/workers/game_workers/lib/protocol-v2.js';
import { capMessagesForScoring, countMessageTurns, filterVisibleMessages, GUEST_PINNED_RULES } from '../../workers/game_workers/lib/char-counter.js';
import { deriveKeysFromSignature } from '../../src/utils/walletTools.js';
import { encryptAction } from '../../src/utils/ecies.js';
import { buildSubmissionBundle } from '../src/recovery/bundle.js';
import { calculateGroupResults } from '../../workers/game_workers/lib/game-result-calculator.js';
import { ReceiptAdmissionQueue } from '../../src/utils/relay.js';

const BLOCK = 5, GROUP = 0, base = 1750000000000;
const CAPS = { maxChars: 10000, maxMessages: 100, maxMsgChars: 1000 };
async function makePlayer(uid, i, eth) {
  const wallet = privateKeyToAccount('0x' + BigInt(i + 1701).toString(16).padStart(64, '0'));
  const ws = await wallet.signMessage({ message: `bitcoinu_mining_block${BLOCK}_user${uid}` });
  const { signKey, encryptKey, blockAddress } = deriveKeysFromSignature(ws, BLOCK);
  const wei = BigInt(Math.round(eth * 1e6)) * 10n ** 12n;
  return { uid, wallet, encryptKey, signAccount: privateKeyToAccount(signKey), addr: wallet.address,
    bAddrString: blockAddress, depIds: JSON.stringify({ deposit: wei.toString(), ids: [String(i + 1)] }) };
}
const V = await makePlayer('user0001', 0, 1);   // 正直な発言者（復元クライアント利用）
const A = await makePlayer('user0002', 1, 1);   // 攻撃者（同組の参加者）
const C = await makePlayer('user0003', 2, 1);   // 不在の3人目（提出なし）
const players = [V, A, C];
const members = players.map((p) => ({ uid: p.uid, addr: p.addr, bAddr: p.bAddrString, depIds: p.depIds }));
const memberUids = members.map((m) => m.uid);
const mkMsg = async (p, text, ts) => ({ type: 'chat', blockNum: BLOCK, groupId: GROUP, uid: p.uid, text, timestamp: ts,
  signature: canonicalizeSignature(await p.signAccount.signMessage({ message: chatSignStringV2(BLOCK, GROUP, p.uid, text, ts) })) });
const refOf = (m) => msgRefOf(computeMsgKeyV2(BLOCK, GROUP, m));
const mkRead = async (r, senderUid, refs, ts) => {
  const msgRefs = [...refs].sort(compareHexAsc);
  return { receiverUid: r.uid, senderUid, msgRefs, timestamp: ts, signature: canonicalizeSignature(
    await r.signAccount.signMessage({ message: readReceiptSignString(BLOCK, GROUP, r.uid, senderUid, msgRefs, ts) })) };
};
const mkAct = async (p, payload, ts) => {
  const encrypted = encryptAction(payload, p.encryptKey);
  return { encrypted, timestamp: ts, signature: canonicalizeSignature(
    await p.signAccount.signMessage({ message: actionSignStringV2('vote', BLOCK, GROUP, p.uid, encrypted, ts) })) };
};
const mkActRc = async (r, actorUid, action, ts) => {
  const actionHash = actionHashV2('vote', BLOCK, GROUP, actorUid, action.encrypted, action.timestamp);
  return { receiverUid: r.uid, actionHash, timestamp: ts, signature: canonicalizeSignature(
    await r.signAccount.signMessage({ message: receiptSignString(BLOCK, GROUP, r.uid, actionHash, ts) })) };
};

// V と A が交互に20回ずつ（1発言30半角文字＝V は600字）。10秒間隔＝全体400秒（全て±10分内）
// A が最初に1回多く話す（A は21ターン＝V の1発言が void になって A の2発言が畳まれても20ターンで適格）
const messages = [];
{ let ts = base; messages.push(await mkMsg(A, 'opening-from-A'.padEnd(30, '.'), (ts += 5_000)));
  for (let t = 0; t < 20; t++) for (const p of [V, A]) messages.push(await mkMsg(p, `t${t}-${p.uid}`.padEnd(30, '.'), (ts += 10_000))); }
const vMsgs = messages.filter((m) => m.uid === V.uid);
const aMsgs = messages.filter((m) => m.uid === A.uid);
const vRefs = vMsgs.map(refOf);
const r1 = vRefs[4], r2 = vRefs[5], r3 = vRefs[6];      // V の5〜7発言目
const rest = vRefs.filter((r) => ![r1, r2, r3].includes(r));

const voteV = await mkAct(V, { targetUid: A.uid }, base + 100);
const voteA = await mkAct(A, { targetUid: V.uid }, base + 200);
// V の正直な既読（A の全発言）と A の投票への受領
const vReadA = await mkRead(V, A.uid, aMsgs.map(refOf), base + 450_000);
const vRcVoteA = await mkActRc(V, A.uid, voteA, base + 300);
const aRcVoteV = await mkActRc(A, V.uid, voteV, base + 400);
// 攻撃者 A の既読（全て鮮度内・正しく署名）
const Z = await mkRead(A, V.uid, rest, base + 450_000);
const X = await mkRead(A, V.uid, [r1], base + 460_000);          // 先着・成立
const W = await mkRead(A, V.uid, [r2, r3], base + 455_000);      // X と素
const Y = await mkRead(A, V.uid, [r1, r2], base + 405_000);      // ts が最も早い（正準順で先頭）・最後に届く
for (const rc of [Z, X, W, Y]) assert(rc.msgRefs.every((r) => {
  const m = vMsgs.find((mm) => refOf(mm) === r); return Math.abs(rc.timestamp - m.timestamp) <= 600_000;
}), 'all A receipts are timely');

// V（復元）の到着順: 正直分 → Z → X → W → Y
const arrival = [vReadA, vRcVoteA, aRcVoteV, Z, X, W, Y];
const vReceipts = {};
arrival.forEach((rc, i) => { vReceipts[`k${i}`] = { ...rc, _seq: i + 1 }; });

// 1) 復元の画面（app.js readersByMsgKey と同じ引数）: V のターン数
const cmp = canonicalComparatorV2(buildMsgKeyGetter(BLOCK, GROUP));
const displayTurns = (receiptsObj) => {
  const readers = buildReceiptMaps(receiptsObj, { messages, myUid: V.uid }, BLOCK, GROUP, null).readersByMsgKey;
  const receipted = capMessagesForScoring(messages, GUEST_PINNED_RULES, cmp)
    .filter((m) => readers[refOf(m)] && [...readers[refOf(m)]].some((u) => u !== m.uid));
  return { turns: countMessageTurns(filterVisibleMessages(receipted))[V.uid] || 0, r1Read: !!readers[r1]?.has(A.uid) };
};
const disp = displayTurns(vReceipts);

// 2) V の提出物（復元クライアントの実物 buildSubmissionBundle）
const buildV = (receipts) => buildSubmissionBundle({
  blockNum: BLOCK, groupId: GROUP, myUid: V.uid, encryptKey: V.encryptKey, members, messages,
  myDepositIds: JSON.parse(V.depIds).ids, myVote: voteV, myVotePrev: [], myReports: [],
  observedActions: { votes: { [A.uid]: voteA }, reports: {} }, receipts,
  intent: { vote: A.uid, reports: [] }, chatCaps: CAPS, submittedAt: base + 900_000,
  signWallet: async (message) => V.wallet.signMessage({ message }),
  signReceiptAggregate: async (message) => canonicalizeSignature(await V.signAccount.signMessage({ message })),
});
const bV = await buildV(vReceipts);
const carriedA = bV.snapshotData.observed.receipts.filter((rc) => rc.receiverUid === A.uid);
const r1Carried = carriedA.some((rc) => rc.msgRefs?.includes(r1));

// 3) A の提出物（攻撃者は自分の r1 既読を自分の集約に入れない＝正当な選択）
const aOwn = [Z, W].map((rc, i) => ({ ...rc, _seq: i + 1 }));
const bA = await buildSubmissionBundle({
  blockNum: BLOCK, groupId: GROUP, myUid: A.uid, encryptKey: A.encryptKey, members, messages,
  myDepositIds: JSON.parse(A.depIds).ids, myVote: voteA, myVotePrev: [], myReports: [],
  observedActions: { votes: { [V.uid]: voteV }, reports: {} },
  receipts: Object.fromEntries([...aOwn, { ...vReadA, _seq: 10 }, { ...vRcVoteA, _seq: 11 }, { ...aRcVoteV, _seq: 12 }].map((rc, i) => [`a${i}`, rc])),
  intent: { vote: V.uid, reports: [] }, chatCaps: CAPS, submittedAt: base + 900_000,
  signWallet: async (message) => A.wallet.signMessage({ message }),
  signReceiptAggregate: async (message) => canonicalizeSignature(await A.signAccount.signMessage({ message })),
});
const score = async (subs) => (await calculateGroupResults(
  { members, submissions: subs, meta: { blockNum: BLOCK, groupId: GROUP } }, 500, 20, CAPS, null)).results;
const fmt = (res) => res.map((r) => `${r.uid}:dq=${r.isDisqualified}${r.isDisqualified ? `(${(r.disqualifyReasons || [r.disqualifyReason]).join('+')})` : ''}:pts=${r.totalPoints ?? r.points ?? '?'}`).join(' ');
const attacked = await score({ [V.uid]: bV.bundle, [A.uid]: bA.bundle });

// 4) 対照A: 同じ受領証明の集合で、到着順と正準順が一致する（Y が X より先に届く）場合
const ctrlOrder = [vReadA, vRcVoteA, aRcVoteV, Z, Y, X, W];
const ctrlReceipts = {}; ctrlOrder.forEach((rc, i) => { ctrlReceipts[`k${i}`] = { ...rc, _seq: i + 1 }; });
const bVctrl = await buildV(ctrlReceipts);
const ctrlScore = await score({ [V.uid]: bVctrl.bundle, [A.uid]: bA.bundle });

// 5) 対照B: 公式クライアントの取り込み待ち行列（resolveReceiptTarget の写し）に同じ到着順で入れる
const accepted = [];
const q = new ReceiptAdmissionQueue({
  getRosterUids: () => memberUids, isRosterVerified: () => true, verifyReceipt: async () => true,
  getChatWindow: () => null,
  resolveReceipt: (receipt, rosterUids) => {
    const targets = buildRealTargets({ votes: { [V.uid]: voteV }, reports: {}, observed: { votes: { [A.uid]: voteA }, reports: {} } }, messages, BLOCK, GROUP);
    if (Array.isArray(receipt.msgRefs)) {
      const admitted = clientReadReceiptAdmission(receipt, targets, { memberUids: rosterUids, chatWindow: null,
        maxRefsPerReceipt: receiptMaxRefsPerReceipt(GUEST_PINNED_RULES.maxMessages), selfUid: V.uid });
      return admitted.state === 'covered' ? { ...admitted, priority: 'F' } : admitted;
    }
    if (!targets.realActionHashes.has(receipt.actionHash)) return { state: 'pending' };
    const claim = receiptCoverClaim(receipt, targets, { memberUids: rosterUids, chatWindow: null,
      maxRefsPerReceipt: receiptMaxRefsPerReceipt(GUEST_PINNED_RULES.maxMessages), atomic: true, selfUid: V.uid });
    if (!claim.windowed || claim.keys.length === 0) return { state: 'invalid' };
    return { state: 'covered', facts: claim.keys, priority: 'F' };
  },
  onAccept: (rc) => accepted.push(rc),
  onRemove: (rc) => { const i = accepted.indexOf(rc); if (i >= 0) accepted.splice(i, 1); },
});
const realNow = Date.now; Date.now = () => base + 500_000;
try {
  const malformed = [
    { ...X, signature: `0x${X.signature.slice(2).toUpperCase()}` },
    { ...X, signature: `0X${X.signature.slice(2)}` },
    { ...X, signature: `${X.signature}0` },
    { ...W, msgRefs: [...W.msgRefs].reverse() },
  ];
  for (const copy of malformed) assert.equal(await q.offer(copy, { verified: true }), false,
    '非正準 WS 写しは取り込み前に棄却');
  for (const rc of arrival) await q.offer(rc, { verified: true });
} finally { Date.now = realNow; }
const officialHasX = accepted.includes(X), officialHasY = accepted.includes(Y);
const fromQueue = Object.fromEntries(accepted.map((rc, i) => [`q${i}`, { ...rc, _seq: i + 1 }]));
const queueBundle = await buildV(fromQueue);
assert(queueBundle.snapshotData.observed.receipts.some((rc) =>
  rc.receiverUid === A.uid && rc.msgRefs?.includes(r1)),
'非正準 WS 写しの後でも P2P 本物 X が復元の提出物に載る');
const officialTargets = buildRealTargets({ votes: { [V.uid]: voteV }, reports: {},
  observed: { votes: { [A.uid]: voteA }, reports: {} } }, messages, BLOCK, GROUP);
assert.deepEqual(admitReadReceiptsByArrival(accepted, officialTargets, {
  memberUids, chatWindow: null, maxRefsPerReceipt: receiptMaxRefsPerReceipt(GUEST_PINNED_RULES.maxMessages),
  selfUid: V.uid,
}), accepted, '公式待ち行列の受理済み集合に到着順処理を重ねても no-op');

console.log(`display (recovery): V turns=${disp.turns} r1 read by A=${disp.r1Read}`);
console.log(`V bundle (recovery): A receipts carried=${carriedA.length} r1 carried=${r1Carried}`);
console.log(`scoring attacked : ${fmt(attacked)}`);
console.log(`scoring control A (arrival==canonical): ${fmt(ctrlScore)}`);
console.log(`official queue control B: accepted X=${officialHasX} Y=${officialHasY}`);
const vRes = attacked.find((r) => r.uid === V.uid);
assert(disp.turns >= 20 && disp.r1Read, '画面は成立済み X の既読を示す');
assert(r1Carried, '到着順の包含後に選抜し X のカバーを運ぶ');
assert(!vRes.isDisqualified, 'V は min_messages で失格しない');
assert(officialHasX && officialHasY, '公式の待ち行列は X と Y の両方を受け入れる（S3R4-U-DUPGATE）');
console.log('recovery-containment-unit: ALL PASSED');

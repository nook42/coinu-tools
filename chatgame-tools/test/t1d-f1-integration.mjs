// S3R4-U-DUPGATE: F-1-01 の一部重複 L={r1,r2}・P1={r2,r3,r4} を両方受け入れ、
// 画面と提出物で r1 のカバーと20ターンを守る。正典コードと復元 bundle の恒久回帰。
import assert from 'node:assert/strict';
import { privateKeyToAccount } from 'viem/accounts';
import {
  chatSignStringV2, actionSignStringV2, actionHashV2, readReceiptSignString, receiptSignString,
  computeMsgKeyV2, msgRefOf, canonicalizeSignature, compareHexAsc, buildReceiptMaps,
  canonicalComparatorV2, buildMsgKeyGetter, buildRealTargets, receiptCoverClaim, clientReadReceiptAdmission, receiptMaxRefsPerReceipt,
} from '../../workers/game_workers/lib/protocol-v2.js';
import { capMessagesForScoring, countMessageTurns, filterVisibleMessages, GUEST_PINNED_RULES } from '../../workers/game_workers/lib/char-counter.js';
import { deriveKeysFromSignature } from '../../src/utils/walletTools.js';
import { encryptAction } from '../../src/utils/ecies.js';
import { buildSubmissionBundle } from '../../chatgame-tools/src/recovery/bundle.js';
import { calculateGroupResults } from '../../workers/game_workers/lib/game-result-calculator.js';
import { ReceiptAdmissionQueue } from '../../src/utils/relay.js';

const BLOCK = 5, GROUP = 0, base = 1750000000000;
const CAPS = { maxChars: 10000, maxMessages: 100, maxMsgChars: 1000 };
async function makePlayer(uid, i) {
  const wallet = privateKeyToAccount('0x' + BigInt(i + 1701).toString(16).padStart(64, '0'));
  const ws = await wallet.signMessage({ message: `bitcoinu_mining_block${BLOCK}_user${uid}` });
  const { signKey, encryptKey, blockAddress } = deriveKeysFromSignature(ws, BLOCK);
  return { uid, wallet, encryptKey, signAccount: privateKeyToAccount(signKey), addr: wallet.address,
    bAddrString: blockAddress, depIds: JSON.stringify({ deposit: (10n ** 18n).toString(), ids: [String(i + 1)] }) };
}
const V = await makePlayer('user0001', 0);   // 正直
const A = await makePlayer('user0002', 1);   // 攻撃者（参加者1人）
const C = await makePlayer('user0003', 2);   // 不在（提出なし）
const members = [V, A, C].map((p) => ({ uid: p.uid, addr: p.addr, bAddr: p.bAddrString, depIds: p.depIds }));
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

// 会話: A の口火 → V と A が交互に20往復（V はちょうど20ターン・F-1-01 と同じ）
const messages = [];
{ let ts = base; messages.push(await mkMsg(A, 'opening-from-A'.padEnd(30, '.'), (ts += 5_000)));
  for (let t = 0; t < 20; t++) for (const p of [V, A]) messages.push(await mkMsg(p, `t${t}-${p.uid}`.padEnd(30, '.'), (ts += 10_000))); }
const vMsgs = messages.filter((m) => m.uid === V.uid);
const aMsgs = messages.filter((m) => m.uid === A.uid);
const vRefs = vMsgs.map(refOf);
const [r1, r2, r3, r4] = [vRefs[4], vRefs[5], vRefs[6], vRefs[7]];
const voteV = await mkAct(V, { targetUid: C.uid }, base + 100);
const voteA = await mkAct(A, { targetUid: V.uid }, base + 200);
const vRcVoteA = await mkActRc(V, A.uid, voteA, base + 300);
const aRcVoteV = await mkActRc(A, V.uid, voteV, base + 400);

// 正直な公式クライアントの発行の形: 交互の会話では相手の発言1件ごとに既読1枚（sender ごとの未読のバッチ）。
// V の自分の既読（A の発言を覆う）21枚。
const vSelf = [];
for (const m of aMsgs) vSelf.push(await mkRead(V, A.uid, [refOf(m)], m.timestamp + 3_000));
// A の既読: r1..r4 以外の V の発言は1件ずつ（正直に見える形）
const aRest = [];
for (const m of vMsgs) { const r = refOf(m); if ([r1, r2, r3, r4].includes(r)) continue;
  aRest.push(await mkRead(A, V.uid, [r], m.timestamp + 3_000)); }
const tsOf = (r) => vMsgs.find((m) => refOf(m) === r).timestamp;
const Z = await mkRead(A, V.uid, [r3], tsOf(r3) + 3_000);
const L = await mkRead(A, V.uid, [r1, r2], tsOf(r2) + 3_000);      // r1 を読んだのは A だけ
const Q = await mkRead(A, V.uid, [r4], tsOf(r4) + 3_000);
// P1 は L と r2 で重なり L を含まない。自称時刻は r2..r4 の鮮度内（後から Nostr で届けてよい）
const P1 = await mkRead(A, V.uid, [r2, r3, r4], tsOf(r4) + 60_000);
for (const rc of [...aRest, Z, L, P1, Q]) assert(rc.msgRefs.every((r) => Math.abs(rc.timestamp - tsOf(r)) <= 600_000), 'timely');

const maxRefs = receiptMaxRefsPerReceipt(GUEST_PINNED_RULES.maxMessages);
const snapshotFor = () => ({ votes: { [V.uid]: voteV }, reports: {}, observed: { votes: { [A.uid]: voteA }, reports: {} } });
// 公式の待ち行列（useGameWebSocket.js の resolveReceiptTarget と getSelectionContext の写し・HEAD と同じ引数）
async function officialSession(order, { log = null } = {}) {
  const accepted = [];
  const targets = buildRealTargets(snapshotFor(), messages, BLOCK, GROUP);
  const q = new ReceiptAdmissionQueue({
    getRosterUids: () => memberUids, isRosterVerified: () => true, verifyReceipt: async () => true,
    getChatWindow: () => null,
    resolveReceipt: (receipt, rosterUids) => {
      if (Array.isArray(receipt.msgRefs)) {
        const admitted = clientReadReceiptAdmission(receipt, targets, { memberUids: rosterUids, chatWindow: null,
          maxRefsPerReceipt: maxRefs, selfUid: V.uid });
        return admitted.state === 'covered' ? { ...admitted, priority: 'F' } : admitted;
      }
      if (!targets.realActionHashes.has(receipt.actionHash)) return { state: 'pending' };
      const claim = receiptCoverClaim(receipt, targets, { memberUids: rosterUids, chatWindow: null,
        maxRefsPerReceipt: maxRefs, atomic: true, selfUid: V.uid });
      if (!claim.windowed || claim.keys.length === 0) return { state: 'invalid' };
      return { state: 'covered', facts: claim.keys, priority: 'F' };
    },
    getSelectionContext: () => ({ messages, blockNum: BLOCK, groupId: GROUP, myUid: V.uid, caps: GUEST_PINNED_RULES }),
    onAccept: (rc) => accepted.push(rc),
    onRemove: (rc, reason) => { const i = accepted.indexOf(rc); if (i >= 0) accepted.splice(i, 1); if (log) log.push([rc, reason]); },
  });
  const realNow = Date.now; Date.now = () => base + 700_000;
  const timeline = [];
  try {
    for (const rc of order) { await q.offer(rc, { verified: true }); timeline.push({ after: rc, snap: [...accepted] }); }
  } finally { Date.now = realNow; }
  q.dispose();
  return { accepted, timeline };
}
const cmp = canonicalComparatorV2(buildMsgKeyGetter(BLOCK, GROUP));
const asSeq = (list) => Object.fromEntries(list.map((rc, i) => [`s${i}`, { ...rc, _seq: i + 1 }]));
const display = (list) => {
  const readers = buildReceiptMaps(asSeq(list), { messages, myUid: V.uid }, BLOCK, GROUP, null).readersByMsgKey;
  const receipted = capMessagesForScoring(messages, GUEST_PINNED_RULES, cmp)
    .filter((m) => readers[refOf(m)] && [...readers[refOf(m)]].some((u) => u !== m.uid));
  return { turns: countMessageTurns(filterVisibleMessages(receipted))[V.uid] || 0, r1Read: !!readers[r1]?.has(A.uid) };
};
const buildV = (receipts) => buildSubmissionBundle({
  blockNum: BLOCK, groupId: GROUP, myUid: V.uid, encryptKey: V.encryptKey, members, messages,
  myDepositIds: ['1'], myVote: voteV, myVotePrev: [], myReports: [],
  observedActions: { votes: { [A.uid]: voteA }, reports: {} }, receipts,
  intent: { vote: C.uid, reports: [] }, chatCaps: CAPS, submittedAt: base + 900_000,
  signWallet: async (message) => V.wallet.signMessage({ message }),
  signReceiptAggregate: async (message) => canonicalizeSignature(await V.signAccount.signMessage({ message })),
});
// A は自分の提出物に L を入れない（正当な選択）。C は不在。
const bA = await buildSubmissionBundle({
  blockNum: BLOCK, groupId: GROUP, myUid: A.uid, encryptKey: A.encryptKey, members, messages,
  myDepositIds: ['2'], myVote: voteA, myVotePrev: [], myReports: [],
  observedActions: { votes: { [V.uid]: voteV }, reports: {} },
  receipts: asSeq([...aRest, P1, ...vSelf, vRcVoteA, aRcVoteV]),
  intent: { vote: V.uid, reports: [] }, chatCaps: CAPS, submittedAt: base + 900_000,
  signWallet: async (message) => A.wallet.signMessage({ message }),
  signReceiptAggregate: async (message) => canonicalizeSignature(await A.signAccount.signMessage({ message })),
});
const score = async (subs) => (await calculateGroupResults(
  { members, submissions: subs, meta: { blockNum: BLOCK, groupId: GROUP } }, 500, 20, CAPS, null)).results;
const fmt = (res) => res.map((r) => `${r.uid}:dq=${r.isDisqualified}${r.isDisqualified ? `(${(r.disqualifyReasons || [r.disqualifyReason]).join('+')})` : ''}:pts=${r.totalPoints ?? r.points ?? '?'}`).join(' ');
const r1Carried = (b) => b.snapshotData.observed.receipts.some((rc) => rc.receiverUid === A.uid && rc.msgRefs?.includes(r1));

let ok = true;
// --- 対照: F-1-01 と同じ最小の盤面（候補10枚以内＝厳密探索）では T1b は L を残す ---
{
  // 最小盤面では A の残りの既読を1枚にまとめ、V の自分の既読も1枚にまとめる（F-1-01 の探針と同じ枚数感）
  // ※ 鮮度: 残りの既読は時刻が広いので採点上は無効になりうるが、ここは選抜の分岐だけを見る対照
  const vSelfOne = vSelf.slice(0, 1);
  const order = [...vSelfOne, Z, L, P1, Q];
  const s = await officialSession(order);
  console.log(`[control small board: ${order.length} read candidates] accepted L=${s.accepted.includes(L)} P1=${s.accepted.includes(P1)}`);
  if (!s.accepted.includes(L)) { ok = false; console.log('  control unexpected'); }
}

// --- 本番の形（正直な1件ずつの既読）: 候補数 = V 自身の21枚 + A の16枚 + Z,L,P1,Q = 41 ---
const live = [];
{ // ライブの到着順: 各発言の直後に既読。L は r2 の後、P1 は最後（チャット終了後に Nostr で届くとする）
  for (const m of messages) {
    if (m.uid === A.uid) live.push(vSelf[aMsgs.indexOf(m)]);
    else { const r = refOf(m);
      if (r === r2) live.push(L); else if (r === r3) live.push(Z); else if (r === r4) live.push(Q);
      else if (r !== r1) live.push(aRest.find((rc) => rc.msgRefs[0] === r)); }
  }
}
live.push(vRcVoteA, aRcVoteV);
const log = [];
const s1 = await officialSession([...live, P1], { log });
const beforeP1 = s1.timeline[s1.timeline.length - 2].snap;
const dBefore = display(beforeP1);
const dAfter = display(s1.accepted);
const reasonL = log.find(([rc]) => rc === L)?.[1] || null;
console.log(`[session1 official, same session] read candidates=${[...live, P1].filter((rc) => Array.isArray(rc.msgRefs)).length}`);
console.log(`  before P1: L accepted=${beforeP1.includes(L)} display V turns=${dBefore.turns} r1 read=${dBefore.r1Read}`);
console.log(`  after  P1: L accepted=${s1.accepted.includes(L)} P1 accepted=${s1.accepted.includes(P1)} onRemove(L)=${reasonL} display V turns=${dAfter.turns} r1 read=${dAfter.r1Read}`);
const b1 = await buildV(asSeq(s1.accepted));
const sc1 = await score({ [V.uid]: b1.bundle, [A.uid]: bA.bundle });
console.log(`  V bundle carries r1=${r1Carried(b1)} | scoring: ${fmt(sc1)}`);
// 対照: P1 が来なければ V は適格
const b0 = await buildV(asSeq(beforeP1));
const sc0 = await score({ [V.uid]: b0.bundle, [A.uid]: bA.bundle });
console.log(`  control (no P1): V bundle carries r1=${r1Carried(b0)} | scoring: ${fmt(sc0)}`);

// 到着順を変えても L と P1 の双方を受け入れる。
const orders = [[P1, ...live], [...live].reverse().concat([P1]), [Q, P1, ...live.slice().reverse()]];
const perOrder = [];
for (const o of orders) { const s = await officialSession(o); perOrder.push(`${s.accepted.includes(L)}/${s.accepted.includes(P1)}`); }
console.log(`[other orders official] L/P1 accepted: ${perOrder.join(' ')}`);

// 復元クライアント: 新しいセッション
const recv = asSeq([...live, P1]);
const b3 = await buildV(recv);
const sc3 = await score({ [V.uid]: b3.bundle, [A.uid]: bA.bundle });
console.log(`[recovery new session] V bundle carries r1=${r1Carried(b3)} L carried=${b3.snapshotData.observed.receipts.some((rc) => rc.signature === L.signature)} | scoring: ${fmt(sc3)}`);

const v0 = sc0.find((r) => r.uid === V.uid), v1 = sc1.find((r) => r.uid === V.uid), a1 = sc1.find((r) => r.uid === A.uid);
const v3 = sc3.find((r) => r.uid === V.uid);
assert(ok, 'small conflict control retains L');
assert(dBefore.turns >= 20 && dAfter.turns >= dBefore.turns,
  'F-1e-01: adding the partial overlap cannot retract the displayed 20 turns');
assert(s1.accepted.includes(L) && s1.accepted.includes(P1),
  'F-1e-01: both partially overlapping receipts are accepted with 41 actual candidates');
assert(r1Carried(b1) && !v1.isDisqualified && !v3.isDisqualified,
  'F-1e-01/02: official and recovery submissions retain the decisive read');
assert(perOrder.every((value) => value === 'true/true'),
  'F-1e-01: five paths are independent of receipt arrival order');
console.log('T1d F1 integration: ALL PASSED; candidates=41; turns=' + dAfter.turns);

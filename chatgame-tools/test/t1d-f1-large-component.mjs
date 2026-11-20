// S3R4-U-DUPGATE: 大きな一部重複成分を受け入れても、正直な会話数が下がらず、
// V が失格しないことを本番に近い枚数で確かめる恒久回帰。
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
import { buildSubmissionBundle } from '../src/recovery/bundle.js';
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


// S3R2 F-1e 探針2: 下げ幅。T1b_RESULT §6-2 は「11枚以上の貪欲では100→99の反例」とだけ書くが、
// 貪欲は会話数を見ないので、攻撃者 A は画面に全部既読と出した後で、自分の既読の大半を撤回できる。
// A の既読の元の形: V の発言を k 件ずつの素な束 O_i（画面は全部既読）。後から各 O_i の最後の1件だけを
// 集めた BIG（参照数 > k）を Nostr で届ける。貪欲は参照数の多い BIG を先に採り、O_i は全部衝突で落ちる。
async function run(nTurns, k, cRounds = 20) {
  // 前半: A と C が交互に cRounds 往復（C は在席・互いに既読）。後半: C は away、V と A が交互に nTurns 往復。
  const messages = [];
  let ts = base;
  messages.push(await mkMsg(A, 'opening-from-A'.padEnd(30, '.'), (ts += 5_000)));
  for (let t = 0; t < cRounds; t++) for (const p of [C, A]) messages.push(await mkMsg(p, `c${t}-${p.uid}`.padEnd(30, '.'), (ts += 10_000)));
  ts += 1_800_000; // C が away になってから30分後に V が来る
  const part2Start = messages.length;
  for (let t = 0; t < nTurns; t++) for (const p of [V, A]) messages.push(await mkMsg(p, `t${t}-${p.uid}`.padEnd(30, '.'), (ts += 10_000)));
  const part1 = messages.slice(0, part2Start), part2 = messages.slice(part2Start);
  const vMsgs = messages.filter((m) => m.uid === V.uid);
  const voteV = await mkAct(V, { targetUid: C.uid }, base + 100);
  const voteA = await mkAct(A, { targetUid: C.uid }, base + 200);
  const voteC = await mkAct(C, { targetUid: A.uid }, base + 250);
  const rcVote = [];
  rcVote.push(await mkActRc(V, A.uid, voteA, base + 300), await mkActRc(A, V.uid, voteV, base + 400),
    await mkActRc(C, A.uid, voteA, base + 500), await mkActRc(A, C.uid, voteC, base + 600));
  // 既読: 前半は A と C が相手の発言1件ずつ。後半は V が A の発言1件ずつ（自分の既読）。
  const cReads = [], aReadsC = [], vSelf = [];
  for (const m of part1) {
    if (m.uid === A.uid) cReads.push(await mkRead(C, A.uid, [refOf(m)], m.timestamp + 3_000));
    else aReadsC.push(await mkRead(A, C.uid, [refOf(m)], m.timestamp + 3_000));
  }
  for (const m of part2) if (m.uid === A.uid) vSelf.push(await mkRead(V, A.uid, [refOf(m)], m.timestamp + 3_000));
  // A の V への既読: k 件ずつの素な束（画面は全部既読）
  const originals = [];
  for (let i = 0; i < vMsgs.length; i += k) {
    const chunk = vMsgs.slice(i, i + k);
    originals.push(await mkRead(A, V.uid, chunk.map(refOf), chunk.at(-1).timestamp + 3_000));
  }
  const bigRefs = originals.map((o) => refOf(vMsgs.filter((m) => o.msgRefs.includes(refOf(m))).at(-1)));
  const mid = vMsgs[Math.floor(vMsgs.length / 2)].timestamp;
  const BIG = await mkRead(A, V.uid, bigRefs, mid);   // チャット終了後に Nostr だけで届ける（自称時刻は鮮度内）
  const tsOfM = (r) => vMsgs.find((m) => refOf(m) === r).timestamp;
  for (const rc of [...originals, BIG]) assert(rc.msgRefs.every((r) => Math.abs(rc.timestamp - tsOfM(r)) <= 600_000), 'timely');
  const snap = { votes: { [V.uid]: voteV }, reports: {}, observed: { votes: { [A.uid]: voteA, [C.uid]: voteC }, reports: {} } };
  const targets = buildRealTargets(snap, messages, BLOCK, GROUP);
  const maxRefs = receiptMaxRefsPerReceipt(GUEST_PINNED_RULES.maxMessages);
  const accepted = [];
  const q = new ReceiptAdmissionQueue({
    getRosterUids: () => memberUids, isRosterVerified: () => true, verifyReceipt: async () => true,
    getChatWindow: () => null,
    resolveReceipt: (receipt, rosterUids) => {
      if (Array.isArray(receipt.msgRefs)) {
        const admitted = clientReadReceiptAdmission(receipt, targets, { memberUids: rosterUids, chatWindow: null,
          maxRefsPerReceipt: maxRefs, selfUid: V.uid });
        return admitted.state === 'covered' ? { ...admitted, priority: 'F' } : admitted;
      }
      if (!Array.isArray(receipt.msgRefs) && !targets.realActionHashes.has(receipt.actionHash)) return { state: 'pending' };
      const claim = receiptCoverClaim(receipt, targets, { memberUids: rosterUids, chatWindow: null, maxRefsPerReceipt: maxRefs, atomic: true, selfUid: V.uid });
      if (!claim.windowed || claim.keys.length === 0) return { state: 'invalid' };
      return { state: 'covered', facts: claim.keys, priority: 'F' };
    },
    getSelectionContext: () => ({ messages, blockNum: BLOCK, groupId: GROUP, myUid: V.uid, caps: GUEST_PINNED_RULES }),
    onAccept: (rc) => accepted.push(rc),
    onRemove: (rc) => { const i = accepted.indexOf(rc); if (i >= 0) accepted.splice(i, 1); },
  });
  const cmp = canonicalComparatorV2(buildMsgKeyGetter(BLOCK, GROUP));
  const display = (list) => {
    const obj = Object.fromEntries(list.map((rc, i) => [`s${i}`, { ...rc, _seq: i + 1 }]));
    const readers = buildReceiptMaps(obj, { messages, myUid: V.uid }, BLOCK, GROUP, null).readersByMsgKey;
    const receipted = capMessagesForScoring(messages, GUEST_PINNED_RULES, cmp)
      .filter((m) => readers[refOf(m)] && [...readers[refOf(m)]].some((u) => u !== m.uid));
    return countMessageTurns(filterVisibleMessages(receipted))[V.uid] || 0;
  };
  const realNow = Date.now; Date.now = () => ts + 60_000;
  let before, after;
  try {
    for (const rc of [...cReads, ...aReadsC, ...vSelf, ...originals, ...rcVote]) await q.offer(rc, { verified: true });
    before = display(accepted);
    await q.offer(BIG, { verified: true });
    after = display(accepted);
  } finally { Date.now = realNow; }
  q.dispose();
  const mk = (who, receipts, vote, intentVote, observedVotes) => buildSubmissionBundle({
    blockNum: BLOCK, groupId: GROUP, myUid: who.uid, encryptKey: who.encryptKey, members, messages,
    myDepositIds: [String(memberUids.indexOf(who.uid) + 1)], myVote: vote, myVotePrev: [], myReports: [],
    observedActions: { votes: observedVotes, reports: {} },
    receipts: Object.fromEntries(receipts.map((rc, i) => [`s${i}`, { ...rc, _seq: i + 1 }])),
    intent: { vote: intentVote, reports: [] }, chatCaps: CAPS, submittedAt: ts + 900_000,
    signWallet: async (message) => who.wallet.signMessage({ message }),
    signReceiptAggregate: async (message) => canonicalizeSignature(await who.signAccount.signMessage({ message })),
  });
  const bV = await mk(V, accepted, voteV, C.uid, { [A.uid]: voteA, [C.uid]: voteC });
  // A は O_i を自分の提出物に入れない（正当な選択）
  const bA = await mk(A, [BIG, ...aReadsC, ...cReads, ...vSelf, ...rcVote], voteA, C.uid, { [V.uid]: voteV, [C.uid]: voteC });
  const bC = await mk(C, [...cReads, ...aReadsC, ...rcVote], voteC, A.uid, { [A.uid]: voteA });
  const res = (await calculateGroupResults({ members, submissions: { [V.uid]: bV.bundle, [A.uid]: bA.bundle, [C.uid]: bC.bundle },
    meta: { blockNum: BLOCK, groupId: GROUP } }, 500, 20, CAPS, null)).results;
  const pick = (u) => res.find((r) => r.uid === u);
  const f = (r) => `dq=${r.isDisqualified}${r.isDisqualified ? `(${(r.disqualifyReasons || []).join('+')})` : ''} pts=${r.totalPoints}`;
  // 対照: BIG が届かなければ V は適格
  const bV0 = await mk(V, accepted.filter((rc) => rc !== BIG).concat(originals.filter((o) => !accepted.includes(o))), voteV, C.uid, { [A.uid]: voteA, [C.uid]: voteC });
  const res0 = (await calculateGroupResults({ members, submissions: { [V.uid]: bV0.bundle, [A.uid]: bA.bundle, [C.uid]: bC.bundle },
    meta: { blockNum: BLOCK, groupId: GROUP } }, 500, 20, CAPS, null)).results;
  console.log(`nTurns=${nTurns} k=${k}: read candidates=${cReads.length + aReadsC.length + vSelf.length + originals.length + 1} originals=${originals.length} BIG refs=${BIG.msgRefs.length} | display V turns before BIG=${before} after BIG=${after} (drop ${before - after}) | scoring V ${f(pick(V.uid))} A ${f(pick(A.uid))} C ${f(pick(C.uid))} | control(no BIG) V ${f(res0.find((r) => r.uid === V.uid))}`);
  return { before, after, vdq: pick(V.uid).isDisqualified, adq: pick(A.uid).isDisqualified, v0: res0.find((r) => r.uid === V.uid).isDisqualified };
}
const out = [];
out.push(await run(24, 2));
out.push(await run(30, 3));
out.push(await run(36, 4));
out.push(await run(40, 5));
assert(out.every((o) => o.before === o.after && !o.vdq && !o.v0), 'large collision component must not retract the honest turns');
console.log('T1d F1 large component: ALL PASSED');

import assert from 'node:assert/strict';
// S3R2 E-2e probe P5: 投票の V 級は「提出物の公開枠（votes[自分]）の投票」を目標にする。復元クライアントは公開枠の選択
// （bundle.js の isReceipted）で宣言窓の外の**行動**受領証明も数える（clientWindowedReceipts は既読しか窓で除かない）。
// 盤面: V の初回投票 V1 には窓内の有効な受領証明 R1（A が後から公開・逆日付だが±10分内）、再送 V2 には締切＋2分＋1秒の R2（窓外）だけ。
//   → 公開枠は V2、V1 は observed へ。V 級は V2（R2 は窓外で G）＝空。採点が使う V1 の受領証明 R1 は E 級。
//   → トリムで E を削る帯では R1 が消え（essential 警告なし）、V は no_vote。公式（窓つき待ち行列が R2 を捨てる）は公開枠 V1・V 級 R1。
// 上限は tmp の写し（evidence-trim-scaled.js）の env で E を削る帯へ縮める（級の仕組みの実測。130,000 での到達は条件つき）。
import { privateKeyToAccount } from 'viem/accounts';
import {
  chatSignStringV2, actionSignStringV2, actionHashV2, readReceiptSignString, receiptSignString,
  computeMsgKeyV2, msgRefOf, canonicalizeSignature, compareHexAsc, chatWindowMsFromTimeline,
} from '../../workers/game_workers/lib/protocol-v2.js';
import { deriveKeysFromSignature } from '../../src/utils/walletTools.js';
import { encryptAction } from '../../src/utils/ecies.js';
import { buildSubmissionBundle } from '../../chatgame-tools/src/recovery/bundle.js';
import { calculateGroupResults } from '../../workers/game_workers/lib/game-result-calculator.js';
import { classifyEvidenceReceipts } from '../../src/utils/evidence-trim-policy.js';
import { decodeSubmissionPayloadString, encodeEvidenceCompactV1 } from '../../workers/game_workers/lib/evidence-compact-v1.js';
import { keccak256, toHex } from 'viem';

const BLOCK = 5, GROUP = 0;
const CAPS = { maxChars: 10000, maxMessages: 100, maxMsgChars: 1000 };
const chattingStart = 1750000000000;
const timeline = { chatOpenAt: chattingStart - 2 * 3600_000, chatCloseAt: chattingStart + 24 * 3600_000 };
const W = chatWindowMsFromTimeline(timeline);
const close = timeline.chatCloseAt;
async function makePlayer(uid, i) {
  const wallet = privateKeyToAccount('0x' + BigInt(i + 3701).toString(16).padStart(64, '0'));
  const ws = await wallet.signMessage({ message: `bitcoinu_mining_block${BLOCK}_user${uid}` });
  const { signKey, encryptKey, blockAddress } = deriveKeysFromSignature(ws, BLOCK);
  return { uid, wallet, encryptKey, signAccount: privateKeyToAccount(signKey), addr: wallet.address,
    bAddrString: blockAddress, depIds: JSON.stringify({ deposit: (10n ** 18n).toString(), ids: [String(i + 1)] }) };
}
const V = await makePlayer('user0001', 0), A = await makePlayer('user0002', 1), C = await makePlayer('user0003', 2);
const members = [V, A, C].map((p) => ({ uid: p.uid, addr: p.addr, bAddr: p.bAddrString, depIds: p.depIds }));
const mkMsg = async (p, text, ts) => ({ uid: p.uid, text, timestamp: ts,
  signature: canonicalizeSignature(await p.signAccount.signMessage({ message: chatSignStringV2(BLOCK, GROUP, p.uid, text, ts) })) });
const refOf = (m) => msgRefOf(computeMsgKeyV2(BLOCK, GROUP, m));
const mkRead = async (r, senderUid, refs, ts) => {
  const msgRefs = [...refs].sort(compareHexAsc);
  return { receiverUid: r.uid, senderUid, msgRefs, timestamp: ts, signature: canonicalizeSignature(
    await r.signAccount.signMessage({ message: readReceiptSignString(BLOCK, GROUP, r.uid, senderUid, msgRefs, ts) })) };
};
const mkVote = async (p, targetUid, ts) => {
  const encrypted = encryptAction({ targetUid }, p.encryptKey);
  return { encrypted, timestamp: ts, signature: canonicalizeSignature(
    await p.signAccount.signMessage({ message: actionSignStringV2('vote', BLOCK, GROUP, p.uid, encrypted, ts) })) };
};
const mkActRc = async (r, actorUid, action, ts) => {
  const actionHash = actionHashV2('vote', BLOCK, GROUP, actorUid, action.encrypted, action.timestamp);
  return { receiverUid: r.uid, actionHash, timestamp: ts, signature: canonicalizeSignature(
    await r.signAccount.signMessage({ message: receiptSignString(BLOCK, GROUP, r.uid, actionHash, ts) })) };
};
// 会話（A と V が交互に 25 往復・全部互いに既読）
const messages = [];
let ts = chattingStart + 3600_000;
for (let t = 1; t <= 25; t++) {
  messages.push(await mkMsg(A, `a${t}`.padEnd(200, '.'), (ts += 10_000)));
  messages.push(await mkMsg(V, `v${t}`.padEnd(200, '.'), (ts += 10_000)));
}
const reads = [];
for (const m of messages) {
  const r = m.uid === V.uid ? A : V;
  reads.push(await mkRead(r, m.uid, [refOf(m)], m.timestamp + 5_000));
}
const voteA = await mkVote(A, V.uid, chattingStart + 3700_000);
const vRcVoteA = await mkActRc(V, A.uid, voteA, chattingStart + 3705_000);
const V1 = await mkVote(V, A.uid, close - 25 * 60_000);           // 10分内に受領が見えず void 表示 → 再送
const V2 = await mkVote(V, A.uid, close - 7 * 60_000);
const R1 = await mkActRc(A, V.uid, V1, V1.timestamp + 5_000);      // 後から公開（窓内・鮮度内＝採点で有効）
const R2 = await mkActRc(A, V.uid, V2, W.endMs + 1_000);           // 窓外（採点で無効）・V2 から9分1秒＝鮮度内
const store = (list) => Object.fromEntries(list.map((rc, i) => [`k${i}`, { ...rc, _seq: i + 1 }]));
const buildV = (receipts) => buildSubmissionBundle({
  blockNum: BLOCK, groupId: GROUP, myUid: V.uid, encryptKey: V.encryptKey, members, messages,
  myDepositIds: ['1'], myVote: V2, myVotePrev: [V1], myReports: [],
  observedActions: { votes: { [A.uid]: voteA }, reports: {} }, receipts,
  intent: { vote: A.uid, reports: [] }, chatCaps: CAPS, chatWindow: W, submittedAt: close + 3600_000,
  signWallet: async (message) => V.wallet.signMessage({ message }),
  signReceiptAggregate: async (message) => canonicalizeSignature(await V.signAccount.signMessage({ message })),
});
const bA = await buildSubmissionBundle({     // A は R1 を自分の提出物に入れない（正当な選択）
  blockNum: BLOCK, groupId: GROUP, myUid: A.uid, encryptKey: A.encryptKey, members, messages,
  myDepositIds: ['2'], myVote: voteA, myVotePrev: [], myReports: [],
  observedActions: { votes: {}, reports: {} }, receipts: store([...reads, vRcVoteA]),
  intent: { vote: V.uid, reports: [] }, chatCaps: CAPS, chatWindow: W, submittedAt: close + 3600_000,
  signWallet: async (message) => A.wallet.signMessage({ message }),
  signReceiptAggregate: async (message) => canonicalizeSignature(await A.signAccount.signMessage({ message })),
});
const score = async (vBundle) => (await calculateGroupResults(
  { members, submissions: { [V.uid]: vBundle, [A.uid]: bA.bundle }, meta: { blockNum: BLOCK, groupId: GROUP } }, 500, 20, CAPS, W)).results;
const vRes = (res) => { const r = res.find((x) => x.uid === V.uid); return `V dq=${r.isDisqualified}${r.isDisqualified ? `(${r.disqualifyReasons.join('+')})` : ''} pts=${r.totalPoints}`; };

for (const [label, recs] of [['recovery (R2 in store)', [...reads, vRcVoteA, R1, R2]], ['official-like (window queue dropped R2)', [...reads, vRcVoteA, R1]]]) {
  const b = await buildV(store(recs));
  const pub = b.snapshotData.votes[V.uid];
  const decoded = decodeSubmissionPayloadString(b.payload);
  const pol = classifyEvidenceReceipts({ bundle: decoded.bundle, blockNum: BLOCK, groupId: GROUP, myUid: V.uid, chatWindow: W });
  const clsOf = (rc) => { const x = pol.receipts.find((r) => r.signature === rc.signature); return x ? pol.priorities.get(x) : 'absent'; };
  const untrimmed = await score(b.bundle);
  assert.equal(pub?.signature, V1.signature, `${label}: confirmed window chooses first valid vote`);
  assert.equal(clsOf(R1), 'V', `${label}: first vote receipt has final protection class`);
  assert.equal(pol.protectedV, 1);
  assert.equal(untrimmed.find((r) => r.uid === V.uid).isDisqualified, false);
  console.log(`${label}: R1=${clsOf(R1)} R2=${clsOf(R2)} V=${vRes(untrimmed)}`);
}

console.log('T1d vote trim: ALL PASSED');

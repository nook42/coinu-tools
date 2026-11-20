// players.mjs — 決定論プレイヤーと実プロトコルデータのビルダー（v3.2）。
//
// 鍵導出チェーンは本番と同一（src/utils/walletTools.js deriveKeysFromSignature /
// script/test-calculator/calc-v2-test.mjs makePlayer）:
//   walletKey（固定値） → sig = personal_sign("bitcoinu_mining_block{N}_user{uid}")
//   → master = keccak256(sig)
//   → signKey = keccak256(master‖"sign")（全署名・永遠非公開） → signAccount → bAddr
//   → encryptKey = keccak256(master‖"encrypt")（投票/密告自己暗号化・提出時公開）
// メッセージ/投票/密告/受領証明/提出は protocol-v2 の正準形で実署名・実ECIES。
import { keccak256, toHex, toBytes, concat, stringToBytes } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { encrypt } from 'eciesjs';
import {
  chatSignStringV2, actionSignStringV2, actionHashV2,
  receiptSignString, readReceiptSignString,
  computeChatHashV2, computeMsgKeyV2, msgRefOf, padActionPlaintext,
  buildRealTargets, selectBundleReceipts, receiptMaxRefsPerReceipt, receiptCanonCmp,
  buildMsgKeyGetter, canonicalComparatorV2,
  applyChatCaps, GUEST_PINNED_RULES,
  aggregateSelfReceipts, filterReceiptsToCarriedTargets,
  limitCarriedReceiptFacts,
  normalizeActionSnapshotForSubmission,
  encodeEvidenceCompactV1, compactBytesToPayload, compactPayloadToBytes,
} from './canonical.mjs';
import { canonicalizeSignature } from '../../src/utils/walletTools.js';
import { deriveNostrKey } from '../../src/utils/p2pKeys.js';
import { clientChatSourcedReceipts } from '../vendor/workers/game_workers/lib/protocol-v2.js';

const enc = new TextEncoder();

/// 🔴 P-2026-0842（2026-08-08）: 平文は **`padActionPlaintext` で固定長**にしてから暗号化する
///    （正典 `encryptAction` と同じ経路）。パディングしないと暗号文長が対象 uid の桁数を漏らし、
///    採点正典（`isCanonicalActionCiphertext`）もライブ層も受け付けない。
export function eciesEncryptFor(pubKeyHex, text) {
  const clean = pubKeyHex.startsWith('0x') ? pubKeyHex.slice(2) : pubKeyHex;
  return Buffer.from(encrypt(clean, enc.encode(padActionPlaintext(text)))).toString('hex');
}

// 固定ウォレット秘密鍵（決定論。hardhat の周知鍵と衝突しない小さいスカラー）
export const fixedWalletKey = (i) => '0x' + BigInt(i + 1).toString(16).padStart(64, '0');

export async function makePlayer({ uid, lang, blockNum, keyIndex, walletKey: suppliedWalletKey = null, name = null, img = null, verified = false }) {
  const walletKey = suppliedWalletKey || fixedWalletKey(keyIndex);
  const wallet = privateKeyToAccount(walletKey);
  // 本番 walletTools と同じ canonical signature を鍵素材にする。
  const sig = canonicalizeSignature(await wallet.signMessage({ message: `bitcoinu_mining_block${blockNum}_user${uid}` }));
  const master = keccak256(toBytes(sig));
  const signKey = keccak256(concat([toBytes(master), stringToBytes('sign')]));
  const encryptKey = keccak256(concat([toBytes(master), stringToBytes('encrypt')]));
  const signAccount = privateKeyToAccount(signKey);
  const encryptAccount = privateKeyToAccount(encryptKey);
  const nostrPubkey = deriveNostrKey(signKey, blockNum).pubkey;
  return {
    uid, lang, name, img, verified,
    walletKey, wallet, signKey, encryptKey, signAccount, encryptAccount,
    addr: wallet.address,
    bAddrObj: { address: signAccount.address, pubKey: signAccount.publicKey, nostrPubkey },
    // walletTools.js deriveKeysFromSignature と同一シリアライズ（pubKey は viem publicKey = "0x04…"）
    bAddrString: JSON.stringify({ address: signAccount.address, pubKey: signAccount.publicKey, nostrPubkey }),
    depIds: null, // gen-fixture がオンチェーンdeposit確定後に entry-worker 形式で埋める
    deposits: [],
  };
}

// entry-worker.js:406-424 と同一の depositIds JSON（キー順: deposit, ids, deposits[]、
// deposits[i] = { id, idFrom, amount, depositerAddress, unlockTime, (name), (img) }）
export function buildDepIdsJson(deposits) {
  let total = 0n;
  for (const d of deposits) total += BigInt(d.amount);
  const list = deposits.map(d => {
    const dep = {
      id: d.id,
      idFrom: d.idFrom,
      amount: d.amount,
      depositerAddress: d.depositerAddress ?? null,
      unlockTime: d.unlockTime,
    };
    if (d.name) dep.name = d.name;
    if (d.img) dep.img = d.img;
    return dep;
  });
  return JSON.stringify({
    deposit: total.toString(),
    // 🔴 本番は 10進**文字列**（entry_workers/lib/deposit-id.js:36 の
    //    canonicalizeDepositId が BigInt(x).toString(10) を返す）。
    //    数値のままだと提出署名のバイト列が本番と食い違い、
    //    P-2026-0806 の型検査で invalid_signature になる。
    ids: deposits.map(d => BigInt(d.id).toString(10)),
    deposits: list,
  });
}

// ---- チャット（クライアント→WS 'chat' の data 部・signKey署名）----
export async function makeChatWsData(player, blockNum, groupId, text, timestamp) {
  const normalized = text;
  const signature = await player.signAccount.signMessage({
    message: chatSignStringV2(blockNum, groupId, player.uid, normalized, timestamp),
  });
  return { text: normalized, timestamp, signature };
}

// ---- 投票/密告（クライアント→WS 'vote'/'report' の data 部）----
// payload は本番と同一: vote={targetUid} / report={targetUid, reason:'suspected_bot'}
// （ChatPhase.js）。encryptKey自己ECIES＋signKey署名。
export async function makeActionWsData(player, type, payload, blockNum, groupId, timestamp) {
  const encrypted = eciesEncryptFor(player.encryptAccount.publicKey, JSON.stringify(payload));
  const signature = await player.signAccount.signMessage({
    message: actionSignStringV2(type, blockNum, groupId, player.uid, encrypted, timestamp),
  });
  return { encrypted, signature, timestamp };
}

// ---- 受領証明（クライアント→WS 'receipt' の data.receipt 部・signKey自動署名）----
// アクション受領: {receiverUid, actionHash, timestamp, signature}
export async function makeActionReceipt(receiver, actorUid, actionType, action, blockNum, groupId, timestamp) {
  const actionHash = actionHashV2(actionType, blockNum, groupId, actorUid, action.encrypted, action.timestamp);
  const signature = await receiver.signAccount.signMessage({
    message: receiptSignString(blockNum, groupId, receiver.uid, actionHash, timestamp),
  });
  return { receiverUid: receiver.uid, actionHash, timestamp, signature };
}

// 既読バッチ受領: {receiverUid, senderUid, msgRefs[], timestamp, signature}（案B: 16バイト参照）
// msgs は sender の署名済みメッセージ配列（正準形）。
export async function makeReadReceipt(receiver, senderUid, msgs, blockNum, groupId, timestamp) {
  const msgRefs = msgs
    .filter(m => m.uid === senderUid)
    .map(m => msgRefOf(computeMsgKeyV2(blockNum, groupId, m)))
    // C25-01/P25-01: 配列順も署名済みsnapshotの正式表現の一部。
    // 署名helper側だけで並べ替えるとwire本体が非正準のまま残るため、生成前に固定する。
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  if (msgRefs.length === 0) return null;
  const signature = await receiver.signAccount.signMessage({
    message: readReceiptSignString(blockNum, groupId, receiver.uid, senderUid, msgRefs, timestamp),
  });
  return { receiverUid: receiver.uid, senderUid, msgRefs, timestamp, signature };
}

// ---- 提出バンドル（正規JSON文字列 = WSとEvidenceの両方へ送る同一バイト列）----
// MIRROR: src/components/game/SubmissionPhase.js の cappedMessages から compact payload までの提出構築
// SubmissionPhase.js handleSubmit と同じ共有関数で構築（v3.2）:
//   snapshotData = { votes: {selfのみ}, reports: {selfのみ},
//                    observed: { votes: {uid→[action]（__extras含む）}, reports: {uid→[action]},
//                                receipts: [署名昇順] } }
//   encryptedDataHash = keccak256(toHex(JSON.stringify(snapshotData)))
//   dataString = JSON.stringify({blockNum, uid, encryptKey, chatHash, submittedAt, encryptedDataHash, depositIds})
//   signature = wallet.personal_sign(dataString)
//   payload = JSON.stringify({uid, encryptKey, chatHash, signature, submittedAt,
//                             encryptedDataHash, depositIds, encryptedActions, messages})
// serverVotes: {uid→action} / serverReports: {uid→[action]} / receipts: 全観測受領証明
export async function buildSubmissionPayload(player, {
  blockNum, groupId, serverMessages, serverVotes = {}, serverReports = {}, receipts = [],
  submittedAt, depositIds, memberUids, chatWindow = null, chatCloseAt = null,
}) {
  const rosterUids = memberUids || [...new Set((serverMessages || []).map((m) => m.uid))];
  const compareCanonical = canonicalComparatorV2(buildMsgKeyGetter(blockNum, groupId));
  const capped = applyChatCaps(
    Array.isArray(serverMessages) ? serverMessages : [],
    GUEST_PINNED_RULES,
    compareCanonical,
  );
  const uniqueMessages = new Map();
  for (const message of capped) {
    const key = computeMsgKeyV2(blockNum, groupId, message);
    if (!uniqueMessages.has(key)) uniqueMessages.set(key, message);
  }
  const cappedMessages = [...uniqueMessages.values()].sort(compareCanonical);

  const snapshotData = { votes: {}, reports: {}, observed: { votes: {}, reports: {}, receipts: [] } };
  if (serverVotes[player.uid]) snapshotData.votes[player.uid] = serverVotes[player.uid];
  if (Array.isArray(serverReports[player.uid]) && serverReports[player.uid].length > 0) {
    snapshotData.reports[player.uid] = serverReports[player.uid];
  }
  for (const [u, v] of Object.entries(serverVotes)) {
    if (u === player.uid || !v) continue;
    snapshotData.observed.votes[u] = Array.isArray(v) ? v : [v];
  }
  for (const [u, arr] of Object.entries(serverReports)) {
    if (u === player.uid || !Array.isArray(arr) || arr.length === 0) continue;
    snapshotData.observed.reports[u] = arr;
  }
  const normalized = normalizeActionSnapshotForSubmission(snapshotData, {
    blockNum: Number(blockNum),
    groupId: Number(groupId),
    memberUids: rosterUids,
    submitterUid: player.uid,
  });
  snapshotData.votes = normalized.votes;
  snapshotData.reports = normalized.reports;
  snapshotData.observed = normalized.observed;

  const targets = buildRealTargets(snapshotData, cappedMessages, blockNum, groupId);
  const kept = selectBundleReceipts(clientChatSourcedReceipts(receipts, chatWindow, chatCloseAt), targets, {
    compare: receiptCanonCmp,
    memberUids: rosterUids,
    chatWindow: null,
    maxRefsPerReceipt: receiptMaxRefsPerReceipt(GUEST_PINNED_RULES.maxMessages),
    selfUid: player.uid,
  });
  const byArrival = [...kept].sort((a, b) => (a._seq ?? 0) - (b._seq ?? 0));
  const normalizedReceipts = byArrival.map((receipt) => (
    Array.isArray(receipt.msgRefs) && receipt.senderUid != null
      ? {
          receiverUid: receipt.receiverUid, senderUid: receipt.senderUid,
          msgRefs: receipt.msgRefs, timestamp: receipt.timestamp, signature: receipt.signature,
        }
      : {
          receiverUid: receipt.receiverUid, actionHash: receipt.actionHash,
          timestamp: receipt.timestamp, signature: receipt.signature,
        }
  ));
  const aggregated = await aggregateSelfReceipts(
    normalizedReceipts,
    player.uid,
    blockNum,
    groupId,
    async (message) => canonicalizeSignature(
      await player.signAccount.signMessage({ message }),
    ),
    targets,
    chatWindow,
  );
  snapshotData.observed.receipts = aggregated.receipts;
  if (aggregated.aggregate) snapshotData.observed.selfReceiptAggregate = aggregated.aggregate;
  const carried = filterReceiptsToCarriedTargets(
    snapshotData, cappedMessages, blockNum, groupId,
  );
  const limited = limitCarriedReceiptFacts(carried, { submitterUid: player.uid, compare: receiptCanonCmp });
  snapshotData.observed = limited.observed;

  const chatHash = computeChatHashV2(cappedMessages, blockNum, groupId);
  let encryptedDataHash = keccak256(toHex(JSON.stringify(snapshotData)));
  const dataString = JSON.stringify({
    blockNum: Number(blockNum),
    uid: player.uid,
    encryptKey: player.encryptKey,
    chatHash,
    submittedAt,
    encryptedDataHash,
    depositIds,
  });
  const signature = canonicalizeSignature(await player.wallet.signMessage({ message: dataString }));
  const submittedMessages = cappedMessages.map(m => ({
    type: 'chat',
    blockNum: Number(blockNum),
    groupId: Number(groupId),
    uid: m.uid,
    text: m.text,
    timestamp: m.timestamp,
    signature: m.signature,
  }));
  let logical = {
    uid: player.uid,
    encryptKey: player.encryptKey,
    chatHash,
    signature,
    submittedAt,
    encryptedDataHash,
    depositIds,
    encryptedActions: snapshotData,
    messages: submittedMessages,
  };
  const encodeCtx = {
    blockNum: Number(blockNum),
    groupId: Number(groupId),
    memberUids: rosterUids,
  };
  const sanitized = {};
  let compact = encodeEvidenceCompactV1(logical, encodeCtx, { sanitized });
  if (sanitized.bundle) {
    const fixedSnapshot = sanitized.bundle.encryptedActions;
    encryptedDataHash = keccak256(toHex(JSON.stringify(fixedSnapshot)));
    const fixedSignature = canonicalizeSignature(await player.wallet.signMessage({
      message: JSON.stringify({
        blockNum: Number(blockNum),
        uid: player.uid,
        encryptKey: player.encryptKey,
        chatHash,
        submittedAt,
        encryptedDataHash,
        depositIds,
      }),
    }));
    logical = {
      ...sanitized.bundle,
      signature: fixedSignature,
      encryptedDataHash,
    };
    const again = {};
    compact = encodeEvidenceCompactV1(logical, encodeCtx, { sanitized: again });
    if (again.bundle) throw new Error('compact encode still dropped receipts after sanitizing');
  }
  const payload = compactBytesToPayload(compact);
  return { payload, chatHash, encryptedDataHash };
}

// ---- gzip（src/utils/evidence.js gzipString / submitResultOnChain の選択規則）----
export async function gzipBytes(str) {
  const cs = new CompressionStream('gzip');
  const stream = new Blob([str]).stream().pipeThrough(cs);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

// evidence.js: gz と raw の小さい方を選び、選択結果が MIN_DATA_BYTES(256) 未満なら raw
export async function evidenceBytesFor(payload) {
  return compactPayloadToBytes(payload);
}

export const bytesToHex = (bytes) => '0x' + Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

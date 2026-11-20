// S3R4-U-PRIORITY: 最優先欄は J-26 の「表示にだけ窓を適用する」の例外。
// 正直なクライアントは確定した宣言窓と確定名簿で E・E′ を確かめてから置く。
// 窓や名簿が採点と違うと束ごと拒まれ、DO は窓を見ずに受け付けるので取り返せない。
// extendGrace の古い窓への心配はここには当たらない。窓が最終になるのは、
// chatOpenAt 以後のブロックで名簿の登録が非ゼロと読めたとき。
// extendGrace は開始後・名簿つきで Started with roster を返し、名簿なしは全員0点。
// クライアントは名簿と窓が確定したとき置く（運営ノードを選んだときも・S3R4-U-OPRPC-E）。
// 便 P2a-2 が配線した。
// 通常欄の組み立てとサーバーには今までどおり窓を入れない。

import {
  buildMsgKeyGetter, canonicalComparatorV2, chatSignStringV2,
  readReceiptSignString, computeMsgKeyV2, msgRefOf, isReceiptTimely,
} from './protocol-v2.js';
import { selfReceiptAggregateSignString, filterReceiptsToCarriedTargets } from './evidence-compact-v1.js';
import {
  isPlainRecord, validateMessages, validatePriorityStructure,
} from './submission-limits.js';
import { countMessageTurns, filterVisibleMessages } from './char-counter.js';

const hasOwn = Object.prototype.hasOwnProperty;

export async function verifyPriorityFields(bundle, {
  blockNum, groupId, memberUids, bAddrOf, chatWindow, verify,
} = {}) {
  const ea = bundle?.encryptedActions;
  if (!isPlainRecord(ea) || !hasOwn.call(ea, 'priority')) return { ok: true };
  const priority = ea.priority;
  const roster = new Set(memberUids);
  const inWin = (timestamp) => chatWindow == null
    || (chatWindow.startMs <= timestamp && timestamp <= chatWindow.endMs);
  const addressOf = (uid) => {
    if (!roster.has(uid)) return null;
    const address = bAddrOf(uid)?.address;
    return typeof address === 'string' ? address : null;
  };
  const check = async (uid, message, signature) => {
    try {
      const address = addressOf(uid);
      if (address === null) return false;
      return Boolean(await verify({ address, message, signature }));
    }
    catch { return false; }
  };
  for (const message of priority.messages) {
    if (!inWin(message.timestamp)) return { ok: false, reason: 'priority message is outside the chat window' };
    if (!await check(message.uid,
      chatSignStringV2(blockNum, groupId, message.uid, message.text, message.timestamp),
      message.signature)) return { ok: false, reason: 'priority message signature is invalid' };
  }
  for (const receipt of priority.receipts) {
    if (!inWin(receipt.timestamp)) return { ok: false, reason: 'priority receipt is outside the chat window' };
    if (!await check(receipt.receiverUid,
      readReceiptSignString(blockNum, groupId, receipt.receiverUid, receipt.senderUid,
        receipt.msgRefs, receipt.timestamp), receipt.signature)) {
      return { ok: false, reason: 'priority receipt signature is invalid' };
    }
  }
  if (hasOwn.call(priority, 'selfReceiptAggregate')) {
    const aggregate = priority.selfReceiptAggregate;
    if (aggregate.entries.some((entry) => !inWin(entry.timestamp))) {
      return { ok: false, reason: 'priority aggregate entry is outside the chat window' };
    }
    if (!await check(bundle.uid,
      selfReceiptAggregateSignString(blockNum, groupId, bundle.uid, aggregate.entries),
      aggregate.signature)) return { ok: false, reason: 'priority aggregate signature is invalid' };
  }
  return { ok: true };
}

export function priorityTurnGuarantee(priority, {
  ownerUid, blockNum, groupId, minMessages,
} = {}) {
  if (!isPlainRecord(priority) || !Array.isArray(priority.messages)) return 0;
  const getter = buildMsgKeyGetter(blockNum, groupId);
  const ordered = [...priority.messages].sort(canonicalComparatorV2(getter));
  const turns = countMessageTurns(filterVisibleMessages(ordered));
  return Math.min(minMessages, turns[ownerUid] ?? 0);
}

// 署名前の束に当てる口。読む入力は uid・messages・encryptedActions.priority だけ。
// chatWindow は GM の calcEvidenceUnit と同じ Evidence.chatWindow(N)×1000 ± CHAT_WINDOW_CLOCK_SKEW_MS で組む。狭い窓は安全だが、広い窓はサーバーが束ごと拒む。
export async function evaluatePriorityGuarantee(bundle, {
  blockNum, groupId, memberUids, bAddrOf, chatWindow, verify, minMessages,
} = {}) {
  let readyAddresses = false;
  if (Array.isArray(memberUids) && typeof bAddrOf === 'function') {
    try { readyAddresses = memberUids.every((uid) => typeof bAddrOf(uid)?.address === 'string'); }
    catch { readyAddresses = false; }
  }
  if (!Array.isArray(memberUids) || !memberUids.includes(bundle?.uid)
    || !Number.isSafeInteger(minMessages) || minMessages < 0
    || !readyAddresses
    || !isPlainRecord(chatWindow)
    || !Number.isFinite(chatWindow.startMs) || !Number.isFinite(chatWindow.endMs)
    || chatWindow.startMs > chatWindow.endMs) {
    return { ok: false, value: 0, reason: 'not_ready' };
  }
  const messages = validateMessages(bundle.messages, { blockNum, groupId, memberUids });
  if (!messages.ok) return { ok: false, value: 0, reason: messages.reason };
  const priority = validatePriorityStructure(bundle, { blockNum, groupId, memberUids });
  if (!priority.ok) return { ok: false, value: 0, reason: priority.reason };
  const verified = await verifyPriorityFields(bundle, {
    blockNum, groupId, memberUids, bAddrOf, chatWindow, verify,
  });
  if (!verified.ok) return { ok: false, value: 0, reason: verified.reason };
  return { ok: true, value: priorityTurnGuarantee(bundle.encryptedActions?.priority,
    { ownerUid: bundle.uid, blockNum, groupId, minMessages }) };
}

// P2c が切り詰めで呼ぶ純粋な口。刈った E は messages へ戻さず、
// 自己集約は一部だけ残して署名を無効にしないよう丸ごと外す。
export function prunePriorityToCoverage(snapshot, messages, {
  dropReceipts = [], dropSelfAggregate = false,
} = {}, { blockNum, groupId } = {}) {
  const keyOf = buildMsgKeyGetter(blockNum, groupId);
  const source = snapshot || {};
  const original = source.priority;
  if (!isPlainRecord(original)) {
    return filterReceiptsToCarriedTargets(source, messages, blockNum, groupId);
  }
  let e = [...original.messages];
  let receipts = original.receipts.filter((receipt) => !dropReceipts.includes(receipt));
  let aggregate = dropSelfAggregate ? null : (original.selfReceiptAggregate || null);
  for (;;) {
    const eKeys = new Set(e.map((message) => keyOf(message)));
    const targetKeys = new Map();
    for (const message of [...e, ...(Array.isArray(messages) ? messages : [])]) {
      const key = keyOf(message);
      const refKey = JSON.stringify([message.uid, msgRefOf(key)]);
      if (!targetKeys.has(refKey)) targetKeys.set(refKey, { key, message });
      else if (targetKeys.get(refKey)?.key !== key) targetKeys.set(refKey, null);
    }
    const targetOf = (senderUid, ref) => targetKeys.get(JSON.stringify([senderUid, ref]));
    const nextReceipts = receipts.filter((receipt) => receipt.msgRefs.every((ref) => targetOf(receipt.senderUid, ref))
      && receipt.msgRefs.some((ref) => {
        const target = targetOf(receipt.senderUid, ref);
        return eKeys.has(target.key) && isReceiptTimely(receipt.timestamp, target.message.timestamp);
      }));
    let nextAggregate = aggregate;
    if (nextAggregate && nextAggregate.entries.some((entry) => {
      const target = targetOf(entry.senderUid, entry.msgRef);
      return !target || !eKeys.has(target.key) || !isReceiptTimely(entry.timestamp, target.message.timestamp);
    })) nextAggregate = null;
    const covered = new Set();
    for (const receipt of nextReceipts) {
      for (const ref of receipt.msgRefs) {
        const target = targetOf(receipt.senderUid, ref);
        if (eKeys.has(target.key) && isReceiptTimely(receipt.timestamp, target.message.timestamp)) covered.add(target.key);
      }
    }
    for (const entry of nextAggregate?.entries || []) covered.add(targetOf(entry.senderUid, entry.msgRef).key);
    const nextE = e.filter((message) => covered.has(keyOf(message)));
    const changed = nextE.length !== e.length || nextReceipts.length !== receipts.length || nextAggregate !== aggregate;
    e = nextE; receipts = nextReceipts; aggregate = nextAggregate;
    if (!changed) break;
  }
  const result = { ...source };
  if (e.length === 0) delete result.priority;
  else {
    result.priority = { messages: e, receipts };
    if (aggregate) result.priority.selfReceiptAggregate = aggregate;
  }
  return filterReceiptsToCarriedTargets(result, messages, blockNum, groupId);
}

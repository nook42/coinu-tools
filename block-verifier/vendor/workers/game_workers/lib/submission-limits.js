// Signed submission envelope limits (Round 21 / R21-F1).
//
// This module is deliberately free of runtime-specific APIs.  The browser,
// ChatGameDO, calculator, Rust-host fixtures and the independent tools all use
// these values as the finite input contract.  Changing a value is a protocol
// change and requires a manifest rule/version bump.

import {
  countHalfWidthChars, hasVisibleContent,
  PRIORITY_OWN_MESSAGES_MAX, PRIORITY_OTHER_MESSAGES_MAX,
  PRIORITY_MESSAGES_MAX, PRIORITY_RECEIPTS_MAX,
} from './char-counter.js';
export {
  PRIORITY_OWN_MESSAGES_MAX, PRIORITY_OTHER_MESSAGES_MAX,
  PRIORITY_MESSAGES_MAX, PRIORITY_RECEIPTS_MAX,
} from './char-counter.js';
import {
  actionHashV2,
  canonArrayIndex,
  compareHexAsc,
  compareStrAsc,
  computeMsgKeyV2,
  isActionHash,
  isCanonicalActionCiphertext,
  isCanonicalDepositIds,
  isRepresentableSignature,
  isCanonicalSignature,
  isCanonicalText,
  isCanonicalTimestamp,
  isCanonicalUid,
  isMsgRef,
  isReceiptTimely,
  msgRefOf,
} from './protocol-v2.js';

export const SUBMISSION_LIMITS_VERSION = 8;
// S3R4-U-DUPGATE: 提出物内の参照の重複を許し、上限は重複を除かない数で掛ける。
export const EVIDENCE_COMPACT_FORMAT = 'bitcoinu-evidence-compact/2';

export const MAX_GROUP_PLAYERS = 5;
// ChatGameDO の単一値保存上限。
export const VALUE_SAFE_BYTES = 100000;
export const MAX_DEPOSIT_IDS = 10;
export const MAX_MESSAGES_PER_PLAYER = 100;
export const MAX_MESSAGES_TOTAL = MAX_GROUP_PLAYERS * MAX_MESSAGES_PER_PLAYER; // 500
export const MAX_MESSAGE_CHARS = 1_000;
export const MAX_MESSAGE_CHARS_PER_PLAYER = 10_000;
export const MAX_ACCEPTED_VOTES_PER_PLAYER = 1;
export const MAX_ACCEPTED_REPORTS_PER_PLAYER = 2;
// 受領 fact 内訳の導出メモ。この2値は個別の受理上限ではなく、
// manifest にも宣言しない。入口で強制するのは下の合計2,400だけである。
export const MAX_CHAT_RECEIPT_FACTS = 2_000;
export const MAX_ACTION_RECEIPT_FACTS = 400; // 受領者5 × 発信者4 × 行動20
export const MAX_RECEIPT_FACTS = MAX_CHAT_RECEIPT_FACTS + MAX_ACTION_RECEIPT_FACTS; // 2,400
// 5人組で受領者本人を除く4発信者 ×（発言100 + 投票10 + 密告10）。
// 正規クライアントの通常件数ではなく、採点規則が許す上限から固定値を導く。
export const MAX_SELF_AGGREGATE_TARGETS = 480;

// The server keeps every legal fact.  These caps are intentionally distinct
// from Evidence.sol's 130,000-byte transaction cap, where C/D facts may be
// trimmed.
//
// v8 (2026-10-08・S3R4-U-PRIORITY): encryptedActions.priority（E・E′）。
// E′ は独立の上限で数え、通常欄の上限には足さない。EVC の版2 で運ぶ。
// 🔴 v7 (2026-08-21): Round 9 で受理ゲートの message.blockNum / groupId を
// 非負の safe-integer number に限定。compact は従来から同じ number を復元するため、
// compact 経路を通る提出物の受理・棄却は1通も変わらない。受理集合に対する
// 現在の実測最大は decoded 1,548,432 B / wire 312,766 B / nodes 21,240。
// いずれも self aggregate entry が1件の A=1 構成が最大。
// 最優先欄つきの実測最大: decoded 1,711,661 B / wire 323,634 B / nodes 25,483（E 40・E′ legacy 40×100 または legacy 39＋集約20）。
// decoded と nodes は構造ゲート最大 A=1、wire は serverLimit＋E′ を実測。
// E′ の解析上界: legacy 40×276 = 11,040 B。legacy 39＋集約20 は
// 39×276＋集約 wrapper 67＋entry 20×11 = 11,051 B（ほかに E 40 と欄の header）。
//
// Round 9 で wire 内訳を実装のエンコーダと突き合わせて訂正:
//   text     5 * (99 * ceil(97*9/8) + ceil(397*9/8))                =    56,685
//            encodeText16Units は発言ごとに bits.finish() でバイト境界へ揃える
//   messages 500 * (4 text units + 1 uid + 8 delta + 64 signature) =    38,500
//   receipts 2,000 * 78 read + 400 * 76 action                     =   186,400
//            read=kind1+receiver1+sender1+delta8+sig64+count1+index2
//            action=kind1+receiver1+delta8+sig64+index2
//   actions  100 * (225 cipher bytes + 64 signature + 8 delta)     =    29,700
//            ACTION_CIPHERTEXT_HEX_LEN=450 は hex 文字数で、wire は225バイト
//   tables   frame header 12 + context 16 + uid table 406 + submitter 1
//            + encryptKey 68 + chatHash 33 + outer signature 65
//            + submittedAt 8 + encryptedDataHash 33 + depositIds 791
//            + action section headers 40 + u16 counts 4 + aggregate flag 1
//            + hasPriority 1                                            =     1,479
//   A=0      56,685 + 38,500 + 186,400 + 29,700 + 1,479              =   312,764
//   A=1      aggregate wrapper 67 + entry 11 - action receipt 76    =        +2
//                                                                       =   312,766
//
// 🔴 上限3定数の据え置き方針（2026-08-21・ユーザー確定）
//    下の解析値は「その時点の実測最大」であり、バッファ率は計測のたびに変動する。
//    バッファ =（上限 − 実測最大）÷ 上限。
//    ・バッファ > 10% … 上限は動かさない。ここの数値だけ実測へ更新する
//    ・バッファ ≤ 10% … 初めて判断事項として上げる
//    ・実測が下の解析値を超えた … 上限は動かさず、解析値のほうを実測へ直す
//    したがって 442,368 / 2,097,152 / 32,768 は「解析値の +30%」ではない。
//    据え置きの値。欄なしのバッファは wire 29.3% / decoded 26.2% / nodes 35.2%。
//    最優先欄つき実測のバッファは wire 26.8% / decoded 18.4% / nodes 22.2%。
//
// 🔴 WS frame ceiling: the payload is hex-encoded on the wire
// (`compactBytesToPayload = bytesHex`), so the WebSocket message is 2x
// SERVER_MAX_WIRE_BYTES.  CHAT_GAME_SIMPLIFICATION_SPEC.md records the frame
// limit as ~1 MiB, but this repository has no pinned, versioned platform primary
// source for that limit.  `JSON.stringify({type:'submit',payload})` adds 32 B
// including the payload's `0x`: 442,368 * 2 + 32 = 884,768 B ≈ 84.4% of 1 MiB.
export const SERVER_MAX_WIRE_BYTES = 27 * 16 * 1024; // 442,368
export const SERVER_MAX_DECODED_BYTES = 32 * 64 * 1024; // 2,097,152
export const EVIDENCE_MAX_WIRE_BYTES = 130_000;

export const MAX_UID_BYTES = 80;
export const MAX_ACTION_CANDIDATES_PER_TYPE_PER_ACTOR = 10;
export const MAX_RECEIPT_OBJECTS = MAX_RECEIPT_FACTS;
export const MAX_REFS_PER_RECEIPT = MAX_MESSAGES_PER_PLAYER;
export const MAX_NESTING_DEPTH = 8;
// 🔴 v5: was a bare literal 20_000 inside assertBoundedShape, which made it the
//    *binding* limit (the honest maximum used 97.8% of it) while being unnamed,
//    underived and absent from the derivation comment above.  The analytic
//    rounded upper bound is 21,500 nodes, so 20,000 rejected legal submissions.
//    32,768 is a retained ceiling under the policy above, not a +30% derivation.
export const MAX_SUBMISSION_NODES = 32_768;

const hasOwn = Object.prototype.hasOwnProperty;

function hasExactOwnKeys(value, expected) {
  if (!isPlainRecord(value)) return false;
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => hasOwn.call(value, key));
}

const isBytes32Hex = (value) => typeof value === 'string' && /^0x[0-9a-f]{64}$/.test(value);
const isCanonicalChatHash = (value) => value === '0x' || isBytes32Hex(value);

function actionCanonCmp(type, blockNum, groupId, uid, a, b) {
  const ah = actionHashV2ForLimit(type, blockNum, groupId, uid, a);
  const bh = actionHashV2ForLimit(type, blockNum, groupId, uid, b);
  return (a.timestamp - b.timestamp)
    || compareHexAsc(ah, bh)
    || compareStrAsc(a.signature.toLowerCase(), b.signature.toLowerCase());
}

function actionHashV2ForLimit(type, blockNum, groupId, uid, action) {
  return actionHashV2(type, blockNum, groupId, uid, action.encrypted, action.timestamp);
}

export function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

export function utf8ByteLength(value) {
  return new TextEncoder().encode(String(value)).byteLength;
}

// isCanonicalUid（印字可能 ASCII）を先に通した uid 専用。JSON 文字列内で
// 追加の escape 1 byte を要するのは二重引用符と backslash だけである。
export function uidEscapedLength(uid) {
  let length = uid.length;
  for (const char of uid) if (char === '"' || char === '\\') length += 1;
  return length;
}

export function assertBoundedShape(root, {
  maxDepth = MAX_NESTING_DEPTH,
  maxArrayLength = MAX_RECEIPT_FACTS,
  maxObjectKeys = 32,
  maxStringBytes = SERVER_MAX_DECODED_BYTES,
} = {}) {
  const stack = [{ value: root, depth: 0 }];
  let nodes = 0;
  while (stack.length) {
    const { value, depth } = stack.pop();
    nodes++;
    if (nodes > MAX_SUBMISSION_NODES) throw new Error('submission has too many nested values');
    if (typeof value === 'string') {
      if (utf8ByteLength(value) > maxStringBytes) throw new Error('submission string exceeds byte limit');
      continue;
    }
    if (value === null || typeof value !== 'object') continue;
    if (depth >= maxDepth) throw new Error('submission nesting exceeds limit');
    if (Array.isArray(value)) {
      if (value.length > maxArrayLength) throw new Error('submission array exceeds element limit');
      for (let i = value.length - 1; i >= 0; i--) stack.push({ value: value[i], depth: depth + 1 });
      continue;
    }
    if (!isPlainRecord(value)) throw new Error('submission contains a non-plain object');
    const keys = Object.keys(value);
    if (keys.length > maxObjectKeys) throw new Error('submission object has too many keys');
    for (const key of keys) stack.push({ value: value[key], depth: depth + 1 });
  }
}

// The submitted list remains in the wallet-signed envelope as a finite,
// canonical and unique record.  It is not scored against the operator-supplied
// entry roster: that one-way comparison could only disqualify a target after
// the roster had been reduced, while the ids do not affect reward calculation.
export function validateDepositIds(depositIds) {
  if (!Array.isArray(depositIds)) return { ok: false, reason: 'depositIds must be an array' };
  if (depositIds.length > MAX_DEPOSIT_IDS) return { ok: false, reason: `depositIds exceeds ${MAX_DEPOSIT_IDS}` };
  if (!isCanonicalDepositIds(depositIds)) return { ok: false, reason: 'depositIds contains a non-canonical id' };
  if (new Set(depositIds).size !== depositIds.length) return { ok: false, reason: 'depositIds contains duplicates' };
  return { ok: true };
}

function messageShapeIsCanonical(message, blockNum, groupId, roster) {
  return isPlainRecord(message)
    && Object.keys(message).length === 7
    && JSON.stringify(message) === JSON.stringify({
      type: message.type, blockNum: message.blockNum, groupId: message.groupId,
      uid: message.uid, text: message.text, timestamp: message.timestamp, signature: message.signature,
    })
    && message.type === 'chat'
    && Number.isSafeInteger(message.blockNum) && message.blockNum >= 0
    && message.blockNum === Number(blockNum)
    && Number.isSafeInteger(message.groupId) && message.groupId >= 0
    && message.groupId === Number(groupId)
    && isCanonicalUid(message.uid)
    && !(uidEscapedLength(message.uid) > MAX_UID_BYTES)
    && (roster.size === 0 || roster.has(message.uid))
    && isCanonicalText(message.text)
    && isCanonicalTimestamp(message.timestamp)
    && isCanonicalSignature(message.signature);
}

export function validateMessages(messages, { blockNum, groupId, memberUids } = {}) {
  if (!Array.isArray(messages)) return { ok: false, reason: 'messages must be an array' };
  if (messages.length > MAX_MESSAGES_TOTAL) return { ok: false, reason: `messages exceeds ${MAX_MESSAGES_TOTAL}` };
  if (Array.isArray(memberUids)
    && (memberUids.length < 1 || memberUids.length > MAX_GROUP_PLAYERS
      || new Set(memberUids).size !== memberUids.length
      || memberUids.some((uid) => !isCanonicalUid(uid) || uidEscapedLength(uid) > MAX_UID_BYTES))) {
    return { ok: false, reason: `roster uid exceeds canonical ${MAX_UID_BYTES}-byte form` };
  }
  const roster = new Set(Array.isArray(memberUids) ? memberUids : []);
  const counts = new Map();
  const chars = new Map();
  const seen = new Set();
  let previous = null;
  for (const message of messages) {
    if (!messageShapeIsCanonical(message, blockNum, groupId, roster)) {
      return { ok: false, reason: 'messages contains a non-canonical message' };
    }
    const width = countHalfWidthChars(message.text);
    if (width > MAX_MESSAGE_CHARS) return { ok: false, reason: `message text exceeds ${MAX_MESSAGE_CHARS}` };
    const count = (counts.get(message.uid) || 0) + 1;
    const total = (chars.get(message.uid) || 0) + width;
    if (count > MAX_MESSAGES_PER_PLAYER) return { ok: false, reason: `messages for ${message.uid} exceeds ${MAX_MESSAGES_PER_PLAYER}` };
    if (total > MAX_MESSAGE_CHARS_PER_PLAYER) return { ok: false, reason: `message text for ${message.uid} exceeds ${MAX_MESSAGE_CHARS_PER_PLAYER}` };
    counts.set(message.uid, count);
    chars.set(message.uid, total);
    const key = computeMsgKeyV2(blockNum, groupId, message);
    if (seen.has(key)) return { ok: false, reason: 'messages contains duplicate msgKey' };
    seen.add(key);
    const row = [message.timestamp, message.uid, key];
    if (previous && (row[0] < previous[0]
      || (row[0] === previous[0] && (compareStrAsc(row[1], previous[1]) < 0
        || (row[1] === previous[1] && compareHexAsc(row[2], previous[2]) < 0))))) {
      return { ok: false, reason: 'messages are not in canonical order' };
    }
    previous = row;
  }
  return { ok: true, counts, chars, msgKeys: seen };
}

function validateAction(action) {
  return hasExactOwnKeys(action, ['encrypted', 'signature', 'timestamp'])
    && isCanonicalActionCiphertext(action.encrypted)
    && isCanonicalSignature(action.signature)
    && isCanonicalTimestamp(action.timestamp);
}

function compareSectionKeys(a, b) {
  const ai = canonArrayIndex(a);
  const bi = canonArrayIndex(b);
  if (ai !== null && bi !== null) return ai - bi;
  if (ai !== null) return -1;
  if (bi !== null) return 1;
  return compareStrAsc(a, b);
}

function sortedSectionKeysAreCanonical(section) {
  if (!isPlainRecord(section)) return false;
  const keys = Object.keys(section);
  const sorted = [...keys].sort(compareSectionKeys);
  return keys.every((key, index) => key === sorted[index]);
}

function actionListIsCanonical(list, type, uid, blockNum, groupId) {
  let previous = null;
  const seen = new Set();
  for (const action of list) {
    if (!validateAction(action)) return false;
    const hash = actionHashV2ForLimit(type, blockNum, groupId, uid, action);
    if (seen.has(hash)) return false;
    seen.add(hash);
    if (previous && actionCanonCmp(type, blockNum, groupId, uid, previous, action) > 0) return false;
    previous = action;
  }
  return true;
}

// Official-client normalization for raw P2P candidates.  The two top-level
// sections contain only the submitter's public slots (one vote, two reports).
// Extra attempts are retained in `observed`, so K-S2-006 can still detect a
// third distinct report target; they are not silently promoted into a slot.
// Every per-(actor,type) pool is sorted, hash-deduplicated and capped before
// the wallet signs the snapshot.
export function normalizeActionSnapshotForSubmission(snapshot, {
  blockNum, groupId, memberUids = [], submitterUid, reportTargetOf = null,
} = {}) {
  const roster = [...memberUids].sort(compareStrAsc);
  const rosterSet = new Set(roster);
  const pools = new Map();
  const preferredVote = snapshot?.votes?.[submitterUid];

  const add = (type, rawUid, raw) => {
    const uid = typeof rawUid === 'string' && rawUid.endsWith('__extras')
      ? rawUid.slice(0, -'__extras'.length) : rawUid;
    if (!rosterSet.has(uid)) return;
    const key = `${type}\u001f${uid}`;
    let list = pools.get(key);
    if (!list) { list = []; pools.set(key, list); }
    for (const action of (Array.isArray(raw) ? raw : [raw])) {
      if (validateAction(action)) list.push({
        encrypted: action.encrypted,
        signature: action.signature,
        timestamp: action.timestamp,
      });
    }
  };
  for (const [section, type] of [
    [snapshot?.votes, 'vote'], [snapshot?.reports, 'report'],
    [snapshot?.observed?.votes, 'vote'], [snapshot?.observed?.reports, 'report'],
  ]) {
    for (const uid of Object.keys(isPlainRecord(section) ? section : {}).sort(compareStrAsc)) {
      add(type, uid, section[uid]);
    }
  }

  const canonical = new Map();
  for (const [key, raw] of pools) {
    const split = key.indexOf('\u001f');
    const type = key.slice(0, split); const uid = key.slice(split + 1);
    raw.sort((a, b) => actionCanonCmp(type, blockNum, groupId, uid, a, b));
    const seen = new Set(); const list = [];
    for (const action of raw) {
      const hash = actionHashV2ForLimit(type, blockNum, groupId, uid, action);
      if (seen.has(hash)) continue;
      seen.add(hash); list.push(action);
      if (list.length === MAX_ACTION_CANDIDATES_PER_TYPE_PER_ACTOR) break;
    }
    canonical.set(key, list);
  }

  const out = {
    votes: Object.create(null),
    reports: Object.create(null),
    observed: { votes: Object.create(null), reports: Object.create(null), receipts: [] },
  };
  const ownVotes = canonical.get(`vote\u001f${submitterUid}`) || [];
  if (ownVotes.length > 0) {
    let chosen = ownVotes[0];
    if (validateAction(preferredVote)) {
      const preferredHash = actionHashV2ForLimit('vote', blockNum, groupId, submitterUid, preferredVote);
      chosen = ownVotes.find((action) => actionHashV2ForLimit('vote', blockNum, groupId, submitterUid, action) === preferredHash) || chosen;
    }
    out.votes[submitterUid] = chosen;
    const rest = ownVotes.filter((action) => action !== chosen);
    if (rest.length) out.observed.votes[submitterUid] = rest;
  }
  const ownReports = canonical.get(`report\u001f${submitterUid}`) || [];
  if (ownReports.length) {
    let slot = ownReports.slice(0, MAX_ACCEPTED_REPORTS_PER_PLAYER);
    let rest = ownReports.slice(MAX_ACCEPTED_REPORTS_PER_PLAYER);
    if (typeof reportTargetOf === 'function') {
      const seen = new Set(); const chosen = []; const others = [];
      for (const action of ownReports) {
        const target = reportTargetOf(action);
        if (target != null && !seen.has(target) && chosen.length < MAX_ACCEPTED_REPORTS_PER_PLAYER) {
          seen.add(target); chosen.push(action);
        } else others.push(action);
      }
      if (chosen.length > 0) { slot = chosen; rest = others; }
    }
    out.reports[submitterUid] = slot;
    if (rest.length) out.observed.reports[submitterUid] = rest;
  }
  for (const uid of roster) {
    if (uid === submitterUid) continue;
    const votes = canonical.get(`vote\u001f${uid}`) || [];
    const reports = canonical.get(`report\u001f${uid}`) || [];
    if (votes.length) out.observed.votes[uid] = votes;
    if (reports.length) out.observed.reports[uid] = reports;
  }
  out.observed.receipts = Array.isArray(snapshot?.observed?.receipts)
    ? snapshot.observed.receipts : [];
  if (snapshot?.observed?.selfReceiptAggregate != null) {
    out.observed.selfReceiptAggregate = snapshot.observed.selfReceiptAggregate;
  }
  const sortSection = (section) => {
    const sorted = Object.create(null);
    for (const uid of Object.keys(section).sort(compareSectionKeys)) sorted[uid] = section[uid];
    return sorted;
  };
  out.votes = sortSection(out.votes);
  out.reports = sortSection(out.reports);
  out.observed.votes = sortSection(out.observed.votes);
  out.observed.reports = sortSection(out.observed.reports);
  return out;
}

function receiptSources(snapshot, submitterUid) {
  return Array.isArray(snapshot?.observed?.receipts) ? [snapshot.observed.receipts] : [];
}

function validateLegacyReceipt(receipt, roster) {
  if (!isPlainRecord(receipt) || !roster.has(receipt.receiverUid)
    || !isCanonicalTimestamp(receipt.timestamp) || !isCanonicalSignature(receipt.signature)) {
    return 'receipt has non-canonical common fields';
  }
  if (Array.isArray(receipt.msgRefs) && receipt.senderUid != null) {
    if (!hasExactOwnKeys(receipt,
      ['receiverUid', 'senderUid', 'msgRefs', 'timestamp', 'signature'])) {
      return 'read receipt fields are not canonical';
    }
    if (!roster.has(receipt.senderUid) || receipt.receiverUid === receipt.senderUid
      || receipt.msgRefs.length < 1 || receipt.msgRefs.length > MAX_REFS_PER_RECEIPT
      || !receipt.msgRefs.every(isMsgRef)) return 'read receipt is invalid';
    if (new Set(receipt.msgRefs).size !== receipt.msgRefs.length
      || receipt.msgRefs.some((ref, index) => index > 0 && compareHexAsc(receipt.msgRefs[index - 1], ref) >= 0)) {
      return 'read receipt refs are not canonical';
    }
    return null;
  }
  if (!hasExactOwnKeys(receipt, ['receiverUid', 'actionHash', 'timestamp', 'signature'])) {
    return 'action receipt fields are not canonical';
  }
  if (!isActionHash(receipt.actionHash)) return 'action receipt is invalid';
  return null;
}

function validateSelfAggregate(aggregate, submitterUid, roster) {
  if (aggregate == null) return { ok: true, facts: 0 };
  if (!isPlainRecord(aggregate) || aggregate.version !== 1
    || aggregate.receiverUid !== submitterUid || !roster.has(aggregate.receiverUid)
    || !isCanonicalSignature(aggregate.signature) || !Array.isArray(aggregate.entries)
    || aggregate.entries.length < 1 || aggregate.entries.length > MAX_SELF_AGGREGATE_TARGETS) {
    return { ok: false, reason: 'self receipt aggregate has an invalid shape' };
  }
  if (!hasExactOwnKeys(aggregate, ['version', 'receiverUid', 'entries', 'signature'])) {
    return { ok: false, reason: 'self receipt aggregate fields are not canonical' };
  }
  const seen = new Set();
  let previous = null;
  for (const entry of aggregate.entries) {
    if (!isPlainRecord(entry) || !isCanonicalTimestamp(entry.timestamp)) {
      return { ok: false, reason: 'self receipt aggregate entry is invalid' };
    }
    let key;
    if (entry.targetType === 'read') {
      if (!hasExactOwnKeys(entry, ['targetType', 'senderUid', 'msgRef', 'timestamp'])) {
        return { ok: false, reason: 'self receipt aggregate read fields are not canonical' };
      }
      if (!roster.has(entry.senderUid) || entry.senderUid === submitterUid || !isMsgRef(entry.msgRef)) {
        return { ok: false, reason: 'self receipt aggregate read target is invalid' };
      }
      key = `r|${entry.senderUid}|${entry.msgRef}`;
    } else if (entry.targetType === 'action') {
      if (!hasExactOwnKeys(entry, ['targetType', 'actionHash', 'timestamp'])) {
        return { ok: false, reason: 'self receipt aggregate action fields are not canonical' };
      }
      if (!isActionHash(entry.actionHash)) return { ok: false, reason: 'self receipt aggregate action target is invalid' };
      key = `a|${entry.actionHash}`;
    } else return { ok: false, reason: 'self receipt aggregate target type is invalid' };
    if (seen.has(key)) return { ok: false, reason: 'self receipt aggregate contains a duplicate target' };
    seen.add(key);
    const row = [entry.timestamp, entry.targetType,
      entry.targetType === 'read' ? entry.senderUid : entry.actionHash,
      entry.targetType === 'read' ? entry.msgRef : null];
    if (previous && (row[0] < previous[0]
      || (row[0] === previous[0] && (compareStrAsc(row[1], previous[1]) < 0
        || (row[1] === previous[1] && (compareStrAsc(row[2], previous[2]) < 0
          || (row[2] === previous[2] && row[3] !== null
            && compareHexAsc(row[3], previous[3]) < 0))))))) {
      return { ok: false, reason: 'self receipt aggregate entries are not canonical' };
    }
    previous = row;
  }
  return { ok: true, facts: aggregate.entries.length };
}

// This is a structural/raw-input cap.  Selection of the one accepted vote and
// two report target slots remains in the scoring engine (J-19 / K-S2-006).
// priority の中身を確かめる入口は validateSubmissionStructure の後続検査だけ。
export function validateActionSnapshot(snapshot, memberUids = [], submitterUid = null, context = {}) {
  if (!isPlainRecord(snapshot) || !isPlainRecord(snapshot.votes)
    || !isPlainRecord(snapshot.reports) || !isPlainRecord(snapshot.observed)
    || !isPlainRecord(snapshot.observed.votes) || !isPlainRecord(snapshot.observed.reports)
    || !Array.isArray(snapshot.observed.receipts)) {
    return { ok: false, reason: 'encryptedActions has an invalid shape' };
  }
  const observedKeys = snapshot.observed.selfReceiptAggregate == null
    ? ['votes', 'reports', 'receipts']
    : ['votes', 'reports', 'receipts', 'selfReceiptAggregate'];
  const snapshotKeys = hasOwn.call(snapshot, 'priority')
    ? ['votes', 'reports', 'observed', 'priority'] : ['votes', 'reports', 'observed'];
  if (!hasExactOwnKeys(snapshot, snapshotKeys)
    || !hasExactOwnKeys(snapshot.observed, observedKeys)) {
    return { ok: false, reason: 'encryptedActions fields are not canonical' };
  }
  const roster = new Set(memberUids);
  if (![snapshot.votes, snapshot.reports, snapshot.observed.votes, snapshot.observed.reports]
    .every(sortedSectionKeysAreCanonical)) {
    return { ok: false, reason: 'encryptedActions uid keys are not in canonical order' };
  }
  if (Object.keys(snapshot.votes).some((uid) => uid !== submitterUid)
    || Object.keys(snapshot.reports).some((uid) => uid !== submitterUid)) {
    return { ok: false, reason: 'top-level action slots may contain only the submitter' };
  }
  if (hasOwn.call(snapshot.votes, submitterUid)
    && (!isPlainRecord(snapshot.votes[submitterUid]) || !validateAction(snapshot.votes[submitterUid]))) {
    return { ok: false, reason: 'a submitter vote slot may contain at most one action' };
  }
  if (hasOwn.call(snapshot.reports, submitterUid)
    && (!Array.isArray(snapshot.reports[submitterUid])
      || snapshot.reports[submitterUid].length < 1
      || snapshot.reports[submitterUid].length > MAX_ACCEPTED_REPORTS_PER_PLAYER)) {
    return { ok: false, reason: `submitter report slots exceed ${MAX_ACCEPTED_REPORTS_PER_PLAYER}` };
  }
  const seenActions = new Map();
  const scan = (section, type, observed) => {
    for (const uid of Object.keys(section)) {
      if (!roster.has(uid)) return `encryptedActions ${type} contains a non-roster uid`;
      if (observed && !Array.isArray(section[uid])) {
        return `encryptedActions ${type}/${uid} must be an array`;
      }
      const list = Array.isArray(section[uid]) ? section[uid] : [section[uid]];
      if (list.length < 1) return `encryptedActions ${type}/${uid} has an empty action slot`;
      if (!actionListIsCanonical(list, type.endsWith('votes') ? 'vote' : 'report', uid,
        context.blockNum, context.groupId)) {
        return `encryptedActions ${type}/${uid} contains unordered, duplicate, or non-canonical actions`;
      }
      const poolKey = `${type.endsWith('votes') ? 'vote' : 'report'}\u001f${uid}`;
      let hashes = seenActions.get(poolKey);
      if (!hashes) { hashes = new Set(); seenActions.set(poolKey, hashes); }
      for (const action of list) {
        const hash = actionHashV2ForLimit(type.endsWith('votes') ? 'vote' : 'report',
          context.blockNum, context.groupId, uid, action);
        if (hashes.has(hash)) return `encryptedActions ${type}/${uid} repeats an action across sections`;
        hashes.add(hash);
      }
      if (hashes.size > MAX_ACTION_CANDIDATES_PER_TYPE_PER_ACTOR) {
        return `encryptedActions ${type}/${uid} exceeds ${MAX_ACTION_CANDIDATES_PER_TYPE_PER_ACTOR}`;
      }
    }
    return null;
  };
  for (const [section, type, observed] of [
    [snapshot.votes, 'votes', false], [snapshot.reports, 'reports', false],
    [snapshot.observed.votes, 'observed.votes', true], [snapshot.observed.reports, 'observed.reports', true],
  ]) {
    const reason = scan(section, type, observed);
    if (reason) return { ok: false, reason };
  }
  if (snapshot.observed.receipts.length > MAX_RECEIPT_OBJECTS) {
    return { ok: false, reason: `receipts exceeds ${MAX_RECEIPT_OBJECTS}` };
  }
  const sources = receiptSources(snapshot, submitterUid);
  let rawObjects = 0;
  let rawFacts = 0;
  for (const source of sources) {
    rawObjects += source.length;
    if (rawObjects > MAX_RECEIPT_OBJECTS) {
      return { ok: false, reason: `receipt objects exceeds ${MAX_RECEIPT_OBJECTS}` };
    }
    for (const receipt of source) {
      const reason = validateLegacyReceipt(receipt, roster);
      if (reason) return { ok: false, reason };
      rawFacts += Array.isArray(receipt.msgRefs) ? receipt.msgRefs.length : 1;
      if (rawFacts > MAX_RECEIPT_FACTS) {
        return { ok: false, reason: `receipt facts exceed ${MAX_RECEIPT_FACTS}` };
      }
    }
  }
  const aggregate = validateSelfAggregate(snapshot.observed.selfReceiptAggregate, submitterUid, roster);
  if (!aggregate.ok) return aggregate;
  if (rawFacts + aggregate.facts > MAX_RECEIPT_FACTS) {
    return { ok: false, reason: `receipt facts exceed ${MAX_RECEIPT_FACTS}` };
  }
  return { ok: true, rawObjects, rawFacts, aggregateFacts: aggregate.facts };
}

// E′ は observed / A の finite caps とは別の予算で数える。
// 呼び手は先に validateMessages で名簿の正準形を確かめる。
export function validatePriorityStructure(bundle, { blockNum, groupId, memberUids } = {}) {
  const ea = bundle?.encryptedActions;
  if (!isPlainRecord(ea) || !hasOwn.call(ea, 'priority')) return { ok: true };
  const priority = ea.priority;
  const keys = isPlainRecord(priority) ? JSON.stringify(Object.keys(priority)) : null;
  if ((keys !== '["messages","receipts"]'
      && keys !== '["messages","receipts","selfReceiptAggregate"]')
    || (hasOwn.call(priority, 'selfReceiptAggregate') && !isPlainRecord(priority.selfReceiptAggregate))
    || !Array.isArray(priority.messages) || priority.messages.length < 1
    || priority.messages.length > PRIORITY_MESSAGES_MAX
    || !Array.isArray(priority.receipts) || priority.receipts.length > PRIORITY_RECEIPTS_MAX) {
    return { ok: false, reason: 'priority has an invalid shape' };
  }
  const roster = new Set(Array.isArray(memberUids) ? memberUids : []);
  const own = bundle.uid;
  const eKeys = new Set();
  const eByKey = new Map();
  const counts = new Map();
  const chars = new Map();
  let ownCount = 0;
  let otherCount = 0;
  let previous = null;
  for (const message of priority.messages) {
    if (!messageShapeIsCanonical(message, blockNum, groupId, roster)
      || countHalfWidthChars(message.text) > MAX_MESSAGE_CHARS || !hasVisibleContent(message.text)) {
      return { ok: false, reason: 'priority messages contains an invalid message' };
    }
    if (message.uid === own) ownCount++; else otherCount++;
    const key = computeMsgKeyV2(blockNum, groupId, message);
    if (eKeys.has(key)) return { ok: false, reason: 'priority messages contains duplicate msgKey' };
    eKeys.add(key);
    eByKey.set(key, message);
    const row = [message.timestamp, message.uid, key];
    if (previous && (row[0] < previous[0]
      || (row[0] === previous[0] && (compareStrAsc(row[1], previous[1]) < 0
        || (row[1] === previous[1] && compareHexAsc(row[2], previous[2]) < 0))))) {
      return { ok: false, reason: 'priority messages are not in canonical order' };
    }
    previous = row;
    counts.set(message.uid, (counts.get(message.uid) || 0) + 1);
    chars.set(message.uid, (chars.get(message.uid) || 0) + countHalfWidthChars(message.text));
  }
  if (ownCount > PRIORITY_OWN_MESSAGES_MAX || otherCount > PRIORITY_OTHER_MESSAGES_MAX) {
    return { ok: false, reason: 'priority messages exceeds owner or other limit' };
  }
  if (bundle.messages.length + priority.messages.length > MAX_MESSAGES_TOTAL) {
    return { ok: false, reason: `messages exceeds ${MAX_MESSAGES_TOTAL}` };
  }
  for (const message of bundle.messages) {
    counts.set(message.uid, (counts.get(message.uid) || 0) + 1);
    chars.set(message.uid, (chars.get(message.uid) || 0) + countHalfWidthChars(message.text));
  }
  for (const [uid, count] of counts) {
    if (count > MAX_MESSAGES_PER_PLAYER) return { ok: false, reason: `messages for ${uid} exceeds ${MAX_MESSAGES_PER_PLAYER}` };
    if (chars.get(uid) > MAX_MESSAGE_CHARS_PER_PLAYER) {
      return { ok: false, reason: `message text for ${uid} exceeds ${MAX_MESSAGE_CHARS_PER_PLAYER}` };
    }
  }
  const hasAggregate = hasOwn.call(priority, 'selfReceiptAggregate');
  if (priority.receipts.length + Number(hasAggregate) > PRIORITY_RECEIPTS_MAX) {
    return { ok: false, reason: `priority receipts exceeds ${PRIORITY_RECEIPTS_MAX}` };
  }
  if (hasAggregate && priority.selfReceiptAggregate.entries?.length > priority.messages.length) {
    return { ok: false, reason: 'priority aggregate entries exceeds messages' };
  }
  for (const receipt of priority.receipts) {
    if (!Array.isArray(receipt?.msgRefs) || typeof receipt.senderUid !== 'string') {
      return { ok: false, reason: 'priority receipt is not a read receipt' };
    }
    const reason = validateLegacyReceipt(receipt, roster);
    if (reason) return { ok: false, reason: `priority ${reason}` };
    if (receipt.receiverUid === own) {
      return { ok: false, reason: 'priority self read receipts must be aggregated' };
    }
  }
  if (hasAggregate) {
    const aggregate = validateSelfAggregate(priority.selfReceiptAggregate, own, roster);
    if (!aggregate.ok) return { ok: false, reason: `priority ${aggregate.reason}` };
    if (priority.selfReceiptAggregate.entries.some((entry) => entry.targetType !== 'read')) {
      return { ok: false, reason: 'priority aggregate contains a non-read target' };
    }
  }
  // 同じ msgKey が E と通常欄の両方にある形は許す。異なる msgKey が
  // 同じ (uid, msgRef) に解ける形だけを曖昧として拒む。
  const targets = new Map();
  for (const message of [...bundle.messages, ...priority.messages]) {
    const key = computeMsgKeyV2(blockNum, groupId, message);
    const refKey = JSON.stringify([message.uid, msgRefOf(key)]);
    const prior = targets.get(refKey);
    if (prior === undefined) targets.set(refKey, key);
    else if (prior !== key) targets.set(refKey, null);
  }
  const covered = new Set();
  for (const receipt of priority.receipts) {
    let timelyE = false;
    for (const ref of receipt.msgRefs) {
      const key = targets.get(JSON.stringify([receipt.senderUid, ref]));
      if (!key) return { ok: false, reason: 'priority receipt reference is missing or ambiguous' };
      if (!eKeys.has(key)) continue;
      const message = eByKey.get(key);
      if (isReceiptTimely(receipt.timestamp, message.timestamp)) {
        timelyE = true;
        covered.add(key);
      }
    }
    if (!timelyE) return { ok: false, reason: 'priority receipt does not timely cover E' };
  }
  for (const entry of priority.selfReceiptAggregate?.entries || []) {
    const key = targets.get(JSON.stringify([entry.senderUid, entry.msgRef]));
    if (!key) return { ok: false, reason: 'priority aggregate reference is missing or ambiguous' };
    const message = eByKey.get(key);
    if (!message || !isReceiptTimely(entry.timestamp, message.timestamp)) {
      return { ok: false, reason: 'priority aggregate entry does not timely cover E' };
    }
    covered.add(key);
  }
  if (covered.size !== eKeys.size) return { ok: false, reason: 'priority messages are not covered' };
  return { ok: true };
}

export function validateSubmissionStructure(bundle, context = {}) {
  try {
    assertBoundedShape(bundle);
  } catch (error) {
    return { ok: false, reason: error.message };
  }
  if (!hasExactOwnKeys(bundle, [
      'uid', 'encryptKey', 'chatHash', 'signature', 'submittedAt', 'encryptedDataHash',
      'depositIds', 'encryptedActions', 'messages',
    ]) || !isCanonicalUid(bundle.uid) || uidEscapedLength(bundle.uid) > MAX_UID_BYTES) {
    return { ok: false, reason: 'submission uid is invalid' };
  }
  if (!Number.isSafeInteger(context.blockNum) || context.blockNum < 0
    || !Number.isSafeInteger(context.groupId) || context.groupId < 0
    || !isBytes32Hex(bundle.encryptKey) || !isCanonicalChatHash(bundle.chatHash)
    || !isRepresentableSignature(bundle.signature)
    || !isCanonicalTimestamp(bundle.submittedAt)
    || !isBytes32Hex(bundle.encryptedDataHash)) {
    return { ok: false, reason: 'submission envelope fields are non-canonical' };
  }
  if (Array.isArray(context.memberUids) && !context.memberUids.includes(bundle.uid)) {
    return { ok: false, reason: 'submission uid is outside the roster' };
  }
  const deposits = validateDepositIds(bundle.depositIds);
  if (!deposits.ok) return deposits;
  const messages = validateMessages(bundle.messages, context);
  if (!messages.ok) return messages;
  const actions = validateActionSnapshot(bundle.encryptedActions, context.memberUids || [], bundle.uid, context);
  if (!actions.ok) return actions;
  const priority = validatePriorityStructure(bundle, context);
  if (!priority.ok) return priority;
  return { ok: true, messages };
}

export function countRawReceipts(snapshot) {
  if (!snapshot || typeof snapshot !== 'object') return 0;
  return Array.isArray(snapshot.observed?.receipts) ? snapshot.observed.receipts.length : 0;
}

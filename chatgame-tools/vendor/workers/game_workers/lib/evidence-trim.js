// Evidence compact payload の容量計測・発信者別帰属・決定論的トリム。
// Web 本体と復元クライアントはこのファイルの byte-exact vendor copy を共有する。

import { keccak256, toHex } from 'viem';
import {
  compactBytesToPayload,
  compactPayloadToBytes,
  decodeSubmissionPayloadString,
  encodeEvidenceCompactV1,
  isEvidenceCompactPayload,
} from './evidence-compact-v1.js';
import { actionHashV2, buildRealTargets, buildMsgKeyGetter, msgRefOf, receiptCoverClaim } from './protocol-v2.js';
import { GUEST_PINNED_RULES } from './char-counter.js';
import { receiptCanonCmp } from './game-result-calculator.js';
import { MAX_REFS_PER_RECEIPT, isPlainRecord } from './submission-limits.js';
import { prunePriorityToCoverage, priorityTurnGuarantee } from './priority-fields.js';
import { classifyEvidenceReceipts } from '../../../src/utils/evidence-trim-policy.js';

export const EVIDENCE_MAX_DATA_BYTES = 130000;
export const EVIDENCE_TRIM_ORDER = Object.freeze(['H', 'G', 'F', 'E', 'C', 'D', 'R', 'A', 'B', 'V']);

export function trimmedSubmissionSignatureMessage(
  bundle, blockNum, encryptedDataHash = bundle.encryptedDataHash,
) {
  return JSON.stringify({
    blockNum: Number(blockNum), uid: bundle.uid, encryptKey: bundle.encryptKey,
    chatHash: bundle.chatHash, submittedAt: bundle.submittedAt,
    encryptedDataHash, depositIds: bundle.depositIds,
  });
}

export function encodeSignedTrimmedPayload(bundle, signature, compactContext) {
  const logical = {
    uid: bundle.uid,
    encryptKey: bundle.encryptKey,
    chatHash: bundle.chatHash,
    signature,
    submittedAt: bundle.submittedAt,
    encryptedDataHash: bundle.encryptedDataHash,
    depositIds: bundle.depositIds,
    encryptedActions: bundle.encryptedActions,
    messages: bundle.messages,
  };
  const sanitized = {};
  const bytes = encodeEvidenceCompactV1(logical, compactContext, { sanitized });
  if (sanitized.bundle) throw new Error('trimmed payload lost receipts during compact encoding');
  if (bytes.length >= EVIDENCE_MAX_DATA_BYTES) {
    throw new Error(`Evidence payload must be < ${EVIDENCE_MAX_DATA_BYTES} bytes`);
  }
  return compactBytesToPayload(bytes);
}

export function measureRawBytes(payload) {
  if (!isEvidenceCompactPayload(payload)) return Number.POSITIVE_INFINITY;
  try { return new TextEncoder().encode(decodeSubmissionPayloadString(payload).raw).length; }
  catch { return Number.POSITIVE_INFINITY; }
}

export async function measureOnChainBytes(payload) {
  if (!isEvidenceCompactPayload(payload)) return Number.POSITIVE_INFINITY;
  return compactPayloadToBytes(payload).length;
}

function jsonSize(value) {
  try { return new TextEncoder().encode(JSON.stringify(value)).length; }
  catch { return 0; }
}

// 残余バイトを発信主体へ帰属する。self aggregate の entry は receiver ではなく、
// read は senderUid、action は actionHash から逆引きした actor へ帰属する。
export function attributeResidualBytes(bundle, { blockNum, groupId } = {}) {
  const byUid = new Map();
  const add = (uid, bytes) => {
    const key = String(uid ?? '');
    if (key) byUid.set(key, (byUid.get(key) || 0) + bytes);
  };
  const messages = Array.isArray(bundle?.messages) ? bundle.messages : [];
  for (const message of messages) add(message?.uid, jsonSize(message));

  const snapshot = bundle?.encryptedActions || {};
  const observed = snapshot.observed || {};
  for (const receipt of Array.isArray(observed.receipts) ? observed.receipts : []) {
    add(receipt?.receiverUid, jsonSize(receipt));
  }

  const actorByActionHash = new Map();
  for (const [type, section] of [
    ['vote', snapshot.votes], ['report', snapshot.reports],
    ['vote', observed.votes], ['report', observed.reports],
  ]) {
    if (!section || typeof section !== 'object') continue;
    for (const [uid, raw] of Object.entries(section)) {
      for (const action of Array.isArray(raw) ? raw : [raw]) {
        if (!action) continue;
        add(uid, jsonSize(action));
        if (Number.isSafeInteger(blockNum) && Number.isSafeInteger(groupId)
          && typeof action.encrypted === 'string' && Number.isSafeInteger(action.timestamp)) {
          actorByActionHash.set(
            actionHashV2(type, blockNum, groupId, uid, action.encrypted, action.timestamp),
            uid,
          );
        }
      }
    }
  }

  const aggregate = observed.selfReceiptAggregate;
  if (aggregate && typeof aggregate === 'object') {
    add(aggregate.receiverUid, jsonSize({
      version: aggregate.version,
      receiverUid: aggregate.receiverUid,
      signature: aggregate.signature,
    }));
    for (const entry of Array.isArray(aggregate.entries) ? aggregate.entries : []) {
      const issuer = entry?.targetType === 'read'
        ? entry.senderUid
        : actorByActionHash.get(entry?.actionHash) || aggregate.receiverUid;
      add(issuer, jsonSize(entry));
    }
  }

  // 外側フィールドとコンテナの概算分は提出者へ帰属する。
  add(bundle?.uid, jsonSize({
    uid: bundle?.uid,
    encryptKey: bundle?.encryptKey,
    chatHash: bundle?.chatHash,
    signature: bundle?.signature,
    submittedAt: bundle?.submittedAt,
    encryptedDataHash: bundle?.encryptedDataHash,
    depositIds: bundle?.depositIds,
  }));
  return byUid;
}

// 署名済み legacy receipt atom と self aggregate は不可分。
// H→G→F→E→C→D→R→A→B→V の順に削り、各 legacy class 内では正準末尾から削る。
// @param opts  `{ chatWindow }` — Evidence 契約の宣言窓（`chatWindowMsFromTimeline` の戻り値）。
//   🔴 2026-08-20（判断1(c)）: 窓を保持方針へ渡す。**null（読めない）なら従来どおり fail-open**。
//   ⚠️ 第5ラウンドの写経解消で第3引数ごと消えていたが、呼出側3箇所は渡し続けていた（R6-08）。
export async function planOnChainTrim(payload, myUid, { chatWindow = null } = {}) {
  if (!isEvidenceCompactPayload(payload)) {
    throw new Error('production Evidence submission must use evidence-compact-v1');
  }
  const beforeBytes = await measureOnChainBytes(payload);
  const beforeRawBytes = measureRawBytes(payload);
  if (beforeBytes < EVIDENCE_MAX_DATA_BYTES) return null;

  const decoded = decodeSubmissionPayloadString(payload);
  const bundle = decoded.bundle;
  const snapshot = bundle.encryptedActions;
  const policy = classifyEvidenceReceipts({
    bundle,
    blockNum: decoded.blockNum,
    groupId: decoded.groupId,
    myUid,
    chatWindow,
  });
  const { receipts, priorities } = policy;
  const priority0 = isPlainRecord(snapshot.priority) ? snapshot.priority : null;
  const guaranteeContext = {
    ownerUid: myUid, blockNum: decoded.blockNum, groupId: decoded.groupId,
    minMessages: GUEST_PINNED_RULES.minMessages,
  };
  const gBefore = priority0 ? priorityTurnGuarantee(priority0, guaranteeContext) : 0;
  const ePrimeOrder = priority0
    ? priority0.receipts.map((receipt, index) => ({ receipt, index }))
      .sort((a, b) => receiptCanonCmp(a.receipt, b.receipt) || a.index - b.index)
      .reverse().map(({ receipt }) => receipt)
    : [];
  const hasPriorityAggregate = Boolean(priority0 && isPlainRecord(priority0.selfReceiptAggregate));
  const ePrimeUnits = ePrimeOrder.length + (hasPriorityAggregate ? 1 : 0);
  let ePrimeDropped = [];
  let ePrimeAggregateDropped = false;
  let freeKept = [];
  let freeAggregateKept = false;
  let droppedEPrimeFree = 0;
  const removed = new Set();
  let aggregateRemoved = false;
  let encoded = compactPayloadToBytes(payload);
  let trimmedBundle = bundle;

  const encodeCurrent = () => {
    const nextObserved = {
      ...snapshot.observed,
      receipts: receipts.filter((receipt) => !removed.has(receipt)),
    };
    if (aggregateRemoved) delete nextObserved.selfReceiptAggregate;
    let nextSnapshot = { ...snapshot, observed: nextObserved };
    if (priority0 && (ePrimeDropped.length || ePrimeAggregateDropped)) {
      nextSnapshot = prunePriorityToCoverage(nextSnapshot, bundle.messages, {
        dropReceipts: ePrimeDropped,
        dropSelfAggregate: ePrimeAggregateDropped,
      }, { blockNum: decoded.blockNum, groupId: decoded.groupId });
    }
    trimmedBundle = {
      ...bundle,
      encryptedActions: nextSnapshot,
      encryptedDataHash: keccak256(toHex(JSON.stringify(nextSnapshot))),
    };
    encoded = encodeEvidenceCompactV1(trimmedBundle, {
      blockNum: decoded.blockNum,
      groupId: decoded.groupId,
      memberUids: decoded.memberUids,
    });
  };

  const trimPriority = (priority) => {
    if (encoded.length < EVIDENCE_MAX_DATA_BYTES) return;
    const candidates = receipts
      .filter((receipt) => priorities.get(receipt) === priority)
      .reverse();
    if (candidates.length === 0) return;
    const base = new Set(removed);
    const tryCount = (count) => {
      removed.clear();
      for (const receipt of base) removed.add(receipt);
      for (let i = 0; i < count; i++) removed.add(candidates[i]);
      encodeCurrent();
    };
    tryCount(candidates.length);
    if (encoded.length >= EVIDENCE_MAX_DATA_BYTES) return;
    let lo = 1;
    let hi = candidates.length;
    while (lo < hi) {
      const mid = Math.floor((lo + hi) / 2);
      tryCount(mid);
      if (encoded.length < EVIDENCE_MAX_DATA_BYTES) hi = mid;
      else lo = mid + 1;
    }
    tryCount(lo);
  };

  const applyPriorityCount = (count) => {
    const rest = ePrimeOrder.filter((receipt) => !freeKept.includes(receipt));
    ePrimeDropped = [...freeKept, ...rest.slice(0, Math.min(count, rest.length))];
    ePrimeAggregateDropped = hasPriorityAggregate && (freeAggregateKept || count > rest.length);
    encodeCurrent();
  };

  // E と E′ の有効な覆いを保てる単位は、E の後・C の前に外したままにする。
  // 判定には分類と同じ receiptCoverClaim を使う。
  const priorityCoverage = (value) => {
    if (!value?.priority) return [];
    const keyOf = buildMsgKeyGetter(decoded.blockNum, decoded.groupId);
    const allMessages = [...(value.priority.messages || []), ...(bundle.messages || [])];
    const seen = new Set();
    const messages = allMessages.filter((message) => {
      const key = keyOf(message);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    const targets = buildRealTargets(value, messages, decoded.blockNum, decoded.groupId);
    const covered = new Set();
    const add = (receipt) => {
      const claim = receiptCoverClaim(receipt, targets, {
        maxRefsPerReceipt: MAX_REFS_PER_RECEIPT, chatWindow,
      });
      if (claim.windowed) for (const target of claim.targetKeys) covered.add(target);
    };
    for (const receipt of value.priority.receipts || []) add(receipt);
    const aggregate = value.priority.selfReceiptAggregate;
    for (const entry of aggregate?.entries || []) {
      add(entry?.targetType === 'read'
        ? { receiverUid: aggregate.receiverUid, senderUid: entry.senderUid,
          msgRefs: [entry.msgRef], timestamp: entry.timestamp, signature: aggregate.signature }
        : { receiverUid: aggregate.receiverUid, actionHash: entry?.actionHash,
          timestamp: entry?.timestamp, signature: aggregate.signature });
    }
    return [...covered].sort();
  };

  const trimFreePriority = () => {
    if (!priority0 || encoded.length < EVIDENCE_MAX_DATA_BYTES || ePrimeUnits === 0) return;
    const originalCoverage = JSON.stringify(priorityCoverage(snapshot));
    const originalMessages = JSON.stringify(priority0.messages);
    const free = [];
    for (const receipt of ePrimeOrder) {
      const trial = prunePriorityToCoverage(snapshot, bundle.messages, {
        dropReceipts: [...free, receipt],
      }, { blockNum: decoded.blockNum, groupId: decoded.groupId });
      if (JSON.stringify(trial.priority?.messages) === originalMessages
        && JSON.stringify(priorityCoverage(trial)) === originalCoverage) free.push(receipt);
    }
    if (hasPriorityAggregate) {
      const trial = prunePriorityToCoverage(snapshot, bundle.messages, {
        dropReceipts: free, dropSelfAggregate: true,
      }, { blockNum: decoded.blockNum, groupId: decoded.groupId });
      if (JSON.stringify(trial.priority?.messages) === originalMessages
        && JSON.stringify(priorityCoverage(trial)) === originalCoverage) free.push(priority0.selfReceiptAggregate);
    }
    if (!free.length) return;
    const apply = (count) => {
      ePrimeDropped = free.slice(0, count).filter((item) => item !== priority0.selfReceiptAggregate);
      ePrimeAggregateDropped = hasPriorityAggregate && free.slice(0, count).includes(priority0.selfReceiptAggregate);
      droppedEPrimeFree = count;
      encodeCurrent();
    };
    apply(free.length);
    if (encoded.length >= EVIDENCE_MAX_DATA_BYTES) {
      freeKept = [...ePrimeDropped];
      freeAggregateKept = ePrimeAggregateDropped;
      return;
    }
    let lo = 1;
    let hi = free.length;
    while (lo < hi) {
      const mid = Math.floor((lo + hi) / 2);
      apply(mid);
      if (encoded.length < EVIDENCE_MAX_DATA_BYTES) hi = mid;
      else lo = mid + 1;
    }
    apply(lo);
  };

  const trimPriorityField = () => {
    if (!priority0 || encoded.length < EVIDENCE_MAX_DATA_BYTES || ePrimeUnits === 0) return;
    const remaining = ePrimeOrder.length - freeKept.length
      + (hasPriorityAggregate && !freeAggregateKept ? 1 : 0);
    applyPriorityCount(remaining);
    if (encoded.length >= EVIDENCE_MAX_DATA_BYTES) return;
    let lo = 0;
    let hi = remaining;
    while (lo < hi) {
      const mid = Math.floor((lo + hi) / 2);
      applyPriorityCount(mid);
      if (encoded.length < EVIDENCE_MAX_DATA_BYTES) hi = mid;
      else lo = mid + 1;
    }
    applyPriorityCount(lo);
  };

  for (const priority of EVIDENCE_TRIM_ORDER) {
    if (priority === 'H') {
      if (encoded.length >= EVIDENCE_MAX_DATA_BYTES && policy.aggregatePriority === 'H') {
        aggregateRemoved = true;
        encodeCurrent();
      }
      trimPriority(priority);
    } else if (priority === 'A') {
      if (encoded.length >= EVIDENCE_MAX_DATA_BYTES && snapshot.observed?.selfReceiptAggregate) {
        aggregateRemoved = true;
        encodeCurrent();
      }
    } else {
      if (priority === 'C') trimFreePriority();
      trimPriority(priority);
      if (priority === 'B') trimPriorityField();
    }
  }

  // 不可分な自己集約を落とした後は、空いた容量を上位の既読から戻す。
  if (aggregateRemoved && encoded.length < EVIDENCE_MAX_DATA_BYTES) {
    for (const priority of ['R', 'D', 'C']) {
      for (const receipt of receipts) {
        if (!removed.has(receipt) || priorities.get(receipt) !== priority) continue;
        removed.delete(receipt);
        encodeCurrent();
        if (encoded.length >= EVIDENCE_MAX_DATA_BYTES
          || (priority0 && !trimmedBundle.encryptedActions.observed.receipts.includes(receipt))) {
          removed.add(receipt);
          encodeCurrent();
        }
      }
    }
  }

  if (priority0 && (ePrimeDropped.length || ePrimeAggregateDropped)) {
    const carriedReceipts = new Set(trimmedBundle.encryptedActions.observed.receipts);
    for (const receipt of receipts) if (!carriedReceipts.has(receipt)) removed.add(receipt);
    if (snapshot.observed?.selfReceiptAggregate
      && !trimmedBundle.encryptedActions.observed.selfReceiptAggregate) aggregateRemoved = true;
  }

  const finalPriority = trimmedBundle.encryptedActions.priority;
  const gAfter = finalPriority ? priorityTurnGuarantee(finalPriority, guaranteeContext) : 0;
  const droppedEPrime = priority0
    ? priority0.receipts.length - (finalPriority?.receipts?.length ?? 0)
      + (hasPriorityAggregate && !finalPriority?.selfReceiptAggregate ? 1 : 0)
    : 0;

  const dropped = (priority) => [...removed]
    .filter((receipt) => priorities.get(receipt) === priority).length;
  const residual = attributeResidualBytes(trimmedBundle, {
    blockNum: decoded.blockNum,
    groupId: decoded.groupId,
  });
  const common = {
    droppedTotal: removed.size + (aggregateRemoved ? 1 : 0) + droppedEPrime,
    droppedH: dropped('H') + (aggregateRemoved && policy.aggregatePriority === 'H' ? 1 : 0),
    droppedG: dropped('G'),
    droppedF: dropped('F'),
    droppedE: dropped('E'),
    droppedD: dropped('D'),
    droppedR: dropped('R'),
    droppedA: aggregateRemoved && policy.aggregatePriority === 'A' ? 1 : 0,
    droppedC: dropped('C'),
    droppedB: dropped('B') + droppedEPrime - droppedEPrimeFree,
    droppedV: dropped('V'),
    essentialEvidenceDropped: (aggregateRemoved && policy.aggregatePriority === 'A'
      && !(priority0 && gBefore >= GUEST_PINNED_RULES.minMessages))
      || dropped('R') > 0
      || dropped('C') > 0 || dropped('B') > 0 || dropped('V') > 0 || gAfter < gBefore,
    gBefore,
    gAfter,
    droppedEPrime,
    droppedEPrimeFree,
    protectedA: policy.protectedA,
    protectedB: policy.protectedB,
    protectedV: policy.protectedV,
    protectedC: policy.protectedC,
    protectedR: policy.protectedR,
    classCounts: policy.classCounts,
    thresholds: policy.thresholds,
    policyFallback: policy.policyFallback,
    beforeBytes,
    afterBytes: encoded.length,
    beforeRawBytes,
    afterRawBytes: new TextEncoder().encode(JSON.stringify(trimmedBundle)).length,
    residualByUid: residual,
  };
  if (encoded.length >= EVIDENCE_MAX_DATA_BYTES) {
    return {
      ...common,
      impossible: true,
      reason: 'all trimmable evidence exceeds contract wire limit',
      oversizeUids: [...residual.entries()]
        .sort((a, b) => (b[1] - a[1]) || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
        .map(([uid]) => uid),
    };
  }
  return {
    ...common,
    trimmedBundle,
    compactContext: {
      blockNum: decoded.blockNum,
      groupId: decoded.groupId,
      memberUids: decoded.memberUids,
    },
  };
}

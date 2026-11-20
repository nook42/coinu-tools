import { sha256, stringToBytes } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { calculateGroupResults } from '../../workers/game_workers/lib/game-result-calculator.js';
import { priorityTurnGuarantee } from '../../workers/game_workers/lib/priority-fields.js';
import { GUEST_PINNED_RULES, countVisibleChars, applyChatCaps } from '../../workers/game_workers/lib/char-counter.js';
import { decodeSubmissionPayloadString } from '../../workers/game_workers/lib/evidence-compact-v1.js';
import { computeMsgKeyV2 } from '../../workers/game_workers/lib/protocol-v2.js';
import { decryptAction } from './ecies.js';

export const GUARANTEE_REJECT_REASONS = Object.freeze([
  'invalid_signature', 'chathash_mismatch', 'snapshot_mismatch', 'vote_fraud', 'report_fraud',
]);

export function makeDryRunSigner() {
  const account = privateKeyToAccount(generatePrivateKey());
  return { address: account.address, signMessage: async (message) => account.signMessage({ message }) };
}

export function dryRunSubmittedAt(chatWindow) {
  return Number.isSafeInteger(chatWindow?.endMs) ? chatWindow.endMs : null;
}

// 押す前の見積もりでは束の各時刻との差を5バイトで符号化できる時刻を使う。
export const ONCHAIN_DRY_RUN_SUBMITTED_AT_OFFSET_MS = 2 ** 28;

export function onChainDryRunSubmittedAt(chatWindow) {
  return Number.isSafeInteger(chatWindow?.endMs)
    ? chatWindow.endMs + ONCHAIN_DRY_RUN_SUBMITTED_AT_OFFSET_MS : null;
}

// 自己集約を外した後の既読の戻しは束の大きさに対して単調ではない。
export function trimPlanDropsSelfAggregate(payload, plan) {
  if (!plan?.trimmedBundle) return false;
  const before = decodeSubmissionPayloadString(payload)?.bundle?.encryptedActions?.observed;
  return Boolean(before?.selfReceiptAggregate)
    && !plan.trimmedBundle.encryptedActions?.observed?.selfReceiptAggregate;
}

function actionEntries(value) {
  if (Array.isArray(value)) return value;
  return value && typeof value === 'object' ? [value] : [];
}

function signedTargetCount(entries, encryptKey) {
  const targets = new Set();
  const ciphertexts = new Set();
  for (const entry of entries) {
    const encrypted = entry?.encrypted;
    if (typeof encrypted !== 'string' || ciphertexts.has(encrypted)) continue;
    ciphertexts.add(encrypted);
    try {
      const targetUid = decryptAction(encrypted, encryptKey)?.targetUid;
      targets.add(targetUid == null ? `unreadable:${encrypted}` : `target:${targetUid}`);
    } catch {
      targets.add(`unreadable:${encrypted}`);
    }
  }
  return targets.size;
}

export async function summarizeOwnSubmission(payload, {
  blockNum, groupId, myUid, members, chatWindow, signerAddress = null,
  ownMessages = [], ownActions = { votes: [], reports: [] },
}) {
  if (!Number.isSafeInteger(chatWindow?.startMs)
      || !Number.isSafeInteger(chatWindow?.endMs)
      || chatWindow.startMs > chatWindow.endMs) {
    throw new Error('A confirmed chat window is required for submission guarantees');
  }
  const { bundle } = decodeSubmissionPayloadString(payload);
  if (bundle.uid !== myUid) throw new Error('Submission owner differs from the current identity');
  const priority = bundle.encryptedActions?.priority;
  const turns = priority ? priorityTurnGuarantee(priority, {
    ownerUid: myUid, blockNum, groupId, minMessages: GUEST_PINNED_RULES.minMessages,
  }) : 0;
  const scoringMembers = signerAddress == null ? members
    : members.map((member) => member.uid === myUid ? { ...member, addr: signerAddress } : member);
  const scored = await calculateGroupResults({
    members: scoringMembers,
    submissions: { [myUid]: bundle },
    meta: { blockNum, groupId },
  }, GUEST_PINNED_RULES.minChars, GUEST_PINNED_RULES.minMessages, {
    maxChars: GUEST_PINNED_RULES.maxChars,
    maxMessages: GUEST_PINNED_RULES.maxMessages,
    maxMsgChars: GUEST_PINNED_RULES.maxMsgChars,
  }, chatWindow);
  const row = scored.results.find((entry) => entry.uid === myUid);
  if (!row) throw new Error('The submission owner has no scoring row');
  const reasons = row.disqualifyReasons ?? [];
  const rejected = reasons.some((reason) => GUARANTEE_REJECT_REASONS.includes(reason));
  const count = scored.canonicalTimeline.reduce((sum, entry) =>
    sum + (entry.kind === 'chat' && entry.uid === myUid ? countVisibleChars(entry.text) : 0), 0);
  const seenMessages = new Set();
  const distinctMessages = [];
  for (const message of ownMessages || []) {
    if (message?.uid !== myUid) continue;
    const key = computeMsgKeyV2(blockNum, groupId, message);
    if (seenMessages.has(key)) continue;
    seenMessages.add(key);
    distinctMessages.push(message);
  }
  const overCaps = applyChatCaps(distinctMessages, GUEST_PINNED_RULES).length < distinctMessages.length;
  // S3R8-A-1-01: 最優先欄の自分の発言の可視字数。
  const priorityChars = Array.isArray(priority?.messages)
    ? priority.messages.reduce((sum, message) =>
      sum + (message?.uid === myUid ? countVisibleChars(message.text) : 0), 0)
    : 0;
  const actions = bundle.encryptedActions || {};
  const ownVotes = [
    ...actionEntries(actions.votes?.[myUid]),
    ...actionEntries(actions.observed?.votes?.[myUid]),
    ...actionEntries(ownActions?.votes),
  ];
  const ownReports = [
    ...actionEntries(actions.reports?.[myUid]),
    ...actionEntries(actions.observed?.reports?.[myUid]),
    ...actionEntries(ownActions?.reports),
  ];
  const voteTargets = signedTargetCount(ownVotes, bundle.encryptKey);
  const reportTargets = signedTargetCount(ownReports, bundle.encryptKey);
  const voteDone = row.voteTargetUid != null;
  return {
    turns,
    chars: { count, overCaps, priorityCount: priorityChars },
    vote: {
      done: voteDone,
      targetUid: voteDone && voteTargets === 1 ? row.voteTargetUid : null,
      signedTargets: voteTargets,
    },
    reports: { counted: [...(row.reportTargetUids ?? [])], signedTargets: reportTargets },
    rejected,
    reasons,
  };
}

export function describeSubmissionGuarantee(summary, { operatorUsed = false } = {}) {
  const row = (key, params = {}, alert = false) => ({ key, params, alert });
  if (summary.rejected) return {
    rows: [row('turnsUnprotected', {}, true), row('charsUnprotected', {}, true),
      row('voteRejected', {}, true), row('reportsRejected', {}, true)],
    notes: operatorUsed ? ['noteOperator', 'noteRejected'] : ['noteRejected'],
  };
  const rows = [row('turns', { count: summary.turns, min: GUEST_PINNED_RULES.minMessages },
    summary.turns < GUEST_PINNED_RULES.minMessages)];
  rows.push(summary.chars.overCaps ? row('charsUnprotected', {}, true)
    : { ...row('chars', { count: summary.chars.count, min: GUEST_PINNED_RULES.minChars },
      summary.chars.count < GUEST_PINNED_RULES.minChars),
    note: summary.chars.priorityCount >= GUEST_PINNED_RULES.minChars
      ? { key: 'charsRareMin', params: { chars: summary.chars.count, min: GUEST_PINNED_RULES.minChars } }
      : { key: 'charsRare', params: { chars: summary.chars.count } } });
  rows.push(!summary.vote.done ? row('voteUnprotected', {}, true)
    : summary.vote.targetUid != null ? row('voteDone', { targetUid: summary.vote.targetUid })
      : row('voteDoneNoTarget'));
  rows.push(summary.reports.signedTargets >= 3 ? row('reportsTooMany')
    : summary.reports.counted.length === 0 ? row('reportsNone')
      : { ...row('reports', { targetUids: summary.reports.counted }),
      note: { key: 'reportsRare', params: {} } });
  return { rows, notes: operatorUsed ? ['noteOperator', 'noteAlways'] : ['noteAlways'] };
}

const onChainFallback = new Map();

export function onChainRecordKey(blockNum, uid) {
  return `evidence_result_${blockNum}_user${uid}_onchain`;
}

export function submissionPayloadSha256(payload) {
  return sha256(stringToBytes(payload));
}

export function makeOnChainRecord(txHash, payload, storedPayload, { chatWindow = null, multiple = false } = {}) {
  return { v: 1, txHash, sha256: sha256(stringToBytes(payload)),
    payload: payload === storedPayload ? null : payload, chatWindow, multiple };
}

function validRecord(record) {
  return record?.v === 1 && typeof record.txHash === 'string' && record.txHash.length > 0
    && typeof record.sha256 === 'string' && /^0x[0-9a-fA-F]{64}$/.test(record.sha256)
    && (record.payload === null || typeof record.payload === 'string')
    && (record.chatWindow == null || (Number.isSafeInteger(record.chatWindow.startMs)
      && Number.isSafeInteger(record.chatWindow.endMs) && record.chatWindow.startMs <= record.chatWindow.endMs))
    && (record.multiple == null || typeof record.multiple === 'boolean');
}

export function writeOnChainRecord(storage, blockNum, uid, record) {
  if (!validRecord(record)) return false;
  const key = onChainRecordKey(blockNum, uid);
  onChainFallback.set(key, record);
  try {
    storage?.setItem(key, JSON.stringify(record));
    return !!storage;
  } catch { return false; }
}

export function readOnChainRecord(storage, blockNum, uid) {
  const key = onChainRecordKey(blockNum, uid);
  const fallback = onChainFallback.get(key);
  if (validRecord(fallback)) return fallback;
  try {
    const raw = storage?.getItem(key);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return validRecord(parsed) ? parsed : null;
  } catch { return null; }
}

export function rebindOnChainRecord(storage, blockNum, uid, fromHash, toHash) {
  const previous = readOnChainRecord(storage, blockNum, uid);
  if (!previous || previous.txHash !== fromHash || typeof toHash !== 'string' || !toHash) return false;
  return writeOnChainRecord(storage, blockNum, uid, { ...previous, txHash: toHash });
}

export function payloadForAcceptedTx(record, txHash, storedPayload) {
  if (!validRecord(record) || record.txHash !== txHash) return null;
  const payload = record.payload === null ? storedPayload : record.payload;
  if (typeof payload !== 'string') return null;
  return sha256(stringToBytes(payload)) === record.sha256 ? payload : null;
}

function defaultGuaranteeTimers() {
  return {
    setTimeout: (callback, delay) => globalThis.setTimeout(callback, delay),
    clearTimeout: (id) => globalThis.clearTimeout(id),
    requestIdleCallback: (callback) => typeof globalThis.requestIdleCallback === 'function'
      ? globalThis.requestIdleCallback(callback) : globalThis.setTimeout(callback, 0),
    cancelIdleCallback: (id) => typeof globalThis.cancelIdleCallback === 'function'
      ? globalThis.cancelIdleCallback(id) : globalThis.clearTimeout(id),
  };
}

export function createGuaranteeScheduler({ delayMs = 1000, timers = defaultGuaranteeTimers() } = {}) {
  let generation = 0;
  let waiting = null;
  let idle = null;
  const cancel = () => {
    generation += 1;
    if (waiting !== null) timers.clearTimeout(waiting);
    if (idle !== null) timers.cancelIdleCallback(idle);
    waiting = null;
    idle = null;
  };
  return {
    cancel,
    request(compute, onResult) {
      cancel();
      const currentGeneration = generation;
      const isCurrent = () => generation === currentGeneration;
      waiting = timers.setTimeout(() => {
        waiting = null;
        if (!isCurrent()) return;
        idle = timers.requestIdleCallback(async () => {
          idle = null;
          try {
            const result = await compute(isCurrent);
            if (isCurrent()) onResult(result);
          } catch (error) {
            if (isCurrent()) onResult({ error });
          }
        });
      }, delayMs);
    },
  };
}

export function createSummaryCache(limit = 8) {
  const entries = new Map();
  return {
    get(key) {
      if (!entries.has(key)) return undefined;
      const value = entries.get(key);
      entries.delete(key);
      entries.set(key, value);
      return value;
    },
    set(key, value) {
      if (entries.has(key)) entries.delete(key);
      entries.set(key, value);
      while (entries.size > limit) entries.delete(entries.keys().next().value);
      return value;
    },
    clear() { entries.clear(); },
  };
}

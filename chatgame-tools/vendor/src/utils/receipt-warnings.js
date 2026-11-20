// Display-only warning observations. Call observe only after the receipt signature was verified.
import { PartialReadReceiptTracker, PARTIAL_READ_RECEIPT_ALERT_THRESHOLD } from '../../workers/game_workers/lib/protocol-v2.js';

export function reissueGroupKey({ receiverUid, senderUid, msgRefs }) {
  return JSON.stringify([receiverUid, senderUid, msgRefs]);
}

export function estimatePartialReadReissues({ uid, known = [], fromMemory = [], tracked = [], plans = [] }) {
  const tracker = new PartialReadReceiptTracker();
  const rows = [...known, ...fromMemory, ...tracked];
  const signatures = new Set(rows.map((row) => row?.signature).filter((value) => typeof value === 'string'));
  const seen = new Set();
  for (const row of rows) {
    if (row?.receiverUid !== uid || row.actionHash || !Array.isArray(row.msgRefs) || !row.signature
        || seen.has(row.signature)) continue;
    seen.add(row.signature);
    tracker.add(row);
  }
  const before = tracker.byIssuer.get(uid)?.partial.size || 0;
  const probes = [];
  for (const plan of plans) {
    let signature = `__clock_reissue_estimate_${probes.length}__`;
    while (signatures.has(signature)) signature += '_';
    signatures.add(signature);
    tracker.add({ ...plan, signature });
    probes.push({ key: reissueGroupKey(plan), signature });
  }
  const partial = tracker.byIssuer.get(uid)?.partial || new Set();
  const after = partial.size;
  return { before, after, alert: after >= PARTIAL_READ_RECEIPT_ALERT_THRESHOLD && after > before,
    keys: [...new Set(probes.filter(({ signature }) => partial.has(signature)).map(({ key }) => key))] };
}
export const RECEIPT_WARNING_WAIT_MS = 10 * 60 * 1000;
export const RECEIPT_WARNING_DUPLICATE_COUNT = 5;
export const RECEIPT_WARNING_MISSING_COUNT = 200;
export const RECEIPT_WARNING_MAX_ROWS_PER_ISSUER = 700;
export const RECEIPT_WARNING_MAX_KEYS_PER_ISSUER = 70000;
const MAX_FUTURE_REFS_PER_SENDER = 100;

export const isCountedActionReceipt = (receipt) =>
  !Array.isArray(receipt?.msgRefs) && typeof receipt?.actionHash === 'string';

// A separate official-page observation. Verification happens at the caller;
// admission and future-target checks must not narrow this count.
export class ActionReceiptDuplicateWarnings {
  constructor(selfUid) {
    this.selfUid = selfUid;
    this.issuers = new Map();
    this.attacked = new Set();
  }

  observe(receipt, digest) {
    const uid = receipt?.receiverUid;
    const hash = receipt?.actionHash;
    if (!isCountedActionReceipt(receipt) || !uid || uid === this.selfUid || !hash || !digest) return false;
    let actions = this.issuers.get(uid);
    if (!actions) { actions = new Map(); this.issuers.set(uid, actions); }
    let digests = actions.get(hash);
    if (!digests) {
      if (actions.size >= RECEIPT_WARNING_MAX_ROWS_PER_ISSUER) return false;
      digests = new Set(); actions.set(hash, digests);
    }
    if (digests.size < RECEIPT_WARNING_DUPLICATE_COUNT) digests.add(digest);
    if (digests.size < RECEIPT_WARNING_DUPLICATE_COUNT || this.attacked.has(uid)) return false;
    this.attacked.add(uid);
    return true;
  }

  attackedIssuers() { return [...this.attacked].sort(); }
}

// The caller supplies reports verified against the confirmed roster.
// Repeated ciphertexts represent one target and do not consume the issuer limit.
export function suspiciousReportingUids({ actions = [] } = {}) {
  const byActor = new Map();
  for (const action of actions) {
    if (!action?.uid || !action.encrypted) continue;
    let rows = byActor.get(action.uid);
    if (!rows) { rows = new Set(); byActor.set(action.uid, rows); }
    if (rows.size < 10) rows.add(action.encrypted);
  }
  return [...byActor].filter(([, rows]) => rows.size >= 3).map(([uid]) => uid).sort();
}

export function showReportingRecommendation(targetUid, reportStatus, activeSlots) {
  const status = reportStatus?.[targetUid];
  return status === 'void' || (!status && activeSlots < 2);
}

export function stableAttackedIssuerList(previous, candidates) {
  const next = [...candidates].sort();
  return previous.length === next.length && previous.every((value, index) => value === next[index])
    ? previous : next;
}

export function scheduleReceiptWarningAt(dueAt, callback, {
  now = () => performance.now(), setTimer = setTimeout,
} = {}) {
  return setTimer(callback, Math.max(0, dueAt - now()));
}

export class ReceiptWarnings {
  constructor(selfUid) {
    this.selfUid = selfUid;
    this.issuers = new Map();
    this.futureChatRefs = new Map();
    this.futureChatRefOverflow = new Set();
  }

  noteFutureChatRef(senderUid, ref) {
    if (!senderUid || !ref) return;
    let refs = this.futureChatRefs.get(senderUid);
    if (!refs) { refs = new Set(); this.futureChatRefs.set(senderUid, refs); }
    if (refs.size < MAX_FUTURE_REFS_PER_SENDER) refs.add(ref);
    else if (!refs.has(ref)) this.futureChatRefOverflow.add(senderUid);
  }

  observe(receipt, digest, arrivedAt, hasTarget = () => false) {
    if (!Array.isArray(receipt?.msgRefs) || !receipt.msgRefs.length || receipt.actionHash
        || !digest || !Number.isFinite(arrivedAt)
        || !receipt.receiverUid || receipt.receiverUid === this.selfUid) return false;
    const uid = receipt.receiverUid;
    let issuer = this.issuers.get(uid);
    if (!issuer) {
      issuer = { keys: new Map(), rows: new Map(), units: new Set(), duplicate: false };
      this.issuers.set(uid, issuer);
    }
    let changed = false;
    for (const ref of receipt.msgRefs) {
      const key = `${receipt.senderUid}|${ref}`;
      let digests = issuer.keys.get(key);
      if (!digests) {
        if (issuer.keys.size >= RECEIPT_WARNING_MAX_KEYS_PER_ISSUER) continue;
        digests = new Set(); issuer.keys.set(key, digests);
      }
      if (digests.size < RECEIPT_WARNING_DUPLICATE_COUNT && !digests.has(digest)) {
        digests.add(digest); changed = true;
      }
      if (digests.size >= RECEIPT_WARNING_DUPLICATE_COUNT) issuer.duplicate = true;
    }
    const unit = receipt.senderUid === uid ? digest : reissueGroupKey(receipt);
    if (!issuer.rows.has(digest) && !issuer.units.has(unit) && issuer.rows.size < RECEIPT_WARNING_MAX_ROWS_PER_ISSUER
        && !receipt.msgRefs.every((ref) => hasTarget(receipt.senderUid, ref))) {
      issuer.rows.set(digest, { senderUid: receipt.senderUid, refs: [...receipt.msgRefs], arrivedAt, unit });
      issuer.units.add(unit);
      changed = true;
    }
    return changed;
  }

  // hasTarget uses the same received-target set as receipt admission. An overflow
  // belongs to the sender whose signed chat filled its own future ledger.
  // 発行者と送り手が同じ行（自分宛ての既読）には溢れと未来の控えの除外を当てない（S3R4-C-6-03）。
  evaluate(now, hasTarget, hasOverflow = () => false) {
    const duplicateUids = [];
    const missingUids = [];
    let nextDueAt = null;
    for (const [uid, issuer] of this.issuers) {
      if (issuer.duplicate) duplicateUids.push(uid);
      let missing = 0;
      for (const [digest, row] of issuer.rows) {
        const absent = row.refs.filter((ref) => !hasTarget(row.senderUid, ref));
        if (!absent.length) { issuer.rows.delete(digest); issuer.units.delete(row.unit); continue; }
        if (row.senderUid !== uid && (hasOverflow(row.senderUid) || this.futureChatRefOverflow.has(row.senderUid))) continue;
        if (row.senderUid !== uid && absent.every((ref) => this.futureChatRefs.get(row.senderUid)?.has(ref))) continue;
        const due = row.arrivedAt + RECEIPT_WARNING_WAIT_MS;
        if (now >= due) missing += 1;
        else if (nextDueAt == null || due < nextDueAt) nextDueAt = due;
      }
      if (missing >= RECEIPT_WARNING_MISSING_COUNT) missingUids.push(uid);
    }
    return { duplicateUids, missingUids, nextDueAt };
  }
}

// Display only. Eligibility itself stays with the existing report gate.
export function soleRemainingReportTarget({ members, selfUid, targetUid, alreadyReported,
  isEligible }) {
  const eligible = members.filter((uid) => uid !== selfUid && isEligible(uid));
  const remaining = eligible.filter((uid) => uid === targetUid || !alreadyReported.has(uid));
  return remaining.length === 1 ? remaining[0] : null;
}

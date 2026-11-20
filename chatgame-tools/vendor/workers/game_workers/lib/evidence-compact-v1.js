// evidence-compact-v1: version 2 bounded, deterministic transport for signed result bundles.
//
// The codec changes transport bytes only.  Decoding recreates the exact logical
// bundle consumed by the calculator. Production accepts this frame only.
// The payload always carries hasPriority after messages. With priority, E is
// encoded there and receipt references index T = E ++ messages (E wins overlap).
// E′ receipt and aggregate facts use a separate bounded decode-work counter.

import {
  actionHashV2,
  buildMsgKeyGetter,
  canonicalizeSignature,
  compareHexAsc,
  compareStrAsc,
  computeMsgKeyV2,
  isCanonicalSignature,
  msgRefOf,
  receiptCoverClaim,
} from './protocol-v2.js';
import {
  EVIDENCE_MAX_WIRE_BYTES,
  MAX_REFS_PER_RECEIPT,
  MAX_RECEIPT_FACTS,
  MAX_RECEIPT_OBJECTS,
  MAX_SELF_AGGREGATE_TARGETS,
  PRIORITY_MESSAGES_MAX,
  PRIORITY_RECEIPTS_MAX,
  SERVER_MAX_DECODED_BYTES,
  SERVER_MAX_WIRE_BYTES,
  validateSubmissionStructure,
} from './submission-limits.js';

export const EVIDENCE_COMPACT_MAGIC = Uint8Array.of(0x45, 0x56, 0x43, 0x31); // EVC1
export const EVIDENCE_COMPACT_VERSION = 2;
export const SELF_RECEIPT_AGGREGATE_SIGN_VERSION = 1;
export const EVIDENCE_COMPACT_MIN_BYTES = 256;
export const SELF_AGGREGATE_READS_PER_SENDER = 100;
export const SELF_AGGREGATE_ACTIONS_PER_SENDER_TYPE = 10;

const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });

class Writer {
  constructor() { this.parts = []; this.length = 0; }
  bytes(value) { const b = value instanceof Uint8Array ? value : Uint8Array.from(value); this.parts.push(b); this.length += b.length; }
  u8(v) { if (!Number.isInteger(v) || v < 0 || v > 0xff) throw new Error('compact u8 overflow'); this.bytes([v]); }
  u16(v) { if (!Number.isInteger(v) || v < 0 || v > 0xffff) throw new Error('compact u16 overflow'); this.bytes([(v >>> 8) & 255, v & 255]); }
  u32(v) { if (!Number.isInteger(v) || v < 0 || v > 0xffffffff) throw new Error('compact u32 overflow'); this.bytes([(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]); }
  u64(v) {
    const n = BigInt(v);
    if (n < 0n || n > 0xffffffffffffffffn) throw new Error('compact u64 overflow');
    const b = new Uint8Array(8);
    let x = n;
    for (let i = 7; i >= 0; i--) { b[i] = Number(x & 255n); x >>= 8n; }
    this.bytes(b);
  }
  i64(v) {
    if (!Number.isSafeInteger(v)) throw new Error('compact i64 requires a safe integer');
    this.i64Big(BigInt(v));
  }
  i64Big(v) {
    const n = BigInt(v);
    if (n < -(1n << 63n) || n >= (1n << 63n)) throw new Error('compact signed i64 overflow');
    this.u64(n + (1n << 63n));
  }
  varUint(v) {
    let n = BigInt(v);
    if (n < 0n) throw new Error('compact varuint is negative');
    do {
      const byte = Number(n & 0x7fn); n >>= 7n;
      this.u8(n === 0n ? byte : (byte | 0x80));
    } while (n !== 0n);
  }
  delta(v, base) {
    if (!Number.isSafeInteger(v) || !Number.isSafeInteger(base)) throw new Error('compact timestamp delta requires safe integers');
    const d = BigInt(v) - BigInt(base);
    this.varUint(d >= 0n ? d * 2n : (-d * 2n) - 1n);
  }
  text8(v) { const b = te.encode(v); this.u8(b.length); this.bytes(b); }
  text16(v) { const b = te.encode(v); this.u16(b.length); this.bytes(b); }
  text32(v) { const b = te.encode(v); this.u32(b.length); this.bytes(b); }
  finish() { const out = new Uint8Array(this.length); let at = 0; for (const p of this.parts) { out.set(p, at); at += p.length; } return out; }
}

class Reader {
  constructor(bytes) { this.bytes = bytes; this.at = 0; }
  need(n) { if (!Number.isInteger(n) || n < 0 || this.at + n > this.bytes.length) throw new Error('compact frame truncated'); }
  take(n) { this.need(n); const out = this.bytes.subarray(this.at, this.at + n); this.at += n; return out; }
  u8() { return this.take(1)[0]; }
  u16() { const b = this.take(2); return b[0] * 256 + b[1]; }
  u32() { const b = this.take(4); return b[0] * 0x1000000 + b[1] * 0x10000 + b[2] * 256 + b[3]; }
  u64() { let n = 0n; for (const b of this.take(8)) n = (n << 8n) | BigInt(b); return n; }
  i64() {
    const n = this.i64Big();
    if (n < BigInt(Number.MIN_SAFE_INTEGER) || n > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('compact i64 exceeds safe integer');
    }
    return Number(n);
  }
  i64Big() { return this.u64() - (1n << 63n); }
  varUint() {
    let n = 0n;
    for (let shift = 0n; shift <= 49n; shift += 7n) {
      const byte = this.u8();
      n |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) {
        if (shift > 0n && byte === 0) throw new Error('compact varuint is non-canonical');
        return n;
      }
    }
    throw new Error('compact varuint exceeds safe delta width');
  }
  delta(base) {
    if (!Number.isSafeInteger(base)) throw new Error('compact timestamp delta base is invalid');
    const z = this.varUint();
    const d = (z & 1n) === 0n ? z / 2n : -((z + 1n) / 2n);
    const n = BigInt(base) + d;
    if (n < BigInt(Number.MIN_SAFE_INTEGER) || n > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('compact timestamp delta exceeds safe integer');
    }
    return Number(n);
  }
  text8() { return td.decode(this.take(this.u8())); }
  text16() { return td.decode(this.take(this.u16())); }
  text32() { return td.decode(this.take(this.u32())); }
}

function hexBytes(hex, expected = null) {
  if (typeof hex !== 'string' || !/^0x(?:[0-9a-f]{2})*$/.test(hex)) throw new Error('compact field is not canonical lowercase hex');
  const out = new Uint8Array((hex.length - 2) / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(2 + i * 2, 4 + i * 2), 16);
  if (expected != null && out.length !== expected) throw new Error(`compact hex length must be ${expected}`);
  return out;
}

function bytesHex(bytes) {
  let out = '0x';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

// EIP-2098 compact form.  All internal signatures are already low-s, so the
// high bit of s is available for yParity.  Outer wallet signatures remain 65B.
export function signature65To64(signature) {
  if (!isCanonicalSignature(signature)) throw new Error('internal signature is not canonical low-s');
  const b = hexBytes(signature, 65);
  const v = b[64];
  const parity = v === 27 ? 0 : (v === 28 ? 1 : -1);
  if (parity < 0) throw new Error('internal signature has invalid recovery id');
  const out = b.slice(0, 64);
  if (parity) out[32] |= 0x80;
  return out;
}

export function signature64To65(compact) {
  if (!(compact instanceof Uint8Array) || compact.length !== 64) throw new Error('compact signature must be 64 bytes');
  const out = new Uint8Array(65);
  out.set(compact);
  const parity = (out[32] & 0x80) !== 0;
  out[32] &= 0x7f;
  out[64] = parity ? 28 : 27;
  return bytesHex(out);
}

function writeVarHex(w, hex, maxBytes) {
  const b = hexBytes(hex);
  if (b.length > maxBytes) throw new Error('compact hex field exceeds limit');
  w.u8(b.length); w.bytes(b);
}
function readVarHex(r, maxBytes) { const n = r.u8(); if (n > maxBytes) throw new Error('compact hex field exceeds limit'); return bytesHex(r.take(n)); }

class BitWriter {
  constructor() { this.bytes = []; this.current = 0; this.used = 0; }
  bit(value) {
    this.current = (this.current << 1) | (value ? 1 : 0); this.used++;
    if (this.used === 8) { this.bytes.push(this.current); this.current = 0; this.used = 0; }
  }
  uint(value, bits) { for (let i = bits - 1; i >= 0; i--) this.bit((value >>> i) & 1); }
  finish() {
    if (this.used) this.bytes.push(this.current << (8 - this.used));
    return Uint8Array.from(this.bytes);
  }
}

class BitReader {
  constructor(reader) { this.reader = reader; this.current = 0; this.left = 0; }
  bit() {
    if (this.left === 0) { this.current = this.reader.u8(); this.left = 8; }
    const value = (this.current >>> (this.left - 1)) & 1; this.left--; return value;
  }
  uint(bits) { let value = 0; for (let i = 0; i < bits; i++) value = value * 2 + this.bit(); return value; }
  finish() {
    if (this.left > 0 && (this.current & ((1 << this.left) - 1)) !== 0) {
      throw new Error('compact text padding bits are non-canonical');
    }
  }
}

// Reversible per-UTF-16-unit bit code matched exactly to countHalfWidthChars:
// one class bit + 8 bits for the 189 half-width units, or one class bit + raw
// u16 for every other unit.  Therefore 50,000 half-width units cost at most
// 56,250 bytes and 25,000 full-width units at most 53,125 bytes, independent
// of empirical compression ratios.
function encodeText16Units(text) {
  const w = new Writer();
  w.u32(text.length);
  const bits = new BitWriter();
  for (let i = 0; i < text.length; i++) {
    const cu = text.charCodeAt(i);
    if (cu >= 0x01 && cu <= 0x7e) { bits.bit(0); bits.uint(cu - 1, 8); }
    else if (cu >= 0x00a1 && cu <= 0x00df) { bits.bit(0); bits.uint(126 + cu - 0x00a1, 8); }
    else { bits.bit(1); bits.uint(cu, 16); }
  }
  w.bytes(bits.finish());
  return w.finish();
}

function decodeText16Units(r) {
  const units = r.u32();
  if (units > 1_000) throw new Error('compact text unit count exceeds limit');
  const bits = new BitReader(r);
  const chunks = [];
  let chunk = [];
  for (let i = 0; i < units; i++) {
    let cu;
    if (bits.bit() === 0) {
      const symbol = bits.uint(8);
      if (symbol >= 189) throw new Error('compact half-width text symbol invalid');
      cu = symbol < 126 ? symbol + 1 : 0x00a1 + symbol - 126;
    } else cu = bits.uint(16);
    chunk.push(cu);
    if (chunk.length === 4096) { chunks.push(String.fromCharCode(...chunk)); chunk = []; }
  }
  bits.finish();
  if (chunk.length) chunks.push(String.fromCharCode(...chunk));
  return chunks.join('');
}

function actionRows(snapshot, blockNum, groupId) {
  const rows = [];
  const add = (type, uid, value) => {
    for (const action of (Array.isArray(value) ? value : [value])) {
      if (!action) continue;
      const hash = actionHashV2(type, blockNum, groupId, uid, action.encrypted, action.timestamp);
      rows.push({ type, uid, action, hash });
    }
  };
  for (const [section, type] of [[snapshot.votes, 'vote'], [snapshot.reports, 'report'], [snapshot.observed?.votes, 'vote'], [snapshot.observed?.reports, 'report']]) {
    for (const uid of Object.keys(section || {})) add(type, uid, section[uid]);
  }
  rows.sort((a, b) => compareStrAsc(a.type, b.type) || compareStrAsc(a.uid, b.uid)
    || (a.action.timestamp - b.action.timestamp) || compareHexAsc(a.hash, b.hash)
    || compareHexAsc(String(a.action.signature).toLowerCase(), String(b.action.signature).toLowerCase()));
  const unique = [];
  const seen = new Set();
  for (const row of rows) if (!seen.has(row.hash)) { seen.add(row.hash); unique.push(row); }
  return unique;
}

function writeActionSection(w, section, uidIndex, timestampBase) {
  const keys = Object.keys(section || {});
  w.u8(keys.length);
  for (const uid of keys) {
    const index = uidIndex.get(uid);
    if (index == null) throw new Error('compact action uid is outside roster');
    const raw = section[uid];
    const isArray = Array.isArray(raw);
    const actions = isArray ? raw : [raw];
    w.u8(index); w.u8(isArray ? 1 : 0); w.u8(actions.length);
    for (const action of actions) {
      w.bytes(hexBytes(`0x${action.encrypted}`, 225));
      w.bytes(signature65To64(action.signature));
      w.delta(action.timestamp, timestampBase);
    }
  }
}

function readActionSection(r, uids, timestampBase) {
  const count = r.u8();
  if (count > uids.length) throw new Error('compact action section has too many keys');
  const section = Object.create(null);
  const seen = new Set();
  for (let i = 0; i < count; i++) {
    const uidIndex = r.u8();
    if (uidIndex >= uids.length || seen.has(uidIndex)) throw new Error('compact action uid index is invalid');
    seen.add(uidIndex);
    const isArray = r.u8();
    if (isArray > 1) throw new Error('compact action array flag is invalid');
    const actionCount = r.u8();
    if (actionCount < 1 || actionCount > 10 || (!isArray && actionCount !== 1)) {
      throw new Error('compact action count is invalid');
    }
    const actions = [];
    for (let j = 0; j < actionCount; j++) {
      const encrypted = bytesHex(r.take(225)).slice(2);
      const signature = signature64To65(r.take(64));
      actions.push({ encrypted, signature, timestamp: r.delta(timestampBase) });
    }
    section[uids[uidIndex]] = isArray ? actions : actions[0];
  }
  return section;
}

export function selfReceiptAggregateSignString(blockNum, groupId, receiverUid, entries) {
  const targets = entries.map((entry) => entry.targetType === 'read'
    ? { targetType: 'read', senderUid: entry.senderUid, msgRef: entry.msgRef, timestamp: entry.timestamp }
    : { targetType: 'action', actionHash: entry.actionHash, timestamp: entry.timestamp });
  return JSON.stringify({
    type: 'receipt_aggregate',
    version: SELF_RECEIPT_AGGREGATE_SIGN_VERSION,
    blockNum: Number(blockNum),
    groupId: Number(groupId),
    receiverUid,
    targets,
  });
}

function selfAggregateEntryCmp(a, b) {
  return (a.timestamp - b.timestamp)
    || compareStrAsc(a.targetType, b.targetType)
    || compareStrAsc(a.targetType === 'read' ? a.senderUid : a.actionHash,
      b.targetType === 'read' ? b.senderUid : b.actionHash)
    || (a.targetType === 'read' ? compareHexAsc(a.msgRef, b.msgRef) : 0);
}

// R3-12: 到着順ではなく正準順で、採点が読む上限分だけを残す。
// targets は buildRealTargets() の戻り値。旧呼出しで省略された場合は
// 従来の fail-closed 全体上限だけを適用し、種別を推測しない。
export function selectSelfAggregateEntries(entries, targets = null) {
  const canonicalOutput = [...(entries || [])].sort(selfAggregateEntryCmp);
  if (!targets) return canonicalOutput;
  // 枠の「先頭」は receipt の受領時刻ではなく、採点が発信候補を切る対象時刻で決める。
  // 選抜後は aggregate 形式が要求する receipt timestamp 順へ戻す。
  const targetTime = (entry) => {
    if (entry.targetType === 'read') {
      const times = targets.refTimes?.get(`${entry.senderUid}|${entry.msgRef}`);
      return Array.isArray(times) ? Math.min(...times) : (times ?? entry.timestamp);
    }
    return targets.actionTimes?.get(entry.actionHash) ?? entry.timestamp;
  };
  const ranked = [...canonicalOutput].sort((a, b) => (targetTime(a) - targetTime(b))
    || compareStrAsc(a.targetType, b.targetType)
    || compareStrAsc(a.targetType === 'read' ? a.senderUid : a.actionHash,
      b.targetType === 'read' ? b.senderUid : b.actionHash)
    || (a.targetType === 'read' ? compareHexAsc(a.msgRef, b.msgRef) : 0));
  const used = new Map();
  const selected = [];
  for (const entry of ranked) {
    let bucket;
    let limit;
    if (entry.targetType === 'read') {
      bucket = `read|${entry.senderUid}`;
      limit = SELF_AGGREGATE_READS_PER_SENDER;
    } else {
      const actorUid = targets.actionActors?.get(entry.actionHash);
      const actionType = targets.actionTypes?.get(entry.actionHash);
      // selectBundleReceipts 後の正常系では必ず引ける。不明な action は
      // 誤った種別へ落とさず、後段の既存全体上限で fail-closed にする。
      if (typeof actorUid !== 'string' || (actionType !== 'vote' && actionType !== 'report')) {
        selected.push(entry);
        continue;
      }
      bucket = `${actionType}|${actorUid}`;
      limit = SELF_AGGREGATE_ACTIONS_PER_SENDER_TYPE;
    }
    const count = used.get(bucket) || 0;
    if (count >= limit) continue;
    used.set(bucket, count + 1);
    selected.push(entry);
  }
  return selected.sort(selfAggregateEntryCmp);
}

// compact wire の既読対象は E ++ messages への u16 索引である。
// したがって受領証明は、その提出物自身が運ぶ発言／発信だけを指さなければならない。
// 署名済み legacy atom と self aggregate は分割できないので、違反する atom は丸ごと落とす。
// 呼出側は encryptedDataHash／外側署名を作る前にこの関数を通すこと。
function carriedMessageIndex(messages, priorityMessages, blockNum, groupId) {
  const index = new Map();
  const ambiguous = new Set();
  const e = Array.isArray(priorityMessages) ? priorityMessages : [];
  const m = Array.isArray(messages) ? messages : [];
  for (const [column, offset] of [[e, 0], [m, e.length]]) {
    const seenInColumn = new Set();
    for (let i = 0; i < column.length; i++) {
      const message = column[i];
      const msgKey = computeMsgKeyV2(blockNum, groupId, message);
      const key = `${message.uid}|${msgRefOf(msgKey)}`;
      if (seenInColumn.has(msgKey)) ambiguous.add(key);
      seenInColumn.add(msgKey);
      const prior = index.get(key);
      if (prior === undefined) index.set(key, { msgKey, position: offset + i });
      else if (prior.msgKey !== msgKey) ambiguous.add(key);
    }
  }
  for (const key of ambiguous) index.delete(key);
  return new Map([...index].map(([key, row]) => [key, row.position]));
}

export function filterReceiptsToCarriedTargets(snapshot, messages, blockNum, groupId) {
  const source = snapshot || {};
  const observed = source.observed || {};
  const msgIndex = carriedMessageIndex(messages, source.priority?.messages, blockNum, groupId);

  const snapshotCore = {
    votes: source.votes || {},
    reports: source.reports || {},
    observed: { votes: observed.votes || {}, reports: observed.reports || {} },
  };
  const actionHashes = new Set(actionRows(snapshotCore, blockNum, groupId).map((row) => row.hash));
  // uid は `|` を含みうるが、ref はここまでに固定長 msgRef として検証済みなので
  // `${senderUid}|${ref}` は単射である。msgRef を可変長へ変えるならキー形式も変えること。
  const carriedRead = (senderUid, ref) => msgIndex.has(`${senderUid}|${ref}`);
  const receipts = (Array.isArray(observed.receipts) ? observed.receipts : []).filter((receipt) => {
    if (Array.isArray(receipt?.msgRefs) && typeof receipt?.senderUid === 'string') {
      return receipt.msgRefs.every((ref) => carriedRead(receipt.senderUid, ref));
    }
    return typeof receipt?.actionHash === 'string' && actionHashes.has(receipt.actionHash);
  });
  const aggregate = observed.selfReceiptAggregate || null;
  const aggregateValid = !aggregate || (Array.isArray(aggregate.entries) && aggregate.entries.every((entry) => (
    entry?.targetType === 'read'
      ? carriedRead(entry.senderUid, entry.msgRef)
      : entry?.targetType === 'action' && actionHashes.has(entry.actionHash)
  )));
  const nextObserved = { ...observed, receipts };
  if (aggregateValid && aggregate) nextObserved.selfReceiptAggregate = aggregate;
  else delete nextObserved.selfReceiptAggregate;
  return { ...source, observed: nextObserved };
}

// Final client-side bound for the raw (non-deduplicated) receipt facts counted by
// validateSubmissionStructure. The caller supplies the canonical receipt comparator
// to avoid importing the calculator here. The ordinary case preserves object identity.
export function limitCarriedReceiptFacts(snapshot, { submitterUid, compare } = {}) {
  const legacy = snapshot?.observed?.receipts;
  if (!Array.isArray(legacy)) return snapshot;
  const aggregate = snapshot.observed.selfReceiptAggregate?.entries;
  const aggregateCost = Array.isArray(aggregate) ? aggregate.length : 0;
  const cost = (receipt) => Array.isArray(receipt?.msgRefs) ? receipt.msgRefs.length : 1;
  const total = legacy.reduce((sum, receipt) => sum + cost(receipt), aggregateCost);
  if (total <= MAX_RECEIPT_FACTS && legacy.length <= MAX_RECEIPT_OBJECTS) return snapshot;

  const byIssuer = new Map();
  for (const receipt of legacy) {
    const issuer = receipt?.receiverUid;
    if (!byIssuer.has(issuer)) byIssuer.set(issuer, []);
    byIssuer.get(issuer).push(receipt);
  }
  const budget = MAX_RECEIPT_FACTS - aggregateCost;
  const share = Math.floor(budget / byIssuer.size);
  const kept = new Set();
  const cmp = (left, right) => compare(left, right)
    || String(left.signature).toLowerCase().localeCompare(String(right.signature).toLowerCase());
  for (const issuer of [...byIssuer.keys()].sort()) {
    const list = byIssuer.get(issuer);
    const actions = list.filter((receipt) => !Array.isArray(receipt?.msgRefs));
    const reads = list.filter((receipt) => Array.isArray(receipt?.msgRefs));
    let used = actions.length;
    for (const receipt of actions) kept.add(receipt);
    const ordered = [
      ...reads.filter((receipt) => receipt.senderUid === submitterUid).sort(cmp),
      ...reads.filter((receipt) => receipt.senderUid !== submitterUid).sort(cmp),
    ];
    // With at most four other issuers and A <= 480, share >= 480. The same
    // bound holds for five issuers when A is absent. Actions use <= 80 per
    // issuer. If malformed input breaks either premise, protect actions.
    // Roster size and validated action caps make this guard unreachable for a valid group.
    if (share < 480 || used > share) continue;
    for (const receipt of ordered) {
      if (used + cost(receipt) <= share) {
        kept.add(receipt);
        used += cost(receipt);
      }
    }
  }
  const receipts = legacy.filter((receipt) => kept.has(receipt));
  const result = { ...snapshot, observed: { ...snapshot.observed, receipts } };
  const resultCost = receipts.reduce((sum, receipt) => sum + cost(receipt), aggregateCost);
  if (resultCost > MAX_RECEIPT_FACTS || receipts.length > MAX_RECEIPT_OBJECTS) {
    throw new Error('receipt facts still exceed submission bounds');
  }
  return result;
}

/**
 * Legacy receipts are consumed in input order, which callers must supply as local arrival order.
 * This function never sorts them and never uses a receipt's self-asserted timestamp to decide
 * which legacy receipt wins: overlapping signed legacy receipts all remain.
 * Self read entries instead keep the earliest timely timestamp per target inside chatWindow;
 * a null window leaves the window filter unapplied. Action entries keep their existing rule.
 */
export async function aggregateSelfReceipts(receipts, receiverUid, blockNum, groupId, signMessage, targets = null, chatWindow = null) {
  const legacyEntries = [];
  const entries = [];
  const seen = new Set();
  const readEntryByKey = new Map();
  for (const receipt of receipts || []) {
    const normalized = Array.isArray(receipt?.msgRefs) && typeof receipt?.senderUid === 'string'
      ? {
        receiverUid: receipt.receiverUid, senderUid: receipt.senderUid,
        msgRefs: [...receipt.msgRefs], timestamp: receipt.timestamp,
        signature: receipt.signature,
      }
      : {
        receiverUid: receipt?.receiverUid, actionHash: receipt?.actionHash,
        timestamp: receipt?.timestamp, signature: receipt?.signature,
      };
    if (Array.isArray(normalized.msgRefs)
      && normalized.msgRefs.some((ref, index) => index > 0
        && compareHexAsc(normalized.msgRefs[index - 1], ref) >= 0)) {
      throw new Error('legacy receipt refs are not canonical');
    }
    const validTargets = targets
      ? new Set(receiptCoverClaim(normalized, targets).targetKeys)
      : null;
    if (normalized.receiverUid !== receiverUid) {
      let facts;
      if (Array.isArray(normalized.msgRefs)) {
        const allValid = normalized.msgRefs.every((ref) => !validTargets
          || validTargets.has(`r:${ref}|${normalized.senderUid}`));
        if (!allValid) continue;
        facts = normalized.msgRefs.map((ref) => `r|${normalized.receiverUid}|${ref}`);
      } else {
        if (validTargets && !validTargets.has(`a:${normalized.actionHash}`)) continue;
        facts = [`a|${normalized.receiverUid}|${normalized.actionHash}`];
      }
      if (facts.length === 0) continue;
      legacyEntries.push(normalized);
      continue;
    }
    if (Array.isArray(normalized.msgRefs) && typeof normalized.senderUid === 'string') {
      // 行動項目と他人の legacy は従来どおり。自己既読だけ採点の窓で絞る。
      if (chatWindow && !(normalized.timestamp >= chatWindow.startMs
        && normalized.timestamp <= chatWindow.endMs)) continue;
      for (const ref of normalized.msgRefs) {
        if (validTargets && !validTargets.has(`r:${ref}|${normalized.senderUid}`)) continue;
        const key = `r|${normalized.senderUid}|${ref}`;
        const previous = readEntryByKey.get(key);
        if (previous) {
          if (normalized.timestamp < previous.timestamp) previous.timestamp = normalized.timestamp;
          continue;
        }
        const entry = { targetType: 'read', senderUid: normalized.senderUid, msgRef: ref, timestamp: normalized.timestamp };
        readEntryByKey.set(key, entry);
        entries.push(entry);
      }
    } else if (typeof normalized.actionHash === 'string') {
      if (validTargets && !validTargets.has(`a:${normalized.actionHash}`)) continue;
      const key = `a|${normalized.actionHash}`;
      if (seen.has(key)) continue;
      seen.add(key);
      entries.push({ targetType: 'action', actionHash: normalized.actionHash, timestamp: normalized.timestamp });
    }
  }
  const selectedEntries = selectSelfAggregateEntries(entries, targets);
  // Finite-bound derivation (zero slack): receiptCoverClaim excludes self-sent reads, and
  // actionActors excludes self-sent actions, leaving MAX_GROUP_PLAYERS - 1 = 4 senders.
  // Read buckets retain SELF_AGGREGATE_READS_PER_SENDER = 100 entries per sender; vote
  // and report buckets each retain SELF_AGGREGATE_ACTIONS_PER_SENDER_TYPE = 10 entries
  // per sender, while MAX_ACTION_CANDIDATES_PER_TYPE_PER_ACTOR = 10 caps the candidate
  // side at the same size.  Thus 4 * 100 + 4 * 2 * 10 = 480, exactly
  // MAX_SELF_AGGREGATE_TARGETS, so the slack is zero.  Changes to MAX_GROUP_PLAYERS,
  // SELF_AGGREGATE_READS_PER_SENDER, SELF_AGGREGATE_ACTIONS_PER_SENDER_TYPE, or
  // MAX_ACTION_CANDIDATES_PER_TYPE_PER_ACTOR must review all four finite-fact thresholds.
  if (selectedEntries.length > MAX_SELF_AGGREGATE_TARGETS) throw new Error(`self receipt aggregate exceeds ${MAX_SELF_AGGREGATE_TARGETS}`);
  if (selectedEntries.length === 0) {
    return { receipts: legacyEntries, aggregate: null };
  }
  const signature = canonicalizeSignature(
    await signMessage(selfReceiptAggregateSignString(blockNum, groupId, receiverUid, selectedEntries))
  );
  if (!isCanonicalSignature(signature)) throw new Error('self receipt aggregate signature is not canonical');
  return {
    receipts: legacyEntries,
    aggregate: { version: 1, receiverUid, entries: selectedEntries, signature },
  };
}

function buildUidTable(bundle, memberUids) {
  const uids = [...memberUids];
  if (!uids.includes(bundle.uid)) throw new Error('submitter is outside compact roster');
  if (uids.length < 1 || uids.length > 5 || new Set(uids).size !== uids.length) throw new Error('compact roster is invalid');
  return { uids, index: new Map(uids.map((uid, i) => [uid, i])) };
}

// @param opts.sanitized  省略可の**出力用オブジェクト**。運んでいない対象を指す受領証明／
//   集約を落とした場合に限り `{ bundle, droppedReceipts, droppedAggregate }` を書き込む。
//
// 🔴 2026-08-20（第6ラウンド 判断2(2)）: **落としたことを呼出側へ必ず伝える。**
//    ここでの除去は `encryptedDataHash` と外側ウォレット署名が**確定した後**に起きるので、
//    落としたまま提出すると復号後の snapshot がハッシュと合わず、採点入口で
//    `snapshot_mismatch` になる ——「fail-soft で提出を続ける」という B-5 の意図が
//    **達成されない**（第6ラウンド CX-R6-01）。落ちたら呼出側は
//    **`sanitized.bundle` から hash と署名を作り直して再符号化する**こと。
//    ⚠️ 一次防衛線は依然として呼出側の `filterReceiptsToCarriedTargets`（ハッシュ**前**）で、
//       ここはそれを通っていない経路を救う二次防衛線である。
export function encodeEvidenceCompactV1(
  bundle, { blockNum, groupId, memberUids } = {}, { sanitized = null } = {},
) {
  const checked = validateSubmissionStructure(bundle, { blockNum, groupId, memberUids });
  if (!checked.ok) throw new Error(`non-canonical submission: ${checked.reason}`);
  const { uids, index: uidIndex } = buildUidTable(bundle, memberUids);
  const snapshot = bundle.encryptedActions;
  const priority = snapshot.priority || null;
  const receipts = snapshot.observed.receipts;
  if (receipts.length > MAX_RECEIPT_FACTS) throw new Error(`receipt objects exceeds ${MAX_RECEIPT_FACTS}`);
  const aggregate = snapshot.observed.selfReceiptAggregate || null;
  const snapshotCore = {
    votes: snapshot.votes,
    reports: snapshot.reports,
    observed: { votes: snapshot.observed.votes, reports: snapshot.observed.reports },
  };
  const actions = actionRows(snapshotCore, blockNum, groupId);
  const actionIndex = new Map(actions.map((row, i) => [row.hash, i]));
  const msgIndex = carriedMessageIndex(bundle.messages, priority?.messages, blockNum, groupId);
  const wireReceipts = receipts.filter((receipt) => {
    if (Array.isArray(receipt?.msgRefs) && typeof receipt?.senderUid === 'string') {
      return receipt.msgRefs.every((ref) => msgIndex.has(`${receipt.senderUid}|${ref}`));
    }
    return typeof receipt?.actionHash === 'string' && actionIndex.has(receipt.actionHash);
  });
  const wireAggregate = aggregate && Array.isArray(aggregate.entries) && aggregate.entries.every((entry) => (
    entry?.targetType === 'read'
      ? msgIndex.has(`${entry.senderUid}|${entry.msgRef}`)
      : entry?.targetType === 'action' && actionIndex.has(entry.actionHash)
  )) ? aggregate : null;

  if (sanitized) {
    const droppedReceipts = receipts.filter((receipt) => !wireReceipts.includes(receipt));
    const droppedAggregate = !!aggregate && !wireAggregate;
    if (droppedReceipts.length || droppedAggregate) {
      const nextObserved = { ...snapshot.observed, receipts: wireReceipts };
      if (wireAggregate) nextObserved.selfReceiptAggregate = wireAggregate;
      else delete nextObserved.selfReceiptAggregate;   // null 代入は非正準（キーごと消す）
      sanitized.bundle = {
        ...bundle,
        encryptedActions: { ...snapshot, observed: nextObserved },
      };
      sanitized.droppedReceipts = droppedReceipts;
      sanitized.droppedAggregate = droppedAggregate;
    }
  }

  const p = new Writer();
  p.u64(blockNum); p.u64(groupId);
  p.u8(uids.length); for (const uid of uids) p.text8(uid);
  p.u8(uidIndex.get(bundle.uid));
  p.text16(bundle.encryptKey);
  writeVarHex(p, bundle.chatHash, 32);
  p.bytes(hexBytes(bundle.signature, 65));
  p.i64(bundle.submittedAt);
  writeVarHex(p, bundle.encryptedDataHash, 32);
  p.u8(bundle.depositIds.length); for (const id of bundle.depositIds) p.text8(id);
  writeActionSection(p, snapshotCore.votes, uidIndex, bundle.submittedAt);
  writeActionSection(p, snapshotCore.reports, uidIndex, bundle.submittedAt);
  writeActionSection(p, snapshotCore.observed.votes, uidIndex, bundle.submittedAt);
  writeActionSection(p, snapshotCore.observed.reports, uidIndex, bundle.submittedAt);
  p.u16(bundle.messages.length);
  for (const message of bundle.messages) {
    p.u8(uidIndex.get(message.uid)); p.delta(message.timestamp, bundle.submittedAt); p.bytes(signature65To64(message.signature));
    p.bytes(encodeText16Units(message.text));
  }
  p.u8(priority ? 1 : 0);
  if (priority) {
    p.u16(priority.messages.length);
    for (const message of priority.messages) {
      p.u8(uidIndex.get(message.uid)); p.delta(message.timestamp, bundle.submittedAt); p.bytes(signature65To64(message.signature));
      p.bytes(encodeText16Units(message.text));
    }
  }
  p.u16(wireReceipts.length);
  for (const receipt of wireReceipts) {
    const receiver = uidIndex.get(receipt.receiverUid);
    if (receiver == null) throw new Error('receipt receiver outside roster');
    if (Array.isArray(receipt.msgRefs) && typeof receipt.senderUid === 'string') {
      const sender = uidIndex.get(receipt.senderUid);
      if (sender == null) throw new Error('receipt sender outside roster');
      p.u8(0); p.u8(receiver); p.u8(sender); p.delta(receipt.timestamp, bundle.submittedAt); p.bytes(signature65To64(receipt.signature));
      p.u8(receipt.msgRefs.length);
      for (const ref of receipt.msgRefs) {
        const target = msgIndex.get(`${receipt.senderUid}|${ref}`);
        p.u16(target);
      }
    } else {
      const target = actionIndex.get(receipt.actionHash);
      p.u8(1); p.u8(receiver); p.delta(receipt.timestamp, bundle.submittedAt); p.bytes(signature65To64(receipt.signature)); p.u16(target);
    }
  }
  p.u8(wireAggregate ? 1 : 0);
  if (wireAggregate) {
    if (wireAggregate.receiverUid !== bundle.uid || wireAggregate.version !== 1 || !Array.isArray(wireAggregate.entries)
      || wireAggregate.entries.length > MAX_SELF_AGGREGATE_TARGETS) throw new Error('self receipt aggregate is invalid');
    p.u8(uidIndex.get(wireAggregate.receiverUid)); p.bytes(signature65To64(wireAggregate.signature)); p.u16(wireAggregate.entries.length);
    for (const entry of wireAggregate.entries) {
      p.delta(entry.timestamp, bundle.submittedAt);
      if (entry.targetType === 'read') {
        const target = msgIndex.get(`${entry.senderUid}|${entry.msgRef}`);
        p.u8(0); p.u16(target);
      } else if (entry.targetType === 'action') {
        const target = actionIndex.get(entry.actionHash);
        p.u8(1); p.u16(target);
      } else throw new Error('aggregate target type is invalid');
    }
  }
  if (priority) {
    p.u8(priority.receipts.length);
    for (const receipt of priority.receipts) {
      const receiver = uidIndex.get(receipt.receiverUid);
      const sender = uidIndex.get(receipt.senderUid);
      if (receiver == null || sender == null) throw new Error('priority receipt uid outside roster');
      p.u8(0); p.u8(receiver); p.u8(sender); p.delta(receipt.timestamp, bundle.submittedAt);
      p.bytes(signature65To64(receipt.signature)); p.u8(receipt.msgRefs.length);
      for (const ref of receipt.msgRefs) p.u16(msgIndex.get(`${receipt.senderUid}|${ref}`));
    }
    const aggregateP = priority.selfReceiptAggregate || null;
    p.u8(aggregateP ? 1 : 0);
    if (aggregateP) {
      p.u8(uidIndex.get(aggregateP.receiverUid)); p.bytes(signature65To64(aggregateP.signature));
      p.u16(aggregateP.entries.length);
      for (const entry of aggregateP.entries) {
        p.delta(entry.timestamp, bundle.submittedAt);
        p.u8(0); p.u16(msgIndex.get(`${entry.senderUid}|${entry.msgRef}`));
      }
    }
  }

  const payload = p.finish();
  let total = 4 + 1 + 1 + 4 + 2 + payload.length;
  const padding = Math.max(0, EVIDENCE_COMPACT_MIN_BYTES - total);
  total += padding;
  if (total > SERVER_MAX_WIRE_BYTES) throw new Error(`compact server payload exceeds ${SERVER_MAX_WIRE_BYTES}`);
  const frame = new Writer();
  frame.bytes(EVIDENCE_COMPACT_MAGIC); frame.u8(EVIDENCE_COMPACT_VERSION); frame.u8(0); frame.u32(payload.length); frame.u16(padding);
  frame.bytes(payload); if (padding) frame.bytes(new Uint8Array(padding));
  return frame.finish();
}

function addCompactTargetFacts(total, additional, maxTargetFacts) {
  const next = total + additional;
  if (next > maxTargetFacts) throw new Error('compact target facts exceed decode work limit');
  return next;
}

export function decodeEvidenceCompactV1(
  frame,
  { maxWireBytes = SERVER_MAX_WIRE_BYTES, maxTargetFacts = MAX_RECEIPT_FACTS } = {},
) {
  if (!(frame instanceof Uint8Array)) throw new Error('compact frame must be bytes');
  if (frame.length > maxWireBytes) throw new Error('compact frame exceeds wire limit');
  if (!Number.isSafeInteger(maxTargetFacts) || maxTargetFacts < 0
    || maxTargetFacts > MAX_RECEIPT_FACTS) {
    throw new Error('compact target fact work limit is invalid');
  }
  const r = new Reader(frame);
  const magic = r.take(4);
  if (!EVIDENCE_COMPACT_MAGIC.every((b, i) => magic[i] === b)) throw new Error('compact magic mismatch');
  if (r.u8() !== EVIDENCE_COMPACT_VERSION) throw new Error('compact version is unsupported');
  if (r.u8() !== 0) throw new Error('compact flags are unsupported');
  const payloadLength = r.u32();
  const paddingLength = r.u16();
  if (payloadLength + paddingLength !== frame.length - r.at) throw new Error('compact frame length mismatch');
  const pr = new Reader(r.take(payloadLength));
  const padding = r.take(paddingLength);
  if (padding.some((b) => b !== 0)) throw new Error('compact padding is not canonical');
  if (frame.length < EVIDENCE_COMPACT_MIN_BYTES || (paddingLength > 0 && frame.length !== EVIDENCE_COMPACT_MIN_BYTES)) {
    throw new Error('compact padding length is not canonical');
  }

  const blockNumBig = pr.u64(); const groupIdBig = pr.u64();
  if (blockNumBig > BigInt(Number.MAX_SAFE_INTEGER) || groupIdBig > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('compact context exceeds safe integer');
  const blockNum = Number(blockNumBig); const groupId = Number(groupIdBig);
  const uidCount = pr.u8(); if (uidCount < 1 || uidCount > 5) throw new Error('compact roster length is invalid');
  const uids = []; for (let i = 0; i < uidCount; i++) uids.push(pr.text8());
  if (new Set(uids).size !== uids.length) throw new Error('compact roster contains duplicates');
  const submitterIndex = pr.u8(); if (submitterIndex >= uids.length) throw new Error('compact submitter index is invalid');
  const uid = uids[submitterIndex];
  const encryptKey = pr.text16(); const chatHash = readVarHex(pr, 32); const signature = bytesHex(pr.take(65));
  const submittedAt = pr.i64(); const encryptedDataHash = readVarHex(pr, 32);
  const depositCount = pr.u8(); if (depositCount > 10) throw new Error('compact depositIds exceeds limit');
  const depositIds = []; for (let i = 0; i < depositCount; i++) depositIds.push(pr.text8());
  const snapshot = {
    votes: readActionSection(pr, uids, submittedAt),
    reports: readActionSection(pr, uids, submittedAt),
    observed: {
      votes: readActionSection(pr, uids, submittedAt),
      reports: readActionSection(pr, uids, submittedAt),
      receipts: [],
    },
  };

  const messageCount = pr.u16(); if (messageCount > 500) throw new Error('compact messages exceeds limit');
  const messages = [];
  for (let i = 0; i < messageCount; i++) {
    const mi = pr.u8(); if (mi >= uids.length) throw new Error('compact message uid index is invalid');
    const ts = pr.delta(submittedAt);
    const message = { type: 'chat', blockNum, groupId, uid: uids[mi], text: '', timestamp: ts, signature: signature64To65(pr.take(64)) };
    message.text = decodeText16Units(pr); messages.push(message);
  }
  const hasPriority = pr.u8();
  if (hasPriority > 1) throw new Error('compact priority flag is invalid');
  const priorityMessages = [];
  if (hasPriority) {
    const count = pr.u16();
    if (count < 1 || count > PRIORITY_MESSAGES_MAX) throw new Error('compact priority message count is invalid');
    for (let i = 0; i < count; i++) {
      const mi = pr.u8(); if (mi >= uids.length) throw new Error('compact priority message uid index is invalid');
      const ts = pr.delta(submittedAt);
      const message = { type: 'chat', blockNum, groupId, uid: uids[mi], text: '', timestamp: ts, signature: signature64To65(pr.take(64)) };
      message.text = decodeText16Units(pr); priorityMessages.push(message);
    }
  }
  const carriedMessages = [...priorityMessages, ...messages];
  // 正典 helper の WeakMap をフレーム全体で共有する。同じ message index が多数の
  // receipt / aggregate entry から参照されても keccak はメッセージ1件につき1回だけ。
  const getMsgKey = buildMsgKeyGetter(blockNum, groupId);
  const actions = actionRows(snapshot, blockNum, groupId);
  const receiptCount = pr.u16(); if (receiptCount > MAX_RECEIPT_FACTS) throw new Error('compact receipts exceeds limit');
  let decodedTargetFacts = 0;
  for (let i = 0; i < receiptCount; i++) {
    const kind = pr.u8(); const receiver = pr.u8(); if (receiver >= uids.length) throw new Error('compact receipt receiver index is invalid');
    if (kind === 0) {
      const sender = pr.u8(); if (sender >= uids.length) throw new Error('compact receipt sender index is invalid');
      const ts = pr.delta(submittedAt); const sig = signature64To65(pr.take(64)); const refs = pr.u8();
      if (refs < 1 || refs > 100) throw new Error('compact read receipt ref count is invalid');
      decodedTargetFacts = addCompactTargetFacts(decodedTargetFacts, refs, maxTargetFacts);
      const msgRefs = [];
      for (let j = 0; j < refs; j++) { const target = pr.u16(); if (target >= carriedMessages.length || carriedMessages[target].uid !== uids[sender]) throw new Error('compact read target index is invalid'); msgRefs.push(msgRefOf(getMsgKey(carriedMessages[target]))); }
      // msgRefs order is part of the legacy receipt signature preimage.  The
      // encoder writes target indices in that signed order, so decoding must
      // preserve it byte-for-byte; sorting here changes encryptedDataHash and
      // invalidates every otherwise-valid compact bundle carrying such a receipt.
      snapshot.observed.receipts.push({ receiverUid: uids[receiver], senderUid: uids[sender], msgRefs, timestamp: ts, signature: sig });
    } else if (kind === 1) {
      decodedTargetFacts = addCompactTargetFacts(decodedTargetFacts, 1, maxTargetFacts);
      const ts = pr.delta(submittedAt); const sig = signature64To65(pr.take(64)); const target = pr.u16();
      if (target >= actions.length) throw new Error('compact action target index is invalid');
      snapshot.observed.receipts.push({ receiverUid: uids[receiver], actionHash: actions[target].hash, timestamp: ts, signature: sig });
    } else throw new Error('compact receipt kind is invalid');
  }
  const hasAggregate = pr.u8();
  if (hasAggregate > 1) throw new Error('compact aggregate flag is invalid');
  if (hasAggregate) {
    const receiver = pr.u8(); if (receiver !== submitterIndex) throw new Error('compact aggregate receiver must be submitter');
    const sig = signature64To65(pr.take(64)); const count = pr.u16();
    if (count < 1 || count > MAX_SELF_AGGREGATE_TARGETS) throw new Error('compact aggregate count is invalid');
    decodedTargetFacts = addCompactTargetFacts(decodedTargetFacts, count, maxTargetFacts);
    const entries = [];
    for (let i = 0; i < count; i++) {
      const ts = pr.delta(submittedAt); const kind = pr.u8(); const target = pr.u16();
      if (kind === 0) {
        if (target >= carriedMessages.length) throw new Error('compact aggregate read target is invalid');
        entries.push({ targetType: 'read', senderUid: carriedMessages[target].uid, msgRef: msgRefOf(getMsgKey(carriedMessages[target])), timestamp: ts });
      } else if (kind === 1) {
        if (target >= actions.length) throw new Error('compact aggregate action target is invalid');
        entries.push({ targetType: 'action', actionHash: actions[target].hash, timestamp: ts });
      } else throw new Error('compact aggregate target kind is invalid');
    }
    snapshot.observed.selfReceiptAggregate = { version: 1, receiverUid: uid, entries, signature: sig };
  }
  let decodedPriorityFacts = 0;
  if (hasPriority) {
    const receipts = [];
    const count = pr.u8();
    if (count > PRIORITY_RECEIPTS_MAX) throw new Error('compact priority receipts exceed limit');
    for (let i = 0; i < count; i++) {
      const kind = pr.u8();
      if (kind !== 0) throw new Error('compact priority receipt kind is invalid');
      const receiver = pr.u8(); const sender = pr.u8();
      if (receiver >= uids.length || sender >= uids.length) throw new Error('compact priority receipt uid index is invalid');
      const ts = pr.delta(submittedAt); const sig = signature64To65(pr.take(64)); const refs = pr.u8();
      if (refs < 1 || refs > MAX_REFS_PER_RECEIPT) throw new Error('compact priority receipt ref count is invalid');
      decodedPriorityFacts = addCompactTargetFacts(decodedPriorityFacts, refs, PRIORITY_RECEIPTS_MAX * MAX_REFS_PER_RECEIPT + PRIORITY_MESSAGES_MAX);
      const msgRefs = [];
      for (let j = 0; j < refs; j++) {
        const target = pr.u16();
        if (target >= carriedMessages.length || carriedMessages[target].uid !== uids[sender]) throw new Error('compact priority read target index is invalid');
        msgRefs.push(msgRefOf(getMsgKey(carriedMessages[target])));
      }
      receipts.push({ receiverUid: uids[receiver], senderUid: uids[sender], msgRefs, timestamp: ts, signature: sig });
    }
    const priority = { messages: priorityMessages, receipts };
    const hasAggregateP = pr.u8();
    if (hasAggregateP > 1) throw new Error('compact priority aggregate flag is invalid');
    if (hasAggregateP) {
      const receiver = pr.u8();
      if (receiver !== submitterIndex) throw new Error('compact priority aggregate receiver must be submitter');
      const sig = signature64To65(pr.take(64)); const count = pr.u16();
      if (count < 1 || count > priorityMessages.length) throw new Error('compact priority aggregate count is invalid');
      decodedPriorityFacts = addCompactTargetFacts(decodedPriorityFacts, count, PRIORITY_RECEIPTS_MAX * MAX_REFS_PER_RECEIPT + PRIORITY_MESSAGES_MAX);
      const entries = [];
      for (let i = 0; i < count; i++) {
        const ts = pr.delta(submittedAt); const kind = pr.u8();
        if (kind !== 0) throw new Error('compact priority aggregate target kind is invalid');
        const target = pr.u16();
        if (target >= carriedMessages.length) throw new Error('compact priority aggregate read target is invalid');
        entries.push({ targetType: 'read', senderUid: carriedMessages[target].uid, msgRef: msgRefOf(getMsgKey(carriedMessages[target])), timestamp: ts });
      }
      priority.selfReceiptAggregate = { version: 1, receiverUid: uid, entries, signature: sig };
    }
    snapshot.priority = priority;
  }
  if (pr.at !== pr.bytes.length) throw new Error('compact payload has trailing bytes');
  const bundle = { uid, encryptKey, chatHash, signature, submittedAt, encryptedDataHash, depositIds, encryptedActions: snapshot, messages };
  const raw = JSON.stringify(bundle);
  if (te.encode(raw).length > SERVER_MAX_DECODED_BYTES) throw new Error('compact decoded bundle exceeds limit');
  const checked = validateSubmissionStructure(bundle, { blockNum, groupId, memberUids: uids });
  if (!checked.ok) throw new Error(`decoded compact submission is non-canonical: ${checked.reason}`);
  return { bundle, blockNum, groupId, memberUids: uids, raw };
}

export function compactBytesToPayload(bytes) { return bytesHex(bytes); }
export function compactPayloadToBytes(payload) { return hexBytes(payload); }
export function isEvidenceCompactBytes(bytes) { return bytes instanceof Uint8Array && bytes.length >= 4 && EVIDENCE_COMPACT_MAGIC.every((b, i) => bytes[i] === b); }
export function isEvidenceCompactPayload(payload) { try { return typeof payload === 'string' && isEvidenceCompactBytes(hexBytes(payload)); } catch { return false; } }
export function decodeSubmissionPayloadString(payload) {
  if (!isEvidenceCompactPayload(payload)) throw new Error('production submission must use evidence-compact-v1');
  return decodeEvidenceCompactV1(compactPayloadToBytes(payload));
}
export function assertEvidenceWireLimit(bytes) { if (bytes.length >= EVIDENCE_MAX_WIRE_BYTES) throw new Error(`Evidence compact payload must be < ${EVIDENCE_MAX_WIRE_BYTES} bytes`); }

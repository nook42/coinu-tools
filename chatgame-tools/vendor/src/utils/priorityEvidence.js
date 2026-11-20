import { keccak256, toHex } from 'viem';
import {
  buildMsgKeyGetter, canonicalComparatorV2, chatSignStringV2, compareHexAsc,
  computeChatHashV2, isCanonicalActionPreimage, isCanonicalSignature,
  msgRefOf, parseBlockAddress, readReceiptSignString, receiptCoverClaim,
  receiptMaxRefsPerReceipt, buildRealTargets, computeMsgKeyV2, clientShownOtherMessageKeys,
  isReceiptTimely, isMsgRef,
} from '../../workers/game_workers/lib/protocol-v2.js';
import {
  countHalfWidthChars, countVisibleChars, hasVisibleContent, GUEST_PINNED_RULES,
  PRIORITY_OWN_MESSAGES_MAX,
} from '../../workers/game_workers/lib/char-counter.js';
import { actionSnapshotPreimage, receiptCanonCmp } from '../../workers/game_workers/lib/game-result-calculator.js';
import {
  aggregateSelfReceipts, decodeEvidenceCompactV1, encodeEvidenceCompactV1,
} from '../../workers/game_workers/lib/evidence-compact-v1.js';
import { validateSubmissionStructure } from '../../workers/game_workers/lib/submission-limits.js';
import { evaluatePriorityGuarantee, priorityTurnGuarantee } from '../../workers/game_workers/lib/priority-fields.js';

export const PRIORITY_PLAN_WORK_LIMIT = 160_000;
export const PRIORITY_PLAN_TOTAL_WORK_LIMIT = 480_000;
export const PRESIGN_PLACEHOLDER_SIGNATURE = `0x${'0'.repeat(128)}1b`;
const BACKDATED_INPUT_SIGNATURE = `0x${'0'.repeat(63)}1${'0'.repeat(63)}11b`;
const SKIP_WEIGHT = 16;
const DP_PARETO_LIMIT = 64;
const messageFactCache = new WeakMap();

// 表示の隠す集合＝上限の外（D2′）−一度画面に出した他人の発言の記憶（S3R4-U-OVERCAP-MEM）。
export function displayHiddenMessageKeys(hidden, shown) {
  if (!(hidden instanceof Set) || !(shown instanceof Set) || shown.size === 0) return hidden;
  return new Set([...hidden].filter((key) => !shown.has(key)));
}

function messageFacts(m, blockNum, groupId) {
  const previous = messageFactCache.get(m);
  if (previous && previous.blockNum === blockNum && previous.groupId === groupId
    && previous.uid === m.uid && previous.text === m.text && previous.timestamp === m.timestamp) return previous;
  const text = typeof m.text === 'string' ? m.text : '';
  const facts = { blockNum, groupId, uid: m.uid, text: m.text, timestamp: m.timestamp,
    key: computeMsgKeyV2(blockNum, groupId, m), half: countHalfWidthChars(text),
    visible: countVisibleChars(text), hasVisible: hasVisibleContent(text) };
  messageFactCache.set(m, facts);
  return facts;
}

export function separatorPoint(nowMs, closeAt) {
  if (!Number.isSafeInteger(nowMs)) return { separatorAtMs: null, separatorClosed: false };
  if (Number.isSafeInteger(closeAt) && nowMs >= closeAt)
    return { separatorAtMs: closeAt, separatorClosed: true };
  return { separatorAtMs: nowMs, separatorClosed: false };
}

export function planReceiptSignatures(plan) {
  const signatures = new Set();
  for (const name of ['eLegacy', 'eSelfReceipts', 'separatorReaders']) {
    for (const rc of (Array.isArray(plan?.[name]) ? plan[name] : [])) {
      if (typeof rc?.signature === 'string' && rc.signature !== BACKDATED_INPUT_SIGNATURE)
        signatures.add(rc.signature);
    }
  }
  return [...signatures].sort();
}

const immutableEmptySet = new Set();
for (const name of ['add', 'delete', 'clear']) {
  Object.defineProperty(immutableEmptySet, name, { value() { throw new TypeError('empty priority keys are immutable'); } });
}
Object.freeze(immutableEmptySet);
const emptyArray = Object.freeze([]);
export const EMPTY_PRIORITY_PLAN = Object.freeze({
  E: emptyArray, heads: emptyArray, seps: emptyArray, selfSeps: emptyArray,
  eLegacy: emptyArray, eSelfReceipts: emptyArray, eSelfBackdated: emptyArray,
  separatorReaders: emptyArray, pinned: emptyArray,
  eKeys: immutableEmptySet, turns: 0, stats: Object.freeze({ work: 0, exhausted: false,
    candidate: null, candidates: emptyArray, backdated: 0, totalWork: 0, totalExhausted: false }),
});

export function shownTurnCount(guarantee, localTurns, minMessages) {
  const min = GUEST_PINNED_RULES.minMessages;
  const g = Number.isSafeInteger(guarantee) && guarantee > 0 ? guarantee : 0;
  if (g < min) return g;
  const local = Number.isSafeInteger(localTurns) && localTurns > 0 ? localTurns : 0;
  return Math.max(g, local);
}

const validWindow = (w) => Number.isSafeInteger(w?.startMs)
  && Number.isSafeInteger(w?.endMs) && w.startMs <= w.endMs;
const ascendingSignature = (a, b) => {
  const x = String(a?.signature ?? '').toLowerCase();
  const y = String(b?.signature ?? '').toLowerCase();
  return x < y ? -1 : x > y ? 1 : 0;
};
const receiptOrder = (a, b) => a.msgRefs.length - b.msgRefs.length
  || a.timestamp - b.timestamp || receiptCanonCmp(a, b) || ascendingSignature(a, b);
const itemIdentity = (kind, item, blockNum, groupId) => {
  const message = kind === 'message'
    ? chatSignStringV2(blockNum, groupId, item.uid, item.text, item.timestamp)
    : readReceiptSignString(blockNum, groupId, item.receiverUid, item.senderUid, item.msgRefs, item.timestamp);
  return JSON.stringify([kind, message, item.signature]);
};
const legacyShape = (rc) => ({ receiverUid: rc.receiverUid, senderUid: rc.senderUid,
  msgRefs: [...rc.msgRefs], timestamp: rc.timestamp, signature: rc.signature });
const toCanonicalChat = (m, blockNum, groupId) => ({
  type: 'chat', blockNum: Number(blockNum), groupId: Number(groupId),
  uid: m.uid, text: m.text, timestamp: m.timestamp, signature: m.signature,
});

// Pass the same blockNum and groupId to preverifyCandidates, carriedMessages, attachPriority, and checkPriority.
// With E, carried/normal and priority.messages are new canonical values; match them by msgKey, not object identity.

export function priorityReady({ rosterConfirmed, members, myUid, chatWindow, canSignSelf } = {}) {
  try {
    if (rosterConfirmed !== true || canSignSelf !== true || !validWindow(chatWindow)
      || !Array.isArray(members) || members.length < 1 || members.length > 5) return false;
    const uids = members.map((member) => member?.uid);
    return uids.every((uid) => typeof uid === 'string')
      && new Set(uids).size === uids.length && uids.includes(myUid)
      && members.every((member) => typeof parseBlockAddress(member.bAddr)?.address === 'string');
  } catch { return false; }
}

export function planPriorityContext(input = {}) {
  const { messages, receipts, myUid, members, blockNum, groupId, chatWindow,
    hiddenMessageKeys = null, shownMessageKeys = null, separatorAtMs = null, separatorClosed = false,
    acceptItem = () => true } = input || {};
  if (!validWindow(chatWindow) || !Array.isArray(members) || !Array.isArray(messages)
    || !Array.isArray(receipts) || typeof myUid !== 'string') return EMPTY_PRIORITY_PLAN;
  const memberUids = members.map((member) => member?.uid);
  if (memberUids.some((uid) => typeof uid !== 'string') || !memberUids.includes(myUid)) return EMPTY_PRIORITY_PLAN;
  const memberSet = new Set(memberUids);
  const key = (m) => messageFacts(m, blockNum, groupId).key;
  const cmp = canonicalComparatorV2(key);
  const safeAccept = (kind, item) => { try { return acceptItem(kind, item) !== false; } catch { return false; } };
  const candidates = [];
  for (const m of messages) {
    try {
      if (m && memberSet.has(m.uid) && Number.isSafeInteger(m.timestamp)
        && m.timestamp >= chatWindow.startMs && m.timestamp <= chatWindow.endMs
        && typeof m.text === 'string' && isCanonicalSignature(m.signature)
        && messageFacts(m, blockNum, groupId).half <= GUEST_PINNED_RULES.maxMsgChars
        && safeAccept('message', m)) candidates.push(m);
    } catch { /* malformed candidate */ }
  }
  candidates.sort((a, b) => cmp(a, b) || ascendingSignature(a, b));
  const byKey = new Map();
  for (const m of candidates) {
    try { if (!byKey.has(key(m))) byKey.set(key(m), m); } catch { /* malformed candidate */ }
  }
  const W = [...byKey.values()];
  const refIndex = new Map(W.map((m) => [`${m.uid}|${msgRefOf(key(m))}`, m]));
  const hidden = hiddenMessageKeys instanceof Set ? hiddenMessageKeys : null;
  const shown = shownMessageKeys instanceof Set ? shownMessageKeys : null;
  const P = W.filter((m) => messageFacts(m, blockNum, groupId).hasVisible && (m.uid === myUid
    || !hidden?.has(key(m)) || shown?.has(key(m))));
  const Pfree = W.filter((m) => messageFacts(m, blockNum, groupId).hasVisible && (m.uid === myUid
    || !hidden?.has(key(m))));
  if (P.length === 0) return EMPTY_PRIORITY_PLAN;
  const targetOf = new Map(W.map((m) => [`r:${msgRefOf(key(m))}|${m.uid}`, m]));
  const targetsW = buildRealTargets({}, W, blockNum, groupId, key);
  const ownByKey = new Map();
  const legacyByKey = new Map();
  const seenReceipts = new Set();
  const closureIntern = new Map();
  for (const rc of receipts) {
    try {
      if (!rc || !Array.isArray(rc.msgRefs) || typeof rc.senderUid !== 'string'
        || !rc.msgRefs.every((ref, i) => typeof ref === 'string'
          && (i === 0 || compareHexAsc(rc.msgRefs[i - 1], ref) < 0))
        || !safeAccept('receipt', rc)) continue;
      const identity = itemIdentity('receipt', rc, blockNum, groupId);
      if (seenReceipts.has(identity)) continue;
      seenReceipts.add(identity);
      const claim = receiptCoverClaim(rc, targetsW, {
        memberUids, chatWindow,
        maxRefsPerReceipt: receiptMaxRefsPerReceipt(GUEST_PINNED_RULES.maxMessages),
        atomic: true, selfUid: myUid,
      });
      if (!claim.windowed || claim.targetKeys.length === 0) continue;
      const rawClosure = rc.msgRefs.map((ref) => refIndex.get(`${rc.senderUid}|${ref}`));
      const carriable = rawClosure.every(Boolean);
      const closureId = `${rc.senderUid}|${rc.msgRefs.join('|')}`;
      let closure = closureIntern.get(closureId);
      if (!closure) {
        closure = rawClosure;
        if (carriable) closureIntern.set(closureId, closure);
      }
      const index = rc.receiverUid === myUid ? ownByKey : legacyByKey;
      if (rc.receiverUid !== myUid && !carriable) continue;
      if (rc.receiverUid !== myUid && closure.some((m) => m.uid !== myUid && hidden?.has(key(m)))) continue;
      for (const targetKey of claim.targetKeys) {
        const m = targetOf.get(targetKey);
        if (!m) continue;
        const k = key(m);
        const arr = index.get(k) || [];
        arr.push({ rc, closure: carriable && rc.receiverUid !== myUid ? closure : null, identity });
        index.set(k, arr);
      }
    } catch { /* malformed candidate */ }
  }
  for (const arr of ownByKey.values()) arr.sort((a, b) => a.rc.timestamp - b.rc.timestamp
    || receiptCanonCmp(a.rc, b.rc) || ascendingSignature(a.rc, b.rc));
  for (const arr of legacyByKey.values()) arr.sort((a, b) => receiptOrder(a.rc, b.rc));
  const runsOf = (list) => {
    const out = [];
    for (let i = 0; i < list.length; i++) {
      if (list[i].uid !== myUid) continue;
      if (i > 0 && list[i - 1].uid === myUid) out[out.length - 1].push(i);
      else out.push([i]);
    }
    return out;
  };
  const runs = runsOf(P);
  const freeRuns = runsOf(Pfree);
  const shownPool = (memory) => clientShownOtherMessageKeys(messages, receipts, {
    blockNum, groupId, myUid, chatWindow, hiddenMessageKeys: hidden,
    shownMessageKeys: memory, atMs: separatorAtMs, closed: separatorClosed,
    getClientMsgKey: key,
  });
  const freeSet = new Set(Pfree.map(key));
  const memSet = new Set(P.map(key));
  const Sfree = new Set([...shownPool(null)].filter((k) => freeSet.has(k)));
  const Smem = shown instanceof Set
    ? new Set([...shownPool(shown)].filter((k) => memSet.has(k))) : Sfree;
  return { messages, receipts, myUid, members, blockNum, groupId, chatWindow,
    hidden, shown, separatorAtMs, separatorClosed, W, P, Pfree, byKey, key, cmp,
    ownByKey, legacyByKey, runs, freeRuns, Sfree, Smem };
}

function headSelection(ctx) {
  const { Pfree: P, ownByKey, legacyByKey, key, byKey, cmp, blockNum, groupId, myUid,
    freeRuns: runs } = ctx;
  const heads = [], seps = [], selfSeps = [], legacy = new Map(), selfReceipts = new Map();
  const choices = [];
  const pinned = new Map(), eKeys = new Set(), budget = new Map();
  let work = 0, exhausted = false, lastHeadPos = -1, pinVer = 0;
  const coverCache = new Map();
  const coverAgg = (c) => {
    let a = coverCache.get(c.closure);
    if (!a) {
      a = { ver: -1, count: 0, chars: 0, keys: new Set(c.closure.map(key)),
        uid: c.rc.senderUid, uniform: c.closure.every((m) => m.uid === c.rc.senderUid) };
      coverCache.set(c.closure, a);
    }
    if (a.ver !== pinVer) {
      a.count = 0; a.chars = 0;
      for (const m of c.closure) if (!pinned.has(key(m))) {
        a.count++; a.chars += messageFacts(m, blockNum, groupId).half;
      }
      a.ver = pinVer;
    }
    return a;
  };
  const partDelta = (m, c) => {
    if (!m) return null;
    let count = 0, chars = 0;
    if (c?.closure) {
      const a = coverAgg(c);
      if (!a.uniform || a.uid !== m.uid) return null;
      count = a.count; chars = a.chars;
      if (!a.keys.has(key(m)) && !pinned.has(key(m))) {
        count++; chars += messageFacts(m, blockNum, groupId).half;
      }
    } else if (!pinned.has(key(m))) {
      count = 1; chars = messageFacts(m, blockNum, groupId).half;
    }
    return { uid: m.uid, count, chars };
  };
  const within = (uid, d) => {
    const b = budget.get(uid) || { count: 0, chars: 0 };
    return b.count + d.count <= GUEST_PINNED_RULES.maxMessages
      && b.chars + d.chars <= GUEST_PINNED_RULES.maxChars;
  };
  const fits = (items) => {
    if (++work >= PRIORITY_PLAN_WORK_LIMIT) { exhausted = true; return false; }
    const delta = new Map();
    const parts = Array.isArray(items) ? null : items.parts;
    if (parts) {
      for (const d of parts) if (d) delta.set(d.uid, d);
    } else {
      const added = new Map();
      for (const m of items) if (!pinned.has(key(m))) added.set(key(m), m);
      for (const m of added.values()) {
        const b = delta.get(m.uid) || { count: 0, chars: 0 };
        b.count++; b.chars += messageFacts(m, blockNum, groupId).half; delta.set(m.uid, b);
      }
    }
    return [...delta].every(([uid, d]) => within(uid, d));
  };
  const fitsParts = (x, cx, h, ch, items) => {
    const dx = partDelta(x, cx), dh = partDelta(h, ch);
    if ((x && !dx) || (h && !dh) || (dx && dh && dx.uid === dh.uid)) return fits(items());
    return fits({ parts: [dx, dh] });
  };
  for (const run of runs) {
    if (exhausted || heads.length >= Math.min(PRIORITY_OWN_MESSAGES_MAX, GUEST_PINNED_RULES.minMessages)) break;
    if (!run.some((hi) => legacyByKey.get(key(P[hi]))?.length)) continue;
    const sepOptions = heads.length === 0 ? [null] : [];
    if (heads.length > 0) for (let i = run[0] - 1; i > lastHeadPos; i--) {
      if (P[i].uid !== myUid) sepOptions.push(i);
    }
    let choice = null;
    outer: for (const xi of sepOptions) {
      const x = xi === null ? null : P[xi];
      const xKey = x && key(x);
      const coversX = x ? [
        ...(ownByKey.get(xKey)?.length ? [ownByKey.get(xKey)[0]] : []),
        ...(legacyByKey.get(xKey) || []),
      ] : [null];
      for (const cx of coversX) {
        const Ux = () => x ? [x, ...(cx.closure || [])] : [];
        if (!fitsParts(x, cx, null, null, Ux)) { if (exhausted) break outer; continue; }
        const headsInRun = [...run].sort((a, b) => messageFacts(P[b], blockNum, groupId).visible
          - messageFacts(P[a], blockNum, groupId).visible || a - b);
        for (const hi of headsInRun) {
          const h = P[hi];
          for (const ch of legacyByKey.get(key(h)) || []) {
            const U = () => [...Ux(), h, ...ch.closure];
            if (fitsParts(x, cx, h, ch, U)) { choice = { x, cx, h, ch, hi, U: U() }; break outer; }
            if (exhausted) break outer;
          }
        }
      }
    }
    if (!choice) continue;
    choices.push(choice);
    if (choice.x) {
      seps.push(choice.x); eKeys.add(key(choice.x));
      if (choice.cx.rc.receiverUid === myUid) {
        selfSeps.push(choice.x); selfReceipts.set(choice.cx.identity, choice.cx.rc);
      } else legacy.set(choice.cx.identity, choice.cx.rc);
    }
    heads.push(choice.h); eKeys.add(key(choice.h));
    legacy.set(choice.ch.identity, choice.ch.rc);
    for (const m of choice.U) if (!pinned.has(key(m))) {
      pinned.set(key(m), m);
      const b = budget.get(m.uid) || { count: 0, chars: 0 };
      b.count++; b.chars += messageFacts(m, blockNum, groupId).half; budget.set(m.uid, b);
    }
    pinVer++;
    lastHeadPos = choice.hi;
  }
  const E = [...eKeys].map((k) => byKey.get(k)).sort(cmp);
  const eLegacy = [...legacy.values()].sort((a, b) => receiptCanonCmp(a, b) || ascendingSignature(a, b));
  if (eLegacy.length + Number(selfSeps.length > 0) > 40) throw new Error('priority receipt construction exceeds 40');
  const turns = priorityTurnGuarantee({ messages: E }, {
    ownerUid: myUid, blockNum, groupId, minMessages: GUEST_PINNED_RULES.minMessages,
  });
  if (turns !== heads.length) throw new Error('priority heads disagree with turn guarantee');
  return { E, heads, seps, selfSeps, eLegacy, eSelfReceipts: [...selfReceipts.values()],
    pinned: [...pinned.values()].sort(cmp), eKeys, turns, stats: { work, exhausted }, choices };
}

const workOf = (units) => Math.ceil(units / SKIP_WEIGHT);
const planGoal = () => Math.min(PRIORITY_OWN_MESSAGES_MAX, GUEST_PINNED_RULES.minMessages);

function consumeWork(clock, run, weight = SKIP_WEIGHT) {
  if (clock.units >= PRIORITY_PLAN_TOTAL_WORK_LIMIT * SKIP_WEIGHT || run.exhausted) return false;
  if (clock.units + weight > PRIORITY_PLAN_TOTAL_WORK_LIMIT * SKIP_WEIGHT
      || run.units + weight > PRIORITY_PLAN_WORK_LIMIT * SKIP_WEIGHT) {
    if (clock.units + weight > PRIORITY_PLAN_TOTAL_WORK_LIMIT * SKIP_WEIGHT) clock.exhausted = true;
    run.exhausted = true;
    return false;
  }
  run.units += weight; run.scanned++;
  clock.units += weight;
  if (clock.units >= PRIORITY_PLAN_TOTAL_WORK_LIMIT * SKIP_WEIGHT) clock.exhausted = true;
  if (run.units >= PRIORITY_PLAN_WORK_LIMIT * SKIP_WEIGHT || clock.exhausted) {
    run.exhausted = true;
    return false;
  }
  return true;
}

function metricCompare(a, b) {
  if (a.tightChars !== b.tightChars) return a.tightChars - b.tightChars;
  if (a.allChars !== b.allChars) return a.allChars - b.allChars;
  const n = Math.min(a.gaps.length, b.gaps.length);
  for (let i = 0; i < n; i++) {
    if (a.gaps[i][0] !== b.gaps[i][0]) return a.gaps[i][0] - b.gaps[i][0];
    if (a.gaps[i][1] !== b.gaps[i][1]) return a.gaps[i][1] - b.gaps[i][1];
  }
  if (a.gaps.length !== b.gaps.length) return a.gaps.length - b.gaps.length;
  const length = Math.min(a.path.length, b.path.length);
  for (let i = 0; i < length; i++) {
    if (a.path[i].ri !== b.path[i].ri) return a.path[i].ri - b.path[i].ri;
    const ax = a.path[i].xi ?? -1;
    const bx = b.path[i].xi ?? -1;
    if (ax !== bx) return ax - bx;
  }
  return a.path.length - b.path.length;
}

function dpRoute(ctx, P, S, runs, tight, clock, run) {
  const { key, legacyByKey, blockNum, groupId } = ctx;
  const R = runs.map((r, ri) => ({ r, ri })).filter(({ r }) =>
    r.some((hi) => legacyByKey.get(key(P[hi]))?.length));
  const ti = new Map(tight.map((uid, i) => [uid, i]));
  const dom = (a, b) => a.every((x, i) => x <= b[i]);
  const dp = R.map(() => []);
  for (let b = 0; b < R.length; b++) dp[b][1] = [{ v: new Array(tight.length * 2).fill(0),
    tightChars: 0, allChars: 0, gaps: [], path: [{ ri: R[b].ri, xi: null }] }];
  for (let a = 0; a < R.length && !run.exhausted; a++) {
    let scan = R[a].r[R[a].r.length - 1] + 1;
    let free = null;
    const cheapest = new Map();
    for (let b = a + 1; b < R.length && !run.exhausted; b++) {
      for (; scan < R[b].r[0]; scan++) {
        const m = P[scan];
        if (m.uid === ctx.myUid || !S.has(key(m))) continue;
        const chars = messageFacts(m, blockNum, groupId).half;
        const better = (old) => old === null || chars < messageFacts(P[old], blockNum, groupId).half
          || (chars === messageFacts(P[old], blockNum, groupId).half && scan > old);
        if (!ti.has(m.uid)) { if (better(free)) free = scan; }
        else { const old = cheapest.get(m.uid) ?? null; if (better(old)) cheapest.set(m.uid, scan); }
      }
      const opts = [...(free === null ? [] : [[free, null]]),
        ...[...cheapest].map(([uid, xi]) => [xi, ti.get(uid)])];
      for (let k = 1; k < planGoal() && !run.exhausted; k++) {
        for (const e of dp[a][k] || []) for (const [xi, t] of opts) {
          if (!consumeWork(clock, run)) break;
          const chars = messageFacts(P[xi], blockNum, groupId).half;
          const v = [...e.v];
          if (t !== null) { v[2 * t]++; v[2 * t + 1] += chars; }
          if (t !== null && (v[2 * t] > GUEST_PINNED_RULES.maxMessages
            || v[2 * t + 1] > GUEST_PINNED_RULES.maxChars)) continue;
          const next = { v, tightChars: e.tightChars + (t === null ? 0 : chars),
            allChars: e.allChars + chars, gaps: [...e.gaps, [chars, -xi]],
            path: [...e.path, { ri: R[b].ri, xi }] };
          const set = dp[b][k + 1] || (dp[b][k + 1] = []);
          if (set.some((other) => dom(other.v, v) && metricCompare(other, next) <= 0)) continue;
          for (let i = set.length - 1; i >= 0; i--)
            if (dom(v, set[i].v) && metricCompare(next, set[i]) <= 0) set.splice(i, 1);
          set.push(next);
          // A bounded frontier also bounds both linear dominance scans per transition.
          // A full frontier exhausts only this DP run; poolPlan tries its greedy routes.
          if (set.length > DP_PARETO_LIMIT) { run.exhausted = true; break; }
        }
      }
    }
  }
  if (run.exhausted) return null;
  let best = null;
  for (const row of dp) for (let k = 1; k <= planGoal(); k++) for (const e of row[k] || []) {
    if (!best || e.path.length > best.path.length
      || (e.path.length === best.path.length && metricCompare(e, best) < 0)) best = e;
  }
  return best?.path || [];
}

function poolSelection(ctx, P, S, runSpec, clock, route = null) {
  const { key, legacyByKey, blockNum, groupId, myUid } = ctx;
  const runs = P === ctx.Pfree ? ctx.freeRuns : ctx.runs;
  const choices = [], pinned = new Map(), budget = new Map(), coverCache = new Map();
  let pinVer = 0, lastHeadPos = -1;
  const half = (m) => messageFacts(m, blockNum, groupId).half;
  const within = (uid, count, chars) => {
    const b = budget.get(uid) || { count: 0, chars: 0 };
    return b.count + count <= GUEST_PINNED_RULES.maxMessages
      && b.chars + chars <= GUEST_PINNED_RULES.maxChars;
  };
  const partHead = (h, c) => {
    let a = coverCache.get(c);
    if (!a) {
      a = { ver: -1, keys: new Set(c.closure.map(key)), uid: c.rc.senderUid,
        uniform: c.closure.every((m) => m.uid === c.rc.senderUid), count: 0, chars: 0 };
      coverCache.set(c, a);
    }
    if (!a.uniform || a.uid !== h.uid) return null;
    if (a.ver !== pinVer) {
      a.count = 0; a.chars = 0;
      for (const m of c.closure) if (!pinned.has(key(m))) { a.count++; a.chars += half(m); }
      a.ver = pinVer;
    }
    const add = !a.keys.has(key(h)) && !pinned.has(key(h));
    return { uid: h.uid, count: a.count + Number(add), chars: a.chars + (add ? half(h) : 0) };
  };
  const tryFit = (items, parts) => {
    if (!consumeWork(clock, runSpec)) return false;
    if (parts && parts.every(Boolean) && new Set(parts.map((p) => p.uid)).size === parts.length)
      return parts.every((p) => within(p.uid, p.count, p.chars));
    const added = new Map();
    for (const m of items) if (!pinned.has(key(m))) added.set(key(m), m);
    const delta = new Map();
    for (const m of added.values()) {
      const d = delta.get(m.uid) || { count: 0, chars: 0 };
      d.count++; d.chars += half(m); delta.set(m.uid, d);
    }
    return [...delta].every(([uid, d]) => within(uid, d.count, d.chars));
  };
  const routeMap = route && new Map(route.map(({ ri, xi }) => [ri, xi]));
  for (let ri = 0; ri < runs.length && !runSpec.exhausted; ri++) {
    if (choices.length >= planGoal()) break;
    if (routeMap && !routeMap.has(ri)) continue;
    const run = runs[ri];
    if (!run.some((hi) => legacyByKey.get(key(P[hi]))?.length)) continue;
    const options = choices.length === 0 ? [null] : [];
    if (choices.length && (!routeMap || routeMap.get(ri) !== null)) {
      for (let i = run[0] - 1; i > lastHeadPos; i--)
        if (P[i].uid !== myUid && S.has(key(P[i]))) options.push(i);
      if (routeMap) options.splice(0, options.length, routeMap.get(ri));
      else if (runSpec.mode !== 'greedy-nearest') options.sort((a, b) => half(P[a]) - half(P[b]) || b - a);
    }
    let choice = null;
    outer: for (const xi of options) {
      const x = xi === null ? null : P[xi];
      const dx = x && !pinned.has(key(x)) ? { uid: x.uid, count: 1, chars: half(x) } : null;
      if (x && runSpec.mode.startsWith('greedy-') && dx && !within(dx.uid, dx.count, dx.chars)) {
        consumeWork(clock, runSpec, 1);
        continue;
      }
      if (!tryFit(x ? [x] : [], dx ? [dx] : [])) { if (runSpec.exhausted) break; continue; }
      const headsInRun = [...run].sort((a, b) => messageFacts(P[b], blockNum, groupId).visible
        - messageFacts(P[a], blockNum, groupId).visible || a - b);
      for (const hi of headsInRun) {
        const h = P[hi];
        for (const ch of legacyByKey.get(key(h)) || []) {
          const dh = partHead(h, ch);
          const U = [...(x ? [x] : []), h, ...ch.closure];
          if (tryFit(U, [dx, dh])) { choice = { x, h, ch, hi, xi }; break outer; }
          if (runSpec.exhausted) break outer;
        }
      }
    }
    if (!choice) continue;
    choices.push(choice);
    for (const m of [...(choice.x ? [choice.x] : []), choice.h, ...choice.ch.closure])
      if (!pinned.has(key(m))) {
        pinned.set(key(m), m);
        const b = budget.get(m.uid) || { count: 0, chars: 0 };
        b.count++; b.chars += half(m); budget.set(m.uid, b);
      }
    lastHeadPos = choice.hi;
    pinVer++;
  }
  return choices;
}

function poolPlan(ctx, P, S, name, clock) {
  const totals = new Map();
  for (const m of P) if (m.uid !== ctx.myUid && S.has(ctx.key(m))) {
    const b = totals.get(m.uid) || { count: 0, chars: 0 };
    b.count++; b.chars += messageFacts(m, ctx.blockNum, ctx.groupId).half; totals.set(m.uid, b);
  }
  const tight = [...totals].filter(([, b]) => b.count > GUEST_PINNED_RULES.maxMessages
    || b.chars > GUEST_PINNED_RULES.maxChars).map(([uid]) => uid).sort();
  const runs = [];
  const makeRun = (mode) => ({ mode, units: 0, scanned: 0, exhausted: false });
  const finishRun = (r) => { runs.push({ mode: r.mode, work: workOf(r.units), scanned: r.scanned,
    exhausted: r.exhausted }); };
  let chosen = [], mode = 'exact', exhausted = false, dpExhausted = null, selectedWork = 0;
  if (!tight.length) {
    const r = makeRun('exact');
    chosen = poolSelection(ctx, P, S, r, clock); finishRun(r);
    selectedWork = workOf(r.units); exhausted = r.exhausted;
  } else {
    const r = makeRun('dp');
    const path = dpRoute(ctx, P, S, P === ctx.Pfree ? ctx.freeRuns : ctx.runs, tight, clock, r);
    if (path && !r.exhausted) chosen = poolSelection(ctx, P, S, r, clock, path);
    dpExhausted = r.exhausted || (path && chosen.length !== path.length);
    if (dpExhausted) r.exhausted = true;
    finishRun(r);
    if (!dpExhausted) { mode = 'dp'; selectedWork = workOf(r.units); }
    else {
      chosen = [];
      for (const greedyMode of ['greedy-nearest', 'greedy-minchar']) {
        if (clock.exhausted) break;
        const g = makeRun(greedyMode);
        const plan = poolSelection(ctx, P, S, g, clock); finishRun(g);
        if (plan.length > chosen.length) {
          chosen = plan; mode = greedyMode; exhausted = g.exhausted; selectedWork = workOf(g.units);
        }
      }
    }
  }
  return { name, mode, choices: chosen, work: runs.reduce((n, r) => n + r.work, 0),
    selectedWork, scanned: runs.reduce((n, r) => n + r.scanned, 0), exhausted,
    dpExhausted, runs, rejected: null };
}

function materializeCandidate(ctx, candidate) {
  const { choices } = candidate;
  const { key, byKey, cmp, blockNum, groupId, myUid, ownByKey, legacyByKey } = ctx;
  const heads = choices.map(({ h }) => h);
  const seps = choices.filter(({ x }) => x).map(({ x }) => x);
  const eKeys = new Set([...heads, ...seps].map(key));
  const E = [...eKeys].map((k) => byKey.get(k)).sort(cmp);
  const legacy = new Map(), self = new Map(), readers = new Map(), pinned = new Map();
  const backdated = [];
  for (const choice of choices) {
    legacy.set(choice.ch.identity, choice.ch.rc);
    for (const m of [choice.h, ...choice.ch.closure, ...(choice.x ? [choice.x] : [])])
      pinned.set(key(m), m);
    if (!choice.x) continue;
    const k = key(choice.x);
    const own = ownByKey.get(k)?.[0];
    if (own) self.set(own.identity, own.rc);
    else backdated.push({ senderUid: choice.x.uid, msgRef: msgRefOf(k), timestamp: choice.x.timestamp });
    const reader = legacyByKey.get(k)?.[0];
    if (reader) readers.set(reader.identity, reader.rc);
  }
  const eLegacy = [...legacy.values()].sort((a, b) => receiptCanonCmp(a, b) || ascendingSignature(a, b));
  const turns = priorityTurnGuarantee({ messages: E }, {
    ownerUid: myUid, blockNum, groupId, minMessages: GUEST_PINNED_RULES.minMessages,
  });
  const invalid = eLegacy.length + Number(seps.length > 0) > 40
    ? 'priority receipt construction exceeds 40'
    : turns !== heads.length ? 'priority heads disagree with turn guarantee' : null;
  if (invalid && candidate.name === 'head') throw new Error(invalid);
  candidate.rejected = candidate.rejected || invalid;
  candidate.turns = invalid ? 0 : turns;
  candidate.headKeys = heads.map(key);
  candidate.sepKeys = seps.map(key);
  if (candidate.rejected) return null;
  return { E, heads, seps, selfSeps: seps, eLegacy,
    eSelfReceipts: [...self.values()], eSelfBackdated: backdated,
    separatorReaders: [...readers.values()], pinned: [...pinned.values()].sort(cmp),
    eKeys, turns };
}

export function planPriority(input = {}) {
  const ctx = planPriorityContext(input);
  if (ctx === EMPTY_PRIORITY_PLAN) return EMPTY_PRIORITY_PLAN;
  const { separatorAtMs, key, Sfree, Smem } = ctx;
  const clock = { units: 0, exhausted: false };
  const raw = headSelection(ctx);
  clock.units += raw.stats.work * SKIP_WEIGHT;
  if (clock.units >= PRIORITY_PLAN_TOTAL_WORK_LIMIT * SKIP_WEIGHT) clock.exhausted = true;
  let aChoices = raw.choices, aMode = 'head', aRejected = null;
  const outside = aChoices.findIndex((choice) => choice.x && !Sfree.has(key(choice.x)));
  if (outside >= 0) {
    if (Number.isSafeInteger(separatorAtMs) && aChoices.slice(outside)
      .filter((choice) => choice.x && !Sfree.has(key(choice.x)))
      .every((choice) => choice.x.timestamp >= separatorAtMs)) {
      aChoices = aChoices.slice(0, outside); aMode = 'head-prefix';
    } else { aChoices = []; aRejected = 'separator-outside-pool'; }
  }
  const a = { name: 'head', mode: aMode, choices: aChoices, work: raw.stats.work,
    selectedWork: raw.stats.work, scanned: raw.stats.work, exhausted: raw.stats.exhausted,
    dpExhausted: null, runs: [{ mode: 'head', work: raw.stats.work,
      scanned: raw.stats.work, exhausted: raw.stats.exhausted }], rejected: aRejected,
    coverSigs: [...new Set([...raw.eLegacy, ...raw.eSelfReceipts].map((r) => r.signature))].sort(),
    pinnedKeys: raw.pinned.map(key) };
  const candidates = [a];
  const plans = new Map();
  plans.set(a, materializeCandidate(ctx, a));
  if (!clock.exhausted) {
    const f = poolPlan(ctx, ctx.Pfree, Sfree, 'free', clock);
    candidates.push(f); plans.set(f, materializeCandidate(ctx, f));
  }
  const samePool = ctx.P.length === ctx.Pfree.length
    && ctx.P.every((m, i) => key(m) === key(ctx.Pfree[i]))
    && Smem.size === Sfree.size && [...Smem].every((k) => Sfree.has(k));
  if (!clock.exhausted && !samePool) {
    const m = poolPlan(ctx, ctx.P, Smem, 'memory', clock);
    candidates.push(m); plans.set(m, materializeCandidate(ctx, m));
  }
  const order = { free: 0, memory: 1, head: 2 };
  const winner = candidates.filter((c) => plans.get(c)).sort((x, y) =>
    y.turns - x.turns || order[x.name] - order[y.name])[0];
  if (!winner || !winner.turns) return EMPTY_PRIORITY_PLAN;
  const plan = plans.get(winner);
  return { ...plan, stats: { work: winner.selectedWork, exhausted: winner.exhausted,
    candidate: winner.name, candidates: candidates.map(({ choices, selectedWork, ...c }) => c),
    backdated: plan.eSelfBackdated.length, totalWork: workOf(clock.units),
    totalExhausted: clock.exhausted } };
}


export async function preverifyCandidates(input, { members, verify, maxRounds = 4, cache = new Map() } = {}) {
  const rejected = new Set();
  const addressOf = new Map((members || []).map((m) => [m.uid, parseBlockAddress(m.bAddr)?.address]));
  let verified = 0;
  for (let rounds = 1; rounds <= maxRounds; rounds++) {
    const plan = planPriority({ ...input, acceptItem: (kind, item) => {
      try { return input.acceptItem?.(kind, item) !== false
        && !rejected.has(itemIdentity(kind, item, input.blockNum, input.groupId)); }
      catch { return false; }
    } });
    if (plan.E.length === 0) return { plan, rejected, rounds, verified };
    const bad = [];
    for (const [kind, item] of [
      ...plan.E.map((m) => ['message', m]), ...plan.eLegacy.map((rc) => ['receipt', rc]),
    ]) {
      const address = addressOf.get(kind === 'message' ? item.uid : item.receiverUid);
      const identity = itemIdentity(kind, item, input.blockNum, input.groupId);
      const message = JSON.parse(identity)[1];
      const cacheKey = JSON.stringify([address, message, item.signature]);
      let ok = cache.get(cacheKey);
      if (ok === undefined) {
        try { ok = !!address && await verify({ address, message, signature: item.signature }); }
        catch { ok = false; }
        cache.set(cacheKey, ok); verified++;
      }
      if (!ok) bad.push(identity);
    }
    if (bad.length === 0) return { plan, rejected, rounds, verified };
    for (const identity of bad) rejected.add(identity);
  }
  return { plan: EMPTY_PRIORITY_PLAN, rejected, rounds: maxRounds, verified };
}

export function carriedMessages(cappedMessages, plan, { blockNum, groupId } = {}) {
  if (!plan?.E?.length) return { carried: cappedMessages, normal: cappedMessages };
  const key = buildMsgKeyGetter(blockNum, groupId);
  const cmp = canonicalComparatorV2(key);
  const pinnedKeys = new Set(plan.pinned.map(key));
  const all = new Map(plan.pinned.map((m) => [key(m), m]));
  for (const m of cappedMessages) if (!all.has(key(m))) all.set(key(m), m);
  const carried = [...all.values()].sort(cmp);
  const totals = new Map();
  for (const m of carried) {
    const b = totals.get(m.uid) || { count: 0, chars: 0 };
    b.count++; b.chars += countHalfWidthChars(m.text); totals.set(m.uid, b);
  }
  for (let i = carried.length - 1; i >= 0; i--) {
    const m = carried[i], b = totals.get(m.uid);
    if (b.count <= GUEST_PINNED_RULES.maxMessages && b.chars <= GUEST_PINNED_RULES.maxChars) continue;
    if (pinnedKeys.has(key(m))) continue;
    b.count--; b.chars -= countHalfWidthChars(m.text); carried.splice(i, 1);
  }
  if ([...totals.values()].some((b) => b.count > GUEST_PINNED_RULES.maxMessages
    || b.chars > GUEST_PINNED_RULES.maxChars)) throw new Error('pinned messages exceed sender budget');
  const canonicalCarried = carried.map((m) => toCanonicalChat(m, blockNum, groupId));
  return { carried: canonicalCarried, normal: canonicalCarried.filter((m) => !plan.eKeys.has(key(m))) };
}

export async function attachPriority(snapshot, plan, { myUid, blockNum, groupId, chatWindow, signSelf } = {}) {
  if (!plan?.E?.length) return snapshot;
  const messages = plan.E.map((m) => toCanonicalChat(m, blockNum, groupId));
  const seen = new Set();
  const receipts = plan.eLegacy.filter((rc) => {
    const id = itemIdentity('receipt', rc, blockNum, groupId);
    if (seen.has(id)) return false;
    seen.add(id); return true;
  }).map(legacyShape).sort((a, b) => receiptCanonCmp(a, b) || ascendingSignature(a, b));
  const priority = { messages, receipts };
  if (plan.selfSeps.length) {
    const backdated = (plan.eSelfBackdated || []).map(({ senderUid, msgRef, timestamp }) => ({
      receiverUid: myUid, senderUid, msgRefs: [msgRef], timestamp,
      signature: BACKDATED_INPUT_SIGNATURE,
    }));
    const result = await aggregateSelfReceipts([...plan.eSelfReceipts.map(legacyShape), ...backdated], myUid,
      blockNum, groupId, signSelf,
      buildRealTargets({}, plan.selfSeps, blockNum, groupId), chatWindow);
    if (!result.aggregate) throw new Error('priority self separator aggregate is missing');
    priority.selfReceiptAggregate = result.aggregate;
  }
  return { votes: snapshot.votes, reports: snapshot.reports, observed: snapshot.observed, priority };
}

export async function checkPriority(bundle, { blockNum, groupId, members, chatWindow, verify, expectedTurns } = {}) {
  const fail = (stage, reason) => ({ ok: false, value: 0, reason: `${stage}: ${reason}` });
  try {
    const memberUids = members.map((m) => m.uid);
    const shape = validateSubmissionStructure(bundle, { blockNum, groupId, memberUids });
    if (!shape.ok) return fail('structure', shape.reason);
    if (bundle.chatHash !== computeChatHashV2(bundle.messages, blockNum, groupId))
      return fail('chatHash', 'chathash_mismatch');
    const preimage = actionSnapshotPreimage(bundle.encryptedActions);
    if (!isCanonicalActionPreimage(preimage) || keccak256(toHex(preimage)) !== bundle.encryptedDataHash)
      return fail('snapshot', 'snapshot_mismatch');
    const bAddr = new Map(members.map((m) => [m.uid, parseBlockAddress(m.bAddr)]));
    const result = await evaluatePriorityGuarantee(bundle, {
      blockNum, groupId, memberUids, bAddrOf: (uid) => bAddr.get(uid), chatWindow, verify,
      minMessages: GUEST_PINNED_RULES.minMessages,
    });
    if (!result.ok) return fail('priority', result.reason);
    if (result.value !== expectedTurns) return fail('turns', `${result.value} != ${expectedTurns}`);
    const roundtrip = decodeEvidenceCompactV1(encodeEvidenceCompactV1(bundle,
      { blockNum, groupId, memberUids }), { blockNum, groupId, memberUids }).bundle;
    if (JSON.stringify(roundtrip.encryptedActions) !== JSON.stringify(bundle.encryptedActions)
      || JSON.stringify(roundtrip.messages) !== JSON.stringify(bundle.messages))
      return fail('codec', 'roundtrip differs');
    return { ok: true, value: result.value, reason: null };
  } catch (error) { return fail('exception', error?.message || String(error)); }
}

export const PRIORITY_LOCK_VERSION = 1;

const lockMessage = (m) => ({ uid: m.uid, text: m.text, timestamp: m.timestamp, signature: m.signature });
const lockReceipt = (rc) => legacyShape(rc);
const exactFields = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
const lockWindow = (w) => exactFields(w, ['startMs', 'endMs']) && validWindow(w);
const lockRosterHash = (value) => typeof value === 'string' && /^0x[0-9a-f]{64}$/.test(value);
const lockIdentity = (ctx) => Number.isSafeInteger(ctx?.blockNum) && ctx.blockNum >= 0
  && Number.isSafeInteger(ctx?.groupId) && ctx.groupId >= 0
  && typeof ctx?.myUid === 'string' && ctx.myUid.length > 0 && !ctx.myUid.includes('_')
  && lockRosterHash(ctx.rosterHash) && lockWindow(ctx.chatWindow)
  && Array.isArray(ctx.members) && ctx.members.length >= 3 && ctx.members.length <= 5
  && new Set(ctx.members.map((m) => m?.uid)).size === ctx.members.length
  && ctx.members.some((m) => m?.uid === ctx.myUid)
  && ctx.members.every((m) => typeof m?.uid === 'string'
    && typeof parseBlockAddress(m?.bAddr)?.address === 'string');

export function priorityLockStorageKey({ blockNum, groupId, uid, rosterHash, chatWindow } = {}) {
  try {
    if (!Number.isSafeInteger(blockNum) || blockNum < 0 || !Number.isSafeInteger(groupId) || groupId < 0
      || typeof uid !== 'string' || uid.length === 0 || uid.includes('_')
      || !lockRosterHash(rosterHash) || !lockWindow(chatWindow)) return null;
    return `priorityLock_v1_${blockNum}_${groupId}_${uid}_${rosterHash}_${chatWindow.startMs}_${chatWindow.endMs}`;
  } catch { return null; }
}

export function priorityLockFromPlan(plan, ctx) {
  try {
    if (!lockIdentity(ctx) || !plan || plan.failed || plan.turns !== planGoal()
      || !Array.isArray(plan.E) || plan.E.length === 0) return null;
    const getKey = buildMsgKeyGetter(ctx.blockNum, ctx.groupId);
    const selected = new Set([...plan.heads, ...plan.seps].map(getKey));
    const record = {
      v: PRIORITY_LOCK_VERSION, blockNum: ctx.blockNum, groupId: ctx.groupId, uid: ctx.myUid,
      rosterHash: ctx.rosterHash,
      members: ctx.members.map(({ uid, bAddr }) => ({ uid, bAddr: JSON.parse(JSON.stringify(bAddr)) })),
      chatWindow: { startMs: ctx.chatWindow.startMs, endMs: ctx.chatWindow.endMs },
      heads: plan.heads.map(lockMessage), seps: plan.seps.map(lockMessage),
      covers: plan.eLegacy.map(lockReceipt), sepReceipts: plan.eSelfReceipts.map(lockReceipt),
      closure: plan.pinned.filter((m) => !selected.has(getKey(m))).map(lockMessage),
    };
    return priorityLockPlan(record, ctx) ? record : null;
  } catch { return null; }
}

export function priorityLockPlan(record, ctx) {
  try {
    if (!lockIdentity(ctx) || !exactFields(record, ['v', 'blockNum', 'groupId', 'uid', 'rosterHash',
      'members', 'chatWindow', 'heads', 'seps', 'covers', 'sepReceipts', 'closure'])
      || record.v !== PRIORITY_LOCK_VERSION || record.blockNum !== ctx.blockNum
      || record.groupId !== ctx.groupId || record.uid !== ctx.myUid || record.rosterHash !== ctx.rosterHash
      || !lockWindow(record.chatWindow) || record.chatWindow.startMs !== ctx.chatWindow.startMs
      || record.chatWindow.endMs !== ctx.chatWindow.endMs || !Array.isArray(record.members)
      || record.members.length !== ctx.members.length
      || record.members.some((m, i) => !exactFields(m, ['uid', 'bAddr'])
        || m.uid !== ctx.members[i].uid
        || JSON.stringify(m.bAddr) !== JSON.stringify(ctx.members[i].bAddr))) return null;
    const { heads, seps, covers, sepReceipts, closure } = record;
    if (![heads, seps, covers, sepReceipts, closure].every(Array.isArray)
      || heads.length !== planGoal() || seps.length > planGoal() || covers.length > 40
      || sepReceipts.length > 40 || closure.length > GUEST_PINNED_RULES.maxMessages * ctx.members.length) return null;
    const memberUids = ctx.members.map((m) => m.uid);
    const inWindow = (timestamp) => Number.isSafeInteger(timestamp)
      && timestamp >= ctx.chatWindow.startMs && timestamp <= ctx.chatWindow.endMs;
    const messageOk = (m, visible) => exactFields(m, ['uid', 'text', 'timestamp', 'signature'])
      && memberUids.includes(m.uid) && typeof m.text === 'string' && inWindow(m.timestamp)
      && isCanonicalSignature(m.signature) && countHalfWidthChars(m.text) <= GUEST_PINNED_RULES.maxMsgChars
      && (!visible || hasVisibleContent(m.text));
    if (heads.some((m) => !messageOk(m, true) || m.uid !== ctx.myUid)
      || seps.some((m) => !messageOk(m, true) || m.uid === ctx.myUid)
      || closure.some((m) => !messageOk(m, false) || m.uid !== ctx.myUid)) return null;
    const getKey = buildMsgKeyGetter(ctx.blockNum, ctx.groupId);
    const allMessages = [...heads, ...seps, ...closure];
    const keys = allMessages.map(getKey);
    if (new Set(keys).size !== keys.length) return null;
    const byKey = new Map(allMessages.map((m) => [getKey(m), m]));
    const byRef = new Map(allMessages.map((m) => [`${m.uid}|${msgRefOf(getKey(m))}`, m]));
    const receiptOk = (rc) => exactFields(rc, ['receiverUid', 'senderUid', 'msgRefs', 'timestamp', 'signature'])
      && memberUids.includes(rc.receiverUid) && memberUids.includes(rc.senderUid)
      && rc.receiverUid !== rc.senderUid && inWindow(rc.timestamp)
      && isCanonicalSignature(rc.signature) && Array.isArray(rc.msgRefs)
      && rc.msgRefs.length > 0 && rc.msgRefs.length <= receiptMaxRefsPerReceipt(GUEST_PINNED_RULES.maxMessages)
      && rc.msgRefs.every((ref, i) => isMsgRef(ref)
        && (i === 0 || compareHexAsc(rc.msgRefs[i - 1], ref) < 0));
    if (covers.some((rc) => !receiptOk(rc) || rc.senderUid !== ctx.myUid || rc.receiverUid === ctx.myUid)
      || sepReceipts.some((rc) => !receiptOk(rc) || rc.receiverUid !== ctx.myUid)) return null;
    const receiptId = (rc) => itemIdentity('receipt', rc, ctx.blockNum, ctx.groupId);
    if (new Set(covers.map(receiptId)).size !== covers.length
      || new Set(sepReceipts.map(receiptId)).size !== sepReceipts.length) return null;
    const targets = buildRealTargets({}, allMessages, ctx.blockNum, ctx.groupId, getKey);
    const headKeys = new Set(heads.map(getKey));
    const covered = new Set(), closureKeys = new Set();
    for (const rc of covers) {
      const claim = receiptCoverClaim(rc, targets, { memberUids, chatWindow: ctx.chatWindow,
        maxRefsPerReceipt: receiptMaxRefsPerReceipt(GUEST_PINNED_RULES.maxMessages),
        atomic: true, selfUid: ctx.myUid });
      if (!claim.windowed) return null;
      let used = false;
      for (const head of heads) {
        if (claim.targetKeys.includes(`r:${msgRefOf(getKey(head))}|${head.uid}`)
          && isReceiptTimely(rc.timestamp, head.timestamp)) { covered.add(getKey(head)); used = true; }
      }
      if (!used) return null;
      for (const ref of rc.msgRefs) {
        const m = byRef.get(`${rc.senderUid}|${ref}`);
        if (!m) return null;
        if (!headKeys.has(getKey(m)) && !seps.some((s) => getKey(s) === getKey(m))) closureKeys.add(getKey(m));
      }
    }
    if (covered.size !== heads.length || closureKeys.size !== closure.length
      || closure.some((m) => !closureKeys.has(getKey(m)))) return null;
    const usedSelf = new Set(), self = new Map(), backdated = [];
    for (const sep of seps) {
      const ref = msgRefOf(getKey(sep));
      const matches = sepReceipts.filter((rc) => rc.senderUid === sep.uid && rc.msgRefs.includes(ref)
        && isReceiptTimely(rc.timestamp, sep.timestamp));
      matches.sort((a, b) => a.timestamp - b.timestamp || receiptCanonCmp(a, b) || ascendingSignature(a, b));
      if (matches.length) {
        const chosen = matches[0];
        usedSelf.add(receiptId(chosen)); self.set(receiptId(chosen), chosen);
      } else backdated.push({ senderUid: sep.uid, msgRef: ref, timestamp: sep.timestamp });
    }
    if (usedSelf.size !== sepReceipts.length) return null;
    const totals = new Map();
    for (const m of allMessages) {
      const count = totals.get(m.uid) || { messages: 0, chars: 0 };
      count.messages++; count.chars += countHalfWidthChars(m.text); totals.set(m.uid, count);
    }
    if ([...totals.values()].some((count) => count.messages > GUEST_PINNED_RULES.maxMessages
      || count.chars > GUEST_PINNED_RULES.maxChars)) return null;
    const cmp = canonicalComparatorV2(getKey);
    const E = [...heads, ...seps].sort(cmp);
    const turns = priorityTurnGuarantee({ messages: E }, { ownerUid: ctx.myUid,
      blockNum: ctx.blockNum, groupId: ctx.groupId, minMessages: GUEST_PINNED_RULES.minMessages });
    if (turns !== planGoal() || covers.length + Number(seps.length > 0) > 40) return null;
    return { E: E.map(lockMessage), heads: heads.map(lockMessage), seps: seps.map(lockMessage),
      selfSeps: seps.map(lockMessage), eLegacy: covers.map(lockReceipt).sort((a, b) => receiptCanonCmp(a, b) || ascendingSignature(a, b)),
      eSelfReceipts: [...self.values()].map(lockReceipt), eSelfBackdated: backdated,
      separatorReaders: [], pinned: allMessages.sort(cmp).map(lockMessage),
      eKeys: new Set(E.map(getKey)), turns,
      stats: { candidate: 'lock', work: 0, exhausted: false, candidates: [],
        backdated: backdated.length, totalWork: 0, totalExhausted: false } };
  } catch { return null; }
}

export async function verifyPriorityLock(record, ctx, { verify } = {}) {
  try {
    if (!priorityLockPlan(record, ctx) || typeof verify !== 'function') return false;
    const addressOf = new Map(ctx.members.map((m) => [m.uid, parseBlockAddress(m.bAddr)?.address]));
    for (const m of [...record.heads, ...record.seps, ...record.closure]) {
      const address = addressOf.get(m.uid);
      if (!address || !await verify({ address,
        message: chatSignStringV2(ctx.blockNum, ctx.groupId, m.uid, m.text, m.timestamp), signature: m.signature })) return false;
    }
    for (const rc of [...record.covers, ...record.sepReceipts]) {
      const address = addressOf.get(rc.receiverUid);
      if (!address || !await verify({ address,
        message: readReceiptSignString(ctx.blockNum, ctx.groupId, rc.receiverUid, rc.senderUid, rc.msgRefs, rc.timestamp),
        signature: rc.signature })) return false;
    }
    return true;
  } catch { return false; }
}

export function memorylessCandidateTurns(plan) {
  if (!plan || plan.failed || !Array.isArray(plan.stats?.candidates)) return 0;
  return plan.stats.candidates.reduce((best, candidate) =>
    candidate && (candidate.name === 'head' || candidate.name === 'free')
      && Number.isSafeInteger(candidate.turns) ? Math.max(best, candidate.turns) : best, 0);
}

// S3FIX-CLOCK-USER: this module only computes decisions from supplied samples,
// clocks and signed self-read records. RPC reads, storage and display belong to callers.

export const CHAIN_CLOCK_AGREEMENT_MS = 24000;
export const CHAIN_CLOCK_EARLY_WARNING_MS = 45000;
export const CHAIN_CLOCK_LATE_WARNING_MS = -15000;
export const CHAIN_CLOCK_BAND_WIDTH_MS = 45000;
export const CHAIN_CLOCK_GAME_RECHECK_MS = 60000;
export const CHAIN_CLOCK_ENTRY_RECHECK_MS = 12000;
export const CHAIN_CLOCK_STEP_MS = 2000;
export const CHAIN_CLOCK_MAX_CORRECTION_MS = 24 * 60 * 60 * 1000;
export const CHAIN_CLOCK_RECEIPT_FRESH_MS = 10 * 60 * 1000;
export const VOTE_RECEIPT_CUTOFF_MS = 10 * 60 * 1000;
export const FUTURE_CLOCK_WARNING_LATE_MS = 100000;
export const FUTURE_CLOCK_WARNING_EARLY_MS = 120000;
export const FUTURE_CLOCK_WARNING_RESHOW_MS = 600000;

function usableClockReading(reading) {
  return reading?.kind === 'consensus' && Array.isArray(reading.sourceIds)
    && reading.sourceIds.length >= 2 && Number.isFinite(reading.timeMs);
}

export function classifyFutureClockWarning(reading, clientTimeMs, itemTimestampMs, skewMs) {
  if (!usableClockReading(reading) || !Number.isSafeInteger(clientTimeMs)) return null;
  const leadMs = clientTimeMs - reading.timeMs;
  if (leadMs >= FUTURE_CLOCK_WARNING_EARLY_MS) return 'early';
  if (-leadMs >= FUTURE_CLOCK_WARNING_LATE_MS && Number.isSafeInteger(itemTimestampMs)
      && Number.isSafeInteger(skewMs) && itemTimestampMs > clientTimeMs + skewMs) return 'late';
  return null;
}

export function futureClockWarningPersists(direction, reading, clientTimeMs) {
  if (!usableClockReading(reading) || !Number.isSafeInteger(clientTimeMs)) return null;
  const leadMs = clientTimeMs - reading.timeMs;
  return direction === 'early' ? leadMs >= FUTURE_CLOCK_WARNING_EARLY_MS
    : -leadMs >= FUTURE_CLOCK_WARNING_LATE_MS;
}

export function futureClockWarningBypassesCooldown(s, reading, nextClientTimeMs, skewMs) {
  if (!s?.warning || !usableClockReading(reading) || !Number.isSafeInteger(nextClientTimeMs)
      || !Number.isSafeInteger(skewMs)) return false;
  if (Math.abs(nextClientTimeMs - reading.timeMs) >= skewMs) return false;
  return futureClockWarningPersists(s.warning.direction, reading, nextClientTimeMs) === false;
}

export function ownClockVoteDeadline(chatCloseAt, lateMs) {
  if (!Number.isSafeInteger(chatCloseAt) || !Number.isFinite(lateMs) || lateMs <= 0) return null;
  if (lateMs >= CHAIN_CLOCK_RECEIPT_FRESH_MS) return { kind: 'none' };
  return { kind: 'at', ms: Math.floor(chatCloseAt - VOTE_RECEIPT_CUTOFF_MS - lateMs) };
}

export const INITIAL_FUTURE_CLOCK_WARNING = Object.freeze({ warning: null, fullShown: false,
  firstFullDeviationMs: null, reshowUsed: false });

export function advanceFutureClockWarning(s, event) {
  const { reading, clientTimeMs, itemTimestampMs, skewMs } = event;
  if (event.type === 'chatEnded') return s.warning ? { ...s, warning: null } : s;
  if (event.type === 'shown') {
    return s.warning?.stage === 'full' && !s.fullShown
      ? { ...s, fullShown: true, firstFullDeviationMs: Math.abs(s.warning.deviationMs) } : s;
  }
  if (event.type === 'continue') {
    return s.warning?.stage === 'full'
      ? { ...s, warning: { ...s.warning, stage: 'band' } } : s;
  }
  if (event.type === 'corrected') {
    if (!s.warning) return s;
    const persists = futureClockWarningPersists(s.warning.direction, reading, clientTimeMs);
    if (persists === null) return s;
    if (!persists) return { ...s, warning: null };
    const deviationMs = clientTimeMs - reading.timeMs;
    return { ...s, warning: { ...s.warning, deviationMs,
      stage: s.warning.stage === 'full' && s.fullShown ? 'band' : s.warning.stage } };
  }
  if (event.type !== 'tick' && event.type !== 'discard') return s;
  if (s.warning && event.type === 'discard') return s;
  if (s.warning) {
    const persists = futureClockWarningPersists(s.warning.direction, reading, clientTimeMs);
    if (persists === null) return s;
    if (persists) {
      const deviationMs = clientTimeMs - reading.timeMs;
      const reshow = s.warning.stage === 'band' && s.fullShown && !s.reshowUsed
        && Math.abs(deviationMs) > FUTURE_CLOCK_WARNING_RESHOW_MS
        && s.firstFullDeviationMs !== null
        && s.firstFullDeviationMs <= FUTURE_CLOCK_WARNING_RESHOW_MS;
      if (deviationMs === s.warning.deviationMs && !reshow) return s;
      return { ...s, warning: { ...s.warning, deviationMs,
        stage: reshow ? 'full' : s.warning.stage }, reshowUsed: s.reshowUsed || reshow };
    }
    s = { ...s, warning: null };
  }
  const direction = classifyFutureClockWarning(reading, clientTimeMs,
    event.type === 'discard' ? itemTimestampMs : null, skewMs);
  if (!direction) return s;
  return { ...s, warning: { direction, stage: s.fullShown ? 'band' : 'full',
    deviationMs: clientTimeMs - reading.timeMs } };
}

// Only a vote needs a known close time and two timestamps before the cutoff.
export function canIssueActionReceiptBeforeVoteCutoff(actionType, actionTimestamp, receiptTimestamp, chatCloseAt) {
  if (actionType !== 'vote') return true;
  if (!Number.isSafeInteger(chatCloseAt)) return false;
  const cutoff = chatCloseAt - VOTE_RECEIPT_CUTOFF_MS;
  return Number.isSafeInteger(actionTimestamp) && actionTimestamp < cutoff
    && Number.isSafeInteger(receiptTimestamp) && receiptTimestamp < cutoff;
}

function safeMs(value, label) {
  if (!Number.isSafeInteger(value)) throw new TypeError(`${label} must be a safe integer in milliseconds`);
  return value;
}

function monoMs(value, label) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new TypeError(`${label} must be a finite nonnegative monotonic time`);
  }
  return value;
}

function projectSample(sample, nowMonoMs, sourceId) {
  if (!sample || typeof sample !== 'object') return null;
  const blockTimestampMs = safeMs(sample.blockTimestampMs, 'blockTimestampMs');
  const observedMonoMs = monoMs(sample.observedMonoMs, 'observedMonoMs');
  if (observedMonoMs > nowMonoMs) throw new RangeError('sample observed after nowMonoMs');
  return { sourceId, timeMs: blockTimestampMs + (nowMonoMs - observedMonoMs) };
}

/**
 * publicSamples contains at most three distinct approved public RPC sources.
 * walletSample is a separate, optional chainId=1 source. There is no operator
 * RPC parameter. Each sample is the latest block timestamp in milliseconds at
 * observedMonoMs; nowMonoMs projects every sample onto the same monotonic instant.
 * An absent/failed source is null or omitted, and has no vote.
 * A remote wallet has one vote like a public source. A live non-remote wallet
 * supplies the clock time unless the second newest time in the largest
 * agreeing public group is newer; sourceIds identifies the selected group.
 * Without a wallet, use that second newest public time. With two or more live
 * sources but no agreeing pair, the time cannot be verified.
 */
export function selectChainClockReading({ publicSamples = [], walletSample = null, nowMonoMs }) {
  if (!Array.isArray(publicSamples) || publicSamples.length > 3) {
    throw new RangeError('publicSamples must contain at most three sources');
  }
  monoMs(nowMonoMs, 'nowMonoMs');
  const samples = [];
  const seen = new Set();
  for (const sample of publicSamples) {
    if (!sample) continue;
    if (typeof sample.sourceId !== 'string' || !sample.sourceId || sample.sourceId === 'wallet') {
      throw new TypeError('public sample needs a sourceId');
    }
    if (seen.has(sample.sourceId)) continue;
    seen.add(sample.sourceId);
    samples.push(projectSample(sample, nowMonoMs, sample.sourceId));
  }
  const walletLive = !!walletSample && Number(walletSample.chainId) === 1;
  if (walletLive) samples.push(projectSample(walletSample, nowMonoMs, 'wallet'));
  const liveCount = samples.length;
  if (liveCount < 2) return {
    kind: 'unavailable', liveCount,
    timeMs: liveCount === 1 ? samples[0].timeMs : null,
    sourceIds: liveCount === 1 ? [samples[0].sourceId] : [],
  };

  let bestSize = 0;
  let bestMax = -Infinity;
  let best = null;
  for (let mask = 1; mask < (1 << liveCount); mask++) {
    const group = samples.filter((_, index) => (mask & (1 << index)) !== 0);
    if (group.length < bestSize) continue;
    const times = group.map((sample) => sample.timeMs);
    if (Math.max(...times) - Math.min(...times) > CHAIN_CLOCK_AGREEMENT_MS) continue;
    const groupMax = Math.max(...times);
    if (group.length > bestSize || (group.length === bestSize && groupMax > bestMax)) {
      bestSize = group.length;
      bestMax = groupMax;
      best = group;
    }
  }
  const sourceIds = best.map((sample) => sample.sourceId);
  if (walletLive && !walletSample.remote) {
    const wallet = samples.find((sample) => sample.sourceId === 'wallet');
    const publicVotes = samples.filter((sample) => sample.sourceId !== 'wallet');
    let publicGroup = null;
    let publicGroupMax = -Infinity;
    for (let mask = 1; mask < (1 << publicVotes.length); mask++) {
      const group = publicVotes.filter((_, index) => (mask & (1 << index)) !== 0);
      if (publicGroup && group.length < publicGroup.length) continue;
      const times = group.map((sample) => sample.timeMs);
      if (Math.max(...times) - Math.min(...times) > CHAIN_CLOCK_AGREEMENT_MS) continue;
      const groupMax = Math.max(...times);
      if (!publicGroup || group.length > publicGroup.length
          || (group.length === publicGroup.length && groupMax > publicGroupMax)) {
        publicGroup = group;
        publicGroupMax = groupMax;
      }
    }
    const publicSecond = publicGroup?.length >= 2
      ? publicGroup.map((sample) => sample.timeMs).sort((a, b) => b - a)[1] : null;
    let walletGroup = [wallet];
    let walletGroupMax = wallet.timeMs;
    for (let mask = 1; mask < (1 << liveCount); mask++) {
      const group = samples.filter((_, index) => (mask & (1 << index)) !== 0);
      if (!group.includes(wallet) || group.length < walletGroup.length) continue;
      const times = group.map((sample) => sample.timeMs);
      if (Math.max(...times) - Math.min(...times) > CHAIN_CLOCK_AGREEMENT_MS) continue;
      if (group.length > walletGroup.length || Math.max(...times) > walletGroupMax) {
        walletGroup = group;
        walletGroupMax = Math.max(...times);
      }
    }
    return publicSecond !== null && wallet.timeMs < publicSecond
      ? { kind: 'consensus', liveCount, timeMs: publicSecond,
        sourceIds: publicGroup.map((sample) => sample.sourceId) }
      : { kind: 'consensus', liveCount, timeMs: wallet.timeMs,
        sourceIds: walletGroup.map((sample) => sample.sourceId) };
  }
  if (bestSize < 2) return { kind: 'unavailable', liveCount: 0, timeMs: null, sourceIds: [] };
  const ordered = best.map((sample) => sample.timeMs).sort((a, b) => b - a);
  return { kind: 'consensus', liveCount, timeMs: ordered[1], sourceIds };
}

export function classifyChainClockDeviation(clientTimeMs, chainTimeMs) {
  safeMs(clientTimeMs, 'clientTimeMs');
  if (typeof chainTimeMs !== 'number' || !Number.isFinite(chainTimeMs)) {
    throw new TypeError('chainTimeMs must be finite');
  }
  const deviationMs = clientTimeMs - chainTimeMs;
  return {
    deviationMs,
    outside: deviationMs >= CHAIN_CLOCK_EARLY_WARNING_MS
      || deviationMs <= CHAIN_CLOCK_LATE_WARNING_MS,
  };
}

/** A UI state transition. The returned nextOutside is page memory, not storage. */
export function advanceChainClockAlert({
  reading, wallNowMs, correctionMs, monoNowMs, context,
  previousOutside = null, confirmedDeviationMs = null,
}) {
  const clientTimeMs = correctedClockTime(wallNowMs, correctionMs);
  monoMs(monoNowMs, 'monoNowMs');
  if (!['entry', 'step', 'game'].includes(context)) throw new TypeError('unknown clock context');
  if (!reading || typeof reading !== 'object') throw new TypeError('reading is required');
  if (reading.kind === 'unavailable' && reading.liveCount === 0) {
    return { kind: context === 'entry' ? 'confirmation' : 'none', nextOutside: null,
      clientTimeMs, deviationMs: null };
  }
  if (reading.kind !== 'consensus'
      && !(reading.kind === 'unavailable' && reading.liveCount === 1)) {
    throw new TypeError('unknown reading kind');
  }
  const { deviationMs, outside } = classifyChainClockDeviation(clientTimeMs, reading.timeMs);
  const base = { clientTimeMs, deviationMs, nextOutside: null };
  if (!outside) return { kind: 'none', ...base };
  if (confirmedDeviationMs !== null) {
    if (typeof confirmedDeviationMs !== 'number' || !Number.isFinite(confirmedDeviationMs)) {
      throw new TypeError('confirmedDeviationMs must be finite');
    }
    if (Math.abs(deviationMs - confirmedDeviationMs) < CHAIN_CLOCK_BAND_WIDTH_MS) {
      return { kind: 'none', ...base };
    }
  }
  const kind = reading.kind === 'consensus' ? 'warning' : 'confirmation';
  if (context !== 'game' && kind === 'confirmation') return { kind, ...base };
  const recheckMs = context === 'game' ? CHAIN_CLOCK_GAME_RECHECK_MS : CHAIN_CLOCK_ENTRY_RECHECK_MS;
  if (previousOutside !== null) {
    monoMs(previousOutside.monoMs, 'previousOutside.monoMs');
    if (monoNowMs >= previousOutside.monoMs
        && monoNowMs - previousOutside.monoMs >= recheckMs) {
      return { kind, ...base };
    }
  }
  return { kind: 'pending', ...base,
    nextOutside: previousOutside && previousOutside.monoMs <= monoNowMs
      ? previousOutside : { monoMs: monoNowMs } };
}

export function detectClockStep({ previousWallMs, previousMonoMs, wallNowMs, monoNowMs }) {
  safeMs(previousWallMs, 'previousWallMs');
  safeMs(wallNowMs, 'wallNowMs');
  monoMs(previousMonoMs, 'previousMonoMs');
  monoMs(monoNowMs, 'monoNowMs');
  if (monoNowMs < previousMonoMs) throw new RangeError('monotonic clock moved backwards');
  return Math.abs((wallNowMs - previousWallMs) - (monoNowMs - previousMonoMs))
    > CHAIN_CLOCK_STEP_MS;
}

/** Signed milliseconds to add to the device wall clock; no chain value is applied. */
export function parseUserCorrectionMs(input) {
  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (!/^[+-]?\d+$/.test(trimmed)) throw new TypeError('correction must be integer milliseconds');
    input = Number(trimmed);
  }
  safeMs(input, 'correction');
  if (Math.abs(input) > CHAIN_CLOCK_MAX_CORRECTION_MS) {
    throw new RangeError('correction exceeds 24 hours');
  }
  return input;
}

export function correctedClockTime(wallNowMs, correctionMs) {
  const corrected = safeMs(wallNowMs, 'wallNowMs') + parseUserCorrectionMs(correctionMs);
  return safeMs(corrected, 'corrected clock');
}

function readReceipts(receipts) {
  if (!Array.isArray(receipts)) throw new TypeError('receipts must be an array');
  return receipts.filter((receipt) => receipt && Array.isArray(receipt.msgRefs)
    && receipt.msgRefs.length > 0 && typeof receipt.signature === 'string'
    && Number.isSafeInteger(receipt.timestamp));
}

const readGroupKey = (receipt) => JSON.stringify([receipt.receiverUid, receipt.senderUid, receipt.msgRefs]);

/** The earliest signed row for each group preserves the order of new reads. */
export function deriveReadReceiptFloor({ receipts, clockMs }) {
  safeMs(clockMs, 'clockMs');
  const earliest = new Map();
  for (const receipt of readReceipts(receipts)) {
    const key = readGroupKey(receipt);
    earliest.set(key, Math.min(earliest.get(key) ?? Infinity, receipt.timestamp));
  }
  const eligible = [...earliest.values()].filter((timestamp) => timestamp <= clockMs);
  return eligible.length ? safeMs(Math.max(...eligible) + 1, 'read receipt floor') : null;
}

export function nextReadReceiptTimestamp({ clockMs, receipts, tickTimestampMs = null }) {
  safeMs(clockMs, 'clockMs');
  if (tickTimestampMs !== null) return safeMs(tickTimestampMs, 'tickTimestampMs');
  const floor = deriveReadReceiptFloor({ receipts, clockMs });
  return floor === null ? clockMs : Math.max(clockMs, floor);
}

function messageTime(messageTimestamps, key) {
  if (messageTimestamps instanceof Map) return messageTimestamps.get(key);
  if (!messageTimestamps || typeof messageTimestamps !== 'object') return undefined;
  return Object.hasOwn(messageTimestamps, key) ? messageTimestamps[key] : undefined;
}

/**
 * Return unsigned plans from the earliest signed row in every group. Every ref
 * must still be within the existing ±10 minute freshness interval.
 */
export function planReadReceiptReissues({
  receipts, shiftBackMs, messageTimestamps, nowMs, chattingStartMs = null, chatCloseAtMs,
}) {
  safeMs(shiftBackMs, 'shiftBackMs');
  safeMs(nowMs, 'nowMs');
  safeMs(chatCloseAtMs, 'chatCloseAtMs');
  if (shiftBackMs <= 0 || nowMs >= chatCloseAtMs) return [];
  const rows = readReceipts(receipts);
  const earliest = new Map();
  for (const receipt of rows) {
    const key = readGroupKey(receipt);
    if (!earliest.has(key) || receipt.timestamp < earliest.get(key).timestamp) earliest.set(key, receipt);
  }
  const plans = [];
  for (const receipt of earliest.values()) {
    const timestamp = safeMs(receipt.timestamp - shiftBackMs, 'shifted receipt time');
    if (Number.isSafeInteger(chattingStartMs) && timestamp < chattingStartMs) continue;
    const fresh = receipt.msgRefs.every((ref) => {
      const claimedMs = messageTime(messageTimestamps, `${receipt.senderUid}|${ref}`);
      return Number.isSafeInteger(claimedMs)
        && Math.abs(nowMs - claimedMs) <= CHAIN_CLOCK_RECEIPT_FRESH_MS
        && Math.abs(timestamp - claimedMs) <= CHAIN_CLOCK_RECEIPT_FRESH_MS;
    });
    if (!fresh) continue;
    plans.push({
      receiverUid: receipt.receiverUid, senderUid: receipt.senderUid,
      msgRefs: [...receipt.msgRefs], originalTimestampMs: receipt.timestamp,
      timestamp, sourceSignature: receipt.signature,
    });
  }
  return plans;
}

/** Count planned groups that already have at least two signed rows in this device's copy. */
export function countRepeatedReissueGroups({ receipts, plans }) {
  const counts = new Map();
  for (const receipt of readReceipts(receipts)) {
    const key = readGroupKey(receipt);
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return plans.filter((plan) => (counts.get(readGroupKey(plan)) || 0) >= 2).length;
}

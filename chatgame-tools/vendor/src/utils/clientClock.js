// A page-local correction. Storage is read lazily so importing this module is SSR-safe.
import { parseUserCorrectionMs } from './chainClock.js';

export const CLIENT_CLOCK_STORAGE_KEY = 'clientClockCorrection_v1';

export function createClientClock(storageKey = CLIENT_CLOCK_STORAGE_KEY) {
  let loaded = false;
  let correctionMs = 0;
  const intervalKey = `${storageKey}_lastChangedAt`;
  const adoptedKey = (blockNum) => `${storageKey}_adoptedBlock_${blockNum}`;
  let lastChangedWallMs = null;
  let lastChangedMonoMs = null;
  const adoptedBlocks = new Set();
  const listeners = new Set();

  function readLastChangedAt() {
    try {
      if (typeof localStorage !== 'undefined') {
        const value = localStorage.getItem(intervalKey);
        const parsed = value === null ? null : Number(value);
        if (parsed !== lastChangedWallMs && Number.isSafeInteger(parsed)) {
          lastChangedWallMs = parsed;
          lastChangedMonoMs = null;
        }
      }
    } catch { /* Keep page memory when storage is unavailable. */ }
    return lastChangedWallMs;
  }

  function correctionCooldownMs(wallNowMs = Date.now(), monoNowMs = performance.now()) {
    const lastWall = readLastChangedAt();
    if (lastWall === null) return 0;
    const elapsed = lastChangedMonoMs !== null
      ? monoNowMs - lastChangedMonoMs : wallNowMs - lastWall;
    if (elapsed < 0) return 0;
    return Math.max(0, 600000 - elapsed);
  }

  function hasAdoptedClock(blockNum) {
    if (blockNum === null || blockNum === undefined || !Number.isSafeInteger(Number(blockNum))) return false;
    const key = String(blockNum);
    if (adoptedBlocks.has(key)) return true;
    try {
      return typeof localStorage !== 'undefined' && localStorage.getItem(adoptedKey(key)) === '1';
    } catch { return false; }
  }

  function markAdoptedClock(blockNum) {
    if (blockNum === null || blockNum === undefined || !Number.isSafeInteger(Number(blockNum))) return;
    const key = String(blockNum);
    adoptedBlocks.add(key);
    try {
      if (typeof localStorage !== 'undefined') localStorage.setItem(adoptedKey(key), '1');
    } catch { /* Keep page memory when storage is unavailable. */ }
  }

  function getClockCorrection() {
    if (!loaded) {
      loaded = true;
      try {
        if (typeof localStorage !== 'undefined') {
          const saved = localStorage.getItem(storageKey);
          if (saved !== null) correctionMs = parseUserCorrectionMs(saved);
        }
      } catch { /* Storage may be disabled; the page still keeps its correction. */ }
    }
    return correctionMs;
  }

  function setClockCorrection(nextMs, { bypassCooldown = false } = {}) {
    const previousMs = getClockCorrection();
    const validNextMs = parseUserCorrectionMs(nextMs);
    if (validNextMs !== previousMs && !bypassCooldown && correctionCooldownMs() > 0) {
      throw new RangeError('clock correction is available after the ten minute interval');
    }
    correctionMs = validNextMs;
    try {
      if (typeof localStorage !== 'undefined') localStorage.setItem(storageKey, String(validNextMs));
    } catch { /* Keep the correction in memory for this page. */ }
    const change = { previousMs, nextMs: validNextMs, deltaMs: validNextMs - previousMs };
    if (change.deltaMs !== 0) {
      lastChangedWallMs = Date.now();
      lastChangedMonoMs = performance.now();
      try {
        if (typeof localStorage !== 'undefined') localStorage.setItem(intervalKey, String(lastChangedWallMs));
      } catch { /* Keep page memory when storage is unavailable. */ }
    }
    if (change.deltaMs !== 0) for (const listener of [...listeners]) listener(change);
    return change;
  }

  function subscribeClockCorrection(listener) {
    listeners.add(listener);
    return () => listeners.delete(listener);
  }

  function clientNow(wallNowMs = Date.now()) {
    return wallNowMs + getClockCorrection();
  }

  return { getClockCorrection, setClockCorrection, subscribeClockCorrection, clientNow,
    correctionCooldownMs, hasAdoptedClock, markAdoptedClock };
}

const pageClock = createClientClock();
export const getClockCorrection = pageClock.getClockCorrection;
export const setClockCorrection = pageClock.setClockCorrection;
export const subscribeClockCorrection = pageClock.subscribeClockCorrection;
export const clientNow = pageClock.clientNow;
export const correctionCooldownMs = pageClock.correctionCooldownMs;
export const hasAdoptedClock = pageClock.hasAdoptedClock;
export const markAdoptedClock = pageClock.markAdoptedClock;

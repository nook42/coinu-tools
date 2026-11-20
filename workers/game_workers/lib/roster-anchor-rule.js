import { keccak256, stringToHex } from 'viem';

export function rosterAnchorKey(blockNum) {
  if (!Number.isSafeInteger(Number(blockNum)) || Number(blockNum) < 0) {
    throw new TypeError('invalid roster block number');
  }
  return keccak256(stringToHex(`bitcoinu:roster:${Number(blockNum)}`));
}

const safeUnsigned = (value, label) => {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) throw new TypeError(`invalid ${label}`);
  return number;
};

// HashStorage の追記順は registeredAt の単調非減少順。同一秒の複数登録も
// upper-bound 探索で最後を選ぶ。各探索は O(log count) 回だけ reader を呼ぶ。
export async function selectCanonicalRosterRegistration({
  count, at, entryEndSec, chattingStartSec, nowSec,
}) {
  const size = safeUnsigned(count, 'registration count');
  const entryEnd = safeUnsigned(entryEndSec, 'entry end');
  const chattingStart = safeUnsigned(chattingStartSec, 'chatting start');
  const now = safeUnsigned(nowSec, 'current time');
  if (typeof at !== 'function' || chattingStart <= entryEnd) throw new TypeError('invalid roster window or reader');

  const read = async (index) => {
    const raw = await at(index);
    const hash = raw?.hash;
    if (typeof hash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(hash)) {
      throw new TypeError('invalid registration hash');
    }
    return {
      hash: hash.toLowerCase(),
      registeredBlock: safeUnsigned(raw.registeredBlock, 'registration block'),
      registeredAt: safeUnsigned(raw.registeredAt, 'registration time'),
    };
  };
  const lowerBound = async (boundary) => {
    let lo = 0; let hi = size;
    while (lo < hi) {
      const mid = lo + Math.floor((hi - lo) / 2);
      if ((await read(mid)).registeredAt < boundary) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  };
  const preEntryCount = await lowerBound(entryEnd);
  const firstLate = await lowerBound(chattingStart);
  const provisional = now < chattingStart;
  const effectiveEnd = provisional ? Math.min(firstLate, await lowerBound(now + 1)) : firstLate;
  const index = effectiveEnd > preEntryCount ? effectiveEnd - 1 : null;
  return {
    status: index == null ? 'none' : (provisional ? 'provisional' : 'canonical'),
    provisional,
    index,
    row: index == null ? null : await read(index),
    lateCount: size - firstLate,
    preEntryCount,
  };
}

// R33-U-B1D01: 採点に提出物を採る前提。履歴ありは上の選択結果だけを使う。
// 旧版 HashStorage は公式クライアントと同じく現在値だけで判定する。
export function evaluateRosterSubmissionEligibility({ selection, legacy = false, chattingStartSec }) {
  const chattingStart = safeUnsigned(chattingStartSec, 'chatting start');
  const row = selection?.row ?? null;
  const hash = row?.hash == null ? null : String(row.hash).toLowerCase();
  if (hash !== null && !/^0x[0-9a-f]{64}$/.test(hash)) throw new TypeError('invalid registration hash');
  const registeredAt = row?.registeredAt == null ? null : safeUnsigned(row.registeredAt, 'registration time');
  const registeredBlock = row?.registeredBlock == null ? null : safeUnsigned(row.registeredBlock, 'registration block');
  const registered = !!hash && hash !== `0x${'0'.repeat(64)}` && registeredBlock !== null && registeredBlock > 0;
  const prestart = legacy ? registered : registered && selection?.status === 'canonical';
  const accepted = prestart;
  return {
    accepted,
    reason: accepted ? null : 'no_prestart_canonical_roster',
    registrationIndex: selection?.index ?? null,
    registeredAt,
    registeredBlock,
    chattingStart,
    hash,
    legacy: Boolean(legacy),
  };
}

export function adoptedForRoster(adopted, decision) {
  if (decision?.accepted === true) return adopted;
  return Array.isArray(adopted) ? [] : Object.create(null);
}

export function applyRosterSubmissionGate(data, decision) {
  if (decision?.accepted === true) return data;
  data.submissions = Object.create(null);
  data.submissionsRaw = Object.create(null);
  data.evidenceSources = Object.create(null);
  return data;
}

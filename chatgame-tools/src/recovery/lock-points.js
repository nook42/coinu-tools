import { GameMasterDO } from '../../vendor/workers/game_workers/game-master-DO.js';
import { calculateDepositPoints } from '../../vendor/workers/game_workers/lib/game-result-calculator.js';
import { MAX_DEPOSIT_IDS, MAX_GROUP_PLAYERS } from '../../vendor/workers/game_workers/lib/submission-limits.js';

export const LOCK_POINTS_REREAD_MS = 300000;
const TOKEN_MINING_ETH_LOCK_ABI = [{ type: 'function', name: 'ethLock', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] }];
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';

export function createLockPointsCache() {
  return { ethLock: null, ethLockKey: null, records: new Map() };
}

export async function verifyRecoveryLockPoints({ client, blockNum, members, contracts, timing, cache }) {
  const result = Object.create(null);
  const allUnverified = () => {
    for (const member of Array.isArray(members) ? members : []) {
      try { if (member && member.uid != null) result[member.uid] = { status: 'unverified' }; }
      catch { /* malformed row has no displayable uid */ }
    }
    return result;
  };
  try {
    if (!Array.isArray(members) || members.length > MAX_GROUP_PLAYERS || !timing
        || !contracts?.tokenMining || !client || !cache) return allUnverified();
    const before = client.unagreedCount?.();
    const ethLock = cache.ethLockKey === contracts.tokenMining && cache.ethLock
      ? cache.ethLock
      : await client.readContract({ address: contracts.tokenMining, abi: TOKEN_MINING_ETH_LOCK_ABI, functionName: 'ethLock' });
    if (typeof ethLock !== 'string' || ethLock.toLowerCase() === ZERO_ADDRESS) return allUnverified();
    const gm = new GameMasterDO({ storage: {} }, {
      ETH_LOCK_CONTRACT_ADDRESS: ethLock,
      START_TIME: String(Number(timing.evidenceStartTimeSec) * 1000),
      BLOCK_TIME: String(Number(timing.blockTimeSec) * 1000),
    });
    gm.createReadOnlyClient = () => client;

    const perUid = Object.create(null);
    for (const member of members) {
      const ids = gm.parseEntryDepositIds(member.depIds);
      if (ids.length > MAX_DEPOSIT_IDS) {
        result[member.uid] = { status: 'unverified' };
      } else {
        perUid[member.uid] = ids;
      }
    }
    const { uniqueIds } = gm.calcCollectDepositIds(blockNum, perUid);
    const merged = Object.create(null);
    const need = [];
    for (const id of uniqueIds) {
      const key = `${ethLock.toLowerCase()}|${id}`;
      if (cache.records.has(key)) merged[id] = cache.records.get(key);
      else need.push(id);
    }
    const { chainData, failedReads } = await gm.calcFetchDepositsFromChain(need);
    for (const [id, record] of Object.entries(chainData)) if (record) merged[id] = record;
    const failed = new Set(failedReads);
    for (const [uid, ids] of Object.entries(perUid)) {
      const one = Object.create(null);
      one[uid] = ids;
      const ownIds = gm.calcCollectDepositIds(blockNum, one).uniqueIds;
      if (ownIds.some((id) => failed.has(id) || !merged[id])) {
        result[uid] = { status: 'unverified' };
        continue;
      }
      const wei = gm.calcFilterEligibleDeposits(blockNum, one, merged).verifiedDepositWei[uid];
      result[uid] = { status: 'verified', wei, points: calculateDepositPoints(wei) };
    }
    if (client.unagreedCount?.() === before) {
      cache.ethLock = ethLock;
      cache.ethLockKey = contracts.tokenMining;
      for (const [id, record] of Object.entries(chainData)) {
        if (record?.lockOwnerAddress && record.lockOwnerAddress.toLowerCase() !== ZERO_ADDRESS) {
          cache.records.set(`${ethLock.toLowerCase()}|${id}`, record);
        }
      }
    }
    return result;
  } catch {
    return allUnverified();
  }
}

export function summaryDeclaredWei(summaryMeta) {
  try {
    const raw = summaryMeta?.depIds;
    const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
    return typeof parsed?.deposit === 'string' ? parsed.deposit : null;
  } catch {
    return null;
  }
}

export function recoveryLockPointView(declaredWei, declaredPoints, result) {
  const current = declaredPoints > 0 ? String(declaredPoints) : '—';
  if (!result) return { text: current, mark: null };
  if (result.status !== 'verified') return { text: current, mark: 'unverified' };
  if (!(declaredPoints > 0)) return { text: String(result.points), mark: null };
  if (declaredWei === result.wei) return { text: current, mark: null };
  return { text: String(result.points), mark: 'corrected' };
}

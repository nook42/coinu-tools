import assert from 'node:assert/strict';
import { sha256, stringToHex } from 'viem';
import { buildRosterMemberCommitment } from '../../workers/game_workers/lib/roster-member-root.js';
import { fetchVerifiedLiveRoster, fetchCachedVerifiedLiveRoster,
  readVerifiedRosterCache, FULL_ROSTER_FETCH_CONCURRENCY } from '../../src/utils/roster-verification.js';
import { loadEvidenceRosterProof } from '../../src/utils/evidence.js';
import { fetchAllRosterGroupTexts, FULL_ROSTER_FETCH_CONCURRENCY as RECOVERY_CONCURRENCY }
  from '../src/recovery/discovery.js';

const blockNum = 5;
const groupCount = 700;
const entryEnd = 1_800_000_000;
const chattingStart = entryEnd + 120;
const files = new Map();
const groups = [];
for (let groupId = 0; groupId < groupCount; groupId++) {
  const members = Array.from({ length: 3 }, (_, j) => {
    const i = groupId * 3 + j + 1;
    return { uid: `u${i}`, walletAddress: `0x${i.toString(16).padStart(40, '0')}` };
  });
  const text = JSON.stringify({ blockNum, groupId, members });
  files.set(`group${groupId}.json`, text);
  groups.push({ groupId, sha256: sha256(stringToHex(text)).slice(2) });
}
const manifestText = JSON.stringify({ blockNum, groups });
files.set('manifest.json', manifestText);
const commitment = buildRosterMemberCommitment({ blockNum, manifestText,
  groupTexts: new Map(groups.map((g) => [g.groupId, files.get(`group${g.groupId}.json`)])) });
let chainC = commitment.C;
let observedBlockTime = chattingStart + 1;
let failGroup = null;
let active = 0;
let peak = 0;
let requests = 0;
let groupRequests = 0;
const fetchImpl = async (url) => {
  active++;
  peak = Math.max(peak, active);
  requests++;
  if (String(url).includes('/group')) groupRequests++;
  await new Promise((resolve) => setTimeout(resolve, 1));
  active--;
  const key = url.split('/').at(-1);
  return new Response(key === `group${failGroup}.json` ? '' : files.get(key) || '',
    { status: key === `group${failGroup}.json` ? 503 : files.has(key) ? 200 : 404 });
};
const client = {
  getBlockNumber: async () => 99n,
  getBlock: async () => ({ timestamp: BigInt(observedBlockTime) }),
  getChainId: async () => 31337,
  readContract: async ({ functionName }) => {
    if (functionName === 'otherRegistrationCount') return 1n;
    if (functionName === 'otherRegistrationAt') return [chainC, 77n, BigInt(entryEnd + 1)];
    if (functionName === 'chatWindow') return [BigInt(entryEnd), BigInt(chattingStart + 180)];
    if (functionName === 'GAME_PERIOD') return 180n;
    throw new Error(`unexpected ${functionName}`);
  },
};
const data = new Map();
const storage = { setItem: (k, v) => data.set(k, v), getItem: (k) => data.get(k) || null };
const options = { blockNum, groupId: 0, uid: 'u1', client,
  hashStorageAddress: '0x1111111111111111111111111111111111111111',
  evidenceAddress: '0x2222222222222222222222222222222222222222',
  fetchImpl, r2Base: 'https://test.invalid', timeoutMs: 1000, proofStorage: storage };
const start = performance.now();
const good = await fetchVerifiedLiveRoster(options);
const elapsedMs = Math.round(performance.now() - start);
assert.equal(good.status, 'verified', good.reason);
assert.equal(good.rosterProofSaved, true);
assert.equal(loadEvidenceRosterProof(blockNum, 'u1', { storage })?.C, chainC);
assert.ok(peak <= FULL_ROSTER_FETCH_CONCURRENCY, `peak=${peak}`);
assert.equal(requests, groupCount + 1);
const startCache = {};
const boundaryCache = process.env.T1E_ROSTER_CACHE_MUTATION === 'off' ? null : startCache;
requests = 0;
observedBlockTime = chattingStart - 1;
for (let i = 0; i < 3; i++) {
  const provisional = await fetchVerifiedLiveRoster({ ...options, rosterContentCache: boundaryCache });
  assert.equal(provisional.status, 'verified', provisional.reason);
  assert.equal(provisional.anchorStatus, 'provisional');
}
assert.equal(requests, groupCount + 1, 'provisional polling fetches each group once');
observedBlockTime = chattingStart + 1;
const promoted = await fetchVerifiedLiveRoster({ ...options, rosterContentCache: boundaryCache });
assert.equal(promoted.anchorStatus, 'canonical');
assert.equal(promoted.rosterProofSaved, true);
assert.equal(requests, groupCount + 1, 'chain promotion reuses verified group bytes');
let transientManifestReads = 0;
const transientCache = {};
const transientFetch = (url) => {
  if (String(url).endsWith('/manifest.json')) {
    transientManifestReads++;
    if (transientManifestReads === 1) return Promise.resolve(new Response(
      JSON.stringify({ blockNum, groups, transientMismatch: true }), { status: 200 }));
  }
  return fetchImpl(url);
};
assert.equal((await fetchVerifiedLiveRoster({ ...options, fetchImpl: transientFetch,
  rosterContentCache: transientCache })).status, 'mismatch');
assert.equal((await fetchVerifiedLiveRoster({ ...options, fetchImpl: transientFetch,
  rosterContentCache: transientCache })).status, 'verified');
assert.equal(transientManifestReads, 2, 'C と食い違う manifest を控えず取り直す');
const reloadStorageData = new Map();
const reloadStorage = { setItem: (k, v) => reloadStorageData.set(k, v),
  getItem: (k) => reloadStorageData.get(k) || null,
  removeItem: (k) => reloadStorageData.delete(k) };
const firstWithoutUid = await fetchCachedVerifiedLiveRoster({ ...options, groupId: 1, uid: null,
  proofStorage: reloadStorage, cacheStorage: reloadStorage });
assert.equal(firstWithoutUid.status, 'verified');
assert.equal(firstWithoutUid.rosterProofSaved, false);
const afterUidKnown = await fetchCachedVerifiedLiveRoster({ ...options, groupId: 1, uid: 'u4',
  proofStorage: reloadStorage, cacheStorage: reloadStorage });
assert.equal(afterUidKnown.status, 'verified');
assert.equal(afterUidKnown.rosterProofSaved, true,
  'a late identity must cause a fresh proof after the uid-less cached observation');
assert.equal(readVerifiedRosterCache(blockNum, 1, { storage: reloadStorage })?.observedAtMs,
  afterUidKnown.observedAtMs, '開始後の固定ブロック観測時刻をキャッシュから復元する');
assert.equal(loadEvidenceRosterProof(blockNum, 'u4', { storage: reloadStorage })?.C, chainC);
failGroup = 699;
const unavailable = await fetchVerifiedLiveRoster(options);
assert.equal(unavailable.status, 'unavailable');
assert.deepEqual(unavailable.failedGroupIds, [699]);
const failedCache = {};
requests = 0;
groupRequests = 0;
assert.equal((await fetchVerifiedLiveRoster({ ...options, rosterContentCache: failedCache })).status, 'unavailable');
assert.equal(requests, groupCount + 1);
assert.equal((await fetchVerifiedLiveRoster({ ...options, rosterContentCache: failedCache })).status, 'unavailable');
assert.equal(groupRequests, groupCount, 'failed group waits during backoff; verified groups are reused');
failGroup = null;
failedCache.failures.get(699).retryAt = 0;
assert.equal((await fetchVerifiedLiveRoster({ ...options, rosterContentCache: failedCache })).status, 'verified');
assert.equal(groupRequests, groupCount + 1, 'only the failed group is retried');
chainC = `0x${'99'.repeat(32)}`;
assert.equal((await fetchVerifiedLiveRoster(options)).status, 'mismatch');
chainC = commitment.C;
const volatile = await fetchVerifiedLiveRoster({ ...options,
  proofStorage: { setItem: () => { throw new Error('quota'); }, getItem: () => null },
});
assert.equal(volatile.status, 'verified');
assert.equal(volatile.rosterProofSaved, true);
assert.equal(volatile.rosterProofPersistent, false);
const originalFetch = globalThis.fetch;
let recoveryActive = 0;
let recoveryPeak = 0;
let recoveryFail = null;
let recoveryElapsedMs = null;
globalThis.fetch = async (url) => {
  recoveryActive++;
  recoveryPeak = Math.max(recoveryPeak, recoveryActive);
  await new Promise((resolve) => setTimeout(resolve, 1));
  recoveryActive--;
  const key = String(url).split('/').at(-1);
  return new Response(key === `group${recoveryFail}.json` ? '' : files.get(key) || '',
    { status: key === `group${recoveryFail}.json` ? 503 : files.has(key) ? 200 : 404 });
};
try {
  const recoveryStart = performance.now();
  const texts = await fetchAllRosterGroupTexts('https://test.invalid', blockNum,
    { groups }, 1000);
  recoveryElapsedMs = Math.round(performance.now() - recoveryStart);
  assert.equal(texts.size, groupCount);
  assert.equal(buildRosterMemberCommitment({ blockNum, manifestText, groupTexts: texts }).C,
    commitment.C);
  assert.ok(recoveryPeak <= RECOVERY_CONCURRENCY);
  recoveryFail = 699;
  await assert.rejects(fetchAllRosterGroupTexts('https://test.invalid', blockNum,
    { groups }, 1000), /699/);
} finally {
  globalThis.fetch = originalFetch;
}
console.log(`t4-3-roster-unit: all checks passed (2100 members, ${groupCount} groups, official=${elapsedMs}ms/peak=${peak}, recovery=${recoveryElapsedMs}ms/peak=${recoveryPeak}, injected fetch failure=1/${groupCount})`);

// 証明高の状態が型付きで読めなかった場合だけの公開値照合。
// R2もPVの自称する高さ/アドレスも、読取先の選択には使わない。
import { encodeAbiParameters, keccak256, parseAbiItem } from 'viem';
import { ArchiveUnavailableError } from './archive.js';
import { LogReadBudget } from './chain.js';
import { CLAIM_DATA_PUBLISHED_EVENT, runningHashOf } from './claim-data.js';
import { EVIDENCE_ABI, HASH_STORAGE_ABI, TOKEN_MINING_ABI, PREV_REGISTRATION_SENTINEL } from '../../Hardhat/bitcoinu/scripts/lib/zkp-pipeline.mjs';
import { rosterAnchorKey } from '../vendor/workers/game_workers/lib/roster-anchor-rule.js';

const ZERO = `0x${'00'.repeat(32)}`;
const ZERO_ADDRESS = `0x${'00'.repeat(20)}`;
const RESULT_EVENT = parseAbiItem('event ResultHashRegistered(uint256 indexed blockNumber, bytes32 hash, address signer, bool isUpdate, uint256 updatedAt, uint256 registrationCount)');
const LOCK_SET = parseAbiItem('event EthLockSet(address indexed ethLock)');
const LOCK_ABI = [
  parseAbiItem('function ethLock() view returns (address)'),
  parseAbiItem('function START_TIME() view returns (uint256)'),
  parseAbiItem('function BLOCK_INTERVAL() view returns (uint256)'),
  parseAbiItem('function calculateBlockReward(uint256) view returns (uint256)'),
];
const DEPLOYMENT_TYPES = ['uint256', 'address', 'uint256', 'uint256', 'uint256', 'address', 'address', 'address'].map((type) => ({ type }));
const WINDOW_ABI = [parseAbiItem('function resultWindow(uint256) view returns (uint256 openAt, uint256 closeAt)')];
export const WORD_CHECK_RPC_LIMIT = 48;
// uint256の件数でも二分探索は最大256行。件数・境界行・同一高ログ等の余裕を含む。
export const WORD_CHECK_WORD_RPC_LIMITS = Object.freeze({
  blockNum: 48, merkleRoot: 48, applicantHash: 48, applicantHashUpdatedBlock: 48,
  randaoEthBlockNumber: 48, randaoBlockHash: 48, evidenceAcc: 48, entryAcc: 48,
  evidenceGraceSec: 48, resultManifestHash: 264, prevResultManifestHash: 48,
  rosterManifestHash: 264, claimDataHash: 48, deploymentParamsHash: 48,
});
const SHARED_RPC_LIMIT = 5; // head・proof見出し・Evidence/HashStorage配線・resultWindowだけ。
export const WORD_CHECK_TOTAL_RPC_LIMIT = SHARED_RPC_LIMIT
  + Object.values(WORD_CHECK_WORD_RPC_LIMITS).reduce((sum, limit) => sum + limit, 0);
export const ETH_LOCK_LOG_RPC_LIMIT = 128;
const lower = (v) => String(v).toLowerCase();
const value = (row, index, name) => row?.[name] ?? row?.[index];

function unavailable(reason) { throw Object.assign(new Error(reason), { wordReason: reason }); }

export async function compareProofWords({ chain, blockNum, root, event, actual,
  prevRegistrationIndex, report, confirmationBlocks = 64, unavailableError }) {
  if (!(unavailableError instanceof ArchiveUnavailableError)) throw new TypeError('typed historical failure required');
  const height = BigInt(event.evtBlock), bn = BigInt(blockNum);
  const expected = {}, sources = {}, unresolved = {}, mismatches = [];
  const counts = {};
  const byWord = Object.fromEntries(Object.entries(WORD_CHECK_WORD_RPC_LIMITS)
    .map(([name, limit]) => [name, { total: 0, limit }]));
  const shared = { total: 0, limit: SHARED_RPC_LIMIT };
  let activeWords = null;
  const lockLogBudget = new LogReadBudget(ETH_LOCK_LOG_RPC_LIMIT);
  let lockLogCalls = 0;
  let calls = 0;
  const rpc = async (method, request) => {
    const budgets = activeWords ? activeWords.map((name) => byWord[name]) : [shared];
    if (calls >= WORD_CHECK_TOTAL_RPC_LIMIT || budgets.some((budget) => budget.total >= budget.limit)) unavailable('read_budget_exceeded');
    for (const budget of budgets) budget.total++;
    calls++; counts[method] = (counts[method] || 0) + 1;
    return chain.client[method](request);
  };
  const attempt = async (names, source, fn) => {
    activeWords = names;
    try {
      const values = await fn();
      for (const name of names) {
        expected[name] = values[name]; sources[name] = source;
        if (lower(actual[name]) !== lower(values[name])) mismatches.push({ name,
          actual: String(actual[name]), expected: String(values[name]) });
      }
      return values;
    } catch (error) {
      if (error.invalidSentinel) {
        for (const name of names) {
          sources[name] = source;
          mismatches.push({ name, actual: String(actual[name]), reason: 'sentinel_registration_before_proof' });
        }
        return null;
      }
      for (const name of names) unresolved[name] = error instanceof ArchiveUnavailableError
        ? 'archive_unavailable' : error.wordReason || 'rpc_unavailable';
      return null;
    } finally { activeWords = null; }
  };
  // この二語は同じtxの外形照合済み。futureAnchorsHashは別の検査だけで扱う。
  await attempt(['blockNum', 'merkleRoot'], 'iv:proof_calldata_and_root', async () => ({ blockNum: bn, merkleRoot: root }));
  const separate = [{ name: 'futureAnchorsHash', check: 'check.stageC.futureAnchorsHash', reason: 'handled_separately' }];
  let safe, proof;
  try {
    const head = await rpc('getBlockNumber', { cacheTime: 0 });
    safe = head >= 64n ? head - 64n : 0n;
    if (safe < height) unavailable('proof_not_safe');
  } catch (error) { safe = null; }
  try { proof = await rpc('getBlock', { blockNumber: height }); } catch { /* 他の語は続ける */ }
  const read = (address, abi, functionName, args = []) => {
    if (safe == null) unavailable('safe_block_unavailable');
    return rpc('readContract', { address, abi, functionName, args, blockNumber: safe });
  };
  // 配線はset-once。成功したproofはEvidence非ゼロを要する。HSはimmutable。
  let evidence, hashStorage;
  try { evidence = await read(chain.contracts.tokenMining, TOKEN_MINING_ABI, 'evidence'); } catch { /* 各語へ理由 */ }
  try { hashStorage = await read(chain.contracts.tokenMining, TOKEN_MINING_ABI, 'hashStorage'); } catch { /* 各語へ理由 */ }
  const ev = (fn, args = [bn], abi = EVIDENCE_ABI) => {
    if (!evidence || lower(evidence) === ZERO_ADDRESS) unavailable('evidence_unavailable');
    return read(evidence, abi, fn, args);
  };
  const hs = (fn, args) => {
    if (!hashStorage) unavailable('hash_storage_unavailable');
    return read(hashStorage, HASH_STORAGE_ABI, fn, args);
  };
  const passed = (id) => report?.get(id)?.status === 'pass' ? report.get(id).params : null;
  // Stage A/BのPASSだけを採用する。公開selectionの値を直接使わない。
  const registration = await attempt(['applicantHash', 'applicantHashUpdatedBlock'], 'iii:stageA_B_registration', async () => {
    const a = passed('check.stageA.rootMatch'), b = passed('check.stageB.hashRegisteredBlock');
    const hash = passed('check.stageB.applicantHashField');
    if (!a || !b || !hash || b.membership !== true || b.onchain == null
      || BigInt(b.onchain) >= height) unavailable('registration_not_verified_before_proof');
    return { applicantHash: hash.onchain, applicantHashUpdatedBlock: BigInt(b.onchain) };
  });
  await attempt(['randaoEthBlockNumber', 'randaoBlockHash'], 'iii:stageB_header', async () => {
    const target = passed('check.stageB.targetBlockNum'), header = passed('check.stageB.targetBlockHash');
    if (!registration || !target || !header || !passed('check.stageB.confirmationBlocks')) unavailable('randao_prerequisite_unverified');
    const number = registration.applicantHashUpdatedBlock + BigInt(confirmationBlocks);
    if (BigInt(target.expected) !== number || number >= height) unavailable('randao_prerequisite_unverified');
    return { randaoEthBlockNumber: number, randaoBlockHash: header.onchain };
  });
  // 現在の窓がproofまでに閉じていれば、submitResult/extendGraceは以後書けない。
  let window;
  try { window = await ev('resultWindow', [bn], WINDOW_ABI); } catch { /* 依存する語だけ未検証 */ }
  const closed = () => {
    if (!proof) unavailable('proof_header_unavailable');
    if (!window) unavailable('result_window_unavailable');
    if (BigInt(proof.timestamp) < BigInt(value(window, 1, 'closeAt'))) unavailable('window_not_closed_at_proof');
  };
  await attempt(['evidenceAcc'], 'i:closed_result_window', async () => {
    closed(); return { evidenceAcc: await ev('evidenceAcc') };
  });
  await attempt(['entryAcc'], 'i:pure_zero', async () => ({ entryAcc: await ev('entryAcc') }));
  const grace = await attempt(['evidenceGraceSec'], 'i:closed_chat_window', async () => {
    closed(); return { evidenceGraceSec: await ev('currentGrace') };
  });
  // 結果履歴を二分探索する。件数に比例する走査はせず、全RPCに上限を設ける。
  const rows = new Map();
  const resultRow = async (n, i) => {
    const key = `${n}:${i}`;
    if (!rows.has(key)) rows.set(key, await hs('resultRegistrationAt', [n, i]));
    return rows.get(key);
  };
  const logCache = new Map();
  const beforeProof = async (row, n, index) => {
    const block = BigInt(value(row, 1, 'registeredBlock'));
    if (block !== height) return block < height;
    if (event.logIndex == null) unavailable('same_block_order_unavailable');
    const key = n.toString();
    if (!logCache.has(key)) logCache.set(key, await rpc('getLogs', {
      address: hashStorage, event: RESULT_EVENT, args: { blockNumber: n }, fromBlock: height, toBlock: height,
    }));
    const logs = logCache.get(key).filter((l) => BigInt(l.args?.registrationCount ?? -1) === index + 1n);
    const log = logs[0];
    if (logs.length !== 1 || lower(log.args.hash) !== lower(value(row, 0, 'hash'))
      || log.removed || log.blockNumber == null || BigInt(log.blockNumber) !== height
      || log.logIndex == null || !Number.isSafeInteger(Number(log.logIndex)) || Number(log.logIndex) < 0
      || !Number.isSafeInteger(Number(event.logIndex)) || Number(event.logIndex) < 0
      || Number(log.logIndex) === Number(event.logIndex)) unavailable('same_block_order_unavailable');
    return Number(log.logIndex) < Number(event.logIndex);
  };
  await attempt(['resultManifestHash'], 'ii:last_result_registration_before_proof', async () => {
    let lo = 0n, hi = BigInt(await hs('resultRegistrationCount', [bn]));
    while (lo < hi) {
      const mid = (lo + hi) / 2n;
      if (await beforeProof(await resultRow(bn, mid), bn, mid)) lo = mid + 1n; else hi = mid;
    }
    return { resultManifestHash: lo ? value(await resultRow(bn, lo - 1n), 0, 'hash') : ZERO };
  });
  await attempt(['prevResultManifestHash'], prevRegistrationIndex === PREV_REGISTRATION_SENTINEL
    ? 'ii:no_previous_registration_before_proof' : 'ii:calldata_named_previous_registration', async () => {
    if (bn === 0n) return { prevResultManifestHash: ZERO };
    const count = BigInt(await hs('resultRegistrationCount', [bn - 1n]));
    if (prevRegistrationIndex === PREV_REGISTRATION_SENTINEL) {
      // 追記順なので、最初の登録より前なら件数は0。後続登録で番兵を偽FAILにしない。
      if (count > 0n && await beforeProof(await resultRow(bn - 1n, 0n), bn - 1n, 0n)) {
        throw Object.assign(new Error('sentinel_registration_before_proof'), { invalidSentinel: true });
      }
      return { prevResultManifestHash: ZERO };
    }
    if (prevRegistrationIndex == null || prevRegistrationIndex >= count) unavailable('named_registration_unavailable');
    const row = await resultRow(bn - 1n, prevRegistrationIndex);
    if (!await beforeProof(row, bn - 1n, prevRegistrationIndex)) unavailable('named_registration_after_proof');
    return { prevResultManifestHash: value(row, 0, 'hash') };
  });
  await attempt(['rosterManifestHash'], 'ii:canonical_roster_registration_before_start_and_proof', async () => {
    if (!grace) unavailable('grace_unverified');
    const start = BigInt(await ev('scheduledGameStart'));
    const end = start + BigInt(grace.evidenceGraceSec), key = rosterAnchorKey(blockNum);
    let lo = 0n, hi = BigInt(await hs('otherRegistrationCount', [key]));
    const cache = new Map();
    const rowAt = async (i) => {
      if (!cache.has(i)) cache.set(i, await hs('otherRegistrationAt', [key, i]));
      return cache.get(i);
    };
    while (lo < hi) {
      const mid = (lo + hi) / 2n, row = await rowAt(mid);
      // startより前の秒の登録だけなので、閉鎖後のproofと同じ高さにはならない。
      if (BigInt(value(row, 2, 'registeredAt')) < end && BigInt(value(row, 1, 'registeredBlock')) < height) lo = mid + 1n;
      else hi = mid;
    }
    const row = lo ? await rowAt(lo - 1n) : null;
    return { rosterManifestHash: row && BigInt(value(row, 2, 'registeredAt')) >= start ? value(row, 0, 'hash') : ZERO };
  });
  await attempt(['claimDataHash'], 'iv:claim_chunks_published_before_proof', async () => {
    const tm = chain.contracts.tokenMining;
    const ref = await read(tm, TOKEN_MINING_ABI, 'claimDataOf', [bn]);
    const blocks = await read(tm, TOKEN_MINING_ABI, 'getClaimDataBlocks', [bn]);
    const total = Number(value(ref, 1, 'chunks'));
    if (!total || total !== Number(value(ref, 2, 'received')) || total !== blocks.length) unavailable('claim_series_incomplete');
    // 再起動/無効化後の現在値を古いproofへ当てない。
    if (blocks.some((b) => BigInt(b) > height)) unavailable('claim_series_replaced_after_proof');
    const logs = [];
    for (const block of new Set(blocks.map(String))) logs.push(...await rpc('getLogs', {
      address: tm, event: CLAIM_DATA_PUBLISHED_EVENT, args: { blockNum: bn }, fromBlock: BigInt(block), toBlock: BigInt(block),
    }));
    const chunks = [];
    for (let i = 0; i < total; i++) {
      const log = logs.filter((l) => BigInt(l.blockNumber) === BigInt(blocks[i])
        && Number(l.args.chunkIndex) === i && Number(l.args.totalChunks) === total)
        .sort((a, b) => Number(a.logIndex) - Number(b.logIndex)).at(-1);
      if (!log) unavailable('claim_chunk_unavailable');
      if (BigInt(log.blockNumber) === height && (event.logIndex == null || Number(log.logIndex) >= Number(event.logIndex))) unavailable('claim_series_replaced_after_proof');
      chunks.push(Buffer.from(log.args.data.slice(2), 'hex'));
      if (lower(runningHashOf(chunks)) !== lower(log.args.runningHash)) unavailable('claim_series_not_linked');
    }
    const hash = runningHashOf(chunks);
    if (lower(hash) !== lower(value(ref, 0, 'dataHash'))) unavailable('claim_series_not_linked');
    return { claimDataHash: hash };
  });
  await attempt(['deploymentParamsHash'], 'i:immutable_parameters_and_proven_set_once_wiring', async () => {
    const tm = chain.contracts.tokenMining;
    const lock = await read(tm, LOCK_ABI, 'ethLock');
    let lockAtProof = lock, startTime;
    const getStartTime = async () => startTime ??= BigInt(await read(tm, LOCK_ABI, 'START_TIME'));
    if (lower(lock) !== ZERO_ADDRESS) {
      const scan = async (fromBlock, toBlock) => {
        for (let to = toBlock; to >= fromBlock; to -= 1000n) {
          const from = to - 999n > fromBlock ? to - 999n : fromBlock;
          lockLogCalls++;
          const logs = await chain.client.getLogs({ address: tm, event: LOCK_SET,
            fromBlock: from, toBlock: to }, { budget: lockLogBudget, reverse: true, stopOnLogs: true });
          for (const log of logs) {
            if (lower(log.address) !== lower(tm) || lower(log.args?.ethLock) !== lower(lock)
              || log.removed || log.blockNumber == null || BigInt(log.blockNumber) < from || BigInt(log.blockNumber) > to) {
              unavailable('ethLock_set_time_unproven');
            }
          }
          if (logs.length) return logs[0]; // set-onceなので、存在の証明だけで十分。
        }
        return null;
      };
      let setLog = await scan(height > 1999n ? height - 1999n : 1n, height);
      if (!setLog) {
        // immutable の応募開始を使う。公開ファイルやPVの自称値から窓を作らない。
        const start = Number(await getStartTime());
        const from = BigInt(await chain.findBlockByTimestamp(start - 7 * 86400));
        const to = BigInt(await chain.findBlockByTimestamp(start + 86400));
        setLog = await scan(from > 0n ? from : 1n, to);
      }
      if (!setLog) unavailable('ethLock_set_time_unproven');
      const setHeight = BigInt(setLog.blockNumber);
      if (setHeight === height && (event.logIndex == null || setLog.logIndex == null)) unavailable('same_block_order_unavailable');
      if (setHeight === height && Number(setLog.logIndex) === Number(event.logIndex)) unavailable('ethLock_set_time_unproven');
      if (setHeight > height || (setHeight === height && Number(setLog.logIndex) > Number(event.logIndex))) lockAtProof = ZERO_ADDRESS;
    }
    if (lockAtProof === ZERO_ADDRESS && lower(lock) !== ZERO_ADDRESS) {
      // TokenMining.deploymentParamsHash と同じ abi.encode の順序。設定後のgetterを
      // 古いproofへ流用せず、設定前のethLock=0で式を再現する。
      if (!evidence || !hashStorage) unavailable('deployment_wiring_unavailable');
      return { deploymentParamsHash: keccak256(encodeAbiParameters(DEPLOYMENT_TYPES, [
        BigInt(await rpc('getChainId')), tm, await getStartTime(),
        await read(tm, LOCK_ABI, 'BLOCK_INTERVAL'), await read(tm, LOCK_ABI, 'calculateBlockReward', [bn]),
        evidence, ZERO_ADDRESS, hashStorage,
      ])) };
    }
    return { deploymentParamsHash: await read(tm, TOKEN_MINING_ABI, 'deploymentParamsHash', [bn]) };
  });
  const verifiedWords = Object.keys(expected).filter((name) => !mismatches.some((m) => m.name === name));
  return { wordwise: true, status: mismatches.length ? 'fail' : Object.keys(unresolved).length ? 'unavailable' : 'pass',
    snapshotBlock: height.toString(), safeBlock: safe?.toString() ?? null,
    verifiedWords, unverifiedWords: Object.entries(unresolved).map(([name, reason]) => ({ name, reason })),
    separateWords: separate, sources, mismatches, rpcReads: { total: calls, limit: WORD_CHECK_TOTAL_RPC_LIMIT, ...counts, shared, byWord,
      ethLockLogs: { total: lockLogBudget.used, calls: lockLogCalls, limit: ETH_LOCK_LOG_RPC_LIMIT } },
    ...(mismatches.length ? { error: 'public_values_mismatch' } : Object.keys(unresolved).length
      ? { error: 'archive_unavailable', unavailableError } : {}),
  };
}

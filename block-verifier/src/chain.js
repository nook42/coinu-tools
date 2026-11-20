// block-verifier/src/chain.js
// チェーン読取（ユーザーが選んだ独立RPC経由 = 信頼アンカー）。viem PublicClient + fallback。
// ABI は正典 Hardhat/bitcoinu/contracts/{HashStorage,TokenMining,Evidence}.sol から転記。
//
// 公開API（createChain(cfg) の戻り）:
//   client, contracts
//   chainId(), getBlock(n), latest(), findBlockByTimestamp(tsSec), estimateRange(startSec,endSec,margin)
//   HashStorage: getApplicantHash(N)→{hash,updated,signer}|null（未登録revert→null）, getResultHash(N),
//                applicantRegistrationCount(N), applicantRegistrationAt(N,i),
//                isApplicantRegistered(N,registeredBlock,hash), resultRegistrationCount(N),
//                resultRegistrationAt(N,i)→{hash,registeredBlock,registeredAt,signer},
//                resultRegistrationHistory(N)→{count,rows[]},
//                applicantHashEvents(N,{fromBlock,toBlock}), resultHashEvents(N,{fromBlock,toBlock})
//   TokenMining: blockStates(N)→{root,verificationStartedAt}, tokenMiningStartTime(), blockInterval(),
//                verificationPeriod(), claimPeriod(), getBlockMode(N), getBlockLifecycle(N),
//                merkleRootEvents(N,{fromBlock,toBlock})
//   Evidence:    evidenceStartTime(), evidenceBlockTime(), gamePeriod(), submitPeriod(), initialGrace(),
//                currentGrace(N,opts), chatWindow(N,opts), resultWindow(N,opts), resultCount(N,opts),
//                blockHashOf(ethBlock,opts),
//                windowFinal(N), resultSubmittedEvents(N,{fromBlock,toBlock})
//   getTimingConstants() … Evidence.START_TIME == TokenMining.START_TIME 不変量検査込み
//
// ※ 2026-07-27: START_TIME の基準は全契約で「ブロック0の応募**開始**」に統一された
//   （旧: TokenMining/EthStake のみ応募終了基準）。両者は同値でなければならず、
//   Evidence の constructor がデプロイ時に強制する（K-S1-003）。
//   命名は tokenMiningStartTime / evidenceStartTime のまま（読み出し元の区別のため）。
// ※ read系の opts.blockNumber で高さ固定読取（evidence-report の safeBlock 再現用）。

import { createPublicClient, http, fallback, parseAbiItem, toFunctionSelector, decodeEventLog } from 'viem';
import { mainnet } from 'viem/chains';
import { getLogs as getLogsAction } from 'viem/actions';
import { displayRpcUrl } from './rpc-privacy.js';
import { archiveProbe, ArchiveUnavailableError, historicalStateFailure, isLogRangeFailure } from './archive.js';
import { LEGACY_HASH_STORAGE_ALLOWLIST } from '../../Hardhat/bitcoinu/scripts/lib/collect-zkp-input.mjs';
import { getLogsAdaptive } from '../vendor/workers/game_workers/lib/getlogs-adaptive.js';

const GETLOGS_CHUNK = 2000; // evidence-reconciler.js と同じチャンク幅
const LEGACY_HASH_STORAGE_SET = new Set(LEGACY_HASH_STORAGE_ALLOWLIST);

export function isLegacyHashStorageAddress(address) {
  return LEGACY_HASH_STORAGE_SET.has(String(address).toLowerCase());
}

function isInternalRpcError(error) {
  return error?.code === -32603
    || (typeof error?.walk === 'function' && Boolean(error.walk((item) =>
      item?.code === -32603
      // viem 2.42 discards the raw code when it wraps -32603 as a revert.
      || (item?.name === 'ContractFunctionRevertedError'
        && /^(internal error|header not found|.*(?:timed out|timeout|rate limit|too many requests|service unavailable|\b429\b|\b503\b).*)$/i
          .test(String(item.reason ?? ''))))));
}

// getLogs を平常時は2,000ブロック幅のまま読み、応答過大のときだけ半分へ割る。
// 第三者検証もサーバーと同じく累計分割数では打ち切らず、1ブロック単位まで到達する。
export async function getLogsChunkedAdaptive(publicClient, {
  address, event, events, args, fromBlock, toBlock,
}, { chunkWidth = GETLOGS_CHUNK, log = () => {} } = {}) {
  const logs = [];
  let from = BigInt(fromBlock);
  const to = BigInt(toBlock);
  while (from <= to) {
    const chunkTo = from + BigInt(chunkWidth - 1) > to ? to : from + BigInt(chunkWidth - 1);
    const chunk = await getLogsAdaptive(
      (f, t) => publicClient.getLogs(events
        ? { address, events, strict: false, fromBlock: f, toBlock: t }
        : { address, event, args, fromBlock: f, toBlock: t }),
      from,
      chunkTo,
      { log },
    );
    logs.push(...chunk);
    from = chunkTo + 1n;
  }
  return logs;
}

// 選択RPCが eth_getLogs を拒否する場合のログ専用フォールバック（mainnet のみ）。
// publicnode 無料枠は範囲・深さに関係なく eth_getLogs を拒否する（403 "Archive requests
// require a personal token"）ことを実測確認済み（2026-07-12）。状態読取（残高・storage・
// resultCount 等）は引き続き選択RPCを使い、ログのみ下記へフォールバックする。
// ログの完全性は選択RPC経由のオンチェーン状態（Evidence.resultCount 等）との突合で
// 検証されるため、フォールバック元の欠落・検閲は検出できる（信頼は選択RPCに残る）。
const LOGS_FALLBACK_RPCS = [
  'https://eth.drpc.org',
  'https://rpc.flashbots.net',
  'https://eth.merkle.io',
];
const LOGS_FALLBACK_CHUNK = 1000; // eth.merkle.io の getLogs 上限（1kブロック）に合わせる

// EthLockSet の有限窓用。失敗したノードへの読みも消費し、再試行で上限を迂回しない。
export class LogReadBudget {
  constructor(limit) { this.limit = limit; this.used = 0; }
  take(count = 1) {
    if (this.used + count > this.limit) {
      throw Object.assign(new Error('ethLock_log_read_budget_exceeded'), { wordReason: 'ethLock_log_read_budget_exceeded' });
    }
    this.used += count;
  }
}

// ---------------------------------------------------------------
// ABI（正典 .sol から。読取に使う関数のみ）
// ---------------------------------------------------------------

// Hardhat/bitcoinu/contracts/HashStorage.sol
const HASH_STORAGE_ABI = [
  { type: 'function', name: 'getOtherHash', stateMutability: 'view',
    inputs: [{ name: 'key', type: 'bytes32' }],
    outputs: [{ name: 'hash', type: 'bytes32' }, { name: 'updated', type: 'uint256' }] },
  { type: 'function', name: 'otherRegistrationCount', stateMutability: 'view',
    inputs: [{ name: 'key', type: 'bytes32' }], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'otherRegistrationAt', stateMutability: 'view',
    inputs: [{ name: 'key', type: 'bytes32' }, { name: 'index', type: 'uint256' }],
    outputs: [{ name: 'hash', type: 'bytes32' }, { name: 'registeredBlock', type: 'uint256' }, { name: 'registeredAt', type: 'uint256' }] },
  { type: 'function', name: 'getApplicantHash', stateMutability: 'view',
    inputs: [{ name: 'blockNumber', type: 'uint256' }],
    outputs: [{ name: 'hash', type: 'bytes32' }, { name: 'updated', type: 'uint256' }, { name: 'signer', type: 'address' }] },
  { type: 'function', name: 'getResultHash', stateMutability: 'view',
    inputs: [{ name: 'blockNumber', type: 'uint256' }],
    outputs: [{ name: 'hash', type: 'bytes32' }, { name: 'updated', type: 'uint256' }, { name: 'signer', type: 'address' }] },
  { type: 'function', name: 'registrationCount', stateMutability: 'view',
    inputs: [{ name: '', type: 'uint256' }], outputs: [{ name: '', type: 'uint256' }] },
  { type: 'function', name: 'applicantRegistrationAt', stateMutability: 'view',
    inputs: [{ name: 'blockNumber', type: 'uint256' }, { name: 'index', type: 'uint256' }],
    outputs: [
      { name: 'hash', type: 'bytes32' },
      { name: 'registeredBlock', type: 'uint256' },
      { name: 'signer', type: 'address' },
    ] },
  { type: 'function', name: 'isApplicantRegistered', stateMutability: 'view',
    inputs: [
      { name: 'blockNumber', type: 'uint256' },
      { name: 'registeredBlock', type: 'uint256' },
      { name: 'hash', type: 'bytes32' },
    ],
    outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'resultRegistrationCount', stateMutability: 'view',
    inputs: [{ name: '', type: 'uint256' }], outputs: [{ name: '', type: 'uint256' }] },
  // HashStorage.resultRegistrationAt（2026-09-22 の追記履歴化）。
  // 🔴 応募者側 `applicantRegistrationAt` は3値だが、こちらは `registeredAt` を足した**4値**で非対称。
  //    正典 HashStorage.resultRegistrationAt の NatSpec どおり、こちらは registeredAt を加えた4値を読む。
  { type: 'function', name: 'resultRegistrationAt', stateMutability: 'view',
    inputs: [{ name: 'blockNumber', type: 'uint256' }, { name: 'index', type: 'uint256' }],
    outputs: [
      { name: 'hash', type: 'bytes32' },
      { name: 'registeredBlock', type: 'uint256' },
      { name: 'registeredAt', type: 'uint256' },
      { name: 'signer', type: 'address' },
    ] },
  { type: 'function', name: 'admin', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'superAdmin', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'pendingSuperAdmin', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'pendingSuperAdminEta', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
];

// HashStorage.ApplicantHashRegistered / ResultHashRegistered
const APPLICANT_HASH_REGISTERED_EVENT = parseAbiItem(
  'event ApplicantHashRegistered(uint256 indexed blockNumber, bytes32 hash, address signer, bool isUpdate, uint256 updatedAt, uint256 registrationCount)'
);
const RESULT_HASH_REGISTERED_EVENT = parseAbiItem(
  'event ResultHashRegistered(uint256 indexed blockNumber, bytes32 hash, address signer, bool isUpdate, uint256 updatedAt, uint256 registrationCount)'
);

// Hardhat/bitcoinu/contracts/TokenMining.sol
const TOKEN_MINING_ABI = [
  { type: 'function', name: 'blockStates', stateMutability: 'view',
    inputs: [{ name: '', type: 'uint256' }],
    outputs: [
      { name: 'merkleRoot', type: 'bytes32' }, { name: 'verificationStartedAt', type: 'uint64' },
      // 2026-08-04: そのブロックを検証した ZKP 世代の index+1（0 = 証明なし＝shadow 期間の提出）
      { name: 'zkEpochPlusOne', type: 'uint32' },
      { name: 'proofAttachedAt', type: 'uint64' },
    ] },
  // ZKP 世代の履歴（現在値だけでなく全世代が state に残る）
  { type: 'function', name: 'vkeyEpochCount', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'vkeyEpochs', stateMutability: 'view',
    inputs: [{ name: '', type: 'uint256' }],
    outputs: [
      { name: 'verifier', type: 'address' }, { name: 'vkey', type: 'bytes32' },
      { name: 'guestSourceHash', type: 'bytes32' },
      { name: 'proposedAt', type: 'uint64' }, { name: 'activatedAt', type: 'uint64' },
    ] },
  { type: 'function', name: 'proofRequired', stateMutability: 'view', inputs: [], outputs: [{ type: 'bool' }] },
  // Q-4: Evidence の配線先（set-once・TokenMining.evidence / setEvidence）。
  //      検証ツールはこれを Evidence アドレスの唯一の権威として使う。
  { type: 'function', name: 'evidence', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  // R26-C4: Lock Reward の**送金先**を決めるのはこの EthLock（`_resolveLockRewardSplit` が
  // `getLock(id).lockOwnerAddress` を読む）。config の値ではなくチェーン値が権威。
  { type: 'function', name: 'ethLock', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'ethStake', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'token', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'hashStorage', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'ethStakeFromBlock', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'getCurrentTimeUnlockedBlock', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'pendingVkey', stateMutability: 'view', inputs: [], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'pendingVerifier', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'pendingGuestSourceHash', stateMutability: 'view', inputs: [], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'pendingProposedAt', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'pendingVkeyEta', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'pendingAnchorProvider', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'admin', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'superAdmin', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'pendingSuperAdmin', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'pendingSuperAdminEta', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'START_TIME', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'BLOCK_INTERVAL', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'MAX_BLOCK_NUM', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'CLAIM_PERIOD', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'verificationPeriod', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'getBlockMode', stateMutability: 'view',
    inputs: [{ name: 'blockNum', type: 'uint256' }], outputs: [{ type: 'uint8' }] },
  { type: 'function', name: 'getBlockLifecycle', stateMutability: 'view',
    inputs: [{ name: 'blockNum', type: 'uint256' }],
    outputs: [
      { name: 'mode', type: 'uint8' }, { name: 'merkleRoot', type: 'bytes32' },
      { name: 'verificationStartedAt', type: 'uint256' }, { name: 'verificationEndsAt', type: 'uint256' },
      { name: 'claimEndsAt', type: 'uint256' }, { name: 'stage', type: 'uint8' },
    ] },
];
const TOKEN_MINING_BLOCK_STATE_LEGACY_ABI = [{
  type: 'function', name: 'blockStates', stateMutability: 'view',
  inputs: [{ name: 'blockNum', type: 'uint256' }],
  outputs: [
    { name: 'merkleRoot', type: 'bytes32' },
    { name: 'verificationStartedAt', type: 'uint64' },
    { name: 'zkEpochPlusOne', type: 'uint32' },
  ],
}];

// TokenMining.MerkleRootSubmitted
const MERKLE_ROOT_SUBMITTED_EVENT = parseAbiItem(
  'event MerkleRootSubmitted(uint256 indexed blockNum, bytes32 indexed root, uint256 timestamp)'
);
const MERKLE_ROOT_INVALIDATED_EVENT = parseAbiItem(
  'event MerkleRootInvalidated(uint256 indexed blockNum, uint256 timestamp)'
);
const VERIFICATION_EXTENDED_EVENT = parseAbiItem(
  'event VerificationExtended(uint256 indexed blockNum, uint256 newEndFloor)'
);
const MERKLE_ROOT_PROOF_ATTACHED_EVENT = parseAbiItem(
  'event MerkleRootProofAttached(uint256 indexed blockNum, bytes32 indexed root, uint256 indexed epochIndex, uint256 timestamp)'
);

// Hardhat/bitcoinu/contracts/Evidence.sol
const EVIDENCE_ABI = [
  { type: 'function', name: 'TOKEN_MINING', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'HASH_STORAGE', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'MAX_RESULTS_PER_SENDER', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'entryAcc', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'evidenceAcc', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'START_TIME', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'BLOCK_TIME', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'MAX_BLOCK_NUM', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'GAME_PERIOD', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'SUBMIT_PERIOD', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'INITIAL_GRACE', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  // C32F2（C32-B-01）: extendGrace の遡りの許容幅（constructor の第8引数）。C32F2 以前の Evidence には無い。
  { type: 'function', name: 'START_PAST_TOLERANCE', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'currentGrace', stateMutability: 'view',
    inputs: [{ name: 'blockNum', type: 'uint256' }], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'chatWindow', stateMutability: 'view',
    inputs: [{ name: 'blockNum', type: 'uint256' }],
    outputs: [{ name: 'chatOpenAt', type: 'uint256' }, { name: 'chatCloseAt', type: 'uint256' }] },
  { type: 'function', name: 'resultWindow', stateMutability: 'view',
    inputs: [{ name: 'blockNum', type: 'uint256' }],
    outputs: [{ name: 'openAt', type: 'uint256' }, { name: 'closeAt', type: 'uint256' }] },
  { type: 'function', name: 'resultCount', stateMutability: 'view',
    inputs: [{ name: '', type: 'uint256' }], outputs: [{ name: '', type: 'uint256' }] },
  { type: 'function', name: 'windowFinal', stateMutability: 'view',
    inputs: [{ name: 'blockNum', type: 'uint256' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'blockHashOf', stateMutability: 'view',
    inputs: [{ name: 'ethBlock', type: 'uint256' }], outputs: [{ type: 'bytes32' }] },
  { type: 'function', name: 'admin', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'superAdmin', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'pendingSuperAdmin', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'pendingSuperAdminEta', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
];

// C32F2（C32-B-01）: Evidence.START_PAST_TOLERANCE の方針値（決定0: 契約は値を検査しないので、ここが第三者の照合）。
// 値は Hardhat/bitcoinu/scripts/lib/mainnet-parameter-policy.js の3つのプロファイルと同じ
// （block-verifier/test/r15-w11-system-audit-unit.mjs が一致を縛る）。デプロイの期間（TokenMining と Evidence の
// 6値）が本番か block 0 E2E（段1/段2・段3）のプロファイルに一致すれば、その許容幅と完全一致を要求する。いずれでもない
// デプロイ（ローカル試験など）では、ガードが働きうる範囲（1 秒以上・GAME_PERIOD−2 以下）だけを要求する。
// 上限の理由: Extend only（newGrace ≥ 旧＋1）と Chat window closed（今 ≤ 開始＋GAME_PERIOD−1）により
// 遡り（今 − 新しい開始）は GAME_PERIOD−2 を超えられないので、GAME_PERIOD−1 以上ではガードが一度も働かない。
export const START_PAST_TOLERANCE_PROFILES = Object.freeze([
  Object.freeze({
    name: 'production', startPastTolerance: 3600,
    params: Object.freeze({
      blockInterval: 345600, verificationPeriod: 345600, claimPeriod: 3456000,
      gamePeriod: 86400, submitPeriod: 86400, initialGrace: 7200,
    }),
  }),
  Object.freeze({
    name: 'block0-e2e', startPastTolerance: 60,
    params: Object.freeze({
      // W-U-E2E-TIMING3（2026-10-31）: mainnet の固定プロファイルと完全一致。
      blockInterval: 5400, verificationPeriod: 300, claimPeriod: 10800,
      gamePeriod: 1200, submitPeriod: 600, initialGrace: 3000,
    }),
  }),
  Object.freeze({
    name: 'block0-e2e-stage3', startPastTolerance: 180,
    params: Object.freeze({
      // W-C-E2E-S3-TIMING（2026-11-13）: 段3の3時間ブロック。
      blockInterval: 10800, verificationPeriod: 300, claimPeriod: 43200,
      gamePeriod: 3600, submitPeriod: 1200, initialGrace: 3600,
    }),
  }),
]);

export function judgeStartPastTolerance(actual, startPastTolerance) {
  const tolerance = Number(startPastTolerance);
  const profile = START_PAST_TOLERANCE_PROFILES.find((candidate) =>
    Object.entries(candidate.params).every(([key, value]) => actual[key] === value)) || null;
  const inRange = Number.isSafeInteger(tolerance) && tolerance >= 1 && tolerance <= actual.gamePeriod - 2;
  const expected = profile ? String(profile.startPastTolerance) : `1..${actual.gamePeriod - 2}`;
  return {
    ok: inRange && (profile === null || tolerance === profile.startPastTolerance),
    startPastTolerance: String(startPastTolerance),
    profile: profile ? profile.name : 'none',
    expected,
    gamePeriod: actual.gamePeriod,
  };
}

const ETH_LOCK_WIRING_ABI = [{
  type: 'function', name: 'tokenMining', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }],
}];
const ETH_STAKE_TIMING_ABI = [
  { type: 'function', name: 'START_TIME', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'BLOCK_INTERVAL', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'MAX_BLOCK_NUM', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
];
const ERC20_AUDIT_ABI = [
  { type: 'function', name: 'name', stateMutability: 'view', inputs: [], outputs: [{ type: 'string' }] },
  { type: 'function', name: 'symbol', stateMutability: 'view', inputs: [], outputs: [{ type: 'string' }] },
  { type: 'function', name: 'nameChanged', stateMutability: 'view', inputs: [], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'totalSupply', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'balanceOf', stateMutability: 'view', inputs: [{ type: 'address' }], outputs: [{ type: 'uint256' }] },
];
const DONATE_SUPER_ADMIN_CHANGED_EVENT = parseAbiItem(
  'event SuperAdminChanged(address oldSuperAdmin, address newSuperAdmin)'
);
const SUPER_ADMIN_CHANGED_INDEXED_EVENT = parseAbiItem(
  'event SuperAdminChanged(address indexed oldSuperAdmin, address indexed newSuperAdmin)'
);
const ADMIN_CHANGED_INDEXED_EVENT = parseAbiItem(
  'event AdminChanged(address indexed oldAdmin, address indexed newAdmin)'
);
const ADMIN_CHANGED_UNINDEXED_EVENT = parseAbiItem(
  'event AdminChanged(address oldAdmin, address newAdmin)'
);
// viem 2.42 の getLogs(strict:true) はデコード不一致を捨てる。false で原ログを
// 残す（複数 event では空 args によるフィルタも渡さない）。topic0 で ABI を選ぶ
// strict デコードをここで行って既存の走査エラーへ渡す。
function decodeAuthorityChanges(logs, events) {
  return logs.map((log) => ({
    log,
    ...decodeEventLog({ abi: events, topics: log.topics, data: log.data, strict: true }),
  }));
}
const UINT256_MAX = (1n << 256n) - 1n;
const ZERO_BYTES32 = /^0x0{64}$/i;

// Evidence.ResultSubmitted（vendored evidence-reconciler と同一シグネチャ）
const RESULT_SUBMITTED_EVENT = parseAbiItem(
  'event ResultSubmitted(uint256 indexed blockNum, uint256 indexed seq, address indexed sender, bytes data, uint256 timestamp)'
);

// ---------------------------------------------------------------

// revert（未登録等）を null 扱いにするための判定
export function isRevertLike(err, includeDataLess = false) {
  if (typeof err?.walk !== 'function') return false;
  const hit = err.walk((e) => e?.name === 'ContractFunctionRevertedError'
    || e?.name === 'ContractFunctionZeroDataError'
    || (includeDataLess && e?.name === 'ExecutionRevertedError'));
  return !!hit;
}

export function createChain(cfg, ui = null, transportOverride = null) {
  const urls = Array.isArray(cfg.rpcUrls) && cfg.rpcUrls.length
    ? cfg.rpcUrls
    : cfg.rpcPresets.map((p) => p.url);

  const client = createPublicClient({
    // mainnet 以外（Hardhat 31337 等）は chain 定義なしの素の transport で読む
    chain: cfg.chainIdExpected === 1 ? mainnet : undefined,
    transport: transportOverride ?? fallback(urls.map((u) => http(u))),
  });

  let archiveCapability = { status: 'unknown', reason: 'not_probed' };
  const probe = archiveProbe(client, cfg);
  async function probeArchive() {
    archiveCapability = await probe();
    return archiveCapability;
  }
  // vendor経由にも同じ型を渡す。現在state・ログ・ヘッダを先回りして拒否しない。
  for (const method of ['readContract', 'getCode', 'getBlock']) {
    const original = client[method].bind(client);
    client[method] = async (request = {}) => {
      // 数値で固定したsnapshotは、応答時には履歴になりうる。接続時のheadは古くなるため
      // 比較しない。latest等の未固定読取は対象外、失敗の分類自体はRPC応答の構造だけ。
      const historical = request.blockNumber != null;
      try { return await original(request); }
      catch (error) {
        if (historical && historicalStateFailure(error) === 'archive_unavailable') {
          archiveCapability = { ...archiveCapability, status: 'unavailable', reason: 'archive_unavailable' };
          throw new ArchiveUnavailableError(error);
        }
        throw error;
      }
    };
  }

  // --- eth_getLogs のログ専用フォールバック ---
  // client.getLogs を包み替えることで、この client を直接使う vendored コード
  // （evidence-reconciler の fetchResultEvents 等）にも透過的に適用される。
  const rawGetLogs = client.getLogs.bind(client);
  let logsFallback = null;   // 初回成功したフォールバック先に固定（{url, client}）
  let warnedFallback = false;

  function logsRead(target, params, budget, cost = 1) {
    if (!budget) return target.getLogs(params);
    return getLogsAction({ request: (request) => {
      budget.take(cost);
      return target.request(request, { retryCount: 0 });
    } }, params);
  }

  function logsRequestCost(transport) {
    const children = transport.transports ?? transport.value?.transports;
    return children ? children.reduce((total, child) => total + logsRequestCost(child), 0) : 1;
  }

  // 予算なしの固定先・分割・再試行には影響させない。幅は候補ごとに記憶する。
  const budgetPrimary = { client, width: LOGS_FALLBACK_CHUNK };
  let budgetFallbacks;
  async function getBudgetedLogs(cand, params, budget, reverse, stopOnLogs, cost = 1) {
    const { fromBlock, toBlock } = params;
    if (typeof fromBlock !== 'bigint' || typeof toBlock !== 'bigint') return logsRead(cand.client, params, budget, cost);
    const logs = [];
    let from = fromBlock, to = toBlock;
    while (from <= to) {
      const width = BigInt(cand.width);
      const f = reverse && to - width + 1n > from ? to - width + 1n : from;
      const t = !reverse && from + width - 1n < to ? from + width - 1n : to;
      try {
        const chunk = await logsRead(cand.client, { ...params, fromBlock: f, toBlock: t }, budget, cost);
        logs.push(...chunk);
        if (stopOnLogs && chunk.length) return logs; // set-onceの存在探索だけで指定する。
        if (reverse) to = f - 1n;
        else from = t + 1n;
      } catch (error) {
        if (!isLogRangeFailure(error) || t - f + 1n <= 100n) throw error;
        cand.width = Math.max(100, Math.floor(Number(t - f + 1n) / 2));
      }
    }
    return logs;
  }

  async function budgetedLogs(params, budget, reverse, stopOnLogs) {
    const failures = [];
    try { return await getBudgetedLogs(budgetPrimary, params, budget, reverse, stopOnLogs, logsRequestCost(client.transport)); }
    catch (error) {
      if (error.wordReason === 'ethLock_log_read_budget_exceeded') throw error;
      failures.push(error);
    }
    if (cfg.chainIdExpected === 1) {
      budgetFallbacks ??= LOGS_FALLBACK_RPCS.map((url) => ({ url, width: LOGS_FALLBACK_CHUNK,
        client: createPublicClient({ chain: mainnet, transport: http(url) }) }));
      // 前の範囲で成功したノードだけに固定しない。失敗したら次の候補を必ず試す。
      for (const cand of budgetFallbacks) {
        try {
          const logs = await getBudgetedLogs(cand, params, budget, reverse, stopOnLogs);
          if (!warnedFallback && ui) {
            ui.warn(ui.t('main.logsFallback', { url: displayRpcUrl(cand.url) }));
            warnedFallback = true;
          }
          return logs;
        } catch (error) {
          if (error.wordReason === 'ethLock_log_read_budget_exceeded') throw error;
          failures.push(error);
        }
      }
    }
    const temporary = failures.find((error) => historicalStateFailure(error) !== 'archive_unavailable');
    if (temporary) throw temporary;
    throw new ArchiveUnavailableError(failures[0]);
  }

  async function getLogsViaFallback(cand, params, budget) {
    const { fromBlock, toBlock } = params;
    // ブロック範囲指定が無い呼び出しはそのまま転送
    if (fromBlock == null || toBlock == null || typeof fromBlock === 'string' || typeof toBlock === 'string') {
      return logsRead(cand.client, params, budget);
    }
    const logs = [];
    let from = BigInt(fromBlock);
    const to = BigInt(toBlock);
    while (from <= to) {
      const chunkTo = from + BigInt(LOGS_FALLBACK_CHUNK - 1) > to ? to : from + BigInt(LOGS_FALLBACK_CHUNK - 1);
      logs.push(...await logsRead(cand.client, { ...params, fromBlock: from, toBlock: chunkTo }, budget));
      from = chunkTo + 1n;
    }
    return logs;
  }

  client.getLogs = async (params, { budget, reverse = false, stopOnLogs = false } = {}) => {
    if (budget) return budgetedLogs(params, budget, reverse, stopOnLogs);
    try {
      return await rawGetLogs(params);
    } catch (primaryErr) {
      if (primaryErr.wordReason === 'ethLock_log_read_budget_exceeded') throw primaryErr;
      if (cfg.chainIdExpected !== 1) throw primaryErr; // Hardhat等はフォールバックしない
      const candidates = logsFallback
        ? [logsFallback]
        : LOGS_FALLBACK_RPCS.map((u) => ({ url: u, client: createPublicClient({ chain: mainnet, transport: http(u) }) }));
      for (const cand of candidates) {
        try {
          const logs = await getLogsViaFallback(cand, params, budget);
          logsFallback = cand;
          if (!warnedFallback && ui) {
            ui.warn(ui.t('main.logsFallback', { url: displayRpcUrl(cand.url) }));
            warnedFallback = true;
          }
          return logs;
        } catch (error) {
          if (error.wordReason === 'ethLock_log_read_budget_exceeded') throw error;
          // 次の候補へ
        }
      }
      // 全滅: 平易なヒントを付けて元エラーを投げる
      const hint = ui ? ui.t('main.logsUnavailable') : 'eth_getLogs failed on the selected RPC and all public fallbacks — use a personal RPC URL (e.g. a free Alchemy/Infura account) as a custom RPC';
      primaryErr.message = `${hint}\n--- original error ---\n${primaryErr.message}`;
      throw primaryErr;
    }
  };

  const contracts = cfg.contracts;

  // opts.blockNumber（Number|BigInt）で高さ固定読取
  function readOpts(opts) {
    const o = {};
    if (opts && opts.blockNumber != null) o.blockNumber = BigInt(opts.blockNumber);
    return o;
  }

  async function read(address, abi, functionName, args = [], opts = undefined) {
    return client.readContract({ address, abi, functionName, args, ...readOpts(opts) });
  }

  // ---------------- 基本 ----------------

  async function chainId() {
    return Number(await client.getChainId());
  }

  async function getBlock(n) {
    return client.getBlock({ blockNumber: BigInt(n) }); // mixHash（RANDAO）含む viem Block
  }

  async function latest() {
    return client.getBlock();
  }

  // デプロイ済みコントラクトコードの取得（存在チェック用。空アドレス→'0x' or undefined）
  async function getCode(address) {
    return client.getCode({ address });
  }

  const deploymentBlockCache = new Map();
  // future blockへのroot前延長もevent replayへ含めるため、contract codeが初めて存在するblockを探す。
  async function findContractDeploymentBlock(address) {
    // 生成高が未確認なら、全履歴をgenesisから走査せず型付き失敗を呼出元へ返す。
    const key = String(address).toLowerCase();
    if (deploymentBlockCache.has(key)) return deploymentBlockCache.get(key);
    const head = await client.getBlockNumber();
    const latestCode = await client.getCode({ address, blockNumber: head });
    if (!latestCode || latestCode === '0x') throw new Error(`contract code not found at ${address}`);
    let lo = 0n;
    let hi = head;
    while (lo < hi) {
      const mid = (lo + hi) / 2n;
      const code = await client.getCode({ address, blockNumber: mid });
      if (code && code !== '0x') hi = mid;
      else lo = mid + 1n;
    }
    deploymentBlockCache.set(key, lo);
    return lo;
  }

  // headから倍々に遡って範囲を絞り、timestamp >= tsSec の最初の高さを返す。
  // 全ブロックが tsSec より古い（未来時刻）なら latest 番号を返す。
  async function findBlockByTimestamp(tsSec) {
    const latestBlock = await client.getBlock();
    if (Number(latestBlock.timestamp) < tsSec) return Number(latestBlock.number);
    let hi = latestBlock.number;
    let lo = hi;
    for (let step = 1n; hi > 0n; step *= 2n) {
      const candidate = latestBlock.number > step ? latestBlock.number - step : 0n;
      const block = await client.getBlock({ blockNumber: candidate });
      if (Number(block.timestamp) < tsSec) { lo = candidate + 1n; break; }
      lo = hi = candidate;
    }
    while (lo < hi) {
      const mid = (lo + hi) / 2n;
      const b = await client.getBlock({ blockNumber: mid });
      if (Number(b.timestamp) < tsSec) lo = mid + 1n;
      else hi = mid;
    }
    return Number(lo);
  }

  // 時刻窓 [startSec, endSec] → イベント走査用 eth ブロック範囲（前後 margin ブロックの余裕）。
  // 範囲の正しさは呼び出し側の完全性検査が担保する（不足時は広げて再試行）。
  async function estimateRange(startSec, endSec, margin = 2000) {
    const latestBlock = await client.getBlock();
    const latestNum = Number(latestBlock.number);
    const fromBase = await findBlockByTimestamp(startSec);
    const toBase = endSec >= Number(latestBlock.timestamp) ? latestNum : await findBlockByTimestamp(endSec);
    const fromBlock = Math.max(0, fromBase - margin);
    const toBlock = Math.min(latestNum, toBase + margin);
    return { fromBlock, toBlock: Math.max(fromBlock, toBlock) };
  }

  // getLogs を平常時2000ブロック幅、応答過大時だけ適応分割で読む。
  async function getLogsChunked({ address, event, events, args, fromBlock, toBlock }) {
    return getLogsChunkedAdaptive(client, { address, event, events, args, fromBlock, toBlock });
  }

  // ---------------- HashStorage ----------------

  async function getApplicantHash(n) {
    try {
      const [hash, updated, signer] = await read(contracts.hashStorage, HASH_STORAGE_ABI, 'getApplicantHash', [BigInt(n)]);
      return { hash, updated: Number(updated), signer };
    } catch (e) {
      if (isRevertLike(e)) return null; // "No hash registered at this block"
      throw e;
    }
  }

  async function getResultHash(n) {
    try {
      const [hash, updated, signer] = await read(contracts.hashStorage, HASH_STORAGE_ABI, 'getResultHash', [BigInt(n)]);
      return { hash, updated: Number(updated), signer };
    } catch (e) {
      if (isRevertLike(e) && !isInternalRpcError(e)) {
        if (isLegacyHashStorage()) return null;
        // 現行契約の未登録だけを null とする。登録済みの現在値読取失敗は保留する。
        if (await resultRegistrationCount(n) === 0) return null;
      }
      throw e;
    }
  }

  async function getOtherHash(key) {
    try {
      const [hash, updated] = await read(contracts.hashStorage, HASH_STORAGE_ABI, 'getOtherHash', [key]);
      return { hash, updated: Number(updated) };
    } catch (e) {
      if (isRevertLike(e)) return null;
      throw e;
    }
  }

  async function otherRegistrationCount(key) {
    try {
      return Number(await read(contracts.hashStorage, HASH_STORAGE_ABI, 'otherRegistrationCount', [key]));
    } catch (error) {
      if (isLegacyHashStorage() && !isInternalRpcError(error)
          && isRevertLike(error, true)) return null; // legacy HashStorage
      throw error;
    }
  }

  async function otherRegistrationAt(key, index) {
    const [hash, registeredBlock, registeredAt] = await read(
      contracts.hashStorage, HASH_STORAGE_ABI, 'otherRegistrationAt', [key, BigInt(index)],
    );
    return { hash, registeredBlock: Number(registeredBlock), registeredAt: Number(registeredAt) };
  }

  async function firstOtherRegistration(key) {
    let countRaw;
    try { countRaw = await read(contracts.hashStorage, HASH_STORAGE_ABI, 'otherRegistrationCount', [key]); }
    catch (error) {
      if (isLegacyHashStorage() && !isInternalRpcError(error)
          && isRevertLike(error, true)) return null; // 旧契約の getter 不在
      throw error;
    }
    const count = Number(countRaw);
    if (!Number.isSafeInteger(count) || count < 0) throw new Error('invalid other registration count');
    if (count === 0) return null;
    const [hash, registeredBlock, registeredAt] = await read(
      contracts.hashStorage, HASH_STORAGE_ABI, 'otherRegistrationAt', [key, 0n],
    );
    return { hash, registeredBlock: Number(registeredBlock), registeredAt: Number(registeredAt), count };
  }

  async function firstMatchingOtherRegistration(key, earliestAt, expectedHash) {
    let countRaw;
    try { countRaw = await read(contracts.hashStorage, HASH_STORAGE_ABI, 'otherRegistrationCount', [key]); }
    catch (error) {
      if (isLegacyHashStorage() && !isInternalRpcError(error)
          && isRevertLike(error, true)) return null;
      throw error;
    }
    const count = Number(countRaw);
    if (!Number.isSafeInteger(count) || count < 0) throw new Error('invalid other registration count');
    const at = async (index) => {
      const [hash, registeredBlock, registeredAt] = await read(
        contracts.hashStorage, HASH_STORAGE_ABI, 'otherRegistrationAt', [key, BigInt(index)],
      );
      return { hash, registeredBlock: Number(registeredBlock), registeredAt: Number(registeredAt), index };
    };
    let low = 0;
    let high = count;
    while (low < high) {
      const mid = Math.floor((low + high) / 2);
      if ((await at(mid)).registeredAt < earliestAt) low = mid + 1;
      else high = mid;
    }
    for (let index = low; index < count; index++) {
      const row = await at(index);
      if (!expectedHash || row.hash.toLowerCase() === expectedHash.toLowerCase()) return { ...row, count };
    }
    return null;
  }

  async function applicantRegistrationCount(n) {
    return Number(await read(contracts.hashStorage, HASH_STORAGE_ABI, 'registrationCount', [BigInt(n)]));
  }

  async function applicantRegistrationAt(n, index) {
    const [hash, registeredBlock, signer] = await read(
      contracts.hashStorage,
      HASH_STORAGE_ABI,
      'applicantRegistrationAt',
      [BigInt(n), BigInt(index)],
    );
    return { hash, registeredBlock: Number(registeredBlock), signer };
  }

  async function isApplicantRegistered(n, registeredBlock, hash) {
    return Boolean(await read(
      contracts.hashStorage,
      HASH_STORAGE_ABI,
      'isApplicantRegistered',
      [BigInt(n), BigInt(registeredBlock), hash],
    ));
  }

  function isLegacyHashStorage() {
    return isLegacyHashStorageAddress(contracts.hashStorage);
  }

  async function resultRegistrationCount(n) {
    return Number(await read(contracts.hashStorage, HASH_STORAGE_ABI, 'resultRegistrationCount', [BigInt(n)]));
  }

  // 結果ハッシュの追記履歴を添字で読む（応募者側 applicantRegistrationAt と同じ形にそろえる。
  // 違いは 4値目 registeredAt が在ることだけ）。
  // この getter は履歴の権威。大量履歴の候補探索は resultHashEvents で範囲を集めるが、
  // ログ専用フォールバックの行を候補・採用・照合に使う前に、この状態 getter と
  // hash / registeredBlock / signer を突き合わせる。registeredAt は event に無いため getter から得る。
  // event の registrationCount は加算後の値なので、状態の添字は count - 1。
  async function resultRegistrationAt(n, index) {
    const [hash, registeredBlock, registeredAt, signer] = await read(
      contracts.hashStorage,
      HASH_STORAGE_ABI,
      'resultRegistrationAt',
      [BigInt(n), BigInt(index)],
    );
    return {
      hash,
      registeredBlock: Number(registeredBlock),
      registeredAt: Number(registeredAt),
      signer,
    };
  }

  // 追記履歴を全件読む。現在値（getResultHash）がどの行かを知るための土台。
  // 読めない添字が1つでもあれば throw（fail-closed。部分履歴を「全部」と名乗らせない）。
  async function resultRegistrationHistory(n) {
    const count = Number(await resultRegistrationCount(n));
    if (!Number.isSafeInteger(count) || count < 0) {
      throw new Error(`invalid resultRegistrationCount(${n}): ${count}`);
    }
    const rows = [];
    for (let index = 0; index < count; index++) {
      rows.push({ index, ...(await resultRegistrationAt(n, index)) });
    }
    return { count, rows };
  }

  function mapHashRegisteredLog(log) {
    return {
      blockNumber: Number(log.args.blockNumber),
      hash: log.args.hash,
      signer: log.args.signer,
      isUpdate: log.args.isUpdate,
      updatedAt: Number(log.args.updatedAt), // 登録時の eth block.number
      registrationCount: Number(log.args.registrationCount),
      evtBlock: Number(log.blockNumber),
      txHash: log.transactionHash,
    };
  }

  async function applicantHashEvents(n, { fromBlock, toBlock }) {
    const logs = await getLogsChunked({
      address: contracts.hashStorage, event: APPLICANT_HASH_REGISTERED_EVENT,
      args: { blockNumber: BigInt(n) }, fromBlock, toBlock,
    });
    return logs.map(mapHashRegisteredLog);
  }

  async function resultHashEvents(n, { fromBlock, toBlock }) {
    const logs = await getLogsChunked({
      address: contracts.hashStorage, event: RESULT_HASH_REGISTERED_EVENT,
      args: { blockNumber: BigInt(n) }, fromBlock, toBlock,
    });
    return logs.map(mapHashRegisteredLog);
  }

  // ---------------- TokenMining ----------------

  async function blockStates(n, opts) {
    let state;
    try {
      state = await read(contracts.tokenMining, TOKEN_MINING_ABI, 'blockStates', [BigInt(n)], opts);
    } catch (currentError) {
      try {
        state = await read(contracts.tokenMining, TOKEN_MINING_BLOCK_STATE_LEGACY_ABI, 'blockStates', [BigInt(n)], opts);
      } catch {
        throw currentError;
      }
    }
    const [root, verificationStartedAt, zkEpochPlusOne, proofAttachedAt = 0n] = state;
    // root===0x00…00 は未提出 / zkEpochPlusOne===0 は「証明なしで提出された」
    return {
      root, verificationStartedAt: Number(verificationStartedAt),
      zkEpochPlusOne: Number(zkEpochPlusOne), proofAttachedAt: Number(proofAttachedAt),
    };
  }

  // ---- ZKP 世代（2026-08-04） ----

  async function proofRequired() {
    return await read(contracts.tokenMining, TOKEN_MINING_ABI, 'proofRequired');
  }

  /// 指定された1世代だけを読む。ブロック単体検証で全世代を総当たりしないための入口。
  async function vkeyEpoch(index) {
    if (!Number.isInteger(index) || index < 0) throw new Error(`invalid ZKP epoch index: ${index}`);
    const [verifier, vkey, guestSourceHash, proposedAt, activatedAt] =
      await read(contracts.tokenMining, TOKEN_MINING_ABI, 'vkeyEpochs', [BigInt(index)]);
    return { index, verifier, vkey, guestSourceHash,
             proposedAt: Number(proposedAt), activatedAt: Number(activatedAt) };
  }

  /// 全世代を古い順に返す。契約が現在値だけでなく履歴を state に残しているので、
  /// 「前に見たときから変わったか」ではなく**過去すべて**を提示できる。
  async function vkeyEpochs() {
    const n = Number(await read(contracts.tokenMining, TOKEN_MINING_ABI, 'vkeyEpochCount'));
    const out = [];
    for (let i = 0; i < n; i++) {
      out.push(await vkeyEpoch(i));
    }
    return out;
  }

  async function pendingVkeyProposal() {
    const eta = await read(contracts.tokenMining, TOKEN_MINING_ABI, 'pendingVkeyEta');
    if (eta === 0n) return { pending: false, eta: 0 };
    const [verifier, vkey, guestSourceHash, proposedAt, anchorProvider] = await Promise.all([
      read(contracts.tokenMining, TOKEN_MINING_ABI, 'pendingVerifier'),
      read(contracts.tokenMining, TOKEN_MINING_ABI, 'pendingVkey'),
      read(contracts.tokenMining, TOKEN_MINING_ABI, 'pendingGuestSourceHash'),
      read(contracts.tokenMining, TOKEN_MINING_ABI, 'pendingProposedAt'),
      read(contracts.tokenMining, TOKEN_MINING_ABI, 'pendingAnchorProvider'),
    ]);
    return { pending: true, verifier, vkey, guestSourceHash,
      proposedAt: Number(proposedAt), eta: Number(eta), anchorProvider };
  }

  async function tokenMiningStartTime() {
    return Number(await read(contracts.tokenMining, TOKEN_MINING_ABI, 'START_TIME'));
  }

  async function blockInterval() {
    return Number(await read(contracts.tokenMining, TOKEN_MINING_ABI, 'BLOCK_INTERVAL'));
  }

  async function maxBlockNum() {
    return Number(await read(contracts.tokenMining, TOKEN_MINING_ABI, 'MAX_BLOCK_NUM'));
  }

  async function verificationPeriod() {
    return Number(await read(contracts.tokenMining, TOKEN_MINING_ABI, 'verificationPeriod'));
  }

  async function claimPeriod() {
    return Number(await read(contracts.tokenMining, TOKEN_MINING_ABI, 'CLAIM_PERIOD'));
  }

  async function getBlockMode(n) {
    return Number(await read(contracts.tokenMining, TOKEN_MINING_ABI, 'getBlockMode', [BigInt(n)])); // 0=AdminCommit 1=EthStake
  }

  async function getBlockLifecycle(n) {
    const [mode, merkleRoot, verificationStartedAt, verificationEndsAt, claimEndsAt, stage] =
      await read(contracts.tokenMining, TOKEN_MINING_ABI, 'getBlockLifecycle', [BigInt(n)]);
    return {
      mode: Number(mode), merkleRoot,
      verificationStartedAt: Number(verificationStartedAt),
      verificationEndsAt: Number(verificationEndsAt),
      claimEndsAt: Number(claimEndsAt),
      stage: Number(stage), // 0=未アンロック 1=ルート未提出 2=検証中 3=請求期間 4=クローズ
    };
  }

  async function merkleRootEvents(n, { fromBlock, toBlock }) {
    const logs = await getLogsChunked({
      address: contracts.tokenMining, event: MERKLE_ROOT_SUBMITTED_EVENT,
      args: { blockNum: BigInt(n) }, fromBlock, toBlock,
    });
    return logs.map((log) => ({
      blockNum: Number(log.args.blockNum),
      root: log.args.root,
      timestamp: Number(log.args.timestamp),
      evtBlock: Number(log.blockNumber),
      transactionIndex: Number(log.transactionIndex),
      logIndex: Number(log.logIndex ?? log.index),
      txHash: log.transactionHash,
    }));
  }

  async function verificationExtendedEvents(n, { fromBlock, toBlock }) {
    const logs = await getLogsChunked({
      address: contracts.tokenMining, event: VERIFICATION_EXTENDED_EVENT,
      args: { blockNum: BigInt(n) }, fromBlock, toBlock,
    });
    const timestamps = new Map();
    for (const number of new Set(logs.map((log) => BigInt(log.blockNumber)))) {
      try {
        const block = await client.getBlock({ blockNumber: number });
        timestamps.set(number.toString(), Number(block.timestamp));
      } catch (error) {
        if (!(error instanceof ArchiveUnavailableError)) throw error;
        timestamps.set(number.toString(), error);
      }
    }
    return logs.map((log) => ({
      blockNum: Number(log.args.blockNum), newEndFloor: Number(log.args.newEndFloor),
      ...(timestamps.get(BigInt(log.blockNumber).toString()) instanceof ArchiveUnavailableError
        ? { timestamp: null, timestampError: timestamps.get(BigInt(log.blockNumber).toString()) }
        : { timestamp: timestamps.get(BigInt(log.blockNumber).toString()) }),
      evtBlock: Number(log.blockNumber), transactionIndex: Number(log.transactionIndex),
      logIndex: Number(log.logIndex ?? log.index), txHash: log.transactionHash,
    }));
  }

  async function merkleRootInvalidatedEvents(n, { fromBlock, toBlock }) {
    const logs = await getLogsChunked({
      address: contracts.tokenMining, event: MERKLE_ROOT_INVALIDATED_EVENT,
      args: { blockNum: BigInt(n) }, fromBlock, toBlock,
    });
    return logs.map((log) => ({
      blockNum: Number(log.args.blockNum), timestamp: Number(log.args.timestamp),
      evtBlock: Number(log.blockNumber), transactionIndex: Number(log.transactionIndex),
      logIndex: Number(log.logIndex ?? log.index), txHash: log.transactionHash,
    }));
  }

  async function merkleRootProofAttachedEvents(n, { fromBlock, toBlock }) {
    const logs = await getLogsChunked({
      address: contracts.tokenMining, event: MERKLE_ROOT_PROOF_ATTACHED_EVENT,
      args: { blockNum: BigInt(n) }, fromBlock, toBlock,
    });
    return logs.map((log) => ({
      blockNum: Number(log.args.blockNum), root: log.args.root,
      epochIndex: Number(log.args.epochIndex), timestamp: Number(log.args.timestamp),
      evtBlock: Number(log.blockNumber), transactionIndex: Number(log.transactionIndex),
      logIndex: Number(log.logIndex ?? log.index), txHash: log.transactionHash,
    }));
  }

  // ---------------- Evidence ----------------
  //
  // 🔴 Q-4（2026-08-08・ユーザー確定）: **Evidence のアドレスはチェーンから読む。**
  //
  // `TokenMining.evidence` は **set-once**（`TokenMining.evidence` の宣言＋TokenMining.setEvidence の
  // `revert EvidenceAlreadySet()`）で、誰でも view で読める。
  // ＝ 運営が後から差し替えられない**チェーン上の権威**がある。
  //
  // 旧実装は `config.js` に焼いたアドレス（＝ツール同梱の申告値）だけを使っていた。
  // 目録（manifest）側の `rules.evidence.contractAddress` も同様に運営の申告で、
  // 「Evidence は使っていません」という申告ひとつで検査6件が消えていた（Q-4 の根）。
  // ここでチェーン値へ一本化することで、その入口そのものを無くす。
  //
  // `config.js` の `contracts.evidence` は**参考値**として残る（起動時の一覧表示・
  // アドレス乖離の告知に使う）。読取の権威ではない。
  let evidenceAddrCache;
  async function evidenceAddress() {
    if (evidenceAddrCache === undefined) {
      let a = null;
      try { a = await read(contracts.tokenMining, TOKEN_MINING_ABI, 'evidence'); } catch { a = null; }
      // 未配線（0x0）は null に潰す。呼び出し側は「Evidence が無い＝検閲対策の層が無い」として
      // **skip ではなく FAIL** に倒すこと（`stages/results.js` の reproduceEvidence）。
      evidenceAddrCache = (a && !/^0x0{40}$/i.test(a)) ? a : null;
    }
    return evidenceAddrCache;
  }

  // R26-C4: EthLock も **チェーン値が権威**。
  //
  // デポッター葉は `to = address(0)` かつ個別配当額を持たない設計で、送金先と額は
  // 請求時に契約が `ethLock.getLock(id)` を読んで決める（`TokenMining._resolveLockRewardSplit`）。
  // つまり「どの EthLock を見るか」を config 側の固定値で決めていると、
  // 運営が `setEthLock` に別実装（amount/idTo/unlockTime は本物と同じで
  // `depositerAddress` だけ攻撃者）を配線しても、検証ツールは**本物の台帳**を見て PASS を出す。
  // 葉のコミットメントはこの差を検出できない（葉に送金先が入っていないため）。
  let ethLockAddrCache;
  async function ethLockAddress() {
    if (ethLockAddrCache === undefined) {
      let a = null;
      try { a = await read(contracts.tokenMining, TOKEN_MINING_ABI, 'ethLock'); } catch { a = null; }
      // 未配線（0x0）は null。呼び出し側は skip ではなく **FAIL** に倒すこと
      // （root 提出は `require(ethLock != 0)` なので、root があるのに 0x0 は異常）。
      ethLockAddrCache = (a && !/^0x0{40}$/i.test(a)) ? a : null;
    }
    return ethLockAddrCache;
  }

  /// Evidence の read ヘルパー。アドレスはチェーン由来（未配線なら throw）。
  async function evRead(fn, args, opts) {
    const addr = await evidenceAddress();
    if (!addr) throw new Error('TokenMining.evidence() is unset (0x0) — Evidence contract is not wired on chain');
    return read(addr, EVIDENCE_ABI, fn, args, opts);
  }

  async function evidenceStartTime() {
    return Number(await evRead('START_TIME'));
  }

  async function evidenceBlockTime() {
    return Number(await evRead('BLOCK_TIME'));
  }

  async function gamePeriod() { return Number(await evRead('GAME_PERIOD')); }
  async function submitPeriod() { return Number(await evRead('SUBMIT_PERIOD')); }
  async function initialGrace() { return Number(await evRead('INITIAL_GRACE')); }

  async function currentGrace(n, opts) {
    return Number(await evRead('currentGrace', [BigInt(n)], opts));
  }

  async function chatWindow(n, opts) {
    const [chatOpenAt, chatCloseAt] = await evRead('chatWindow', [BigInt(n)], opts);
    return { chatOpenAt: Number(chatOpenAt), chatCloseAt: Number(chatCloseAt) };
  }

  async function resultWindow(n, opts) {
    const [openAt, closeAt] = await evRead('resultWindow', [BigInt(n)], opts);
    return { openAt: Number(openAt), closeAt: Number(closeAt) };
  }

  async function resultCount(n, opts) {
    return Number(await evRead('resultCount', [BigInt(n)], opts));
  }

  async function windowFinal(n) {
    return Boolean(await evRead('windowFinal', [BigInt(n)]));
  }

  async function blockHashOf(ethBlock, opts) {
    return evRead('blockHashOf', [BigInt(ethBlock)], opts);
  }

  async function resultSubmittedEvents(n, { fromBlock, toBlock }) {
    const addr = await evidenceAddress();
    const logs = await getLogsChunked({
      address: addr, event: RESULT_SUBMITTED_EVENT,
      args: { blockNum: BigInt(n) }, fromBlock, toBlock,
    });
    return logs.map((log) => ({
      blockNum: Number(log.args.blockNum),
      seq: Number(log.args.seq),
      sender: log.args.sender,
      data: log.args.data,
      timestamp: Number(log.args.timestamp),
      txHash: log.transactionHash,
      evtBlock: Number(log.blockNumber),
    }));
  }

  async function evidenceAcc(n, opts) {
    return evRead('evidenceAcc', [BigInt(n)], opts);
  }

  // ---------------- タイミング定数（チェーンが正） ----------------

  let timingCache = null;

  // Evidence の宣言タイムライン定数＋TokenMining 側基準時刻。
  // 不変量: Evidence.START_TIME == TokenMining.START_TIME かつ
  //         Evidence.BLOCK_TIME == TokenMining.BLOCK_INTERVAL
  //         （Evidence constructor・deploy.js の検査と同一）。
  async function getTimingConstants() {
    if (timingCache) return timingCache;
    const [evStart, evBlockTime, gp, sp, grace, tmStart, tmInterval, verSec, claimSec] = await Promise.all([
      evidenceStartTime(), evidenceBlockTime(), gamePeriod(), submitPeriod(), initialGrace(),
      tokenMiningStartTime(), blockInterval(), verificationPeriod(), claimPeriod(),
    ]);
    timingCache = {
      startTimeEntryMs: evStart * 1000, // 応募期間【開始】基準（= Evidence.START_TIME*1000）
      blockTimeMs: evBlockTime * 1000,
      gamePeriodMs: gp * 1000,
      submitPeriodMs: sp * 1000,
      initialGraceSec: grace,
      evidenceStartTime: evStart,           // 秒
      tokenMiningStartTime: tmStart,        // 秒（応募【開始】基準・Evidence と同値）
      tokenMiningBlockInterval: tmInterval, // 秒
      verificationPeriodSec: verSec,
      claimPeriodSec: claimSec,
      // 不変量検査結果
      invariantOk: evStart === tmStart,
      blockIntervalMatches: evBlockTime === tmInterval,
    };
    return timingCache;
  }

  // メニュー1のsystemAuditとメニュー3で同じset-once配線を照合する。
  async function hashStorageAddress() {
    return read(contracts.tokenMining, TOKEN_MINING_ABI, 'hashStorage');
  }

  // R26 決定0: 構築時に固定された配線は契約自身へ自己検査を足さず、第三者ツールが
  // 双方向参照・時刻・token実体・本番parameterをまとめて検証する。
  let tokenMetadataCache = null;
  async function tokenMetadata() {
    if (tokenMetadataCache) return tokenMetadataCache;
    const tm = contracts.tokenMining;
    const address = await read(tm, TOKEN_MINING_ABI, 'token');
    // name / symbol / nameChanged は必ず同一ブロックの状態から読む。
    // 改名投票の確定ブロックを跨いだ一過性の不整合を、改ざんとして誤検出しないため。
    const blockNumber = await client.getBlockNumber();
    const atSnapshot = { blockNumber };
    const [name, symbol, nameChanged] = await Promise.all([
      read(address, ERC20_AUDIT_ABI, 'name', [], atSnapshot),
      read(address, ERC20_AUDIT_ABI, 'symbol', [], atSnapshot),
      read(address, ERC20_AUDIT_ABI, 'nameChanged', [], atSnapshot),
    ]);
    const expectedName = nameChanged ? 'Bitcoin' : 'COINU';
    const expectedSymbol = nameChanged ? 'BTC' : 'COINU';
    tokenMetadataCache = {
      address,
      name,
      symbol,
      nameChanged,
      expectedName,
      expectedSymbol,
      metadataOk: name === expectedName && symbol === expectedSymbol,
      blockNumber,
    };
    return tokenMetadataCache;
  }

  let systemAuditCache = null;
  async function systemAudit() {
    if (systemAuditCache) return systemAuditCache;
    const tm = contracts.tokenMining;
    const [evidenceAddr, ethLockAddr, ethStakeAddr, tokenMeta, hashStorageAddr,
      tmStartRaw, tmIntervalRaw, tmMaxBlockRaw, verificationRaw, claimRaw,
      ethStakeFromBlockRaw, currentUnlockedRaw, pendingVkeyRaw, pendingGuestSourceHashRaw, pendingVkeyEtaRaw] = await Promise.all([
      read(tm, TOKEN_MINING_ABI, 'evidence'),
      read(tm, TOKEN_MINING_ABI, 'ethLock'),
      read(tm, TOKEN_MINING_ABI, 'ethStake'),
      tokenMetadata(),
      hashStorageAddress(),
      read(tm, TOKEN_MINING_ABI, 'START_TIME'),
      read(tm, TOKEN_MINING_ABI, 'BLOCK_INTERVAL'),
      read(tm, TOKEN_MINING_ABI, 'MAX_BLOCK_NUM'),
      read(tm, TOKEN_MINING_ABI, 'verificationPeriod'),
      read(tm, TOKEN_MINING_ABI, 'CLAIM_PERIOD'),
      read(tm, TOKEN_MINING_ABI, 'ethStakeFromBlock'),
      read(tm, TOKEN_MINING_ABI, 'getCurrentTimeUnlockedBlock'),
      read(tm, TOKEN_MINING_ABI, 'pendingVkey'),
      read(tm, TOKEN_MINING_ABI, 'pendingGuestSourceHash'),
      read(tm, TOKEN_MINING_ABI, 'pendingVkeyEta'),
    ]);
    const tokenAddr = tokenMeta.address;
    const [evidenceBack, evidenceHashStorage, ethLockBack, ethStakeStartRaw, ethStakeIntervalRaw,
      ethStakeMaxBlockRaw, evidenceMaxBlockRaw, totalSupply, tmTokenBalance,
      gameRaw, submitRaw, graceRaw, startPastToleranceRaw,
      maxResultsPerSenderRaw, entryAccZero, entryAccMax, evidenceCode] = await Promise.all([
      read(evidenceAddr, EVIDENCE_ABI, 'TOKEN_MINING'),
      read(evidenceAddr, EVIDENCE_ABI, 'HASH_STORAGE'),
      read(ethLockAddr, ETH_LOCK_WIRING_ABI, 'tokenMining'),
      read(ethStakeAddr, ETH_STAKE_TIMING_ABI, 'START_TIME'),
      read(ethStakeAddr, ETH_STAKE_TIMING_ABI, 'BLOCK_INTERVAL'),
      read(ethStakeAddr, ETH_STAKE_TIMING_ABI, 'MAX_BLOCK_NUM'),
      read(evidenceAddr, EVIDENCE_ABI, 'MAX_BLOCK_NUM'),
      read(tokenAddr, ERC20_AUDIT_ABI, 'totalSupply', [], { blockNumber: tokenMeta.blockNumber }),
      read(tokenAddr, ERC20_AUDIT_ABI, 'balanceOf', [tm], { blockNumber: tokenMeta.blockNumber }),
      read(evidenceAddr, EVIDENCE_ABI, 'GAME_PERIOD'),
      read(evidenceAddr, EVIDENCE_ABI, 'SUBMIT_PERIOD'),
      read(evidenceAddr, EVIDENCE_ABI, 'INITIAL_GRACE'),
      // C32F2: C32F2 以前の Evidence（getter なし）では読めずに systemAudit 全体が落ち、
      // check.system.auditUnavailable の fail になる（HASH_STORAGE と同じ扱い）。
      read(evidenceAddr, EVIDENCE_ABI, 'START_PAST_TOLERANCE'),
      read(evidenceAddr, EVIDENCE_ABI, 'MAX_RESULTS_PER_SENDER'),
      read(evidenceAddr, EVIDENCE_ABI, 'entryAcc', [0n]),
      read(evidenceAddr, EVIDENCE_ABI, 'entryAcc', [BigInt(tmMaxBlockRaw)]),
      getCode(evidenceAddr),
    ]);
    const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();
    const expectedSupply = 21_000_000n * (10n ** 18n);
    const tokenMetadataOk = tokenMeta.metadataOk;
    const actual = {
      blockInterval: Number(tmIntervalRaw),
      verificationPeriod: Number(verificationRaw),
      claimPeriod: Number(claimRaw),
      gamePeriod: Number(gameRaw),
      submitPeriod: Number(submitRaw),
      initialGrace: Number(graceRaw),
      startPastTolerance: Number(startPastToleranceRaw),
    };
    const expected = {
      blockInterval: 4 * 24 * 60 * 60,
      verificationPeriod: 4 * 24 * 60 * 60,
      claimPeriod: 40 * 24 * 60 * 60,
      gamePeriod: 24 * 60 * 60,
      submitPeriod: 24 * 60 * 60,
      initialGrace: 2 * 60 * 60,
      startPastTolerance: 60 * 60, // C32F2（C32-B-01）
    };
    const productionMismatches = Object.keys(expected)
      .filter((key) => actual[key] !== expected[key])
      .map((key) => `${key}=${actual[key]} (expected ${expected[key]})`);

    const pending = [];
    const adminRotation = [];
    // BitcoinuDonate は pendingSuperAdmin を持たず採点・報酬にも関与しないため、タイムロック付き3契約だけを検査する。
    for (const [name, address, abi] of [
      ['TokenMining', tm, TOKEN_MINING_ABI],
      ['Evidence', evidenceAddr, EVIDENCE_ABI],
      ['HashStorage', hashStorageAddr, HASH_STORAGE_ABI],
    ]) {
      const [admin, superAdmin, to, eta] = await Promise.all([
        read(address, abi, 'admin'),
        read(address, abi, 'superAdmin'),
        read(address, abi, 'pendingSuperAdmin'),
        read(address, abi, 'pendingSuperAdminEta'),
      ]);
      adminRotation.push({
        contract: name, address, admin, superAdmin,
        immediateAdminRotation: true,
        separated: !same(admin, superAdmin),
      });
      if (!/^0x0{40}$/i.test(to) || eta !== 0n) pending.push({ contract: name, address, to, eta: Number(eta) });
    }

    const ethStakeAnnounced = BigInt(ethStakeFromBlockRaw) !== UINT256_MAX;
    const currentUnlocked = Number(currentUnlockedRaw);
    const fromBlock = ethStakeAnnounced ? Number(ethStakeFromBlockRaw) : null;
    const blocksAhead = ethStakeAnnounced ? Math.max(0, fromBlock - currentUnlocked) : null;
    const pendingVkeyEta = Number(pendingVkeyEtaRaw);
    const pendingVkeyActive = !ZERO_BYTES32.test(String(pendingVkeyRaw)) || pendingVkeyEta !== 0;
    const oldEntrySelector = toFunctionSelector('submitEntry(uint256,bytes)');
    const entrySelectorPresent = typeof evidenceCode === 'string'
      && evidenceCode.toLowerCase().includes(`63${oldEntrySelector.slice(2).toLowerCase()}`);

    // E11-02 / V7: 実際の AdminChanged・済んだ SuperAdminChanged の履歴を同時に走査する。
    // HashStorageだけは正典ABIで2引数がnon-indexed、TokenMining/Evidenceはindexed。
    let adminChanges = [];
    const superAdminChanges = [];
    const adminChangeErrors = [];
    const adminChangeArchiveErrors = [];
    if (cfg.chainIdExpected === 1) {
      try {
        const toBlock = await client.getBlockNumber();
        for (const [name, address, events] of [
          ['TokenMining', tm, [ADMIN_CHANGED_INDEXED_EVENT, SUPER_ADMIN_CHANGED_INDEXED_EVENT]],
          ['Evidence', evidenceAddr, [ADMIN_CHANGED_INDEXED_EVENT, SUPER_ADMIN_CHANGED_INDEXED_EVENT]],
          ['HashStorage', hashStorageAddr, [ADMIN_CHANGED_UNINDEXED_EVENT, DONATE_SUPER_ADMIN_CHANGED_EVENT]],
        ]) {
          try {
            const fromBlock = await findContractDeploymentBlock(address);
            const logs = await getLogsChunked({ address, events, args: {}, fromBlock, toBlock });
            for (const { log, eventName, args } of decodeAuthorityChanges(logs, events)) {
              const isAdmin = eventName === 'AdminChanged';
              (isAdmin ? adminChanges : superAdminChanges).push({
                contract: name,
                address,
                ...(isAdmin ? { oldAdmin: args.oldAdmin, newAdmin: args.newAdmin }
                  : { oldSuperAdmin: args.oldSuperAdmin, newSuperAdmin: args.newSuperAdmin }),
                blockNumber: Number(log.blockNumber),
                transactionIndex: Number(log.transactionIndex ?? 0),
                logIndex: Number(log.logIndex ?? log.index ?? 0),
                txHash: log.transactionHash,
              });
            }
          } catch (error) {
            if (error instanceof ArchiveUnavailableError) adminChangeArchiveErrors.push(error);
            adminChangeErrors.push(`${name}: ${error?.message || String(error)}`);
          }
        }
        adminChanges.sort((a, b) => a.blockNumber - b.blockNumber
          || a.transactionIndex - b.transactionIndex || a.logIndex - b.logIndex);
        superAdminChanges.sort((a, b) => a.blockNumber - b.blockNumber
          || a.transactionIndex - b.transactionIndex || a.logIndex - b.logIndex);
      } catch (error) {
        adminChangeErrors.push(`head: ${error?.message || String(error)}`);
      }
    }

    let donateChanges = [];
    const donateAdminChanges = [];
    let donateEventError = null;
    let donateEventArchiveError = null;
    const donateChecked = Boolean(cfg.chainIdExpected === 1 && contracts.donate);
    if (donateChecked) {
      try {
        const fromBlock = await findContractDeploymentBlock(contracts.donate);
        const toBlock = await client.getBlockNumber();
        const events = [DONATE_SUPER_ADMIN_CHANGED_EVENT, ADMIN_CHANGED_UNINDEXED_EVENT];
        const logs = await getLogsChunked({
          address: contracts.donate, events,
          args: {}, fromBlock, toBlock,
        });
        for (const { log, eventName, args } of decodeAuthorityChanges(logs, events)) {
          const isAdmin = eventName === 'AdminChanged';
          (isAdmin ? donateAdminChanges : donateChanges).push({
            ...(isAdmin ? { oldAdmin: args.oldAdmin, newAdmin: args.newAdmin }
              : { oldSuperAdmin: args.oldSuperAdmin, newSuperAdmin: args.newSuperAdmin }),
            blockNumber: Number(log.blockNumber),
            txHash: log.transactionHash,
          });
        }
      } catch (e) {
        if (e instanceof ArchiveUnavailableError) donateEventArchiveError = e;
        donateEventError = e?.message || String(e);
      }
    }

    systemAuditCache = {
      wiring: {
        evidence: { ok: same(evidenceBack, tm), forward: evidenceAddr, reverse: evidenceBack, tokenMining: tm },
        evidenceHashStorage: {
          ok: same(evidenceHashStorage, hashStorageAddr),
          evidence: evidenceHashStorage, tokenMining: hashStorageAddr,
        },
        evidenceSenderLimit: { ok: BigInt(maxResultsPerSenderRaw) === 3n,
          actual: Number(maxResultsPerSenderRaw), expected: 3 },
        evidenceEntryRemoved: { ok: typeof evidenceCode === 'string' && !entrySelectorPresent,
          selector: oldEntrySelector, present: entrySelectorPresent },
        evidenceEntryAccZero: { ok: ZERO_BYTES32.test(String(entryAccZero))
            && ZERO_BYTES32.test(String(entryAccMax)),
          atZero: entryAccZero, atMax: entryAccMax },
        evidenceStartPastTolerance: judgeStartPastTolerance(actual, startPastToleranceRaw),
        ethLock: { ok: same(ethLockBack, tm), forward: ethLockAddr, reverse: ethLockBack, tokenMining: tm },
        ethStakeTiming: {
          ok: BigInt(ethStakeStartRaw) === BigInt(tmStartRaw) && BigInt(ethStakeIntervalRaw) === BigInt(tmIntervalRaw),
          ethStake: ethStakeAddr,
          tokenMiningStartTime: Number(tmStartRaw), ethStakeStartTime: Number(ethStakeStartRaw),
          tokenMiningBlockInterval: Number(tmIntervalRaw), ethStakeBlockInterval: Number(ethStakeIntervalRaw),
        },
        ethStake: { ok: same(ethStakeAddr, contracts.ethStake), onchain: ethStakeAddr, config: contracts.ethStake },
        maxBlockNum: {
          ok: BigInt(tmMaxBlockRaw) === BigInt(evidenceMaxBlockRaw)
            && BigInt(tmMaxBlockRaw) === BigInt(ethStakeMaxBlockRaw),
          tokenMining: Number(tmMaxBlockRaw), evidence: Number(evidenceMaxBlockRaw),
          ethStake: Number(ethStakeMaxBlockRaw),
        },
        hashStorage: { ok: same(hashStorageAddr, contracts.hashStorage), onchain: hashStorageAddr, config: contracts.hashStorage },
        authoritySeparation: {
          ok: adminRotation.every((a) => a.separated),
          collapsed: adminRotation.filter((a) => !a.separated)
            .map((a) => `${a.contract}: admin == superAdmin == ${a.admin}`).join('; ') || '-',
          contracts: adminRotation.map((a) => `${a.contract}: ${a.admin} / ${a.superAdmin}`).join('; '),
        },
        token: {
          ok: totalSupply === expectedSupply && tokenMetadataOk,
          ...tokenMeta,
          blockNumber: tokenMeta.blockNumber.toString(),
          totalSupply: totalSupply.toString(),
          expectedSupply: expectedSupply.toString(),
          tokenMiningBalance: tmTokenBalance.toString(),
        },
      },
      production: {
        applicable: cfg.chainIdExpected === 1,
        ok: productionMismatches.length === 0,
        actual, expected, mismatches: productionMismatches,
      },
      ethStakeSwitch: {
        announced: ethStakeAnnounced,
        fromBlock,
        currentUnlocked,
        blocksAhead,
        daysLeft: ethStakeAnnounced ? Math.ceil((blocksAhead * Number(tmIntervalRaw)) / 86400) : null,
      },
      pendingVkey: {
        pending: pendingVkeyActive,
        vkey: pendingVkeyRaw,
        guestSourceHash: pendingGuestSourceHashRaw,
        eta: pendingVkeyEta,
        daysLeft: pendingVkeyActive
          ? Math.max(0, Math.ceil((pendingVkeyEta - Math.floor(Date.now() / 1000)) / 86400))
          : null,
      },
      adminRotation,
      adminChanges,
      superAdminChanges,
      adminChangeError: adminChangeErrors.join('; ') || null,
      adminChangeArchiveErrors,
      adminHistoryChecked: cfg.chainIdExpected === 1,
      pendingSuperAdmin: pending,
      donateChanges,
      donateAdminChanges,
      donateChecked,
      donateEventError,
      donateEventArchiveError,
    };
    return systemAuditCache;
  }

  return {
    client,
    probeArchive,
    get archiveCapability() { return archiveCapability; },
    contracts,
    chainId,
    rpcUrl: urls[0],   // K-S5-002: RPC 限界の案内文で「今どこを使っているか」を示すため
    getBlock,
    latest,
    getCode,
    findContractDeploymentBlock,
    findBlockByTimestamp,
    hashStorageAddress,
    estimateRange,
    getLogsChunked,
    // HashStorage
    getApplicantHash,
    getResultHash,
    getOtherHash,
    otherRegistrationCount,
    otherRegistrationAt,
    firstOtherRegistration,
    firstMatchingOtherRegistration,
    applicantRegistrationCount,
    applicantRegistrationAt,
    isApplicantRegistered,
    isLegacyHashStorage,
    resultRegistrationCount,
    resultRegistrationAt,
    resultRegistrationHistory,
    applicantHashEvents,
    resultHashEvents,
    // TokenMining
    blockStates,
    maxBlockNum,
    tokenMiningStartTime,
    blockInterval,
    verificationPeriod,
    claimPeriod,
    getBlockMode,
    getBlockLifecycle,
    merkleRootEvents,
    verificationExtendedEvents,
    merkleRootInvalidatedEvents,
    merkleRootProofAttachedEvents,
    proofRequired,
    vkeyEpoch,
    vkeyEpochs,
    pendingVkeyProposal,
    // Evidence
    evidenceAddress,
    ethLockAddress,
    evidenceStartTime,
    evidenceBlockTime,
    gamePeriod,
    submitPeriod,
    initialGrace,
    currentGrace,
    chatWindow,
    resultWindow,
    resultCount,
    windowFinal,
    blockHashOf,
    resultSubmittedEvents,
    evidenceAcc,
    // timing
    getTimingConstants,
    tokenMetadata,
    systemAudit,
  };
}

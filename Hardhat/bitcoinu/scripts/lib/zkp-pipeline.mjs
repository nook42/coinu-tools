import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import {
  concatHex,
  decodeAbiParameters,
  encodeAbiParameters,
  getAddress,
  isAddress,
  keccak256,
} from 'viem';

export const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
export const ZERO_HASH = `0x${'00'.repeat(32)}`;
export const CONFIRMATION_BLOCKS = 64n;

// `TokenMining.submitMerkleRootWithProof` / `attachProofToMerkleRoot` の第7引数
// `prevRegistrationIndex` の番兵（`type(uint256).max`）。
// 契約は「前ブロックの結果ハッシュ登録が0件」のときだけ番兵を受け付ける
// （TokenMining._checkAnchors — `if (n != 0) revert PvPrevResultManifestMismatch();`）。
export const PREV_REGISTRATION_SENTINEL = (1n << 256n) - 1n;

export const PV_COMPONENTS = [
  { name: 'blockNum', type: 'uint256' },
  { name: 'claimDataHash', type: 'bytes32' },
  { name: 'merkleRoot', type: 'bytes32' },
  { name: 'evidenceAcc', type: 'bytes32' },
  { name: 'entryAcc', type: 'bytes32' },
  { name: 'randaoBlockHash', type: 'bytes32' },
  { name: 'resultManifestHash', type: 'bytes32' },
  { name: 'prevResultManifestHash', type: 'bytes32' },
  { name: 'applicantHash', type: 'bytes32' },
  { name: 'applicantHashUpdatedBlock', type: 'uint256' },
  { name: 'evidenceGraceSec', type: 'uint256' },
  { name: 'randaoEthBlockNumber', type: 'uint256' },
  { name: 'deploymentParamsHash', type: 'bytes32' },
  { name: 'futureAnchorsHash', type: 'bytes32' },
  { name: 'rosterManifestHash', type: 'bytes32' },
];

export const PV_PARAMETER = { name: 'pv', type: 'tuple', components: PV_COMPONENTS };
export const NUMERIC_PV_FIELDS = new Set([
  'blockNum',
  'applicantHashUpdatedBlock',
  'evidenceGraceSec',
  'randaoEthBlockNumber',
]);

export const TOKEN_MINING_ABI = [
  { name: 'admin', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { name: 'superAdmin', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { name: 'evidence', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { name: 'ethLock', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { name: 'hashStorage', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { name: 'anchorProvider', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { name: 'proofRequired', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'bool' }] },
  { name: 'verifier', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { name: 'vkey', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'bytes32' }] },
  { name: 'pendingVerifier', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { name: 'pendingVkey', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'bytes32' }] },
  { name: 'pendingAnchorProvider', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { name: 'pendingGuestSourceHash', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'bytes32' }] },
  { name: 'pendingVkeyEta', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { name: 'vkeyEpochCount', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  {
    name: 'vkeyEpochs', type: 'function', stateMutability: 'view', inputs: [{ type: 'uint256' }],
    outputs: [
      { name: 'epochVerifier', type: 'address' },
      { name: 'epochVkey', type: 'bytes32' },
      { name: 'guestSourceHash', type: 'bytes32' },
      { name: 'proposedAt', type: 'uint64' },
      { name: 'activatedAt', type: 'uint64' },
    ],
  },
  {
    name: 'effectiveVerifierAndVkey', type: 'function', stateMutability: 'view', inputs: [],
    outputs: [{ name: 'v', type: 'address' }, { name: 'k', type: 'bytes32' }],
  },
  {
    name: 'claimDataOf', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }],
    outputs: [{ name: 'dataHash', type: 'bytes32' }, { name: 'chunks', type: 'uint32' }, { name: 'received', type: 'uint32' }],
  },
  {
    name: 'getClaimDataBlocks', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'uint64[]' }],
  },
  {
    name: 'guestSourceOf', type: 'function', stateMutability: 'view',
    inputs: [{ name: 'guestSourceHash', type: 'bytes32' }],
    outputs: [{ name: 'dataHash', type: 'bytes32' }, { name: 'chunks', type: 'uint32' }, { name: 'received', type: 'uint32' }],
  },
  {
    name: 'guestSourceBlocks', type: 'function', stateMutability: 'view',
    inputs: [{ name: 'guestSourceHash', type: 'bytes32' }, { name: 'index', type: 'uint256' }],
    outputs: [{ type: 'uint64' }],
  },
  {
    name: 'isBlockTimeUnlocked', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'bool' }],
  },
  {
    name: 'getBlockMode', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'uint8' }],
  },
  {
    name: 'blockStates', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }],
    outputs: [
      { name: 'merkleRoot', type: 'bytes32' },
      { name: 'verificationStartedAt', type: 'uint64' },
      { name: 'zkEpochPlusOne', type: 'uint32' },
      { name: 'proofAttachedAt', type: 'uint64' },
    ],
  },
  {
    name: 'deploymentParamsHash', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'bytes32' }],
  },
  {
    name: 'publishGuestSource', type: 'function', stateMutability: 'nonpayable',
    inputs: [
      { name: 'guestSourceHash', type: 'bytes32' },
      { name: 'chunkIndex', type: 'uint32' },
      { name: 'totalChunks', type: 'uint32' },
      { name: 'data', type: 'bytes' },
    ], outputs: [],
  },
  {
    name: 'proposeVerifierAndVkey', type: 'function', stateMutability: 'nonpayable',
    inputs: [
      { name: 'newVerifier', type: 'address' },
      { name: 'newVkey', type: 'bytes32' },
      { name: 'newAnchorProvider', type: 'address' },
      { name: 'guestSourceHash', type: 'bytes32' },
    ], outputs: [],
  },
  {
    name: 'submitMerkleRootWithProof', type: 'function', stateMutability: 'nonpayable',
    inputs: [
      { name: 'blockNum', type: 'uint256' },
      { name: 'root', type: 'bytes32' },
      { name: 'expectedVerifier', type: 'address' },
      { name: 'expectedVkey', type: 'bytes32' },
      { name: 'publicValues', type: 'bytes' },
      { name: 'proofBytes', type: 'bytes' },
      // word7 が名乗る前ブロックの結果ハッシュ登録の添字（TokenMining.submitMerkleRootWithProof の @param prevRegistrationIndex）。
      { name: 'prevRegistrationIndex', type: 'uint256' },
    ], outputs: [],
  },
  {
    name: 'attachProofToMerkleRoot', type: 'function', stateMutability: 'nonpayable',
    inputs: [
      { name: 'blockNum', type: 'uint256' },
      { name: 'expectedVerifier', type: 'address' },
      { name: 'expectedVkey', type: 'bytes32' },
      { name: 'publicValues', type: 'bytes' },
      { name: 'proofBytes', type: 'bytes' },
      // 同上（TokenMining.attachProofToMerkleRoot）。
      { name: 'prevRegistrationIndex', type: 'uint256' },
    ], outputs: [],
  },
];

export const EVIDENCE_ABI = [
  {
    name: 'scheduledGameStart', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'uint256' }],
  },
  {
    name: 'evidenceAcc', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'bytes32' }],
  },
  {
    name: 'entryAcc', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'bytes32' }],
  },
  {
    name: 'currentGrace', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'uint256' }],
  },
  {
    name: 'blockHashOf', type: 'function', stateMutability: 'view',
    inputs: [{ name: 'ethBlockNumber', type: 'uint256' }], outputs: [{ type: 'bytes32' }],
  },
];

export const HASH_STORAGE_ABI = [
  {
    name: 'rosterLastIn', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }, { type: 'uint256' }, { type: 'uint256' }],
    outputs: [{ name: 'found', type: 'bool' }, { name: 'hash', type: 'bytes32' }],
  },
  {
    name: 'otherRegistrationCount', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'bytes32' }], outputs: [{ type: 'uint256' }],
  },
  {
    name: 'otherRegistrationAt', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'bytes32' }, { type: 'uint256' }],
    outputs: [{ name: 'hash', type: 'bytes32' }, { name: 'registeredBlock', type: 'uint256' },
      { name: 'registeredAt', type: 'uint256' }],
  },
  {
    name: 'applicantHashes', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }],
    outputs: [{ name: 'hash', type: 'bytes32' }, { name: 'updated', type: 'uint256' }, { name: 'signer', type: 'address' }],
  },
  {
    name: 'registrationCount', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'uint256' }],
  },
  {
    name: 'isApplicantRegistered', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }, { type: 'uint256' }, { type: 'bytes32' }], outputs: [{ type: 'bool' }],
  },
  {
    name: 'applicantRegistrationAt', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }, { type: 'uint256' }],
    outputs: [
      { name: 'hash', type: 'bytes32' },
      { name: 'registeredBlock', type: 'uint256' },
      { name: 'signer', type: 'address' },
    ],
  },
  {
    name: 'resultHashes', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }],
    outputs: [{ name: 'hash', type: 'bytes32' }, { name: 'updated', type: 'uint256' }, { name: 'signer', type: 'address' }],
  },
  {
    name: 'resultRegistrationCount', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'uint256' }],
  },
  {
    // 🔴 applicantRegistrationAt は3値だが、結果側は registeredAt を足した**4値**（HashStorage.resultRegistrationAt）。
    name: 'resultRegistrationAt', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }, { type: 'uint256' }],
    outputs: [
      { name: 'hash', type: 'bytes32' },
      { name: 'registeredBlock', type: 'uint256' },
      { name: 'registeredAt', type: 'uint256' },
      { name: 'signer', type: 'address' },
    ],
  },
];

export const ANCHOR_PROVIDER_ABI = [
  {
    name: 'anchorsHash', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }], outputs: [{ type: 'bytes32' }],
  },
];

export const CLAIM_DATA_EVENT_ABI = [{
  type: 'event',
  name: 'ClaimDataPublished',
  inputs: [
    { name: 'blockNum', type: 'uint256', indexed: true },
    { name: 'chunkIndex', type: 'uint32', indexed: true },
    { name: 'totalChunks', type: 'uint32', indexed: false },
    { name: 'runningHash', type: 'bytes32', indexed: false },
    { name: 'data', type: 'bytes', indexed: false },
  ],
}];

export function parseArgs(argv, valueFlags = [], booleanFlags = []) {
  const values = new Set(valueFlags);
  const booleans = new Set(booleanFlags);
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (!flag.startsWith('--')) throw new Error(`不明な引数: ${flag}`);
    const key = flag.slice(2);
    if (booleans.has(key)) {
      if (out[key] !== undefined) throw new Error(`重複した引数: ${flag}`);
      out[key] = true;
      continue;
    }
    if (!values.has(key)) throw new Error(`不明な引数: ${flag}`);
    if (out[key] !== undefined) throw new Error(`重複した引数: ${flag}`);
    const value = argv[++i];
    if (value === undefined || value.startsWith('--')) throw new Error(`${flag} には値が必要です`);
    out[key] = value;
  }
  return out;
}

export function requireBlockNum(raw) {
  if (!/^(0|[1-9]\d*)$/.test(String(raw ?? ''))) {
    throw new Error('--block は0以上の整数で指定してください');
  }
  const value = BigInt(raw);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('--block がJavaScriptの安全整数を超えています');
  return Number(value);
}

export function requireAddress(value, label, { allowZero = false } = {}) {
  if (!isAddress(value || '', { strict: true })) throw new Error(`${label} は0x付き20-byteアドレスで指定してください`);
  const address = getAddress(value);
  if (!allowZero && address.toLowerCase() === ZERO_ADDRESS) throw new Error(`${label} にゼロアドレスは使えません`);
  return address;
}

export function requireBytes32(value, label, { allowZero = true } = {}) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(value || '')) throw new Error(`${label} は0x付きbytes32で指定してください`);
  const normalized = value.toLowerCase();
  if (!allowZero && normalized === ZERO_HASH) throw new Error(`${label} にゼロ値は使えません`);
  return normalized;
}

export function requireHexBytes(value, label, { allowEmpty = false } = {}) {
  if (!/^0x(?:[0-9a-fA-F]{2})*$/.test(value || '')) throw new Error(`${label} は0x付きの偶数桁hexで指定してください`);
  if (!allowEmpty && value.length === 2) throw new Error(`${label} は空にできません`);
  return value.toLowerCase();
}

export function encodePublicValues(values) {
  return encodeAbiParameters([PV_PARAMETER], [values]);
}

export function decodePublicValues(publicValues) {
  requireHexBytes(publicValues, 'publicValues');
  if ((publicValues.length - 2) / 2 !== PV_COMPONENTS.length * 32) {
    throw new Error(`publicValues は32 bytes × ${PV_COMPONENTS.length}語である必要があります`);
  }
  const [decoded] = decodeAbiParameters([PV_PARAMETER], publicValues);
  const out = {};
  for (const { name } of PV_COMPONENTS) out[name] = decoded[name];
  return out;
}

function normalizePvValue(name, value) {
  if (NUMERIC_PV_FIELDS.has(name)) return BigInt(value);
  return requireBytes32(value, name).toLowerCase();
}

export function comparePublicValues(actual, expected) {
  const mismatches = [];
  for (const { name } of PV_COMPONENTS) {
    const got = normalizePvValue(name, actual[name]);
    const want = normalizePvValue(name, expected[name]);
    if (got !== want) mismatches.push({ name, actual: got.toString(), expected: want.toString() });
  }
  return mismatches;
}

export function sha256Hex(bytes) {
  return `0x${createHash('sha256').update(bytes).digest('hex')}`;
}

export function chunkChainHash(chunksHex) {
  if (!Array.isArray(chunksHex) || chunksHex.length === 0) throw new Error('chunksHex が空です');
  let running = ZERO_HASH;
  for (let i = 0; i < chunksHex.length; i++) {
    const chunk = requireHexBytes(chunksHex[i], `chunksHex[${i}]`);
    const leaf = keccak256(chunk);
    running = keccak256(concatHex([running, leaf]));
  }
  return running;
}

/** 現行 `claimDataBlocks` とイベント列から、最後に成立した現在系列を選ぶ。 */
export function recoverClaimDataChunks(logs, blockNumbers, expectedHash, expectedTotal) {
  const wantedBlocks = blockNumbers.map((v) => BigInt(v).toString());
  const sorted = [...logs].sort((a, b) => {
    const blockCmp = BigInt(a.blockNumber) < BigInt(b.blockNumber) ? -1 : BigInt(a.blockNumber) > BigInt(b.blockNumber) ? 1 : 0;
    if (blockCmp) return blockCmp;
    return Number(a.logIndex) - Number(b.logIndex);
  });
  let candidate = null;
  const complete = [];
  for (const log of sorted) {
    const args = log.args || {};
    const index = Number(args.chunkIndex);
    const total = Number(args.totalChunks);
    if (!Number.isInteger(index) || !Number.isInteger(total) || typeof args.data !== 'string') continue;
    if (index === 0) {
      candidate = { total, chunks: [], blocks: [], running: ZERO_HASH };
    }
    if (!candidate || total !== candidate.total || index !== candidate.chunks.length) continue;
    const data = requireHexBytes(args.data, `ClaimDataPublished[${index}].data`);
    const leaf = keccak256(data);
    const running = keccak256(concatHex([candidate.running, leaf]));
    if (running.toLowerCase() !== String(args.runningHash).toLowerCase()) {
      candidate = null;
      continue;
    }
    candidate.chunks.push(data);
    candidate.blocks.push(BigInt(log.blockNumber).toString());
    candidate.running = running;
    if (candidate.chunks.length === candidate.total) complete.push({ ...candidate });
  }
  const hash = requireBytes32(expectedHash, 'claimDataOf.dataHash');
  const matches = complete.filter((c) =>
    c.total === Number(expectedTotal)
    && c.running.toLowerCase() === hash
    && c.blocks.join(',') === wantedBlocks.join(','));
  if (!matches.length) {
    throw new Error(
      `ClaimDataPublished の現在系列を復元できません（logs=${logs.length}, complete=${complete.length}, `
      + `blocks=[${wantedBlocks.join(',')}], expectedHash=${hash}）`
    );
  }
  return matches[matches.length - 1].chunks;
}

function skipWs(bytes, start) {
  let i = start;
  while (i < bytes.length && (bytes[i] === 0x20 || bytes[i] === 0x09 || bytes[i] === 0x0a || bytes[i] === 0x0d)) i++;
  return i;
}

function stringEnd(bytes, start) {
  if (bytes[start] !== 0x22) throw new Error(`JSON string expected at byte ${start}`);
  let escaped = false;
  for (let i = start + 1; i < bytes.length; i++) {
    if (escaped) { escaped = false; continue; }
    if (bytes[i] === 0x5c) { escaped = true; continue; }
    if (bytes[i] === 0x22) return i + 1;
  }
  throw new Error('JSON string is not closed');
}

function valueEnd(bytes, start) {
  let i = skipWs(bytes, start);
  if (bytes[i] === 0x22) return stringEnd(bytes, i);
  if (bytes[i] === 0x7b || bytes[i] === 0x5b) {
    const stack = [bytes[i] === 0x7b ? 0x7d : 0x5d];
    i++;
    while (i < bytes.length && stack.length) {
      if (bytes[i] === 0x22) { i = stringEnd(bytes, i); continue; }
      if (bytes[i] === 0x7b) stack.push(0x7d);
      else if (bytes[i] === 0x5b) stack.push(0x5d);
      else if (bytes[i] === stack[stack.length - 1]) stack.pop();
      i++;
    }
    if (stack.length) throw new Error('JSON container is not closed');
    return i;
  }
  while (i < bytes.length && bytes[i] !== 0x2c && bytes[i] !== 0x7d) i++;
  return i;
}

/**
 * R2 の full manifest から `manifestCore` の生バイトを復元する。
 * JSON.parse → JSON.stringify は使わず、先頭から `manifestHash` の直前までをそのまま残す。
 */
export function extractManifestCore(raw) {
  const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
  let i = skipWs(bytes, 0);
  if (bytes[i] !== 0x7b) throw new Error('manifest はJSON objectではありません');
  i++;
  let first = true;
  for (;;) {
    i = skipWs(bytes, i);
    if (bytes[i] === 0x7d) break;
    let commaAt = null;
    if (!first) {
      if (bytes[i] !== 0x2c) throw new Error(`manifest のbyte ${i}にカンマがありません`);
      commaAt = i;
      i = skipWs(bytes, i + 1);
    }
    const keyStart = i;
    const keyEnd = stringEnd(bytes, keyStart);
    const key = JSON.parse(bytes.subarray(keyStart, keyEnd).toString('utf8'));
    i = skipWs(bytes, keyEnd);
    if (bytes[i] !== 0x3a) throw new Error(`manifest key ${key} の後にコロンがありません`);
    i = valueEnd(bytes, i + 1);
    if (key === 'manifestHash') {
      if (commaAt === null) throw new Error('manifestHash がcoreの前にあります');
      const core = Buffer.concat([bytes.subarray(0, commaAt), Buffer.from('}')]);
      const keys = Object.keys(JSON.parse(core.toString('utf8')));
      if (keys.join(',') !== 'blockNum,algorithm,rules,files') {
        throw new Error(`manifest core のキー順が不正です: ${keys.join(',')}`);
      }
      return core;
    }
    first = false;
  }
  throw new Error('manifestHash が見つかりません');
}

export function toJsonNumber(value, label) {
  const n = BigInt(value);
  if (n < 0n || n > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${label} がJSON安全整数の範囲外です: ${n}`);
  return Number(n);
}

export function tupleValue(tuple, index, name) {
  if (Array.isArray(tuple)) return tuple[index];
  if (tuple && tuple[name] !== undefined) return tuple[name];
  throw new Error(`tuple field ${name} が見つかりません`);
}

export function loadDeploymentInfo(hardhatDir, network) {
  const file = path.join(hardhatDir, `deployment-info-TokenMining-${network}.json`);
  if (!fs.existsSync(file)) return { file, info: null };
  return { file, info: JSON.parse(fs.readFileSync(file, 'utf8')) };
}

export function rpcUrlForNetwork(network, env, override) {
  if (override) return override;
  const table = {
    mainnet: ['ETHEREUM_MAINNET_RPC_URL'],
    sepolia: ['ETHEREUM_TESTNET_RPC_URL'],
    'base-mainnet': ['BASE_MAINNET_RPC_URL'],
    'base-sepolia': ['BASE_TESTNET_RPC_URL'],
    localhost: [],
    hardhat: [],
  };
  if (!(network in table)) throw new Error(`未対応のnetworkです: ${network}（--rpc-url で明示できます）`);
  if (network === 'localhost' || network === 'hardhat') return 'http://127.0.0.1:8545';
  for (const key of table[network]) if (env[key]) return env[key];
  throw new Error(`${table[network].join(' または ')} が未設定です`);
}

export function privateKeyEnvForNetwork(network) {
  return network === 'mainnet' || network === 'base-mainnet' ? 'PRIVATE_KEY_MAINNET' : 'PRIVATE_KEY_TESTNET';
}

export function errorMessage(error) {
  const seen = new Set();
  const queue = [error];
  const candidates = [];
  while (queue.length) {
    const current = queue.shift();
    if (!current || seen.has(current)) continue;
    seen.add(current);
    for (const key of ['reason', 'shortMessage', 'details', 'message']) {
      if (typeof current[key] === 'string' && current[key].trim()) candidates.push(current[key].trim());
    }
    for (const key of ['cause', 'error']) if (current[key]) queue.push(current[key]);
  }
  return candidates.find((s) => /revert|PV:|Only |not set|incomplete|required|mismatch/i.test(s))
    || candidates[0]
    || String(error);
}

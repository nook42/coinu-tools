// block-verifier/src/zkp.js
// メニュー②「ZKPシステムのコード整合性を検証」。
//
// ここで確かめるのは **「オンチェーンの vkey は、公開されているゲストソース由来か」** の1点。
//
// 🔴 契約はソースと vkey の対応を検証**できない**。EVM ではコンパイル（ソース→ELF）も
//    vkey 導出（ELF→vkey）もガス的に不可能なため（後者は KoalaBear 体上の Poseidon2 で
//    前処理トレースにコミットする処理で、普通のPCでも CPU 約2分かかる）。
//    Etherscan のソース検証とまったく同じ構造で、**対応の照合は第三者＝あなたが行う**。
//    契約が強制できるのは「対応すると主張されたソース全チャンクの公開を提案前に
//    完了させ、その系列を凍結すること」まで。
//
// したがって本モードは3段構えになっている:
//   ① 契約の記録（vkeyEpochs）と、state が示す block 上の
//      GuestSourceChunkPublished 列の**整合**を検査する
//      — チャンク順・各 runningHash・最終 package ID を照合し、監査の門を通ったソースを保存する
//   ② 本ツールにピン留めされた vkey と**オンチェーンの現在値**を突き合わせる
//      — 「ツール公開時点から差し替えられていないか」が分かる
//   ③ 同意を得てから①の保存先で再現ビルド・鍵の算出と照合を実行する
//      — ①②を越えて「本当にこのソースからこの vkey が出るか」を確かめたい人向け。
//        Docker と SP1 が要るので**任意**（強制すると一般ユーザーが使えなくなる）

import fs from 'node:fs';
import { ArchiveUnavailableError } from './archive.js';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { brotliDecompressSync } from 'node:zlib';
import { concatHex, decodeFunctionData, hexToBytes, keccak256, parseAbiItem } from 'viem';
import { collectZkpInput } from '../../Hardhat/bitcoinu/scripts/lib/collect-zkp-input.mjs';
import { compareProofWords } from './zkp-word-checks.js';
import {
  HASH_STORAGE_ABI,
  PREV_REGISTRATION_SENTINEL,
  TOKEN_MINING_ABI,
  comparePublicValues,
  decodePublicValues,
  encodePublicValues,
} from '../../Hardhat/bitcoinu/scripts/lib/zkp-pipeline.mjs';
import { decodeUtf8 } from './utf8.js';
import { concatChunks, decodeClaimData } from '../vendor/workers/game_workers/lib/claim-data-codec.js';
import { ZKP_EXPECTED } from '../vendor/workers/game_workers/lib/zkp-protocol.js';
import { WIRE_GUESTS, WIRE_VKEY_EDGES, checkWireBuildInputs, quotedSourcePath, visibleTerminalText,
  verifyWireVkeys } from './wiring-vkeys.js';
export { decodePublicValues } from '../../Hardhat/bitcoinu/scripts/lib/zkp-pipeline.mjs';

const SEP = '─'.repeat(72);
const ZERO_HASH = `0x${'00'.repeat(32)}`;
const RESULT_HASH_REGISTERED_EVENT = parseAbiItem(
  'event ResultHashRegistered(uint256 indexed blockNumber, bytes32 hash, address signer, bool isUpdate, uint256 updatedAt, uint256 registrationCount)',
);

// V25-05: 現行package実測は 220,197 compressed bytes / 1,115,916 payload bytes /
// 43 files / 最大162,824 bytes。オンチェーンの16 * 98,304 bytesをpackage上限とし、
// 展開側は現物の約7.5倍、file数は約6倍、単体は約12倍まで余裕を持たせる。
export const GUEST_SOURCE_LIMITS = Object.freeze({
  packageBytes: 16 * 98_304,
  payloadBytes: 8 * 1024 * 1024,
  files: 256,
  fileBytes: 2 * 1024 * 1024,
  pathBytes: 512,
  headerBytes: 1_024,
});
const SP1_IMAGE_PATTERN = /^ghcr\.io\/succinctlabs\/sp1@sha256:[0-9a-f]{64}$/;

// SP1 Groth16 の軽量な外形検査。暗号検証自体は TokenMining が提出 tx 内で実行済み。
// 将来世代の vkey は必ず vkeyEpochs から読むため、ここには固定しない。
export const ZKP_PROOF_FORMAT = Object.freeze({
  selector: '0x4388a21c',
  proofBytes: 356,
  publicValuesBytes: 480,
  publicValueWords: 15,
});
const GUEST_SOURCE_REF_ABI = [
  {
    type: 'function', name: 'guestSourceOf', stateMutability: 'view',
    inputs: [{ name: 'guestSourceHash', type: 'bytes32' }],
    outputs: [
      { name: 'dataHash', type: 'bytes32' },
      { name: 'chunks', type: 'uint32' },
      { name: 'received', type: 'uint32' },
    ],
  },
  {
    type: 'function', name: 'guestSourceBlocks', stateMutability: 'view',
    inputs: [{ name: 'guestSourceHash', type: 'bytes32' }, { name: 'index', type: 'uint256' }],
    outputs: [{ type: 'uint64' }],
  },
];
const GUEST_SOURCE_CHUNK_EVENT = parseAbiItem(
  'event GuestSourceChunkPublished(bytes32 indexed guestSourceHash, uint32 indexed chunkIndex, uint32 totalChunks, bytes32 runningHash, bytes data)',
);

function hexByteLength(value) {
  if (typeof value !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(value)) {
    throw new Error('0x付きの偶数桁hexではありません');
  }
  return (value.length - 2) / 2;
}

function errorText(error) {
  return error?.shortMessage || error?.message || String(error);
}

export const ZKP_COLLECTION_FAILURE_CAUSES = Object.freeze({
  artifactMissing: 'artifact_missing',
  artifactMismatch: 'artifact_mismatch',
  artifactInvalid: 'artifact_invalid',
  artifactFetchError: 'artifact_fetch_error',
  proofBoundToOtherManifest: 'proof_bound_to_other_manifest',
  rpcUnavailable: 'rpc_unavailable',
});

function resultAnchorMismatchHashes(error) {
  const match = /^HashStorage\.resultHashes不一致: chain=(0x[0-9a-fA-F]{64}) R2=(0x[0-9a-fA-F]{64})$/
    .exec(errorText(error));
  return match ? {
    proofBoundResultHash: match[1].toLowerCase(),
    reconstructedResultHash: match[2].toLowerCase(),
  } : null;
}

export function classifyZkpCollectionFailure(error) {
  if (error?.zkpArtifactMissing === true) return ZKP_COLLECTION_FAILURE_CAUSES.artifactMissing;
  if (error?.zkpChainAnchorMismatch === true && resultAnchorMismatchHashes(error)) {
    return ZKP_COLLECTION_FAILURE_CAUSES.proofBoundToOtherManifest;
  }
  if (error?.zkpArtifactInvalid === true) return ZKP_COLLECTION_FAILURE_CAUSES.artifactInvalid;
  if (error?.zkpArtifactMismatch === true) return ZKP_COLLECTION_FAILURE_CAUSES.artifactMismatch;
  if (error?.zkpArtifactFetchError === true) return ZKP_COLLECTION_FAILURE_CAUSES.artifactFetchError;
  return ZKP_COLLECTION_FAILURE_CAUSES.rpcUnavailable;
}

export function zkpCollectionUnavailableMessage(error, ethereumBlock, cause = classifyZkpCollectionFailure(error)) {
  const message = errorText(error);
  if (cause === ZKP_COLLECTION_FAILURE_CAUSES.artifactMissing) {
    return `${message}; a required ZKP artifact is unavailable`;
  }
  if (cause === ZKP_COLLECTION_FAILURE_CAUSES.artifactMismatch) {
    return `${message}; a required ZKP artifact failed sha256 or canonical JSON validation`;
  }
  if (cause === ZKP_COLLECTION_FAILURE_CAUSES.artifactInvalid) {
    return `${message}; a required ZKP artifact is structurally invalid or exceeds its bounded input limit`;
  }
  if (cause === ZKP_COLLECTION_FAILURE_CAUSES.artifactFetchError) {
    return `${message}; a required ZKP artifact fetch failed without proving that the artifact is absent`;
  }
  if (cause === ZKP_COLLECTION_FAILURE_CAUSES.proofBoundToOtherManifest) {
    return `${message}; the proof snapshot is bound to a different result manifest registration`;
  }
  return `${message}; historical state at Ethereum block ${ethereumBlock} requires an archive-capable RPC`;
}

export function describeZkpCollectionFailure(error, ethereumBlock) {
  const cause = classifyZkpCollectionFailure(error);
  const anchorMismatch = cause === ZKP_COLLECTION_FAILURE_CAUSES.proofBoundToOtherManifest
    ? resultAnchorMismatchHashes(error) : null;
  return {
    status: 'unavailable',
    cause,
    error: zkpCollectionUnavailableMessage(error, ethereumBlock, cause),
    ...(anchorMismatch || {}),
    ...(error instanceof ArchiveUnavailableError ? { unavailableError: error } : {}),
  };
}

/**
 * 1ブロックのZKP状態を、root / 記録済みepoch / 現在のproofRequiredから分類する。
 * 取得不能を shadow と混同せず、決して「証明なし」と推測しない。
 */
export async function inspectBlockZkpState(chain, blockNum) {
  let blockState;
  let currentProofRequired = null;
  let proofRequiredError = null;
  try {
    blockState = await chain.blockStates(blockNum);
    try { currentProofRequired = !!(await chain.proofRequired()); }
    catch (error) { proofRequiredError = errorText(error); }
    const root = blockState?.root ?? blockState?.merkleRoot ?? null;
    if (!root || root.toLowerCase() === ZERO_HASH) {
      return { kind: 'no_root', blockState, currentProofRequired, proofRequiredError };
    }
    const epochPlusOne = Number(blockState.zkEpochPlusOne);
    if (!Number.isInteger(epochPlusOne) || epochPlusOne < 0) {
      throw new Error(`invalid blockStates.zkEpochPlusOne: ${blockState.zkEpochPlusOne}`);
    }
    if (epochPlusOne === 0) {
      return { kind: 'shadow', blockState, currentProofRequired, proofRequiredError };
    }
    const index = epochPlusOne - 1;
    const epoch = typeof chain.vkeyEpoch === 'function'
      ? await chain.vkeyEpoch(index)
      : (await chain.vkeyEpochs())[index];
    if (!epoch?.vkey || !epoch?.verifier) throw new Error(`ZKP epoch ${index} is unavailable`);
    return { kind: 'proof', blockState, currentProofRequired, proofRequiredError, epoch };
  } catch (error) {
    return { kind: 'unavailable', blockState, currentProofRequired, proofRequiredError, error: errorText(error) };
  }
}

/** proofBytes/publicValues の固定外形と、PV中の blockNum/root を検査する。 */
export function inspectProofEnvelope({ proofBytes, publicValues, blockNum, root }) {
  const errors = [];
  let proofLength = null;
  let publicValuesLength = null;
  let decoded = null;
  try { proofLength = hexByteLength(proofBytes); }
  catch (error) { errors.push(`proofBytes: ${error.message}`); }
  try { publicValuesLength = hexByteLength(publicValues); }
  catch (error) { errors.push(`publicValues: ${error.message}`); }

  const selector = typeof proofBytes === 'string' ? proofBytes.slice(0, 10).toLowerCase() : null;
  if (selector !== ZKP_PROOF_FORMAT.selector) {
    errors.push(`proof selector ${selector ?? '-'} != ${ZKP_PROOF_FORMAT.selector}`);
  }
  if (proofLength !== null && proofLength !== ZKP_PROOF_FORMAT.proofBytes) {
    errors.push(`proofBytes ${proofLength} bytes != ${ZKP_PROOF_FORMAT.proofBytes}`);
  }
  if (publicValuesLength !== null && publicValuesLength !== ZKP_PROOF_FORMAT.publicValuesBytes) {
    errors.push(`publicValues ${publicValuesLength} bytes != ${ZKP_PROOF_FORMAT.publicValuesBytes}`);
  }
  if (publicValuesLength === ZKP_PROOF_FORMAT.publicValuesBytes) {
    try {
      decoded = decodePublicValues(publicValues);
      if (blockNum != null && decoded.blockNum !== BigInt(blockNum)) {
        errors.push(`PV blockNum ${decoded.blockNum} != ${blockNum}`);
      }
      if (root && String(decoded.merkleRoot).toLowerCase() !== String(root).toLowerCase()) {
        errors.push(`PV merkleRoot ${decoded.merkleRoot} != ${root}`);
      }
    } catch (error) {
      errors.push(`publicValues decode: ${error.message}`);
    }
  }
  return { ok: errors.length === 0, errors, selector, proofLength, publicValuesLength, decoded };
}

/**
 * 共有収集コアの戻り値から、契約と同じ15語の public values を組み立てる。
 * collector は manifest 固定の game_selection.json と HashStorage 履歴を照合済みなので、
 * 語8 applicantHash / 語9 applicantHashUpdatedBlock も selection の登録そのものになる。
 */
export function buildExpectedPublicValues(collected) {
  const input = collected?.input;
  if (!input) throw new Error('collected ZKP input is missing');
  if (Array.isArray(input.chunksHex)) {
    const decoded = decodeClaimData(concatChunks(input.chunksHex.map((chunk) => hexToBytes(chunk))));
    if (decoded.blockNum !== Number(input.blockNum)) {
      throw new Error(`claim data blob blockNum ${decoded.blockNum} != K0 ${input.blockNum}`);
    }
  }
  return {
    blockNum: BigInt(input.blockNum),
    claimDataHash: collected.claimDataHash,
    merkleRoot: collected.merkleRoot,
    evidenceAcc: input.evidenceAcc,
    entryAcc: input.entryAcc,
    randaoBlockHash: input.randaoBlockHash,
    resultManifestHash: collected.resultManifestHash,
    prevResultManifestHash: input.prevResultManifestHash,
    applicantHash: input.applicantHash,
    applicantHashUpdatedBlock: BigInt(input.applicantHashUpdatedBlock),
    evidenceGraceSec: BigInt(input.evidenceGraceSec),
    randaoEthBlockNumber: BigInt(input.randaoEthBlockNumber),
    deploymentParamsHash: input.deploymentParamsHash,
    futureAnchorsHash: input.futureAnchorsHash,
    rosterManifestHash: input.rosterManifestHash,
  };
}

export function compareRebuiltPublicValues(publicValues, collected) {
  const actual = decodePublicValues(publicValues);
  const expected = buildExpectedPublicValues(collected);
  const encoded = encodePublicValues(expected);
  const mismatches = comparePublicValues(actual, expected);
  if (encoded.toLowerCase() !== publicValues.toLowerCase() && mismatches.length === 0) {
    mismatches.push({ name: 'abiEncoding', actual: publicValues, expected: encoded });
  }
  return { ok: mismatches.length === 0, mismatches, actual, expected, encoded };
}

// Evidence.sol folds the exact event sender and data in sequence order.
export function foldEvidenceAcc(previous, sender, data) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(previous)
      || !/^0x[0-9a-fA-F]{40}$/.test(sender)
      || !/^0x(?:[0-9a-fA-F]{2})*$/.test(data)) {
    throw new TypeError('invalid Evidence accumulator input');
  }
  return keccak256(concatHex([previous, sender, keccak256(data)]));
}

/** 初回proof同時提出／既存rootへの事後添付calldataを共有ABIで復号する。 */
export function decodeProofSubmissionCalldata(input) {
  const decoded = decodeFunctionData({ abi: TOKEN_MINING_ABI, data: input });
  if (decoded.functionName !== 'submitMerkleRootWithProof'
    && decoded.functionName !== 'attachProofToMerkleRoot') {
    throw new Error(`unexpected TokenMining call: ${decoded.functionName}`);
  }
  if (decoded.functionName === 'submitMerkleRootWithProof') {
    const [blockNum, root, expectedVerifier, expectedVkey, publicValues, proofBytes] = decoded.args;
    return { functionName: decoded.functionName, blockNum, root, expectedVerifier, expectedVkey, publicValues, proofBytes };
  }
  const [blockNum, expectedVerifier, expectedVkey, publicValues, proofBytes] = decoded.args;
  return { functionName: decoded.functionName, blockNum, root: null, expectedVerifier, expectedVkey, publicValues, proofBytes };
}

/**
 * 証明提出 calldata から第7引数 `prevRegistrationIndex`（名乗った前ブロックの履歴の添字）を読む。
 * 🔴 ABI は正典の共有 ABI（`Hardhat/bitcoinu/scripts/lib/zkp-pipeline.mjs` の `TOKEN_MINING_ABI`）を
 *    そのまま使う。block-verifier 側に写しを置かない（写しは必ず古くなる）。
 * 🔴 復号できないとき・共有 ABI がこの引数を宣言していないときに 0 を返さない。
 *    `{ ok:false, reason }` を返して呼び出し側に skip させる
 *    （0 を返すと「先頭の行を名乗った」という嘘になる＝fail-open）。
 */
export function decodeProofPrevRegistrationIndex(input) {
  let decoded;
  try {
    decoded = decodeFunctionData({ abi: TOKEN_MINING_ABI, data: input });
  } catch (error) {
    return { ok: false, reason: 'calldata_without_prev_registration_index', error: errorText(error) };
  }
  if (decoded.functionName !== 'submitMerkleRootWithProof'
    && decoded.functionName !== 'attachProofToMerkleRoot') {
    return {
      ok: false, reason: 'calldata_without_prev_registration_index',
      error: `unexpected TokenMining call: ${decoded.functionName}`,
    };
  }
  // 共有 ABI が第7引数を落としたら、黙って proofBytes を添字と読まずに止める。
  const abiItem = TOKEN_MINING_ABI.find((item) => item.name === decoded.functionName);
  const lastInput = abiItem?.inputs?.[abiItem.inputs.length - 1];
  if (lastInput?.name !== 'prevRegistrationIndex' || lastInput?.type !== 'uint256') {
    return {
      ok: false, reason: 'calldata_without_prev_registration_index',
      error: `shared TOKEN_MINING_ABI does not declare prevRegistrationIndex for ${decoded.functionName}`,
    };
  }
  const args = decoded.args || [];
  const prevRegistrationIndex = args[args.length - 1];
  if (typeof prevRegistrationIndex !== 'bigint') {
    return {
      ok: false, reason: 'calldata_without_prev_registration_index',
      error: 'last decoded argument is not a uint256',
    };
  }
  return { ok: true, functionName: decoded.functionName, prevRegistrationIndex };
}

export function requireProofPrevRegistrationIndex(
  input,
  { decoder = decodeProofPrevRegistrationIndex } = {},
) {
  const decoded = decoder(input);
  if (!decoded?.ok) {
    throw new Error(
      `${decoded?.reason || 'calldata_without_prev_registration_index'}: `
      + `${decoded?.error || 'prevRegistrationIndex is unavailable'}`,
    );
  }
  if (typeof decoded.prevRegistrationIndex !== 'bigint') {
    throw new Error('calldata_without_prev_registration_index: decoded prevRegistrationIndex is not uint256 bigint');
  }
  return decoded;
}

export function localArtifactFetch(blockNum, artifacts) {
  const rawBySuffix = new Map([
    [`verification/block${blockNum}/manifest.json`, artifacts?.manifest],
    [`games/block${blockNum}/summary.json`, artifacts?.summary],
    [`merkle/block_${blockNum}.json`, artifacts?.merkle],
    [`entries/block${blockNum}/game_selection.json`, artifacts?.selection],
    [`verification/block${blockNum}/stage3/manifest.json`, artifacts?.stage3Manifest],
    [`games/block${blockNum}/roster/manifest.json`, artifacts?.rosterManifest],
    [`games/block${blockNum}/roster/index.json`, artifacts?.rosterIndex],
  ]);
  for (const [groupId, raw] of artifacts?.rosterGroups ?? []) {
    rawBySuffix.set(`games/block${blockNum}/roster/group${groupId}.json`, raw);
  }
  return async (url) => {
    const match = [...rawBySuffix.entries()].find(([suffix]) => String(url).endsWith(`/${suffix}`));
    if (!match || typeof match[1] !== 'string') {
      return { ok: false, status: 404, arrayBuffer: async () => new ArrayBuffer(0) };
    }
    const bytes = Buffer.from(match[1], 'utf8');
    const arrayBuffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    return { ok: true, status: 200, arrayBuffer: async () => arrayBuffer };
  };
}

function historicalClient(chain, snapshotBlock) {
  return {
    getBlock: async () => chain.client.getBlock({ blockNumber: snapshotBlock }),
    readContract: async (request) => chain.client.readContract({ ...request, blockNumber: snapshotBlock }),
    getContractEvents: async ({ abi, eventName, ...request }) => {
      const event = abi.find((item) => item.type === 'event' && item.name === eventName);
      if (!event) throw new Error(`event ABI not found: ${eventName}`);
      return chain.getLogsChunked({ ...request, event });
    },
  };
}

// 番兵だけはブロック末の state ではなく、証明ログの直前の件数を使う。
// collector の既定経路には手を加えず、検証中の readContract だけを補正する。
async function sentinelClientAtProof(chain, event, blockNum, snapshotBlock, client) {
  if (blockNum === 0 || event.logIndex == null) return client;
  const proofLogIndex = Number(event.logIndex);
  if (!Number.isSafeInteger(proofLogIndex) || proofLogIndex < 0) {
    throw new Error('invalid proof event logIndex');
  }
  const hashStorage = await chain.client.readContract({
    address: chain.contracts.tokenMining, abi: TOKEN_MINING_ABI,
    functionName: 'hashStorage', blockNumber: snapshotBlock,
  });
  const prev = BigInt(blockNum - 1);
  const readCount = (blockNumber) => chain.client.readContract({
    address: hashStorage, abi: HASH_STORAGE_ABI,
    functionName: 'resultRegistrationCount', args: [prev], blockNumber,
  });
  const [before, after, logs] = await Promise.all([
    readCount(snapshotBlock - 1n), readCount(snapshotBlock),
    chain.getLogsChunked({
      address: hashStorage, event: RESULT_HASH_REGISTERED_EVENT,
      args: { blockNumber: prev }, fromBlock: snapshotBlock, toBlock: snapshotBlock,
    }),
  ]);
  const beforeCount = BigInt(before);
  const afterCount = BigInt(after);
  if (beforeCount !== 0n || afterCount < 0n
      || afterCount !== BigInt(logs.length)
      || logs.some((log, index) =>
        BigInt(log.args?.registrationCount ?? -1) !== BigInt(index + 1)
        || !Number.isSafeInteger(Number(log.logIndex ?? log.index))
        || Number(log.logIndex ?? log.index) <= proofLogIndex)) {
    const error = new Error('証明 tx の位置では前ブロック結果登録の番兵を名乗れません');
    error.zkpInvalidPrevRegistration = true;
    throw error;
  }
  if (afterCount === 0n) return client;
  return {
    ...client,
    readContract: async (request) => {
      if (String(request.address).toLowerCase() === String(hashStorage).toLowerCase()
          && BigInt(request.args?.[0] ?? -1) === prev) {
        if (request.functionName === 'resultRegistrationCount') return 0n;
        if (request.functionName === 'resultHashes') return [ZERO_HASH, 0n, '0x0000000000000000000000000000000000000000'];
      }
      return client.readContract(request);
    },
  };
}

async function proofHashInResultHistory(chain, blockNum, hash) {
  if (!/^0x[0-9a-f]{64}$/i.test(String(hash))
      || typeof chain.resultRegistrationCount !== 'function'
      || typeof chain.resultRegistrationAt !== 'function') return false;
  const count = Number(await chain.resultRegistrationCount(blockNum));
  if (!Number.isSafeInteger(count) || count < 0) throw new Error('invalid result registration count');
  if (count > 0 && typeof chain.resultHashEvents === 'function') {
    const [first, last] = await Promise.all([
      chain.resultRegistrationAt(blockNum, 0), chain.resultRegistrationAt(blockNum, count - 1),
    ]);
    const logs = await chain.resultHashEvents(blockNum, {
      fromBlock: BigInt(first.registeredBlock), toBlock: BigInt(last.registeredBlock),
    });
    const found = logs.findLast((event) =>
      String(event.hash).toLowerCase() === String(hash).toLowerCase());
    if (found) {
      const index = Number(found.registrationCount) - 1;
      if (!Number.isSafeInteger(index) || index < 0 || index >= count) {
        throw new Error(`block ${blockNum}: invalid ResultHashRegistered index`);
      }
      const row = await chain.resultRegistrationAt(blockNum, index);
      if (String(row?.hash).toLowerCase() !== String(found.hash).toLowerCase()
          || Number(row?.registeredBlock) !== Number(found.updatedAt ?? found.evtBlock)
          || String(row?.signer).toLowerCase() !== String(found.signer).toLowerCase()) {
        throw new Error(`block ${blockNum}: ResultHashRegistered log differs from state row ${index}`);
      }
      return true;
    }
    // 不完全なログ応答でも、getter の正しい行を見落とさない。
  }
  for (let index = count - 1; index >= 0; index--) {
    const row = await chain.resultRegistrationAt(blockNum, index);
    if (String(row?.hash).toLowerCase() === String(hash).toLowerCase()) return true;
  }
  return false;
}

function traceFrameFailed(frame) {
  if (frame?.error != null && String(frame.error).trim() !== '') return true;
  if (frame?.revertReason != null && String(frame.revertReason).trim() !== '') return true;
  if (frame?.status === false || frame?.status === 0 || frame?.status === '0x0') return true;
  return false;
}

function traceProofSubmissionCalls(
  frame,
  tokenMining,
  matches = [],
) {
  const pending = [{ frame, isRoot: true, ancestorFailed: false }];
  while (pending.length > 0) {
    const current = pending.pop();
    const node = current.frame;
    if (!node || typeof node !== 'object') continue;
    const failed = current.ancestorFailed || traceFrameFailed(node);
    if (!failed && !current.isRoot && String(node.type || '').toUpperCase() === 'CALL'
        && String(node.to || '').toLowerCase() === tokenMining.toLowerCase()
        && typeof node.input === 'string') {
      try {
        matches.push({ input: node.input, call: decodeProofSubmissionCalldata(node.input) });
      } catch {
        // TokenMining への別関数呼び出しは数えない。証明付き submit / attach だけが対象。
      }
    }
    if (Array.isArray(node.calls)) {
      for (let i = node.calls.length - 1; i >= 0; i--) {
        pending.push({ frame: node.calls[i], isRoot: false, ancestorFailed: failed });
      }
    }
  }
  return matches;
}

export const PROOF_TRACE_TIMEOUT_MS = 15_000;

/**
 * 証明イベントの実際の calldata と、そこに名乗られた前結果履歴の添字を返す。
 * 直送なら tx.input、中継なら成功した TokenMining CALL の input を使う。
 * P8b の証人も `prevRegistrationIndex` と `calldata` を同じ戻り値から使うこと。
 */
export async function resolveProofSubmissionCalldata({ chain, event, transaction = null, targetBlockNum = null }) {
  if (!event?.txHash) throw new Error('proof submission/attachment transaction hash is missing');
  const tx = transaction || await chain.client.getTransaction({ hash: event.txHash });
  const tokenMining = chain.contracts.tokenMining;
  if (tx.to?.toLowerCase() === tokenMining.toLowerCase()) {
    const call = decodeProofSubmissionCalldata(tx.input);
    const claimed = requireProofPrevRegistrationIndex(tx.input);
    return {
      calldata: tx.input,
      input: tx.input,
      call,
      prevRegistrationIndex: claimed.prevRegistrationIndex,
      route: 'direct',
    };
  }

  let trace;
  try {
    let timer;
    try {
      trace = await Promise.race([
        chain.client.request({
          method: 'debug_traceTransaction',
          params: [event.txHash, { tracer: 'callTracer' }],
        }),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('callTracer timed out')), PROOF_TRACE_TIMEOUT_MS);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  } catch (error) {
    if (/(?:response|trace|body).{0,40}(?:too large|size limit|exceeds.*limit)/i.test(errorText(error))) {
      throw new Error('trace_too_large: callTracer response exceeded its size limit');
    }
    throw new Error(`internal_call_trace_unavailable: ${errorText(error)}`);
  }
  const tracedCalls = traceProofSubmissionCalls(trace, tokenMining);
  const matches = targetBlockNum == null ? tracedCalls
    : tracedCalls.filter((match) => match.call.blockNum === BigInt(targetBlockNum));
  if (matches.length === 0) {
    throw new Error('internal_call_not_found: TokenMining proof submit/attach call was not found');
  }
  if (matches.length !== 1) {
    throw new Error(`internal_call_ambiguous: found ${matches.length} TokenMining proof submit/attach calls`);
  }
  const match = matches[0];
  const claimed = requireProofPrevRegistrationIndex(match.input);
  return {
    calldata: match.input,
    input: match.input,
    call: match.call,
    prevRegistrationIndex: claimed.prevRegistrationIndex,
    route: 'internal',
  };
}

/**
 * 最終 MerkleRootSubmitted / MerkleRootProofAttached tx を読み、証明外形と public values を検査する。
 * 直送でなければ callTracer の内側にある TokenMining 向け証明呼び出し1件だけを採用する。
 * RPC取得不能は invalid と混同せず unavailable を返すが、呼び出し側は pass にしない。
 */
export async function inspectProofSubmission({
  chain, blockNum, root, event, epoch, artifacts, r2Base, confirmationBlocks = 64,
  emergencyMode = false, report = null,
}) {
  let transaction;
  try {
    if (!event?.txHash) throw new Error('proof submission/attachment transaction hash is missing');
    transaction = await chain.client.getTransaction({ hash: event.txHash });
  } catch (error) {
    return {
      format: { status: 'unavailable', error: errorText(error) },
      publicValues: { status: 'unavailable', error: 'submission transaction was not available' },
    };
  }

  let call;
  let claimedPrevRegistration;
  let resolvedSubmission;
  try {
    resolvedSubmission = await resolveProofSubmissionCalldata({
      chain, event, transaction, targetBlockNum: blockNum,
    });
    call = resolvedSubmission.call;
    claimedPrevRegistration = resolvedSubmission.prevRegistrationIndex;
  } catch (error) {
    return {
      format: { status: 'fail', error: errorText(error) },
      publicValues: { status: 'fail', error: 'proof calldata could not be decoded' },
    };
  }

  const envelope = inspectProofEnvelope({
    proofBytes: call.proofBytes,
    publicValues: call.publicValues,
    blockNum,
    root,
  });
  const callMatches = call.blockNum === BigInt(blockNum)
    && (call.root == null || String(call.root).toLowerCase() === String(root).toLowerCase());
  if (!callMatches) {
    envelope.errors.push(`calldata block/root != blockStates (${call.blockNum}, ${call.root})`);
    envelope.ok = false;
  }
  if (epoch && (String(call.expectedVerifier).toLowerCase() !== String(epoch.verifier).toLowerCase()
    || String(call.expectedVkey).toLowerCase() !== String(epoch.vkey).toLowerCase())) {
    envelope.errors.push(
      `calldata expected prover ${call.expectedVerifier}/${call.expectedVkey} != recorded epoch ${epoch.verifier}/${epoch.vkey}`
    );
    envelope.ok = false;
  }
  if (!envelope.ok) {
    return {
      format: { status: 'fail', ...envelope },
      publicValues: { status: 'fail', error: 'proof envelope is invalid' },
      resolvedSubmission,
    };
  }

  let collected;
  let collectionError = null;
  let collectorClient;
  let snapshotBlock;
  let anchorReplaySucceeded = false;
  try {
    if (!Number.isInteger(event.evtBlock) || event.evtBlock < 0) {
      throw new Error(`invalid proof transaction block: ${event.evtBlock}`);
    }
    snapshotBlock = BigInt(event.evtBlock);
    collectorClient = historicalClient(chain, snapshotBlock);
    collected = await collectZkpInput({
      rpcUrl: chain.rpcUrl,
      tokenMining: chain.contracts.tokenMining,
      blockNum,
      r2Base,
      fetchImpl: localArtifactFetch(blockNum, artifacts),
      client: collectorClient,
      namedPrevRegistrationIndex: claimedPrevRegistration,
      skipGroupingRecord: true,
      confirmationBlocks,
    });
  } catch (error) {
    collectionError = error;
    if (claimedPrevRegistration === PREV_REGISTRATION_SENTINEL
        && error?.zkpInvalidPrevRegistration === true && event.logIndex != null
        && collectorClient) {
      try {
        collectorClient = await sentinelClientAtProof(
          chain, event, blockNum, snapshotBlock, collectorClient,
        );
        collected = await collectZkpInput({
          rpcUrl: chain.rpcUrl,
          tokenMining: chain.contracts.tokenMining,
          blockNum,
          r2Base,
          fetchImpl: localArtifactFetch(blockNum, artifacts),
          client: collectorClient,
          namedPrevRegistrationIndex: claimedPrevRegistration,
          skipGroupingRecord: true,
          confirmationBlocks,
        });
        collectionError = null;
      } catch (retryError) {
        // 番兵の再現が通った後に word6 の目印不一致へ進んだ場合、
        // 緊急の13語再照合には番兵補正済み client とその原因を引き継ぐ。
        if (retryError?.zkpChainAnchorMismatch === true) collectionError = retryError;
        // それ以外は従来の番兵不合格を保持する。
      }
    }
    // U-7 は緊急経路だけ。末尾 state の目印が固定一式と違う場合も、
    // その一語だけを仮に固定一式へ置いて他の13語を collector で再照合する。
    const mismatch = !collected && emergencyMode && collectionError?.zkpChainAnchorMismatch === true
      ? resultAnchorMismatchHashes(collectionError) : null;
    if (mismatch && collectorClient) {
      try {
        const hashStorage = await chain.client.readContract({
          address: chain.contracts.tokenMining, abi: TOKEN_MINING_ABI,
          functionName: 'hashStorage', blockNumber: snapshotBlock,
        });
        collected = await collectZkpInput({
          rpcUrl: chain.rpcUrl,
          tokenMining: chain.contracts.tokenMining,
          blockNum,
          r2Base,
          fetchImpl: localArtifactFetch(blockNum, artifacts),
          client: {
            ...collectorClient,
            readContract: (request) =>
              String(request.address).toLowerCase() === String(hashStorage).toLowerCase()
                && request.functionName === 'resultHashes'
                && BigInt(request.args?.[0] ?? -1) === BigInt(blockNum)
                ? [mismatch.reconstructedResultHash, 0n, '0x0000000000000000000000000000000000000000']
                : collectorClient.readContract(request),
          },
          namedPrevRegistrationIndex: claimedPrevRegistration,
          skipGroupingRecord: true,
          confirmationBlocks,
        });
        anchorReplaySucceeded = true;
      } catch (replayError) {
        collectionError = replayError;
      }
    }
    if (!collected && collectionError instanceof ArchiveUnavailableError) {
      return {
        format: { status: 'pass', ...envelope },
        publicValues: await compareProofWords({ chain, blockNum, root, event,
          actual: envelope.decoded, prevRegistrationIndex: claimedPrevRegistration,
          report, confirmationBlocks, unavailableError: collectionError }),
        resolvedSubmission,
      };
    }
    if (!collected) return {
      format: { status: 'pass', ...envelope },
      publicValues: collectionError?.zkpInvalidPrevRegistration === true
        ? { status: 'fail', error: errorText(collectionError) }
        : emergencyMode && collectionError?.zkpChainAnchorMismatch === true
          ? { status: 'fail', error: errorText(collectionError) }
        : describeZkpCollectionFailure(collectionError, event.evtBlock),
      resolvedSubmission,
    };
  }

  try {
    const compared = compareRebuiltPublicValues(call.publicValues, collected);
    if (anchorReplaySucceeded && compared.mismatches.some((row) => row.name === 'resultManifestHash')
        && await proofHashInResultHistory(chain, blockNum, compared.actual.resultManifestHash)) {
      return {
        format: { status: 'pass', ...envelope },
        publicValues: {
          status: 'unavailable',
          cause: ZKP_COLLECTION_FAILURE_CAUSES.proofBoundToOtherManifest,
          error: errorText(collectionError),
          proofBoundResultHash: String(compared.actual.resultManifestHash).toLowerCase(),
          otherMismatches: compared.mismatches
            .filter((row) => row.name !== 'resultManifestHash').map((row) => row.name),
          snapshotBlock: collected.snapshotBlock,
        },
        resolvedSubmission,
      };
    }
    if (anchorReplaySucceeded && compared.ok) {
      if (!await proofHashInResultHistory(chain, blockNum, compared.actual.resultManifestHash)) {
        return {
          format: { status: 'pass', ...envelope },
          publicValues: { status: 'fail', error: errorText(collectionError) },
          resolvedSubmission,
        };
      }
      return {
        format: { status: 'pass', ...envelope },
        publicValues: { status: 'pass', ...compared, snapshotBlock: collected.snapshotBlock },
        resolvedSubmission,
      };
    }
    if (emergencyMode && compared.mismatches.length === 1
        && compared.mismatches[0].name === 'resultManifestHash'
        && await proofHashInResultHistory(chain, blockNum, compared.actual.resultManifestHash)) {
      return {
        format: { status: 'pass', ...envelope },
        publicValues: {
          status: 'unavailable',
          cause: ZKP_COLLECTION_FAILURE_CAUSES.proofBoundToOtherManifest,
          error: collectionError ? errorText(collectionError)
            : 'proof public values bind another registered result manifest',
          proofBoundResultHash: String(compared.actual.resultManifestHash).toLowerCase(),
          snapshotBlock: collected.snapshotBlock,
        },
        resolvedSubmission,
      };
    }
    if (collectionError && compared.ok) {
      return {
        format: { status: 'pass', ...envelope },
        publicValues: { status: 'fail', error: errorText(collectionError) },
        resolvedSubmission,
      };
    }
    return {
      format: { status: 'pass', ...envelope },
      publicValues: { status: compared.ok ? 'pass' : 'fail', ...compared, snapshotBlock: collected.snapshotBlock },
      resolvedSubmission,
    };
  } catch (error) {
    return {
      format: { status: 'pass', ...envelope },
      publicValues: { status: 'fail', error: errorText(error) },
      resolvedSubmission,
    };
  }
}

/// ブロック → 世代 の対応を集める。
/// `BlockState.zkEpochPlusOne` は**提出時に刻まれる**ので、時刻からの逆算と違い
/// ルート再提出でずれない（これが範囲表示の根拠）。
export const ZKP_BLOCK_READ_CONCURRENCY = 10;

export async function collectBlockEpochs(chain, maxBlock) {
  const byEpoch = new Map();   // epochIndex(0始まり) | -1(証明なし) → [blockNum]
  byEpoch.unavailable = [];
  byEpoch.unsubmitted = [];
  for (let start = 0; start <= maxBlock; start += ZKP_BLOCK_READ_CONCURRENCY) {
    const end = Math.min(maxBlock, start + ZKP_BLOCK_READ_CONCURRENCY - 1);
    const unit = await Promise.all(Array.from({ length: end - start + 1 }, async (_, index) => {
      const blockNum = start + index;
      try { return { blockNum, state: await chain.blockStates(blockNum), error: null }; }
      catch (error) { return { blockNum, state: null, error }; }
    }));
    for (const { blockNum, state: st, error } of unit) {
      if (error) {
        byEpoch.unavailable.push({ blockNum, error: errorText(error) });
        continue;
      }
      if (!st?.root || /^0x0+$/.test(st.root)) {
        byEpoch.unsubmitted.push(blockNum);
        continue;
      }
      const epochPlusOne = Number(st.zkEpochPlusOne);
      if (!Number.isSafeInteger(epochPlusOne) || epochPlusOne < 0) {
        byEpoch.unavailable.push({
          blockNum,
          error: `blockStates.zkEpochPlusOne is unavailable or invalid: ${st.zkEpochPlusOne}`,
        });
        continue;
      }
      const key = epochPlusOne > 0 ? epochPlusOne - 1 : -1;
      if (!byEpoch.has(key)) byEpoch.set(key, []);
      byEpoch.get(key).push(blockNum);
    }
  }
  return byEpoch;
}

/// [0,1,2,5,6] → "0-2, 5-6"
export function formatRanges(nums) {
  if (!nums || nums.length === 0) return '-';
  const sorted = [...nums].sort((a, b) => a - b);
  const parts = [];
  let start = sorted[0], prev = sorted[0];
  for (let i = 1; i <= sorted.length; i++) {
    const cur = sorted[i];
    if (cur === prev + 1) { prev = cur; continue; }
    parts.push(start === prev ? `${start}` : `${start}-${prev}`);
    start = cur; prev = cur;
  }
  return parts.join(', ');
}

function guestSourceBuffer(bytes) {
  if (Buffer.isBuffer(bytes) || bytes instanceof Uint8Array) return Buffer.from(bytes);
  if (typeof bytes !== 'string' || !/^0x(?:[0-9a-fA-F]{2})+$/.test(bytes)) {
    throw new Error('guest source must be non-empty bytes or 0x-prefixed hex');
  }
  return Buffer.from(bytes.slice(2), 'hex');
}

function validateSp1Image(image) {
  if (!SP1_IMAGE_PATTERN.test(image || '')) {
    throw new Error('guest source v1: sp1-image must be ghcr.io/succinctlabs/sp1 pinned by lowercase sha256 digest');
  }
  return image;
}

export function validateGuestSourcePath(fpath, limits = GUEST_SOURCE_LIMITS) {
  if (typeof fpath !== 'string' || fpath.length === 0) throw new Error('guest source v1: file path is empty');
  const pathBytes = Buffer.byteLength(fpath, 'utf8');
  if (pathBytes > limits.pathBytes) throw new Error(`guest source v1: file path exceeds ${limits.pathBytes} bytes`);
  if (fpath.includes('\0')) throw new Error('guest source v1: file path contains NUL');
  if (fpath.includes('\\')) throw new Error('guest source v1: backslash is not allowed in file path');
  if (path.posix.isAbsolute(fpath)) throw new Error('guest source v1: absolute file path is not allowed');
  const segments = fpath.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw new Error('guest source v1: file path contains an empty or dot segment');
  }
  if (segments.some((segment) => /[\u0000-\u001f\u007f]/u.test(segment))) {
    throw new Error('guest source v1: control character is not allowed in file path');
  }
  if (path.posix.normalize(fpath) !== fpath) throw new Error('guest source v1: file path is not normalized');
  return fpath;
}

function assertNoPathConflict(paths, candidate) {
  if (paths.has(candidate)) throw new Error(`guest source v1: duplicate file path ${candidate}`);
  for (const existing of paths) {
    if (candidate.startsWith(`${existing}/`) || existing.startsWith(`${candidate}/`)) {
      throw new Error(`guest source v1: file/directory prefix conflict ${candidate}`);
    }
  }
}

/// 従来v1 payloadを厳密に展開する。v2はこの全体をBrotli圧縮して包む。
function unpackGuestSourceV1(buf, limits) {
  // 🔴 **必ずバイト単位で走査すること。** ヘッダの長さはバイト数だが、JS の文字列
  //    インデックスは UTF-16 単位なので、非ASCII（日本語コメント等）が入ると
  //    `String.slice(i, i+len)` が**静かに途中で切れる**。実際にこれを踏んだ
  //    （12ファイルのうち2ファイルしか復元されず、しかもエラーが出なかった）。
  const files = [];
  const paths = new Set();
  let sp1Image = null;
  let i = 0;
  const readLine = () => {
    const end = buf.indexOf(0x0a, i);
    if (end < 0) throw new Error(`guest source v1: unterminated header at byte ${i}`);
    if (end - i > limits.headerBytes) {
      throw new Error(`guest source v1: header exceeds ${limits.headerBytes} bytes`);
    }
    const line = decodeUtf8(buf.subarray(i, end), 'guest source v1 header');
    i = end + 1;
    return line;
  };

  const magic = readLine();
  if (magic !== 'bitcoinu-guest-source/1') throw new Error(`guest source v1: invalid inner magic ${magic}`);

  while (i < buf.length) {
    const line = readLine();
    if (line.startsWith('sp1-image\t')) {
      const fields = line.split('\t');
      if (fields.length !== 2 || !fields[1] || sp1Image !== null) throw new Error('guest source v1: invalid sp1-image header');
      sp1Image = validateSp1Image(fields[1]);
      continue;
    }
    if (line.startsWith('file\t')) {
      const fields = line.split('\t');
      if (fields.length !== 3 || !fields[1] || !/^(0|[1-9]\d*)$/.test(fields[2])) {
        throw new Error(`guest source v1: invalid file header ${line}`);
      }
      const [, fpath, lenStr] = fields;
      validateGuestSourcePath(fpath, limits);
      assertNoPathConflict(paths, fpath);
      const len = Number(lenStr);
      if (!Number.isSafeInteger(len) || len > limits.fileBytes) {
        throw new Error(`guest source v1: file ${fpath} exceeds ${limits.fileBytes} bytes`);
      }
      if (i + len >= buf.length || buf[i + len] !== 0x0a) {
        throw new Error(`guest source v1: invalid byte length for ${fpath}`);
      }
      if (files.length >= limits.files) throw new Error(`guest source v1: file count exceeds ${limits.files}`);
      const body = buf.subarray(i, i + len);
      files.push({ path: fpath, content: decodeUtf8(body, `guest source v1 file ${fpath}`), bytes: body });
      paths.add(fpath);
      i += len + 1; // 本文＋末尾の改行
      continue;
    }
    if (line.trim() === '') continue;
    throw new Error(`guest source v1: unknown header ${line}`);
  }
  if (!sp1Image) throw new Error('guest source v1: sp1-image is missing');
  return { magic, sp1Image, files };
}

/// 公開packageを展開する。v2は平文のversion/codecヘッダ＋Brotli(v1 payload)。
/// 未知version・codec・壊れた圧縮本文は必ず例外にしてfail-closedにする。
export function unpackGuestSource(bytes, limits = GUEST_SOURCE_LIMITS) {
  const packageBytes = guestSourceBuffer(bytes);
  if (packageBytes.length > limits.packageBytes) {
    throw new Error(`guest source package exceeds ${limits.packageBytes} bytes`);
  }
  const headerEnd = packageBytes.indexOf(0x0a);
  if (headerEnd < 0) throw new Error('guest source: unterminated format header');
  if (headerEnd > limits.headerBytes) throw new Error(`guest source: format header exceeds ${limits.headerBytes} bytes`);
  const header = decodeUtf8(packageBytes.subarray(0, headerEnd), 'guest source format header');

  if (header === 'bitcoinu-guest-source/1') {
    if (packageBytes.length > limits.payloadBytes) throw new Error(`guest source payload exceeds ${limits.payloadBytes} bytes`);
    const unpacked = unpackGuestSourceV1(packageBytes, limits);
    return { ...unpacked, formatVersion: 1, codec: 'none', rawBytes: packageBytes.length, payloadBytes: packageBytes.length };
  }

  const fields = header.split('\t');
  const magic = fields[0];
  if (magic !== 'bitcoinu-guest-source/2') throw new Error(`unsupported guest source format: ${magic}`);
  if (fields.length !== 2 || fields[1] !== 'brotli') {
    throw new Error(`unsupported guest source codec: ${fields.slice(1).join('\t') || '(missing)'}`);
  }
  const compressed = packageBytes.subarray(headerEnd + 1);
  if (compressed.length === 0) throw new Error('guest source v2: compressed payload is empty');
  let payload;
  try {
    // NodeのmaxOutputLengthは出力Buffer確保前に上限を強制する。高圧縮bombもOOM前に停止する。
    payload = brotliDecompressSync(compressed, { maxOutputLength: limits.payloadBytes });
  } catch (error) {
    if (error?.code === 'ERR_BUFFER_TOO_LARGE' || /maxOutputLength|larger than/i.test(error?.message || '')) {
      throw new Error(`guest source v2: payload exceeds ${limits.payloadBytes} bytes`);
    }
    throw new Error(`guest source v2: invalid brotli payload: ${error.message}`);
  }
  if (payload.length > limits.payloadBytes) throw new Error(`guest source v2: payload exceeds ${limits.payloadBytes} bytes`);
  const unpacked = unpackGuestSourceV1(payload, limits);
  return {
    ...unpacked,
    magic,
    innerMagic: unpacked.magic,
    formatVersion: 2,
    codec: 'brotli',
    rawBytes: packageBytes.length,
    payloadBytes: payload.length,
  };
}

function ensureNewDirectoryTree(root, relativeDir) {
  let cursor = root;
  for (const segment of relativeDir.split('/').filter(Boolean)) {
    cursor = path.join(cursor, segment);
    try { fs.mkdirSync(cursor, { mode: 0o700 }); }
    catch (error) { if (error?.code !== 'EEXIST') throw error; }
    const stat = fs.lstatSync(cursor);
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error(`unsafe output directory component: ${cursor}`);
  }
}

/** 検証済みpackageを新規directoryへだけ書く。失敗時は最終出力先を作らない。 */
export function writeGuestSourceSafely(unpacked, baseDir, directoryName) {
  // Gate (a): reject executable Cargo inputs before creating any output tree.
  checkWireBuildInputs(unpacked.files);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(directoryName || '')) throw new Error('invalid guest source output directory name');
  const base = path.resolve(baseDir || '.');
  fs.mkdirSync(base, { recursive: true, mode: 0o700 });
  const baseStat = fs.lstatSync(base);
  if (baseStat.isSymbolicLink() || !baseStat.isDirectory()) throw new Error('guest source output base must be a real directory');
  const realBase = fs.realpathSync(base);
  const outDir = path.resolve(realBase, directoryName);
  if (path.dirname(outDir) !== realBase) throw new Error('guest source output escaped its base directory');
  const outputExists = () => { try { fs.lstatSync(outDir); return true; } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  } };
  const outputExistsError = () => Object.assign(new Error(`guest source output already exists: ${outDir}`),
    { code: 'GUEST_SOURCE_OUTPUT_EXISTS' });
  if (outputExists()) throw outputExistsError();

  const tempDir = fs.mkdtempSync(path.join(realBase, '.zkp-guest-source-tmp-'));
  let published = false;
  try {
    const seen = new Set();
    for (const file of unpacked?.files || []) {
      const fpath = validateGuestSourcePath(file.path);
      assertNoPathConflict(seen, fpath);
      seen.add(fpath);
      const target = path.resolve(tempDir, ...fpath.split('/'));
      if (!target.startsWith(`${tempDir}${path.sep}`)) throw new Error(`guest source output escaped temporary directory: ${quotedSourcePath(fpath)}`);
      ensureNewDirectoryTree(tempDir, path.posix.dirname(fpath) === '.' ? '' : path.posix.dirname(fpath));
      if (!Number.isInteger(fs.constants.O_NOFOLLOW)) throw new Error('this platform cannot enforce O_NOFOLLOW');
      const flags = fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW;
      const fd = fs.openSync(target, flags, 0o600);
      try { fs.writeFileSync(fd, file.bytes); }
      finally { fs.closeSync(fd); }
    }
    for (const crate of new Set(WIRE_GUESTS.map((guest) => guest.crate))) {
      ensureNewDirectoryTree(tempDir, crate);
      const target = path.join(tempDir, crate, 'target');
      if (fs.existsSync(target)) throw new Error(`${crate}: source overlaps writable target`);
      fs.mkdirSync(target, { mode: 0o700 });
    }
    if (outputExists()) throw outputExistsError();
    fs.renameSync(tempDir, outDir);
    published = true;
    return outDir;
  } finally {
    if (!published) fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

function shellQuote(value) {
  const text = String(value);
  return /^[A-Za-z0-9_./:@%+=,-]+$/.test(text) ? text : `'${text.replaceAll("'", `'"'"'`)}'`;
}

// sp1-build 6.3.1 docker.rs/build_docker_args and command/utils.rs. The
// succinct rustc version and sysroot were observed for this exact digest in
// the stage3-l4-current-standard remote build log. WR-15-FIX3 RESULT §7
// records captured docker argv and byte-equal ELF builds for representative guests.
const SP1_REBUILD_IMAGE = 'ghcr.io/succinctlabs/sp1@sha256:0942a27dbe8e38f4b14f3732e779df4027b17bde93e9fbc9e8c773c15eb63400';
// The image above and each guest Cargo.lock pin SP1 6.3.1. The prover install
// is pinned to this commit in services/zkp-prover/Dockerfile.batch.
const SP1_PROVE_VERSION = '6.3.1';
const SP1_PROVE_COMMIT = '8252c29';
const SP1_REBUILD_RUSTC = '/root/.sp1/toolchains/g7wv95WZT7/bin/rustc';
const SP1_REBUILD_FLAGS = [
  '-C', 'passes=lower-atomic', '-C', 'link-arg=--image-base=2013265920',
  '-C', 'panic=abort', '--cfg', 'getrandom_backend="custom"',
  '-C', 'llvm-args=-misched-prera-direction=bottomup',
  '-C', 'llvm-args=-misched-postra-direction=bottomup',
].join('\x1f');
const SP1_TARGET = 'riscv64im-succinct-zkvm-elf';

function rebuildEnvironment(crate) {
  return [
    `CARGO_TARGET_DIR=/root/program/${crate}/target/elf-compilation/docker`,
    'RUSTUP_TOOLCHAIN=succinct',
    'RUSTC_BOOTSTRAP=1',
    `CARGO_ENCODED_RUSTFLAGS=${SP1_REBUILD_FLAGS}`,
    `RUSTC=${SP1_REBUILD_RUSTC}`,
    'CFLAGS_riscv32im_succinct_zkvm_elf=-D__ILP32__',
  ].join('\n') + '\n';
}

function dockerRebuildCommand(outDir, sp1Image, crate, elf, bin, feature,
  { replaceExistingEnv = false, writtenEnvPaths = null } = {}) {
  validateSp1Image(sp1Image);
  if (sp1Image !== SP1_REBUILD_IMAGE) throw new Error('SP1 image has no captured rebuild parameters');
  const sourceDir = path.resolve(outDir);
  if (/[:,\x00-\x1f\x7f]/.test(sourceDir)) throw new Error('source output path cannot be mounted unambiguously');
  const envPath = `${sourceDir}.${crate}.docker.env`;
  const envBytes = rebuildEnvironment(crate);
  try { fs.writeFileSync(envPath, envBytes, { flag: 'wx', mode: 0o600 }); writtenEnvPaths?.push(envPath); }
  catch (error) {
    if (error?.code !== 'EEXIST') throw error;
    const stat = fs.lstatSync(envPath);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`environment path is not a regular file: ${envPath}`);
    if (replaceExistingEnv) {
      fs.unlinkSync(envPath);
      fs.writeFileSync(envPath, envBytes, { flag: 'wx', mode: 0o600 });
      writtenEnvPaths?.push(envPath);
    } else if (fs.readFileSync(envPath, 'utf8') !== envBytes) {
      throw new Error(`environment file differs from expected content: ${envPath}`);
    }
  }
  // Keep 'cargo' and '--locked' in the same literal argv array for cargoLockAudit.
  const argv = ['docker', 'run', '--rm', '--platform', 'linux/amd64',
    '-v', `${sourceDir}:/root/program:ro`,
    '-v', `${path.join(sourceDir, crate, 'target')}:/root/program/${crate}/target`,
    '-w', `/root/program/${crate}`, '--env-file', envPath,
    '--entrypoint', '', sp1Image, 'cargo', 'build', '--release', '--target', SP1_TARGET,
    '--locked'];
  if (bin) argv.splice(argv.indexOf('--locked'), 0, '--bin', bin, '--features', feature);
  return { argv, build: argv.map(shellQuote).join(' '),
    elfPath: path.join(sourceDir, crate, 'target/elf-compilation/docker', SP1_TARGET, 'release', elf),
    envPath };
}

export function formatWireGuestRebuildCommands(outDir, sp1Image, files, { replaceExistingEnv = false } = {}) {
  // Gate (c): execution and formatting require the same source audit.
  checkWireBuildInputs(files);
  const writtenEnvPaths = [];
  try {
    return WIRE_GUESTS.map((guest) => ({ ...guest, ...dockerRebuildCommand(outDir, sp1Image,
      guest.crate, guest.elf, guest.bin, guest.feature, { replaceExistingEnv, writtenEnvPaths }) }));
  } catch (error) {
    for (const envPath of writtenEnvPaths) fs.rmSync(envPath, { force: true });
    throw error;
  }
}

export async function cargoProveVkey(p, spawnProcess = spawn) {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'bitcoinu-vkey-'));
  try {
    // Invoke the external subcommand directly: Cargo aliases in ancestor
    // .cargo/config.toml must not be able to replace `prove`.
    const cmd = ['cargo-prove', 'prove', 'vkey', '--elf', p];
    const stdout = await new Promise((resolve, reject) => {
      const child = spawnProcess(cmd[0], cmd.slice(1), { shell: false, cwd });
      let out = '';
      let err = '';
      child.stdout.on('data', (bytes) => { out += bytes.toString(); });
      child.stderr.on('data', (bytes) => { err += bytes.toString(); });
      child.on('error', reject);
      child.on('close', (code) => code === 0 ? resolve(out) : reject(new Error(`cargo-prove vkey exited ${code}: ${err}`)));
    });
    const keys = stdout.match(/0x[0-9a-fA-F]{64}/g) || [];
    if (keys.length !== 1) throw new Error('cargo prove vkey did not return exactly one bytes32 key');
    return keys[0].toLowerCase();
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
}

export async function cargoProveVersion(spawnProcess = spawn) {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'bitcoinu-prove-version-'));
  try {
    return await new Promise((resolve, reject) => {
      const child = spawnProcess('cargo-prove', ['prove', '--version'], { shell: false, cwd });
      let output = '';
      child.stdout.on('data', (bytes) => { output += bytes.toString(); });
      child.stderr.on('data', (bytes) => { output += bytes.toString(); });
      child.on('error', reject);
      child.on('close', (code) => code === 0 ? resolve(output.trim())
        : reject(new Error(`cargo-prove prove --version exited ${code}: ${output.trim()}`)));
    });
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
}

function matchingCargoProveVersion(version) {
  const commit = version.match(/^(?:cargo-prove\s+)?sp1 \(([0-9a-f]{7,40})(?:\s|\))/m)?.[1];
  return commit?.slice(0, 7) === SP1_PROVE_COMMIT;
}

// 子の出力を端末に継承しない。例外は呼出元で定型文へ変換する。
async function runQuietProcess(argv, spawnProcess) {
  return new Promise((resolve, reject) => {
    const child = spawnProcess(argv[0], argv.slice(1),
      { shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.resume();
    child.stderr.resume();
    child.on('error', reject);
    child.on('close', (code) => code === 0 ? resolve() : reject(new Error('Stage3 process failed')));
  });
}

async function deriveWireGuestVkey(guest, sourceDirectory, runVkey) {
  const target = path.resolve(sourceDirectory, guest.crate, 'target');
  const p = path.join(target, 'elf-compilation/docker', SP1_TARGET, 'release', guest.elf);
  if (!fs.lstatSync(target).isDirectory()) throw new Error('guest target is not a real directory');
  if (!fs.lstatSync(p).isFile()) throw new Error('ELF is not a regular file');
  const realSource = fs.realpathSync(sourceDirectory);
  const realTarget = fs.realpathSync(target);
  const realElf = fs.realpathSync(p);
  if (!realTarget.startsWith(`${realSource}${path.sep}`)) throw new Error('guest target escapes source');
  if (!realElf.startsWith(`${realTarget}${path.sep}`)) throw new Error('ELF escapes guest target');
  return runVkey(p);
}

// readline の raw mode と OS の SIGINT の両方を受ける。子の close まで待ってから
// cargo-prove の finally を通し、一時ディレクトリを消して終了する。
function stage3Interruption(prompts, spawnProcess) {
  const controller = new AbortController();
  const { signal } = controller;
  const interrupt = () => controller.abort();
  process.on('SIGINT', interrupt);
  const unsubscribe = prompts.onInterrupt?.(interrupt);
  return {
    signal,
    close() { process.removeListener('SIGINT', interrupt); unsubscribe?.(); },
    async waitFor(operation) {
      signal.throwIfAborted();
      let onAbort;
      const aborted = new Promise((_, reject) => {
        onAbort = () => reject(signal.reason);
        signal.addEventListener('abort', onAbort, { once: true });
      });
      try { return await Promise.race([operation(), aborted]); }
      finally { signal.removeEventListener('abort', onAbort); }
    },
    spawn(command, args, options) {
      signal.throwIfAborted();
      const child = spawnProcess(command, args, options);
      let terminate, force;
      const stop = () => {
        const kill = (signal) => child.kill(signal);
        kill('SIGINT');
        terminate = setTimeout(() => kill('SIGTERM'), 300);
        force = setTimeout(() => kill('SIGKILL'), 1300);
      };
      signal.addEventListener('abort', stop, { once: true });
      const cleanup = () => {
        signal.removeEventListener('abort', stop);
        clearTimeout(terminate); clearTimeout(force);
      };
      child.once('close', cleanup);
      child.once('error', cleanup);
      return child;
    },
  };
}

async function rebuildWireGuestParts(commands, outDir, vkeys, failed, ui, spawnProcess, runVkey, signal) {
  let done = 0;
  const running = () => {
    signal.throwIfAborted();
    ui.println(ui.t('zk.running', { done: ++done, total: commands.length * 2 }));
  };
  const built = [];
  for (const command of commands) {
    delete vkeys[command.id];
    failed.add(command.id);
    running();
    try {
      await runQuietProcess(command.argv, spawnProcess);
      built.push(command);
    } catch { signal.throwIfAborted(); }
  }
  for (const command of built) {
    running();
    try {
      vkeys[command.id] = await deriveWireGuestVkey(command, outDir, runVkey);
      failed.delete(command.id);
    } catch { signal.throwIfAborted(); }
  }
  signal.throwIfAborted();
}

export async function inspectWireGuestVkeys(unpacked, epochVkey, sourceDirectory,
  runVkey = cargoProveVkey, readVersion = cargoProveVersion,
  { beforeVkey = () => {}, throwOnError = false } = {}) {
  // A different local prover can derive different keys from byte-identical ELF.
  // Classify every edge as unavailable before deriving any key in that case.
  try {
    checkWireBuildInputs(unpacked.files);
    if (unpacked.sp1Image !== SP1_REBUILD_IMAGE) throw new Error('SP1 image differs from the pinned 6.3.1 image');
    const lock = unpacked.files.find((file) => file.path === 'final-wire-guest/Cargo.lock');
    if (!lock || !/^name = "sp1-zkvm"\nversion = "6\.3\.1"$/m.test(Buffer.from(lock.bytes).toString('utf8'))) {
      throw new Error('published Cargo.lock does not pin sp1-zkvm 6.3.1');
    }
    const version = await readVersion();
    if (!matchingCargoProveVersion(version)) {
      throw new Error(`cargo-prove version mismatch: expected SP1 ${SP1_PROVE_VERSION} (${SP1_PROVE_COMMIT}), got ${version || '(empty)'}; install with sp1up -v ${SP1_PROVE_VERSION} and check cargo-prove prove --version`);
    }
  } catch (error) {
    if (throwOnError) throw error;
    const reason = String(error.message || error);
    return [...WIRE_VKEY_EDGES, { parent: 'CHAIN', child: 'FINAL' }]
      .map((edge) => ({ ...edge, status: 'unavailable', reason }));
  }
  const vkeys = {};
  const unavailable = {};
  for (const guest of WIRE_GUESTS) {
    beforeVkey(guest);
    try { vkeys[guest.id] = await deriveWireGuestVkey(guest, sourceDirectory, runVkey); }
    catch (error) {
      if (throwOnError) throw error;
      unavailable[guest.id] = String(error.message || error);
    }
  }
  const results = verifyWireVkeys(unpacked.files, vkeys, epochVkey);
  return results.map((item) => item.status === 'unavailable' && unavailable[item.child]
    ? { ...item, reason: unavailable[item.child] } : item);
}

export function wireVkeyExitCode(wireResults, { pinMismatch = false, verifierMismatch = false, scanIncomplete = false } = {}) {
  if (pinMismatch || verifierMismatch || wireResults?.some((result) => result.status !== 'pass')) return 2;
  return scanIncomplete ? 1 : 0;
}

/// 契約と同じ package ID: H0=bytes32(0)、全チャンクで H=keccak(Hprev || keccak(chunk))。
export function guestSourceChainHash(chunks) {
  if (!Array.isArray(chunks) || chunks.length === 0) throw new Error('guest source chunks are empty');
  let running = ZERO_HASH;
  for (const chunk of chunks) {
    if (!/^0x(?:[0-9a-fA-F]{2})+$/.test(chunk || '')) throw new Error('guest source chunk is empty or invalid hex');
    const leaf = keccak256(chunk);
    running = keccak256(concatHex([running, leaf]));
  }
  return running;
}

export function joinGuestSourceChunks(chunks, expectedHash) {
  const actual = guestSourceChainHash(chunks);
  if (actual.toLowerCase() !== expectedHash.toLowerCase()) {
    throw new Error(`guest source hash mismatch: actual=${actual}, expected=${expectedHash}`);
  }
  return concatHex(chunks);
}

/// 現在 state が指す block locator と一致する、順序・runningHash が完全な系列だけを返す。
export function recoverGuestSourceChunks(logs, blockNumbers, expectedHash, expectedTotal) {
  const wantedBlocks = blockNumbers.map((v) => BigInt(v).toString());
  const sorted = [...logs].sort((a, b) => {
    const blockCmp = BigInt(a.blockNumber) < BigInt(b.blockNumber) ? -1 : BigInt(a.blockNumber) > BigInt(b.blockNumber) ? 1 : 0;
    if (blockCmp) return blockCmp;
    return Number(a.logIndex) - Number(b.logIndex);
  });
  let candidate = null;
  let complete = null;
  for (const log of sorted) {
    const args = log.args || {};
    if (String(args.guestSourceHash || '').toLowerCase() !== expectedHash.toLowerCase()) continue;
    const index = Number(args.chunkIndex);
    const total = Number(args.totalChunks);
    if (!Number.isInteger(index) || !Number.isInteger(total) || !/^0x(?:[0-9a-fA-F]{2})+$/.test(args.data || '')) continue;
    if (index === 0) candidate = { total, chunks: [], blocks: [], running: ZERO_HASH };
    if (!candidate || total !== candidate.total || index !== candidate.chunks.length) continue;
    const leaf = keccak256(args.data);
    const running = keccak256(concatHex([candidate.running, leaf]));
    if (String(args.runningHash || '').toLowerCase() !== running.toLowerCase()) {
      candidate = null;
      continue;
    }
    candidate.chunks.push(args.data);
    candidate.blocks.push(BigInt(log.blockNumber).toString());
    candidate.running = running;
    if (candidate.chunks.length === candidate.total
      && candidate.total === expectedTotal
      && running.toLowerCase() === expectedHash.toLowerCase()
      && candidate.blocks.length === wantedBlocks.length
      && candidate.blocks.every((block, i) => block === wantedBlocks[i])) {
      complete = candidate;
    }
  }
  if (!complete) return null;
  return {
    source: joinGuestSourceChunks(complete.chunks, expectedHash),
    chunks: complete.chunks,
    blocks: complete.blocks.map(Number),
  };
}

/// state の ref → block locator → event body の順に辿り、パッケージを復元する。
export async function collectGuestSource(chain, guestSourceHash) {
  const ref = await chain.client.readContract({
    address: chain.contracts.tokenMining,
    abi: GUEST_SOURCE_REF_ABI,
    functionName: 'guestSourceOf',
    args: [guestSourceHash],
  });
  const dataHash = ref[0];
  const chunks = Number(ref[1]);
  const received = Number(ref[2]);
  if (chunks === 0 || received !== chunks || dataHash.toLowerCase() !== guestSourceHash.toLowerCase()) return null;

  const blockNumbers = [];
  for (let index = 0; index < received; index++) {
    blockNumbers.push(await chain.client.readContract({
      address: chain.contracts.tokenMining,
      abi: GUEST_SOURCE_REF_ABI,
      functionName: 'guestSourceBlocks',
      args: [guestSourceHash, BigInt(index)],
    }));
  }
  const logs = [];
  for (const block of [...new Set(blockNumbers.map((v) => BigInt(v).toString()))]) {
    logs.push(...await chain.getLogsChunked({
      address: chain.contracts.tokenMining,
      event: GUEST_SOURCE_CHUNK_EVENT,
      args: { guestSourceHash },
      fromBlock: BigInt(block),
      toBlock: BigInt(block),
    }));
  }
  return recoverGuestSourceChunks(logs, blockNumbers, guestSourceHash, chunks);
}

/// メニュー②の本体。
export async function runZkpMode(cfg, chain, ui, prompts,
  { spawnProcess = spawn, runVkey = null,
    readVersion = cargoProveVersion, platform = process.platform,
    exitProcess = (code) => process.exit(code) } = {}) {
  ui.println('');
  ui.println(SEP);
  ui.println(ui.t('zk.header'));
  ui.println(SEP);

  const [epochs, required, pending] = await Promise.all([
    chain.vkeyEpochs(), chain.proofRequired(), chain.pendingVkeyProposal(),
  ]);
  ui.println('');
  ui.println(ui.t('zk.enforcement', {
    state: required ? ui.t('zk.enforcementOn') : ui.t('zk.enforcementOff'),
  }));

  // ブロック→世代の対応。テストの明示overrideが無ければ契約のMAX_BLOCK_NUMを読む。
  const maxBlock = cfg.zkScanMaxBlock ?? await chain.maxBlockNum();
  const byEpoch = await collectBlockEpochs(chain, maxBlock);
  const unavailable = byEpoch.unavailable || [];
  const scanIncomplete = unavailable.length > 0;
  if (scanIncomplete) {
    ui.warn(ui.t('zk.blockScanUnavailable', {
      count: unavailable.length,
      range: formatRanges(unavailable.map((item) => item.blockNum)),
      error: unavailable[0].error,
    }));
  }

  ui.println('');
  if (epochs.length === 0 && !pending.pending) {
    ui.println(ui.t(scanIncomplete ? 'zk.noEpochsPartial' : 'zk.noEpochs'));
    const noProof = byEpoch.get(-1) || [];
    if (noProof.length > 0) {
      ui.println(ui.t('zk.conclusionShadow', { range: formatRanges(noProof) }));
    }
    return scanIncomplete ? 1 : 0;
  }

  ui.println(ui.t('zk.epochList'));
  const noProof = byEpoch.get(-1) || [];
  if (noProof.length > 0) ui.println(ui.t('zk.noProofRow', { range: formatRanges(noProof) }));
  for (const e of epochs) {
    const blocks = byEpoch.get(e.index) || [];
    const activated = new Date(e.activatedAt * 1000).toLocaleString();
    ui.println(ui.t(blocks.length > 0 ? 'zk.epochRow' : 'zk.epochRowNoBlocks', {
      i: e.index, range: formatRanges(blocks), vkey: e.vkey, activated,
    }));
  }
  if (pending.pending) {
    ui.println(ui.t('zk.pendingRow', {
      vkey: pending.vkey, source: pending.guestSourceHash,
      eta: new Date(pending.eta * 1000).toLocaleString(),
      daysLeft: Math.max(0, Math.ceil((pending.eta - Math.floor(Date.now() / 1000)) / 86400)),
    }));
  }

  // 調べる世代を選ぶ
  let pick = Math.max(0, epochs.length - 1); // 既定は最新の適用済み世代
  if ((epochs.length > 1 || pending.pending) && prompts.isInteractive) {
    const items = epochs.map((e) =>
      `[${e.index}] ${formatRanges(byEpoch.get(e.index) || [])} — ${e.vkey.slice(0, 18)}…`);
    if (pending.pending) items.push(ui.t('zk.pendingChoice', { vkey: pending.vkey,
      eta: new Date(pending.eta * 1000).toLocaleString() }));
    pick = await prompts.choice(ui.t('zk.pickEpoch'), items,
      { defaultIndex: epochs.length ? epochs.length - 1 : 0 });
  }
  const isPending = pending.pending && pick === epochs.length;
  const epoch = isPending ? pending : epochs[pick];
  if (isPending) ui.println(ui.t('zk.pendingSelected'));

  // --- ① 契約の記録と公開イベントの整合 ---
  ui.println('');
  ui.println(ui.t('zk.stage1'));
  ui.println(ui.t('zk.fetching'));
  const published = await collectGuestSource(chain, epoch.guestSourceHash);
  if (!published) {
    ui.warn(ui.t('zk.sourceMissing'));
    return 2;
  }
  ui.println(ui.t('zk.sourceHashOk', { hash: epoch.guestSourceHash }));

  let unpacked, outDir, sourceError, writeError;
  try {
    unpacked = unpackGuestSource(published.source);
    checkWireBuildInputs(unpacked.files);
  } catch (error) {
    sourceError = error;
  }
  if (!sourceError) {
    try {
      const outputName = isPending
        ? `zkp-pending-source-${epoch.vkey.slice(2, 14)}-${epoch.guestSourceHash.slice(2, 14)}`
        : `zkp-guest-source-${epoch.vkey.slice(2, 14)}`;
      for (let suffix = 1; ; suffix++) {
        try {
          outDir = writeGuestSourceSafely(unpacked, cfg.dataDir || '.',
            suffix === 1 ? outputName : `${outputName}-${suffix}`);
          break;
        } catch (error) {
          if (error?.code !== 'GUEST_SOURCE_OUTPUT_EXISTS') throw error;
        }
      }
      ui.println(ui.t('zk.sourceSaved', {
        path: visibleTerminalText(outDir),
      }));
      if (unpacked.sp1Image) ui.println(`  SP1 image: ${unpacked.sp1Image}`);
    } catch (error) {
      // Local write failures are reported only after consent and tool checks.
      writeError = error;
    }
  }

  // --- ② ピン留め値との突き合わせ（ツール公開時点からの差し替え検知） ---
  ui.println('');
  ui.println(ui.t('zk.stage2'));
  const pinned = cfg.zkVkey || null;
  let pinMismatch = false;
  if (isPending) {
    ui.println(ui.t('zk.pendingPinNotApplicable'));
  } else if (!pinned) {
    ui.println(ui.t('zk.pinNone'));
  } else if (pinned.toLowerCase() === epoch.vkey.toLowerCase()) {
    ui.println(ui.t('zk.pinOk', { vkey: epoch.vkey }));
  } else {
    // 🔴 F1-4（第15ラウンド）: ここで即 return すると、③の同意確認が出ない。
    //    pin 不一致は「第三者がいちばん再現ビルドを試したい場面」なので、
    //    同意確認・処理の後に終了コードへ反映する（終了は関数末尾で行う）。
    ui.warn(ui.t('zk.pinDiff', { onchain: epoch.vkey, pinned }));
    pinMismatch = true;
  }
  const verifierMismatch = String(epoch.verifier).toLowerCase() !== ZKP_EXPECTED.verifier.toLowerCase();
  if (verifierMismatch) {
    ui.warn(ui.t('zk.verifierDiff', { onchain: epoch.verifier, expected: ZKP_EXPECTED.verifier }));
  } else {
    ui.println(ui.t('zk.verifierOk', { verifier: epoch.verifier }));
  }

  // --- ③ 同意後に再現ビルド・鍵の算出と照合（任意） ---
  ui.println('');
  ui.println(ui.t('zk.stage3'));
  if (sourceError) {
    ui.warn(ui.t('zk.wireUnsafeSource', { reason: visibleTerminalText(errorText(sourceError)) }));
    return 2;
  }
  let wireResults = null;
  let notVerified = false;
  const confirmed = prompts.isInteractive
    && await prompts.yesNo(ui.t('zk.stage3Confirm'), { defaultValue: null });
  if (confirmed) {
    const interrupted = stage3Interruption(prompts, spawnProcess);
    try {
      let dockerReady = false;
      let version = null;
      let dockerMissing = false;
      let proveNeedsInstall = false;
      try {
        await runQuietProcess(['docker', 'version', '--format', '{{.Server.Version}}'], interrupted.spawn);
        dockerReady = true;
      } catch (error) {
        interrupted.signal.throwIfAborted();
        dockerMissing = error?.code === 'ENOENT';
      }
      try {
        version = await readVersion(interrupted.spawn);
        proveNeedsInstall = !matchingCargoProveVersion(version);
      } catch (error) {
        interrupted.signal.throwIfAborted();
        proveNeedsInstall = error?.code === 'ENOENT';
      }
      interrupted.signal.throwIfAborted();

      if (!dockerReady || version === null || proveNeedsInstall) {
        ui.warn(ui.t('zk.stage3Failed'));
        const installCommands = [];
        if (dockerMissing) {
          const dockerInstall = {
            darwin: 'brew install --cask docker',
            linux: 'curl -fsSL https://get.docker.com | sh',
          }[platform];
          if (dockerInstall) installCommands.push(dockerInstall);
        }
        if (proveNeedsInstall) installCommands.push('curl -fsSL https://sp1up.succinct.xyz | bash',
          '~/.sp1/bin/sp1up -v 6.3.1');
        if (platform !== 'win32' && installCommands.length > 0) {
          ui.println(ui.t('zk.stage3InstallHint'));
          for (const command of installCommands) ui.println(command);
        }
      } else {
        let commands;
        try {
          if (writeError) throw writeError;
          commands = formatWireGuestRebuildCommands(outDir, unpacked.sp1Image, unpacked.files,
            { replaceExistingEnv: true });
        } catch (error) {
          // The formatter cleans up its env-files; keep the source saved in Stage1.
          ui.warn(ui.t('zk.wireUnsafeSource', { reason: visibleTerminalText(errorText(error)) }));
          return 2;
        }
        const vkeys = {};
        const failed = new Set();
        let pendingCommands = commands;
        for (;;) {
          await rebuildWireGuestParts(pendingCommands, outDir, vkeys, failed, ui,
            interrupted.spawn, runVkey || ((p) => cargoProveVkey(p, interrupted.spawn)), interrupted.signal);
          wireResults = verifyWireVkeys(unpacked.files, vkeys, epoch.vkey).map((edge) =>
            failed.has(edge.child) || (failed.has(edge.parent) && edge.status !== 'fail')
              ? { ...edge, status: 'unavailable' } : edge);
          if (wireResults.some((edge) => edge.status === 'fail') || failed.size === 0) break;
          const n = failed.size;
          for (const line of ui.t('zk.stage3RetryExplain', { n }).split('\n')) ui.println(line);
          const retry = await interrupted.waitFor(() =>
            prompts.yesNo(ui.t('zk.stage3RetryPrompt', { n }), { defaultValue: null }));
          interrupted.signal.throwIfAborted();
          if (!retry) { notVerified = true; break; }
          pendingCommands = commands.filter((command) => failed.has(command.id));
        }
      }
    } catch (error) {
      if (!interrupted.signal.aborted) throw error;
    } finally {
      interrupted.close();
      if (interrupted.signal.aborted) {
        prompts.close?.();
        exitProcess(130);
      }
    }
    if (interrupted.signal.aborted) return 130;
  }
  if (wireResults) {
    for (const result of wireResults) {
      ui.println(ui.t('zk.wireEdge', {
        parent: result.parent, child: result.child,
        status: ui.t(`zk.wireStatus.${result.status}`),
        detail: result.status === 'unavailable' ? '-'
          : visibleTerminalText(`${result.baked || result.expected || '-'} / ${result.derived || '-'}`),
      }));
    }
  }
  if (!wireResults) {
    for (const edge of [...WIRE_VKEY_EDGES, { parent: 'CHAIN', child: 'FINAL' }]) {
      ui.println(ui.t('zk.wireEdge', { parent: edge.parent, child: edge.child,
        status: ui.t('zk.wireStatus.unperformed'), detail: '-' }));
    }
    ui.println(ui.t('zk.wireUnperformed'));
  }

  // --- 結論 ---
  const blocks = isPending ? [] : (byEpoch.get(epoch.index) || []);
  ui.println('');
  ui.println(SEP);
  const wireState = !wireResults ? 'unperformed'
    : wireResults.some((result) => result.status === 'fail') ? 'failed'
      : wireResults.some((result) => result.status === 'unavailable') ? 'unavailable' : 'pass';
  if (verifierMismatch) {
    ui.println(ui.t(isPending ? 'zk.conclusionPendingVerifierMismatch' : 'zk.conclusionVerifierMismatch'));
  } else if (notVerified) {
    ui.println(ui.t('zk.stage3NotVerified'));
  } else if (isPending) {
    ui.println(ui.t(`zk.conclusionPending.${wireState}`));
  } else if (wireState === 'pass') {
    ui.println(ui.t('zk.conclusionSourceMatches', { path: visibleTerminalText(outDir) }));
  } else {
    ui.println(blocks.length > 0
      ? ui.t(`zk.conclusionWire.${wireState}`, { range: formatRanges(blocks) })
      : ui.t('zk.conclusionShadow', { range: formatRanges(noProof) }));
    if (blocks.length === 0 && wireState !== 'pass') {
      ui.println(ui.t(`zk.conclusionWire.${wireState}`, { range: formatRanges(blocks) }));
    }
  }
  ui.println(SEP);
  // 🔴 F1-4: pin 不一致は③の同意確認・処理の後に終了コードへ反映する。
  return wireVkeyExitCode(wireResults, { pinMismatch, verifierMismatch, scanIncomplete: isPending ? false : scanIncomplete });
}

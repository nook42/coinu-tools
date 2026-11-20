// src/recovery/submit.js — Evidence 直接提出（current compact only）

import { EVIDENCE_ABI } from '../common/chain.js';
import {
  compactPayloadToBytes,
  decodeSubmissionPayloadString,
  isEvidenceCompactPayload,
} from '../../vendor/workers/game_workers/lib/evidence-compact-v1.js';
import { canonicalizeSignature } from '../../vendor/workers/game_workers/lib/protocol-v2.js';
import { decodeEventLog, encodeFunctionData, publicActions, recoverMessageAddress, sha256, stringToBytes } from 'viem';
import { verifyRosterCommitmentProof } from '../../vendor/workers/game_workers/lib/roster-member-root.js';
import {
  EVIDENCE_MAX_DATA_BYTES,
  attributeResidualBytes,
  measureOnChainBytes,
  measureRawBytes,
  planOnChainTrim as planOnChainTrimBase,
  encodeSignedTrimmedPayload,
  trimmedSubmissionSignatureMessage,
} from '../../vendor/workers/game_workers/lib/evidence-trim.js';

export {
  EVIDENCE_MAX_DATA_BYTES,
  attributeResidualBytes,
  measureOnChainBytes,
  measureRawBytes,
};

const MIN_DATA_BYTES = 256;
const proofKey = (blockNum, uid) => `evidence_roster_proof_${Number(blockNum)}_user${String(uid)}`;
const payloadKey = (blockNum, uid) => `evidence_result_${Number(blockNum)}_user${String(uid)}`;
const volatileProofs = new Map();
const volatilePayloads = new Map();
const volatilePayloadSavedAt = new Map();
const volatilePayloadWindow = new Map();
const persistentProofs = new Set();
const persistentPayloads = new Set();
const isAddress = (value) => typeof value === 'string' && /^0x[0-9a-f]{40}$/i.test(value);
const isHash = (value) => typeof value === 'string' && /^0x[0-9a-f]{64}$/i.test(value);

export function validRecoveryRosterProof(record) {
  return Number.isSafeInteger(record?.blockNum) && record.blockNum >= 0
    && Number.isSafeInteger(record?.groupId) && record.groupId >= 0
    && typeof record?.uid === 'string' && record.uid.length > 0
    && Number.isSafeInteger(record?.chainId) && record.chainId > 0
    && isAddress(record?.evidenceAddress) && isAddress(record?.walletAddress)
    && isHash(record?.manifestHash) && isHash(record?.C)
    && Array.isArray(record?.proof) && record.proof.length <= 12 && record.proof.every(isHash)
    && Number.isSafeInteger(record?.sharedWalletUids) && record.sharedWalletUids > 0
    && verifyRosterCommitmentProof({ blockNum: record.blockNum,
      address: record.walletAddress, manifestHash: record.manifestHash, C: record.C, proof: record.proof });
}

export function saveRecoveryRosterProof(record, storage = null) {
  if (!validRecoveryRosterProof(record)) return false;
  const key = proofKey(record.blockNum, record.uid);
  volatileProofs.set(key, record);
  try {
    const target = storage || localStorage;
    target.setItem(key, JSON.stringify(record));
    if (target.getItem(key) === JSON.stringify(record)) persistentProofs.add(key);
    else persistentProofs.delete(key);
  } catch { persistentProofs.delete(key); }
  return true;
}

export const isRecoveryRosterProofPersistent = (blockNum, uid) =>
  persistentProofs.has(proofKey(blockNum, uid));

const savedAtRecord = (raw) => {
  try { const parsed = JSON.parse(raw); return typeof parsed === 'object' && parsed !== null ? parsed : { at: Number(raw) }; }
  catch { return { at: Number(raw) }; }
};

export function saveRecoveryEvidencePayload(blockNum, uid, payload, storage = null, chatWindow = null) {
  const key = payloadKey(blockNum, uid);
  volatilePayloads.set(key, payload);
  volatilePayloadSavedAt.set(key, Date.now());
  volatilePayloadWindow.set(key, chatWindow);
  try {
    const target = storage || localStorage;
    target.setItem(key, payload);
    target.setItem(`${key}_savedAt`, chatWindow ? JSON.stringify({
      at: volatilePayloadSavedAt.get(key), chatWindow, sha256: sha256(stringToBytes(payload)),
    }) : String(volatilePayloadSavedAt.get(key)));
    persistentPayloads.add(key);
  }
  catch {
    persistentPayloads.delete(key);
    try {
      const target = storage || localStorage;
      target.removeItem(key);
      target.removeItem(`${key}_savedAt`);
    } catch { /* volatile copy remains available until reload */ }
  }
  return true;
}

export const isRecoveryEvidencePayloadPersistent = (blockNum, uid) =>
  persistentPayloads.has(payloadKey(blockNum, uid));

export function loadRecoveryEvidencePayload(blockNum, uid, storage = null) {
  const key = payloadKey(blockNum, uid);
  try {
    const target = storage || localStorage;
    const stored = target.getItem(key);
    const storedAt = Number(savedAtRecord(target.getItem(`${key}_savedAt`)).at || 0);
    if (stored && storedAt >= (volatilePayloadSavedAt.get(key) || 0)) return stored;
    return volatilePayloads.get(key) || stored || null;
  }
  catch { return volatilePayloads.get(key) || null; }
}

export function loadRecoveryEvidencePayloadWindow(blockNum, uid, payload, storage = null) {
  const key = payloadKey(blockNum, uid);
  if (typeof payload !== 'string') return null;
  try {
    const record = savedAtRecord((storage || localStorage).getItem(`${key}_savedAt`));
    if (record.sha256 === sha256(stringToBytes(payload))) return record.chatWindow ?? null;
  } catch { /* volatile copy below */ }
  return volatilePayloads.get(key) === payload ? volatilePayloadWindow.get(key) ?? null : null;
}

export function loadRecoveryRosterProof(blockNum, uid, storage = null) {
  try {
    const key = proofKey(blockNum, uid);
    const record = volatileProofs.get(key) || JSON.parse((storage || localStorage).getItem(key) || 'null');
    return record?.blockNum === Number(blockNum) && record?.uid === String(uid)
      && validRecoveryRosterProof(record) ? record : null;
  } catch { return volatileProofs.get(proofKey(blockNum, uid)) || null; }
}

// 端末に既に残る proof と提出バンドルだけから、R2 を使わず救済できる本人を列挙する。
export function findSavedRecoveryProofs(blockNum, walletAddress, evidenceAddress, storage = null) {
  if (!Number.isSafeInteger(Number(blockNum)) || Number(blockNum) < 0
      || !isAddress(walletAddress) || !isAddress(evidenceAddress)) return [];
  try {
    const prefix = `evidence_roster_proof_${Number(blockNum)}_user`;
    const found = [];
    const candidateKeys = new Set([...volatileProofs.keys()]);
    let target = storage;
    try { target ||= localStorage; } catch { /* memory copy only */ }
    try { for (let i = 0; i < (target?.length || 0); i++) candidateKeys.add(target.key(i)); }
    catch { /* storage enumeration unavailable; use in-memory proofs */ }
    for (const key of candidateKeys) {
      if (typeof key !== 'string' || !key.startsWith(prefix)) continue;
      const uid = key.slice(prefix.length);
      const proof = loadRecoveryRosterProof(blockNum, uid, target);
      if (!proof || proof.walletAddress.toLowerCase() !== walletAddress.toLowerCase()
          || proof.evidenceAddress.toLowerCase() !== evidenceAddress.toLowerCase()
          || typeof loadRecoveryEvidencePayload(blockNum, uid, target) !== 'string') continue;
      found.push(proof);
    }
    return found.sort((a, b) => a.uid.localeCompare(b.uid));
  } catch { return []; }
}

const submissionSignatureMessage = (bundle, blockNum) => JSON.stringify({
  blockNum: Number(blockNum), uid: bundle.uid, encryptKey: bundle.encryptKey,
  chatHash: bundle.chatHash, submittedAt: bundle.submittedAt,
  encryptedDataHash: bundle.encryptedDataHash, depositIds: bundle.depositIds,
});

export function bytesToHex(bytes) {
  let hex = '0x';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex;
}

// 容量計測・A〜H分類・トリムはWeb本体と同じvendor共有実装だけを使う。

const originalTrimHashByBundle = new WeakMap();

export async function planOnChainTrim(payload, myUid, options = {}) {
  const plan = await planOnChainTrimBase(payload, myUid, options);
  if (!plan?.trimmedBundle) return plan;
  const originalEncryptedDataHash = decodeSubmissionPayloadString(payload).bundle.encryptedDataHash;
  originalTrimHashByBundle.set(plan.trimmedBundle, originalEncryptedDataHash);
  return { ...plan, originalEncryptedDataHash };
}

export function describeTrimPlan(plan) {
  return [
    `  H 無効・不鮮度 / invalid or stale: ${plan?.droppedH || 0}`,
    `  G 完全冗長 / redundant: ${plan?.droppedG || 0}`,
    `  F 他者の補助 / other-player auxiliary: ${plan?.droppedF || 0}`,
    `  E 自分の余剰 / own extra coverage: ${plan?.droppedE || 0}`,
    `  C 密告の標的の先頭の発言（旧規則の名残） / reported players' first messages (legacy rule): ${plan?.droppedC || 0}`,
    `  D 2倍安全余裕 / safety margin: ${plan?.droppedD || 0}`,
    `  R 自分の密告と根拠の投票の受領証明 / own reports and their grounding votes: ${plan?.droppedR || 0}`,
    `  A 自己集約 / self aggregate: ${plan?.droppedA || 0}`,
    `  B 自分の資格の根拠（会話数・500字） / own eligibility (turns, 500 chars): ${plan?.droppedB || 0}`,
    `  V 自分の投票 / own vote: ${plan?.droppedV || 0}`,
    ...(plan?.droppedEPrimeFree > 0
      ? [`  最優先欄の無損失分 / priority receipts removed without lost coverage: ${plan.droppedEPrimeFree}`]
      : []),
  ].join('\n');
}

export async function signTrimmedPayload(b, {
  blockNum,
  signMessage,
  compactContext,
  originalEncryptedDataHash = null,
}) {
  if (!compactContext) throw new Error('compact context is required for production submission');
  const originalHash = originalEncryptedDataHash || originalTrimHashByBundle.get(b);
  if (typeof originalHash !== 'string' || !originalHash) {
    throw new Error('original encryptedDataHash is required for trimmed payload signing');
  }
  const originalSigner = await recoverMessageAddress({
    message: trimmedSubmissionSignatureMessage(b, blockNum, originalHash),
    signature: b.signature,
  });
  const dataString = trimmedSubmissionSignatureMessage(b, blockNum);
  const signature = canonicalizeSignature(await signMessage(dataString));
  const nextSigner = await recoverMessageAddress({ message: dataString, signature });
  if (originalSigner.toLowerCase() !== nextSigner.toLowerCase()) {
    throw new Error('trimmed bundle was signed by a different wallet');
  }
  return encodeSignedTrimmedPayload(b, signature, compactContext);
}

// Evidence.submitResult を送信。walletClient は viem WalletClient（chainId=1 バインド前提）。
// evidenceAddress は config.contracts.evidence（バッチ後の実アドレス）。
export async function submitResultOnChain(walletClient, evidenceAddress, blockNum, payload,
  { storage = localStorage, rebuildProof = null, proofRefreshAttempted = false } = {}) {
  if (!evidenceAddress) throw new Error('Evidence contract address is not configured');
  if (!walletClient) throw new Error('Wallet is not connected');
  if (!isEvidenceCompactPayload(payload)) throw new Error('production Evidence submission must use evidence-compact-v1');
  const chosen = compactPayloadToBytes(payload);
  const data = bytesToHex(chosen);
  const byteLength = chosen.length;
  if (byteLength < MIN_DATA_BYTES) throw new Error(`payload too small (${byteLength}B < ${MIN_DATA_BYTES}B)`);
  if (byteLength >= EVIDENCE_MAX_DATA_BYTES) throw new Error(`payload too large (${byteLength}B >= ${EVIDENCE_MAX_DATA_BYTES}B)`);
  const decoded = decodeSubmissionPayloadString(payload);
  const proof = loadRecoveryRosterProof(blockNum, decoded.bundle?.uid, storage);
  if (!proof || proof.groupId !== decoded.groupId
      || proof.evidenceAddress.toLowerCase() !== evidenceAddress.toLowerCase()) {
    if (!proofRefreshAttempted && typeof rebuildProof === 'function' && await rebuildProof()) {
      return submitResultOnChain(walletClient, evidenceAddress, blockNum, payload,
        { storage, rebuildProof, proofRefreshAttempted: true });
    }
    throw new Error('saved final roster proof is missing or does not match this submission');
  }
  const sender = typeof walletClient.account === 'string' ? walletClient.account : walletClient.account?.address;
  if (typeof walletClient.getAddresses === 'function') {
    const [connected] = await walletClient.getAddresses();
    if (!connected || connected.toLowerCase() !== sender?.toLowerCase()) {
      throw new Error('connected wallet changed before Evidence submission');
    }
  }
  const recovered = await recoverMessageAddress({
    message: submissionSignatureMessage(decoded.bundle, decoded.blockNum), signature: decoded.bundle.signature,
  });
  if (!sender || sender.toLowerCase() !== proof.walletAddress.toLowerCase()
      || recovered.toLowerCase() !== proof.walletAddress.toLowerCase()) {
    throw new Error('connected wallet, saved signer and roster leaf differ');
  }
  const client = walletClient.extend(publicActions);
  if (Number(await client.getChainId()) !== proof.chainId) throw new Error('Evidence chain changed');
  const n = BigInt(blockNum);
  const [count, hashStorage, entryEnd, grace] = await Promise.all([
    client.readContract({ address: evidenceAddress, abi: EVIDENCE_ABI,
      functionName: 'resultCountOf', args: [n, sender] }),
    client.readContract({ address: evidenceAddress, abi: EVIDENCE_ABI, functionName: 'HASH_STORAGE' }),
    client.readContract({ address: evidenceAddress, abi: EVIDENCE_ABI,
      functionName: 'scheduledGameStart', args: [n] }),
    client.readContract({ address: evidenceAddress, abi: EVIDENCE_ABI,
      functionName: 'currentGrace', args: [n] }),
  ]);
  if (BigInt(count) >= 3n) throw new Error('Evidence sender has used all 3 submissions');
  const rosterWindowAbi = [{ name: 'rosterLastIn', type: 'function', stateMutability: 'view',
    inputs: [{ type: 'uint256' }, { type: 'uint256' }, { type: 'uint256' }],
    outputs: [{ type: 'bool' }, { type: 'bytes32' }] }];
  const [found, currentC] = await client.readContract({ address: hashStorage, abi: rosterWindowAbi,
    functionName: 'rosterLastIn', args: [n, entryEnd, entryEnd + grace] });
  if (!found || String(currentC).toLowerCase() !== proof.C.toLowerCase()) {
    if (found && !proofRefreshAttempted && typeof rebuildProof === 'function' && await rebuildProof()) {
      return submitResultOnChain(walletClient, evidenceAddress, blockNum, payload,
        { storage, rebuildProof, proofRefreshAttempted: true });
    }
    throw new Error('canonical roster commitment changed');
  }
  const hash = await walletClient.writeContract({
    address: evidenceAddress,
    abi: EVIDENCE_ABI,
    functionName: 'submitResult',
    args: [n, data, proof.manifestHash, proof.proof],
    account: walletClient.account,
  });
  const expectedCalldata = encodeFunctionData({ abi: EVIDENCE_ABI, functionName: 'submitResult',
    args: [n, data, proof.manifestHash, proof.proof] });
  let replacement = null;
  let replacementReason = null;
  const receipt = await client.waitForTransactionReceipt({ hash, confirmations: 1,
    onReplaced: (event) => { replacement = event.replacement; replacementReason = event.reason; } });
  if (receipt?.transactionHash?.toLowerCase() !== hash.toLowerCase()) {
    if (replacementReason === 'cancelled') throw new Error('Evidence transaction was cancelled');
    const actual = replacement || (typeof client.getTransaction === 'function'
      ? await client.getTransaction({ hash: receipt.transactionHash }) : null);
    if (actual?.to?.toLowerCase() !== evidenceAddress.toLowerCase()
        || actual?.input?.toLowerCase() !== expectedCalldata.toLowerCase()) {
      throw new Error('Evidence transaction was replaced with different calldata');
    }
  }
  if (receipt?.status !== 'success') throw new Error('Evidence transaction failed');
  const events = receipt.logs.flatMap((log) => {
    if (log.address.toLowerCase() !== evidenceAddress.toLowerCase()) return [];
    try { return [decodeEventLog({ abi: EVIDENCE_ABI, data: log.data, topics: log.topics })]; }
    catch { return []; }
  }).filter((event) => event.eventName === 'ResultSubmitted'
    && event.args.blockNum === n && event.args.sender.toLowerCase() === sender.toLowerCase()
    && event.args.seq > 0n && event.args.data === data);
  if (events.length !== 1) throw new Error('Evidence receipt has no matching sequence event');
  return { hash: receipt.transactionHash, data, byteLength, receipt,
    seq: events[0].args.seq.toString(), resultCountOf: Number(count) + 1 };
}

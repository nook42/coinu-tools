import fs from 'node:fs';
import { encodePacked, keccak256, parseAbiItem } from 'viem';
import { ArchiveUnavailableError } from './archive.js';

const ZERO_ADDRESS = `0x${'00'.repeat(20)}`;
const ZERO_HASH = `0x${'00'.repeat(32)}`;
const TM_ABI = [
  ...['evidence', 'anchorProvider', 'pendingAnchorProvider'].map((name) => ({
    type: 'function', name, stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }],
  })),
  { type: 'function', name: 'pendingVkeyEta', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
];
const EVIDENCE_ABI = [{ type: 'function', name: 'GAME_PERIOD', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] }];
const PROVIDER_ABI = [
  { type: 'function', name: 'evidence', stateMutability: 'view', inputs: [], outputs: [{ type: 'address' }] },
  { type: 'function', name: 'anchorsHash', stateMutability: 'view', inputs: [{ type: 'uint256' }], outputs: [{ type: 'bytes32' }] },
];
const APPLIED = parseAbiItem('event VerifierAndVkeyApplied(uint256 indexed epochIndex, address indexed verifier, bytes32 indexed vkey)');
const CANCELLED = parseAbiItem('event VerifierAndVkeyCancelled(address indexed verifier, bytes32 indexed vkey)');
const PROPOSED = parseAbiItem('event VerifierAndVkeyProposed(address indexed verifier, bytes32 indexed vkey, uint256 eta)');

export function futureAnchorsHash(blockNum, gamePeriod) {
  return keccak256(encodePacked(
    ['uint64', 'string', 'uint64', 'uint32', 'uint64', 'uint256', 'uint64', 'uint256'],
    [29n, 'BitcoinU.Stage5.FutureAnchors', 4n, 1, 32n, BigInt(blockNum), 32n, BigInt(gamePeriod)],
  ));
}

export function compareFutureAnchorRuntime(actual, canonical, evidence) {
  if (!canonical?.object || !Array.isArray(canonical.immutableReferences)) {
    return { ok: false, reason: 'canonical_runtime_missing' };
  }
  const expected = canonical.object.toLowerCase().replace(/^0x/, '');
  const code = String(actual || '').toLowerCase().replace(/^0x/, '');
  if (code.length !== expected.length || !/^[0-9a-f]+$/.test(code)) {
    return { ok: false, reason: 'runtime_length_or_encoding' };
  }
  if (canonical.immutableReferences.length !== 2) return { ok: false, reason: 'immutable_reference_count' };
  const embedded = `0`.repeat(24) + String(evidence).toLowerCase().replace(/^0x/, '');
  let maskedActual = code;
  let maskedExpected = expected;
  for (const { start, length } of canonical.immutableReferences) {
    if (!Number.isSafeInteger(start) || length !== 32 || start < 0 || (start + length) * 2 > code.length) {
      return { ok: false, reason: 'invalid_immutable_reference' };
    }
    if (code.slice(start * 2, (start + length) * 2) !== embedded) {
      return { ok: false, reason: 'evidence_immutable_mismatch' };
    }
    maskedActual = `${maskedActual.slice(0, start * 2)}${'0'.repeat(length * 2)}${maskedActual.slice((start + length) * 2)}`;
    maskedExpected = `${maskedExpected.slice(0, start * 2)}${'0'.repeat(length * 2)}${maskedExpected.slice((start + length) * 2)}`;
  }
  return { ok: maskedActual === maskedExpected, reason: maskedActual === maskedExpected ? 'canonical_runtime' : 'runtime_code_mismatch' };
}

export function loadCanonicalFutureAnchorRuntime() {
  try { return JSON.parse(fs.readFileSync(new URL('./future-anchor-runtime.json', import.meta.url), 'utf8')); }
  catch { return null; }
}

async function read(client, address, abi, functionName, args = [], blockNumber = undefined) {
  return client.readContract({ address, abi, functionName, args,
    ...(blockNumber == null ? {} : { blockNumber }) });
}

async function providerState(client, tokenMining, blockNumber) {
  const [current, pending, eta] = await Promise.all([
    read(client, tokenMining, TM_ABI, 'anchorProvider', [], blockNumber),
    read(client, tokenMining, TM_ABI, 'pendingAnchorProvider', [], blockNumber),
    read(client, tokenMining, TM_ABI, 'pendingVkeyEta', [], blockNumber),
  ]);
  return { current, pending, eta: BigInt(eta) };
}

export async function providerAtProof(chain, event) {
  const height = BigInt(event.evtBlock ?? event.blockNumber);
  const proofIndex = Number(event.logIndex);
  if (!Number.isSafeInteger(proofIndex) || proofIndex < 0) throw new Error('invalid proof logIndex');
  const tm = chain.contracts.tokenMining;
  const block = await chain.client.getBlock({ blockNumber: height });
  const logs = (await Promise.all([APPLIED, CANCELLED, PROPOSED].map((abi) => chain.getLogsChunked({
    address: tm, event: abi, fromBlock: height, toBlock: height,
  })))).flat().sort((a, b) => Number(a.logIndex) - Number(b.logIndex));
  // A shadow-period proposal writes anchorProvider directly and emits Applied
  // without Proposed. A later Proposed in this block cannot explain that
  // earlier Applied. The event has no provider address, so replay is unsafe.
  let proposals = 0;
  for (const log of logs) {
    if (log.eventName === 'VerifierAndVkeyProposed') proposals++;
    if (log.eventName === 'VerifierAndVkeyApplied' && proposals-- <= 0) {
      throw new Error('Applied without preceding same-block Proposed: provider history unavailable');
    }
  }
  // State at a block is end-of-block. If later changes exist, replay only the
  // changes before this proof from the previous block's state.
  const laterChange = logs.some((log) => Number(log.logIndex) > proofIndex);
  if (laterChange && height === 0n) throw new Error('cannot reconstruct block zero provider before proof');
  let state = laterChange
    ? await providerState(chain.client, tm, height - 1n)
    : await providerState(chain.client, tm, height);
  if (laterChange) {
    for (const log of logs.filter((item) => Number(item.logIndex) < proofIndex)) {
      if (log.eventName === 'VerifierAndVkeyApplied') {
        state = { current: state.pending, pending: ZERO_ADDRESS, eta: 0n };
      } else if (log.eventName === 'VerifierAndVkeyCancelled') {
        state = { ...state, pending: ZERO_ADDRESS, eta: 0n };
      }
    }
  }
  const due = state.eta !== 0n && BigInt(block.timestamp) >= state.eta;
  return { address: due ? state.pending : state.current, source: due ? 'pending' : 'current',
    pendingDue: due, eta: state.eta.toString() };
}

export async function checkProofFutureAnchor(chain, blockNum, event, claimed) {
  const tm = chain.contracts.tokenMining;
  const evidence = await read(chain.client, tm, TM_ABI, 'evidence');
  const period = await read(chain.client, evidence, EVIDENCE_ABI, 'GAME_PERIOD');
  let provider;
  try { provider = await providerAtProof(chain, event); }
  catch (error) {
    if (error instanceof ArchiveUnavailableError) {
      // 配線が不明でも、許される値は未配線の0かEvidenceからの式だけ。
      const expected = futureAnchorsHash(blockNum, period);
      if (![ZERO_HASH, expected.toLowerCase()].includes(String(claimed).toLowerCase())) {
        return { status: 'fail', reason: 'provider_unavailable', provider: 'unavailable', expected, claimed,
          gamePeriod: String(period), evidence };
      }
      return { status: 'skip', reason: 'archive_unavailable', provider: 'unavailable', unavailableError: error };
    }
    provider = { address: 'unavailable', source: 'unavailable', error: String(error.message || error) }; }
  const unknown = provider.source === 'unavailable';
  const unconnected = String(provider.address).toLowerCase() === ZERO_ADDRESS;
  const expected = unconnected ? ZERO_HASH : futureAnchorsHash(blockNum, period);
  const claimedLower = String(claimed).toLowerCase();
  const status = unknown && claimedLower === ZERO_HASH ? 'skip'
    : claimedLower === expected.toLowerCase() ? 'pass' : 'fail';
  return { status, ...(status === 'skip' ? { reason: 'provider_unavailable' } : {}),
    provider: unconnected ? 'none' : provider.address, source: provider.source,
    expected, claimed, gamePeriod: String(period), evidence,
    ...(provider.error ? { providerReadError: provider.error } : {}) };
}

export async function auditFutureAnchorProviders(chain, canonical = loadCanonicalFutureAnchorRuntime()) {
  const client = chain.client;
  const tm = chain.contracts.tokenMining;
  const blockNum = await client.getBlockNumber();
  const evidence = await read(client, tm, TM_ABI, 'evidence', [], blockNum);
  const period = await read(client, evidence, EVIDENCE_ABI, 'GAME_PERIOD', [], blockNum);
  const state = await providerState(client, tm, blockNum);
  const auditOne = async (address, role) => {
    if (String(address).toLowerCase() === ZERO_ADDRESS) return { status: 'unwired', role, address };
    try {
      const [reportedEvidence, code, actualHash] = await Promise.all([
        read(client, address, PROVIDER_ABI, 'evidence', [], blockNum),
        client.getCode({ address, blockNumber: blockNum }),
        read(client, address, PROVIDER_ABI, 'anchorsHash', [blockNum], blockNum),
      ]);
      const runtime = compareFutureAnchorRuntime(code, canonical, evidence);
      const hash = futureAnchorsHash(blockNum, period);
      return { status: String(reportedEvidence).toLowerCase() === String(evidence).toLowerCase()
          && runtime.ok && String(actualHash).toLowerCase() === hash.toLowerCase() ? 'pass' : 'fail',
        role, address, evidence: reportedEvidence, expectedEvidence: evidence, runtime,
        blockNum: String(blockNum), anchorsHash: actualHash, expectedHash: hash };
    } catch (error) { return { status: 'fail', role, address, error: String(error.message || error) }; }
  };
  return { current: await auditOne(state.current, 'current'),
    pending: state.eta !== 0n ? await auditOne(state.pending, 'pending') : null };
}

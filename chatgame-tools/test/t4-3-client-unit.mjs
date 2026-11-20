import assert from 'node:assert/strict';
import { EVIDENCE_ABI, saveEvidenceRosterProof, loadEvidenceRosterProof, isEvidenceRosterProofPersistent,
  saveEvidencePayload, loadEvidencePayload, submitResultOnChain } from '../../src/utils/evidence.js';
import { EVIDENCE_ABI as RECOVERY_ABI } from '../src/common/chain.js';
import { buildRosterMemberCommitment, createRosterMemberProof } from '../../workers/game_workers/lib/roster-member-root.js';
import { decodeFunctionData, encodeAbiParameters, encodeEventTopics, encodeFunctionData,
  encodeFunctionResult, stringToHex } from 'viem';
import { buildScenario } from './scenario.mjs';
import { chainReadVoterUrls } from '../../src/utils/rpcClient.js';

const blockNum = 5;
const uid = 'player-1';
const address = '0x1111111111111111111111111111111111111111';
const evidenceAddress = '0x2222222222222222222222222222222222222222';
const manifestText = JSON.stringify({ blockNum, groups: [{ groupId: 0, sha256: '0'.repeat(64) }] });
const groupText = JSON.stringify({ blockNum, groupId: 0, members: [{ uid, walletAddress: address }] });
const { sha256 } = await import('viem');
const actualManifestText = manifestText.replace('0'.repeat(64), sha256(`0x${Buffer.from(groupText).toString('hex')}`).slice(2));
const commitment = buildRosterMemberCommitment({ blockNum, manifestText: actualManifestText, groupTexts: { 0: groupText } });
const record = {
  blockNum, groupId: 0, uid, chainId: 1, evidenceAddress, walletAddress: address,
  manifestHash: commitment.manifestHash, C: commitment.C,
  proof: createRosterMemberProof(commitment, address), sharedWalletUids: 1,
};
const data = new Map();
const storage = { setItem: (k, v) => data.set(k, v), getItem: (k) => data.get(k) || null };
assert.equal(EVIDENCE_ABI.find((e) => e.name === 'submitResult').inputs.length, 4);
assert.equal(RECOVERY_ABI.find((e) => e.name === 'submitResult').inputs.length, 4);
assert.equal(saveEvidenceRosterProof(record, { storage }), true);
assert.deepEqual(loadEvidenceRosterProof(blockNum, uid, { storage }), record);
assert.equal(saveEvidenceRosterProof(record, { storage: { setItem: () => { throw new Error('quota'); } } }), true);
assert.equal(isEvidenceRosterProofPersistent(blockNum, uid), false);
assert.deepEqual(loadEvidenceRosterProof(blockNum, uid, { storage: { getItem: () => { throw new Error('quota'); } } }), record);
const scenario = await buildScenario({ blockNum });
const player = scenario.players[1];
const gameGroupText = JSON.stringify({ blockNum, groupId: 0,
  members: scenario.players.map((p) => ({ uid: p.uid, walletAddress: p.addr })) });
const gameManifestText = JSON.stringify({ blockNum, groups: [{ groupId: 0,
  sha256: sha256(stringToHex(gameGroupText)).slice(2) }] });
const gameCommitment = buildRosterMemberCommitment({ blockNum, manifestText: gameManifestText,
  groupTexts: { 0: gameGroupText } });
const gameRecord = { ...record, uid: player.uid, chainId: 31337, walletAddress: player.addr,
  manifestHash: gameCommitment.manifestHash, C: gameCommitment.C,
  proof: createRosterMemberProof(gameCommitment, player.addr) };
globalThis.localStorage = storage;
saveEvidencePayload(blockNum, uid, 'old-payload');
data.set(`evidence_result_${blockNum}_user${uid}`, 'new-payload');
data.set(`evidence_result_${blockNum}_user${uid}_savedAt`, String(Date.now() + 1000));
assert.equal(loadEvidencePayload(blockNum, uid), 'new-payload', '別タブの新しい保存物を読む');
process.env.NEXT_PUBLIC_EVIDENCE_CONTRACT_ADDRESS = evidenceAddress;
assert.equal(saveEvidenceRosterProof(gameRecord), true);
let writes = 0;
let senderCount = 0n;
let chainC = gameCommitment.C;
let receiptStatus = 'success';
let txData;
const txHash = `0x${'44'.repeat(32)}`;
let receiptHash = txHash;
let replacementMode = null;
let writtenArgs = null;
let walletReadContracts = 0;
const publicClient = {
  getChainId: async () => 31337,
  getTransaction: async () => ({ nonce: 1, input: '0x' }),
  getBlockNumber: async () => 9n,
  readContract: async ({ functionName }) => {
    walletReadContracts++;
    if (functionName === 'resultCountOf') return senderCount;
    if (functionName === 'HASH_STORAGE') return '0x3333333333333333333333333333333333333333';
    if (functionName === 'scheduledGameStart') return 100n;
    if (functionName === 'currentGrace') return 10n;
    if (functionName === 'rosterLastIn') return [true, chainC];
    throw new Error(`unknown ${functionName}`);
  },
  waitForTransactionReceipt: async ({ onReplaced }) => {
    if (replacementMode) onReplaced({ reason: replacementMode,
      replacement: { to: replacementMode === 'cancelled' ? player.addr : evidenceAddress,
        input: replacementMode === 'repriced'
          ? encodeFunctionData({ abi: EVIDENCE_ABI, functionName: 'submitResult', args: writtenArgs })
          : '0xdeadbeef' } });
    return { status: receiptStatus, transactionHash: receiptHash, logs: [{
    address: evidenceAddress,
    topics: encodeEventTopics({ abi: EVIDENCE_ABI, eventName: 'ResultSubmitted',
      args: { blockNum: BigInt(blockNum), seq: 1n, sender: player.addr } }),
    data: encodeAbiParameters([{ type: 'bytes' }, { type: 'uint256' }], [txData, 120n]),
  }] };
  },
};
const walletClient = { account: player.wallet, extend: () => publicClient,
  writeContract: async ({ args }) => { writes++;
    assert.equal(args.length, 4);
    assert.equal(args[2], gameCommitment.manifestHash);
    assert.deepEqual(args[3], gameRecord.proof);
    txData = args[1]; writtenArgs = args; return txHash;
  } };
const payload = scenario.p2Recovery.payload;
let rpcCalls = 0;
const rpcUrls = new Set(chainReadVoterUrls());
globalThis.fetch = async (url, init) => {
  if (!rpcUrls.has(String(url))) throw new Error(`unexpected URL ${url}`);
  const request = JSON.parse(init.body);
  const answer = (item) => {
    if (item.method === 'eth_chainId') return { jsonrpc: '2.0', id: item.id, result: '0x1' };
    if (item.method !== 'eth_call') return { jsonrpc: '2.0', id: item.id,
      error: { code: -32000, message: 'unavailable' } };
    rpcCalls++;
    const abi = item.params[0].to.toLowerCase() === evidenceAddress.toLowerCase()
      ? EVIDENCE_ABI : [{ name: 'rosterLastIn', type: 'function', stateMutability: 'view',
        inputs: [{ type: 'uint256' }, { type: 'uint256' }, { type: 'uint256' }],
        outputs: [{ type: 'bool' }, { type: 'bytes32' }] }];
    const { functionName } = decodeFunctionData({ abi, data: item.params[0].data });
    const value = functionName === 'resultCountOf' ? senderCount
      : functionName === 'HASH_STORAGE' ? '0x3333333333333333333333333333333333333333'
        : functionName === 'scheduledGameStart' ? 100n
          : functionName === 'currentGrace' ? 10n
            : functionName === 'rosterLastIn' ? [true, chainC] : null;
    if (value === null) return { jsonrpc: '2.0', id: item.id,
      error: { code: -32000, message: 'unavailable' } };
    return { jsonrpc: '2.0', id: item.id,
      result: encodeFunctionResult({ abi, functionName, result: value }) };
  };
  const body = Array.isArray(request) ? request.map(answer) : answer(request);
  return new Response(JSON.stringify(body), { status: 200,
    headers: { 'content-type': 'application/json' } });
};
await assert.rejects(submitResultOnChain({ ...walletClient, account: scenario.players[0].wallet },
  blockNum, payload), /differ/);
await assert.rejects(submitResultOnChain({ ...walletClient,
  getAddresses: async () => [scenario.players[0].addr] }, blockNum, payload), /Connected wallet changed/);
senderCount = 3n;
await assert.rejects(submitResultOnChain(walletClient, blockNum, payload), /all 3/);
senderCount = 0n;
chainC = `0x${'99'.repeat(32)}`;
await assert.rejects(submitResultOnChain(walletClient, blockNum, payload), /commitment changed/);
chainC = gameCommitment.C;
receiptStatus = 'reverted';
await assert.rejects(submitResultOnChain(walletClient, blockNum, payload), /transaction failed/);
receiptStatus = 'success';
const result = await submitResultOnChain(walletClient, blockNum, payload);
assert.equal(result.seq, '1');
assert.equal(result.receipt.status, 'success');
receiptHash = `0x${'55'.repeat(32)}`;
replacementMode = 'repriced';
assert.equal((await submitResultOnChain(walletClient, blockNum, payload)).hash, receiptHash);
replacementMode = 'replaced';
await assert.rejects(submitResultOnChain(walletClient, blockNum, payload), /different calldata/);
replacementMode = 'cancelled';
await assert.rejects(submitResultOnChain(walletClient, blockNum, payload), /cancelled/);
assert.equal(writes, 5);
assert.ok(rpcCalls > 0);
assert.equal(walletReadContracts, 0);
console.log('t4-3-client-unit: all checks passed');

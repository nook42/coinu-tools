import assert from 'node:assert/strict';
import { encodeAbiParameters, encodeEventTopics, encodeFunctionData, sha256, stringToHex } from 'viem';
import { buildScenario } from './scenario.mjs';
import { EVIDENCE_ABI } from '../src/common/chain.js';
import { buildRosterMemberCommitment, createRosterMemberProof } from '../vendor/workers/game_workers/lib/roster-member-root.js';
import { saveRecoveryRosterProof, loadRecoveryRosterProof, findSavedRecoveryProofs,
  isRecoveryRosterProofPersistent, saveRecoveryEvidencePayload,
  isRecoveryEvidencePayloadPersistent, loadRecoveryEvidencePayload,
  submitResultOnChain } from '../src/recovery/submit.js';

const blockNum = 5;
const sc = await buildScenario({ blockNum });
const person = sc.players[1];
const groupText = JSON.stringify({ blockNum, groupId: 0,
  members: sc.players.map((player) => ({ uid: player.uid, walletAddress: player.addr })) });
const manifestText = JSON.stringify({ blockNum, groups: [{ groupId: 0,
  sha256: sha256(stringToHex(groupText)).slice(2) }] });
const commitment = buildRosterMemberCommitment({ blockNum, manifestText, groupTexts: { 0: groupText } });
const evidenceAddress = '0x2222222222222222222222222222222222222222';
const hashStorage = '0x3333333333333333333333333333333333333333';
const record = { blockNum, groupId: 0, uid: person.uid, chainId: 31337,
  evidenceAddress, walletAddress: person.addr, manifestHash: commitment.manifestHash,
  C: commitment.C, proof: createRosterMemberProof(commitment, person.addr), sharedWalletUids: 1 };
const map = new Map();
const storage = { setItem: (k, v) => map.set(k, v), getItem: (k) => map.get(k) || null,
  get length() { return map.size; }, key: (i) => [...map.keys()][i] ?? null };
assert.equal(saveRecoveryRosterProof(record, storage), true);
assert.deepEqual(loadRecoveryRosterProof(blockNum, person.uid, storage), record);
storage.setItem(`evidence_result_${blockNum}_user${person.uid}`, sc.p2Recovery.payload);
assert.deepEqual(findSavedRecoveryProofs(blockNum, person.addr, evidenceAddress, storage), [record]);
assert.deepEqual(findSavedRecoveryProofs(blockNum,
  sc.players[0].addr, evidenceAddress, storage), []);
let senderCount = 0n;
let wrote = 0;
const hash = `0x${'44'.repeat(32)}`;
let txData = null;
let receiptHash = hash;
let replacementMode = null;
let writtenArgs = null;
const publicClient = {
  getChainId: async () => 31337,
  readContract: async ({ functionName }) => {
    if (functionName === 'resultCountOf') return senderCount;
    if (functionName === 'HASH_STORAGE') return hashStorage;
    if (functionName === 'scheduledGameStart') return 100n;
    if (functionName === 'currentGrace') return 10n;
    if (functionName === 'rosterLastIn') return [true, commitment.C];
    throw new Error(`unknown ${functionName}`);
  },
  waitForTransactionReceipt: async ({ onReplaced }) => {
    if (replacementMode) onReplaced({ reason: replacementMode,
      replacement: { to: replacementMode === 'cancelled' ? person.addr : evidenceAddress,
        input: replacementMode === 'repriced'
          ? encodeFunctionData({ abi: EVIDENCE_ABI, functionName: 'submitResult', args: writtenArgs })
          : '0xdeadbeef' } });
    return { status: 'success', transactionHash: receiptHash, logs: [{
    address: evidenceAddress,
    topics: encodeEventTopics({ abi: EVIDENCE_ABI, eventName: 'ResultSubmitted',
      args: { blockNum: BigInt(blockNum), seq: 1n, sender: person.addr } }),
    data: encodeAbiParameters([{ type: 'bytes' }, { type: 'uint256' }], [txData, 120n]),
  }] };
  },
};
const walletClient = { account: person.wallet, extend: () => publicClient,
  writeContract: async ({ args }) => { wrote++; txData = args[1]; writtenArgs = args;
    assert.equal(args.length, 4); assert.equal(args[2], commitment.manifestHash);
    assert.deepEqual(args[3], record.proof); return hash; },
};
const ok = await submitResultOnChain(walletClient, evidenceAddress, blockNum, sc.p2Recovery.payload, { storage });
assert.equal(ok.seq, '1');
assert.equal(wrote, 1);
receiptHash = `0x${'55'.repeat(32)}`;
await assert.rejects(submitResultOnChain(walletClient, evidenceAddress, blockNum,
  sc.p2Recovery.payload, { storage }), /was replaced/);
replacementMode = 'repriced';
const repriced = await submitResultOnChain(walletClient, evidenceAddress, blockNum,
  sc.p2Recovery.payload, { storage });
assert.equal(repriced.hash, receiptHash);
assert.equal(repriced.seq, '1');
replacementMode = 'replaced';
await assert.rejects(submitResultOnChain(walletClient, evidenceAddress, blockNum,
  sc.p2Recovery.payload, { storage }), /different calldata/);
replacementMode = 'cancelled';
await assert.rejects(submitResultOnChain(walletClient, evidenceAddress, blockNum,
  sc.p2Recovery.payload, { storage }), /cancelled/);
replacementMode = null;
receiptHash = hash;
await assert.rejects(submitResultOnChain({ ...walletClient,
  account: sc.players[0].wallet }, evidenceAddress, blockNum, sc.p2Recovery.payload, { storage }), /differ/);
await assert.rejects(submitResultOnChain({ ...walletClient,
  getAddresses: async () => [sc.players[0].addr] }, evidenceAddress, blockNum,
  sc.p2Recovery.payload, { storage }), /connected wallet changed/);
assert.equal(wrote, 5);
senderCount = 3n;
await assert.rejects(submitResultOnChain(walletClient, evidenceAddress, blockNum, sc.p2Recovery.payload, { storage }), /all 3/);
assert.equal(wrote, 5);
assert.equal(saveRecoveryRosterProof({ ...record, C: `0x${'99'.repeat(32)}` }, storage), false);
saveRecoveryEvidencePayload(blockNum, person.uid, 'old-payload', storage);
map.set(`evidence_result_${blockNum}_user${person.uid}`, 'new-payload');
map.set(`evidence_result_${blockNum}_user${person.uid}_savedAt`, String(Date.now() + 1000));
assert.equal(loadRecoveryEvidencePayload(blockNum, person.uid, storage), 'new-payload');
const quotaStorage = { setItem() { throw new Error('quota'); }, getItem() { throw new Error('quota'); },
  get length() { return 0; }, key() { return null; } };
assert.equal(saveRecoveryRosterProof(record, quotaStorage), true);
assert.equal(isRecoveryRosterProofPersistent(blockNum, person.uid), false);
assert.equal(saveRecoveryEvidencePayload(blockNum, person.uid, sc.p2Recovery.payload, quotaStorage), true);
assert.equal(isRecoveryEvidencePayloadPersistent(blockNum, person.uid), false);
assert.equal(loadRecoveryEvidencePayload(blockNum, person.uid, quotaStorage), sc.p2Recovery.payload);
assert.deepEqual(findSavedRecoveryProofs(blockNum, person.addr, evidenceAddress, quotaStorage), [record]);
senderCount = 0n;
assert.equal((await submitResultOnChain(walletClient, evidenceAddress, blockNum,
  sc.p2Recovery.payload, { storage: quotaStorage })).seq, '1');
console.log('t4-3-recovery-unit: all checks passed');

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { privateKeyToAccount } from 'viem/accounts';
const { markActionReceiptSource, mayCarryActionReceipt, clientChatSourcedReceipts,
  isActionReceiptDuringChat, mergeActionReceiptSources, receiptArrivalContainment, receiptSignString,
  actionSignStringV2, actionHashV2 } =
  await import(process.env.T3B_PROTOCOL_OVERRIDE || '../../workers/game_workers/lib/protocol-v2.js');
const { parseOfficialStorage } = await import(process.env.T3B_IMPORT_OVERRIDE || '../src/recovery/import-local-storage.js');
import { makeVerifyRelayInner } from '../src/recovery/relay-verify.js';
import { encryptAction } from '../vendor/src/utils/ecies.js';
import { ChatGameDO } from '../../workers/game_workers/chat-game-DO.js';
const u8RelaySource = process.env.U8_RELAY_SOURCE || new URL('../../src/utils/relay.js', import.meta.url);
const { ReceiptAdmissionQueue, receiptTrimVictim, receiptIdentityDigest } = await import(u8RelaySource);
console.log(`U8 relay source sha256=${createHash('sha256').update(readFileSync(u8RelaySource)).digest('hex')}`);
import { RecoveryRelay } from '../src/recovery/relay-client.js';
import { buildScenario } from './scenario.mjs';
import { buildRosterMemberTree, createRosterMemberProof, rosterCommitment } from
  '../vendor/workers/game_workers/lib/roster-member-root.js';
import { saveRecoveryRosterProof, submitResultOnChain } from '../src/recovery/submit.js';

// Evaluate only the cap method in memory, leaving the source and git tree intact.
const fx2dMutation = process.env.FX2D_TEST_MUTATION;
const fx2dCapBody = (source) => {
  const match = /  _enforceIssuerCap\(issuerUid\) \{\n([\s\S]*?)\n  \}\n\n  _drop/.exec(source);
  assert(match, 'FX2D cap method anchor');
  return match[1];
};
const fx2dReplace = (body, from, to) => {
  assert(body.includes(from), `FX2D mutation anchor: ${from}`);
  return body.replace(from, to);
};
const installFx2dMutation = (q) => {
  if (!fx2dMutation) return q;
  assert(['head', 'while', 'cands', 'refresh'].includes(fx2dMutation));
  const source = readFileSync(fx2dMutation === 'head'
    ? process.env.FX2D_TEST_BEFORE_SOURCE
    : new URL('../../src/utils/relay.js', import.meta.url), 'utf8');
  let body = fx2dCapBody(source);
  if (fx2dMutation === 'while') body = fx2dReplace(body,
    'while (settled() > this.maxPerIssuer) {',
    'while (issuerEntries.length > this.maxPerIssuer) {');
  if (fx2dMutation === 'cands') body = fx2dReplace(body,
    'const candidates = issuerEntries.filter((entry) => !entry.checking);',
    'const candidates = issuerEntries;');
  if (fx2dMutation === 'refresh') {
    const before = fx2dCapBody(readFileSync(process.env.FX2D_TEST_BEFORE_SOURCE, 'utf8'));
    const oldRefresh = /    const refresh = \(\) => \{[\s\S]*?\n    \};/.exec(before);
    assert(oldRefresh, 'FX2D original refresh');
    body = fx2dReplace(body, '    const refresh = () => this._refreshActions();', oldRefresh[0]);
  }
  q._enforceIssuerCap = new Function('receiptTrimVictim',
    `return function _enforceIssuerCap(issuerUid) {\n${body}\n};`)(receiptTrimVictim);
  return q;
};

const close = 1_800_000_000_000;
const action = { receiverUid: '1', actionHash: `0x${'ab'.repeat(32)}`, timestamp: close - 10,
  signature: `0x${'11'.repeat(64)}1b` };
const read = { receiverUid: '1', senderUid: '0', msgRefs: [`0x${'cd'.repeat(16)}`],
  timestamp: close + 30, signature: `0x${'22'.repeat(64)}1b` };
const window = { startMs: close - 60_000, endMs: close + 120_000 };
const before = markActionReceiptSource(action, { source: 'device', chatEnded: true,
  chainTimeMs: close - 1, chatCloseAt: close, nowMs: close + 900000 });
const after = markActionReceiptSource(action, { source: 'device', chatEnded: false,
  chainTimeMs: close + 1, chatCloseAt: close, nowMs: close - 1 });
assert(mayCarryActionReceipt(before, close));
assert(!mayCarryActionReceipt(after, close));
assert.equal(isActionReceiptDuringChat(close, close - 1, close + 900000), true);
assert.equal(isActionReceiptDuringChat(close, close + 1, close - 900000), false);
assert.equal(isActionReceiptDuringChat(close, null, close), true);
assert.equal(isActionReceiptDuringChat(close, null, close + 1), false);
assert.equal(isActionReceiptDuringChat(null, null, close + 900000), true);
assert(!mayCarryActionReceipt(markActionReceiptSource(action, { source: 'device',
  chatCloseAt: close, nowMs: close + 120001 }), close));
assert(!mayCarryActionReceipt(markActionReceiptSource({ ...action, _receivedAt: close - 1 }, {
  source: 'do', chatCloseAt: close, chainTimeMs: close + 1, nowMs: close + 1 }), close));
assert(mayCarryActionReceipt(markActionReceiptSource(before, { source: 'storage' }), close));
assert.deepEqual(clientChatSourcedReceipts([before, after, read], window, close), [before, read]);
assert.deepEqual(clientChatSourcedReceipts([before], null), [before]);
assert.equal(mayCarryActionReceipt(mergeActionReceiptSources(after, before), close), true);
assert.equal(receiptArrivalContainment(new Set(['a', 'b']),
  [{ facts: new Set(['a']), receipt: before }], after, close).admit, false);
const accepted = [];
const queue = new ReceiptAdmissionQueue({
  getRosterUids: () => ['0', '1'], verifyReceipt: async () => true,
  resolveReceipt: () => ({ state: 'covered', facts: [`a|1|${action.actionHash}`] }),
  getSelectionContext: () => ({ messages: [], blockNum: 17, groupId: 2, myUid: '0' }),
  onAccept: (receipt) => accepted.push(receipt),
});
const pendingAction = { ...action, timestamp: Date.now() - 1000 };
await queue.offer(markActionReceiptSource(pendingAction, { source: 'device',
  chatCloseAt: close, chainTimeMs: close + 1, nowMs: close + 1 }), { verified: true });
await queue.offer(markActionReceiptSource(pendingAction, { source: 'device',
  chatCloseAt: close, chainTimeMs: close - 2, nowMs: close + 1 }), { verified: true });
assert.equal(queue.getAcceptedReceipts().length, 1);
assert(mayCarryActionReceipt(queue.getAcceptedReceipts()[0], close), 'early chain mark upgrades a duplicate');
assert.equal(accepted.length, 2);
queue.dispose();

// A historical signed receipt must remain importable after the relay freshness window.
const account = privateKeyToAccount(`0x${'37'.repeat(32)}`);
const oldTs = Date.now() - 3_600_000;
const signed = { ...action, timestamp: oldTs,
  signature: await account.signMessage({ message: receiptSignString(17, 2, '1', action.actionHash, oldTs) }),
  _chatSources: ['device'], _deviceSeenAt: oldTs };
const members = [{ uid: '0', bAddr: { address: privateKeyToAccount(`0x${'38'.repeat(32)}`).address } },
  { uid: '1', bAddr: { address: account.address } }];
const liveVerify = makeVerifyRelayInner(() => members, 17, 2);
const storedVerify = makeVerifyRelayInner(() => members, 17, 2);
assert.equal(await liveVerify('receipt', signed), true);
assert.equal(await storedVerify('receipt', signed), true);
assert.equal(await storedVerify('receipt', { ...signed, actionHash: `0x${'ac'.repeat(32)}` }), false);
const firstFutureArrival = Date.now();
let futureClientNow = firstFutureArrival;
const futureReceiptTs = firstFutureArrival + 180_000;
const futureSigned = { ...action, timestamp: futureReceiptTs,
  signature: await account.signMessage({
    message: receiptSignString(17, 2, '1', action.actionHash, futureReceiptTs),
  }) };
const futureRecovery = new RecoveryRelay({ signKey: `0x${'38'.repeat(32)}`,
  blockNum: 17, groupId: 2, uid: '0', members,
  getChatWindow: () => ({ startMs: firstFutureArrival - 60_000,
    endMs: firstFutureArrival + 300_000 }),
  getChatCloseAtMs: () => firstFutureArrival + 300_000,
  getChainTimeMs: async () => null, now: () => futureClientNow });
futureRecovery._verifyInner = liveVerify;
await futureRecovery._ingestReceiptArrivals([futureSigned], { arrivalAtOverride: firstFutureArrival });
assert.equal(futureRecovery.getReceipts().length, 0, 'Q18 recovery discards signed future receipt');
assert.equal(futureRecovery.futureMarks.has('receipt', futureSigned), true);
futureClientNow = firstFutureArrival + 60_000;
await futureRecovery._ingestReceiptArrivals([futureSigned]);
assert.equal(futureRecovery.getReceipts().length, 0, 'Q18 time passing does not accept a marked receipt');
futureRecovery.refetchHistory({ deltaMs: 60_000, nextMs: 60_000 });
await futureRecovery._ingestReceiptArrivals([futureSigned]);
assert.equal(futureRecovery.getReceipts().length, 1, 'Q12A recovery ingests after correction and redelivery');
assert.ok(futureRecovery.getReceipts()[0]._deviceSeenAt >= firstFutureArrival,
  'Q12A redelivery carries the new arrival for U-18');
const identity = '17_group2_user0';
const exportJson = JSON.stringify({
  [`observedReceipts_${identity}`]: JSON.stringify({ [signed.signature]: signed }),
  [`clientReadSelection_v1_${identity}`]: JSON.stringify({ version: 1, signatures: [signed.signature] }),
  'evidence_roster_proof_17_user0': JSON.stringify({ uid: '0', blockNum: 17 }),
  'evidence_result_17_user0': 'saved-payload',
});
const imported = await parseOfficialStorage(exportJson, {
  blockNum: 17, groupId: 2, uid: '0', members, verify: storedVerify,
});
assert.equal(imported.receipts.length, 1);
assert.deepEqual(imported.receipts[0]._chatSources, ['device']);
assert.equal(imported.selectedRead, undefined, 'old selection backup is ignored');
assert.equal(imported.proof.uid, '0');
assert.equal(imported.payload, 'saved-payload');
// 密告の控えは自分の確認済み密告と結び、票と既読をそれぞれ発行者の署名で作り直す。
const owner = privateKeyToAccount(`0x${'38'.repeat(32)}`);
const issuer = privateKeyToAccount(`0x${'39'.repeat(32)}`);
const groundMembers = [...members, { uid: '2', bAddr: { address: issuer.address } }];
const groundVerify = makeVerifyRelayInner(() => groundMembers, 17, 2);
const voteCipher = encryptAction({ targetUid: '0' }, `0x${'37'.repeat(32)}`);
const reportCipher = encryptAction({ targetUid: '1' }, `0x${'38'.repeat(32)}`);
const groundVote = { encrypted: voteCipher, timestamp: oldTs,
  signature: await account.signMessage({ message: actionSignStringV2('vote', 17, 2, '1', voteCipher, oldTs) }) };
const groundReport = { encrypted: reportCipher, timestamp: oldTs + 1_000,
  signature: await owner.signMessage({ message: actionSignStringV2('report', 17, 2, '0', reportCipher, oldTs + 1_000) }) };
const groundHash = actionHashV2('vote', 17, 2, '1', groundVote.encrypted, groundVote.timestamp);
const groundReceipt = { receiverUid: '2', actionHash: groundHash, timestamp: oldTs + 500,
  signature: await issuer.signMessage({ message: receiptSignString(17, 2, '2', groundHash, oldTs + 500) }),
  _deviceSeenAt: oldTs + 600, _chatSources: ['device'] };
const groundPaste = (ground, reports = [groundReport]) => JSON.stringify({
  myReports_17_user0: JSON.stringify(reports),
  myReportGrounds_17_user0: JSON.stringify({ [groundReport.signature]: ground }),
});
const validGround = { targetUid: '1', reportTimestamp: -1, votes: [groundVote],
  receipts: [{ ...groundReceipt, evil: true }] };
const parsedGround = await parseOfficialStorage(groundPaste(validGround), {
  blockNum: 17, groupId: 2, uid: '0', members: groundMembers, verify: groundVerify,
});
assert.equal(parsedGround.reportGrounds[groundReport.signature].reportTimestamp, groundReport.timestamp);
assert.equal(parsedGround.reportGrounds[groundReport.signature].receipts[0].evil, undefined);
for (const bad of [
  { ...validGround, receipts: [{ ...groundReceipt, timestamp: groundReceipt.timestamp + 1 }] },
  { ...validGround, receipts: [{ ...groundReceipt, receiverUid: '0' }] },
  { ...validGround, receipts: [{ ...groundReceipt, receiverUid: '1' }] },
  { ...validGround, receipts: [{ ...groundReceipt, msgRefs: [] }] },
]) {
  const parsed = await parseOfficialStorage(groundPaste(bad), {
    blockNum: 17, groupId: 2, uid: '0', members: groundMembers, verify: groundVerify,
  });
  assert.equal(parsed.reportGrounds[groundReport.signature].receipts.length, 0);
}
assert.deepEqual((await parseOfficialStorage(groundPaste(validGround, []), {
  blockNum: 17, groupId: 2, uid: '0', members: groundMembers, verify: groundVerify,
})).reportGrounds, {});
assert.deepEqual((await parseOfficialStorage(groundPaste({ ...validGround, targetUid: 'outside' }), {
  blockNum: 17, groupId: 2, uid: '0', members: groundMembers, verify: groundVerify,
})).reportGrounds, {});
// A's excess entries cannot consume B's persistence or admission budget.
const threeMembers = [...members, { uid: '2', bAddr: { address: account.address } }];
const excessA = Array.from({ length: 2100 }, (_, index) => ({
  ...action, receiverUid: '0', actionHash: `0x${(index + 1).toString(16).padStart(64, '0')}`,
  signature: `0x${(index + 1).toString(16).padStart(128, '0')}1b`,
}));
const importedCrowd = await parseOfficialStorage(JSON.stringify({
  [`observedReceipts_${identity}`]: JSON.stringify([...excessA, signed]),
}), { blockNum: 17, groupId: 2, uid: '0', members: threeMembers,
  verify: async (_type, receipt) => receipt.receiverUid === '1' });
assert.equal(importedCrowd.receipts.length, 1);
assert.equal(importedCrowd.receipts[0].receiverUid, '1');
const originalStorage = globalThis.localStorage;
let savedArrivals = 0;
globalThis.localStorage = { setItem: () => { savedArrivals++; } };
try {
  const recovery = Object.create(RecoveryRelay.prototype);
  recovery.blockNum = 17; recovery.groupId = 2; recovery.uid = '0';
  recovery.members = threeMembers;
  recovery.messages = [];
  recovery.getMsgKey = () => '';
  recovery.getChatWindow = () => null;
  recovery._receipts = Object.fromEntries([...excessA, signed].map((receipt, index) =>
    [String(index), receipt]));
  recovery.onPersistenceError = () => {};
  await recovery.verifyStoredReceipts();
  assert.equal(Object.values(recovery._receipts).length, 1);
  assert.equal(Object.values(recovery._receipts)[0].receiverUid, '1');
  assert.equal(savedArrivals, 1, 'verified retained receipts replace the forged over-cap storage');
} finally { globalThis.localStorage = originalStorage; }
const forged = JSON.parse(exportJson);
forged[`observedReceipts_${identity}`] = JSON.stringify({ fake: { ...signed, actionHash: `0x${'ac'.repeat(32)}` } });
assert.equal((await parseOfficialStorage(JSON.stringify(forged), {
  blockNum: 17, groupId: 2, uid: '0', members, verify: storedVerify,
})).receipts.length, 0);

// A real DO handler keeps the first receive time, including after an idempotent retry.
const saved = new Map([
  ['phase', 'chatting'], ['meta', { blockNum: 17, groupId: 2 }],
  ['members', members.map((member) => ({ ...member, bAddr: JSON.stringify(member.bAddr) }))],
]);
const doInstance = Object.create(ChatGameDO.prototype);
doInstance.env = {};
doInstance.maxMessages = 100;
doInstance.maxChars = 10000;
doInstance.maxMsgChars = 1000;
doInstance.storage = {
  get: async (key) => saved.get(key), put: async (key, value) => { saved.set(key, value); },
  list: async ({ prefix }) => new Map([...saved].filter(([key]) => key.startsWith(prefix))),
};
const broadcasts = [], errors = [];
doInstance.broadcast = (message) => broadcasts.push(message);
doInstance.sendTo = (_ws, message) => errors.push(message);
doInstance.strikeWs = () => false;
doInstance.strikeIfOverQuota = () => false;
doInstance.reserveReceiptQuota = async () => true;
doInstance.publishLiveSnapshot = async () => {};
await doInstance.handleWsReceipt({}, '1', { receipt: signed });
assert.equal(errors.filter((message) => message.type === 'error').length, 0);
assert.equal(broadcasts.length, 1);
const firstTime = broadcasts[0].receipt._receivedAt;
assert(Number.isSafeInteger(firstTime));
assert.equal((await doInstance.loadReceipts())[0]._receivedAt, firstTime);
await doInstance.handleWsReceipt({}, '1', { receipt: signed });
assert.equal((await doInstance.loadReceipts()).length, 1);
assert.equal((await doInstance.loadReceipts())[0]._receivedAt, firstTime);
assert.equal(broadcasts.length, 1);

// Retry quantity is capped by the same per-issuer bound.
const doSource = readFileSync(process.env.T3B_DO_SOURCE || new URL('../../workers/game_workers/chat-game-DO.js', import.meta.url), 'utf8');
assert(doSource.includes('if (!exists) {'));
assert(doSource.includes('await this.storage.put(rcptKey, { ...rcNorm, _receivedSeq: receiveOrder, _receivedAt: receivedAt })')); 
assert.match(doSource, /receipt: \{ \.\.\.rcNorm, _receivedAt: receivedAt \}/);
const hookSource = readFileSync(process.env.T3B_HOOK_SOURCE || new URL('../../src/hooks/useGameWebSocket.js', import.meta.url), 'utf8');
assert.match(hookSource, /\.slice\(0, MAX_RECEIPTS_PER_ISSUER\)/);
assert.match(hookSource, /ws\.send\(JSON\.stringify\(\{ type: 'receipt', receipt: clean \}\)\)/);
const recoveryAppSource = readFileSync(new URL('../src/recovery/app.js', import.meta.url), 'utf8');
assert.match(recoveryAppSource, /rebuildRecoveryRosterProof\(blockNum, proof\.uid, proof\.walletAddress, pc\)/,
  'Sign & load 前の保存済み救済も接続中のチェーンクライアントで proof を作り直せる');
// 保存済み proof の C が後で選ばれた正典行と違う盤面。本人の公開名簿 proof を
// 作り直せば tx 送信まで進み、別ウォレットの leaf なら送信前に拒否する。
const scenario = await buildScenario({ blockNum: 5, groupId: 0 });
const signerAddress = scenario.players[1].addr;
const evidenceAddress = `0x${'44'.repeat(20)}`;
const proofStore = new Map();
const proofStorage = { getItem: (key) => proofStore.get(key) || null,
  setItem: (key, value) => proofStore.set(key, value) };
const makeProof = (walletAddress, manifestByte) => {
  const tree = buildRosterMemberTree(5, [walletAddress]);
  const manifestHash = `0x${manifestByte.repeat(32)}`;
  return { blockNum: 5, groupId: 0, uid: scenario.players[1].uid, chainId: 31337,
    evidenceAddress, walletAddress, manifestHash,
    C: rosterCommitment(manifestHash, tree.memberRoot),
    proof: createRosterMemberProof(tree, walletAddress), sharedWalletUids: 1 };
};
const staleProof = makeProof(signerAddress, '11');
const freshProof = makeProof(signerAddress, '22');
assert(saveRecoveryRosterProof(staleProof, proofStorage));
let sent = 0;
const readClient = { getChainId: async () => 31337,
  readContract: async ({ functionName }) => {
    if (functionName === 'resultCountOf') return 0n;
    if (functionName === 'HASH_STORAGE') return `0x${'55'.repeat(20)}`;
    if (functionName === 'scheduledGameStart') return 1000n;
    if (functionName === 'currentGrace') return 100n;
    if (functionName === 'rosterLastIn') return [true, freshProof.C];
    throw Error(`unexpected ${functionName}`);
  } };
const wallet = { account: { address: signerAddress }, getAddresses: async () => [signerAddress],
  extend: () => readClient,
  writeContract: async ({ args }) => { sent++; assert.equal(args[2], freshProof.manifestHash);
    throw Error('write reached'); } };
await assert.rejects(submitResultOnChain(wallet, evidenceAddress, 5, scenario.p2Recovery.payload,
  { storage: proofStorage }), /canonical roster commitment changed/);
let rebuilt = 0;
await assert.rejects(submitResultOnChain(wallet, evidenceAddress, 5, scenario.p2Recovery.payload,
  { storage: proofStorage, rebuildProof: async () => {
    rebuilt++; return saveRecoveryRosterProof(freshProof, proofStorage);
  } }), /write reached/);
assert.equal(rebuilt, 1);
assert.equal(sent, 1, '新しい本人 proof でのみ送信に進む');
assert(saveRecoveryRosterProof(staleProof, proofStorage));
const outsiderProof = makeProof(privateKeyToAccount(`0x${'39'.repeat(32)}`).address, '22');
readClient.readContract = async ({ functionName }) => functionName === 'rosterLastIn'
  ? [true, outsiderProof.C] : functionName === 'resultCountOf' ? 0n
    : functionName === 'HASH_STORAGE' ? `0x${'55'.repeat(20)}` : 1000n;
await assert.rejects(submitResultOnChain(wallet, evidenceAddress, 5, scenario.p2Recovery.payload,
  { storage: proofStorage, rebuildProof: async () => saveRecoveryRosterProof(outsiderProof, proofStorage) }),
  /connected wallet, saved signer and roster leaf differ/);
assert.equal(sent, 1, '別ウォレットの proof は送信されない');
// VDG fx2c: the admission winner survives even if a post-close duplicate arrived first.
const capBoard = ({ badFirst = true, backdated = false, oldRule = false } = {}) => {
  const dropped = [];
  const q = new ReceiptAdmissionQueue({ maxPerIssuer: 4, getChatCloseAtMs: () => close,
    onDiscard: (receipt, why) => dropped.push([receipt.signature, why]) });
  if (oldRule) q._enforceIssuerCap = function oldEnforce(issuerUid) {
    let entries = [...this.entries.values()].filter((e) => e.issuerUid === issuerUid);
    while (entries.length > this.maxPerIssuer) {
      const victim = receiptTrimVictim(entries);
      this._drop(victim, 'issuer_cap'); entries = entries.filter((e) => e !== victim);
    }
  };
  const mk = (signature, fact, priority, arrived, timestamp = close - 1000) => {
    const receipt = markActionReceiptSource({ receiverUid: '1', actionHash: fact,
      signature, timestamp }, { source: 'do', chatCloseAt: close,
      chainTimeMs: arrived, nowMs: arrived });
    return { receipt, digest: signature, issuerUid: '1', order: 0,
      facts: new Set([fact]), status: 'eligible', priority, checking: false };
  };
  const good = mk('good', 'x', 'C', close - 1000);
  const bad = mk('bad', 'x', 'C', close + 1000, backdated ? close - 2000 : close - 500);
  const rows = [...(badFirst ? [bad, good] : [good, bad]),
    mk('v1', 'v1', 'V', close - 900), mk('v2', 'v2', 'V', close - 800),
    mk('v3', 'v3', 'V', close - 700)];
  rows.forEach((entry, index) => { entry.order = index + 1; q.entries.set(entry.digest, entry); });
  q._enforceIssuerCap('1');
  const result = { good: q.entries.has('good'), bad: q.entries.has('bad'),
    accepted: [...q.entries.values()].filter((e) => e.status === 'accepted' && e.facts.has('x')).length,
    dropped };
  q.dispose();
  return result;
};
for (const board of [{ badFirst: true }, { badFirst: true, backdated: true }, { badFirst: false }]) {
  const result = capBoard({ ...board, oldRule: process.env.VDG_TEST_OLD_CAP === '1' });
  assert.equal(result.good, true, 'fx2c keeps the pre-close admission winner');
  assert.equal(result.bad, false, 'fx2c discards the post-close duplicate');
  assert.equal(result.accepted, 1);
  assert(result.dropped.every(([, why]) => why === 'issuer_cap'));
}
assert.equal(capBoard({ badFirst: true, oldRule: true }).good, false,
  'the old trim order loses the action receipt');
// The same deadline board through real offer/evaluate, including the verified
// admission and onAccept/onRemove paths used by the official page.
for (const backdated of [false, true]) {
  const acceptedBySignature = new Map();
  const droppedBySignature = new Map();
  const xHash = `0x${'ab'.repeat(32)}`;
  const q = new ReceiptAdmissionQueue({ maxPerIssuer: 3, now: () => close - 1000,
    getRosterUids: () => ['0', 'M'], getChatWindow: () => ({ startMs: close - 600000,
      endMs: close + 120000 }), getChatCloseAtMs: () => close,
    resolveReceipt: (receipt) => ({ state: 'covered', facts: [receipt.actionHash],
      priority: 'C' }),
    onAccept: (receipt) => acceptedBySignature.set(receipt.signature, receipt),
    onRemove: (receipt) => acceptedBySignature.delete(receipt.signature),
    onDiscard: (receipt, reason) => droppedBySignature.set(receipt.signature, reason) });
  const makeReceipt = (index, hash, arrived, timestamp) => markActionReceiptSource({
    receiverUid: 'M', actionHash: hash, timestamp,
    signature: `0x${(index + 1).toString(16).padStart(128, '0')}1b`,
  }, { source: 'do', chatCloseAt: close, chainTimeMs: arrived, nowMs: arrived });
  const bad = makeReceipt(0, xHash, close + 1000, backdated ? close - 3000 : close - 1000);
  const good = makeReceipt(1, xHash, close - 1000, close - 2000);
  const fillers = Array.from({ length: 3 }, (_, index) => makeReceipt(index + 2,
    `0x${(index + 3).toString(16).padStart(64, '0')}`, close - 500 + index, close - 1000));
  for (const receipt of [bad, good, ...fillers]) await q.offer(receipt, { verified: true });
  const onX = q.getAcceptedReceipts().filter((receipt) => receipt.actionHash === xHash);
  assert.deepEqual(onX.map((receipt) => receipt.signature), [good.signature],
    `actual admission keeps the pre-close receipt, backdated=${backdated}, entries=${[...q.entries.values()].map((entry) => [entry.digest, entry.status, entry.reason])}, drops=${[...droppedBySignature]}`);
  assert(mayCarryActionReceipt(onX[0], close));
  assert(clientChatSourcedReceipts(q.getAcceptedReceipts(),
    { startMs: close - 600000, endMs: close + 120000 }, close)
    .some((receipt) => receipt.signature === good.signature),
  'the pre-close receipt remains in the submission-visible set, so x stays confirmed');
  assert.equal(droppedBySignature.get(bad.signature), 'issuer_cap');
  assert(acceptedBySignature.has(good.signature));
  q.dispose();
}

// S1-02/03/04: a burst of duplicates, including a 1,100-receipt batch, cannot expel r.
const burstBoard = (count, oldRule = false) => {
  const drops = [];
  const q = new ReceiptAdmissionQueue({ maxPerIssuer: 700, getChatCloseAtMs: () => close,
    onDiscard: (receipt, why) => drops.push([receipt.signature, why]) });
  if (oldRule) q._enforceIssuerCap = function oldEnforce(issuerUid) {
    let entries = [...this.entries.values()].filter((e) => e.issuerUid === issuerUid);
    while (entries.length > this.maxPerIssuer) {
      const victim = receiptTrimVictim(entries);
      this._drop(victim, 'issuer_cap'); entries = entries.filter((e) => e !== victim);
    }
  };
  const makeEntry = (signature, fact, priority, order, issuerUid = 'M') => ({
    receipt: { receiverUid: issuerUid, actionHash: fact, signature,
      _deviceSeenAt: close - 1000 }, digest: signature, issuerUid, order,
    facts: new Set([fact]), status: 'eligible', priority, checking: false,
  });
  q.entries.set('r', makeEntry('r', 'report-x', 'C', 1));
  for (let i = 0; i < count; i++) {
    const e = makeEntry(`f${i}`, 'vote-x', 'V', i + 2);
    q.entries.set(e.digest, e);
  }
  q.entries.set('other', makeEntry('other', 'other-action', 'C', count + 3, 'OTHER'));
  const t0 = performance.now();
  q._enforceIssuerCap('M');
  const elapsed = performance.now() - t0;
  const result = { keptR: q.entries.has('r'), keptOther: q.entries.has('other'),
    acceptedR: q.entries.get('r')?.status === 'accepted', dropped: drops,
    count: [...q.entries.values()].filter((e) => e.issuerUid === 'M').length, elapsed };
  q.dispose();
  return result;
};
for (const count of [699, 700, 1100]) {
  const r = burstBoard(count);
  assert(r.keptR && r.keptOther && (count === 699 || r.acceptedR),
    `S1-02/03/04: r and another issuer survive ${count}`);
  assert.equal(r.count, 700);
  assert(r.dropped.every(([, why]) => why === 'issuer_cap'));
}
assert.equal(burstBoard(700, true).keptR, false, 'old cap evicts r on the threshold');
// Below the threshold, the new cap path must be byte-for-byte inert for varied issuer mixes.
let randomState = 0x51a7c3;
const nextRandom = () => { randomState ^= randomState << 13; randomState ^= randomState >>> 17;
  randomState ^= randomState << 5; return randomState >>> 0; };
for (let board = 0; board < 40; board++) {
  const q = new ReceiptAdmissionQueue({ maxPerIssuer: 700 });
  const ownCount = 1 + nextRandom() % 700;
  for (let index = 0; index < ownCount + 5; index++) {
    const issuerUid = index < ownCount ? 'M' : 'OTHER';
    const digest = `random-${board}-${index}`;
    q.entries.set(digest, { receipt: { signature: digest, receiverUid: issuerUid,
      actionHash: `x${nextRandom() % 40}` }, digest, issuerUid, order: index + 1,
    status: index % 3 ? 'eligible' : 'accepted', priority: index % 2 ? 'V' : 'C',
    facts: new Set([`f${nextRandom() % 40}`]), checking: index % 7 === 0 });
  }
  const before = [...q.entries.values()].map((entry) => [entry.digest, entry.status]);
  q._enforceIssuerCap('M');
  assert.deepEqual([...q.entries.values()].map((entry) => [entry.digest, entry.status]), before,
    `under-cap board ${board} is unchanged`);
  q.dispose();
}
const oldPerf = burstBoard(1400, true);
const newPerf = burstBoard(1400);
assert(newPerf.keptR && newPerf.count === 700 && newPerf.keptOther);
assert(newPerf.elapsed < Math.max(5000, oldPerf.elapsed * 30),
  `fx2c 1,400 receipts stays bounded: old ${oldPerf.elapsed} ms, new ${newPerf.elapsed} ms`);
console.log(`fx2c 1,400 receipts: old=${oldPerf.elapsed.toFixed(1)}ms new=${newPerf.elapsed.toFixed(1)}ms`);

// S1-05: a pending check does not consume the settled cap; once r resolves,
// its action priority wins and the other still checking entry survives.
{
  const drops = new Map();
  const q = installFx2dMutation(new ReceiptAdmissionQueue({ maxPerIssuer: 1,
    onDiscard: (receipt, why) => drops.set(receipt.signature, why) }));
  const entry = (signature, order, checking) => ({ receipt: { signature }, digest: signature,
    issuerUid: 'M', order, status: 'pending', priority: 'H', facts: new Set([signature]), checking });
  q.entries.set('old', entry('old', 1, false));
  q.entries.set('r', entry('r', 2, true));
  q._enforceIssuerCap('M');
  assert.deepEqual([...q.entries.keys()], ['old', 'r'], 'FX2D S1-05 pending r keeps old');
  q.entries.set('other-checking', entry('other-checking', 3, true));
  q._enforceIssuerCap('M');
  assert.deepEqual([...q.entries.keys()], ['old', 'r', 'other-checking'],
    'FX2D S1-05 both checking entries remain');
  const r = q.entries.get('r');
  r.checking = false; r.status = 'eligible'; r.priority = 'C';
  r.receipt = { signature: 'r', receiverUid: 'M', actionHash: 'x' };
  r.facts = new Set(['M|a:x']);
  q._enforceIssuerCap('M');
  assert.deepEqual([...q.entries.keys()].sort(), ['other-checking', 'r'],
    'FX2D S1-05 resolved r wins while other-checking survives');
  assert.equal(q.entries.get('r').status, 'accepted');
  assert.equal(drops.get('old'), 'issuer_cap');
  q.dispose();
}
// An all-checking issuer returns before trimming. The defensive empty-candidate
// break in the cap method is unreachable with its settled-count condition.
{
  const q = installFx2dMutation(new ReceiptAdmissionQueue({ maxPerIssuer: 1 }));
  for (const signature of ['a', 'b', 'c']) q.entries.set(signature, {
    receipt: { signature }, digest: signature, issuerUid: 'M', order: q.entries.size + 1,
    status: 'pending', priority: 'H', facts: new Set(), checking: true });
  q._enforceIssuerCap('M');
  assert.equal(q.entries.size, 3, 'FX2D all-checking early return keeps every entry');
  q.dispose();
}
// W9-FX2C-01 mirror: accepted C/V receipts remain during a pending H burst.
{
  const q = installFx2dMutation(new ReceiptAdmissionQueue({ maxPerIssuer: 3 }));
  const put = (signature, fact, status, priority, checking) => q.entries.set(signature, {
    receipt: { signature, receiverUid: 'M', actionHash: fact }, digest: signature,
    issuerUid: 'M', order: q.entries.size + 1, status, priority, checking,
    facts: new Set([fact]) });
  put('r', 'x', 'accepted', 'C', false);
  put('vwin', 'vB', 'accepted', 'V', false);
  for (let i = 0; i < 4; i++) put(`pending-${i}`, 'vB', 'pending', 'H', true);
  q._enforceIssuerCap('M');
  assert(q.entries.has('r') && q.entries.has('vwin') && q.entries.size === 6,
    'FX2D mirror keeps accepted receipts and pending checks');
  q.dispose();
}
// Once one item in a large pending burst settles, only settled entries compete.
for (const settleOne of [false, true]) {
  const q = installFx2dMutation(new ReceiptAdmissionQueue({ maxPerIssuer: 700,
    getChatCloseAtMs: () => close }));
  const put = (signature, fact, status, priority, checking) => q.entries.set(signature, {
    receipt: { signature, receiverUid: 'M', actionHash: fact, _deviceSeenAt: close - 1000 },
    digest: signature, issuerUid: 'M', order: q.entries.size + 1, status, priority, checking,
    facts: new Set([checking ? `pending:${fact}` : `M|a:${fact}`]) });
  put('r', 'x', 'accepted', 'C', false);
  put('vwin', 'vB', 'accepted', 'V', false);
  for (let i = 0; i < 698; i++) put(`duplicate-${i}`, 'vB', 'eligible', 'V', false);
  for (let i = 0; i < 1400; i++) put(`checking-${i}`, 'vB', 'pending', 'H', true);
  if (settleOne) {
    const first = q.entries.get('checking-0');
    first.checking = false; first.status = 'eligible'; first.priority = 'V';
    first.facts = new Set(['M|a:vB']);
  }
  const started = performance.now();
  q._enforceIssuerCap('M');
  const elapsed = performance.now() - started;
  console.log(`FX2D burst settleOne=${settleOne} mutation=${fx2dMutation || 'fixed'} `
    + `capMs=${elapsed.toFixed(1)}`);
  assert(q.entries.has('r') && q.entries.has('vwin'),
    `FX2D burst keeps r and vwin after settleOne=${settleOne}`);
  assert.equal([...q.entries.values()].filter((e) => !e.checking).length, 700);
  assert.equal([...q.entries.values()].filter((e) => e.checking).length,
    settleOne ? 1399 : 1400);
  q.dispose();
}
// Real offer/evaluate: g finishes before r. Pending H entries count toward the
// issuer cap, but a still checking r cannot be chosen as a victim.
{
  const now = close - 60_000;
  const waits = new Map(), drops = new Map();
  const hash = (n) => `0x${n.toString(16).padStart(64, '0')}`;
  const sig = (n) => `0x${n.toString(16).padStart(128, '0')}1b`;
  const xHash = hash(999), vHash = hash(998);
  const q = installFx2dMutation(new ReceiptAdmissionQueue({ maxPerIssuer: 3,
    now: () => now, getRosterUids: () => ['M', 'B'],
    getChatWindow: () => ({ startMs: close - 3_600_000, endMs: close + 120_000 }),
    getChatCloseAtMs: () => close,
    verifyReceipt: (rc) => new Promise((resolve) => waits.set(rc.signature, resolve)),
    resolveReceipt: (rc) => rc.actionHash === xHash || rc.actionHash === vHash
      ? { state: 'covered', facts: [`M|a:${rc.actionHash}`],
        priority: rc.actionHash === xHash ? 'C' : 'V' }
      : { state: 'pending' },
    onDiscard: (rc, why) => drops.set(rc.signature, why) }));
  const rc = (n, actionHash) => ({ receiverUid: 'M', actionHash, timestamp: now - 1000,
    signature: sig(n), _chainSeenAt: now - 30_000 });
  for (const n of [1, 2]) await q.offer(rc(n, hash(n)), { verified: true });
  await q.offer(rc(3, vHash), { verified: true });
  const g = rc(4, hash(4)), r = rc(5, xHash);
  const pg = q.offer(g), pr = q.offer(r);
  await new Promise((resolve) => setImmediate(resolve));
  waits.get(g.signature)(true);
  await pg;
  assert([...q.entries.values()].some((e) => e.receipt.signature === r.signature),
    'FX2D real offer keeps r while g settles first');
  waits.get(r.signature)(true);
  await pr;
  assert(q.getAcceptedReceipts().some((e) => e.signature === r.signature),
    'FX2D real offer accepts r after its check finishes');
  assert([...drops.values()].every((why) => why === 'issuer_cap'));
  q.dispose();
}
// Reopen via the real queue: restored r/vwin, pending verification of historical
// duplicates, a verified re-delivery, then FIFO completion of those checks.
{
  const now = close - 60_000;
  const waits = [], drops = new Map();
  const hash = (n) => `0x${n.toString(16).padStart(64, '0')}`;
  const sig = (n) => `0x${n.toString(16).padStart(128, '0')}1b`;
  const xHash = hash(0xa1), vHash = hash(0xb2);
  const q = installFx2dMutation(new ReceiptAdmissionQueue({ maxPerIssuer: 3,
    now: () => now, getRosterUids: () => ['M', 'B', 'V'],
    getChatWindow: () => ({ startMs: close - 3_600_000, endMs: close + 120_000 }),
    getChatCloseAtMs: () => close,
    verifyReceipt: () => new Promise((resolve) => waits.push(resolve)),
    resolveReceipt: (rc) => ({ state: 'covered', facts: [`M|a:${rc.actionHash}`],
      priority: rc.actionHash === xHash ? 'C' : 'V' }),
    onDiscard: (rc, why) => drops.set(rc.signature, why) }));
  const rc = (n, actionHash) => ({ receiverUid: 'M', actionHash,
    timestamp: now - 200_000 + n, signature: sig(n), _deviceSeenAt: now - 300_000 });
  const r = rc(100, xHash), vwin = rc(101, vHash);
  await q.offer(r, { verified: true });
  await q.offer(vwin, { verified: true });
  const pending = Array.from({ length: 4 }, (_, i) => q.offer(rc(i + 200, vHash)));
  await new Promise((resolve) => setImmediate(resolve));
  await q.offer(rc(300, vHash), { verified: true });
  assert([...q.entries.values()].some((e) => e.receipt.signature === r.signature),
    'FX2D reopen retains r immediately after re-delivery');
  for (const resolve of waits.splice(0)) {
    resolve(true);
    await new Promise((done) => setImmediate(done));
  }
  await Promise.all(pending);
  const kept = [...q.entries.values()].filter((e) => e.issuerUid === 'M');
  assert(kept.some((e) => e.receipt.signature === r.signature), 'FX2D reopen retains r');
  assert(kept.some((e) => e.receipt.signature === vwin.signature), 'FX2D reopen retains vwin');
  assert.equal(kept.length, 3, 'FX2D reopen returns to issuer cap');
  assert.equal(q.getAcceptedReceipts().filter((e) => e.actionHash === xHash).length, 1,
    'FX2D reopen keeps exactly one proof for x');
  assert.equal(drops.has(r.signature), false);
  q.dispose();
}
console.log('t3b-receipt-unit: ALL PASSED (U-18 source, issuer cap, proof refresh, DO time, bounded retry, fx2c)');

// U8: exercise the real offer/evaluation/cap path with confirmed-window waiting.
// U8_TOOTH selects one board when checking an old or mutated relay copy.
const u8Start = 1_780_000_000_000;
const u8Window = { startMs: u8Start, endMs: u8Start + 86_400_000 };
const u8Digest = (receipt) => receiptIdentityDigest(receipt);
const u8Receipt = (n, readReceipt = false) => ({ receiverUid: 'V',
  ...(readReceipt ? { senderUid: 'B', msgRefs: [`0x${n.toString(16).padStart(32, '0')}`] }
    : { actionHash: `0x${n.toString(16).padStart(64, '0')}` }),
  timestamp: u8Start + 1000,
  signature: `0x${n.toString(16).padStart(128, '0')}1b`,
});
const u8Board = ({ cap = 4, readReceipt = false, windowInitially = false } = {}) => {
  let windowOn = windowInitially, checks = 0;
  const validSignatures = new Set(), checksBySignature = new Map();
  const drops = new Map(), accepted = new Set();
  const q = new ReceiptAdmissionQueue({ maxPerIssuer: cap, requireConfirmedWindow: true,
    getChatWindow: () => windowOn ? u8Window : null,
    getRosterUids: () => ['B', 'V'], isRosterVerified: () => true,
    getSelectionContext: () => ({ myUid: 'B', messages: [] }),
    now: () => u8Start + 2000, getChatCloseAtMs: () => u8Window.endMs,
    verifyReceipt: async (rc) => { checks++;
      checksBySignature.set(rc.signature, (checksBySignature.get(rc.signature) || 0) + 1);
      return validSignatures.has(rc.signature); },
    resolveReceipt: (rc) => ({ state: 'covered',
      facts: [`u8:${rc.signature}`], priority: readReceipt ? 'F' : 'V' }),
    onAccept: (rc) => accepted.add(u8Digest(rc)),
    onRemove: (rc) => accepted.delete(u8Digest(rc)),
    onDiscard: (rc, reason) => drops.set(u8Digest(rc), reason),
  });
  return { q, drops, accepted, validSignatures, checksBySignature,
    get checks() { return checks; },
    confirm: async () => { windowOn = true; await q.reevaluate();
} };
};
const u8Tests = {
  1: async () => {
    const b = u8Board({ windowInitially: true });
    const old1 = u8Receipt(1001), old2 = u8Receipt(1002);
    await b.q.offer(old1, { verified: true });
    await b.q.offer(old2, { verified: true });
    // Two admitted actions, then a missing window, three forgeries, then V1.
    // Reconfigure only the source of the window; the queue and its cap stay real.
    let open = false;
    b.q.configure({ getChatWindow: () => open ? u8Window : null });
    const forged = [u8Receipt(1003), u8Receipt(1004), u8Receipt(1005)];
    for (const rc of forged) await b.q.offer(rc, { verified: false });
    const v1 = u8Receipt(1006);
    await b.q.offer(v1, { verified: true });
    assert.equal(b.drops.get(u8Digest(forged[2])), 'issuer_cap', 'U8-1 newest unverified forgery is dropped');
    assert(b.q.entries.has(u8Digest(v1)), 'U8-1 verified V1 survives');
    assert(b.q.entries.has(u8Digest(old1)) && b.q.entries.has(u8Digest(old2)),
      'U8-1 admitted actions survive');
    open = true; await b.q.reevaluate();
    assert(b.accepted.has(u8Digest(v1)), 'U8-1 V1 is accepted after window confirmation');
    b.q.dispose();
  },
  2: async () => {
    for (const readReceipt of [false, true]) {
      const b = u8Board({ cap: 1, readReceipt });
      const verified = u8Receipt(readReceipt ? 2001 : 2003, readReceipt);
      const unverified = u8Receipt(readReceipt ? 2002 : 2004, readReceipt);
      await b.q.offer(verified, { verified: true });
      await b.q.offer(unverified, { verified: false });
      const digest = u8Digest(unverified);
      assert.equal(b.drops.get(digest), 'issuer_cap', 'U8-2 unverified cap drop occurs');
      assert(!b.q.seenDigests.has(digest), 'U8-2 unverified digest is not seen');
      assert(!b.q.rejectedDigestsByIssuer.get('V')?.has(digest), 'U8-2 unverified digest is not rejected');
      b.q.configure({ maxPerIssuer: 2 });
      await b.q.offer(unverified, { verified: true });
      await b.confirm();
      assert(b.accepted.has(digest), 'U8-2 retried receipt is accepted');
      b.q.dispose();
    }
    const b = u8Board({ cap: 1 });
    const first = u8Receipt(2011), second = u8Receipt(2012);
    await b.q.offer(first, { verified: true });
    await b.q.offer(second, { verified: true });
    const lost = [first, second].find((rc) => b.drops.has(u8Digest(rc)));
    assert(lost, 'U8-2 verified cap drop occurs');
    assert(b.q.seenDigests.has(u8Digest(lost)), 'U8-2 verified drop stays seen');
    assert(b.q.rejectedDigestsByIssuer.get('V')?.has(u8Digest(lost)),
      'U8-2 verified drop stays rejected');
    b.q.dispose();
  },
  3: async () => {
    for (const readReceipt of [false, true]) {
      const b = u8Board({ cap: 4, readReceipt });
      const offset = readReceipt ? 3000 : 3100;
      const forged = [1, 2, 3].map((i) => u8Receipt(offset + i, readReceipt));
      for (const rc of forged) await b.q.offer(rc, { verified: false });
      const r = u8Receipt(offset + 4, readReceipt), h2 = u8Receipt(offset + 5, readReceipt);
      b.validSignatures.add(r.signature);
      const pending = b.q.offer(r, { verified: false });
      const merged = b.q.offer({ ...r }, { verified: true });
      await Promise.all([pending, merged]);
      await b.q.offer(h2, { verified: true });
      assert.equal(b.drops.get(u8Digest(forged[2])), 'issuer_cap',
        `U8-3 ${readReceipt ? 'read' : 'action'} newest forgery is dropped`);
      assert(b.q.entries.has(u8Digest(r)) && b.q.entries.has(u8Digest(h2)),
        `U8-3 ${readReceipt ? 'read' : 'action'} R and H2 survive`);
      await b.confirm();
      assert(b.accepted.has(u8Digest(r)) && b.accepted.has(u8Digest(h2)),
        'U8-3 R and H2 are accepted');
      assert.equal(b.checksBySignature.get(r.signature), 1, 'U8-3 merged R is checked once');
      b.q.dispose();
    }
  },
  4: async () => {
    for (const readReceipt of [false, true]) {
      let survived = 0;
      for (let seed = 1; seed <= 20; seed++) {
        const b = u8Board({ cap: 8, readReceipt });
        const offset = 4000 + seed * 20 + (readReceipt ? 1000 : 0);
        for (let i = 0; i < 7; i++) await b.q.offer(u8Receipt(offset + i, readReceipt));
        const r = u8Receipt(offset + 7, readReceipt), h2 = u8Receipt(offset + 8, readReceipt);
        b.validSignatures.add(r.signature);
        const doCopy = b.q.offer(r, { verified: false });
        const relayCopy = b.q.offer({ ...r }, { verified: true });
        await Promise.all([doCopy, relayCopy]);
        await b.q.offer(h2, { verified: true });
        if (b.q.entries.has(u8Digest(r)) && b.q.entries.has(u8Digest(h2))) survived++;
        b.q.dispose();
      }
      assert.equal(survived, 20, `U8-4 ${readReceipt ? 'READ_SPAM' : 'ACT_SPAM_A4'} 20/20 survive`);
    }
  },
  5: async () => {
    const b = u8Board({ cap: 4 });
    const r = u8Receipt(5001), digest = u8Digest(r);
    b.validSignatures.add(r.signature);
    const doCopy = b.q.offer(r, { verified: false });
    const relayCopy = b.q.offer({ ...r }, { verified: true });
    await Promise.all([doCopy, relayCopy]);
    await b.confirm();
    assert(b.accepted.has(digest), 'U8-5a accepted under cap');
    assert.equal(b.q.entries.get(digest)?.status, 'accepted', 'U8-5a status');
    assert.equal(b.q.entries.get(digest)?.priority, 'V', 'U8-5a priority');
    assert.equal(b.drops.size, 0, 'U8-5a no discard');
    assert.equal(b.q.seenDigests.size, 1, 'U8-5a seen');
    assert.equal(b.q.rejectedDigestsByIssuer.get('V')?.size || 0, 0, 'U8-5a no rejection');
    assert.equal(b.checks, 1, 'U8-5a merged copy still checked once');
    b.q.dispose();
    const all = u8Board({ cap: 700, windowInitially: true });
    const rs = Array.from({ length: 1200 }, (_, i) => u8Receipt(6001 + i));
    for (const rc of rs) await all.q.offer(rc, { verified: true });
    assert.equal(all.accepted.size, 700, 'U8-5b 700 accepted');
    assert(all.accepted.has(u8Digest(rs[0])), 'U8-5b first stays');
    assert(!all.accepted.has(u8Digest(rs[700])), 'U8-5b 701st drops');
    assert.equal(all.q.rejectedDigestsByIssuer.get('V')?.size || 0, 500, 'U8-5b 500 rejected');
    assert.equal(all.checks, 0, 'U8-5b no re-verification');
    all.q.dispose();
  },
  6: async () => {
    const b = u8Board({ cap: 2 });
    const a = u8Receipt(7001), c = u8Receipt(7002), d = u8Receipt(7003);
    await b.q.offer(a, { verified: true });
    await b.q.offer(c, { verified: true });
    await b.q.offer(d, { verified: false });
    assert.equal(b.drops.get(u8Digest(d)), 'issuer_cap', 'U8-6 pending only is retryable');
    assert(!b.q.seenDigests.has(u8Digest(d)), 'U8-6 pending digest is forgotten');
    b.q.dispose();
  },
};
let u8Failed = false;
for (const [number, run] of Object.entries(u8Tests)) {
  if (process.env.U8_TOOTH && process.env.U8_TOOTH !== number) continue;
  try { await run(); console.log(`U8-${number} GREEN`); }
  catch (error) { u8Failed = true; console.error(`U8-${number} RED: ${error.message}`); }
}
assert.equal(u8Failed, false, 'U8 teeth');

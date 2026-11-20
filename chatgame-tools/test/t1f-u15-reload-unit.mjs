import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { privateKeyToAccount } from 'viem/accounts';
import { RecoveryRelay } from '../src/recovery/relay-client.js';
import { parseOfficialStorage } from '../src/recovery/import-local-storage.js';
import { receiptIdentityDigest } from '../../src/utils/relay.js';
import {
  buildMsgKeyGetter, canonicalComparatorV2, clientReceiptableMessages as actualReceiptableMessages,
  msgRefOf, readReceiptSignString, isReceiptTimely, compareHexAsc,
} from '../../workers/game_workers/lib/protocol-v2.js';
import { GUEST_PINNED_RULES } from '../../workers/game_workers/lib/char-counter.js';
import { openReadReceiptPause, readReceiptTickGap } from '../vendor/src/utils/read-receipt-pause.js';

const clientReceiptableMessages = process.env.T1F_MUTATION === 'noFro'
  ? (messages, _receipts, { caps, compare }) => [...messages].sort(compare).slice(0, caps.maxMessages)
  : actualReceiptableMessages;
const blockNum = 5, groupId = 0, uid = 'V', now = Date.now();
const sender = 'M';
const account = privateKeyToAccount(`0x${'31'.repeat(32)}`);
const getKey = buildMsgKeyGetter(blockNum, groupId);
const compare = canonicalComparatorV2(getKey);
const makeMessage = (name, offset, from = sender) => ({
  uid: from, text: name, timestamp: now + offset, signature: `s-${name}`,
});
const refOf = (message) => msgRefOf(getKey(message));
const signRead = async (receiverUid, messages, timestamp = now - 500) => {
  const refs = messages.map(refOf).sort(compareHexAsc);
  return { receiverUid, senderUid: messages[0].uid, msgRefs: refs, timestamp,
    signature: await account.signMessage({ message: readReceiptSignString(
      blockNum, groupId, receiverUid, messages[0].uid, refs, timestamp) }) };
};
const caps = { ...GUEST_PINNED_RULES, maxMessages: 2 };
const context = { blockNum, groupId, myUid: uid, timestamp: now, caps, compare,
  getClientMsgKey: getKey, memberUids: [uid, sender, 'H', 'N'] };
const reply1 = makeMessage('reply-1', -1000);
const reply2 = makeMessage('reply-2', -900);
const backdate = makeMessage('backdate', -3000);
const covered = [await signRead('H', [reply1], now - 500),
  await signRead('H', [reply2], now - 400)];
assert.deepEqual(clientReceiptableMessages([backdate, reply2, reply1], covered, context),
  [reply1, reply2], 'FRO: already read replies keep the sender cap');
const oversizedRead = await signRead('H', [reply1, reply2, backdate]);
assert.deepEqual(clientReceiptableMessages([backdate, reply1, reply2], [oversizedRead], context),
  [backdate, reply1], 'a receipt beyond the scoring ref cap cannot reserve FRO priority');
assert.deepEqual(clientReceiptableMessages([reply1, backdate], [], {
  ...context, caps: { ...caps, maxMessages: 1 },
}), [backdate], 'FRO: equally unread candidates use canonical order');
const other = makeMessage('other', -500, 'N');
assert(clientReceiptableMessages([reply1, reply2, other], covered, context).includes(other),
  'a sender cannot consume another sender’s cap');
assert(clientReceiptableMessages([reply1, reply2], [], context).includes(reply2),
  'honest fresh messages under the cap remain eligible');
const ownRead = await signRead(uid, [reply1]);
assert.deepEqual(clientReceiptableMessages([reply1], [ownRead], context), [],
  'a received own read suppresses a duplicate');

// The official tick body, including the chain gate and the ten-second window.
const hook = readFileSync(process.env.OBS_HOOK_SOURCE || new URL('../../src/hooks/useGameWebSocket.js', import.meta.url), 'utf8');
const tickAt = hook.indexOf('const readReceiptTick = async () => {');
const tickEnd = hook.indexOf('};\n    readReceiptTimerRef.current', tickAt);
assert(tickAt >= 0 && tickEnd > tickAt);
let tickSource = hook.slice(hook.indexOf('async () => {', tickAt), tickEnd + 1);
if (process.env.T1F_MUTATION === 'noWindowRecheck') {
  tickSource = tickSource
    .replace('if (readReceiptPauseRef.current && performance.now() < readReceiptPauseRef.current.until) continue;', '')
    .replace('|| (readReceiptPauseRef.current && performance.now() < readReceiptPauseRef.current.until)', '');
}
const makeOfficialTick = ({ messages = [reply1], receipts = {}, until = -1,
  chainAllows = () => true, monotonic = () => 20000, wallClock = () => now,
  warned = false, ended = false, clockWarning = null } = {}) => {
  const published = [], issued = new Set(); let chainChecks = 0;
  const pause = { until, sequenceStartAt: 0, lastTickAt: monotonic(), lastTickWallAt: wallClock() };
  const pauseRef = { current: pause };
  const scope = {
    readReceiptPauseRef: pauseRef, performance: { now: monotonic },
    READ_RECEIPT_BATCH_MS: 8000, openReadReceiptPause, readReceiptTickGap,
    readReceiptTickRunningRef: { current: false },
    isAwayRef: { current: false }, phaseRef: { current: 'chatting' },
    sessionActivityRef: { current: { warned, ended, clockWarning } },
    rosterStartConfirmedRef: { current: true }, isGameIdentityCurrent: () => true,
    messagesRef: { current: messages }, uid, liveOnlyMessagesRef: { current: new Set() },
    issuedReadMsgKeysRef: { current: issued }, msgRefOf,
    computeMsgKeyV2: (_b, _g, message) => getKey(message), blockNum, groupId,
    coordinateSelfReadReceiptBatch: async (_key, _accept, issue) => issue(),
    queueReceipt: async () => true, canIssueReceiptAtChainTip: async () => { chainChecks++; return chainAllows(); },
    receiptsRef: { current: receipts }, clientReceiptableMessages,
    chatWindowMsFromTimeline: () => ({ startMs: now - 200000, endMs: now + 100000 }),
    chainTimelineRef: { current: {} }, GUEST_PINNED_RULES: caps,
    canonicalComparatorV2, buildMsgKeyGetter, getClientMsgKey: getKey,
    verifiedRosterRef: { current: { members: [{ uid }, { uid: sender }, { uid: 'H' }] } },
    issuedReadCountBySenderRef: { current: {} }, isReceiptTimely,
    issuingReadMsgKeysRef: { current: new Set() }, privateKeyToAccount,
    signKey: `0x${'31'.repeat(32)}`, compareHexAsc,
    canonicalizeSignature: (signature) => signature, readReceiptSignString,
    rememberOwnReadSignature: () => {}, send: (payload) => published.push(payload.receipt),
    relayChannelRef: { current: null }, readReceiptChannelRef: { current: null }, console,
    Date: { now: wallClock },
    clientNow: wallClock,
    getClockCorrection: () => 0,
    receiptIssuanceBlocked: () => scope.isAwayRef.current || scope.sessionActivityRef.current.warned
      || scope.sessionActivityRef.current.ended,
    nextReadReceiptTimestamp: ({ clockMs }) => clockMs,
    detectClockStep: () => false,
  };
  const tick = new Function(...Object.keys(scope), `return (${tickSource});`)(...Object.values(scope));
  return { tick, published, get chainChecks() { return chainChecks; },
    get pause() { return pauseRef.current; }, issued };
};
let mono = 0;
const official = makeOfficialTick({ until: 10000, monotonic: () => mono });
await official.tick();
assert.equal(official.published.length, 0, 'official join window blocks read');
mono = 8000;
await official.tick();
mono = 10001;
await official.tick();
assert.equal(official.published.length, 1, 'official first tick after 10 seconds emits without sync');
let delayedNow = 0;
const delayedTick = makeOfficialTick({ until: 10000, monotonic: () => delayedNow });
for (const at of [0, 10000, 20000, 30000]) { delayedNow = at; await delayedTick.tick(); }
assert.equal(delayedTick.published.length, 1,
  'repeated ten-second tick gaps still allow issuance at the 30-second cap');
delayedNow = 0;
const elevenSecondTick = makeOfficialTick({ until: 10000, monotonic: () => delayedNow });
for (const at of [0, 11000, 22000, 33000, 44000]) { delayedNow = at; await elevenSecondTick.tick(); }
assert.equal(elevenSecondTick.published.length, 1,
  'repeated eleven-second tick gaps do not keep reopening past the cap');
let afterIssueNow = 20000;
const afterIssueMessages = [reply1];
const afterIssue = makeOfficialTick({ messages: afterIssueMessages, monotonic: () => afterIssueNow });
await afterIssue.tick();
assert.equal(afterIssue.published.length, 1, 'official has already issued before sleep');
afterIssueMessages.push(reply2);
afterIssueNow = 320000;
await afterIssue.tick();
assert.equal(afterIssue.pause.until, 330000, 'five-minute sleep after a prior issuance still opens ten seconds');
assert.equal(afterIssue.published.length, 1, 'wake does not issue immediately');
afterIssueNow = 328000;
await afterIssue.tick();
afterIssueNow = 336000;
await afterIssue.tick();
assert.equal(afterIssue.published.length, 2, 'new message is read after the wake window');
for (const mode of [{ warned: true }, { ended: true }]) {
  const blocked = makeOfficialTick(mode);
  await blocked.tick();
  assert.equal(blocked.published.length, 0, 'official warning or closed tab blocks automatic read');
}
for (const stage of ['full', 'band']) {
  const warning = makeOfficialTick({ clockWarning: { warning: { direction: 'late', stage,
    deviationMs: -180000 } } });
  await warning.tick();
  assert(warning.chainChecks > 0, `official ${stage} clock warning permits chain check`);
  assert.equal(warning.published.length, 1, `official ${stage} clock warning permits signed read`);
}
const overlapping = makeOfficialTick({ receipts: { own: ownRead } });
overlapping.issued.add(`${sender}|${refOf(reply1)}`);
await overlapping.tick();
assert.equal(overlapping.published.length, 0, 'own receipt observed during window prevents overlap');
const afterClose = makeOfficialTick({ chainAllows: () => false });
await afterClose.tick();
assert.equal(afterClose.published.length, 0, 'official chain time beyond close blocks read');
const beforeClose = makeOfficialTick();
await beforeClose.tick();
assert.equal(beforeClose.published.length, 1, 'official chain time at close allows fresh read');
let midOfficial;
midOfficial = makeOfficialTick({ chainAllows: () => {
  midOfficial.pause.until = 30000; // チェーン確認の await 中に再接続が窓を開いた
  return true;
} });
await midOfficial.tick();
assert.equal(midOfficial.published.length, 0, 'official in-flight batch stops when a window opens');
// The recovery issue body must apply the same candidate selection and timing.
let app = readFileSync(process.env.T1F_RECOVERY_SOURCE || new URL('../src/recovery/app.js', import.meta.url), 'utf8');
const recoveryIssueMutation = (process.argv.find((arg) => arg.startsWith('--mutation=issue-rc-')) || '').slice('--mutation='.length);
const mutateRecoveryOnce = (before, after) => {
  assert.equal(app.split(before).length, 2, `ISSUE recovery mutation target: ${recoveryIssueMutation}`);
  app = app.replace(before, after);
};
if (recoveryIssueMutation === 'issue-rc-no-mark') mutateRecoveryOnce(
  'state.issuedActionHashes.add(receipt.actionHash);\n    }\n  }\n  if (!canStartRecoveryP2P',
  'void receipt.actionHash;\n    }\n  }\n  if (!canStartRecoveryP2P');
else if (recoveryIssueMutation === 'issue-rc-no-grace') mutateRecoveryOnce(
  'if (!grace || (!grace.passed && performance.now() < grace.until)) return;', 'if (false) return;');
else if (recoveryIssueMutation === 'issue-rc-no-precheck') mutateRecoveryOnce(
  'if (hasOwnActionReceipt(actionHash)) {', 'if (false) {');
else if (recoveryIssueMutation === 'issue-rc-no-replay') mutateRecoveryOnce(
  'state.actionReceiptGrace.passed = true;\n    handleObservedActions(state.relay.getRelayActionsRaw());',
  'state.actionReceiptGrace.passed = true;');
else if (recoveryIssueMutation === 'issue-rc-replay-redefer') mutateRecoveryOnce(
  'state.actionReceiptGrace.passed = true;\n    handleObservedActions(state.relay.getRelayActionsRaw());',
  'handleObservedActions(state.relay.getRelayActionsRaw());');
else assert.equal(recoveryIssueMutation, '', 'ISSUE recovery mutation known');
// Visibility alone must not create a pause; the tick detects an actual long scheduling gap.
assert.doesNotMatch(hook, /visibilitychange[\s\S]*?openReadReceiptPause/);
assert.doesNotMatch(app, /visibilitychange[\s\S]*?reopenReadReceiptPause/);
let resumedAt = 36_000;
const repeated = makeOfficialTick({ until: 30_000, monotonic: () => resumedAt });
repeated.pause.lastTickAt = resumedAt;
await repeated.tick();
assert.equal(repeated.published.length, 1, 'repeated resume cannot stop official reads indefinitely');
let sleepNow = 300000;
const officialSleep = makeOfficialTick({ monotonic: () => sleepNow });
officialSleep.pause.lastTickAt = 0;
await officialSleep.tick();
assert.equal(officialSleep.pause.until, 310000,
  'official five-minute sleep opens a full ten-second resume window');
assert.equal(officialSleep.published.length, 0, 'official sleep window blocks read');
sleepNow = 308000;
await officialSleep.tick();
sleepNow = 316000;
await officialSleep.tick();
assert.equal(officialSleep.published.length, 1,
  'official resumes issuing after the sleep window');
const officialGap = (mono, wall) => {
  let m = 0, w = 0;
  const sample = makeOfficialTick({ messages: [], monotonic: () => m, wallClock: () => w });
  m = mono; w = wall;
  return sample.tick().then(() => sample.pause.until);
};
assert.equal(await officialGap(29_000, 29_000), -1, 'official 29-second tick gap stays closed');
assert.equal(await officialGap(31_000, 29_000), 41_000, 'official monotonic 31-second gap opens');
assert.equal(await officialGap(0, 31_000), 10_000, 'official wall-clock 31-second gap opens when monotonic clock stops');
const recoveryTickAt = app.indexOf('state._rrTick = () => {');
const recoveryTickEnd = app.indexOf('state._rrTimer = setInterval', recoveryTickAt);
assert(recoveryTickAt >= 0 && recoveryTickEnd > recoveryTickAt);
const sleepState = { readReceiptPause: { until: -1, sequenceStartAt: 0, lastTickAt: 0 },
  relay: { getMessages: () => [] }, uid };
const recoverySleepTick = new Function('state', 'performance', 'Date', 'READ_RECEIPT_BATCH_MS',
  'rosterReady', 'currentPhase', 'openReadReceiptPause', 'readReceiptTickGap', 'detectClockStep', 'checkClock',
  `${app.slice(recoveryTickAt, recoveryTickEnd)}\nreturn state._rrTick;`)(
    sleepState, { now: () => 300000 }, { now: () => now + 300000 }, 8000,
    () => false, () => 'chatting', openReadReceiptPause, readReceiptTickGap, () => false, () => {});
recoverySleepTick();
assert.equal(sleepState.readReceiptPause.until, 310000,
  'recovery five-minute sleep opens a full ten-second resume window');
const recoveryGap = (mono, wall) => {
  const state = { readReceiptPause: { until: -1, sequenceStartAt: 0,
    lastTickAt: 0, lastTickWallAt: 0 }, relay: { getMessages: () => [] }, uid };
  const tick = new Function('state', 'performance', 'Date', 'READ_RECEIPT_BATCH_MS',
    'rosterReady', 'currentPhase', 'openReadReceiptPause', 'readReceiptTickGap', 'detectClockStep', 'checkClock',
    `${app.slice(recoveryTickAt, recoveryTickEnd)}\nreturn state._rrTick;`)(
      state, { now: () => mono }, { now: () => wall }, 8000,
      () => false, () => 'chatting', openReadReceiptPause, readReceiptTickGap, () => false, () => {});
  tick();
  return state.readReceiptPause.until;
};
assert.equal(recoveryGap(29_000, 29_000), -1, 'recovery 29-second tick gap stays closed');
assert.equal(recoveryGap(31_000, 29_000), 41_000, 'recovery monotonic 31-second gap opens');
assert.equal(recoveryGap(0, 31_000), 10_000, 'recovery wall-clock 31-second gap opens');

const issueAt = app.indexOf('async function issueReadReceiptBatch({ signal, known, tickCorrection = recoveryClock.getClockCorrection() } = {}) {');
const issueEnd = app.indexOf('// 既読マップ:', issueAt);
assert(issueAt >= 0 && issueEnd > issueAt);
const issueSource = app.slice(issueAt, issueEnd);
const recoveryBlockedAt = app.indexOf('function receiptIssuanceBlocked() {');
const recoveryBlockedEnd = app.indexOf('\n}', recoveryBlockedAt);
assert(recoveryBlockedAt >= 0 && recoveryBlockedEnd > recoveryBlockedAt);
const recoveryBlockedSource = app.slice(recoveryBlockedAt, recoveryBlockedEnd + 2);
const makeRecoveryBatch = ({ messages = [reply1], receipts = {}, until = -1,
  chainAllows = () => true, monotonic = () => 20000, warned = false, ended = false,
  clockWarning = null } = {}) => {
  const published = [], issued = new Set();
  const state = { uid, blockNum, groupId, identity: { signKey: `0x${'31'.repeat(32)}` },
    members: [{ uid }, { uid: sender }, { uid: 'H' }], receipts, away: false,
    otherSessionReadReceipt: warned, tabEnded: ended, clockWarning,
    readReceiptPause: { until, sequenceStartAt: 0, lastTickAt: monotonic() },
    issuedReadMsgKeys: issued, ownSessionReadSignatures: new Set(), ownSessionSignatures: new Set(),
    cfg: { pins: { chatCaps: caps } }, relay: {
      getMessages: () => messages, getMsgKey: getKey, isLiveOnlyMessage: () => false,
      publishReceipt: async (receipt) => { published.push(receipt); },
    } };
  const receiptIssuanceBlocked = new Function('state',
    `${recoveryBlockedSource}\nreturn receiptIssuanceBlocked;`)(state);
  const scope = { state, rosterReady: () => true, currentPhase: () => 'chatting',
    receiptIssuanceBlocked,
    performance: { now: monotonic }, canIssueReceiptAtChainTip: async () => chainAllows(),
    clientReceiptableMessages, submissionChatWindow: () => ({ startMs: now - 200000, endMs: now + 100000 }),
    normalizeChatCaps: (value) => value, canonicalComparatorV2, isReceiptTimely,
    msgRefOf, privateKeyToAccount, canonicalizeSignature: (signature) => signature,
    recoveryClock: { getClockCorrection: () => 0 },
    nextReadReceiptTimestamp: ({ clockMs }) => clockMs,
    readReceiptSignString, compareHexAsc, Date: { now: () => now }, clientNow: () => now,
    sessionStorage: { getItem: () => null, setItem: () => {} },
    recoveryAdmittedReceipts: () => Object.values(state.receipts),
    log: (message) => { throw new Error(message); },
  };
  const issue = new Function(...Object.keys(scope), `${issueSource}\nreturn issueReadReceiptBatch;`)(
    ...Object.values(scope));
  return { issue, published, state, receiptIssuanceBlocked };
};
let recoveryMono = 9999;
const recoveryReady = makeRecoveryBatch({ until: 10000, monotonic: () => recoveryMono });
await recoveryReady.issue();
assert.equal(recoveryReady.published.length, 0, 'recovery join window blocks read');
recoveryMono = 10001;
await recoveryReady.issue();
assert.equal(recoveryReady.published.length, 1, 'recovery emits without history or live sync');
for (const mode of [{ warned: true }, { ended: true }]) {
  const blocked = makeRecoveryBatch(mode);
  await blocked.issue();
  assert.equal(blocked.published.length, 0, 'recovery warning or closed tab blocks automatic read');
}
for (const stage of ['full', 'band']) {
  const warning = makeRecoveryBatch({ clockWarning: { warning: { direction: 'late', stage,
    deviationMs: -180000 } } });
  await warning.issue();
  assert.equal(warning.published.length, 1,
    `recovery ${stage} clock warning permits signed automatic read`);
}
// C3c: enter the actual eight-second tick and Q9C reissue gates under both warning displays.
const rrTickSource = app.slice(recoveryTickAt, recoveryTickEnd);
const reissueAt = app.indexOf('async function reissueReadReceipts(');
const reissueEnd = app.indexOf('// 既読マップ:', reissueAt);
assert(reissueAt >= 0 && reissueEnd > reissueAt);
const reissueSource = app.slice(reissueAt, reissueEnd);
for (const stage of ['full', 'band']) {
  const clockWarning = { warning: { direction: 'late', stage, deviationMs: -180000 } };
  const automatic = makeRecoveryBatch({ clockWarning });
  automatic.state.readReceiptPause = null;
  let tickFinished;
  const tickDone = new Promise((resolve, reject) => { tickFinished = { resolve, reject }; });
  const tickScope = { state: automatic.state, performance: { now: () => 20000 },
    Date: { now: () => now }, detectClockStep: () => false,
    readReceiptTickGap, openReadReceiptPause, checkClock: () => {},
    rosterReady: () => true, receiptIssuanceBlocked: automatic.receiptIssuanceBlocked,
    currentPhase: () => 'chatting', msgRefOf, coordinateSelfReadReceiptBatch:
      async (_key, _accept, issue) => {
        try { const result = await issue({ known: [] }); tickFinished.resolve(result); return result; }
        catch (error) { tickFinished.reject(error); throw error; }
      },
    recoveryClock: { getClockCorrection: () => 0 }, receiptIdentityDigest,
    mergeReceipts: () => {}, issueReadReceiptBatch: automatic.issue };
  new Function(...Object.keys(tickScope), `${rrTickSource}\nreturn state._rrTick;`)(...Object.values(tickScope))();
  await Promise.race([tickDone, new Promise((resolve) => setTimeout(resolve, 250))]);
  assert.equal(automatic.published.length, 1,
    `C3c: recovery ${stage} warning passes the real eight-second tick gate`);
  const issued = automatic.published[0];
  assert.equal(issued.signature, await account.signMessage({ message: readReceiptSignString(
    blockNum, groupId, issued.receiverUid, issued.senderUid, issued.msgRefs, issued.timestamp) }),
  `C3c: recovery ${stage} tick publishes a signed read receipt`);

  const reissued = makeRecoveryBatch({ clockWarning });
  reissued.state.timeline = { chattingStart: now - 200000, chatCloseAt: now + 100000 };
  const reissueScope = { state: reissued.state, setTimeout, rosterReady: () => true,
    receiptIssuanceBlocked: reissued.receiptIssuanceBlocked, currentPhase: () => 'chatting',
    coordinateSelfReadReceiptBatch: async (_key, _accept, issue) => issue({ known: [] }),
    receiptIdentityDigest, mergeReceipts: () => {}, canIssueReceiptAtChainTip: async () => true,
    msgRefOf, planReadReceiptReissues: () => [{ receiverUid: uid, senderUid: sender,
      msgRefs: [refOf(reply1)], timestamp: now - 500 }], clientNow: () => now,
    privateKeyToAccount, canonicalizeSignature: (value) => value,
    readReceiptSignString, sessionStorage: { getItem: () => null, setItem: () => {} },
    reissueGroupKey: () => 'unused' };
  const reissue = new Function(...Object.keys(reissueScope),
    `${reissueSource}\nreturn reissueReadReceipts;`)(...Object.values(reissueScope));
  await reissue(150000);
  assert.equal(reissued.published.length, 1,
    `C3c: recovery ${stage} warning passes Q9C reissue gate and publishes`);
  const again = reissued.published[0];
  assert.equal(again.signature, await account.signMessage({ message: readReceiptSignString(
    blockNum, groupId, again.receiverUid, again.senderUid, again.msgRefs, again.timestamp) }),
  `C3c: recovery ${stage} Q9C reissue is signed`);
}
const recoveryOwn = makeRecoveryBatch({ receipts: { own: ownRead } });
recoveryOwn.state.issuedReadMsgKeys.add(`${sender}|${refOf(reply1)}`);
await recoveryOwn.issue();
assert.equal(recoveryOwn.published.length, 0, 'recovery skips an overlapping own read');
const recoveryClosed = makeRecoveryBatch({ chainAllows: () => false });
await recoveryClosed.issue();
assert.equal(recoveryClosed.published.length, 0, 'recovery chain time beyond close blocks read');
let midRecovery;
midRecovery = makeRecoveryBatch({ chainAllows: () => {
  midRecovery.state.readReceiptPause.until = 30000;
  return true;
} });
await midRecovery.issue();
assert.equal(midRecovery.published.length, 0, 'recovery in-flight batch stops when a window opens');

// Q4: official localStorage export no longer supplies messages to recovery.
assert.doesNotMatch(hook, /messageArrivals_/);
const parsed = await parseOfficialStorage(JSON.stringify({
  [`messageArrivals_${blockNum}_group${groupId}_user${uid}`]: JSON.stringify([
    ['signature', sender, now, 'message']]),
}), { blockNum, groupId, uid, members: [{ uid }, { uid: sender }],
  verify: async (type) => { assert.notEqual(type, 'chat'); return true; } });
assert.equal(Object.hasOwn(parsed, 'messages'), false);

// Q5: already verified durable reads survive startup; new unknown targets stay volatile.
const values = new Map();
globalThis.localStorage = {
  getItem: (key) => values.get(key) ?? null,
  setItem: (key, value) => { values.set(key, value); },
  removeItem: (key) => values.delete(key),
};
const member = { uid, bAddr: { address: account.address } };
const recoveryOptions = { signKey: `0x${'31'.repeat(32)}`, blockNum, groupId, uid,
  members: [member, { uid: sender, bAddr: { address: account.address } }],
  sinceSec: Math.floor((now - 300000) / 1000),
  getChatWindow: () => ({ startMs: now - 200000, endMs: now + 100000 }) };
const durableKey = `recoveryReceiptArrivals_${blockNum}_group${groupId}_user${uid}`;
values.set(durableKey, JSON.stringify({ [receiptIdentityDigest(ownRead)]: { ...ownRead, _seq: 1 } }));
const relay = new RecoveryRelay(recoveryOptions);
await relay.verifyStoredReceipts();
assert(Object.values(JSON.parse(values.get(durableKey))).some((receipt) =>
  receiptIdentityDigest(receipt) === receiptIdentityDigest(ownRead)),
'validated stored read survives startup before target chat arrives');
const unknown = await signRead('H', [reply2]);
relay._receipts[receiptIdentityDigest(unknown)] = { ...unknown, _seq: 2 };
relay._saveReceiptArrivals();
assert(!Object.values(JSON.parse(values.get(durableKey))).some((receipt) =>
  receiptIdentityDigest(receipt) === receiptIdentityDigest(unknown)),
'new receipt without a known target is not newly persisted');
relay._verifyChat = async () => true;
assert.equal(await relay._ingestChat(makeMessage('old-run', -600000)), false,
  'recovery rejects a chat predating the authoritative START_TIME');
console.log('T1f FRO / Q4 / Q5 / join-window: ALL PASSED');
if (process.env.C3C_GATE_ONLY === '1') process.exit(0);


// OBSBASE / MSGBASE: the real hook callbacks are extracted from the selected source.
{
  const { createRequire } = await import('node:module');
  const require = createRequire(new URL('../../package.json', import.meta.url));
  const { parse } = require('@babel/parser');
  const acorn = require('acorn');
  const eslintScope = require('eslint-scope');
  const { verifyMessage } = await import('viem');
  const P = await import('../../workers/game_workers/lib/protocol-v2.js');
  const CC = await import('../../workers/game_workers/lib/char-counter.js');
  const R = await import('../../src/utils/relay.js');
  const RV = await import('../../src/utils/roster-verification.js');
  const CK = await import('../../src/utils/chainClock.js');
  const RP = await import('../../src/utils/read-receipt-pause.js');
  const mutation = (process.argv.find((arg) => /^--mutation=(obs-|issue-(?!rc-))/.test(arg)) || '').slice('--mutation='.length);
  let selectedHook = hook;
  const replaceOnce = (before, after) => {
    assert.ok(selectedHook.includes(before), `OBS mutation target exists: ${mutation}`);
    selectedHook = selectedHook.replace(before, after);
  };
  if (mutation === 'obs-chat-gate') replaceOnce(
    "if (!actionIngestGateOpen()) break; // S3FIX-G3W-U10 案 (i): message_history と同じ門", '');
  else if (mutation === 'obs-history-gate') replaceOnce(
    'if (!actionIngestGateOpen()) break;\n          // E-2: 履歴', '// E-2: 履歴');
  else if (mutation === 'obs-chat-after-verify') {
    replaceOnce("if (!actionIngestGateOpen()) break; // S3FIX-G3W-U10 案 (i): message_history と同じ門", '');
    replaceOnce('const valid = await verifyIncomingMessage(incoming);',
      'const valid = await verifyIncomingMessage(incoming);\n            if (!actionIngestGateOpen()) return;');
  } else if (mutation === 'obs-history-after-verify') {
    replaceOnce('if (!actionIngestGateOpen()) break;\n          // E-2: 履歴', '// E-2: 履歴');
    replaceOnce('const valid = checked.filter(Boolean);',
      'if (!actionIngestGateOpen()) return;\n            const valid = checked.filter(Boolean);');
  } else if (mutation === 'obs-sign-gate') replaceOnce(
    'const roster = verifiedRosterRef.current;',
    'if (!rosterStartConfirmedRef.current) return false;\n    const roster = verifiedRosterRef.current;');
  else if (mutation === 'obs-no-entry-gate') replaceOnce(
    'if (!actionIngestGateOpen()) return;\n    const queue = actionVerificationQueueRef.current;',
    'const queue = actionVerificationQueueRef.current;');
  else if (mutation === 'obs-no-ingest-gate') replaceOnce(
    'if (!actionIngestGateOpen()) return false;\n      const prev = observedActionsRef.current;',
    'const prev = observedActionsRef.current;');
  else if (mutation === 'obs-restore-gate') replaceOnce(
    '// 観測データ復元（WS経由分。リレー分はGameRelayChannelが自前で復元）\n    if (groupId != null) {',
    '// 観測データ復元（WS経由分。リレー分はGameRelayChannelが自前で復元）\n    if (!actionIngestGateOpen()) return;\n    if (groupId != null) {');
  else if (mutation === 'obs-relay-gate') replaceOnce(
    'const handleRelayChat = useCallback((inner) => {',
    'const handleRelayChat = useCallback((inner) => {\n    if (!actionIngestGateOpen()) return;');
  else if (mutation === 'obs-own-bypass') replaceOnce(
    'if (!actionIngestGateOpen()) return;\n    const queue = actionVerificationQueueRef.current;',
    'if (actorUid !== uid && !actionIngestGateOpen()) return;\n    const queue = actionVerificationQueueRef.current;');
  else if (mutation === 'issue-no-restore-mark') replaceOnce(
    'issuedActionHashesRef.current.add(receipt.actionHash);', 'void receipt.actionHash;');
  else if (mutation === 'issue-no-precheck') replaceOnce('if (hasOwnActionReceipt(actionHash)) {', 'if (false) {');
  else if (mutation === 'issue-no-grace') replaceOnce(
    'if (deferActionReceipt(actorUid, actionType, action, isCurrentOwner)) return;',
    'if (false && deferActionReceipt(actorUid, actionType, action, isCurrentOwner)) return;');
  else if (mutation === 'issue-no-replay') replaceOnce(
    'void retryReceiptForAcceptedAction(item.actionType, item.actorUid, item.action, item.isCurrentOwner);',
    'void item;');
  else if (mutation === 'issue-replay-redefer') replaceOnce('grace.passed = true;', 'void grace;');
  else if (mutation === 'issue-grace-from-mount') replaceOnce(
    'until: openReadReceiptPause(null, performance.now(), false, Date.now()).until,',
    'until: openReadReceiptPause(null, actionReceiptMountAt, false, Date.now()).until,');
  else if (mutation === 'issue-precheck-counts-pending') replaceOnce(
    'receiptAdmissionRef.current?.getAcceptedReceipts().some(isOwn)',
    '[...(receiptAdmissionRef.current?.getAcceptedReceipts() || []), ...(receiptAdmissionRef.current?.getPendingReceipts() || [])].some(isOwn)');
  else assert.equal(mutation, '', `OBS mutation known: ${mutation}`);
  const VARIANTS = { current: selectedHook };
const PARSE_OPTS = { sourceType: 'module', plugins: ['jsx', 'bigInt', 'numericSeparator', 'optionalChaining', 'nullishCoalescingOperator', 'logicalAssignment'] };
const ASTS = Object.fromEntries(Object.entries(VARIANTS).map(([k, t]) => [k, parse(t, PARSE_OPTS)]));
function walk(node, pred, out = []) {
  if (!node || typeof node !== 'object') return out;
  if (pred(node)) out.push(node);
  for (const [k, v] of Object.entries(node)) {
    if (['loc', 'start', 'end', 'tokens', 'comments', 'leadingComments', 'trailingComments', 'innerComments'].includes(k)) continue;
    if (Array.isArray(v)) v.forEach((c) => walk(c, pred, out)); else if (v && typeof v === 'object') walk(v, pred, out);
  }
  return out;
}
const lineOf = (text, n) => text.slice(0, n.start).split('\n').length;
function hookCallback(variant, name) {
  const text = VARIANTS[variant];
  const rows = walk(ASTS[variant], (n) => n.type === 'VariableDeclarator' && n.id?.name === name
    && n.init?.type === 'CallExpression' && n.init.callee?.name === 'useCallback');
  if (rows.length !== 1) return null;
  return { text: text.slice(rows[0].init.arguments[0].start, rows[0].init.arguments[0].end), line: lineOf(text, rows[0]) };
}
function plainDecl(variant, name) {
  const text = VARIANTS[variant];
  const rows = walk(ASTS[variant], (n) => n.type === 'VariableDeclarator' && n.id?.name === name);
  assert.equal(rows.length, 1, name);
  return { text: text.slice(rows[0].init.start, rows[0].init.end), line: lineOf(text, rows[0]) };
}
const GLOBALS = new Set(['Array', 'Boolean', 'Date', 'Error', 'JSON', 'Map', 'Math', 'Number', 'Object',
  'Promise', 'Set', 'String', 'Symbol', 'console', 'undefined', 'setTimeout', 'clearTimeout', 'BigInt', 'Infinity', 'NaN']);
function freeIds(text) {
  const ast = acorn.parse(`const __x = (${text});`, { ecmaVersion: 'latest', sourceType: 'script', ranges: true });
  const sm = eslintScope.analyze(ast, { ecmaVersion: 2024, sourceType: 'script' });
  return [...new Set(sm.globalScope.through.map((r) => r.identifier.name))].sort();
}
const STUB = new Proxy(function () {}, {
  get(t, p) { if (p === 'then') return undefined; if (p === Symbol.toPrimitive) return () => 0; if (p === Symbol.iterator) return function* () {}; return STUB; },
  apply() { return STUB; }, construct() { return STUB; },
});
const stubbed = {};
function bind(label, text, provided, { allowStub = false } = {}) {
  const free = freeIds(text).filter((n) => !GLOBALS.has(n));
  const missing = free.filter((n) => !(n in provided));
  if (missing.length && !allowStub) throw new Error(`${label}: unbound ${missing.join(',')}`);
  const bindings = { ...provided };
  for (const n of missing) bindings[n] = STUB;
  if (missing.length) stubbed[label] = missing;
  const names = Object.keys(bindings);
  return Function(...names, `'use strict'; return (${text});`)(...names.map((n) => bindings[n]));
}
const flush = async () => { for (let i = 0; i < 60; i++) await new Promise((r) => setImmediate(r)); };

// ------------------------------------------------------------ 盤面の材料
const blockNum = 7; const groupId = 3;
const V = 'uidV'; const B = 'uidB'; const W = 'uidW';
const keyOf = (n) => `0x${n.repeat(64)}`;
const KEY = { V: keyOf('1'), B: keyOf('2'), W: keyOf('3'), OP: keyOf('9') };
const ACC = Object.fromEntries(Object.entries(KEY).map(([k, v]) => [k, privateKeyToAccount(v)]));
const KEY_OF_UID = { [V]: KEY.V, [W]: KEY.W, [B]: KEY.B };
const ACC_OF_UID = { [V]: ACC.V, [W]: ACC.W, [B]: ACC.B };
const pub = (uid, acc, n) => ({ uid, walletAddress: '0x' + n.repeat(40), blockAddress: acc.address,
  pubKey: '0x04' + n.repeat(128), nostrPubkey: n.repeat(64), depositIds: ['1'] });
const canonicalPublic = [pub(V, ACC.V, 'a'), pub(B, ACC.B, 'b'), pub(W, ACC.W, 'c')];
const fakePublic = [pub(V, ACC.V, 'a'), { ...pub(B, ACC.B, 'b'), blockAddress: ACC.OP.address }, pub(W, ACC.W, 'c')];
const gameMembers = (pubs) => RV.publicRosterToGameMembers(pubs, []);
const S = Date.UTC(2026, 9, 10, 12, 0, 0);
const SEC = 1000; const MIN = 60 * SEC;
const chainTimeline = { chatOpenAt: S - 2 * 3600000, chattingStart: S, chatCloseAt: S + 24 * 3600000, resultCloseAt: S + 48 * 3600000 };
const rosterResult = (pubs, anchorStatus, chainHashByte, observedAtMs, extra = {}) => ({
  status: 'verified', blockNum, groupId, members: gameMembers(pubs), publicMembers: pubs, anchorStatus,
  chainHash: '0x' + chainHashByte.repeat(64), observedAtMs, chattingStartMs: S,
  rosterProofSaved: anchorStatus !== 'provisional', ...extra,
});
const C1 = rosterResult(fakePublic, 'provisional', '1', S - 40 * MIN);       // 偽の仮の名簿（B の行だけ運営の鍵）
const C2p = rosterResult(canonicalPublic, 'provisional', '2', S - 40 * MIN); // 正しい仮の名簿（正直な盤面）
const C2 = rosterResult(canonicalPublic, 'canonical', '2', S + 12 * SEC);    // 開始後の正典（証明つき）
const refOf = (m) => P.msgRefOf(P.computeMsgKeyV2(blockNum, groupId, m));

const LEN = P.ACTION_CIPHERTEXT_HEX_LEN;
const cipher = (seed) => (seed.toString(16).padStart(4, '0').repeat(LEN)).slice(0, LEN);
async function signedAction(acc, type, actorUid, seed, ts) {
  const encrypted = cipher(seed);
  const signature = P.canonicalizeSignature(await acc.signMessage({
    message: P.actionSignStringV2(type, blockNum, groupId, actorUid, encrypted, ts) }));
  return { encrypted, signature, timestamp: ts };
}
async function signChat(acc, uidX, text, ts) {
  return { uid: uidX, text, timestamp: ts,
    signature: P.canonicalizeSignature(await acc.signMessage({ message: P.chatSignStringV2(blockNum, groupId, uidX, text, ts) })) };
}
const initMsg = (actions) => ({ data: JSON.stringify({ type: 'init_response', phase: 'chatting', members: [], actions }) });
const actionMade = (actorUid, type, a) => ({ data: JSON.stringify({ type: 'action_made', uid: actorUid, actionType: type, ...a }) });
const chatMsg = (m) => ({ data: JSON.stringify({ type: 'chat', message: m }) });
const historyMsg = (ms) => ({ data: JSON.stringify({ type: 'message_history', messages: ms }) });
const resetObsStorage = () => {
  const rows = new Map();
  globalThis.localStorage = {
    getItem: (key) => rows.get(key) ?? null,
    setItem: (key, value) => { rows.set(key, value); },
    removeItem: (key) => rows.delete(key),
  };
};

// ------------------------------------------------------------ 1つの画面
function makePage(variant, me = V, { liveGrace = false, openedAt = S - 60 * MIN } = {}) {
  const now = { value: openedAt };
  const timers = [];
  const refs = {
    verifiedRosterRef: { current: null }, operatorRosterProofRef: { current: false }, unverifiedRosterRef: { current: null },
    observedActionsRef: { current: { votes: {}, reports: {} } },
    rosterStartConfirmedRef: { current: false }, phaseRef: { current: 'waiting' },
    chainTimelineRef: { current: chainTimeline }, confirmedChatWindowRef: { current: null },
    issuedActionHashesRef: { current: new Set() }, issuedActionReceiptBucketsRef: { current: new Map() },
    issuingActionReceiptBucketsRef: { current: new Map() }, actionVerificationQueueRef: { current: new Map() },
    receiptAdmissionIdentityRef: { current: { blockNum, groupId, uid: me } },
    actionReceiptGraceRef: { current: null }, receiptAdmissionRef: { current: {
      getAcceptedReceipts: () => [], getPendingReceipts: () => [],
    } },
    currentRosterIdentityRef: { current: { blockNum, groupId, uid: me } },
    peerActivityRef: { current: {} }, liveOnlyActionsRef: { current: new Set() }, liveOnlyMessagesRef: { current: new Set() },
    isAwayRef: { current: false },
    sessionActivityRef: { current: { entryAt: null, awayIntervals: [], ownSignatures: new Set(), ended: false, warned: false } },
    relayChannelRef: { current: null }, rosterStartCheckedRef: { current: new Set() },
    g3ObservationsRef: { current: { identity: 'w', actions: new Map(), serverReceipts: new Map(), historicReports: new Set() } },
    chatEndedRef: { current: false },
    receiptsRef: { current: {} }, issuedReadMsgKeysRef: { current: new Set() }, issuingReadMsgKeysRef: { current: new Set() },
    issuedReadCountBySenderRef: { current: {} },
  };
  const futureMarks = new R.FutureAdmissionMarks({ blockNum, groupId, now: () => now.value, correction: () => 0 });
  refs.futureMarksRef = { current: futureMarks };
  const spy = { receipts: [], saves: [], published: [], actionEvents: [], verifyCalls: 0 };
  const page = { variant, me, now, refs, spy, futureMarks, signKey: null, messages: [], verifyHold: null };
  page.timers = timers;
  page.fireTimers = async () => {
    for (const timer of timers.filter((item) => !item.cancelled && !item.fired && item.at <= now.value)) {
      timer.fired = true; timer.fn();
    }
    await flush();
  };
  page.restoreReceipts = () => {
    const rows = walk(ASTS[variant], (node) => node.type === 'CallExpression'
      && node.callee?.name === 'useEffect' && node.arguments?.[0]?.type === 'ArrowFunctionExpression'
      && VARIANTS[variant].slice(node.start, node.end).includes('const stored = loadJson(OBSERVED_RECEIPTS_KEY'));
    assert.equal(rows.length, 1, 'ISSUE restore effect exists');
    const effect = bind('ISSUE restore effect', VARIANTS[variant].slice(rows[0].arguments[0].start, rows[0].arguments[0].end), {
      blockNum, groupId, uid: me, isSpectator: false,
      OBSERVED_RECEIPTS_KEY: (bn, g, u) => `observedReceipts_${bn}_group${g}_user${u}`,
      loadJson: (key, fallback) => { try { return JSON.parse(globalThis.localStorage.getItem(key)) || fallback; } catch { return fallback; } },
      getObservedReceiptWriter: () => ({ syncDisk: () => {} }),
      issuedActionHashesRef: refs.issuedActionHashesRef,
      queueReceipt: () => {},
    });
    effect();
  };
  const heldVerify = async (args) => { spy.verifyCalls++; if (page.verifyHold) await page.verifyHold; return verifyMessage(args); };
  const rscText = plainDecl(variant, 'rosterStartConfirmed').text;
  const rscFn = (state) => Function('rosterIdentityMatches', 'verifiedRosterState', 'blockNum', 'groupId', 'chainTimeline',
    `'use strict'; return (${rscText});`)(RV.rosterIdentityMatches, state, blockNum, groupId, refs.chainTimelineRef.current);
  const selectCurrentRoster = () => RV.selectCurrentRoster(refs.verifiedRosterRef.current, refs.unverifiedRosterRef.current, blockNum, groupId);
  page.selectCurrentRoster = selectCurrentRoster;
  const common = { blockNum, groupId, uid: me, isGameIdentityCurrent: () => true,
    receiptIssuanceBlocked: () => refs.isAwayRef.current || refs.sessionActivityRef.current.warned
      || refs.sessionActivityRef.current.ended };
  // 受け取った既読（自分のものと他人のもの）を receiptsRef へ入れ、hook :1754-1772 の effect と同じく発行済みを作り直す
  const recompute = () => {
    const perSender = {}; const distinct = new Set();
    for (const rc of Object.values(refs.receiptsRef.current)) {
      if (rc.receiverUid !== me) continue;
      if (Array.isArray(rc.msgRefs)) for (const k of rc.msgRefs) {
        const key = `${rc.senderUid}|${k}`;
        refs.issuedReadMsgKeysRef.current.add(key);
        if (rc.senderUid != null && !distinct.has(key)) { distinct.add(key); perSender[rc.senderUid] = (perSender[rc.senderUid] || 0) + 1; }
      }
    }
    refs.issuedReadCountBySenderRef.current = perSender;
  };
  page.receiveReceipt = (rc) => { refs.receiptsRef.current = { ...refs.receiptsRef.current, [rc.signature]: rc }; recompute(); };
  page.render = () => {
    const state = refs.verifiedRosterRef.current;
    const rsc = !!state && rscFn(state);
    refs.rosterStartConfirmedRef.current = rsc;
    page.signKey = rsc && ['canonical', 'legacy'].includes(state.anchorStatus) ? KEY_OF_UID[me] : null;
    refs.phaseRef.current = now.value < S ? 'waiting' : (now.value < chainTimeline.chatCloseAt ? 'chatting' : 'submitting');
    refs.confirmedChatWindowRef.current = rsc ? P.chatWindowMsFromTimeline(refs.chainTimelineRef.current) : null;
    const b = {};
    b.verifyRelayInner = bind('verifyRelayInner', hookCallback(variant, 'verifyRelayInner').text, {
      ...common, selectCurrentRoster, effectiveClientNow: () => now.value, isCanonicalTimestamp: P.isCanonicalTimestamp, isCanonicalSignature: P.isCanonicalSignature,
      isCanonicalText: P.isCanonicalText, hasVisibleContent: CC.hasVisibleContent, chatSignStringV2: P.chatSignStringV2,
      actionSignStringV2: P.actionSignStringV2, isCanonicalActionCiphertext: P.isCanonicalActionCiphertext,
      presenceSignStringV2: P.presenceSignStringV2, isMsgRef: P.isMsgRef, receiptMaxRefsPerReceipt: P.receiptMaxRefsPerReceipt,
      GUEST_PINNED_RULES: CC.GUEST_PINNED_RULES, compareHexAsc: P.compareHexAsc, readReceiptSignString: P.readReceiptSignString,
      isActionHash: P.isActionHash, receiptSignString: P.receiptSignString, verifyMessage: heldVerify,
    }, { allowStub: true });
    const gate = hookCallback(variant, 'actionIngestGateOpen');
    b.actionIngestGateOpen = gate ? bind('actionIngestGateOpen', gate.text, {
      blockNum, groupId, rosterStartConfirmedRef: refs.rosterStartConfirmedRef, verifiedRosterRef: refs.verifiedRosterRef,
      rosterIdentityMatches: RV.rosterIdentityMatches, chainTimelineRef: refs.chainTimelineRef,
    }) : null;
    const gateBinding = b.actionIngestGateOpen ? { actionIngestGateOpen: b.actionIngestGateOpen } : {};
    b.ingestObservedAction = bind('ingestObservedAction', hookCallback(variant, 'ingestObservedAction').text, {
      ...common, ...gateBinding, observedActionsRef: refs.observedActionsRef,
      shouldIssueReceiptForObservedAction: P.shouldIssueReceiptForObservedAction,
      MAX_OBSERVED_ACTIONS_PER_ACTOR: P.MAX_OBSERVED_ACTIONS_PER_ACTOR, setObservedActions: () => {},
      saveJson: (k, v) => { spy.saves.push(JSON.parse(JSON.stringify(v))); return true; },
      OBSERVED_ACTIONS_KEY: (bn, g, u) => `observedActions_${bn}_group${g}_user${u}`, warnActionPersistenceFailure: () => {},
    });
    const graceSource = hookCallback(variant, 'getActionReceiptGrace');
    b.getActionReceiptGrace = graceSource ? bind('getActionReceiptGrace', graceSource.text, {
      receiptAdmissionIdentityRef: refs.receiptAdmissionIdentityRef,
      actionReceiptGraceRef: refs.actionReceiptGraceRef, openReadReceiptPause: RP.openReadReceiptPause,
      actionReceiptMountAt: openedAt,
      performance: { now: () => now.value },
    }) : () => null;
    const deferSource = hookCallback(variant, 'deferActionReceipt');
    b.deferActionReceipt = deferSource ? bind('deferActionReceipt', deferSource.text, {
      getActionReceiptGrace: b.getActionReceiptGrace, performance: { now: () => now.value },
      MAX_OBSERVED_ACTIONS_PER_ACTOR: P.MAX_OBSERVED_ACTIONS_PER_ACTOR,
    }) : () => false;
    const precheckSource = hookCallback(variant, 'hasOwnActionReceipt');
    b.hasOwnActionReceipt = precheckSource ? bind('hasOwnActionReceipt', precheckSource.text, {
      blockNum, groupId, uid: me, receiptAdmissionRef: refs.receiptAdmissionRef,
      OBSERVED_RECEIPTS_KEY: (bn, g, u) => `observedReceipts_${bn}_group${g}_user${u}`,
      loadJson: (key, fallback) => { try { return JSON.parse(globalThis.localStorage.getItem(key)) || fallback; } catch { return fallback; } },
    }) : () => false;
    if (!liveGrace && page.signKey && graceSource) {
      const grace = b.getActionReceiptGrace(); grace.until = -Infinity; grace.passed = true;
    }
    b.issueActionReceipt = bind('issueActionReceipt', hookCallback(variant, 'issueActionReceipt').text, {
      ...common, receiptAdmissionIdentityRef: refs.receiptAdmissionIdentityRef, rosterStartConfirmedRef: refs.rosterStartConfirmedRef,
      rosterIdentityMatches: RV.rosterIdentityMatches, currentRosterIdentityRef: refs.currentRosterIdentityRef,
      signKey: page.signKey, isSpectator: false, phaseRef: refs.phaseRef, isAwayRef: refs.isAwayRef,
      sessionActivityRef: refs.sessionActivityRef, clientNow: () => Math.floor(now.value), isReceiptTimely: P.isReceiptTimely,
      chainTimelineRef: refs.chainTimelineRef, confirmedChatWindowRef: refs.confirmedChatWindowRef,
      CHAT_WINDOW_CLOCK_SKEW_MS: P.CHAT_WINDOW_CLOCK_SKEW_MS,
      canIssueActionReceiptBeforeVoteCutoff: CK.canIssueActionReceiptBeforeVoteCutoff,
      canIssueReceiptAtChainTip: async () => true, actionHashV2: P.actionHashV2,
      issuedActionHashesRef: refs.issuedActionHashesRef, issuedActionReceiptBucketsRef: refs.issuedActionReceiptBucketsRef,
      issuingActionReceiptBucketsRef: refs.issuingActionReceiptBucketsRef,
      MAX_OBSERVED_ACTIONS_PER_ACTOR: P.MAX_OBSERVED_ACTIONS_PER_ACTOR, privateKeyToAccount,
      canonicalizeSignature: P.canonicalizeSignature, receiptSignString: P.receiptSignString,
      send: (frame) => { spy.actionEvents.push(['send', frame.receipt]); return true; }, relayChannelRef: refs.relayChannelRef,
      queueReceipt: async (receipt) => { spy.actionEvents.push(['queueReceipt', receipt]); spy.receipts.push(receipt); return true; },
      deferActionReceipt: b.deferActionReceipt, hasOwnActionReceipt: b.hasOwnActionReceipt,
    }, { allowStub: true });
    if (graceSource) assert(!['deferActionReceipt', 'hasOwnActionReceipt'].some((id) =>
      (stubbed.issueActionReceipt || []).includes(id)), 'ISSUE harness binds real receipt guards');
    b.retryReceiptForAcceptedAction = bind('retryReceiptForAcceptedAction', hookCallback(variant, 'retryReceiptForAcceptedAction').text, {
      ...common, actionHashV2: P.actionHashV2, issuedActionHashesRef: refs.issuedActionHashesRef,
      isClientTimestampAllowed: R.isClientTimestampAllowed, effectiveClientNow: () => Math.floor(now.value),
      considerFutureClockWarning: () => {},
      verifyRelayInner: b.verifyRelayInner, shouldIssueReceiptForObservedAction: P.shouldIssueReceiptForObservedAction,
      observedActionsRef: refs.observedActionsRef, issueActionReceipt: b.issueActionReceipt,
    });
    b.handleIncomingAction = bind('handleIncomingAction', hookCallback(variant, 'handleIncomingAction').text, {
      ...common, ...gateBinding, receiptAdmissionIdentityRef: refs.receiptAdmissionIdentityRef, peerActivityRef: refs.peerActivityRef,
      actionVerificationQueueRef: refs.actionVerificationQueueRef, observedActionsRef: refs.observedActionsRef,
      retryReceiptForAcceptedAction: b.retryReceiptForAcceptedAction, futureMarksRef: refs.futureMarksRef,
      verifyRelayInner: b.verifyRelayInner, isClientTimestampAllowed: R.isClientTimestampAllowed,
      effectiveClientNow: () => now.value, flagOtherSession: () => {}, liveOnlyActionsRef: refs.liveOnlyActionsRef,
      ingestObservedAction: b.ingestObservedAction, setVotedUids: () => {}, issueActionReceipt: b.issueActionReceipt,
      markG3Action: () => false, setG3Version: () => {},
    });
    b.adoptVerifiedRoster = bind('adoptVerifiedRoster', hookCallback(variant, 'adoptVerifiedRoster').text, {
      rosterIdentityMatches: RV.rosterIdentityMatches, currentRosterIdentityRef: refs.currentRosterIdentityRef,
      blockNum, groupId, chainTimeline: refs.chainTimelineRef.current, clientNow: () => now.value, rosterStartCheckedRef: refs.rosterStartCheckedRef,
      verifiedRosterRef: refs.verifiedRosterRef, operatorRosterProofRef: refs.operatorRosterProofRef,
      liveRosterMatches: RV.liveRosterMatches,
      publicRosterToGameMembers: RV.publicRosterToGameMembers, setVerifiedRosterState: () => {}, setRosterVerification: () => {},
    });
    b.verifyIncomingMessage = bind('verifyIncomingMessage', hookCallback(variant, 'verifyIncomingMessage').text, {
      blockNum, groupId, uid: me, messagesRef: { get current() { return page.messages; } }, futureMarksRef: refs.futureMarksRef,
      isCanonicalSignature: P.isCanonicalSignature, isCanonicalUid: P.isCanonicalUid, isCanonicalText: P.isCanonicalText,
      isClientChatWithinLimit: R.isClientChatWithinLimit, GUEST_PINNED_RULES: CC.GUEST_PINNED_RULES,
      hasVisibleContent: CC.hasVisibleContent, isCanonicalTimestamp: P.isCanonicalTimestamp,
      selectCurrentRoster, chatSignStringV2: P.chatSignStringV2, verifyMessage: heldVerify, flagOtherSession: () => {},
    });
    b.mergeMessagesV2 = bind('mergeMessagesV2', hookCallback(variant, 'mergeMessagesV2').text, {
      getClientMsgKey: P.buildMsgKeyGetter(blockNum, groupId), canonicalComparatorV2: P.canonicalComparatorV2 });
    const setMessages = (fn) => { page.messages = typeof fn === 'function' ? fn(page.messages) : fn; };
    b.handleMessage = bind('handleMessage', hookCallback(variant, 'handleMessage').text, {
      clientNow: () => now.value, notePresenceDisplayChat: () => {}, // 表示の控えは presence 試験へ。
      ...gateBinding, verifyIncomingMessage: b.verifyIncomingMessage, setMessages, mergeMessagesV2: b.mergeMessagesV2,
      liveOnlyMessagesRef: refs.liveOnlyMessagesRef,
      uid: me, blockNum, groupId, isGameIdentityCurrent: () => true, rosterIdentityMatches: RV.rosterIdentityMatches,
      currentRosterIdentityRef: refs.currentRosterIdentityRef, verifiedRosterRef: refs.verifiedRosterRef,
      unverifiedRosterRef: refs.unverifiedRosterRef, adoptVerifiedRoster: b.adoptVerifiedRoster,
      handleIncomingAction: b.handleIncomingAction, verifyRelayInner: b.verifyRelayInner,
      g3ObservationsRef: refs.g3ObservationsRef, chatEndedRef: refs.chatEndedRef, flagOtherSession: () => {},
      markG3Action: () => false, peerActivityRef: refs.peerActivityRef,
    }, { allowStub: true });
    b.handleRelayChat = bind('handleRelayChat', hookCallback(variant, 'handleRelayChat').text, {
      clientNow: () => now.value, notePresenceDisplayChat: () => {},
      ...gateBinding,
      isGameIdentityCurrent: () => true, isClientChatWithinLimit: R.isClientChatWithinLimit, GUEST_PINNED_RULES: CC.GUEST_PINNED_RULES,
      uid: me, peerActivityRef: refs.peerActivityRef, verifyIncomingMessage: b.verifyIncomingMessage,
      liveOnlyMessagesRef: refs.liveOnlyMessagesRef, setMessages, mergeMessagesV2: b.mergeMessagesV2,
    });
    // 自動既読の回（effect の中の readReceiptTick。開始の10秒の休みは呼び手が回の時刻で表す）
    b.readReceiptTick = bind('readReceiptTick', plainDecl(variant, 'readReceiptTick').text, {
      readReceiptPauseRef: { current: null }, performance: { now: () => now.value },
      detectClockStep: CK.detectClockStep, setClockStepTick: () => {},
      readReceiptTickGap: RP.readReceiptTickGap, openReadReceiptPause: RP.openReadReceiptPause,
      readReceiptTickRunningRef: { current: false }, isAwayRef: refs.isAwayRef,
      receiptIssuanceBlocked: common.receiptIssuanceBlocked,
      sessionActivityRef: refs.sessionActivityRef, phaseRef: refs.phaseRef, rosterStartConfirmedRef: refs.rosterStartConfirmedRef,
      isGameIdentityCurrent: () => true, messagesRef: { get current() { return page.messages; } }, uid: me,
      liveOnlyMessagesRef: refs.liveOnlyMessagesRef, issuedReadMsgKeysRef: refs.issuedReadMsgKeysRef,
      msgRefOf: P.msgRefOf, computeMsgKeyV2: P.computeMsgKeyV2, blockNum, groupId, getClockCorrection: () => 0,
      coordinateSelfReadReceiptBatch: R.coordinateSelfReadReceiptBatch,
      queueReceipt: async (receipt) => { page.receiveReceipt(receipt); return true; },
      canIssueReceiptAtChainTip: async () => true, receiptsRef: refs.receiptsRef,
      nextReadReceiptTimestamp: CK.nextReadReceiptTimestamp, clientNow: () => now.value,
      clientReceiptableMessages: P.clientReceiptableMessages, chatWindowMsFromTimeline: P.chatWindowMsFromTimeline,
      chainTimelineRef: refs.chainTimelineRef, GUEST_PINNED_RULES: CC.GUEST_PINNED_RULES, canonicalComparatorV2: P.canonicalComparatorV2,
      buildMsgKeyGetter: P.buildMsgKeyGetter, getClientMsgKey: P.buildMsgKeyGetter(blockNum, groupId), verifiedRosterRef: refs.verifiedRosterRef,
      issuedReadCountBySenderRef: refs.issuedReadCountBySenderRef,
      isReceiptTimely: P.isReceiptTimely, issuingReadMsgKeysRef: refs.issuingReadMsgKeysRef, privateKeyToAccount,
      signKey: page.signKey, compareHexAsc: P.compareHexAsc, canonicalizeSignature: P.canonicalizeSignature,
      readReceiptSignString: P.readReceiptSignString, rememberOwnReadSignature: () => {},
      send: (frame) => { if (frame?.type === 'receipt') spy.published.push(frame.receipt); return true; },
      relayChannelRef: { current: null }, readReceiptChannelRef: { current: null },
    });
    page.b = b;
  };
  page.adopt = (result) => { page.b.adoptVerifiedRoster(result, []); page.render(); };
  page.startActionGrace = () => {
    const rows = walk(ASTS[variant], (node) => node.type === 'CallExpression'
      && node.callee?.name === 'useEffect' && node.arguments?.[0]?.type === 'ArrowFunctionExpression'
      && VARIANTS[variant].slice(node.start, node.end).includes('grace.timer = setTimeout(replay'));
    if (!rows.length) return;
    assert.equal(rows.length, 1, 'ISSUE grace effect exists');
    function setFakeTimeout(fn, ms) {
      assert.equal(this, undefined, 'ISSUE official timer is invoked directly');
      const timer = { fn, at: now.value + Math.trunc(ms), cancelled: false, fired: false };
      timers.push(timer); return timer;
    }
    const effect = bind('ISSUE grace effect', VARIANTS[variant].slice(rows[0].arguments[0].start, rows[0].arguments[0].end), {
      isSpectator: false, signKey: page.signKey, getActionReceiptGrace: page.b.getActionReceiptGrace,
      receiptAdmissionIdentityRef: refs.receiptAdmissionIdentityRef,
      retryReceiptForAcceptedAction: page.b.retryReceiptForAcceptedAction,
      performance: { now: () => now.value }, setTimeout: setFakeTimeout,
      clearTimeout: function (timer) {
        assert.equal(this, undefined, 'ISSUE official timer cancellation is invoked directly');
        timer.cancelled = true;
      },
    });
    page.graceCleanup?.(); page.graceCleanup = effect();
  };
  page.receiptsFor = (actorUid, type, action) => {
    const h = P.actionHashV2(type, blockNum, groupId, actorUid, action.encrypted, action.timestamp);
    return spy.receipts.filter((r) => r.actionHash === h && r.receiverUid === me).length;
  };
  page.gate = () => (page.b.actionIngestGateOpen ? page.b.actionIngestGateOpen() : null);
  page.tickAt = async (t) => {
    now.value = t; page.render();
    const before = spy.published.length;
    await page.b.readReceiptTick(); await flush();
    return spy.published.slice(before);
  };
  page.readRefsFor = (sender) => new Set(spy.published.filter((rc) => rc.senderUid === sender).flatMap((rc) => rc.msgRefs));
  page.deliverChat = async (m) => { page.b.handleMessage(chatMsg(m), () => true); await flush(); };
  page.deliverHistory = async (ms) => { page.b.handleMessage(historyMsg(ms), () => true); await flush(); };
  page.render();
  return page;
}

// ============================================================ 盤面 M: MSGBASE-01（偽の発言で B への既読の枠を埋める）
// 運営は B の行だけ運営の鍵の仮の名簿 C1 を登録し、V（と W）が C1 を持つ間（開始の100秒前）に
// 偽の B の発言を message_history（前半）と chat（後半）で配る。偽物の自称時刻は開始の60秒前から（B の本物より早い）。
// V は開始＋15秒・W は開始＋20秒に正典 C2 を採る。B は開始＋20秒に短い発言、開始＋5分から3分ごとに30件。
// 自動既読は確定の16秒後から8秒ごと（入室の10秒の休みの後の格子・c03r2 と同じ）。V と W は互いの既読を受け取る。
async function msgbase(variant, { fakeCount = 10, fakeLen = 1000, bCount = 30, bLen = 40, withW = true, route = 'split' } = {}) {
  resetObsStorage();
  const pages = [makePage(variant, V)].concat(withW ? [makePage(variant, W)] : []);
  for (const p of pages) { p.now.value = S - 60 * MIN; p.adopt(C1); }
  const fakes = [];
  for (let i = 0; i < fakeCount; i++) {
    const text = fakeLen >= 26 ? String.fromCharCode(97 + (i % 26)).repeat(fakeLen) : `f${i}`;
    fakes.push(await signChat(ACC.OP, B, text, S - 60 * SEC + i * 10));
  }
  const half = route === 'chat' ? 0 : route === 'history' ? fakes.length : Math.ceil(fakes.length / 2);
  for (const p of pages) {
    p.now.value = S - 100 * SEC;
    await p.deliverHistory(fakes.slice(0, half));
    for (const m of fakes.slice(half)) await p.deliverChat(m);
  }
  const out = { fakesInViewBeforeStart: pages.map((p) => p.messages.filter((m) => fakes.some((f) => f.signature === m.signature)).length) };
  const confirmAt = { [V]: S + 15 * SEC, [W]: S + 20 * SEC };
  const real = [await signChat(ACC.B, B, 'hi everyone', S + 20 * SEC)];
  for (let i = 0; i < bCount; i++) real.push(await signChat(ACC.B, B, `B real message ${String(i).padStart(2, '0')} `.padEnd(bLen, 'x'), S + 5 * MIN + i * 3 * MIN));
  const events = [];
  for (const p of pages) events.push({ at: confirmAt[p.me], kind: 'adopt', p });
  for (const m of real) for (const p of pages) events.push({ at: m.timestamp + 500, kind: 'deliver', p, m });
  const tickTimes = (p) => { const set = new Set(); const c = confirmAt[p.me];
    for (let k = 2; k <= 4; k++) set.add(c + k * 8 * SEC);
    for (const m of real) { const g = c + Math.max(2, Math.ceil((m.timestamp + 500 - c) / (8 * SEC))) * 8 * SEC; set.add(g); set.add(g + 8 * SEC); }
    return [...set]; };
  for (const p of pages) for (const t of tickTimes(p)) events.push({ at: t + (p.me === W ? 2 * SEC : 0), kind: 'tick', p });
  events.sort((a, b) => a.at - b.at || (a.kind === 'adopt' ? -1 : b.kind === 'adopt' ? 1 : 0));
  for (const e of events) {
    e.p.now.value = e.at;
    if (e.kind === 'adopt') e.p.adopt(C2);
    else if (e.kind === 'deliver') { e.p.render(); await e.p.deliverChat(e.m); }
    else {
      const outRc = await e.p.tickAt(e.at);
      for (const q of pages) if (q !== e.p) for (const rc of outRc) q.receiveReceipt(rc);
    }
  }
  out.afterConfirm = pages.map((p) => ({ me: p.me, gate: p.gate(), rosterStartConfirmed: p.refs.rosterStartConfirmedRef.current,
    fakesInView: p.messages.filter((m) => fakes.some((f) => f.signature === m.signature)).length,
    realInView: p.messages.filter((m) => real.some((r) => r.signature === m.signature)).length }));
  out.realTotal = real.length;
  out.readBy = Object.fromEntries(pages.map((p) => {
    const refs = p.readRefsFor(B);
    return [p.me, { real: real.filter((m) => refs.has(refOf(m))).length, fakes: fakes.filter((f) => refs.has(refOf(f))).length,
      realChars: real.filter((m) => refs.has(refOf(m))).reduce((s, m) => s + CC.countHalfWidthChars(m.text), 0) }];
  }));
  return out;
}

// ============================================================ 盤面 M-cross: 確かめ（await）を確定がまたぐ（発言）
async function msgCrossing(variant, kind) {
  const p = makePage(variant, V);
  p.now.value = S - 30 * MIN; p.adopt(C1);
  p.now.value = S + 5 * SEC; p.render(); // 開始は過ぎたが V はまだ C1
  let release; p.verifyHold = new Promise((r) => { release = r; });
  const fake = await signChat(ACC.OP, B, 'x'.repeat(1000), S - 60 * SEC);
  if (kind === 'chat') p.b.handleMessage(chatMsg(fake), () => true); else p.b.handleMessage(historyMsg([fake]), () => true);
  await flush();
  p.now.value = S + 15 * SEC; p.adopt(C2); // 確かめの途中で正典を採る
  p.verifyHold = null; release(); await flush();
  return { fakeInView: p.messages.some((m) => m.signature === fake.signature) };
}

async function actionCrossing(variant) {
  const p = makePage(variant, V);
  p.now.value = S - 30 * MIN; p.adopt(C1);
  p.now.value = S + 5 * SEC; p.render();
  let release; p.verifyHold = new Promise((resolve) => { release = resolve; });
  const fake = await signedAction(ACC.OP, 'vote', B, 701, S - 60 * SEC);
  p.b.handleIncomingAction('vote', B, fake);
  await flush();
  p.now.value = S + 15 * SEC; p.adopt(C2);
  p.verifyHold = null; release(); await flush();
  const fakeInView = !!p.refs.observedActionsRef.current.votes[B];
  p.now.value = S + 3 * MIN; p.render();
  const real = await signedAction(ACC.B, 'vote', B, 702, p.now.value);
  p.b.handleIncomingAction('vote', B, real); await flush();
  return { fakeInView, realReceipts: p.receiptsFor(B, 'vote', real) };
}

// ============================================================ 盤面 O: OBSBASE-01（CLOSE の盤面1 と同じ）
async function obsbase(variant) {
  const p = makePage(variant, V);
  p.now.value = S - 30 * MIN;
  p.adopt(C1);
  const fakeTs = p.now.value;
  const votes = {}; votes[B] = await signedAction(ACC.OP, 'vote', B, 100, fakeTs);
  votes[`${B}__extras`] = [];
  for (let i = 1; i < 10; i++) votes[`${B}__extras`].push(await signedAction(ACC.OP, 'vote', B, 100 + i, fakeTs - i));
  const reports = []; for (let i = 0; i < 9; i++) reports.push(await signedAction(ACC.OP, 'report', B, 200 + i, fakeTs - i));
  p.b.handleMessage(initMsg({ votes, reports: { [B]: reports } }), () => true);
  p.b.handleMessage(actionMade(B, 'report', await signedAction(ACC.OP, 'report', B, 299, fakeTs - 20)), () => true);
  await flush();
  const obs = p.refs.observedActionsRef.current;
  const out = { gateBefore: p.gate(), afterPoison: { voteBucket: (obs.votes[B] ? 1 : 0) + (obs.votes[`${B}__extras`]?.length || 0),
    reportBucket: obs.reports[B]?.length || 0, storageWrites: p.spy.saves.length, futureMarks: p.futureMarks.marks.size } };
  p.now.value = S + 15 * SEC; p.adopt(C2);
  out.gateAfter = p.gate();
  p.now.value = S + 5 * MIN;
  const real = await signedAction(ACC.B, 'vote', B, 7, p.now.value);
  p.b.handleMessage(actionMade(B, 'vote', real), () => true); await flush();
  out.receiptRealVote = p.receiptsFor(B, 'vote', real);
  p.b.handleIncomingAction('vote', B, real); await flush();
  out.receiptRealVoteAfterRedelivery = p.receiptsFor(B, 'vote', real);
  p.now.value = S + 30 * MIN;
  const resend = await signedAction(ACC.B, 'vote', B, 8, p.now.value);
  p.b.handleMessage(actionMade(B, 'vote', resend), () => true); await flush();
  out.receiptResend = p.receiptsFor(B, 'vote', resend);
  p.now.value = S + 40 * MIN;
  const rep = await signedAction(ACC.B, 'report', B, 9, p.now.value);
  p.b.handleMessage(actionMade(B, 'report', rep), () => true); await flush();
  out.receiptRealReport = p.receiptsFor(B, 'report', rep);
  return out;
}

// ============================================================ 盤面 L: U9-LAG（チャットの途中で開いた新しい画面）
// game.js は本人性が立つまで uid を渡さないので、最初の名簿は uid なしの読み（証明を保存しない）＝canonical でも
// rosterStartConfirmed は偽。uid が立つと WS をつなぎ、init と会話の履歴が証明つきの読み直しより先に着く。
async function midGameFreshPage(variant, { redeliver }) {
  resetObsStorage();
  const p = makePage(variant, V);
  p.now.value = S + 6 * 3600000;
  p.adopt({ ...C2, observedAtMs: p.now.value - 5000, rosterProofSaved: false });
  const bVote = await signedAction(ACC.B, 'vote', B, 21, p.now.value - 5 * MIN);
  const wReport = await signedAction(ACC.W, 'report', W, 22, p.now.value - 4 * MIN);
  const hist = [await signChat(ACC.B, B, 'earlier B (30 min ago)', p.now.value - 30 * MIN),
    await signChat(ACC.W, W, 'earlier W (20 min ago)', p.now.value - 20 * MIN),
    await signChat(ACC.B, B, 'recent B (3 min ago)', p.now.value - 3 * MIN),
    await signChat(ACC.V, V, 'my own earlier line', p.now.value - 10 * MIN)];
  const out = { source: p.selectCurrentRoster().source, anchor: p.refs.verifiedRosterRef.current.anchorStatus,
    rosterStartConfirmed: p.refs.rosterStartConfirmedRef.current, gateAtInit: p.gate() };
  p.b.handleMessage(initMsg({ votes: { [B]: bVote }, reports: { [W]: [wReport] } }), () => true);
  p.b.handleMessage(historyMsg(hist), () => true);
  await flush();
  out.observedBeforeConfirm = { bVote: !!p.refs.observedActionsRef.current.votes[B], wReport: (p.refs.observedActionsRef.current.reports[W] || []).length };
  out.historyBeforeConfirm = p.messages.length;
  p.now.value += 2000;
  p.adopt({ ...C2, observedAtMs: p.now.value - 1000, rosterProofSaved: true }); // 証明つきの読み直しが後から着く
  if (redeliver) {
    p.now.value += 3000;
    p.b.handleIncomingAction('vote', B, bVote); p.b.handleIncomingAction('report', W, wReport);
    for (const m of hist) await p.b.handleRelayChat(m);
    await flush();
  }
  out.observedAfter = { bVote: !!p.refs.observedActionsRef.current.votes[B], wReport: (p.refs.observedActionsRef.current.reports[W] || []).length };
  out.historyAfter = p.messages.length;
  out.actionReceiptsAfter = p.receiptsFor(B, 'vote', bVote) + p.receiptsFor(W, 'report', wReport);
  const rcs = await p.tickAt(p.now.value + 16 * SEC);
  out.readReceiptsFirstTick = rcs.reduce((s, rc) => s + rc.msgRefs.length, 0);
  return out;
}

// ============================================================ 盤面 H: 正直・開始直後の競走（発言）
// B の画面は開始＋3秒に確定し、開始＋4秒から発言する。V（と W）は開始＋15秒（W は16秒）に確定する。
// 確定前に WS で届いた B の発言を、案 (i) は門で捨てる。届き直し: 'relay'（確定の3秒後にリレーの履歴）・
// 'ws'（確定の2分後に WS の張り直しの message_history）・'none'（Nostr が全部落ちていて WS も切れない）。
async function startRace(variant, { redeliver = 'none', burst = 1, vConfirm = 15 * SEC, wConfirm = 16 * SEC, wEarly = false } = {}) {
  resetObsStorage();
  const pages = [makePage(variant, V), makePage(variant, W)];
  for (const p of pages) { p.now.value = S - 30 * MIN; p.adopt(C2p); }
  const early = [];
  for (let i = 0; i < burst; i++) early.push(await signChat(ACC.B, B, `hi at start ${i}`, S + 4 * SEC + i * 2 * SEC));
  const later = await signChat(ACC.B, B, 'later message after everyone confirmed', S + 3 * MIN);
  const confirmAt = { [V]: vConfirm, [W]: wEarly ? 2 * SEC : wConfirm };
  const out = { lagView: {} };
  for (const p of pages) {
    for (const m of early) {
      p.now.value = m.timestamp + 500;
      if (p.now.value >= S + confirmAt[p.me]) { if (!p.refs.verifiedRosterRef.current || p.refs.verifiedRosterRef.current.anchorStatus !== 'canonical') p.adopt(C2); }
      else p.render();
      await p.deliverChat(m);
    }
    out.lagView[p.me] = { gate: p.gate(), inView: p.messages.length };
    p.now.value = Math.max(p.now.value, S + confirmAt[p.me]);
    if (p.refs.verifiedRosterRef.current.anchorStatus !== 'canonical') p.adopt(C2);
    if (redeliver === 'relay') { p.now.value += 3 * SEC; for (const m of early) await p.b.handleRelayChat(m); await flush(); }
  }
  for (const p of pages) {
    const c = S + confirmAt[p.me];
    for (let k = 2; k <= 4; k++) await p.tickAt(c + k * 8 * SEC);
    if (redeliver === 'ws') { p.now.value = c + 2 * MIN; await p.deliverHistory(early); await p.tickAt(c + 2 * MIN + 8 * SEC); }
    p.now.value = later.timestamp + 500; await p.deliverChat(later); await p.tickAt(later.timestamp + 8 * SEC);
  }
  out.readBy = Object.fromEntries(pages.map((p) => { const refs = p.readRefsFor(B);
    return [p.me, { early: early.filter((m) => refs.has(refOf(m))).length, later: refs.has(refOf(later)) ? 1 : 0 }]; }));
  // 採点の見方: 送り手以外の誰かの既読が1枚でもあれば、その発言は数えられる
  out.earlyCounted = early.filter((m) => pages.some((p) => p.readRefsFor(B).has(refOf(m)))).length;
  out.earlyTotal = early.length;
  return out;
}

// ============================================================ CLOSE から移した盤面（行動・正直・遅れ・未来）
async function honest(variant) {
  resetObsStorage();
  const p = makePage(variant, V);
  p.now.value = S - 30 * MIN; p.adopt(C2p);
  p.b.handleMessage(initMsg({ votes: {}, reports: {} }), () => true);
  p.now.value = S + 15 * SEC; p.adopt(C2);
  const out = {};
  p.now.value = S + 5 * MIN;
  const real = await signedAction(ACC.B, 'vote', B, 7, p.now.value);
  p.b.handleMessage(actionMade(B, 'vote', real), () => true); await flush();
  out.receiptRealVote = p.receiptsFor(B, 'vote', real);
  p.now.value = S + 30 * MIN;
  const resend = await signedAction(ACC.B, 'vote', B, 8, p.now.value);
  p.b.handleMessage(actionMade(B, 'vote', resend), () => true); await flush();
  out.receiptResend = p.receiptsFor(B, 'vote', resend);
  p.now.value = S + 40 * MIN;
  const rep = await signedAction(ACC.B, 'report', B, 9, p.now.value);
  p.b.handleMessage(actionMade(B, 'report', rep), () => true); await flush();
  out.receiptRealReport = p.receiptsFor(B, 'report', rep);
  p.now.value = S + 50 * MIN;
  const wv = await signedAction(ACC.W, 'vote', W, 11, p.now.value);
  p.b.handleMessage(actionMade(W, 'vote', wv), () => true); await flush();
  out.receiptW = p.receiptsFor(W, 'vote', wv);
  // 発言（確定の後）
  const bm = await signChat(ACC.B, B, 'honest chat after confirm', S + 51 * MIN);
  p.now.value = bm.timestamp + 500; await p.deliverChat(bm);
  const rc = await p.tickAt(bm.timestamp + 8 * SEC);
  out.readHonestChat = rc.some((r) => r.msgRefs.includes(refOf(bm)));
  const obs = p.refs.observedActionsRef.current;
  out.observed = { firstVoteB: obs.votes[B]?.encrypted === real.encrypted, extrasB: obs.votes[`${B}__extras`]?.length || 0,
    reportsB: obs.reports[B]?.length || 0, firstVoteW: obs.votes[W]?.encrypted === wv.encrypted };
  out.totalActionReceipts = p.spy.receipts.length;
  return out;
}
async function lag(variant, { redeliver }) {
  const p = makePage(variant, V);
  p.now.value = S - 30 * MIN; p.adopt(C2p);
  p.now.value = S + 5 * SEC; p.render();
  const real = await signedAction(ACC.B, 'vote', B, 7, S + 4 * SEC);
  p.b.handleMessage(actionMade(B, 'vote', real), () => true); await flush();
  const out = { inLagObserved: !!p.refs.observedActionsRef.current.votes[B], inLagGate: p.gate() };
  p.now.value = S + 20 * SEC; p.adopt(C2);
  if (redeliver) { p.now.value = S + 25 * SEC; p.b.handleIncomingAction('vote', B, real); await flush(); }
  out.afterObserved = !!p.refs.observedActionsRef.current.votes[B];
  out.afterReceipts = p.receiptsFor(B, 'vote', real);
  return out;
}
async function futureLag(variant) {
  const p = makePage(variant, V);
  p.now.value = S - 30 * MIN; p.adopt(C2p);
  p.now.value = S + 5 * SEC; p.render();
  const wv = await signedAction(ACC.W, 'vote', W, 12, S + 5 * SEC + 3 * MIN);
  p.b.handleMessage(actionMade(W, 'vote', wv), () => true);
  const wm = await signChat(ACC.W, W, 'future chat from a fast clock', S + 5 * SEC + 3 * MIN);
  p.b.handleMessage(chatMsg(wm), () => true);
  const wh = await signChat(ACC.W, W, 'future history from a fast clock', S + 5 * SEC + 3 * MIN);
  p.b.handleMessage(historyMsg([wh]), () => true);
  await flush();
  const out = { marksAfterLagArrival: p.futureMarks.marks.size };
  p.now.value = S + 20 * SEC; p.adopt(C2);
  p.now.value = S + 70 * SEC;
  p.b.handleIncomingAction('vote', W, wv); await p.b.handleRelayChat(wm); await p.b.handleRelayChat(wh); await flush();
  out.observedAfterRedelivery = !!p.refs.observedActionsRef.current.votes[W];
  out.receiptsAfterRedelivery = p.receiptsFor(W, 'vote', wv);
  out.chatInViewAfterRedelivery = [wm, wh].every((message) => p.messages.some((m) => m.signature === message.signature));
  return out;
}
async function directIngestWhileClosed(variant) {
  const p = makePage(variant, V);
  p.now.value = S - 30 * MIN; p.adopt(C1);
  const fake = await signedAction(ACC.OP, 'vote', B, 400, p.now.value);
  p.b.ingestObservedAction('vote', B, fake);
  return { ingestedWhileClosed: !!p.refs.observedActionsRef.current.votes[B], saves: p.spy.saves.length };
}

// ============================================================ 盤面 G: 述語の真理表
function gateTable(variant) {
  const p = makePage(variant, V);
  const set = (rec, timeline = chainTimeline, rsc = null) => {
    p.refs.verifiedRosterRef.current = rec; p.refs.chainTimelineRef.current = timeline;
    p.refs.rosterStartConfirmedRef.current = rsc ?? (!!rec && Function('rosterIdentityMatches', 'verifiedRosterState', 'blockNum', 'groupId', 'chainTimeline',
      `'use strict'; return (${plainDecl(variant, 'rosterStartConfirmed').text});`)(RV.rosterIdentityMatches, rec, blockNum, groupId, timeline));
    p.render(); return p.gate();
  };
  const base = { ...C2, members: gameMembers(canonicalPublic) };
  const legacyAfter = { ...base, anchorStatus: 'legacy', observedAtMs: S + 30 * SEC };
  return {
    none: set(null),
    provisional: set({ ...C1, members: gameMembers(fakePublic) }),
    canonicalWithProof: set(base),
    canonicalNoProof: set({ ...base, rosterProofSaved: false }),
    canonicalStartMismatch: set(base, { ...chainTimeline, chattingStart: S + 10 * MIN }),
    canonicalNoTimeline: set(base, null),
    canonicalObservedBeforeStart: set({ ...base, observedAtMs: S - SEC }),
    canonicalOtherGroup: set({ ...base, groupId: groupId + 1 }),
    legacyBeforeStart: set({ ...legacyAfter, observedAtMs: S - 10 * SEC }),
    legacyAfterStart: set(legacyAfter),
    legacyAfterStartNoProof: set({ ...legacyAfter, rosterProofSaved: false }),
    legacyNullStart: set({ ...legacyAfter, chattingStartMs: null }, null),
    noneAnchor: set({ ...base, anchorStatus: 'none' }),
  };
}

if (process.env.OBS_HONEST_ONLY === '1') {
  console.log('OBS-HONEST-COMPARISON ' + JSON.stringify(await honest('current')));
  process.exit(0);
}
const observed = await obsbase('current');
assert.deepEqual(observed.afterPoison, { voteBucket: 0, reportBucket: 0, storageWrites: 0, futureMarks: 0 },
  'OBSBASE: provisional signed poison consumes no observation, storage, or future mark');
assert.deepEqual([observed.receiptRealVote, observed.receiptRealVoteAfterRedelivery,
  observed.receiptResend, observed.receiptRealReport], [1, 1, 1, 1],
  'OBSBASE: real vote, redelivery, resend, and report each receive one receipt');

if (process.env.T1F_ISSUE_ONLY !== '1') {
const control = await msgbase('current', { fakeCount: 0 });
const long = await msgbase('current');
const short = await msgbase('current', { fakeCount: 100, fakeLen: 2 });
for (const result of [long, short]) {
  assert.deepEqual(result.fakesInViewBeforeStart, [0, 0], 'MSGBASE: poison not in either view');
  assert.deepEqual(result.readBy, control.readBy, 'MSGBASE: V and W read the same real messages as clean screens');
  assert.equal(result.readBy[V].real, 31, 'MSGBASE: V reads all 31 real messages');
  assert.equal(result.readBy[W].real, 31, 'MSGBASE: W reads all 31 real messages');
}
for (const route of ['chat', 'history']) {
  const result = await msgbase('current', { route });
  assert.equal(result.readBy[V].real, 31, `MSGBASE ${route}: route gate preserves all real reads`);
  assert.equal(result.readBy[V].fakes, 0, `MSGBASE ${route}: route gate excludes fake reads`);
  const crossed = await msgCrossing('current', route);
  assert.equal(crossed.fakeInView, false, `MSGBASE ${route}: confirm during signature await excludes fake`);
}
assert.deepEqual(await actionCrossing('current'), { fakeInView: false, realReceipts: 1 },
  'OBS-CROSS: action verified across canonical adoption cannot poison later real vote');

const midGame = await midGameFreshPage('current', { redeliver: false });
assert.equal(midGame.rosterStartConfirmed, false, 'OBS-LAG: own proof has not been saved');
assert.equal(midGame.gateAtInit, true, 'OBS-LAG: canonical roster already opens ingest gate');
assert.deepEqual(midGame.observedBeforeConfirm, { bVote: true, wReport: 1 },
  'OBS-LAG: init actions taken before own proof is saved');
assert.equal(midGame.historyBeforeConfirm, 4, 'OBS-LAG: history taken before own proof is saved');
const honestResult = await honest('current');
assert.equal(honestResult.totalActionReceipts, 4, 'OBS-HONEST: four action receipts');
assert.equal(honestResult.readHonestChat, true, 'OBS-HONEST: real chat receives read receipt');
assert.deepEqual(honestResult.observed, { firstVoteB: true, extrasB: 1, reportsB: 1, firstVoteW: true },
  'OBS-HONEST: canonical observed actions retained');
const noRedelivery = await startRace('current', { redeliver: 'none' });
const relayRedelivery = await startRace('current', { redeliver: 'relay' });
assert.equal(noRedelivery.earlyCounted, 0, 'OBS-RACE: loss confined to sender/receiver confirmation gap');
assert.equal(relayRedelivery.earlyCounted, 1, 'OBS-RACE: relay redelivery restores early real chat');
assert.equal(noRedelivery.readBy[V].later, 1, 'OBS-RACE: post confirmation chat is read');
const future = await futureLag('current');
assert.equal(future.marksAfterLagArrival, 0, 'OBS-FUTURE: no future mark before gate opens');
assert.equal(future.receiptsAfterRedelivery, 1, 'OBS-FUTURE: redelivered action is receipted');
assert.equal(future.chatInViewAfterRedelivery, true, 'OBS-FUTURE: redelivered chat is shown');
const direct = await directIngestWhileClosed('current');
assert.deepEqual(direct, { ingestedWhileClosed: false, saves: 0 },
  'OBS-DIRECT: direct ingest before gate cannot persist');

// The relay chat path must remain open because the relay does not replay an already processed id.
const relayScreen = makePage('current', V);
relayScreen.now.value = S - 30 * MIN; relayScreen.adopt(C1);
const relayFake = await signChat(ACC.OP, B, 'relay path stays unchanged', S - 30 * MIN);
await relayScreen.b.handleRelayChat(relayFake);
await flush();
assert.equal(relayScreen.messages.some((m) => m.signature === relayFake.signature), true,
  'OBS-RELAY: relay chat remains outside the new gate');

// The gate also applies to an action_made from the viewer's own uid on another tab.
const ownScreen = makePage('current', B);
ownScreen.now.value = S - 30 * MIN; ownScreen.adopt(C1);
const fakeOwnVote = await signedAction(ACC.OP, 'vote', B, 500, S - 30 * MIN);
ownScreen.b.handleIncomingAction('vote', B, fakeOwnVote);
await flush();
assert.equal(ownScreen.refs.observedActionsRef.current.votes[B], undefined,
  'OBS-OWN: action_made from own uid is gated before canonical roster');
assert.equal(ownScreen.spy.verifyCalls, 0,
  'OBS-OWN: action_made from own uid is not verified before canonical roster');

// Existing saved observations and own actions return on reload even while the new ingest gate is closed.
const restoreScreen = makePage('current', V);
restoreScreen.now.value = S - 30 * MIN; restoreScreen.adopt(C1);
const savedVote = await signedAction(ACC.B, 'vote', B, 801, S + 10 * MIN);
const savedOwn = await signedAction(ACC.V, 'vote', V, 802, S + 10 * MIN);
const savedOwnReport = await signedAction(ACC.V, 'report', V, 803, S + 10 * MIN);
const saved = { votes: { [B]: savedVote }, reports: {} };
const effectRows = walk(ASTS.current, (node) => node.type === 'CallExpression'
  && node.callee?.name === 'useEffect' && node.arguments?.[0]?.type === 'ArrowFunctionExpression'
  && selectedHook.slice(node.start, node.end).includes('loadJson(OBSERVED_ACTIONS_KEY'));
assert.equal(effectRows.length, 1, 'OBS-RESTORE: original restore effect exists');
const mergeRows = walk(ASTS.current, (node) => node.type === 'FunctionDeclaration'
  && node.id?.name === 'mergeObservedActions');
assert.equal(mergeRows.length, 1, 'OBS-RESTORE: original observation merger exists');
const mergeObservedActions = Function('MAX_OBSERVED_ACTIONS_PER_ACTOR',
  `return (${selectedHook.slice(mergeRows[0].start, mergeRows[0].end)});`)(P.MAX_OBSERVED_ACTIONS_PER_ACTOR);
let restoredOwn = null, restoredOwnReports = [], restoredObserved = null;
const restoreScope = {
  blockNum, groupId, uid: V, isSpectator: false, runStartMs: () => 0,
  SELF_VOTE_KEY: () => 'self-vote', SELF_REPORTS_KEY: () => 'self-reports',
  ACTION_INTENT_KEY: () => 'intent', isStaleTs: () => false,
  removeKey: () => {}, saveJson: () => true, warnActionPersistenceFailure: () => {},
  OBSERVED_ACTIONS_KEY: () => 'observed-actions',
  loadJson: (key, fallback) => key === 'observed-actions' ? saved
    : key === 'self-vote' ? savedOwn : key === 'self-reports' ? [savedOwnReport] : fallback,
  setMyVote: (fn) => { restoredOwn = fn(null); },
  setVotedUids: () => {}, setMyReports: (fn) => { restoredOwnReports = fn([]); },
  g3ObservationsRef: { current: { actions: new Map(), historicReports: new Set() } },
  g3SavedReportsRef: { current: { identity: null, reports: [] } },
  observedActionsRef: { current: { votes: {}, reports: {} } },
  mergeObservedActions, setObservedActions: (value) => { restoredObserved = value; },
  actionIngestGateOpen: restoreScreen.b.actionIngestGateOpen,
};
const restoreEffect = bind('OBS-RESTORE effect',
  selectedHook.slice(effectRows[0].arguments[0].start, effectRows[0].arguments[0].end), restoreScope);
restoreEffect();
assert.equal(restoredOwn?.signature, savedOwn.signature, 'OBS-RESTORE: own vote remains outside gate');
assert.equal(restoredOwnReports[0]?.signature, savedOwnReport.signature,
  'OBS-RESTORE: own reports remain outside gate');
assert.equal(restoredObserved?.votes?.[B]?.signature, savedVote.signature,
  'OBS-RESTORE: previously saved other vote returns before gate opens');

// R2-A uses the actual game.js count expressions and ChatPhase's cap comparison.
const gameSource = readFileSync(new URL('../../src/pages/game.js', import.meta.url), 'utf8');
const gameAst = parse(gameSource, PARSE_OPTS);
const countBy = (name, messages) => {
  const rows = walk(gameAst, (node) => node.type === 'VariableDeclarator' && node.id?.name === name);
  assert.equal(rows.length, 1, `R2-A ${name} expression exists`);
  const expr = gameSource.slice(rows[0].init.start, rows[0].init.end);
  return Function('useMemo', 'effectiveMessages', 'countHalfWidthChars', `return (${expr});`)(
    (fn) => fn(), messages, CC.countHalfWidthChars);
};
for (const [label, count, length, route] of [['short', 100, 2, 'chat'], ['long', 10, 1000, 'history']]) {
  const page = makePage('current', B);
  page.now.value = S - 30 * MIN; page.adopt(C1);
  const fakes = await Promise.all(Array.from({ length: count }, (_, i) =>
    signChat(ACC.OP, B, String.fromCharCode(97 + i % 26).repeat(length), S - 20 * MIN + i)));
  if (route === 'history') await page.deliverHistory(fakes);
  else for (const fake of fakes) await page.deliverChat(fake);
  page.now.value = S + 20 * SEC; page.adopt(C2);
  const messageCounts = countBy('effectiveMessageCounts', page.messages);
  const charCounts = countBy('effectiveCharCounts', page.messages);
  assert.equal(messageCounts[B] || 0, 0, `R2-A ${label}: no fake message count`);
  assert.equal(charCounts[B] || 0, 0, `R2-A ${label}: no fake char count`);
  assert.ok((messageCounts[B] || 0) + 1 <= CC.GUEST_PINNED_RULES.maxMessages,
    `R2-A ${label}: ChatPhase message cap permits send`);
  assert.ok((charCounts[B] || 0) + 2 <= CC.GUEST_PINNED_RULES.maxChars,
    `R2-A ${label}: ChatPhase char cap permits send`);
}

// AST checks ignore comments and keep the gate before extraction and before every ingress effect.
const callbackNode = (name) => {
  const rows = walk(ASTS.current, (node) => node.type === 'VariableDeclarator' && node.id?.name === name
    && node.init?.callee?.name === 'useCallback');
  assert.equal(rows.length, 1, `OBS-AST ${name} callback exists`);
  return rows[0];
};
const gateNode = callbackNode('actionIngestGateOpen');
const ingestNode = callbackNode('ingestObservedAction');
const incomingNode = callbackNode('handleIncomingAction');
const messageNode = callbackNode('handleMessage');
assert.ok(gateNode.start < ingestNode.start, 'OBS-AST gate declared before ingest');
assert.deepEqual(freeIds(hookCallback('current', 'actionIngestGateOpen').text),
  ['Number', 'blockNum', 'chainTimelineRef', 'groupId', 'rosterIdentityMatches', 'verifiedRosterRef'],
  'OBS-AST gate reads only roster and chain refs');
assert.equal(walk(gateNode.init.arguments[0], (node) => node.type === 'MemberExpression'
  && node.property?.name === 'rosterProofSaved').length, 0, 'OBS-AST own proof is not required');
for (const node of [ingestNode, incomingNode, messageNode]) {
  assert.ok(node.init.arguments[1].elements.some((el) => el?.name === 'actionIngestGateOpen'),
    `OBS-AST ${node.id.name} deps include gate`);
}
assert.deepEqual(gateNode.init.arguments[1].elements.map((el) => el.name), ['blockNum', 'groupId'],
  'OBS-AST gate deps are block and group');
const isGateIf = (stmt, mode) => stmt?.type === 'IfStatement'
  && stmt.test?.type === 'UnaryExpression' && stmt.test.argument?.callee?.name === 'actionIngestGateOpen'
  && stmt.consequent?.type === mode;
assert.ok(isGateIf(ingestNode.init.arguments[0].body.body[1], 'ReturnStatement'),
  'OBS-AST ingest gate follows identity check');
const incomingStatements = incomingNode.init.arguments[0].body.body;
const incomingGateAt = incomingStatements.findIndex((stmt) => isGateIf(stmt, 'ReturnStatement'));
const queueAt = incomingStatements.findIndex((stmt) => stmt.type === 'VariableDeclaration'
  && stmt.declarations.some((decl) => decl.id?.name === 'queue'));
assert.ok(incomingGateAt >= 0 && incomingGateAt < queueAt,
  'OBS-AST action gate precedes verification queue and future handling');
for (const name of ['futureMarksRef', 'verifyRelayInner']) {
  const uses = walk(incomingNode.init.arguments[0].body, (node) => node.type === 'Identifier' && node.name === name);
  assert.ok(uses.length > 0 && uses.every((node) => node.start > incomingStatements[incomingGateAt].end),
    `OBS-AST action gate precedes ${name}`);
}
for (const caseName of ['message_history', 'chat']) {
  const rows = walk(messageNode.init.arguments[0], (node) => node.type === 'SwitchCase'
    && node.test?.value === caseName);
  assert.equal(rows.length, 1, `OBS-AST ${caseName} case exists`);
  assert.ok(isGateIf(rows[0].consequent[0].body[0], 'BreakStatement'),
    `OBS-AST ${caseName} first statement gates before await`);
}
}
// ===== ISSUE（S3R5-U-R12-FIX）: the real hook callbacks and effects =====
{
  const { ActionReceiptDuplicateWarnings } = await import('../../src/utils/receipt-warnings.js');
  const key = `observedReceipts_${blockNum}_group${groupId}_user${V}`;
  const own = (action, actorUid = B, type = 'vote') => ({ receiverUid: V,
    actionHash: P.actionHashV2(type, blockNum, groupId, actorUid, action.encrypted, action.timestamp),
    timestamp: action.timestamp + 3000, signature: `receipt-${action.signature}` });
  const open = (at, { restore = false } = {}) => {
    const page = makePage('current', V, { liveGrace: true, openedAt: at });
    page.now.value = at;
    if (restore) page.restoreReceipts();
    page.adopt(C2);
    page.startActionGrace();
    return page;
  };
  const deliver = async (page, actorUid, type, action) => {
    page.b.handleMessage(actionMade(actorUid, type, action), () => true);
    await flush();
  };
  const vote = await signedAction(ACC.B, 'vote', B, 910, S + 5 * MIN);
  // ISSUE-1: four remounts share only local storage, as in a 4001/reload loop.
  resetObsStorage();
  const receipts = [];
  let first = open(S + 5 * MIN);
  first.now.value += 10 * SEC; await first.fireTimers();
  await deliver(first, B, 'vote', vote);
  receipts.push(...first.spy.receipts);
  assert.equal(receipts.length, 1, 'ISSUE-1 initial receipt');
  globalThis.localStorage.setItem(key, JSON.stringify({ [receipts[0].signature]: receipts[0] }));
  for (let i = 0; i < 4; i++) {
    const page = open(S + 5 * MIN + (i + 1) * 60 * SEC, { restore: true });
    assert(page.refs.issuedActionHashesRef.current.has(own(vote).actionHash), 'ISSUE-1 synchronous restore mark');
    await deliver(page, B, 'vote', vote);
    page.now.value += 10 * SEC; await page.fireTimers();
    await deliver(page, B, 'vote', vote);
    receipts.push(...page.spy.receipts);
  }
  assert.equal(receipts.length, 1, 'ISSUE-1 five loads keep one own receipt');
  const watcher = new ActionReceiptDuplicateWarnings(W);
  assert(receipts.every((receipt) => !watcher.observe(receipt, R.receiptIdentityDigest(receipt))),
    'ISSUE-1 no duplicate warning');
  assert(!watcher.attackedIssuers().includes(V), 'ISSUE-1 V absent from duplicate warning');

  // ISSUE-2: a verified relay arrival during the pause wins; a later one does not.
  resetObsStorage();
  const relayPage = open(S + 6 * MIN);
  const relayReceipt = own(vote);
  relayPage.now.value += 500; await deliver(relayPage, B, 'vote', vote);
  assert.equal(relayPage.spy.receipts.length, 0, 'ISSUE-2 no signature during grace');
  relayPage.refs.receiptAdmissionRef.current.getAcceptedReceipts = () => [relayReceipt];
  relayPage.now.value += 10_500; await relayPage.fireTimers();
  await deliver(relayPage, B, 'vote', vote);
  assert.equal(relayPage.spy.receipts.length, 0, 'ISSUE-2 accepted own receipt blocks issue');
  const latePage = open(S + 6 * MIN);
  latePage.now.value += 11 * SEC; await latePage.fireTimers();
  await deliver(latePage, B, 'vote', vote);
  latePage.refs.receiptAdmissionRef.current.getAcceptedReceipts = () => [relayReceipt];
  assert.equal(latePage.spy.receipts.length, 1, 'ISSUE-2 history later than grace permits one');
  console.log('ISSUE-2 known limit: relay history after ten seconds permits one per load');

  // ISSUE-3: first delivery after grace and a triple delivery during grace both issue once.
  resetObsStorage();
  const report = await signedAction(ACC.W, 'report', W, 911, S + 8 * MIN);
  const immediate = open(S + 8 * MIN);
  immediate.refs.relayChannelRef.current = { publishReceipt: (receipt) => {
    immediate.spy.actionEvents.push(['publishReceipt', receipt]);
  } };
  immediate.now.value += 10 * SEC; await immediate.fireTimers();
  await deliver(immediate, B, 'vote', vote); await deliver(immediate, W, 'report', report);
  assert.equal(immediate.spy.receipts.length, 2, 'ISSUE-3 first vote and report after grace');
  assert.deepEqual(immediate.spy.actionEvents.map(([event]) => event),
    ['send', 'publishReceipt', 'queueReceipt', 'send', 'publishReceipt', 'queueReceipt'],
    'ISSUE-3 publishing order remains unchanged');
  for (let i = 0; i < immediate.spy.actionEvents.length; i += 3) {
    assert.deepEqual(immediate.spy.actionEvents[i][1], immediate.spy.actionEvents[i + 1][1]);
    assert.deepEqual(immediate.spy.actionEvents[i][1], immediate.spy.actionEvents[i + 2][1]);
  }
  const held = open(S + 8 * MIN + 500);
  for (let i = 0; i < 3; i++) {
    await deliver(held, B, 'vote', vote); await deliver(held, W, 'report', report);
  }
  held.now.value += 9999;
  assert.equal(held.spy.receipts.length, 0, 'ISSUE-3 nothing before deadline');
  held.now.value += 1; await held.fireTimers();
  assert.equal(held.spy.receipts.length, 2, 'ISSUE-3 replay emits one per action');
  await deliver(held, B, 'vote', vote); await deliver(held, W, 'report', report);
  assert.equal(held.spy.receipts.length, 2, 'ISSUE-3 redelivery does not increase count');
  const blocked = open(S + 8 * MIN);
  await deliver(blocked, B, 'vote', vote);
  blocked.refs.isAwayRef.current = true;
  blocked.now.value += 10 * SEC; await blocked.fireTimers();
  assert.equal(blocked.spy.receipts.length, 0, 'ISSUE-3 replay still obeys away gate');
  const early = makePage('current', V, { liveGrace: true, openedAt: S + 8 * MIN });
  early.now.value = S + 8 * MIN; early.adopt(C2);
  await deliver(early, B, 'vote', vote); await deliver(early, W, 'report', report);
  assert.equal(early.refs.actionReceiptGraceRef.current?.deferred.size, 2,
    'ISSUE-3 two distinct actions deferred before fractional timer');
  early.now.value += 0.5; early.startActionGrace();
  early.now.value += 9999; await early.fireTimers(); await flush(); await flush();
  assert.equal(early.spy.receipts.length, 2, 'ISSUE-3 fractional timer replay does not defer again');

  // ISSUE-4: grace starts at roster confirmation, twenty seconds after mount.
  const slow = makePage('current', V, { liveGrace: true, openedAt: S });
  slow.now.value = S + 20 * SEC; slow.adopt(C2); slow.startActionGrace();
  assert.equal(slow.refs.actionReceiptGraceRef.current?.until, S + 30 * SEC,
    'ISSUE-4 ten seconds from roster confirmation');
  const slowVote = await signedAction(ACC.B, 'vote', B, 912, S + 21 * SEC);
  slow.now.value = S + 25 * SEC; await deliver(slow, B, 'vote', slowVote);
  assert.equal(slow.spy.receipts.length, 0, 'ISSUE-4 fifth second held');
  slow.now.value = S + 30 * SEC; await slow.fireTimers();
  assert.equal(slow.spy.receipts.length, 1, 'ISSUE-4 deadline releases issue');

  // ISSUE-5: a second tab's disk write and accepted queue are checked immediately before signing.
  const disk = open(S + 7 * MIN);
  disk.now.value += 10 * SEC; await disk.fireTimers();
  globalThis.localStorage.setItem(key, JSON.stringify({ x: own(vote) }));
  await disk.b.issueActionReceipt(B, 'vote', vote);
  assert.equal(disk.spy.receipts.length, 0, 'ISSUE-5 late disk write blocks');
  assert(disk.refs.issuedActionHashesRef.current.has(own(vote).actionHash));
  resetObsStorage();
  const queue = open(S + 7 * MIN);
  queue.now.value += 10 * SEC; await queue.fireTimers();
  const actionHash = own(vote).actionHash;
  const acceptedReceipt = { ...own(vote), signature: P.canonicalizeSignature(await ACC.V.signMessage({
    message: P.receiptSignString(blockNum, groupId, V, actionHash, vote.timestamp + 3000) })) };
  const acceptedQueue = new R.ReceiptAdmissionQueue({
    getRosterUids: () => [V, B, W], isRosterVerified: () => true,
    verifyReceipt: (receipt) => queue.b.verifyRelayInner('receipt', receipt),
    resolveReceipt: () => ({ state: 'covered' }),
    getChatWindow: () => P.chatWindowMsFromTimeline(chainTimeline),
    getChatCloseAtMs: () => chainTimeline.chatCloseAt,
    now: () => queue.now.value,
  });
  await acceptedQueue.offer(acceptedReceipt);
  assert.equal(acceptedQueue.getAcceptedReceipts().length, 1, 'ISSUE-5 real queue accepts verified receipt');
  queue.refs.receiptAdmissionRef.current = acceptedQueue;
  await queue.b.issueActionReceipt(B, 'vote', vote);
  assert.equal(queue.spy.receipts.length, 0, 'ISSUE-5 accepted receipt blocks');
  const pending = open(S + 7 * MIN);
  pending.now.value += 10 * SEC; await pending.fireTimers();
  const pendingQueue = new R.ReceiptAdmissionQueue({
    getRosterUids: () => [V, B, W], isRosterVerified: () => true,
    verifyReceipt: (receipt) => pending.b.verifyRelayInner('receipt', receipt),
    resolveReceipt: () => ({ state: 'covered' }),
    getChatWindow: () => null, requireConfirmedWindow: true, now: () => pending.now.value,
  });
  await pendingQueue.offer({ ...acceptedReceipt, signature: P.canonicalizeSignature(await ACC.OP.signMessage({
    message: P.receiptSignString(blockNum, groupId, V, actionHash, vote.timestamp + 3000) })) });
  assert.equal(pendingQueue.getPendingReceipts().length, 1, 'ISSUE-5 real queue retains unverified fake as pending');
  pending.refs.receiptAdmissionRef.current = pendingQueue;
  await pending.b.issueActionReceipt(B, 'vote', vote);
  assert.equal(pending.spy.receipts.length, 1, 'ISSUE-5 pending false receipt cannot block');
  acceptedQueue.dispose(); pendingQueue.dispose();
  for (const value of ['not-json', '[]', '[null]', '"text"']) {
    resetObsStorage(); globalThis.localStorage.setItem(key, value);
    const valid = open(S + 7 * MIN); valid.now.value += 10 * SEC; await valid.fireTimers();
    await valid.b.issueActionReceipt(B, 'vote', vote);
    assert.equal(valid.spy.receipts.length, 1, `ISSUE-5 malformed store ${value} cannot block`);
  }
  resetObsStorage(); globalThis.localStorage.setItem(key, JSON.stringify({
    other: { ...own(vote), receiverUid: W },
    otherAction: own(report, W, 'report'),
    read: { ...own(vote), msgRefs: [] },
  }));
  const different = open(S + 7 * MIN); different.now.value += 10 * SEC; await different.fireTimers();
  await different.b.issueActionReceipt(B, 'vote', vote);
  assert.equal(different.spy.receipts.length, 1, 'ISSUE-5 other uid and read receipt cannot block');

  // ISSUE-6: an old owner timer cannot replay on a new identity.
  const switched = open(S + 8 * MIN);
  await deliver(switched, B, 'vote', vote);
  switched.refs.receiptAdmissionIdentityRef.current = { blockNum, groupId, uid: V };
  switched.now.value += 10 * SEC; await switched.fireTimers();
  assert.equal(switched.spy.receipts.length, 0, 'ISSUE-6 old timer belongs only to old owner');
  switched.startActionGrace();
  assert.equal(switched.refs.actionReceiptGraceRef.current?.until, S + 8 * MIN + 20 * SEC,
    'ISSUE-6 new owner receives its own ten seconds');

  // ISSUE-7: execute the recovery source's restore, grace, issue, observation and merge bodies.
  const extractRecovery = (start, end) => {
    const a = app.indexOf(start); const b = app.indexOf(end, a + start.length);
    assert(a >= 0 && b > a, `ISSUE-7 recovery source ${start}`);
    return app.slice(a, b);
  };
  const restoreSource = extractRecovery('  for (const receipt of state.relay.getReceipts()) {',
    '  if (!canStartRecoveryP2P(myMember)) {');
  const graceSource = extractRecovery('  const actionReceiptGraceToken = {};',
    '  await state.relay.verifyRestoredReports?.();');
  const recoveryIssue = extractRecovery('async function issueActionReceipt(actorUid, actionType, action) {',
    '\n// 既読受領証明の自動バッチ発行');
  const recoveryPrecheck = extractRecovery('function hasOwnActionReceipt(actionHash) {',
    '\n// action受領証明の発行');
  const recoveryHandle = extractRecovery('function handleObservedActions(raw) {',
    '\n// ============================================================\n// v3.3追補: 在席');
  const recoveryMerge = extractRecovery('function mergeReceipts(list) {',
    '\nasync function importOfficialLocalStorage()');
  const recoveryKey = `recoveryReceiptArrivals_${blockNum}_group${groupId}_user${V}`;
  const realOwn = async (action, actorUid = B, type = 'vote') => {
    const hash = P.actionHashV2(type, blockNum, groupId, actorUid, action.encrypted, action.timestamp);
    const timestamp = action.timestamp + 3000;
    return { receiverUid: V, actionHash: hash, timestamp,
      signature: P.canonicalizeSignature(await ACC.V.signMessage({
        message: P.receiptSignString(blockNum, groupId, V, hash, timestamp) })) };
  };
  const recoveredReceipt = await realOwn(vote);
  const makeRecovery = ({ arrivals = [], fractional = false, rawActions = null } = {}) => {
    const clock = { mono: 0, wall: S + 8 * MIN + 10 * SEC };
    let performanceCalls = 0;
    const timers = []; const published = [];
    let relayRaw = rawActions || { votes: { [B]: vote }, reports: { [W]: [report] } };
    const state = {
      uid: V, blockNum, groupId, identity: { signKey: KEY.V }, rosterPaused: false,
      importedActions: { votes: {}, reports: {} }, observedActions: { votes: {}, reports: {} },
      receipts: {}, issuedActionHashes: new Set(), issuedActionReceiptBuckets: new Map(),
      issuedReadMsgKeys: new Set(), ownSessionSignatures: new Set(),
      myVote: null, myVotePrev: [], myReports: [], cfg: { pins: { maxReports: 2, chatCaps: {} } },
      relay: { isLiveOnlyAction: () => false, getReceipts: () => arrivals,
        getRelayActionsRaw: () => relayRaw,
        getMessages: () => [], publishReceipt: async (receipt) => { published.push(receipt); } },
    };
    const scope = { state, rosterReady: () => true, currentPhase: () => 'chatting',
      shouldIssueReceiptForObservedAction: P.shouldIssueReceiptForObservedAction,
      receiptIssuanceBlocked: () => false, clientNow: () => clock.wall,
      isReceiptTimely: P.isReceiptTimely, canIssueReceiptAtChainTip: async () => true,
      canIssueActionReceiptBeforeVoteCutoff: CK.canIssueActionReceiptBeforeVoteCutoff,
      submissionChatCloseAt: () => chainTimeline.chatCloseAt,
      actionHashV2: P.actionHashV2, MAX_OBSERVED_ACTIONS_PER_ACTOR: P.MAX_OBSERVED_ACTIONS_PER_ACTOR,
      privateKeyToAccount, canonicalizeSignature: P.canonicalizeSignature, receiptSignString: P.receiptSignString,
      localStorage: globalThis.localStorage, performance: { now: () =>
        fractional && performanceCalls++ === 0 ? 0 : clock.mono },
      observeOtherSessionItem: () => {}, decryptSelfTarget: () => null, renderGame: () => {},
      receiptIdentityDigest: R.receiptIdentityDigest, mergeActionReceiptSources: P.mergeActionReceiptSources,
      log: () => {},
    };
    const precheck = bind('ISSUE-7 precheck', `(${recoveryPrecheck.trim()})`, scope);
    scope.hasOwnActionReceipt = precheck;
    const issue = bind('ISSUE-7 issue', `(${recoveryIssue.trim()})`, scope);
    scope.issueActionReceipt = issue;
    const handle = bind('ISSUE-7 handle', `(${recoveryHandle.trim()})`, scope, { allowStub: true });
    scope.handleObservedActions = handle;
    const merge = bind('ISSUE-7 merge', `(${recoveryMerge.trim()})`, scope, { allowStub: true });
    const restore = bind('ISSUE-7 restore', `() => { ${restoreSource} }`, scope);
    function fakeSetTimeout(fn, delay) {
      assert.equal(this, undefined, 'ISSUE recovery timer is invoked directly');
      const timer = { fn, at: clock.mono + Math.trunc(delay), fired: false };
      timers.push(timer); return timer;
    }
    const grace = bind('ISSUE-7 grace', `() => { ${graceSource} }`, {
      ...scope, openReadReceiptPause: RP.openReadReceiptPause,
      setTimeout: fakeSetTimeout,
    });
    const start = () => { restore(); if (fractional) clock.mono = 0.5; grace(); };
    const fire = async (time) => {
      clock.mono = time;
      for (const timer of timers.filter((item) => !item.fired && item.at <= clock.mono)) {
        timer.fired = true; timer.fn();
      }
      await flush();
    };
    return { state, clock, published, start, fire, handle, merge, issue, timers,
      setRaw: (value) => { relayRaw = value; } };
  };
  resetObsStorage();
  const restored = makeRecovery({ arrivals: [recoveredReceipt] });
  restored.start();
  assert(restored.state.issuedActionHashes.has(recoveredReceipt.actionHash), 'ISSUE-7 verified restore marks before action');
  restored.handle(restored.state.relay.getRelayActionsRaw()); await flush();
  restored.merge(restored.state.relay.getReceipts());
  await restored.fire(10 * SEC);
  assert.equal(restored.published.filter((r) => r.actionHash === recoveredReceipt.actionHash).length, 0,
    'ISSUE-7 restored own receipt suppresses vote before merge');
  resetObsStorage();
  const recoveryFresh = makeRecovery(); recoveryFresh.start();
  recoveryFresh.handle(recoveryFresh.state.relay.getRelayActionsRaw()); await flush();
  assert.equal(recoveryFresh.published.length, 0, 'ISSUE-7 recovery grace suppresses initial issue');
  await recoveryFresh.fire(10 * SEC);
  assert.equal(recoveryFresh.published.length, 2, 'ISSUE-7 grace replay issues vote and report once');
  recoveryFresh.handle(recoveryFresh.state.relay.getRelayActionsRaw()); await flush();
  assert.equal(recoveryFresh.published.length, 2, 'ISSUE-7 later relay replay does not duplicate');
  resetObsStorage();
  const recoveryDisk = makeRecovery({ rawActions: { votes: {}, reports: {} } }); recoveryDisk.start();
  await recoveryDisk.fire(10 * SEC);
  globalThis.localStorage.setItem(recoveryKey, JSON.stringify({ x: recoveredReceipt }));
  recoveryDisk.handle({ votes: { [B]: vote }, reports: {} }); await flush();
  assert.equal(recoveryDisk.published.filter((r) => r.actionHash === recoveredReceipt.actionHash).length, 0,
    'ISSUE-7 late recovery disk write blocks');
  resetObsStorage();
  const recoveryQueue = makeRecovery({ rawActions: { votes: {}, reports: {} } }); recoveryQueue.start(); await recoveryQueue.fire(10 * SEC);
  recoveryQueue.state.relay.getReceipts = () => [recoveredReceipt];
  recoveryQueue.handle({ votes: { [B]: vote }, reports: {} }); await flush();
  assert.equal(recoveryQueue.published.filter((r) => r.actionHash === recoveredReceipt.actionHash).length, 0,
    'ISSUE-7 accepted recovery relay receipt blocks');
  for (const value of ['not-json', '[]', '[null]', '"text"', JSON.stringify({
    other: { ...recoveredReceipt, receiverUid: W },
    otherAction: await realOwn(report, W, 'report'),
    read: { ...recoveredReceipt, msgRefs: [] },
  })]) {
    resetObsStorage(); globalThis.localStorage.setItem(recoveryKey, value);
    const valid = makeRecovery({ rawActions: { votes: {}, reports: {} } });
    valid.start(); await valid.fire(10 * SEC);
    valid.handle({ votes: { [B]: vote }, reports: {} }); await flush();
    assert.equal(valid.published.length, 1, `ISSUE-7 unrelated or malformed recovery storage ${value}`);
  }
  resetObsStorage(); globalThis.localStorage.setItem(recoveryKey, JSON.stringify({ x: recoveredReceipt }));
  let persistedTotal = 0;
  for (let i = 0; i < 5; i++) {
    const page = makeRecovery({ arrivals: [recoveredReceipt], rawActions: { votes: { [B]: vote }, reports: {} } });
    page.start(); page.handle(page.state.relay.getRelayActionsRaw()); await page.fire(10 * SEC);
    persistedTotal += page.published.length;
  }
  assert.equal(persistedTotal, 0, 'ISSUE-7 five launches with stored own receipt stay at zero');
  resetObsStorage();
  let lostTotal = 0;
  for (let i = 0; i < 5; i++) {
    const page = makeRecovery({ rawActions: { votes: {}, reports: {} } });
    page.start(); await page.fire(10 * SEC);
    page.handle({ votes: { [B]: vote }, reports: {} }); await flush();
    lostTotal += page.published.length;
  }
  assert.equal(lostTotal, 5, 'ISSUE-7 absent storage and late history remains one per load');
  resetObsStorage();
  const recoveryEarly = makeRecovery({ fractional: true }); recoveryEarly.start();
  recoveryEarly.handle({ votes: { [B]: vote }, reports: { [W]: [report] } }); await flush();
  await recoveryEarly.fire(9999.5);
  assert.equal(recoveryEarly.published.length, 2, 'ISSUE-7 fractional timer replay issues both actions');
  console.log('ISSUE-7 known limit: absent storage and history after grace permits one per load');
  // ISSUE-8: source wiring and ordering of the extracted paths.
  const restoreAt = selectedHook.indexOf('const stored = loadJson(OBSERVED_RECEIPTS_KEY');
  const orderedAt = selectedHook.indexOf('for (const receipt of ordered)', restoreAt);
  assert(restoreAt >= 0 && selectedHook.indexOf('issuedActionHashesRef.current.add(receipt.actionHash)', restoreAt) < orderedAt,
    'ISSUE-8 official restore marks before queueing');
  const officialBody = hookCallback('current', 'issueActionReceipt').text;
  const firstGate = officialBody.indexOf('if (receiptIssuanceBlocked()) return;');
  const pauseGate = officialBody.indexOf('deferActionReceipt(', firstGate);
  const firstAwait = officialBody.indexOf('await ');
  assert(firstGate < pauseGate && pauseGate < firstAwait, 'ISSUE-8 grace before asynchronous work');
  const pendingAt = officialBody.indexOf('pendingReservations.has(actionHash)');
  const precheckAt = officialBody.indexOf('hasOwnActionReceipt(actionHash)', pendingAt);
  const signerAt = officialBody.indexOf('const signature =', precheckAt);
  assert(pendingAt < precheckAt && precheckAt < signerAt
    && !officialBody.slice(precheckAt, signerAt).includes('await '),
  'ISSUE-8 disk and accepted queue check immediately before signing');
  const officialGraceEffectAt = selectedHook.indexOf('grace.timer = setTimeout(replay');
  assert(officialGraceEffectAt > selectedHook.indexOf('channel.start();')
    && selectedHook.slice(officialGraceEffectAt, selectedHook.indexOf('// 自分の行が壊れて', officialGraceEffectAt)).includes('signKey'),
  'ISSUE-8 grace effect follows relay and depends on signKey');
  const officialGraceEffect = walk(ASTS.current, (node) => node.type === 'CallExpression'
    && node.callee?.name === 'useEffect' && selectedHook.slice(node.start, node.end).includes('grace.timer = setTimeout(replay'));
  assert.equal(officialGraceEffect.length, 1, 'ISSUE-8 one official grace effect');
  assert.equal(walk(officialGraceEffect[0], (node) => node.type === 'CallExpression'
    && node.callee?.type === 'Identifier' && node.callee.name === 'setTimeout').length, 1,
  'ISSUE-8 official timer uses direct global call');
  const recoveryTimerCalls = walk(parse(graceSource, PARSE_OPTS), (node) => node.type === 'CallExpression'
    && node.callee?.type === 'Identifier' && node.callee.name === 'setTimeout');
  assert.equal(recoveryTimerCalls.length, 1, 'ISSUE-8 recovery timer uses direct global call');
  assert(selectedHook.slice(selectedHook.indexOf('const issueActionReceipt = useCallback'),
    selectedHook.indexOf('const issuingReadMsgKeysRef')).includes('deferActionReceipt, hasOwnActionReceipt]);'),
  'ISSUE-8 issue callback has guard dependencies');
  const recoveryVerifyAt = app.indexOf('await state.relay.verifyStoredReceipts();');
  const recoveryStartAt = app.indexOf('if (!canStartRecoveryP2P(myMember)) {', recoveryVerifyAt);
  const recoveryGraceAt = app.indexOf('const actionReceiptGraceToken = {};', recoveryStartAt);
  const recoveryReportAt = app.indexOf('await state.relay.verifyRestoredReports?.();', recoveryGraceAt);
  assert(recoveryVerifyAt < app.indexOf('state.issuedActionHashes.add(receipt.actionHash)', recoveryVerifyAt)
    && app.indexOf('state.issuedActionHashes.add(receipt.actionHash)', recoveryVerifyAt) < recoveryStartAt
    && recoveryStartAt < recoveryGraceAt && recoveryGraceAt < recoveryReportAt,
  'ISSUE-8 recovery restore and grace startup order');
  assert(recoveryIssue.indexOf('receiptIssuanceBlocked()') < recoveryIssue.indexOf('const grace = state.actionReceiptGrace;')
    && recoveryIssue.indexOf('const grace = state.actionReceiptGrace;') < recoveryIssue.indexOf('await canIssueReceiptAtChainTip()')
    && recoveryIssue.indexOf('hasOwnActionReceipt(actionHash)') < recoveryIssue.indexOf('state.issuedActionHashes.add(actionHash);', recoveryIssue.indexOf('hasOwnActionReceipt(actionHash)')),
  'ISSUE-8 recovery grace and precheck order');
  console.log('ISSUE: PASS');
}
console.log('OBSBASE / MSGBASE / R2-A / AST: PASS');
}

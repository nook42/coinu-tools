import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { openReadReceiptPause } from '../vendor/src/utils/read-receipt-pause.js';

const hook = readFileSync(new URL('../../src/hooks/useGameWebSocket.js', import.meta.url), 'utf8');
const app = readFileSync(process.env.T8_RECOVERY_APP_SOURCE
  || new URL('../src/recovery/app.js', import.meta.url), 'utf8');
const between = (source, start, end) => {
  const a = source.indexOf(start), b = source.indexOf(end, a + start.length);
  assert(a >= 0 && b > a, `missing source boundary: ${start}`);
  return source.slice(a, b);
};

const officialPredicateSource = between(hook,
  'function isOtherSessionItem(item, session, uid, ownerUid) {', '\nexport function useGameWebSocket');
const mutations = {
  'entry-inclusive': ['item.timestamp > session.entryAt', 'item.timestamp >= session.entryAt'],
  'ignore-own': ['!session.ownSignatures.has(item.signature)', 'true'],
  'ignore-away': ['!session.awayIntervals.some(({ start, end }) => item.timestamp >= start && item.timestamp <= end)', 'true'],
};
const mutation = mutations[process.env.T1N_MUTATION];
const testedOfficialSource = mutation ? officialPredicateSource.replace(...mutation) : officialPredicateSource;
if (mutation) assert.notEqual(testedOfficialSource, officialPredicateSource, 'mutation hit source');
const officialPredicate = new Function(`${testedOfficialSource}\nreturn isOtherSessionItem;`)();
const recoveryState = { uid: 'V', sessionEntryAt: 100, awayIntervals: [], ownSessionSignatures: new Set() };
const recoveryPredicateSource = between(app,
  'function isOtherSessionItem(item, ownerUid) {', '\nfunction observeOtherSessionItem(');
const recoveryPredicate = new Function('state', `${recoveryPredicateSource}\nreturn isOtherSessionItem;`)(recoveryState);
const officialSession = { entryAt: 100, awayIntervals: [], ownSignatures: new Set() };
const checkBoth = (item, ownerUid, expected, label) => {
  assert.equal(officialPredicate(item, officialSession, 'V', ownerUid), expected, `official ${label}`);
  assert.equal(recoveryPredicate(item, ownerUid), expected, `recovery ${label}`);
};
for (const kind of ['chat', 'vote', 'report', 'read']) {
  const item = { signature: `${kind}-other`, timestamp: 101 };
  checkBoth(item, 'V', true, `${kind}: all conditions`);
  checkBoth(item, 'H', false, `${kind}: another player`);
  checkBoth({ ...item, timestamp: 100 }, 'V', false, `${kind}: entry boundary`);
  checkBoth({ ...item, timestamp: 99 }, 'V', false, `${kind}: old item`);
  officialSession.ownSignatures.add(item.signature);
  recoveryState.ownSessionSignatures.add(item.signature);
  checkBoth(item, 'V', false, `${kind}: emitted by this screen`);
  officialSession.ownSignatures.delete(item.signature);
  recoveryState.ownSessionSignatures.delete(item.signature);
  officialSession.awayIntervals = [{ start: 101, end: 103 }];
  recoveryState.awayIntervals = [{ start: 101, end: 103 }];
  checkBoth(item, 'V', false, `${kind}: away interval`);
  officialSession.awayIntervals = [];
  recoveryState.awayIntervals = [];
}
checkBoth({ signature: 'missing-time' }, 'V', false, 'missing signed time');
assert.match(between(hook, 'const mergeMessagesV2 = useCallback(', 'const effectiveClientNow ='),
  /for \(const message of messages\) flagOtherSession\(message, message\.uid\)/,
  'official verified chat union reaches the predicate');
assert.match(between(hook, 'const ingestReceipt = useCallback(', 'const readSessionKey ='),
  /flagOtherSession\(receipt, receipt\.receiverUid\)/,
  'official accepted receipts reach the predicate');
assert.match(between(hook, 'const handleIncomingAction = useCallback(', '// 密告件数'),
  /flagOtherSession\(value, actorUid\)/g,
  'official verified vote and report reach the predicate with signed fields');
assert.equal([...between(hook, 'const handleIncomingAction = useCallback(', '// 密告件数')
  .matchAll(/flagOtherSession\(value, actorUid\)/g)].length, 2,
  'future and accepted branches both pass the signed value');
assert.doesNotMatch(between(hook, 'const handleIncomingAction = useCallback(', '// 密告件数'),
  /flagOtherSession\(action, actorUid\)/,
  'raw action cannot reach the warning predicate');
assert.match(between(hook, 'onSelfAction: async (type, inner) => {', '\n        },\n      });'),
  /flagOtherSession\(inner, uid\)/,
  'official verified P2P self action reaches the predicate');
assert.match(between(app, 'onUpdate: () => {', 'onSelfAction: handleSelfAction'),
  /observeOtherSessionItem\(message, message\.uid\)/,
  'recovery verified chat union reaches the predicate');
assert.match(between(app, 'function mergeReceipts(list) {', 'async function importOfficialLocalStorage'),
  /observeOtherSessionItem\(rc, rc\.receiverUid\)/,
  'recovery verified receipts reach the predicate');
assert.match(between(app, 'function handleObservedActions(raw) {', '// v3.3追補: 在席'),
  /observeOtherSessionItem\(vote, state\.uid\)/,
  'recovery verified votes reach the predicate');
assert.match(between(app, 'function handleObservedActions(raw) {', '// v3.3追補: 在席'),
  /observeOtherSessionItem\(report, state\.uid\)/,
  'recovery verified reports reach the predicate');

const originalTest = (item) => officialPredicate(item, officialSession, 'V', 'V');
const mutated = new Function(`${officialPredicateSource.replace('item.timestamp > session.entryAt',
  'item.timestamp >= session.entryAt')}\nreturn isOtherSessionItem;`)();
assert.equal(originalTest({ signature: 'boundary', timestamp: 100 }), false);
assert.equal(mutated({ signature: 'boundary', timestamp: 100 }, officialSession, 'V', 'V'), true,
  'the entry-boundary mutation must turn this test red');

const officialResumeSource = between(hook,
  'const resumeOtherSession = useCallback(() => {', '\n  const endThisTab = useCallback(');
let officialWarned = true, officialPresence = null;
const officialRef = { current: { entryAt: 100, awayIntervals: [{ start: 101, end: 102 }],
  warned: true, ended: false } };
const officialPause = { current: { until: 0, lastIssuedAt: 0, lastTickAt: 0 } };
const officialResume = new Function('useCallback', 'sessionActivityRef', 'readReceiptPauseRef',
  'performance', 'Date', 'clientNow', 'setOtherSessionReadReceipt', 'isAwayRef', 'publishPresence', 'openReadReceiptPause', 'receiptIssuanceBlocked',
  `${officialResumeSource}\nreturn resumeOtherSession;`)(
  (fn) => fn, officialRef, officialPause, { now: () => 5000 }, { now: () => 120 }, () => 120,
  (value) => { officialWarned = value; }, { current: false }, (value) => { officialPresence = value; }, openReadReceiptPause,
  () => officialRef.current.warned || officialRef.current.ended);
officialResume();
assert.equal(officialRef.current.entryAt, 120);
assert.deepEqual(officialRef.current.awayIntervals, []);
assert.equal(officialPause.current.until, 0, 'explicit resume does not open the read pause');
assert.equal(officialWarned, false);
assert.equal(officialPresence, 'active');
officialSession.entryAt = 120;
recoveryState.sessionEntryAt = 120;
checkBoth({ signature: 'old-after-resume', timestamp: 110 }, 'V', false, 'old item after resume');
checkBoth({ signature: 'new-after-resume', timestamp: 121 }, 'V', true, 'new item after resume');

const recoveryResumeSource = between(app, 'function resumeOtherSession() {', '\nfunction endThisTab() {');
let recoveryPresence = null;
Object.assign(recoveryState, { otherSessionReadReceipt: true, tabEnded: false,
  readReceiptPause: { until: 0, lastIssuedAt: 0, lastTickAt: 0 }, away: false });
const recoveryResume = new Function('state', 'Date', 'performance', 'clientNow', 'publishPresence', 'renderGame', 'openReadReceiptPause', 'receiptIssuanceBlocked',
  `${recoveryResumeSource}\nreturn resumeOtherSession;`)(
  recoveryState, { now: () => 130 }, { now: () => 9000 }, () => 130,
  (value) => { recoveryPresence = value; }, () => {}, openReadReceiptPause,
  () => recoveryState.otherSessionReadReceipt || recoveryState.tabEnded);
recoveryResume();
assert.equal(recoveryState.sessionEntryAt, 130);
assert.equal(recoveryState.readReceiptPause.until, 0);
assert.equal(recoveryPresence, 'active');

const officialEndSource = between(hook, 'const endThisTab = useCallback(() => {', '\n  useEffect(() => {\n    if (isSpectator) return;');
let disconnected = 0, stopped = 0, channelClosed = 0, ended = false;
const officialEnd = new Function('useCallback', 'sessionActivityRef', 'setSessionEnded', 'disconnect',
  'relayChannelRef', 'readReceiptChannelRef', `${officialEndSource}\nreturn endThisTab;`)(
  (fn) => fn, officialRef, (value) => { ended = value; }, () => { disconnected++; },
  { current: { stop: () => { stopped++; } } }, { current: { close: () => { channelClosed++; } } });
officialEnd(); officialEnd();
assert.equal(ended, true);
assert.deepEqual([disconnected, stopped, channelClosed], [1, 1, 1]);

const recoveryEndSource = between(app, 'function endThisTab() {', '\nfunction reopenReadReceiptPause() {');
let recoveryStopped = 0;
recoveryState.relay = { stop: () => { recoveryStopped++; } };
const recoveryEnd = new Function('state', 'clearInterval', 'renderGame',
  `${recoveryEndSource}\nreturn endThisTab;`)(recoveryState, () => {}, () => {});
recoveryEnd(); recoveryEnd();
assert.equal(recoveryStopped, 1);
assert.equal(recoveryState.tabEnded, true);
assert.equal(recoveryState.relay, null);
assert.match(hook, /ended: sessionActivityRef\.current\.ended/,
  'an identity change in the same tab cannot reconnect after Close this tab');

const officialActionAt = hook.indexOf('const issueActionReceipt = useCallback(async (actorUid, actionType, action, isCurrentOwner = () => true) => {');
const officialActionEnd = hook.indexOf('\n  }, [signKey, isSpectator', officialActionAt);
assert(officialActionAt >= 0 && officialActionEnd > officialActionAt);
const officialActionText = hook.slice(hook.indexOf('async (actorUid', officialActionAt), officialActionEnd + 4);
let officialChainChecks = 0;
officialRef.current.warned = true;
const officialAction = new Function('receiptAdmissionIdentityRef', 'isGameIdentityCurrent',
  'rosterStartConfirmedRef', 'rosterIdentityMatches', 'currentRosterIdentityRef',
  'blockNum', 'groupId', 'signKey', 'isSpectator', 'uid', 'phaseRef', 'isAwayRef',
  'sessionActivityRef', 'canIssueReceiptAtChainTip', 'receiptIssuanceBlocked', 'clientNow',
  'isReceiptTimely', 'chainTimelineRef', 'confirmedChatWindowRef',
  'canIssueActionReceiptBeforeVoteCutoff', 'deferActionReceipt', 'hasOwnActionReceipt', `return (${officialActionText});`)(
  { current: {} }, () => true, { current: true }, () => true,
  { current: {} }, 1, 0, 'key', false, 'V', { current: 'chatting' }, { current: false },
  { current: { warned: true, ended: false } }, async () => { officialChainChecks++; return false; },
  () => officialRef.current.warned || officialRef.current.ended, () => 101,
  () => true, { current: { chatCloseAt: 1_000_000 } }, { current: null }, () => true,
  () => false, () => false);
await officialAction('H', 'vote', { timestamp: 101 });
assert.equal(officialChainChecks, 0, 'official warning blocks action receipts before chain/signing');
officialRef.current.warned = false;
officialRef.current.ended = false;
officialRef.current.clockWarning = { warning: { direction: 'late', stage: 'full', deviationMs: -180000 } };
await officialAction('H', 'vote', { timestamp: 101 });
assert.equal(officialChainChecks, 1, 'official clock warning permits action receipt chain check');

const recoveryActionSource = between(app, 'async function issueActionReceipt(actorUid, actionType, action) {',
  '\n// 既読受領証明の自動バッチ発行');
const recoveryBlockedSource = between(app, 'function receiptIssuanceBlocked() {', '\n}');
let recoveryChainChecks = 0;
const recoveryActionState = { uid: 'V', identity: {}, relay: { isLiveOnlyAction: () => false, getReceipts: () => [] },
  actionReceiptGrace: { passed: true, until: -Infinity },
  observedActions: { votes: {} }, away: false, otherSessionReadReceipt: true, tabEnded: false };
const recoveryAction = new Function('state', 'rosterReady', 'currentPhase',
  'shouldIssueReceiptForObservedAction', 'canIssueReceiptAtChainTip', 'receiptIssuanceBlocked',
  'clientNow', 'isReceiptTimely', 'hasOwnActionReceipt',
  `${recoveryActionSource}\nreturn issueActionReceipt;`)(
  recoveryActionState, () => true, () => 'chatting', () => true,
  async () => { recoveryChainChecks++; return false; },
  () => recoveryActionState.otherSessionReadReceipt, () => 101, () => true, () => false);
await recoveryAction('H', 'vote', { timestamp: 101 });
assert.equal(recoveryChainChecks, 0, 'recovery warning blocks action receipts before chain/signing');
recoveryActionState.otherSessionReadReceipt = false;
recoveryActionState.clockWarning = { warning: { direction: 'late', stage: 'full', deviationMs: -180000 } };
await recoveryAction('H', 'vote', { timestamp: 101 });
assert.equal(recoveryChainChecks, 1, 'recovery clock warning permits action receipt chain check');

// T8: a flag raised while the chain check is pending must release both reservations.
let t8ActionSource = recoveryActionSource;
if (process.argv.includes('--mutation=t8-keep-mark-after-gate')) {
  const gate = '    if (receiptIssuanceBlocked()) {\n      state.issuedActionReceiptBuckets.delete(actionHash);\n      state.issuedActionHashes.delete(actionHash);\n      return;\n    }\n    state.ownSessionSignatures.add(signature);';
  assert.equal(t8ActionSource.split(gate).length, 2, 'T8 mutation hits only the post-sign gate');
  t8ActionSource = t8ActionSource.replace(gate,
    '    if (receiptIssuanceBlocked()) return;\n    state.ownSessionSignatures.add(signature);');
}
for (const flag of ['away', 'otherSessionReadReceipt', 'tabEnded']) {
  const board = { uid: 'H', identity: { signKey: 'key' }, blockNum: 1, groupId: 0,
    relay: { isLiveOnlyAction: () => false, getReceipts: () => [], publishReceipt: async () => { published++; } },
    actionReceiptGrace: { passed: true, until: -Infinity },
    observedActions: { votes: {} }, issuedActionHashes: new Set(),
    issuedActionReceiptBuckets: new Map(), ownSessionSignatures: new Set(),
    away: false, otherSessionReadReceipt: false, tabEnded: false,
    clockWarning: { warning: { direction: 'late', stage: 'full', deviationMs: -180000 } } };
  let published = 0, raiseOnChain = true;
  const blocked = new Function('state', `${recoveryBlockedSource}\n}\nreturn receiptIssuanceBlocked;`)(board);
  const deps = { state: board, rosterReady: () => true, currentPhase: () => 'chatting',
    shouldIssueReceiptForObservedAction: () => true, clientNow: () => 1_000_000,
    isReceiptTimely: (a, b) => Math.abs(a - b) <= 600_000,
    canIssueReceiptAtChainTip: async () => { if (raiseOnChain) board[flag] = true; return true; },
    canIssueActionReceiptBeforeVoteCutoff: () => true, submissionChatCloseAt: () => 2_000_000,
    actionHashV2: (...parts) => parts.join('|'), MAX_OBSERVED_ACTIONS_PER_ACTOR: 10,
    privateKeyToAccount: () => ({ signMessage: async () => 'signature' }),
    canonicalizeSignature: (value) => value, receiptSignString: () => 'payload', log: () => {},
    receiptIssuanceBlocked: blocked, hasOwnActionReceipt: () => false };
  const issue = new Function(...Object.keys(deps), `${t8ActionSource}\nreturn issueActionReceipt;`)(...Object.values(deps));
  const action = { encrypted: 'cipher', timestamp: 999_000 };
  await issue('V', 'vote', action);
  assert.equal(published, 0, `${flag}: blocked after signing`);
  assert.equal(board.issuedActionHashes.size, 0, `${flag}: hash reservation released`);
  assert.equal(board.issuedActionReceiptBuckets.size, 0, `${flag}: bucket reservation released`);
  raiseOnChain = false;
  await issue('V', 'vote', action);
  assert.equal(published, 0, `${flag}: retry while blocked`);
  if (flag === 'tabEnded') continue; // a real ended tab closes its relay permanently.
  board[flag] = false;
  await issue('V', 'vote', action);
  await issue('V', 'vote', action);
  assert.equal(published, 1, `${flag}: retry with a clock warning after the flag clears publishes once`);
}

const officialPresenceAt = hook.indexOf('const publishPresence = useCallback(async (state) => {');
const officialPresenceEnd = hook.indexOf('\n  }, [isSpectator, uid, blockNum, groupId, signKey, send, isGameIdentityCurrent]);', officialPresenceAt);
assert(officialPresenceAt >= 0 && officialPresenceEnd > officialPresenceAt);
const officialPresenceText = hook.slice(hook.indexOf('async (state)', officialPresenceAt), officialPresenceEnd + 4);
let releaseOfficialSignature;
const officialSigned = new Promise((resolve) => { releaseOfficialSignature = resolve; });
let officialRelayPresence = 0;
const presenceSession = { current: { warned: true, ended: false } };
const officialPublishPresence = new Function('isSpectator', 'uid', 'blockNum', 'groupId',
  'rosterStartConfirmedRef', 'isGameIdentityCurrent', 'sessionActivityRef', 'Date', 'clientNow',
  'send', 'signKey', 'relayChannelRef', 'privateKeyToAccount', 'canonicalizeSignature',
  'presenceSignStringV2', 'isAwayRef', 'receiptIssuanceBlocked', `return (${officialPresenceText});`)(
  false, 'V', 1, 0, { current: true }, () => true, presenceSession, { now: () => 101 }, () => 101,
  () => true, 'key', { current: { publishPresence: () => { officialRelayPresence++; } } },
  () => ({ signMessage: () => officialSigned }), (value) => value, () => 'signed', { current: false },
  () => presenceSession.current.warned || presenceSession.current.ended);
const pendingOfficialPresence = officialPublishPresence('away');
presenceSession.current.warned = false;
releaseOfficialSignature('signature');
await pendingOfficialPresence;
assert.equal(officialRelayPresence, 0, 'late away signature cannot overwrite resumed P2P presence');

const recoveryPresenceSource = between(app, 'async function publishPresence(nextState) {', '\nfunction markActive() {');
let releaseRecoverySignature;
const recoverySigned = new Promise((resolve) => { releaseRecoverySignature = resolve; });
let recoveryRelayPresence = 0;
const recoveryPresenceState = { identity: { signKey: 'key' }, uid: 'V', blockNum: 1,
  groupId: 0, tabEnded: false, otherSessionReadReceipt: true, away: false,
  relay: { publishPresence: () => { recoveryRelayPresence++; } } };
const recoveryPublishPresence = new Function('state', 'rosterReady', 'Date', 'clientNow', 'privateKeyToAccount',
  'canonicalizeSignature', 'presenceSignStringV2', 'log', 'receiptIssuanceBlocked',
  `${recoveryPresenceSource}\nreturn publishPresence;`)(
  recoveryPresenceState, () => true, { now: () => 101 }, () => 101,
  () => ({ signMessage: () => recoverySigned }), (value) => value, () => 'signed', () => {},
  () => recoveryPresenceState.otherSessionReadReceipt || recoveryPresenceState.tabEnded);
const pendingRecoveryPresence = recoveryPublishPresence('away');
recoveryPresenceState.otherSessionReadReceipt = false;
releaseRecoverySignature('signature');
await pendingRecoveryPresence;
assert.equal(recoveryRelayPresence, 0, 'recovery late away signature cannot overwrite resumed presence');

for (const source of [hook, app]) {
  assert.match(source, /otherSessionReadReceipt|sessionActivityRef\.current\.warned/);
}
const ja = JSON.parse(readFileSync(new URL('../../public/locales/ja/game_ja.json', import.meta.url)));
const en = JSON.parse(readFileSync(new URL('../../public/locales/en/game_en.json', import.meta.url)));
const i18n = readFileSync(new URL('../src/common/i18n.js', import.meta.url), 'utf8');
for (const locale of [ja, en]) {
  for (const key of ['multipleSessionsWarning', 'multiSessionResume', 'multiSessionClose', 'multiSessionEnded']) {
    assert(locale.members[key], `missing official i18n ${key}`);
  }
}
for (const key of ['multipleSessionsWarning', 'session.resume', 'session.close', 'session.ended']) {
  const full = key === 'multipleSessionsWarning' ? `recovery.members.${key}` : `recovery.${key}`;
  assert.equal(i18n.split(`'${full}'`).length - 1, 3, `missing recovery en/ja/zh ${full}`);
}
console.log('T1n multi-session: ALL PASSED (four kinds, three guards, resume, close, locales, mutation)');

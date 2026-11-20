import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { markActionReceiptSource } from '../../workers/game_workers/lib/protocol-v2.js';
import { receiptIdentityDigest, RelayPool, FutureAdmissionMarks, ReceiptAdmissionQueue } from '../../src/utils/relay.js';
import { countHalfWidthChars, GUEST_PINNED_RULES } from '../../workers/game_workers/lib/char-counter.js';

const hook = readFileSync(process.env.MCF_HOOK_SOURCE
  || new URL('../../src/hooks/useGameWebSocket.js', import.meta.url), 'utf8');
const defaultsAt = hook.indexOf('export const RULE_PARAM_DEFAULTS =');
const defaultsEnd = hook.indexOf('});', defaultsAt) + 3;
const normalizeAt = hook.indexOf('export function normalizeRuleParams(');
const normalizeEnd = hook.indexOf('\n}', normalizeAt) + 2;
assert(defaultsAt >= 0 && normalizeAt >= 0);
const normalizeRuleParams = new Function(`${hook.slice(defaultsAt, defaultsEnd).replace('export ', '')}\n${hook.slice(normalizeAt, normalizeEnd).replace('export ', '')}\nreturn normalizeRuleParams;`)();
const failures = [];
const check = (name, actual, expected) => {
  if (actual !== expected) failures.push(`${name}: actual=${String(actual)} expected=${String(expected)}`);
};
check('T1m-3 operator cap', normalizeRuleParams({ maxMsgChars: 2000 }).maxMsgChars, 1000);
assert.equal(normalizeRuleParams({ maxMsgChars: 700 }).maxMsgChars, 1000,
  'S3R4-U-A501: a lower operator cap cannot close the send gate');
assert.deepEqual(JSON.parse(JSON.stringify(normalizeRuleParams({
  maxChars: 100000, maxMessages: 1000, maxMsgChars: 2000,
}))), { minChars: 500, minMessages: 20, maxChars: 10000, maxMessages: 100, maxMsgChars: 1000 },
  'S3R4-U-A501: raised operator caps cannot extend the send gate');
assert.deepEqual(JSON.parse(JSON.stringify(normalizeRuleParams({
  maxChars: 500, maxMessages: 20, maxMsgChars: 25, minChars: 20000, minMessages: 500,
}))), { minChars: 10000, minMessages: 100, maxChars: 10000, maxMessages: 100, maxMsgChars: 1000 },
  'S3R4-U-A501: minimums remain reachable under pinned caps');
for (const key of ['minChars', 'minMessages', 'maxChars', 'maxMessages', 'maxMsgChars']) {
  assert.equal(normalizeRuleParams({})[key], GUEST_PINNED_RULES[key],
    `S3R4-U-A501: ${key} matches the scoring pin`);
}
const sendAt = hook.indexOf('const sendMessage = useCallback(async (text, keyOverride) => {');
const sendEnd = hook.indexOf('\n  }, [send, uid, blockNum, groupId, mergeMessagesV2', sendAt);
assert(sendAt >= 0 && sendEnd > sendAt);
let sends = 0;
const sendScope = {
  signKey: 'key', rosterStartConfirmedRef: { current: true }, isGameIdentityCurrent: () => true,
  ownChatHistoryReadyRef: { current: '1|1|V' },
  setServerError: () => {}, privateKeyToAccount: () => ({ signMessage: async () => 'signature' }),
  chatSignStringV2: () => 'signed', canonicalizeSignature: (value) => value,
  blockNum: 1, groupId: 1, uid: 'V', maxMsgCharsRef: { current: 1000 }, countHalfWidthChars,
  GUEST_PINNED_RULES: { maxMsgChars: 1000 },
  setMessages: () => {}, mergeMessagesV2: () => [], relayChannelRef: { current: null },
  sessionActivityRef: { current: { ownSignatures: new Set() } },
  send: () => { sends++; return true; }, setChatSendAttempted: () => {},
  notePresenceDisplayChat: () => {}, // 在席の表示の控え（UI_IMPROVEMENTS_S3 #33）。専用の presence 試験で確かめる。
  clientNow: () => Date.now(),
};
const sendMessage = new Function(...Object.keys(sendScope),
  `return (${hook.slice(sendAt + 'const sendMessage = useCallback('.length, sendEnd + 4)});`)(...Object.values(sendScope));
check('T1m-3 1500 character direct send', await sendMessage('x'.repeat(1500)), false);
check('T1m-3 oversized send count', sends, 0);
assert.equal(await sendMessage('x'.repeat(1000)), true, 'T1m-3: the pinned boundary sends');

const evidence = await import('../../src/utils/evidence.js');
const values = new Map();
globalThis.localStorage = {
  getItem: (key) => values.has(key) ? values.get(key) : null,
  setItem: (key, value) => values.set(key, String(value)),
  removeItem: (key) => values.delete(key),
};
evidence.saveEvidencePayload(991, 'T1m', 'signed-first-submission');
evidence.settleEvidencePayload(991, 'T1m', true);
check('T1m-2 Evidence rescue', evidence.loadEvidencePayload(991, 'T1m'), 'signed-first-submission');

const at = hook.indexOf('const queueReceipt = useCallback(async (receipt, options = {}) => {');
const end = hook.indexOf('\n  }, [blockNum, groupId, uid, ingestReceipt, gameRpcSession]);', at);
assert(at >= 0 && end > at);
const close = Date.now() - 30_000;
const action = { receiverUid: 'V', actionHash: `0x${'ab'.repeat(32)}`,
  timestamp: close - 1000, signature: `0x${'11'.repeat(64)}1b` };
let known = { ...action };
let latestChainRead = 0;
let chainAt = close + 30_000;
let ingested = null;
const scope = {
  receiptAdmissionRef: { current: { offer: async () => true } },
  receiptsRef: { current: { [action.signature]: known } },
  liveOnlyReceiptsRef: { current: new Map() },
  receiptIdentityDigest, MAX_RECEIPTS_PER_ISSUER: 700,
  receiptChainClockRef: { current: {} },
  receiptTipRetryAfterRef: { current: 0 }, gameRpcSession: null,
  readReceiptChainTime: async () => { latestChainRead++; return chainAt; },
  markActionReceiptSource, chainTimelineRef: { current: { chatCloseAt: close } },
  confirmedChatWindowRef: { current: null }, CHAT_WINDOW_CLOCK_SKEW_MS: 120_000,
  ingestReceipt: (row) => { ingested = row; },
  blockNum: 1, groupId: 1, uid: 'V',
  clientNow: () => Date.now(),
};
const queueReceipt = new Function(...Object.keys(scope), `return (${hook.slice(at + 'const queueReceipt = useCallback('.length, end + 4)});`)(...Object.values(scope));
await queueReceipt(action);
check('T1m-4 chain read', latestChainRead, 1);
check('T1m-4 late source mark', ingested?._deviceSeenAt, null);
chainAt = close - 1000;
await queueReceipt(action);
check('T1m-4 timely chain source mark', ingested?._chainSeenAt, chainAt);
chainAt = null;
await queueReceipt(action);
check('T1m-4 unavailable chain after close uses device without extra allowance',
  Number.isSafeInteger(ingested?._deviceSeenAt), false);
await queueReceipt({ ...action, _firstArrivalAt: close - 1 });
check('T3-3 untrusted WS arrival mark ignored', ingested?._deviceSeenAt, null);
const localReceipt = { ...action };
Object.defineProperty(localReceipt, '_firstArrivalAt', { value: close - 1 });
await queueReceipt(localReceipt);
check('D1b U-18 device mark uses C even when the raw arrival was before close', ingested?._deviceSeenAt, null);
check('T1-4 first-arrival transport marker is not submitted',
  Object.hasOwn(ingested || {}, '_firstArrivalAt'), false);

// MCF: DO acknowledgement and stored U-18 marks survive the signed-field rebuild.
{
  const state = { receipts: {} };
  const saved = new Map();
  let offered = null;
  const mcfScope = { ...scope,
    receiptsRef: { current: state.receipts },
    receiptAdmissionRef: { current: { offer: async (row) => {
      offered = row;
      state.receipts[row.signature] = row;
      saved.set(row.signature, JSON.stringify(row));
      return true;
    } } },
  };
  const mcfQueue = new Function(...Object.keys(mcfScope),
    `return (${hook.slice(at + 'const queueReceipt = useCallback('.length, end + 4)});`)(
    ...Object.values(mcfScope));
  const read = { receiverUid: 'V', senderUid: 'B', msgRefs: [], timestamp: close - 1000,
    signature: `0x${'55'.repeat(64)}1b`, _receivedAt: close - 2000 };
  await mcfQueue(read, { source: 'do' });
  check('MCF DO acknowledgement in state', state.receipts[read.signature]?._receivedAt, read._receivedAt);
  check('MCF DO acknowledgement in storage', JSON.parse(saved.get(read.signature))._receivedAt, read._receivedAt);
  const resendStart = hook.indexOf('const own = Object.values({ ...saved, ...receiptsRef.current })');
  const resendTail = '.slice(0, MAX_RECEIPTS_PER_ISSUER);';
  const resendEnd = hook.indexOf(resendTail, resendStart);
  assert(resendStart >= 0 && resendEnd > resendStart, 'MCF WS open resend filter extraction');
  const savedRows = Object.fromEntries([...saved].map(([key, value]) => [key, JSON.parse(value)]));
  const resend = new Function('saved', 'receiptsRef', 'uid', 'MAX_RECEIPTS_PER_ISSUER',
    `${hook.slice(resendStart, resendEnd + resendTail.length)}\nreturn own;`)(
    savedRows, mcfScope.receiptsRef, 'V', 700);
  check('MCF reconnect resend count', resend.length, 0);
  const stored = { ...action, _chainSeenAt: close - 2000, _deviceSeenAt: close - 3000,
    _receivedAt: close - 4000 };
  await mcfQueue(stored, { source: 'storage' });
  check('MCF stored chain mark', offered?._chainSeenAt, stored._chainSeenAt);
  check('MCF stored device mark', offered?._deviceSeenAt, stored._deviceSeenAt);
  const mixed = { ...read, senderUid: 9, actionHash: action.actionHash,
    signature: `0x${'56'.repeat(64)}1b` };
  await mcfQueue(mixed, { source: 'do' });
  check('MCF array kind before actionHash for non-string sender', Object.hasOwn(offered, 'actionHash'), false);
  check('MCF array kind keeps digest', receiptIdentityDigest(offered), receiptIdentityDigest(mixed));
  for (const [i, msgRefs] of [[], ['a'], 'x', {}, null].entries()) {
    const raw = { ...action, msgRefs, signature: `0x${(60 + i).toString(16).repeat(64)}1b` };
    await mcfQueue(raw, { source: 'do' });
    check(`MCF digest shape ${JSON.stringify(msgRefs)}`, receiptIdentityDigest(offered), receiptIdentityDigest(raw));
  }
}

const app = readFileSync(new URL('../src/recovery/app.js', import.meta.url), 'utf8');
const spec = readFileSync(new URL('../../docs/CHAT_GAME_SIMPLIFICATION_SPEC.md', import.meta.url), 'utf8');
const design = readFileSync(new URL('../DESIGN.md', import.meta.url), 'utf8');
assert.match(spec, /S3FIX で U-15 の保留を撤去/, 'FRO replaced U-15 holding');
assert.match(design, /登録値 `C = keccak256\(abi\.encode\(keccak256\(manifestText\), memberRoot\)\)`/,
  'T1m-6: the recovery design names roster value C');
assert.match(design, /正典名簿の本人のウォレットだけが送れる/,
  'T1m-6: the recovery design preserves self-wallet Evidence rescue');
assert.doesNotMatch(design, /permissionless/i,
  'T1m-6: the obsolete permissionless assertion is gone');
let futureNow = Date.now();
const futureQueue = new FutureAdmissionMarks({ blockNum: 1, groupId: 1, now: () => futureNow });
const futureAction = { actionType: 'vote', encrypted: 'encrypted', uid: 'V', timestamp: futureNow + 180000,
  signature: `0x${'33'.repeat(64)}1b` };
check('Q18 future action discarded', futureQueue.discard('action', futureAction), true);
check('Q18 future action marked', futureQueue.has('action', futureAction), true);
futureNow += 60000;
check('Q18 marked action stays discarded when clock catches up', futureQueue.has('action', futureAction), true);
check('Q12A forward correction releases the action', futureQueue.releaseEligible(60000).released, 1);
const pendingFutureReceipt = { receiverUid: 'V', actionHash: `0x${'cc'.repeat(32)}`,
  timestamp: Date.now() + 180000, signature: `0x${'44'.repeat(64)}1b` };
let futureClock = Date.now();
const admittedFuture = [];
const receiptMarks = new FutureAdmissionMarks({ blockNum: 1, groupId: 1, now: () => futureClock });
const futureReceipts = new ReceiptAdmissionQueue({
  getRosterUids: () => ['V'], verifyReceipt: async () => true,
  resolveReceipt: () => ({ state: 'covered', facts: ['a'], priority: 'F' }),
  now: () => futureClock, futureMarks: receiptMarks,
  onAccept: (receipt) => admittedFuture.push(receipt),
});
await futureReceipts.offer(pendingFutureReceipt);
check('Q18 signed future receipt discarded', futureReceipts.entries.size, 0);
check('Q18 signed future receipt marked', receiptMarks.has('receipt', pendingFutureReceipt), true);
futureClock += 60000;
await futureReceipts.offer(pendingFutureReceipt);
check('Q18 time does not admit marked receipt', admittedFuture.length, 0);
check('Q12A correction releases marked receipt', receiptMarks.releaseEligible(60000).released, 1);
futureReceipts.forgetFutureDigests(new Set([receiptIdentityDigest(pendingFutureReceipt)]));
await futureReceipts.offer(pendingFutureReceipt);
check('Q12A reoffered receipt is admitted', admittedFuture.length, 1);
futureReceipts.dispose();
const issueGateAt = hook.indexOf('const canIssueReceiptAtChainTip = useCallback(async () => {');
const issueGateEnd = hook.indexOf('\n  }, [gameRpcSession, gameRpcVersion]);', issueGateAt);
assert(issueGateAt >= 0 && issueGateEnd > issueGateAt);
const issueGateText = hook.slice(issueGateAt, issueGateEnd + '\n  }, [gameRpcSession, gameRpcVersion]);'.length)
  .replace('useCallback(', '(').replace(/, \[gameRpcSession, gameRpcVersion\]\);$/, ');');
let observedChainTime = close + 1;
const issueGateScope = { chainTimelineRef: { current: { chatCloseAt: close } },
  confirmedChatWindowRef: { current: null }, CHAT_WINDOW_CLOCK_SKEW_MS: 120000,
  readReceiptChainTime: async () => observedChainTime, receiptChainClockRef: { current: {} },
  gameRpcSession: null, readTimeChainTipMs: async () => observedChainTime };
const officialIssueGate = new Function(...Object.keys(issueGateScope),
  `${issueGateText}\nreturn canIssueReceiptAtChainTip;`)(...Object.values(issueGateScope));
check('T1-5 official chain after close blocks issue', await officialIssueGate(), false);
observedChainTime = close;
check('T1-5 official chain at close permits issue', await officialIssueGate(), true);
observedChainTime = null;
check('T1-5 official unreadable chain retains device phase gate', await officialIssueGate(), true);
const recoveryGateAt = app.indexOf('async function canIssueReceiptAtChainTip() {');
const recoveryGateEnd = app.indexOf('\nasync function issueActionReceipt(', recoveryGateAt);
assert(recoveryGateAt >= 0 && recoveryGateEnd > recoveryGateAt);
const recoveryIssueGate = new Function('state', 'submissionChatCloseAt', 'readReceiptChainTime',
  `${app.slice(recoveryGateAt, recoveryGateEnd)}\nreturn canIssueReceiptAtChainTip;`)(
    { relay: { _chainClock: {}, getChainTimeMs: async () => close + 1 } }, () => close,
    async (_clock, read) => read());
check('T1-5 recovery chain after close blocks issue', await recoveryIssueGate(), false);
const recoveryBatchAt = app.indexOf('async function issueReadReceiptBatch(');
const recoveryBatchEnd = app.indexOf('\n// 既読マップ:', recoveryBatchAt);
assert(recoveryBatchAt >= 0 && recoveryBatchEnd > recoveryBatchAt);
const recoveryMessage = { uid: 'V', signature: 'recovery-honest', timestamp: Date.now() };
const recoveryPublished = [];
let recoveryChainAllows = false;
const recoveryReadState = { identity: { signKey: 'key' }, blockNum: 1, groupId: 1,
  uid: 'me', receipts: {}, away: false, issuedReadMsgKeys: new Set(), members: [{ uid: 'me' }, { uid: 'V' }],
  ownSessionReadSignatures: new Set(), ownSessionSignatures: new Set(), messageReceiptableAt: new Map(),
  firstLiveSnapshotComplete: true, cfg: { pins: { chatCaps: { maxMessages: 100 } } },
  relay: { getMessages: () => [recoveryMessage], getRememberedMessages: () => [],
    getMsgKey: () => `0x${'ab'.repeat(32)}`,
    isLiveOnlyMessage: () => false, _chainClock: {},
    publishReceipt: async (receipt) => recoveryPublished.push(receipt) } };
const recoveryBatchScope = { state: recoveryReadState, rosterReady: () => true,
  clientNow: () => Date.now(),
  recoveryClock: { getClockCorrection: () => 0 },
  receiptIssuanceBlocked: () => false,
  nextReadReceiptTimestamp: ({ clockMs }) => clockMs,
  currentPhase: () => 'chatting', clientReceiptableMessages: (messages) => messages,
  submissionChatWindow: () => null, normalizeChatCaps: (caps) => caps,
  canonicalComparatorV2: () => () => 0, isReceiptTimely: () => true,
  RECEIPT_FRESH_WINDOW_MS: 600_000, CHAT_WINDOW_CLOCK_SKEW_MS: 120_000,
  performance, submissionChatCloseAt: () => Date.now() + 60000,
  canIssueReceiptAtChainTip: async () => recoveryChainAllows,
  msgRefOf: (key) => key.slice(0, 34),
  privateKeyToAccount: () => ({ signMessage: async () => 'signature' }),
  canonicalizeSignature: (value) => value, readReceiptSignString: () => 'signed',
  compareHexAsc: (a, b) => a.localeCompare(b),
  sessionStorage: { getItem: () => null, setItem: () => {} },
  recoveryAdmittedReceipts: () => Object.values(recoveryReadState.receipts),
  log: (message) => { throw new Error(message); } };
const recoveryBatch = new Function(...Object.keys(recoveryBatchScope),
  `${app.slice(recoveryBatchAt, recoveryBatchEnd)}\nreturn issueReadReceiptBatch;`)(
    ...Object.values(recoveryBatchScope));
await recoveryBatch();
check('T1-5 recovery read blocked when chain tip is after close', recoveryPublished.length, 0);
recoveryChainAllows = true;
await recoveryBatch();
check('T1-5 recovery read permitted before close', recoveryPublished.length, 1);

assert.deepEqual(failures, [], failures.join('\n'));
console.log('T1m regression: ALL PASSED');

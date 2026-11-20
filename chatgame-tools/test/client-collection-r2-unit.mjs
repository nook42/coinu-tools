// T1 U-6/U-12/U-13: 篩いと窓を上限より先に適用し、未来の発言を保留する。
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { privateKeyToAccount } from 'viem/accounts';
import {
  buildMsgKeyGetter, canonicalComparatorV2, clientScoreableMessages,
  clientReceiptableMessages, clientWindowedReceipts, computeMsgKeyV2, msgRefOf,
  readReceiptSignString,
} from '../vendor/workers/game_workers/lib/protocol-v2.js';
import { capMessagesForScoring } from '../vendor/workers/game_workers/lib/char-counter.js';
import { FutureAdmissionMarks, LiveSnapshotRejectionMemory } from '../vendor/src/utils/relay.js';
import { hasTimestampVisibleConfirmedVote } from '../src/recovery/app.js';

const account = privateKeyToAccount(`0x${'11'.repeat(32)}`);
const blockNum = 4;
const groupId = 0;
const base = 1_750_000_000_000;
const window = { startMs: base - 120_000, endMs: base + 500_000 };
const caps = { maxMessages: 2, maxChars: 10_000, maxMsgChars: 1000 };
const cmp = canonicalComparatorV2(buildMsgKeyGetter(blockNum, groupId));
const msg = (uid, text, timestamp) => ({ uid, text, timestamp });
const receipt = async (receiverUid, message, timestamp) => {
  const ref = msgRefOf(computeMsgKeyV2(blockNum, groupId, message));
  const msgRefs = [ref];
  return { receiverUid, senderUid: message.uid, msgRefs, timestamp,
    signature: await account.signMessage({ message: readReceiptSignString(
      blockNum, groupId, receiverUid, message.uid, msgRefs, timestamp,
    ) }) };
};

const voidMessage = msg('M', 'void', base);
const valid1 = msg('M', 'valid-one', base + 1000);
const valid2 = msg('M', 'valid-two', base + 2000);
const reads = [await receipt('H', valid1, base + 1000), await receipt('H', valid2, base + 2000)];
const source = [voidMessage, valid1, valid2];
const options = { blockNum, groupId, myUid: 'V', chatWindow: window, caps, compare: cmp };
const picked = process.env.T1_MUTATION === 'cap_first'
  ? clientScoreableMessages(capMessagesForScoring(source, caps, cmp), reads, options)
  : clientScoreableMessages(source, reads, options);
assert.deepEqual(picked, [valid1, valid2], 'U-6: void cannot spend a cap slot');
const oldOrder = clientScoreableMessages(capMessagesForScoring(source, caps, cmp), reads, options);
assert.deepEqual(oldOrder, [valid1], 'mutation: cap-before-receipt loses one valid message');
assert.deepEqual(clientReceiptableMessages(source, [], { ...options, timestamp: base + 2000 }),
  [voidMessage, valid1], 'fresh, not-yet-read candidates still consume the cap');
assert.deepEqual(clientReceiptableMessages(source, [], { ...options, timestamp: base + 700_001 }),
  [], 'stale void messages never consume the cap');

const confirmedVote = { encrypted: 'cipher', timestamp: base + 1000 };
const voteEligible = (receiptors) => hasTimestampVisibleConfirmedVote({
  votes: [confirmedVote], ownUid: 'V', targetUid: 'M', nowMs: base + 10_000,
  receiptorsForVote: () => receiptors,
});
assert.equal(voteEligible(['H']), true, '報告は第三者の受領証明がある票の後で可能');
assert.equal(voteEligible(['V']), false, '見る人自身の受領証明では報告できない');

const outside = await receipt('H', valid2, window.endMs + 1);
assert.deepEqual(process.env.T1_MUTATION === 'outside_read'
  ? [...reads, outside] : clientWindowedReceipts([...reads, outside], window, 'V'), reads,
  'U-12: other-member outside read cannot replace or travel in second tier');
assert.deepEqual(clientWindowedReceipts([...reads, outside], null, 'V'), [...reads, outside],
  'U-12: no confirmed window keeps every candidate and submission proceeds with a warning');

let now = base;
const queue = new FutureAdmissionMarks({ blockNum, groupId, now: () => now });
const future1 = { ...valid1, timestamp: base + 120_001,
  signature: await account.signMessage({ message: 'future-1' }) };
const future2 = { ...valid2, timestamp: base + 120_002,
  signature: await account.signMessage({ message: 'future-2' }) };
const future3 = { ...valid2, timestamp: base + 120_003,
  signature: await account.signMessage({ message: 'future-3' }) };
assert.equal(process.env.T1_MUTATION === 'drop_future'
  ? false : queue.discard('chat', future1), true);
assert.equal(queue.discard('chat', future2), true);
assert.equal(queue.discard('chat', future3), true);
assert.equal(queue.marks.size, 3, 'Q18: verified future messages receive page-local marks');
now += 2;
assert.equal(queue.has('chat', future1), true, 'Q18: passage of time cannot accept a marked message');
assert.equal(queue.releaseEligible(1).released, 1, 'Q12A: forward correction releases eligible marks');

// U-10: 公式フックの live effect 本体を実行する。React と fetch は注入し、
// 接続状態・30秒周期・失敗時の live-only 巻き戻しを実際の分岐で確かめる。
const hookText = readFileSync(process.env.T3G_HOOK_SOURCE
  || new URL('../../src/hooks/useGameWebSocket.js', import.meta.url), 'utf8');
const liveMarker = hookText.indexOf('// WS が使えない間だけ公開 live を読む。');
const effectStart = hookText.indexOf('useEffect(() => {', liveMarker);
const effectEnd = hookText.indexOf('\n  }, [isSpectator', effectStart);
assert(liveMarker >= 0 && effectStart > liveMarker && effectEnd > effectStart);
const effectBody = hookText.slice(effectStart + 'useEffect('.length, effectEnd + 4);
let readCount = 0;
let failFetch = false;
let interval = null;
let cleared = false;
let displayed = [];
const liveMessage = { uid: 'M', text: 'live', timestamp: base + 1000, signature: 'live-signature' };
const socket = { current: { readyState: 3 } };
const liveOnly = { current: new Set() };
const queuedReceipts = [];
const liveReceipt = { receiverUid: 'V', senderUid: 'M', actionHash: 'action-hash' };
let liveOptions = null;
const liveOptionsHistory = [];
const liveVerifyCalls = [];
const effectScope = {
  isSpectator: false, uid: 'V', rosterStartConfirmed: true, phase: 'chatting',
  connectionStatus: process.env.T1_MUTATION === 'no_official_poll' ? 'connected' : 'superseded',
  isGameIdentityCurrent: () => true,
  wsRef: socket, WebSocket: { OPEN: 1 },
  selectCurrentRoster: () => ({ source: 'verified', members: [{ uid: 'M' }, { uid: 'V' }] }),
  liveRejectionsRef: { current: null }, LiveSnapshotRejectionMemory,
  chainTimelineRef: { current: {} }, chatWindowMsFromTimeline: () => window,
  chatEndedRef: { current: false },
  readLiveSnapshot: async () => { readCount++; if (failFetch) throw new Error('stale'); return {}; },
  ROSTER_R2_BASE: 'https://example.invalid', blockNum, groupId,
  effectiveClientNow: () => Date.now(), clientNow: (raw = Date.now()) => raw, setLocalWarning: () => {},
  receiptsRef: { current: {} }, receiptIdentityDigest: () => null,
  verifyLiveSnapshotEntries: async (_snapshot, options) => {
    liveOptions = options;
    liveOptionsHistory.push(options);
    return { messages: [liveMessage], actions: [], receipts: [liveReceipt] };
  },
  GUEST_PINNED_RULES: { maxMsgChars: 1000 },
  maxMsgCharsRef: { current: 1000 },
  verifyIncomingMessage: async () => true,
  verifyRelayInner: async (type) => { liveVerifyCalls.push(['raw', type]); return true; },
  verifyCounted: async (type, _inner, options) => {
    liveVerifyCalls.push(['counted', type, options?.relayAction === true]); return true;
  }, liveOnlyMessagesRef: liveOnly,
  setMessages: (update) => { displayed = update(displayed); },
  mergeMessagesV2: (old, incoming) => [...old, ...incoming],
  observedActionsRef: { current: { votes: {}, reports: {} } },
  ingestObservedAction() {}, liveOnlyActionsRef: { current: new Set() },
  queueReceipt: async (receipt) => { queuedReceipts.push(receipt); return true; },
  liveOnlyReceiptsRef: { current: new Map() },
  receiptAdmissionRef: { current: { forgetLiveReceipt() {}, beginSelectionBatch: () => () => {} } },
  receiptHistoryRemainingRef: { current: 0 },
  setObservedActions() {}, saveJson() {}, OBSERVED_ACTIONS_KEY: () => '',
  LIVE_SNAPSHOT_POLL_MS: 30_000,
  setInterval: (fn, ms) => { interval = { fn, ms }; return 1; },
  clearInterval: () => { cleared = true; },
};
const makeEffect = () => new Function(...Object.keys(effectScope),
  `return (${effectBody});`)(...Object.values(effectScope));
const pollStartedAt = Date.now();
let cleanup = makeEffect()();
await new Promise((resolve) => setTimeout(resolve, 0));
const pollObservedAt = Date.now();
assert.equal(readCount, 1, 'U-10: superseded starts a live read');
assert(liveOptions, 'W9F: live verification options were captured');
await liveOptions.verifyInner('receipt', liveReceipt);
assert.deepEqual(liveVerifyCalls, [['counted', 'receipt', false]],
  'W9F: live entry uses verifyCounted');
assert.deepEqual(displayed, [liveMessage], 'U-10: verified live item joins the official collection');
assert.equal(queuedReceipts.length, 1, 'T3: live action receipt enters the receipt queue');
const arrivalMark = Object.getOwnPropertyDescriptor(queuedReceipts[0], '_firstArrivalAt');
assert(Number.isFinite(arrivalMark?.value)
  && arrivalMark.value >= pollStartedAt && arrivalMark.value <= pollObservedAt,
  'T3: live action receipt has a locally assigned arrival mark');
assert.equal(arrivalMark.enumerable, false, 'T3: local arrival mark is not serialized');
assert.equal(interval.ms, 30_000, 'U-10: poll interval is approximately 30 seconds');
failFetch = true;
interval.fn();
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(readCount, 2);
assert.deepEqual(displayed, [liveMessage], 'U-10: one failed read retains verified live item');
socket.current.readyState = 1;
interval.fn();
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(readCount, 2, 'U-10: OPEN socket stops public reads');
cleanup();
assert(cleared, 'U-10: cleanup cancels poll timer');
effectScope.connectionStatus = 'connected';
assert.equal(makeEffect()(), undefined, 'U-10: connected session never starts a poll');
assert.equal(readCount, 2);
effectScope.connectionStatus = 'superseded';
socket.current.readyState = 3;
failFetch = false;
const cleanupSecond = makeEffect()();
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(liveOptionsHistory.length, 2, 'S3R5: two successful polls provide verification options');
assert(liveOptionsHistory[0].rejectionMemory instanceof LiveSnapshotRejectionMemory,
  'S3R5: official live uses rejection memory');
assert.equal(liveOptionsHistory[0].rejectionMemory, liveOptionsHistory[1].rejectionMemory,
  'S3R5: official live reuses the memory across effects');
assert.deepEqual(liveOptionsHistory[1].verifierMembers(), effectScope.selectCurrentRoster().members,
  'S3R5: verifier roster follows the current roster');
cleanupSecond();
console.log('client-collection-r2-unit: ALL PASSED');

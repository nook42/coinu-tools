import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { openReadReceiptPause, readReceiptTickGap } from '../vendor/src/utils/read-receipt-pause.js';
import { privateKeyToAccount } from 'viem/accounts';
import {
  actionHashV2, buildMsgKeyGetter, canonicalComparatorV2, clientReceiptableMessages, chatSignStringV2,
  computeMsgKeyV2, msgRefOf, readReceiptSignString, receiptSignString,
} from '../../workers/game_workers/lib/protocol-v2.js';
import { GUEST_PINNED_RULES } from '../../workers/game_workers/lib/char-counter.js';
import { FutureAdmissionMarks, ReceiptAdmissionQueue, GameRelayChannel,
  buildEvent, deriveNostrKey, groupTag } from '../vendor/src/utils/relay.js';
import { nextReadReceiptTimestamp } from '../vendor/src/utils/chainClock.js';
import { describeTrimPlan } from '../../src/utils/evidence.js';

const account = privateKeyToAccount(`0x${'31'.repeat(32)}`);
const blockNum = 4, groupId = 2, now = Date.now();
const getKey = buildMsgKeyGetter(blockNum, groupId);
const cmp = canonicalComparatorV2(getKey);
const message = (text, timestamp) => ({ uid: 'M', text, timestamp, signature: `s-${text}` });
const older = message('older', now - 3000);
const middle = message('middle', now - 2000);
const newer = message('newer', now - 1000);
const refOf = (m) => msgRefOf(computeMsgKeyV2(blockNum, groupId, m));
const signRead = async (receiverUid, msgs, timestamp) => {
  const msgRefs = msgs.map(refOf).sort();
  return { receiverUid, senderUid: 'M', msgRefs, timestamp,
    signature: await account.signMessage({ message: readReceiptSignString(
      blockNum, groupId, receiverUid, 'M', msgRefs, timestamp,
    ) }) };
};
const caps = { maxMessages: 2, maxChars: 10_000, maxMsgChars: 1000 };
const context = { blockNum, groupId, myUid: 'V', timestamp: now, caps, compare: cmp };
const covered = [await signRead('H', [middle], now - 500), await signRead('H', [newer], now - 500)];
assert.deepEqual(clientReceiptableMessages([middle, newer, older], covered, context),
  [middle, newer], 'U-15: later backdate cannot evict already covered messages');
assert.deepEqual(clientReceiptableMessages([middle, newer], covered, context),
  [middle, newer], 'U-15: honest incremental messages remain receiptable');
assert.deepEqual(clientReceiptableMessages([newer, older], [], {
  ...context, caps: { ...caps, maxMessages: 1 },
}), [older], 'FRO: unread candidates with the same signing time use canonical order');
for (const [count, chars] of [[100, 100], [50, 200]]) {
  const prior = Array.from({ length: count }, (_, i) =>
    message(`${i.toString().padStart(3, '0')}${'x'.repeat(chars - 3)}`, now - 100000 + i * 1000));
  const lateBackdate = message('z'.repeat(chars), now - 101000);
  const coveredLast = await signRead('H', [prior.at(-1)], now - 500);
  const actual = clientReceiptableMessages([...prior, lateBackdate], [coveredLast], {
    ...context, caps: GUEST_PINNED_RULES,
  });
  assert(actual.includes(prior.at(-1)),
    `FRO: production ${count} messages / 10000 chars preserve first-read boundary`);
}

let clock = now;
const window = { startMs: now - 10_000, endMs: now + 900_000 };
let correction = 0;
const future = new FutureAdmissionMarks({ blockNum, groupId, now: () => clock,
  correction: () => correction });
const f1 = { uid: 'M', text: 'far-1', signature: await account.signMessage({ message: 'far-1' }), timestamp: now + 500_000 };
const f2 = { uid: 'M', text: 'far-2', signature: await account.signMessage({ message: 'far-2' }), timestamp: now + 600_000 };
assert.equal(future.discard('chat', f1), true);
assert.equal(future.discard('chat', f2), true);
clock = now + 500_000;
assert.equal(future.has('chat', f1), true, 'Q18: time passing does not admit a marked chat');
correction = 380_000;
assert.equal(future.releaseEligible().released, 1, 'Q12A: correction releases only eligible marks');
assert.equal(future.has('chat', f2), true, 'Q12A: larger excess remains marked');

const own1 = await signRead('V', [older, middle], now);
const own2 = await signRead('V', [middle, newer], now + 1);
const ownQueue = new ReceiptAdmissionQueue({
  getRosterUids: () => ['V', 'M'], verifyReceipt: async () => true,
  resolveReceipt: (rc) => ({ state: 'covered', facts: rc.msgRefs.map((ref) => `r|V|M|${ref}`) }),
  getChatWindow: () => window,
  getSelectionContext: () => ({ messages: [older, middle, newer], blockNum, groupId,
    myUid: 'V', caps: GUEST_PINNED_RULES }),
});
await ownQueue.offer(own1, { verified: true });
await ownQueue.offer(own2, { verified: true });
assert.deepEqual(new Set(ownQueue.getAcceptedReceipts().map((rc) => rc.signature)),
  new Set([own1.signature, own2.signature]),
  'CRITIC-I1: overlapping self receipts from two tabs both reach aggregation');
ownQueue.dispose();

const voteHash = actionHashV2('vote', blockNum, groupId, 'V', '0xdead', now - 1000);
const actionReceipt = async (timestamp) => ({ receiverUid: 'H', actionHash: voteHash, timestamp,
  signature: await account.signMessage({ message: receiptSignString(
    blockNum, groupId, 'H', voteHash, timestamp,
  ) }) });
let confirmed = null;
const twin = new ReceiptAdmissionQueue({
  getRosterUids: () => ['V', 'H'], verifyReceipt: async () => true,
  resolveReceipt: () => ({ state: 'covered', facts: [`a|H|${voteHash}`] }),
  getChatWindow: () => confirmed, allowWindowless: () => true,
  getSelectionContext: () => ({ messages: [], blockNum, groupId, myUid: 'V' }),
});
const out = await actionReceipt(now + 3000);
const inside = await actionReceipt(now + 1000);
await twin.offer(out, { verified: true });
await twin.offer(inside, { verified: true });
confirmed = { startMs: now - 10_000, endMs: now + 2000 };
await twin.reevaluate();
assert.deepEqual(twin.getAcceptedReceipts().map((rc) => rc.signature), [inside.signature],
  'F-1e-03: a windowless twin cannot permanently displace the in-window vote receipt');
twin.dispose();

const plan = { droppedTotal: 10, droppedH: 1, droppedG: 1, droppedF: 1,
  droppedE: 1, droppedC: 1, droppedD: 1, droppedR: 1, droppedA: 1, droppedB: 1, droppedV: 1 };
const description = describeTrimPlan(plan, { t: (key) => key });
const classes = [...description.matchAll(/・([HGFEC DRABV]):\s*(\d+)/g)].map((match) => match[1]);
assert.deepEqual(classes, ['H', 'G', 'F', 'E', 'C', 'D', 'R', 'A', 'B', 'V']);
assert.equal(classes.length, plan.droppedTotal, 'E-2e-04: every dropped class is described');

// 公式の実際の自動既読 tick を切り出し、live の印だけを変えて比較する。
const hookText = readFileSync(process.env.T1D_HOOK_OVERRIDE
  || new URL('../../src/hooks/useGameWebSocket.js', import.meta.url), 'utf8');
const marker = hookText.indexOf('const readReceiptTick = async () => {');
const start = hookText.indexOf('async () => {', marker);
const end = hookText.indexOf('};\n    readReceiptTimerRef.current', start);
assert(marker >= 0 && end > start);
const tickText = hookText.slice(start, end + 1);
const liveMessage = { ...middle, signature: await account.signMessage({ message:
  chatSignStringV2(blockNum, groupId, middle.uid, middle.text, middle.timestamp) }) };
const runTick = async (liveOnly, relayCopy = null) => {
  const published = [];
  const scope = {
    isGameIdentityCurrent: () => true, rosterStartConfirmedRef: { current: true },
    phaseRef: { current: 'chatting' }, isAwayRef: { current: false },
    sessionActivityRef: { current: { warned: false, ended: false } },
    receiptIssuanceBlocked: () => false,
    messagesRef: { current: [liveMessage] }, clientReceiptableMessages,
    readReceiptPauseRef: { current: { until: -1, lastIssuedAt: 0, lastTickAt: performance.now() } },
    performance, READ_RECEIPT_BATCH_MS: 8000, openReadReceiptPause, readReceiptTickGap, Date,
    detectClockStep: () => false, clientNow: () => Date.now(),
    getClockCorrection: () => 0, nextReadReceiptTimestamp,
    verifiedRosterRef: { current: { members: [{ uid: 'M' }, { uid: 'V' }] } },
    receiptsRef: { current: {} }, blockNum, groupId, uid: 'V',
    chatWindowMsFromTimeline: () => window, chainTimelineRef: { current: {} },
    GUEST_PINNED_RULES, canonicalComparatorV2, buildMsgKeyGetter, getClientMsgKey: getKey,
    issuedReadCountBySenderRef: { current: {} },
    canIssueReceiptAtChainTip: async () => true,
    isReceiptTimely: (a, b) => Math.abs(a - b) <= 600_000,
    msgRefOf, computeMsgKeyV2, issuedReadMsgKeysRef: { current: new Set() },
    issuingReadMsgKeysRef: { current: new Set() }, privateKeyToAccount,
    readReceiptTickRunningRef: { current: false },
    signKey: `0x${'32'.repeat(32)}`, compareHexAsc: (a, b) => a.localeCompare(b),
    canonicalizeSignature: (signature) => signature, readReceiptSignString,
    queueReceipt: async () => true, send: () => {},
    coordinateSelfReadReceiptBatch: async (_key, _acceptKnown, issue) => issue(),
    rememberOwnReadSignature: () => {},
    readReceiptChannelRef: { current: null },
    relayChannelRef: { current: { publishReceipt: (receipt) => published.push(receipt) } },
    liveOnlyMessagesRef: { current: liveOnly ? new Set([liveMessage.signature]) : new Set() },
    console,
  };
  if (relayCopy) {
    const propStart = hookText.indexOf('        isAccepted: (type, inner) => {');
    const propEnd = hookText.indexOf('\n        },', propStart);
    assert(propStart >= 0 && propEnd > propStart, 'T2 extracts the official isAccepted callback');
    let acceptedSource = hookText.slice(propStart + '        isAccepted: '.length, propEnd + 10)
      .replace(/,\s*$/, '');
    if (process.argv.includes('--mutation=t2-hook-liveonly-keep')) {
      const previous = acceptedSource;
      acceptedSource = acceptedSource.replace('if (known) liveOnlyMessagesRef.current.delete(inner.signature);', '');
      assert.notEqual(acceptedSource, previous, 'T2 hook mutation applies');
    }
    const isAccepted = new Function('messagesRef', 'liveOnlyMessagesRef',
      `return (${acceptedSource});`)(scope.messagesRef, scope.liveOnlyMessagesRef);
    const senderNostr = deriveNostrKey(`0x${'31'.repeat(32)}`, blockNum);
    const viewerNostr = deriveNostrKey(`0x${'32'.repeat(32)}`, blockNum);
    let verified = 0, onChat = 0, future = 0;
    const channel = new GameRelayChannel({ signKey: `0x${'32'.repeat(32)}`,
      blockNum, groupId, uid: 'V', members: [{ uid: 'M' }, { uid: 'V' }], isAccepted,
      verifyInnerSignature: async () => { verified++; return false; },
      onChat: () => { onChat++; }, futureMarks: { noteEvent: () => { future++; return false; } },
      now: () => now });
    channel.validNostrByUid = new Map([['M', senderNostr.pubkey], ['V', viewerNostr.pubkey]]);
    const inner = { type: 'chat', blockNum, groupId, ...liveMessage,
      ...(relayCopy === true ? {} : relayCopy) };
    const ev = buildEvent(senderNostr.sk, senderNostr.pubkey,
      [['t', groupTag(blockNum, groupId)]], JSON.stringify(inner), Math.floor(now / 1000));
    await channel._handleEvent(ev);
    if (relayCopy === true) assert.deepEqual([verified, onChat, future], [0, 0, 0],
      'T2: a known relay arrival does not reverify, reingest or revisit future marks');
  }
  const tick = new Function(...Object.keys(scope), `return (${tickText});`)(...Object.values(scope));
  await tick();
  return published;
};
assert.equal((await runTick(true)).length, 0, 'U-10: official tick skips live-only message');
assert.equal((await runTick(false)).length, 1, 'U-10: a verified WS/P2P message remains receiptable');
assert.equal((await runTick(true, true)).length, 1, 'T2: live then relay makes the official tick receiptable');
assert.equal((await runTick(false, true)).length, 1, 'T2: relay then live has no live-only mark');
for (const changed of [{ uid: 'V' }, { text: 'different' }, { timestamp: liveMessage.timestamp + 1 },
  { signature: `${liveMessage.signature}00` }]) {
  assert.equal((await runTick(true, changed)).length, 0,
    'T2: a different field cannot remove the official live-only mark');
}

console.log('T1d client regression: ALL PASSED');

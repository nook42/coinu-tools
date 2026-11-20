import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { readFileSync } from 'node:fs';
const { ReceiptAdmissionQueue, RelayPool, RECEIPT_PENDING_TTL_MS } = await import(
  process.env.T2_RELAY_OVERRIDE || new URL('../../src/utils/relay.js', import.meta.url));
const { actionHashV2, buildMsgKeyGetter, buildRealTargets, computeMsgKeyV2, msgRefOf,
  receiptCoverClaim, clientReadReceiptAdmission, isActionHash } = await import(
  process.env.T2_PROTOCOL_OVERRIDE || new URL('../../workers/game_workers/lib/protocol-v2.js', import.meta.url));
import { GUEST_PINNED_RULES } from '../../workers/game_workers/lib/char-counter.js';
const { mergeChainWindows } = await import(process.env.T2_TIMELINE_OVERRIDE
  || new URL('../../workers/game_workers/lib/timeline-check.js', import.meta.url));

const B = 7, G = 3, now = Date.now();
const hook = readFileSync(process.env.T2_HOOK_OVERRIDE
  || new URL('../../src/hooks/useGameWebSocket.js', import.meta.url), 'utf8');
const window = { startMs: now - 100_000, endMs: now + 100_000 };
const chainWindow = { chatOpenAt: 1, chattingStart: 2, chatCloseAt: 3, resultOpenAt: 3, resultCloseAt: 4 };
assert.equal(mergeChainWindows(chainWindow, { ...chainWindow }), chainWindow,
  'same chain window keeps reference');
assert.notEqual(mergeChainWindows(chainWindow, { ...chainWindow, chatCloseAt: 5 }), chainWindow,
  'extended window changes reference');
const fakeSig = (n) => `0x${n.toString(16).padStart(64, '0')}${'22'.repeat(32)}1b`;
const message = (n, text) => ({ uid: '2', text, timestamp: now + n, signature: fakeSig(n + 1) });
const receipt = (n, msg) => ({ receiverUid: '1', senderUid: '2',
  msgRefs: [msgRefOf(computeMsgKeyV2(B, G, msg))], timestamp: msg.timestamp, signature: fakeSig(n + 10_000) });

function fixture(messages, receipts, incremental = true) {
  let currentMessages = messages;
  let currentWindow = window;
  const accepted = new Set();
  const removed = [];
  const getKey = buildMsgKeyGetter(B, G);
  let targetCache = null, builds = 0, resolves = 0;
  const queue = new ReceiptAdmissionQueue({
    getRosterUids: () => ['1', '2'], verifyReceipt: async () => true,
    getChatWindow: () => currentWindow,
    getSelectionContext: () => ({ messages: currentMessages, blockNum: B, groupId: G,
      myUid: '1', getClientMsgKey: getKey }),
    ...(incremental ? { getMaterialState: () => ({
      keys: currentMessages.map((m) => `m|${m.uid}|${m.signature}`),
      roster: ['1', '2'], window: currentWindow,
    }) } : {}),
    resolveReceipt: (rc, roster) => {
      resolves++;
      if (!targetCache || targetCache.messages !== currentMessages) {
        targetCache = { messages: currentMessages,
          targets: buildRealTargets({}, currentMessages, B, G, getKey) }; builds++;
      }
      const targets = targetCache.targets;
      const admitted = clientReadReceiptAdmission(rc, targets, { memberUids: roster,
        chatWindow: currentWindow, selfUid: '1' });
      return admitted.state === 'covered' ? { ...admitted, priority: 'F' } : admitted;
    },
    onAccept: (rc) => accepted.add(rc.signature),
    onRemove: (rc, reason) => { accepted.delete(rc.signature); removed.push(reason); },
  });
  return { queue, accepted, removed, receipts, get counts() { return { builds, resolves }; },
    setMessages(next) { currentMessages = next; },
    primeKeys() { for (const item of currentMessages) getKey(item); },
    setWindow(next) { currentWindow = next; },
    state() { return JSON.stringify([...queue.entries.values()].map((entry) =>
      [entry.receipt, entry.status, entry.reason, entry.priority, [...entry.facts].sort()]).sort((a, b) =>
      a[0].signature.localeCompare(b[0].signature))); },
  };
}

// 同じ集合の並び替え、材料追加、材料削除、窓縮小を旧全件再評価と逐次比較する。
const small = Array.from({ length: 12 }, (_, i) => message(i, `m${i}`));
const slips = small.map((m, i) => receipt(i, m));
const base = fixture([], slips, false), fast = fixture([], slips, true);
for (const rc of [...slips].sort((a, b) => b.timestamp - a.timestamp)) {
  await base.queue.offer(rc, { verified: true });
  await fast.queue.offer(rc, { verified: true });
}
for (const list of [small.slice(0, 6), [...small].reverse(), small.filter((_, i) => i !== 3)]) {
  base.setMessages(list); fast.setMessages(list);
  await base.queue.reevaluate(); await fast.queue.reevaluate();
  assert.equal(fast.state(), base.state(), 'incremental vs full states');
  assert.deepEqual([...fast.accepted].sort(), [...base.accepted].sort(), 'incremental vs full accepted');
}
const narrow = { startMs: now + 5, endMs: now + 100_000 };
base.setWindow(narrow); fast.setWindow(narrow);
await base.queue.reevaluate(); await fast.queue.reevaluate();
assert.equal(fast.state(), base.state(), 'narrowed window');
assert.deepEqual([...fast.accepted].sort(), [...base.accepted].sort());
base.queue.dispose(); fast.queue.dispose();

// 提出段階の窓なし受理後に確定窓が現れると、窓外の既読は撤回される。
const unwindowedBase = fixture([small[0]], [slips[0]], false);
const unwindowedFast = fixture([small[0]], [slips[0]], true);
for (const subject of [unwindowedBase, unwindowedFast]) {
  subject.setWindow(null);
  await subject.queue.offer(slips[0], { verified: true });
  await subject.queue.reevaluate();
  assert.equal(subject.accepted.size, 1);
  subject.setWindow({ startMs: now + 1, endMs: now + 100_000 });
  await subject.queue.reevaluate();
}
assert.equal(unwindowedFast.state(), unwindowedBase.state(), 'first confirmed window narrows materials');
assert.equal(unwindowedFast.accepted.size, 0);
unwindowedBase.queue.dispose(); unwindowedFast.queue.dispose();

let seed = 91;
const shuffle = (values) => [...values].sort(() => {
  seed = (seed * 1664525 + 1013904223) >>> 0;
  return (seed & 1) ? 1 : -1;
});
for (let trial = 0; trial < 8; trial++) {
  const ordered = shuffle(small);
  const offered = shuffle([...slips, { ...receipt(100 + trial, small[0]), senderUid: '3' }]);
  const full = fixture(ordered.slice(0, 5), offered, false);
  const memo = fixture(ordered.slice(0, 5), offered, true);
  for (const rc of offered) { await full.queue.offer(rc, { verified: true }); await memo.queue.offer(rc, { verified: true }); }
  for (const current of [ordered, ordered.slice(1), ordered.slice(0, 7)]) {
    full.setMessages(current); memo.setMessages(current);
    await full.queue.reevaluate(); await memo.queue.reevaluate();
    assert.equal(memo.state(), full.state(), `random trial ${trial}`);
  }
  full.queue.dispose(); memo.queue.dispose();
}

// React フックにある本物の resolveReceiptTarget 本体を抽出し、表の共有と世代破棄を実行する。
const resolverSource = hook.match(/const resolveReceiptTarget = useCallback\(((?:.|\n)*?\n  }), \[blockNum, groupId, uid\]\);/);
assert(resolverSource, 'resolver source found');
const resolverMessages = { current: small.slice(0, 2),
  targetCache: { getter: buildMsgKeyGetter(B, G), built: null } };
const observedActionsRef = { current: { votes: {}, reports: {} } };
let actualBuilds = 0;
const bound = { messagesRef: resolverMessages, observedActionsRef,
  myVoteRef: { current: null }, myVotePrevRef: { current: [] }, myReportsRef: { current: [] },
  uid: '1', blockNum: B, groupId: G, confirmedChatWindowRef: { current: window },
  buildRealTargets: (...args) => { actualBuilds++; return buildRealTargets(...args); },
  receiptCoverClaim, clientReadReceiptAdmission, GUEST_PINNED_RULES,
  receiptMaxRefsPerReceipt: () => 100,
  isActionHash: () => false, actionHashV2: () => '',
};
const resolveActual = new Function(...Object.keys(bound), `return (${resolverSource[1]});`)(...Object.values(bound));
assert.equal(resolveActual(slips[0], ['1', '2']).state, 'covered');
assert.equal(resolveActual(slips[1], ['1', '2']).state, 'covered');
assert.equal(actualBuilds, 1, 'real target table shared across receipts');
resolverMessages.current = [...resolverMessages.current];
assert.equal(resolveActual(slips[0], ['1', '2']).state, 'covered');
assert.equal(actualBuilds, 2, 'changed message collection rebuilds once');
resolverMessages.targetCache = { getter: buildMsgKeyGetter(B, G), built: null };
assert.equal(resolveActual(slips[0], ['1', '2']).state, 'covered');
assert.equal(actualBuilds, 3, 'identity generation discards cached targets');

// T4: the actual resolver and admission queue must revisit an action receipt when a
// self vote reaches the saved history after receipt_history has been offered.
{
  const currentVote = { encrypted: 'first-vote', signature: fakeSig(30), timestamp: now };
  const laterVote = { encrypted: 'later-vote', signature: fakeSig(31), timestamp: now + 1 };
  const history = { current: [] };
  const messagesRef = { current: [], targetCache: { getter: null, built: null } };
  let builds = 0;
  const scope = { ...bound, uid: '1', myVoteRef: { current: currentVote }, myVotePrevRef: history,
    messagesRef, isActionHash, actionHashV2,
    buildRealTargets: (...args) => { builds++; return buildRealTargets(...args); } };
  const resolver = new Function(...Object.keys(scope), `return (${resolverSource[1]});`)(...Object.values(scope));
  const actionReceipt = { receiverUid: '2', actionHash: actionHashV2('vote', B, G,
    '1', laterVote.encrypted, laterVote.timestamp), timestamp: now + 2, signature: fakeSig(32) };
  const accepted = [], discarded = [];
  let queueNow = now + 3;
  const queue = new ReceiptAdmissionQueue({
    getRosterUids: () => ['1', '2'], isRosterVerified: () => true,
    verifyReceipt: async () => true, resolveReceipt: resolver,
    getChatWindow: () => window, getChatCloseAtMs: () => window.endMs,
    now: () => queueNow, isChatting: () => true,
    getSelectionContext: () => ({ messages: [], blockNum: B, groupId: G, myUid: '1' }),
    onAccept: (row) => accepted.push(row.signature),
    onDiscard: (_row, reason) => discarded.push(reason),
  });
  await queue.offer(actionReceipt, { verified: true });
  assert.equal([...queue.entries.values()][0]?.status, 'pending', 'receipt arrives before self history');
  history.current = [laterVote];
  await queue.reevaluate();
  assert.deepEqual(accepted, [actionReceipt.signature], 'receipt for saved self history is admitted');
  assert.equal(builds, 2, 'history reference invalidates the target cache');
  queueNow += RECEIPT_PENDING_TTL_MS + 1;
  await queue.reevaluate();
  assert.deepEqual(discarded, [], 'admitted former-vote receipt never reaches target_expired');
  assert.match(hook, /\[members, messages, observedActions, myVote, myVotePrev, myReports, chainTimeline, phase,/,
    'history state triggers the production reevaluation effect');
  assert(hook.indexOf('myVotePrevRef.current = myVotePrev') >= 0
    && hook.indexOf('myVotePrevRef.current = myVotePrev') < hook.indexOf('void queue?.reevaluate();'),
    'history ref is synchronized before the reevaluation effect');
  assert.equal((hook.match(/myVotePrevRef\.current = next;\s*setMyVotePrev\(/g) || []).length, 3,
    'each of the three history writers replaces the ref and schedules a new state array');
  queue.dispose();
}

// D-1c の攻撃盤面。初回のハッシュ生成後、400枚の定常再評価を測る。
for (const len of [60_000, 1_000]) {
  const text = 'x'.repeat(len);
  const flood = Array.from({ length: 1200 }, (_, i) => message(i, text));
  const proofs = flood.slice(0, 400).map((m, i) => receipt(i, m));
  const subject = fixture([], proofs);
  for (const rc of proofs) await subject.queue.offer(rc, { verified: true });
  subject.setMessages(flood);
  // 本番は mergeMessagesV2 が各受信時に同じ getter を使い、全発言の key を一度だけ作る。
  subject.primeKeys();
  const firstStart = performance.now();
  await subject.queue.reevaluate();
  const firstMs = performance.now() - firstStart;
  assert.equal(subject.accepted.size, 400);
  assert(firstMs < 1000, `${len}: first reevaluate ${firstMs.toFixed(2)}ms >= 1s`);
  const before = subject.counts;
  const start = performance.now();
  let yielded = false;
  setTimeout(() => { yielded = true; }, 0);
  await subject.queue.reevaluate();
  const ms = performance.now() - start;
  const after = subject.counts;
  assert.equal(after.builds, before.builds, 'unchanged targets built once');
  assert.equal(after.resolves, before.resolves, 'accepted entries skipped');
  assert(yielded, 'event loop yielded during 400 entries');
  assert(ms < 1000, `${len}: ${ms.toFixed(2)}ms >= 1s`);
  console.log(`T2 M1 len=${len} messages=1200 accepted=400 first=${firstMs.toFixed(2)}ms steady=${ms.toFixed(2)}ms builds=${after.builds}`);
  subject.queue.dispose();
}

assert.match(hook, /if \(cached\) cached\.built = \{ materials, targets: built \}/);
assert.match(hook, /getMaterialState: \(\) =>/);
assert.match(hook, /getClientMsgKey: getClientMsgKey|getClientMsgKey,/);
const submitSource = readFileSync(new URL('../../src/components/game/SubmissionPhase.js', import.meta.url), 'utf8');
assert.match(submitSource, /pendingReceiptCount > 0/);
// 2026-11-19（反証 D-4）: オンチェーンの準備中（preparingForChain）も「署名して提出」を止めるようにした。
// 受理待ちの数（pendingReceiptCount）は今どおり disabled の条件に入れない。
assert.match(submitSource, /disabled=\{isSubmitting \|\| preparingForChain \|\| addressMismatch \|\| quiescing\}/,
  '受理待ちの表示は提出ボタンを止めない');
assert(!/disabled=\{[^}]*pendingReceiptCount/.test(submitSource), '受理待ちの数を disabled の条件に入れない');
let readsProcessed = 0;
let readsWhenActionAccepted = null;
const actionQueue = new ReceiptAdmissionQueue({
  getRosterUids: () => ['1', '2'], verifyReceipt: async () => true,
  getChatWindow: () => window,
  getSelectionContext: () => ({ messages: [small[0]], blockNum: B, groupId: G, myUid: '2' }),
  resolveReceipt: (rc) => {
    if (rc.msgRefs) {
      readsProcessed++;
      const until = performance.now() + 1;
      while (performance.now() < until) { /* model costly target resolution */ }
    }
    return { state: 'covered',
      facts: rc.actionHash ? [`a|${rc.receiverUid}|${rc.actionHash}`]
        : [`r|${rc.receiverUid}|${rc.senderUid}|${rc.msgRefs[0]}`],
      priority: rc.actionHash ? 'B' : 'F' };
  },
  onAccept: (rc) => { if (rc.actionHash) readsWhenActionAccepted = readsProcessed; },
});
const queuedReads = Array.from({ length: 100 }, (_, i) => receipt(i + 100, small[0]))
  .map((rc) => actionQueue.offer(rc, { verified: true }));
const action = { receiverUid: '1', actionHash: `0x${'ab'.repeat(32)}`,
  timestamp: now, signature: fakeSig(999_999) };
await actionQueue.offer(action, { verified: true });
assert(readsWhenActionAccepted !== null && readsWhenActionAccepted < 100,
  '行動受領証明は先頭100枚の既読の対象解決を待たない');
await Promise.all(queuedReads);
actionQueue.dispose();
console.log('T2 receipt memo: ALL PASSED');

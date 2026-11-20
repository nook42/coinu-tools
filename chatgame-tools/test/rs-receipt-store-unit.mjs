import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { privateKeyToAccount } from 'viem/accounts';
import { CarriedReceiptStoreIndex, ReceiptClaimMemo, ReceiptAdmissionQueue } from '../../src/utils/relay.js';
import { receiptCanonCmp } from '../../workers/game_workers/lib/game-result-calculator.js';
import { limitCarriedReceiptFacts } from '../../workers/game_workers/lib/evidence-compact-v1.js';
import { readReceiptSignString, receiptSignString, receiptCoverClaim,
  chatSignStringV2, buildMsgKeyGetter, msgRefOf, compareHexAsc, computeMsgKeyV2,
  buildReceiptMaps, clientScoreableMessages } from '../../workers/game_workers/lib/protocol-v2.js';
import { GUEST_PINNED_RULES, countVisibleChars, countMessageTurns,
  filterVisibleMessages } from '../../workers/game_workers/lib/char-counter.js';
import { planPriority, planReceiptSignatures } from '../../src/utils/priorityEvidence.js';
import { RecoveryRelay } from '../src/recovery/relay-client.js';

const hookSource = readFileSync(new URL('../../src/hooks/useGameWebSocket.js', import.meta.url), 'utf8');
const start = hookSource.indexOf('class ObservedReceiptWriter {');
const end = hookSource.indexOf('\n}\n', start);
assert(start >= 0 && end > start, 'the official writer can be extracted');
assert.match(hookSource, /const ingestReceipt = useCallback\([\s\S]*?getObservedReceiptWriter\(\)\?\.accept\(receiptWithArrival\)/,
  'the official acceptance callback uses this writer');
assert.match(hookSource, /const removeAcceptedReceipt = useCallback\([\s\S]*?getObservedReceiptWriter\(\)\?\.remove\(receipt\.signature\)/,
  'onRemove uses the same writer');
const mutation = process.argv.find((arg) => arg.startsWith('--mutation='))?.slice(11) || '';
let source = hookSource.slice(start, end + 2);
if (mutation === 'drop-disk') source = source.replaceAll(
  'this.index.syncDisk(loadJson(this.key, {}));', 'this.index.syncDisk({});');
if (mutation === 'no-batch') source = source.replace(
  'this.timer = setTimeout(() => { this.timer = null; void this.flush(); }, 50);',
  'this.flushSync();');
const uid = 'user0005', block = 1, group = 1, base = 1_900_000_000_000;
const accounts = Object.fromEntries(Array.from({ length: 5 }, (_, i) => [
  `user000${i + 1}`, privateKeyToAccount(`0x${(i + 1).toString(16).padStart(64, '0')}`),
]));
const refs = Array.from({ length: 100 }, (_, i) => `0x${i.toString(16).padStart(32, '0')}`);
let serial = 0;
async function signedRead(issuer, sender, msgRefs, timestamp) {
  const signature = await accounts[issuer].signMessage({ message: readReceiptSignString(
    block, group, issuer, sender, msgRefs, timestamp,
  ) });
  return { receiverUid: issuer, senderUid: sender, msgRefs, timestamp, signature };
}
async function signedAction(issuer, timestamp) {
  const actionHash = `0x${(++serial).toString(16).padStart(64, '0')}`;
  const signature = await accounts[issuer].signMessage({ message: receiptSignString(
    block, group, issuer, actionHash, timestamp,
  ) });
  return { receiverUid: issuer, actionHash, timestamp, signature };
}
const issuers = Object.keys(accounts).filter((name) => name !== uid);
const honest = [];
for (const issuer of issuers) {
  for (let i = 0; i < 85; i++) honest.push(await signedRead(issuer, uid, [refs[i]], base + i * 1000 + issuers.indexOf(issuer)));
}
for (let i = 0; i < 400; i++) honest.push(await signedRead(uid, issuers[i % 4], [refs[Math.floor(i / 4)]], base + i * 1000));
assert.equal(honest.length, 740);

function makeStorage(limit = 5_000_000, background = 512_000) {
  const rows = new Map([['p2pRelayReceipts_background', 'x'.repeat(background)]]);
  const metrics = { writes: 0, bytes: 0, rejected: 0 };
  const storage = {
    getItem: (key) => rows.get(key) ?? null,
    setItem(key, value) {
      const next = new Map(rows); next.set(key, String(value));
      const chars = [...next].reduce((n, [k, v]) => n + k.length + v.length, 0);
      if (chars > limit) { metrics.rejected++; throw new Error('quota'); }
      rows.set(key, String(value)); metrics.writes++; metrics.bytes += String(value).length;
    },
  };
  return { rows, storage, metrics };
}
let nextTimer = 0;
const timers = new Map();
const setTimer = (callback) => { const id = ++nextTimer; timers.set(id, callback); return id; };
const clearTimer = (id) => timers.delete(id);
const runTimers = async () => { const callbacks = [...timers.values()]; timers.clear(); for (const callback of callbacks) await callback(); };
function writerFor(store, key = 'observedReceipts_1_group1_useruser0005', current = () => true) {
  const loadJson = (name, fallback) => { const raw = store.storage.getItem(name); return raw ? JSON.parse(raw) : fallback; };
  const saveJson = (name, value) => {
    try { store.storage.setItem(name, JSON.stringify(value)); return true; } catch { return false; }
  };
  const Writer = new Function('CarriedReceiptStoreIndex', 'receiptCanonCmp', 'loadJson', 'saveJson',
    'setTimeout', 'clearTimeout', `return (${source});`)(
      CarriedReceiptStoreIndex, receiptCanonCmp, loadJson, saveJson, setTimer, clearTimer);
  let warned = 0;
  const writer = new Writer(key, uid, current, () => { warned++; }, () => null);
  return { writer, warnings: () => warned, load: () => loadJson(key, {}) };
}
const signatures = (rows) => new Set(Object.values(rows).map((row) => row.signature));
const factCount = (rows) => Object.values(rows).reduce((n, row) => n + (row.msgRefs?.length || 1), 0);

// Honest W3 is byte identical to the former observedReceipts map.
{
  const ordinary = { observed: { receipts: honest } };
  assert.strictEqual(limitCarriedReceiptFacts(ordinary, { submitterUid: uid,
    compare: receiptCanonCmp }), ordinary, 'ordinary pure limiter preserves snapshot identity');
  const store = makeStorage(); const { writer, load } = writerFor(store);
  for (const receipt of honest) writer.accept(receipt);
  await writer.flush();
  assert.equal(JSON.stringify(load()), JSON.stringify(Object.fromEntries(honest.map((r) => [r.signature, r]))));
  assert.equal(store.metrics.writes, 1);
  writer.dispose();
}

// Signed flood shapes go directly to the writer as an independent store test.
const flood = [];
for (const issuer of issuers) for (let i = 0; i < 620; i++) {
  const ref = `0x${(i + issuers.indexOf(issuer) * 620 + 100).toString(16).padStart(32, '0')}`;
  flood.push(await signedRead(issuer, uid, [ref], base + 200_000 + i));
}
for (const issuer of issuers) for (let i = 0; i < 80; i++) flood.push(await signedAction(issuer, base + 300_000 + i));
const repeated = [];
const chain = [];
for (const issuer of issuers) {
  for (let i = 0; i < 700; i++) repeated.push(await signedRead(issuer, uid, refs, base + 100_000 + i));
  for (let length = 1; length <= 100; length++) chain.push(await signedRead(
    issuer, uid, refs.slice(0, length), base + 200_000 + length));
  for (let i = 0; i < 520; i++) chain.push(await signedRead(issuer, issuers[(issuers.indexOf(issuer) + 1) % 4],
    [`0x${(i + 200 + issuers.indexOf(issuer) * 520).toString(16).padStart(32, '0')}`], base + 300_000 + i));
  for (let i = 0; i < 80; i++) chain.push(await signedAction(issuer, base + 400_000 + i));
}
const boards = {
  RS4: repeated,
  WORST4C: chain,
  WORST4L: [...flood.slice(80), ...flood.slice(0, 80)],
  BACK4: [...repeated].reverse(),
  BACKLIM: [...flood.slice(0, 2160)].reverse(),
  CHAIN: chain.slice(0, 2100),
  SLIDE: chain.slice(0, 1400),
};
const results = [];
for (const [name, board] of Object.entries(boards)) {
  const store = makeStorage(); const { writer, warnings, load } = writerFor(store);
  const started = performance.now();
  for (let i = 0; i < board.length; i++) {
    writer.accept(board[i]);
    if ((i + 1) % 32 === 0) await writer.flush();
  }
  await writer.flush();
  const elapsedMs = Math.round(performance.now() - started);
  const saved = load();
  assert.equal(warnings(), 0, `${name}: no observed write failure`);
  assert.equal(store.metrics.rejected, 0, `${name}: no quota failure`);
  assert(JSON.stringify(saved).length < 2_000_000, `${name}: bounded durable bytes`);
  const issuerCounts = Object.values(saved).reduce((counts, row) => {
    counts[row.receiverUid] = (counts[row.receiverUid] || 0) + 1; return counts;
  }, {});
  assert(Object.values(issuerCounts).every((count) => count <= 700), `${name}: issuer cap`);
  const receiptWrites = store.metrics.writes;
  const receiptBytes = store.metrics.bytes;
  // All nine self keys, including a 300,000-character evidence record, fit.
  for (const [key, value] of Object.entries({
    myVote: 'v'.repeat(430), myReports: 'r'.repeat(4300), intent: 'i'.repeat(70),
    myVotePrev: 'p'.repeat(430), evidence_result: 'e'.repeat(300_000),
    evidence_roster_proof: 'o'.repeat(10_000), signKey_next: 's'.repeat(200),
    encryptKey_next: 'k'.repeat(200), keySig_next: 'g'.repeat(200),
  })) store.storage.setItem(key, value);
  assert.equal(store.metrics.rejected, 0, `${name}: nine self keys fit`);
  results.push({ name, receipts: Object.keys(saved).length, chars: JSON.stringify(saved).length,
    writes: receiptWrites, bytes: receiptBytes, elapsedMs });
  writer.dispose();
}
// 段A: 同じ7盤面を本物の offer/onAccept/onRemove から保存へ流す。
const queuedResults = [];
for (const [name, board] of Object.entries(boards)) {
  const store = makeStorage(); const { writer, warnings, load } = writerFor(store);
  let accepted = 0;
  const queue = new ReceiptAdmissionQueue({
    getRosterUids: () => Object.keys(accounts), isRosterVerified: () => true,
    getSelectionContext: () => ({ myUid: uid }),
    getChatWindow: () => ({ startMs: base, endMs: base + 1_000_000 }),
    now: () => base + 500_000,
    resolveReceipt: (receipt) => ({ state: 'covered', priority: 'F', facts: receipt.msgRefs
      ? receipt.msgRefs.map((ref) => `${receipt.receiverUid}|r:${receipt.senderUid}|${ref}`)
      : [`${receipt.receiverUid}|a:${receipt.actionHash}`] }),
    onAccept: (receipt) => { accepted++; writer.accept(receipt); },
    onRemove: (receipt) => writer.remove(receipt.signature),
  });
  const start = performance.now();
  for (let i = 0; i < board.length; i++) {
    await queue.offer(board[i], { verified: true });
    if ((i + 1) % 32 === 0) await writer.flush();
  }
  await writer.flush();
  const elapsedMs = Math.round(performance.now() - start);
  const saved = load();
  assert.equal(warnings(), 0, `${name}: queue -> writer warning`);
  assert.equal(store.metrics.rejected, 0, `${name}: queue -> writer quota`);
  assert(JSON.stringify(saved).length < 2_000_000, `${name}: queue -> writer bounded`);
  const counts = Object.values(saved).reduce((map, row) => {
    map[row.receiverUid] = (map[row.receiverUid] || 0) + 1; return map;
  }, {});
  assert(Object.values(counts).every((count) => count <= 700), `${name}: queue -> writer issuer cap`);
  queuedResults.push({ name, offered: board.length, accepted, saved: Object.keys(saved).length, elapsedMs });
  queue.dispose(); writer.dispose();
}
const rs4QueueTimes = [queuedResults.find((row) => row.name === 'RS4').elapsedMs];
for (let trial = 0; trial < 2; trial++) {
  const store = makeStorage(); const { writer } = writerFor(store);
  const queue = new ReceiptAdmissionQueue({
    getRosterUids: () => Object.keys(accounts), isRosterVerified: () => true,
    getSelectionContext: () => ({ myUid: uid }),
    getChatWindow: () => ({ startMs: base, endMs: base + 1_000_000 }), now: () => base + 500_000,
    resolveReceipt: (receipt) => ({ state: 'covered', priority: 'F',
      facts: receipt.msgRefs.map((ref) => `${receipt.receiverUid}|r:${receipt.senderUid}|${ref}`) }),
    onAccept: (receipt) => writer.accept(receipt),
    onRemove: (receipt) => writer.remove(receipt.signature),
  });
  const start = performance.now();
  for (let i = 0; i < boards.RS4.length; i++) {
    await queue.offer(boards.RS4[i], { verified: true });
    if ((i + 1) % 32 === 0) await writer.flush();
  }
  await writer.flush();
  rs4QueueTimes.push(Math.round(performance.now() - start));
  queue.dispose(); writer.dispose();
}
rs4QueueTimes.sort((a, b) => a - b);
assert(rs4QueueTimes[1] < 5000, `RS4 offer and save median ${rs4QueueTimes[1]}ms < 5s`);
console.log(`rs-store-real-offer ${JSON.stringify({ boards: queuedResults, rs4MedianMs: rs4QueueTimes[1] })}`);
if (process.argv.includes('--screen-speed')) {
  const screenWindow = { startMs: base, endMs: base + 1_000_000 };
  const screenMessages = [];
  for (const sender of Object.keys(accounts)) for (let i = 0; i < 100; i++) {
    const text = `screen ${sender} ${i}`;
    const timestamp = base + 1000 + i * 500;
    screenMessages.push({ uid: sender, text, timestamp,
      signature: await accounts[sender].signMessage({ message: chatSignStringV2(
        block, group, sender, text, timestamp,
      ) }) });
  }
  const screenRefs = Object.fromEntries(Object.keys(accounts).map((sender) => [sender,
    screenMessages.filter((message) => message.uid === sender)
      .map((message) => msgRefOf(buildMsgKeyGetter(block, group)(message)))]));
  const originalRefIndex = new Map(refs.map((ref, index) => [ref, index]));
  const forScreen = (rows) => rows.map((row) => !row.msgRefs ? row : ({ ...row,
    msgRefs: row.msgRefs.map((ref) => {
      const index = originalRefIndex.get(ref);
      return index === undefined ? ref : screenRefs[row.senderUid]?.[index] || ref;
    }).sort(compareHexAsc),
  }));
  const honestMax = [];
  for (const receiver of Object.keys(accounts)) for (const sender of Object.keys(accounts)) {
    if (receiver !== sender) honestMax.push(await signedRead(receiver, sender,
      [...screenRefs[sender]].sort(compareHexAsc), base + 100_000));
  }
  const screenBoards = { HONEST_MAX: honestMax,
    ...Object.fromEntries(Object.entries(boards).map(([name, rows]) => [name, forScreen(rows)])) };
  for (const [name, rows] of Object.entries(screenBoards)) {
    const start = performance.now();
    buildReceiptMaps(rows, { messages: screenMessages, myUid: uid }, block, group, screenWindow);
    const cold = clientScoreableMessages(screenMessages, rows, { blockNum: block, groupId: group,
      myUid: uid, chatWindow: screenWindow, caps: GUEST_PINNED_RULES, claimMemo: new ReceiptClaimMemo() });
    const coldMs = Math.round(performance.now() - start);
    const memo = new ReceiptClaimMemo();
    const acceptStart = performance.now();
    let maxPrimeMs = 0;
    for (const receipt of rows) {
      const oneStart = performance.now();
      memo.primeScoreable(receipt, screenMessages, { blockNum: block, groupId: group,
        selfUid: uid, chatWindow: screenWindow, caps: GUEST_PINNED_RULES });
      maxPrimeMs = Math.max(maxPrimeMs, performance.now() - oneStart);
    }
    const primeMs = Math.round(performance.now() - acceptStart);
    const warmStart = performance.now();
    buildReceiptMaps(rows, { messages: screenMessages, myUid: uid }, block, group, screenWindow);
    const warm = clientScoreableMessages(screenMessages, rows, { blockNum: block, groupId: group,
      myUid: uid, chatWindow: screenWindow, caps: GUEST_PINNED_RULES, claimMemo: memo });
    const warmMs = Math.round(performance.now() - warmStart);
    assert.deepEqual(warm, cold, `${name}: cold and warm screen bytes are identical`);
    assert(warmMs < 1000, `${name}: warmed screen ${warmMs}ms < 1s`);
    assert(primeMs < 5000, `${name}: accepted receipt priming ${primeMs}ms < 5s`);
    console.log(`rs-screen-speed ${JSON.stringify({ name, receipts: rows.length,
      refs: rows.reduce((n, row) => n + (row.msgRefs?.length || 0), 0),
      coldMs, warmMs, primeMs, maxPrimeMs: Number(maxPrimeMs.toFixed(2)), uptime: Number(process.uptime().toFixed(1)) })}`);
  }
}
const rs4Times = [results.find((row) => row.name === 'RS4').elapsedMs];
for (let trial = 0; trial < 2; trial++) {
  const store = makeStorage(); const { writer } = writerFor(store);
  const started = performance.now();
  for (let i = 0; i < boards.RS4.length; i++) {
    writer.accept(boards.RS4[i]);
    if ((i + 1) % 32 === 0) await writer.flush();
  }
  await writer.flush();
  rs4Times.push(Math.round(performance.now() - started));
  writer.dispose();
}
rs4Times.sort((a, b) => a - b);
assert(rs4Times[1] < 5000, `RS4 writer median ${rs4Times[1]}ms < 5s`);

// A paced BACK4 flushes after every signed receipt. The durable cap stays
// per-issuer even when the 50ms timer would fire before each next receipt.
let pacedBack4 = null;
{
  const store = makeStorage(); const { writer, load } = writerFor(store);
  for (const receipt of boards.BACK4) { writer.accept(receipt); await writer.flush(); }
  const byIssuer = Object.values(load()).reduce((counts, row) => {
    counts[row.receiverUid] = (counts[row.receiverUid] || 0) + 1; return counts;
  }, {});
  assert(Object.values(byIssuer).every((count) => count <= 700), 'paced BACK4 issuer cap');
  assert.equal(store.metrics.writes, boards.BACK4.length, 'one paced write per receipt');
  pacedBack4 = { writes: store.metrics.writes, bytes: store.metrics.bytes,
    chars: JSON.stringify(load()).length, maxIssuer: Math.max(...Object.values(byIssuer)) };
  writer.dispose();
}

// W3: a newly opened tab and a partial reload cannot overwrite the old set.
for (const mode of ['multitab', 'reload', 'expire']) {
  const store = makeStorage(); const first = writerFor(store);
  for (const row of honest) first.writer.accept(row);
  await first.writer.flush();
  const before = signatures(first.load());
  const second = writerFor(store);
  for (const row of honest.slice(0, mode === 'multitab' ? 32 : 604)) second.writer.accept(row);
  // Expired pending entries receive onDiscard, not onRemove.
  if (mutation === 'subtract-discard' && mode === 'expire') {
    for (const row of honest.slice(604)) second.writer.remove(row.signature);
  }
  await second.writer.flush();
  for (const signature of before) assert(signatures(second.load()).has(signature), `${mode}: no shrink`);
  first.writer.dispose(); second.writer.dispose();
}

{
  const originalNavigator = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  const calls = [];
  let tail = Promise.resolve();
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { locks: {
    request(name, callback) {
      calls.push(name);
      const next = tail.then(callback);
      tail = next.catch(() => {});
      return next;
    },
  } } });
  try {
    const store = makeStorage(); const first = writerFor(store); const second = writerFor(store);
    first.writer.accept(honest[0]); second.writer.accept(honest[1]);
    await Promise.all([first.writer.flush(), second.writer.flush()]);
    const saved = signatures(first.load());
    assert(saved.has(honest[0].signature) && saved.has(honest[1].signature),
      'locked concurrent tabs retain both receipts');
    assert.deepEqual(calls, Array(2).fill(`observedReceipts:${first.writer.key}`));
    first.writer.dispose(); second.writer.dispose();
  } finally {
    if (originalNavigator) Object.defineProperty(globalThis, 'navigator', originalNavigator);
    else delete globalThis.navigator;
  }
}

// Storage events only refresh the disk half of the index, and pagehide writes
// synchronously without waiting for navigator.locks. Identity loss drops work.
{
  const store = makeStorage(); const first = writerFor(store);
  first.writer.accept(honest[0]); await first.writer.flush();
  const second = writerFor(store);
  const writes = store.metrics.writes;
  second.writer.syncDisk(first.load());
  // Gift receipts expose the future P2a-2/P2b plan input: without it the
// durable material proves 14 turns, while the same signed set plus the plan
// preserves all 20 turns from memory. This test owns its fixture.
{
const gift = true;
const B = 1, G = 1, T0 = 1_900_000_000_000;
const uids = ['user0001', 'user0002', 'user0003', 'user0004', 'user0005'];
const acct = Object.fromEntries(uids.map((u, i) => [u, privateKeyToAccount(`0x${(i + 1).toString(16).padStart(64, '0')}`)]));
const [A1, A2, H, Bm, V] = uids;
const key = buildMsgKeyGetter(B, G);
const ref = (m) => msgRefOf(key(m));
const messages = [];
async function say(uid, text, timestamp) {
  const signature = await acct[uid].signMessage({ message: chatSignStringV2(B, G, uid, text, timestamp) });
  const m = { uid, text, timestamp, signature }; messages.push(m); return m;
}
async function rc(issuer, sender, refs, timestamp) {
  const msgRefs = [...refs].sort(compareHexAsc);
  const signature = await acct[issuer].signMessage({ message: readReceiptSignString(B, G, issuer, sender, msgRefs, timestamp) });
  return { receiverUid: issuer, senderUid: sender, msgRefs, timestamp, signature };
}
// timeline: 30 s steps
let t = T0 + 60_000;
const step = () => (t += 30_000);
const honestSeps = [], giftSeps = [];
// opening: H talks (A1 floods on these early H messages later)
for (let i = 0; i < 40; i++) await say(H, `H opening ${i} hello there`, step());
// 14 rounds: honest separator then V's run (2 messages)
for (let r = 0; r < 14; r++) {
  honestSeps.push(await say(r % 2 ? Bm : H, `honest sep ${r} what do you think`, step()));
  await say(V, `V reply ${r} a`, step()); await say(V, `V reply ${r} b`, step());
}
// 10 rounds separated only by A2's backdated x_i (gift) — without gift V's runs just merge
for (let r = 0; r < 10; r++) {
  const xTs = step();
  if (gift) giftSeps.push(await say(A2, `A2 x ${r} sure`, xTs));
  await say(V, `V more ${r} a`, step()); await say(V, `V more ${r} b`, step());
}
// A2's over-cap burst (P2P), late in the chat
const burst = [];
for (let i = 0; i < 600; i++) burst.push(await say(A2, `burst ${i}`, T0 + 1_000 + i * 50)); // early P2P burst (over cap)

const receipts = [];
const fresh = (m, ts) => Math.abs(ts - m.timestamp) <= 600_000;
// honest readers read every fresh message of others (one receipt per message, 8 s later), except backdated x_i and burst
for (const reader of [H, Bm, V]) {
  for (const m of messages) {
    if (m.uid === reader || giftSeps.includes(m) || burst.includes(m)) continue;
    receipts.push(await rc(reader, m.uid, [ref(m)], m.timestamp + 8_000 + uids.indexOf(reader)));
  }
  // honest readers read the first 100 burst messages (local cap)
  for (const m of burst.slice(0, 100)) receipts.push(await rc(reader, A2, [ref(m)], m.timestamp + 8_000 + uids.indexOf(reader)));
}
// A1: sliding chain on H's 40 opening messages (canonically early) -> 820 refs (exceeds share)
const hOpen = messages.filter((m) => m.uid === H).slice(0, 40);
for (let k = 1; k <= 40; k++) receipts.push(await rc(A1, H, hOpen.slice(0, k).map(ref), hOpen[k - 1].timestamp + 1_000));
// A1 gift: covers each x_i (1 ref) shortly after it
for (const x of giftSeps) receipts.push(await rc(A1, A2, [ref(x)], x.timestamp + 5_000));
// A1 also covers V's messages (so it also has own-cover receipts) — one per V message
for (const m of messages.filter((m) => m.uid === V)) receipts.push(await rc(A1, V, [ref(m)], m.timestamp + 9_000));
// A2 floods 1-ref receipts on burst + sliding windows of 50 refs on the burst
for (let k = 0; k < 200; k++) receipts.push(await rc(A2, H, [ref(hOpen[k % 40])], hOpen[k % 40].timestamp + 2_000 + k));
// A2 own-cover sliding chain on V's messages (pushes the total over 2,400)
{ const vm = messages.filter((m) => m.uid === V); for (let k = 1; k <= vm.length; k++) receipts.push(await rc(A2, V, vm.slice(0, k).map(ref), vm[k - 1].timestamp + 2_000)); }
// A1 fills its share with 1-ref receipts on the early burst (canonically before its x_i receipts)
for (const m of burst) receipts.push(await rc(A1, A2, [ref(m)], m.timestamp + 1_000));

const chatWindow = { startMs: T0, endMs: T0 + 86_400_000 };
const members = uids.map((uid) => ({ uid }));
const runPlan = (list) => planPriority({ messages, receipts: list.filter((r) => Array.isArray(r.msgRefs)), myUid: V, members, blockNum: B, groupId: G, chatWindow });
const memPlan = runPlan(receipts);
const index = new CarriedReceiptStoreIndex(V, receiptCanonCmp);
for (const receipt of receipts) index.accept(receipt);
assert.equal(runPlan(Object.values(index.selectedReceipts())).turns, 14, 'empty plan has known gap');
index.setPlanSignatures(planReceiptSignatures(memPlan));
assert.equal(memPlan.turns, 20);
assert.equal(runPlan(Object.values(index.selectedReceipts())).turns, memPlan.turns,
  'plan signatures survive a storage reload');
}

await runTimers();
  assert.equal(store.metrics.writes, writes, 'storage event causes no write');
  second.writer.accept(honest[1]); second.writer.flushSync();
  assert.equal(store.metrics.writes, writes + 1, 'pagehide writes pending work immediately');
  const stale = writerFor(store, undefined, () => false);
  stale.writer.accept(honest[2]); stale.writer.flushSync();
  assert.equal(store.metrics.writes, writes + 1, 'old identity writes nothing');
  first.writer.dispose(); second.writer.dispose(); stale.writer.dispose();
}

// Incremental first-owner index and the pure bundle limiter agree for L.
for (const [name, board] of Object.entries(boards)) {
  const index = new CarriedReceiptStoreIndex(uid, receiptCanonCmp);
  for (const row of board) index.accept(row);
  const byIssuer = new Map();
  for (const row of board) {
    if (!byIssuer.has(row.receiverUid)) byIssuer.set(row.receiverUid, []);
    byIssuer.get(row.receiverUid).push(row);
  }
  const legacy = [];
  for (const rows of byIssuer.values()) {
    const seen = new Set();
    for (const row of [...rows].sort(receiptCanonCmp)) {
      const facts = row.msgRefs?.map((ref) => `${row.senderUid}|${ref}`) || [`a|${row.actionHash}`];
      if (facts.some((fact) => !seen.has(fact))) legacy.push(row);
      for (const fact of facts) seen.add(fact);
    }
  }
  const limited = limitCarriedReceiptFacts({ observed: { receipts: legacy } },
    { submitterUid: uid, compare: receiptCanonCmp }).observed.receipts;
  assert.deepEqual(index.normalSignatures(), new Set(limited.map((row) => row.signature)), `${name}: L equals pure limiter`);
}

// A is the number of distinct self facts, not the number of self receipts.
// Feed it to the pure limiter as aggregate entries and compare the same L.
{
  const board = [...honest, ...boards.WORST4C];
  const index = new CarriedReceiptStoreIndex(uid, receiptCanonCmp);
  for (const row of board) index.accept(row);
  const firstOwners = [];
  for (const issuer of issuers) {
    const seen = new Set();
    for (const row of board.filter((item) => item.receiverUid === issuer).sort(receiptCanonCmp)) {
      const facts = row.msgRefs?.map((ref) => `${row.senderUid}|${ref}`) || [`a|${row.actionHash}`];
      if (facts.some((fact) => !seen.has(fact))) firstOwners.push(row);
      for (const fact of facts) seen.add(fact);
    }
  }
  const ownFacts = new Set(honest.filter((row) => row.receiverUid === uid)
    .flatMap((row) => row.msgRefs.map((ref) => `${row.senderUid}|${ref}`)));
  const aggregate = { entries: [...ownFacts].map(() => ({})) };
  const limited = limitCarriedReceiptFacts({ observed: {
    receipts: firstOwners, selfReceiptAggregate: aggregate,
  } }, { submitterUid: uid, compare: receiptCanonCmp }).observed.receipts;
  assert.deepEqual(index.normalSignatures(), new Set(limited.map((row) => row.signature)),
    'incremental L equals pure limiter with self aggregate cost');
}

// Recovery retains its knownRefs prefilter and then counts only real, timely
// claim keys. A single known ref plus 99 nonexistent ones cannot consume the
// own-cover priority ahead of honest L.
{
  const store = makeStorage();
  const previousStorage = globalThis.localStorage;
  globalThis.localStorage = store.storage;
  try {
    const relay = new RecoveryRelay({ signKey: `0x${'1'.repeat(64)}`, blockNum: block,
      groupId: group, uid, members: Object.keys(accounts).map((name) => ({ uid: name })),
      getChatWindow: () => ({ startMs: base - 1000, endMs: base + 1_000_000 }) });
    relay.messages = [];
    for (let i = 0; i < 100; i++) {
      const text = `V message ${i}`; const timestamp = base + i * 1000;
      relay.messages.push({ uid, text, timestamp,
        signature: await accounts[uid].signMessage({ message: chatSignStringV2(
          block, group, uid, text, timestamp,
        ) }) });
    }
    const messageRefs = relay.messages.map((row) => msgRefOf(relay.getMsgKey(row)));
    const honestReads = [];
    for (let i = 0; i < 100; i++) honestReads.push(await signedRead('user0003', uid,
      [messageRefs[i]], relay.messages[i].timestamp + 1000));
    relay._receipts = Object.fromEntries(honestReads.map((row, index) =>
      [row.signature, { ...row, _seq: index + 1 }]));
    relay._saveReceiptArrivals();
    assert.equal(store.storage.getItem(relay._receiptArrivalsStoreKey()),
      JSON.stringify(relay._receipts), 'honest recovery store retains original bytes');
    const fakeReads = [];
    for (const issuer of ['user0001', 'user0002']) for (let i = 0; i < 700; i++) {
      const unknown = Array.from({ length: 99 }, (_, j) =>
        `0x${(i * 100 + j + (issuer === 'user0001' ? 100_000 : 200_000)).toString(16).padStart(32, '0')}`);
      fakeReads.push(await signedRead(issuer, uid, [messageRefs[0], ...unknown].sort(), base + 2000 + i));
    }
    relay._receipts = Object.fromEntries([...honestReads, ...fakeReads]
      .map((row, index) => [row.signature, { ...row, _seq: index + 1 }]));
    relay._saveReceiptArrivals();
    const saved = JSON.parse(store.storage.getItem(relay._receiptArrivalsStoreKey()));
    assert.equal(honestReads.filter((row) => saved[row.signature]).length, 100,
      'recovery retains every honest L read');
    assert.equal(fakeReads.filter((row) => saved[row.signature]).length, 0,
      'recovery rejects one-known-plus-99-fake atomic claims');
    assert(JSON.stringify(saved).length < 3 * 1024 * 1024, 'recovery stays below safety net');
    const evidencePayload = 'p'.repeat(3 * 1024 * 1024);
    store.storage.setItem(`evidence_result_${block}_user${uid}`, evidencePayload);
    const reloadStart = performance.now();
    const reloaded = new RecoveryRelay({ signKey: `0x${'1'.repeat(64)}`, blockNum: block,
      groupId: group, uid, members: Object.keys(accounts).map((name) => ({ uid: name })),
      getChatWindow: () => ({ startMs: base - 1000, endMs: base + 1_000_000 }) });
    reloaded.messages = relay.messages;
    const reloadedReceipts = reloaded.getReceipts();
    assert.equal(reloadedReceipts.length, 100, 'reload keeps all valid recovery receipts');
    const scoreable = clientScoreableMessages(reloaded.getMessages(), reloadedReceipts, {
      blockNum: block, groupId: group, myUid: uid,
      chatWindow: { startMs: base - 1000, endMs: base + 1_000_000 }, caps: GUEST_PINNED_RULES,
    });
    const maps = buildReceiptMaps(reloadedReceipts,
      { messages: reloaded.getMessages(), myUid: uid }, block, group,
      { startMs: base - 1000, endMs: base + 1_000_000 });
    const app = readFileSync(new URL('../src/recovery/app.js', import.meta.url), 'utf8');
    const progressStart = app.indexOf('function myReceiptedChatProgress(');
    const progressEnd = app.indexOf('\nlet recoveryPriorityLock', progressStart);
    assert(progressStart >= 0 && progressEnd > progressStart);
    const progressFn = new Function('readersByMsgKey', 'locallyProvableMessages', 'state',
      'msgRefOf', 'computeMsgKeyV2', 'isTimestampVisible', 'countVisibleChars',
      'countMessageTurns', 'filterVisibleMessages', 'clientNow',
      `return (${app.slice(progressStart, progressEnd)});`)(
      () => maps.readersByMsgKey, () => scoreable, { blockNum: block, groupId: group, uid },
      msgRefOf, computeMsgKeyV2, (timestamp, now) => timestamp < now,
      countVisibleChars, countMessageTurns, filterVisibleMessages, () => base + 1_000_000);
    const screen = progressFn(reloaded.getMessages(), base + 1_000_000);
    const renderMs = Math.round(performance.now() - reloadStart);
    assert(screen.chars > 0 && screen.turns > 0, 'reloaded recovery screen reads honest receipts');
    console.log(`rs-storage recovery-screen: storedPayloadBytes=${evidencePayload.length} receipts=${reloadedReceipts.length} turns=${screen.turns} reloadAndScreenMs=${renderMs}`);
  } finally { globalThis.localStorage = previousStorage; }
}

// The claim memo varies with every relevant option and each named target, not
// with an unrelated new message elsewhere in the target map.
{
  const receipt = honest[0];
  const target = `${receipt.senderUid}|${receipt.msgRefs[0]}`;
  const targets = { realRefs: new Set([target]), refTimes: new Map([[target, [receipt.timestamp]]]) };
  const memo = new ReceiptClaimMemo();
  if (mutation === 'memo-maxrefs') {
    const original = memo.claim.bind(memo);
    memo.claim = (row, targetIndex, opts = {}) => original(row, targetIndex,
      { ...opts, maxRefsPerReceipt: 101 });
  }
  for (const opts of [
    { selfUid: uid, atomic: true, maxRefsPerReceipt: 100 },
    { selfUid: uid, atomic: true, maxRefsPerReceipt: 0 },
    { selfUid: uid, atomic: true, memberUids: [uid] },
    { selfUid: uid, atomic: true, chatWindow: { startMs: base + 1, endMs: base + 2 } },
  ]) assert.deepEqual(memo.claim(receipt, targets, opts), receiptCoverClaim(receipt, targets, opts));
  targets.realRefs.add(`someone|${refs[99]}`);
  const stableOptions = { selfUid: uid, atomic: true };
  const beforeUnrelated = memo.claim(receipt, targets, stableOptions);
  if (mutation === 'clear-on-unrelated') memo.clear();
  assert.strictEqual(memo.claim(receipt, targets, stableOptions), beforeUnrelated,
    'unrelated target reuses the same claim object');
  assert.deepEqual(beforeUnrelated, receiptCoverClaim(receipt, targets, stableOptions));
  targets.refTimes.set(target, [receipt.timestamp + 700_000]);
  assert.notStrictEqual(memo.claim(receipt, targets, stableOptions), beforeUnrelated,
    'a named target time invalidates only its claim');
  assert.deepEqual(memo.claim(receipt, targets, stableOptions),
    receiptCoverClaim(receipt, targets, stableOptions));
  const longRefs = Array.from({ length: 101 }, (_, i) =>
    `0x${(i + 5000).toString(16).padStart(32, '0')}`);
  const longReceipt = await signedRead('user0001', uid, longRefs, base + 5000);
  const longTargets = { realRefs: new Set(longRefs.map((ref) => `${uid}|${ref}`)),
    refTimes: new Map(longRefs.map((ref) => [`${uid}|${ref}`, [base + 4000]])) };
  assert.notDeepEqual(memo.claim(longReceipt, longTargets, { maxRefsPerReceipt: 100 }),
    memo.claim(longReceipt, longTargets, { maxRefsPerReceipt: 101 }),
    '101 refs separate the two clientScoreableMessages claim options');
}

// Gift receipts expose the future P2a-2/P2b plan input: without it the
// durable material proves 14 turns, while the same signed set plus the plan
// preserves all 20 turns from memory. This test owns its fixture.
{
const gift = true;
const B = 1, G = 1, T0 = 1_900_000_000_000;
const uids = ['user0001', 'user0002', 'user0003', 'user0004', 'user0005'];
const acct = Object.fromEntries(uids.map((u, i) => [u, privateKeyToAccount(`0x${(i + 1).toString(16).padStart(64, '0')}`)]));
const [A1, A2, H, Bm, V] = uids;
const key = buildMsgKeyGetter(B, G);
const ref = (m) => msgRefOf(key(m));
const messages = [];
async function say(uid, text, timestamp) {
  const signature = await acct[uid].signMessage({ message: chatSignStringV2(B, G, uid, text, timestamp) });
  const m = { uid, text, timestamp, signature }; messages.push(m); return m;
}
async function rc(issuer, sender, refs, timestamp) {
  const msgRefs = [...refs].sort(compareHexAsc);
  const signature = await acct[issuer].signMessage({ message: readReceiptSignString(B, G, issuer, sender, msgRefs, timestamp) });
  return { receiverUid: issuer, senderUid: sender, msgRefs, timestamp, signature };
}
// timeline: 30 s steps
let t = T0 + 60_000;
const step = () => (t += 30_000);
const honestSeps = [], giftSeps = [];
// opening: H talks (A1 floods on these early H messages later)
for (let i = 0; i < 40; i++) await say(H, `H opening ${i} hello there`, step());
// 14 rounds: honest separator then V's run (2 messages)
for (let r = 0; r < 14; r++) {
  honestSeps.push(await say(r % 2 ? Bm : H, `honest sep ${r} what do you think`, step()));
  await say(V, `V reply ${r} a`, step()); await say(V, `V reply ${r} b`, step());
}
// 10 rounds separated only by A2's backdated x_i (gift) — without gift V's runs just merge
for (let r = 0; r < 10; r++) {
  const xTs = step();
  if (gift) giftSeps.push(await say(A2, `A2 x ${r} sure`, xTs));
  await say(V, `V more ${r} a`, step()); await say(V, `V more ${r} b`, step());
}
// A2's over-cap burst (P2P), late in the chat
const burst = [];
for (let i = 0; i < 600; i++) burst.push(await say(A2, `burst ${i}`, T0 + 1_000 + i * 50)); // early P2P burst (over cap)

const receipts = [];
const fresh = (m, ts) => Math.abs(ts - m.timestamp) <= 600_000;
// honest readers read every fresh message of others (one receipt per message, 8 s later), except backdated x_i and burst
for (const reader of [H, Bm, V]) {
  for (const m of messages) {
    if (m.uid === reader || giftSeps.includes(m) || burst.includes(m)) continue;
    receipts.push(await rc(reader, m.uid, [ref(m)], m.timestamp + 8_000 + uids.indexOf(reader)));
  }
  // honest readers read the first 100 burst messages (local cap)
  for (const m of burst.slice(0, 100)) receipts.push(await rc(reader, A2, [ref(m)], m.timestamp + 8_000 + uids.indexOf(reader)));
}
// A1: sliding chain on H's 40 opening messages (canonically early) -> 820 refs (exceeds share)
const hOpen = messages.filter((m) => m.uid === H).slice(0, 40);
for (let k = 1; k <= 40; k++) receipts.push(await rc(A1, H, hOpen.slice(0, k).map(ref), hOpen[k - 1].timestamp + 1_000));
// A1 gift: covers each x_i (1 ref) shortly after it
for (const x of giftSeps) receipts.push(await rc(A1, A2, [ref(x)], x.timestamp + 5_000));
// A1 also covers V's messages (so it also has own-cover receipts) — one per V message
for (const m of messages.filter((m) => m.uid === V)) receipts.push(await rc(A1, V, [ref(m)], m.timestamp + 9_000));
// A2 floods 1-ref receipts on burst + sliding windows of 50 refs on the burst
for (let k = 0; k < 200; k++) receipts.push(await rc(A2, H, [ref(hOpen[k % 40])], hOpen[k % 40].timestamp + 2_000 + k));
// A2 own-cover sliding chain on V's messages (pushes the total over 2,400)
{ const vm = messages.filter((m) => m.uid === V); for (let k = 1; k <= vm.length; k++) receipts.push(await rc(A2, V, vm.slice(0, k).map(ref), vm[k - 1].timestamp + 2_000)); }
// A1 fills its share with 1-ref receipts on the early burst (canonically before its x_i receipts)
for (const m of burst) receipts.push(await rc(A1, A2, [ref(m)], m.timestamp + 1_000));

const chatWindow = { startMs: T0, endMs: T0 + 86_400_000 };
const members = uids.map((uid) => ({ uid }));
const runPlan = (list) => planPriority({ messages, receipts: list.filter((r) => Array.isArray(r.msgRefs)), myUid: V, members, blockNum: B, groupId: G, chatWindow });
const memPlan = runPlan(receipts);
const index = new CarriedReceiptStoreIndex(V, receiptCanonCmp);
for (const receipt of receipts) index.accept(receipt);
assert.equal(runPlan(Object.values(index.selectedReceipts())).turns, 14, 'empty plan has known gap');
index.setPlanSignatures(planReceiptSignatures(memPlan));
assert.equal(memPlan.turns, 20);
assert.equal(runPlan(Object.values(index.selectedReceipts())).turns, memPlan.turns,
  'plan signatures survive a storage reload');
}

await runTimers();
console.log(`rs-receipt-store-unit: ALL PASSED ${JSON.stringify({ results,
  rs4MedianMs: rs4Times[1], pacedBack4 })}`);

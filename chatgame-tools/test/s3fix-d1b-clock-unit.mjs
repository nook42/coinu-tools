import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { transformSync } from 'esbuild';
import { privateKeyToAccount } from 'viem/accounts';
import { createClientClock } from '../../src/utils/clientClock.js';
import { selectChainClockReading, advanceChainClockAlert, parseUserCorrectionMs, detectClockStep, planReadReceiptReissues, countRepeatedReissueGroups,
  advanceFutureClockWarning, futureClockWarningBypassesCooldown, INITIAL_FUTURE_CLOCK_WARNING } from '../../src/utils/chainClock.js';
import { estimatePartialReadReissues, reissueGroupKey } from '../../src/utils/receipt-warnings.js';
import { FutureAdmissionMarks, isClientTimestampAllowed, receiptIdentityDigest } from '../../src/utils/relay.js';
import { derivePhaseFromWindows } from '../vendor/workers/game_workers/lib/timeline-check.js';
import { getTimeReadSources, readTimeChainTipMs, readTimeClockSamples } from '../../src/utils/rpcClient.js';
import { makeTimeReadClient } from '../src/common/chain.js';
import { markActionReceiptSource, mayCarryActionReceipt, clientChatSourcedReceipts, PartialReadReceiptTracker,
  canonicalizeSignature } from '../../workers/game_workers/lib/protocol-v2.js';
import { RecoveryRelay } from '../src/recovery/relay-client.js';
import { openReadReceiptPause, readReceiptTickGap } from '../../src/utils/read-receipt-pause.js';

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8');
const realStorage = globalThis.localStorage;
const saved = new Map();
globalThis.localStorage = {
  getItem: (key) => saved.get(key) ?? null,
  setItem: (key, value) => saved.set(key, value),
};
try {
  const clock = createClientClock('d1b-test');
  const wall = 1_800_000_000_000;
  assert.equal(clock.clientNow(wall), wall);
  const notifications = [];
  const unsubscribe = clock.subscribeClockCorrection((change) => notifications.push(change));
  assert.deepEqual(clock.setClockCorrection(30_000), { previousMs: 0, nextMs: 30_000, deltaMs: 30_000 });
  assert.equal(clock.clientNow(wall), wall + 30_000);
  assert.equal(saved.get('d1b-test'), '30000');
  assert.equal(clock.correctionCooldownMs() > 599000, true);
  assert.equal(createClientClock('d1b-test').correctionCooldownMs() > 599000, true);
  assert.throws(() => clock.setClockCorrection(0), RangeError);
  assert.equal(saved.get('d1b-test'), '30000');
  assert.equal(clock.correctionCooldownMs(Date.now() + 600001, performance.now() + 600001), 0);
  assert.equal(createClientClock('d1b-test').correctionCooldownMs(Number(saved.get('d1b-test_lastChangedAt')) - 1), 0);
  clock.markAdoptedClock(77);
  assert.equal(createClientClock('d1b-test').hasAdoptedClock(77), true);
  assert.equal(clock.hasAdoptedClock(78), false);
  saved.set('d1b-test_lastChangedAt', String(Date.now() - 600001));
  const reopened = createClientClock('d1b-test');
  assert.equal(reopened.correctionCooldownMs(), 0);
  assert.equal(reopened.setClockCorrection(0).deltaMs, -30_000);
  assert.equal(createClientClock('d1b-test').clientNow(wall), wall);
  assert.deepEqual(clock.setClockCorrection(30_000), { previousMs: 30_000, nextMs: 30_000, deltaMs: 0 });
  assert.equal(notifications.length, 1);
  unsubscribe();
  clock.setClockCorrection(30_000);
  assert.equal(notifications.length, 1);
  assert.throws(() => clock.setClockCorrection(86_400_001));
  globalThis.localStorage = { getItem() { throw Error('denied'); }, setItem() { throw Error('denied'); } };
  const memoryClock = createClientClock('denied');
  assert.equal(memoryClock.clientNow(wall), wall);
  memoryClock.setClockCorrection(-300_000);
  assert.equal(memoryClock.clientNow(wall), wall - 300_000);
  assert.equal(memoryClock.correctionCooldownMs() > 0, true);
} finally { globalThis.localStorage = realStorage; }
if (process.env.S3FIX_D1D_MUTATION === 'cooldown-skipped') {
  const source = read('src/utils/clientClock.js');
  const body = source.slice(source.indexOf('export function createClientClock('),
    source.indexOf('\nconst pageClock ='));
  const changed = body.replace('validNextMs !== previousMs && !bypassCooldown && correctionCooldownMs() > 0', 'false');
  assert.notEqual(changed, body);
  const makeClock = new Function('parseUserCorrectionMs', 'CLIENT_CLOCK_STORAGE_KEY',
    `${changed.replace('export ', '')}\nreturn createClientClock;`)(parseUserCorrectionMs, 'mutation-key');
  const priorStorage = globalThis.localStorage;
  const data = new Map();
  globalThis.localStorage = { getItem: (key) => data.get(key) ?? null,
    setItem: (key, value) => data.set(key, value) };
  try {
    const clock = makeClock('mutation-key');
    clock.setClockCorrection(1000);
    assert.throws(() => clock.setClockCorrection(2000), RangeError,
      '10分の間は補正量を再保存できない');
  } finally { globalThis.localStorage = priorStorage; }
}

const base = 1_800_000_000_000;
assert.deepEqual((await getTimeReadSources()).map(({ sourceId }) => sourceId),
  ['ethereum-rpc.publicnode.com', 'gateway.tenderly.co', 'eth.drpc.org']);
const recoveryTime = makeTimeReadClient({ rpcUrls: [
  'https://ethereum-rpc.publicnode.com', 'https://1rpc.io/eth',
  'https://rpc.flashbots.net', 'https://rpc.flashbots.net/duplicate',
] });
assert.deepEqual(recoveryTime.sources,
  ['ethereum-rpc.publicnode.com', '1rpc.io', 'rpc.flashbots.net']);
const modalSource = process.env.S3FIX_D1B2_MUTATION === 'ascii-input'
  ? read('src/components/game/ClockCorrectionModal.js').replace('0-9０-９]+$/u', '0-9]+$/u')
  : read('src/components/game/ClockCorrectionModal.js');
const parseSource = modalSource.slice(modalSource.indexOf('const acceptedInput ='),
  modalSource.indexOf('\nexport default function ClockCorrectionModal'));
const parseCorrectionSeconds = new Function('getClockCorrection', 'parseUserCorrectionMs',
  `${parseSource.replaceAll('export ', '')}\nreturn parseCorrectionSeconds;`)(() => 30_000, parseUserCorrectionMs);
assert.deepEqual(parseCorrectionSeconds('+30'), { deltaMs: 30_000, nextMs: 60_000 });
for (const value of ['-180', '−180', '－１８０']) {
  assert.deepEqual(parseCorrectionSeconds(value), { deltaMs: -180_000, nextMs: -150_000 });
}
assert.deepEqual(parseCorrectionSeconds('＋30'), { deltaMs: 30_000, nextMs: 60_000 });
for (const value of [' 30', '\t−30\u3000', '\u00a0+30\u00a0', 'ー３０', 'ｰ３０', '‐３０', '‑３０', '‒３０', '–３０', '—３０', '―３０']) {
  assert.equal(parseCorrectionSeconds(value).deltaMs, Number(value.trim().normalize('NFKC').replace(/[−－ーｰ‐‑‒–—―]/gu, '-')) * 1000);
}
for (const invalid of ['', '1.5', 'abc', '86401', '-86401', '①']) {
  assert.throws(() => parseCorrectionSeconds(invalid));
}
const timeline = { chatOpenAt: base - 10_000, chattingStart: base - 5_000,
  chatCloseAt: base + 180_000, resultCloseAt: base + 600_000 };
assert.equal(derivePhaseFromWindows(base, timeline), 'chatting');
assert.equal(derivePhaseFromWindows(base + 300_000, timeline), 'submitting');
assert.equal(derivePhaseFromWindows(base - 300_000, timeline), 'entry');
const action = { actionHash: `0x${'ab'.repeat(32)}` };
for (const correction of [-300_000, 0, 300_000]) {
  const beforeClose = markActionReceiptSource(action, {
    chatCloseAt: base, chainTimeMs: base - 1, nowMs: base + correction,
  });
  const afterClose = markActionReceiptSource(action, {
    chatCloseAt: base, chainTimeMs: base + 1, nowMs: base + correction,
  });
  assert.equal(beforeClose._chainSeenAt, base - 1);
  assert.equal(beforeClose._deviceSeenAt, null);
  assert.equal(afterClose._chainSeenAt, null);
  assert.equal(afterClose._deviceSeenAt, null);
}
// Correction changes signed-time comparisons, never the raw elapsed-time pause.
const pause = openReadReceiptPause(null, 1000, true, 1000);
assert.equal(readReceiptTickGap(pause, 9000, 9000), false);
assert.equal(readReceiptTickGap(pause, 9000, 9000), false);
assert.match(read('src/hooks/useGameWebSocket.js'), /readReceiptTickGap\(pause, now, wallNow\)/);
assert.match(read('chatgame-tools/src/recovery/app.js'), /readReceiptTickGap\(pause, now, wallNow\)/);
let cNow = base;
const queue = new FutureAdmissionMarks({ blockNum: 1, groupId: 1, now: () => cNow });
const received = [];
const correctPeer = { uid: 'correct-peer', signature: `0x${'22'.repeat(64)}1b`, timestamp: base };
assert.equal(isClientTimestampAllowed(correctPeer.timestamp, base - 300_000), false);
assert.equal(isClientTimestampAllowed(correctPeer.timestamp, cNow), true);
if (isClientTimestampAllowed(correctPeer.timestamp, cNow)) received.push(correctPeer);
assert.deepEqual(received, [correctPeer]);
received.length = 0;
const future = { uid: 'other', text: 'future', signature: `0x${'11'.repeat(64)}1b`, timestamp: base + 180_001 };
assert.equal(queue.discard('chat', future), true);
cNow += 300_000;
assert.deepEqual(received, []);
assert.equal(queue.has('chat', future), true);
const sample = (sourceId, seconds) => ({ sourceId, blockTimestampMs: base + seconds * 1000, observedMonoMs: 100 });
const choose = (publicSamples, walletSeconds = null) => selectChainClockReading({ publicSamples,
  walletSample: walletSeconds === null ? null : { ...sample('wallet', walletSeconds), chainId: 1 }, nowMonoMs: 100 });
assert.deepEqual(choose([sample('a', 0), sample('b', 1), sample('c', 2)], -100).sourceIds, ['a', 'b', 'c']);
assert.deepEqual(choose([sample('a', 0), sample('b', 1), sample('c', 60)], 120).sourceIds, ['wallet']);
assert.equal(choose([sample('a', 0), sample('b', 1), sample('c', 60)], 61).timeMs, base + 61_000);
assert.equal(choose([sample('a', 0), sample('b', 20), sample('c', 40)]).timeMs, base + 20_000);
assert.equal(choose([sample('a', 0), sample('b', 60)]).timeMs, null);
assert.equal(choose([sample('a', 0)]).timeMs, base);
assert.equal(choose([]).timeMs, null);

const alert = (deviationMs, context, previousOutside = null, confirmedDeviationMs = null, monoNowMs = 0,
  reading = { kind: 'consensus', liveCount: 2, timeMs: base }) => advanceChainClockAlert({
  reading, wallNowMs: base + deviationMs, correctionMs: 0, monoNowMs, context,
  previousOutside, confirmedDeviationMs,
});
assert.equal(alert(44_999, 'entry').kind, 'none');
// S3R8-C-1b-01: 入室・段差の consensus の外れは1回目を保留し、12秒以上あけた2回目でだけ警告する。
assert.equal(alert(45_000, 'entry').kind, 'pending');
assert.equal(alert(45_000, 'entry', { monoMs: 0 }, null, 11_999).kind, 'pending');
assert.equal(alert(45_000, 'entry', { monoMs: 0 }, null, 12_000).kind, 'warning');
assert.equal(alert(-14_000, 'entry').kind, 'none');
assert.equal(alert(-15_000, 'entry').kind, 'pending');
assert.equal(alert(-15_000, 'step', { monoMs: 0 }, null, 12_000).kind, 'warning');
const first = alert(45_000, 'game');
assert.equal(first.kind, 'pending');
assert.equal(alert(45_000, 'game', first.nextOutside, null, 59_999).kind, 'pending');
assert.equal(alert(45_000, 'game', first.nextOutside, null, 60_000).kind, 'warning');
assert.equal(alert(74_999, 'entry', null, 30_000).kind, 'none');
assert.equal(alert(75_000, 'entry', null, 30_000).kind, 'pending');
assert.equal(alert(75_000, 'entry', { monoMs: 0 }, 30_000, 12_000).kind, 'warning');
assert.equal(alert(0, 'entry', null, null, 0, { kind: 'unavailable', liveCount: 0, timeMs: null }).kind, 'confirmation');
assert.equal(alert(45_000, 'entry', null, null, 0, { kind: 'unavailable', liveCount: 1, timeMs: base }).kind, 'confirmation');

const hookSource = process.env.MCF_HOOK_SOURCE
  ? readFileSync(process.env.MCF_HOOK_SOURCE, 'utf8') : read('src/hooks/useGameWebSocket.js');
const cacheAdapterText = hookSource.slice(hookSource.indexOf('function clockAlignedRosterCacheStorage() {'),
  hookSource.indexOf('\nexport function useGameWebSocket('));
const cacheSaved = new Map();
const cacheStorage = { getItem: (key) => cacheSaved.get(key) ?? null,
  setItem: (key, value) => cacheSaved.set(key, value), removeItem: (key) => cacheSaved.delete(key) };
const alignedCache = new Function('getClockCorrection', 'localStorage',
  `${cacheAdapterText}\nreturn clockAlignedRosterCacheStorage;`)(() => 300_000, cacheStorage)();
cacheStorage.setItem('roster', JSON.stringify({ cachedAt: base, expiresAt: base + 10_000,
  chattingStartMs: base + 120_000 }));
assert.deepEqual(JSON.parse(alignedCache.getItem('roster')),
  { cachedAt: base + 300_000, expiresAt: base + 310_000, chattingStartMs: base + 120_000 });
alignedCache.setItem('roster', JSON.stringify({ cachedAt: base + 300_000,
  expiresAt: base + 310_000, chattingStartMs: base + 120_000 }));
assert.deepEqual(JSON.parse(cacheStorage.getItem('roster')),
  { cachedAt: base, expiresAt: base + 10_000, chattingStartMs: base + 120_000 });
assert.match(hookSource, /cacheStorage: storageWithoutOperatorWrites\(client, clockAlignedRosterCacheStorage\(\)\)/);
const hook = process.env.S3FIX_D1B_MUTATION === 'raw-future-queue'
  ? hookSource.replace('blockNum, groupId, now: clientNow', 'blockNum, groupId, now: Date.now')
  : process.env.S3FIX_D1B2_MUTATION === 'late-stamp'
    ? hookSource.replace('chainTimeMs, nowMs: markedDeviceArrivalMs,', 'chainTimeMs, nowMs: clientNow(),')
    : process.env.S3FIX_D1B2_MUTATION === 'closed-sleep-window'
      ? hookSource.replace('if (readReceiptTickGap(pause, now, wallNow)) {',
        'const gapWallNow = stepped ? pause.lastTickWallAt + (now - pause.lastTickAt) : wallNow;\n        if (readReceiptTickGap(pause, now, gapWallNow)) {')
      : hookSource;
const pageSource = read('src/pages/game.js');
const page = process.env.S3FIX_D1D_MUTATION === 'manual-entry-removed'
  ? pageSource.replace('onClick={openManualClock}', 'onClick={undefined}') : pageSource;
const relay = read('src/utils/relay.js');
const recovery = process.env.W6R_RECOVERY_SOURCE
  ? readFileSync(process.env.W6R_RECOVERY_SOURCE, 'utf8')
  : process.env.S3FIX_D1B2_MUTATION === 'stale-end-modal'
  ? read('chatgame-tools/src/recovery/app.js').replace(
    'state.tabEnded = true;\n  state.clockAlert = null;', 'state.tabEnded = true;')
  : read('chatgame-tools/src/recovery/app.js');
{
  const prepareStart = page.indexOf('  const prepareClockCorrection = useCallback(');
  const prepareEnd = page.indexOf('\n  const acknowledgeClock = useCallback(', prepareStart);
  assert(prepareStart >= 0 && prepareEnd > prepareStart);
  const prepareSource = process.env.S3FIX_D1D_MUTATION === 'adoption-skipped'
    ? page.slice(prepareStart, prepareEnd).replace('const adoption = deviation?.outside ?? false;',
      'const adoption = false;') : page.slice(prepareStart, prepareEnd);
  const makePrepare = (reading, now = base) => new Function('useCallback', 'readFreshClock',
    'classifyChainClockDeviation', 'clientNow', 'wsRaw', 'blockNum', 'groupId',
    `${prepareSource}\nreturn prepareClockCorrection;`)(
    (fn) => fn, async () => reading, (c, l) => ({ deviationMs: c - l,
      outside: c - l >= 45000 || c - l <= -15000 }), () => now,
    { reviewClockReissues: ({ deltaMs }) => ({ repeated: deltaMs < 0 ? 1 : 0,
      partial: { alert: false } }) }, 77, 1);
  const two = await makePrepare({ timeMs: base, sourceIds: ['wallet', 'rpc.example'] })({ deltaMs: 45000 });
  assert.equal(two.adoption, true);
  assert.equal(two.deviationMs, 45000);
  assert.deepEqual(two.sourceIds, ['wallet', 'rpc.example']);
  assert.equal((await makePrepare({ timeMs: base, sourceIds: ['rpc.example'] })({ deltaMs: -15000 })).adoption, true);
  assert.equal((await makePrepare(null)({ deltaMs: 45000 })).adoption, false);
  const repeated = await makePrepare({ timeMs: base, sourceIds: ['wallet'] }, base + 70000)({ deltaMs: -60000 });
  assert.equal(repeated.adoption, false);
  assert.equal(repeated.repeated, true);

  const acknowledgeStart = page.indexOf('  const acknowledgeClock = useCallback(');
  const acknowledgeEnd = page.indexOf('\n  const openManualClock = useCallback(', acknowledgeStart);
  const check = { current: { blockNum: 77, generation: 0, open: true } };
  let adopted = null;
  let savedCorrection = null;
  let visibleAlert = true;
  const acknowledge = new Function('useCallback', 'clockCheckRef', 'clockAlert',
    'correctionCooldownMs', 'wsRaw', 'markAdoptedClock', 'setClockAlert', 'readFreshClock',
    `${page.slice(acknowledgeStart, acknowledgeEnd)}\nreturn acknowledgeClock;`)(
    (fn) => fn, check, { deviationMs: 50000 }, () => 0,
    { applyClockCorrection: (value) => { savedCorrection = value; } }, (block) => { adopted = block; },
    (value) => { visibleAlert = value; }, async () => null);
  acknowledge({ deltaMs: 0, nextMs: 0, review: { adoption: true, deviationMs: 45000 } });
  assert.equal(adopted, 77);
  assert.equal(check.current.confirmedDeviationMs, 45000);
  assert.equal(savedCorrection, null, '補正0は間隔を始めない');
  assert.equal(visibleAlert, null);
}
{
  const start = recovery.indexOf('async function acknowledgeClockCorrection(');
  const end = recovery.indexOf('\nasync function openManualClockCorrection()', start);
  assert(start >= 0 && end > start);
  const correctionState = { blockNum: 77, clockAlert: { deviationMs: 50000 },
    clockPendingCorrection: null, clockDraft: '', clockCheckGeneration: 0 };
  let adopted = null;
  let saved = null;
  let skipAtSave = null;
  const correctionClock = { correctionCooldownMs: () => 0, getClockCorrection: () => 0,
    setClockCorrection: (value) => { saved = value; skipAtSave = correctionState.clockReissueSkip; },
    markAdoptedClock: (block) => { adopted = block; } };
  const acknowledge = new Function('state', 'recoveryClock', 'parseRecoveryCorrectionSeconds',
    'parseUserCorrectionMs', 'renderClockModal', 'freshRecoveryClockReading',
    'classifyChainClockDeviation', 'clientNow', 'repeatedRecoveryReissues', 'recoveryPartialChats',
    `${recovery.slice(start, end)}\nreturn acknowledgeClockCorrection;`)(
    correctionState, correctionClock, (input) => Number(input) * 1000,
    parseUserCorrectionMs, () => {}, async () => ({ timeMs: base, sourceIds: ['rpc.example'] }),
    (c, l) => ({ deviationMs: c - l, outside: c - l >= 45000 || c - l <= -15000 }),
    () => base + 45000, (deltaMs) => ({ repeated: deltaMs < 0 && deltaMs !== -45000 ? 1 : 0,
      partial: [-120000, -45000].includes(deltaMs)
        ? { alert: true, keys: ['chosen'] } : { alert: false } }),
    () => [{ key: 'm1', label: 'S: m1' }]);
  await acknowledge(null);
  assert.equal(correctionState.clockPendingCorrection.adoption, true);
  assert.equal(correctionState.clockPendingCorrection.repeated, false);
  assert.deepEqual(correctionState.clockPendingCorrection.sourceIds, ['rpc.example']);
  await acknowledge(null, true);
  assert.equal(adopted, 77);
  assert.equal(saved, null, '復元も補正0で間隔を始めない');
  assert.equal(correctionState.clockConfirmedDeviationMs, 45000);
  correctionState.clockAlert = { deviationMs: 45000 };
  await acknowledge('-60');
  assert.equal(correctionState.clockPendingCorrection.adoption, true);
  assert.equal(correctionState.clockPendingCorrection.repeated, true);
  await acknowledge(null, true);
  assert.equal(saved, -60000);
  correctionState.clockAlert = { deviationMs: 45000 };
  await acknowledge('-120');
  assert.equal(correctionState.clockPendingCorrection.stage, 'review');
  assert.deepEqual(correctionState.clockPendingCorrection.partial.chats, [{ key: 'm1', label: 'S: m1' }]);
  await acknowledge(null, true);
  assert.equal(correctionState.clockPendingCorrection.stage, 'partial');
  assert.equal(saved, -60000, 'D1d の確認ではまだ保存しない');
  await acknowledge(null, true, true);
  assert.equal(saved, -120000);
  assert.deepEqual([...skipAtSave], ['chosen']);
  assert.equal(correctionState.clockReissueSkip, null);
  correctionState.clockAlert = { deviationMs: 45000 };
  await acknowledge('-120');
  await acknowledge(null, true);
  const saveNormally = correctionClock.setClockCorrection;
  correctionClock.setClockCorrection = () => { throw new RangeError('another tab changed the cooldown'); };
  await assert.rejects(() => acknowledge(null, true, true), RangeError);
  assert.equal(correctionState.clockReissueSkip, null);
  correctionClock.setClockCorrection = saveNormally;
  await acknowledge(null, true, false);
  assert.equal(skipAtSave, null, '失敗した選択を次の補正へ持ち越さない');
  correctionState.clockAlert = { deviationMs: 45000 };
  await acknowledge('-45');
  assert.equal(correctionState.clockPendingCorrection.stage, 'partial',
    'D1d の画面が無くても直接この画面へ来る');
}
{
  let mono = 1000;
  let wall = base;
  let reads = 0;
  const clockCheckRef = { current: { stepTick: 0, reading: null } };
  const start = page.indexOf('  const readFreshClock = useCallback(async () => {');
  const end = page.indexOf('\n  futureLockClockRef.current =', start);
  assert(start >= 0 && end > start);
  const freshSource = process.env.S3FIX_D1D_MUTATION === 'stale-cache'
    ? page.slice(start, end).replaceAll('<= 60000', '<= Infinity') : page.slice(start, end);
  const fresh = new Function('useCallback', 'clockCheckRef', 'performance', 'Date',
    'readTimeClockSamples', 'selectChainClockReading', 'setTimeout', 'clearTimeout',
    `${freshSource}\nreturn readFreshClock;`)(
    (fn) => fn, clockCheckRef, { now: () => mono }, { now: () => wall },
    async () => { reads++; return { publicSamples: [{ sourceId: 'rpc.example',
      blockTimestampMs: base, observedMonoMs: mono }] }; },
    selectChainClockReading, setTimeout, clearTimeout);
  assert.equal((await fresh()).timeMs, base);
  assert.equal(reads, 1);
  mono += 30000; wall += 30000;
  assert.equal((await fresh()).timeMs, base + 30000);
  assert.equal(reads, 1, '公式は60秒以内のLを単調時計で進める');
  mono += 31000; wall += 31000;
  await fresh();
  assert.equal(reads, 2, '公式は60秒を超えたLを読み直す');
  clockCheckRef.current.stepTick++;
  await fresh();
  assert.equal(reads, 3, '公式は段差検出後のLを読み直す');

  const recoveryState = { clockReading: null, clockStepVersion: 0,
    _timeClient: { readSamples: async () => { reads++; return { publicSamples: [{
      sourceId: 'rpc.example', blockTimestampMs: base, observedMonoMs: mono }] }; } } };
  const recoveryStart = recovery.indexOf('async function freshRecoveryClockReading() {');
  const recoveryEnd = recovery.indexOf('\nasync function checkClock(context)', recoveryStart);
  assert(recoveryStart >= 0 && recoveryEnd > recoveryStart);
  const recoveryFresh = new Function('state', 'performance', 'Date', 'selectChainClockReading',
    'setTimeout', 'clearTimeout',
    `${recovery.slice(recoveryStart, recoveryEnd)}\nreturn freshRecoveryClockReading;`)(
    recoveryState, { now: () => mono }, { now: () => wall }, selectChainClockReading,
    setTimeout, clearTimeout);
  await recoveryFresh();
  assert.equal(reads, 4);
  mono += 30000; wall += 30000;
  await recoveryFresh();
  assert.equal(reads, 4, '復元も60秒以内はLを進める');
  recoveryState.clockStepVersion++;
  await recoveryFresh();
  assert.equal(reads, 5, '復元も段差検出後のLを読み直す');
}
const recoveryRelay = read('chatgame-tools/src/recovery/relay-client.js');
const rpc = read('src/utils/rpcClient.js');
const commonChain = read('chatgame-tools/src/common/chain.js');
const officialModalSource = read('src/components/game/ClockCorrectionModal.js');
const officialModal = process.env.S3FIX_D1D_MUTATION === 'neutral-sign-removed'
  ? officialModalSource.replace('game.clock.neutralSignHelp', 'game.clock.signHelp')
  : process.env.S3FIX_D1D_MUTATION === 'reload-hint-removed'
    ? officialModalSource.replace('game.clock.reloadAfterDeviceFix', 'game.clock.close')
    : officialModalSource;
assert.match(hook, /blockNum, groupId, now: clientNow, correction: getClockCorrection/,
  'shared future marks use C');
assert.match(hook, /futureMarks: futureMarksRef\.current/);
assert.match(hook, /subscribeClockCorrection\(\(change\) =>/);
assert.match(hook, /readTimeChainTipMs\(gameRpcSession\)/);
assert.match(hook, /case 'pong':\s*break;/);
assert.doesNotMatch(hook, /handleServerClockSample|serverClockOffsetRef|useServerClockRef/);
assert.match(relay, /const clientNow = this\.now\(\)/);
assert.match(recoveryRelay, /refetchHistory\(change\)/);
assert.match(recovery, /DEFAULTS\.rpcPresets\.map\(\(\{ url \}\) => url\)/);
assert.match(recovery, /state\._timeClient\.getBlock\(\)/);
assert.match(recovery, /renderClockModal\(\)/);
assert.match(recovery, /clockModalRenderKey/);
assert.match(page, /<ClockCorrectionModal/);
assert.match(page, /\['waiting', 'chatting', 'submitting'\]\.includes\(effectivePhase\)/);
assert(page.includes('onClick={openManualClock}'), '公式の手動入口は同じ時計モーダルを開く');
assert.match(page, /<ClockCorrectionControl t=\{t\} onClick=\{openManualClock\} \/>/);
assert.match(page, /disabled=\{cooldownMs > 0\}/);
assert.match(recovery, /STAGE1_PHASES\.includes\(phase\) && !state\.tabEnded/);
assert.match(recovery, /onclick: \(\) => \{ void openManualClockCorrection\(\); \}/);
assert(officialModal.includes('game.clock.neutralSignHelp'), '公式のずれ無し画面は中立の符号説明');
assert.match(recovery, /recovery\.clock\.neutralSignHelp/);
assert(officialModal.includes('game.clock.reloadAfterDeviceFix'), '公式の時計画面に端末設定後の再読込案内');
assert.match(recovery, /recovery\.clock\.reloadAfterDeviceFix/);
assert.match(page, /readTimeClockSamples\(\)/);
assert.match(rpc, /getTimeReadSources/);
assert.match(commonChain, /export function makeTimeReadClient/);
assert.match(officialModal, /parseUserCorrectionMs\(Number\(normalized\) \* 1000\)/);
assert.match(officialModal, /setInterval\(\(\) => setNow\(clientNow\(\)\), 1000\)/);
assert.match(officialModal, /value=\{input\}[\s\S]*onChange=/);
assert.match(officialModal, /<time data-testid="clock-current">/);
assert.match(officialModal, /<time data-testid="clock-corrected">/);
assert.doesNotMatch(officialModal, /<input[^>]*\bkey=/);
assert.doesNotMatch(page, /<ClockCorrectionModal[^>]*\bkey=/);
assert.match(read('src/utils/gameUtils.js'), /formatRemainingDHMS\([^\n]*nowMs = Date\.now\(\)/);

// The recovery clock dialog lives under the G2 holder, even before game-area exists.
const modalFns = recovery.slice(recovery.indexOf('let modalRoot = null;'),
  recovery.indexOf('function renderGameModals('));
const body = { children: [], append(node) { this.children.push(node); node.parentNode = this; node.isConnected = true; } };
const element = (tag, props = {}, ...kids) => {
  const node = { tag, ...props, children: [], isConnected: true, append(...children) {
    for (const child of children) { this.children.push(child); child.parentNode = this; }
  } };
  Object.defineProperty(node, 'innerHTML', { set(value) { assert.equal(value, ''); this.children = []; } });
  node.append(...kids);
  return node;
};
const findNode = (root, id) => root.id === id ? root
  : root.children?.map((child) => findNode(child, id)).find(Boolean) || null;
const document = { body, getElementById: (id) => findNode(body, id) };
const modalState = { clockAlert: { kind: 'warning', deviationMs: 31_000 }, lang: 'ja',
  tr: (key) => key };
let tickClock = base;
const modal = new Function('state', 'el', 'document', '$', 'clientNow', 'recoveryClock',
  'parseUserCorrectionMs', 'parseRecoveryCorrectionSeconds', 'acknowledgeClockCorrection', 'closeClockCorrection',
  'toggleRecoveryCorrectionSign',
  `${modalFns}\nreturn { renderClockModal, updateClockTimes };`)(
  modalState, element, document, document.getElementById, () => tickClock,
  { getClockCorrection: () => 0 }, parseUserCorrectionMs, (value) => parseUserCorrectionMs(Number(value) * 1000), () => {}, () => {},
  (value) => value.startsWith('－') ? `＋${value.slice(1)}` : `−${value}`);
modal.renderClockModal();
const inputNode = document.getElementById('recovery-clock-input');
const currentNode = document.getElementById('recovery-clock-current');
const correctedNode = document.getElementById('recovery-clock-corrected');
assert(inputNode && currentNode && correctedNode);
inputNode.value = '+30';
inputNode.focused = true;
modal.updateClockTimes();
const before = currentNode.textContent;
tickClock += 3000;
modal.renderClockModal();
assert.strictEqual(document.getElementById('recovery-clock-input'), inputNode);
assert.strictEqual(document.getElementById('recovery-clock-current'), currentNode);
assert.equal(inputNode.value, '+30');
assert.equal(inputNode.focused, true);
assert.notEqual(currentNode.textContent, before);
assert.equal(correctedNode.textContent, new Date(tickClock + 30_000).toLocaleString('ja'));

const ja = JSON.parse(read('public/locales/ja/game_ja.json'));
const en = JSON.parse(read('public/locales/en/game_en.json'));
const i18n = read('chatgame-tools/src/common/i18n.js');
for (const key of ['warning', 'confirmation', 'current', 'correction', 'corrected', 'confirm', 'correct', 'close']) {
  assert(ja.clock[key] && en.clock[key] && i18n.includes(`'recovery.clock.${key}'`));
}
assert.match(ja.clock.warning, /オンチェーンのブロックタイム/);
assert.match(ja.clock.warning, /\{offset\}/);

// D1b2: U-18 marks the C captured at arrival, even when the chain read finishes later.
const closeAt = base + 60_000;
const correctionMs = 30_000;
let rawNow = closeAt - correctionMs - 1500;
const makeActionReceipt = (suffix) => ({ receiverUid: 'V', actionHash: `0x${'ab'.repeat(32)}`,
  timestamp: closeAt - 5000, signature: `0x${suffix.repeat(128)}1b` });
const queueStart = hook.indexOf('const queueReceipt = useCallback(async (receipt, options = {}) => {');
const queueEnd = hook.indexOf('\n  }, [blockNum, groupId, uid, ingestReceipt, gameRpcSession]);', queueStart);
assert(queueStart >= 0 && queueEnd > queueStart);
let offered = null;
const queueScope = {
  useCallback: (fn) => fn, Date: { now: () => rawNow }, clientNow: (wall = rawNow) => wall + correctionMs,
  receiptAdmissionRef: { current: { offer: async (row) => { offered = row; return true; } } },
  receiptsRef: { current: {} }, liveOnlyReceiptsRef: { current: new Map() },
  receiptIdentityDigest, MAX_RECEIPTS_PER_ISSUER: 700,
  receiptChainClockRef: { current: {} },
  receiptTipRetryAfterRef: { current: 0 }, gameRpcSession: null,
  readReceiptChainTime: async () => { rawNow += 3000; return null; },
  readTimeChainTipMs: async () => null, markActionReceiptSource,
  chainTimelineRef: { current: { chatCloseAt: closeAt } },
  confirmedChatWindowRef: { current: null }, CHAT_WINDOW_CLOCK_SKEW_MS: 120_000,
  ingestReceipt: () => {}, blockNum: 1, groupId: 1, uid: 'V',
};
const officialQueue = new Function(...Object.keys(queueScope),
  `return (${hook.slice(queueStart + 'const queueReceipt = useCallback('.length, queueEnd + 4)});`)(
  ...Object.values(queueScope));
await officialQueue(makeActionReceipt('1'));
assert.equal(offered._deviceSeenAt, closeAt - 1500);
assert.equal(mayCarryActionReceipt(offered, closeAt), true);
rawNow = closeAt - correctionMs + 1500;
await officialQueue(makeActionReceipt('2'));
assert.equal(offered._deviceSeenAt, null);
assert.equal(mayCarryActionReceipt(offered, closeAt), false);
rawNow = closeAt - correctionMs + 1500;
await officialQueue(makeActionReceipt('5'), { deviceArrivalMs: closeAt - 1500, fromLive: true });
assert.equal(offered._deviceSeenAt, closeAt - 1500, 'live verification keeps the arrival correction');
rawNow = closeAt - correctionMs + 1500;
const storedMarked = { ...makeActionReceipt('6'), _chainSeenAt: closeAt - 1000,
  _deviceSeenAt: closeAt - 1500 };
await officialQueue(storedMarked, { source: 'storage' });
assert.equal(clientChatSourcedReceipts({ [offered.signature]: offered }, null, closeAt).length, 1,
  'MCF stored U-18 marks keep the action receipt in the submission source after close');

const makeRecovery = () => new RecoveryRelay({ signKey: `0x${'38'.repeat(32)}`,
  blockNum: 1, groupId: 1, uid: 'A', members: [{ uid: 'A' }, { uid: 'V' }],
  getChatCloseAtMs: () => closeAt, now: (wall = rawNow) => wall + correctionMs,
  getChainTimeMs: async () => { rawNow += 3000; return null; } });
rawNow = closeAt - correctionMs - 1500;
const earlyRecovery = makeRecovery();
await earlyRecovery._ingestReceiptArrivals([makeActionReceipt('3')], { arrivalAtOverride: rawNow });
const recoveryEarly = earlyRecovery.getReceipts()[0];
assert.equal(recoveryEarly._deviceSeenAt, closeAt - 1500);
assert.equal(mayCarryActionReceipt(recoveryEarly, closeAt), true);
rawNow = closeAt - correctionMs + 1500;
const lateRecovery = makeRecovery();
await lateRecovery._ingestReceiptArrivals([makeActionReceipt('4')], { arrivalAtOverride: rawNow });
const recoveryLate = lateRecovery.getReceipts()[0];
assert.equal(recoveryLate._deviceSeenAt, null);
assert.equal(mayCarryActionReceipt(recoveryLate, closeAt), false);
rawNow = closeAt - correctionMs + 1500;
const liveRecovery = makeRecovery();
await liveRecovery._ingestReceiptArrivals([makeActionReceipt('6')], {
  fromLive: true, arrivalAtOverride: closeAt - correctionMs - 1500,
  deviceArrivalMsOverride: closeAt - 1500 });
assert.equal(liveRecovery.getReceipts()[0]._deviceSeenAt, closeAt - 1500);

// A step remains a warning trigger. Only a forward raw-wall gap (or a monotonic gap) opens the window.
const hookTickStart = hook.indexOf('const readReceiptTick = async () => {');
const hookTickEnd = hook.indexOf('      if (readReceiptTickRunningRef.current) return;', hookTickStart);
assert(hookTickStart >= 0 && hookTickEnd > hookTickStart);
const officialGap = async (wallNow) => {
  const pauseRef = { current: openReadReceiptPause(null, 1000, false, 1000) };
  let stepChecks = 0;
  const bindings = { readReceiptPauseRef: pauseRef, performance: { now: () => 9000 },
    Date: { now: () => wallNow }, detectClockStep,
    setClockStepTick: () => { stepChecks++; }, readReceiptTickGap, openReadReceiptPause };
  const tick = new Function(...Object.keys(bindings),
    `${hook.slice(hookTickStart, hookTickEnd)}\n}; return readReceiptTick;`)(...Object.values(bindings));
  await tick();
  return { pause: pauseRef.current, stepChecks };
};
const officialForward = await officialGap(301_000);
assert.equal(officialForward.stepChecks, 1);
assert.equal(officialForward.pause.until, 19_000);
assert.equal((await officialGap(-299_000)).pause.until, 11_000);
const recoveryTickStart = recovery.indexOf('state._rrTick = () => {');
const recoveryTickEnd = recovery.indexOf('    if (state._rrTickRunning) return;', recoveryTickStart);
assert(recoveryTickStart >= 0 && recoveryTickEnd > recoveryTickStart);
const recoveryGap = (wallNow) => {
  const tickState = { readReceiptPause: openReadReceiptPause(null, 1000, false, 1000) };
  let stepChecks = 0;
  const bindings = { state: tickState, performance: { now: () => 9000 }, Date: { now: () => wallNow },
    detectClockStep, checkClock: () => { stepChecks++; }, readReceiptTickGap, openReadReceiptPause };
  const tick = new Function(...Object.keys(bindings),
    `${recovery.slice(recoveryTickStart, recoveryTickEnd)}\n}; return state._rrTick;`)(...Object.values(bindings));
  tick();
  return { pause: tickState.readReceiptPause, stepChecks };
};
assert.deepEqual({ until: recoveryGap(301_000).pause.until, steps: recoveryGap(301_000).stepChecks },
  { until: 19_000, steps: 1 });
assert.equal(recoveryGap(-299_000).pause.until, 11_000);

// Invalid block timestamps are absent; a stalled first public reader cannot consume the outer 3 s budget.
const realFetch = globalThis.fetch;
const blockSeconds = Math.floor(base / 1000);
const blockResponse = (id, seconds) => new Response(JSON.stringify({ jsonrpc: '2.0', id,
  result: { number: '0x10', hash: `0x${'11'.repeat(32)}`, parentHash: `0x${'22'.repeat(32)}`,
    timestamp: `0x${seconds.toString(16)}`, nonce: '0x0000000000000000', difficulty: '0x0',
    gasLimit: '0x1', gasUsed: '0x0', miner: `0x${'00'.repeat(20)}`, extraData: '0x',
    logsBloom: `0x${'00'.repeat(256)}`, transactionsRoot: `0x${'33'.repeat(32)}`,
    stateRoot: `0x${'44'.repeat(32)}`, receiptsRoot: `0x${'55'.repeat(32)}`,
    sha3Uncles: `0x${'66'.repeat(32)}`, size: '0x1', totalDifficulty: '0x0',
    transactions: [], uncles: [], baseFeePerGas: '0x1' } }),
{ status: 200, headers: { 'content-type': 'application/json' } });
let rpcMode = 'stall';
const tipRead = process.env.S3FIX_D1B2_MUTATION === 'sequential-read'
  ? async () => {
    for (const { client } of await getTimeReadSources()) {
      let timer;
      try {
        const block = await Promise.race([client.getBlock(), new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('old source timeout')), 3000);
        })]);
        return Number(block.timestamp) * 1000;
      }
      catch { /* old serial fallback */ }
      finally { clearTimeout(timer); }
    }
    return null;
  } : readTimeChainTipMs;
globalThis.fetch = async (url, init) => {
  const host = String(url instanceof Request ? url.url : url);
  const { id } = JSON.parse(init.body);
  if (rpcMode === 'stall' && host.includes('publicnode')) return new Promise(() => {});
  if (rpcMode === 'stall' && /1rpc|tenderly/.test(host)) await new Promise((resolve) => setTimeout(resolve, 1000));
  if (rpcMode === 'invalid-first' && /ankr|flashbots|drpc/.test(host)) {
    return new Promise(() => {});
  }
  if (rpcMode === 'invalid-first' && /1rpc|tenderly/.test(host)) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  const seconds = (rpcMode === 'all-invalid' || (/1rpc|tenderly/.test(host) && rpcMode === 'invalid')
    || (host.includes('publicnode') && rpcMode === 'invalid-first')) ? 2 ** 53 : blockSeconds;
  return blockResponse(id, seconds);
};
try {
  const started = performance.now();
  assert.equal(await tipRead(), base);
  assert(performance.now() - started < 2800, 'official second reader answers inside the outer 3 s budget');
  const recoveryReader = makeTimeReadClient({ rpcUrls: ['https://ethereum-rpc.publicnode.com',
    'https://1rpc.io/eth', 'https://rpc.flashbots.net'] });
  const recoveryStarted = performance.now();
  assert.equal(Number((await recoveryReader.getBlock()).timestamp) * 1000, base);
  assert(performance.now() - recoveryStarted < 2800);
  rpcMode = 'invalid';
  const officialSamples = await readTimeClockSamples();
  const recoverySamples = await recoveryReader.readSamples();
  if (process.env.S3FIX_D1B2_MUTATION === 'unsafe-sample') {
    officialSamples.publicSamples.push({ sourceId: 'bad', blockTimestampMs: 2 ** 53,
      observedMonoMs: performance.now() });
  }
  for (const samples of [officialSamples, recoverySamples]) {
    assert.equal(samples.publicSamples.length, 2);
    const reading = selectChainClockReading({ ...samples, nowMonoMs: performance.now() });
    const firstMono = performance.now();
    const first = advanceChainClockAlert({ reading, wallNowMs: base + 300_000,
      correctionMs: 0, monoNowMs: firstMono, context: 'entry' });
    assert.equal(first.kind, 'pending');
    assert.equal(advanceChainClockAlert({ reading, wallNowMs: base + 300_000, correctionMs: 0,
      monoNowMs: firstMono + 12_000, context: 'entry', previousOutside: first.nextOutside }).kind, 'warning');
  }
  rpcMode = 'invalid-first';
  assert.equal(await readTimeChainTipMs(), base, 'invalid first response is skipped');
  await assert.rejects(() => recoveryReader.getBlock(), 'one unapproved public answer cannot open the gate');
  const approvedReader = makeTimeReadClient({ rpcUrls: ['https://ethereum-rpc.publicnode.com',
    'https://1rpc.io/eth', 'https://rpc.flashbots.net'], agreementState: { approved: new Set(['1rpc.io']) },
    clientNowMs: () => base });
  assert.equal(Number((await approvedReader.getBlock()).timestamp) * 1000, base);
  rpcMode = 'all-invalid';
  assert.equal(await readTimeChainTipMs(), null);
  await assert.rejects(() => recoveryReader.getBlock());
} finally { globalThis.fetch = realFetch; }

// Both UIs accept whitespace and the displayed sign variants.
const recoveryParserStart = recovery.indexOf('function parseRecoveryCorrectionSeconds(');
const recoveryParserEnd = recovery.indexOf('\nfunction repeatedRecoveryReissues(', recoveryParserStart);
assert(recoveryParserStart >= 0 && recoveryParserEnd > recoveryParserStart);
const recoveryParser = new Function('parseUserCorrectionMs',
  `${recovery.slice(recoveryParserStart, recoveryParserEnd)}\nreturn parseRecoveryCorrectionSeconds;`)(parseUserCorrectionMs);
for (const value of ['-180', '−180', '－１８０', '＋30', ' 30', '\t—３０\u3000', '\u00a0+30\u00a0']) {
  assert.equal(recoveryParser(value), parseCorrectionSeconds(value, 0).deltaMs);
}
for (const value of ['1.5', 'abc', '86401', '①']) assert.throws(() => recoveryParser(value));
const officialConfirmStart = officialModal.indexOf('  const finishCorrection = async (selected) => {');
const officialConfirmEnd = officialModal.indexOf('  return (', officialConfirmStart);
let pendingOfficial = null;
let savedOfficial = null;
const officialConfirm = new Function('parseCorrectionSeconds', 'input', 'setError', 'setChecking',
  'setPendingCorrection', 'onConfirm', 'onPrepare',
  `${officialModal.slice(officialConfirmStart, officialConfirmEnd)}\nreturn confirm;`)(
    parseCorrectionSeconds, '+70', () => {}, () => {},
    (value) => { pendingOfficial = value; }, (value) => { savedOfficial = value; },
    async () => ({ adoption: true, repeated: true, deviationMs: 70_000, sourceIds: ['wallet'] }));
await officialConfirm();
assert.equal(pendingOfficial.review.adoption, true);
assert.equal(pendingOfficial.review.repeated, true);
assert.equal(pendingOfficial.stage, 'review');
assert.equal(savedOfficial, null);
assert.match(officialModal, /setPendingCorrection\(\{ \.\.\.pendingCorrection, stage: 'partial' \}\)/);
const officialConfirmNoL = new Function('parseCorrectionSeconds', 'input', 'setError', 'setChecking',
  'setPendingCorrection', 'onConfirm', 'onPrepare',
  `${officialModal.slice(officialConfirmStart, officialConfirmEnd)}\nreturn confirm;`)(
    parseCorrectionSeconds, '+30', () => {}, () => {},
    () => { throw Error('no L must not prompt'); }, (value) => { savedOfficial = value; },
    async () => ({ adoption: false, repeated: false, deviationMs: null }));
await officialConfirmNoL();
assert.equal(savedOfficial.nextMs, 60_000);
const officialPartial = new Function('parseCorrectionSeconds', 'input', 'setError', 'setChecking',
  'setPendingCorrection', 'onConfirm', 'onPrepare',
  `${officialModal.slice(officialConfirmStart, officialConfirmEnd)}\nreturn confirm;`)(
    parseCorrectionSeconds, '-60', () => {}, () => {},
    (value) => { pendingOfficial = value; }, () => { throw Error('partial must prompt'); },
    async () => ({ adoption: false, repeated: false, partial: { alert: true, keys: ['chosen'] } }));
await officialPartial();
assert.equal(pendingOfficial.stage, 'partial');
assert.match(officialModal, /skipKeys: new Set\(pendingCorrection\.review\.partial\.keys\)/);
assert.match(officialModal, /game\.clock\.partialReissueApply/);
assert.match(officialModal, /game\.clock\.partialReissueSkip/);
const toggleSource = officialModal.slice(officialModal.indexOf('export function toggleCorrectionSign('),
  officialModal.indexOf('\nexport default function ClockCorrectionModal'));
const toggleSign = new Function('leadingSign', `${toggleSource.replace('export ', '')}\nreturn toggleCorrectionSign;`)(
  /^[+＋\-−－ーｰ‐‑‒–—―]/u);
assert.equal(toggleSign(' \t－１８０ '), '＋１８０');
assert.equal(toggleSign('＋１８０'), '−１８０');
assert.match(officialModal, /inputMode="text"/);
assert.match(officialModal, /aria-label=\{t\('game\.clock\.toggleSign'\)\}/);
assert.match(recovery, /inputMode: 'text'/);
assert.match(page, /reading = selectChainClockReading\([\s\S]*?console\.warn\('clock reading failed:'/);
assert.match(recovery, /reading = selectChainClockReading\([\s\S]*?log\(`clock reading failed:/);
const findTextNode = (root, value) => root.textContent === value ? root
  : root.children?.map((child) => findTextNode(child, value)).find(Boolean) || null;
const recoverySign = findTextNode(body, '＋ / −');
assert(recoverySign && typeof recoverySign.onclick === 'function');
inputNode.value = '－１８０';
recoverySign.onclick();
assert.equal(inputNode.value, '＋１８０');
modalState.clockPendingCorrection = { deltaMs: 70_000, nextMs: 70_000 };
modalState.clockDraft = '−180';
modal.renderClockModal();
const backToInput = findTextNode(body, 'recovery.clock.back');
assert(backToInput && typeof backToInput.onclick === 'function');
backToInput.onclick();
assert.equal(modalState.clockPendingCorrection, null);
assert.equal(document.getElementById('recovery-clock-input').value, '−180');
modalState.clockPendingCorrection = { stage: 'review', adoption: false, repeated: true,
  partial: { alert: true, keys: ['chosen'], chats: [{ key: 'm1', label: 'S: m1' }] } };
modal.renderClockModal();
assert(findTextNode(body, 'recovery.clock.repeated'));
modalState.clockPendingCorrection.stage = 'partial';
modal.renderClockModal();
assert(findTextNode(body, 'recovery.clock.partialReissue'));
assert(findTextNode(body, 'S: m1'));
assert(findTextNode(body, 'recovery.clock.partialReissueApply'));
assert(findTextNode(body, 'recovery.clock.partialReissueSkip'));
const endTabStart = recovery.indexOf('function endThisTab() {');
const endTabEnd = recovery.indexOf('\nfunction reopenReadReceiptPause()', endTabStart);
const endedState = { tabEnded: false, clockAlert: { kind: 'warning' }, relay: { stop() {} } };
const endTab = new Function('state', 'clearInterval', 'renderGame',
  'receiptDisplayCoalescer', 'receiptDisplayMemo', 'provableMessagesMemo',
  `${recovery.slice(endTabStart, endTabEnd)}\nreturn endThisTab;`)(endedState, () => {}, () => {},
  null, null, null);
endTab();
assert.equal(endedState.clockAlert, null);

// D1e: a second honest device is visible in memory but absent from this device's stored rows.
{
  const row = (signature, msgRefs, senderUid = 'S', receiverUid = 'R') =>
    ({ signature, msgRefs, senderUid, receiverUid, timestamp: base });
  const a1 = row('A1', ['m1', 'm2']);
  const b1 = row('B1', ['m2', 'm3']);
  const a2 = row('A2', ['m3', 'm4']);
  const b2 = row('B2', ['m4', 'm5']);
  const unrelated = row('A0', ['n1'], 'T');
  const known = [a1, a2, unrelated];
  const fromMemory = [b1, b2, a1];
  const plans = [a1, a2, unrelated];
  const options = { uid: 'R', known, fromMemory, plans,
    tracked: [b1, { ...row('X', ['m1', 'm2']), actionHash: 'action' }, row('Y', ['m1', 'm2'], 'S', 'other')] };
  const estimate = estimatePartialReadReissues(options);
  assert.deepEqual([estimate.before, estimate.after, estimate.alert], [4, 6, true]);
  assert.equal(estimatePartialReadReissues({ ...options, tracked: [] }).before, 4,
    'actionHash と他の発行者、および署名の重複は土台を増やさない');
  assert.deepEqual(estimate.keys, [reissueGroupKey(a1), reissueGroupKey(a2)]);
  assert.equal(estimatePartialReadReissues({ ...options, fromMemory: [], tracked: [] }).alert, false);
  assert.deepEqual(estimatePartialReadReissues({ ...options, plans: [a1] }).after, 5);
  assert.equal(estimatePartialReadReissues({ uid: 'R', known: [a1, b1, a2], plans: [a1] }).after, 4);
  assert.equal(estimatePartialReadReissues({ ...options, plans: [unrelated] }).alert, false);
  const alreadyFive = [a1, b1, a2, b2, { ...a1, signature: 'A1x' }];
  assert.deepEqual(estimatePartialReadReissues({ uid: 'R', known: alreadyFive,
    plans: [unrelated] }).alert, false);
  assert.equal(estimatePartialReadReissues({ uid: 'R', known: alreadyFive, plans: [a1] }).alert, true);
  assert.equal(estimatePartialReadReissues({ uid: 'R', known: [a1], plans: [a1] }).alert, false);
  assert.equal(estimatePartialReadReissues({ ...options, plans: [] }).alert, false);
  const afterSkip = new PartialReadReceiptTracker();
  for (const receipt of [...known, b1, b2, ...plans.filter((plan) => !estimate.keys.includes(reissueGroupKey(plan)))]) {
    afterSkip.add({ ...receipt, signature: receipt === unrelated && plans.includes(receipt) ? 'A0x' : receipt.signature });
  }
  assert.equal(afterSkip.byIssuer.get('R').partial.size, estimate.before);
  const colliding = estimatePartialReadReissues({ uid: 'R', known: [
    { ...a1, signature: '__clock_reissue_estimate_0__' }, b1, a2, b2], plans: [a1] });
  assert.equal(colliding.after, 5, '仮の署名は実在の署名に衝突しない');
  if (process.env.S3FIX_D1E_MUTATION === 'threshold-six') {
    const source = read('src/utils/receipt-warnings.js');
    const start = source.indexOf('export function reissueGroupKey(');
    const end = source.indexOf('export const RECEIPT_WARNING_WAIT_MS', start);
    const original = source.slice(start, end);
    const changed = original.replace('after >= PARTIAL_READ_RECEIPT_ALERT_THRESHOLD',
      'after > PARTIAL_READ_RECEIPT_ALERT_THRESHOLD');
    assert.notEqual(changed, original);
    const oldEstimate = new Function('PartialReadReceiptTracker', 'PARTIAL_READ_RECEIPT_ALERT_THRESHOLD',
      `${changed.replaceAll('export ', '')}\nreturn estimatePartialReadReissues;`)(PartialReadReceiptTracker, 5);
    assert.equal(oldEstimate({ uid: 'R', known: [a1, b1, a2, b2], plans: [a1] }).alert, true,
      '5枚ちょうどで確認する');
  }
  const messageTimestamps = new Map([['S|m1', base], ['S|m2', base]]);
  const actualPlan = planReadReceiptReissues({ receipts: [a1], shiftBackMs: 1000,
    messageTimestamps, nowMs: base - 1000, chattingStartMs: base - 5000, chatCloseAtMs: base + 5000 });
  assert.equal(reissueGroupKey(actualPlan[0]), reissueGroupKey(a1));
  assert.equal(read('src/utils/receipt-warnings.js'), read('chatgame-tools/vendor/src/utils/receipt-warnings.js'));
  const ja = JSON.parse(read('public/locales/ja/game_ja.json')).clock;
  const en = JSON.parse(read('public/locales/en/game_en.json')).clock;
  const sentence = '以下のチャットに対する既読を時刻を修正して再発行を行うと、不正行為「対象が重複する既読の累積枚数が5枚を超える」に該当するため、他のプレイヤーに密告される可能性が高くなります。以下のチャットに対する既読の時刻修正を行いますか？';
  assert.equal(ja.partialReissue, sentence);
  assert.equal(ja.partialReissueApply, '時刻修正を行う');
  assert.equal(ja.partialReissueSkip, '時刻修正を行わない');
  assert(en.partialReissue && en.partialReissueApply && en.partialReissueSkip);
  const recoveryI18n = read('chatgame-tools/src/common/i18n.js');
  assert(recoveryI18n.includes(`'recovery.clock.partialReissue': '${sentence}'`));
  assert(recoveryI18n.includes("'recovery.clock.partialReissueApply': '時刻修正を行う'"));
  assert(recoveryI18n.includes("'recovery.clock.partialReissue': '如果修正以下聊天的已读回执时间并重新发放，将属于不正行为“目标重叠的已读回执累计超过5张”，被其他玩家举报的可能性会提高。要修正以下聊天的已读回执时间吗？'"));
  assert.match(recoveryI18n, /'recovery\.clock\.partialReissueSkip': '不修正时间'/);

  const messages = ['m1', 'm2', 'm3', 'm4', 'm5'].map((ref) =>
    ({ uid: 'S', ref, timestamp: base, text: ref })).concat([{ uid: 'T', ref: 'n1', timestamp: base, text: 'n1' }]);
  const timelineRef = { current: { chattingStart: base - 5000, chatCloseAt: base + 5000 } };
  const storage = { getItem: () => JSON.stringify(known) };
  const reviewStart = hook.indexOf('  const reviewClockReissues = ({ deltaMs, nowMs }) => {');
  const reviewEnd = hook.indexOf('\n  const countRepeatedClockReissues', reviewStart);
  assert(reviewStart >= 0 && reviewEnd > reviewStart);
  const officialReview = new Function('chainTimelineRef', 'blockNum', 'groupId', 'uid', 'localStorage',
    'receiptsRef', 'messagesRef', 'msgRefOf', 'computeMsgKeyV2', 'planReadReceiptReissues',
    'countRepeatedReissueGroups', 'estimatePartialReadReissues', 'readReceiptTrackerRef', 'reissueGroupKey',
    `${hook.slice(reviewStart, reviewEnd)}\nreturn reviewClockReissues;`)(
    timelineRef, 77, 1, 'R', storage, { current: { b1, b2 } }, { current: messages },
    (key) => key, (_block, _group, message) => message.ref, planReadReceiptReissues,
    () => 0, estimatePartialReadReissues, { current: new PartialReadReceiptTracker() }, reissueGroupKey);
  const reviewed = officialReview({ deltaMs: -1000, nowMs: base - 1000 });
  assert.equal(reviewed.repeated, 0);
  assert.deepEqual([reviewed.partial.before, reviewed.partial.after], [4, 6]);
  assert.deepEqual(reviewed.partial.groups, [
    { senderUid: 'S', msgRefs: ['m1', 'm2'] }, { senderUid: 'S', msgRefs: ['m3', 'm4'] }]);
  const memoryOnly = [a1, { ...a1, signature: 'A1-other' }];
  const emptyStorage = { getItem: () => null };
  const firstOfficialReview = new Function('chainTimelineRef', 'blockNum', 'groupId', 'uid', 'localStorage',
    'receiptsRef', 'messagesRef', 'msgRefOf', 'computeMsgKeyV2', 'planReadReceiptReissues',
    'countRepeatedReissueGroups', 'estimatePartialReadReissues', 'readReceiptTrackerRef', 'reissueGroupKey',
    `${hook.slice(reviewStart, reviewEnd)}\nreturn reviewClockReissues;`)(
    timelineRef, 77, 1, 'R', emptyStorage,
    { current: Object.fromEntries(memoryOnly.map((row) => [row.signature, row])) },
    { current: messages }, (key) => key, (_block, _group, message) => message.ref,
    planReadReceiptReissues, countRepeatedReissueGroups, estimatePartialReadReissues,
    { current: new PartialReadReceiptTracker() }, reissueGroupKey);
  assert.equal(firstOfficialReview({ deltaMs: -1000, nowMs: base - 1000 }).repeated, 0,
    '保存が空なら他端末の同じ組は初回の出し直し警告に数えない');
  // W6R: a fresh storage origin must still review the groups already visible in memory.
  const w6Messages = ['m1', 'm2', 'm3', 'm4', 'm5'].map((ref, i) =>
    ({ uid: 'S', ref, timestamp: base - 360000 + i * 10000 }));
  const w6Timeline = { current: { chattingStart: base - 3600000, chatCloseAt: base + 3600000 } };
  const w6Row = (signature, msgRefs, timestamp) =>
    ({ signature, msgRefs, senderUid: 'S', receiverUid: 'R', timestamp });
  const fast = 60000;
  const w6Memory = [
    w6Row('A1', ['m1', 'm2'], base - 300000 + fast),
    w6Row('B1', ['m2', 'm3'], base - 298000 + fast),
    w6Row('A2', ['m3', 'm4'], base - 240000 + fast),
    w6Row('B2', ['m4', 'm5'], base - 238000 + fast),
  ];
  const w6Tracker = new PartialReadReceiptTracker();
  for (const receipt of w6Memory) w6Tracker.add(receipt);
  const makeOfficialW6Review = (memory, tracked = w6Tracker) => new Function(
    'chainTimelineRef', 'blockNum', 'groupId', 'uid', 'localStorage', 'receiptsRef',
    'messagesRef', 'msgRefOf', 'computeMsgKeyV2', 'planReadReceiptReissues',
    'countRepeatedReissueGroups', 'estimatePartialReadReissues', 'readReceiptTrackerRef',
    'reissueGroupKey', `${hook.slice(reviewStart, reviewEnd)}\nreturn reviewClockReissues;`)(
    w6Timeline, 77, 1, 'R', emptyStorage,
    { current: Object.fromEntries(memory.map((receipt) => [receipt.signature, receipt])) },
    { current: w6Messages }, (key) => key, (_block, _group, message) => message.ref,
    planReadReceiptReissues, countRepeatedReissueGroups, estimatePartialReadReissues,
    { current: tracked }, reissueGroupKey);
  const w6RecoveryReviewStart = recovery.indexOf('function repeatedRecoveryReissues(deltaMs) {');
  const w6RecoveryReviewEnd = recovery.indexOf('\nfunction recoveryPartialChats(', w6RecoveryReviewStart);
  assert(w6RecoveryReviewStart >= 0 && w6RecoveryReviewEnd > w6RecoveryReviewStart);
  const makeRecoveryW6Review = (memory) => new Function('state', 'localStorage',
    'msgRefOf', 'planReadReceiptReissues', 'clientNow', 'countRepeatedReissueGroups',
    'estimatePartialReadReissues', 'reissueGroupKey',
    `${recovery.slice(w6RecoveryReviewStart, w6RecoveryReviewEnd)}\nreturn repeatedRecoveryReissues;`)(
    { timeline: w6Timeline.current, blockNum: 77, groupId: 1, uid: 'R',
      receipts: Object.fromEntries(memory.map((receipt) => [receipt.signature, receipt])),
      relay: { getMessages: () => w6Messages, getMsgKey: (message) => message.ref } },
    emptyStorage, (key) => key, planReadReceiptReissues, () => base + fast,
    countRepeatedReissueGroups, estimatePartialReadReissues, reissueGroupKey);
  const officialW6 = makeOfficialW6Review(w6Memory)({ deltaMs: -fast, nowMs: base });
  const recoveryW6 = makeRecoveryW6Review(w6Memory)(-fast);
  assert.equal(officialW6.partial.alert, true, '公式は保存が空でも一部重複を確認する');
  assert.equal(officialW6.partial.keys.length, 4);
  assert.equal(recoveryW6.partial.alert, true, '復元は保存が空でも一部重複を確認する');
  assert.equal(recoveryW6.partial.keys.length, 4);
  const floorMemory = [w6Row('original', ['m1', 'm2'], base - 300000 + fast),
    w6Row('reissued', ['m1', 'm2'], base - 300000)];
  assert.equal(makeOfficialW6Review(floorMemory)({ deltaMs: -fast, nowMs: base }).repeated, 0,
    '公式の二度目の警告は保存済みだけで数える');
  assert.equal(makeRecoveryW6Review(floorMemory)(-fast).repeated, 0,
    '復元の二度目の警告は保存済みだけで数える');
  const prepareStart = page.indexOf('  const prepareClockCorrection = useCallback(');
  const prepareEnd = page.indexOf('\n  const acknowledgeClock = useCallback(', prepareStart);
  const listedMessages = [...messages, messages[2]];
  const listingPrepare = new Function('useCallback', 'readFreshClock', 'classifyChainClockDeviation',
    'clientNow', 'wsRaw', 'blockNum', 'groupId', 'msgRefOf', 'computeMsgKeyV2', 'getMemberDisplayName',
    `${page.slice(prepareStart, prepareEnd)}\nreturn prepareClockCorrection;`)(
    (fn) => fn, async () => null, () => null, () => base,
    { reviewClockReissues: () => ({ repeated: 0, partial: { ...reviewed.partial } }),
      messages: listedMessages, members: [{ uid: 'S', name: 'Sender' }, { uid: 'T', name: 'Other' }] },
    77, 1, (key) => key, (_block, _group, message) => message.ref,
    (member) => member?.name || '?');
  const listedReview = await listingPrepare({ deltaMs: -1000 });
  assert.deepEqual(listedReview.partial.chats.map(({ key }) => key),
    ['S|m1', 'S|m2', 'S|m3', 'S|m4']);
  assert.equal(listedReview.partial.chats[0].label, 'Sender: m1');
  assert.equal(officialReview({ deltaMs: 1000, nowMs: base + 1000 }).partial.alert, false);
  const trackerOnly = new PartialReadReceiptTracker();
  trackerOnly.add(b1); trackerOnly.add(b2);
  const trackedReview = new Function('chainTimelineRef', 'blockNum', 'groupId', 'uid', 'localStorage',
    'receiptsRef', 'messagesRef', 'msgRefOf', 'computeMsgKeyV2', 'planReadReceiptReissues',
    'countRepeatedReissueGroups', 'estimatePartialReadReissues', 'readReceiptTrackerRef', 'reissueGroupKey',
    `${hook.slice(reviewStart, reviewEnd)}\nreturn reviewClockReissues;`)(
    timelineRef, 77, 1, 'R', storage, { current: {} }, { current: messages },
    (key) => key, (_block, _group, message) => message.ref, planReadReceiptReissues,
    () => 0, estimatePartialReadReissues, { current: trackerOnly }, reissueGroupKey);
  assert.equal(trackedReview({ deltaMs: -1000, nowMs: base - 1000 }).partial.alert, true);

  const reissueStart = hook.indexOf('  reissueReadReceiptsRef.current = async (shiftBackMs');
  const reissueEnd = hook.indexOf('\n  // 既読受領証明の自動バッチ発行', reissueStart);
  assert(reissueStart >= 0 && reissueEnd > reissueStart);
  const reissueRef = { current: null };
  const issued = [];
  const signKey = `0x${'11'.repeat(32)}`;
  new Function('reissueReadReceiptsRef', 'readReceiptTickRunningRef', 'isSpectator', 'signKey', 'uid',
    'isGameIdentityCurrent', 'rosterStartConfirmedRef', 'phaseRef', 'isAwayRef', 'sessionActivityRef',
    'coordinateSelfReadReceiptBatch', 'blockNum', 'groupId', 'queueReceipt', 'canIssueReceiptAtChainTip',
    'messagesRef', 'msgRefOf', 'computeMsgKeyV2', 'receiptsRef', 'chainTimelineRef',
    'planReadReceiptReissues', 'clientNow', 'privateKeyToAccount', 'canonicalizeSignature',
    'readReceiptSignString', 'rememberOwnReadSignature', 'send', 'relayChannelRef', 'readReceiptChannelRef', 'reissueGroupKey',
    'receiptIssuanceBlocked',
    process.env.S3FIX_D1E_MUTATION === 'ignore-skip'
      ? hook.slice(reissueStart, reissueEnd).replace('if (skipKeys?.has(reissueGroupKey(plan))) continue;',
        'if (false) continue;') : hook.slice(reissueStart, reissueEnd))(
    reissueRef, { current: false }, false, signKey, 'R', () => true, { current: true },
    { current: 'chatting' }, { current: false }, { current: { warned: false, ended: false } },
    async (_key, _restore, emit) => emit({ signal: null, known }), 77, 1, async () => true,
    async () => true, { current: messages }, (key) => key, (_block, _group, message) => message.ref,
    { current: { b1, b2 } }, timelineRef, planReadReceiptReissues, () => base - 1000,
    privateKeyToAccount, canonicalizeSignature, (...parts) => JSON.stringify(parts), () => {},
    ({ receipt }) => issued.push(receipt), { current: { publishReceipt() {} } },
    { current: { postMessage() {} } }, reissueGroupKey, () => false);
  assert.equal(typeof reissueRef.current, 'function');
  const listenerStart = hook.indexOf('  useEffect(() => subscribeClockCorrection((change) => {');
  const listenerClose = '\n  }), []);';
  const listenerEnd = hook.indexOf(listenerClose, listenerStart) + listenerClose.length;
  const applyStart = hook.indexOf('  const applyClockCorrection = (nextMs, skipKeys = null, reading = null) => {');
  const applyEnd = hook.indexOf('\n  reissueReadReceiptsRef.current = async', applyStart);
  assert(listenerStart >= 0 && listenerEnd > listenerStart && applyStart >= 0 && applyEnd > applyStart);
  let subscriber = null;
  let correction = 0;
  let shouldThrow = false;
  let maturityRearms = 0;
  const workRef = { current: Promise.resolve() };
  const skipRef = { current: null };
  const apply = new Function('useEffect', 'subscribeClockCorrection', 'setClockVersion', 'setPhaseTick',
    'maturitySchedulerRef',
    'correctionWorkRef', 'reissueReadReceiptsRef', 'clockReissueSkipRef', 'setClockCorrection',
    'sessionActivityRef', 'futureClockWarningBypassesCooldown', 'isGameIdentityCurrent', 'commitClockWarning',
    'advanceFutureClockWarning', 'Date', 'CHAT_WINDOW_CLOCK_SKEW_MS',
    `${hook.slice(listenerStart, listenerEnd)}\n${hook.slice(applyStart, applyEnd)}\nreturn applyClockCorrection;`)(
    (fn) => fn(), (fn) => { subscriber = fn; }, () => {}, () => {},
    { current: { rearm: () => { maturityRearms++; } } }, workRef, reissueRef, skipRef,
    (next) => { if (shouldThrow) throw new RangeError('cooldown');
      const deltaMs = next - correction; correction = next;
      if (deltaMs) subscriber({ deltaMs, nextMs: next });
      return { deltaMs }; }, { current: { clockWarning: INITIAL_FUTURE_CLOCK_WARNING } },
      futureClockWarningBypassesCooldown, () => true, () => {}, advanceFutureClockWarning, Date, 120000);
  apply(-1000, new Set(estimate.keys));
  await workRef.current;
  assert.deepEqual(issued.map(reissueGroupKey), [reissueGroupKey(unrelated)]);
  const actual = new PartialReadReceiptTracker();
  for (const receipt of [a1, b1, a2, b2, ...issued]) actual.add(receipt);
  assert.equal(actual.byIssuer.get('R').partial.size, 4);
  assert.equal(skipRef.current, null);
  issued.length = 0;
  apply(-1000, new Set(estimate.keys)); // delta 0 cannot leave a choice for the next correction.
  assert.equal(skipRef.current, null);
  apply(-2000, null);
  await workRef.current;
  assert.equal(maturityRearms, 0, '補正では成熟の見回りを張り直さない（S3R4-U-MATURE18・見回りが毎回 C を読む）');
  assert(!hook.slice(listenerStart, listenerEnd).includes('maturitySchedulerRef'),
    'MATURE18: 補正の購読に成熟のタイマーの張り直し口を残さない');
  assert.deepEqual(issued.map(reissueGroupKey), plans.map(reissueGroupKey));
  shouldThrow = true;
  assert.throws(() => apply(-3000, new Set(estimate.keys)), RangeError);
  assert.equal(skipRef.current, null);
  shouldThrow = false;
  issued.length = 0;
  apply(-4000, null);
  await workRef.current;
  assert.deepEqual(issued.map(reissueGroupKey), plans.map(reissueGroupKey));
  const noSubscriberRef = { current: null };
  const applyWithoutSubscriber = new Function('clockReissueSkipRef', 'setClockCorrection',
    'sessionActivityRef', 'futureClockWarningBypassesCooldown', 'isGameIdentityCurrent', 'commitClockWarning',
    'advanceFutureClockWarning', 'Date', 'CHAT_WINDOW_CLOCK_SKEW_MS',
    `${hook.slice(applyStart, applyEnd)}\nreturn applyClockCorrection;`)(
    noSubscriberRef, (value) => ({ nextMs: value }), { current: { clockWarning: INITIAL_FUTURE_CLOCK_WARNING } },
      futureClockWarningBypassesCooldown, () => true, () => {}, advanceFutureClockWarning, Date, 120000);
  applyWithoutSubscriber(-1000, new Set(estimate.keys));
  assert.equal(noSubscriberRef.current, null, '購読が無い場合も集合を消す');

  const recoveryReviewStart = recovery.indexOf('function repeatedRecoveryReissues(deltaMs) {');
  const recoveryReviewEnd = recovery.indexOf('\nfunction recoveryPartialChats(', recoveryReviewStart);
  const stateForReview = { uid: 'R', blockNum: 77, groupId: 1, timeline: timelineRef.current,
    receipts: { b1, b2 }, relay: { getMessages: () => messages, getMsgKey: (message) => message.ref } };
  const recoveryReview = new Function('state', 'localStorage', 'msgRefOf', 'planReadReceiptReissues',
    'clientNow', 'countRepeatedReissueGroups', 'estimatePartialReadReissues', 'reissueGroupKey',
    `${recovery.slice(recoveryReviewStart, recoveryReviewEnd)}\nreturn repeatedRecoveryReissues;`)(
    stateForReview, storage, (key) => key, planReadReceiptReissues, () => base,
    () => 0, estimatePartialReadReissues, reissueGroupKey);
  assert.deepEqual(recoveryReview(-1000).partial.keys, estimate.keys);
  const firstRecoveryReview = new Function('state', 'localStorage', 'msgRefOf', 'planReadReceiptReissues',
    'clientNow', 'countRepeatedReissueGroups', 'estimatePartialReadReissues', 'reissueGroupKey',
    `${recovery.slice(recoveryReviewStart, recoveryReviewEnd)}\nreturn repeatedRecoveryReissues;`)(
    { ...stateForReview, receipts: Object.fromEntries(memoryOnly.map((row) => [row.signature, row])) },
    emptyStorage, (key) => key, planReadReceiptReissues, () => base,
    countRepeatedReissueGroups, estimatePartialReadReissues, reissueGroupKey);
  assert.equal(firstRecoveryReview(-1000).repeated, 0);
  const listingStart = recovery.indexOf('function recoveryPartialChats(partial) {');
  const listingEnd = recovery.indexOf('\nasync function acknowledgeClockCorrection(', listingStart);
  const recoveryListing = new Function('state', 'msgRefOf', 'memberName',
    `${recovery.slice(listingStart, listingEnd)}\nreturn recoveryPartialChats;`)(
    { ...stateForReview, members: [{ uid: 'S', name: 'Sender' }],
      relay: { getMessages: () => listedMessages, getMsgKey: (message) => message.ref } },
    (key) => key, (member) => member?.name || '?');
  assert.deepEqual(recoveryListing(recoveryReview(-1000).partial).map(({ key }) => key),
    ['S|m1', 'S|m2', 'S|m3', 'S|m4']);
  const recoveryReissueStart = recovery.indexOf('async function reissueReadReceipts(');
  const recoveryReissueEnd = recovery.indexOf('\n// 既読マップ:', recoveryReissueStart);
  const recovered = [];
  const recoveryState = { ...stateForReview, identity: { signKey }, away: false,
    otherSessionReadReceipt: false, tabEnded: false, _rrTickRunning: false,
    ownSessionReadSignatures: new Set(), ownSessionSignatures: new Set(),
    relay: { ...stateForReview.relay, publishReceipt: async (receipt) => recovered.push(receipt),
      restartMaturityTimer: () => {} } };
  const recoveryReissue = new Function('state', 'rosterReady', 'currentPhase',
    'coordinateSelfReadReceiptBatch', 'canIssueReceiptAtChainTip', 'msgRefOf',
    'planReadReceiptReissues', 'clientNow', 'privateKeyToAccount', 'canonicalizeSignature',
    'readReceiptSignString', 'sessionStorage', 'reissueGroupKey', 'receiptIssuanceBlocked',
    `${recovery.slice(recoveryReissueStart, recoveryReissueEnd)}\nreturn reissueReadReceipts;`)(
    recoveryState, () => true, () => 'chatting', async (_key, _restore, emit) =>
      emit({ signal: null, known }), async () => true, (key) => key, planReadReceiptReissues,
    () => base - 1000, privateKeyToAccount, canonicalizeSignature, (...parts) => JSON.stringify(parts),
    { getItem: () => '[]', setItem() {} }, reissueGroupKey, () => false);
  await recoveryReissue(1000, new Set(estimate.keys));
  assert.deepEqual(recovered.map(reissueGroupKey), [reissueGroupKey(unrelated)]);
  const recoveredTracker = new PartialReadReceiptTracker();
  for (const receipt of [a1, b1, a2, b2, ...recovered]) recoveredTracker.add(receipt);
  assert.equal(recoveredTracker.byIssuer.get('R').partial.size, estimate.before);
  recovered.length = 0;
  await recoveryReissue(1000, null);
  assert.deepEqual(recovered.map(reissueGroupKey), plans.map(reissueGroupKey));
  const recoveryListenerStart = recovery.indexOf('let correctionWork = Promise.resolve();');
  const recoveryListenerEnd = recovery.indexOf('\nfunction isOtherSessionItem(', recoveryListenerStart);
  assert(recoveryListenerStart >= 0 && recoveryListenerEnd > recoveryListenerStart);
  let recoverySubscriber = null;
  const recoveryWork = new Function('recoveryClock', 'state', 'reissueReadReceipts', 'renderGame', 'log',
    `${recovery.slice(recoveryListenerStart, recoveryListenerEnd)}\nreturn () => correctionWork;`)(
    { subscribeClockCorrection: (fn) => { recoverySubscriber = fn; } }, recoveryState,
    recoveryReissue, () => {}, () => {});
  recovered.length = 0;
  recoveryState.clockReissueSkip = new Set(estimate.keys);
  recoverySubscriber({ deltaMs: -1000, nextMs: -1000 });
  recoveryState.clockReissueSkip = null;
  await recoveryWork();
  assert.deepEqual(recovered.map(reissueGroupKey), [reissueGroupKey(unrelated)],
    '復元の購読も保存の同期区間で集合を取り出す');
  recovered.length = 0;
  recoverySubscriber({ deltaMs: -1000, nextMs: -2000 });
  await recoveryWork();
  assert.deepEqual(recovered.map(reissueGroupKey), plans.map(reissueGroupKey));
}
// D1f: Keep the one-second clock display inside its own component.
{
  const currentPage = read('src/pages/game.js');
  const page = process.env.S3FIX_D1F_MUTATION === 'parent-ticker'
    ? currentPage.replace('  const readFreshClock = useCallback',
      '  useEffect(() => { setInterval(() => setClockRenderVersion((version) => version + 1), 1000); }, []);\n  const readFreshClock = useCallback')
    : currentPage;
  const modal = read('src/components/game/ClockCorrectionModal.js');
  // The correction notification may restart clock-dependent effects. A periodic page tick may not.
  const pageTicker = /setInterval\(\(\) => setClockRenderVersion\(\(version\) => version \+ 1\), 1000\)/;
  const tickerPresent = pageTicker.test(page);
  const modeledReadsInTenSeconds = tickerPresent ? 10 : 1; // [0, 10秒) の初回＋毎秒更新
  console.log(`10秒間の開始時刻読取モデル: ${modeledReadsInTenSeconds}回`);
  assert.equal(modeledReadsInTenSeconds, 1, '画面全体の1秒 ticker は開始時刻のチェーン読取を毎秒再起動する');
  assert.match(page, /subscribeClockCorrection\(\(\) => setClockRenderVersion\(\(version\) => version \+ 1\)\)/);
  const correctionDependentEffects = [...page.matchAll(/\}, \[([^\]]*\bclockRenderVersion\b[^\]]*)\]\);/g)];
  // REGENUID-WAITING: 開始待ち専用の再検証1本だけを削除。残る6本の補正量依存は保つ。
  assert.equal(correctionDependentEffects.length, 6, '開始時刻・カウントダウンの補正量依存6本を保つ');
  assert.equal(correctionDependentEffects.filter((match) => match[1].includes('regenerationRosterRetryNeeded')).length, 0,
    '開始待ち専用の名簿再検証effectは残さない');

  // Evaluate the actual start-time effect with a fake timer and a counted chain read.
  const start = page.indexOf('  useEffect(() => {', page.indexOf('// グループ分け完了前は'));
  const endMarker = '  }, [isSpectator, r2Trusted, autoDistributedGate, r2Probed, blockNum, groupId, ws.phase, clockRenderVersion]);';
  const end = page.indexOf(endMarker, start);
  assert(start >= 0 && end > start, '開始時刻の effect を実コードから取得する');
  const startEffect = page.slice(start, end + endMarker.length);

  async function checkPolling(failChain) {
    let now = 0;
    let chainReads = 0;
    let groupReads = 0;
    const pendingStarts = [];
    let cleanup;
    const timers = [];
    let version = 0;
    const useEffect = (fn, deps) => {
      assert(deps.includes(version), '補正量の版数が依存に残る');
      cleanup = fn();
    };
    const setTimeout = (fn, delay) => {
      const timer = { fn, at: now + delay, cancelled: false };
      timers.push(timer);
      return timer;
    };
    const clearTimeout = (timer) => { timer.cancelled = true; };
    const readGameTimeline = async () => {
      chainReads += 1;
      if (failChain) throw Error('RPC unavailable');
      return { chattingStart: 50_000 };
    };
    const fetchResponseWithTimeout = async () => {
      groupReads += 1;
      return { ok: true, json: async () => ({ phaseSchedule: { tasks: [
        { targetPhase: 'chatting', executeAt: 50_000 },
      ] } }) };
    };
    const scope = {
      useEffect, isSpectator: false, r2Trusted: false, autoDistributedGate: false,
      r2Probed: true, blockNum: 1, groupId: 2, ws: { phase: null }, clockRenderVersion: 0,
      setPendingStart: (value) => pendingStarts.push(value), readGameTimeline, fetchResponseWithTimeout,
      GAME_WORKER_URL: 'https://example.invalid', clientNow: () => now,
      setTimeout, clearTimeout,
    };
    const runEffect = () => {
      if (cleanup) cleanup();
      scope.clockRenderVersion = version;
      new Function(...Object.keys(scope), startEffect)(...Object.values(scope));
    };
    runEffect();
    const flush = async () => { for (let i = 0; i < 6; i += 1) await Promise.resolve(); };
    await flush();
    assert.equal(chainReads, 1);
    assert.equal(groupReads, 0);
    if (failChain) assert(pendingStarts.every((value) => value == null));
    now = 9_000;
    assert.equal(timers.filter((timer) => !timer.cancelled && timer.at <= now).length, 0);
    assert.equal(chainReads, 1);
    console.log(`開始時刻 [0,10秒) ${failChain ? 'RPC故障' : '正常'}: chain=${chainReads}, group-status=${groupReads}`);
    now = 10_000;
    const due = timers.find((timer) => !timer.cancelled && timer.at <= now);
    assert(due, '元の10秒周期で次の読みが予定される');
    due.cancelled = true;
    due.fn();
    await flush();
    assert.equal(chainReads, 2);
    assert.equal(groupReads, 0);
    if (failChain) assert(pendingStarts.every((value) => value == null));
    console.log(`開始時刻 10秒時点 ${failChain ? 'RPC故障' : '正常'}: chain=${chainReads}, group-status=${groupReads}`);
    version += 1;
    runEffect();
    await flush();
    assert.equal(chainReads, 3, '補正量の変更時はすぐにチェーンを読み直す');
    assert.equal(groupReads, 0);
    if (failChain) assert(pendingStarts.every((value) => value == null));
    cleanup();
    return { chainReads, groupReads };
  }
  assert.deepEqual(await checkPolling(false), { chainReads: 3, groupReads: 0 });
  assert.deepEqual(await checkPolling(true), { chainReads: 3, groupReads: 0 });

  // Run the extracted control with fake hooks. Its timer must only update its own state.
  const controlStart = page.indexOf('function ClockCorrectionControl(');
  const controlEnd = page.indexOf('\nexport default function GamePage()', controlStart);
  assert(controlStart >= 0 && controlEnd > controlStart, '手動入口を独立した部品へ切り出す');
  const controlSource = transformSync(page.slice(controlStart, controlEnd), {
    loader: 'jsx', format: 'cjs', jsxFactory: 'h',
  }).code;
  let now = 0;
  let state;
  let effect;
  let localRenders = 0;
  let parentRenders = 1;
  let tree;
  let tick;
  let correctionListener;
  let opened = 0;
  const h = (type, props, ...children) => ({ type, props: props || {}, children: children.flat() });
  const useState = (initial) => {
    if (state === undefined) state = typeof initial === 'function' ? initial() : initial;
    return [state, (next) => {
      const value = typeof next === 'function' ? next(state) : next;
      if (value !== state) { state = value; render(); }
    }];
  };
  const useEffect = (fn) => { if (!effect) effect = fn; };
  const correctionCooldownMs = () => Math.max(0, 61_000 - now);
  const subscribeClockCorrection = (listener) => { correctionListener = listener; return () => { correctionListener = null; }; };
  const setInterval = (fn, ms) => { assert.equal(ms, 1000); tick = fn; return 1; };
  const clearInterval = () => { tick = null; };
  const control = new Function('useState', 'useEffect', 'correctionCooldownMs',
    'subscribeClockCorrection', 'setInterval', 'clearInterval', 'h',
    `${controlSource}\nreturn ClockCorrectionControl;`)(useState, useEffect,
    correctionCooldownMs, subscribeClockCorrection, setInterval, clearInterval, h);
  function render() {
    localRenders += 1;
    tree = control({ t: (key, params) => `${key}:${params?.minutes ?? ''}`, onClick: () => { opened += 1; } });
  }
  const find = (node, type) => node?.type === type ? node
    : node?.children?.map((child) => find(child, type)).find(Boolean);
  render();
  const dispose = effect();
  assert.equal(find(tree, 'button').props.disabled, true);
  assert.equal(find(tree, 'span').children[0], 'game.clock.cooldown:2');
  now = 1_000;
  tick();
  assert.equal(find(tree, 'span').children[0], 'game.clock.cooldown:1');
  assert.equal(parentRenders, 1);
  now = 61_000;
  tick();
  assert.equal(find(tree, 'button').props.disabled, false);
  assert.equal(find(tree, 'span'), undefined);
  find(tree, 'button').props.onClick();
  assert.equal(opened, 1);
  now = 0;
  correctionListener();
  assert.equal(find(tree, 'button').props.disabled, true);
  assert(localRenders >= 4);
  assert.equal(parentRenders, 1);
  dispose();
  assert.equal(tick, null);

  assert.match(modal, /setInterval\(\(\) => setNow\(clientNow\(\)\), 1000\)/);
  assert.match(modal, /const \[now, setNow\] = useState\(\(\) => clientNow\(\)\)/);
  assert.match(modal, /<time data-testid="clock-current">\{clockText\(now\)\}<\/time>/);
  assert.match(modal, /<time data-testid="clock-corrected">\{clockText\(preview\)\}<\/time>/);
  console.log('s3fix-d1f-clock-render: ALL PASSED');
}
console.log('s3fix-d1b-clock-unit: all checks passed');

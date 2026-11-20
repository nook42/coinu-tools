import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { playerNumberOf, pointedTemplateText, pointedTemplateParts } from '../vendor/src/utils/playerNumber.js';
import { createRequire } from 'node:module';
import { parse } from '@babel/parser';
import { transformSync } from 'esbuild';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { verifyMessage, keccak256, toBytes } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { FutureAdmissionMarks, ReceiptAdmissionQueue, RelayPool, GameRelayChannel, groupTag,
  buildEvent, deriveNostrKey, receiptIdentityDigest, MAX_SEEN_EVENT_IDS } from '../../src/utils/relay.js';
import { FutureAdmissionMarks as VendoredMarks,
  RelayPool as VendoredPool } from '../vendor/src/utils/relay.js';
import { computeMsgKeyV2, msgRefOf, readReceiptSignString, chatSignStringV2,
  CHAT_WINDOW_CLOCK_SKEW_MS } from '../../src/utils/protocol.js';
import { RecoveryRelay } from '../src/recovery/relay-client.js';
import { nextReadReceiptTimestamp as officialTickTime,
  classifyFutureClockWarning, advanceFutureClockWarning, INITIAL_FUTURE_CLOCK_WARNING,
  futureClockWarningBypassesCooldown, ownClockVoteDeadline,
  futureClockWarningPersists } from '../../src/utils/chainClock.js';
import { GUEST_PINNED_RULES, countMessageTurns, filterVisibleMessages,
  normalizeChatCaps } from '../../workers/game_workers/lib/char-counter.js';
import { isCanonicalTimestamp, isCanonicalSignature, admitReadReceiptsByArrival,
  buildRealTargets, receiptCoverClaim, receiptMaxRefsPerReceipt,
  canonicalComparatorV2, buildMsgKeyGetter } from '../../workers/game_workers/lib/protocol-v2.js';
import { ReceiptWarnings } from '../../src/utils/receipt-warnings.js';
import { nextReadReceiptTimestamp as recoveryTickTime,
  advanceFutureClockWarning as recoveryAdvance, INITIAL_FUTURE_CLOCK_WARNING as recoveryInitial,
} from '../vendor/src/utils/chainClock.js';
import { derivePhaseFromWindows } from '../../workers/game_workers/lib/timeline-check.js';
import { derivePhase } from '../src/common/chain.js';

const base = 1_750_000_000_000;
const signature = await privateKeyToAccount(`0x${'52'.repeat(32)}`).signMessage({ message: 'd1c' });
// Both tick paths use the same C and the same signed self-read floor. A stale M row
// from the fast clock must not make the next S row future on R's own admission queue.
const officialHook = readFileSync(new URL('../../src/hooks/useGameWebSocket.js', import.meta.url), 'utf8');
let recoveryApp = readFileSync(process.env.T5E_RECOVERY_SOURCE || new URL('../src/recovery/app.js', import.meta.url), 'utf8');
assert.match(officialHook, /nextReadReceiptTimestamp\(\{ clockMs: clientNow\(\)/);
assert.match(recoveryApp, /nextReadReceiptTimestamp\(\{ clockMs: clientNow\(\)/);
const readAccount = privateKeyToAccount(`0x${'43'.repeat(32)}`);
let tickTimes = [officialTickTime, recoveryTickTime];
if (process.env.S3FIX_D1D_MUTATION === 'floor-unfiltered') {
  const floorSource = readFileSync(new URL('../../src/utils/chainClock.js', import.meta.url), 'utf8')
    .replace('timestamp <= clockMs', 'true');
  const mutated = await import(`data:text/javascript;base64,${Buffer.from(floorSource).toString('base64')}`);
  tickTimes = [mutated.nextReadReceiptTimestamp, mutated.nextReadReceiptTimestamp];
}

// T5b: exercise the actual hook callback, admission callback, lock state and two exits.
// The source override points at the copied pre-edit hook; it must fail before this fix.
const t5bMutation = process.argv.find((arg) => arg.startsWith('--mutation=t5b-'))?.slice('--mutation='.length);
const t5eMutation = process.argv.find((arg) => arg.startsWith('--mutation=t5e-'))?.slice('--mutation='.length);
const t5gMutation = process.argv.find((arg) => arg.startsWith('--mutation=t5g-'))?.slice('--mutation='.length);
const t5hMutation = process.argv.find((arg) => arg.startsWith('--mutation=t5h-'))?.slice('--mutation='.length);
const c3Mutation = process.argv.find((arg) => arg.startsWith('--mutation=c3-'))?.slice('--mutation='.length);
const mutationAnchor = (source, anchor, name, count = 1) => {
  if (source.split(anchor).length !== count + 1) {
    console.error(`mutation anchor missing: ${name}`);
    process.exit(2);
  }
};
let t5bHook = process.env.T5E_HOOK_SOURCE || process.env.T5B_HOOK_SOURCE
  ? readFileSync(process.env.T5E_HOOK_SOURCE || process.env.T5B_HOOK_SOURCE, 'utf8') : officialHook;
if (c3Mutation === 'c3-recovery-receipt-gate-warning') {
  const anchor = 'return state.away || state.otherSessionReadReceipt || state.tabEnded;';
  mutationAnchor(recoveryApp, anchor, c3Mutation);
  recoveryApp = recoveryApp.replace(anchor,
    'return state.away || state.otherSessionReadReceipt || state.tabEnded || !!state.clockWarning.warning;');
}
if (c3Mutation === 'c3-recovery-send-gate-warning') {
  const anchor = 'async function sendChat(text) {\n  if (!rosterReady()) return;';
  mutationAnchor(recoveryApp, anchor, c3Mutation);
  recoveryApp = recoveryApp.replace(anchor,
    'async function sendChat(text) {\n  if (!rosterReady() || state.clockWarning.warning) return;');
}
if (c3Mutation === 'c3-recovery-away-on-warning') {
  const anchor = 'state.clockWarning = next;\n    renderGame();';
  mutationAnchor(recoveryApp, anchor, c3Mutation, 2);
  recoveryApp = recoveryApp.replace(anchor, "state.clockWarning = next;\n    void publishPresence('away');\n    renderGame();");
}
if (c3Mutation === 'c3-send-gate-warning') {
  const anchor = 'if (!rosterStartConfirmedRef.current || !key || !isGameIdentityCurrent()) return false;';
  mutationAnchor(t5bHook, anchor, c3Mutation, 3);
  t5bHook = t5bHook.replaceAll(anchor,
    'if (!rosterStartConfirmedRef.current || !key || !isGameIdentityCurrent() || sessionActivityRef.current.clockWarning.warning) return false;');
  const afterSign = 'if (!rosterStartConfirmedRef.current || !isGameIdentityCurrent()) return false;';
  mutationAnchor(t5bHook, afterSign, c3Mutation, 3);
  t5bHook = t5bHook.replaceAll(afterSign,
    'if (!rosterStartConfirmedRef.current || !isGameIdentityCurrent() || sessionActivityRef.current.clockWarning.warning) return false;');
}
if (c3Mutation === 'c3-away-on-warning') {
  const anchor = '  const continueClockWarning = () => {';
  mutationAnchor(t5bHook, anchor, c3Mutation);
  t5bHook = t5bHook.replace(anchor,
    "  useEffect(() => { if (clockWarning.warning) void publishPresence('away'); }, [clockWarning]);\n" + anchor);
}
if (c3Mutation === 'c3-close-after-3min') {
  const anchor = 'return commitClockWarning(advanceFutureClockWarning(sessionActivityRef.current.clockWarning,';
  mutationAnchor(t5bHook, anchor, c3Mutation);
  t5bHook = t5bHook.replace(anchor, 'return performance.now() >= 180000 && ' + anchor.slice('return '.length));
}
if (t5eMutation === 't5e-phase-not-chatting') {
  mutationAnchor(t5bHook, "(chainPhase === 'submitting' || chainPhase === 'completed')", t5eMutation);
  mutationAnchor(recoveryApp, "(phase === 'submitting' || phase === 'completed') && state.clockWarning.warning", t5eMutation);
  t5bHook = t5bHook.replace("(chainPhase === 'submitting' || chainPhase === 'completed')", "phase !== 'chatting'");
  recoveryApp = recoveryApp.replace("(phase === 'submitting' || phase === 'completed') && state.clockWarning.warning", "phase !== 'chatting' && state.clockWarning.warning");
}
const t5eGate = "['submitting', 'completed'].includes(derivePhaseFromWindows(clientNow(), chainTimelineRef.current))";
if (t5gMutation === 't5g-recovery-chatting-only') {
  const gate = "['submitting', 'completed'].includes(currentPhase())";
  mutationAnchor(recoveryApp, gate, t5gMutation, 2);
  recoveryApp = recoveryApp.replaceAll(gate, "currentPhase() !== 'chatting'");
}
let t5eWarningFunction = classifyFutureClockWarning;
let t5eAdvanceFunction = advanceFutureClockWarning;
if (process.env.T5E_CHAIN_CLOCK_SOURCE || t5eMutation === 't5e-safe-integer-L') {
  const source = readFileSync(process.env.T5E_CHAIN_CLOCK_SOURCE || new URL('../../src/utils/chainClock.js', import.meta.url), 'utf8');
  const finiteAnchor = 'reading.sourceIds.length >= 2 && Number.isFinite(reading.timeMs);';
  if (t5eMutation === 't5e-safe-integer-L') mutationAnchor(source, finiteAnchor, t5eMutation);
  const mutated = t5eMutation === 't5e-safe-integer-L'
    ? source.replace(finiteAnchor, 'reading.sourceIds.length >= 2 && Number.isSafeInteger(reading.timeMs);') : source;
  const module = await import(`data:text/javascript;base64,${Buffer.from(mutated).toString('base64')}`);
  if (!module.classifyFutureClockWarning) {
    console.error('pre-edit export missing: classifyFutureClockWarning');
    process.exit(2);
  }
  t5eWarningFunction = module.classifyFutureClockWarning;
  t5eAdvanceFunction = module.advanceFutureClockWarning;
}
if (t5bMutation === 't5b-trigger-without-skew') {
  const source = readFileSync(new URL('../../src/utils/chainClock.js', import.meta.url), 'utf8');
  const anchor = 'if (-leadMs >= FUTURE_CLOCK_WARNING_LATE_MS && Number.isSafeInteger(itemTimestampMs)';
  mutationAnchor(source, anchor, t5bMutation);
  const module = await import(`data:text/javascript;base64,${Buffer.from(source.replace(anchor,
    'if (true && Number.isSafeInteger(itemTimestampMs)')).toString('base64')}`);
  t5eWarningFunction = module.classifyFutureClockWarning;
  t5eAdvanceFunction = module.advanceFutureClockWarning;
}
const t5bBetween = (source, start, end) => {
  const a = source.indexOf(start), b = source.indexOf(end, a + start.length);
  assert(a >= 0 && b > a, `T5b source boundary: ${start}`);
  return source.slice(a, b);
};
let t5bIngress = t5bBetween(t5bHook, '  const receiptIssuanceBlocked = () =>', '  const flagOtherSession =');
if (t5eMutation === 't5e-operator-phase-trigger' || t5eMutation === 't5e-entry-excluded') {
  mutationAnchor(t5bIngress, t5eGate, t5eMutation, 2);
  t5bIngress = t5bIngress.replaceAll(t5eGate, t5eMutation === 't5e-entry-excluded'
    ? "['entry', 'waiting', 'submitting', 'completed'].includes(derivePhaseFromWindows(clientNow(), chainTimelineRef.current))"
    : "phaseRef.current !== 'chatting'");
}
if (t5gMutation === 't5g-waiting-excluded') {
  mutationAnchor(t5bIngress, t5eGate, t5gMutation, 2);
  t5bIngress = t5bIngress.replaceAll(t5eGate,
    "['waiting', 'submitting', 'completed'].includes(derivePhaseFromWindows(clientNow(), chainTimelineRef.current))");
}
assert.match(t5bIngress, /considerFutureClockWarning/, 'C3a: official future warning callback exists');
if (t5bMutation === 't5b-no-lock') {
  const anchor = 'futureMarksRef.current.onFutureDiscard = considerFutureClockWarning;';
  mutationAnchor(t5bIngress, anchor, t5bMutation);
  t5bIngress = t5bIngress.replace(anchor, 'futureMarksRef.current.onFutureDiscard = () => {};');
}
if (c3Mutation === 'c3-receipt-gate-warning') {
  const anchor = '|| sessionActivityRef.current.ended;';
  mutationAnchor(t5bIngress, anchor, c3Mutation);
  t5bIngress = t5bIngress.replace(anchor, '|| sessionActivityRef.current.ended || !!sessionActivityRef.current.clockWarning.warning;');
}
const t5bBase = 1_760_000_000_000;
let t5bMono = 0;
const t5bReading = { kind: 'consensus', sourceIds: ['wallet', 'public-a'], timeMs: t5bBase };
const t5eWindows = { chatOpenAt: t5bBase - 360000, chattingStart: t5bBase - 240000,
  chatCloseAt: t5bBase + 360000, resultCloseAt: t5bBase + 720000 };
function makeT5bHookHarness(clientAt = t5bBase - 180000, reading = t5bReading,
  { chainTimeline = t5eWindows, serverPhase = 'chatting', spectator = false,
    ended = false, futureLockClock = null } = {}) {
  const sessionActivityRef = { current: { warned: false, ended,
    clockWarning: INITIAL_FUTURE_CLOCK_WARNING } };
  let clockAt = clientAt;
  const phaseRef = { current: serverPhase };
  const chainTimelineRef = { current: chainTimeline };
  const isAwayRef = { current: false };
  const futureMarksRef = { current: new FutureAdmissionMarks({ blockNum: 3, groupId: 2, now: () => clockAt }) };
  const errors = [];
  let shown = INITIAL_FUTURE_CLOCK_WARNING;
  const commitClockWarning = (next) => {
    if (next === sessionActivityRef.current.clockWarning) return false;
    sessionActivityRef.current.clockWarning = next;
    shown = next;
    return true;
  };
  const classifier = t5eWarningFunction;
  const make = new Function('sessionActivityRef', 'phaseRef', 'isAwayRef', 'futureMarksRef',
    'futureLockClockRef', 'isSpectator', 'isGameIdentityCurrent', 'classifyFutureClockWarning',
    'advanceFutureClockWarning', 'commitClockWarning', 'clientNow', 'CHAT_WINDOW_CLOCK_SKEW_MS',
    'derivePhaseFromWindows', 'chainTimelineRef',
    `${t5bIngress}\nreturn { receiptIssuanceBlocked, considerFutureClockWarning };`);
  const createIngress = () => {
    const result = make(sessionActivityRef, phaseRef, isAwayRef, futureMarksRef,
      { current: futureLockClock || (() => reading) }, spectator, () => true, classifier,
      t5eAdvanceFunction, commitClockWarning, () => clockAt, CHAT_WINDOW_CLOCK_SKEW_MS,
      derivePhaseFromWindows, chainTimelineRef);
    const callback = futureMarksRef.current.onFutureDiscard;
    futureMarksRef.current.onFutureDiscard = (...args) => {
      try { return callback(...args); } catch (error) { errors.push(error); throw error; }
    };
    return result;
  };
  const ingress = createIngress();
  return { ...ingress, sessionActivityRef, phaseRef, chainTimelineRef, futureMarksRef,
    errors, commitClockWarning, shown: () => shown,
    setShown: (value) => { shown = value; sessionActivityRef.current.clockWarning = value; },
    setClientAt: (value) => { clockAt = value; }, setScreenPhase: (screen) => { phaseRef.current = screen; } };
}
const t5bFuture = (timestamp = t5bBase) => ({ uid: 'H', text: 'now on L', timestamp, signature });
const showT5bClockWarning = (h, phase = 'chatting', chainPhase = 'chatting') => {
  const effect = t5bBetween(t5bHook, '  useEffect(() => {\n    phaseRef.current = phase;', '  // §6:');
  new Function('useEffect', 'phaseRef', 'sessionActivityRef', 'setClockWarning',
    'advanceFutureClockWarning', 'clockWarning', 'phase', 'chainPhase', 'isSpectator', effect)(
      (fn) => fn(), h.phaseRef, h.sessionActivityRef, h.setShown,
      advanceFutureClockWarning, h.shown(), phase, chainPhase, false);
};
const t5bLocked = makeT5bHookHarness();
assert.equal(t5bLocked.receiptIssuanceBlocked(), false);
assert.equal(t5bLocked.futureMarksRef.current.discard('chat', t5bFuture()), true);
assert.equal(t5bLocked.errors.length, 0, 'C3a: discard callback exceptions are visible');
assert.equal(t5bLocked.shown().warning?.direction, 'late', 'F-1-01: slow clock and future item warn');
assert.equal(t5bLocked.receiptIssuanceBlocked(), false, 'C3a: warning never blocks receipts');
showT5bClockWarning(t5bLocked);
assert.equal(t5bLocked.shown().fullShown, true, 'C3a: first visible commit marks full shown');
const t5bRedelivery = t5bLocked.shown();
t5bLocked.futureMarksRef.current.discard('chat', t5bFuture());
assert.equal(t5bLocked.shown(), t5bRedelivery, 'C3a: redelivery never restarts full screen');
const t5bGood = makeT5bHookHarness(t5bBase, t5bReading);
t5bGood.futureMarksRef.current.discard('chat', t5bFuture(t5bBase + 120001));
assert.equal(t5bGood.shown().warning, null, 'C3a: attacker future item alone never warns correct clock');
assert.equal(t5bGood.errors.length, 0);
if (!process.argv.some((arg) => arg.startsWith('--mutation=')) && !process.env.S3FIX_D1D_MUTATION) {
  const correctClocks = [t5bBase, t5bBase - 99999, t5bBase + 119999]
    .map((clientAt) => makeT5bHookHarness(clientAt, t5bReading));
  for (let i = 0; i < 1200; i++) {
    const itemTimestamp = t5bBase + 360000 + i;
    const text = `signed future ${i}`;
    const signed = await readAccount.signMessage({ message: chatSignStringV2(3, 2, 'H', text, itemTimestamp) });
    assert(await verifyMessage({ address: readAccount.address,
      message: chatSignStringV2(3, 2, 'H', text, itemTimestamp), signature: signed }));
    const item = { uid: 'H', text, timestamp: itemTimestamp, signature: signed };
    for (const h of correctClocks) h.futureMarksRef.current.discard('chat', item);
  }
  for (const h of correctClocks) {
    assert.equal(h.shown().warning, null,
      'C3a: 1,200 verified future items never warn a correct clock');
    assert.equal(h.errors.length, 0);
  }
}
const t5bNoL = makeT5bHookHarness(t5bBase - 180000, { kind: 'unavailable', sourceIds: [], timeMs: null });
t5bNoL.futureMarksRef.current.discard('chat', t5bFuture());
assert.equal(t5bNoL.shown().warning, null, 'C3a: no consensus L never warns');
assert.equal(t5bNoL.errors.length, 0);
const t5bEarlyWaiting = makeT5bHookHarness(t5bBase + 120000, t5bReading,
  { chainTimeline: { ...t5eWindows, chattingStart: t5bBase + 200000 } });
t5bEarlyWaiting.futureMarksRef.current.discard('chat', t5bFuture(t5bBase + 240001));
assert.equal(t5bEarlyWaiting.shown().warning?.direction, 'early',
  'C3a: waiting future discard can detect an early clock');
showT5bClockWarning(t5bEarlyWaiting, 'waiting', 'waiting');
assert.equal(t5bEarlyWaiting.shown().fullShown, false,
  'C3a: waiting early warning is not shown yet');
showT5bClockWarning(t5bEarlyWaiting, 'chatting', 'chatting');
assert.equal(t5bEarlyWaiting.shown().fullShown, true,
  'C3a: waiting early warning first shows on the chatting screen');
assert.equal(t5bEarlyWaiting.errors.length, 0);
for (const [label, serverPhase, chainTimeline, expected] of [
  ['operator null', null, t5eWindows, true],
  ['operator waiting with unread chain', 'waiting', null, true],
  ['chain entry', 'chatting', { ...t5eWindows, chatOpenAt: t5bBase + 1000,
    chattingStart: t5bBase + 2000 }, true],
  ['chain waiting', 'chatting', { ...t5eWindows, chattingStart: t5bBase + 1000 }, true],
  ['chain submitting', 'chatting', { ...t5eWindows, chatCloseAt: t5bBase - 200000 }, false],
  ['chain completed', 'chatting', { ...t5eWindows, resultCloseAt: t5bBase - 200000,
    chatCloseAt: t5bBase - 200001 }, false],
]) {
  const slow = makeT5bHookHarness(t5bBase - 180000, t5bReading, { serverPhase, chainTimeline });
  slow.futureMarksRef.current.discard('chat', t5bFuture());
  assert.equal(!!slow.shown().warning, expected, `T5e trigger: ${label}`);
  assert.equal(slow.errors.length, 0);
  const correct = makeT5bHookHarness(t5bBase, t5bReading, { serverPhase, chainTimeline });
  correct.futureMarksRef.current.discard('chat', t5bFuture(t5bBase + 120001));
  assert.equal(correct.shown().warning, null, `T5e correct clock: ${label}`);
  assert.equal(correct.errors.length, 0);
}
for (const options of [{ spectator: true }, { ended: true }]) {
  const h = makeT5bHookHarness(t5bBase - 180000, t5bReading, options);
  h.futureMarksRef.current.discard('chat', t5bFuture());
  assert.equal(h.shown().warning, null, 'C3a: spectator and ended never warn');
  assert.equal(h.errors.length, 0);
}
{
  const page = readFileSync(new URL('../../src/pages/game.js', import.meta.url), 'utf8');
  const getterText = t5bBetween(page, '  futureLockClockRef.current = () => {',
    '  const checkClock = useCallback(');
  const clockCheckRef = { current: { stepTick: 0, reading: { ...t5bReading,
    monoMs: 100.3, wallMs: t5bBase, stepTick: 0 } } };
  const futureLockClockRef = { current: null };
  let mono = 153.6;
  new Function('clockCheckRef', 'futureClockReadRef', 'futureLockClockRef', 'performance',
    'Date', 'readFreshClock', getterText)(clockCheckRef,
    { current: { inFlight: null, lastMono: -Infinity, lastWall: -Infinity } }, futureLockClockRef,
    { now: () => (mono += 0.1) }, { now: () => t5bBase + 54 }, async () => null);
  const fractional = futureLockClockRef.current();
  assert(!Number.isInteger(fractional.timeMs), 'C3a: game getter supplies fractional L');
  const h = makeT5bHookHarness(t5bBase - 180000, t5bReading,
    { futureLockClock: futureLockClockRef.current });
  h.futureMarksRef.current.discard('chat', t5bFuture(t5bBase + 54));
  assert(h.shown().warning, 'C3a: fractional cached L warns on first future item');
  assert.equal(h.errors.length, 0);
}
{
  const source = t5bBetween(recoveryApp, 'async function freshRecoveryClockReading() {',
    '\nfunction receiptIssuanceBlocked()');
  const state = { clockReading: null, clockStepVersion: 0,
    _timeClient: { readSamples: async () => ({ publicSamples: [
      { sourceId: 'a', blockTimestampMs: t5bBase, observedMonoMs: 100.3 },
      { sourceId: 'b', blockTimestampMs: t5bBase, observedMonoMs: 100.3 },
    ] }) } };
  let mono = 153.6;
  const readFuture = new Function('state', 'performance', 'Date', 'selectChainClockReading',
    'setTimeout', 'clearTimeout', `${source}\nreturn readFutureLockClock;`)(state,
    { now: () => (mono += 0.1) }, { now: () => t5bBase + 54 },
    (await import('../../src/utils/chainClock.js')).selectChainClockReading, setTimeout, clearTimeout);
  const fractional = await readFuture();
  assert(!Number.isInteger(fractional.timeMs), 'recovery fresh getter supplies fractional L');
  const recoverySource = t5bBetween(recoveryApp, 'function receiptIssuanceBlocked() {', '\nasync function checkClock(');
  const recoveryState = { away: false, otherSessionReadReceipt: false, tabEnded: false,
    clockWarning: INITIAL_FUTURE_CLOCK_WARNING, receiptWarningIdentity: '3|2|R' };
  const make = new Function('state', 'currentPhase', 'readFutureLockClock',
    'advanceFutureClockWarning', 'renderGame', 'clientNow', 'CHAT_WINDOW_CLOCK_SKEW_MS', 'publishPresence',
    `${recoverySource}\nreturn considerRecoveryFuture;`);
  const detect = make(recoveryState, () => 'chatting', readFuture,
    advanceFutureClockWarning, () => {}, () => t5bBase - 180000, CHAT_WINDOW_CLOCK_SKEW_MS, () => {});
  detect('chat', t5bFuture(t5bBase + 54));
  await Promise.resolve();
  assert(recoveryState.clockWarning.warning, 'fractional fresh recovery L warns on the first future item');
}
{
  const memoSource = t5bBetween(t5bHook, '  const chainPhase = useMemo(', '  // UI 警告用:');
  const effectSource = t5bBetween(t5bHook, '  useEffect(() => {\n    phaseRef.current = phase;', '  // §6:');
  if (!process.env.T5E_HOOK_SOURCE && t5eMutation !== 't5e-phase-not-chatting')
    assert.match(effectSource, /}, \[phase, chainPhase, clockWarning, isSpectator\]\);/,
      'C3a: chain phase reevaluates the warning effect');
  assert.match(t5bHook, /case 'phase_change':\s*if \(data\.phase != null\) setServerPhase\(data\.phase\);/);
  assert.match(t5bHook, /case 'init_response':[\s\S]*?if \(data\.phase != null\) setServerPhase\(data\.phase\);/);
  const memo = new Function('useMemo', 'derivePhaseFromWindows', 'clientNow', 'chainTimeline',
    'phaseTick', 'clockVersion', 'serverPhase', `${memoSource}\nreturn { phase, chainPhase };`);
  const runEffect = new Function('useEffect', 'phaseRef', 'sessionActivityRef',
    'setClockWarning', 'advanceFutureClockWarning', 'clockWarning', 'phase', 'chainPhase',
    'isSpectator', effectSource);
  const runPhase = (h, chainTimeline, serverPhase, now = t5bBase) => {
    const phases = memo((fn) => fn(), derivePhaseFromWindows, () => now, chainTimeline,
      0, 0, serverPhase);
    runEffect((fn) => fn(), h.phaseRef, h.sessionActivityRef, h.setShown,
      advanceFutureClockWarning, h.shown(), phases.phase, phases.chainPhase, false);
    h.setScreenPhase(phases.phase);
    return phases;
  };
  const slowAt = t5bBase - 180000;
  const windowsByPhase = {
    null: null,
    entry: { chatOpenAt: slowAt + 1000, chattingStart: slowAt + 2000,
      chatCloseAt: slowAt + 360000, resultCloseAt: slowAt + 720000 },
    waiting: { chatOpenAt: slowAt - 1000, chattingStart: slowAt + 1000,
      chatCloseAt: slowAt + 360000, resultCloseAt: slowAt + 720000 },
    chatting: { chatOpenAt: slowAt - 2000, chattingStart: slowAt - 1000,
      chatCloseAt: slowAt + 360000, resultCloseAt: slowAt + 720000 },
    submitting: { chatOpenAt: slowAt - 360000, chattingStart: slowAt - 300000,
      chatCloseAt: slowAt - 1000, resultCloseAt: slowAt + 720000 },
    completed: { chatOpenAt: slowAt - 720000, chattingStart: slowAt - 660000,
      chatCloseAt: slowAt - 360000, resultCloseAt: slowAt - 1000 },
  };
  for (const [chainName, windows] of Object.entries(windowsByPhase)) {
    for (const serverPhase of [null, 'waiting', 'chatting', 'submitting']) {
      const h = makeT5bHookHarness(slowAt, t5bReading, { chainTimeline: windows, serverPhase });
      const { phase: screen, chainPhase } = runPhase(h, windows, serverPhase, slowAt);
      assert.equal(chainPhase, chainName === 'null' ? null : chainName);
      h.futureMarksRef.current.discard('chat', t5bFuture());
      const expected = !['submitting', 'completed'].includes(chainName);
      assert.equal(!!h.shown().warning, expected,
        `C3a chain=${chainName} server=${serverPhase} screen=${screen}`);
      assert.equal(h.errors.length, 0);
      if (screen === 'chatting' && expected) {
        runPhase(h, windows, serverPhase, slowAt);
        assert.equal(h.shown().fullShown, true, 'C3a: chatting commit shows full once');
      }
    }
  }
  const waitingWindows = windowsByPhase.waiting;
  const h = makeT5bHookHarness(slowAt, t5bReading, { chainTimeline: waitingWindows });
  assert.equal(runPhase(h, waitingWindows, 'chatting', slowAt).phase, 'waiting');
  h.futureMarksRef.current.discard('chat', t5bFuture());
  assert.equal(h.shown().warning?.stage, 'full', 'T5g official: waiting discard already warns');
  assert.equal(h.shown().fullShown, false, 'T5g official: waiting has no displayed full');
  assert.equal(h.receiptIssuanceBlocked(), false);
  h.setClientAt(slowAt + 2000);
  assert.equal(runPhase(h, waitingWindows, 'chatting', slowAt + 2000).phase, 'chatting');
  assert.equal(h.shown().fullShown, true, 'T5g official: first chat commit counts full once');
  const firstShown = h.shown();
  runPhase(h, waitingWindows, 'chatting', slowAt + 2000);
  assert.equal(h.shown(), firstShown, 'T5h official: repeated effect does not recount full');
  const closeSource = t5bBetween(t5bHook, '  const continueClockWarning = () => {',
    '  const resumeOtherSession =');
  const close = new Function('sessionActivityRef', 'commitClockWarning',
    'advanceFutureClockWarning', 'performance', `${closeSource}\nreturn continueClockWarning;`)(
      h.sessionActivityRef, h.commitClockWarning, advanceFutureClockWarning, { now: () => t5bMono });
  assert.equal(close(), true, 'C3a: full closes immediately');
  assert.equal(h.shown().warning.stage, 'band');
  h.futureMarksRef.current.discard('chat', t5bFuture());
  assert.equal(h.shown().warning.stage, 'band', 'C3a: future redelivery stays in band');
  h.sessionActivityRef.current.warned = true;
  assert.equal(h.receiptIssuanceBlocked(), true, 'C3a: other session still blocks receipts');
  h.sessionActivityRef.current.warned = false;
  for (const [name, now] of [['submitting', t5eWindows.chatCloseAt],
    ['completed', t5eWindows.resultCloseAt]]) {
    const ended = makeT5bHookHarness();
    ended.futureMarksRef.current.discard('chat', t5bFuture());
    assert.equal(runPhase(ended, t5eWindows, 'chatting', now).chainPhase, name);
    assert.equal(ended.shown().warning, null, `C3a chain ${name} clears warning`);
  }
  const unread = makeT5bHookHarness();
  unread.futureMarksRef.current.discard('chat', t5bFuture());
  runPhase(unread, null, 'submitting');
  assert(unread.shown().warning, 'C3a: operator phase alone does not clear warning');
  assert.match(readFileSync(new URL('../../src/pages/game.js', import.meta.url), 'utf8'),
    /const clockWarningModal = !isSpectator && wsRaw\.phase === 'chatting' && wsRaw\.clockWarning/);
  const submission = t5bBetween(t5bHook, '  const sendSubmission = useCallback((payload) => {',
    '\n  }, [send, startSubmitConfirm, isGameIdentityCurrent]);');
  assert.doesNotMatch(submission, /clockWarning|clockLock|receiptIssuanceBlocked/);
}
{
  const source = t5bBetween(recoveryApp, 'function currentPhase() {', '\nasync function pollLiveSnapshot()');
  const makePhase = (timeline, now) => {
    const state = { timeline, clockWarning: { ...INITIAL_FUTURE_CLOCK_WARNING,
      warning: { direction: 'late', stage: 'band', deviationMs: -180000 } }, chatEnded: false };
    const currentPhase = new Function('state', 'derivePhase', 'clientNow', 'advanceFutureClockWarning',
      `${source}\nreturn currentPhase;`)(state, derivePhase, () => now, advanceFutureClockWarning);
    return { state, phase: currentPhase() };
  };
  for (const [name, timeline, now, remains] of [
    ['waiting', { ...t5eWindows, chattingStart: t5bBase + 1000 }, t5bBase, true],
    ['invalid', { ...t5eWindows, chatCloseAt: NaN }, t5bBase, true],
    ['unknown', null, t5bBase, true],
    ['submitting', t5eWindows, t5eWindows.chatCloseAt, false],
    ['completed', t5eWindows, t5eWindows.resultCloseAt, false],
  ]) {
    const result = makePhase(timeline, now);
    assert.equal(!!result.state.clockWarning.warning, remains,
      `recovery ${name}: only the chain's submitting/completed phases clear warning`);
  }
}
{
  const recoverySource = t5bBetween(recoveryApp, 'function receiptIssuanceBlocked() {',
    '\nasync function checkClock(');
  const state = { away: false, otherSessionReadReceipt: false, tabEnded: false,
    clockWarning: INITIAL_FUTURE_CLOCK_WARNING, receiptWarningIdentity: '3|2|R' };
  const presence = [], renders = [], errors = [];
  const make = new Function('state', 'currentPhase', 'renderGame', 'readFutureLockClock',
    'advanceFutureClockWarning', 'clientNow', 'CHAT_WINDOW_CLOCK_SKEW_MS', 'publishPresence',
    `${recoverySource}\nreturn { considerRecoveryFuture, receiptIssuanceBlocked, continueRecoveryClockWarning };`);
  const currentPhase = () => 'waiting';
  const recovery = make(state, currentPhase, () => renders.push(1), () => t5bReading,
    advanceFutureClockWarning, () => t5bBase - 180000, CHAT_WINDOW_CLOCK_SKEW_MS,
    (value) => presence.push(value));
  const marks = new FutureAdmissionMarks({ blockNum: 3, groupId: 2, now: () => t5bBase - 180000,
    onFutureDiscard: (...args) => { try { recovery.considerRecoveryFuture(...args); } catch (error) { errors.push(error); throw error; } } });
  marks.discard('chat', t5bFuture());
  assert(state.clockWarning.warning, 'T5g recovery: waiting discard already warns');
  assert.equal(state.clockWarning.fullShown, false, 'T5h recovery: waiting never counts a full overlay');
  assert.equal(recovery.receiptIssuanceBlocked(), false, 'C3b: warning never blocks receipts');
  assert.equal(recovery.continueRecoveryClockWarning(), true, 'C3b: first full screen closes immediately');
  assert.equal(state.clockWarning.warning.stage, 'band');
  assert.deepEqual(presence, [], 'C3b: warning does not publish presence');
  state.otherSessionReadReceipt = true;
  assert.equal(recovery.receiptIssuanceBlocked(), true, 'C3b: other-session warning still blocks');
  assert.equal(errors.length, 0, 'C3b: discard callback has no swallowed exception');
  assert(renders.length > 0);
  const renderGameSource = t5bBetween(recoveryApp, 'function renderGame() {',
    '\n// 復元に使う契約を常時可視化する。');
  assert.match(renderGameSource, /if \(state\.rosterPaused \|\| state\.rosterInvalid\) \{[\s\S]*?renderGameModals\(null\);\s*return;/);
  assert.match(renderGameSource, /phase === 'chatting' && state\.clockWarning\?\.warning/);
  assert.doesNotMatch(recoveryApp, /setTimeout\(\(\) => renderGame\(\), 180100\)/);
}
console.log('t5e-clock-warning: all checks passed');


const closeSource = t5bBetween(t5bHook, '  const continueClockWarning = () => {',
  '  const resumeOtherSession =');
const t5bPresence = [];
const close = new Function('sessionActivityRef', 'commitClockWarning', 'advanceFutureClockWarning',
  'publishPresence', 'performance', `${closeSource}\nreturn continueClockWarning;`)(
    t5bLocked.sessionActivityRef, t5bLocked.commitClockWarning, advanceFutureClockWarning,
    (value) => t5bPresence.push(value), { now: () => t5bMono });
assert.equal(close(), true, 'C3a: continue closes full immediately');
assert.equal(t5bLocked.shown().warning.stage, 'band');
assert.deepEqual(t5bPresence, [], 'C3a: continue does not publish presence');
t5bLocked.futureMarksRef.current.discard('chat', t5bFuture());
assert.equal(t5bLocked.shown().warning.stage, 'band', 'C3a: future redelivery stays in band');
t5bLocked.sessionActivityRef.current.warned = true;
assert.equal(t5bLocked.receiptIssuanceBlocked(), true, 'C3a: other session warning still blocks');
t5bLocked.sessionActivityRef.current.warned = false;
let t5bApply = t5bBetween(t5bHook, '  const applyClockCorrection = (nextMs, skipKeys = null, reading = null) => {',
  '  reissueReadReceiptsRef.current = async');
if (c3Mutation === 'c3-bypass-any') {
  const anchor = '!!before?.warning && futureClockWarningBypassesCooldown(before, reading,';
  mutationAnchor(t5bApply, anchor, c3Mutation);
  t5bApply = t5bApply.replace(anchor, '!!before?.warning || futureClockWarningBypassesCooldown(before, reading,');
}
const applyCalls = [];
const t5bApplyFn = new Function('sessionActivityRef', 'clockReissueSkipRef',
  'setClockCorrection', 'Date', 'CHAT_WINDOW_CLOCK_SKEW_MS',
  'futureClockWarningBypassesCooldown', 'isGameIdentityCurrent', 'commitClockWarning',
  'advanceFutureClockWarning', `${t5bApply}\nreturn applyClockCorrection;`)(
    t5bLocked.sessionActivityRef, { current: null },
    (next, { bypassCooldown }) => {
      applyCalls.push({ next, bypassCooldown });
      if (next !== 0 && !bypassCooldown) throw new RangeError('10-minute cooldown');
      return { next };
    }, { now: () => t5bBase - 180000 }, CHAT_WINDOW_CLOCK_SKEW_MS,
    futureClockWarningBypassesCooldown, () => true, t5bLocked.commitClockWarning,
    advanceFutureClockWarning);
assert.doesNotThrow(() => t5bApplyFn(0, null, t5bReading),
  'C3a: adopting a still-skewed clock is allowed');
assert(t5bLocked.shown().warning, 'C3a: adoption without correction does not clear warning');
assert.equal(t5bLocked.shown().warning.stage, 'band');
assert.throws(() => t5bApplyFn(70000, null, t5bReading), RangeError,
  'C3a: 110 seconds late cannot bypass cooldown');
assert.equal(t5bLocked.shown().warning.direction, 'late', 'C3a: refused correction keeps warning');
assert.doesNotThrow(() => t5bApplyFn(80001, null, t5bReading),
  'C3a: correction that clears warning bypasses cooldown');
assert.equal(t5bLocked.shown().warning, null, 'C3a: saved correction clears warning');
assert.deepEqual(applyCalls.map((call) => call.bypassCooldown), [false, false, true]);
assert.deepEqual(t5bPresence, [], 'C3a: correction does not publish active');
assert.match(t5bHook, /if \(receiptIssuanceBlocked\(\) \|\| phaseRef\.current !== 'chatting'/,
  'C3a: automatic read receipt tick keeps the shared gate');
const t5bActionReceipt = t5bBetween(t5bHook, '  const issueActionReceipt = useCallback(',
  '\n  }, [signKey, isSpectator');
assert.equal([...t5bActionReceipt.matchAll(/receiptIssuanceBlocked\(\)/g)].length, 2,
  'C3a: action receipt checks the shared gate before and after signing');
for (const name of ['sendMessage', 'sendVote', 'sendReport']) {
  const fn = t5bBetween(t5bHook, `  const ${name} = useCallback(async (`, '\n  }, [');
  assert.doesNotMatch(fn, /clockLock|clockWarning/,
    `C3a: ${name} has no clock warning gate`);
  assert.match(fn, /await account\.signMessage/,
    `C3a: ${name} still signs`);
  assert.match(fn, /isGameIdentityCurrent\(\)/,
    `C3a: ${name} still verifies identity`);
}
{
  const sent = [], relayed = [], signatures = [];
  let messages = [], reports = [], vote = null;
  const sendSession = { current: { warned: false, ended: false,
    clockWarning: { warning: { direction: 'late', stage: 'full', deviationMs: -180000 } },
    ownSignatures: new Set() } };
  const scope = {
    useCallback: (fn) => fn, signKey: 'key', rosterStartConfirmedRef: { current: true },
    ownChatHistoryReadyRef: { current: '3|2|H' },
    isGameIdentityCurrent: () => true, countHalfWidthChars: (value) => value.length,
    maxMsgCharsRef: { current: 200 }, GUEST_PINNED_RULES: { maxMsgChars: 200 },
    setServerError: () => {}, clientNow: () => t5bBase - 180000,
    privateKeyToAccount: () => ({ signMessage: async () => {
      const signature = `signature-${signatures.length}`; signatures.push(signature); return signature;
    } }), canonicalizeSignature: (value) => value,
    chatSignStringV2: () => 'chat', actionSignStringV2: () => 'action',
    blockNum: 3, groupId: 2, uid: 'H', sessionActivityRef: sendSession,
    notePresenceDisplayChat: () => {}, // 表示の控えは専用の presence 試験で確認する。
    setMessages: (updater) => { messages = updater(messages); },
    mergeMessagesV2: (prev, next) => [...prev, ...next],
    relayChannelRef: { current: { publishChat: (item) => relayed.push(item),
      publishAction: (_type, item) => relayed.push(item) } },
    send: (item) => { sent.push(item); return true; }, setChatSendAttempted: () => {},
    rosterStartConfirmed: true, loadJson: (_key, fallback) => fallback,
    saveJson: () => true, SELF_REPORTS_KEY: () => 'reports', SELF_VOTE_KEY: () => 'vote',
    SELF_VOTE_PREV_KEY: () => 'previous', warnActionPersistenceFailure: () => {},
    setMyReports: (updater) => { reports = updater(reports); },
    setReportCounts: (updater) => { updater({}); },
    setMyVote: (updater) => { vote = updater(vote); },
    setVotedUids: (updater) => { updater([]); },
    myVotePrevRef: { current: [] }, setMyVotePrev: () => {},
  };
  for (const [name, value] of [['sendMessage', 'hello'], ['sendVote', 'vote-cipher'],
    ['sendReport', 'report-cipher']]) {
    const fn = t5bBetween(t5bHook, `  const ${name} = useCallback(async (`, '\n  }, [');
    const sendActual = new Function(...Object.keys(scope), `${fn}\n  }, []);\nreturn ${name};`)(...Object.values(scope));
    assert.equal(await sendActual(value), true, `C3a: ${name} sends while warning is full`);
  }
  assert.deepEqual(sent.map((item) => item.type), ['chat', 'vote', 'report'],
    'C3a: warning permits chat, vote and report WS payloads');
  assert.equal(relayed.length, 3, 'C3a: warning permits three signed relay payloads');
  assert.equal(signatures.length, 3, 'C3a: warning permits all three signatures');
  assert.equal(messages.length, 1);
  assert.equal(reports.length, 1);
  assert.equal(vote?.voted, true);
}
{
  const h = makeT5bHookHarness();
  h.futureMarksRef.current.discard('chat', t5bFuture());
  const source = t5bBetween(t5bHook, '  reissueReadReceiptsRef.current = async (shiftBackMs, skipKeys = null) => {',
    '  // 既読受領証明の自動バッチ発行');
  const sent = [], relayed = [], signatures = [];
  const scope = {
    reissueReadReceiptsRef: { current: null }, readReceiptTickRunningRef: { current: false },
    isSpectator: false, signKey: 'key', uid: 'R', isGameIdentityCurrent: () => true,
    rosterStartConfirmedRef: { current: true }, phaseRef: { current: 'chatting' },
    receiptIssuanceBlocked: h.receiptIssuanceBlocked, blockNum: 3, groupId: 2,
    coordinateSelfReadReceiptBatch: async (_key, _accept, issue) => issue({ signal: { aborted: false }, known: [] }),
    queueReceipt: async () => true, canIssueReceiptAtChainTip: async () => true,
    messagesRef: { current: [] }, msgRefOf: () => 'ref', computeMsgKeyV2: () => 'key',
    receiptsRef: { current: {} }, chainTimelineRef: { current: { chattingStart: t5bBase - 240000,
      chatCloseAt: t5bBase + 360000 } },
    planReadReceiptReissues: () => [{ receiverUid: 'R', senderUid: 'H', msgRefs: ['ref'],
      timestamp: t5bBase - 180000 }], clientNow: () => t5bBase - 180000,
    privateKeyToAccount: () => ({ signMessage: async () => {
      signatures.push('signed'); return 'signed';
    } }), canonicalizeSignature: (value) => value, readReceiptSignString: () => 'payload',
    rememberOwnReadSignature: () => {}, send: (item) => sent.push(item),
    relayChannelRef: { current: { publishReceipt: (item) => relayed.push(item) } },
    readReceiptChannelRef: { current: null },
  };
  new Function(...Object.keys(scope), source)(...Object.values(scope));
  for (const stage of ['full', 'band']) {
    if (stage === 'band') h.commitClockWarning(advanceFutureClockWarning(h.shown(), { type: 'continue' }));
    await scope.reissueReadReceiptsRef.current(180000);
    assert.equal(sent.length, stage === 'full' ? 1 : 2,
      `C3a: Q9C reissues a signed read while warning is ${stage}`);
  }
  assert.equal(signatures.length, 2);
  assert.equal(relayed.length, 2);
  assert.equal(h.errors.length, 0);
}
{
  const h = makeT5bHookHarness();
  h.futureMarksRef.current.discard('chat', t5bFuture());
  h.sessionActivityRef.current.ownSignatures = new Set();
  const signed = [], sent = [], relayed = []; let chainChecks = 0;
  const receiptOwner = { current: {} };
  const scope = {
    useCallback: (fn) => fn, receiptAdmissionIdentityRef: receiptOwner,
    isGameIdentityCurrent: () => true, rosterStartConfirmedRef: { current: true },
    rosterIdentityMatches: () => true, currentRosterIdentityRef: { current: {} },
    blockNum: 3, groupId: 2, signKey: 'key', isSpectator: false, uid: 'R',
    phaseRef: { current: 'chatting' }, receiptIssuanceBlocked: h.receiptIssuanceBlocked,
    deferActionReceipt: () => false, hasOwnActionReceipt: () => false,
    clientNow: () => t5bBase - 180000, isReceiptTimely: () => true,
    chainTimelineRef: { current: { chatCloseAt: t5bBase + 1_000_000 } },
    confirmedChatWindowRef: { current: null }, CHAT_WINDOW_CLOCK_SKEW_MS,
    canIssueActionReceiptBeforeVoteCutoff: () => true,
    canIssueReceiptAtChainTip: async () => { chainChecks++; return true; },
    actionHashV2: (...parts) => parts.join('|'),
    issuedActionHashesRef: { current: new Set() },
    issuedActionReceiptBucketsRef: { current: new Map() },
    issuingActionReceiptBucketsRef: { current: new Map() },
    MAX_OBSERVED_ACTIONS_PER_ACTOR: 10,
    privateKeyToAccount: () => ({ signMessage: async () => {
      signed.push('signed'); return `signed-${signed.length}`;
    } }), canonicalizeSignature: (value) => value, receiptSignString: () => 'payload',
    sessionActivityRef: h.sessionActivityRef,
    send: (item) => sent.push(item),
    relayChannelRef: { current: { publishReceipt: (item) => relayed.push(item) } },
    queueReceipt: async () => true,
  };
  const source = t5bBetween(t5bHook, '  const issueActionReceipt = useCallback(async (',
    '\n  }, [signKey, isSpectator');
  const issue = new Function(...Object.keys(scope), `${source}\n  }, []);\nreturn issueActionReceipt;`)(...Object.values(scope));
  await issue('H', 'vote', { encrypted: 'vote-cipher', timestamp: t5bBase - 180000 });
  assert.equal(sent.length, 1, 'C3a: full warning permits signed action receipt');
  h.commitClockWarning(advanceFutureClockWarning(h.shown(), { type: 'continue' }));
  await issue('H', 'report', { encrypted: 'report-cipher', timestamp: t5bBase - 180000 });
  assert.equal(sent.length, 2, 'C3a: band warning permits signed action receipt');
  assert.equal(signed.length, 2);
  assert.equal(relayed.length, 2);
  assert.equal(chainChecks, 2);
}
{
  const h = makeT5bHookHarness();
  h.futureMarksRef.current.discard('chat', t5bFuture());
  const source = t5bBetween(t5bHook, '  const onlineUids = useMemo(',
    '  // 参加可能時刻（在席予定/復帰予定）設定。');
  // 表示判定を委譲した現物の関数も束縛し、自分の警告の検査はそのまま通す。
  const top = parse(t5bHook, { sourceType: 'module', plugins: ['jsx'] }).program.body;
  const compute = top.find((node) => node.type === 'FunctionDeclaration' && node.id.name === 'computeOnlineUids');
  const timing = top.find((node) => node.type === 'VariableDeclaration'
    && node.declarations.some((decl) => decl.id.name === 'PRESENCE_DISPLAY_TIMING'));
  assert(compute && timing, 'C3a: 現物の表示判定と定数を切り出せる');
  const helpers = `${t5bHook.slice(timing.start, timing.end)}\n${t5bHook.slice(compute.start, compute.end)}`;
  const makeOnline = new Function('useMemo', 'Date', 'peerActivityRef', 'IDLE_TIMEOUT_MS',
    'awayUids', 'uid', 'receiptIssuanceBlocked', 'isAway', 'otherSessionReadReceipt',
    'presenceTick', 'connectedUids', 'isConnected', 'presenceDisplayRef', 'presenceDisplayIdentityKey',
    `${helpers}\n${source}\nreturn onlineUids;`);
  const inputs = [(fn) => fn(), { now: () => t5bBase }, { current: {} }, 600000,
    [], 'R', h.receiptIssuanceBlocked, false, false, 0, [], false, { current: { lastChatByUid: {} } }, '3|2|R'];
  assert.deepEqual(makeOnline(...inputs), ['R'],
    'C3a: the warning alone keeps self in onlineUids');
  h.sessionActivityRef.current.warned = true;
  assert.deepEqual(makeOnline(...inputs), [],
    'C3a: other-session warning still removes self from onlineUids');
}
assert.match(recoveryApp, /futureMarks\.onFutureDiscard = considerRecoveryFuture/);
const receiptGateBody = t5bBetween(recoveryApp, 'function receiptIssuanceBlocked() {', '\n}');
assert.doesNotMatch(receiptGateBody, /clockLock|clockWarning/,
  'C3b: recovery shared receipt gate ignores clock warning');
const recoveryWarningIngress = t5bBetween(recoveryApp, 'function considerRecoveryFuture(type, item) {',
  '\nasync function refreshRecoveryClockWarning()');
assert.doesNotMatch(recoveryWarningIngress, /publishPresence\('away'\)/,
  'C3b: future discard does not publish dedicated away');
{
  const recoverySource = t5bBetween(recoveryApp, 'function receiptIssuanceBlocked() {',
    '\nasync function checkClock(');
  const state = { away: false, otherSessionReadReceipt: false, tabEnded: false,
    clockWarning: INITIAL_FUTURE_CLOCK_WARNING, receiptWarningIdentity: '3|2|R' };
  const presence = [], errors = [];
  const recovery = new Function('state', 'currentPhase', 'renderGame', 'readFutureLockClock',
    'advanceFutureClockWarning', 'clientNow', 'CHAT_WINDOW_CLOCK_SKEW_MS', 'publishPresence',
    `${recoverySource}\nreturn { considerRecoveryFuture, receiptIssuanceBlocked, continueRecoveryClockWarning };`)(
      state, () => 'chatting', () => {}, () => t5bReading,
      advanceFutureClockWarning, () => t5bBase - 180000, CHAT_WINDOW_CLOCK_SKEW_MS,
      (value) => presence.push(value));
  const marks = new VendoredMarks({ blockNum: 3, groupId: 2, now: () => t5bBase - 180000,
    onFutureDiscard: (...args) => { try { recovery.considerRecoveryFuture(...args); } catch (error) { errors.push(error); throw error; } } });
  marks.discard('chat', t5bFuture());
  assert(state.clockWarning.warning, 'C3b: verified recovery future discard starts warning');
  assert.equal(recovery.receiptIssuanceBlocked(), false, 'C3b: warning permits recovery receipts');
  assert.deepEqual(presence, [], 'C3b: warning sends no dedicated away');
  recovery.continueRecoveryClockWarning();
  assert.equal(state.clockWarning.warning.stage, 'band', 'C3b: continue leaves a band');
  assert.equal(errors.length, 0);
  state.otherSessionReadReceipt = true;
  assert.equal(recovery.receiptIssuanceBlocked(), true,
    'C3b: other-session warning survives clock warning continue');
}
const officialPage = readFileSync(new URL('../../src/pages/game.js', import.meta.url), 'utf8');
{
  const getterText = t5bBetween(officialPage, '  futureLockClockRef.current = () => {',
    '  const checkClock = useCallback(');
  const clockCheckRef = { current: { stepTick: 0, reading: { ...t5bReading,
    monoMs: 0, wallMs: t5bBase, stepTick: 0 } } };
  const futureClockReadRef = { current: { inFlight: null, lastMono: -Infinity, lastWall: -Infinity } };
  const futureLockClockRef = { current: null };
  let monoNow = 100, wallNow = t5bBase + 100, reads = 0;
  const readFreshClock = async () => { reads++; return { ...t5bReading, timeMs: wallNow }; };
  new Function('clockCheckRef', 'futureClockReadRef', 'futureLockClockRef', 'performance',
    'Date', 'readFreshClock', getterText)(clockCheckRef, futureClockReadRef, futureLockClockRef,
      { now: () => monoNow }, { now: () => wallNow }, readFreshClock);
  assert.equal(futureLockClockRef.current().timeMs, t5bBase + 100);
  assert.equal(reads, 0, 'fresh consensus L is used synchronously before discard');
  monoNow = 70000; wallNow = t5bBase + 70000;
  const firstRead = futureLockClockRef.current();
  assert.equal(futureLockClockRef.current(), firstRead, 'concurrent future items share one L request');
  assert.equal((await firstRead).timeMs, wallNow);
  assert.equal(reads, 1, 'stale L rereads even with the CLOCK-USER modal open');
  await Promise.resolve();
  clockCheckRef.current.reading = { ...t5bReading, monoMs: 100, wallMs: t5bBase, stepTick: 0 };
  futureClockReadRef.current.lastMono = 100;
  futureClockReadRef.current.lastWall = t5bBase;
  monoNow = 200; wallNow = t5bBase + 180000;
  assert.equal((await futureLockClockRef.current()).timeMs, wallNow);
  assert.equal(reads, 2, 'wall-only sleep invalidates L and allows a bounded reread');
  await Promise.resolve();
  clockCheckRef.current.reading = { ...t5bReading, monoMs: 0, wallMs: t5bBase, stepTick: 0 };
  monoNow = 201; wallNow += 1;
  assert.equal(futureLockClockRef.current(), null, 'future flood cannot exceed one request per 60 seconds');
  assert.equal(reads, 2);
}
{
  const recoveryGetter = t5bBetween(recoveryApp, 'function readFutureLockClock() {',
    '\nfunction receiptIssuanceBlocked()');
  let monoNow = 100, wallNow = t5bBase + 180000, reads = 0;
  const state = { clockReading: { ...t5bReading, monoMs: 0, wallMs: t5bBase, stepVersion: 0 },
    clockStepVersion: 0 };
  const futureClockRead = { inFlight: null, lastMono: -Infinity, lastWall: -Infinity };
  const getter = new Function('state', 'performance', 'Date', 'futureClockRead',
    'freshRecoveryClockReading', `${recoveryGetter}\nreturn readFutureLockClock;`)(
      state, { now: () => monoNow }, { now: () => wallNow }, futureClockRead,
      async () => { reads++; return { ...t5bReading, timeMs: wallNow }; });
  assert.equal((await getter()).timeMs, wallNow);
  assert.equal(reads, 1, 'recovery wall-only sleep does not use stale L');
}
const officialClockModal = readFileSync(new URL('../../src/components/game/ClockCorrectionModal.js', import.meta.url), 'utf8');
const officialLockModal = readFileSync(new URL('../../src/components/game/MultiSessionModal.js', import.meta.url), 'utf8');
{
  const source = officialLockModal.replace("import styles from '../../styles/Game.module.css';",
    "const styles = { multiSessionBackdrop: 'backdrop', multiSessionPanel: 'panel' };");
  const compiled = transformSync(source, { loader: 'jsx', format: 'cjs', jsx: 'automatic' }).code;
  const module = { exports: {} };
  new Function('module', 'exports', 'require', compiled)(module, module.exports,
    createRequire(import.meta.url));
  const Modal = module.exports.default;
  for (const direction of ['late', 'early']) {
    const markup = renderToStaticMarkup(createElement(Modal, { t: (key) => key,
      clockWarning: { direction }, onCorrect: () => {}, onContinue: () => {} }));
    assert.match(markup, /game\.clock\.manualEntry/,
      'C3a: first full render includes correction');
    assert.match(markup, /game\.clock\.warningContinue/,
      'C3a: first full render includes continue');
    assert.match(markup, direction === 'late' ? /game\.clock\.futureLockWarning/
      : /game\.clock\.futureEarlyWarning/);
    assert.doesNotMatch(markup, /game\.clock\.close/,
      'C3a: full render has no three-minute close gate');
  }
  const otherSession = renderToStaticMarkup(createElement(Modal, { t: (key) => key,
    onResume: () => {}, onClose: () => {} }));
  assert.match(otherSession, /game\.members\.multipleSessionsWarning/,
    'C3a: other-session branch remains visible');
}
{
  const finishSource = t5bBetween(officialClockModal, '  const finishCorrection = async (selected) => {',
    '  const confirm = async (correction) => {');
  for (const [cooldown, expected] of [[600000, 'cooldown'], [0, 'invalid']]) {
    let errorKind = null;
    const finish = new Function('setChecking', 'onConfirm', 'setPendingCorrection',
      'setError', 'correctionCooldownMs', `${finishSource}\nreturn finishCorrection;`)(
      () => {}, async () => { throw new RangeError('rejected'); }, () => {},
      (value) => { errorKind = value; }, () => cooldown);
    await finish(0);
    assert.equal(errorKind, expected,
      'C3a: only a RangeError during a running cooldown shows cooldownRejected');
  }
  assert.match(officialClockModal, /game\.clock\.cooldownRejected/);
}
assert.match(officialPage, /const rpcModal = [\s\S]*?zIndex: 10005/);
assert.match(officialPage, /const clockWarningModal = [\s\S]*?wsRaw\.phase === 'chatting'[\s\S]*?onCorrect=\{openManualClock\}/);
assert.match(officialClockModal, /aboveLock \? \{ \.\.\.backdrop, zIndex: 10004 \}/);
assert.match(officialLockModal, /zIndex: 10003/);
assert.match(recoveryApp, /futureLockWarning[\s\S]*?z-index:10003/);
assert.doesNotMatch(recoveryApp, /clockLockCloseReady|180100|releaseRecoveryClockLock/);
for (const [name, source] of Object.entries({ officialHook, officialPage,
  officialLockModal, recoveryApp,
  chainClock: readFileSync(new URL('../../src/utils/chainClock.js', import.meta.url), 'utf8'),
  vendorChainClock: readFileSync(new URL('../vendor/src/utils/chainClock.js', import.meta.url), 'utf8') })) {
  assert.doesNotMatch(source,
    /closeClockLock|releaseClockLock|releaseRecoveryClockLock|clockLockCloseReady|showClockLock|shouldLockForFutureItem|180100|\bclockLock\b|setClockLock/,
    `C3b: obsolete clock-lock names are absent from ${name}`);
}
for (const name of ['sendChat', 'sendVote', 'sendReport']) {
  const fn = t5bBetween(recoveryApp, `async function ${name}(`, '\n}');
  assert.doesNotMatch(fn, /state\.clockWarning|state\.clockLock/, `C3b: recovery ${name} has no clock warning gate`);
}
for (const stage of ['full', 'band']) {
  const sent = [];
  const state = { uid: 'H', blockNum: 3, groupId: 2,
    identity: { signKey: 'key', encryptKey: 'encrypt' },
    clockWarning: { warning: { direction: 'late', stage, deviationMs: -180000 } },
    ownSessionSignatures: new Set(), myVote: null, myVotePrev: [], myReports: [],
    intent: { vote: null, reports: [] }, voteWarningAccepted: true, reportWarningAccepted: true,
    cfg: { pins: { minMessages: 20, minChars: 500, maxReports: 2 } },
    members: [{ uid: 'H' }, { uid: 'V' }, { uid: 'R' }], tr: (key) => key,
    relay: { ownHistoryReady: true, getMessages: () => [], publishChat: async (item) => { sent.push(['chat', item]); return true; },
      publishAction: async (type, item) => { sent.push([type, item]); return true; } } };
  const pointedSource = recoveryApp.slice(recoveryApp.indexOf('function reportWarningName('), recoveryApp.indexOf('\nasync function freshRecoveryClockReading('))
    + recoveryApp.slice(recoveryApp.indexOf('function memberName(m) {'), recoveryApp.indexOf('\n// デポジットポイントは'));
  const recoveryPointedText = new Function('state', 'el', 'playerNumberOf', 'pointedTemplateText', 'pointedTemplateParts',
    `${pointedSource}\nreturn recoveryPointedText;`)(state, () => null, playerNumberOf, pointedTemplateText, pointedTemplateParts);
  const scope = { state, recoveryPointedText, rosterReady: () => true, p2pSendReady: () => true,
    chatSendBlockReason: () => null, chatSendBlockText: () => '', clientNow: () => t5bBase,
    privateKeyToAccount: () => ({ signMessage: async () => 'signature' }),
    canonicalizeSignature: (value) => value, chatSignStringV2: () => 'chat bytes',
    actionSignStringV2: () => 'action bytes', encryptAction: () => 'vote cipher',
    encryptReportDeterministic: () => 'report cipher',
    GUEST_PINNED_RULES: { minMessages: 20 }, myShownProgress: () => ({ turns: 20, chars: 500 }),
    submissionChatCloseAt: () => null, VOTE_RECEIPT_CUTOFF_MS: 600000,
    reportTargetStatusMap: () => ({}), decryptSelfTarget: () => null,
    canReportTarget: () => true, soleRemainingReportTarget: () => null,
    hasVisibleConfirmedVote: () => true, renderGame: () => {}, log: () => {},
    window: { confirm: () => true, alert: () => {} }, localStorage: { setItem: () => {} },
    showPersistenceWarning: () => {}, Date: { now: () => t5bBase } };
  const makeSend = (name) => new Function(...Object.keys(scope),
    `${t5bBetween(recoveryApp, `async function ${name}(`, '\n}')}\n}\nreturn ${name};`)(...Object.values(scope));
  await makeSend('sendChat')('hello');
  await makeSend('sendVote')('V');
  await makeSend('sendReport')('R');
  assert.deepEqual(sent.map(([type]) => type), ['chat', 'vote', 'report'],
    `C3b: recovery ${stage} warning permits signed chat, vote, report publication`);
  assert.equal(state.ownSessionSignatures.size, 1,
    `C3b: recovery ${stage} warning reaches signing in every sender`);
}
{
  const source = t5bBetween(recoveryApp, 'async function acknowledgeClockCorrection(',
    '\nasync function openManualClockCorrection()');
  const run = async (deltaMs) => {
    const state = { clockPendingCorrection: { deltaMs, nextMs: deltaMs,
      adoption: false, partial: { alert: false, keys: [] }, deviationMs: -180000 },
      clockAlert: { deviationMs: -180000 }, clockWarning: recoveryAdvance(
        recoveryInitial, { type: 'discard', reading: t5bReading, clientTimeMs: t5bBase - 180000,
          itemTimestampMs: t5bBase + 1, skewMs: 120000 }),
      clockConfirmedDeviationMs: 17, members: [{}], blockNum: 3 };
    state.clockWarning = recoveryAdvance(state.clockWarning, { type: 'shown' });
    const reading = t5bReading;
    let saved = 0, rendered = 0;
    const recoveryClock = { getClockCorrection: () => 0,
      setClockCorrection: (_next, { bypassCooldown }) => {
        if (!bypassCooldown) throw new RangeError('clock correction is available after the ten minute interval');
        saved++;
        state.clockWarning = recoveryAdvance(state.clockWarning, { type: 'shown' });
      }, markAdoptedClock: () => {} };
    const scope = { state, recoveryClock, parseUserCorrectionMs: (value) => value,
      freshRecoveryClockReading: async () => reading,
      futureClockWarningBypassesCooldown, CHAT_WINDOW_CLOCK_SKEW_MS: 120000,
      Date: { now: () => t5bBase - 180000 }, advanceFutureClockWarning: recoveryAdvance,
      renderClockModal: () => {}, renderGame: () => { rendered++; } };
    const confirm = new Function(...Object.keys(scope), `${source}\nreturn acknowledgeClockCorrection;`)(
      ...Object.values(scope));
    if (deltaMs === 70000) {
      await assert.rejects(confirm(null, true), RangeError,
        'C3b: warning correction to 110 seconds late cannot bypass cooldown');
      assert.equal(state.clockConfirmedDeviationMs, 17,
        'C3b: rejected recovery correction does not confirm its deviation');
    } else await confirm(null, true);
    return { state, saved, rendered };
  };
  await run(70000);
  const adopted = await run(0);
  assert.equal(adopted.state.clockWarning.warning?.stage, 'band',
    'C3b: adopting a still-skewed clock keeps the warning');
  assert.equal(adopted.rendered, 1, 'C3b: zero-correction adoption redraws warning immediately');
  const corrected = await run(180000);
  assert.equal(corrected.saved, 1);
  assert.equal(corrected.state.clockWarning.warning, null,
    'C3b: successful correction clears warning in the same call');
  assert.equal(corrected.state.clockWarning.fullShown, true,
    'C3b: correction preserves shown stamp written during notification');
  assert.equal(corrected.rendered, 1, 'C3b: recovery redraws the game after clearing warning');
}
// C3a: shared pure state and the official wiring. The recovery caller is updated in C3b.
const c3ClockMutations = {
  'c3-no-reshow': ["stage: reshow ? 'full' : s.warning.stage", "stage: s.warning.stage"],
  'c3-reshow-repeat': ['&& !s.reshowUsed', '&& true'],
  'c3-late-threshold-120': ['FUTURE_CLOCK_WARNING_LATE_MS = 100000', 'FUTURE_CLOCK_WARNING_LATE_MS = 120000'],
  'c3-early-needs-item': ["if (leadMs >= FUTURE_CLOCK_WARNING_EARLY_MS) return 'early';",
    "if (leadMs >= FUTURE_CLOCK_WARNING_EARLY_MS && itemTimestampMs != null) return 'early';"],
  'c3-deadline-ignores-lag': ['- VOTE_RECEIPT_CUTOFF_MS - lateMs', '- VOTE_RECEIPT_CUTOFF_MS'],
  'c3-deadline-ignores-freshness': ["if (lateMs >= CHAIN_CLOCK_RECEIPT_FRESH_MS) return { kind: 'none' };",
    '/* freshness deliberately bypassed by mutation */'],
  'c3-full-per-episode': ["stage: s.fullShown ? 'band' : 'full'", "stage: 'full'"],
  'c3-full-per-direction': ["stage: s.fullShown ? 'band' : 'full'",
    "stage: s.fullShown && direction === 'late' ? 'band' : 'full'"],
  'c3-adopt-clears': ["if (persists === null) return s;\n    if (!persists) return { ...s, warning: null };",
    "if (persists === null) return s;\n    return { ...s, warning: null };"],
};
let c3Clock = { classifyFutureClockWarning, advanceFutureClockWarning,
  futureClockWarningPersists, futureClockWarningBypassesCooldown, ownClockVoteDeadline,
  INITIAL_FUTURE_CLOCK_WARNING };
if (c3ClockMutations[c3Mutation] || c3Mutation === 'c3-late-without-item') {
  let source = readFileSync(new URL('../../src/utils/chainClock.js', import.meta.url), 'utf8');
  if (c3Mutation === 'c3-late-without-item') {
    const anchor = '&& Number.isSafeInteger(itemTimestampMs)\n      && Number.isSafeInteger(skewMs) && itemTimestampMs > clientTimeMs + skewMs';
    mutationAnchor(source, anchor, c3Mutation);
    source = source.replace(anchor, '&& Number.isSafeInteger(skewMs)');
  } else {
    const [anchor, replacement] = c3ClockMutations[c3Mutation];
    mutationAnchor(source, anchor, c3Mutation);
    source = source.replace(anchor, replacement);
  }
  c3Clock = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
}
const c3Reading = (timeMs) => ({ kind: 'consensus', sourceIds: ['a', 'b'], timeMs });
const c3L = c3Reading(t5bBase);
const c3C = t5bBase - 180000;
const c3Event = (type, clientTimeMs = c3C, reading = c3L, itemTimestampMs = t5bBase) =>
  ({ type, reading, clientTimeMs, itemTimestampMs, skewMs: CHAT_WINDOW_CLOCK_SKEW_MS });
const c3Advance = c3Clock.advanceFutureClockWarning;
let c3State = c3Advance(c3Clock.INITIAL_FUTURE_CLOCK_WARNING, c3Event('discard'));
assert.equal(c3State.warning.direction, 'late', 'C3a: L-C=3min and verified future discard warns');
assert.equal(c3Clock.classifyFutureClockWarning(c3Reading(t5bBase), t5bBase - 100000,
  t5bBase + 20001, 120000), 'late', 'C3a: late threshold is 100 seconds');
assert.equal(c3Clock.classifyFutureClockWarning(c3Reading(t5bBase), t5bBase - 100000,
  null, 120000), null, 'C3a: lag without future discard never warns');
assert.equal(c3Clock.classifyFutureClockWarning(c3Reading(t5bBase), t5bBase + 120000,
  null, 120000), 'early', 'C3a: early threshold needs no future item');
assert.equal(c3Clock.classifyFutureClockWarning(c3Reading(t5bBase), t5bBase + 119999,
  null, 120000), null, 'C3a: early threshold is exact');
assert.equal(c3Clock.classifyFutureClockWarning({ ...c3L, sourceIds: ['a'] }, c3C,
  t5bBase, 120000), null, 'C3a: one source cannot warn');
assert.equal(c3Clock.classifyFutureClockWarning({ ...c3L, timeMs: Infinity }, c3C,
  t5bBase, 120000), null, 'C3a: nonfinite L cannot warn');
for (const c of [t5bBase, t5bBase - 99999, t5bBase + 119999]) {
  assert.equal(c3Clock.classifyFutureClockWarning(c3L, c, c + 3600000, 120000), null,
    'C3a: attacker future item alone cannot warn correct clock');
}
c3State = c3Advance(c3State, { type: 'shown' });
assert.equal(c3State.fullShown, true);
c3State = c3Advance(c3State, { type: 'continue' });
assert.equal(c3State.warning.stage, 'band', 'C3a: first full is immediately closable');
const c3Band = c3State;
assert.equal(c3Advance(c3State, c3Event('discard')), c3State,
  'C3a: repeated future discard does not restart overlay');
assert.equal(c3Advance(c3State, c3Event('tick', c3C, null)), c3State,
  'C3a: unreadable L keeps existing band');
assert.equal(c3Advance(c3State, c3Event('tick', t5bBase - 99999)).warning, null,
  'C3a: late warning clears below 100 seconds');
assert.equal(c3Advance(c3Band, c3Event('tick', c3C,
  c3Reading(c3C + 600000))).warning.stage, 'band',
  'C3a: exactly ten minutes does not re-show full');
const c3FarL = c3Reading(c3C + 600001);
let c3Reshow = c3Advance(c3Band, c3Event('tick', c3C, c3FarL));
assert.equal(c3Reshow.warning.stage, 'full', 'C3a: above 10 minutes re-shows full once');
assert.equal(c3Reshow.reshowUsed, true);
c3Reshow = c3Advance(c3Reshow, { type: 'continue' });
assert.equal(c3Advance(c3Reshow, c3Event('tick', c3C, c3FarL)).warning.stage, 'band',
  'C3a: above 10 minutes never re-shows again');
let c3InitiallyFar = c3Advance(c3Clock.INITIAL_FUTURE_CLOCK_WARNING,
  c3Event('discard', c3C, c3Reading(c3C + 700001), c3C + 120001));
c3InitiallyFar = c3Advance(c3InitiallyFar, { type: 'shown' });
c3InitiallyFar = c3Advance(c3InitiallyFar, { type: 'continue' });
assert.equal(c3Advance(c3InitiallyFar, c3Event('tick', c3C,
  c3Reading(c3C + 700001))).warning.stage, 'band',
'C3a: initial full already above 10 minutes is not shown twice');
let c3AfterClear = c3Advance(c3Band, c3Event('tick', t5bBase - 99999));
assert.equal(c3AfterClear.warning, null);
c3AfterClear = c3Advance(c3AfterClear, c3Event('discard'));
assert.equal(c3AfterClear.warning.stage, 'band', 'C3a: next episode uses band only');
const c3Early = c3Advance(c3Band, c3Event('tick', c3C, c3Reading(c3C - 120000)));
assert.equal(c3Early.warning.direction, 'early', 'C3a: direction switches in same tick');
assert.equal(c3Early.warning.stage, 'band', 'C3a: direction switch does not re-show full');
let c3Adopt = c3Advance(c3Clock.INITIAL_FUTURE_CLOCK_WARNING, c3Event('discard'));
c3Adopt = c3Advance(c3Adopt, { type: 'shown' });
c3Adopt = c3Advance(c3Adopt, c3Event('corrected', c3C));
assert.equal(c3Adopt.warning?.direction, 'late', 'C3a: adoption at unchanged skew does not clear');
assert.equal(c3Adopt.warning?.stage, 'band', 'C3a: adoption after full moves to band');
assert.equal(c3Clock.futureClockWarningBypassesCooldown(c3Adopt, c3L,
  t5bBase - 110000, 120000), false, 'C3a: 110s correction cannot bypass cooldown');
assert.equal(c3Clock.futureClockWarningBypassesCooldown(c3Adopt, c3L,
  t5bBase - 99999, 120000), true, 'C3a: clearing correction bypasses cooldown');
assert.equal(c3Clock.futureClockWarningBypassesCooldown(c3Adopt, null,
  t5bBase, 120000), false, 'C3a: unreadable L cannot bypass cooldown');
const c3CloseAt = t5bBase + 1_000_000;
assert.deepEqual(c3Clock.ownClockVoteDeadline(c3CloseAt, 180500),
  { kind: 'at', ms: c3CloseAt - 600000 - 180500 },
  'C3a: own-clock deadline subtracts lag with second precision');
assert.deepEqual(c3Clock.ownClockVoteDeadline(c3CloseAt, 600000), { kind: 'none' },
  'C3a: no deadline row when freshness cannot hold');
assert.deepEqual(c3Clock.ownClockVoteDeadline(c3CloseAt, 599999),
  { kind: 'at', ms: c3CloseAt - 600000 - 599999 },
  'C3a: freshness edge below ten minutes still has time');
assert.equal(c3Clock.ownClockVoteDeadline(null, 180000), null,
  'C3a: unknown chat close has no deadline row');
let c3RefreshSource = t5bBetween(t5bHook, '  const refreshClockWarning = useCallback(async () => {',
  '  const applyClockCorrection = (nextMs, skipKeys = null, reading = null) => {');
if (c3Mutation === 'c3-refresh-stale-spectator') {
  const anchor = '!connectionIdentityRef.current.isSpectator';
  mutationAnchor(c3RefreshSource, anchor, c3Mutation);
  c3RefreshSource = c3RefreshSource.replace(anchor, '!isSpectator');
}
const c3RefreshSession = { current: { ended: false, clockWarning: c3Clock.INITIAL_FUTURE_CLOCK_WARNING } };
const c3RefreshIdentity = { current: { isSpectator: true } };
let c3RefreshReading = c3Reading(t5bBase);
const c3Refresh = new Function('useCallback', 'phaseRef', 'derivePhaseFromWindows', 'clientNow',
  'chainTimelineRef', 'connectionIdentityRef', 'sessionActivityRef', 'isGameIdentityCurrent',
  'futureLockClockRef', 'commitClockWarning', 'advanceFutureClockWarning',
  'CHAT_WINDOW_CLOCK_SKEW_MS', 'isSpectator',
  `${c3RefreshSource}\nreturn refreshClockWarning;`)(
  (fn) => fn, { current: 'chatting' }, () => 'chatting', () => t5bBase + 120000,
  { current: {} }, c3RefreshIdentity, c3RefreshSession, () => true,
  { current: () => c3RefreshReading }, (next) => { c3RefreshSession.current.clockWarning = next; },
  c3Clock.advanceFutureClockWarning, 120000, true);
await c3Refresh();
assert.equal(c3RefreshSession.current.clockWarning.warning, null,
  'C3a: spectator render does not warn');
c3RefreshIdentity.current.isSpectator = false;
await c3Refresh();
assert.equal(c3RefreshSession.current.clockWarning.warning?.direction, 'early',
  'C3a: stable refresh callback sees spectator switching to player');
c3RefreshReading = Promise.reject(new Error('RPC unavailable'));
await assert.doesNotReject(c3Refresh(), 'C3a: refresh catches rejected clock reads');
let c3Page = readFileSync(process.env.C3_PAGE_SOURCE || new URL('../../src/pages/game.js', import.meta.url), 'utf8');
if (c3Mutation === 'c3-deadline-minutes') {
  const anchor = "second: '2-digit'";
  mutationAnchor(c3Page, anchor, c3Mutation);
  c3Page = c3Page.replace(anchor, "second: undefined");
}
if (c3Mutation === 'c3-deadline-on-early') {
  const anchor = "warning.direction === 'late'\n              ? ownClockVoteDeadline";
  mutationAnchor(c3Page, anchor, c3Mutation);
  c3Page = c3Page.replace(anchor, "warning.direction === 'early'\n              ? ownClockVoteDeadline");
}
if (c3Mutation === 'c3-confirmed-before-save') {
  const anchor = "if (deltaMs !== 0 || wsRaw.clockWarning?.warning) wsRaw.applyClockCorrection(nextMs, skipKeys, warningReading);";
  mutationAnchor(c3Page, anchor, c3Mutation);
  const confirmed = 'if (Number.isFinite(review?.deviationMs)) check.confirmedDeviationMs = review.deviationMs;';
  mutationAnchor(c3Page, confirmed, c3Mutation);
  c3Page = c3Page.replace(anchor, '').replace(confirmed, `${confirmed}\n    ${anchor}`);
}
if (c3Mutation === 'c3-confirmed-only-on-save') {
  const anchor = "if (Number.isFinite(review?.deviationMs)) check.confirmedDeviationMs = review.deviationMs;";
  mutationAnchor(c3Page, anchor, c3Mutation);
  c3Page = c3Page.replace(anchor,
    "if ((deltaMs !== 0 || wsRaw.clockWarning?.warning) && Number.isFinite(review?.deviationMs)) check.confirmedDeviationMs = review.deviationMs;");
}
const c3BandText = t5bBetween(c3Page, "          {!isSpectator && wsRaw.phase === 'chatting' && wsRaw.clockWarning?.warning", "          {effectivePhase === 'chatting' && (");
assert.match(c3BandText, /warning\.direction === 'late'\s*\? ownClockVoteDeadline/,
  'C3a: own-clock deadline is in late band only');
assert.match(c3BandText, /ownClockVoteDeadline\(ws\.chatCloseAt, -warning\.deviationMs\)/,
  'C3c: official band passes chat close and positive lag to the deadline calculator');
assert.match(c3BandText, /new Date\(deadline\.ms\)\.toLocaleTimeString/,
  'C3c: official band formats the calculated deadline without changing its value');
assert.match(c3BandText, /second: '2-digit'/,
  'C3a: own-clock deadline includes seconds');
assert.match(c3BandText, /role="status"/,
  'C3a: chat band is a nonblocking status');
const c3Acknowledge = t5bBetween(c3Page,
  '  const acknowledgeClock = useCallback(', '  const openManualClock = useCallback(');
assert(c3Acknowledge.indexOf('wsRaw.applyClockCorrection(nextMs, skipKeys, warningReading)')
  < c3Acknowledge.indexOf('check.confirmedDeviationMs = review.deviationMs'),
'C3a: confirmed deviation is written only after a successful save');
assert.match(c3Acknowledge, /if \(Number\.isFinite\(review\?\.deviationMs\)\) check\.confirmedDeviationMs/,
  'C3a: zero correction without a warning still records adoption');
const c3ClockOverlay = t5bBetween(t5bHook, '  const continueClockWarning = () => {',
  '  const resumeOtherSession =');
assert.doesNotMatch(c3ClockOverlay, /publishPresence\('away'\)|publishPresence\('active'\)/,
  'C3a: warning transition has no presence message');
assert.doesNotMatch(t5bHook, /if \(clockWarning\.warning\) void publishPresence\('away'\)/,
  'C3a: warning has no dedicated away effect');
{
  const ast = parse(t5bHook, { sourceType: 'module', plugins: ['jsx', 'logicalAssignment'] });
  const awayCalls = [];
  const visit = (node, ancestors = []) => {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'CallExpression' && node.callee?.name === 'publishPresence'
        && node.arguments?.[0]?.value === 'away') awayCalls.push({ node, ancestors });
    for (const [key, value] of Object.entries(node)) {
      if (key === 'loc' || key === 'start' || key === 'end' || key === 'extra') continue;
      if (Array.isArray(value)) value.forEach((child) => visit(child, [...ancestors, node]));
      else if (value && typeof value === 'object') visit(value, [...ancestors, node]);
    }
  };
  visit(ast);
  const isOtherSessionEffect = ({ ancestors }) => ancestors.some((ancestor) =>
    ancestor.type === 'CallExpression' && ancestor.callee?.name === 'useEffect'
      && ancestor.arguments?.[1]?.elements?.some((item) => item.name === 'otherSessionReadReceipt'));
  const isIdleTimer = ({ ancestors }) => ancestors.some((ancestor) =>
    ancestor.type === 'CallExpression' && ancestor.callee?.name === 'setInterval'
      && ancestor.arguments?.[1]?.value === 15000);
  assert.equal(awayCalls.length, 2, 'C3c: only other-session effect and idle timer publish away');
  assert.equal(awayCalls.filter(isOtherSessionEffect).length, 1,
    'C3c: the only away effect belongs to the other-session warning');
  assert.equal(awayCalls.filter(isIdleTimer).length, 1,
    'C3c: the ordinary inactivity timer retains its away call');
  const onopen = t5bBetween(t5bHook, '      ws.onopen = () => {', '      ws.onmessage =');
  assert.match(onopen, /if \(receiptIssuanceBlocked\(\)\) ws\.send\(JSON\.stringify\(\{ type: 'set_presence', state: 'away' \}\)\)/,
    'C3c: WS onopen sends away only through the shared gate');
}
assert.match(c3Page, /checkClock\('game'\)\.finally\(\(\) => refreshClockWarning\(\)\)/,
  'C3a: warning sweep follows the existing 61-second clock check');
{
  const sweepSource = t5bBetween(c3Page, "  useEffect(() => {\n    if (!clockEntryKey || !['chatting', 'submitting'].includes(wsRaw.phase))",
    '  useEffect(() => {\n    clockCheckRef.current.stepTick');
  let timer = null; const order = [];
  new Function('useEffect', 'clockEntryKey', 'wsRaw', 'refreshClockWarning',
    'setInterval', 'clearInterval', 'checkClock', sweepSource)(
      (effect) => effect(), '3/2/R', { phase: 'chatting' }, () => order.push('refresh'),
      (fn, ms) => { assert.equal(ms, 61000); timer = fn; return 1; }, () => {},
      async () => { order.push('check'); });
  assert.deepEqual(order, ['refresh'], 'C3a: entering chat refreshes warning once');
  timer();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(order, ['refresh', 'check', 'refresh'],
    'C3a: 61-second sweep refreshes only after CLOCK-USER check finishes');
}
assert.match(t5bHook, /connectionIdentityRef\.current\.isSpectator/,
  'C3a: refresh uses current spectator identity');
{
  const identitySource = t5bBetween(t5bHook,
    '  if (!rosterIdentityMatches(receiptAdmissionIdentityRef.current, blockNum, groupId)',
    '  const [rosterVerification, setRosterVerification]');
  const oldWarning = { warning: { direction: 'late', stage: 'band' }, fullShown: true,
    reshowUsed: true };
  const ref = (current = null) => ({ current });
  const activity = ref({ ended: false, clockWarning: oldWarning });
  const admission = ref({ dispose: () => {} });
  const identity = ref({ blockNum: 2, groupId: 2, uid: 'old' });
  let renderedWarning = null;
  const scope = { blockNum: 3, groupId: 2, uid: 'R', receiptAdmissionIdentityRef: identity,
    rosterIdentityMatches: () => false, chatEndedRef: ref(true), receiptAdmissionRef: admission,
    futureMarksRef: ref(), FutureAdmissionMarks: class {}, clientNow: () => t5bBase,
    getClockCorrection: () => 0, readReceiptTrackerRef: ref(), PartialReadReceiptTracker: class {},
    ownSessionReadSignaturesRef: ref(), sessionActivityRef: activity,
    INITIAL_FUTURE_CLOCK_WARNING, setClockWarning: (value) => { renderedWarning = value; },
    issuedActionHashesRef: ref(), issuedActionReceiptBucketsRef: ref(),
    issuingActionReceiptBucketsRef: ref(), actionVerificationQueueRef: ref(),
    readReceiptConnectionRef: ref(), receiptTipRetryAfterRef: ref(), readReceiptPauseRef: ref({ until: 1 }) };
  new Function(...Object.keys(scope), identitySource)(...Object.values(scope));
  assert.deepEqual(activity.current.clockWarning, INITIAL_FUTURE_CLOCK_WARNING,
    'C3c: official new game clears band and full-screen count');
  assert.deepEqual(renderedWarning, INITIAL_FUTURE_CLOCK_WARNING,
    'C3c: official new game resets rendered warning');
  assert.deepEqual(identity.current, { blockNum: 3, groupId: 2, uid: 'R' },
    'C3c: reset belongs to the new receipt admission identity');
  assert.equal(scope.readReceiptPauseRef.current, null, 'R8-PHASEPAUSE: identity switch clears the read-receipt pause');
}
console.log('c3-official-warning: all checks passed');

// C3b: the official and recovery clients run the same transition sequence from byte-identical code.
const parityEvents = [c3Event('discard'), { type: 'shown' }, { type: 'continue' },
  c3Event('tick', c3C, c3Reading(c3C + 600001)), { type: 'continue' },
  c3Event('corrected', t5bBase - 99999), c3Event('discard'), { type: 'chatEnded' }];
let officialSequence = INITIAL_FUTURE_CLOCK_WARNING;
let recoverySequence = recoveryInitial;
for (const event of parityEvents) {
  officialSequence = advanceFutureClockWarning(officialSequence, event);
  recoverySequence = recoveryAdvance(recoverySequence, event);
  assert.deepEqual(recoverySequence, officialSequence,
    `C3b: official and recovery state parity after ${event.type}`);
}
assert.match(recoveryApp, /advanceFutureClockWarning\(state\.clockWarning/,
  'C3b: recovery caller imports the shared transition');
assert.match(recoveryApp, /classifyFutureClockWarning/,
  'C3b: recovery imports the shared classifier');
{
  const source = t5bBetween(recoveryApp, 'function renderClockWarningBand() {',
    '\nfunction renderFutureCountRows()');
  const makeBand = (direction, deviationMs, chatCloseAt) => {
    const state = { lang: 'ja', clockWarning: { warning: { direction, deviationMs, stage: 'band' } },
      tr: (key, args) => args?.time ? `${key}:${args.time}` : key };
    const el = (_tag, props = {}) => ({ ...props, children: [], append(child) { this.children.push(child); } });
    const scope = { state, el, ownClockVoteDeadline, submissionChatCloseAt: () => chatCloseAt,
      openManualClockCorrection: () => {} };
    const render = new Function(...Object.keys(scope), `${source}\nreturn renderClockWarningBand;`)(
      ...Object.values(scope));
    return render();
  };
  const late = makeBand('late', -180500, t5bBase + 3600000);
  assert.equal(late.role, 'status');
  const expectedDeadline = new Date(Math.floor((t5bBase + 3600000 - 600000 - 180500) / 1000) * 1000)
    .toLocaleTimeString('ja', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  assert.equal(late.children[1].textContent, `recovery.clock.bandDeadline:${expectedDeadline}`,
    'C3c: recovery band shows the actual own-clock vote deadline to the second');
  assert.equal(makeBand('early', 180000, t5bBase + 3600000).children.length, 2,
    'C3b: recovery early band has no deadline row');
  assert.equal(makeBand('late', -600000, t5bBase + 3600000).children.length, 2,
    'C3b: recovery ten-minute lag has no deadline row');
  assert.equal(makeBand('late', -180000, null).children.length, 2,
    'C3b: recovery unknown chat close has no deadline row');
}
{
  const source = t5bBetween(recoveryApp, 'async function refreshRecoveryClockWarning() {',
    '\nasync function checkClock(');
  const state = { tabEnded: false, members: [{}], rosterPaused: false, rosterInvalid: false,
    receiptWarningIdentity: '3|2|R', clockWarning: recoveryInitial };
  let reads = 0, renders = 0, awayPublishes = 0, phase = 'submitting';
  let resolveRead = null;
  const refresh = new Function('state', 'currentPhase', 'readFutureLockClock',
    'advanceFutureClockWarning', 'clientNow', 'CHAT_WINDOW_CLOCK_SKEW_MS', 'renderGame', 'log',
    'publishPresence',
    `${source}\nreturn refreshRecoveryClockWarning;`)(state, () => phase,
    () => { reads++; return resolveRead ? new Promise((resolve) => { resolveRead = resolve; }) : c3L; },
    recoveryAdvance, () => t5bBase + 120000, 120000, () => { renders++; }, () => {},
    () => { awayPublishes++; });
  await refresh();
  assert.equal(reads, 0, 'C3b: recovery submitting never reads for warning');
  assert.equal(state.clockWarning.reshowUsed, false,
    'C3b: recovery submitting does not consume reshow count');
  phase = 'chatting';
  await refresh();
  assert.equal(state.clockWarning.warning?.direction, 'early',
    'C3b: recovery chatting sweep starts early warning without an item');
  assert.equal(renders, 1);
  assert.equal(awayPublishes, 0, 'C3c: recovery warning refresh never publishes away');
  state.clockWarning = recoveryInitial;
  resolveRead = () => {};
  const pending = refresh();
  state.receiptWarningIdentity = '4|2|R';
  resolveRead(c3L);
  await pending;
  assert.equal(state.clockWarning.warning, null,
    'C3b: stale asynchronous reading cannot warn the next game');
  assert.equal(awayPublishes, 0, 'C3c: stale warning refresh never publishes away');
}
{
  const timerSource = t5bBetween(recoveryApp, '  state._clockTimer = setInterval(() => {',
    '  clearInterval(state._liveTimer);');
  const state = {};
  let timer, checks = 0, refreshes = 0, finishCheck;
  new Function('state', 'setInterval', 'currentPhase', 'checkClock', 'refreshRecoveryClockWarning',
    timerSource)(state, (callback, delay) => { assert.equal(delay, 61000); timer = callback; return 1; },
    () => 'chatting', () => { checks++; return new Promise((resolve) => { finishCheck = resolve; }); },
    () => { refreshes++; });
  timer();
  assert.equal(checks, 1, 'C3c: recovery 61-second callback runs the existing clock check');
  assert.equal(refreshes, 0, 'C3c: recovery warning waits for clock check settlement');
  finishCheck();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(refreshes, 1, 'C3c: recovery 61-second callback refreshes warning after check');
  const renderNowAt = recoveryApp.indexOf("  const renderNow = phase === 'completed'", recoveryApp.indexOf('function renderGame() {'));
  const entryAt = recoveryApp.lastIndexOf('  const phase = currentPhase();', renderNowAt);
  assert(entryAt > recoveryApp.indexOf('function renderGame() {') && renderNowAt > entryAt);
  const entrySource = recoveryApp.slice(entryAt, renderNowAt);
  const entryState = { _renderedPhase: 'waiting' };
  new Function('state', 'currentPhase', 'refreshRecoveryClockWarning', entrySource)(
    entryState, () => 'chatting', () => { refreshes++; });
  assert.equal(refreshes, 2, 'C3c: entering recovery chat refreshes warning once');
  new Function('state', 'currentPhase', 'refreshRecoveryClockWarning', entrySource)(
    entryState, () => 'chatting', () => { refreshes++; });
  assert.equal(refreshes, 2, 'C3c: ordinary recovery redraw does not refresh twice');
}
{
  const source = t5bBetween(recoveryApp, 'async function acknowledgeClockCorrection(',
    '\nfunction ');
  const warning = recoveryAdvance(recoveryInitial,
    c3Event('discard', t5bBase - 150000, c3Reading(t5bBase), t5bBase - 29000));
  const review = { deltaMs: 150000, nextMs: 150000, deviationMs: null, adoption: true,
    partial: { alert: false, keys: [] }, stage: 'review' };
  const state = { blockNum: 3, members: [{}], clockAlert: { deviationMs: -150000 },
    clockWarning: warning, clockPendingCorrection: review, clockDraft: '150',
    clockPreviousOutside: true, clockCheckGeneration: 0 };
  const saved = [], adopted = [], transitions = [];
  const correction = new Function('state', 'parseUserCorrectionMs', 'recoveryClock',
    'freshRecoveryClockReading', 'futureClockWarningBypassesCooldown', 'CHAT_WINDOW_CLOCK_SKEW_MS',
    'advanceFutureClockWarning', 'Date', 'renderClockModal', 'renderGame', source + '\nreturn acknowledgeClockCorrection;')(
    state, (value) => value,
    { getClockCorrection: () => 0, setClockCorrection: (...args) => saved.push(args),
      markAdoptedClock: (block) => adopted.push(block) },
    async () => { state.clockAlert = null; return c3Reading(t5bBase); },
    futureClockWarningBypassesCooldown, 120000,
    (before, event) => { transitions.push(event.type); return recoveryAdvance(before, event); },
    { now: () => t5bBase - 150000 }, () => {}, () => {});
  await assert.doesNotReject(correction(null, true),
    'C3c: clearing clockAlert during the awaited read does not interrupt a saved correction');
  assert.deepEqual(saved, [[150000, { bypassCooldown: true }]],
    'C3c: correction is saved with the warning cooldown exception');
  assert.deepEqual(transitions, ['corrected'], 'C3c: saved correction advances warning state');
  assert.deepEqual(adopted, [3], 'C3c: successful correction records adoption');
  assert.equal(state.clockConfirmedDeviationMs, null, 'C3c/S3R8-C-1b-01: a correction without a fresh review sets no band centre');
  assert.equal(state.clockPendingCorrection, null, 'C3c: successful correction clears pending review');
  assert.equal(state.clockWarning.warning, null, 'C3c: corrected warning clears immediately');
}
{
  const source = t5bBetween(recoveryApp, 'async function acknowledgeClockCorrection(',
    '\nfunction ');
  const warning = recoveryAdvance(recoveryInitial,
    c3Event('discard', t5bBase - 150000, c3Reading(t5bBase), t5bBase - 29000));
  const review = { deltaMs: 0, nextMs: 0, deviationMs: null, adoption: true,
    partial: { alert: false, keys: [] }, stage: 'review' };
  const state = { blockNum: 3, members: [{}], clockAlert: { deviationMs: -150000 },
    clockWarning: warning, clockPendingCorrection: review, clockDraft: '150',
    clockPreviousOutside: true, clockCheckGeneration: 0 };
  const saved = [], adopted = [], transitions = [];
  const correction = new Function('state', 'parseUserCorrectionMs', 'recoveryClock',
    'freshRecoveryClockReading', 'futureClockWarningBypassesCooldown', 'CHAT_WINDOW_CLOCK_SKEW_MS',
    'advanceFutureClockWarning', 'Date', 'renderClockModal', 'renderGame', source + '\nreturn acknowledgeClockCorrection;')(
    state, (value) => value,
    { getClockCorrection: () => 0, setClockCorrection: (...args) => saved.push(args),
      markAdoptedClock: (block) => adopted.push(block) },
    async () => { state.clockAlert = null; return c3Reading(t5bBase); },
    futureClockWarningBypassesCooldown, 120000,
    (before, event) => { transitions.push(event.type); return recoveryAdvance(before, event); },
    { now: () => t5bBase - 150000 }, () => {}, () => {});
  await correction(null, true);
  assert.deepEqual(saved, [], 'C3c/S3R8: zero correction is not saved');
  assert.equal(state.clockConfirmedDeviationMs, -150000, 'C3c: zero correction keeps the pre-await alert deviation');
}
{
  const source = t5bBetween(recoveryApp, '  if (showClockWarningFull) {',
    '\n}\n\nfunction renderGame() {');
  const state = { tr: (key) => key, clockWarning: recoveryAdvance(recoveryInitial,
    c3Event('discard')) };
  const root = { children: [], append(child) { this.children.push(child); } };
  const el = (_tag, props = {}) => ({ ...props, children: [], append(child) { this.children.push(child); } });
  let continued = 0;
  new Function('showClockWarningFull', 'clockDirection', 'state', 'el', 'modalContentRoot',
    'openManualClockCorrection', 'continueRecoveryClockWarning', 'advanceFutureClockWarning', source)(
      true, 'late', state, el, root, () => {}, () => { continued++; }, recoveryAdvance);
  assert.equal(state.clockWarning.fullShown, true,
    'C3b: recovery counts full only after drawing its modal');
  const full = root.children[0];
  const buttons = full.children[0].children.filter((child) => child.type === 'button');
  assert.deepEqual(buttons.map((button) => button.textContent),
    ['recovery.clock.manualEntry', 'recovery.clock.warningContinue'],
    'C3b: first full render offers correction and immediate continue');
  buttons[1].onclick();
  assert.equal(continued, 1);
  assert.doesNotMatch(source, /setTimeout|180000|180100/,
    'C3b: full warning has no three-minute timer');
}
console.log('c3-recovery-warning: all checks passed');

console.log('t5b-clock-lock: all checks passed');
let lostS = 0;
for (const [index, tickTime] of tickTimes.entries()) {
  const source = index === 0 ? officialHook : recoveryApp;
  const start = source.indexOf('const timestamp = nextReadReceiptTimestamp({ clockMs: clientNow(),');
  const end = source.indexOf(';', start);
  assert(start >= 0 && end > start, 'tick の時刻式を公式・復元から抽出する');
  const tickExpression = new Function('clientNow', 'known', 'fromMemory', 'nextReadReceiptTimestamp',
    `${source.slice(start, end + 1)}\nreturn timestamp;`);
  for (const [ahead, oldSender] of [[61 * 60_000, 'M'], [11 * 60_000, 'X']]) {
    const stale = { receiverUid: 'R', senderUid: oldSender, msgRefs: [`0x${'ab'.repeat(16)}`],
      timestamp: base + ahead, signature: 'old-signed-row' };
    const clockMs = base;
    const timestamp = tickExpression(() => clockMs, [stale], [], tickTime);
    const msgRefs = [`0x${'ad'.repeat(16)}`];
    const message = readReceiptSignString(3, 2, 'R', 'S', msgRefs, timestamp);
    const signed = { receiverUid: 'R', senderUid: 'S', msgRefs, timestamp,
      signature: await readAccount.signMessage({ message }) };
    const marks = new FutureAdmissionMarks({ blockNum: 3, groupId: 2, now: () => clockMs });
    let admitted = 0;
    const queue = new ReceiptAdmissionQueue({ now: () => clockMs, futureMarks: marks,
      getRosterUids: () => ['R', 'S', 'M'], getSelectionContext: () => ({ myUid: 'R' }),
      verifyReceipt: (receipt) => verifyMessage({ address: readAccount.address,
        message: readReceiptSignString(3, 2, receipt.receiverUid, receipt.senderUid,
          receipt.msgRefs, receipt.timestamp), signature: receipt.signature }),
      resolveReceipt: (receipt) => Math.abs(receipt.timestamp - clockMs) <= 600000
        ? { state: 'covered', priority: 'F', facts: msgRefs } : { state: 'invalid' },
      onAccept: () => { admitted++; } });
    const accepted = await queue.offer(signed);
    if (!accepted || admitted !== 1) lostS++;
    if (accepted) assert.equal(marks.has('receipt', signed), false);
    queue.dispose();
  }
}
assert.equal(lostS, 0, 'S の失う発言数（公式・復元の署名済み既読）');
const makeMarks = (Ctor = FutureAdmissionMarks) => {
  let now = base;
  let correction = 0;
  const marks = new Ctor({ blockNum: 3, groupId: 2, now: () => now,
    correction: () => correction });
  return { marks, setNow: (value) => { now = value; }, setCorrection: (value) => { correction = value; } };
};
for (const Ctor of [FutureAdmissionMarks, VendoredMarks]) {
  const observed = [];
  const marks = new Ctor({ blockNum: 3, groupId: 2, now: () => base,
    onFutureDiscard: (type, item) => observed.push(`${type}:${item.timestamp}`) });
  const item = { uid: 'A', text: 'future-observation', timestamp: base + 120001, signature };
  assert.equal(marks.discard('chat', item), true);
  assert.equal(marks.noteEvent('chat', item, 'event-A'), true);
  assert.equal(marks.has('chat', item), true);
  assert.equal(marks.discard('chat', item), true);
  assert.equal(observed.length, 4, 'new mark, P2P event, early has and redelivery each notify');
  assert.equal(marks.discard('chat', { ...item, timestamp: base + 120000 }), false);
  assert.equal(observed.length, 4, 'boundary item does not notify');
}
for (const Ctor of [FutureAdmissionMarks, VendoredMarks]) {
  const { marks, setNow, setCorrection } = makeMarks(Ctor);
  const edge = { uid: 'A', text: 'edge', timestamp: base + 120_000, signature };
  const future = { uid: 'A', text: 'future', timestamp: base + 120_001, signature };
  assert.equal(marks.discard('chat', edge), false, '+2分ちょうどは通す');
  assert.equal(marks.discard('chat', future, { eventId: 'event-A' }), true, '+2分+1msは捨てる');
  const ref = msgRefOf(computeMsgKeyV2(3, 2, future));
  assert.equal(marks.hasDiscardedChatRef('A', ref), true, 'Q34Aの控え');
  setNow(base + 200_000);
  assert.equal(marks.has('chat', future), true, '時刻が来てもページ内の印は残る');
  assert.equal(marks.releaseEligible(0).released, 0, '時計の自然な経過では印を外さない');
  setCorrection(0);
  assert.equal(marks.releaseEligible(0).released, 0, 'delta=0');
  assert.equal(marks.releaseEligible(0).released, 0);
  const short = marks.releaseEligible(0);
  assert.equal(short.eventIds.size, 0);
  assert.equal(marks.releaseEligible(1).released, 1, '補正差が超過と等しいと外す');
  assert.equal(marks.hasDiscardedChatRef('A', ref), false, '取り込み直す参照は控えから外す');
  assert.equal(marks.has('chat', future), false);

  const b = makeMarks(Ctor);
  const msg = { uid: 'B', text: 'stable', timestamp: base + 220_000, signature };
  b.marks.discard('chat', msg, { eventId: 'B-event' });
  b.setNow(base + 50_000);
  assert.equal(b.marks.discard('chat', msg), true);
  assert.equal(b.marks.releaseEligible(99_999).released, 0, '初回の超過100秒を保持');
  const released = b.marks.releaseEligible(100_000);
  assert.equal(released.released, 1);
  assert.deepEqual([...released.eventIds], ['B-event']);
  assert.equal(b.marks.discard('chat', { ...msg, timestamp: 1.5 }), false, '非正準時刻に印なし');

  const cap = makeMarks(Ctor);
  for (let i = 0; i < 1201; i++) cap.marks.discard('chat', {
    uid: 'A', text: `flood-${i}`, timestamp: base + 200_000 + i, signature,
  });
  assert.equal(cap.marks.byIssuer.get('A').size, 1200, '送り手の印の上限');
  cap.marks.discard('chat', { uid: 'B', text: 'honest', timestamp: base + 200_000, signature });
  assert.equal(cap.marks.byIssuer.get('B').size, 1, '別の送り手の予算を奪わない');
  assert.equal(cap.marks.chatRefs.get('A').size, 100, '送り手ごとの参照控え100件');
  const overflowReceipt = { receiverUid: 'A', senderUid: 'B',
    msgRefs: [`0x${'ac'.repeat(16)}`], timestamp: base + 180_000, signature };
  const overflowQueue = new ReceiptAdmissionQueue({ futureMarks: cap.marks, now: () => base,
    getRosterUids: () => ['A', 'B'], verifyReceipt: async () => true });
  await overflowQueue.offer(overflowReceipt);
  assert.equal(cap.marks.has('receipt', overflowReceipt), false, '印の上限超過では印を作らない');
  assert.equal(overflowQueue.seenDigests.size, 0, '上限超過を既出要約の隠れた印にしない');
  overflowQueue.dispose();

  const stepped = makeMarks(Ctor);
  stepped.setCorrection(60_000);
  stepped.marks.discard('chat', { uid: 'C', text: 'baseline',
    timestamp: base + 420_000, signature });
  assert.equal(stepped.marks.releaseEligible(300_000).released, 0,
    '印を付ける前の補正60秒を差に含めない');
  assert.equal(stepped.marks.releaseEligible(360_000).released, 1,
    '印の時点からの補正差300秒で解放');
  const staged = makeMarks(Ctor);
  staged.marks.discard('chat', { uid: 'D', text: 'two steps',
    timestamp: base + 400_000, signature });
  assert.equal(staged.marks.releaseEligible(150_000).released, 0);
  assert.equal(staged.marks.releaseEligible(300_000).released, 1,
    '150秒を2回の増加で超過280秒を解放');
  const rollback = makeMarks(Ctor);
  rollback.marks.discard('chat', { uid: 'E', text: 'signed delta',
    timestamp: base + 220_000, signature });
  assert.equal(rollback.marks.releaseEligible(-200_000).released, 0);
  assert.equal(rollback.marks.releaseEligible(50_000).released, 0,
    '戻す補正も含む符号つきの総差50秒では残す');
  assert.equal(rollback.marks.releaseEligible(100_000).released, 1);
}

{
  const { marks } = makeMarks();
  const receipt = { receiverUid: 'A', senderUid: 'B', msgRefs: [`0x${'ab'.repeat(16)}`],
    timestamp: base + 120_001, signature };
  assert.equal(marks.discard('receipt', receipt), true);
  assert.equal(marks.has('receipt', { ...receipt, _receivedAt: base }), true,
    '署名の外の到着時刻は印の鍵に入れない');
  let verified = 0;
  const queue = new ReceiptAdmissionQueue({ futureMarks: marks,
    getRosterUids: () => ['A', 'B'], verifyReceipt: async () => { verified++; return true; } });
  assert.equal(await queue.offer(receipt), false, '別経路の未来印を先に引く');
  assert.equal(verified, 0, '印の再到着では署名検証のCPUを使わない');
  queue.dispose();
  let restored = 0;
  const ownQueue = new ReceiptAdmissionQueue({ futureMarks: marks, now: () => base,
    getRosterUids: () => ['A', 'B'], getSelectionContext: () => ({ myUid: 'A' }),
    verifyReceipt: async () => true,
    resolveReceipt: () => ({ state: 'covered', priority: 'F', facts: ['own'] }),
    onAccept: () => { restored++; } });
  assert.equal(await ownQueue.offer(receipt, { restoredOwn: true, verified: true }), true,
    '同じ項目のネットワーク印が先でもこの端末の保存済み自己既読を戻す');
  assert.equal(restored, 1);
  ownQueue.forgetFutureDigests(marks.releaseEligible(1).receiptDigests);
  assert.equal(ownQueue.seenDigests.size, 1,
    '補正で未来印を外すときも、すでに戻した自分の既読の既出要約は保つ');
  ownQueue.dispose();
}

{
  let clock = base + 200_000;
  const marks = new FutureAdmissionMarks({ blockNum: 3, groupId: 2, now: () => clock });
  const acceptedReceipt = { receiverUid: 'A', actionHash: `0x${'af'.repeat(32)}`,
    timestamp: clock, signature };
  const queue = new ReceiptAdmissionQueue({ now: () => clock, futureMarks: marks,
    getRosterUids: () => ['A'], verifyReceipt: async () => true,
    resolveReceipt: () => ({ state: 'covered', priority: 'F', facts: ['accepted'] }) });
  await queue.offer(acceptedReceipt);
  assert.equal(queue.getAcceptedReceipts().length, 1);
  clock -= 300_000;
  await queue._evaluate([...queue.entries.values()][0]);
  assert.equal(queue.getAcceptedReceipts().length, 1,
    '補正を戻しても最初の取り込みで受理した項目を遡及して取り消さない');
  assert.equal(marks.has('receipt', acceptedReceipt), false);
  queue.dispose();
}

{
  const priorStorage = globalThis.localStorage;
  const stored = new Map();
  globalThis.localStorage = { getItem: (key) => stored.get(key) ?? null,
    setItem: (key, value) => stored.set(key, value), removeItem: (key) => stored.delete(key) };
  try {
    const relay = new RecoveryRelay({ signKey: `0x${'52'.repeat(32)}`,
      blockNum: 3, groupId: 2, uid: 'A', members: [{ uid: 'A' }, { uid: 'B' }],
      now: () => base });
    const own = { receiverUid: 'A', senderUid: 'B', msgRefs: [`0x${'ad'.repeat(16)}`],
      timestamp: base + 120_001, signature };
    relay.futureMarks.discard('receipt', own);
    await relay._ingestReceiptArrivals([own], { fromChannelStorage: true });
    assert.equal(!!relay._receipts[receiptIdentityDigest(own)], true,
      '復元はチャネルの保存から戻す自分の既読を先行する未来印で消さない');
  } finally { globalThis.localStorage = priorStorage; }
}

const oldWebSocket = globalThis.WebSocket;
globalThis.WebSocket = { OPEN: 1 };
try {
  for (const Pool of [RelayPool, VendoredPool]) {
  const sent = [];
  const socket = { readyState: 1, send: (value) => sent.push(JSON.parse(value)) };
  const pool = new Pool({ relays: [], tag: 'tag', authors: ['pubkey'],
    onEvent: () => {}, now: () => base + 300_000 });
  pool.sockets.set('wss://fake', socket);
  pool.seenIds.add('event-A');
  pool._seenCreatedAt.set('event-A', 100);
  pool._countedIds.set('event-A', 100);
  pool.refetchHistory(new Set(['event-A']));
  assert.equal(pool.seenIds.has('event-A'), false);
  assert.equal(pool._seenCreatedAt.has('event-A'), false);
  assert.equal(pool._countedIds.has('event-A'), true, '件数は二重に数えない');
  assert.equal(sent[0][0], 'REQ');
  assert.equal(sent[0][2].until, Math.floor((base + 420_000) / 1000), '履歴のuntilはC+2分');
  assert.equal(pool.historyPages.get('wss://fake').pageCount, 1, '履歴ページを0から始める');

  const key = deriveNostrKey(`0x${'52'.repeat(32)}`, 3);
  const delayed = buildEvent(key.sk, key.pubkey, [['t', 'tag']],
    JSON.stringify({ type: 'chat' }), Math.floor((base - 100_000) / 1000));
  let wallNow = base - 300_000;
  let delivered = 0;
  let historyPool;
  const filteredSocket = { readyState: 1, send: (wire) => {
    const [kind, subId, filter] = JSON.parse(wire);
    if (kind === 'REQ' && delayed.created_at <= filter.until) {
      queueMicrotask(() => historyPool._handleMessage({
        data: JSON.stringify(['EVENT', subId, delayed]),
      }, 'wss://history'));
    }
  } };
  historyPool = new Pool({ relays: [], tag: 'tag', authors: [key.pubkey],
    onEvent: () => { delivered++; return true; }, now: () => wallNow });
  historyPool.sockets.set('wss://history', filteredSocket);
  historyPool._requestHistoryPage(filteredSocket, 'wss://history',
    Math.floor((wallNow + 120_000) / 1000));
  await Promise.resolve();
  assert.equal(delivered, 0, '生時計が5分遅れた初回のuntilではイベントが履歴に現れない');
  wallNow += 300_000;
  historyPool.refetchHistory();
  await Promise.resolve();
  assert.equal(delivered, 1, '補正したC＋2分のuntilで、WSなし・liveなしでもリレー履歴から届く');
  }
} finally { globalThis.WebSocket = oldWebSocket; }

console.log('S3FIX D1c future: ALL PASSED');

// S3R4 T5a: natural maturity, ids REQ, official timer and recovery wiring.
{
const mutation = process.argv.find((arg) => arg.startsWith('--mutation='))?.slice(11);
let source = readFileSync(process.env.T5A_RELAY_SOURCE || new URL('../../src/utils/relay.js', import.meta.url), 'utf8');
if (mutation === 't5c-count-receipts') {
  const target = "if (type === 'chat' || type === 'action') this.markCounts[type]++;";
  mutationAnchor(source, target, mutation);
  source = source.replace(target,
    "if (type === 'chat' || type === 'action') this.markCounts[type]++; if (type === 'receipt') this.markCounts.action++;");
}
const hookSource = readFileSync(new URL('../../src/hooks/useGameWebSocket.js', import.meta.url), 'utf8');
const classBody = source.slice(source.indexOf('export class FutureAdmissionMarks {'), source.indexOf('\nfunction receiptRawFacts('));
const Marks = new Function('isCanonicalTimestamp', 'isCanonicalSignature', 'receiptIdentityDigest',
  'keccak256', 'toBytes', 'CHAT_WINDOW_CLOCK_SKEW_MS', 'PER_PUBKEY_EVENT_CAP',
  'GUEST_PINNED_RULES', 'computeMsgKeyV2', 'msgRefOf',
  `${classBody.replace('export class', 'class')}\nreturn FutureAdmissionMarks;`)(
  isCanonicalTimestamp, isCanonicalSignature, receiptIdentityDigest, keccak256, toBytes,
  CHAT_WINDOW_CLOCK_SKEW_MS, 1200, GUEST_PINNED_RULES, computeMsgKeyV2, msgRefOf);
let now = 1_750_000_000_000;
const marks = new Marks({ blockNum: 3, groupId: 2, now: () => now });
const sig = await privateKeyToAccount(`0x${'11'.repeat(32)}`).signMessage({ message: 't5a' });
const chat = { uid: 'A', text: 'mature', timestamp: now + 120_001, signature: sig };
assert.equal(marks.discard('chat', chat, { eventId: 'event-A' }), true);
const ref = msgRefOf(computeMsgKeyV2(3, 2, chat));
assert.equal(marks.hasDiscardedChatRef('A', ref), true);
assert.equal(marks.releaseMatured(now).released, 0, '成熟前に印を外さない');
now += 1;
const release = mutation === 't5a-no-mature-release'
  ? { released: 0, eventIds: new Set(), receiptDigests: new Set() }
  : marks.releaseMatured(now);
assert.equal(release.released, 1, '自然な時計の経過で印を外す');
assert.deepEqual([...release.eventIds], ['event-A']);
assert.equal(marks.hasDiscardedChatRef('A', ref), false, 'chatRefs を掃除する');
assert.equal(marks.has('chat', chat), false);
assert.deepEqual(marks.countsByType(), { chat: 0, action: 0 });
now -= 2;
assert.equal(marks.discard('chat', chat), true, '時計が戻って再び未来なら新しい印を付ける');

const receipt = { receiverUid: 'A', senderUid: 'B', msgRefs: [`0x${'ab'.repeat(16)}`],
  timestamp: now + 120_001, signature: sig };
marks.discard('receipt', receipt);
assert.deepEqual(marks.countsByType(), { chat: 1, action: 0 }, '受領証明を表示件数に含めない');
now += 1;
assert(marks.releaseMatured(now).receiptDigests.has(receiptIdentityDigest(receipt)));

// 1200 marks for A do not consume B's quota. Releasing them clears the owner budget.
const capped = new Marks({ blockNum: 3, groupId: 2, now: () => now });
for (let i = 0; i < 1201; i++) capped.discard('chat', { uid: 'A', text: `f${i}`,
  timestamp: now + 120_001 + i, signature: sig });
capped.discard('chat', { uid: 'B', text: 'honest', timestamp: now + 120_001, signature: sig });
assert.equal(capped.byIssuer.get('A').size, 1200);
assert.equal(capped.byIssuer.get('B').size, 1);
let groupedRefetches = 0;
for (let step = 0; step < 5; step++) {
  now += 300000;
  if (capped.releaseMatured(now).inWindow) groupedRefetches++;
}
assert(groupedRefetches <= 5, '1秒刻みの1200印も5分の見回りでまとめる');
assert.equal(capped.byIssuer.size, 0);
const longFuture = new Marks({ blockNum: 3, groupId: 2, now: () => now });
longFuture.discard('chat', { uid: 'A', text: '30 days',
  timestamp: now + 30 * 24 * 60 * 60 * 1000, signature: sig });
for (let step = 0; step < 2; step++) {
  now += 300000;
  assert.equal(longFuture.releaseMatured(now).released, 0);
}
assert.equal(longFuture.marks.size, 1, '遠い未来の印で短い再試行を回さない');
const outside = new Marks({ blockNum: 3, groupId: 2, now: () => now });
const afterClose = { uid: 'A', text: 'after close', timestamp: now + 120_001, signature: sig };
outside.discard('chat', afterClose, { eventId: 'outside-id' });
now += 1;
const outsideRelease = outside.releaseMatured(now, afterClose.timestamp - 1);
assert.equal(outsideRelease.released, 1);
assert.equal(outsideRelease.inWindow, 0);
assert.equal(outsideRelease.eventIds.size, 0, '窓の後の印は外すだけでリレーを呼ばない');

// The marked request is bounded by ids, not by an until/limit history page.
const pool = new RelayPool({ relays: ['wss://fake'], tag: 'group', authors: ['author'], now: () => now });
const sent = [];
const socket = { readyState: 1, send: (value) => sent.push(JSON.parse(value)) };
pool.sockets.set('wss://fake', socket);
globalThis.WebSocket = { OPEN: 1 };
if (mutation !== 't5a-no-refetch') {
  if (mutation === 't5a-refetch-by-until') pool.refetchHistory(new Set(['event-A']));
  else pool.refetchMarkedIds(new Set(['event-A']));
}
const requests = sent.filter((row) => row[0] === 'REQ');
assert.equal(requests.length, 1, '成熟した id を1回要求する');
assert.deepEqual(requests[0][2].ids, ['event-A']);
assert.equal('until' in requests[0][2], false);
assert.equal('limit' in requests[0][2], false);
pool._handleMessage({ data: JSON.stringify(['EOSE', requests[0][1]]) }, 'wss://fake');
assert(sent.some((row) => row[0] === 'CLOSE' && row[1] === requests[0][1]));
const closedMarks = new FutureAdmissionMarks({ blockNum: 3, groupId: 2 });
const closedPool = new RelayPool({ relays: ['wss://fake'], tag: 'group', authors: ['author'],
  onMarkedRequestClosed: (owners) => closedMarks.noteClosedMarkedIds(owners) });
const closedSent = [];
closedPool.sockets.set('wss://fake', { readyState: 1,
  send: (value) => closedSent.push(JSON.parse(value)) });
closedPool.refetchMarkedIds(new Set(['lost-chat']), new Map([['lost-chat', 'B']]));
const closedSub = closedSent.find((row) => row[0] === 'REQ')[1];
closedPool._handleMessage({ data: JSON.stringify(['CLOSED', closedSub, 'lost']) }, 'wss://fake');
assert.equal(closedMarks.hasClosedMarkedRequest('B'), true,
  'ids の REQ が CLOSED で終わった送り手の区切りは確定しない');
closedMarks.noteRecoveredMarkedId('lost-chat');
assert.equal(closedMarks.hasClosedMarkedRequest('B'), false,
  '後で同じ id が得られたら表示の確定不能を解除する');
const boundedClosed = new FutureAdmissionMarks({ blockNum: 3, groupId: 2 });
boundedClosed.noteClosedMarkedIds(new Map(Array.from({ length: MAX_SEEN_EVENT_IDS }, (_, index) =>
  [`closed-${index}`, 'A'])));
boundedClosed.noteClosedMarkedIds(new Map([['beyond-cap', 'B']]));
assert.equal(boundedClosed.closedMarkedIds.size, MAX_SEEN_EVENT_IDS,
  '長時間の CLOSED でも id の記録は既存の総上限を超えない');
assert.equal(boundedClosed.hasClosedMarkedRequest('B'), true,
  '記録できなかった CLOSED の送り手を確定扱いにしない');

// Real GameRelayChannel, signed outer event and fake socket: late created_at
// cannot hide a marked event from an ids request when it matures.
const storage = new Map();
globalThis.localStorage = { getItem: (key) => storage.get(key) ?? null,
  setItem: (key, value) => storage.set(key, value), removeItem: (key) => storage.delete(key) };
const aKey = `0x${'21'.repeat(32)}`;
const vKey = `0x${'22'.repeat(32)}`;
const a = privateKeyToAccount(aKey);
const v = privateKeyToAccount(vKey);
const aNostr = deriveNostrKey(aKey, 3);
const vNostr = deriveNostrKey(vKey, 3);
const boardClock = { now: 1_750_000_000_000 };
const received = [];
const realMarks = new FutureAdmissionMarks({ blockNum: 3, groupId: 2, now: () => boardClock.now });
const channel = new GameRelayChannel({ signKey: vKey, blockNum: 3, groupId: 2, uid: 'V',
  members: [{ uid: 'V', bAddr: { address: v.address, pubKey: v.publicKey,
    nostrPubkey: vNostr.pubkey } }, { uid: 'A', bAddr: { address: a.address,
    pubKey: a.publicKey, nostrPubkey: aNostr.pubkey } }],
  now: () => boardClock.now, futureMarks: realMarks,
  verifyInnerSignature: (type, inner) => type === 'chat' && verifyMessage({
    address: a.address, message: chatSignStringV2(3, 2, 'A', inner.text, inner.timestamp),
    signature: inner.signature }), onChat: (inner) => received.push(inner) });
channel.validNostrByUid.set('A', aNostr.pubkey);
channel.validNostrByUid.set('V', vNostr.pubkey);
const signedChat = { type: 'chat', blockNum: 3, groupId: 2, uid: 'A', text: 'h',
  timestamp: boardClock.now + 120_001 };
signedChat.signature = await a.signMessage({ message: chatSignStringV2(3, 2, 'A', 'h', signedChat.timestamp) });
const outer = buildEvent(aNostr.sk, aNostr.pubkey, [['t', groupTag(3, 2)]],
  JSON.stringify(signedChat), Math.floor(boardClock.now / 1000) + 3600);
const realPool = new RelayPool({ relays: ['wss://board'], tag: groupTag(3, 2),
  authors: [aNostr.pubkey, vNostr.pubkey], now: () => boardClock.now,
  onEvent: (event) => channel._handleEvent(event) });
channel.pool = realPool;
const boardSent = [];
realPool.sockets.set('wss://board', { readyState: 1,
  send: (value) => boardSent.push(JSON.parse(value)) });
realPool._handleMessage({ data: JSON.stringify(['EVENT', 'live', outer]) }, 'wss://board');
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(received.length, 0);
assert.equal(realMarks.has('chat', signedChat), true);
boardClock.now += 1;
const boardRelease = realMarks.releaseMatured(boardClock.now);
channel.refetchMarkedIds(boardRelease.eventIds);
const boardReq = boardSent.find((frame) => frame[0] === 'REQ');
assert.deepEqual(boardReq[2].ids, [outer.id]);
realPool._handleMessage({ data: JSON.stringify(['EVENT', boardReq[1], outer]) }, 'wss://board');
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(received.length, 1, '成熟後に本物のチャネルが発言を取り込む');
const warnings = new ReceiptWarnings('V');
const hRef = msgRefOf(computeMsgKeyV2(3, 2, signedChat));
warnings.noteFutureChatRef('A', hRef);
warnings.observe({ receiverUid: 'H', senderUid: 'A', msgRefs: [hRef] }, 'digest-h', 0);
assert.equal(warnings.issuers.get('H').rows.size, 1);
warnings.evaluate(1_000_000, () => false);
assert.equal(warnings.issuers.get('H').rows.size, 1,
  '項目が戻らなければ未来参照の控えを維持する');
warnings.evaluate(1_000_000, (_uid, ref) => ref === hRef);
assert.equal(warnings.issuers.get('H').rows.size, 0,
  '成熟して届いた発言は警告②の対象に数える');

const recoveryClock = { now: 1_750_000_000_000 };
const recovery = new RecoveryRelay({ signKey: vKey, blockNum: 3, groupId: 2,
  uid: 'V', members: [], now: () => recoveryClock.now,
  getChatWindow: () => ({ endMs: recoveryClock.now + 600000 }) });
const recoveryIds = [];
recovery.channel = { refetchMarkedIds: (ids) => recoveryIds.push([...ids]), stop: () => {} };
recovery.futureMarks.discard('chat', { ...chat, timestamp: recoveryClock.now + 120_001 },
  { eventId: 'recovery-id' });
recovery.refetchMatured();
assert.equal(recoveryIds.length, 0);
recoveryClock.now += 1;
recovery.refetchMatured();
assert.deepEqual(recoveryIds, [['recovery-id']]);
// The recovery sweep is independent of mark additions and is stopped with its original id.
const originalInterval = globalThis.setInterval;
const originalClearInterval = globalThis.clearInterval;
let intervalDelay;
let intervalCount = 0;
const intervalClears = [];
globalThis.setInterval = (_callback, ms) => { intervalDelay = ms; return 200 + ++intervalCount; };
globalThis.clearInterval = (id) => intervalClears.push(id);
try {
  recovery.restartMaturityTimer();
  assert.equal(intervalDelay, 60000, 'MATURE18: 復元の成熟の見回りは60秒ごと');
  for (let i = 0; i < 10; i++) recovery.futureMarks.discard('chat',
    { ...chat, text: `later-${i}`, timestamp: recoveryClock.now + 120_001 + i });
  assert.equal(intervalCount, 1, 'MATURE18: 印の追加で復元の見回りを張り直さない');
  recovery.stop();
  assert.deepEqual(intervalClears, [201], 'RecoveryRelay.stop で見回りを止める');
} finally {
  globalThis.setInterval = originalInterval;
  globalThis.clearInterval = originalClearInterval;
}

// The actual official hook effect: one recurring sweep per mounted identity.
const effectStart = hookSource.indexOf('  // 未来印は中身を持たない。');
const effectEndMarker = '  }, [blockNum, groupId, uid, sessionEnded]);';
const effectEnd = hookSource.indexOf(effectEndMarker, effectStart);
assert(effectStart >= 0 && effectEnd > effectStart, '公式 hook の成熟の見回りの配線');
let effect = hookSource.slice(effectStart, effectEnd + effectEndMarker.length);
const displayLine = 'marks.onChange = () => setFutureMarkVersion((version) => version + 1);';
const officialMutations = {
  't5a-unbounded-reconnect': ['}, 60000);', '}, 1);'],
  't5a-timer-unclamped': ['}, 60000);', '}, 1);'],
  't5a-drop-throttled': ['if (!released.inWindow) return;', 'if (true) return;'],
  'm18-official-oneshot': ['const timer = setInterval(() => {', 'const timer = setTimeout(() => {'],
  'm18-official-rearm-on-change': [displayLine,
    'marks.onChange = () => { setFutureMarkVersion((version) => version + 1); setInterval(() => {}, 60000); };'],
  'm18-official-no-display-version': [displayLine, 'marks.onChange = () => {};'],
  'm18-official-ignore-window': ['      if (!released.inWindow) return;\n', ''],
  'm18-official-no-cleanup': ['      clearInterval(timer);\n', ''],
  'm18-official-no-onchange-null': ['      if (marks.onChange) marks.onChange = null;\n', ''],
  'm18-official-no-ended': ['      if (sessionActivityRef.current.ended) { clearInterval(timer); return; }\n', ''],
  'm18-official-clock-deps': [effectEndMarker,
    '  }, [blockNum, groupId, uid, clockVersion, sessionEnded]);'],
  'm18-official-reconnect-unguarded': [
    'if (owner && !owner.intentional && !sessionActivityRef.current.ended\n'
    + '          && !connectionIdentityRef.current.isSpectator\n'
    + "          && connectionStatusRef.current === 'connected'\n"
    + '          && wsRef.current?.readyState === WebSocket.OPEN)', 'if (true)'],
  'm18-official-reconnect-spectator': ['          && !connectionIdentityRef.current.isSpectator\n', ''],
};
if (officialMutations[mutation]) {
  const [from, to] = officialMutations[mutation];
  mutationAnchor(effect, from, mutation);
  effect = effect.replace(from, to);
}
assert(!/setTimeout\(/.test(effect), 'MATURE18: 成熟の見回りに一回きりのタイマーを使わない');
assert(!effect.includes('maturitySchedulerRef') && !hookSource.includes('maturitySchedulerRef'),
  'MATURE18: 精密なタイマーの張り直し口を残さない');
assert(!effect.includes('clockVersion'), 'MATURE18: 補正で見回りを張り直さない');
const sweepClock = { now };
const mounted = { current: { ended: false } };
const ownerRef = { current: { intentional: false } };
const identityRef = { current: { isSpectator: false } };
const statusRef = { current: 'connected' };
const socketRef = { current: { readyState: 1 } };
let tick;
let intervalMs;
let intervals = 0;
const cleared = [];
let versionBumps = 0;
let refetches = 0;
let reconnects = 0;
let windowEnd = Infinity;
const refetchArgs = [];
const forgottenDigests = [];
const markSet = new FutureAdmissionMarks({ blockNum: 3, groupId: 2, now: () => sweepClock.now });
const runEffect = new Function('useEffect', 'setInterval', 'clearInterval', 'setTimeout',
  'setFutureMarkVersion', 'sessionActivityRef', 'futureMarksRef', 'clientNow',
  'chatWindowMsFromTimeline', 'chainTimelineRef', 'receiptAdmissionRef', 'relayChannelRef',
  'connectionOwnerRef', 'connectionIdentityRef', 'connectionStatusRef', 'wsRef', 'connectRef',
  'blockNum', 'groupId', 'uid', 'WebSocket', 'sessionEnded', effect);
let cleanup;
runEffect((callback) => { cleanup = callback(); },
  (callback, ms) => { tick = callback; intervalMs = ms; return 700 + ++intervals; },
  (id) => cleared.push(id), () => { throw Error('one-shot maturity timer'); },
  () => { versionBumps++; }, mounted, { current: markSet }, () => sweepClock.now,
  () => ({ endMs: windowEnd }), { current: null },
  { current: { forgetFutureDigests: (digests) => forgottenDigests.push([...digests]) } },
  { current: { refetchMarkedIds: (...args) => { refetches++; refetchArgs.push(args); } } },
  ownerRef, identityRef, statusRef, socketRef, { current: () => { reconnects++; } },
  3, 2, 'V', { OPEN: 1 }, false);
assert.equal(intervals, 1, 'MATURE18: 見回りは1本');
assert.equal(intervalMs, 60000, 'MATURE18: 成熟の見回りは60秒ごと');
markSet.discard('chat', { ...chat, text: 'first', timestamp: sweepClock.now + 120_001 },
  { eventId: 'first-id' });
const firstReceipt = { receiverUid: 'H', senderUid: 'A', msgRefs: [ref],
  timestamp: sweepClock.now + 120_001, signature: sig };
markSet.discard('receipt', firstReceipt, { eventId: 'first-receipt-id' });
const laterReceipt = { receiverUid: 'H', senderUid: 'A', msgRefs: [ref],
  timestamp: sweepClock.now + 720_001, signature: sig };
markSet.discard('receipt', laterReceipt);
for (let i = 1; i < 10; i++) markSet.discard('receipt',
  { ...laterReceipt, timestamp: laterReceipt.timestamp + i });
assert(versionBumps >= 1, 'MATURE18: 印の件数の表示を更新する');
assert.equal(intervals, 1, 'MATURE18: 印の追加では見回りを張り直さない');
sweepClock.now++;
tick();
assert.equal(refetches, 1, 'MATURE18: 成熟分を次の見回りで取り寄せる');
assert.equal(refetchArgs[0].length, 1, 'MATURE18: 公式は ids の1引数だけを渡す');
assert.equal(markSet.has('receipt', laterReceipt), true,
  'M18b: 公式は10分後に成熟する印を1回目に外さない');
assert.deepEqual(forgottenDigests, [[receiptIdentityDigest(firstReceipt)]],
  'M18b: 公式は外した受領証明の digest を forgetFutureDigests へ渡す');
assert.deepEqual([...refetchArgs[0][0]].sort(), ['first-id', 'first-receipt-id'].sort(),
  'M18b: 公式は外した eventIds を refetchMarkedIds へ渡す');
assert.equal(reconnects, 1);
for (let i = 0; i < 1200; i++) tick();
assert.equal(refetches, 1, 'MATURE18: 同じ印を二度取り寄せない');
assert.equal(reconnects, 1);
const stormStart = sweepClock.now;
const requestsBeforeStorm = refetches;
const reconnectsBeforeStorm = reconnects;
for (let i = 0; i < 1200; i++) markSet.discard('chat',
  { ...chat, text: `storm-${i}`, timestamp: stormStart + 120_001 + i * 1000 },
  { eventId: `storm-id-${i}` });
const otherMark = { ...chat, uid: 'H', text: 'other-sender', timestamp: stormStart + 1_319_001 };
markSet.discard('chat', otherMark, { eventId: 'other-id' });
assert(markSet.has('chat', otherMark), 'MATURE18: 一人の1200印は他人を押し出さない');
assert.equal(intervals, 1);
let sweeps = 0;
for (let at = stormStart + 60000; at <= stormStart + 1_260_000; at += 60000) {
  sweepClock.now = at; tick(); sweeps++;
}
assert(refetches - requestsBeforeStorm <= sweeps && reconnects - reconnectsBeforeStorm <= sweeps,
  'MATURE18: 要求と張り直しは見回りごと各1回まで');
assert.equal(markSet.countsByType().chat, 0, 'MATURE18: 1200印と他人の印をすべて外す');
windowEnd = sweepClock.now + 120000;
const priorRequests = refetches;
const priorReconnects = reconnects;
markSet.discard('chat', { ...chat, text: 'outside', timestamp: sweepClock.now + 120001 },
  { eventId: 'outside-id' });
sweepClock.now += 60000;
tick();
assert.equal(markSet.countsByType().chat, 0);
assert.equal(refetches, priorRequests, 'MATURE18: 窓の後の印は取り寄せない');
assert.equal(reconnects, priorReconnects, 'MATURE18: 窓の後の印では張り直さない');
windowEnd = Infinity;
markSet.discard('chat', { ...chat, text: 'ended', timestamp: sweepClock.now + 120001 },
  { eventId: 'ended-id' });
sweepClock.now += 60000;
mounted.current.ended = true;
tick();
assert.equal(refetches, priorRequests, 'MATURE18: 終わった画面は取り寄せない');
assert(cleared.includes(701), 'MATURE18: 終わった画面で見回りを止める');
const clearsBeforeCleanup = cleared.length;
cleanup?.();
assert.deepEqual(cleared.slice(clearsBeforeCleanup), [701], 'MATURE18: cleanup で見回りを止める');
assert.equal(markSet.onChange, null, 'MATURE18: cleanup で onChange を外す');
// Each failed WS gate still permits the relay request, but never reconnects.
for (const gate of ['intentional', 'owner', 'spectator', 'status', 'socket']) {
  const localClock = { now };
  const localMarks = new FutureAdmissionMarks({ blockNum: 3, groupId: 2, now: () => localClock.now });
  const localOwner = { current: gate === 'owner' ? null : { intentional: gate === 'intentional' } };
  const localIdentity = { current: { isSpectator: gate === 'spectator' } };
  const localStatus = { current: gate === 'status' ? 'connecting' : 'connected' };
  const localSocket = { current: { readyState: gate === 'socket' ? 0 : 1 } };
  let localTick;
  let localRequests = 0;
  let localReconnects = 0;
  let localCleanup;
  runEffect((callback) => { localCleanup = callback(); },
    (callback) => { localTick = callback; return 900; }, () => {},
    () => { throw Error('one-shot maturity timer'); }, () => {},
    { current: { ended: false } }, { current: localMarks }, () => localClock.now,
    () => ({ endMs: Infinity }), { current: null },
    { current: { forgetFutureDigests: () => {} } },
    { current: { refetchMarkedIds: (...args) => { assert.equal(args.length, 1); localRequests++; } } },
    localOwner, localIdentity, localStatus, localSocket,
    { current: () => { localReconnects++; } }, 3, 2, 'V', { OPEN: 1 }, false);
  localMarks.discard('chat', { ...chat, text: gate, timestamp: localClock.now + 120001 },
    { eventId: `gate-${gate}` });
  localClock.now++;
  localTick();
  assert.equal(localRequests, 1);
  assert.equal(localReconnects, 0,
    'MATURE18: 意図した切断・観戦・接続中でない WS を見回りで張り直さない');
  localCleanup?.();
}

// 未来の件数行は会話数の12分の確定を撤去した後も残る。
const t = 1_750_000_000_000;
const conversations = [
  { uid: 'A', text: 'one', timestamp: t, signature: sig },
  { uid: 'B', text: 'separator', timestamp: t + 1, signature: sig },
  { uid: 'A', text: 'two', timestamp: t + 2, signature: sig },
];
const viewerRead = { receiverUid: 'A', senderUid: 'B', msgRefs: [msgRefOf(computeMsgKeyV2(3, 2, conversations[1]))],
  timestamp: t + 120000, signature: sig };
const countMarks = new Marks({ blockNum: 3, groupId: 2, now: () => t });
countMarks.discard('chat', { ...conversations[1], timestamp: t + 120001 });
countMarks.discard('action', { actionType: 'vote', uid: 'B', encrypted: 'cipher',
  timestamp: t + 120001, signature: sig });
countMarks.discard('receipt', { ...viewerRead, timestamp: t + 120001 });
assert.deepEqual(countMarks.countsByType(), { chat: 1, action: 1 },
  '未来の発言と投票・密告だけを数える');
countMarks.releaseMatured(t + 1);
assert.deepEqual(countMarks.countsByType(), { chat: 0, action: 0 },
  '成熟して印が外れたら上部の0件表示を消す');
// RT5a-mat-01 の P2 退出直後と P1 締切前: 隠れた9件を取り戻すと
// 上限の後ろの区切りが落ち、画面と採点の V の会話数が同じになる。
for (const { board, before, after, trimmed } of [
  { board: 'p2_leave_after_twenty', before: 20, after: 19, trimmed: 1 },
  { board: 'p1_endwindow_residual', before: 21, after: 18, trimmed: 3 },
]) {
  const late = [];
  for (let index = 0; index < before; index++) {
    late.push({ uid: 'V', text: `${board}-reply-${index}`, timestamp: t + index * 2000,
      signature: sig });
    if (index < before - 1) late.push({ uid: 'A', text: `${board}-late-${index}`,
      timestamp: t + index * 2000 + 1000, signature: sig });
  }
  const boardClock = { now: t };
  const boardMarks = new Marks({ blockNum: 3, groupId: 2, now: () => boardClock.now });
  const hidden = Array.from({ length: 9 }, (_, index) => ({ uid: 'A',
    text: `${board}-hidden-${index}`, timestamp: t + 120001 + index,
    signature: sig }));
  hidden.forEach((item, index) => boardMarks.discard('chat', item,
    { eventId: `${board}-hidden-id-${index}` }));
  assert.equal(countMessageTurns(filterVisibleMessages(late)).V, before, `${board}: 成熟前の V 画面`);
  boardClock.now = t + 10;
  const released = boardMarks.releaseMatured();
  assert.equal(released.eventIds.size, 9, `${board}: 最早成熟から9件の ids を取り寄せる`);
  const afterMaturity = [...hidden, ...late.filter((message) =>
    message.uid === 'V' || Number(message.text.split('-').at(-1)) < before - 1 - trimmed)];
  assert.equal(countMessageTurns(filterVisibleMessages(afterMaturity)).V, after,
    `${board}: 取り寄せ後の V 画面は採点の会話数と一致`);

}
console.log('t5a-maturity-unit: all checks passed');

}

// T5d: source overrides run the same teeth against before/ copies without changing the tree.
{
const requested = process.argv.find((arg) => arg.startsWith('--t5d-case='))?.slice(11);
const run = (name) => !requested || requested === name;
const readSource = (env, path) => readFileSync(process.env[env] || new URL(path, import.meta.url), 'utf8');
const hook = readSource('T5D_HOOK_SOURCE', '../../src/hooks/useGameWebSocket.js');
let relaySource = readSource('T5D_RELAY_SOURCE', '../../src/utils/relay.js');
const recoverySource = readSource('T5D_RECOVERY_SOURCE', '../src/recovery/relay-client.js');
const page = readSource('T5D_PAGE_SOURCE', '../../src/pages/game.js');
const phase = readSource('T5D_PHASE_SOURCE', '../../src/components/game/ChatPhase.js');
const app = readSource('T5D_APP_SOURCE', '../src/recovery/app.js');
const t5dMutation = process.argv.find((arg) => arg.startsWith('--mutation=t5d-'))?.slice(11);
const baseTime = 1_750_000_000_000;
const t5dChat = { uid: 'A', text: 'mature', timestamp: baseTime + 120_001, signature };
const t5dRef = msgRefOf(computeMsgKeyV2(3, 2, t5dChat));
const makeTimers = () => {
  let at = baseTime;
  let serial = 0;
  const jobs = new Map();
  const set = (callback, delay) => {
    const id = ++serial;
    jobs.set(id, { at: at + delay, callback });
    return id;
  };
  const clear = (id) => jobs.delete(id);
  const advance = (target) => {
    for (;;) {
      const first = [...jobs].sort((a, b) => a[1].at - b[1].at)[0];
      if (!first || first[1].at > target) break;
      jobs.delete(first[0]);
      at = first[1].at;
      first[1].callback();
    }
    at = target;
  };
  return { set, clear, advance, now: () => at, mono: { now: () => at - baseTime }, jobs };
};
const futureRead = (index) => ({ receiverUid: 'H', senderUid: 'A',
  msgRefs: [t5dRef], timestamp: baseTime + 3_600_000 + index, signature });

if (run('maturity-official')) {
  const timers = makeTimers();
  const start = hook.indexOf('  // 未来印は中身を持たない。');
  const end = hook.indexOf('  }, [blockNum, groupId, uid, sessionEnded]);', start);
  assert(start >= 0 && end > start);
  const body = hook.slice(start, end + '  }, [blockNum, groupId, uid, sessionEnded]);'.length);
  assert(!/setTimeout\(/.test(body) && !body.includes('maturitySchedulerRef'),
    'MATURE18: 公式の成熟の見回りに精密なタイマーを残さない');
  const made = [];
  const repeat = (callback, delay) => {
    let id;
    const fire = () => {
      timers.jobs.set(id, { at: timers.now() + delay, callback: fire });
      callback();
    };
    id = timers.set(fire, delay);
    made.push(id);
    return id;
  };
  const marks = new FutureAdmissionMarks({ blockNum: 3, groupId: 2, now: timers.now });
  let requests = 0;
  const requestedIds = [];
  const forgotten = [];
  let cleanup;
  new Function('useEffect', 'setInterval', 'clearInterval', 'setTimeout', 'setFutureMarkVersion',
    'sessionActivityRef', 'futureMarksRef', 'clientNow', 'chatWindowMsFromTimeline', 'chainTimelineRef',
    'receiptAdmissionRef', 'relayChannelRef', 'connectionOwnerRef', 'connectionIdentityRef',
    'connectionStatusRef', 'wsRef', 'connectRef', 'blockNum', 'groupId', 'uid', 'WebSocket', 'sessionEnded', body)(
      (callback) => { cleanup = callback(); }, repeat, timers.clear,
      () => { throw Error('one-shot maturity timer'); }, () => {},
      { current: { ended: false } }, { current: marks }, timers.now,
      () => ({ endMs: Infinity }), { current: null },
      { current: { forgetFutureDigests: (digests) => forgotten.push([...digests]) } },
      { current: { refetchMarkedIds: (...args) => {
        assert.equal(args.length, 1); requests++; requestedIds.push([...args[0]]);
      } } },
      { current: { intentional: false } }, { current: { isSpectator: false } },
      { current: 'connected' }, { current: { readyState: 1 } }, { current: () => {} },
      3, 2, 'V', { OPEN: 1 }, false);
  assert.equal(made.length, 1, 'MATURE18: 見回りは effect ごとに1本');
  marks.discard('chat', t5dChat, { eventId: 'starve-chat' });
  const maturedRead = { receiverUid: 'H', senderUid: 'A', msgRefs: [t5dRef],
    timestamp: baseTime + 120_001, signature };
  marks.discard('receipt', maturedRead, { eventId: 'starve-receipt' });
  const laterRead = { ...maturedRead, timestamp: baseTime + 720_001 };
  marks.discard('receipt', laterRead);
  for (let index = 1; index <= 10; index++) {
    timers.advance(baseTime + index * 990);
    marks.discard('receipt', futureRead(index));
  }
  assert.equal(requests, 0, 'MATURE18: 成熟から次の見回りまで取り寄せない');
  assert.equal(made.length, 1, 'MATURE18: 印の追加で見回りを張り直さない');
  timers.advance(baseTime + 60000);
  assert.equal(requests, 1, 'MATURE18: 次の60秒の見回りで取り寄せる');
  assert.equal(marks.has('receipt', laterRead), true,
    'M18b: T5d 公式は10分後に成熟する印を残す');
  assert.deepEqual(forgotten, [[receiptIdentityDigest(maturedRead)]],
    'M18b: T5d 公式は外した受領証明の digest を forgetFutureDigests へ渡す');
  assert.deepEqual(requestedIds, [['starve-chat', 'starve-receipt']],
    'M18b: T5d 公式は外した eventIds を要求する');
  timers.advance(baseTime + 600000);
  assert.equal(requests, 1, 'MATURE18: 同じ印を再処理しない');
  cleanup?.();
  assert.equal(timers.jobs.size, 0, 'MATURE18: cleanup で見回りを止める');
  console.log('t5d-maturity-official: passed');
}

if (run('maturity-recovery')) {
  const m18 = process.argv.find((arg) => arg.startsWith('--mutation=m18-'))?.slice(11);
  let source = recoverySource;
  const mutations = {
    'm18-recovery-oneshot': ['setInterval(() => this.refetchMatured(), 60000)',
      'setTimeout(() => this.refetchMatured(), 60000)'],
    'm18-recovery-rearm-on-change': ['this.futureMarkVersion = (this.futureMarkVersion || 0) + 1;\n',
      'this.futureMarkVersion = (this.futureMarkVersion || 0) + 1;\n        this.restartMaturityTimer();\n'],
    'm18-recovery-ignore-window': ['    if (released.inWindow) this.channel?.refetchMarkedIds(released.eventIds);',
      '    this.channel?.refetchMarkedIds(released.eventIds);'],
    'm18-recovery-restart-no-clear': ['    if (this._maturityTimer) clearInterval(this._maturityTimer);\n', ''],
  };
  if (mutations[m18]) {
    mutationAnchor(source, mutations[m18][0], m18);
    source = source.replace(mutations[m18][0], mutations[m18][1]);
  }
  for (const oldName of ['flushMaturedRelay', '_maturityDueAt', '_maturedRelayTimer',
    '_pendingMaturedIds', '_pendingMaturedIssuers', '_lastMaturedRelayAt']) {
    assert(!source.includes(oldName), 'MATURE18: 復元の精密なタイマーの部品を残さない');
  }
  assert(source.includes('setInterval(() => this.refetchMatured(), 60000)'),
    'MATURE18: 復元の見回りは繰り返す60秒の interval');
  const ctorStart = source.indexOf('groupId: this.groupId, now, correction, onChange: () => {');
  const ctorEnd = source.indexOf('} });', ctorStart);
  assert(ctorStart >= 0 && ctorEnd > ctorStart
    && !source.slice(ctorStart, ctorEnd).includes('restartMaturityTimer'),
  'MATURE18: 復元の印の追加で見回りを張り直さない');
  assert.equal(source.split('this.restartMaturityTimer()').length - 1, 1,
    'M18b: 復元の見回りを起こす口は1か所だけ');
  const listenerStart = app.indexOf('recoveryClock.subscribeClockCorrection((change) => {');
  const listenerEnd = app.indexOf('\n});', listenerStart);
  assert(listenerStart >= 0 && listenerEnd > listenerStart
    && !app.slice(listenerStart, listenerEnd).includes('restartMaturityTimer'),
  'MATURE18: 復元の補正で見回りを張り直さない');
  const firstAt = source.indexOf('  refetchMatured() {');
  const lastAt = source.indexOf('  restartMaturityTimer() {', firstAt);
  const endAt = source.indexOf('\n}\n\n// リレー設定', lastAt);
  assert(firstAt >= 0 && lastAt > firstAt && endAt > lastAt);
  const methods = source.slice(firstAt, endAt).replace('\n  restartMaturityTimer() {',
    ',\n  restartMaturityTimer() {');
  for (const scenario of ['starve', 'empty', 'after-window']) {
    const timers = makeTimers();
    const repeat = (callback, delay) => {
      let id;
      const fire = () => { timers.jobs.set(id, { at: timers.now() + delay, callback: fire }); callback(); };
      id = timers.set(fire, delay);
      return id;
    };
    const marks = new FutureAdmissionMarks({ blockNum: 3, groupId: 2, now: timers.now });
    let requests = 0;
    const requestedIds = [];
    const functions = new Function('setInterval', 'clearInterval', 'setTimeout',
      `return ({${methods}});`)(repeat, timers.clear,
      () => { throw Error('one-shot maturity timer'); });
    const client = { ...functions, futureMarks: marks, now: timers.now,
      getChatWindow: () => ({ endMs: scenario === 'after-window' ? baseTime + 120000 : Infinity }),
      channel: { refetchMarkedIds: (...args) => {
        assert.equal(args.length, 1); requests++; requestedIds.push([...args[0]]);
      } },
      _maturityTimer: null };
    client.restartMaturityTimer();
    client.restartMaturityTimer();
    assert.equal(timers.jobs.size, 1, 'MATURE18: 復元の見回りを起こし直しても1本');
    marks.discard('chat', { ...t5dChat, timestamp: baseTime + (scenario === 'empty' ? 600000 : 120001) },
      { eventId: scenario });
    if (scenario === 'starve') {
      marks.discard('receipt', { receiverUid: 'H', senderUid: 'A', msgRefs: [t5dRef],
        timestamp: baseTime + 120_001, signature }, { eventId: 'recovery-receipt' });
      const laterRead = { receiverUid: 'H', senderUid: 'A', msgRefs: [t5dRef],
        timestamp: baseTime + 720_001, signature };
      marks.discard('receipt', laterRead);
      for (let i = 1; i <= 10; i++) {
        timers.advance(baseTime + i * 990);
        marks.discard('receipt', futureRead(i));
      }
      assert.equal(requests, 0);
      timers.advance(baseTime + 60000);
      assert.equal(requests, 1, 'MATURE18: 復元も60秒の見回りで取り寄せる');
      assert.deepEqual(requestedIds, [['starve', 'recovery-receipt']],
        'M18b: 復元は外した eventIds を要求する');
      assert.equal(marks.has('receipt', laterRead), true,
        'M18b: 復元は10分後に成熟する印を残す');
    } else if (scenario === 'empty') {
      timers.advance(baseTime + 420000);
      assert.equal(requests, 0, 'MATURE18: 成熟前の空振り');
      timers.advance(baseTime + 480000);
      assert.equal(requests, 1, 'MATURE18: 空振りの後も見回りを失わない');
    } else {
      timers.advance(baseTime + 60000);
      assert.equal(marks.countsByType().chat, 0);
      assert.equal(requests, 0, 'MATURE18: 復元も窓の後の印は外すだけで取り寄せない');
    }
    assert.equal(timers.jobs.size, 1, 'MATURE18: 復元の見回りは続く');
    for (const id of timers.jobs.keys()) timers.clear(id);
  }
  // app.js は名簿確認後に verifyStoredReceipts を await してから P2P を選ぶ。
  const verifiedAt = app.indexOf('await state.relay.verifyStoredReceipts();');
  const noP2PAt = app.indexOf('if (!canStartRecoveryP2P(myMember)) {', verifiedAt);
  const p2pElseAt = app.indexOf('} else {', noP2PAt);
  assert(verifiedAt >= 0 && noP2PAt > verifiedAt && p2pElseAt > noP2PAt
    && !app.slice(noP2PAt, p2pElseAt).includes('state.relay.start()'),
  'M18b: 名簿確認後に P2P なしでも verifyStoredReceipts を通る');
  const previousWebSocket = globalThis.WebSocket;
  const previousSetInterval = globalThis.setInterval;
  const previousClearInterval = globalThis.clearInterval;
  class FakeRecoveryWebSocket {
    constructor(url) { this.url = url; this.readyState = 0; }
    addEventListener() {}
    send() {}
    close() { this.readyState = 3; }
  }
  FakeRecoveryWebSocket.OPEN = 1;
  FakeRecoveryWebSocket.CONNECTING = 0;
  globalThis.WebSocket = FakeRecoveryWebSocket;
  const activeIntervals = new Map();
  let intervalSerial = 0;
  globalThis.setInterval = (callback, ms) => {
    const id = ++intervalSerial;
    activeIntervals.set(id, { callback, ms });
    return id;
  };
  globalThis.clearInterval = (id) => activeIntervals.delete(id);
  try {
    const clock = { now: baseTime };
    const m18bCase = process.argv.find((arg) => arg.startsWith('--m18b-case='))?.slice(12);
    const makeRelay = (onActionsChange = null) => new RecoveryRelay({ signKey: `0x${'22'.repeat(32)}`,
      blockNum: 3, groupId: 2, uid: 'V', members: [], now: () => clock.now,
      getChatWindow: () => ({ endMs: Infinity }), onActionsChange });
    if (!m18bCase || m18bCase === 'no-p2p') {
      const noP2P = makeRelay();
      await noP2P.verifyStoredReceipts();
      assert.equal(activeIntervals.size, 1,
        'M18b: P2P なしでも名簿確認後の成熟見回りは1本');
      await noP2P.verifyStoredReceipts();
      assert.equal(activeIntervals.size, 1,
        'M18b: 保存済み受領証明を再検証しても見回りは2本にならない');
      const honestBefore = JSON.stringify({ messages: noP2P.getMessages(),
        receipts: noP2P.getReceipts(), actions: noP2P.getRelayActionsRaw() });
      for (const { callback } of activeIntervals.values()) callback();
      assert.equal(JSON.stringify({ messages: noP2P.getMessages(),
        receipts: noP2P.getReceipts(), actions: noP2P.getRelayActionsRaw() }), honestBefore,
      'M18b: 未来印のない盤面の取り込み・束の材料は同じバイト列');
      noP2P.futureMarks.discard('chat', { ...t5dChat, timestamp: clock.now + 120_001 },
        { eventId: 'no-p2p' });
      clock.now += 1;
      for (const { callback } of activeIntervals.values()) callback();
      assert.equal(noP2P.futureMarks.countsByType().chat, 0,
        'M18b: P2P なしでも成熟した未来印を外す');
      assert.equal(noP2P.channel, null, 'M18b: P2P なしではチャネル要求をしない');
      noP2P.stop();
      assert.equal(activeIntervals.size, 0, 'M18b: P2P なしの見回りも stop で止まる');
    }

    if (!m18bCase || m18bCase === 'start-throw') {
      let throws = 0;
      const failingCallback = makeRelay(() => {
        if (throws++ === 0) throw Error('render broke once');
      });
      await failingCallback.verifyStoredReceipts();
      await assert.rejects(failingCallback.start(), /render broke once/);
      assert.equal(throws, 1, 'M18b: start の callback が1回例外を投げる');
      assert(failingCallback.channel, 'M18b: 例外後もチャネルはある');
      assert.deepEqual([...activeIntervals.values()].map(({ ms }) => ms), [60000],
        'M18b: start の callback 例外後も60秒の interval が1本ある');
      failingCallback.stop();
      assert.equal(activeIntervals.size, 0, 'M18b: callback 例外後も stop で見回りを止める');
    }
  } finally {
    globalThis.WebSocket = previousWebSocket;
    globalThis.setInterval = previousSetInterval;
    globalThis.clearInterval = previousClearInterval;
  }
  const verifyEnd = source.indexOf('\n  // 検証済み受領証明の唯一の取り込み口', source.indexOf('  async verifyStoredReceipts() {'));
  assert(verifyEnd > 0 && source.slice(source.indexOf('  async verifyStoredReceipts() {'), verifyEnd)
    .includes('this.restartMaturityTimer();'),
  'M18b: 見回りは検証済み受領証明の処理の末尾で起こす');
  assert(!source.slice(source.indexOf('  async start() {'), source.indexOf('  async verifyRestoredReports() {'))
    .includes('this.restartMaturityTimer();'),
  'M18b: start の callback の後で見回りを起こさない');
  assert(!source.slice(lastAt, endAt).includes('if (!this.channel) return;'),
  'M18b: チャネルがなくても成熟の見回りを張る');
  console.log('t5d-maturity-recovery: passed');
}

if (run('turn-banner')) {
  const banner = phase.indexOf('(futureMarkCounts.chat > 0 || futureMarkCounts.action > 0)');
  const box = phase.indexOf('<div className={styles.chatMessages} ref={chatMessagesRef}>');
  assert(banner >= 0 && box >= 0 && banner < box, '公式の件数行はスクロール箱の外');
  assert(phase.includes("className={styles.chatMessagesWrap} style={{ flexDirection: 'column' }}"),
    '公式の兄弟要素は上下に並ぶ');
  const wrap = t5bBetween(app, 'function renderChatSection(', '\nfunction renderActionPanel(');
  assert(wrap.indexOf('renderFutureCountRows()') < wrap.indexOf('msgsWrap.append(msgsBox)'),
    '復元の件数行は msgsBox の前');
  assert(wrap.includes("className: 'chatMessagesWrap', style: 'flex-direction:column;'"),
    '復元の兄弟要素は上下に並ぶ');
  console.log('t5d-turn-banner: passed');
}

if (run('turn-filter')) {
  const board = [
    { uid: 'Y', text: 'y1', timestamp: baseTime - 100000, signature },
    { uid: 'Z', text: 'z1', timestamp: baseTime - 90000, signature },
    { uid: 'Y', text: 'y2', timestamp: baseTime - 80000, signature },
    { uid: 'Z', text: 'z2', timestamp: baseTime + 60000, signature },
    { uid: 'Y', text: 'y3', timestamp: baseTime + 90000, signature },
  ];
  const readers = Object.fromEntries(board.map((message) => [
    msgRefOf(computeMsgKeyV2(3, 2, message)), new Set(['R'])]));
  const state = { blockNum: 3, groupId: 2, uid: 'Y' };
  for (const name of ['renderMemberList', 'myReceiptedChatProgress']) {
    const section = name === 'renderMemberList'
      ? t5bBetween(app, 'function renderMemberList(', '\nfunction renderChatLog(')
      : t5bBetween(app, 'function myReceiptedChatProgress(', '\nlet screenPlanMemo');
    const begin = section.indexOf('const receiptedMsgs = locallyProvableMessages(msgs).filter((m) => {');
    const finish = section.indexOf('\n  });', begin);
    assert(begin >= 0 && finish > begin);
    const expression = section.slice(begin, finish + '\n  });'.length);
    const selected = new Function('msgs', 'readers', 'state', 'msgRefOf', 'computeMsgKeyV2',
      'isTimestampVisible', 'displayNow', 'now', 'locallyProvableMessages',
      `${expression}\nreturn receiptedMsgs;`)(board, readers, state, msgRefOf, computeMsgKeyV2,
        (timestamp, clock) => timestamp < clock, baseTime, baseTime, (msgs) => msgs);
    assert.equal(countMessageTurns(filterVisibleMessages(selected)).Y, 2,
      `${name}: 盤面 H の未来の区切りは表示の会話数に入れない`);
  }
  console.log('t5d-turn-filter: passed');
}

if (run('marked-socket')) {
  const start = relaySource.indexOf('  _handleMessage(msg, url) {');
  const end = relaySource.indexOf('\n  _rememberSeenId(', start);
  assert(start >= 0 && end > start);
  const method = new Function('WebSocket', `return ({${relaySource.slice(start, end)}\n})._handleMessage;`)({ OPEN: 1 });
  for (const frame of ['CLOSED', 'EOSE']) {
    const a = { send() {} }, b = { send() {} };
    let closed = 0;
    const pool = { markedIdRequests: new Map([['p2p-marked-1', {
      ws: a, ids: new Set(['id']), received: new Set(), owners: new Map([['id', 'Y']]) }]]),
    sockets: new Map([['a', a], ['b', b]]), historyPages: new Map(),
    onMarkedRequestClosed: () => { closed++; } };
    const msg = { data: JSON.stringify([frame, 'p2p-marked-1']) };
    method.call(pool, msg, 'b');
    assert.equal(pool.markedIdRequests.size, 1, `${frame}: 別ソケットは要求を閉じない`);
    assert.equal(closed, 0, `${frame}: 別ソケットは台帳を変えない`);
    method.call(pool, msg, 'a');
    assert.equal(pool.markedIdRequests.size, 0, `${frame}: 正しいソケットは閉じる`);
    assert.equal(closed, frame === 'CLOSED' ? 1 : 0);
  }
  console.log('t5d-marked-socket: passed');
}
}

import assert from 'node:assert/strict';
import {
  partialReadReceiptAlerts, PartialReadReceiptTracker,
  PARTIAL_READ_RECEIPT_ALERT_THRESHOLD,
  computeMsgKeyV2, msgRefOf, buildMsgKeyGetter, receiptMaxRefsPerReceipt,
  mergeActionReceiptSources,
} from '../../workers/game_workers/lib/protocol-v2.js';
import { coordinateSelfReadReceiptBatch, GameRelayChannel, readReceiptChainTime,
  MAX_RECEIPTS_PER_ISSUER, ReceiptAdmissionQueue, ReceiptClaimMemo } from '../../src/utils/relay.js';
import { normalizeChatCaps, GUEST_PINNED_RULES } from '../../workers/game_workers/lib/char-counter.js';
import { receiptIdentityDigest } from '../../src/utils/relay.js';
import { aggregateSelfReceipts } from '../../workers/game_workers/lib/evidence-compact-v1.js';
import { privateKeyToAccount } from 'viem/accounts';
import { readFileSync } from 'node:fs';
import { t } from '../src/common/i18n.js';

const blockNum = 1, groupId = 2, myUid = 'V';
const clock = { at: 0, timeMs: null, pending: null };
let clockReads = 0;
const timeResults = await Promise.all(Array.from({ length: 1200 }, () =>
  readReceiptChainTime(clock, async () => { clockReads++; return 1000; }, Date.now(), 20)));
assert.equal(clockReads, 1, '1,200件の同時到着がチェーン読み取りを共有する');
assert(timeResults.every(Number.isSafeInteger));
assert.equal(await readReceiptChainTime({ at: 0, timeMs: null, pending: null },
  () => new Promise(() => {}), Date.now(), 20), null, '止まった読み取りは期限で端末時計へ退避できる');
const receipt = (signature, refs) => ({ receiverUid: 'A', senderUid: 'V', signature, msgRefs: refs });
const overlap = [receipt('one', ['a', 'b']), receipt('two', ['b', 'c']),
  receipt('three', ['c', 'd']), receipt('four', ['d', 'e']), receipt('five', ['e', 'f'])];
assert.deepEqual(partialReadReceiptAlerts(overlap.slice(0, 4)), {});
assert.deepEqual(partialReadReceiptAlerts([
  receipt('browser-one', ['a', 'b']), receipt('browser-two', ['b', 'c']),
]), {}, 'one simultaneous tick in two browsers does not alert');
assert.equal(partialReadReceiptAlerts(overlap).A, PARTIAL_READ_RECEIPT_ALERT_THRESHOLD);
const tracker = new PartialReadReceiptTracker();
for (const rc of overlap.slice(0, 4)) assert(tracker.add(rc) <= 4);
assert.equal(tracker.add(overlap[4]), 5);
assert.equal(tracker.add(overlap[4]), 5, 'duplicate delivery does not increase the count');
assert.deepEqual(partialReadReceiptAlerts([receipt('x', ['a', 'b']), receipt('y', ['a', 'b', 'c'])]), {},
  'containment is not a strict partial overlap');
const signer = privateKeyToAccount(`0x${'22'.repeat(32)}`);
const otherSessionReceipt = { receiverUid: 'V', senderUid: 'A',
  msgRefs: [`0x${'11'.repeat(16)}`], timestamp: 10, signature: 'other-session' };
const thisSessionReceipt = { receiverUid: 'V', senderUid: 'A',
  msgRefs: [`0x${'22'.repeat(16)}`], timestamp: 11, signature: 'this-session' };
const aggregate = await aggregateSelfReceipts([otherSessionReceipt, thisSessionReceipt],
  'V', blockNum, groupId, (message) => signer.signMessage({ message }));
assert.equal(aggregate.aggregate.entries.length, 2,
  'another session’s signed read is carried in the self aggregate');
const appSource = readFileSync(new URL('../src/recovery/app.js', import.meta.url), 'utf8');
const mergeStart = appSource.indexOf('function mergeReceipts(list) {');
const mergeEnd = appSource.indexOf('// リレー観測アクションの反映', mergeStart);
assert(mergeStart >= 0 && mergeEnd > mergeStart);
const recoveryState = { uid: 'V', blockNum, groupId, receipts: {},
  cfg: { pins: { chatCaps: GUEST_PINNED_RULES } },
  readReceiptTracker: new PartialReadReceiptTracker(), readReceiptAlerts: {},
  otherSessionReadReceipt: false, ownSessionReadSignatures: new Set(),
  ownSessionSignatures: new Set(), sessionEntryAt: 5, awayIntervals: [], tabEnded: false,
  issuedReadMsgKeys: new Set(), issuedActionHashes: new Set(), receiptSelectionRevision: 0 };
const predicateStart = appSource.indexOf('function isOtherSessionItem(item, ownerUid) {');
const predicateEnd = appSource.indexOf('\nfunction observeOtherSessionItem(', predicateStart);
const isOtherSessionItem = new Function('state', `${appSource.slice(predicateStart, predicateEnd)}\nreturn isOtherSessionItem;`)(recoveryState);
const observeOtherSessionItem = (item, ownerUid) => {
  if (isOtherSessionItem(item, ownerUid)) recoveryState.otherSessionReadReceipt = true;
};
const recoveryClaimMemo = new ReceiptClaimMemo();
const merge = new Function('state', 'receiptIdentityDigest', 'PARTIAL_READ_RECEIPT_ALERT_THRESHOLD',
  'sessionStorage', 'renderGame', 'observeOtherSessionItem', 'clientNow',
  'computeMsgKeyV2', 'msgRefOf', 'mergeActionReceiptSources', 'normalizeChatCaps',
  'receiptMaxRefsPerReceipt', 'currentRecoveryClaimMemo', 'submissionChatWindow',
  'buildMsgKeyGetter', 'scheduleRenderGame', `${appSource.slice(mergeStart, mergeEnd)}\nreturn mergeReceipts;`)(
  recoveryState, receiptIdentityDigest, PARTIAL_READ_RECEIPT_ALERT_THRESHOLD,
  { getItem: () => null }, () => {}, observeOtherSessionItem, () => 50,
  computeMsgKeyV2, msgRefOf, mergeActionReceiptSources, normalizeChatCaps,
  receiptMaxRefsPerReceipt, () => recoveryClaimMemo, () => null,
  buildMsgKeyGetter, () => {});
const signedOther = { ...otherSessionReceipt, signature: await signer.signMessage({ message: 'other' }) };
const signedOwn = { ...thisSessionReceipt, signature: await signer.signMessage({ message: 'own' }) };
recoveryState.ownSessionReadSignatures.add(signedOwn.signature);
recoveryState.ownSessionSignatures.add(signedOwn.signature);
merge([signedOther, signedOwn]);
assert.equal(Object.keys(recoveryState.receipts).length, 2);
assert(recoveryState.otherSessionReadReceipt, 'recovery client warns about another session');
assert(recoveryState.issuedReadMsgKeys.has(`A|${signedOther.msgRefs[0]}`),
  'the other session’s read suppresses duplicate issuance');
const recoveryAggregate = await aggregateSelfReceipts(Object.values(recoveryState.receipts),
  'V', blockNum, groupId, (message) => signer.signMessage({ message }));
assert.equal(recoveryAggregate.aggregate.entries.length, 2);
const gameSource = readFileSync(new URL('../../src/pages/game.js', import.meta.url), 'utf8');
const modalSource = readFileSync(new URL('../../src/components/game/MultiSessionModal.js', import.meta.url), 'utf8');
const hookSource = readFileSync(new URL('../../src/hooks/useGameWebSocket.js', import.meta.url), 'utf8');
for (const source of [gameSource, appSource]) {
  assert.match(source, /invalidReadReceiptTip/, 'the warning has a visible explanation');
}
for (const source of [modalSource, appSource]) {
  assert.match(source, /multipleSessionsWarning/, 'self warning is rendered');
}
assert.match(gameSource, /ws\.readReceiptAlerts\?\.\[member\.uid\]/);
assert.match(hookSource, /onVerifiedReadReceipt: observeVerifiedReadReceipt/);
const warningHook = hookSource.slice(hookSource.indexOf('const observeVerifiedReadReceipt ='),
  hookSource.indexOf('const ingestObservedAction ='));
assert(!warningHook.includes('sendReport('), 'detection only displays a recommendation');
assert(!warningHook.includes('issuedReadMsgKeysRef.current.add'),
  '署名だけ検証され、target_expired・invalid・上限で落ちる既読は発行済みにしない');
const acceptedHook = hookSource.slice(hookSource.indexOf('const ingestReceipt ='),
  hookSource.indexOf('const readSessionKey ='));
assert.match(acceptedHook, /issuedReadMsgKeysRef\.current\.add/,
  '受理後の onAccept だけが自己既読の発行済み印を付ける');
for (const lang of ['ja', 'en']) {
  const locale = JSON.parse(readFileSync(new URL(`../../public/locales/${lang}/game_${lang}.json`, import.meta.url)));
  assert(locale.members.invalidReadReceiptTip && locale.members.multipleSessionsWarning);
}
const exactMultipleSessionsWarning = '複数画面での同時参加が検出されました。複数端末、複数タブでの同時参加が続くと、Botとみなされ他プレイヤーに密告を推奨する警告が出されるので一つの画面で参加するようにしてください。どちらかを選ぶまで、この画面は離席と同じ扱いになり、既読を出しません。';
const japaneseGame = JSON.parse(readFileSync(new URL('../../public/locales/ja/game_ja.json', import.meta.url)));
assert.equal(japaneseGame.members.multipleSessionsWarning, exactMultipleSessionsWarning);
assert.equal(t('ja')('recovery.members.multipleSessionsWarning'), exactMultipleSessionsWarning);

const oldStorage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
const oldNavigator = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
const shared = new Map();
let tail = Promise.resolve();
Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: {
  getItem: (key) => shared.get(key) || null, setItem: (key, value) => shared.set(key, value),
  removeItem: (key) => shared.delete(key),
} });
Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { locks: {
  request: (_key, work) => { const result = tail.then(work); tail = result.catch(() => {}); return result; },
} } });
try {
  let issued = 0;
  const oneTab = () => {
    const known = new Set();
    return coordinateSelfReadReceiptBatch('test-own', async (rc) => {
      for (const ref of rc.msgRefs) known.add(ref);
    }, async () => {
      if (known.has('m')) return [];
      issued++;
      return [receipt(`tab-${issued}`, ['m'])];
    });
  };
  await Promise.all([oneTab(), oneTab()]);
  assert.equal(issued, 1, 'same eight-second tick in two tabs issues only once');
  shared.set('test-backlog', JSON.stringify([receipt('known-own', ['old'])]));
  let releaseBacklog;
  const backlog = new Promise((resolve) => { releaseBacklog = resolve; });
  let advanced = 0;
  await coordinateSelfReadReceiptBatch('test-backlog', async () => backlog,
    async () => { advanced++; return [receipt('new-own', ['new'])]; }, 25);
  releaseBacklog();
  assert.equal(advanced, 1,
    'T1m-5: admission backlog cannot hold self read publication behind the watchdog');
  const fastQueue = new ReceiptAdmissionQueue({ getSelectionContext: () => ({ myUid: 'V' }) });
  fastQueue.work = new Promise(() => {}); // a 30-second older read admission, scaled to the watchdog
  fastQueue._evaluate = async (item) => { item.status = 'eligible'; };
  fastQueue._enforceIssuerCap = () => {};
  fastQueue._scheduleExpiry = () => {};
  const fastOwnAdmission = fastQueue.offer({ receiverUid: 'V', senderUid: 'H',
    msgRefs: [`0x${'33'.repeat(16)}`], timestamp: Date.now(),
    signature: await signer.signMessage({ message: 'own-fast' }) },
    { verified: true, immediateOwnRead: true });
  const fastResult = await Promise.race([fastOwnAdmission,
    new Promise((resolve) => setTimeout(() => resolve('watchdog'), 25))]);
  assert.equal(fastResult, true,
    'T1m-5: newly signed self read admission overtakes the older 30-second backlog');
  let releaseHung;
  const hung = new Promise((resolve) => { releaseHung = resolve; });
  let lateIssued = 0;
  await coordinateSelfReadReceiptBatch('test-hung', async () => {}, async ({ signal }) => {
    await hung;
    if (!signal.aborted) lateIssued++;
    return [];
  }, 25);
  await coordinateSelfReadReceiptBatch('test-hung', async () => {}, async () => {
    lateIssued++;
    return [];
  }, 25);
  releaseHung();
  await Promise.resolve();
  assert.equal(lateIssued, 1, 'a hung issue releases the lease and cannot publish after abort');
  shared.set('test-future_lease', JSON.stringify({ token: 'other', until: Date.now() + 60000 }));
  let futureIssued = false;
  await coordinateSelfReadReceiptBatch('test-future', async () => {}, async () => {
    futureIssued = true;
    return [];
  });
  assert.equal(futureIssued, true, 'an implausibly long lease cannot block another tab');
  const channel = new GameRelayChannel({ signKey: `0x${'31'.repeat(32)}`,
    blockNum: 33, groupId: 1, uid: 'V', members: [] });
  const makeAction = (issuer, index) => ({ receiverUid: issuer,
    actionHash: `0x${'ab'.repeat(32)}`, timestamp: Date.now(),
    signature: `0x${index.toString(16).padStart(128, '0')}1b` });
  for (let i = 0; i < MAX_RECEIPTS_PER_ISSUER + 1; i++) channel._ingestReceipt(makeAction('A', i));
  channel._ingestReceipt(makeAction('B', 900));
  assert.equal(Object.values(channel.relayReceipts).filter((rc) => rc.receiverUid === 'A').length,
    MAX_RECEIPTS_PER_ISSUER, 'one issuer cannot exceed the relay persistence cap');
  assert.equal(Object.values(channel.relayReceipts).filter((rc) => rc.receiverUid === 'B').length,
    1, 'an issuer at cap cannot displace another issuer');
} finally {
  if (oldStorage) Object.defineProperty(globalThis, 'localStorage', oldStorage);
  else delete globalThis.localStorage;
  if (oldNavigator) Object.defineProperty(globalThis, 'navigator', oldNavigator);
  else delete globalThis.navigator;
}
assert.match(hookSource, /queueReceipt\(receipt, \{ verified: true, immediateOwnRead: true, isCurrentOwner: currentOwner \}\)/,
  'T1m-5: the official issuer requests immediate admission for its own signed read');
console.log('T1g receipt: ALL PASSED (partial 4/5, duplicate delivery, immediate own read, two tabs)');

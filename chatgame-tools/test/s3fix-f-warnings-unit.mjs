import assert from 'node:assert/strict';
let warningModule = process.env.W9F_WARNING_SOURCE || new URL('../vendor/src/utils/receipt-warnings.js', import.meta.url).href;
if (process.argv.includes('--mutation=t8-self-row-excluded')) {
  const source = (await import('node:fs')).readFileSync(new URL(warningModule, import.meta.url), 'utf8');
  const original = 'row.senderUid !== uid && ';
  assert.equal(source.split(original).length, 3, 'T8 mutation hits both self-row exclusions');
  const protocolUrl = new URL('../vendor/workers/game_workers/lib/protocol-v2.js', import.meta.url).href;
  const mutated = source.replaceAll(original, '').replace(
    "'../../workers/game_workers/lib/protocol-v2.js'", `'${protocolUrl}'`);
  warningModule = `data:text/javascript,${encodeURIComponent(mutated)}`;
}
const { ReceiptWarnings, ActionReceiptDuplicateWarnings, isCountedActionReceipt, suspiciousReportingUids,
  showReportingRecommendation, soleRemainingReportTarget, stableAttackedIssuerList,
  scheduleReceiptWarningAt, RECEIPT_WARNING_WAIT_MS } = await import(warningModule);
import { FutureAdmissionMarks, ReceiptAdmissionQueue, ReceiptClaimMemo,
  receiptIdentityDigest, verifyLiveSnapshotEntries } from '../vendor/src/utils/relay.js';
import { privateKeyToAccount } from 'viem/accounts';
import { verifyMessage } from 'viem';
import * as protocol from '../vendor/workers/game_workers/lib/protocol-v2.js';
import * as counter from '../vendor/workers/game_workers/lib/char-counter.js';
import i18next from 'i18next';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { t as recoveryT } from '../src/common/i18n.js';
import { encryptReportDeterministic, encryptAction, decryptAction } from '../vendor/src/utils/ecies.js';
import { encryptReportDeterministic as sourceReportEncrypt } from '../../src/utils/ecies.js';
import { RecoveryRelay } from '../src/recovery/relay-client.js';

const read = (issuer, sender, refs, timestamp) => ({ receiverUid: issuer, senderUid: sender,
  msgRefs: refs, timestamp });
const evalAt = (tracker, now, present = new Set(), overflow = new Set()) => tracker.evaluate(now,
  (sender, ref) => present.has(`${sender}|${ref}`), (sender) => overflow.has(sender));
const priorAttack = ['A', 'B'];
assert.equal(showReportingRecommendation('B', {}, 0), true, 'vote gate alone cannot remove advice');
assert.equal(showReportingRecommendation('B', { B: 'void', A: 'receipted' }, 2), true);
assert.equal(showReportingRecommendation('B', { A: 'void', C: 'pending' }, 2), false);
assert.equal(showReportingRecommendation('B', { B: 'pending' }, 1), false);
{
  const warnings = new ActionReceiptDuplicateWarnings('V');
  for (let i = 0; i < 4; i++) assert.equal(warnings.observe({ receiverUid: 'M', actionHash: 'x' }, `d${i}`), false);
  assert.equal(warnings.observe({ receiverUid: 'M', actionHash: 'x' }, 'd4'), true);
  assert.equal(warnings.observe({ receiverUid: 'M', actionHash: 'x' }, 'd4'), false);
  assert.deepEqual(warnings.attackedIssuers(), ['M']);
  const honest = new ActionReceiptDuplicateWarnings('V');
  for (let i = 0; i < 700; i++) honest.observe({ receiverUid: 'H', actionHash: `x${i}` }, `h${i}`);
  assert.equal(honest.observe({ receiverUid: 'H', actionHash: 'overflow' }, 'last'), false);
  assert.equal(honest.issuers.get('H').size, 700);
  assert.deepEqual(honest.attackedIssuers(), []);
}
{
  const key = `0x${'42'.repeat(32)}`;
  const ctx = { blockNum: 7, groupId: 3 };
  const target = '1234567890123456789';
  const fixed = '043bb39978a872af59f2e8ea1280c652fcf4a32797d2fb8ed3692c234d282595fed5110aec8c164d401e638461abc55111017c7082381b8ddccc7614230fa40d889a7b1345db2fa2f4dd6649d9b6281cdab27bbd22566f0a8c92d765b19a9265cc139befb5ded69df8ab0834ec4c43bf2a147145b5afe4f23204a6ef4fe9c8b7eedfd5ff22fda497cbcf566ab79a0863525765864b283812d73644a44e76b118dd50a39d9fb3aeb51bbcd94eb32ec70fcf8e9a51d241deb5cad8bad20ac8a7212523e5917caa293ef0145fa2b7fdf81eca0d351dbb9cb3397a18a74e52bc1ca461';
  assert.equal(encryptReportDeterministic(target, key, ctx), fixed);
  assert.equal(sourceReportEncrypt(target, key, ctx), fixed);
  const dist = readFileSync(new URL('../dist/recovery.bundle.js', import.meta.url), 'utf8');
  const head = '(() => {\n';
  assert(dist.startsWith(head));
  const probe = head + 'globalThis.__detReport = (...a) => encryptReportDeterministic(...a);\n'
    + dist.slice(head.length);
  const vmContext = { console: { log() {}, warn() {}, error() {} }, TextEncoder, TextDecoder,
    crypto: globalThis.crypto, Uint8Array, setTimeout, clearTimeout, setInterval, clearInterval, URL, Buffer };
  vmContext.globalThis = vmContext;
  vmContext.self = vmContext;
  vm.createContext(vmContext);
  try { vm.runInContext(probe, vmContext); } catch { /* DOM is intentionally absent. */ }
  assert.equal(vmContext.__detReport(target, key, ctx), fixed, 'dist emits the pinned envelope');
  assert.equal(encryptReportDeterministic(target, key, ctx), fixed);
  assert.equal(decryptAction(fixed, key).targetUid, target);
  assert.equal(protocol.isCanonicalActionCiphertext(fixed), true);
  assert.equal(fixed.length, 450);
  assert.notEqual(encryptReportDeterministic('other', key, ctx), fixed);
  assert.notEqual(encryptReportDeterministic(target, key, { ...ctx, blockNum: 8 }), fixed);
  assert.notEqual(encryptReportDeterministic(target, key, { ...ctx, groupId: 4 }), fixed);
  for (const invalid of [null, '', 4]) assert.throws(() => encryptReportDeterministic(invalid, key, ctx));
  for (const invalid of [1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => encryptReportDeterministic(target, key, { ...ctx, blockNum: invalid }));
    assert.throws(() => encryptReportDeterministic(target, key, { ...ctx, groupId: invalid }));
  }
  assert.throws(() => encryptReportDeterministic(target, '0xzz', ctx));
  assert.notEqual(encryptAction({ targetUid: target }, key), encryptAction({ targetUid: target }, key),
    'votes remain randomized');
  const one = encryptReportDeterministic('A', key, ctx);
  const two = encryptReportDeterministic('C', key, ctx);
  const three = encryptReportDeterministic('D', key, ctx);
  const reports = (values) => values.map((encrypted) => ({ uid: 'B', encrypted }));
  assert.deepEqual(suspiciousReportingUids({ actions: reports([one, one, two]) }), []);
  assert.deepEqual(suspiciousReportingUids({ actions: reports([one, two, three]) }), ['B']);
  assert.deepEqual(suspiciousReportingUids({ actions: reports([
    ...Array(12).fill(one), two, three]) }), ['B'], 'retries consume no distinct budget');
  assert.deepEqual(suspiciousReportingUids({ actions: reports([one, two, three]),
    receipts: [], chatWindow: null, excludedIssuers: new Set(['B']) }), ['B'],
    'receipts and time do not narrow the warning');
  assert.deepEqual(suspiciousReportingUids({ actions: [
    ...reports([one, two]), ...reports([three]).map((a) => ({ ...a, uid: 'C' }))] }), []);
  const randomResends = [0, 1, 2].map(() => encryptAction({ targetUid: 'A', reason: 'suspected_bot' }, key));
  assert.deepEqual(suspiciousReportingUids({ actions: reports(randomResends) }), ['B'],
    'a random-encryption mutation makes an honest retry board fail');

  // Mixed-board generator: honest two-target retries and positive three-target boards.
  // Each ciphertext comes from the production encryptor; the reference only counts targets.
  const honestCipherByTarget = new Map(['A', 'C', 'D'].map((targetUid) =>
    [targetUid, encryptReportDeterministic(targetUid, key, ctx)]));
  let honestBoards = 0;
  let positiveBoards = 0;
  for (let seed = 1; seed <= 20000; seed++) {
    let x = seed;
    const rnd = () => ((x = (Math.imul(x, 1664525) + 1013904223) >>> 0) / 2 ** 32);
    const targets = seed % 5 === 0 ? ['A', 'C', 'D'] : ['A', 'C'];
    const issued = Array.from({ length: 2 + Math.floor(rnd() * 9) }, () => targets[Math.floor(rnd() * targets.length)]);
    const actions = issued.map((t) => ({ uid: 'B', encrypted: honestCipherByTarget.get(t) }));
    const expected = new Set(issued).size >= 3;
    assert.equal(suspiciousReportingUids({ actions }).includes('B'), expected);
    if (expected) positiveBoards++; else honestBoards++;
  }
  assert.equal(honestBoards + positiveBoards, 20000);
  assert(positiveBoards > 0);
  // Re-encrypt every retry in a smaller MC run, so replacing the production
  // encryptor with random encryptAction makes this honest-board test turn red.
  const directHonestBoards = (encryptor) => {
    let falsePositives = 0;
    for (let seed = 1; seed <= 128; seed++) {
      const targets = seed % 2 ? ['A', 'A', 'A', 'C'] : ['C', 'C', 'A', 'C'];
      const actions = targets.map((targetUid) => ({ uid: 'B', encrypted: encryptor(targetUid) }));
      if (suspiciousReportingUids({ actions }).includes('B')) falsePositives++;
    }
    return falsePositives;
  };
  assert.equal(directHonestBoards((targetUid) => encryptReportDeterministic(targetUid, key, ctx)), 0);
  const randomMutationFalsePositives = directHonestBoards((targetUid) =>
    encryptAction({ targetUid, reason: 'suspected_bot' }, key));
  assert.equal(randomMutationFalsePositives, 128,
    'random-encryption mutation makes every honest retry board fail');
  assert.deepEqual(suspiciousReportingUids({ actions: reports([one, two, three]) }), ['B'],
    'positive three-target reference board');
  console.log(`G3 Monte Carlo: ${honestBoards} negative + ${positiveBoards} positive boards, 0 mismatches; 128 direct honest boards, 0 false positives; random mutation ${randomMutationFalsePositives}/128 false positives`);
}
assert.equal(stableAttackedIssuerList(priorAttack, ['B', 'A']), priorAttack);
assert.deepEqual(stableAttackedIssuerList(priorAttack, ['A', 'C']), ['A', 'C']);
let timerDelay = null;
assert.equal(scheduleReceiptWarningAt(600001, () => {}, {
  now: () => 1, setTimer: (_callback, delay) => { timerDelay = delay; return 7; },
}), 7);
assert.equal(timerDelay, 600000);

{
  const warnings = new ReceiptWarnings('me');
  for (let i = 0; i < 4; i++) {
    assert.equal(warnings.observe(read('A', 'S', ['r'], 100 + i), `sig-${i}`, 0), true);
    assert.deepEqual(evalAt(warnings, 0).duplicateUids, []);
  }
  assert.equal(warnings.observe(read('A', 'S', ['r'], 100), 'sig-0', 0), false);
  warnings.observe(read('A', 'S', ['r'], 104), 'sig-4', 0);
  assert.deepEqual(evalAt(warnings, 0).duplicateUids, ['A']);
  for (let i = 0; i < 5; i++) warnings.observe(read('B', 'S', [`other-${i}`], 100), `b-${i}`, 0);
  warnings.observe(read('me', 'S', ['r'], 100), 'mine', 0);
  assert.deepEqual(evalAt(warnings, 0).duplicateUids, ['A']);
}

{
  const warnings = new ReceiptWarnings('me');
  for (let i = 0; i < 700; i++) warnings.observe(read('A', 'S', [`present-${i}`], 0), `present-${i}`, 0,
    () => true);
  assert.equal(warnings.issuers.get('A').rows.size, 0, 'present targets consume no unresolved rows');
  for (let i = 0; i < 200; i++) warnings.observe(read('A', 'S', [`missing-${i}`], 0), `missing-${i}`, 0);
  assert.deepEqual(evalAt(warnings, RECEIPT_WARNING_WAIT_MS).missingUids, ['A']);
  warnings.observe(read('B', 'S', ['one'], 0), 'B-one', 0);
  assert.equal(warnings.issuers.get('B').rows.size, 1, 'another issuer keeps its own budget');
}

{
  const warnings = new ReceiptWarnings('me');
  for (let i = 0; i < 199; i++) warnings.observe(read('R', 'S', [`missing-${i}`], 0), `r-${i}`, 100);
  assert.deepEqual(evalAt(warnings, 100 + RECEIPT_WARNING_WAIT_MS).missingUids, []);
  warnings.observe(read('R', 'S', ['missing-199'], 0), 'r-199', 100);
  assert.deepEqual(evalAt(warnings, 100 + RECEIPT_WARNING_WAIT_MS - 1).missingUids, []);
  assert.deepEqual(evalAt(warnings, 100 + RECEIPT_WARNING_WAIT_MS).missingUids, ['R']);
  const present = new Set(['S|missing-0']);
  assert.deepEqual(evalAt(warnings, 100 + RECEIPT_WARNING_WAIT_MS, present).missingUids, []);
  assert.equal(warnings.issuers.get('R').rows.size, 199);
  assert.equal(warnings.observe({ ...read('R', 'S', [], 0), actionHash: 'action' }, 'action', 100), false);
  assert.equal(warnings.observe({ receiverUid: 'R', actionHash: 'action' }, 'action-only', 100), false);
}

{
  const warnings = new ReceiptWarnings('me');
  warnings.noteFutureChatRef('S', 'a');
  warnings.observe(read('R', 'S', ['a'], 0), 'all-marked', 0);
  warnings.observe(read('R', 'S', ['a', 'b'], 0), 'partial-marked', 0);
  assert.equal(warnings.issuers.get('R').rows.size, 2);
  const result = evalAt(warnings, RECEIPT_WARNING_WAIT_MS);
  assert.equal(result.missingUids.length, 0);
  // The partial row is still counted. Fill the same issuer to the threshold.
  for (let i = 0; i < 199; i++) warnings.observe(read('R', 'S', [`false-${i}`], 0), `false-${i}`, 0);
  assert.deepEqual(evalAt(warnings, RECEIPT_WARNING_WAIT_MS).missingUids, ['R']);
  assert.deepEqual(evalAt(warnings, RECEIPT_WARNING_WAIT_MS, new Set(), new Set(['S'])).missingUids, []);
  const present = new Set(['S|a']);
  for (let i = 0; i < 199; i++) present.add(`S|false-${i}`);
  assert.deepEqual(evalAt(warnings, RECEIPT_WARNING_WAIT_MS, present).missingUids, []);
}

{
  assert.equal(soleRemainingReportTarget({ members: ['T', 'M', 'V'], selfUid: 'V',
    targetUid: 'T', alreadyReported: new Set(), isEligible: (uid) => uid === 'T' }), 'T');
  assert.equal(soleRemainingReportTarget({ members: ['T', 'M', 'V'], selfUid: 'V',
    targetUid: 'T', alreadyReported: new Set(), isEligible: (uid) => uid !== 'V' }), null);
  assert.equal(soleRemainingReportTarget({ members: ['T', 'M', 'V'], selfUid: 'V',
    targetUid: 'M', alreadyReported: new Set(['T']), isEligible: (uid) => uid !== 'V' }), 'M');
  assert.equal(soleRemainingReportTarget({ members: ['T', 'M', 'V'], selfUid: 'V',
    targetUid: 'T', alreadyReported: new Set(['T']), isEligible: (uid) => uid === 'T' }), 'T',
    'void resend keeps the same button warning');
}

{
  const base = 1_750_000_000_000;
  const signature = await privateKeyToAccount(`0x${'52'.repeat(32)}`).signMessage({ message: 'f' });
  const tracker = new ReceiptWarnings('me');
  const marks = new FutureAdmissionMarks({ blockNum: 1, groupId: 1, now: () => base,
    onDiscardedChatRef: (sender, ref) => tracker.noteFutureChatRef(sender, ref) });
  for (let i = 0; i < 101; i++) marks.discard('chat', {
    uid: 'S', text: `future-${i}`, timestamp: base + 120001 + i, signature,
  });
  assert.equal(marks.chatRefs.get('S').size, 100);
  assert.equal(marks.hasChatRefOverflow('S'), true);
  assert.equal(marks.byIssuer.get('S').size, 101);
  assert.equal(marks.has('chat', { uid: 'S', text: 'future-100',
    timestamp: base + 120101, signature }), true);
  assert.equal(marks.hasChatRefOverflow('T'), false);
  marks.discard('chat', { uid: 'T', text: 'one-future', timestamp: base + 120001, signature });
  marks.releaseEligible(102);
  assert.equal(marks.byIssuer.has('S'), false);
  assert.equal(marks.hasChatRefOverflow('S'), true, 'overflow stays until identity replacement');
  const firstFutureRef = [...tracker.futureChatRefs.get('T')][0];
  for (let i = 0; i < 200; i++) tracker.observe(read('R', 'T', [firstFutureRef], 0), `after-release-${i}`, 0);
  assert.deepEqual(evalAt(tracker, RECEIPT_WARNING_WAIT_MS).missingUids, [],
    'the ref stays excluded until the signed message actually arrives');
  const issuerCap = new FutureAdmissionMarks({ blockNum: 1, groupId: 1, now: () => base });
  for (let i = 0; i < 1200; i++) issuerCap.discard('action', {
    uid: 'U', actionType: 'vote', encrypted: 'x', timestamp: base + 120001 + i, signature,
  });
  issuerCap.discard('chat', { uid: 'U', text: 'over-limit', timestamp: base + 300000, signature });
  assert.equal(issuerCap.hasChatRefOverflow('U'), true, 'the early per-issuer return flags overflow');
  const globalCap = new FutureAdmissionMarks({ blockNum: 1, groupId: 1, now: () => base });
  globalCap.marks = new Map(Array.from({ length: 6000 }, (_, i) => [`old-${i}`, {}]));
  globalCap.discard('chat', { uid: 'V', text: 'over-global', timestamp: base + 300000, signature });
  assert.equal(globalCap.hasChatRefOverflow('V'), true, 'the early global return flags overflow');
  const unverified = new ReceiptWarnings('me');
  const invalidReceipt = { receiverUid: 'R', senderUid: 'S',
    msgRefs: [`0x${'ab'.repeat(16)}`], timestamp: base, signature };
  const queue = new ReceiptAdmissionQueue({ getRosterUids: () => ['R', 'S'],
    verifyReceipt: async () => false, now: () => base,
    onVerifiedReadReceipt: (receipt) => unverified.observe(receipt, receiptIdentityDigest(receipt), 0) });
  await queue.offer(invalidReceipt);
  assert.equal(unverified.issuers.size, 0, 'a failed inner signature never reaches the warning observer');
  queue.dispose();
}

{
  const hook = readFileSync(process.env.W9F_HOOK_SOURCE
    || new URL('../../src/hooks/useGameWebSocket.js', import.meta.url), 'utf8');
  const page = readFileSync(new URL('../../src/pages/game.js', import.meta.url), 'utf8');
  const recovery = readFileSync(new URL('../src/recovery/app.js', import.meta.url), 'utf8');
  const warningSource = readFileSync(new URL('../../src/utils/receipt-warnings.js', import.meta.url), 'utf8');
  const chatPhase = readFileSync(new URL('../../src/components/game/ChatPhase.js', import.meta.url), 'utf8');
  const vendorWarningSource = readFileSync(new URL('../vendor/src/utils/receipt-warnings.js', import.meta.url), 'utf8');
  const translations = readFileSync(new URL('../src/common/i18n.js', import.meta.url), 'utf8');
  const bundle = readFileSync(new URL('../dist/recovery.bundle.js', import.meta.url), 'utf8');
  const loaderBundle = readFileSync(new URL('../dist/loader.bundle.js', import.meta.url), 'utf8');
  const recoveryHtml = readFileSync(new URL('../src/recovery/index.html', import.meta.url), 'utf8');
  const distHtml = readFileSync(new URL('../dist/recovery.html', import.meta.url), 'utf8');
  const oldKey = 'fraudulent' + 'Report';
  const markSource = hook.match(/const markG3Action = useCallback\((\(inner\) => \{[\s\S]*?\n  \}), \[warningIdentity\]\);/);
  assert(markSource);
  const arrivalRef = { current: { identity: '1|2|V', actions: new Map() } };
  const rosterRef = { current: { chainHash: 'C' } };
  const markAction = new Function('g3ObservationsRef', 'warningIdentity', 'verifiedRosterRef',
    `return (${markSource[1]});`)(arrivalRef, '1|2|V', rosterRef);
  const report = (encrypted) => ({ actionType: 'report', uid: 'B', encrypted });
  assert.equal(markAction(report('a')), true);
  assert.equal(markAction(report('a')), false);
  for (let i = 0; i < 9; i++) assert.equal(markAction(report(`other-${i}`)), true);
  assert.equal(markAction(report('overflow')), false);
  assert.equal(arrivalRef.current.actions.get('B').size, 10);
  assert.equal(markAction({ ...report('vote'), actionType: 'vote' }), false);
  rosterRef.current.chainHash = 'C2';
  assert.equal(markAction(report('new')), true, 'a changed confirmed roster resets the observations');
  const countedSource = hook.match(/const verifyCounted = useCallback\((async \(type, inner, \{ relayAction = false \} = \{\}\) => \{[\s\S]*?\n  \}), \[verifyRelayInner, warningIdentity, warningGeneration, markG3Action\]\);/);
  assert(countedSource, 'official signature wrapper remains outside the mirrored verifier');
  let duplicateState = { generation: 1, uids: [] };
  const countingRef = { current: { tracker: new ActionReceiptDuplicateWarnings('V') } };
  const wrapperBindings = {
    verifyRelayInner: async (_type, inner) => inner.valid !== false,
    isCountedActionReceipt,
    g3ObservationsRef: { current: { identity: '1|2|V' } }, warningIdentity: '1|2|V',
    actionDuplicateRef: countingRef, receiptIdentityDigest: (inner) => inner.digest,
    warningGeneration: 1, stableAttackedIssuerList,
    setActionDuplicateState: (updater) => { duplicateState = updater(duplicateState); },
    markG3Action: () => false, setG3Version: () => {}, performance: { now: () => 0 },
  };
  const verifyCounted = new Function(...Object.keys(wrapperBindings),
    `return (${countedSource[1]});`)(...Object.values(wrapperBindings));
  const observed = [];
  countingRef.current.tracker = { observe: (...args) => { observed.push(args); return false; } };
  await verifyCounted('receipt', { receiverUid: 'I', senderUid: 'B', msgRefs: ['ref'],
    actionHash: 'junk', digest: 'read-digest', valid: true });
  assert.deepEqual(observed, [], 'the hook must keep read receipts out of the C-prime observer');
  countingRef.current.tracker = new ActionReceiptDuplicateWarnings('V');
  for (let i = 0; i < 4; i++) await verifyCounted('receipt', {
    receiverUid: 'M', actionHash: 'x', digest: `d${i}`, valid: true });
  assert.deepEqual(duplicateState.uids, []);
  await verifyCounted('receipt', { receiverUid: 'M', actionHash: 'x', digest: 'invalid', valid: false });
  assert.deepEqual(duplicateState.uids, [], 'failed signatures do not count');
  await verifyCounted('receipt', { receiverUid: 'M', actionHash: 'x', digest: 'd4', valid: true });
  assert.deepEqual(duplicateState.uids, ['M'], 'five verified distinct digests count before later queue drops');
  const actionHash = `0x${'ab'.repeat(32)}`;
  const base = 1_750_000_000_000;
  const actionReceipt = (index, timestamp) => {
    const receipt = { receiverUid: 'M', actionHash, timestamp,
      signature: `0x${(index + 1).toString(16).padStart(128, '0')}1b` };
    return { ...receipt, digest: receiptIdentityDigest(receipt) };
  };
  const admissionBoard = async (kind) => {
    countingRef.current.tracker = new ActionReceiptDuplicateWarnings('V');
    duplicateState = { generation: 1, uids: [] };
    const discarded = [];
    const q = new ReceiptAdmissionQueue({ maxPerIssuer: kind === 'cap' ? 1 : 700,
      now: () => base, getRosterUids: () => ['M', 'V'],
      getChatWindow: () => ({ startMs: base - 1000,
        endMs: kind === 'outside' ? base - 1 : base + 300000 }),
      verifyReceipt: (receipt) => verifyCounted('receipt', receipt),
      resolveReceipt: () => kind === 'pending' ? { state: 'pending' }
        : { state: 'covered', facts: [actionHash], priority: 'C' },
      onDiscard: (_receipt, reason) => discarded.push(reason) });
    for (let i = 0; i < 5; i++) await q.offer(actionReceipt(i,
      kind === 'future' ? base + 180000 : base));
    const result = { warned: [...duplicateState.uids], discarded,
      accepted: q.getAcceptedReceipts().length };
    q.dispose();
    return result;
  };
  const capped = await admissionBoard('cap');
  assert.deepEqual(capped.warned, ['M']);
  assert(capped.discarded.includes('issuer_cap'), 'post-verification cap drops still count');
  assert.equal(capped.accepted, 1);
  const future = await admissionBoard('future');
  assert.deepEqual(future.warned, ['M']);
  assert.equal(future.accepted, 0, 'post-verification future drops still count');
  assert.deepEqual((await admissionBoard('pending')).warned, ['M'], 'unresolved targets still count');
  assert.deepEqual((await admissionBoard('outside')).warned, [], 'the window gate adds no verification');
  const g3Start = '    if (g3ObservationsRef.current.identity !== warningIdentity) return;\n    const actions = [];';
  const g3StartAt = hook.indexOf(g3Start);
  const g3EndAt = hook.indexOf('\n  }, [warningIdentity, warningGeneration, g3Version', g3StartAt);
  assert(g3StartAt >= 0 && g3EndAt > g3StartAt, 'extract the official G3 effect');
  let g3Body = hook.slice(g3StartAt, g3EndAt);
  if (process.argv.includes('--mutation=t2-g3-no-hash-check')) {
    const previous = g3Body;
    g3Body = g3Body.replace('const differentRoster = found.length > 0 && g3ObservationsRef.current.rosterHash !== rosterHash;',
      'const differentRoster = false;');
    assert.notEqual(g3Body, previous, 'T2 G3 mutation applies');
  }
  let g3Warning = null;
  const g3Bindings = {
    g3ObservationsRef: { current: { identity: '1|2|V', rosterHash: 'C', actions: new Map([
      ['B', new Set(['one', 'two', 'three'])]]) } },
    verifiedRosterRef: { current: { chainHash: 'C' } },
    warningIdentity: '1|2|V', warningGeneration: 1,
    actionIngestGateOpen: () => false,
    suspiciousReportingUids,
    setG3WarningState: (update) => { g3Warning = update({ generation: 1, uids: [] }).uids; },
    stableAttackedIssuerList,
  };
  new Function(...Object.keys(g3Bindings), g3Body)(...Object.values(g3Bindings));
  assert.deepEqual(g3Warning, [], 'before the confirmed roster gate no member is named');
  g3Bindings.actionIngestGateOpen = () => true;
  new Function(...Object.keys(g3Bindings), g3Body)(...Object.values(g3Bindings));
  assert.deepEqual(g3Warning, ['B'], 'three verified distinct report ciphertexts name B');
  const g3Board = (recordHash, currentHash, count = 3) => {
    const observations = { current: { identity: '1|2|V', actions: new Map() } };
    const currentRoster = { current: { chainHash: recordHash } };
    const mark = new Function('g3ObservationsRef', 'warningIdentity', 'verifiedRosterRef',
      `return (${markSource[1]});`)(observations, '1|2|V', currentRoster);
    const counted = new Function('verifyRelayInner', 'g3ObservationsRef', 'warningIdentity',
      'isCountedActionReceipt', 'markG3Action', 'setG3Version',
      `return (${countedSource[1]});`)(async () => true, observations, '1|2|V',
      isCountedActionReceipt, mark, () => {});
    return { observations, currentRoster, counted, count, currentHash };
  };
  const evaluateG3Board = (board) => {
    board.currentRoster.current.chainHash = board.currentHash;
    let named;
    const bindings = { ...g3Bindings, g3ObservationsRef: board.observations,
      verifiedRosterRef: board.currentRoster, actionIngestGateOpen: () => true,
      setG3WarningState: (update) => { named = update({ generation: 1, uids: [] }).uids; } };
    new Function(...Object.keys(bindings), g3Body)(...Object.values(bindings));
    return named;
  };
  const changed = g3Board('Hp', 'Hc');
  for (const encrypted of ['one', 'two', 'three']) {
    await changed.counted('action', { actionType: 'report', uid: 'B', encrypted }, { relayAction: true });
  }
  assert.deepEqual(evaluateG3Board(changed), [], 'T2: old roster observations cannot name B');
  assert.equal(changed.observations.current.actions.size, 0, 'T2: old roster observations are discarded');
  assert.equal(changed.observations.current.rosterHash, 'Hc', 'T2: new hash becomes the observation anchor');
  for (const [recordHash, currentHash] of [['Hc', 'Hc'], ['Hp', 'Hc']]) {
    const same = g3Board(recordHash, currentHash);
    if (recordHash !== currentHash) same.currentRoster.current.chainHash = currentHash;
    for (const encrypted of ['one', 'two', 'three']) {
      await same.counted('action', { actionType: 'report', uid: 'B', encrypted }, { relayAction: true });
    }
    assert.deepEqual(evaluateG3Board(same), ['B'], 'T2: reports verified under the current hash still name B');
  }
  const two = g3Board('Hp', 'Hc', 2);
  for (const encrypted of ['one', 'two']) {
    await two.counted('action', { actionType: 'report', uid: 'B', encrypted }, { relayAction: true });
  }
  assert.deepEqual(evaluateG3Board(two), [], 'T2: two ciphertexts do not name B');
  assert.equal(two.observations.current.rosterHash, 'Hp', 'T2: hash is not compared before three ciphertexts');
  assert.equal(two.observations.current.actions.get('B').size, 2, 'T2: two observations are retained');
  const relaySource = hook.match(/const verifyRelayInner = useCallback\((async \(type, inner\) => \{[\s\S]*?\n  \}), \[blockNum, groupId, effectiveClientNow, selectCurrentRoster\]\);/);
  assert(relaySource, 'extract the real signature verifier');
  const signer = privateKeyToAccount(`0x${'12'.repeat(32)}`);
  const roster = [{ uid: 'I', bAddr: { address: signer.address } },
    { uid: 'B', bAddr: { address: privateKeyToAccount(`0x${'34'.repeat(32)}`).address } }];
  const verifierBindings = { ...protocol, ...counter, verifyMessage, blockNum: 7, groupId: 3,
    selectCurrentRoster: () => ({ members: roster }) };
  const realVerifier = new Function(...Object.keys(verifierBindings),
    `return (${relaySource[1]});`)(...Object.values(verifierBindings));
  const restoreAnchor = '  useEffect(() => {\n    if (!actionIngestGateOpen()) return;\n    const saved = g3SavedReportsRef.current;';
  const restoreStart = hook.indexOf(restoreAnchor);
  const restoreEnd = hook.indexOf('\n  }, [warningIdentity, verifiedRosterState, chainTimeline, verifyRelayInner, markG3Action]);', restoreStart);
  assert(restoreStart >= 0 && restoreEnd > restoreStart, 'extract G3 saved-observation recheck');
  const restoreSource = hook.slice(restoreStart + '  useEffect('.length, restoreEnd + 4);
  const signedReport = async (secret, target, timestamp) => {
    const encrypted = encryptReportDeterministic(target, `0x${'42'.repeat(32)}`, { blockNum: 7, groupId: 3 });
    const signature = protocol.canonicalizeSignature(await privateKeyToAccount(secret).signMessage({
      message: protocol.actionSignStringV2('report', 7, 3, 'B', encrypted, timestamp),
    }));
    return { actionType: 'report', uid: 'B', encrypted, signature, timestamp };
  };
  const reportSigner = `0x${'34'.repeat(32)}`;
  const restoredRows = [await signedReport(reportSigner, 'A', base),
    await signedReport(reportSigner, 'C', base + 1),
    await signedReport(`0x${'56'.repeat(32)}`, 'X', base + 2),
    await signedReport(reportSigner, 'Y', base - 1)];
  restoredRows.push({ ...(await signedReport(reportSigner, 'D', base + 4)),
    signature: restoredRows[0].signature });
  const savedRef = { current: { identity: '7|3|V', reports: restoredRows } };
  const savedObservationsRef = { current: { identity: '7|3|V', actions: new Map(), rosterHash: 'C' } };
  const savedRosterRef = { current: { chainHash: 'C' } };
  const savedMarker = new Function('g3ObservationsRef', 'warningIdentity', 'verifiedRosterRef',
    `return (${markSource[1]});`)(savedObservationsRef, '7|3|V', savedRosterRef);
  let gateOpen = false;
  const savedBindings = {
    actionIngestGateOpen: () => gateOpen, g3SavedReportsRef: savedRef,
    g3ObservationsRef: savedObservationsRef, verifiedRosterRef: savedRosterRef,
    warningIdentity: '7|3|V', setG3Version: () => {}, runStartMs: () => base,
    warningBaseIdentity: '7|3|V',
    verifyRelayInner: realVerifier, g3SavedVerificationRef: { current: new Map() },
    markG3Action: savedMarker,
  };
  const runRestore = async (source = restoreSource) => {
    const callback = new Function(...Object.keys(savedBindings), `return (${source});`)(...Object.values(savedBindings));
    callback();
    for (let i = 0; i < 8; i++) await new Promise((resolve) => setImmediate(resolve));
  };
  await runRestore();
  assert.equal(savedObservationsRef.current.actions.size, 0, 'provisional roster does not count saved reports');
  gateOpen = true;
  await runRestore();
  assert.equal(savedObservationsRef.current.actions.get('B')?.size, 2,
    'old key and pre-run timestamp cannot complete a saved triple');
  savedObservationsRef.current.actions.clear();
  savedBindings.g3SavedVerificationRef.current.clear();
  const unsafeCache = restoreSource.replace(
    /const key = JSON\.stringify\(\[warningIdentity, rosterHash, inner\.uid,\s*inner\.actionType, inner\.encrypted, inner\.timestamp, inner\.signature\]\);/,
    'const key = `${warningIdentity}|${rosterHash}|${inner.signature}`;');
  assert.notEqual(unsafeCache, restoreSource, 'extract the complete-action cache key');
  await runRestore(unsafeCache);
  assert.equal(savedObservationsRef.current.actions.get('B')?.size, 3,
    'signature-only cache incorrectly accepts an altered ciphertext');
  savedObservationsRef.current.actions.clear();
  savedBindings.g3SavedVerificationRef.current.clear();
  await runRestore();
  assert.equal(savedObservationsRef.current.actions.get('B')?.size, 2);
  savedRef.current.reports.push(await signedReport(reportSigner, 'D', base + 3));
  await runRestore();
  assert.equal(savedObservationsRef.current.actions.get('B')?.size, 3,
    'three valid saved reports appear after the roster gate opens');
  savedObservationsRef.current.actions.clear();
  savedRef.current.reports.pop();
  savedBindings.g3SavedVerificationRef.current.clear();
  await runRestore(restoreSource.replace("valid = await verifyRelayInner('action', inner);", 'valid = true;'));
  const noSignatureRecheckCount = savedObservationsRef.current.actions.get('B')?.size;
  assert.equal(noSignatureRecheckCount, 4,
    'mutation removing saved signature recheck falsely names B');
  savedObservationsRef.current.actions.clear();
  savedBindings.g3SavedVerificationRef.current.clear();
  await runRestore(restoreSource.replace(' || inner.timestamp < cutoff', ''));
  assert.equal(savedObservationsRef.current.actions.get('B')?.size, 3,
    'mutation removing current-run cutoff falsely names B');
  console.log(`G3 saved-observation mutations: baseline 2, no-signature-recheck ${noSignatureRecheckCount}, no-run-cutoff 3`);
  const recoveryObserverStart = recovery.indexOf('function noteG3VerifiedReport(inner) {');
  const recoveryObserverEnd = recovery.indexOf('\nfunction reportWarningName(', recoveryObserverStart);
  assert(recoveryObserverStart >= 0 && recoveryObserverEnd > recoveryObserverStart);
  const recoveryState = { uid: 'I', g3Reports: new Map() };
  const recoveryObserve = new Function('state',
    `return (${recovery.slice(recoveryObserverStart, recoveryObserverEnd)});`)(recoveryState);
  const previousStorage = globalThis.localStorage;
  globalThis.localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
  try {
    const restoredRelay = new RecoveryRelay({ blockNum: 7, groupId: 3, uid: 'I', members: roster,
      signKey: `0x${'12'.repeat(32)}`, sinceSec: base / 1000, onVerifiedAction: recoveryObserve });
    restoredRelay.channel = { relayActions: { B: { reports: restoredRows.map(({ actionType, uid, ...r }) => r) } } };
    await restoredRelay.verifyRestoredReports();
    assert.equal(recoveryState.g3Reports.get('B')?.size, 2,
      'recovery rechecks cached signatures and the current-run cutoff');
    restoredRelay.channel.relayActions.B.reports.push((await signedReport(reportSigner, 'D', base + 3)));
    await restoredRelay.verifyRestoredReports();
    assert.equal(recoveryState.g3Reports.get('B')?.size, 3,
      'recovery restores the third verified target after reopening');
  } finally {
    if (previousStorage === undefined) delete globalThis.localStorage;
    else globalThis.localStorage = previousStorage;
  }
  const signedReads = [];
  for (let i = 0; i < 5; i++) {
    const msgRefs = [`0x${(i + 1).toString(16).padStart(32, '0')}`];
    const timestamp = base + i * 7000;
    const signature = protocol.canonicalizeSignature(await signer.signMessage({ message:
      protocol.readReceiptSignString(7, 3, 'I', 'B', msgRefs, timestamp) }));
    signedReads.push({ receiverUid: 'I', senderUid: 'B', msgRefs, timestamp, signature });
  }
  const makeVerifiedCounter = () => {
    const state = { generation: 1, uids: [] };
    const bindings = { ...wrapperBindings, verifyRelayInner: realVerifier,
      actionDuplicateRef: { current: { tracker: new ActionReceiptDuplicateWarnings('V') } },
      setActionDuplicateState: (update) => Object.assign(state, update(state)),
      receiptIdentityDigest };
    return { state, verify: new Function(...Object.keys(bindings),
      `return (${countedSource[1]});`)(...Object.values(bindings)) };
  };
  const carried = signedReads.map((r) => ({ ...r, actionHash }));
  for (const receipt of carried) {
    assert.equal(await realVerifier('receipt', receipt), true, 'operator metadata leaves read signature valid');
    assert.equal(receiptIdentityDigest(receipt), receiptIdentityDigest({ ...receipt, actionHash: undefined }));
  }
  const fresh = makeVerifiedCounter();
  const windowState = { current: null };
  const queueOptions = {
    now: () => base + 60000, requireConfirmedWindow: true,
    getRosterUids: () => roster.map((member) => member.uid),
    getChatWindow: () => windowState.current,
    verifyReceipt: (receipt) => fresh.verify('receipt', receipt),
    resolveReceipt: () => ({ state: 'covered', facts: [], priority: 'F' }),
    getSelectionContext: () => ({ messages: [], blockNum: 7, groupId: 3, myUid: 'V' }),
  };
  const freshQueue = new ReceiptAdmissionQueue(queueOptions);
  for (const receipt of carried) await freshQueue.offer(receipt);
  assert.equal(freshQueue.getPendingReceipts().length, 5,
    'receipt_history waits for the confirmed window on a fresh page');
  for (const receipt of signedReads) assert.equal(await freshQueue.offer(receipt,
    { verified: true }), false, 'a later genuine relay copy has the same digest');
  windowState.current = { startMs: base - 1000, endMs: base + 3600000 };
  await freshQueue.reevaluate();
  assert.deepEqual(fresh.state.uids, [], 'the fresh-page queue cannot accuse I');
  const persisted = freshQueue.getAcceptedReceipts();
  freshQueue.dispose();
  const reopened = makeVerifiedCounter();
  const reopenedQueue = new ReceiptAdmissionQueue({ ...queueOptions,
    verifyReceipt: (receipt) => reopened.verify('receipt', receipt) });
  for (const receipt of persisted) await reopenedQueue.offer(receipt);
  await reopenedQueue.reevaluate();
  assert.deepEqual(reopened.state.uids, [], 'reloaded accepted receipts cannot accuse I');
  reopenedQueue.dispose();
  const live = makeVerifiedCounter();
  await verifyLiveSnapshotEntries({ blockNum: 7, groupId: 3, messages: [], actions: {}, receipts: carried },
    { blockNum: 7, groupId: 3, members: roster, verifyChat: async () => true,
      verifyInner: (type, inner) => live.verify(type, inner), knownReceiptDigests: new Set() });
  assert.deepEqual(live.state.uids, [], 'the live path cannot accuse I');
  const positive = makeVerifiedCounter();
  for (let i = 0; i < 5; i++) {
    const timestamp = base + i * 7000;
    const signature = protocol.canonicalizeSignature(await signer.signMessage({ message:
      protocol.receiptSignString(7, 3, 'I', actionHash, timestamp) }));
    await positive.verify('receipt', { receiverUid: 'I', actionHash, timestamp, signature });
  }
  assert.deepEqual(positive.state.uids, ['I'], 'five genuine action receipts still accuse I');
  for (const msgRefs of ['x', {}]) {
    const raws = [];
    for (let i = 0; i < 5; i++) {
      const timestamp = base + 100000 + i * 7000;
      const signature = protocol.canonicalizeSignature(await signer.signMessage({ message:
        protocol.receiptSignString(7, 3, 'I', actionHash, timestamp) }));
      raws.push({ receiverUid: 'I', actionHash, msgRefs, timestamp, signature });
    }
    const pure = new ActionReceiptDuplicateWarnings('V');
    for (const row of raws) pure.observe(row, receiptIdentityDigest(row));
    assert.deepEqual(pure.attackedIssuers(), ['I'], 'MCF C-prime pure path counts non-array msgRefs');
    const rawCounter = makeVerifiedCounter();
    for (const row of raws) await rawCounter.verify('receipt', row, { relayAction: true });
    assert.deepEqual(rawCounter.state.uids, ['I'], 'MCF relay signature path counts raw action receipts');
    const liveCounter = makeVerifiedCounter();
    await verifyLiveSnapshotEntries({ blockNum: 7, groupId: 3, messages: [], actions: {}, receipts: raws },
      { blockNum: 7, groupId: 3, members: roster, verifyChat: async () => true,
        verifyInner: (type, inner) => liveCounter.verify(type, inner), knownReceiptDigests: new Set() });
    assert.deepEqual(liveCounter.state.uids, ['I'], 'MCF live signature path counts raw action receipts');
  }
  for (const source of [hook, page, recovery, warningSource]) assert.equal(source.includes(oldKey), false);
  for (const source of [hook, page, recovery, warningSource, vendorWarningSource, translations,
    bundle, loaderBundle]) {
    for (const removed of ['ReceiptWithholdingWarnings', 'receiptWithholding', 'noteWarningPath'])
      assert.equal(source.includes(removed), false, `${removed} must be absent from production code`);
  }
  const modals = recovery.slice(recovery.indexOf('function renderGameModals('), recovery.indexOf('function renderGame()'));
  assert.match(hook, /observeVerifiedReadReceipt[\s\S]*?tracker\.observe\(/);
  assert.match(hook, /onVerifiedReadReceipt: observeVerifiedReadReceipt/);
  assert.doesNotMatch(hook, /attackedReadIssuers/);
  assert.match(hook, /verifyReceipt: \(receipt\) => verifyCounted\('receipt', receipt\)/);
  assert.match(hook, /verifyInner: \(type, inner\) => verifyCounted\(type, inner\)/);
  assert.match(hook, /verifyInnerSignature: \(type, inner\) => verifyCounted\(type, inner, \{ relayAction: true \}\)/);
  assert.match(hook, /if \(!actionIngestGateOpen\(\)\) return;[\s\S]*?verifyRelayInner\('action', inner\)[\s\S]*?markG3Action\(inner\)/);
  assert.match(hook, /for \(const inner of projected\.actions\) \{[\s\S]*?markG3Action\(inner\)[\s\S]*?futureMarksRef/);
  assert.match(hook, /relayAction && type === 'action' && markG3Action\(inner\)/);
  assert.match(hook, /g3SavedReportsRef\.current =/);
  assert.match(hook, /await verifyRelayInner\('action', inner\)/);
  assert.doesNotMatch(hook, /historicReports|serverReceipts|markG3ServerReceipt|relayArrivedAt/);
  const ephemeralWarningCode = hook.slice(hook.indexOf('const actionDuplicateRef = useRef('),
    hook.indexOf('const receiptWarningTimerRef = useRef('));
  assert.doesNotMatch(ephemeralWarningCode, /saveJson|localStorage|OBSERVED_ACTIONS_KEY|OBSERVED_RECEIPTS_KEY/);
  assert.match(recovery, /suspiciousReportingUids/);
  assert.doesNotMatch(recovery, /ActionReceiptDuplicateWarnings/);
  assert.match(page, /ws\.receiptWarningUids\?\.missing\?\.includes\(member\.uid\)/);
  assert.match(page, /!isSelf && !isSpectator && effectivePhase === 'chatting'[\s\S]*?ws\.suspiciousReportingUids\?\.includes\(member\.uid\)/);
  assert.match(page, /showReportingRecommendation\(member\.uid, reportAdvice\.status, reportAdvice\.slots\)/);
  assert.match(recovery, /function mergeReceipts[\s\S]*?state\.receiptWarnings\?\.observe\(/);
  assert.match(recovery, /function renderMemberList[\s\S]*?recovery\.members\.fraudulentReceipts/);
  assert.match(chatPhase, /soleRemainingReportTarget\([\s\S]*?setPendingReportWarningTarget\(targetUid\)/);
  assert.match(chatPhase, /handleReport\(target, true\)/);
  assert.match(recovery, /state\.reportWarningAccepted = true;[\s\S]*?sendReport\(target\)/);
  assert.match(recovery, /reportRevealCancel'[\s\S]*?state\.pendingReportWarningTarget = null; renderGame\(\)/);
  assert.doesNotMatch(recovery, /attackedReadNotice|attackedReadReport/);
  for (const html of [recoveryHtml, distHtml]) assert.match(html, /\.memberFloodAlert\s*\{[^}]*color:/);
  assert.doesNotMatch(modals, /attackedReadNotice|fraudulentReceipts/);
  for (const lang of ['ja', 'en']) {
    const json = JSON.parse(readFileSync(new URL(`../../public/locales/${lang}/game_${lang}.json`, import.meta.url)));
    assert.equal(Object.hasOwn(json.members, oldKey), false);
    for (const key of ['fraudulentReceipts']) {
      assert.ok(json.members[key]?.includes('{{name}}'));
    }
    assert.equal(Object.hasOwn(json.members, 'attackedReadNotice'), false);
    assert.equal(Object.hasOwn(json.members, 'attackedReadReport'), false);
    assert.equal(Object.hasOwn(json.members, 'receiptWithholding'), false);
  }
  assert.equal(translations.includes(`recovery.members.${oldKey}`), false);
  for (const key of ['fraudulentReceipts',
    'suspiciousReporting', 'suspiciousReportingShort']) {
    assert.equal(translations.split(`'recovery.members.${key}'`).length - 1, 3);
  }
  assert.doesNotMatch(translations, /recovery\.members\.attackedRead(?:Notice|Report)/);
  const ja = JSON.parse(readFileSync(new URL('../../public/locales/ja/game_ja.json', import.meta.url)));
  const reveal = '密告対象要件（投票の確定）を満たしているのはAだけなので、Aに密告を出していることが他のプレイヤーにバレる可能性があります。特にAから密告をされ返される可能性が高くなります。このまま密告をしても良いですか？他のプレイヤーの投票が確定してから密告することを推奨します。';
  const revealLate = '密告対象要件（投票の確定）を満たしているのはAだけなので、Aに密告を出していることが他のプレイヤーにバレる可能性があります。特にAから密告をされ返される可能性が高くなります。このまま密告をしても良いですか？';
  const officialI18n = i18next.createInstance();
  await officialI18n.init({ lng: 'ja', fallbackLng: false, resources: { ja: { translation: { game: ja } } },
    interpolation: { escapeValue: false } });
  assert.equal(officialI18n.t('game.action.reportRevealWarning', { A: 'A' }), reveal);
  assert.equal(recoveryT('ja')('recovery.action.reportRevealWarning', { A: 'A' }), reveal);
  assert.equal(officialI18n.t('game.action.reportRevealWarningLate', { A: 'A' }), revealLate);
  assert.equal(officialI18n.t('game.members.suspiciousReporting', { name: 'B' }),
    recoveryT('ja')('recovery.members.suspiciousReporting', { name: 'B' }));
  assert.equal(officialI18n.t('game.members.suspiciousReportingShort', { name: 'B' }),
    recoveryT('ja')('recovery.members.suspiciousReportingShort', { name: 'B' }));
  assert.equal(recoveryT('ja')('recovery.action.reportRevealWarningLate', { A: 'A' }), revealLate);
  assert.equal(recoveryT('ja')('recovery.action.reportRevealProceed'), '密告する');
  assert.equal(recoveryT('ja')('recovery.action.reportRevealCancel'), 'やめる');
  for (const lang of ['en', 'zh']) {
    assert.ok(recoveryT(lang)('recovery.action.reportRevealWarning', { A: 'A' }).includes('A'));
  }
}

{
  const roots = ['../../src', '../../workers', '../src', '../vendor', '../dist']
    .map((relative) => fileURLToPath(new URL(relative, import.meta.url)));
  const checked = new Set();
  const removedNames = ['typesByIssuer', 'hasFutureMarksFrom',
    'onFutureWarningSourcesChanged'];
  const inspect = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) inspect(path);
      else if (entry.isFile()) {
        checked.add(path);
        const source = readFileSync(path, 'utf8');
        for (const name of removedNames) assert.equal(source.includes(name), false,
          `${name} remains in ${path}`);
      }
    }
  };
  roots.forEach(inspect);
  for (const relative of ['../../src/utils/relay.js', '../vendor/src/utils/relay.js',
    '../dist/recovery.bundle.js']) {
    assert(checked.has(fileURLToPath(new URL(relative, import.meta.url))), relative);
  }
  const ledger = readFileSync(new URL('../VENDOR_SYNC.md', import.meta.url), 'utf8');
  for (const name of removedNames) assert.equal(ledger.includes(name), false);
}

// MCF: the official queue, verifier, target resolver, and persistence path.
{
  const hook = readFileSync(process.env.W9F_HOOK_SOURCE
    || new URL('../../src/hooks/useGameWebSocket.js', import.meta.url), 'utf8');
  const extract = (name, deps) => {
    const anchor = `const ${name} = useCallback(`;
    const start = hook.indexOf(anchor);
    const end = hook.indexOf(`\n  }, ${deps});`, start);
    assert(start >= 0 && end > start, `MCF extracts ${name}`);
    return hook.slice(start + anchor.length, end + 4);
  };
  const verifySrc = extract('verifyRelayInner', '[blockNum, groupId, effectiveClientNow, selectCurrentRoster]');
  const ingestSrc = extract('ingestReceipt', '[blockNum, groupId, uid, warnActionPersistenceFailure, isGameIdentityCurrent, getClientMsgKey, flagOtherSession, getObservedReceiptWriter]');
  const resolveSrc = extract('resolveReceiptTarget', '[blockNum, groupId, uid]');
  const queueSrc = extract('queueReceipt', '[blockNum, groupId, uid, ingestReceipt, gameRpcSession]');
  const bind = (src, scope) => new Function(...Object.keys(scope), `return (${src});`)(...Object.values(scope));
  const B = privateKeyToAccount(`0x${'35'.repeat(32)}`);
  const I = privateKeyToAccount(`0x${'36'.repeat(32)}`);
  const blockNum = 7, groupId = 3, uid = 'B';
  const now = Date.now();
  const window = { startMs: now - 60_000, endMs: now + 60_000 };
  const roster = [{ uid: 'B', bAddr: { address: B.address } },
    { uid: 'I', bAddr: { address: I.address } }];
  const msg = { uid: 'B', text: 'MCF signed message', timestamp: now,
    signature: protocol.canonicalizeSignature(await B.signMessage({ message:
      protocol.chatSignStringV2(blockNum, groupId, 'B', 'MCF signed message', now) })) };
  const ref = protocol.msgRefOf(protocol.computeMsgKeyV2(blockNum, groupId, msg));
  const readReceipt = { receiverUid: 'I', senderUid: 'B', msgRefs: [ref], timestamp: now + 1000 };
  readReceipt.signature = protocol.canonicalizeSignature(await I.signMessage({ message:
    protocol.readReceiptSignString(blockNum, groupId, 'I', 'B', [ref], readReceipt.timestamp) }));
  const vote = { encrypted: 'cipher', timestamp: now, signature: 'vote' };
  const hash = protocol.actionHashV2('vote', blockNum, groupId, 'B', vote.encrypted, vote.timestamp);
  const actionReceipt = { receiverUid: 'I', actionHash: hash, timestamp: now + 2000 };
  actionReceipt.signature = protocol.canonicalizeSignature(await I.signMessage({ message:
    protocol.receiptSignString(blockNum, groupId, 'I', hash, actionReceipt.timestamp) }));
  const common = { ...protocol, ...counter, verifyMessage, blockNum, groupId, uid,
    selectCurrentRoster: () => ({ source: 'verified', members: roster }) };
  const realVerify = bind(verifySrc, common);
  const run = async (steps, { storage = null, pending = false } = {}) => {
    const state = { receipts: {} }, saved = storage ? { ...storage } : {};
    const receiptsRef = { current: state.receipts };
    const setReceipts = (update) => { state.receipts = update(state.receipts); receiptsRef.current = state.receipts; };
    const loadJson = () => saved;
    const saveJson = (_key, rows) => { for (const key of Object.keys(saved)) delete saved[key]; Object.assign(saved, rows); return true; };
    const getObservedReceiptWriter = () => ({ accept: (row) => { saved[row.signature] = row; } });
    const confirmedChatWindowRef = { current: pending ? null : window };
    let rosterReady = !pending;
    const chainTimelineRef = { current: { chatCloseAt: now + 60_000 } };
    const messagesRef = { current: [msg] }, observedActionsRef = { current: { votes: {}, reports: {} } };
    const myVoteRef = { current: vote }, myVotePrevRef = { current: [] }, myReportsRef = { current: [] };
    const ingestReceipt = bind(ingestSrc, { ...common, isGameIdentityCurrent: () => true,
      flagOtherSession: () => {}, issuedReadMsgKeysRef: { current: new Set() },
      peerActivityRef: { current: {} }, setReceipts, mergeActionReceiptSources: protocol.mergeActionReceiptSources,
      saveJson, loadJson, OBSERVED_RECEIPTS_KEY: () => 'saved', warnActionPersistenceFailure: () => {},
      receiptArrivalSeqRef: { current: 0 }, maxReceiptArrivalSeq: () => 0,
      receiptClaimMemoRef: { current: { memo: new ReceiptClaimMemo() } },
      messagesRef, confirmedChatWindowRef, getClientMsgKey: protocol.buildMsgKeyGetter(blockNum, groupId),
      getObservedReceiptWriter });
    const resolveReceiptTarget = bind(resolveSrc, { ...common, messagesRef, observedActionsRef,
      myVoteRef, myVotePrevRef, myReportsRef, confirmedChatWindowRef, GUEST_PINNED_RULES: counter.GUEST_PINNED_RULES });
    const discarded = [];
    const admission = new ReceiptAdmissionQueue({
      getRosterUids: () => rosterReady ? roster.map((m) => m.uid) : null,
      isRosterVerified: () => rosterReady,
      verifyReceipt: (row) => realVerify('receipt', row), resolveReceipt: resolveReceiptTarget,
      getChatWindow: () => confirmedChatWindowRef.current, getChatCloseAtMs: () => now + 60_000,
      requireConfirmedWindow: true, now: () => now, isChatting: () => true,
      getSelectionContext: () => ({ messages: [msg], blockNum, groupId, myUid: uid,
        caps: counter.GUEST_PINNED_RULES, getClientMsgKey: null }),
      onAccept: ingestReceipt, onDiscard: (row, reason) => discarded.push([receiptIdentityDigest(row), reason]),
    });
    const queue = bind(queueSrc, { ...common, receiptAdmissionRef: { current: admission },
      liveOnlyReceiptsRef: { current: new Map() }, receiptsRef, receiptIdentityDigest,
      MAX_RECEIPTS_PER_ISSUER: 700, receiptChainClockRef: { current: {} },
      receiptTipRetryAfterRef: { current: 0 }, gameRpcSession: null,
      readReceiptChainTime: async () => now, readTimeChainTipMs: async () => now,
      markActionReceiptSource: protocol.markActionReceiptSource, chainTimelineRef,
      confirmedChatWindowRef, CHAT_WINDOW_CLOCK_SKEW_MS: protocol.CHAT_WINDOW_CLOCK_SKEW_MS,
      clientNow: () => now, ingestReceipt });
    if (storage) for (const row of Object.values(storage)) await queue(row, { source: 'storage' });
    for (const [row, options] of steps) await queue(row, options);
    if (pending) { confirmedChatWindowRef.current = window; rosterReady = true; }
    await admission.reevaluate(); await admission.work;
    const carried = protocol.clientChatSourcedReceipts(state.receipts, window, now + 60_000);
    const maps = protocol.buildReceiptMaps(carried, { messages: [msg], actions: [{ ...vote, type: 'vote', uid: 'B' }],
      myUid: uid }, blockNum, groupId, window);
    const priority = [...admission.entries.values()].find((e) => e.receipt.signature === readReceipt.signature)?.priority;
    admission.dispose();
    return { state: state.receipts, saved, carried, maps, priority, discarded };
  };
  const copiedRead = { ...readReceipt, actionHash: hash, _receivedAt: now };
  for (const pending of [false, true]) {
    const result = await run([[copiedRead, { source: 'do' }], [readReceipt, { verified: true }]], { pending });
    assert.equal(result.maps.readersByMsgKey[ref]?.has('I'), true, 'MCF read remains visible');
    assert.equal(result.carried.some((row) => row.signature === readReceipt.signature), true,
      'MCF read remains in the submission source');
    assert.equal(Object.hasOwn(result.state[readReceipt.signature], 'actionHash'), false);
    assert.equal(result.priority, 'F', 'MCF read cannot claim vote priority');
    const reopened = await run([], { storage: result.saved });
    assert.equal(Object.hasOwn(reopened.state[readReceipt.signature], 'actionHash'), false,
      'MCF poisoned storage is repaired on import');
  }
  const poisonedStorage = await run([], { storage: { [readReceipt.signature]: copiedRead } });
  assert.equal(Object.values(poisonedStorage.state).filter((row) => row.actionHash).length, 0,
    'MCF poisoned storage is repaired in state');
  assert.equal(Object.values(poisonedStorage.saved).filter((row) => row.actionHash).length, 0,
    'MCF poisoned storage is repaired on disk');
  assert.equal(poisonedStorage.maps.readersByMsgKey[ref]?.has('I'), true,
    'MCF repaired storage remains visible');
  assert.equal(poisonedStorage.carried.some((row) => row.signature === readReceipt.signature), true,
    'MCF repaired storage remains in the submission source');
  const reverse = { ...actionReceipt, senderUid: 'B', msgRefs: [ref] };
  for (const pending of [false, true]) {
    const reverseResult = await run([[reverse, { source: 'do' }], [actionReceipt, { verified: true }]],
      { pending });
    assert.equal(reverseResult.maps.receiptorsByActionHash[hash]?.has('I'), true,
      'MCF genuine action receipt survives the reverse WS and relay copies');
    assert.equal(reverseResult.discarded.some(([digest]) => digest === receiptIdentityDigest(actionReceipt)), false,
      'MCF genuine digest is never rejected');
    const historyResult = await run([[reverse, { source: 'do' }], [actionReceipt, { source: 'do' }]],
      { pending });
    assert.equal(historyResult.maps.receiptorsByActionHash[hash]?.has('I'), true,
      'MCF genuine history receipt survives the reverse copy');
  }
  const live = await verifyLiveSnapshotEntries({ blockNum, groupId, messages: [], actions: {},
    receipts: [reverse, actionReceipt] }, { blockNum, groupId, members: roster,
    verifyChat: async () => true, verifyInner: (type, row) => realVerify(type, row),
    knownReceiptDigests: new Set() });
  assert.equal(live.receipts.length, 1, 'MCF live keeps the genuine action receipt');
  assert.equal((await run(live.receipts.map((row) => [row, { fromLive: true, source: 'do' }])))
    .maps.receiptorsByActionHash[hash]?.has('I'), true);
}

// T8: self-addressed rows must retain warning ② even when the sender overflowed
// or all missing refs were discarded as future. Other-sender rows remain exempt.
for (const exclusion of ['overflow', 'future']) {
  for (const [issuer, sender, expected] of [['Q', 'Q', ['Q']], ['R', 'S', []]]) {
    const tracker = new ReceiptWarnings('V');
    if (exclusion === 'future') {
      for (let i = 0; i < 100; i++) tracker.noteFutureChatRef(sender, `f${i}`);
    }
    for (let i = 0; i < 250; i++) {
      tracker.observe(read(issuer, sender, [exclusion === 'future' ? `f${i % 100}` : `m${i}`], 0),
        `${issuer}-${i}`, 0, () => false);
    }
    const overflow = exclusion === 'overflow' ? new Set([sender]) : new Set();
    assert.deepEqual(evalAt(tracker, RECEIPT_WARNING_WAIT_MS, new Set(), overflow).missingUids,
      expected, `T8 ${exclusion}: ${issuer} -> ${sender}`);
  }
}
{
  const tracker = new ReceiptWarnings('V');
  for (let i = 0; i < 199; i++) tracker.observe(read('Q', 'Q', [`m${i}`], 0), `under-${i}`, 0);
  assert.deepEqual(evalAt(tracker, RECEIPT_WARNING_WAIT_MS).missingUids, [], 'T8 threshold remains 200');
}
console.log('s3fix-f-warnings-unit: ALL PASSED');

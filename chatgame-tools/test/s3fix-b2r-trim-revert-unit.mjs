// S3FIX-W2a-TR-01 の系譜探針を、B2R の正典と vendor を直接比べる歯へ移した。
// 発見者の最初の探針から変えた盤面:
//  - 19-digit numeric uids (claim-data-codec playerLeafKey enforces [0-9]{1,20})
//  - M's extra vote candidates spaced so honest clients actually receipt them (D-02: > first vote + 10 min)
//  - V's bundle built through the SubmissionPhase pure pipeline:
//    normalizeActionSnapshotForSubmission -> buildRealTargets -> clientWindowedReceipts ->
//    selectBundleReceipts -> aggregateSelfReceipts(targets) -> filterReceiptsToCarriedTargets
//  - planOnChainTrim with a real (non-null) chat window
//  - honest text volume / script parameterised (HU = half-width units per honest message, HN = honest count,
//    ASCII=1 for ASCII honest text)
import { keccak256, toHex, toBytes, concat, stringToBytes } from 'viem';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { privateKeyToAccount } from 'viem/accounts';
import { encrypt } from 'eciesjs';
// B2R (f78bc892) with the P2c priority branch, E-prime trim stage, and S3R5 SELF R 級; SYNC2 fixes the trim-order comment only.
const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const NODE = process.execPath;
const FILE = fileURLToPath(import.meta.url);
const expected = {
  'src/utils/evidence-trim-policy.js': 'f6a3f7a37247d925fc64cdc2abf8c7a4ba78ea215db1972f1cc3cd2f09baf3e4',
  'workers/game_workers/lib/evidence-trim.js': 'd637a5a8f316612c7467da29947f55611ad79a81055a976d9d8bb051fc2dc90f',
};
if (!process.argv[2]) {
  const started = Date.now();
  for (const [mode, env, expectedPts] of [
    ['vslow,mact', { HREP: '1' }, 0],
    ['mback,mact', { HREP: '1' }, 0],
    ['ordinary', { HREP: '0', HN: '90', MN: '90' }, 0],
  ]) {
    const stdout = execFileSync(NODE, [FILE, mode], { env: { ...process.env, ...env }, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
    const result = JSON.parse(stdout.trim().split('\n').at(-1));
    const [canonical, vendor] = result.rows;
    assert.equal(canonical.signedPayloadSha256, vendor.signedPayloadSha256, `${mode}: canonical/vendor wire bytes`);
    assert.deepEqual(canonical.dropped, vendor.dropped, `${mode}: canonical/vendor dropped classes`);
    assert.deepEqual(canonical.remainingReportReceipts, vendor.remainingReportReceipts, `${mode}: canonical/vendor receipts`);
    if (mode !== 'ordinary') {
      assert.equal(result.h1CarriesOwnOnVRep, 1, `${mode}: H1 held receipt`);
      assert.equal(result.mCarriesOnVRep, 0, `${mode}: M withheld receipt`);
      assert.equal(canonical.remainingReportReceipts, 1, `${mode}: V must carry H1's report receipt`);
      assert.equal(canonical.results.M.dq, true, `${mode}: M must be disqualified`);
      assert(canonical.results.M.why.includes('reported'), `${mode}: report disqualification`);
      assert.equal(canonical.results.M.pts, expectedPts);
      assert.equal(canonical.results.V.pts, 212, `${mode}: V's score`);
      assert.equal(canonical.results.H1.pts, 229, `${mode}: H1's score`);
    } else {
      assert.equal(result.messageCounts.V, 90);
      assert.equal(result.messageCounts.M, 90);
      assert.equal(result.charsPerSender.V, 9000);
      assert.equal(result.charsPerSender.M, 9000);
    }
    console.log(`B2R ${mode}: reportReceipts=${canonical.remainingReportReceipts} M=${canonical.results.M.dq ? 'DQ' : 'notDQ'}/${canonical.results.M.pts} dropped=${JSON.stringify(canonical.dropped)} signedSha256=${canonical.signedPayloadSha256}`);
  }
  for (const [path, sha] of Object.entries(expected)) {
    const bytes = readFileSync(`${ROOT}/${path}`);
    const vendor = readFileSync(`${ROOT}/chatgame-tools/vendor/${path}`);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), sha, `${path}: B2R source with P2c additions`);
    assert.deepEqual(bytes, vendor, `${path}: vendor copy bytes`);
  }
  console.log(`S3FIX B2R trim revert: ALL PASSED (${Date.now() - started} ms)`);
  process.exit(0);
}
const L = `${ROOT}/workers/game_workers/lib`;
const { calculateGroupResults, receiptCanonCmp } = await import(`${L}/game-result-calculator.js`);
const C = await import(`${L}/evidence-compact-v1.js`);
const P = await import(`${L}/protocol-v2.js`);
const SL = await import(`${L}/submission-limits.js`);
const CANON = await import(`${L}/evidence-trim.js`);
const VENDOR = await import(`${ROOT}/chatgame-tools/vendor/workers/game_workers/lib/evidence-trim.js`);

const BLOCK = 5; const GROUP = 0; const base = 1_750_000_000_000;
const mode = process.argv[2];
const F = new Set(mode.split(','));
const HU = Number(process.env.HU || 100);   // half-width units per honest message
const HN = Number(process.env.HN || 100);   // honest messages per player
const ASCII = process.env.ASCII === '1';
const enc = new TextEncoder();
const eciesFor = (pub, text) => Buffer.from(encrypt(pub.slice(2), enc.encode(P.padActionPlaintext(text)))).toString('hex');
let seed = BigInt(process.env.SEED || 7);
const rnd = () => { seed = (seed * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n); return Number(seed >> 11n) / 2 ** 53; };

async function makePlayer(uid, depositEth, idx) {
  const wallet = privateKeyToAccount(`0x${BigInt(1000 + idx).toString(16).padStart(64, '0')}`);
  const sig = await wallet.signMessage({ message: `bitcoinu_mining_block${BLOCK}_user${uid}` });
  const master = keccak256(toBytes(sig));
  const signKey = keccak256(concat([toBytes(master), stringToBytes('sign')]));
  const encryptKey = keccak256(concat([toBytes(master), stringToBytes('encrypt')]));
  const signAccount = privateKeyToAccount(signKey);
  const encryptAccount = privateKeyToAccount(encryptKey);
  const depositWei = BigInt(Math.round(depositEth * 1e6)) * 10n ** 12n;
  return { idx, uid, wallet, signAccount, encryptAccount, encryptKey, addr: wallet.address,
    bAddr: { address: signAccount.address, pubKey: signAccount.publicKey },
    depIds: JSON.stringify({ deposit: depositWei.toString(), ids: [String(idx + 1)] }) };
}
const names = ['V', 'M', 'H1', 'H2', 'H3'];
const deps = [1.0, 0.25, 1.0, 0.5, 0.5];
const players = [];
for (let i = 0; i < 5; i++) players.push(await makePlayer(`176543210987654321${i + 1}`, deps[i], i));
const [V, M, H1, H2, H3] = players;
const members = players.map((p) => ({ uid: p.uid, addr: p.addr, bAddr: p.bAddr, depIds: p.depIds }));
const memberUids = players.map((p) => p.uid);
const getKey = P.buildMsgKeyGetter(BLOCK, GROUP);
const refOf = (m) => P.msgRefOf(getKey(m));

const messages = [];
for (let round = 0; round < 100; round++) {
  for (const p of players) {
    const honest = p !== M;
    if (honest && round >= HN) continue;
    if (!honest && round >= Number(process.env.MN || 100)) continue;
    const units = honest ? HU : 100;
    let text = '';
    if (honest && ASCII) { while (text.length < units) text += String.fromCharCode(97 + Math.floor(rnd() * 26)); }
    else { while (text.length < Math.floor(units / 2)) text += String.fromCharCode(0x4e00 + Math.floor(rnd() * 20000)); }
    const ts = base + round * 100_000 + p.idx * 20_000;
    const signature = await p.signAccount.signMessage({ message: P.chatSignStringV2(BLOCK, GROUP, p.uid, text, ts) });
    messages.push({ type: 'chat', blockNum: BLOCK, groupId: GROUP, uid: p.uid, text, timestamp: ts, signature });
  }
}
messages.sort(P.canonicalComparatorV2(getKey));
const lastMsgTs = Math.max(...messages.map((m) => m.timestamp));
const chatCloseAt = lastMsgTs + 10 * 60_000;
const chatWindow = { startMs: base - 60_000 - 120_000, endMs: chatCloseAt + 120_000 };

const readReceipts = [];
for (const m of messages) {
  for (const r of players) {
    if (r.uid === m.uid) continue;
    let d = (F.has('vslow') && r === V) ? 7000 + Math.floor(rnd() * 1000) : 500 + Math.floor(rnd() * 6500);
    if (F.has('mback') && r === M) d = -Math.min(9 * 60_000, m.timestamp - (base - 60_000));
    const ts = m.timestamp + d;
    const msgRefs = [refOf(m)];
    const signature = await r.signAccount.signMessage({ message: P.readReceiptSignString(BLOCK, GROUP, r.uid, m.uid, msgRefs, ts) });
    readReceipts.push({ receiverUid: r.uid, senderUid: m.uid, msgRefs, timestamp: ts, signature });
  }
}

async function makeAction(p, type, payload, ts) {
  const encrypted = eciesFor(p.encryptAccount.publicKey, JSON.stringify(payload));
  const signature = await p.signAccount.signMessage({ message: P.actionSignStringV2(type, BLOCK, GROUP, p.uid, encrypted, ts) });
  return { encrypted, signature, timestamp: ts };
}
async function actionReceipt(receiver, actor, type, action, ts) {
  const actionHash = P.actionHashV2(type, BLOCK, GROUP, actor.uid, action.encrypted, action.timestamp);
  const signature = await receiver.signAccount.signMessage({ message: P.receiptSignString(BLOCK, GROUP, receiver.uid, actionHash, ts) });
  return { receiverUid: receiver.uid, actionHash, timestamp: ts, signature };
}
const tA = base + 30 * 60_000;
// M's first vote is early; its 9 extra votes come > 10 min later so honest clients receipt them (D-02).
const mFirstVote = await makeAction(M, 'vote', { targetUid: H1.uid }, tA);
const votes = {
  [V.uid]: await makeAction(V, 'vote', { targetUid: H1.uid }, lastMsgTs + 60_000),
  [H1.uid]: await makeAction(H1, 'vote', { targetUid: V.uid }, lastMsgTs + 62_000),
  [H2.uid]: await makeAction(H2, 'vote', { targetUid: V.uid }, tA + 1000),
  [H3.uid]: await makeAction(H3, 'vote', { targetUid: V.uid }, tA + 2000),
};
const reports = {
  [V.uid]: [await makeAction(V, 'report', { targetUid: M.uid, reason: 'suspected_bot' }, lastMsgTs + 70_000)],
  [H1.uid]: [await makeAction(H1, 'report', { targetUid: M.uid, reason: 'suspected_bot' }, lastMsgTs + 71_000)],
};
const actionReceipts = [
  ...await Promise.all([V, H1, H2, H3].map((r) => actionReceipt(r, M, 'vote', mFirstVote, tA + 1500 + r.idx * 100))),
  await actionReceipt(H1, V, 'vote', votes[V.uid], lastMsgTs + 60_500),
  await actionReceipt(V, H1, 'vote', votes[H1.uid], lastMsgTs + 62_500),
  await actionReceipt(V, H2, 'vote', votes[H2.uid], tA + 1500),
  await actionReceipt(H1, H2, 'vote', votes[H2.uid], tA + 1600),
  await actionReceipt(V, H3, 'vote', votes[H3.uid], tA + 2500),
  await actionReceipt(H1, H3, 'vote', votes[H3.uid], tA + 2600),
  await actionReceipt(H1, V, 'report', reports[V.uid][0], lastMsgTs + 70_500), // M refuses, H2/H3 gone
  await actionReceipt(V, H1, 'report', reports[H1.uid][0], lastMsgTs + 71_500),
];
if (process.env.HREP === '1') {
  // honest players also use their report slots (each honest player may report up to 2 targets)
  const add = async (actor, target, ts, receivers) => {
    const a = await makeAction(actor, 'report', { targetUid: target.uid, reason: 'suspected_bot' }, ts);
    (reports[actor.uid] ||= []).push(a);
    for (const r of receivers) actionReceipts.push(await actionReceipt(r, actor, 'report', a, ts + 1200 + r.idx * 100));
  };
  await add(H2, H3, tA + 5000, [V, M, H1, H3]);
  await add(H3, H2, tA + 6000, [V, M, H1, H2]);
  await add(H2, H1, tA + 7000, [V, M, H1, H3]);
  await add(H3, V, tA + 8000, [V, M, H1, H2]);
  await add(H1, H2, lastMsgTs + 72_000, [V, M]);
  await add(V, H3, lastMsgTs + 73_000, [H1, M]);
}
const extraVotes = []; const extraReports = [];
if (F.has('mact')) {
  for (let k = 0; k < (Number(process.env.NV ?? 9)); k++) {
    const a = await makeAction(M, 'vote', { targetUid: H1.uid }, tA + 11 * 60_000 + k * 1000);
    if (!P.shouldIssueReceiptForObservedAction('vote', mFirstVote, a)) throw new Error('D-02 would refuse');
    extraVotes.push(a);
    for (const r of [V, H1, H2, H3]) actionReceipts.push(await actionReceipt(r, M, 'vote', a, a.timestamp + 1500 + r.idx * 100));
  }
  for (let k = 0; k < (Number(process.env.MREP ?? 9)); k++) {
    const a = await makeAction(M, 'report', { targetUid: H2.uid, reason: 'suspected_bot' }, tA + 30_000 + k * 1000);
    extraReports.push(a);
    for (const r of [V, H1, H2, H3]) actionReceipts.push(await actionReceipt(r, M, 'report', a, a.timestamp + 1500 + r.idx * 100));
  }
}
const allReceipts = [...readReceipts, ...actionReceipts].sort(receiptCanonCmp);

async function bundleFor(p, { omit = () => false } = {}) {
  const snapshotData = { votes: {}, reports: {}, observed: { votes: {}, reports: {}, receipts: [] } };
  for (const q of players) {
    const qv = q === M ? [mFirstVote, ...extraVotes] : (votes[q.uid] ? [votes[q.uid]] : []);
    const qr = q === M ? extraReports : (reports[q.uid] || []);
    if (q === p) {
      if (qv.length) snapshotData.votes[q.uid] = qv[0];
      if (qv.length > 1) snapshotData.observed.votes[q.uid] = qv.slice(1);
      if (qr.length) snapshotData.reports[q.uid] = qr;
    } else {
      if (qv.length) snapshotData.observed.votes[q.uid] = qv;
      if (qr.length) snapshotData.observed.reports[q.uid] = qr;
    }
  }
  const normalized = SL.normalizeActionSnapshotForSubmission(snapshotData, {
    blockNum: BLOCK, groupId: GROUP, memberUids, submitterUid: p.uid, reportTargetOf: () => null,
  });
  snapshotData.votes = normalized.votes; snapshotData.reports = normalized.reports; snapshotData.observed = normalized.observed;
  const targets = P.buildRealTargets(snapshotData, messages, BLOCK, GROUP);
  const sourced = allReceipts.filter((rc) => !omit(rc));
  const admissible = P.clientWindowedReceipts(sourced, chatWindow, p.uid);
  const kept = P.selectBundleReceipts(admissible, targets, {
    compare: receiptCanonCmp, memberUids, chatWindow, maxRefsPerReceipt: P.receiptMaxRefsPerReceipt(100), selfUid: p.uid,
  });
  const agg = await C.aggregateSelfReceipts([...kept], p.uid, BLOCK, GROUP, (message) => p.signAccount.signMessage({ message }), targets, chatWindow);
  snapshotData.observed.receipts = agg.receipts;
  if (agg.aggregate) snapshotData.observed.selfReceiptAggregate = agg.aggregate;
  const carried = C.filterReceiptsToCarriedTargets(snapshotData, messages, BLOCK, GROUP);
  snapshotData.observed = carried.observed;
  const submittedAt = chatCloseAt + 3600_000;
  const depositIds = JSON.parse(p.depIds).ids;
  const chatHash = P.computeChatHashV2(messages, BLOCK, GROUP);
  const encryptedDataHash = keccak256(toHex(JSON.stringify(snapshotData)));
  const signature = await p.wallet.signMessage({ message: JSON.stringify({ blockNum: BLOCK, uid: p.uid, encryptKey: p.encryptKey, chatHash, submittedAt, encryptedDataHash, depositIds }) });
  const bundle = { uid: p.uid, encryptKey: p.encryptKey, chatHash, signature, submittedAt, encryptedDataHash, depositIds, encryptedActions: snapshotData, messages };
  const ctx = { blockNum: BLOCK, groupId: GROUP, memberUids };
  return { bundle, payload: C.compactBytesToPayload(C.encodeEvidenceCompactV1(bundle, ctx)), ctx };
}
const decoded = (payload) => C.decodeSubmissionPayloadString(payload).bundle;
const vRepHash = P.actionHashV2('report', BLOCK, GROUP, V.uid, reports[V.uid][0].encrypted, reports[V.uid][0].timestamp);
const vB = await bundleFor(V);
const mB = await bundleFor(M, { omit: (rc) => rc.actionHash === vRepHash });
const h1B = await bundleFor(H1);
const vBytes = C.compactPayloadToBytes(vB.payload).length;

async function onChainCopy(TRIM) {
  const plan = await TRIM.planOnChainTrim(vB.payload, V.uid, { chatWindow });
  if (!plan) return { plan: null, sub: decoded(vB.payload), wire: vB.payload };
  if (plan.impossible) return { plan, sub: null, wire: null };
  const t = plan.trimmedBundle;
  const sig = await V.wallet.signMessage({ message: JSON.stringify({ blockNum: BLOCK, uid: t.uid, encryptKey: t.encryptKey, chatHash: t.chatHash, submittedAt: t.submittedAt, encryptedDataHash: t.encryptedDataHash, depositIds: t.depositIds }) });
  const wire = CANON.encodeSignedTrimmedPayload(t, sig, plan.compactContext);
  return { plan, sub: decoded(wire), wire };
}
const caps = { maxChars: 10000, maxMessages: 100, maxMsgChars: 1000 };
const summarize = (results) => Object.fromEntries(results.map((r) => [names[memberUids.indexOf(r.uid)],
  { dq: r.isDisqualified, why: r.disqualifyReasons, pts: r.totalPoints }]));
const h1CarriesOwnOnVRep = decoded(h1B.payload).encryptedActions.observed.receipts.filter((rc) => rc.actionHash === vRepHash && rc.receiverUid === H1.uid).length
  + (decoded(h1B.payload).encryptedActions.observed.selfReceiptAggregate?.entries || []).filter((e) => e.targetType === 'action' && e.actionHash === vRepHash).length;
const mCarriesOnVRep = decoded(mB.payload).encryptedActions.observed.receipts.filter((rc) => rc.actionHash === vRepHash).length;
const rows = [];
for (const [tag, TRIM] of [['canonical', CANON], ['vendor', VENDOR]]) {
  const { plan, sub, wire } = await onChainCopy(TRIM);
  assert(sub && wire, `${mode}: trim is possible`);
  const gd = { members, submissions: { [V.uid]: sub, [M.uid]: decoded(mB.payload), [H1.uid]: decoded(h1B.payload) }, meta: { blockNum: BLOCK, groupId: GROUP } };
  const { results } = await calculateGroupResults(gd, 500, 20, caps, chatWindow);
  rows.push({ tag, beforeBytes: vBytes, afterBytes: plan?.afterBytes ?? vBytes,
    dropped: Object.fromEntries('H G F E C D A B V'.split(' ').map((k) => [k, plan?.[`dropped${k}`] ?? 0])),
    remainingReportReceipts: sub.encryptedActions.observed.receipts.filter((rc) => rc.actionHash === vRepHash).length,
    signedPayloadSha256: createHash('sha256').update(C.compactPayloadToBytes(wire)).digest('hex'),
    results: summarize(results),
  });
}
console.log(JSON.stringify({ mode, h1CarriesOwnOnVRep, mCarriesOnVRep,
  messageCounts: Object.fromEntries(players.map((p) => [names[p.idx], messages.filter((m) => m.uid === p.uid).length])),
  charsPerSender: Object.fromEntries(players.map((p) => [names[p.idx], messages.filter((m) => m.uid === p.uid).reduce((n, m) => n + m.text.length * 2, 0)])),
  rows }));

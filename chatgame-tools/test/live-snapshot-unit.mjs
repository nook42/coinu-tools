// S3R1-E-2-01: 公開 live JSON の検証済み取り込みで、復元 R の表示が採点へ揃うか。
//
// 盤面（3人組 R / M / H・H は公式クライアントの正直者で WS と P2P の両方を見る）:
//   1) M は WS だけで 500字×20件を早い時刻に出す（DO の上限 10,000字の内側）。H が受領証明。
//      R は WS を持たず、公開 live JSON からのみこの20件を見る。
//   2) その後 R と M が P2P で交互に話す（R_k の直後に M の短い返事 Mp_k）。
//   3) R の画面（app.js の renderChatSection と同じ式）は Mp_k を区切りとして会話回数を数える。
//   4) P2 で最優先欄を付けるまで P2P-only の束も版数16 と同じ。
//      attack では min_messages、control では失格しない。
//
// vendor の正典・復元 relay-client・bundle の実物を使う。fetch は差し替え、ネットワーク・ポートなし。

import { keccak256, toHex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { readFileSync } from 'node:fs';
const CT = new URL('..', import.meta.url).pathname.replace(/\/$/, '');
const { makePlayer } = await import(`${CT}/test/scenario.mjs`);
const P = await import(`${CT}/vendor/workers/game_workers/lib/protocol-v2.js`);
const CC = await import(`${CT}/vendor/workers/game_workers/lib/char-counter.js`);
const { calculateGroupResults } = await import(`${CT}/vendor/workers/game_workers/lib/game-result-calculator.js`);
const { validateResultBundle, buildMembersIndex } = await import(`${CT}/vendor/workers/game_workers/lib/evidence-reconciler.js`);
const { encryptAction } = await import(`${CT}/vendor/src/utils/ecies.js`);
const { buildSubmissionBundle } = await import(`${CT}/src/recovery/bundle.js`);
const { RecoveryRelay, readLiveSnapshot, LIVE_SNAPSHOT_MAX_BYTES } = await import(`${CT}/src/recovery/relay-client.js`);
const { buildEvent, deriveNostrKey, groupTag } = await import(`${CT}/vendor/src/utils/relay.js`);
const assert = (await import('node:assert/strict')).default;
globalThis.localStorage = { getItem: () => null, setItem: () => {} };
const { DEFAULTS } = await import(`${CT}/config.js`);

const blockNum = 5;
const groupId = 0;
const base = 1750000000000;
const MIN_CHARS = 500;
const MIN_MESSAGES = 20;
const withAttack = process.argv[2] !== 'control';

const R = await makePlayer('user0001', 0, 1.0, blockNum);
const M = await makePlayer('user0002', 1, 1.0, blockNum);
const H = await makePlayer('user0003', 2, 1.0, blockNum);
const players = [R, M, H];
const members = players.map((p) => ({ uid: p.uid, addr: p.addr, bAddr: p.bAddrString, depIds: p.depIds }));
const cmp = P.canonicalComparatorV2(P.buildMsgKeyGetter(blockNum, groupId));
const sortCanon = (list) => [...list].sort(cmp);

const makeMsg = async (p, text, ts) => {
  const signature = await p.signAccount.signMessage({ message: P.chatSignStringV2(blockNum, groupId, p.uid, text, ts) });
  return { type: 'chat', blockNum, groupId, uid: p.uid, text, timestamp: ts, signature };
};
const refOf = (m) => P.msgRefOf(P.computeMsgKeyV2(blockNum, groupId, m));
const readReceipt = async (receiver, msg, ts) => {
  const msgRefs = [refOf(msg)];
  const signature = await receiver.signAccount.signMessage({
    message: P.readReceiptSignString(blockNum, groupId, receiver.uid, msg.uid, msgRefs, ts),
  });
  return { receiverUid: receiver.uid, senderUid: msg.uid, msgRefs, timestamp: ts, signature };
};
const makeAction = async (p, type, payload, ts) => {
  const encrypted = encryptAction(payload, p.encryptKey);
  const signature = await p.signAccount.signMessage({ message: P.actionSignStringV2(type, blockNum, groupId, p.uid, encrypted, ts) });
  return { encrypted, signature, timestamp: ts };
};
const actionReceipt = async (receiver, actor, action, ts) => {
  const actionHash = P.actionHashV2('vote', blockNum, groupId, actor.uid, action.encrypted, action.timestamp);
  const signature = await receiver.signAccount.signMessage({ message: P.receiptSignString(blockNum, groupId, receiver.uid, actionHash, ts) });
  return { receiverUid: receiver.uid, actionHash, timestamp: ts, signature };
};

// ---- 発言 ----
// H の20件と M の WS 限定発言20件を交互に（H・M とも20ターン）
const hMsgs = [];
const mWs = [];
for (let i = 0; i < 20; i++) {
  // 攻撃: M の WS 限定発言は 500字 × 20件 = 10,000字（maxChars ちょうど）
  // 対照: M の WS 発言は30字（上限に触れない）
  const text = withAttack ? `M-ws-${i}-`.padEnd(500, 'w') : `M ws chat line ${i} hello there`.padEnd(30, '.');
  mWs.push(await makeMsg(M, text, base + i * 4000 + 1000));
  hMsgs.push(await makeMsg(H, `H says hello number ${i} to everyone here`, base + i * 4000 + 2000));
}
// R と M の P2P の往復（R_k の10秒後に M の短い返事）
const T1 = base + 200000;
const rMsgs = [];
const mP2p = [];
for (let k = 0; k < 20; k++) {
  rMsgs.push(await makeMsg(R, `R reply number ${k} about the topic`, T1 + k * 20000));
  mP2p.push(await makeMsg(M, `M answer ${k}`, T1 + k * 20000 + 10000));
}

// ---- 受領証明（各発言の5秒後・±10分の内） ----
const rc = [];
const add = (x) => { rc.push(x); return x; };
const receiptsBy = { [R.uid]: [], [M.uid]: [], [H.uid]: [] };
for (const m of [...hMsgs, ...mWs, ...rMsgs, ...mP2p]) {
  for (const receiver of players) {
    if (receiver.uid === m.uid) continue;
    // R は M の WS 限定発言を見ない＝受領証明も出さない
    if (receiver === R && mWs.includes(m)) continue;
    // H（公式）は上限の外の発言に既読を出さない（useGameWebSocket の cappedCurrent）。
    // 攻撃では M の P2P 返事が H の手元で上限外になる。
    if (receiver === H && withAttack && mP2p.includes(m)) continue;
    // M（攻撃者）は既読を一切出さない（協力しない）
    if (receiver === M) continue;
    receiptsBy[receiver.uid].push(add(await readReceipt(receiver, m, m.timestamp + 5000)));
  }
}
// ---- 投票（R→H・M→H・H→R）と受領証明 ----
const votes = {
  [R.uid]: await makeAction(R, 'vote', { targetUid: H.uid }, T1 + 1),
  [M.uid]: await makeAction(M, 'vote', { targetUid: H.uid }, T1 + 2),
  [H.uid]: await makeAction(H, 'vote', { targetUid: R.uid }, T1 + 3),
};
const voteReceipts = [
  add(await actionReceipt(H, R, votes[R.uid], T1 + 5000)),
  add(await actionReceipt(H, M, votes[M.uid], T1 + 5001)),
  add(await actionReceipt(R, H, votes[H.uid], T1 + 5002)),
];

// ---- 各自の見えている集合 ----
// R（復元・WS なし）: M の WS 限定発言が無い。受領証明は P2P で配られるので全員分が届くが、
// M の WS 限定発言への H の受領証明は R の手元では対象不明（運べない）になる。
let rView = sortCanon([...hMsgs, ...rMsgs, ...mP2p]);
const p2pOnlyView = rView;
const allMsgs = sortCanon([...hMsgs, ...mWs, ...rMsgs, ...mP2p]);
const recovery = new RecoveryRelay({ signKey: R.signKey, blockNum, groupId, uid: R.uid, members });
recovery.messages = rView;
const mixedRefs = [refOf(mWs[0]), `0x${'f'.repeat(32)}`].sort(P.compareHexAsc);
const mixedSignature = await H.signAccount.signMessage({
  message: P.readReceiptSignString(blockNum, groupId, H.uid, M.uid, mixedRefs, mWs[0].timestamp + 5000),
});
const mixedReceipt = { receiverUid: H.uid, senderUid: M.uid, msgRefs: mixedRefs,
  timestamp: mWs[0].timestamp + 5000, signature: mixedSignature };
const live = { blockNum, groupId, updatedAt: Date.now(), messages: mWs,
  actions: { votes: {}, reports: {} }, receipts: [...rc, mixedReceipt] };
if (process.env.T2_MUTATE_NO_INGEST !== '1') await recovery.ingestLiveSnapshot(live);
rView = recovery.getMessages();
assert.equal(rView.length, allMsgs.length, 'signed WS messages join recovery collection');

// ---- R の手元の数（myReceiptedChatProgress と同じ式。画面の X はこれと g から作る） ----
const chatWindow = { startMs: base - 3600000, endMs: base + 86400000 };
const readers = P.buildReceiptMaps(recovery.getReceipts(), { messages: rView, myUid: R.uid }, blockNum, groupId, chatWindow).readersByMsgKey;
const receiptedMsgs = P.clientScoreableMessages(rView, recovery.getReceipts(), {
  blockNum, groupId, myUid: R.uid, chatWindow,
  caps: CC.normalizeChatCaps(DEFAULTS.pins.chatCaps), compare: cmp,
});
const displayTurns = CC.countMessageTurns(CC.filterVisibleMessages(receiptedMsgs))[R.uid] || 0;
const displayChars = receiptedMsgs.filter((x) => x.uid === R.uid).reduce((s, x) => s + CC.countVisibleChars(x.text || ''), 0);
const { hasTimestampVisibleConfirmedVote } = await import(`${CT}/src/recovery/app.js`);
const reportVote = { encrypted: 'vote-cipher', timestamp: Date.now() - 1 };
assert.equal(hasTimestampVisibleConfirmedVote({ votes: [reportVote], ownUid: R.uid,
  targetUid: M.uid, nowMs: Date.now(), receiptorsForVote: () => ['third'] }), true,
  'report eligibility accepts a visible vote with a third-party receipt');
assert.equal(hasTimestampVisibleConfirmedVote({ votes: [reportVote], ownUid: R.uid,
  targetUid: M.uid, nowMs: Date.now(), receiptorsForVote: () => [R.uid] }), false,
  'the viewer cannot confirm the target vote alone');

// 対照: WS も見える端末（公式クライアントで WS に繋がっている R）なら同じ式で何と出るか。
// 第10ラウンド O-4 が荷重部材とした「標的の画面にも出る」の確認。
const receiptedFull = P.clientScoreableMessages(allMsgs, rc, {
  blockNum, groupId, myUid: R.uid, chatWindow, caps: CC.GUEST_PINNED_RULES, compare: cmp,
});
const displayTurnsWithWs = CC.countMessageTurns(CC.filterVisibleMessages(receiptedFull))[R.uid] || 0;

// ---- 提出物 ----
// R: 復元クライアントの buildSubmissionBundle の実物（R の見えている集合）
const rBuilt = await buildSubmissionBundle({
  blockNum, groupId, myUid: R.uid, encryptKey: R.encryptKey,
  members, messages: rView, myDepositIds: JSON.parse(R.depIds).ids,
  myVote: votes[R.uid], myVotePrev: [], myReports: [],
  observedActions: { votes: { [M.uid]: votes[M.uid], [H.uid]: votes[H.uid] }, reports: {} },
  receipts: recovery.getReceipts(), intent: { vote: H.uid, reports: [] },
  chatCaps: DEFAULTS.pins.chatCaps, chatWindow,
  submittedAt: T1 + 999999,
  signWallet: async (message) => R.wallet.signMessage({ message }),
});
const ingressIndex = buildMembersIndex([{ group_id: groupId, members }]);
assert.equal((await validateResultBundle(rBuilt.payload, blockNum, ingressIndex, R.addr)).valid, true,
  'snapshot-enriched honest submission passes ingress');

// H・M: 公式クライアント相当（全発言を見て、GUEST_PINNED_RULES で上限を掛けた集合を運ぶ）
const cappedSet = (list) => {
  const kept = CC.applyChatCaps(list, CC.GUEST_PINNED_RULES, cmp);
  return sortCanon(kept);
};
const makeOfficialSubmission = async (p) => {
  const msgs = cappedSet(allMsgs);
  const carried = new Set(msgs.map((m) => `${m.uid}|${refOf(m)}`));
  const actionHashes = new Set(Object.entries(votes).map(([u, a]) => P.actionHashV2('vote', blockNum, groupId, u, a.encrypted, a.timestamp)));
  const receipts = rc.filter((x) => (x.msgRefs
    ? x.msgRefs.every((r) => carried.has(`${x.senderUid}|${r}`))
    : actionHashes.has(x.actionHash)));
  const snapshot = { votes: { [p.uid]: votes[p.uid] }, reports: {}, observed: { votes: {}, reports: {}, receipts: [] } };
  for (const q of players) if (q.uid !== p.uid) snapshot.observed.votes[q.uid] = [votes[q.uid]];
  snapshot.observed.receipts = [...receipts].sort((a, b) => (a.signature < b.signature ? -1 : a.signature > b.signature ? 1 : 0));
  const submittedAt = T1 + 999999;
  const chatHash = P.computeChatHashV2(msgs, blockNum, groupId);
  const encryptedDataHash = keccak256(toHex(JSON.stringify(snapshot)));
  const depositIds = JSON.parse(p.depIds).ids;
  const dataString = JSON.stringify({ blockNum, uid: p.uid, encryptKey: p.encryptKey, chatHash, submittedAt, encryptedDataHash, depositIds });
  const signature = await p.wallet.signMessage({ message: dataString });
  return { uid: p.uid, encryptKey: p.encryptKey, chatHash, signature, submittedAt, encryptedDataHash, depositIds, encryptedActions: snapshot,
    messages: msgs.map((m) => ({ type: 'chat', blockNum, groupId, uid: m.uid, text: m.text, timestamp: m.timestamp, signature: m.signature })) };
};

const submissions = {
  [R.uid]: rBuilt.bundle,
  [M.uid]: await makeOfficialSubmission(M),
  [H.uid]: await makeOfficialSubmission(H),
};
const gd = { members, submissions, meta: { blockNum, groupId } };
const { results } = await calculateGroupResults(gd, MIN_CHARS, MIN_MESSAGES, {}, chatWindow);
const byUid = Object.fromEntries(results.map((r) => [r.uid, r]));

const rBundleMsgs = rBuilt.bundle.messages;
console.log(`mode=${withAttack ? 'attack' : 'control'}`);
console.log(`R bundle messages: total=${rBundleMsgs.length} R=${rBundleMsgs.filter((m) => m.uid === R.uid).length} Mp2p=${rBundleMsgs.filter((m) => m.uid === M.uid).length}`);
console.log(`R display (recovery app formula): turns=${displayTurns}/${MIN_MESSAGES} chars=${displayChars}/${MIN_CHARS}`);
console.log(`R display if the same formula saw the WS messages too (official client with WS): turns=${displayTurnsWithWs}/${MIN_MESSAGES}`);
for (const p of players) {
  const r = byUid[p.uid];
  console.log(`score ${p.uid === R.uid ? 'R' : p.uid === M.uid ? 'M' : 'H'}: dq=${r.isDisqualified} reason=${r.disqualifyReason || '-'} keys=${Object.keys(r).filter((k)=>/turn|mess|char|point|total/i.test(k)).map((k)=>k+":"+JSON.stringify(r[k])).join(",")}`);
}
const verdict = displayTurns >= MIN_MESSAGES && displayChars >= MIN_CHARS && byUid[R.uid].isDisqualified;
console.log(`RESULT: ${verdict ? 'REPRODUCED (display says R met both minimums; scoring disqualifies R)' : 'NOT_REPRODUCED'}`);

assert.equal(displayTurns, withAttack ? 1 : 20, 'recovery turn display matches capped canonical union');
assert.equal(byUid[R.uid].disqualifyReason, withAttack ? 'min_messages' : null, 'scoring input stays valid');
assert(rBuilt.bundle.messages.some((m) => m.uid === M.uid && m.text === mWs[0].text), 'WS message carried by recovery submission');
assert(rBuilt.bundle.encryptedActions.observed.receipts.some((x) => x.receiverUid === H.uid && x.msgRefs?.includes(refOf(mWs[0]))), 'honest other-reader receipt retained');
const carriedReceiptSigs = new Set(rBuilt.bundle.encryptedActions.observed.receipts.map((x) => x.signature));
assert(receiptsBy[H.uid].every((x) => carriedReceiptSigs.has(x.signature)),
  'all honest other-reader chat receipts for carried messages remain');
assert(!rBuilt.bundle.encryptedActions.observed.receipts.some((x) => x.signature === mixedSignature),
  'other-reader receipt with an invalid reference cannot displace honest receipt');

const p2pBundle = await buildSubmissionBundle({
  blockNum, groupId, myUid: R.uid, encryptKey: R.encryptKey,
  members, messages: p2pOnlyView, myDepositIds: JSON.parse(R.depIds).ids,
  myVote: votes[R.uid], myVotePrev: [], myReports: [],
  observedActions: { votes: { [M.uid]: votes[M.uid], [H.uid]: votes[H.uid] }, reports: {} },
  receipts: rc, intent: { vote: H.uid, reports: [] },
  chatCaps: DEFAULTS.pins.chatCaps, chatWindow, submittedAt: T1 + 999999,
  signWallet: async (message) => R.wallet.signMessage({ message }),
});
assert.equal((await validateResultBundle(p2pBundle.payload, blockNum, ingressIndex, R.addr)).valid, true,
  'P2P-only honest submission passes ingress');
const p2pRefs = new Set(p2pOnlyView.map(refOf));
const p2pReceiptSigs = new Set(p2pBundle.bundle.encryptedActions.observed.receipts.map((x) => x.signature));
assert(receiptsBy[H.uid].filter((x) => x.msgRefs.every((ref) => p2pRefs.has(ref)))
  .every((x) => p2pReceiptSigs.has(x.signature)), 'P2P-only bundle keeps all known honest other-reader receipts');
const p2pScore = await calculateGroupResults({ members, submissions: { ...submissions, [R.uid]: p2pBundle.bundle }, meta: { blockNum, groupId } }, MIN_CHARS, MIN_MESSAGES, {}, chatWindow);
assert.equal(p2pScore.results.find((x) => x.uid === R.uid).disqualifyReason,
  withAttack ? 'min_messages' : null, 'P2P-only honest bundle passes ingress');

const freshRelay = () => new RecoveryRelay({ signKey: R.signKey, blockNum, groupId, uid: R.uid, members });
const invalidSig = { ...mWs[0], signature: `0x${'0'.repeat(130)}` };
const outsider = { ...mWs[0], uid: 'outsider' };
const wrongBlock = { ...mWs[0], blockNum: blockNum + 1 };
const wrongGroup = { ...mWs[0], groupId: groupId + 1 };
const future = await makeMsg(M, 'future chat', Date.now() + 121_000);
const trustRelay = freshRelay();
if (process.env.T2_MUTATE_SKIP_SIGNATURE === '1') trustRelay._verifyChat = async () => true;
const validReport = await makeAction(M, 'report', { targetUid: H.uid }, T1 + 4);
const futureVote = await makeAction(M, 'vote', { targetUid: H.uid }, Date.now() + 121_000);
await trustRelay.ingestLiveSnapshot({ ...live,
  messages: [mWs[0], invalidSig, outsider, wrongBlock, wrongGroup, future],
  actions: { votes: { [M.uid]: votes[M.uid], [`${M.uid}__extras`]: [futureVote] },
    reports: { [M.uid]: [validReport, { ...validReport, groupId: groupId + 1 }] } },
  receipts: [receiptsBy[H.uid].find((x) => x.msgRefs?.includes(refOf(mWs[0]))), { ...rc[0], signature: invalidSig.signature }],
});
assert.equal(trustRelay.getMessages().length, 1, 'bad signature, outsider, wrong block/group and future chat rejected');
assert.equal(trustRelay.getRelayActionsRaw().votes[M.uid]?.signature, votes[M.uid].signature, 'valid public action accepted');
assert.equal(trustRelay.getRelayActionsRaw().votes[`${M.uid}__extras`]?.length || 0, 0, 'future action rejected');
assert.equal(trustRelay.getRelayActionsRaw().reports[M.uid]?.length, 1, 'valid report accepted; wrong-group report rejected');
assert.equal(trustRelay.getReceipts().length, 1, 'valid other-reader receipt accepted; bad signature rejected');

const cappedRelay = freshRelay();
await cappedRelay.ingestLiveSnapshot({ ...live,
  messages: [...Array.from({ length: 1201 }, () => ({ ...invalidSig })), mWs[0], hMsgs[0]],
  actions: {}, receipts: [],
});
assert.deepEqual(cappedRelay.getMessages().map((x) => x.uid), [H.uid], 'one actor over cap cannot consume another actor budget');

const rollbackRelay = freshRelay();
rollbackRelay.messages = [hMsgs[0]]; // P2P で先に受け取ったものは残す
await rollbackRelay._ingestReceiptArrivals([rc.find((x) => x.receiverUid === R.uid)]);
const p2pReceiptCount = rollbackRelay.getReceipts().length;
await rollbackRelay.ingestLiveSnapshot({ ...live, messages: [hMsgs[0], mWs[0]],
  actions: { votes: { [M.uid]: votes[M.uid] }, reports: {} },
  receipts: [rc.find((x) => x.receiverUid === H.uid)] });
assert.equal(rollbackRelay.getMessages().length, 2);
assert.equal(rollbackRelay.getRelayActionsRaw().votes[M.uid]?.signature, votes[M.uid].signature);
rollbackRelay.clearLiveSnapshot();
assert.deepEqual(rollbackRelay.getMessages().map((x) => x.signature), [hMsgs[0].signature], 'failed next read returns to P2P messages');
assert.equal(rollbackRelay.getReceipts().length, p2pReceiptCount, 'failed next read removes only live receipts');
assert.equal(Object.keys(rollbackRelay.getRelayActionsRaw().votes).length, 0, 'failed next read removes live actions');

const realFetch = globalThis.fetch;
const fetchCase = async (response, expected) => {
  globalThis.fetch = async () => response;
  let failed = false;
  try { await readLiveSnapshot({ r2Base: 'https://example.invalid', blockNum, groupId, nowMs: Date.now() }); }
  catch { failed = true; }
  assert.equal(failed, expected);
};
try {
  await fetchCase(new Response('missing', { status: 404 }), true);
  await fetchCase(new Response('{broken', { status: 200 }), true);
  await fetchCase(new Response('x'.repeat(LIVE_SNAPSHOT_MAX_BYTES + 1), { status: 200 }), true);
  await fetchCase(new Response(JSON.stringify(live), { status: 200 }), false);
  await fetchCase(new Response(JSON.stringify({ ...live, updatedAt: 1 }), { status: 200 }), true);
} finally { globalThis.fetch = realFetch; }

const appSource = readFileSync(process.env.T1E_APP_SOURCE || `${CT}/src/recovery/app.js`, 'utf8');
const officialSource = readFileSync(`${CT}/../src/hooks/useGameWebSocket.js`, 'utf8');
assert.match(officialSource, /connectionStatus === 'connected'\) return undefined;/,
  'U-10: official client never polls while WebSocket is open');
assert.match(officialSource, /verifyLiveSnapshotEntries\(snapshot, \{/,
  'U-10: official and recovery clients share the same live entry gate');
assert.match(officialSource, /setInterval\(poll, LIVE_SNAPSHOT_POLL_MS\)/,
  'U-10: disconnected official client retries about every 30 seconds');
const actionStart = appSource.indexOf('async function issueActionReceipt(');
const actionEnd = appSource.indexOf('async function issueReadReceiptBatch(', actionStart);
assert(actionStart >= 0 && actionEnd > actionStart);
const guardedActionReceipt = new Function('state', 'rosterReady',
  `${appSource.slice(actionStart, actionEnd)}\nreturn issueActionReceipt;`)(
  { identity: {}, relay: { isLiveOnlyAction: () => true, publishReceipt: () => { throw new Error('P2P amplification'); } }, uid: R.uid },
  () => true,
);
await guardedActionReceipt(M.uid, 'vote', votes[M.uid]);
const readStart = appSource.indexOf('async function issueReadReceiptBatch(');
const readEnd = appSource.indexOf('// 既読マップ:', readStart);
assert(readStart >= 0 && readEnd > readStart);
let p2pReceiptsPublished = 0;
const readBindings = {
  state: { identity: { signKey: R.signKey }, uid: R.uid, blockNum, groupId, away: false,
    messageReceiptableAt: new Map(), receipts: {}, members: [{ uid: R.uid }, { uid: M.uid }],
    cfg: { pins: { chatCaps: DEFAULTS.pins.chatCaps } }, issuedReadMsgKeys: new Set(),
    relay: { getMessages: () => [mWs[0]], isLiveOnlyMessage: () => true,
      getMsgKey: (m) => P.computeMsgKeyV2(blockNum, groupId, m),
      publishReceipt: async () => { p2pReceiptsPublished++; } } },
  rosterReady: () => true, currentPhase: () => 'chatting',
  submissionChatCloseAt: () => null,
  canIssueReceiptAtChainTip: async () => true,
  clientReceiptableMessages: (msgs) => msgs,
  recoveryAdmittedReceipts: () => Object.values(readBindings.state.receipts),
  chatWindowMsFromTimeline: () => null,
  submissionChatWindow: () => null,
  normalizeChatCaps: (caps) => caps,
  canonicalComparatorV2: () => () => 0, buildMsgKeyGetter: () => () => '',
  isReceiptTimely: () => true, msgRefOf: P.msgRefOf, computeMsgKeyV2: (_b, _g, m) => P.computeMsgKeyV2(blockNum, groupId, m),
  privateKeyToAccount: () => ({ signMessage: async () => 'signature' }),
  compareHexAsc: P.compareHexAsc, canonicalizeSignature: (x) => x,
  readReceiptSignString: () => 'signed', log: (message) => { throw new Error(message); },
  clientNow: () => Date.now(),
  recoveryClock: { getClockCorrection: () => 0 },
  receiptIssuanceBlocked: () => false,
  nextReadReceiptTimestamp: ({ clockMs }) => clockMs,
};
const guardedReadReceipt = new Function(...Object.keys(readBindings),
  `${appSource.slice(readStart, readEnd)}\nreturn issueReadReceiptBatch;`)(...Object.values(readBindings));
await guardedReadReceipt();
assert.equal(p2pReceiptsPublished, 0, 'live-only message does not consume a P2P receipt slot');
const pollStart = appSource.indexOf('async function pollLiveSnapshot() {');
const pollEnd = appSource.indexOf('// ============================================================\n// 観測データ', pollStart);
assert(pollStart >= 0 && pollEnd > pollStart);
const pollSource = appSource.slice(pollStart, pollEnd);
let fallbackReceipts = [
  { signature: 'live-read', receiverUid: R.uid, senderUid: M.uid,
    msgRefs: ['live-only', 'kept'], _liveOnly: true },
  { signature: 'live-action', receiverUid: R.uid, actionHash: 'live-hash', _liveOnly: true },
  { signature: 'p2p-read', receiverUid: R.uid, senderUid: M.uid, msgRefs: ['kept'] },
  { signature: 'p2p-action', receiverUid: R.uid, actionHash: 'kept-hash' },
];
const fallbackState = { relay: { getMessages: () => p2pOnlyView, getReceipts: () => fallbackReceipts,
  getRelayActionsRaw: () => ({ votes: {}, reports: {} }),
  clearLiveSnapshot: () => { fallbackReceipts = fallbackReceipts.filter((receipt) => !receipt._liveOnly); },
  ingestLiveSnapshot: async () => { throw new Error('must not ingest'); } },
  uid: R.uid, issuedReadMsgKeys: new Set([`${M.uid}|live-only`, `${M.uid}|kept`]),
  issuedActionHashes: new Set(['live-hash', 'kept-hash']),
  cfg: { r2Base: 'https://example.invalid' }, blockNum, groupId, timeline: {},
  liveSnapshotLastAttempt: 0, liveSnapshotPending: null, liveSnapshotUnread: false };
let rendered = 0;
let liveReads = 0;
let readNowMs = 0;
const pollFallback = new Function('state', 'rosterReady', 'currentPhase', 'LIVE_SNAPSHOT_POLL_MS',
  'receiptIdentityDigest',
  'submissionChatWindow', 'readLiveSnapshot', 'renderGame', 'clientNow', `${pollSource}\nreturn pollLiveSnapshot;`)(
  fallbackState, () => true, () => 'chatting', 30_000, (receipt) => receipt.signature,
  () => ({ startMs: base }),
  async (options) => { liveReads++; readNowMs = options.nowMs; throw new Error('HTTP 404'); },
  () => { rendered++; }, () => Date.now(),
);
await pollFallback();
assert(fallbackState.liveSnapshotUnread && rendered === 1 && fallbackState.relay.getMessages().length === 60,
  'unavailable public snapshot leaves P2P display and submission path running');
assert(fallbackState.issuedReadMsgKeys.has(`${M.uid}|live-only`)
  && fallbackState.issuedReadMsgKeys.has(`${M.uid}|kept`)
  && fallbackState.issuedActionHashes.has('live-hash')
  && fallbackState.issuedActionHashes.has('kept-hash')
  && fallbackReceipts.length === 4,
  'failed refresh retains last successful live receipts and issuance markers');
assert(readNowMs >= Date.now() + 119000,
  'recovery live read gets the same two-minute clock allowance as official client');
await pollFallback();
assert.equal(liveReads, 1, 'public snapshot is not reread before the 30-second interval');

// T2: live-first chat becomes receiptable only after the same four signed fields arrive by relay.
const beforeRecoverySource = readFileSync(process.env.T2_RECOVERY_SOURCE
  || new URL('../src/recovery/relay-client.js', import.meta.url), 'utf8');
const oldAcceptedStart = beforeRecoverySource.indexOf('      isAccepted: (type, inner) => {');
const oldAcceptedEnd = beforeRecoverySource.indexOf('\n      },', oldAcceptedStart);
const oldIngestStart = beforeRecoverySource.indexOf('  async _ingestChat(msg, { fromLive = false } = {}) {');
const oldIngestEnd = beforeRecoverySource.indexOf('\n  _mergeLiveMessage(msg)', oldIngestStart);
assert(oldAcceptedStart >= 0 && oldAcceptedEnd > oldAcceptedStart
  && oldIngestStart >= 0 && oldIngestEnd > oldIngestStart, 'T2 before source has both cut points');
const oldAccepted = beforeRecoverySource.slice(oldAcceptedStart + '      isAccepted: '.length, oldAcceptedEnd + 8)
  .replace(/,\s*$/, '')
  .replace('if (known && this.liveOnlySignatures.delete(inner.signature)) this.onUpdate?.();', '');
const oldIngest = beforeRecoverySource.slice(oldIngestStart, oldIngestEnd)
  .replace('if (!fromLive && this.liveOnlySignatures.delete(msg.signature)) this.onUpdate?.();', '');
const keepAccepted = process.argv.includes('--mutation=t2-recovery-liveonly-keep') || !!process.env.T2_RECOVERY_SOURCE;
const keepIngest = process.argv.includes('--mutation=t2-recovery-ingest-keep') || !!process.env.T2_RECOVERY_SOURCE;
const senderNostr = deriveNostrKey(M.signKey, blockNum);
const relayEvent = (message) => buildEvent(senderNostr.sk, senderNostr.pubkey,
  [['t', groupTag(blockNum, groupId)]], JSON.stringify(message), Math.floor(message.timestamp / 1000));
const recoveryLive = { blockNum, groupId, messages: [mWs[0]],
  actions: { votes: {}, reports: {} }, receipts: [] };
const makeLiveFirstRecovery = async () => {
  let updates = 0;
  const relay = new RecoveryRelay({ signKey: R.signKey, blockNum, groupId, uid: R.uid,
    members, now: () => base + 5000, onUpdate: () => { updates++; } });
  await relay.ingestLiveSnapshot(recoveryLive);
  assert.equal(relay.isLiveOnlyMessage(mWs[0]), true, 'T2: live arrival sets the mark');
  const priorWebSocket = globalThis.WebSocket;
  globalThis.WebSocket = class { static OPEN = 1; constructor() { this.readyState = 0; }
    addEventListener() {} close() { this.readyState = 3; } };
  try { await relay.start(); } finally { globalThis.WebSocket = priorWebSocket; }
  if (keepAccepted) {
    relay.channel.isAccepted = new Function('type', 'inner', `return (${oldAccepted})(type, inner);`).bind(relay);
  }
  if (keepIngest) relay._ingestChat = new Function(`return ({ ${oldIngest} })._ingestChat;`)();
  return { relay, updates: () => updates };
};
const recovered = await makeLiveFirstRecovery();
const recoveredState = readBindings.state;
recoveredState.relay = recovered.relay;
recoveredState.ownSessionReadSignatures = new Set();
recoveredState.ownSessionSignatures = new Set();
const recoveryBindings = { ...readBindings, sessionStorage: { getItem: () => null, setItem: () => {} },
  performance: { now: () => 0 } };
const issueRecoveredRead = new Function(...Object.keys(recoveryBindings),
  `${appSource.slice(readStart, readEnd)}\nreturn issueReadReceiptBatch;`)(...Object.values(recoveryBindings));
const recoveredPublished = [];
recovered.relay.publishReceipt = async (receipt) => { recoveredPublished.push(receipt); };
await issueRecoveredRead();
assert.equal(recoveredPublished.length, 0, 'T2: live-only recovery chat has no read receipt');
let reverified = 0, chatted = 0, revisitedFuture = 0;
const actualVerify = recovered.relay.channel.verifyInnerSignature;
const actualChat = recovered.relay.channel.onChat;
const actualFuture = recovered.relay.futureMarks.noteEvent.bind(recovered.relay.futureMarks);
recovered.relay.channel.verifyInnerSignature = async (...args) => { reverified++; return actualVerify(...args); };
recovered.relay.channel.onChat = async (...args) => { chatted++; return actualChat(...args); };
recovered.relay.futureMarks.noteEvent = (...args) => { revisitedFuture++; return actualFuture(...args); };
const updatesBefore = recovered.updates();
await recovered.relay.channel._handleEvent(relayEvent(mWs[0]));
assert.deepEqual([reverified, chatted, revisitedFuture], [0, 0, 0],
  'T2: known relay delivery stays ahead of reverify, onChat and future marks');
assert.equal(recovered.relay.isLiveOnlyMessage(mWs[0]), false, 'T2: relay removes the recovery mark');
assert.equal(recovered.updates(), updatesBefore + 1, 'T2: removal notifies the recovery view once');
await issueRecoveredRead();
assert.equal(recoveredPublished.length, 1, 'T2: the real recovery batch can read the relayed chat');
await recovered.relay.ingestLiveSnapshot(recoveryLive);
assert.equal(recovered.relay.isLiveOnlyMessage(mWs[0]), false, 'T2: relay then live remains unmarked');
recovered.relay.stop();
const mismatched = await makeLiveFirstRecovery();
for (const altered of [{ uid: R.uid }, { text: 'changed' }, { timestamp: mWs[0].timestamp + 1 },
  { signature: `${mWs[0].signature}00` }]) {
  await mismatched.relay.channel._handleEvent(relayEvent({ ...mWs[0], ...altered }));
  assert.equal(mismatched.relay.isLiveOnlyMessage(mWs[0]), true,
    'T2: a different field cannot remove the recovery mark');
}
mismatched.relay.stop();
const direct = await makeLiveFirstRecovery();
const directUpdates = direct.updates();
await direct.relay._ingestChat(mWs[0], { fromLive: true });
assert.equal(direct.relay.isLiveOnlyMessage(mWs[0]), true, 'T2: duplicate live arrival keeps the mark');
await direct.relay._ingestChat(mWs[0]);
assert.equal(direct.relay.isLiveOnlyMessage(mWs[0]), false, 'T2: direct known relay ingest removes the mark');
assert.equal(direct.updates(), directUpdates + 1, 'T2: direct removal notifies once');
direct.relay.stop();
console.log('live-snapshot-unit: E-2-01 ALL PASSED');

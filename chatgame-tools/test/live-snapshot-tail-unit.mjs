// S3R1-E-2r probe A の旧失敗盤面: 先頭だけの間引きでは、参加者 M が公開直後の
// 30秒内に WS 限定の発言を流し、その後 WS の出来事がなければスナップショットは古いまま。
// 復元クライアントは古い版を受理する。末尾公開後は R の画面が採点と同じ 1/20 になる。
// HEAD の現物: chat-game-DO.js の publishLiveSnapshot 本体をそのまま切り出して動かす。
// relay-client.js の readLiveSnapshot / ingestLiveSnapshot と bundle.js・calculator の実物を使う。
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
const HEADROOT = new URL('../../', import.meta.url).pathname;
const HEAD = `${HEADROOT}chatgame-tools/`;
const { makePlayer } = await import(`${HEAD}test/scenario.mjs`);
const P = await import(`${HEAD}vendor/workers/game_workers/lib/protocol-v2.js`);
const CC = await import(`${HEAD}vendor/workers/game_workers/lib/char-counter.js`);
const { calculateGroupResults } = await import(`${HEAD}vendor/workers/game_workers/lib/game-result-calculator.js`);
const { buildSubmissionBundle } = await import(`${HEAD}src/recovery/bundle.js`);
globalThis.localStorage = { getItem: () => null, setItem: () => {} };
const { RecoveryRelay, readLiveSnapshot } = await import(`${HEAD}src/recovery/relay-client.js`);
const { DEFAULTS } = await import(`${HEAD}config.js`);

const blockNum = 5;
const groupId = 0;
const base = 1750000000000;
const MIN_CHARS = 500;
const MIN_MESSAGES = 20;
const chatWindow = { startMs: base - 3600000, endMs: base + 86400000 };
const R = await makePlayer('user0001', 0, 1.0, blockNum);
const M = await makePlayer('user0002', 1, 1.0, blockNum);
const H = await makePlayer('user0003', 2, 1.0, blockNum);
const players = [R, M, H];
const members = players.map((p) => ({ uid: p.uid, addr: p.addr, bAddr: p.bAddrString, depIds: p.depIds }));
const cmp = P.canonicalComparatorV2(P.buildMsgKeyGetter(blockNum, groupId));
const sortCanon = (list) => [...list].sort(cmp);
const refOf = (m) => P.msgRefOf(P.computeMsgKeyV2(blockNum, groupId, m));
const makeMsg = async (p, text, ts) => {
  const signature = await p.signAccount.signMessage({ message: P.chatSignStringV2(blockNum, groupId, p.uid, text, ts) });
  return { type: 'chat', blockNum, groupId, uid: p.uid, text, timestamp: ts, signature };
};
const readReceipt = async (receiver, msg, ts) => {
  const msgRefs = [refOf(msg)];
  const signature = await receiver.signAccount.signMessage({
    message: P.readReceiptSignString(blockNum, groupId, receiver.uid, msg.uid, msgRefs, ts),
  });
  return { receiverUid: receiver.uid, senderUid: msg.uid, msgRefs, timestamp: ts, signature };
};

// ---- 盤面（E-2-01 と同じ形。違いは H が M の WS 発言を受領した直後に離席すること） ----
const hMsgs = []; const mWs = [];
for (let i = 0; i < 20; i++) {
  mWs.push(await makeMsg(M, `M-ws-${i}-`.padEnd(500, 'w'), base + i * 4000 + 1000)); // 500字×20＝上限 10,000字
  hMsgs.push(await makeMsg(H, `H says hello number ${i} to everyone here`, base + i * 4000 + 2000));
}
const T1 = base + 200000;
const rMsgs = []; const mP2p = [];
for (let k = 0; k < 20; k++) {
  rMsgs.push(await makeMsg(R, `R reply number ${k} about the topic`, T1 + k * 20000));
  mP2p.push(await makeMsg(M, `M answer ${k}`, T1 + k * 20000 + 10000));
}
const receipts = [];
for (const m of hMsgs) for (const rc of [R, M]) receipts.push(await readReceipt(rc, m, m.timestamp + 5000));
const hOnMws = [];
for (const m of mWs) { const x = await readReceipt(H, m, m.timestamp + 5000); hOnMws.push(x); receipts.push(x); } // H は離席前に受領
for (const m of rMsgs) receipts.push(await readReceipt(M, m, m.timestamp + 5000)); // H は離席中。M が P2P で R に既読を出す
for (const m of mP2p) receipts.push(await readReceipt(R, m, m.timestamp + 5000));

// ---- ChatGameDO.publishLiveSnapshot の現物を切り出す ----
const doSrc = readFileSync(`${HEADROOT}workers/game_workers/chat-game-DO.js`, 'utf8');
const start = doSrc.indexOf('  async publishLiveSnapshot(force = false) {');
const end = doSrc.indexOf('  // ゲームデータをR2にアーカイブ', start);
if (start < 0 || end < 0) throw new Error('publishLiveSnapshot not found');
let clock = 0;
const FakeDate = { now: () => clock };
const debounceMs = Number(/const LIVE_SNAPSHOT_DEBOUNCE_MS = (\d+);/.exec(doSrc)[1]); // HEAD の値をそのまま読む
const alarmStart = doSrc.indexOf('  async armSnapshotAlarms() {');
const alarmEnd = doSrc.indexOf('  // force=false は', alarmStart);
assert(alarmStart >= 0 && alarmEnd > alarmStart, 'alarm methods exist');
const FakeDO = new Function('Date', 'isCanonicalActionCiphertext', 'safeJsonStringify', 'boundedError',
  'LIVE_SNAPSHOT_DEBOUNCE_MS', 'LIVE_SNAPSHOT_ALARM_KEY', 'SUBMISSION_SNAPSHOT_ALARM_KEY',
  `return class FakeDO { ${doSrc.slice(alarmStart, alarmEnd)} ${doSrc.slice(start, end)} };`)(
    FakeDate, () => true, (v) => JSON.stringify(v), (e) => String(e), debounceMs,
    'live_snapshot_alarm', 'live_submissions_snapshot_alarm');
const store = new Map();
const r2 = new Map();
const puts = [];
let alarmAt = null;
const doThis = Object.assign(new FakeDO(), {
  env: { R2_BUCKET: { put: async (key, body) => { r2.set(key, body); puts.push({ at: clock, key }); } } },
  storage: {
    get: async (k) => store.get(k),
    put: async (k, v) => { store.set(k, v); },
    delete: async (k) => { store.delete(k); },
    setAlarm: async (at) => { alarmAt = at; },
    deleteAlarm: async () => { alarmAt = null; },
    list: async ({ prefix }) => new Map([...store.entries()].filter(([k]) => k.startsWith(prefix)).sort(([a], [b]) => (a < b ? -1 : 1))),
  },
  recordDependencyOutcome: () => {}, recordStorageOutcome: () => {},
  loadMessages: async function () { return [...(await this.storage.list({ prefix: 'msg:' })).values()]; },
  loadReceipts: async function () { return [...(await this.storage.list({ prefix: 'rcpt:' })).values()]; },
  getConnectedUids: () => [], computeActiveUids: async () => [],
  minChars: 500, minMessages: 20, maxChars: 10000, maxMessages: 100, maxMsgChars: 1000,
});
store.set('meta', { blockNum, groupId });
store.set('members', members);
store.set('phase', 'chatting');
let msgId = 0;
const doChat = async (m) => { msgId++; store.set(`msg:${String(msgId).padStart(8, '0')}`, { id: msgId, uid: m.uid, text: m.text, timestamp: m.timestamp, charCount: CC.countHalfWidthChars(m.text), signature: m.signature }); await doThis.publishLiveSnapshot(); };
const doReceipt = async (rc) => { store.set(`rcpt:${rc.signature}`, rc); await doThis.publishLiveSnapshot(); };

// DO への到着（公開の時計）: T0 = ある時刻
const T0 = 1_900_000_000_000;
// H の WS 発言（到着 T0-100s..）と R/M の受領証明は WS には来ない（R は WS なし・M は WS で既読を出さない）
for (let i = 0; i < 20; i++) { clock = T0 - 100_000 + i * 3000; await doChat(hMsgs[i]); }
// M の「呼び水」: 既存の受領証明の再送（handleWsReceipt の exists 経路も ack の後に publishLiveSnapshot を呼ぶ）
clock = Math.max(...puts.map((p) => p.at)) + 30_000; const primeAt = clock;
await doThis.publishLiveSnapshot();
// 30秒の内側に M の WS 限定の発言20件と、H の受領証明20件
for (let i = 0; i < 20; i++) { clock = primeAt + 500 + i * 600; await doChat(mWs[i]); }
for (let i = 0; i < 20; i++) { clock = primeAt + 13_000 + i * 700; await doReceipt(hOnMws[i]); }
// その後 H は離席（受領証明を出さない）。R と M は P2P だけで話す＝DO への出来事なし。
assert.equal(alarmAt, primeAt + debounceMs, '間引いた最後の更新は窓明けを予約');
clock = alarmAt; await doThis.alarm();
assert.equal(alarmAt, null, '末尾公開後に重複予約を残さない');
assert.equal(puts.filter((p) => p.at >= primeAt && p.at <= primeAt + debounceMs).length, 2,
  '30秒窓の公開は先頭と末尾の2回');
const snapshotKey = `live/block${blockNum}/group${groupId}.json`;
const staleBody = r2.get(snapshotKey);
const stale = JSON.parse(staleBody);
console.log(`DO publishes: ${puts.length} (last at +${(Math.max(...puts.map((p) => p.at)) - primeAt) / 1000}s from priming) ; stored msgs=${msgId} ; snapshot msgs=${stale.messages.length} (M WS msgs in snapshot=${stale.messages.filter((m) => m.uid === M.uid).length}/20) ; snapshot receipts=${stale.receipts.length}`);

// ---- 復元 R の取得（30分後）: 古い版を受け入れ、警告は出ない ----
const pollAt = primeAt + 30 * 60_000;
const realFetch = globalThis.fetch;
globalThis.fetch = async () => new Response(staleBody, { status: 200 });
let accepted = true;
let fetched;
try { fetched = await readLiveSnapshot({ r2Base: 'https://r2.example', blockNum, groupId, chatStartMs: chatWindow.startMs, maxAgeMs: 26 * 3600_000, nowMs: pollAt }); }
catch (e) { accepted = false; console.log(`readLiveSnapshot threw: ${e.message}`); }
finally { globalThis.fetch = realFetch; }
const recovery = new RecoveryRelay({ signKey: R.signKey, blockNum, groupId, uid: R.uid, members });
recovery.messages = sortCanon([...hMsgs, ...rMsgs, ...mP2p]); // R の P2P 集合
await recovery._ingestReceiptArrivals(receipts.filter((x) => !hOnMws.includes(x))); // P2P で届いた受領証明
if (accepted) await recovery.ingestLiveSnapshot(fetched);
const view = recovery.getMessages();
const readers = P.buildReceiptMaps(recovery.getReceipts(), { messages: view, myUid: R.uid }, blockNum, groupId, chatWindow).readersByMsgKey;
const isReceipted = (m) => { const k = refOf(m); return readers[k] && [...readers[k]].some((u) => u !== m.uid); };
const receipted = CC.capMessagesForScoring(view, CC.normalizeChatCaps(DEFAULTS.pins.chatCaps), cmp).filter(isReceipted);
const turns = CC.countMessageTurns(CC.filterVisibleMessages(receipted))[R.uid] || 0;
const chars = receipted.filter((x) => x.uid === R.uid).reduce((s, x) => s + CC.countVisibleChars(x.text), 0);
console.log(`recovery R at +30min: snapshot accepted=${accepted} (liveSnapshotUnread stays false ⇒ no warning) ; R display turns=${turns}/${MIN_MESSAGES} chars=${chars}/${MIN_CHARS}`);

// ---- 提出（submitting への遷移は force で公開＝ここで初めて M の WS 発言が載る） ----
store.set('phase', 'submitting'); clock = primeAt + 24 * 3600_000;
await doThis.publishLiveSnapshot(true);
const fresh = JSON.parse(r2.get(snapshotKey));
await recovery.ingestLiveSnapshot(fresh);
{
  const v2 = recovery.getMessages();
  const rd2 = P.buildReceiptMaps(recovery.getReceipts(), { messages: v2, myUid: R.uid }, blockNum, groupId, chatWindow).readersByMsgKey;
  const ok2 = (m) => { const k = refOf(m); return rd2[k] && [...rd2[k]].some((u) => u !== m.uid); };
  const rec2 = CC.capMessagesForScoring(v2, CC.normalizeChatCaps(DEFAULTS.pins.chatCaps), cmp).filter(ok2);
  console.log(`control: once a fresh snapshot (forced at submitting) is ingested, R display turns=${CC.countMessageTurns(CC.filterVisibleMessages(rec2))[R.uid] || 0}/${MIN_MESSAGES} (too late: chat period is over)`);
}
const rBuilt = await buildSubmissionBundle({
  blockNum, groupId, myUid: R.uid, encryptKey: R.encryptKey, members, messages: recovery.getMessages(),
  myDepositIds: JSON.parse(R.depIds).ids, myVote: null, myVotePrev: [], myReports: [],
  observedActions: { votes: {}, reports: {} }, receipts: recovery.getReceipts(), intent: null,
  chatCaps: DEFAULTS.pins.chatCaps, chatWindow, submittedAt: base + 999999,
  signWallet: async (message) => R.wallet.signMessage({ message }),
});
const allMsgs = sortCanon([...hMsgs, ...mWs, ...rMsgs, ...mP2p]);
const hBuilt = await buildSubmissionBundle({
  blockNum, groupId, myUid: H.uid, encryptKey: H.encryptKey, members, messages: allMsgs,
  myDepositIds: JSON.parse(H.depIds).ids, myVote: null, myVotePrev: [], myReports: [],
  observedActions: { votes: {}, reports: {} }, receipts, intent: null,
  chatCaps: DEFAULTS.pins.chatCaps, chatWindow, submittedAt: base + 999999,
  signWallet: async (message) => H.wallet.signMessage({ message }),
});
const mBuilt = await buildSubmissionBundle({
  blockNum, groupId, myUid: M.uid, encryptKey: M.encryptKey, members, messages: allMsgs,
  myDepositIds: JSON.parse(M.depIds).ids, myVote: null, myVotePrev: [], myReports: [],
  observedActions: { votes: {}, reports: {} }, receipts, intent: null,
  chatCaps: DEFAULTS.pins.chatCaps, chatWindow, submittedAt: base + 999999,
  signWallet: async (message) => M.wallet.signMessage({ message }),
});
const { results } = await calculateGroupResults({ members, submissions: { [R.uid]: rBuilt.bundle, [H.uid]: hBuilt.bundle, [M.uid]: mBuilt.bundle }, meta: { blockNum, groupId } }, MIN_CHARS, MIN_MESSAGES, {}, chatWindow);
const r = results.find((x) => x.uid === R.uid);
console.log(`score R: dq=${r.isDisqualified} reason=${r.disqualifyReason || '-'}`);
assert(accepted, '復元は公開版を受理する');
assert.equal(stale.messages.filter((m) => m.uid === M.uid).length, 20, '30秒の末尾公開に M の WS 発言20件');
assert.equal(turns, 1, '復元の R はチャット中に 1/20 を表示');
assert.equal(r.disqualifyReason, 'min_messages', '採点盤面は元の探針と同じ');
// DO の alarm は1つ。提出写しと live の期限が競合しても早い方から実行する。
let submissionAlarms = 0;
doThis.publishSubmissionSnapshot = async () => { submissionAlarms++; };
const alarmBase = clock;
await doThis.scheduleLiveSnapshotAlarm(alarmBase + 60_000);
await doThis.scheduleSubmissionSnapshotAlarm(alarmBase + 30_000, 'unit');
assert.equal(alarmAt, alarmBase + 30_000, '提出写しの早い期限を維持');
clock = alarmAt; await doThis.alarm();
assert.equal(submissionAlarms, 1, '提出写しの期限で1回起動');
assert.equal(alarmAt, alarmBase + 60_000, '残る live の期限を再予約');
clock = alarmAt; await doThis.alarm();
assert.equal(alarmAt, null, '両方を処理した後に alarm を消す');
const secondBase = clock;
await doThis.scheduleSubmissionSnapshotAlarm(secondBase + 60_000, 'unit');
await doThis.scheduleLiveSnapshotAlarm(secondBase + 30_000);
assert.equal(alarmAt, secondBase + 30_000, 'live の早い期限を維持');
await doThis.clearSubmissionSnapshotAlarm();
assert.equal(alarmAt, secondBase + 30_000, '提出写しの取消で live の予約を消さない');
clock = alarmAt; await doThis.alarm();
assert.equal(submissionAlarms, 1, '取消済みの提出写しは起動しない');
assert.equal(alarmAt, null, 'live の末尾公開は1回だけ');
const bothDue = clock + 30_000;
await doThis.scheduleSubmissionSnapshotAlarm(bothDue, 'unit');
await doThis.scheduleLiveSnapshotAlarm(bothDue);
clock = bothDue; await doThis.alarm();
assert.equal(submissionAlarms, 2, '同じ期限なら提出写しも処理');
assert.equal(alarmAt, null, '同じ期限の2種類を1回の alarm で処理');
// R2 書込み失敗は採点や alarm 処理へ例外を返さない。
const savedPut = doThis.env.R2_BUCKET.put;
doThis.env.R2_BUCKET.put = async () => { throw new Error('unit R2 failure'); };
await doThis.scheduleLiveSnapshotAlarm(clock + 30_000);
clock += 30_000;
await doThis.alarm();
assert.equal(alarmAt, null, 'R2 失敗でも alarm が残留しない');
doThis.env.R2_BUCKET.put = savedPut;
console.log('live-snapshot-tail-unit: ALL PASSED');

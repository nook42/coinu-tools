// g4-ws-abuse-unit.mjs — G4是正（メンバーによるWSスパム連打対策）ユニットテスト
//
// 背景（総点検G4）: WS接続はメンバー限定＋認証済みだが、接続後の「無効署名」
// 「上限/重複を超えた再送」には上限が無く、毎回の署名検証（重いECDSA）等で
// グループDOのCPUを浪費できた（自グループDoS）。さらにチャット/密告/投票は
// 「署名検証→上限チェック」の順だったため、上限到達後の有効署名スパムにも
// 毎回検証CPUを払っていた。
//
// 本物の ChatGameDO をスタブ state 上で駆動して検証する:
//  T1: 無効署名チャット連打 — 10回まではエラー応答・11回目で1008切断
//  T2: 正規プレイは無影響 — 有効チャット連続受理／無効5発の後でも有効メッセージは通る
//  T3: 上限超え有効署名スパム — 上限到達後は安いチェックで拒否され、連打で切断
//  T4: 受領証明（v3.2） — 正規受領証明は受理・無効署名/なりすまし受領証明の連打は切断
//  T5: 投票の再送・冪等・10件上限・再接続後の初期配信
//  T6: 密告の再送・冪等・10件上限（署名検証前の拒否）
//  T7: ping総量キャップ — 5,000通で切断（それ以下は全てpong）
//  T8: スパム切断常習uidは接続拒否(429)・無関係uidは拒否されない
//  T9〜T13（R33-F-1-01・D-12・便 S3C11/S3C11b）: OPEN 4本なら本人の最も古い OPEN を4001で閉じる・
//      OPEN＋CLOSING 16本なら429・他の uid は無影響・在席・同時 upgrade も120回/分・
//      正直なつなぎ直しと Close 応答・close code のサーバー⇔クライアント一致
//
// 実行: node block-verifier/test/g4-ws-abuse-unit.mjs （Node 22）

import { ChatGameDO } from './canonical.mjs';
import { makeChatGameNamespace, makeFakeWs, authedRequest, TEST_API_SECRET } from './stubs.mjs';
import { makePlayer, makeChatWsData, makeActionWsData, makeReadReceipt, makeActionReceipt } from './players.mjs';

const BLOCK_NUM = 999;
const GROUP_ID = 0;

let passed = 0;
let failed = 0;
const ok = (name, cond, detail = '') => {
  if (cond) { passed++; console.log(`  ok: ${name}`); }
  else { failed++; console.error(`  FAIL: ${name}${detail ? ` — ${detail}` : ''}`); }
};

// 切断を記録できる偽ソケット
function makeWs(uid) {
  const ws = makeFakeWs(uid);
  ws.closes = [];
  ws.close = (code, reason) => { ws.closes.push({ code, reason }); ws.readyState = 2; };
  ws.errors = () => ws.sent.filter(m => m?.type === 'error');
  return ws;
}

// グループを初期化した本物のChatGameDOインスタンスを作る
async function makeGroup(env = {}, stateOptions = {}, ChatGameClass = ChatGameDO) {
  const players = [];
  for (let i = 0; i < 4; i++) {
    players.push(await makePlayer({ uid: `22000${i}01`, lang: 'ja', blockNum: BLOCK_NUM, keyIndex: i }));
  }
  const members = players.map((p, i) => ({
    uid: p.uid, addr: p.addr, bAddr: p.bAddrString, lang: p.lang,
    depIds: null, globalIndex: i, name: null, img: null, verified: false,
  }));
  // S3-002: ChatGameDO の HTTP 制御面は X-Api-Secret 必須（未設定は fail-closed で 401）
  const ns = makeChatGameNamespace(ChatGameClass, { RELEASE_TIME: '2099-01-01T00:00:00Z', API_SECRET: TEST_API_SECRET, ...env }, stateOptions);
  const inst = ns.instance(`${BLOCK_NUM}-${GROUP_ID}`);
  const res = await inst.fetch(authedRequest('https://do/init', {
    method: 'POST',
    body: JSON.stringify({
      blockNum: BLOCK_NUM, groupId: GROUP_ID, lang: 'ja', mixed: false, members,
      periodDurations: { gamePeriod: 600000, submitPeriod: 600000 },
    }),
  }));
  if (!res.ok) throw new Error(`init failed: ${await res.text()}`);
  return { inst, players };
}

const setPhase = async (inst, phase) => {
  const res = await inst.fetch(authedRequest('https://do/set-phase', {
    method: 'POST', body: JSON.stringify({ phase }),
  }));
  if (!res.ok) throw new Error(`set-phase(${phase}) failed: ${await res.text()}`);
};

let ts = 1750000000000;

// ---- T1+T2: 無効署名チャット連打で切断・正規プレイは無影響 ----
{
  const { inst, players } = await makeGroup();
  await setPhase(inst, 'chatting');
  const [attacker, honest] = players;

  // T1: 無効署名を11発
  const wsA = makeWs(attacker.uid);
  for (let i = 0; i < 11; i++) {
    const data = await makeChatWsData(attacker, BLOCK_NUM, GROUP_ID, `spam${i}`, ts++);
    data.signature = '0x' + 'ab'.repeat(65); // 壊した署名
    await inst.handleWsChat(wsA, attacker.uid, data);
  }
  ok('T1 無効署名10回まではエラー応答のみ・11回目で1008切断',
    wsA.errors().length === 10 && wsA.closes.length === 1 && wsA.closes[0].code === 1008,
    `errors=${wsA.errors().length} closes=${JSON.stringify(wsA.closes)}`);

  // T2a: 正規メンバーの有効チャットは全件受理
  const wsH = makeWs(honest.uid);
  let hErrors = 0;
  for (let i = 0; i < 20; i++) {
    await inst.handleWsChat(wsH, honest.uid, await makeChatWsData(honest, BLOCK_NUM, GROUP_ID, `hello${i}`, ts++));
    if (wsH.errors().length > 0) hErrors++;
  }
  ok('T2 正規チャット20件は全件受理・切断なし', hErrors === 0 && wsH.closes.length === 0);

  // T2b: 無効5発（<10）の後でも有効メッセージは通る（閾値未満は機能に影響しない）
  const p3 = players[2];
  const ws3 = makeWs(p3.uid);
  for (let i = 0; i < 5; i++) {
    const bad = await makeChatWsData(p3, BLOCK_NUM, GROUP_ID, `x${i}`, ts++);
    bad.signature = '0x' + 'cd'.repeat(65);
    await inst.handleWsChat(ws3, p3.uid, bad);
  }
  const before = ws3.sent.length;
  await inst.handleWsChat(ws3, p3.uid, await makeChatWsData(p3, BLOCK_NUM, GROUP_ID, 'legit', ts++));
  const newErr = ws3.sent.slice(before).some(m => m?.type === 'error');
  ok('T2b 閾値未満の失敗後も有効メッセージは受理', !newErr && ws3.closes.length === 0);
}

// ---- T3: 上限超え有効署名スパム（本番 pin: GAME_MAX_MESSAGES=100） ----
{
  const t3StartedAt = performance.now();
  const { inst, players } = await makeGroup();
  await setPhase(inst, 'chatting');
  const p = players[0];
  const ws = makeWs(p.uid);
  // 署名生成を99回繰り返さず上限直下を再現する。境界の100通目は本番と同じ
  // handleWsChat を通し、署名検証・保存・カウンタ更新を実行する。
  const messageCounts = await inst.storage.get('messageCounts') || Object.create(null);
  messageCounts[p.uid] = 99;
  await inst.storage.put('messageCounts', messageCounts);
  await inst.handleWsChat(ws, p.uid, await makeChatWsData(p, BLOCK_NUM, GROUP_ID, 'ok99', ts++));
  const okErrors = ws.errors().length;
  // 上限超えの有効署名を11発 → 全て安い拒否（max_messages_reached）＋11発目で切断
  for (let i = 0; i < 11; i++) {
    await inst.handleWsChat(ws, p.uid, await makeChatWsData(p, BLOCK_NUM, GROUP_ID, `over${i}`, ts++));
  }
  const overErrors = ws.errors();
  ok('T3 上限超えは全てmax_messages_reachedで拒否（署名検証前の安いチェック）',
    okErrors === 0 && overErrors.length === 10 && overErrors.every(e => e.code === 'max_messages_reached'),
    `errors=${overErrors.length}`);
  ok('T3b 上限超え連打11発目で切断', ws.closes.length === 1 && ws.closes[0].code === 1008);
  console.log(`  info: T3 実行時間 ${Math.round((performance.now() - t3StartedAt) * 10) / 10}ms`);
}

// ---- T4: 受領証明（v3.2）— 正規受理・無効署名/なりすましの連打で切断 ----
{
  const { inst, players } = await makeGroup();
  await setPhase(inst, 'chatting');
  const [sender, receiver, third] = players;
  // 下準備: sender のチャット1件（既読受領証明の対象）
  const chatWs = makeWs(sender.uid);
  const chatData = await makeChatWsData(sender, BLOCK_NUM, GROUP_ID, 'receipt me', ts++);
  await inst.handleWsChat(chatWs, sender.uid, chatData);
  const msg = { type: 'chat', blockNum: BLOCK_NUM, groupId: GROUP_ID, uid: sender.uid, text: chatData.text, timestamp: chatData.timestamp, signature: chatData.signature };

  // 正規: receiver の既読受領証明は受理（receipt_ack）
  const ws = makeWs(receiver.uid);
  const rc = await makeReadReceipt(receiver, sender.uid, [msg], BLOCK_NUM, GROUP_ID, ts++);
  await inst.handleWsReceipt(ws, receiver.uid, { receipt: rc });
  ok('T4 正規既読受領証明は受理（receipt_ack）',
    ws.sent.some(m => m?.type === 'receipt_ack') && ws.errors().length === 0 && ws.closes.length === 0,
    JSON.stringify(ws.errors()));

  // アクション受領証明も受理される（vote → 他メンバーの受領）
  const voteWs = makeWs(third.uid);
  const voteAction = await makeActionWsData(third, 'vote', { targetUid: sender.uid }, BLOCK_NUM, GROUP_ID, ts++);
  await inst.handleWsVote(voteWs, third.uid, voteAction);
  const arc = await makeActionReceipt(receiver, third.uid, 'vote', voteAction, BLOCK_NUM, GROUP_ID, ts++);
  await inst.handleWsReceipt(ws, receiver.uid, { receipt: arc });
  ok('T4b アクション受領証明も受理', ws.sent.filter(m => m?.type === 'receipt_ack').length === 2);

  // なりすまし: receiverUid ≠ 接続uid は strike（他人名義の受領証明中継は不可）
  const rcSpoof = await makeReadReceipt(third, sender.uid, [msg], BLOCK_NUM, GROUP_ID, ts++);
  await inst.handleWsReceipt(ws, receiver.uid, { receipt: rcSpoof });
  ok('T4c receiverUid≠接続uidの受領証明は拒否', ws.errors().some(e => /receiverUid/.test(e.message)),
    JSON.stringify(ws.errors()));

  // 無効署名の連打 → 切断（G4 strike）
  const wsBad = makeWs(receiver.uid);
  for (let i = 0; i < 11 && wsBad.closes.length === 0; i++) {
    const bad = { ...rc, timestamp: ts++, signature: '0x' + 'ab'.repeat(65) };
    await inst.handleWsReceipt(wsBad, receiver.uid, { receipt: bad });
  }
  ok('T4d 無効署名受領証明の連打で1008切断', wsBad.closes.length === 1 && wsBad.closes[0].code === 1008,
    `closes=${JSON.stringify(wsBad.closes)}`);
}

// ---- T5: 受領済み投票の再送・冪等・10件上限 ----
{
  const { inst, players } = await makeGroup();
  await setPhase(inst, 'chatting');
  const p = players[0];
  const ws = makeWs(p.uid);
  const first = await makeActionWsData(p, 'vote', { targetUid: players[1].uid }, BLOCK_NUM, GROUP_ID, Date.now());
  await inst.handleWsVote(ws, p.uid, first);
  ok('T5 初回投票は受理', ws.sent.some(m => m?.type === 'vote_ack') && ws.errors().length === 0);
  const receiver = players[3];
  await inst.handleWsReceipt(makeWs(receiver.uid), receiver.uid, {
    receipt: await makeActionReceipt(receiver, p.uid, 'vote', first, BLOCK_NUM, GROUP_ID, first.timestamp + 1),
  });
  const forwarded = [];
  const broadcast = inst.broadcast.bind(inst);
  inst.broadcast = (message, exceptUid) => { forwarded.push(message); return broadcast(message, exceptUid); };
  const second = await makeActionWsData(p, 'vote', { targetUid: players[1].uid }, BLOCK_NUM, GROUP_ID, first.timestamp + 600001);
  await inst.handleWsVote(ws, p.uid, second);
  ok('T5b 受領済みの先着投票の後も再送を受理・中継',
    ws.sent.filter(m => m?.type === 'vote_ack').length === 2
      && !ws.errors().length && (await inst.storage.get(`votes:${p.uid}`))?.signature === first.signature
      && forwarded.some(m => m.type === 'action_made' && m.signature === second.signature));
  await inst.handleWsVote(ws, p.uid, { ...second, encrypted: 'tampered' });
  ok('T5c 同じ署名は冪等で件数に入らない',
    ws.sent.filter(m => m?.type === 'vote_ack').length === 3
      && ws.sent.filter(m => m?.type === 'vote_ack').at(-1)?.encrypted === second.encrypted
      && (await inst.storage.get(`voteExtras:${p.uid}`))?.length === 1);
  for (let i = 2; i < 10; i++) {
    await inst.handleWsVote(ws, p.uid, await makeActionWsData(p, 'vote', { targetUid: players[1].uid }, BLOCK_NUM, GROUP_ID, first.timestamp + 600001 + i));
  }
  ok('T5d 発信者の投票10件まで受理', ws.sent.filter(m => m?.type === 'vote_ack').length === 11 && !ws.errors().length);
  const initWs = makeWs(p.uid);
  await inst.handleWsInit(initWs, p.uid);
  const initVotes = initWs.sent.find(m => m.type === 'init_response')?.actions?.votes;
  ok('T5e 再接続のinitで先着＋後続9件を到着順に配布',
    initVotes?.[p.uid]?.signature === first.signature
      && initVotes?.[`${p.uid}__extras`]?.length === 9
      && initVotes[`${p.uid}__extras`][0]?.signature === second.signature);
  const myVoteEcho = initWs.sent.find(m => m.type === 'my_vote');
  ok('T5e2 my_voteは従来の先着位置と後続配列を返す',
    myVoteEcho?.vote?.signature === first.signature && myVoteEcho?.extras?.length === 9);
  const results = await (await inst.handleGetResults()).json();
  ok('T5e3 /get-resultsは先着と後続を返す',
    results.votes[p.uid]?.signature === first.signature && results.votes[`${p.uid}__extras`]?.length === 9);
  const r2Writes = new Map();
  inst.env.R2_BUCKET = { put: async (key, body) => { r2Writes.set(key, JSON.parse(body)); } };
  await inst.archiveGameData();
  await inst.publishLiveSnapshot(true);
  const archiveVotes = r2Writes.get(`games/block${BLOCK_NUM}/group${GROUP_ID}.json`)?.votes;
  const liveVotes = r2Writes.get(`live/block${BLOCK_NUM}/group${GROUP_ID}.json`)?.actions?.votes;
  ok('T5e4 群アーカイブと観戦スナップショットも先着＋後続を返す',
    archiveVotes?.[p.uid]?.signature === first.signature && archiveVotes?.[`${p.uid}__extras`]?.length === 9
      && liveVotes?.[p.uid]?.signature === first.signature && liveVotes?.[`${p.uid}__extras`]?.length === 9);
  const lateReceipt = await makeActionReceipt(receiver, p.uid, 'vote', second, BLOCK_NUM, GROUP_ID,
    second.timestamp + 600001);
  ok('T5e5 後続投票の既知hashに対する窓外受領は拒否',
    !(await inst.isReceiptTimelyForTarget(lateReceipt, 'action')));
  const over = await makeActionWsData(p, 'vote', { targetUid: players[2].uid }, BLOCK_NUM, GROUP_ID, first.timestamp + 700000);
  over.signature = '0x' + 'ef'.repeat(65);
  let overVerifications = 0;
  const verify = inst.verifyActionSignature.bind(inst);
  inst.verifyActionSignature = async (...args) => { overVerifications++; return verify(...args); };
  await inst.handleWsVote(initWs, p.uid, over);
  ok('T5f 再接続後の11件目は署名検証前に拒否',
    initWs.errors().at(-1)?.message === 'Maximum 10 votes allowed' && overVerifications === 0);
  for (let i = 0; i < 10 && !initWs.closes.length; i++) await inst.handleWsVote(initWs, p.uid, over);
  ok('T5g 11件目の連打は strike で切断', initWs.closes[0]?.code === 1008);
}

// ---- T6: 密告上限チェックが署名検証より先 ----
{
  const { inst, players } = await makeGroup();
  await setPhase(inst, 'chatting');
  const p = players[0];
  const ws = makeWs(p.uid);
  const first = await makeActionWsData(p, 'report', { targetUid: players[1].uid }, BLOCK_NUM, GROUP_ID, Date.now());
  await inst.handleWsReport(ws, p.uid, first);
  await inst.handleWsReport(ws, p.uid, { ...first, encrypted: 'tampered' });
  for (let i = 1; i < 10; i++) await inst.handleWsReport(ws, p.uid,
    await makeActionWsData(p, 'report', { targetUid: players[1].uid }, BLOCK_NUM, GROUP_ID, first.timestamp + i));
  ok('T6 正規の密告10件は受理', ws.sent.filter(m => m?.type === 'report_ack').length === 11 && ws.errors().length === 0);
  ok('T6b 密告10件を保存し、同署名の再送を数えない',
    (await inst.storage.get(`reports:${p.uid}`))?.length === 10 && ws.sent.filter(m => m?.type === 'report_ack').length === 11
      && ws.sent.filter(m => m?.type === 'report_ack')[1]?.encrypted === first.encrypted);
  const reconnect = makeWs(p.uid);
  const over = await makeActionWsData(p, 'report', { targetUid: players[2].uid }, BLOCK_NUM, GROUP_ID, first.timestamp + 11);
  over.signature = '0x' + '12'.repeat(65);
  let overVerifications = 0;
  const verify = inst.verifyActionSignature.bind(inst);
  inst.verifyActionSignature = async (...args) => { overVerifications++; return verify(...args); };
  await inst.handleWsReport(reconnect, p.uid, over);
  ok('T6c 再接続後の11件目は署名検証前に拒否', reconnect.errors().at(-1)?.message === 'Maximum 10 reports allowed' && overVerifications === 0);
  for (let i = 0; i < 10 && !reconnect.closes.length; i++) await inst.handleWsReport(reconnect, p.uid, over);
  ok('T6d 11件目の連打は strike で切断', reconnect.closes[0]?.code === 1008);
}

// ---- T7: ping総量キャップ（webSocketMessage経由） ----
{
  const { inst, players } = await makeGroup();
  await setPhase(inst, 'chatting');
  const [p, other] = players;
  const ws = makeWs(p.uid);
  const otherWs = makeWs(other.uid);
  const votes = [];
  const reports = [];
  for (let i = 0; i < 11; i++) {
    votes.push(await makeActionWsData(p, 'vote', { targetUid: other.uid }, BLOCK_NUM, GROUP_ID, ts++));
    reports.push(await makeActionWsData(p, 'report', { targetUid: other.uid }, BLOCK_NUM, GROUP_ID, ts++));
  }
  const otherVote = await makeActionWsData(other, 'vote', { targetUid: p.uid }, BLOCK_NUM, GROUP_ID, ts++);
  await Promise.all([
    ...votes.map(v => inst.handleWsVote(ws, p.uid, v)),
    ...reports.map(r => inst.handleWsReport(ws, p.uid, r)),
    inst.handleWsVote(otherWs, other.uid, otherVote),
  ]);
  ok('T6e 並行発信でも発信者・種別ごとに10件、他人の予算は独立',
    ws.sent.filter(m => m?.type === 'vote_ack').length === 10
      && ws.sent.filter(m => m?.type === 'report_ack').length === 10
      && ws.errors().length === 2
      && otherWs.sent.filter(m => m?.type === 'vote_ack').length === 1);
}
// 2026-11-19（ユーザーの決定）: chat-game-DO の WS_TOTAL_MSG_MAX を 5,000→10,000 にした分だけ数を取り直した（27fb47c6f）。

// ---- T7: ping総量キャップ（webSocketMessage経由） ----
{
  const { inst, players } = await makeGroup();
  const p = players[0];
  const ws = makeWs(p.uid);
  for (let i = 0; i < 10001 && ws.closes.length === 0; i++) {
    await inst.webSocketMessage(ws, JSON.stringify({ type: 'ping' }));
  }
  const pongs = ws.sent.filter(m => m?.type === 'pong').length;
  ok('T7 総量10,000通で切断（それまでは全てpong）', ws.closes.length === 1 && pongs === 10000,
    `pongs=${pongs} closes=${ws.closes.length}`);
  const sentAfterClose = ws.sent.length;
  const abuseAfterClose = inst.wsAbuse.get(ws)?.total;
  await inst.webSocketMessage(ws, JSON.stringify({ type: 'ping' }));
  await inst.webSocketMessage(ws, JSON.stringify({ type: 'chat', text: 'late' }));
  await inst.webSocketMessage(ws, JSON.stringify({ type: 'vote', targetUid: 'late' }));
  ok('T7b 1008 の CLOSING からの ping/chat/vote は応答せず予算も増やさない',
    ws.readyState === 2 && ws.sent.length === sentAfterClose && inst.wsAbuse.get(ws)?.total === abuseAfterClose);
}

// ---- T8: スパム切断常習uidの接続拒否（クールダウン） ----
{
  const { inst, players } = await makeGroup();
  await setPhase(inst, 'chatting');
  const attacker = players[0];
  // 3回スパム切断させる（各回は新しい接続＝カウンタリセットを再現）
  for (let round = 0; round < 3; round++) {
    const ws = makeWs(attacker.uid);
    for (let i = 0; i < 11; i++) {
      const bad = await makeChatWsData(attacker, BLOCK_NUM, GROUP_ID, `z${i}`, ts++);
      bad.signature = '0x' + '34'.repeat(65);
      await inst.handleWsChat(ws, attacker.uid, bad);
    }
  }
  const url = new URL(`https://do/websocket?uid=${attacker.uid}&token=t`);
  const res = await inst.handleWebSocketUpgrade(new Request(url), url);
  ok('T8 3回のスパム切断後は接続拒否(429)', res.status === 429, `status=${res.status}`);
  // 無関係uid（非メンバー）はクールダウンでなくメンバー検証(403)へ進む＝uid単位の拒否である証明
  const url2 = new URL('https://do/websocket?uid=99999999&token=t');
  const res2 = await inst.handleWebSocketUpgrade(new Request(url2), url2);
  ok('T8b 無関係uidは429ではない（メンバー検証403へ進む）', res2.status === 403, `status=${res2.status}`);
}

// ============================================================================
// T9〜T13: R33-F-1-01（ユーザー決定 D-12・便 S3C11/S3C11b）— uid ごとの接続本数の上限。
// OPEN の4本では最も古い OPEN を閉じ、OPEN＋CLOSING の16本では新しい接続を断る。
//
// upgrade の成功枝を Node で通すため、この節の間だけ Workers 専用の2つを差し替える
// （本番コードは1バイトも変えない）:
//   - WebSocketPair: サーバー側の偽ソケット（readyState・send・close の記録）を返す
//   - Response: Node の Response は status 101 を作れないので、101 のときだけ中身を持たない応答にする
// auth-worker は Service Binding の偽物（token 'bad' だけ 403・ほかは 200）で、呼び出し回数を数える。
// ============================================================================
const cgMod = await import(new URL('../../workers/game_workers/chat-game-DO.js', import.meta.url));
ok('T9-const D-12 の値を固定（OPEN=4・合計=16・4001・120/60000）',
  cgMod.WS_MAX_SOCKETS_PER_UID === 4
    && cgMod.WS_MAX_TOTAL_SOCKETS_PER_UID === 16
    && cgMod.WS_CLOSE_SUPERSEDED === 4001
    && cgMod.WS_UPGRADE_RATE_MAX === 120 && cgMod.WS_UPGRADE_RATE_WINDOW_MS === 60000,
  `K=${cgMod.WS_MAX_SOCKETS_PER_UID} total=${cgMod.WS_MAX_TOTAL_SOCKETS_PER_UID} code=${cgMod.WS_CLOSE_SUPERSEDED} `
    + `rate=${cgMod.WS_UPGRADE_RATE_MAX}/${cgMod.WS_UPGRADE_RATE_WINDOW_MS}`);
// 定数が無い版（直す前）でも振る舞いの歯を走らせて赤を見られるよう、既定値を置く（直した後は現物の値だけを使う）
const K = cgMod.WS_MAX_SOCKETS_PER_UID ?? 4;
const CLOSE_SUPERSEDED = cgMod.WS_CLOSE_SUPERSEDED ?? 4001;
const RATE_MAX = cgMod.WS_UPGRADE_RATE_MAX ?? 120;
const RATE_WINDOW_MS = cgMod.WS_UPGRADE_RATE_WINDOW_MS ?? 60000;
const TOTAL_MAX = cgMod.WS_MAX_TOTAL_SOCKETS_PER_UID ?? 16;

const RealResponse = globalThis.Response;
const realDateNow = Date.now;
const hadWebSocketPair = Object.hasOwn(globalThis, 'WebSocketPair');
class UpgradeResponse extends RealResponse {
  constructor(body, init = {}) {
    if (init?.status === 101) {
      super(null, { status: 200 });
      Object.defineProperty(this, 'status', { value: 101 });
      this.webSocket = init.webSocket;
      return;
    }
    super(body, init);
  }
}
let autoCloseReply = false;
function makeServerSocket() {
  const ws = {
    readyState: 1, sent: [], closes: [],
    send(str) {
      if (this.readyState !== 1) throw new Error('socket is not open');
      this.sent.push(JSON.parse(str));
    },
    close(code, reason) { this.closes.push({ code, reason }); this.readyState = autoCloseReply ? 3 : 2; },
  };
  return ws;
}
let clock = 1_900_000_000_000;
const authCalls = [];
function makeAuthEnv(afterCall) {
  const env = {};
  for (let i = 0; i < 100; i++) {
    env[`AUTH_WORKER_${i}`] = {
      fetch: async (req) => {
        const token = (req.headers.get('Authorization') || '').replace(/^Bearer /, '');
        authCalls.push(token);
        if (afterCall) await afterCall(token);
        return new RealResponse('{}', { status: token === 'bad' ? 403 : 200 });
      },
    };
  }
  return env;
}
async function upgrade(inst, uid, token = 'good') {
  const url = new URL(`https://do/websocket?uid=${uid}&token=${token}`);
  const res = await inst.handleWebSocketUpgrade(new Request(url), url);
  return { status: res.status, ws: res.webSocket?.peer || null };
}
// 本番の state.getWebSockets() と同じく、閉じ終えた接続は除き、開いている接続だけを数える
const openOf = (inst, uid) => inst.state.getWebSockets(uid).filter(ws => inst.state.getTags(ws)[0] === uid && ws.readyState === 1);
const liveOf = (inst, uid) => inst.state.getWebSockets(uid).filter(ws => inst.state.getTags(ws)[0] === uid && ws.readyState !== 3);
// 閉じた接続を「閉じ終えた」扱いにし、本番と同じく webSocketClose を呼ぶ
async function finishClose(inst, ws, code, reason) {
  ws.readyState = 3;
  await inst.webSocketClose(ws, code, reason);
}
const disconnectsOf = (ws, uid) => ws.sent.filter(m => m?.type === 'member_disconnected' && m.uid === uid).length;

globalThis.Response = UpgradeResponse;
globalThis.WebSocketPair = function WebSocketPair() {
  const server = makeServerSocket();
  return { 0: { peer: server }, 1: server };
};
Date.now = () => clock;
try {
  // ---- T9: K+1 本目で本人の最も古い接続が close code 付きで閉じられ、新しい接続は通る ----
  for (const phase of ['waiting', 'chatting', 'submitting', 'completed']) for (const reverseWebSockets of [false, true]) {
    const { inst, players } = await makeGroup(makeAuthEnv(), { reverseWebSockets });
    if (phase !== 'waiting') await setPhase(inst, phase);
    const [a, b] = players;
    const bWs = (await upgrade(inst, b.uid)).ws;
    const aSockets = [];
    for (let i = 0; i < K; i++) { clock += 1000; aSockets.push((await upgrade(inst, a.uid)).ws); }
    const noneClosedAtK = aSockets.every(ws => ws && ws.closes.length === 0);
    clock += 1000;
    const next = await upgrade(inst, a.uid);
    ok(`T9 [${phase} reverse=${reverseWebSockets}] K=${K} 本までは誰も閉じられない`, noneClosedAtK);
    ok(`T9 [${phase} reverse=${reverseWebSockets}] K+1 本目の upgrade は断られない（101）`, next.status === 101 && next.ws, `status=${next.status}`);
    ok(`T9 [${phase} reverse=${reverseWebSockets}] 最も古い接続が close code ${CLOSE_SUPERSEDED}（superseded）で閉じられる`,
      aSockets[0].closes.length === 1 && aSockets[0].closes[0].code === CLOSE_SUPERSEDED
        && aSockets[0].closes[0].reason === 'superseded',
      JSON.stringify(aSockets[0].closes));
    ok(`T9 [${phase} reverse=${reverseWebSockets}] 2番目以降の古い接続は閉じられない`, aSockets.slice(1).every(ws => ws.closes.length === 0));
    ok(`T9 [${phase} reverse=${reverseWebSockets}] 本人の開いている接続は K 本のまま`, openOf(inst, a.uid).length === K,
      `open=${openOf(inst, a.uid).length}`);
    ok(`T9 [${phase} reverse=${reverseWebSockets}] 別の uid の接続は閉じられない`, bWs.closes.length === 0 && openOf(inst, b.uid).length === 1);
  }

  // ---- T10: Close 応答ありなら、他のプレイヤーの接続は通り、組の OPEN は「人数 × K」以下 ----
  {
    autoCloseReply = true; // ブラウザは Close に応答し、閉じ終えた接続は getWebSockets から消える
    const { inst, players } = await makeGroup(makeAuthEnv());
    await setPhase(inst, 'chatting');
    const [a, b, c] = players;
    const bWs = (await upgrade(inst, b.uid)).ws;
    const statuses = [];
    for (let i = 0; i < 10 * K; i++) { clock += 1000; statuses.push((await upgrade(inst, a.uid)).status); }
    ok('T10 Close 応答ありの大量 upgrade は全部 101',
      statuses.every(s => s === 101), `statuses=${[...new Set(statuses)]}`);
    ok('T10 大量に張る本人の開いている接続は K 本', openOf(inst, a.uid).length === K);
    ok('T10 先に張っていた別のプレイヤーの接続は閉じられない', bWs.closes.length === 0);
    const cRes = await upgrade(inst, c.uid);
    ok('T10 後から来た別のプレイヤーの接続も通る', cRes.status === 101 && cRes.ws.closes.length === 0);
    for (const p of players) {
      for (let i = 0; i < 3 * K; i++) { clock += 1000; await upgrade(inst, p.uid); }
    }
    const total = inst.state.getWebSockets().filter(ws => ws.readyState === 1).length;
    ok('T10 組の開いている接続の総数は「人数 × K」以下', total <= players.length * K,
      `total=${total} bound=${players.length * K}`);
    autoCloseReply = false;
  }

  // ---- T11: 古い接続を閉じても、その uid の接続が残っていれば member_disconnected を配らない ----
  {
    const { inst, players } = await makeGroup(makeAuthEnv());
    await setPhase(inst, 'chatting');
    const [a, b] = players;
    const bWs = (await upgrade(inst, b.uid)).ws;
    const aSockets = [];
    for (let i = 0; i < K; i++) { clock += 1000; aSockets.push((await upgrade(inst, a.uid)).ws); }
    clock += 1000;
    aSockets.push((await upgrade(inst, a.uid)).ws);
    bWs.sent.length = 0;
    await finishClose(inst, aSockets[0], CLOSE_SUPERSEDED, 'superseded');
    ok('T11 superseded で閉じた接続の close では member_disconnected を配らない（本人の接続が残る）',
      disconnectsOf(bWs, a.uid) === 0, JSON.stringify(bWs.sent.map(m => m?.type)));
    // 利用者がタブを1つ閉じた（1000）場合も、同じ uid の接続が残っていれば配らない
    await finishClose(inst, aSockets[1], 1000, 'tab closed');
    ok('T11 タブを1つ閉じても本人の接続が残っていれば member_disconnected を配らない',
      disconnectsOf(bWs, a.uid) === 0);
    // 🔴 逆方向: 本人の最後の接続が閉じたら、今までどおり1回だけ配る
    const rest = aSockets.slice(2);
    for (const ws of rest.slice(0, -1)) await finishClose(inst, ws, 1001, 'going away');
    ok('T11 最後の1本が残っている間は配らない', disconnectsOf(bWs, a.uid) === 0);
    await finishClose(inst, rest.at(-1), 1006, 'network');
    ok('T11 本人の最後の接続が閉じたら member_disconnected を1回だけ配る', disconnectsOf(bWs, a.uid) === 1,
      `count=${disconnectsOf(bWs, a.uid)}`);
    ok('T11 member_disconnected は本人のソケットへは送らない（従来どおり）',
      aSockets.every(ws => disconnectsOf(ws, a.uid) === 0));
  }

  // ---- T11b: 閉じる本人の接続が「まだ OPEN に見える」・別のオブジェクトで渡されても、本人は数えない ----
  // （本番の webSocketClose の時点の readyState とオブジェクトの同一性に依存しない。依存すると、
  //   1本だけの人の離脱が永久に配られず、在席の表示が「接続中」のまま固まる）
  {
    const { inst, players } = await makeGroup(makeAuthEnv());
    await setPhase(inst, 'chatting');
    const [a, b, c] = players;
    const bWs = (await upgrade(inst, b.uid)).ws;
    clock += 1000;
    const aWs = (await upgrade(inst, a.uid)).ws;
    bWs.sent.length = 0;
    await inst.webSocketClose(aWs, 1006, 'network'); // readyState は 1 のまま
    ok('T11b 1本だけの人の close は、その接続が OPEN に見えても member_disconnected を配る',
      disconnectsOf(bWs, a.uid) === 1, `count=${disconnectsOf(bWs, a.uid)}`);
    clock += 1000;
    const cWs = (await upgrade(inst, c.uid)).ws;
    const alias = { __tags: [...inst.state.getTags(cWs)], readyState: 1 };
    bWs.sent.length = 0;
    await inst.webSocketClose(alias, 1006, 'network');
    ok('T11b 同じ接続が別のオブジェクトで渡されても、accept のタグで本人を除いて配る',
      disconnectsOf(bWs, c.uid) === 1, `count=${disconnectsOf(bWs, c.uid)}`);
  }

  // ---- T12: upgrade の頻度の上限（uid ごと・認証に通った回数・auth 前後で 429） ----
  {
    autoCloseReply = true;
    // (1) 正直なつなぎ直し: K 個のタブがそれぞれ最短の backoff（3秒）で張り直し続けても断られない
    const { inst, players } = await makeGroup(makeAuthEnv());
    await setPhase(inst, 'chatting');
    const [a, b] = players;
    const honestStatuses = [];
    for (let t = 0; t < 10 * 60; t += 3) {
      clock += 3000;
      for (let tab = 0; tab < K; tab++) honestStatuses.push((await upgrade(inst, a.uid)).status);
    }
    ok(`T12 K=${K} タブがそれぞれ3秒ごとに10分張り直しても 429 にならない（${honestStatuses.length} 回）`,
      honestStatuses.every(s => s === 101), `statuses=${[...new Set(honestStatuses)]}`);
    // backoff 3→6→12→24→30→30… の1タブも断られない
    const backoff = [3, 6, 12, 24, 30, 30, 30, 30];
    const backoffStatuses = [];
    for (let round = 0; round < 20; round++) {
      for (const sec of backoff) { clock += sec * 1000; backoffStatuses.push((await upgrade(inst, b.uid)).status); }
    }
    ok('T12 backoff 3→6→12→24→30 秒のつなぎ直しは断られない', backoffStatuses.every(s => s === 101));

    // PC と電話の2台。Close に応答するブラウザなら、短い回線切替を繰り返しても両端末が使える。
    const { inst: twoDeviceInst, players: twoDevicePlayers } = await makeGroup(makeAuthEnv());
    const deviceUid = twoDevicePlayers[0].uid;
    let pc, phone;
    const deviceStatuses = [];
    for (let i = 0; i < 40; i++) {
      clock += 1000;
      const pcRes = await upgrade(twoDeviceInst, deviceUid);
      const phoneRes = await upgrade(twoDeviceInst, deviceUid);
      deviceStatuses.push(pcRes.status, phoneRes.status);
      pc = pcRes.ws; phone = phoneRes.ws;
    }
    await twoDeviceInst.webSocketMessage(pc, JSON.stringify({ type: 'ping' }));
    await twoDeviceInst.webSocketMessage(phone, JSON.stringify({ type: 'ping' }));
    ok('T12 PC と電話の2台は Close 応答ありなら 429 も応答の取りこぼしもない',
      deviceStatuses.every(s => s === 101) && pc?.readyState === 1 && phone?.readyState === 1
      && pc.sent.at(-1)?.type === 'pong' && phone.sent.at(-1)?.type === 'pong');

    // (2) 連打: 同じ時刻に大量の upgrade → 上限を超えた分は auth を呼ばずに 429
    const { inst: inst2, players: players2 } = await makeGroup(makeAuthEnv());
    await setPhase(inst2, 'chatting');
    const [x, y] = players2;
    clock += 60 * 60 * 1000;
    authCalls.length = 0;
    const flood = [];
    for (let i = 0; i < RATE_MAX + 50; i++) flood.push((await upgrade(inst2, x.uid)).status);
    const accepted = flood.filter(s => s === 101).length;
    const rejected = flood.filter(s => s === 429).length;
    ok('T12 連打は窓あたり上限の本数まで 101・超えた分は 429', accepted === RATE_MAX && rejected === 50,
      `accepted=${accepted} rejected=${rejected}`);
    ok('T12 429 の分は auth-worker を呼ばない', authCalls.length === RATE_MAX,
      `authCalls=${authCalls.length}`);
    ok('T12 連打した本人の開いている接続は K 本のまま', openOf(inst2, x.uid).length === K);
    // (3) 他人の uid を騙る連打（token が通らない）では、その人の窓は埋まらない
    for (let i = 0; i < 3 * RATE_MAX; i++) await upgrade(inst2, y.uid, 'bad');
    const yRes = await upgrade(inst2, y.uid);
    ok('T12 token の通らない upgrade を他人が何回送っても、本人の接続は断られない',
      yRes.status === 101, `status=${yRes.status}`);
    // (4) 窓が過ぎれば本人も再び張れる
    clock += RATE_WINDOW_MS + 1;
    const xAgain = await upgrade(inst2, x.uid);
    ok('T12 窓が過ぎれば連打した本人も再び張れる', xAgain.status === 101, `status=${xAgain.status}`);
    autoCloseReply = false;
  }

  // ---- CAP-01: Close に応えないクライアントも uid ごとの合計16本に含める ----
  {
    const { inst, players } = await makeGroup(makeAuthEnv());
    await setPhase(inst, 'chatting');
    const [a, b] = players;
    const bWs = (await upgrade(inst, b.uid)).ws;
    bWs.__tags.push(a.uid); // getWebSockets(a.uid) は2番目以降のタグ一致も返す
    const aSockets = [];
    for (let i = 0; i < TOTAL_MAX; i++) aSockets.push((await upgrade(inst, a.uid)).ws);
    ok('CAP-01 OPEN+CLOSING は16本、OPEN は4本',
      liveOf(inst, a.uid).length === TOTAL_MAX && openOf(inst, a.uid).length === K
      && aSockets.slice(0, TOTAL_MAX - K).every(ws => ws.readyState === 2),
      `live=${liveOf(inst, a.uid).length} open=${openOf(inst, a.uid).length}`);
    const callsBefore = authCalls.length;
    const denied = await upgrade(inst, a.uid);
    ok('CAP-01 17本目は auth の前で429、他人の接続は閉じない',
      denied.status === 429 && authCalls.length === callsBefore && liveOf(inst, a.uid).length === TOTAL_MAX
      && bWs.closes.length === 0);
    const another = await upgrade(inst, players[2].uid);
    ok('CAP-01 他の名簿メンバーは新たに接続できる', another.status === 101 && another.ws?.readyState === 1);

    // 4001 で閉じたソケットは CLOSING のまま残し、全種別を入口で捨てる。
    const old = aSockets[0];
    const sentBefore = old.sent.length;
    const seenBefore = inst.memberSeen.get(a.uid);
    const originalGet = inst.storage.get.bind(inst.storage);
    let reads = 0;
    inst.storage.get = (...args) => { reads++; return originalGet(...args); };
    await inst.webSocketMessage(old, JSON.stringify({ type: 'ping' }));
    await inst.webSocketMessage(old, JSON.stringify({ type: 'chat', text: 'late' }));
    await inst.webSocketMessage(old, JSON.stringify({ type: 'vote', targetUid: b.uid }));
    inst.storage.get = originalGet;
    ok('CAP-01 4001 の CLOSING からの ping/chat/vote は storage も応答も変えない',
      old.readyState === 2 && reads === 0 && old.sent.length === sentBefore && inst.memberSeen.get(a.uid) === seenBefore,
      `reads=${reads} sent=${old.sent.length - sentBefore}`);
    const fresh = aSockets.at(-1);
    const freshSent = fresh.sent.length;
    await inst.webSocketMessage(fresh, JSON.stringify({ type: 'ping' }));
    ok('CAP-01 OPEN の ping は従来どおり pong', fresh.sent.length === freshSent + 1 && fresh.sent.at(-1)?.type === 'pong');
  }

  // ---- CAP-02: auth が同時に待っても、auth 後の同期区間で120回に制限する ----
  {
    autoCloseReply = true;
    let release;
    const authGate = new Promise(resolve => { release = resolve; });
    const { inst, players } = await makeGroup(makeAuthEnv(() => authGate));
    const uid = players[0].uid;
    authCalls.length = 0;
    const pending = Array.from({ length: 3 * RATE_MAX }, () => upgrade(inst, uid));
    for (let i = 0; i < 100 && authCalls.length < 3 * RATE_MAX; i++) await new Promise(setImmediate);
    const allReachedAuth = authCalls.length === 3 * RATE_MAX;
    release();
    const results = await Promise.all(pending);
    ok('CAP-02 同時 upgrade も認証に通った120本まで accept',
      allReachedAuth && results.filter(r => r.status === 101).length === RATE_MAX
      && results.filter(r => r.status === 429).length === 2 * RATE_MAX,
      `auth=${authCalls.length} accept=${results.filter(r => r.status === 101).length}`);
    ok('CAP-02 同時 accept の OPEN は4本以内', openOf(inst, uid).length === K);

    // Close に応えない接続では、auth 待ちの間に通った全本数も合計上限に縛る。
    autoCloseReply = false;
    let releaseNoReply;
    const noReplyGate = new Promise(resolve => { releaseNoReply = resolve; });
    const { inst: noReplyInst, players: noReplyPlayers } = await makeGroup(makeAuthEnv(() => noReplyGate));
    const noReplyUid = noReplyPlayers[0].uid;
    authCalls.length = 0;
    const noReplyPending = Array.from({ length: 3 * RATE_MAX }, () => upgrade(noReplyInst, noReplyUid));
    for (let i = 0; i < 100 && authCalls.length < 3 * RATE_MAX; i++) await new Promise(setImmediate);
    const noReplyReachedAuth = authCalls.length === 3 * RATE_MAX;
    releaseNoReply();
    const noReplyResults = await Promise.all(noReplyPending);
    const noReplyAccepted = noReplyResults.filter(r => r.status === 101).length;
    ok('CAP-02 Close 無応答の同時 auth 後 accept は16本以下',
      noReplyReachedAuth && noReplyAccepted <= TOTAL_MAX, `accept=${noReplyAccepted}`);
    ok('CAP-02 Close 無応答の OPEN+CLOSING は16本以下',
      liveOf(noReplyInst, noReplyUid).length <= TOTAL_MAX,
      `live=${liveOf(noReplyInst, noReplyUid).length}`);
    autoCloseReply = true;

    let releaseBad;
    const badGate = new Promise(resolve => { releaseBad = resolve; });
    const { inst: otherInst, players: others } = await makeGroup(makeAuthEnv(() => badGate));
    authCalls.length = 0;
    const spoof = Array.from({ length: 3 * RATE_MAX }, () => upgrade(otherInst, others[1].uid, 'bad'));
    for (let i = 0; i < 100 && authCalls.length < 3 * RATE_MAX; i++) await new Promise(setImmediate);
    releaseBad();
    const rejected = await Promise.all(spoof);
    const honest = await upgrade(otherInst, others[1].uid);
    ok('CAP-02 token 不正の同時 upgrade は本人の頻度の窓を埋めない',
      rejected.every(r => r.status === 403) && honest.status === 101, `honest=${honest.status}`);
    autoCloseReply = false;
  }

  // ---- T13: close code はサーバーと公式クライアントで同じ値 ----
  {
    const { readFileSync } = await import('node:fs');
    const hook = readFileSync(new URL('../../src/hooks/useGameWebSocket.js', import.meta.url), 'utf8');
    const m = hook.match(/^const WS_CLOSE_SUPERSEDED = (\d+);$/m);
    ok('T13 公式クライアントの WS_CLOSE_SUPERSEDED はサーバーと同じ値',
      m && Number(m[1]) === CLOSE_SUPERSEDED, `client=${m && m[1]} server=${CLOSE_SUPERSEDED}`);
  }
} finally {
  globalThis.Response = RealResponse;
  Date.now = realDateNow;
  if (!hadWebSocketPair) delete globalThis.WebSocketPair;
}

// ============================================================================
// T14〜T19: WR-PRE-PRESENCE — 正典ハンドラで時間回復・在席配信・既存の守りを検証。
// HEAD の回帰実証だけ、新設の歯のクラスを差し替える（T1〜T13 の読込先・期待は不変）。
// WR_PRE_PRESENCE_SOURCE=/absolute/path/to/head/workers/game_workers/chat-game-DO.js
// ============================================================================
const { pathToFileURL } = await import('node:url');
const { resolve } = await import('node:path');
const PresenceChatGameDO = process.env.WR_PRE_PRESENCE_SOURCE
  ? (await import(pathToFileURL(resolve(process.env.WR_PRE_PRESENCE_SOURCE)).href)).ChatGameDO
  : ChatGameDO;
const presenceStart = 1750000000000;
let presenceNow = presenceStart;
const presenceUpdates = (ws, uid) => ws.sent.filter(m => m?.type === 'presence_update' && m.uid === uid);
const presenceSend = (inst, ws, state = 'active') => inst.webSocketMessage(ws, JSON.stringify({ type: 'set_presence', state }));
async function makePresenceGroup(phase = 'chatting') {
  const { inst, players } = await makeGroup({}, {}, PresenceChatGameDO);
  await setPhase(inst, phase);
  const [a, b] = players;
  const ws = makeWs(a.uid), peer = makeWs(b.uid);
  inst.state.acceptWebSocket(ws, [a.uid]);
  inst.state.acceptWebSocket(peer, [b.uid]);
  const counts = { reads: 0, phaseReads: 0, presenceReads: 0, presenceWrites: 0, writes: 0 };
  const get = inst.storage.get.bind(inst.storage), put = inst.storage.put.bind(inst.storage);
  inst.storage.get = async key => {
    counts.reads++;
    if (key === 'phase') counts.phaseReads++;
    if (key === 'presence') counts.presenceReads++;
    const value = await get(key);
    // 本物の storage は読み出したオブジェクトの変更だけでは永続化しない。
    return key === 'presence' && value !== undefined ? structuredClone(value) : value;
  };
  inst.storage.put = async (key, value) => {
    counts.writes++;
    if (key === 'presence') counts.presenceWrites++;
    return put(key, value);
  };
  return { inst, a, b, ws, peer, counts };
}

Date.now = () => presenceNow;
try {
  // T14a: ハートビートだけでも旧版は131回目（4時間22分）に1008。
  {
    presenceNow = presenceStart;
    const { inst, ws, counts } = await makePresenceGroup('waiting');
    let beats = 0;
    for (let minute = 2; minute <= 48 * 60 && !ws.closes.length; minute += 2) {
      presenceNow = presenceStart + minute * 60000;
      if (minute === 122) await inst.storage.put('phase', 'chatting');
      await presenceSend(inst, ws);
      beats++;
    }
    ok('T14a 2分ごとの active を48時間1440回・presence strike 0・切断なし',
      beats === 1440 && inst.wsAbuseOf(ws).strikes === 0 && ws.closes.length === 0,
      `beats=${beats} elapsedMin=${(presenceNow - presenceStart) / 60000} strikes=${inst.wsAbuseOf(ws).strikes} closes=${JSON.stringify(ws.closes)}`);
    ok('T14a active ハートビートだけなら presence の保存0回', counts.presenceWrites === 0);
  }
  {
    presenceNow = presenceStart;
    const { inst, ws, counts } = await makePresenceGroup('waiting');
    let beats = 0, roundTrips = 0;
    for (let minute = 2; minute <= 48 * 60 && !ws.closes.length; minute += 2) {
      presenceNow = presenceStart + minute * 60000;
      if (minute === 122) await inst.storage.put('phase', 'chatting');
      await presenceSend(inst, ws);
      beats++;
      if (minute % 10 === 0 && !ws.closes.length) {
        await presenceSend(inst, ws, 'away');
        await presenceSend(inst, ws, 'active');
        roundTrips++;
      }
    }
    ok('T14b 同じ接続で48時間1440合図＋288往復＝2016通でも strike 0・切断なし',
      beats === 1440 && roundTrips === 288 && inst.wsAbuseOf(ws).total === 2016
      && inst.wsAbuseOf(ws).strikes === 0 && ws.closes.length === 0,
      `beats=${beats} roundTrips=${roundTrips} total=${inst.wsAbuseOf(ws).total} strikes=${inst.wsAbuseOf(ws).strikes}`);
    ok('T14b presence の保存は576回の状態変化だけ', counts.presenceWrites === 576,
      `writes=${counts.presenceWrites}`);
  }

  // T15: 枠超過も従来どおり11 strikeで1008→noteStrikeClose→10分内3回で429。
  for (const [intervalMs, expectedCount, expectedSeconds] of [[1000, 135, 134], [10000, 195, 1940]]) {
    presenceNow = presenceStart;
    const { inst, a } = await makePresenceGroup();
    const rounds = intervalMs === 1000 ? 3 : 1;
    const closes = [];
    for (let round = 0; round < rounds; round++) {
      const ws = makeWs(a.uid), start = presenceNow;
      let count = 0;
      for (; count < 500 && !ws.closes.length; count++) {
        presenceNow = start + count * intervalMs;
        await presenceSend(inst, ws);
      }
      closes.push({ count, elapsed: (presenceNow - start) / 1000 });
      ok(`T15 ${intervalMs / 1000}秒に1回 round=${round + 1} は11 strike・1008（${expectedSeconds}秒/${expectedCount}通）`,
        count === expectedCount && (presenceNow - start) / 1000 === expectedSeconds
        && inst.wsAbuseOf(ws).strikes === 11 && ws.closes.length === 1 && ws.closes[0].code === 1008,
        JSON.stringify({ ...closes.at(-1), strikes: inst.wsAbuseOf(ws).strikes, closes: ws.closes }));
    }
    ok(`T15 ${intervalMs / 1000}秒に1回の切断は noteStrikeClose に残る`,
      inst.uidStrikeCloses.get(a.uid)?.length === rounds);
    if (rounds === 3) {
      const url = new URL(`https://do/websocket?uid=${a.uid}&token=t`);
      const res = await inst.handleWebSocketUpgrade(new Request(url), url);
      ok('T15 毎秒連打の3切断は268秒以内の窓に収まり upgrade は429', res.status === 429, `status=${res.status}`);
      presenceNow += 600001;
      ok('T15 10分の窓が過ぎれば strike cooldown は解ける', !inst.isUidStrikeCoolingDown(a.uid));
    }
  }

  // T16: 回復速度ちょうどの不変状態は48hでなく総量上限の手前まで実入口で確認。
  {
    presenceNow = presenceStart;
    const { inst, a, ws, peer, counts } = await makePresenceGroup();
    for (let i = 0; i < 10000 && !ws.closes.length; i++) {
      presenceNow = presenceStart + i * 30000;
      await presenceSend(inst, ws);
    }
    ok('T16 30秒に1回10000通は presence strike 0・切断なし',
      inst.wsAbuseOf(ws).strikes === 0 && inst.wsAbuseOf(ws).total === 10000 && ws.closes.length === 0);
    ok('T16 10000通の費用＝共通の無効化読10000＋phase読10000＋presence読10000・保存0・配信5000',
      counts.reads === 30000 && counts.phaseReads === 10000 && counts.presenceReads === 10000 && counts.writes === 0
      && presenceUpdates(peer, a.uid).length === 5000,
      JSON.stringify({ ...counts, relays: presenceUpdates(peer, a.uid).length }));
    presenceNow += 30000;
    await presenceSend(inst, ws);
    ok('T16 10001通目は既存の総量だけで1008・presence読は増えない',
      ws.closes.length === 1 && ws.closes[0].code === 1008 && ws.closes[0].reason === 'Message budget exceeded'
      && inst.wsAbuseOf(ws).strikes === 0 && counts.reads === 30001 && counts.presenceReads === 10000);
  }

  // T17: 送信先・形は本物の broadcast。2台のソケットと観戦者も同じ配信を受ける。
  {
    presenceNow = presenceStart;
    const { inst, a, ws, peer, counts } = await makePresenceGroup();
    const second = makeWs(a.uid), spectator = makeWs('spectator:observer');
    inst.state.acceptWebSocket(second, [a.uid]);
    inst.state.acceptWebSocket(spectator, ['spectator:observer']);
    for (let i = 0; i < 7; i++) {
      presenceNow = presenceStart + i * 120000;
      await presenceSend(inst, ws);
    }
    const updates = presenceUpdates(peer, a.uid);
    ok('T17 B は A の2分ごとの active を12分間7回とも観測（10分で途切れない）',
      updates.length === 7 && updates.every(m => JSON.stringify(m) === JSON.stringify({ type: 'presence_update', uid: a.uid, state: 'active' })),
      `relays=${updates.length}`);
    ok('T17 自分・同じuidの2台目・観戦者も従来の broadcast と同じ相手・形',
      [ws, second, spectator].every(s => JSON.stringify(presenceUpdates(s, a.uid)) === JSON.stringify(updates)));
    presenceNow += 30000;
    await Promise.all([presenceSend(inst, ws), presenceSend(inst, second)]);
    ok('T17 30秒後に2台から同時送信しても配信は増えない', presenceUpdates(peer, a.uid).length === 7);
    presenceNow += 30000;
    await Promise.all([presenceSend(inst, ws), presenceSend(inst, second)]);
    ok('T17 60秒後の2台同時送信は1回だけ配る', presenceUpdates(peer, a.uid).length === 8);
    presenceNow += 59999;
    await presenceSend(inst, second);
    ok('T17 59999msでは配らない', presenceUpdates(peer, a.uid).length === 8);
    presenceNow++;
    await presenceSend(inst, second);
    ok('T17 60000msちょうどで配る・不変activeは保存しない',
      presenceUpdates(peer, a.uid).length === 9 && counts.presenceWrites === 0);
    await presenceSend(inst, ws, 'away');
    const afterAway = await inst.storage.get('presence');
    presenceNow += 1000;
    await presenceSend(inst, ws, 'away');
    ok('T17 away の繰り返しは配らず保存も増やさない（atも不変）',
      presenceUpdates(peer, a.uid).length === 10 && counts.presenceWrites === 1
      && JSON.stringify(await inst.storage.get('presence')) === JSON.stringify(afterAway));
    await presenceSend(inst, second, 'active');
    ok('T17 active→away→active は60秒以内でも即配信・保存2回だけ',
      presenceUpdates(peer, a.uid).slice(-2).map(m => m.state).join(',') === 'away,active'
      && presenceUpdates(peer, a.uid).length === 11 && counts.presenceWrites === 2
      && !Object.hasOwn(await inst.storage.get('presence'), a.uid));
    await presenceSend(inst, ws);
    ok('T17 状態変化直後の active は重ねて配らない', presenceUpdates(peer, a.uid).length === 11);
    await presenceSend(inst, peer);
    ok('T17 uid が違えば配信の60秒枠も独立', presenceUpdates(ws, peer.__tags[0]).length === 1);
  }

  // T18: 端数時間の持越し・長い休止の容量頭打ち・時計の巻戻り・接続ごとの独立性。
  {
    presenceNow = presenceStart;
    const { inst, a, ws } = await makePresenceGroup();
    for (let i = 0; i < 120; i++) await presenceSend(inst, ws);
    presenceNow += 15000;
    await presenceSend(inst, ws); // tokenなし、strike 1
    presenceNow += 14999;
    await presenceSend(inst, ws); // tokenなし、strike 2
    presenceNow++;
    await presenceSend(inst, ws); // 端数を捨てていなければ tokenあり
    ok('T18 15秒＋14999ms＋1ms の端数を持越し30秒で1つ戻る', inst.wsAbuseOf(ws).strikes === 2);
    presenceNow -= 60000;
    await presenceSend(inst, ws);
    ok('T18 時計が戻っても token を余分に戻さない', inst.wsAbuseOf(ws).strikes === 3);
    presenceNow = presenceStart + 48 * 60 * 60000;
    for (let i = 0; i < 120; i++) await presenceSend(inst, ws);
    ok('T18 長い休止で120まで戻る', inst.wsAbuseOf(ws).strikes === 3);
    await presenceSend(inst, ws);
    ok('T18 回復は容量120で頭打ち・余った時間を貯め込まない', inst.wsAbuseOf(ws).strikes === 4);
    const second = makeWs(a.uid);
    for (let i = 0; i < 120; i++) await presenceSend(inst, second);
    ok('T18 同じuidでも無料枠は接続ごとに独立', inst.wsAbuseOf(second).strikes === 0 && second.closes.length === 0);
  }

  // T19: 対象外フェーズはpresence枠を使わず、観戦者は本物の入口で拒否される。
  {
    presenceNow = presenceStart;
    const { inst, ws, peer, counts } = await makePresenceGroup('submitting');
    for (let i = 0; i < 200; i++) await presenceSend(inst, ws, i % 2 ? 'active' : 'away');
    await inst.storage.put('phase', 'completed');
    for (let i = 0; i < 200; i++) await presenceSend(inst, ws);
    ok('T19 submitting/completed の400通はpresence枠も保存・配信も使わない',
      inst.wsAbuseOf(ws).strikes === 0 && counts.presenceReads === 0 && counts.presenceWrites === 0 && peer.sent.length === 0);
    await inst.storage.put('phase', 'waiting');
    for (let i = 0; i < 120; i++) await presenceSend(inst, ws);
    ok('T19 対象外フェーズ後も waiting の120通を無料で使える', inst.wsAbuseOf(ws).strikes === 0);
    await presenceSend(inst, ws);
    ok('T19 waiting も121通目はpresence strike', inst.wsAbuseOf(ws).strikes === 1);
    const spectator = makeWs('spectator:observer');
    const readsBefore = counts.phaseReads;
    await presenceSend(inst, spectator, 'away');
    ok('T19 観戦者のset_presenceはphase読取前に拒否・presence strikeなし',
      spectator.errors().at(-1)?.message === 'Spectators cannot perform this action'
      && inst.wsAbuseOf(spectator).strikes === 0 && counts.phaseReads === readsBefore);
  }

  // T20〜T22: WR-PRE-PRESENCE-FIX1 — 反証で生き残った M1・M2・M5 の回帰試験。
  // T20: 回復が起きた45秒時点でも15秒の端数を残し、60秒で次の1個が戻る。
  {
    presenceNow = presenceStart;
    const { inst, ws } = await makePresenceGroup();
    for (let i = 0; i < 120; i++) await presenceSend(inst, ws);
    const strikesAfterBurst = inst.wsAbuseOf(ws).strikes;
    presenceNow += 45000;
    await presenceSend(inst, ws);
    const strikesAt45s = inst.wsAbuseOf(ws).strikes;
    presenceNow += 15000;
    await presenceSend(inst, ws);
    ok('T20 120通の後45秒で1通・さらに15秒で1通とも端数の持越しで strike 0',
      strikesAfterBurst === 0 && strikesAt45s === 0 && inst.wsAbuseOf(ws).strikes === 0
      && inst.wsAbuseOf(ws).total === 122 && ws.closes.length === 0,
      JSON.stringify({ strikesAfterBurst, strikesAt45s, strikesAt60s: inst.wsAbuseOf(ws).strikes,
        total: inst.wsAbuseOf(ws).total, closes: ws.closes }));
  }

  // T21: 配信の60秒の控えが切れていても、不変awayは配信も保存もしない。
  {
    presenceNow = presenceStart;
    const { inst, a, ws, peer, counts } = await makePresenceGroup();
    await presenceSend(inst, ws, 'away');
    const afterAway = await inst.storage.get('presence');
    const updatesAfterAway = presenceUpdates(peer, a.uid);
    presenceNow += 61000;
    await presenceSend(inst, ws, 'away');
    ok('T21 away の61秒後の繰返しも配信0追加・保存0追加・保存済みatは不変',
      updatesAfterAway.length === 1 && updatesAfterAway[0].state === 'away'
      && JSON.stringify(presenceUpdates(peer, a.uid)) === JSON.stringify(updatesAfterAway)
      && counts.presenceWrites === 1
      && JSON.stringify(await inst.storage.get('presence')) === JSON.stringify(afterAway)
      && inst.wsAbuseOf(ws).strikes === 0 && ws.closes.length === 0,
      JSON.stringify({ relays: presenceUpdates(peer, a.uid).length, writes: counts.presenceWrites }));
  }

  // T22: 古い不変activeの控えから61秒後に往復し、状態変化でも控えを更新する。
  {
    presenceNow = presenceStart;
    const { inst, a, ws, peer, counts } = await makePresenceGroup();
    await presenceSend(inst, ws);
    presenceNow += 61000;
    await presenceSend(inst, ws, 'away');
    presenceNow += 1000;
    await presenceSend(inst, ws);
    const updatesAfterReturn = presenceUpdates(peer, a.uid);
    presenceNow += 1000;
    await presenceSend(inst, ws);
    ok('T22 active→61秒後away→1秒後active は即配信・さらに1秒後のactiveは配らない',
      updatesAfterReturn.map(m => m.state).join(',') === 'active,away,active'
      && JSON.stringify(presenceUpdates(peer, a.uid)) === JSON.stringify(updatesAfterReturn)
      && counts.presenceWrites === 2 && !Object.hasOwn(await inst.storage.get('presence'), a.uid)
      && inst.wsAbuseOf(ws).strikes === 0 && ws.closes.length === 0,
      JSON.stringify({ states: presenceUpdates(peer, a.uid).map(m => m.state), writes: counts.presenceWrites }));
  }
} finally {
  Date.now = realDateNow;
}

console.log('');
if (failed > 0) { console.error(`❌ ${failed} FAILED (${passed} passed)`); process.exit(1); }
console.log(`✅ ALL PASSED (${passed} checks)`);

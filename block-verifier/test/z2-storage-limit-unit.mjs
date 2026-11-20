// z2-storage-limit-unit.mjs — Z2是正（ChatGameDOストレージのキー分割）ユニットテスト
//
// 背景: DOストレージは1値あたり128KiB(131,072B)上限。旧実装はチャット全履歴・提出バンドル・
// 提出生バイト列をそれぞれ1キーに保存しており、ゲーム規定量（5人×100件×1万字）内の会話でも
// 上限を超え、チャット途中死・提出保存失敗（→no_submit失格）が起き得た（②監査 Z2/H4）。
//
// 本テストは本物の ChatGameDO をスタブ state 上で規定上限まで駆動し、以下を機械検証する:
//  U1: 5人×100件（各100字）＝500件のチャット全件受理（旧実装は~400件目以降が保存不能サイズ）
//  U2: 全ストレージ値が 131,072B 未満（本番DOで put が構造的に失敗しない証明）＋分割パスが実際に発動
//  U3: loadMessages の件数・ID順・内容が送信と一致
//  U4: 提出バンドル（>100KB→チャンク分割）の get-results 復元が payload とバイト完全一致
//  U5: 提出生バイト列（分割保存）の復元が payload とバイト完全一致（evidence照合の前提）
//  U6: first-write-wins（再提出は alreadySubmitted・保存不変）
//  U7: 旧形式互換（旧 'messages' 単一キーの既存データ＋新分割キーの結合・順序保存）
//  U8: デバッグ delete が分割チャンクも完全削除
//
// 実行: node block-verifier/test/z2-storage-limit-unit.mjs （Node 22）

import { ChatGameDO } from './canonical.mjs';
import { makeChatGameNamespace, makeFakeWs, authedRequest, TEST_API_SECRET } from './stubs.mjs';
import { makePlayer, makeChatWsData, buildSubmissionPayload } from './players.mjs';
import { decodeSubmissionPayloadString } from '../vendor/workers/game_workers/lib/evidence-compact-v1.js';

const DO_VALUE_LIMIT = 131072;
const BLOCK_NUM = 999;
const GROUP_ID = 0;

let passed = 0;
let failed = 0;
const ok = (name, cond, detail = '') => {
  if (cond) { passed++; console.log(`  ok: ${name}`); }
  else { failed++; console.error(`  FAIL: ${name}${detail ? ` — ${detail}` : ''}`); }
};
const bytesOf = (v) => new TextEncoder().encode(typeof v === 'string' ? v : JSON.stringify(v)).length;

// ---- セットアップ: 本物の ChatGameDO（スタブstate・環境はデフォルト値） ----
// S3-002: ChatGameDO の HTTP 制御面は X-Api-Secret 必須（未設定は fail-closed で 401）
const env = { RELEASE_TIME: '2099-01-01T00:00:00Z', API_SECRET: TEST_API_SECRET }; // debug-submission 用（未リリース扱い）
const chatNS = makeChatGameNamespace(ChatGameDO, env);
const inst = chatNS.instance(`${BLOCK_NUM}-${GROUP_ID}`);

const players = [];
for (let i = 0; i < 5; i++) {
  players.push(await makePlayer({ uid: `21000${i}01`, lang: 'ja', blockNum: BLOCK_NUM, keyIndex: i }));
}
const members = players.map((p, i) => ({
  uid: p.uid, addr: p.addr, bAddr: p.bAddrString, lang: p.lang,
  depIds: null, globalIndex: i, name: null, img: null, verified: false,
}));
const wsOf = Object.fromEntries(players.map(p => [p.uid, makeFakeWs(p.uid)]));

// init（GameMasterDOからの呼び出しと同一契約・v3.2）
{
  const res = await inst.fetch(authedRequest('https://do/init', {
    method: 'POST',
    body: JSON.stringify({
      blockNum: BLOCK_NUM, groupId: GROUP_ID, lang: 'ja', mixed: false, members,
      periodDurations: { gamePeriod: 600000, submitPeriod: 600000 },
    }),
  }));
  if (!res.ok) throw new Error(`init failed: ${await res.text()}`);
}
let ts = 1750000000000;

// waiting → chatting
{
  const res = await inst.fetch(authedRequest('https://do/set-phase', {
    method: 'POST', body: JSON.stringify({ phase: 'chatting' }),
  }));
  if (!res.ok) throw new Error(`set-phase(chatting) failed: ${await res.text()}`);
}

// ---- U1: 規定上限チャット（5人×100件×100字＝500件・計5万字） ----
const sentTexts = [];
let chatErrors = 0;
for (let m = 0; m < 100; m++) {
  for (const p of players) {
    const text = `m${String(m).padStart(3, '0')}u${p.uid.slice(4, 5)}`.padEnd(100, 'x'); // 半角100字
    const data = await makeChatWsData(p, BLOCK_NUM, GROUP_ID, text, ts++);
    await inst.handleWsChat(wsOf[p.uid], p.uid, data);
    const err = wsOf[p.uid].lastError();
    if (err) { chatErrors++; wsOf[p.uid].sent.length = 0; continue; }
    sentTexts.push(data.text);
  }
}
ok('U1 規定上限500件のチャットが全件受理（エラー0）', chatErrors === 0 && sentTexts.length === 500, `errors=${chatErrors}, accepted=${sentTexts.length}`);

// ---- U3: loadMessages の件数・順序・内容 ----
{
  const msgs = await inst.loadMessages();
  const idsAscending = msgs.every((m, i) => i === 0 || m.id > msgs[i - 1].id);
  const textsMatch = msgs.length === 500 && msgs.every((m, i) => m.text === sentTexts[i]);
  ok('U3 loadMessages: 500件・ID昇順・内容一致', msgs.length === 500 && idsAscending && textsMatch,
    `len=${msgs.length}, asc=${idsAscending}, texts=${textsMatch}`);
  const totalBytes = bytesOf(msgs);
  ok('U3b 総チャット量が旧実装の1値上限を実際に超えている（=旧実装なら途中死していた規模）',
    totalBytes > DO_VALUE_LIMIT, `total=${totalBytes}B`);
}

// chatting → submitting
{
  const res = await inst.fetch(authedRequest('https://do/set-phase', {
    method: 'POST', body: JSON.stringify({ phase: 'submitting' }),
  }));
  if (!res.ok) throw new Error(`set-phase(submitting) failed: ${await res.text()}`);
}

// ---- 提出（本番と同一のバンドル構築ヘルパー・v3.2） ----
const serverMessages = await inst.loadMessages();
const payloads = {};
for (let i = 0; i < players.length; i++) {
  const p = players[i];
  const { payload } = await buildSubmissionPayload(p, {
    blockNum: BLOCK_NUM, groupId: GROUP_ID, serverMessages,
    serverVotes: {}, serverReports: {}, receipts: [],
    submittedAt: 1750009000000 + i, depositIds: [],
  });
  payloads[p.uid] = payload;
  wsOf[p.uid].sent.length = 0;
  await inst.handleWsSubmit(wsOf[p.uid], p.uid, { payload });
  const err = wsOf[p.uid].lastError();
  if (err) throw new Error(`submit ${p.uid}: ${err.message}`);
  if (!wsOf[p.uid].sent.some(x => x.type === 'submit_ack')) throw new Error(`submit ${p.uid}: no ack`);
}

// ---- U2: 全ストレージ値 < 128KiB ＋ 分割パスの実発動 ----
{
  const map = inst.state.storage._map;
  let maxBytes = 0, maxKey = '', over = 0;
  for (const [k, v] of map) {
    const b = bytesOf(v);
    if (b > maxBytes) { maxBytes = b; maxKey = k; }
    if (b > DO_VALUE_LIMIT) { over++; console.error(`    OVER: ${k} = ${b}B`); }
  }
  ok('U2 全ストレージ値が131,072B以下', over === 0, `max=${maxKey}:${maxBytes}B`);
  console.log(`    (最大値キー: ${maxKey} = ${maxBytes}B / 総キー数: ${map.size})`);
  const chunkedSubs = players.filter(p => map.get(`submissions:${p.uid}`)?._msgsChunks !== undefined).length;
  const chunkedRaws = players.filter(p => typeof map.get(`submissions_raw:${p.uid}`)?._chunks === 'number').length;
  const msgKeys = [...map.keys()].filter(k => k.startsWith('msg:')).length;
  ok('U2b 分割パスが実際に発動（メッセージ=分割キー・提出=チャンク化）',
    msgKeys === 500 && chunkedSubs === 5 && chunkedRaws === 5,
    `msgKeys=${msgKeys}, chunkedSubs=${chunkedSubs}, chunkedRaws=${chunkedRaws}`);
}

// ---- U4/U5: get-results の復元がバイト完全一致 ----
{
  const res = await inst.handleGetResults();
  const body = JSON.parse(await res.text());
  let subExact = 0, rawExact = 0;
  for (const p of players) {
    const expectedBundle = decodeSubmissionPayloadString(payloads[p.uid]).bundle;
    if (JSON.stringify(body.submissions[p.uid]) === JSON.stringify(expectedBundle)) subExact++;
    if (body.submissionsRaw[p.uid] === payloads[p.uid]) rawExact++;
  }
  ok('U4 提出バンドル復元がpayloadとバイト完全一致（フィールド順含む）', subExact === 5, `${subExact}/5`);
  ok('U5 生バイト列復元がpayloadとバイト完全一致', rawExact === 5, `${rawExact}/5`);
  ok('U4b get-results.messages = 500件', Array.isArray(body.messages) && body.messages.length === 500, `len=${body.messages?.length}`);
}

// ---- U6: first-write-wins（再提出→alreadySubmitted・保存不変） ----
{
  const p = players[0];
  const before = JSON.stringify(inst.state.storage._map.get(`submissions:${p.uid}`));
  wsOf[p.uid].sent.length = 0;
  await inst.handleWsSubmit(wsOf[p.uid], p.uid, { payload: payloads[p.uid].replace('"submittedAt"', '"submittedAt"') });
  const ack = wsOf[p.uid].sent.find(x => x.type === 'submit_ack');
  const after = JSON.stringify(inst.state.storage._map.get(`submissions:${p.uid}`));
  ok('U6 再提出はalreadySubmitted・保存不変', !!ack?.alreadySubmitted && before === after);
}

// ---- U8: デバッグdeleteが分割チャンクも完全削除 ----
{
  const p = players[1];
  const res = await inst.fetch(authedRequest('https://do/debug-submission', {
    method: 'POST', body: JSON.stringify({ action: 'delete', uid: p.uid }),
  }));
  if (!res.ok) throw new Error(`debug delete failed: ${await res.text()}`);
  const leftovers = [...inst.state.storage._map.keys()].filter(k =>
    k === `submissions:${p.uid}` || k === `submissions_raw:${p.uid}` ||
    k.startsWith(`submission_msgs:${p.uid}:`) || k.startsWith(`submissions_raw:${p.uid}:`));
  ok('U8 delete後に提出関連キーの残骸ゼロ', leftovers.length === 0, `leftovers=${leftovers.join(',')}`);
}

// ---- U7: 旧形式互換（別インスタンスで legacy 'messages' 配列と分割キーの結合） ----
{
  const inst2 = chatNS.instance(`${BLOCK_NUM}-1`);
  const p2 = [players[0], players[1]];
  const members2 = members.slice(0, 2);
  const r = await inst2.fetch(authedRequest('https://do/init', {
    method: 'POST',
    body: JSON.stringify({
      blockNum: BLOCK_NUM, groupId: 1, lang: 'ja', mixed: false, members: members2,
      periodDurations: { gamePeriod: 600000, submitPeriod: 600000 },
    }),
  }));
  if (!r.ok) throw new Error(`init2 failed: ${await r.text()}`);
  // デプロイ前に旧形式で保存されていた2件を再現
  const legacy = [
    { id: 1, uid: p2[0].uid, text: 'legacy-1', timestamp: ts++, charCount: 8, signature: '0xdead' },
    { id: 2, uid: p2[1].uid, text: 'legacy-2', timestamp: ts++, charCount: 8, signature: '0xbeef' },
  ];
  await inst2.storage.put('messages', legacy);
  await inst2.storage.put('messageCounter', 2);
  await inst2.fetch(authedRequest('https://do/set-phase', { method: 'POST', body: JSON.stringify({ phase: 'chatting' }) }));
  for (let i = 0; i < 2; i++) {
    const data = await makeChatWsData(p2[i], BLOCK_NUM, 1, `new-msg-${i}`, ts++);
    await inst2.handleWsChat(wsOf[p2[i].uid], p2[i].uid, data);
    const err = wsOf[p2[i].uid].lastError();
    if (err) throw new Error(`legacy-compat chat: ${err.message}`);
  }
  const msgs2 = await inst2.loadMessages();
  const orderOk = msgs2.length === 4 &&
    msgs2[0].text === 'legacy-1' && msgs2[1].text === 'legacy-2' &&
    msgs2[2].text === 'new-msg-0' && msgs2[3].text === 'new-msg-1' &&
    msgs2.every((m, i) => m.id === i + 1);
  ok('U7 旧形式2件＋新形式2件が旧→新の順で結合・ID連番', orderOk,
    JSON.stringify(msgs2.map(m => [m.id, m.text])));
}

// ---- U9: 旧形式分割キー（`:{NNN}`）の移行フォールバック ----
//
// 🔴 R-3（2026-08-08・ラウンド20 回帰-3）: P-2026-0841 は分割キーの区切りを `:` から
//   `GameChunkKeys.SEP`（``）へ変えた。正典（`chat-game-DO.js:727-731`）は
//   「デプロイ跨ぎの進行中ゲームがあるので**読み出し側は旧形式も当面読み続ける**」と
//   明記しているのに、それを守る検査が正典側にもここにも1本も無かった
//   （唯一の pin は `/legacyChunkKey\(/` ＝**メソッド定義行で自己充足**）。
//   実測: `purgeChunks` / `getChunk` の旧形式参照を2箇所とも消しても全テストが緑で、
//   旧形式で保存済みの提出物は raw 0 文字 / messages 0 件 になり、
//   `_fromRaw` 経路では `JSON.parse('')` → `catch { return null }` で
//   **提出済みの参加者が無言で `no_submit` 失格**する。
{
  const inst3 = chatNS.instance(`${BLOCK_NUM}-9`);
  const UID = players[0].uid;
  const legacyKey = (base, i) => `${base}:${UID}:${String(i).padStart(3, '0')}`;

  // (1) 旧形式 raw チャンク → loadSubmissionRaw がバイト完全一致で復元
  const rawStr = payloads[UID];
  const n = 4;
  const slice = Math.ceil(rawStr.length / n);
  for (let i = 0; i < n; i++) await inst3.storage.put(legacyKey('submissions_raw', i), rawStr.slice(i * slice, (i + 1) * slice));
  await inst3.storage.put(`submissions_raw:${UID}`, { _chunks: n });
  const back = await inst3.loadSubmissionRaw(UID);
  ok('U9 旧形式 raw チャンクをバイト完全一致で復元（移行窓）', back === rawStr,
    `len=${back?.length ?? 'null'} want=${rawStr.length}`);

  // (2) `_fromRaw` 経路も旧形式から復元できる（＝静かな no_submit にならない）
  await inst3.storage.put(`submissions:${UID}`, { _fromRaw: true, _msgsChunks: 0, submittedAt: '2026-08-05T09:55:00.000Z' });
  const loaded = await inst3.loadSubmission(UID);
  const expectedLoaded = decodeSubmissionPayloadString(rawStr).bundle;
  ok('U9 _fromRaw 経路が旧形式 raw から復元（null なら無言の no_submit 失格）',
    loaded !== null && JSON.stringify(loaded) === JSON.stringify(expectedLoaded),
    loaded === null ? 'null' : 'bytes differ');

  // (3) 旧形式 submission_msgs チャンク → loadSubmission が messages を全件復元
  const inst4 = chatNS.instance(`${BLOCK_NUM}-10`);
  const parsed = decodeSubmissionPayloadString(rawStr).bundle;
  const msgs = Array.isArray(parsed.messages) ? parsed.messages : [];
  const half = Math.ceil(msgs.length / 2);
  await inst4.storage.put(`submission_msgs:${UID}:000`, msgs.slice(0, half));
  await inst4.storage.put(`submission_msgs:${UID}:001`, msgs.slice(half));
  const meta = { ...parsed }; delete meta.messages; meta._msgsChunks = 2;
  await inst4.storage.put(`submissions:${UID}`, meta);
  const loaded2 = await inst4.loadSubmission(UID);
  ok('U9 旧形式 submission_msgs から messages を全件復元',
    loaded2?.messages?.length === msgs.length, `${loaded2?.messages?.length} / ${msgs.length}`);

  // (4) deleteSubmissionKeys が旧形式チャンクを1件も残さない
  await inst3.deleteSubmissionKeys(UID);
  const leftovers3 = [...inst3.state.storage._map.keys()].filter(k => k.includes(UID));
  ok('U9 deleteSubmissionKeys 後に旧形式チャンクの残骸ゼロ', leftovers3.length === 0,
    `leftovers=${leftovers3.join(',')}`);
}

console.log('');
if (failed > 0) {
  console.error(`❌ ${failed} FAILED (${passed} passed)`);
  process.exit(1);
}
console.log(`✅ ALL PASSED (${passed} checks)`);

// c1-shard-write-unit.mjs — C1/R4是正（グループ/結果/フェーズのシャード書き込み増幅）ユニットテスト
//
// 背景（総点検C1+R4）: 旧実装は①グループ書き込みのデポジッター通知をデポジット1件毎に
// 重複生成（dedupなし） ②write-worker 1台へ全行を1リクエスト（件数上限なし） ③受信側は
// 1行=1回のCAS——の三重増幅で、外部デポジッター平均5〜6件/人からwrite-workerの
// サブリクエスト1,000を超過して途中死し、win_blocksが無音欠落していた（自己修復なし）。
// 是正: 送信側=（支援者,プレイヤー）dedup＋ユーザー単位束ね＋100ユーザー毎チャンク＋
// カーソル再開＋失敗throw／受信側=uid束ね1CAS＋100ユーザー上限バリデーション。
//
// 本物の GameMasterDO（canonical.mjs）と本物の write-to-D1.js を、fetchルータ＋
// スタブD1（生値ガードCAS）で直結して検証する:
//  T1: グループ書き込み — 同一支援者の3デポジット→1レコード（dedup）・支援者CAS 1回・通知1件
//  T2: 結果書き込み — プレイヤー結果＋同一支援者の2デポジット報酬→支援者CAS 1回で2エントリー
//  T3: チャンク化 — 250ユーザー→3リクエスト（100/100/50）・全件反映
//  T4: 受信側cap — 101ユーザーのリクエストは400
//  T5: 失敗throw＋カーソル再開 — チャンク2でHTTP 500→throw・再実行はチャンク2から・完了でカーソル削除
//  T6: フェーズ更新 — 複数プレイヤーを支援する支援者はグローバルdedupで1行・1CAS・全game_deposits更新
//  T7: D1/R2予算 — 100人でCAS競合が続くと890クエリで止め、deferred 11人だけを継続送信
//  T8: 継続上限 — 受信側がdeferredを返し続けても10回でthrowし、カーソルを進めない
//  T9: R2経路 — D1 SELECT/UPDATEだけでなくR2 GET/PUTも同じ900件予算へ算入
//
// 実行: node block-verifier/test/c1-shard-write-unit.mjs （Node 22）

import { GameMasterDO } from './canonical.mjs';
import { makeState } from './stubs.mjs';
import writeWorker from '../../workers/write_workers/write-to-D1.js';

let passed = 0, failed = 0;
const ok = (name, cond, detail = '') => {
  if (cond) { passed++; realLog(`  ok: ${name}`); }
  else { failed++; realErr(`  FAIL: ${name}${detail ? ` — ${detail}` : ''}`); }
};
const norm = (sql) => sql.replace(/\s+/g, ' ').trim();
const BLOCK = 7;
const SECRET = 'test-secret';
const realLog = console.log.bind(console), realErr = console.error.bind(console), realWarn = console.warn.bind(console);

// ---- シャードD1スタブ（users行・生値ガードCAS・a4ユニットと同型） ----
function makeShardDb({ casConflicts = new Map() } = {}) {
  const users = new Map();
  const stats = { blobUpdates: {}, d1Queries: 0 };
  const db = {
    prepare(sql) {
      const q = norm(sql);
      return { bind(...args) {
        const exec = () => {
          let m;
          if (q === 'INSERT OR IGNORE INTO users (id, username) VALUES (?, ?)') {
            if (!users.has(String(args[0]))) {
              users.set(String(args[0]), { deposits_from: null, deposits_to: null, win_blocks: null });
            }
            return { results: [], meta: { changes: 1 } };
          }
          if ((m = q.match(/^SELECT (.+) FROM users WHERE id = \?$/))) {
            const row = users.get(String(args[0]));
            if (!row) return { results: [] };
            const out = {};
            for (const c of m[1].split(',').map(s => s.trim())) out[c] = row[c] ?? null;
            return { results: [out] };
          }
          // UPDATE users SET <cols> WHERE id = ? AND <col> IS ? ...（生値ガード CAS）
          // ⚠️ K-S5-010（2026-07-31）でガード列に相乗り列 mined が加わった。SQL 文字列を
          //    丸ごと固定すると同種の変更のたびに「unhandled SQL」で落ちるので、形を解釈する。
          //    ただし「ガードが消える」退行は見逃してはいけないので mined の存在は明示検査する。
          if ((m = q.match(/^UPDATE users SET (.+) WHERE id = \? AND (.+)$/))) {
            const setCols = m[1].split(',').map(x => x.trim().replace(/ = \?$/, ''));
            const guardCols = m[2].split(' AND ').map(x => x.trim().replace(/ IS \?$/, ''));
            // K-S5-010 の不変条件: **書く列は必ずガードにも入れる。**
            // 相乗り列 mined は /write-game-results だけが書くので、
            // 「SET に mined があるのにガードに無い」＝退行、として条件付きで検査する
            // （/write-game-groups は mined を書かないのでガードにも入らないのが正しい）。
            if (setCols.includes('mined') && !guardCols.includes('mined')) {
              throw new Error(`shard D1 stub: mined を書くのに CAS ガードに入っていない（K-S5-010 の退行）: ${q}`);
            }
            const setVals = args.slice(0, setCols.length);
            const id = String(args[setCols.length]);
            const guardVals = args.slice(setCols.length + 1);
            const row = users.get(id);
            const remainingConflicts = Number(casConflicts.get(id) || 0);
            if (remainingConflicts > 0) {
              casConflicts.set(id, remainingConflicts - 1);
              return { results: [], meta: { changes: 0 } };
            }
            const same = (a, b) => (a ?? null) === (b ?? null);
            if (!row || !guardCols.every((c, i) => same(row[c], guardVals[i]))) {
              return { results: [], meta: { changes: 0 } };
            }
            setCols.forEach((c, i) => { row[c] = setVals[i]; });
            stats.blobUpdates[id] = (stats.blobUpdates[id] || 0) + 1;
            return { results: [], meta: { changes: 1 } };
          }
          throw new Error(`shard D1 stub: unhandled SQL: ${q}`);
        };
        return {
          async all() { stats.d1Queries++; return exec(); },
          async run() { stats.d1Queries++; return exec(); },
          async first() { stats.d1Queries++; const r = exec(); return r.results[0] ?? null; },
        };
      } };
    },
  };
  return { db, users, stats };
}

// ---- 中央D1スタブ（game_groups読み取りのみ） ----
function makeCentralDb(groupRows) {
  return {
    prepare(sql) {
      const q = norm(sql);
      return { bind(...args) {
        const exec = () => {
          if (q === 'SELECT group_id, lang, members FROM game_groups WHERE block_num = ? ORDER BY group_id') {
            return { results: groupRows.filter(g => g.block_num === args[0]) };
          }
          if (q === 'SELECT members FROM game_groups WHERE block_num = ? ORDER BY group_id') {
            return { results: groupRows.filter(g => g.block_num === args[0]).map(g => ({ members: g.members })) };
          }
          throw new Error(`central D1 stub: unhandled SQL: ${q}`);
        };
        return {
          async all() { return exec(); },
          async run() { return exec(); },
          async first() { const r = exec(); return r.results[0] ?? null; },
        };
      } };
    },
  };
}

// ---- 世界構築: 実write-to-D1.jsをfetchルータで直結 ----
// 本テストのuidは全て末尾4桁が0000-0249（worker 0レンジ）＝ルータは全シャードを
// 同一スタブDBへ解決する（シャード分散自体はここでは検証対象外）。
function makeWorld(groupRows, {
  casConflicts = new Map(),
  r2Bucket = { get: async () => null },
} = {}) {
  const shard = makeShardDb({ casConflicts });
  const workerEnv = new Proxy({
    API_SECRET: SECRET,
    WORKER_INDEX: 0,
    R2_BUCKET: r2Bucket,
  }, {
    get(t, p) {
      if (p in t) return t[p];
      if (typeof p === 'string' && p.startsWith('SHARD_')) return shard.db;
      return undefined;
    },
  });

  const requests = [];                       // { endpoint, body }
  const failOnce = { at: -1, used: false };  // requests.length===at のリクエストを1回だけ500に
  // S3-003 / K-S4-001 / K-S5-001（2026-07-29）: DO→write-worker は公開 workers.dev URL への
  // fetch ではなく **Service Binding**（env.WRITE_WORKER_<n>）になった。
  // requireBinding は fail-closed で、公開URLへの暗黙フォールバックを持たない。
  const writeBinding = {
    async fetch(request) {
      const u = new URL(request.url);       // Service Binding のURLは内部固定（ホスト名は意味を持たない）
      const idx = requests.length;
      requests.push({ endpoint: u.pathname, body: await request.clone().json() });
      if (failOnce.at === idx && !failOnce.used) {
        failOnce.used = true;
        return new Response('boom', { status: 500 });
      }
      const beforeD1 = shard.stats.d1Queries;
      const response = await writeWorker.fetch(request, workerEnv);
      requests[idx].d1Queries = shard.stats.d1Queries - beforeD1;
      requests[idx].response = await response.clone().json();
      return response;
    },
  };
  // 公開URLへの退行を検出するガード: 正典が globalThis.fetch を使ったら即失敗させる
  const fetchRouter = async (url) => { throw new Error(`unexpected global fetch (service binding へ移行済み): ${url}`); };

  // WRITE_WORKER_0..39 を全て同じスタブへ束ねる（このテストの主題はシャード分散ではない）
  const gmEnv = new Proxy({
    RELEASE_TIME: '2099-01-01T00:00:00Z',
    API_SECRET: SECRET,
    BITCOINU_DATA: makeCentralDb(groupRows),
  }, {
    get(t, p) {
      if (p in t) return t[p];
      if (typeof p === 'string' && /^WRITE_WORKER_\d+$/.test(p)) return writeBinding;
      return undefined;
    },
    has(t, p) { return (p in t) || (typeof p === 'string' && /^WRITE_WORKER_\d+$/.test(p)); },
  });
  const gm = new GameMasterDO(makeState(), gmEnv);
  return { gm, shard, workerEnv, requests, failOnce, fetchRouter, writeBinding };
}

const winOf = (shard, uid) => JSON.parse(shard.users.get(uid)?.win_blocks || 'null');

// consoleノイズ抑制つき実行（fetchルータの配線・復元込み）
const origFetch = globalThis.fetch;
async function runQuiet(world, fn) {
  console.log = () => {}; console.error = () => {}; console.warn = () => {};
  globalThis.fetch = world.fetchRouter;
  try { return await fn(); }
  finally { globalThis.fetch = origFetch; console.log = realLog; console.error = realErr; console.warn = realWarn; }
}

// ============================================================
// T1: グループ書き込み — 支援者dedup・1CAS・通知1件
// ============================================================
{
  // プレイヤーA('900001')に支援者B('900002')が3回デポジット＋自己デポジット1件
  const world = makeWorld([{
    block_num: BLOCK, group_id: 0, lang: 'ja',
    members: JSON.stringify([{
      uid: '900001',
      depIds: JSON.stringify({ deposits: [
        { id: 'd1', idFrom: '900002', deposit: '10000000000000000' },
        { id: 'd2', idFrom: '900002', deposit: '10000000000000000' },
        { id: 'd3', idFrom: '900002', deposit: '10000000000000000' },
        { id: 'd4', idFrom: '900001', deposit: '10000000000000000' },
      ] }),
    }]),
  }]);
  // プレイヤー行はwrite-worker側でusers行が必要（プレイヤーはINSERT OR IGNORE対象外）
  world.shard.users.set('900001', { deposits_from: null, deposits_to: null, win_blocks: null });

  const result = await runQuiet(world, () => world.gm.writeGameGroupsToShards(BLOCK));

  ok('T1 リクエストは1回（1チャンク）', world.requests.length === 1, String(world.requests.length));
  const sent = world.requests[0]?.body?.members || [];
  const depRows = sent.filter(m => m.role === 'depositor');
  ok('T1b 支援者レコードは1件にdedup（3デポジット・自己は除外）',
    depRows.length === 1 && depRows[0].uid === '900002' && depRows[0].playerUid === '900001',
    JSON.stringify(depRows));
  const bWin = winOf(world.shard, '900002');
  ok('T1c 支援者の通知エントリーは1件', (bWin?.[BLOCK]?.game_deposits || []).length === 1, JSON.stringify(bWin));
  ok('T1d プレイヤーAのgame書き込み', winOf(world.shard, '900001')?.[BLOCK]?.game?.groupId === 0);
  ok('T1e 支援者のCASは1回', world.shard.stats.blobUpdates['900002'] === 1,
    JSON.stringify(world.shard.stats.blobUpdates));
  ok('T1f 戻り値=総書き込み行数・エラー0', result.totalWritten === 2 && result.totalErrors === 0, JSON.stringify(result));
}

// ============================================================
// T2: 結果書き込み — ユーザー単位束ね（プレイヤー結果＋複数デポジット報酬=1CAS）
// ============================================================
{
  const world = makeWorld([]);
  world.shard.users.set('900001', { deposits_from: null, deposits_to: null, win_blocks: null });
  world.shard.users.set('900002', { deposits_from: null, deposits_to: null, win_blocks: null });

  const allGroupResults = [{ groupId: 0, members: [
    { uid: '900001', depositPoints: 10, bonusPoints: 5, totalPoints: 15, isDisqualified: false, disqualifyReason: null, btcuReward: '1000' },
  ] }];
  const depositorResults = [
    { groupId: 0, playerUid: '900001', depositorUid: '900002', depositId: 'd1', btcuReward: '10' },
    { groupId: 0, playerUid: '900001', depositorUid: '900002', depositId: 'd2', btcuReward: '20' },
  ];
  const result = await runQuiet(world, () => world.gm.writeGameResultsToShards(BLOCK, allGroupResults, depositorResults));

  ok('T2 リクエストは1回・3行', world.requests.length === 1 && result.totalWritten === 3, JSON.stringify(result));
  ok('T2b 支援者のCASは1回で2報酬エントリー',
    world.shard.stats.blobUpdates['900002'] === 1 &&
    (winOf(world.shard, '900002')?.[BLOCK]?.game_deposits || []).length === 2,
    JSON.stringify(world.shard.stats.blobUpdates));
  const aGame = winOf(world.shard, '900001')?.[BLOCK]?.game;
  ok('T2c プレイヤー結果書き込み（result.btcuReward）',
    aGame?.phase === 'completed' && aGame?.result?.btcuReward === '1000', JSON.stringify(aGame));
  ok('T2d 結果カーソルは完了時に削除', (await world.gm.storage.get(world.gm.calcKey(BLOCK, 'shards_cursor'))) === undefined);
}

// ============================================================
// T3: チャンク化 — 250ユーザー→3リクエスト（100/100/50）
// ============================================================
{
  // uid末尾4桁を0000-0249に分散（全てworker 0レンジ・スタブでは同一DB）
  const uids = Array.from({ length: 250 }, (_, i) => `9${String(i).padStart(4, '0')}`);
  const world = makeWorld([]);
  for (const uid of uids) world.shard.users.set(uid, { deposits_from: null, deposits_to: null, win_blocks: null });

  const allGroupResults = [{ groupId: 0, members: uids.map(uid => ({
    uid, depositPoints: 1, bonusPoints: 0, totalPoints: 1, isDisqualified: false, disqualifyReason: null, btcuReward: '1',
  })) }];
  const result = await runQuiet(world, () => world.gm.writeGameResultsToShards(BLOCK, allGroupResults, []));

  const sizes = world.requests.map(r => new Set(r.body.members.map(m => String(m.uid))).size);
  ok('T3 3リクエスト（100/100/50ユーザー）', JSON.stringify(sizes) === '[100,100,50]', JSON.stringify(sizes));
  ok('T3b 全250件反映', result.totalWritten === 250 &&
    uids.every(uid => winOf(world.shard, uid)?.[BLOCK]?.game?.phase === 'completed'));
}

// ============================================================
// T4: 受信側cap — 101ユーザーは400
// ============================================================
{
  const world = makeWorld([]);
  const members = Array.from({ length: 101 }, (_, i) => ({ uid: `9${String(i).padStart(4, '0')}`, groupId: 0, lang: 'ja' }));
  const res = await runQuiet(world, () => writeWorker.fetch(new Request(
    'https://write-worker-0000_0249.tasuketsu1954.workers.dev/write-game-groups',
    { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Api-Secret': SECRET },
      body: JSON.stringify({ block_num: BLOCK, members }) }
  ), world.workerEnv));
  ok('T4 101ユーザーのリクエストは400', res.status === 400);

  const res100 = await runQuiet(world, () => writeWorker.fetch(new Request(
    'https://write-worker-0000_0249.tasuketsu1954.workers.dev/update-game-phase',
    { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Api-Secret': SECRET },
      body: JSON.stringify({ block_num: BLOCK, phase: 'chatting', members: members.slice(0, 100), deferred_protocol: 1 }) }
  ), world.workerEnv));
  ok('T4b 100ユーザーは受理（フェーズ側も同cap）', res100.status === 200);

  const legacy = await runQuiet(world, () => writeWorker.fetch(new Request(
    'https://write-worker-0000_0249.tasuketsu1954.workers.dev/write-game-groups',
    { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Api-Secret': SECRET },
      body: JSON.stringify({ block_num: BLOCK, members: members.slice(0, 1) }) }
  ), world.workerEnv));
  ok('T4c 予算継続が不要な通常経路ではdeferredは発動しない', legacy.status === 200);
}

// ============================================================
// T5: 失敗throw＋カーソル再開（グループ書き込み・250ユーザー=3チャンク）
// ============================================================
{
  const uids = Array.from({ length: 250 }, (_, i) => `9${String(i).padStart(4, '0')}`);
  const world = makeWorld(uids.map((uid, i) => ({
    block_num: BLOCK, group_id: i, lang: 'ja',
    members: JSON.stringify([{ uid, depIds: null }]),
  })));
  for (const uid of uids) world.shard.users.set(uid, { deposits_from: null, deposits_to: null, win_blocks: null });

  // 2番目のリクエスト（チャンク2）を1回だけHTTP 500に
  world.failOnce.at = 1;
  let thrown = null;
  await runQuiet(world, async () => {
    try { await world.gm.writeGameGroupsToShards(BLOCK); } catch (e) { thrown = e; }
  });
  const cursorKey = `grouping_shard_cursor_block${BLOCK}`;
  ok('T5 チャンク失敗はthrow（無音欠落しない）', thrown !== null && /HTTP 500/.test(thrown.message), thrown?.message);
  ok('T5b カーソル=1（チャンク1完了済み）', (await world.gm.storage.get(cursorKey)) === 1);

  const before = world.requests.length; // 2（成功1+失敗1）
  const result = await runQuiet(world, () => world.gm.writeGameGroupsToShards(BLOCK));
  ok('T5c 再実行はチャンク2から（追加リクエスト2回のみ）', world.requests.length - before === 2,
    String(world.requests.length - before));
  ok('T5d 全件反映＋カーソル削除', result.totalWritten === 150 /* 再開分のみの計上 */ &&
    uids.every(uid => winOf(world.shard, uid)?.[BLOCK]?.game) &&
    (await world.gm.storage.get(cursorKey)) === undefined,
    JSON.stringify({ written: result.totalWritten }));
}

// ============================================================
// T6: フェーズ更新 — 支援者グローバルdedup・1CAS・全エントリー更新
// ============================================================
{
  // B('900002')がA('900001')とC('900003')の両方を支援
  const world = makeWorld([
    { block_num: BLOCK, group_id: 0, lang: 'ja', members: JSON.stringify([
      { uid: '900001', depIds: JSON.stringify({ deposits: [{ id: 'd1', idFrom: '900002' }] }) },
    ]) },
    { block_num: BLOCK, group_id: 1, lang: 'ja', members: JSON.stringify([
      { uid: '900003', depIds: JSON.stringify({ deposits: [{ id: 'd2', idFrom: '900002' }] }) },
    ]) },
  ]);
  for (const uid of ['900001', '900002', '900003']) {
    world.shard.users.set(uid, { deposits_from: null, deposits_to: null, win_blocks: null });
  }
  // 事前状態: グループ書き込み済み相当のwin_blocks
  world.shard.users.get('900001').win_blocks = JSON.stringify({ [BLOCK]: { game: { groupId: 0, phase: 'preparing' } } });
  world.shard.users.get('900003').win_blocks = JSON.stringify({ [BLOCK]: { game: { groupId: 1, phase: 'preparing' } } });
  world.shard.users.get('900002').win_blocks = JSON.stringify({ [BLOCK]: { game_deposits: [
    { groupId: 0, playerUid: '900001', phase: 'preparing', role: 'depositor' },
    { groupId: 1, playerUid: '900003', phase: 'preparing', role: 'depositor' },
  ] } });

  const result = await runQuiet(world, () => world.gm.updateGamePhaseToShards(BLOCK, 'chatting'));

  const sent = world.requests[0]?.body?.members || [];
  ok('T6 行はグローバルdedup（3ユーザー=3行・Bは1行）',
    sent.length === 3 && sent.filter(m => m.uid === '900002').length === 1, JSON.stringify(sent));
  ok('T6b Bの2つのgame_depositsが両方chattingへ・CAS1回',
    winOf(world.shard, '900002')[BLOCK].game_deposits.every(d => d.phase === 'chatting') &&
    world.shard.stats.blobUpdates['900002'] === 1);
  ok('T6c プレイヤーのphaseも更新',
    winOf(world.shard, '900001')[BLOCK].game.phase === 'chatting' &&
    winOf(world.shard, '900003')[BLOCK].game.phase === 'chatting');
  ok('T6d written=行数・エラー0', result.totalWritten === 3 && result.totalErrors === 0, JSON.stringify(result));
}

// ============================================================
// T7: D1予算到達 — deferred uidだけを継続送信
// ============================================================
{
  const uids = Array.from({ length: 100 }, (_, i) => `9${String(i).padStart(4, '0')}`);
  // 各uidは4回CAS競合し、5回目で成功（SELECT+UPDATE × 5 = 10 D1クエリ）。
  // R2経路の最悪4サブリクエスト/試行も予約するため、890件で89人まで完了し、
  // 残り11人は同じwrite-workerへの継続便になる。
  const casConflicts = new Map(uids.map((uid) => [uid, 4]));
  const world = makeWorld([], { casConflicts });
  for (const uid of uids) world.shard.users.set(uid, { deposits_from: null, deposits_to: null, win_blocks: null });

  const allGroupResults = [{ groupId: 0, members: uids.map(uid => ({
    uid, depositPoints: 1, bonusPoints: 0, totalPoints: 1,
    isDisqualified: false, disqualifyReason: null, btcuReward: '1',
  })) }];
  const result = await runQuiet(world, () => world.gm.writeGameResultsToShards(BLOCK, allGroupResults, []));

  const sizes = world.requests.map((request) => new Set(request.body.members.map((member) => String(member.uid))).size);
  ok('T7 予算到達時は100人束→deferred 11人の2リクエスト',
    JSON.stringify(sizes) === '[100,11]', JSON.stringify(sizes));
  ok('T7b 1便目はストレージサブリクエスト890件で89人完了・11人deferred',
    world.requests[0]?.d1Queries === 890 &&
    world.requests[0]?.response?.written_count === 89 &&
    world.requests[0]?.response?.deferred_count === 11,
    JSON.stringify(world.requests[0]?.response));
  ok('T7c 継続便はdeferred 11人だけを完了',
    world.requests[1]?.d1Queries === 110 &&
    world.requests[1]?.response?.written_count === 11 &&
    world.requests[1]?.response?.deferred_count === 0,
    JSON.stringify(world.requests[1]?.response));
  ok('T7d 全100人は各1回だけコミットされ、総written=100',
    result.totalWritten === 100 && uids.every((uid) => world.shard.stats.blobUpdates[uid] === 1),
    JSON.stringify({ totalWritten: result.totalWritten, updates: world.shard.stats.blobUpdates }));
  ok('T7e チャンク・deferredカーソルは完了時に両方削除',
    (await world.gm.storage.get(world.gm.calcKey(BLOCK, 'shards_cursor'))) === undefined &&
    (await world.gm.storage.get(`${world.gm.calcKey(BLOCK, 'shards_cursor')}:deferred`)) === undefined);

  const legacyConflicts = new Map(uids.map((uid) => [uid, 4]));
  const legacyWorld = makeWorld([], { casConflicts: legacyConflicts });
  for (const uid of uids) legacyWorld.shard.users.set(uid, {
    deposits_from: null, deposits_to: null, win_blocks: null,
  });
  const legacyResponse = await runQuiet(legacyWorld, () => writeWorker.fetch(new Request(
    'https://write-worker-0000_0249.tasuketsu1954.workers.dev/write-game-results',
    { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Api-Secret': SECRET },
      body: JSON.stringify({ block_num: BLOCK, members: allGroupResults[0].members }) }
  ), legacyWorld.workerEnv));
  ok('T7f deferred対応未申告の旧送信側は、予算継続が必要になった時点で409でfail-closed',
    legacyResponse.status === 409 && Object.keys(legacyWorld.shard.stats.blobUpdates).length === 89,
    JSON.stringify({ status: legacyResponse.status, completed: Object.keys(legacyWorld.shard.stats.blobUpdates).length }));
}

// ============================================================
// T8: deferred継続上限 — 無限ループせずthrow
// ============================================================
{
  const world = makeWorld([]);
  const calls = [];
  world.writeBinding.fetch = async (request) => {
    const body = await request.json();
    calls.push(body);
    const uids = [...new Set(body.members.map((member) => String(member.uid)))];
    return new Response(JSON.stringify({
      written_count: 1,
      error_count: 0,
      deferred: uids.slice(1),
    }), { status: 200 });
  };
  const members = Array.from({ length: 100 }, (_, i) => ({ uid: `9${String(i).padStart(4, '0')}` }));
  let thrown = null;
  await runQuiet(world, async () => {
    try {
      await world.gm.sendShardWriteChunks(
        '/write-game-results', BLOCK,
        [{ workerIndex: 0, users: 100, members }],
        { cursorKey: 't8_cursor' }
      );
    } catch (error) { thrown = error; }
  });
  ok('T8 追加リクエスト10回を超える前にthrow',
    /continuation limit exceeded/.test(thrown?.message || '') && calls.length === 11,
    JSON.stringify({ error: thrown?.message, calls: calls.length }));
  ok('T8b 未処理uidを残し、チャンクカーソルは進めない',
    (await world.gm.storage.get('t8_cursor')) === undefined &&
    (await world.gm.storage.get('t8_cursor:deferred'))?.uids?.length === 89);
}

// ============================================================
// T9: R2経路もストレージサブリクエスト予算へ算入
// ============================================================
{
  const uid = '900001';
  const r2Key = `users_data/${uid}.json`;
  let stored = JSON.stringify({ deposits_from: {}, deposits_to: {}, win_blocks: {} });
  let etag = 'etag-1';
  let r2Queries = 0;
  const r2Bucket = {
    async get(key) {
      r2Queries++;
      if (key !== r2Key) return null;
      return { etag, async text() { return stored; } };
    },
    async put(key, body, options) {
      r2Queries++;
      if (key !== r2Key || options?.onlyIf?.etagMatches !== etag) return null;
      stored = String(body);
      etag = 'etag-2';
      return { etag };
    },
  };
  const world = makeWorld([], { r2Bucket });
  const ref = `r2:${r2Key}`;
  world.shard.users.set(uid, { deposits_from: ref, deposits_to: ref, win_blocks: ref, mined: null });
  const result = await runQuiet(world, () => world.gm.writeGameResultsToShards(BLOCK, [{
    groupId: 0,
    members: [{
      uid, depositPoints: 1, bonusPoints: 0, totalPoints: 1,
      isDisqualified: false, disqualifyReason: null, btcuReward: '1',
    }],
  }], []));
  ok('T9 R2経路はD1 2件＋R2 2件＝ストレージサブリクエスト4件と数える',
    result.totalWritten === 1 &&
    world.requests[0]?.d1Queries === 2 && r2Queries === 2,
    JSON.stringify({ d1Queries: world.requests[0]?.d1Queries, r2Queries, response: world.requests[0]?.response }));
}

realLog(`\nc1-shard-write-unit: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

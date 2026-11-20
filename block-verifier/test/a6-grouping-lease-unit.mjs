// a6-grouping-lease-unit.mjs — A6是正（startGroupingのリース化＝途中死からの自己復旧）ユニットテスト
//
// 背景（②監査 A6）: グループ分けの'started'クレームは無期限で、実行がcatchを通らず死ぬ
// （runtime kill・退避・再デプロイ）と札が'started'のまま残り、以後の再実行が永遠に弾かれて
// そのブロックのゲームが二度と始まらなかった（手動復旧のみ・2100人級では処理が長く現実的）。
// 是正: クレームは期限付きリース（各フェーズ境界で延長）・期限切れは乗っ取り再実行可
// （決定論的シード＝再実行で同一グループ・全書き込み冪等）・クレーム時にwatchdogタスクを
// 仕掛けて自己復旧（A3/calcのresurrectionと同思想）・乗っ取り上限20でpark。
//
// 本物の GameMasterDO をスタブstate上で駆動する（重い内部処理のみインスタンス上で差し替え）:
//  T1: 正常完走 — completed・watchdog登録・完走後のwatchdogはno-op
//  T2: リース有効中の再実行要求は拒絶（二重実行防止は維持）
//  T3: リース切れ乗っ取り → 最初から再実行して完走（attempts加算）／leaseUntil無しの旧'started'も対象
//  T4: 途中死 → alarm(watchdog)が自動で再実行して完走（自己復旧の本体）
//  T5: リース有効中のwatchdogは失効後の再チェックを予約するだけ（生きている実行を乗っ取らない）
//  T6: 乗っ取り上限20超 → park・以後の再実行/watchdogは何もしない
//  T7: preparing到達後の途中死 → resume（チャット初期化再送＋スケジュールのみ・グループ再作成なし）
//  T8: chatting以降まで進行済み → progressをcompletedへ自己修復のみ
//  T9: schedulePhaseTransitionsは同一ブロックのタスクを置き換え（resume再実行で二重登録しない）
//  T10: 初回実行(attempts=1)でD1に進行済みデータ → 従来どおりfailed（安全弁の維持）
//  T11: watchdogタスク自体のdequeue直後kill → A3マーカーresurrectionで復活して自己復旧
//  T13: AdminTxCoordinatorのpendingはresumable、未接続はterminal（成功偽装なし）
//
// 実行: node block-verifier/test/a6-grouping-lease-unit.mjs （Node 22）

import { GameMasterDO } from './canonical.mjs';
import { makeState } from './stubs.mjs';

let passed = 0, failed = 0;
const ok = (name, cond, detail = '') => {
  if (cond) { passed++; console.log(`  ok: ${name}`); }
  else { failed++; console.error(`  FAIL: ${name}${detail ? ` — ${detail}` : ''}`); }
};
const norm = (sql) => sql.replace(/\s+/g, ' ').trim();

const BLOCK = 5;
const pk = `grouping_block${BLOCK}_progress`;
const LEASE_MS = 10 * 60 * 1000;

// 中央D1スタブ: game_groups の状態別行数を設定できる
function makeDb(rowsByStatus = {}) {
  return {
    prepare(sql) {
      const q = norm(sql);
      return { bind() {
        const exec = () => {
          if (q.startsWith("SELECT COUNT(*) as cnt FROM game_groups WHERE block_num = ? AND status != 'formed'")) {
            const cnt = Object.entries(rowsByStatus).filter(([s]) => s !== 'formed').reduce((a, [, c]) => a + c, 0);
            return { results: [{ cnt }] };
          }
          if (q.startsWith("SELECT COUNT(*) AS cnt FROM game_groups WHERE block_num = ? AND status = 'formed'")) {
            return { results: [{ cnt: rowsByStatus.formed || 0 }] };
          }
          if (q.startsWith('SELECT status, COUNT(*) AS cnt FROM game_groups WHERE block_num = ? GROUP BY status')) {
            return { results: Object.entries(rowsByStatus).map(([status, cnt]) => ({ status, cnt })) };
          }
          if (q === 'SELECT group_id FROM game_groups WHERE block_num = ?') {
            const count = Object.values(rowsByStatus).reduce((sum, n) => sum + n, 0);
            return { results: Array.from({ length: count }, (_, group_id) => ({ group_id })) };
          }
          throw new Error(`db stub: unhandled SQL: ${q}`);
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

// 本物のGameMasterDO。重い内部処理（R2/シャード/チャット初期化等）だけ記録付きスタブに差し替え
function makeGm({ rowsByStatus = {}, players, randaoAnchor } = {}) {
  const state = makeState();
  const alarms = [];
  state.storage.setAlarm = async (t) => { alarms.push(t); };
  const r2Puts = {}; // key -> value（putR2Objectの記録）
  const env = {
    RELEASE_TIME: '2099-01-01T00:00:00Z',
    BITCOINU_DATA: makeDb(rowsByStatus),
    R2_BUCKET: {
      get: async (key) => Object.prototype.hasOwnProperty.call(r2Puts, key) ? {
        text: async () => JSON.stringify(r2Puts[key]),
        json: async () => structuredClone(r2Puts[key]),
      } : null,
      put: async (key, value) => { r2Puts[key] = JSON.parse(String(value)); return {}; },
    },
  };
  const gm = new GameMasterDO(state, env);
  const calls = { writeD1: 0, init: 0, start: 0, auto: 0, merkle: 0, manifest: 0 };
  // S3-001（2026-07-29）: startGrouping は 100 個の info ファイルから応募者数を数え直し
  // （readCommittedEntryInfos）、game_selection.json を verifySelectionIntegrity で再現検査する。
  // R2 の totalEntries を信用しなくなったので、スタブも info ファイルを返す必要がある。
  // 全員当選（totalEntries === totalSelected）にすると selectWinners が短絡するため
  // globalIndex は連番でよい。
  // P-2026-0815（2026-08-07）: 検査は当選者行を **info ＋ entries データファイル**から
  // 再構築して localIndex / file / data まで照合するようになった。スタブも
  // info に filename を載せ、そのデータファイルの実体を返す必要がある。
  const DATA_FILE = '00_0';
  const ps = players !== undefined ? players
    : [0, 1, 2, 3, 4].map((i) => ({ globalIndex: i, localIndex: i, file: DATA_FILE, data: { uid: String(i + 1) } }));
  gm.getR2Object = async (key) => {
    const k = String(key);
    if (k.includes('game_selection.json')) {
      return {
        blockNum: BLOCK,
        totalEntries: ps.length,
        totalSelected: ps.length,
        players: ps,
        randao: '0x' + '11'.repeat(32),
        applicantHash: '0x' + '22'.repeat(32),
      };
    }
    const m = k.match(/\/info\/(\d{2})_info\.json$/);
    if (m) return { entries: (m[1] === '00' && ps.length > 0) ? [{ filename: DATA_FILE, number: ps.length }] : [] };
    if (k.endsWith(`/entries/${DATA_FILE}.json`)) return ps.map((p) => p.data);
    return null;
  };
  gm.computeMajorLangs = async () => [];
  if (randaoAnchor) gm.anchorRandaoTargetOnChain = async () => structuredClone(randaoAnchor);
  // 🔴 P-2026-0817（2026-08-07）: **`formGroups` / `createGroupSummary` /
  //    `buildBlockSummaryForR2` はスタブせず本物を使う。**
  //    旧スタブは `members: []` の空グループを返していたが、
  //    `verifyGroupingIntegrity`（新設）が「全当選者がちょうど1つのグループに入る」ことを
  //    照合するので、空メンバーだと `5 winner(s) are not in any group` で必ず落ちる。
  //    このテストが見たいのはリースと watchdog の挙動なので、
  //    **検査を無効化するのではなくスタブを現実に合わせる**（本物の分割を通す）。
  //    ⚠️ `writeGroupsToD1` だけは副作用の回数を数えたいのでスタブのまま。
  gm.writeGroupsToD1 = async () => { calls.writeD1++; };
  // S3-011（2026-07-29）: putR2ObjectOrThrow が戻り値を検査するようになった
  // （公開データの書き込み失敗を無言で通さない）。本番 putR2Object は true を返す。
  gm.putR2Object = async (key, value) => { r2Puts[key] = value; return true; };
  gm.writeGameGroupsToShards = async () => ({ totalWritten: 5, totalErrors: 0 });
  gm.initChatGames = async () => { calls.init++; return { success: true, initialized: 1, alreadyInitialized: 0, errors: 0 }; };
  gm.autoDistribute = async () => { calls.auto++; return {}; };
  // S3-010（2026-07-29）: 「公開＋提出を1回で行う publishAndSubmitMerkle」は**削除された**。
  // root 提出は常に全工程の最後（tree publish → manifest → 提出）。存在しないメソッドを
  // スタブしても呼ばれないので、分割後の2つを個別に差し替える。
  gm.publishMerkleTree = async () => { calls.merkle++; return { ok: true, root: '0xsentinel' }; };
  gm.submitMerkleRootForBlock = async () => ({ submitted: true });
  gm.publishVerificationManifest = async () => { calls.manifest++; return { ok: true }; };
  const origStart = gm.startGrouping.bind(gm);
  gm.startGrouping = (n) => { calls.start++; return origStart(n); };
  return { gm, state, store: state.storage._map, alarms, calls, r2Puts };
}
const queueOf = (store) => store.get('phase_task_queue') || [];

// ---- T1: 正常完走＋watchdog登録・完走後のwatchdogはno-op ----
{
  const w = makeGm();
  const before = Date.now();
  const r = await w.gm.startGrouping(BLOCK);
  const prog = w.store.get(pk);
  ok('T1 正常完走（completed・attempts=1・leaseUntil付与）',
    r.success === true && prog.status === 'completed' && prog.attempts === 1 && prog.leaseUntil >= before + LEASE_MS - 1000,
    JSON.stringify({ r: r.success, prog: prog.status }));
  const wd = queueOf(w.store).find(t => t.type === 'grouping_watchdog' && t.blockNum === BLOCK);
  ok('T1b クレーム時にwatchdogタスクが登録される（リース失効後に発火）',
    !!wd && wd.executeAt >= before + LEASE_MS && w.alarms.length > 0, JSON.stringify(queueOf(w.store)));

  // 完走後にwatchdogが発火してもno-op（再実行しない・キューから消える）
  wd.executeAt = Date.now() - 1000;
  await w.gm.storage.put('phase_task_queue', queueOf(w.store));
  await w.gm.alarm();
  ok('T1c 完走後のwatchdogはno-op（再実行なし・キュー掃除）',
    w.calls.start === 1 && !queueOf(w.store).some(t => t.type === 'grouping_watchdog'));
}

// ---- T2: リース有効中は拒絶 ----
{
  const w = makeGm();
  w.store.set(pk, { blockNum: BLOCK, status: 'started', attempts: 1, leaseUntil: Date.now() + LEASE_MS, phase: 'forming_groups' });
  const r = await w.gm.startGrouping(BLOCK);
  ok('T2 リース有効中の再実行要求は拒絶', r.success === false && /already started/.test(r.error) && w.store.get(pk).status === 'started');
}

// ---- T3: リース切れ乗っ取り ----
{
  const w = makeGm();
  w.store.set(pk, { blockNum: BLOCK, status: 'started', attempts: 1, leaseUntil: Date.now() - 1000, phase: 'writing_to_shard_dbs' });
  const r = await w.gm.startGrouping(BLOCK);
  ok('T3 リース切れは乗っ取って最初から完走（attempts=2）',
    r.success === true && w.store.get(pk).status === 'completed' && w.store.get(pk).attempts === 2 && w.calls.writeD1 === 1);

  const w2 = makeGm();
  w2.store.set(pk, { blockNum: BLOCK, status: 'started', phase: 'forming_groups' }); // 旧実装の'started'（leaseUntil無し）
  const r2 = await w2.gm.startGrouping(BLOCK);
  ok('T3b リース導入前の旧\'started\'も乗っ取り可能（既存スタック状態の自己修復）',
    r2.success === true && w2.store.get(pk).status === 'completed');
}

// ---- T4: 途中死 → watchdogが自動再実行 ----
{
  const w = makeGm();
  // 「writing_to_d1フェーズで死んだ」状態: progressはstartedのままリース失効・watchdogだけ残存
  w.store.set(pk, { blockNum: BLOCK, status: 'started', attempts: 1, leaseUntil: Date.now() - 1000, phase: 'writing_to_d1' });
  w.store.set('phase_task_queue', [{ type: 'grouping_watchdog', blockNum: BLOCK, executeAt: Date.now() - 1000 }]);
  await w.gm.alarm();
  ok('T4 watchdogが途中死を検知して自動再実行→完走（自己復旧）',
    w.calls.start === 1 && w.store.get(pk).status === 'completed' && w.store.get(pk).attempts === 2
    && !w.store.has('phase_task_active'),
    JSON.stringify({ start: w.calls.start, prog: w.store.get(pk) }));
}

// ---- T5: リース有効中のwatchdogは再チェック予約のみ ----
{
  const w = makeGm();
  const leaseUntil = Date.now() + 5000;
  w.store.set(pk, { blockNum: BLOCK, status: 'started', attempts: 1, leaseUntil, phase: 'forming_groups' });
  w.store.set('phase_task_queue', [{ type: 'grouping_watchdog', blockNum: BLOCK, executeAt: Date.now() - 1000 }]);
  await w.gm.alarm();
  const wd = queueOf(w.store).find(t => t.type === 'grouping_watchdog');
  ok('T5 リース有効中は乗っ取らず、失効後の再チェックを予約',
    w.calls.start === 0 && w.store.get(pk).status === 'started'
    && !!wd && wd.executeAt >= leaseUntil + 30000 - 5, JSON.stringify(queueOf(w.store)));
}

// ---- T6: 乗っ取り上限超 → park ----
{
  const w = makeGm();
  w.store.set(pk, { blockNum: BLOCK, status: 'started', attempts: 20, leaseUntil: Date.now() - 1000, phase: 'writing_to_d1' });
  const r = await w.gm.startGrouping(BLOCK);
  ok('T6 20回目の乗っ取りでpark（実行せず）',
    r.success === false && /parked/.test(r.error) && w.store.get(pk).status === 'parked' && w.calls.writeD1 === 0);
  const r2 = await w.gm.startGrouping(BLOCK);
  ok('T6b park後の再実行要求は拒絶', r2.success === false && /already parked/.test(r2.error));
  w.store.set('phase_task_queue', [{ type: 'grouping_watchdog', blockNum: BLOCK, executeAt: Date.now() - 1000 }]);
  const startsBefore = w.calls.start;
  await w.gm.alarm();
  ok('T6c park後のwatchdogは何もしない', w.calls.start === startsBefore && !queueOf(w.store).some(t => t.type === 'grouping_watchdog'));
}

// ---- T7: waiting到達後の途中死 → resume ----
{
  const w = makeGm({ rowsByStatus: { waiting: 3 } });
  // writeGroupsToD1 完了後に落ちた状態: D1 の3行と完了印は揃っている。
  w.store.set(`grouping_d1_complete_block${BLOCK}`, { totalGroups: 3 });
  w.store.set(pk, { blockNum: BLOCK, status: 'started', attempts: 1, leaseUntil: Date.now() - 1000, phase: 'initializing_chat_games' });
  const r = await w.gm.startGrouping(BLOCK);
  ok('T7 waiting死はresume（チャット初期化再送＋スケジュールのみ・グループ再作成なし）',
    r.success === true && r.resumed === true && r.totalGroups === 3
    && w.calls.init === 1 && w.calls.writeD1 === 0
    && w.store.get(pk).status === 'completed' && w.store.get(pk).resumed === true,
    JSON.stringify({ r, calls: w.calls }));
}

// ---- T8: chatting以降まで進行済み → 自己修復のみ ----
{
  const w = makeGm({ rowsByStatus: { chatting: 3 } });
  w.store.set(`grouping_d1_complete_block${BLOCK}`, { totalGroups: 3 });
  w.store.set(pk, { blockNum: BLOCK, status: 'started', attempts: 1, leaseUntil: Date.now() - 1000, phase: 'initializing_chat_games' });
  const r = await w.gm.startGrouping(BLOCK);
  ok('T8 chatting以降ならprogressをcompletedへ自己修復のみ（何も再実行しない）',
    r.success === true && r.alreadyProgressed === true && w.calls.init === 0 && w.calls.writeD1 === 0
    && w.store.get(pk).status === 'completed');
}

// ---- T9: schedulePhaseTransitionsの置き換え登録 ----
{
  const w = makeGm();
  const now = Date.now();
  w.store.set('phase_task_queue', [
    { type: 'phase_transition', blockNum: BLOCK, targetPhase: 'chatting', executeAt: now - 5000, phaseEndTime: 1 },
    { type: 'phase_transition', blockNum: BLOCK, targetPhase: 'submitting', executeAt: now - 4000, phaseEndTime: 2 },
    { type: 'phase_transition', blockNum: BLOCK, targetPhase: 'completed', executeAt: now - 3000, phaseEndTime: null },
    { type: 'phase_transition', blockNum: 6, targetPhase: 'chatting', executeAt: now + 9000, phaseEndTime: 3 },
  ]);
  const declared = { chattingStart: now + 1000, submittingStart: now + 2000, closeAt: now + 3000, completedAt: now + 4000 };
  await w.gm.schedulePhaseTransitions(BLOCK, { declared, graceSec: 0 });
  const q = queueOf(w.store);
  const mine = q.filter(t => t.type === 'phase_transition' && t.blockNum === BLOCK);
  ok('T9 同一ブロックのタスクは置き換え（3件のまま・新タイムライン・他ブロックは温存）',
    mine.length === 3 && mine.every(t => t.executeAt >= now + 1000)
    && q.some(t => t.blockNum === 6 && t.phaseEndTime === 3), JSON.stringify(q));
}

// ---- T10: 初回実行でD1に進行済み → 従来どおりfailed ----
{
  const w = makeGm({ rowsByStatus: { chatting: 2 } });
  const r = await w.gm.startGrouping(BLOCK);
  ok('T10 初回実行(attempts=1)でのD1進行済み検出は従来どおりfailed（安全弁維持）',
    r.success === false && /already has/.test(r.error) && w.store.get(pk).status === 'failed' && w.calls.init === 0);
}

// ---- T11: watchdogタスク自体の喪失 → A3マーカーresurrectionで復活 ----
{
  const w = makeGm();
  w.store.set(pk, { blockNum: BLOCK, status: 'started', attempts: 1, leaseUntil: Date.now() - 1000, phase: 'writing_to_d1' });
  // 「dequeue＋マーカーput直後にkill」後の状態: キューに無くマーカーだけ残る
  w.store.set('phase_task_active', { type: 'grouping_watchdog', blockNum: BLOCK, executeAt: Date.now() - 2000 });
  w.store.set('phase_task_queue', []);
  await w.gm.alarm();
  ok('T11 watchdog喪失もresurrection→自己復旧まで到達',
    w.calls.start === 1 && w.store.get(pk).status === 'completed' && !w.store.has('phase_task_active'),
    JSON.stringify({ start: w.calls.start, prog: w.store.get(pk)?.status }));
}

// ---- T12: 0名ブロックのno-game確定（B4） ----
{
  const w = makeGm({ players: [] });
  const r = await w.gm.startGrouping(BLOCK);
  const summary = w.r2Puts[`games/block${BLOCK}/summary.json`];
  ok('T12 0名ブロック: noGameサマリー公開＋標識root提出＋manifest公開で完了',
    r.success === true && r.noGame === true
    && summary?.noGame === true && summary?.totalPlayers === 0 && Array.isArray(summary?.groups) && summary.groups.length === 0
    && typeof summary?.blockReward === 'string' && BigInt(summary.blockReward) > 0n
    && w.calls.merkle === 1 && w.calls.manifest === 1,
    JSON.stringify({ r, summary, calls: w.calls }));
  ok('T12b progressはcompleted（failedにしない＝再実行不要・watchdogもno-op）',
    w.store.get(pk).status === 'completed' && w.store.get(pk).noGame === true
    && w.calls.writeD1 === 0 && w.calls.init === 0 && w.calls.auto === 0);
  // 再実行要求は completed として拒絶（冪等）
  const r2 = await w.gm.startGrouping(BLOCK);
  ok('T12c 再実行はalready completedで拒絶', r2.success === false && /already completed/.test(r2.error));
}

// ---- T13: Coordinator pendingだけをwatchdogで再開する ----
{
  const pending = makeGm({
    randaoAnchor: {
      required: true,
      anchored: false,
      pending: true,
      reason: 'receipt_pending',
      txHash: `0x${'ab'.repeat(32)}`,
    },
  });
  const pendingResult = await pending.gm.startGrouping(BLOCK);
  const pendingProgress = pending.store.get(pk);
  ok('T13 Coordinator pendingはresumableとしてintent情報をprogressに保持',
    pendingResult.success === false && pendingResult.resumable === true
    && pendingProgress.resumable === true
    && pendingProgress.randaoAnchor?.reason === 'receipt_pending'
    && pendingProgress.randaoAnchor?.txHash === `0x${'ab'.repeat(32)}`
    && queueOf(pending.store).some((task) => task.type === 'grouping_watchdog' && task.blockNum === BLOCK),
    JSON.stringify({ result: pendingResult, progress: pendingProgress, queue: queueOf(pending.store) }));

  const missingBinding = makeGm({
    randaoAnchor: { required: true, anchored: false, pending: false, reason: 'coordinator_binding_missing' },
  });
  const missingResult = await missingBinding.gm.startGrouping(BLOCK);
  ok('T13b Coordinator未接続を未実行のままresumable成功に数えない',
    missingResult.success === false && missingResult.resumable !== true
    && missingBinding.store.get(pk)?.status === 'failed',
    JSON.stringify({ result: missingResult, progress: missingBinding.store.get(pk) }));
}

console.log('');
if (failed > 0) { console.error(`❌ ${failed} FAILED (${passed} passed)`); process.exit(1); }
console.log(`✅ ALL PASSED (${passed} checks)`);

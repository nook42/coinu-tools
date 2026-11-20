// immediate-init-unit.mjs — v3.2 チャット初期化（早着ガード撤廃・宣言タイムライン配布）ユニットテスト
//
// 背景: v3.2 で TERM1（準備期間）を撤廃し、waiting はカウントダウン表示のみになった。
// 旧「早着待機ガード」（宣言 preparingStart まで init_chat_games タスクで待機）は撤去され、
// グループ分けが早く終わっても ChatGameDO は waiting フェーズで即初期化される。
// chatting への遷移は schedulePhaseTransitions の phase_transition タスクが
// 宣言 chattingStart（= entryEnd + grace）に発火させる＝開始は常に宣言時刻。
//
// 本物の GameMasterDO をスタブ state 上で駆動する:
//  T1: 早着 → 即init（deferredなし）・phaseEndTime=宣言chattingStart・periodDurations配布・
//      D1='waiting'・summary(status+timeline)・phase_transition 3件が宣言時刻に登録・roster索引公開
//  T2: 60秒トレランス内の開始遅れ → graceは延長されない（waitingが短くなるだけ）
//  T3: パイプライン遅刻（Evidence無効）→ ephemeralGrace でローカル延長し即init
//  T4: init失敗 → success:false・D1未更新・スケジュール未登録
//  T5: watchdog安全網 — グループ分けcompletedなのにinitタスク消失 → 再登録（二重登録なし）
//  T6: schedulePhaseTransitions の置き換え登録（同一ブロックのphase_transitionは重複しない）
//
// 実行: node block-verifier/test/immediate-init-unit.mjs （Node 22）

import { GameMasterDO } from './canonical.mjs';
import { makeState } from './stubs.mjs';

let passed = 0, failed = 0;
const ok = (name, cond, detail = '') => {
  if (cond) { passed++; console.log(`  ok: ${name}`); }
  else { failed++; console.error(`  FAIL: ${name}${detail ? ` — ${detail}` : ''}`); }
};
const norm = (sql) => sql.replace(/\s+/g, ' ').trim();

const BLOCK = 3;
const BLOCK_TIME = 600_000;
const GAME_PERIOD = 180_000;
const SUBMIT_PERIOD = 120_000;

// chattingIn: 宣言chattingStart が now から何ms先か（負=パイプライン遅刻）
function makeWorld({ chattingIn = 600_000, graceSec = 60, doFail = false } = {}) {
  const now = Date.now();
  // chattingStart = START_TIME + (BLOCK+1)*BLOCK_TIME + grace*1000 = now + chattingIn となるよう逆算
  const startTime = now + chattingIn - graceSec * 1000 - (BLOCK + 1) * BLOCK_TIME;

  const state = makeState();
  const alarms = [];
  state.storage.setAlarm = async (t) => { alarms.push(t); };

  const initBodies = [];
  const updates = [];
  const groupRows = [0, 1].map(i => ({
    group_id: i, lang: 'ja', mixed: 0,
    members: JSON.stringify([{ uid: `u${i}a` }, { uid: `u${i}b` }, { uid: `u${i}c` }]),
    status: 'formed',
  }));
  let formedCount = groupRows.length;

  const db = {
    prepare(sql) {
      const q = norm(sql);
      return { bind() {
        return {
          async all() {
            if (q.startsWith("SELECT group_id, lang, mixed, members FROM game_groups WHERE block_num = ? AND status = 'formed'")) {
              return { results: formedCount > 0 ? groupRows : [] };
            }
            if (q.startsWith('SELECT block_num, group_id, members FROM game_groups WHERE block_num = ?')) {
              return { results: groupRows.map(({ block_num, group_id, members }) => ({ block_num, group_id, members })) };
            }
            if (q.startsWith('SELECT group_id, members FROM game_groups WHERE block_num = ?')) {
              return { results: groupRows.map(({ group_id, members }) => ({ group_id, members })) };
            }
            if (q.startsWith('SELECT group_id FROM game_groups WHERE block_num = ?')) {
              return { results: groupRows.map(({ group_id }) => ({ group_id })) };
            }
            if (q.includes("status IN ('chatting','submitting','completed')")) {
              return { results: groupRows
                .filter(({ status }) => ['chatting', 'submitting', 'completed'].includes(status))
                .map(({ group_id, status }) => ({ group_id, status })) };
            }
            if (q.startsWith('SELECT group_id, status FROM game_groups WHERE block_num = ?')) {
              return { results: groupRows.map(({ group_id, status }) => ({ group_id, status })) };
            }
            throw new Error(`db stub: unhandled all(): ${q}`);
          },
          async run() {
            if (q.startsWith("UPDATE game_groups SET status = 'waiting'")) {
              updates.push(q);
              for (const row of groupRows) if (row.status === 'formed') row.status = 'waiting';
              formedCount = 0;
              return {};
            }
            throw new Error(`db stub: unhandled run(): ${q}`);
          },
          async first() {
            if (q.startsWith("SELECT COUNT(*) AS cnt FROM game_groups WHERE block_num = ? AND status = 'formed'")) {
              return { cnt: formedCount };
            }
            throw new Error(`db stub: unhandled first(): ${q}`);
          },
        };
      } };
    },
  };

  const r2 = {};
  const env = {
    // 書き込み競合対策（2026-07-31）で mergeBlockSummary は etag 条件付きの
    // mutateR2ObjectWithCAS を使うようになり、getR2Object/putR2Object ラッパーではなく
    // env.R2_BUCKET を直に叩く（listen-worker の claimed patch を潰さないため）。
    // 本番 API 面: get -> null | {etag, text()} / put(key, string, opts) -> null なら CAS 敗北
    R2_BUCKET: {
      async get(k) {
        if (r2[k] === undefined) return null;
        const text = JSON.stringify(r2[k]);
        return { etag: 'etag-stub', async text() { return text; }, async json() { return JSON.parse(text); } };
      },
      async put(k, v) { r2[k] = JSON.parse(v); return {}; },
    },
    RELEASE_TIME: '2099-01-01T00:00:00Z',
    START_TIME: String(startTime),
    BLOCK_TIME: String(BLOCK_TIME),
    GAME_PERIOD: String(GAME_PERIOD),
    SUBMIT_PERIOD: String(SUBMIT_PERIOD),
    RESULT_GRACE: String(graceSec),
    BITCOINU_DATA: db,
    CHAT_GAME_DO: {
      idFromName: (n) => n,
      get: (id) => ({
        fetch: async (req) => {
          if (doFail) throw new Error('DO down');
          const groupId = Number(String(id).split('-').at(-1));
          if (new URL(req.url).pathname === '/republish-roster') {
            return { ok: true, status: 200, json: async () => ({ rosterSha256: String(groupId).padStart(64, '0') }) };
          }
          initBodies.push({ id: String(id), body: JSON.parse(await req.text()) });
          return { ok: true, status: 200, json: async () => ({ rosterSha256: String(groupId).padStart(64, '0') }) };
        },
      }),
    },
  };

  const gm = new GameMasterDO(state, env);
  // この2組は書き込みを終えた組の fixture。実際の writeGroupsToD1 と同じ完了印を置く。
  state.storage._map.set(`grouping_d1_complete_block${BLOCK}`, { totalGroups: groupRows.length });
  gm.checkRosterAnchorForStart = async () => state.storage._map.has(`roster_anchor_block${BLOCK}`)
    ? { ready: true } : { ready: false, reason: 'roster_anchor_or_manifest_missing' };
  gm.getR2Object = async (k) => r2[k] ?? null;
  gm.putR2Object = async (k, v) => { r2[k] = v; return true; };
  // updateBlockSummaryStatus のマージ先（グループ分け時に書かれる summary を模擬）
  r2[`games/block${BLOCK}/summary.json`] = {
    blockNum: BLOCK,
    groups: groupRows.map(g => ({ group_id: g.group_id, status: 'formed' })),
  };

  return {
    gm, state, store: state.storage._map, alarms, initBodies, updates, r2, env,
    declaredChattingStart: now + chattingIn,
    declaredSubmittingStart: now + chattingIn + GAME_PERIOD,
    // completedAt = closeAt + confirmations(既定64)×12s + 30s（computeDeclaredTimesMs）
    declaredCompletedAt: now + chattingIn + GAME_PERIOD + SUBMIT_PERIOD + 64 * 12000 + 30000,
  };
}
const queueOf = (store) => store.get('phase_task_queue') || [];
const initTasks = (store) => queueOf(store).filter(t => t.type === 'init_chat_games');
const confirmRoster = async (world) => {
  await world.state.storage.put(`roster_anchor_block${BLOCK}`, { hash: 'confirmed-fixture' });
  return world.gm.scheduleChatWhenAllGroupsReady(BLOCK);
};

// ---- T1: 早着 → 即init（deferredなし）＋宣言タイムライン配布 ----
{
  const w = makeWorld({ chattingIn: 600_000 });
  const r = await w.gm.initChatGames(BLOCK);
  ok('T1 早着でも即init（deferredなし）', r?.success === true && !r?.deferred && r?.initialized === 2,
    JSON.stringify(r));
  ok('T1 待機タスクは登録されない', initTasks(w.store).length === 0);
  ok('T1 phaseEndTime=宣言chattingStart が全DOに配布される',
    w.initBodies.length === 2 && w.initBodies.every(b => Math.abs(b.body.phaseEndTime - w.declaredChattingStart) < 5000),
    JSON.stringify(w.initBodies.map(b => b.body.phaseEndTime)));
  ok('T1 periodDurations（gamePeriod/submitPeriod）が配布される',
    w.initBodies.every(b => b.body.periodDurations?.gamePeriod === GAME_PERIOD && b.body.periodDurations?.submitPeriod === SUBMIT_PERIOD));
  ok('T1 D1ステータスがwaitingへ更新される', w.updates.length === 1);
  ok('T1 登録確定前はphase taskを張らない', queueOf(w.store).filter(t => t.type === 'phase_transition').length === 0);
  await confirmRoster(w);
  const summary = w.r2[`games/block${BLOCK}/summary.json`];
  ok('T1 summaryステータスがwaitingへ', summary.groups.every(g => g.status === 'waiting'));
  ok('T1 summaryにtimelineが載る（chattingStart/submittingStart/closeAt）',
    !!summary.timeline && Math.abs(summary.timeline.chattingStart - w.declaredChattingStart) < 5000
    && typeof summary.timeline.submittingStart === 'number' && typeof summary.timeline.closeAt === 'number');
  ok('T1 timeline.graceSec が載る', summary.timeline?.graceSec === 60, `grace=${summary.timeline?.graceSec}`);
  const phases = queueOf(w.store).filter(t => t.type === 'phase_transition');
  const at = Object.fromEntries(phases.map(t => [t.targetPhase, t.executeAt]));
  ok('T1 phase_transition 3件が宣言時刻に登録される',
    phases.length === 3
    && Math.abs(at.chatting - w.declaredChattingStart) < 5000
    && Math.abs(at.submitting - w.declaredSubmittingStart) < 5000
    && Math.abs(at.completed - w.declaredCompletedAt) < 5000,
    JSON.stringify(at));
  ok('T1 roster索引がR2公開される', !!w.r2[`games/block${BLOCK}/roster/index.json`]);
  ok('T1 roster manifestは初回invocationで公開しない',
    w.r2[`games/block${BLOCK}/roster/manifest.json`] === undefined);
  // roster_anchor alarm の別invocationで呼ばれる再構築本体を駆動する。
  await w.gm.rebuildAndPublishRosterManifest(BLOCK);
  ok('T1 roster manifestが別invocationでgroupId昇順のminified内容でR2公開される', (() => {
    const manifest = w.r2[`games/block${BLOCK}/roster/manifest.json`];
    return manifest?.blockNum === BLOCK
      && manifest.groups?.map((group) => group.groupId).join(',') === '0,1'
      && manifest.groups.every((group) => /^[0-9]{64}$/.test(group.sha256));
  })());
  const queue = queueOf(w.store);
  // R32-A-1-04: 関門が roster_anchor task の外で ready を返したら、同じブロックの残りの
  // roster_anchor task は外す（残すと groups_not_all_waiting を未準備として積み直し続ける）。
  ok('T1 アンカー確定後はチャット遷移を登録し、同じブロックの残りの名簿再試行 task を外す',
    !queue.some((task) => task.type === 'roster_anchor' && Number(task.blockNum) === BLOCK)
    && phases.length === 3,
    JSON.stringify(queue.map((task) => task.type)));
  ok('T1 アラームがキューの最早タスクに設定される',
    w.alarms.length > 0 && Math.abs(w.alarms.at(-1) - queue[0].executeAt) < 5000);
}

// ---- T2: 1〜60秒の開始遅れ → grace を延長しない ----
{
  const w = makeWorld({ chattingIn: -30_000 }); // 宣言chattingStartの30秒後
  const r = await w.gm.initChatGames(BLOCK);
  await confirmRoster(w);
  const summary = w.r2[`games/block${BLOCK}/summary.json`];
  ok('T2 30秒遅れでも即init・60秒トレランス内はgraceを延長しない',
    r?.success === true && summary.timeline?.graceSec === 60,
    `grace=${summary.timeline?.graceSec}`);
  ok('T2 宣言chattingStartを維持する',
    Math.abs(summary.timeline?.chattingStart - w.declaredChattingStart) < 5000);
}

// ---- T3: パイプライン遅刻（Evidence無効）→ ephemeralGrace ローカル延長で即init ----
{
  const w = makeWorld({ chattingIn: -120_000 }); // 2分遅刻（>60秒トレランス）
  const r = await w.gm.initChatGames(BLOCK);
  await confirmRoster(w);
  const summary = w.r2[`games/block${BLOCK}/summary.json`];
  ok('T3 遅刻でも即init（待機なし）', r?.success === true && w.initBodies.length === 2);
  ok('T3 ローカル延長でgraceが増える（ephemeral）', summary.timeline?.graceSec > 60, `grace=${summary.timeline?.graceSec}`);
  ok('T3 延長後のchattingStartは現在以降', summary.timeline?.chattingStart >= Date.now() - 60_000);
}

// ---- T4: init失敗 → success:false・D1未更新 ----
{
  const w = makeWorld({ chattingIn: 600_000, doFail: true });
  const r = await w.gm.initChatGames(BLOCK);
  ok('T4 init失敗はsuccess:false（errors=2）', r?.success === false && r?.errors === 2, JSON.stringify(r));
  ok('T4 D1ステータスは未更新（formedのまま）', w.updates.length === 0);
  ok('T4 フェーズ遷移は未登録', queueOf(w.store).filter(t => t.type === 'phase_transition').length === 0);
}

// ---- T5: watchdog安全網 — completedなのにinitタスク消失 → 再登録 ----
{
  const w = makeWorld({ chattingIn: 600_000 });
  w.store.set(`grouping_block${BLOCK}_progress`, { blockNum: BLOCK, status: 'completed' });
  await w.gm.checkGroupingWatchdog(BLOCK);
  ok('T5 watchdogがinit_chat_gamesを再登録する', initTasks(w.store).length === 1);
  await w.gm.checkGroupingWatchdog(BLOCK);
  ok('T5 既存タスクがあれば二重登録しない', initTasks(w.store).length === 1);
}

// ---- T6: schedulePhaseTransitions の置き換え登録 ----
{
  const w = makeWorld({ chattingIn: 600_000 });
  await w.gm.initChatGames(BLOCK);
  await confirmRoster(w);
  const before = queueOf(w.store).filter(t => t.type === 'phase_transition').length;
  await w.gm.schedulePhaseTransitions(BLOCK);
  const after = queueOf(w.store).filter(t => t.type === 'phase_transition').length;
  ok('T6 再スケジュールは置き換え（二重登録なし）', before === 3 && after === 3, `before=${before} after=${after}`);
}

console.log(failed === 0 ? `\n✅ ALL PASSED (${passed} checks)` : `\n❌ ${failed} FAILED / ${passed} passed`);
process.exit(failed === 0 ? 0 : 1);

// a3-phase-task-unit.mjs — A3是正（alarm phase_transition タスクの恒久消失対策）ユニットテスト
//
// 背景（②監査 A3）: alarmのタスクは「実行前dequeue」なので、dequeue直後のruntime kill・
// advancePhase内のthrowでタスクが恒久消失していた。さらにthrowはalarmループ全体を中断し、
// final setAlarmも実行されないためキューが外部リクエストまで停止していた。
// 是正: dequeueと同一putで実行中マーカー(phase_task_active)を書き、alarm冒頭のresurrection
// チェックで復活（calc_chunkのcalc_active:{N}と同思想）。throwはタスク内でcatchして
// バックオフ再enqueue（attempts上限20でpark）。外側catchにもsetAlarm安全網。
//
// 本テストは本物の GameMasterDO.alarm() をスタブstate上で駆動する（advancePhaseのみ
// インスタンス上で差し替え、成功/失敗を制御）:
//  T1: 正常系 — 実行後にマーカーが残らない・キュー前進
//  T2: advancePhase throw — バックオフ付き再enqueue（attempts=1）→ 復旧後に同引数で完遂
//  T3: dequeue直後kill（マーカー有り・キュー無し）→ resurrectionで復活・実行
//  T4: 再enqueue後・マーカー削除前にkill → 二重実行しない（マーカーのみ破棄）
//  T5: attempts上限超 → park（phase_task_parked:{N}:{phase}・再enqueueなし）
//  T6: 1タスクのthrowが後続タスク実行とfinal setAlarmを阻害しない（旧実装の恒久停止の是正）
//  T7: alarmループ外の予期しないthrow → 安全網setAlarm(+30s)
//  T8: calc_chunkタスクはphase_task_activeマーカーの対象外（calc_activeで別途復旧）
//
// 実行: node block-verifier/test/a3-phase-task-unit.mjs （Node 22）

import { GameMasterDO } from './canonical.mjs';
import { makeState } from './stubs.mjs';

let passed = 0, failed = 0;
const ok = (name, cond, detail = '') => {
  if (cond) { passed++; console.log(`  ok: ${name}`); }
  else { failed++; console.error(`  FAIL: ${name}${detail ? ` — ${detail}` : ''}`); }
};

const BLOCK = 7;
const task = (targetPhase, over = {}) => ({
  type: 'phase_transition', blockNum: BLOCK, targetPhase,
  executeAt: Date.now() - 1000, phaseEndTime: 12345, ...over,
});

// 本物のGameMasterDO＋スタブstate。advancePhaseを差し替えて成功/失敗を制御し、
// 呼び出し（引数）とsetAlarmを記録する。
function makeGm({ advanceImpl } = {}) {
  const state = makeState();
  const alarms = [];
  state.storage.setAlarm = async (t) => { alarms.push(t); };
  const env = { RELEASE_TIME: '2099-01-01T00:00:00Z' }; // EVIDENCE無し=autoExtend経路はスキップ
  const gm = new GameMasterDO(state, env);
  const advCalls = [];
  gm.advancePhase = async (blockNum, targetPhase, phaseEndTime) => {
    advCalls.push({ blockNum, targetPhase, phaseEndTime });
    if (advanceImpl) return advanceImpl({ blockNum, targetPhase, phaseEndTime }, advCalls.length);
    return { success: true };
  };
  return { gm, state, alarms, advCalls, store: state.storage._map };
}
const q = (store) => store.get('phase_task_queue') || [];

// ---- T1: 正常系 ----
{
  const { gm, advCalls, store } = makeGm();
  await gm.storage.put('phase_task_queue', [task('chatting')]);
  await gm.alarm();
  ok('T1 正常実行（引数=blockNum/targetPhase/phaseEndTime）',
    advCalls.length === 1 && advCalls[0].blockNum === BLOCK && advCalls[0].targetPhase === 'chatting' && advCalls[0].phaseEndTime === 12345);
  ok('T1b 実行後: キュー空・実行中マーカーなし', q(store).length === 0 && !store.has('phase_task_active'));
}

// ---- T2: advancePhase throw → バックオフ再enqueue → 復旧後に完遂 ----
{
  let fail = true;
  const { gm, advCalls, store, alarms } = makeGm({ advanceImpl: () => { if (fail) throw new Error('boom'); return { success: true }; } });
  await gm.storage.put('phase_task_queue', [task('chatting')]);
  await gm.alarm();
  const retry = q(store)[0];
  ok('T2 throwで再enqueue（attempts=1・約90秒バックオフ）',
    q(store).length === 1 && retry.attempts === 1 && retry.executeAt > Date.now() + 60000 && retry.targetPhase === 'chatting',
    JSON.stringify(q(store)));
  ok('T2b マーカーは下ろされ・final setAlarmが仕掛かる', !store.has('phase_task_active') && alarms.length > 0);

  // 復旧: executeAtを過去に巻き戻して次のalarm → 同引数で完遂
  fail = false;
  await gm.storage.put('phase_task_queue', [{ ...retry, executeAt: Date.now() - 1000 }]);
  await gm.alarm();
  ok('T2c 復旧後に同引数で完遂・キュー空', advCalls.length === 2 && advCalls[1].phaseEndTime === 12345 && q(store).length === 0 && !store.has('phase_task_active'));
}

// ---- T3: dequeue直後kill → resurrection ----
{
  const { gm, advCalls, store } = makeGm();
  // 「dequeue＋マーカーputの直後にkill」後の状態を再現: キューに無くマーカーだけ残る
  await gm.storage.put('phase_task_active', task('submitting'));
  await gm.storage.put('phase_task_queue', []);
  await gm.alarm();
  ok('T3 resurrectionで復活し実行される', advCalls.length === 1 && advCalls[0].targetPhase === 'submitting');
  ok('T3b 実行後: キュー空・マーカーなし', q(store).length === 0 && !store.has('phase_task_active'));
}

// ---- T4: 再enqueue後・マーカー削除前にkill → 二重実行しない ----
{
  const { gm, advCalls, store } = makeGm();
  const t = task('chatting', { attempts: 1 });
  await gm.storage.put('phase_task_active', t);
  await gm.storage.put('phase_task_queue', [t]); // 既にキューに同一タスクが居る
  await gm.alarm();
  ok('T4 マーカーのみ破棄・キューのタスクを1回だけ実行', advCalls.length === 1 && q(store).length === 0 && !store.has('phase_task_active'));
}

// ---- T5: attempts上限超 → park ----
{
  // T5a: kill喪失の繰り返し（resurrection経路でattempts超過）
  const { gm, advCalls, store } = makeGm();
  await gm.storage.put('phase_task_active', task('chatting', { attempts: 20 }));
  await gm.storage.put('phase_task_queue', []);
  await gm.alarm();
  const parked = store.get(`phase_task_parked:${BLOCK}:chatting`);
  ok('T5a kill喪失20回超でpark（再enqueue・実行なし）',
    advCalls.length === 0 && q(store).length === 0 && !store.has('phase_task_active') && parked?.attempts === 21);

  // T5b: throw失敗の繰り返し（実行経路でattempts超過）
  const w2 = makeGm({ advanceImpl: () => { throw new Error('always'); } });
  await w2.gm.storage.put('phase_task_queue', [task('submitting', { attempts: 20 })]);
  await w2.gm.alarm();
  const parked2 = w2.store.get(`phase_task_parked:${BLOCK}:submitting`);
  ok('T5b throw失敗20回超でpark（lastError記録・再enqueueなし）',
    q(w2.store).length === 0 && !w2.store.has('phase_task_active') && parked2?.attempts === 21 && parked2?.lastError === 'always');
}

// ---- T6: 1タスクのthrowが後続実行とfinal setAlarmを阻害しない ----
{
  const { gm, advCalls, store, alarms } = makeGm({
    advanceImpl: ({ blockNum }) => { if (blockNum === 1) throw new Error('b1 down'); return { success: true }; },
  });
  await gm.storage.put('phase_task_queue', [
    { type: 'phase_transition', blockNum: 1, targetPhase: 'chatting', executeAt: Date.now() - 2000, phaseEndTime: 1 },
    { type: 'phase_transition', blockNum: 2, targetPhase: 'chatting', executeAt: Date.now() - 1000, phaseEndTime: 2 },
  ]);
  await gm.alarm();
  ok('T6 block1失敗でもblock2は同一alarm内で実行される',
    advCalls.some(c => c.blockNum === 2) && q(store).length === 1 && q(store)[0].blockNum === 1 && q(store)[0].attempts === 1,
    JSON.stringify({ advCalls, q: q(store) }));
  ok('T6b 残タスクへfinal setAlarmが仕掛かる（旧実装はthrowで恒久停止）', alarms.length > 0 && !store.has('phase_task_active'));
}

// ---- T7: alarmループ外の予期しないthrow → 安全網setAlarm ----
{
  const { gm, state, alarms } = makeGm();
  const origGet = state.storage.get.bind(state.storage);
  state.storage.get = async (key) => {
    if (key === 'phase_task_queue') throw new Error('storage glitch');
    return origGet(key);
  };
  const before = Date.now();
  await gm.alarm();
  ok('T7 予期しないthrowでも安全網setAlarm(+30s)が仕掛かる',
    alarms.length === 1 && alarms[0] >= before + 29000 && alarms[0] <= Date.now() + 31000, JSON.stringify(alarms));
}

// ---- T8: calc_chunkはphase_task_activeマーカー対象外 ----
{
  const { gm, store } = makeGm();
  const markerPuts = [];
  const origPut = gm.storage.put.bind(gm.storage);
  gm.storage.put = async (key, value) => {
    if (key === 'phase_task_active' || (typeof key === 'object' && key !== null && 'phase_task_active' in key)) markerPuts.push(key);
    return origPut(key, value);
  };
  gm.calculateAndStoreResults = async () => ({ success: true });
  await gm.storage.put('phase_task_queue', [{ type: 'calc_chunk', blockNum: BLOCK, executeAt: Date.now() - 1000 }]);
  await gm.alarm();
  ok('T8 calc_chunk実行でphase_task_activeマーカーは書かれない（calc_activeで別途復旧）',
    markerPuts.length === 0 && q(store).length === 0);
}

console.log('');
if (failed > 0) { console.error(`❌ ${failed} FAILED (${passed} passed)`); process.exit(1); }
console.log(`✅ ALL PASSED (${passed} checks)`);

// r2-evidence-ingest-unit.mjs — R2是正（evidenceイベント取得のメモリOOM）ユニットテスト
//
// 背景（総点検R2）: calcEvidenceUnitは検証を400件/回にチャンク化していたが、取得
// （fetchResultEvents）がユニット毎に全量一括で、dataは最大約260KB/件のhex文字列
// → 2100件（検閲シナリオ）や第三者の大量無効投稿で数百MB＝128MB上限でOOM。
// 是正: getLogsをチャンク幅で歩き（progress.evidenceIngestカーソル）、取得分を即
// D1へ永続してメモリから破棄。完全性は全走査の完了後にprogress.seenでseq 1..resultCountの
// 被覆を判定する。
// 🔴 S3C5（D-06・2026-09-27）: 判定は取り込みの段でその場で行い、D1 には要約と判定だけを置く
// （中身は各 uid の採用候補だけ）。旧「D1 から件数＋data文字数の両上限で刻んで読む検証段」は無くなり、
// 同じ1ユニットの上限（件数・文字数）は取り込みの読み取りの刻みで守る（U2）。
//
// 本物の calcEvidenceUnit をスタブchainクライアント＋stubs.mjs D1で駆動して検証する:
//  U1: チャンク歩行 — 成功範囲ごとに進捗保存して複数ユニットに分割・全getLogs範囲が重複なく被覆・
//      即D1永続（その場で判定・無効は中身なし）・resume（続きから）・採用まで到達
//  U2: 判定のバイト上限 — 契約上限サイズ64件は旧検証段と同じ1ユニット12M字以内に刻まれる
//  U3: 完全性→範囲拡張 — 概算範囲外（過去側）のイベントをwiden再歩行で発見し完走
//  U4: 採用のseq範囲フィルタ（H2同値）— 範囲外の残存行は不採用・範囲内の残存行はチェーンで上書きし判定し直す
//
// 実行: node block-verifier/test/r2-evidence-ingest-unit.mjs （Node 22）

import { keccak256 } from 'viem';
import { GameMasterDO, REPO_ROOT } from './canonical.mjs';
import { makeState, makeD1Stub } from './stubs.mjs';
import { getLogsChunkedAdaptive } from '../src/chain.js';
import { access, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { join, sep } from 'node:path';
import {
  EVIDENCE_EVENTS_PER_UNIT,
  createEvidenceSpool,
  scanEvidenceEventsInUnits,
  retainAdoptedEvidenceUnit,
} from '../src/stages/results.js';

let passed = 0, failed = 0;
const realLog = console.log.bind(console), realWarn = console.warn.bind(console), realErr = console.error.bind(console);
const ok = (name, cond, detail = '') => {
  if (cond) { passed++; realLog(`  ok: ${name}`); }
  else { failed++; realErr(`  FAIL: ${name}${detail ? ` — ${detail}` : ''}`); }
};

const BLOCK = 7;
const CONTRACT = '0x' + 'e'.repeat(40);
const HASH_STORAGE = '0x' + '2'.repeat(40);
const ROSTER_HASH = '0x' + '3'.repeat(64);
const LATEST = 100000n;
const LATEST_TS = 2000000;

// スタブchainクライアント: 窓時刻からestimateBlockRangeの範囲を制御し、getLogs呼び出しを記録
function makeChainStub({ openAt, closeAt, resultCount, logs, maxRange = Infinity, onReturn = null }) {
  const getLogsCalls = [];
  return {
    getLogsCalls,
    async getBlock(opts = {}) {
      return { number: LATEST, timestamp: BigInt(LATEST_TS) };
    },
    async readContract({ functionName }) {
      if (functionName === 'resultWindow') return [BigInt(openAt), BigInt(closeAt)];
      if (functionName === 'chatWindow') return [BigInt(openAt), BigInt(closeAt)];
      if (functionName === 'currentGrace') return 100n;
      if (functionName === 'otherRegistrationCount') return 1n;
      if (functionName === 'otherRegistrationAt') return [ROSTER_HASH, 1n, BigInt(openAt + 1)];
      if (functionName === 'resultCount') return BigInt(resultCount);
      throw new Error(`readContract stub: ${functionName}`);
    },
    async getLogs({ fromBlock, toBlock, args = {} }) {
      getLogsCalls.push([fromBlock, toBlock]);
      if (Number(toBlock - fromBlock + 1n) > maxRange) {
        const error = new Error('query returned more than 10000 results');
        error.code = -32602;
        throw error;
      }
      // 周20 T2: 正典は indexed seq の topic OR で絞る（RESULT_LOG_SEQS_PER_READ 件ずつ）。
      // 本物の RPC は topic フィルタを適用するので、stub も同じく seq で絞る。
      const wantSeqs = Array.isArray(args.seq) ? args.seq.map((s) => BigInt(s)) : null;
      const found = logs.filter((l) => l.blockNumber >= fromBlock && l.blockNumber <= toBlock
        && (wantSeqs === null || wantSeqs.some((s) => s === l.args.seq)));
      onReturn?.(found);
      return found;
    },
  };
}

const mkLog = (seq, evtBlock, data = '0xdeadbeef') => ({
  args: { blockNum: BigInt(BLOCK), seq: BigInt(seq), sender: '0x' + 'a'.repeat(40), data, timestamp: BigInt(LATEST_TS - 100) },
  transactionHash: '0x' + String(seq).padStart(64, '0'),
  blockNumber: BigInt(evtBlock),
});

function makeGm(chain, envOverrides = {}) {
  const state = makeState();
  const db = makeD1Stub();
  const gm = new GameMasterDO(state, {
    RELEASE_TIME: '2099-01-01T00:00:00Z',
    EVIDENCE_CONTRACT_ADDRESS: CONTRACT,
    HASH_STORAGE_CONTRACT_ADDRESS: HASH_STORAGE,
    ETHEREUM_MAINNET_RPC_URL: 'http://stub',
    CONFIRMATION_BLOCKS: '0',
    BITCOINU_DATA: db,
    // 🔴 J-34（2026-08-09）: 集計は `entries/block{N}/game_groups.json`（権威）を起点に回すので、
    //    テストダブルにも権威ファイルが要る（D1 と食い違いのない正直な1グループ）。
    R2_BUCKET: {
      async get(key) {
        if (key !== `entries/block${BLOCK}/game_groups.json`) return null;
        const body = JSON.stringify({
          blockNum: BLOCK, totalPlayers: 1, totalGroups: 1,
          groups: [{ groupId: 0, lang: 'ja', mixed: false, memberCount: 1, memberIds: ['21000000'] }],
        });
        return { text: async () => body };
      },
      async put() { return {}; },
    },
    ...envOverrides,
  });
  gm.createReadOnlyClient = () => chain;
  // 検証段のcalcLoadGroups用に最小のグループ行をseed（membersIndex は1人で足りる＝decode失敗系）
  // ⚠️ J-34 以降、`members: '[]'` は「グループ分けデータの破損」として弾かれる（正典側の既存規則）。
  db.__store.gameGroups.push({
    block_num: BLOCK, group_id: 0, lang: 'ja', mixed: 0,
    members: JSON.stringify([{ uid: '21000000', addr: '0x' + '1'.repeat(40), bAddr: null, depIds: null }]),
    status: 'completed',
  });
  return { gm, db, store: db.__store, storage: state.storage };
}

// evidenceステージを完走まで駆動（安全上限つき）。ユニット毎のスナップショットを返す。
async function driveEvidence(gm, maxUnits = 40) {
  let progress = { stage: 'evidence', cursor: 0 };
  const snapshots = [];
  console.log = () => {}; console.warn = () => {}; console.error = () => {};
  try {
    for (let i = 0; i < maxUnits; i++) {
      progress = await gm.calcEvidenceUnit(BLOCK, progress);
      snapshots.push({ stage: progress.stage, ingestDone: progress.evidenceIngest?.done ?? null, cursor: progress.cursor });
      if (progress.stage !== 'evidence') return { progress, snapshots };
    }
    throw new Error('driveEvidence: did not finish');
  } finally {
    console.log = realLog; console.warn = realWarn; console.error = realErr;
  }
}

// ============================================================
// U1: チャンク歩行（約50,000ブロック≒26成功範囲）＋即永続＋採用到達
// ============================================================
{
  // latestTs - openAt = 600,000秒 ≒ 50,000 ethブロック
  const logs = [1, 2, 3, 4, 5].map(seq => mkLog(seq, 100000 - seq * 7000));
  const chain = makeChainStub({ openAt: LATEST_TS - 600000, closeAt: LATEST_TS - 60, resultCount: 5, logs });
  const { gm, store, storage } = makeGm(chain);

  const { progress, snapshots } = await driveEvidence(gm);

  ok('U1 複数ユニットに分割（成功範囲ごとに進捗保存）', snapshots.length >= 25, JSON.stringify(snapshots));
  ok('U1b ユニット1はingest未完で返る', snapshots[0].stage === 'evidence' && snapshots[0].ingestDone === false);

  // getLogs範囲の被覆: 重複なし・ギャップなし・各チャンク≦2000ブロック
  const calls = chain.getLogsCalls.map(([f, t]) => [Number(f), Number(t)]).sort((a, b) => a[0] - b[0]);
  let coverageOk = true;
  for (let i = 0; i < calls.length; i++) {
    if (calls[i][1] - calls[i][0] + 1 > 2000) coverageOk = false;
    if (i > 0 && calls[i][0] !== calls[i - 1][1] + 1) coverageOk = false;
  }
  ok(`U1c getLogsは2000ブロック幅で連続被覆（${calls.length}回）`, coverageOk && calls.length >= 25, JSON.stringify(calls.slice(0, 3)));

  ok('U1d 5イベント全てD1永続・全て検証済み（decode失敗=invalid）',
    store.evidenceEvents.size === 5 &&
    [...store.evidenceEvents.values()].every(r => r.valid === 0 && r.invalid_reason),
    JSON.stringify([...store.evidenceEvents.values()].map(r => ({ seq: r.seq, valid: r.valid }))));
  // S3C5（D-06）: 無効な提出の中身は D1 に残さず、要約（バイト長・keccak256）だけを置く
  ok('U1d2 無効な提出は中身なし・要約（data_len=4・data_keccak=keccak256(data)）だけ',
    [...store.evidenceEvents.values()].every(r => r.data === '' && r.data_len === 4
      && r.data_keccak === keccak256('0xdeadbeef')),
    JSON.stringify([...store.evidenceEvents.values()].map(r => ({ seq: r.seq, data: r.data, len: r.data_len, k: r.data_keccak }))));

  const marker = await storage.get(`calc:${BLOCK}:adopted`);
  ok('U1e 採用確定（adopted 0件・invalid 5件）＋depids遷移＋ingestカーソル掃除',
    progress.stage === 'depids' && marker?.adoptedCount === 0 && marker?.invalidCount === 5 &&
    progress.evidenceIngest === undefined, JSON.stringify(marker));
}

// ============================================================
// U2: 判定のバイト上限（S3C5）— 契約上限サイズ64件は1ユニット12M字以内に刻まれる
// ============================================================
// 旧実装は取り込み後の検証段が D1 から「件数400・data 12,000,000字」までを1ユニットで読んだ。
// S3C5 で判定を取り込みへ移したので、同じ上限を取り込みの刻みで守る: 次の1応答（8件 ×
// 契約 MAX_DATA_BYTES=130,000 の hex 260,002字）を足して 12,000,000字を超えるなら読む前に返す。
// 64件（1ブロック＝1物理範囲）なら 5応答=40件（10,400,080字）→ 残り24件 の2ユニットになる。
// 旧実装では取り込み中に cursor は増えず、検証段が 46件（11,960,092字）→18件 で刻んでいた。
{
  const MAX_HEX = 2 + 2 * 130000; // Evidence.sol MAX_DATA_BYTES の hex 字数
  const maxData = '0x' + 'ab'.repeat(130000);
  const logs = Array.from({ length: 64 }, (_, i) => mkLog(i + 1, 99000, maxData));
  const chain = makeChainStub({ openAt: LATEST_TS - 120000, closeAt: LATEST_TS - 60, resultCount: 64, logs });
  const { gm, store } = makeGm(chain);

  const { snapshots } = await driveEvidence(gm);
  const increments = [];
  let prev = 0;
  for (const s of snapshots) { if (s.cursor > prev) { increments.push(s.cursor - prev); prev = s.cursor; } }
  ok('U2 契約上限サイズ64件は取り込みで判定され、1ユニット≦12,000,000字に刻まれる（増分=[40,24]）',
    JSON.stringify(increments) === '[40,24]' && Math.max(...increments) * MAX_HEX <= 12000000
      && snapshots.at(-1).stage === 'depids',
    JSON.stringify({ increments, last: snapshots.at(-1) }));
  ok('U2b 64件とも判定済み・無効な提出は中身なし（data_len=130000）',
    store.evidenceEvents.size === 64
      && [...store.evidenceEvents.values()].every(r => r.valid === 0 && r.data === '' && r.data_len === 130000));
}

// ============================================================
// U3: 完全性→widen再歩行（概算範囲より過去のイベントを発見）
// ============================================================
{
  // 概算範囲はおよそ [latest-12000, latest]。seq1をその手前（latest-30000）に置く。
  // 拡張後は低いseqだけでなく元範囲も再歩行し、時系列順のseq2/3を取りこぼさない。
  const logs = [mkLog(1, 70000), mkLog(2, 99500), mkLog(3, 99600)];
  const chain = makeChainStub({ openAt: LATEST_TS - 120000, closeAt: LATEST_TS - 60, resultCount: 3, logs });
  const { gm, store, storage } = makeGm(chain);

  const { progress } = await driveEvidence(gm, 80);
  ok('U3 widen再歩行で範囲外イベントを発見し完走',
    progress.stage === 'depids' && store.evidenceEvents.size === 3,
    `size=${store.evidenceEvents.size} stage=${progress.stage}`);
  const marker = await storage.get(`calc:${BLOCK}:adopted`);
  ok('U3b invalid 3件で採用確定', marker?.invalidCount === 3, JSON.stringify(marker));
}

// ============================================================
// U4: 採用のseq範囲フィルタ（H2同値）＋範囲内の残存行はチェーンで上書きして判定し直す
// ============================================================
{
  const logs = [mkLog(1, 99500), mkLog(2, 99600)];
  const chain = makeChainStub({ openAt: LATEST_TS - 120000, closeAt: LATEST_TS - 60, resultCount: 2, logs });
  const { gm, store, storage } = makeGm(chain);

  // 残存行: seq=99（範囲外・valid=1）は不採用対象。seq=1（範囲内・valid=1・uid='111'）は
  // tx_hash が現行イベントと同じでも**キャッシュとして再利用しない**。
  // 🔴 P-2026-0813 以降の正典は常にチェーンの値で上書きし、S3C5（D-06）以降はその場で判定し直す。
  //    旧スタブは同一 tx_hash の行を温存していたため、この項は「キャッシュ再利用で採用」を
  //    正典と食い違ったまま固定していた（S3C5 でスタブを正典の SQL どおりに直した）。
  store.evidenceEvents.set(99, { kind: 'result', block_num: BLOCK, seq: 99, sender: '0x1', data: '0x00', tx_hash: '0xstale', evt_block: 1, evt_timestamp: 1, valid: 1, invalid_reason: null, uid: '999', group_id: 0, ingested_at: 1 });
  store.evidenceEvents.set(1, { kind: 'result', block_num: BLOCK, seq: 1, sender: '0x1', data: '0xcached', tx_hash: '0x' + '1'.padStart(64, '0'), evt_block: 99500, evt_timestamp: 1, valid: 1, invalid_reason: null, uid: '111', group_id: 0, ingested_at: 1 });

  const { progress } = await driveEvidence(gm);
  const rec = await gm.calcLoadAdopted(BLOCK, { withInvalid: true });
  ok('U4 範囲外の残存行（seq=99）は不採用', !rec.adopted.some(a => a.seq === 99) && !rec.invalid.some(x => x.seq === 99),
    JSON.stringify(rec.adopted));
  const seq1 = store.evidenceEvents.get(1);
  ok('U4b 範囲内の残存行（seq=1）はチェーンの値で上書きされ、その場で判定し直される（キャッシュ再利用しない）',
    rec.adopted.length === 0 && seq1.valid === 0 && seq1.invalid_reason === 'unsupported_format'
      && seq1.uid === null && seq1.data === '' && seq1.data_keccak === keccak256('0xdeadbeef'),
    JSON.stringify({ adopted: rec.adopted, seq1 }));
  ok('U4c seq=1・2はinvalidに分類', rec.invalid.length === 2 && rec.invalid[0].seq === 1 && rec.invalid[1].seq === 2,
    JSON.stringify(rec.invalid));
  ok('U4d depids遷移', progress.stage === 'depids');
}

// ============================================================
// U5: R12-06 B-M1/B-M2 — 128MiB超を既存alarmキューで分割取り込み
// ============================================================
{
  // 1イベント129,999 bytes × 1,088件 = 141,438,912 bytes（128MiB超）。
  // 同じ文字列参照を使うのはテストプロセス自体のOOMを避けるためで、getLogsが返す各葉の
  // 論理payload量と全量は実寸で計測する。本番ではRPC JSONが同じサイズの別文字列を返す。
  const data = '0x' + 'ab'.repeat(129999);
  const blocks = 17;
  const perBlock = 64;
  const count = blocks * perBlock;
  const logs = [];
  // block 1/2 の seq 64/65 境界は維持し、block 2/3 は63件/65件にずらす。
  // これにより8件窓の一部だけが現在blockにある境界でも次seqを引き継げることを踏む。
  const eventsPerBlock = [perBlock, perBlock - 1, perBlock + 1,
    ...Array.from({ length: blocks - 3 }, () => perBlock)];
  let seq = 1;
  for (let b = 1; b <= blocks; b++) {
    for (let i = 0; i < eventsPerBlock[b - 1]; i++) logs.push(mkLog(seq++, b, data));
  }
  let peakResponseBytes = 0;
  const chain = makeChainStub({
    openAt: LATEST_TS - 120000,
    closeAt: LATEST_TS - 60,
    resultCount: count,
    logs,
    maxRange: 1,
    onReturn(found) {
      const bytes = found.reduce((sum, item) => sum + ((item.args.data.length - 2) / 2), 0);
      peakResponseBytes = Math.max(peakResponseBytes, bytes);
    },
  });
  const { gm, store, storage } = makeGm(chain, { GAME_CALC_UNITS_PER_DRIVE: '1' });
  await storage.put(gm.calcProgressKey(BLOCK), {
    blockNum: BLOCK,
    stage: 'evidence',
    cursor: 0,
    startedAt: Date.now(),
    failures: 0,
    evidenceIngest: {
      segs: [['1', String(blocks)]], segIdx: 0, next: '1', widened: false, done: false, seen: [],
    },
  });
  await storage.put(`calc_active:${BLOCK}`, { blockNum: BLOCK, at: Date.now() });
  await storage.put('phase_task_queue', [{ type: 'calc_chunk', blockNum: BLOCK, executeAt: 0 }]);

  let alarmCount = 0;
  let progress = null;
  let lastSeen = [];
  console.log = () => {}; console.warn = () => {}; console.error = () => {};
  try {
    for (; alarmCount < 100; alarmCount++) {
      const queue = await storage.get('phase_task_queue') || [];
      for (const task of queue) task.executeAt = 0;
      await storage.put('phase_task_queue', queue);
      await gm.alarm();
      progress = await storage.get(gm.calcProgressKey(BLOCK));
      if (Array.isArray(progress?.evidenceIngest?.seen)) lastSeen = progress.evidenceIngest.seen;
      // T4: 取り込みの後に seq ページの最終集計が複数ユニット続く。
      if (progress?.stage !== 'evidence') { alarmCount++; break; }
    }
  } finally {
    console.log = realLog; console.warn = realWarn; console.error = realErr;
  }

  const logicalBytes = count * ((data.length - 2) / 2);
  const reconciled = await storage.get(`evidence_reconciled_block${BLOCK}`);
  // 完了直前のユニットまでの観測集合（完了ユニットで歩行カーソルは消える）は最後の1応答ぶん欠けうるので、
  // 被覆の確定は完了時の記録（evidence_reconciled_block{N}.resultCount＝完全性を通った件数）で見る。
  const covered = gm.calcSeqSeenCovered(lastSeen, count);
  realLog(`  measurement B-M1/B-M2: logicalBytes=${logicalBytes} alarms=${alarmCount} `
    + `getLogsCalls=${chain.getLogsCalls.length} peakResponseBytes=${peakResponseBytes} covered(before last unit)=${covered.covered}/${count}`);
  ok('U5 B-M1 128MiB超の取り込みが既存calc_chunk alarmをまたいで完走',
    logicalBytes > 128 * 1024 * 1024 && alarmCount > 1 && progress?.stage === 'depids'
      && store.evidenceEvents.size === count,
    JSON.stringify({ logicalBytes, alarmCount, rows: store.evidenceEvents.size, stage: progress?.stage }));
  ok('U5b B-M2 alarm境界（seq64/65ほか）を欠番と誤判定せず、全走査後に1..countを被覆',
    reconciled?.resultCount === count && progress?.failures === 0
      && [...store.evidenceEvents.keys()].sort((a, b) => a - b).every((seqNo, i) => seqNo === i + 1),
    JSON.stringify({ reconciled, covered, failures: progress?.failures }));
  ok('U5b2 S3C5: 無効な提出1,088件の中身は D1 に残らない（要約だけ）',
    [...store.evidenceEvents.values()].every((r) => r.data === '' && r.data_len === 129999));
  ok('U5c 1回の成功応答は全量を保持せず8 seqぶんに限定',
    peakResponseBytes === 8 * ((data.length - 2) / 2) && peakResponseBytes < 128 * 1024 * 1024,
    `peak=${peakResponseBytes}`);
}

// D1保存が一時失敗しても、成功応答の範囲を先に完了扱いせず同じ葉から再開する。
{
  const chain = makeChainStub({
    openAt: LATEST_TS - 120000,
    closeAt: LATEST_TS - 60,
    resultCount: 1,
    logs: [mkLog(1, 1)],
  });
  const { gm, db, store } = makeGm(chain);
  const progress = {
    blockNum: BLOCK, stage: 'evidence', cursor: 0, failures: 0,
    evidenceIngest: {
      segs: [['1', '1']], segIdx: 0, next: '1', widened: false, done: false, seen: [],
    },
  };
  const realBatch = db.batch.bind(db);
  let failOnce = true;
  db.batch = async (statements) => {
    if (failOnce) { failOnce = false; throw new Error('temporary D1 write failure'); }
    return realBatch(statements);
  };

  let firstError = null;
  console.log = () => {}; console.warn = () => {}; console.error = () => {};
  try {
    await gm.calcEvidenceUnit(BLOCK, progress);
  } catch (error) {
    firstError = error;
  } finally {
    console.log = realLog; console.warn = realWarn; console.error = realErr;
  }
  ok('U5d D1一時障害では処理中の1ブロック範囲をpendingに保持',
    firstError?.message === 'temporary D1 write failure'
      && JSON.stringify(progress.evidenceIngest?.adaptive?.pending) === '[["1","1","1"]]',
    JSON.stringify({ error: firstError?.message, pending: progress.evidenceIngest?.adaptive?.pending }));

  const resumed = await gm.calcEvidenceUnit(BLOCK, progress);
  ok('U5e 再試行は保持した範囲を再取得・D1保存して前進',
    store.evidenceEvents.size === 1 && resumed.evidenceIngest?.next === '2'
      && resumed.evidenceIngest?.adaptive === undefined,
    JSON.stringify({ rows: store.evidenceEvents.size, ingest: resumed.evidenceIngest }));
}

// ============================================================
// U6: R12-06 B-M3 — 平常時は広い幅を維持（7,200回へ膨張しない）
// ============================================================
{
  const chain = makeChainStub({
    openAt: LATEST_TS - 120000,
    closeAt: LATEST_TS - 60,
    resultCount: 1,
    logs: [mkLog(1, 1)],
  });
  const { gm } = makeGm(chain);
  let progress = {
    blockNum: BLOCK,
    stage: 'evidence', cursor: 0, failures: 0,
    evidenceIngest: {
      segs: [['1', '7200']], segIdx: 0, next: '1', widened: false, done: false, seen: [],
    },
  };
  console.log = () => {}; console.warn = () => {}; console.error = () => {};
  try {
    for (let i = 0; i < 10 && progress.stage === 'evidence'; i++) {
      progress = await gm.calcEvidenceUnit(BLOCK, progress);
    }
  } finally {
    console.log = realLog; console.warn = realWarn; console.error = realErr;
  }
  realLog(`  measurement B-M3: blocks=7200 getLogsCalls=${chain.getLogsCalls.length} widths=${chain.getLogsCalls.map(([f, t]) => Number(t - f + 1n)).join(',')}`);
  ok('U6 B-M3 平常時7,200ブロックは従来同等の4 RPC（2,000幅）で完走',
    chain.getLogsCalls.length === 4 && progress.stage === 'depids',
    `calls=${chain.getLogsCalls.length} stage=${progress.stage}`);
}

// ============================================================
// U7: R12-06 C-M1 — block-verifierのchain.jsも1ブロックまで分割
// ============================================================
{
  let calls = 0;
  const client = {
    async getLogs({ fromBlock, toBlock }) {
      calls++;
      if (fromBlock !== toBlock) {
        const error = new Error('log response size exceeded');
        error.code = -32005;
        throw error;
      }
      return [{ blockNumber: fromBlock, logIndex: 0 }];
    },
  };
  const logs = await getLogsChunkedAdaptive(client, {
    address: CONTRACT, event: undefined, args: { blockNum: BigInt(BLOCK) }, fromBlock: 1n, toBlock: 2000n,
  });
  realLog(`  measurement C-M1: blocks=2000 calls=${calls} logs=${logs.length} leafWidth=1`);
  ok('U7 C-M1 block-verifierが累計64分割で止まらず1ブロック単位まで割って読み切る',
    calls === 3999 && logs.length === 2000,
    `calls=${calls} logs=${logs.length}`);
}

// ============================================================
// U8: BV-SCALE-01 — 第三者検証器も正典と同じ400件単位で処理
// ============================================================
{
  const events = Array.from({ length: 2100 }, (_, index) => ({
    seq: index + 1,
    timestamp: 1700000000 + index,
    txHash: `0x${String(index + 1).padStart(64, '0')}`,
    data: '0x01',
  }));
  const unitSizes = [];
  const seqFilterSizes = [];
  const metadata = await scanEvidenceEventsInUnits({
    fromBlock: 1n,
    toBlock: 1n,
    resultCount: events.length,
    fetchRange: async (_from, _to, seqs) => {
      seqFilterSizes.push(seqs.length);
      const wanted = new Set(seqs.map(Number));
      return events.filter((event) => wanted.has(event.seq));
    },
    onUnit: async (unit) => { unitSizes.push(unit.length); },
  });
  realLog(`  measurement BV-SCALE-01: events=${events.length} units=${unitSizes.length} sizes=${unitSizes.join(',')}`);
  ok('U8 Evidence 2,100件を正典400件以下のunitへ分割',
    EVIDENCE_EVENTS_PER_UNIT === 400
      && Math.max(...unitSizes) === 400
      && unitSizes.length === 6
      && Math.max(...seqFilterSizes) === 400
      && metadata.length === 2100,
    JSON.stringify({ constant: EVIDENCE_EVENTS_PER_UNIT, unitSizes, seqFilterSizes, metadata: metadata.length }));
  ok('U8 永続メタデータは巨大dataを保持しない',
    metadata.every((event) => !Object.prototype.hasOwnProperty.call(event, 'data')));

  const retained = Object.create(null);
  let persisted = 0;
  for (let start = 0; start < events.length; start += EVIDENCE_EVENTS_PER_UNIT) {
    const selected = { adoptedByUid: Object.create(null) };
    for (const event of events.slice(start, start + EVIDENCE_EVENTS_PER_UNIT)) {
      selected.adoptedByUid[`uid-${event.seq}`] = {
        seq: event.seq, txHash: event.txHash, raw: `raw-${event.seq}`,
        bundle: { deliberately: 'large parsed bundle placeholder' }, groupId: event.seq % 420,
      };
    }
    await retainAdoptedEvidenceUnit(selected, retained, async (seq, raw) => {
      persisted++;
      return `/spool/${seq}-${raw.length}`;
    });
  }
  ok('U8 採用2,100件のraw/bundleをメモリ保持せずspool参照だけ残す',
    persisted === 2100 && Object.values(retained).every((item) => (
      typeof item.rawRef === 'string'
      && !Object.prototype.hasOwnProperty.call(item, 'raw')
      && !Object.prototype.hasOwnProperty.call(item, 'bundle')
    )));
}

// ============================================================
// U9: A6-03 — 採用Evidence spoolはR2 cache外で、run終端に掃除可能
// ============================================================
{
  const taskTmp = join(REPO_ROOT, 'tmp', 'T4-4');
  await mkdir(taskTmp, { recursive: true });
  const root = await mkdtemp(join(taskTmp, 'bv-evidence-spool-'));
  const r2BaseDir = join(root, 'block7');
  await mkdir(r2BaseDir, { recursive: true });
  const spool = await createEvidenceSpool(r2BaseDir, BLOCK);
  const rawPath = await spool.persistRaw(1, 'compact-evidence');
  ok('U9 spool directoryはblock R2 cache配下に入らない',
    !spool.dir.startsWith(`${r2BaseDir}${sep}`), `cache=${r2BaseDir} spool=${spool.dir}`);
  ok('U9 採用rawをcache外spoolからbyte-exactに読める',
    await readFile(rawPath, 'utf8') === 'compact-evidence');
  await spool.cleanup();
  let remains = true;
  try { await access(spool.dir); } catch { remains = false; }
  ok('U9 cleanup後にrun固有spoolが残らない', !remains, spool.dir);
  const resultsSource = await readFile(new URL('../src/stages/results.js', import.meta.url), 'utf8');
  ok('U9 run finallyがEvidence spool cleanupを必ず呼ぶ',
    /finally\s*\{[\s\S]*?await S\.evidenceSpool\.cleanup\(\);/.test(resultsSource));
  await rm(root, { recursive: true, force: true });
}

realLog(`\nr2-evidence-ingest-unit: ${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

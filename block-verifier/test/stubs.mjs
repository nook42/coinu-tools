// stubs.mjs — Durable Object / D1 / R2 のローカルスタブ。
//
// 方針（test-grouping/run.mjs・deposit-verify-test.mjs の実証済みパターンの拡張）:
//   - ロジックは一切持たない。本番コードが要求する最小 API 面のみ提供する。
//   - R2 はファイルバック: put されたバイト列（本番と同じ JSON.stringify 済み文字列）を
//     フィクスチャディレクトリへ**そのまま**書く → 公開 R2 と同じ minified バイトが残る。
//   - D1 は SQL 文字列のパターンマッチ。未知の SQL は throw（無言の齟齬を作らない）。
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';

// ---------------- DO storage / state ----------------

export function makeStorage() {
  const map = new Map();
  let alarmAt = null;
  return {
    async get(key) { return map.has(key) ? map.get(key) : undefined; },
    // 本番DO同様、オブジェクト形式のマルチキーput（同一トランザクション書込）も受け付ける
    // （A3 の phase_task_queue + phase_task_active 同時書込が使用）
    async put(key, value) {
      if (value === undefined && key !== null && typeof key === 'object') {
        for (const [k, v] of Object.entries(key)) map.set(k, v);
        return;
      }
      map.set(key, value);
    },
    // 本番DO同様、配列も受け付ける（Z2キー分割の deleteSubmissionKeys が使用）
    async delete(key) {
      if (Array.isArray(key)) { for (const k of key) map.delete(k); return; }
      map.delete(key);
    },
    async deleteAll() { map.clear(); },
    // 本番DOのlist準拠: キーの辞書順で返す（Z2キー分割の loadMessages 等が使用）
    async list(options = {}) {
      const { prefix, limit } = options;
      const keys = [...map.keys()].filter(k => !prefix || String(k).startsWith(prefix)).sort();
      const out = new Map();
      for (const k of (limit ? keys.slice(0, limit) : keys)) out.set(k, map.get(k));
      return out;
    },
    async setAlarm(t) { alarmAt = Number(t); },
    async getAlarm() { return alarmAt; },
    _map: map,
  };
}

// ChatGameDO / GameMasterDO 用 state スタブ。
// 多くの歯は WebSocket を accept せず（ハンドラ直接呼び出し）、そのとき getWebSockets は空。
// R33-F-1-01（便 S3C11）: upgrade の成功枝を通す歯のために、本番の
// `state.getWebSockets(tag)` と同じく「accept した接続のうち tag を持つもの（tag 省略時は全部）」を返す。
// 閉じ終わった接続（readyState 3）は返さない。
export function makeState({ reverseWebSockets = false } = {}) {
  const storage = makeStorage();
  const accepted = [];
  return {
    storage,
    getWebSockets(tag) {
      const sockets = accepted.filter(ws => ws?.readyState !== 3
        && (tag === undefined || (ws.__tags || []).includes(tag)));
      return reverseWebSockets ? sockets.reverse() : sockets;
    },
    getTags(ws) { return ws?.__tags || []; },
    acceptWebSocket(ws, tags) { ws.__tags = tags; accepted.push(ws); },
  };
}

// WSハンドラ直接呼び出し用の偽ソケット。sendTo の内容を記録し、エラー応答を検出可能にする。
export function makeFakeWs(uid) {
  const sent = [];
  return {
    __tags: [uid],
    readyState: 1,
    sent,
    send(str) { sent.push(JSON.parse(str)); },
    close() {},
    lastError() { return sent.find(m => m && m.type === 'error') || null; },
  };
}

// ---------------- R2（ファイルバック） ----------------

// R2 multipart のサイズ・番号制約。最後だけ 5 MiB 未満を許す。
export function validateR2MultipartParts(parts, uploads) {
  if (!Array.isArray(parts) || parts.length < 1 || parts.length > 10000) throw new Error('R2 multipart: part count outside 1..10000');
  let regularSize = null;
  for (let i = 0; i < parts.length; i++) {
    const number = parts[i]?.partNumber;
    if (number !== i + 1 || number > 10000) throw new Error('R2 multipart: invalid part number');
    const bytes = uploads.get(number);
    if (!(bytes instanceof Uint8Array) || parts[i].etag !== `etag${number}`) throw new Error('R2 multipart: missing part');
    if (bytes.byteLength < 1 || bytes.byteLength > 5 * 1024 ** 3) throw new Error('R2 multipart: part outside 1B..5GiB');
    if (i < parts.length - 1) {
      if (bytes.byteLength < 5 * 1024 ** 2) throw new Error('R2 multipart: non-final part below 5MiB');
      if (regularSize !== null && bytes.byteLength !== regularSize) throw new Error('R2 multipart: non-final parts differ in size');
      regularSize = bytes.byteLength;
    } else if (regularSize !== null && bytes.byteLength > regularSize) {
      throw new Error('R2 multipart: final part larger than regular parts');
    }
  }
  if (uploads.size !== parts.length) throw new Error('R2 multipart: unexpected uploaded parts');
}

// 本番の R2_BUCKET API 面: get(key) -> null | { text(), json() } / put(key, string, opts)
export function makeR2Bucket(rootDir) {
  return {
    rootDir,
    async get(key) {
      const p = join(rootDir, key);
      if (!existsSync(p)) return null;
      const text = readFileSync(p, 'utf8');
      return {
        async text() { return text; },
        async json() { return JSON.parse(text); },
      };
    },
    async put(key, data, _opts) {
      if (typeof data !== 'string') {
        // 本番の全書き込みは JSON.stringify 済み文字列（putR2Object / 直接put とも）。
        // 別型が来たらスタブの想定外＝フィクスチャのバイト同一性が壊れるので停止する。
        throw new Error(`R2 stub: non-string put for ${key} (${typeof data})`);
      }
      const p = join(rootDir, key);
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, data);
    },
  };
}

// ---------------- D1（SQL パターンマッチ） ----------------

// game_groups 行: { block_num, group_id, lang, mixed, members, status, result, completed_at, created_at }
export function makeD1Stub() {
  const store = {
    gameGroups: [],      // 行の配列
    gameResults: [],     // INSERT された行（検査用に保持）
    evidenceEvents: new Map(), // seq -> row
  };

  function exec(sql, args) {
    const q = sql.replace(/\s+/g, ' ').trim();

    // --- game_groups ---
    if (q.startsWith("SELECT COUNT(*) as cnt FROM game_groups WHERE block_num = ? AND status != 'formed'")) {
      const [blockNum] = args;
      const cnt = store.gameGroups.filter(r => r.block_num === blockNum && r.status !== 'formed').length;
      return { results: [{ cnt }] };
    }
    // grouping watchdog の resumable 再入。通常の fresh fixture では読まないが、
    // Coordinator receipt pending から呼び出し側を再開すると実際に通る。
    if (q.startsWith('SELECT COUNT(*) AS c FROM game_groups WHERE block_num = ?')) {
      const [blockNum] = args;
      return { results: [{ c: store.gameGroups.filter(r => r.block_num === blockNum).length }] };
    }
    if (q.startsWith("SELECT COUNT(*) AS cnt FROM game_groups WHERE block_num = ? AND status = 'formed'")) {
      const [blockNum] = args;
      const cnt = store.gameGroups.filter(r => r.block_num === blockNum && r.status === 'formed').length;
      return { results: [{ cnt }] };
    }
    if (q.startsWith('SELECT status, COUNT(*) AS cnt FROM game_groups WHERE block_num = ? GROUP BY status')) {
      const [blockNum] = args;
      const counts = new Map();
      for (const row of store.gameGroups.filter(r => r.block_num === blockNum)) {
        counts.set(row.status, (counts.get(row.status) || 0) + 1);
      }
      return { results: [...counts].map(([status, cnt]) => ({ status, cnt })) };
    }
    if (q.startsWith('DELETE FROM game_groups WHERE block_num = ?')) {
      const [blockNum] = args;
      store.gameGroups = store.gameGroups.filter(r => r.block_num !== blockNum);
      return { results: [] };
    }
    if (q.startsWith('INSERT INTO game_groups (block_num, group_id, lang, mixed, members, status, created_at)')) {
      const [block_num, group_id, lang, mixed, members, created_at] = args;
      store.gameGroups.push({ block_num, group_id, lang, mixed, members, status: 'formed', result: null, completed_at: null, created_at });
      return { results: [] };
    }
    // autoDistribute（game-master-DO.js:3377-3379）: 列リストに result / completed_at を含む1行INSERT
    if (q.startsWith("INSERT INTO game_groups (block_num, group_id, lang, mixed, members, status, result, completed_at, created_at) VALUES (?, 0, 'auto', 0, ?, 'auto_distributed', ?, ?, ?)")) {
      const [block_num, members, result, completed_at, created_at] = args;
      store.gameGroups.push({ block_num, group_id: 0, lang: 'auto', mixed: 0, members, status: 'auto_distributed', result, completed_at, created_at });
      return { results: [] };
    }
    if (q.startsWith("SELECT group_id, lang, mixed, members FROM game_groups WHERE block_num = ? AND status = 'formed'")) {
      const [blockNum] = args;
      return { results: store.gameGroups.filter(r => r.block_num === blockNum && r.status === 'formed')
        .map(({ group_id, lang, mixed, members }) => ({ group_id, lang, mixed, members })) };
    }
    if (q.startsWith("UPDATE game_groups SET status = 'waiting' WHERE block_num = ? AND status = 'formed'")) {
      const [blockNum] = args;
      for (const r of store.gameGroups) if (r.block_num === blockNum && r.status === 'formed') r.status = 'waiting';
      return { results: [] };
    }
    if (q.startsWith('SELECT block_num, group_id, members FROM game_groups WHERE block_num = ?')) {
      const [blockNum] = args;
      const rows = store.gameGroups.filter(r => r.block_num === blockNum)
        .map(({ block_num, group_id, members }) => ({ block_num, group_id, members }));
      if (q.includes('ORDER BY group_id')) rows.sort((a, b) => a.group_id - b.group_id);
      return { results: rows };
    }
    if (q.startsWith('SELECT group_id, members FROM game_groups WHERE block_num = ?')) {
      const [blockNum] = args;
      const rows = store.gameGroups.filter(r => r.block_num === blockNum)
        .map(({ group_id, members }) => ({ group_id, members }));
      if (q.includes('ORDER BY group_id')) rows.sort((a, b) => a.group_id - b.group_id);
      return { results: rows };
    }
    // 🔴 ラウンド19 判断不要-4（2026-08-08）: `advancePhase` は
    //    ⚠️ ここは長く `P-2026-0843` を名乗っていたが、同 ID は他の全所で
    //       **判断③（提出物にも applyChatCaps を掛ける）**を指す＝衝突していた。
    //       この項目に P-ID は割り当てられていない（`PENDING_DECISIONS.md` の決定 ID 索引を参照）。
    //    フェーズ飛び越し（chatting を通っていないグループ）を検知するため
    //    `status` も引くようになった。
    if (q.includes("status IN ('chatting','submitting','completed')")) {
      const [blockNum] = args;
      return { results: store.gameGroups
        .filter(r => r.block_num === blockNum && ['chatting', 'submitting', 'completed'].includes(r.status))
        .map(({ group_id, status }) => ({ group_id, status })) };
    }
    if (q.startsWith('SELECT group_id, status FROM game_groups WHERE block_num = ?')) {
      const [blockNum] = args;
      return { results: store.gameGroups.filter(r => r.block_num === blockNum)
        .map(({ group_id, status }) => ({ group_id, status })) };
    }
    if (q.startsWith('SELECT group_id FROM game_groups WHERE block_num = ?')) {
      const [blockNum] = args;
      return { results: store.gameGroups.filter(r => r.block_num === blockNum).map(({ group_id }) => ({ group_id })) };
    }
    if (q.startsWith('SELECT members FROM game_groups WHERE block_num = ?')) {
      const [blockNum] = args;
      return { results: store.gameGroups.filter(r => r.block_num === blockNum).map(({ members }) => ({ members })) };
    }
    if (q.startsWith('UPDATE game_groups SET result = ?, completed_at = ? WHERE block_num = ? AND group_id = ?')) {
      const [result, completed_at, blockNum, groupId] = args;
      for (const r of store.gameGroups) if (r.block_num === blockNum && r.group_id === groupId) { r.result = result; r.completed_at = completed_at; }
      return { results: [] };
    }
    if (q.startsWith('UPDATE game_groups SET status = ? WHERE block_num = ?')) {
      const [status, blockNum] = args;
      for (const r of store.gameGroups) if (r.block_num === blockNum) r.status = status;
      return { results: [] };
    }

    // --- game_groups 件数（A1ドライバの初期化ガード） ---
    if (q.startsWith('SELECT COUNT(*) as cnt FROM game_groups WHERE block_num = ?')) {
      const [blockNum] = args;
      return { results: [{ cnt: store.gameGroups.filter(r => r.block_num === blockNum).length }] };
    }

    // --- evidence_events ---
    if (q.startsWith("SELECT seq, valid, invalid_reason, uid, group_id FROM evidence_events WHERE kind='result' AND block_num = ?")) {
      const [blockNum] = args;
      return { results: [...store.evidenceEvents.values()].filter(r => r.block_num === blockNum)
        .map(({ seq, valid, invalid_reason, uid, group_id }) => ({ seq, valid, invalid_reason, uid, group_id })) };
    }
    // A1: 採用集合の確定（seq昇順・tx_hash込み）
    if (q.startsWith("SELECT seq, tx_hash, sender, valid, invalid_reason, uid, group_id FROM evidence_events WHERE kind='result' AND block_num = ? ORDER BY seq ASC")) {
      const [blockNum] = args;
      return { results: [...store.evidenceEvents.values()].filter(r => r.block_num === blockNum)
        .sort((a, b) => a.seq - b.seq)
        .map(({ seq, tx_hash, sender, valid, invalid_reason, uid, group_id }) => ({ seq, tx_hash, sender, valid, invalid_reason, uid, group_id })) };
    }
    // A1: 採用イベントrawの遅延ロード
    if (q === "SELECT data, sender, tx_hash FROM evidence_events WHERE kind='result' AND block_num = ? AND seq = ?") {
      const [blockNum, seq] = args;
      const row = [...store.evidenceEvents.values()].find(r => r.block_num === blockNum && r.seq === seq);
      return { results: row ? [{ data: row.data, sender: row.sender, tx_hash: row.tx_hash }] : [] };
    }
    if (q.startsWith('INSERT OR REPLACE INTO evidence_events')) {
      const [block_num, seq, sender, data, tx_hash, evt_block, evt_timestamp, valid, invalid_reason, uid, group_id, ingested_at] = args;
      store.evidenceEvents.set(seq, { kind: 'result', block_num, seq, sender, data, tx_hash, evt_block, evt_timestamp, valid, invalid_reason, uid, group_id, ingested_at });
      return { results: [] };
    }
    // R2 / S3C5（D-06）: ingest は取り込みの段でその場で判定し、要約・判定と
    // （有効な提出だけ）中身を書く。正典は P-2026-0813 以降 WHERE 句なしで**常にチェーンの値で上書き**する
    // （旧スタブは tx_hash が同じ既存行を温存していた＝正典と食い違っていた）。
    // 列の並び・VALUES・DO UPDATE SET の代入は SQL の文言から読む（正典の SQL が変われば挙動も追随する）。
    if (q.startsWith('INSERT INTO evidence_events') && q.includes('ON CONFLICT(kind, block_num, seq) DO UPDATE')) {
      const cols = q.match(/\(([^)]*)\) VALUES/)[1].split(',').map(s => s.trim());
      const vals = q.match(/VALUES \(([^)]*)\)/)[1].split(',').map(s => s.trim());
      const incoming = {};
      let ai = 0;
      cols.forEach((col, i) => {
        const v = vals[i];
        incoming[col] = v === '?' ? args[ai++] : (v === 'NULL' ? null : v.replace(/^'|'$/g, ''));
      });
      const existing = store.evidenceEvents.get(incoming.seq);
      if (!existing) {
        store.evidenceEvents.set(incoming.seq, incoming);
      } else {
        const setClause = q.split('DO UPDATE SET')[1].split(/\bWHERE\b/)[0];
        for (const assign of setClause.split(',').map(s => s.trim()).filter(Boolean)) {
          const [col, rhs] = assign.split('=').map(s => s.trim());
          existing[col] = rhs === 'NULL' ? null : incoming[rhs.replace(/^excluded\./, '')];
        }
      }
      return { results: [] };
    }
    // S3C5: 「候補以外を空ける」— uid ごとに範囲内で最小 seq の有効な行以外の data を空ける
    if (q.startsWith("UPDATE evidence_events SET data = '' WHERE kind='result' AND block_num = ? AND uid = ? AND data <> '' AND seq <> (SELECT MIN(seq) FROM evidence_events WHERE kind='result' AND block_num = ? AND uid = ? AND valid = 1 AND seq BETWEEN 1 AND ?)")) {
      const [blockNum, uid, , uid2, maxSeq] = args;
      let min = null;
      for (const r of store.evidenceEvents.values()) {
        if (r.block_num === blockNum && r.uid === uid2 && r.valid === 1 && r.seq >= 1 && r.seq <= maxSeq
          && (min === null || r.seq < min)) min = r.seq;
      }
      if (min !== null) {
        for (const r of store.evidenceEvents.values()) {
          if (r.block_num === blockNum && r.uid === uid && r.data !== '' && r.seq !== min) r.data = '';
        }
      }
      return { results: [] };
    }
    // S3C5: cleanup — そのブロックの集計がすべて終わった後に採用候補の中身も空ける
    if (q.startsWith("UPDATE evidence_events SET data = '' WHERE kind='result' AND block_num = ? AND data <> ''")) {
      const [blockNum] = args;
      for (const r of store.evidenceEvents.values()) if (r.block_num === blockNum && r.data !== '') r.data = '';
      return { results: [] };
    }
    // R2: 完全性検証（seq 1..resultCount被覆のCOUNT）
    if (q.startsWith("SELECT COUNT(*) AS c FROM evidence_events WHERE kind='result' AND block_num = ? AND seq BETWEEN 1 AND ?")) {
      const [blockNum, maxSeq] = args;
      const c = [...store.evidenceEvents.values()].filter(r => r.block_num === blockNum && r.seq >= 1 && r.seq <= maxSeq).length;
      return { results: [{ c }] };
    }
    // S3C5（D-06）: 旧「未検証行のメタ／本体ロード／検証結果の反映」の3つの SQL は、判定を取り込みへ
    // 移したので正典から消えた。正典がそれらを再び発行したら、下の unhandled SQL で落ちる。
    // R2: 採用集合の確定（seq範囲つき・A1旧形の後継）
    if (q.startsWith("SELECT seq, tx_hash, sender, valid, invalid_reason, uid, group_id FROM evidence_events WHERE kind='result' AND block_num = ? AND seq > ? AND seq <= ? ORDER BY seq ASC LIMIT ?")) {
      const [blockNum, afterSeq, maxSeq, limit] = args;
      return { results: [...store.evidenceEvents.values()]
        .filter(r => r.block_num === blockNum && r.seq > afterSeq && r.seq <= maxSeq)
        .sort((a, b) => a.seq - b.seq)
        .slice(0, limit)
        .map(({ seq, tx_hash, sender, valid, invalid_reason, uid, group_id }) => ({ seq, tx_hash, sender, valid, invalid_reason, uid, group_id })) };
    }
    if (q.startsWith("SELECT seq, data_len FROM evidence_events WHERE kind='result' AND block_num = ? AND seq > ? AND seq <= ? ORDER BY seq ASC LIMIT ?")) {
      const [blockNum, afterSeq, maxSeq, limit] = args;
      return { results: [...store.evidenceEvents.values()]
        .filter(r => r.block_num === blockNum && r.seq > afterSeq && r.seq <= maxSeq)
        .sort((a, b) => a.seq - b.seq).slice(0, limit)
        .map(({ seq, data_len }) => ({ seq, data_len })) };
    }

    // --- game_results ---
    // R20-F1: autoDistribute置換前に旧shard対象uidを列挙する。通常fixtureはfresh D1なので空。
    // 置換・再開そのものは専用auto-distribute-resume-testで旧行を含めて検証する。
    if (q.startsWith('SELECT DISTINCT userId FROM game_results WHERE block_num = ?')) {
      return { results: [] };
    }
    if (q.startsWith('DELETE FROM game_results WHERE block_num = ?')) {
      store.gameResults = [];
      return { results: [] };
    }
    // 旧: INSERT OR REPLACE / 新: INSERT ... ON CONFLICT(...) DO UPDATE（claimed温存UPSERT・
    // 2026-07-16 競合修正）。どちらも検査用に記録するのみ（他所で未消費）。
    if (q.startsWith('INSERT OR REPLACE INTO game_results') || q.startsWith('INSERT INTO game_results')) {
      store.gameResults.push({ sql: q, args });
      return { results: [] };
    }

    throw new Error(`D1 stub: unhandled SQL: ${q}`);
  }

  const db = {
    prepare(sql) {
      return {
        bind(...args) {
          return {
            sql, args,
            async all() { return exec(sql, args); },
            async run() { return exec(sql, args); },
            async first() { const r = exec(sql, args); return r.results[0] ?? null; },
            __exec() { return exec(sql, args); },
          };
        },
      };
    },
    async batch(stmts) { return stmts.map(s => s.__exec()); },
    __store: store,
  };
  return db;
}

// ---------------- CHAT_GAME_DO namespace ----------------

// 本物の ChatGameDO クラスをインスタンス管理する DO ネームスペーススタブ。
// idFromName(`${blockNum}-${groupId}`) → get(id).fetch(request) が本番と同じ流れ。
// gen-fixture はゲーム進行（WSハンドラ直接呼び出し）のため instance(name) で生インスタンスにも触る。
/// S3-002（2026-07-29）: ChatGameDO の HTTP 制御面（/init /set-phase /get-results /reset
/// /debug-submission /cleanup）は `X-Api-Secret` 必須になった（chat-game-DO.js の AUTHED）。
/// secret 未設定は fail-closed で 401 なので、テストから叩くときは env に API_SECRET を入れ、
/// リクエストはこのヘルパーで作ること。
export const TEST_API_SECRET = 'unit-test-secret';

/// 認証ヘッダ付きの Request を作る。ChatGameDO の AUTHED endpoint 用。
export function authedRequest(url, init = {}, secret = TEST_API_SECRET) {
  return new Request(url, {
    ...init,
    headers: { ...(init.headers || {}), 'X-Api-Secret': secret },
  });
}

export function makeChatGameNamespace(ChatGameDO, env, stateOptions = {}) {
  const instances = new Map();
  function instance(name) {
    if (!instances.has(name)) {
      instances.set(name, new ChatGameDO(makeState(stateOptions), env));
    }
    return instances.get(name);
  }
  return {
    idFromName(name) { return name; },
    get(id) {
      const inst = instance(id);
      return { fetch: (req) => inst.fetch(req) };
    },
    instance,
    instances,
  };
}

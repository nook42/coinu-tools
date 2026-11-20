// workers/game_workers/lib/timeline-check.js
// F-TL5（audit/REPORT_timeline.md）: env（START_TIME/BLOCK_TIME/GAME_PERIOD/SUBMIT_PERIOD）から計算する
// 宣言タイムラインと、Evidence 契約がチェーン上で計算する窓（chatWindow/resultWindow＝正）の整合検証。
// 純関数のみ（RPC・env 読取なし）— game-master-do.js とテストが同一実装を共有する。
// v3.2: TERM1（準備期間）撤廃。chattingStart = 応募終了 + grace。TERM2/TERM3 → GAME_PERIOD/SUBMIT_PERIOD 改名。

// 有限な非負数か（NaN/Infinity/文字列/undefined/null/真偽値を全部落とす）。
// 🔴 typeof を見る: `true - 0 === 1` のような暗黙変換で通してしまわないため。
const isNonNegFinite = (v) => typeof v === 'number' && Number.isFinite(v) && v >= 0;

// GameMaster が timeline_unverified の no-game として確定でき、block-verifier が
// 同じ schema を受理する原因の単一台帳。書き手と読み手で別々の集合を持たない。
export const TIMELINE_NO_GAME_CAUSES = Object.freeze([
  'chain_unreadable',
  'env_chain_mismatch',
  'grouping_anchor_unreadable',
  'previous_block_not_ready',
  'previous_block_anchor_pending',
]);

// ブロック番号を 0 以上の整数へ。10進表記の文字列も受ける（管理 API の JSON body 経路）。
// それ以外（負値・小数・"0x1"・null・オブジェクト）は null。
function normalizeBlockNum(blockNum) {
  if (typeof blockNum === 'number') {
    return Number.isSafeInteger(blockNum) && blockNum >= 0 ? blockNum : null;
  }
  if (typeof blockNum === 'string' && /^[0-9]+$/.test(blockNum)) {
    const n = Number(blockNum);
    return Number.isSafeInteger(n) ? n : null;
  }
  return null;
}

// getDeclaredTimesMs の純関数版（game-master-do.js から委譲）。
// 引数は解析済み数値（ms）。**必須値が1つでも欠けていれば null**（従来動作＝相対スケジュールへ）。
//
// 🔴 外部レビュー（2026-08-07・④）で実測された穴:
//   `gamePeriodMs` が欠けているだけで
//     { submittingStart: NaN, closeAt: NaN, completedAt: NaN }
//   という**部分結果**が返っていた。呼び出し元（schedulePhaseTransitions:3502-3510）は
//   これを executeAt としてタスクキューへ入れるので、フェーズ遷移が NaN 時刻で登録される
//   ＝「いつまでも実行されない／ソート順が壊れる」。
//   壊れた時刻表を作るくらいなら null を返して呼び出し元の「タイムライン不明」経路
//   （'no_env_timeline' / 'no_declared_times' / 'unknown'）へ落とす方が安全。
//   既存の呼び出し元は全て null を扱える（game-master-DO.js:565,575,833,877,989,3416 /
//   block-verifier src/stages/results.js:1010）。
export function computeDeclaredTimesMs({ startTimeMs, blockTimeMs, gamePeriodMs, submitPeriodMs, confirmations }, blockNum, graceSec) {
  // startTimeMs は Unix epoch ms なので負値もありうる（1970年より前）＝ 有限だけ要求する。
  if (!Number.isFinite(startTimeMs)) return null;
  // 期間・回数は非負の有限値が必須。1つでも欠けたら部分結果を作らない。
  if (!isNonNegFinite(blockTimeMs)) return null;
  if (!isNonNegFinite(gamePeriodMs)) return null;
  if (!isNonNegFinite(submitPeriodMs)) return null;
  if (!isNonNegFinite(confirmations)) return null;
  if (!isNonNegFinite(graceSec)) return null;
  // blockNum は 0 以上の整数。**文字列のまま計算しない**
  //（旧実装では "3" が渡ると (blockNum + 1) が "31" になり、31 ブロック先の時刻表が出来ていた）。
  // 管理 API の JSON body から文字列で来る経路があるので、10進表記の文字列だけは数値化して受ける。
  const n = normalizeBlockNum(blockNum);
  if (n === null) return null;

  const entryEndMs = startTimeMs + (n + 1) * blockTimeMs;
  const graceMs = graceSec * 1000;
  const chattingStart = entryEndMs + graceMs;         // 開始待機（waiting）= [グループ分け完了, chattingStart)
  const submittingStart = chattingStart + gamePeriodMs; // = チャット窓終端 = オンチェーン窓 openAt
  const closeAt = submittingStart + submitPeriodMs;     // = オンチェーン窓 closeAt
  const completedAt = closeAt + confirmations * 12000 + 30000;
  return { entryEndMs, graceMs, chattingStart, submittingStart, closeAt, completedAt };
}

// ============================================================
// 必須不変量①（CLAUDE.md「チャットゲーム仕様」節）— 初期設定の検査
// ============================================================
//   GAME_PERIOD + SUBMIT_PERIOD + INITIAL_GRACE <= BLOCK_TIME
//
// 🔴 外部レビュー（2026-08-07・④）で実測された穴:
//   BLOCK_TIME=100s / GAME_PERIOD=60s / SUBMIT_PERIOD=41s を env・チェーンの**両側**へ
//   入れると、compareEnvParamsToChainParams も compareDeclaredToChainWindows も
//   「不一致なし」を返した（両辺が同じ壊れた値なので当然）。
//   closeAt=201,000ms が次ブロック境界 200,000ms を 1,000ms 超えていても誰も気づかない。
//   「env とチェーンが一致しているか」と「その値が仕様として成立しているか」は別の検査なので、
//   別の純関数として切り出す。
//
// ⚠️ **延長後の grace には適用しないこと**（CLAUDE.md の必須不変量①の注記）:
//   ①を強制するのは Evidence の constructor で、対象は**初期 grace のみ**。
//   `extendGrace` の上限は BLOCK_TIME なので、障害時の延長では①を意図的に超えうる
//   （設計どおり。超過分は次ブロック以降のグループ分け待ちで吸収される）。
//   したがってこの関数へ渡してよいのは **initialGraceMs（＝デプロイ時の定数）だけ**であり、
//   `Evidence.currentGrace(N)` の実測値を渡してはならない。実測 grace 込みの時刻計算は
//   computeDeclaredTimesMs 側の仕事で、そちらは①を検査しない。
//
// 返り値は問題の説明の配列（空配列＝不変量を満たす）。throw はしない
//（呼び出し元が「設定ミスとして停止」「レポートに FAIL として載せる」を選べるようにする）。
export function checkTimelineInvariant({ blockTimeMs, gamePeriodMs, submitPeriodMs, initialGraceMs }) {
  const problems = [];
  const fields = { blockTimeMs, gamePeriodMs, submitPeriodMs, initialGraceMs };
  for (const [k, v] of Object.entries(fields)) {
    if (!isNonNegFinite(v)) problems.push(`${k}: expected a finite non-negative number, got ${describe(v)}`);
  }
  if (problems.length > 0) return problems;
  if (blockTimeMs <= 0) problems.push('blockTimeMs: must be > 0');
  const consumed = gamePeriodMs + submitPeriodMs + initialGraceMs;
  if (consumed > blockTimeMs) {
    problems.push(
      `invariant #1 violated: GAME_PERIOD(${gamePeriodMs}) + SUBMIT_PERIOD(${submitPeriodMs}) + ` +
      `INITIAL_GRACE(${initialGraceMs}) = ${consumed} > BLOCK_TIME(${blockTimeMs}) ` +
      `(overflow ${consumed - blockTimeMs}ms: the block would close after the next block already opened)`
    );
  }
  return problems;
}

// 値の説明（エラーメッセージ用・型が分かる形に）
function describe(v) {
  if (typeof v === 'number') return Number.isNaN(v) ? 'NaN' : String(v);
  if (v === null) return 'null';
  if (v === undefined) return 'undefined';
  return `${typeof v} ${JSON.stringify(v)}`;
}

// env の生パラメータ（秒）と契約 immutable（秒）の直接比較 —【主検査】。
// 境界照合には相殺ズレ（例: START_TIME+δ ∧ GAME_PERIOD−δ で境界不変）の盲点があるため
// （Lean Timeline.lean boundary_blindspot_witness）、個別パラメータ比較を主とする。
// どの env 変数がいくつズレたかをそのまま示せる利点もある。返り値は不一致の説明（空配列＝一致）。
//
// 🔴 外部レビュー（2026-08-07・④）で実測された穴:
//   `compareEnvParamsToChainParams({}, {})` が `[]`（＝一致）を返していた。
//   `undefined !== undefined` は false なので、**両側とも値が無い**ときに「一致」と報告される。
//   env もチェーンも読めていない（＝何も検査できていない）場面が、
//   verifyEnvChainTimeline の `paramDiffs.length === 0` を通って「検証 OK」になっていた。
//   NaN（片側だけ欠けた場合の Math.round(undefined) 由来）も同様に扱いを明示する。
//   欠損・非数値・負値は「不一致」として説明を返す（＝呼び出し元は従来どおり throw / FAIL する）。
//   throw ではなく返り値にするのは、block-verifier が「例外で落ちる」ではなく
//   「FAIL として報告する」必要があるため（src/stages/results.js:350）。
const TIMELINE_PARAM_KEYS = ['START_TIME', 'BLOCK_TIME', 'GAME_PERIOD', 'SUBMIT_PERIOD'];

export function compareEnvParamsToChainParams(envParams, chainParams) {
  const mismatches = [];
  const envOk = envParams !== null && typeof envParams === 'object';
  const chainOk = chainParams !== null && typeof chainParams === 'object';
  if (!envOk) mismatches.push(`envParams: expected an object, got ${describe(envParams)}`);
  if (!chainOk) mismatches.push(`chainParams: expected an object, got ${describe(chainParams)}`);
  if (!envOk || !chainOk) return mismatches;

  for (const key of TIMELINE_PARAM_KEYS) {
    const e = envParams[key];
    const c = chainParams[key];
    // 秒単位の値。START_TIME は epoch 秒なので 0 以上、期間も 0 以上。
    const eBad = !isNonNegFinite(e);
    const cBad = !isNonNegFinite(c);
    if (eBad || cBad) {
      mismatches.push(
        `${key}: missing or invalid (env=${describe(e)} chain=${describe(c)}) — ` +
        `both sides must be finite non-negative numbers of seconds`
      );
      continue;
    }
    if (e !== c) {
      mismatches.push(`${key}: env=${e}s chain=${c}s`);
    }
  }
  return mismatches;
}

// env 計算の宣言タイムライン（ms）と契約の窓（秒）の対応3点を比較し、不一致の説明を返す（空配列＝一致）。
//   chatOpenAt    = entryEnd（grace 非依存＝許容包絡の始点）
//   chatCloseAt   = submittingStart（grace 込み）
//   resultCloseAt = closeAt
//【副検査】ワーカー転記式と契約式のドリフト検出用アサート（パラメータ一致⇒3点一致は Lean check_sound）。
// grace は呼び出し側が同一スナップショットの値で declared を組むため両辺で構成上同一。
// 秒単位の丸め比較（env は ms・契約は秒。sub-second 差は宣言窓に実害がないため許容）。
// ④（2026-08-07）: declared / chain が欠けている場合に `undefined !== undefined` で
// 「一致」と報告してしまう穴は、こちらにも同じ形で存在した。両側とも有限値であることを先に見る。
export function compareDeclaredToChainWindows(declared, chain) {
  const mismatches = [];
  const dOk = declared !== null && typeof declared === 'object';
  const cOk = chain !== null && typeof chain === 'object';
  if (!dOk) mismatches.push(`declared: expected an object, got ${describe(declared)}`);
  if (!cOk) mismatches.push(`chain: expected an object, got ${describe(chain)}`);
  if (!dOk || !cOk) return mismatches;

  const srcKeys = { chatOpenAt: 'entryEndMs', chatCloseAt: 'submittingStart', resultCloseAt: 'closeAt' };
  for (const [key, src] of Object.entries(srcKeys)) {
    const ms = declared[src];
    const c = chain[key];
    if (!Number.isFinite(ms) || !Number.isFinite(c)) {
      mismatches.push(
        `${key}: missing or invalid (declared.${src}=${describe(ms)} chain=${describe(c)}) — ` +
        `both sides must be finite numbers`
      );
      continue;
    }
    const e = Math.round(ms / 1000);
    if (e !== c) {
      mismatches.push(`${key}: env=${e} chain=${c} (env-chain=${e - c}s)`);
    }
  }
  return mismatches;
}

// ============================================================
// チェーン窓からのフェーズ判定（K-S6-006・2026-07-29）
// ============================================================
// 「いま何期間か」は**チェーンの窓だけ**から決める。運営サーバーの申告は使わない。
//
// 動機: 本体アプリはチャット開始までしかチェーンを読まず、`init_response` が届いた瞬間に
// サーバーの `phase` へ全面的に従っていた。運営は**標的の接続にだけ**「もう提出期間です」と
// 返すだけで、標的の画面をチャット画面から提出画面へ移し、残りのチャット期間の発言・投票・
// 密告を封じて min_chars / min_messages / no_vote 失格へ誘導できた。
// WS の phase には運営署名もオンチェーン記録も無いため、標的が録画しても第三者に証明できず、
// buildHash は「正しいクライアントを配ったこと」しか縛らない（接続ごとの応答は縛れない）。
//
// 復元クライアント（chatgame-tools）は最初からこの判定を使っていた。本体が採り入れていな
// かっただけなので、実装をここ（両ツールが vendor する正典）へ移して共有する。
//
//   entry      : now < chatOpenAt（応募終了前・grace非依存の下限）
//   waiting    : [chatOpenAt, chattingStart)   グループ分け〜宣言チャット開始
//   chatting   : [chattingStart, chatCloseAt)  chattingStart = chatCloseAt − GAME_PERIOD（grace追従）
//   submitting : [resultOpenAt, resultCloseAt)
//   completed  : now ≥ resultCloseAt
export function derivePhaseFromWindows(nowMs, t) {
  if (!t) return null;
  // 🔴 P-2026-0817（2026-08-07）: **4境界すべてが有限であることを先に要求する。**
  //    旧実装は `<` 比較だけで、**NaN 比較は常に false** なので最終行の
  //    `return 'completed'` に落ちていた（fail-open）。実測:
  //      全境界 NaN      → 'completed'
  //      全境界 undefined → 'completed'
  //    このモジュールは K-S6-006（運営がフェーズを詐称して標的を提出画面へ飛ばし、
  //    `min_chars` / `no_vote` 失格へ誘導する）を封じるために作られたもので、
  //    **同じ結果を別経路で再現できていた**。到達経路は
  //    `src/utils/evidence.js` の `readGameTimeline` が `Number(win[1])` を無検証で返し、
  //    `mergeChainWindows` の `!prev` 分岐（初回）が NaN 込みのオブジェクトを
  //    そのまま採用するところ。
  //    ⚠️ `null` を返すと呼び出し側（公式の画面）はフェーズ未確定として待ち、サーバー申告へは縮退しない（＝「読めない」経路・S3R5-U-R03-PHASE）。
  //       これは「チェーンが読めないときの既存の扱い」と同じで、偽の 'completed' より安全。
  if (!Number.isFinite(nowMs)) return null;
  for (const k of ['chatOpenAt', 'chattingStart', 'chatCloseAt', 'resultCloseAt']) {
    if (!Number.isFinite(t[k])) return null;
  }
  if (nowMs < t.chatOpenAt) return 'entry';
  if (nowMs < t.chattingStart) return 'waiting';
  if (nowMs < t.chatCloseAt) return 'chatting';
  if (nowMs < t.resultCloseAt) return 'submitting';
  return 'completed';
}

// チェーン窓のマージ（K-S6-006）。extendGrace は**後ろにしか動かない**ので、
// 「より後ろへ延びる更新だけを受け入れる」ことで、
//   ・RPC が一時的に読めない間も直近の窓を使い続けられる（サーバー申告へ落ちない）
//   ・運営が正当に延長したときは追随できる（古い窓で締め切る誤動作を防ぐ）
// の両方を満たす。前へ巻き戻す更新は無視する（延長の取り消しは契約上できない）。
export function mergeChainWindows(prev, next) {
  if (!next) return prev || null;
  // 🔴 P-2026-0817: 初回（`prev` が無い）でも**非有限な窓は採用しない**。
  //    旧実装は `if (!prev) return next` で NaN 込みのオブジェクトをそのまま通しており、
  //    それが `derivePhaseFromWindows` の fail-open への入口になっていた。
  const finite = (o) => o && ['chatOpenAt', 'chattingStart', 'chatCloseAt', 'resultCloseAt']
    .every((k) => Number.isFinite(o[k]));
  if (!prev) return finite(next) ? next : null;
  const later = (a, b) => (Number.isFinite(b) && (!Number.isFinite(a) || b > a) ? b : a);
  const merged = {
    ...next,
    chatOpenAt: later(prev.chatOpenAt, next.chatOpenAt),
    chattingStart: later(prev.chattingStart, next.chattingStart),
    chatCloseAt: later(prev.chatCloseAt, next.chatCloseAt),
    resultOpenAt: later(prev.resultOpenAt, next.resultOpenAt),
    resultCloseAt: later(prev.resultCloseAt, next.resultCloseAt),
  };
  return ['chatOpenAt', 'chattingStart', 'chatCloseAt', 'resultOpenAt', 'resultCloseAt']
    .every((key) => Object.is(merged[key], prev[key])) ? prev : merged;
}

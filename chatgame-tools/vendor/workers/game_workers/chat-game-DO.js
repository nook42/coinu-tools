// workers/game_workers/chat-game-DO.js
// Hibernation APIを使用したWebSocketチャットDurable Object
// 各グループ（4人）のチャットゲームのライフサイクルを管理する。

import { countHalfWidthChars, stripInvisibleChars, requireIntEnv, normalizeChatCaps, assertGuestPinnedRules } from './lib/char-counter.js';
import { createCORSResponse } from '../auth_workers/lib/cors.js';
import {
  acknowledgeObservationWriteFailures,
  carryObservationWriteFailures,
  createObservationWriteFailureCounter,
  observationWriteFailureFields,
  recordObservationWriteFailure,
} from './lib/observation-write-failures.js';
import { requireBinding, internalRequest, authWorkerBinding } from './lib/service-binding.js';
import { verifyMessage, keccak256, stringToHex } from 'viem';
import {
  chatSignStringV2, actionSignStringV2, actionHashV2,
  receiptSignString, readReceiptSignString,
  isReceiptTimely, RECEIPT_FRESH_WINDOW_MS, IDLE_TIMEOUT_MS,
  isMsgRef, isActionHash, receiptBundleCap, receiptMaxRefsPerReceipt, messageBundleCap,
  MAX_OBSERVED_ACTIONS_PER_ACTOR,
  receiptMaxActionsPerPair,
  msgRefOf, computeMsgKeyV2, compareHexAsc,
  // D-1（2026-08-07）: 提出ゲートの述語は採点本体と同じものを import する
  // （`!submittedAt` のような truthy 判定を各所で書き直さないこと）
  isCanonicalTimestamp, isCanonicalDepositIds, isOpaqueField,
  // 🔴 P-2026-0842（2026-08-08）: 投票・密告の暗号文長は**ライブ層でも**採点と同じ述語で
  //    課す（入れないと「DO は ack を返すのに採点で消える」遅延失敗になる）。
  isCanonicalActionCiphertext,
  // 🔴 P-2026-0836（ラウンド19 判断不要-2）: ライブ層でも署名の正準性（形式＋low-s）を
  //    課す。⚠️ 提出物の**外側ウォレット署名**（`handleWsSubmit`）は
  //    `isRepresentableSignature`（low-s なし）のまま。J-16（2026-08-08・ユーザー確定）の
  //    恒久原則「制御できる signKey 署名には厳格に、制御できない wallet 署名には寛容に」により、
  //    この2述語は一本化しない。
  isCanonicalSignature,
  // 修正C（P-2026-0828）: `messages` の要素述語も採点本体と同じものを import する
  isCanonicalUid, isCanonicalText,
  // 🔴 P-2026-0829（2026-08-07）: 採点本体にしかなかった門番を**入口にも**置く。
  //    `canonMetaInt` は保存前に（遅延 park の解消）、`parseBlockAddress` は
  //    生の `JSON.parse(member.bAddr)` の置き換え（`Internal error` と roster 全損の解消）。
  canonMetaInt, parseBlockAddress,
  // 🔴 J-33 案D / J-12 案A3（2026-08-08）: ②.6 の原像を1通りに固定する門番。
  //    ライブ層でも同じ述語を課す（入れないと「WS は受け取るのに採点で丸ごと無視される」
  //    遅延失敗になり、原因が本人に分からない）。
  isCanonicalActionPreimage, actionSectionKeysAreMembers
} from './lib/protocol-v2.js';
// 🔴 P-2026-0830（2026-08-08）: 提出の**完全検証**（検証①外側ウォレット署名／②.5 chatHash
//    再計算／②.6 スナップショット再計算）は Evidence 経路と**同じ関数**を呼ぶ。
//    写経すると実装が3つに増え、必ずどれか1つが取り残される（本プロジェクト最頻の失敗形）。
import { verifyBundleCore } from './lib/evidence-reconciler.js';
// 🔴 P-2026-0831（2026-08-08）: **輸送の直列化も深さに依存させない。**
//    非再帰の直列化は正典（`game-result-calculator.js`）に既にあるものを**使い回す**。
//    写経すると実装が増え、必ずどれか1つが取り残される（本プロジェクト最頻の失敗形）。
import { iterativeJsonStringify, actionSnapshotPreimage } from './lib/game-result-calculator.js';
import { canonicalRosterText } from './lib/roster-canonical.js';
import { isReactionShape, mergeReactionInto, pickReaction } from './lib/reaction.js';
import {
  compactPayloadToBytes,
  decodeEvidenceCompactV1,
  decodeSubmissionPayloadString,
  isEvidenceCompactPayload,
} from './lib/evidence-compact-v1.js';
import {
  MAX_ACTION_CANDIDATES_PER_TYPE_PER_ACTOR, MAX_RECEIPT_FACTS,
  SERVER_MAX_WIRE_BYTES,
  validateSubmissionStructure,
} from './lib/submission-limits.js';

// D-02: 発信件数の上限は submission-limits.js と共有する。

const sameStringArray = (a, b) => Array.isArray(a) && Array.isArray(b)
  && a.length === b.length && a.every((value, index) => value === b[index]);

// S3-013: グループ名簿の同一性ハッシュ。GameMasterDO 側と**同じ式**で計算すること
// （uid を文字列化 → 重複排除 → 昇順 → '|' 連結 → keccak256）。
// 順序ゆらぎ・型ゆらぎを吸収し、メンバー集合が同じなら必ず同じ値になる。
export function rosterHashOfMembers(members) {
  const uids = [...new Set((Array.isArray(members) ? members : [])
    .map(m => (m && m.uid != null) ? String(m.uid) : null)
    .filter(Boolean))].sort();
  return keccak256(stringToHex(uids.join('|')));
}

// G4是正（2026-07-19）: メンバーによるWSスパム連打対策。
// WS接続はメンバー限定＋認証済みだが、接続後の「無効署名」「上限/重複を超えた再送」には
// 上限が無く、毎回の署名検証（重いECDSA）等でグループDOのCPUを浪費できた（自グループDoS）。
// 対策: 無駄打ちを接続ごとの連打カウンタ（strike）で数え、WS_STRIKE_MAX超で1008切断。
// スパム切断が窓内WS_STRIKE_CLOSE_MAX回に達したuidは接続自体を拒否（429）。
// ping含む全メッセージにはWS_TOTAL_MSG_MAXの粗い総量キャップ。
// すべてDOメモリのみ（ストレージ書き込みなし）。正規クライアントは無効署名を出さず、
// 再送も連打枠に収まるため挙動変化ゼロ。切断されても自動再接続（要再認証）で復帰できる。
const WS_STRIKE_MAX = 10;                         // 連打カウンタ上限（超えたら切断）
const WS_TOTAL_MSG_MAX = 10000;                   // 1接続の総メッセージ上限（2026-11-19 5,000→10,000: チャット＋提出の48h正規≈ping5,760+在席1,440+発言・既読ほか≈8,200）
const WS_STRIKE_CLOSE_WINDOW_MS = 10 * 60 * 1000; // スパム切断履歴の窓（10分）
const WS_STRIKE_CLOSE_MAX = 3;                    // 窓内スパム切断回数 → 以後は接続拒否（窓経過で自動解除）
const WS_FREE_AVAILABILITY = 10;                  // set_availability の無料枠/接続（予定変更は正規でも数回ある）
const WS_FREE_PRESENCE = 120;                     // set_presence の回復する枠/接続の容量（2分ごとの合図＋10分ごとの往復に余裕）
const WS_PRESENCE_REFILL_MS = 30000;              // 30秒に1つ回復（端数の時間は持ち越す・容量で頭打ち）
const PRESENCE_RELAY_MIN_MS = 60000;              // 同じuidの不変activeを配る最短間隔（状態変化は即配信）
// 便 LIKE（2026-11-26）: 発言へのいいね（表示だけ・採点に無関係）。押す・外すの連打は回復する枠で制限し、枠の外は黙って捨てる。
const WS_FREE_REACTIONS = 60;                      // reaction（いいね）の回復する枠/接続の容量
const WS_REACTION_REFILL_MS = 2000;                // 2秒に1つ回復
const WS_REACTION_DROPS_PER_STRIKE = 20;           // 枠の外で捨てた reaction 20件ごとに連打の数えを1つ
const REACTION_TIME_SLACK_MS = 24 * 60 * 60 * 1000; // 押した人の時計とサーバーの時計の差の許容（表示だけなので広く）
const WS_FREE_RECEIPTS = 600;                     // 受領証明の無料枠/接続（既読バッチ＋action受領。正規≈メッセージ数以下）
// R33-F-1-01（ユーザー決定 D-12・2026-09-27）: WS の接続本数に uid ごとの上限を置き、プレイヤーを優先する。
// 名簿のメンバーは自分の session token だけで接続を何本でも張れた（探針: 同じ uid・同じ token の300本が
// どのフェーズでも受理）。1本ごとに storage・auth・broadcast（全ソケットの走査）の費用が掛かり、
// 張り終えるまでの合計は本数の2乗になる。OPEN の上限では本人の最も古い OPEN を閉じて受け付ける。
// ただし Cloudflare の close() は Close フレームを送るだけで、1本だけを強制切断する API は無い。
// 相手が Close に応えないと CLOSING のまま getWebSockets() に残るため、合計にも別の上限を置く。
// 4 の理由: 正直な同時使用の最大を「PC と電話の2台 ＋ 各1本の閉じ切っていない古い接続（回線の切替・
// 半開き）」と見た。公式クライアントは張り直す前に自分の古い接続を閉じるので1タブは通常1本、
// 復元クライアントは DO の WS を使わない。4本を超えたら最も古い OPEN を閉じる。
// CLOSING は残りうるが、その接続からのメッセージは入口で捨てる。
export const WS_MAX_SOCKETS_PER_UID = 4;
// OPEN 4本に、回線切替で切断検出まで残る古い接続12本の余裕を足す。合計が16本なら新規を429で断る。
// 正直な利用者がこの制限に届くのは、応えない古い接続を12本以上ためた場合。
// 認証後に accept した接続だけが数を増やせるので、他人がその uid の枠を消費できない。
// 組の接続は最大「名簿の人数 × 16」本。
export const WS_MAX_TOTAL_SOCKETS_PER_UID = 16;
// 閉じる接続へ送る close code（4000〜4999 はアプリ用）。公式クライアント（useGameWebSocket.js の同名定数・
// 値の一致は block-verifier/test/g4-ws-abuse-unit.mjs が固定）は、この code で閉じられたら自動で張り直さない
// （張り直すと同じ人の別のタブ・端末を追い出し返し、互いを追い出し続ける）。
export const WS_CLOSE_SUPERSEDED = 4001;
const WS_CLOSE_SUPERSEDED_REASON = 'superseded';
// 2026-11-26（本番の保守の依頼・ユーザーの決め「では直しましょう。」・便 DOMOVED）: Cloudflare が DO を別の機械へ移した後も、
// 古い実体につながったままの WS が残ると、届くものが storage に触るたびに「cannot access storage because object has moved to
// a different machine」で失敗し続けた（`Internal error` を返すだけで閉じないので、クライアントは張り直さなかった・本番の
// wrangler tail で 30 秒〈ping の間隔〉ごと）。この誤りのときだけ、その WS を閉じて張り直させる（公式クライアントは
// 4001 以外の close で張り直す・新しい接続は新しい実体へ行く）。ほかの誤りでは閉じない（張り直しの繰り返しを招かない）。
// 閉じた後の webSocketClose は storage に触らない。code はアプリ用の 4012（1012 は WHATWG の決まりでは close に使えず、
// 実行環境の互換の設定しだいで拒まれうる・反証 DM-R02）。ping 以外の発信（提出など）には、閉じる前に今までどおり
// Internal error を返す（拒否を黙って落とさない・反証 DM-R01）。閉じられなければ今までどおり Internal error だけを返す。
export const WS_CLOSE_OBJECT_MOVED = 4012;
const WS_CLOSE_OBJECT_MOVED_REASON = 'object moved';
export function isObjectMovedError(error) {
  const text = typeof error === 'string' ? error : (typeof error?.message === 'string' ? error.message : '');
  return /object has moved to a different machine/i.test(text);
}
// 同じ uid の upgrade の頻度の上限。本数の上限の下でも upgrade を連打すると、1本ごとの auth の
// Service Binding・storage・broadcast の費用が続く。**認証に通った** upgrade を uid ごとに数え、窓の中で
// 上限に達したら auth の前と後（accept 前の同期区間）で 429 を返す。accept・storage・broadcast・
// supersede は accept した接続について窓あたり120回まで。auth 前の storage 読みは抑えない
// （invalidatedNoGame は毎回、members は同時に送った本数分）。同時送信中の auth 呼び出しも抑えない。
// token が通らない upgrade も従来どおり毎回 auth を呼ぶが、本人の窓は埋めない。
// 120/分 の理由: 公式クライアントの最短のつなぎ直し（backoff 3秒・開いたら0に戻る）で 4 タブが同時に
// 張り直し続けても 4 × 20 = 80/分。これに5割の余裕を足した。DO メモリのみ（G4 と同じくベストエフォート）。
export const WS_UPGRADE_RATE_WINDOW_MS = 60 * 1000;
export const WS_UPGRADE_RATE_MAX = 120;
// accept の順（最も古い接続の特定）を hibernation を越えて保つための2つ目のタグ（先頭タグは従来どおり uid）。
// 空白は uid の許可アルファベット（isCanonicalUid の \x21-\x7E）の外なので、uid のタグと衝突しない。
const WS_ACCEPT_TAG_PREFIX = 'ws-accepted ';
const WS_READY_STATE_OPEN = 1;

// accept の順を2つ目のタグから読む（[時刻ms, 連番]）。タグの無い接続は最も古いとみなす。
function wsAcceptOrderOf(tags) {
  const tag = Array.isArray(tags) && typeof tags[1] === 'string' && tags[1].startsWith(WS_ACCEPT_TAG_PREFIX)
    ? tags[1] : null;
  if (!tag) return [-1, -1];
  const [ms, seq] = tag.slice(WS_ACCEPT_TAG_PREFIX.length).split(' ').map(Number);
  return [Number.isFinite(ms) ? ms : -1, Number.isFinite(seq) ? seq : -1];
}
// RT3-01: 既読の distinct 枠とは別に、保存する msgRefs の延べ量をペアごとに縛る。
// 採点正典の receiptMaxRefsPerReceipt は変更せず、DO の保存量だけに K=3 の余裕を持たせる。
const RECEIPT_PAIR_RAW_REF_FACTOR = 3;
const RECEIPT_QUOTA_DUPLICATE = 'duplicate';

// Z2是正: DOストレージ1値上限(128KiB=131,072B)に対する安全域（キー分割ヘルパー用）
const VALUE_SAFE_BYTES = 100000;   // 単一値のまま保存してよい上限
const CHUNK_TARGET_BYTES = 96000;  // 分割チャンク1個の目標上限
// G7是正（2026-07-18）: 観戦のライブ配信はWSではなくR2スナップショット（CDNポーリング）。
// チャット着信はこの間隔で間引いて live/block{N}/group{G}.json を更新する
// （フェーズ遷移・初期化時は即時公開）。
const LIVE_SNAPSHOT_DEBOUNCE_MS = 30000;
const LIVE_SNAPSHOT_ALARM_KEY = 'live_snapshot_alarm';
const SUBMISSION_SNAPSHOT_ALARM_KEY = 'live_submissions_snapshot_alarm';
const SUBMISSION_SNAPSHOT_FINAL_STATUS_KEY = 'submissionSnapshotFinalStatus';
const INVALIDATED_NO_GAME_KEY = 'invalidatedNoGame';
// 便 PLAYAT 反証 PA-R02（2026-11-25）: 先に設定した参加予定時刻（/seed-availability）が、待機中の
// 宣言のチャット開始より前のとき、「開始から参加」と読んで開始時刻へ寄せてよい幅。
// 値はエントリーの時（古い開始の見込み）に入れるので、その後に grace が延長されると新しい開始より
// 前になる。grace の延長の上限は BLOCK_TIME（本番4日）で、それより前の値はこのブロックの窓の値として
// 説明できないので入れない（余裕を見て8日）。
const AVAILABILITY_SEED_CLAMP_REACH_MS = 8 * 24 * 60 * 60 * 1000;

// A3-12 / A3-8（2026-08-24）: ChatGameDO の永続観測。
// 履歴配列は持たず、飽和カウンタ＋最終状態／最終失敗だけを保存するため際限なく育たない。
// `state.waitUntil()` へ渡す直列キューで本来の応答を待たせず、観測ストレージが失敗しても
// メモリ上の fallback を `/status` から読めるようにして本処理へ例外を返さない。
const CHAT_OBSERVABILITY_KEY = 'chatObservability:v1';
const OBSERVABILITY_VERSION = 1;
const OBSERVABILITY_ERROR_MAX_CHARS = 500;
const COUNTER_MAX = Number.MAX_SAFE_INTEGER;

const observationNow = () => new Date().toISOString();
const boundedCounterInc = (value) => Math.min(COUNTER_MAX, (Number.isSafeInteger(value) && value >= 0 ? value : 0) + 1);

// 公開HTTP制御面の認証台帳。ルーターとテストが同じ現物から導出し、片側だけの追加を許さない。
export const CHAT_HTTP_AUTH_METHODS = Object.freeze({
  '/init': 'POST',
  '/republish-roster': 'POST',
  '/set-phase': 'POST',
  '/get-results': 'GET',
  '/reset': 'DELETE',
  '/invalidate-no-game': 'POST',
  '/debug-submission': 'POST',
  '/cleanup': 'POST',
  // 便 PLAYAT（2026-11-25）: 先に設定した参加予定時刻の受け取り口。グループのメンバーにだけ見せる値を
  // 保存して全員へ配る口なので、GameMasterDO 以外から呼べないようにする。
  '/seed-availability': 'POST',
});
const CHAT_HTTP_AUTH_PATHS = new Set(Object.keys(CHAT_HTTP_AUTH_METHODS));
const boundedError = (error) => String(error?.message || error || 'unknown error')
  .replace(/Bearer\s+[^\s,;]+/gi, 'Bearer [redacted]')
  .replace(/([?&](?:token|secret|key)=)[^&\s]+/gi, '$1[redacted]')
  .slice(0, OBSERVABILITY_ERROR_MAX_CHARS);

const emptyOutcome = () => ({
  state: 'not_attempted',
  attemptCount: 0,
  successCount: 0,
  failureCount: 0,
  lastStatus: null,
  lastFailure: null,
});

const emptyChatObservability = () => ({
  version: OBSERVABILITY_VERSION,
  observationWriteFailures: 0,
  observationWriteFailureReason: null,
  auth: emptyOutcome(),
  dependency: emptyOutcome(),
  storage: emptyOutcome(),
  phaseEndTime: {
    state: 'not_attempted',
    lastStatus: null,
  },
  persistence: {
    failureCount: 0,
    lastFailure: null,
  },
});

const normalizeOutcome = (stored) => ({ ...emptyOutcome(), ...(stored && typeof stored === 'object' ? stored : {}) });
const normalizeChatObservability = (stored) => {
  const base = emptyChatObservability();
  if (!stored || typeof stored !== 'object') return base;
  return {
    ...base,
    ...stored,
    version: OBSERVABILITY_VERSION,
    auth: normalizeOutcome(stored.auth),
    dependency: normalizeOutcome(stored.dependency),
    storage: normalizeOutcome(stored.storage),
    phaseEndTime: { ...base.phaseEndTime, ...(stored.phaseEndTime || {}) },
    persistence: { ...base.persistence, ...(stored.persistence || {}) },
  };
};

const applyOutcome = (outcome, state, status) => {
  outcome.state = state;
  outcome.attemptCount = boundedCounterInc(outcome.attemptCount);
  if (state === 'succeeded') outcome.successCount = boundedCounterInc(outcome.successCount);
  if (state === 'failed') outcome.failureCount = boundedCounterInc(outcome.failureCount);
  outcome.lastStatus = status;
  if (state === 'failed') outcome.lastFailure = status;
};
// 🔴 P-2026-0827（2026-08-08）: **サイズ見積もりは例外を投げてはいけない → `Infinity` に倒す。**
//   `JSON.stringify` は再帰なので、Node v22 では**深さ 6,842 で
//   `RangeError: Maximum call stack size exceeded`**（実測・二分探索）を投げる。
//   一方 `JSON.parse` は非再帰で深さ 1,000,000 まで通るので、提出バンドルの
//   `encryptedActions`（`encryptedDataHash` のプリイメージ＝中身の形は誰も検査していない）に
//   `{"votes":{"a":{"a":{…}}}}` を積めば、この見積もりだけで例外が飛ぶ。
//   ここは「分割するか／raw へ委譲するか」を決める早期フィードバックなので、
//   測れないものは **「大きすぎる」に倒す**のが安全側（＝分割・raw 委譲の経路へ落ちる）。
//   例外にすると提出が 'Internal error' になり、後段（採点本体）が
//   `snapshot_mismatch` で完走できるはずの入力を保存すらできない。
const jsonBytes = (v) => {
  try {
    return new TextEncoder().encode(typeof v === 'string' ? v : JSON.stringify(v)).length;
  } catch { return Infinity; }
};

// 2026-08-03 修正（block27 実障害）: DOストレージの値サイズは **UTF-8 バイト数ではない**。
// V8 の直列化は JS 文字列を「Latin-1 だけなら 1バイト/文字、非Latin-1 を1文字でも含むと
// 2バイト/コードユニット」で書く。つまり日本語チャットを含む提出バンドルは
// UTF-8 で 87KB でも実際には約 164KB を占め、128KiB/値 の上限を超えて put が例外を投げる。
// jsonBytes（UTF-8）で分割要否を判定していたため、日本語のグループは提出が丸ごと保存できず
// （submit_ack も返らず）、後段の採点が parsed/raw 不整合で fail-closed していた。
// 分割判定には必ずこちら（最悪ケース見積もり）を使う。
// 🔴 P-2026-0827: `jsonBytes` と同じ理由で **例外を投げず `Infinity`**（上のコメント参照）。
//   実測: 深さ 7,000 の `encryptedActions` を載せた提出で、旧実装は
//   `storeSubmissionBundle` / metaBytes の両方で RangeError を投げた。
//   `Infinity` なら「単一値に収まらない」判定になり `_fromRaw` 委譲の経路へ落ちる
//   （raw は文字列なので `.length` に再帰は無い＝必ず保存できる）。
const storageBytes = (v) => {
  try {
    return (typeof v === 'string' ? v : JSON.stringify(v)).length * 2;
  } catch { return Infinity; }
};

// ============================================================
// 🔴 P-2026-0831（2026-08-08）: **輸送の直列化は深さに依存してはいけない。**
// ============================================================
// P-2026-0827 は「見積もり（`jsonBytes` / `storageBytes`）」と「②.6 のプリイメージ」を
// 深さ非依存にしたが、**保存したあとの輸送**が1本残っていた。
//
//   ・`handleGetResults` … `createCORSResponse(オブジェクト)` の中で
//     `JSON.stringify(response)`（`auth_workers/lib/cors.js`・**再帰**）が走る
//   ・`archiveGameData`  … `JSON.stringify(archiveData)`
//   ・`publishLiveSnapshot` / `handleInit` の roster 公開 … 同上
//
// 深い入れ子の `encryptedActions` を持つ提出は `storeSubmissionBundle` が
// **raw 委譲（`_fromRaw`）**で保存する（raw は文字列なので必ず書ける）。
// ところが `loadSubmission` は読み出し時に `JSON.parse(raw)` で**木を作り直す**ので、
// 深い木は `/get-results` の応答生成でだけ実体化する。実測（本物のハンドラ）:
//   深さ 6,102 → `submit_ack` / `handleGetResults` 正常
//   深さ 6,103 → `submit_ack`（エラー無し）なのに `handleGetResults` が `RangeError`
// `fetch` に try が無いので 500 → `game-master-DO.js` の `[calc] get-results returned …` →
// K-S2-004 のリトライ（15秒→10分・20回）→ **park**。入力は DO ストレージに固定されており、
// `/reset-block` も `unpark` も同じ壁に当たる（`/debug-submission` と `/reset` は
// `RELEASE_TIME` ガードで本番リリース後は呼べない）。攻撃コストは認証済み WS 1通。
// `archiveGameData` 側は例外が握られるので park はしないが、
// `games/block{N}/group{g}.json` が**無言で欠落**し block-verifier の Stage C が落ちる。
//
// # 直し方
// `JSON.stringify` を**まず素直に呼ぶ**（既存の応答は1バイトも動かない）。
// V8 の再帰が尽きたときだけ、正典の**非再帰実装**（`iterativeJsonStringify`）で作り直す。
// 出力はバイト同一なので、受信側（`deriveSubmissionsFromRaw` のバイト照合・block-verifier）の
// 前提は何も変わらない。
//
// ⚠️ 例外を握って空応答に倒してはいけない。採点入力そのものが消え、
//    「park は消えたが全員 `no_submit`」というより静かな全損に置き換わる。
const safeJsonStringify = (v) => {
  try { return JSON.stringify(v); }
  catch { return iterativeJsonStringify(v); }
};

const sha256Hex = async (text) => {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
};

// `createCORSResponse` に**すでに直列化済みの `Response`** を渡すための薄いラッパ。
// `createCORSResponse` は `response instanceof Response` を素通し（ヘッダーに CORS を足すだけ）
// するので、採点外の全ワーカーが共有する `auth_workers/lib/cors.js` に手を入れずに済む。
// ⚠️ `Content-Type` は**内側の Response** に付ける（外側は headers を引き継ぐだけ）。
const corsJsonResponse = (body, status = 200) => createCORSResponse(new Response(
  safeJsonStringify(body),
  { status, headers: { 'Content-Type': 'application/json' } }
));

// ============================================================
// 🔴 P-2026-0823（2026-08-07）: uid 鍵の辞書は **プロトタイプ鎖を持たせない**
// ============================================================
// `isCanonicalUid` は `/^[\x21-\x7E]+$/` を許す（将来の匿名エントリー用の意図的な広さ）。
// uid を割り当てるのは運営なので、`__proto__` / `toString` / `constructor` / `valueOf` /
// `hasOwnProperty` は**運営が任意の参加者に付けられる値**とみなす必要がある。
// 素の `{}` を uid で添字にすると値の型ごとに別々の壊れ方をする:
//   ・値がオブジェクト（署名済み発信）→ `m['__proto__'] = v` は own property に
//     ならず、`JSON.stringify` にも V8 直列化にも乗らない＝**その人の発信が誰にも届かない**
//     （＝受領証明がもらえず void ＝ `no_vote` 失格）
//   ・値が数値（文字数・件数）→ 代入が黙って捨てられ、読み返すと `Object.prototype` が
//     返る。`(charCounts[uid] || 0) + n > this.maxChars` は文字列比較になって **false**
//     ＝ P-2026-0821 で塞いだ「上限が消える」状態がこの uid でだけ復活する
//   ・読み出しが `!m[uid]` → Object.prototype のメソッド（truthy）で分岐を誤る
// DO storage（V8 直列化）は own の `__proto__` を own property のまま往復させるので、
// 作る側が `Object.create(null)` なら保存・復元しても壊れない。
// 既存レコード（是正前に書かれたもの）のために**読み出し側でも**正規化する。
const uidMap = (stored) => Object.assign(Object.create(null), stored);

// 🔴 P-2026-0835（2026-08-08・ラウンド19 判断不要-1）: keyed セクションを
//    `Object.entries` で回さないための空セクション。詳細は
//    `lib/game-result-calculator.js` の `keyedSection` のコメント。
const EMPTY_SECTION = Object.freeze(Object.create(null));

// 🔴 P-2026-0841（2026-08-08・ラウンド19 判断不要-9）: DO ストレージの分割キー区切り。
//    `isCanonicalUid` の許可アルファベット `/^[\x21-\x7E]+$/` の**外**の文字を使う
//    （`game-result-calculator.js` の `KEY_SEP = '\x1f'` と同じ発想）。
//    `:` は許可アルファベットの中にあるので `submissions_raw:{uid}` と
//    `submissions_raw:{uid}:{NNN}` が uid について prefix-free にならない。
const GameChunkKeys = Object.freeze({ SEP: '\u0001' });

// auth workerのシャード番号をユーザーIDから算出（useXAuth.jsのgetWorkerNumberと同一ロジック）
function getAuthWorkerNumber(userId) {
  if (!userId) return 0;
  const lastFourDigits = userId.slice(-4).padStart(4, '0');
  return parseInt(lastFourDigits.slice(0, 2), 10);
}

export class ChatGameDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.storage = state.storage;
    // ============================================================
    // P-2026-0821（2026-08-07）: ライブ上限は **fail-closed** で読む
    // ============================================================
    // 🔴 旧実装は `env.X ? parseInt(env.X) : 既定値` で、`parseInt` の結果を検査していなかった。
    //    `GAME_MAX_MESSAGES` に全角数字・空白・単位付き文字列が入ると **NaN** になり、
    //    NaN は比較を両方向とも false にするので **上限がまるごと消える**。実測:
    //      ・`msgChars > this.maxMsgChars` → false（1メッセージの長さ制限が消える）
    //      ・`messageCounts[uid] + 1 > this.maxMessages` → false（件数制限が消える）
    //      ・`charCounts[uid] + msgChars > this.maxChars` → false（総文字数制限が消える）
    //      ・`receiptMaxRefsPerReceipt(NaN)` / `receiptBundleCap(NaN, n)` /
    //        `messageBundleCap(NaN, n)` がすべて NaN ＝ 提出ゲート3本とも素通り
    //    つまり **CPU 枯渇攻撃（P-2026-0814 で塞いだ park 攻撃）の入口がそのまま復活する**。
    //
    // 🔴 既定値へ黙って落とさず throw する（ユーザー確定・2026-08-07）:
    //    しきい値は ZKP ゲスト（crates/scoring-core）に焼かれているので、
    //    黙って既定値に落とすと宣言値と適用値が食い違ったままブロックが1本進む。
    //    **DO が起動しないほうが、上限なしのチャット期間より安全。**
    //    ⚠️ 運用注意: 環境変数を1つ打ち間違えると ChatGameDO が起動しない。
    this.minChars = requireIntEnv('GAME_MIN_CHARS', env.GAME_MIN_CHARS, 500, 0);
    this.minMessages = requireIntEnv('GAME_MIN_MESSAGES', env.GAME_MIN_MESSAGES, 20, 0);
    // チャット量キャップ（Evidence計画 §2.1b）。上限なしだとグループメンバーのスパムで
    // 全員の提出バンドルが肥大化し、オンチェーン証明（MAX_DATA_BYTES）が物理的に不可能になる。
    // calculator の applyChatCaps と同一値・同一規則（manifest rules にアンカーされる）。
    const caps = normalizeChatCaps({
      maxChars: requireIntEnv('GAME_MAX_CHARS', env.GAME_MAX_CHARS, 10000),
      maxMessages: requireIntEnv('GAME_MAX_MESSAGES', env.GAME_MAX_MESSAGES, 100),
      maxMsgChars: requireIntEnv('GAME_MAX_MSG_CHARS', env.GAME_MAX_MSG_CHARS, 1000),
    });
    this.maxChars = caps.maxChars;
    this.maxMessages = caps.maxMessages;
    this.maxMsgChars = caps.maxMsgChars;
    // ChatGameDO は長寿命なので、vars をゲスト定数から動かすと既存個体を含め起動を拒否する。
    // requireIntEnv と同じ fail-closed の運用制約として受け入れ、正規化後の適用値を照合する。
    assertGuestPinnedRules({
      minChars: this.minChars,
      minMessages: this.minMessages,
      maxChars: this.maxChars,
      maxMessages: this.maxMessages,
      maxMsgChars: this.maxMsgChars,
    }, 'ChatGameDO constructor');
    // §2.5 R3 沈静化窓（提出ビュー凍結前にリレー伝播を待つミリ秒）。フロントへ init_response で配信。
    this.quiescenceMs = requireIntEnv('GAME_QUIESCENCE_MS', env.GAME_QUIESCENCE_MS, 10000, 0);
    // G4: 接続ごとの連打カウンタとスパム切断常習uid（DOメモリのみ・hibernation/退避で
    // リセット＝ベストエフォートのレート制限として十分。攻撃者が接続を張り続ける限り
    // DOは起きたままなのでカウンタも生きる）
    this.wsAbuse = new Map();         // ws -> { strikes, total, ops: Map(opKey -> count) }
    // v3.3追補（在席）: メンバーuid -> 最後にWSメッセージを受けた時刻。
    // WS接続が生きていてもタブが凍結/スロットルされたクライアントは何も送ってこないので、
    // 「接続の有無」ではなく「実際に喋っているか（2分ごとのハートビート含む）」で在席を判定する。
    // ソフト状態（DO退避で消えても次のハートビートで復元）なのでstorageには置かない。
    this.memberSeen = new Map();
    this.uidStrikeCloses = new Map(); // uid -> [スパム切断時刻(ms), ...]
    // R33-F-1-01: uid -> 認証に通った upgrade の時刻(ms)の配列（窓の中だけ残す・DOメモリのみ）と、accept の連番
    this.uidUpgradeTimes = new Map();
    this.wsAcceptSeq = 0;
    this.observabilityWriteTail = Promise.resolve();
    // Q25: 同じR2 keyへの途中版・末尾版・completed最終版を開始順に直列化する。
    // R2 put のI/O待ち中に別入力が入っても、古い途中版が最終版の後から完了して
    // 上書きする順序逆転を起こさない。waitUntil中は同じDO個体が保持される。
    this.submissionSnapshotPublishTail = Promise.resolve();
    this.observabilityFallback = null;
    this.observationWriteFailureCounter = createObservationWriteFailureCounter();
  }

  // ---- A3-12 / A3-8: 本処理から分離した永続観測ヘルパー ----
  queueObservabilityUpdate(mutator) {
    const previous = this.observabilityWriteTail || Promise.resolve();
    const task = previous.then(async () => {
      let current;
      try {
        current = this.observabilityFallback
          || normalizeChatObservability(await this.storage.get(CHAT_OBSERVABILITY_KEY));
        mutator(current);
        const pending = carryObservationWriteFailures(
          current,
          this.observationWriteFailureCounter,
        );
        await this.storage.put(CHAT_OBSERVABILITY_KEY, current);
        acknowledgeObservationWriteFailures(this.observationWriteFailureCounter, pending);
        this.observabilityFallback = null;
      } catch (error) {
        current = normalizeChatObservability(current || this.observabilityFallback);
        current.persistence.failureCount = boundedCounterInc(current.persistence.failureCount);
        current.persistence.lastFailure = { state: 'failed', at: observationNow(), error: boundedError(error) };
        this.observabilityFallback = current;
        recordObservationWriteFailure(
          this.observationWriteFailureCounter,
          'chat_observation_write_failed',
        );
        console.error('ChatGameDO observability persistence failed:', boundedError(error));
      }
    });
    this.observabilityWriteTail = task;
    try {
      if (typeof this.state?.waitUntil === 'function') this.state.waitUntil(task);
    } catch (error) {
      const current = normalizeChatObservability(this.observabilityFallback);
      current.persistence.failureCount = boundedCounterInc(current.persistence.failureCount);
      current.persistence.lastFailure = { state: 'failed', at: observationNow(), error: boundedError(error) };
      this.observabilityFallback = current;
      recordObservationWriteFailure(
        this.observationWriteFailureCounter,
        'chat_observation_waituntil_failed',
      );
      console.error('ChatGameDO observability waitUntil failed:', boundedError(error));
    }
    return task;
  }

  recordAuthOutcome(state, detail = {}) {
    const status = { state, at: observationNow(), ...detail };
    return this.queueObservabilityUpdate((observation) => {
      applyOutcome(observation.auth, state, status);
    });
  }

  recordDependencyOutcome(state, dependency, operation, detail = {}) {
    const status = { state, at: observationNow(), dependency, operation, ...detail };
    return this.queueObservabilityUpdate((observation) => {
      applyOutcome(observation.dependency, state, status);
    });
  }

  recordStorageOutcome(state, operation, detail = {}) {
    const status = { state, at: observationNow(), operation, ...detail };
    return this.queueObservabilityUpdate((observation) => {
      applyOutcome(observation.storage, state, status);
    });
  }

  recordPhaseEndTime(phase, phaseEndTime, source, manualFallback) {
    const hasEndTime = Number.isFinite(phaseEndTime) && phaseEndTime > 0;
    const normalizedSource = typeof source === 'string' && source.trim()
      ? source.trim().slice(0, 100)
      : (hasEndTime ? 'caller_provided_legacy' : 'none');
    const normalizedManualFallback = typeof manualFallback === 'boolean'
      ? manualFallback
      : (normalizedSource === 'manual_relative_fallback' ? true : null);
    const status = {
      state: 'succeeded',
      at: observationNow(),
      phase,
      value: hasEndTime ? phaseEndTime : null,
      source: normalizedSource,
      manualFallback: normalizedManualFallback,
    };
    return this.queueObservabilityUpdate((observation) => {
      observation.phaseEndTime = { state: 'succeeded', lastStatus: status };
    });
  }

  async readObservability() {
    let stored = null;
    let readFailure = null;
    try {
      stored = await this.storage.get(CHAT_OBSERVABILITY_KEY);
    } catch (error) {
      readFailure = { state: 'failed', at: observationNow(), error: boundedError(error) };
    }
    const observation = normalizeChatObservability(this.observabilityFallback || stored);
    if (readFailure) observation.persistence = {
      failureCount: boundedCounterInc(observation.persistence.failureCount),
      lastFailure: readFailure,
    };
    return observation;
  }

  // ---- G4: WSスパム連打対策ヘルパー ----
  wsAbuseOf(ws) {
    let a = this.wsAbuse.get(ws);
    if (!a) { a = { strikes: 0, total: 0, ops: new Map() }; this.wsAbuse.set(ws, a); }
    return a;
  }

  // 無駄打ち（無効署名・上限/重複を超えた再送）を1カウント。上限超で切断しtrueを返す
  // （呼び出し元は即return。切断後のsendToはtry/catchで握られるため順序は安全）。
  strikeWs(ws, uid, reason) {
    const a = this.wsAbuseOf(ws);
    a.strikes++;
    if (a.strikes > WS_STRIKE_MAX) {
      console.warn(`WS strike limit exceeded: uid=${uid} reason=${reason} — closing connection`);
      this.noteStrikeClose(uid);
      try { ws.close(1008, 'Too many invalid or redundant requests'); } catch { /* 既閉 */ }
      return true;
    }
    return false;
  }

  // 操作キー（'init'・'receipt' 等）の使用回数を数え、無料枠を超えた分を連打カウント。
  // 枠超過でも操作自体は（切断に至るまで）正規処理を続ける＝上書き再設定等の正規機能は不変。
  strikeIfOverQuota(ws, uid, opKey, freeQuota, reason) {
    const a = this.wsAbuseOf(ws);
    const n = (a.ops.get(opKey) || 0) + 1;
    a.ops.set(opKey, n);
    if (n <= freeQuota) return false;
    return this.strikeWs(ws, uid, reason);
  }

  // presence 専用の時間で戻る枠。wsAbuse と同じ接続単位のメモリだけに置く。
  // 整数個の回復と残り時間を分け、端数を捨てず、長い休止でも容量以上は貯めない。
  // 枠超過時の返り値は従来と同じ（11 strikeで切断するまでは正規処理を続ける）。
  strikeIfOverRefillingQuota(ws, uid, opKey, capacity, refillMs, reason) {
    const a = this.wsAbuseOf(ws);
    const buckets = a.refillingOps ||= new Map();
    const now = Date.now();
    let bucket = buckets.get(opKey);
    if (!bucket) {
      bucket = { tokens: capacity, at: now };
      buckets.set(opKey, bucket);
    }
    const refill = Math.floor(Math.max(0, now - bucket.at) / refillMs);
    if (refill > 0) {
      bucket.tokens = Math.min(capacity, bucket.tokens + refill);
      bucket.at += refill * refillMs;
    }
    if (bucket.tokens > 0) {
      bucket.tokens--;
      return false;
    }
    return this.strikeWs(ws, uid, reason);
  }

  // 便 LIKE: いいね（表示だけ）の時間で戻る枠。枠を超えた分は黙って捨て（真を返す）、連打の数えは
  // 捨てた分の WS_REACTION_DROPS_PER_STRIKE 件ごとに1つだけ足す（正直な画面は枠より遅く送るので、捨てる前に止まる。
  // 押し続けるだけでチャットの接続を閉じさせない・それでも氾濫は最後には閉じる）。
  dropIfOverReactionQuota(ws, uid) {
    const a = this.wsAbuseOf(ws);
    const buckets = a.refillingOps ||= new Map();
    const now = Date.now();
    let bucket = buckets.get('reaction');
    if (!bucket) {
      bucket = { tokens: WS_FREE_REACTIONS, at: now };
      buckets.set('reaction', bucket);
    }
    const refill = Math.floor(Math.max(0, now - bucket.at) / WS_REACTION_REFILL_MS);
    if (refill > 0) {
      bucket.tokens = Math.min(WS_FREE_REACTIONS, bucket.tokens + refill);
      bucket.at += refill * WS_REACTION_REFILL_MS;
    }
    if (bucket.tokens > 0) {
      bucket.tokens--;
      return false;
    }
    a.reactionDrops = (a.reactionDrops || 0) + 1;
    if (a.reactionDrops % WS_REACTION_DROPS_PER_STRIKE === 0) this.strikeWs(ws, uid, 'reaction spam');
    return true;
  }

  noteStrikeClose(uid) {
    if (!uid) return;
    const now = Date.now();
    const arr = (this.uidStrikeCloses.get(uid) || []).filter(t => now - t < WS_STRIKE_CLOSE_WINDOW_MS);
    arr.push(now);
    this.uidStrikeCloses.set(uid, arr);
  }

  isUidStrikeCoolingDown(uid) {
    const now = Date.now();
    const arr = (this.uidStrikeCloses.get(uid) || []).filter(t => now - t < WS_STRIKE_CLOSE_WINDOW_MS);
    this.uidStrikeCloses.set(uid, arr);
    return arr.length >= WS_STRIKE_CLOSE_MAX;
  }

  // ---- R33-F-1-01（D-12）: uid ごとの接続本数の上限と upgrade の頻度 ----
  // 認証に通った upgrade が窓の中で上限に達しているか。認証の前後に読むが、記録の無い uid
  // （名簿の外・まだ認証に通っていない）では何も書かない（任意の uid の文字列で Map を太らせない）。
  isUidUpgradeRateLimited(uid) {
    const arr = this.uidUpgradeTimes.get(uid);
    if (!arr) return false;
    const now = Date.now();
    const recent = arr.filter(t => now - t < WS_UPGRADE_RATE_WINDOW_MS);
    if (recent.length === 0) { this.uidUpgradeTimes.delete(uid); return false; }
    this.uidUpgradeTimes.set(uid, recent);
    return recent.length >= WS_UPGRADE_RATE_MAX;
  }

  noteUidUpgrade(uid) {
    const now = Date.now();
    const arr = (this.uidUpgradeTimes.get(uid) || []).filter(t => now - t < WS_UPGRADE_RATE_WINDOW_MS);
    arr.push(now);
    this.uidUpgradeTimes.set(uid, arr);
  }

  // CLOSING も DO の接続枠に残る。getWebSockets(tag) はタグのどの位置も照合するため、
  // 先頭タグが uid の、readyState が数値かつ CLOSED(3) 以外の接続だけを数える。
  totalSocketsOfUid(uid) {
    let count = 0;
    for (const ws of this.state.getWebSockets(uid)) {
      if (typeof ws?.readyState !== 'number' || ws.readyState === 3) continue;
      if (this.state.getTags(ws)[0] === uid) count++;
    }
    return count;
  }

  // uid の開いている接続を accept の古い順に返す。`getWebSockets(tag)` はどの位置のタグの一致も返すので
  // 先頭タグ（uid）で絞り直す。CLOSING はここでは閉じ直さず、合計の上限に数える。
  openSocketsOfUidOldestFirst(uid) {
    const rows = [];
    for (const ws of this.state.getWebSockets(uid)) {
      if (typeof ws?.readyState === 'number' && ws.readyState !== WS_READY_STATE_OPEN) continue;
      const tags = this.state.getTags(ws);
      if (tags[0] !== uid) continue;
      rows.push({ ws, order: wsAcceptOrderOf(tags) });
    }
    rows.sort((a, b) => (a.order[0] - b.order[0]) || (a.order[1] - b.order[1]));
    return rows.map(row => row.ws);
  }

  // 同じ uid の OPEN が上限に達していたら、最も古い OPEN から閉じる。
  // CLOSING は残りうるので、そのメッセージを入口で捨て、合計16本で新規を断る。
  supersedeOldSocketsOf(uid) {
    const open = this.openSocketsOfUidOldestFirst(uid);
    const excess = open.length - (WS_MAX_SOCKETS_PER_UID - 1);
    for (let i = 0; i < excess; i++) {
      this.wsAbuse.delete(open[i]); // G4: 接続ごとのカウンタ破棄（webSocketClose が来なくても残さない）
      try { open[i].close(WS_CLOSE_SUPERSEDED, WS_CLOSE_SUPERSEDED_REASON); } catch { /* 既閉 */ }
    }
    if (excess > 0) {
      console.log(`WebSocket superseded: uid=${uid} closed=${excess} (limit ${WS_MAX_SOCKETS_PER_UID}/uid)`);
    }
  }

  // 同じ uid の接続が ws のほかにまだ開いているか（在席の表示用）。
  // 閉じる本人は、オブジェクトの同一性に加えて accept のタグでも除く（閉じかけが OPEN に見えても数えない）。
  hasOtherOpenSocketOfUid(uid, ws) {
    const selfAcceptTag = this.state.getTags(ws)?.[1];
    return this.openSocketsOfUidOldestFirst(uid).some(other => other !== ws
      && (typeof selfAcceptTag !== 'string' || this.state.getTags(other)[1] !== selfAcceptTag));
  }

  // このグループのプロトコル版数と署名文脈（blockNum/groupId）。
  // 版数ゲート廃止（2026-07-07）: v1ブロックは存在しない前提＝常に v2。
  async getProtocolContext() {
    const meta = await this.storage.get('meta');
    if (!meta) return { protocolVersion: 2, blockNum: null, groupId: null };
    return { protocolVersion: 2, blockNum: meta.blockNum, groupId: meta.groupId };
  }

  // S3-002: 公開 HTTP 制御面の認証。
  // workers/game_workers/index.js は /chat/{block}/{group}/{endpoint} を「そのままの request」で
  // 決定論的 ID の ChatGameDO へ転送するため、内部呼び出しと外部リクエストが区別できない。
  // GameMasterDO 側は DO binding 経由で X-Api-Secret を必ず付ける（chatDoRequest ヘルパー）。
  // secret 未設定時も fail-closed（GameMasterDO.verifyApiSecret と同じ規則）。
  verifyApiSecret(request) {
    const expected = this.env.API_SECRET;
    if (!expected) return false;
    return request.headers.get('X-Api-Secret') === expected;
  }

  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return createCORSResponse({}, 200);
    }

    // WebSocketアップグレード（認証は handleWebSocketUpgrade 内で
    // roster メンバー + session token + token の user.id 一致の3点照合を行う）
    if (request.headers.get('Upgrade') === 'websocket') {
      return this.handleWebSocketUpgrade(request, url);
    }

    // --- 認証必須の HTTP endpoints（GameMasterDO からのみ呼ばれる） ---
    // /status の浅い観測だけは公開のまま。全履歴・提出値・R2 HEAD を読む deep=1 は
    // 下で個別に認証する（運用モニターと reset 後の残留確認は浅い観測だけで足りる）。
    if (CHAT_HTTP_AUTH_PATHS.has(path) && !this.verifyApiSecret(request)) {
      return createCORSResponse({ error: 'Unauthorized' }, 401);
    }

    // HTTP endpoints (GameMasterDOから呼び出し)
    if (path === '/init' && request.method === 'POST') {
      return this.handleInit(request);
    }

    if (path === '/republish-roster' && request.method === 'POST') {
      return this.handleRepublishRoster();
    }

    if (path === '/set-phase' && request.method === 'POST') {
      return this.handleSetPhase(request);
    }

    if (path === '/status' && request.method === 'GET') {
      const deep = url.searchParams.get('deep') === '1';
      if (deep && !this.verifyApiSecret(request)) {
        return createCORSResponse({ error: 'Unauthorized' }, 401);
      }
      return this.handleGetStatus({ deep });
    }

    if (path === '/get-results' && request.method === 'GET') {
      return this.handleGetResults();
    }

    if (path === '/reset' && request.method === 'DELETE') {
      return this.handleReset(request);
    }

    if (path === '/invalidate-no-game' && request.method === 'POST') {
      return this.handleInvalidateNoGame();
    }

    // テスト専用: 提出データの削除/改変（Evidence計画 §7 検閲シミュレーション用、
    // handleReset と同じ RELEASE_TIME ガードでリリース後は構造的に呼び出し不能）
    if (path === '/debug-submission' && request.method === 'POST') {
      return this.handleDebugSubmission(request);
    }

    // ストレージクリーンアップ（GameMasterDO経由、RELEASE_TIMEチェックなし）
    if (path === '/cleanup' && request.method === 'POST') {
      return this.handleCleanup();
    }

    // 便 PLAYAT（2026-11-25）: エントリーの時とマイページで先に設定した参加予定時刻を、
    // GameMasterDO が初期化の後に渡す口（認証は上の台帳 CHAT_HTTP_AUTH_METHODS）
    if (path === '/seed-availability' && request.method === 'POST') {
      return this.handleSeedAvailability(request);
    }

    return createCORSResponse({ error: 'Not Found' }, 404);
  }

  // ストレージクリーンアップ（completed済みDOのストレージを解放）
  async handleCleanup() {
    const phase = await this.storage.get('phase');
    if (phase && phase !== 'completed') {
      return createCORSResponse({
        error: 'Cannot cleanup: game not completed',
        phase
      }, 409);
    }

    const archiveStatus = await this.storage.get('archiveStatus') || null;
    if (archiveStatus?.ok !== true) {
      return createCORSResponse({
        error: 'Cannot cleanup: game archive not completed',
        archiveStatus,
      }, 409);
    }

    const finalSubmissionSnapshot = await this.storage.get(SUBMISSION_SNAPSHOT_FINAL_STATUS_KEY) || null;
    if (finalSubmissionSnapshot?.ok !== true) {
      return createCORSResponse({
        error: 'Cannot cleanup: final submission snapshot not completed',
        finalSubmissionSnapshot,
      }, 409);
    }

    // 全WebSocket接続を閉じる
    const sockets = this.state.getWebSockets();
    for (const ws of sockets) {
      try { ws.close(1000, 'Cleanup'); } catch (e) { /* ignore */ }
    }

    if (typeof this.storage.deleteAlarm === 'function') await this.storage.deleteAlarm();
    await this.storage.deleteAll();
    return createCORSResponse({ success: true, message: 'Storage cleaned up' });
  }

  // ============================================================
  // HTTP handlers (GameMasterDOから呼び出される)
  // ============================================================

  async publishRosterFile(blockNum, groupId, members) {
    // R-4.17: roster の raw SHA-256 を初期化時刻に依存させない。
    // rosterText 自体から createdAt を除外し、raw bytes を再ハッシュする既存 reader と整合させる。
    const rosterText = canonicalRosterText(blockNum, groupId, members);
    const rosterSha256 = await sha256Hex(rosterText);
    try {
      await this.env.R2_BUCKET.put(
        `games/block${Number(blockNum)}/roster/group${Number(groupId)}.json`,
        rosterText,
        { httpMetadata: { contentType: 'application/json' } },
      );
      this.recordDependencyOutcome('succeeded', 'R2_BUCKET', 'publish_roster');
    } catch (error) {
      this.recordDependencyOutcome('failed', 'R2_BUCKET', 'publish_roster', { error: boundedError(error) });
      throw error;
    }
    await this.storage.put('rosterSha256', rosterSha256);
    return rosterSha256;
  }

  async handleRepublishRoster() {
    const [meta, members] = await Promise.all([
      this.storage.get('meta'), this.storage.get('members'),
    ]);
    if (!meta || !Array.isArray(members) || members.length === 0) {
      return createCORSResponse({ error: 'Roster is not initialized' }, 409);
    }
    try {
      const rosterSha256 = await this.publishRosterFile(meta.blockNum, meta.groupId, members);
      return createCORSResponse({ success: true, rosterSha256 });
    } catch (error) {
      console.error(`Roster R2 republish failed for block${meta.blockNum} group${meta.groupId}:`, error);
      return createCORSResponse({ error: error?.message || String(error) }, 503);
    }
  }

  // グループ初期化（v3.2: グループ分け完了後ただちに waiting フェーズで初期化。
  // 早着ガードは撤去＝「宣言 chattingStart まで待つ」役割は waiting→chatting の
  // phase_transition タスクが担う）
  async handleInit(request) {
    if (await this.storage.get(INVALIDATED_NO_GAME_KEY)) {
      return createCORSResponse({ error: 'Timeline no-game is terminal' }, 409);
    }
    const body = await request.json();
    const {
      blockNum, groupId, lang, mixed, members, periodDurations, phaseEndTime,
      phaseEndTimeSource, phaseEndTimeManualFallback, manualFallback,
    } = body;

    if (!blockNum && blockNum !== 0) {
      return createCORSResponse({ error: 'blockNum is required' }, 400);
    }
    if (groupId === undefined || groupId === null) {
      return createCORSResponse({ error: 'groupId is required' }, 400);
    }
    if (!members || !Array.isArray(members) || members.length === 0) {
      return createCORSResponse({ error: 'members array is required' }, 400);
    }

    // 🔴 P-2026-0829（2026-08-07）: **署名文脈の正準性は入口で課す。**
    //    旧実装は `blockNum` / `groupId` を無検証で `storage.put('meta')` していた。実測で
    //      groupId: '0x5' / ' 5 ' / [5] / 5.5      → HTTP 200 success
    //      blockNum: '0x7' / true / -1 / 2^53+1    → HTTP 200 success
    //    が保存でき、同じ規則を持つ `canonMetaInt` は**採点本体にしか無かった**ので、
    //    48時間後（チャット24h＋提出24h）の採点で初めて throw していた。
    //    これは「遅延 fail-closed」＝入口で拒否できたものを、修復の窓（`extendGrace`）が
    //    閉じたあとで落とす、という最も質の悪い失敗。しかも保存済み入力は不変なので
    //    リトライも同じ壁に当たり、第三者の検証ツールも同じ park に道連れになる。
    //    ⚠️ Rust ゲスト（`crates/group-guest/src/witness.rs:379-387`）にも同型の門番が在り、
    //       両端は元から fail-closed。ここで直しているのは **park のタイミング**だけで、
    //       受理集合（正常な `0` / `'5'` / `9007199254740991`）は1つも変えていない。
    let canonBlockNum, canonGroupId;
    try {
      canonBlockNum = canonMetaInt(blockNum, 'blockNum', '[chat-do]');
      canonGroupId = canonMetaInt(groupId, 'groupId', '[chat-do]');
    } catch (err) {
      return createCORSResponse({ error: err.message }, 400);
    }

    // 🔴 P-2026-0841（2026-08-08・ラウンド19 判断不要-9）: **uid も入口で縛る。**
    //    `handleInit` は API_SECRET を持つ任意の呼び出し元から `members` を受け取り、
    //    uid を**一切検査せずに** `storage.put('members')` していた
    //    （`formGroups` は `isCanonicalUid` を課すが、それはこの入口を通らない）。
    //    DO ストレージの分割キーは区切りを `\u0001` にして prefix-free にしたが、
    //    移行期間中は旧形式 `:{NNN}` も読むので、`:` を含む uid は入れない。
    //    ⚠️ 過剰遮断ゼロ: 本番の uid は X の snowflake ＝数字列
    //       （`auth_workers/lib/db-sharded.js:69`）。将来の匿名エントリー（`0x…`）も
    //       `:` を含まない。加えて報酬が正なら `claim-data-codec.js` の `playerLeafKey`
    //       （`^\d{1,20}$`）が独立に throw するので、ここで通しても結局 park する。
    for (const m of members) {
      const uid = m?.uid;
      if (!isCanonicalUid(uid) || uid.includes(':') || uid.includes(GameChunkKeys.SEP)) {
        return createCORSResponse({
          // ⚠️ ここで `JSON.stringify(uid)` を使わない（参加者由来の値に再帰 stringify を
          //    掛けると深い入れ子で RangeError になる・P-2026-0827 / stringify-depth-park-test）。
          error: `Invalid member uid (type=${typeof uid}${typeof uid === 'string' ? `, value=${uid.slice(0, 64)}` : ''})`
            + ` — must be canonical (printable ASCII) and contain neither ':' nor U+0001`,
        }, 400);
      }
    }

    // 既に初期化済みかチェック
    // S3-013（2026-07-29）: 409 の応答に**保存済み名簿のハッシュ**を載せる。
    // GameMasterDO 側は D1 の名簿から同じ式でハッシュを計算し、一致したときだけ
    // 「初期化済み＝冪等成功」と数える。一致しない DO（前ランの残留＝孤児、
    // あるいは別 roster で先回り初期化されたもの）を黙って採用しないため。
    const existingPhase = await this.storage.get('phase');
    if (existingPhase && existingPhase !== 'init') {
      const stored = await this.storage.get('members') || [];
      let rosterSha256 = await this.storage.get('rosterSha256') || null;
      if (!rosterSha256) {
        const meta = await this.storage.get('meta');
        try {
          rosterSha256 = await this.publishRosterFile(
            meta?.blockNum ?? canonBlockNum,
            meta?.groupId ?? canonGroupId,
            stored,
          );
        } catch (error) {
          console.error(`Roster R2 republish on idempotent init failed for block${canonBlockNum} group${canonGroupId}:`, error);
        }
      }
      return createCORSResponse({
        error: 'Already initialized',
        phase: existingPhase,
        rosterHash: rosterHashOfMembers(stored),
        rosterSha256,
      }, 409);
    }

    const now = new Date().toISOString();

    // 期間durations保存（フェーズ終了時刻計算用・GAME_PERIOD/SUBMIT_PERIOD）
    await this.storage.put('periodDurations', periodDurations || { gamePeriod: 86400000, submitPeriod: 86400000 });

    // メタデータ保存
    // ⚠️ 保存するのは **Number へ正規化した値**（`'5'` と `5` で署名文脈が割れないように）。
    await this.storage.put('meta', {
      blockNum: canonBlockNum,
      groupId: canonGroupId,
      lang: lang || 'mixed',
      mixed: !!mixed,
      memberCount: members.length,
      createdAt: now
    });

    // メンバーリスト保存
    await this.storage.put('members', members);

    // フェーズ初期化（waitingの終了時刻 = 宣言タイムラインのchattingStart。
    // grace延長後の実遷移時刻と一致させる）
    await this.storage.put('phase', 'waiting');
    await this.storage.put('phaseEndTime', (typeof phaseEndTime === 'number' && phaseEndTime > 0) ? phaseEndTime : null);
    this.recordPhaseEndTime('waiting', phaseEndTime, phaseEndTimeSource,
      phaseEndTimeManualFallback ?? manualFallback);
    await this.storage.put('phaseTimestamps', {
      waitingAt: now,
      chattingAt: null,
      submittingAt: null,
      completedAt: null
    });

    // カウンター初期化
    await this.storage.put('messageCounter', 0);
    await this.storage.put('messages', []);

    // 文字数カウント初期化（全メンバー0）
    const charCounts = Object.create(null);   // P-2026-0823: uid は `__proto__` になりうる
    for (const member of members) {
      charCounts[member.uid] = 0;
    }
    await this.storage.put('charCounts', charCounts);

    // P2P §4.6（F4）: formation時点でロスターをR2公開ドメインへ書く。
    // tag/pubkey/depositIdsが全て運営WSチャネル依存だと、ゲーム開始時点からWS検閲された
    // 標的はP2Pチャネルをブートストラップできない（購読タグも相手pubkeyも不明）。
    // R2はゲームサーバーと別経路（r2.bitcoinu.org）で読めるため、WS検閲下でも取得できる。
    // 従来の completed 時アーカイブ（games/blockN/groupX.json）とは別の軽量ファイル。
    //
    // 🔴 P-2026-0829（2026-08-07）: **1人の壊れた `bAddr` で全員分の roster が消えていた。**
    //    旧実装は `members.map(...)` 全体が1つの `try` の中にあり、map の中の生の
    //    `JSON.parse(m.bAddr)` が投げると R2 の `put` に到達しない（実測: put 1回 → 0回）。
    //    しかも HTTP は 200 を返すので、**P2P ブートストラップが無言で消える**
    //    ＝WS を検閲された標的が冗長経路を張れない。検閲対策そのものが自壊する経路だった。
    //    → パースは **per-member** にして、壊れた1人は `null` で載せ、roster は必ず publish する
    //      （その1人だけが P2P を張れない ≪ 全員が張れない）。
    try {
      await this.publishRosterFile(canonBlockNum, canonGroupId, members);
    } catch (error) {
      console.error(`Roster R2 publish failed for block${canonBlockNum} group${canonGroupId}:`, error);
    }

    console.log(`ChatGameDO initialized: block${canonBlockNum} group${canonGroupId} (${members.length} members, lang=${lang})`);

    // G7: 観戦用の初期スナップショット公開（グループ発表を観戦者にも即時反映）
    await this.publishLiveSnapshot(true);

    return createCORSResponse({
      success: true,
      blockNum: canonBlockNum,
      groupId: canonGroupId,
      memberCount: members.length,
      phase: 'waiting',
      rosterSha256: await this.storage.get('rosterSha256') || null,
    });
  }

  // フェーズ遷移（v3.2: waiting → chatting → submitting → completed）
  async handleSetPhase(request) {
    if (await this.storage.get(INVALIDATED_NO_GAME_KEY)) {
      return createCORSResponse({ error: 'Timeline no-game is terminal' }, 409);
    }
    const body = await request.json();
    const {
      phase, phaseEndTime, rearchive = false,
      phaseEndTimeSource, phaseEndTimeManualFallback, manualFallback,
    } = body;

    const validPhases = ['waiting', 'chatting', 'submitting', 'completed'];
    if (!validPhases.includes(phase)) {
      return createCORSResponse({ error: `Invalid phase: ${phase}` }, 400);
    }

    const currentPhase = await this.storage.get('phase');
    if (!currentPhase) {
      return createCORSResponse({ error: 'Not initialized' }, 400);
    }

    // S3-009（2026-07-30）: フェーズは**前進のみ**。後退を禁止する。
    //
    // なぜ危険か（「運営自身も攻撃者」という前提での話）:
    //   ・`completed` → `chatting` へ戻せば、締め切ったあとに
    //     チャット／投票／密告を**追加させる**ことができる
    //   ・後退のたびに `phaseTimestamps` が上書きされる。これは第三者が
    //     「運営がフェーズをいじった」ことを検知する手がかりそのものなので、
    //     後退を許すと**不正の痕跡を消せてしまう**
    //   ・`archiveGameData()`（completed 時）を何度も走らせられる
    //
    // 同一フェーズへの再送は**冪等成功**にする。S3-006 で「遷移できたグループだけ控える」
    // ようにしたため、一部グループだけ失敗したときの再送が正常系に入る。
    // このとき既存の `phaseEndTime` と証跡は上書きしない。ただし completed の公開
    // アーカイブだけは、R12-48 により「phase へ到達したか」ではなく `archiveStatus.ok` で
    // 完了を判定する。R2 の一過性障害で未完了なら再試行し、成功済みなら二重に書かない。
    // `rearchive:true` は `/anchor-result` が R2 欠落を実確認した場合だけ送る復旧指定。
    // （本当に遷移が失敗していたグループは currentPhase が古いままなので通常経路を通る）
    const PHASE_ORDER = ['waiting', 'chatting', 'submitting', 'completed'];
    const curIdx = PHASE_ORDER.indexOf(currentPhase);
    const nextIdx = PHASE_ORDER.indexOf(phase);
    if (curIdx >= 0 && nextIdx < curIdx) {
      return createCORSResponse({
        error: 'phase regression is not allowed',
        currentPhase,
        requestedPhase: phase,
        hint: 'やり直しは reset 系で行う（このDOは /reset、ブロック全体は game-master-do の /reset-block）',
      }, 409);
    }
    if (curIdx >= 0 && nextIdx === curIdx) {
      if (phase === 'completed') {
        let finalSubmissionSnapshot = await this.storage.get(SUBMISSION_SNAPSHOT_FINAL_STATUS_KEY) || null;
        let finalSubmissionSnapshotRetried = false;
        if (finalSubmissionSnapshot?.ok !== true) {
          finalSubmissionSnapshot = await this.publishSubmissionSnapshot(true);
          finalSubmissionSnapshotRetried = true;
        }
        let archive = await this.storage.get('archiveStatus') || null;
        let archiveRetried = false;
        if (rearchive === true || !archive?.ok) {
          archive = await this.archiveGameData();
          archiveRetried = true;
        }
        return createCORSResponse({
          success: true, phase, unchanged: true,
          finalSubmissionSnapshot, finalSubmissionSnapshotRetried,
          archive, archiveRetried,
        });
      }
      return createCORSResponse({ success: true, phase, unchanged: true });
    }

    // waiting → chatting 遷移時
    if (currentPhase === 'waiting' && phase === 'chatting') {
      const members = await this.storage.get('members') || [];
      if (members.length <= 1) {
        // 1人グループ: ゲームスキップフラグを設定
        await this.storage.put('gameSkipped', { reason: 'solo_player' });
      }

      // チャット開始時点で既にオンラインのメンバーは「復帰予定」へ切替＆予定時刻クリア
      // （接続継続中のメンバーは再接続イベントが発火しないため、ここで処理する）
      const connectedNow = this.getConnectedUids();
      if (connectedNow.length > 0) {
        const everOnline = uidMap(await this.storage.get('everOnline'));     // P-2026-0823
        const availability = uidMap(await this.storage.get('availability')); // P-2026-0823
        const clearedUids = [];
        for (const cu of connectedNow) {
          everOnline[cu] = true;
          if (availability[cu] != null) {
            delete availability[cu];
            clearedUids.push(cu);
          }
        }
        await this.storage.put('everOnline', everOnline);
        if (clearedUids.length > 0) {
          await this.storage.put('availability', availability);
          for (const cu of clearedUids) {
            this.broadcast({ type: 'availability_update', uid: cu, availableAt: null });
          }
        }
      }
    }

    // フェーズ更新
    await this.storage.put('phase', phase);
    await this.storage.put('phaseEndTime', phaseEndTime || null);
    this.recordPhaseEndTime(phase, phaseEndTime, phaseEndTimeSource,
      phaseEndTimeManualFallback ?? manualFallback);

    const timestamps = await this.storage.get('phaseTimestamps') || {};
    const now = new Date().toISOString();
    // S3-009: 証跡は**最初の記録を残す**（上書きしない）。
    // 前進のみの制限と併せて、「いつそのフェーズに入ったか」を後から書き換えられなくする。
    // 上の冪等分岐で同一フェーズは弾いているので、ここに来て既に値がある＝
    // 想定外の経路。その場合も既存値を優先し、証跡を壊さない。
    const stamp = (key) => { if (!timestamps[key]) timestamps[key] = now; };
    switch (phase) {
      case 'chatting': stamp('chattingAt'); break;
      case 'submitting': stamp('submittingAt'); break;
      case 'completed': stamp('completedAt'); break;
    }
    await this.storage.put('phaseTimestamps', timestamps);

    // R12-48 / R12-50: completed は先に phase と最初の completedAt を確定して提出を閉じ、
    // その後で公開一次資料を書き出す。R2 失敗でも phase は戻さない（提出期限後の受理を防ぐ）。
    // archiveGameData は成否を archiveStatus に記録するため、同一 phase の再送でだけ再試行できる。
    let archive = null;
    let finalSubmissionSnapshot = null;
    if (phase === 'completed') {
      // Q22（2026-09-16 ユーザー決定）: 提出期間中の保全用写しを、間引きを無視して
      // completed 状態でも最後に1回公開する。この live key は manifest / 採点 / BIND の
      // 権威ではなく、権威は従来どおり games/.../groupG.json と manifest の file set。
      finalSubmissionSnapshot = await this.publishSubmissionSnapshot(true);
      archive = await this.archiveGameData();
    }

    // 全接続中クライアントにフェーズ遷移通知
    const phaseChangeMsg = {
      type: 'phase_change',
      phase,
      phaseEndTime: phaseEndTime || null,
      timestamp: now
    };
    // ゲームスキップ情報をフェーズ遷移通知に含める
    const gameSkipped = await this.storage.get('gameSkipped');
    if (gameSkipped) {
      phaseChangeMsg.gameSkipped = gameSkipped;
    }
    // 一度でもオンラインになったUID一覧（参加予定→復帰予定の切替用）
    if (phase === 'chatting') {
      const everOnline = await this.storage.get('everOnline') || {};
      phaseChangeMsg.everOnlineUids = Object.keys(everOnline);
    }
    this.broadcast(phaseChangeMsg);

    console.log(`Phase changed to ${phase}`);

    // G7: フェーズ遷移は即時スナップショット（観戦者が遷移表示を最大30秒待たされないように）
    await this.publishLiveSnapshot(true);

    return createCORSResponse({
      success: true, phase,
      ...(finalSubmissionSnapshot ? { finalSubmissionSnapshot } : {}),
      ...(archive ? { archive } : {}),
    });
  }

  // ============================================================
  // Z2是正（2026-07-16）: ストレージのキー分割ヘルパー
  // DOストレージには「1値あたり128KiB」の上限があり、旧実装は
  //   - チャット履歴全体を 'messages' の1キー
  //   - 提出バンドル（チャット全文コピー同梱）を 'submissions:{uid}' の1キー
  //   - 提出生バイト列を 'submissions_raw:{uid}' の1キー
  // に保存していたため、ゲーム規定量（5人×100件×1万字）内の会話でも上限を超え、
  // チャット途中死・提出保存失敗（→no_submit失格）が起き得た。
  // 本ヘルパー群は「保存の形」だけを分割し、読み出し時に旧形状（配列/オブジェクト/文字列）を
  // 完全に復元する。プロトコル・署名・chatHash・採点・block-verifier検証には影響しない。
  // デプロイ跨ぎの進行中ゲームは、旧キーの既存データ＋新分割キーを読み出しで結合する。
  // ============================================================

  // メッセージキー（messageCounterは単調増加・6桁ゼロ詰め→listの辞書順=時系列順）
  msgKey(n) {
    return `msg:${String(n).padStart(6, '0')}`;
  }

  // 🔴 P-2026-0841（2026-08-08・ラウンド19 判断不要-9）:
  //    **分割キーの区切りを `isCanonicalUid` のアルファベット外にする。**
  //
  //    旧キー空間は `submissions_raw:{uid}` / `submissions_raw:{uid}:{NNN}` /
  //    `submission_msgs:{uid}:{NNN}` で、区切りの `:` が
  //    `isCanonicalUid` の許可アルファベット `/^[\x21-\x7E]+$/`（ASCII 印字可能）**の中**にある
  //    （`protocol-v2.js:223` は将来の匿名エントリーのために意図的に広く取っている）。
  //    ＝ uid について **prefix-free でない**。実測:
  //      B='12:000' が提出 → キー `submissions_raw:12:000`
  //      A='12' が 119,997 文字（storageBytes 239,994 > VALUE_SAFE_BYTES）を提出
  //       → `list({prefix:'submissions_raw:12:'})` が **B の raw を削除**、
  //         チャンク0が同じキーを上書き → `loadSubmissionRaw('12:000')` が A の断片を返す
  //      順序が逆なら first-write-wins ゲートが A のチャンクを existingSubmission として読み、
  //      B は `alreadySubmitted` で WS 提出そのものが不可能になる
  //
  //    被害像は「静かな窃取」ではなく **大声の停止**（`deriveSubmissionsFromRaw` が
  //    fail-closed で throw → K-S2-004 リトライ → `CALC_MAX_CONSECUTIVE_FAILURES=20` で
  //    ブロック全体が park）。到達も運営のみ（uid は X の snowflake ＝数字列）。
  //    それでも直す理由は、P-2026-0819（`isCanonicalUid` は `|` も `:` も許すので
  //    4箇所を同時に直すこと）の掃討が「鍵はすべて内部の Map/Set で外へは出ない」と
  //    範囲を切り、**DO ストレージのキー空間を一度も見ていなかった**から
  //    （既知パターンの新実例）。
  //
  //    ⚠️ **移行の罠**: `:657` が明記する「デプロイ跨ぎの進行中ゲーム」があるので、
  //       **読み出し側は旧形式 `:{NNN}` も当面読み続ける**。書き込みは新形式のみ。
  //       掃除は「新形式は prefix 走査（prefix-free なので安全）／旧形式はマーカーが
  //       示す件数ぶんだけピンポイント削除」にする。旧形式を prefix 走査で消すと
  //       それ自体がこのバグの再現になる。
  chunkKey(base, uid, i) {
    return `${base}:${uid}${GameChunkKeys.SEP}${String(i).padStart(3, '0')}`;
  }

  legacyChunkKey(base, uid, i) {
    return `${base}:${uid}:${String(i).padStart(3, '0')}`;
  }

  /// 新形式チャンクの一括削除（prefix-free なので prefix 走査が安全）＋
  /// 旧形式チャンクの**件数限定**削除（`n` は自分が書いたマーカー由来）。
  async purgeChunks(base, uid, legacyCount = 0) {
    const stale = await this.storage.list({ prefix: `${base}:${uid}${GameChunkKeys.SEP}` });
    const keys = [...stale.keys()];
    for (let i = 0; i < legacyCount; i++) keys.push(this.legacyChunkKey(base, uid, i));
    if (keys.length > 0) await this.storage.delete(keys);
  }

  /// 新形式 → 旧形式の順に読む（移行期間中のみ旧形式へフォールバック）
  async getChunk(base, uid, i) {
    const v = await this.storage.get(this.chunkKey(base, uid, i));
    if (v !== undefined && v !== null) return v;
    return await this.storage.get(this.legacyChunkKey(base, uid, i));
  }

  // チャット履歴の全読み出し（旧 'messages' 配列 → 新 'msg:*' 分割キーの順に結合。
  // 旧配列はデプロイ前の発言なのでidは必ず分割キー分より小さく、結合順=時系列順が保たれる）
  async loadMessages() {
    const legacy = await this.storage.get('messages') || [];
    const map = await this.storage.list({ prefix: 'msg:' });
    return legacy.concat([...map.values()]);
  }

  // 提出バンドル保存。全体が安全サイズなら旧形状のまま1キー（大半のゲームはこちら）。
  // 超える場合は messages 配列だけをバイト量ベースで分割し、メタに _msgsChunks を記録。
  // チャンク→メタの順で書く（メタの存在=コミット点。first-write-winsチェックはメタを見る）。
  async storeSubmissionBundle(uid, bundle) {
    // 上書き時（デバッグtamper等）の旧チャンク掃除
    // P-2026-0841: 旧形式は「自分が書いた件数」ぶんだけ消す（prefix 走査だと
    // uid が prefix-free でないため他人のキーを巻き込む）。
    {
      const prev = await this.storage.get(`submissions:${uid}`);
      await this.purgeChunks('submission_msgs', uid, Number(prev?._msgsChunks) || 0);
    }

    // 🔴 P-2026-0813 ⑥（2026-08-07）: 早期 return の条件は **サイズが安全域に収まること**。
    //   旧条件は `!Array.isArray(bundle.messages) || size <= VALUE_SAFE_BYTES` で、
    //   `messages` が配列でない（＝ null）だけでサイズ検査を丸ごと飛ばしていた。
    //   `messages:null` の巨大バンドル（encryptedActions 側が大きい）で
    //   「DO 値サイズ上限超過: submissions:u3 = 958796B」の throw を実測。
    //   分割できる messages が無くても raw 委譲（_fromRaw）で保存できるので、
    //   サイズを先に見て、超えるなら必ず分割/委譲の経路へ落とす。
    if (storageBytes(bundle) <= VALUE_SAFE_BYTES) {
      await this.storage.put(`submissions:${uid}`, bundle);
      return;
    }
    if (!Array.isArray(bundle.messages)) {
      // 分割対象（messages 配列）が無いのに単一値上限を超えた＝ meta 側が大きい。
      // raw から丸ごと復元する（loadSubmission の _fromRaw 経路。raw は先に保存済み）。
      await this.storage.put(`submissions:${uid}`, {
        _fromRaw: true, _msgsChunks: 0, submittedAt: bundle.submittedAt,
      });
      return;
    }
    const chunks = [];
    let cur = [];
    let curBytes = 4; // '[]'
    for (const m of bundle.messages) {
      const b = storageBytes(m) + 2;
      if (cur.length > 0 && curBytes + b > CHUNK_TARGET_BYTES) {
        chunks.push(cur); cur = []; curBytes = 4;
      }
      cur.push(m);
      curBytes += b;
    }
    if (cur.length > 0) chunks.push(cur);
    for (let i = 0; i < chunks.length; i++) {
      await this.storage.put(this.chunkKey('submission_msgs', uid, i), chunks[i]);
    }
    const meta = { ...bundle };
    delete meta.messages;
    meta._msgsChunks = chunks.length;

    // 🔴 messages を外しても meta が単一値に収まらないことがある（2026-08-05 実障害）。
    // meta には encryptedActions が入り、その observed.receipts は
    // receiptBundleCap（4人・100メッセージで **1320件**）まで許されるため、
    // 実測4人ゲームでも 131,108 バイト（> VALUE_SAFE_BYTES 100,000）に達した。
    // プロトコルが許す量の 1/6 で保存が破綻していた＝上限どうしが噛み合っていない。
    //
    // 対処: **meta を保存せず raw から復元する**。
    //   ・submissions_raw は既に文字列スライスでサイズ無制限に対応済み
    //   ・raw は bundle より**先に**書かれる（2026-08-03 の順序修正）ので必ず存在する
    //   ・bundle は raw を JSON.parse したものと同一（フィールド順も一致させる設計）
    // 新しい保存形式を増やさずに上限そのものが消える。
    if (storageBytes(meta) > VALUE_SAFE_BYTES) {
      // submittedAt はマーカーにも持たせる。my_submission 応答（handleWsGetMySubmission /
      // init 時）がこのキーを **loadSubmission を通さず直接** 読んで submittedAt を返すため、
      // 落とすと提出済みなのに提出時刻が undefined になる。
      await this.storage.put(`submissions:${uid}`, {
        _fromRaw: true, _msgsChunks: chunks.length, submittedAt: bundle.submittedAt,
      });
      return;
    }
    await this.storage.put(`submissions:${uid}`, meta);
  }

  // 提出バンドル読み出し（分割時は結合して旧形状を復元。フィールド順も保存時と同一）
  async loadSubmission(uid) {
    const sub = await this.storage.get(`submissions:${uid}`);
    if (!sub) return null;
    // meta が単一値に収まらず raw 委譲になっている場合（storeSubmissionBundle 参照）。
    // raw は必ず先に保存されているので、そこから丸ごと復元する。
    if (sub._fromRaw) {
      const raw = await this.loadSubmissionRaw(uid);
      if (raw == null) return null;   // 例外にせず「提出無し」に落とす（採点側の分岐は既存のまま）
      try { return decodeSubmissionPayloadString(raw).bundle; } catch { return null; }
    }
    if (sub._msgsChunks === undefined) return sub;
    const messages = [];
    for (let i = 0; i < sub._msgsChunks; i++) {
      const c = await this.getChunk('submission_msgs', uid, i);   // P-2026-0841: 新→旧の順
      if (Array.isArray(c)) messages.push(...c);
    }
    const { _msgsChunks, ...rest } = sub;
    return { ...rest, messages };
  }

  // 提出生バイト列の保存（安全サイズは旧形状の文字列1キー。超える場合は
  // CHUNK_TARGET_BYTES/2 文字ずつ（＝最悪2B/コードユニットでも目標内）に分割し、
  // 基点キーに {_chunks:N} マーカー）
  async storeSubmissionRaw(uid, raw) {
    // P-2026-0841: 旧形式は「自分が書いた件数」ぶんだけ消す（prefix 走査だと
    // `submissions_raw:12:` が uid='12:000' の**本体キー**まで巻き込む＝このバグそのもの）。
    {
      const prev = await this.storage.get(`submissions_raw:${uid}`);
      await this.purgeChunks('submissions_raw', uid,
        (prev && typeof prev === 'object' && typeof prev._chunks === 'number') ? prev._chunks : 0);
    }

    if (storageBytes(raw) <= VALUE_SAFE_BYTES) {
      await this.storage.put(`submissions_raw:${uid}`, raw);
      return;
    }
    const SLICE = Math.floor(CHUNK_TARGET_BYTES / 2);
    const n = Math.ceil(raw.length / SLICE);
    for (let i = 0; i < n; i++) {
      await this.storage.put(this.chunkKey('submissions_raw', uid, i), raw.slice(i * SLICE, (i + 1) * SLICE));
    }
    await this.storage.put(`submissions_raw:${uid}`, { _chunks: n });
  }

  // 提出生バイト列の読み出し（文字列=旧形状そのまま / {_chunks:N}=結合復元）
  async loadSubmissionRaw(uid) {
    const raw = await this.storage.get(`submissions_raw:${uid}`);
    if (raw == null) return null;
    if (typeof raw === 'string') return raw;
    if (typeof raw._chunks === 'number') {
      let out = '';
      for (let i = 0; i < raw._chunks; i++) {
        out += (await this.getChunk('submissions_raw', uid, i)) || '';   // P-2026-0841: 新→旧の順
      }
      return out;
    }
    return null;
  }

  // raw → parsed marker のコミット順と例外伝播は従来どおり。観測だけを脇に足す。
  // parsed marker で失敗した場合は raw-only が残り、`/status` がストレージ実体から検出する。
  async persistSubmission(uid, rawPayload, bundle) {
    let operation = 'submission_raw';
    try {
      await this.storeSubmissionRaw(uid, rawPayload);
      operation = 'submission_bundle';
      await this.storeSubmissionBundle(uid, bundle);
    } catch (error) {
      this.recordStorageOutcome('failed', operation, { error: boundedError(error) });
      throw error;
    }
    this.recordStorageOutcome('succeeded', 'submission_commit');
  }

  // 提出関連キーの完全削除（本体＋分割チャンク。検閲シミュレーション/デバッグ用）
  async deleteSubmissionKeys(uid) {
    // P-2026-0841: 新形式は prefix 走査（`\u0001` は uid のアルファベット外＝prefix-free）。
    //   旧形式はマーカーが示す件数ぶんだけピンポイントで消す。
    const sub = await this.storage.get(`submissions:${uid}`);
    const rawMeta = await this.storage.get(`submissions_raw:${uid}`);
    await this.purgeChunks('submission_msgs', uid, Number(sub?._msgsChunks) || 0);
    await this.purgeChunks('submissions_raw', uid,
      (rawMeta && typeof rawMeta === 'object' && typeof rawMeta._chunks === 'number') ? rawMeta._chunks : 0);
    await this.storage.delete([`submissions:${uid}`, `submissions_raw:${uid}`]);
  }

  // ステータス取得
  async handleGetStatus({ deep = false } = {}) {
    const [meta, phase, charCounts, phaseTimestamps, phaseEndTime, members, archiveStatus,
      finalSubmissionSnapshot, observability, messageCounter] = await Promise.all([
      this.storage.get('meta'),
      this.storage.get('phase'),
      this.storage.get('charCounts'),
      this.storage.get('phaseTimestamps'),
      this.storage.get('phaseEndTime'),
      this.storage.get('members'),
      this.storage.get('archiveStatus'),
      this.storage.get(SUBMISSION_SNAPSHOT_FINAL_STATUS_KEY),
      this.readObservability(),
      this.storage.get('messageCounter'),
    ]);
    let messageCount = Number(messageCounter || 0);
    let submissionCount = null;
    let submissionRawCount = null;
    let submissionRawOnlyCount = null;
    let submissionParsedOnlyCount = null;
    let archiveR2Head = {
      state: 'not_attempted', checkedAt: observationNow(), reason: 'deep_check_disabled',
    };
    if (deep) {
      const messages = await this.loadMessages();
      messageCount = messages.length;
      const submissionRows = await Promise.all((Array.isArray(members) ? members : []).map(async (member) => {
        const [submission, raw] = await Promise.all([
          this.storage.get(`submissions:${member.uid}`),
          this.storage.get(`submissions_raw:${member.uid}`),
        ]);
        return { hasSubmission: submission != null, hasRaw: raw != null };
      }));
      submissionCount = submissionRows.filter((row) => row.hasSubmission).length;
      submissionRawCount = submissionRows.filter((row) => row.hasRaw).length;
      submissionRawOnlyCount = submissionRows.filter((row) => row.hasRaw && !row.hasSubmission).length;
      submissionParsedOnlyCount = submissionRows.filter((row) => row.hasSubmission && !row.hasRaw).length;
      archiveR2Head = await this.readArchiveR2Head(meta);
    }
    const phaseEndStatus = observability.phaseEndTime.lastStatus;
    const checkedAt = observationNow();
    const pendingObservationWrites = observationWriteFailureFields(
      this.observationWriteFailureCounter,
    );

    return createCORSResponse({
      checkedAt,
      deep,
      meta,
      phase: phase || 'init',
      charCounts: charCounts || {},
      phaseTimestamps: phaseTimestamps || {},
      phaseEndTime: phaseEndTime || null,
      phaseEndTimeSource: phaseEndStatus?.source || (phaseEndTime ? 'legacy_or_unspecified' : 'none'),
      phaseEndTimeManualFallback: phaseEndStatus?.manualFallback ?? null,
      phaseEndTimeStatus: observability.phaseEndTime,
      messageCount,
      connectedCount: this.state.getWebSockets().length,
      authFailureCount: observability.auth.failureCount,
      lastAuthStatus: observability.auth.lastStatus,
      lastDependencyStatus: observability.dependency.lastStatus,
      lastDependencyFailure: observability.dependency.lastFailure,
      submissionCount,
      submissionRawCount,
      submissionRawOnlyCount,
      submissionParsedOnlyCount,
      lastStorageStatus: observability.storage.lastStatus,
      lastStorageError: observability.storage.lastFailure,
      archiveStatus: archiveStatus || null,
      finalSubmissionSnapshot: finalSubmissionSnapshot || null,
      archiveR2Head,
      observationWriteFailures: Number(observability.observationWriteFailures || 0)
        + pendingObservationWrites.observationWriteFailures,
      observationWriteFailureReason:
        pendingObservationWrites.observationWriteFailures > 0
          ? pendingObservationWrites.observationWriteFailureReason
          : (observability.observationWriteFailureReason || null),
      observability,
    });
  }

  // `/status` の読み出し専用 HEAD。結果はここでは永続化せず、副作用を持たせない。
  async readArchiveR2Head(meta) {
    const checkedAt = observationNow();
    if (!meta || meta.blockNum === undefined || meta.groupId === undefined) {
      return { state: 'not_attempted', checkedAt, reason: 'meta_missing' };
    }
    const key = `games/block${meta.blockNum}/group${meta.groupId}.json`;
    if (!this.env.R2_BUCKET || typeof this.env.R2_BUCKET.head !== 'function') {
      return { state: 'not_attempted', checkedAt, key, reason: 'R2_BUCKET_head_unavailable' };
    }
    try {
      const object = await this.env.R2_BUCKET.head(key);
      return { state: 'succeeded', checkedAt, key, exists: !!object };
    } catch (error) {
      return { state: 'failed', checkedAt, key, error: boundedError(error) };
    }
  }

  // ゲーム結果取得（完了後）
  async handleGetResults() {
    const phase = await this.storage.get('phase');

    const meta = await this.storage.get('meta');
    const members = await this.storage.get('members') || [];
    const charCounts = await this.storage.get('charCounts') || {};

    // 各メンバーのsubmissions取得（raw = 受信生バイト列。evidence バイト照合用）
    // Z2是正: 分割保存に対応した読み出しヘルパー経由（旧形状はそのまま返る）
    //
    // 🔴 P-2026-0820（2026-08-07・C-6）: **`Object.create(null)` を使う。**
    //    `isCanonicalUid` は `/^[\x21-\x7E]+$/` を許すので uid に `__proto__` を置ける。
    //    素の `{}` だと `obj['__proto__'] = sub` が `Object.prototype.__proto__` の
    //    **setter** を叩くだけで own property にならず、`JSON.stringify` の出力から
    //    **その uid のエントリーが丸ごと消える**（＝採点にすら届かない＝本人が
    //    自分の提出物ごと no_submit で失格する）。
    //    calculator 側の入口正規化（`asUidMap`）は「消えたあと」なので戻せない。
    const submissions = Object.create(null);
    const submissionsRaw = Object.create(null);
    for (const member of members) {
      const sub = await this.loadSubmission(member.uid);
      if (sub) {
        submissions[member.uid] = sub;
      }
      const raw = await this.loadSubmissionRaw(member.uid);
      if (raw) submissionsRaw[member.uid] = raw;
    }

    // 各メンバーのreports取得
    const reports = Object.create(null);
    for (const member of members) {
      const rep = await this.storage.get(`reports:${member.uid}`);
      if (rep) {
        reports[member.uid] = rep;
      }
    }

    // 各メンバーのvotes取得
    const votes = Object.create(null);
    for (const member of members) {
      const vote = await this.storage.get(`votes:${member.uid}`);
      if (vote) {
        votes[member.uid] = vote;
        const extras = await this.storage.get(`voteExtras:${member.uid}`) || [];
        if (extras.length) votes[`${member.uid}__extras`] = extras;
      }
    }

    // メッセージ（Z2: 分割キー対応の読み出し）＋受領証明（サーバー観測分・デバッグ/アーカイブ用）
    const messages = await this.loadMessages();
    const receipts = await this.loadReceipts();

    // 🔴 P-2026-0831（2026-08-08）: **ここは `createCORSResponse(オブジェクト)` にしない。**
    //   `submissions` は `loadSubmission` が raw から作り直した**参加者由来のツリー**で、
    //   深さは誰も検査していない（②.6 は `encryptedActions` の形を見ない）。
    //   `cors.js` の `JSON.stringify(response)` は再帰なので、深い1通で 500 → park する。
    //   直列化済みの `Response` を渡せば共有ヘルパーに触らずに再帰を外せる（上の
    //   `corsJsonResponse` 参照）。出力バイト列は `JSON.stringify` と完全に同一。
    return corsJsonResponse({
      phase,
      meta,
      members,
      charCounts,
      submissions,
      submissionsRaw,
      reports,
      votes,
      messages,
      receipts
    });
  }

  // リセット（テスト用）
  async handleReset(request) {
    const releaseTime = this.env.RELEASE_TIME ? Date.parse(this.env.RELEASE_TIME) : null;

    if (!releaseTime || isNaN(releaseTime)) {
      return createCORSResponse({
        error: 'RELEASE_TIME is not configured. Reset is not allowed.'
      }, 403);
    }

    if (Date.now() >= releaseTime) {
      return createCORSResponse({
        error: 'System is already released. Reset is not allowed.'
      }, 403);
    }

    // 全WebSocket接続を閉じる
    const sockets = this.state.getWebSockets();
    for (const ws of sockets) {
      try {
        ws.close(1000, 'Reset');
      } catch (e) { /* ignore */ }
    }

    if (typeof this.storage.deleteAlarm === 'function') await this.storage.deleteAlarm();
    await this.storage.deleteAll();
    console.log('ChatGameDO reset');
    return createCORSResponse({ success: true, message: 'ChatGameDO reset' });
  }

  // timeline no-game 確定前の本番用終端入口。
  // 試験専用 /reset と異なり RELEASE_TIME へ依存せず、既存データは消さない。
  // completed へ固定して既存WSを閉じ、以後のWS接続・受信を拒否する。
  async handleInvalidateNoGame() {
    const now = new Date().toISOString();
    const previous = await this.storage.get(INVALIDATED_NO_GAME_KEY);
    const phaseTimestamps = await this.storage.get('phaseTimestamps') || {};
    const invalidated = previous || {
      schemaVersion: 1,
      reason: 'timeline_unverified',
      invalidatedAt: now,
    };
    await this.storage.put({
      [INVALIDATED_NO_GAME_KEY]: invalidated,
      phase: 'completed',
      phaseTimestamps: {
        ...phaseTimestamps,
        completedAt: phaseTimestamps.completedAt || now,
      },
    });

    const sockets = this.state.getWebSockets();
    for (const ws of sockets) {
      try {
        ws.close(1000, 'Timeline no-game invalidated');
      } catch { /* already closed */ }
    }
    if (typeof this.storage.deleteAlarm === 'function') await this.storage.deleteAlarm();

    return createCORSResponse({
      success: true,
      phase: 'completed',
      invalidatedNoGame: true,
      unchanged: !!previous,
    });
  }

  // ============================================================
  // テスト専用デバッグ（Evidence計画 §7 検閲シミュレーション）
  // ------------------------------------------------------------
  // 実システム通しで検閲/改変攻撃を再現するために、ChatGameDO が保存した提出データ
  // （submissions:{uid} / submissions_raw:{uid}）を削除・改変できる。
  // handleReset と同一の RELEASE_TIME ガードを課すため、本番リリース後は構造的に呼べない。
  //
  // body:
  //   { action: 'list' }                       → 全メンバーの提出保存状況を返す（破壊なし）
  //   { action: 'delete', uid }                → シナリオ2（検閲系）: 提出を丸ごと削除して no_submit 相当を作る
  //   { action: 'tamper', uid, mutate: {...} } → シナリオ3（改変系）: 保存済みバンドルを書き換える
  //        mutate.dropMessage: true            → messages 配列の末尾1件を削除（chatHash 不整合を誘発）
  //        mutate.corruptChatHash: true        → chatHash を書き換え
  //        mutate.rawReplace: "<文字列>"       → submissions_raw を任意文字列で置換（バイト不一致を強制）
  // ============================================================
  async handleDebugSubmission(request) {
    const releaseTime = this.env.RELEASE_TIME ? Date.parse(this.env.RELEASE_TIME) : null;
    if (!releaseTime || isNaN(releaseTime)) {
      return createCORSResponse({ error: 'RELEASE_TIME is not configured. Debug is not allowed.' }, 403);
    }
    if (Date.now() >= releaseTime) {
      return createCORSResponse({ error: 'System is already released. Debug is not allowed.' }, 403);
    }

    let body;
    try {
      body = await request.json();
    } catch (e) {
      return createCORSResponse({ error: 'Invalid JSON body' }, 400);
    }
    const { action, uid } = body;
    const members = await this.storage.get('members') || [];

    if (action === 'list') {
      const rows = [];
      for (const m of members) {
        const sub = await this.loadSubmission(m.uid);
        const raw = await this.loadSubmissionRaw(m.uid);
        rows.push({
          uid: m.uid,
          hasSubmission: !!sub,
          rawBytes: raw ? new TextEncoder().encode(raw).length : 0,
          chatHash: sub?.chatHash || null,
          messageCount: Array.isArray(sub?.messages) ? sub.messages.length : null
        });
      }
      return createCORSResponse({ success: true, phase: await this.storage.get('phase'), submissions: rows });
    }

    if (!uid) {
      return createCORSResponse({ error: 'uid is required for delete/tamper' }, 400);
    }
    if (!members.some(m => m.uid === uid)) {
      return createCORSResponse({ error: `uid ${uid} is not a member of this group` }, 404);
    }

    if (action === 'delete') {
      const had = !!(await this.storage.get(`submissions:${uid}`));
      await this.deleteSubmissionKeys(uid); // Z2: 分割チャンクも含めて完全削除
      console.log(`[debug] deleted submission for uid=${uid} (censorship simulation)`);
      return createCORSResponse({ success: true, action: 'delete', uid, deleted: had });
    }

    if (action === 'tamper') {
      const mutate = body.mutate || {};
      const sub = await this.loadSubmission(uid); // Z2: 分割対応読み出し（messages復元済み）
      if (!sub) {
        return createCORSResponse({ error: `no submission stored for uid ${uid}` }, 404);
      }
      let raw = await this.loadSubmissionRaw(uid);

      if (typeof mutate.rawReplace === 'string') {
        raw = mutate.rawReplace;
      } else {
        if (mutate.dropMessage && Array.isArray(sub.messages) && sub.messages.length > 0) {
          sub.messages = sub.messages.slice(0, -1);
        }
        if (mutate.corruptChatHash) {
          sub.chatHash = '0x' + 'de'.repeat(32); // 0xdede...（64 hex）で確実に不整合
        }
        // raw を parsed 側の改変に追従させる（バイト不一致＝mismatch を再現）
        if (raw != null) {
          try {
            const parsedRaw = JSON.parse(raw);
            if (mutate.dropMessage && Array.isArray(parsedRaw.messages) && parsedRaw.messages.length > 0) {
              parsedRaw.messages = parsedRaw.messages.slice(0, -1);
            }
            if (mutate.corruptChatHash) parsedRaw.chatHash = sub.chatHash;
            raw = JSON.stringify(parsedRaw);
          } catch (e) { /* raw がJSONでなければそのまま */ }
        }
      }

      await this.storeSubmissionBundle(uid, sub); // Z2: 分割対応書き込み（旧チャンク掃除込み）
      if (raw != null) await this.storeSubmissionRaw(uid, raw);
      console.log(`[debug] tampered submission for uid=${uid} (tamper simulation): ${JSON.stringify(Object.keys(mutate))}`);
      return createCORSResponse({
        success: true, action: 'tamper', uid,
        newChatHash: sub.chatHash,
        newMessageCount: Array.isArray(sub.messages) ? sub.messages.length : null,
        newRawBytes: raw ? new TextEncoder().encode(raw).length : 0
      });
    }

    return createCORSResponse({ error: `unknown action: ${action}` }, 400);
  }

  // ============================================================
  // WebSocket handling (Hibernation API)
  // ============================================================

  // WebSocketアップグレード
  async handleWebSocketUpgrade(request, url) {
    if (await this.storage.get(INVALIDATED_NO_GAME_KEY)) {
      return new Response('This game was invalidated as timeline no-game', { status: 410 });
    }
    const uid = url.searchParams.get('uid');
    if (!uid) {
      return new Response('uid parameter is required', { status: 400 });
    }

    // G4: スパム切断常習uidは接続自体を拒否（切断→再接続ループの仕上げ。
    // 認証fetchより先＝再接続ループでauth-workerに負荷を流さない。窓経過で自動解除）
    if (this.isUidStrikeCoolingDown(uid)) {
      return new Response('Too many abusive requests — try again later', { status: 429 });
    }

    // R33-F-1-01（D-12）: 同じ uid の upgrade の連打は auth を呼ぶ前に断る
    // （数えるのは認証に通った upgrade だけ＝他人がこの uid を騙っても窓は埋まらない）。
    if (this.isUidUpgradeRateLimited(uid)) {
      return new Response('Too many connection attempts — try again later', { status: 429 });
    }
    if (this.totalSocketsOfUid(uid) >= WS_MAX_TOTAL_SOCKETS_PER_UID) {
      return new Response('Too many connections — try again later', { status: 429 });
    }

    // メンバー検証。
    // G7是正（2026-07-18）: 観戦WS（?spectator=1・無認証・上限なし）は廃止。
    // 全ソケットへの逐次broadcast増幅（1メッセージ×観戦者数）と、無認証の接続で
    // DO の接続を増やす経路はこれで無くなった。
    // 名簿のメンバー自身の本数は、OPEN 4本と CLOSING を含む合計16本の uid ごとの上限で縛る。
    // DO 全体の上限32,768本へ1人が残骸を積み上げることも防ぐ。
    // 観戦は R2 の live/block{N}/group{G}.json（CDN・約30秒毎更新）のポーリングで行う。
    const members = await this.storage.get('members') || [];
    const isMember = members.some(m => m.uid === uid);

    if (!isMember) {
      return new Response('Not a member of this group (spectator websocket is disabled — poll the live snapshot on R2)', { status: 403 });
    }

    // メンバー（プレイヤー）の場合、sessionTokenでログイン認証
    {
      const token = url.searchParams.get('token');
      if (!token) {
        this.recordAuthOutcome('failed', { reason: 'missing_token' });
        return new Response('Authentication required', { status: 401 });
      }

      try {
        // S3-003: 公開 workers.dev URL → Service Binding（1接続につき1呼び出し＝上限に触れない）
        const workerNum = getAuthWorkerNumber(uid);
        const verifyRes = await requireBinding(this.env, authWorkerBinding(workerNum)).fetch(
          internalRequest('/auth/verify', {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ userId: uid })
          })
        );

        if (!verifyRes.ok) {
          this.recordDependencyOutcome(verifyRes.status >= 500 ? 'failed' : 'succeeded',
            'AUTH_WORKER', 'verify_session', { httpStatus: verifyRes.status });
          this.recordAuthOutcome('failed', { reason: 'rejected', httpStatus: verifyRes.status });
          console.log(`WebSocket auth failed for uid=${uid}: status=${verifyRes.status}`);
          return new Response('Authentication failed', { status: 403 });
        }

        this.recordDependencyOutcome('succeeded', 'AUTH_WORKER', 'verify_session', { httpStatus: verifyRes.status });
        this.recordAuthOutcome('succeeded', { reason: 'verified', httpStatus: verifyRes.status });
        console.log(`WebSocket auth verified for uid=${uid}`);
      } catch (authError) {
        this.recordDependencyOutcome('failed', 'AUTH_WORKER', 'verify_session', { error: boundedError(authError) });
        this.recordAuthOutcome('failed', { reason: 'dependency_error' });
        console.error(`WebSocket auth error for uid=${uid}:`, authError);
        return new Response('Authentication service unavailable', { status: 503 });
      }
    }

    // auth の await 中に同じ uid の upgrade が並行して通りうる。ここから accept まで await せず、
    // 頻度と OPEN+CLOSING の本数を再判定してから、認証に通った upgrade だけを窓へ数える。
    if (this.isUidUpgradeRateLimited(uid)) {
      return new Response('Too many connection attempts — try again later', { status: 429 });
    }
    if (this.totalSocketsOfUid(uid) >= WS_MAX_TOTAL_SOCKETS_PER_UID) {
      return new Response('Too many connections — try again later', { status: 429 });
    }
    this.noteUidUpgrade(uid);

    // WebSocket Pair作成
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    // R33-F-1-01（D-12）: 同じ uid の OPEN が4本なら、本人の最も古い OPEN を閉じてから受け付ける。
    this.supersedeOldSocketsOf(uid);

    // Hibernation API: uidをタグとして付与（G7: 観戦WS廃止によりメンバーのみ）。
    // 2つ目のタグは accept の順（R33-F-1-01 の「最も古い接続」の特定用）。先頭タグ＝uid の読み手は変わらない。
    this.state.acceptWebSocket(server, [uid, `${WS_ACCEPT_TAG_PREFIX}${Date.now()} ${this.wsAcceptSeq++}`]);

    console.log(`WebSocket connected: uid=${uid}`);

    // 接続通知をブロードキャスト
    {
      // チャット期間中にオンラインになった場合のみ「復帰予定」へ切替＆予定時刻クリア。
      // 準備期間は「参加予定」のまま（記録もクリアもしない）。
      const phase = await this.storage.get('phase');
      if (phase === 'chatting') {
        const everOnline = uidMap(await this.storage.get('everOnline')); // P-2026-0823
        if (!everOnline[uid]) {
          everOnline[uid] = true;
          await this.storage.put('everOnline', everOnline);
        }

        // オンラインになるたびに登録済みの参加/復帰予定時刻をクリア
        const availability = uidMap(await this.storage.get('availability')); // P-2026-0823
        const hadAvailability = availability[uid] != null;
        if (hadAvailability) {
          delete availability[uid];
          await this.storage.put('availability', availability);
        }

        this.broadcast({ type: 'member_connected', uid, everOnline: true }, uid);

        // クリアした予定時刻を全員（送信者含む）へ反映
        if (hadAvailability) {
          this.broadcast({ type: 'availability_update', uid, availableAt: null });
        }
      } else {
        this.broadcast({ type: 'member_connected', uid }, uid);
      }
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  // Hibernation API: WebSocketメッセージ受信
  async webSocketMessage(ws, message) {
    // close(4001/1008) の後も、相手が Close に応えなければメッセージが届く。
    // storage 読みより先に、数値の OPEN(1) 以外は応答せず捨てる。
    if (typeof ws?.readyState !== 'number' || ws.readyState !== WS_READY_STATE_OPEN) return;
    let messageType = null; // 便 DOMOVED: catch で ping と他を分ける（読めなければ null）
    try {
      if (await this.storage.get(INVALIDATED_NO_GAME_KEY)) {
        try { ws.close(1008, 'Timeline no-game invalidated'); } catch { /* already closed */ }
        return;
      }
      const data = JSON.parse(message);
      messageType = typeof data?.type === 'string' ? data.type : null;
      const tags = this.state.getTags(ws);
      const tag = tags[0];

      if (!tag) {
        this.sendTo(ws, { type: 'error', message: 'Unknown connection' });
        return;
      }

      // 観戦者の判定
      const isSpectator = tag.startsWith('spectator:');
      const uid = isSpectator ? tag.replace('spectator:', '') : tag;

      // G4: 総メッセージ量の粗いキャップ（ping含む全種別。24h正規接続≈3,000に対し5,000）
      const abuse = this.wsAbuseOf(ws);
      if (data?.type !== 'reaction') abuse.total++; // 便 LIKE: いいねは自分の枠（dropIfOverReactionQuota）で縛り、総量には数えない（Lean RS2-L03）
      if (abuse.total > WS_TOTAL_MSG_MAX) {
        console.warn(`WS message budget exceeded: uid=${uid} — closing connection`);
        this.noteStrikeClose(uid);
        try { ws.close(1008, 'Message budget exceeded'); } catch { /* 既閉 */ }
        return;
      }

      // v3.3追補: メンバーからの受信＝その瞬間アクティブだった証跡（在席表示の実測値）
      if (!isSpectator) this.memberSeen.set(uid, Date.now());

      // 観戦者はinit（読み取り）とpingのみ許可
      if (isSpectator && data.type !== 'init' && data.type !== 'ping') {
        this.sendTo(ws, { type: 'error', message: 'Spectators cannot perform this action' });
        return;
      }

      switch (data.type) {
        case 'init':
          await this.handleWsInit(ws, uid);
          break;
        case 'chat':
          await this.handleWsChat(ws, uid, data);
          break;
        case 'receipt':
          await this.handleWsReceipt(ws, uid, data);
          break;
        case 'set_availability':
          await this.handleWsSetAvailability(ws, uid, data);
          break;
        case 'set_presence':
          await this.handleWsSetPresence(ws, uid, data);
          break;
        case 'reaction':
          await this.handleWsReaction(ws, uid, data);
          break;
        case 'report':
          await this.handleWsReport(ws, uid, data);
          break;
        case 'vote':
          await this.handleWsVote(ws, uid, data);
          break;
        case 'submit':
          await this.handleWsSubmit(ws, uid, data);
          break;
        case 'get_my_submission':
          await this.handleWsGetMySubmission(ws, uid);
          break;
        case 'ping':
          this.sendTo(ws, { type: 'pong', timestamp: Date.now() });
          break;
        default:
          this.sendTo(ws, { type: 'error', message: `Unknown message type: ${data.type}` });
      }
    } catch (error) {
      console.error('Error handling WebSocket message:', error);
      // 便 DOMOVED: 古い実体につながったままの WS は閉じて張り直させる（この誤りのときだけ）
      if (isObjectMovedError(error)) {
        // 冒頭の storage の読みで落ちたときは、まだ種類を読んでいない（誤りの道でだけ読み直す）
        if (messageType === null) {
          try { const parsed = JSON.parse(message); messageType = typeof parsed?.type === 'string' ? parsed.type : null; } catch { /* 読めない */ }
        }
        if (messageType !== 'ping' && messageType !== 'reaction') this.sendTo(ws, { type: 'error', message: 'Internal error' });
        try {
          ws.close(WS_CLOSE_OBJECT_MOVED, WS_CLOSE_OBJECT_MOVED_REASON);
          return;
        } catch {
          if (messageType !== 'ping' && messageType !== 'reaction') return; // 拒否はもう返した
        }
      }
      // 便 LIKE: いいね（表示だけ・待ち行列から自動で出る）の失敗では誤りの帯を出させない（反証 RS3-R08）
      if (messageType === 'reaction') return;
      this.sendTo(ws, { type: 'error', message: 'Internal error' });
    }
  }

  // Hibernation API: WebSocket切断
  async webSocketClose(ws, code, reason) {
    this.wsAbuse.delete(ws); // G4: 接続ごとのカウンタ破棄
    const tags = this.state.getTags(ws);
    const tag = tags[0];
    const isSpectator = tag?.startsWith('spectator:');
    const uid = isSpectator ? tag.replace('spectator:', '') : tag;
    console.log(`WebSocket closed: uid=${uid}${isSpectator ? ' (spectator)' : ''}, code=${code}`);

    // 観戦者の切断は通知しない。
    // R33-F-1-01（D-12）: 同じ uid の接続がまだ開いているなら（superseded で古い接続を閉じた・
    // 複数のタブの1つを閉じた）、他のメンバーへ「離脱」を配らない（在席の表示を誤らせない）。
    if (uid && !isSpectator && !this.hasOtherOpenSocketOfUid(uid, ws)) {
      this.broadcast({
        type: 'member_disconnected',
        uid
      }, uid);
    }
  }

  // Hibernation API: WebSocketエラー
  async webSocketError(ws, error) {
    this.wsAbuse.delete(ws); // G4: 接続ごとのカウンタ破棄
    const tags = this.state.getTags(ws);
    const tag = tags[0];
    const isSpectator = tag?.startsWith('spectator:');
    const uid = isSpectator ? tag.replace('spectator:', '') : tag;
    console.error(`WebSocket error: uid=${uid}${isSpectator ? ' (spectator)' : ''}`, error);
  }

  // ============================================================
  // WebSocket message handlers
  // ============================================================

  // 初期化/再接続: 全状態を送信
  async handleWsInit(ws, uid) {
    // G4: initは全履歴送信の重い操作＝正規クライアントは接続ごとに1回。2回目以降は連打カウント
    if (this.strikeIfOverQuota(ws, uid, 'init', 1, 'redundant init')) return;
    const [meta, members, phase, charCounts, phaseTimestamps, phaseEndTime, messages] = await Promise.all([
      this.storage.get('meta'),
      this.storage.get('members'),
      this.storage.get('phase'),
      this.storage.get('charCounts'),
      this.storage.get('phaseTimestamps'),
      this.storage.get('phaseEndTime'),
      this.loadMessages() // Z2: 分割キー対応の読み出し
    ]);

    // 接続中メンバーのUID一覧
    const connectedUids = this.getConnectedUids();
    const memberList = members || [];

    // 全メンバーの投票済み・密告件数・提出済みを集計（誰に投票/密告したかは伏せる）。
    // v3.2: 署名済み発信本体（対象は自己暗号化＝内容は読めない）も配布する
    // — 受信者が受領証明（actionHash）を発行し、観測分を提出物 observed へ同梱するため。
    const votedUids = [];
    // 🔴 P-2026-0823: uid 鍵の辞書は `Object.create(null)`。素の `{}` だと
    //   uid=`__proto__` の**署名済み発信（投票/密告）が配信に乗らない**
    //   （代入が [[Prototype]] 設定に化け `JSON.stringify` に出ない）。
    //   誰も受領証明を出せない＝10分で void ＝ `no_vote` 失格になる。
    const reportCounts = Object.create(null);
    const submittedUids = [];
    const actions = { votes: Object.create(null), reports: Object.create(null) };
    for (const m of memberList) {
      const vote = await this.storage.get(`votes:${m.uid}`);
      if (vote) {
        votedUids.push(m.uid);
        actions.votes[m.uid] = vote;
        const extras = await this.storage.get(`voteExtras:${m.uid}`) || [];
        if (extras.length) actions.votes[`${m.uid}__extras`] = extras;
      }
      const reports = await this.storage.get(`reports:${m.uid}`);
      if (reports && reports.length > 0) {
        reportCounts[m.uid] = reports.length;
        actions.reports[m.uid] = reports;
      }
      const sub = await this.storage.get(`submissions:${m.uid}`);
      if (sub) submittedUids.push(m.uid);
    }

    // ゲームスキップフラグを取得
    const gameSkipped = await this.storage.get('gameSkipped') || null;

    // 参加可能時刻（在席予定/復帰予定）マップ { [uid]: epochMs }
    const availability = await this.storage.get('availability') || {};

    // 在席状態（v3.3追補）: away のメンバーのuid一覧。10分間操作が無いクライアントは
    // away を送ってきて受領証明の発行を止めている＝他メンバー画面では「オフライン」扱いにする。
    const presenceMap = await this.storage.get('presence') || {};
    const awayUids = Object.keys(presenceMap).filter(u => presenceMap[u]?.state === 'away');

    // 一度でもオンラインになったUID一覧（ラベルを「参加予定」→「復帰予定」へ切替えるため）
    const everOnline = await this.storage.get('everOnline') || {};
    const everOnlineUids = Object.keys(everOnline);

    // 状態スナップショット送信
    this.sendTo(ws, {
      type: 'init_response',
      // 決定4: クライアントが端末時計との差を利用者へ知らせるための情報だけを送る。
      // DO の受理判定には使わず、未来時刻を理由に発信を拒否しない。
      serverNow: Date.now(),
      phase: phase || 'init',
      meta,
      members: memberList.map(m => ({
        uid: m.uid,
        addr: m.addr,
        bAddr: m.bAddr,
        lang: m.lang,
        depIds: m.depIds,
        globalIndex: m.globalIndex,
        name: m.name || null,
        img: m.img || null,
        verified: m.verified || false
      })),
      charCounts: charCounts || {},
      messageCounts: await this.storage.get('messageCounts') || {},
      minChars: this.minChars,
      minMessages: this.minMessages,
      maxChars: this.maxChars,
      maxMessages: this.maxMessages,
      maxMsgChars: this.maxMsgChars,
      quiescenceMs: this.quiescenceMs, // §2.5 R3 沈静化窓（workers/.env GAME_QUIESCENCE_MS）
      phaseTimestamps: phaseTimestamps || {},
      phaseEndTime: phaseEndTime || null,
      connectedUids,
      votedUids,
      reportCounts,
      submittedUids,
      actions,
      gameSkipped,
      availability,
      everOnlineUids,
      awayUids,
      // 便 LIKE: 発言へのいいね（署名つき・表示だけ）。この欄があることで、クライアントは WS でも送ってよいと知る
      reactions: await this.collectReactions(memberList),
      activeUids: await this.computeActiveUids()
    });

    // メッセージ履歴送信
    this.sendTo(ws, {
      type: 'message_history',
      messages: messages || []
    });

    // 受領証明履歴送信（既読UX・再接続時の状態復元用。v3.2 §6.3）
    {
      const receipts = await this.loadReceipts();
      this.sendTo(ws, { type: 'receipt_history', receipts });
    }



    // 自分のreport/vote状態送信
    const myReports = await this.storage.get(`reports:${uid}`);
    if (myReports) {
      this.sendTo(ws, {
        type: 'my_reports',
        reports: myReports
      });
    }

    const myVote = await this.storage.get(`votes:${uid}`);
    if (myVote) {
      this.sendTo(ws, {
        type: 'my_vote',
        vote: myVote,
        extras: await this.storage.get(`voteExtras:${uid}`) || []
      });
    }

    // 自分のsubmission状態送信
    const mySubmission = await this.storage.get(`submissions:${uid}`);
    if (mySubmission) {
      this.sendTo(ws, {
        type: 'my_submission',
        submission: { submittedAt: mySubmission.submittedAt }
      });
    }
  }

  // 提出状態の再確認（submit_ack を取りこぼしたクライアントの収束用・読み取りのみ）。
  // init と同じく「提出があるときだけ」返す＝提出直後の問い合わせが遅れて届いても
  // 既に立った提出済み表示を null で巻き戻さない。
  async handleWsGetMySubmission(ws, uid) {
    if (this.strikeIfOverQuota(ws, uid, 'get_my_submission', 10, 'get_my_submission flood')) return;
    const mySubmission = await this.storage.get(`submissions:${uid}`);
    if (!mySubmission) return;
    this.sendTo(ws, {
      type: 'my_submission',
      submission: { submittedAt: mySubmission.submittedAt }
    });
  }

  // チャットメッセージ
  async handleWsChat(ws, uid, data) {
    const phase = await this.storage.get('phase');
    if (phase !== 'chatting') {
      this.sendTo(ws, { type: 'error', message: 'Chat is only available during chatting phase' });
      return;
    }

    let { text, timestamp, signature } = data;
    if (!text || typeof text !== 'string') {
      this.sendTo(ws, { type: 'error', message: 'text is required' });
      return;
    }

    // 🔴 P-2026-0829（2026-08-07）: **採点本体と同じ `isCanonicalTimestamp` を課す。**
    //    旧実装の `!timestamp` は truthy 判定なので、
    //    ① 小数 / 文字列 / 2^53 / `true` といった**非正準 timestamp を受理**し、
    //    ② 正当な `timestamp === 0` を**逆に弾いて**いた（採点本体は P-2026-0822 で 0 を是正済み）。
    //    ①が致命的なのは、DO が受理した発言は**全員へブロードキャストされ**、
    //    受け取った全員の提出物に載るため。採点は正準ゲート（`game-result-calculator.js:936` /
    //    `:844-848`）でその提出物ごと `chathash_mismatch` に落とすので、
    //    攻撃者1人が1発撃つだけで **WS 提出もオンチェーン Evidence 自己救済も同時に閉じる**。
    //    実測: 4人組で `{200,200,200}` → `{0,0,0}`。
    //    ⚠️ 述語は import で共有する（`!timestamp` のような truthy 判定を書き直さないこと）。
    if (!signature || !isCanonicalTimestamp(timestamp)) {
      this.sendTo(ws, { type: 'error', message: 'signature and canonical (safe-integer) timestamp are required' });
      return;
    }

    // 2026-08-04: テキストは正規化しない（protocol-v2.js 冒頭の項を参照）。
    // 署名対象文字列は受け取ったバイト列そのもので構築するため、
    // 送信者が署名した文字列と1バイトでも違えば下の署名検証で落ちる。
    const ctx = await this.getProtocolContext();

    // K-S2-003（2026-07-27）: 可視内容がゼロ（不可視文字だけ／空）の発言は受け付けない。
    // 採点側でも数えないが、送信時に弾いて「送れたのに0文字扱いだった」という
    // 事故を防ぐ（P2P 経由は迂回できるため、採点側の規則が最終的な砦）。
    if (stripInvisibleChars(text).length === 0) {
      this.sendTo(ws, { type: 'error', message: 'message has no visible content' });
      return;
    }

    // 1メッセージ上限（半角換算。全角は2とカウント）
    const msgChars = countHalfWidthChars(text);
    if (msgChars > this.maxMsgChars) {
      if (this.strikeWs(ws, uid, 'msg_too_long')) return; // G4: 上限超は連打カウント
      this.sendTo(ws, { type: 'error', code: 'msg_too_long', message: `Message too long (max ${this.maxMsgChars} half-width chars)` });
      return;
    }

    // G4是正: 量キャップは署名検証（重いECDSA）より先に安く弾く。旧実装は検証→上限の順
    // だったため、上限到達後の「有効署名スパム」に毎回検証CPUを払っていた。
    // 🔴 P-2026-0823: 素の `{}` のままだと uid=`__proto__` で `charCounts[uid]` /
    //   `messageCounts[uid]` が `Object.prototype` になり、比較が文字列 vs 数値＝false
    //   ＝ **量キャップがその uid だけ消える**（P-2026-0821 の NaN 経路と同じ結果）。
    const charCounts = uidMap(await this.storage.get('charCounts'));
    const messageCounts = uidMap(await this.storage.get('messageCounts'));
    if ((messageCounts[uid] || 0) + 1 > this.maxMessages) {
      if (this.strikeWs(ws, uid, 'over max_messages')) return;
      this.sendTo(ws, { type: 'error', code: 'max_messages_reached', message: `Message limit reached (max ${this.maxMessages} messages)` });
      return;
    }
    if ((charCounts[uid] || 0) + msgChars > this.maxChars) {
      if (this.strikeWs(ws, uid, 'over max_chars')) return;
      this.sendTo(ws, { type: 'error', code: 'max_chars_reached', message: `Character limit reached (max ${this.maxChars} half-width chars)` });
      return;
    }

    // 署名検証: メンバーのblockAddressで検証
    const members = await this.storage.get('members') || [];
    const member = members.find(m => m.uid === uid);
    // P-2026-0829: 生の `JSON.parse` をやめ、採点本体と同じ `parseBlockAddress` に合流させる。
    // 壊れた `bAddr`（`'{'` / `'not-json'` / `'[]'` / `'123'`）は例外ではなく既存の
    // 'Member block address not found' 分岐で落とす（`Internal error` にしない）。
    const bAddr = parseBlockAddress(member?.bAddr);
    if (!member || !bAddr) {
      this.sendTo(ws, { type: 'error', message: 'Member block address not found' });
      return;
    }

    // §2.6正準形（type/blockNum/groupId束縛・C6）。署名鍵はsignKey（登録pubKeyで検証）
    const dataString = chatSignStringV2(ctx.blockNum, ctx.groupId, uid, text, timestamp);

    // 🔴 P-2026-0836（2026-08-08・ラウンド19 判断不要-2）: **署名の正準性（形式＋low-s）は
    //    `verifyMessage` と同じ場所で課す**（＝既存の「無効署名」経路に合流させる）。
    //    P-2026-0829 は同じ6箇所に `isCanonicalTimestamp` を入れたが、`signature` は
    //    truthy 判定のまま残っていた（是正前は
    //    `grep -c isCanonicalSignature workers/game_workers/chat-game-DO.js` = **0**）。
    //    採点正典（`game-result-calculator.js:1238` の `isCanonicalSignature`）と
    //    Rust（`crates/scoring-core/src/receipts.rs:186` の `is_low_s`）は high-s の
    //    「双子」を落とすのに、ライブ層は viem `verifyMessage` 1本だけで **双子に true を返す**
    //    （`protocol-v2.js:117-122` のコメントが自ら明記）。
    //    ＝ 3経路の割れではなく「ライブ層 vs 採点層」の割れで、block-verifier も ZKP も鳴らない。
    //    実測（3人組・巡回投票）: 本物 low-s なら {200,200,200}、high-s 双子だと
    //    {0(no_vote),100,200}。DO は `*_ack` を返し `rcpt:{keccak(sig)}` へ**永続保存**
    //    （本物と keccak が別なので冪等排除もすり抜ける）、`receipt_history` で再配布する。
    //    標的の画面は「投票: 完了」のままで**再送導線が出ない**。
    //    ⚠️ **早期ゲート（`if (!signature || …)` の並び）には入れない。** そこに入れると
    //       `strikeWs` を通らず、無効署名の連打で切断されなくなる（G4 の連打対策が空振り）
    //       ／投票・密告の件数上限より先に落ちて安いチェックの順序も崩れる。
    //    ⚠️ 過剰遮断ゼロ: viem `signMessage` 500サンプルで high-s は **0件**。
    try {
      const valid = isCanonicalSignature(signature) && await verifyMessage({
        address: bAddr.address,
        message: dataString,
        signature
      });

      if (!valid) {
        if (this.strikeWs(ws, uid, 'invalid chat signature')) return; // G4: 無効署名は連打カウント
        this.sendTo(ws, { type: 'error', message: 'Invalid message signature' });
        return;
      }
    } catch (err) {
      console.error(`Signature verification error for uid=${uid}:`, err.message);
      if (this.strikeWs(ws, uid, 'chat signature verification error')) return; // G4
      this.sendTo(ws, { type: 'error', message: 'Signature verification failed' });
      return;
    }

    // 文字数カウント（半角換算・上でチェック済みの値を再利用。キャップは署名検証前に確認済み）
    const charCount = msgChars;

    // メッセージID取得・インクリメント
    let counter = await this.storage.get('messageCounter') || 0;
    counter++;
    await this.storage.put('messageCounter', counter);

    // メッセージ作成（クライアントのtimestampと署名を保存）
    const message = {
      id: counter,
      uid,
      text,
      timestamp,
      charCount,
      signature
    };

    // メッセージ保存（Z2是正: 1発言=1キー。旧「全履歴を読み直して丸ごと書き戻す」方式は
    // 128KiB/値の上限にゲーム規定量内で到達し、以降の全発言が失敗していた）
    await this.storage.put(this.msgKey(counter), message);

    // 文字数・件数カウント更新
    charCounts[uid] = (charCounts[uid] || 0) + charCount;
    messageCounts[uid] = (messageCounts[uid] || 0) + 1;
    await this.storage.put('charCounts', charCounts);
    await this.storage.put('messageCounts', messageCounts);

    // 全員にブロードキャスト
    this.broadcast({
      type: 'chat',
      message,
      charCounts,
      messageCounts
    });

    // G7: 観戦スナップショット更新（30秒debounce・失敗は握る）
    await this.publishLiveSnapshot();
  }

  // ============================================================
  // 受領証明（v3.2 §6.3）: メンバーのsignKey署名による既読/アクション受領証明の中継。
  // サーバーは配送経路の一つにすぎず、サーバー自身は受領証明を発行しない
  // （サーバー証明は運営鍵署名＝運営バックデートの穴になるため存在しない）。
  // 検証の上で保存（再接続時のreceipt_history復元用）し、グループ全員へブロードキャストする。
  //   既読受領証明:       { receiverUid, senderUid, msgRefs[], timestamp, signature }
  //   アクション受領証明: { receiverUid, actionHash, timestamp, signature }
  // ============================================================
  async handleWsReceipt(ws, uid, data) {
    const receivedAt = Date.now();
    const phase = await this.storage.get('phase');
    if (phase !== 'chatting') {
      this.sendTo(ws, { type: 'error', message: 'Receipts are only available during chatting phase' });
      return;
    }

    const rc = data.receipt;
    // 🔴 P-2026-0829（2026-08-07）: **採点本体（`game-result-calculator.js:1252`）と同じ
    //    `isCanonicalTimestamp` を課す。** 旧実装は `== null` だけで、小数 / 文字列 / 2^53 の
    //    受領証明を**中継していた**。標的の投票を覆う唯一の受領証明をこの形で発行すると、
    //    標的の画面には「受領済み」と出るのに採点だけが void にする＝**標的型の冤罪**になる。
    //    実測: 4人組で `{200,200,200}` → `{0(no_vote), 100, 200}`（攻撃者は自損ゼロ）。
    if (!rc || typeof rc !== 'object' || !rc.signature || !isCanonicalTimestamp(rc.timestamp)) {
      this.sendTo(ws, { type: 'error', message: 'receipt object with signature and canonical (safe-integer) timestamp is required' });
      return;
    }
    // 自分の受領証明のみ中継可能（receiverUid = 接続uid）
    if (rc.receiverUid !== uid) {
      if (this.strikeWs(ws, uid, 'receipt uid mismatch')) return;
      this.sendTo(ws, { type: 'error', message: 'receiverUid must match your uid' });
      return;
    }
    // C7-02: loadMessages() と署名検証より前で、受領証明の重い前段を接続単位に有界化する。
    // RT3-01 の永続枠・増分0 no-op は別 opKey のまま維持し、正直な理論最大≈484通に余裕を持たせる。
    if (this.strikeIfOverQuota(ws, uid, 'receipt_ingress', WS_FREE_RECEIPTS * 2, 'receipt ingress spam')) return;
    const members = await this.storage.get('members') || [];
    const member = members.find(m => m.uid === uid);
    // P-2026-0829: 生の `JSON.parse` をやめ、採点本体と同じ `parseBlockAddress` に合流させる。
    const bAddr = parseBlockAddress(member?.bAddr);
    if (!member || !bAddr) {
      this.sendTo(ws, { type: 'error', message: 'Member block address not found' });
      return;
    }
    const ctx = await this.getProtocolContext();

    // 種別判定＋署名検証（signKey＝登録pubKey）
    let dataString = null;
    let kind = null;
    if (Array.isArray(rc.msgRefs) && rc.senderUid != null) {
      if (rc.senderUid === uid) {
        this.sendTo(ws, { type: 'error', message: 'Cannot issue read receipt for own messages' });
        return;
      }
      if (!members.some(m => m.uid === rc.senderUid)) {
        this.sendTo(ws, { type: 'error', message: 'senderUid is not a member' });
        return;
      }
      // Q-S2-001: 1枚に入れられる msgRef の上限を採点エンジンと同じ値に揃える。
      // 旧実装は 500 固定で、提出物の経路には上限が無かった（＝2経路で値が食い違っていた）。
      if (rc.msgRefs.length === 0 || rc.msgRefs.length > receiptMaxRefsPerReceipt(this.maxMessages)) {
        this.sendTo(ws, { type: 'error', message: 'Invalid msgRefs batch size' });
        return;
      }
      // 参照は msgKey の先頭16バイト。旧8バイト／32バイト形式はここで落ちる。
      if (!rc.msgRefs.every(isMsgRef)) {
        this.sendTo(ws, { type: 'error', message: 'msgRefs must be 16-byte hex refs' });
        return;
      }
      if (rc.msgRefs.some((ref, i) => i > 0 && compareHexAsc(rc.msgRefs[i - 1], ref) >= 0)) {
        this.sendTo(ws, { type: 'error', message: 'msgRefs must be strictly sorted and unique' });
        return;
      }
      dataString = readReceiptSignString(ctx.blockNum, ctx.groupId, uid, rc.senderUid, rc.msgRefs, rc.timestamp);
      kind = 'read';
    } else if (rc.actionHash !== undefined) {
      // K-S6-002（2026-07-29）: actionHash は keccak256 の出力＝0x + 64桁hex に固定。
      // 旧実装は `typeof === 'string'` だけで**任意長の文字列**を受理しており、
      // 4,096文字の乱数を200枚流すだけで他メンバーの提出物が1MBを超え、
      // WS提出（DOの単一値128KiB）もオンチェーン提出（gzip後128KB）も同時に不能になった。
      if (!isActionHash(rc.actionHash)) {
        this.sendTo(ws, { type: 'error', message: 'actionHash must be 0x + 64 hex' });
        return;
      }
      dataString = receiptSignString(ctx.blockNum, ctx.groupId, uid, rc.actionHash, rc.timestamp);
      kind = 'action';
    } else {
      this.sendTo(ws, { type: 'error', message: 'receipt must have msgRefs+senderUid or actionHash' });
      return;
    }

    // K-S6-005（2026-07-29）: 参照先の発信時刻から ±10分を外れた受領証明は中継しない。
    // 採点は元から ±10分で篩っていたが、サーバーもクライアントも見ていなかったため、
    // 「署名は正しいが時刻を11分ずらした受領証明」だけで被害者の画面を『条件達成』に見せ、
    // 失格へ誘導できた。ここは**正典ではなく早期フィードバック**（改造クライアントは
    // P2P で迂回できるので、本丸はクライアント側の判定＝buildReceiptMaps）。
    // 参照先を知らない場合は素通しする（サーバーが知らないだけで無効化すると、
    // 運営が『知らないふり』をして正当な受領証明を潰す検閲レバーになる）。
    if (!(await this.isReceiptTimelyForTarget(rc, kind))) {
      this.sendTo(ws, { type: 'error', message: 'Receipt timestamp is outside the ±10min window of its target' });
      return;
    }

    let valid = false;
    try {
      valid = isCanonicalSignature(rc.signature)
        && await verifyMessage({ address: bAddr.address, message: dataString, signature: rc.signature });
    } catch {
      valid = false;
    }
    if (!valid) {
      if (this.strikeWs(ws, uid, 'invalid receipt signature')) return;
      this.sendTo(ws, { type: 'error', message: 'Invalid receipt signature' });
      return;
    }

    // 🔴 P-2026-0840（2026-08-08・ラウンド19 判断不要-8）: **保存・中継の前に既知フィールドだけへ正規化する。**
    //
    //    `readReceiptSignString` / `receiptSignString` の署名対象は
    //    (blockNum, groupId, receiverUid, senderUid, msgRefs, timestamp) / (…, actionHash, …) だけで、
    //    **それ以外のフィールドは署名に覆われておらず、長さの検査もどこにも無かった**。
    //    旧実装は検証を通った `rc` オブジェクトを**そのまま** `rcpt:{keccak(sig)}` へ put し、
    //    そのまま全員へ中継していた。
    //    実測（junk = 100KiB の未署名フィールド1つ・3人組）:
    //      DO: relayed=true / receipt_ack / 保存値 102,653B（単値上限 131,072 の内側）
    //      正直者 p1 の生バンドル: 5枚 531,458 / 12枚 1,250,036 / 20枚 2,071,268
    //                            / **21枚 2,173,922 > 2,097,152（Evidence の上限）**
    //      21枚時の gzip は 13,574（EVIDENCE_MAX_DATA_BYTES=130,000 の内側＝容量ゲートは鳴らない）
    //      `planOnChainTrim`: 20枚 null / **21枚 IMPOSSIBLE**（受領証明は削れない）
    //      40枚時の `rcpt:*` 合計 4,106,120B を `receipt_history` が再接続のたび1回の sendTo で送る
    //
    //    署名対象に入っていないフィールドは**定義上「情報を持たない」**（採点も Rust も
    //    既知フィールドしか読まない）ので、落としても正典は1ビットも変わらない。
    //    中継されるバイト列が痩せるので、**クライアント側は何もしなくても救われる**。
    //
    //    ⚠️ P2P 側は既に正規化済み（`src/utils/relay.js` の `_handleReceipt` と
    //       `useGameWebSocket.js` の `onSelfAction` が作り直している）。未正規化の入口は
    //       DO の broadcast と `receipt_history` の2つだけなので、**DO 側1点で閉じる**。
    //    ⚠️ **これは DoS を閉じない。** 同じ `IMPOSSIBLE` には、未署名フィールドを一切使わず
    //       正しく署名された `encrypted` 1,200,000 文字の密告2通でも到達できる
    //       （`isOpaqueField` に長さ上限が無いため・台帳 J-30/J-24 の判断待ち）。ここは衛生。
    const rcNorm = kind === 'read'
      ? { receiverUid: rc.receiverUid, senderUid: rc.senderUid, msgRefs: rc.msgRefs, timestamp: rc.timestamp, signature: rc.signature }
      : { receiverUid: rc.receiverUid, actionHash: rc.actionHash, timestamp: rc.timestamp, signature: rc.signature };

    // 署名ハッシュキーで冪等保存（重複中継はno-op）
    const rcptKey = `rcpt:${keccak256(rc.signature)}`;
    const exists = await this.storage.get(rcptKey);
    if (!exists) {
      // S3-005（2026-07-29）: **永続の総量上限**。
      // 接続ごとの無料枠（WS_FREE_RECEIPTS）は切断・再接続でリセットされるため、
      // 「形式は正しいが実在しない msgRef」を時刻違いで作り続けるだけで rcpt:* が
      // 無限に増やせた（署名は自分の signKey なので何枚でも正当に作れる）。
      // 溜まった受領証明は /get-results にそのまま載り、結果集計ユニットの取得で
      // メモリを食い潰す → K-S2-004 の fail-closed により**ブロック全体が park** する、
      // つまりメンバー1人が決済を止められる状態だった。
      const quotaResult = await this.reserveReceiptQuota(rc, kind);
      if (!quotaResult) {
        // RT3-01: 枠切れは正典が受理する既読でも起こりうるため strike に積まない。
        // 1008切断 → 429接続拒否 → WS提出不能（no_submit）への連鎖を防ぐ。
        this.sendTo(ws, { type: 'error', message: 'Receipt quota for this pair is exhausted' });
        return;
      }
      if (quotaResult === RECEIPT_QUOTA_DUPLICATE) {
        // 同じペアで既に覆っている ref だけなら、正常な冪等 no-op とする。
        // 枠・保存・broadcast のいずれも消費しない。
        this.sendTo(ws, { type: 'receipt_ack', kind });
        return;
      }
      // 署名の振り直しで storage.list の鍵順を選べないよう、受理順を保存値に固定する。
      const write = (this._receiptOrderTail || Promise.resolve()).catch(() => {}).then(async () => {
        const receiveOrder = (await this.storage.get('rcpt_receive_order') || 0) + 1;
        await this.storage.put('rcpt_receive_order', receiveOrder);
        await this.storage.put(rcptKey, { ...rcNorm, _receivedSeq: receiveOrder, _receivedAt: receivedAt });
      });
      this._receiptOrderTail = write;
      await write;
      // 全員へブロードキャスト（発行者の他タブにも届くよう除外なし）
      this.broadcast({ type: 'receipt', receipt: { ...rcNorm, _receivedAt: receivedAt } });
      // G4: 永続化した新規受領証明だけを接続ごとの無料枠へ数える。
      // 増分0の冪等 no-op と永続枠切れは strike を一切消費しない。
      if (this.strikeIfOverQuota(ws, uid, 'receipt', WS_FREE_RECEIPTS, 'receipt spam')) return;
    }

    this.sendTo(ws, { type: 'receipt_ack', kind });

    // G7: 観戦スナップショット更新（30秒debounce・失敗は握る）。受領証明でも更新するのは、
    // 発言/発信の直後に生成されたスナップショットには受領証明がまだ載っておらず、次の発言まで
    // （＝会話が止まると何分でも）観戦画面が「受領なし」のまま固まってしまうため。
    // 観戦画面は v3.3 の表示ルール（受領≥1 or 発信から10分以内）をスナップショット時刻基準で
    // 判定するので、受領証明が遅れて届くほど「既読で確定した発言」が pending 表示に留まる。
    await this.publishLiveSnapshot();
  }

  // K-S6-005: 受領証明が参照先（発言 or 発信）の主張時刻から ±10分以内かを、
  // サーバーが知っている範囲で確認する。**知らない参照は true（素通し）**。
  //   - 既読: 送信者の発言のうち、その msgRef を持つものが1件でも ±10分内なら有効
  //   - 行動: 保存済みの投票・密告の actionHash と突き合わせる
  async isReceiptTimelyForTarget(rc, kind) {
    try {
      const ctx = await this.getProtocolContext();
      if (kind === 'read') {
        const msgs = await this.loadMessages();
        const refs = new Set(rc.msgRefs);
        let known = false;
        for (const m of msgs) {
          if (m.uid !== rc.senderUid) continue;
          if (!refs.has(msgRefOf(computeMsgKeyV2(ctx.blockNum, ctx.groupId, m)))) continue;
          known = true;
          if (isReceiptTimely(rc.timestamp, m.timestamp)) return true;
        }
        return !known; // 参照先を1件も知らないなら判断しない（素通し）
      }
      // kind === 'action'
      const members = await this.storage.get('members') || [];
      for (const m of members) {
        const vote = await this.storage.get(`votes:${m.uid}`);
        const cands = [];
        if (vote) cands.push({ type: 'vote', uid: m.uid, a: vote });
        for (const extra of (await this.storage.get(`voteExtras:${m.uid}`) || [])) {
          cands.push({ type: 'vote', uid: m.uid, a: extra });
        }
        for (const rep of (await this.storage.get(`reports:${m.uid}`) || [])) {
          cands.push({ type: 'report', uid: m.uid, a: rep });
        }
        for (const c of cands) {
          if (!c.a?.encrypted || c.a.timestamp == null) continue;
          const h = actionHashV2(c.type, ctx.blockNum, ctx.groupId, c.uid, c.a.encrypted, c.a.timestamp);
          if (h !== rc.actionHash) continue;
          return isReceiptTimely(rc.timestamp, c.a.timestamp);
        }
      }
      return true; // 参照先の発信を知らない（P2P 先行など）＝判断しない
    } catch {
      return true; // 判定できないときは通す（サーバー都合で正当な受領証明を落とさない）
    }
  }

  // S3-005: 受領証明の**永続**総量上限。新規保存の直前に1件だけ枠を確保する。
  // 戻り値は true=確保、false=枠切れ、RECEIPT_QUOTA_DUPLICATE=正常な増分0 no-op。
  //
  // 上限は Q-S2-001 と同じ考え方で「正当に存在しうる最大」から導く（恣意的な数字を作らない）:
  //   ・既読: (受領者, 発信者) ペアごとに distinct msgRef 数 ≤ GAME_MAX_MESSAGES。
  //     さらに保存バイト数を縛るため、延べ msgRef 数 ≤ GAME_MAX_MESSAGES × 3 とする。
  //     distinct 集合は `rcpt:` と混ざらないペア別キーへ保存し、純粋な重複は保存も中継もしない。
  //   ・行動受領: 受領者ごとに「正典が受理しうる最大」＝
  //     2種別 × (グループ人数−1) × receiptMaxActionsPerPair(グループ人数)
  //     （P-2026-0832。下の `else` 節のコメントに導出と経緯）。
  //
  // **押し出し（A4）は起きない**: 枠は「受領証明を出した本人（receiverUid）」ごとに
  // 独立しているため、攻撃者が使い切れるのは自分の枠だけである。
  //
  // **正直な参加者が損をすることも無い**: クライアントは送信前に自分の state へ
  // 取り込む（ingestReceipt）ので、サーバーが中継を断っても自分の提出物には残る。
  // さらに P2P リレーにも同じものが流れる。正典は全提出物の union なので消えない。
  async reserveReceiptQuota(rc, kind) {
    const members = await this.storage.get('members') || [];
    const groupSize = Math.max(1, members.length);
    // 🔴 P-2026-0823 の取りこぼし（2026-08-08・修正B）: **uid 添字の辞書は `uidMap()` を通す。**
    //   同ファイルの他の uid 添字マップ（`charCounts` / `messageCounts` / `everOnline` /
    //   `availability` / `presence`）は全部 `uidMap()` 経由だが、
    //   ここ**だけ**素の `{}` のままだった。uid を割り当てるのは運営なので
    //   `__proto__` / `toString` / `constructor` / `valueOf` は「運営が任意の参加者に
    //   付けられる値」であり、素の `{}` は uid ごとに別々の壊れ方をする（実測・6人組=上限60）:
    //     ・`__proto__`   → `counts['__proto__']` が `Object.prototype` を返し、
    //       `slot.action` が `undefined` ＝ `NaN > cap` が **false** で**上限が消える**。
    //       しかも `slot.action += 1` が **`Object.prototype.action = NaN`** ＝
    //       アイソレート全体を汚染する（同 DO の他の判定にも波及する）
    //     ・`toString` / `constructor` / `valueOf` → `slot` が **関数**になり、
    //       `storage.put` の V8 直列化が `DataCloneError`。
    //       ＝ その uid は **WS 経由で受領証明を1枚も中継できない**（既読も行動も 0/60）
    //     ・既読側は `slot.read[sender]` が `undefined[...]` で `TypeError`
    //   終着点は S3-005 のコメントが書いているとおり修正Aと同じ（溜まった受領証明が
    //   `/get-results` に載り、K-S2-004 の fail-closed で**ブロック全体が park**）。
    //   既存レコードのために**読み出し側でも**正規化する（`slot.read` も含めて）。
    const counts = uidMap(await this.storage.get('rcpt_counts'));
    const receiver = String(rc.receiverUid);
    const slot = Object.prototype.hasOwnProperty.call(counts, receiver)
      ? counts[receiver]
      : { read: Object.create(null), action: 0 };
    slot.read = uidMap(slot.read);

    if (kind === 'read') {
      const sender = String(rc.senderUid);
      // `rcpt:` は loadReceipts() の列挙対象なので、添字は必ず別 prefix にする。
      // uid は ASCII 印字可能文字に限定され、区切りの \x1f を含まない。
      const refsKey = `rcptrefs:${receiver}\x1f${sender}`;
      const storedRefs = await this.storage.get(refsKey);
      const covered = new Set(Array.isArray(storedRefs) ? storedRefs : []);
      let newRefCount = 0;
      for (const ref of rc.msgRefs) {
        if (covered.has(ref)) continue;
        covered.add(ref);
        newRefCount += 1;
      }

      // 時刻違い再発行など、既に覆った ref だけの受領証明は正常な no-op。
      if (newRefCount === 0) return RECEIPT_QUOTA_DUPLICATE;
      if (covered.size > this.maxMessages) return false;

      const rawUsed = slot.read[sender] || 0;
      const rawBudget = this.maxMessages * RECEIPT_PAIR_RAW_REF_FACTOR;
      if (rawUsed + rc.msgRefs.length > rawBudget) return false;
      slot.read[sender] = rawUsed + rc.msgRefs.length;
      counts[receiver] = slot;
      // 安全側に倒すため延べカウンタを先に保存する。ref集合はペアごとに分離し、
      // 受領証明1通ごとに全ペアの集合を書き戻さない。
      await this.storage.put('rcpt_counts', counts);
      await this.storage.put(refsKey, [...covered].sort(compareHexAsc));
      return true;
    } else {
      // 🔴 P-2026-0832（2026-08-08）: **枠の判定は `receiptMaxActionsPerPair()` から導く。**
      //   旧実装は `RECEIPT_MAX_ACTIONS_PER_PAIR * groupSize` と書いていたが、その定数には
      //   `protocol-v2.js` 側に「互換のため残す。**枠の判定には使わないこと**」と明記されている
      //   （現在は行動受領証明の基数としてだけ使う）。いまは数値が一致するので
      //   差は出ないが、正典が形を変えた瞬間に DO だけ黙ってずれる。
      //
      //   併せて**数え方の食い違い**も塞ぐ。正典（採点本体 `game-result-calculator.js` の
      //   `pairKey = 受領者␟a␟種別␟発信者` / Rust `crates/scoring-core/src/receipts.rs`）は
      //   **(受領者, 種別, 発信者) ごと**に `receiptMaxActionsPerPair(groupSize)` 件を受理する。
      //   DO は**受領者ごとの合計**で数えていたため、5人組で
      //     DO   … 50 件で飽和
      //     正典 … 2種別 × 他4人 × 50 ＝ 400 件まで受理
      //   と DO のほうが 8 倍きつく、**正典が受理する受領証明を DO が先に拒否**していた。
      //   拒否は `strikeWs`（連打カウント）に載るので、正直な参加者が再送の巻き添えで
      //   1008 切断 → 窓内3回で**接続拒否（429）**まで行き着く。提出は WS 経路なので、
      //   そこまで行くと `no_submit` で全損し、その人の投票先も巻き添えでボーナスを失う。
      //   正常系（他4人 ×（投票1 + 密告2）＝ 12件）では届かないが、void 後の再送が
      //   絡むと 50 は現実に届く（1人あたり最大 投票10 + 密告10 ＝ 20 件が正典側で有効）。
      //
      //   ⚠️ DO は `rc.actionHash` から (種別, 発信者) を**常には解決できない**
      //      （P2P 先行の発信はサーバーに無い＝`isReceiptTimelyForTarget` が素通しする理由と同じ）。
      //      正典と同じキーを作ろうとすると「DO だけが持つ第三の規則」になるので、
      //      バケツは受領者ごとの合計のまま、**上限を正典が受理しうる最大**へ揃える
      //      ＝ 2種別 × 自分以外のメンバー数 × `receiptMaxActionsPerPair(groupSize)`。
      //      こうすると「DO が正典より先に飽和する」ことが構造的に起きない。
      //   ⚠️ ここは**保存量の制御であって採点の正典ではない**（正典は全提出物の union）。
      //      枠を広げても採点結果は1ビットも変わらない — サーバーが中継を断っても
      //      受領証明はクライアントの提出物と P2P リレーに残る（S3-005 のコメント参照）。
      const cap = 2 * Math.max(1, groupSize - 1) * receiptMaxActionsPerPair(groupSize);
      if (slot.action + 1 > cap) return false;
      slot.action += 1;
    }

    counts[receiver] = slot;
    await this.storage.put('rcpt_counts', counts);
    return true;
  }

  // 保存済み受領証明を DO の受理順で返す。旧保存値は鍵順で先頭に置く。
  async loadReceipts() {
    const map = await this.storage.list({ prefix: 'rcpt:' });
    return [...map.entries()]
      .sort(([ak, a], [bk, b]) => (a?._receivedSeq || 0) - (b?._receivedSeq || 0)
        || (ak < bk ? -1 : ak > bk ? 1 : 0))
      .map(([, { _receivedSeq, ...receipt }]) => receipt);
  }

  // 参加可能時刻（在席予定/復帰予定）設定
  // 開始待機〜チャット期間のみ。各自が「次にオンラインになる予定の時刻」をエポックms(UTC絶対時刻)で登録。
  // null/未指定でクリア。オンライン中に「オンライン」と表示するかは閲覧側(フロント)で判定する。
  async handleWsSetAvailability(ws, uid, data) {
    const phase = await this.storage.get('phase');
    if (phase !== 'waiting' && phase !== 'chatting') {
      this.sendTo(ws, { type: 'error', message: 'Availability can only be set during waiting or chatting phase' });
      return;
    }

    // G4: 署名なしで保存＋全員配信が走る操作。予定変更は正規でも数回あるため無料枠10、超過は連打カウント
    if (this.strikeIfOverQuota(ws, uid, 'availability', WS_FREE_AVAILABILITY, 'availability spam')) return;

    let availableAt = data.availableAt;
    if (availableAt === null || availableAt === undefined || availableAt === '') {
      availableAt = null;
    } else {
      availableAt = Number(availableAt);
      const now = Date.now();
      // 妥当な範囲（過去1分〜未来48h）のみ許可。範囲外・非数は不正値として拒否
      if (!Number.isFinite(availableAt) || availableAt < now - 60 * 1000 || availableAt > now + 48 * 60 * 60 * 1000) {
        this.sendTo(ws, { type: 'error', message: 'Invalid availableAt' });
        return;
      }
    }

    const availability = uidMap(await this.storage.get('availability')); // P-2026-0823
    if (availableAt === null) {
      delete availability[uid];
    } else {
      availability[uid] = availableAt;
    }
    // 便 PLAYAT（2026-11-25）: 本人が WS で設定・クリアした uid には印を立て、後から届く
    // 「先に設定した値」（/seed-availability）を入れない。本人がここで消した値が、遅れて届いた
    // 古い値で戻るのを防ぐ。印は `availability` と同じ1回の put で書く（片方だけ書けた状態を作らない）。
    const availabilitySeedClosed = uidMap(await this.storage.get('availabilitySeedClosed'));
    availabilitySeedClosed[uid] = true;
    await this.storage.put({ availability, availabilitySeedClosed });

    // 全員に反映（冪等なので除外なし＝送信者の他タブにも届く）
    this.broadcast({
      type: 'availability_update',
      uid,
      availableAt
    });

    console.log(`Availability set by ${uid}: ${availableAt}`);
  }

  // 便 PLAYAT（2026-11-25）: 先に設定した参加予定時刻の受け取り口（GameMasterDO から・API_SECRET 必須）。
  // 利用者がエントリーの時かマイページで入れた値（`users.entry_blocks[N].playAt`）を、GameMasterDO が
  // 初期化の後に集めて `{ availability: { uid: エポックms } }` で渡す。署名なし・採点に無関係の表示だけの値。
  // 🔴 上書きしない（依頼書 I5）: 入れるのは、名簿のメンバーで、まだ値が無く、本人が WS で触っておらず、
  //    前に渡したことも無い uid だけ。本人が今の画面で入れた・消した値の方が新しいので、そちらを残す。
  // 🔴 名簿のメンバーを回す（本文の鍵を回さない）。本文は API_SECRET を持つ呼び手が作るが、
  //    大きさに関係なく手数を名簿の人数までにしておく。
  async handleSeedAvailability(request) {
    let body;
    try {
      body = await request.json();
    } catch {
      return createCORSResponse({ error: 'Request body must be JSON' }, 400);
    }
    const incoming = body?.availability;
    if (incoming === null || typeof incoming !== 'object' || Array.isArray(incoming)) {
      return createCORSResponse({ error: 'availability object is required' }, 400);
    }
    // ここから下で await するのは storage の読み書きだけ（本文の読みは上で済ませた）。
    // 読んでから書くまでの間に WS の `set_availability` が割り込むと、本人の操作を古い写しで潰すため。
    if (await this.storage.get(INVALIDATED_NO_GAME_KEY)) {
      return createCORSResponse({ error: 'Timeline no-game is terminal' }, 409);
    }
    const phase = await this.storage.get('phase');
    if (phase !== 'waiting' && phase !== 'chatting') {
      // 参加予定時刻を出すのは開始待機とチャット中だけ（WS の口と同じ）。失敗ではないので 200 で返す。
      return createCORSResponse({ success: true, applied: 0, skipped: 'phase' });
    }

    const members = await this.storage.get('members');
    const availability = uidMap(await this.storage.get('availability')); // P-2026-0823
    const availabilitySeedClosed = uidMap(await this.storage.get('availabilitySeedClosed'));
    // チャット中に一度オンラインになった人は「復帰予定」の扱いで、接続の時に予定時刻を消している。
    // 開始前に入れた値を、その後から戻さない。
    const everOnline = phase === 'chatting' ? uidMap(await this.storage.get('everOnline')) : null;
    const phaseEndTime = await this.storage.get('phaseEndTime');
    const periodDurations = await this.storage.get('periodDurations');

    // 外枠は WS の口と同じ（過去1分〜未来48h）。その内側を、読めるならチャットの窓で狭める。
    //   waiting : phaseEndTime＝宣言のチャット開始 → [開始, 開始 + gamePeriod]
    //   chatting: phaseEndTime＝チャットの終わり   → 終わり以下
    // 窓が読めないとき（手動の遷移で phaseEndTime が null など）は外枠だけで見る。
    // 反証 PA-R02: waiting で窓が読めるとき、開始より前（開始−8日まで）の値は「開始から参加」と読み、
    //   開始時刻へ寄せてから同じ検査を当てる。初期化より前に grace が延長されると、エントリーの時に入れた
    //   値（札の既定の「開始ちょうど」など）が新しい開始より前になり、黙って捨てられていたため。
    //   寄せるのは waiting だけ（chatting の phaseEndTime はチャットの終わりで、過去の値は今までどおり入れない）。
    //   寄せた値をそのまま保存するので、開始時刻が安全な整数のときだけ寄せる。
    const now = Date.now();
    let earliest = now - 60 * 1000;
    let latest = now + 48 * 60 * 60 * 1000;
    let clampStart = null;
    const endTimeReadable = Number.isFinite(phaseEndTime) && phaseEndTime > 0;
    if (phase === 'waiting') {
      const gamePeriod = periodDurations?.gamePeriod;
      if (endTimeReadable && Number.isFinite(gamePeriod) && gamePeriod > 0) {
        earliest = Math.max(earliest, phaseEndTime);
        latest = Math.min(latest, phaseEndTime + gamePeriod);
        if (Number.isSafeInteger(phaseEndTime)) clampStart = phaseEndTime;
      }
    } else if (endTimeReadable) {
      latest = Math.min(latest, phaseEndTime);
    }

    const applied = [];
    for (const member of Array.isArray(members) ? members : []) {
      const uid = member?.uid;
      // 自分の鍵としてあるときだけ見る（`toString` などプロトタイプ由来の値を拾わない）。
      if (typeof uid !== 'string' || !Object.hasOwn(incoming, uid)) continue;
      if (availabilitySeedClosed[uid] || availability[uid] != null) continue;
      if (everOnline && everOnline[uid]) continue;
      let value = incoming[uid];
      if (!Number.isSafeInteger(value)) continue;
      // PA-R02: 開始より前の値を開始へ寄せる。寄せた後の値にも下の検査をそのまま当てるので、
      // 開始が今−60秒より前（遷移が遅れている）なら今までどおり入らない。保存と配信は寄せた後の値。
      if (clampStart !== null && value < clampStart && value >= clampStart - AVAILABILITY_SEED_CLAMP_REACH_MS) {
        value = clampStart;
      }
      if (value < earliest || value > latest) continue;
      availability[uid] = value;
      availabilitySeedClosed[uid] = true; // 一度渡した uid には二度と入れない（値が後で消えても、再送で戻さない）
      applied.push([uid, value]);
    }
    if (applied.length === 0) {
      return createCORSResponse({ success: true, applied: 0 });
    }

    // 値と印は1回の put で書く（片方だけ書けた状態を作らず、「渡した uid には必ず印がある」を保存の上でも保つ）。
    // 配るのは書けた後（書けなかった値を画面にだけ出さない）。
    await this.storage.put({ availability, availabilitySeedClosed });
    for (const [uid, availableAt] of applied) {
      this.broadcast({ type: 'availability_update', uid, availableAt });
    }
    // 値は本人とグループのメンバーにだけ見せるものなので、ログには件数だけを出す。
    console.log(`Availability seeded: applied=${applied.length}`);
    return createCORSResponse({ success: true, applied: applied.length });
  }

  // 在席状態（active / away）の受理と配信（v3.3追補）。
  // クライアントは操作が IDLE_TIMEOUT_MS（10分）検知されないと away になり、その間は受領証明を
  // 発行しない。away を他メンバーの画面へ反映するためだけの通知で、採点には一切影響しない
  //（サーバーが在席を証明することはない＝運営の裁量が入らない）。
  async handleWsSetPresence(ws, uid, data) {
    const phase = await this.storage.get('phase');
    if (phase !== 'waiting' && phase !== 'chatting') return; // それ以外のフェーズでは無視（エラーにしない）

    // G4: 署名なしの保存＋全員配信を回復する枠で制限。正規の2分ごとの合図は長時間でも枠切れしない。
    if (this.strikeIfOverRefillingQuota(ws, uid, 'presence', WS_FREE_PRESENCE, WS_PRESENCE_REFILL_MS, 'presence spam')) return;

    const state = data.state === 'away' ? 'away' : 'active';
    const presence = uidMap(await this.storage.get('presence')); // P-2026-0823
    const prevState = presence[uid]?.state === 'away' ? 'away' : 'active';
    if (state === 'active') {
      delete presence[uid]; // active が既定（保存しない）
    } else {
      presence[uid] = { state, at: Date.now() };
    }
    if (prevState !== state) await this.storage.put('presence', presence);

    // 状態変化は即配信。不変activeも他メンバーが活動を観測できるよう60秒に1回まで配る。
    // uidごとの控えなので2台目も同じ間隔を共有する。名簿の人数で有界・退避で消えてよいソフト状態。
    const relayAt = this.presenceRelayAt ||= new Map();
    const now = Date.now();
    const lastRelayAt = relayAt.get(uid);
    if (prevState !== state || (state === 'active' && (lastRelayAt === undefined || now - lastRelayAt >= PRESENCE_RELAY_MIN_MS))) {
      relayAt.set(uid, now);
      this.broadcast({ type: 'presence_update', uid, state });
    }
  }

  // 便 LIKE（2026-11-26・ユーザーの指示）: 発言へのいいね。表示だけで、採点・受理・提出物・受領証明には使わない。
  // 署名は確かめない（受け取る各クライアントが名簿の signKey で確かめ、合わないものを捨てる）。ここで見るのは、
  // 接続の uid と同じ名義・形・時刻の大まかな範囲・名簿のメンバーであることだけ。おかしなものは黙って捨てる
  // （古いクライアントにも新しいクライアントにも、エラーの帯を出させない）。枠を超えた分も黙って捨てる（dropIfOverReactionQuota）。
  // 保存は uid ごとの鍵 `reactions:{uid}`（1つの値が大きくならないように）に、（発言, 種類）ごとの最新だけ・上限つき。
  async handleWsReaction(ws, uid, data) {
    if (this.dropIfOverReactionQuota(ws, uid)) return;
    const phase = await this.storage.get('phase');
    if (phase !== 'chatting') return;
    const reaction = data?.reaction;
    if (!isReactionShape(reaction) || reaction.uid !== uid) return;
    if (Math.abs(Date.now() - reaction.timestamp) > REACTION_TIME_SLACK_MS) return;
    const members = await this.storage.get('members') || [];
    if (!members.some((m) => m?.uid === uid)) return;
    await this.serializeActionByActor(uid, 'reaction', async () => {
      const key = `reactions:${uid}`;
      const table = await this.storage.get(key) || {};
      if (!mergeReactionInto(table, reaction)) return;
      await this.storage.put(key, table);
      this.broadcast({ type: 'reaction', reaction: pickReaction(reaction) });
    });
  }

  // 便 LIKE: 名簿のメンバーの保存済みのいいねを一覧にする（init_response 用）。表示だけなので、読めなくても
  // init は止めない（空の一覧を返す）。
  async collectReactions(memberList) {
    const keys = (memberList || []).map((m) => m?.uid).filter((u) => typeof u === 'string' && u).map((u) => `reactions:${u}`);
    if (keys.length === 0) return [];
    let stored;
    try { stored = await this.storage.get(keys); } catch { return []; }
    if (!(stored instanceof Map)) return [];
    const out = [];
    for (const table of stored.values()) {
      if (!table || typeof table !== 'object') continue;
      for (const r of Object.values(table)) if (isReactionShape(r)) out.push(pickReaction(r));
    }
    return out;
  }

  // 同じ発信者・種別の署名検証待ちが重なっても、保存件数の読み書きを直列にする。
  // 予算は発信者・種別ごとであり、他人の発信を待たせない。
  async serializeActionByActor(uid, type, task) {
    const key = `${type}:${uid}`;
    const queues = this.actionWriteQueues ||= new Map();
    const previous = queues.get(key) || Promise.resolve();
    const current = previous.catch(() => {}).then(task);
    queues.set(key, current);
    try { return await current; }
    finally { if (queues.get(key) === current) queues.delete(key); }
  }

  // 密告（発信者ごとに最大10件・チャット期間中のみ・対象は自己暗号化で非公開）
  async handleWsReport(ws, uid, data) {
    return this.serializeActionByActor(uid, 'report', () => this.handleWsReportQueued(ws, uid, data));
  }

  async handleWsReportQueued(ws, uid, data) {
    const phase = await this.storage.get('phase');
    if (phase !== 'chatting') {
      this.sendTo(ws, { type: 'error', message: 'Reporting is only available during chatting phase' });
      return;
    }

    const { encrypted, signature, timestamp } = data;

    if (!encrypted) {
      this.sendTo(ws, { type: 'error', message: 'encrypted is required' });
      return;
    }

    // A-5: signKey署名を検証して保存（チャットと同様、登録blockAddressで検証）
    // 🔴 P-2026-0829（2026-08-07）: 採点本体（`verifyActionSignature` の
    //    `isCanonicalTimestamp(action.timestamp)`）と同じ述語を課す。
    //    旧 `!timestamp` は非正準 ts の密告を `report_ack` で受理しておきながら
    //    採点では消える（＝自傷）一方、正当な `timestamp === 0` を弾いていた。
    if (!signature || !isCanonicalTimestamp(timestamp)) {
      this.sendTo(ws, { type: 'error', message: 'signature and canonical (safe-integer) timestamp are required' });
      return;
    }
    // DO は発信件数だけを制限する。対象の2枠と void 判定は採点が扱う。
    // 同じ署名の再送は保存・中継を増やさず ACK のみ返す。
    const reportsKey = `reports:${uid}`;
    const reports = await this.storage.get(reportsKey) || [];
    const storedReport = reports.find(rep => rep.signature === signature);
    if (storedReport) {
      this.sendTo(ws, { type: 'report_ack', ...storedReport, totalReports: reports.length });
      return;
    }
    if (reports.length >= MAX_ACTION_CANDIDATES_PER_TYPE_PER_ACTOR) {
      if (this.strikeWs(ws, uid, 'over max_reports')) return;
      this.sendTo(ws, { type: 'error', message: `Maximum ${MAX_ACTION_CANDIDATES_PER_TYPE_PER_ACTOR} reports allowed` });
      return;
    }

    const sigValid = await this.verifyActionSignature('report', uid, { encrypted, signature, timestamp });
    if (!sigValid) {
      if (this.strikeWs(ws, uid, 'invalid report signature')) return; // G4
      this.sendTo(ws, { type: 'error', message: 'Invalid report signature' });
      return;
    }

    // レポート保存（暗号化データ＋signKey署名、targetUidは保存しない）
    // ※ フィールド順（encrypted, signature, timestamp）は encryptedDataHash（A-7）の
    //    シリアライズに影響するため変更しないこと
    reports.push({
      encrypted,
      signature,
      timestamp
    });
    await this.storage.put(reportsKey, reports);

    // ACK（encrypted/signature/timestampを返す: フロントが密告内容の表示と
    // 提出スナップショットへの自己マージ（A-3）に使う）
    this.sendTo(ws, {
      type: 'report_ack',
      encrypted,
      signature,
      timestamp,
      totalReports: reports.length
    });

    // 他メンバーに署名済み発信本体を配布（対象は自己暗号化＝誰を密告したかは読めない）。
    // 受信者は受領証明（actionHash）を発行し、観測分を提出物 observed に同梱する（v3.2 §6.3）
    this.broadcast({
      type: 'action_made',
      actionType: 'report',
      uid,
      encrypted,
      signature,
      timestamp,
      reportCount: reports.length
    }, uid);

    console.log(`Report by ${uid} (encrypted, target hidden)`);
  }

  // 投票（発信者ごとに最大10件・チャット期間中のみ・対象は自己暗号化で非公開）
  async handleWsVote(ws, uid, data) {
    return this.serializeActionByActor(uid, 'vote', () => this.handleWsVoteQueued(ws, uid, data));
  }

  async handleWsVoteQueued(ws, uid, data) {
    const phase = await this.storage.get('phase');
    if (phase !== 'chatting') {
      this.sendTo(ws, { type: 'error', message: 'Voting is only available during chatting phase' });
      return;
    }

    const { encrypted, signature, timestamp } = data;

    if (!encrypted) {
      this.sendTo(ws, { type: 'error', message: 'encrypted is required' });
      return;
    }

    // A-5: signKey署名を検証して保存（チャットと同様、登録blockAddressで検証）
    // 🔴 P-2026-0829（2026-08-07）: 採点本体（`verifyActionSignature` の
    //    `isCanonicalTimestamp(action.timestamp)`）と同じ述語を課す。
    //    旧 `!timestamp` では `vote_ack` を返した投票が採点で消え（no_vote 失格＝自傷）、
    //    逆に正当な `timestamp === 0` の投票が送れなかった。
    if (!signature || !isCanonicalTimestamp(timestamp)) {
      this.sendTo(ws, { type: 'error', message: 'signature and canonical (safe-integer) timestamp are required' });
      return;
    }
    // 先着の保存位置を保ち、後続だけ別キーに到着順で永続化する。
    // 件数上限は署名検証の前に検査し、同じ署名は冪等に ACK する。
    const voteKey = `votes:${uid}`;
    const existingVote = await this.storage.get(voteKey);
    const extrasKey = `voteExtras:${uid}`;
    const extras = await this.storage.get(extrasKey) || [];
    const storedVote = existingVote?.signature === signature ? existingVote : extras.find(v => v.signature === signature);
    if (storedVote) {
      this.sendTo(ws, { type: 'vote_ack', ...storedVote });
      return;
    }
    if ((existingVote ? 1 : 0) + extras.length >= MAX_ACTION_CANDIDATES_PER_TYPE_PER_ACTOR) {
      if (this.strikeWs(ws, uid, 'over max_votes')) return;
      this.sendTo(ws, { type: 'error', message: `Maximum ${MAX_ACTION_CANDIDATES_PER_TYPE_PER_ACTOR} votes allowed` });
      return;
    }

    const sigValid = await this.verifyActionSignature('vote', uid, { encrypted, signature, timestamp });
    if (!sigValid) {
      if (this.strikeWs(ws, uid, 'invalid vote signature')) return; // G4
      this.sendTo(ws, { type: 'error', message: 'Invalid vote signature' });
      return;
    }

    // 投票保存（先着の従来位置＋後続の到着順、暗号化データ＋signKey署名）
    // ※ フィールド順（encrypted, signature, timestamp）は encryptedDataHash（A-7）の
    //    シリアライズに影響するため変更しないこと（保存形状は不変・チェック順のみG4で前倒し）
    const acceptedVote = {
      encrypted,
      signature,
      timestamp
    };
    if (existingVote) await this.storage.put(extrasKey, [...extras, acceptedVote]);
    else await this.storage.put(voteKey, acceptedVote);

    // ACK（encrypted/signature/timestampを返す: フロントが投票内容の表示と
    // 提出スナップショットへの自己マージ（A-3）に使う）
    this.sendTo(ws, {
      type: 'vote_ack',
      encrypted,
      signature,
      timestamp
    });

    // 他メンバーに署名済み発信本体を配布（対象は自己暗号化＝誰に投票したかは読めない）。
    // 受信者は受領証明（actionHash）を発行し、観測分を提出物 observed に同梱する（v3.2 §6.3）
    this.broadcast({
      type: 'action_made',
      actionType: 'vote',
      uid,
      encrypted,
      signature,
      timestamp
    }, uid);

    console.log(`Vote by ${uid} (encrypted, target hidden)`);
  }

  // 結果提出
  // Evidence §4.3 バイト比較戦略: クライアントは正規バンドルを payload（JSON文字列）として
  // 1回だけ構築し、WS とオンチェーン（Evidence.submitResult）の両方へ同一バイト列を送る。
  // サーバーは生バイト列を submissions_raw に併存保存（evidence↔サーバー照合を単純な
  // バイト等価にするため。輸送エンベロープの type 等はバンドル外＝比較対象外）。
  async handleWsSubmit(ws, uid, data) {
    const phase = await this.storage.get('phase');
    if (phase !== 'submitting') {
      this.sendTo(ws, { type: 'error', message: 'Submission is only available during submitting phase' });
      return;
    }

    // G4: 大きなpayloadのJSONパースを伴う重い操作。正規の再送はack喪失時の冪等再送のみ
    // （first-write-winsでalreadySubmitted応答）。2回目以降は連打カウント対象
    if (this.strikeIfOverQuota(ws, uid, 'submit', 1, 'submit re-send')) return;

    if (typeof data.payload !== 'string' || !data.payload) {
      this.sendTo(ws, { type: 'error', message: 'payload (canonical submission JSON string) is required' });
      return;
    }
    const rawPayload = data.payload;
    let parsed;
    let compactContext;
    try {
      if (!isEvidenceCompactPayload(rawPayload)) throw new Error('production submission must use evidence-compact-v1');
      const bytes = compactPayloadToBytes(rawPayload);
      if (bytes.length > SERVER_MAX_WIRE_BYTES) throw new Error('compact payload exceeds server wire limit');
      // 無効フレームでも ref 展開が正当提出の総fact上限を超えてCPUを占有しないよう、
      // decoder の安価なwork capを明示してから msgKey/keccak 導出へ進む。
      compactContext = decodeEvidenceCompactV1(bytes, { maxTargetFacts: MAX_RECEIPT_FACTS });
      parsed = compactContext.bundle;
    } catch (e) {
      this.sendTo(ws, { type: 'error', message: `payload decode failed: ${e?.message || 'invalid payload'}` });
      return;
    }
    // v3.2: walletSignature/blockKey は廃止（walletSignatureはsignKey/encryptKeyのmaster素材のため
    // 提出物に含めてはならない）。encryptKey（投票/密告の復号鍵）を公開する。
    const { uid: payloadUid, encryptKey, chatHash, signature, submittedAt, encryptedDataHash, depositIds, encryptedActions, messages: submittedMessages } = parsed;

    // 🔴 P-2026-0826（2026-08-07・D-1）: `submittedAt` は **採点本体と同じ述語**で見る。
    //   旧 `!submittedAt` は JS の falsy 規則で正当な `0` を弾き（`isCanonicalTimestamp(0)`
    //   は真・Rust ゲストも受理）、同時に小数・文字列・2^53 超は素通りさせていた
    //   ＝ 受理側でも棄却側でも採点本体とズレていた。
    //   併せて `encryptKey` / `chatHash` の **孤立サロゲート**も同じ述語（`isOpaqueField`）で
    //   弾く。旧実装は truthy しか見ておらず、採点本体が `invalid_signature` で失格にする
    //   バンドルを WS だけが受け取って保存していた（＝提出できたのに 0 点になる）。
    //   正規クライアントの値は keccak/hex なので、締めても正直な提出は1件も落ちない。
    if (!encryptKey || !isOpaqueField(encryptKey)
      || !chatHash || !isOpaqueField(chatHash)
      || !signature || !isCanonicalTimestamp(submittedAt)) {
      this.sendTo(ws, {
        type: 'error',
        message: 'encryptKey, chatHash, signature, and submittedAt (safe integer) are required'
      });
      return;
    }
    // バンドルのuidは接続uid（＝提出者本人）と一致必須（他人名義バンドルの中継を遮断）
    if (payloadUid !== uid) {
      this.sendTo(ws, { type: 'error', message: 'payload uid must match your uid' });
      return;
    }
    const meta = await this.storage.get('meta');
    const memberUids = ((await this.storage.get('members')) || []).map((m) => m.uid);
    if (!meta || compactContext.blockNum !== Number(meta.blockNum)
      || compactContext.groupId !== Number(meta.groupId)
      || !sameStringArray(compactContext.memberUids, memberUids)) {
      this.sendTo(ws, { type: 'error', message: 'compact payload context/roster does not match this game' });
      return;
    }

    // E6/A-4: encryptedDataHash と depositIds は正規署名メッセージ
    // {blockNum, uid, encryptKey, chatHash, submittedAt, encryptedDataHash, depositIds} の構成要素として必須
    // ⚠️ `isOpaqueField` は空文字を許すので truthy 判定と**両方**要る。
    //    採点本体は空文字/欠落を検証②.6（snapshot_mismatch）で必ず失格にするので、
    //    受理／棄却の結論は一致する（理由だけが早期フィードバック側で具体的になる）。
    if (!encryptedDataHash || !isOpaqueField(encryptedDataHash)) {
      this.sendTo(ws, { type: 'error', message: 'encryptedDataHash is required' });
      return;
    }
    // 🔴 P-2026-0826（2026-08-07・D-1）: `depositIds` も **採点本体と同じ述語**。
    //   採点本体（検証①）は `isCanonicalDepositIds(Array.isArray(x) ? x : null)` で、
    //   `null`／非配列は `null` へ正規化して**受理**する（署名対象の `dataString` も同じ）。
    //   旧 `!Array.isArray(depositIds)` は `null` を弾く一方、`[1, 2]`（数値）や
    //   `['0xff']` は素通りさせていた ＝ 双方向にズレていた。
    if (!isCanonicalDepositIds(Array.isArray(depositIds) ? depositIds : null)) {
      this.sendTo(ws, {
        type: 'error',
        message: 'depositIds must be null or an array of decimal id strings'
      });
      return;
    }
    // depositIds は外側ウォレット署名に覆われる提出者自身の記録として残す。
    // 名簿の depIds との部分列照合は、名簿側を改竄すると提出者だけを
    // invalid_signature にできる一方向ゲートだったため行わない。強制するのは
    // ZKP 表現可能性と有限入力契約に必要な「最大10件・正準形・重複なし」だけ。
    {
      const MAX_DEPOSIT_IDS = 10; // entry-worker / Stage 3 witness と同値
      // D-1: 上のゲートが非配列（`null` 含む）を通すようになったので、ここは
      // 採点本体と同じ正規化（非配列＝申告なし＝空集合）で受ける。素の `depositIds` を
      // 触ると `null.length` で例外になり、提出が 'Internal error' で落ちる。
      const declaredIds = Array.isArray(depositIds) ? depositIds : [];
      const memberList = await this.storage.get('members') || [];
      const memberUidsForStructure = memberList.map((m) => m?.uid);
      if (memberUidsForStructure.length < 1 || memberUidsForStructure.length > 5
        || new Set(memberUidsForStructure).size !== memberUidsForStructure.length
        || memberUidsForStructure.some((memberUid) => !isCanonicalUid(memberUid))) {
        this.sendTo(ws, {
          type: 'error',
          message: 'Submission could not be verified (server roster/context unavailable). Please try again.'
        });
        return;
      }
      const meta = await this.storage.get('meta');
      const structure = validateSubmissionStructure(parsed, {
        blockNum: meta?.blockNum,
        groupId: meta?.groupId,
        memberUids: memberUidsForStructure,
      });
      if (!structure.ok) {
        this.sendTo(ws, { type: 'error', message: `non-canonical submission: ${structure.reason}` });
        return;
      }
    }
    // 🔴 P-2026-0828（2026-08-08・修正C）: `messages` も **採点本体と同じ述語**で見る。
    //
    //   このゲートには `messages` の検査が**一つも無かった**（下の `msgCap` は件数だけ）。
    //   ところが `messages` は**署名に覆われていない唯一の必須フィールド**で、
    //   採点本体（`game-result-calculator.js` の (a)・P-2026-0811 #4/#5）は
    //     `Array.isArray(sub.messages)` でなければ／要素が非正準なら → `chathash_mismatch` 失格、
    //   Evidence 経路（`evidence-reconciler.js`）は `missing_fields` 棄却。
    //   実測（3経路の比較）:
    //     messages=欠落／null／非配列 → WS=受理 / EV=missing_fields / CALC=chathash_mismatch
    //     点数表 {user0001:0, user0002:100, user0003:200}
    //   ＝ 正直に遊んだ本人が 200 → **0点**、その投票先も 200 → **100点**（巻き添え）。
    //   しかも WS は `submit_ack` を返して**成功に見え**、first-write-wins のゲート
    //   （`submissions_raw:{uid}`）が閉じるので**再提出も `alreadySubmitted` で拒否**される。
    //   画面上は「提出完了」なので、本人には気づく手段が無い。
    //   このゲートの存在理由は「正規クライアントの不具合を提出の瞬間に顕在化させる」ことなので、
    //   いちばん壊れやすい場所が素通りしていたのは目的そのものの取りこぼしだった。
    //
    //   ⚠️ 述語は採点本体と**同じ順序・同じ顔ぶれ**で書く（差分を目で照合できるようにするため）。
    //      `typeof m === 'object' && m !== null` を先に置くこと（省くと採点本体側で
    //      `WeakMap.get(null)` の TypeError が残る）。
    //   ⚠️ ここでは chatHash の再計算まではしない（採点本体が権威）。件数上限は下の `msgCap`。
    if (!Array.isArray(submittedMessages) || !submittedMessages.every((m) =>
      typeof m === 'object' && m !== null && !Array.isArray(m)
      && isCanonicalUid(m.uid)
      && isCanonicalText(m.text ?? '')
      && isCanonicalTimestamp(m.timestamp))) {
      this.sendTo(ws, {
        type: 'error',
        message: 'messages must be an array of canonical {uid, text, timestamp} objects'
      });
      return;
    }
    // A-7: encryptedDataHashの生成元スナップショット本体 {votes, reports, observed} も提出必須。
    // 集計はサーバー保存データではなく「各プレイヤーがウォレット署名で提出したスナップショット」から行う。
    if (!encryptedActions || typeof encryptedActions !== 'object') {
      this.sendTo(ws, { type: 'error', message: 'encryptedActions snapshot is required' });
      return;
    }

    // Q-S2-001（2026-07-28）: 受領証明の分量ガード。
    // 採点エンジン（game-result-calculator）が権威で、ここは
    //   ① 正規クライアントの不具合を提出の瞬間に顕在化させる
    //   ② 巨大なバンドルを DO ストレージへ書かせない
    // ための早期フィードバック（改造クライアントは P2P + オンチェーンで迂回できるので防御ではない）。
    // 超過は「無視」ではなく「受け取らない」— 保存してしまうと②が達成できないため。
    {
      const memberCount = (await this.storage.get('members') || []).length;
      const cap = receiptBundleCap(this.maxMessages, memberCount || 5);
      const maxRefs = receiptMaxRefsPerReceipt(this.maxMessages);

      // 🔴 P-2026-0814（2026-08-07）: **`messages` にも件数上限を課す。**
      //    `depositIds` は10件、`receipts` は `receiptBundleCap` で縛られているのに
      //    `messages` だけ素通りだった。保存側も `storeSubmissionBundle` が分割するので
      //    サイズでは止まらず、実質の上限は WS フレーム（約1MiB・1件約210B）だけ
      //    ＝ 1通あたり約5,000件。採点は1件ずつ署名検証する（実測 0.826〜1.45 ms/回）ので、
      //    5人組で約25,000回＝20〜36秒となり、`game-master-DO.js` の CPU 予算（約30秒）を
      //    決定論的に超えて **park（ブロック全停止）** させられた。
      //    上限は `applyChatCaps`（1発信者あたり maxMessages 件しか正典に残らない）×
      //    グループ人数 ＝ この DO が WS 経路で通す総数と同値。
      //    ⚠️ ここは早期フィードバックであって防御ではない（改造クライアントは
      //       P2P + オンチェーン Evidence で迂回できる）。CPU の有界性そのものは
      //       採点側の予算（game-result-calculator 検証②.5(b)）が担う。
      //
      // 🔴 P-2026-0833（2026-08-08）: **バンドル全体を拒否してはいけない。**
      //   採点本体（`game-result-calculator.js` 検証②.5(b)）は超過分を
      //   **発信者ごとの予算で読み飛ばす**だけで、提出物そのものは有効なまま採点される。
      //   実測（他は全部正規・メッセージ件数だけを変える）:
      //     300件（＝ちょうど cap）… WS ACCEPT / Evidence ACCEPT / 採点 `{200,200,200}`
      //     301件               … WS **REJECT（保存なし）** / Evidence ACCEPT / 採点 `{200,200,200}`
      //   ＝ WS 入口だけが、**採点では無視されるデータを理由に**バンドル全体を棄却していた。
      //   本人が Evidence へ出せなければ `no_submit` で全損し、投票先も巻き添えで
      //   `A:0(no_submit) B:100 C:200` になる。
      //
      // 🔴 **これは検閲のレバーだった。** クライアントの取り込みには発信者ごとの件数上限が無く
      //   （`useGameWebSocket.js` の `mergeMessagesV2` / `handleRelayChat`・`relay.js` の
      //    `case 'chat'`）、`SubmissionPhase.js` は `messages` を全件そのままバンドルへ載せる。
      //   ＝ グループの1人が自分の signKey で署名したチャットを Nostr へ msgCap 件超流すだけで、
      //   同席した**正直な全員**の WS 提出が「メッセージが多すぎる」で落ちた。
      //   被害者の側に削れるものは何も無い（2026-08-05 に撤去した `VALUE_SAFE_BYTES` 拒否と同型）。
      //
      // ⚠️ 「保存量の制御のため」は実測で否定されている: `isCanonicalText` は長さを見ないので
      //   **メッセージ1件・本文 8MiB** が上限の内側で受理され `submissions_raw` に 8.00MiB 入る。
      //   実際にバイトを縛っているのは WS フレーム上限（約1MiB）だけで、ここを緩めても最大値は
      //   変わらない（Evidence 経路の 2MiB のほうがむしろ緩い）。
      //   採点 CPU も 3,000件（フレーム上限相当）で 1,698 ms ＜ `CALC_GROUP_WORST_MS`(20,000)。
      //   → 定数はそのまま、超過は**数えて記録するだけ**にする。
      const msgCap = messageBundleCap(this.maxMessages, memberCount || 5);
      if (Array.isArray(submittedMessages) && submittedMessages.length > msgCap) {
        // 早期フィードバックはログだけ（採点は発信者ごとの予算で超過分を読み飛ばす）
        console.warn(`[chat-game-DO] messages over ${msgCap} `
          + `(scoring skips the overflow per sender) uid=${uid} count=${submittedMessages.length}`);
      }

      // 🔴 P-2026-0827（2026-08-08・修正B）: **`push(...配列)` を使わない。**
      //   spread は**引数展開**なので、要素数が多いとスタックが溢れる
      //   （実測 Node v22: **13万要素で `RangeError: Maximum call stack size exceeded`**。
      //    プリイメージ 260KB・gzip 後 約1KB ＝ オンチェーン提出でも余裕で載る）。
      //   受領証明の配列は平坦なので `encryptedDataHash` を攻撃者が自分で計算でき、
      //   検証②.6 を**通ってしまう** ＝ 深い入れ子の対策（try/catch）では止まらない。
      //   ⚠️ **しかも順序が間違っていた**: それを縛るはずの `allReceipts.length > cap` が
      //      spread の**後ろ**にあり、ガードが発火する前に落ちていた。
      //   → 収集口だけ先に列挙して**合計を数え**、上限判定を通ってから1件ずつ積む。
      //     こうすると上限超過時のエラー文（実数を出す）も従来と1文字も変わらない。
      //   `receiptSources` 自身の要素数は「収集口3つ」だけなので、ここが溢れることは無い。
      //
      // 🔴 P-2026-0833（2026-08-08）: **`submittedMessages[].receipts` を収集口から外した。**
      //   採点本体の `receiptsOfBundle`（`game-result-calculator.js`）は P-2026-0811 #3 で
      //   この経路を削除済みで、いま読むのは `ea.votes[uid].receipts` /
      //   `ea.reports[uid][].receipts` / `ea.observed.receipts` の3つだけ。
      //   ZKP ゲスト（`crates/scoring-core/src/json.rs` / `receipts.rs`）も同じ3つ。
      //   ＝ **採点がそもそも読まない場所**を理由に、下の `Too many receipts …` /
      //   `Invalid msgRefs …` がバンドル全体を棄却していた（形式不正が1件混ざるだけで落ちた）。
      //   `messages[].receipts` は署名にも覆われていないので、**他人が P2P で流した
      //   チャットに勝手にぶら下げるだけ**で、それを取り込んだ正直な提出者を落とせた。
      //
      //   以前ここで数え続けていた理由は「DO ストレージに書かせる量の門番」（Q-S2-001 ②）
      //   だったが、実測で否定された: 受領証明**ちょうど 960 件**（上限の内側）に
      //   1件 8KiB の未検査フィールドを付ければ 7.73MiB が受理される。
      //   このループは `msgRefs` と `actionHash` しか見ないので、バイト量は元から縛れていない。
      //   実際に縛っているのは WS フレーム上限（約1MiB）だけ。
      //   → 収集をやめる（＝配列にそもそも触れない）ので、13万件を積まれても
      //     `receipt-spread-overflow-test.mjs` が固定する park 耐性はむしろ強くなる。
      const receiptSources = [];
      const ownVote = encryptedActions.votes?.[uid];
      if (Array.isArray(ownVote?.receipts)) receiptSources.push(ownVote.receipts);
      for (const rep of (Array.isArray(encryptedActions.reports?.[uid]) ? encryptedActions.reports[uid] : [])) {
        if (Array.isArray(rep?.receipts)) receiptSources.push(rep.receipts);
      }
      if (Array.isArray(encryptedActions.observed?.receipts)) receiptSources.push(encryptedActions.observed.receipts);

      let receiptTotal = 0;
      for (const src of receiptSources) receiptTotal += src.length;
      // 🔴 P-2026-0833（2026-08-08）: **バンドル全体を拒否してはいけない。**
      //   採点本体（Q-S2-001 (c)）は `receiptBundleCap` を超えた分を
      //   **正準順序で読み飛ばす**だけで、提出物そのものは有効なまま採点される。
      //   実測（他は全部正規・受領証明の件数だけを変える）:
      //     960件（＝ちょうど cap）… WS ACCEPT / Evidence ACCEPT / 採点 `{200,200,200}`
      //     961件               … WS **REJECT（保存なし）** / Evidence ACCEPT / 採点 `{200,200,200}`
      //   自作メッセージへの自己受領を量産すれば他人にこの超過を踏ませられる
      //   （＝ msgCap と同じ検閲レバー）。被害者に削れるものは無い。
      //   保存量の門番としても機能していない（上の収集口コメント参照・960件ちょうどで 7.73MiB）。
      //   → 定数はそのまま、超過は**数えて記録するだけ**にする。
      if (receiptTotal > cap) {
        // 早期フィードバックはログだけ（採点は正準順序の先頭 cap 件を採る）
        console.warn(`[chat-game-DO] receipts over ${cap} `
          + `(scoring truncates in canonical order) uid=${uid} count=${receiptTotal}`);
      }
      // 収集口は3つだけ＝ここが溢れることは無い（spread ではなく1件ずつ積むことも維持）。
      const allReceipts = [];
      for (const src of receiptSources) for (const rc of src) allReceipts.push(rc);
      // 🔴 P-2026-0834（2026-08-08・P-2026-0833 の掃討の取り残し）: **バンドル全体を拒否してはいけない。**
      //   採点本体（`game-result-calculator.js:1255` / `:1265-1266` / `:1315`）も
      //   ZKP ゲスト（`crates/scoring-core/src/json.rs` の `receipt()` は `Err` ではなく `None` /
      //   `receipts.rs` の `continue`）も、形式不正な受領証明は**1件ずつ読み飛ばす**だけで、
      //   提出物そのものは有効なまま採点される。Evidence 経路
      //   （`evidence-reconciler.js:356-424`）にも対応するゲートは無い。
      //
      // 🔴 **これは検閲のレバーだった。** 分岐条件がライブ側・正典側と非対称で、
      //   ライブ（`:1590`）・クライアント取り込み（`useGameWebSocket.js:355`）・
      //   Nostr（`relay.js`）・バンドル構築（`SubmissionPhase.js:408`）はいずれも
      //   `Array.isArray(rc.msgRefs) && rc.senderUid != null` で既読分岐に入るのに、
      //   ここだけ `Array.isArray(rc?.msgRefs)` 単独だった。したがって
      //   `{receiverUid, actionHash: <実在する発信の本物のハッシュ>, msgRefs: ['NOT-A-REF'], …}`
      //   という**正当に署名された行動受領証明を1通**流すだけで、DO はそれを検証も
      //   サニタイズもせず全員へ中継・再配布し（`receipt_history`）、
      //   取り込んだ**正直な同席者全員の WS 提出**がここで落ちた（攻撃者の自損はゼロ）。
      //   落ちた本人が Evidence 自己救済をしなければ `no_submit` で全損し、
      //   投票先も巻き添えになる（実測 3人組 600pt 中 300pt 消失）。
      //   → ① 分岐条件を正典・ライブ側と揃える ② 逸脱は**数えて記録するだけ**にする。
      let badMsgRefs = 0;
      let badActionHash = 0;
      for (const rc of allReceipts) {
        if (Array.isArray(rc?.msgRefs) && rc?.senderUid != null) {
          if (rc.msgRefs.length > maxRefs || !rc.msgRefs.every(isMsgRef)) badMsgRefs++;
        } else if (rc?.actionHash !== undefined && !isActionHash(rc.actionHash)) {
          // K-S6-002: 任意長文字列の actionHash（採点は読み飛ばす）
          badActionHash++;
        }
      }
      if (badMsgRefs > 0 || badActionHash > 0) {
        // 早期フィードバックはログだけ（採点は形式不正な受領証明を1件ずつ読み飛ばす）
        console.warn(`[chat-game-DO] malformed receipts in submission `
          + `(scoring skips them individually) uid=${uid} `
          + `badMsgRefs=${badMsgRefs} badActionHash=${badActionHash} maxRefs=${maxRefs}`);
      }

      // K-S6-002: 観測した発信（投票/密告）の件数上限。**(提出者, 発信者) ペアごと**に数える
      // ＝ここは1通ぶんなので「発信者ごと」。上限が無いと、受領証明の参照整合性を入れても
      // 「偽の発信＋その受領証明」のペアを量産すれば同じ肥大化が起きる。
      //
      // 🔴 P-2026-0832（2026-08-08）: **バンドル全体を拒否してはいけない。**
      //   採点本体（`game-result-calculator.js` の `MAX_OBSERVED_ACTIONS_PER_ACTOR` 判定）も
      //   ZKP ゲスト（`crates/scoring-core/src/actions.rs`）も、超過分は
      //   **正準順序（timestamp 昇順 → actionHash 昇順）で先頭 N 件を残して切り詰める**
      //   ＝ `break` するだけで、提出物そのものは有効なまま採点される。
      //   ところが WS 入口だけが `Too many observed …` で**バンドル全体を棄却**していた。
      //   実測（他は全部正規・観測発信の件数だけを変える）:
      //     11件 … WS ACCEPT / Evidence ACCEPT / 採点 切り詰めて no_vote
      //     12件 … WS **REJECT（保存なし）** / Evidence ACCEPT / 採点 切り詰め
      //   ＝ 12件以降を運ぶ参加者は通常経路で提出できず、ガス代を払ってオンチェーン
      //   （Evidence）に出すしか道が無い。出せなければ `no_submit` で全損し、しかも
      //   **そのバンドルが運ぶはずだった他人の受領証明も union から消える**（他人の巻き添え）。
      //   突き合わせ相手のいない厳しさは、この系では常に検閲レバーになる。
      //
      // ⚠️ **「超過分を落として保存する」ことはできない。** `submissions:{uid}` は
      //   `JSON.parse(submissions_raw:{uid})` と同一であることが設計の前提で
      //   （`storeSubmissionBundle` の `_fromRaw` 経路は実際に raw から丸ごと復元する）、
      //   raw は Evidence とのバイト同一比較のために1バイトも触れない。
      //   ここで parsed 側だけを削ると「小さいバンドルは切り詰まり、大きいバンドルは
      //   raw 復元で丸ごと残る」というサイズ依存の食い違いが生まれ、公開アーカイブ
      //   （`games/block{N}/group{g}.json`）の `encryptedActions` が自分の
      //   `encryptedDataHash` と一致しなくなる（第三者検証が壊れる）。
      //   → 切り詰めは**採点側に一本化**し、ここは数えて記録するだけにする。
      //   保存量そのものは WS フレーム上限（約1MiB）・`msgCap`・`receiptBundleCap` と
      //   `storeSubmissionBundle` の raw 委譲が押さえる。
      {
        const obs = encryptedActions.observed;
        const overflow = [];
        // 🔴 P-2026-0835（2026-08-08・ラウンド19 判断不要-1）: `Object.entries` は
        //    **文字列に 1文字＝1エントリ / 配列に 1要素＝1ペア**の中間配列を
        //    materialize する。`encryptedActions.votes` に 1e6 文字の文字列や
        //    1,045,000 要素の配列を入れると isolate が catch 不能の FATAL に落ちる。
        //    採点本体（`game-result-calculator.js` の `keyedSection`）と**同じ**
        //    書き換えをここにも入れる。ここを落とすとグループの ChatGameDO 側が
        //    同じ入力で死ぬ。**受理集合は1ビットも変わらない**（ここは数えるだけ）。
        const scan = (label, obj, listOf) => {
          const src = (obj !== null && typeof obj === 'object') ? obj : EMPTY_SECTION;
          for (const actorUid in src) {
            if (!Object.prototype.hasOwnProperty.call(src, actorUid)) continue;
            const n = listOf(src[actorUid]).length;
            if (n > MAX_OBSERVED_ACTIONS_PER_ACTOR) overflow.push(`${label}/${actorUid}=${n}`);
          }
        };
        const asList = (v) => (Array.isArray(v) ? v : (v ? [v] : []));
        scan('votes', encryptedActions.votes, asList);
        scan('reports', encryptedActions.reports, asList);
        if (obs && typeof obs === 'object') {
          scan('votes', obs.votes, asList);
          scan('reports', obs.reports, asList);
        }
        if (overflow.length > 0) {
          // 早期フィードバックはログだけ（採点は正準順序の先頭 MAX_OBSERVED_ACTIONS_PER_ACTOR 件を採る）
          console.warn(`[chat-game-DO] observed actions over ${MAX_OBSERVED_ACTIONS_PER_ACTOR} `
            + `(scoring truncates in canonical order) uid=${uid} ${overflow.join(' ')}`);
        }

        // ============================================================
        // 🔴 J-33 案D / J-12 案A3（2026-08-08・ユーザー確定）: **ここは拒否してよい。**
        // ============================================================
        //
        // 上の2つ（発信件数・メッセージ件数）と違い、この2つは採点が
        // 「**そのバンドルを丸ごと無視する**」規則なので、受け取って保存しても
        // 本人の得になることは何も無い（発信も受領証明も0件・②.6 は失格）。
        // 提出の瞬間に理由を返すほうが、48時間後に理由不明で0点になるより良い。
        //
        // ⚠️ **これは検閲のレバーではない。** 拒否するのは**提出者自身のバンドル**で、
        //    判定材料は `encryptedDataHash` → 外側ウォレット署名が覆う領域だけ。
        //    他人がここへ異物を混ぜることは誰にもできない ＝ **自傷にしかならない**
        //    （他人の受領証明を巻き添えにする形にはなっていない — 巻き添えが起きるのは
        //     「他人が書いた値でバンドル全体を落とす」場合で、2026-08-08 に
        //     P-2026-0832/0833/0834 で潰したのはそちら）。
        //
        // ⚠️ 名簿は `members` の uid。`memberUids.includes` は prototype-safe
        //    （`__proto__` / `toString` を uid に持つメンバーを弾かない）。
        const memberUids = ((await this.storage.get('members')) || [])
          .map(m => (m && m.uid != null) ? String(m.uid) : null)
          .filter(v => v !== null);
        if (!actionSectionKeysAreMembers(encryptedActions, memberUids)) {
          this.sendTo(ws, {
            type: 'error',
            message: 'encryptedActions: every key of votes/reports/observed.votes/observed.reports '
              + 'must be a uid of this group (scoring ignores such a bundle entirely)'
          });
          return;
        }
        const preimage = actionSnapshotPreimage(encryptedActions);
        if (preimage === null || !isCanonicalActionPreimage(preimage)) {
          this.sendTo(ws, {
            type: 'error',
            message: 'encryptedActions: the verification-2.6 preimage must be canonical JSON with '
              + 'safe-integer numbers only (scoring marks such a bundle snapshot_mismatch)'
          });
          return;
        }
      }
    }

    // K-S6-002: ここまでの上限を全部満たしていてもバンドルが単一値の保存上限を超え得る
    // （正典は採点エンジンなので、ここは早期フィードバック）。超過を storage.put の例外に
    // 任せると、クライアントには原因不明の 'Internal error' が返り、再送が連打カウントされる。
    {
      // 🔴 ここで拒否してはいけない（2026-08-05 実障害で削除）。
      // 以前は meta が VALUE_SAFE_BYTES(100,000) を超えると提出そのものを拒否していたが、
      // meta に入る encryptedActions.observed.receipts は receiptBundleCap
      // （4人・100メッセージで 1320 件）まで**プロトコルが許している**。
      // 実測4人ゲームで 131,108 バイトに達し、**正規クライアントの正当な提出が
      // 一律に弾かれた**（block3・4人全員）。プロトコルの上限と保存の上限が
      // 噛み合っていないだけで、利用者に削れるものは何も無く、案内文
      //「自分のバンドルが参照していない受領証明を削れ」も実行不能な指示だった。
      // storeSubmissionBundle が meta を raw 委譲（_fromRaw）で保存できるようにしたので、
      // 保存側にサイズ上限は無くなった。数量そのものは receiptBundleCap /
      // MAX_OBSERVED_ACTIONS_PER_ACTOR が上流で押さえている。
      const metaBytes = storageBytes({
        uid, encryptKey, chatHash, signature, submittedAt, encryptedDataHash, depositIds, encryptedActions
      });
      if (metaBytes > VALUE_SAFE_BYTES) {
        console.warn(`[chat-game-DO] large submission meta (${metaBytes}B) — raw 委譲で保存します uid=${uid}`);
      }
    }

    // E-3: 再提出は受け付けない（first-write-wins）。
    // 上書きを許すと、同一プレイヤーの複数の有効署名済み提出から運営が好きな方を
    // 選べる自由度（chatHash陣営・タブー多数決の操作材料）が生まれるため、最初の提出で確定する。
    // ack喪失後のクライアント再送は成功扱い（冪等にsubmit_ackを返す）。
    //
    // 🔴 P-2026-0813 ⑥（2026-08-07）: **ゲートは `submissions_raw:{uid}` を見る。**
    //   採点入力は K-S2-001 以降 `submissions_raw` が権威（deriveSubmissionsFromRaw）で、
    //   保存も 2026-08-03 の順序修正で raw が先にコミットされる。にもかかわらずゲートだけが
    //   `submissions:{uid}`（＝後から書かれる方）を見ていたため、
    //   `storeSubmissionRaw` が成功して `storeSubmissionBundle` が落ちると
    //   **ゲートは開いたまま raw だけがコミットされた**状態になり、以後の再提出が
    //   raw を上書きし続ける（その uid だけ last-write-wins ＝ E-3 の不変量が破れる）。
    //   実測: `messages:null` の巨大バンドルで storeSubmissionBundle が
    //   「DO 値サイズ上限超過: submissions:u3 = 958796B」で throw した。
    //   コミット点そのもの（raw）を見れば、raw が書けた時点で必ず閉じる。
    //   両方見るのは、raw だけ消えて bundle が残る経路（デバッグ tamper 等）でも
    //   「一度提出した」判定を落とさないため。
    const existingSubmission =
      (await this.storage.get(`submissions_raw:${uid}`)) ??
      (await this.storage.get(`submissions:${uid}`));
    if (existingSubmission) {
      this.sendTo(ws, {
        type: 'submit_ack',
        submittedAt: new Date().toISOString(),
        alreadySubmitted: true
      });
      return;
    }

    // 🔴 P-2026-0830（2026-08-08）: **保存する前に完全検証する**（＝「先着」の定義を揃える）。
    //
    //   ここまでのゲートは「形式（述語）」しか見ておらず、
    //     ・外側ウォレット署名（検証①）
    //     ・chatHash ↔ messages の再計算（検証②.5）
    //     ・encryptedDataHash ↔ encryptedActions の再計算（検証②.6）
    //   のどれもしていなかった。ところが上の first-write-wins ゲートは
    //   `submissions_raw:{uid}` が書けた時点で閉じるので、**形式は合っているが署名が無効な
    //   1通目が枠を焼けた**。画面には「提出完了」が出て（`submit_ack` を返していた）、
    //   再提出は `alreadySubmitted` で拒否され、採点では `invalid_signature` で0点。
    //   オンチェーン救済（Evidence）もクライアントは同じ無効なバイト列を再送するだけなので
    //   救われない。実測（3人巡回投票）: WS 経由 `{0, 100, 200}` ／ Evidence 経由 `{200,200,200}`
    //   ＝ 本人が全損し、**その投票先も巻き添えでボーナス100を失う**。
    //
    //   Evidence 側（`validateResultBundle`）は元から「完全に検証を通った提出」を先着としていた。
    //   ＝ 同じ「first-write-wins」という言葉で、2つの入口が**別の述語**を使っていた。
    //   検証に失敗した提出は保存しない（＝枠を焼かない）ので、本人はそのまま送り直せる。
    //   別途の再提出機能は要らない。
    //
    //   ⚠️ 呼ぶのは **Evidence と同じ `verifyBundleCore`**（写経禁止）。
    //   ⚠️ CPU: 2026-10-08、実署名・priority E40／E′39＋集約20 の
    //      honest-max で12回測定し、窓なし中央値 270.01ms／最大 340.88ms、
    //      窓あり中央値 266.59ms／最大 306.66ms。1 DO = 1グループ
    //      （最大5人）・提出は1人1回。再試行は接続ごとの無料1回＋
    //      WS_STRIKE_MAX=10、WS_STRIKE_CLOSE_MAX=3 per 10分、
    //      upgrade は WS_UPGRADE_RATE_MAX=120 per 60秒で有界。
    //      1本の接続で重い検証まで通るのは無料1回＋strike 10回＝11回
    //      （検証の失敗は strike を足さない）。自発的な張り直し込みの上界は
    //      1 uid で1分1,320回・5人で10分66,000回、strike 切断の経路は
    //      3本×11回＝33回/uid（5人で165回）。実測の最大（約0.2〜0.3秒/回）
    //      なら 1 uid で DO の約4〜5コア分＝受容済み S3R1-F-4-01。
    //      WS メッセージごとに
    //      別 CPU 予算なので、採点本体のような「1リクエストに全部載る」問題は起きない。
    //   ⚠️ 検証は first-write-wins ゲートの**後ろ**に置く。前に置くと、ack を取りこぼした
    //      クライアントの正当な再送（同一バイト列）でも重い検証を毎回走らせることになり、
    //      さらに「保存済みなのにエラーを返す」経路が生まれる（`alreadySubmitted` を
    //      失敗として扱ってはいけない — 本人が混乱する）。
    {
      const meta = await this.storage.get('meta');
      const memberList = await this.storage.get('members') || [];
      // 🔴 P-2026-0834（2026-08-08）: 名簿の照合は**厳密比較**。
      //   下の `verifyBundleCore` は `me.uid` を**そのまま署名対象へ入れる**
      //   （`evidence-reconciler.js:260-268` の `dataString` の `uid`）。
      //   `String()` を噛ませた緩い照合だと、名簿に数値 `7` が混ざった場合に
      //   WS だけが `invalid_signature` を返し、同じバイト列を
      //   `validateResultBundle`（D1 名簿は文字列）に通すと `{valid:true}` になる
      //   ＝ 入口ごとに署名対象が変わる。WS の `uid` は
      //   `acceptWebSocket(server,[uid, …])` の先頭タグ＝必ず文字列で、接続時の名簿検証
      //   （`:1055` の `members.some(m => m.uid === uid)`）も厳密比較なので過剰遮断は無い
      //   （見つからなければ直下の fail-closed 枝へ落ちる）。
      const me = memberList.find(m => m.uid === uid);
      if (!meta || meta.blockNum == null || meta.groupId == null || !me || !me.addr) {
        // 名簿・署名文脈が壊れているのはサーバー側の異常。**保存はしない**
        // （fail-closed。保存すると検証を通っていないバイト列で枠が焼ける）。
        console.error(`[chat-game-DO] submit verification context missing uid=${uid} meta=${!!meta} member=${!!me}`);
        this.sendTo(ws, { type: 'error', message: 'Submission could not be verified (server roster/context unavailable). Please try again.' });
        return;
      }
      const core = await verifyBundleCore(parsed, meta.blockNum, {
        uid: me.uid,
        addr: me.addr,
        bAddr: me.bAddr,
        depIds: me.depIds,
        groupId: meta.groupId,
        memberUids: memberList.map((member) => member.uid),
        memberBAddrs: memberList.reduce((map, member) => {
          map[member.uid] = member.bAddr; return map;
        }, Object.create(null)),
      });
      if (!core.valid) {
        // 理由の分かるエラーを返す（原因不明のまま締切を過ぎるのが最悪。2026-08-05 実障害）。
        const detail = typeof core.detail === 'string' ? core.detail : ({
          invalid_signature: 'the wallet signature does not match the submitted bundle (signed with a different wallet, or a signed field was altered)',
          chathash_mismatch: 'chatHash does not match the submitted messages',
          snapshot_mismatch: 'encryptedDataHash does not match encryptedActions'
        }[core.reason] || 'the bundle failed verification');
        this.sendTo(ws, {
          type: 'error',
          message: `Submission rejected (${core.reason}): ${detail}. Nothing was saved — you can submit again.`
        });
        return;
      }
    }

    // 生バイト列を**先に**保存する（evidence 照合用）。
    // 2026-08-03 修正: 以前は bundle → raw の順だった。raw の保存が失敗すると
    // 「コミット点である bundle だけが残り raw が無い」状態が確定し、first-write-wins に
    // 阻まれて再提出もできず、後段の採点が parsed/raw 不整合でブロック全体を止めた
    // （block27 実障害）。raw を先に書けば「bundle があれば raw もある」が構造的に成立し、
    // 途中で落ちても何もコミットされない＝ユーザーは普通に再提出できる。
    // 提出保存（chatHash/encryptedDataHashの生成元データも保存し、集計時に整合性・署名検証を行う）
    // Z2是正: バンドルが128KiB/値を超え得るため（チャット全文コピー同梱）、分割保存ヘルパー経由
    // ※ フィールド順は payload（SubmissionPhase構築）と同一に保つ＝復元stringify が
    //    生バイト列と一致する（evidence照合・Z2 U4 の前提）
    await this.persistSubmission(uid, rawPayload, {
      uid,
      encryptKey,
      chatHash,
      signature,
      submittedAt,
      encryptedDataHash,
      depositIds,
      encryptedActions,
      messages: Array.isArray(submittedMessages) ? submittedMessages : null
    });

    // ACK
    const now = new Date().toISOString();
    this.sendTo(ws, {
      type: 'submit_ack',
      submittedAt: now
    });

    // Q22: ACK は R2 公開より先に返す。途中公開は best-effort の保全用写しであり、
    // R2 障害を提出受理の成否へ逆流させない。保存に成功した初回提出だけがここへ到達するため、
    // 検証エラー・alreadySubmitted の再送・raw-only の途中失敗は新しい公開対象にならない。
    this.queueSubmissionSnapshotPublish();

    // 他メンバーに通知
    this.broadcast({
      type: 'submission_made',
      uid,
      timestamp: Date.now()
    }, uid);

    console.log(`Submission by ${uid}`);

    // 全メンバー提出完了チェック
    const members = await this.storage.get('members') || [];
    let allSubmitted = true;
    for (const member of members) {
      const sub = await this.storage.get(`submissions:${member.uid}`);
      if (!sub) {
        allSubmitted = false;
        break;
      }
    }

    if (allSubmitted) {
      console.log('All members submitted');
      this.broadcast({ type: 'all_submitted', timestamp: Date.now() });
    }
  }

  // A-5: 投票・密告のsignKey署名検証。
  // 署名対象はクライアント（useGameWebSocket）・計算側（game-result-calculator）と同一の
  // §2.6正準形（type/blockNum/groupId束縛・C6）。検証先＝登録blockAddress.address。
  async verifyActionSignature(type, uid, { encrypted, signature, timestamp }) {
    const members = await this.storage.get('members') || [];
    const member = members.find(m => m.uid === uid);
    // P-2026-0829: 生の `JSON.parse` をやめ、採点本体と同じ `parseBlockAddress` に合流させる。
    // 壊れた `bAddr` はここでは「検証できない＝false」（例外を呼び出し元へ出さない）。
    const bAddr = parseBlockAddress(member?.bAddr);
    if (!member || !bAddr) return false;
    const ctx = await this.getProtocolContext();
    const dataString = actionSignStringV2(type, ctx.blockNum, ctx.groupId, uid, encrypted, timestamp);
    // 🔴 P-2026-0836（2026-08-08・ラウンド19 判断不要-2）: **署名の正準性（形式＋low-s）は
    //    `verifyMessage` と同じ場所で課す**（＝既存の「無効署名」経路に合流させる）。
    //    P-2026-0829 は同じ6箇所に `isCanonicalTimestamp` を入れたが、`signature` は
    //    truthy 判定のまま残っていた（是正前は
    //    `grep -c isCanonicalSignature workers/game_workers/chat-game-DO.js` = **0**）。
    //    採点正典（`game-result-calculator.js:1238` の `isCanonicalSignature`）と
    //    Rust（`crates/scoring-core/src/receipts.rs:186` の `is_low_s`）は high-s の
    //    「双子」を落とすのに、ライブ層は viem `verifyMessage` 1本だけで **双子に true を返す**
    //    （`protocol-v2.js:117-122` のコメントが自ら明記）。
    //    ＝ 3経路の割れではなく「ライブ層 vs 採点層」の割れで、block-verifier も ZKP も鳴らない。
    //    実測（3人組・巡回投票）: 本物 low-s なら {200,200,200}、high-s 双子だと
    //    {0(no_vote),100,200}。DO は `*_ack` を返し `rcpt:{keccak(sig)}` へ**永続保存**
    //    （本物と keccak が別なので冪等排除もすり抜ける）、`receipt_history` で再配布する。
    //    標的の画面は「投票: 完了」のままで**再送導線が出ない**。
    //    ⚠️ **早期ゲート（`if (!signature || …)` の並び）には入れない。** そこに入れると
    //       `strikeWs` を通らず、無効署名の連打で切断されなくなる（G4 の連打対策が空振り）
    //       ／投票・密告の件数上限より先に落ちて安いチェックの順序も崩れる。
    //    ⚠️ 過剰遮断ゼロ: viem `signMessage` 500サンプルで high-s は **0件**。
    // 🔴 `encrypted` も採点本体と同じ `isOpaqueField` に通す（数値 `12345` / 孤立サロゲート /
    //    オブジェクトが `vote_ack` ＋ `action_made` で中継されていた。自傷どまりだが同じ1行）。
    // 🔴 P-2026-0842（2026-08-08・ユーザー確定）: **暗号文の正準長も採点と同じ述語で課す。**
    //    採点だけに入れると「DO は `vote_ack` / `report_ack` を返して `action_made` で
    //    全員へ中継し、`live/…json` にも公開したのに、48時間後の採点では消えている」
    //    という遅延失敗になる（P-2026-0829 が `isCanonicalTimestamp` で塞いだのと同型）。
    //    しかも中継・公開されてしまう以上、**漏れる側の被害は取り返しがつかない**
    //    （長さから対象 uid の桁数が読める）。入口で止めるほかない。
    //    ⚠️ 述語は写経せず `protocol-v2.js` の同じ関数を使う（3実装が割れないこと）。
    //    ⚠️ 過剰遮断ゼロ: 正規クライアントの `encryptAction` は必ずこの長さを返す
    //       （`test-calculator/action-padding-unit.mjs` が実測で固定）。
    if (!isCanonicalSignature(signature) || !isOpaqueField(encrypted)
      || !isCanonicalActionCiphertext(encrypted)) return false;
    try {
      return await verifyMessage({ address: bAddr.address, message: dataString, signature });
    } catch (err) {
      console.error(`Action signature verification error for uid=${uid} type=${type}:`, err.message);
      return false;
    }
  }

  // ============================================================
  // ユーティリティ
  // ============================================================

  // 全接続にブロードキャスト
  broadcast(data, excludeUid) {
    const sockets = this.state.getWebSockets();
    // P-2026-0831: `data` には参加者由来の値（受領証明そのもの・投票/密告の `encrypted`）が
    // 載る。今日は sign-string 構築（`actionSignStringV2` 等）と DO storage の V8 直列化が
    // 先に落ちるので深い木はここへ届かないが、**それは他レイヤーのスタック上限に
    // 依存した「たまたま」**。ここで例外を出すと `handleWsMessage` の catch が
    // 'Internal error' に潰し、原因がどこにも残らない。出力はバイト同一。
    const message = safeJsonStringify(data);

    for (const ws of sockets) {
      try {
        const tags = this.state.getTags(ws);
        const wsUid = tags[0];
        if (excludeUid && wsUid === excludeUid) continue;
        ws.send(message);
      } catch (e) {
        // 送信失敗は無視（切断済みソケット）
      }
    }
  }

  // 特定のWebSocketに送信
  sendTo(ws, data) {
    // 拒否理由はサーバー側にも必ず残す（2026-08-05 実障害）。
    // 提出が 4/4 拒否されたのに、理由がクライアントの console にしか無く、
    // 締切後は誰も原因を確認できなかった。wrangler tail で追えるようにしておく。
    if (data && data.type === 'error') {
      try {
        console.warn(`[chat-game-DO] reject: ${data.message}`);
      } catch { /* ログ失敗で本処理を止めない */ }
    }
    try {
      // P-2026-0831: broadcast と同じ理由（`init_response` の `actions` / `receipt_history` /
      // `my_vote` / `my_reports` は参加者由来）。例外はこの catch が握るので、
      // 深さで落ちると**その接続だけ状態復元が無言で失敗する**。出力はバイト同一。
      ws.send(safeJsonStringify(data));
    } catch (e) {
      // 送信失敗は無視
    }
  }

  // 接続中のUID一覧を取得（観戦者は含めない）
  getConnectedUids() {
    const sockets = this.state.getWebSockets();
    const uids = [];
    for (const ws of sockets) {
      const tags = this.state.getTags(ws);
      const tag = tags[0];
      if (tag && !tag.startsWith('spectator:')) uids.push(tag);
    }
    return [...new Set(uids)];
  }

  // v3.3追補: 在席中（アクティブ）のメンバーuid一覧。
  //   ① away を明示宣言していない ∧ ② 直近 IDLE_TIMEOUT_MS 以内にWS受信がある
  // 「WS接続中」だけでは判定しない（凍結タブは接続が生きたまま何も送ってこないため）。
  async computeActiveUids() {
    const presence = await this.storage.get('presence') || {};
    const now = Date.now();
    const out = [];
    for (const [uid, at] of this.memberSeen.entries()) {
      if (presence[uid]?.state === 'away') continue;
      if (now - at <= IDLE_TIMEOUT_MS) out.push(uid);
    }
    return out;
  }

  // Q22（2026-09-16 ユーザー決定）: WS で保存に成功した提出の生バイト列を、提出期間中から
  // 観戦用 live JSON とは別の公開 key へ出す。これは保全用の非権威な写しであり、
  // manifest の file set・Stage 3/5・block-verifier の通常経路には入れない。
  // 呼び出し元は submit_ack を先に送ってから waitUntil へ積むため、公開失敗は提出受理と独立する。
  queueSubmissionSnapshotPublish() {
    const task = Promise.resolve().then(() => this.publishSubmissionSnapshot(false));
    try {
      if (typeof this.state?.waitUntil === 'function') this.state.waitUntil(task);
    } catch (error) {
      this.recordDependencyOutcome?.('failed', 'R2_BUCKET', 'publish_submission_snapshot_schedule', {
        error: boundedError(error),
      });
      console.error('Submission snapshot scheduling failed:', error?.message || error);
    }
    return task;
  }

  // 2種類の末尾公開は DO の1つの alarm を共有し、常に最も早い期限を予約する。
  async armSnapshotAlarms() {
    const [submission, live] = await Promise.all([
      this.storage.get(SUBMISSION_SNAPSHOT_ALARM_KEY),
      this.storage.get(LIVE_SNAPSHOT_ALARM_KEY),
    ]);
    const dues = [submission?.dueAt, live?.dueAt].filter((value) => Number.isFinite(value));
    if (dues.length > 0) await this.storage.setAlarm(Math.min(...dues));
    else if (typeof this.storage.deleteAlarm === 'function') await this.storage.deleteAlarm();
  }

  // 間引いた提出があるときは、最後に成功した公開から30秒後の最古時刻を永続化する。
  async scheduleSubmissionSnapshotAlarm(dueAt, reason) {
    try {
      if (!Number.isFinite(dueAt) || typeof this.storage?.setAlarm !== 'function') {
        throw new Error('Durable Object alarm is unavailable');
      }
      const previous = await this.storage.get(SUBMISSION_SNAPSHOT_ALARM_KEY);
      const previousDueAt = Number(previous?.dueAt);
      const scheduledAt = Number.isFinite(previousDueAt) ? Math.min(previousDueAt, dueAt) : dueAt;
      await this.storage.put(SUBMISSION_SNAPSHOT_ALARM_KEY, {
        dueAt: scheduledAt,
        reason,
        requestedAt: Date.now(),
      });
      await this.armSnapshotAlarms();
      return { ok: true, dueAt: scheduledAt };
    } catch (error) {
      this.recordStorageOutcome?.('failed', 'schedule_submission_snapshot_alarm', {
        error: boundedError(error),
      });
      console.error('Submission snapshot alarm scheduling failed:', error?.message || error);
      return { ok: false, error: boundedError(error) };
    }
  }

  async clearSubmissionSnapshotAlarm() {
    try {
      await this.storage.delete(SUBMISSION_SNAPSHOT_ALARM_KEY);
      await this.armSnapshotAlarms();
    } catch (error) {
      this.recordStorageOutcome?.('failed', 'clear_submission_snapshot_alarm', {
        error: boundedError(error),
      });
    }
  }

  async scheduleLiveSnapshotAlarm(dueAt) {
    try {
      if (!Number.isFinite(dueAt) || typeof this.storage?.setAlarm !== 'function') {
        throw new Error('Durable Object alarm is unavailable');
      }
      const previous = await this.storage.get(LIVE_SNAPSHOT_ALARM_KEY);
      const previousDueAt = Number(previous?.dueAt);
      await this.storage.put(LIVE_SNAPSHOT_ALARM_KEY, {
        dueAt: Number.isFinite(previousDueAt) ? Math.min(previousDueAt, dueAt) : dueAt,
      });
      await this.armSnapshotAlarms();
    } catch (error) {
      this.recordStorageOutcome?.('failed', 'schedule_live_snapshot_alarm', { error: boundedError(error) });
    }
  }

  async clearLiveSnapshotAlarm() {
    try {
      await this.storage.delete(LIVE_SNAPSHOT_ALARM_KEY);
      await this.armSnapshotAlarms();
    } catch (error) {
      this.recordStorageOutcome?.('failed', 'clear_live_snapshot_alarm', { error: boundedError(error) });
    }
  }

  async alarm() {
    const [submission, live] = await Promise.all([
      this.storage.get(SUBMISSION_SNAPSHOT_ALARM_KEY),
      this.storage.get(LIVE_SNAPSHOT_ALARM_KEY),
    ]);
    const now = Date.now();
    if (Number.isFinite(submission?.dueAt) && now >= submission.dueAt) {
      await this.storage.delete(SUBMISSION_SNAPSHOT_ALARM_KEY);
      await this.publishSubmissionSnapshot(false);
    }
    if (Number.isFinite(live?.dueAt) && now >= live.dueAt) {
      await this.storage.delete(LIVE_SNAPSHOT_ALARM_KEY);
      await this.publishLiveSnapshot(false);
    }
    await this.armSnapshotAlarms();
  }

  // force=false は観戦用スナップショットと同じ LIVE_SNAPSHOT_DEBOUNCE_MS で間引く。
  // force=true は submitting→completed 遷移の最終1回だけに使う。
  async publishSubmissionSnapshot(force = false) {
    const previous = this.submissionSnapshotPublishTail || Promise.resolve();
    const task = previous.catch(() => {}).then(async () => {
      const result = await this.performSubmissionSnapshotPublish(force);
      if (!force) return result;

      // completed最終版はarchiveStatusと同じく、成功/失敗を永続化して同一phase再送の
      // 再試行判定とcleanupの完了条件にする。
      const status = { ...result, attemptedAt: new Date().toISOString() };
      try {
        await this.storage.put(SUBMISSION_SNAPSHOT_FINAL_STATUS_KEY, status);
      } catch (error) {
        this.recordStorageOutcome?.('failed', 'submission_snapshot_final_status_record', {
          error: boundedError(error),
        });
        return {
          ok: false,
          ...(result?.r2Key ? { r2Key: result.r2Key } : {}),
          published: result?.ok === true,
          attemptedAt: status.attemptedAt,
          error: `final submission snapshot completion record failed: ${boundedError(error)}`,
        };
      } finally {
        // completed後は途中版alarmを残さない。失敗した最終版は同一phase再送で再試行する。
        await this.clearSubmissionSnapshotAlarm();
      }
      return status;
    });
    this.submissionSnapshotPublishTail = task.catch(() => {});
    return task;
  }

  async performSubmissionSnapshotPublish(force = false) {
    try {
      if (!this.env?.R2_BUCKET) {
        this.recordDependencyOutcome?.('failed', 'R2_BUCKET', 'publish_submission_snapshot', {
          error: 'binding missing',
        });
        return { ok: false, error: 'R2_BUCKET binding missing' };
      }

      const [meta, phase, members] = await Promise.all([
        this.storage.get('meta'),
        this.storage.get('phase'),
        this.storage.get('members'),
      ]);
      if (!meta || meta.blockNum === undefined || meta.groupId === undefined) {
        return { ok: false, skipped: 'meta_missing' };
      }
      if (phase !== 'submitting' && !(force && phase === 'completed')) {
        return { ok: false, skipped: 'phase_not_publishable' };
      }

      const now = Date.now();
      if (!force) {
        const last = await this.storage.get('live_submissions_snapshot_at') || 0;
        if (now - last < LIVE_SNAPSHOT_DEBOUNCE_MS) {
          const alarm = await this.scheduleSubmissionSnapshotAlarm(
            last + LIVE_SNAPSHOT_DEBOUNCE_MS,
            'debounced_submission_snapshot',
          );
          return { ok: false, skipped: 'debounced', alarm };
        }
      }

      // archiveGameData() と同じ uid key / raw string 表現を使う。
      // parsed marker がある＝raw→bundle の永続保存が完了した uid だけを公開し、
      // raw-first 保存の途中で bundle が失敗した raw-only 状態は公開しない。
      const submissionsRaw = Object.create(null);
      for (const member of (Array.isArray(members) ? members : [])) {
        const committed = await this.storage.get(`submissions:${member.uid}`);
        if (!committed) continue;
        const raw = await this.loadSubmissionRaw(member.uid);
        if (raw) submissionsRaw[member.uid] = raw;
      }

      const snapshot = {
        blockNum: meta.blockNum,
        groupId: meta.groupId,
        phase,
        publishedAt: new Date(now).toISOString(),
        submissionsRaw,
      };
      const r2Key = `live/block${meta.blockNum}/group${meta.groupId}.submissions.json`;
      await this.env.R2_BUCKET.put(r2Key, safeJsonStringify(snapshot), {
        httpMetadata: { contentType: 'application/json', cacheControl: 'public, max-age=10' },
      });
      await this.storage.put('live_submissions_snapshot_at', now);
      this.recordDependencyOutcome?.('succeeded', 'R2_BUCKET', 'publish_submission_snapshot');
      return { ok: true, r2Key, publishedAt: snapshot.publishedAt };
    } catch (error) {
      this.recordDependencyOutcome?.('failed', 'R2_BUCKET', 'publish_submission_snapshot', {
        error: boundedError(error),
      });
      console.error('Submission snapshot publish failed:', error?.message || error);
      const alarm = force ? null : await this.scheduleSubmissionSnapshotAlarm(
        Date.now() + LIVE_SNAPSHOT_DEBOUNCE_MS,
        'submission_snapshot_retry',
      );
      return { ok: false, error: boundedError(error), ...(alarm ? { alarm } : {}) };
    }
  }

  // G7是正（2026-07-18）: 観戦用ライブスナップショットのR2公開。
  // 観戦WSを廃止した代替で、観戦者はCDN（r2.bitcoinu.org）経由でこのJSONをポーリングする。
  // 内容は旧・観戦WSのinit_responseで既に無認証配信していた公開情報のみ（新規露出なし）。
  // force=false時はLIVE_SNAPSHOT_DEBOUNCE_MSで間引き、間引いたら窓明けに1回末尾公開する。
  // 失敗は従来どおり握る（配信はbest-effort）。
  async publishLiveSnapshot(force = false) {
    try {
      if (!this.env.R2_BUCKET) {
        this.recordDependencyOutcome('failed', 'R2_BUCKET', 'publish_live_snapshot', { error: 'binding missing' });
        return;
      }
      const meta = await this.storage.get('meta');
      if (!meta || meta.blockNum === undefined || meta.groupId === undefined) return;
      const now = Date.now();
      if (!force) {
        const last = await this.storage.get('live_snapshot_at') || 0;
        if (now - last < LIVE_SNAPSHOT_DEBOUNCE_MS) {
          await this.scheduleLiveSnapshotAlarm(last + LIVE_SNAPSHOT_DEBOUNCE_MS);
          return;
        }
      }
      await this.storage.put('live_snapshot_at', now);
      await this.clearLiveSnapshotAlarm();

      const [phase, memberList, charCounts, messageCounts, phaseTimestamps, phaseEndTime, gameSkipped, submittedUids] = await Promise.all([
        this.storage.get('phase'),
        this.storage.get('members'),
        this.storage.get('charCounts'),
        this.storage.get('messageCounts'),
        this.storage.get('phaseTimestamps'),
        this.storage.get('phaseEndTime'),
        this.storage.get('gameSkipped'),
        this.storage.get('submittedUids'),
      ]);
      const messages = await this.loadMessages();

      // 観戦者の既読UX用: 署名済み投票/密告本体（対象は自己暗号化＝内容は読めない）＋受領証明。
      // これで観戦画面（ChatPhase）が「〜が投票/密告しました」を既読状況付きで表示できる。
      // P-2026-0823: 観戦スナップショットも同じ（uid=`__proto__` の発信が消えない）。
      //
      // 🔴 P-2026-0842（2026-08-08）: **この JSON は無認証で公開される**（`r2.bitcoinu.org`）。
      //    しかも照合用の uid 一覧が同じ JSON に載っているので、
      //    暗号文の長さが対象 uid の桁数を漏らすと**受動観測だけで票の行き先が絞れる**。
      //    根本対策は平文の固定長パディング（`protocol-v2.js` の `ACTION_PLAINTEXT_BYTES`）で、
      //    入口（`verifyActionSignature`）が正準長でない発信を保存させない。
      //    ここは**多層防御**: 公開する直前にもう一度同じ述語で篩う。
      //    ・入口の是正より前に保存された記録（旧ラン）を公開しない
      //    ・将来ここへ別経路で値が入っても、公開面だけは構造的に長さ一定になる
      //    ⚠️ **落とさずに篩う**のが要点。`encrypted` は観戦画面が `actionHashV2` を
      //       計算するのに要る（`game.js` の `spectatorObserved` → `collectKnownActions` →
      //       `buildReceiptMaps` → 「〜が投票しました（既読 n）」表示）。丸ごと消すと
      //       観戦画面の受領状況が全部「未受領」に見える。正準長の発信は全部通るので
      //       正規のゲームでは表示は1ピクセルも変わらない（落ちるのは採点でも
      //       落ちる発信だけ＝**表示 ≡ 採点**が保たれる）。
      const canonAction = (a) => a && isCanonicalActionCiphertext(a.encrypted);
      const actions = { votes: Object.create(null), reports: Object.create(null) };
      for (const m of (memberList || [])) {
        const vote = await this.storage.get(`votes:${m.uid}`);
        if (canonAction(vote)) actions.votes[m.uid] = vote;
        const extras = (await this.storage.get(`voteExtras:${m.uid}`) || []).filter(canonAction);
        if (extras.length) actions.votes[`${m.uid}__extras`] = extras;
        const reports = (await this.storage.get(`reports:${m.uid}`) || []).filter(canonAction);
        if (reports.length > 0) actions.reports[m.uid] = reports;
      }
      const receipts = await this.loadReceipts();
      // 在席状態（away のメンバー）: 観戦画面でも「オフライン」を正しく出すため同梱
      const presenceMap = await this.storage.get('presence') || {};
      const awayUids = Object.keys(presenceMap).filter(u => presenceMap[u]?.state === 'away');

      const snapshot = {
        blockNum: meta.blockNum,
        groupId: meta.groupId,
        phase: phase || 'waiting',
        meta,
        members: (memberList || []).map(m => ({
          uid: m.uid, addr: m.addr, bAddr: m.bAddr, lang: m.lang, depIds: m.depIds,
          globalIndex: m.globalIndex, name: m.name || null, img: m.img || null, verified: m.verified || false
        })),
        messages,
        charCounts: charCounts || {},
        messageCounts: messageCounts || {},
        connectedUids: this.getConnectedUids(),
        awayUids,
        activeUids: await this.computeActiveUids(),
        minChars: this.minChars,
        minMessages: this.minMessages,
        maxChars: this.maxChars,
        maxMessages: this.maxMessages,
        maxMsgChars: this.maxMsgChars,
        phaseTimestamps: phaseTimestamps || {},
        phaseEndTime: phaseEndTime || null,
        gameSkipped: gameSkipped || null,
        submittedUids: submittedUids || [],
        actions,
        receipts: receipts || [],
        updatedAt: now,
      };
      await this.env.R2_BUCKET.put(
        `live/block${meta.blockNum}/group${meta.groupId}.json`,
        // P-2026-0831: `actions` / `receipts` / `messages` は参加者由来。現状は
        // 「V8 直列化（DO storage）を通り抜けたものだけ」なので `JSON.stringify` でも
        // 落ちないはずだが、その前提は**別レイヤーのスタック上限**に依存している。
        // 例外は下の catch が握る＝観戦画面がゲーム中ずっと凍る（無言）ので、
        // 依存を持たずに済む方を使う（出力はバイト同一）。
        safeJsonStringify(snapshot),
        // P5関連（2026-07-19）: max-age=10明示＝CDNのEdge TTL「cache-control尊重」側に乗せ、
        // 観戦の15秒ポーリングに対するエッジ側の遅れを既定30秒→10秒に短縮
        { httpMetadata: { contentType: 'application/json', cacheControl: 'public, max-age=10' } }
      );
      this.recordDependencyOutcome('succeeded', 'R2_BUCKET', 'publish_live_snapshot');
    } catch (e) {
      this.recordDependencyOutcome('failed', 'R2_BUCKET', 'publish_live_snapshot', { error: boundedError(e) });
      console.error('Live snapshot publish failed:', e?.message || e);
    }
  }

  // ゲームデータをR2にアーカイブ
  async archiveGameData() {
    const meta = await this.storage.get('meta');
    const attemptedAt = new Date().toISOString();
    if (!meta) {
      const status = { ok: false, attemptedAt, error: 'meta is missing' };
      try {
        await this.storage.put('archiveStatus', status);
        this.recordStorageOutcome?.('succeeded', 'archive_status_record');
      } catch (error) {
        this.recordStorageOutcome?.('failed', 'archive_status_record', { error: boundedError(error) });
        console.error('Error recording archive failure:', error);
      }
      return status;
    }

    const [members, charCounts, phaseTimestamps] = await Promise.all([
      this.storage.get('members'),
      this.storage.get('charCounts'),
      this.storage.get('phaseTimestamps')
    ]);
    const messages = await this.loadMessages();
    const receipts = await this.loadReceipts();

    // submissions, reports, votes を収集（raw = 受信生バイト列。evidence バイト照合の再現用）
    // 🔴 P-2026-0820（2026-08-07・C-6）: uid=`__proto__` の代入を own property にする
    //    （素の `{}` だとアーカイブ JSON から当該 uid が丸ごと消える）。handleGetResults と同じ。
    const submissions = Object.create(null);
    const submissionsRaw = Object.create(null);
    const reports = Object.create(null);
    const votes = Object.create(null);
    for (const member of (members || [])) {
      const sub = await this.loadSubmission(member.uid);
      if (sub) submissions[member.uid] = sub;

      const raw = await this.loadSubmissionRaw(member.uid);
      if (raw) submissionsRaw[member.uid] = raw;

      const rep = await this.storage.get(`reports:${member.uid}`);
      if (rep) reports[member.uid] = rep;

      const vote = await this.storage.get(`votes:${member.uid}`);
      if (vote) {
        votes[member.uid] = vote;
        const extras = await this.storage.get(`voteExtras:${member.uid}`) || [];
        if (extras.length) votes[`${member.uid}__extras`] = extras;
      }
    }

    const gameSkipped = await this.storage.get('gameSkipped') || null;

    const archiveData = {
      meta,
      members,
      messages,
      receipts,
      charCounts,
      phaseTimestamps,
      submissions,
      submissionsRaw,
      reports,
      votes,
      gameSkipped,
      archivedAt: attemptedAt
    };

    const r2Key = `games/block${meta.blockNum}/group${meta.groupId}.json`;

    try {
      // P-2026-0831: `submissions` は参加者由来のツリー（`handleGetResults` と同じ素性）。
      // 素の `JSON.stringify` だと深い1通で例外 → この try が握って**無言で欠落**し、
      // block-verifier の Stage C（`games/block{N}/group{g}.json`）が落ちる。
      await this.env.R2_BUCKET.put(r2Key, safeJsonStringify(archiveData), {
        httpMetadata: { contentType: 'application/json' }
      });
      this.recordDependencyOutcome?.('succeeded', 'R2_BUCKET', 'archive_game_data');
      const status = { ok: true, r2Key, archivedAt: attemptedAt };
      try {
        await this.storage.put('archiveStatus', status);
        this.recordStorageOutcome?.('succeeded', 'archive_status_record');
      } catch (error) {
        this.recordStorageOutcome?.('failed', 'archive_status_record', { error: boundedError(error) });
        console.error(`Game data reached R2 but archive completion could not be recorded: ${r2Key}`, error);
        return {
          ok: false,
          r2Key,
          attemptedAt,
          published: true,
          error: `archive completion record failed: ${error?.message || error}`
        };
      }
      console.log(`Game data archived to R2: ${r2Key}`);
      return status;
    } catch (error) {
      this.recordDependencyOutcome?.('failed', 'R2_BUCKET', 'archive_game_data', { error: boundedError(error) });
      console.error(`Error archiving game data to R2:`, error);
      const status = { ok: false, r2Key, attemptedAt, error: String(error?.message || error) };
      try {
        await this.storage.put('archiveStatus', status);
        this.recordStorageOutcome?.('succeeded', 'archive_status_record');
      } catch (recordError) {
        this.recordStorageOutcome?.('failed', 'archive_status_record', { error: boundedError(recordError) });
        console.error('Error recording archive failure:', recordError);
      }
      return status;
    }
  }
}

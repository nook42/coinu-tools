// workers/game_workers/lib/evidence-reconciler.js
// Evidence コントラクト（検閲対策・結果提出オンチェーン記録）のイベント取得・検証・採用選定。
// docs/EVIDENCE_CENSORSHIP_PLAN.md §4.2/§4.3
//
// 役割:
//   1. getLogs（チャンク分割）で block N の ResultSubmitted イベントを全件取得
//   2. 完全性検証: 取得件数 == resultCount(N) かつ seq が 1..count を欠番なく被覆（不一致は throw）
//   3. 各イベントの検証（安価棄却順序: サイズ → compact frame →
//      メンバーuid照合 → 署名/ハッシュのフル検証）
//   4. 優先規則: uid ごとに seq 昇順で最初の有効イベントを採用（E-3 first-write-wins のオンチェーン拡張）
//
// 検証ツールはこのファイルと同一の規則を独立実装して照合する（決定論厳守）。

import { verifyMessage, keccak256, toHex, parseAbiItem } from 'viem';
import {
  computeChatHashV2,
  isCanonicalUid, isCanonicalText, isCanonicalTimestamp,
  isOpaqueField, isCanonicalDepositIds, isCanonicalSignature, isRepresentableSignature,
  isCanonicalActionPreimage, isMsgRef, isActionHash, parseBlockAddress} from './protocol-v2.js';
// P-2026-0827（2026-08-08）: 検証②.6 のプリイメージは**採点本体と同一実装**を使う。
// 写経すると「片方だけ深い入れ子で park する／片方だけ受理する」形の食い違いが必ず戻る
// （`no-shadow-implementation-test.mjs` が守っているのと同じ規則）。
import { actionSnapshotPreimage } from './game-result-calculator.js';
import { verifyPriorityFields } from './priority-fields.js';
import {
  compactBytesToPayload,
  decodeSubmissionPayloadString,
  isEvidenceCompactBytes,
  selfReceiptAggregateSignString,
} from './evidence-compact-v1.js';
import {
  MAX_SELF_AGGREGATE_TARGETS,
  validateSubmissionStructure, isPlainRecord,
} from './submission-limits.js';
import { getLogsAdaptive } from './getlogs-adaptive.js';

// getLogs のチャンク幅（プロバイダの範囲上限対策）と範囲推定の安全マージン（ブロック数）
const GETLOGS_CHUNK = 2000;
const RANGE_MARGIN = 2000;
const ETH_BLOCK_SEC = 12;
// ResultSubmitted.seq は indexed かつコントラクトが 1..resultCount の連番で一度だけ発行する。
// topic OR をこの件数に刻めば、同一ブロックへ最大長提出が集中しても viem が
// 1応答で復号する data は最大8件に固定される（ブロック幅だけではこの上限を作れない）。
export const RESULT_LOG_SEQS_PER_READ = 8;

export const RESULT_SUBMITTED_EVENT = parseAbiItem(
  'event ResultSubmitted(uint256 indexed blockNum, uint256 indexed seq, address indexed sender, bytes data, uint256 timestamp)'
);

// hex文字列(0x...) → Uint8Array
export function hexToBytes(hex) {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

// イベントの data(hex) → 正式compact payload。
// Evidence contract自体は任意bytesを保存するため、現行compact以外は正式提出として採用しない。
export async function decodeEvidenceData(hexData) {
  const bytes = hexToBytes(hexData);
  if (!isEvidenceCompactBytes(bytes)) return { ok: false, reason: 'unsupported_format' };
  try {
    const raw = compactBytesToPayload(bytes);
    const compactContext = { payload: raw, context: decodeSubmissionPayloadString(raw) };
    return { ok: true, raw, compactContext, format: 'evidence-compact-v1' };
  } catch {
    return { ok: false, reason: 'compact_decode_error' };
  }
}

// ============================================================
// オンチェーン取得
// ============================================================

// resultCount(blockNum) を読む
export async function getResultCount(publicClient, contractAddress, blockNum) {
  const count = await publicClient.readContract({
    address: contractAddress,
    abi: [{ name: 'resultCount', type: 'function', stateMutability: 'view',
            inputs: [{ name: '', type: 'uint256' }], outputs: [{ name: '', type: 'uint256' }] }],
    functionName: 'resultCount',
    args: [BigInt(blockNum)]
  });
  return Number(count);
}

// 提出窓のタイムスタンプ範囲からethブロック範囲を概算する（マージン込み）。
// 概算の正しさは完全性検証（counter照合）が担保する — 足りなければ呼び出し側が範囲を広げて再試行。
export function estimateBlockRange(latestBlockNumber, latestBlockTimestampSec, windowStartSec, windowEndSec) {
  const latestNum = Number(latestBlockNumber);
  const latestTs = Number(latestBlockTimestampSec);
  const fromBlock = Math.max(0, latestNum - Math.ceil((latestTs - windowStartSec) / ETH_BLOCK_SEC) - RANGE_MARGIN);
  const toBlock = Math.min(latestNum, latestNum - Math.floor((latestTs - windowEndSec) / ETH_BLOCK_SEC) + RANGE_MARGIN);
  return { fromBlock: BigInt(fromBlock), toBlock: BigInt(Math.max(fromBlock, toBlock)) };
}

// ResultSubmitted(blockNum=N) を指定範囲から1回だけ取得する。
// GameMasterDO の alarm 再開経路はこの関数を1つの成功範囲ずつ呼び、即D1へ逃がす。
export async function fetchResultEventsRange(
  publicClient, contractAddress, blockNum, fromBlock, toBlock, seqs = null, includeProvenance = false,
) {
  let boundedSeqs = null;
  if (seqs !== null) {
    if (!Array.isArray(seqs) || seqs.length < 1 || seqs.length > RESULT_LOG_SEQS_PER_READ) {
      throw new Error(`evidence seq filter must contain 1..${RESULT_LOG_SEQS_PER_READ} entries`);
    }
    boundedSeqs = seqs.map((seq) => BigInt(seq));
    if (boundedSeqs.some((seq) => seq < 1n)
      || new Set(boundedSeqs.map(String)).size !== boundedSeqs.length) {
      throw new Error('evidence seq filter must contain unique positive integers');
    }
  }
  const logs = await publicClient.getLogs({
    address: contractAddress,
    event: RESULT_SUBMITTED_EVENT,
    args: boundedSeqs === null
      ? { blockNum: BigInt(blockNum) }
      : { blockNum: BigInt(blockNum), seq: boundedSeqs },
    fromBlock: BigInt(fromBlock),
    toBlock: BigInt(toBlock)
  });
  for (const log of logs) {
    for (const value of [log.args.blockNum, log.args.seq, log.args.timestamp, log.blockNumber]) {
      if (!Number.isSafeInteger(Number(value)) || Number(value) < 0) {
        throw new Error('Evidence log integer is outside the JS safe integer range');
      }
    }
  }
  return logs.map((log) => ({
    blockNum: Number(log.args.blockNum),
    seq: Number(log.args.seq),
    sender: log.args.sender,
    data: log.args.data,
    timestamp: Number(log.args.timestamp),
    txHash: log.transactionHash,
    evtBlock: Number(log.blockNumber),
    ...(includeProvenance ? { blockHash: log.blockHash, logIndex: Number(log.logIndex) } : {}),
  }));
}

// ResultSubmitted(blockNum=N) を [fromBlock, toBlock] からチャンク分割で全件取得。
// 平常時は従来どおり2,000ブロック幅の1 RPC。応答過大のときだけ半分へ割り、
// 累計分割数では打ち切らず1ブロック単位まで到達する。
//
// 注意: この全件返却APIは第三者検証ツール向け。128MB制約のあるGameMasterDOは
// fetchResultEventsRange を alarm 間で1成功範囲ずつ処理し、この配列へ全量を集めない。
export async function fetchResultEvents(publicClient, contractAddress, blockNum, fromBlock, toBlock) {
  const events = [];
  let from = BigInt(fromBlock);
  const to = BigInt(toBlock);
  while (from <= to) {
    const chunkTo = from + BigInt(GETLOGS_CHUNK - 1) > to ? to : from + BigInt(GETLOGS_CHUNK - 1);
    const chunk = await getLogsAdaptive(
      (f, t) => fetchResultEventsRange(publicClient, contractAddress, blockNum, f, t),
      from,
      chunkTo,
    );
    events.push(...chunk);
    from = chunkTo + 1n;
  }
  return events;
}

// 完全性検証: seq が 1..expectedCount を欠番・重複なく被覆していること。
// 満たさない場合は throw（無言スキップ禁止 — RPC取りこぼしや範囲不足をここで顕在化させる）。
export function verifyCompleteness(events, expectedCount) {
  const seen = new Set();
  for (const ev of events) {
    if (seen.has(ev.seq)) throw new Error(`evidence completeness: duplicate seq ${ev.seq}`);
    seen.add(ev.seq);
  }
  if (seen.size !== expectedCount) {
    throw new Error(`evidence completeness: got ${seen.size} events, expected resultCount=${expectedCount}`);
  }
  for (let s = 1; s <= expectedCount; s++) {
    if (!seen.has(s)) throw new Error(`evidence completeness: missing seq ${s}`);
  }
}

// ============================================================
// バンドル検証（安価棄却順序・calculator ①②/②.5/②.6 と同一規則）
// ============================================================

// 🔴 P-2026-0830（2026-08-08）: **検証①／②.5／②.6 は WS 提出入口と共有する。**
//
//   結果提出は先着1回だけ受け付ける（E-3 first-write-wins）。ところが「先着」の定義が
//   入口ごとに違っていた:
//     ・WS（`chat-game-DO.handleWsSubmit`） … **形式が合っているバイト列**を受け取った時点で確定
//     ・Evidence（`validateResultBundle`）   … **完全に検証を通った提出**を受け取った時点で確定
//   WS 側は保存の前に、外側ウォレット署名も chatHash 再計算も encryptedDataHash 再計算も
//   していなかったので、**形式は正しいが署名が無効な1通目**が枠を焼けた。画面には
//   「提出完了」が出て再提出は `alreadySubmitted` で拒否され、採点では `invalid_signature`
//   で0点。オンチェーン救済もクライアントは同じ無効なバイト列を再送するだけ。
//   実測（3人巡回投票）: WS 経由 `{0, 100, 200}` ／ Evidence 経由 `{200, 200, 200}`
//   ＝ 本人が全損し、その投票先も巻き添えでボーナス100を失う。
//
//   → 検証そのものを**関数として切り出し、WS からも同じ関数を呼ぶ**。
//   ⚠️ **写経は禁止**（実装が3つに増えると必ずどれか1つが取り残される）。
//      ここを直したら WS 側も自動的に直る、という関係を壊さないこと。
//   ⚠️ 切り出しは純粋なリファクタで、Evidence 経路の受理集合・棄却理由・
//      評価順序を1ビットも変えていない。

// 検証①/②.5/②.6 のコア。`validateResultBundle` の JSON パース・`missing_fields`・
// `not_a_member`（＝ Evidence 固有の入口検査）を除いた**残り全部**。
//
// bundle: JSON.parse 済みの提出バンドル
// blockNum: 採点対象ブロック（署名文脈）
// member: { uid, addr, groupId } — 登録名簿の値（uid は名簿の生値・addr は登録ウォレット）
// 戻り値: { valid: true } | { valid: false, reason: 'invalid_signature'|'chathash_mismatch'|'snapshot_mismatch' }
export async function verifyBundleCore(bundle, blockNum, member) {
  const { encryptKey, chatHash, signature, submittedAt, encryptedDataHash, depositIds, encryptedActions, messages } = bundle;
  const memberUids = Array.isArray(member?.memberUids) ? member.memberUids : [member?.uid];

  const bounded = validateSubmissionStructure(bundle, {
    blockNum: Number(blockNum),
    groupId: Number(member?.groupId),
    memberUids,
  });
  if (!bounded.ok) return { valid: false, reason: 'invalid_signature' };

  // 🔴 P-2026-0824（2026-08-07・F3）: **署名対象に入る値の正準性検査**。
  //   採点本体（`game-result-calculator.js` 検証①）は `isOpaqueField` /
  //   `isCanonicalTimestamp` / `isCanonicalDepositIds` を通してから署名検証へ入るのに、
  //   ここには**同じゲートが無かった**。`typeof` すら見ていないので、
  //   `chatHash` に孤立サロゲート・`submittedAt` に小数・`depositIds` に数値を入れた
  //   バンドルが（本人が正しく署名できるので）Evidence 側では **valid=1 で「採用」**され、
  //   採点側では同じバイト列が `invalid_signature` で失格になる。
  //   evidence-report.json（公開・block-verifier が厳密照合）と game_results が
  //   食い違うので、**結論そのものが割れる**。
  //   さらに ZKP ゲスト（Rust）は `submittedAt: i64` / `depositIds: Vec<String>` なので
  //   これらの値を表現できない ＝ 正典側で落としておかないと回路が再現できない。
  //   ⚠️ 理由は**採点本体と同じ `invalid_signature`** を返す（`missing_fields` にすると
  //      採用／棄却は揃っても理由が割れたままになる）。`not_a_member` より後ろに置くのは、
  //      非メンバーの理由を従来どおり `not_a_member` に保つため。
  //   ⚠️ `depositIds` の正規化は **採点本体と同一**（`Array.isArray(x) ? x : null`）。
  //      非配列を `null` に寄せるのは、下の `dataString`（署名対象）も同じ正規化を
  //      しているため — ここだけ厳しくすると「本人が正しく署名したのに Evidence だけ棄却」
  //      が復活する（D-1 の再発）。
  //
  // 🔴 P-2026-0832（2026-08-08）: **外側ウォレット署名そのものの正準形**も同じゲートで見る。
  //   系内の他の署名は全部 `isCanonicalSignature` を通っていた
  //   （`game-result-calculator.js` の 発信 `:242` / メッセージ `:898` / 受領証明 `:1225` /
  //    候補収集 `:1563`）のに、**提出物の外側署名だけが素通し**だった。
  //   実測（外側署名だけを差し替え・他は全部正規）:
  //     正規 `0x`+130 hex        … WS ACCEPT / Evidence ACCEPT / 採点 200,200,200
  //     オブジェクト `{r,s,v}`   … WS ACCEPT / Evidence ACCEPT / 採点 200,200,200 ← 🔴
  //     high-s の双子 `(r,n−s)`  … WS ACCEPT / Evidence ACCEPT / 採点 200,200,200 ← 🔴
  //   ZKP ゲスト（Rust）の `SubmissionIn.sig` は `[u8; 65]` で、**オブジェクト署名は型として
  //   表現できない**。唯一のデコーダ `crates/group-host/src/main.rs::sig65()` は `as_str()` を
  //   前提にしているので、非文字列の署名を載せた提出物が正典で受理されると
  //   **プルーバがその場で panic ＝ そのブロックの証明が永久に作れない**。
  //   P-2026-0806 が `encryptKey` / `chatHash` / `submittedAt` / `depositIds` / `messages` に
  //   課した「ZKP ゲストが表現できない型を排除する」方針から取り残された最後の1フィールド。
  //   ⚠️ 署名文字列は現行の述語どおり小文字 hex のみ。viem の正規形と一致する。
  //   ⚠️ low-s は層ごとの攻撃者モデルが異なる。制御できるものには厳格に、
  //      制御できないものには寛容に扱い、JS の外側署名と Rust の復元受理を一本化しない
  //      （J-16）。ZKP 側に追加の low-s ゲートを足さない。
  if (!isOpaqueField(encryptKey) || !isOpaqueField(chatHash)
    || !isCanonicalTimestamp(submittedAt)
    || !isOpaqueField(encryptedDataHash)
    || !isCanonicalDepositIds(Array.isArray(depositIds) ? depositIds : null)
    || !isRepresentableSignature(signature)) {
    return { valid: false, reason: 'invalid_signature' };
  }

  // ①: 正規署名メッセージ（v3.2・calculator 検証① と同一シリアライズ。
  // blockNum/uid を明示束縛＝クロスブロック再利用・uid偽装は署名不一致で棄却）
  try {
    const dataString = JSON.stringify({
      blockNum: Number(blockNum),
      uid: member.uid,
      encryptKey,
      chatHash,
      submittedAt,
      encryptedDataHash: encryptedDataHash ?? null,
      depositIds: Array.isArray(depositIds) ? depositIds : null
    });
    const ok = await verifyMessage({ address: member.addr, message: dataString, signature });
    if (!ok) return { valid: false, reason: 'invalid_signature' };
  } catch {
    return { valid: false, reason: 'invalid_signature' };
  }
  // ②.5: chatHash ↔ messages（本物署名＋壊した本体の変種で正規サーバー版を置換する攻撃の遮断）。
  // chatHash 規則版13（§2.3・正準順の msgKey と発言署名）。msgKey文脈は採点対象の blockNum とメンバーの groupId で
  // 構築＝クロスブロック/グループは不一致。
  //
  // 🔴 P-2026-0824（2026-08-07・F2）: **`computeChatHashV2` を呼ぶ前に要素の型を検査する。**
  //   ここには `Array.isArray(messages)` しか無く、要素は生の JSON 値のまま
  //   `computeChatHashV2` へ流れていた。`messages` は外側署名に直接は入らず
  //   （署名対象は blockNum/uid/encryptKey/chatHash/submittedAt/encryptedDataHash/depositIds）、
  //   提出者は本物の署名を付けたまま `messages: [null]` を載せられる。
  //   すると `buildMsgKeyGetter` の `WeakMap.get(null)` / `m.uid` 参照で **TypeError** が飛び、
  //   `calcEvidenceUnit` の外まで抜けて**ブロック全体が park** する。
  //   入力はオンチェーンにあって不変なので、リトライも `/reset-block` も `unpark` も
  //   同じ壁に当たり、そのブロックの集計・Merkle ルート・報酬配布は**コードを直さない限り
  //   永久に完了しない**（同じ vendor コードを使う block-verifier も同時に落ちる）。
  //   採点本体（`game-result-calculator.js` の P-2026-0811 #4/#5）には**同じゲートが既にあり**、
  //   要素型が壊れていれば `submittedMsgs = null` → `chathash_mismatch` で完走する。
  //   ＝「同じ修正を2箇所のうち1箇所にしか入れていない」形だった。ここを採点本体に揃える。
  //   ⚠️ 述語は採点本体と**同じ順序・同じ顔ぶれ**で書く（差分を目で照合できるようにするため）。
  //      実測（ミューテーション）での各述語の効き:
  //        `m !== null` … 必須（外すと `[null]` で TypeError → park に戻る）
  //        `isCanonicalUid` / `isCanonicalText` / `isCanonicalTimestamp` … 必須
  //          （外すと「例外にはならないが非正準」な messages が **valid=1 で採用**され、
  //            採点本体の `chathash_mismatch` と結論が割れる。T4c 参照）
  //        `typeof m === 'object'` / `!Array.isArray(m)` … **JSON 入力からは到達しない冗長**。
  //          JSON のプリミティブ・配列は `.uid` が必ず undefined なので `isCanonicalUid` が
  //          先に落とす。採点本体と1対1で並べるために残す（消しても現状は挙動不変）。
  //   ⚠️ `Array.isArray(messages)` は Evidence 経路では上流の `missing_fields` が既に
  //      保証しているので**到達しない**（＝ Evidence の理由は1つも変わらない）。
  //      WS 経路から呼ばれたときにこの関数だけで自己完結するために置く。
  if (!Array.isArray(messages) || !messages.every((m) =>
    typeof m === 'object' && m !== null && !Array.isArray(m)
    && isCanonicalUid(m.uid)
    && isCanonicalText(m.text ?? '')
    && isCanonicalTimestamp(m.timestamp))) {
    return { valid: false, reason: 'chathash_mismatch' };
  }
  // 多重防御: 上のゲートを抜けた値でも例外は park させない（結論は chathash_mismatch）。
  // ⚠️ 上のゲートがある限り **JSON 入力からは到達しない**（実測: try/catch を外しても
  //    全テストが緑のまま）。ゲートを緩めた／`computeChatHashV2` が将来増えた例外を
  //    投げるようになった場合の最後の受け皿として置く。**park は最悪の失敗モード**
  //    （オンチェーン入力は不変＝リトライも reset も効かない）なので、ここは残す。
  let computedChatHash;
  try {
    computedChatHash = computeChatHashV2(messages, blockNum, member.groupId);
  } catch {
    return { valid: false, reason: 'chathash_mismatch' };
  }
  if (computedChatHash !== chatHash) {
    return { valid: false, reason: 'chathash_mismatch' };
  }
  // ②.6: encryptedDataHash ↔ スナップショット本体（正規3フィールド順・calculator と同一・v3.2）
  //
  // 🔴 P-2026-0827（2026-08-08）: プリイメージは**採点本体と同じ関数**で作る。
  //   `JSON.parse` は非再帰（V8 は深さ 1,000,000 まで通る）のに `JSON.stringify` は再帰で、
  //   Node v22 は**深さ 6,842 で `RangeError: Maximum call stack size exceeded`**（実測・二分探索）。
  //   `encryptedActions` は署名で覆われた `encryptedDataHash` の**プリイメージ**であって
  //   中身の形は誰も検査していないので、`{"votes":{"a":{"a":{...}}}}` を積むだけで例外が飛び、
  //   `calcEvidenceUnit` の外まで抜けて**ブロック全体が park** していた。
  //   攻撃コストは **gzip 後 388 バイトの `Evidence.submitResult` 1回**
  //   （`messages: []` ＋ 正しい chatHash ＋ 本物のウォレット署名で足りる）。
  //   オンチェーン入力は不変なので、リトライも `/reset-block` も `unpark` も同じ壁に当たる
  //   ＝ そのブロックの集計・Merkle ルート・報酬配布は**コードを直さない限り永久に完了しない**
  //   （同じ vendor コードを使う block-verifier も同時に落ちる）。
  //   5行上の `computeChatHashV2` にはこの受け皿が入っていたのに、ここだけ外に出ていた。
  // ⚠️ 例外を握って `snapshot_mismatch` に倒すのは**誤り**（2026-08-08 訂正）。
  //   ZKP ゲストは深い入れ子でも受理するので、正典だけ失格にすると採点が割れる。
  //   `actionSnapshotPreimage` は深さに依存せず**同じバイト列**を作る。
  const preimage = actionSnapshotPreimage(encryptedActions);
  const recomputed = (preimage === null || !isCanonicalActionPreimage(preimage))
    ? null : keccak256(toHex(preimage));
  if (recomputed === null || recomputed !== encryptedDataHash) {
    return { valid: false, reason: 'snapshot_mismatch' };
  }

  const aggregate = encryptedActions?.observed?.selfReceiptAggregate;
  if (aggregate != null) {
    if (aggregate?.version !== 1 || aggregate.receiverUid !== member.uid
      || !Array.isArray(aggregate.entries) || aggregate.entries.length < 1
      || aggregate.entries.length > MAX_SELF_AGGREGATE_TARGETS
      || !isCanonicalSignature(aggregate.signature)) {
      return { valid: false, reason: 'snapshot_mismatch' };
    }
    const seen = new Set();
    for (const entry of aggregate.entries) {
      if (!entry || !isCanonicalTimestamp(entry.timestamp)) return { valid: false, reason: 'snapshot_mismatch' };
      const key = entry.targetType === 'read'
        ? (typeof entry.senderUid === 'string' && isMsgRef(entry.msgRef) ? `r|${entry.senderUid}|${entry.msgRef}` : null)
        : (entry.targetType === 'action' && isActionHash(entry.actionHash) ? `a|${entry.actionHash}` : null);
      if (!key || seen.has(key)) return { valid: false, reason: 'snapshot_mismatch' };
      seen.add(key);
    }
    const bAddr = parseBlockAddress(member.bAddr);
    if (!bAddr) return { valid: false, reason: 'snapshot_mismatch' };
    try {
      const ok = await verifyMessage({
        address: bAddr.address,
        message: selfReceiptAggregateSignString(blockNum, member.groupId, member.uid, aggregate.entries),
        signature: aggregate.signature,
      });
      if (!ok) return { valid: false, reason: 'snapshot_mismatch' };
    } catch {
      return { valid: false, reason: 'snapshot_mismatch' };
    }
  }

  if (Object.prototype.hasOwnProperty.call(encryptedActions, 'priority')) {
    let priority;
    try {
      if (!isPlainRecord(member.memberBAddrs)) {
        return { valid: false, reason: 'invalid_signature', detail: 'member block addresses are unavailable' };
      }
      priority = await verifyPriorityFields(bundle, {
        blockNum: Number(blockNum), groupId: Number(member.groupId), memberUids,
        bAddrOf: (uid) => parseBlockAddress(member.memberBAddrs[uid]),
        chatWindow: member.chatWindow ?? null, verify: verifyMessage,
      });
    } catch {
      return { valid: false, reason: 'invalid_signature', detail: 'priority verification failed unexpectedly' };
    }
    if (!priority.ok) return { valid: false, reason: 'invalid_signature', detail: priority.reason };
  }

  return { valid: true };
}

// members: ブロックN全グループのメンバー配列 [{uid, addr, bAddr, groupId}]
// chatHash照合は常に computeChatHashV2（規則版13・正準順の msgKey と発言署名）。
// v3.2: walletSignature/blockKey廃止 — バンドルは uid を自己申告し、外側ウォレット署名
// （dataString = {blockNum, uid, encryptKey, chatHash, submittedAt, encryptedDataHash, depositIds}）
// を登録アドレスで検証することで帰属を証明する（uid偽装は署名不一致で棄却）。
// 戻り値: { valid, reason?, uid?, groupId?, bundle? }
export async function validateResultBundle(raw, blockNum, membersIndex, sender, predecodedContext = null) {
  // 本番提出は versioned compact 単一形式。失敗理由も実際の境界名に合わせる。
  let compactContext;
  let bundle;
  try {
    // decodeEvidenceData が同じ raw から返した文脈だけを再利用する。raw の一致を必須にし、
    // 任意の別 bundle を第4引数から注入できる検証バイパスにはしない。
    if (predecodedContext !== null && predecodedContext?.payload !== raw) {
      throw new Error('predecoded compact context does not match raw payload');
    }
    compactContext = predecodedContext === null
      ? decodeSubmissionPayloadString(raw)
      : predecodedContext.context;
    bundle = compactContext.bundle;
  } catch {
    return { valid: false, reason: 'compact_decode_error' };
  }
  if (!bundle || typeof bundle !== 'object') return { valid: false, reason: 'compact_decode_error' };

  const { uid, encryptKey, chatHash, signature, submittedAt, encryptedDataHash, depositIds, encryptedActions, messages } = bundle;
  // 🔴 P-2026-0826（2026-08-07・D-1）: **`submittedAt` と `depositIds` を truthy 判定から外す。**
  //   `!submittedAt` は JS の falsy 規則で **正当な `0` を「項目欠落」と誤認**していた。
  //   `depositIds` も `!Array.isArray(...)` で `null` を弾いていた。どちらも採点本体
  //   （`game-result-calculator.js` 検証①）と Rust ゲスト（`submitted_at: i64` /
  //   `deposit_ids: Option<Vec<String>>`）は**受理する**値で、この経路だけが厳しかった。
  //   Evidence 経路は「運営に握り潰された参加者の自己救済」なので、ここで棄却されると
  //   その人は `no_submit` で0点になり、**その人の投票先もボーナスを失う**
  //   （3人組の実測: 本来 A=200/B=200/C=200 → A=0/B=100/C=200）。
  //   判定は下の正準性ゲート（採点本体と1ビット同じ述語）へ一本化する。
  //   ⚠️ 反対方向（緩めすぎ）にも注意: 小数・文字列・2^53 超の `submittedAt`、
  //      数値要素や非10進文字列を含む `depositIds` は、下のゲートが従来どおり弾く。
  if (!uid || !encryptKey || !chatHash || !signature || !encryptedDataHash ||
      !encryptedActions || typeof encryptedActions !== 'object' || !Array.isArray(messages)) {
    return { valid: false, reason: 'missing_fields' };
  }

  // メンバー照合（安価）: 自己申告 uid → 登録メンバー（帰属の真正性は下の外側署名で確定）
  //
  // 🔴 P-2026-0831（2026-08-08・ユーザー確定 (A)）: **uid は文字列で照合する。**
  //   利用者 ID は X のアカウント ID（`1234567890123456789` のような数字の並び）だが、
  //   2^53 を超えるので**文字列として**持ち回る（将来の匿名エントリーでは `0x…` の
  //   ウォレットアドレスになりうる ——`EVIDENCE_CENSORSHIP_PLAN.md` §8b-2 ④）。
  //   ところが入口ごとに照合が違っていた:
  //     ・WS（`chat-game-DO.handleWsSubmit`） … `payloadUid !== uid` の**厳密比較**＝数値 `1` は拒否
  //     ・Evidence（ここ）                     … `byUid[String(uid)]` ＝ **文字列へ変換してから**探す
  //                                              ので数値 `1` / `true` / `["1"]` / `null` が名簿の
  //                                              `"1"` / `"true"` / `"null"` に当たって**受理**された
  //   得点は変わらない（採点は名簿側の uid で引き直す）が、Evidence 採用と WS 保存の
  //   バイト列が食い違うので `calcApplyEvidenceToGroup` が **`serverState:'mismatch'`
  //   （改竄の疑い）**を立てる。`evidence-report.json` は「運営が嘘をついていないか」を
  //   記録で示す系なので、**理由のない改竄シグナル**はそれ自体がノイズ＝害。
  //
  //   ⚠️ `String()` は残す。先に「文字列であること」を検査すれば恒等変換になり、
  //      `Object.create(null)` のマップで `__proto__` 等の正準 uid を扱う既存の形
  //      （P-2026-0823）を壊さない。**検査を足すだけ**にしてある。
  //   ⚠️ 理由は **`not_a_member`**。採点本体（`game-result-calculator.js`）は提出物を
  //      **名簿の uid で引く**（`submissions?.[r.uid]`）ので、名簿の uid と厳密一致しない
  //      自己申告 uid の提出物は「その人の提出物ではない」＝誰の提出物にもならず、
  //      その人は `no_submit` になる。WS 拒否（`payload uid must match your uid`）も
  //      同じ `no_submit` に落ちるので、3経路の結論が揃う。
  //      `invalid_signature` にしないのは、バンドルの `uid` が**署名対象に入っていない**
  //      （署名文字列の `uid` は名簿値 `member.uid`）＝署名の問題ではないから。
  //   ⚠️ Rust 側（ZKP）は `uid: String` で、`group-host` は `m["uid"].as_str().unwrap()`
  //      なので**非文字列 uid はそもそも表現できない**。JS を締める方向でしか揃わない。
  if (!isCanonicalUid(uid)) return { valid: false, reason: 'not_a_member' };
  const member = membersIndex.byUid[String(uid)];
  // 名簿側が非文字列（運営が壊した名簿）なら `uid === member.uid` が成立しない。
  // その名簿は採点本体の `memberUids.every(isCanonicalUid)` で必ず throw するので、
  // ここで採用しないほうが安全側（fail-closed）。
  if (!member || uid !== member.uid) return { valid: false, reason: 'not_a_member' };
  if (typeof sender !== 'string' || typeof member.addr !== 'string'
      || sender.toLowerCase() !== member.addr.toLowerCase()) {
    return { valid: false, reason: 'sender_mismatch' };
  }

  // P7-B: compact 枠も WS 入口・Stage 3 witness と同じ権威文脈へ束縛する。
  // codec は参加者を memberUids の添字で運ぶため、名簿順だけを入れ替えて添字も
  // 揃えれば、復号後 bundle は完全に同じまま枠だけを変えられる。旧 Evidence 入口は
  // `.bundle` だけを残して枠を捨てたのでその提出を採用し、保存された raw を後で読む
  // Stage 3 が compact roster mismatch を throw してブロック全体を停止していた。
  // blockNum / groupId も同じ「入口で捨て、後段で必須」の形なので3欄を一緒に検査する。
  const rosterMatches = Array.isArray(compactContext.memberUids)
    && Array.isArray(member.memberUids)
    && compactContext.memberUids.length === member.memberUids.length
    && compactContext.memberUids.every((memberUid, index) => memberUid === member.memberUids[index]);
  if (compactContext.blockNum !== Number(blockNum)
      || compactContext.groupId !== Number(member.groupId)
      || !rosterMatches) {
    return { valid: false, reason: 'compact_context_mismatch' };
  }

  // 検証① / ②.5 / ②.6。**WS 提出入口（chat-game-DO.handleWsSubmit）と同じ関数**を呼ぶ
  // （P-2026-0830・上の `verifyBundleCore` の項）。ここに写経を戻さないこと。
  const core = await verifyBundleCore(bundle, blockNum, member);
  if (!core.valid) return { valid: false, reason: core.reason };

  return { valid: true, uid: member.uid, groupId: member.groupId, bundle };
}

// メンバー索引の構築: groups = [{group_id, members:[{uid, addr, bAddr}]}]
// v3.2: 帰属は自己申告 uid → 外側ウォレット署名で確定するため byUid 索引を使う
// 🔴 P-2026-0823（2026-08-07）: **`Object.create(null)` を使う。**
//   `isCanonicalUid` は `/^[\x21-\x7E]+$/` を許すので uid は `__proto__` / `toString` /
//   `constructor` / `valueOf` / `hasOwnProperty` になりうる（意図的な広さ）。素の `{}` だと
//     ・`byUid['__proto__'] = member` は **own property にならず**、索引の [[Prototype]] が
//       member オブジェクトに差し替わる（＝索引が member のフィールド名を全部「メンバー」として
//       持つようになる: `byUid['addr']` / `byUid['groupId']` が引ける）
//     ・メンバーでない uid `'toString'` を自己申告したバンドルで `byUid['toString']` が
//       `Object.prototype.toString`（truthy）を返し、`not_a_member` で落ちるべきものが
//       `member.addr === undefined` 経由の `invalid_signature` になる
//   invalid_reason は D1 evidence_events と evidence-report.json に載り block-verifier が
//   厳密照合するので、理由の食い違いはそのまま検証不一致になる。
export function buildMembersIndex(groups, { chatWindow = null } = {}) {
  const byUid = Object.create(null);
  for (const g of groups) {
    const memberUids = (g.members || []).map((m) => m.uid);
    const memberBAddrs = Object.create(null);
    for (const m of g.members || []) {
      if (m.uid != null) memberBAddrs[String(m.uid)] = m.bAddr;
    }
    Object.freeze(memberBAddrs);
    for (const m of g.members || []) {
      if (m.uid != null) {
        byUid[String(m.uid)] = {
          uid: m.uid,
          addr: m.addr,
          bAddr: m.bAddr,
          depIds: m.depIds,
          groupId: g.group_id,
          memberUids,
          memberBAddrs,
          chatWindow: isPlainRecord(chatWindow) ? chatWindow : null,
        };
      }
    }
  }
  return { byUid };
}

// ============================================================
// 優先規則（precedence）: uid ごとに seq 昇順で最初の有効イベントを採用
// ============================================================

// validatedEvents: [{seq, txHash, raw, validation:{valid, reason?, uid?, groupId?, bundle?}}]
// 戻り値: { adoptedByUid: { [uid]: {seq, txHash, raw, bundle, groupId} }, invalid: [...] }
// 🔴 P-2026-0823（2026-08-07）: **`Object.create(null)` を使う。**
//   素の `{}` だと uid が `toString` / `constructor` / `valueOf` / `hasOwnProperty` の
//   提出で `!adoptedByUid[uid]` が **Object.prototype のメソッド（truthy）**を拾い、
//   「もう採用済み」と誤判定して **1件も採用されない**。uid が `__proto__` の場合は
//   代入が [[Prototype]] 設定に化けて own property にならず、これも採用集合から消える。
//   どちらもエラーも警告も出ず `invalid` にも入らない＝`GET /evidence-failures` にも出ない。
//   uid を割り当てるのは運営なので、これは **Evidence（検閲対策の自己救済）を運営が
//   uid ひとつで無効化できる**穴だった（オンチェーン提出済みなのに no_submit で0点）。
//   ⚠️ `Object.create(null)` でもキー列挙順（整数風キー昇順 → それ以外は挿入順）は
//      素の `{}` と同一なので、下流の `Object.entries` 順に依存したレポートは不変。
export function selectAdoptedResults(validatedEvents) {
  const sorted = [...validatedEvents].sort((a, b) => a.seq - b.seq);
  const adoptedByUid = Object.create(null);
  const invalid = [];
  for (const ev of sorted) {
    if (!ev.validation.valid) {
      invalid.push({ seq: ev.seq, txHash: ev.txHash, reason: ev.validation.reason });
      continue;
    }
    const uid = ev.validation.uid;
    if (!adoptedByUid[uid]) {
      adoptedByUid[uid] = {
        seq: ev.seq,
        txHash: ev.txHash,
        raw: ev.raw,
        bundle: ev.validation.bundle,
        groupId: ev.validation.groupId
      };
    }
    // 2件目以降の有効イベントは不採用（first-write-wins）— レポートには含めない（正当な再送のため）
  }
  return { adoptedByUid, invalid };
}

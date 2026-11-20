// src/recovery/bundle.js — 提出バンドルの byte-exact 再構成（v3.2/v3.3）
//
// MIRROR: src/components/game/SubmissionPhase.js:742-1485（handleSubmit の本体）。
// React state → 引数に置換した以外はロジックをバイト等価に写す。VENDOR_SYNC.md に行範囲 sha256 を記録。
// priority は署名の前に確かめて付け、偽なら欄なしの束に戻す。
//
// v3.2 提出物（§6.8）:
//   snapshotData = { votes: {myUid: 自分の投票}, reports: {myUid: [自分の密告]},
//                    observed: { votes, reports, receipts } }（観測した他人の発信＋全受領証明）
//   dataString   = {blockNum, uid, encryptKey, chatHash, submittedAt, encryptedDataHash, depositIds}
//                  （ウォレット署名対象。walletSignature フィールドは廃止 — masterの素材のため
//                   提出物に絶対に含めない。blockNum/uid の文脈束縛は dataString へ明示的に移設）
//   payload      = {uid, encryptKey, chatHash, signature, submittedAt, encryptedDataHash,
//                   depositIds, encryptedActions, messages}
//
// v3.3 リアルタイム受領証明ルールの提出側:
//   - 投票: 再送（void後リトライ）履歴 myVotePrev を含む候補から「受領済みの発信」を優先して
//     votes スロットへ。残りの自発信（void含む）は observed.votes[自uid] へ同梱（取下げ冤罪防止）。
//   - 密告: 同一対象の再送も全て同梱（対象別dedupなし）。採点側(⑤)が受領済みのみを数える。
//   - A-3 照合: 再送で同一対象の発信が複数あるため distinct 対象集合で比較。
//
// 参照する正典プリミティブは vendor から import（バイト厳密一致）。

import { keccak256, toHex, verifyMessage } from 'viem';
import { canonicalizeSignature, computeChatHashV2, computeMsgKeyV2, actionHashV2, buildRealTargets, selectBundleReceipts, receiptMaxRefsPerReceipt, buildReceiptMaps, collectKnownActions, buildMsgKeyGetter, canonicalComparatorV2 } from '../../vendor/src/utils/protocol.js';
// 🔴 J-40（2026-08-09）: 受領証明の正準順序は**採点と同じ関数**を使う（本体 SubmissionPhase.js と同一）。
import { receiptCanonCmp } from '../../vendor/workers/game_workers/lib/game-result-calculator.js';
import { applyChatCaps, normalizeChatCaps, GUEST_PINNED_RULES } from '../../vendor/workers/game_workers/lib/char-counter.js';
import { decryptAction } from '../../vendor/src/utils/ecies.js';
import {
  aggregateSelfReceipts, compactBytesToPayload, encodeEvidenceCompactV1,
  filterReceiptsToCarriedTargets,
  limitCarriedReceiptFacts,
} from '../../vendor/workers/game_workers/lib/evidence-compact-v1.js';
import { normalizeActionSnapshotForSubmission } from '../../vendor/workers/game_workers/lib/submission-limits.js';
import { preferReportGroundVotes, withReportGroundReceipts } from '../../vendor/src/utils/reportGround.js';
import { admitReadReceiptsByArrival, clientScoreableMessages, clientWindowedReceipts, clientChatSourcedReceipts } from '../../vendor/workers/game_workers/lib/protocol-v2.js';
import {
  priorityReady, preverifyCandidates, carriedMessages, attachPriority,
  checkPriority, EMPTY_PRIORITY_PLAN, PRESIGN_PLACEHOLDER_SIGNATURE,
  priorityLockPlan, verifyPriorityLock,
} from '../../vendor/src/utils/priorityEvidence.js';

export class SelfVerifyError extends Error {
  constructor(code) { super(`self-verify failed: ${code}`); this.name = 'SelfVerifyError'; this.code = code; }
}

// 受領証明から未署名のローカルメタデータを落とす最終白名簿。
// 引数の順序を保ったまま既知フィールドだけを新しいオブジェクトへ写す。
const whitelistReceiptsForSubmission = (kept) => kept.map((rc) => (Array.isArray(rc.msgRefs) && rc.senderUid != null
  ? { receiverUid: rc.receiverUid, senderUid: rc.senderUid, msgRefs: rc.msgRefs, timestamp: rc.timestamp, signature: rc.signature }
  : { receiverUid: rc.receiverUid, actionHash: rc.actionHash, timestamp: rc.timestamp, signature: rc.signature }));

// buildSubmissionBundle — 検閲下の本人提出バンドルを再構成する。
//
// 入力（すべて本人がウォレット/localStorage/リレーから復元できるもの）:
//   blockNum, groupId, myUid
//   encryptKey      : 自己暗号化鍵（提出時に公開・採点復号用）。signKey は不要＝渡さない
//   members         : ロスター（配布正準順・{uid, addr, bAddr, depIds}）
//   messages        : 正準マージ済みメッセージ集合（自発言＋リレー受信の他発言・§2.5）
//   myDepositIds    : depIds.ids 配列
//   myVote          : {encrypted, signature, timestamp} | null（最新の発信）
//   myVotePrev      : [{encrypted, signature, timestamp}]（v3.3: void後再送で退避した旧発信履歴）
//   myReports       : [{encrypted, signature, timestamp}]（再送含む全発信）
//   observedActions : { votes: {uid: action, uid__extras: [action]}, reports: {uid: [action]} }
//                     （リレー観測。自分の分も含んでよい＝本関数が myUid を除外する）
//   receipts        : { signature: receipt } | [receipt]（観測した全受領証明・既読バッチ含む）
//   intent          : { vote, reports:[] } | null（actionIntent_ 相当・A-3自己検証用）
//   chatCaps        : { maxChars, maxMessages, maxMsgChars }（§2.1b。未指定は既定値へ正規化）
//   chatWindow      : { startMs, endMs } | null（J-40b。Evidence が宣言したチャット窓 ± 時計ずれ許容
//                     ＝ `chatWindowMsFromTimeline(readGameTimelineMs(...))`。
//                     🔴 **null（チェーンが読めない）は fail-open**＝窓ゲート無し。
//                        fail-closed にすると RPC 障害だけで自己救済が不能になるため。
//                        残るリスクは `receiptCoverClaim` のコメント参照）
//   priorityChatWindow : {startMs,endMs} | null | undefined（最優先欄の4つの口だけ。省略時は chatWindow）
//   submittedAt     : ms（既定 Date.now()。テストでは固定注入）
//   signWallet      : async (message) => walletSignature（EIP-191 personal_sign）
//   hiddenMessageKeys : Set<msgKey> | null（上限の外の他人の発言。計画の池から外す。既定 null は従来と同じ）
//   shownMessageKeys : Set<msgKey> | null（一度画面に出した他人の発言の記憶。計画の池にだけ使う。既定 null）
//   separatorAtMs : ms | null（区切りの void を判定する時刻＝min(C, 画面の締切)。既定 null は読み手のある発言だけ）
//   separatorClosed : boolean（締切の後か。真なら読み手の無い区切りを記憶からだけ選ぶ。既定 false）
//
// 戻り値: { payload, encryptedDataHash, chatHash, snapshotData, dataString, signature, submittedAt, fieldWindow }
export async function buildSubmissionBundle({
  priorityLock = null,
  blockNum, groupId, myUid, encryptKey,
  members, messages, myDepositIds,
  myVote = null, myVotePrev = [], myReports = [],
  observedActions = { votes: {}, reports: {} },
  receipts = {}, intent = null, chatCaps = null, chatWindow = null, chatCloseAt = null,
  submittedAt = Date.now(), signWallet, signReceiptAggregate,
  requireConfirmedWindow = false,
  priorityChatWindow = undefined,
  rosterConfirmed = false,
  hiddenMessageKeys = null,
  shownMessageKeys = null,
  separatorAtMs = null,
  separatorClosed = false,
  reportGrounds = {},
}) {
  if (!encryptKey) throw new Error('encryptKey required');
  const fieldWindow = priorityChatWindow === undefined ? chatWindow : priorityChatWindow;

  // 提出物の上限適用（P-2026-0843・2026-08-08・本体 SubmissionPhase.js と同一規則）。
  // 採点と同じ上限（`clientScoreableMessages`）を同じ正準順序比較器で通し、chatHash も submittedMessages も
  // **この集合**から作る（片方だけ絞ると chathash_mismatch で提出が丸ごと無効になる）。
  // 最優先欄を置くときは carriedForSubmit が E と閉包を運び、normalForSubmit が通常欄に残る。
  // 元の配列順は保つ（正常系で提出バイト列を1バイトも変えないため）。
  const cappedMessages = (() => {
    const list = Array.isArray(messages) ? messages : [];
    const compareCanonical = canonicalComparatorV2(buildMsgKeyGetter(blockNum, groupId));
    const capped = clientScoreableMessages(list, receipts, {
      blockNum, groupId, myUid, chatWindow,
      caps: normalizeChatCaps(chatCaps), compare: compareCanonical,
    });
    const unique = new Map();
    for (const message of capped) {
      const key = computeMsgKeyV2(blockNum, groupId, message);
      if (!unique.has(key)) unique.set(key, message);
    }
    return [...unique.values()].sort(compareCanonical);
  })();

  // 受領済みactionHash → 受領者集合（本体 SubmissionPhase の receiptorsByActionHash と同一導出）
  // K-S6-005: 採点と同じ ±10分（isReceiptTimely）で篩う。判定は buildReceiptMaps に集約。
  const sourcedReceipts = clientChatSourcedReceipts(withReportGroundReceipts(receipts, reportGrounds), chatWindow, chatCloseAt);
  const receiptList = clientWindowedReceipts(sourcedReceipts, chatWindow, myUid);
  const { receiptorsByActionHash } = buildReceiptMaps(
    receiptList,
    {
      messages,
      actions: collectKnownActions({
        myUid, myVote, myVotePrev: Array.isArray(myVotePrev) ? myVotePrev : [], myReports, observedActions,
      }),
      myUid,
    },
    blockNum, groupId, chatWindow
  );

  // 1. 提出スナップショット構築（v3.2 §6.8）:
  //    votes/reports = 自分の発信のみ（本人の行動は本人が正・§5.5でACK非依存にローカル永続化済み）
  //    observed      = 観測した他人の発信＋全受領証明（検証⑥の不正証拠・削除耐性の材料）
  let snapshotData = { votes: {}, reports: {}, observed: { votes: {}, reports: {}, receipts: [] } };

  // 自分の投票（§5.5: ACK非依存の値）。
  // v3.3: 再送（void後リトライ）した場合は「受領済みの発信」を優先して votes スロットへ。
  // S3R4-U-U8: 受領済みが複数なら intent と同じ相手を先に選ぶ。
  // 旧発信に遅延受領があったケースでも受領済みの方が同梱され、取下げ(⑥b)に見えない。
  // 残りの自発信（void含む）も observed へ同梱＝受領証明を後から捏造されても
  // 「提出済みの発信」であり続ける（冤罪防止）。
  if (myVote?.encrypted && myVote?.signature && myVote?.timestamp) {
    const prevVotes = Array.isArray(myVotePrev) ? myVotePrev : [];
    const cands = [myVote, ...prevVotes].filter((v) => v?.encrypted && v?.signature && v?.timestamp);
    const isReceipted = (v) => {
      const h = actionHashV2('vote', blockNum, groupId, myUid, v.encrypted, v.timestamp);
      const set = receiptorsByActionHash?.[h];
      return !!set && [...set].some((u) => u !== myUid);
    };
    const chosen = (intent?.vote && cands.find((v) => {
      if (!isReceipted(v)) return false;
      try { return decryptAction(v.encrypted, encryptKey)?.targetUid === intent.vote; }
      catch (e) { return false; }
    })) || cands.find(isReceipted) || cands[0];
    snapshotData.votes[myUid] = { encrypted: chosen.encrypted, signature: chosen.signature, timestamp: chosen.timestamp };
    const rest = cands.filter((v) => v.signature !== chosen.signature)
      .map((v) => ({ encrypted: v.encrypted, signature: v.signature, timestamp: v.timestamp }));
    if (rest.length > 0) snapshotData.observed.votes[myUid] = rest;
  }
  // 自分の密告（intentフィルタ・タイムスタンプ昇順）
  const reportTargetByCiphertext = new Map();
  {
    const ownReports = (myReports || [])
      .filter((r) => r?.encrypted && r?.signature && r?.timestamp)
      .map((r) => ({ encrypted: r.encrypted, signature: r.signature, timestamp: r.timestamp }));
    if (ownReports.length > 0) {
      const byTarget = new Map();
      for (const rep of ownReports) {
        let target = null;
        try {
          target = decryptAction(rep.encrypted, encryptKey)?.targetUid || null;
        } catch (e) { /* 復号不能＝自分の密告ではない */ }
        if (!target) {
          console.warn('Dropping undecryptable report entry attributed to self');
          continue;
        }
        reportTargetByCiphertext.set(rep.encrypted, target);
        // v3.3: 同一対象の再送（void後リトライ）も全て同梱する（対象別dedupしない）。
        // 採点側(⑤)が受領済みのみを数え対象別にdedupする。void発信も同梱することで
        // 「後から受領証明を捏造して復活させても提出済みの発信」となり取下げ冤罪を防ぐ。
        byTarget.set(`${target}|${rep.signature}`, { ...rep, _target: target });
      }
      // 🔴 intent による**除去はしない**（2026-08-05 修正・本体 SubmissionPhase と同一）。
      // intent は送信成功時にローカルへ書く記録なので実発信と食い違い得る。捨てた密告が
      // 他メンバーの提出物＋受領証明で正典に残ると、採点⑥(b)が「受領済みなのに本人提出に
      // 無い＝取下げ」と見なし report_fraud で失格になる（block1 で冤罪失格が発生）。
      // ここの発信は全て自分の signKey 署名付き＝他人には捏造できないので除去の利点は無い。
      let merged = [...byTarget.values()];
      merged.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
      merged = merged.map(({ _target, ...rest }) => rest);
      if (merged.length > 0) {
        snapshotData.reports[myUid] = merged;
      }
    }
  }

  // 観測した他人の発信（配列形式・矛盾候補 __extras も同梱＝検証⑥の証拠）
  const memberUidList = members.map((m) => m.uid);
  for (const [u, v] of Object.entries(observedActions.votes || {})) {
    if (u.endsWith('__extras')) {
      const base = u.slice(0, -'__extras'.length);
      if (!memberUidList.includes(base) || base === myUid) continue;
      const cur = snapshotData.observed.votes[base] || [];
      snapshotData.observed.votes[base] = [...cur, ...(Array.isArray(v) ? v : [])];
      continue;
    }
    if (!memberUidList.includes(u) || u === myUid || !v?.encrypted) continue;
    const cur = snapshotData.observed.votes[u] || [];
    snapshotData.observed.votes[u] = [{ encrypted: v.encrypted, signature: v.signature, timestamp: v.timestamp }, ...cur];
  }
  for (const [u, arr] of Object.entries(observedActions.reports || {})) {
    if (!memberUidList.includes(u) || u === myUid || !Array.isArray(arr)) continue;
    snapshotData.observed.reports[u] = arr
      .filter((r) => r?.encrypted && r?.signature)
      .map((r) => ({ encrypted: r.encrypted, signature: r.signature, timestamp: r.timestamp }));
  }
  // S3R5-U-R13-SELF: 自分の密告の根拠の投票を送り手ごと10件の内に先に置く（本体と同じ）。
  snapshotData.observed.votes = preferReportGroundVotes(snapshotData.observed.votes, reportGrounds, {
    blockNum: Number(blockNum), groupId: Number(groupId), selfUid: myUid, memberUids: memberUidList,
  });
  // 観測した全受領証明（既読バッチ＋action受領・署名昇順で決定論的に整列）
  // K-S6-002 (f): 自分のバンドルに実在する対象をカバーしないものは載せない
  // Q-S2-001 (e): カバー先がすべて他の受領証明と重複しているものは載せない
  // 🔴 J-40（2026-08-09）: 並びは採点正典と同じ `receiptCanonCmp`（生の signature 昇順をやめた）＋
  //    枠取りに鮮度ゲート（`isReceiptTimely`）。不鮮度な受領証明で本物を枠から追い出す攻撃の遮断。
  // 🔴 J-40b（2026-08-09）: J-40 は**宣言窓（`inChatWindow`）を取りこぼしていた**。
  //    述語は `protocol-v2.js` の `receiptCoverClaim` に集約し、選別は
  //    `selectBundleReceipts`（第1階層＝窓内が枠を取る／第2階層＝窓外は残りカバーだけ運ぶ）。
  //    ここに述語を並べ直さないこと。
  //（本体 SubmissionPhase.js と同一規則。理由はそちらのコメント参照）
  //
  // 公式の復元画面は requireConfirmedWindow=true。読めない間は提出を保留する。
  // 引数省略のライブラリ呼出しは従来の形式を保つ。
  // carriedForSubmit は E と閉包を運び、normalForSubmit は E を除いた通常欄。
  const baseSnapshot = structuredClone(snapshotData);
  let priorityPlan = EMPTY_PRIORITY_PLAN;
  let carriedForSubmit = cappedMessages;
  let normalForSubmit = cappedMessages;
  let signingError = null;
  const signAggregate = async (message) => {
    try { return await signReceiptAggregate(message); }
    catch (error) { signingError = error; throw error; }
  };
  const toSubmittedMessages = (list) => (list || []).map((m) => ({
    type: 'chat',
    blockNum: Number(blockNum),
    groupId: Number(groupId),
    uid: m.uid,
    text: m.text,
    timestamp: m.timestamp,
    signature: m.signature
  }));
  const assembleReceiptsForSubmit = async () => {
    snapshotData = structuredClone(baseSnapshot);
  {
    const normalizedActions = normalizeActionSnapshotForSubmission(snapshotData, {
      blockNum: Number(blockNum), groupId: Number(groupId),
      memberUids: members.map((m) => m.uid), submitterUid: myUid,
      // 自分の密告を上で復号した結果だけを使う。欠落・復号失敗は null として
      // 従来の正準順フォールバックへ任せ、提出自体は止めない。
      reportTargetOf: (action) => reportTargetByCiphertext.get(action?.encrypted) || null,
    });
    snapshotData.votes = normalizedActions.votes;
    snapshotData.reports = normalizedActions.reports;
    snapshotData.observed = normalizedActions.observed;
    const targets = buildRealTargets(snapshotData, carriedForSubmit, blockNum, groupId);
    // S3R1-C-4-01: 他人の既読は全参照が有効な束だけが枠を取る。自己発行分は参照ごと。
    const admitted = admitReadReceiptsByArrival(receiptList, targets, {
      messages: carriedForSubmit, blockNum, groupId, myUid,
      compare: receiptCanonCmp,
      memberUids: members.map((m) => m.uid),
      chatWindow,
      maxRefsPerReceipt: receiptMaxRefsPerReceipt(normalizeChatCaps(chatCaps).maxMessages),
      selfUid: myUid,
    });
    const kept = selectBundleReceipts(admitted, targets, {
      compare: receiptCanonCmp,
      memberUids: members.map((m) => m.uid),
      chatWindow,
      maxRefsPerReceipt: receiptMaxRefsPerReceipt(normalizeChatCaps(chatCaps).maxMessages),
      selfUid: myUid,
    });
    // 枠取りは従来の正準順のまま。その後だけローカル到着順へ戻し、
    // 正直な束のバイト列を保つため、集約へ渡す順は到着順のままにする。
    const byArrival = [...kept].sort((a, b) => (a._seq ?? 0) - (b._seq ?? 0));
    // 🔴 P-2026-0840（2026-08-08・ラウンド19 判断不要-8）: 正典（`SubmissionPhase.js`）が
    //    `observed.votes` / `observed.reports` と同じ白名簿に揃えたので、ここも揃える。
    //    受領証明の署名対象は (blockNum, groupId, receiverUid, senderUid, msgRefs, timestamp)
    //    / (…, actionHash, …) だけで、それ以外は定義上「情報を持たない」。
    const normalized = whitelistReceiptsForSubmission(byArrival);
    // Official recovery UI always supplies the derived sign-key callback and
    // therefore emits the compact self aggregate.  Keep the library callable
    // by legacy/offline consumers that only possess already-signed receipts:
    // their atomic legacy receipts remain valid, merely less space-efficient.
    const aggregated = typeof signReceiptAggregate === 'function'
      ? await aggregateSelfReceipts(
        normalized, myUid, blockNum, groupId,
        (message) => signAggregate(message),
        targets,
        chatWindow,
      )
      : { receipts: normalized, aggregate: null };
    snapshotData.observed.receipts = aggregated.receipts;
    if (aggregated.aggregate) snapshotData.observed.selfReceiptAggregate = aggregated.aggregate;
    if (priorityPlan.E.length > 0) {
      snapshotData = await attachPriority(snapshotData, priorityPlan, {
        myUid, blockNum, groupId, chatWindow: fieldWindow,
        signSelf: (message) => signAggregate(message),
      });
    }
    const carried = filterReceiptsToCarriedTargets(
      snapshotData, normalForSubmit, blockNum, groupId,
    );
    const limited = limitCarriedReceiptFacts(carried, { submitterUid: myUid, compare: receiptCanonCmp });
    snapshotData.observed = limited.observed;
  }
    return keccak256(toHex(JSON.stringify(snapshotData)));
  };
  let encryptedDataHash = null;
  let chatHashForSubmit = null;
  let submittedMessages = null;
  if (priorityReady({ rosterConfirmed, members, myUid, chatWindow: fieldWindow,
    canSignSelf: typeof signReceiptAggregate === 'function' })) {
    try {
      const pre = await preverifyCandidates({
        messages: Array.isArray(messages) ? messages : [], receipts: sourcedReceipts,
        myUid, members, blockNum, groupId, chatWindow: fieldWindow,
        hiddenMessageKeys,
        shownMessageKeys: shownMessageKeys instanceof Set ? new Set(shownMessageKeys) : null, separatorAtMs, separatorClosed,
      }, { members, verify: verifyMessage });
      if (pre.plan.E.length > 0) {
        ({ carried: carriedForSubmit, normal: normalForSubmit } = carriedMessages(
          cappedMessages, pre.plan, { blockNum, groupId },
        ));
        priorityPlan = pre.plan;
        encryptedDataHash = await assembleReceiptsForSubmit();
        chatHashForSubmit = computeChatHashV2(normalForSubmit, blockNum, groupId);
        submittedMessages = toSubmittedMessages(normalForSubmit);
        const check = await checkPriority({
          uid: myUid, encryptKey, chatHash: chatHashForSubmit,
          signature: PRESIGN_PLACEHOLDER_SIGNATURE, submittedAt,
          encryptedDataHash, depositIds: myDepositIds,
          encryptedActions: snapshotData, messages: submittedMessages,
        }, { blockNum, groupId, members, chatWindow: fieldWindow, verify: verifyMessage,
          expectedTurns: priorityPlan.turns });
        if (!check.ok) throw new Error(`priority check failed: ${check.reason}`);
      }
    } catch (priorityError) {
      if (signingError) throw signingError;
      console.warn('[submit] priority field dropped; submitting without it:', priorityError?.message || priorityError);
      priorityPlan = EMPTY_PRIORITY_PLAN;
      carriedForSubmit = normalForSubmit = cappedMessages;
      encryptedDataHash = null;
      chatHashForSubmit = null;
      submittedMessages = null;
    }
    if (priorityLock && (priorityPlan.E.length > 0 ? priorityPlan.turns : 0) < GUEST_PINNED_RULES.minMessages) {
      const rebuilt = { priorityPlan, carriedForSubmit, normalForSubmit,
        encryptedDataHash, chatHashForSubmit, submittedMessages, snapshotData };
      try {
        const lockPlan = priorityLockPlan(priorityLock, { blockNum, groupId, myUid, members,
          rosterHash: priorityLock.rosterHash, chatWindow: fieldWindow });
        if (!lockPlan) throw new Error('priority lock plan unavailable');
        const lockVerified = await verifyPriorityLock(priorityLock, { blockNum, groupId, myUid, members,
          rosterHash: priorityLock.rosterHash, chatWindow: fieldWindow }, { verify: verifyMessage });
        if (!lockVerified) throw new Error('priority lock signature failed');
        priorityPlan = lockPlan;
        ({ carried: carriedForSubmit, normal: normalForSubmit } = carriedMessages(
          cappedMessages, lockPlan, { blockNum, groupId },
        ));
        encryptedDataHash = await assembleReceiptsForSubmit();
        const lockedChatHash = computeChatHashV2(normalForSubmit, blockNum, groupId);
        chatHashForSubmit = lockedChatHash;
        submittedMessages = toSubmittedMessages(normalForSubmit);
        const lockCheck = await checkPriority({
          uid: myUid, encryptKey, chatHash: lockedChatHash,
          signature: PRESIGN_PLACEHOLDER_SIGNATURE, submittedAt,
          encryptedDataHash, depositIds: myDepositIds,
          encryptedActions: snapshotData, messages: submittedMessages,
        }, { blockNum, groupId, members, chatWindow: fieldWindow, verify: verifyMessage,
          expectedTurns: GUEST_PINNED_RULES.minMessages });
        if (!lockCheck.ok) throw new Error(`priority lock check failed: ${lockCheck.reason}`);
      } catch (lockError) {
        if (signingError !== null) throw signingError;
        ({ priorityPlan, carriedForSubmit, normalForSubmit, encryptedDataHash,
          chatHashForSubmit, submittedMessages, snapshotData } = rebuilt);
        console.warn('[submit] priority lock not used; keeping the rebuilt field:', lockError?.message || lockError);
      }
    }
  }
  if (encryptedDataHash === null) {
    encryptedDataHash = await assembleReceiptsForSubmit();
    submittedMessages = toSubmittedMessages(cappedMessages);
  }

  // 2. A-3: 署名前の自己検証 — スナップショット内の「自分の」投票・密告を復号し、
  //    自分が投じた内容（intent）と照合。正規化後の自分の票のどれにも無ければ署名を拒否する。
  const snapVote = snapshotData.votes?.[myUid];
  let snapVoteTarget = null;
  if (snapVote?.encrypted) {
    try {
      snapVoteTarget = decryptAction(snapVote.encrypted, encryptKey)?.targetUid || null;
    } catch (e) {
      throw new SelfVerifyError('vote_undecryptable');
    }
  }
  const observedSnapVotes = Array.isArray(snapshotData.observed?.votes?.[myUid])
    ? snapshotData.observed.votes[myUid] : [];
  const hasIntentVote = snapVoteTarget === intent?.vote || (intent?.vote && observedSnapVotes.some((vote) => {
    try { return decryptAction(vote.encrypted, encryptKey)?.targetUid === intent.vote; }
    catch (e) { return false; }
  }));
  if (intent?.vote && !hasIntentVote) throw new SelfVerifyError('vote_mismatch');

  const publicSnapReports = Array.isArray(snapshotData.reports?.[myUid]) ? snapshotData.reports[myUid] : [];
  const observedSnapReports = Array.isArray(snapshotData.observed?.reports?.[myUid])
    ? snapshotData.observed.reports[myUid] : [];
  // 採点と同じ候補プール（公開スロット ∪ observed の自分の分）を照合する。
  const snapReports = [...publicSnapReports, ...observedSnapReports];
  const snapReportTargets = [];
  for (const rep of snapReports) {
    try {
      const d = decryptAction(rep.encrypted, encryptKey);
      if (d?.targetUid) snapReportTargets.push(d.targetUid);
    } catch (e) {
      throw new SelfVerifyError('report_undecryptable');
    }
  }
  // 「**提出物に足りない**」向きだけを拒否する（2026-08-05 修正・本体と同一規則）。
  //   足りない → そのまま出すと採点⑥(b)で report_fraud 失格。出す前に止める。
  //   多い     → intent の取りこぼし。発信は自分の signKey 署名付きなのでそのまま出してよい
  //              （ここで拒否すると提出自体ができず no_submit 失格になり害が大きい）。
  if (Array.isArray(intent?.reports) && intent.reports.length > 0) {
    const actualSet = new Set(snapReportTargets);
    const missing = [...new Set(intent.reports)].filter((tgt) => !actualSet.has(tgt));
    if (missing.length > 0) {
      throw new SelfVerifyError('report_missing');
    }
  }

  // --- chatHash（正準マージ集合から自己計算・規則版13＝正準順の各発言の (msgKey, 署名) の組 §2.3） ---
  // 🔴 上限適用「後」の集合から計算する（下の submittedMessages と同一集合）。
  const chatHash = chatHashForSubmit ?? computeChatHashV2(cappedMessages, blockNum, groupId);

  // 3. 正規署名メッセージ（v3.2・フィールド順固定・blockNum/uid明示束縛）
  //    calculator（game-result-calculator.js 検証①）とバイト同一シリアライズ厳守。
  //    ⚠ signKey・ウォレット署名（keySig）は絶対に含めない（signKeyのmaster素材のため）。
  const dataString = JSON.stringify({
    blockNum: Number(blockNum),
    uid: myUid,
    encryptKey,
    chatHash,
    submittedAt,
    encryptedDataHash,
    depositIds: myDepositIds
  });
  const signature = canonicalizeSignature(await signWallet(dataString)); // ウォレット personal_sign（signKeyではない）

  // 4. 提出メッセージ（§2.6正準形＋signature・signKey署名済み）
  // normalForSubmit は chatHash と同じ順で、提出時には7キーへ写す。

  // --- payload（9キー固定・Evidence へ同一バイト列） ---
  const logicalBundle = {
    uid: myUid,
    encryptKey,
    chatHash,
    signature,
    submittedAt,
    encryptedDataHash,
    depositIds: myDepositIds,
    encryptedActions: snapshotData,
    messages: submittedMessages
  };
  const encodeCtx = { blockNum, groupId, memberUids: members.map((member) => member.uid) };
  // 🔴 2026-08-20（第6ラウンド 判断2(2)）: codec が「運んでいない対象を指す受領証明」を
  //    落としたら、それは **ハッシュ確定後の改変**なので、そのまま送ると復号後の snapshot が
  //    `encryptedDataHash` と合わず採点入口で `snapshot_mismatch` になる。
  //    落ちたら **sanitize 済み bundle から hash と署名を作り直して再符号化する**。
  //    ⚠️ 一次防衛線は上の `filterReceiptsToCarriedTargets`（ハッシュ前）なので正常系では発火しない。
  //       ここは検閲下の自己救済経路なので、一次防衛線が回帰しても提出を落とさない。
  const sanitized = {};
  let compact = encodeEvidenceCompactV1(logicalBundle, encodeCtx, { sanitized });
  let finalBundle = logicalBundle;
  let finalHash = encryptedDataHash;
  let finalDataString = dataString;
  let finalSignature = signature;
  if (sanitized.bundle) {
    const fixedSnapshot = sanitized.bundle.encryptedActions;
    finalHash = keccak256(toHex(JSON.stringify(fixedSnapshot)));
    finalDataString = JSON.stringify({
      blockNum: Number(blockNum),
      uid: myUid,
      encryptKey,
      chatHash,
      submittedAt,
      encryptedDataHash: finalHash,
      depositIds: myDepositIds
    });
    finalSignature = canonicalizeSignature(await signWallet(finalDataString));
    finalBundle = { ...sanitized.bundle, signature: finalSignature, encryptedDataHash: finalHash };
    const again = {};
    compact = encodeEvidenceCompactV1(finalBundle, encodeCtx, { sanitized: again });
    if (again.bundle) throw new Error('compact encode still dropped receipts after sanitizing');
  }
  const payload = compactBytesToPayload(compact);

  return {
    payload,
    bundle: finalBundle,
    encryptedDataHash: finalHash,
    chatHash,
    snapshotData: finalBundle.encryptedActions,
    dataString: finalDataString,
    signature: finalSignature,
    submittedAt,
    fieldWindow,
  };
}

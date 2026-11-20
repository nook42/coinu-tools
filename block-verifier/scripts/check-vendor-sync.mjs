#!/usr/bin/env node
// check-vendor-sync.mjs — vendor/ と正典（モノレポ）の同期検査
//
// 検査内容（VENDOR_SYNC.md の台帳と対応）:
//   COPY    … vendor ファイルと正典ファイルのバイト一致
//   EXTRACT … select-winners.js のマーカー間本体と lottery-DO.js の selectWinners 本体の一致
//   MIRROR  … 正典の該当行範囲の sha256 が台帳記録値と一致（変わったらミラー再レビューが必要）
// いずれかが不一致なら exit 1。
// 🔴 F-7(b)（2026-08-08）: モノレポ外（独立リポジトリ化後）で実行された場合は
//    照合対象が存在しないので **exit 1**（旧実装は「skip」として exit 0 ＝ fail-open だった）。

import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULTS } from '../src/config.js';

const here = dirname(fileURLToPath(import.meta.url));
const toolRoot = resolve(here, '..');          // block-verifier/
const repoRoot = resolve(toolRoot, '..');      // モノレポルート

const pinConst = (file, name) => ({ file, name });
const pinObject = (file, name, key) => ({ file, name, key });

// 公開数値pinと正典定数の対応。対応不能なpinは PIN_OMISSIONS に理由を宣言する。
// 数値pinの実集合とこの2台帳を双方向照合するため、幽霊・未登録のどちらも赤になる。
const PIN_BINDINGS = Object.freeze({
  minChars: [pinObject('workers/game_workers/lib/char-counter.js', 'GUEST_PINNED_RULES', 'minChars')],
  minMessages: [pinObject('workers/game_workers/lib/char-counter.js', 'GUEST_PINNED_RULES', 'minMessages')],
  'chatCaps.maxChars': [pinObject('workers/game_workers/lib/char-counter.js', 'GUEST_PINNED_RULES', 'maxChars')],
  'chatCaps.maxMessages': [pinObject('workers/game_workers/lib/char-counter.js', 'GUEST_PINNED_RULES', 'maxMessages')],
  'chatCaps.maxMsgChars': [pinObject('workers/game_workers/lib/char-counter.js', 'GUEST_PINNED_RULES', 'maxMsgChars')],
  maxReports: [
    pinConst('workers/game_workers/lib/submission-limits.js', 'MAX_ACCEPTED_REPORTS_PER_PLAYER'),
  ],
  receiptFreshWindowMs: [pinConst('workers/game_workers/lib/protocol-v2.js', 'RECEIPT_FRESH_WINDOW_MS')],
  confirmationBlocks: [pinConst('workers/lottery_workers/lottery-DO.js', 'CONFIRMATION_BLOCKS_DEFAULT')],
  ethereumHeaderRuleVersion: [pinConst('workers/game_workers/lib/roster-canonical.js', 'ETH_HEADER_RULE_VERSION')],
  clockSkewAllowMs: [pinConst('workers/game_workers/lib/protocol-v2.js', 'CHAT_WINDOW_CLOCK_SKEW_MS')],
  gameMaxPlayers: [
    pinConst('workers/game_workers/game-master-DO.js', 'GAME_MAX_PLAYERS'),
    pinConst('workers/lottery_workers/lottery-DO.js', 'GAME_MAX_PLAYERS'),
  ],
  visibleCharsRule: [pinConst('workers/game_workers/lib/char-counter.js', 'VISIBLE_CHARS_RULE_VERSION')],
  reportMinReadReceipts: [pinConst('workers/game_workers/lib/protocol-v2.js', 'REPORT_MIN_READ_RECEIPTS')],
  reportEligibilityRule: [pinConst('workers/game_workers/lib/protocol-v2.js', 'REPORT_ELIGIBILITY_RULE_VERSION')],
  msgRefBytes: [pinConst('workers/game_workers/lib/protocol-v2.js', 'MSG_REF_BYTES')],
  receiptMaxActionsPerPairBase: [pinConst('workers/game_workers/lib/protocol-v2.js', 'RECEIPT_MAX_ACTIONS_PER_PAIR_BASE')],
  receiptMaxActionsPerPair: [pinConst('workers/game_workers/lib/protocol-v2.js', 'RECEIPT_MAX_ACTIONS_PER_PAIR_BASE')],
  receiptMaxRefsPerReceipt: [pinConst('workers/game_workers/lib/submission-limits.js', 'MAX_MESSAGES_PER_PLAYER')],
  maxObservedActionsPerActor: [pinConst('workers/game_workers/lib/protocol-v2.js', 'MAX_OBSERVED_ACTIONS_PER_ACTOR')],
  receiptAcceptanceRule: [pinConst('workers/game_workers/lib/protocol-v2.js', 'RECEIPT_ACCEPTANCE_RULE_VERSION')],
  submissionLimitsVersion: [pinConst('workers/game_workers/lib/submission-limits.js', 'SUBMISSION_LIMITS_VERSION')],
  maxDepositIds: [pinConst('workers/game_workers/lib/submission-limits.js', 'MAX_DEPOSIT_IDS')],
  maxMessagesPerPlayer: [pinConst('workers/game_workers/lib/submission-limits.js', 'MAX_MESSAGES_PER_PLAYER')],
  maxMessagesTotal: [pinConst('workers/game_workers/lib/submission-limits.js', 'MAX_MESSAGES_TOTAL')],
  maxMessageChars: [pinConst('workers/game_workers/lib/submission-limits.js', 'MAX_MESSAGE_CHARS')],
  maxMessageCharsPerPlayer: [pinConst('workers/game_workers/lib/submission-limits.js', 'MAX_MESSAGE_CHARS_PER_PLAYER')],
  maxAcceptedVotesPerPlayer: [pinConst('workers/game_workers/lib/submission-limits.js', 'MAX_ACCEPTED_VOTES_PER_PLAYER')],
  maxAcceptedReportsPerPlayer: [pinConst('workers/game_workers/lib/submission-limits.js', 'MAX_ACCEPTED_REPORTS_PER_PLAYER')],
  maxReceiptFacts: [pinConst('workers/game_workers/lib/submission-limits.js', 'MAX_RECEIPT_FACTS')],
  maxSelfAggregateTargets: [pinConst('workers/game_workers/lib/submission-limits.js', 'MAX_SELF_AGGREGATE_TARGETS')],
  maxPriorityOwnMessages: [pinConst('workers/game_workers/lib/char-counter.js', 'PRIORITY_OWN_MESSAGES_MAX')],
  maxPriorityOtherMessages: [pinConst('workers/game_workers/lib/char-counter.js', 'PRIORITY_OTHER_MESSAGES_MAX')],
  maxPriorityReceipts: [pinConst('workers/game_workers/lib/char-counter.js', 'PRIORITY_RECEIPTS_MAX')],
  serverMaxSubmissionWireBytes: [pinConst('workers/game_workers/lib/submission-limits.js', 'SERVER_MAX_WIRE_BYTES')],
  serverMaxSubmissionDecodedBytes: [pinConst('workers/game_workers/lib/submission-limits.js', 'SERVER_MAX_DECODED_BYTES')],
  evidenceMaxDataBytesExclusive: [pinConst('workers/game_workers/lib/evidence-trim.js', 'EVIDENCE_MAX_DATA_BYTES')],
  claimDataChunkBytes: [pinConst('workers/game_workers/game-master-DO.js', 'CLAIM_DATA_CHUNK_BYTES')],
});
const PIN_OMISSIONS = Object.freeze({});

// COPY 台帳: [vendor相対, 正典相対]
const COPIES = [
  ['vendor/workers/auth_workers/lib/cors.js', 'workers/auth_workers/lib/cors.js'],
  // M10a: 開始関門の変更も正典 GM との byte 一致で検査する。
  ['vendor/workers/game_workers/game-master-DO.js', 'workers/game_workers/game-master-DO.js'],
  ['vendor/workers/game_workers/lib/roster-anchor-rule.js', 'workers/game_workers/lib/roster-anchor-rule.js'],
  ['vendor/workers/game_workers/lib/roster-canonical.js', 'workers/game_workers/lib/roster-canonical.js'],
  // S6 持ち越し課題の解消（2026-07-29）: vendor の chat-game-DO.js は import されないため
  // 台帳に無く、手コピーで静かに古びる状態だった。COPY 台帳に載せて drift を機械検出する。
  ['vendor/workers/game_workers/chat-game-DO.js', 'workers/game_workers/chat-game-DO.js'],
  // P2b-2c: 共有の既読入口。公式の提出 MIRROR 窓は本体不変を検査する。
  ['vendor/workers/game_workers/lib/protocol-v2.js', 'workers/game_workers/lib/protocol-v2.js'],
  ['vendor/workers/game_workers/lib/submission-limits.js', 'workers/game_workers/lib/submission-limits.js'],
  ['vendor/workers/game_workers/lib/priority-fields.js', 'workers/game_workers/lib/priority-fields.js'],
  ['vendor/workers/game_workers/lib/evidence-compact-v1.js', 'workers/game_workers/lib/evidence-compact-v1.js'],
  ['vendor/workers/game_workers/lib/zkp-protocol.js', 'workers/game_workers/lib/zkp-protocol.js'],
  ['vendor/workers/game_workers/lib/roster-member-root.js', 'workers/game_workers/lib/roster-member-root.js'],
  ['vendor/workers/game_workers/lib/evidence-sender-vectors.json', 'workers/game_workers/lib/evidence-sender-vectors.json'],
  // 周11 P1: game-master-DO.js が Stage 3 の group witness 生成のため import するようになった。
  ['vendor/workers/game_workers/lib/group-witness.js', 'workers/game_workers/lib/group-witness.js'],
  // 同上: group-witness.js が depositId の正準化を entry_workers から取り込む。
  ['vendor/workers/entry_workers/lib/deposit-id.js', 'workers/entry_workers/lib/deposit-id.js'],
  ['vendor/workers/entry_workers/lib/nostr-key.js', 'workers/entry_workers/lib/nostr-key.js'],
  ['vendor/workers/game_workers/lib/game-result-calculator.js', 'workers/game_workers/lib/game-result-calculator.js'],
  ['vendor/workers/game_workers/lib/evidence-reconciler.js', 'workers/game_workers/lib/evidence-reconciler.js'],
  ['vendor/workers/game_workers/lib/finality.js', 'workers/game_workers/lib/finality.js'],
  ['vendor/workers/game_workers/lib/evidence-segment-plan.js', 'workers/game_workers/lib/evidence-segment-plan.js'],
  ['vendor/workers/game_workers/lib/getlogs-adaptive.js', 'workers/game_workers/lib/getlogs-adaptive.js'],
  ['vendor/workers/game_workers/lib/timeline-check.js', 'workers/game_workers/lib/timeline-check.js'],
  ['vendor/workers/game_workers/lib/block-lifecycle.js', 'workers/game_workers/lib/block-lifecycle.js'],
  ['vendor/workers/game_workers/lib/char-counter.js', 'workers/game_workers/lib/char-counter.js'],
  // S3-001: GameMasterDO 側の選出データ完全性検査と、その依存の決定的抽選。
  // select-winners.js は正典 lib と vendor/lottery_workers 側の両方に COPY 台帳を張ることで
  //   lottery-DO.js 本体 =(EXTRACT)= vendor/lottery_workers =(COPY)= 正典 lib =(COPY)= vendor/game_workers
  // の連鎖が成立し、どこか1つが変わればここで赤くなる。
  ['vendor/workers/game_workers/lib/selection-integrity.js', 'workers/game_workers/lib/selection-integrity.js'],
  ['vendor/workers/game_workers/lib/select-winners.js', 'workers/game_workers/lib/select-winners.js'],
  // P-2026-0816: GameMasterDO 側のグループ分け完全性検査（formGroups の独立再実行照合＋
  // 前ブロック成果物のオンチェーンアンカー検証）。src/stages/grouping.js の対応物は
  // 独立再実装なので MIRROR ではなく、game-master-DO.js の import 依存として COPY する。
  ['vendor/workers/game_workers/lib/grouping-integrity.js', 'workers/game_workers/lib/grouping-integrity.js'],
  ['vendor/workers/game_workers/lib/canonical-json.js', 'workers/game_workers/lib/canonical-json.js'],
  // S3-003: DO→Worker を Service Binding へ移した共通ヘルパー（game-master-DO / chat-game-DO が import）
  ['vendor/workers/game_workers/lib/service-binding.js', 'workers/game_workers/lib/service-binding.js'],
  // 管理者txは単一DOへ委譲し、caller側は型付きintentだけを送る。
  ['vendor/workers/game_workers/lib/admin-tx-client.js', 'workers/game_workers/lib/admin-tx-client.js'],
  // S3-008: RPC 一覧の組み立てと障害通知（game-master-DO が import）
  ['vendor/workers/game_workers/lib/rpc-urls.js', 'workers/game_workers/lib/rpc-urls.js'],
  ['vendor/workers/game_workers/lib/rpc-independence.js', 'workers/game_workers/lib/rpc-independence.js'],
  ['vendor/workers/game_workers/lib/alert.js', 'workers/game_workers/lib/alert.js'],
  ['vendor/workers/game_workers/lib/observation-write-failures.js', 'workers/game_workers/lib/observation-write-failures.js'],
  // E2E/load識別ヘッダーを、通常経路へ影響させず隔離環境だけで照合する共通ガード。
  ['vendor/workers/game_workers/lib/load-test-context.js', 'workers/game_workers/lib/load-test-context.js'],
  // K-S5-002: 請求データのオンチェーン公開フォーマット（正典と1バイトも違ってはならない）
  ['vendor/workers/game_workers/lib/claim-data-codec.js', 'workers/game_workers/lib/claim-data-codec.js'],
  ['vendor/workers/game_workers/lib/group-witness.js', 'workers/game_workers/lib/group-witness.js'],
  ['vendor/workers/entry_workers/lib/deposit-id.js', 'workers/entry_workers/lib/deposit-id.js'],
  ['vendor/workers/lottery_workers/select-winners.js', 'workers/game_workers/lib/select-winners.js'],
];

// EXTRACT 台帳
const EXTRACT = {
  vendor: 'vendor/workers/lottery_workers/select-winners.js',
  source: 'workers/lottery_workers/lottery-DO.js',
  signature: '  async selectWinners(seed, totalApplicants, winnerCount) {',
  closing: '  }',
  beginMarker: '// ===== BEGIN VERBATIM BODY',
  endMarker: '// ===== END VERBATIM BODY',
};

// MIRROR 台帳: 正典行範囲（1-indexed 両端含む）の sha256（VENDOR_SYNC.md と一致させること）。
// Q52でも行窓を維持する。対象には大きな関数内の意味上の部分区間があり、関数名からの抽出へ
// 広げると検証ツールが写していないD1/R2処理までpinし、逆に内側の部分区間を表せないため。
// 行移動時は既存sha256の全走査で一致が1箇所だけであることを確認して位置だけ更新する。
const MIRRORS = [
  {
    name: 'src/stages/results.js autoRosterTextFromSelection',
    declarationText: 'MIRROR: GM publishAutoRosterFile の selection → group0 写像。',
    source: 'workers/game_workers/game-master-DO.js',
    // 2026-11-06 便 WR-E2E-S15-PROVERFIX（/zkp-successor の口と後継の追跡・attach）: GM 前方で +120 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP・GMGROUP-FIX1（組分けの shard の書き込みの一時的な失敗の再開・警報・待ち・印）: GM 前方で +75 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP-FIX2（開始関門の待ちの終わりの道・警報の印の原因と配送の結果）: GM 前方で +53 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 便 WR-PRE-PRESENCE（presence の時間回復・合図の配信・ADMINGAS の同期）: 前方で +25 行。旧 sha256 の同じ行数の窓を全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 WR-PRE-ADMINGAS-FIX1: 同長窓を全走査し唯一一致を再確認。本文・sha256・行位置は不変。
    startLine: 16962, endLine: 16966,
    sha256: 'c77ef5c98b2e2f974483c5e4b533628bf748e7566bf94da7ea963fdbe20b7986',
    mirrorFile: 'src/stages/results.js',
    mirrorSignature: 'export function autoRosterTextFromSelection(blockNum, players) {',
    mirrorSha256: '4aee3a139fd6ce49bcf46ff993113315e7498e3af621de873bebc5be265a4862',
  },
  {
    // 周13 C8-01(う)（2026-09-05 新設）: 公開キャッシュが失われたときに、アンカー済み sha256 の
    // 照合相手として名簿の正準バイト列を再構成する。writer を変えたらミラーも変えること。
    name: 'src/stages/results.js rosterMembersOf',
    source: 'workers/game_workers/chat-game-DO.js',
    // 2026-09-16 周25 Q25: chat-game の末尾公開 alarm / completed 再送追加で前方+15行。
    // 旧20行窓の sha256 は新位置で唯一一致し、窓本体は byte 不変。
    // 2026-09-18 周26 R4: timeline no-game 専用入口の前方追加で+6行。旧sha256は唯一一致。
    // 2026-09-27 周33 便 S3C11（D-12・R33-F-1-01）: uid ごとの WS 本数の上限の定数・helper を前方へ足して +95 行。
    // 同じ20行窓を全走査し、旧sha256の唯一一致（754-773）を確認（中身は不変）。
    // S3C15: sendkey import の削除で前方が1行減。窓本体は byte 同一。
    // S3C11b: WS 接続の合計上限・受信ガード・同時 upgrade の判定を前方へ追加。21行窓は唯一一致。
    // 2026-09-27 周33 便 S3C13（文書の一括）: 定数のコメントで前方 +1 行。旧sha256の21行窓は全走査で772-792に唯一一致（中身は不変）。
    // 2026-11-15 便 WR-PRE-PRESENCE（presence の時間回復・合図の配信・ADMINGAS の同期）: 前方で +26 行。旧 sha256 の同じ行数の窓を全走査し唯一一致の位置へ付け直した（中身は不変）。
    startLine: 800,
    endLine: 818,
    sha256: '1e548c657d58f66ed592d2af8199e1aa5aa5092456c69dec9a6502f9684f33c2',
    mirrorFile: 'src/stages/results.js',
    mirrorSignature: 'export function rosterMembersOf(group) {',
    mirrorSha256: '64a1924f009af93037974cab73a97c771dffbc9620458dad4a5af77fff187f27',
  },
  {
    // 周13 C8-01(う)（2026-09-05 新設）: 上と対になる索引側。
    // 配列添字にならない uid は挿入順。buildRosterIndex の呼び手の groupId sort も pin する。
    name: 'src/stages/results.js reconstructedRosterIndexSha256',
    source: 'workers/game_workers/game-master-DO.js',
    // 2026-09-06 周14 T2: 上限定数の一元化で前方が+14行。15行窓の旧sha256は唯一一致。
    // 2026-09-06 周14 T5: calc-status の cursor 入力追加で前方が+9行。同じ窓はbyte不変。
    // 2026-09-07 周15 T4: reset cleanup有界化・storage分冊で前方が+38行。旧sha256の唯一一致を確認。
    // 2026-09-08 周16 S0: 統合後の旧15行窓は4652-4666に唯一一致。
    // 2026-09-14 M1: Stage 3 本番安定化の取り込み後、同じ15行窓の唯一一致を4803-4817で確認。
    // 2026-09-15 M1b: 依存待ちshield追加による前方+42行。窓本体はbyte不変。
    // 2026-09-15 周25 T2: GM-LATCH 追加で前方が+343行。15行窓の旧sha256は唯一一致。
    // 2026-09-16 周25 T2b: landing_unverified の非終端化で前方が+32行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q7: deposit読取上限定数の追加で前方+3行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q11: 依存待ちgraceの必要量化で前方+21行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q11b: 6時間刻み化による前方+4行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q23: TokenMining ABI 追加により前方+3行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q25: dependency shield の完了済み判定追加で前方+19行。
    // 旧15行窓の sha256 は新位置で唯一一致し、窓本体は byte 不変。
    // 2026-09-17 周25 Q39: Q11bの6時間切り上げ4行を外し、旧sha256は新位置で唯一一致。
    // 2026-09-18 周26 R4: GM前方の定数・ABI追加で+6行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1: parked警報定数の前方+1行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1c: 管理tx専用待機・凍結印・手動API案内の前方追加で+82行。
    // 旧15行窓のsha256は新位置で唯一一致し、窓本体はbyte不変。
    // 2026-09-18 周26 T1d: 管理tx待ちの共通化による前方+55行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1e: no-game checkpoint境界の限定による前方+41行。旧sha256は唯一一致。
    // 2026-09-19 周26 T1f: 前方修正+9行。旧sha256の唯一一致を確認。
    // 2026-09-19 周26 T1h: no-game復旧・再登録の前方差分+13行。旧sha256は唯一一致。
    // 2026-09-22 周29 便 PV: GM前方に7引数ABI・HashStorage履歴ABI・prev登録読取を足して +28 行。同じ行数の窓を全走査し旧sha256の唯一一致を確認（中身は不変）。
    // 2026-09-24 周31 便 M8: 名簿の開始関門・共有規則の取込（ユーザー決定 R31-U-A・U-B）で前方がずれた。同じ行数の窓を全走査し旧sha256の唯一一致を確認（中身は不変）。
    // 2026-09-27 便 C32F1（C32-A-14）: GM 前方（extendGraceOnChain の already_sufficient に名簿つき開始の印・関門の roster_pipeline_late の出口）で +23 行。旧 sha256 の同じ行数の窓を全走査し唯一一致を確認（中身不変）。
    // 2026-09-27 便 C32F2（C32-B-01）: GM 前方（START_PAST_TOLERANCE の ABI・shieldStartWindow の頭打ちの印・依存 shield の取り直し・extendGraceOnChain の Start in past の事前検査）で +73 行。旧 sha256 の同じ行数の窓を全走査し唯一一致を確認（中身不変）。
    // 2026-11-06 便 WR-E2E-S15-PROVERFIX（/zkp-successor の口と後継の追跡・attach）: GM 前方で +20 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP・GMGROUP-FIX1（組分けの shard の書き込みの一時的な失敗の再開・警報・待ち・印）: GM 前方で +75 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP-FIX2（開始関門の待ちの終わりの道・警報の印の原因と配送の結果）: GM 前方で +46 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 便 WR-PRE-PRESENCE（presence の時間回復・合図の配信・ADMINGAS の同期）: 前方で +0 行。旧 sha256 の同じ行数の窓を全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 WR-PRE-ADMINGAS-FIX1: 同長窓を全走査し唯一一致を再確認。本文・sha256・行位置は不変。
    startLine: 7109, endLine: 7134,
    sha256: 'ebde280106257101672f3c27f9996225f96a142f9022d0fa2efaa5b5d630cb61',
    mirrorFile: 'src/stages/results.js',
    mirrorSignature: 'export function reconstructedRosterIndexSha256(groups) {',
    mirrorSha256: '02922779c8e03763257ef04ebc7372e1caee5fa532a4b0d4111c6f49e1390f32',
  },
  {
    name: 'src/stages/results.js reconstructCanonicalRosterPayloads index order',
    declarationText: 'MIRROR: GM rebuildAndPublishRosterManifest の index 用 groupId sort と indexText',
    source: 'workers/game_workers/game-master-DO.js',
    // 2026-09-27 便 C32F1（C32-A-14）: GM 前方（extendGraceOnChain の already_sufficient に名簿つき開始の印・関門の roster_pipeline_late の出口）で +23 行。旧 sha256 の同じ行数の窓を全走査し唯一一致を確認（中身不変）。
    // 2026-09-27 便 C32F2（C32-B-01）: GM 前方（START_PAST_TOLERANCE の ABI・shieldStartWindow の頭打ちの印・依存 shield の取り直し・extendGraceOnChain の Start in past の事前検査）で +73 行。旧 sha256 の同じ行数の窓を全走査し唯一一致を確認（中身不変）。
    // 2026-11-06 便 WR-E2E-S15-PROVERFIX（/zkp-successor の口と後継の追跡・attach）: GM 前方で +20 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP・GMGROUP-FIX1（組分けの shard の書き込みの一時的な失敗の再開・警報・待ち・印）: GM 前方で +75 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP-FIX2（開始関門の待ちの終わりの道・警報の印の原因と配送の結果）: GM 前方で +46 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 便 WR-PRE-PRESENCE（presence の時間回復・合図の配信・ADMINGAS の同期）: 前方で +0 行。旧 sha256 の同じ行数の窓を全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 WR-PRE-ADMINGAS-FIX1: 同長窓を全走査し唯一一致を再確認。本文・sha256・行位置は不変。
    startLine: 7169, endLine: 7172,
    sha256: '9e4206afcf1aa3579903b523eb55dde7ef7c5c4be9641a9f8a2224dbe3329c84',
    mirrorFile: 'src/stages/results.js',
    mirrorSignature: 'export function reconstructCanonicalRosterPayloads(blockNum, groups) {',
    mirrorSha256: '86b6b8edbf52e3c3e37cc13ed5dc92777de7fc0de1f9f1309be232f722d853ea',
  },
  {
    name: 'src/stages/results.js reconstructCanonicalRosterPayloads manifest order',
    declarationText: 'MIRROR: GM rebuildAndPublishRosterManifest の groups.sort と manifestText',
    source: 'workers/game_workers/game-master-DO.js',
    // 2026-09-27 便 C32F1（C32-A-14）: GM 前方（extendGraceOnChain の already_sufficient に名簿つき開始の印・関門の roster_pipeline_late の出口）で +23 行。旧 sha256 の同じ行数の窓を全走査し唯一一致を確認（中身不変）。
    // 2026-09-27 便 C32F2（C32-B-01）: GM 前方（START_PAST_TOLERANCE の ABI・shieldStartWindow の頭打ちの印・依存 shield の取り直し・extendGraceOnChain の Start in past の事前検査）で +73 行。旧 sha256 の同じ行数の窓を全走査し唯一一致を確認（中身不変）。
    // 2026-11-06 便 WR-E2E-S15-PROVERFIX（/zkp-successor の口と後継の追跡・attach）: GM 前方で +20 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP・GMGROUP-FIX1（組分けの shard の書き込みの一時的な失敗の再開・警報・待ち・印）: GM 前方で +75 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP-FIX2（開始関門の待ちの終わりの道・警報の印の原因と配送の結果）: GM 前方で +46 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 便 WR-PRE-PRESENCE（presence の時間回復・合図の配信・ADMINGAS の同期）: 前方で +0 行。旧 sha256 の同じ行数の窓を全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 WR-PRE-ADMINGAS-FIX1: 同長窓を全走査し唯一一致を再確認。本文・sha256・行位置は不変。
    startLine: 7205, endLine: 7206,
    sha256: '6a41a1467ea787aa4dc9942ee15a46be57f83fa5e76eba6f09abca3c37a61f56',
    mirrorFile: 'src/stages/results.js',
    mirrorSignature: 'export function reconstructCanonicalRosterPayloads(blockNum, groups) {',
    mirrorSha256: '86b6b8edbf52e3c3e37cc13ed5dc92777de7fc0de1f9f1309be232f722d853ea',
  },
  {
    name: 'src/stages/results.js mirrorRewardSplit',
    declarationText: 'MIRROR: workers/game_workers/game-master-DO.js の calcRewardsUnit 内 50/50 スプリット',
    source: 'workers/game_workers/game-master-DO.js',
    // 🔴 2026-08-06: 正典に P-2026-0811 #14（名簿の重複 uid 検査）が入り13行、
    //    P-2026-0812（名簿の**順序**検査）が入りさらに27行、この範囲より前で増えた。
    //    区間の中身は byte 一致のまま（sha256 は据え置き）。
    // 🔴 2026-08-07: P-2026-0813（Evidence 取り込みの権威化）でこの範囲より前が
    //    大きく動いたが、**差し引きちょうど 0 行**だった
    //    （旧 reconcileEvidence の削除 −188 / ingest・採用の再検証・meta 照合の追加 +188）。
    //    中身も byte 一致のままなので、行番号・sha256 とも据え置き。
    //    ⚠️ 偶然の一致なので、次に触るときは必ずここを再計算すること。
    // 🔴 2026-08-07: P-2026-0814（scoring ユニットの CPU ガードを
    //    `CALC_CPU_BUDGET_MS − CALC_GROUP_WORST_MS` から導くようにした）で
    //    この範囲より前が **+32 行**（定数ブロック31行＋コメント1行）。
    //    区間の中身は byte 一致のまま（sha256 は据え置き・行番号だけ +32）。
    // 🔴 2026-08-07: P-2026-0815（選出データ照合を当選者行の全フィールドまで強化）で
    //    この範囲より前が **+31 行**（startGrouping の検査ブロック +27 / progress 初期化 +4）。
    //    区間の中身は byte 一致のまま（sha256 は据え置き・行番号だけ +31）。
    // 🔴 2026-08-07: P-2026-0816（グループ分け完全性検査の新設）で
    //    この範囲より前が **+60 行**（import 1 / startGrouping の検査ブロック 59）。
    //    区間の中身は byte 一致のまま（sha256 は据え置き・行番号だけ +60）。
    // 🔴 2026-08-07: P-2026-0820（デポジット検証の fail-closed 化）と
    //    P-2026-0823（uid 添字マップのプロトタイプ穴の一掃）で
    //    この範囲より前が **+103 行**。区間の中身は byte 一致のまま
    //    （sha256 は据え置き・行番号だけ +103）。
    //    ⚠️ ずれの確認方法: 同じ行数（159行）の窓を全走査して sha256 が一致する開始行を探す。
    //       一致する窓が在れば「行がずれただけ」、無ければ**中身が変わっている**ので
    //       ミラーを人手で再レビューすること。
    // 🔴 2026-08-07: P-2026-0825（正準 JSON ゲート）ほか本日の一連の修正で
    //    この範囲より前が **+33 行**。区間の中身は byte 一致のまま
    //    （sha256 は据え置き・行番号だけ +33）。上の確認手順で窓を全走査して特定した。
    // 🔴 2026-08-08: P-2026-0830（vdep.wei 形式ガード）ほかでこの範囲より前が **+16 行**。
    //    区間の中身は byte 一致のまま（sha256 据え置き・行番号だけ +16）。窓の全走査で特定。
    // 🔴 2026-08-08: P-2026-0909（manifest の `receiptMaxActionsPerPairBase` 追加）で
    //    import 行が **+1 行**。区間の中身は byte 一致のまま
    //    （sha256 据え置き・行番号だけ +1）。窓の全走査で特定。
    // 🔴 2026-08-08: P-2026-0834（R18・`serverState` のコメント訂正）でこの範囲より前が
    //    **+14 行**。区間の中身は byte 一致のまま（sha256 据え置き・行番号だけ +14）。
    //    同じ行数（159行）の窓を全走査して特定した。
    // 🔴 2026-08-08: ラウンド19（判断不要-3 / -6 / -7 と台帳 C-3）でこの範囲より前が
    //    **+102 行**。区間の中身は byte 一致のまま（sha256 据え置き・行番号だけ +102）。
    //    同じ行数（159行）の窓を全走査して特定した（一致は1箇所のみ）。
    // 🔴 2026-08-08: J-31（自動配布経路の適格デポジット判定）で import 行が **+5 行**
    //    （`game-result-calculator.js` から適格帯の定数と判定を取り込むため）。
    //    区間の中身は byte 一致のまま（sha256 据え置き・行番号だけ +5）。
    //    同じ行数（159行）の窓を全走査して特定した（一致は 5315-5473 の1箇所のみ）。
    // 🔴 2026-08-08: ラウンド20（回帰-1 R-1 の root 提出4経路そろえ・回帰-2 R-2 のフェーズ表）で
    //    この範囲より前が **+92 行**。区間の中身は byte 一致のまま
    //    （sha256 据え置き・行番号だけ +92）。同じ行数（159行）の窓を全走査して特定した
    //    （一致は 5407-5565 の1箇所のみ）。
    // 🔴 2026-08-09: J-34（集計の起点を `entries/block{N}/game_groups.json` へ）で
    //    この範囲より前が **+131 行**（`calcLoadGroupAuthority` の新設と `calcLoadGroups` の
    //    書き換え）。区間の中身は byte 一致のまま（sha256 据え置き・行番号だけ +131）。
    //    同じ行数（159行）の窓を全走査して特定した（一致は 5538-5696 の1箇所のみ）。
    // 🔴 2026-08-09: D-1 #5（集計ステージ列挙のコメント訂正・`proofs` / `adminCommit` の追記）で
    //    この範囲より前が **+5 行**。区間の中身は byte 一致のまま（sha256 据え置き・行番号だけ +5）。
    //    窓の全走査で特定（一致は 5543-5701 の1箇所のみ）。
    // 2026-08-11: canonicalTimeline の R2 書き戻しを scoring 後へ追加し、この範囲より前が +6 行。
    // 同じ159行窓の全走査で旧sha256と一致する唯一の位置を確認（中身は不変）。
    // 2026-08-11: Stage 2 shadow proving の待機・fallback 制御追加により +20 行。
    // 同じ159行窓の全走査で旧sha256と一致する唯一の位置を確認（中身は不変）。
    // 2026-08-11: Stage 3 一括修正（lean summary・claim overlay・再開checkpoint）で
    // この範囲より前が +104 行。159行窓の全走査で旧sha256の唯一一致を確認した。
    // 2026-08-12: Round 21--24 の追加はこの範囲より前だけに入り +48 行。
    // 159行窓の全走査で旧sha256の唯一一致（5768-5926）を確認した。
    // 2026-08-13: Round 25 Evidence救済実装はこの範囲より前だけに入り +217 行。
    // 同じ159行窓の全走査で旧sha256の唯一一致（5985-6143）を確認した。
    // 2026-08-14: R26-C8（normalizeLang の冪等化）でこの範囲より前が +9 行。
    // 159行窓の全走査で旧sha256の唯一一致（5994-6152）を確認した（中身は不変）。
    // 2026-08-14: Round 26 の RANDAO Ethereum block fact anchor 追加でこの範囲より前が +52 行。
    // 159行窓の全走査で旧sha256の唯一一致（6046-6204）を確認した（中身は不変）。
    // 2026-08-17: scoring/ZKP fix request 2 のライブ名簿アンカー追加で、この範囲より前が +71 行。
    // 159行窓の全走査で旧sha256の唯一一致（6117-6275）を確認した（中身は不変）。
    // 同REQUEST2のアンカー時刻保証追加でさらに +6 行。旧sha256の唯一一致を再確認。
    // 2026-08-17: REQUEST3のroster再公開／一斉開始追加で前方が+97行。
    // 159行窓の全走査で旧sha256の唯一一致（6220-6378）を確認した。
    // 2026-08-22: R11-03 の lostRuns 復旧カウンタ追加で前方が+8行。
    // 159行窓の全走査で旧sha256の唯一一致（6228-6386）を確認した。
    // 2026-08-22: 第11ラウンド便4の CPU 天井コメント訂正で前方が+5行。
    // 同じ159行窓を全走査し、旧sha256の唯一一致（6233-6391）を確認（中身は不変）。
    // 2026-08-23: Round12 FIX_3 の GameMasterDO 修正で前方が+100行。
    // 同じ159行窓を全走査し、旧sha256の唯一一致（6333-6491）を確認（中身は不変）。
    // 2026-08-23: Round12 FIX_4 の `/anchor-result` 再archive復旧追加で前方が+49行。
    // 同じ159行窓を全走査し、旧sha256の唯一一致（6382-6540）を確認（中身は不変）。
    // 2026-08-23: Round12 FIX_8 の再開可能なEvidence分割取り込みで前方が合計+59行。
    // 同じ159行窓を全走査し、旧sha256の唯一一致を確認（中身は不変）。
    // 2026-08-24: Round13 A3 α1〜α3 の観測・再開処理追加で前方が+453行。
    // 同じ159行窓を全走査し、旧sha256の唯一一致（6894-7052）を確認（中身は不変）。
    // 2026-08-25: R14 F3 の status 観測修正が前方へ +6 行。
    // 159行窓の全走査で旧sha256の唯一一致（6900-7058）を確認した（中身は不変）。
    // 2026-08-25: R14 F15 同期時点（F9/F11/F12 等）の前方差分 +77 行。
    // 159行窓の全走査で旧sha256の唯一一致（6977-7135）を確認した（中身は不変）。
    // 2026-08-26: C17 の正典前方差分 +38 行。159行窓の全走査で旧sha256の唯一一致
    // （7015-7173）を確認し、総点按分・失格時0・検証済みdeposit優先・50/50・
    // depositorShareOf の各規則をミラー本体と再レビューした（中身・sha256とも不変）。

    // 2026-08-26: 便W10（R15-40/50/30/26/10＋ガス3日自動force）で前方が増えた。
    //   同じ行数の窓を全走査し、旧sha256の唯一一致を確認（中身は byte 一致）。

    // 2026-08-26: origin/main（本番配備系統）との統合で前方が増えた。
    //   同じ行数の窓を全走査し、旧sha256の唯一一致を確認（中身は byte 一致）。

    // 🔴 2026-08-28（第17ラウンド it1・W2）: `/group-status` の deep 化と
    //   lifecycle キャッシュ拡張で、この範囲より前が **+33 行**。
    //   同じ行数の窓を全走査して**旧 sha256 の唯一一致**を確認済み（中身は byte 一致）。
    //   ⇒ 行番号だけ +33、sha256 は据え置き。
    // 2026-08-31: Step 2 commit 2（lang の UTF-16 well-formedness 検査）の helper が
    // この範囲より前に +18 行。同じ159行窓の全走査で旧sha256の唯一一致を確認した。
    // 2026-08-31: S3-A の entry-worker 同期先コメント追加で前方が +1 行。
    // 2026-09-04: main（改名監査の修正一式）取り込みで前方が +14 行。
    //   同じ行数の窓を全走査して旧 sha256 の唯一一致を確認（中身 byte 一致・sha256 据え置き）。
    // 2026-09-04（周11 R11-C01/A-1）: 正典に lang の文字集合検査が入り前方が +16 行。
    //   同じ行数の窓を全走査して旧 sha256 の唯一一致を確認（中身 byte 一致・sha256 据え置き）。
    // 2026-09-04（周11 P1）: Stage 3 集約の自動発注配線で前方が +10 行。
    //   同じ行数の窓を全走査して旧 sha256 の唯一一致を確認（中身 byte 一致・sha256 据え置き）。
    // 2026-09-06 周14 T2: 上限定数の一元化で前方が+14行。159行窓の旧sha256は唯一一致。
    // 2026-09-06 周14 T5: calc-status の cursor 入力追加で前方が+9行。同じ窓はbyte不変。
    // 2026-09-07 周15 T4: reset cleanup・storage分冊・roster分離で前方が+46行。旧sha256の唯一一致を確認。
    // 2026-09-08 周16 S0: Stage 3実走の追加と周15を統合後、旧159行窓の唯一一致は7694-7852。
    // 2026-09-14 M1: calcRewardsUnit の // 4 から50/50 split完了までの159行を最終正典で再確定。
    // 2026-09-15 M1b: 依存待ちshield追加による前方+42行。窓本体はbyte不変。
    // 2026-09-16 周25 T2b: G8 の前方差分+32行。159行窓の旧sha256は唯一一致。
    // 2026-09-16 周25 Q7: 預託適格規則の変更で前方+6行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q11: 依存待ちgraceの必要量化で前方+21行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q11b: 6時間刻み化による前方+4行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q23: HashStorage配線照合helper追加により前方+94行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q25: shield 閉鎖・depositId 正準形拒否・監視転送で前方+49行。
    // 旧159行窓の sha256 は新位置で唯一一致し、窓本体は byte 不変。
    // 2026-09-17 周25 Q39: Q11bの6時間切り上げ4行を外し、旧sha256は新位置で唯一一致。
    // 2026-09-18 周26 R4: GM前方の定数・ABI追加で+6行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1: parked警報の前方追加で+22行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1c: 上記GM待機処理の前方追加で+82行。旧159行窓は唯一一致。
    // 2026-09-18 周26 T1d: 同じ前方差分+55行。旧159行窓は唯一一致。
    // 2026-09-18 周26 T1e: 同じ前方差分+41行。旧159行窓は唯一一致。
    // 2026-09-19 周26 T1f: 前方修正+12行。旧sha256の唯一一致を確認。
    // 2026-09-22 周29 便 PV: GM前方に7引数ABI・HashStorage履歴ABI・prev登録読取を足して +28 行。同じ行数の窓を全走査し旧sha256の唯一一致を確認（中身は不変）。
    // 2026-09-24 周31 便 M8: 名簿の開始関門・共有規則の取込（ユーザー決定 R31-U-A・U-B）で前方がずれた。同じ行数の窓を全走査し旧sha256の唯一一致を確認（中身は不変）。
    // 2026-09-24 周31 便 M10d: 旧sha256の同じ159行窓は全走査で9390-9548に唯一一致。
    // 2026-09-27 周33 便 S3C5（D-06）: calcEvidenceUnit・calcFinalizeUnit の前方差分でずれた。旧sha256の同じ159行窓は全走査で9801-9959に唯一一致（中身は不変）。
    // 2026-09-27 便 C30F1c: GM 前方（開始関門の shield 幅・遅れた開始の印）で +49 行。旧 sha256 の唯一一致を全走査で確認（中身不変）。
    // 2026-09-27 統合（contract-review-2026-09 × stage4-review の merge）: 上の S3C5 と C30F1c の両方の前方差分を合わせた GM で、旧 sha256 の同じ行数の窓を全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-09-27 周33 便 S3C8（D-09）: calcFetchGroupData の取得の失敗を救済より前に throw する直しとコメントで GM 前方 +7 行。旧sha256の同じ159行窓は全走査で9904-10062に唯一一致（中身は不変）。
    // 2026-09-27 周33 便 S3C13（文書の一括・R33-F-3-02）: 窓の中のコメント2行（改名前の契約の関数名 claimDepositor・_payDepositor → claimLockReward の _resolveLockRewardSplit・_payLockReward）だけを直した。コメントを除いた中身と行の位置は不変なので正典の窓の sha256 だけを更新した（ミラー本体は不変）。
    // 2026-09-27 便 C32F1（C32-A-14）: GM 前方（extendGraceOnChain の already_sufficient に名簿つき開始の印・関門の roster_pipeline_late の出口）で +27 行。旧 sha256 の同じ行数の窓を全走査し唯一一致を確認（中身不変）。
    // 2026-09-27 便 C32F2（C32-B-01）: GM 前方（上の +73 行＋自動延長の注記・shieldRosterStartWindow の終端）で +76 行。旧 sha256 の同じ行数の窓を全走査し唯一一致を確認（中身不変）。
    // 2026-09-28 Stage 3 再レビュー周1 段0（C32 の合流・contract-review-2026-09-r2 281d06dd を main へ）: 上の S3C8／S3C13（main 側）と C32F1／C32F2（契約側）の両方の前方差分を合わせた GM で、同じ行数の窓を全走査し、sha256 の唯一一致の位置へ付け直した（中身は不変・sha256 は S3C13 の後の値）。
    // 2026-11-06 便 WR-E2E-S15-PROVERFIX（/zkp-successor の口と後継の追跡・attach）: GM 前方で +22 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP・GMGROUP-FIX1（組分けの shard の書き込みの一時的な失敗の再開・警報・待ち・印）: GM 前方で +75 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP-FIX2（開始関門の待ちの終わりの道・警報の印の原因と配送の結果）: GM 前方で +53 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 便 WR-PRE-PRESENCE（presence の時間回復・合図の配信・ADMINGAS の同期）: 前方で +0 行。旧 sha256 の同じ行数の窓を全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 WR-PRE-ADMINGAS-FIX1: 同長窓を全走査し唯一一致を再確認。本文・sha256・行位置は不変。
    startLine: 11580,
    endLine: 11738,
    sha256: '320b6e967119dca5931207551995bdd3543d5a639feaec439f627fa3a269553e',
    // 🔴 F-7(b)-3（2026-08-08・ラウンド20 判断不要-7）: **逆方向**（ミラー側）も固定する。
    //   旧実装は正典側の行範囲しか見ていなかったので、ミラーの中身を
    //   50/50 → 90/10 に書き換えても `OK MIRROR src/stages/results.js mirrorRewardSplit` と
    //   **名指しで緑**になった（実測）。ミラー関数の本体は行番号ではなく
    //   **シグネチャ行から列0の `}` まで**で自己特定する（行の churn で偽 FAIL しない）。
    mirrorFile: 'src/stages/results.js',
    mirrorSignature: 'function mirrorRewardSplit(blockNum, allGroupResults, groups, verifiedDeposits) {',
    mirrorSha256: '489f45c5a68da54066417e181325dc4c42aa49329618301ae24c4d955f359cb9',
  },
  // 🔴 2026-08-09（ラウンド22 タスク2-a）: **未登録だった手写しミラーの登録。**
  //
  //   `docs/external-audit/FINDINGS_LEDGER.md` 冒頭の指摘そのもの。
  //   `runAutoDistribute` は正典 `game-master-DO.js` の `autoDistribute` を手写しして
  //   いるのに MIRROR 行が `mirrorRewardSplit` の1本しか無く、
  //   **正典側の `autoDistribute` が変わってもミラーが追随しなくても鳴らなかった**。
  //   J-31（自動配布経路に適格帯判定が無い）では両側とも同じ穴を持ったまま
  //   「45項目・FAIL 0・WARN 0」が出ていた＝ミラーの同期が台帳で守られていなかったのが原因。
  //
  //   範囲は `autoDistribute` の**点数計算部**（B1 のオンチェーン再検証 →
  //   memberResults（適格帯判定込み）→ COINU 按分 → 50/50 Split）。
  //   後続の D1/R2 書き込み・summary 生成は検証ツールが写していないので入れない
  //   （入れると無関係な churn で偽 FAIL を量産し、台帳が読まれなくなる）。
  //   ⚠️ ずれの確認方法は上の `mirrorRewardSplit` と同じ: 同じ行数（126行）の窓を全走査して
  //      sha256 が一致する開始行を探す。一致する窓が在れば「行がずれただけ」、
  //      無ければ**中身が変わっている**のでミラーを人手で再レビューすること。
  {
    name: 'src/stages/results.js runAutoDistribute',
    source: 'workers/game_workers/game-master-DO.js',
    // 2026-08-11: 上記 canonicalTimeline 書き戻し追加により +6 行。
    // 同じ126行窓の全走査で旧sha256と一致する唯一の位置を確認（中身は不変）。
    // 2026-08-11: 同 shadow proving 制御追加により、この範囲より前が +176 行。
    // 同じ126行窓の全走査で旧sha256と一致する唯一の位置を確認（中身は不変）。
    // 2026-08-11: 同一括修正の auto-distribute checkpoint 追加で +449 行。
    // 126行窓の全走査で旧sha256の唯一一致を確認した。
    // 2026-08-12: 同一括修正でこの範囲より前が +73 行。
    // 126行窓の全走査で旧sha256の唯一一致（8436-8561）を確認した。
    // 2026-08-13: Round 25 Evidence救済実装による同じ +217 行だけずれた。
    // 旧sha256の唯一一致（8653-8778）を確認した。
    // 2026-08-14: R26-C8 の同じ +9 行。126行窓の全走査で旧sha256の唯一一致（8662-8787）を確認した。
    // 2026-08-14: Round 26 の RANDAO anchor と `/calc-status` 監視出力追加でこの範囲より前が +140 行。
    // 126行窓の全走査で旧sha256の唯一一致（8802-8927）を確認した（中身は不変）。
    // 2026-08-17: scoring/ZKP fix request 2 のライブ名簿アンカー追加で、この範囲より前が +138 行。
    // 126行窓の全走査で旧sha256の唯一一致（8940-9065）を確認した（中身は不変）。
    // 同REQUEST2のアンカー時刻保証追加でさらに +6 行。旧sha256の唯一一致を再確認。
    // 2026-08-17: 同REQUEST3の前方追加で+134行。
    // 126行窓の全走査で旧sha256の唯一一致（9080-9205）を確認した。
    // 2026-08-21: REQUEST8 便Aでmanifestの個別receipt内訳2行を削除したため -2 行。
    // 126行窓の全走査で旧sha256の唯一一致（9078-9203）を確認した（中身は不変）。
    // 2026-08-21: manifest から散文2キーを降ろし、この範囲より前が -2 行。
    // 126行窓の sha256 は不変で、唯一一致位置を 9076-9201 に更新した。
    // 2026-08-22: R11-03 の lostRuns 復旧カウンタ追加で前方が+8行。
    // 126行窓の全走査で旧sha256の唯一一致（9084-9209）を確認した。
    // 2026-08-22: 第11ラウンド便4の CPU 天井コメント訂正で前方が+5行。
    // 同じ126行窓を全走査し、旧sha256の唯一一致（9089-9214）を確認（中身は不変）。
    // 2026-08-23: Round12 FIX_3 の GameMasterDO 修正で前方が+105行。
    // 同じ126行窓を全走査し、旧sha256の唯一一致（9194-9319）を確認（中身は不変）。
    // 2026-08-23: Round12 FIX_4 の同じ前方差分+49行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-23: Round12 FIX_8 の同じ前方差分+59行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-24: Round13 A3 α1〜α3 の観測・manifest・再開処理追加で前方が+526行。
    // 同じ126行窓を全走査し、旧sha256の唯一一致（9828-9953）を確認（中身は不変）。
    // 2026-08-25: R14 F3 の同じ前方差分 +6 行。
    // 126行窓の全走査で旧sha256の唯一一致（9834-9959）を確認した（中身は不変）。
    // 2026-08-25: R14 F15 同期時点（F9/F11/F12 等）の前方差分 +80 行。
    // 126行窓の全走査で旧sha256の唯一一致（9914-10039）を確認した（中身は不変）。
    // 2026-08-26: C17 の正典前方差分 +159 行。126行窓の全走査で旧sha256の唯一一致
    // （10073-10198）を確認し、B1再検証・適格帯・総点按分・50/50・
    // depositorShareOf の各規則をミラー本体と再レビューした（中身・sha256とも不変）。

    // 2026-08-26: 便W10（R15-40/50/30/26/10＋ガス3日自動force）で前方が増えた。
    //   同じ行数の窓を全走査し、旧sha256の唯一一致を確認（中身は byte 一致）。

    // 2026-08-26: origin/main（本番配備系統）との統合で前方が増えた。
    //   同じ行数の窓を全走査し、旧sha256の唯一一致を確認（中身は byte 一致）。
    // 2026-08-31: Step 2 commit 2（lang の UTF-16 well-formedness 検査）の helper が
    // この範囲より前に +18 行。同じ126行窓の全走査で旧sha256の唯一一致を確認した。
    // 2026-08-31: S3-A の entry-worker 同期先コメント追加で前方が +1 行。
    // 2026-09-04: main（改名監査の修正一式）取り込みで前方が +14 行。
    //   同じ行数の窓を全走査して旧 sha256 の唯一一致を確認（中身 byte 一致・sha256 据え置き）。
    // 2026-09-04（周11 R11-C01/A-1）: 正典に lang の文字集合検査が入り前方が +16 行。
    //   同じ行数の窓を全走査して旧 sha256 の唯一一致を確認（中身 byte 一致・sha256 据え置き）。
    // 2026-09-04（周11 P1）: Stage 3 集約の自動発注配線で前方が +121 行。
    //   同じ行数の窓を全走査して旧 sha256 の唯一一致を確認（中身 byte 一致・sha256 据え置き）。
    // 2026-09-06 周14 T2: 上限定数とsummary分割で前方が+33行。126行窓の旧sha256は唯一一致。
    // 2026-09-06 周14 T5: calc-status の cursor 入力追加で前方が+9行。同じ窓はbyte不変。
    // 2026-09-07 周15 T4: 同じ前方差分-29行。旧sha256の唯一一致を確認。
    // 2026-09-08 周15 T7: 前方の GS-02 コメントを1行短くした。126行窓の
    // 全走査で旧sha256の唯一一致を確認（中身 byte 一致・sha256据え置き）。
    // 2026-09-08 周16 S0: 統合後の旧126行窓は11223-11348に唯一一致。
    // 2026-09-14 M1: autoDistribute の B1 再検証から50/50 split完了までの126行を最終正典で再確定。
    // 2026-09-15 M1b: 依存待ちshield追加による前方+42行。窓本体はbyte不変。
    // 2026-09-16 周25 T2b: G8 の前方差分+32行。126行窓の旧sha256は唯一一致。
    // 2026-09-16 周25 Q7: 預託適格規則の前方差分+6行。窓本体と旧sha256は不変。
    // 2026-09-16 周25 Q11: 依存待ちgraceの必要量化で前方+21行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q11b: 6時間刻み化による前方+4行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q23: 配線照合と各HashStorage経路のguard追加で前方+111行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q25: 同じ前方差分+49行。旧126行窓は新位置で唯一一致。
    // 2026-09-17 周25 Q39: Q11bの6時間切り上げ4行を外し、旧sha256は新位置で唯一一致。
    // 2026-09-18 周26 R4: GM前方+6行とRANDAO窓helper+43行で合計+49行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1: parked警報とadmin_freeze待ちの前方追加で+36行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1b: manifest待ちとCoordinator戻り値の前方追加で+33行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1c: 管理tx待機・手動API・claim-data試験可能化の前方追加で+207行。
    // 旧126行窓は新位置で唯一一致し、採点・按分本体はbyte不変。
    // 2026-09-18 周26 T1d: 待ち共通化・連続期間・read-only照会の前方差分+132行。
    // 旧126行窓は唯一一致し、採点・按分本体はbyte不変。
    // 2026-09-18 周26 T1e: 同じ前方差分+104行。旧126行窓は唯一一致。
    // 2026-09-19 周26 T1f: 前方修正+49行。旧sha256の唯一一致を確認。
    // 2026-09-22 周29 便 PV: 同じ追加＋`resolvePrevRegistrationIndexForProof` で前方 +152 行。窓の全走査で旧sha256の唯一一致を確認（中身は不変）。
    // 2026-09-22 周29 便 Z7: 0履歴の最新ビュー検算とintentIdへの添字束縛で前方+20行。旧sha256は唯一一致。
    // 2026-09-24 周31 便 M8: 名簿の開始関門・共有規則の取込（ユーザー決定 R31-U-A・U-B）で前方がずれた。同じ行数の窓を全走査し旧sha256の唯一一致を確認（中身は不変）。
    // 2026-09-24 周31 便 M10d: 旧sha256の同じ126行窓は全走査で13656-13781に唯一一致。
    // 2026-09-27 周33 便 S3C5（D-06）: calcEvidenceUnit・calcFinalizeUnit の前方差分でずれた。旧sha256の同じ126行窓は全走査で14085-14210に唯一一致（中身は不変）。
    // 2026-09-27 便 C30F1c: GM 前方（開始関門の shield 幅・遅れた開始の印）で +49 行。旧 sha256 の唯一一致を全走査で確認（中身不変）。
    // 2026-09-27 統合（contract-review-2026-09 × stage4-review の merge）: 上の S3C5 と C30F1c の両方の前方差分を合わせた GM で、旧 sha256 の同じ行数の窓を全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-09-27 周33 便 S3C8（D-09）: calcFetchGroupData の取得の失敗を救済より前に throw する直しとコメントで GM 前方 +7 行。旧sha256の同じ126行窓は全走査で14188-14313に唯一一致（中身は不変）。
    // 2026-09-27 便 C32F1（C32-A-14）: GM 前方（extendGraceOnChain の already_sufficient に名簿つき開始の印・関門の roster_pipeline_late の出口）で +27 行。旧 sha256 の同じ行数の窓を全走査し唯一一致を確認（中身不変）。
    // 2026-09-27 便 C32F2（C32-B-01）: GM 前方（上の +73 行＋自動延長の注記・shieldRosterStartWindow の終端）で +76 行。旧 sha256 の同じ行数の窓を全走査し唯一一致を確認（中身不変）。
    // 2026-09-28 Stage 3 再レビュー周1 段0（C32 の合流・contract-review-2026-09-r2 281d06dd を main へ）: 上の S3C8／S3C13（main 側）と C32F1／C32F2（契約側）の両方の前方差分を合わせた GM で、同じ行数の窓を全走査し、sha256 の唯一一致の位置へ付け直した（中身は不変・sha256 は S3C13 の後の値）。
    // S3R4 P1a-i-1: manifest の3キーと注記で前方 +4 行。旧 sha256 の窓は全走査で唯一一致（中身不変）。
    // 2026-11-06 便 WR-E2E-S15-PROVERFIX（/zkp-successor の口と後継の追跡・attach）: GM 前方で +120 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP・GMGROUP-FIX1（組分けの shard の書き込みの一時的な失敗の再開・警報・待ち・印）: GM 前方で +75 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP-FIX2（開始関門の待ちの終わりの道・警報の印の原因と配送の結果）: GM 前方で +56 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 便 WR-PRE-PRESENCE（presence の時間回復・合図の配信・ADMINGAS の同期）: 前方で +25 行。旧 sha256 の同じ行数の窓を全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 WR-PRE-ADMINGAS-FIX1: 同長窓を全走査し唯一一致を再確認。本文・sha256・行位置は不変。
    startLine: 17003, endLine: 17128,
    sha256: '1df9664d0e69182291d074fae90dff646eebe257ce47a6d3b07a72e4ba22060b',
    // 🔴 R26-C5（2026-08-13・ラウンド26）: **逆方向（ミラー側）が未固定だった。**
    //   `MIRRORS[0]`（mirrorRewardSplit）は F-7(b)-3 で両側を固定したのに、この行だけ
    //   `mirrorFile` / `mirrorSha256` が無く、`if (m.mirrorFile && m.mirrorSha256)`（:294）の
    //   ブロックも台帳の `MIRROR-BODY` 照合（:425 の `if (s.mirrorSha256 != null)`）も
    //   丸ごと素通りしていた。つまり**検証ツール側の自動配布採点だけを書き換えても緑のまま**で、
    //   これは F-7(b)-3 が「実測で緑になった」と記録したのと同じ穴（50/50 → 90/10 の類）。
    //   正典側だけを固定しても、ミラーが勝手に変われば第三者の再計算は別物になる。
    // 2026-09-07 周15 T5: 検証ツール固有の取得境界を 250 depositId 単位にし、取得不能を
    // mismatch と分けて採点前に not_ready で止める分岐を追加した。正典の点数計算規則は
    // 変えておらず、取得成功後のミラー部分を再レビューしたうえで本体 hash を更新。
    mirrorFile: 'src/stages/results.js',
    mirrorSignature: 'async function runAutoDistribute(ctx, S, gm, timing) {',
    // 2026-09-16 周25 Q25: 並行便Q24の緊急再構築メタデータをレビュー。
    // 取得成功後の採点規則は不変で、Q24の現在の関数本体を逆方向pinへ反映する。
    mirrorSha256: '32d7a6ef6170af8799145d2617ea4743f3e242c15adf83034725972393f6f2f0',
  },
  // R12-19（2026-08-23）: src/stages/grouping.js にある game_groups.json 統計の
  // 手書きミラー3本を登録する。正典側・ミラー側のどちらが変わっても再レビューを要求する。
  {
    name: 'src/stages/grouping.js toPublishedShape',
    source: 'workers/game_workers/game-master-DO.js',
    // 2026-08-23: Round12 FIX_3 の前方差分+105行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-23: Round12 FIX_4 の同じ前方差分+49行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-23: Round12 FIX_8 の同じ前方差分+59行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-24: Round13 A3 α1〜α3 の前方差分+526行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-25: R14 F3 の同じ前方差分 +6 行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-25: R14 F15 同期時点（F9/F11/F12 等）の前方差分 +66 行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-26: C17 の正典前方差分 +159 行。7行窓の全走査で旧sha256の唯一一致
    // （11251-11257）を確認し、公開5フィールドと uid/globalIndex fallback を再レビューした。

    // 2026-08-26: 便W10（R15-40/50/30/26/10＋ガス3日自動force）で前方が増えた。
    //   同じ行数の窓を全走査し、旧sha256の唯一一致を確認（中身は byte 一致）。

    // 2026-08-26: origin/main（本番配備系統）との統合で前方が増えた。
    //   同じ行数の窓を全走査し、旧sha256の唯一一致を確認（中身は byte 一致）。
    // 2026-08-31: Step 2 A1（主要言語優先）で前方が +3 行。
    // 7行窓の全走査で旧sha256の唯一一致を確認（中身は byte 一致）。
    // 2026-08-31: Step 2 commit 2（lang の UTF-16 well-formedness 検査）が前方へ +24 行。
    // 7行窓の全走査で旧sha256の唯一一致を確認（中身は byte 一致）。
    // 2026-08-31: S3-A の entry-worker 同期先コメント追加で前方が +1 行。
    // 2026-09-04: main（改名監査の修正一式）取り込みで前方が +14 行。
    //   同じ行数の窓を全走査して旧 sha256 の唯一一致を確認（中身 byte 一致・sha256 据え置き）。
    // 2026-09-04（周11 R11-C01/A-1）: 正典に lang の文字集合検査が入り前方が +41 行。
    //   同じ行数の窓を全走査して旧 sha256 の唯一一致を確認（中身 byte 一致・sha256 据え置き）。
    // 2026-09-04（周11 P1）: Stage 3 集約の自動発注配線で前方が +121 行。
    //   同じ行数の窓を全走査して旧 sha256 の唯一一致を確認（中身 byte 一致・sha256 据え置き）。
    // 2026-09-06 周14 T2: 同じ前方差分+33行。7行窓の旧sha256は唯一一致。
    // 2026-09-06 周14 T5: calc-status の cursor 入力追加で前方が+9行。同じ窓はbyte不変。
    // 2026-09-07 周15 T4: 同じ前方差分+46行。旧sha256の唯一一致を確認。
    // 2026-09-08 周15 T7: 同じ前方差分 -1 行。旧sha256の唯一一致を確認。
    // 2026-09-08 周16 S0: 統合後の旧7行窓は12436-12442に唯一一致。
    // 2026-09-14 M1: createGroupSummary の公開 groups 写像7行を最終正典で再確定。
    // 2026-09-15 M1b: 依存待ちshield追加による前方+42行。窓本体はbyte不変。
    // 2026-09-16 周25 T2b: G8 の前方差分+32行。7行窓の旧sha256は唯一一致。
    // 2026-09-16 周25 Q7: 預託適格規則の前方差分+6行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q11: 依存待ちgraceの必要量化で前方+21行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q11b: 6時間刻み化による前方+4行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q23: 同じ前方差分+111行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q25: 同じ前方差分+49行。旧7行窓は新位置で唯一一致。
    // 2026-09-17 周25 Q39: Q11bの6時間切り上げ4行を外し、旧sha256は新位置で唯一一致。
    // 2026-09-18 周26 R4: GM前方差分+49行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1: 同じ前方差分+36行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1b: 同じ前方差分+33行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1c: 自動配布manifest専用待機ほかの前方追加で+227行。
    // 旧7行窓は新位置で唯一一致。
    // 2026-09-18 周26 T1d: 同じ前方差分+146行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1e: 同じ前方差分+104行。旧sha256は唯一一致。
    // 2026-09-19 周26 T1f: 前方修正+50行。旧sha256の唯一一致を確認。
    // 2026-09-22 周29 便 PV: 同じ追加＋`resolvePrevRegistrationIndexForProof` で前方 +152 行。窓の全走査で旧sha256の唯一一致を確認（中身は不変）。
    // 2026-09-22 周29 便 Z7: 同じ前方+20行。旧sha256は唯一一致。
    // 2026-09-24 周31 便 M8: 名簿の開始関門・共有規則の取込（ユーザー決定 R31-U-A・U-B）で前方がずれた。同じ行数の窓を全走査し旧sha256の唯一一致を確認（中身は不変）。
    // 2026-09-24 周31 便 M10d: 旧sha256の同じ7行窓は全走査で14912-14918に唯一一致。
    // 2026-09-27 周33 便 S3C5（D-06）: calcEvidenceUnit・calcFinalizeUnit の前方差分でずれた。旧sha256の同じ7行窓は全走査で15347-15353に唯一一致（中身は不変）。
    // 2026-09-27 便 C30F1c: GM 前方（開始関門の shield 幅・遅れた開始の印）で +49 行。旧 sha256 の唯一一致を全走査で確認（中身不変）。
    // 2026-09-27 統合（contract-review-2026-09 × stage4-review の merge）: 上の S3C5 と C30F1c の両方の前方差分を合わせた GM で、旧 sha256 の同じ行数の窓を全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-09-27 周33 便 S3C8（D-09）: calcFetchGroupData の取得の失敗を救済より前に throw する直しとコメントで GM 前方 +7 行。旧sha256の同じ7行窓は全走査で15450-15456に唯一一致（中身は不変）。
    // 2026-09-27 便 C32F1（C32-A-14）: GM 前方（extendGraceOnChain の already_sufficient に名簿つき開始の印・関門の roster_pipeline_late の出口）で +27 行。旧 sha256 の同じ行数の窓を全走査し唯一一致を確認（中身不変）。
    // 2026-09-27 便 C32F2（C32-B-01）: GM 前方（上の +73 行＋自動延長の注記・shieldRosterStartWindow の終端）で +76 行。旧 sha256 の同じ行数の窓を全走査し唯一一致を確認（中身不変）。
    // 2026-09-28 Stage 3 再レビュー周1 段0（C32 の合流・contract-review-2026-09-r2 281d06dd を main へ）: 上の S3C8／S3C13（main 側）と C32F1／C32F2（契約側）の両方の前方差分を合わせた GM で、同じ行数の窓を全走査し、sha256 の唯一一致の位置へ付け直した（中身は不変・sha256 は S3C13 の後の値）。
    // 2026-11-06 便 WR-E2E-S15-PROVERFIX（/zkp-successor の口と後継の追跡・attach）: GM 前方で +120 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP・GMGROUP-FIX1（組分けの shard の書き込みの一時的な失敗の再開・警報・待ち・印）: GM 前方で +75 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP-FIX2（開始関門の待ちの終わりの道・警報の印の原因と配送の結果）: GM 前方で +57 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 便 WR-PRE-PRESENCE（presence の時間回復・合図の配信・ADMINGAS の同期）: 前方で +25 行。旧 sha256 の同じ行数の窓を全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 WR-PRE-ADMINGAS-FIX1: 同長窓を全走査し唯一一致を再確認。本文・sha256・行位置は不変。
    startLine: 18326, endLine: 18332,
    sha256: '8c0caf301712ae3b40201922a1810e04190e1199fb2f573ff4721199786022d6',
    mirrorFile: 'src/stages/grouping.js',
    mirrorSignature: 'function toPublishedShape(groups) {',
    mirrorSha256: '658476c7aaec92d22ad2f8d1e530439d83e9542c1a96ebe5c9e5a598fb342d12',
  },
  {
    name: 'src/stages/grouping.js countGroupsByLang',
    source: 'workers/game_workers/game-master-DO.js',
    // 2026-08-23: Round12 FIX_3 の前方差分+105行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-23: Round12 FIX_4 の同じ前方差分+49行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-23: Round12 FIX_8 の同じ前方差分+59行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-24: Round13 A3 α1〜α3 の前方差分+526行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-25: R14 F3 の同じ前方差分 +6 行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-25: R14 F15 同期時点（F9/F11/F12 等）の前方差分 +66 行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-26: C17 の正典前方差分 +159 行。11行窓の全走査で旧sha256の唯一一致
    // （11263-11273）を確認し、null-prototype辞書と lang 別加算を再レビューした。

    // 2026-08-26: 便W10（R15-40/50/30/26/10＋ガス3日自動force）で前方が増えた。
    //   同じ行数の窓を全走査し、旧sha256の唯一一致を確認（中身は byte 一致）。

    // 2026-08-26: origin/main（本番配備系統）との統合で前方が増えた。
    //   同じ行数の窓を全走査し、旧sha256の唯一一致を確認（中身は byte 一致）。
    // 2026-08-31: Step 2 A1（主要言語優先）で前方が +3 行。
    // 11行窓の全走査で旧sha256の唯一一致を確認（中身は byte 一致）。
    // 2026-08-31: Step 2 commit 2（lang の UTF-16 well-formedness 検査）が前方へ +24 行。
    // 11行窓の全走査で旧sha256の唯一一致を確認（中身は byte 一致）。
    // 2026-08-31: S3-A の entry-worker 同期先コメント追加で前方が +1 行。
    // 2026-09-04: main（改名監査の修正一式）取り込みで前方が +14 行。
    //   同じ行数の窓を全走査して旧 sha256 の唯一一致を確認（中身 byte 一致・sha256 据え置き）。
    // 2026-09-04（周11 R11-C01/A-1）: 正典に lang の文字集合検査が入り前方が +41 行。
    //   同じ行数の窓を全走査して旧 sha256 の唯一一致を確認（中身 byte 一致・sha256 据え置き）。
    // 2026-09-04（周11 P1）: Stage 3 集約の自動発注配線で前方が +121 行。
    //   同じ行数の窓を全走査して旧 sha256 の唯一一致を確認（中身 byte 一致・sha256 据え置き）。
    // 2026-09-06 周14 T2: 同じ前方差分+33行。11行窓の旧sha256は唯一一致。
    // 2026-09-06 周14 T5: calc-status の cursor 入力追加で前方が+9行。同じ窓はbyte不変。
    // 2026-09-07 周15 T4: 同じ前方差分+46行。旧sha256の唯一一致を確認。
    // 2026-09-08 周15 T7: 同じ前方差分 -1 行。旧sha256の唯一一致を確認。
    // 2026-09-08 周16 S0: 統合後の旧11行窓は12448-12458に唯一一致。
    // 2026-09-14 M1: countGroupsByLang 11行を最終正典で再確定。
    // 2026-09-15 M1b: 依存待ちshield追加による前方+42行。窓本体はbyte不変。
    // 2026-09-16 周25 T2b: G8 の前方差分+32行。11行窓の旧sha256は唯一一致。
    // 2026-09-16 周25 Q7: 預託適格規則の前方差分+6行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q11: 依存待ちgraceの必要量化で前方+21行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q11b: 6時間刻み化による前方+4行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q23: 同じ前方差分+111行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q25: 同じ前方差分+49行。旧11行窓は新位置で唯一一致。
    // 2026-09-17 周25 Q39: Q11bの6時間切り上げ4行を外し、旧sha256は新位置で唯一一致。
    // 2026-09-18 周26 R4: GM前方差分+49行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1: 同じ前方差分+36行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1b: 同じ前方差分+33行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1c: 同上+227行。旧11行窓は新位置で唯一一致。
    // 2026-09-18 周26 T1d: 同じ前方差分+146行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1e: 同じ前方差分+104行。旧sha256は唯一一致。
    // 2026-09-19 周26 T1f: 前方修正+50行。旧sha256の唯一一致を確認。
    // 2026-09-22 周29 便 PV: 同じ追加＋`resolvePrevRegistrationIndexForProof` で前方 +152 行。窓の全走査で旧sha256の唯一一致を確認（中身は不変）。
    // 2026-09-22 周29 便 Z7: 同じ前方+20行。旧sha256は唯一一致。
    // 2026-09-24 周31 便 M8: 名簿の開始関門・共有規則の取込（ユーザー決定 R31-U-A・U-B）で前方がずれた。同じ行数の窓を全走査し旧sha256の唯一一致を確認（中身は不変）。
    // 2026-09-24 周31 便 M10d: 旧sha256の同じ11行窓は全走査で14924-14934に唯一一致。
    // 2026-09-27 周33 便 S3C5（D-06）: calcEvidenceUnit・calcFinalizeUnit の前方差分でずれた。旧sha256の同じ11行窓は全走査で15359-15369に唯一一致（中身は不変）。
    // 2026-09-27 便 C30F1c: GM 前方（開始関門の shield 幅・遅れた開始の印）で +49 行。旧 sha256 の唯一一致を全走査で確認（中身不変）。
    // 2026-09-27 統合（contract-review-2026-09 × stage4-review の merge）: 上の S3C5 と C30F1c の両方の前方差分を合わせた GM で、旧 sha256 の同じ行数の窓を全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-09-27 周33 便 S3C8（D-09）: calcFetchGroupData の取得の失敗を救済より前に throw する直しとコメントで GM 前方 +7 行。旧sha256の同じ11行窓は全走査で15462-15472に唯一一致（中身は不変）。
    // 2026-09-27 便 C32F1（C32-A-14）: GM 前方（extendGraceOnChain の already_sufficient に名簿つき開始の印・関門の roster_pipeline_late の出口）で +27 行。旧 sha256 の同じ行数の窓を全走査し唯一一致を確認（中身不変）。
    // 2026-09-27 便 C32F2（C32-B-01）: GM 前方（上の +73 行＋自動延長の注記・shieldRosterStartWindow の終端）で +76 行。旧 sha256 の同じ行数の窓を全走査し唯一一致を確認（中身不変）。
    // 2026-09-28 Stage 3 再レビュー周1 段0（C32 の合流・contract-review-2026-09-r2 281d06dd を main へ）: 上の S3C8／S3C13（main 側）と C32F1／C32F2（契約側）の両方の前方差分を合わせた GM で、同じ行数の窓を全走査し、sha256 の唯一一致の位置へ付け直した（中身は不変・sha256 は S3C13 の後の値）。
    // 2026-11-06 便 WR-E2E-S15-PROVERFIX（/zkp-successor の口と後継の追跡・attach）: GM 前方で +120 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP・GMGROUP-FIX1（組分けの shard の書き込みの一時的な失敗の再開・警報・待ち・印）: GM 前方で +75 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP-FIX2（開始関門の待ちの終わりの道・警報の印の原因と配送の結果）: GM 前方で +57 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 便 WR-PRE-PRESENCE（presence の時間回復・合図の配信・ADMINGAS の同期）: 前方で +25 行。旧 sha256 の同じ行数の窓を全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 WR-PRE-ADMINGAS-FIX1: 同長窓を全走査し唯一一致を再確認。本文・sha256・行位置は不変。
    startLine: 18338, endLine: 18348,
    sha256: '46451a5b65b4a77861508ec844322cf4e47a0edd66776dc16b604841cf7a38ae',
    mirrorFile: 'src/stages/grouping.js',
    mirrorSignature: 'function countGroupsByLang(groups) {',
    mirrorSha256: '5fedf0570fdb7550d910ea28e9347a77feba10b6e63cbfd58c8c569e2f68f9f3',
  },
  {
    name: 'src/stages/grouping.js getGroupSizeDistribution',
    source: 'workers/game_workers/game-master-DO.js',
    // 2026-08-23: Round12 FIX_3 の前方差分+105行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-23: Round12 FIX_4 の同じ前方差分+49行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-23: Round12 FIX_8 の同じ前方差分+59行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-24: Round13 A3 α1〜α3 の前方差分+526行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-25: R14 F3 の同じ前方差分 +6 行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-25: R14 F15 同期時点（F9/F11/F12 等）の前方差分 +66 行。旧sha256の唯一一致を全走査で確認。
    // 2026-08-26: C17 の正典前方差分 +159 行。7行窓の全走査で旧sha256の唯一一致
    // （11277-11283）を確認し、members.length 別の分布加算を再レビューした。

    // 2026-08-26: 便W10（R15-40/50/30/26/10＋ガス3日自動force）で前方が増えた。
    //   同じ行数の窓を全走査し、旧sha256の唯一一致を確認（中身は byte 一致）。

    // 2026-08-26: origin/main（本番配備系統）との統合で前方が増えた。
    //   同じ行数の窓を全走査し、旧sha256の唯一一致を確認（中身は byte 一致）。
    // 2026-08-31: Step 2 A1（主要言語優先）で前方が +3 行。
    // 7行窓の全走査で旧sha256の唯一一致を確認（中身は byte 一致）。
    // 2026-08-31: Step 2 commit 2（lang の UTF-16 well-formedness 検査）が前方へ +24 行。
    // 7行窓の全走査で旧sha256の唯一一致を確認（中身は byte 一致）。
    // 2026-08-31: S3-A の entry-worker 同期先コメント追加で前方が +1 行。
    // 2026-09-04: main（改名監査の修正一式）取り込みで前方が +14 行。
    //   同じ行数の窓を全走査して旧 sha256 の唯一一致を確認（中身 byte 一致・sha256 据え置き）。
    // 2026-09-04（周11 R11-C01/A-1）: 正典に lang の文字集合検査が入り前方が +41 行。
    //   同じ行数の窓を全走査して旧 sha256 の唯一一致を確認（中身 byte 一致・sha256 据え置き）。
    // 2026-09-04（周11 P1）: Stage 3 集約の自動発注配線で前方が +121 行。
    //   同じ行数の窓を全走査して旧 sha256 の唯一一致を確認（中身 byte 一致・sha256 据え置き）。
    // 2026-09-06 周14 T2: 同じ前方差分+33行。7行窓の旧sha256は唯一一致。
    // 2026-09-06 周14 T5: calc-status の cursor 入力追加で前方が+9行。同じ窓はbyte不変。
    // 2026-09-07 周15 T4: 同じ前方差分+46行。旧sha256の唯一一致を確認。
    // 2026-09-08 周15 T7: 同じ前方差分 -1 行。旧sha256の唯一一致を確認。
    // 2026-09-08 周16 S0: 統合後の旧7行窓は12462-12468に唯一一致。
    // 2026-09-14 M1: getGroupSizeDistribution 7行を最終正典で再確定。
    // 2026-09-15 M1b: 依存待ちshield追加による前方+42行。窓本体はbyte不変。
    // 2026-09-16 周25 T2b: G8 の前方差分+32行。7行窓の旧sha256は唯一一致。
    // 2026-09-16 周25 Q7: 預託適格規則の前方差分+6行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q11: 依存待ちgraceの必要量化で前方+21行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q11b: 6時間刻み化による前方+4行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q23: 同じ前方差分+111行。旧sha256は唯一一致。
    // 2026-09-16 周25 Q25: 同じ前方差分+49行。旧7行窓は新位置で唯一一致。
    // 2026-09-17 周25 Q39: Q11bの6時間切り上げ4行を外し、旧sha256は新位置で唯一一致。
    // 2026-09-18 周26 R4: GM前方差分+49行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1: 同じ前方差分+36行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1b: 同じ前方差分+33行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1c: 同上+227行。旧7行窓は新位置で唯一一致。
    // 2026-09-18 周26 T1d: 同じ前方差分+146行。旧sha256は唯一一致。
    // 2026-09-18 周26 T1e: 同じ前方差分+104行。旧sha256は唯一一致。
    // 2026-09-19 周26 T1f: 前方修正+50行。旧sha256の唯一一致を確認。
    // 2026-09-22 周29 便 PV: 同じ追加＋`resolvePrevRegistrationIndexForProof` で前方 +152 行。窓の全走査で旧sha256の唯一一致を確認（中身は不変）。
    // 2026-09-22 周29 便 Z7: 同じ前方+20行。旧sha256は唯一一致。
    // 2026-09-24 周31 便 M8: 名簿の開始関門・共有規則の取込（ユーザー決定 R31-U-A・U-B）で前方がずれた。同じ行数の窓を全走査し旧sha256の唯一一致を確認（中身は不変）。
    // 2026-09-24 周31 便 M10d: 旧sha256の同じ7行窓は全走査で14938-14944に唯一一致。
    // 2026-09-27 周33 便 S3C5（D-06）: calcEvidenceUnit・calcFinalizeUnit の前方差分でずれた。旧sha256の同じ7行窓は全走査で15373-15379に唯一一致（中身は不変）。
    // 2026-09-27 便 C30F1c: GM 前方（開始関門の shield 幅・遅れた開始の印）で +49 行。旧 sha256 の唯一一致を全走査で確認（中身不変）。
    // 2026-09-27 統合（contract-review-2026-09 × stage4-review の merge）: 上の S3C5 と C30F1c の両方の前方差分を合わせた GM で、旧 sha256 の同じ行数の窓を全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-09-27 周33 便 S3C8（D-09）: calcFetchGroupData の取得の失敗を救済より前に throw する直しとコメントで GM 前方 +7 行。旧sha256の同じ7行窓は全走査で15476-15482に唯一一致（中身は不変）。
    // 2026-09-27 便 C32F1（C32-A-14）: GM 前方（extendGraceOnChain の already_sufficient に名簿つき開始の印・関門の roster_pipeline_late の出口）で +27 行。旧 sha256 の同じ行数の窓を全走査し唯一一致を確認（中身不変）。
    // 2026-09-27 便 C32F2（C32-B-01）: GM 前方（上の +73 行＋自動延長の注記・shieldRosterStartWindow の終端）で +76 行。旧 sha256 の同じ行数の窓を全走査し唯一一致を確認（中身不変）。
    // 2026-09-28 Stage 3 再レビュー周1 段0（C32 の合流・contract-review-2026-09-r2 281d06dd を main へ）: 上の S3C8／S3C13（main 側）と C32F1／C32F2（契約側）の両方の前方差分を合わせた GM で、同じ行数の窓を全走査し、sha256 の唯一一致の位置へ付け直した（中身は不変・sha256 は S3C13 の後の値）。
    // 2026-11-06 便 WR-E2E-S15-PROVERFIX（/zkp-successor の口と後継の追跡・attach）: GM 前方で +120 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP・GMGROUP-FIX1（組分けの shard の書き込みの一時的な失敗の再開・警報・待ち・印）: GM 前方で +75 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-07 便 WR-E2E-S2-GMGROUP-FIX2（開始関門の待ちの終わりの道・警報の印の原因と配送の結果）: GM 前方で +57 行。旧 sha256 の同じ行数の窓を新しい GM で全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 便 WR-PRE-PRESENCE（presence の時間回復・合図の配信・ADMINGAS の同期）: 前方で +25 行。旧 sha256 の同じ行数の窓を全走査し唯一一致の位置へ付け直した（中身は不変）。
    // 2026-11-15 WR-PRE-ADMINGAS-FIX1: 同長窓を全走査し唯一一致を再確認。本文・sha256・行位置は不変。
    startLine: 18352, endLine: 18358,
    sha256: 'bb24b57c75500851c6d8751c2bb8b649a6f256e1cc1a3d92913c1f78aa39a8be',
    mirrorFile: 'src/stages/grouping.js',
    mirrorSignature: 'function getGroupSizeDistribution(groups) {',
    mirrorSha256: '634613c9ea1e8d4c1b2b819ad94dba67fc49c4ed9c911807d53a2ebefc9b741e',
  },
  {
    // D2-03（周17）: chain fixtureの提出組立は本番クライアントの回帰証拠ではないが、
    // 「同じ構築」と名乗る以上、上限適用・snapshot正規化・receipt集約・sanitize再署名を
    // 追随させる。test/も宣言走査へ含め、正典側／fixture側どちらの変更も再レビュー要求にする。
    name: 'test/players.mjs buildSubmissionPayload',
    declarationText: 'MIRROR: src/components/game/SubmissionPhase.js の cappedMessages から compact payload までの提出構築',
    source: 'src/components/game/SubmissionPhase.js',
    // P2b-2a-2: 公式の区切り判定時刻と記憶、T9 注記を反映。players.mjs の本体は据え置き。
    // S3R5 便 LOCK（2b479a6af）: 正典の確定段を再レビュー。試験束は priorityLock を渡さず本体は不変。
    // S3R5 便 DISP5（09b088876）: 窓の中は自己検証の失敗の文言（i18n の既定文）だけが変わった。試験束は文言を写さず本体は不変。
    // S3R6 便 SUBMITVIEW・SUBMITVIEW2・SUBMITVIEW3・SV4: 正典の切り出しと控えの窓を再レビュー。試験束の本体は不変。
    // S3R8 便 R8-POSTSEND（00de73aca）: 正典の窓の前に送信の直後の記録の配線が入り +15 行。窓の中身は byte 不変（同じ長さ738行の全走査で旧 sha256 617175bb… が 580-1317 に唯一一致・便の報告書と Astra の通す側の反証で確かめた）。
    // S3R8 第2波: 便 R8-SVA8（5586ea8be）で窓の前が +9 行、便 R8-MSGKEY（7ddb086dc）で窓の中の cappedMessages の memo が発言の鍵の getter（頁の寿命の使い回し・性能だけ）を使うようになった。鍵の値と提出の集合・並び・バイト列は不変（便の反証で起点と一致を確かめた）＝写し先の本体は据え置き、行と sha だけ取り直した。
    // 2026-11-15 UI_IMPROVEMENTS_S3（版 2〜版 6 の提出画面の直し）: 窓より前の行が増えて、窓の位置が 589-1326 から
    // 731-1468 へ移った（+142 行）。窓の中身は byte 不変（同じ長さ738行・sha256 cee4b6c9… のまま。chatgame-tools の
    // 同じ窓の検査と docs/ui-improvements-s3/impl/ui-s3-mirror-windows.py も同じ値）。players.mjs の本体は不変。
    // 2026-11-19（ユーザーの指示・0ae797985 と反証 D-2）: 窓の前に state 2つ（4行）と再提出の確認の文の差し替え・
    // 準備中の印の try/finally が入り、窓の中の handleSubmit に prepareOnly（署名・保存だけでWSへ送らない・isSubmitting を
    // 立てない）と送る直前の setServerSendTried(true) が入った。窓を 742-1485（744行）へ取り直した。旧窓との差は
    // この6行の追加と1行の置き換えだけで、提出物の組立・バイト列は不変（players.mjs は送信も画面の state も写さない）＝本体は不変。
    startLine: 742,
    endLine: 1485,
    // T1j で players.mjs に出どころ門と chatCloseAt 引数を追加した。
    // T1l 時点の呼び出し元は chatCloseAt を渡さず、この MIRROR は配線の固定である。
    // 公式の提出構築の窓は cappedMessages から compact payload までを覆う。
    // 2026-10-01 S3FIX 便 B1（e4b16e05）: handleSubmit の自己集約に確定した窓を渡す1行を正典と写し先の両方に足した（統括が同じ意味であることを確認）。窓の終わり 1029→1030・sha256 と写し先の本体の sha256 を更新。
    // P2b-1a: 正典の handleSubmit は隠す集合を計画へ渡す。players.mjs は欄を組まない試験の束で MIRROR-BODY は不変。
    // S3R5 便 SELF（3ca690bc5）: 正典は密告根拠の票と証明を優先する。試験束は根拠を持たず、空の根拠では旧値を返すため MIRROR-BODY は不変。
    // RS-0: cappedMessages gets an optional claim memo; payload bytes and the
    // players mirror body are unchanged. The window also moved six lines.
    // S3R6 便 SV5（d24034360）: 窓内は控えに残す窓の条件の1行だけ。試験束は控えを持たず本体は不変。窓の前の行のずれは SV5 と SV6（e16b31382）。
    sha256: '8d3bdc1d69f10f9548716084bf6262102d0b59182150c590081935e85ad8496b',
    mirrorFile: 'test/players.mjs',
    mirrorSignature: 'export async function buildSubmissionPayload(player, {',
    mirrorSha256: 'fb4a2f84c3af2c94505b406540314e6e8e85c5321e672d4e135cce838c89718a',
  },
];

const sha256 = (bufOrStr) => createHash('sha256').update(bufOrStr).digest('hex');

function mirrorDeclarationKey(file, text) {
  return `${file}\u0000${text.replace(/^\/\/\s*/, '').trim()}`;
}

function collectMirrorDeclarations(dir, prefix = 'src') {
  const found = [];
  const walk = (current, rel) => {
    for (const name of readdirSync(current).sort()) {
      const absolute = join(current, name);
      const childRel = `${rel}/${name}`;
      if (statSync(absolute).isDirectory()) {
        walk(absolute, childRel);
        continue;
      }
      if (!/\.m?js$/.test(name)) continue;
      readFileSync(absolute, 'utf8').split('\n').forEach((line, index) => {
        if (/^\/\/\s*MIRROR:/.test(line.trim())) {
          found.push({ file: childRel, line: index + 1, text: line.trim() });
        }
      });
    }
  };
  walk(dir, prefix);
  return found;
}

let failed = 0;
const ok = (msg) => console.log(`  OK   ${msg}`);
const ng = (msg) => { failed++; console.error(`  FAIL ${msg}`); };

// 🔴 F-7(b)（2026-08-08・ラウンド20 判断不要-7）: **fail-open（exit 0）をやめる。**
//
//   旧実装は正典が読めなければ「skip」として **exit 0** で終わっていた。
//   実測: standalone コピーで `MAX_DEPOSIT_WEI` を 10 ETH → 1000 ETH に改変しても
//   `monorepo sources not found — skipping` と出て **exit 0**（1バイトも照合していない）。
//   しかもメッセージは「In standalone mode, VENDOR_SYNC.md sha256 values are the source of truth」
//   と書いているのに、**その実装が存在しない**。
//
//   ⚠️ **これは第三者検証の保証ではない**（台帳照合を実装しても対運営の保証は増えない＝自己参照ガード。
//     実測: 台帳照合を足しても `VENDOR_SYNC.md` の64桁を1行書き換えるだけで exit 0 に戻る）。
//     ここで直すのは**運用衛生**＝「照合できていないのに緑を出す」ことをやめる、それだけ。
//     コピーの真正性が要るなら `HashStorage.buildHashes` への登録（別項目）が必要。
if (!existsSync(resolve(repoRoot, 'workers/game_workers/game-master-DO.js'))) {
  console.error('check-vendor-sync: monorepo sources not found — CANNOT VERIFY here (standalone checkout).');
  console.error('  This script compares vendor/ against the canonical sources in the monorepo.');
  console.error('  Outside the monorepo there is nothing to compare against, so it exits 1 instead of');
  console.error('  reporting a green it did not earn. Run it from a monorepo checkout.');
  console.error('  NOTE: VENDOR_SYNC.md is a drift ledger, not a proof of authenticity — anyone who can');
  console.error('        edit vendor/ can edit the ledger in the same commit.');
  process.exit(1);
}

console.log('check-vendor-sync: comparing vendor/ against monorepo canon');

const sourceCache = new Map();
function pinSource(file) {
  if (!sourceCache.has(file)) sourceCache.set(file, readFileSync(resolve(repoRoot, file), 'utf8'));
  return sourceCache.get(file);
}

function resolveNumericConst(file, name, stack = []) {
  if (stack.includes(name)) throw new Error(`${file}: const cycle ${[...stack, name].join(' -> ')}`);
  const source = pinSource(file);
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const expression = source.match(new RegExp(`^(?:export\\s+)?const\\s+${escaped}\\s*=\\s*([^;]+);`, 'm'))?.[1];
  if (!expression) throw new Error(`${file}: const ${name} not found`);
  let arithmetic = expression.replace(/\b\d[\d_]*\b/g, (value) => String(value).replaceAll('_', ''));
  const identifiers = [...new Set(arithmetic.match(/\b[A-Za-z_$][\w$]*\b/g) || [])];
  for (const identifier of identifiers) {
    const value = resolveNumericConst(file, identifier, [...stack, name]);
    arithmetic = arithmetic.replace(new RegExp(`\\b${identifier}\\b`, 'g'), String(value));
  }
  if (!/^[\d+\-*/%()\s.]+$/.test(arithmetic)) throw new Error(`${file}:${name}: unsafe expression ${expression}`);
  const value = Function(`"use strict"; return (${arithmetic});`)();
  if (!Number.isFinite(value)) throw new Error(`${file}:${name}: non-finite value`);
  return value;
}

function resolvePinSource(binding) {
  if (binding.key == null) return resolveNumericConst(binding.file, binding.name);
  const source = pinSource(binding.file);
  const escaped = binding.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const body = source.match(new RegExp(
    `^(?:export\\s+)?const\\s+${escaped}\\s*=\\s*Object\\.freeze\\(\\{([\\s\\S]*?)\\}\\);`, 'm',
  ))?.[1];
  if (!body) throw new Error(`${binding.file}: object ${binding.name} not found`);
  const key = binding.key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const raw = body.match(new RegExp(`^\\s*${key}\\s*:\\s*([0-9_]+)\\s*,?`, 'm'))?.[1];
  if (!raw) throw new Error(`${binding.file}:${binding.name}.${binding.key} not found`);
  return Number(String(raw).replaceAll('_', ''));
}

function numericPinEntries(value, prefix = []) {
  const out = [];
  for (const [key, child] of Object.entries(value || {})) {
    const path = [...prefix, key];
    if (typeof child === 'number') out.push([path.join('.'), child]);
    else if (child && typeof child === 'object' && !Array.isArray(child)) {
      out.push(...numericPinEntries(child, path));
    }
  }
  return out;
}

// --- PIN: block-verifierの全数値pinを正典定数へ機械束縛 ---
{
  const numericPins = numericPinEntries(DEFAULTS.pins);
  const actualPaths = new Set(numericPins.map(([path]) => path));
  const ledgerPaths = [...Object.keys(PIN_BINDINGS), ...Object.keys(PIN_OMISSIONS)];
  const duplicatePaths = ledgerPaths.filter((path, index) => ledgerPaths.indexOf(path) !== index);
  const missing = [...actualPaths].filter((path) => !ledgerPaths.includes(path));
  const ghosts = ledgerPaths.filter((path) => !actualPaths.has(path));
  if (duplicatePaths.length || missing.length || ghosts.length) {
    ng(`PIN-LEDGER numeric pins ⇔ bindings/omissions mismatch (duplicate=${duplicatePaths.join(',') || '-'} missing=${missing.join(',') || '-'} ghost=${ghosts.join(',') || '-'})`);
  } else {
    ok(`PIN-LEDGER 数値pin ${numericPins.length}件を双方向照合`);
  }
  for (const [path, reason] of Object.entries(PIN_OMISSIONS)) {
    if (typeof reason !== 'string' || reason.trim().length < 20) ng(`PIN-OMISSION ${path} — reason missing`);
    else ok(`PIN-OMISSION ${path} — ${reason}`);
  }
  for (const [path, expected] of numericPins) {
    const bindings = PIN_BINDINGS[path];
    if (!bindings) continue;
    const mismatches = [];
    for (const binding of bindings) {
      try {
        const actual = resolvePinSource(binding);
        if (!Object.is(actual, expected)) mismatches.push(`${binding.file}:${binding.name}${binding.key ? `.${binding.key}` : ''}=${actual}`);
      } catch (error) {
        mismatches.push(error.message);
      }
    }
    if (mismatches.length) ng(`PIN ${path}=${expected} — ${mismatches.join('; ')}`);
    else ok(`PIN ${path}=${expected} ⇔ ${bindings.map((binding) => `${binding.file}:${binding.name}${binding.key ? `.${binding.key}` : ''}`).join(' + ')}`);
  }
  const headerSource = pinSource('workers/game_workers/lib/roster-canonical.js');
  const headerFork = headerSource.match(/^export const ETH_HEADER_FORK = '([^']+)';$/m)?.[1];
  if (headerFork !== DEFAULTS.pins.ethereumHeaderFork) {
    ng(`PIN ethereumHeaderFork=${DEFAULTS.pins.ethereumHeaderFork} — writer=${headerFork}`);
  } else {
    ok(`PIN ethereumHeaderFork=${headerFork} ⇔ roster writer`);
  }
  const protocol = pinSource('workers/game_workers/lib/protocol-v2.js');
  if (!/receiptMaxActionsPerPair\s*=\s*\(groupSize\)\s*=>\s*\n?\s*RECEIPT_MAX_ACTIONS_PER_PAIR_BASE\s*\*\s*Math\.max\(1, groupSize\)/.test(protocol)) {
    ng('PIN-DERIVATION receiptMaxActionsPerPair が BASE * max(1, groupSize) から外れた');
  } else ok('PIN-DERIVATION receiptMaxActionsPerPair は基準pinから導出');
  if (!/receiptMaxRefsPerReceipt\s*=\s*\(maxMessages\)\s*=>\s*maxMessages/.test(protocol)) {
    ng('PIN-DERIVATION receiptMaxRefsPerReceipt が maxMessages の恒等写像から外れた');
  } else ok('PIN-DERIVATION receiptMaxRefsPerReceipt は maxMessages pinから導出');
}

// --- COPY: バイト一致 ---
// vendor/ に台帳外のファイルがあると、照合されない古い実装を誤って参照できてしまう。
{
  const listed = new Set([...COPIES.map(([vendor]) => vendor), EXTRACT.vendor]);
  const walk = (dir) => readdirSync(resolve(toolRoot, dir), { withFileTypes: true })
    .filter((entry) => entry.name !== '.DS_Store' && !entry.name.startsWith('._'))
    .flatMap((entry) => {
      const path = `${dir}/${entry.name}`;
      return entry.isDirectory() ? walk(path) : [path];
    });
  const actual = walk('vendor');
  for (const path of actual) if (!listed.has(path)) ng(`VENDOR-INVENTORY ${path} — 台帳外ファイル`);
  for (const path of listed) if (!actual.includes(path)) ng(`VENDOR-INVENTORY ${path} — 台帳にだけ存在`);
  if (actual.length === listed.size && actual.every((path) => listed.has(path))) {
    ok(`VENDOR-INVENTORY ${actual.length} files listed`);
  }
}
for (const [v, s] of COPIES) {
  const vp = resolve(toolRoot, v);
  const sp = resolve(repoRoot, s);
  if (!existsSync(vp)) { ng(`${v} — vendor file missing`); continue; }
  if (!existsSync(sp)) { ng(`${v} — canonical source ${s} missing`); continue; }
  const vb = readFileSync(vp);
  const sb = readFileSync(sp);
  if (vb.equals(sb)) ok(`COPY    ${v}`);
  else ng(`COPY    ${v} — bytes differ from ${s} (vendor sha256=${sha256(vb)}, source sha256=${sha256(sb)})`);
}

let extractRangeActual = null;

// --- EXTRACT: 本体一致 ---
{
  const vp = resolve(toolRoot, EXTRACT.vendor);
  const sp = resolve(repoRoot, EXTRACT.source);
  if (!existsSync(vp)) {
    ng(`${EXTRACT.vendor} — vendor file missing`);
  } else {
    const srcLines = readFileSync(sp, 'utf8').split('\n');
    // 正典からメソッド本体を特定（シグネチャ行〜メソッド閉じ括弧 `  }` の間）
    // 🔴 F-7(b)（2026-08-08・ラウンド20 判断不要-7）: `findIndex` は**最初の1件**しか見ないので、
    //    `lottery-DO.js` に同名メソッドを**後置**すると（JS は後勝ちで後者が実行される）
    //    実行される実装が別物でも緑になった。実測: 後置した `selectWinners` が
    //    `(seed,10,4)` に対して `[2,3,7,8]` → `[0,1,2,3]` を返すのに `OK EXTRACT`。
    //    → 一致件数を数えて **2件以上は FAIL**。
    const sigHits = [];
    srcLines.forEach((l, i) => { if (l === EXTRACT.signature) sigHits.push(i + 1); });
    const sigIdx = sigHits.length > 0 ? sigHits[0] - 1 : -1;
    if (sigHits.length > 1) {
      ng(`EXTRACT ${EXTRACT.vendor} — signature line appears ${sigHits.length} times in ${EXTRACT.source} `
        + `(lines ${sigHits.join(', ')}); JS keeps the LAST definition, so the extracted body may not be the one that runs`);
    }
    if (sigIdx === -1) {
      ng(`EXTRACT ${EXTRACT.vendor} — signature line not found in ${EXTRACT.source} (method renamed/moved?)`);
    } else {
      let closeIdx = -1;
      for (let i = sigIdx + 1; i < srcLines.length; i++) {
        if (srcLines[i] === EXTRACT.closing) { closeIdx = i; break; }
      }
      if (closeIdx === -1) {
        ng(`EXTRACT ${EXTRACT.vendor} — closing brace not found in ${EXTRACT.source}`);
      } else {
        const canonicalBody = srcLines.slice(sigIdx + 1, closeIdx).join('\n');
        const vLines = readFileSync(vp, 'utf8').split('\n');
        const b = vLines.findIndex((l) => l.startsWith(EXTRACT.beginMarker));
        const e = vLines.findIndex((l) => l.startsWith(EXTRACT.endMarker));
        if (b === -1 || e === -1 || e <= b) {
          ng(`EXTRACT ${EXTRACT.vendor} — verbatim body markers missing/malformed`);
        } else {
          const vendorBody = vLines.slice(b + 1, e).join('\n');
          if (vendorBody === canonicalBody) {
            ok(`EXTRACT ${EXTRACT.vendor} (body = ${EXTRACT.source} lines ${sigIdx + 2}-${closeIdx})`);
            // 台帳に書いてある行範囲も一致させる（本体は動的に探すので検査自体は正しいが、
            // 人が読む注記だけが静かに古びる。2026-07-31 に実際に 779-863 のまま残っていた）
            extractRangeActual = { full: `${sigIdx + 1}-${closeIdx + 1}`, body: `${sigIdx + 2}-${closeIdx}` };
          } else {
            ng(`EXTRACT ${EXTRACT.vendor} — body differs from ${EXTRACT.source} lines ${sigIdx + 2}-${closeIdx}`);
          }
        }
      }
    }
  }
}

// --- MIRROR: 正典行範囲の sha256 が台帳値のまま ---
{
  const declared = [
    ...collectMirrorDeclarations(resolve(toolRoot, 'src')),
    ...collectMirrorDeclarations(resolve(toolRoot, 'test'), 'test'),
  ];
  const registered = MIRRORS.filter(({ declarationText }) => declarationText)
    .map(({ mirrorFile, declarationText }) => ({
      file: mirrorFile,
      text: declarationText,
      key: mirrorDeclarationKey(mirrorFile, declarationText),
    }));
  const declaredKeys = new Set(declared.map(({ file, text }) => mirrorDeclarationKey(file, text)));
  const registeredKeys = new Set(registered.map(({ key }) => key));
  if (declared.length !== declaredKeys.size) {
    ng(`MIRROR-DECL 同じ宣言が重複している (宣言=${declared.length} unique=${declaredKeys.size})`);
  }
  if (registered.length !== registeredKeys.size) {
    ng(`MIRROR-DECL 同じ登録が重複している (登録=${registered.length} unique=${registeredKeys.size})`);
  }
  for (const declaration of declared) {
    const key = mirrorDeclarationKey(declaration.file, declaration.text);
    if (!registeredKeys.has(key)) {
      ng(`MIRROR-DECL ${declaration.file}:${declaration.line} が MIRRORS 台帳に未登録: ${declaration.text}`);
    }
  }
  for (const registration of registered) {
    if (!declaredKeys.has(registration.key)) {
      ng(`MIRROR-DECL 台帳にだけ存在: ${registration.file} ${registration.text}`);
    }
  }
  if (declared.length === registered.length && declaredKeys.size === registeredKeys.size
      && declared.every(({ file, text }) => registeredKeys.has(mirrorDeclarationKey(file, text)))) {
    ok(`MIRROR-DECL 宣言 ${declared.length}件 / 登録 ${registered.length}件`);
  }
}

for (const m of MIRRORS) {
  const sp = resolve(repoRoot, m.source);
  const lines = readFileSync(sp, 'utf8').split('\n');
  const seg = lines.slice(m.startLine - 1, m.endLine).join('\n');
  const h = sha256(seg);
  if (h === m.sha256) {
    ok(`MIRROR  ${m.name} (source ${m.source}:${m.startLine}-${m.endLine} unchanged)`);
  } else {
    ng(`MIRROR  ${m.name} — ${m.source}:${m.startLine}-${m.endLine} changed (sha256=${h}); re-review the mirror and update VENDOR_SYNC.md + this script`);
  }

  // F-7(b)-3: ミラー**側**の関数本体も固定する（片方向だけだと 50/50 → 90/10 が緑で通る）
  if (m.mirrorFile && m.mirrorSha256) {
    const mp = resolve(toolRoot, m.mirrorFile);
    if (!existsSync(mp)) { ng(`MIRROR  ${m.name} — mirror file ${m.mirrorFile} missing`); continue; }
    const mlines = readFileSync(mp, 'utf8').split('\n');
    const hits = [];
    mlines.forEach((l, i) => { if (l === m.mirrorSignature) hits.push(i + 1); });
    if (hits.length !== 1) {
      ng(`MIRROR  ${m.name} — mirror signature found ${hits.length} time(s) in ${m.mirrorFile} (expected exactly 1)`);
      continue;
    }
    const start = hits[0] - 1;
    let end = -1;
    for (let i = start + 1; i < mlines.length; i++) { if (mlines[i] === '}') { end = i; break; } }
    if (end === -1) { ng(`MIRROR  ${m.name} — mirror function body is not closed in ${m.mirrorFile}`); continue; }
    const mh = sha256(mlines.slice(start, end + 1).join('\n'));
    if (mh === m.mirrorSha256) {
      ok(`MIRROR  ${m.name} (mirror body ${m.mirrorFile}:${start + 1}-${end + 1} unchanged)`);
    } else {
      ng(`MIRROR  ${m.name} — mirror body in ${m.mirrorFile}:${start + 1}-${end + 1} changed (sha256=${mh}); `
        + 're-review it against the canon and update VENDOR_SYNC.md + this script');
    }
  }
}

// --- LEDGER: VENDOR_SYNC.md に書いてある sha256 が正典と一致しているか ---
//
// 2026-07-31 追加。**これが無かったせいで台帳が静かに古びていた**（発見時 7/11 行がズレ）。
// COPY 検査は vendor と正典を直接比べるだけなので、両方を更新すれば通ってしまい、
// VENDOR_SYNC.md に書いた sha256 が古いままでも誰も気づかない。
//
// ところがこのツールを**モノレポ外へ配って単体で使う**とき（＝第三者検証という本来の用途）、
// 正典が手元に無いので照合の基準は **VENDOR_SYNC.md の sha256 だけ**になる（上の skip メッセージ参照）。
// つまり古い台帳は「第三者が正しいコピーを不正と判定する／古いコピーを正しいと判定する」に直結する。
// 台帳は飾りではなく検証の土台なので、機械で固定する。
{
  const mdPath = resolve(toolRoot, 'VENDOR_SYNC.md');
  if (!existsSync(mdPath)) {
    ng('LEDGER  VENDOR_SYNC.md not found');
  } else {
    const md = readFileSync(mdPath, 'utf8');
    // | `vendor相対` | `正典相対` | `sha256` | COPY |
    const rowRe = /^\|\s*`([^`]+)`\s*\|\s*`([^`]+)`\s*\|\s*`([0-9a-f]{64})`\s*\|\s*(COPY|MIRROR|EXTRACT)\s*\|/gm;
    const recorded = new Map();
    let m;
    while ((m = rowRe.exec(md)) !== null) {
      const [, , srcRel, sha, kind] = m;
      if (kind === 'COPY') recorded.set(srcRel, sha);
    }
    // 台帳に載っていない COPY があれば、それも「静かに古びる」入口なので失敗にする
    let ledgerBad = 0;
    for (const [, s] of COPIES) {
      const rec = recorded.get(s);
      if (!rec) { ng(`LEDGER  ${s} — VENDOR_SYNC.md に COPY 行が無い（台帳に追加すること）`); ledgerBad++; continue; }
      const sp = resolve(repoRoot, s);
      if (!existsSync(sp)) continue; // COPY 検査側で既に報告済み
      const actual = sha256(readFileSync(sp));
      if (actual !== rec) {
        ng(`LEDGER  ${s} — VENDOR_SYNC.md の sha256 が古い（recorded=${rec} actual=${actual}）`);
        ledgerBad++;
      }
    }
    // EXTRACT 行の行範囲注記も台帳と突き合わせる
    if (extractRangeActual) {
      const want = `${EXTRACT.source}:${extractRangeActual.full}`;
      if (!md.includes(want)) {
        ng(`LEDGER  EXTRACT 行範囲の注記が古い（VENDOR_SYNC.md を \`${want}\`（本体=${extractRangeActual.body}）に更新すること）`);
        ledgerBad++;
      }
    }
    if (ledgerBad === 0) ok(`LEDGER  VENDOR_SYNC.md sha256 (${COPIES.length} COPY rows) + EXTRACT range up to date`);

    // --- LEDGER(MIRROR): このスクリプトの MIRRORS と VENDOR_SYNC.md の MIRROR 行を突き合わせる ---
    //
    // 🔴 2026-08-09（ラウンド23）追加。**孤立した不変量の解消。**
    //   上の LEDGER 検査は `kind === 'COPY'` の行と EXTRACT の行範囲注記しか見ていなかったので、
    //   MIRROR 行（行範囲＋sha256）は**スクリプトとも正典とも突き合わされていなかった**。
    //   MIRROR の判定は「行範囲を切って sha256」なので、行範囲は sha256 と同格の台帳データであり、
    //   同じ台帳が2箇所（このスクリプトと VENDOR_SYNC.md）に在るのに照合者がいない状態だった。
    //   実際 `chatgame-tools` 側では同じ穴で2本とも食い違っていた（script 329-382 / MD 326-379）。
    //   さらに `mirrorSha256`（ミラー本体の pin）は MD に行が1つも無かった → `MIRROR-BODY` 行を新設。
    //
    //   ⚠️ 本検査が守るのは**2つの記録の一致**であって真正性ではない（冒頭の警告と同じ）。
    //     両方を同じコミットで書き換えれば通る。狙いは「片方だけ直して満足する」事故の遮断。
    const mirrorRowRe =
      /^\|\s*`([^`]+)`\s*\|\s*`([^`:]+):(\d+)-(\d+)`[^|]*\|\s*`([0-9a-f]{64})`\s*\|\s*MIRROR\s*\|/gm;
    const bodyRowRe =
      /^\|\s*`([^`]+)`\s*\|\s*`([^`]+)`[^|]*\|\s*`([0-9a-f]{64})`\s*\|\s*MIRROR-BODY\s*\|/gm;
    const mdMirrors = new Map();
    const mdBodies = new Map();
    let mr;
    while ((mr = mirrorRowRe.exec(md)) !== null) {
      const [, name, src, s0, s1, sha] = mr;
      mdMirrors.set(name, { source: src, startLine: Number(s0), endLine: Number(s1), sha256: sha });
    }
    while ((mr = bodyRowRe.exec(md)) !== null) {
      const [, name, file, sha] = mr;
      mdBodies.set(name, { mirrorFile: file, sha256: sha });
    }
    // 空振り防止: MD の MIRROR / MIRROR-BODY 行の総数とパースできた件数が一致すること。
    // （形が崩れてパースから漏れると、突き合わせが黙って素通りする）
    const mdMirrorRowCount = (md.match(/^\|.*\|\s*MIRROR\s*\|\s*$/gm) || []).length;
    const mdBodyRowCount = (md.match(/^\|.*\|\s*MIRROR-BODY\s*\|\s*$/gm) || []).length;
    let mirrorLedgerBad = 0;
    if (mdMirrorRowCount !== mdMirrors.size) {
      ng(`LEDGER  VENDOR_SYNC.md の MIRROR 行 ${mdMirrorRowCount} 本のうち ${mdMirrors.size} 本しかパースできない` +
         `（"source:開始-終了" の形になっていない行がある＝突き合わせが素通りする）`);
      mirrorLedgerBad++;
    }
    if (mdBodyRowCount !== mdBodies.size) {
      ng(`LEDGER  VENDOR_SYNC.md の MIRROR-BODY 行 ${mdBodyRowCount} 本のうち ${mdBodies.size} 本しかパースできない`);
      mirrorLedgerBad++;
    }
    const expectedBodies = new Set();
    for (const s of MIRRORS) {
      const rec = mdMirrors.get(s.name);
      if (!rec) {
        ng(`LEDGER  MIRROR ${s.name} — VENDOR_SYNC.md に MIRROR 行が無い（台帳に追加すること）`);
        mirrorLedgerBad++;
      } else {
        const want = `${s.source}:${s.startLine}-${s.endLine}`;
        const got = `${rec.source}:${rec.startLine}-${rec.endLine}`;
        if (want !== got) {
          ng(`LEDGER  MIRROR ${s.name} — 行範囲がスクリプトと VENDOR_SYNC.md で食い違う（script=${want} md=${got}）`);
          mirrorLedgerBad++;
        }
        if (s.sha256 != null && s.sha256 !== rec.sha256) {
          ng(`LEDGER  MIRROR ${s.name} — sha256 がスクリプトと VENDOR_SYNC.md で食い違う（script=${s.sha256} md=${rec.sha256}）`);
          mirrorLedgerBad++;
        }
      }
      // ミラー本体の pin（逆方向）も台帳に載っていること
      if (s.mirrorSha256 != null) {
        expectedBodies.add(s.name);
        const brec = mdBodies.get(s.name);
        if (!brec) {
          ng(`LEDGER  MIRROR-BODY ${s.name} — VENDOR_SYNC.md に MIRROR-BODY 行が無い（ミラー本体の pin が台帳に無い）`);
          mirrorLedgerBad++;
        } else {
          if (brec.mirrorFile !== s.mirrorFile) {
            ng(`LEDGER  MIRROR-BODY ${s.name} — ミラーファイルが食い違う（script=${s.mirrorFile} md=${brec.mirrorFile}）`);
            mirrorLedgerBad++;
          }
          if (brec.sha256 !== s.mirrorSha256) {
            ng(`LEDGER  MIRROR-BODY ${s.name} — sha256 が食い違う（script=${s.mirrorSha256} md=${brec.sha256}）`);
            mirrorLedgerBad++;
          }
        }
      }
    }
    // 逆方向: MD にだけ在る幽霊行（スクリプトから消したのに台帳に残っている）も赤にする。
    const scriptNames = new Set(MIRRORS.map((s) => s.name));
    for (const name of mdMirrors.keys()) {
      if (!scriptNames.has(name)) {
        ng(`LEDGER  MIRROR ${name} — VENDOR_SYNC.md にだけ在る（このスクリプトの MIRRORS に無い＝検査されていない）`);
        mirrorLedgerBad++;
      }
    }
    for (const name of mdBodies.keys()) {
      if (!expectedBodies.has(name)) {
        ng(`LEDGER  MIRROR-BODY ${name} — VENDOR_SYNC.md にだけ在る（対応する mirrorSha256 がスクリプトに無い）`);
        mirrorLedgerBad++;
      }
    }
    if (mirrorLedgerBad === 0) {
      ok(`LEDGER  VENDOR_SYNC.md ⇔ check-vendor-sync.mjs MIRROR 台帳 (${MIRRORS.length} rows + ${expectedBodies.size} body) 一致`);
    }
  }
}

if (failed > 0) {
  console.error(`check-vendor-sync: ${failed} check(s) FAILED`);
  process.exit(1);
}
console.log('check-vendor-sync: all checks passed');

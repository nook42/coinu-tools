// block-verifier Stage C: 採点・報酬・オンチェーン確定の検証（DESIGN.md §3 Stage C / CONTRACT stage-C）
//
// 正典（byte-exact 写像元・行番号は 2026-07-09 main HEAD）:
//   workers/game_workers/game-master-DO.js
//     :440-624   reconcileEvidence（マージ規則 :587-608）
//     :2246-2375 verifyDepositsOnChainForUids / verifySignedDepositsOnChain
//     :2377-2796 calculateAndStoreResults（採点→按分→summary→merkle→manifest）
//     :2463-2612 報酬按分＋50/50スプリット（本ファイル mirrorRewardSplit が忠実ミラー）
//     :2813-2907 publishVerificationManifest
//     :2987-3059 collectClaimEntriesFromSummary / buildMerkleTree（leaf式 :61-102）
//     :3214-3521 autoDistribute
//     :3777-3822 writeGroupsToD1（d1Groups 再構成の形状）
//     :3875-3955 buildBlockSummaryWithResults
//   workers/game_workers/chat-game-DO.js :356-428（get-results）/ :1781-1857（グループアーカイブ）
//   workers/game_workers/lib/evidence-reconciler.js（全体・vendored を直接実行）
//   workers/game_workers/lib/timeline-check.js（vendored を直接実行）
//   workers/listen_workers/src/index_new.js :464-510（summary.json の claimed 可変化 → 比較時に中立化）
//
// 旧形式の可変フィールド（公表後に書き換わる正当なフィールド）:
//   schema v1 summary.json: updatedAt / createdAt（生成時刻）、members[].claimed・depositor_results[].claimed
//   schema v1/v2 の group{G}.json / auto-results.json: gameResults[].claimed
// schema v3 は行別 claimed を manifest 外のグループ別overlayへ分離したため、上記ファイルは
// 全フィールド immutable。旧形式だけ比較前に中立化し、それ以外の差分は FAIL。

import { withVendorLogging } from '../vendor-logging.js';
import { ZKP_EXPECTED } from '../../vendor/workers/game_workers/lib/zkp-protocol.js';
import fs from 'node:fs/promises';
import path from 'node:path';
// G1（2026-07-18）: viem直接利用はproof個別検証の削除で不要になった（leaf/root計算は
// vendoredのgm.buildMerkleTreeに一本化）。
import { GameMasterDO } from '../../vendor/workers/game_workers/game-master-DO.js';
import { canonicalRosterMember, canonicalRosterText } from '../../vendor/workers/game_workers/lib/roster-canonical.js';
import {
  calculateGroupResults, getBlockRewardWei, calculateDepositPoints, parseDepositWei,
  // J-31（2026-08-08）: 自動配布経路の適格帯判定。正典と**同じ関数**を使う
  // （ベンダリング済みなので、ここで独自に帯を書き直してはならない＝byte-exact原則）。
  isIneligibleDepositWei
} from '../../vendor/workers/game_workers/lib/game-result-calculator.js';
import {
  RESULT_SUBMITTED_EVENT, verifyCompleteness, decodeEvidenceData, validateResultBundle,
  selectAdoptedResults, buildMembersIndex, estimateBlockRange
} from '../../vendor/workers/game_workers/lib/evidence-reconciler.js';
import { getLogsAdaptive } from '../../vendor/workers/game_workers/lib/getlogs-adaptive.js';
import {
  computeDeclaredTimesMs, compareDeclaredToChainWindows,
  TIMELINE_NO_GAME_CAUSES,
} from '../../vendor/workers/game_workers/lib/timeline-check.js';
import {
  claimEntriesFromClaimData, decodeClaimData, concatChunks,
  CLAIM_DATA_FORMAT, DEPOSITOR_LEAF_FORMAT, DEPOSITOR_ROUNDING, depositorShareOf,
} from '../../vendor/workers/game_workers/lib/claim-data-codec.js';
import { fetchClaimDataFromChain } from '../claim-data.js';
// P-2026-0822: 正典と**同一の**正準JSON検査（vendored）。正典が拒否する summary を
// 検証ツールが受理すると、今度は逆向きに「正典と第三者検証で答えが割れる」状態が作れる。
import { parseCanonicalJson } from '../../vendor/workers/game_workers/lib/canonical-json.js';
// Q-6: 名簿の blockAddress / pubKey を応募データから再構成するときの門番（正典と同じ実装）。
import {
  chatSignStringV2, isCanonicalSignature, parseBlockAddress,
} from '../../vendor/workers/game_workers/lib/protocol-v2.js';
import { decodeSubmissionPayloadString } from '../../vendor/workers/game_workers/lib/evidence-compact-v1.js';
import { evidenceSegmentArtifact } from '../../vendor/workers/game_workers/lib/evidence-segment-plan.js';
import { buildRosterMemberCommitment } from '../../vendor/workers/game_workers/lib/roster-member-root.js';
import { rosterAnchorKey, selectCanonicalRosterRegistration, evaluateRosterSubmissionEligibility,
  adoptedForRoster, applyRosterSubmissionGate } from '../../vendor/workers/game_workers/lib/roster-anchor-rule.js';
import {
  BLOCK_MODE_ADMIN_COMMIT,
  MAX_VERIFICATION_EXTENSION_SEC,
  TIMELINE_NO_GAME_ROOT_STATE,
  adminCommitRootSubmissionDeadline,
  classifyTimelineNoGameRoot,
  classifyProofAttachment,
  lifecycleReplayMatchesCurrent,
  normalizeBlockLifecycle,
  replayAdminCommitLifecycle,
} from '../../vendor/workers/game_workers/lib/block-lifecycle.js';
import { sha256HexOfString, byteEqual, canonicalEqual, diffPaths, displayTime } from '../json-utils.js';
import { r2LimitForKey } from '../r2.js';
import {
  decodeProofPrevRegistrationIndex,
  inspectBlockZkpState,
  inspectProofSubmission,
  decodePublicValues,
  foldEvidenceAcc,
  ZKP_COLLECTION_FAILURE_CAUSES,
} from '../zkp.js';
import {
  PREV_REGISTRATION_SENTINEL,
  judgePrevRegistrationWitness,
  groupingObservedAtMs,
  readObserverChainSnapshots,
  selectObserverResultWitness,
} from '../prev-registration-witness.js';
import {
  isEmergencyCheckDowngradable,
  manifestCoreHash,
  readEmergencyArtifactGenerations,
  gcpCandidates,
  gcpUnevaluated,
} from '../emergency.js';
import { keccak256, stringToHex, verifyMessage } from 'viem';
import { checkProofFutureAnchor } from '../future-anchor.js';
import { createReport } from '../report.js';
import { ArchiveUnavailableError, historicalStateFailure, conciseRpcText } from '../archive.js';

// 応募の申告値を仮定した計算専用。K11の状態をlatestで代用しない。
// 適格判定/採点/按分はvendorの同じ関数を通し、reportが依存検査を未検証にする。
export function provisionalDepositInputs(ctx, gm) {
  const perUid = Object.create(null);
  const chainData = Object.create(null);
  for (const p of ctx.data.gameSelection?.players || []) {
    const uid = p.data?.uid;
    if (uid == null) continue;
    perUid[String(uid)] = parseEntryDepositIds(p.data.depIds);
    if (perUid[String(uid)].length === 0) continue;
    // 正典の解析でIDが得られた入力だけ、仮計算用の申告値を読む。
    const entry = typeof p.data.depIds === 'string' ? JSON.parse(p.data.depIds) : p.data.depIds;
    for (const id of perUid[String(uid)]) {
      const dep = entry?.deposits?.find((d) => String(d.id) === id);
      if (!dep || dep.amount == null || dep.unlockTime == null || dep.idFrom == null) return null;
      // 同じIDへの異なる申告は、どちらも独立検証できない。推測で採らない。
      const row = { ...dep, idTo: String(uid), withdrawn: false };
      if (chainData[id] && !canonicalEqual(chainData[id], row)) return null;
      chainData[id] = row;
    }
  }
  withVendorLogging(() => gm.calcCollectDepositIds(ctx.blockNum, perUid)); // 正典の総数/ID制約も維持
  return withVendorLogging(() => gm.calcFilterEligibleDeposits(ctx.blockNum, perUid, chainData));
}

function skipHistoricalDeposits(ctx, S, gm, error) {
  if (!(error instanceof ArchiveUnavailableError)) throw error;
  ctx.report.fact('stageC.lockStateError', error);
  ctx.report.fact('stageC.lockStateUnchecked', true);
  ctx.report.unverified('check.stageC.depositVerification', error, { reason: 'archive_unavailable' });
  if (!S.archiveNotice) {
    const message = ctx.ui.t('reason.archiveUnavailable');
    ctx.ui.warn(message);
    S.archiveNotice = true;
  }
  return provisionalDepositInputs(ctx, gm);
}

async function verifyDepositsWithAvailableState(ctx, S, gm, perUid) {
  try { return await verifyDepositsOnChainInUnits(gm, ctx.blockNum, perUid); }
  catch (error) {
    if (!(error instanceof ArchiveUnavailableError)) throw error;
    return skipHistoricalDeposits(ctx, S, gm, error);
  }
}

async function finishWithoutDepositInputs(ctx, S, gm, timing) {
  ctx.report.check('check.stageC.scoring', 'skip', { reason: 'archive_unavailable' });
  ctx.report.check('check.stageC.summaryMatch', 'skip', { reason: 'archive_unavailable' });
  await verifyMerkle(ctx, S, gm);
  await verifyTimeline(ctx, S, timing);
  ctx.report.fact('stageC.anomalies', S.anomalies);
  return { stop: false };
}

function addProofProviderAnomaly(ctx, S) {
  const key = S.zkInfo?.kind === 'proof'
    ? 'stageC.anomaly.proofMerkleRootMismatch' : 'stageC.anomaly.merkleRootMismatch';
  const index = S.anomalies.length;
  S.anomalies.push(ctx.ui.t(key, { provider: 'unavailable' }));
  if (S.zkInfo?.kind === 'proof') (S.proofProviderAnomalies ||= []).push({ index, key });
}

export function resolveProofProviderLabels(ctx, S) {
  const provider = S.futureAnchorCheck?.provider ?? 'unavailable';
  for (const { index, key } of S.proofProviderAnomalies || []) {
    S.anomalies[index] = ctx.ui.t(key, { provider });
  }
  const check = ctx.report.get('check.stageC.evidenceReportMatch');
  if (check?.params?.provider === 'unavailable') {
    ctx.report.check('check.stageC.evidenceReportMatch', check.status,
      { ...check.params, provider });
  }
}

const ZERO_ROOT = '0x' + '0'.repeat(64);
export const MANIFEST_CORE_RETRY_INSTRUCTION = '正しい manifest core を登録してから再実行してください';
export const EVIDENCE_EVENTS_PER_UNIT = 400;
export const EVIDENCE_CHARS_PER_UNIT = 12000000;
export const EVIDENCE_LOG_BLOCKS_PER_READ = 2000;
export const DEPOSIT_IDS_PER_UNIT = 250;

export class DepositReadsUnavailableError extends Error {
  constructor(message, cause = null) {
    super(message, cause ? { cause } : undefined);
    this.name = 'DepositReadsUnavailableError';
    this.code = 'deposit_reads_unavailable';
  }
}

export function buildMajorLangsMatchCheck(published, derived) {
  return {
    status: canonicalEqual(published, derived) ? 'pass' : 'fail',
    params: {
      published: JSON.stringify(published ?? null),
      derived: JSON.stringify(derived ?? null),
      instruction: MANIFEST_CORE_RETRY_INSTRUCTION,
    },
  };
}

export function recordMajorLangsMatchForMode(
  ctx,
  published,
  derived,
  { emergencyZeroEntryNoGame = false } = {},
) {
  const match = buildMajorLangsMatchCheck(published, derived);
  const emergencyDifference = Boolean(ctx.data?.emergencySource)
    && emergencyZeroEntryNoGame && match.status === 'fail';
  ctx.report.check(
    'check.stageC.majorLangsMatch',
    emergencyDifference ? 'skip' : match.status,
    emergencyDifference
      ? { ...match.params, reason: 'zero_entry_no_game_emergency_difference' }
      : match.params,
  );
  if (emergencyDifference) {
    recordEmergencyDifference(ctx, {
      checkId: 'check.stageC.majorLangsMatch',
      what: 'published zero-entry no-game majorLangs differs from the canonical empty list',
      chain: { published: published ?? null },
      rebuilt: { majorLangs: derived ?? null },
      reason: 'the canonical zero-entry writer regenerates an empty majorLangs list',
    });
  }
  return { ...match, recordedStatus: emergencyDifference ? 'skip' : match.status };
}

export function buildZeroEntryNoGameSummary(blockNum, publishedSchemaVersion, emergencyMode = false) {
  const groupClaimOverlay = Boolean(emergencyMode) || Number(publishedSchemaVersion) >= 3;
  const rebuilt = {
    schemaVersion: groupClaimOverlay ? 3 : 2,
    blockNum,
    blockReward: getBlockRewardWei(blockNum).toString(),
    totalPlayers: 0,
    totalGroups: 0,
    noGame: true,
    majorLangs: [],
    groups: [],
    claimStatusKey: `games/block${blockNum}/claim-status.json`,
    ...(groupClaimOverlay ? { claimLayout: 'group-overlays-v1' } : {}),
    noGameReason: 'zero_entries',
  };
  // writerは noGameReason を claimStatusKey の後に追加する。
  const reason = rebuilt.noGameReason;
  delete rebuilt.noGameReason;
  rebuilt.noGameReason = reason;
  return rebuilt;
}

export function zeroEntryNoGameSummaryShapeMatches({
  selectionPlayers,
  published,
  rebuilt,
  blockNum,
  gameGroups = null,
  autoResult = null,
  emergencyMode = false,
}) {
  return Array.isArray(selectionPlayers)
    && selectionPlayers.length === 0
    && published?.schemaVersion === rebuilt.schemaVersion
    && published?.blockNum === blockNum
    && published?.blockReward === getBlockRewardWei(blockNum).toString()
    && published?.totalPlayers === 0
    && published?.totalGroups === 0
    && published?.noGame === true
    && published?.noGameReason === 'zero_entries'
    && published?.noGameCause === undefined
    && published?.autoDistributed === undefined
    && Array.isArray(published?.majorLangs) && published.majorLangs.length === 0
    && Array.isArray(published?.groups) && published.groups.length === 0
    && published?.claimStatusKey === `games/block${blockNum}/claim-status.json`
    // P5以前の通常モードは claimLayout をこの shape check の条件にしていない。
    // 固定一式を新規生成する緊急モードだけ、v3 overlay 宣言まで厳密に固定する。
    && (!emergencyMode || published?.claimLayout === rebuilt.claimLayout)
    && gameGroups == null
    && autoResult == null;
}

export function classifyDepositVerificationError(error) {
  if (error instanceof ArchiveUnavailableError) return 'archive_rpc_required';
  return error?.code === 'deposit_reads_unavailable' ? 'unavailable' : 'mismatch';
}

// 正典入口 verifyDepositsOnChainForUids を直接実行し、RPC読取だけを
// calcChainUnit と同じ250 ID単位へ分ける。Q7のdistinct列挙・総数上限・正準uid照合・
// 失敗判定は、COPY済みの正典メソッドから外へ写経しない。
export async function verifyDepositsOnChainInUnits(gm, blockNum, perUid) {
  try { return await verifyDepositsOnChainInUnitsCore(gm, blockNum, perUid); }
  catch (error) {
    if (!(error instanceof ArchiveUnavailableError) || !gm.availableStateContext) throw error;
    const { ctx, S } = gm.availableStateContext;
    const provisional = skipHistoricalDeposits(ctx, S, gm, error);
    if (!provisional) throw error;
    return provisional;
  }
}

async function verifyDepositsOnChainInUnitsCore(gm, blockNum, perUid) {
  const unitizedGm = Object.create(gm);
  let filterCalled = false;
  let filteredResult;
  unitizedGm.calcFetchDepositsFromChain = async (uniqueIds, blockNumber) => {
    const chainData = Object.create(null);
    for (let start = 0; start < uniqueIds.length; start += DEPOSIT_IDS_PER_UNIT) {
      const ids = uniqueIds.slice(start, start + DEPOSIT_IDS_PER_UNIT);
      let fetched;
      try {
        const readGm = Object.create(gm);
        const denied = new Set();
        readGm.isArchiveStateUnavailable = (error) => historicalStateFailure(error) === 'archive_unavailable';
        readGm.createReadOnlyClient = () => {
          const client = gm.createReadOnlyClient();
          return { ...client, readContract: async (request) => {
            try { return await client.readContract(request); }
            catch (error) {
              if (error instanceof ArchiveUnavailableError) denied.add(String(request.args[0]));
              throw error;
            }
          } };
        };
        fetched = await withVendorLogging(() => gm.calcFetchDepositsFromChain.call(readGm, ids, blockNumber));
        if (fetched?.failedReads?.length && fetched.failedReads.every((id) => denied.has(String(id)))) {
          throw new ArchiveUnavailableError();
        }
      } catch (error) {
        if (error instanceof ArchiveUnavailableError) throw error;
        throw new DepositReadsUnavailableError(
          `[B1] on-chain deposit reads unavailable for unit ${Math.floor(start / DEPOSIT_IDS_PER_UNIT) + 1}: ${error?.message || error}`,
          error,
        );
      }
      const failedReads = fetched?.failedReads || [];
      if (failedReads.length > 0) {
        throw new DepositReadsUnavailableError(
          `[B1] on-chain deposit reads unavailable for ${failedReads.length}/${ids.length} ids (first: ${failedReads[0]})`,
        );
      }
      Object.assign(chainData, fetched?.chainData || {});
    }
    return { chainData, failedReads: [] };
  };
  // 正典入口は成功ログで Object.keys(verifiedDepositWei) を呼ぶ。テスト差し替え等で
  // null/undefined表が返った場合も、そのログのTypeErrorへ潰さず後段の専用shape checkへ
  // 元の値を渡す。通常の正典戻り値は一切差し替えない。
  unitizedGm.calcFilterEligibleDeposits = (...args) => {
    filterCalled = true;
    filteredResult = withVendorLogging(() => gm.calcFilterEligibleDeposits.apply(gm, args));
    if (filteredResult?.verifiedDepositWei == null) {
      return { ...filteredResult, verifiedDepositWei: Object.create(null) };
    }
    return filteredResult;
  };
  const canonicalResult = await withVendorLogging(() => GameMasterDO.prototype.verifyDepositsOnChainForUids.call(
    unitizedGm, blockNum, perUid,
  ));
  return filterCalled ? filteredResult : canonicalResult;
}

// R31-U-D: A compact submission rejected by the public grouping can still be
// cryptographically valid against its own slot and the committed applicants.
// The alternate index is diagnostic only; it never enters evidence adoption.
export async function submissionContradictsGrouping(raw, blockNum, publicValidation, applicants, sender) {
  if (publicValidation?.reason !== 'compact_context_mismatch' || typeof raw !== 'string') return null;
  let compact;
  try { compact = decodeSubmissionPayloadString(raw); } catch { return null; }
  if (!Array.isArray(compact.memberUids) || !Number.isSafeInteger(compact.groupId)) return null;
  const byUid = new Map((applicants || []).map((item) => {
    const data = item?.data ?? item;
    return [data?.uid, data];
  }));
  const members = compact.memberUids.map((uid) => byUid.get(uid));
  if (members.some((member) => !member)) return null;
  const ownIndex = buildMembersIndex([{ group_id: compact.groupId, members }]);
  const ownValidation = await validateResultBundle(raw, blockNum, ownIndex, sender);
  return ownValidation.valid === true
    ? { groupId: compact.groupId, uid: ownValidation.uid } : null;
}

// R12-43/S4: claim 後に正当に書き換わりうる旧成果物の唯一の判定源。
// schema v3 は行別 claimed を manifest 外へ分離したため group/auto page も不変。
// schemaVersion が欠落・不正型なら「旧版だろう」と推測せず安全側の不変扱いに倒す。
export function isClaimMutableArtifact(key, blockNum, summarySchemaVersion) {
  const knownVersion = typeof summarySchemaVersion === 'number'
    && Number.isFinite(summarySchemaVersion);
  if (key === `games/block${blockNum}/summary.json`) {
    return knownVersion && summarySchemaVersion < 2;
  }
  const resultPage = key === `games/block${blockNum}/auto-results.json`
    || new RegExp(`^games/block${blockNum}/group\\d+\\.json$`).test(key);
  // schemaVersion 自体が無い旧inline summaryも実在する。旧判定は result page を常に
  // mutable としていたため、欠落だけはlegacyとして維持する。不正型は将来形式と推測しない。
  const legacyResultPage = summarySchemaVersion == null
    || (knownVersion && summarySchemaVersion < 3);
  return legacyResultPage && resultPage;
}

export function shouldParkManifestHashMismatch(
  key, blockNum, summarySchemaVersion, raw, declared
) {
  return raw != null && declared != null
    && isClaimMutableArtifact(key, blockNum, summarySchemaVersion);
}

// R13-P7L-02: refetch の戻りは「オブジェクトがある」だけでは足りず、raw 本体と
// 宣言 hash の一致が必要。precheck と manifest 全件照合がこの1実装を共有する。
export async function refetchDeclaredRaw(r2, key, declared) {
  const fresh = await r2.refetch(key).catch(() => null);
  return fresh?.raw && sha256HexOfString(fresh.raw) === declared ? fresh : null;
}

// LR-02: roster manifest の中身へ入ってよい条件。declared が無ければ live が完全でも
// オンチェーン時刻との比較材料が無いので、参照を始めない。
export function canInspectRosterManifest(live, declared) {
  return Boolean(live?.raw && live?.data && declared);
}

// B-3: Merkle 木再構築用分冊の列挙規則は、byte-exact COPY 済みの正典を直接使う。
// leafCount <= 0（および旧版／不完全メタ）で [] を返す分岐、並び順、上限検査を含め、
// verifier 側へ定数やアルゴリズムを手写ししない。
export function merkleRebuildArtifactKeys(blockNum, treeMeta) {
  return withVendorLogging(() => GameMasterDO.prototype.merkleRebuildArtifactKeys.call(null, blockNum, treeMeta));
}

// R29-D-2-02: 緊急固定一式が公開バイトを運ばず、正準 writer で必ず作り直す成果物だけ。
// `R29_ALLOWED_CENSUS.json` が (ii) とした selection / game_groups / evidence / manifest / roster
// はここへ足さない。merkle メタ本体も manifest の鍵集合を導くため対象外にし、再生成される
// leaves / levels / index 分冊と auto-results、従来から救済する group archive に限定する。
export function isEmergencyRegeneratedResultArtifact(key, blockNum) {
  const value = String(key || '').split(': ', 1)[0];
  return new RegExp(`^games/block${blockNum}/group\\d+\\.json$`).test(value)
    || value === `games/block${blockNum}/zkp/evidence-segments.json`
    || value === `games/block${blockNum}/auto-results.json`
    || new RegExp(`^merkle/block_${blockNum}/(?:index/[0-9a-f]+|leaves/\\d+|levels/\\d+/\\d+)\\.json$`)
      .test(value);
}

export function canContinueEmergencyAfterDownloadIssues(blockNum, emergencyMode, issues) {
  const list = Array.isArray(issues) ? issues : [];
  return Boolean(emergencyMode) && list.length > 0
    && list.every((item) => isEmergencyRegeneratedResultArtifact(item, blockNum));
}

// REQUEST8 便E: リリース前で block 0 から始めるため、旧manifest互換は持たない。
// 第三者検証器は運営manifestの欠落を検出する側なので、未宣言も値の逸脱と同じくFAILにする。
export function collectRequiredScoringRuleDeviations(rules = {}, pins = {}) {
  const deviations = [];
  for (const key of ['visibleCharsRule', 'reportMinReadReceipts', 'reportEligibilityRule']) {
    if (rules[key] !== pins[key]) deviations.push(`${key}=${rules[key]}`);
  }
  return deviations;
}

// 全て manifest で必須の flat pin。この配列を実際の Stage C 照合と
// request3-bounds-test のキー被覆検査の両方が使う。これにより、pin の
// 宣言だけを追加して照合を忘れる状態を作らない。
export const STRICT_MANIFEST_RULE_PIN_KEYS = Object.freeze([
  'msgRefBytes', 'receiptMaxActionsPerPairBase', 'receiptMaxActionsPerPair',
  'receiptMaxRefsPerReceipt', 'maxObservedActionsPerActor', 'receiptAcceptanceRule',
  'submissionLimitsVersion', 'evidenceCompactFormat', 'maxDepositIds',
  'maxMessagesPerPlayer', 'maxMessagesTotal', 'maxMessageChars',
  'maxMessageCharsPerPlayer', 'maxAcceptedVotesPerPlayer',
  'maxAcceptedReportsPerPlayer', 'maxReceiptFacts', 'maxSelfAggregateTargets',
  'serverMaxSubmissionWireBytes', 'serverMaxSubmissionDecodedBytes',
  'evidenceMaxDataBytesExclusive',
  'maxPriorityOwnMessages', 'maxPriorityOtherMessages', 'maxPriorityReceipts',
  'ethereumHeaderRuleVersion', 'ethereumHeaderFork', 'confirmationBlocks',
]);

export function collectStrictManifestRulePinDeviations(rules = {}, pins = {}) {
  const deviations = [];
  for (const key of STRICT_MANIFEST_RULE_PIN_KEYS) {
    if (rules[key] !== pins[key]) deviations.push(`${key}=${rules[key]}`);
  }
  return deviations;
}

export function scoringThresholdsFromPins(cfg) {
  const pins = cfg.pins;
  return {
    minChars: pins.minChars,
    minMessages: pins.minMessages,
    chatCaps: {
      maxChars: pins.chatCaps.maxChars,
      maxMessages: pins.chatCaps.maxMessages,
      maxMsgChars: pins.chatCaps.maxMsgChars,
    },
  };
}

export function declaredAdoptedCountForVerification(declaredCounts) {
  return (declaredCounts.adoptedCount == null && declaredCounts.resultCount === 0)
    ? 0 : declaredCounts.adoptedCount;
}

export function emergencyAdoptedCountOf(resultCount, adoptedByUid) {
  return resultCount === 0 ? null : Object.keys(adoptedByUid || {}).length;
}

// ============================================================
// 小道具
// ============================================================

const num = (v) => (v == null ? null : Number(v));
const isoOf = (sec) => (Number.isFinite(sec) ? displayTime(sec * 1000) : null);
const lower = (h) => (typeof h === 'string' ? h.toLowerCase() : h);

export function recordEmergencyDifference(ctx, difference) {
  if (!ctx?.data?.emergencySource) return false;
  (ctx.data.emergencyDifferences ||= []).push(difference);
  return true;
}

export function recordGcpGroupingContradictions(ctx) {
  if (ctx.data.emergencySource?.authority !== 'gcp') return 0;
  const contradictory = (ctx.data.emergencySubmissionCandidates || [])
    .filter((candidate) => Number.isSafeInteger(candidate.contradictionGroupId))
    .map((candidate) => ({ groupId: candidate.contradictionGroupId,
      sha256: candidate.sha256 }));
  if (contradictory.length > 0) recordEmergencyDifference(ctx, {
    checkId: 'emergency.gcpEvidenceContradictsGrouping',
    what: 'preserved submissions valid for their own compact grouping slot',
    chain: { blockNum: ctx.blockNum },
    rebuilt: { count: contradictory.length, submissions: contradictory },
    reason: 'diagnostic only; these submissions cannot select the grouping or stop recovery',
  });
  return contradictory.length;
}

export function classifyZkpPublicValuesForMode(publicValues, emergencyMode = false, {
  currentResultMarker = null,
  fixedManifestCoreHash = null,
  gcpHistoricalProofHash = false,
} = {}) {
  const emergencyArtifactMissing = Boolean(emergencyMode)
    && publicValues?.status === 'unavailable'
    && publicValues?.cause === ZKP_COLLECTION_FAILURE_CAUSES.artifactMissing;
  const currentMarkerMatchesFixedCore = Boolean(currentResultMarker?.hash && fixedManifestCoreHash)
    && lower(currentResultMarker.hash) === lower(fixedManifestCoreHash);
  const proofBoundHashDiffersFromFixedCore = Boolean(
    publicValues?.proofBoundResultHash && fixedManifestCoreHash,
  ) && lower(publicValues.proofBoundResultHash) !== lower(fixedManifestCoreHash);
  const emergencyHijackPeriodProof = Boolean(emergencyMode)
    && publicValues?.status === 'unavailable'
    && publicValues?.cause === ZKP_COLLECTION_FAILURE_CAUSES.proofBoundToOtherManifest
    && currentMarkerMatchesFixedCore
    && proofBoundHashDiffersFromFixedCore;
  const gcpPriorRootProof = Boolean(emergencyMode) && gcpHistoricalProofHash
    && publicValues?.status === 'unavailable'
    && publicValues?.cause === ZKP_COLLECTION_FAILURE_CAUSES.proofBoundToOtherManifest
    && proofBoundHashDiffersFromFixedCore;
  return {
    emergencyArtifactMissing,
    emergencyHijackPeriodProof,
    gcpPriorRootProof,
    currentMarkerMatchesFixedCore,
    proofBoundHashDiffersFromFixedCore,
    status: publicValues?.status === 'pass'
      ? 'pass' : (emergencyArtifactMissing || emergencyHijackPeriodProof || gcpPriorRootProof ? 'warn' : 'fail'),
  };
}

export async function findGcpProofRegistration(chain, blockNum, proofBoundHash) {
  if (!/^0x[0-9a-f]{64}$/i.test(String(proofBoundHash || ''))) return null;
  const count = Number(await chain.resultRegistrationCount(blockNum));
  if (!Number.isSafeInteger(count) || count < 0) {
    throw new Error(`invalid resultRegistrationCount(${blockNum}): ${count}`);
  }
  if (count > 0 && typeof chain.resultHashEvents === 'function') {
    const [first, last] = await Promise.all([
      chain.resultRegistrationAt(blockNum, 0), chain.resultRegistrationAt(blockNum, count - 1),
    ]);
    const logs = await chain.resultHashEvents(blockNum, {
      fromBlock: BigInt(first.registeredBlock), toBlock: BigInt(last.registeredBlock),
    });
    const found = logs.findLast((event) => lower(event.hash) === lower(proofBoundHash));
    if (found) {
      const index = Number(found.registrationCount) - 1;
      if (!Number.isSafeInteger(index) || index < 0 || index >= count) {
        throw new Error(`block ${blockNum}: invalid ResultHashRegistered index`);
      }
      const state = await chain.resultRegistrationAt(blockNum, index);
      if (lower(state?.hash) !== lower(found.hash)
          || Number(state?.registeredBlock) !== Number(found.updatedAt ?? found.evtBlock)
          || String(state?.signer).toLowerCase() !== String(found.signer).toLowerCase()) {
        throw new Error(`block ${blockNum}: ResultHashRegistered log differs from state row ${index}`);
      }
      return index;
    }
    // An incomplete log response must not hide a registration in state.
  }
  for (let index = count - 1; index >= 0; index--) {
    const row = await chain.resultRegistrationAt(blockNum, index);
    if (lower(row.hash) === lower(proofBoundHash)) return index;
  }
  return null;
}

// R29-A-3b-01: manifestHash は manifestCore の外にある公開ファイルの自称ラベル。
// blockNum / algorithm は構造上の不変量なので緊急時も fail-closed のままにし、
// 自称ラベルだけの不一致に限って、緊急復旧では差として残して再計算を続ける。
// emergencyMode=false の真理値は従来の3脚ANDと完全に同じである。
export function classifyManifestSelfConsistency({
  coreHash,
  declaredManifestHash,
  expectedBlockNum,
  declaredBlockNum,
  declaredAlgorithm,
  emergencyMode = false,
}) {
  const manifestHashLabelMatches = coreHash === declaredManifestHash;
  const blockNumMatches = declaredBlockNum === expectedBlockNum;
  const algorithmMatches = declaredAlgorithm === 'sha256';
  const emergencyManifestHashLabelDifference = Boolean(emergencyMode)
    && !manifestHashLabelMatches && blockNumMatches && algorithmMatches;
  return {
    manifestHashLabelMatches,
    blockNumMatches,
    algorithmMatches,
    emergencyManifestHashLabelDifference,
    status: manifestHashLabelMatches && blockNumMatches && algorithmMatches
      ? 'pass' : (emergencyManifestHashLabelDifference ? 'warn' : 'fail'),
  };
}

export async function routeMissingRootInStageC(ctx, S, state, root = null) {
  const { report, ui, blockNum: N } = ctx;
  // 分岐順は意図的: 緊急固定一式ではtimeline no-gameでも新rootを組み直すため、
  // 平時の「期待されたroot省略」終端より先に緊急再構築へ入れる。
  if (isEmergencyCheckDowngradable('check.stageC.rootSubmitted', Boolean(ctx.data.emergencySource))) {
    S.emergencyRootMissing = true;
    ctx.data.emergencyChainRoot = null;
    report.check('check.stageC.rootSubmitted', 'warn', { reason: 'no_root_emergency_rebuild_continues' });
    recordEmergencyDifference(ctx, {
      checkId: 'check.stageC.rootSubmitted',
      what: 'existing Merkle root is absent',
      chain: { root: root || null, verificationStartedAt: num(state?.verificationStartedAt) },
      rebuilt: { action: 'derive a fresh Merkle root from the independently recomputed summary' },
      reason: 'emergency recomputation must finish before the replacement root can be submitted',
    });
    return { stop: false, branch: 'emergency_rebuild' };
  }
  if (S.timelineNoGame) {
    return { ...(await verifyTimelineNoGameRootOmission(ctx, S)), branch: 'timeline_no_game_omission' };
  }
  report.check('check.stageC.rootSubmitted', 'skip', { reason: 'no_root' });
  ui.println(ui.t('stageC.gateNoRoot', { block: N }));
  ctx.data.stopReason = 'not_ready';
  return { stop: true, branch: 'not_ready' };
}

export const EMERGENCY_ROSTER_ANCHOR_DIFFERENCE_REASONS = Object.freeze([
  'on-chain roster hash is unregistered',
  'published roster manifest bytes do not match the on-chain hash',
  'on-chain roster hash was registered at or after chattingStart',
]);

export function classifyRosterAnchorForMode(failures, warnings, emergencyMode) {
  const accepted = isEmergencyCheckDowngradable('check.stageC.rosterLiveAnchor', emergencyMode)
    ? failures.filter((failure) => EMERGENCY_ROSTER_ANCHOR_DIFFERENCE_REASONS.includes(failure))
    : [];
  const remainingFailures = failures.filter((failure) => !accepted.includes(failure));
  const finalWarnings = [...warnings];
  if (accepted.length > 0) {
    finalWarnings.push(
      'emergency acceptance: the published roster differs from the selected chain registration; '
      + 'ordinary third-party verification remains failed',
    );
  }
  return {
    accepted,
    failures: remainingFailures,
    warnings: finalWarnings,
    status: remainingFailures.length > 0 ? 'fail'
      : (finalWarnings.length > 0 ? 'warn' : 'pass'),
  };
}

function toBlockBigInt(v) {
  if (typeof v === 'bigint') return v;
  if (v && typeof v === 'object' && v.number != null) return BigInt(v.number);
  return BigInt(v);
}

// merkleRootEvents / getLogs の戻りを正規化（viem生ログ / 整形済みの両対応）
function normalizeRootEvent(ev) {
  return {
    root: ev.root ?? ev.args?.root ?? null,
    timestamp: num(ev.timestamp ?? ev.args?.timestamp),
    txHash: ev.txHash ?? ev.transactionHash ?? null,
    evtBlock: num(ev.evtBlock ?? ev.blockNumber),
    transactionIndex: num(ev.transactionIndex),
    logIndex: num(ev.logIndex ?? ev.index),
  };
}

function normalizeExtensionEvent(ev) {
  return {
    ...(ev.timestampError ? { timestampError: ev.timestampError } : {}),
    newEndFloor: num(ev.newEndFloor ?? ev.args?.newEndFloor),
    timestamp: num(ev.timestamp),
    txHash: ev.txHash ?? ev.transactionHash ?? null,
    evtBlock: num(ev.evtBlock ?? ev.blockNumber),
    transactionIndex: num(ev.transactionIndex),
    logIndex: num(ev.logIndex ?? ev.index),
  };
}

function normalizeInvalidationEvent(ev) {
  return {
    timestamp: num(ev.timestamp ?? ev.args?.timestamp),
    txHash: ev.txHash ?? ev.transactionHash ?? null,
    evtBlock: num(ev.evtBlock ?? ev.blockNumber),
    transactionIndex: num(ev.transactionIndex),
    logIndex: num(ev.logIndex ?? ev.index),
  };
}

function normalizedEventPosition(event) {
  const values = [event?.evtBlock, event?.transactionIndex, event?.logIndex].map(Number);
  if (!values.every(Number.isSafeInteger) || values.some((value) => value < 0)) {
    throw new Error('event position (block/transaction/log index) is incomplete');
  }
  return values;
}

function compareEventPosition(a, b) {
  const ap = normalizedEventPosition(a);
  const bp = normalizedEventPosition(b);
  return ap[0] - bp[0] || ap[1] - bp[1] || ap[2] - bp[2];
}

export function resolveCurrentProofAttachment({ rootEvent, attachmentEvents, currentRoot, epochIndex, proofAttachedAt }) {
  const errors = [];
  if (!rootEvent) return { ok: false, errors: ['current MerkleRootSubmitted event is missing'], event: null, kind: 'unverified' };
  let afterRoot = [];
  try {
    afterRoot = (attachmentEvents || []).filter((event) => compareEventPosition(event, rootEvent) > 0);
  } catch (error) {
    errors.push(error.message);
  }
  if (afterRoot.length !== 1) errors.push(`expected exactly one attachment after current root, found ${afterRoot.length}`);
  const event = afterRoot.length === 1 ? afterRoot[0] : null;
  if (event) {
    if (lower(event.root) !== lower(currentRoot)) errors.push('attachment root != current root');
    if (Number(event.epochIndex) !== Number(epochIndex)) errors.push('attachment epoch != current state epoch');
    if (Number(event.timestamp) !== Number(proofAttachedAt)) errors.push('attachment timestamp != blockStates.proofAttachedAt');
    if (!event.txHash || !rootEvent.txHash) errors.push('attachment/root txHash is missing');
  }
  const kind = event?.txHash && rootEvent?.txHash
    && lower(event.txHash) === lower(rootEvent.txHash)
    ? 'simultaneous' : 'post_commit';
  return { ok: errors.length === 0, errors, event: errors.length === 0 ? event : null, kind };
}

export function recordZkpState(ctx, S, zkInfo) {
  const { report } = ctx;
  const common = {
    kind: zkInfo.kind,
    currentProofRequired: zkInfo.currentProofRequired,
  };
  if (typeof zkInfo.currentProofRequired === 'boolean') {
    report.check('check.stageC.zkCurrentRequirement', 'pass', common);
  } else {
    report.check('check.stageC.zkCurrentRequirement', 'fail', {
      ...common,
      error: zkInfo.proofRequiredError || zkInfo.error || 'proofRequired unavailable',
    });
  }

  if (zkInfo.kind === 'proof') {
    report.check('check.stageC.zkProofStatus', 'pass', {
      ...common,
      epoch: zkInfo.epoch.index,
    });
    report.check('check.stageC.zkEpoch', 'pass', {
      epoch: zkInfo.epoch.index,
      verifier: zkInfo.epoch.verifier,
      vkey: zkInfo.epoch.vkey,
      guestSourceHash: zkInfo.epoch.guestSourceHash,
    });
    report.check('check.stageC.zkVerifierIdentity',
      String(zkInfo.epoch.verifier).toLowerCase() === ZKP_EXPECTED.verifier.toLowerCase() ? 'pass' : 'fail', {
        epoch: zkInfo.epoch.index,
        verifier: zkInfo.epoch.verifier,
        expected: ZKP_EXPECTED.verifier,
      });
    report.check('check.stageC.futureAnchorsHash', 'skip', { reason: 'proof_check_pending' });
    report.check('check.stageC.evidenceSegmentBoundaries', 'skip', { reason: 'evidence_scan_pending' });
    return;
  }
  if (zkInfo.kind === 'shadow') {
    // shadow は正常な「証明なし」。検査不能ではないので WARN として明示し、FAILにはしない。
    report.check('check.stageC.zkProofStatus', 'warn', common);
    report.check('check.stageC.zkEpoch', 'skip', { reason: 'shadow_no_proof' });
    report.check('check.stageC.zkVerifierIdentity', 'skip', { reason: 'shadow_no_proof' });
    report.check('check.stageC.zkProofFormat', 'skip', { reason: 'shadow_no_proof' });
    report.check('check.stageC.zkPublicValues', 'skip', { reason: 'shadow_no_proof' });
    report.check('check.stageC.zkPrevRegistrationWitness', 'skip', { reason: 'shadow_no_proof' });
    report.check('check.stageC.futureAnchorsHash', 'skip', { reason: 'shadow_no_proof' });
    report.check('check.stageC.evidenceSegmentBoundaries', 'skip', { reason: 'shadow_no_proof' });
    return;
  }
  if (zkInfo.kind === 'no_root') {
    const reason = S.timelineNoGame ? 'timeline_no_game_root_omission' : 'no_root';
    report.check('check.stageC.zkProofStatus', 'skip', { ...common, reason });
    report.check('check.stageC.zkEpoch', 'skip', { reason });
    report.check('check.stageC.zkVerifierIdentity', 'skip', { reason });
    report.check('check.stageC.zkProofFormat', 'skip', { reason });
    report.check('check.stageC.zkPublicValues', 'skip', { reason });
    report.check('check.stageC.zkPrevRegistrationWitness', 'skip', { reason });
    report.check('check.stageC.futureAnchorsHash', 'skip', { reason });
    report.check('check.stageC.evidenceSegmentBoundaries', 'skip', { reason });
    return;
  }
  report.check('check.stageC.zkProofStatus', 'fail', {
    ...common,
    error: zkInfo.error || 'ZKP state unavailable',
  });
  report.check('check.stageC.zkEpoch', 'fail', { error: zkInfo.error || 'ZKP epoch unavailable' });
  report.check('check.stageC.zkVerifierIdentity', 'skip', { reason: 'zk_state_unavailable' });
  report.check('check.stageC.zkProofFormat', 'skip', { reason: 'zk_state_unavailable' });
  report.check('check.stageC.zkPublicValues', 'skip', { reason: 'zk_state_unavailable' });
  report.check('check.stageC.zkPrevRegistrationWitness', 'skip', { reason: 'zk_state_unavailable' });
  report.check('check.stageC.futureAnchorsHash', 'skip', { reason: 'zk_state_unavailable' });
  report.check('check.stageC.evidenceSegmentBoundaries', 'skip', { reason: 'zk_state_unavailable' });
  S.anomalies.push(`ZKP state could not be verified: ${conciseRpcText(zkInfo.error || 'unavailable', ctx.ui?.t)}`);
}

export function selectZkpSummaryRaw({ publishedRaw, rebuiltSummary, manifest, blockNum }) {
  const key = `games/block${blockNum}/summary.json`;
  const declared = String(manifest?.files?.[key] || '').toLowerCase().replace(/^0x/, '');
  const rebuiltRaw = rebuiltSummary ? JSON.stringify(rebuiltSummary) : null;
  for (const candidate of [
    { source: 'published', raw: publishedRaw },
    { source: 'rebuilt', raw: rebuiltRaw },
  ]) {
    if (typeof candidate.raw === 'string' && declared
      && sha256HexOfString(candidate.raw) === declared) return candidate;
  }
  // collectZkpInput側のmanifest検査を迂回しない。不一致の公開bytesを渡して明示的にFAILさせる。
  return { source: 'unmatched', raw: publishedRaw };
}

/** manifest照合済みの公開bytesを、共有ZKP入力collectorのローカルfetchへ渡す。 */
export function buildZkpArtifacts(S, summaryRaw, emergencySource = null) {
  let merkleRaw = S.files?.merkle?.raw;
  if (emergencySource) {
    const blockNum = Number(S.files?.manifest?.data?.blockNum ?? S.files?.summary?.data?.blockNum);
    const root = String(S.blockState?.root || '').toLowerCase();
    if (Number.isSafeInteger(blockNum) && blockNum >= 0 && /^0x[0-9a-f]{64}$/.test(root)
        && root !== ZERO_ROOT) {
      // proof の public values は、inspectProofEnvelope が既に照合したオンチェーン root と
      // 比較する。公開 merkle metadata は緊急固定一式の権威にはしない。
      merkleRaw = JSON.stringify({ blockNum, root });
    }
  }
  return {
    manifest: S.files?.manifest?.raw,
    summary: summaryRaw,
    merkle: merkleRaw,
    selection: S.files?.selection?.raw,
    stage3Manifest: emergencySource?.stage3ManifestUsableForZkp === false
      ? undefined : S.files?.stage3Manifest?.raw,
    rosterManifest: S.rosterManifestText,
    rosterIndex: S.rosterIndexText,
    rosterGroups: S.rosterGroupTexts,
  };
}

function gcpMerkleComparisonDescriptor(S) {
  const raw = S.files?.merkle?.raw;
  const data = S.files?.merkle?.data;
  return {
    sha256: typeof raw === 'string' ? sha256HexOfString(raw) : null,
    bytes: typeof raw === 'string' ? Buffer.byteLength(raw, 'utf8') : null,
    valueType: data === null ? 'null' : Array.isArray(data) ? 'array' : typeof data,
  };
}

export function recordEmergencyZkpMerkleMetadataDifference(ctx, S) {
  if (!ctx.data?.emergencySource) return false;
  const published = S.files?.merkle?.data;
  const onchainRoot = String(S.blockState?.root || '').toLowerCase();
  const publishedRoot = typeof published?.root === 'string' ? published.root.toLowerCase() : null;
  const publishedBlockNum = Number(published?.blockNum);
  const differs = !/^0x[0-9a-f]{64}$/.test(publishedRoot || '')
    || publishedRoot === ZERO_ROOT
    || publishedRoot !== onchainRoot
    || publishedBlockNum !== Number(ctx.blockNum);
  if (!differs) return false;
  recordEmergencyDifference(ctx, {
    checkId: 'check.stageC.merkleRoot',
    what: 'published merkle metadata differs from the on-chain root used by the proof envelope',
    chain: { blockNum: Number(ctx.blockNum), root: onchainRoot },
    rebuilt: { zkpMerkleMetadata: { blockNum: Number(ctx.blockNum), root: onchainRoot } },
    params: ctx.data.emergencySource?.authority === 'gcp'
      ? { savedMerkleMeta: gcpMerkleComparisonDescriptor(S) }
      : { publishedBlockNum: published?.blockNum ?? null, publishedRoot: published?.root ?? null },
    reason: 'emergency proof reproduction binds merkle metadata to the inspected on-chain root; the public mismatch remains a difference',
  });
  return true;
}

export function recordZkpPublicValuesCheck(ctx, publicValues, summarySource = null, proofEvent = null,
  untraceableOldProof = false) {
  const emergencySource = ctx.data?.emergencySource;
  const fixedManifestCoreHash = emergencySource?.selectedManifest
    ? manifestCoreHash(emergencySource.selectedManifest) : null;
  const decision = classifyZkpPublicValuesForMode(
    publicValues,
    Boolean(emergencySource),
    {
      currentResultMarker: emergencySource?.chainResultMarker ?? null,
      fixedManifestCoreHash,
      gcpHistoricalProofHash: emergencySource?.authority === 'gcp'
        && emergencySource.gcpHistoricalProofHash === true,
    },
  );
  const params = publicValues.wordwise ? {
    snapshotBlock: publicValues.snapshotBlock,
    safeBlock: publicValues.safeBlock,
    words: publicValues.verifiedWords.length,
    verifiedWords: publicValues.verifiedWords,
    unverifiedWords: publicValues.unverifiedWords,
    separateWords: publicValues.separateWords,
    sources: publicValues.sources,
    mismatches: publicValues.mismatches,
    rpcReads: publicValues.rpcReads,
    ...(publicValues.error ? { error: publicValues.error } : {}),
  } : publicValues.status === 'pass'
    ? {
        snapshotBlock: publicValues.snapshotBlock,
        words: 14,
        summaryBytes: summarySource,
        mismatches: '-',
      }
    : {
        error: publicValues.error || 'public values mismatch',
        mismatches: publicValues.mismatches?.slice(0, 3) || [],
        unavailable: publicValues.status === 'unavailable',
        ...(publicValues.cause ? { cause: publicValues.cause } : {}),
      };
  if (publicValues.unavailableError instanceof ArchiveUnavailableError) {
    ctx.report.unverified('check.stageC.zkPublicValues', publicValues.unavailableError, params);
    return decision;
  }
  ctx.report.check('check.stageC.zkPublicValues', untraceableOldProof ? 'warn' : decision.status,
    untraceableOldProof ? { cause: 'old_root_internal_call_untraceable', unavailable: true } : params);
  if (decision.emergencyArtifactMissing) {
    recordEmergencyDifference(ctx, {
      checkId: 'check.stageC.zkPublicValues',
      what: 'a required ZKP artifact is unavailable from the emergency fixed set',
      chain: { proofPublicValues: 'present' },
      rebuilt: { publicValues: 'not reproducible because the artifact is absent' },
      params: { cause: publicValues.cause, error: publicValues.error },
      reason: 'artifact absence is recorded separately; artifact mismatch and RPC failures remain FAIL',
    });
  }
  if (decision.emergencyHijackPeriodProof) {
    recordEmergencyDifference(ctx, {
      checkId: 'emergency.hijackPeriodProof',
      what: 'the recorded proof was attached while HashStorage selected a different result manifest',
      chain: {
        proofBlock: proofEvent?.evtBlock ?? proofEvent?.blockNumber ?? null,
        currentResultMarker: emergencySource?.chainResultMarker ?? null,
      },
      rebuilt: {
        fixedManifestCoreHash,
        action: 'retain the independently verified fixed set and record the old proof as hijack-period evidence',
      },
      params: { cause: publicValues.cause, error: publicValues.error },
      reason: 'emergency mode is active, the current marker selects the fixed-set core, and the proof snapshot binds a different result hash',
    });
  }
  if (decision.gcpPriorRootProof) {
    recordEmergencyDifference(ctx, {
      checkId: 'emergency.gcpPriorRootProof',
      what: 'the proof attached to the root binds a registered pre-replacement result hash',
      chain: { proofBoundResultHash: publicValues.proofBoundResultHash,
        currentResultMarker: emergencySource.chainResultMarker,
        registrationIndex: emergencySource.gcpProofRegistrationIndex },
      rebuilt: { syntheticManifestCoreHash: fixedManifestCoreHash,
        action: 'replace the root after exporting and registering the canonical fixed set' },
      reason: 'GCP authority was explicit and the proof-bound hash was verified in append-only result history',
    });
  }
  return { decision, params };
}

export function classifyUntraceableHijackProof(format, emergencySource) {
  const cause = /^(?:internal_call_(?:trace_unavailable|ambiguous)|trace_too_large)\b/.exec(String(format?.error || ''))?.[0] ?? null;
  const fixedCoreHash = emergencySource?.selectedManifest
    ? manifestCoreHash(emergencySource.selectedManifest) : null;
  const gcpAuthority = emergencySource?.authority === 'gcp';
  return {
    cause,
    fixedCoreHash,
    accepted: Boolean(format?.status === 'fail' && cause && emergencySource
      && (gcpAuthority || (fixedCoreHash && emergencySource.chainResultMarker?.hash
        && lower(emergencySource.chainResultMarker.hash) === lower(fixedCoreHash)))),
  };
}

export function recordZkpProofFormatForMode(ctx, format, proofEvent = null) {
  const traceException = classifyUntraceableHijackProof(format, ctx.data?.emergencySource);
  const formatParams = format.status === 'pass'
    ? { selector: format.selector, proofBytes: format.proofLength,
      publicValuesBytes: format.publicValuesLength }
    : { error: format.error || format.errors?.join('; ') || 'unavailable',
      unavailable: format.status === 'unavailable' };
  ctx.report.check('check.stageC.zkProofFormat', format.status === 'pass'
    ? 'pass' : traceException.accepted ? 'warn' : 'fail',
  traceException.accepted ? { cause: traceException.cause, emergencyDifference: true } : formatParams);
  if (traceException.accepted) {
    if (ctx.data.emergencySource.authority === 'gcp') {
      ctx.data.emergencySource.gcpUntraceableOldProof = true;
    }
    recordEmergencyDifference(ctx, {
      checkId: 'emergency.hijackPeriodProof',
      what: 'the replaced root proof internal call cannot be uniquely traced',
      chain: { proofBlock: proofEvent?.evtBlock ?? proofEvent?.blockNumber ?? null,
        currentResultMarker: ctx.data.emergencySource.chainResultMarker },
      rebuilt: { ...(ctx.data.emergencySource.authority === 'gcp'
        ? { syntheticManifestCoreHash: traceException.fixedCoreHash }
        : { fixedManifestCoreHash: traceException.fixedCoreHash }),
        action: 'retain the independently verified fixed set and replace the old root' },
      params: { cause: traceException.cause },
      reason: ctx.data.emergencySource.authority === 'gcp'
        ? 'GCP authority was explicit; the fixed result core is checked against the current marker by the canonical writer before export'
        : 'the current result marker selects the fixed core; the untraceable old proof is recorded without copying attacker calldata',
    });
  }
  return traceException;
}

export async function verifyZkpSubmission(ctx, S, lastEvent) {
  const { report, blockNum: N } = ctx;
  const zkInfo = S.zkInfo;
  if (zkInfo?.kind !== 'proof') return;

  // listen-workerによるclaim後の正当なclaimed更新はmanifestの元bytesと異なる。
  // Stage Cが独立再構築したsummaryがmanifest SHAと一致するときだけ、その元bytesを使う。
  const gcpSyntheticSummary = ctx.data?.emergencySource?.authority === 'gcp'
    && S.auto && ctx.data.emergencySource.syntheticSummary;
  const zkpSummary = selectZkpSummaryRaw({
    // summary は最大192 MiBになり得るため、正準JSON検査後は取得時の raw を保持しない。
    // parseCanonicalJson が往復一致を確認済みなので、ここでの JSON.stringify(data) は
    // 公開バイト列と byte-exact に同じである。
    publishedRaw: gcpSyntheticSummary ? JSON.stringify(gcpSyntheticSummary) : S.files?.summary?.raw
      ?? (S.files?.summary?.data ? JSON.stringify(S.files.summary.data) : null),
    rebuiltSummary: S.rebuiltSummary,
    manifest: gcpSyntheticSummary
      ? ctx.data.emergencySource.selectedManifest : S.files?.manifest?.data,
    blockNum: N,
  });
  recordEmergencyZkpMerkleMetadataDifference(ctx, S);
  report.fact('stageC.zkp', {
    kind: 'proof',
    epoch: zkInfo.epoch.index,
    verifier: zkInfo.epoch.verifier,
    vkey: zkInfo.epoch.vkey,
    guestSourceHash: zkInfo.epoch.guestSourceHash,
    cryptographicVerification: 'performed on-chain by the recorded epoch verifier',
  });
  if (!lastEvent && S.proofEventReadError instanceof ArchiveUnavailableError) {
    // イベント範囲を取得できずtxを特定できない。この先の4検査はすべてtx/提出高を要する。
    for (const name of ['zkProofFormat', 'zkPublicValues', 'zkPrevRegistrationWitness', 'futureAnchorsHash']) {
      report.unverified(`check.stageC.${name}`, S.proofEventReadError, { reason: 'archive_unavailable' });
    }
    return;
  }
  const inspected = await inspectProofSubmission({
    chain: ctx.chain,
    blockNum: N,
    root: S.blockState.root,
    event: lastEvent,
    epoch: zkInfo.epoch,
    artifacts: buildZkpArtifacts(S, zkpSummary.raw, ctx.data?.emergencySource),
    r2Base: ctx.cfg.r2Base,
    confirmationBlocks: ctx.cfg.pins.confirmationBlocks,
    emergencyMode: Boolean(ctx.data?.emergencySource),
    report,
  });

  // U-J2: only a registered fixed core permits this emergency difference.
  const traceException = recordZkpProofFormatForMode(ctx, inspected.format, lastEvent);

  if (ctx.data?.emergencySource?.authority === 'gcp'
      && inspected.publicValues?.cause === ZKP_COLLECTION_FAILURE_CAUSES.proofBoundToOtherManifest) {
    const index = await findGcpProofRegistration(ctx.chain, N,
      inspected.publicValues.proofBoundResultHash);
    if (index !== null) {
      ctx.data.emergencySource.gcpHistoricalProofHash = true;
      ctx.data.emergencySource.gcpProofRegistrationIndex = index;
    }
  }
  recordZkpPublicValuesCheck(ctx, inspected.publicValues, zkpSummary.source, lastEvent,
    traceException.accepted);
  if (inspected.resolvedSubmission?.call?.publicValues) {
    try {
      const claimed = decodePublicValues(inspected.resolvedSubmission.call.publicValues).futureAnchorsHash;
      const checked = await checkProofFutureAnchor(ctx.chain, N, lastEvent, claimed);
      S.futureAnchorCheck = checked;
      ctx.data.futureAnchorCheck = checked;
      if (checked.unavailableError instanceof ArchiveUnavailableError) report.unverified('check.stageC.futureAnchorsHash', checked.unavailableError, {reason:'archive_unavailable',provider:'unavailable'});
      else report.check('check.stageC.futureAnchorsHash', checked.status === 'fail'
        && isEmergencyCheckDowngradable('check.stageC.futureAnchorsHash', Boolean(ctx.data?.emergencySource))
        ? 'warn' : checked.status, checked);
    } catch (error) {
      report.check('check.stageC.futureAnchorsHash',
        isEmergencyCheckDowngradable('check.stageC.futureAnchorsHash', Boolean(ctx.data?.emergencySource))
          ? 'warn' : 'fail', { error: String(error.message || error) });
    }
  } else {
    report.check('check.stageC.futureAnchorsHash', 'skip', { reason: 'proof_calldata_unavailable' });
  }
  if (inspected.format.status !== 'pass' || inspected.publicValues.status !== 'pass') {
    S.anomalies.push(inspected.publicValues.status === 'unavailable'
      ? `ZKP public values could not be reproduced: ${conciseRpcText(inspected.publicValues.error, ctx.ui?.t)}`
      : 'ZKP submission calldata or public values did not match the public block data.');
  }

  await verifyPrevRegistrationWitness(ctx, S, lastEvent, inspected.resolvedSubmission);
}

/**
 * 周29（2026-09-22・ユーザー決定）: 証明が名乗った `prevRegistrationIndex` が、
 * **このブロックのグループ分け時点に対応する前ブロックの登録**かを記録で確かめる。
 *
 * 🔴 **`fail` にしない。** ユーザーの規則は「グループ分けの時点の N の配布を正典として扱う。
 *    それ以降に N の配布が変更しても反映しない」であり、その時点の登録が攻撃者のものであっても
 *    **許容する**。したがってこの検査の仕事は止めることではなく、
 *    **後から積まれた行が使われたことを第三者に見せること**である。
 * 🔴 見張り役の記録が読めないときは `skip`（読めなかったことを params に残す）。**pass にしない**。
 */
// R30-U-4: Stage B／緊急の組分け上限の fallback。chatOpenAt は grace を含まない。
// 周29 の証人検査③は別規則で、見張り役の game_groups firstSeenAt を使う。
export async function deriveGroupingChattingStartMs(chain, N, suppliedChatWindow = undefined) {
  const timing = await chain.getTimingConstants();
  const entryEndMs = timing.startTimeEntryMs + (N + 1) * timing.blockTimeMs;
  const chatWindow = suppliedChatWindow === undefined && typeof chain.chatWindow === 'function'
    ? await chain.chatWindow(N) : suppliedChatWindow;
  const graceSec = typeof chain.currentGrace === 'function'
    ? Number(await chain.currentGrace(N))
    : chatWindow?.chatCloseAt
      ? chatWindow.chatCloseAt
        - (Math.round(entryEndMs / 1000) + Math.round(timing.gamePeriodMs / 1000))
      : NaN;
  if (!Number.isFinite(entryEndMs) || !Number.isFinite(graceSec)) {
    throw new Error(`block ${N}: chain grouping time is unavailable`);
  }
  return { entryEndMs, graceSec, chattingStartMs: entryEndMs + graceSec * 1000 };
}

// R31-U-B: 名簿の選択は writer/復元クライアントと同じ共有関数だけに委ねる。
export async function resolveRosterRegistration(chain, N, time = null) {
  const window = time ?? await deriveGroupingChattingStartMs(chain, N);
  const key = rosterAnchorKey(N);
  const entryEndSec = Math.round(window.entryEndMs / 1000);
  const chattingStartSec = Math.round(window.chattingStartMs / 1000);
  const count = typeof chain.otherRegistrationCount === 'function'
    ? await chain.otherRegistrationCount(key) : null;
  if (count === null) {
    // Old HashStorage has no append-only getter. Retain the original current-value
    // comparison, explicitly marked legacy; it cannot prove earlier generations.
    const marker = typeof chain.getOtherHash === 'function'
      ? await chain.getOtherHash(key) : null;
    let block = null;
    if (marker?.updated) {
      try { block = await chain.getBlock(marker.updated); } catch { /* inspect reports time separately */ }
    }
    const at = block == null ? null : Number(block.timestamp);
    return { key, legacy: true, status: marker ? 'legacy' : 'none',
      index: marker ? 0 : null,
      row: marker ? { hash: marker.hash, registeredBlock: marker.updated, registeredAt: at } : null,
      first: marker && at >= entryEndSec
        ? { hash: marker.hash, registeredBlock: marker.updated, registeredAt: at, index: 0 } : null,
      firstMatching: marker && at >= entryEndSec
        ? { hash: marker.hash, registeredBlock: marker.updated, registeredAt: at, index: 0 } : null,
      lateCount: at != null && at >= chattingStartSec ? 1 : 0, preEntryCount: 0 };
  }
  if (typeof chain.otherRegistrationAt !== 'function') throw new Error('otherRegistrationAt is unavailable');
  const cache = new Map();
  const at = async (index) => {
    if (!cache.has(index)) cache.set(index, await chain.otherRegistrationAt(key, index));
    return cache.get(index);
  };
  const selected = await selectCanonicalRosterRegistration({
    count, at, entryEndSec, chattingStartSec, nowSec: chattingStartSec,
  });
  const first = selected.index == null ? null
    : { ...(await at(selected.preEntryCount)), index: selected.preEntryCount };
  let firstMatching = null;
  if (selected.index != null) {
    for (let index = selected.preEntryCount; index <= selected.index; index++) {
      const row = await at(index);
      if (lower(row.hash) === selected.row.hash) {
        firstMatching = { ...row, index };
        break;
      }
    }
  }
  return { ...selected, key, legacy: false, first, firstMatching };
}

export async function resolveRosterSubmissionEligibility(chain, N, safeTimestamp, chatOpenAt) {
  if (typeof chain.currentGrace !== 'function') throw new Error(`block ${N}: currentGrace reader unavailable`);
  const entryEndSec = Number(chatOpenAt);
  const grace = Number(await chain.currentGrace(N));
  const nowSec = Number(safeTimestamp);
  if (!Number.isSafeInteger(entryEndSec) || !Number.isSafeInteger(grace) || grace <= 0
      || !Number.isSafeInteger(nowSec)) throw new Error(`block ${N}: roster chain time or grace unavailable`);
  const entryEndMs = entryEndSec * 1000;
  if (!Number.isSafeInteger(entryEndMs)) throw new Error(`block ${N}: roster entry end unavailable`);
  const chattingStartSec = entryEndSec + grace;
  const registration = await resolveRosterRegistration(chain, N, {
    entryEndMs, chattingStartMs: chattingStartSec * 1000,
  });
  return evaluateRosterSubmissionEligibility({
    selection: registration, legacy: registration.legacy,
    chattingStartSec,
  });
}

// R30-U-4 の上限の意味は維持し、錨だけを正典 hash の応募終了後の最初の登録にする。
export async function deriveGroupingUpperBound(chain, N, suppliedChatWindow = undefined, rosterHash = null) {
  const key = rosterAnchorKey(N);
  const time = await deriveGroupingChattingStartMs(chain, N, suppliedChatWindow);
  let first = null;
  if (rosterHash !== false && String(rosterHash ?? '').toLowerCase() !== ZERO_ROOT) {
    const selected = await resolveRosterRegistration(chain, N, time);
    if (selected.row && String(selected.row.hash).toLowerCase() !== ZERO_ROOT && (rosterHash == null
        || String(selected.row.hash).toLowerCase() === String(rosterHash).toLowerCase())) {
      first = selected.firstMatching;
    }
  }
  if (first != null) {
      const registeredAt = Number(first.registeredAt);
      if (!Number.isSafeInteger(registeredAt) || registeredAt < 0) {
        throw new Error(`block ${N}: invalid roster anchor registration time`);
      }
      return { ...time, upperMs: Math.min(registeredAt * 1000, time.chattingStartMs),
        source: registeredAt * 1000 <= time.chattingStartMs
          ? 'matching_roster_anchor_registration' : 'chattingStart_before_roster_anchor',
        rosterKey: key, rosterHash: first.hash, rosterRegistrationBlock: first.registeredBlock,
        rosterRegistrationIndex: first.index ?? 0 };
  }
  return { ...time, upperMs: time.chattingStartMs, source: 'chattingStart_fallback', rosterKey: key };
}

export function registeredByGroupingUpperBound(row, upperMs) {
  const at = Number(row?.registeredAt);
  if (!Number.isSafeInteger(at) || at < 0) throw new Error('invalid result registration time');
  return at * 1000 <= upperMs;
}

export async function verifyPrevRegistrationWitness(ctx, S, proofEvent, resolvedSubmission = null) {
  const { report, blockNum: N } = ctx;
  if (N === 0) {
    report.check('check.stageC.zkPrevRegistrationWitness', 'skip', { reason: 'no_previous_block', prev: '-' });
    return;
  }
  const prev = N - 1;

  // ① 名乗った添字（calldata 第7引数）
  if (!proofEvent?.txHash) {
    report.check('check.stageC.zkPrevRegistrationWitness', 'skip', { reason: 'proof_tx_unavailable', prev });
    return;
  }
  let claimed;
  if (typeof resolvedSubmission?.prevRegistrationIndex === 'bigint') {
    claimed = {
      ok: true,
      functionName: resolvedSubmission.call?.functionName ?? 'resolved_proof_submission',
      prevRegistrationIndex: resolvedSubmission.prevRegistrationIndex,
    };
  } else {
    let calldata;
    try {
      calldata = (await ctx.chain.client.getTransaction({ hash: proofEvent.txHash })).input;
    } catch (error) {
      report.check('check.stageC.zkPrevRegistrationWitness', 'skip', { reason: 'proof_tx_unavailable', prev, error: String(error?.message || error) });
      return;
    }
    claimed = decodeProofPrevRegistrationIndex(calldata);
  }
  if (!claimed.ok) {
    report.check('check.stageC.zkPrevRegistrationWitness', 'skip', { reason: claimed.reason, prev, error: claimed.error ?? '-' });
    return;
  }

  // ② チェーンの追記履歴（状態読取・全件）
  let history;
  try {
    history = await ctx.chain.resultRegistrationHistory(prev);
  } catch (error) {
    report.check('check.stageC.zkPrevRegistrationWitness', 'skip', { reason: 'chain_history_unreadable', prev, error: String(error?.message || error) });
    return;
  }

  // ③ grace 由来の時刻は付随情報だけに使う。証人の締切は見張り役の初回観測で決める。
  let entryEndMs = null;
  let graceSec = null;
  try {
    if (S.chatWindow) {
      const timing = await ctx.chain.getTimingConstants();
      entryEndMs = timing.startTimeEntryMs + (N + 1) * timing.blockTimeMs;
      graceSec = S.chatWindow.chatCloseAt
        - (Math.round(entryEndMs / 1000) + Math.round(timing.gamePeriodMs / 1000));
    } else {
      ({ entryEndMs, graceSec } = await deriveGroupingChattingStartMs(ctx.chain, N, null));
    }
  } catch (error) {
    report.check('check.stageC.zkPrevRegistrationWitness', 'skip', {
      reason: 'grouping_deadline_unavailable', prev, error: String(error?.message || error),
    });
    return;
  }
  const graceDerivedDeadlineMs = Number.isFinite(graceSec) && Number.isFinite(entryEndMs)
    ? entryEndMs + graceSec * 1000 : null;

  // ④ 見張り役の記録（判定の材料）
  const observer = readObserverChainSnapshots(ctx.cfg.observerManifest);
  const claimedLabel = claimed.prevRegistrationIndex === PREV_REGISTRATION_SENTINEL
    ? 'sentinel' : String(claimed.prevRegistrationIndex);
  if (!observer.ok) {
    report.check('check.stageC.zkPrevRegistrationWitness', 'skip', {
      reason: 'observer_record_unavailable',
      observerReason: observer.reason,
      observerPath: ctx.cfg.observerManifest ?? null,
      observerFiles: observer.files.length,
      observerRejected: observer.rejected.slice(0, 3),
      prev,
      claimedIndex: claimedLabel,
      registrationCount: history.count,
      graceDerivedDeadlineIso: graceDerivedDeadlineMs == null
        ? null : new Date(graceDerivedDeadlineMs).toISOString(),
      error: observer.error ?? '-',
    });
    return;
  }
  const groupingDeadlineMs = groupingObservedAtMs(observer.records, N);
  if (groupingDeadlineMs == null) {
    report.check('check.stageC.zkPrevRegistrationWitness', 'skip', {
      reason: 'grouping_observation_unavailable',
      detail: `見張り役の記録に entries/block${N}/game_groups.json の firstSeenAt が無い`
        + '（grace から作った締切は admin に動かされるので代用しない）',
      observerPath: ctx.cfg.observerManifest ?? null,
      prev, claimedIndex: claimedLabel, registrationCount: history.count,
      graceDerivedDeadlineIso: graceDerivedDeadlineMs == null
        ? null : new Date(graceDerivedDeadlineMs).toISOString(),
    });
    return;
  }
  const selected = selectObserverResultWitness({
    snapshots: observer.snapshots, prevBlockNum: prev, entryEndMs, groupingDeadlineMs,
  });
  const witnessStats = {
    observerManifests: observer.manifestCount,
    observerSnapshotsForPrev: selected.consideredCount,
    snapshotsAtOrBeforeGrouping: selected.eligibleCount,
    snapshotsInGraceWindow: selected.inGraceWindowCount,
    distinctHashesInGraceWindow: selected.distinctHashesInGraceWindow,
    groupingDeadlineIso: groupingDeadlineMs == null ? null : new Date(groupingDeadlineMs).toISOString(),
  };
  if (!selected.ok) {
    report.check('check.stageC.zkPrevRegistrationWitness', 'skip', {
      reason: 'observer_record_unavailable',
      observerReason: selected.reason,
      observerPath: ctx.cfg.observerManifest ?? null,
      prev,
      claimedIndex: claimedLabel,
      registrationCount: history.count,
      ...witnessStats,
    });
    return;
  }

  const verdict = judgePrevRegistrationWitness({
    claimedIndex: claimed.prevRegistrationIndex, history, witness: selected.witness,
  });
  const params = {
    prev,
    claimedIndex: claimedLabel,
    registrationCount: history.count,
    claimedHash: verdict.claimedRow?.hash ?? null,
    claimedRegisteredBlock: verdict.claimedRow?.registeredBlock ?? null,
    // チェーン側 registeredAt は付随情報。grace を動かされると意味が変わるので判定には使わない。
    claimedRegisteredAtIso: verdict.claimedRow?.registeredAt
      ? new Date(verdict.claimedRow.registeredAt * 1000).toISOString() : null,
    witnessReadAt: selected.witness.readAt,
    witnessObservedBlock: selected.witness.observedBlock,
    witnessHash: selected.witness.resultHash?.hash ?? null,
    witnessUpdatedBlock: selected.witness.resultHash?.updated ?? null,
    witnessRegistrationCount: selected.witness.resultRegistrationCount,
    ...witnessStats,
    mismatches: verdict.mismatches.length === 0 ? '-' : verdict.mismatches.slice(0, 3),
  };
  report.check('check.stageC.zkPrevRegistrationWitness', verdict.status, params);
  report.fact('stageC.prevRegistrationWitness', { ...params, function: claimed.functionName });
}

// ============================================================
// vendored GameMasterDO のセットアップ（CONTRACT「vendored GameMasterDO の使い方」）
// env 値はチェーン由来の getTimingConstants() のみ（workers/.env は使わない）。
// ============================================================
/// R26-C4: 検証に使う EthLock を **`TokenMining.ethLock()`（チェーン値）へ束縛**する。
///
/// なぜ必要か: デポッター葉は `to = address(0)` で個別配当額も持たない。送金先と額は
/// 請求時に契約が `ethLock.getLock(id).lockOwnerAddress` から決める
/// （`TokenMining._resolveLockRewardSplit`）。したがって「どの EthLock を読むか」を
/// 同梱 config の固定値で決めていると、運営が `setEthLock` へ別実装
/// （amount / idTo / unlockTime は本物と同一で `depositerAddress` だけ攻撃者）を配線しても、
/// 検証ツールは**本物の台帳**を見て PASS を出してしまう。葉のコミットメントは
/// 送金先を含まないのでこの差を検出できない。
///
/// Evidence（Q-4）と同じ思想で、config の値は**参考値**（乖離の告知のみ）に降格する。
async function bindEthLockAuthority(ctx, S) {
  const { report, ui } = ctx;
  // 読めない・実装が無い場合でも**全体を落とさない**（TypeError で `##RESULT fatal` / exit 3 に
  // なると「契約コード欠落」と同じ重い信号になり、F-6 で直した逆転をまた作ってしまう）。
  // 解決できないこと自体は下で FAIL として記録する。
  const onchain = typeof ctx.chain?.ethLockAddress === 'function'
    ? await ctx.chain.ethLockAddress().catch(() => null)
    : null;
  if (!onchain) {
    // root 提出は `require(ethLock != address(0))` なので、root がある状態で 0x0 は異常。
    report.check('check.stageC.ethLockWiring', 'fail', { onchain: '0x0', config: ctx.cfg.contracts.ethLock || '-' });
    S.anomalies.push(ui.t('stageC.anomaly.ethLockUnwired'));
    ctx.ethLockAuthority = null;
    return false;
  }
  const cfgAddr = ctx.cfg.contracts.ethLock;
  const matches = !!cfgAddr && lower(cfgAddr) === lower(onchain);
  // 一致しない＝同梱 config が古いか、運営が別実装を配線した。どちらかを区別できないので
  // **チェーン値で検証を続行しつつ FAIL で記録する**（skip や warn へ降格しない）。
  report.check('check.stageC.ethLockWiring', matches ? 'pass' : 'fail', {
    onchain, config: cfgAddr || '-',
  });
  if (!matches) {
    S.anomalies.push(ui.t('stageC.anomaly.ethLockAddressDiffers', {
      onchain, config: cfgAddr || '-' }));
  }
  ctx.ethLockAuthority = onchain;
  return matches;
}

function makeGm(ctx, timing, published) {
  // R26-C4: 権威はチェーン値。`bindEthLockAuthority` を先に呼んでいないのは配線ミスなので
  // 素通しではなく throw する（fail-closed）。
  if (ctx.ethLockAuthority === undefined) {
    throw new Error('[stageC] makeGm called before bindEthLockAuthority — EthLock authority unresolved');
  }
  const gm = withVendorLogging(() => new GameMasterDO({ storage: {} }, {
    ETH_LOCK_CONTRACT_ADDRESS: ctx.ethLockAuthority || ctx.cfg.contracts.ethLock,
    START_TIME: String(timing.startTimeEntryMs),   // 応募期間開始（Evidence.START_TIME×1000）
    BLOCK_TIME: String(timing.blockTimeMs),
    GAME_PERIOD: String(timing.gamePeriodMs),
    SUBMIT_PERIOD: String(timing.submitPeriodMs),
  }));
  gm.createReadOnlyClient = () => ctx.chain.client; // 実RPC読取（deposit-verify-test.mjs の前例）
  // vendorはエラーをconsoleへ書くため、履歴不足は呼出前に短い例外へ変換する。
  gm.isArchiveStateUnavailable = (error) => historicalStateFailure(error) === 'archive_unavailable';
  // Stage B がチェーン値と照合した selection を再利用する。Stage C で別世代を読み直さない。
  gm.readDepositSelectionK11 = async () => {
    const target = ctx.data.gameSelection?.targetBlockNum;
    if (!Number.isSafeInteger(target) || target < 0) throw new Error('[B1] invalid K11 targetBlockNum in Stage B game_selection.json');
    return BigInt(target);
  };
  gm.getR2Object = async (key) => {
    // buildBlockSummaryWithResults が majorLangs 継承のため summary.json を読む → 公表版を返す
    if (published && published[key] !== undefined) return published[key];
    const res = await ctx.r2.fetchJson(key);
    return res ? res.data : null;
  };
  return gm;
}

// ============================================================
// Step 2: R2 一式取得
// ============================================================
export async function downloadArtifacts(ctx, groupIds, S) {
  const N = ctx.blockNum;
  const { ui } = ctx;
  // 🔴 F-6（2026-08-08・ラウンド20 判断不要-6）: 「読めない公開データ」は**欠落と同じ扱い**。
  //   ・`parseError` … JSON として読めない（旧実装は共通入口で throw → exit 3 / fatal）
  //   ・オブジェクトでない … `null` / 数値 / 文字列。とくに `manifest.json = null` は
  //     `if (!manifest) return;` の fail-open で **20 チェックが無記録のまま消え**、
  //     その後 `results.js:1562` の `Cannot read properties of null (reading 'rules')` で
  //     exit 3（キー名も原因も出ない）に落ちていた。
  //   どちらも「root 提出済み ⟹ 公開データは全部揃っている」の破れなので FAIL（exit 2）。
  const need = async (key, required) => {
    const res = await ctx.r2.fetchJson(key);
    if (res && (res.parseError || res.sizeError || res.data === null || typeof res.data !== 'object')) {
      const detail = res.parseError || res.sizeError || 'not a JSON object';
      S.corrupt.push(`${key}: ${detail}`);
      return null;
    }
    if (!res && required) S.missing.push(key);
    return res;
  };
  S.files = {
    selection: await need(`entries/block${N}/game_selection.json`, !S.auto),
    gameGroups: await need(`entries/block${N}/game_groups.json`, !S.auto && !S.noGame && !S.timelineNoGame),
    summary: await need(`games/block${N}/summary.json`, true),
    merkle: await need(`merkle/block_${N}.json`, ctx.data?.emergencySource?.authority !== 'gcp'),
    manifest: await need(`verification/block${N}/manifest.json`, true),
    evidenceReport: await need(`verification/block${N}/evidence-report.json`, false),
    evidenceSegments: await need(`games/block${N}/zkp/evidence-segments.json`, false),
    // 必須性は外側manifest.filesの宣言hash照合で判定する。ここでは取得対象へ必ず含めるが、
    // 未宣言の旧/敵対fixtureを汎用downloadsで早期停止させずmanifestFileListまで到達させる。
    stage3Manifest: await need(`verification/block${N}/stage3/manifest.json`, false),
    autoResult: null,
    autoRoster: null,
    // 🔴 Q-6（2026-08-08）: 名簿は P2P 冗長経路の**信頼の起点**。manifest に載るようになった。
    //    ⚠️ ここでは `required: false` にする（＝汎用の「公開データ欠落」FAIL には載せない）。
    //       不在はキャッシュ照合側では `skip` とし、専用の `rosterLiveAnchor` が
    //       オンチェーン固定済みmanifestと実ファイルhashの欠落を **FAIL** として記録する。
    rosterIndex: await need(`games/block${N}/roster/index.json`, false),
    rosterManifest: await need(`games/block${N}/roster/manifest.json`, false),
    groups: new Map(),
    rosters: new Map(),
  };
  if (ctx.data?.emergencySource?.authority === 'gcp' && !S.files.merkle) {
    recordEmergencyDifference(ctx, {
      checkId: 'emergency.gcpMerkleMetadataRebuilt', what: `merkle/block_${N}.json`,
      chain: { root: S.blockState.root },
      rebuilt: { adoption: 'GameMasterDO.publishMerkleTree' },
      reason: 'saved Merkle metadata is comparison material; the canonical writer recreates it',
    });
  }

  let autoResultKey = null;
  if (S.auto && Number(S.files.summary?.data?.schemaVersion || 1) >= 2) {
    autoResultKey = `games/block${N}/auto-results.json`;
    const declared = S.files.summary?.data?.groups?.[0]?.detailKey;
    if (S.files.summary?.data?.resultLayout !== 'auto-distribution-page-v1' || declared !== autoResultKey) {
      S.corrupt.push(`games/block${N}/summary.json: invalid auto result page declaration`);
    } else {
      S.files.autoResult = await need(autoResultKey, true);
    }
  }
  if (S.auto && [1, 2].includes(ctx.data.gameSelection?.players?.length)) {
    S.files.autoRoster = await need(`games/block${N}/roster/group0.json`, !ctx.data?.emergencySource);
  }

  // group/roster は最大420組ある。全部の raw と巨大 submissions を同時保持せず、
  // manifest宣言とのbyte hashをその場で確認してから軽量投影だけ残す。
  const precheck = async (key, initial, { keepRaw = false } = {}) => {
    let entry = initial;
    const declared = S.files.manifest?.data?.files?.[key] ?? null;
    let raw = entry?.raw ?? null;
    let bad = declared == null ? raw != null : raw == null || sha256HexOfString(raw) !== declared;
    if (bad && declared != null) {
      const fresh = await refetchDeclaredRaw(ctx.r2, key, declared);
      if (fresh) {
        entry = fresh;
        raw = fresh.raw;
        bad = false;
        ui.println(ui.t('stageC.cacheRefreshed', { key }));
      }
    }
    const parked = bad && shouldParkManifestHashMismatch(
      key, N, S.files.summary?.data?.schemaVersion, raw, declared
    );
    S.precheckedHashes.set(key, {
      bad,
      parked,
      actualHash: raw == null ? null : sha256HexOfString(raw),
    });
    if (!keepRaw) {
      ctx.r2.releaseRaw?.(key);
      if (entry) entry.raw = undefined;
    }
    return entry;
  };

  const fixed = [
    ['selection', `entries/block${N}/game_selection.json`],
    ['gameGroups', `entries/block${N}/game_groups.json`],
    ['summary', `games/block${N}/summary.json`],
    ['merkle', `merkle/block_${N}.json`],
    ['evidenceReport', `verification/block${N}/evidence-report.json`],
    ['evidenceSegments', `games/block${N}/zkp/evidence-segments.json`],
    ['stage3Manifest', `verification/block${N}/stage3/manifest.json`],
    ['autoResult', autoResultKey],
    ['autoRoster', S.files.autoRoster ? `games/block${N}/roster/group0.json` : null],
    ['rosterIndex', `games/block${N}/roster/index.json`],
  ];
  for (const [slot, key] of fixed) {
    if (!key || !S.files[slot]) continue;
    // summary.raw は後段の正準JSON検査まで、merkle/selection/stage3Manifest.raw は
    // ZKP public valuesの共有collector再現まで残す。全てmanifest宣言sha256を照合済み。
    S.files[slot] = await precheck(key, S.files[slot],
      { keepRaw: ['summary', 'merkle', 'selection', 'stage3Manifest', 'autoRoster'].includes(slot) });
  }

  // B-3: manifest に載る木再構築用分冊も、通常アーティファクトと同じ byte 照合へ通す。
  // 宣言から抜かれていても正典メタから独立に列挙するため、後段の files 一覧照合が必ず鳴る。
  const merkleRebuildKeys = merkleRebuildArtifactKeys(N, S.files.merkle?.data);
  for (const key of merkleRebuildKeys) {
    let res = await need(key, true);
    if (!res) continue;
    res = await precheck(key, res);
    res.data = undefined;
    ctx.r2.release?.(key);
  }

  for (const gid of groupIds) {
    const groupKey = `games/block${N}/group${gid}.json`;
    // V25-03: group archive はEvidence採点の権威ではない。欠損は後段でcommit済みrosterから
    // 合成し、有効Evidenceが1件も無ければそこでFAILする。
    let res = await need(groupKey, false);
    if (res) {
      res = await precheck(groupKey, res);
      const full = res?.data;
      if (full && typeof full === 'object') {
        // Evidenceの名簿・画面表示照合に要る部分だけ残す。採点時は同じcacheを1組ずつ再読込。
        S.files.groups.set(gid, {
          data: {
            meta: full.meta,
            members: full.members,
            gameResults: full.gameResults,
            canonicalTimeline: full.canonicalTimeline,
          },
          path: res.path,
        });
      }
      res.data = undefined;
      ctx.r2.release?.(groupKey);
    }
    const rosterKey = `games/block${N}/roster/group${gid}.json`;
    let ros = await need(rosterKey, false);
    if (ros) {
      ros = await precheck(rosterKey, ros);
      S.files.rosters.set(gid, ros);
    }
  }
}

// ============================================================
// Step 3: manifest 照合（game-master-DO.js:2813-2907 の写像）
// ============================================================
// 🔴 便 X1 / Q-A（2026-09-21・ユーザー決定 (a)）: 登録回数の増加を「事故差」に数えない。
//
//   `HashStorage.registerResultHash` の直前のコメントは逐語で次のとおり:
//     「resultHash は何度でも上書き可能（障害時の再計算・再登録に対応）だが、
//       登録回数は単調増加カウンタに記録され改ざんできない（差し替えの可視化）。」
//   ⇒ 回数カウンタは**可視化**のためのものであって、違反の印ではない。
//   さらに緊急復旧の手順書は再登録を必須にしているので、**正しく復旧すると必ず回数が2以上**に
//   なる。回数を差に数えると、正常な復旧が毎回「事故差あり」＝終了コード4 になってしまう。
//
//   🔴 値の正しさは別の検査が見ている。`checkManifest()`（下の 3b）が
//   `inspectResultManifestAnchor()` と `classifyResultManifestAnchorForMode()` で
//   チェーンの hash と再計算した core を突き合わせ、食い違えば
//   `check.stageC.manifestAnchor` の差として1件記録する。回数側で数えていたのは二重計上だった。
//
//   だから `recordEmergencyDifference()` の呼び出しだけを外す。
//   `warn` と `S.anomalies` への記録は**残す**（可視化は続ける）。`skip`/`pass` の枝も変えない。
export async function checkResultReregistration(ctx, S) {
  const { report, ui, blockNum: N } = ctx;
  const regCount = await ctx.chain.resultRegistrationCount(N).catch(() => null);
  if (regCount == null) {
    report.check('check.stageC.resultReregistration', 'skip', { reason: 'unreadable' });
  } else if (Number(regCount) > 1) {
    report.check('check.stageC.resultReregistration', 'warn', { count: Number(regCount) });
    S.anomalies.push(ui.t('stageC.anomaly.reregistered', { count: Number(regCount) }));
  } else {
    report.check('check.stageC.resultReregistration', 'pass', { count: Number(regCount) });
  }
}

// E11-03: 結果manifestは「現在のhashが一致する」だけでなく、root提出より前に
// 登録されて初めて時点コミットメントになる。RPC読取不能を改竄FAILとは混同しない。
export async function inspectResultManifestAnchor(chain, anchored, coreHash, verificationStartedAtSec) {
  if (!anchored || !anchored.updated || Number(anchored.updated) === 0) {
    return { status: 'warn', reason: 'not_anchored', updatedTimestamp: null };
  }
  if (lower(anchored.hash) !== lower(coreHash)) {
    return { status: 'fail', reason: 'hash_mismatch', updatedTimestamp: null };
  }
  try {
    const block = await chain.getBlock(anchored.updated);
    const updatedTimestamp = Number(block.timestamp);
    if (!Number.isFinite(verificationStartedAtSec) || verificationStartedAtSec <= 0) {
      return { status: 'fail', reason: 'root_submission_time_unavailable', updatedTimestamp };
    }
    if (updatedTimestamp >= verificationStartedAtSec) {
      return { status: 'fail', reason: 'anchored_after_root_submission', updatedTimestamp };
    }
    return { status: 'pass', reason: 'anchored_before_root_submission', updatedTimestamp };
  } catch (error) {
    if (error instanceof ArchiveUnavailableError
        && (!Number.isFinite(verificationStartedAtSec) || verificationStartedAtSec <= 0)) {
      return { status: 'fail', reason: 'root_submission_time_unavailable', updatedTimestamp: null };
    }
    return {
      status: 'warn',
      reason: 'anchor_registration_time_unreadable',
      ...(error instanceof ArchiveUnavailableError ? { unavailableError: error } : {}),
      error: error?.message || String(error),
      updatedTimestamp: null,
    };
  }
}

export const EMERGENCY_RESULT_ANCHOR_DIFFERENCE_REASONS = Object.freeze([
  'not_anchored',
  'hash_mismatch',
  'root_submission_time_unavailable',
  'anchored_after_root_submission',
]);

export function classifyResultManifestAnchorForMode(anchorInspection, emergencyMode) {
  const accepted = isEmergencyCheckDowngradable('check.stageC.manifestAnchor', emergencyMode)
    && EMERGENCY_RESULT_ANCHOR_DIFFERENCE_REASONS.includes(anchorInspection.reason);
  return {
    accepted,
    status: accepted ? 'warn' : anchorInspection.status,
  };
}

export function checkManifestFileList(ctx, S) {
  const { report, blockNum: N } = ctx;
  const manifest = S.files.manifest?.data;
  const sortedGroupIds = [...S.groupIds].sort((a, b) => a - b);
  const autoResultKeys = S.auto && Number(S.files.summary?.data?.schemaVersion || 1) >= 2
    ? [`games/block${N}/auto-results.json`] : [];
  const merkleRebuildKeys = merkleRebuildArtifactKeys(N, S.files.merkle?.data);
  const expectedKeys = [
    `entries/block${N}/game_selection.json`,
    `entries/block${N}/game_groups.json`,
    `games/block${N}/summary.json`,
    `merkle/block_${N}.json`,
    ...merkleRebuildKeys,
    `verification/block${N}/evidence-report.json`,
    `games/block${N}/zkp/evidence-segments.json`,
    `verification/block${N}/stage3/manifest.json`,
    ...sortedGroupIds.map(g => `games/block${N}/group${g}.json`),
    ...autoResultKeys,
    `games/block${N}/roster/index.json`,
    ...sortedGroupIds.map(g => `games/block${N}/roster/group${g}.json`),
    ...(S.auto && [1, 2].includes(S.files.summary?.data?.totalPlayers)
      ? [`games/block${N}/roster/group0.json`] : []),
  ];
  const actualKeys = Object.keys(manifest.files || {});
  report.check('check.stageC.manifestFileList',
    JSON.stringify(expectedKeys) === JSON.stringify(actualKeys) ? 'pass' : 'fail',
    { expected: expectedKeys.length, actual: actualKeys.length });
  return { expectedKeys, actualKeys };
}

export async function checkManifest(ctx, S, timing) {
  const { report, ui, blockNum: N } = ctx;
  if (ctx.data.emergencySource?.authority === 'gcp') {
    const reason = 'GCP authority: public result manifest is not an input';
    report.check('check.stageC.manifestSelfConsistent', 'skip', { reason });
    report.check('check.stageC.manifestAnchor', 'skip', { reason });
    report.check('check.stageC.manifestFileList', 'skip', { reason });
    report.check('check.stageC.manifestFiles', 'skip', { reason });
    report.check('check.stageC.rulesPins', 'skip', { reason });
    report.check('check.stageC.rulesReward', 'skip', { reason });
    report.check('check.stageC.rulesTiming', 'skip', { reason });
    return;
  }
  const manifest = S.files.manifest?.data;
  // 🔴 F-6: `manifest.json = null` の fail-open（実測 **20 チェックが無記録で消失**し、
  //    その後 `Cannot read properties of null (reading 'rules')` で exit 3）を塞ぐ。
  //    ここに来る時点で `downloadArtifacts` の corrupt 判定を通っているはずなので、
  //    到達したら「入口の検査が抜けた」ことを意味する＝黙って return しない。
  if (!manifest || typeof manifest !== 'object') {
    report.check('check.stageC.manifestSelfConsistent', 'fail',
      { reason: 'manifest is not an object', got: manifest === null ? 'null' : typeof manifest });
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }

  // 3a. core 再ハッシュ（:2877-2878 と同一: 決定的 core のみ・minified）
  const coreStr = JSON.stringify({
    blockNum: manifest.blockNum, algorithm: manifest.algorithm,
    rules: manifest.rules, files: manifest.files,
  });
  const coreHash = '0x' + sha256HexOfString(coreStr);
  const selfConsistency = classifyManifestSelfConsistency({
    coreHash,
    declaredManifestHash: manifest.manifestHash,
    expectedBlockNum: N,
    declaredBlockNum: manifest.blockNum,
    declaredAlgorithm: manifest.algorithm,
    emergencyMode: Boolean(ctx.data.emergencySource),
  });
  report.check('check.stageC.manifestSelfConsistent',
    selfConsistency.status,
    {
      computed: coreHash,
      declared: manifest.manifestHash,
      blockNum: { computed: N, declared: manifest.blockNum },
      algorithm: { computed: 'sha256', declared: manifest.algorithm },
    });

  // 3b. オンチェーンアンカー（HashStorage.getResultHash）
  const anchored = await ctx.chain.getResultHash(N);
  const anchorInspection = await inspectResultManifestAnchor(
    ctx.chain, anchored, coreHash, Number(S.blockState?.verificationStartedAt),
  );
  const anchorDecision = classifyResultManifestAnchorForMode(
    anchorInspection,
    Boolean(ctx.data.emergencySource),
  );
  const recordAnchor = anchorInspection.unavailableError instanceof ArchiveUnavailableError
    ? (_id, _status, params) => report.unverified(_id, anchorInspection.unavailableError, params)
    : report.check;
  recordAnchor('check.stageC.manifestAnchor', anchorDecision.status, {
    reason: anchorInspection.reason,
    onchain: anchored?.hash ?? null,
    computed: coreHash,
    updatedBlock: anchored?.updated ?? null,
    updatedTimestamp: anchorInspection.updatedTimestamp,
    rootSubmittedAt: Number(S.blockState?.verificationStartedAt) || null,
    error: anchorInspection.error ?? '-',
  });
  if (selfConsistency.emergencyManifestHashLabelDifference) {
    recordEmergencyDifference(ctx, {
      checkId: 'check.stageC.manifestSelfConsistent',
      what: 'published manifestHash label differs from the computed manifestCore sha256',
      chain: { manifestCoreHash: anchored?.hash ?? null },
      rebuilt: { manifestCoreHash: coreHash },
      params: {
        declaredManifestHash: manifest.manifestHash ?? null,
        computedManifestCoreHash: coreHash,
      },
      reason: 'manifestHash is a self-declared label outside manifestCore; the chain marker is checked separately',
    });
  }
  if (anchorDecision.accepted) {
    recordEmergencyDifference(ctx, {
      checkId: 'check.stageC.manifestAnchor',
      what: 'result manifest chain marker or registration order differs from the emergency reconstruction',
      chain: {
        reason: anchorInspection.reason,
        hash: anchored?.hash ?? null,
        updatedBlock: anchored?.updated ?? null,
        updatedTimestamp: anchorInspection.updatedTimestamp,
        rootSubmittedAt: Number(S.blockState?.verificationStartedAt) || null,
      },
      rebuilt: { manifestCoreHash: coreHash },
      reason: 'the recovery transaction registers this rebuilt manifest immediately before root submission',
    });
  }
  if (anchorInspection.reason === 'not_anchored') {
    S.anomalies.push(ui.t('stageC.anomaly.notAnchored'));
  } else if (anchorInspection.reason === 'anchored_after_root_submission') {
    S.anomalies.push(ui.t('stageC.anomaly.manifestAnchorLate', {
      anchoredAt: anchorInspection.updatedTimestamp,
      rootAt: Number(S.blockState?.verificationStartedAt) || '-',
    }));
  } else if (anchorInspection.reason === 'anchor_registration_time_unreadable') {
    S.anomalies.push(ui.t('stageC.anomaly.manifestAnchorTimeUnreadable', {
      error: anchorInspection.error,
    }));
  }
  await checkResultReregistration(ctx, S);

  // 3c. files キー一覧（:2815-2822 と同一の順序・グループは数値昇順）
  //     B-3: Merkle 木再構築用分冊をメタから列挙し、merkle メタ直後に挿入する。
  //     Q-6: 名簿（roster/index.json ＋ roster/group{G}.json）も目録に載る。
  const { actualKeys } = checkManifestFileList(ctx, S);

  // 3d. files の各 sha256 == 手元の生バイト sha256（差し替え検出）
  //
  // 🔴 `rawOf` は必ず `Object.create(null)`（2026-08-07）。引く鍵は `manifest.files` の
  //   キー＝**運営が書いた公開バイト列そのもの**で、`JSON.parse` は `"__proto__"` すら
  //   own property として復元するため任意の文字列が来る。素の `{}` だと
  //   `rawOf['toString']` 等が Object.prototype の関数を返し、下の
  //   `sha256HexOfString(raw)` の `Buffer.from(関数,'utf8')` が TypeError を投げる。
  //   それは index.js:242-245 の最外殻 catch に落ちて `##RESULT fatal` / exit 3 になり、
  //   「運営の不正を検出した」ではなく「ツールが原因不明で落ちた」という出方をする
  //   （以降の採点再現・merkle・タイムラインは全部スキップされる）。
  //   壊れた／細工された公開データは運営側の問題なので FAIL（exit 2）で報告する。
  const rawOf = Object.create(null);
  rawOf[`entries/block${N}/game_selection.json`] = S.files.selection?.raw ?? null;
  rawOf[`entries/block${N}/game_groups.json`] = S.files.gameGroups?.raw ?? null;
  rawOf[`games/block${N}/summary.json`] = S.files.summary?.raw ?? null;
  rawOf[`merkle/block_${N}.json`] = S.files.merkle?.raw ?? null;
  rawOf[`verification/block${N}/evidence-report.json`] = S.files.evidenceReport?.raw ?? null;
  rawOf[`games/block${N}/zkp/evidence-segments.json`] = S.files.evidenceSegments?.raw ?? null;
  rawOf[`verification/block${N}/stage3/manifest.json`] = S.files.stage3Manifest?.raw ?? null;
  for (const [gid, res] of S.files.groups) rawOf[`games/block${N}/group${gid}.json`] = res?.raw ?? null;
  rawOf[`games/block${N}/auto-results.json`] = S.files.autoResult?.raw ?? null;
  // Q-6: 名簿。差し替えられていれば sha256 が合わない＝ここで FAIL する（immutable 扱い）。
  rawOf[`games/block${N}/roster/index.json`] = S.files.rosterIndex?.raw ?? null;
  for (const [gid, res] of S.files.rosters) rawOf[`games/block${N}/roster/group${gid}.json`] = res?.raw ?? null;
  if (S.files.autoRoster) rawOf[`games/block${N}/roster/group0.json`] = S.files.autoRoster.raw ?? null;

  // G5: 2段階判定 — listen-worker（index_new.js:464-550）が請求検知後に書き換える
  // claim可変アーティファクト（schema v1 summary.json の members[].claimed /
  // depositor_results[].claimed、group{G}.json / auto-results.json の gameResults[].claimed）の
  // sha256 不一致は、いったん保留リストに積み、
  // Stage C 末尾で「summaryMatch＋group{G}.json / gameResults 内容照合が全て PASS」
  // の場合に限り WARN へ降格する
  //（settleManifestParked）。immutable 系（selection/groups/merkle/evidence-report）は常に FAIL。
  // 不一致時の鮮度回復先: key → S.files 側の参照を最新エントリで差し替える
  //（--reuse で古いフェーズのキャッシュを掴んだ場合、後続ステップも最新バイトで走らせるため）
  const applyRefresh = (key, entry) => {
    if (key === `entries/block${N}/game_selection.json`) S.files.selection = entry;
    else if (key === `entries/block${N}/game_groups.json`) S.files.gameGroups = entry;
    else if (key === `games/block${N}/summary.json`) { S.files.summary = entry; ctx.data.summary = entry.data; }
    else if (key === `merkle/block_${N}.json`) S.files.merkle = entry;
    else if (key === `verification/block${N}/evidence-report.json`) S.files.evidenceReport = entry;
    else if (key === `games/block${N}/zkp/evidence-segments.json`) S.files.evidenceSegments = entry;
    else if (key === `verification/block${N}/stage3/manifest.json`) S.files.stage3Manifest = entry;
    else if (key === `games/block${N}/auto-results.json`) S.files.autoResult = entry;
    else if (key === `games/block${N}/roster/group0.json` && S.auto) S.files.autoRoster = entry;
    else if (key === `games/block${N}/roster/index.json`) S.files.rosterIndex = entry;
    else {
      const mr = key.match(new RegExp(`^games/block${N}/roster/group(\\d+)\\.json$`));
      if (mr) { S.files.rosters.set(Number(mr[1]), entry); return; }
      const m = key.match(new RegExp(`^games/block${N}/group(\\d+)\\.json$`));
      if (m) S.files.groups.set(Number(m[1]), entry);
    }
  };

  const fileFailures = [];
  const parked = [];
  const optionalUnavailable = [];
  for (const key of actualKeys) {
    const prechecked = S.precheckedHashes.get(key);
    if (prechecked) {
      if (prechecked.bad) {
        if (prechecked.parked) parked.push(key);
        else fileFailures.push(key);
      }
      continue;
    }
    const declared = manifest.files[key];
    let raw = rawOf[key] ?? null;
    if (declared == null && raw == null) continue;               // 未公開（autoDistribute等）＝整合
    // V25-03: rosterはselection/groupingから再構築でき、group archiveの採点入力はEvidenceが
    // 権威になる。宣言hashがあるのに配信元から取れない「availability」は、内容不一致と
    // 同じFAILにしない。archive救済の成立条件（有効Evidenceあり）は採点入口で別途強制する。
    if (raw == null && (/^games\/block\d+\/group\d+\.json$/.test(key)
        || /^games\/block\d+\/roster\/(?:index|group\d+)\.json$/.test(key))) {
      optionalUnavailable.push(key);
      continue;
    }
    // 🔴 R29-B-5b-02（2026-09-21・緊急モード限定・1鍵限定）: 便 W1 が「公開 Stage 3 manifest は
    //    権威ではなく比較のための証跡」にした結果、その鍵は固定一式の fileMap から落ちうる。
    //    ここで FAIL にすると emergency.js の輸出関門（assertEmergencyVerificationGate）が
    //    拒否し、W1 が救おうとしたまさにその盤面で緊急輸出が0バイトになる。
    //    採用する Stage 3 入力 manifest は publishStage3InputManifest が再計算 pin から
    //    作り直すので、ここを warn にしても攻撃者のバイトは固定一式へ入らない。
    // 🔴 通常モード（ctx.data.emergencySource が無い）と他の宣言鍵は1ミリも変えない。
    //    許容集合（EMERGENCY_ALLOWED_DIFFERENCE_CHECKS）にも降格集合にも1件も足していない。
    if (raw == null && ctx.data?.emergencySource
        && key === `verification/block${N}/stage3/manifest.json`) {
      optionalUnavailable.push(key);
      recordEmergencyDifference(ctx, {
        checkId: 'emergency.stage3WitnessUnavailable',
        what: `${key}: the published Stage 3 input manifest is unavailable in the fixed bundle`,
        chain: { stage3ManifestKey: key, declaredSha256: declared ?? null },
        rebuilt: { adoption: 'rebuild the Stage 3 input manifest from the independent recomputation' },
        reason: 'the published Stage 3 artifacts are evidence only; the recomputed manifest is adopted instead',
      });
      continue;
    }
    // R29-D-2-02: 保存世代が1つも無い再生成物は、公開版のhash照合を warn＋差分として残し、
    // 固定一式の正準 writer に作り直させる。対象は上の census (i) allowlist だけで、
    // 公開バイトを運ぶ (ii) の鍵や通常モードは従来どおり FAIL のまま。
    if (raw == null && ctx.data?.emergencySource
        && isEmergencyRegeneratedResultArtifact(key, N)) {
      optionalUnavailable.push(key);
      recordEmergencyDifference(ctx, {
        checkId: 'check.stageC.downloads',
        what: `${key}: the declared public artifact has no saved generation`,
        chain: { key, declaredSha256: declared ?? null },
        rebuilt: { adoption: 'regenerate this artifact with the canonical fixed-bundle writer' },
        reason: 'the fixed bundle does not carry these public bytes and deterministically regenerates them',
      });
      continue;
    }
    let bad = false;
    if (declared == null && raw != null) bad = true;
    else if (raw == null) bad = true;                            // 宣言ありなのに取得不能
    else if (sha256HexOfString(raw) !== declared) bad = true;
    // 不一致は「--reuse による古いキャッシュ」の可能性があるため、キャッシュを無視して
    // R2から取り直して再判定する。本物の差し替え・改ざんなら再取得後も不一致＝FAIL維持。
    if (bad && declared != null) {
      const fresh = await refetchDeclaredRaw(ctx.r2, key, declared);
      if (fresh) {
        applyRefresh(key, fresh);
        rawOf[key] = fresh.raw;
        raw = fresh.raw;
        ui.println(ui.t('stageC.cacheRefreshed', { key }));
        bad = false;
      }
    }
    if (!bad) continue;
    if (shouldParkManifestHashMismatch(
      key, N, S.files.summary?.data?.schemaVersion, raw, declared
    )) parked.push(key);
    else fileFailures.push(key);
  }
  S.manifestChecked = actualKeys.length;
  if (fileFailures.length > 0) {
    // immutable 系の不一致あり → 保留分も含めて即 FAIL（降格なし）
    const all = fileFailures.concat(parked);
    report.check('check.stageC.manifestFiles', 'fail', { failures: all.join(', '), checked: actualKeys.length });
    S.anomalies.push(ui.t('stageC.anomaly.fileHashMismatch', { files: all.join(', ') }));
    S.manifestParked = [];
  } else if (parked.length > 0) {
    // 暫定 FAIL（Stage C 末尾で settleManifestParked が確定させる。途中終了時はこの FAIL が残る＝安全側）
    report.check('check.stageC.manifestFiles', 'fail', { failures: parked.join(', '), checked: actualKeys.length });
    S.manifestParked = parked;
  } else if (optionalUnavailable.length > 0) {
    report.check('check.stageC.manifestFiles', 'warn', {
      failures: `unavailable/reconstructed: ${optionalUnavailable.join(', ')}`,
      checked: actualKeys.length,
    });
    S.optionalUnavailable = optionalUnavailable;
    S.manifestParked = [];
  } else {
    report.check('check.stageC.manifestFiles', 'pass', { failures: '-', checked: actualKeys.length });
    S.manifestParked = [];
  }

  // 3e. rules を ピン値と照合（G11: 採点に影響するルールの逸脱は FAIL。
  // 正当なルール変更は --config の pins 上書きで明示承認する運用 — README参照）
  const rules = manifest.rules || {};
  const pins = ctx.cfg.pins;
  const deviations = [];
  if (rules.minChars !== pins.minChars) deviations.push(`minChars=${rules.minChars}`);
  if (rules.minMessages !== pins.minMessages) deviations.push(`minMessages=${rules.minMessages}`);
  if (rules.maxChars !== pins.chatCaps.maxChars) deviations.push(`maxChars=${rules.maxChars}`);
  if (rules.maxMessages !== pins.chatCaps.maxMessages) deviations.push(`maxMessages=${rules.maxMessages}`);
  if (rules.maxMsgChars !== pins.chatCaps.maxMsgChars) deviations.push(`maxMsgChars=${rules.maxMsgChars}`);
  if (rules.maxReports !== pins.maxReports) deviations.push(`maxReports=${rules.maxReports}`);
  if (rules.receiptFreshWindowMs !== pins.receiptFreshWindowMs) deviations.push(`receiptFreshWindowMs=${rules.receiptFreshWindowMs}`);
  if (rules.minDepositWei !== pins.minDepositWei) deviations.push(`minDepositWei=${rules.minDepositWei}`);
  // K-S4-002: 合計上限。下限と対称に**厳密**照合する（未宣言も逸脱）。
  // リリース前でブロック0からやり直すため、未宣言を許す後方互換は不要。
  // ここを緩めると「manifest から maxDepositWei を落とすだけで上限を無効化できる」穴になる。
  if (rules.maxDepositWei !== pins.maxDepositWei) deviations.push(`maxDepositWei=${rules.maxDepositWei}`);
  // 請求データ自己完結化（2026-08-01）: デポッター按分の端数規則と葉の形式。
  // maxDepositWei と同じく**厳密**照合（未宣言も逸脱）。ここを緩めると
  // 「manifest から落とすだけで分配規則を無効化できる」穴になる（SPEC §7-3）。
  if (rules.depositorRounding !== pins.depositorRounding) deviations.push(`depositorRounding=${rules.depositorRounding}`);
  if (rules.depositorLeafFormat !== pins.depositorLeafFormat) deviations.push(`depositorLeafFormat=${rules.depositorLeafFormat}`);
  // vendored コーデック自身の版数が pin と噛み合っているか（vendor 取り残しの検出）。
  // これが無いと「vendor だけ旧版」でも decode 失敗まで気づけない。
  // K-S5-002: チャンクサイズは契約の MAX_CLAIM_DATA_BYTES と同値でなければならない。
  // pin してあるのに一度も照合していなかった（＝検証済みに見えて未検証だった）。
  if (rules.claimDataChunkBytes !== pins.claimDataChunkBytes) deviations.push(`claimDataChunkBytes=${rules.claimDataChunkBytes}`);
  if (CLAIM_DATA_FORMAT !== pins.claimDataFormat) deviations.push(`vendoredClaimDataFormat=${CLAIM_DATA_FORMAT}`);
  if (DEPOSITOR_LEAF_FORMAT !== pins.depositorLeafFormat) deviations.push(`vendoredDepositorLeafFormat=${DEPOSITOR_LEAF_FORMAT}`);
  if (DEPOSITOR_ROUNDING !== pins.depositorRounding) deviations.push(`vendoredDepositorRounding=${DEPOSITOR_ROUNDING}`);
  // K-S2-003 / §6.9: 可視文字規則と密告要件は未宣言も逸脱（REQUEST8 便E）。
  deviations.push(...collectRequiredScoringRuleDeviations(rules, pins));
  // 案B / Q-S2-001 / K-S6-002: 既読参照のバイト数・受領証明の分量上限・観測発信の上限と
  // 受理規則の版数。
  //
  // 🔴 C-2（2026-08-09・ラウンド21）: 旧実装は `rules[k] != null &&` で守られており、
  //    **宣言を落とすだけで pin を無効化できた**（＝片側限定の防御的上限）。
  //    同じファイルの `maxDepositWei` は「未宣言も逸脱」と明記して厳密照合しているのに、
  //    この5キーにだけその理屈が適用されていなかった。リリース前でブロック0からやり直すので
  //    「旧ブロックには宣言が無い」という後方互換の理由は成立しない。
  //    正典（`game-master-DO.js` の manifest 組み立て）は対象キーを**常に**宣言する。
  deviations.push(...collectStrictManifestRulePinDeviations(rules, pins));
  report.check('check.stageC.rulesPins', deviations.length === 0 ? 'pass' : 'fail',
    { deviations: deviations.join(', ') || '-' });
  if (deviations.length > 0) {
    S.anomalies.push(ui.t('stageC.anomaly.rulesDeviation', { deviations: deviations.join(', ') }));
    recordEmergencyDifference(ctx, {
      checkId: 'check.stageC.rulesPins',
      what: 'result manifest rule declarations differ from the verifier scoring pins',
      chain: { manifestCoreHash: anchored?.hash ?? null },
      rebuilt: { manifestCoreHash: coreHash, scoringAuthority: 'ctx.cfg.pins', deviations },
      reason: 'emergency scoring uses the locally pinned rules; strict declaration comparison remains FAIL',
    });
  }

  // 3f. protocol / blockRewardWei（プロトコル定数＝逸脱は FAIL）
  report.check('check.stageC.rulesReward',
    (rules.protocol === 2 && rules.blockRewardWei === getBlockRewardWei(N).toString()) ? 'pass' : 'fail',
    { protocol: rules.protocol, blockRewardWei: rules.blockRewardWei, expected: getBlockRewardWei(N).toString() });

  // 3g. 宣言タイミング（rules.startTime/blockTime/periodDurations）とチェーン immutable の
  //     生パラメータ比較【主検査】。両側とも ms を保持しているので、秒へ丸めず厳密に比べる。
  //     秒へ Math.round すると公開 rules の ±499ms が pass し、その値が緊急 writer の env と
  //     再生成 manifest へそのまま焼き込まれるため、ここが fail-closed の境界である。
  const mism = compareManifestRulesTimingMs(rules, timing);
  report.check('check.stageC.rulesTiming', mism.length === 0 ? 'pass' : 'fail', { mismatches: mism.join('; ') || '-' });
  if (mism.length > 0) S.anomalies.push(ui.t('stageC.anomaly.timingMismatch', { mismatches: mism.join('; ') }));
}

function manifestStartTimeMs(value) {
  if (value === null || value === undefined || value === '') return NaN;
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : Date.parse(value);
}

/** 公開manifestの4 timing値とチェーンimmutableの4値を、丸めないms単位で比較する。 */
export function compareManifestRulesTimingMs(rules = {}, timing = {}) {
  const declared = {
    START_TIME: manifestStartTimeMs(rules.startTime),
    BLOCK_TIME: Number(rules.blockTime),
    GAME_PERIOD: Number(rules.periodDurations?.gamePeriod),
    SUBMIT_PERIOD: Number(rules.periodDurations?.submitPeriod),
  };
  const immutable = {
    START_TIME: Number(timing.startTimeEntryMs),
    BLOCK_TIME: Number(timing.blockTimeMs),
    GAME_PERIOD: Number(timing.gamePeriodMs),
    SUBMIT_PERIOD: Number(timing.submitPeriodMs),
  };
  const mismatches = [];
  for (const key of ['START_TIME', 'BLOCK_TIME', 'GAME_PERIOD', 'SUBMIT_PERIOD']) {
    const published = declared[key];
    const onchain = immutable[key];
    if (!Number.isSafeInteger(published) || published < 0
        || !Number.isSafeInteger(onchain) || onchain < 0) {
      mismatches.push(`${key}: missing or invalid ms (manifest=${published} chain=${onchain})`);
    } else if (published !== onchain) {
      mismatches.push(`${key}: manifest=${published}ms chain=${onchain}ms`);
    }
  }
  return mismatches;
}

// ============================================================
// Step 4: Evidence 再現（vendored evidence-reconciler ＋ マージ規則 :587-608 の写像）
// ============================================================
export async function scanEvidenceEventsInUnits({
  fromBlock, toBlock, resultCount, fetchRange, onUnit,
}) {
  const metadata = [];
  const count = Number(resultCount);
  if (!Number.isSafeInteger(count) || count < 0) {
    throw new Error(`invalid Evidence resultCount: ${resultCount}`);
  }
  const to = BigInt(toBlock);
  // seq は indexed かつ 1..resultCount の連番なので、正典の400件 unitを topic OR にも使う。
  // block幅だけの分割では、同一blockに全提出が集中したときgetLogs応答自体が全件になる。
  for (let seqStart = 1; seqStart <= count; seqStart += EVIDENCE_EVENTS_PER_UNIT) {
    const seqs = Array.from(
      { length: Math.min(EVIDENCE_EVENTS_PER_UNIT, count - seqStart + 1) },
      (_, index) => BigInt(seqStart + index),
    );
    let from = BigInt(fromBlock);
    while (from <= to) {
      const chunkTo = from + BigInt(EVIDENCE_LOG_BLOCKS_PER_READ - 1) > to
        ? to : from + BigInt(EVIDENCE_LOG_BLOCKS_PER_READ - 1);
      const pending = await getLogsAdaptive((rangeFrom, rangeTo) => (
        fetchRange(rangeFrom, rangeTo, seqs)
      ), from, chunkTo);
      pending.sort((a, b) => Number(a.seq) - Number(b.seq));
      while (pending.length > 0) {
        let take = 0;
        let chars = 0;
        for (const event of pending) {
          const eventChars = typeof event?.data === 'string' ? event.data.length : 0;
          if (take > 0 && (take >= EVIDENCE_EVENTS_PER_UNIT
            || chars + eventChars > EVIDENCE_CHARS_PER_UNIT)) break;
          take += 1;
          chars += eventChars;
        }
        const unit = pending.splice(0, take);
        metadata.push(...unit.map((event) => ({
          seq: event.seq, timestamp: event.timestamp, txHash: event.txHash,
          rawBytes: typeof event.data === 'string' && /^0x(?:[0-9a-fA-F]{2})*$/.test(event.data)
            ? (event.data.length - 2) / 2 : null,
        })));
        await onUnit(unit);
      }
      from = chunkTo + 1n;
    }
  }
  return metadata;
}

export async function retainAdoptedEvidenceUnit(selected, adoptedByUid, persistRaw) {
  for (const [uid, adopted] of Object.entries(selected.adoptedByUid)) {
    if (adoptedByUid[uid]) continue;
    const rawRef = await persistRaw(adopted.seq, adopted.raw);
    // raw/bundleはunitの外へ保持しない。採点する組だけrawRefから再読込する。
    adoptedByUid[uid] = {
      seq: adopted.seq,
      txHash: adopted.txHash,
      rawRef,
      groupId: adopted.groupId,
    };
  }
}

// 採用Evidenceのrawは採点まで生存させる必要があるが、R2 cacheの成果物ではない。
// block{N}/ 配下へ置くと再検証時にessential予算へ算入されるため、dataDir直下の
// sibling spoolへ分離し、run() の finally から必ず掃除する。一意directoryなので
// 同じblockを並列検証しても互いのrawを上書きしない。
export async function createEvidenceSpool(r2BaseDir, blockNum) {
  const cacheDir = path.resolve(r2BaseDir);
  const spoolRoot = path.join(path.dirname(cacheDir), '.evidence-spool');
  await fs.mkdir(spoolRoot, { recursive: true, mode: 0o700 });
  const dir = await fs.mkdtemp(path.join(spoolRoot, `block${Number(blockNum)}-`));
  let closed = false;
  return {
    dir,
    async persistRaw(seq, raw) {
      if (closed) throw new Error('Evidence spool is already closed');
      const n = Number(seq);
      if (!Number.isSafeInteger(n) || n < 0) throw new Error(`Invalid Evidence sequence: ${seq}`);
      const rawPath = path.join(dir, `seq-${n}.compact`);
      await fs.writeFile(rawPath, raw, { encoding: 'utf8', mode: 0o600 });
      return rawPath;
    },
    async cleanup() {
      if (closed) return;
      closed = true;
      await fs.rm(dir, { recursive: true, force: true });
      // 並列runのspoolが残っていれば ENOTEMPTY になるだけ。親は共有なので再帰削除しない。
      await fs.rmdir(spoolRoot).catch((error) => {
        if (error?.code !== 'ENOENT' && error?.code !== 'ENOTEMPTY') throw error;
      });
    },
  };
}

export function assessEvidenceSegmentBoundaries(frames, published) {
  const params = { pinVersion: published?.pinVersion ?? '-' };
  try {
    if (!published || typeof published.pinVersion !== 'string') throw new Error('evidence segment artifact missing');
    const expected = evidenceSegmentArtifact(frames, published.pinVersion);
    params.expectedSegments = expected.segments.length;
    params.publishedSegments = published.segments?.length ?? '-';
    for (const field of ['coefficients', 'budget', 'invalidCosts', 'segments']) {
      if (!canonicalEqual(published[field], expected[field])) {
        return { status: 'warn', params: { ...params, reason: `${field}_mismatch` } };
      }
    }
    return { status: 'pass', params: { ...params, reason: 'matching_boundaries_and_prices' } };
  } catch (error) {
    return { status: 'warn', params: { ...params, reason: String(error.message || error) } };
  }
}

async function reproduceEvidence(ctx, S) {
  const { report, ui, blockNum: N } = ctx;
  const rulesEvidence = S.files.manifest?.data?.rules?.evidence ?? null;

  // 🔴 Q-4（2026-08-08・ユーザー確定）: **Evidence のアドレスはチェーンから読む。**
  //    `TokenMining.evidence()` は set-once（`TokenMining.evidence` / TokenMining.setEvidence）＝運営が
  //    後から動かせない。目録の `rules.evidence.contractAddress` は廃止した（申告を読む経路を無くす）。
  const evidenceAddr = await ctx.chain.evidenceAddress();

  // G8: 安全ブロックへのピン留め（canonical game-master-DO.js:452-455 と同一）:
  //   safeNumber = latest.number − confirmations、safeBlock = getBlock(safeNumber)。
  //   finality 判定は safeBlock.timestamp、resultWindow / chatWindow / resultCount は
  //   {blockNumber: safeNumber} の高さ固定で読む（リオーグ確定済みの世界だけを見る）。
  const latest = await ctx.chain.latest();
  let safeNumber = toBlockBigInt(latest.number) - BigInt(ctx.cfg.pins.confirmationBlocks);
  if (ctx.data?.emergencySource?.authority === 'gcp') {
    // GCP 入口の固定一式は実行時の head に依存させない。窓の閉鎖を
    // 含む最初のブロックを確定し、その confirmations 後を固定した安全高にする。
    const closingWindow = await ctx.chain.resultWindow(N);
    const closeAt = Number(closingWindow.closeAt ?? closingWindow[1]);
    if (!Number.isSafeInteger(closeAt) || closeAt < 0) {
      throw new Error(`block ${N}: Evidence result closeAt is unavailable`);
    }
    let closingBlock;
    if (typeof ctx.chain.findBlockByTimestamp === 'function') {
      closingBlock = BigInt(await ctx.chain.findBlockByTimestamp(closeAt));
    } else {
      let low = 0n;
      let high = toBlockBigInt(latest.number);
      while (low < high) {
        const mid = (low + high) / 2n;
        if (Number((await ctx.chain.getBlock(mid)).timestamp) < closeAt) low = mid + 1n;
        else high = mid;
      }
      closingBlock = low;
    }
    if (Number((await ctx.chain.getBlock(closingBlock)).timestamp) < closeAt) {
      throw new Error(`block ${N}: Evidence result window has not closed`);
    }
    safeNumber = closingBlock + BigInt(ctx.cfg.pins.confirmationBlocks);
    if (safeNumber > toBlockBigInt(latest.number)) {
      throw new Error(`block ${N}: deterministic Evidence safe block ${safeNumber} is not confirmed`);
    }
  }
  const safeBlock = await ctx.chain.getBlock(safeNumber);
  const atSafe = { blockNumber: safeNumber };

  // 🔴 Q-4: `TokenMining.evidence()` が未配線（0x0）＝**検閲対策の層そのものが存在しない**。
  //    これは「検査をしなくてよい」ではなく「検査対象が無い」＝ 6件すべて FAIL で記録する。
  //    旧実装はここで早期 return して6件を消していた（`##RESULT full` / exit 0 のまま）。
  if (!evidenceAddr) {
    S.chatWindowMs = null;
    const d = { reason: 'evidence_unwired' };
    report.check('check.stageC.evidenceDeclaredDisabled', 'fail', { resultCount: '-' });
    report.check('check.stageC.chatWindowDeclared', 'fail', { derived: '-', declared: '-' });
    report.check('check.stageC.evidenceFinality', 'fail', { closeAt: '-', now: '-' });
    report.check('check.stageC.evidenceCompleteness', 'fail', d);
    report.check('check.stageC.archiveChainConsistency', 'fail', { adopted: 0, diverged: 'evidence_unwired' });
    report.check('check.stageC.evidenceReportMatch', 'fail', { notes: 'TokenMining.evidence() is unset (0x0)' });
    S.anomalies.push(ui.t('stageC.anomaly.evidenceDisabled'));
    return;
  }

  // 同梱 config.js のアドレスが古い（契約再デプロイ後の更新漏れ）ことの告知。
  // 権威はあくまでチェーン側なので検証は続行する（既知の運用罠の可視化）。
  if (ctx.cfg.contracts.evidence && lower(ctx.cfg.contracts.evidence) !== lower(evidenceAddr)) {
    S.anomalies.push(ui.t('stageC.anomaly.evidenceAddressDiffers', {
      onchain: evidenceAddr, config: ctx.cfg.contracts.evidence }));
  }

  // 🔴 Q-4: 「Evidence は使っていない」という**目録の申告で検査を飛ばす経路を削除した**。
  //    旧実装は `rules.evidence === null` かつチェーンの resultCount が 0 なら早期 return し、
  //    `chatWindowDeclared` / `evidenceFinality` / `evidenceReportMatch` が消えて
  //    残り3件も skip になっていた（改変ゼロで 60 checks / FAIL 0 / `##RESULT full` / exit 0）。
  //    Evidence への提出は検閲対策の中核なので、宣言が無いこと自体を FAIL として記録し、
  //    以降はチェーン由来の窓で evidence 再現一式を**必ず**走らせる。
  let declaredDisabled = false;
  if (rulesEvidence === null) {
    let chainCount = null;
    try { chainCount = Number(await ctx.chain.resultCount(N, atSafe)); } catch { chainCount = null; }
    if (ctx.data.emergencySource?.authority === 'gcp') {
      report.check('check.stageC.evidenceDeclaredDisabled', 'skip', {
        reason: 'GCP authority: no public manifest declaration', resultCount: chainCount ?? '-',
      });
    } else {
      report.check('check.stageC.evidenceDeclaredDisabled', 'fail', { resultCount: chainCount ?? '-' });
      S.anomalies.push(ui.t('stageC.anomaly.evidenceDeclaredButSubmitted', { count: chainCount ?? '-' }));
    }
    declaredDisabled = true;
  } else {
    report.check('check.stageC.evidenceDeclaredDisabled', 'pass', { resultCount: '-' });
  }

  // 窓の確定性ガード（:471-477 相当）＋ 宣言チャット窓の再導出（:480-488）— 全て安全ブロック高で読む
  let rw, cw;
  try { rw = await ctx.chain.resultWindow(N, atSafe); }
  catch (error) {
    if (!(error instanceof ArchiveUnavailableError)) throw error;
    S.evidenceStateError = error;
    report.fact('stageC.resultStateError', error);
    report.unverified('check.stageC.evidenceFinality', error, { reason: 'archive_unavailable' });
    return;
  }
  try { cw = await ctx.chain.chatWindow(N, atSafe); }
  catch (error) {
    if (!(error instanceof ArchiveUnavailableError)) throw error;
    S.evidenceStateError = error;
    report.fact('stageC.resultStateError', error);
    report.unverified('check.stageC.chatWindowDeclared', error, { reason: 'archive_unavailable' });
    return;
  }
  const openAt = num(rw.openAt ?? rw[0]);
  const closeAt = num(rw.closeAt ?? rw[1]);
  const chatOpenAt = num(cw.chatOpenAt ?? cw[0]);
  const chatCloseAt = num(cw.chatCloseAt ?? cw[1]);
  const finalized = Number(safeBlock.timestamp) >= closeAt;
  report.check('check.stageC.evidenceFinality', finalized ? 'pass' : 'fail',
    { closeAt: isoOf(closeAt), now: isoOf(Number(safeBlock.timestamp)) });
  if (!finalized) return; // 窓が閉じていない＝結果確定自体が不整合。以降の evidence 再現は不能

  S.rosterSubmission = S.groupIds?.length > 0 && !S.auto && !S.noGame && !S.timelineNoGame
    ? await resolveRosterSubmissionEligibility(
      ctx.chain, N, safeBlock.timestamp, chatOpenAt,
    ) : { accepted: true };

  const skew = ctx.cfg.pins.clockSkewAllowMs; // = 120000（game-master-DO.js:484）
  S.chatWindowMs = { startMs: chatOpenAt * 1000 - skew, endMs: chatCloseAt * 1000 + skew };
  S.resultWindow = { openAt, closeAt };
  S.chatWindow = { chatOpenAt, chatCloseAt };
  if (declaredDisabled) {
    // 宣言値が無い（null宣言）ため宣言窓との照合は不能 — チェーン由来窓をそのまま採点に使う
    report.check('check.stageC.chatWindowDeclared', 'skip', { derived: JSON.stringify(S.chatWindowMs), declared: 'null' });
  } else {
    report.check('check.stageC.chatWindowDeclared',
      canonicalEqual(S.chatWindowMs, rulesEvidence.chatWindowMs) ? 'pass' : 'fail',
      { derived: JSON.stringify(S.chatWindowMs), declared: JSON.stringify(rulesEvidence.chatWindowMs) });
  }

  // resultCount → イベント全走査 → 完全性（:490-529 の写像・安全ブロック高で読取）
  let resultCount;
  try { resultCount = Number(await ctx.chain.resultCount(N, atSafe)); }
  catch (error) {
    if (!(error instanceof ArchiveUnavailableError)) throw error;
    S.evidenceStateError = error;
    report.fact('stageC.resultStateError', error);
    report.unverified('check.stageC.evidenceCompleteness', error, { reason: 'archive_unavailable' });
    return;
  }
  S.resultCount = resultCount;

  // 走査中にsafeNumberがノードの保持範囲から外れる前に、同じ高さのaccも確保する。
  // 判定の記録順と比較材料は従来どおり完全性検査の後にする。
  let onchainEvidenceAcc, evidenceAccError;
  try { onchainEvidenceAcc = await ctx.chain.evidenceAcc(N, atSafe); }
  catch (error) { evidenceAccError = error; }

  let evidenceEvents = [];
  let adoptedByUid = Object.create(null);
  let invalid = [];
  let contradictoryEvidence = [];
  let rebuiltEvidenceAcc = ZERO_ROOT;
  const membersIndex = buildMembersIndex(
    S.groupDataList.map(({ group, data }) => ({ group_id: group.group_id, members: data?.members || [] })), { chatWindow: S.chatWindowMs }
  );
  const scanAndValidate = async (fromBlock, toBlock) => {
    adoptedByUid = Object.create(null);
    invalid = [];
    contradictoryEvidence = [];
    rebuiltEvidenceAcc = ZERO_ROOT;
    if (!S.evidenceSpool) {
      S.evidenceSpool = await createEvidenceSpool(ctx.r2.baseDir, N);
    }
    return scanEvidenceEventsInUnits({
      fromBlock,
      toBlock,
      resultCount,
      fetchRange: async (from, to, seqs) => {
        const logs = await ctx.chain.client.getLogs({
          address: evidenceAddr,
          event: RESULT_SUBMITTED_EVENT,
          args: { blockNum: BigInt(N), seq: seqs },
          fromBlock: BigInt(from),
          toBlock: BigInt(to),
        });
        return logs.map((log) => ({
          blockNum: Number(log.args.blockNum),
          seq: Number(log.args.seq),
          sender: log.args.sender,
          data: log.args.data,
          timestamp: Number(log.args.timestamp),
          txHash: log.transactionHash,
          evtBlock: Number(log.blockNumber),
        }));
      },
      onUnit: async (events) => {
        const validated = [];
        for (const event of events) {
          rebuiltEvidenceAcc = foldEvidenceAcc(rebuiltEvidenceAcc, event.sender, event.data);
          let raw = null;
          let validation;
          const decoded = await decodeEvidenceData(event.data);
          if (!decoded.ok) {
            validation = { valid: false, reason: decoded.reason };
          } else {
            raw = decoded.raw;
            validation = await validateResultBundle(raw, N, membersIndex, event.sender);
            const contradiction = await submissionContradictsGrouping(
              raw, N, validation, ctx.data.players, event.sender,
            );
            if (contradiction) contradictoryEvidence.push({ seq: event.seq, groupId: contradiction.groupId });
          }
          validated.push({ seq: event.seq, txHash: event.txHash, raw, validation });
        }
        const selected = selectAdoptedResults(validated);
        invalid.push(...selected.invalid);
        await retainAdoptedEvidenceUnit(
          selected, adoptedByUid, S.evidenceSpool.persistRaw,
        );
      },
    });
  };
  if (resultCount > 0) {
    let { fromBlock, toBlock } = estimateBlockRange(safeNumber, Number(safeBlock.timestamp), openAt, closeAt);
    if (toBlock > safeNumber) toBlock = safeNumber;
    evidenceEvents = await scanAndValidate(fromBlock, toBlock);
    try {
      verifyCompleteness(evidenceEvents, resultCount);
    } catch (e) {
      // 範囲不足の可能性 → 一度だけ広げて再試行（:524-528 と同一規則）
      const widenedFrom = fromBlock > 50000n ? fromBlock - 50000n : 0n;
      evidenceEvents = await scanAndValidate(widenedFrom, safeNumber);
      try {
        verifyCompleteness(evidenceEvents, resultCount);
      } catch (e2) {
        report.check('check.stageC.evidenceCompleteness', 'fail', { error: e2.message, resultCount });
        S.anomalies.push(ui.t('stageC.anomaly.evidenceIncomplete', { error: conciseRpcText(e2, ui.t) }));
        return;
      }
    }
  }
  report.check('check.stageC.evidenceCompleteness', 'pass', { resultCount, events: evidenceEvents.length });
  try {
    if (evidenceAccError) throw evidenceAccError;
    const onchain = onchainEvidenceAcc;
    report.check('check.stageC.evidenceAcc',
      lower(rebuiltEvidenceAcc) === lower(onchain) ? 'pass' : 'fail',
      { rebuilt: rebuiltEvidenceAcc, onchain });
  } catch (error) {
    if (error instanceof ArchiveUnavailableError) {
      report.fact('stageC.resultStateError', error);
      report.unverified('check.stageC.evidenceAcc', error, { reason: 'archive_unavailable' });
    }
    else report.check('check.stageC.evidenceAcc', 'fail', { error: error.message });
  }
  adoptedByUid = adoptedForRoster(adoptedByUid, S.rosterSubmission);
  report.check('check.stageC.evidenceContradictsGrouping',
    contradictoryEvidence.length > 0 ? 'warn' : 'pass', {
      count: contradictoryEvidence.length,
      submissions: contradictoryEvidence,
    });
  ui.println(ui.t('stageC.evidenceEventCount', { count: evidenceEvents.length, resultCount }));

  S.evidenceEvents = evidenceEvents;
  ctx.data.emergencyEvidenceSegmentFrames = evidenceEvents.map(({ seq, rawBytes }) => ({ seq, rawBytes }));
  if (S.zkInfo?.kind === 'proof') {
    const assessed = assessEvidenceSegmentBoundaries(ctx.data.emergencyEvidenceSegmentFrames,
      S.files?.evidenceSegments?.data);
    report.check('check.stageC.evidenceSegmentBoundaries', assessed.status, assessed.params);
  }
  S.adoptedByUid = adoptedByUid;
  // 巨大group archiveは同時保持しない。採点時に1組ずつcacheから戻し、その場で
  // game-master-DO.js:587-608 と同じEvidenceマージを行う。ここには小さい判定表だけ残す。
  S.evidenceFinalize = {
    declaredDisabled,
    rosterSubmission: S.rosterSubmission,
    rulesEvidence,
    resultCount,
    invalid,
    reportMeta: {
      contractAddress: evidenceAddr,
      blockNum: N,
      resultCount,
      window: { openAt, closeAt },
      chatWindow: { chatOpenAt, chatCloseAt, clockSkewAllowMs: skew },
      safeBlock: String(safeNumber),
      confirmations: ctx.cfg.pins.confirmationBlocks,
    },
    serverStates: Object.create(null),
    sources: Object.create(null),
  };
}

// E11-01 は欠落 group 自身の採用 Evidence／保全提出で救う。
// R31-U-J3 は緊急時に限り、ブロック全体のゲーム実施を独立に示せた場合、
// 両方0件の組を提出なしの空組として採点する。
export function classifyMissingGroupEvidence(
  missingGroupArchives,
  adoptedByUid,
  emergencySelectedByUid = null,
  blockGameEvidence = null,
) {
  const adoptedResults = Object.values(adoptedByUid || {});
  const preservedResults = Object.values(emergencySelectedByUid || {})
    .filter((item) => item?.valid === true);
  const groups = [...(missingGroupArchives || [])].map((gid) => {
    const adopted = adoptedResults.filter((item) => Number(item?.groupId) === Number(gid)).length;
    const preserved = preservedResults.filter((item) => Number(item?.groupId) === Number(gid)).length;
    return { gid, adopted, preserved,
      emptyGroup: Boolean(blockGameEvidence && adopted + preserved === 0) };
  });
  return {
    groups,
    unrescued: groups.filter((item) => item.adopted + item.preserved === 0 && !item.emptyGroup),
  };
}

async function mergeEvidenceIntoGroup(S, data) {
  if (!S.evidenceFinalize || !S.adoptedByUid) return;
  for (const m of (data?.members || [])) {
    const uid = String(m.uid);
    const adopted = S.adoptedByUid[uid];
    if (!adopted) continue;
    const adoptedRaw = await fs.readFile(adopted.rawRef, 'utf8');
    const serverRaw = data.submissionsRaw?.[uid] || null;
    let serverState = 'identical';
    if (serverRaw !== adoptedRaw) {
      serverState = serverRaw == null ? 'missing' : 'mismatch';
      data.submissions = data.submissions || {};
      // Evidence走査中はparsed bundleを保持しない。採点へ実際に差し込む提出だけをここで戻す。
      data.submissions[uid] = decodeSubmissionPayloadString(adoptedRaw).bundle;
      data.submissionsRaw = data.submissionsRaw || {};
      data.submissionsRaw[uid] = adoptedRaw;
      data.evidenceSources = data.evidenceSources || {};
      data.evidenceSources[uid] = { seq: adopted.seq, txHash: adopted.txHash };
    }
    S.evidenceFinalize.serverStates[uid] = serverState;
    S.evidenceFinalize.sources[uid] = data.evidenceSources?.[uid] || null;
  }
}

// 緊急入口だけが使う採用層。Evidence の採用済み uid は常に残し、それ以外は
// 見張り役の全世代から事前に完全検証された「最初の1件」だけへ置き換える。
// 最新公開アーカイブに残っている値を暗黙に採用しない。
export function mergeEmergencyServerSubmissions(S, data, selectedByUid) {
  const nextRaw = Object.create(null);
  for (const member of (data?.members || [])) {
    const uid = String(member?.uid);
    if (S.adoptedByUid?.[uid]) {
      if (typeof data.submissionsRaw?.[uid] === 'string') nextRaw[uid] = data.submissionsRaw[uid];
      continue;
    }
    const selected = selectedByUid?.[uid];
    if (typeof selected?.raw === 'string') nextRaw[uid] = selected.raw;
  }
  data.submissionsRaw = nextRaw;
  data.submissions = Object.create(null);
  return data;
}

async function finalizeEvidenceArchiveChecks(ctx, S) {
  if (!S.evidenceFinalize) return;
  const { report, ui } = ctx;
  const F = S.evidenceFinalize;
  const adoptedRecords = [];
  const diverged = [];
  for (const [uid, adopted] of Object.entries(S.adoptedByUid || {})) {
    const serverState = F.serverStates[uid];
    if (!serverState) continue;
    adoptedRecords.push({ uid, groupId: adopted.groupId, seq: adopted.seq, txHash: adopted.txHash, serverState });
    if (serverState !== 'identical') diverged.push({ uid, serverState });
  }
  // V25-03: serverState は不正の証拠ではない（正式Evidenceだけの自己救済は常にmissing、
  // compact再署名は正常にmismatchになり得る）。採点入力は上で無条件にEvidenceへ置換済み。
  // 結果の不一致は独立再採点後のsummaryMatchがFAILさせる。
  report.check('check.stageC.archiveChainConsistency', 'pass',
    { adopted: adoptedRecords.length, diverged: diverged.map(d => `${d.uid}:${d.serverState}`).join(', ') || '-' });

  if (ctx.data.emergencySource?.authority === 'gcp') {
    const key = `verification/block${ctx.blockNum}/evidence-report.json`;
    const source = ctx.data.emergencySource;
    const reconstructed = {
      ...F.reportMeta,
      adopted: adoptedRecords.map(({ uid, groupId, seq, txHash, serverState }) => (
        { uid, groupId, seq, txHash, serverState }
      )),
      invalid: F.invalid,
    };
    if (F.rosterSubmission?.accepted === false) reconstructed.rosterSubmission = F.rosterSubmission;
    const { safeBlock: _observedAt, ...expectedContent } = reconstructed;
    const rebuiltSha256 = sha256HexOfString(JSON.stringify(reconstructed));
    const candidates = [];
    let chosen = null;
    for await (const generation of gcpCandidates(source.sourceDir, source.index, key, candidates)) {
      const value = generation.data;
      const { safeBlock: _savedAt, ...savedContent } = value && typeof value === 'object'
        && !Array.isArray(value) ? value : {};
      const valid = canonicalEqual(savedContent, expectedContent);
      candidates.push({ generation: generation.row.generation, sha256: generation.row.sha256,
        observationOrdinal: generation.row.observationOrdinal,
        reason: valid ? 'matches chain Evidence reconstruction apart from observation height' :
          'Evidence content differs from chain reconstruction' });
      if (valid) { chosen = generation; break; }
    }
    // The canonical GM writes this exact shape with JSON.stringify. A saved
    // row is comparison evidence only, even when its content matches.
    ctx.data.emergencyEvidenceReport = reconstructed;
    S.files.evidenceReport = { data: reconstructed };
    if (!chosen || chosen.row.sha256 !== rebuiltSha256) {
      recordEmergencyDifference(ctx, {
        checkId: 'emergency.gcpEvidenceReportRebuilt', what: key,
        chain: { resultCount: F.resultCount, adopted: adoptedRecords.length },
        rebuilt: { sha256: rebuiltSha256, candidates },
        reason: 'the saved report bytes differ from the chain Evidence reconstruction; canonical report bytes will be written',
      });
    }
    if ((source.index.objects?.[key] || []).length > 1) {
      gcpUnevaluated(source.index, key, candidates);
      (ctx.data.emergencyDifferences ||= []).push({
        checkId: 'emergency.gcpEvidenceReportGeneration', what: key,
        chain: { resultCount: F.resultCount },
        rebuilt: { selectedGeneration: chosen?.row.generation ?? null, candidates },
        reason: 'the earliest report whose adopted and invalid sets match chain Evidence was selected',
      });
    }
  }
  const rep = S.files.evidenceReport?.data ?? null;
  let reportOk = true;
  const reportNotes = [];
  if (!F.declaredDisabled) {
    const declaredCounts = { resultCount: F.rulesEvidence.resultCount, adoptedCount: F.rulesEvidence.adoptedCount };
    if (declaredCounts.resultCount !== F.resultCount) {
      reportOk = false; reportNotes.push(`manifest resultCount=${declaredCounts.resultCount}≠${F.resultCount}`);
    }
    const declaredAdopted = declaredAdoptedCountForVerification(declaredCounts);
    if (declaredAdopted !== adoptedRecords.length) {
      reportOk = false; reportNotes.push(`manifest adoptedCount=${declaredCounts.adoptedCount}≠${adoptedRecords.length}`);
    }
  }
  if (rep) {
    if (rep.resultCount !== F.resultCount) { reportOk = false; reportNotes.push(`report resultCount=${rep.resultCount}`); }
    const ours = adoptedRecords.map(({ uid, groupId, seq, txHash }) => ({ uid, groupId, seq, txHash }));
    const theirs = (rep.adopted || []).map(({ uid, groupId, seq, txHash }) => ({ uid, groupId, seq, txHash }));
    if (!canonicalEqual(ours, theirs)) { reportOk = false; reportNotes.push('adopted set differs'); }
    if (!canonicalEqual(F.invalid, rep.invalid || [])) { reportOk = false; reportNotes.push('invalid list differs'); }
    if (F.rosterSubmission?.accepted === false && !canonicalEqual(F.rosterSubmission, rep.rosterSubmission)) {
      reportOk = false; reportNotes.push('roster submission decision differs');
    }
    for (const a of (rep.adopted || [])) {
      if (a.serverState === 'identical') continue;
      const src = F.sources[a.uid];
      if (!src || src.seq !== a.seq || lower(src.txHash) !== lower(a.txHash)) {
        reportNotes.push(`evidenceSources[${a.uid}] inconsistent`);
      }
    }
  } else if (F.resultCount > 0) {
    reportOk = false; reportNotes.push('evidence-report.json missing');
  }
  report.check('check.stageC.evidenceReportMatch', reportOk ? 'pass' : 'fail', {
    notes: reportNotes.join('; ') || '-',
    ...(reportOk || S.zkInfo?.kind !== 'proof' ? {} : {
      childKeys: 'unperformed_in_menu1',
      provider: S.futureAnchorCheck?.provider ?? 'unavailable',
    }),
  });
  if (!reportOk) S.anomalies.push(ui.t('stageC.anomaly.reportMismatch', { notes: reportNotes.join('; ') }));
}

// ============================================================
// Step 5 前半: groupData 組立（アーカイブ＝get-results 形状。検証済みグループと突合）
// ============================================================
function buildGroupDataList(ctx, S) {
  const { report, ui, blockNum: N } = ctx;
  const d1MembersByGid = new Map(S.d1Groups.map(g => [g.group_id, JSON.parse(g.members)]));
  const memberFailures = [];
  const metaFailures = [];
  S.groupDataList = [];
  for (const gid of S.orderedGroupIds) {
    const res = S.files.groups.get(gid);
    const expected = d1MembersByGid.get(gid);
    if (!res) {
      // V25-03: membersは独立再現済みselection/groupingが権威。archive欠損を理由に
      // Evidence検証を開始前に止めない。採点時にも同じ合成入力を使う。
      S.missingGroupArchives = S.missingGroupArchives || new Set();
      S.missingGroupArchives.add(gid);
      S.groupDataList.push({ group: { group_id: gid }, data: { members: expected || [] } });
      continue;
    }
    const projection = res.data;
    // meta 照合（chat-game-DO.js:152-159。calculator の msgKey 文脈が正しいことの担保）
    if (!projection?.meta || Number(projection.meta.blockNum) !== N || Number(projection.meta.groupId) !== gid) {
      metaFailures.push(`group${gid}`);
    }
    // members 照合: アーカイブの members == 検証済みグループ分けの D1 membersJson（独立再構成）
    if (!expected || !canonicalEqual(projection?.members, expected)) {
      memberFailures.push(`group${gid}:members`);
    }
    S.groupPublished.set(gid, {
      gameResults: projection?.gameResults,
      canonicalTimeline: projection?.canonicalTimeline,
    });
    // 緊急時の署名検証・採点名簿は、applicantHashから再現済みのグループ分けを権威にする。
    // 通常モードは従来どおり公開archiveを使い、不一致検出の集合を変えない。
    const scoringMembers = ctx.data.emergencySource ? (expected || []) : (projection?.members || []);
    S.groupDataList.push({ group: { group_id: gid }, data: { members: scoringMembers } });
  }
  report.check('check.stageC.groupMeta', metaFailures.length === 0 ? 'pass' : 'fail',
    { failures: metaFailures.join(', ') || '-' });
  report.check('check.stageC.groupMembersMatch', memberFailures.length === 0 ? 'pass' : 'fail',
    { failures: memberFailures.join(', ') || '-' });
  if (memberFailures.length > 0) S.anomalies.push(ui.t('stageC.anomaly.membersMismatch', { failures: memberFailures.join(', ') }));
  if (metaFailures.length > 0) {
    recordEmergencyDifference(ctx, {
      checkId: 'check.stageC.groupMeta',
      what: 'published group meta differs from the recomputed block/group context',
      chain: { applicantRegistration: ctx.data.emergencySource?.applicantRegistration ?? null },
      rebuilt: { failures: metaFailures, authority: 'recomputed grouping' },
      reason: 'emergency scoring replaces blockNum/groupId with the recomputed context',
    });
  }
  if (memberFailures.length > 0) {
    recordEmergencyDifference(ctx, {
      checkId: 'check.stageC.groupMembersMatch',
      what: 'published group members differ from the recomputed roster',
      chain: { applicantRegistration: ctx.data.emergencySource?.applicantRegistration ?? null },
      rebuilt: { failures: memberFailures, authority: 'applicantHash-fixed grouping' },
      reason: 'emergency signature validation and scoring use the recomputed roster',
    });
  }
}

// writeGroupsToD1（game-master-DO.js:3798-3813）の membersJson を検証済みグループから再構成。
// 本番 SELECT は group_id, members のみ（:2386-2388）→ lang 列は持たせない
// （buildBlockSummaryWithResults の d1Group?.lang は undefined → 'mixed' になるのが本番挙動）。
function reconstructD1Groups(groupsDerived) {
  return groupsDerived.map(group => ({
    group_id: group.groupId,
    members: JSON.stringify(group.members.map(m => ({
      uid: m.data?.uid,
      addr: m.data?.addr,
      bAddr: m.data?.bAddr,
      lang: m.data?.lang,
      depIds: m.data?.depIds,
      globalIndex: m.globalIndex,
      name: m.data?.name || null,
      img: m.data?.img || null,
      verified: m.data?.verified || false,
    }))),
  }));
}

export function applyEmergencyGroupAuthority(ctx, S, data, groupId) {
  if (!ctx.data.emergencySource) return data;
  const row = S.d1Groups.find((candidate) => Number(candidate.group_id) === Number(groupId));
  if (!row) throw new Error(`recomputed roster is missing for group ${groupId}`);
  data.members = JSON.parse(row.members);
  data.meta = {
    ...(data.meta && typeof data.meta === 'object' && !Array.isArray(data.meta) ? data.meta : {}),
    blockNum: Number(ctx.blockNum),
    groupId: Number(groupId),
  };
  return data;
}

// K-S2-002: depositId 一覧の唯一の権威 = エントリー時の depIds
// （entries/block{N}/game_selection.json・applicantHash でオンチェーン固定）。
// vendorから読み込んだ正典の関数を、通常/自動配布/仮計算で共有する。
const parseEntryDepositIds = GameMasterDO.prototype.parseEntryDepositIds;

// ============================================================
// Step 6 後半: 報酬按分＋50/50スプリット
// MIRROR: workers/game_workers/game-master-DO.js の calcRewardsUnit 内 50/50 スプリット
// （行範囲と sha256 の正典は VENDOR_SYNC.md / scripts/check-vendor-sync.mjs の MIRROR 台帳）
// ============================================================
function mirrorRewardSplit(blockNum, allGroupResults, groups, verifiedDeposits) {
  // 4. 全グループのtotalPointsを集計（:2463-2469）
  let totalPoints = 0;
  for (const group of allGroupResults) {
    for (const member of group.members) {
      totalPoints += member.totalPoints;
    }
  }

  // 5. BTCu分配 (BigInt演算)（:2471-2486）
  const blockRewardWei = getBlockRewardWei(blockNum);

  for (const group of allGroupResults) {
    for (const member of group.members) {
      if (member.isDisqualified || totalPoints === 0) {
        member.btcuReward = '0';
      } else {
        member.btcuReward = (
          blockRewardWei * BigInt(member.totalPoints) / BigInt(totalPoints)
        ).toString();
      }
      // 50/50スプリット前の元報酬を保存（プレイヤー+デポジッター合計）
      member.fullReward = member.btcuReward;
    }
  }

  // 6. BTCu 50/50 Split（:2488-2612）
  const depositorResults = [];

  const parseDepIds = (depIdsRaw) => {
    if (!depIdsRaw) return null;
    try {
      return typeof depIdsRaw === 'string' ? JSON.parse(depIdsRaw) : depIdsRaw;
    } catch { return null; }
  };

  // オンチェーン検証済みデポジット（適格のみ・depositId昇順）
  const onchainDepositsOf = (uid) => {
    const verified = verifiedDeposits[uid];
    if (!Array.isArray(verified) || verified.length === 0) return null;
    return {
      source: 'onchain',
      deposits: verified,
      totalWei: verified.reduce((s, d) => s + BigInt(d.amount), 0n)
    };
  };
  // エントリー時キャッシュ（フォールバック専用: 旧データ／未提出者の報酬0行の上書き用）
  const cachedDepositsOf = (memberInfo) => {
    const depIds = parseDepIds(memberInfo?.depIds);
    if (!depIds?.deposits?.length) return null;
    const deposits = depIds.deposits.map(d => ({
      depositId: String(d.id),
      amount: d.amount,
      depositerAddress: d.depositerAddress || null,
      idFrom: d.idFrom ?? null
    }));
    // F-R1 是正: 分母は按分に使う各 amount の実合計（malformed はスキップ）
    let totalWei = 0n;
    for (const d of deposits) { try { totalWei += BigInt(d.amount); } catch { /* skip malformed */ } }
    return { source: 'cache', deposits, totalWei };
  };

  for (const group of allGroupResults) {
    const groupRow = groups.find(g => g.group_id === group.groupId);
    const memberData = groupRow ? JSON.parse(groupRow.members || '[]') : [];

    for (const member of group.members) {
      const totalReward = BigInt(member.btcuReward || '0');

      const memberInfo = memberData.find(m => m.uid === member.uid);
      // 請求データ自己完結化（2026-08-01）: **報酬>0 のときはオンチェーン検証済みのみを使う。**
      //   デポッター葉は適格集合そのものを setHash で焼き込み、契約 claimDepositor が
      //   全件を再検証して1件でも不適格なら revert する。自己申告キャッシュ由来の未検証 ID が
      //   1つ混ざるだけで、そのプレイヤーのデポッター配分が丸ごと請求不能になる。
      const onchain = onchainDepositsOf(member.uid);
      const depInfo = totalReward === 0n ? (onchain || cachedDepositsOf(memberInfo)) : onchain;

      // 報酬0（失格・無得点）でも各デポジットを報酬0でdepositorResultsへ登録する（:2544-2562）
      if (totalReward === 0n) {
        member.playerShare = '0';
        if (depInfo?.deposits?.length) {
          member.depositorShare = '0';
          for (const dep of depInfo.deposits) {
            depositorResults.push({
              groupId: group.groupId,
              playerUid: member.uid,
              depositorUid: dep.idFrom,
              depositId: dep.depositId,
              depositerAddress: dep.depositerAddress || null,
              depositAmount: dep.amount,
              btcuReward: '0',
              isPlayerSelf: dep.idFrom === member.uid
            });
          }
        }
        continue;
      }

      if (!depInfo?.deposits?.length || depInfo.totalWei <= 0n) {
        // 適格deposit詳細なし → プレイヤーが全額取得（:2564-2569）
        member.playerShare = totalReward.toString();
        continue;
      }

      const playerShare = totalReward / 2n;
      const depositorShareTotal = totalReward - playerShare;
      member.btcuReward = playerShare.toString();
      member.playerShare = playerShare.toString();
      member.depositorShare = depositorShareTotal.toString();

      // プロラタ配分（重み＝オンチェーンamount）。**全員切り捨て**（SPEC §7・2026-08-01）。
      // 式は正典と同じ lib/claim-data-codec.js の depositorShareOf を vendored 経由で呼ぶ
      // （手書きで写経すると必ずずれるため、ここだけは MIRROR ではなく COPY を使う）。
      const totalDepWei = depInfo.totalWei;

      for (let i = 0; i < depInfo.deposits.length; i++) {
        const dep = depInfo.deposits[i];
        const depBtcu = depositorShareOf(depositorShareTotal, dep.amount, totalDepWei);

        if (depBtcu < 0n) {
          throw new Error(`[reward] block ${blockNum}: negative depositor reward (player=${member.uid}, deposit=${dep.depositId}, dst=${depositorShareTotal}, totalDepWei=${totalDepWei}) — aborting`);
        }

        depositorResults.push({
          groupId: group.groupId,
          playerUid: member.uid,
          depositorUid: dep.idFrom,
          depositId: dep.depositId,
          depositerAddress: dep.depositerAddress || null,
          depositAmount: dep.amount,
          btcuReward: depBtcu.toString(),
          isPlayerSelf: dep.idFrom === member.uid
        });
      }

    }
  }

  return { totalPoints, blockRewardWei, depositorResults };
}

// ============================================================
// Step 6c: group{G}.json / gameResults の再構築と照合
// ============================================================
// R2-F1（2026-08-10）: game.js が表示する gameResults は summary.json ではなく
// group{G}.json にある。従来はファイルの hash 差分を「claimed 更新の可能性」として
// WARN へ降格していたが、claimed 以外の表示用結果は一度も再計算値と照合していなかった。
//
// 🔴 行形状をここに写経しない。vendored 正典の
// `appendGameResultsToR2Groups` をメモリ上の CAS 受け口で実行し、実際に書くはずの
// gameResults を投影する。これにより writer の行形状が変わっても検証側だけが古びない。
export async function rebuildCanonicalGroupGameResults(
  blockNum, allGroupResults, depositorResults, groups = []
) {
  const rebuilt = new Map();
  const writerErrors = [];
  const receiver = {
    async mutateR2ObjectWithCAS(key, mutate, { tag } = {}) {
      if (tag !== 'results') throw new Error(`unexpected CAS tag: ${String(tag)}`);
      const m = key.match(new RegExp(`^games/block${blockNum}/group(\\d+)\\.json$`));
      if (!m) throw new Error(`unexpected group result key: ${key}`);
      const archiveData = {};
      mutate(archiveData);
      // R2 書込みと同じ JSON.stringify 境界を通し、undefined キーの脱落も含めて再現する。
      rebuilt.set(Number(m[1]), JSON.parse(JSON.stringify(archiveData.gameResults)));
      return { ok: true };
    },
  };

  // writer の失敗ログは従来どおり検査材料として回収し、DEBUG 時だけ画面にも出す。
  await withVendorLogging(() => GameMasterDO.prototype.appendGameResultsToR2Groups.call(
      receiver, blockNum, allGroupResults, depositorResults, groups
    ), { onError: (...args) => writerErrors.push(args.map(String).join(' ')) });

  const missing = allGroupResults
    .map((g) => Number(g.groupId))
    .filter((gid) => !rebuilt.has(gid));
  if (writerErrors.length > 0 || missing.length > 0) {
    throw new Error([
      ...writerErrors,
      ...(missing.length > 0 ? [`canonical writer produced no rows for group(s): ${missing.join(',')}`] : []),
    ].join('; '));
  }
  return rebuilt;
}

export function neutralizeGroupGameResults(rows, summarySchemaVersion) {
  if (!Array.isArray(rows)) return rows;
  const c = JSON.parse(JSON.stringify(rows));
  const legacyMutable = summarySchemaVersion == null
    || (typeof summarySchemaVersion === 'number'
      && Number.isFinite(summarySchemaVersion)
      && summarySchemaVersion < 3);
  if (legacyMutable) {
    for (const row of c) {
      if (row && typeof row === 'object' && !Array.isArray(row)) delete row.claimed;
    }
  }
  return c;
}

export function compareGroupGameResultRows(expectedRows, publishedRows, summarySchemaVersion) {
  const expected = neutralizeGroupGameResults(expectedRows, summarySchemaVersion);
  const published = neutralizeGroupGameResults(publishedRows, summarySchemaVersion);
  const diffs = diffPaths(expected, published, { ignore: [] }) || [];
  return { ok: diffs.length === 0, diffs };
}

async function compareGroupGameResults(ctx, S, allGroupResults, depositorResults) {
  const { report, ui, blockNum: N } = ctx;
  let expectedByGroup;
  try {
    expectedByGroup = await rebuildCanonicalGroupGameResults(
      N, allGroupResults, depositorResults, S.d1Groups
    );
  } catch (e) {
    const failures = `canonical projection failed: ${e?.message || String(e)}`;
    report.check('check.stageC.groupGameResultsMatch', 'fail', {
      groups: S.orderedGroupIds.length, failures, diffCount: '-',
    });
    S.anomalies.push(ui.t('stageC.anomaly.groupGameResultsMismatch', { failures }));
    return false;
  }

  const failures = [];
  let diffCount = 0;
  for (const gid of S.orderedGroupIds) {
    if (S.missingGroupArchives?.has(gid)) continue;
    const expected = expectedByGroup.get(Number(gid));
    const published = S.groupPublished.get(gid)?.gameResults;
    const cmp = compareGroupGameResultRows(
      expected, published, S.files.summary?.data?.schemaVersion
    );
    if (!cmp.ok) {
      diffCount += cmp.diffs.length;
      const sample = cmp.diffs.slice(0, 3).map((d) => d.path || '(root)').join(',');
      failures.push(`group${gid}:${sample}`);
    }
  }
  const ok = failures.length === 0;
  report.check('check.stageC.groupGameResultsMatch', ok ? 'pass' : 'fail', {
    groups: S.orderedGroupIds.length - (S.missingGroupArchives?.size || 0),
    failures: failures.slice(0, 10).join('; ') || '-',
    diffCount,
  });
  if (!ok) {
    S.anomalies.push(ui.t('stageC.anomaly.groupGameResultsMismatch', {
      failures: failures.slice(0, 5).join('; '),
    }));
  }
  return ok;
}

export function compareGroupCanonicalTimelineRows(expectedRows, publishedRows) {
  const diffs = diffPaths(expectedRows, publishedRows, { ignore: [] }) || [];
  return { ok: diffs.length === 0, diffs };
}

function compareGroupCanonicalTimelines(ctx, S, allGroupResults) {
  const { report, ui } = ctx;
  const expectedByGroup = new Map(
    allGroupResults.map(group => [Number(group.groupId), group.canonicalTimeline])
  );
  const failures = [];
  let diffCount = 0;
  for (const gid of S.orderedGroupIds) {
    if (S.missingGroupArchives?.has(gid)) continue;
    const expected = expectedByGroup.get(Number(gid));
    const published = S.groupPublished.get(gid)?.canonicalTimeline;
    const cmp = compareGroupCanonicalTimelineRows(expected, published);
    if (!cmp.ok) {
      diffCount += cmp.diffs.length;
      const sample = cmp.diffs.slice(0, 3).map(d => d.path || '(root)').join(',');
      failures.push(`group${gid}:${sample}`);
    }
  }
  const ok = failures.length === 0;
  report.check('check.stageC.groupCanonicalTimelineMatch', ok ? 'pass' : 'fail', {
    groups: S.orderedGroupIds.length - (S.missingGroupArchives?.size || 0),
    failures: failures.slice(0, 10).join('; ') || '-',
    diffCount,
  });
  if (!ok) {
    S.anomalies.push(ui.t('stageC.anomaly.groupCanonicalTimelineMismatch', {
      failures: failures.slice(0, 5).join('; '),
    }));
  }
  return ok;
}

// ============================================================
// Step 7: summary 照合（生バイト優先 → 可変フィールド中立化して差分）
// ============================================================
function neutralizeSummary(summary) {
  const c = JSON.parse(JSON.stringify(summary));
  // 🔴 P-2026-0842（2026-08-08・台帳 C-3）: 正典は `updatedAt` / `createdAt` を
  //    公開 summary に**入れなくなった**（実行時刻でバイトが動くと manifestHash が動き、
  //    `resultRegistrationCount` の「結果差し替えの可能性」WARN が
  //    無害な再実行と区別できなくなるため）。
  //    削除は**旧ブロックの互換のため残す**（存在しないキーの delete は no-op）。
  const legacyMutable = c?.schemaVersion == null
    || (typeof c.schemaVersion === 'number'
      && Number.isFinite(c.schemaVersion)
      && c.schemaVersion < 2);
  if (legacyMutable) {
    delete c.updatedAt;  // 旧 buildBlockSummaryWithResults（生成時刻）
    delete c.createdAt;  // 旧 autoDistribute / finalizeNoGameBlock（生成時刻）
    for (const g of (c.groups || [])) {
      for (const m of (g.members || [])) delete m.claimed;
      for (const d of (g.depositor_results || [])) delete d.claimed;
    }
  }
  return c;
}

function compareSummary(ctx, S, rebuilt) {
  const { report, ui } = ctx;
  // G1: デュアルroot検証（verifyMerkle）が「独自再計算した結果から構築したroot」を
  // 導出できるよう、再計算summaryを保存する（auto/本編どちらの経路もここを通る）。
  S.rebuiltSummary = rebuilt;
  const published = S.files.summary.data;
  const rebuiltRaw = JSON.stringify(rebuilt);
  // 公開 summary は入口で正準JSONを確認済み。巨大な取得時 raw はそこで解放しているため、
  // 必要なこの瞬間だけ再直列化する（公開rawと同一バイトになる）。
  const publishedRaw = S.files.summary.raw ?? JSON.stringify(published);
  const byteExact = byteEqual(rebuiltRaw, publishedRaw);
  if (byteExact) {
    report.check('check.stageC.summaryByteExact', 'pass', {});
    report.check('check.stageC.summaryMatch', 'pass', { mode: 'byte' });
    return true;
  }
  // byte不一致は公開後の可変フィールド更新（claimed/updatedAt）で正常に起こる。
  // 判定は下の中立化比較（summaryMatch）が行うため、ここは情報表示のみ。
  ui.println(ui.t('stageC.summaryNotByteExact'));
  const diffs = (diffPaths(neutralizeSummary(rebuilt), neutralizeSummary(published), { ignore: [] }) || [])
    .map(d => (typeof d === 'string' ? d : JSON.stringify(d)));
  const ok = diffs.length === 0;
  report.check('check.stageC.summaryMatch', ok ? 'pass' : 'fail',
    { mode: 'neutralized', diffs: diffs.slice(0, 20).join(', ') || '-', diffCount: diffs.length });
  if (!ok) S.anomalies.push(ui.t('stageC.anomaly.summaryDiff', { count: diffs.length, sample: diffs.slice(0, 5).join(', ') }));
  return ok;
}

export async function verifyTimelineNoGameFinality(ctx, S) {
  const { report, blockNum: N } = ctx;
  const published = S.files.summary?.data;
  const finality = published?.noGameFinality;
  const causeAllowed = TIMELINE_NO_GAME_CAUSES.includes(published?.noGameCause);
  const invalidEmergencyCause = Boolean(ctx.data.emergencySource) && !causeAllowed;
  let chainOk = false;
  let chainError = null;
  let finalityError = null;
  let authoritative = null;
  const observedFinality = {};
  let knownFinalityMismatch = false;
  let closeBlock = null;
  let finalityBeforeClose = false;
  try {
    if (!finality || finality.schemaVersion !== 1 || !/^\d+$/.test(String(finality.safeBlockNumber))) {
      throw new Error('missing or invalid noGameFinality schema');
    }
    const safeNumber = BigInt(finality.safeBlockNumber);
    const latest = await ctx.chain.latest();
    const currentSafe = toBlockBigInt(latest.number) - BigInt(ctx.cfg.pins.confirmationBlocks);
    if (safeNumber > currentSafe) throw new Error('declared safe block is not confirmation-safe');
    // 公開の窓も偽りうるため、宣言高を読む前に今の安全高の窓で照合する。
    // root省略経路もこの同じ高さ・読取結果を使い、窓を読み直さない。
    const currentWindow = { safeNumber: currentSafe.toString(), rw: null, error: null };
    S.timelineNoGameCurrentWindow = currentWindow;
    try {
      const rw = await ctx.chain.resultWindow(N, { blockNumber: currentSafe });
      currentWindow.rw = { openAt: num(rw.openAt ?? rw[0]), closeAt: num(rw.closeAt ?? rw[1]) };
      observedFinality.resultOpenAt = currentWindow.rw.openAt;
      observedFinality.resultCloseAt = currentWindow.rw.closeAt;
      knownFinalityMismatch = Number(finality.resultOpenAt) !== observedFinality.resultOpenAt
        || Number(finality.resultCloseAt) !== observedFinality.resultCloseAt;
    } catch (error) {
      if (!(error instanceof ArchiveUnavailableError)) throw error;
      currentWindow.error = error;
    }
    // 現在の窓が型付きで読めないときだけ公開値の下限へ落ちる。
    // 公開値で古い読取先を選ばせない。閉鎖時刻のlower_boundより前なら、
    // その高さを読まなくても閉鎖前と分かる。探索不能でも他の読取は続ける。
    try {
      closeBlock = toBlockBigInt(await ctx.chain.findBlockByTimestamp(
        currentWindow.rw ? observedFinality.resultCloseAt : Number(finality.resultCloseAt),
      ));
    } catch (error) {
      if (!(error instanceof ArchiveUnavailableError)) throw error;
    }
    if (closeBlock !== null && safeNumber < closeBlock) {
      finalityBeforeClose = true;
      throw new Error('declared safe block precedes result window close');
    }
    if (knownFinalityMismatch) throw new Error('declared result window differs from current safe-chain window');
    const atSafe = { blockNumber: safeNumber };
    // 一つの履歴state失敗で、ヘッダ・set-once配線・別の読取の結果を捨てない。
    const reads = await Promise.allSettled([
      ctx.chain.getBlock(safeNumber),
      ctx.chain.resultWindow(N, atSafe),
      ctx.chain.resultCount(N, atSafe),
      ctx.chain.evidenceAddress(),
    ]);
    const [safeBlock, rw, count, evidenceAddress] = reads.map((r) => r.value);
    if (safeBlock) observedFinality.safeTimestamp = Number(safeBlock.timestamp);
    if (rw) {
      observedFinality.resultOpenAt = num(rw.openAt ?? rw[0]);
      observedFinality.resultCloseAt = num(rw.closeAt ?? rw[1]);
    }
    if (count != null) observedFinality.resultCount = Number(count);
    if (evidenceAddress != null) observedFinality.evidenceContract = lower(evidenceAddress);
    knownFinalityMismatch = Object.entries(observedFinality).some(([key, value]) =>
      key === 'evidenceContract' ? lower(finality[key]) !== value : Number(finality[key]) !== value)
      || (count != null && Number(count) !== 0)
      || (safeBlock && rw && Number(safeBlock.timestamp) < observedFinality.resultCloseAt);
    const failed = reads.filter((r) => r.status === 'rejected');
    if (failed.length) throw (failed.find((r) => !(r.reason instanceof ArchiveUnavailableError)) || failed[0]).reason;
    if (currentWindow.error) throw currentWindow.error;
    authoritative = {
      schemaVersion: 1,
      evidenceContract: lower(evidenceAddress),
      safeBlockNumber: safeNumber.toString(),
      safeTimestamp: Number(safeBlock.timestamp),
      resultOpenAt: num(rw.openAt ?? rw[0]),
      resultCloseAt: num(rw.closeAt ?? rw[1]),
      resultCount: Number(count),
    };
    chainOk = lower(finality.evidenceContract) === authoritative.evidenceContract
      && String(finality.safeBlockNumber) === authoritative.safeBlockNumber
      && Number(finality.safeTimestamp) === authoritative.safeTimestamp
      && Number(finality.resultOpenAt) === authoritative.resultOpenAt
      && Number(finality.resultCloseAt) === authoritative.resultCloseAt
      && Number(finality.resultCount) === 0
      && authoritative.resultCount === 0
      && authoritative.safeTimestamp >= authoritative.resultCloseAt;
  } catch (error) {
    if (error instanceof ArchiveUnavailableError) {
      finalityError = error;
      // no-gameの形や配分の再構築はこの古いfinalityの真偽に依存しない。
      report.fact('stageC.noGameFinalityError', error);
      if (!invalidEmergencyCause && !knownFinalityMismatch) report.unverified('check.stageC.timelineNoGameFinality', error, { reason: 'archive_unavailable' });
    }
    chainError = String(error?.message || error);
  }
  if (!finalityError || invalidEmergencyCause || knownFinalityMismatch) report.check(
    'check.stageC.timelineNoGameFinality',
    chainOk && !invalidEmergencyCause ? 'pass' : 'fail',
    invalidEmergencyCause
      ? {
        safeBlock: finality?.safeBlockNumber ?? '-',
        resultCount: authoritative?.resultCount ?? '-',
        reason: 'invalid_no_game_cause',
        cause: published?.noGameCause ?? null,
        allowedCauses: TIMELINE_NO_GAME_CAUSES.join(','),
        instruction: MANIFEST_CORE_RETRY_INSTRUCTION,
        error: 'noGameCause cannot be independently recomputed and is outside the canonical allowlist',
      }
      : {
        safeBlock: finality?.safeBlockNumber ?? '-',
        resultCount: authoritative?.resultCount ?? '-',
        error: chainError || (chainOk ? '-' : 'declared finality differs from safe-chain state'),
      },
  );

  const rebuiltFinality = authoritative ? {
    schemaVersion: 1,
    evidenceContract: authoritative.evidenceContract,
    safeBlockNumber: authoritative.safeBlockNumber,
    safeTimestamp: authoritative.safeTimestamp,
    resultOpenAt: authoritative.resultOpenAt,
    resultCloseAt: authoritative.resultCloseAt,
    resultCount: 0,
  } : finalityError || knownFinalityMismatch ? { ...finality, ...observedFinality } : finality;
  const orderedFinality = rebuiltFinality ? {
    schemaVersion: 1,
    evidenceContract: rebuiltFinality.evidenceContract,
    safeBlockNumber: rebuiltFinality.safeBlockNumber,
    safeTimestamp: rebuiltFinality.safeTimestamp,
    resultOpenAt: rebuiltFinality.resultOpenAt,
    resultCloseAt: rebuiltFinality.resultCloseAt,
    resultCount: 0,
  } : null;

  const groupClaimOverlay = Boolean(ctx.data.emergencySource) || Number(published?.schemaVersion) >= 3;
  const rebuilt = {
    schemaVersion: groupClaimOverlay ? 3 : 2,
    blockNum: N,
    blockReward: getBlockRewardWei(N).toString(),
    totalPlayers: ctx.data.gameSelection?.players?.length ?? 0,
    totalGroups: 0,
    noGame: true,
    majorLangs: [],
    groups: [],
    claimStatusKey: `games/block${N}/claim-status.json`,
    ...(groupClaimOverlay ? { claimLayout: 'group-overlays-v1' } : {}),
    noGameReason: 'timeline_unverified',
    noGameCause: published?.noGameCause,
    noGameFinality: orderedFinality,
  };
  // finality writerの正確な順序は schema/address/safeBlock/safeTs/resultOpen/resultClose/resultCount。
  // chat window は evidence-report/manifest rules 側で固定し、summary の最小 schema には含めない。
  const shapeOk = (chainOk || finalityError instanceof ArchiveUnavailableError) && rebuilt.totalPlayers >= 3
    && causeAllowed
    && published?.autoDistributed === undefined
    && canonicalEqual(published, rebuilt);
  report.check('check.stageC.timelineNoGameSummary', shapeOk ? 'pass' : 'fail', {
    players: rebuilt.totalPlayers,
    cause: published?.noGameCause ?? '-',
  });
  compareSummary(ctx, S, rebuilt);
  if (finalityBeforeClose) report.check('check.stageC.summaryMatch', 'fail', {
    ...report.get('check.stageC.summaryMatch').params,
    reason: 'safe_block_before_result_close',
    safeBlock: finality.safeBlockNumber,
    closeBlock: closeBlock.toString(),
  });
  // 緊急固定一式は、公開summaryを写すのではなく、この関数が安全ブロックから
  // 再構築した値を vendored GM の finalizeNoGameBlock() へ渡す。
  S.timelineNoGameCanonical = {
    rebuilt,
    authoritative,
    invalidNoGameCause: invalidEmergencyCause,
  };
  return chainOk && shapeOk && !invalidEmergencyCause;
}

function timelineNoGameLiveSnapshotShowsStarted(response) {
  if (!response) return false;
  if (response.parseError || response.sizeError || !response.data
      || typeof response.data !== 'object' || Array.isArray(response.data)) {
    return null;
  }
  const snapshot = response.data;
  const phaseStarted = ['chatting', 'submitting', 'completed'].includes(snapshot.phase);
  const phaseTimes = snapshot.phaseTimestamps && typeof snapshot.phaseTimestamps === 'object'
    ? ['chattingAt', 'submittingAt', 'completedAt']
      .some((key) => snapshot.phaseTimestamps[key] != null)
    : false;
  const positiveCounter = (value) => value && typeof value === 'object'
    && Object.values(value).some((count) => Number(count) > 0);
  const actions = snapshot.actions && typeof snapshot.actions === 'object'
    ? snapshot.actions : {};
  const actionPresent = ['votes', 'reports'].some((key) => actions[key]
    && typeof actions[key] === 'object' && Object.keys(actions[key]).length > 0);
  return phaseStarted
    || phaseTimes
    || (Array.isArray(snapshot.messages) && snapshot.messages.length > 0)
    || positiveCounter(snapshot.charCounts)
    || positiveCounter(snapshot.messageCounts)
    || actionPresent
    || (Array.isArray(snapshot.receipts) && snapshot.receipts.length > 0)
    || (Array.isArray(snapshot.submittedUids) && snapshot.submittedUids.length > 0)
    || snapshot.gameSkipped != null;
}

async function emergencySignedLiveMessageCount(ctx, key, snapshot) {
  const match = new RegExp(`^live/block${ctx.blockNum}/group(\\d+)\\.json$`).exec(key);
  if (!match || !Array.isArray(snapshot?.messages)) return 0;
  const groupId = Number(match[1]);
  const members = new Map((ctx.data.gameSelection?.players || [])
    .map((player) => [String(player?.data?.uid), player?.data]));
  let valid = 0;
  for (const message of snapshot.messages.slice(0, 1_000)) {
    const uid = String(message?.uid ?? '');
    const member = members.get(uid);
    const bAddr = parseBlockAddress(member?.bAddr);
    if (!bAddr || typeof message?.text !== 'string' || !Number.isSafeInteger(message?.timestamp)
        || !isCanonicalSignature(message?.signature)) continue;
    try {
      if (await verifyMessage({
        address: bAddr.address,
        message: chatSignStringV2(ctx.blockNum, groupId, uid, message.text, message.timestamp),
        signature: message.signature,
      })) valid++;
    } catch {
      // 署名として読めない世代は開始根拠に格上げしない。
    }
  }
  return valid;
}

async function inspectEmergencyTimelineNoGameChatArtifacts(ctx, manifest) {
  const N = ctx.blockNum;
  const index = ctx.data.emergencySource.index;
  let manifestAnchored = false;
  try {
    manifestAnchored = Boolean(manifest && ctx.data.emergencySource.chainResultMarker?.hash
      && manifestCoreHash(manifest).toLowerCase()
        === String(ctx.data.emergencySource.chainResultMarker.hash).toLowerCase());
  } catch {
    // 錨と照合できない manifest の申告は開始証拠にならない。
  }
  const derived = ctx.data.groupsDerived;
  const groupIds = Array.isArray(derived) && derived.length > 0
    ? derived.map((group) => Number(group?.groupId)) : [];
  const knownGroups = groupIds.length > 0;
  const indexedKeys = Object.keys(index?.objects || {}).filter((key) => (
    new RegExp(`^games/block${N}/group\\d+\\.json$`).test(key)
    || new RegExp(`^live/block${N}/group\\d+(?:\\.submissions)?\\.json$`).test(key)
  ));
  const keys = knownGroups ? groupIds.flatMap((groupId) => [
    `games/block${N}/group${groupId}.json`,
    `live/block${N}/group${groupId}.submissions.json`,
    `live/block${N}/group${groupId}.json`,
  ]) : indexedKeys;
  const evidenceKeys = new Set();
  const inspectionErrors = [];
  const ignored = new Map();
  const noteIgnored = (key, difference) => {
    const id = `${key}:${difference.what}:${difference.reason}`;
    const prior = ignored.get(id);
    if (prior) { prior.rebuilt.ignoredGenerations++; return; }
    difference.rebuilt.ignoredGenerations = 1;
    ignored.set(id, difference);
    recordEmergencyDifference(ctx, difference);
  };
  for (const key of keys) {
    const isGroupArchive = key.startsWith(`games/block${N}/group`);
    const isLive = new RegExp(`^live/block${N}/group\\d+\\.json$`).test(key);
    const groupId = Number(/group(\d+)/.exec(key)?.[1]);
    let offset = 0;
    let hasMore = false;
    do {
      const archived = await readEmergencyArtifactGenerations({
        sourceDir: ctx.data.emergencySource.sourceDir, index, keys: [key], offset,
      });
      const item = archived.get(key);
      hasMore = item?.hasMore === true;
      offset += item?.generations?.length || 0;
      for (const generation of (item?.generations || [])) {
        if (generation.error) {
          noteIgnored(key, {
            checkId: 'check.stageC.timelineNoGameChatNotStarted',
            what: 'unreadable archived chat generation is ignored',
            chain: { sha256: generation.row?.sha256 ?? null,
              bytes: generation.row?.bytes ?? null, valueType: 'unparsed' },
            rebuilt: { acceptedAsStartEvidence: false },
            reason: generation.error,
          });
          continue;
        }
        if (isGroupArchive) {
          const data = generation.data;
          const shapeValid = data && !Array.isArray(data) && typeof data === 'object'
            && data.meta?.blockNum === N && data.meta?.groupId === groupId
            && Array.isArray(data.members) && Array.isArray(data.messages);
          const declared = manifestAnchored ? manifest?.files?.[key] : null;
          if (shapeValid && typeof declared === 'string'
              && declared.replace(/^0x/i, '').toLowerCase() === String(generation.row.sha256).toLowerCase()) {
            evidenceKeys.add(`${key} manifest-anchored`);
          } else {
            noteIgnored(key, {
              checkId: 'check.stageC.timelineNoGameChatNotStarted',
              what: 'unanchored or malformed group archive is ignored',
              chain: { sha256: generation.row?.sha256 ?? null,
                bytes: generation.row?.bytes ?? null, valueType: Array.isArray(data) ? 'array' : typeof data },
              rebuilt: { acceptedAsStartEvidence: false },
              reason: 'a group archive needs its declared manifest sha256 and group structure',
            });
          }
        } else if (isLive) {
          const signedMessages = await emergencySignedLiveMessageCount(ctx, key, generation.data);
          if (signedMessages > 0) evidenceKeys.add(`${key} signedMessages=${signedMessages}`);
          else if (timelineNoGameLiveSnapshotShowsStarted({ data: generation.data }) === true) {
            noteIgnored(key, {
              checkId: 'check.stageC.timelineNoGameChatNotStarted',
              what: 'unsigned live snapshot fields claim that chat started',
              chain: { sha256: generation.row?.sha256 ?? null,
                bytes: generation.row?.bytes ?? null, valueType: 'object' },
              rebuilt: { validSignedMessages: 0, acceptedAsStartEvidence: false },
              reason: 'phase, counters, actions, receipts and submitted uids are not signed',
            });
          }
        }
      }
    } while (hasMore && evidenceKeys.size === 0);
    if (evidenceKeys.size > 0) break;
  }
  for (const candidate of (ctx.data.emergencySubmissionCandidates || [])) {
    if (candidate?.valid === true) evidenceKeys.add('valid archived submission');
  }
  return { gameGroupsValid: true, groupIds, inspectedKeys: keys,
    evidenceKeys: [...evidenceKeys], inspectionErrors, error: null };
}

async function inspectTimelineNoGameChatArtifacts(ctx, gameGroupsResponse, manifest = null) {
  const N = ctx.blockNum;
  if (ctx.data.emergencySource) {
    return inspectEmergencyTimelineNoGameChatArtifacts(ctx, manifest);
  }
  // Stage B-1 が公開選出記録を再導出済みなら、組分けより前の段階は確定している。
  // 組の一覧が無い／読めない場合だけ記録を再読し、探索キーが空のまま
  // 「未開始」と断定するのを防ぐ。Stage B の確認印が無い直呼び出しや
  // 選出前の no-game は従来の判定を維持する。
  const groupsUnreadable = Boolean(gameGroupsResponse?.parseError || gameGroupsResponse?.sizeError)
    || Boolean(gameGroupsResponse && (!gameGroupsResponse.data
      || typeof gameGroupsResponse.data !== 'object'));
  if (!gameGroupsResponse || groupsUnreadable) {
    const selectionVerified = ctx.report.get?.('check.stageB.playersMatch')?.status === 'pass';
    if (!selectionVerified && !gameGroupsResponse) {
      return { gameGroupsValid: true, groupIds: [], inspectedKeys: [],
        evidenceKeys: [], inspectionErrors: [], error: null };
    }
    let selectionResponse;
    let selectionError = null;
    if (selectionVerified) {
      try {
        selectionResponse = await ctx.r2.fetchJson(
          `entries/block${N}/game_selection.json`, { reuse: ctx.data.reuseFiles },
        );
      } catch (error) {
        selectionError = String(error?.message || error);
      }
    }
    const selection = selectionResponse?.data;
    const selectionReadable = selection && typeof selection === 'object'
      && !Array.isArray(selection) && selection.blockNum === N
      && Array.isArray(selection.players);
    if (selectionVerified) {
      if (!gameGroupsResponse && selectionReadable) {
        try {
          const registration = await resolveRosterRegistration(ctx.chain, N);
          // 追記履歴から開始前の正典登録が無いと確定できる場合だけ通す。
          // 旧 HashStorage の現在値だけでは過去の不在を証明できない。
          if (!registration.legacy && registration.status === 'none') {
            return { gameGroupsValid: true, groupIds: [], inspectedKeys: [],
              evidenceKeys: [], inspectionErrors: [], error: null };
          }
        } catch { /* 登録を読めなければ従来の未検証へ倒す */ }
      }
      let error;
      if (selectionError) error = `game_selection read failed: ${selectionError}`;
      else if (!selectionResponse) error = 'game_selection disappeared after Stage B verification';
      else if (!selectionReadable) {
        error = `game_selection unreadable: ${selectionResponse.sizeError || selectionResponse.parseError || 'invalid selection record'}`;
      } else {
        error = `game_groups unavailable after published game_selection: ${gameGroupsResponse?.sizeError || gameGroupsResponse?.parseError || 'missing or unreadable'}`;
      }
      return { gameGroupsValid: false, groupIds: [], inspectedKeys: [],
        evidenceKeys: [], inspectionErrors: [], unverified: true, error };
    }
    if (groupsUnreadable) {
      return { gameGroupsValid: false, groupIds: [], inspectedKeys: [],
        evidenceKeys: [], inspectionErrors: [],
        error: gameGroupsResponse.sizeError || gameGroupsResponse.parseError || 'unreadable game_groups' };
    }
  }
  const data = gameGroupsResponse.data;
  if (!data || typeof data !== 'object' || !Array.isArray(data.groups)) {
    return {
      gameGroupsValid: false,
      groupIds: [],
      inspectedKeys: [],
      evidenceKeys: [],
      inspectionErrors: [],
      error: gameGroupsResponse.sizeError || gameGroupsResponse.parseError
        || 'game_groups is not a JSON object with groups[]',
    };
  }
  const groupIds = data.groups.map((group) => Number(group?.groupId));
  const uniqueIds = new Set(groupIds);
  const gameGroupsValid = groupIds.length > 0
    && groupIds.every((groupId) => Number.isSafeInteger(groupId) && groupId >= 0)
    && uniqueIds.size === groupIds.length
    && (data.totalGroups === undefined || Number(data.totalGroups) === groupIds.length);
  if (!gameGroupsValid) {
    return {
      gameGroupsValid: false,
      groupIds,
      inspectedKeys: [],
      evidenceKeys: [],
      inspectionErrors: [],
      error: 'game_groups has invalid, duplicate, empty, or inconsistent group ids',
    };
  }

  // Q51 の「チャット開始の証拠」として独立検証器が列挙できる公開物は次の2系統。
  // roster / shard / game_groups 自体はチャット開始前にも公開されるため含めない。
  const inspectedKeys = [];
  const evidenceKeys = [];
  const inspectionErrors = [];
  for (const groupId of groupIds) {
    const keys = [
      `games/block${N}/group${groupId}.json`,
      `live/block${N}/group${groupId}.submissions.json`,
      `live/block${N}/group${groupId}.json`,
    ];
    const responses = await Promise.all(keys.map(async (key) => {
      inspectedKeys.push(key);
      return [key, await ctx.r2.fetchJson(key, { reuse: ctx.data.reuseFiles })];
    }));
    for (const [key, response] of responses) {
      // JSON が壊れていてもキーの存在自体が、結果／提出写しを公開した証拠になる。
      if (key.endsWith('.submissions.json') || key.startsWith(`games/block${N}/group`)) {
        if (response) evidenceKeys.push(key);
        continue;
      }
      // live snapshot は初期化直後の waiting 状態でも公開される。存在だけではなく、
      // phase・発言・行動・receipt・提出のいずれかが進んだ内容だけを開始証拠にする。
      const started = timelineNoGameLiveSnapshotShowsStarted(response);
      if (started === true) evidenceKeys.push(key);
      else if (started === null) inspectionErrors.push(`${key}: unreadable live snapshot`);
    }
    if (evidenceKeys.length > 0) break;
  }
  return { gameGroupsValid, groupIds, inspectedKeys, evidenceKeys, inspectionErrors, error: null };
}

export async function verifyTimelineNoGameChatNotStarted(ctx, S) {
  const chatArtifacts = await inspectTimelineNoGameChatArtifacts(ctx, S.files.gameGroups, S.files.manifest?.data);
  const chatNotStarted = chatArtifacts.gameGroupsValid
    && chatArtifacts.evidenceKeys.length === 0
    && chatArtifacts.inspectionErrors.length === 0;
  const chatStatus = chatArtifacts.unverified ? 'warn' : (chatNotStarted ? 'pass' : 'fail');
  ctx.report.check('check.stageC.timelineNoGameChatNotStarted', chatStatus, {
    groups: chatArtifacts.groupIds.length,
    inspected: chatArtifacts.inspectedKeys.length,
    evidence: chatArtifacts.evidenceKeys.join(', ') || '-',
    error: chatArtifacts.error || chatArtifacts.inspectionErrors.join('; ') || '-',
  });
  return { chatNotStarted, chatStatus, chatArtifacts };
}

// run() が blockStates の非0 root を確認した後だけ使う専用ゲート。
// 共通の証拠検査を呼ぶだけで終わらせず、rootあり分岐の全体判定へFAILを反映する。
export async function verifyTimelineNoGameRootPresentChatGate(ctx, S) {
  const result = await verifyTimelineNoGameChatNotStarted(ctx, S);
  if (result.chatStatus === 'fail') ctx.data.stopReason = 'fail';
  if (result.chatStatus === 'warn') ctx.data.stopReason = 'not_ready';
  return result;
}

// Q46: proofRequired後にrootを出さない timeline no-game の専用終端。
// Stage A/B が登録・抽選を再導出済みであることを前提に、root gateより先に公開summaryと
// safe-chain finalityを検査する。名乗りだけでは通さず、期限前は未完了に留める。
export async function verifyTimelineNoGameRootOmission(ctx, S) {
  const { report, blockNum: N } = ctx;
  const summaryResponse = await ctx.r2.fetchJson(
    `games/block${N}/summary.json`,
    { reuse: ctx.data.reuseFiles },
  );
  if (!summaryResponse?.data || typeof summaryResponse.data !== 'object') {
    report.check('check.stageC.timelineNoGameFinality', 'fail', {
      safeBlock: '-', resultCount: '-', error: 'timeline no-game summary is unavailable',
    });
    report.check('check.stageC.timelineNoGameSummary', 'fail', { players: '-', cause: '-' });
    report.check('check.stageC.rootSubmitted', 'fail', { reason: 'timeline_no_game_summary_unavailable' });
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }

  let gameGroupsResponse;
  try {
    gameGroupsResponse = await ctx.r2.fetchJson(
      `entries/block${N}/game_groups.json`,
      { reuse: ctx.data.reuseFiles },
    );
  } catch (error) {
    gameGroupsResponse = { data: null, parseError: String(error?.message || error) };
  }

  S.files = {
    summary: {
      data: summaryResponse.data,
      raw: summaryResponse.raw ?? JSON.stringify(summaryResponse.data),
    },
    gameGroups: gameGroupsResponse,
  };
  const { chatNotStarted, chatStatus } = await verifyTimelineNoGameChatNotStarted(ctx, S);
  report.check('check.stageC.prerequisites', 'pass', { mode: 'timeline_no_game_root_omission' });
  const schemaOk = await verifyTimelineNoGameFinality(ctx, S);
  const stateError = report.getFact('stageC.noGameFinalityError') || report.getFact('stageC.resultStateError');
  const finalityUnchecked = stateError instanceof ArchiveUnavailableError;
  let authoritative = S.timelineNoGameCanonical?.authoritative ?? null;
  let currentReadError = null;
  let windowClosed = schemaOk;
  if (finalityUnchecked) {
    // 窓が閉じた後のNのcount/窓は変わらない。古いfinalityと別に今の安全高で検閲を調べる。
    const currentWindow = S.timelineNoGameCurrentWindow;
    const safeNumber = BigInt(currentWindow.safeNumber);
    const atSafe = { blockNumber: safeNumber };
    const reads = await Promise.allSettled([
      ctx.chain.resultCount(N, atSafe),
      currentWindow.error ? Promise.reject(currentWindow.error) : Promise.resolve(currentWindow.rw),
      ctx.chain.getBlock(safeNumber),
    ]);
    const [count, rw, block] = reads.map((r) => r.value);
    authoritative = {
      resultCount: count == null ? null : Number(count),
      resultCloseAt: rw ? num(rw.closeAt ?? rw[1]) : null,
    };
    windowClosed = Boolean(rw && block && Number(block.timestamp) >= authoritative.resultCloseAt);
    const failed = reads.filter((r) => r.status === 'rejected');
    currentReadError = (failed.find((r) => !(r.reason instanceof ArchiveUnavailableError)) || failed[0])?.reason;
  }
  const shapeValid = report.get('check.stageC.timelineNoGameSummary')?.status === 'pass'
    && report.get('check.stageC.timelineNoGameFinality')?.status !== 'fail';
  const noEvidence = (finalityUnchecked ? shapeValid && windowClosed : schemaOk) && authoritative?.resultCount === 0;
  if (finalityUnchecked && shapeValid
      && (authoritative?.resultCount == null || (authoritative.resultCount === 0 && !windowClosed))
      && (!currentReadError || currentReadError instanceof ArchiveUnavailableError)) {
    report.unverified('check.stageC.timelineNoGameEvidenceEmpty', currentReadError || stateError, { resultCount: authoritative?.resultCount ?? '-' });
  } else report.check('check.stageC.timelineNoGameEvidenceEmpty', noEvidence ? 'pass' : 'fail', {
    resultCount: authoritative?.resultCount ?? '-',
  });

  let classification = null;
  let deadlineError = null;
  try {
    if (!authoritative || authoritative.resultCloseAt == null) throw new Error('authoritative finality is unavailable');
    const verificationPeriodSec = Number(await ctx.chain.verificationPeriod());
    const latest = await ctx.chain.latest();
    const nowSec = Number(latest.timestamp);
    const deadline = adminCommitRootSubmissionDeadline(
      authoritative.resultCloseAt,
      verificationPeriodSec,
    );
    classification = classifyTimelineNoGameRoot({
      summary: summaryResponse.data,
      chainRoot: ZERO_ROOT,
      rootSubmissionDeadlineSec: deadline,
      nowSec,
      proofRequired: S.zkInfo?.currentProofRequired,
      verification: {
        safeResultWindowClosed: windowClosed && shapeValid,
        evidenceResultCount: authoritative.resultCount,
        selectedPlayerCount: ctx.data.gameSelection?.players?.length ?? null,
        chatStartEvidenceAbsent: chatNotStarted,
      },
    });
  } catch (error) {
    deadlineError = String(error?.message || error);
    classification = classifyTimelineNoGameRoot({
      summary: summaryResponse.data,
      chainRoot: ZERO_ROOT,
      rootSubmissionDeadlineSec: null,
      nowSec: 0,
      proofRequired: S.zkInfo?.currentProofRequired,
      verification: {
        safeResultWindowClosed: windowClosed && shapeValid,
        evidenceResultCount: authoritative?.resultCount ?? null,
        selectedPlayerCount: ctx.data.gameSelection?.players?.length ?? null,
        chatStartEvidenceAbsent: chatNotStarted,
      },
    });
  }

  report.fact('stageC.noGame', true);
  report.fact('stageC.timelineNoGame', true);
  report.fact('stageC.timelineNoGameRoot', classification);
  report.fact('stageC.autoDistributed', false);
  report.fact('stageC.blockReward', getBlockRewardWei(N).toString());
  report.fact('stageC.totalPoints', 0);
  report.fact('stageC.groupCount', 0);
  report.fact('stageC.playerCount', ctx.data.gameSelection?.players?.length ?? 0);
  report.fact('stageC.disqualifiedCount', 0);
  report.fact('stageC.resultCount', authoritative?.resultCount ?? null);
  report.fact('stageC.anomalies', S.anomalies);

  const independentFailure = !shapeValid || authoritative?.resultCount > 0 || chatStatus === 'fail'
    || (currentReadError && !(currentReadError instanceof ArchiveUnavailableError));
  if (independentFailure || (!finalityUnchecked && (!schemaOk || !noEvidence))) {
    report.check('check.stageC.rootSubmitted', 'fail', {
      reason: chatStatus === 'fail'
        ? 'timeline_no_game_chat_artifact_present_or_grouping_invalid'
        : 'timeline_no_game_finality_failed',
    });
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }
  if (chatStatus === 'warn') {
    report.check('check.stageC.rootSubmitted', 'warn', {
      reason: 'timeline_no_game_chat_absence_unverified',
    });
    ctx.data.stopReason = 'not_ready';
    return { stop: true };
  }
  if (finalityUnchecked) {
    report.unverified('check.stageC.rootSubmitted', stateError, {
      reason: currentReadError ? 'archive_unavailable'
        : deadlineError ? 'timeline_no_game_deadline_unavailable'
          : classification.state === TIMELINE_NO_GAME_ROOT_STATE.OMITTED_TERMINAL
            ? 'expected_timeline_no_game_omission' : 'timeline_no_game_deadline_open',
      deadline: classification.rootSubmissionDeadlineSec ?? '-',
    });
    ctx.data.stopReason = 'not_ready';
    return { stop: true };
  }
  if (classification.state === TIMELINE_NO_GAME_ROOT_STATE.OMITTED_TERMINAL) {
    report.check('check.stageC.rootSubmitted', 'pass', {
      reason: 'expected_timeline_no_game_omission',
      deadline: classification.rootSubmissionDeadlineSec,
    });
    return { stop: false };
  }

  report.check('check.stageC.rootSubmitted', 'skip', {
    reason: deadlineError ? 'timeline_no_game_deadline_unavailable' : 'timeline_no_game_deadline_open',
    deadline: classification.rootSubmissionDeadlineSec ?? '-',
    error: deadlineError ?? '-',
  });
  ctx.data.stopReason = 'not_ready';
  return { stop: true };
}

export function checkTimelineNoGameEvidenceEmpty(ctx, S) {
  if (S.evidenceStateError instanceof ArchiveUnavailableError) {
    ctx.report.unverified('check.stageC.timelineNoGameEvidenceEmpty', S.evidenceStateError, {
      resultCount: S.resultCount ?? '-',
    });
    return false;
  }
  const noEvidence = S.resultCount === 0 && Object.keys(S.adoptedByUid || {}).length === 0;
  ctx.report.check('check.stageC.timelineNoGameEvidenceEmpty', noEvidence ? 'pass' : 'fail', {
    resultCount: S.resultCount ?? '-',
  });
  return noEvidence;
}

// ============================================================
// G5 後段: manifest 保留分の確定（Stage C 末尾で呼ぶ）
// claim可変キー（schema v1 summary / group{G} / auto-results）の sha256 不一致は、summaryMatch と
// group{G}.json / gameResults 内容照合が全て PASS した場合に限り
// WARN（post-claim mutation の可能性）へ降格。それ以外は暫定 FAIL のまま確定。
// ============================================================
export function settleManifestParked(ctx, S) {
  const { report, ui } = ctx;
  const parked = S.manifestParked || [];
  if (parked.length === 0) return;
  const st = (id) => report.get(id)?.status;
  const hasGroupKey = parked.some((k) => /\/group\d+\.json$/.test(k));
  const hasAutoResultKey = parked.some((k) => /\/auto-results\.json$/.test(k));
  const prerequisites = ['check.stageC.summaryMatch', ...(hasGroupKey ? [
    'check.stageC.groupGameResultsMatch', 'check.stageC.groupCanonicalTimelineMatch',
  ] : []), ...(hasAutoResultKey ? ['check.stageC.autoResultPage'] : [])];
  if (prerequisites.some((id) => report.get(id)?.status === 'skip'
      && report.get(id)?.reason === 'archive_unavailable')) {
    const error = report.getFact('stageC.lockStateError') || report.getFact('stageC.resultStateError');
    report.unverified('check.stageC.manifestFiles', error, report.get('check.stageC.manifestFiles').params,
      { prerequisite: 'result_content_checks', comparisonStatus: 'fail' });
    return;
  }
  // archiveChainConsistency は、正式Evidenceだけの自己救済で serverState=missing になる正常系を
  // 記述する観測値であり、採点結果の正しさを判定する検査ではない。従来は無条件PASSだったため、
  // claim可変ファイルの降格条件に見せかけて置かず、実際に内容を照合する検査だけを前提にする。
  let ok = st('check.stageC.summaryMatch') === 'pass';
  if (hasGroupKey) {
    ok = ok
      && st('check.stageC.groupMeta') === 'pass'
      && st('check.stageC.groupMembersMatch') === 'pass'
      && st('check.stageC.groupGameResultsMatch') === 'pass'
      && st('check.stageC.groupCanonicalTimelineMatch') === 'pass';
  }
  if (hasAutoResultKey) ok = ok && st('check.stageC.autoResultPage') === 'pass';
  if (ok) {
    report.check('check.stageC.manifestFiles', 'warn',
      { failures: parked.join(', '), checked: S.manifestChecked ?? '-' });
    S.anomalies.push(ui.t('stageC.anomaly.manifestClaimMutation', { files: parked.join(', ') }));
  } else {
    S.anomalies.push(ui.t('stageC.anomaly.fileHashMismatch', { files: parked.join(', ') }));
  }
}

// ============================================================
// Step 8: Merkle 照合（G1改・2026-07-18）— デュアルroot検証。
// leaf 式は game-master-DO.js merkleLeafAndClaimId / TokenMining.sol と同一（vendored本物を使用）。
//
// 保証の主役: 「①独自再計算した結果（S.rebuiltSummary）から構築したroot」と
// 「②配信されているsummary.jsonから構築したroot」の両方がオンチェーンのコミット済み
// rootと一致すること。葉は（請求キー・受取アドレス・金額）のみを含むため、root一致＝
// 金銭的配分の完全一致がMerkleの性質で保証される（運営がコミット済みrootと異なる内容を
// 配信すれば②が、公正な計算と異なる内容をコミットすれば①が不一致になる）。
//
// 旧実装から削除した検査（2026-07-18・ユーザー合意）:
//  - 全items proof検証: rootが一致するツリーから導出されるproofは常に正しい（数学的に冗長）。
//    配布proofファイルの破損は請求時にコントラクトがrevertするだけで公正性と無関係
//    （claim-workerのフォールバック生成が自己修復する）。
//  - 公開ファイルとのバイト同一照合: 公開merkleファイルはメタのみ（G1b分割形式）になった
//    ため、メタ値（root/leafCount/totalAmount）の一致検査に置き換え。
// summaryMatch（内容の全項目比較）は金銭保証の担い手ではなくなったが、葉に入らない公開情報
// （失格理由・ポイント内訳・タブーワード等）の検証と、不一致時の差分診断のため存続する。
// ============================================================
export async function verifyMerkle(ctx, S, gm) {
  const { report, ui, blockNum: N } = ctx;
  const published = S.files.merkle?.data; // G1b: メタのみ {root, leafCount, proofDepth, totalAmount, format:'v2'}
  const onchainRoot = S.blockState.root;
  const emergencyMode = Boolean(ctx.data.emergencySource);

  // ② 配信summary.jsonからの構築
  let tree = null;
  let publicBuildError = null;
  try {
    const entries = withVendorLogging(() => gm.collectClaimEntriesFromSummary(N, S.files.summary.data));
    tree = withVendorLogging(() => gm.buildMerkleTree(N, entries));
  } catch (e) {
    publicBuildError = e;
    S.anomalies.push(ui.t('stageC.anomaly.merkleBuildFailed', { error: e.message }));
  }

  // ① 独自再計算した結果からの構築（compareSummary が S.rebuiltSummary として保存）
  let recomputedRoot = null;
  let recomputedTree = null;
  let recomputedBuildError = null;
  if (S.rebuiltSummary) {
    try {
      recomputedTree = withVendorLogging(() => gm.buildMerkleTree(
        N,
        gm.collectClaimEntriesFromSummary(N, S.rebuiltSummary),
      ));
      recomputedRoot = recomputedTree.root;
    } catch (e) {
      recomputedRoot = null;
      recomputedBuildError = e;
      S.anomalies.push(ui.t('stageC.anomaly.merkleBuildFailed', { error: `recomputed: ${e.message}` }));
    }
  }

  // 必須の merkleRebuild は通常／緊急で同じ「独立再計算summaryの木」を見る。
  // 以前は同じIDを通常=公開summary、緊急=独立summaryで二重定義し、配列外で
  // fail→passへ変えていた。公開summary側の可否は下の別ID `merkleRoot` が
  // tree/published/onchain/recomputedの全要素を比較して常に記録する。
  report.check('check.stageC.merkleRebuild', recomputedTree ? 'pass' : 'fail', recomputedTree
    ? { source: 'recomputed-summary', root: recomputedTree.root, leafCount: recomputedTree.leafCount }
    : { source: 'recomputed-summary', error: recomputedBuildError?.message || 'rebuilt summary unavailable' });
  const unchecked = report.getFact('stageC.lockStateError') instanceof ArchiveUnavailableError;
  if (!recomputedTree && !unchecked) return;
  if (emergencyMode && publicBuildError) {
    recordEmergencyDifference(ctx, {
      checkId: 'check.stageC.merkleRoot',
      what: 'published summary cannot be used to rebuild a Merkle tree',
      chain: { root: S.emergencyRootMissing ? null : onchainRoot },
      rebuilt: { root: recomputedTree.root, leafCount: recomputedTree.leafCount },
      reason: publicBuildError.message,
    });
  }

  // デュアルroot: ①再計算 == ②配信summary == 公開メタ == オンチェーン
  const rootOk = tree && published
    && lower(tree.root) === lower(published.root)
    && lower(tree.root) === lower(onchainRoot)
    && (unchecked || (recomputedRoot !== null && lower(recomputedRoot) === lower(onchainRoot)));
  const gcpMerkleMeta = ctx.data.emergencySource?.authority === 'gcp'
    ? gcpMerkleComparisonDescriptor(S) : null;
  report.check('check.stageC.merkleRoot', rootOk ? 'pass' : 'fail',
    {
      rebuilt: tree?.root ?? null,
      recomputed: recomputedRoot,
      published: gcpMerkleMeta ?? published?.root ?? null,
      onchain: S.emergencyRootMissing ? null : onchainRoot,
      publicBuildError: publicBuildError?.message ?? null,
      ...(unchecked ? { scope: 'published_summary_only', rewardCalculationVerified: false } : {}),
    });
  if (!rootOk) addProofProviderAnomaly(ctx, S);

  // 公開メタの数値一致＋配分合計がブロック報酬以内
  const totalsOk = tree && published
    && Number(published.leafCount) === tree.leafCount
    && String(published.totalAmount) === String(tree.totalAmount)
    && BigInt(tree.totalAmount) <= getBlockRewardWei(N);
  report.check('check.stageC.merkleTotals', totalsOk ? 'pass' : 'fail',
    {
      totalAmount: tree?.totalAmount ?? null,
      declared: gcpMerkleMeta ?? published?.totalAmount ?? null,
      cap: getBlockRewardWei(N).toString(),
    });
  const factsTree = recomputedTree || tree;
  S.factsMerkle = {
    root: factsTree?.root,
    leafCount: factsTree?.leafCount,
    totalAmount: factsTree?.totalAmount,
  };

  // ③ K-S5-002: チェーンに載った請求データからの構築（＝運営が消えたときの保険）
  //
  // R2（②）が主経路で、ほとんどの利用者はそれを見る。チェーン（③）は保険。
  // 両方が提出済み root と一致して初めて「見えているものも保険も正しい」と言える。
  //   ・R2 だけ不一致   → 利用者が見ている内容が偽物
  //   ・チェーンだけ不一致 → 保険が壊れている
  // どちらも FAIL。取得できなかった場合だけ注記つきで skip する（ユーザー決定④）。
  await verifyOnchainClaimData(ctx, S, gm, { onchainRoot });
}

// ============================================================
// K-S5-002: チェーンに載った請求データからの root 再計算
//
// 「運営が R2 を消しても、チェーンのデータだけで提出済み root と同じ木を組み直せる」
// を確かめる。★ 2026-08-01（請求データ自己完結化）以降、組み直しに **EthLock は一切要らない**
// ——受取アドレスと個別配当額が葉から外れ、請求時に契約が EthLock から読むようになったため。
// したがってこの検査は RPC 1本（請求データのチャンク取得）だけで完結し、pass/fail の二値になる。
// ⚠️ 適格集合の完全性（SPEC §8 L1）を見ているのはここではなく、
//    verifyDepositsOnChainForUids → mirrorRewardSplit → compareSummary（summaryMatch）の経路。
// ============================================================
async function verifyOnchainClaimData(ctx, S, gm, { onchainRoot }) {
  const { report, ui, blockNum: N, cfg, chain } = ctx;

  // 宣言フォーマットの pin 照合（知らない形式を「それっぽく」読んで通さない）
  // ⚠️ **厳密照合（未宣言も逸脱）**。maxDepositWei / depositorRounding と同じ扱いにそろえた。
  //    旧実装は未宣言を skip で通していたが、正典は常に claimDataFormat を書き出すので
  //    「無い」＝運営が落としたということ。緩いままだと宣言を消すだけで版数ゲートを外せた。
  const declaredFormat = S.files.manifest?.data?.rules?.claimDataFormat ?? null;
  if (declaredFormat !== cfg.pins.claimDataFormat) {
    report.check('check.stageC.claimDataFormat', 'fail',
      { declared: declaredFormat ?? '(undeclared)', pinned: cfg.pins.claimDataFormat });
    return;
  }
  report.check('check.stageC.claimDataFormat', 'pass',
    { declared: declaredFormat, pinned: cfg.pins.claimDataFormat });

  let fetched;
  try {
    fetched = await fetchClaimDataFromChain(chain, ui, N);
  } catch (e) {
    if (e.integrityFailure) {
      // 取れなかったのではなく**食い違っている** = 保険が壊れている
      report.check('check.stageC.onchainClaimData', 'fail', { error: e.message });
      S.anomalies.push(e.message);
      return;
    }
    fetched = { available: false, reason: e.shortMessage || e.message };
  }

  if (!fetched.available) {
    // ユーザー決定④: 取得できないときは注記つきで skip（R2 側の検証は継続済み）
    const reason = fetched.reason || 'unknown';
    if (fetched.unavailableError instanceof ArchiveUnavailableError) report.unverified('check.stageC.onchainClaimData', fetched.unavailableError, { reason });
    else report.check('check.stageC.onchainClaimData', 'skip', { reason });
    ui.warn(reason === 'not_published'
      ? ui.t('claimData.notPublished')
      : ui.t('claimData.skipped', { reason: fetched.unavailableError instanceof ArchiveUnavailableError ? ui.t('reason.archiveUnavailable') : reason }));
    return;
  }

  let decoded;
  try {
    // bitcoinu-claimdata/3 で非圧縮化。チャンクを連結すればそのまま blob。
    decoded = decodeClaimData(concatChunks(fetched.chunks));
  } catch (e) {
    report.check('check.stageC.onchainClaimData', 'fail', { error: `decode: ${e.message}` });
    S.anomalies.push(`on-chain claim data decode failed: ${e.message}`);
    return;
  }
  if (Number(decoded.blockNum) !== Number(N)) {
    report.check('check.stageC.onchainClaimData', 'fail',
      { error: `blockNum mismatch: payload says ${decoded.blockNum}, expected ${N}` });
    return;
  }

  // ★ 請求データ自己完結化（2026-08-01）: **EthLock を1件も読まずに木を組む。**
  //   これが本改修の主目的そのもので、`claimEntriesFromClaimData` が台帳引数を
  //   受け取らないこと自体が「root は blob の純関数である」ことの型による証明になっている。
  //
  //   旧実装はここで buildDepositLedger を呼んでおり、RPC が過去ログを拒否するなどして
  //   台帳が組めないと `skip` で return していた。skip は report.js の結論判定で fail 扱いに
  //   ならないため、**請求データ検証が無検査になったまま「検証OK」と表示される**経路が
  //   存在した。台帳依存が消えたので、この検査は pass/fail の二値になる。
  //
  //   ⚠️ 適格集合の完全性（SPEC §8 L1）を見ているのはこの関数ではなく、
  //   verifyDepositsOnChainForUids → mirrorRewardSplit → compareSummary（summaryMatch）の経路。
  //   そちらの EthLock 読み取りは**絶対に消さないこと**（消すと本当に穴が開く）。
  let chainRoot;
  try {
    chainRoot = withVendorLogging(() => gm.buildMerkleTree(N, claimEntriesFromClaimData(decoded))).root;
  } catch (e) {
    report.check('check.stageC.onchainClaimData', 'fail', { error: `rebuild: ${e.message}` });
    S.anomalies.push(`on-chain claim data rebuild failed: ${e.message}`);
    return;
  }

  const ok = lower(chainRoot) === lower(onchainRoot);
  report.check('check.stageC.onchainClaimData', ok ? 'pass' : 'fail', {
    chainRebuilt: chainRoot, onchain: onchainRoot,
    chunks: fetched.chunks.length, routes: (fetched.routes || []).join(','),
    deposits: decoded.depositIds.length,   // 全プレイヤーの適格 depositId の和集合（派生値）
  });
  if (!ok) addProofProviderAnomaly(ctx, S);
}

// ============================================================
// Step 9: タイムライン照合（vendored timeline-check ＋ MerkleRootSubmitted 履歴）
// ============================================================
// E6-09: 未登録・late・RPC失敗の振る舞いを、本文文字列ではなく実行可能な単位に分離する。
// ── 名簿の正準バイト列の再構成（V25-03: 公開キャッシュが失われた場合の照合相手） ──
//
// 🔴 なぜ要るか: `roster/manifest.json` は各 group ファイルの sha256 を持ち、**チャット開始前に**
//    チェーンへアンカーされる。ところが公開キャッシュ（`roster/index.json` /
//    `roster/group{G}.json`）が失われると、旧実装は「実バイトが読めない」というだけの理由で
//    `rosterLiveAnchor` を必ず FAIL にしていた。一方 `rosterKeys` は不在キャッシュを
//    `if (!data) continue;`（:2683 付近）で読み飛ばす。
//    ⇒ **キャッシュを消すと、名簿のバイト検査が1つも残らない**。
//    そこで不在時は、アンカー済み sha256 を「運営が後から動かせないデータ
//    （applicantHash で固定された応募データ ＋ committed grouping）から再構成した正準バイト列」の
//    sha256 と突き合わせる。**検査を緩めるのではなく、無検査だった穴を塞ぐ強化である。**
//
// ⚠️ これは writer の**手書き忠実ミラー**である（VENDOR_SYNC.md の MIRROR 台帳に登録済み）。
//    writer 側を変えたらここも変えること。変え忘れれば FAIL に倒れる（無言の乖離にならない）。
export function rosterDepositIdsOf(depIdsRaw) {
  try {
    const d = typeof depIdsRaw === 'string' ? JSON.parse(depIdsRaw) : depIdsRaw;
    return Array.isArray(d?.ids) ? d.ids : [];
  } catch { return []; }
}

// `workers/game_workers/chat-game-DO.js` publishRosterFile の rosterMembers 写像のミラー。
export function rosterMembersOf(group) {
  return (group?.members ?? []).map((m) => canonicalRosterMember({
    ...m.data, globalIndex: m.globalIndex,
  }));
}

// MIRROR: GM publishAutoRosterFile の selection → group0 写像。
// 正準化そのものは vendored roster-canonical.js に委譲する。
export function autoRosterTextFromSelection(blockNum, players) {
  const members = players.map(p => ({ ...p.data, globalIndex: p.globalIndex }));
  if (members.some((member, index) => index > 0 && member.globalIndex <= members[index - 1].globalIndex)) {
    throw new Error('[auto-distribute] selected entries are not in winner index order');
  }
  return canonicalRosterText(blockNum, 0, members);
}

// 同 publishRosterFile の rosterText（`safeJsonStringify` は正常系では `JSON.stringify`）。
export function reconstructedRosterGroupSha256(blockNum, group) {
  return sha256HexOfString(canonicalRosterText(blockNum, group.groupId,
    group.members.map((m) => ({ ...m.data, globalIndex: m.globalIndex }))));
}

// `workers/game_workers/game-master-DO.js` buildRosterIndex ＋ `JSON.stringify(rosterIndex)` のミラー。
// JSON.stringify は配列添字キー（2^32-2 以下）だけを数値順にする。
// それを超える uid は挿入順なので writer の呼び手と同じ groupId 昇順で挿入する。
export function reconstructedRosterIndexSha256(groups) {
  const idx = Object.create(null);
  for (const g of [...groups].sort((a, b) => Number(a.groupId) - Number(b.groupId))) {
    for (const m of (g?.members ?? [])) idx[m.data?.uid] = Number(g.groupId);
  }
  return sha256HexOfString(JSON.stringify(idx));
}

// MIRROR: GM rebuildAndPublishRosterManifest の index 用 groupId sort と indexText
// MIRROR: GM rebuildAndPublishRosterManifest の groups.sort と manifestText
// GM rebuildAndPublishRosterManifest と ChatGameDO.publishRosterFile の直列化順を写す。
export function reconstructCanonicalRosterPayloads(blockNum, groups) {
  const index = Object.create(null);
  const ordered = [...groups].sort((a, b) => Number(a.groupId) - Number(b.groupId));
  for (const group of ordered) {
    for (const member of (group?.members ?? [])) index[member.data?.uid] = Number(group.groupId);
  }
  const indexText = JSON.stringify(index);
  const groupTexts = new Map();
  const manifestGroups = [];
  for (const group of groups) {
    const groupId = Number(group.groupId);
    const text = JSON.stringify({
      blockNum: Number(blockNum), groupId, members: rosterMembersOf(group),
    });
    groupTexts.set(groupId, text);
    manifestGroups.push({ groupId, sha256: sha256HexOfString(text) });
  }
  manifestGroups.sort((a, b) => a.groupId - b.groupId);
  const manifestText = JSON.stringify({
    blockNum: Number(blockNum), indexSha256: sha256HexOfString(indexText), groups: manifestGroups,
  });
  return { manifestText, indexText, groupTexts };
}

// Compare two independently obtained rosters with the exact canonical HashStorage row.
// The published group texts are read from their files; the other side is rebuilt from
// the selection and grouping that Stage B already verified.
export function inspectRosterCommitment({ blockNum, manifestText, groupTexts, groupsDerived, chainHash }) {
  const failures = [];
  const expected = reconstructCanonicalRosterPayloads(blockNum, groupsDerived);
  let published = null;
  let rebuilt = null;
  try {
    rebuilt = buildRosterMemberCommitment({ blockNum,
      manifestText: expected.manifestText, groupTexts: expected.groupTexts });
    if (typeof manifestText === 'string') {
      published = buildRosterMemberCommitment({ blockNum, manifestText, groupTexts });
    } else if (groupsDerived.length > 0) failures.push('published roster manifest missing');
  } catch (error) { failures.push(`roster C reconstruction: ${error.message}`); }
  const zero = ZERO_ROOT;
  const canonical = chainHash ?? zero;
  const value = rebuilt?.C ?? zero;
  if (lower(value) !== lower(canonical)) failures.push('reconstructed roster C differs from canonical HashStorage row');
  if (groupsDerived.length > 0) {
    if (manifestText !== expected.manifestText) failures.push('published roster manifest differs from committed grouping');
    if (!published || lower(published.C) !== lower(canonical)) {
      failures.push('published roster C differs from canonical HashStorage row');
    }
    for (const [gid, text] of expected.groupTexts) {
      if (groupTexts?.get(gid) !== text) failures.push(`published group${gid} differs from committed grouping`);
    }
  } else {
    if (canonical !== zero) failures.push('empty roster has a nonzero canonical C');
    if (manifestText !== null) failures.push('empty roster has an unexpected published manifest');
  }
  return { status: failures.length ? 'fail' : 'pass', failures,
    canonical, rebuiltC: value, publishedC: published?.C ?? null,
    members: rebuilt?.members.length ?? 0 };
}

export async function inspectRosterAnchor(chain, { blockNum, raw, groupTexts, chattingStartMs, entryEndMs },
  fallbackToCurrentOnHistoryError = false, resolvedRegistration = undefined) {
  const failures = [];
  const warnings = [];
  let anchored = null;
  let updatedTimestampMs = null;
  let registration = null;
  try {
    let historyGetterFailed = false;
    const historyChain = fallbackToCurrentOnHistoryError ? Object.create(chain) : chain;
    if (fallbackToCurrentOnHistoryError) {
      for (const name of ['otherRegistrationCount', 'otherRegistrationAt']) {
        if (typeof chain[name] === 'function') {
          historyChain[name] = async (...args) => {
            try { return await chain[name](...args); } catch (error) {
              historyGetterFailed = true;
              throw error;
            }
          };
        }
      }
    }
    try {
      if (resolvedRegistration !== undefined) {
        if (resolvedRegistration.error) throw resolvedRegistration.error;
        registration = resolvedRegistration.registration;
      } else {
        registration = await resolveRosterRegistration(historyChain, blockNum,
          { chattingStartMs, entryEndMs });
      }
    } catch (error) {
      if (!fallbackToCurrentOnHistoryError || !historyGetterFailed) throw error;
      // 通常検証だけ、履歴 getter が読めない場合は起点の現在値照合を行う。
      const key = rosterAnchorKey(blockNum);
      const marker = typeof chain.getOtherHash === 'function'
        ? await chain.getOtherHash(key) : null;
      let block = null;
      if (marker?.updated) {
        try { block = await chain.getBlock(marker.updated); } catch { /* 時刻は後段で報告 */ }
      }
      const at = block == null ? null : Number(block.timestamp);
      const entryEndSec = Math.round(entryEndMs / 1000);
      const chattingStartSec = Math.round(chattingStartMs / 1000);
      const row = marker ? { hash: marker.hash, registeredBlock: marker.updated,
        registeredAt: at } : null;
      const first = row && at >= entryEndSec ? { ...row, index: 0 } : null;
      registration = { key, legacy: true, status: marker ? 'legacy' : 'none',
        index: marker ? 0 : null, row, first, firstMatching: first,
        lateCount: at != null && at >= chattingStartSec ? 1 : 0,
        preEntryCount: 0, historyUnreadable: String(error?.message || error) };
    }
    anchored = registration.row && {
      hash: registration.row.hash, updated: registration.row.registeredBlock,
    };
    // Stage C always supplies exact group texts. Historical time-selection unit
    // probes call this helper without them and exercise only the row/window rule.
    const computed = groupTexts === undefined ? keccak256(stringToHex(raw))
      : buildRosterMemberCommitment({ blockNum, manifestText: raw, groupTexts }).C;
    if (!registration.row || (registration.legacy && !anchored.updated)
        || (!registration.legacy && registration.status === 'none')) {
      failures.push('on-chain roster hash is unregistered');
    } else if (lower(anchored.hash) !== lower(computed)) {
      failures.push('published roster C does not match the on-chain hash');
    } else {
      try {
        updatedTimestampMs = registration.legacy
          ? Number((await chain.getBlock(anchored.updated)).timestamp) * 1000
          : registration.row.registeredAt * 1000;
        if (!(updatedTimestampMs < chattingStartMs)
            || (registration.legacy && !(updatedTimestampMs >= entryEndMs))) {
          failures.push('on-chain roster hash was registered at or after chattingStart');
        }
      } catch (error) {
        warnings.push(`anchor registration time could not be read: ${error?.message || error}`);
      }
    }
  } catch (error) {
    warnings.push(`on-chain roster anchor could not be read: ${error?.message || error}`);
  }
  return { failures, warnings, anchored, updatedTimestampMs, registration };
}

export function rosterReregistrationCheck(registration) {
  if (!registration || registration.historyUnreadable || registration.legacy) {
    return { status: 'skip', params: {
      reason: registration?.historyUnreadable || !registration
        ? 'roster_history_unreadable' : 'legacy_hash_storage_has_no_history',
      error: registration?.historyUnreadable ?? null,
      count: null, firstIndex: null, firstRegisteredAt: null, firstHash: null,
      canonicalIndex: null, canonicalRegisteredAt: null, canonicalHash: null,
    } };
  }
  const first = registration?.first;
  const selected = registration?.row;
  const reregistered = Boolean(!registration?.legacy && first && selected
    && lower(first.hash) !== lower(selected.hash));
  return { status: reregistered ? 'warn' : 'pass', params: {
    count: registration && !registration.legacy && selected
      ? registration.index - registration.preEntryCount + 1 : 0,
    firstIndex: first?.index ?? null,
    firstRegisteredAt: first?.registeredAt ?? null,
    firstHash: first?.hash ?? null,
    canonicalIndex: registration?.index ?? null,
    canonicalRegisteredAt: selected?.registeredAt ?? null,
    canonicalHash: selected?.hash ?? null,
  } };
}

export async function verifyTimeline(ctx, S, timing) {
  const { report, ui, blockNum: N } = ctx;

  // 9a. 宣言窓とチェーン窓の3点照合【副検査】（timeline-check.js。両辺チェーン由来＝ドリフト検出）
  let declared = null;
  let graceSec = null;
  if (S.chatWindow && S.resultWindow) {
    const entryEndSec = Math.round((timing.startTimeEntryMs + (N + 1) * timing.blockTimeMs) / 1000);
    graceSec = S.chatWindow.chatCloseAt
      - (entryEndSec + Math.round(timing.gamePeriodMs / 1000));
    declared = computeDeclaredTimesMs({
      startTimeMs: timing.startTimeEntryMs, blockTimeMs: timing.blockTimeMs,
      gamePeriodMs: timing.gamePeriodMs, submitPeriodMs: timing.submitPeriodMs,
      confirmations: ctx.cfg.pins.confirmationBlocks,
    }, N, graceSec);
    const mism = declared ? compareDeclaredToChainWindows(declared, {
      chatOpenAt: S.chatWindow.chatOpenAt,
      chatCloseAt: S.chatWindow.chatCloseAt,
      resultCloseAt: S.resultWindow.closeAt,
    }) : ['declared timeline unavailable'];
    report.check('check.stageC.timelineWindows', mism.length === 0 ? 'pass' : 'fail',
      { mismatches: mism.join('; ') || '-', graceSec });
  } else {
    report.check('check.stageC.timelineWindows', 'skip', { reason: 'no_evidence_windows' });
  }


  // F-1: ライブ中に使われた名簿manifestがHashStorage.otherHashesへ固定され、
  // 全group/indexの公開バイトと一致し、登録ブロックがチャット開始より前かを検査する。
  // S.groupIds の :2476 における代入条件と同じ no-game 集合に対応させる。
  if (S.groupIds.length === 0 || S.auto || S.noGame || S.files.summary?.data?.noGame === true || S.timelineNoGame) {
    report.check('check.stageC.rosterLiveAnchor', 'skip', { reason: 'no_chat_game_groups' });
    try {
      const registration = await resolveRosterRegistration(ctx.chain, N);
      const inspected = inspectRosterCommitment({ blockNum: N,
        manifestText: S.files?.rosterManifest?.raw ?? null,
        groupTexts: new Map(), groupsDerived: [], chainHash: registration.row?.hash });
      report.check('check.stageC.rosterCommitment', inspected.status, inspected);
    } catch (error) {
      report.check('check.stageC.rosterCommitment', 'fail', { error: error.message });
    }
  } else {
    let live = S.files?.rosterManifest;
    const failures = [];
    const warnings = [];
    let anchored = null;
    let updatedTimestampMs = null;
    let anchorInspection = null;
    let resolvedRosterRegistration;
    if (ctx.data.emergencySource && declared) {
      const entryEndMs = Math.round((timing.startTimeEntryMs + (N + 1) * timing.blockTimeMs) / 1000) * 1000;
      try {
        resolvedRosterRegistration = { registration: await resolveRosterRegistration(ctx.chain, N, {
          chattingStartMs: declared.chattingStart, entryEndMs,
        }) };
      } catch (error) { resolvedRosterRegistration = { error }; }
      const registration = resolvedRosterRegistration.registration;
      const derived = Array.isArray(ctx.data.groupsDerived) ? ctx.data.groupsDerived : [];
      if (derived.length > 0) {
        const payloads = reconstructCanonicalRosterPayloads(N, derived);
        const rebuiltHash = buildRosterMemberCommitment({ blockNum: N,
          manifestText: payloads.manifestText, groupTexts: payloads.groupTexts }).C;
        const liveHash = live?.raw === payloads.manifestText ? rebuiltHash : null;
        const canonicalHash = registration?.row?.hash ?? null;
        if ((!live?.raw || !live?.data || !liveHash ||
            String(liveHash).toLowerCase() !== String(canonicalHash).toLowerCase())
            && canonicalHash && String(rebuiltHash).toLowerCase() === String(canonicalHash).toLowerCase()
            && Buffer.byteLength(payloads.manifestText) <= r2LimitForKey(`games/block${N}/roster/manifest.json`)) {
          recordEmergencyDifference(ctx, {
            checkId: 'emergency.rosterManifestReconstructed',
            what: 'the saved roster manifest is absent or differs from the canonical registration',
            chain: { hash: canonicalHash, savedSha256: live?.raw ? sha256HexOfString(live.raw) : null },
            rebuilt: { rosterC: rebuiltHash },
            reason: 'reconstructed GM bytes match the canonical pre-chat roster registration',
          });
          live = { raw: payloads.manifestText, data: JSON.parse(payloads.manifestText) };
          ctx.data.emergencyRosterPayloads = { ...payloads, origin: 'reconstructed' };
        } else if (live?.raw && live?.data && liveHash
            && String(liveHash).toLowerCase() === String(canonicalHash).toLowerCase()) {
          ctx.data.emergencyRosterPayloads = { ...payloads, manifestText: live.raw, origin: 'saved' };
        } else if (canonicalHash && String(rebuiltHash).toLowerCase() !== String(canonicalHash).toLowerCase()) {
          failures.push('reconstructed roster manifest does not match the canonical on-chain hash');
        }
      }
    }
    if (!live?.raw || !live?.data) failures.push('roster manifest missing');
    if (!declared) failures.push('declared chattingStart unavailable');
    if (!canInspectRosterManifest(live, declared)) {
      report.check('check.stageC.rosterCommitment', 'fail', { error: 'roster manifest or chain window unavailable' });
    }
    if (canInspectRosterManifest(live, declared)) {
      if (JSON.stringify(live.data) !== live.raw) failures.push('manifest is not minified canonical JSON');
      if (Number(live.data.blockNum) !== Number(N)) failures.push('blockNum mismatch');
      const groups = Array.isArray(live.data.groups) ? live.data.groups : [];
      const expectedIds = [...S.groupIds].sort((a, b) => a - b);
      if (JSON.stringify(groups.map((entry) => Number(entry?.groupId))) !== JSON.stringify(expectedIds)) {
        failures.push('groupId list/order mismatch');
      }
      // 公開キャッシュが読めるならそれを、読めないなら再構成した正準バイト列を照合相手にする。
      // どちらの場合も「アンカー済み sha256 と一致するか」しか見ないので、検査は緩まない。
      const derived = Array.isArray(ctx.data.groupsDerived) ? ctx.data.groupsDerived : [];
      const sameHash = (a, b) => !!a && !!b && String(a).toLowerCase() === String(b).toLowerCase();
      const groupTexts = new Map();
      for (const group of groups) {
        const gid = Number(group?.groupId);
        const file = S.files.rosters.get(gid)?.path;
        if (file) {
          try { groupTexts.set(gid, new TextDecoder('utf-8', { fatal: true }).decode(await fs.readFile(file))); }
          catch { /* The commitment check below records a missing published group. */ }
        } else if (ctx.data.emergencySource) {
          const rebuilt = reconstructCanonicalRosterPayloads(N, derived).groupTexts.get(gid);
          if (rebuilt) groupTexts.set(gid, rebuilt);
        }
      }
      S.rosterManifestText = live.raw;
      S.rosterGroupTexts = groupTexts;
      const indexPath = S.files.rosterIndex?.path;
      if (indexPath) {
        try { S.rosterIndexText = new TextDecoder('utf-8', { fatal: true }).decode(await fs.readFile(indexPath)); }
        catch { S.rosterIndexText = null; }
      } else if (ctx.data.emergencySource) {
        S.rosterIndexText = reconstructCanonicalRosterPayloads(N, derived).indexText;
      }

      const indexHash = S.precheckedHashes.get(`games/block${N}/roster/index.json`)?.actualHash ?? null;
      if (indexHash) {
        if (!sameHash(live.data.indexSha256, indexHash)) failures.push('roster index sha256 mismatch');
      } else if (derived.length === 0) {
        failures.push('roster index sha256 mismatch');
      } else if (!sameHash(live.data.indexSha256, reconstructedRosterIndexSha256(derived))) {
        failures.push('anchored roster index sha256 does not match the roster reconstructed from committed data');
      } else {
        warnings.push('roster index cache is unavailable; the anchored sha256 matched the reconstructed roster');
      }

      for (const entry of groups) {
        const gid = Number(entry?.groupId);
        const actual = S.precheckedHashes.get(`games/block${N}/roster/group${gid}.json`)?.actualHash ?? null;
        if (actual) {
          if (!sameHash(entry?.sha256, actual)) failures.push(`group${gid} sha256 mismatch`);
          continue;
        }
        const g = derived.find((x) => Number(x.groupId) === gid) ?? null;
        if (!g) {
          failures.push(`group${gid} sha256 mismatch`);
        } else if (!sameHash(entry?.sha256, reconstructedRosterGroupSha256(N, g))) {
          failures.push(`anchored group${gid} sha256 does not match the roster reconstructed from committed data`);
        } else {
          warnings.push(`group${gid} roster cache is unavailable; the anchored sha256 matched the reconstructed roster`);
        }
      }
      anchorInspection = await inspectRosterAnchor(ctx.chain, {
        blockNum: N,
        raw: live.raw,
        groupTexts,
        chattingStartMs: declared.chattingStart,
        entryEndMs: Math.round((timing.startTimeEntryMs + (N + 1) * timing.blockTimeMs) / 1000) * 1000,
      }, !ctx.data.emergencySource, resolvedRosterRegistration);
      const inspected = inspectRosterCommitment({ blockNum: N, manifestText: live.raw,
        groupTexts, groupsDerived: derived, chainHash: anchorInspection.registration?.row?.hash });
      report.check('check.stageC.rosterCommitment', inspected.status, inspected);
      if (inspected.status === 'fail') failures.push(...inspected.failures);
      const registration = anchorInspection.registration;
      const reregistration = rosterReregistrationCheck(registration);
      report.check('check.stageC.rosterReregistration',
        reregistration.status, reregistration.status === 'skip'
          ? { ...reregistration.params,
            reasonText: ui.t(reregistration.params.reason === 'legacy_hash_storage_has_no_history'
              ? 'stageC.rosterReregistrationLegacyUnavailable'
              : 'stageC.rosterReregistrationHistoryUnreadable') }
          : reregistration.params);
      const rosterAnchor = classifyRosterAnchorForMode(
        anchorInspection.failures,
        anchorInspection.warnings,
        Boolean(ctx.data.emergencySource),
      );
      failures.push(...rosterAnchor.failures);
      warnings.push(...rosterAnchor.warnings);
      if (!registration?.legacy && (registration?.lateCount ?? 0) > 0) {
        warnings.push(ui.t('stageC.rosterLateRegistrations', { count: registration.lateCount }));
      }
      for (const accepted of rosterAnchor.accepted) {
        recordEmergencyDifference(ctx, {
          checkId: 'check.stageC.rosterLiveAnchor',
          what: accepted,
          chain: {
            hash: anchorInspection.anchored?.hash ?? null,
            updatedBlock: anchorInspection.anchored?.updated ?? null,
            updatedTimestampMs: anchorInspection.updatedTimestampMs,
          },
          rebuilt: {
            rosterC: inspected.rebuiltC,
            chattingStartMs: declared.chattingStart,
          },
          reason: accepted === 'on-chain roster hash is unregistered'
            ? 'no canonical pre-chat roster registration exists; ordinary third-party verification remains failed'
            : 'the published roster differs from the canonical pre-chat registration; '
              + 'ordinary third-party verification remains failed',
        });
      }
      anchored = anchorInspection.anchored;
      updatedTimestampMs = anchorInspection.updatedTimestampMs;
    }
    for (const warning of warnings) S.anomalies.push(`live roster anchor warning: ${warning}`);
    const status = failures.length > 0 ? 'fail' : (warnings.length > 0 ? 'warn' : 'pass');
    report.check('check.stageC.rosterLiveAnchor', status, {
      failures: failures.join('; ') || '-',
      warnings: warnings.join('; ') || '-',
      updatedBlock: anchored?.updated ?? null,
      updatedTimestampMs,
      chattingStart: declared?.chattingStart ?? null,
      canonicalIndex: anchorInspection?.registration?.index ?? null,
      lateRegistrations: anchorInspection?.registration?.lateCount ?? null,
      legacy: anchorInspection?.registration?.legacy ?? false,
      historyUnreadable: anchorInspection?.registration?.historyUnreadable ?? null,
      preEntryCount: anchorInspection?.registration?.legacy
        ? (anchorInspection.registration.row?.registeredAt != null
          && anchorInspection.registration.row.registeredAt * 1000 < Math.round(
            (timing.startTimeEntryMs + (N + 1) * timing.blockTimeMs) / 1000) * 1000 ? 1 : 0)
        : anchorInspection?.registration?.preEntryCount ?? null,
      registrationPhase: anchorInspection?.registration?.legacy
        ? (anchorInspection.registration.row?.registeredAt != null
          && anchorInspection.registration.row.registeredAt * 1000 < Math.round(
            (timing.startTimeEntryMs + (N + 1) * timing.blockTimeMs) / 1000) * 1000
          ? 'before_entry_end'
          : anchorInspection.registration.row?.registeredAt != null
            && anchorInspection.registration.row.registeredAt * 1000 >= declared?.chattingStart
            ? 'at_or_after_chattingStart' : null)
        : null,
    });
    ctx.r2.release?.(`games/block${N}/roster/manifest.json`);
  }

  // ── 9a-2. 🔴 F-7(a)（2026-08-08・ラウンド20 判断不要-7）: `summary.timeline` の照合 ──
  //
  // `game-master-DO.js:8031-8034` は公表 summary から **majorLangs と timeline の2つ**を継承する。
  // `majorLangs` は `check.stageC.majorLangsMatch` が Stage B 導出値と突き合わせているが、
  // **`timeline` は誰も読んでいなかった**（`timelineWindows` はチェーン窓どうしの照合で、
  // summary.timeline を1回も参照しない）。
  // 実測: `graceSec 60→999999` / `chattingStart +14.32日` に改変しても
  //   **exit 0 / `##RESULT full` / FAIL 0**、しかも **`summaryByteExact = pass`**
  //   （再構築 summary が嘘の timeline ごとバイト同一になる）。
  //   対照の `majorLangs [] → ['zz']` は exit 2 で FAIL。
  //
  // ⚠️ 式の罠2つ（当初案のまま実装すると grace>0 の全ブロックが偽 FAIL になる）:
  //   1. `chattingStart = chatOpenAt*1000` は**誤り**。`chatOpenAt ↔ entryEndMs`（grace 非依存）で、
  //      正しくは `chattingStart = entryEndMs + graceMs`。本番 grace 2h なら毎ブロック 7,200,000ms ずれる。
  //      → **上で作った `declared` をそのまま使う**（自己参照にならない: `graceSec` はチェーン由来）。
  //   2. `timeline` は4フィールドではなく**5フィールド**。
  //      `completedAt = closeAt + confirmations*12000 + 30000` が抜けていた。
  //
  // ⚠️ `neutralizeSummary`（:812-）は timeline を触らない**ままでよい**。
  //    ここが唯一の照合点なので、byte 比較側で無効化してはいけない。
  {
    const published = S.files?.summary?.data?.timeline;
    const noGameKind = Boolean(S.auto || S.noGame || S.timelineNoGame);
    if (published === undefined) {
      // auto / 0名 / timeline no-game の正典 writer は timeline を持たない。
      // 判定は公開 summary の自己申告ではなく、Stage B までに確定した分岐を使う。
      // これによりゲーム有り summary が noGame:true を偽装しても緊急ゲートを迂回できない。
      const gameWasPlayed = !S.auto && !S.noGame && !S.timelineNoGame;
      if (ctx.data.emergencySource && gameWasPlayed) {
        report.check('check.stageC.timelineMatch', 'fail', {
          reason: 'not_published_emergency',
          instruction: MANIFEST_CORE_RETRY_INSTRUCTION,
        });
        S.anomalies.push(ui.t('stageC.anomaly.timelineMismatch', { block: N }));
      } else {
        // timeline が無い旧ブロック（deferred-init 導入前）は通常検証の対象外
        report.check('check.stageC.timelineMatch', 'skip', {
          reason: ctx.data.emergencySource ? 'not_published_no_game' : 'not_published',
        });
      }
    } else if (published === null) {
      if (ctx.data.emergencySource && noGameKind) {
        report.check('check.stageC.timelineMatch', 'skip', {
          reason: 'published_null_no_game_emergency',
        });
        recordEmergencyDifference(ctx, {
          checkId: 'check.stageC.timelineMatch',
          what: 'published no-game timeline is null',
          chain: { published: null },
          rebuilt: { expected: declared ? {
            graceSec,
            chattingStart: declared.chattingStart,
            submittingStart: declared.submittingStart,
            closeAt: declared.closeAt,
            completedAt: declared.completedAt,
          } : null },
          reason: 'the canonical no-game writer omits timeline; the public null is retained as an emergency difference',
        });
      } else {
        report.check('check.stageC.timelineMatch', 'fail', { reason: 'published_null' });
        S.anomalies.push(ui.t('stageC.anomaly.timelineMismatch', { block: N }));
      }
    } else if (!declared) {
      report.check('check.stageC.timelineMatch', 'skip', { reason: 'declared_unavailable' });
    } else {
      // ↔ 正典 `GameMasterDO.buildSummaryTimeline(declared, graceSec)`
      const expected = {
        graceSec,
        chattingStart: declared.chattingStart,
        submittingStart: declared.submittingStart,
        closeAt: declared.closeAt,
        completedAt: declared.completedAt,
      };
      const okTl = canonicalEqual(published, expected);
      const emergencyTimelineNoGameDifference = Boolean(ctx.data.emergencySource)
        && noGameKind && !okTl;
      report.check(
        'check.stageC.timelineMatch',
        emergencyTimelineNoGameDifference ? 'skip' : (okTl ? 'pass' : 'fail'),
        {
          published: JSON.stringify(published),
          expected: JSON.stringify(expected),
          ...(emergencyTimelineNoGameDifference ? { reason: 'timeline_no_game_emergency_difference' } : {}),
        },
      );
      if (emergencyTimelineNoGameDifference) {
        recordEmergencyDifference(ctx, {
          checkId: 'check.stageC.timelineMatch',
          what: 'published no-game timeline differs from the independently derived timeline',
          chain: { published },
          rebuilt: { expected },
          reason: 'the no-game summary is regenerated without a timeline field; the public mismatch is retained as an emergency difference',
        });
      } else if (!okTl) {
        S.anomalies.push(ui.t('stageC.anomaly.timelineMismatch', { block: N }));
      }
    }
  }

  // 9b. MerkleRootSubmitted + MerkleRootInvalidated + VerificationExtended履歴。現在値はgetter、
  // 歴史はEthereum event順のreplayをそれぞれ権威とし、不一致はFAILにする。
  const unlockSec = Math.round((timing.startTimeEntryMs + (N + 1) * timing.blockTimeMs) / 1000);
  const latest = await ctx.chain.latest();
  let fromBlock = null;
  let historyError = null;
  let rangeError = null;
  try {
    fromBlock = toBlockBigInt(await ctx.chain.findBlockByTimestamp(unlockSec));
    fromBlock = fromBlock > 2000n ? fromBlock - 2000n : 0n;
  } catch (error) {
    if (!(error instanceof ArchiveUnavailableError)) throw error;
    rangeError = error;
  }
  if (typeof ctx.chain.findContractDeploymentBlock === 'function') {
    // extendVerificationはrootやunlock前にも可能。unlock起点の窓では履歴を取りこぼすため、
    // contract生成blockまで二分探索して全eventを読む。
    try {
      fromBlock = toBlockBigInt(await ctx.chain.findContractDeploymentBlock(ctx.cfg.contracts.tokenMining));
      rangeError = null;
    } catch (error) {
      if (!(error instanceof ArchiveUnavailableError)) throw error;
      // root/proofはunlock後の窓で読める。全履歴の前提だけを未検証にする。
      historyError = error;
    }
  }
  const toBlock = toBlockBigInt(latest.number);
  const readHistory = async (reader) => {
    try {
      if (rangeError) throw rangeError;
      return await reader();
    } catch (error) {
      if (!(error instanceof ArchiveUnavailableError)) throw error;
      historyError = error;
      return null;
    }
  };
  const rootRows = await readHistory(() => ctx.chain.merkleRootEvents(N, { fromBlock, toBlock }));
  const events = (rootRows || []).map(normalizeRootEvent);
  events.sort((a, b) => (a.evtBlock ?? -1) - (b.evtBlock ?? -1)
    || (a.transactionIndex ?? -1) - (b.transactionIndex ?? -1)
    || (a.logIndex ?? -1) - (b.logIndex ?? -1));
  const extensionEvents = typeof ctx.chain.verificationExtendedEvents === 'function'
    ? ((await readHistory(() => ctx.chain.verificationExtendedEvents(N, { fromBlock, toBlock }))) || []).map(normalizeExtensionEvent)
    : [];
  const invalidationEvents = typeof ctx.chain.merkleRootInvalidatedEvents === 'function'
    ? ((await readHistory(() => ctx.chain.merkleRootInvalidatedEvents(N, { fromBlock, toBlock }))) || []).map(normalizeInvalidationEvent)
    : [];

  const extensionTimeError = extensionEvents.find((event) => event.timestampError)?.timestampError;
  if (extensionTimeError) historyError = extensionTimeError;
  const verificationPeriodSec = Number(await ctx.chain.verificationPeriod());
  const claimPeriodSec = Number(await ctx.chain.claimPeriod());
  const resultWindow = S.resultWindow || await ctx.chain.resultWindow(N);
  const verificationCap = Number(resultWindow.closeAt) + MAX_VERIFICATION_EXTENSION_SEC;

  let lifecycle = null;
  let lifecycleError = null;
  try { lifecycle = await ctx.chain.getBlockLifecycle(N); }
  catch (error) { lifecycleError = error.message; }

  let replay = null;
  let replayError = null;
  try {
    replay = replayAdminCommitLifecycle({
      rootEvents: events,
      extensionEvents: extensionEvents.filter((event) => !event.timestampError),
      invalidationEvents,
      verificationPeriodSec,
      verificationCap,
    });
  } catch (error) {
    replayError = error.message;
  }

  const notes = [];
  // ヘッダが読めなくても、ログに在る延長値とcap/観測済みfloorは比較できる。
  let observedFloor = 0;
  for (const event of [...extensionEvents].sort(compareEventPosition)) {
    if (event.timestampError && event.newEndFloor > verificationCap) notes.push('extension exceeded verification cap');
    if (event.timestampError && event.newEndFloor <= observedFloor) notes.push('extension did not increase effective end');
    observedFloor = Math.max(observedFloor, event.newEndFloor);
  }
  if (rootRows && events.length === 0) notes.push('no MerkleRootSubmitted events found');
  if (lifecycleError) notes.push(`getBlockLifecycle unavailable: ${lifecycleError}`);
  if (replayError) notes.push(`event replay unavailable: ${replayError}`);
  // 最初の観測済み延長より前だけ、見えていない初期floorが期限違反を説明しうる。
  // 観測済みの延長があればfloorは既知。非増加・cap超過などは初期floorに依存しない。
  const unknownFloorFailures = new Set();
  let floorObserved = false;
  for (const [index, event] of (replay?.history || []).entries()) {
    const before = replay.history[index - 1];
    if (!floorObserved && before?.root) {
      unknownFloorFailures.add(`extension re-opened a closed verification window at ${event.timestamp} (>= ${before.verificationEndsAt})`);
      unknownFloorFailures.add(`root resubmission at/after effective end (${event.timestamp} >= ${before.verificationEndsAt})`);
    }
    if (event.kind === 'extension') floorObserved = true;
  }
  if (replay && !replay.ok) notes.push(...replay.errors.filter((note) =>
    !historyError || !unknownFloorFailures.has(note)));
  // 古い延長floorを取りこぼす場合も、今のfloorより遅い再提出/再開なら違反と断定できる。
  if (historyError && lifecycle && replay) {
    const floor = Number(lifecycle.verificationEndsAt || 0);
    for (const [index, event] of replay.history.entries()) {
      const before = replay.history[index - 1];
      if (floor > 0 && before?.root && ['root', 'extension'].includes(event.kind)
          && event.timestamp >= Math.max(before.verificationEndsAt, floor)) {
        notes.push(`event at/after effective end (${event.timestamp})`);
      }
    }
  }
  // 🔴 R29-01 のミラー（2026-08-16）: **非常口が閉まる前に root は打てない。**
  //    契約側 `TokenMining._submitMerkleRoot` は
  //    `if (block.timestamp < closeAt) revert EvidenceWindowOpen();` を強制する
  //    （closeAt = Evidence.resultWindow(N).closeAt ＝ オンチェーン提出窓の終端）。
  //    この規則が守る対象は「運営に検閲されたユーザーが自力で提出する窓」そのもので、
  //    外れると root を早期確定 → 検証期間も請求期間も前倒し → 1件でも請求が入ると
  //    `blockClaimCount != 0` で root が恒久確定し、後から届いた Evidence 提出を
  //    反映する経路が消える。本番の死角は grace + GAME + SUBMIT ＝ 50時間
  //    （`extendGrace` 上限時は 6日）。
  //    ↔ `block-lifecycle.js` の R26-C1 ミラーと同じ理由でここに置く: block-verifier は
  //    TokenMining を**アドレスでしか束縛していない**（`index.js` は getCode が空でないことしか
  //    見ない）ので、ガードを外した契約を配備された場合にそれを機械検出できる層はここしかない。
  //    正直なチェーンでは発火しない: root 提出は closeAt 以降を要求し、`extendGrace` は
  //    chatCloseAt 前しか通らないので、提出後に closeAt が動くことはない（Round 29 実機 S5）。
  const evidenceCloseAt = Number(resultWindow.closeAt);
  for (const event of events) {
    if (event.timestamp < unlockSec) notes.push(`submission before time-unlock (${isoOf(event.timestamp)})`);
    if (event.timestamp < evidenceCloseAt) {
      notes.push(`root submitted before the evidence window closed (${isoOf(event.timestamp)} < ${isoOf(evidenceCloseAt)})`);
    }
  }
  if (rootRows && replay && lower(replay.root) !== lower(S.blockState.root)) notes.push('replayed root != blockStates root');
  if (rootRows && replay && replay.verificationStartedAt !== Number(S.blockState.verificationStartedAt)) {
    notes.push('replayed verificationStartedAt != blockStates verificationStartedAt');
  }
  const currentMatch = replay && lifecycle
    ? lifecycleReplayMatchesCurrent(replay, lifecycle, claimPeriodSec)
    : { ok: false, mismatches: ['current/replay unavailable'] };
  // 不明なのは古い延長floorを含む期限の完全再現だけ。現在値どうしの
  // 制約と、取得できたrootログとの照合は履歴不足でも検査する。
  const currentMismatches = historyError
    ? currentMatch.mismatches.filter((name) => !['verificationEndsAt', 'claimEndsAt'].includes(name)
      && (rootRows || !['root', 'verificationStartedAt'].includes(name)))
    : currentMatch.mismatches;
  if (historyError && lifecycle) {
    const current = normalizeBlockLifecycle(lifecycle);
    if (current.mode !== BLOCK_MODE_ADMIN_COMMIT && !currentMismatches.some((name) => name.includes('AdminCommit'))) {
      currentMismatches.push(`mode=${current.mode} is not AdminCommit`);
    }
    if (current.claimEndsAt !== current.verificationEndsAt + claimPeriodSec) {
      currentMismatches.push('claimEndsAt != verificationEndsAt + claimPeriod');
    }
    if (current.verificationEndsAt < current.verificationStartedAt + verificationPeriodSec
        || current.verificationEndsAt > verificationCap) {
      currentMismatches.push('verificationEndsAt outside current bounds');
    }
  }
  const currentOk = historyError ? currentMismatches.length === 0 : currentMatch.ok;
  if (!currentOk) notes.push(`current getter != event replay (${currentMismatches.join(', ')})`);

  const emergencyRootMissing = Boolean(ctx.data.emergencySource && S.emergencyRootMissing);
  const canDowngradeRootResubmitted = isEmergencyCheckDowngradable(
    'check.stageC.rootResubmitted', emergencyRootMissing,
  );
  const canDowngradeSubmissionRules = isEmergencyCheckDowngradable(
    'check.stageC.rootSubmissionRules', emergencyRootMissing,
  );
  const canDowngradeLifecycleReplay = isEmergencyCheckDowngradable(
    'check.stageC.lifecycleReplayCurrent', emergencyRootMissing,
  );
  if (!rootRows) {
    report.unverified('check.stageC.rootResubmitted', historyError, { reason: 'archive_unavailable' });
  } else if (events.length > 1) {
    report.check('check.stageC.rootResubmitted', 'warn', { count: events.length });
    S.anomalies.push(ui.t('stageC.anomaly.rootResubmitted', { count: events.length }));
  } else if (events.length === 1 && historyError) {
    report.unverified('check.stageC.rootResubmitted', historyError, { count: events.length });
  } else {
    report.check('check.stageC.rootResubmitted', events.length === 1 ? 'pass'
      : (canDowngradeRootResubmitted ? 'warn' : 'fail'), { count: events.length });
  }
  const ok = notes.length === 0;
  if (ok && historyError) report.unverified('check.stageC.rootSubmissionRules', historyError, { notes: '-' });
  else report.check('check.stageC.rootSubmissionRules', ok ? 'pass'
    : (canDowngradeSubmissionRules ? 'warn' : 'fail'), { notes: notes.join('; ') || '-' });
  if (!ok) S.anomalies.push(ui.t('stageC.anomaly.rootSubmission', { notes: notes.join('; ') }));
  if (historyError && currentOk) report.unverified('check.stageC.lifecycleReplayCurrent', historyError, { reason: 'archive_unavailable' });
  else report.check('check.stageC.lifecycleReplayCurrent', currentOk ? 'pass'
    : (canDowngradeLifecycleReplay ? 'warn' : 'fail'), {
    mismatches: currentMismatches.join(', ') || '-',
    replayError: replayError || '-', lifecycleError: lifecycleError || '-',
  });
  if (emergencyRootMissing) {
    recordEmergencyDifference(ctx, {
      checkId: 'check.stageC.rootSubmissionRules',
      what: 'root submission history is absent while emergency recomputation continues',
      chain: {
        root: null,
        submissionEvents: events.length,
        lifecycleMatchesReplay: currentMatch.ok,
        notes,
      },
      rebuilt: { root: S.factsMerkle?.root ?? null },
      reason: 'the replacement root is intentionally submitted only after the fixed emergency result set is complete',
    });
  }
  report.fact('stageC.lifecycleReplay', historyError ? { unavailable: 'archive_unavailable' } : replay ? {
    verificationEndFloor: replay.verificationEndFloor,
    verificationEndsAt: replay.verificationEndsAt,
    eventCount: replay.history.length,
    verificationCap,
  } : { unavailable: replayError || 'unavailable' });

  // 現在の窓は独自計算せずgetBlockLifecycleを使う。履歴不一致でも都合の良い側へ切替えない。
  const vStartedAt = lifecycle ? Number(lifecycle.verificationStartedAt) : null;
  const vEnd = lifecycle ? Number(lifecycle.verificationEndsAt) : null;
  const claimEnd = lifecycle ? Number(lifecycle.claimEndsAt) : null;

  // 9c. 証明付きなら、初回root txまたは事後attach txのcalldataと15語PVを検査する。
  let proofEvent = events.length > 0 ? events[events.length - 1] : null;
  if (S.zkInfo?.kind === 'proof') {
    const proofAttachedAt = Number(S.blockState.proofAttachedAt || 0);
    let attached = [];
    let attachmentReadError = null;
    try {
      if (typeof ctx.chain.merkleRootProofAttachedEvents !== 'function') {
        throw new Error('MerkleRootProofAttached event reader is unavailable');
      }
      if (rangeError) throw rangeError;
      attached = (await ctx.chain.merkleRootProofAttachedEvents(N, { fromBlock, toBlock }))
        .map((event) => ({
          root: event.root ?? event.args?.root,
          epochIndex: num(event.epochIndex ?? event.args?.epochIndex),
          timestamp: num(event.timestamp ?? event.args?.timestamp),
          txHash: event.txHash ?? event.transactionHash ?? null,
          evtBlock: num(event.evtBlock ?? event.blockNumber),
          transactionIndex: num(event.transactionIndex),
          logIndex: num(event.logIndex ?? event.index),
        }));
    } catch (error) {
      attachmentReadError = error;
    }
    const attachment = attachmentReadError
      ? { ok: false, errors: [attachmentReadError.message], event: null, kind: 'unverified' }
      : resolveCurrentProofAttachment({
          rootEvent: proofEvent,
          attachmentEvents: attached,
          currentRoot: S.blockState.root,
          epochIndex: S.zkInfo.epoch.index,
          proofAttachedAt,
        });
    if (!rootRows && historyError) attachmentReadError ||= historyError;
    if (attachmentReadError instanceof ArchiveUnavailableError) report.unverified('check.stageC.proofAttachmentEvent', attachmentReadError, { reason: 'archive_unavailable' });
    else report.check('check.stageC.proofAttachmentEvent', attachment.ok ? 'pass' : 'fail', {
      kind: attachment.kind,
      errors: attachment.errors.join('; ') || '-',
      candidates: attached.length,
    });
    if (!attachment.ok) S.anomalies.push(`ZKP attachment event could not be uniquely tied to the current root: ${attachment.errors.join('; ')}`);
    const simultaneous = proofEvent?.timestamp === proofAttachedAt;
    proofEvent = attachment.event || (attachmentReadError instanceof ArchiveUnavailableError && simultaneous ? proofEvent : null);
    if (!proofEvent && attachmentReadError instanceof ArchiveUnavailableError) S.proofEventReadError = attachmentReadError;
    const claimStart = vEnd;
    report.fact('stageC.proofAttachment', {
      kind: attachment.kind,
      rootSubmittedAt: events.at(-1)?.timestamp ?? null,
      proofAttachedAt,
      claimStartedAt: claimStart,
      attachedBeforeClaim: claimStart !== null && proofAttachedAt > 0 && proofAttachedAt < claimStart,
      attachedAfterClaimStarted: claimStart !== null && proofAttachedAt >= claimStart,
      securityMeaning: claimStart === null
        ? 'unverified_lifecycle'
        : classifyProofAttachment(proofAttachedAt, claimStart),
      txHash: proofEvent?.txHash || null,
    });
  }
  await verifyZkpSubmission(ctx, S, proofEvent);
  resolveProofProviderLabels(ctx, S);

  // 9d. まとめ用ファクト（getBlockLifecycleの現在値）
  report.fact('stageC.merkleSubmissions', events.map(e => ({
    root: e.root, timestamp: e.timestamp, iso: isoOf(e.timestamp), txHash: e.txHash })));
  report.fact('stageC.verificationStartedAt', { sec: vStartedAt, iso: isoOf(vStartedAt) });
  report.fact('stageC.verificationEndsAt', { sec: vEnd, iso: isoOf(vEnd) });
  report.fact('stageC.claimWindow', {
    startSec: vEnd, endSec: claimEnd, startIso: isoOf(vEnd), endIso: isoOf(claimEnd),
    source: lifecycle ? 'TokenMining.getBlockLifecycle' : 'unavailable',
  });
}

// ------------------------------------------------------------
// 「公開データが壊れていて正典計算を走らせられない」ことを伝えるメッセージ（en/ja/zh）。
//
// ⚠️ ここだけ src/i18n.js のカタログではなくローカルに置いている。カタログへ移す場合は
//    **3言語まとめて**移すこと（1言語だけ移すと欠落キー警告＋英語フォールバックになる）。
//
// 文面の要件（重要）: 第三者が読んで「ツールが壊れた」ではなく「公開データが壊れている
// ＝運営側の問題」と分かること。exit 3（fatal）で落ちると以降のチェックが全部スキップされ、
// 「何が起きたのか分からないまま検証が終わった」という最悪の見え方になる。
const AUTO_DISTRIBUTE_DATA_CORRUPT = {
  en: (n, err) =>
    `Auto-distribution could not be reproduced because the operator-published data for block ${n} is malformed `
    + `(entries/block${n}/game_selection.json — the frozen entry records the canonical calculation runs on). `
    + `This is a defect in the published data, i.e. on the operator's side — not a crash of this tool. `
    + `Treat this block's payout as UNVERIFIED. Details: ${err}`,
  ja: (n, err) =>
    `運営が公開したブロック${n}のデータが壊れているため、自動配布を再現できませんでした`
    + `（entries/block${n}/game_selection.json ＝ 正典の計算が読む凍結済みエントリー）。`
    + `これは本ツールの異常終了ではなく、公開データ＝運営側の問題です。`
    + `このブロックの配布は「未検証」として扱ってください。詳細: ${err}`,
  zh: (n, err) =>
    `由于运营方公开的区块${n}数据已损坏，无法重现自动分配`
    + `（entries/block${n}/game_selection.json ＝ 正典计算所读取的冻结报名数据）。`
    + `这不是本工具的崩溃，而是公开数据（即运营方）的问题。`
    + `请将本区块的分配视为“未经验证”。详情: ${err}`,
};
function autoDistributeDataCorruptMessage(ctx, n, err) {
  const lang = ctx.cfg?.lang;
  const make = Object.hasOwn(AUTO_DISTRIBUTE_DATA_CORRUPT, lang)
    ? AUTO_DISTRIBUTE_DATA_CORRUPT[lang] : AUTO_DISTRIBUTE_DATA_CORRUPT.en;
  return make(n, err);
}

// ============================================================
// Step 10: autoDistribute 経路（game-master-DO.js:3214-3521 の写像）
// ============================================================
async function runAutoWithAvailableState(ctx, S, gm, timing) {
  const adaptedGm = Object.create(gm);
  adaptedGm.availableStateContext = { ctx, S };
  const displayCtx = { ...ctx, ui: { ...ctx.ui, t: (key, params) => ctx.ui.t(key,
    ['stageC.anomaly.depositVerifyUnavailable', 'stageC.anomaly.depositVerifyFailed'].includes(key)
      ? { ...params, error: conciseRpcText(params.error, ctx.ui.t) } : params) } };
  const ok = await runAutoDistribute(displayCtx, S, adaptedGm, timing);
  if (!ok && ctx.report.getFact('stageC.lockStateError') instanceof ArchiveUnavailableError
      && ctx.data.stopReason === 'not_ready') {
    ctx.report.check('check.stageC.autoDistribute', 'skip', { reason: 'archive_unavailable' });
    ctx.report.check('check.stageC.summaryMatch', 'skip', { reason: 'archive_unavailable' });
    delete ctx.data.stopReason;
    return true;
  }
  return ok;
}

async function runAutoDistribute(ctx, S, gm, timing) {
  const { report, ui, blockNum: N } = ctx;
  ui.println(ui.t('stageC.autoMode'));
  const players = ctx.data.gameSelection?.players || [];

  // B1: コミット済みエントリーの depositIds（正典 autoDistribute の parseEntryDepositIds と同一規則）
  //
  // 🔴 uid を添字にする表は必ず `Object.create(null)`（2026-08-07・正典と同時是正）。
  //   uid は `isCanonicalUid` が `/^[\x21-\x7E]+$/` を許すので `__proto__` を置ける。
  //   素の `{}` に `perUid['__proto__'] = [...]`（配列＝オブジェクト）を代入すると
  //   **own property にならず [[Prototype]] の差し替えになる**ため、そのプレイヤーは
  //   `Object.entries(perUid)` から消える＝**オンチェーンのデポジット検証を丸ごと素通り**する。
  //   その結果 depositWei は自己申告の depIds（parseDepositWei）へフォールバックし、
  //   運営が uid を配る立場である以上「検証されないポイント」を任意に作れてしまう。
  const perUid = Object.create(null);
  for (const p of players) {
    const uid = p.data?.uid;
    if (uid == null) continue;
    perUid[uid] = parseEntryDepositIds(p.data?.depIds);
  }
  let verifiedDepositWei, verifiedDeposits;
  try {
    ({ verifiedDepositWei, verifiedDeposits } = await verifyDepositsOnChainInUnits(gm, N, perUid));
    report.check('check.stageC.depositVerification', 'pass', { players: Object.keys(perUid).length });
  } catch (e) {
    const classification = classifyDepositVerificationError(e);
    if (classification === 'unavailable' || classification === 'archive_rpc_required') {
      report.check('check.stageC.depositVerification', 'skip', {
        classification, unavailable: true, error: e.message,
      });
      const message = ui.t('stageC.anomaly.depositVerifyUnavailable', { error: e.message });
      ui.warn(message);
      S.anomalies.push(message);
      ctx.data.stopReason = 'not_ready';
      return false;
    }
    report.check('check.stageC.depositVerification', 'fail', {
      classification, unavailable: false, error: e.message,
    });
    S.anomalies.push(ui.t('stageC.anomaly.depositVerifyFailed', { error: e.message }));
    ctx.data.stopReason = 'fail';
    return false;
  }

  const blockRewardWei = getBlockRewardWei(N);

  // 🔴 公開データ由来の値で正典計算が例外を投げても **fatal（exit 3）にしない**（2026-08-07）。
  //
  //   ここから先の入力は全て公開 R2 の `game_selection.json`（= 運営が書いたバイト列）である。
  //   例えば uid の無いレコードに `depIds = {"deposit":"abc"}` が入っていると
  //   `parseDepositWei` が "abc" を返し `calculateDepositPoints` の `BigInt()` が投げる。
  //   これを素通しすると index.js の最外殻 catch に落ちて `##RESULT fatal` / exit 3 になり、
  //   **「運営の不正を検出した」ではなく「ツールが原因不明で落ちた」**という出方をする。
  //   その瞬間に以降のチェックは全部スキップされ、第三者には何が起きたのか分からない。
  //   壊れた公開データは運営側の問題なので、FAIL（exit 2）＝検証結果として報告する。
  let memberResults, totalPoints, depositorResults, rebuilt;
  try {
    // メンバー結果（:3241-3264）
    //
    // 🔴 J-31（2026-08-08）: 正典 `autoDistribute` と同じ**適格帯判定**を持つ。
    //    以前はここも `isDisqualified: false` を決め打ちしていたので、
    //    「宣言だけして適用していない」自動配布ブロックが満点で PASS していた。
    //    判定は正典と同じ `isIneligibleDepositWei`（ベンダリング済み）1箇所。
    memberResults = players.map(p => {
      const uid = p.data?.uid;
      const hasVerified = uid != null && verifiedDepositWei[uid] !== undefined;
      const depositWei = hasVerified
        ? verifiedDepositWei[uid]
        : parseDepositWei(p.data?.depIds);
      const depositPoints = calculateDepositPoints(depositWei);
      const ineligible = hasVerified && isIneligibleDepositWei(depositWei);
      return {
        uid,
        addr: p.data?.addr || null,
        bAddr: p.data?.bAddr || null,
        lang: p.data?.lang || null,
        depIds: p.data?.depIds || null,
        name: p.data?.name || null,
        img: p.data?.img || null,
        verified: p.data?.verified || false,
        globalIndex: p.globalIndex,
        depositPoints,
        bonusPoints: 0,
        totalPoints: ineligible ? 0 : depositPoints,
        isDisqualified: ineligible,
        disqualifyReason: ineligible ? 'ineligible_deposit' : null,
        btcuReward: '0'
      };
    });

    totalPoints = memberResults.reduce((s, m) => s + m.totalPoints, 0);

    // BTCu按分（:3270-3279）
    for (const member of memberResults) {
      if (totalPoints === 0) {
        member.btcuReward = '0';
      } else {
        member.btcuReward = (
          blockRewardWei * BigInt(member.totalPoints) / BigInt(totalPoints)
        ).toString();
      }
      member.fullReward = member.btcuReward;
    }

    // 50/50 Split（正典 autoDistribute の第2実装。報酬0メンバーは continue＝ゲーム経路と異なる）
    depositorResults = [];
    for (const member of memberResults) {
      const totalReward = BigInt(member.btcuReward || '0');
      if (totalReward === 0n) continue;

      const deposits = verifiedDeposits[member.uid] || [];
      const totalDepWei = deposits.reduce((s, d) => s + BigInt(d.amount), 0n);
      if (deposits.length === 0 || totalDepWei <= 0n) {
        member.playerShare = totalReward.toString();
        continue;
      }

      const playerShare = totalReward / 2n;
      const depositorShareTotal = totalReward - playerShare;
      member.btcuReward = playerShare.toString();
      member.playerShare = playerShare.toString();
      member.depositorShare = depositorShareTotal.toString();

      // **全員切り捨て**（SPEC §7・2026-08-01）。正典 autoDistribute と同じ depositorShareOf を使う。
      // ⚠️ これはゲーム経路とは完全に独立した第2実装。自動配布ブロックでしか走らないので、
      //    片方だけ直すと「自動配布ブロックだけ summaryMatch が FAIL する」形で遅れて出る。
      for (let i = 0; i < deposits.length; i++) {
        const dep = deposits[i];
        const depBtcu = depositorShareOf(depositorShareTotal, dep.amount, totalDepWei);
        depositorResults.push({
          groupId: 0,
          playerUid: member.uid,
          depositorUid: dep.idFrom,
          depositId: dep.depositId,
          depositerAddress: dep.depositerAddress || null,
          depositAmount: dep.amount,
          btcuReward: depBtcu.toString(),
          isPlayerSelf: dep.idFrom === member.uid
        });
      }
    }

    // summary 再構築（:3404-3449。createdAt は中立化対象）
    rebuilt = {
      blockNum: N,
      blockReward: blockRewardWei.toString(),
      totalPlayers: players.length,
      totalGroups: 0,
      autoDistributed: true,
      majorLangs: [],
      groups: [{
        group_id: 0,
        lang: 'auto',
        member_count: memberResults.length,
        status: 'auto_distributed',
        total_points: totalPoints,
        members: memberResults.map(m => ({
          userId: m.uid,
          address: m.addr,
          img: m.img,
          name: m.name,
          lang: m.lang,
          verified: m.verified,
          depIds: m.depIds,
          deposit_points: m.depositPoints,
          bonus_points: 0,
          total_points: m.totalPoints,
          // J-31: 正典と同じく決め打ちをやめる（ここが 0 固定のままだと
          // 適格帯を適用した公開 summary と食い違って summaryMatch が誤 FAIL する）。
          is_disqualified: m.isDisqualified ? 1 : 0,
          disqualify_reason: m.disqualifyReason,
          btcu_reward: m.btcuReward,
          full_btcu_reward: m.fullReward,
          player_share: m.playerShare || null,
          depositor_share: m.depositorShare || null,
          claimed: 0
        })),
        depositor_results: depositorResults.map(d => ({
          depositorUid: d.depositorUid,
          playerUid: d.playerUid,
          depositId: d.depositId,
          depositerAddress: d.depositerAddress || null,
          btcuReward: d.btcuReward,
          isPlayerSelf: d.isPlayerSelf,
          depositorName: memberResults.find(m => m.uid === d.depositorUid)?.name || null,
          depositorImg: memberResults.find(m => m.uid === d.depositorUid)?.img || null,
          depositorVerified: memberResults.find(m => m.uid === d.depositorUid)?.verified || false
        }))
      }],
      // 🔴 P-2026-0842（2026-08-08・台帳 C-3）: 正典（`autoDistribute`）は
      //    公開 summary に実行時刻を入れなくなった（manifest の `files[key]` は
      //    公開バイト列の sha256 なので、実行時刻を入れると同一入力でも
      //    `manifestHash` が動き `resultRegistrationCount` が加算される）。
      //    再構築側も同じ形にしておかないと `summaryByteExact` が常に落ちる。
    };

    // R15-F1 schema v2: claim/Merkle/Stage 2に必要な最小行だけをsummaryへ残し、
    // 表示用の全行はmanifest固定の専用ページへ分離する。旧inline summaryは上の形で互換検証する。
    if (Number(S.files.summary.data?.schemaVersion || 1) >= 2) {
      const autoDetailKey = `games/block${N}/auto-results.json`;
      const summarySchemaVersion = Number(S.files.summary.data.schemaVersion);
      const groupClaimOverlay = summarySchemaVersion >= 3;
      S.expectedAutoResult = {
        schemaVersion: 1,
        meta: { blockNum: N, groupId: 0, autoDistributed: true },
        members: memberResults.map(m => ({
          uid: m.uid, addr: m.addr, bAddr: m.bAddr, lang: m.lang, depIds: m.depIds,
          globalIndex: m.globalIndex, name: m.name, img: m.img, verified: m.verified,
        })),
        gameResults: [
          ...memberResults.map(m => ({
            userId: m.uid, role: 'player', deposit_id: '', address: m.addr || null,
            btcu_reward: m.btcuReward, deposit_to: null,
            ...(groupClaimOverlay ? {} : { claimed: 0 }),
            deposit_points: m.depositPoints, bonus_points: 0, total_points: m.totalPoints,
            is_disqualified: m.isDisqualified ? 1 : 0,
            disqualify_reason: m.disqualifyReason || null, report_gain_points: 0,
            vote_target_uid: null, report_target_uids: null, voted_by_uids: null,
          })),
          ...depositorResults.map(d => ({
            userId: d.depositorUid, role: 'depositor', deposit_id: d.depositId,
            address: d.depositerAddress || null, btcu_reward: d.btcuReward,
            deposit_to: d.playerUid,
            ...(groupClaimOverlay ? {} : { claimed: 0 }),
          })),
        ],
        canonicalTimeline: [],
      };
      rebuilt = {
        schemaVersion: summarySchemaVersion,
        blockNum: N,
        blockReward: blockRewardWei.toString(),
        totalPlayers: players.length,
        totalGroups: 0,
        autoDistributed: true,
        majorLangs: [],
        groups: [{
          group_id: 0,
          lang: 'auto',
          member_count: memberResults.length,
          status: 'auto_distributed',
          total_points: totalPoints,
          detailKey: autoDetailKey,
          ...(groupClaimOverlay ? {
            claimOverlayKey: `games/block${N}/claim-status/group0.json`,
          } : {}),
          members: memberResults.map(m => ({
            userId: m.uid,
            address: m.addr,
            lang: m.lang,
            total_points: m.totalPoints,
            is_disqualified: m.isDisqualified ? 1 : 0,
            full_btcu_reward: m.fullReward,
          })),
          depositor_results: depositorResults.map(d => ({
            playerUid: d.playerUid,
            depositId: d.depositId,
          })),
        }],
        resultLayout: 'auto-distribution-page-v1',
        claimStatusKey: `games/block${N}/claim-status.json`,
        ...(groupClaimOverlay ? { claimLayout: 'group-overlays-v1' } : {}),
      };
    }
  } catch (e) {
    // 到達地点を残す: 深部チェック（summaryMatch / merkle）は動かせないので pass にしない。
    report.check('check.stageC.autoDistribute', 'fail',
      { players: players.length, error: e?.message || String(e) });
    S.anomalies.push(autoDistributeDataCorruptMessage(ctx, N, e?.message || String(e)));
    return false;
  }

  const consistent = S.files.summary.data?.autoDistributed === true;
  report.check('check.stageC.autoDistributeConsistent', consistent ? 'pass' : 'fail',
    { published: S.files.summary.data?.autoDistributed ?? null });
  if (S.expectedAutoResult) {
    const neutralize = (page) => {
      const value = JSON.parse(JSON.stringify(page));
      value.gameResults = neutralizeGroupGameResults(
        value?.gameResults,
        S.files.summary.data?.schemaVersion,
      );
      return value;
    };
    const diffs = diffPaths(
      neutralize(S.expectedAutoResult),
      neutralize(S.files.autoResult?.data || {}),
      { ignore: [] },
    ) || [];
    report.check('check.stageC.autoResultPage', diffs.length === 0 ? 'pass' : 'fail', {
      diffCount: diffs.length,
      failures: diffs.slice(0, 10).map(d => typeof d === 'string' ? d : JSON.stringify(d)).join(', ') || '-',
    });
    if (diffs.length) S.anomalies.push(`auto-results.json differs from canonical rebuilt display rows (${diffs.length})`);
  } else {
    report.check('check.stageC.autoResultPage', 'skip', { reason: 'legacy_inline_summary' });
  }
  compareSummary(ctx, S, rebuilt);
  report.check('check.stageC.autoDistribute', 'pass', { players: players.length, totalPoints });

  report.fact('stageC.autoDistributed', true);
  report.fact('stageC.totalPoints', totalPoints);
  report.fact('stageC.blockReward', blockRewardWei.toString());
  report.fact('stageC.playerCount', players.length);
  report.fact('stageC.groupCount', 0);
  report.fact('stageC.disqualifiedCount', 0);
  if (ctx.data.emergencyServerSubmissions) {
    ctx.data.emergencyRebuild = {
      kind: 'autoDistribute',
      rebuiltSummary: rebuilt,
      allGroupResults: [{ groupId: 0, members: memberResults }],
      depositorResults,
      autoResult: S.expectedAutoResult || null,
      factsMerkle: null,
    };
  }
  return true;
}

// ============================================================
// エントリポイント
// ============================================================
export async function run(ctx) {
  const { ui, report, blockNum: N } = ctx;
  const S = {
    auto: !!ctx.data.autoDistribute,
    noGame: !!ctx.data.noGame,
    timelineNoGame: !!ctx.data.timelineNoGame,
    anomalies: [],
    missing: [],
    // F-6: 「あるが読めない」公開データ（JSON parse 失敗 / オブジェクトでない）
    corrupt: [],
    groupIds: [],
    orderedGroupIds: [],
    chatWindowMs: null,
    resultCount: null,
    evidenceEvents: [],
    groupDataList: [],
    precheckedHashes: new Map(),
    groupPublished: new Map(),
  };
  try {
    ui.section?.();
    ui.println(ui.t('stageC.title', { block: N }));

  recordGcpGroupingContradictions(ctx);

  // ── 1. blockStates / ZKP ゲート: root と、提出時の証明世代を同じ state から読む ──
  // index.js の先行表示で読めていれば再利用し、RPC呼び出しを増やさない。
  const zkInfo = ctx.data.zkInfo || await inspectBlockZkpState(ctx.chain, N);
  S.zkInfo = zkInfo;
  recordZkpState(ctx, S, zkInfo);
  const state = zkInfo.blockState || null;
  if (!state) {
    report.check('check.stageC.rootSubmitted', 'fail', {
      reason: 'blockStates_unavailable',
      error: zkInfo.error || 'unavailable',
    });
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }
  const root = state ? (state.root ?? state.merkleRoot ?? null) : null;
  if (!root || lower(root) === ZERO_ROOT) {
    const routed = await routeMissingRootInStageC(ctx, S, state, root);
    if (routed.stop || routed.branch !== 'emergency_rebuild') return routed;
  } else {
    report.check('check.stageC.rootSubmitted', 'pass', { root });
    ctx.data.emergencyChainRoot = root;
  }
  S.blockState = {
    root: root || ZERO_ROOT,
    verificationStartedAt: num(state.verificationStartedAt),
    zkEpochPlusOne: num(state.zkEpochPlusOne),
    proofAttachedAt: num(state.proofAttachedAt),
  };

  // 前提データ（Stage A/B の成果物）
  if (!S.auto && !S.noGame && !S.timelineNoGame && !Array.isArray(ctx.data.groupsDerived)) {
    report.check('check.stageC.prerequisites', 'fail', { reason: 'groups_not_verified' });
    ui.println(ui.t('stageC.prereqMissing'));
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }
  report.check('check.stageC.prerequisites', 'pass', {});

  // タイミング定数はオンチェーン getter から（env/.env 不信・DESIGN §3）
  const timing = await ctx.chain.getTimingConstants();
  if (timing.invariantOk === false) {
    S.anomalies.push(ui.t('stageC.anomaly.timingInvariant'));
  }

  // R26-C4: 再計算に使う EthLock を `TokenMining.ethLock()` へ束縛してから
  //         `makeGm` を組み立てる（同梱 config の固定値を権威にしない）。
  await bindEthLockAuthority(ctx, S);

  // ── 2. R2 一式取得 ──
  ui.println(ui.t('stageC.downloading'));
  S.groupIds = (S.auto || S.noGame || S.timelineNoGame) ? [] : ctx.data.groupsDerived.map(g => g.groupId);
  await downloadArtifacts(ctx, S.groupIds, S);
  const emergencyRegeneratedArtifactIssue = canContinueEmergencyAfterDownloadIssues(
    N,
    Boolean(ctx.data.emergencySource),
    [...S.corrupt, ...S.missing],
  );
  // 🔴 F-6（2026-08-08・ラウンド20 判断不要-6）: 「あるが読めない」公開データ。
  //    旧実装は共通入口 `r2.js` の `JSON.parse` が throw して最外殻へ抜け、
  //    **`##RESULT fatal` / exit 3**（＝「契約コード欠落」と同じ終了コード）になっていた。
  //    同じファイルの**より軽い**異常（pretty-print / `{}`）は exit 2 の FAIL なので、
  //    「重い異常のほうが弱い信号」という逆転が起きていた。ここで FAIL に揃える。
  if (S.corrupt.length > 0) {
    report.check('check.stageC.downloads', 'fail', { corrupt: S.corrupt.join(', ') });
    ui.println(ui.t('stageC.downloadFailed', { missing: S.corrupt.join(', ') }));
    if (emergencyRegeneratedArtifactIssue) {
      recordEmergencyDifference(ctx, {
        checkId: 'check.stageC.downloads',
        what: 'published artifact regenerated by the fixed-bundle writer is unreadable in emergency recovery',
        chain: { resultManifestHash: ctx.data.emergencySource?.chainResultMarker?.hash ?? null },
        rebuilt: { corrupt: [...S.corrupt], authority: 'canonical fixed-bundle writer' },
        reason: 'these public bytes are not carried into the fixed bundle and are regenerated',
      });
    } else {
      ctx.data.stopReason = 'fail';
      return { stop: true };
    }
  }
  if (S.missing.length > 0) {
    // root（adminCommit）は step 1 で提出済みが確認できている。正典パイプラインは
    // adminCommit を最終段階（merkle→manifest→proofs→adminCommit）に置くため、
    // 「root 提出済み ⟹ manifest／proofs 等は全て公開済み」が不変条件。したがって
    // root があるのに必要な公開ファイルが欠落しているのは事後差し替え・握り潰しの疑い＝FAIL。
    report.check('check.stageC.downloads', 'fail', { missing: S.missing.join(', ') });
    ui.println(ui.t('stageC.downloadFailed', { missing: S.missing.join(', ') }));
    if (emergencyRegeneratedArtifactIssue) {
      recordEmergencyDifference(ctx, {
        checkId: 'check.stageC.downloads',
        what: 'published artifact regenerated by the fixed-bundle writer is missing in emergency recovery',
        chain: { resultManifestHash: ctx.data.emergencySource?.chainResultMarker?.hash ?? null },
        rebuilt: { missing: [...S.missing], authority: 'canonical fixed-bundle writer' },
        reason: 'these public bytes are not carried into the fixed bundle and are regenerated',
      });
    } else {
      ctx.data.stopReason = 'fail';
      return { stop: true };
    }
  }
  if (S.corrupt.length === 0 && S.missing.length === 0) {
    report.check('check.stageC.downloads', 'pass', { groups: S.groupIds.length });
  }

  // ── 2b. 公開 summary.json が正準JSONか（P-2026-0822・2026-08-07） ──
  //
  // 正典（game-master-DO.js）は `summary.json` を読むとき
  // `JSON.stringify(JSON.parse(text)) === text` を要求し、外れたら park する。
  // ここで同じ検査をしないと、**正典が拒否する入力を検証ツールだけが受理する**＝
  // 逆向きに「正典と第三者検証で答えが割れる」状態が作れてしまう（byte-exact 原則）。
  //
  // 🔴 例外を素通しさせない。ここで throw すると index.js:242-245 の最外殻 catch に落ちて
  //   `##RESULT fatal` / exit 3 になり、「運営の不正を検出した」ではなく
  //   「ツールが原因不明で落ちた」という出方になる。壊れた公開データは運営側の問題なので
  //   FAIL（exit 2）＝検証結果として報告する（`runAutoDistribute` の同趣旨コメント参照）。
  //
  // ⚠️ 検査対象は `summary.json` **だけ**。`game_groups.json` 等は整数に見えるキーを含み、
  //   `JSON.parse` がそれを昇順へ並べ替えるため、正しく書かれたファイルでも往復が一致しない
  //   ＝偽陽性になる（vendor/.../lib/canonical-json.js の適用範囲コメントを参照）。
  try {
    parseCanonicalJson(S.files.summary.raw, `games/block${N}/summary.json`);
    report.check('check.stageC.summaryCanonicalJson', 'pass', { reason: 'round-trip identical' });
  } catch (e) {
    const emergencyDifference = isEmergencyCheckDowngradable(
      'check.stageC.summaryCanonicalJson', Boolean(ctx.data.emergencySource),
    );
    report.check('check.stageC.summaryCanonicalJson', emergencyDifference ? 'warn' : 'fail',
      { reason: e?.canonicalJsonReason || 'error', offset: e?.canonicalJsonOffset ?? null, error: e?.message || String(e) });
    ui.println(ui.t('stageC.summaryNotCanonical', { block: N, error: e?.message || String(e) }));
    S.anomalies.push(ui.t('stageC.anomaly.summaryNotCanonical', { block: N }));
    if (emergencyDifference) {
      recordEmergencyDifference(ctx, {
        checkId: 'check.stageC.summaryCanonicalJson',
        what: 'published summary is not canonical minified JSON',
        chain: {
          resultManifestHash: ctx.data.emergencySource.chainResultMarker?.hash ?? null,
          declaredSha256: S.files.manifest?.data?.files?.[`games/block${N}/summary.json`] ?? null,
        },
        rebuilt: { action: 'serialize the independently recomputed summary with JSON.stringify' },
        reason: e?.message || String(e),
      });
    } else {
      report.fact('stageC.anomalies', S.anomalies);
      ctx.data.stopReason = 'fail';
      return { stop: true };
    }
  }

  // manifest hash・正準JSON検査が終わったため、最大192 MiBのraw文字列は以降不要。
  S.files.summary.raw = undefined;
  ctx.r2.releaseRaw?.(`games/block${N}/summary.json`);

  ctx.data.summary = S.files.summary.data;

  // ============================================================
  // 名簿（P2P 冗長経路の信頼の起点）— Q-6（2026-08-08・ユーザー確定）
  // ============================================================
  //
  // 🔴 旧実装の穴: `roster/index.json` だけを `required:false` で読み、記録点は
  //    `pass|warn|skip` の3つ＝**`fail` が存在しなかった**。`roster/group{G}.json` に至っては
  //    artifactKeys にも入っておらず、**一度も読まれていなかった**。
  //    実測: `roster/group0.json` の1人の `blockAddress`/`pubKey` を攻撃者鍵へ差し替えると
  //    `exit 0 / ##RESULT full / pass 62 / warn 0 / fail 0`。差し替えは無言で
  //    （`chatgame-tools/src/recovery/relay-verify.js:71` の `catch { return false }`）、
  //    被害者には「相手が何も喋っていない」ようにしか見えない。
  //
  // 🔴 2段構え（片方だけでは閉じない）:
  //    ① manifest（artifactKeys）に載せる … バイト列がチェーンのアンカーに固定される。
  //       これは上の 3d（sha256 照合）が担当する。
  //    ② **応募データとの突き合わせ** … ①だけだと、運営が差し替えた名簿を目録に含めて
  //       一貫させれば通る。名簿の `walletAddress` / `blockAddress` / `pubKey` / `depositIds` が
  //       **応募時の登録値**（`entries/block{N}/game_selection.json` → `applicantHash` で
  //       チェーンに固定・運営が後から動かせない）と一致することをここで見る。
  //
  // ⚠️ 自動配布／0名ブロックは ChatGameDO が起きない＝名簿は存在しないのが正しい。
  //    その場合も**検査を飛ばさず**、「余計な名簿が公開されていないこと」を検査する
  //    （旧実装は `if (!S.auto)` で囲まれていて自動配布経路では何も記録しなかった）。
  {
    const idx = S.files.rosterIndex?.data ?? null;
    const hasGame = !S.auto && !S.timelineNoGame
      && Array.isArray(ctx.data.groupsDerived) && ctx.data.groupsDerived.length > 0;

    if (!hasGame) {
      const extras = [];
      if (idx) extras.push(`games/block${N}/roster/index.json`);
      for (const gid of S.files.rosters.keys()) extras.push(`games/block${N}/roster/group${gid}.json`);
      if (S.auto) {
        const players = ctx.data.gameSelection?.players;
        const roster = S.files.autoRoster;
        if (!Array.isArray(players)) extras.push('auto group0 selection missing');
        else {
          try {
            const expectedRaw = autoRosterTextFromSelection(N, players);
            if (roster?.raw !== expectedRaw) {
              const reason = roster?.raw ? 'published group0 differs from selected entries' : 'published group0 missing';
              if (ctx.data.emergencySource) {
                report.check('check.stageC.autoRoster', 'fail', { reason });
                recordEmergencyDifference(ctx, {
                  checkId: 'check.stageC.autoRoster', what: `games/block${N}/roster/group0.json`,
                  chain: { publishedSha256: roster?.raw ? sha256HexOfString(roster.raw) : null },
                  rebuilt: { sha256: sha256HexOfString(expectedRaw), source: 'Stage B selection' },
                  reason: 'the canonical emergency writer recreates group0 from the selected entries',
                });
              } else extras.push(`auto group0 ${reason}`);
            }
          } catch (error) {
            extras.push(`invalid selected auto roster: ${error.message}`);
          }
        }
      }
      report.check('check.stageC.rosterIndex', extras.length === 0 ? 'pass' : 'fail',
        { failures: extras.join(', ') || '-' });
      report.check('check.stageC.rosterKeys', extras.length === 0 ? 'pass' : 'fail',
        { groups: 0, failures: extras.join(', ') || '-' });
    } else {
      // ── ① uid → groupId 索引 ──
      const idxFailures = [];
      if (idx && typeof idx === 'object') {
        let expectedCount = 0;
        for (const g of ctx.data.groupsDerived) {
          for (const m of g.members) {
            expectedCount++;
            const uid = m.data?.uid;
            if (idx[uid] !== g.groupId) idxFailures.push(`${uid}: ${JSON.stringify(idx[uid] ?? null)} != ${g.groupId}`);
          }
        }
        const actualCount = Object.keys(idx).length;
        if (actualCount !== expectedCount) idxFailures.push(`entries ${actualCount} != ${expectedCount}`);
      }
      report.check('check.stageC.rosterIndex', idxFailures.length === 0 ? 'pass' : 'fail',
        { failures: idxFailures.slice(0, 5).join('; ') || (idx ? '-' : 'cache absent; reconstructed from committed grouping') });
      if (idxFailures.length > 0) S.anomalies.push(ui.t('stageC.anomaly.rosterIndexMismatch', { failures: idxFailures.slice(0, 5).join('; ') }));

      // ── ② グループ名簿の鍵が応募データと一致するか ──
      //    `chat-game-DO.js:627-646`（roster writer）の**手書きミラー**（`rosterMembersOf`）。
      //    writer 側を変えたらここも変えること（変え忘れれば FAIL に倒れる＝無言の乖離にならない）。
      //    🔴 2026-09-05（周13）: 行番号が `526-538` のまま取り残されていたので実測へ直し、
      //       写像そのものを `rosterMembersOf` へ集約して VENDOR_SYNC.md の MIRROR 台帳へ登録した
      //       （それまでこのミラーは**ドリフト検知の台帳に載っていなかった**）。
      const keyFailures = [];
      for (const g of ctx.data.groupsDerived) {
        const key = `games/block${N}/roster/group${g.groupId}.json`;
        const data = S.files.rosters.get(g.groupId)?.data ?? null;
        // V25-03: 不在はselection + groupingの独立再現で代替する。存在するキャッシュだけを
        // 厳密照合し、偽の鍵を載せたcacheは従来どおりFAILする。
        if (!data) continue;
        if (typeof data !== 'object') { keyFailures.push(`${key}: invalid object`); continue; }
        if (data.blockNum !== N || data.groupId !== g.groupId) {
          keyFailures.push(`${key}: header {blockNum:${JSON.stringify(data.blockNum)}, groupId:${JSON.stringify(data.groupId)}}`);
          continue;
        }
        const expected = rosterMembersOf(g);
        const published = Array.isArray(data.members) ? data.members : null;
        if (!published) { keyFailures.push(`${key}: members is not an array`); continue; }
        const actual = published;
        if (!canonicalEqual(expected, actual)) {
          const len = Math.max(expected.length, actual.length);
          let first = null;
          for (let i = 0; i < len && first === null; i++) {
            if (!canonicalEqual(expected[i] ?? null, actual[i] ?? null)) {
              first = `#${i} expected=${JSON.stringify(expected[i] ?? null)} actual=${JSON.stringify(actual[i] ?? null)}`;
            }
          }
          keyFailures.push(`${key}: ${first ?? 'member list differs'}`);
        }
      }
      report.check('check.stageC.rosterKeys', keyFailures.length === 0 ? 'pass' : 'fail',
        { groups: ctx.data.groupsDerived.length,
          failures: keyFailures.slice(0, 3).join(' | ')
            || (S.files.rosters.size < ctx.data.groupsDerived.length ? 'missing caches reconstructed from committed grouping' : '-') });
      if (keyFailures.length > 0) S.anomalies.push(ui.t('stageC.anomaly.rosterKeysMismatch', { failures: keyFailures.slice(0, 3).join(' | ') }));
    }
  }

  // ── 3. manifest 照合（D2） ──
  ui.println(ui.t('stageC.manifestChecking'));
  // 🔴 F-6: manifest が読めない（null / オブジェクトでない）場合は `{stop:true}` が返る。
  //    旧実装は戻り値を見ておらず、そのまま先へ進んで `manifest.rules` の TypeError で
  //    `##RESULT fatal` / exit 3 になっていた。
  {
    const r = await checkManifest(ctx, S, timing);
    if (r && r.stop) return r;
  }

  // V25-03: timeline不照合の終端は「応募0件」ではない。専用summaryを再構築し、
  // 記録されたsafe block上のEvidence窓終了＋resultCount=0を直接照合する。
  if (S.timelineNoGame) {
    const schemaOk = await verifyTimelineNoGameFinality(ctx, S);
    const chatGate = await verifyTimelineNoGameRootPresentChatGate(ctx, S);
    if (chatGate.chatStatus === 'warn') return { stop: true };
    S.groupDataList = [];
    await reproduceEvidence(ctx, S);
    await finalizeEvidenceArchiveChecks(ctx, S);
    const noEvidence = checkTimelineNoGameEvidenceEmpty(ctx, S);
    await verifyMerkle(ctx, S, makeGm(ctx, timing, {
      [`games/block${N}/summary.json`]: S.files.summary.data,
    }));
    await verifyTimeline(ctx, S, timing);
    report.check('check.stageC.majorLangsMatch', 'skip', { published: '-', derived: '-' });
    report.fact('stageC.noGame', true);
    report.fact('stageC.timelineNoGame', true);
    report.fact('stageC.autoDistributed', false);
    report.fact('stageC.blockReward', getBlockRewardWei(N).toString());
    report.fact('stageC.totalPoints', 0);
    report.fact('stageC.groupCount', 0);
    report.fact('stageC.playerCount', ctx.data.gameSelection?.players?.length ?? 0);
    report.fact('stageC.disqualifiedCount', 0);
    report.fact('stageC.resultCount', S.resultCount ?? null);
    if (ctx.data.emergencyServerSubmissions && S.timelineNoGameCanonical?.rebuilt) {
      const authoritative = S.timelineNoGameCanonical.authoritative;
      ctx.data.emergencyRebuild = {
        kind: 'timelineNoGame',
        rebuiltSummary: S.timelineNoGameCanonical.rebuilt,
        invalidNoGameCause: S.timelineNoGameCanonical.invalidNoGameCause === true,
        allGroupResults: [],
        depositorResults: [],
        evidence: {
          resultCount: 0,
          adoptedCount: emergencyAdoptedCountOf(0, S.adoptedByUid),
          chatWindowMs: S.chatWindowMs,
        },
        noGameMeta: {
          reason: 'timeline_unverified',
          cause: S.timelineNoGameCanonical.rebuilt.noGameCause,
          totalPlayers: ctx.data.gameSelection?.players?.length ?? 0,
          chainFinality: authoritative ? {
            evidenceContract: authoritative.evidenceContract,
            safeBlockNumber: authoritative.safeBlockNumber,
            safeTimestamp: authoritative.safeTimestamp,
            resultOpenAt: authoritative.resultOpenAt,
            resultCloseAt: authoritative.resultCloseAt,
            resultCount: 0,
            chatOpenAt: S.chatWindow?.chatOpenAt,
            chatCloseAt: S.chatWindow?.chatCloseAt,
            confirmations: ctx.cfg.pins.confirmationBlocks,
          } : null,
        },
        factsMerkle: S.factsMerkle || null,
      };
    }
    if (!schemaOk || !noEvidence) ctx.data.stopReason = 'fail';
    settleManifestParked(ctx, S);
    report.fact('stageC.anomalies', S.anomalies);
    ui.println(ui.t('stageC.completed', { anomalies: S.anomalies.length }));
    return { stop: false };
  }

  const gm = makeGm(ctx, timing, {
    [`games/block${N}/summary.json`]: S.files.summary.data,
  });

  // ── 10a. 0名 noGame 分岐 ──
  // 正典 finalizeNoGameBlock のschema v2/v3出力を独立再構築し、空ツリー標識root、
  // オンチェーンclaim data、manifest、root提出履歴まで通常のStage Cゲートで検証する。
  if (S.noGame) {
    const rebuilt = buildZeroEntryNoGameSummary(
      N,
      S.files.summary.data?.schemaVersion,
      Boolean(ctx.data.emergencySource),
    );

    const published = S.files.summary.data;
    const shapeOk = zeroEntryNoGameSummaryShapeMatches({
      selectionPlayers: ctx.data.gameSelection?.players,
      published,
      rebuilt,
      blockNum: N,
      gameGroups: S.files.gameGroups,
      autoResult: S.files.autoResult,
      emergencyMode: Boolean(ctx.data.emergencySource),
    });
    report.check('check.stageC.noGameSummary', shapeOk ? 'pass' : 'fail', {
      selectionPlayers: ctx.data.gameSelection?.players?.length ?? null,
      schemaVersion: published?.schemaVersion ?? null,
      reason: published?.noGameReason ?? null,
    });
    if (!shapeOk) S.anomalies.push('The published noGame summary does not match the canonical zero-entry schema.');

    compareSummary(ctx, S, rebuilt);
    recordMajorLangsMatchForMode(ctx, published?.majorLangs, [], {
      emergencyZeroEntryNoGame: true,
    });

    ui.println(ui.t('stageC.merkleChecking'));
    await verifyMerkle(ctx, S, gm);
    ui.println(ui.t('stageC.timelineChecking'));
    await verifyTimeline(ctx, S, timing);

    report.fact('stageC.noGame', true);
    report.fact('stageC.autoDistributed', false);
    report.fact('stageC.blockReward', getBlockRewardWei(N).toString());
    report.fact('stageC.totalPoints', 0);
    report.fact('stageC.groupCount', 0);
    report.fact('stageC.playerCount', 0);
    report.fact('stageC.disqualifiedCount', 0);
    report.fact('stageC.resultCount', 0);
    if (ctx.data.emergencyServerSubmissions) {
      ctx.data.emergencyRebuild = {
        kind: 'noGame',
        rebuiltSummary: rebuilt,
        allGroupResults: [],
        depositorResults: [],
        noGameMeta: { reason: 'zero_entries' },
        factsMerkle: S.factsMerkle || null,
      };
    }
    settleManifestParked(ctx, S);
    report.fact('stageC.anomalies', S.anomalies);
    ui.println(ui.t('stageC.completed', { anomalies: S.anomalies.length }));
    return { stop: false };
  }

  // ── 10. autoDistribute 分岐 ──
  if (S.auto) {
    if (ctx.data?.emergencySource?.authority === 'gcp'
        && ctx.data.emergencySource.syntheticSummary) {
      // 結果未公開の入口だけ正準計算を試行してから、同じ mirror を本検証として実行する。
      // 試行の report と S は隔離し、MIRROR の本体は変更しない。
      const trialCtx = {
        ...ctx,
        report: createReport(),
        ui: { t: (...args) => ui.t(...args), println() {}, warn() {} },
        data: { ...ctx.data, emergencyRebuild: null },
      };
      // This page is regenerated by the trial. Its saved comparison copy is
      // attacker controlled and must never enter the mirror's neutralize path.
      const trialS = { ...S, files: { ...S.files, autoResult: null }, anomalies: [] };
      const prepared = await runAutoWithAvailableState(trialCtx, trialS, gm, timing);
      if (!prepared || !trialCtx.data.emergencyRebuild?.rebuiltSummary) {
        throw new Error(`block ${N}: GCP auto summary could not be recalculated from chain deposits`);
      }
      const rebuilt = trialCtx.data.emergencyRebuild.rebuiltSummary;
      S.files.summary = { data: rebuilt, raw: JSON.stringify(rebuilt) };
      if (trialCtx.data.emergencyRebuild.autoResult) {
        const page = trialCtx.data.emergencyRebuild.autoResult;
        S.files.autoResult = { data: page, raw: JSON.stringify(page) };
      }
      recordEmergencyDifference(ctx, {
        checkId: 'emergency.gcpAutoSummaryRebuilt',
        what: `games/block${N}/summary.json`,
        chain: { selectedPlayers: ctx.data.gameSelection?.players?.length ?? 0 },
        rebuilt: { authority: 'runAutoDistribute', summarySha256: sha256HexOfString(S.files.summary.raw) },
        reason: 'the saved summary is comparison evidence only; deposits and reward were recalculated from chain data',
      });
    }
    const ok = await runAutoWithAvailableState(ctx, S, gm, timing);
    if (!ok && ctx.data.stopReason === 'not_ready') {
      report.fact('stageC.anomalies', S.anomalies);
      return { stop: true };
    }
    if (ok) {
      await verifyMerkle(ctx, S, gm);
      if (ctx.data.emergencyRebuild) ctx.data.emergencyRebuild.factsMerkle = S.factsMerkle;
      await verifyTimeline(ctx, S, timing);
    }
    // G6: autoDistribute ブロックは majorLangs を持たない → skip
    report.check('check.stageC.majorLangsMatch', 'skip', { published: '-', derived: '-' });
    // G5 後段: manifest 保留分の確定
    settleManifestParked(ctx, S);
    report.fact('stageC.anomalies', S.anomalies);
    ui.println(ui.t('stageC.completed', { anomalies: S.anomalies.length }));
    return { stop: false };
  }

  // グループ順序: 公表 summary の観測順（＝本番 D1 行順）を正とし、検証済み集合と一致必須
  const publishedIds = (S.files.summary.data.groups || []).map(g => g.group_id);
  const derivedSet = new Set(S.groupIds);
  const setOk = publishedIds.length === derivedSet.size
    && new Set(publishedIds).size === publishedIds.length
    && publishedIds.every(gid => derivedSet.has(gid));
  report.check('check.stageC.summaryGroupSet', setOk ? 'pass' : 'fail',
    { published: publishedIds.join(','), derived: [...derivedSet].join(',') });
  if (!setOk) {
    S.anomalies.push(ui.t('stageC.anomaly.groupSetMismatch'));
    if (!ctx.data.emergencyServerSubmissions) {
      report.fact('stageC.anomalies', S.anomalies);
      ctx.data.stopReason = 'fail';
      return { stop: true };
    }
  }
  // 緊急経路は、攻撃者が書いたsummaryの欠落・並べ替えで再計算自体を止めない。
  // Stage Bで再現済みのgroupId列を使い、食い違いは上のFAILと差分へ残す。
  S.orderedGroupIds = setOk ? publishedIds : [...S.groupIds];
  S.d1Groups = reconstructD1Groups(ctx.data.groupsDerived);

  // ── 5a. groupData 組立（アーカイブ vs 検証済みグループ） ──
  buildGroupDataList(ctx, S);
  if (S.groupDataList.length === 0) {
    report.fact('stageC.anomalies', S.anomalies);
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }

  // ── 4. Evidence 再現＋マージ（採点入力の確定。デポジット検証より前＝本番 :2429-2435 と同順） ──
  ui.println(ui.t('stageC.evidenceChecking'));
  await reproduceEvidence(ctx, S);
  if (S.evidenceStateError) return finishWithoutDepositInputs(ctx, S, gm, timing);
  // E11-01 は同じ組の提出／Evidence を採用する。R31-U-J3 は緊急時だけ、
  // 他組の証拠などでブロック全体のゲーム実施を示せれば欠落組を提出0として通す。
  let blockGameEvidence = null;
  if (ctx.data.emergencySource && S.missingGroupArchives?.size > 0) {
    if (Object.keys(S.adoptedByUid || {}).length > 0) {
      blockGameEvidence = 'adopted_evidence';
    } else {
      const inspected = await inspectEmergencyTimelineNoGameChatArtifacts(ctx, S.files.manifest?.data);
      if (inspected.evidenceKeys.length > 0) {
        blockGameEvidence = inspected.evidenceKeys.some((key) => key.includes('signedMessages='))
          ? 'signed_chat_start' : 'saved_other_group_record_or_submission';
      }
    }
  }
  const {
    groups: missingGroupRescue,
    unrescued: missingWithoutEvidence,
  } = classifyMissingGroupEvidence(
    S.missingGroupArchives,
    S.adoptedByUid,
    ctx.data.emergencySource ? ctx.data.emergencyServerSubmissions : null,
    blockGameEvidence,
  );
  if (missingWithoutEvidence.length > 0) {
    report.check('check.stageC.scoring', 'fail', {
      groups: 0,
      failures: `group archive(s) missing (${missingWithoutEvidence.map((item) => item.gid).join(',')}) and no valid Evidence${ctx.data.emergencySource ? ' or preserved submission' : ''} from those groups is available for rescue`,
    });
    for (const item of missingWithoutEvidence) {
      S.anomalies.push(ui.t('stageC.anomaly.groupArchiveUnrescued', { group: item.gid }));
    }
    report.fact('stageC.anomalies', S.anomalies);
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }
  for (const item of missingGroupRescue) {
    if (item.emptyGroup) {
      const members = S.d1Groups.find((row) => Number(row.group_id) === Number(item.gid));
      recordEmergencyDifference(ctx, {
        checkId: 'emergency.missingGroupWithoutSubmissions',
        what: 'a committed group has no archive, preserved submission, or adopted Evidence',
        chain: { blockNum: N, groupId: item.gid },
        rebuilt: { groupId: item.gid,
          members: members ? JSON.parse(members.members).length : 0,
          submissions: 0 },
        reason: blockGameEvidence,
      });
      continue;
    }
    S.anomalies.push(ui.t('stageC.anomaly.groupArchiveRescued', {
      group: item.gid, adopted: item.adopted + item.preserved,
    }));
  }
  // membersIndex構築後は軽量投影のmembersも不要。採点は各archiveを1組ずつ再読込する。
  for (const item of S.groupDataList) item.data = undefined;
  S.files.groups.clear();

  // ── 5b. B1 デポジット再検証（本物 gm.verifyDepositsOnChainForUids・実RPC読取） ──
  //
  // K-S2-002（2026-08-01 是正・Stage C）: depositId 一覧の権威は **エントリー時の depIds**。
  //   正典は calcDepidsUnit で game_selection.json の depIds を使うようになったが、
  //   検証ツールはここだけ `verifySignedDepositsOnChain`（＝**提出物**の depositIds）を
  //   呼び続けており、正典と入力ソースが食い違っていた
  //   （正典 game-master-DO.js のコメント「本是正で両者が同一ソースになる」は
  //     検証ツール側が未追随のため成立していなかった）。
  //   食い違うと、提出物に後出し ID を混ぜた参加者が居るだけで
  //   **正直な運営を summaryMatch FAIL で告発してしまう**。
  //   autoDistribute 経路（runAutoDistribute）は元からエントリー depIds を使っている。
  ui.println(ui.t('stageC.depositChecking'));
  let verifiedDepositWei, verifiedDeposits;
  try {
    // 🔴 uid 添字の表は `Object.create(null)`（理由は runAutoDistribute 側の同名コメント参照）。
    //   ここで `__proto__` の uid が落ちると、そのプレイヤーだけ verifiedDepositWei が
    //   欠けたまま採点へ渡り、デポジットポイントが検証されない。
    const perUid = Object.create(null);
    for (const p of (ctx.data.gameSelection?.players || [])) {
      const uid = p?.data?.uid;
      if (uid == null) continue;
      perUid[String(uid)] = parseEntryDepositIds(p.data?.depIds);
    }
    const inputs = await verifyDepositsWithAvailableState(ctx, S, gm, perUid);
    if (!inputs) {
      return finishWithoutDepositInputs(ctx, S, gm, timing);
    }
    ({ verifiedDepositWei, verifiedDeposits } = inputs);

    // 🔴 5b-2: 権威表の**形**を確認してから採点へ渡す
    //    （P-2026-0822・ユーザー判断 J-10 (B)・2026-08-07）
    //
    // 正典 `calculateGroupResults` は `groupData.verifiedDepositWei` が `undefined` / `null` だと
    // **自己申告デポジット（`member.depIds`）へフォールバックする枝**へ落ちる。その枝は
    // B1 の上限も下限も一切かけない（実測: 自己申告 1e12 ETH が無音で 100,000,000pt）。
    // フォールバック枝はテストと一部ツールのために意図的に残されているので、
    // **枝を塞ぐのではなくそこへ続く扉に鍵をかける**
    // （正典側の対応物は `game-master-DO.js` `calcScoringUnit` の `vdep.wei` 形式検査）。
    //
    // 🔴 ここで throw してはいけない。index.js:242-245 の最外殻 catch に落ちると
    //   `##RESULT fatal` / exit 3 になり、「運営の不正を検出した」ではなく
    //   「ツールが原因不明で落ちた」という出方になる（`runAutoDistribute` の同趣旨コメント参照）。
    //   FAIL（exit 2）＝検証結果として報告する。
    //
    // ⚠️ この検査は `Object.keys(verifiedDepositWei)` の**前**に置くこと。
    //   `Object.keys(null)` は TypeError を投げるので、後ろに置くと `null` のときだけ
    //   下の catch（`depositVerifyFailed`）に化けて、この検査に一度も到達しない。
    const tableShape = Array.isArray(verifiedDepositWei) ? 'array'
      : (verifiedDepositWei === null ? 'null' : typeof verifiedDepositWei);
    report.check('check.stageC.depositTableShape', tableShape === 'object' ? 'pass' : 'fail',
      { shape: tableShape });
    if (tableShape !== 'object') {
      S.anomalies.push(ui.t('stageC.anomaly.depositTableShape', { shape: tableShape }));
      report.fact('stageC.anomalies', S.anomalies);
      ctx.data.stopReason = 'fail';
      return { stop: true };
    }

    if (!report.getFact('stageC.lockStateError')) report.check('check.stageC.depositVerification', 'pass',
      { players: Object.keys(verifiedDepositWei).length });
  } catch (e) {
    const classification = classifyDepositVerificationError(e);
    if (classification === 'unavailable' || classification === 'archive_rpc_required') {
      report.check('check.stageC.depositVerification', 'skip', {
        classification, unavailable: true, error: e.message,
      });
      const message = ui.t('stageC.anomaly.depositVerifyUnavailable', { error: conciseRpcText(e.message, ui.t) });
      ui.warn(message);
      S.anomalies.push(message);
      report.fact('stageC.anomalies', S.anomalies);
      ctx.data.stopReason = 'not_ready';
      return { stop: true };
    }
    report.check('check.stageC.depositVerification', 'fail', {
      classification, unavailable: false, error: e.message,
    });
    S.anomalies.push(ui.t('stageC.anomaly.depositVerifyFailed', { error: conciseRpcText(e.message, ui.t) }));
    report.fact('stageC.anomalies', S.anomalies);
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }

  // ── 6. 採点（本物 calculateGroupResults・検証器の固定 pin 値で実行） ──
  // manifest.rules は上の rulesPins で厳密照合するが、緊急再計算の入力権威にはしない。
  const { minChars, minMessages, chatCaps } = scoringThresholdsFromPins(ctx.cfg);
  ui.println(ui.t('stageC.scoringGroups', { count: S.groupDataList.length }));
  const allGroupResults = [];
  const scoreFailures = [];
  for (const { group } of S.groupDataList) {
    const groupKey = `games/block${N}/group${group.group_id}.json`;
    let loaded = null;
    try {
      // 初回passでmanifest hash確認済みのcacheを使う。古いcacheならR2を再取得し、
      // 同じ宣言hashを満たすバイトだけを採点へ渡す。
      loaded = await ctx.r2.fetchJson(groupKey, { reuse: true });
      const checkedHash = S.precheckedHashes.get(groupKey)?.actualHash ?? null;
      if (checkedHash != null && loaded?.raw && sha256HexOfString(loaded.raw) !== checkedHash) {
        loaded = await ctx.r2.refetch(groupKey);
      }
      if ((!loaded?.data || typeof loaded.data !== 'object') && S.missingGroupArchives?.has(group.group_id)) {
        const row = S.d1Groups.find((g) => Number(g.group_id) === Number(group.group_id));
        const members = row ? JSON.parse(row.members) : [];
        loaded = {
          data: {
            phase: 'completed',
            meta: { blockNum: N, groupId: group.group_id },
            members,
            messages: [], receipts: [], charCounts: {}, phaseTimestamps: {},
            submissions: {}, submissionsRaw: {}, reports: {}, votes: {}, gameSkipped: null,
            evidenceRescue: { schemaVersion: 1, source: 'committed_grouping' },
          },
          raw: null,
          reconstructed: true,
        };
      }
      if (!loaded?.data || typeof loaded.data !== 'object') {
        throw new Error(loaded?.sizeError || loaded?.parseError || 'group archive missing or invalid');
      }
      if (checkedHash != null && (!loaded.raw || sha256HexOfString(loaded.raw) !== checkedHash)) {
        // claimed更新でparkされた場合も、初回passの内容投影とは違うバイトを採点入力にしない。
        // 初回cacheが残っていないのは資源上限到達等の異常なので明示FAILにする。
        throw new Error('group archive bytes differ from the manifest-checked snapshot');
      }
      const data = loaded.data;
      applyEmergencyGroupAuthority(ctx, S, data, group.group_id);
      await mergeEvidenceIntoGroup(S, data);
      if (ctx.data.emergencyServerSubmissions) {
        mergeEmergencyServerSubmissions(S, data, ctx.data.emergencyServerSubmissions);
      }
      if (S.rosterSubmission) applyRosterSubmissionGate(data, S.rosterSubmission);
      data.verifiedDepositWei = verifiedDepositWei; // 本番 :2446
      // K-S2-001 是正（2026-07-27・正典 game-master-DO.deriveSubmissionsFromRaw の写像）:
      // 採点入力は必ず submissionsRaw から導出する。公開アーカイブの submissions（parsed）を
      // そのまま信用すると、「raw はチェーンと一致・parsed だけ改変」という運営改竄を
      // 検証ツールも忠実に再現してPASSさせてしまう（＝Evidence の保険が無効化される）。
      withVendorLogging(() => GameMasterDO.prototype.deriveSubmissionsFromRaw.call({}, data, group.group_id));
      if (ctx.data.emergencyServerSubmissions) {
        const fixedInput = JSON.parse(JSON.stringify(data));
        delete fixedInput.verifiedDepositWei;
        (ctx.data.emergencyGroupArchives ||= new Map()).set(Number(group.group_id), fixedInput);
      }
      const { results: memberResults, resolvedTaboos, canonicalTimeline } =
        await withVendorLogging(() => calculateGroupResults(data, minChars, minMessages, chatCaps, S.chatWindowMs));
      allGroupResults.push({
        groupId: group.group_id,
        members: memberResults,
        resolvedTaboos: resolvedTaboos || {},
        canonicalTimeline,
      });
    } catch (e) {
      // 本番 :2454-2456 はエラーグループをスキップして続行 — 同じ挙動＋アノマリー記録
      scoreFailures.push(`group${group.group_id}: ${e.message}`);
      S.anomalies.push(ui.t('stageC.anomaly.groupScoreFailed', { group: group.group_id, error: e.message }));
    } finally {
      if (loaded) { loaded.data = undefined; loaded.raw = undefined; }
      ctx.r2.release?.(groupKey);
    }
  }
  await finalizeEvidenceArchiveChecks(ctx, S);
  report.check('check.stageC.scoring', scoreFailures.length === 0 ? 'pass' : 'fail',
    { groups: allGroupResults.length, failures: scoreFailures.join('; ') || '-' });
  if (allGroupResults.length === 0) {
    report.fact('stageC.anomalies', S.anomalies);
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }

  // 報酬按分＋50/50スプリット（MIRROR :2463-2612）→ summary 再構築（本物 :3875-3955）
  let split;
  try {
    split = mirrorRewardSplit(N, allGroupResults, S.d1Groups, verifiedDeposits);
  } catch (e) {
    report.check('check.stageC.summaryMatch', 'fail', { error: e.message });
    S.anomalies.push(ui.t('stageC.anomaly.rewardSplitFailed', { error: e.message }));
    report.fact('stageC.anomalies', S.anomalies);
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }

  // ── 6c. game.js が表示する group{G}.json / gameResults 照合 ──
  // claimed だけは請求後に listen-worker が書き換えるため中立化する。
  // それ以外の行・順序・表示用採点値・投票/密告対象は正典 writer の再構築値と完全一致が必要。
  await compareGroupGameResults(ctx, S, allGroupResults, split.depositorResults);

  // ── 6d. game.js のチャット欄が表示する canonicalTimeline 照合 ──
  // 表示側で生ログを再集計せず、採点器が確定した union と完全一致することを要求する。
  compareGroupCanonicalTimelines(ctx, S, allGroupResults);

  // ── 7. summary 照合 ──
  ui.println(ui.t('stageC.summaryComparing'));
  const rebuiltSummary = await withVendorLogging(() => gm.buildBlockSummaryWithResults(
    N, allGroupResults, S.d1Groups, split.blockRewardWei.toString(), split.depositorResults));
  compareSummary(ctx, S, rebuiltSummary);
  if (ctx.data.emergencyServerSubmissions) {
    const canonicalRows = await rebuildCanonicalGroupGameResults(
      N, allGroupResults, split.depositorResults, S.d1Groups,
    );
    for (const groupResult of allGroupResults) {
      const archive = ctx.data.emergencyGroupArchives?.get(Number(groupResult.groupId));
      if (!archive) continue;
      archive.gameResults = canonicalRows.get(Number(groupResult.groupId));
      archive.canonicalTimeline = groupResult.canonicalTimeline;
    }
    ctx.data.emergencyRebuild = {
      kind: 'groupGame',
      rosterSubmission: S.rosterSubmission,
      rebuiltSummary,
      allGroupResults,
      depositorResults: split.depositorResults,
      d1Groups: S.d1Groups,
      verifiedDepositWei: JSON.parse(JSON.stringify(verifiedDepositWei)),
      chatWindowMs: S.chatWindowMs,
      factsMerkle: null,
      evidence: {
        resultCount: S.resultCount,
        adoptedCount: emergencyAdoptedCountOf(S.resultCount, S.adoptedByUid),
        chatWindowMs: S.chatWindowMs,
      },
    };
  }

  // G6: majorLangs の固定点照合 — 再構築 summary は公表 summary から majorLangs を継承するため
  // summaryMatch では検出できない。公表値を Stage B 導出値（ctx.data.majorLangs）と直接照合する。
  {
    const publishedMajor = S.files.summary.data?.majorLangs;
    const majorLangsMatch = buildMajorLangsMatchCheck(publishedMajor, ctx.data.majorLangs);
    report.check('check.stageC.majorLangsMatch', majorLangsMatch.status, majorLangsMatch.params);
  }

  // ── 8. Merkle 照合（公表 summary → ツリー → root → 全proof） ──
  ui.println(ui.t('stageC.merkleChecking'));
  await verifyMerkle(ctx, S, gm);
  if (ctx.data.emergencyRebuild) ctx.data.emergencyRebuild.factsMerkle = S.factsMerkle;

  // ── 9. タイムライン照合＋まとめ用ファクト ──
  ui.println(ui.t('stageC.timelineChecking'));
  await verifyTimeline(ctx, S, timing);

  // まとめ用ファクト
  const allMembers = allGroupResults.flatMap(g => g.members);
  report.fact('stageC.autoDistributed', false);
  report.fact('stageC.blockReward', split.blockRewardWei.toString());
  report.fact('stageC.totalPoints', split.totalPoints);
  report.fact('stageC.groupCount', allGroupResults.length);
  report.fact('stageC.playerCount', allMembers.length);
  report.fact('stageC.disqualifiedCount', allMembers.filter(m => m.isDisqualified).length);
  report.fact('stageC.resultCount', S.resultCount);
  report.fact('stageC.adoptedCount', S.adoptedByUid ? Object.keys(S.adoptedByUid).length : 0);
  report.fact('stageC.evidenceSubmissions', S.evidenceEvents.map(e => ({
    seq: e.seq, timestamp: e.timestamp, iso: isoOf(e.timestamp), txHash: e.txHash })));
  report.fact('stageC.chatWindow', S.chatWindow ?? null);
  report.fact('stageC.resultWindow', S.resultWindow ?? null);

  // G5 後段: manifest 保留分の確定（summaryMatch・group内容照合の結果が出そろった後）
  settleManifestParked(ctx, S);
  report.fact('stageC.anomalies', S.anomalies);

    ui.println(ui.t('stageC.completed', { anomalies: S.anomalies.length }));
    return { stop: false };
  } finally {
    if (S.evidenceSpool) {
      try {
        await S.evidenceSpool.cleanup();
      } catch (error) {
        const message = `Evidence spool cleanup failed: ${error?.message || error}`;
        S.anomalies.push(message);
        ui.warn(message);
      }
    }
  }
}

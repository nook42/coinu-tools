// src/recovery/app.js — 復元クライアント UI エントリ（esbuild でバンドル・ブラウザ専用）
//
// フロー: ウォレット接続(EIP-6963) → uid特定 → ブロック番号 → 署名して鍵導出 → ロスター/フェーズ →
//         リレー起動 → (waiting 開始待機 / chatting チャット・投票・密告・受領証明 / submitting 提出) 。
// v3.2: タブー全廃。鍵は signKey（全署名・永遠に非公開）＋ encryptKey（投票/密告の自己暗号化・
// 提出時公開）。チャット/投票/密告の正典条件 = 「本人signKey署名 ∧ 他メンバー受領証明≥1件」。
// 受信側は既読受領証明（msgKeyバッチ）・action受領証明を自動発行してグループ全員へブロードキャスト。
// 各フェーズの操作は正典 byte-exact モジュール（identity/relay-client/bundle/submit）に委譲。
// UI は本体 /game ページ（src/pages/game.js + Game.module.css）を忠実に移植したダークテーマ。

import '../common/buffer-polyfill.js'; // eciesjs が要求するグローバル Buffer（最初に import）
import { DEFAULTS, loadConfig, saveConfig } from '../../config.js';
import { t, pickLang, SUPPORTED_LANGS } from '../common/i18n.js';
import { EVIDENCE_ABI, makeR4Client, makeTimeReadClient, makeRecoveryAgreementState, getWalletTransportIfMainnet, readGameTimelineMs, readTimingConstants, derivePhase, readPressChatWindowsMs } from '../common/chain.js';
import { comparePressWindows, pressPromptFor, pressDecisionFor } from '../../vendor/src/utils/windowCompare.js';
import { createClientClock } from '../../vendor/src/utils/clientClock.js';
import { selectChainClockReading, advanceChainClockAlert, classifyChainClockDeviation,
  detectClockStep, parseUserCorrectionMs, planReadReceiptReissues, classifyFutureClockWarning,
  advanceFutureClockWarning, INITIAL_FUTURE_CLOCK_WARNING, futureClockWarningBypassesCooldown,
  ownClockVoteDeadline,
  nextReadReceiptTimestamp, countRepeatedReissueGroups, VOTE_RECEIPT_CUTOFF_MS,
  canIssueActionReceiptBeforeVoteCutoff, CHAIN_CLOCK_ENTRY_RECHECK_MS } from '../../vendor/src/utils/chainClock.js';
import { fetchBounded } from '../common/bounded-fetch.js';
import { discoverProviders, connectProvider, ensureMainnet, makeSigner, makeWalletClient } from './wallet.js';
import { discoverUidCandidates, fetchRoster, detectGameHeld, pollRecoveryRosterAtStart, finalRosterHashMatches, readCanonicalRosterEvidence } from './discovery.js';
import { formatRosterIntegrityWarning, formatLateRosterWarning } from './roster-warning.js';
import { deriveBlockIdentity, deriveP2PKeys, canStartRecoveryP2P } from './identity.js';
import * as blockKeyTools from '../../vendor/src/utils/walletTools.js';
import { RecoveryRelay, getRelayList, saveRelayList, readLiveSnapshot, LIVE_SNAPSHOT_POLL_MS,
  priorRecoveryStorageBlocks, clearFinalizedRecoveryBlockKeys } from './relay-client.js';
import { makeVerifyRelayInner } from './relay-verify.js';
import { parseOfficialStorage } from './import-local-storage.js';
import { receiptIdentityDigest, saveConfirmedChatWindow, loadConfirmedChatWindow, coordinateSelfReadReceiptBatch, readReceiptChainTime, ReceiptClaimMemo, OTHER_READ_RECEIPT_PENDING_EXPIRES, RECEIPT_PENDING_TTL_MS } from '../../vendor/src/utils/relay.js';
import { ReceiptWarnings, soleRemainingReportTarget, estimatePartialReadReissues, reissueGroupKey, suspiciousReportingUids, showReportingRecommendation } from '../../vendor/src/utils/receipt-warnings.js';
import { playerNumberOf, pointedTemplateText, pointedTemplateParts } from '../../vendor/src/utils/playerNumber.js';
import { buildSubmissionBundle } from './bundle.js';
import {
  submitResultOnChain,
  describeTrimPlan,
  planOnChainTrim,
  signTrimmedPayload,
  EVIDENCE_MAX_DATA_BYTES,
  saveRecoveryRosterProof, loadRecoveryRosterProof, findSavedRecoveryProofs,
  isRecoveryRosterProofPersistent, saveRecoveryEvidencePayload,
  isRecoveryEvidencePayloadPersistent, loadRecoveryEvidencePayload, loadRecoveryEvidencePayloadWindow,
} from './submit.js';
import {
  chatSignStringV2, actionSignStringV2, actionHashV2,
  receiptSignString, readReceiptSignString, computeMsgKeyV2, msgRefOf, computeChatHashV2,
  isReceiptTimely, RECEIPT_FRESH_WINDOW_MS, IDLE_TIMEOUT_MS, presenceSignStringV2,
  isMsgRef, isActionHash, buildReceiptMaps, chatWindowMsFromTimeline,
  buildMsgKeyGetter, canonicalComparatorV2, dedupAndSortV2,
  canonicalizeSignature, compareHexAsc, MAX_OBSERVED_ACTIONS_PER_ACTOR,
  buildRealTargets, receiptMaxRefsPerReceipt,
} from '../../vendor/src/utils/protocol.js';
import { encryptAction, decryptAction, encryptReportDeterministic } from '../../vendor/src/utils/ecies.js';
import {
  countHalfWidthChars, countVisibleChars, countMessageTurns, filterVisibleMessages,
  // 🔴 P-2026-0844（2026-08-09・ラウンド22）: 送信ゲートと「画面 ≡ 採点」のための正典述語。
  //    写しを作らず正典から import する（`hasVisibleContent` は relay-client.js が J-17 で
  //    既に使っているものと同一）。
  hasVisibleContent, applyChatCaps, capMessagesForScoring, normalizeChatCaps, GUEST_PINNED_RULES,
} from '../../vendor/workers/game_workers/lib/char-counter.js';
import { calculateDepositPoints } from '../../vendor/workers/game_workers/lib/game-result-calculator.js';
import { LOCK_POINTS_REREAD_MS, createLockPointsCache, verifyRecoveryLockPoints, summaryDeclaredWei, recoveryLockPointView } from './lock-points.js';
import { READ_RECEIPT_BATCH_MS } from '../../vendor/src/utils/read-receipt-batching.js';
import { openReadReceiptPause, readReceiptTickGap } from '../../vendor/src/utils/read-receipt-pause.js';
import { privateKeyToAccount } from 'viem/accounts';
import { publicActions, verifyMessage } from 'viem';
import { compactPayloadToBytes, decodeSubmissionPayloadString, isEvidenceCompactPayload } from '../../vendor/workers/game_workers/lib/evidence-compact-v1.js';
import { priorityTurnGuarantee } from '../../vendor/workers/game_workers/lib/priority-fields.js';
import { summarizeOwnSubmission, describeSubmissionGuarantee, makeDryRunSigner, dryRunSubmittedAt, onChainDryRunSubmittedAt, trimPlanDropsSelfAggregate, makeOnChainRecord, writeOnChainRecord, readOnChainRecord, payloadForAcceptedTx, createGuaranteeScheduler, createSummaryCache, submissionPayloadSha256 } from '../../vendor/src/utils/submissionGuarantee.js';
import { priorityReady, planPriority, shownTurnCount, EMPTY_PRIORITY_PLAN, planReceiptSignatures, separatorPoint, displayHiddenMessageKeys, priorityLockStorageKey, priorityLockFromPlan, verifyPriorityLock, memorylessCandidateTurns } from '../../vendor/src/utils/priorityEvidence.js';
import { shouldIssueReceiptForObservedAction } from '../../vendor/workers/game_workers/lib/protocol-v2.js';
import { clientScoreableMessages, clientReceiptableMessages, clientReceiptCapExcluded, admitReadReceiptsByArrival, PartialReadReceiptTracker, PARTIAL_READ_RECEIPT_ALERT_THRESHOLD, mergeActionReceiptSources, clientChatSourcedReceipts, clientReadReceiptAdmission, CHAT_WINDOW_CLOCK_SKEW_MS } from '../../vendor/workers/game_workers/lib/protocol-v2.js';
import { REPORT_GROUNDS_KEY, collectReportGround, mergeReportGrounds, mergeReportGroundMaps, loadReportGrounds, sameDeviceBandReasons } from '../../vendor/src/utils/reportGround.js';
import { checkTrimGuarantee, formatTrimGuaranteeWarning } from '../../vendor/src/utils/trimGuaranteeCheck.js';

// compositionend の直後に届く Enter を「変換確定キー」とみなして無視する猶予（ms）。
// Safari 等は compositionend → keydown の順で出るため、この窓が無いと確定 Enter で送信される。
// 人間が確定してから送信のため押し直す間隔より十分短くする。
const IME_COMMIT_GUARD_MS = 100;

// 「アクティブ」とみなす直近活動の窓（ms）。v3.3追補で在席仕様（10分間操作なし＝away）と統一。
// 明示の在席通知（P2P presence）が届かない相手は、直近の発信/受領証明の観測で近似する。
const ACTIVITY_WINDOW_MS = IDLE_TIMEOUT_MS;
const recoveryClock = createClientClock('recoveryClockCorrection_v1');
const clientNow = recoveryClock.clientNow;

const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...kids) => { const e = document.createElement(tag); Object.assign(e, props); for (const k of kids) e.append(k); return e; };

const state = {
  cfg: loadConfig(),
  lang: null,
  tr: null,
  provider: null,
  address: null,
  uid: null,
  blockNum: null,
  identity: null,   // { signKey, encryptKey, blockAddress, bAddr }
  keys: null,       // { nostrSk, nostrPubkey, tag }
  members: null,
  groupId: null,
  timeline: null,
  chatEnded: false,
  timing: null,
  relay: null,
  _timeClient: null,
  _agreement: null,
  clockAlert: null,
  clockPendingCorrection: null,
  clockReissueSkip: null,
  clockDraft: '',
  clockPreviousOutside: null,
  clockConfirmedDeviationMs: null,
  clockCheckGeneration: 0,
  clockReading: null,
  clockStepVersion: 0,
  liveSnapshotUnread: false,
  liveSnapshotLastAttempt: 0,
  liveSnapshotPending: null,
  liveSubmittedSelf: false,
  readReceiptPause: null,
  rosterAnchorHash: null,
  rosterProof: null,
  rosterProofReady: false,
  evidenceSenderCount: null,
  evidenceSenderCountWallet: null,
  evidenceSenderCountBlockNum: null,
  rosterPaused: false,
  rosterInvalid: false,
  rosterCheckCount: 0,
  verifiedRosters: new Map(),
  rosterWaitCancelled: false,
  rosterLateCount: 0,
  lockPoints: null,
  lockPointsCache: null,
  _lockPtsTimer: null,
  // ローカル行動（ACK非依存・one-shot）
  myVote: null,     // {encrypted, signature, timestamp}
  myVotePrev: [],   // v3.3: void後再送で退避した旧投票発信の履歴（提出時の受領済み選択用）
  myReports: [],    // [{encrypted, signature, timestamp}]（再送含む全発信）
  reportGrounds: {}, // S3R5-U-R13-SELF: 密告の署名 → 根拠（標的の投票＋自分と標的以外の受領証明）
  reportGroundSaveFailed: false,
  intent: { vote: null, reports: [] }, // A-3 自己検証用の平文記録（自セッション発のみ）
  draft: { chat: '' }, // 再描画で消えない入力途中テキスト
  pendingVoteTarget: null, // 投票前の表示確認だけ
  pendingVoteWarningKey: null,
  pendingReportWarningTarget: null,
  voteWarningAccepted: false,
  reportWarningAccepted: false,
  voteDeadlineNoticeOpen: false,
  voteDeadlineEntryPending: true,
  // v3.2: 観測データ（提出物 observed セクション＋既読UXの材料）
  observedActions: { votes: {}, reports: {} }, // リレー観測（自分の発信含む・getRelayActionsRaw 形）
  importedActions: { votes: {}, reports: {} },
  receipts: {},     // digest -> receipt（既読バッチ＋action受領・全チャネルunion）
  readReceiptTracker: new PartialReadReceiptTracker(),
  readReceiptAlerts: {},
  receiptWarnings: new ReceiptWarnings(null),
  g3Reports: new Map(),
  g3Identity: null,
  warningTargetCache: null,
  otherSessionReadReceipt: false,
  clockWarning: INITIAL_FUTURE_CLOCK_WARNING,
  sessionEntryAt: null,
  awayIntervals: [],
  ownSessionSignatures: new Set(),
  tabEnded: false,
  ownSessionReadSignatures: new Set(),
  issuedReadMsgKeys: new Set(),   // 発行済みの `${senderUid}|${msgRef}`
  issuedActionHashes: new Set(),  // 自分がaction受領証明を発行済みのactionHash
  issuedActionReceiptBuckets: new Map(), // actionHash -> `${actorUid}|${type}`
  actionReceiptGrace: null,
  // P2P で観測した自己アクション（別クライアント=game.js等が発信済み）。intent は付けない
  // （平文を知らない＝A-3自己検証をスキップさせる）。観測が入ったら該当種別のローカル入力はロック。
  observedP2P: { vote: false, report: false },
  // v3.3追補（在席）: 自分のaway状態と最終操作時刻／他メンバーの明示在席通知
  away: false,
  lastActivityAt: Date.now(),
  peerPresence: {}, // uid -> 'active' | 'away'（P2P presence 由来。未通知は活動観測で近似）
};
state.lang = pickLang(state.cfg.lang);
state.tr = t(state.lang);

function noteG3VerifiedReport(inner) {
  if (inner?.actionType !== 'report' || !inner.uid || inner.uid === state.uid || !inner.encrypted) return false;
  let reports = state.g3Reports.get(inner.uid);
  if (!reports) { reports = new Set(); state.g3Reports.set(inner.uid, reports); }
  if (reports.has(inner.encrypted) || reports.size >= 10) return false;
  reports.add(inner.encrypted);
  return true;
}

function reportWarningName(name) {
  if (typeof name !== 'string') return '';
  let width = 0;
  for (let i = 0; i < name.length; i++) width += /[^\x01-\x7E\xA1-\xDF]/.test(name[i]) ? 2 : 1;
  if (width <= 20) return name;
  let shortened = '';
  width = 0;
  for (let i = 0; i < name.length; i++) {
    const char = name[i];
    const charWidth = /[^\x01-\x7E\xA1-\xDF]/.test(char) ? 2 : 1;
    if (width + charWidth > 18) break;
    shortened += char;
    width += charWidth;
  }
  return `${shortened}..`;
}

async function freshRecoveryClockReading() {
  const cached = state.clockReading;
  const monoNow = performance.now();
  const wallNow = Date.now();
  if (cached && Number.isFinite(cached.timeMs) && cached.stepVersion === state.clockStepVersion
      && monoNow >= cached.monoMs && monoNow - cached.monoMs <= 60000
      && wallNow >= cached.wallMs && wallNow - cached.wallMs <= 60000) {
    return { ...cached, timeMs: cached.timeMs + monoNow - cached.monoMs };
  }
  if (!state._timeClient) return null;
  const startVersion = state.clockStepVersion;
  const expired = Symbol('expired');
  let timeout;
  try {
    const sources = await Promise.race([state._timeClient.readSamples(),
      new Promise((resolve) => { timeout = setTimeout(() => resolve(expired), 3000); })]);
    if (sources === expired || startVersion !== state.clockStepVersion) return null;
    const nowMonoMs = performance.now();
    const reading = selectChainClockReading({ ...sources, nowMonoMs });
    state.clockReading = { kind: reading.kind, timeMs: reading.timeMs, monoMs: nowMonoMs, wallMs: Date.now(),
      sourceIds: reading.sourceIds, stepVersion: state.clockStepVersion };
    return Number.isFinite(reading.timeMs) ? state.clockReading : null;
  } catch { return null; }
  finally { clearTimeout(timeout); }
}

const futureClockRead = { inFlight: null, lastMono: -Infinity, lastWall: -Infinity };
function readFutureLockClock() {
  const cached = state.clockReading;
  const monoNow = performance.now();
  const wallNow = Date.now();
  if (cached && Number.isFinite(cached.timeMs) && cached.stepVersion === state.clockStepVersion
      && monoNow >= cached.monoMs && monoNow - cached.monoMs <= 60000
      && wallNow >= cached.wallMs && wallNow - cached.wallMs <= 60000) {
    return { ...cached, timeMs: cached.timeMs + monoNow - cached.monoMs };
  }
  if (futureClockRead.inFlight) return futureClockRead.inFlight;
  if (monoNow - futureClockRead.lastMono < 60000 && wallNow - futureClockRead.lastWall < 60000) return null;
  futureClockRead.lastMono = monoNow;
  futureClockRead.lastWall = wallNow;
  futureClockRead.inFlight = freshRecoveryClockReading().finally(() => { futureClockRead.inFlight = null; });
  return futureClockRead.inFlight;
}

function receiptIssuanceBlocked() {
  return state.away || state.otherSessionReadReceipt || state.tabEnded;
}

function continueRecoveryClockWarning() {
  const next = advanceFutureClockWarning(state.clockWarning, { type: 'continue' });
  if (next === state.clockWarning) return false;
  state.clockWarning = next;
  renderGame();
  return true;
}

function considerRecoveryFuture(type, item) {
  if (['submitting', 'completed'].includes(currentPhase()) || state.tabEnded || state.clockWarning.warning) return;
  const identity = state.receiptWarningIdentity;
  const applyReading = (reading) => {
    if (['submitting', 'completed'].includes(currentPhase()) || state.tabEnded || state.clockWarning.warning
        || identity !== state.receiptWarningIdentity) return;
    const next = advanceFutureClockWarning(state.clockWarning, { type: 'discard', reading,
      clientTimeMs: clientNow(), itemTimestampMs: item?.timestamp, skewMs: CHAT_WINDOW_CLOCK_SKEW_MS });
    if (next === state.clockWarning) return;
    state.clockWarning = next;
    renderGame();
  };
  const reading = readFutureLockClock();
  if (reading && typeof reading.then === 'function') void reading.then(applyReading, () => {});
  else applyReading(reading);
}

async function refreshRecoveryClockWarning() {
  try {
    const eligible = () => currentPhase() === 'chatting' && !state.tabEnded && !!state.members
      && !state.rosterPaused && !state.rosterInvalid;
    if (!eligible()) return;
    const identity = state.receiptWarningIdentity;
    const reading = await readFutureLockClock();
    if (!eligible() || identity !== state.receiptWarningIdentity) return;
    const next = advanceFutureClockWarning(state.clockWarning,
      { type: 'tick', reading, clientTimeMs: clientNow(), skewMs: CHAT_WINDOW_CLOCK_SKEW_MS });
    if (next === state.clockWarning) return;
    state.clockWarning = next;
    renderGame();
  } catch (error) { log(`clock warning refresh failed: ${error.message}`); }
}

async function checkClock(context) {
  if (!state._timeClient || state.clockAlert || state.tabEnded
      || recoveryClock.correctionCooldownMs() > 0 || recoveryClock.hasAdoptedClock(state.blockNum)) return;
  const generation = ++state.clockCheckGeneration;
  const startingStep = state.clockStepVersion;
  let sources;
  try { sources = await state._timeClient.readSamples(); }
  catch { sources = { walletSample: null, publicSamples: [] }; }
  if (generation !== state.clockCheckGeneration || startingStep !== state.clockStepVersion
      || state.clockAlert || state.tabEnded
      || recoveryClock.correctionCooldownMs() > 0 || recoveryClock.hasAdoptedClock(state.blockNum)) return;
  let reading;
  try {
    const nowMonoMs = performance.now();
    reading = selectChainClockReading({ ...sources, nowMonoMs });
    state.clockReading = { kind: reading.kind, timeMs: reading.timeMs, monoMs: nowMonoMs, wallMs: Date.now(),
      sourceIds: reading.sourceIds, stepVersion: state.clockStepVersion };
  }
  catch (error) { log(`clock reading failed: ${error.message}`); return; }
  const result = advanceChainClockAlert({ reading, wallNowMs: Date.now(),
    correctionMs: recoveryClock.getClockCorrection(), monoNowMs: performance.now(), context,
    previousOutside: state.clockPreviousOutside,
    confirmedDeviationMs: state.clockConfirmedDeviationMs });
  state.clockPreviousOutside = result.nextOutside;
  if (result.kind === 'warning' || result.kind === 'confirmation') {
    state.clockReading = null;
    state.clockAlert = { kind: result.kind, deviationMs: result.deviationMs };
    state.clockDraft = '';
    renderClockModal();
  } else if (result.kind === 'pending' && context !== 'game') {
    const scheduledBlockNum = state.blockNum;
    const scheduledUid = state.uid;
    setTimeout(() => {
      if (state.blockNum === scheduledBlockNum && state.uid === scheduledUid) void checkClock(context);
    }, CHAIN_CLOCK_ENTRY_RECHECK_MS);
  }
}

function parseRecoveryCorrectionSeconds(input) {
  if (typeof input !== 'string') {
    throw new TypeError('correction must be integer seconds');
  }
  const trimmed = input.trim();
  if (!/^[+＋\-−－ーｰ‐‑‒–—―0-9０-９]+$/u.test(trimmed)) {
    throw new TypeError('correction must be integer seconds');
  }
  const normalized = trimmed.normalize('NFKC').replace(/[−－ーｰ‐‑‒–—―]/gu, '-').replace(/＋/gu, '+');
  if (!/^[+-]?[0-9]+$/.test(normalized)) throw new TypeError('correction must be integer seconds');
  return parseUserCorrectionMs(Number(normalized) * 1000);
}

function repeatedRecoveryReissues(deltaMs) {
  if (deltaMs >= 0 || !Number.isSafeInteger(state.timeline?.chatCloseAt))
    return { repeated: 0, partial: { before: 0, after: 0, alert: false, keys: [], groups: [] } };
  const key = `selfReadReceipts_v1_${state.blockNum}_group${state.groupId}_user${state.uid}`;
  let known = [];
  try {
    const stored = JSON.parse(localStorage.getItem(key) || '[]');
    if (Array.isArray(stored)) known = stored;
  } catch { /* Use memory when storage is unavailable. */ }
  const fromMemory = Object.values(state.receipts).filter((receipt) => receipt.receiverUid === state.uid);
  const receipts = known.length ? known : fromMemory;
  const messages = state.relay?.getMessages() || [];
  const messageTimestamps = new Map(messages.map((message) => [
    `${message.uid}|${msgRefOf(state.relay.getMsgKey(message))}`, message.timestamp,
  ]));
  const plans = planReadReceiptReissues({ receipts, shiftBackMs: -deltaMs,
    messageTimestamps, nowMs: clientNow() + deltaMs,
    chattingStartMs: state.timeline.chattingStart, chatCloseAtMs: state.timeline.chatCloseAt });
  const partial = estimatePartialReadReissues({ uid: state.uid, known, fromMemory, plans });
  partial.groups = plans.filter((plan) => partial.keys.includes(reissueGroupKey(plan)))
    .map(({ senderUid, msgRefs }) => ({ senderUid, msgRefs }));
  return { repeated: countRepeatedReissueGroups({ receipts: known, plans }), partial };
}

function recoveryPartialChats(partial) {
  const target = new Set(partial.groups.flatMap(({ senderUid, msgRefs }) =>
    msgRefs.map((ref) => `${senderUid}|${ref}`)));
  const listed = new Set();
  return (state.relay?.getMessages() || []).filter((message) => {
    const key = `${message.uid}|${msgRefOf(state.relay.getMsgKey(message))}`;
    if (!target.has(key) || listed.has(key)) return false;
    listed.add(key);
    return true;
  })
    .map((message) => {
      const name = memberName(state.members?.find((member) => member.uid === message.uid));
      const chars = Array.from(message.text || '');
      return { key: `${message.uid}|${msgRefOf(state.relay.getMsgKey(message))}`,
        label: `${name}: ${chars.slice(0, 40).join('')}${chars.length > 40 ? '…' : ''}` };
    });
}

async function acknowledgeClockCorrection(input, finalize = false, skipListed = false) {
  if (!state.clockAlert) return;
  if (finalize && !state.clockPendingCorrection) return;
  const deltaMs = finalize ? state.clockPendingCorrection?.deltaMs
    : input === null ? 0 : parseRecoveryCorrectionSeconds(input);
  if (deltaMs !== 0 && !state.clockWarning?.warning && recoveryClock.correctionCooldownMs() > 0) return;
  const nextMs = parseUserCorrectionMs(recoveryClock.getClockCorrection() + deltaMs);
  if (!finalize) {
    const generation = state.clockCheckGeneration;
    state.clockDraft = input || '';
    state.clockChecking = true;
    renderClockModal();
    const reading = await freshRecoveryClockReading();
    state.clockChecking = false;
    if (!state.clockAlert || generation !== state.clockCheckGeneration) return;
    const deviation = reading ? classifyChainClockDeviation(clientNow() + deltaMs, reading.timeMs) : null;
    const deviationMs = deviation?.deviationMs ?? null;
    const adoption = deviation?.outside ?? false;
    const reissues = repeatedRecoveryReissues(deltaMs);
    const repeated = reissues.repeated > 0;
    const partial = reissues.partial;
    if (partial.alert) partial.chats = recoveryPartialChats(partial);
    if (adoption || repeated) {
      state.clockPendingCorrection = { deltaMs, nextMs, adoption, repeated,
        deviationMs, sourceIds: reading?.sourceIds || [], partial, stage: 'review' };
      state.clockDraft = input || '';
      renderClockModal();
      return;
    }
    state.clockPendingCorrection = { deltaMs, nextMs, adoption, repeated, deviationMs,
      partial, stage: partial.alert ? 'partial' : null };
    if (partial.alert) { renderClockModal(); return; }
  }
  const review = state.clockPendingCorrection;
  if (finalize && review?.partial?.alert && review.stage !== 'partial') {
    review.stage = 'partial';
    renderClockModal();
    return;
  }
  const warningBefore = state.clockWarning;
  const alertDeviationMs = state.clockAlert?.deviationMs;
  const warningReading = warningBefore?.warning ? await freshRecoveryClockReading() : null;
  const bypassCooldown = !!warningBefore?.warning && futureClockWarningBypassesCooldown(warningBefore,
    warningReading, Date.now() + nextMs, CHAT_WINDOW_CLOCK_SKEW_MS);
  state.clockReissueSkip = skipListed ? new Set(review.partial.keys) : null;
  try { if (deltaMs !== 0) recoveryClock.setClockCorrection(nextMs, { bypassCooldown }); }
  finally { state.clockReissueSkip = null; }
  if (Number.isFinite(review?.deviationMs)) state.clockConfirmedDeviationMs = review.deviationMs;
  else if (Number.isFinite(alertDeviationMs)) {
    state.clockConfirmedDeviationMs = deltaMs === 0 ? alertDeviationMs : null;
  }
  if (state.clockWarning?.warning) {
    state.clockWarning = advanceFutureClockWarning(state.clockWarning,
      { type: 'corrected', reading: warningReading, clientTimeMs: Date.now() + nextMs });
  }
  if (review?.adoption) recoveryClock.markAdoptedClock(state.blockNum);
  state.clockAlert = null;
  state.clockPendingCorrection = null;
  state.clockDraft = '';
  state.clockPreviousOutside = null;
  state.clockCheckGeneration += 1;
  renderClockModal();
  if (warningBefore?.warning && state.members) renderGame();
}

async function openManualClockCorrection() {
  if (state.tabEnded || (!state.clockWarning?.warning && recoveryClock.correctionCooldownMs() > 0)) return;
  state.clockAlert = { kind: 'manual', deviationMs: null };
  state.clockCheckGeneration += 1;
  const generation = state.clockCheckGeneration;
  state.clockDraft = '';
  state.clockChecking = true;
  renderClockModal();
  const reading = await freshRecoveryClockReading();
  state.clockChecking = false;
  if (!state.clockAlert || generation !== state.clockCheckGeneration) return;
  state.clockAlert.deviationMs = reading
    ? classifyChainClockDeviation(clientNow(), reading.timeMs).deviationMs : null;
  renderClockModal();
}

function toggleRecoveryCorrectionSign(value) {
  const trimmed = value.trim();
  if (!trimmed) return '−';
  const sign = /^[+＋\-−－ーｰ‐‑‒–—―]/u.exec(trimmed)?.[0];
  if (!sign) return `−${trimmed}`;
  return `${/[+＋]/u.test(sign) ? '−' : '＋'}${trimmed.slice(sign.length)}`;
}

function closeClockCorrection() {
  state.clockAlert = null;
  state.clockPendingCorrection = null;
  state.clockDraft = '';
  state.clockPreviousOutside = null;
  state.clockCheckGeneration += 1;
  renderClockModal();
}

let correctionWork = Promise.resolve();
recoveryClock.subscribeClockCorrection((change) => {
  if (change.deltaMs > 0) state.relay?.refetchHistory(change);
  else if (change.deltaMs < 0) {
    const skip = state.clockReissueSkip;
    correctionWork = correctionWork.then(() =>
      reissueReadReceipts(-change.deltaMs, skip)).catch((error) => log(`read receipt reissue failed: ${error.message}`));
  }
  if (state.members) renderGame();
});

function isOtherSessionItem(item, ownerUid) {
  return !!state.uid && ownerUid === state.uid && typeof item?.signature === 'string'
    && Number.isSafeInteger(item.timestamp) && Number.isSafeInteger(state.sessionEntryAt)
    && item.timestamp > state.sessionEntryAt && !state.ownSessionSignatures.has(item.signature)
    && !state.awayIntervals.some(({ start, end }) => item.timestamp >= start && item.timestamp <= end);
}

function observeOtherSessionItem(item, ownerUid) {
  if (state.tabEnded || state.otherSessionReadReceipt || !isOtherSessionItem(item, ownerUid)) return;
  state.otherSessionReadReceipt = true;
  void publishPresence('away');
  renderGame();
}

function resumeOtherSession() {
  if (state.tabEnded || !state.otherSessionReadReceipt) return;
  state.sessionEntryAt = clientNow();
  state.awayIntervals = [];
  state.otherSessionReadReceipt = false;
  if (!receiptIssuanceBlocked()) void publishPresence('active');
  renderGame();
}

function endThisTab() {
  if (state.tabEnded) return;
  state.tabEnded = true;
  state.clockAlert = null;
  state.clockPendingCorrection = null;
  state.relay?.stop();
  state.relay = null;
  for (const key of ['_rrTimer', '_liveTimer', '_tlTimer', '_phTimer', '_secTimer', '_awayTimer', '_voidTimer', '_dbgTimer', '_senderCountTimer', '_clockTimer', '_lockPtsTimer']) {
    clearInterval(state[key]);
    state[key] = null;
  }
  renderGame();
}

function reopenReadReceiptPause() {
  const pause = state.readReceiptPause;
  if (!pause) return;
  const now = performance.now();
  const wallNow = Date.now();
  state.readReceiptPause = openReadReceiptPause(pause, now,
    readReceiptTickGap(pause, now, wallNow), wallNow);
}

function log(msg) { const box = $('log'); if (box) { box.textContent = `${msg}\n${box.textContent}`.slice(0, 4000); } }

function showRosterIntegrityWarning(message) {
  const box = $('roster-integrity-warning');
  if (!box) return;
  box.textContent = message;
  box.style.display = 'block';
}
function clearProvisionalRosterWarning() {
  const box = $('roster-integrity-warning');
  if (!box) return;
  const waiting = [state.tr('recovery.warn.rosterProvisional'), state.tr('recovery.warn.rosterPending')];
  const lines = box.textContent.split('\n').filter((line) => !waiting.includes(line));
  box.textContent = lines.join('\n');
  box.style.display = lines.length ? 'block' : 'none';
}
function warnLateRoster(lateCount) {
  if (!(lateCount > 0)) return;
  const message = formatLateRosterWarning(lateCount, state.tr);
  const box = $('roster-integrity-warning');
  if (!box?.textContent?.includes(message)) {
    showRosterIntegrityWarning(box?.textContent ? `${box.textContent}\n${message}` : message);
  }
  if (lateCount > state.rosterLateCount) {
    state.rosterLateCount = lateCount;
    log(message);
  }
}

function rosterReady() { return !state.rosterPaused && !state.rosterInvalid
  && state.rosterCheckCount === 0 && !!state.rosterAnchorHash
  && state.rosterProofReady === true; }

async function refreshEvidenceSenderCount() {
  if (!state._client || !state.address || state.blockNum == null) return;
  const walletAddress = state.address;
  const blockNum = state.blockNum;
  try {
    state.evidenceSenderCount = Number(await state._client.readContract({
      address: state.cfg.contracts.evidence, abi: EVIDENCE_ABI,
      functionName: 'resultCountOf', args: [BigInt(blockNum), walletAddress],
    }));
    state.evidenceSenderCountWallet = walletAddress;
    state.evidenceSenderCountBlockNum = Number(blockNum);
    renderGame();
  } catch {}
}
function stopForChangedRoster() {
  state.rosterPaused = true;
  state.rosterInvalid = true;
  state.relay?.stop();
  const message = state.tr('recovery.warn.rosterChanged');
  showRosterIntegrityWarning(message);
  log(message);
  renderGame();

}

function rosterFetchOptions(client = state._client) {
  return {
    client, contracts: state.cfg.contracts,
    maxPlayers: state.cfg.pins.gameMaxPlayers,
    confirmationBlocks: state.cfg.pins.confirmationBlocks,
    onWarning: (warning) => {
      if (warning?.code === 'applicantHashRegistrationCount') {
        log(`⚠ ${state.tr('recovery.warn.applicantHashRegistrationCount', {
          registrationCount: warning.registrationCount,
        })}`);
      }
    },
  };
}
function fetchCurrentRoster() {
  return fetchRoster(state.cfg.r2Base, state.blockNum, state.uid, rosterFetchOptions());
}
async function rebuildRecoveryRosterProof(blockNum = state.blockNum, uid = state.uid,
  walletAddress = state.address, client = state._client) {
  const roster = await fetchRoster(state.cfg.r2Base, blockNum, uid, rosterFetchOptions(client));
  if (!roster?.rosterProof || !roster.rosterAnchorHash
      || roster.rosterProof.C?.toLowerCase() !== roster.rosterAnchorHash.toLowerCase()
      || roster.rosterProof.walletAddress?.toLowerCase() !== walletAddress?.toLowerCase()) return false;
  return saveRecoveryRosterProof({ ...roster.rosterProof,
    chainId: Number(await client.getChainId()),
    evidenceAddress: state.cfg.contracts.evidence });
}
async function waitForFinalRoster(ignoreCancel = false) {
  let lastStatus = null;
  return pollRecoveryRosterAtStart(async () => {
    state.timeline = await readGameTimelineMs(state._client, state.cfg.contracts.evidence, state.blockNum);
    const anchor = await readCanonicalRosterEvidence(state._client, state.cfg.contracts, state.blockNum);
    warnLateRoster(anchor.lateCount);
    if (Number.isFinite(anchor.chattingStartMs)
        && anchor.chattingStartMs !== state.timeline.chattingStart) return anchor;
    // 組を選ぶ前だけ R2 bytes を検証する。同じ hash は開始境界でも再読しない。
    if (anchor.rosterAnchorHash && !state.rosterAnchorHash) {
      const key = `${state.blockNum}:${state.uid}:${anchor.rosterAnchorHash.toLowerCase()}`;
      if (!state.verifiedRosters.has(key)) {
        let roster;
        try { roster = await fetchCurrentRoster(); }
        catch (error) {
          if (error?.warningKey || [
            'recomputed_roster_anchor_mismatch', 'roster_reconstruction_unavailable',
          ].includes(error?.code)) throw error;
          const retry = new Error(error?.message || String(error));
          retry.rosterReconstructionRetry = true;
          throw retry;
        }
        if (roster.rosterAnchorHash?.toLowerCase() !== anchor.rosterAnchorHash.toLowerCase()) {
          const retry = new Error('roster anchor changed during reconstruction');
          retry.rosterReconstructionRetry = true;
          throw retry;
        }
        state.verifiedRosters.set(key, roster);
      }
      return { ...state.verifiedRosters.get(key), ...anchor };
    }
    return anchor;
  }, () => state.timeline?.chattingStart, {
    getChatCloseAtMs: submissionChatCloseAt,
    shouldContinue: () => !state.rosterInvalid && (ignoreCancel || !state.rosterWaitCancelled),
    onObservation: (result) => {
      const status = result?.rosterAnchorStatus || 'unavailable';
      if (status === lastStatus) return;
      lastStatus = status;
      if (status === 'provisional') {
        const message = state.tr('recovery.warn.rosterProvisional');
        showRosterIntegrityWarning(message);
        log(message);
      } else if (status === 'none') {
        const message = state.tr('recovery.warn.rosterPending');
        showRosterIntegrityWarning(message);
        log(message);
      } else if (status === 'unavailable') { log('roster read unavailable; retrying (details are in the browser console)'); console.warn('[recovery] roster read unavailable:', result?.reason); }
    },
  });
}

function showPersistenceWarning(detail = '') {
  const box = $('persistence-warning');
  const message = state.tr('recovery.persistenceFailure');
  if (box) {
    box.textContent = detail ? `${message} (${detail})` : message;
    box.style.display = 'block';
  }
  log(detail ? `${message} (${detail})` : message);
}
function showVolatileRescueWarning() {
  const box = $('persistence-warning');
  const message = state.tr('recovery.persistenceVolatile');
  if (box) { box.textContent = message; box.style.display = 'block'; }
  log(message);
}

// 復元クライアントには Next.js の NEXT_PUBLIC_* env が無い。チェーン検証に使う
// config の TokenMining アドレスを、同じ walletTools モジュールを使う identity.js へ渡す。
// vendor 同期前の旧 walletTools でアドレス無しの鍵を黙って導出しないよう fail-closed にする。
export function configureRecoveryBlockKeyDomain(tokenMiningAddress, tools = blockKeyTools) {
  if (typeof tools?.setBlockKeyTokenMiningAddress !== 'function') {
    throw new Error('walletTools vendor sync is required for TokenMining key-domain separation');
  }
  tools.setBlockKeyTokenMiningAddress(tokenMiningAddress);
}

// --- ウォレット（モーダルで選択） ---
async function connectWallet() {
  const box = $('wallet-options');
  const modal = $('wallet-modal');
  if (!box || !modal) {
    // 古いHTMLがキャッシュされている（新バンドル×旧HTML）。ハードリロードを促す。
    log('ページが古いです。ハードリロード（Cmd+Shift+R）してください / stale page — hard-reload');
    return;
  }
  const providers = await discoverProviders();
  box.innerHTML = '';
  if (!providers.length) {
    box.append(el('div', { className: 'muted', textContent: state.tr('recovery.noWallet') }));
  } else {
    for (const p of providers) {
      const b = el('button', { className: 'walletOpt', onclick: () => selectWallet(p) });
      if (p.info?.icon) b.append(el('img', { className: 'walletIcon', src: p.info.icon, alt: '' }));
      b.append(el('span', { textContent: p.info?.name || 'Wallet' }));
      box.append(b);
    }
  }
  $('wallet-modal').style.display = 'flex';
}

function closeWalletModal() { $('wallet-modal').style.display = 'none'; }

async function selectWallet(p) {
  try {
    state.provider = p.provider;
    const { address, chainId } = await connectProvider(p.provider);
    state.address = address;
    if (chainId !== 1) { const ok = await ensureMainnet(p.provider); if (!ok) log('please switch wallet to mainnet'); }
    $('wallet-status').textContent = address;
    log(`connected ${address} (${p.info?.name || 'wallet'})`);
    closeWalletModal();
    if (state._agreement) await rebuildRecoveryChainClients();
    // 接続完了 → 接続ボタンを消してアドレス表示＋ブロック番号入力へ
    $('step-connect').style.display = 'none';
    $('wallet-display').style.display = '';
    if (!(state.identity && state.blockNum != null && state.uid != null)
      && !($('derive-btn')?.disabled && recoveryGuaranteePressing === 0)) {
      $('step-block').style.display = '';
      $('discover-btn').disabled = $('block-input').value.trim() === '';
      $('block-input').focus();
    }
  } catch (e) { log(`connect failed: ${e.message}`); }
}

// --- uid 特定 ---
let discovering = false;
async function discoverUid() {
  if (recoveryGuaranteePressing > 0) { log('submission in progress — try again after it finishes'); return; }
  if ($('derive-btn')?.disabled && recoveryGuaranteePressing === 0) { log('submission in progress — try again after it finishes'); return; }
  if (!state.address) { log('connect wallet first'); return; }
  if (discovering) { log('uid discovery already running…'); return; }
  const raw = $('block-input').value.trim();
  if (raw === '') { log('enter block number'); return; } // 空欄は不可（ブロック0での誤動作防止）
  const blockNum = Number(raw);
  if (!Number.isInteger(blockNum) || blockNum < 0) { log('invalid block number'); return; }
  state.blockNum = blockNum;
  discovering = true;
  try {
    const held = await detectGameHeld({ r2Base: state.cfg.r2Base, blockNum });
    log(`game held: ${held.held} (${held.reason})`);
    log('searching uid by registered withdrawal address…');
    const cands = await discoverUidCandidates({
      r2Base: state.cfg.r2Base, blockNum, walletAddress: state.address,
    });
    if (!cands.length) { log('no uid found for this wallet at this block'); return; }
    const sel = $('uid-select'); sel.innerHTML = '';
    // uid は必ず併記する。1つの引き出しアドレスを複数プレイヤーが共有し、かつ表示名が
    // 同一（X の表示名は重複可）だと、name だけでは候補を区別できず選びようがなくなる。
    for (const c of cands) sel.append(el('option', { value: c.uid, textContent: typeof c.name === 'string' && c.name && c.name.length <= 256 ? `${c.name} — ${c.uid} (${c.source})` : `${c.uid} (${c.source})` }));
    // 検索成功 → ブロック入力/検索ボタンを消してユーザー選択＋署名へ
    $('step-block').style.display = 'none';
    $('step-uid').style.display = '';
    log(`found ${cands.length} uid candidate(s) — select and Sign & load`);
  } catch (e) {
    log(`uid discovery failed: ${e.message}`);
  } finally {
    discovering = false;
  }
}

// 保存済みの提出バンドルと開始時の proof があれば、R2 の停止・ページ再読込後も送る。
let recoveryGuaranteePressing = 0;
let recoveryDeriving = false;
function syncRecoverySubmitButtons() {
  const deriveButton = $('derive-btn');
  if (deriveButton) deriveButton.disabled = recoveryGuaranteePressing > 0 || recoveryDeriving;
  const discoverButton = $('discover-btn');
  const blockInput = $('block-input');
  if (discoverButton) discoverButton.disabled = recoveryGuaranteePressing > 0 || !blockInput || blockInput.value.trim() === '';
  const rescueButton = $('saved-rescue-btn');
  if (rescueButton) rescueButton.disabled = recoveryGuaranteePressing > 0;
  const submitButton = document.querySelector('#game-area .submitButton');
  if (submitButton) submitButton.disabled = recoveryGuaranteePressing > 0
    || state.evidenceSenderCount >= 3 || !!state.onchainTxHash;
}
// 保存済みの控えも上限以上なら切り詰めて署名し直す。null は送信をやめる。
async function recoverySavedRescueTrim({ payload, blockNum, uid, walletAddress, chatWindow, sameGame, signMessage }) {
  const plan = await planOnChainTrim(payload, uid, { chatWindow });
  if (!plan) return payload;
  if (plan.impossible) {
    log(state.tr('recovery.trimImpossible'));
    const topUids = (plan.oversizeUids || []).slice(0, 3);
    if (topUids.length) log(state.tr('recovery.trimImpossibleContributors', { uids: topUids.join(', ') }));
    return null;
  }
  let decoded = null;
  try { decoded = decodeSubmissionPayloadString(payload); } catch { decoded = null; }
  let trimCheck = { status: 'failed', reason: sameGame ? 'error' : 'no-roster' };
  if (sameGame) {
    try {
      trimCheck = await checkTrimGuarantee(payload, plan, {
        blockNum, groupId: decoded?.groupId, myUid: uid, members: state.members || [], chatWindow,
      });
    } catch { trimCheck = { status: 'failed', reason: 'error' }; }
  }
  const lines = describeTrimPlan(plan);
  const wsAcked = sameGame && (state.submittedUids || []).some((memberUid) => String(memberUid) === String(uid));
  const essentialWarning = trimCheck.status !== 'ok' && plan.essentialEvidenceDropped
    ? `\n\n${state.tr('recovery.trimEssentialUnionWarning')}`
      + `\n${state.tr('recovery.trimEssentialOverrideWarning')}`
      + (wsAcked ? `\n${state.tr('recovery.trimEssentialCancelRecommended')}` : '')
    : '';
  const guarantee = Number.isSafeInteger(plan.gBefore) && plan.gBefore > 0
    ? `\n${state.tr('recovery.trimGuarantee', { gBefore: plan.gBefore, gAfter: plan.gAfter })}`
    : '';
  const trimLossWarning = formatTrimGuaranteeWarning(trimCheck, {
    translate: (key, params) => state.tr(key, params), prefix: 'recovery.',
    resolveName: (memberUid) => memberName((state.members || []).find((member) => member.uid === memberUid) || { uid: memberUid }),
    serverSubmitted: sameGame && state.liveSubmittedSelf === true,
    separator: state.tr('recovery.submit.guarantee.nameSeparator'),
  });
  const ok = window.confirm(`${state.tr('recovery.trimNotice')}\n\n${lines}${guarantee}\n\n`
    + `${Math.round(plan.beforeBytes / 1024)}KB → ${Math.round(plan.afterBytes / 1024)}KB `
    + `(max ${Math.round(EVIDENCE_MAX_DATA_BYTES / 1024)}KB)`
    + trimLossWarning
    + essentialWarning);
  if (!ok) return null;
  return signTrimmedPayload(plan.trimmedBundle, {
    blockNum, signMessage, compactContext: plan.compactContext,
    originalEncryptedDataHash: plan.originalEncryptedDataHash,
  });
}
async function rescueSavedSubmission() {
  const button = $('saved-rescue-btn');
  if (button?.disabled || recoveryGuaranteePressing > 0
    || ($('derive-btn')?.disabled && recoveryGuaranteePressing === 0)
    || !state.provider || !state.address) return;
  const raw = $('block-input')?.value.trim();
  const blockNum = Number(raw);
  if (raw === '' || !Number.isSafeInteger(blockNum) || blockNum < 0) { log('invalid block number'); return; }
  const proofs = findSavedRecoveryProofs(blockNum, state.address, state.cfg.contracts.evidence);
  if (!proofs.length) { log(state.tr('recovery.savedRescueMissing')); return; }
  const selectedUid = proofs.length === 1 ? proofs[0].uid
    : window.prompt(`${state.tr('recovery.savedRescueChoose')} ${proofs.map((p) => p.uid).join(', ')}`, proofs[0].uid);
  const proof = proofs.find((p) => p.uid === selectedUid);
  if (!proof) return;
  const payload = loadRecoveryEvidencePayload(blockNum, proof.uid);
  if (!payload) { log(state.tr('recovery.savedRescueMissing')); return; }
  const gameLoaded = !!(state.identity && state.blockNum != null && state.uid != null);
  const sameGame = gameLoaded && state.blockNum === blockNum && state.uid === proof.uid;
  recoveryGuaranteePressing += 1;
  syncRecoverySubmitButtons();
  recoveryGuaranteeScheduler.cancel();
  recoveryGuaranteeFingerprint = null;
  try {
    const connected = await connectProvider(state.provider);
    if (connected.address.toLowerCase() !== proof.walletAddress.toLowerCase()) {
      throw new Error('connected wallet differs from saved roster leaf');
    }
    const wc = makeWalletClient(state.provider, connected.address);
    const pc = wc.extend(publicActions);
    if (Number(await pc.getChainId()) !== proof.chainId) throw new Error('saved Evidence chain differs');
    const count = Number(await pc.readContract({ address: proof.evidenceAddress, abi: EVIDENCE_ABI,
      functionName: 'resultCountOf', args: [BigInt(blockNum), connected.address] }));
    log(`${state.tr('recovery.senderSlots')}: ${count}/3`);
    if (count >= 3) throw new Error('Evidence sender has used all 3 submissions');
    let storedPriority = null;
    try { storedPriority = decodeSubmissionPayloadString(payload)?.bundle?.encryptedActions?.priority || null; }
    catch { storedPriority = null; }
    if (storedPriority) {
      const decision = await recoveryPressFieldWindow(null,
        { storedPriority, evidenceAddress: proof.evidenceAddress, blockNum });
      if (decision.kind !== 'stored') { log(state.tr('recovery.windowCompare.cancelled')); return; }
    }
    if (!window.confirm(`${state.tr('recovery.savedRescueConfirm')} ${proof.uid} (${count}/3)`)) return;
    const sendPayload = await recoverySavedRescueTrim({ payload, blockNum, uid: proof.uid,
      walletAddress: proof.walletAddress,
      chatWindow: loadRecoveryEvidencePayloadWindow(blockNum, proof.uid, payload)
        ?? (state.blockNum === blockNum && !state.timeline?._operatorUsed ? submissionChatWindow() : null),
      sameGame, signMessage: (message) => wc.signMessage({ account: connected.address, message }) });
    if (sendPayload == null) return;
    const result = await submitResultOnChain(wc, proof.evidenceAddress, blockNum, sendPayload,
      { rebuildProof: () => rebuildRecoveryRosterProof(blockNum, proof.uid, proof.walletAddress, pc) });
    const loadedBlockNum = state.blockNum;
    if (!gameLoaded) {
      state.blockNum = blockNum;
      state.uid = proof.uid;
    }
    const priorTxHash = loadOnchainTx(blockNum, proof.uid);
    const txSaved = saveOnchainTx(result.hash, blockNum, proof.uid);
    try { writeOnChainRecord(localStorage, blockNum, proof.uid,
      makeOnChainRecord(result.hash, sendPayload, payload, {
        chatWindow: loadRecoveryEvidencePayloadWindow(blockNum, proof.uid, payload)
          ?? (loadedBlockNum === blockNum && !state.timeline?._operatorUsed
            ? submissionChatWindow() : null),
        multiple: (() => { const previous = readOnChainRecord(localStorage, blockNum, proof.uid);
          return previous?.multiple === true
            || (proof.sharedWalletUids === 1 && result.resultCountOf >= 2)
            || !!((previous?.txHash || priorTxHash)
            && (previous?.txHash || priorTxHash) !== result.hash); })(),
      })); } catch { /* 表示用記録だけ */ }
    if (state.blockNum === blockNum && state.uid === proof.uid) {
      state.onchainTxHash = result.hash;
      state.evidenceSenderCount = result.resultCountOf;
      state.evidenceSenderCountWallet = proof.walletAddress;
      state.evidenceSenderCountBlockNum = Number(blockNum);
    }
    log(`${state.tr('recovery.submitted')}: ${result.hash} seq ${result.seq}`);
    if (!txSaved) showPersistenceWarning('confirmed transaction');
  } catch (error) { log(`saved rescue failed: ${error?.message || error}`); }
  finally {
    recoveryGuaranteePressing -= 1;
    syncRecoverySubmitButtons();
    recoveryGuaranteeFingerprint = null;
    scheduleRecoveryGuarantee();
  }
}

async function readUntilAgreed(read) {
  for (;;) {
    try { return await read(); }
    catch (error) {
      let current = error;
      while (current && !current.agreement) current = current.cause;
      if (!current?.agreement || state.rosterWaitCancelled) throw error;
      log(current.agreement.kind === 'chosen-wait'
        ? state.tr('recovery.rpcNode.chosenWaiting', { host: state._agreement?.chosen || '' })
        : state.tr('recovery.rpcNode.waiting'));
      await new Promise((resolve) => setTimeout(resolve, 5000));
      if (state.rosterWaitCancelled) throw error;
    }
  }
}

async function rebuildRecoveryChainClients() {
  const agreement = state._agreement;
  if (!agreement) return;
  const wt = await getWalletTransportIfMainnet(1, state.provider);
  state._client = makeR4Client({ rpcUrls: agreement.voterUrls, operatorRpc: state.cfg.operatorRpc,
    walletTransport: wt, agreementState: agreement });
  state._timeClient = makeTimeReadClient({ rpcUrls: agreement.voterUrls,
    walletTransport: wt, agreementState: agreement, clientNowMs: clientNow });
}

// --- 署名して鍵導出＋ロスター＋フェーズ ---
async function deriveAndLoad() {
  if (recoveryGuaranteePressing > 0) { log('submission in progress — try again after it finishes'); return; }
  const deriveButton = $('derive-btn');
  if (deriveButton?.disabled) return;
  if (deriveButton) deriveButton.disabled = true;
  state.rosterWaitCancelled = false;
  const cancelWait = el('button', { type: 'button', textContent: state.tr('recovery.cancelRosterWait'),
    onclick: () => { state.rosterWaitCancelled = true; } });
  deriveButton?.parentElement?.append(cancelWait);
  recoveryDeriving = true;
  try {
  state.uid = $('uid-select').value;
  const blockNum = state.blockNum;
  state.onchainTxHash = null;
  state.evidenceSenderCount = null;
  state.evidenceSenderCountWallet = null;
  state.evidenceSenderCountBlockNum = null;
  state.clockAlert = null;
  state.clockPreviousOutside = null;
  state.clockCheckGeneration += 1;
  clearInterval(state._clockTimer);
  state._timeClient = null;
  renderClockModal();
  state.chatEnded = false;
  state.pendingVoteTarget = null;
  state.pendingVoteWarningKey = null;
  state.voteWarningAccepted = false;
  state.pendingReportWarningTarget = null;
  state.reportWarningAccepted = false;
  state.voteDeadlineNoticeOpen = false;
  state.voteDeadlineEntryPending = true;
  state.importedActions = { votes: {}, reports: {} };
  state.rosterPaused = true;
  state.rosterInvalid = false;
  state.rosterAnchorHash = null;
  state.rosterProof = null;
  state.rosterProofReady = false;
  state.rosterLateCount = 0;
  clearInterval(state._lockPtsTimer);
  state._lockPtsTimer = null;
  state.lockPoints = null;
  // V25-03: roster cacheより先にchainを固定する。タイムラインもgrouping commitmentも
  // 同じR4 clientで直接読み、RPC不通時に公開キャッシュだけでP2Pを開始しない。
  let client;
  try {
    const wt = await getWalletTransportIfMainnet(1, state.provider);
    state._agreement = makeRecoveryAgreementState({ storage: localStorage,
      storageKey: `recoveryRpcNodeTrust_v1_${blockNum}_user${state.uid}`,
      voterUrls: DEFAULTS.rpcPresets.map(({ url }) => url), onPrompt: renderRecoveryNodePrompt, clientNowMs: clientNow });
    client = makeR4Client({ rpcUrls: state._agreement.voterUrls, operatorRpc: state.cfg.operatorRpc,
      walletTransport: wt, agreementState: state._agreement });
    state._client = client;
    state._timeClient = makeTimeReadClient({ rpcUrls: DEFAULTS.rpcPresets.map(({ url }) => url),
      walletTransport: wt, agreementState: state._agreement, clientNowMs: clientNow });
    state.timing = await readUntilAgreed(() => readTimingConstants(state._client, state.cfg.contracts));
    if (state.timing.invariantOk !== true) {
      log('warning: Evidence/TokenMining timeline invariant is not verified; recovery remains available');
    }
    state.timeline = await readUntilAgreed(() => readGameTimelineMs(state._client, state.cfg.contracts.evidence, blockNum));
    client = state._client;
    for (const oldBlock of priorRecoveryStorageBlocks(localStorage, blockNum)) {
      try {
        const before = client.unagreedCount();
        const windowFinal = await client.readContract({ address: state.cfg.contracts.evidence,
          abi: EVIDENCE_ABI, functionName: 'windowFinal', args: [BigInt(oldBlock)] });
        if (windowFinal && client.unagreedCount() === before) clearFinalizedRecoveryBlockKeys(localStorage, oldBlock);
      } catch { /* 読めないブロックは次回に再確認する */ }
    }
  } catch (e) {
    log(`chain verification failed; recovery remains stopped: ${e.message}`);
    return;
  }
  state._agreement.staleBlock.subscribe(renderStaleBlockBand); renderStaleBlockBand();

  let roster;
  try {
    roster = await waitForFinalRoster();
  } catch (e) {
    console.warn('[recovery] roster verification failed:', e);
    const message = e?.code === 'canonical_roster_anchor_absent'
      ? state.tr('recovery.warn.rosterAbsentStop')
      : (e?.rosterWarning ? formatRosterIntegrityWarning(e.rosterWarning, state.tr) : null)
        || state.tr('recovery.warn.rosterVerificationFailed');
    showRosterIntegrityWarning(message);
    log(message);
    return;
  } finally {
    // 中止口は名簿待機にだけ効かせる。署名・relay 起動中へ旗を持ち越さない。
    cancelWait.remove();
    state.rosterWaitCancelled = false;
  }
  if (!roster || !['canonical', 'legacy'].includes(roster.rosterAnchorStatus)
      || !Number.isFinite(roster.rosterObservedAtMs)
      || !finalRosterHashMatches(roster, roster.rosterAnchorHash, state.timeline.chattingStart)) {
    log('final roster is unavailable; recovery remains stopped');
    return;
  }
  clearProvisionalRosterWarning();
  if (roster.groupId == null || !roster.members) { log(`roster unavailable: ${roster.reason}`); return; }
  if (!roster.rosterProof || roster.rosterProof.C.toLowerCase() !== roster.rosterAnchorHash.toLowerCase()
      || roster.rosterProof.walletAddress.toLowerCase() !== state.address.toLowerCase()) {
    showRosterIntegrityWarning(state.tr('recovery.warn.proofMissing'));
    return;
  }
  const proofRecord = { ...roster.rosterProof, chainId: Number(await state._client.getChainId()),
    evidenceAddress: state.cfg.contracts.evidence };
  if (!saveRecoveryRosterProof(proofRecord)) {
    showPersistenceWarning('final roster proof');
    return;
  }
  if (!isRecoveryRosterProofPersistent(blockNum, state.uid)) {
    showVolatileRescueWarning();
  }
  state.rosterProof = proofRecord;
  state.rosterProofReady = true;
  state.rosterAnchorHash = roster.rosterAnchorHash;
  const g3Identity = `${blockNum}|${roster.groupId}|${state.uid}|${roster.rosterAnchorHash}`;
  if (state.g3Identity !== g3Identity) {
    state.g3Reports = new Map();
    state.g3Identity = g3Identity;
  }
  state.groupId = roster.groupId;
  state.members = roster.members;
  const receiptWarningIdentity = `${blockNum}|${state.groupId}|${state.uid}`;
  if (state.receiptWarningIdentity !== receiptWarningIdentity) {
    state.receiptWarningIdentity = receiptWarningIdentity;
    state.readReceiptTracker = new PartialReadReceiptTracker();
    state.readReceiptAlerts = {};
    state.receiptWarnings = new ReceiptWarnings(state.uid);
    state.warningTargetCache = null;
    receiptDisplayMemo = null;
    provableMessagesMemo = null;
    overcapHiddenMemo = null;
    if (recoveryShownMemory.timer) flushRecoveryShownKeys(recoveryShownMemory);
    recoveryShownMemory = { identity: null, keys: new Set(), savedKeys: new Set(), storedKeys: new Set(), loaded: false, timer: null };
    screenPlanMemo = null;
    state.otherSessionReadReceipt = false;
    state.clockWarning = INITIAL_FUTURE_CLOCK_WARNING;
    state.ownSessionReadSignatures = new Set();
    state.ownSessionSignatures = new Set();
    state.sessionEntryAt = null;
    state.awayIntervals = [];
  }
  await refreshEvidenceSenderCount();
  if (state._senderCountTimer) clearInterval(state._senderCountTimer);
  state._senderCountTimer = setInterval(refreshEvidenceSenderCount, 15000);
  try {
    saveConfirmedChatWindow(localStorage, blockNum, state.groupId, state.rosterAnchorHash,
      state.timeline.chattingStart, chatWindowMsFromTimeline(state.timeline));
  } catch { showPersistenceWarning('confirmed chat window'); }
  log(`roster source: ${roster.source}${roster.reason ? ` (${roster.reason})` : ''}`);
  if (roster.anchoredRosterFallback || roster.recomputedRosterFallback) {
    const warning = formatRosterIntegrityWarning(roster, state.tr);
    showRosterIntegrityWarning(warning);
    log(warning);
    if (roster.recomputedRosterFallbackAnchorError) {
      log(`anchored roster verification: ${roster.recomputedRosterFallbackAnchorError}`);
    }
  } else if (roster.rosterMismatchCommitted) {
    const warning = `⚠ ${state.tr('recovery.warn.rosterConflict')}`;
    showRosterIntegrityWarning(warning);
    log(warning);
  } else if (!roster.liveRosterCrossChecked) {
    log('live roster anchor unavailable; continuing with the committed-selection reconstruction (fail-open)');
  }
  warnLateRoster(roster.lateCount);
  await enrichMembersFromSummary(blockNum); // 表示用の name/img/verified/デポジット額（無くても機能は成立）
  startRecoveryLockPoints();
  const myMember = roster.members.find((m) => m.uid === state.uid);
  const signer = makeSigner(state.provider, state.address);
  try {
    configureRecoveryBlockKeyDomain(state.cfg.contracts.tokenMining);
    // 単一ウォレット署名から signKey/encryptKey を兄弟導出（UI 総称は「ブロックキー」・§6.1）
    state.identity = await deriveBlockIdentity({ signMessage: signer, address: state.address, blockNum, uid: state.uid, rosterMember: myMember });
  } catch (e) { log(`identity error: ${e.message}`); return; }
  state.keys = deriveP2PKeys(state.identity.signKey, blockNum, state.groupId);
  log(`derived block keys (signKey/encryptKey) + Nostr key (group ${state.groupId})`);

  // S3R5-U-R13-SELF: 密告の根拠の控え（本体 hook と同一キー myReportGrounds_）
  state.reportGrounds = loadReportGrounds(blockNum, state.uid);
  state.reportGroundSaveFailed = false;
  // v3.3: void後再送で退避した旧投票発信の履歴を復元（本体 hook と同一キー myVotePrev_）
  try {
    state.myVotePrev = JSON.parse(localStorage.getItem(`myVotePrev_${blockNum}_user${state.uid}`) || '[]');
    if (!Array.isArray(state.myVotePrev)) state.myVotePrev = [];
  } catch { state.myVotePrev = []; }

  // リレー起動。sinceSec=チェーン権威 START_TIME（Evidence.START_TIME 秒）でラン間汚染を遮断
  // （本体アプリの NEXT_PUBLIC_START_TIME カットオフと同等）。chain読取失敗時は上で停止済み。
  const sinceSec = Number(state.timing.evidenceStartTimeSec);
  state.relay = new RecoveryRelay({
    signKey: state.identity.signKey, blockNum, groupId: state.groupId, uid: state.uid, members: state.members,
    getChatWindow: submissionChatWindow,
    getChatCloseAtMs: submissionChatCloseAt,
    getChainTimeMs: async () => {
      try { return Number((await state._timeClient.getBlock()).timestamp) * 1000; }
      catch { return null; }
    },
    now: clientNow,
    correction: recoveryClock.getClockCorrection,
    getMaxMsgChars: () => normalizeChatCaps(state.cfg.pins.chatCaps).maxMsgChars,
    onUpdate: () => {
      for (const message of (state.relay?.getMessages() || [])) observeOtherSessionItem(message, message.uid);
      scheduleRenderGame();
    }, onSelfAction: handleSelfAction, onSelfFuture: (item, ownerUid) => {
      observeOtherSessionItem(item, ownerUid);
      considerRecoveryFuture(item.actionType ? 'action' : item.receiverUid ? 'receipt' : 'chat', item);
    },
    onVerifiedAction: (inner) => { if (noteG3VerifiedReport(inner)) renderGame(); },
    onReconnect: reopenReadReceiptPause,
    onActionsChange: handleObservedActions, onReceiptsChange: (list) => mergeReceipts(list),
    onPersistenceError: ({ key } = {}) => showPersistenceWarning(key || 'relay state'),
    onRosterKeyInvalid: (invalidUid) => log(`⚠ ${invalidUid}: P2P なし（名簿の Nostr 公開鍵が無効）`),
    // v3.3追補: 他メンバーの在席通知（away の相手はプロフィール欄で「オフライン/復帰予定」表示）
    onPresence: (peerUid, pState) => {
      if (!peerUid || peerUid === state.uid) return;
      state.peerPresence[peerUid] = pState === 'away' ? 'away' : 'active';
    },
    sinceSec,
  });
  state.relay.futureMarks.onDiscardedChatRef = (senderUid, ref) =>
    state.receiptWarnings.noteFutureChatRef(senderUid, ref);
  state.relay.futureMarks.onFutureDiscard = considerRecoveryFuture;
  await state.relay.verifyStoredReceipts();
  for (const receipt of state.relay.getReceipts()) {
    if (receipt && typeof receipt === 'object' && receipt.receiverUid === state.uid
        && typeof receipt.actionHash === 'string' && !Array.isArray(receipt.msgRefs)) {
      state.issuedActionHashes.add(receipt.actionHash);
    }
  }
  if (!canStartRecoveryP2P(myMember)) {
    log(`⚠ ${state.uid}: P2P なし（名簿の Nostr 公開鍵が無効）`);
  } else {
    try {
      await state.relay.start(); log('relay channel started');
    }
    catch (e) { log(`relay start failed (browser only): ${e.message}`); }
  }
  const actionReceiptGraceToken = {};
  state.actionReceiptGrace = {
    token: actionReceiptGraceToken,
    until: openReadReceiptPause(null, performance.now(), false, Date.now()).until,
    passed: false,
  };
  setTimeout(() => {
    if (state.actionReceiptGrace?.token !== actionReceiptGraceToken || !state.relay) return;
    state.actionReceiptGrace.passed = true;
    handleObservedActions(state.relay.getRelayActionsRaw());
  }, Math.max(0, state.actionReceiptGrace.until - performance.now()));
  await state.relay.verifyRestoredReports?.();
  state.rosterPaused = false;
  // リロード復元分（チャネルが localStorage から復元して即時 fire する分が start 前に落ちる場合に備える）
  handleObservedActions(state.relay.getRelayActionsRaw());
  mergeReceipts(state.relay.getReceipts());

  renderGame();
  void checkClock('entry');
  clearInterval(state._clockTimer);
  state._clockTimer = setInterval(() => {
    if (['chatting', 'submitting'].includes(currentPhase())) void checkClock('game').finally(() => refreshRecoveryClockWarning());
  }, 61000);
  clearInterval(state._liveTimer);
  state.liveSnapshotLastAttempt = 0;
  state.liveSnapshotUnread = false;
  state.liveSubmittedSelf = false;
  await pollLiveSnapshot();
  state._liveTimer = setInterval(pollLiveSnapshot, LIVE_SNAPSHOT_POLL_MS);

  // タイムラインのチェーン追従（extendGrace で窓が動く）＋フェーズ遷移の自動再描画。
  // Sign & load 時の1回読みだけだと、リセット/延長後に古い締切で誤ったフェーズを表示し続ける。
  clearInterval(state._tlTimer);
  clearInterval(state._phTimer);
  clearInterval(state._secTimer);
  state._tlTimer = setInterval(refreshTimeline, 30000);
  state._phTimer = setInterval(() => { if (currentPhase() !== state._renderedPhase) renderGame(); }, 5000);
  // 既読受領証明の自動バッチ発行（チャット期間中のみ・§6.7）
  clearInterval(state._rrTimer);
  const startedAt = performance.now();
  state.readReceiptPause = openReadReceiptPause(null, startedAt, false, Date.now());
  state.sessionEntryAt = clientNow();
  state._rrTick = () => {
    const pause = state.readReceiptPause;
    if (pause) {
      const now = performance.now();
      const wallNow = Date.now();
      const stepped = detectClockStep({ previousWallMs: pause.lastTickWallAt,
        previousMonoMs: pause.lastTickAt, wallNowMs: wallNow, monoNowMs: now });
      if (stepped) { state.clockStepVersion += 1; void checkClock('step'); }
      if (readReceiptTickGap(pause, now, wallNow)) {
        state.readReceiptPause = openReadReceiptPause(pause, now, true, wallNow);
      } else if (now >= pause.until) {
        pause.settled = true;
        pause.lastTickAt = now;
        pause.lastTickWallAt = wallNow;
      } else {
        pause.lastTickAt = now;
        pause.lastTickWallAt = wallNow;
      }
    }
    if (state._rrTickRunning) return;
    if (!rosterReady() || receiptIssuanceBlocked() || currentPhase() !== 'chatting') return;
    if (!(state.relay?.getMessages() || []).some((message) => message?.uid !== state.uid
        && !state.issuedReadMsgKeys.has(`${message.uid}|${msgRefOf(state.relay.getMsgKey(message))}`))) return;
    state._rrTickRunning = true;
    const tickCorrection = recoveryClock.getClockCorrection();
    void coordinateSelfReadReceiptBatch(
      `selfReadReceipts_v1_${state.blockNum}_group${state.groupId}_user${state.uid}`,
      async (receipt) => {
        if (receipt?.receiverUid === state.uid && Array.isArray(receipt.msgRefs)) {
          for (const ref of receipt.msgRefs) state.issuedReadMsgKeys.add(`${receipt.senderUid}|${ref}`);
        }
        const digest = receiptIdentityDigest(receipt);
        if (!digest || state.receipts[digest]) return;
        if (await state.relay?._verifyInner?.('receipt', receipt)) mergeReceipts([receipt]);
      }, ({ signal, known }) => issueReadReceiptBatch({ signal, known, tickCorrection }))
      .finally(() => { state._rrTickRunning = false; });
  };
  state._rrTimer = setInterval(state._rrTick, READ_RECEIPT_BATCH_MS);
  setupActivityTracking(); // v3.3追補: 10分間操作なしで away（受領証明の発行を止める）
  // v3.3: 1秒tick — void判定（10分経過・受領なし）と未来時刻の表示フィルタを再評価。
  clearInterval(state._voidTimer);
  state._voidTimer = setInterval(() => { renderGame(); }, 1000);
  // P2P診断ログ: 5秒ごとに有効な名簿の鍵数をログ欄へ
  clearInterval(state._dbgTimer);
  state._dbgTimer = setInterval(() => {
    const d = state.relay?.getP2PDebug?.();
    if (d) log(`[P2P] relays=${d.relays} rosterKeys=${d.pubkeys}/${state.members.length} msgs=${d.msgs} rcpts=${Object.keys(state.receipts).length} | obsVote=${state.observedP2P.vote} obsRep=${state.observedP2P.report} myRep=${state.myReports.length} intentRep=[${(state.intent.reports || []).join(',')}]`);
  }, 5000);
  // 残り時間カウントダウン＋リレー接続状態は毎秒、要素だけ更新（フル再描画しない）
  state._secTimer = setInterval(() => {
    updateClockTimes();
    const timer = $('phase-timer');
    // 結果集計(completed=第二段階)はカウントダウンせず集計待ちメッセージ（timerText は '' を返す）
    if (timer) timer.textContent = currentPhase() === 'completed'
      ? state.tr('recovery.phaseName.aggregatingWait')
      : timerText(currentPhase());
    const rs = $('relay-status');
    if (rs) { rs.className = relayStatusClass(); rs.textContent = `${relayStatusText()} ›`; }
    updateUnreadCountdowns(); // v3.3: 未読カウントダウン「未読 3:38」を毎秒更新
  }, 1000);

  // 署名・鍵導出まで完了 → セットアップ欄は「再スタート」ボタンだけ残して全部畳む
  $('wallet-display').style.display = 'none';
  $('step-uid').style.display = 'none';
  $('step-restart').style.display = '';
  } finally {
    cancelWait.remove();
    state.rosterWaitCancelled = false;
    recoveryDeriving = false;
    if (deriveButton) deriveButton.disabled = false;
  }
}

// summary.json から表示専用メタ（name/img/verified/デポジット額入り depIds）を補完。
// チェーン束縛済み m.depIds はウォレット署名対象なので、未検証 summary で上書きしない。
async function enrichMembersFromSummary(blockNum) {
  try {
    const summary = await fetchBounded(
      `${state.cfg.r2Base}/games/block${blockNum}/summary.json`,
      { cache: 'no-store' },
      {
        label: `summary metadata for block ${blockNum}`,
        read: (res) => res.ok ? res.json() : null,
      },
    );
    if (!summary) return;
    const info = new Map();
    for (const gr of summary.groups || []) for (const mm of gr.members || []) info.set(String(mm.userId), mm);
    for (const m of state.members) {
      const mm = info.get(String(m.uid));
      if (!mm) continue;
      m.summaryMeta = {
        name: typeof mm.name === 'string' && mm.name && mm.name.length <= 256 ? mm.name : null,
        img: typeof mm.img === 'string' && mm.img && mm.img.length <= 2048 ? mm.img : null,
        verified: !!mm.verified,
        depIds: mm.depIds ?? null,
      };
    }
  } catch { /* 表示補完のみ・期限切れを含め、失敗しても uid 表示で続行 */ }
}

// force=true: 手動「更新」ボタン。変化が無くても必ず再描画＋現在フェーズ/graceをログ報告。
async function refreshTimeline(force = false) {
  if (!state._client || state.blockNum == null || state.rosterInvalid) return;
  if (force) log(state.tr('recovery.refreshing'));
  try {
    const tl = await readGameTimelineMs(state._client, state.cfg.contracts.evidence, state.blockNum);
    const startChanged = !!state.timeline && tl.chattingStart !== state.timeline.chattingStart;
    const changed = startChanged || !state.timeline || tl.chatCloseAt !== state.timeline.chatCloseAt || tl.graceSec !== state.timeline.graceSec;
    state.timeline = tl;
    try {
      const latest = await state._timeClient.getBlock();
      if (state.relay?._chainClock) {
        Object.assign(state.relay._chainClock,
          { at: Date.now(), timeMs: Number(latest.timestamp) * 1000 });
      }
      if (Number(latest.timestamp) * 1000 >= tl.chatCloseAt) state.chatEnded = true;
    } catch { /* next timeline poll may provide the phase */ }
    if ((startChanged || (state.rosterPaused && state.rosterCheckCount === 0)) && state.rosterAnchorHash) {
      state.rosterPaused = true;
      renderGame();
      if (!state._rosterRefresh) state._rosterRefresh = (async () => {
        let confirmed = false;
        try {
          const roster = await waitForFinalRoster(true);
          if (!finalRosterHashMatches(roster, state.rosterAnchorHash, state.timeline.chattingStart)) {
            stopForChangedRoster();
            return;
          }
          confirmed = true;
          state.rosterPaused = state.rosterCheckCount > 0;
          clearProvisionalRosterWarning();
          log('final roster hash unchanged after timeline update');
          renderGame();
        } catch (error) {
          log(`roster refresh failed; retrying: ${error.message}`);
          setTimeout(() => refreshTimeline(true), 1000);
        } finally {
          state._rosterRefresh = null;
          if (confirmed && !state.rosterInvalid && state.rosterCheckCount === 0) {
            state.rosterPaused = false;
            renderGame();
          }
        }
      })();
      await state._rosterRefresh;
    }
    if (changed || force) renderGame();
    if (force) log(state.tr('recovery.refreshed', { phase: currentPhase(), grace: tl.graceSec }));
    else if (changed) log(`timeline updated from chain (grace ${tl.graceSec}s)`);
  } catch (e) {
    if (force) log(`refresh failed: ${e.message}`);
    /* 自動更新時の一時的なRPC失敗は次回30秒後に再試行 */
  }
}

function currentPhase() {
  if (!state.timeline) return 'unknown';
  const phase = derivePhase(clientNow(), state.timeline);
  if ((phase === 'submitting' || phase === 'completed') && state.clockWarning.warning) {
    state.clockWarning = advanceFutureClockWarning(state.clockWarning, { type: 'chatEnded' });
  }
  if (phase === 'submitting' || phase === 'completed') state.chatEnded = true;
  return phase;
}

async function pollLiveSnapshot() {
  if (!state.relay || !rosterReady()) return;
  const phase = currentPhase();
  if (phase !== 'chatting' && phase !== 'submitting') return;
  if (state.liveSnapshotPending) return state.liveSnapshotPending;
  const now = Date.now();
  if (now - state.liveSnapshotLastAttempt < LIVE_SNAPSHOT_POLL_MS) return;
  state.liveSnapshotLastAttempt = now;
  state.liveSnapshotPending = (async () => {
    try {
      const chatWindow = submissionChatWindow();
      const snapshot = await readLiveSnapshot({
        r2Base: state.cfg.r2Base, blockNum: state.blockNum, groupId: state.groupId,
        chatStartMs: chatWindow?.startMs || 0,
        // DO は更新を間引き、無発言なら updatedAt が進まない。静かな組の有効な履歴を捨てない。
        maxAgeMs: 26 * 60 * 60 * 1000,
        nowMs: clientNow() + 120000,
      });
      if (snapshot.phase === 'submitting' || snapshot.phase === 'completed'
        || (Array.isArray(snapshot.submittedUids) && snapshot.submittedUids.length > 0)) state.chatEnded = true;
      await state.relay.ingestLiveSnapshot(snapshot);
      state.liveSnapshotUnread = false;
      state.liveSubmittedSelf = Array.isArray(snapshot.submittedUids) && snapshot.submittedUids.some((uid) => (typeof uid === 'string' || (typeof uid === 'number' && Number.isFinite(uid))) && String(uid) === String(state.uid));
    } catch {
      // A failed poll does not revoke the last successfully verified live snapshot.
      state.liveSnapshotUnread = true;
    } finally {
      state.liveSnapshotPending = null;
      renderGame();
    }
  })();
  return state.liveSnapshotPending;
}

// ============================================================
// 観測データ（受領証明・アクション）の集約と受領証明の自動発行（v3.2 §6.3/§6.7）
// ============================================================

let renderGameScheduled = false;
function scheduleRenderGame() {
  if (renderGameScheduled) return;
  renderGameScheduled = true;
  setTimeout(() => {
    renderGameScheduled = false;
    renderGame();
  }, 0);
}

// 観測受領証明の union（全署名対象の digest dedup）。自分発行分の既読msgKey/actionHashも復元（リロード対応）。
function mergeReceipts(list) {
  let changed = false;
  const warningMessages = state.relay?.getMessages() || [];
  if (state.warningTargetCache?.messages !== warningMessages) {
    state.warningTargetCache = { messages: warningMessages,
      keys: new Set(warningMessages.map((message) =>
        `${message.uid}|${msgRefOf(computeMsgKeyV2(state.blockNum, state.groupId, message))}`)) };
  }
  const warningTargets = state.warningTargetCache.keys;
  for (const rc of (Array.isArray(list) ? list : [list])) {
    const digest = receiptIdentityDigest(rc);
    if (!digest) continue;
    if (state.receipts[digest]) {
      const old = state.receipts[digest];
      if (rc.actionHash) {
        const merged = mergeActionReceiptSources(old, rc);
        if (JSON.stringify(merged) !== JSON.stringify(old)) {
          state.receipts[digest] = merged;
          changed = true;
        }
      }
      continue;
    }
    state.receipts[digest] = rc;
    changed = true;
    if (Array.isArray(rc.msgRefs)) {
      const caps = normalizeChatCaps(state.cfg.pins.chatCaps);
      const maxRefsPerReceipt = receiptMaxRefsPerReceipt(caps.maxMessages);
      currentRecoveryClaimMemo().primeScoreable(rc, warningMessages, {
        blockNum: state.blockNum, groupId: state.groupId, selfUid: state.uid,
        chatWindow: submissionChatWindow(), caps,
        getClientMsgKey: state.relay?.getMsgKey || buildMsgKeyGetter(state.blockNum, state.groupId),
        memberUids: state.members?.map((member) => member.uid) || null,
        maxRefsPerReceipt, scoreMaxRefsPerReceipt: maxRefsPerReceipt,
      });
      state.receiptWarnings?.observe(rc, digest, performance.now(),
        (senderUid, ref) => warningTargets.has(`${senderUid}|${ref}`));
      const overlapCount = state.readReceiptTracker.add(rc);
      if (overlapCount >= PARTIAL_READ_RECEIPT_ALERT_THRESHOLD && rc.receiverUid !== state.uid) {
        state.readReceiptAlerts[rc.receiverUid] = overlapCount;
      }
    }
    if (rc.receiverUid === state.uid) {
      observeOtherSessionItem(rc, rc.receiverUid);
      if (Array.isArray(rc.msgRefs)) {
        for (const k of rc.msgRefs) state.issuedReadMsgKeys.add(`${rc.senderUid}|${k}`);
      }
      if (typeof rc.actionHash === 'string') state.issuedActionHashes.add(rc.actionHash);
    }
  }
  if (changed) {
    state.receiptSelectionRevision = (state.receiptSelectionRevision || 0) + 1;
    scheduleRenderGame();
  }
}

async function importOfficialLocalStorage() {
  if (!rosterReady() || !state.relay || !state.identity) {
    log(state.tr('recovery.import.wait'));
    return;
  }
  try {
    const verify = makeVerifyRelayInner(() => state.members, state.blockNum, state.groupId);
    const imported = await parseOfficialStorage($('storage-import-text').value, {
      blockNum: state.blockNum, groupId: state.groupId, uid: state.uid,
      members: state.members, verify,
    });
    await state.relay._ingestReceiptArrivals(imported.receipts, { fromStorage: true });
    if (imported.vote && !state.myVote) state.myVote = imported.vote;
    const voteSignatures = new Set([state.myVote?.signature, ...state.myVotePrev.map((vote) => vote.signature)]);
    for (const vote of imported.votePrev) if (!voteSignatures.has(vote.signature)) {
      state.myVotePrev.push(vote);
      voteSignatures.add(vote.signature);
    }
    const reportSignatures = new Set(state.myReports.map((report) => report.signature));
    for (const report of imported.reports) if (!reportSignatures.has(report.signature)) {
      state.myReports.push(report);
      reportSignatures.add(report.signature);
    }
    for (const [signature, ground] of Object.entries(imported.reportGrounds || {})) {
      try { saveReportGround(signature, ground); } catch { showPersistenceWarning('report grounds'); }
    }
    for (const [key, value] of Object.entries(imported.observedActions.votes)) state.importedActions.votes[key] = value;
    for (const [key, value] of Object.entries(imported.observedActions.reports)) state.importedActions.reports[key] = value;
    for (const [actorUid, reports] of Object.entries(imported.observedActions.reports)) {
      if (actorUid === state.uid || !Array.isArray(reports)) continue;
      for (const report of reports) if (Number.isSafeInteger(report?.timestamp)
          && report.timestamp >= Number(state.timing.evidenceStartTimeSec) * 1000) {
        noteG3VerifiedReport({ actionType: 'report', uid: actorUid, ...report });
      }
    }
    handleObservedActions(state.relay.getRelayActionsRaw());
    if (imported.proof && imported.proof.blockNum === state.blockNum
      && imported.proof.groupId === state.groupId && imported.proof.uid === state.uid
      && imported.proof.C?.toLowerCase() === state.rosterProof?.C?.toLowerCase()
      && imported.proof.manifestHash?.toLowerCase() === state.rosterProof?.manifestHash?.toLowerCase()
      && imported.proof.walletAddress?.toLowerCase() === state.address?.toLowerCase()
      && imported.proof.evidenceAddress?.toLowerCase() === state.rosterProof?.evidenceAddress?.toLowerCase()
      && imported.proof.chainId === state.rosterProof?.chainId) {
      saveRecoveryRosterProof(imported.proof);
    }
    if (typeof imported.payload === 'string' && imported.payload.length <= 260000) {
      try {
        const decoded = decodeSubmissionPayloadString(imported.payload);
        const bundle = decoded.bundle;
        const sameMembers = decoded.memberUids.length === state.members.length
          && decoded.memberUids.every((memberUid, index) => memberUid === state.members[index].uid);
        const message = JSON.stringify({ blockNum: Number(decoded.blockNum), uid: bundle.uid,
          encryptKey: bundle.encryptKey, chatHash: bundle.chatHash, submittedAt: bundle.submittedAt,
          encryptedDataHash: bundle.encryptedDataHash, depositIds: bundle.depositIds });
        if (decoded.blockNum === state.blockNum && decoded.groupId === state.groupId
            && bundle.uid === state.uid && sameMembers
            && await verifyMessage({ address: state.address, message, signature: bundle.signature })) {
          saveRecoveryEvidencePayload(state.blockNum, state.uid, imported.payload, null, imported.payloadWindow);
        }
      } catch { /* an invalid saved bundle is ignored */ }
    }
    log(state.tr('recovery.import.done', { receipts: imported.receipts.length }));
    renderGame();
  } catch (error) {
    log(`${state.tr('recovery.import.failed')}: ${error.message}`);
  }
}

// リレー観測アクションの反映: observed 更新＋自己発信の復元（リロード後）＋受領証明の発行
function handleObservedActions(raw) {
  const { fromSnapshot = false } = arguments[1] || {};
  const incoming = raw || { votes: {}, reports: {} };
  const votes = { ...(incoming.votes || {}) };
  for (const [key, value] of Object.entries(state.importedActions.votes)) {
    if (key.endsWith('__extras')) {
      const existing = Array.isArray(votes[key]) ? votes[key] : [];
      votes[key] = [...existing, ...value].filter((item, index, all) =>
        all.findIndex((other) => other.signature === item.signature) === index);
    } else if (!votes[key]) votes[key] = value;
    else if (votes[key].signature !== value.signature) {
      const extraKey = `${key}__extras`;
      const existing = Array.isArray(votes[extraKey]) ? votes[extraKey] : [];
      if (!existing.some((item) => item.signature === value.signature)
          && existing.length + 1 < MAX_OBSERVED_ACTIONS_PER_ACTOR) votes[extraKey] = [...existing, value];
    }
  }
  for (const key of Object.keys(votes).filter((value) => value.endsWith('__extras'))) {
    votes[key] = (Array.isArray(votes[key]) ? votes[key] : [])
      .slice(0, MAX_OBSERVED_ACTIONS_PER_ACTOR - (votes[key.slice(0, -8)] ? 1 : 0));
  }
  const reports = { ...(incoming.reports || {}) };
  for (const [key, values] of Object.entries(state.importedActions.reports)) {
    const existing = Array.isArray(reports[key]) ? reports[key] : [];
    reports[key] = [...existing, ...values].filter((item, index, all) =>
      all.findIndex((other) => other.signature === item.signature) === index)
      .slice(0, MAX_OBSERVED_ACTIONS_PER_ACTOR);
  }
  state.observedActions = {
    votes, reports,
  };
  for (const vote of [votes[state.uid], ...(votes[`${state.uid}__extras`] || [])]) {
    if (vote) observeOtherSessionItem(vote, state.uid);
  }
  for (const report of (reports[state.uid] || [])) observeOtherSessionItem(report, state.uid);
  // 自己復元: チャネルは自分の発信も localStorage に集約する → リロード後にワンショット状態を戻す。
  // v3.3: 再送があると自分の投票が votes[uid]（先着）＋ votes[uid__extras] に分かれて観測される。
  // 最新の発信を myVote に、それ以外は myVotePrev（旧発信履歴）へ＝提出時の受領済み選択の材料。
  const ownVoteMain = state.observedActions.votes?.[state.uid];
  const ownVoteExtras = Array.isArray(state.observedActions.votes?.[`${state.uid}__extras`])
    ? state.observedActions.votes[`${state.uid}__extras`] : [];
  const ownVotes = [ownVoteMain, ...ownVoteExtras].filter((v) => v?.encrypted && v?.signature);
  if (ownVotes.length > 0) {
    if (!state.myVote) {
      const newest = [...ownVotes].sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0))[0];
      state.myVote = { encrypted: newest.encrypted, signature: newest.signature, timestamp: newest.timestamp };
    }
    for (const v of ownVotes) {
      if (v.signature === state.myVote.signature) continue;
      if (!state.myVotePrev.some((p) => p.signature === v.signature)) {
        state.myVotePrev.push({ encrypted: v.encrypted, signature: v.signature, timestamp: v.timestamp });
      }
    }
  }
  const ownReports = state.observedActions.reports?.[state.uid];
  if (Array.isArray(ownReports)) {
    const maxReports = state.cfg.pins.maxReports;
    for (const rep of ownReports) {
      if (!rep?.signature || state.myReports.some((r) => r.signature === rep.signature)) continue;
      // v3.3: 上限はエントリ数でなく distinct 対象数（同一対象の再送は枠を消費しない・枠=2）
      const knownTargets = new Set(state.myReports.map((r) => decryptSelfTarget(r.encrypted)).filter(Boolean));
      const tgt = decryptSelfTarget(rep.encrypted);
      if (tgt
        ? (!knownTargets.has(tgt) && knownTargets.size >= maxReports)
        : state.myReports.length >= maxReports) continue;
      state.myReports.push({ encrypted: rep.encrypted, signature: rep.signature, timestamp: rep.timestamp });
    }
  }
  // 他メンバーの発信に action 受領証明を発行（チャット期間中のみ・受信＝正典化の証人になる）
  for (const [u, v] of Object.entries(fromSnapshot ? {} : state.observedActions.votes || {})) {
    if (u.endsWith('__extras') || u === state.uid || !v?.encrypted) continue;
    issueActionReceipt(u, 'vote', v);
    const extras = state.observedActions.votes[`${u}__extras`];
    if (Array.isArray(extras)) for (const extra of extras) issueActionReceipt(u, 'vote', extra);
  }
  for (const [u, arr] of Object.entries(fromSnapshot ? {} : state.observedActions.reports || {})) {
    if (u === state.uid || !Array.isArray(arr)) continue;
    for (const rep of arr) issueActionReceipt(u, 'report', rep);
  }
  // 観測アクションが増えたらチャット画面のインライン行（〜が投票/密告しました）を即反映
  renderGame();
}

// ============================================================
// v3.3追補: 在席（アクティブ）判定。クリック/入力/スクロール/（タブが前面の時の）マウス移動が
// IDLE_TIMEOUT_MS(10分) 検知されないと away になり、その間は受領証明を発行しない。
// away/active の変化は署名付き presence として P2P に配り、他メンバー画面の「オフライン/復帰予定」
// 表示に反映させる。採点には一切影響しない（本体 useGameWebSocket と同一仕様）。
// ============================================================
async function publishPresence(nextState) {
  if (!rosterReady() || !state.identity || !state.relay || !state.uid || state.blockNum == null || state.groupId == null || state.tabEnded) return;
  if (nextState === 'active' && receiptIssuanceBlocked()) return;
  try {
    const timestamp = clientNow();
    const account = privateKeyToAccount(state.identity.signKey);
    const signature = canonicalizeSignature(await account.signMessage({
      message: presenceSignStringV2(state.blockNum, state.groupId, state.uid, nextState, timestamp),
    }));
    if (rosterReady() && !state.tabEnded
        && !(nextState === 'active' && receiptIssuanceBlocked())
        && !(nextState === 'away' && !receiptIssuanceBlocked())) {
      await state.relay.publishPresence({ uid: state.uid, state: nextState, timestamp, signature });
    }
  } catch (e) { log(`presence publish failed: ${e.message}`); }
}

function markActive() {
  state.lastActivityAt = Date.now();
  if (state.away) {
    if (state.awayIntervals.length) state.awayIntervals[state.awayIntervals.length - 1].end = clientNow();
    state.away = false;
    publishPresence('active');
    renderGame();
  }
}

let _lastMouseMoveAt = 0;
function setupActivityTracking() {
  if (state._activityBound) return;
  state._activityBound = true;
  // scroll は使わない（新着で自動スクロールすると発火し「放置＝操作扱い」になるため）。
  // 人のスクロール操作は wheel / touchstart / pointerdown / keydown で拾える。
  const opts = { passive: true, capture: true };
  for (const ev of ['pointerdown', 'keydown', 'wheel', 'touchstart']) {
    window.addEventListener(ev, markActive, opts);
  }
  // マウス移動はタブが前面の時のみ（5秒に1回だけ反映）
  window.addEventListener('mousemove', () => {
    if (typeof document !== 'undefined' && document.visibilityState !== 'visible') return;
    const now = Date.now();
    if (now - _lastMouseMoveAt < 5000) return;
    _lastMouseMoveAt = now;
    markActive();
  }, opts);
  clearInterval(state._awayTimer);
  state._awayTimer = setInterval(() => {
    if (currentPhase() !== 'chatting') {
      if (state.away) {
        if (state.awayIntervals.length) state.awayIntervals[state.awayIntervals.length - 1].end = clientNow();
        state.away = false; renderGame();
      }
      return;
    }
    if (!state.away && Date.now() - state.lastActivityAt >= IDLE_TIMEOUT_MS) {
      state.awayIntervals.push({ start: clientNow(), end: Infinity });
      state.away = true;
      publishPresence('away');
      renderGame();
    }
  }, 15000);
}

function hasOwnActionReceipt(actionHash) {
  const isOwn = (receipt) => receipt && typeof receipt === 'object'
    && receipt.receiverUid === state.uid && typeof receipt.actionHash === 'string'
    && !Array.isArray(receipt.msgRefs) && receipt.actionHash === actionHash;
  try {
    const saved = JSON.parse(localStorage.getItem(
      `recoveryReceiptArrivals_${state.blockNum}_group${state.groupId}_user${state.uid}`) || 'null');
    if (saved && typeof saved === 'object' && !Array.isArray(saved)
        && Object.values(saved).some(isOwn)) return true;
  } catch { /* An unreadable store cannot prove a previous issue. */ }
  return state.relay?.getReceipts().some(isOwn) || false;
}

// action受領証明の発行（受信直後・チャット期間中のみ・自分の発信には発行しない）
async function canIssueReceiptAtChainTip() {
  const closeAt = submissionChatCloseAt();
  if (!Number.isSafeInteger(closeAt) || !state.relay) return true;
  const chainTime = await readReceiptChainTime(state.relay._chainClock,
    () => state.relay.getChainTimeMs(), Date.now());
  return !Number.isSafeInteger(chainTime) || chainTime <= closeAt;
}

async function issueActionReceipt(actorUid, actionType, action) {
  if (!rosterReady() || !state.identity || !state.relay || actorUid === state.uid) return;
  if (state.relay.isLiveOnlyAction?.(action)) return;
  if (!shouldIssueReceiptForObservedAction(actionType, state.observedActions.votes?.[actorUid], action)) return;
  if (currentPhase() !== 'chatting') return;
  if (receiptIssuanceBlocked()) return;
  const grace = state.actionReceiptGrace;
  if (!grace || (!grace.passed && performance.now() < grace.until)) return;
  // v3.3: 発信主張時刻の±10分以内に受信した投票/密告にのみ受領証明を発行（チャットと統一）
  const timestamp = clientNow();
  if (!isReceiptTimely(timestamp, action.timestamp)) return;
  if (!(await canIssueReceiptAtChainTip()) || currentPhase() !== 'chatting') return;
  if (!canIssueActionReceiptBeforeVoteCutoff(actionType, action.timestamp, timestamp, submissionChatCloseAt())) return;
  try {
    const actionHash = actionHashV2(actionType, state.blockNum, state.groupId, actorUid, action.encrypted, action.timestamp);
    const bucket = `${actorUid}|${actionType}`;
    if (state.issuedActionHashes.has(actionHash)) {
      if (!state.issuedActionReceiptBuckets.has(actionHash)) {
        state.issuedActionReceiptBuckets.set(actionHash, bucket);
      }
      return;
    }
    if (hasOwnActionReceipt(actionHash)) {
      state.issuedActionHashes.add(actionHash);
      if (!state.issuedActionReceiptBuckets.has(actionHash)) {
        state.issuedActionReceiptBuckets.set(actionHash, bucket);
      }
      return;
    }
    const bucketCount = [...state.issuedActionReceiptBuckets.values()]
      .filter((value) => value === bucket).length;
    if (bucketCount >= MAX_OBSERVED_ACTIONS_PER_ACTOR) return;
    state.issuedActionReceiptBuckets.set(actionHash, bucket);
    state.issuedActionHashes.add(actionHash);
    const account = privateKeyToAccount(state.identity.signKey);
    const signature = canonicalizeSignature(await account.signMessage({
      message: receiptSignString(state.blockNum, state.groupId, state.uid, actionHash, timestamp)
    }));
    const receipt = { receiverUid: state.uid, actionHash, timestamp, signature };
    if (!rosterReady()) {
      state.issuedActionReceiptBuckets.delete(actionHash);
      state.issuedActionHashes.delete(actionHash);
      return;
    }
    if (receiptIssuanceBlocked()) {
      state.issuedActionReceiptBuckets.delete(actionHash);
      state.issuedActionHashes.delete(actionHash);
      return;
    }
    state.ownSessionSignatures.add(signature);
    await state.relay.publishReceipt(receipt);
  } catch (e) { log(`action receipt issue failed: ${e.message}`); }
}

// 既読受領証明の自動バッチ発行: 他メンバーの未受領メッセージをsender毎にまとめて署名（§6.7）
async function issueReadReceiptBatch({ signal, known, tickCorrection = recoveryClock.getClockCorrection() } = {}) {
  if (signal?.aborted) return;
  if (!rosterReady() || !state.identity || !state.relay) return;
  if (currentPhase() !== 'chatting') return;
  if (receiptIssuanceBlocked()) return;
  if (state.readReceiptPause && performance.now() < state.readReceiptPause.until) return;
  if (!(await canIssueReceiptAtChainTip())) return;
  const published = [];
  try {
    const msgs = state.relay.getMessages() || [];
    const fromMemory = Object.values(state.receipts).filter((receipt) => receipt.receiverUid === state.uid);
    const timestamp = nextReadReceiptTimestamp({ clockMs: clientNow(),
      receipts: Array.isArray(known) && known.length ? known : fromMemory });
    const cappedMsgs = clientReceiptableMessages(msgs, recoveryAdmittedReceipts(), {
      blockNum: state.blockNum, groupId: state.groupId, myUid: state.uid, timestamp,
      chatWindow: submissionChatWindow(),
      caps: normalizeChatCaps(state.cfg.pins.chatCaps),
      compare: canonicalComparatorV2(state.relay.getMsgKey), getClientMsgKey: state.relay.getMsgKey,
      memberUids: state.members.map((member) => member.uid),
    });
    const bySender = {};
    const issuedPerSender = {};
    for (const key of state.issuedReadMsgKeys) {
      const senderUid = key.split('|', 1)[0];
      issuedPerSender[senderUid] = (issuedPerSender[senderUid] || 0) + 1;
    }
    for (const m of cappedMsgs) {
      if (!m || m.uid == null || m.uid === state.uid || !m.signature) continue;
      if (state.relay.isLiveOnlyMessage?.(m)) continue;
      // v3.3: 発信主張時刻の±10分以内に受信したメッセージにのみ既読を発行する。
      // バックデート/ポストデート発信（過去の会話への挟み込み・会話数水増し）には
      // 正直なクライアントは既読を付けない＝正典に入らない。
      if (!isReceiptTimely(timestamp, m.timestamp)) continue;
      // 既読が指す参照は msgKey の先頭16バイト（本体クライアントと同一）
      const k = msgRefOf(state.relay.getMsgKey(m));
      if (state.issuedReadMsgKeys.has(`${m.uid}|${k}`)) continue;
      if ((issuedPerSender[m.uid] || 0) + (bySender[m.uid]?.length || 0)
          >= normalizeChatCaps(state.cfg.pins.chatCaps).maxMessages) continue;
      (bySender[m.uid] = bySender[m.uid] || []).push(k);
    }
    if (Object.keys(bySender).length && !(await canIssueReceiptAtChainTip())) return;
    const account = privateKeyToAccount(state.identity.signKey);
    for (const [senderUid, rawMsgRefs] of Object.entries(bySender)) {
      const msgRefs = [...rawMsgRefs].sort(compareHexAsc);
      const signature = canonicalizeSignature(await account.signMessage({
        message: readReceiptSignString(state.blockNum, state.groupId, state.uid, senderUid, msgRefs, timestamp)
      }));
      if (signal?.aborted || recoveryClock.getClockCorrection() !== tickCorrection) return published;
      if (state.readReceiptPause && performance.now() < state.readReceiptPause.until) return published;
      const receipt = { receiverUid: state.uid, senderUid, msgRefs, timestamp, signature };
      state.ownSessionReadSignatures.add(signature);
      state.ownSessionSignatures.add(signature);
      try {
        const key = `ownReadSession_v1_${state.blockNum}_group${state.groupId}_user${state.uid}`;
        const stored = JSON.parse(sessionStorage.getItem(key) || '[]');
        sessionStorage.setItem(key, JSON.stringify([...new Set([...(Array.isArray(stored) ? stored : []), signature])]));
      } catch { /* memory remains usable */ }
      if (signal?.aborted || recoveryClock.getClockCorrection() !== tickCorrection
          || !rosterReady() || receiptIssuanceBlocked()) return published;
      await state.relay.publishReceipt(receipt);
      published.push(receipt);
      for (const k of msgRefs) state.issuedReadMsgKeys.add(`${senderUid}|${k}`);
    }
  } catch (e) { log(`read receipt batch failed: ${e.message}`); }
  return published;
}

async function reissueReadReceipts(shiftBackMs, skipKeys = null) {
  while (state._rrTickRunning) await new Promise((resolve) => setTimeout(resolve, 20));
  if (!rosterReady() || !state.identity || !state.relay || receiptIssuanceBlocked()
      || currentPhase() !== 'chatting') return;
  state._rrTickRunning = true;
  try {
    await coordinateSelfReadReceiptBatch(
      `selfReadReceipts_v1_${state.blockNum}_group${state.groupId}_user${state.uid}`,
      async (receipt) => {
        const digest = receiptIdentityDigest(receipt);
        if (digest && !state.receipts[digest] && await state.relay?._verifyInner?.('receipt', receipt)) {
          mergeReceipts([receipt]);
        }
      }, async ({ signal, known }) => {
        if (signal?.aborted || !rosterReady() || receiptIssuanceBlocked() || currentPhase() !== 'chatting'
            || !(await canIssueReceiptAtChainTip()) || !Number.isSafeInteger(state.timeline?.chatCloseAt)) return [];
        const messages = state.relay.getMessages() || [];
        const messageTimestamps = new Map(messages.map((message) => [
          `${message.uid}|${msgRefOf(state.relay.getMsgKey(message))}`, message.timestamp,
        ]));
        const fromMemory = Object.values(state.receipts).filter((receipt) => receipt.receiverUid === state.uid);
        const plans = planReadReceiptReissues({
          receipts: Array.isArray(known) && known.length ? known : fromMemory,
          shiftBackMs, messageTimestamps, nowMs: clientNow(),
          chattingStartMs: state.timeline.chattingStart, chatCloseAtMs: state.timeline.chatCloseAt,
        });
        const issued = [];
        const account = privateKeyToAccount(state.identity.signKey);
        for (const plan of plans) {
          if (skipKeys?.has(reissueGroupKey(plan))) continue;
          if (signal?.aborted || !rosterReady() || receiptIssuanceBlocked() || currentPhase() !== 'chatting' || !(await canIssueReceiptAtChainTip())) break;
          const { receiverUid, senderUid, msgRefs, timestamp } = plan;
          const signature = canonicalizeSignature(await account.signMessage({
            message: readReceiptSignString(state.blockNum, state.groupId,
              receiverUid, senderUid, msgRefs, timestamp),
          }));
          if (signal?.aborted || !rosterReady() || receiptIssuanceBlocked() || currentPhase() !== 'chatting') break;
          const receipt = { receiverUid, senderUid, msgRefs, timestamp, signature };
          state.ownSessionReadSignatures.add(signature);
          state.ownSessionSignatures.add(signature);
          try {
            const key = `ownReadSession_v1_${state.blockNum}_group${state.groupId}_user${state.uid}`;
            const stored = JSON.parse(sessionStorage.getItem(key) || '[]');
            sessionStorage.setItem(key, JSON.stringify([...new Set([...(Array.isArray(stored) ? stored : []), signature])]));
          } catch { /* memory remains usable */ }
          await state.relay.publishReceipt(receipt);
          issued.push(receipt);
        }
        return issued;
      });
  } finally { state._rrTickRunning = false; }
}

// 既読マップ: msgKey → 既読者uid集合（renderChatLog / 未読警告用）
// K-S6-005: 採点と同じ ±10分（isReceiptTimely）で篩う。時刻を見ないと、時刻をずらした
// 受領証明だけで「条件達成」に見せて利用者を失格へ誘導できた（本体 useGameWebSocket と同一規則）。
// J-26: **表示にだけ**チェーンの宣言窓も課す（本体 useGameWebSocket と同一規則）。
// 他人の既読は buildReceiptMaps が全参照を atom 単位で検査する。自己発行分は参照ごと。
// 自称時刻同士しか比べない鮮度検査は「相手の発言 ts + 9分」の受領証明を通すので、
// 採点では無効な受領証明で画面だけ「既読」にできた。開始時に検証して保存した
// 窓を画面・提出物の構築に共通で渡す。
let receiptDisplayMemo = null;
let recoveryAdmissionMemo = null;
let recoveryFirstSeen = { identity: null, receipts: new Map() };
let provableMessagesMemo = null;
let recoveryClaimMemo = null;
function currentRecoveryClaimMemo() {
  const identity = `${state.blockNum}|${state.groupId}|${state.uid}|${(state.members || []).map((member) => member.uid).join('|')}`;
  if (recoveryClaimMemo?.identity !== identity) recoveryClaimMemo = { identity, memo: new ReceiptClaimMemo() };
  return recoveryClaimMemo.memo;
}
// 受け取った集合は警告・在席・保存に残し、採点へ通せる既読だけを画面と提出へ渡す。
function recoveryAdmittedReceipts() {
  const receipts = Object.values(state.receipts);
  const ready = rosterReady();
  if (!ready) return receipts;
  const messages = state.relay?.getMessages() || [];
  const window = submissionChatWindow();
  const revision = state.receiptSelectionRevision || 0;
  const rawCaps = state.cfg.pins.chatCaps;
  const identity = `${state.blockNum}|${state.groupId}|${state.uid}`;
  const now = OTHER_READ_RECEIPT_PENDING_EXPIRES ? Date.now() : 0;
  if (recoveryAdmissionMemo?.relay === state.relay && recoveryAdmissionMemo.messages === messages
    && recoveryAdmissionMemo.receipts === state.receipts && recoveryAdmissionMemo.revision === revision
    && recoveryAdmissionMemo.startMs === window?.startMs && recoveryAdmissionMemo.endMs === window?.endMs
    && recoveryAdmissionMemo.members === state.members && recoveryAdmissionMemo.ready === ready
    && recoveryAdmissionMemo.rawCaps === rawCaps && recoveryAdmissionMemo.identity === identity
    && (!OTHER_READ_RECEIPT_PENDING_EXPIRES || now < recoveryAdmissionMemo.nextExpiry)) return recoveryAdmissionMemo.value;
  const memberUids = state.members.map((member) => member.uid);
  const targets = buildRealTargets({}, messages, state.blockNum, state.groupId, state.relay?.getMsgKey);
  const maxRefsPerReceipt = receiptMaxRefsPerReceipt(normalizeChatCaps(rawCaps).maxMessages);
  if (OTHER_READ_RECEIPT_PENDING_EXPIRES && recoveryFirstSeen.identity !== identity)
    recoveryFirstSeen = { identity, receipts: new Map() };
  const presentDigests = OTHER_READ_RECEIPT_PENDING_EXPIRES ? new Set() : null;
  let nextExpiry = Infinity;
  const value = receipts.filter((rc) => {
    if (!Array.isArray(rc.msgRefs) || rc.receiverUid === state.uid) return true;
    const admission = clientReadReceiptAdmission(rc, targets, {
      chatWindow: window, memberUids, selfUid: state.uid, maxRefsPerReceipt,
    });
    if (!OTHER_READ_RECEIPT_PENDING_EXPIRES) return admission.state === 'covered';
    const digest = receiptIdentityDigest(rc);
    if (!digest) return false;
    presentDigests.add(digest);
    let first = recoveryFirstSeen.receipts.get(digest);
    if (!first) {
      first = { at: now, covered: false };
      recoveryFirstSeen.receipts.set(digest, first);
    }
    if (admission.state === 'covered' && (first.covered || now <= first.at + RECEIPT_PENDING_TTL_MS)) {
      first.covered = true;
      return true;
    }
    if (admission.state === 'pending' && !first.covered && now <= first.at + RECEIPT_PENDING_TTL_MS)
      nextExpiry = Math.min(nextExpiry, first.at + RECEIPT_PENDING_TTL_MS + 1);
    return false;
  });
  if (OTHER_READ_RECEIPT_PENDING_EXPIRES) {
    for (const digest of recoveryFirstSeen.receipts.keys()) {
      if (!presentDigests.has(digest)) recoveryFirstSeen.receipts.delete(digest);
    }
  }
  recoveryAdmissionMemo = { relay: state.relay, messages, receipts: state.receipts, revision,
    startMs: window?.startMs, endMs: window?.endMs, members: state.members, ready, rawCaps,
    identity, nextExpiry, value };
  return value;
}
function selectedReadReceiptsForDisplay(messages, window) {
  const revision = state.receiptSelectionRevision || 0;
  const rawCaps = state.cfg.pins.chatCaps;
  const admittedReceipts = recoveryAdmittedReceipts();
  if (receiptDisplayMemo?.relay === state.relay && receiptDisplayMemo.messages === messages
    && receiptDisplayMemo.receipts === admittedReceipts && receiptDisplayMemo.revision === revision
    && receiptDisplayMemo.startMs === window?.startMs && receiptDisplayMemo.endMs === window?.endMs
    && receiptDisplayMemo.rawCaps === rawCaps) return receiptDisplayMemo.selected;
  const caps = normalizeChatCaps(rawCaps);
  const getClientMsgKey = state.relay?.getMsgKey || buildMsgKeyGetter(state.blockNum, state.groupId);
  const targets = buildRealTargets({ votes: {}, reports: {}, observed: { votes: {}, reports: {} } },
    messages, state.blockNum, state.groupId, getClientMsgKey);
  const selected = admitReadReceiptsByArrival(admittedReceipts, targets, {
    messages, blockNum: state.blockNum, groupId: state.groupId, myUid: state.uid,
    selfUid: state.uid, memberUids: state.members.map((member) => member.uid),
    chatWindow: window, maxRefsPerReceipt: receiptMaxRefsPerReceipt(caps.maxMessages),
    caps, getClientMsgKey, claimMemo: currentRecoveryClaimMemo(),
  });
  receiptDisplayMemo = { relay: state.relay, messages, receipts: admittedReceipts,
    revision, startMs: window?.startMs, endMs: window?.endMs, rawCaps, selected };
  return selected;
}

function submissionChatWindow() {
  return loadConfirmedChatWindow(localStorage, state.blockNum, state.groupId,
    state.rosterAnchorHash, state.timeline?.chattingStart)
    || chatWindowMsFromTimeline(state.timeline);
}

function submissionChatCloseAt() {
  if (Number.isSafeInteger(state.timeline?.chatCloseAt)) return state.timeline.chatCloseAt;
  const endMs = submissionChatWindow()?.endMs;
  return Number.isSafeInteger(endMs) ? endMs - CHAT_WINDOW_CLOCK_SKEW_MS : null;
}

// S3R4-U-RPCWIN: 復元の押下でも署名前に固定の読み先を読み比べる。
async function recoveryPressFieldWindow(current, { storedPriority = null,
  evidenceAddress = state.cfg.contracts.evidence, blockNum = state.blockNum } = {}) {
  const keep = storedPriority ? { kind: 'stored' } : { kind: 'current' };
  if (!storedPriority && !priorityReady({ rosterConfirmed: rosterReady(), members: state.members,
    myUid: state.uid, chatWindow: current, canSignSelf: true })) return keep;
  let comparison;
  let planned;
  try {
    log(state.tr('recovery.windowCompare.reading'));
    let walletTimer;
    const walletTransport = await Promise.race([
      getWalletTransportIfMainnet(1, state.provider).catch(() => null),
      new Promise((resolve) => { walletTimer = setTimeout(() => resolve(null), 3000); }),
    ]).finally(() => clearTimeout(walletTimer));
    const read = await readPressChatWindowsMs({ rpcUrls: DEFAULTS.rpcPresets.map(({ url }) => url),
      walletTransport, operatorRpc: state.cfg.operatorRpc, evidenceAddress, blockNum });
    comparison = comparePressWindows({ current, answers: read.answers, operator: read.operator });
    planned = pressPromptFor({ comparison, storedPriority, canRebuild: false });
  } catch (error) {
    log(`press window compare failed; continuing as before: ${error?.message || error}`);
    return keep;
  }
  if (planned.decision) return planned.decision;
  const choice = await chooseRecoveryFieldWindow(comparison, planned.prompt, usableRecoveryLock()?.chatWindow ?? null);
  return pressDecisionFor({ comparison, prompt: planned.prompt, choice, current });
}

// S3R4-U-RPC1-STALE2: 読んだブロックが C より約3分以上古いときの表示だけの帯（判定は公式と共有の chainAgreement.js）。
function renderStaleBlockBand() {
  const box = $('rpc-stale-notice');
  const notice = state._agreement?.staleBlock?.get();
  if (!box) return;
  box.textContent = notice ? state.tr(`recovery.rpcStale.${notice.source === 'wallet' ? 'wallet' : 'public'}`, { minutes: notice.minutes }) : '';
  box.style.display = notice ? 'block' : 'none';
}

function renderRecoveryNodePrompt(prompt, agreement) {
  const previous = document.getElementById('recovery-rpc-node-root');
  previous?._rpcNodeClose?.();
  previous?.remove();
  if (!prompt) return;
  const root = el('div', { id: 'recovery-rpc-node-root', role: 'dialog', ariaModal: 'true',
    style: 'position:fixed;inset:0;z-index:10005;background:rgba(0,0,0,.82);display:flex;align-items:center;justify-content:center;padding:24px;overflow:auto;' });
  const panel = el('div', { className: 'card', style: 'max-width:780px;max-height:90vh;overflow:auto;' });
  const close = () => { window.removeEventListener('keydown', onKey); root.remove(); };
  root._rpcNodeClose = close;
  const dismiss = () => { agreement.dismiss(); close(); };
  const onKey = (event) => { if (event.key === 'Escape') dismiss(); };
  root.onclick = (event) => { if (event.target === root) dismiss(); };
  // S3R4-U-RPC1-CHOICE: 選んだノードが W を超えて答えないときの2択（候補は「別のノードを選ぶ」の後だけ）。
  if (prompt.kind === 'chosen-wait') {
    panel.append(el('h2', { textContent: state.tr('recovery.rpcNode.waitTitle') }));
    panel.append(el('p', { textContent: state.tr('recovery.rpcNode.waitBody', { host: prompt.host,
      seconds: Math.max(1, Math.round((prompt.waitedMs || 0) / 1000)) }) }));
    if (prompt.noCandidates) panel.append(el('p', { textContent: state.tr('recovery.rpcNode.waitNoCandidates') }));
    panel.append(el('button', { type: 'button', textContent: state.tr('recovery.rpcNode.waitKeep'),
      onclick: () => { agreement.waitChosen(); close(); } }));
    panel.append(el('button', { type: 'button', textContent: state.tr('recovery.rpcNode.waitPickAnother'),
      onclick: () => { close(); agreement.pickAnother(); } }));
    root.append(panel); document.body.append(root);
    window.addEventListener('keydown', onKey);
    return;
  }
  const pick = prompt.kind === 'pick';
  const single = prompt.kind === 'single';
  panel.append(el('h2', { textContent: state.tr(pick ? 'recovery.rpcNode.pickTitle' : single ? 'recovery.rpcNode.singleTitle' : 'recovery.rpcNode.splitTitle') }));
  panel.append(el('p', { textContent: state.tr(pick ? 'recovery.rpcNode.pickBody' : single ? 'recovery.rpcNode.singleBody' : 'recovery.rpcNode.splitBody') }));
  if (!single && !pick) panel.append(el('p', { textContent: state.tr('recovery.rpcNode.splitSameWindowNote') }));
  const rows = el('div');
  panel.append(rows);
  const connect = el('button', { type: 'button', textContent: state.tr('recovery.rpcNode.connectWallet'),
    onclick: () => { dismiss(); connectWallet(); } });
  const fmt = (ms) => Number.isFinite(ms) ? new Date(ms).toLocaleString() : '—';
  const candidates = prompt.candidates || [];
  const hosts = single ? [prompt.host] : candidates.map(({ host }) => host);
  const method = String(prompt.key || '').split(':')[0];
  const windowRows = new Map();
  for (const host of hosts) {
    const row = el('div', { style: 'border-top:1px solid #888;padding:8px 0;' });
    if (single) row.append(el('div', { textContent: state.tr('recovery.rpcNode.nodeLine', { host }) }));
    const windowRow = el('div', { textContent: state.tr('recovery.rpcNode.splitNodeUnread', { host }) });
    windowRows.set(host, windowRow);
    const candidate = candidates.find((item) => item.host === host);
    row.append(windowRow, el('div', { textContent: state.tr(pick ? 'recovery.rpcNode.pickNodeValue' : 'recovery.rpcNode.splitNodeValue', {
      method: pick ? String(candidate?.key || prompt.key || '').split(':')[0] : method, value: candidate?.value || '—',
    }) }));
    row.append(el('button', { type: 'button', textContent: state.tr(single
      ? 'recovery.rpcNode.trustContinue' : pick ? 'recovery.rpcNode.pickThis' : 'recovery.rpcNode.trustThis'), onclick: () => {
      if (single) agreement.approve(host); else agreement.choose(host);
      close(); log(state.tr('recovery.rpcNode.approved', { host }));
    } }));
    rows.append(row);
  }
  // 単独の警告でも候補の窓と値を表示する。読み比べは固定 S に対して1回だけ行う。
  readPressChatWindowsMs({ rpcUrls: agreement.voterUrls, walletTransport: null,
    evidenceAddress: state.cfg.contracts.evidence, blockNum: state.blockNum }).then(({ answers }) => {
    if (document.getElementById('recovery-rpc-node-root') !== root) return;
    for (const host of hosts) {
      const answer = answers.find((item) => item.sourceId === host);
      windowRows.get(host).textContent = answer && !answer.error
        ? state.tr('recovery.rpcNode.splitNodeWindow', { host, start: fmt(answer.chatOpenAt), close: fmt(answer.chatCloseAt) })
        : state.tr('recovery.rpcNode.splitNodeUnread', { host });
    }
  }).catch(() => { /* 窓は読めないと表示済み。候補の値は残す */ });
  panel.append(connect);
  root.append(panel); document.body.append(root);
  window.addEventListener('keydown', onKey);
}

function chooseRecoveryFieldWindow(comparison, prompt, lockWindow = null) {
  return new Promise((resolve) => {
    const previous = document.getElementById('recovery-window-compare-root');
    if (previous) {
      previous._rpcwinResolve?.({ kind: 'cancel' });
      previous.remove();
    }
    const root = el('div', { id: 'recovery-window-compare-root', role: 'dialog', ariaModal: 'true',
      style: 'position:fixed;inset:0;z-index:10006;background:rgba(0,0,0,.82);display:flex;align-items:center;justify-content:center;padding:24px;overflow:auto;' });
    const panel = el('div', { className: 'card', style: 'max-width:780px;max-height:90vh;overflow:auto;' });
    const onKey = (event) => { if (event.key === 'Escape') finish({ kind: 'cancel' }); };
    const finish = (choice) => { window.removeEventListener('keydown', onKey); root.remove(); resolve(choice); };
    root._rpcwinResolve = finish;
    const fmt = (ms) => Number.isFinite(ms) ? new Date(ms).toLocaleString() : '—';
    const source = (id) => id === 'wallet' ? state.tr('recovery.windowCompare.walletOwnNode') : id;
    panel.append(el('h2', { textContent: state.tr('recovery.windowCompare.title') }));
    panel.append(el('p', { textContent: state.tr(prompt.mode === 'build'
      ? 'recovery.windowCompare.introBuild' : 'recovery.windowCompare.introStored') }));
    if (comparison.defaultReason === 'device' || (!comparison.defaultKey && !comparison.agree)) panel.append(el('p', { textContent: state.tr(comparison.defaultReason === 'device' ? 'recovery.windowCompare.tieHint' : 'recovery.windowCompare.noMarkHint') }));
    let selected = prompt.initial || null;
    const radio = (label, choice) => {
      const input = el('input', { type: 'radio', name: 'recovery-window-choice',
        checked: selected?.kind === choice.kind && selected?.key === choice.key,
        onchange: () => { selected = choice; confirm.disabled = false; } });
      return el('label', { style: 'display:block;margin:10px 0;' }, input, ` ${label}`);
    };
    for (const group of comparison.groups) {
      const row = el('div', { style: 'border-top:1px solid #888;padding:8px 0;' });
      row.append(el('strong', { textContent: state.tr('recovery.windowCompare.groupLine', {
        start: fmt(group.chatOpenAt), close: fmt(group.chatCloseAt),
      }) }));
      row.append(el('div', { textContent: group.sources.length
        ? state.tr('recovery.windowCompare.groupSources', { sources: group.sources.map(source).join(', ') })
        : state.tr('recovery.windowCompare.noSources') }));
      if (group.isCurrent) row.append(el('div', { textContent: state.tr('recovery.windowCompare.thisDevice') }));
      if (comparison.defaultKey === group.key) row.append(el('div', { textContent: state.tr(comparison.defaultReason === 'majority' ? 'recovery.windowCompare.majority' : 'recovery.windowCompare.deviceMark') }));
      if (prompt.storedInside) row.append(el('div', { textContent: state.tr(prompt.storedInside[group.key]
        ? 'recovery.windowCompare.storedInside' : 'recovery.windowCompare.storedOutside') }));
      if (lockWindow && group.window && prompt.mode === 'build'
        && (lockWindow.startMs !== group.window.startMs || lockWindow.endMs !== group.window.endMs))
        row.append(el('div', { textContent: state.tr('recovery.windowCompare.lockNotUsed') }));
      if (prompt.mode !== 'stored-only') row.append(radio(state.tr(prompt.mode === 'build'
        ? 'recovery.windowCompare.chooseWindow' : 'recovery.windowCompare.chooseWindowStored'),
      { kind: 'group', key: group.key }));
      panel.append(row);
    }
    if (comparison.unanswered.length) panel.append(el('p', { textContent: state.tr('recovery.windowCompare.unanswered',
      { sources: comparison.unanswered.map(source).join(', ') }) }));
    if (comparison.operator) panel.append(el('p', { textContent: comparison.operator.window
      ? state.tr('recovery.windowCompare.operatorNode', {
        start: fmt(comparison.operator.window.startMs + CHAT_WINDOW_CLOCK_SKEW_MS),
        close: fmt(comparison.operator.window.endMs - CHAT_WINDOW_CLOCK_SKEW_MS),
      }) : state.tr('recovery.windowCompare.operatorNodeUnread') }));
    if (prompt.mode === 'stored-only') {
      panel.append(radio(state.tr('recovery.windowCompare.chooseStored'), { kind: 'stored' }));
      panel.append(el('p', { textContent: state.tr('recovery.windowCompare.storedOnlyNote') }));
    } else panel.append(radio(state.tr(prompt.mode === 'build'
      ? 'recovery.windowCompare.chooseNone' : 'recovery.windowCompare.chooseNoneStored'), { kind: 'none' }));
    const confirm = el('button', { type: 'button', disabled: !selected,
      textContent: state.tr('recovery.windowCompare.confirm'), onclick: () => finish(selected) });
    panel.append(confirm, ' ', el('button', { type: 'button', textContent: state.tr('recovery.windowCompare.cancel'),
      onclick: () => finish({ kind: 'cancel' }) }));
    root.append(panel);
    document.body.append(root);
    window.addEventListener('keydown', onKey);
  });
}

function readersByMsgKey() {
  const confirmedWindow = submissionChatWindow();
  const messages = state.relay?.getMessages() || [];
  return buildReceiptMaps(
    selectedReadReceiptsForDisplay(messages, confirmedWindow),
    { messages, myUid: state.uid },
    state.blockNum, state.groupId, confirmedWindow, state.relay?.getMsgKey
  ).readersByMsgKey;
}

let overcapHiddenMemo = null;
let recoveryShownMemory = { identity: null, keys: new Set(), savedKeys: new Set(), storedKeys: new Set(), loaded: false, timer: null };
const recoveryShownStorageKey = (blockNum, groupId, uid) => `priorityShownSeparators_${blockNum}_${groupId}_${uid}`;
const validRecoveryShownKey = (key) => typeof key === 'string' && /^0x[0-9a-f]{64}$/.test(key);
function loadRecoveryShownKeys(identity) {
  const storageKey = recoveryShownStorageKey(state.blockNum, state.groupId, state.uid);
  try {
    const raw = localStorage.getItem(storageKey);
    if (raw === null) return [];
    const value = JSON.parse(raw);
    const limit = Math.min(400, 100 * (state.members.length - 1));
    if (value?.v !== 1 || value.identity !== identity || !Array.isArray(value.keys)
      || value.keys.length > limit || value.keys.some((key) => !validRecoveryShownKey(key))
      || new Set(value.keys).size !== value.keys.length) throw new Error('invalid saved shown keys');
    const byKey = new Map((state.relay?.getMessages() || []).map((message) => [state.relay.getMsgKey(message), message]));
    const perSender = new Map();
    const memberUids = new Set(state.members.map((member) => member.uid));
    for (const key of value.keys) {
      const message = byKey.get(key);
      const sender = message?.uid;
      if (sender == null) continue;
      if (sender === state.uid || !memberUids.has(sender))
        throw new Error('invalid saved shown sender');
      const list = perSender.get(sender) || [];
      list.push({ key, timestamp: message.timestamp });
      perSender.set(sender, list);
    }
    const keep = new Set(value.keys);
    let trimmed = false;
    for (const list of perSender.values()) {
      if (list.length <= 100) continue;
      trimmed = true;
      list.sort((a, b) => b.timestamp - a.timestamp || a.key.localeCompare(b.key));
      for (const { key } of list.slice(100)) keep.delete(key);
    }
    return trimmed ? value.keys.filter((key) => keep.has(key)).sort() : value.keys;
  } catch {
    try { localStorage.removeItem(storageKey); } catch { /* storage unavailable */ }
    return [];
  }
}

function saveRecoveryShownKeys(memory) {
  memory.timer = null;
  const context = memory.saveContext;
  if (!context) return;
  if (recoveryShownMemory !== memory || !context.relay) return;
  const bySender = new Map();
  const saved = memory.savedKeys;
  const storedKeys = memory.storedKeys || saved;
  const memberUids = new Set(context.members.map((member) => member.uid));
  const byKey = new Map((context.relay.getMessages() || []).map((message) =>
    [context.relay.getMsgKey(message), message]));
  for (const key of saved) {
    const message = byKey.get(key);
    if (!message || message.uid === context.uid || !memberUids.has(message.uid)) continue;
    const list = bySender.get(message.uid) || [];
    list.push({ key, timestamp: message.timestamp });
    bySender.set(message.uid, list);
  }
  for (const list of bySender.values()) {
    list.sort((a, b) => b.timestamp - a.timestamp || a.key.localeCompare(b.key));
    list.length = Math.min(list.length, 100);
  }
  const unresolved = [...saved].filter((key) => !byKey.has(key) && storedKeys.has(key));
  const limit = Math.min(400, 100 * (context.members.length - 1));
  const prior = [...unresolved];
  const fresh = [];
  for (const [uid, list] of bySender) {
    for (const item of list) {
      if (storedKeys.has(item.key)) prior.push(item.key);
      else fresh.push({ ...item, uid });
    }
  }
  let selected;
  if (prior.length + fresh.length <= limit) {
    selected = [...prior, ...fresh.map(({ key }) => key)].sort();
  } else {
    const room = Math.max(0, limit - prior.length);
    const byFreshSender = new Map();
    for (const item of fresh) {
      const list = byFreshSender.get(item.uid) || [];
      list.push(item);
      byFreshSender.set(item.uid, list);
    }
    const chosen = new Map([...byFreshSender.keys()].map((uid) => [uid, 0]));
    for (let count = 0; count < room; count++) {
      const next = [...byFreshSender.keys()].filter((uid) => chosen.get(uid) < byFreshSender.get(uid).length)
        .sort((a, b) => chosen.get(a) - chosen.get(b) || a.localeCompare(b))[0];
      if (next === undefined) break;
      chosen.set(next, chosen.get(next) + 1);
    }
    selected = [...prior, ...[...byFreshSender].flatMap(([uid, list]) =>
      list.slice(0, chosen.get(uid)).map(({ key }) => key))].sort();
  }
  memory.savedKeys = new Set(selected);
  try {
    localStorage.setItem(recoveryShownStorageKey(context.blockNum, context.groupId, context.uid),
      JSON.stringify({ v: 1, identity: memory.identity, keys: selected }));
    memory.storedKeys = new Set(selected);
  } catch { /* 保存できなくても画面と提出は続ける */ }
}

function flushRecoveryShownKeys(memory) {
  if (!memory.timer) return;
  clearTimeout(memory.timer);
  saveRecoveryShownKeys(memory);
}

function rememberRecoveryShownSeparator(message, key, readers) {
  const memory = recoveryShownMemory;
  if (!memory.loaded) return;
  const closeAt = submissionChatCloseAt();
  const memberUids = new Set(state.members.map((member) => member.uid));
  if ([...(readers || [])].some((uid) => uid !== state.uid && uid !== message.uid && memberUids.has(uid))
    || !validRecoveryShownKey(key) || !Number.isSafeInteger(closeAt)
    || !Number.isSafeInteger(message.timestamp) || message.uid === state.uid
    || !state.members.some((member) => member.uid === message.uid)
    || message.timestamp < closeAt - RECEIPT_FRESH_WINDOW_MS || message.timestamp >= closeAt
    || memory.savedKeys.has(key)) return;
  memory.savedKeys.add(key);
  if (!memory.timer) memory.timer = setTimeout(() => flushRecoveryShownKeys(memory), 50);
}
function recoveryShownKeys() {
  const identity = `${state.blockNum}|${state.groupId}|${state.uid}`;
  if (recoveryShownMemory.identity !== identity) {
    flushRecoveryShownKeys(recoveryShownMemory);
    recoveryShownMemory = { identity, keys: new Set(), savedKeys: new Set(), storedKeys: new Set(), loaded: false, timer: null };
  }
  if (state.relay && rosterReady() && Array.isArray(state.members)
    && state.members.length >= 3 && state.members.length <= 5) {
    recoveryShownMemory.saveContext = { relay: state.relay, members: state.members,
      uid: state.uid, blockNum: state.blockNum, groupId: state.groupId };
  }
  if (!recoveryShownMemory.loaded && rosterReady() && Number.isSafeInteger(state.blockNum)
    && Number.isSafeInteger(state.groupId) && typeof state.uid === 'string'
    && Array.isArray(state.members) && state.members.length >= 3 && state.members.length <= 5
    && state.members.some((member) => member.uid === state.uid)) {
    const saved = loadRecoveryShownKeys(identity);
    recoveryShownMemory.loaded = true;
    recoveryShownMemory.savedKeys = new Set(saved);
    recoveryShownMemory.storedKeys = new Set(saved);
    for (const key of saved) recoveryShownMemory.keys.add(key);
  }
  return recoveryShownMemory.keys;
}
// S3R4-U-OVERCAP: 提出と同じ確認済み窓・名簿で上限の外の他人の発言を決める。
// 描画の相はこの門に入れない。提出は期間境界でも名簿と窓があれば欄を組む。
function recoveryOvercapHiddenKeys() {
  const confirmedWindow = submissionChatWindow();
  if (!rosterReady() || !state.relay
    || !Number.isSafeInteger(confirmedWindow?.startMs) || !Number.isSafeInteger(confirmedWindow?.endMs)) return null;
  const messages = state.relay.getMessages() || [];
  const revision = state.receiptSelectionRevision || 0;
  const rawCaps = state.cfg.pins.chatCaps;
  const admittedReceipts = recoveryAdmittedReceipts();
  if (overcapHiddenMemo?.messages === messages && overcapHiddenMemo.revision === revision
    && overcapHiddenMemo.startMs === confirmedWindow.startMs && overcapHiddenMemo.endMs === confirmedWindow.endMs
    && overcapHiddenMemo.rawCaps === rawCaps && overcapHiddenMemo.members === state.members
    && overcapHiddenMemo.receipts === admittedReceipts) return overcapHiddenMemo.value;
  const value = clientReceiptCapExcluded(messages, admittedReceipts, {
    blockNum: state.blockNum, groupId: state.groupId, myUid: state.uid, chatWindow: confirmedWindow,
    caps: normalizeChatCaps(rawCaps), compare: canonicalComparatorV2(state.relay.getMsgKey),
    getClientMsgKey: state.relay.getMsgKey, memberUids: state.members.map((member) => member.uid),
  });
  overcapHiddenMemo = { messages, revision, startMs: confirmedWindow.startMs,
    endMs: confirmedWindow.endMs, rawCaps, members: state.members, receipts: admittedReceipts, value };
  return value;
}

// 🔴 §6.9（規則版数5）: 見る人と標的以外の受領証明がある、見える投票。
// MIRROR: 本体 `src/components/game/ChatPhase.js` の `hasVisibleConfirmedVote`。
function hasVisibleConfirmedVote(targetUid, atMs) {
  const votes = state.observedActions.votes || {};
  const receipts = clientChatSourcedReceipts(state.receipts, submissionChatWindow(), submissionChatCloseAt());
  return hasTimestampVisibleConfirmedVote({
    votes: [votes[targetUid], ...(votes[`${targetUid}__extras`] || [])],
    ownUid: state.uid, targetUid, nowMs: atMs,
    receiptorsForVote: (vote) => {
      const hash = actionHashV2('vote', state.blockNum, state.groupId, targetUid, vote.encrypted, vote.timestamp);
      return receipts.filter((rc) => rc.actionHash === hash && isReceiptTimely(rc.timestamp, vote.timestamp))
        .map((rc) => rc.receiverUid);
    },
  });
}

function canReportTarget(targetUid, atMs) {
  const closeAt = submissionChatCloseAt();
  return (Number.isSafeInteger(closeAt) && atMs >= closeAt - VOTE_RECEIPT_CUTOFF_MS)
    || hasVisibleConfirmedVote(targetUid, atMs);
}

// 自分の発信（投票/密告）が他メンバーの受領証明を得たか（受領待ち→確定の表示用）
function actionReceipted(actorUid, actionType, action) {
  if (!action?.encrypted || action.timestamp == null) return false;
  const h = actionHashV2(actionType, state.blockNum, state.groupId, actorUid, action.encrypted, action.timestamp);
  const set = new Set();
  for (const rc of clientChatSourcedReceipts(state.receipts, submissionChatWindow(), submissionChatCloseAt())) {
    // K-S6-005: 発信時刻から ±10分以内の受領証明だけを数える（採点と同一）
    if (rc.actionHash === h && isReceiptTimely(rc.timestamp, action.timestamp)) set.add(rc.receiverUid);
  }
  return [...set].some((u) => u !== actorUid);
}

// v3.3: 自分の投票がvoid（発信から10分経過・他メンバーの受領証明なし＝なかったこと）。
// voidになったら同一対象への再送のみ可能（対象変更は不可＝受領証明捏造による
// 対象矛盾フレーミングを構造的に排除する。本体 ChatPhase.myVoteVoid と同じ判定）。
function myVoteIsVoid() {
  return !!state.myVote?.timestamp && !actionReceipted(state.uid, 'vote', state.myVote)
    && (clientNow() - state.myVote.timestamp) > RECEIPT_FRESH_WINDOW_MS;
}

// v3.3: 自分の各密告対象の状態（receipted > pending > void）。同一対象への複数発信（再送）は
// 最良状態を採用。voidの対象のみ再送可能（本体 ChatPhase.reportTargetStatus と同じ判定）。
function reportTargetStatusMap() {
  const rank = { receipted: 3, pending: 2, void: 1 };
  const status = {};
  const now = clientNow();
  for (const r of (state.myReports || [])) {
    if (!r?.encrypted || r.timestamp == null) continue;
    const tgt = decryptSelfTarget(r.encrypted);
    if (!tgt) continue;
    const st = actionReceipted(state.uid, 'report', r) ? 'receipted'
      : ((now - r.timestamp) > RECEIPT_FRESH_WINDOW_MS ? 'void' : 'pending');
    if (!status[tgt] || rank[st] > rank[status[tgt]]) status[tgt] = st;
  }
  return status;
}

// P2P で観測した自己アクション（別クライアント発行）を提出物 state に注入する。
// 罠回避の要: intent は付けない（平文不明＝A-3自己検証をスキップ）＋観測が入ったら
// 該当種別のローカル入力をロック（intent が混ざると A-3 の mismatch で提出拒否になる）。
function handleSelfAction(type, inner) {
  try {
    if (type === 'receipt') {
      // 別クライアントが発行した自分の受領証明も観測分として同梱（union正典の材料）
      // K-S6-002: 形式が不正な参照は取り込まない（本体 useGameWebSocket と同一規則）
      const receipt = { receiverUid: inner.receiverUid, timestamp: inner.timestamp, signature: inner.signature };
      if (Array.isArray(inner.msgRefs)) {
        if (inner.msgRefs.length === 0 || !inner.msgRefs.every(isMsgRef)) return;
        receipt.msgRefs = inner.msgRefs;
        receipt.senderUid = inner.senderUid;
      } else if (isActionHash(inner.actionHash)) {
        receipt.actionHash = inner.actionHash;
      } else {
        return;
      }
      mergeReceipts([{ ...receipt,
        _chainSeenAt: inner._chainSeenAt, _deviceSeenAt: inner._deviceSeenAt,
        _chatSources: inner._chatSources,
      }]);
      return;
    }
    if (type !== 'action') return;
    observeOtherSessionItem(inner, inner.uid);
    if (inner.actionType === 'vote') {
      state.observedP2P.vote = true;
      if (!state.myVote) { state.myVote = { encrypted: inner.encrypted, signature: inner.signature, timestamp: inner.timestamp }; renderGame(); }
      else if (inner.signature !== state.myVote.signature && !state.myVotePrev.some((p) => p.signature === inner.signature)) {
        // v3.3: 別クライアント発の別署名投票（再送）は旧発信履歴へ＝提出時の受領済み選択の材料
        state.myVotePrev.push({ encrypted: inner.encrypted, signature: inner.signature, timestamp: inner.timestamp });
      }
    } else if (inner.actionType === 'report') {
      // 自分の密告(game.js 等の別クライアント発・自セッションのエコー含む)を myReports に取り込む。
      // 署名で重複排除・最大2件。ロックは observedP2P.report の全ロックではなく密告相手の distinct 数で
      // 判定する（renderActionPanel の knownReportTargets）ので、観測1件＋ツールで1件追加＝計2件まで
      // 出せる。observedP2P.report は診断表示用に残すのみ（ゲーティングには使わない）。
      const bySig = state.myReports.some((r) => r.signature === inner.signature);
      const target = decryptSelfTarget(inner.encrypted);
      const isSelfMade = bySig || (target && state.intent.reports.includes(target));
      if (!isSelfMade) state.observedP2P.report = true;
      // v3.3: 上限はエントリ数でなく distinct 対象数（同一対象の再送は枠を消費しない・枠=2）
      const knownTargets = new Set(state.myReports.map((r) => decryptSelfTarget(r.encrypted)).filter(Boolean));
      const maxReports = state.cfg.pins.maxReports;
      const capBlocked = target
        ? (!knownTargets.has(target) && knownTargets.size >= maxReports)
        : state.myReports.length >= maxReports;
      if (!bySig && !capBlocked) {
        state.myReports.push({ encrypted: inner.encrypted, signature: inner.signature, timestamp: inner.timestamp });
        renderGame();
      }
    }
  } catch (e) { log(`self-action observe failed: ${e.message}`); }
}

// ============================================================
// 🔴 P-2026-0844（2026-08-09・ラウンド22 タスク2-a）: チャット送信側の上限ゲート。
//    MIRROR: 本体 `src/components/game/ChatPhase.js` の `handleSend` の4ゲート。
//
//    これが1つも無かったため、復元クライアントでは1メッセージ上限（半角1,000字）超の
//    貼り付けが**警告ゼロで送信でき**、画面は緑のまま採点だけが落ちていた。
//    実測（30字×19通＋501字の貼り付け1通・全角）: 画面 2,142字/20ターン（両方緑）に対し
//    採点は 1,140字/**19ターン** → `min_messages` で失格・0点。
//    採点側の `applyChatCaps` が「①1メッセージが maxMsgChars 超 → そのメッセージを除外」を
//    無言で適用するためで、利用者には何の手がかりも出ない。
// ============================================================

// キャップ判定に使う「自分のチャット総量」（未読込みの生カウント）。
// 本体は `charCounts[myUid]` / `messageCounts[myUid]`（手元の全発言の総量）を見るが、
// 復元クライアントにはサーバーが無いので正準マージ済み集合から同じものを数える。
function myRawChatTotals() {
  const mine = (state.relay?.getMessages() || []).filter((m) => m && m.uid === state.uid);
  return {
    chars: mine.reduce((s, m) => s + countHalfWidthChars(m.text || ''), 0),
    msgs: mine.length,
  };
}

// 送信抑止の理由（null = 送信可）。本体 handleSend と同じ順序・同じ判定。
// 不可視文字ゲートは `stripInvisibleChars(text).length === 0` と同値の `hasVisibleContent`
// （正典 char-counter.js・relay-client.js の J-17 受信ゲートと同一述語）を使う。
function chatSendBlockReason(text) {
  const trimmed = (text || '').trim();
  if (!trimmed) return 'empty';
  if (!hasVisibleContent(trimmed)) return 'invisible';          // ①可視内容ゼロ
  const caps = normalizeChatCaps(state.cfg.pins.chatCaps);
  const chars = countHalfWidthChars(trimmed);
  if (chars > caps.maxMsgChars) return 'msgTooLong';            // ②1メッセージ上限
  const raw = myRawChatTotals();
  if (raw.msgs + 1 > caps.maxMessages) return 'maxMsgs';        // ③発言数上限
  if (raw.chars + chars > caps.maxChars) return 'maxChars';     // ④総文字数上限
  return null;
}

// 抑止理由の表示文（送信ボタンの上に出す警告。本体の `msgTooLong` 警告行に相当）。
function chatSendBlockText(reason) {
  const caps = normalizeChatCaps(state.cfg.pins.chatCaps);
  if (reason === 'invisible') return state.tr('recovery.chat.invisibleOnly');
  if (reason === 'msgTooLong') return state.tr('recovery.chat.msgTooLong', { max: caps.maxMsgChars });
  if (reason === 'maxMsgs') return state.tr('recovery.chat.maxMsgsReached');
  if (reason === 'maxChars') return state.tr('recovery.chat.maxCharsReached');
  return '';
}

// 「画面 ≡ この端末が提出できるもの」: 正典の共有 helper へ caps と正準比較器を渡す。
function locallyProvableMessages(msgs) {
  const list = Array.isArray(msgs) ? msgs : [];
  if (state.blockNum == null || state.groupId == null) return list;
  const confirmedWindow = submissionChatWindow();
  const selectedReads = selectedReadReceiptsForDisplay(list, confirmedWindow);
  if (provableMessagesMemo?.messages === list && provableMessagesMemo.selected === selectedReads
    && provableMessagesMemo.revision === (state.receiptSelectionRevision || 0)
    && provableMessagesMemo.startMs === confirmedWindow?.startMs
    && provableMessagesMemo.endMs === confirmedWindow?.endMs
    && provableMessagesMemo.rawCaps === state.cfg.pins.chatCaps) return provableMessagesMemo.value;
  const getClientMsgKey = state.relay?.getMsgKey || buildMsgKeyGetter(state.blockNum, state.groupId);
  const compareCanonical = canonicalComparatorV2(getClientMsgKey);
  function scoreCurrentMessages() {
    return clientScoreableMessages(list, selectedReads, {
      blockNum: state.blockNum, groupId: state.groupId, myUid: state.uid,
      chatWindow: confirmedWindow,
      caps: normalizeChatCaps(state.cfg.pins.chatCaps), compare: compareCanonical, getClientMsgKey,
      claimMemo: currentRecoveryClaimMemo(),
    });
  }
  const value = scoreCurrentMessages();
  provableMessagesMemo = { messages: list, selected: selectedReads,
    revision: state.receiptSelectionRevision || 0, startMs: confirmedWindow?.startMs,
    endMs: confirmedWindow?.endMs, rawCaps: state.cfg.pins.chatCaps, value };
  return value;
}

// 最低条件と投票前の案内は、同じ既読付き進捗を表示する。
function myReceiptedChatProgress(msgs, now = clientNow()) {
  const readers = readersByMsgKey();
  const receiptedMsgs = locallyProvableMessages(msgs).filter((m) => {
    const k = msgRefOf(computeMsgKeyV2(state.blockNum, state.groupId, m));
    return isTimestampVisible(m.timestamp, now)
      && readers[k] && [...readers[k]].some((u) => u !== m.uid);
  });
  const mine = receiptedMsgs.filter((m) => m.uid === state.uid);
  return {
    chars: mine.reduce((s, m) => s + countVisibleChars(m.text || ''), 0),
    turns: countMessageTurns(filterVisibleMessages(receiptedMsgs))[state.uid] || 0,
  };
}

let recoveryPriorityLock = { key: null, record: null, verified: false, loading: false, stored: 'unknown' };
function recoveryPriorityLockKey() {
  try {
    if (!rosterReady()) return null;
    return priorityLockStorageKey({ blockNum: state.blockNum, groupId: state.groupId, uid: state.uid,
      rosterHash: state.rosterAnchorHash?.toLowerCase(), chatWindow: submissionChatWindow() });
  } catch { return null; }
}
function recoveryPriorityLockContext() {
  return { blockNum: state.blockNum, groupId: state.groupId, myUid: state.uid,
    members: state.members, rosterHash: state.rosterAnchorHash?.toLowerCase(),
    chatWindow: submissionChatWindow() };
}
function loadRecoveryPriorityLock() {
  try {
    const key = recoveryPriorityLockKey();
    if (recoveryPriorityLock.key !== key)
      recoveryPriorityLock = { key, record: null, verified: false, loading: false, stored: 'unknown' };
    if (!key || recoveryPriorityLock.loading || recoveryPriorityLock.stored !== 'unknown') return;
    recoveryPriorityLock.loading = true;
    let record;
    try { const raw = localStorage.getItem(key); record = raw === null ? null : JSON.parse(raw); }
    catch { recoveryPriorityLock.loading = false; recoveryPriorityLock.stored = 'rejected'; return; }
    if (record === null) { recoveryPriorityLock.loading = false; recoveryPriorityLock.stored = 'absent'; return; }
    const ctx = recoveryPriorityLockContext();
    verifyPriorityLock(record, ctx, { verify: verifyMessage }).then((ok) => {
      if (recoveryPriorityLock.key !== key) return;
      recoveryPriorityLock.loading = false;
      recoveryPriorityLock.stored = ok ? 'verified' : 'rejected';
      if (ok) { recoveryPriorityLock.record = record; recoveryPriorityLock.verified = true; }
    }).catch(() => {
      if (recoveryPriorityLock.key === key) {
        recoveryPriorityLock.loading = false; recoveryPriorityLock.stored = 'rejected';
      }
    });
  } catch { /* A storage error must not turn a valid screen plan into failed. */ }
}
function noteRecoveryScreenPlan(plan) {
  try {
    const key = recoveryPriorityLockKey();
    if (!key || recoveryPriorityLock.key !== key || recoveryPriorityLock.record || plan?.failed
      || plan?.turns < GUEST_PINNED_RULES.minMessages) return;
    let existing;
    try { existing = localStorage.getItem(key); }
    catch { existing = 'unreadable'; showPersistenceWarning('priority lock'); }
    if (existing !== null && existing !== 'unreadable' && recoveryPriorityLock.stored !== 'rejected') return;
    const ctx = recoveryPriorityLockContext();
    const record = priorityLockFromPlan(plan, ctx);
    if (!record) return;
    recoveryPriorityLock.record = record;
    if (existing === null) {
      let canWrite = false;
      try {
        const prefix = `priorityLock_v1_${state.blockNum}_${state.groupId}_${state.uid}_`;
        let count = 0;
        for (let i = 0; i < localStorage.length; i++) if (localStorage.key(i)?.startsWith(prefix)) count++;
        canWrite = count < 2;
      } catch { canWrite = false; }
      if (canWrite) {
        try { localStorage.setItem(key, JSON.stringify(record)); }
        catch { showPersistenceWarning('priority lock'); }
      }
    }
    verifyPriorityLock(record, ctx, { verify: verifyMessage }).then((ok) => {
      if (ok && recoveryPriorityLock.key === key) recoveryPriorityLock.verified = true;
    }).catch(() => {});
  } catch { /* The screen plan remains authoritative when storage fails. */ }
}
function usableRecoveryLock() {
  try { return recoveryPriorityLock.key === recoveryPriorityLockKey() && recoveryPriorityLock.verified
    ? recoveryPriorityLock.record : null; } catch { return null; }
}

let screenPlanMemo = null;
// 提出時の束と同じ材料を、既存の約1秒の再描画に合わせて計画する。
function recoveryScreenPlan() {
  const phase = currentPhase(), confirmedWindow = submissionChatWindow();
  const rosterConfirmed = rosterReady();
  const ready = (phase === 'chatting' || phase === 'submitting') && rosterConfirmed && !!state.relay
    && priorityReady({ rosterConfirmed, members: state.members, myUid: state.uid,
      chatWindow: confirmedWindow, canSignSelf: !!state.identity?.signKey });
  const identity = `${state.blockNum}|${state.groupId}|${state.uid}|${confirmedWindow?.startMs}|${confirmedWindow?.endMs}|${ready}`;
  const now = performance.now();
  if (screenPlanMemo?.identity === identity && now - screenPlanMemo.at < 1000) return screenPlanMemo.value;
  let value = null;
  let errorText = null;
  if (ready) {
    try {
      loadRecoveryPriorityLock();
      value = planPriority({ messages: state.relay.getMessages() || [], myUid: state.uid, members: state.members,
        blockNum: state.blockNum, groupId: state.groupId, chatWindow: confirmedWindow,
        receipts: clientChatSourcedReceipts(recoveryAdmittedReceipts(), confirmedWindow, submissionChatCloseAt()),
        ...separatorPoint(clientNow(), submissionChatCloseAt()),
        shownMessageKeys: recoveryShownKeys(),
        hiddenMessageKeys: recoveryOvercapHiddenKeys() });
      noteRecoveryScreenPlan(value);
    } catch (error) {
      errorText = String(error?.message || error);
      if (screenPlanMemo?.errorText !== errorText) log(`priority plan failed: ${errorText}`);
      value = { ...EMPTY_PRIORITY_PLAN, failed: true };
    }
  }
  const sigKey = value && !value.failed
    ? planReceiptSignatures(value).join('|') : null;
  if (phase === 'chatting' && sigKey !== null && sigKey !== screenPlanMemo?.sigKey)
    state.relay.setPriorityReceiptSignatures?.(sigKey ? sigKey.split('|') : []);
  screenPlanMemo = { identity, at: now, value, sigKey, errorText };
  return value;
}
function myShownProgress(msgs, now = clientNow()) {
  const local = myReceiptedChatProgress(msgs, now);
  const plan = recoveryScreenPlan();
  const guarantee = plan ? (plan.failed ? 0 : Math.max(plan.turns,
    usableRecoveryLock() ? GUEST_PINNED_RULES.minMessages : 0)) : 0;
  return { chars: local.chars, local: local.turns, guarantee, ready: plan !== null,
    failed: plan?.failed === true,
    turns: shownTurnCount(guarantee, local.turns, GUEST_PINNED_RULES.minMessages) };
}

// --- チャット発言（signKey署名） ---
function p2pSendReady() {
  if (state.relay?.canPublish()) return true;
  log(`⚠ ${state.uid}: P2P なし（発言・投票・密告を送れません）`);
  return false;
}

async function sendChat(text) {
  if (!rosterReady()) return;
  if (!p2pSendReady()) return;
  if (state.relay?.ownHistoryReady !== true) { log('chat not sent: history is loading'); return; }
  // 🔴 最終防波堤（P-2026-0844）: `publishChat` は `addOwnMessage` で自分の canon へ直接
  //    マージするので、受信側の `_verifyChat`（J-17 の可視内容ゲート）を**通らない**。
  //    ここで止めないと不可視文字だけの発言がローカル集合と提出バンドルに載り、
  //    画面と採点がまた食い違う（chatHash の原像にだけ入る「幽霊」）。
  const blocked = chatSendBlockReason(text);
  if (blocked) { log(`chat not sent (${blocked}): ${chatSendBlockText(blocked)}`); return; }
  try {
    const ts = clientNow();
    // 本体 handleSend と同じく trim 後の本文に署名して送る（ゲートも trim 後で数えている＝
    // 空白を足して1メッセージ上限を素通りさせられない）。
    const normalized = (text || '').trim();
    const account = privateKeyToAccount(state.identity.signKey);
    const signature = canonicalizeSignature(await account.signMessage({ message: chatSignStringV2(state.blockNum, state.groupId, state.uid, normalized, ts) }));
    state.ownSessionSignatures.add(signature);
    const signedMsg = { uid: state.uid, text: normalized, timestamp: ts, signature };
    if (!rosterReady()) return;
    if (!p2pSendReady() || !await state.relay.publishChat(signedMsg)) return;
    log(`sent chat (${normalized.length} chars)`);
  } catch (e) { log(`chat failed: ${e.message}`); }
}

// --- 投票 / 密告（one-shot発信・signKey署名・対象は encryptKey で自己暗号化） ---
// 本体 ChatPhase の handleVote/handleReport と同じく、取り消せない操作なので確認ダイアログを
// 挟み、完了を明示する。確認はローカル状態を変える前に出す（キャンセルで何も起きない）。
async function sendVote(targetUid) {
  const warningAccepted = state.voteWarningAccepted;
  state.voteWarningAccepted = false;
  if (!rosterReady()) return;
  if (!p2pSendReady()) return;
  const voteCloseAt = submissionChatCloseAt();
  if (Number.isSafeInteger(voteCloseAt) && clientNow() >= voteCloseAt - VOTE_RECEIPT_CUTOFF_MS) return;
  // v3.3: void（10分経過・受領なし＝なかったこと）になった場合のみ同一対象へ再送可能
  const isResend = !!state.myVote;
  if (isResend) {
    const prevTarget = state.intent.vote || decryptSelfTarget(state.myVote.encrypted);
    if (!myVoteIsVoid() || targetUid !== prevTarget) return;
  }
  const progress = myShownProgress(state.relay?.getMessages() || []);
  if (!warningAccepted && (progress.turns < GUEST_PINNED_RULES.minMessages || progress.chars < state.cfg.pins.minChars)) {
    state.pendingVoteWarningKey = progress.turns < GUEST_PINNED_RULES.minMessages ? 'turns' : 'chars';
    state.pendingVoteTarget = targetUid;
    renderGame();
    return;
  }
  if (!window.confirm(recoveryPointedText(isResend ? 'recovery.action.voteResendConfirm' : 'recovery.action.voteConfirm', 'name', targetUid))) return;
  try {
    const ts = clientNow();
    const sendCloseAt = submissionChatCloseAt();
    if (Number.isSafeInteger(sendCloseAt) && ts >= sendCloseAt - VOTE_RECEIPT_CUTOFF_MS) {
      window.alert(state.tr('recovery.action.votingClosed'));
      return;
    }
    const encrypted = encryptAction({ targetUid }, state.identity.encryptKey);
    const account = privateKeyToAccount(state.identity.signKey);
    const signature = canonicalizeSignature(await account.signMessage({ message: actionSignStringV2('vote', state.blockNum, state.groupId, state.uid, encrypted, ts) }));
    state.ownSessionSignatures.add(signature);
    if (!rosterReady()) return;
    if (!p2pSendReady()) return;
    // v3.3: 再送時は旧発信を履歴へ退避（旧発信に遅延受領があっても提出物へ「受領済みの方」を
    // 同梱できる＝取下げ冤罪防止。本体 useGameWebSocket.sendVote の myVotePrev_ と同一キー）
    if (!await state.relay.publishAction('vote', { encrypted, signature, timestamp: ts })) return;
    if (state.myVote?.encrypted && state.myVote.encrypted !== encrypted) {
      if (!state.myVotePrev.some((v) => v.signature === state.myVote.signature)) {
        state.myVotePrev.push({ encrypted: state.myVote.encrypted, signature: state.myVote.signature, timestamp: state.myVote.timestamp });
      }
      try { localStorage.setItem(`myVotePrev_${state.blockNum}_user${state.uid}`, JSON.stringify(state.myVotePrev)); }
      catch { showPersistenceWarning('vote history'); }
    }
    state.myVote = { encrypted, signature, timestamp: ts };
    state.intent.vote = targetUid;
    log(`voted for ${targetUid}${isResend ? ' (resend)' : ''}`);
    renderGame();
    window.alert(state.tr('recovery.action.voteSuccess'));
  } catch (e) { log(`vote failed: ${e.message}`); }
}
async function sendReport(targetUid) {
  const warningAccepted = state.reportWarningAccepted;
  state.reportWarningAccepted = false;
  if (!rosterReady()) return;
  if (!p2pSendReady()) return;
  // v3.3: 同一対象がvoid（10分経過・受領なし）の場合のみ再送を許可。
  // 正直な画面では void の対象も2枠に数え、同じ対象への再送だけを許す。
  const repStatus = reportTargetStatusMap();
  const knownTargets = [...new Set([
    ...(state.intent.reports || []),
    ...state.myReports.map((r) => decryptSelfTarget(r.encrypted)).filter(Boolean),
  ])];
  const isResend = knownTargets.includes(targetUid);
  const maxReports = state.cfg.pins.maxReports;
  if (isResend && repStatus[targetUid] !== 'void') return;
  // 密告の2枠は、最初の受領証明の時刻が早い順の2人で決まる。受領証明の無い（void の）
  // 密告は、その後でだけ枠を取る。正直な画面は void の対象も2枠に数え、3人目への密告を出させない。
  if (Object.keys(repStatus).length >= maxReports && !isResend) {
    log(`max ${maxReports} reports`);
    return;
  }
  const reportNow = clientNow();
  if (!canReportTarget(targetUid, reportNow)) return;
  const soleTarget = soleRemainingReportTarget({
    members: state.members.map((member) => member.uid), selfUid: state.uid, targetUid,
    alreadyReported: new Set(knownTargets),
    isEligible: (memberUid) => hasVisibleConfirmedVote(memberUid, reportNow),
  });
  if (!warningAccepted && soleTarget === targetUid) {
    state.pendingReportWarningTarget = targetUid;
    renderGame();
    return;
  }
  if (!window.confirm(recoveryPointedText(isResend ? 'recovery.action.reportResendConfirm' : 'recovery.action.reportConfirm', 'name', targetUid))) return;
  try {
    const ts = clientNow();
    if (!canReportTarget(targetUid, ts)) return;
    let ground = null;
    try {
      ground = collectReportGround({
        blockNum: state.blockNum, groupId: state.groupId, selfUid: state.uid, targetUid, reportTimestamp: ts,
        votes: [state.observedActions.votes?.[targetUid], ...(state.observedActions.votes?.[`${targetUid}__extras`] || [])],
        receipts: state.receipts, chatWindow: submissionChatWindow(), chatCloseAt: submissionChatCloseAt(),
      });
    } catch { ground = null; }
    const encrypted = encryptReportDeterministic(targetUid, state.identity.encryptKey,
      { blockNum: state.blockNum, groupId: state.groupId });
    const account = privateKeyToAccount(state.identity.signKey);
    const signature = canonicalizeSignature(await account.signMessage({ message: actionSignStringV2('report', state.blockNum, state.groupId, state.uid, encrypted, ts) }));
    state.ownSessionSignatures.add(signature);
    if (!rosterReady()) return;
    if (!p2pSendReady()) return;
    if (ground?.votes?.length) {
      try { saveReportGround(signature, ground); }
      catch { state.reportGroundSaveFailed = true; showPersistenceWarning('report grounds'); }
    }
    if (!await state.relay.publishAction('report', { encrypted, signature, timestamp: ts })) return;
    state.myReports.push({ encrypted, signature, timestamp: ts });
    // intent は「自分が出した密告の平文相手」。P2P観測分(game.js 等で先に出した自分の密告)も自分の
    // encryptKey で復号でき自分の密告と確定するので、提出物が観測分＋今回分の両方を含むよう intent に
    // 全 distinct 相手を載せる（bundle.js の intent フィルタで観測分が落ちず、A-3 は全集合一致で通過）。
    state.intent.reports = [...new Set([
      targetUid,
      ...state.myReports.map((r) => decryptSelfTarget(r.encrypted)).filter(Boolean),
    ])];
    log(`reported ${targetUid}`);
    renderGame();
    window.alert(state.tr('recovery.action.reportSuccess'));
  } catch (e) { log(`report failed: ${e.message}`); }
}

// A-3 自己検証に渡す intent（自分が投じた内容の平文ローカル記録・vote/reports のみ）。
//
// 本体は localStorage の actionIntent_ を JSON.parse(... || 'null') で読むので、記録が無ければ
// intent 自体が null になり、照合は丸ごとスキップされる（別端末・別クライアントで行動した場合の
// 正常系）。復元クライアントの state.intent は常に {vote:null, reports:[]} という空の入れ物なので、
// 空の区画は渡さない（未知は「未知」として扱わせる）。
function selfVerifyIntent() {
  const vote = state.intent.vote || undefined;
  const reports = state.intent.reports?.length ? state.intent.reports : undefined;
  if (!vote && !reports) return null; // 何も知らない＝本体の intent=null と同じ
  return { vote: vote ?? null, reports: reports ?? [] };
}

// --- オンチェーン提出 tx の永続化（確認済みならボタンを隠して「提出済み: hash」表示） ---
// 本体 SubmissionPhase.js と同じキー体系（evidence_result_tx_{block}_user{uid}）。
function onchainTxKey(blockNum = state.blockNum, uid = state.uid) { return `evidence_result_tx_${blockNum}_user${uid}`; }
function loadOnchainTx(blockNum = state.blockNum, uid = state.uid) { try { return localStorage.getItem(onchainTxKey(blockNum, uid)) || null; } catch { return null; } }
function saveOnchainTx(hash, blockNum = state.blockNum, uid = state.uid) {
  try { localStorage.setItem(onchainTxKey(blockNum, uid), hash); return true; }
  catch { showPersistenceWarning('submission transaction'); return false; }
}
function shortHash(h) { return `${h.slice(0, 10)}…${h.slice(-8)}`; }

function saveReportGround(signature, ground) {
  if (!ground?.votes?.length) return;
  const next = mergeReportGrounds(loadReportGrounds(state.blockNum, state.uid), signature, ground);
  state.reportGrounds = mergeReportGroundMaps(state.reportGrounds, next);
  try { localStorage.setItem(REPORT_GROUNDS_KEY(state.blockNum, state.uid), JSON.stringify(next)); }
  catch { state.reportGroundSaveFailed = true; showPersistenceWarning('report grounds'); }
}

function renderSameDeviceBand(phase) {
  if ((phase !== 'chatting' && phase !== 'submitting') || loadOnchainTx()) return null;
  const reasons = sameDeviceBandReasons({
    grounds: mergeReportGroundMaps(state.reportGrounds, loadReportGrounds(state.blockNum, state.uid)),
    ownReportSignatures: state.myReports.map(report => report?.signature).filter(Boolean),
    saveFailed: state.reportGroundSaveFailed,
    conversationAtRisk: myShownProgress(state.relay?.getMessages() || []).turns >= GUEST_PINNED_RULES.minMessages
      && memorylessCandidateTurns(recoveryScreenPlan()) < GUEST_PINNED_RULES.minMessages,
  });
  if (!reasons.length) return null;
  return el('div', { className: 'warn', role: 'status' },
    ...reasons.map(reason => el('p', { textContent: state.tr(`recovery.sameDeviceBand.${reason}`) })));
}

function renderOwnHistoryPromptBand(phase) {
  if (phase !== 'chatting') return null;
  const prompt = state.relay?.ownHistoryPrompt?.();
  if (!prompt) return null;
  const band = el('div', { className: 'warn', role: 'status' });
  band.append(el('p', { textContent: state.tr('recovery.chat.ownHistoryPrompt') }));
  if (prompt.relays.length) band.append(el('p', { textContent: state.tr('recovery.chat.ownHistoryWaitingRelays', { relays: prompt.relays.join(', ') }) }));
  band.append(el('button', { type: 'button', textContent: state.tr('recovery.chat.ownHistoryWait'), onclick: () => { state.relay?.waitOwnHistory?.(); renderGame(); } }));
  band.append(el('button', { type: 'button', textContent: state.tr('recovery.chat.ownHistoryStart'), style: 'margin-left:8px;', onclick: () => { state.relay?.startWithoutOwnHistory?.(); renderGame(); } }));
  return band;
}

async function confirmCurrentRosterHash() {
  state.rosterCheckCount += 1;
  state.rosterPaused = true;
  renderGame();
  try {
    const latest = await waitForFinalRoster(true);
    if (!finalRosterHashMatches(latest, state.rosterAnchorHash, state.timeline.chattingStart)) {
      stopForChangedRoster();
      return false;
    }
    return true;
  } catch (error) {
    log('roster verification failed before submission (details are in the browser console)'); console.warn('[recovery] roster verification failed before submission:', error);
    return false;
  } finally {
    state.rosterCheckCount -= 1;
    if (!state.rosterInvalid && !state._rosterRefresh && state.rosterCheckCount === 0) state.rosterPaused = false;
    renderGame();
  }
}

function recoveryMyDepositIds() {
  const myMember = state.members.find((member) => member.uid === state.uid);
  let ids = [];
  let error = null;
  try {
    const depIds = myMember?.depIds;
    if (depIds) {
      const parsed = typeof depIds === 'string' ? JSON.parse(depIds) : depIds;
      ids = Array.isArray(parsed?.ids) ? parsed.ids : [];
    }
  } catch (caught) {
    error = caught;
    ids = [];
  }
  return { ids, error };
}

async function recoverySignReceiptAggregate(message) {
  if (!rosterReady()) throw new Error('roster changed during signing');
  const signature = canonicalizeSignature(
    await privateKeyToAccount(state.identity.signKey).signMessage({ message })
  );
  if (!rosterReady()) throw new Error('roster changed during signing');
  return signature;
}

function recoveryBundleArgs({ myDepositIds, chatWindow, priorityChatWindow, signWallet, submittedAt }) {
  return {
    priorityLock: usableRecoveryLock(),
    blockNum: state.blockNum, groupId: state.groupId, myUid: state.uid,
    encryptKey: state.identity.encryptKey,
    members: state.members, messages: state.relay.getMessages(), myDepositIds,
    myVote: state.myVote, myVotePrev: state.myVotePrev, myReports: state.myReports,
    reportGrounds: mergeReportGroundMaps(state.reportGrounds, loadReportGrounds(state.blockNum, state.uid)),
    observedActions: state.observedActions, receipts: recoveryAdmittedReceipts(),
    intent: selfVerifyIntent(),
    // §2.1b チャット量キャップ（本体 SubmissionPhase.js と同一規則で提出物へ適用）
    chatCaps: state.cfg.pins.chatCaps,
    // 🔴 J-40b（2026-08-09）: Evidence が宣言したチャット窓。受領証明の枠取りにだけ使う。
    chatWindow,
    rosterConfirmed: rosterReady(),
    hiddenMessageKeys: recoveryOvercapHiddenKeys(),
    ...separatorPoint(clientNow(), submissionChatCloseAt()),
    shownMessageKeys: new Set(recoveryShownKeys()),
    priorityChatWindow,
    chatCloseAt: submissionChatCloseAt(),
    signWallet,
    requireConfirmedWindow: false,
    signReceiptAggregate: recoverySignReceiptAggregate,
    ...(submittedAt === undefined ? {} : { submittedAt }),
  };
}

// --- 提出（結果窓） ---
async function reconstructAndSubmit() {
  const pressBlockNum = state.blockNum;
  const pressUid = state.uid;
  recoveryGuaranteePressing += 1;
  syncRecoverySubmitButtons();
  recoveryGuaranteeScheduler.cancel();
  recoveryGuaranteeFingerprint = null;
  try {
  if (!state.identity || !state.relay || !rosterReady()) { log('not ready'); return; }
  if (!await confirmCurrentRosterHash()) return;
  await pollLiveSnapshot();
  if (state.liveSubmittedSelf === true && !window.confirm(state.tr('recovery.submit.wsAckedOverwrite'))) return;
  const walletSigner = makeSigner(state.provider, state.address);
  const guardedWalletSigner = async (message) => {
    if (!rosterReady()) throw new Error('roster changed during signing');
    const signature = await walletSigner(message);
    if (!rosterReady()) throw new Error('roster changed during signing');
    return signature;
  };
  const { ids: myDepositIds, error: depositIdsError } = recoveryMyDepositIds();
  if (depositIdsError) log(`failed to parse deposit ids; continuing with an empty list: ${depositIdsError.message}`);
  let built;
  const submissionWindow = submissionChatWindow();
  const pressDecision = await recoveryPressFieldWindow(submissionWindow);
  if (pressDecision.kind === 'cancel') { log(state.tr('recovery.windowCompare.cancelled')); return; }
  if (!rosterReady()) { log('not ready'); return; }
  const priorityChatWindow = pressDecision.kind === 'window' ? pressDecision.fieldWindow
    : (pressDecision.kind === 'none' ? null : undefined);
  try {
    if (!Number.isSafeInteger(submissionChatCloseAt())) {
      log('⚠ 確認済みのチャット窓が読めないため、窓による受領証明の除外をせずに提出します');
    }
    // 提出時は受領証明の版が変わらない取り込みにも備え、その場の材料で再計算する。
    overcapHiddenMemo = null;
    built = await buildSubmissionBundle(recoveryBundleArgs({
      myDepositIds, chatWindow: submissionWindow, priorityChatWindow,
      signWallet: guardedWalletSigner,
    }));
  } catch (e) { log(`bundle build refused: ${e.code || e.message}`); return; }
  // localStorage 永続化（同一バイト再送のため）
  const chosenWindow = built.fieldWindow
    && (pressDecision.kind === 'window'
      || built.fieldWindow.startMs !== submissionWindow?.startMs
      || built.fieldWindow.endMs !== submissionWindow?.endMs)
    && (!state.timeline?._operatorUsed || pressDecision.kind === 'window')
    ? built.fieldWindow : null;
  saveRecoveryEvidencePayload(state.blockNum, state.uid, built.payload, null, chosenWindow);
  if (!isRecoveryEvidencePayloadPersistent(state.blockNum, state.uid)) {
    showVolatileRescueWarning();
  }
  log(`bundle built (${built.payload.length} bytes). submitting on-chain…`);
  try {
    const wc = makeWalletClient(state.provider, state.address);
    const countWalletAddress = state.address;
    // 送信に渡したブロックをその場で控え、待機後の state の変更で件数の読み先を取り違えない。
    let countBlockNum;
    // データ容量の事前チェック（2026-07-28・本体 SubmissionPhase.js と同一規則）
    let payload = built.payload;
    const plan = await planOnChainTrim(built.payload, state.uid, {
      chatWindow: submissionWindow,
    });
    if (plan?.impossible) {
      log(state.tr('recovery.trimImpossible'));
      const topUids = (plan.oversizeUids || []).slice(0, 3);
      if (topUids.length) {
        log(state.tr('recovery.trimImpossibleContributors', { uids: topUids.join(', ') }));
      }
      return;
    }
    if (plan) {
      let trimCheck = { status: 'failed', reason: 'error' };
      try {
        trimCheck = await checkTrimGuarantee(built.payload, plan, {
          blockNum: state.blockNum, groupId: state.groupId, myUid: state.uid, members: state.members,
          chatWindow: chosenWindow ?? submissionWindow, ownMessages: state.relay?.getMessages() || [],
          ownActions: {
            votes: [state.myVote, ...(state.myVotePrev || [])].filter(Boolean),
            reports: (state.myReports || []).filter(Boolean),
          },
        });
      } catch { trimCheck = { status: 'failed', reason: 'error' }; }
      const lines = describeTrimPlan(plan);
      const wsAcked = (state.submittedUids || []).some((uid) => String(uid) === String(state.uid));
      const essentialWarning = trimCheck.status !== 'ok' && plan.essentialEvidenceDropped
        ? `\n\n${state.tr('recovery.trimEssentialUnionWarning')}`
          + `\n${state.tr('recovery.trimEssentialOverrideWarning')}`
          + (wsAcked ? `\n${state.tr('recovery.trimEssentialCancelRecommended')}` : '')
        : '';
      const guarantee = Number.isSafeInteger(plan.gBefore) && plan.gBefore > 0
        ? `\n${state.tr('recovery.trimGuarantee', { gBefore: plan.gBefore, gAfter: plan.gAfter })}`
        : '';
      const trimLossWarning = formatTrimGuaranteeWarning(trimCheck, {
        translate: (key, params) => state.tr(key, params), prefix: 'recovery.',
        resolveName: (uid) => memberName(state.members.find((member) => member.uid === uid)),
        serverSubmitted: state.liveSubmittedSelf === true,
        separator: state.tr('recovery.submit.guarantee.nameSeparator'),
      });
      const ok = window.confirm(`${state.tr('recovery.trimNotice')}\n\n${lines}${guarantee}\n\n`
        + `${Math.round(plan.beforeBytes / 1024)}KB → ${Math.round(plan.afterBytes / 1024)}KB `
        + `(max ${Math.round(EVIDENCE_MAX_DATA_BYTES / 1024)}KB)`
        + trimLossWarning
        + essentialWarning);
      if (!ok) return;
      payload = await signTrimmedPayload(plan.trimmedBundle, {
        blockNum: state.blockNum, signMessage: guardedWalletSigner,
        compactContext: plan.compactContext,
      });
    }
    if (!rosterReady() || !await confirmCurrentRosterHash() || !rosterReady()) return;
    const res = await submitResultOnChain(wc, state.cfg.contracts.evidence,
      (countBlockNum = state.blockNum), payload,
      { rebuildProof: () => rebuildRecoveryRosterProof() });
    log(`confirmed: tx ${res.hash}, seq ${res.seq} (${res.byteLength} bytes)`);
    const sr = $('submit-result');
    if (sr) sr.textContent = state.tr('recovery.submitted');
    // 二重送信防止: 確認待ちの間はボタンを無効化する
    const btn = document.querySelector('#game-area .submitButton');
    if (btn) btn.disabled = true;
    // オンチェーンに載ったことを確認（1 confirmation）してから「提出済み: hash」を表示し
    // ボタンを非表示にする。reorg で覆らない限り確定。確認待ちに失敗した場合は tx がまだ
    // pending の可能性があるためボタンを戻して再送を許す（再送は無害＝重複提出可）。
    try {
      if (!state._client) throw new Error('chain client unavailable');
      if (res.receipt?.status !== 'success' || !res.seq) throw new Error('receipt sequence missing');
      const priorTxHash = loadOnchainTx(pressBlockNum, pressUid);
      saveOnchainTx(res.hash, pressBlockNum, pressUid);
      try { writeOnChainRecord(localStorage, pressBlockNum, pressUid,
        makeOnChainRecord(res.hash, payload, loadRecoveryEvidencePayload(pressBlockNum, pressUid), {
          chatWindow: loadRecoveryEvidencePayloadWindow(pressBlockNum, pressUid, built.payload),
          multiple: (() => { const previous = readOnChainRecord(localStorage, pressBlockNum, pressUid);
            return previous?.multiple === true
              || (state.rosterProof?.sharedWalletUids === 1 && res.resultCountOf >= 2)
              || !!((previous?.txHash || priorTxHash)
              && (previous?.txHash || priorTxHash) !== res.hash); })(),
        })); }
      catch { /* 表示用記録だけ */ }
      if (state.blockNum === pressBlockNum && state.uid === pressUid) {
        state.onchainTxHash = res.hash;
        state.evidenceSenderCount = res.resultCountOf;
        state.evidenceSenderCountWallet = countWalletAddress;
        state.evidenceSenderCountBlockNum = Number(countBlockNum);
        renderGame(); // 確定 → ボタンを消して「提出済み: hash」表示へ再描画
      }
      log(`confirmed on-chain: ${res.hash}`);
    } catch (e) {
      log(`confirmation failed or transaction was unsuccessful: ${e.message}`);
      if (sr) sr.textContent = '';
      if (btn) btn.disabled = false;
    }
  } catch (e) { log(`submit failed: ${e.message}`); }
  } finally {
    recoveryGuaranteePressing -= 1;
    syncRecoverySubmitButtons();
    recoveryGuaranteeFingerprint = null;
    scheduleRecoveryGuarantee();
  }
}

// ============================================================
// レンダリング — 本体 /game ページ（game.js + Game.module.css）を移植
// ============================================================

function memberName(m) {
  const summaryName = m?.summaryMeta?.name;
  if (typeof summaryName === 'string' && summaryName && summaryName.length <= 256) return summaryName;
  const rosterName = m?.name;
  if (typeof rosterName === 'string' && rosterName && rosterName.length <= 256) return rosterName;
  return m?.uid || '?';
}
function recoveryPlayerNumber(uid) { return state.rosterProofReady === true ? playerNumberOf(state.members, uid) : null; }
function recoveryPlayerLabel(uid) { const n = recoveryPlayerNumber(uid); if (n === null) return null; try { const label = state.tr('recovery.members.playerNumber', { n }); return typeof label === 'string' ? label : String(label ?? ''); } catch { return null; } }
function recoveryPlayerTitle(uid) { const label = recoveryPlayerLabel(uid); return label === null ? {} : { title: label }; }
function recoveryPointedText(key, param, uid) {
  const member = Array.isArray(state.members) ? state.members.find((x) => x?.uid === uid) : undefined;
  return pointedTemplateText(state.tr, key, param, reportWarningName(memberName(member)), recoveryPlayerLabel(uid));
}
function recoveryPointedElement(tag, props, prefix, key, param, member, shown = memberName(member)) {
  const parts = pointedTemplateParts(state.tr, key, param, shown, recoveryPlayerLabel(member?.uid));
  if (parts === null) return el(tag, { ...props, textContent: `${prefix}${state.tr(key, { [param]: shown })}` });
  return el(tag, props, ...(prefix ? [prefix] : []), ...parts.map((part) => typeof part === 'string' ? part : el('span', {}, part.name, el('span', { className: 'playerTag', textContent: part.tag }))));
}

// デポジットポイントはベンダリング済み採点正典へ委譲する（非正準weiは0）。
function depositPointsOf(m) {
  try {
    const depIds = m?.summaryMeta?.depIds;
    const d = typeof depIds === 'string' ? JSON.parse(depIds) : depIds;
    return calculateDepositPoints(d?.deposit || '0');
  } catch { return 0; }
}

function recoveryLockPointsIdentity() {
  if (!Array.isArray(state.members) || state.rosterProofReady !== true) return null;
  return `${state.blockNum}|${state.groupId}|${state.uid}|${state.rosterAnchorHash}|${JSON.stringify(state.members.map((m) => [m.uid, m.depIds]))}`;
}

async function refreshRecoveryLockPoints() {
  const identity = recoveryLockPointsIdentity();
  if (identity === null || !state._client || state.tabEnded || refreshRecoveryLockPoints.runningIdentity === identity) return;
  refreshRecoveryLockPoints.runningIdentity = identity;
  let byUid;
  try {
    if (!state.lockPointsCache) state.lockPointsCache = createLockPointsCache();
    byUid = await verifyRecoveryLockPoints({ client: state._client, blockNum: state.blockNum,
      members: state.members, contracts: state.cfg.contracts, timing: state.timing, cache: state.lockPointsCache });
  } catch {
    byUid = Object.create(null);
    for (const m of Array.isArray(state.members) ? state.members : []) byUid[m.uid] = { status: 'unverified' };
  } finally {
    if (refreshRecoveryLockPoints.runningIdentity === identity) refreshRecoveryLockPoints.runningIdentity = null;
  }
  if (!state.tabEnded && recoveryLockPointsIdentity() === identity) {
    state.lockPoints = { identity, byUid };
    scheduleRenderGame();
  }
}

function startRecoveryLockPoints() {
  clearInterval(state._lockPtsTimer);
  state.lockPoints = null;
  void refreshRecoveryLockPoints();
  state._lockPtsTimer = setInterval(refreshRecoveryLockPoints, LOCK_POINTS_REREAD_MS);
}

// 自己アクション（投票/密告）の暗号文は自分の encryptKey で自己暗号化されている（encryptAction）。
// game.js など別クライアントで投じた分は P2P 観測で state.myVote / state.myReports に暗号文だけが
// 入り、平文（相手 uid）は intent に載らない（intent 汚染＝提出の A-3 自己検証を乱すため意図的に空）。
// だが暗号文は自分の鍵で復号できるので、「誰に投じたか」を表示専用に復元する。
// ※ここで得た値は表示（ボタンのハイライト）だけに使い、state.intent には書き戻さない。
function decryptSelfTarget(encrypted) {
  if (!encrypted || !state.identity?.encryptKey) return null;
  try { return decryptAction(encrypted, state.identity.encryptKey)?.targetUid || null; }
  catch { return null; }
}

// 直近の活動時刻（ms）。プレゼンス（在席通知）プロトコルは無いので、署名済みの
// チャット/受領証明/発信で観測した最新の timestamp を使う。無言のメンバーは判別できない。
function lastActivityMap(msgs) {
  const at = {};
  const bump = (uid, ts) => {
    const n = Number(ts);
    if (!uid || !Number.isFinite(n)) return;
    if (!at[uid] || n > at[uid]) at[uid] = n;
  };
  for (const m of msgs) bump(m.uid, m.timestamp);
  for (const rc of Object.values(state.receipts)) bump(rc.receiverUid, rc.timestamp);
  for (const [u, v] of Object.entries(state.observedActions.votes || {})) {
    if (!u.endsWith('__extras')) bump(u, v?.timestamp);
  }
  for (const [u, arr] of Object.entries(state.observedActions.reports || {})) {
    for (const rep of (Array.isArray(arr) ? arr : [])) bump(u, rep?.timestamp);
  }
  return at;
}

function relayStatus() {
  const st = state.relay?.channel?.getRelayStatus?.();
  if (!st || !st.length) return 'disconnected';
  if (st.some((r) => r.status === 'connected')) return 'connected';
  if (st.some((r) => r.status === 'connecting')) return 'connecting';
  return 'disconnected';
}
function relayStatusClass() {
  return { connected: 'statusConnected', connecting: 'statusConnecting', disconnected: 'statusDisconnected' }[relayStatus()];
}
function relayStatusText() { return state.tr(`recovery.connection.${relayStatus()}`); }

// --- 接続状態モーダル（game.js の ConnectionModal 相当・リレー設定内蔵） ---
const CONN_COLOR = { connected: '#4caf50', connecting: '#ffb300', disconnected: '#f44336' };
let _connTimer = null;
function renderConnRelays() {
  const list = $('conn-relay-list');
  if (!list) return;
  const st = state.relay?.channel?.getRelayStatus?.() || [];
  const connected = st.filter((r) => r.status === 'connected').length;
  const title = $('conn-p2p-title');
  if (title) {
    title.textContent = state.tr('recovery.connection.p2p');
    if (st.length) {
      const badge = el('span', { textContent: `  ${state.tr('recovery.connection.relayConnected', { connected, total: st.length })}` });
      badge.style.color = connected > 0 ? '#4caf50' : '#f44336';
      badge.style.fontWeight = 'normal';
      title.append(badge);
    }
  }
  list.innerHTML = '';
  if (!st.length) { list.append(el('div', { className: 'muted', textContent: '—' })); return; }
  for (const { url, status } of st) {
    const row = el('div', { className: 'connRelayRow' });
    const left = el('div', { className: 'connLeft' });
    const dot = el('span', { className: 'connDot' }); dot.style.background = CONN_COLOR[status] || '#888';
    left.append(dot, el('span', { className: 'connUrl', textContent: url }));
    const label = el('span', { className: 'connStatusLabel', textContent: state.tr(`recovery.status.${status}`) });
    label.style.color = CONN_COLOR[status] || '#888';
    row.append(left, label);
    list.append(row);
  }
}
function openConnModal() {
  renderConnRelays();
  $('conn-modal').style.display = 'flex';
  clearInterval(_connTimer);
  _connTimer = setInterval(renderConnRelays, 2000);
}
function closeConnModal() { $('conn-modal').style.display = 'none'; clearInterval(_connTimer); }

// 現在フェーズの終端までの残り時間表示（本体 game.js の「残り時間: 0日 00:05:39」形式）
// v3.2: entry終端=応募終了(chatOpenAt) / waiting終端=実チャット開始(chattingStart・grace追従)
function timerText(phase, nowMs = clientNow()) {
  if (!state.timeline) return '';
  const tl = state.timeline;
  const endMs = phase === 'entry' ? tl.chatOpenAt
    : phase === 'waiting' ? tl.chattingStart
      : phase === 'chatting' ? tl.chatCloseAt
        : phase === 'submitting' ? tl.resultCloseAt : null;
  if (!endMs) return '';
  let s = Math.max(0, Math.floor((endMs - nowMs) / 1000));
  const d = Math.floor(s / 86400); s -= d * 86400;
  const hh = String(Math.floor(s / 3600)).padStart(2, '0');
  const mm = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
  const ss = String(s % 60).padStart(2, '0');
  return `${state.tr('recovery.timeRemaining')}: ${d}${state.tr('recovery.days')} ${hh}:${mm}:${ss}`;
}

// フォーカス保持: リレー更新の全再描画で入力中のフォーカスが飛ばないように
function focusKeyOf(elem) {
  if (!elem) return null;
  if (elem.classList?.contains('chatInput')) return 'chat';
  return null;
}
function restoreFocus(key) {
  if (!key) return;
  const target = key === 'chat' ? document.querySelector('.chatInput') : null;
  if (target && target !== document.activeElement) {
    target.focus();
    const len = target.value.length;
    try { target.setSelectionRange(len, len); } catch { /* selection 非対応要素 */ }
  }
}

// game-area は毎秒描き直すが、ダイアログの DOM とスクロールは表示内容が変わるまで保つ。
let modalRoot = null;
let modalRenderKey = null;
let modalContentRoot = null;
let clockModalRoot = null;
let clockModalRenderKey = null;
function ensureModalRoot() {
  if (!modalRoot || !modalRoot.isConnected) {
    modalRoot = el('div', { id: 'game-modal-root' });
    document.body.append(modalRoot);
    modalContentRoot = null;
    clockModalRoot = null;
    modalRenderKey = null;
    clockModalRenderKey = null;
  }
  const g = $('game-area');
  if (g && modalRoot.parentNode !== g.parentNode) g.after(modalRoot);
  if (!modalContentRoot) {
    modalContentRoot = el('div', { id: 'game-modal-content' });
    modalRoot.append(modalContentRoot);
  }
  if (!clockModalRoot) {
    clockModalRoot = el('div', { id: 'recovery-clock-modal-root' });
    modalRoot.append(clockModalRoot);
  }
}
function updateClockTimes() {
  if (!state.clockAlert || !clockModalRoot) return;
  const now = clientNow();
  const input = $('recovery-clock-input')?.value || '';
  let correction = 0;
  try {
    if (input !== '') {
      correction = parseRecoveryCorrectionSeconds(input);
      parseUserCorrectionMs(recoveryClock.getClockCorrection() + correction);
    }
  } catch { correction = 0; }
  const current = $('recovery-clock-current');
  const corrected = $('recovery-clock-corrected');
  if (current) current.textContent = new Date(now).toLocaleString(state.lang);
  if (corrected) corrected.textContent = new Date(now + correction).toLocaleString(state.lang);
}
function renderClockModal() {
  if (!state.clockAlert && !clockModalRoot) return;
  ensureModalRoot();
  const reissueRiskShown = () => {
    try {
      return state._renderedPhase === 'chatting'
        && parseRecoveryCorrectionSeconds(state.clockDraft) < 0;
    } catch { return false; /* Incomplete input. */ }
  };
  const syncReissueRisk = () => {
    const shown = reissueRiskShown();
    const reload = $('recovery-clock-reload-hint');
    const risk = $('recovery-clock-reissue-risk');
    if (reload && shown && !risk) reload.before(el('p', {
      id: 'recovery-clock-reissue-risk', textContent: state.tr('recovery.clock.reissueRisk'),
    }));
    else if (!shown && risk) risk.remove();
  };
  const showReissueRisk = reissueRiskShown();
  const nextKey = state.clockAlert
    ? JSON.stringify([state.lang, state.clockAlert.kind, state.clockAlert.deviationMs,
      !!state.clockPendingCorrection, state.clockPendingCorrection?.stage ?? null,
      !!state.clockChecking]) : null;
  if (nextKey === clockModalRenderKey) {
    syncReissueRisk();
    updateClockTimes();
    return;
  }
  clockModalRenderKey = nextKey;
  clockModalRoot.innerHTML = '';
  if (!state.clockAlert) return;
  const offsetSeconds = Math.sign(state.clockAlert.deviationMs)
    * Math.round(Math.abs(state.clockAlert.deviationMs) / 1000);
  const offset = `${offsetSeconds >= 0 ? '+' : ''}${offsetSeconds}`;
  const modal = el('div', { role: 'dialog', ariaModal: 'true',
    style: 'position:fixed;inset:0;z-index:10004;background:rgba(0,0,0,.8);display:flex;align-items:center;justify-content:center;padding:24px;overflow-y:auto;' });
  const panel = el('div', { className: 'card',
    style: 'max-width:560px;width:100%;max-height:calc(100dvh - 48px);overflow-y:auto;color:#fff;padding:24px;' });
  if (state.clockPendingCorrection) {
    const review = state.clockPendingCorrection;
    if (review.stage === 'partial') {
      panel.append(el('p', { textContent: state.tr('recovery.clock.partialReissue') }));
      const list = el('ul');
      for (const chat of review.partial.chats || []) list.append(el('li', { textContent: chat.label }));
      panel.append(list);
      panel.append(el('p', { id: 'recovery-clock-review-error', role: 'alert' }));
      panel.append(el('button', { type: 'button', textContent: state.tr('recovery.clock.partialReissueApply'),
        onclick: () => { void acknowledgeClockCorrection(null, true, false).catch(showRecoveryClockCorrectionError); } }));
      panel.append(el('button', { type: 'button', textContent: state.tr('recovery.clock.partialReissueSkip'),
        onclick: () => { void acknowledgeClockCorrection(null, true, true).catch(showRecoveryClockCorrectionError); } }));
      panel.append(el('button', { type: 'button', textContent: state.tr('recovery.clock.back'),
        onclick: () => { state.clockPendingCorrection = null; renderClockModal(); } }));
      modal.append(panel);
      clockModalRoot.append(modal);
      return;
    }
    if (review.adoption) {
      const rounded = Math.round(Math.abs(review.deviationMs) / 1000);
      const offset = `${review.deviationMs >= 0 ? '+' : '−'}${rounded}`;
      panel.append(el('p', { textContent: state.tr('recovery.clock.adopt', { offset }) }));
      const list = el('ul');
      for (const id of review.sourceIds) list.append(el('li', {
        textContent: id === 'wallet' ? state.tr('recovery.clock.wallet') : id }));
      panel.append(list);
    }
    if (review.repeated) panel.append(el('p', { textContent: state.tr('recovery.clock.repeated') }));
    panel.append(el('p', { id: 'recovery-clock-review-error', role: 'alert' }));
    panel.append(el('button', { type: 'button', textContent: state.tr(review.adoption
      ? 'recovery.clock.adoptButton' : 'recovery.clock.continue'),
    onclick: () => { void acknowledgeClockCorrection(null, true).catch(showRecoveryClockCorrectionError); } }));
    panel.append(el('button', { type: 'button', textContent: state.tr('recovery.clock.back'),
      onclick: () => { state.clockPendingCorrection = null; renderClockModal(); } }));
    modal.append(panel);
    clockModalRoot.append(modal);
    return;
  }
  panel.append(el('p', { textContent: state.tr(state.clockAlert.kind === 'manual'
    ? 'recovery.clock.manualHeading' : state.clockAlert.kind === 'warning'
      ? 'recovery.clock.warning' : 'recovery.clock.confirmation', { offset }) }));
  if (state.clockAlert.kind === 'manual' && Number.isFinite(state.clockAlert.deviationMs)) {
    panel.append(el('p', { textContent: state.tr('recovery.clock.offset', { offset }) }));
  }
  if (state.clockChecking) panel.append(el('p', { textContent: state.tr('recovery.clock.checking') }));
  panel.append(el('p', { textContent: state.tr('recovery.clock.current') }),
    el('time', { id: 'recovery-clock-current' }));
  const input = el('input', { id: 'recovery-clock-input', type: 'text', inputMode: 'text', value: state.clockDraft,
    oninput: () => { state.clockDraft = input.value; $('recovery-clock-error').textContent = ''; syncReissueRisk(); updateClockTimes(); },
    style: 'flex:1;min-width:0;color:#111;margin:8px 0;' });
  const signButton = el('button', { type: 'button', textContent: '＋ / −',
    ariaLabel: state.tr('recovery.clock.toggleSign'), onclick: () => {
      input.value = toggleRecoveryCorrectionSign(input.value);
      input.oninput();
    } });
  panel.append(el('label', { htmlFor: 'recovery-clock-input', textContent: state.tr('recovery.clock.correction') }),
    el('div', { style: 'display:flex;align-items:center;gap:8px;' }, input, signButton));
  panel.append(el('p', { textContent: state.tr(state.clockAlert.kind === 'warning'
    || (state.clockAlert.kind === 'manual' && Number.isFinite(state.clockAlert.deviationMs))
    ? 'recovery.clock.signHelp' : 'recovery.clock.neutralSignHelp') }));
  panel.append(el('p', { id: 'recovery-clock-error', role: 'alert' }));
  panel.append(el('p', { textContent: state.tr('recovery.clock.corrected') }),
    el('time', { id: 'recovery-clock-corrected' }));
  if (showReissueRisk) panel.append(el('p', {
    id: 'recovery-clock-reissue-risk', textContent: state.tr('recovery.clock.reissueRisk'),
  }));
  panel.append(el('p', { id: 'recovery-clock-reload-hint', textContent: state.tr('recovery.clock.reloadAfterDeviceFix') }));
  panel.append(el('button', { type: 'button', textContent: state.clockChecking
    ? state.tr('recovery.clock.checking') : state.tr('recovery.clock.confirm'), disabled: !!state.clockChecking,
    onclick: () => {
      void acknowledgeClockCorrection(input.value).catch(showRecoveryClockCorrectionError);
    } }));
  panel.append(el('button', { type: 'button', textContent: state.tr('recovery.clock.correct'),
    disabled: !!state.clockChecking, onclick: () => { void acknowledgeClockCorrection(null).catch(showRecoveryClockCorrectionError); } }));
  panel.append(el('button', { type: 'button', textContent: state.tr('recovery.clock.close'),
    onclick: closeClockCorrection }));
  modal.append(panel);
  clockModalRoot.append(modal);
  updateClockTimes();
}
function showRecoveryClockCorrectionError(error) {
  const key = error instanceof RangeError && recoveryClock.correctionCooldownMs() > 0
    ? 'recovery.clock.cooldownRejected' : 'recovery.clock.invalid';
  const target = $('recovery-clock-error') || $('recovery-clock-review-error');
  if (target) target.textContent = state.tr(key);
}
function renderGameModals(phase) {
  renderClockModal();
  const g = $('game-area');
  if (!g) return;
  ensureModalRoot();
  const closeAt = submissionChatCloseAt();
  const cutoff = Number.isSafeInteger(closeAt) ? closeAt - VOTE_RECEIPT_CUTOFF_MS : null;
  const votingClosed = cutoff !== null && clientNow() >= cutoff;
  const cutoffTime = cutoff === null ? null
    : `${String(new Date(cutoff).getHours()).padStart(2, '0')}:${String(new Date(cutoff).getMinutes()).padStart(2, '0')}`;
  const showDeadline = phase === 'chatting' && state.voteDeadlineNoticeOpen && !state.away
    && !(state.myVote && actionReceipted(state.uid, 'vote', state.myVote));
  const showProgress = phase === 'chatting' && state.pendingVoteTarget !== null;
  const showReportWarning = phase === 'chatting' && state.pendingReportWarningTarget != null;
  const showMultiSession = phase !== null && state.otherSessionReadReceipt;
  const showClockWarningFull = phase === 'chatting' && state.clockWarning?.warning?.stage === 'full';
  const clockDirection = state.clockWarning?.warning?.direction;
  const nextKey = JSON.stringify([state.lang, showDeadline, showProgress ? state.pendingVoteTarget : null,
    showProgress ? state.pendingVoteWarningKey : null, showProgress ? GUEST_PINNED_RULES.minMessages : null,
    showProgress ? state.cfg.pins.minChars : null, showReportWarning ? state.pendingReportWarningTarget : null,
    showMultiSession, showClockWarningFull, clockDirection, state.clockWarning?.reshowUsed,
    showDeadline ? cutoffTime : null, showDeadline ? votingClosed : null,
    showReportWarning ? votingClosed : null]);
  if (modalRenderKey === nextKey) return;
  modalRenderKey = nextKey;
  modalContentRoot.innerHTML = '';

  if (showDeadline) {
    const modal = el('div', { role: 'dialog', ariaModal: 'true',
      style: 'position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,.8);display:flex;align-items:center;justify-content:center;padding:24px;overflow-y:auto;' });
    const panel = el('div', { className: 'card', style: 'max-width:560px;width:100%;max-height:calc(100dvh - 48px);overflow-y:auto;color:#fff;padding:24px;' });
    panel.append(el('p', { textContent: votingClosed
      ? state.tr('recovery.action.votingClosed')
      : state.tr('recovery.action.deadlineVoteNotice')
        + (cutoffTime === null ? '' : ` ${state.tr('recovery.action.deadlineVoteReceiptNotice', { time: cutoffTime })}`) }));
    panel.append(el('button', { type: 'button', textContent: state.tr('recovery.action.noticeClose'),
      onclick: () => { state.voteDeadlineNoticeOpen = false; renderGame(); } }));
    modal.append(panel); modalContentRoot.append(modal);
  }

  if (showProgress) {
    const key = state.pendingVoteWarningKey === 'turns'
      ? 'recovery.action.voteProgressTurns' : 'recovery.action.voteProgressChars';
    const modal = el('div', { role: 'dialog', ariaModal: 'true',
      style: 'position:fixed;inset:0;z-index:10001;background:rgba(0,0,0,.8);display:flex;align-items:center;justify-content:center;padding:24px;overflow-y:auto;' });
    const panel = el('div', { className: 'card', style: 'max-width:560px;width:100%;max-height:calc(100dvh - 48px);overflow-y:auto;color:#fff;padding:24px;' });
    panel.append(el('p', { textContent: state.tr(key, { minMessages: GUEST_PINNED_RULES.minMessages, minChars: state.cfg.pins.minChars }) }));
    panel.append(el('button', { type: 'button', textContent: state.tr('recovery.action.voteProgressProceed'),
      onclick: () => {
        const target = state.pendingVoteTarget;
        state.pendingVoteTarget = null;
        state.pendingVoteWarningKey = null;
        state.voteWarningAccepted = true;
        renderGame();
        sendVote(target);
      } }));
    panel.append(el('button', { type: 'button', textContent: state.tr('recovery.action.voteProgressBack'),
      onclick: () => { state.pendingVoteTarget = null; state.pendingVoteWarningKey = null; renderGame(); } }));
    modal.append(panel); modalContentRoot.append(modal);
  }

  if (showReportWarning) {
    const target = state.pendingReportWarningTarget;
    const modal = el('div', { role: 'dialog', ariaModal: 'true',
      style: 'position:fixed;inset:0;z-index:10002;background:rgba(0,0,0,.8);display:flex;align-items:center;justify-content:center;padding:24px;overflow-y:auto;' });
    const panel = el('div', { className: 'card',
      style: 'max-width:560px;width:100%;max-height:calc(100dvh - 48px);overflow-y:auto;color:#fff;padding:24px;' });
    panel.append(recoveryPointedElement('p', {}, '', votingClosed
      ? 'recovery.action.reportRevealWarningLate' : 'recovery.action.reportRevealWarning',
      'A', state.members.find((member) => member.uid === target),
      recoveryPlayerLabel(target) === null ? memberName(state.members.find((member) => member.uid === target))
        : reportWarningName(memberName(state.members.find((member) => member.uid === target)))));
    panel.append(el('button', { type: 'button', textContent: state.tr('recovery.action.reportRevealProceed'),
      onclick: () => {
        state.pendingReportWarningTarget = null;
        state.reportWarningAccepted = true;
        renderGame();
        sendReport(target);
      } }));
    panel.append(el('button', { type: 'button', textContent: state.tr('recovery.action.reportRevealCancel'),
      onclick: () => { state.pendingReportWarningTarget = null; renderGame(); } }));
    modal.append(panel); modalContentRoot.append(modal);
  }

  if (showMultiSession) {
    const modal = el('div', { role: 'dialog', ariaModal: 'true', ariaLabel: state.tr('recovery.members.multipleSessionsWarning'),
      style: 'position:fixed;inset:0;z-index:10002;background:rgba(0,0,0,.8);display:flex;align-items:center;justify-content:center;padding:24px;overflow-y:auto;' });
    const panel = el('div', { className: 'card', style: 'max-width:560px;width:100%;max-height:calc(100dvh - 48px);overflow-y:auto;color:#fff;padding:24px;' });
    panel.append(el('p', { textContent: state.tr('recovery.members.multipleSessionsWarning') }));
    panel.append(el('button', { type: 'button', textContent: state.tr('recovery.session.resume'), onclick: resumeOtherSession,
      style: 'display:block;width:100%;margin:12px 0;padding:12px;' }));
    panel.append(el('button', { type: 'button', textContent: state.tr('recovery.session.close'), onclick: endThisTab,
      style: 'display:block;width:100%;padding:12px;' }));
    modal.append(panel); modalContentRoot.append(modal);
  }
  if (showClockWarningFull) {
    const warningKey = clockDirection === 'early' ? 'recovery.clock.futureEarlyWarning'
      : 'recovery.clock.futureLockWarning';
    const modal = el('div', { role: 'dialog', ariaModal: 'true',
      ariaLabel: state.tr(warningKey),
      style: 'position:fixed;inset:0;z-index:10003;background:rgba(0,0,0,.8);display:flex;align-items:center;justify-content:center;padding:24px;overflow-y:auto;' });
    const panel = el('div', { className: 'card', style: 'max-width:560px;width:100%;max-height:calc(100dvh - 48px);overflow-y:auto;color:#fff;padding:24px;' });
    panel.append(el('p', { textContent: state.tr(warningKey) }));
    panel.append(el('button', { type: 'button', textContent: state.tr('recovery.clock.manualEntry'),
      onclick: () => { void openManualClockCorrection(); } }));
    panel.append(el('button', { type: 'button', textContent: state.tr('recovery.clock.warningContinue'),
      onclick: continueRecoveryClockWarning }));
    modal.append(panel); modalContentRoot.append(modal);
    state.clockWarning = advanceFutureClockWarning(state.clockWarning, { type: 'shown' });
  }
}

function renderGame() {
  const g = $('game-area');
  if (!g) return;
  const keptChat = clearGameAreaKeepingChat(g);
  if (state.tabEnded) {
    g.append(el('div', { role: 'status', style: 'position:fixed;inset:0;z-index:10000;background:rgba(0,0,0,.85);display:flex;align-items:center;justify-content:center;padding:24px;color:#fff;text-align:center;' },
      el('div', { className: 'card', textContent: state.tr('recovery.session.ended') })));
    settleGameArea(g, keptChat);
    renderGameModals(null);
    return;
  }
  g.append(renderContractStatus());
  if (state.rosterPaused || state.rosterInvalid) {
    g.append(el('div', { className: 'statusText', textContent: state.tr(state.rosterInvalid
      ? 'recovery.warn.rosterChanged' : 'recovery.warn.rosterRechecking') }));
    settleGameArea(g, keptChat);
    renderGameModals(null);
    return;
  }
  if (!state.members) { settleGameArea(g, keptChat); renderGameModals(null); return; }
  const phase = currentPhase();
  if (phase === 'chatting' && state._renderedPhase !== 'chatting') void refreshRecoveryClockWarning();
  state._renderedPhase = phase;
  const renderNow = phase === 'completed' ? null : clientNow(); // 初回の残り時間表示と共有する時計
  if (state.away) state.voteDeadlineEntryPending = true;
  else if (phase === 'chatting' && state.voteDeadlineEntryPending && Number.isFinite(state.timeline?.chatCloseAt)) {
    state.voteDeadlineEntryPending = false;
    const hasValidVote = !!state.myVote && actionReceipted(state.uid, 'vote', state.myVote);
    const remaining = state.timeline.chatCloseAt - renderNow;
    if (!hasValidVote && remaining >= 0 && remaining <= 3 * 60 * 60 * 1000) {
      state.voteDeadlineNoticeOpen = true;
    }
  }
  const focusKey = focusKeyOf(document.activeElement);
  g.append(renderHeader(phase, renderNow));
  g.append(el('div', { className: 'ceiling', textContent: state.tr('recovery.ceiling') }));
  if (phase === 'chatting' && state.clockWarning?.warning) g.append(renderClockWarningBand());
  const sameDeviceBand = renderSameDeviceBand(phase);
  if (sameDeviceBand) g.append(sameDeviceBand);
  const ownHistoryBand = renderOwnHistoryPromptBand(phase);
  if (ownHistoryBand) g.append(ownHistoryBand);

  if (phase === 'entry') g.append(el('div', { className: 'description', textContent: state.tr('recovery.entryWait') }));
  if (phase === 'waiting') g.append(renderWaitingSection());
  if (phase === 'chatting' || phase === 'unknown') { placeChatSection(g, renderChatSection(renderNow)); g.append(renderActionPanel()); }
  if (phase === 'submitting' || phase === 'unknown') g.append(renderSubmitSection());
  if (phase === 'completed') g.append(el('div', { className: 'completedMessage', textContent: state.tr('recovery.completedMsg') }));

  settleGameArea(g, keptChat);
  renderGameModals(phase);
  restoreFocus(focusKey);
}

// 復元に使う契約を常時可視化する。localStorage 上書きはテストネット等のため維持するが、
// 既定値との差分は赤字で示す。不変量を確認できなくても縮退モードの提出は止めない。
function renderContractStatus() {
  const panel = el('div', { className: 'card' });
  panel.append(el('div', { className: 'connSectionTitle', textContent: 'Contracts in use' }));
  const changed = [];
  for (const key of ['hashStorage', 'tokenMining', 'evidence', 'ethLock']) {
    const address = state.cfg?.contracts?.[key] || '(unset)';
    if (String(address).toLowerCase() !== String(DEFAULTS.contracts[key]).toLowerCase()) changed.push(key);
    panel.append(el('div', {
      className: 'muted',
      style: 'font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all;',
      textContent: `${key}: ${address}`,
    }));
  }
  if (changed.length > 0) {
    panel.append(el('div', {
      style: 'color:#ff5a5a;font-weight:bold;margin-top:8px;',
      textContent: `WARNING: non-default contract address in use (${changed.join(', ')})`,
    }));
  }
  if (state.timing?.tokenMiningLinkOk === false) {
    panel.append(el('div', {
      style: 'color:#ff5a5a;font-weight:bold;font-size:12px;margin-top:6px;',
      textContent: 'WARNING: Evidence points to a different TokenMining contract than this recovery client. The Evidence setting may be stale. Recovery submission remains available.',
    }));
  } else if (state.timing?.invariantOk !== true) {
    panel.append(el('div', {
      style: 'color:#c9a227;font-size:12px;margin-top:6px;',
      textContent: 'Timeline invariant is not verified. Recovery submission remains available.',
    }));
  }
  const operatorRpc = state.cfg?.operatorRpc;
  if (typeof operatorRpc === 'string' && operatorRpc !== '') {
    let host = '?';
    try { host = new URL(operatorRpc).host || '?'; } catch { host = '?'; }
    panel.append(el('div', {
      style: 'color:#ff5a5a;font-weight:bold;font-size:12px;margin-top:6px;',
      textContent: state.tr('recovery.operatorRpc.configured', { host }),
    }));
  }
  return panel;
}

// ヘッダー: ブロック/グループ + フェーズステップバー + 残り時間 + 接続状態 + メンバーカード
// 進行ステッパー 二段構成（本体 game.js と同一）:
//   第一段階(緑): 待機 / チャット期間 / 提出期間
//   第二段階(金): 結果集計 / 検証期間 / 請求期間
//   提出窓終了(resultCloseAt)後は derivePhase='completed' → 第二段階「結果集計」を表示する。
//   結果集計はファイナリティ待ち〜オンチェーン提出完了までを含む（復元ツールはチェーンの
//   TokenMining lifecycle を追わないため、検証/請求は pending 表示のまま＝提出後は役目終了）。
const STAGE1_PHASES = ['waiting', 'chatting', 'submitting'];
const STAGE2_PHASES = ['aggregating', 'verification', 'claimable'];

function renderHeader(phase, nowMs) {
  const header = el('div', { className: 'gameHeader' });
  const isStage1 = phase !== 'completed';
  const bar = el('div', { className: isStage1 ? 'phaseBar' : 'phaseBar phaseBarStage2' });
  bar.append(el('div', { className: 'blockGroupInfo' },
    `${state.tr('recovery.blockLabel')}${state.blockNum} - ${state.tr('recovery.groupLabel')}${state.groupId}`));

  const phases = isStage1 ? STAGE1_PHASES : STAGE2_PHASES;
  const activeIdx = isStage1 ? STAGE1_PHASES.indexOf(phase) : 0; // completed → 結果集計 active（entry/unknown は -1）
  const steps = el('div', { className: 'phaseSteps' });
  phases.forEach((p, i) => {
    const cls = i < activeIdx ? 'phaseStepDone'
      : i === activeIdx ? 'phaseStepActive' : 'phaseStepPending';
    const step = el('div', { className: cls });
    step.append(el('div', { className: 'phaseStepDot' }));
    step.append(el('span', { className: 'phaseStepLabel', textContent: state.tr(`recovery.phaseName.${p}`) }));
    steps.append(step);
  });
  bar.append(steps);
  // 残り時間 + 手動更新ボタン（reset/extendGrace 後に即チェーン再読取してフェーズを最新化）。
  // 結果集計(第二段階)はカウントダウンせず集計待ちメッセージを表示。
  const timerRow = el('div', { className: 'phaseTimerRow' });
  const timerInit = isStage1 ? timerText(phase, nowMs) : state.tr('recovery.phaseName.aggregatingWait');
  timerRow.append(el('div', { className: 'phaseTimer', id: 'phase-timer', textContent: timerInit }));
  timerRow.append(el('button', { className: 'refreshBtn', textContent: `⟳ ${state.tr('recovery.refresh')}`, onclick: () => refreshTimeline(true) }));
  if (STAGE1_PHASES.includes(phase) && !state.tabEnded) {
    const remaining = recoveryClock.correctionCooldownMs();
    timerRow.append(el('button', { type: 'button', textContent: state.tr('recovery.clock.manualEntry'),
      disabled: remaining > 0, onclick: () => { void openManualClockCorrection(); } }));
    if (remaining > 0) timerRow.append(el('span', { textContent: state.tr('recovery.clock.cooldown',
      { minutes: Math.ceil(remaining / 60000) }) }));
    timerRow.append(el('span', { textContent: state.tr('recovery.clock.reloadAfterDeviceFix') }));
  }
  bar.append(timerRow);
  header.append(bar);

  const statusRow = el('div', { className: 'statusRow' });
  statusRow.append(el('div', { id: 'relay-status', className: relayStatusClass(), textContent: `${relayStatusText()} ›`, onclick: openConnModal, title: state.tr('recovery.connection.title') }));
  if (state.liveSnapshotUnread) statusRow.append(el('span', {
    className: 'charCountWarning',
    textContent: state.lang === 'ja' ? '公開の live スナップショットを読めません。表示は P2P の情報のみです。'
      : state.lang === 'zh' ? '无法读取公开的实时快照。进度仅使用 P2P 信息。'
        : 'Public live snapshot unavailable. Progress uses P2P data only.',
  }));
  header.append(statusRow);

  if (phase !== 'completed') header.append(renderMemberList(nowMs));
  return header;
}

function renderMemberList(displayNow) {
  const list = el('div', { className: 'memberList' });
  const msgs = state.relay?.getMessages() || [];
  // この端末が提出でき、かつ他メンバーの受領証明≥1件を持つメッセージだけを数える。
  // 🔴 P-2026-0844: 採点は `applyChatCaps` を通した集合しか見ないので、メンバーカードの
  //    「文字数 / 会話回数」も同じ集合から数える（下の達成状況3行と同一の入力にする）。
  const readers = readersByMsgKey();
  const targetKeys = new Set(msgs.map((message) =>
    `${message.uid}|${msgRefOf(computeMsgKeyV2(state.blockNum, state.groupId, message))}`));
  const warningResult = state.receiptWarnings.evaluate(performance.now(),
    (senderUid, ref) => targetKeys.has(`${senderUid}|${ref}`),
    (senderUid) => state.relay?.futureMarks.hasChatRefOverflow(senderUid));
  const g3Actions = [...state.g3Reports].flatMap(([uid, reports]) =>
    [...reports].map((encrypted) => ({ uid, encrypted })));
  const suspicious = suspiciousReportingUids({ actions: g3Actions });
  const reportStatus = reportTargetStatusMap();
  const opaqueReports = state.myReports.filter((report) => report?.encrypted
    && report.timestamp != null && !decryptSelfTarget(report.encrypted)).length;
  const activeReportSlots = Object.keys(reportStatus).length + opaqueReports;
  const receiptedMsgs = locallyProvableMessages(msgs).filter((m) => {
    const k = msgRefOf(computeMsgKeyV2(state.blockNum, state.groupId, m)); // 既読は msgRef 参照（案B）
    return isTimestampVisible(m.timestamp, displayNow)
      && readers[k] && [...readers[k]].some((u) => u !== m.uid);
  });
  const turnsMap = countMessageTurns(filterVisibleMessages(receiptedMsgs));
  const charsMap = {};
  for (const msg of receiptedMsgs) charsMap[msg.uid] = (charsMap[msg.uid] || 0) + countVisibleChars(msg.text || '');
  const { minChars, minMessages } = state.cfg.pins;

  const activityAt = lastActivityMap(msgs);
  const now = displayNow;
  const siteOrigin = state.cfg.siteOrigin || 'https://bitcoinu.org';

  const lockPointsIdentity = recoveryLockPointsIdentity();
  for (const m of state.members) {
    const isSelf = m.uid === state.uid;
    // v3.3追補: 明示の在席通知（away）が来ていればオフライン。無ければ直近10分の活動観測で近似。
    // 自分は away 判定（10分間操作なし）に従う。
    const isOnline = isSelf
      ? !receiptIssuanceBlocked()
      : (state.peerPresence[m.uid] !== 'away' && (now - (activityAt[m.uid] || 0)) < ACTIVITY_WINDOW_MS);
    const card = el('div', { className: isSelf ? 'memberCard memberCardSelf' : 'memberCard' });
    const playerNo = recoveryPlayerNumber(m.uid); if (playerNo !== null) card.append(el('span', { className: 'memberPlayerNo', textContent: String(playerNo) }));

    // アイコン＋名前 → 本体サイトのユーザーページ（別タブ・§8.1）
    const link = el('a', { className: 'memberProfileLink', href: `${siteOrigin}/user?id=${m.uid}`, target: '_blank', rel: 'noopener noreferrer' });
    const summaryImg = m.summaryMeta?.img;
    const displayImg = (typeof summaryImg === 'string' && summaryImg.length <= 2048 && summaryImg) || (typeof m.img === 'string' && m.img.length <= 2048 && m.img) || null;
    if (displayImg) link.append(el('img', { className: 'memberAvatar', src: displayImg, alt: '' }));
    else link.append(el('div', { className: isOnline ? 'memberOnline' : 'memberOffline' }));
    link.append(el('span', { className: 'memberName', textContent: memberName(m) }));
    if (m.summaryMeta?.verified ?? m.verified) link.append(el('span', { className: 'verifiedBadge', textContent: '✓' }));
    card.append(link);

    const lockView = recoveryLockPointView(summaryDeclaredWei(m.summaryMeta), depositPointsOf(m),
      state.lockPoints && state.lockPoints.identity === lockPointsIdentity ? state.lockPoints.byUid[m.uid] : undefined);
    const lockMark = lockView.mark === 'corrected' ? 'recovery.members.depositPointsCorrected'
      : lockView.mark === 'unverified' ? 'recovery.members.depositPointsUnverified' : null;
    card.append(el('div', { className: 'memberDepositPoints', textContent: `${state.tr('recovery.members.depositPoints')}: ${lockView.text}${lockMark ? ` (${state.tr(lockMark)})` : ''}` }));

    const chars = charsMap[m.uid] || 0;
    const turns = isSelf
      ? myShownProgress(msgs, displayNow).turns
      : (turnsMap[m.uid] || 0);
    const row = el('div', { className: 'memberInfoRow' });
    row.append(el('div', { className: 'memberChars' },
      el('span', { className: chars >= minChars ? 'charCountOk' : 'charCountWarning', textContent: String(chars) }),
      ` / ${minChars} ${state.tr('recovery.members.chars')}`));
    row.append(el('div', { className: 'memberChars' },
      el('span', { className: turns >= (isSelf ? GUEST_PINNED_RULES.minMessages : minMessages) ? 'charCountOk' : 'charCountWarning', textContent: String(turns) }),
      ` / ${isSelf ? GUEST_PINNED_RULES.minMessages : minMessages} ${state.tr('recovery.members.times')}`));
    card.append(row);

    // 投票/密告バッジ（自分=ローカル発信、他人=リレー観測。対象は非公開・事実のみ）
    const status = el('div', { className: 'memberActionStatus' });
    // 「投票済み」は受領証明≥1件を得てから表示（正典に数えられる状態＝§6.7）
    const memberVote = isSelf ? state.myVote : state.observedActions?.votes?.[m.uid];
    const voted = !!memberVote && actionReadCount(m.uid, 'vote', memberVote) > 0;
    // 「密告：N」も受領証明≥1件で確定した分だけ数える（生件数＝facts.reportCount / myReports.length は
    // 未読＝正典未確定や void の発信も数えてしまう。本体 game.js reportReceiptedCounts と同一判定）
    const memberReports = isSelf ? state.myReports : (state.observedActions?.reports?.[m.uid] || []);
    const reported = (memberReports || [])
      .filter((a) => a?.encrypted && a.timestamp != null && actionReadCount(m.uid, 'report', a) > 0).length;
    if (voted) status.append(el('span', { className: 'memberVotedBadge', textContent: state.tr('recovery.members.voted') }));
    if (reported > 0) status.append(el('span', { className: 'memberReportedBadge', textContent: `${state.tr('recovery.members.reported')} ${reported}` }));
    card.append(status);

    if (!isSelf && state.readReceiptAlerts[m.uid]) card.append(el('div', {
      className: 'memberFloodAlert', title: state.tr('recovery.members.invalidReadReceiptTip'),
      textContent: `⚠ ${state.tr('recovery.members.invalidReadReceipt')}`,
    }));
    if (!isSelf && currentPhase() === 'chatting'
        && (warningResult.duplicateUids.includes(m.uid) || warningResult.missingUids.includes(m.uid))) {
      const warningName = memberName(m);
      card.append(recoveryPointedElement('div', { className: 'memberFloodAlert' }, '⚠ ', 'recovery.members.fraudulentReceipts', 'name', m,
        recoveryPlayerLabel(m.uid) === null ? warningName : reportWarningName(warningName)));
    }
    if (!isSelf && currentPhase() === 'chatting' && suspicious.includes(m.uid)) {
      const key = showReportingRecommendation(m.uid, reportStatus, activeReportSlots)
        ? 'recovery.members.suspiciousReporting' : 'recovery.members.suspiciousReportingShort';
      card.append(recoveryPointedElement('div', { className: 'memberFloodAlert' }, '⚠ ', key, 'name', m, reportWarningName(memberName(m))));
    }
    if (isSelf && state.otherSessionReadReceipt) card.append(el('div', {
      className: 'memberFloodAlert', textContent: state.tr('recovery.members.multipleSessionsWarning'),
    }));

    // 「Xを見る」ボタン（旧タブーバー位置・§8.1: https://x.com/i/user/{uid} を別タブで）
    card.append(el('a', {
      className: 'memberXLink',
      href: `https://x.com/i/user/${m.uid}`,
      target: '_blank',
      rel: 'noopener noreferrer',
      textContent: state.tr('recovery.members.viewOnX'),
    }));

    // 活動状況（本体の「参加予定/復帰予定」は運営サーバー依存なので置かない）
    const foot = el('div', { className: 'memberActivityFooter', title: state.tr('recovery.members.activityTip') });
    foot.append(el('span', { className: isOnline ? 'memberOnline' : 'memberOffline' }));
    foot.append(el('span', {
      className: isOnline ? 'memberActivityOnline' : 'memberActivityOffline',
      textContent: state.tr(isOnline ? 'recovery.members.online' : 'recovery.members.offline'),
    }));
    card.append(foot);

    list.append(card);
  }
  return list;
}

// 開始待機（waiting）: グループ発表＋チャット開始カウントダウン（ヘッダーのタイマーが担う）
function renderWaitingSection() {
  return el('div', { className: 'description', textContent: state.tr('recovery.waiting.description') });
}

// チャット履歴の吹き出し一覧（本体 ChatPhase / SubmissionPhase と同じ描画・v3.2 既読UX付き）。
// 全件出す（本体も messages.map で切り詰めない。1人あたり最大100発言のキャップがあるので上限は有限）。
// 自分のメッセージは他メンバーの受領証明を得るまで半透明＋「未読」、1件以上で不透明＋「既読N」（§6.7）。
// アクション（投票/密告）の受領証明者数（発信者本人を除く）— 既読N表示用。
function actionReadCount(actorUid, actionType, action) {
  if (!action?.encrypted || action.timestamp == null) return 0;
  const h = actionHashV2(actionType, state.blockNum, state.groupId, actorUid, action.encrypted, action.timestamp);
  const set = new Set();
  for (const rc of clientChatSourcedReceipts(state.receipts, submissionChatWindow(), submissionChatCloseAt())) {
    if (rc.actionHash === h && rc.receiverUid !== actorUid && isReceiptTimely(rc.timestamp, action.timestamp)) set.add(rc.receiverUid);
  }
  return set.size;
}

// 投票/密告の文字色＝吹き出しの枠線色（本体 chatTimeline.ACTION_LABEL_COLOR と同値）。
const ACTION_LABEL_COLOR = { vote: '#0000ff', report: '#ff0000' };

// v3.3: 未読バッジのテキスト（発信から10分の残りカウントダウン付き＝「未読 3:38」）。
function unreadCountdownLabel(ts, actionType = null) {
  const closeAt = submissionChatCloseAt();
  if (actionType === 'vote' && Number.isSafeInteger(closeAt)
    && clientNow() >= closeAt - VOTE_RECEIPT_CUTOFF_MS) return state.tr('recovery.chat.unreadBadge');
  const remainingSec = Math.max(0, Math.ceil((ts + RECEIPT_FRESH_WINDOW_MS - clientNow()) / 1000));
  const m = Math.floor(remainingSec / 60);
  const s = String(remainingSec % 60).padStart(2, '0');
  return `${state.tr('recovery.chat.unreadBadge')} ${m}:${s}`;
}
// 自分の未読発信バッジ（data-ts を持たせ、毎秒テキストだけ更新する）。
function makeUnreadBadge(ts, actionType = null) {
  const span = el('span', { className: 'unreadBadge unreadCountdown', textContent: unreadCountdownLabel(ts, actionType) });
  span.dataset.ts = String(ts);
  if (actionType) span.dataset.actionType = actionType;
  return span;
}
// 毎秒: 既存の未読バッジのカウントダウンだけ更新（フル再描画せずスクロール維持）。
// 10分経過（void）した発信があれば renderGame で表示から除去する。
function updateUnreadCountdowns() {
  const badges = document.querySelectorAll('.unreadCountdown');
  if (!badges.length) return;
  let anyExpired = false;
  badges.forEach((b) => {
    const ts = Number(b.dataset.ts);
    if (!Number.isFinite(ts)) return;
    if ((ts + RECEIPT_FRESH_WINDOW_MS - clientNow()) <= 0) anyExpired = true;
    b.textContent = unreadCountdownLabel(ts, b.dataset.actionType || null);
  });
  if (anyExpired) renderGame();
}

// receiptedOnly=true（提出画面）: 受領証明≥1件のものだけ表示。チャットは終了済みで受領は
// もう増えないので、未読のまま終わった発言/発信は「なかったこと」として出さない
// （本体 chatTimeline.buildChatTimeline の receiptedOnly と同一）。
function renderChatLog({ receiptedOnly = false } = {}) {
  const msgsBox = el('div', { className: 'chatMessages' });
  const byUid = new Map(state.members.map((m) => [m.uid, m]));
  const readers = readersByMsgKey();
  const phase = currentPhase();
  const hidden = phase === 'chatting' || phase === 'submitting' ? recoveryOvercapHiddenKeys() : null;
  const displayHidden = displayHiddenMessageKeys(hidden, recoveryShownKeys());
  const messages = state.relay?.getMessages() || [];
  const visibleMessages = displayHidden instanceof Set && displayHidden.size > 0
    ? messages.filter((msg) => msg.uid === state.uid || !displayHidden.has(state.relay.getMsgKey(msg))) : null;
  const visibleReaders = visibleMessages
    ? buildReceiptMaps(selectedReadReceiptsForDisplay(messages, submissionChatWindow()),
    { messages: visibleMessages, myUid: state.uid },
    state.blockNum, state.groupId, submissionChatWindow(), state.relay.getMsgKey).readersByMsgKey
    : null;
  const nowMs = clientNow();

  // 提出期間中にリレー経由で初めて届いた発信（chatCloseAt=チャット窓終端より後）は
  // 採点対象外・受領証明も未発行なので表示から除外する（チャット期間中は窓が未来なので無影響）。
  const chatCloseAt = state.timeline?.chatCloseAt;
  const withinWindow = (ts) => isTimestampVisible(ts, nowMs)
    && (!Number.isFinite(chatCloseAt) || (ts ?? 0) <= chatCloseAt);
  const msgs = messages.filter((m) => withinWindow(m.timestamp));

  // v3.3 表示ルール（本体 chatTimeline.buildChatTimeline と同一）: 表示されるのは
  //   ①受領証明が1件以上あるもの（誰かが±10分以内に受信した＝正典候補）
  //   ②発信主張時刻から10分以内のもの（少なくとも閲覧者が今から受領証明を発行できる）
  // のいずれか。10分経過して受領証明ゼロの発信（void）は全員の画面から消える
  // （発信者画面では10分間半透明→消滅。消滅後は同一対象への再送が可能）。
  // 提出画面（receiptedOnly）は「受領証明≥1件」のみ＝10分の受領待ち枠はチャット終了で失効。
  const visible = (ts, readCount) => isTimestampVisible(ts, nowMs) && (readCount > 0
    || (!receiptedOnly && typeof ts === 'number' && Math.abs(nowMs - ts) <= RECEIPT_FRESH_WINDOW_MS));

  // タイムライン: チャット吹き出し＋投票/密告のインラインシステム行を時系列で並べる
  // （本体 ChatPhase / SubmissionPhase と同一・v3.2 §6.7 既読UX）。
  const rows = [];

  for (const msg of msgs) {
    const self = msg.uid === state.uid;
    if (!self && displayHidden instanceof Set && displayHidden.has(state.relay.getMsgKey(msg))) continue;
    const m = byUid.get(msg.uid);
    const k = msgRefOf(computeMsgKeyV2(state.blockNum, state.groupId, msg)); // 既読は msgRef 参照（案B）
    const source = !self && visibleReaders ? visibleReaders : readers;
    const readCount = source[k] ? [...source[k]].filter((u) => u !== msg.uid).length : 0;
    if (!visible(msg.timestamp, readCount)) continue; // void（10分経過・受領なし）は非表示
    const avatar = typeof m?.img === 'string' && m.img && m.img.length <= 2048 ? el('img', { className: 'chatAvatar', src: m.img, alt: '' }) : null;
    const rowEl = el('div', { className: self ? 'chatRowSelf' : 'chatRow' });
    const wrapB = el('div', { className: 'chatBubbleWrapper' });
    if (!self) wrapB.append(el('div', { className: 'chatBubbleSender', textContent: memberName(m) || msg.uid, ...(receiptedOnly ? {} : recoveryPlayerTitle(msg.uid)) }));
    const bubble = el('div', { className: self ? 'chatBubbleSelf' : 'chatBubble' });
    bubble.append(el('div', { className: 'chatBubbleText', textContent: msg.text }));
    wrapB.append(bubble);
    const timeRow = el('div', { className: 'chatBubbleTime' });
    if (self) {
      // 既読UX: 未受領は行全体を半透明＋「未読」・受領で「既読N」（正典未確定の可視化）
      if (readCount === 0) rowEl.style.opacity = '0.5';
      timeRow.append(readCount > 0
        ? el('span', { className: 'readBadge', textContent: state.tr('recovery.chat.readBadge', { count: readCount }) })
        : makeUnreadBadge(msg.timestamp));
      timeRow.append(' ');
    }
    timeRow.append(new Date(msg.timestamp).toLocaleTimeString());
    wrapB.append(timeRow);
    if (self) { rowEl.append(wrapB); if (avatar) rowEl.append(avatar); }
    else { if (avatar) rowEl.append(avatar); rowEl.append(wrapB); }
    if (!self) {
      const msgKey = state.relay.getMsgKey(msg);
      recoveryShownKeys().add(msgKey);
      rememberRecoveryShownSeparator(msg, msgKey, source[k]);
    }
    rows.push({ ts: msg.timestamp || 0, node: rowEl });
  }

  // 投票/密告の吹き出し行（自分＝myVote/myReports・他人＝observedActions）。
  // v3.3: チャットと同じアイコン/名前つき吹き出し（斜体・投票=原色の青#0000ff/密告=原色の赤#ff0000）。
  // 吹き出しは自分/他者とも白背景＋テキスト色の枠線(2px)・上下左右中央寄せ、右下に「既読N」＋時刻。
  // テキストは「投票」「密告(N回目)」のみ（対象は非公開）。既読/未読バッジと未読半透明はチャットと
  // 同一挙動（自分の発信のみバッジ表示・未読=半透明。本体 chatTimeline.ChatActionRow と同じ）。
  const pushAction = (actorUid, actionType, action, nth) => {
    const isSelf = actorUid === state.uid;
    const readCount = actionReadCount(actorUid, actionType, action);
    const actor = byUid.get(actorUid);
    const color = actionType === 'vote' ? ACTION_LABEL_COLOR.vote : ACTION_LABEL_COLOR.report;
    const label = actionType === 'vote'
      ? state.tr('recovery.chat.bubbleVote')
      : state.tr('recovery.chat.bubbleReport', { nth });
    const rowEl = el('div', { className: isSelf ? 'chatRowSelf' : 'chatRow' });
    if (isSelf && readCount === 0) rowEl.style.opacity = '0.5';
    const avatar = typeof actor?.img === 'string' && actor.img && actor.img.length <= 2048 ? el('img', { className: 'chatAvatar', src: actor.img, alt: '' }) : null;
    const wrapB = el('div', { className: 'chatBubbleWrapper' });
    if (!isSelf) wrapB.append(el('div', { className: 'chatBubbleSender', textContent: memberName(actor) || actorUid, ...(receiptedOnly ? {} : recoveryPlayerTitle(actorUid)) }));
    const bubble = el('div', { className: 'chatBubbleAction' });
    bubble.style.borderColor = color;
    const labelSpan = el('span', { textContent: label });
    labelSpan.style.color = color;
    labelSpan.style.fontStyle = 'italic';
    labelSpan.style.fontWeight = 'bold';
    const textDiv = el('div', { className: 'chatBubbleText' });
    textDiv.append(labelSpan);
    bubble.append(textDiv);
    wrapB.append(bubble);
    const timeRow = el('div', { className: 'chatBubbleTime' });
    if (isSelf) {
      timeRow.append(readCount > 0
        ? el('span', { className: 'readBadge', textContent: state.tr('recovery.chat.readBadge', { count: readCount }) })
        : makeUnreadBadge(action.timestamp, actionType));
      timeRow.append(' ');
    }
    timeRow.append(new Date(action.timestamp).toLocaleTimeString());
    wrapB.append(timeRow);
    if (isSelf) { rowEl.append(wrapB); if (avatar) rowEl.append(avatar); }
    else { if (avatar) rowEl.append(avatar); rowEl.append(wrapB); }
    rows.push({ ts: action.timestamp || 0, node: rowEl });
  };

  // 密告の2枠は最初の受領証明の時刻が早い順に決まる。受領証明の無い（void の）密告は
  // その後で枠を取り、正直な画面では void の対象も2枠に数える。表示の nth は可視行の順。
  const pushActions = (actorUid, actionType, list) => {
    const sorted = (list || [])
      .filter((a) => a?.encrypted && a.timestamp != null && withinWindow(a.timestamp))
      .sort((a, b) => a.timestamp - b.timestamp);
    let nth = 0;
    for (const action of sorted) {
      const readCount = actionReadCount(actorUid, actionType, action);
      if (!visible(action.timestamp, readCount)) continue; // void発信は非表示（再送可能になる）
      nth += 1;
      pushAction(actorUid, actionType, action, nth);
    }
  };

  if (state.myVote?.encrypted) pushActions(state.uid, 'vote', [state.myVote]);
  pushActions(state.uid, 'report', state.myReports);
  for (const [u, v] of Object.entries(state.observedActions.votes || {})) {
    if (u.endsWith('__extras') || u === state.uid) continue;
    pushActions(u, 'vote', [v]);
  }
  for (const [u, arr] of Object.entries(state.observedActions.reports || {})) {
    if (u === state.uid || !Array.isArray(arr)) continue;
    pushActions(u, 'report', arr);
  }

  rows.sort((a, b) => a.ts - b.ts);
  for (const r of rows) msgsBox.append(r.node);
  return msgsBox;
}

function renderClockWarningBand() {
  const warning = state.clockWarning.warning;
  const seconds = Math.floor(Math.abs(warning.deviationMs) / 1000);
  const band = el('div', { role: 'status',
    style: 'padding:10px 14px;margin:8px 0;background:#493b13;color:#fff;border:1px solid #bda447;border-radius:6px;' });
  band.append(el('span', { textContent: state.tr(warning.direction === 'late'
    ? 'recovery.clock.bandLate' : 'recovery.clock.bandEarly', { seconds }) }));
  if (warning.direction === 'late') {
    const deadline = ownClockVoteDeadline(submissionChatCloseAt(), -warning.deviationMs);
    if (deadline?.kind === 'at') {
      const time = new Date(deadline.ms).toLocaleTimeString(state.lang,
        { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
      band.append(el('div', { textContent: state.tr('recovery.clock.bandDeadline', { time }) }));
    }
  }
  band.append(el('button', { type: 'button', textContent: state.tr('recovery.clock.manualEntry'),
    onclick: () => { void openManualClockCorrection(); }, style: 'margin-left:12px;' }));
  return band;
}

function renderFutureCountRows() {
  const counts = state.relay?.futureMarks.countsByType() || { chat: 0, action: 0 };
  const rows = [];
  if (counts.chat > 0) rows.push(el('div', { role: 'status',
    textContent: state.tr('recovery.chat.futureMessages', { count: counts.chat }) }));
  if (counts.action > 0) rows.push(el('div', { role: 'status',
    textContent: state.tr('recovery.chat.futureActions', { count: counts.action }) }));
  return rows;
}

let recoveryChatInput = null;
function recoveryChatInputFor() {
  const key = JSON.stringify([state.blockNum, state.groupId, state.uid]);
  if (recoveryChatInput?.key === key) return recoveryChatInput;
  const root = el('div', { className: 'chatContainer' });
  const inputArea = el('div', { className: 'chatInputArea' });
  const capWarn = el('div', { className: 'charCounter' });
  const ime = { composing: false, endedAt: 0 };
  const latest = { doSend: null, syncSendGate: null };
  // IME（日本語など）の変換確定 Enter で送信してしまわないようにする。判定が3重なのは
  // ブラウザによって確定時のイベント順が違うため:
  //   Chrome/Firefox … 確定 Enter の keydown が isComposing=true（keyCode 229）で届く
  //   Safari/一部IME … compositionend が keydown より先に出るので isComposing=false になり、
  //                     フラグだけでは取りこぼす → 直後の Enter は確定キーとみなして無視
  // 送信は「変換確定後にもう一度押した Enter」だけ。
  const ta = el('textarea', {
    className: 'chatInput', rows: 1,
    placeholder: state.tr('recovery.chat.inputPlaceholder'),
    value: state.draft.chat,
    oninput: (e) => { state.draft.chat = e.target.value; },
    oncompositionstart: () => { ime.composing = true; },
    oncompositionend: () => { ime.composing = false; ime.endedAt = Date.now(); },
    onkeydown: (e) => {
      if (e.key !== 'Enter' || e.shiftKey) return; // Shift+Enter は改行
      if (ime.composing || e.isComposing || e.keyCode === 229
        || (Date.now() - ime.endedAt) < IME_COMMIT_GUARD_MS) return;
      e.preventDefault();
      if (latest.doSend) latest.doSend();
    },
  });
  ta.addEventListener('input', () => { if (latest.syncSendGate) latest.syncSendGate(); });
  const sendBtn = el('button', { className: 'chatSendButton',
    textContent: state.relay?.ownHistoryReady === true ? state.tr('recovery.chat.send') : state.tr('recovery.chat.historyLoading'),
    onclick: () => { if (latest.doSend) latest.doSend(); } });
  inputArea.append(ta, sendBtn);
  root.append(inputArea);
  recoveryChatInput = { key, root, inputArea, capWarn, ta, sendBtn, ime, latest };
  return recoveryChatInput;
}

function clearGameAreaKeepingChat(g) {
  const kept = recoveryChatInput?.root?.parentNode === g ? recoveryChatInput.root : null;
  for (const child of Array.from(g.childNodes)) if (child !== kept) child.remove();
  return kept;
}

function placeChatSection(g, root) {
  if (root.parentNode === g) {
    const marker = document.createComment('chat-placement');
    g.append(marker);
    root._chatPlacement = marker;
  } else {
    g.append(root);
  }
}

function settleGameArea(g, kept) {
  const marker = kept?._chatPlacement;
  if (marker?.parentNode === g) {
    const preceding = [];
    for (let child = kept.nextSibling; child && child !== marker; child = child.nextSibling) preceding.push(child);
    kept.before(...preceding);
    marker.remove();
    kept._chatPlacement = null;
  } else if (kept?.parentNode === g) {
    kept.remove();
  }
}

// チャット（本体 ChatPhase の chatContainer/吹き出し/カウンター/入力欄を移植）
function renderChatSection(renderNow) {
  const container = el('div', { className: 'chatContainer' });
  const msgsBox = renderChatLog();
  const msgs = state.relay?.getMessages() || [];
  // v3.3追補: away（10分間操作なし）の間は吹き出し一覧にオーバーレイを被せて、既読を付けていない
  // ことを明示する。入力欄・投票/密告パネルは覆わない（クリック＝操作で即座に復帰する）。
  const msgsWrap = el('div', { className: 'chatMessagesWrap', style: 'flex-direction:column;' });
  for (const row of renderFutureCountRows()) msgsWrap.append(row);
  msgsWrap.append(msgsBox);
  if (state.away) {
    msgsWrap.append(el('div', { className: 'idleOverlay' },
      el('span', { textContent: state.tr('recovery.chat.idleOverlay') })));
  }
  container.append(msgsWrap);

  // 最低条件2行・送信上限2行・投票1行（本体 ChatPhase.js と同じ単位・判定）。
  // 本体は文字数/発言回数を渡された charCounts/messageCounts から取るが、こちらは
  // サーバーが無いので正準マージ済みメッセージから数える（採点の入力と同じ集合）。
  const { minChars, chatCaps } = state.cfg.pins;
  const myMsgs = msgs.filter((x) => x.uid === state.uid);
  // この端末が提出でき、かつ他メンバーの受領証明≥1件を持つメッセージだけを
  // 「文字数」「会話回数」に算入する。未読は数えず、「発言数」は総数（未読込み）。
  // 🔴 P-2026-0844: **画面 ≡ 採点**。採点は `applyChatCaps` を通した集合しか見ないので、
  //    達成状況（文字数・会話回数）も同じ集合から数える。これが無いと、1メッセージ上限を
  //    超えた貼り付け1通が画面にだけ算入され、両方緑のまま `min_messages` で失格する。
  //    「発言数 / 上限」と残枠（capCharsLeft / capMessagesLeft）は**総量**（未読・除外分込み）の
  //    ままにする＝上限の会計は本体の charCounts/messageCounts と同じく生カウントで行う。
  const progress = myReceiptedChatProgress(msgs, renderNow);
  const myCharsRaw = myRawChatTotals().chars; // キャップ判定用（総量）
  const myChars = progress.chars;
  const myMsgCount = myMsgs.length; // 発言数=総数（未読込み）
  const shown = myShownProgress(msgs, renderNow);
  const myTurns = shown.turns;
  const charsRemaining = Math.max(0, minChars - myChars);
  const turnsRemaining = Math.max(0, GUEST_PINNED_RULES.minMessages - shown.guarantee);
  const capCharsLeft = Math.max(0, chatCaps.maxChars - myCharsRaw);
  const capMessagesLeft = Math.max(0, chatCaps.maxMessages - myMsgCount);
  const hasVoted = !!state.myVote || state.observedP2P.vote;
  const voteReceipted = state.myVote ? actionReceipted(state.uid, 'vote', state.myVote) : false;

  const row = (left, rightText, ok) => {
    const d = el('div', { className: 'charCounter' });
    d.append(left);
    d.append(el('span', { className: ok ? 'charCountOk' : 'charCountWarning', textContent: rightText }));
    container.append(d);
  };

  // 1行目: 文字数
  row(
    el('span', { textContent: `${state.tr('recovery.chat.minCharProgress')}: ${myChars} / ${minChars}` }),
    charsRemaining > 0
      ? `${state.tr('recovery.chat.minCharsRemaining')} ${charsRemaining}`
      : state.tr('recovery.chat.minCharsReached'),
    charsRemaining === 0,
  );
  row(el('span', { textContent: `${state.tr('recovery.chat.maxCharProgress')}: ${myCharsRaw} / ${chatCaps.maxChars}` }),
    `${state.tr('recovery.chat.capRemaining')}: ${capCharsLeft}`, capCharsLeft > 0);

  // 最低会話数と全発言の上限は別行にする。
  {
    const left = el('span', { className: 'charCounterGroup' });
    left.append(el('span', {
      textContent: `${state.tr('recovery.chat.minTurnProgress')}: ${myTurns} / ${GUEST_PINNED_RULES.minMessages}`,
    }));
    row(
      left,
      turnsRemaining > 0
        ? `${state.tr('recovery.chat.minMsgsRemaining')} ${turnsRemaining}`
        : state.tr('recovery.chat.minMsgsReached'),
      turnsRemaining === 0,
    );
  }
  if (shown.failed || !shown.ready) container.append(el('div', { className: 'charCounter',
    textContent: state.tr(shown.failed ? 'recovery.chat.priorityPlanFailed' : 'recovery.chat.priorityNotReady') }));
  row(el('span', { textContent: `${state.tr('recovery.chat.maxPostProgress')}: ${myMsgCount} / ${chatCaps.maxMessages}` }),
    `${state.tr('recovery.chat.capRemaining')}: ${capMessagesLeft}`, capMessagesLeft > 0);

  // 投票（必須ミッション）。「投票」として数えられるのは受領証明≥1件を得てから＝
  // 緑(ok)は voteReceipted でゲート（発信済み・未受領は「受領待ち」＝正典未確定・§6.4）。
  // v3.3: void（10分経過・受領なし＝なかったこと）になったら同一対象への再送を促す。
  // 「完了」表示は void を除く（void=なかったこと＝再送しないと no_vote 失格。本体 ChatPhase voteCounted と同一）
  row(
    el('span', { textContent: `${state.tr('recovery.chat.voteStatus')}: ${state.tr(hasVoted && !myVoteIsVoid() ? 'recovery.chat.voteDone' : 'recovery.chat.voteNotYet')}` }),
    hasVoted
      ? state.tr(voteReceipted
        ? 'recovery.chat.voteCleared'
        : (myVoteIsVoid()
          ? (Number.isSafeInteger(submissionChatCloseAt())
            && clientNow() >= submissionChatCloseAt() - VOTE_RECEIPT_CUTOFF_MS
            ? 'recovery.action.voteVoidNoResend' : 'recovery.action.voteVoidResend')
          : 'recovery.chat.voteAwaitingReceipt'))
      : state.tr('recovery.chat.votePending'),
    voteReceipted,
  );

  const chatInput = recoveryChatInputFor();
  const { ta, sendBtn, capWarn } = chatInput;
  // 🔴 P-2026-0844: 上限超過の警告行（本体 ChatPhase の `msgTooLong` 警告に相当）。
  //    入力欄の直前に置き、`syncSendGate` が入力のたびに書き換える。
  container.append(capWarn);

  const doSend = () => {
    const text = ta.value.trim(); // 本体 handleSend と同じく trim 後を送る
    // 本体 handleSend と同じ4ゲート（可視内容 / 1メッセージ上限 / 発言数上限 / 総文字数上限）。
    // sendChat 側にも同じゲートがあるが、ここで止めないと入力欄だけ空になる。
    if (chatSendBlockReason(text)) return;
    if (state.relay?.ownHistoryReady !== true) return;
    state.draft.chat = '';
    ta.value = '';
    sendChat(text);
    syncSendGate();
  };
  // 枠切れ・上限超過なら送信ボタンを無効化し、理由を明示する（本体は
  // `disabled={!inputText.trim() || overMsgCap || overTotalCap}` ＋ 警告行）。
  function syncSendGate() {
    const reason = chatSendBlockReason(ta.value);
    sendBtn.disabled = reason !== null || state.relay?.ownHistoryReady !== true;
    sendBtn.textContent = state.relay?.ownHistoryReady === true ? state.tr('recovery.chat.send') : state.tr('recovery.chat.historyLoading');
    capWarn.innerHTML = '';
    const visibleReason = reason === 'empty'
      ? (capMessagesLeft <= 0 ? 'maxMsgs' : capCharsLeft <= 0 ? 'maxChars' : null)
      : reason;
    if (visibleReason) {
      capWarn.append(el('span', { className: 'charCountWarning', textContent: chatSendBlockText(visibleReason) }));
    }
  }
  chatInput.latest.doSend = doSend;
  chatInput.latest.syncSendGate = syncSendGate;
  syncSendGate(); // 初期状態（下書き復元・枠切れ後の再描画）にも効かせる
  const placeholder = state.tr('recovery.chat.inputPlaceholder');
  if (ta.placeholder !== placeholder) ta.placeholder = placeholder;
  for (const child of Array.from(chatInput.root.childNodes)) if (child !== chatInput.inputArea) child.remove();
  chatInput.inputArea.before(...Array.from(container.childNodes));

  // 新着で最下部へ（描画後）
  setTimeout(() => { msgsBox.scrollTop = msgsBox.scrollHeight; }, 0);
  return chatInput.root;
}

// 投票・密告パネル（本体 ChatPhase の actionPanel を移植・v3.2 one-shot＋受領状況表示）
function renderActionPanel() {
  const panel = el('div', { className: 'actionPanel' });
  // 投票・密告の対象は「自分以外の全員」（最終的な失格・採点は提出物が権威なのでUIで足切りしない）
  const others = state.members.filter((m) => m.uid !== state.uid);
  const hasVoted = !!state.myVote || state.observedP2P.vote;

  // 締切警告は投票と密告の設定可能期間を示す。
  if (!hasVoted) {
    panel.append(el('div', { className: 'actionDescription deadlineWarning', textContent: state.tr('recovery.action.deadlineWarning') }));
  }

  // 受領状況の1行（発信済みアクション用）: 受領待ち → 確定
  const receiptStatusRow = (receipted) => el('div', {
    className: receipted ? 'receiptStatus receiptStatusOk' : 'receiptStatus',
    textContent: receipted
      ? `✓ ${state.tr('recovery.chat.voteCleared')}`
      : state.tr('recovery.chat.voteAwaitingReceipt'),
  });

  // 投票（必須・1名・変更不可）
  const voteSec = el('div', { className: 'actionSection' });
  voteSec.append(el('div', { className: 'actionTitle', textContent: state.tr('recovery.action.voteTitle') }));
  voteSec.append(el('div', { className: 'actionDescription', textContent: state.tr('recovery.action.voteDescription') }));
  voteSec.append(el('div', { className: 'actionDescription', textContent: state.tr('recovery.action.receiptNotice') }));
  const voteBtns = el('div', { className: 'actionButtons' });
  // 自セッションで投じた分は intent、別クライアント発（P2P観測）分は暗号文を自己復号して相手を特定。
  const voteTarget = state.intent.vote || decryptSelfTarget(state.myVote?.encrypted);
  // v3.3: void（10分経過・受領なし＝なかったこと）になった場合のみ同一対象へ再送可能
  const voteVoid = myVoteIsVoid();
  // 受領済み（他メンバーの受領証明≥1件）なら濃い色、受領待ちなら薄い色にする
  const voteReceiptedNow = !!state.myVote && actionReceipted(state.uid, 'vote', state.myVote);
  const voteCloseAt = submissionChatCloseAt();
  const cutoff = Number.isSafeInteger(voteCloseAt) ? voteCloseAt - VOTE_RECEIPT_CUTOFF_MS : null;
  const votingClosed = cutoff !== null && clientNow() >= cutoff;
  for (const m of others) {
    // void（なかったこと）は選択色を消して押す前の見た目に戻す＝投票済みに見せない
    const isVoted = voteTarget === m.uid && !voteVoid;
    const voteDisabled = (voteVoid
      ? m.uid !== voteTarget
      : (!!state.myVote || state.observedP2P.vote)) || votingClosed;
    const resendSuffix = voteVoid && m.uid === voteTarget ? ` (${state.tr('recovery.action.resendLabel')})` : '';
    voteBtns.append(el('button', {
      // 受領待ち（既読なし＝正典未確定）は薄い色、受領済みで濃い色にする
      className: isVoted
        ? (voteReceiptedNow ? 'actionButtonActiveVote' : 'actionButtonActiveVotePending')
        : voteDisabled ? 'actionButtonDisabled' : 'actionButton',
      textContent: memberName(m) + resendSuffix, ...recoveryPlayerTitle(m.uid),
      disabled: voteDisabled,
      onclick: () => { if (!voteDisabled) sendVote(m.uid); },
    }));
  }
  voteSec.append(voteBtns);
  if (state.myVote) voteSec.append(receiptStatusRow(actionReceipted(state.uid, 'vote', state.myVote)));
  panel.append(voteSec);

  // 密告（最大2名）
  const repSec = el('div', { className: 'actionSection' });
  repSec.append(el('div', { className: 'actionTitle', textContent: state.tr('recovery.action.reportTitle') }));
  repSec.append(el('div', { className: 'actionDescription', textContent: state.tr('recovery.action.reportDescription') }));
  repSec.append(el('div', { className: 'actionDescription', textContent: state.tr('recovery.action.receiptNotice') }));
  const repBtns = el('div', { className: 'actionButtons' });
  // 既知の密告相手 = 自セッションで出した分(intent) ∪ P2P観測分(自己復号)。復元ツールは自分の
  // 密告を必ず自己復号できるので、game.js 等で先に出した密告も自分のものとして「完成」させられる。
  // ロックは observedP2P.report の全ロックではなく distinct 相手数で判定する（最大2）。これで
  // game.js で1件出した後でも復元ツールで2件目を追加でき、提出は両方を含む（sendReport が intent を
  // 全distinct集合に更新＝bundle.js の intent フィルタで観測分が落ちず A-3 も一致で通過）。
  const knownReportTargets = [...new Set([
    ...(state.intent.reports || []),
    ...state.myReports.map((r) => decryptSelfTarget(r.encrypted)).filter(Boolean),
  ])];
  // 密告の2枠は、最初の受領証明の時刻が早い順の2人で決まる。受領証明の無い（void の）
  // 密告は、その後でだけ枠を取る。正直な画面は void の対象も2枠に数え、3人目への密告を出させない。
  const repStatus = reportTargetStatusMap();
  const activeReportSlots = Object.keys(repStatus).length;
  const maxReports = state.cfg.pins.maxReports;
  // 資格は見える確定した投票。ラスト10分は送信の門だけ全員へ開く。
  for (const m of others) {
    const already = knownReportTargets.includes(m.uid);
    const maxReached = activeReportSlots >= maxReports;
    const hasConfirmedVote = hasVisibleConfirmedVote(m.uid, clientNow());
    const waitingForVote = !already && !hasConfirmedVote;
    const reportGateClosed = !canReportTarget(m.uid, clientNow());
    // void の同一対象への再送は distinct 枠を増やさないため、2対象使用済みでも可能。
    const canResend = already && repStatus[m.uid] === 'void';
    const disabled = canResend ? reportGateClosed : (already || maxReached || reportGateClosed);
    const resendSuffix = (canResend ? ` (${state.tr('recovery.action.resendLabel')})` : '')
      + (waitingForVote
        ? ` (${state.tr(votingClosed ? 'recovery.action.reportVoteNotVisible' : 'recovery.action.reportWaitingVote')})`
        : '');
    repBtns.append(el('button', {
      // 選択色は void を除く＝void（なかったこと）は押す前の見た目に戻す（投票ボタンと同じ）
      className: already && repStatus[m.uid] !== 'void'
        ? (repStatus[m.uid] === 'receipted' ? 'actionButtonActiveReport' : 'actionButtonActiveReportPending')
        : disabled ? 'actionButtonDisabled' : 'actionButton',
      textContent: memberName(m) + resendSuffix, ...recoveryPlayerTitle(m.uid),
      disabled,
      onclick: () => { if (!disabled) sendReport(m.uid); },
    }));
  }
  repSec.append(repBtns);
  // 受領ステータス行は密告セクションには出さない（2026-08-05）。
  // ・文言が 'recovery.chat.voteCleared'（＝「投票クリア」）固定で、密告なのに投票と表示される
  // ・本体 ChatPhase の密告セクションにもこの行は無く、受領状態はボタン色
  //   （actionButtonActiveReport ⇄ …ReportPending）だけで表している
  // 復元ツールは本体の見た目に揃えるのが原則なので行ごと削除する。
  panel.append(repSec);

  return panel;
}

let recoveryGuaranteeView = null;
let recoveryGuaranteeScheduler = createGuaranteeScheduler();
let recoveryGuaranteeCache = createSummaryCache();
let recoveryGuaranteeFingerprint = null;
let recoveryGuaranteeSigner = null;
let recoveryGuaranteeHost = null;
let recoveryOnChainView = null;
let recoveryOnChainFingerprint = null;
let recoveryOnChainScheduler = createGuaranteeScheduler();

async function recoveryPrePressDryRun(isCurrent) {
  if (!state.identity?.signKey || !state.identity?.encryptKey || !rosterReady()) return null;
  const dryRunWindow = submissionChatWindow();
  if (!Number.isSafeInteger(dryRunWindow?.startMs)
      || !Number.isSafeInteger(dryRunWindow?.endMs)) return null;
  if (!recoveryGuaranteeSigner) recoveryGuaranteeSigner = makeDryRunSigner();
  const signer = recoveryGuaranteeSigner;
  overcapHiddenMemo = null;
  const built = await buildSubmissionBundle(recoveryBundleArgs({
    myDepositIds: recoveryMyDepositIds().ids,
    chatWindow: dryRunWindow,
    priorityChatWindow: undefined,
    signWallet: (message) => signer.signMessage(message),
    submittedAt: onChainDryRunSubmittedAt(dryRunWindow),
  }));
  if (!isCurrent()) return null;
  await new Promise((resolve) => globalThis.setTimeout(resolve, 0));
  let payload = built.payload;
  const plan = await planOnChainTrim(built.payload, state.uid, { chatWindow: dryRunWindow });
  if (plan?.impossible) throw new Error('Cannot plan the on-chain submission');
  if (plan && trimPlanDropsSelfAggregate(built.payload, plan)) throw new Error('Cannot verify the on-chain estimate');
  if (plan) {
    payload = await signTrimmedPayload(plan.trimmedBundle, {
      blockNum: state.blockNum,
      signMessage: (message) => signer.signMessage(message),
      compactContext: plan.compactContext,
    });
  }
  if (!isCurrent()) return null;
  await new Promise((resolve) => globalThis.setTimeout(resolve, 0));
  return { payload, signerAddress: signer.address, chatWindow: dryRunWindow };
}

function recoveryGuaranteeInputs() {
  const identity = `${state.blockNum}|${state.groupId}|${state.uid}`;
  const stored = loadRecoveryEvidencePayload(state.blockNum, state.uid);
  // compactPayloadToBytes is the byte count used by measureOnChainBytes; an oversized
  // saved bundle cannot be submitted through the recovery on-chain path.
  const storedOverLimit = !state.onchainTxHash && stored && isEvidenceCompactPayload(stored)
    && compactPayloadToBytes(stored).length >= EVIDENCE_MAX_DATA_BYTES;
  const stage = state.onchainTxHash ? 'accepted' : stored && !storedOverLimit ? 'signed' : 'pre';
  const record = stage === 'accepted'
    ? readOnChainRecord(localStorage, state.blockNum, state.uid) : null;
  const payload = stage === 'accepted'
    ? payloadForAcceptedTx(record, state.onchainTxHash, stored) : stage === 'signed' ? stored : null;
  const chatWindow = stage === 'accepted' ? record?.chatWindow ?? submissionChatWindow()
    : stage === 'signed' ? loadRecoveryEvidencePayloadWindow(state.blockNum, state.uid, stored) ?? submissionChatWindow()
    : submissionChatWindow();
  const messages = state.relay?.getMessages() || [];
  const admitted = recoveryAdmittedReceipts();
  const shown = recoveryShownKeys();
  const ownMessages = messages.filter((message) => message?.uid === state.uid);
  const fingerprint = JSON.stringify({
    identity, stage, payload, txHash: state.onchainTxHash,
    rosterReady: rosterReady(),
    members: (state.members || []).map((member) => [member.uid, member.addr, member.bAddr, member.depIds]),
    chatWindow: [chatWindow?.startMs, chatWindow?.endMs],
    messages: [ownMessages.length, ownMessages.at(-1)?.signature],
    myVote: state.myVote?.signature,
    myVotePrev: (state.myVotePrev || []).map((vote) => vote.signature),
    myReports: (state.myReports || []).map((report) => report.signature),
    ...(stage === 'pre' ? {
      phase: currentPhase(), stored,
      chatCloseAt: submissionChatCloseAt(),
      preBundleMessages: [messages.length, messages.at(-1)?.signature],
      receiptSelectionRevision: state.receiptSelectionRevision,
      admitted: [admitted?.length, admitted?.at(-1)?.signature],
      observedVotes: Object.values(state.observedActions?.votes || {}).map((entry) =>
        Array.isArray(entry) ? entry.map((item) => item.signature) : entry?.signature),
      observedReports: Object.values(state.observedActions?.reports || {}).map((entries) =>
        (entries || []).map((entry) => entry.signature)),
      reportGrounds: Object.values(state.reportGrounds || {}).map((ground) =>
        [ground?.votes?.length, ground?.receipts?.length]),
      priorityLock: usableRecoveryLock() ? true : false,
      shown: shown.size,
      signKey: state.identity?.signKey || null,
      encryptKey: state.identity?.encryptKey || null,
      intent: state.intent,
    } : {}),
  });
  return { identity, stage, payload, chatWindow, messages, fingerprint,
    multiple: record?.multiple === true
      || (state.rosterProof?.sharedWalletUids === 1
        && state.rosterProof.blockNum === Number(state.blockNum)
        && String(state.rosterProof.uid) === String(state.uid)
        && state.evidenceSenderCountBlockNum === Number(state.blockNum)
        && typeof state.evidenceSenderCountWallet === 'string'
        && typeof state.rosterProof.walletAddress === 'string'
        && state.evidenceSenderCountWallet.toLowerCase() === state.rosterProof.walletAddress.toLowerCase()
        && state.evidenceSenderCount >= 2) };
}

function renderGuaranteeSection() {
  const source = recoveryGuaranteeInputs();
  const view = recoveryGuaranteeView?.stage === source.stage
    && recoveryGuaranteeView.identity === source.identity
    && recoveryGuaranteeView.inputKey === (source.stage === 'pre' ? source.fingerprint : source.payload)
    ? recoveryGuaranteeView : { status: 'checking' };
  const section = el('div', { className: 'submissionField' });
  if (source.stage === 'pre' && state.evidenceSenderCount >= 1) return section;
  const multiple = source.stage === 'accepted' && source.multiple;
  const heading = source.stage === 'accepted' && !multiple ? 'headingAccepted'
    : source.stage === 'signed' || multiple ? 'headingSigned' : 'headingPreOnChain';
  section.append(el('div', { className: 'submissionLabelLarge',
    textContent: state.tr(`recovery.submit.guarantee.${heading}`) }));
  if (multiple) section.append(el('div', { className: 'statusText',
    textContent: state.tr('recovery.submit.guarantee.noteMultiple') }));
  if (source.stage === 'signed' || source.stage === 'pre') section.append(el('div', { className: 'statusText', textContent: state.tr('recovery.submit.guarantee.notePriorOnChain') }));
  if (view.status !== 'ready') {
    section.append(el('div', { className: 'statusText',
      textContent: view.error || state.tr(`recovery.submit.guarantee.${view.status === 'failed' ? 'failed' : 'checking'}`) }));
    if (source.stage === 'signed' && !(state.evidenceSenderCount >= 1)) section.append(renderRecoveryOnChainPreview(false));
    return section;
  }
  const display = describeSubmissionGuarantee(view.summary);
  for (const { key, params, alert, note } of display.rows) {
    const resolved = { ...params };
    if (key === 'voteDone') {
      resolved.name = memberName(state.members.find((member) => member.uid === params.targetUid));
    }
    if (key === 'reports') {
      resolved.names = params.targetUids.map((uid) =>
        memberName(state.members.find((member) => member.uid === uid)))
        .join(state.tr('recovery.submit.guarantee.nameSeparator'));
    }
    section.append(el('div', { className: 'statusText',
      style: alert ? 'color:#f44336' : '',
      textContent: state.tr(`recovery.submit.guarantee.${key}`, resolved) }));
    if (note) section.append(el('div', { className: 'statusText', style: 'font-size:0.85em',
      textContent: state.tr(`recovery.submit.guarantee.${note.key}`, note.params) }));
  }
  for (const key of display.notes) section.append(el('div', { className: 'statusText',
    textContent: state.tr(`recovery.submit.guarantee.${key === 'noteRejected' && state.onchainTxHash
      ? 'noteRejectedAccepted' : key}`) }));
  const mainLowTurnsNote = display.rows.some(({ key, params }) => key === 'turnsUnprotected'
    || (key === 'turns' && params.count < 20));
  if (mainLowTurnsNote) {
    section.append(el('div', { className: 'statusText', style: 'font-size:0.85em',
      textContent: state.tr('recovery.submit.guarantee.noteLowTurns') }));
  }
  if (source.stage === 'signed' && !(state.evidenceSenderCount >= 1)) section.append(renderRecoveryOnChainPreview(mainLowTurnsNote));
  return section;
}

function renderRecoveryOnChainPreview(mainLowTurnsNote) {
  const section = el('div', { className: 'submissionField', style: 'margin-top:16px' });
  if (state.evidenceSenderCount >= 1) return section;
  section.append(el('div', { className: 'submissionLabelLarge',
    textContent: state.tr('recovery.submit.guarantee.headingPreOnChain') }));
  const view = recoveryOnChainView?.fingerprint === recoveryOnChainFingerprint
    ? recoveryOnChainView : { status: 'checking' };
  if (view.status !== 'ready') {
    section.append(el('div', { className: 'statusText',
      textContent: view.error || state.tr(`recovery.submit.guarantee.${view.status === 'failed' ? 'failed' : 'checking'}`) }));
    return section;
  }
  const display = describeSubmissionGuarantee(view.summary);
  for (const { key, params, alert, note } of display.rows) {
    const resolved = { ...params };
    if (key === 'voteDone') {
      resolved.name = memberName(state.members.find((member) => member.uid === params.targetUid));
    }
    if (key === 'reports') {
      resolved.names = params.targetUids.map((uid) =>
        memberName(state.members.find((member) => member.uid === uid)))
        .join(state.tr('recovery.submit.guarantee.nameSeparator'));
    }
    section.append(el('div', { className: 'statusText', style: alert ? 'color:#f44336' : '',
      textContent: state.tr(`recovery.submit.guarantee.${key}`, resolved) }));
    if (note) section.append(el('div', { className: 'statusText', style: 'font-size:0.85em',
      textContent: state.tr(`recovery.submit.guarantee.${note.key}`, note.params) }));
  }
  for (const key of display.notes.filter((note) => note !== 'noteAlways')) {
    section.append(el('div', { className: 'statusText',
      textContent: state.tr(`recovery.submit.guarantee.${key}`) }));
  }
  if (!mainLowTurnsNote && display.rows.some(({ key, params }) => key === 'turnsUnprotected'
      || (key === 'turns' && params.count < 20))) {
    section.append(el('div', { className: 'statusText', style: 'font-size:0.85em',
      textContent: state.tr('recovery.submit.guarantee.noteLowTurns') }));
  }
  return section;
}

function scheduleRecoveryOnChainPreview() {
  const source = recoveryGuaranteeInputs();
  if (source.stage !== 'signed' || state.evidenceSenderCount >= 1 || recoveryGuaranteePressing) {
    recoveryOnChainScheduler.cancel();
    recoveryOnChainFingerprint = null;
    return;
  }
  const admitted = recoveryAdmittedReceipts();
  const messages = source.messages;
  const fingerprint = JSON.stringify({
    identity: source.identity, window: submissionChatWindow(),
    rosterReady: rosterReady(),
    members: (state.members || []).map((member) =>
      [member.uid, member.addr, member.bAddr, member.depIds]),
    messages: [messages.length, messages.at(-1)?.signature],
    admitted: [admitted?.length, admitted?.at(-1)?.signature],
    receiptSelectionRevision: state.receiptSelectionRevision,
    observedVotes: Object.values(state.observedActions?.votes || {}).map((entry) =>
      Array.isArray(entry) ? entry.map((item) => item.signature) : entry?.signature),
    observedReports: Object.values(state.observedActions?.reports || {}).map((entries) =>
      (entries || []).map((entry) => entry.signature)),
    reportGrounds: Object.values(state.reportGrounds || {}).map((ground) =>
      [ground?.votes?.length, ground?.receipts?.length]),
    myVote: state.myVote?.signature,
    myVotePrev: (state.myVotePrev || []).map((vote) => vote.signature),
    myReports: (state.myReports || []).map((report) => report.signature),
    priorityLock: usableRecoveryLock() ? true : false,
    shown: recoveryShownKeys().size,
    signKey: state.identity?.signKey || null,
    encryptKey: state.identity?.encryptKey || null,
    intent: state.intent,
    phase: currentPhase(), chatCloseAt: submissionChatCloseAt(),
  });
  if (fingerprint === recoveryOnChainFingerprint) return;
  recoveryOnChainFingerprint = fingerprint;
  recoveryOnChainScheduler.cancel();
  recoveryOnChainView = { fingerprint, status: 'checking' };
  const dryRunWindow = submissionChatWindow();
  if (!rosterReady() || currentPhase() === 'unknown'
      || !Number.isSafeInteger(dryRunWindow?.startMs)
      || !Number.isSafeInteger(dryRunWindow?.endMs)
      || dryRunWindow.startMs > dryRunWindow.endMs
      || !state.identity?.signKey || !state.identity?.encryptKey) return;
  recoveryOnChainScheduler.request(async (isCurrent) => {
    const dryRun = await recoveryPrePressDryRun(isCurrent);
    if (!isCurrent() || !dryRun) return null;
    const ownActions = { votes: [state.myVote, ...(state.myVotePrev || [])].filter(Boolean),
      reports: (state.myReports || []).filter(Boolean) };
    const ownMessages = messages.filter((message) => message?.uid === state.uid);
    const summary = await summarizeOwnSubmission(dryRun.payload, {
      blockNum: state.blockNum, groupId: state.groupId, myUid: state.uid,
      members: state.members, chatWindow: dryRun.chatWindow,
      signerAddress: dryRun.signerAddress, ownMessages, ownActions,
    });
    return { status: 'ready', summary };
  }, (result) => {
    recoveryOnChainView = { fingerprint,
      status: result?.status === 'ready' ? 'ready' : 'failed',
      summary: result?.summary ?? null,
      error: ['vote_undecryptable', 'vote_mismatch', 'report_undecryptable', 'report_missing']
        .includes(result?.error?.code) ? result.error.message : null };
    if (recoveryGuaranteeHost?.isConnected) recoveryGuaranteeHost.replaceChildren(renderGuaranteeSection());
  });
}

function scheduleRecoveryGuarantee() {
  if (recoveryGuaranteePressing) {
    recoveryGuaranteeScheduler.cancel();
    recoveryGuaranteeFingerprint = null;
    return;
  }
  const source = recoveryGuaranteeInputs();
  if (source.fingerprint === recoveryGuaranteeFingerprint) return;
  recoveryGuaranteeFingerprint = source.fingerprint;
  recoveryGuaranteeScheduler.cancel();
  const inputKey = source.stage === 'pre' ? source.fingerprint : source.payload;
  const checking = { stage: source.stage, identity: source.identity, inputKey,
    status: 'checking', summary: null };
  recoveryGuaranteeView = checking;
  if (!rosterReady() || (source.stage === 'pre' && currentPhase() === 'unknown')
      || !Number.isSafeInteger(source.chatWindow?.startMs)
      || !Number.isSafeInteger(source.chatWindow?.endMs)
      || source.chatWindow.startMs > source.chatWindow.endMs
      || (source.stage === 'pre' && (!state.identity?.signKey || !state.identity?.encryptKey))) return;
  if (source.stage !== 'pre' && !source.payload) {
    recoveryGuaranteeView = { ...checking, status: 'failed' };
    return;
  }
  recoveryGuaranteeScheduler.request(async (isCurrent) => {
    const dryRun = source.stage === 'pre' ? await recoveryPrePressDryRun(isCurrent) : null;
    if (!isCurrent()) return null;
    const payload = source.stage === 'pre' ? dryRun?.payload : source.payload;
    if (!payload) return { status: 'checking' };
    const ownActions = { votes: [state.myVote, ...(state.myVotePrev || [])].filter(Boolean),
      reports: (state.myReports || []).filter(Boolean) };
    const ownMessages = source.messages.filter((message) => message?.uid === state.uid);
    const chatWindow = dryRun?.chatWindow ?? source.chatWindow;
    const key = JSON.stringify({
      sha256: submissionPayloadSha256(payload),
      roster: state.members.map((member) => [member.uid, member.addr, member.bAddr, member.depIds]),
      window: chatWindow,
      ownMessages: [ownMessages.length, ownMessages.at(-1)?.signature],
      ownActions: [...ownActions.votes, ...ownActions.reports].map((action) => action.signature),
    });
    let summary = recoveryGuaranteeCache.get(key);
    if (summary === undefined) {
      summary = await summarizeOwnSubmission(payload, {
        blockNum: state.blockNum, groupId: state.groupId, myUid: state.uid,
        members: state.members, chatWindow,
        signerAddress: dryRun?.signerAddress ?? null,
        ownMessages, ownActions,
      });
      recoveryGuaranteeCache.set(key, summary);
    }
    return { status: 'ready', summary };
  }, (result) => {
    recoveryGuaranteeView = { stage: source.stage, identity: source.identity, inputKey,
      status: result?.status === 'ready' ? 'ready' : result?.status === 'checking' ? 'checking' : 'failed',
      summary: result?.summary ?? null,
      error: ['vote_undecryptable', 'vote_mismatch', 'report_undecryptable', 'report_missing']
        .includes(result?.error?.code) ? result.error.message : null };
    if (recoveryGuaranteeView.status === 'failed' && !rosterReady()) recoveryGuaranteeFingerprint = null;
    if (recoveryGuaranteeHost?.isConnected) recoveryGuaranteeHost.replaceChildren(renderGuaranteeSection());
  });
}

// 提出（本体 SubmissionPhase の submissionCard/submitButton を移植）
function renderSubmitSection() {
  const card = el('div', { className: 'submissionCard' });
  // チャット履歴（読み取り専用）。本体 SubmissionPhase と同じく、何を提出しようとしているのかを
  // 確認できるよう出す。提出期間はチャット終了済み＝受領証明はもう増えないので、受領証明≥1件
  //（正典候補）のものだけを表示する（未読のまま終わった発言/発信は出てこない＝未読警告も不要）。
  const chat = el('div', { className: 'chatContainer' });
  for (const row of renderFutureCountRows()) chat.append(row);
  chat.append(renderChatLog({ receiptedOnly: true }));
  card.append(chat);

  // 確認済みの提出 tx があればボタンは出さず「提出済み: (tx hash)」だけ表示（reorg以外は確定）。
  // リロード後も localStorage から復元される（何度も押せる回帰の防止）。
  if (!state.onchainTxHash) state.onchainTxHash = loadOnchainTx();
  recoveryGuaranteeHost = el('div');
  scheduleRecoveryGuarantee();
  scheduleRecoveryOnChainPreview();
  recoveryGuaranteeHost.append(renderGuaranteeSection());
  card.append(recoveryGuaranteeHost);
  card.append(el('div', { className: 'statusText', textContent: `${state.tr('recovery.senderSlots')}: ${state.evidenceSenderCount == null ? '–' : `${state.evidenceSenderCount}/3`}` }));
  if (state.rosterProof?.sharedWalletUids > 1) card.append(el('div', {
    className: 'statusText', textContent: state.tr('recovery.sharedWalletLimit'),
  }));
  if (state.onchainTxHash) {
    card.append(el('div', { className: 'statusText', style: 'color:#4caf50; font-size:1.15em; font-weight:bold; text-align:center;' },
      `⛓ ${state.tr('recovery.onchainDone')}: ${shortHash(state.onchainTxHash)}`));
  } else {
    card.append(el('button', { className: 'submitButton', textContent: state.tr('recovery.submit'),
      disabled: recoveryGuaranteePressing > 0 || state.evidenceSenderCount >= 3,
      onclick: reconstructAndSubmit }));
    card.append(el('div', { id: 'submit-result', className: 'statusText' }));
  }
  return card;
}

function renderRelaySettings() {
  const area = $('relay-area');
  area.innerHTML = '';
  const ta = el('textarea', { value: getRelayList().join('\n'), rows: 5 });
  const btn = el('button', {
    textContent: state.tr('recovery.relay.save'),
    onclick: () => {
      const saved = saveRelayList(ta.value.split('\n').map((s) => s.trim()).filter(Boolean));
      log(state.tr(saved ? 'recovery.relay.saved' : 'recovery.relay.saveFailed'));
    },
  });
  area.append(ta, btn);
}

// 静的ラベル（セットアップカード等）を選択言語で更新
function applyStaticLabels() {
  document.title = state.tr('app.title');
  const set = (id, text) => { const e = $(id); if (e) e.textContent = text; };
  set('app-title', state.tr('recovery.title'));
  set('connect-btn', state.tr('recovery.connect'));
  set('discover-btn', state.tr('recovery.discover'));
  set('derive-btn', state.tr('recovery.sign'));
  set('saved-rescue-btn', state.tr('recovery.savedRescue'));
  set('restart-btn', state.tr('recovery.restart'));
  set('storage-import-title', state.tr('recovery.import.title'));
  set('storage-import-description', state.tr('recovery.import.description', { signLabel: state.tr('recovery.sign') }));
  set('storage-import-btn', state.tr('recovery.import.button'));
  set('wallet-modal-title', state.tr('recovery.selectWallet'));
  set('conn-modal-title', state.tr('recovery.connection.title'));
  set('conn-settings-title', state.tr('recovery.connection.settingsTitle'));
  set('conn-settings-desc', state.tr('recovery.connection.settingsDesc'));
  set('conn-relay-desc', state.tr('recovery.connection.p2pDescription'));
  const bi = $('block-input');
  if (bi) bi.placeholder = state.tr('recovery.block');
}

function init() {
  // 握りつぶされる例外を必ずログ欄に出す（復元ツールはDevToolsを開けないユーザーが前提）
  window.addEventListener('error', (e) => log(`ERROR: ${e.message}`));
  window.addEventListener('unhandledrejection', (e) => log(`ERROR: ${e.reason?.message || e.reason}`));
  window.addEventListener('pagehide', () => flushRecoveryShownKeys(recoveryShownMemory));
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') flushRecoveryShownKeys(recoveryShownMemory);
  });
  const langSel = $('lang-select');
  for (const l of SUPPORTED_LANGS) {
    const o = el('option', { value: l, textContent: t(l)('lang.name') }); if (l === state.lang) o.selected = true; langSel.append(o);
  }
  langSel.onchange = () => {
    state.lang = langSel.value; state.tr = t(state.lang); saveConfig({ lang: state.lang });
    applyStaticLabels(); renderGame(); renderStaleBlockBand();
  };
  $('connect-btn').onclick = connectWallet;
  $('discover-btn').onclick = discoverUid;
  $('step-block')?.append(el('button', { id: 'saved-rescue-btn', type: 'button',
    textContent: state.tr('recovery.savedRescue'), disabled: recoveryGuaranteePressing > 0,
    onclick: rescueSavedSubmission }));
  $('derive-btn').onclick = deriveAndLoad;
  $('storage-import-btn').onclick = importOfficialLocalStorage;
  // ブロック番号が空だと検索ボタンを押せない（ブロック0での誤動作防止）
  $('block-input').oninput = () => { $('discover-btn').disabled = $('block-input').value.trim() === ''; };
  $('block-input').onkeydown = (e) => { if (e.key === 'Enter' && !$('discover-btn').disabled) discoverUid(); };
  // 再スタート: ウォレット接続からやり直す（クリーンにリロード）
  $('restart-btn').onclick = () => location.reload();
  // ウォレット選択モーダルを閉じる
  $('wallet-modal-close').onclick = closeWalletModal;
  $('wallet-modal').onclick = (e) => { if (e.target === $('wallet-modal')) closeWalletModal(); };
  // 接続状態モーダルを閉じる
  $('conn-modal-close').onclick = closeConnModal;
  $('conn-modal').onclick = (e) => { if (e.target === $('conn-modal')) closeConnModal(); };
  applyStaticLabels();
  renderRelaySettings();
  renderGame();
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}

// 未来時刻の発信は、端末時刻がその timestamp を厳密に超えるまで表示・カウントしない。
export function isTimestampVisible(timestamp, nowMs) {
  return timestamp < nowMs;
}

// 投票のどれか1つが見え、第三者の期限内受領証明を持つときだけ資格を満たす。
export function hasTimestampVisibleConfirmedVote({
  votes, ownUid, targetUid, nowMs, receiptorsForVote,
}) {
  return (votes || []).some((vote) => vote?.encrypted
    && isTimestampVisible(vote.timestamp, nowMs)
    && [...(receiptorsForVote(vote) || [])].some((uid) => uid !== ownUid && uid !== targetUid));
}

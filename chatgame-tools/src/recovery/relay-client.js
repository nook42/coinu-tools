// src/recovery/relay-client.js — 復元クライアントの Nostr リレー駆動（ブラウザ専用）
//
// 正典 GameRelayChannel（vendored・byte-exact）を wrap する。運営WSは使わない（書込不可）ので、
// chat/action(投票・密告)/receipt(受領証明) の発行と、他メンバー分の購読・
// リレーと検証済み公開 live JSON を正準マージする。バンドル再構成には
// getMessages()/getRelayActionsRaw()/getReceipts() を渡す。
//
// 依存: 実行時に window/WebSocket/localStorage が必要（ブラウザ）。Node からは import 可だが start() は不可。

import { verifyMessage } from 'viem';
import {
  GameRelayChannel, isClientTimestampAllowed, saveRelayList, getRelayList,
  receiptIdentityDigest, MAX_RECEIPTS_PER_ISSUER, CarriedReceiptStoreIndex, readLiveSnapshot, LIVE_SNAPSHOT_POLL_MS, LIVE_SNAPSHOT_MAX_BYTES,
  readReceiptChainTime,
  ownHistoryComplete, ownHistoryPromptKind, ownHistoryPromptDueAt,
  verifyLiveSnapshotEntries, FutureAdmissionMarks, isClientChatWithinLimit, LiveSnapshotRejectionMemory,
} from '../../vendor/src/utils/relay.js';
import { chatSignStringV2, dedupAndSortV2, buildMsgKeyGetter, msgRefOf, MAX_OBSERVED_ACTIONS_PER_ACTOR, buildRealTargets } from '../../vendor/src/utils/protocol.js';
import { receiptCanonCmp } from '../../vendor/workers/game_workers/lib/game-result-calculator.js';
import { makeVerifyRelayInner } from './relay-verify.js';
import { readReceiptConnectionChange } from '../../vendor/src/utils/read-receipt-pause.js';
// V25-03 / C25-01: 本体の P2P 受信口と同じ正準ゲートを使う。
// viem の署名検証だけでは high-s の双子や非正準 timestamp を受理し得るため、
// 復元クライアントでも採点集合へ混ざる前に fail closed する。
import {
  isCanonicalSignature, isCanonicalUid, isCanonicalText, isCanonicalTimestamp,
  markActionReceiptSource,
  mergeActionReceiptSources,
  receiptCoverClaim,
  admitReadReceiptsByArrival,
  CHAT_WINDOW_CLOCK_SKEW_MS,
} from '../../vendor/workers/game_workers/lib/protocol-v2.js';
// 🔴 J-17（2026-08-08）: 幽霊メッセージ（`text` 欠落・`null`・不可視文字だけ）の受信ゲート。
//    採点本体の `filterVisibleMessages` と**同一の述語**を正典から import する（写しを作らない）。
import { hasVisibleContent, GUEST_PINNED_RULES } from '../../vendor/workers/game_workers/lib/char-counter.js';

// 受領証明の `_seq` は署名対象ではないローカル到着順メタデータ。
// localStorage 復元後も、保存済みの最大値より大きい番号から採番を再開する。
const maxReceiptArrivalSeq = (receiptMap) => Object.values(receiptMap || {}).reduce(
  (max, receipt) => (Number.isSafeInteger(receipt?._seq) && receipt._seq > max ? receipt._seq : max),
  0,
);

export { readLiveSnapshot, LIVE_SNAPSHOT_POLL_MS, LIVE_SNAPSHOT_MAX_BYTES };

const FINALIZED_RECOVERY_PREFIXES = [
  'p2pRelayReceipts', 'recoveryReceiptArrivals', 'p2pSelfActions',
  'p2pRelayActions', 'p2pOwnSigs', 'clientReadSelection_v1', 'messageArrivals', 'priorityShownSeparators', 'priorityLock_v1',
  'recoveryRpcNodeTrust_v1',
  'myReportGrounds',
];

export function priorRecoveryStorageBlocks(storage, currentBlockNum) {
  const blocks = new Set();
  if (!storage || !Number.isSafeInteger(Number(currentBlockNum))) return [];
  for (let index = 0; index < storage.length; index++) {
    const key = storage.key(index);
    const match = typeof key === 'string' && /^(.*?)_(\d+)_/.exec(key);
    if (!match || !FINALIZED_RECOVERY_PREFIXES.includes(match[1])) continue;
    const block = Number(match[2]);
    if (Number.isSafeInteger(block) && block < Number(currentBlockNum)) blocks.add(block);
  }
  return [...blocks].sort((a, b) => a - b);
}

export function clearFinalizedRecoveryBlockKeys(storage, blockNum) {
  if (!storage || !Number.isSafeInteger(Number(blockNum))) return false;
  const markers = FINALIZED_RECOVERY_PREFIXES.map((prefix) => `${prefix}_${blockNum}_`);
  const keys = [];
  for (let index = 0; index < storage.length; index++) {
    const key = storage.key(index);
    if (typeof key === 'string' && markers.some((marker) => key.startsWith(marker))) keys.push(key);
  }
  for (const key of keys) storage.removeItem(key);
  return true;
}

export class RecoveryRelay {
  // onSelfAction(type, inner): 自分の別クライアント（同一signKey・例: game.js）が P2P に
  //   発行した自己アクションの観測。type='action'（inner.actionType='vote'|'report'）| 'receipt'。
  //   相互ロック（サーバー非依存）の入口。chat は canon へ直接マージするため呼ばれない。
  // onActionsChange(raw): 観測アクション（自分の発信含む）の更新。raw は getRelayActionsRaw 形
  //   （votes: uid→action / uid__extras→[action] / reports: uid→[action]）。
  // onReceiptsChange(list): 観測受領証明（既読バッチ＋action受領）の更新。
  constructor({ signKey, blockNum, groupId, uid, members, onUpdate = null, onSelfAction = null, onSelfFuture = null, onVerifiedAction = null, onActionsChange = null, onReceiptsChange = null, onReconnect = null, onPresence = null, onPersistenceError = null, onRosterKeyInvalid = null, sinceSec = null, getChatWindow = () => null, getChatCloseAtMs = () => null, getChainTimeMs = () => null, getMaxMsgChars = () => GUEST_PINNED_RULES.maxMsgChars, now = () => Date.now(), correction = () => 0 }) {
    this.signKey = signKey;
    this.blockNum = Number(blockNum);
    this.groupId = Number(groupId);
    this.uid = uid;
    this.members = members; // [{uid, addr, bAddr, depIds}]（bAddr は文字列/オブジェクト両対応）
    this.getMaxMsgChars = getMaxMsgChars;
    this.getChatWindow = getChatWindow;
    this.getChatCloseAtMs = getChatCloseAtMs;
    this.getChainTimeMs = getChainTimeMs;
    this.now = now;
    this.getMsgKey = buildMsgKeyGetter(this.blockNum, this.groupId);
    this.onUpdate = onUpdate;
    this.onSelfAction = onSelfAction;
    this.onSelfFuture = onSelfFuture;
    this.onVerifiedAction = onVerifiedAction;
    this.onReconnect = onReconnect;
    this.onPresence = onPresence; // v3.3追補: 在席通知（uid, state, timestamp）
    this.onRosterKeyInvalid = onRosterKeyInvalid;
    this.onActionsChange = onActionsChange;
    this.onReceiptsChange = onReceiptsChange;
    this.onPersistenceError = onPersistenceError || (() => {});
    // created_at 下限（秒）＝チェーン権威 START_TIME（Evidence.START_TIME）。ラン間汚染遮断:
    // reset再ランで前ラン block0 と鍵が一致しても、公開リレー保持の前ランイベントを破棄する。
    // 本体アプリと同じ挙動を、env非依存（process未定義バンドル）でチェーン値により実現する。
    this.sinceSec = sinceSec != null ? Math.floor(Number(sinceSec)) : null;
    this.futureMarks = new FutureAdmissionMarks({ blockNum: this.blockNum,
      groupId: this.groupId, now, correction, onChange: () => {
        this.futureMarkVersion = (this.futureMarkVersion || 0) + 1;
        if (!this._marksRenderTimer) this._marksRenderTimer = setTimeout(() => {
          this._marksRenderTimer = null;
          this.onUpdate?.();
        }, 0);
      } });
    this.futureMarkVersion = 0;
    this.messages = [];        // 正準マージ済み（自発言＋リレー受信）
    this.liveOnlySignatures = new Set(); // WS だけの発言へ P2P 既読を新規発行しない
    this.liveOnlyActionSignatures = new Set();
    this.liveActions = { votes: Object.create(null), reports: Object.create(null) };
    this.liveGeneration = 0;
    this.liveRejections = new LiveSnapshotRejectionMemory();
    this.relayFacts = {};      // uid -> {voted, reportCount}
    this.channel = null;
    this._verifyInner = null;  // verifyInnerSignature（action/receipt 用・start で確定）
    // GameRelayChannel の receipt ストアは正準受領証明だけを保存するため、署名対象外の
    // 到着連番は復元クライアント専用ストアへ分離する。同じ digest の履歴再注入では上書きしない。
    this._receipts = this._loadReceiptArrivals();
    this.liveOnlyReceiptDigests = new Set(Object.values(this._receipts)
      .filter((receipt) => receipt?._liveOnly).map(receiptIdentityDigest));
    this._receiptArrivalSeq = maxReceiptArrivalSeq(this._receipts);
    this._chainClock = { at: 0, timeMs: null, pending: null };
    this._maturityTimer = null;
    this._ownHistoryPrompt = { waitedAt: null, timer: null };
  }

  _receiptArrivalsStoreKey() {
    return `recoveryReceiptArrivals_${this.blockNum}_group${this.groupId}_user${this.uid}`;
  }

  setPriorityReceiptSignatures(signatures = []) {
    this._priorityReceiptSignatures = new Set(signatures);
    if (this._receiptStoreIndex?.setPlanSignatures(this._priorityReceiptSignatures)) {
      this._scheduleReceiptArrivalsSave();
    }
  }

  _loadReceiptArrivals() {
    try {
      const parsed = JSON.parse(localStorage.getItem(this._receiptArrivalsStoreKey()) || '{}');
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
      const cutoffMs = this.sinceSec != null && this.sinceSec > 0 ? this.sinceSec * 1000 : 0;
      return Object.fromEntries(Object.values(parsed).filter((receipt) => (
        receiptIdentityDigest(receipt)
        && Number.isSafeInteger(receipt._seq) && receipt._seq > 0
        && (!cutoffMs || (typeof receipt.timestamp === 'number' && receipt.timestamp >= cutoffMs))
      )).map((receipt) => [receiptIdentityDigest(receipt), receipt]));
    } catch { return {}; }
  }

  _saveReceiptArrivals() {
    // A signed receipt can name 100 nonexistent messages. Keep such entries in
    // memory for later target arrival, but do not let them occupy durable space.
    const knownRefs = new Set(this.messages.map((message) =>
      `${message.uid}|${msgRefOf(this.getMsgKey(message))}`));
    const actions = Object.entries(this._receipts).filter(([, receipt]) => !!receipt?.actionHash);
    const eligibleReads = Object.entries(this._receipts).filter(([, receipt]) =>
      Array.isArray(receipt?.msgRefs) && (this._verifiedStoredReadDigests?.has(receiptIdentityDigest(receipt))
        || receipt.msgRefs.some((ref) => knownRefs.has(`${receipt.senderUid}|${ref}`))));
    const targets = buildRealTargets({}, this.messages, this.blockNum, this.groupId, this.getMsgKey);
    const chatWindow = this.getChatWindow();
    const memberUids = this.members.map((member) => member.uid);
    const admitted = new Set(admitReadReceiptsByArrival(eligibleReads.map(([, receipt]) => receipt), targets, {
      selfUid: this.uid, chatWindow,
      memberUids, atomic: true,
    }).map((receipt) => receipt.signature));
    const targetRevision = JSON.stringify([this.messages.map((message) => [message.uid,
      msgRefOf(this.getMsgKey(message)), message.timestamp]), chatWindow?.startMs, chatWindow?.endMs]);
    if (!this._receiptStoreIndex || this._receiptStoreTargetsRevision !== targetRevision) {
      this._receiptStoreClaimKeys = new Map();
      this._receiptStoreIndex = new CarriedReceiptStoreIndex(this.uid, receiptCanonCmp,
        (receipt) => this._receiptStoreClaimKeys.get(receipt.signature) || []);
      this._receiptStoreTargetsRevision = targetRevision;
    }
    const reads = eligibleReads.filter(([, receipt]) => {
      const restored = this._verifiedStoredReadDigests?.has(receiptIdentityDigest(receipt));
      if (!restored && !admitted.has(receipt.signature)) return false;
      const claim = receiptCoverClaim(receipt, targets, {
        selfUid: this.uid, chatWindow, atomic: true, memberUids,
      });
      // A previously verified durable receipt must survive while its target
      // message is being fetched again. It grants no cover until that target
      // exists; the singleton only gives the W3 disk side an index owner.
      const facts = claim.keys.length ? claim.keys : (restored ? [`stored|${receipt.signature}`] : []);
      if (!facts.length) return false;
      this._receiptStoreClaimKeys.set(receipt.signature, facts);
      return true;
    });
    this._receiptStoreIndex.setPlanSignatures(this._priorityReceiptSignatures || []);
    this._receiptStoreIndex.syncDisk(Object.fromEntries([...actions, ...reads]
      .map(([, receipt]) => [receipt.signature, receipt])));
    const carried = this._receiptStoreIndex.selectedReceipts();
    const selectedEntries = [...actions, ...reads].filter(([, receipt]) => carried[receipt.signature]);
    const ownReads = selectedEntries.filter(([, receipt]) => receipt.receiverUid === this.uid && Array.isArray(receipt.msgRefs));
    const actionEntries = selectedEntries.filter(([, receipt]) => !Array.isArray(receipt.msgRefs));
    const ownCover = selectedEntries.filter(([, receipt]) => receipt.receiverUid !== this.uid
      && Array.isArray(receipt.msgRefs) && receipt.senderUid === this.uid);
    const remaining = selectedEntries.filter(([, receipt]) => receipt.receiverUid !== this.uid
      && Array.isArray(receipt.msgRefs) && receipt.senderUid !== this.uid);
    const baselineEntries = [...actions, ...eligibleReads];
    const baselineSize = 2 + baselineEntries.reduce((sum, [digest, receipt]) =>
      sum + JSON.stringify(digest).length + JSON.stringify(receipt).length + 2, 0);
    const orderedEntries = baselineEntries.length === selectedEntries.length
      && baselineEntries.every(([, receipt]) => carried[receipt.signature])
      && baselineSize <= 3 * 1024 * 1024
      ? baselineEntries : [...ownReads, ...actionEntries, ...ownCover, ...remaining];
    const selected = {};
    let size = 2;
    for (const [digest, receipt] of orderedEntries) {
      const entrySize = JSON.stringify(digest).length + JSON.stringify(receipt).length + 2;
      if (size + entrySize > 3 * 1024 * 1024) continue;
      selected[digest] = receipt;
      size += entrySize;
    }
    try { localStorage.setItem(this._receiptArrivalsStoreKey(), JSON.stringify(selected)); }
    catch (error) {
      const actionOnly = Object.fromEntries(actions.filter(([digest]) => selected[digest]));
      try {
        localStorage.removeItem(`p2pRelayReceipts_${this.blockNum}_group${this.groupId}_user${this.uid}`);
        localStorage.setItem(this._receiptArrivalsStoreKey(), JSON.stringify(actionOnly));
        return;
      } catch { /* keep the original storage error for the UI */ }
      try { this.onPersistenceError({ key: this._receiptArrivalsStoreKey(), error }); } catch { /* UI failure */ }
    }
  }

  _scheduleReceiptArrivalsSave() {
    if (this._receiptArrivalsTimer) return;
    this._receiptArrivalsTimer = setTimeout(() => {
      this._receiptArrivalsTimer = null;
      this._saveReceiptArrivals();
    }, 50);
    if (typeof this._receiptArrivalsTimer?.unref === 'function') this._receiptArrivalsTimer.unref();
  }

  _persistReceiptsForMessage(message) {
    const ref = msgRefOf(this.getMsgKey(message));
    if (Object.values(this._receipts).some((receipt) => receipt?.senderUid === message.uid
        && receipt.msgRefs?.includes(ref))) this._scheduleReceiptArrivalsSave();
  }

  async verifyStoredReceipts() {
    const verify = makeVerifyRelayInner(() => this.members, this.blockNum, this.groupId);
    const valid = {};
    this._verifiedStoredReadDigests = new Set();
    const counts = new Map();
    let truncated = false;
    for (const receipt of Object.values(this._receipts)) {
      const issuer = receipt?.receiverUid;
      if (!this.members.some((member) => member.uid === issuer)) continue;
      const count = (counts.get(issuer) || 0) + 1;
      counts.set(issuer, count);
      if (count > MAX_RECEIPTS_PER_ISSUER) { truncated = true; continue; }
      if (!(await verify('receipt', receipt))) continue;
      const digest = receiptIdentityDigest(receipt);
      valid[digest] = markActionReceiptSource(receipt, { source: 'storage' });
      if (Array.isArray(receipt.msgRefs)) this._verifiedStoredReadDigests.add(digest);
    }
    this._receipts = valid;
    this._receiptArrivalsTruncated = truncated;
    this.liveOnlyReceiptDigests = new Set(Object.values(valid)
      .filter((receipt) => receipt._liveOnly).map(receiptIdentityDigest));
    this._saveReceiptArrivals();
    this.restartMaturityTimer();
  }

  // 検証済み受領証明の唯一の取り込み口。外部入力が自称 `_seq` を含んでも、初回取り込み時の
  // ローカル連番で必ず上書きする。receipt history／リレー再配信の同一 digest は先着値を維持する。
  async _ingestReceiptArrivals(list, { fromLive = false, fromStorage = false,
    fromChannelStorage = false, arrivalAtOverride = null, deviceArrivalMsOverride = null } = {}) {
    const arrivalAt = Number.isSafeInteger(arrivalAtOverride) ? arrivalAtOverride : Date.now();
    const deviceArrivalMs = Number.isSafeInteger(deviceArrivalMsOverride)
      ? deviceArrivalMsOverride : this.now(arrivalAt);
    const incoming = Array.isArray(list) ? list : [list];
    const ready = [];
    for (const rawReceipt of incoming) {
      const { _firstArrivalAt: _untrustedArrival, ...receipt } = rawReceipt || {};
      const restoredOwn = (fromStorage || fromChannelStorage) && receipt.receiverUid === this.uid;
      if (this._receipts[receiptIdentityDigest(receipt)]) { ready.push(receipt); continue; }
      if (!restoredOwn && this.futureMarks.has('receipt', receipt)) continue;
      if (restoredOwn || isClientTimestampAllowed(receipt?.timestamp, this.now())) {
        ready.push(receipt);
        continue;
      }
      if (!(await (this._verifyInner || makeVerifyRelayInner(() => this.members, this.blockNum, this.groupId))
        ('receipt', receipt))) continue;
      if (isClientTimestampAllowed(receipt.timestamp, this.now())) {
        ready.push(receipt);
        continue;
      }
      if (receipt.receiverUid === this.uid) this.onSelfFuture?.(receipt, receipt.receiverUid);
      this.futureMarks.discard('receipt', receipt);
    }
    if (!ready.length) return;
    // A slow chain read for action provenance must not hold read receipts in
    // the same relay history batch behind it.
    if (!fromStorage && ready.some((receipt) => receipt?.actionHash)
        && ready.some((receipt) => Array.isArray(receipt?.msgRefs))) {
      await this._ingestReceiptArrivals(ready.filter((receipt) => Array.isArray(receipt?.msgRefs)),
        { fromLive, fromStorage, fromChannelStorage, arrivalAtOverride: arrivalAt,
          deviceArrivalMsOverride: deviceArrivalMs });
      return this._ingestReceiptArrivals(ready.filter((receipt) => !Array.isArray(receipt?.msgRefs)),
        { fromLive, fromStorage, fromChannelStorage, arrivalAtOverride: arrivalAt,
          deviceArrivalMsOverride: deviceArrivalMs });
    }
    const countsBefore = new Map();
    for (const value of Object.values(this._receipts)) {
      countsBefore.set(value.receiverUid, (countsBefore.get(value.receiverUid) || 0) + 1);
    }
    const needsClock = !fromStorage && ready.some((receipt) => {
      if (!receipt?.actionHash) return false;
      const digest = receiptIdentityDigest(receipt);
      if (!digest) return false;
      const known = this._receipts[digest];
      if (known) return !Number.isSafeInteger(known._chainSeenAt)
        && !Number.isSafeInteger(known._deviceSeenAt);
      return this.members.some((member) => member.uid === receipt.receiverUid)
        && (countsBefore.get(receipt.receiverUid) || 0) < MAX_RECEIPTS_PER_ISSUER;
    });
    const chainReadMs = needsClock ? await readReceiptChainTime(this._chainClock,
      () => this.getChainTimeMs(), arrivalAt) : null;
    const chainTimeMs = Number.isSafeInteger(chainReadMs) && Number.isSafeInteger(deviceArrivalMs)
      ? Math.max(chainReadMs, deviceArrivalMs - CHAT_WINDOW_CLOCK_SKEW_MS) : chainReadMs;
    const preceding = this._receiptIngestTail || Promise.resolve();
    let release;
    this._receiptIngestTail = new Promise((resolve) => { release = resolve; });
    await preceding;
    try {
    let changed = false;
    const counts = new Map();
    for (const value of Object.values(this._receipts)) {
      counts.set(value.receiverUid, (counts.get(value.receiverUid) || 0) + 1);
    }
    for (const receipt of ready) {
      const digest = receiptIdentityDigest(receipt);
      if (!digest) continue;
      const marked = markActionReceiptSource(receipt, {
        source: fromStorage && !fromChannelStorage ? 'storage' : 'device',
        chatCloseAt: this.getChatCloseAtMs(),
        chainTimeMs, nowMs: deviceArrivalMs,
      });
      if (this._receipts[digest]) {
        const old = this._receipts[digest];
        if (marked?.actionHash) {
          const merged = mergeActionReceiptSources(old, marked);
          if (JSON.stringify(merged) !== JSON.stringify(old)) {
            this._receipts[digest] = merged;
            changed = true;
          }
        }
        if (!fromLive && this.liveOnlyReceiptDigests.delete(digest)) {
          delete this._receipts[digest]._liveOnly;
          changed = true;
        }
        continue;
      }
      const issuer = receipt?.receiverUid;
      if (!this.members.some((member) => member.uid === issuer)
          || (counts.get(issuer) || 0) >= MAX_RECEIPTS_PER_ISSUER) continue;
      counts.set(issuer, (counts.get(issuer) || 0) + 1);
      const nextSeq = Math.max(
        this._receiptArrivalSeq,
        maxReceiptArrivalSeq(this._receipts),
      ) + 1;
      this._receiptArrivalSeq = nextSeq;
      this._receipts[digest] = { ...marked, _seq: nextSeq,
        ...(fromLive ? { _liveOnly: true } : {}) };
      if (fromLive) this.liveOnlyReceiptDigests.add(digest);
      changed = true;
    }
    if (changed) this._scheduleReceiptArrivalsSave();
    if (this.onReceiptsChange) this.onReceiptsChange(Object.values(this._receipts));
    } finally { release(); }
  }

  // 自分の別クライアント発行の自己アクション観測（相互ロック用）。認証は Schnorr と名簿照合で
  // 保証済みだが、signKey署名も明示検証（「署名が検証できれば正当」原則）。
  async _handleSelfAction(type, inner) {
    try {
      if (type === 'chat') {
        const msg = { uid: inner.uid, text: inner.text, timestamp: inner.timestamp, signature: inner.signature };
        await this._ingestChat(msg); // 別クライアントの自己発言を canon へ
        return;
      }
      if (type !== 'action' && type !== 'receipt') return;
      if (this._verifyInner && !(await this._verifyInner(type, inner))) return;
      if (!isClientTimestampAllowed(inner.timestamp, this.now())) {
        this.onSelfFuture?.(inner, inner.receiverUid || inner.uid);
        return;
      }
      if (type === 'receipt') await this._ingestReceiptArrivals([inner]);
      if (!this.onSelfAction) return;
      this.onSelfAction(type, type === 'receipt' ? this._receipts[receiptIdentityDigest(inner)] : inner);
    } catch (e) { /* 観測失敗は無視（従来の自己エコー破棄と等価） */ }
  }

  // 受信チャットの検証（MIRROR相当: useGameWebSocket.js verifyIncomingMessage の v2 経路）
  async _verifyChat(msg) {
    if (msg.uid == null || !msg.signature) return false;
    if (this.futureMarks.has('chat', msg)) return false;
    if (!isCanonicalSignature(msg.signature)) return false;
    if (!isCanonicalUid(msg.uid)) return false;
    if (!isCanonicalText(msg.text ?? '') || !isClientChatWithinLimit(msg.text, this.getMaxMsgChars())) return false;
    // 🔴 J-17（2026-08-08・ユーザー確定）: 可視内容ゼロ（`text` 欠落・`null`・不可視文字だけ）は
    //    ここで弾く。採点の正典集合からは `filterVisibleMessages` が落とすので点数は動かないが、
    //    取り込むと画面に出て**自分の提出バンドルにも載り**、chatHash の原像にだけ入る
    //    「幽霊」になる。復元クライアントは Nostr 直受けなので、まさにこの経路の入口。
    if (!hasVisibleContent(msg.text)) return false;
    if (!isCanonicalTimestamp(msg.timestamp)) return false;
    const member = this.members.find((m) => m.uid === msg.uid);
    if (!member || !member.bAddr) return false;
    const bAddr = typeof member.bAddr === 'string' ? JSON.parse(member.bAddr) : member.bAddr;
    const dataString = chatSignStringV2(this.blockNum, this.groupId, msg.uid, msg.text, msg.timestamp);
    try {
      if (!await verifyMessage({ address: bAddr.address, message: dataString, signature: msg.signature })) return false;
      if (msg.uid === this.uid && !isClientTimestampAllowed(msg.timestamp, this.now())) {
        this.onSelfFuture?.(msg, msg.uid);
      }
      return !this.futureMarks.discard('chat', msg);
    }
    catch { return false; }
  }

  async _ingestChat(msg, { fromLive = false } = {}) {
    if (this.sinceSec != null && msg?.timestamp < this.sinceSec * 1000) return false;
    if (this.messages.some((known) => known.uid === msg.uid && known.text === msg.text
        && known.timestamp === msg.timestamp && known.signature === msg.signature)) {
      if (!fromLive && this.liveOnlySignatures.delete(msg.signature)) this.onUpdate?.();
      return true;
    }
    if (this.futureMarks.has('chat', msg)) return false;
    if (!(await this._verifyChat(msg))) return false;
    if (fromLive) this._mergeLiveMessage(msg);
    else this._mergeMessage(msg);
    return true;
  }

  _mergeLiveMessage(msg) {
    if (!this.messages.some((existing) => existing.signature === msg.signature)) {
      this.liveOnlySignatures.add(msg.signature);
    }
    this.messages = dedupAndSortV2([...this.messages, msg], this.blockNum, this.groupId, this.getMsgKey);
    this._persistReceiptsForMessage(msg);
    if (this.onUpdate) this.onUpdate();
  }

  _mergeMessage(msg) {
    this.liveOnlySignatures.delete(msg.signature);
    this.messages = dedupAndSortV2([...this.messages, msg], this.blockNum, this.groupId, this.getMsgKey);
    this._persistReceiptsForMessage(msg);
    if (this.onUpdate) this.onUpdate();
  }

  // 無認証公開 JSON の各項目を、リレー内側と同じ名簿鍵・正準形・未来時刻の関門で検査する。
  // 予算は発信者ごと。悪意ある1人が他人の枠を食わない。署名済み項目も再発信しない。
  async ingestLiveSnapshot(snapshot) {
    if (!snapshot || snapshot.blockNum !== this.blockNum || snapshot.groupId !== this.groupId) return;
    const receiptArrivalAt = Date.now();
    const receiptDeviceArrivalMs = this.now(receiptArrivalAt);
    const verify = this._verifyInner || makeVerifyRelayInner(() => this.members, this.blockNum, this.groupId);
    const knownReceiptDigests = new Set(Object.values(this._receipts)
      .map(receiptIdentityDigest).filter(Boolean));
    const { messages: arrivals, actions, receipts } = await verifyLiveSnapshotEntries(snapshot, {
      blockNum: this.blockNum, groupId: this.groupId, members: this.members,
      maxMsgChars: this.getMaxMsgChars(),
      verifyChat: async (message) => {
        if (this.messages.some((known) => known.uid === message.uid && known.text === message.text
            && known.timestamp === message.timestamp && known.signature === message.signature)) return true;
        if (this.futureMarks.has('chat', message) || !(await this._verifyChat(message))) return false;
        return !this.futureMarks.discard('chat', message);
      }, verifyInner: verify,
      knownReceiptDigests,
      rejectionMemory: this.liveRejections,
    });
    if (arrivals.length) {
      const known = new Set(this.messages.map((m) => m.signature));
      for (const msg of arrivals) if (!known.has(msg.signature)) this.liveOnlySignatures.add(msg.signature);
      this.messages = dedupAndSortV2([...this.messages, ...arrivals], this.blockNum, this.groupId, this.getMsgKey);
    }
    let actionsChanged = false;
    for (const inner of actions) {
      if (inner.uid !== this.uid && inner.actionType === 'report') this.onVerifiedAction?.(inner);
      const prior = inner.actionType === 'vote' ? this.liveActions.votes[inner.uid] : this.liveActions.reports[inner.uid];
      if (prior?.some((known) => known.signature === inner.signature && known.timestamp === inner.timestamp
          && known.encrypted === inner.encrypted)) continue;
      if (this.futureMarks.has('action', inner)) continue;
      if (!isClientTimestampAllowed(inner.timestamp, this.now())) {
        if (inner.uid === this.uid) this.onSelfFuture?.(inner, inner.uid);
        this.futureMarks.discard('action', inner);
        continue;
      }
      const kind = inner.actionType;
      const uid = inner.uid;
      const list = kind === 'vote' ? (this.liveActions.votes[uid] ||= []) : (this.liveActions.reports[uid] ||= []);
      if (list.some((a) => a.signature === inner.signature)) continue;
      if (list.length >= MAX_OBSERVED_ACTIONS_PER_ACTOR) continue;
      list.push({ encrypted: inner.encrypted, timestamp: inner.timestamp, signature: inner.signature });
      const relaySlot = this.channel?.relayActions?.[uid];
      const relayKnown = kind === 'vote'
        ? [relaySlot?.vote, ...(Array.isArray(relaySlot?.voteExtras) ? relaySlot.voteExtras : [])]
        : (Array.isArray(relaySlot?.reports) ? relaySlot.reports : []);
      if (!relayKnown.some((known) => known?.signature === inner.signature
          && known.timestamp === inner.timestamp && known.encrypted === inner.encrypted)) {
        this.liveOnlyActionSignatures.add(inner.signature);
      }
      actionsChanged = true;
    }
    if (receipts.length) await this._ingestReceiptArrivals(receipts,
      { fromLive: true, arrivalAtOverride: receiptArrivalAt,
        deviceArrivalMsOverride: receiptDeviceArrivalMs });
    if (actionsChanged && this.onActionsChange) this.onActionsChange(this.getRelayActionsRaw(), { fromSnapshot: true });
    if (arrivals.length && this.onUpdate) this.onUpdate();
  }

  clearLiveSnapshot() {
    this.liveGeneration += 1;
    if (this.liveOnlySignatures.size) {
      this.messages = this.messages.filter((msg) => !this.liveOnlySignatures.has(msg.signature));
      this.liveOnlySignatures.clear();
    }
    this.liveActions = { votes: Object.create(null), reports: Object.create(null) };
    this.liveOnlyActionSignatures.clear();
    if (this.liveOnlyReceiptDigests.size) {
      for (const digest of this.liveOnlyReceiptDigests) delete this._receipts[digest];
      this.liveOnlyReceiptDigests.clear();
      this._saveReceiptArrivals();
    }
    if (this.onUpdate) this.onUpdate();
  }

  // ローカルで作成した自分のメッセージを正準集合へ入れる（ACK非依存・§5.5）
  addOwnMessage(signedMsg) {
    this._mergeMessage({ uid: signedMsg.uid, text: signedMsg.text, timestamp: signedMsg.timestamp, signature: signedMsg.signature });
  }

  async start() {
    if (typeof WebSocket === 'undefined') throw new Error('RecoveryRelay.start() requires a browser (WebSocket)');
    const verifyInnerSignature = makeVerifyRelayInner(() => this.members, this.blockNum, this.groupId);
    const verifyAndObserve = async (type, inner) => {
      const valid = await verifyInnerSignature(type, inner);
      if (valid && type === 'action' && inner?.uid !== this.uid && inner?.actionType === 'report') {
        this.onVerifiedAction?.(inner);
      }
      return valid;
    };
    this._verifyInner = verifyAndObserve;

    this.channel = new GameRelayChannel({
      signKey: this.signKey,
      blockNum: this.blockNum,
      groupId: this.groupId,
      uid: this.uid,
      members: this.members,
      verifyInnerSignature: verifyAndObserve,
      getMaxMsgChars: this.getMaxMsgChars,
      getChatWindow: this.getChatWindow,
      now: this.now,
      futureMarks: this.futureMarks,
      isAccepted: (type, inner) => {
        if (type === 'chat') {
          const known = this.messages.some((message) => message.uid === inner.uid
            && message.text === inner.text && message.timestamp === inner.timestamp
            && message.signature === inner.signature);
          if (known && this.liveOnlySignatures.delete(inner.signature)) this.onUpdate?.();
          return known;
        }
        if (type === 'receipt') return !!this._receipts[receiptIdentityDigest(inner)];
        if (type !== 'action') return false;
        const slot = this.channel?.relayActions?.[inner.uid];
        const prior = inner.actionType === 'vote' ? [slot?.vote, ...(slot?.voteExtras || [])] : (slot?.reports || []);
        return prior.some((known) => known?.signature === inner.signature
          && known.timestamp === inner.timestamp && known.encrypted === inner.encrypted);
      },
      sinceSec: this.sinceSec,
      onChat: async (inner) => {
        const msg = { uid: inner.uid, text: inner.text, timestamp: inner.timestamp, signature: inner.signature };
        await this._ingestChat(msg);
      },
      // 観測アクション（自分の発信含む・チャネルが署名検証済み）→ アプリの observed へ
      onActionsChange: (raw) => {
        for (const value of Object.values(raw?.votes || {})) {
          for (const action of (Array.isArray(value) ? value : [value])) this.liveOnlyActionSignatures.delete(action?.signature);
        }
        for (const value of Object.values(raw?.reports || {})) {
          for (const action of (Array.isArray(value) ? value : [value])) this.liveOnlyActionSignatures.delete(action?.signature);
        }
        if (this.onActionsChange) this.onActionsChange(this.getRelayActionsRaw());
        if (this.onUpdate) this.onUpdate();
      },
      // 観測受領証明（チャネルが署名検証済み。自発行分は publishReceipt で集約済み）→ アプリへ
      onReceiptsChange: async (list, { verified = false } = {}) => {
        if (verified) {
          // 新着は GameRelayChannel が内側署名を検証済み。
          await this._ingestReceiptArrivals(list);
          if (this.onUpdate) this.onUpdate();
          return;
        }
        // GameRelayChannel が localStorage から復元した集合は未検証。
        void (async () => {
          const checked = [];
          for (const receipt of list) if (await verifyInnerSignature('receipt', receipt)) checked.push(receipt);
          if (checked.length) await this._ingestReceiptArrivals(checked, { fromChannelStorage: true });
          if (this.onUpdate) this.onUpdate();
        })();
      },
      onFactsChange: (facts) => { this.relayFacts = facts; if (this.onUpdate) this.onUpdate(); },
      onFlood: () => { /* §9.4c: 氾濫検知アラート（UI 側で表示） */ },
      onRosterKeyInvalid: (invalidUid) => {
        console.warn(`P2P unavailable for ${invalidUid}: invalid roster Nostr pubkey`);
        if (this.onRosterKeyInvalid) this.onRosterKeyInvalid(invalidUid);
      },
      onSelfAction: (type, inner) => this._handleSelfAction(type, inner),
      // v3.3追補: 他メンバーの在席通知（active/away・署名検証済み）→ アプリへ
      onPresence: (peerUid, pState, ts) => { if (this.onPresence) this.onPresence(peerUid, pState, ts); if (this.onUpdate) this.onUpdate(); },
      onPersistenceError: this.onPersistenceError,
      onHistoryProgress: (status) => this._noteOwnHistoryProgress(status),
    });
    this.channel.start();
    // RelayPool の各 socket の実際の開閉を観測する。最後の1本の切断から測る。
    const pool = this.channel.pool;
    if (pool && this.onReconnect) {
      const tracked = new WeakSet();
      let connection = null;
      const trackSocket = (socket) => {
        if (!socket || tracked.has(socket)) return;
        tracked.add(socket);
        socket.addEventListener('open', () => {
          if (pool.closed) return;
          connection = readReceiptConnectionChange(connection, true, Date.now());
          if (connection.reopen) this.onReconnect();
        });
        socket.addEventListener('close', () => {
          if (!pool.closed) connection = readReceiptConnectionChange(connection,
            [...pool.sockets.values()].some((other) => other.readyState === WebSocket.OPEN), Date.now());
        });
      };
      for (const socket of pool.sockets.values()) trackSocket(socket);
      const connectOne = pool._connectOne.bind(pool);
      pool._connectOne = (url) => {
        connectOne(url);
        trackSocket(pool.sockets.get(url));
      };
    }
    // GameRelayChannel restores its cache inside its constructor, before
    // `this.channel` receives the new instance. Publish that restored union
    // once more after assignment so the app can recover its own actions.
    if (this.onActionsChange) this.onActionsChange(this.getRelayActionsRaw());
    if (this.onUpdate) this.onUpdate();
  }

  // The channel's local action cache is delivered without verification.
  // Recheck its report signatures against the confirmed roster after start().
  async verifyRestoredReports() {
    const verify = makeVerifyRelayInner(() => this.members, this.blockNum, this.groupId);
    const cutoff = this.sinceSec != null ? this.sinceSec * 1000 : 0;
    for (const [actorUid, slot] of Object.entries(this.channel?.relayActions || {})) {
      if (actorUid === this.uid) continue;
      for (const report of slot?.reports || []) {
        const inner = { actionType: 'report', uid: actorUid, ...report };
        if (Number.isSafeInteger(inner.timestamp) && inner.timestamp >= cutoff
            && await verify('action', inner)) this.onVerifiedAction?.(inner);
      }
    }
  }

  // 発行系（GameRelayChannel に委譲。自分の canon にも即時反映）
  canPublish() { return !!(this.channel?.pool && !this.channel.p2pUnavailable); }
  async publishChat(signedMsg) {
    if (!this.canPublish()) return false;
    await this.channel.publishChat(signedMsg);
    this.addOwnMessage(signedMsg);
    return true;
  }
  // 投票/密告の発信（signKey署名済み {encrypted, signature, timestamp}）。チャネルが自分の
  // 発信も relayActions へ集約する（提出物の自己マージ・別クライアント復元用）。
  async publishAction(actionType, action) {
    if (!this.canPublish()) return false;
    await this.channel.publishAction(actionType, action);
    return true;
  }
  // 受領証明の発行（既読msgKeyバッチ / action受領）。チャネルが自発行分も relayReceipts へ集約。
  async publishReceipt(receipt) {
    if (!this.canPublish()) return false;
    await this.channel.publishReceipt(receipt);
    return true;
  }
  // v3.3追補: 自分の在席状態（active/away）を署名付きで配る
  async publishPresence(presence) {
    if (!this.canPublish()) return false;
    await this.channel.publishPresence(presence);
    return true;
  }

  getMessages() { return this.messages; }
  // 観測アクション（votes: uid→action / uid__extras→[action] / reports: uid→[action]）
  getRelayActionsRaw() {
    const relay = this.channel?.getRelayActionsRaw?.() || { votes: {}, reports: {} };
    const votes = Object.assign(Object.create(null), relay.votes);
    const reports = Object.assign(Object.create(null), relay.reports);
    for (const member of this.members) {
      const uid = member.uid;
      const liveVotes = this.liveActions.votes[uid] || [];
      const allVotes = [votes[uid], ...(votes[`${uid}__extras`] || []), ...liveVotes].filter(Boolean);
      const uniqueVotes = [...new Map(allVotes.map((a) => [a.signature, a])).values()].slice(0, MAX_OBSERVED_ACTIONS_PER_ACTOR);
      if (uniqueVotes.length) votes[uid] = uniqueVotes[0];
      if (uniqueVotes.length > 1) votes[`${uid}__extras`] = uniqueVotes.slice(1);
      const allReports = [...(reports[uid] || []), ...(this.liveActions.reports[uid] || [])];
      const uniqueReports = [...new Map(allReports.map((a) => [a.signature, a])).values()].slice(0, MAX_OBSERVED_ACTIONS_PER_ACTOR);
      if (uniqueReports.length) reports[uid] = uniqueReports;
    }
    return { votes, reports };
  }
  isLiveOnlyMessage(msg) { return this.liveOnlySignatures.has(msg?.signature); }
  isLiveOnlyAction(action) { return this.liveOnlyActionSignatures.has(action?.signature); }
  // 観測受領証明の一覧（提出物 observed.receipts の材料）
  getReceipts() { return Object.values(this._receipts); }

  // P2P診断: 名簿にある有効な公開鍵数とリレー接続数を返す。
  getP2PDebug() {
    const ch = this.channel;
    if (!ch) return { relays: '0/0', pubkeys: 0, msgs: this.messages.length };
    const st = ch.getRelayStatus?.() || [];
    return {
      relays: `${st.filter(r => r.status === 'connected').length}/${st.length}`,
      pubkeys: ch.validNostrByUid.size,
      msgs: this.messages.length,
    };
  }

  _noteOwnHistoryProgress(status) {
    // WR-UI-S3-OWNHIST: 復元には W がないので、読み終わったリレーだけを数える。
    const historySufficient = ownHistoryComplete(status) || (status?.unavailable !== true
      && Number.isSafeInteger(status?.done) && status.done >= 2 && Array.isArray(status.waiting));
    if (!this.ownHistoryReady && historySufficient) {
      this.ownHistoryReady = true;
      this._clearOwnHistoryPrompt();
    } else if (!this.ownHistoryReady) this._armOwnHistoryPrompt();
    this.onUpdate?.();
  }

  ownHistoryPrompt(now = Date.now()) {
    if (this.ownHistoryReady || !this.channel) return null;
    const status = this.channel.historyStatus();
    const historySufficient = ownHistoryComplete(status) || (status?.unavailable !== true
      && Number.isSafeInteger(status?.done) && status.done >= 2 && Array.isArray(status.waiting));
    if (!status || status.unavailable === true || historySufficient) return null;
    const dueAt = ownHistoryPromptDueAt(status, this._ownHistoryPrompt.waitedAt);
    if (dueAt === null || dueAt > now) return null;
    return { kind: ownHistoryPromptKind(status), relays: [...status.waiting] };
  }

  _clearOwnHistoryPrompt() {
    if (this._ownHistoryPrompt.timer !== null) clearTimeout(this._ownHistoryPrompt.timer);
    this._ownHistoryPrompt.timer = null;
  }

  _armOwnHistoryPrompt() {
    this._clearOwnHistoryPrompt();
    if (this.ownHistoryReady || !this.channel) return;
    const status = this.channel.historyStatus();
    const historySufficient = ownHistoryComplete(status) || (status?.unavailable !== true
      && Number.isSafeInteger(status?.done) && status.done >= 2 && Array.isArray(status.waiting));
    if (!status || status.unavailable === true || historySufficient) return;
    const dueAt = ownHistoryPromptDueAt(status, this._ownHistoryPrompt.waitedAt);
    if (dueAt === null) return;
    const delay = dueAt - Date.now();
    if (delay <= 0) return;
    const timer = setTimeout(() => { this._ownHistoryPrompt.timer = null; this.onUpdate?.(); }, delay);
    if (timer && typeof timer.unref === 'function') timer.unref();
    this._ownHistoryPrompt.timer = timer;
  }

  waitOwnHistory() {
    if (!this.ownHistoryPrompt()) return false;
    this._ownHistoryPrompt.waitedAt = Date.now();
    this._armOwnHistoryPrompt();
    this.onUpdate?.();
    return true;
  }

  startWithoutOwnHistory() {
    if (!this.ownHistoryPrompt()) return false;
    this.ownHistoryReady = true;
    this._clearOwnHistoryPrompt();
    this.onUpdate?.();
    return true;
  }

  stop() {
    this._clearOwnHistoryPrompt();
    if (this._maturityTimer) { clearInterval(this._maturityTimer); this._maturityTimer = null; }
    if (this._marksRenderTimer) { clearTimeout(this._marksRenderTimer); this._marksRenderTimer = null; }
    if (this._receiptArrivalsTimer) {
      clearTimeout(this._receiptArrivalsTimer);
      this._receiptArrivalsTimer = null;
      this._saveReceiptArrivals();
    }
    this.channel?.stop?.();
  }

  refetchHistory(change) {
    if (!change || change.deltaMs <= 0) return;
    const released = this.futureMarks.releaseEligible(change.nextMs);
    if (released.released) this.channel?.refetchHistory(released.eventIds);
  }

  // 成熟の見回り（S3R4-U-MATURE18・S3R4-U-M18-SWEEP）: 保存済み受領証明の検証後に1本だけ起こし、60秒ごとにその時の C で判定する。
  refetchMatured() {
    if (this.futureMarks.nextMaturityAt() > this.now()) return;
    const endMs = this.getChatWindow()?.endMs;
    const released = this.futureMarks.releaseMatured(this.now(), Number.isFinite(endMs) ? endMs : Infinity);
    if (released.inWindow) this.channel?.refetchMarkedIds(released.eventIds);
  }
  restartMaturityTimer() {
    if (this._maturityTimer) clearInterval(this._maturityTimer);
    this._maturityTimer = null;
    this._maturityTimer = setInterval(() => this.refetchMatured(), 60000);
    if (typeof this._maturityTimer?.unref === 'function') this._maturityTimer.unref();
  }
}

// リレー設定（ユーザー追加＝§9.9 の唯一の脱出路。正典 saveRelayList/getRelayList を委譲）
export { saveRelayList, getRelayList };

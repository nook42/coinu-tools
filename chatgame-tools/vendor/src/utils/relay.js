// src/utils/relay.js
// P2P冗長チャネル — Nostr二層リレー層（docs/P2P_REDUNDANT_CHANNEL_PLAN.md §3/§4/§6）
//
// 外側 = Nostrイベント封筒（NIP-01・BIP-340 Schnorr）: リレーに受理させるためだけのもの。
// 内側 = signKey署名済みペイロード（§2.6正準形）: 採点・検証はこれだけを見る。
// リレーは伝送路であって証拠源ではない（原則1）。リレー全滅時は現行WSのみの動作に一致（原則5）。
//
// 鍵導出（§3.1・v2）: Nostr鍵はsignKeyからHKDFドメイン分離導出。
// signKeyは永遠に非公開（提出物に含まれない）ため、ゲーム終了後のリレー上のなりすましも
// 構造的に不可能。端末喪失時もウォレット→signKey→Nostr鍵を再導出できる（§6完全復元の前提）。
// 導出式は §6 が依存するためバイト正確に固定。

import { keccak256, toBytes } from 'viem';
import { sha256 } from '@noble/hashes/sha256';
import { schnorr } from '@noble/curves/secp256k1';
import {
  isMsgRef, isActionHash, compareHexAsc, computeMsgKeyV2, msgRefOf,
  MAX_OBSERVED_ACTIONS_PER_ACTOR, receiptMaxRefsPerReceipt,
  RECEIPT_FRESH_WINDOW_MS, CHAT_WINDOW_CLOCK_SKEW_MS
} from './protocol.js';
// 🔴 P-2026-0837（2026-08-08・ラウンド19 判断不要-5）: `bAddr` の門番は採点本体と同じ
//    `parseBlockAddress` を使う（生の `JSON.parse` をやめる）。`src/utils/protocol.js` の
//    バレルはこの述語を再エクスポートしていないので、正典（protocol-v2.js）から直接取る
//    （`src/hooks/useGameWebSocket.js:23` と同じ流儀）。
import { isCanonicalTimestamp, isCanonicalSignature, receiptArrivalContainment, mergeActionReceiptSources, receiptCoverClaim, buildRealTargets } from '../../workers/game_workers/lib/protocol-v2.js';
import { GUEST_PINNED_RULES, countHalfWidthChars } from '../../workers/game_workers/lib/char-counter.js';
import { deriveNostrKey, isValidNostrPubkey } from './p2pKeys.js';
export { deriveNostrKey } from './p2pKeys.js';

// ============================================================
// 定数（§11 実装で確定・P2P_IMPL_DECISIONS.md 参照）
// ============================================================

// Nostr kind: 通常（regular・リレーが保存する）レンジ [1000, 10000) の未割当番号。
// 全イベント種別を同一kindで発行（メタデータ最小化・§3.2）
export const P2P_EVENT_KIND = 7742;

// デフォルトリレー（§3.3 curation: 地理・運営主体分散。ユーザーが設定で置換可能）。
// ⚠️ 分散性はNostrプロトコルの保証ではなくリレー選択の問題。per-pubkeyレート制限のある
// リレーを優先（§9.4b）。本番前に要ユーザーレビュー（P2P_IMPL_DECISIONS.md）。
export const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.nostr.band',
  'wss://offchain.pub',
  'wss://relay.primal.net',
];

// 沈静化窓（R3・§2.5）: チャット窓終端後、提出ビュー凍結前にリレー伝播を待つ時間。
// 終了間際の発言・投票・密告がリレー経由で全員に行き渡るのを待ってから提出を許可する
// （ユーザー確認済み 2026-07-07: 5-10秒程度・デフォルト10秒。テストはenvで短縮可）
export const QUIESCENCE_MS = Number(process.env.NEXT_PUBLIC_P2P_QUIESCENCE_MS || 10000);

// クライアント側 per-pubkey 受信キャップ（§9.4b ②: 高コスト処理前のCPU防御）。
// ※ユニークイベント（id重複排除後）だけを数える。v3.2 の正当上限
// （chat≤100/投票・密告/受領証明≤480＝既読4×100＋行動4×2×10、
// 在席通知と出し直し）の上。正直な多弁での誤検知を避ける。
const PER_PUBKEY_EVENT_CAP = 1200;

// 名簿の最大5鍵が per-pubkey 上限へ到達した場合（上限超過を確定する各1件を含む）も、
// 全イベントidを保持できる。組の外の鍵は記憶に入らない。
export const MAX_SEEN_EVENT_IDS = PER_PUBKEY_EVENT_CAP * 5 + 5;

// 第12ラウンド 決定3: 受領証明は発行者（receiverUid）ごとに生の枚数を制限する。
// 正当なカバー先の理論上限480に対し、未測定の正当な発行形へ46%の余裕を持たせた値。
export const MAX_RECEIPTS_PER_ISSUER = 700;

// RS-0: incremental index of accepted and durable receipts. A read is an
// addsNew member exactly when it is the canonical first owner of at least one
// sender/ref fact. This index deliberately does not inspect target messages:
// restored receipts must survive until those messages can be fetched again.
export class CarriedReceiptStoreIndex {
  constructor(myUid, compare, factKeysOf = null) {
    this.myUid = myUid;
    this.compare = compare;
    this.factKeysOf = factKeysOf;
    this.memory = new Map();
    this.disk = new Map();
    this.removed = new Set();
    this.issuers = new Map();
    this.own = new Map();
    this.selected = new Map();
    this.normal = new Map();
    this.planSignatures = new Set();
    this.lastShare = null;
    this.lastTrimmed = null;
    this.dirty = new Set();
  }
  _factKeys(receipt) {
    return Array.isArray(receipt?.msgRefs)
      ? (this.factKeysOf ? this.factKeysOf(receipt)
        : receipt.msgRefs.map((ref) => `${receipt.senderUid}|${ref}`))
      : [`a|${receipt.actionHash}`];
  }
  _cost(receipt) { return Array.isArray(receipt?.msgRefs) ? this._factKeys(receipt).length : 1; }
  _cmp(a, b) {
    return this.compare(a, b) || String(a.signature).toLowerCase().localeCompare(String(b.signature).toLowerCase());
  }
  _issuer(uid) {
    if (!this.issuers.has(uid)) this.issuers.set(uid, {
      all: new Map(), owner: new Map(), owned: new Map(), facts: new Map(), cost: 0, count: 0,
    });
    return this.issuers.get(uid);
  }
  _add(receipt) {
    const signature = receipt?.signature;
    if (!signature) return;
    if (receipt.receiverUid === this.myUid) {
      this.own.set(signature, receipt);
      this.dirty.add('own');
      return;
    }
    const issuer = this._issuer(receipt.receiverUid);
    issuer.all.set(signature, receipt);
    const facts = this._factKeys(receipt);
    issuer.facts.set(signature, facts);
    let owned = 0;
    for (const fact of facts) {
      const previous = issuer.owner.get(fact);
      if (!previous || this._cmp(receipt, previous) < 0) {
        issuer.owner.set(fact, receipt);
        owned += 1;
        if (previous) {
          const priorCount = issuer.owned.get(previous.signature) - 1;
          issuer.owned.set(previous.signature, priorCount);
          if (priorCount === 0) { issuer.count -= 1; issuer.cost -= this._cost(previous); }
        }
      }
    }
    issuer.owned.set(signature, owned);
    if (owned > 0) { issuer.count += 1; issuer.cost += this._cost(receipt); }
    this.dirty.add(receipt.receiverUid);
  }
  _remove(receipt) {
    if (!receipt?.signature) return;
    if (receipt.receiverUid === this.myUid) {
      this.own.delete(receipt.signature);
      this.dirty.add('own');
      return;
    }
    const issuer = this.issuers.get(receipt.receiverUid);
    if (!issuer?.all.has(receipt.signature)) return;
    const rest = [...issuer.all.values()].filter((item) => item.signature !== receipt.signature);
    this.issuers.delete(receipt.receiverUid);
    this.selected.delete(receipt.receiverUid);
    this.normal.delete(receipt.receiverUid);
    this.dirty.add(receipt.receiverUid);
    for (const item of rest) this._add(item);
  }
  _active(signature) { return !this.removed.has(signature) && (this.memory.get(signature) || this.disk.get(signature)); }
  accept(receipt) {
    if (!receipt?.signature) return;
    this.removed.delete(receipt.signature);
    const previous = this._active(receipt.signature);
    this.memory.set(receipt.signature, receipt);
    if (previous && JSON.stringify(previous) === JSON.stringify(receipt)) return;
    if (previous) this._remove(previous);
    this._add(receipt);
  }
  remove(signature) {
    const previous = this._active(signature);
    this.removed.add(signature);
    this.memory.delete(signature);
    if (previous) this._remove(previous);
  }
  syncDisk(receiptMap) {
    const next = new Map(Object.values(receiptMap || {}).filter((item) => item?.signature)
      .map((item) => [item.signature, item]));
    for (const [signature, old] of this.disk) {
      if (!next.has(signature) && !this.memory.has(signature) && !this.removed.has(signature)) this._remove(old);
    }
    for (const [signature, receipt] of next) {
      if (this.removed.has(signature) || this.memory.has(signature)) continue;
      const old = this.disk.get(signature);
      if (!old) this._add(receipt);
      else if (JSON.stringify(old) !== JSON.stringify(receipt)) { this._remove(old); this._add(receipt); }
    }
    this.disk = next;
  }
  setPlanSignatures(signatures = []) {
    const next = new Set(signatures);
    if (next.size === this.planSignatures.size && [...next].every((value) => this.planSignatures.has(value))) return false;
    this.planSignatures = next;
    for (const issuer of this.issuers.keys()) this.dirty.add(issuer);
    return true;
  }
  pruneOutside(predicate) {
    for (const [signature, receipt] of [...this.disk, ...this.memory]) {
      if (!this.removed.has(signature) && !predicate(receipt)) this.remove(signature);
    }
  }
  _ownCost() {
    const facts = new Set();
    for (const receipt of this.own.values()) for (const fact of this._factKeys(receipt)) facts.add(fact);
    return Math.min(480, facts.size);
  }
  selectedReceipts() {
    const A = this._ownCost();
    const activeIssuers = [...this.issuers.entries()].filter(([, row]) => row.count > 0);
    const total = A + activeIssuers.reduce((sum, [, row]) => sum + row.cost, 0);
    const count = activeIssuers.reduce((sum, [, row]) => sum + row.count, 0);
    const trimmed = total > 2400 || count > 2400;
    const share = trimmed && activeIssuers.length ? Math.floor((2400 - A) / activeIssuers.length) : null;
    if (trimmed !== this.lastTrimmed || share !== this.lastShare) {
      for (const issuer of this.issuers.keys()) this.dirty.add(issuer);
      this.lastTrimmed = trimmed;
      this.lastShare = share;
    }
    for (const uid of this.dirty) {
      if (uid === 'own') continue;
      const row = this.issuers.get(uid);
      const keep = new Set();
      const normal = new Set();
      if (row) {
        const first = [...row.all.values()].filter((item) => row.owned.get(item.signature) > 0);
        const actions = first.filter((item) => !Array.isArray(item.msgRefs));
        for (const item of actions) normal.add(item.signature);
        const ownCover = first.filter((item) => Array.isArray(item.msgRefs) && item.senderUid === this.myUid).sort((a, b) => this._cmp(a, b));
        const rest = first.filter((item) => Array.isArray(item.msgRefs) && item.senderUid !== this.myUid).sort((a, b) => this._cmp(a, b));
        if (!trimmed) for (const item of first) normal.add(item.signature);
        else {
          let used = actions.length;
          for (const item of [...ownCover, ...rest]) if (used + this._cost(item) <= share) {
            normal.add(item.signature); used += this._cost(item);
          }
        }
        for (const signature of normal) keep.add(signature);
        for (const item of ownCover) keep.add(item.signature);
        // Monotone safety margin: a canonical prefix of at most 600 facts per
        // issuer survives changes in A or in another issuer's share.
        let prefixCost = actions.length;
        for (const item of [...ownCover, ...rest]) {
          if (prefixCost + this._cost(item) > 600) break;
          keep.add(item.signature); prefixCost += this._cost(item);
        }
        for (const item of row.all.values()) if (!Array.isArray(item.msgRefs) || this.planSignatures.has(item.signature)) keep.add(item.signature);
        // Preserve the priority order under the existing per-issuer cap.
        const prioritized = [
          ...[...row.all.values()].filter((item) => !Array.isArray(item.msgRefs)),
          ...ownCover,
          ...first.filter((item) => keep.has(item.signature) && Array.isArray(item.msgRefs) && item.senderUid !== this.myUid).sort((a, b) => this._cmp(a, b)),
          ...[...row.all.values()].filter((item) => this.planSignatures.has(item.signature)),
        ];
        const capped = new Set(prioritized.slice(0, MAX_RECEIPTS_PER_ISSUER).map((item) => item.signature));
        for (const signature of keep) if (!capped.has(signature)) keep.delete(signature);
      }
      this.selected.set(uid, keep);
      this.normal.set(uid, normal);
    }
    this.dirty.clear();
    const signatures = new Set(this.own.keys());
    for (const kept of this.selected.values()) for (const signature of kept) signatures.add(signature);
    const result = {};
    for (const [signature, receipt] of [...this.disk, ...this.memory]) {
      if (signatures.has(signature) && !this.removed.has(signature)) result[signature] = this.memory.get(signature) || receipt;
    }
    return result;
  }
  normalSignatures() {
    this.selectedReceipts();
    const out = new Set();
    for (const signatures of this.normal.values()) for (const signature of signatures) out.add(signature);
    return out;
  }
}

// Cache each receipt's claim against only the targets it names. A new message
// invalidates a receipt only when that message changes one of its target refs.
// Callers own the instance and clear it when game identity or roster changes.
export class ReceiptClaimMemo {
  constructor() { this.entries = new Map(); this.digests = new WeakMap(); this.screenTargets = null; }
  clear() { this.entries.clear(); this.digests = new WeakMap(); this.screenTargets = null; }
  // Pay for each accepted receipt before a render asks for the whole screen.
  // The target index is shared until the message set or window changes; claim()
  // still checks each named target and every option before reusing a value.
  primeScoreable(receipt, messages, { blockNum, groupId, selfUid, chatWindow = null,
    caps, getClientMsgKey = null, memberUids = null, maxRefsPerReceipt = null,
    scoreMaxRefsPerReceipt = receiptMaxRefsPerReceipt(GUEST_PINNED_RULES.maxMessages) } = {}) {
    if (!Array.isArray(receipt?.msgRefs)) return;
    const startMs = chatWindow?.startMs ?? null;
    const endMs = chatWindow?.endMs ?? null;
    const prior = this.screenTargets;
    if (!prior || prior.messages !== messages || prior.blockNum !== blockNum
        || prior.groupId !== groupId || prior.getClientMsgKey !== getClientMsgKey
        || prior.startMs !== startMs || prior.endMs !== endMs) {
      const windowed = (Array.isArray(messages) ? messages : []).filter((message) =>
        !chatWindow || (message.timestamp >= chatWindow.startMs && message.timestamp <= chatWindow.endMs));
      this.screenTargets = { messages, blockNum, groupId, getClientMsgKey, startMs, endMs,
        targets: buildRealTargets({}, windowed, blockNum, groupId, getClientMsgKey) };
    }
    const targets = this.screenTargets.targets;
    this.claim(receipt, targets, { chatWindow, selfUid, caps, atomic: true });
    this.claim(receipt, targets, { chatWindow, selfUid,
      maxRefsPerReceipt: scoreMaxRefsPerReceipt, atomic: true });
    if (Array.isArray(memberUids)) this.claim(receipt, targets, { chatWindow, selfUid,
      memberUids, maxRefsPerReceipt, caps, atomic: true });
  }
  claim(receipt, targets, opts = {}) {
    if (!receipt || typeof receipt !== 'object') return receiptCoverClaim(receipt, targets, opts);
    let digest = this.digests.get(receipt);
    if (digest === undefined) {
      digest = receiptIdentityDigest(receipt);
      this.digests.set(receipt, digest);
    }
    if (!digest) return receiptCoverClaim(receipt, targets, opts);
    const window = opts.chatWindow;
    const optionsKey = JSON.stringify([
      window?.startMs ?? null, window?.endMs ?? null,
      opts.selfUid ?? null, Array.isArray(opts.memberUids) ? opts.memberUids : null,
      Number.isFinite(opts.maxRefsPerReceipt) ? opts.maxRefsPerReceipt : null,
      opts.atomic === true, opts.caps || null,
    ]);
    const key = `${digest}|${optionsKey}`;
    const deps = Array.isArray(receipt.msgRefs)
      ? receipt.msgRefs.map((ref) => {
        const target = `${receipt.senderUid}|${ref}`;
        return [target, targets?.realRefs?.has(target) === true, targets?.refTimes?.get(target) ?? null];
      })
      : [receipt.actionHash, targets?.realActionHashes?.has(receipt.actionHash) === true,
        targets?.actionTimes?.get(receipt.actionHash) ?? null,
        targets?.actionActors?.get(receipt.actionHash) ?? null];
    const depsKey = JSON.stringify(deps);
    const cached = this.entries.get(key);
    if (cached?.depsKey === depsKey) return cached.value;
    const value = receiptCoverClaim(receipt, targets, opts);
    this.entries.set(key, { depsKey, value });
    return value;
  }
}

// One bounded chain observation is shared by receipts arriving together.
// Cache age is measured at arrival, so a slow RPC cannot turn an earlier
// arrival into a later one merely by completing after the chat boundary.
export async function readReceiptChainTime(clock, getTime, arrivalAt, timeoutMs = 3000) {
  if (Number.isSafeInteger(clock.timeMs) && arrivalAt >= clock.at
      && arrivalAt - clock.at <= 3000) return clock.timeMs + arrivalAt - clock.at;
  if (!clock.pending) {
    const startedAt = Date.now();
    clock.pending = new Promise((resolve) => {
      const timer = setTimeout(() => resolve(null), timeoutMs);
      Promise.resolve().then(getTime).then((value) => {
        clearTimeout(timer);
        resolve(Number.isSafeInteger(value) ? value : null);
      }, () => { clearTimeout(timer); resolve(null); });
    }).then((value) => {
      if (Number.isSafeInteger(value)) { clock.timeMs = value; clock.at = startedAt; }
      clock.pending = null;
      return value;
    });
  }
  const value = await clock.pending;
  return Number.isSafeInteger(value) ? value + Math.max(0, arrivalAt - clock.at) : null;
}

// 1件の上限だけは正準順序に依らず採点でも必ず除外される。
export function isClientChatWithinLimit(text, maxMsgChars = GUEST_PINNED_RULES.maxMsgChars) {
  return typeof text === 'string' && countHalfWidthChars(text) <= maxMsgChars;
}

// 開始関門で検証済みの名簿とチェーンから得た窓だけを端末に保存する。
// 同じブロック・組でも別の名簿／開始時刻なら再利用しない。
export function confirmedWindowStorageKey(blockNum, groupId) {
  return `confirmedChatWindow_${blockNum}_group${groupId}`;
}

export function saveConfirmedChatWindow(storage, blockNum, groupId, rosterId, start, window) {
  if (!storage || !rosterId || !Number.isFinite(start)
      || !Number.isFinite(window?.startMs) || !Number.isFinite(window?.endMs)) return false;
  try {
    storage.setItem(confirmedWindowStorageKey(blockNum, groupId),
      JSON.stringify({ rosterId, start, window }));
    return true;
  } catch { return false; }
}

export function loadConfirmedChatWindow(storage, blockNum, groupId, rosterId, start) {
  if (!storage || !rosterId || !Number.isFinite(start)) return null;
  try {
    const record = JSON.parse(storage.getItem(confirmedWindowStorageKey(blockNum, groupId)) || 'null');
    return record?.rosterId === rosterId && record?.start === start
      && Number.isFinite(record?.window?.startMs) && Number.isFinite(record?.window?.endMs)
      && record.window.startMs <= record.window.endMs ? record.window : null;
  } catch { return null; }
}

export const LIVE_SNAPSHOT_POLL_MS = 30_000;
export const LIVE_SNAPSHOT_MAX_BYTES = 16 * 1024 * 1024;
const LIVE_SNAPSHOT_PER_ACTOR_CAP = 1200;

export class LiveSnapshotRejectionMemory {
  constructor({ capPerIssuer = LIVE_SNAPSHOT_PER_ACTOR_CAP } = {}) {
    this.capPerIssuer = Math.min(LIVE_SNAPSHOT_PER_ACTOR_CAP,
      Number.isSafeInteger(capPerIssuer) && capPerIssuer > 0 ? capPerIssuer : LIVE_SNAPSHOT_PER_ACTOR_CAP);
    this.context = null;
    this.rejectedByIssuer = new Map();
  }

  bind(context) {
    if (this.context === context) return;
    this.context = context;
    this.rejectedByIssuer.clear();
  }

  has(context, issuerUid, key) {
    return this.context === context && this.rejectedByIssuer.get(issuerUid)?.has(key) === true;
  }

  add(context, issuerUid, key) {
    if (this.context !== context) return;
    let rejected = this.rejectedByIssuer.get(issuerUid);
    if (!rejected) {
      rejected = new Set();
      this.rejectedByIssuer.set(issuerUid, rejected);
    }
    if (rejected.has(key)) return;
    rejected.add(key);
    if (rejected.size > this.capPerIssuer) rejected.delete(rejected.values().next().value);
  }
}

// 公開 live JSON は運搬路であり、各項目は検証済み名簿の鍵による P2P 入口を通す。
// 公式と復元の両クライアントは、この同じ関数が返した項目だけを集合に加える。
export async function verifyLiveSnapshotEntries(snapshot, {
  blockNum, groupId, members, verifyChat, verifyInner, knownReceiptDigests = new Set(),
  maxMsgChars = GUEST_PINNED_RULES.maxMsgChars,
  rejectionMemory = null, verifierMembers = null,
} = {}) {
  if (!snapshot || snapshot.blockNum !== blockNum || snapshot.groupId !== groupId) {
    return { messages: [], actions: [], receipts: [] };
  }
  const roster = Array.isArray(members) ? members : [];
  const rosterContext = (rows) => JSON.stringify([blockNum, groupId,
    rows.map((m) => [m.uid, typeof m.bAddr === 'string' ? m.bAddr : JSON.stringify(m.bAddr ?? null)])]);
  const context = rejectionMemory ? rosterContext(roster) : null;
  if (rejectionMemory) rejectionMemory.bind(context);
  const sameVerifierContext = () => {
    try {
      const current = verifierMembers ? verifierMembers() : members;
      return rosterContext(Array.isArray(current) ? current : []) === context;
    } catch { return false; }
  };
  const digestFields = (fields) => keccak256(toBytes(JSON.stringify(fields)));
  const sliceNow = () => (typeof performance !== 'undefined' && typeof performance.now === 'function'
    ? performance.now() : Date.now());
  let sliceStart = sliceNow();
  let sliceCalls = 0;
  const afterItem = async (called) => {
    const priorCalls = sliceCalls;
    if (called) sliceCalls += called;
    // S3R5-U-R06-FIX: ReceiptAdmissionQueue と同じ32件か16msでタイマーへ譲る。
    if ((called && Math.floor(priorCalls / 32) !== Math.floor(sliceCalls / 32))
      || sliceNow() - sliceStart >= 16) {
      await yieldToTimers();
      sliceStart = sliceNow();
    }
  };
  const inGroup = (uid) => roster.some((m) => m.uid === uid);
  const matching = (item) => item && typeof item === 'object' && !Array.isArray(item)
    && (!('blockNum' in item) || item.blockNum === blockNum)
    && (!('groupId' in item) || item.groupId === groupId);
  const actorCounts = Object.create(null);
  const takeBudget = (uid) => {
    actorCounts[uid] = (actorCounts[uid] || 0) + 1;
    return actorCounts[uid] <= LIVE_SNAPSHOT_PER_ACTOR_CAP;
  };
  const messages = [];
  for (const item of (Array.isArray(snapshot.messages) ? snapshot.messages : [])) {
    let called = 0;
    try {
      if (!matching(item) || !inGroup(item.uid) || !takeBudget(item.uid)
        || !isClientChatWithinLimit(item.text, maxMsgChars)) continue;
      const message = { uid: item.uid, text: item.text, timestamp: item.timestamp, signature: item.signature };
      const key = rejectionMemory ? digestFields(['chat', message.uid, message.text,
        message.timestamp, message.signature]) : null;
      if (rejectionMemory && sameVerifierContext() && rejectionMemory.has(context, item.uid, key)) continue;
      const before = rejectionMemory && sameVerifierContext();
      called++;
      if (await verifyChat(message)) { messages.push(message); continue; }
      if (rejectionMemory) {
        const beforeInner = sameVerifierContext();
        called++;
        const inner = { type: 'chat', blockNum, groupId, ...message };
        if (!(await verifyInner('chat', inner)) && before && beforeInner && sameVerifierContext()) {
          rejectionMemory.add(context, item.uid, key);
        }
      }
    } finally { await afterItem(called); }
  }
  const actions = [];
  const sourceActions = snapshot.actions && typeof snapshot.actions === 'object' ? snapshot.actions : {};
  for (const [kind, entries] of [['vote', sourceActions.votes], ['report', sourceActions.reports]]) {
    if (!entries || typeof entries !== 'object') continue;
    for (const member of roster) {
      const uid = member.uid;
      const primary = kind === 'vote'
        ? [entries[uid], ...(Array.isArray(entries[`${uid}__extras`]) ? entries[`${uid}__extras`] : [])]
        : (Array.isArray(entries[uid]) ? entries[uid] : []);
      for (const item of primary.slice(0, MAX_OBSERVED_ACTIONS_PER_ACTOR)) {
        let called = 0;
        try {
          if (!matching(item) || !takeBudget(uid)) continue;
          const inner = { type: 'action', blockNum, groupId, actionType: kind, uid,
            encrypted: item.encrypted, timestamp: item.timestamp, signature: item.signature };
          const key = rejectionMemory ? digestFields(['action', kind, uid, item.encrypted,
            item.timestamp, item.signature]) : null;
          if (rejectionMemory && sameVerifierContext() && rejectionMemory.has(context, uid, key)) continue;
          const before = rejectionMemory && sameVerifierContext();
          called++;
          if (await verifyInner('action', inner)) actions.push(inner);
          else if (rejectionMemory && before && sameVerifierContext()) rejectionMemory.add(context, uid, key);
        } finally { await afterItem(called); }
      }
    }
  }
  const receiptCounts = Object.create(null);
  const receipts = [];
  for (const item of (Array.isArray(snapshot.receipts) ? snapshot.receipts : [])) {
    let called = 0;
    try {
      if (!matching(item) || !inGroup(item.receiverUid)) continue;
      receiptCounts[item.receiverUid] = (receiptCounts[item.receiverUid] || 0) + 1;
      if (!takeBudget(item.receiverUid) || receiptCounts[item.receiverUid] > MAX_RECEIPTS_PER_ISSUER) continue;
      const digest = receiptIdentityDigest(item);
      if (!digest || knownReceiptDigests.has(digest)) continue;
      if (rejectionMemory && sameVerifierContext()
        && rejectionMemory.has(context, item.receiverUid, digest)) continue;
      const before = rejectionMemory && sameVerifierContext();
      const inner = { ...item, type: 'receipt', blockNum, groupId };
      called++;
      if (!(await verifyInner('receipt', inner))) {
        if (rejectionMemory && before && sameVerifierContext()) {
          rejectionMemory.add(context, item.receiverUid, digest);
        }
        continue;
      }
      const receipt = { receiverUid: item.receiverUid, timestamp: item.timestamp, signature: item.signature };
      if (Number.isSafeInteger(item._receivedAt)) receipt._receivedAt = item._receivedAt;
      if (Array.isArray(item.msgRefs)) {
        receipt.senderUid = item.senderUid; receipt.msgRefs = item.msgRefs;
      } else receipt.actionHash = item.actionHash;
      receipts.push(receipt);
    } finally { await afterItem(called); }
  }
  return { messages, actions, receipts };
}

export async function readLiveSnapshot({ r2Base, blockNum, groupId, chatStartMs = 0,
  maxAgeMs = 26 * 60 * 60 * 1000, nowMs = Date.now() }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const url = `${String(r2Base).replace(/\/$/, '')}/live/block${blockNum}/group${groupId}.json`;
    const response = await fetch(url, { cache: 'no-store', signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const length = Number(response.headers?.get?.('content-length'));
    if (Number.isFinite(length) && length > LIVE_SNAPSHOT_MAX_BYTES) throw new Error('live snapshot too large');
    if (!response.body?.getReader) throw new Error('live snapshot body unavailable');
    const reader = response.body.getReader();
    const chunks = [];
    let bytes = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > LIVE_SNAPSHOT_MAX_BYTES) {
        await reader.cancel().catch(() => {});
        throw new Error('live snapshot too large');
      }
      chunks.push(value);
    }
    const raw = new Uint8Array(bytes);
    let offset = 0;
    for (const chunk of chunks) { raw.set(chunk, offset); offset += chunk.byteLength; }
    const snapshot = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
    if (!snapshot || snapshot.blockNum !== blockNum || snapshot.groupId !== groupId
      || !Number.isSafeInteger(snapshot.updatedAt) || snapshot.updatedAt < chatStartMs
      || snapshot.updatedAt > nowMs + 120_000 || nowMs - snapshot.updatedAt > maxAgeMs) {
      throw new Error('live snapshot stale or mismatched');
    }
    return snapshot;
  } finally { clearTimeout(timer); }
}

// 証拠容量トリムの正典順。受領証明ストアが上限を超えた場合も同じ順だけを使い、
// 発行者が操作できる timestamp を選抜材料にはしない。
export const RECEIPT_TRIM_ORDER = Object.freeze(['H', 'G', 'F', 'E', 'C', 'D', 'A', 'B', 'V']);

// 名簿待ちとカバー先待ちに共通の期限。新しい猶予定数は作らず、既存の10分鮮度窓と
// CHAT_WINDOW_CLOCK_SKEW_MS（2分）をそのまま合成する。
// S3R4-U-P2B2-ADMIT2: メモリを溢れさせる攻撃が見つかったら捨てる道へすぐ戻せるよう残す。
export const RECEIPT_PENDING_TTL_MS = RECEIPT_FRESH_WINDOW_MS + CHAT_WINDOW_CLOCK_SKEW_MS;
export const OTHER_READ_RECEIPT_PENDING_EXPIRES = false;

/**
 * クライアント取り込みの未来時刻ゲート（決定4）。過去側は宣言チャット窓／鮮度判定が担う。
 * DO はこの述語を使わない。既定 now は必ずクライアント自身の時計である。
 */
export function isClientTimestampAllowed(timestamp, now = Date.now()) {
  return isCanonicalTimestamp(timestamp)
    && Number.isFinite(now)
    && timestamp <= now + CHAT_WINDOW_CLOCK_SKEW_MS;
}

// One page owns one instance across WS, P2P and live. Only callers that have
// verified the appropriate signature may call discard().
export class FutureAdmissionMarks {
  constructor({ blockNum, groupId, now = () => Date.now(), correction = () => 0,
    onDiscardedChatRef = null, onChatRefOverflow = null, onChange = null,
    onFutureDiscard = null }) {
    this.blockNum = blockNum;
    this.groupId = groupId;
    this.now = now;
    this.correction = correction;
    this.marks = new Map();
    this.markCounts = { chat: 0, action: 0 };
    this.confirmationVersion = 0;
    this.nextMaturityMs = Infinity;
    this.byIssuer = new Map();
    this.chatRefs = new Map();
    this.chatRefOverflow = new Set();
    this.closedMarkedIds = new Map();
    this.closedIssuerCounts = new Map();
    this.closedIssuerSticky = new Set();
    this.onDiscardedChatRef = onDiscardedChatRef;
    this.onChatRefOverflow = onChatRefOverflow;
    this.onChange = onChange;
    this.onFutureDiscard = onFutureDiscard;
  }

  key(type, item) {
    if (!isCanonicalTimestamp(item?.timestamp) || !isCanonicalSignature(item?.signature)) return null;
    let fields;
    if (type === 'chat') fields = ['chat', item.uid, item.text, item.timestamp, item.signature];
    else if (type === 'action') fields = ['action', item.actionType, item.uid,
      item.encrypted, item.timestamp, item.signature];
    else if (type === 'receipt') fields = ['receipt', receiptIdentityDigest(item)];
    else return null;
    if (fields.some((field) => field == null)) return null;
    return keccak256(toBytes(JSON.stringify(fields)));
  }

  has(type, item) {
    const key = this.key(type, item);
    const found = !!key && this.marks.has(key);
    if (found && item.timestamp > this.now() + CHAT_WINDOW_CLOCK_SKEW_MS) {
      try { this.onFutureDiscard?.(type, item); } catch { /* Admission remains independent of UI. */ }
    }
    return found;
  }

  noteEvent(type, item, eventId) {
    const record = this.marks.get(this.key(type, item));
    if (record && eventId) record.eventIds.add(eventId);
    if (record && item.timestamp > this.now() + CHAT_WINDOW_CLOCK_SKEW_MS) {
      try { this.onFutureDiscard?.(type, item); } catch { /* Admission remains independent of UI. */ }
    }
    return !!record;
  }

  discard(type, item, { eventId = null, issuer = null } = {}) {
    const key = this.key(type, item);
    const limit = this.now() + CHAT_WINDOW_CLOCK_SKEW_MS;
    if (!key || item.timestamp <= limit) return false;
    const existing = this.marks.get(key);
    if (existing) { if (eventId) existing.eventIds.add(eventId);
      try { this.onFutureDiscard?.(type, item); } catch { /* Admission remains independent of UI. */ }
      return true; }
    try { this.onFutureDiscard?.(type, item); } catch { /* Admission remains independent of UI. */ }
    const owner = issuer || (type === 'receipt' ? item.receiverUid : item.uid);
    const owned = this.byIssuer.get(owner) || new Set();
    if (owned.size >= PER_PUBKEY_EVENT_CAP || this.marks.size >= PER_PUBKEY_EVENT_CAP * 5) {
      if (type === 'chat' && !this.chatRefOverflow.has(owner)) {
        this.chatRefOverflow.add(owner);
        this.confirmationVersion++;
        try { this.onChatRefOverflow?.(owner); } catch { /* display only */ }
        try { this.onChange?.(); } catch { /* display only */ }
      }
      return true;
    }
    const record = { type, issuer: owner, timestamp: item.timestamp, excessMs: item.timestamp - limit,
      correctionMs: this.correction(), eventIds: new Set(eventId ? [eventId] : []), chatRef: null,
      receiptDigest: type === 'receipt' ? receiptIdentityDigest(item) : null };
    if (type === 'chat') {
      const ref = msgRefOf(computeMsgKeyV2(this.blockNum, this.groupId, item));
      const refs = this.chatRefs.get(owner) || new Set();
      if (refs.size < GUEST_PINNED_RULES.maxMessages) {
        refs.add(ref); this.chatRefs.set(owner, refs); record.chatRef = ref;
      } else if (!this.chatRefOverflow.has(owner)) {
        this.chatRefOverflow.add(owner);
        this.confirmationVersion++;
        try { this.onChatRefOverflow?.(owner); } catch { /* display only */ }
      }
      try { this.onDiscardedChatRef?.(owner, ref); } catch { /* display only */ }
    }
    this.marks.set(key, record);
    if (type === 'chat' || type === 'action') this.markCounts[type]++;
    this.nextMaturityMs = Math.min(this.nextMaturityMs, record.timestamp - CHAT_WINDOW_CLOCK_SKEW_MS);
    owned.add(key); this.byIssuer.set(owner, owned);
    try { this.onChange?.(); } catch { /* display only */ }
    return true;
  }

  countsByType() {
    return { ...this.markCounts };
  }

  hasDiscardedChatRef(senderUid, ref) { return this.chatRefs.get(senderUid)?.has(ref) || false; }
  hasChatRefOverflow(senderUid) { return this.chatRefOverflow.has(senderUid); }
  hasClosedMarkedRequest(senderUid) {
    return this.closedIssuerSticky.has(senderUid)
      || (this.closedIssuerCounts.get(senderUid) || 0) > 0;
  }
  noteClosedMarkedIds(eventIssuers) {
    let changed = false;
    for (const [id, issuer] of eventIssuers) {
      if (this.closedMarkedIds.has(id)) continue;
      // The bounded id ledger cannot prove recovery of an evicted id. Keep that
      // sender unconfirmed for this session instead of growing memory forever.
      if (this.closedMarkedIds.size >= MAX_SEEN_EVENT_IDS) {
        changed ||= !this.closedIssuerSticky.has(issuer);
        this.closedIssuerSticky.add(issuer);
        continue;
      }
      this.closedMarkedIds.set(id, issuer);
      this.closedIssuerCounts.set(issuer, (this.closedIssuerCounts.get(issuer) || 0) + 1);
      changed = true;
    }
    if (changed) this.confirmationVersion++;
    if (eventIssuers.size) try { this.onChange?.(); } catch { /* display only */ }
  }
  noteRecoveredMarkedId(id) {
    const issuer = this.closedMarkedIds.get(id);
    if (issuer === undefined) return;
    this.closedMarkedIds.delete(id);
    const remaining = (this.closedIssuerCounts.get(issuer) || 1) - 1;
    if (remaining) this.closedIssuerCounts.set(issuer, remaining);
    else this.closedIssuerCounts.delete(issuer);
    this.confirmationVersion++;
    try { this.onChange?.(); } catch { /* display only */ }
  }
  nextMaturityAt() {
    return this.nextMaturityMs;
  }
  releaseMatured(nowMs = this.now(), chatEndMs = Infinity) {
    return this._releaseWhere((record) => record.timestamp <= nowMs + CHAT_WINDOW_CLOCK_SKEW_MS,
      chatEndMs);
  }
  releaseEligible(correctionMs = this.correction()) {
    const result = this._releaseWhere((record) =>
      correctionMs - record.correctionMs >= record.excessMs);
    return { released: result.released, eventIds: result.eventIds,
      receiptDigests: result.receiptDigests };
  }
  _releaseWhere(shouldRelease, chatEndMs = Infinity) {
    const eventIds = new Set();
    const eventIssuers = new Map();
    const receiptDigests = new Set();
    let released = 0;
    let inWindow = 0;
    for (const [key, record] of this.marks) {
      if (!shouldRelease(record)) continue;
      this.marks.delete(key);
      if (record.type === 'chat' || record.type === 'action') this.markCounts[record.type]--;
      const owned = this.byIssuer.get(record.issuer);
      owned?.delete(key);
      if (owned?.size === 0) this.byIssuer.delete(record.issuer);
      if (record.chatRef) {
        const stillHeld = [...this.marks.values()].some((mark) =>
          mark.issuer === record.issuer && mark.chatRef === record.chatRef);
        if (!stillHeld) this.chatRefs.get(record.issuer)?.delete(record.chatRef);
      }
      if (record.timestamp <= chatEndMs) {
        for (const id of record.eventIds) {
          eventIds.add(id);
          if (record.type === 'chat') eventIssuers.set(id, record.issuer);
        }
        inWindow++;
      }
      if (record.receiptDigest) receiptDigests.add(record.receiptDigest);
      released++;
    }
    if (released) {
      this.nextMaturityMs = Infinity;
      for (const record of this.marks.values()) {
        this.nextMaturityMs = Math.min(this.nextMaturityMs,
          record.timestamp - CHAT_WINDOW_CLOCK_SKEW_MS);
      }
      try { this.onChange?.(); } catch { /* display only */ }
    }
    return { released, eventIds, eventIssuers, receiptDigests, inWindow };
  }
}

function receiptRawFacts(receipt) {
  if (Array.isArray(receipt?.msgRefs) && typeof receipt.senderUid === 'string') {
    return receipt.msgRefs.map((ref) => `r|${receipt.receiverUid}|${receipt.senderUid}|${ref}`);
  }
  if (isActionHash(receipt?.actionHash)) {
    return [`a|${receipt.receiverUid}|${receipt.actionHash}`];
  }
  return [];
}

// 検証が読む項目を受信した表記のまま使う。輸送用メタデータとキー順は含めない。
// 形式が不正なものには digest を与えず、既出記録と署名検証の前に捨てる。
const receiptDigestCache = new WeakMap();
export function receiptIdentityDigest(receipt) {
  if (!receipt || typeof receipt !== 'object') return null;
  let fields = null;
  if (isCanonicalSignature(receipt.signature)
      && typeof receipt.receiverUid === 'string' && isCanonicalTimestamp(receipt.timestamp)) {
    if (Array.isArray(receipt.msgRefs) && typeof receipt.senderUid === 'string'
        && receipt.msgRefs.length > 0
        && receipt.msgRefs.length <= receiptMaxRefsPerReceipt(GUEST_PINNED_RULES.maxMessages)
        && receipt.msgRefs.every(isMsgRef)
        && receipt.msgRefs.every((ref, i) => i === 0 || compareHexAsc(receipt.msgRefs[i - 1], ref) < 0)) {
      fields = ['read_receipt', receipt.receiverUid, receipt.senderUid,
        receipt.msgRefs, receipt.timestamp, receipt.signature];
    } else if (!Array.isArray(receipt.msgRefs) && isActionHash(receipt.actionHash)) {
      fields = ['receipt', receipt.receiverUid, receipt.actionHash, receipt.timestamp, receipt.signature];
    }
  }
  if (!fields) return null;
  const bytes = JSON.stringify(fields);
  const cached = receiptDigestCache.get(receipt);
  if (cached?.bytes === bytes) return cached.digest;
  const digest = keccak256(toBytes(bytes));
  receiptDigestCache.set(receipt, { bytes, digest });
  return digest;
}

/**
 * 正典トリム順で落とす1件を返す。同一クラスでは先着を守るため到着順の末尾を返す。
 * テストからも順序そのものを実測できるよう純粋関数として公開する。
 */
export function receiptTrimVictim(entries) {
  const list = Array.isArray(entries) ? entries : [];
  for (const priority of RECEIPT_TRIM_ORDER) {
    const candidates = list.filter((entry) => entry?.priority === priority);
    if (candidates.length > 0) {
      return candidates.reduce((latest, entry) => (
        Number(entry.order) > Number(latest.order) ? entry : latest
      ));
    }
  }
  return list.reduce((latest, entry) => (
    !latest || Number(entry?.order) > Number(latest?.order) ? entry : latest
  ), null);
}

/**
 * 受領証明の単一保留機構。
 *
 * - 名簿未着とカバー先未着を同じ entries Map の pending 状態で扱う。
 * - 同一性は形式を満たす受領証明の検証対象フィールドの生の digest。改変品が同じ署名で本物の枠を奪えない。
 * - 既出は offer 時に記録し、署名検証は新着ごとに1回だけ。材料更新時は検証済みの保留分だけを再評価する。
 * - onAccept へ渡るのは、名簿・署名・実在/鮮度が全て確定した受領証明だけ。
 * - H は queue へ投入された pendingSince + 10分 + 既存2分猶予で破棄する。
 */
// A same-origin tab lock covers reading the signed receipts and publishing the
// next batch. If storage fails, the current tab continues with its memory set.
export async function coordinateSelfReadReceiptBatch(key, acceptKnown, issue, timeoutMs = 20000) {
  const readKnown = () => {
    try {
      const value = JSON.parse(localStorage.getItem(key) || '[]');
      return Array.isArray(value) ? value : [];
    } catch { return []; }
  };
  const lock = (run) => typeof navigator !== 'undefined' && navigator.locks?.request
    ? navigator.locks.request(key, run) : run();
  const leaseKey = `${key}_lease`;
  const token = `${Date.now()}:${Math.random()}`;
  const reserve = () => lock(() => {
    try {
      const lease = JSON.parse(localStorage.getItem(leaseKey) || 'null');
      const now = Date.now();
      if (lease?.until > now && lease.until <= now + 30000) return null;
      localStorage.setItem(leaseKey, JSON.stringify({ token, until: now + 30000 }));
    } catch { /* storage is optional; proceed with in-memory coordination */ }
    return readKnown();
  });
  let reservation = await reserve();
  const retryUntil = Date.now() + 4000;
  while (reservation === null && Date.now() < retryUntil) {
    await new Promise((resolve) => setTimeout(resolve, 50 + Math.floor(Math.random() * 951)));
    reservation = await reserve();
  }
  if (reservation === null) return;
  const heartbeat = setInterval(() => {
    try {
      const lease = JSON.parse(localStorage.getItem(leaseKey) || 'null');
      if (lease?.token === token) {
        const now = Date.now();
        localStorage.setItem(leaseKey, JSON.stringify({ token, until: now + 30000 }));
      }
    } catch { /* storage is optional */ }
  }, 5000);
  const controller = new AbortController();
  let deadline;
  try {
    const issuing = (async () => {
      for (const receipt of reservation) {
        if (controller.signal.aborted) return [];
        // A stored self receipt reserves its refs synchronously; its admission
        // may continue behind a backlog without delaying this batch's publish.
        try { Promise.resolve(acceptKnown(receipt)).catch(() => {}); }
        catch { /* a broken stored row cannot block the new batch */ }
      }
      return controller.signal.aborted ? [] : issue({ signal: controller.signal, known: reservation });
    })();
    const issued = await Promise.race([issuing, new Promise((resolve) => {
      deadline = setTimeout(() => { controller.abort(); resolve([]); },
        Math.min(20000, Math.max(1, timeoutMs)));
    })]);
    if (controller.signal.aborted) return;
    await lock(() => {
      try {
        const bySignature = new Map([...readKnown(), ...(Array.isArray(issued) ? issued : [])]
          .filter((rc) => rc?.signature).map((rc) => [rc.signature, rc]));
        localStorage.setItem(key, JSON.stringify([...bySignature.values()]));
      } catch { /* memory and relay still carry issued receipts */ }
    });
  } finally {
    clearTimeout(deadline);
    controller.abort();
    clearInterval(heartbeat);
    await lock(() => {
      try {
        const lease = JSON.parse(localStorage.getItem(leaseKey) || 'null');
        if (lease?.token === token) localStorage.removeItem(leaseKey);
      } catch { /* storage is optional */ }
    });
  }
}

function yieldToTimers() {
  if (typeof MessageChannel !== 'function') return new Promise((resolve) => setTimeout(resolve, 0));
  return new Promise((resolve) => {
    const channel = new MessageChannel();
    channel.port1.onmessage = () => {
      channel.port1.close();
      channel.port2.close();
      // A due timer can still be behind this channel task (notably in Node).
      setTimeout(resolve, 0);
    };
    channel.port2.postMessage(null);
  });
}

export class ReceiptAdmissionQueue {
  constructor(options = {}) {
    this.entries = new Map();
    this.seenDigests = new Set();
    this.rejectedDigestsByIssuer = new Map();
    this.order = 0;
    this.timer = null;
    this.disposed = false;
    this.work = Promise.resolve();
    this.workCount = 0;
    this.configure(options);
  }

  configure(options = {}) {
    this.getRosterUids = options.getRosterUids || this.getRosterUids || (() => null);
    this.isRosterVerified = options.isRosterVerified || this.isRosterVerified || (() => true);
    this.verifyReceipt = options.verifyReceipt || this.verifyReceipt || (async () => false);
    this.resolveReceipt = options.resolveReceipt || this.resolveReceipt || (() => ({ state: 'pending' }));
    this.getChatWindow = options.getChatWindow || this.getChatWindow || (() => null);
    this.getChatCloseAtMs = options.getChatCloseAtMs || this.getChatCloseAtMs || (() => null);
    this.allowWindowless = options.allowWindowless || this.allowWindowless || (() => false);
    this.getRosterId = options.getRosterId || this.getRosterId || (() => null);
    this.getSelectionContext = options.getSelectionContext || this.getSelectionContext || (() => ({}));
    this.getMaterialState = options.getMaterialState || this.getMaterialState || null;
    this.requireConfirmedWindow = options.requireConfirmedWindow === true
      || this.requireConfirmedWindow === true;
    this.now = options.now || this.now || (() => Date.now());
    this.selectionNow = options.selectionNow || this.selectionNow || (() => performance.now());
    this.futureMarks = options.futureMarks || this.futureMarks || null;
    this.onAccept = options.onAccept || this.onAccept || (() => {});
    this.onVerifiedReadReceipt = options.onVerifiedReadReceipt || this.onVerifiedReadReceipt || (() => {});
    this.onRemove = options.onRemove || this.onRemove || (() => {});
    this.onDiscard = options.onDiscard || this.onDiscard || (() => {});
    this.maxPerIssuer = Number.isSafeInteger(options.maxPerIssuer)
      ? options.maxPerIssuer
      : (this.maxPerIssuer || MAX_RECEIPTS_PER_ISSUER);
    this.otherReadReceiptPendingExpires = typeof options.otherReadReceiptPendingExpires === 'boolean' ? options.otherReadReceiptPendingExpires : (typeof this.otherReadReceiptPendingExpires === 'boolean' ? this.otherReadReceiptPendingExpires : OTHER_READ_RECEIPT_PENDING_EXPIRES);
    return this;
  }

  getPendingReceipts() {
    return [...this.entries.values()]
      .filter((entry) => entry.status === 'pending')
      .sort((a, b) => a.order - b.order)
      .map((entry) => entry.receipt);
  }

  getAcceptedReceipts() {
    return [...this.entries.values()]
      .filter((entry) => entry.status === 'accepted')
      .sort((a, b) => a.order - b.order)
      .map((entry) => entry.receipt);
  }

  forgetLiveReceipt(receipt) {
    const digest = receiptIdentityDigest(receipt);
    const entry = digest ? this.entries.get(digest) : null;
    if (entry) this._drop(entry, 'live_stale');
  }

  forgetFutureDigests(digests) {
    for (const digest of digests) {
      if (this.entries.has(digest)) continue; // 保存済み自己項目など、受理済みの同じ中身は維持する。
      this.seenDigests.delete(digest);
      for (const rejected of this.rejectedDigestsByIssuer.values()) rejected.delete(digest);
    }
  }

  offer(receipt, { verified = false, immediateOwnRead = false, restoredOwn = false } = {}) {
    const digest = receiptIdentityDigest(receipt);
    if (!digest || this.disposed) return Promise.resolve(false);
    this._syncRosterId();
    if (!restoredOwn && this.futureMarks?.has('receipt', receipt)) return Promise.resolve(false);
    if (restoredOwn && !this.entries.has(digest)) {
      this.seenDigests.delete(digest);
      for (const rejected of this.rejectedDigestsByIssuer.values()) rejected.delete(digest);
    }
    if (this.seenDigests.has(digest)) {
      // 同じ署名が遅れて DO 履歴からも届いた場合、採否と到着順は先着のまま、
      // 出どころだけ追加する。保留中の項目も更新し、参照先の到着後に正しい印で採る。
      const entry = this.entries.get(digest);
      // 同じ digest の確かめ済みの写しは、犠牲の順でも確かめ済みとして扱う。
      if (entry && verified === true) entry.verifiedCopy = true;
      if (!entry || !receipt?.actionHash) return Promise.resolve(false);
      const old = entry.receipt;
      const merged = mergeActionReceiptSources(old, receipt);
      if (JSON.stringify(merged) !== JSON.stringify(old)) {
        entry.receipt = merged;
        if (entry.status === 'accepted') {
          try { this.onAccept(merged); } catch { /* local persistence failure is reported by callback */ }
        }
      }
      return Promise.resolve(false);
    }
    const ownRead = Array.isArray(receipt?.msgRefs) && verified && immediateOwnRead
      && receipt.receiverUid === this.getSelectionContext()?.myUid;
    this.seenDigests.add(digest);
    const entry = {
      receipt, digest,
      issuerUid: receipt?.receiverUid,
      order: ++this.order,
      pendingSince: Date.now(),
      verified: verified === true,
      verifiedRosterId: verified === true ? this.getRosterId() : undefined,
      immediateOwnRead: ownRead,
      restoredOwn,
      checking: false,
      status: 'pending',
      reason: 'materials',
      priority: 'H',
      facts: new Set(receiptRawFacts(receipt)),
    };
    this.entries.set(digest, entry);
    const evaluate = async () => {
      await this._evaluate(entry);
      this._enforceIssuerCap(entry.issuerUid);
      if (!Array.isArray(entry.receipt?.msgRefs)) this._refreshActions();
      this._scheduleExpiry();
      return this.entries.has(digest);
    };
    // Action receipts and locally signed reads are evaluated immediately.
    // Other reads keep their arrival queue and its cooperative yield.
    return Array.isArray(receipt?.msgRefs) && !ownRead ? this._enqueue(evaluate) : evaluate();
  }

  reevaluate() {
    // Recheck action receipts as soon as their target arrives.
    const actions = (async () => {
      if (this.disposed) return;
      const current = [...this.entries.values()].filter((entry) =>
        !Array.isArray(entry.receipt?.msgRefs));
      for (const entry of current) await this._evaluate(entry);
      for (const issuerUid of new Set(current.map((entry) => entry.issuerUid))) {
        this._enforceIssuerCap(issuerUid);
      }
      this._refreshActions();
      this._scheduleExpiry();
    })();
    const reads = this._enqueue(async () => {
      if (this.disposed) return;
      const recheckAccepted = this._updateMaterialState();
      const current = [...this.entries.values()].filter((entry) =>
        Array.isArray(entry.receipt?.msgRefs)).sort((a, b) => a.order - b.order);
      let sliceStart = this.selectionNow();
      for (let i = 0; i < current.length; i++) {
        const entry = current[i];
        if (entry.status !== 'accepted' || recheckAccepted) await this._evaluate(entry);
        if ((i + 1) % 32 === 0 || this.selectionNow() - sliceStart >= 16) {
          await yieldToTimers();
          sliceStart = this.selectionNow();
        }
      }
      for (const issuerUid of new Set(current.map((entry) => entry.issuerUid))) {
        this._enforceIssuerCap(issuerUid);
      }
      this._scheduleExpiry();
    });
    return Promise.all([actions, reads]);
  }

  _updateMaterialState() {
    if (!this.getMaterialState) return true;
    let next;
    try { next = this.getMaterialState(); } catch { this.materialState = null; return true; }
    if (!next || !Array.isArray(next.keys)) { this.materialState = null; return true; }
    const keys = new Set(next.keys);
    const roster = new Set(next.roster || []);
    const window = next.window || null;
    const rosterId = next.rosterId ?? null;
    const previous = this.materialState;
    const rosterChanged = this._syncRosterId() || (!!previous && previous.rosterId !== rosterId);
    const changed = rosterChanged || !previous || keys.size !== previous.keys.size || roster.size !== previous.roster.size
      || [...keys].some((key) => !previous.keys.has(key))
      || [...roster].some((uid) => !previous.roster.has(uid))
      || window?.startMs !== previous.window?.startMs || window?.endMs !== previous.window?.endMs
      || !!next.allowWindowless !== previous.allowWindowless;
    const reduced = rosterChanged || !previous || [...previous.keys].some((key) => !keys.has(key))
      || [...previous.roster].some((uid) => !roster.has(uid))
      || (!previous.window && !!window)
      || (previous.window && (!window || window.startMs > previous.window.startMs
        || window.endMs < previous.window.endMs))
      || (previous.allowWindowless && !next.allowWindowless);
    this.materialState = { keys, roster, window, rosterId, allowWindowless: !!next.allowWindowless };
    if (changed) this.materialVersion = (this.materialVersion || 0) + 1;
    return reduced;
  }

  _syncRosterId() {
    const next = this.getRosterId();
    if (this.rosterId === undefined) { this.rosterId = next; return false; }
    if (this.rosterId === next) return false;
    this.rosterId = next;
    this._forgetRejectedForRoster();
    return true;
  }

  _forgetRejectedForRoster() {
    for (const rejected of this.rejectedDigestsByIssuer.values()) {
      for (const digest of rejected) if (!this.entries.has(digest)) this.seenDigests.delete(digest);
    }
    this.rejectedDigestsByIssuer.clear();
  }

  _enqueue(task) {
    const runTask = async () => {
      if (this.workCount % 32 === 0) this.workSliceStart = this.selectionNow();
      if (++this.workCount % 32 === 0 || this.selectionNow() - this.workSliceStart >= 16) {
        await yieldToTimers();
        this.workSliceStart = this.selectionNow();
      }
      return task();
    };
    const run = this.work.then(runTask, runTask);
    this.work = run.catch(() => {});
    return run;
  }

  _keepsOtherReadWaiting(receipt, rosterUids) {
    return this.otherReadReceiptPendingExpires !== true
      && Array.isArray(receipt?.msgRefs)
      && receipt.receiverUid !== this.getSelectionContext()?.myUid
      && Array.isArray(rosterUids) && rosterUids.length > 0
      && this.isRosterVerified() === true
      && typeof receipt.receiverUid === 'string' && rosterUids.includes(receipt.receiverUid)
      && typeof receipt.senderUid === 'string' && rosterUids.includes(receipt.senderUid);
  }

  async _evaluate(entry) {
    if (this.disposed || !this.entries.has(entry.digest) || entry.checking) return;
    const receipt = entry.receipt;
    const now = Date.now();
    // A locally verified receipt must not expire merely because earlier queue
    // tasks occupied the event loop before its first evaluation.
    if (entry.verified && receipt?.receiverUid === this.getSelectionContext()?.myUid
        && !entry.firstEvaluated) entry.pendingSince = now;
    entry.firstEvaluated = true;
    const clientNow = this.now();
    const chatWindow = this.getChatWindow();
    const rosterUids = this.getRosterUids();
    const rosterVerified = Array.isArray(rosterUids) && rosterUids.length > 0
      && this.isRosterVerified() === true;
    const keepWaiting = this._keepsOtherReadWaiting(receipt, rosterUids);
    // 確定名簿の外の発行者を、窓待ちで上限を占める前に落とす。
    if (rosterVerified) {
      if (typeof receipt.receiverUid !== 'string' || !rosterUids.includes(receipt.receiverUid)) {
        this._drop(entry, 'receiver_not_in_roster');
        return;
      }
      if (Array.isArray(receipt.msgRefs)
          && (typeof receipt.senderUid !== 'string' || !rosterUids.includes(receipt.senderUid))) {
        this._drop(entry, 'sender_not_in_roster');
        return;
      }
    }
    // 開始時にチェーンの確定窓を読み直すまで受理を保留する。
    if (this.requireConfirmedWindow && !chatWindow && !this.allowWindowless()) {
      entry.status = 'pending';
      entry.reason = 'window';
      entry.priority = 'H';
      return;
    }
    if (chatWindow && (receipt.timestamp < chatWindow.startMs || receipt.timestamp > chatWindow.endMs)) {
      this._drop(entry, 'outside_chat_window');
      return;
    }
    if (isClientTimestampAllowed(receipt?.timestamp, clientNow)
        && now > entry.pendingSince + RECEIPT_PENDING_TTL_MS && entry.status === 'pending'
        && !keepWaiting) {
      this._drop(entry, 'pending_expired');
      return;
    }

    if (!Array.isArray(rosterUids) || rosterUids.length === 0) {
      entry.status = 'pending';
      entry.reason = 'roster';
      entry.priority = 'H';
      return;
    }
    if (!rosterVerified) {
      if (typeof receipt.receiverUid !== 'string' || !rosterUids.includes(receipt.receiverUid)) {
        this._drop(entry, 'receiver_not_in_roster');
        return;
      }
      if (Array.isArray(receipt.msgRefs)
          && (typeof receipt.senderUid !== 'string' || !rosterUids.includes(receipt.senderUid))) {
        this._drop(entry, 'sender_not_in_roster');
        return;
      }
    }

    if (entry.verified && entry.verifiedRosterId !== undefined
        && entry.verifiedRosterId !== this.getRosterId()) {
      entry.verified = false;
      entry.verifiedCopy = false;
      entry.notifiedVerified = false;
    }
    if (!entry.verified) {
      entry.checking = true;
      let valid = false;
      const checkingRosterId = this.getRosterId();
      try { valid = await this.verifyReceipt(receipt); } catch { valid = false; }
      entry.checking = false;
      if (!this.entries.has(entry.digest)) return;
      if (checkingRosterId !== this.getRosterId()) return;
      if (!valid) {
        this._drop(entry, 'invalid_signature');
        return;
      }
      entry.verified = true;
      entry.verifiedRosterId = checkingRosterId;
    }
    if (!entry.futureChecked) {
      if (!entry.restoredOwn && !isClientTimestampAllowed(receipt?.timestamp, clientNow)) {
        this.futureMarks?.discard('receipt', receipt);
        this._drop(entry, this.futureMarks?.has('receipt', receipt) ? 'future_timestamp' : 'future_overflow');
        return;
      }
      entry.futureChecked = true;
    }
    if (Array.isArray(receipt.msgRefs) && !entry.notifiedVerified) {
      entry.notifiedVerified = true;
      try { this.onVerifiedReadReceipt(receipt); } catch { /* alert must not stop admission */ }
    }

    let resolved;
    try { resolved = this.resolveReceipt(receipt, rosterUids); } catch { resolved = { state: 'invalid' }; }
    if (!resolved || resolved.state === 'invalid') {
      this._drop(entry, 'invalid_target');
      return;
    }
    if (resolved.state !== 'covered') {
      if (!keepWaiting && Date.now() > entry.pendingSince + RECEIPT_PENDING_TTL_MS) {
        this._drop(entry, 'target_expired');
      } else {
        if (entry.status === 'accepted') {
          entry.status = 'pending';
          try { this.onRemove(receipt, 'target_pending'); } catch { /* noop */ }
        }
        entry.reason = 'target';
        entry.priority = 'H';
      }
      return;
    }

    entry.priority = RECEIPT_TRIM_ORDER.includes(resolved.priority) ? resolved.priority : 'F';
    entry.facts = new Set(Array.isArray(resolved.facts) && resolved.facts.length > 0
      ? resolved.facts
      : receiptRawFacts(receipt));
    if (entry.status !== 'accepted') entry.status = 'eligible';
    entry.reason = null;
    if (Array.isArray(receipt.msgRefs) && entry.status === 'eligible') {
      this._enforceIssuerCap(entry.issuerUid);
      if (this.entries.has(entry.digest)) {
        entry.status = 'accepted';
        try { this.onAccept(receipt); } catch { /* noop */ }
      }
    }
  }

  _refreshActions() {
    const eligible = [...this.entries.values()].filter((entry) =>
      (entry.status === 'eligible' || entry.status === 'accepted')
      && !Array.isArray(entry.receipt?.msgRefs));
    const keep = new Set();
    const keptActions = [];
    for (const entry of eligible.sort((a, b) => a.order - b.order)) {
      const rivals = keptActions.filter((rival) => rival.issuerUid === entry.issuerUid);
      const decision = receiptArrivalContainment(entry.facts, rivals, entry.receipt,
        this.getChatCloseAtMs());
      if (!decision.admit) continue;
      for (const rival of decision.superseded) {
        keep.delete(rival.receipt);
        const at = keptActions.indexOf(rival);
        if (at >= 0) keptActions.splice(at, 1);
      }
      keep.add(entry.receipt);
      keptActions.push(entry);
    }
    for (const entry of eligible) {
      if (!this.entries.has(entry.digest)) continue;
      const selected = keep.has(entry.receipt);
      if (selected && entry.status !== 'accepted') {
        entry.status = 'accepted';
        try { this.onAccept(entry.receipt); } catch { /* noop */ }
      } else if (!selected && entry.status === 'accepted') {
        entry.status = 'eligible';
        try { this.onRemove(entry.receipt, 'reselected'); } catch { /* noop */ }
      }
    }
  }

  _enforceIssuerCap(issuerUid) {
    if (typeof issuerUid !== 'string') return;
    let issuerEntries = [...this.entries.values()].filter((entry) => entry.issuerUid === issuerUid);
    const settled = () => issuerEntries.filter((entry) => !entry.checking).length;
    if (settled() <= this.maxPerIssuer) return;
    // Resolve the admission winner before trimming. A later receipt can be the
    // one carried in the submission when it arrived before the chat deadline.
    const refresh = () => this._refreshActions();
    refresh();
    while (settled() > this.maxPerIssuer) {
      const candidates = issuerEntries.filter((entry) => !entry.checking);
      if (candidates.length === 0) break;
      // 窓待ちなどで署名をまだ確かめていない項目を、新しいものから捨てる。
      let victim = candidates.filter((entry) => entry.status === 'pending' && entry.verified !== true && entry.verifiedCopy !== true)
        .reduce((latest, entry) => !latest || entry.order > latest.order ? entry : latest, null);
      let fallback = false;
      if (!victim) {
        const accepted = new Set();
        for (const entry of issuerEntries) if (entry.status === 'accepted') {
          for (const fact of entry.facts) accepted.add(fact);
        }
        victim = candidates.filter((entry) => entry.status !== 'accepted'
          && entry.facts?.size > 0 && [...entry.facts].every((fact) => accepted.has(fact)))
          .reduce((latest, entry) => !latest || entry.order > latest.order ? entry : latest, null);
        fallback = !victim;
        if (!victim) victim = receiptTrimVictim(candidates);
      }
      if (!victim) break;
      this._drop(victim, 'issuer_cap');
      issuerEntries = issuerEntries.filter((entry) => entry !== victim);
      if (fallback && victim.status === 'accepted' && settled() > this.maxPerIssuer) refresh();
    }
  }

  _drop(entry, reason) {
    if (!entry || !this.entries.delete(entry.digest)) return;
    const retryable = new Set(['outside_chat_window', 'live_stale', 'pending_expired', 'future_overflow',
      'target_expired', 'receiver_not_in_roster', 'sender_not_in_roster', 'invalid_target']);
    const unverifiedCap = reason === 'issuer_cap' && entry.status === 'pending' && entry.verified !== true && entry.verifiedCopy !== true;
    if (unverifiedCap || retryable.has(reason) || (reason === 'invalid_signature' && !this.isRosterVerified())) {
      this.seenDigests.delete(entry.digest);
    } else {
      // 検証済み名簿で落ちた固定入力の再署名費を防ぐ。履歴は発行者ごとに有界。
      const rejected = this.rejectedDigestsByIssuer.get(entry.issuerUid) || new Set();
      rejected.add(entry.digest);
      while (rejected.size > this.maxPerIssuer) {
        const oldest = rejected.values().next().value;
        rejected.delete(oldest);
        if (!this.entries.has(oldest)) this.seenDigests.delete(oldest);
      }
      this.rejectedDigestsByIssuer.set(entry.issuerUid, rejected);
    }
    if (entry.status === 'accepted') {
      try { this.onRemove(entry.receipt, reason); } catch { /* noop */ }
    }
    try { this.onDiscard(entry.receipt, reason, entry.digest); } catch { /* noop */ }
  }

  _scheduleExpiry() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    if (this.disposed) return;
    const rosterUids = this.getRosterUids();
    const pending = [...this.entries.values()].filter((entry) => entry.status === 'pending'
      && entry.reason !== 'window'
      && !this._keepsOtherReadWaiting(entry.receipt, rosterUids));
    if (pending.length === 0) return;
    const at = Math.min(...pending.map((entry) => entry.pendingSince + RECEIPT_PENDING_TTL_MS + 1));
    const delay = Math.max(0, Math.min(at - Date.now(), 2 ** 31 - 1));
    this.timer = setTimeout(() => { void this.reevaluate(); }, delay);
    if (typeof this.timer?.unref === 'function') this.timer.unref();
  }

  dispose() {
    this.disposed = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.entries.clear();
    this.seenDigests.clear();
    this.rejectedDigestsByIssuer.clear();
    this.materialState = null;
  }
}
// メンバー氾濫検知の閾値（§9.4c 密告カウンターUIのアラート発火点・ユニークイベント数）
const FLOOD_ALERT_THRESHOLD = 1000;

// K-S6-003（2026-07-29）: 署名検証に**失敗した**イベントの、リレーごとの許容数。
// 無効イベントは「差出人」ではなく**それを送ってきたリレー**の責任として数える
//（封筒の差出人欄は誰でも書けるので、封蝋を検める前に人を責めてはならない）。
// 超過したリレーは一定時間隔離する＝検証前のCPU防御はこちらが担う。
// 正規リレーは無効イベントを配らないので、正直な運用でここに触れることはない。
const PER_RELAY_INVALID_CAP = 200;

// 隔離の解除までの時間（ユーザー確定 2026-07-29: 30分）。**恒久切断にはしない**理由:
// 署名検証をしていない「正直だが実装の緩いリレー」に対して、攻撃者は外からゴミを投稿するだけで
// 全員にそのリレーを切らせられる。恒久だと、無関係な第三者が P2P 経路を1本ずつ永久に削れてしまう。
// 時限にすれば、攻撃が止まれば自動で復帰し、続いていれば再び隔離されるだけで済む。
// 解除時に無効カウントもリセットする（さもないと復帰直後の1件で即再隔離になる）。
const RELAY_QUARANTINE_MS = 30 * 60 * 1000;

const RELAY_LIST_KEY = 'p2pRelays';

// ============================================================
// ユーティリティ
// ============================================================

const utf8 = (s) => new TextEncoder().encode(s);

function hexToBytesPlain(hex) {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

function bytesToHexPlain(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================
// 鍵導出（§3.1 / §4.1 — バイト正確に固定・§6完全復元が依存）
// ============================================================

// Nostr鍵（C1: cross-protocol key reuse回避のHKDFドメイン分離）。
//   nostrSk = HKDF-SHA256(ikm=signKey(32B), salt=keccak256("bitcoinu/p2p/nostr-key/v2"),
//                         info=utf8(`blockNum=${N}`), L=32)
//   0 または ≥n なら info に `|ctr=${k}`（k=1,2,…）を付けて再試行（k=0は接尾辞なし）。
// deriveNostrKey は p2pKeys.js のブロック単位 v2 を再エクスポートする。

// グループタグ（§3.3）: H(blockNum, groupId) の公開値
export function groupTag(blockNum, groupId) {
  return keccak256(toBytes(`bitcoinu/p2p/group-tag/v1|blockNum=${Number(blockNum)}|groupId=${Number(groupId)}`)).slice(2);
}

// ============================================================
// NIP-01 イベント
// ============================================================

function serializeEvent(pubkey, created_at, kind, tags, content) {
  return JSON.stringify([0, pubkey, created_at, kind, tags, content]);
}

export function buildEvent(skBytes, pubkeyHex, tags, content, createdAtSec = Math.floor(Date.now() / 1000)) {
  const id = bytesToHexPlain(sha256(utf8(serializeEvent(pubkeyHex, createdAtSec, P2P_EVENT_KIND, tags, content))));
  const sig = bytesToHexPlain(schnorr.sign(hexToBytesPlain(id), skBytes));
  return { id, pubkey: pubkeyHex, created_at: createdAtSec, kind: P2P_EVENT_KIND, tags, content, sig };
}

export function verifyEventSignature(ev) {
  try {
    const id = bytesToHexPlain(sha256(utf8(serializeEvent(ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content))));
    if (id !== ev.id) return false;
    return schnorr.verify(hexToBytesPlain(ev.sig), hexToBytesPlain(id), hexToBytesPlain(ev.pubkey));
  } catch (e) {
    return false;
  }
}

// ============================================================
// リレーリスト（ユーザーが設定で置換可能＝運営がデフォルトを全滅させても迂回可能・§3.3/F5）
// ============================================================

export function getRelayList() {
  try {
    const stored = JSON.parse(localStorage.getItem(RELAY_LIST_KEY) || 'null');
    if (Array.isArray(stored) && stored.length > 0) {
      return stored.filter(u => typeof u === 'string' && /^wss?:\/\//.test(u));
    }
  } catch (e) { /* noop */ }
  return DEFAULT_RELAYS;
}

export function saveRelayList(urls) {
  try {
    if (!Array.isArray(urls) || urls.length === 0) {
      localStorage.removeItem(RELAY_LIST_KEY);
    } else {
      localStorage.setItem(RELAY_LIST_KEY, JSON.stringify(urls));
    }
    return true;
  } catch (e) {
    return false;
  }
}

// ラン間汚染の遮断（reset→再ラン対策）。
// P2Pの識別子（groupTag / Nostr鍵）は決定論関数で
// ラン固有のnonceを持たない。resetでブロックを巻き戻す（例: block0再ラン）と同一タグ・同一鍵に
// なり、公開リレーに保持された前ランのイベント（発言→文字数・投票・密告）が再生され混入する。
// 対策: 現ランの START_TIME より前に created_at を持つイベントを全ブロック共通で破棄する。
// reset毎に START_TIME が更新される前提のため、ブロック単位（START_TIME + BLOCK_TIME*n）の
// 計算は不要＝単一カットオフで十分（正規イベントの最速でも準備期間＝応募期間後なので余裕は大）。
// Nostr created_at は秒。START_TIME 未設定/不正なら 0（フィルタ無効＝従来動作）。
// try/catch は復元クライアント（chatgame-tools バンドル）対策: そこでは process が未定義で
// NEXT_PUBLIC_START_TIME も焼き込まれない → 参照が throw する。捕捉して 0 を返し（過去ゲームの
// 全履歴を復元する正しい挙動）、本体アプリ（Next.js が値をインライン置換）ではそのまま効かせる。
export function relaySinceSec() {
  try {
    const ms = Date.parse(process.env.NEXT_PUBLIC_START_TIME);
    return Number.isFinite(ms) ? Math.floor(ms / 1000) : 0;
  } catch (e) {
    return 0;
  }
}

// ============================================================
// RelayPool — 複数リレーへの発行/購読（1つでも生き残れば伝送成立・§3.3）
// ============================================================

const RECONNECT_BASE_MS = 3000;
const RECONNECT_MAX_MS = 60000;
// 履歴は現在のライブ購読とは別の REQ で過去へ送る。リレーが limit を縮めても
// 境界秒を再要求する。履歴のページ数は接続ごとに制限する。
const HISTORY_PAGE_LIMIT = MAX_SEEN_EVENT_IDS;
const MARKED_ID_REQUEST_SIZE = 100;
// 最小 limit=1 のリレーでも、新規 id 1件と境界秒の重複だけの1ページを各件に許す。
// それ以上は per-pubkey キャップ下の正直な履歴ではなく、接続ごとの巡回を止める。
const MAX_HISTORY_PAGES = MAX_SEEN_EVENT_IDS * 2 + 2;
// S3R5-U-WSR-U2 (a): まだ一度も開いていない接続の試みだけを30秒で待つ組から外す（一度開いたリレーは時間で外さない）
export const OWN_HISTORY_CONNECT_WAIT_MS = 30 * 1000;
// S3R5-U-WSR01-A1・S3R5-U-WSR-U1: 自分の取り寄せの開始（待つを押したらその時）から1分で2択
export const OWN_HISTORY_PROMPT_MS = 60 * 1000;
export const OWN_HISTORY_RETRY_BASE_MS = 3000;
export const OWN_HISTORY_RETRY_MAX_MS = 30 * 1000;
export const OWN_HISTORY_PAGE_WATCH_MS = 15 * 1000;

export function ownHistoryComplete(status) {
  return status?.unavailable !== true && Number.isSafeInteger(status?.done) && status.done >= 1
    && Array.isArray(status.waiting) && status.waiting.length === 0;
}

export function ownHistoryPromptKind(status, { operatorHistory = false } = {}) {
  return operatorHistory === true && status?.done === 0 ? 'operator' : 'careful';
}

export function ownHistoryPromptDueAt(status, waitedAt = null) {
  if (!Number.isFinite(status?.startedAt)) return null;
  return Math.max(status.startedAt, Number.isFinite(waitedAt) ? waitedAt : -Infinity) + OWN_HISTORY_PROMPT_MS;
}

export function ownHistoryClosedVerdict(reason) {
  return typeof reason === 'string' && /^(auth-required|restricted|blocked|invalid|unsupported):/.test(reason)
    ? 'refused' : 'retry';
}

export class RelayPool {
  /**
   * @param {Object} opts
   *   relays: string[] — 接続先
   *   tag: string — グループタグ（'#t'フィルタ）
   *   authors: string[] — 検証済み名簿の Nostr pubkey allowlist
   *   ownAuthor: string — 自分の履歴だけを取り寄せる名簿の Nostr 鍵
   *   since: number — created_at 下限（秒・0=無効）。ラン間汚染遮断（relaySinceSec）。
   *   onEvent: (ev, relayUrl) => void — 外側検証済みイベント
   *   onFlood: (pubkeyHex, count) => void — メンバー氾濫検知（§9.4c）
   */
  constructor({ relays, tag, authors, since = 0, onEvent, onFlood = null, onConnectionChange = null,
    onMarkedRequestClosed = null, onMarkedRequestRecovered = null, onHistoryProgress = null, ownAuthor = null,
    now = () => Date.now() }) {
    this.relays = relays;
    this.tag = tag;
    this.authors = new Set(authors || []);
    this.ownAuthor = typeof ownAuthor === 'string' && this.authors.has(ownAuthor) ? ownAuthor : null;
    this.since = Number(since) > 0 ? Math.floor(Number(since)) : 0;
    this.onEvent = onEvent;
    this.onFlood = onFlood;
    this.onConnectionChange = onConnectionChange;
    this.onMarkedRequestClosed = onMarkedRequestClosed;
    this.onMarkedRequestRecovered = onMarkedRequestRecovered;
    this.now = now;
    this.sockets = new Map();      // url -> WebSocket
    this.reconnectAttempts = new Map();
    this.seenIds = new Set();      // イベントid重複排除（リレー間冗長受信・LRU順）
    this._pendingChatIds = new Set(); // 内側の非同期検証中だけ重複を止める
    this._countedIds = new Map(); // 内側が未確定でも外側の検証済み封筒を二重計上しない
    this._seenCreatedAt = new Map(); // 初回の署名検証時刻。既知 id の封筒欄はカーソルに使わない
    this._seenIdsLimit = MAX_SEEN_EVENT_IDS;
    this._seenIdsDropped = 0;
    this.perPubkeyCount = new Map();
    this.floodAlerted = new Set();
    this.perRelayInvalid = new Map();   // K-S6-003: url -> 署名検証に失敗した件数
    this.quarantinedUntil = new Map();  // K-S6-003: url -> 隔離解除時刻（ms・時限）
    // K-S6-003: **検証済みイベントで**キャップを超えたpubkey。以後は署名検証より前に落とす
    // ＝「正しい署名で氾濫させるメンバー」への CPU 防御（§9.4b）を、証拠つきで維持する。
    // 偽造イベントは検証を通らないので、ここに他人を入れることはできない。
    this.verifiedOverCap = new Set();
    this.pendingPublishes = [];    // 全リレー切断中のバッファ
    this.closed = false;
    this.subSerial = 0;
    this.activeSubscriptions = new Map();
    this.historyPages = new Map();
    this.markedIdRequests = new Map(); // EOSE までの ids 指定 REQ だけ
    this.onHistoryProgress = onHistoryProgress;
    this._ownState = new Map();
    this._ownOpened = new Set();
    this.ownHistoryPages = new Map();
    this._ownInflight = new Set();
    this._ownConnectTimers = new Map();
    this._ownRetry = new Map();
    this._ownWatchTimers = new Map();
    this.ownHistoryStartedAt = null;
  }

  connect() {
    if (this.ownAuthor && this.ownHistoryStartedAt === null) this.ownHistoryStartedAt = Date.now();
    for (const url of this.relays) {
      if (this.ownAuthor && !this._ownState.has(url)) {
        this._ownState.set(url, 'connecting');
        const timer = setTimeout(() => {
          this._ownConnectTimers.delete(url);
          if (this._ownState.get(url) === 'connecting') this._setOwnState(url, 'timeout');
        }, OWN_HISTORY_CONNECT_WAIT_MS);
        if (timer && typeof timer.unref === 'function') timer.unref();
        this._ownConnectTimers.set(url, timer);
      }
      this._connectOne(url);
    }
    if (this.ownAuthor) this._emitHistoryProgress();
  }

  refetchHistory(eventIds = new Set()) {
    for (const id of eventIds) { this.seenIds.delete(id); this._seenCreatedAt.delete(id); }
    for (const [url, ws] of this.sockets) {
      if (ws.readyState !== WebSocket.OPEN) continue;
      const old = this.historyPages.get(url);
      if (old) { try { ws.send(JSON.stringify(['CLOSE', old.subId])); } catch { /* noop */ } }
      this.historyPages.delete(url);
      this._requestHistoryPage(ws, url, Math.floor((this.now() + CHAT_WINDOW_CLOCK_SKEW_MS) / 1000));
    }
  }

  refetchMarkedIds(eventIds = new Set(), eventIssuers = new Map()) {
    const ids = [...eventIds].filter((id) => typeof id === 'string').slice(0, MAX_SEEN_EVENT_IDS);
    if (!ids.length || !this.authors.size) return;
    for (const id of ids) { this.seenIds.delete(id); this._seenCreatedAt.delete(id); }
    for (const ws of this.sockets.values()) {
      if (ws.readyState !== WebSocket.OPEN) continue;
      for (let at = 0; at < ids.length; at += MARKED_ID_REQUEST_SIZE) {
        const batch = ids.slice(at, at + MARKED_ID_REQUEST_SIZE);
        const subId = `p2p-marked-${++this.subSerial}`;
        const filter = { kinds: [P2P_EVENT_KIND], '#t': [this.tag],
          authors: [...this.authors], ids: batch };
        if (this.since > 0) filter.since = this.since;
        try {
          ws.send(JSON.stringify(['REQ', subId, filter]));
          this.markedIdRequests.set(subId, { ws, ids: new Set(batch), received: new Set(),
            owners: new Map(batch.filter((id) => eventIssuers.has(id)).map((id) => [id, eventIssuers.get(id)])) });
        } catch { /* reconnect will request normal history */ }
      }
    }
  }

  // K-S6-003: 無効イベントを撒くリレーの時限隔離。切断し、RELAY_QUARANTINE_MS の間つなぎ直さない。
  // 他のリレーへの購読はそのまま＝検閲耐性（経路の冗長性）は残る。
  // ⚠️ 隔離するのは**リレー**であってメンバーではない。メンバーを authors から外すと、
  //    誤検知したときに正直な参加者を恒久的に黙らせる新しいレバーになる。
  _quarantineRelay(url) {
    if (this.isQuarantined(url)) return;
    this.quarantinedUntil.set(url, Date.now() + RELAY_QUARANTINE_MS);
    if (this.ownAuthor && this._ownState.get(url) !== 'done') this._setOwnState(url, 'quarantined');
    console.warn(`P2P relay quarantined for ${RELAY_QUARANTINE_MS / 60000}min (too many invalid events): ${url}`);
    const ws = this.sockets.get(url);
    if (ws) {
      try { ws.close(); } catch (e) { /* noop */ }
      this.sockets.delete(url);
      this.onConnectionChange?.();
    }
    // 期限が来たら自動で復帰させる（攻撃が続いていれば再び隔離されるだけ）。
    // unref: Node（テスト・復元ツールのCLI経路）でこのタイマーがプロセスを掴んで
    // 終了しなくなるのを防ぐ。ブラウザには unref が無いので存在確認してから呼ぶ。
    const timer = setTimeout(() => {
      if (this.closed) return;
      this.quarantinedUntil.delete(url);
      this.perRelayInvalid.delete(url); // 復帰直後の1件で即再隔離にならないようリセット
      this._connectOne(url);
    }, RELAY_QUARANTINE_MS);
    if (timer && typeof timer.unref === 'function') timer.unref();
  }

  // 隔離中か（期限切れは自動的に false。復帰は上の setTimeout が行う）
  isQuarantined(url) {
    const until = this.quarantinedUntil.get(url);
    return until != null && until > Date.now();
  }

  _connectOne(url) {
    if (this.closed || this.sockets.has(url)) return;
    if (this.isQuarantined(url)) { if (this.ownAuthor) this._setOwnState(url, 'quarantined'); return; } // K-S6-003
    let ws;
    let opened = false;
    try {
      ws = new WebSocket(url);
    } catch (e) {
      if (this.ownAuthor && this._ownState.get(url) === 'connecting') this._setOwnState(url, 'unreachable');
      this._scheduleReconnect(url);
      return;
    }
    this.sockets.set(url, ws);
    ws.onopen = () => {
      opened = true;
      this.reconnectAttempts.set(url, 0);
      this.onConnectionChange?.();
      if (this.ownAuthor && !['done', 'noncompliant', 'refused', 'quarantined'].includes(this._ownState.get(url))) {
        this._ownOpened.add(url);
        this._setOwnState(url, 'reading');
        this._clearOwnRetry(url);
        this._requestOwnHistoryPage(ws, url, Math.floor((this.now() + CHAT_WINDOW_CLOCK_SKEW_MS) / 1000));
      }
      this._subscribe(ws);
      this._requestHistoryPage(ws, url, Math.floor((this.now() + CHAT_WINDOW_CLOCK_SKEW_MS) / 1000));
      // 切断中に溜まった発行を流す
      for (const evJson of this.pendingPublishes) {
        try { ws.send(evJson); } catch (e) { /* noop */ }
      }
    };
    ws.onmessage = (msg) => this._handleMessage(msg, url);
    ws.onclose = () => {
      if (this.ownAuthor && !opened && this._ownState.get(url) === 'connecting') this._setOwnState(url, 'unreachable');
      if (this.ownAuthor) {
        for (const [subId, page] of this.ownHistoryPages) {
          if (page.ws === ws) this.ownHistoryPages.delete(subId);
        }
        this._clearOwnWatch(url);
        this._clearOwnRetry(url);
      }
      this.sockets.delete(url);
      if (!this.closed) this.onConnectionChange?.();
      this.activeSubscriptions.delete(ws);
      this.historyPages.delete(url);
      for (const [subId, request] of this.markedIdRequests) {
        if (request.ws === ws) this.markedIdRequests.delete(subId);
      }
      if (!this.closed) this._scheduleReconnect(url);
    };
    ws.onerror = () => { /* oncloseで処理 */ };
  }

  _scheduleReconnect(url) {
    if (this.isQuarantined(url)) return; // K-S6-003
    const attempt = (this.reconnectAttempts.get(url) || 0) + 1;
    this.reconnectAttempts.set(url, attempt);
    const delay = Math.min(RECONNECT_BASE_MS * 2 ** (attempt - 1), RECONNECT_MAX_MS);
    setTimeout(() => this._connectOne(url), delay);
  }

  _subscribe(ws) {
    const filter = { kinds: [P2P_EVENT_KIND], '#t': [this.tag] };
    // ラン間汚染遮断: 現ラン START_TIME 以降のイベントのみ要求（前ランの保持イベントを除外）。
    // リレーは since 遵守を義務付けられないため _handleMessage 側でも created_at を再チェックする。
    if (this.since > 0) filter.since = this.since;
    // R1: authorsフィルタ（リレー側で非メンバーをワイヤに乗る前に落とす・スパム防御の要）。
    // 著者は名簿の鍵に固定する。空集合の場合も無制限購読へ広げない。
    if (this.authors.size === 0) return;
    filter.authors = [...this.authors];
    this.subSerial += 1;
    const subId = `p2p-${this.subSerial}`;
    try {
      const previous = this.activeSubscriptions.get(ws);
      if (previous) ws.send(JSON.stringify(['CLOSE', previous]));
      ws.send(JSON.stringify(['REQ', subId, filter]));
      this.activeSubscriptions.set(ws, subId);
    } catch (e) { /* noop */ }
  }

  _requestHistoryPage(ws, url, until, retryBoundary = false, pageCount = 0) {
    if (this.authors.size === 0 || !Number.isSafeInteger(until)
        || (this.since > 0 && until < this.since) || pageCount >= MAX_HISTORY_PAGES) return 'end';
    const filter = {
      kinds: [P2P_EVENT_KIND], '#t': [this.tag], authors: [...this.authors],
      until, limit: HISTORY_PAGE_LIMIT,
    };
    if (this.since > 0) filter.since = this.since;
    const subId = `p2p-history-${++this.subSerial}`;
    try {
      ws.send(JSON.stringify(['REQ', subId, filter]));
      this.historyPages.set(url, { subId, oldest: null, until, retryBoundary,
        pageCount: pageCount + 1, newIds: 0, knownIds: 0 });
      return 'requested';
    } catch (e) { return 'failed'; /* reconnect will retry */ }
  }

  _handleMessage(msg, url) {
    let parsed;
    try {
      parsed = JSON.parse(msg.data);
    } catch (e) {
      return;
    }
    if (!Array.isArray(parsed)) return;
    if (parsed[0] === 'EOSE') {
      const marked = this.markedIdRequests.get(parsed[1]);
      if (marked) {
        if (marked.ws !== this.sockets.get(url)) return;
        this.markedIdRequests.delete(parsed[1]);
        try { marked.ws.send(JSON.stringify(['CLOSE', parsed[1]])); } catch { /* noop */ }
        return;
      }
      if (this.ownAuthor) {
        const own = this.ownHistoryPages.get(parsed[1]);
        if (own && own.url === url && own.ws === this.sockets.get(url)) {
          this.ownHistoryPages.delete(parsed[1]);
          this._clearOwnWatch(url);
          try { own.ws.send(JSON.stringify(['CLOSE', own.subId])); } catch { /* noop */ }
          if (own.oldest === null) this._noteOwnHistoryDone(url);
          else {
            const until = own.newIds > 0 ? own.oldest : own.retryBoundary ? own.until - 1 : own.oldest;
            const retryBoundary = own.newIds > 0 || !own.retryBoundary;
            const result = this._requestOwnHistoryPage(own.ws, url, until, retryBoundary, own.pageCount);
            if (result === 'end') this._noteOwnHistoryDone(url);
            else if (result === 'exhausted') this._setOwnState(url, 'noncompliant');
          }
          return;
        }
      }
      const page = this.historyPages.get(url);
      if (!page || parsed[1] !== page.subId) return;
      this.historyPages.delete(url);
      const ws = this.sockets.get(url);
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      try { ws.send(JSON.stringify(['CLOSE', page.subId])); } catch (e) { /* noop */ }
      if (page.oldest === null) {
        return;
      } // カーソルに使える履歴が0件なら終了
      if (page.newIds > 0) {
        // 同じ秒を含めて再要求し、次ページでまだ見ていない id を取り込む。
        this._requestHistoryPage(ws, url, page.oldest, true, page.pageCount);
      } else if (page.retryBoundary) {
        // 境界秒に新しい id が無ければ、その秒を取り切ったとして前へ進む。
        this._requestHistoryPage(ws, url, page.until - 1, false, page.pageCount);
      } else {
        // 全件既知でも境界秒に未取得の id があり得る。1回だけ同じ秒を再要求する。
        this._requestHistoryPage(ws, url, page.oldest, true, page.pageCount);
      }
      return;
    }
    if (parsed[0] === 'CLOSED') {
      const marked = this.markedIdRequests.get(parsed[1]);
      if (marked) {
        if (marked.ws !== this.sockets.get(url)) return;
        this.markedIdRequests.delete(parsed[1]);
        const missing = new Map([...marked.owners].filter(([id]) => !marked.received.has(id)));
        if (missing.size) this.onMarkedRequestClosed?.(missing);
        return;
      }
      if (this.ownAuthor) {
        const own = this.ownHistoryPages.get(parsed[1]);
        if (own && own.url === url && own.ws === this.sockets.get(url)) {
          this.ownHistoryPages.delete(parsed[1]);
          this._clearOwnWatch(url);
          if (ownHistoryClosedVerdict(parsed[2]) === 'refused') this._setOwnState(url, 'refused');
          else this._scheduleOwnRetry(own);
          return;
        }
      }
      const page = this.historyPages.get(url);
      if (!page || parsed[1] !== page.subId) return;
      this.historyPages.delete(url);
      return;
    }
    if (parsed[0] !== 'EVENT') return;
    const ev = parsed[2];
    if (!ev || typeof ev !== 'object') return;
    const marked = this.markedIdRequests.get(parsed[1]);
    if (marked && !marked.ids.has(ev.id)) return;

    let ownPage;
    if (this.ownAuthor) {
      const candidate = this.ownHistoryPages.get(parsed[1]);
      if (candidate && candidate.url === url && candidate.ws === this.sockets.get(url)) {
        ownPage = candidate;
        if (ev.pubkey !== this.ownAuthor || ev.kind !== P2P_EVENT_KIND
            || !Array.isArray(ev.tags) || !ev.tags.some(tag => Array.isArray(tag) && tag[0] === 't' && tag[1] === this.tag)) {
          this.ownHistoryPages.delete(candidate.subId);
          this._clearOwnWatch(url);
          try { candidate.ws.send(JSON.stringify(['CLOSE', candidate.subId])); } catch { /* noop */ }
          this._setOwnState(url, 'noncompliant');
          return;
        }
        candidate.lastActivityAt = Date.now();
        this._armOwnWatch(candidate);
      }
    }
    if (typeof ev.pubkey !== 'string') return;
    const page = ownPage || this.historyPages.get(url);
    // 上限後の既知 id はタグ走査より前に捨てる。リレーごとのページだけを縛る。
    if (page && parsed[1] === page.subId && page.knownIds >= HISTORY_PAGE_LIMIT
        && this.seenIds.has(ev.id)) return;

    // ラン間汚染遮断（sinceの念押し・§reset）: 非準拠リレーが下限を無視して返す前ランの
    // 保持イベントをここで確実に破棄する。created_at 欠落/型不正も破棄（正規イベントは必ず持つ）。
    const rememberedAt = this._seenCreatedAt.get(ev.id) ?? this._countedIds.get(ev.id);
    const cursorTime = rememberedAt ?? ev.created_at;
    if (this.since > 0 && (typeof cursorTime !== 'number' || cursorTime < this.since)) return;

    // §3.3 3層防御のクライアント層:
    // 1) 安価な著者チェック（O(1)・高コストなSchnorr検証の前）
    if (!this.authors.has(ev.pubkey)) return;
    if (ev.kind !== P2P_EVENT_KIND || !Array.isArray(ev.tags)
        || !ev.tags.some(tag => Array.isArray(tag) && tag[0] === 't' && tag[1] === this.tag)) return;
    // 1b) 検証済みキャップ超過のpubkeyは署名も件数も再確認しない。
    //     履歴ではそのリレーのページだけを前へ送る（他リレーのカーソルには効かない）。
    if (this.verifiedOverCap.has(ev.pubkey)) {
      if (page && parsed[1] === page.subId && Number.isSafeInteger(ev.created_at)
          && ev.created_at <= page.until) {
        page.oldest = page.oldest === null ? ev.created_at : Math.min(page.oldest, ev.created_at);
      }
      return;
    }
    // 2) イベントid重複排除（複数リレーからの冗長受信・再接続時の履歴再送）。
    //    per-pubkeyカウントより先に行う＝カウントはユニークイベントのみ。
    //    旧実装は重複排除前に数えていたため「5リレー配信×履歴再送」で正常プレイが
    //    氾濫閾値を踏む誤検知があった。Set.has は O(1)。既知 id は初回検証時刻を再利用する。
    if (this._pendingChatIds.has(ev.id)) {
      // 内側の非同期判定中でも、別の履歴ページに再配送された同じ id は
      // 最初に検証した封筒の時刻でカーソルを進める。
      if (page && parsed[1] === page.subId && page.knownIds < HISTORY_PAGE_LIMIT) {
        page.knownIds += 1;
        if (Number.isSafeInteger(rememberedAt) && rememberedAt <= page.until) {
          page.oldest = page.oldest === null ? rememberedAt : Math.min(page.oldest, rememberedAt);
        }
      }
      return;
    }
    if (this.seenIds.has(ev.id)) {
      if (page && parsed[1] === page.subId) {
        // EOSE を返さないリレーが送り続けても、ページ limit 件より先は捨てる。
        // リレーごとの予算なので、他リレーや送り手の予算を消費しない。
        if (page.knownIds >= HISTORY_PAGE_LIMIT) return;
        page.knownIds += 1;
        if (Number.isSafeInteger(rememberedAt) && rememberedAt <= page.until) {
          page.oldest = page.oldest === null ? rememberedAt : Math.min(page.oldest, rememberedAt);
        }
      }
      // Setの挿入順をLRU順として使う。重複受信されたidは直近側へ移し、
      // 複数リレー間で今まさに再送されているイベントを優先して保持する。
      this.seenIds.delete(ev.id);
      this.seenIds.add(ev.id);
      return;
    }
    // 3) 外側Schnorr署名検証（非準拠リレーへの念押し）。
    //    seenIds への追加は検証成功後のまま（検証前に追加すると「正しいid＋壊れた署名」を
    //    先行送信して本物のイベントを封殺できる検閲ベクタになるため）
    //
    // K-S6-003 是正（2026-07-29）: **検証をカウントより前に置く**。
    // 旧実装は per-pubkey のカウントとキャップを検証**前**に行っていた。封筒の差出人欄
    // （ev.pubkey）は誰でも書けるので、悪意あるリレーは「標的の pubkey ＋ 壊れた署名 ＋
    // 毎回違う id」のイベントを流すだけで、
    //   ・警告閾値で「⚠ ネットワーク攻撃を検知 — 密告を推奨」を**正直な標的**に表示させ
    //   ・1,200件で標的の**本物のイベントを全リレーぶん**（カウンタはpool共有）捨てさせられた
    // ＝検閲対策であるP2P経路を、標的だけ選んで無力化できた。
    // 「被害者署名は偽造不可＝冤罪アラート不可」という設計前提（§9.4c）は、
    // 署名を偽造せずとも成立してしまうため崩れていた。
    if (!verifyEventSignature(ev)) {
      // 4) 検証前のCPU防御は「送ってきたリレー」に帰属させる（人ではなく経路を責める）。
      //    閾値を超えたリレーは隔離して再接続もしない。
      const bad = (this.perRelayInvalid.get(url) || 0) + 1;
      this.perRelayInvalid.set(url, bad);
      if (bad > PER_RELAY_INVALID_CAP) this._quarantineRelay(url);
      return;
    }
    const alreadyCounted = this._countedIds.has(ev.id);
    if (!alreadyCounted) {
      this._countedIds.set(ev.id, ev.created_at);
      while (this._countedIds.size > this._seenIdsLimit) {
        this._countedIds.delete(this._countedIds.keys().next().value);
      }
    }
    // 履歴カーソルは初回検証済みの新規 id、既知 id の記録時刻、
    // キャップ超過の送り手の封筒時刻で、そのリレーのページだけを進める。
    if (page && parsed[1] === page.subId && Number.isSafeInteger(ev.created_at)
        && ev.created_at <= page.until) {
      page.oldest = page.oldest === null ? ev.created_at : Math.min(page.oldest, ev.created_at);
      if (alreadyCounted) page.knownIds += 1;
      else page.newIds += 1;
    }

    // 5) per-pubkeyキャップ（§9.4b: メンバー氾濫のCPU防御）＋氾濫検知（§9.4c）。
    //    **署名検証に合格したイベントだけ**を数える＝そのメンバーが本当に発行した証拠がある。
    if (!alreadyCounted) {
      const count = (this.perPubkeyCount.get(ev.pubkey) || 0) + 1;
      this.perPubkeyCount.set(ev.pubkey, count);
      if (count === FLOOD_ALERT_THRESHOLD && this.onFlood && !this.floodAlerted.has(ev.pubkey)) {
        this.floodAlerted.add(ev.pubkey);
        try { this.onFlood(ev.pubkey, count); } catch (e) { /* noop */ }
      }
      if (count > PER_PUBKEY_EVENT_CAP) {
        this.verifiedOverCap.add(ev.pubkey); // 以後は 1b) で検証前に落とす
        this._rememberSeenId(ev.id, ev.created_at);
        return;
      }
    }

    try {
      const result = this.onEvent(ev, url);
      if (result && typeof result.then === 'function') {
        const pending = Promise.resolve(result);
        if (this.ownAuthor && ev.pubkey === this.ownAuthor) {
          this._ownInflight.add(pending);
          const remove = () => this._ownInflight.delete(pending);
          pending.then(remove, remove);
        }
        this._pendingChatIds.add(ev.id);
        pending.then((outcome) => {
          if (outcome) {
            for (const request of this.markedIdRequests.values()) {
              if (request.ids.has(ev.id)) request.received.add(ev.id);
            }
            marked?.received.add(ev.id);
            this.onMarkedRequestRecovered?.(ev.id);
          }
          this._rememberSeenId(ev.id, ev.created_at);
        }).catch((e) => console.error('relay onEvent error:', e))
          .finally(() => this._pendingChatIds.delete(ev.id));
      } else {
        if (result) {
          for (const request of this.markedIdRequests.values()) {
            if (request.ids.has(ev.id)) request.received.add(ev.id);
          }
          marked?.received.add(ev.id);
          this.onMarkedRequestRecovered?.(ev.id);
        }
        this._rememberSeenId(ev.id, ev.created_at);
      }
    } catch (e) {
      console.error('relay onEvent error:', e);
    }
  }

  // 署名検証済みidだけをLRUへ入れる。上限到達時は最古のidを追い出し、
  // 「打ち切ったのに件数が出ない」を避けるため追い出し数を必ず加算する。
  _rememberSeenId(id, createdAt) {
    if (!this._seenCreatedAt.has(id)) this._seenCreatedAt.set(id, createdAt);
    if (this.seenIds.delete(id)) this.seenIds.add(id);
    else this.seenIds.add(id);
    while (this.seenIds.size > this._seenIdsLimit) {
      const oldest = this.seenIds.values().next().value;
      this.seenIds.delete(oldest);
      this._seenCreatedAt.delete(oldest);
      this._seenIdsDropped += 1;
    }
  }

  // 上限到達をUI／診断コード／回帰テストから観測するための読み取り専用スナップショット。
  getBudgetStats() {
    return {
      seenIds: {
        size: this.seenIds.size,
        limit: this._seenIdsLimit,
        dropped: this._seenIdsDropped,
      },
    };
  }

  _setOwnState(url, next) {
    if (!this.ownAuthor || this.closed) return;
    const current = this._ownState.get(url);
    if (['done', 'noncompliant', 'refused', 'quarantined'].includes(current) || current === next) return;
    this._ownState.set(url, next);
    if (next !== 'connecting' && next !== 'reading') {
      const timer = this._ownConnectTimers.get(url);
      if (timer !== undefined) clearTimeout(timer);
      this._ownConnectTimers.delete(url);
    }
    if (next === 'reading') {
      const timer = this._ownConnectTimers.get(url);
      if (timer !== undefined) clearTimeout(timer);
      this._ownConnectTimers.delete(url);
    }
    this._emitHistoryProgress();
  }

  _requestOwnHistoryPage(ws, url, until, retryBoundary = false, pageCount = 0) {
    if (!Number.isSafeInteger(until) || (this.since > 0 && until < this.since)) return 'end';
    if (pageCount >= MAX_HISTORY_PAGES) return 'exhausted';
    const filter = { kinds: [P2P_EVENT_KIND], '#t': [this.tag], authors: [this.ownAuthor],
      until, limit: HISTORY_PAGE_LIMIT };
    if (this.since > 0) filter.since = this.since;
    const subId = `p2p-own-${++this.subSerial}`;
    try {
      ws.send(JSON.stringify(['REQ', subId, filter]));
      const page = { subId, url, ws, oldest: null, until, retryBoundary, pageCount: pageCount + 1,
        newIds: 0, knownIds: 0, lastActivityAt: Date.now() };
      this.ownHistoryPages.set(subId, page);
      this._armOwnWatch(page);
      return 'requested';
    } catch (e) { return 'failed'; }
  }

  _clearOwnWatch(url) {
    const timer = this._ownWatchTimers.get(url);
    if (timer !== undefined) clearTimeout(timer);
    this._ownWatchTimers.delete(url);
  }

  _armOwnWatch(page) {
    this._clearOwnWatch(page.url);
    const timer = setTimeout(() => {
      this._ownWatchTimers.delete(page.url);
      if (this.closed || this.ownHistoryPages.get(page.subId) !== page
          || this.sockets.get(page.url) !== page.ws || page.ws.readyState !== WebSocket.OPEN) return;
      if (Date.now() - page.lastActivityAt < OWN_HISTORY_PAGE_WATCH_MS) {
        this._armOwnWatch(page);
        return;
      }
      this.ownHistoryPages.delete(page.subId);
      try { page.ws.send(JSON.stringify(['CLOSE', page.subId])); } catch { /* noop */ }
      this._requestOwnHistoryPage(page.ws, page.url, page.until, page.retryBoundary, page.pageCount - 1);
    }, OWN_HISTORY_PAGE_WATCH_MS);
    if (timer && typeof timer.unref === 'function') timer.unref();
    this._ownWatchTimers.set(page.url, timer);
  }

  _clearOwnRetry(url) {
    const retry = this._ownRetry.get(url);
    if (retry?.timer !== undefined && retry.timer !== null) clearTimeout(retry.timer);
    this._ownRetry.delete(url);
  }

  _scheduleOwnRetry(page) {
    const prior = this._ownRetry.get(page.url);
    if (prior?.timer !== undefined && prior.timer !== null) clearTimeout(prior.timer);
    const attempt = prior?.attempt || 0;
    const delay = Math.min(OWN_HISTORY_RETRY_BASE_MS * 2 ** attempt, OWN_HISTORY_RETRY_MAX_MS);
    const timer = setTimeout(() => {
      this._ownRetry.set(page.url, { attempt: attempt + 1, timer: null });
      if (this.closed || this._ownState.get(page.url) !== 'reading'
          || this.sockets.get(page.url) !== page.ws || page.ws.readyState !== WebSocket.OPEN) return;
      this._requestOwnHistoryPage(page.ws, page.url, page.until, page.retryBoundary, page.pageCount - 1);
    }, delay);
    if (timer && typeof timer.unref === 'function') timer.unref();
    this._ownRetry.set(page.url, { attempt: attempt + 1, timer });
  }

  async _noteOwnHistoryDone(url) {
    const inflight = [...this._ownInflight];
    await Promise.allSettled(inflight);
    if (!this.closed && this._ownState.get(url) === 'reading') this._setOwnState(url, 'done');
  }

  _emitHistoryProgress() {
    if (this.closed) return;
    try { this.onHistoryProgress?.(this.historyStatus()); }
    catch (e) { console.error('relay history progress error:', e); }
  }

  historyStatus() {
    const urls = this.ownAuthor ? [...new Set(this.relays)] : [];
    return { startedAt: this.ownAuthor ? this.ownHistoryStartedAt : null,
      done: urls.filter((url) => this._ownState.get(url) === 'done').length,
      waiting: urls.filter((url) => ['connecting', 'reading'].includes(this._ownState.get(url))),
      states: Object.fromEntries(urls.filter((url) => this._ownState.has(url)).map((url) => [url, this._ownState.get(url)])) };
  }

  publish(event) {
    const json = JSON.stringify(['EVENT', event]);
    let sent = 0;
    for (const ws of this.sockets.values()) {
      if (ws.readyState === WebSocket.OPEN) {
        try { ws.send(json); sent++; } catch (e) { /* noop */ }
      }
    }
    if (sent === 0) {
      this.pendingPublishes.push(json);
      if (this.pendingPublishes.length > 200) this.pendingPublishes.shift();
    }
    return sent;
  }

  // 各リレーの接続状態スナップショット（UI表示用・非リアクティブなので呼出側がポーリングする）
  getStatus() {
    return this.relays.map(url => {
      // K-S6-003: 隔離中は「切断中」と区別して見せる。利用者が「経路が減っていること」に
      // 気づけないと、運営の検閲に対する逃げ道が静かに細っていても分からない
      //（RelaySettings で自分のリレーを追加できる＝気づけば対処できる）。
      if (this.isQuarantined(url)) {
        return { url, status: 'quarantined', quarantinedUntil: this.quarantinedUntil.get(url) };
      }
      const ws = this.sockets.get(url);
      let status = 'disconnected'; // 切断中（onclose後は再接続待ちでsocketsから消える）
      if (ws) {
        if (ws.readyState === WebSocket.OPEN) status = 'connected';
        else if (ws.readyState === WebSocket.CONNECTING) status = 'connecting';
      }
      return { url, status };
    });
  }

  close() {
    this.closed = true;
    for (const [url, ws] of this.sockets) {
      const subId = this.activeSubscriptions.get(ws);
      if (subId && ws.readyState === WebSocket.OPEN) {
        try { ws.send(JSON.stringify(['CLOSE', subId])); } catch (e) { /* noop */ }
      }
      const page = this.historyPages.get(url);
      if (page && ws.readyState === WebSocket.OPEN) {
        try { ws.send(JSON.stringify(['CLOSE', page.subId])); } catch (e) { /* noop */ }
      }
      for (const own of this.ownHistoryPages.values()) {
        if (own.ws === ws && ws.readyState === WebSocket.OPEN) {
          try { ws.send(JSON.stringify(['CLOSE', own.subId])); } catch { /* noop */ }
        }
      }
      for (const [subId, request] of this.markedIdRequests) {
        if (request.ws === ws && ws.readyState === WebSocket.OPEN) {
          try { ws.send(JSON.stringify(['CLOSE', subId])); } catch { /* noop */ }
        }
      }
      try { ws.close(); } catch (e) { /* noop */ }
    }
    this.sockets.clear();
    this.activeSubscriptions.clear();
    this.historyPages.clear();
    this.markedIdRequests.clear();
    this.ownHistoryPages.clear();
    for (const timer of this._ownConnectTimers.values()) clearTimeout(timer);
    this._ownConnectTimers.clear();
    for (const timer of this._ownWatchTimers.values()) clearTimeout(timer);
    this._ownWatchTimers.clear();
    for (const retry of this._ownRetry.values()) if (retry.timer !== null) clearTimeout(retry.timer);
    this._ownRetry.clear();
  }
}

// ============================================================
// GameRelayChannel — ゲーム1グループ分のリレーチャネル（§3〜§4・§6）
// ============================================================

export class GameRelayChannel {
  /**
   * @param {Object} opts
   *   signKey, blockNum, groupId, uid
   *   members: [{uid, bAddr}] — 検証済み配布順ロスター（Nostr 鍵は bAddr 内）
   *   verifyInnerSignature: async (type, inner) => boolean — §2.6署名検証（呼出側=フックが提供）
   *   onChat: (inner) => void
   *   onActionsChange / onReceiptsChange / onFactsChange — v3.2 観測フック
   *   onFlood: (uid|null, pubkey) => void — 氾濫検知（§9.4c 密告カウンターUI）
   *   onSelfAction: (type, inner) => void — 自分の別クライアント発行の観測（相互ロック用・観測専用）
   *   hasOwnRecord: (inner) => boolean — 公式の自分の行動の控え。true のときだけエコーを読み飛ばす（S3R5-U-RXF1b）。省略時は従来どおり。
   *   sinceSec: number — created_at 下限（秒）の明示指定。未指定なら relaySinceSec()（本体アプリの
   *     NEXT_PUBLIC_START_TIME）。復元クライアントは process/env を持たないため、チェーン権威の
   *     START_TIME（Evidence.START_TIME 秒）をここに渡してラン間汚染を同じく遮断する。
   */
  constructor(opts) {
    this.signKey = opts.signKey;
    this.blockNum = Number(opts.blockNum);
    this.groupId = Number(opts.groupId);
    this.uid = opts.uid;
    this.members = opts.members;
    this.verifyInnerSignature = opts.verifyInnerSignature;
    this.getMaxMsgChars = opts.getMaxMsgChars || (() => GUEST_PINNED_RULES.maxMsgChars);
    this.onChat = opts.onChat || (() => {});
    this.isAccepted = opts.isAccepted || (() => false);
    this.onFlood = opts.onFlood || (() => {});
    this.onConnectionChange = opts.onConnectionChange || null;
    this.onHistoryProgress = opts.onHistoryProgress || null;
    this.onPersistenceError = opts.onPersistenceError || (() => {});
    // created_at 下限（秒）の明示指定。null なら start() で relaySinceSec() にフォールバック。
    this.sinceSec = opts.sinceSec != null ? Math.floor(Number(opts.sinceSec)) : null;

    this.tag = groupTag(this.blockNum, this.groupId);
    const { sk, pubkey } = deriveNostrKey(this.signKey, this.blockNum);
    this.nostrSk = sk;
    this.nostrPubkey = pubkey;
    this.pool = null;
    this.p2pUnavailable = false;
    this.validNostrByUid = new Map();
    this.onRosterKeyInvalid = opts.onRosterKeyInvalid || (() => {});

    // v3.2: リレー受信の投票・密告発信（signKey署名済み・対象は自己暗号化）:
    //   uid → { vote: action|null, reports: [action,...] }
    // 観測分は提出物の observed セクションへ union される（検証⑥の不正証拠＋WS検閲耐性）。
    // localStorage から復元＝リロード後も観測を保持。
    this.relayActions = this._loadJson(this._actionsStoreKey(), {});
    // Own actions have a small, independent record. The shared observation
    // cache can be overwritten by another tab or fill with a peer's traffic.
    const ownActions = this._loadJson(this._selfActionsStoreKey(), { vote: null, voteExtras: [], reports: [] });
    if (ownActions && typeof ownActions === 'object') {
      const slot = this.relayActions[this.uid] || { vote: null, reports: [] };
      const allVotes = [slot.vote, ...(slot.voteExtras || []), ownActions.vote,
        ...(ownActions.voteExtras || [])].filter((action) => action?.signature);
      const votes = [...new Map(allVotes.map((action) => [action.signature, action])).values()];
      const reports = [...new Map([...(slot.reports || []), ...(ownActions.reports || [])]
        .filter((action) => action?.signature).map((action) => [action.signature, action])).values()];
      if (votes.length || reports.length) this.relayActions[this.uid] = {
        vote: votes[0] || null, voteExtras: votes.slice(1, MAX_OBSERVED_ACTIONS_PER_ACTOR),
        reports: reports.slice(0, MAX_OBSERVED_ACTIONS_PER_ACTOR),
      };
    }
    // v3.2: リレー受信の受領証明（既読バッチ＋action受領・signKey署名済み）:
    //   digest → receipt。旧署名鍵ストアも値から再計算し、改変写しに本物の枠を渡さない。
    this.relayReceipts = Object.fromEntries(Object.values(this._loadJson(this._receiptsStoreKey(), {}))
      .map((receipt) => [receiptIdentityDigest(receipt), receipt]).filter(([digest]) => digest));
    const storedReceiptCounts = new Map();
    for (const [digest, receipt] of Object.entries(this.relayReceipts)) {
      const issuer = receipt?.receiverUid;
      const count = (storedReceiptCounts.get(issuer) || 0) + 1;
      storedReceiptCounts.set(issuer, count);
      if (count > MAX_RECEIPTS_PER_ISSUER) delete this.relayReceipts[digest];
    }
    // ラン間汚染遮断（localStorage復元経路）: ストアキーは block/group/uid スコープのため、
    // リセット再ラン（決定論鍵で uid が前ランと一致）ではキーが衝突し前ランの観測が復活する。
    // ライブ受信の since カットオフと同じ基準（START_TIME）で復元分を要素単位で篩う。
    this._pruneStaleObservations();
    this._relayReceiptCounts = new Map();
    for (const receipt of Object.values(this.relayReceipts)) {
      const issuer = receipt?.receiverUid;
      this._relayReceiptCounts.set(issuer, (this._relayReceiptCounts.get(issuer) || 0) + 1);
    }
    // 投票/密告の事実（UI可視化用・relayActionsから導出）: uid → { voted:bool, reportCount:int }
    this.relayFacts = {};
    this.onFactsChange = opts.onFactsChange || (() => {});
    this.onActionsChange = opts.onActionsChange || (() => {});
    this.onReceiptsChange = opts.onReceiptsChange || (() => {});
    this.getChatWindow = opts.getChatWindow || (() => null);
    this.now = opts.now || (() => Date.now());
    this.futureMarks = opts.futureMarks || null;
    // 自分の別クライアント（同一signKey・例: game.js↔リカバリーツール）が P2P に発行した
    // 自己アクションの観測フック。採点ローカル正典には混ぜず、UIが「別ツールで既に提出済み」を
    // 客観検知するためだけに検証済みinnerを渡す（サーバーの嘘で締め出されない相互ロック）。
    this.onSelfAction = opts.onSelfAction || null;
    this.hasOwnRecord = typeof opts.hasOwnRecord === 'function' ? opts.hasOwnRecord : null;
    // 在席通知（v3.3追補）: onPresence(uid, state, timestamp)。UI表示専用（採点に影響しない）。
    this.onPresence = opts.onPresence || (() => {});
    this.presenceByUid = {}; // uid -> { state, timestamp }（最新のみ保持・永続化しない）
    // このチャネルが発行した inner の署名（自セッションのエコーを onSelfAction から除外するため）。
    this._ownPublishedSigs = new Set(this._loadJson(this._ownSigsStoreKey(), []));
    // リロード時: 復元した観測アクション/受領証明を即時にアプリへ反映。
    if (Object.keys(this.relayActions).length > 0) {
      this._recomputeFacts();
      try { this.onActionsChange(this.getRelayActionsRaw()); } catch (e) { /* noop */ }
    }
    if (Object.keys(this.relayReceipts).length > 0) {
      try { this.onReceiptsChange(this.getRelayReceipts(), { verified: false, restored: true }); } catch (e) { /* noop */ }
    }
  }

  // 自セッションが発行したアクション署名（リロードをまたぐ自己エコー抑止＝相互ロック誤爆防止）。
  _ownSigsStoreKey() { return `p2pOwnSigs_${this.blockNum}_group${this.groupId}_user${this.uid}`; }
  // リレー受信済みの投票・密告発信/受領証明（リロード後も観測を保持）。
  _actionsStoreKey() { return `p2pRelayActions_${this.blockNum}_group${this.groupId}_user${this.uid}`; }
  _selfActionsStoreKey() { return `p2pSelfActions_${this.blockNum}_group${this.groupId}_user${this.uid}`; }
  _receiptsStoreKey() { return `p2pRelayReceipts_${this.blockNum}_group${this.groupId}_user${this.uid}`; }
  // localStorage 復元した relayActions/relayReceipts から前ラン（START_TIME より古い timestamp）の
  // 要素を破棄する。ライブ受信は RelayPool の since ゲートで守られているが、復元経路は素通り
  // だったため、リセット再ランで前ランの密告/既読が復活し件数が水増しされていた（§reset）。
  // カットオフ未設定（sinceSec 明示なし かつ START_TIME env なし＝relaySinceSec()=0）は従来どおり全採用。
  _pruneStaleObservations() {
    const cutoffSec = this.sinceSec != null ? this.sinceSec : relaySinceSec();
    if (!(cutoffSec > 0)) return;
    const cutoffMs = cutoffSec * 1000;
    const stale = (ts) => !(typeof ts === 'number' && ts >= cutoffMs);
    let changed = false;
    for (const [u, slot] of Object.entries(this.relayActions)) {
      if (!slot || typeof slot !== 'object') { delete this.relayActions[u]; changed = true; continue; }
      if (slot.vote && stale(slot.vote.timestamp)) { slot.vote = null; changed = true; }
      if (Array.isArray(slot.voteExtras)) {
        const fresh = slot.voteExtras.filter(a => a && !stale(a.timestamp));
        if (fresh.length !== slot.voteExtras.length) changed = true;
        if (fresh.length > 0) slot.voteExtras = fresh; else delete slot.voteExtras;
      }
      if (Array.isArray(slot.reports)) {
        const fresh = slot.reports.filter(a => a && !stale(a.timestamp));
        if (fresh.length !== slot.reports.length) { slot.reports = fresh; changed = true; }
      }
      if (!slot.vote && !(slot.voteExtras && slot.voteExtras.length) && !(slot.reports && slot.reports.length)) {
        delete this.relayActions[u];
        changed = true;
      }
    }
    for (const [sig, rc] of Object.entries(this.relayReceipts)) {
      if (!rc || stale(rc.timestamp)) { delete this.relayReceipts[sig]; changed = true; }
    }
    if (changed) {
      // 掃除後の内容を書き戻す＝次回リロードで再汚染しない（永続的に浄化）
      this._saveJson(this._actionsStoreKey(), this.relayActions);
      this._saveOwnActions();
      this._saveReceiptCache();
    }
  }

  _loadJson(key, fallback) {
    try { return JSON.parse(localStorage.getItem(key) || 'null') ?? fallback; } catch (e) { return fallback; }
  }
  _saveJson(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
      return true;
    } catch (error) {
      try { this.onPersistenceError({ key, error }); } catch { /* UI callback failure */ }
      return false;
    }
  }
  _saveOwnActions() {
    const key = this._selfActionsStoreKey();
    const stored = this._loadJson(key, { vote: null, voteExtras: [], reports: [] });
    const current = this.relayActions[this.uid] || { vote: null, reports: [] };
    const cutoffSec = this.sinceSec != null ? this.sinceSec : relaySinceSec();
    const cutoffMs = cutoffSec > 0 ? cutoffSec * 1000 : 0;
    const fresh = (action) => action?.signature && (!cutoffMs
      || (typeof action.timestamp === 'number' && action.timestamp >= cutoffMs));
    const votes = [...new Map([stored.vote, ...(stored.voteExtras || []), current.vote,
      ...(current.voteExtras || [])].filter(fresh)
      .map((action) => [action.signature, action])).values()];
    const reports = [...new Map([...(stored.reports || []), ...(current.reports || [])]
      .filter(fresh).map((action) => [action.signature, action])).values()];
    const merged = { vote: votes[0] || null,
      voteExtras: votes.slice(1, MAX_OBSERVED_ACTIONS_PER_ACTOR),
      reports: reports.slice(0, MAX_OBSERVED_ACTIONS_PER_ACTOR) };
    this.relayActions[this.uid] = merged;
    return this._saveJson(key, merged);
  }
  _hasStoredOwnAction(signature) {
    const slot = this._loadJson(this._selfActionsStoreKey(), null);
    return !!slot && [slot.vote, ...(slot.voteExtras || []), ...(slot.reports || [])]
      .some((action) => action?.signature === signature);
  }
  _ownRecordMissing(inner) {
    if (!this.hasOwnRecord) return false;
    try { return this.hasOwnRecord(inner) !== true; } catch { return true; }
  }
  _saveReceiptCache() {
    const cap = 512 * 1024;
    const values = Object.entries(this.relayReceipts);
    this._receiptCacheSizes ||= new Map();
    const selected = {};
    let size = 2;
    for (const [digest, receipt] of [...values.filter(([, value]) => value?.actionHash),
      ...values.filter(([, value]) => Array.isArray(value?.msgRefs))]) {
      let entrySize = this._receiptCacheSizes.get(digest);
      if (entrySize === undefined) {
        entrySize = JSON.stringify(digest).length + JSON.stringify(receipt).length + 2;
        this._receiptCacheSizes.set(digest, entrySize);
      }
      if (size + entrySize > cap) continue;
      selected[digest] = receipt;
      size += entrySize;
    }
    return this._saveJson(this._receiptsStoreKey(), selected);
  }
  _scheduleReceiptCacheSave() {
    if (this._receiptCacheTimer) return;
    this._receiptCacheTimer = setTimeout(() => {
      this._receiptCacheTimer = null;
      this._saveReceiptCache();
    }, 50);
    if (typeof this._receiptCacheTimer?.unref === 'function') this._receiptCacheTimer.unref();
  }
  // 自セッション発行アクション署名を追記保存（アクション系のみ・件数は小さいので上限で頭切り）。
  _persistOwnSig(sig) {
    const key = this._ownSigsStoreKey();
    const arr = this._loadJson(key, []);
    if (arr.includes(sig)) return;
    arr.push(sig);
    if (arr.length > 64) arr.splice(0, arr.length - 64); // 投票1+密告2+受領証明の再送分でも十分収まる
    this._saveJson(key, arr);
  }

  start() {
    if (this.pool || this.p2pUnavailable) return;
    for (const member of this.members) {
      let blockAddress = member?.bAddr;
      if (typeof blockAddress === 'string') {
        try { blockAddress = JSON.parse(blockAddress); } catch { blockAddress = null; }
      }
      const key = blockAddress?.nostrPubkey;
      if (isValidNostrPubkey(key)) this.validNostrByUid.set(member.uid, key);
      else {
        console.warn(`[relay] P2P unavailable for ${member?.uid}: invalid roster Nostr pubkey`);
        this.onRosterKeyInvalid(member?.uid);
      }
    }
    // 自分の固定名簿の鍵が無ければ、この端末の P2P 送受信を止める。
    // WS と Evidence の行動経路は呼び手がそのまま使える。
    if (!this.validNostrByUid.has(this.uid)) {
      this.p2pUnavailable = true;
      this.onHistoryProgress?.(this.historyStatus());
      return;
    }
    const authors = [...new Set(this.validNostrByUid.values())];
    this.pool = new RelayPool({
      relays: getRelayList(), tag: this.tag, authors,
      since: this.sinceSec != null ? this.sinceSec : relaySinceSec(),
      now: this.now,
      onEvent: (ev) => this._handleEvent(ev),
      onConnectionChange: this.onConnectionChange,
      onMarkedRequestClosed: (owners) => this.futureMarks?.noteClosedMarkedIds(owners),
      onMarkedRequestRecovered: (id) => this.futureMarks?.noteRecoveredMarkedId(id),
      onHistoryProgress: this.onHistoryProgress ? (status) => this.onHistoryProgress?.(status) : null,
      ownAuthor: this.onHistoryProgress ? this.validNostrByUid.get(this.uid) : null,
      onFlood: (pubkey, count) => {
        const member = this.members.find(m => this.validNostrByUid.get(m.uid) === pubkey);
        this.onFlood(member?.uid || null, pubkey, count);
      },
    });
    this.pool.connect();
  }

  stop() {
    if (this._receiptCacheTimer) {
      clearTimeout(this._receiptCacheTimer);
      this._receiptCacheTimer = null;
      this._saveReceiptCache();
    }
    if (this.pool) { this.pool.close(); this.pool = null; }
  }

  refetchHistory(eventIds = new Set()) { this.pool?.refetchHistory(eventIds); }
  refetchMarkedIds(eventIds = new Set(), eventIssuers = new Map()) {
    this.pool?.refetchMarkedIds(eventIds, eventIssuers);
  }

  // UI用: 各リレーの接続状態（pool未起動ならnull）
  getRelayStatus() {
    return this.pool ? this.pool.getStatus() : null;
  }

  getRelayBudgetStats() {
    return { seenIds: this.pool
      ? this.pool.getBudgetStats().seenIds
      : { size: 0, limit: MAX_SEEN_EVENT_IDS, dropped: 0 } };
  }

  historyStatus() {
    if (this.pool) return this.pool.historyStatus();
    return this.p2pUnavailable
      ? { unavailable: true, startedAt: null, done: 0, waiting: [], states: {} }
      : { startedAt: null, done: 0, waiting: [], states: {} };
  }

  // ---------- 発行 ----------

  _publishInner(innerObj) {
    // このチャネル自身が発行した inner の署名を記録する。リレーは自分の発行イベントを購読へ
    // エコーバックするため、onSelfAction が「自分の別クライアント」と「自セッションのエコー」を
    // 取り違えないよう、この集合に含まれ、かつ本人の行動の控えが保存済みのエコーだけを無視する。
    if (innerObj && innerObj.signature) {
      this._ownPublishedSigs.add(innerObj.signature);
      // アクション系のみ永続化（相互ロックに関与する種別）。chat/receipt は下流が署名で
      // 重複排除・冪等処理するので永続不要＝localStorage 肥大を避ける。
      if (innerObj.type === 'action') this._persistOwnSig(innerObj.signature);
    }
    const doPublish = async () => {
      if (!this.pool) this.start();
      if (!this.pool) return;
      const content = JSON.stringify(innerObj);
      const ev = buildEvent(this.nostrSk, this.nostrPubkey, [['t', this.tag]], content,
        Math.floor(this.now() / 1000));
      this.pool.publish(ev);
    };
    return doPublish().catch(e => console.error('relay publish failed:', e));
  }

  // 署名済みチャットメッセージの発行（§2.5: WS送信と同一の内側オブジェクト）
  publishChat(signedMsg) {
    return this._publishInner({
      type: 'chat',
      blockNum: this.blockNum,
      groupId: this.groupId,
      uid: signedMsg.uid,
      text: signedMsg.text,
      timestamp: signedMsg.timestamp,
      signature: signedMsg.signature
    });
  }

  // 投票/密告の発信（v3.2・平文封筒）。signKey署名済み完全形をそのまま流す。
  // 観測者は提出物の observed セクションへ union する（検証⑥の不正証拠＋WS検閲耐性）。
  publishAction(actionType /* 'vote'|'report' */, action /* {encrypted, signature, timestamp} */) {
    const inner = {
      type: 'action', actionType, blockNum: this.blockNum, groupId: this.groupId, uid: this.uid,
      encrypted: action.encrypted, signature: action.signature, timestamp: action.timestamp
    };
    // 自分の発信もローカル集約へ（提出物の自己マージ・別クライアント復元用）
    this._ingestAction(inner);
    return this._publishInner(inner);
  }

  // 在席通知の発行（v3.3追補・平文封筒）。active/away の変化時のみ送る（ハートビートはしない＝
  // リレー負荷を増やさない。取りこぼしても受信側は「直近10分の活動観測」で自然に復帰判定できる）。
  publishPresence(presence /* {uid, state, timestamp, signature} */) {
    return this._publishInner({
      type: 'presence',
      blockNum: this.blockNum,
      groupId: this.groupId,
      uid: presence.uid,
      state: presence.state,
      timestamp: presence.timestamp,
      signature: presence.signature
    });
  }

  // 受領証明の発行（v3.2 §6.3・平文封筒・グループ全員へブロードキャスト）。
  // receipt = {receiverUid, actionHash, timestamp, signature}（action受領）
  //         | {receiverUid, senderUid, msgRefs[], timestamp, signature}（既読バッチ）
  publishReceipt(receipt) {
    const inner = {
      type: 'receipt', blockNum: this.blockNum, groupId: this.groupId, ...receipt
    };
    void this._ingestReceipt(receipt, { verified: true });
    return this._publishInner(inner);
  }

  // ---------- 受信 ----------

  async _handleEvent(ev) {
    try {
      const inner = JSON.parse(ev.content);
      if (!inner || inner.blockNum !== this.blockNum || inner.groupId !== this.groupId) return;
      if (!['chat', 'action', 'receipt', 'presence'].includes(inner.type)) return;
      const senderUid = inner.type === 'receipt' ? inner.receiverUid : inner.uid;
      // 鍵から uid は逆引きしない。内側が主張する発信者の名簿行だけを照合する。
      if (this.validNostrByUid.get(senderUid) !== ev.pubkey) return;
      if (inner.type === 'chat' && !isClientChatWithinLimit(inner.text, this.getMaxMsgChars())) return;
      if (this.isAccepted(inner.type, inner)) return true;
      if (this.futureMarks?.noteEvent(inner.type, inner, ev.id)) return true;
      if (senderUid === this.uid) {
        if (!await this.verifyInnerSignature(inner.type, inner)) return false;
        if (!isClientTimestampAllowed(inner.timestamp, this.now())) {
          if (!this._ownPublishedSigs.has(inner.signature)) await this.onSelfAction?.(inner.type, inner);
          this.futureMarks?.discard(inner.type, inner, { eventId: ev.id, issuer: senderUid });
          return true;
        }
        if (this.onSelfAction) {
          const ownActionMissing = inner.type === 'action' && !this._hasStoredOwnAction(inner.signature);
          if (ownActionMissing) this._ingestAction(inner);
          if (!inner.signature || !this._ownPublishedSigs.has(inner.signature) || ownActionMissing
            || (inner.type === 'action' && this._ownRecordMissing(inner))) {
            await this.onSelfAction(inner.type, inner);
          }
        }
        return true;
      }
      switch (inner.type) {
        case 'chat':
          if (!await this.verifyInnerSignature('chat', inner)) return false;
          if (!isClientTimestampAllowed(inner.timestamp, this.now())) {
            this.futureMarks?.discard('chat', inner, { eventId: ev.id, issuer: senderUid });
            return true;
          }
          if (this.getChatWindow()?.endMs < inner.timestamp) return true;
          await this.onChat(inner);
          return true;
        case 'action': return await this._handleAction(inner, ev);
        case 'receipt': return await this._handleReceipt(inner, ev);
        case 'presence': await this._handlePresence(inner); break;
      }
    } catch (e) { /* 単一イベントの処理失敗はチャネルを止めない */ }
  }

  // 投票/密告発信の受信（v3.2）。署名検証（signKey・登録pubKey）の上で観測集約へ。
  async _handleAction(inner, ev = null) {
    const { actionType, uid, encrypted, timestamp, signature } = inner;
    if (!uid || !encrypted || !timestamp || !signature) return;
    if (actionType !== 'vote' && actionType !== 'report') return;
    if (!this.members.some(m => m.uid === uid)) return;
    const valid = await this.verifyInnerSignature('action', inner);
    if (!valid) return;
    if (!isClientTimestampAllowed(timestamp, this.now())) {
      this.futureMarks?.discard('action', inner, { eventId: ev?.id, issuer: uid });
      return true;
    }
    this._ingestAction(inner);
  }

  // アクションの観測集約（自分の発信・受信の両方が通る）
  _ingestAction(inner) {
    const { actionType, uid, encrypted, timestamp, signature } = inner;
    const action = { encrypted, signature, timestamp };
    const slot = this.relayActions[uid] || (this.relayActions[uid] = { vote: null, reports: [] });
    // K-S6-002（2026-07-29）: 1人の発信者について溜め込む発信の上限。
    // リレー経路はサーバーの one-shot 制限を通らないため、メンバーが自分の signKey で
    // 正しく署名した発信を数千件流すと、全員の localStorage と提出物が肥大して
    // WS提出（DOの単一値128KiB）もオンチェーン提出（gzip後128KB）も同時に潰せた。
    // 署名検証済みなので埋まるのは**その発信者自身のバケツだけ**＝他人を押し出せない。
    if (actionType === 'vote') {
      if (slot.vote && slot.vote.signature === signature) {
        if (uid === this.uid) this._saveOwnActions();
        return;
      }
      // one-shot: 既存と異なる署名の投票も保持はする（矛盾検出の証拠。上書きせず先着を維持し
      // 追加分は reports 側ではなく voteExtras に積む）
      if (!slot.vote) slot.vote = action;
      else {
        slot.voteExtras = slot.voteExtras || [];
        if (slot.voteExtras.length + 1 >= MAX_OBSERVED_ACTIONS_PER_ACTOR) return;
        if (!slot.voteExtras.some(a => a.signature === signature)) slot.voteExtras.push(action);
      }
    } else {
      if (slot.reports.length >= MAX_OBSERVED_ACTIONS_PER_ACTOR) return;
      if (!slot.reports.some(a => a.signature === signature)) slot.reports.push(action);
    }
    if (uid === this.uid) this._saveOwnActions();
    this._saveJson(this._actionsStoreKey(), this.relayActions);
    this._recomputeFacts();
    this.onActionsChange(this.getRelayActionsRaw());
  }

  // 受領証明の受信（v3.2 §6.3）。署名検証の上で観測集約へ（全員が提出物に同梱＝削除耐性）。
  async _handleReceipt(inner, ev = null) {
    const { receiverUid, timestamp, signature } = inner;
    if (!receiverUid || !timestamp || !signature) return;
    if (!this.members.some(m => m.uid === receiverUid)) return;
    // K-S6-002（2026-07-29）: 形式が不正な参照は取り込まない。**署名検証より前**に行う
    // （不正な入力に楕円曲線の検証コストを払わない＝氾濫時のCPUも同時に抑える）。
    // 受領証明は全員が提出物に同梱する設計なので、ここを通した異物は
    // グループ全員の提出物を肥大させ、WS提出もオンチェーン提出も同時に潰せた。
    const receipt = { receiverUid, timestamp, signature };
    if (Array.isArray(inner.msgRefs)) {
      if (inner.msgRefs.length === 0 || !inner.msgRefs.every(isMsgRef)) return;
      if (inner.msgRefs.length > receiptMaxRefsPerReceipt(GUEST_PINNED_RULES.maxMessages)) return;
      // 決定1: Nostr 入口も DO と同じ名簿検査。GameRelayChannel は名簿確定後に
      // 起動され、起動前に届いた受領証明は上位の単一保留機構が扱う。
      if (typeof inner.senderUid !== 'string' || !this.members.some(m => m.uid === inner.senderUid)) return;
      receipt.msgRefs = inner.msgRefs;
      receipt.senderUid = inner.senderUid;
    } else if (isActionHash(inner.actionHash)) {
      receipt.actionHash = inner.actionHash;
    } else {
      return;
    }
    const digest = receiptIdentityDigest(receipt);
    if (!digest || this.relayReceipts[digest]) return;
    const valid = await this.verifyInnerSignature('receipt', inner);
    if (!valid) return;
    if (!isClientTimestampAllowed(timestamp, this.now())) {
      this.futureMarks?.discard('receipt', receipt, { eventId: ev?.id, issuer: receiverUid });
      return true;
    }
    await this._ingestReceipt(receipt, { verified: true });
  }

  // 在席通知の受理（v3.3追補）。署名検証＋古い通知の無視のみ。表示専用なので永続化しない。
  async _handlePresence(inner) {
    const { uid, state, timestamp, signature } = inner;
    if (!uid || !timestamp || !signature) return;
    if (state !== 'active' && state !== 'away') return;
    if (!this.members.some(m => m.uid === uid)) return;
    const prev = this.presenceByUid[uid];
    if (prev && prev.timestamp >= timestamp) return; // 古い/重複通知は無視
    const valid = await this.verifyInnerSignature('presence', inner);
    if (!valid) return;
    this.presenceByUid[uid] = { state, timestamp };
    try { this.onPresence(uid, state, timestamp); } catch (e) { /* noop */ }
  }

  _ingestReceipt(receipt, { verified = false } = {}) {
    const digest = receiptIdentityDigest(receipt);
    if (!digest || this.relayReceipts[digest]) return;
    const issuer = receipt?.receiverUid;
    if ((this._relayReceiptCounts?.get(issuer) || 0) >= MAX_RECEIPTS_PER_ISSUER) {
      // Keep the persistence cap without hiding an independently delivered
      // receipt from the caller's own admission cap and duplicate checks.
      return this.onReceiptsChange([receipt], { verified });
    }
    this.relayReceipts[digest] = receipt;
    this._relayReceiptCounts?.set(issuer, (this._relayReceiptCounts.get(issuer) || 0) + 1);
    if (receipt.actionHash) this._saveReceiptCache();
    else this._scheduleReceiptCacheSave();
    // 決定3: 新着1件だけを渡す。復元時だけ constructor が保存集合を1回渡す。
    return this.onReceiptsChange([receipt], { verified });
  }

  // 上位の保留機構が H／名簿外／上限超過と確定した受領証明を、リレーの復元用キャッシュからも除く。
  forgetReceipt(digest) {
    if (!digest || !this.relayReceipts[digest]) return false;
    const issuer = this.relayReceipts[digest]?.receiverUid;
    delete this.relayReceipts[digest];
    this._receiptCacheSizes?.delete(digest);
    if (this._relayReceiptCounts?.has(issuer)) this._relayReceiptCounts.set(issuer,
      Math.max(0, this._relayReceiptCounts.get(issuer) - 1));
    this._scheduleReceiptCacheSave();
    return true;
  }

  // UI可視化用の事実（relayActionsから導出）
  _recomputeFacts() {
    const facts = {};
    for (const [uid, slot] of Object.entries(this.relayActions)) {
      facts[uid] = { voted: !!slot.vote, reportCount: (slot.reports || []).length };
    }
    this.relayFacts = facts;
    try { this.onFactsChange({ ...facts }); } catch (e) { /* noop */ }
  }

  // リレー観測アクションを observed 形（votes: uid→action / reports: uid→[action]）へ。
  // voteExtras（矛盾候補）も votes 側の配列として返す（検証⑥の証拠提出用）。
  getRelayActionsRaw() {
    const votes = {};
    const reports = {};
    for (const [uid, slot] of Object.entries(this.relayActions)) {
      if (slot.vote) votes[uid] = slot.vote;
      if (Array.isArray(slot.voteExtras) && slot.voteExtras.length > 0) {
        votes[`${uid}__extras`] = slot.voteExtras;
      }
      if (Array.isArray(slot.reports) && slot.reports.length > 0) reports[uid] = slot.reports;
    }
    return { votes, reports };
  }

  // 観測受領証明の一覧（提出物 observed.receipts へ同梱する形）
  getRelayReceipts() {
    return Object.values(this.relayReceipts);
  }

}

// ============================================================
// ロスター取得（§4.6 F4: from-the-start WS検閲下のブートストラップ）
// ============================================================

const R2_PUBLIC_BASE = 'https://r2.bitcoinu.org';

// 復元クライアントへ byte-exact vendor されるため、この入口だけは relay 内で完結させる。
// 既存の QUIESCENCE_MS を期限として再利用し、fetch と JSON body の両方を独立 race で有界化する。
async function fetchR2JsonWithTimeout(url, options = {}, timeoutMs = QUIESCENCE_MS) {
  const controller = new AbortController();
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error(`R2 fetch timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });
  try {
    const response = await Promise.race([
      fetch(url, { ...options, signal: controller.signal }), timeout,
    ]);
    const data = response.ok ? await Promise.race([response.json(), timeout]) : null;
    return { ok: response.ok, status: response.status, data };
  } finally {
    clearTimeout(timer);
  }
}

// 自分のgroupIdが不明な場合は index.json（uid→groupId）を引いてからグループロスターを取得
export async function fetchRoster(blockNum, groupId = null, uid = null) {
  let gid = groupId;
  if (gid === null || gid === undefined) {
    if (!uid) return null;
    const idxRes = await fetchR2JsonWithTimeout(
      `${R2_PUBLIC_BASE}/games/block${blockNum}/roster/index.json`, { cache: 'no-store' },
    );
    if (!idxRes.ok) return null;
    const index = idxRes.data;
    gid = index?.[uid];
    if (gid === null || gid === undefined) return null;
  }
  const res = await fetchR2JsonWithTimeout(
    `${R2_PUBLIC_BASE}/games/block${blockNum}/roster/group${gid}.json`, { cache: 'no-store' },
  );
  if (!res.ok) return null;
  return res.data; // R-4.19: members contain the 10 canonical roster fields.
}

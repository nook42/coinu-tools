// 自分の密告の根拠（S3R5-U-R13-SELF・原則「自分の投票・密告の正当性も自分の提出物で守る」）。
//
// 根拠＝標的の投票のうち、密告の自称時刻より前の時刻で、自分と標的以外のメンバーの
// 鮮度内（±10分）・宣言窓内の受領証明が付いているもの＋その受領証明（発行者ごとに正準先頭の1枚）。
// 公式（useGameWebSocket.sendReport）と復元（app.js sendReport）が密告の時に控えへ残し、
// 提出物の観測欄（送り手ごと10件）で最優先に選び、その受領証明も運ぶ。
// 採点はこのファイルを読まない（クライアントの選び方だけ）。chatgame-tools/vendor へ byte-exact COPY。
import { actionHashV2, clientChatSourcedReceipts, isReceiptTimely, MAX_OBSERVED_ACTIONS_PER_ACTOR, mergeActionReceiptSources }
  from '../../workers/game_workers/lib/protocol-v2.js';
import { receiptCanonCmp } from '../../workers/game_workers/lib/game-result-calculator.js';

export const REPORT_GROUNDS_KEY = (blockNum, uid) => `myReportGrounds_${blockNum}_user${uid}`;
export const MAX_REPORT_GROUNDS = 10;

const plain = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
const entries = (value) => plain(value) ? Object.entries(value) : [];
const strCmp = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const pickAction = (a) => ({ encrypted: a.encrypted, signature: a.signature, timestamp: a.timestamp });
// 受領証明は署名の覆う欄と、提出の門（mayCarryActionReceipt）が読む到着の印だけを控える。
export const pickReportGroundReceipt = (rc) => {
  const out = { receiverUid: rc.receiverUid, actionHash: rc.actionHash, timestamp: rc.timestamp, signature: rc.signature };
  for (const key of ['_chainSeenAt', '_deviceSeenAt', '_receivedAt']) {
    if (Number.isSafeInteger(rc[key])) out[key] = rc[key];
  }
  if (Array.isArray(rc._chatSources)) out._chatSources = rc._chatSources.filter((s) => s === 'chain' || s === 'device');
  return out;
};

export function collectReportGround({
  blockNum, groupId, selfUid, targetUid, reportTimestamp, votes, receipts, chatWindow = null, chatCloseAt = null,
} = {}) {
  const ground = { targetUid, reportTimestamp, votes: [], receipts: [] };
  if (typeof targetUid !== 'string' || targetUid === selfUid || !Number.isSafeInteger(reportTimestamp)) return ground;
  const list = clientChatSourcedReceipts(receipts, chatWindow, chatCloseAt);
  const seen = new Set();
  const candidates = (Array.isArray(votes) ? votes : [])
    .filter((v) => v?.encrypted && v?.signature && Number.isSafeInteger(v.timestamp) && v.timestamp < reportTimestamp)
    .sort((a, b) => a.timestamp - b.timestamp || strCmp(String(a.signature), String(b.signature)));
  for (const vote of candidates) {
    const hash = actionHashV2('vote', blockNum, groupId, targetUid, vote.encrypted, vote.timestamp);
    if (seen.has(hash) || ground.votes.length >= MAX_OBSERVED_ACTIONS_PER_ACTOR) continue;
    const byIssuer = new Map();
    for (const rc of list) {
      if (!rc || Array.isArray(rc.msgRefs) || typeof rc.actionHash !== 'string'
        || rc.actionHash !== hash || !rc.signature || typeof rc.receiverUid !== 'string') continue;
      if (rc.receiverUid === selfUid || rc.receiverUid === targetUid) continue;
      if (!isReceiptTimely(rc.timestamp, vote.timestamp)) continue;
      if (chatWindow && !(rc.timestamp >= chatWindow.startMs && rc.timestamp <= chatWindow.endMs)) continue;
      const prev = byIssuer.get(rc.receiverUid);
      if (!prev || receiptCanonCmp(rc, prev) < 0) byIssuer.set(rc.receiverUid, rc);
    }
    if (byIssuer.size === 0) continue;
    seen.add(hash);
    ground.votes.push(pickAction(vote));
    for (const uid of [...byIssuer.keys()].sort()) ground.receipts.push(pickReportGroundReceipt(byIssuer.get(uid)));
  }
  return ground;
}

// grounds: { [reportSignature]: ground }
export function mergeReportGrounds(prev, reportSignature, ground) {
  const next = Object.fromEntries(entries(prev));
  if (typeof reportSignature !== 'string' || !ground || !Array.isArray(ground.votes) || ground.votes.length === 0) return next;
  if (Object.hasOwn(next, reportSignature)) return next;
  const full = Object.values(next).filter((g) => Array.isArray(g?.votes) && g.votes.length > 0);
  if (full.length >= MAX_REPORT_GROUNDS) return next;
  const sigs = new Set(ground.votes.map((vote) => vote.signature));
  if (full.some((g) => g.targetUid === ground.targetUid
    && [...sigs].every((signature) => g.votes.some((vote) => vote.signature === signature)))) return next;
  next[reportSignature] = ground;
  return next;
}

export function mergeReportGroundMaps(a, b) {
  let merged = Object.fromEntries(entries(a));
  for (const [signature, ground] of entries(b).sort(([x], [y]) => strCmp(x, y))) {
    merged = mergeReportGrounds(merged, signature, ground);
  }
  return merged;
}

export function loadReportGrounds(blockNum, uid, storage = globalThis.localStorage) {
  try {
    const value = JSON.parse(storage.getItem(REPORT_GROUNDS_KEY(blockNum, uid)) || '{}');
    return plain(value) ? value : {};
  } catch { return {}; }
}

export function hasReportGround(grounds) {
  return entries(grounds)
    .map(([, ground]) => ground)
    .some((g) => Array.isArray(g?.votes) && g.votes.length > 0);
}

export function reportGroundReceipts(grounds) {
  const out = [];
  for (const [, g] of entries(grounds)) {
    for (const rc of (Array.isArray(g?.receipts) ? g.receipts : [])) out.push(rc);
  }
  return out;
}

// receipts（署名→受領証明の写像か配列）に控えの受領証明を足す。到着の印は早い方を残す。
export function withReportGroundReceipts(receipts, grounds) {
  const extra = reportGroundReceipts(grounds);
  if (extra.length === 0) return receipts;
  const map = new Map((Array.isArray(receipts) ? receipts : Object.values(receipts || {}))
    .filter((rc) => rc?.signature).map((rc) => [rc.signature, rc]));
  for (const rc of extra) {
    const old = map.get(rc.signature);
    map.set(rc.signature, old ? mergeActionReceiptSources(old, rc) : rc);
  }
  return Array.isArray(receipts) ? [...map.values()] : Object.fromEntries(map);
}

// 提出物の観測欄 observed.votes（uid → 配列）で、標的ごとの最も早い確定票だけを守る。
// 通常の正準先頭10件に既にあれば変えず、無いときだけ最後の1件と入れ替える。
// 最後は正規化と同じ actionCanonCmp 順、actionHash ごとに一意の10件以内にする。
export function preferReportGroundVotes(observedVotes, grounds, { blockNum, groupId, selfUid, memberUids = [] } = {}) {
  const out = { ...(observedVotes || {}) };
  const roster = new Set(memberUids);
  const byTarget = new Map();
  for (const [, g] of entries(grounds)) {
    if (typeof g?.targetUid !== 'string' || g.targetUid === selfUid || !roster.has(g.targetUid)) continue;
    const list = byTarget.get(g.targetUid) || [];
    for (const v of (Array.isArray(g.votes) ? g.votes : [])) if (v?.encrypted && v?.signature && Number.isSafeInteger(v.timestamp)) list.push(v);
    byTarget.set(g.targetUid, list);
  }
  for (const [targetUid, preferredRaw] of byTarget) {
    const hashOf = (a) => actionHashV2('vote', blockNum, groupId, targetUid, a.encrypted, a.timestamp);
    const byCanon = (a, b) => a.timestamp - b.timestamp || strCmp(hashOf(a), hashOf(b))
      || strCmp(a.signature.toLowerCase(), b.signature.toLowerCase());
    const groundVote = [...preferredRaw].sort((a, b) => a.timestamp - b.timestamp
      || strCmp(a.signature.toLowerCase(), b.signature.toLowerCase()))[0];
    if (!groundVote) continue;
    const rest = (Array.isArray(out[targetUid]) ? out[targetUid] : (out[targetUid] ? [out[targetUid]] : []))
      .filter((a) => a?.encrypted && a?.signature && Number.isSafeInteger(a.timestamp));
    const sigs = new Set(); const hashes = new Set(); const canonical = [];
    for (const a of [...rest].sort(byCanon)) {
      const hash = hashOf(a);
      if (sigs.has(a.signature) || hashes.has(hash)) continue;
      sigs.add(a.signature); hashes.add(hash); canonical.push(a);
    }
    const firstTen = canonical.slice(0, MAX_OBSERVED_ACTIONS_PER_ACTOR);
    const groundHash = hashOf(groundVote);
    if (firstTen.some((a) => hashOf(a) === groundHash)) {
      out[targetUid] = firstTen.map(pickAction);
      continue;
    }
    const representative = canonical.find((a) => hashOf(a) === groundHash) || groundVote;
    const chosen = [...firstTen.slice(0, MAX_OBSERVED_ACTIONS_PER_ACTOR - 1), representative];
    out[targetUid] = chosen.sort(byCanon).map(pickAction);
  }
  return out;
}

export function sameDeviceBandReasons({ grounds, ownReportSignatures = [], saveFailed = false, conversationAtRisk = false } = {}) {
  const hasGround = hasReportGround(grounds);
  const hasReport = Array.isArray(ownReportSignatures) && ownReportSignatures.length > 0;
  return [
    ...(saveFailed && (hasGround || hasReport) ? ['reportGroundSaveFailed'] : []),
    ...(hasGround ? ['reportGround'] : []),
    ...(conversationAtRisk ? ['conversationMemory'] : []),
    ...((hasGround || conversationAtRisk) ? ['switchClient'] : []),
  ];
}

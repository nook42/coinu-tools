// The pasted export is untrusted. Only keys for the current identity are read;
// signed observations are checked against the confirmed roster before merging.
import { receiptIdentityDigest } from '../../vendor/src/utils/relay.js';
import { mergeActionReceiptSources } from '../../vendor/workers/game_workers/lib/protocol-v2.js';
import { MAX_RECEIPTS_PER_ISSUER } from '../../vendor/src/utils/relay.js';
import { actionHashV2 } from '../../vendor/workers/game_workers/lib/protocol-v2.js';
import { MAX_REPORT_GROUNDS, pickReportGroundReceipt } from '../../vendor/src/utils/reportGround.js';
import { sha256, stringToBytes } from 'viem';

export async function parseOfficialStorage(text, { blockNum, groupId, uid, members, verify }) {
  if (typeof text !== 'string' || text.length > 12_000_000) throw new Error('localStorage export is too large');
  const object = JSON.parse(text);
  if (!object || Array.isArray(object) || typeof object !== 'object') throw new Error('expected a JSON object of localStorage keys');
  const b = Number(blockNum), g = Number(groupId);
  const identity = `${b}_group${g}_user${uid}`;
  const own = `${b}_user${uid}`;
  const read = (key, fallback) => {
    const raw = object[key];
    if (typeof raw !== 'string') return fallback;
    try { return JSON.parse(raw); } catch { return fallback; }
  };
  const receipts = new Map();
  const limit = MAX_RECEIPTS_PER_ISSUER * members.length;
  const counts = new Map();
  for (const key of [`observedReceipts_${identity}`, `p2pRelayReceipts_${identity}`,
    `selfReadReceipts_v1_${identity}`]) {
    const raw = read(key, []);
    for (const receipt of (Array.isArray(raw) ? raw : Object.values(raw && typeof raw === 'object' ? raw : {}))) {
      const digest = receiptIdentityDigest(receipt);
      if (!digest || !members.some((member) => member.uid === receipt.receiverUid)) continue;
      const old = receipts.get(digest);
      if (!old && (counts.get(receipt.receiverUid) || 0) >= MAX_RECEIPTS_PER_ISSUER) continue;
      if (!(await verify('receipt', receipt))) continue;
      if (!old) counts.set(receipt.receiverUid, (counts.get(receipt.receiverUid) || 0) + 1);
      receipts.set(digest, old ? mergeActionReceiptSources(old, receipt) : receipt);
    }
  }
  const verifyAction = async (type, actorUid, value) => {
    if (!value || !(await verify('action', { ...value, uid: actorUid, actionType: type }))) return null;
    return { encrypted: value.encrypted, signature: value.signature, timestamp: value.timestamp };
  };
  const vote = await verifyAction('vote', uid, read(`myVote_${own}`, null));
  const votePrev = [];
  const rawVotePrev = read(`myVotePrev_${own}`, []);
  for (const item of (Array.isArray(rawVotePrev) ? rawVotePrev : []).slice(0, 10)) {
    const valid = await verifyAction('vote', uid, item);
    if (valid) votePrev.push(valid);
  }
  const reports = [];
  const rawReports = read(`myReports_${own}`, []);
  for (const item of (Array.isArray(rawReports) ? rawReports : []).slice(0, 10)) {
    const valid = await verifyAction('report', uid, item);
    if (valid) reports.push(valid);
  }
  const observedActions = { votes: {}, reports: {} };
  const rawActions = read(`observedActions_${identity}`, {});
  for (const [key, raw] of Object.entries(rawActions?.votes || {})) {
    const actorUid = key.endsWith('__extras') ? key.slice(0, -8) : key;
    if (!members.some((member) => member.uid === actorUid)) continue;
    const values = [];
    for (const item of (Array.isArray(raw) ? raw : [raw]).slice(0, 10)) {
      const valid = await verifyAction('vote', actorUid, item);
      if (valid) values.push(valid);
    }
    if (values.length) observedActions.votes[key] = key.endsWith('__extras') ? values : values[0];
  }
  for (const [actorUid, raw] of Object.entries(rawActions?.reports || {})) {
    if (!members.some((member) => member.uid === actorUid)) continue;
    const values = [];
    for (const item of (Array.isArray(raw) ? raw : []).slice(0, 10)) {
      const valid = await verifyAction('report', actorUid, item);
      if (valid) values.push(valid);
    }
    if (values.length) observedActions.reports[actorUid] = values;
  }
  // S3R5-U-R13-SELF: 密告の根拠の控え。投票は標的の署名、受領証明は発行者の署名と指す先を確かめる。
  const reportGrounds = {};
  const rawGrounds = read(`myReportGrounds_${own}`, {});
  for (const [reportSignature, raw] of Object.entries(rawGrounds && typeof rawGrounds === 'object' && !Array.isArray(rawGrounds) ? rawGrounds : {})
    .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).slice(0, MAX_REPORT_GROUNDS)) {
    const verifiedReport = reports.find((report) => report.signature === reportSignature);
    if (!verifiedReport) continue;
    const targetUid = raw?.targetUid;
    if (typeof targetUid !== 'string' || targetUid === uid || !members.some((member) => member.uid === targetUid)) continue;
    const votes = [];
    const voteHashes = new Set();
    for (const item of (Array.isArray(raw.votes) ? raw.votes : []).slice(0, 10)) {
      const valid = await verifyAction('vote', targetUid, item);
      if (!valid) continue;
      const hash = actionHashV2('vote', b, g, targetUid, valid.encrypted, valid.timestamp);
      if (voteHashes.has(hash)) continue;
      voteHashes.add(hash);
      votes.push(valid);
    }
    if (!votes.length) continue;
    const groundReceipts = [];
    const receiptIssuers = new Set();
    for (const rc of (Array.isArray(raw.receipts) ? raw.receipts : []).slice(0, 40)) {
      if (!rc || Array.isArray(rc.msgRefs) || typeof rc.actionHash !== 'string'
          || !voteHashes.has(rc.actionHash) || !Number.isSafeInteger(rc.timestamp)
          || rc.receiverUid === uid || rc.receiverUid === targetUid) continue;
      if (!members.some((member) => member.uid === rc.receiverUid)) continue;
      const issuerKey = `${rc.actionHash}|${rc.receiverUid}`;
      if (receiptIssuers.has(issuerKey) || !(await verify('receipt', rc))) continue;
      receiptIssuers.add(issuerKey);
      groundReceipts.push(pickReportGroundReceipt(rc));
    }
    reportGrounds[reportSignature] = { targetUid, reportTimestamp: verifiedReport.timestamp, votes, receipts: groundReceipts };
  }
  const payload = object[`evidence_result_${own}`] || null;
  const savedAt = read(`evidence_result_${own}_savedAt`, null);
  const savedWindow = savedAt?.chatWindow;
  const payloadWindow = typeof payload === 'string'
    && savedAt?.sha256 === sha256(stringToBytes(payload))
    && Number.isSafeInteger(savedWindow?.startMs)
    && Number.isSafeInteger(savedWindow?.endMs)
    && savedWindow.startMs <= savedWindow.endMs
    ? { startMs: savedWindow.startMs, endMs: savedWindow.endMs } : null;
  return { receipts: [...receipts.values()], vote, votePrev, reports, reportGrounds,
    observedActions,
    proof: read(`evidence_roster_proof_${own}`, null),
    payload, payloadWindow };
}

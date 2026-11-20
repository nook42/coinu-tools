import { summarizeOwnSubmission, makeDryRunSigner, describeSubmissionGuarantee } from './submissionGuarantee.js';
import { trimmedSubmissionSignatureMessage, encodeSignedTrimmedPayload } from '../../workers/game_workers/lib/evidence-trim.js';
import { canonicalizeSignature } from '../../workers/game_workers/lib/protocol-v2.js';

export const TRIM_LOSS_KEYS = Object.freeze([
  'trimLossWarning', 'trimLossWarningNoServer', 'trimLossTurns', 'trimLossChars',
  'trimLossCharsUnprotected', 'trimLossVote', 'trimLossVoteNoTarget',
  'trimLossReports', 'trimLossUnchecked',
]);

function guaranteedRows(summary) {
  const value = { turns: 0, chars: null, vote: null, reports: [] };
  const seen = new Set();
  for (const { key, params } of describeSubmissionGuarantee(summary).rows) {
    let category;
    switch (key) {
      case 'turns':
        category = 'turns';
        value.turns = params.count;
        break;
      case 'turnsUnprotected':
        category = 'turns';
        break;
      case 'chars':
        category = 'chars';
        value.chars = { count: params.count, held: Math.min(params.count, params.min) };
        break;
      case 'charsUnprotected':
        category = 'chars';
        break;
      case 'voteDone':
        category = 'vote';
        value.vote = { targetUid: params.targetUid };
        break;
      case 'voteDoneNoTarget':
        category = 'vote';
        value.vote = { targetUid: null };
        break;
      case 'voteUnprotected':
      case 'voteRejected':
        category = 'vote';
        break;
      case 'reports':
        category = 'reports';
        value.reports = params.targetUids;
        break;
      case 'reportsNone':
      case 'reportsTooMany':
      case 'reportsRejected':
        category = 'reports';
        break;
      default:
        throw new Error(`Unknown guarantee row: ${key}`);
    }
    if (seen.has(category)) throw new Error(`Duplicate guarantee row: ${category}`);
    seen.add(category);
  }
  if (seen.size !== 4) throw new Error('Incomplete guarantee rows');
  return value;
}

export function trimGuaranteeLoss(before, after) {
  const prior = guaranteedRows(before);
  const next = guaranteedRows(after);
  const lost = [];
  if (next.turns < prior.turns) {
    lost.push({ key: 'turns', params: { before: prior.turns, after: next.turns } });
  }
  if (prior.chars?.held > 0) {
    if (!next.chars) {
      lost.push({ key: 'charsUnprotected', params: { before: prior.chars.count } });
    } else if (next.chars.held < prior.chars.held) {
      lost.push({ key: 'chars', params: { before: prior.chars.count, after: next.chars.count } });
    }
  }
  if (prior.vote && (!next.vote || (prior.vote.targetUid != null
      && String(prior.vote.targetUid) !== String(next.vote.targetUid)))) {
    lost.push(prior.vote.targetUid == null
      ? { key: 'voteNoTarget', params: {} }
      : { key: 'vote', params: { targetUid: prior.vote.targetUid } });
  }
  const retained = new Set(next.reports.map(String));
  const missing = prior.reports.filter((uid) => !retained.has(String(uid)));
  if (missing.length) lost.push({ key: 'reports', params: { targetUids: missing } });
  return lost;
}

export async function checkTrimGuarantee(beforePayload, plan, {
  blockNum, groupId, myUid, members, chatWindow, ownMessages = [],
  ownActions = { votes: [], reports: [] }, signer = null,
} = {}) {
  if (typeof beforePayload !== 'string' || !beforePayload || !plan?.trimmedBundle
      || plan.compactContext == null) return { status: 'failed', reason: 'input' };
  try {
    const inputs = { blockNum, groupId, myUid, members, chatWindow, ownMessages, ownActions };
    const before = await summarizeOwnSubmission(beforePayload, { ...inputs, signerAddress: null });
    if (before.rejected) return { status: 'failed', reason: 'before-rejected' };
    await new Promise((resolve) => globalThis.setTimeout(resolve, 0));
    const dry = signer || makeDryRunSigner();
    const signature = canonicalizeSignature(
      await dry.signMessage(trimmedSubmissionSignatureMessage(plan.trimmedBundle, blockNum)));
    const trimmedPayload = encodeSignedTrimmedPayload(plan.trimmedBundle, signature, plan.compactContext);
    await new Promise((resolve) => globalThis.setTimeout(resolve, 0));
    const after = await summarizeOwnSubmission(trimmedPayload, {
      ...inputs, signerAddress: dry.address,
    });
    return { status: 'ok', lost: trimGuaranteeLoss(before, after), before, after };
  } catch (error) {
    return { status: 'failed', reason: 'error', error };
  }
}

export function formatTrimGuaranteeWarning(check, {
  translate, prefix, resolveName, serverSubmitted = false, separator = ', ',
}) {
  if (check?.status !== 'ok') return `\n\n${translate(`${prefix}trimLossUnchecked`)}`;
  if (!check.lost.length) return '';
  let message = `\n\n${translate(`${prefix}${serverSubmitted ? 'trimLossWarning' : 'trimLossWarningNoServer'}`)}`;
  for (const { key, params } of check.lost) {
    const suffix = `trimLoss${key[0].toUpperCase()}${key.slice(1)}`;
    if (!TRIM_LOSS_KEYS.includes(suffix)) throw new Error(`Unknown trim loss: ${key}`);
    const named = key === 'vote' ? { name: resolveName(params.targetUid) }
      : key === 'reports' ? { names: params.targetUids.map(resolveName).join(separator) }
        : params;
    message += `\n  ・${translate(`${prefix}${suffix}`, named)}`;
  }
  return message;
}

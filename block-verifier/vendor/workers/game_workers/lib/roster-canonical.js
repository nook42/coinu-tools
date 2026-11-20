// R-4.19: production roster bytes. Both roster writers use this one serializer.
import { iterativeJsonStringify, parseDepositWei } from './game-result-calculator.js';

export const ETH_HEADER_RULE_VERSION = 1;
export const ETH_HEADER_FORK = 'osaka';

export function normalizeLang(lang) {
  const value = typeof lang === 'string' ? lang.trim().toLowerCase().slice(0, 32).trim() : '';
  return value || 'unknown';
}

export function canonicalRosterMember(member) {
  let bAddr = null;
  let depIds = null;
  try { bAddr = typeof member?.bAddr === 'string' ? JSON.parse(member.bAddr) : member?.bAddr; }
  catch { /* invalid block address is represented by nulls */ }
  try { depIds = typeof member?.depIds === 'string' ? JSON.parse(member.depIds) : member?.depIds; }
  catch { /* invalid depositIds is represented by [] and 0 wei */ }
  const blockAddress = typeof bAddr?.address === 'string' && bAddr.address ? bAddr.address : null;
  const globalIndex = member?.globalIndex;
  if (!Number.isSafeInteger(globalIndex) || globalIndex < 0) {
    throw new Error('canonical roster member has invalid globalIndex');
  }
  if (typeof member?.uid !== 'string') throw new Error('canonical roster member has invalid uid');
  return {
    uid: member.uid,
    walletAddress: member.addr || null,
    blockAddress,
    pubKey: blockAddress ? bAddr?.pubKey || null : null,
    nostrPubkey: blockAddress ? bAddr?.nostrPubkey || null : null,
    depositIds: Array.isArray(depIds?.ids) ? depIds.ids : [],
    lang: normalizeLang(member.lang),
    globalIndex,
    depositWei: parseDepositWei(member.depIds),
    depositVerified: member.verified === true,
  };
}

export function canonicalRosterText(blockNum, groupId, members) {
  if (!Number.isSafeInteger(Number(blockNum)) || !Number.isSafeInteger(Number(groupId))) {
    throw new Error('canonical roster has invalid blockNum or groupId');
  }
  const roster = {
    blockNum: Number(blockNum),
    groupId: Number(groupId),
    members: members.map(canonicalRosterMember),
  };
  try { return JSON.stringify(roster); }
  catch { return iterativeJsonStringify(roster); }
}

// src/recovery/discovery.js — uid / ロスター / グループ / フェーズの ゼロサーバー発見（DESIGN.md §2.6）
//
// 公開R2（r2Base 注入・正典 fetchRoster と同じパス/形状）＋ EthLock ログ（chain.js）。
// 運営サーバーの /my-group 等は使わない（検閲下で使えない）。
// バイト影響のある操作はないので config 注入で再現（byte-exact 対象外）。

import { keccak256, concatHex, stringToHex } from 'viem';
import { buildRosterMemberCommitment, createRosterMemberProof } from '../../vendor/workers/game_workers/lib/roster-member-root.js';
import { GameMasterDO } from '../../vendor/workers/game_workers/game-master-DO.js';
import { ChatGameDO } from '../../vendor/workers/game_workers/chat-game-DO.js';
import { canonicalRosterMember } from '../../vendor/workers/game_workers/lib/roster-canonical.js';
import { t, pickLang } from '../common/i18n.js';
import { formatRosterIntegrityWarning, rosterFallbackWarningKey, anchoredRosterErrorCode } from './roster-warning.js';
import {
  SELECTION_VERIFY_WALL_BUDGET_MS,
  verifySelectionIntegrity,
} from '../../vendor/workers/game_workers/lib/selection-integrity.js';
import {
  readSelectionAnchors,
  readResultHash,
  readCanonicalRosterRegistration,
  LEGACY_HASH_STORAGE_ALLOWLIST,
} from '../common/chain.js';
import {
  EXTERNAL_READ_TIMEOUT_MS,
  fetchBounded,
} from '../common/bounded-fetch.js';

export { LEGACY_HASH_STORAGE_ALLOWLIST };
const LEGACY_HASH_STORAGE_SET = new Set(LEGACY_HASH_STORAGE_ALLOWLIST);
const isLegacyHashStorage = (address) => LEGACY_HASH_STORAGE_SET.has(String(address).toLowerCase());

// 再照合で比較に使うのはチェーンの行だけ。R2 の全再構成をここでは行わない。
export async function readCanonicalRosterEvidence(client, contracts, blockNum) {
  const anchor = await readCanonicalRosterRegistration(client, contracts.hashStorage,
    contracts.evidence, blockNum, { legacyHashStorage: isLegacyHashStorage(contracts.hashStorage) });
  return {
    rosterAnchorStatus: anchor.row ? anchor.status : 'none',
    rosterObservedAtMs: anchor.observedAtMs,
    rosterAnchorHash: anchor.row?.hash ?? null,
    rosterAnchorIndex: anchor.index,
    chattingStartMs: anchor.chattingStartMs,
    chatCloseAtMs: anchor.chatCloseAtMs,
    lateCount: anchor.lateCount ?? 0,
  };
}

async function getJson(url, { signal = undefined, timeoutMs = EXTERNAL_READ_TIMEOUT_MS } = {}) {
  try {
    return await fetchBounded(url, { cache: 'no-store', signal }, {
      timeoutMs,
      label: `JSON read ${url}`,
      read: (response) => {
        if (!response.ok) return null;
        return response.json();
      },
    });
  } catch (error) {
    if (error?.code === 'external_read_unavailable') throw error;
    return null;
  }
}

async function getText(url, { signal = undefined, timeoutMs = EXTERNAL_READ_TIMEOUT_MS } = {}) {
  return fetchBounded(url, { cache: 'no-store', signal }, {
    timeoutMs,
    label: `text read ${url}`,
    read: (response) => response.ok ? response.text() : null,
  });
}

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export const FULL_ROSTER_FETCH_CONCURRENCY = 16;

export async function fetchAllRosterGroupTexts(r2Base, blockNum, manifest, timeoutMs = EXTERNAL_READ_TIMEOUT_MS) {
  if (!Array.isArray(manifest?.groups)) throw new Error('roster manifest groups are invalid');
  const groupTexts = new Map();
  const failedGroupIds = [];
  let next = 0;
  async function worker() {
    while (next < manifest.groups.length) {
      const group = manifest.groups[next++];
      try {
        const text = await getText(`${r2Base}/games/block${blockNum}/roster/group${group.groupId}.json`,
          { timeoutMs });
        if (!text) throw new Error('missing');
        groupTexts.set(group.groupId, text);
      } catch { failedGroupIds.push(group.groupId); }
    }
  }
  await Promise.all(Array.from({ length: Math.min(FULL_ROSTER_FETCH_CONCURRENCY, manifest.groups.length) }, worker));
  if (failedGroupIds.length) throw new Error(`roster group fetch failed: ${failedGroupIds.join(', ')}`);
  return groupTexts;
}

function proofForUid(commitment, groupTexts, blockNum, groupId, uid) {
  const roster = JSON.parse(groupTexts.get(groupId));
  const matching = roster.members.filter((member) => String(member.uid) === String(uid));
  if (matching.length !== 1) throw new Error('own uid is missing or duplicated in roster');
  const walletAddress = matching[0].walletAddress.toLowerCase();
  const sharedWalletUids = [...groupTexts.values()].reduce((sum, text) => sum
    + JSON.parse(text).members.filter((member) => String(member.walletAddress).toLowerCase() === walletAddress).length, 0);
  return { blockNum: Number(blockNum), groupId: Number(groupId), uid: String(uid),
    walletAddress, manifestHash: commitment.manifestHash, C: commitment.C,
    proof: createRosterMemberProof(commitment, walletAddress), sharedWalletUids };
}

export const ROSTER_VERIFICATION_TIMEOUT_MS = EXTERNAL_READ_TIMEOUT_MS;
export const RECOVERY_SELECTION_WALL_BUDGET_MS = SELECTION_VERIFY_WALL_BUDGET_MS;

async function withRosterVerificationTimeout(operation, timeoutMs) {
  const controller = new AbortController();
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error(`Roster verification timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });
  try {
    return await Promise.race([operation(controller.signal), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

export async function verifyLiveRosterAnchor({
  r2Base, blockNum, groupId, uid = null, client, hashStorage, evidence,
  timeoutMs = ROSTER_VERIFICATION_TIMEOUT_MS,
}) {
  try {
    const limit = Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0
      ? Number(timeoutMs) : ROSTER_VERIFICATION_TIMEOUT_MS;
    return await withRosterVerificationTimeout(async (signal) => {
      const [manifestRaw, anchored] = await Promise.all([
        getText(`${r2Base}/games/block${blockNum}/roster/manifest.json`, { signal, timeoutMs: limit }),
        readCanonicalRosterRegistration(client, hashStorage, evidence, blockNum,
          { legacyHashStorage: isLegacyHashStorage(hashStorage) }),
      ]);
      if (!anchored.row) {
        return {
          status: 'unavailable', reason: 'canonical roster registration is absent', blockNum, groupId,
          anchorStatus: anchored.status, observedAtMs: anchored.observedAtMs,
        };
      }
      if (!manifestRaw) {
        return { status: 'unavailable', reason: 'live roster file is unavailable', blockNum, groupId,
          anchorStatus: anchored.status, observedAtMs: anchored.observedAtMs };
      }
      let manifest;
      try {
        manifest = JSON.parse(manifestRaw);
      } catch {
        return { status: 'mismatch', reason: 'live roster file is not valid JSON', blockNum, groupId };
      }
      const groupTexts = await fetchAllRosterGroupTexts(r2Base, blockNum, manifest, limit);
      let commitment;
      try { commitment = buildRosterMemberCommitment({ blockNum, manifestText: manifestRaw, groupTexts }); }
      catch (error) { return { status: 'mismatch', reason: error.message, blockNum, groupId }; }
      if (String(commitment.C).toLowerCase() !== anchored.row.hash.toLowerCase()) {
        return { status: 'mismatch', reason: 'live roster commitment C mismatch', blockNum, groupId };
      }
      const roster = JSON.parse(groupTexts.get(Number(groupId)) || 'null');
      if (!roster || !Array.isArray(roster.members)) {
        return {
          status: 'mismatch', reason: 'live roster file does not match the anchored manifest', blockNum, groupId,
        };
      }
      return {
        status: 'verified', members: roster.members, updated: anchored.row.registeredBlock,
        anchorStatus: anchored.status, manifest, blockNum, groupId,
        observedAtMs: anchored.observedAtMs,
        rosterProof: uid == null ? null : proofForUid(commitment, groupTexts, blockNum, groupId, uid),
      };
    }, 240000);
  } catch (error) {
    return { status: 'unavailable', reason: error?.message || String(error), blockNum, groupId };
  }
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

function rosterMemberOf(data, globalIndex) {
  let bAddr = null;
  try {
    bAddr = typeof data?.bAddr === 'string' ? JSON.parse(data.bAddr) : data?.bAddr;
  } catch { bAddr = null; }
  return {
    uid: data?.uid,
    addr: data?.addr || null,
    bAddr: { address: bAddr?.address || null, pubKey: bAddr?.pubKey || null,
      nostrPubkey: bAddr?.nostrPubkey || null },
    depIds: typeof data?.depIds === 'string'
      ? data.depIds
      : JSON.stringify(data?.depIds || { ids: [] }),
    lang: data?.lang,
    globalIndex,
    name: typeof data?.name === 'string' && data.name && data.name.length <= 256 ? data.name : null,
    img: typeof data?.img === 'string' && data.img && data.img.length <= 2048 ? data.img : null,
    verified: data?.verified || false,
  };
}

function cachedRosterShape(member) {
  return canonicalRosterMember(member);
}


function comparableRosterMember(member) {
  const text = (value, field) => {
    if (typeof value !== 'string') throw new Error(`roster member ${field} is not a string`);
    return value;
  };
  if (!Array.isArray(member?.depositIds)) throw new Error('roster member depositIds is not an array');
  return {
    uid: text(member.uid, 'uid'),
    walletAddress: text(member.walletAddress, 'walletAddress').toLowerCase(),
    blockAddress: text(member.blockAddress, 'blockAddress').toLowerCase(),
    pubKey: text(member.pubKey, 'pubKey').toLowerCase(),
    nostrPubkey: text(member.nostrPubkey, 'nostrPubkey'),
    depositIds: member.depositIds.map((id) => text(id, 'depositId')),
    lang: text(member.lang, 'lang'),
    globalIndex: Number.isSafeInteger(member.globalIndex) && member.globalIndex >= 0
      ? member.globalIndex : (() => { throw new Error('roster member globalIndex is invalid'); })(),
    depositWei: text(member.depositWei, 'depositWei'),
    depositVerified: typeof member.depositVerified === 'boolean'
      ? member.depositVerified : (() => { throw new Error('roster member depositVerified is invalid'); })(),
  };
}

function assertAnchoredRosterFileForm(member) {
  const form = (value, pattern, field) => {
    if (typeof value !== 'string' || !pattern.test(value)) throw new Error(`anchored roster member ${field} is not in the writer form`);
  };
  form(member?.walletAddress, /^0x[0-9a-fA-F]{40}$/, 'walletAddress');
  form(member?.blockAddress, /^0x[0-9a-fA-F]{40}$/, 'blockAddress');
  form(member?.pubKey, /^0x04[0-9a-fA-F]{128}$/, 'pubKey');
  form(member?.nostrPubkey, /^[0-9a-f]{64}$/, 'nostrPubkey');
  form(member?.depositWei, /^(0|[1-9][0-9]*)$/, 'depositWei');
  if (Object.keys(member).join(',') !== 'uid,walletAddress,blockAddress,pubKey,nostrPubkey,depositIds,lang,globalIndex,depositWei,depositVerified') {
    throw new Error('anchored roster member is not the 10-key writer form');
  }
}

function anchoredRosterRuntimeMember(member, selected) {
  return {
    uid: member.uid,
    addr: member.walletAddress,
    bAddr: { address: member.blockAddress, pubKey: member.pubKey, nostrPubkey: member.nostrPubkey },
    depIds: selected.depIds,
    lang: member.lang,
    globalIndex: selected.globalIndex,
    name: selected.name,
    img: selected.img,
    verified: member.depositVerified,
  };
}

function selectionRosterMember(player) {
  const runtime = rosterMemberOf(player?.data, player?.globalIndex);
  let depositIds;
  try {
    const parsed = typeof player?.data?.depIds === 'string'
      ? JSON.parse(player.data.depIds) : player?.data?.depIds;
    if (!Array.isArray(parsed?.ids)) throw new Error('ids is not an array');
    depositIds = parsed.ids;
  } catch {
    throw new Error(`verified selection member ${String(runtime.uid)} has invalid depositIds`);
  }
  return {
    runtime,
    comparable: comparableRosterMember(canonicalRosterMember({ ...player.data, globalIndex: player.globalIndex })),
  };
}

function assertAnchoredRosterMatchesSelection(rosters, selection) {
  if (!Array.isArray(selection?.players)) {
    throw new Error('verified selection players are unavailable');
  }
  const selectedByUid = new Map();
  for (const player of selection.players) {
    const selected = selectionRosterMember(player);
    const uid = selected.comparable.uid;
    if (!uid || selectedByUid.has(uid)) {
      throw new Error(`verified selection contains an invalid or duplicate uid: ${uid || '(empty)'}`);
    }
    selectedByUid.set(uid, selected);
  }

  const anchoredByUid = new Map();
  for (const roster of rosters) {
    for (const member of roster.members) {
      if (!Array.isArray(member?.depositIds)) {
        throw new Error(`anchored roster member ${String(member?.uid)} has invalid depositIds`);
      }
      const comparable = comparableRosterMember(member);
      if (!comparable.uid || anchoredByUid.has(comparable.uid)) {
        throw new Error(`anchored roster contains an invalid or duplicate uid: ${comparable.uid || '(empty)'}`);
      }
      if (!selectedByUid.has(comparable.uid)) {
        throw new Error(`anchored roster uid ${comparable.uid} is not present in the verified selection`);
      }
      anchoredByUid.set(comparable.uid, { comparable, groupId: roster.groupId, member });
    }
  }
  if (anchoredByUid.size !== selectedByUid.size) {
    const missing = [...selectedByUid.keys()].filter((uid) => !anchoredByUid.has(uid));
    throw new Error(`anchored roster does not contain the full verified selection: missing ${missing.join(',') || '(unknown)'}`);
  }

  for (const [uid, selected] of selectedByUid) {
    const anchored = anchoredByUid.get(uid)?.comparable;
    const differing = ['walletAddress', 'blockAddress', 'pubKey', 'nostrPubkey', 'depositIds',
      'lang', 'globalIndex', 'depositWei', 'depositVerified']
      .filter((field) => !same(anchored?.[field], selected.comparable[field]));
    if (differing.length > 0) {
      throw new Error(`anchored roster member ${uid} differs from the verified selection: ${differing.join(',')}`);
    }
    assertAnchoredRosterFileForm(anchoredByUid.get(uid).member);
  }
  return selectedByUid;
}

function selectedRosterByUid(selection) {
  if (!Array.isArray(selection?.players)) {
    throw new Error('verified selection players are unavailable');
  }
  const selectedByUid = new Map();
  for (const player of selection.players) {
    const selected = selectionRosterMember(player);
    const uid = selected.comparable.uid;
    if (!uid || selectedByUid.has(uid)) {
      throw new Error(`verified selection contains an invalid or duplicate uid: ${uid || '(empty)'}`);
    }
    selectedByUid.set(uid, selected);
  }
  return selectedByUid;
}

function assertTargetRosterMatchesIndexAndSelection({ roster, groupId, rosterIndex, selectedByUid }) {
  const expectedUids = Object.keys(rosterIndex)
    .filter((uid) => Number(rosterIndex[uid]) === groupId);
  const actualUids = [];
  const seen = new Set();
  for (const member of roster.members) {
    if (!Array.isArray(member?.depositIds)) {
      throw new Error(`anchored roster member ${String(member?.uid)} has invalid depositIds`);
    }
    const comparable = comparableRosterMember(member);
    if (!comparable.uid || seen.has(comparable.uid)) {
      throw new Error(`anchored roster contains an invalid or duplicate uid: ${comparable.uid || '(empty)'}`);
    }
    seen.add(comparable.uid);
    actualUids.push(comparable.uid);
    const selected = selectedByUid.get(comparable.uid);
    if (!selected) {
      throw new Error(`anchored roster uid ${comparable.uid} is not present in the verified selection`);
    }
    const differing = ['walletAddress', 'blockAddress', 'pubKey', 'nostrPubkey', 'depositIds',
      'lang', 'globalIndex', 'depositWei', 'depositVerified']
      .filter((field) => !same(comparable[field], selected.comparable[field]));
    if (differing.length > 0) {
      throw new Error(`anchored roster member ${comparable.uid} differs from the verified selection: ${differing.join(',')}`);
    }
    assertAnchoredRosterFileForm(member);
  }
  if (expectedUids.length !== actualUids.length
      || expectedUids.some((uid) => !seen.has(uid))) {
    throw new Error(`anchored roster group ${groupId} uid set does not match the anchored index`);
  }
}

// N+1 の組分け後に N が変わり、再計算が実際の組を再現できない場合だけ使う。
// 現行配備は manifest → index → 対象group の3ファイルを検証する。indexSha256 が無い
// 旧配備だけ全groupへ落とす。各R2読取は独立した期限を持ち、全体のwall clockでは縛らない。
export async function resolveAnchoredRosterFromSelection({
  r2Base, blockNum, uid, client, hashStorage, evidence, selection,
  timeoutMs = ROSTER_VERIFICATION_TIMEOUT_MS,
  nowMs = Date.now(),
  canonicalAnchor = null,
}) {
  if (!client || !hashStorage) {
    throw recoveryError('anchored_roster_config_missing', 'chain client and HashStorage address are required for anchored roster fallback');
  }
  const limit = Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0
    ? Number(timeoutMs) : ROSTER_VERIFICATION_TIMEOUT_MS;
  const [manifestRaw, anchored] = await Promise.all([
    getText(`${r2Base}/games/block${blockNum}/roster/manifest.json`, { timeoutMs: limit })
      .catch((error) => { throw recoveryError('anchored_roster_manifest_unavailable', error?.message || String(error), error); }),
    canonicalAnchor || readCanonicalRosterRegistration(client, hashStorage, evidence, blockNum,
      { legacyHashStorage: isLegacyHashStorage(hashStorage) })
      .catch((error) => { throw recoveryError('anchored_roster_chain_read_failed', error?.message || String(error), error); }),
  ]);
  if (!manifestRaw) throw recoveryError('anchored_roster_manifest_unavailable', 'anchored roster manifest is unavailable');
  if (!anchored?.row) {
    throw recoveryError('anchored_roster_chain_anchor_unavailable', 'anchored roster chain anchor is unavailable');
  }
  let manifest;
  try { manifest = JSON.parse(manifestRaw); }
  catch { throw recoveryError('anchored_roster_manifest_invalid', 'anchored roster manifest is not valid JSON'); }
  if (Number(manifest?.blockNum) !== Number(blockNum)
      || !Array.isArray(manifest?.groups) || manifest.groups.length === 0) {
    throw recoveryError('anchored_roster_manifest_invalid', 'anchored roster manifest shape is invalid');
  }
  if (!Array.isArray(selection?.players) || manifest.groups.length > selection.players.length) {
    throw recoveryError('anchored_roster_selection_mismatch', 'anchored roster manifest group count exceeds the verified selection');
  }
  const groupIds = new Set();
  const entries = manifest.groups.map((entry) => {
    const groupId = Number(entry?.groupId);
    const sha256 = String(entry?.sha256 || '').toLowerCase();
    if (!Number.isSafeInteger(groupId) || groupId < 0 || groupIds.has(groupId)
        || !/^[0-9a-f]{64}$/.test(sha256)) {
      throw recoveryError('anchored_roster_manifest_invalid', 'anchored roster manifest has an invalid or duplicate group entry');
    }
    groupIds.add(groupId);
    return { groupId, sha256 };
  });
  let groupTexts;
  try { groupTexts = await fetchAllRosterGroupTexts(r2Base, blockNum, manifest, limit); }
  catch (error) { throw recoveryError('anchored_roster_group_unavailable', error?.message || String(error), error); }
  let commitment;
  try { commitment = buildRosterMemberCommitment({ blockNum, manifestText: manifestRaw, groupTexts }); }
  catch (error) { throw recoveryError('anchored_roster_commitment_invalid', error?.message || String(error), error); }
  if (String(commitment.C).toLowerCase() !== anchored.row.hash.toLowerCase()) {
    throw recoveryError('anchored_roster_commitment_mismatch', 'anchored roster commitment C does not match the on-chain anchor');
  }
  let selectedByUid;
  try { selectedByUid = selectedRosterByUid(selection); }
  catch (error) { throw recoveryError('anchored_roster_selection_mismatch', error?.message || String(error), error); }
  const targetUid = String(uid);

  if (manifest.indexSha256 !== undefined) {
    const expectedIndexSha256 = String(manifest.indexSha256 || '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(expectedIndexSha256)) {
      throw recoveryError('anchored_roster_manifest_invalid', 'anchored roster manifest indexSha256 is invalid');
    }
    let indexRaw;
    try {
      indexRaw = await getText(`${r2Base}/games/block${blockNum}/roster/index.json`, { timeoutMs: limit });
    } catch (error) {
      throw recoveryError('anchored_roster_index_unavailable', error?.message || String(error), error);
    }
    if (!indexRaw) throw recoveryError('anchored_roster_index_unavailable', 'anchored roster index is unavailable');
    if (await sha256Hex(indexRaw) !== expectedIndexSha256) {
      throw recoveryError('anchored_roster_index_mismatch', 'anchored roster index sha256 does not match the manifest');
    }
    let rosterIndex;
    try { rosterIndex = JSON.parse(indexRaw); }
    catch { throw recoveryError('anchored_roster_index_invalid', 'anchored roster index is not valid JSON'); }
    if (!rosterIndex || typeof rosterIndex !== 'object' || Array.isArray(rosterIndex)) {
      throw recoveryError('anchored_roster_index_invalid', 'anchored roster index shape is invalid');
    }
    const indexUids = Object.keys(rosterIndex);
    if (indexUids.length !== selectedByUid.size
        || indexUids.some((entryUid) => !selectedByUid.has(entryUid))
        || [...selectedByUid.keys()].some((entryUid) => !Object.hasOwn(rosterIndex, entryUid))) {
      const extra = indexUids.filter((entryUid) => !selectedByUid.has(entryUid));
      const missing = [...selectedByUid.keys()].filter((entryUid) => !Object.hasOwn(rosterIndex, entryUid));
      throw recoveryError('anchored_roster_selection_mismatch', `anchored roster index uid set does not match the verified selection: unexpected ${extra.join(',') || '(none)'}, missing ${missing.join(',') || '(none)'}`);
    }
    for (const entryUid of indexUids) {
      const indexedGroupId = Number(rosterIndex[entryUid]);
      if (!Number.isSafeInteger(indexedGroupId) || indexedGroupId < 0
          || !groupIds.has(indexedGroupId)) {
        throw recoveryError('anchored_roster_index_invalid', `anchored roster index has an invalid group for uid ${entryUid}`);
      }
    }
    if (!selectedByUid.has(targetUid)) {
      return {
        groupId: null, members: null, reason: 'uid_not_selected', source: 'anchored_roster',
        liveRosterCrossChecked: true, rosterAnchorUpdated: anchored.row.registeredBlock,
        rosterAnchorStatus: anchored.status,
      };
    }
    const groupId = Number(rosterIndex[targetUid]);
    const entry = entries.find((candidate) => candidate.groupId === groupId);
    const rosterRaw = groupTexts.get(groupId);
    if (!rosterRaw) throw recoveryError('anchored_roster_group_unavailable', `anchored roster group ${groupId} is unavailable`);
    if (await sha256Hex(rosterRaw) !== entry.sha256) {
      throw recoveryError('anchored_roster_group_mismatch', `anchored roster group ${groupId} sha256 does not match the manifest`);
    }
    let roster;
    try { roster = JSON.parse(rosterRaw); }
    catch { throw recoveryError('anchored_roster_group_invalid', `anchored roster group ${groupId} is not valid JSON`); }
    if (Number(roster?.blockNum) !== Number(blockNum)
        || Number(roster?.groupId) !== groupId || !Array.isArray(roster?.members)) {
      throw recoveryError('anchored_roster_group_invalid', `anchored roster group ${groupId} shape does not match the manifest`);
    }
    try { assertTargetRosterMatchesIndexAndSelection({ roster, groupId, rosterIndex, selectedByUid }); }
    catch (error) { throw recoveryError('anchored_roster_selection_mismatch', error?.message || String(error), error); }
    let rosterProof;
    try { rosterProof = proofForUid(commitment, groupTexts, blockNum, groupId, uid); }
    catch (error) { throw recoveryError('anchored_roster_proof_invalid', error?.message || String(error), error); }
    return {
      groupId,
      members: roster.members.map((member) => anchoredRosterRuntimeMember(member, selectedByUid.get(member.uid).runtime)),
      reason: null,
      source: 'anchored_roster',
      liveRosterCrossChecked: true,
      rosterAnchorUpdated: anchored.row.registeredBlock,
      rosterAnchorStatus: anchored.status,
      rosterProof,
    };
  }

  // indexSha256 の無い旧manifestだけを、全groupの個別期限付き読取へ戻す。
  const rosters = new Array(entries.length);
  let next = 0;
  async function worker() {
    while (next < entries.length) {
      const index = next++;
      const entry = entries[index];
      const rosterRaw = groupTexts.get(entry.groupId);
      if (!rosterRaw) throw recoveryError('anchored_roster_group_unavailable', `anchored roster group ${entry.groupId} is unavailable`);
      if (await sha256Hex(rosterRaw) !== entry.sha256) {
        throw recoveryError('anchored_roster_group_mismatch', `anchored roster group ${entry.groupId} sha256 does not match the manifest`);
      }
      let roster;
      try { roster = JSON.parse(rosterRaw); }
      catch { throw recoveryError('anchored_roster_group_invalid', `anchored roster group ${entry.groupId} is not valid JSON`); }
      if (Number(roster?.blockNum) !== Number(blockNum)
          || Number(roster?.groupId) !== entry.groupId || !Array.isArray(roster?.members)) {
        throw recoveryError('anchored_roster_group_invalid', `anchored roster group ${entry.groupId} shape does not match the manifest`);
      }
      rosters[index] = { groupId: entry.groupId, members: roster.members };
    }
  }
  await Promise.all(Array.from(
    { length: Math.min(FULL_ROSTER_FETCH_CONCURRENCY, entries.length) }, worker,
  ));
  let legacySelectedByUid;
  try { legacySelectedByUid = assertAnchoredRosterMatchesSelection(rosters, selection); }
  catch (error) { throw recoveryError('anchored_roster_selection_mismatch', error?.message || String(error), error); }
  if (!legacySelectedByUid.has(targetUid)) {
    return {
      groupId: null, members: null, reason: 'uid_not_selected', source: 'anchored_roster',
      liveRosterCrossChecked: true, rosterAnchorUpdated: anchored.row.registeredBlock,
      rosterAnchorStatus: anchored.status,
    };
  }
  const group = rosters.find((candidate) => (
    candidate.members.some((member) => String(member?.uid) === targetUid)
  ));
  if (!group) throw recoveryError('anchored_roster_selection_mismatch', `anchored roster does not place selected uid ${targetUid} in any group`);
  let rosterProof;
  try { rosterProof = proofForUid(commitment, groupTexts, blockNum, group.groupId, uid); }
  catch (error) { throw recoveryError('anchored_roster_proof_invalid', error?.message || String(error), error); }
  return {
    groupId: group.groupId,
    members: group.members.map((member) => anchoredRosterRuntimeMember(member, legacySelectedByUid.get(member.uid).runtime)),
    reason: null,
    source: 'anchored_roster',
    liveRosterCrossChecked: true,
    rosterAnchorUpdated: anchored.row.registeredBlock,
    rosterAnchorStatus: anchored.status,
    rosterProof,
  };
}

function recoveryError(code, message, cause = undefined) {
  const error = new Error(message, cause === undefined ? undefined : { cause });
  error.code = code;
  return error;
}

async function verifyPreviousSummaryAnchor({
  r2Base, blockNum, client, contracts, externalReadTimeoutMs = EXTERNAL_READ_TIMEOUT_MS,
}) {
  if (blockNum === 0) return null;
  const prev = blockNum - 1;
  const summaryKey = `games/block${prev}/summary.json`;
  let summaryRaw;
  let manifestRaw;
  let anchored;
  try {
    [summaryRaw, manifestRaw, anchored] = await Promise.all([
      getText(`${r2Base}/${summaryKey}`, { timeoutMs: externalReadTimeoutMs }),
      getText(`${r2Base}/verification/block${prev}/manifest.json`, { timeoutMs: externalReadTimeoutMs }),
      readResultHash(client, contracts.hashStorage, prev),
    ]);
  } catch (error) {
    throw recoveryError(
      'previous_summary_anchor_unavailable',
      `previous block ${prev} result anchor could not be read: ${error?.message || String(error)}`,
      error,
    );
  }
  if (summaryRaw == null || manifestRaw == null || !anchored?.updated) {
    throw recoveryError(
      'previous_summary_anchor_unavailable',
      `previous block ${prev} result anchor is unavailable`,
    );
  }
  let summary;
  let manifest;
  try { summary = JSON.parse(summaryRaw); manifest = JSON.parse(manifestRaw); }
  catch (error) {
    throw recoveryError(
      'previous_summary_anchor_invalid',
      `previous block ${prev} result artifact is invalid JSON: ${error.message}`,
      error,
    );
  }
  const coreHash = '0x' + await sha256Hex(JSON.stringify({
    blockNum: manifest.blockNum,
    algorithm: manifest.algorithm,
    rules: manifest.rules,
    files: manifest.files,
  }));
  if (coreHash !== anchored.hash) {
    throw recoveryError(
      'previous_summary_anchor_mismatch',
      `previous block ${prev} manifest does not match on-chain resultHash`,
    );
  }
  if (manifest.files?.[summaryKey] !== await sha256Hex(summaryRaw)) {
    throw recoveryError(
      'previous_summary_anchor_mismatch',
      `previous block ${prev} summary does not match the anchored manifest`,
    );
  }
  return summary;
}

// 本番の D1 行形は GameMasterDO.writeGroupsToD1 の map と同じ。
// index と group のバイトは vendor の書き手を実行して得る。manifest 最終式だけは
// rebuildAndPublishRosterManifest が DO の R2/DB に結合しているためここで写す。
export async function buildRecomputedRosterManifest(blockNum, computedGroups) {
  const gm = new GameMasterDO({ storage: {} }, {});
  const rows = computedGroups.map((group) => ({
    group_id: group.groupId,
    members: group.members.map((m) => ({
      uid: m.data?.uid, addr: m.data?.addr, bAddr: m.data?.bAddr,
      lang: m.data?.lang, depIds: m.data?.depIds, globalIndex: m.globalIndex,
      name: m.data?.name || null, img: m.data?.img || null,
      verified: m.data?.verified || false,
    })),
  }));
  const orderedRows = [...rows].sort((a, b) => Number(a.group_id) - Number(b.group_id));
  const indexText = JSON.stringify(gm.buildRosterIndex(orderedRows));
  const indexSha256 = await sha256Hex(indexText);
  const groups = [];
  const groupTexts = new Map();
  for (const row of rows) {
    let rosterText = null;
    const writer = {
      env: { R2_BUCKET: { put: async (_key, text) => { rosterText = text; } } },
      storage: { put: async () => {} },
      recordDependencyOutcome: () => {},
    };
    const sha256 = await ChatGameDO.prototype.publishRosterFile.call(
      writer, blockNum, row.group_id, row.members,
    );
    if (typeof rosterText !== 'string' || sha256 !== await sha256Hex(rosterText)) {
      throw new Error(`recomputed roster group ${row.group_id} writer did not produce expected bytes`);
    }
    groupTexts.set(Number(row.group_id), rosterText);
    groups.push({ groupId: Number(row.group_id), sha256 });
  }
  groups.sort((a, b) => a.groupId - b.groupId);
  const manifestText = JSON.stringify({ blockNum: Number(blockNum), indexSha256, groups });
  const commitment = buildRosterMemberCommitment({ blockNum, manifestText, groupTexts });
  return { manifestText, indexText, groups, groupTexts, hash: commitment.C, commitment };
}

async function fetchCommittedInfos(r2Base, blockNum, externalReadTimeoutMs = EXTERNAL_READ_TIMEOUT_MS) {
  const infos = new Array(100);
  let next = 0;
  async function worker() {
    while (next < infos.length) {
      const i = next++;
      const key = `${i.toString().padStart(2, '0')}_info.json`;
      infos[i] = await getJson(`${r2Base}/entries/block${blockNum}/info/${key}`, {
        timeoutMs: externalReadTimeoutMs,
      });
    }
  }
  await Promise.all(Array.from({ length: 10 }, worker));
  let total = 0;
  for (let i = 0; i < infos.length; i++) {
    if (!Array.isArray(infos[i]?.entries)) throw new Error(`committed info file ${i} is missing or invalid`);
    for (const f of infos[i].entries) {
      if (!Number.isSafeInteger(f?.number) || f.number < 0) throw new Error(`committed info file ${i} has invalid count`);
      total += f.number;
    }
  }
  return { infos, total };
}

async function verifySelectionIntegrityToCompletion(selectionIntegrityVerifier, args) {
  let resumeFrom = 0;
  while (true) {
    try {
      return await selectionIntegrityVerifier({ ...args, resumeFrom });
    } catch (error) {
      if (!error?.resumable) throw error;
      const nextResumeFrom = Number(error.selectionResumeFrom);
      if (!Number.isSafeInteger(nextResumeFrom) || nextResumeFrom <= resumeFrom) {
        throw new Error(
          `selection integrity returned an invalid resume cursor: current=${resumeFrom}, next=${error.selectionResumeFrom}`,
          { cause: error },
        );
      }
      resumeFrom = nextResumeFrom;
      // ブラウザの同一 invocation 内で正典カーソルを引き継ぐ。各回の有限 wall budget は
      // 維持しつつ、次 chunk の前に描画・入力イベントへ制御を返す。
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }
}

// V25-03: 平時は selection + previous anchored result から正典 formGroups を再実行する。
// 前 block の照合不能・game_groups の欠落/不一致時だけ、chain 錨つき roster から実際の組分けを復元する。
export async function reconstructCommittedRoster({
  r2Base, blockNum, uid, client, contracts, maxPlayers = 2100, confirmationBlocks = 64,
  externalReadTimeoutMs = EXTERNAL_READ_TIMEOUT_MS,
  selectionWallBudgetMs = RECOVERY_SELECTION_WALL_BUDGET_MS,
  selectionAnchorsReader = readSelectionAnchors,
  selectionIntegrityVerifier = verifySelectionIntegrity,
  previousSummaryVerifier = verifyPreviousSummaryAnchor,
  anchoredRosterResolver = resolveAnchoredRosterFromSelection,
  rosterRegistrationReader = readCanonicalRosterRegistration,
  onWarning = () => {},
}) {
  if (!client || !contracts?.hashStorage || !contracts?.evidence) {
    throw new Error('chain client and HashStorage/Evidence addresses are required for roster reconstruction');
  }
  const selection = await getJson(`${r2Base}/entries/block${blockNum}/game_selection.json`, {
    timeoutMs: externalReadTimeoutMs,
  });
  if (!selection || !Array.isArray(selection.players)) throw new Error('game_selection.json is missing or invalid');

  const anchors = await selectionAnchorsReader(
    client,
    contracts,
    blockNum,
    confirmationBlocks,
    selection,
    { legacyHashStorage: LEGACY_HASH_STORAGE_SET.has(String(contracts.hashStorage).toLowerCase()) },
  );
  const selectionDiffersFromLatest = String(selection.applicantHash).toLowerCase() !== anchors.applicantHash
    || Number(selection.hashRegisteredBlock) !== anchors.applicantUpdatedBlock;
  if (anchors.registrationCount !== 1 || selectionDiffersFromLatest) {
    try {
      onWarning({
        code: 'applicantHashRegistrationCount',
        registrationCount: anchors.registrationCount,
        expected: 1,
        selectionDiffersFromLatest,
        selectionApplicantHash: String(selection.applicantHash).toLowerCase(),
        selectionRegisteredBlock: Number(selection.hashRegisteredBlock),
        latestApplicantHash: anchors.applicantHash,
        latestRegisteredBlock: anchors.applicantUpdatedBlock,
      });
    } catch { /* warning display failure must not stop recovery */ }
  }
  if (anchors.selectionRegistered !== true) {
    throw new Error('game_selection.json applicant registration is not present in HashStorage history');
  }
  if (Number(selection.confirmationBlocks) !== Number(confirmationBlocks)) {
    throw new Error(`selection confirmationBlocks=${selection.confirmationBlocks}, expected ${confirmationBlocks}`);
  }
  const targetBlockNum = Number(selection.hashRegisteredBlock) + Number(confirmationBlocks);
  if (Number(selection.targetBlockNum) !== targetBlockNum
      || anchors.randaoEthBlockNumber !== targetBlockNum) {
    throw new Error('selection RANDAO target block does not match the committed confirmation rule');
  }
  const target = await client.getBlock({ blockNumber: BigInt(targetBlockNum) });
  const targetHash = String(target.hash).toLowerCase();
  const targetRandao = String(target.mixHash).toLowerCase();
  if (String(selection.targetBlockHash).toLowerCase() !== targetHash
      || anchors.randaoBlockHash !== targetHash
      || String(selection.randao).toLowerCase() !== targetRandao) {
    throw new Error('selection RANDAO/hash does not match the anchored Ethereum block');
  }

  const { infos, total } = await fetchCommittedInfos(r2Base, blockNum, externalReadTimeoutMs);
  await verifySelectionIntegrityToCompletion(selectionIntegrityVerifier, {
    blockNum, selectionData: selection, committedTotal: total, maxPlayers, infos,
    wallBudgetMs: selectionWallBudgetMs,
    readEntryFile: (filename) => getJson(
      `${r2Base}/entries/block${blockNum}/entries/${filename}.json`,
      { timeoutMs: externalReadTimeoutMs },
    ),
  });

  // R31-U-B: 起動に使う組は開始前の最後の登録に束縛する。公開名簿を
  // 読める場合はその組を採り、欠ける場合だけ同じ manifest bytes を再計算する。
  const anchor = await rosterRegistrationReader(
    client, contracts.hashStorage, contracts.evidence, blockNum,
    { legacyHashStorage: isLegacyHashStorage(contracts.hashStorage) },
  );
  if (!anchor?.row) {
    throw recoveryError('canonical_roster_anchor_absent',
      `canonical roster registration is absent for block ${blockNum}. ${formatRosterIntegrityWarning(
        { rosterAnchorCheckStatus: 'absent' }, t(pickLang()),
      )}`);
  }
  const anchorEvidence = {
    rosterAnchorHash: anchor.row.hash, rosterAnchorIndex: anchor.index,
    rosterObservedAtMs: anchor.observedAtMs,
    chattingStartMs: anchor.chattingStartMs,
    lateCount: anchor.lateCount ?? 0,
  };
  let anchorError = null;
  let anchorErrorCode = 'unknown';
  try {
    const anchored = await anchoredRosterResolver({
      r2Base, blockNum, uid, client, hashStorage: contracts.hashStorage,
      evidence: contracts.evidence, selection, timeoutMs: externalReadTimeoutMs,
      canonicalAnchor: anchor,
    });
    return { ...anchored, ...anchorEvidence, rosterAnchorStatus: anchor.status,
      anchoredRosterFallback: anchor.status === 'legacy' };
  } catch (error) {
    anchorError = error?.message || String(error);
    anchorErrorCode = anchoredRosterErrorCode(error);
    console.warn('[recovery] anchored roster verification failed:', anchorError);
  }

  try { selectedRosterByUid(selection); }
  catch (cause) {
    const error = recoveryError('roster_reconstruction_unavailable',
      'selection roster member is malformed', cause);
    error.rosterAnchorHash = anchor.row.hash;
    error.rosterAnchorIndex = anchor.index;
    throw error;
  }

  let fallback = null;
  let previousSummary = null;
  try {
    previousSummary = await previousSummaryVerifier({
      r2Base, blockNum, client, contracts, externalReadTimeoutMs,
    });
  } catch (error) {
    fallback = {
      code: error?.code || 'previous_summary_anchor_invalid',
      detail: error?.message || String(error),
    };
  }
  const gm = new GameMasterDO({ storage: {} }, {});
  gm.getR2Object = async (key) => {
    if (blockNum > 0 && key === `games/block${blockNum - 1}/summary.json`) return previousSummary;
    return null;
  };
  const groupSeed = keccak256(concatHex([
    selection.randao, selection.applicantHash, stringToHex('group'),
  ]));
  let majorLangs = null;
  let groups = null;
  if (!fallback) {
    majorLangs = await gm.computeMajorLangs(blockNum);
    groups = await gm.formGroups(selection.players, groupSeed, majorLangs);
    const published = await getJson(`${r2Base}/entries/block${blockNum}/game_groups.json`, {
      timeoutMs: externalReadTimeoutMs,
    });
    if (!published) {
      fallback = {
        code: 'published_game_groups_unavailable',
        detail: 'published game_groups.json is unavailable or invalid',
      };
    } else {
      const expectedGroups = groups.map((g) => ({
        groupId: g.groupId, lang: g.lang, mixed: g.mixed,
        memberCount: g.members.length,
        memberIds: g.members.map((m) => m.data?.uid || m.globalIndex),
      }));
      if (published.blockNum !== blockNum
          || published.totalPlayers !== selection.players.length
          || published.totalGroups !== groups.length
          || String(published.groupSeed).toLowerCase() !== groupSeed
          || !same(published.groups, expectedGroups)) {
        fallback = {
          code: 'published_game_groups_mismatch',
          detail: 'published game_groups.json does not match reconstructed grouping',
        };
      }
    }
  }

  if (!groups) {
    const stop = {
      rosterAnchorCheckStatus: 'reconstruction_unavailable',
      anchoredRosterFallbackReason: fallback?.code,
      rosterAnchorHash: anchor.row.hash, rosterAnchorIndex: anchor.index,
    };
    const error = recoveryError(fallback?.code || 'roster_reconstruction_unavailable',
      `roster files unavailable (${anchorError}); ${fallback?.detail || 'grouping unavailable'}. ${formatRosterIntegrityWarning(
        stop, t(pickLang()),
      )}`);
    error.warningKey = rosterFallbackWarningKey(stop);
    error.rosterWarning = stop;
    error.rosterAnchorHash = anchor.row.hash;
    error.rosterAnchorIndex = anchor.index;
    throw error;
  }
  const recomputed = await buildRecomputedRosterManifest(blockNum, groups);
  if (recomputed.hash.toLowerCase() !== anchor.row.hash) {
    const mismatch = {
      rosterAnchorCheckStatus: 'mismatch',
      rosterAnchorHash: anchor.row.hash, rosterAnchorIndex: anchor.index,
      recomputedHash: recomputed.hash,
    };
    const error = recoveryError('recomputed_roster_anchor_mismatch',
      `recomputed roster manifest does not match canonical on-chain hash for block ${blockNum}; roster files: ${anchorError}. ${formatRosterIntegrityWarning(
        mismatch, t(pickLang()),
      )}`);
    error.warningKey = rosterFallbackWarningKey(mismatch);
    error.rosterWarning = mismatch;
    error.rosterAnchorHash = anchor.row.hash;
    error.rosterAnchorIndex = anchor.index;
    error.recomputedHash = recomputed.hash;
    throw error;
  }
  const group = groups.find((g) => g.members.some((m) => String(m.data?.uid) === String(uid)));
  if (!group) return { groupId: null, members: null, reason: 'uid_not_selected', source: 'committed_selection',
    rosterAnchorStatus: anchor.status, ...anchorEvidence };
  const members = group.members.map((m) => rosterMemberOf(m.data, m.globalIndex));
  return { groupId: group.groupId, members, reason: null, source: 'committed_selection',
    rosterProof: proofForUid(recomputed.commitment, recomputed.groupTexts,
      blockNum, group.groupId, uid),
    recomputedRosterFallback: true, recomputedRosterFallbackReason: 'canonical_manifest_match',
    recomputedRosterFallbackDetail: fallback?.detail || null,
    recomputedRosterFallbackAnchorError: anchorErrorCode,
    rosterAnchorStatus: anchor.status, majorLangs, groupSeed,
    ...anchorEvidence };
}

// liveRosterVerifier は注入専用。既定の錨つき名簿・再計算経路は上で返る。
// 平時は commit から再構築して cache を照合し、限定 fallback 時だけ検証済み錨つき roster の組を採る。
export async function fetchRoster(r2Base, blockNum, uid, options = {}) {
  if (options.client) {
    const rosterReconstructor = options.rosterReconstructor || reconstructCommittedRoster;
    const liveRosterVerifier = options.liveRosterVerifier || verifyLiveRosterAnchor;
    const reconstructed = await rosterReconstructor({
      r2Base, blockNum, uid,
      client: options.client,
      contracts: options.contracts,
      maxPlayers: options.maxPlayers,
      confirmationBlocks: options.confirmationBlocks,
      selectionAnchorsReader: options.selectionAnchorsReader,
      selectionIntegrityVerifier: options.selectionIntegrityVerifier,
      previousSummaryVerifier: options.previousSummaryVerifier,
      anchoredRosterResolver: options.anchoredRosterResolver,
      rosterRegistrationReader: options.rosterRegistrationReader,
      externalReadTimeoutMs: options.externalReadTimeoutMs,
      selectionWallBudgetMs: options.selectionWallBudgetMs,
      onWarning: options.onWarning,
    });
    if (reconstructed.groupId == null) return reconstructed;
    if (reconstructed.source === 'anchored_roster'
        || reconstructed.recomputedRosterFallback === true) return reconstructed;

    const live = await liveRosterVerifier({
      r2Base, blockNum, groupId: reconstructed.groupId, uid,
      client: options.client, hashStorage: options.contracts.hashStorage,
      evidence: options.contracts.evidence,
      timeoutMs: options.externalReadTimeoutMs,
    });
    if (live.status === 'verified') {
      const expected = reconstructed.members.map(cachedRosterShape);
      const actual = live.members;
      reconstructed.rosterMismatchCommitted = !same(actual, expected);
      reconstructed.liveRosterCrossChecked = true;
      reconstructed.rosterAnchorUpdated = live.updated;
      reconstructed.rosterProof = live.rosterProof;
    } else {
      reconstructed.reason = live.reason || 'live_roster_unavailable_reconstructed';
    }
    return reconstructed;
  }

  // 後方互換のオフライン読取。実アプリはchain付き経路だけを使う。
  const index = await getJson(`${r2Base}/games/block${blockNum}/roster/index.json`, {
    timeoutMs: options.externalReadTimeoutMs,
  });
  if (!index) return { groupId: null, members: null, reason: 'no_roster_index' };
  const groupId = index[uid];
  if (groupId === undefined || groupId === null) return { groupId: null, members: null, reason: 'uid_not_in_index' };
  const group = await getJson(`${r2Base}/games/block${blockNum}/roster/group${groupId}.json`, {
    timeoutMs: options.externalReadTimeoutMs,
  });
  if (!group || !Array.isArray(group.members)) return { groupId, members: null, reason: 'no_roster_group' };
  // members を GameRelayChannel/bundle が期待する形に整える（bAddr は {address, pubKey}）
  const members = group.members.map((m) => ({
    uid: m.uid,
    addr: m.walletAddress || null,
    bAddr: { address: m.blockAddress, pubKey: m.pubKey, nostrPubkey: m.nostrPubkey },
    depIds: JSON.stringify({ ids: Array.isArray(m.depositIds) ? m.depositIds : [], deposit: m.depositWei }),
    lang: m.lang,
    globalIndex: m.globalIndex,
    verified: m.depositVerified === true,
  }));
  return { groupId, members, reason: null };
}

// 開始境界の復元用。固定ブロックの時刻が現在の開始へ達した確定行だけを返す。
// 一過性の読取失敗と暫定観測は表示して再試行する。R2 再構成の失敗だけ間隔を伸ばす。
export async function pollRecoveryRosterAtStart(fetchCurrent, getChattingStartMs, {
  wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  delayMs = 1000, shouldContinue = () => true, onObservation = () => {},
  getChatCloseAtMs = () => Infinity,
} = {}) {
  const ordinaryDelayMs = Math.min(Math.max(1, delayMs), 1000);
  let reconstructionDelayMs = ordinaryDelayMs;
  while (shouldContinue()) {
    let result;
    let waitMs = ordinaryDelayMs;
    try {
      result = await fetchCurrent();
      reconstructionDelayMs = ordinaryDelayMs;
    }
    catch (error) {
      // R2 再構成の恒久的な不一致は、同じ bytes を毎秒読み直しても直らない。
      if (error?.warningKey || [
        'recomputed_roster_anchor_mismatch', 'roster_reconstruction_unavailable',
      ].includes(error?.code)) throw error;
      if (error?.rosterReconstructionRetry) {
        waitMs = reconstructionDelayMs;
        reconstructionDelayMs = Math.min(reconstructionDelayMs * 2, 30000);
      }
      result = { rosterAnchorStatus: 'unavailable', reason: error?.message || String(error) };
    }
    if (!shouldContinue()) break;
    onObservation(result);
    const start = getChattingStartMs();
    if (result?.rosterAnchorStatus === 'none'
        && Number.isFinite(result.rosterObservedAtMs)
        && (!Number.isFinite(result.chattingStartMs)
          || result.chattingStartMs === start)
        && result.rosterObservedAtMs >= (Number.isFinite(result.chatCloseAtMs)
          ? result.chatCloseAtMs : getChatCloseAtMs())) {
      throw recoveryError('canonical_roster_anchor_absent',
        'canonical roster registration is absent after chatCloseAt');
    }
    if (result?.reason === 'uid_not_selected') return result;
    if (['canonical', 'legacy'].includes(result?.rosterAnchorStatus)
        && Number.isFinite(start)
        && Number.isFinite(result?.rosterObservedAtMs)
        && result.rosterObservedAtMs >= start
        && (!Number.isFinite(result.chattingStartMs)
          || result.chattingStartMs === start)) return result;
    await wait(waitMs);
  }
  return null;
}

export function finalRosterHashMatches(roster, expectedHash, chattingStartMs) {
  return ['canonical', 'legacy'].includes(roster?.rosterAnchorStatus)
    && Number.isFinite(chattingStartMs)
    && Number.isFinite(roster?.rosterObservedAtMs)
    && roster.rosterObservedAtMs >= chattingStartMs
    && (!Number.isFinite(roster.chattingStartMs)
      || roster.chattingStartMs === chattingStartMs)
    && typeof roster?.rosterAnchorHash === 'string'
    && typeof expectedHash === 'string'
    && roster.rosterAnchorHash.toLowerCase() === expectedHash.toLowerCase();
}

// wallet → uid 候補。検索キーは「プレイヤーがエントリー時に登録した引き出しアドレス」のみ。
//
// EthLock の Deposited ログからは引けない。idFrom はデポジッター、idTo は資金を受けたプレイヤーで、
// どちらもコントラクト未検証の自己申告 JSON である上、そもそも「引き出しアドレスの登録」という
// 束縛はチェーン上に存在しない（オフチェーンのエントリー情報）。実測でも同一ウォレットが複数の
// デポジッターIDを名乗り、かつ別プレイヤーの引き出しアドレスでもあり得ることを確認済み。
// よって登録アドレスを載せている R2 の2系統（selection / summary）だけを照合する。
export async function discoverUidCandidates({ r2Base, blockNum, walletAddress }) {
  const wallet = String(walletAddress).toLowerCase();
  const candidates = new Map(); // uid -> { source, name?, img? }

  // Route B: R2 game_selection.json（当該ブロックの選出者に addr が載る）
  const selection = await getJson(`${r2Base}/entries/block${blockNum}/game_selection.json`);
  if (selection && Array.isArray(selection.players)) {
    for (const pl of selection.players) {
      const data = pl?.data;
      const addr = data?.addr;
      if (typeof addr !== 'string' || addr.toLowerCase() !== wallet) continue;
      if (typeof data.uid !== 'string' || data.uid === '') continue;
      if (!candidates.has(data.uid)) candidates.set(data.uid, { source: 'r2_selection',
        name: typeof data.name === 'string' && data.name.length <= 256 ? data.name : null, img: typeof data.img === 'string' && data.img.length <= 2048 ? data.img : null });
    }
  }

  // Route C: R2 summary.json（groups[].members[].address）
  const summary = await getJson(`${r2Base}/games/block${blockNum}/summary.json`);
  if (summary && Array.isArray(summary.groups)) {
    for (const g of summary.groups) {
      for (const m of (Array.isArray(g?.members) ? g.members : [])) {
        if (typeof m?.address !== 'string' || m.address.toLowerCase() !== wallet) continue;
        if (typeof m.userId !== 'string' || m.userId === '') continue;
        if (!candidates.has(m.userId)) candidates.set(m.userId, { source: 'r2_summary',
          name: typeof m.name === 'string' && m.name.length <= 256 ? m.name : null, img: typeof m.img === 'string' && m.img.length <= 2048 ? m.img : null });
      }
    }
  }

  return [...candidates.entries()].map(([uid, v]) => ({ uid, ...v }));
}

// ゲーム無し（autoDistribute / ≤2名）判定 — computeMajorLangs と同じロジック（§2.6）。
// 戻り: { held: bool, reason }。held=false は「ゲーム無し（自動配布/≤2名）」、
//        held=null は「未確定/判定不能」（roster欠落だけでは no-game と断じない）。
export async function detectGameHeld({ r2Base, blockNum }) {
  const summary = await getJson(`${r2Base}/games/block${blockNum}/summary.json`);
  if (summary) {
    if (summary.autoDistributed === true) return { held: false, reason: 'auto_distributed' };
    if (Array.isArray(summary.groups) && summary.groups.some((g) => g?.status === 'auto_distributed')) {
      return { held: false, reason: 'auto_distributed_group_status' };
    }
    return { held: true, reason: 'summary_present' };
  }
  // summary 無し → game_selection で判定
  const selection = await getJson(`${r2Base}/entries/block${blockNum}/game_selection.json`);
  if (selection && Array.isArray(selection.players)) {
    if (selection.players.length <= 2) return { held: false, reason: 'players_le_2' };
    return { held: null, reason: 'results_not_ready' }; // 3名以上なのに summary 無し = 未確定
  }
  return { held: null, reason: 'selection_missing' };
}

// Stage 3 production witness builder.
//
// This module only maps already-authoritative production data to the private
// input shape consumed by crates/group-guest. It does not score, aggregate, or
// submit anything on-chain.

import { keccak256, toHex } from 'viem';

import { canonicalizeDepositIds } from '../../entry_workers/lib/deposit-id.js';
import { decodeSubmissionPayloadString } from './evidence-compact-v1.js';
import { actionSnapshotPreimage } from './game-result-calculator.js';
import { canonMetaInt, isCanonicalUid, parseBlockAddress } from './protocol-v2.js';
import { MAX_DEPOSIT_IDS, MAX_GROUP_PLAYERS } from './submission-limits.js';

export const GROUP_WITNESS_SCHEMA_VERSION = 1;

const MAX_SAFE_META = Number.MAX_SAFE_INTEGER;
const MAX_U128 = (1n << 128n) - 1n;
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const HASH_RE = /^0x[0-9a-f]{64}$/;

function own(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function uidMap(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`[group-witness] ${label} must be an object keyed by uid`);
  }
  return Object.assign(Object.create(null), value);
}

function address(value, label) {
  if (typeof value !== 'string' || !ADDRESS_RE.test(value)) {
    throw new Error(`[group-witness] ${label} must be a 20-byte 0x address`);
  }
  return value;
}

function verifiedWei(value, uid) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`[group-witness] verified deposit row for uid=${uid} is not canonical wei`);
  }
  const n = BigInt(value);
  if (n > MAX_U128) {
    throw new Error(`[group-witness] verified deposit row for uid=${uid} exceeds u128`);
  }
  return value;
}

function authoritativeDepositIds(raw, uid) {
  let parsed;
  try {
    parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
  } catch (error) {
    throw new Error(`[group-witness] D1 depIds for uid=${uid} is invalid JSON: ${error.message}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || !Array.isArray(parsed.ids)) {
    throw new Error(`[group-witness] D1 depIds for uid=${uid} has no ids array`);
  }
  if (parsed.ids.length > MAX_DEPOSIT_IDS) {
    throw new Error(`[group-witness] authoritative depositIds for uid=${uid} exceed ${MAX_DEPOSIT_IDS}`);
  }
  const canonical = canonicalizeDepositIds(parsed.ids);
  if (canonical.length !== parsed.ids.length
      || canonical.some((id, index) => id !== parsed.ids[index])) {
    throw new Error(`[group-witness] authoritative depositIds for uid=${uid} are not canonical, unique BigInt order`);
  }
  return canonical;
}

function utf16Units(value, label) {
  if (typeof value !== 'string') {
    // The accepted compact format always carries strings. Keep the guest's
    // historical null/missing mapping out of this production-only path.
    throw new Error(`[group-witness] ${label} must be a string`);
  }
  const units = new Array(value.length);
  for (let i = 0; i < value.length; i++) units[i] = value.charCodeAt(i);
  return units;
}

function normalizedChatWindow(chatWindow) {
  if (chatWindow == null) return null;
  if (!chatWindow || typeof chatWindow !== 'object' || Array.isArray(chatWindow)) {
    throw new Error('[group-witness] chatWindow must be null or {startMs,endMs}');
  }
  const { startMs, endMs } = chatWindow;
  if (!Number.isSafeInteger(startMs) || !Number.isSafeInteger(endMs)
      || Math.abs(startMs) > MAX_SAFE_META || Math.abs(endMs) > MAX_SAFE_META
      || startMs > endMs) {
    throw new Error('[group-witness] chatWindow must contain ordered safe-integer milliseconds');
  }
  return { startMs, endMs };
}

/**
 * Build the exact validation-(2.6) preimage and fail before zkVM execution if
 * its keccak does not equal the wallet-signed encryptedDataHash.
 *
 * The preimage function is deliberately imported from the JS scoring canon.
 */
export function actionSnapshotBytesForWitness(bundle, uid = bundle?.uid) {
  const preimage = actionSnapshotPreimage(bundle?.encryptedActions);
  if (preimage === null) {
    throw new Error(`[group-witness] action snapshot preimage cannot be built for uid=${uid}`);
  }
  const declared = bundle?.encryptedDataHash;
  const actual = keccak256(toHex(preimage));
  if (typeof declared !== 'string' || !HASH_RE.test(declared) || actual !== declared) {
    throw new Error(
      `[group-witness] action snapshot preimage hash mismatch for uid=${uid}: `
      + `declared=${String(declared)} actual=${actual}`,
    );
  }
  return preimage;
}

function parseRoster(membersText, verifiedDepositWei) {
  if (typeof membersText !== 'string') {
    throw new Error('[group-witness] game_groups.members must be the D1 TEXT value');
  }
  let rows;
  try {
    rows = JSON.parse(membersText);
  } catch (error) {
    throw new Error(`[group-witness] game_groups.members is invalid JSON: ${error.message}`);
  }
  if (!Array.isArray(rows) || rows.length < 1 || rows.length > MAX_GROUP_PLAYERS) {
    throw new Error(`[group-witness] game_groups.members length must be 1..${MAX_GROUP_PLAYERS}`);
  }
  const seen = new Set();
  return rows.map((member, index) => {
    const uid = member?.uid;
    if (!isCanonicalUid(uid) || seen.has(uid)) {
      throw new Error(`[group-witness] invalid or duplicate roster uid at members[${index}]`);
    }
    seen.add(uid);
    if (!own(verifiedDepositWei, uid)) {
      // Do not encode false: the JS canon throws for an incomplete authority
      // table, and the guest's false flag is only the corresponding rejection.
      throw new Error(`[group-witness] verified deposit table is incomplete: uid=${uid}`);
    }
    const parsedBlockAddress = parseBlockAddress(member.bAddr);
    if (!parsedBlockAddress) {
      throw new Error(`[group-witness] D1 bAddr is invalid for uid=${uid}`);
    }
    return {
      uid,
      blockAddress: address(parsedBlockAddress.address, `blockAddress for uid=${uid}`),
      walletAddress: address(member.addr, `walletAddress for uid=${uid}`),
      depositWei: verifiedWei(verifiedDepositWei[uid], uid),
      depositVerified: true,
      depositIds: authoritativeDepositIds(member.depIds, uid),
    };
  });
}

function parseSubmissions({ blockNum, groupId, members, submissions, submissionsRaw }) {
  const memberUids = members.map(({ uid }) => uid);
  const roster = new Set(memberUids);
  for (const uid of Object.keys(submissions)) {
    if (!own(submissionsRaw, uid)) {
      throw new Error(`[group-witness] submissions_raw is missing for parsed uid=${uid}`);
    }
  }

  const out = [];
  for (const [uid, rawPayload] of Object.entries(submissionsRaw)) {
    if (!roster.has(uid)) {
      throw new Error(`[group-witness] submissions_raw contains non-roster uid=${uid}`);
    }
    if (typeof rawPayload !== 'string') {
      throw new Error(`[group-witness] submissions_raw for uid=${uid} must remain a string`);
    }
    let decoded;
    try {
      decoded = decodeSubmissionPayloadString(rawPayload);
    } catch (error) {
      throw new Error(`[group-witness] submissions_raw decode failed for uid=${uid}: ${error.message}`);
    }
    if (decoded.blockNum !== blockNum || decoded.groupId !== groupId) {
      throw new Error(`[group-witness] compact context mismatch for uid=${uid}`);
    }
    if (JSON.stringify(decoded.memberUids) !== JSON.stringify(memberUids)) {
      throw new Error(`[group-witness] compact roster mismatch for uid=${uid}`);
    }
    const bundle = decoded.bundle;
    if (bundle.uid !== uid) {
      throw new Error(`[group-witness] compact submitter mismatch: key=${uid} bundle=${bundle.uid}`);
    }
    const snapshotBytes = actionSnapshotBytesForWitness(bundle, uid);
    out.push({
      uid,
      // Preserve the exact compact string held in submissions_raw. It is not
      // parse/stringified and remains available for Stage 5 input binding.
      rawPayload,
      encryptKey: bundle.encryptKey,
      chatHash: bundle.chatHash,
      submittedAt: bundle.submittedAt,
      encryptedDataHash: bundle.encryptedDataHash,
      depositIds: bundle.depositIds,
      signature: bundle.signature,
      messages: bundle.messages.map((message, index) => ({
        uid: message.uid,
        textUnits: utf16Units(message.text, `messages[${index}].text for uid=${uid}`),
        timestamp: message.timestamp,
        signature: message.signature,
      })),
      snapshotBytes,
    });
  }
  return out;
}

/**
 * Map production records to the JSON consumed by `crates/group-host --input`.
 *
 * Sources:
 *   - groupRow.members: D1 game_groups.members TEXT (authoritative roster)
 *   - groupData.submissionsRaw: exact ChatGameDO compact strings (authoritative)
 *   - groupData.submissions: presence-consistency check only; never trusted
 *   - verifiedDepositWei: on-chain-reverified uid -> wei table
 *   - chatWindow: declared Evidence window, or null until Stage 5 requires it
 */
export function buildGroupWitness({ groupRow, groupData, verifiedDepositWei, chatWindow = null }) {
  if (!groupRow || typeof groupRow !== 'object' || Array.isArray(groupRow)) {
    throw new Error('[group-witness] groupRow is required');
  }
  const blockNum = canonMetaInt(groupRow.block_num, 'blockNum', '[group-witness]');
  const groupId = canonMetaInt(groupRow.group_id, 'groupId', '[group-witness]');
  const verified = uidMap(verifiedDepositWei, 'verifiedDepositWei');
  const parsed = uidMap(groupData?.submissions ?? {}, 'groupData.submissions');
  const raw = uidMap(groupData?.submissionsRaw ?? {}, 'groupData.submissionsRaw');
  const members = parseRoster(groupRow.members, verified);
  const witness = {
    schemaVersion: GROUP_WITNESS_SCHEMA_VERSION,
    blockNum,
    groupId,
    chatWindow: normalizedChatWindow(chatWindow),
    members,
    submissions: parseSubmissions({
      blockNum, groupId, members, submissions: parsed, submissionsRaw: raw,
    }),
  };
  return witness;
}

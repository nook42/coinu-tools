// Cloudflare compromise emergency path.
// The observer archive is the only artifact source for generation selection and
// Evidence. The pre-export preservation check probes the current public R2
// manifest only to see whether an unsaved in-window version can still be copied.

import { withVendorLogging } from './vendor-logging.js';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { configRpcUrls, redactRpcText } from './rpc-privacy.js';
import { isDeepStrictEqual } from 'node:util';
import { GameMasterDO } from '../vendor/workers/game_workers/game-master-DO.js';
import {
  CURRENT_EVIDENCE_SEGMENT_PIN_VERSION, evidenceSegmentPrice,
} from '../vendor/workers/game_workers/lib/evidence-segment-plan.js';
import { selectWinners } from '../vendor/workers/lottery_workers/select-winners.js';
import { computeDeclaredTimesMs } from '../vendor/workers/game_workers/lib/timeline-check.js';
import {
  buildMembersIndex, validateResultBundle,
} from '../vendor/workers/game_workers/lib/evidence-reconciler.js';
import {
  chunkChainHash, encodeClaimData, splitChunks,
} from '../vendor/workers/game_workers/lib/claim-data-codec.js';
import { buildGroupWitness } from '../vendor/workers/game_workers/lib/group-witness.js';
import { parseCanonicalJson } from '../vendor/workers/game_workers/lib/canonical-json.js';
import { canonicalEqual, diffPaths, hashLikeBackend } from './json-utils.js';
import { r2LimitForKey } from './r2.js';
import { locateCurrentResultRow } from './prev-registration-witness.js';
import { buildZeroEntryNoGameSummary, zeroEntryNoGameSummaryShapeMatches,
  deriveGroupingUpperBound, reconstructedRosterIndexSha256,
  reconstructedRosterGroupSha256, reconstructCanonicalRosterPayloads,
  registeredByGroupingUpperBound, merkleRebuildArtifactKeys, resolveRosterRegistration,
  submissionContradictsGrouping } from './stages/results.js';
import {
  validateStage3InputManifest,
  ZKP_INPUT_LIMITS,
} from '../../Hardhat/bitcoinu/scripts/lib/collect-zkp-input.mjs';
import { concat, concatHex, keccak256, stringToHex } from 'viem';
import { buildRosterMemberCommitment } from '../vendor/workers/game_workers/lib/roster-member-root.js';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const hashEq = (a, b) => String(a || '').replace(/^0x/i, '').toLowerCase()
  === String(b || '').replace(/^0x/i, '').toLowerCase();
const WORKER_COUNT = 100;
const EMERGENCY_SUBMISSION_INVALID_REASONS = new Set([
  'invalid_signature', 'chathash_mismatch', 'snapshot_mismatch',
  'compact_decode_error', 'missing_fields', 'not_a_member',
  'compact_context_mismatch', 'sender_mismatch', 'validation_error',
]);
const workerName = (index) => String(index).padStart(2, '0');
export const EMERGENCY_FALLBACK_COMBINATION_LIMIT = 10_000;
// 🔴 R29-A-4b-02（2026-09-21）: 主経路（intermediate から worker 単位に解く側）の組み合わせ予算。
//    fallback（100 worker の直積）とは意味が違う「1 worker の部分木の和」なので、
//    後から片方だけ動かせるよう **別定数**にする。共有しないこと。
export const EMERGENCY_WORKER_COMBINATION_LIMIT = 10_000;
// P6b: 予算の持ち主はこの実行の HashStorage 状態 RPC 読み取り回数。
// 登録総数や保存世代数は攻撃者が増やせるので、件数を停止条件にしない。
export const PREVIOUS_RESULT_HISTORY_LIMIT = 8_192;
export const PREVIOUS_RESULT_EVALUATION_LIMIT = 8_192;
export const PREVIOUS_MANIFEST_GENERATION_LIMIT = 2_048;
export const PREVIOUS_SUMMARY_GENERATION_LIMIT = 2_048;

export function previousMajorLangsMatch(candidateMajorLangs, declaredMajorLangs) {
  return Array.isArray(declaredMajorLangs)
    && canonicalEqual(candidateMajorLangs, declaredMajorLangs);
}

function safeRelative(value) {
  const key = String(value || '');
  if (!key || key.startsWith('/') || key.includes('\\') || key.includes('..')
      || !/^[A-Za-z0-9._/-]+$/.test(key)) throw new Error(`unsafe archive path: ${JSON.stringify(value)}`);
  return key;
}

function under(rootDir, relative) {
  const root = path.resolve(rootDir);
  const target = path.resolve(root, safeRelative(relative));
  if (!target.startsWith(`${root}${path.sep}`)) throw new Error(`path escaped archive root: ${relative}`);
  return target;
}

async function readJsonFile(rootDir, relative) {
  return JSON.parse(await fs.readFile(under(rootDir, relative), 'utf8'));
}

async function readRowBytes(rootDir, row) {
  const bytes = await fs.readFile(under(rootDir, row.savedFile));
  if (sha256(bytes) !== String(row.sha256).toLowerCase()) {
    throw new Error(`observer generation sha256 mismatch: ${row.savedFile}`);
  }
  return bytes;
}

export function manifestCoreOf(manifest) {
  return {
    blockNum: manifest?.blockNum,
    algorithm: manifest?.algorithm,
    rules: manifest?.rules,
    files: manifest?.files,
  };
}

export function manifestCoreHash(manifest) {
  return `0x${sha256(Buffer.from(JSON.stringify(manifestCoreOf(manifest))))}`;
}

export function classifyPublicArtifactDifference({
  key, manifestKey, recomputedBytes, publicBytes, publicCopy,
}) {
  const difference = {
    key,
    recomputedSha256: sha256(recomputedBytes),
    publicSha256: sha256(publicBytes),
    publicCopy,
  };
  if (key !== manifestKey) return { difference, affectsResult: true };

  try {
    const recomputed = JSON.parse(recomputedBytes.toString('utf8'));
    const published = JSON.parse(publicBytes.toString('utf8'));
    const coreMatches = hashEq(manifestCoreHash(recomputed), manifestCoreHash(published));
    const differingFields = diffPaths(recomputed, published, { ignore: [] }).map((item) => (
      item.path || '(root)'
    ));
    return {
      difference: {
        ...difference,
        coreMatches,
        differingFields: differingFields.length > 0 || coreMatches
          ? differingFields : ['(manifestCore serialization)'],
      },
      affectsResult: !coreMatches,
    };
  } catch (error) {
    return {
      difference: {
        ...difference,
        coreMatches: false,
        differingFields: ['(unparseable manifest)'],
        manifestParseError: error?.message || String(error),
      },
      affectsResult: true,
    };
  }
}

function rowsFor(index, key) {
  const rows = index?.objects?.[key];
  if (!Array.isArray(rows)) return [];
  return [...rows].sort((a, b) => (
    String(a.observationOrdinal || '').localeCompare(String(b.observationOrdinal || ''))
      || Number(a.generation) - Number(b.generation)
  ));
}

async function selectRowByHash(sourceDir, rows, wantedHash, label) {
  const matching = rows.filter((row) => hashEq(row.sha256, wantedHash));
  if (matching.length === 0) throw new Error(`${label}: no saved generation matches ${wantedHash}`);
  const distinct = new Set(matching.map((row) => `${String(row.sha256).toLowerCase()}:${row.savedFile}`));
  // Same bytes saved under more than one object are equivalent; conflicting bytes cannot share sha256.
  if (new Set(matching.map((row) => String(row.sha256).toLowerCase())).size !== 1) {
    throw new Error(`${label}: multiple conflicting generations match the chain marker`);
  }
  const row = matching[0];
  await readRowBytes(sourceDir, row);
  return { ...row, equivalentSavedObjects: distinct.size };
}

function isEmergencyApplicantInput(key, blockNum) {
  const n = Number(blockNum);
  return new RegExp(`^entries/block${n}/info/\\d{2}_info\\.json$`).test(key)
    || new RegExp(`^entries/block${n}/entries/\\d{2}_\\d+\\.json$`).test(key);
}

async function* jsonCandidates(sourceDir, index, key, differences = []) {
  const seenHashes = new Set();
  for (const row of rowsFor(index, key)) {
    const rowHash = String(row.sha256).toLowerCase();
    if (seenHashes.has(rowHash)) continue;
    seenHashes.add(rowHash);
    const declaredBytes = Number(row.bytes);
    const reject = (reason, bytes = null) => differences.push({
      checkId: 'emergency.applicantDiscardedGenerations',
      what: 'applicant input generation could not be evaluated',
      chain: { generation: row.generation ?? null, sha256: rowHash,
        bytes: bytes ?? (Number.isSafeInteger(declaredBytes) ? declaredBytes : null), valueType: 'unparsed' },
      rebuilt: { accepted: false }, reason,
    });
    if (!Number.isSafeInteger(declaredBytes) || declaredBytes < 0
        || declaredBytes > GCP_GENERATION_BYTE_LIMIT) {
      reject('individual row byte limit');
      continue;
    }
    const stat = await fs.stat(under(sourceDir, row.savedFile));
    if (stat.size > GCP_GENERATION_BYTE_LIMIT) {
      reject('individual row byte limit', stat.size);
      continue;
    }
    const bytes = await readRowBytes(sourceDir, row);
    if (bytes.length > GCP_GENERATION_BYTE_LIMIT) {
      reject('individual row byte limit', bytes.length);
      continue;
    }
    if (!jsonDepthWithinLimit(bytes, GCP_JSON_DEPTH_LIMIT)) {
      reject('JSON depth limit', bytes.length);
      continue;
    }
    try {
      yield { row, data: JSON.parse(bytes.toString('utf8')), bytes: bytes.length };
    } catch {
      reject('invalid JSON', bytes.length);
    }
  }
}

function archiveIntegrityFailure(error) {
  return error?.code === 'ENOENT'
    || /^observer generation sha256 mismatch:/.test(error?.message || '')
    || /^unsafe archive path:/.test(error?.message || '')
    || /^path escaped archive root:/.test(error?.message || '');
}

function archiveIntegrityError() {
  return new Error('保存ファイルが壊れているか欠けています。空の出力先へ materialize-block をやり直してください');
}

// collect-worker / 通常 Stage A と同じ per-worker hash file 要素。
// 保管庫の不正世代も暗黙に 0/undefined へ寄せず、root 材料に使わない。
export function applicantHashEntry(fileInfo, hash) {
  const number = fileInfo?.number;
  if (!Number.isSafeInteger(number) || number < 0) {
    throw new Error(
      `Invalid info.entries[].number for ${String(fileInfo?.filename ?? '(missing filename)')}: `
      + 'expected a non-negative safe integer'
    );
  }
  return { filename: fileInfo.filename, hash, number };
}

export function applicantRootOf(blockNum, infos, entriesByFilename) {
  const hashList = infos.map((info, workerIndex) => {
    const entries = info.entries.map((fileInfo) => applicantHashEntry(
      fileInfo,
      hashLikeBackend(entriesByFilename.get(fileInfo.filename)),
    ));
    return {
      workerIndex,
      hash: hashLikeBackend({ block_num: blockNum, status: 'success', entries }),
    };
  });
  const hash = hashList.map(({ workerIndex, hash: value }) => ({
    filename: `${workerName(workerIndex)}_hash`, hash: value,
  }));
  hash.sort((a, b) => a.filename.localeCompare(b.filename));
  return `0x${hashLikeBackend({ block_num: blockNum, status: 'success', hash })}`;
}

const APPLICANT_SIGNER_WARNING = 'signer is a caller-supplied registerHash argument; it does not authenticate the transaction sender';

function applicantRegistrationMaterial(registration, diagnostic = null) {
  return {
    index: registration.index,
    hash: registration.hash,
    registeredBlock: registration.registeredBlock,
    registeredTime: new Date(registration.registeredTimeMs).toISOString(),
    registeredTimeMs: registration.registeredTimeMs,
    applicantCount: diagnostic?.applicantCount ?? null,
    reproducible: diagnostic !== null,
    signer: registration.signer,
    signerWarning: APPLICANT_SIGNER_WARNING,
  };
}

async function describeApplicantCandidate(sourceDir, candidate) {
  const files = new Map();
  for (const { key, row } of candidate.rows) {
    const infoMatch = key.match(/\/info\/(\d{2})_info\.json$/);
    const entryMatch = key.match(/\/entries\/(\d{2})_(\d+)\.json$/);
    if (!infoMatch && !entryMatch) continue;
    const bytes = await readRowBytes(sourceDir, row);
    const data = JSON.parse(bytes.toString('utf8'));
    const kind = entryMatch ? 'entries' : 'info';
    const logical = kind === 'entries'
      ? data
      : { entries: (data?.entries || []).map(({ filename, number }) => ({ filename, number })) };
    files.set(key, {
      key,
      kind,
      worker: Number((entryMatch || infoMatch)[1]),
      filename: key.slice(key.lastIndexOf('/') + 1),
      rowCount: kind === 'entries'
        ? (Array.isArray(data) ? data.length : null)
        : (Array.isArray(data?.entries)
          ? data.entries.reduce((sum, entry) => sum + (Number.isSafeInteger(entry?.number) ? entry.number : 0), 0)
          : null),
      sha256: row.sha256,
      fingerprint: JSON.stringify(logical),
    });
  }
  return {
    applicantCount: [...files.values()]
      .filter((file) => file.kind === 'entries')
      .reduce((sum, file) => sum + file.rowCount, 0),
    files,
  };
}

function firstApplicantCandidateDifference(left, right) {
  const allKeys = [...new Set([...left.files.keys(), ...right.files.keys()])];
  allKeys.sort((a, b) => {
    const leftFile = left.files.get(a) || right.files.get(a);
    const rightFile = left.files.get(b) || right.files.get(b);
    if (leftFile.worker !== rightFile.worker) return leftFile.worker - rightFile.worker;
    // 応募者データそのものを先に示し、entry 内容が同じ場合だけ info 宣言差へ進む。
    if (leftFile.kind !== rightFile.kind) return leftFile.kind === 'entries' ? -1 : 1;
    return leftFile.filename.localeCompare(rightFile.filename);
  });
  for (const key of allKeys) {
    const a = left.files.get(key) || null;
    const b = right.files.get(key) || null;
    if (a?.fingerprint === b?.fingerprint) continue;
    return {
      worker: a?.worker ?? b?.worker ?? null,
      filename: a?.filename ?? b?.filename ?? key.slice(key.lastIndexOf('/') + 1),
      kind: a && b ? 'content' : (a ? 'missingFromRight' : 'missingFromLeft'),
      leftRows: a?.rowCount ?? 0,
      rightRows: b?.rowCount ?? 0,
      leftSha256: a?.sha256 ?? null,
      rightSha256: b?.sha256 ?? null,
    };
  }
  return null;
}

export async function selectApplicantGenerationCombination({
  sourceDir, index, chain, blockNum,
  applicantRegistrationIndex = null, applicantRoot = null,
  workerOptionLimit = EMERGENCY_WORKER_COMBINATION_LIMIT,
  selectedByteLimit = GCP_GENERATION_BYTE_LIMIT,
}) {
  if (applicantRegistrationIndex !== null && applicantRoot !== null) {
    throw new Error('applicant registration index and root overrides cannot be used together');
  }
  if (applicantRegistrationIndex !== null
      && (!Number.isSafeInteger(applicantRegistrationIndex) || applicantRegistrationIndex < 0)) {
    throw new Error(`block ${blockNum}: invalid applicantHash registration override index ${applicantRegistrationIndex}`);
  }
  const normalizedApplicantRoot = applicantRoot === null ? null : String(applicantRoot).toLowerCase();
  if (normalizedApplicantRoot !== null && !/^0x[0-9a-f]{64}$/.test(normalizedApplicantRoot)) {
    throw new Error(`block ${blockNum}: invalid applicantHash root override ${applicantRoot}`);
  }
  const registrationCount = Number(await chain.applicantRegistrationCount(blockNum));
  if (!Number.isSafeInteger(registrationCount) || registrationCount < 1) {
    throw new Error(`block ${blockNum}: HashStorage applicantHash registration history is absent`);
  }
  const registrations = [];
  for (let registrationIndex = 0; registrationIndex < registrationCount; registrationIndex++) {
    const value = await chain.applicantRegistrationAt(blockNum, registrationIndex);
    const registeredBlock = Number(value?.registeredBlock);
    if (!value?.hash || !Number.isSafeInteger(registeredBlock) || registeredBlock < 0) {
      throw new Error(`block ${blockNum}: invalid applicantHash registration at index ${registrationIndex}`);
    }
    registrations.push({
      index: registrationIndex,
      registeredBlock,
      hash: String(value.hash).toLowerCase(),
      signer: value.signer ?? null,
    });
  }
  const timing = await chain.getTimingConstants();
  const entryPeriodEnd = timing.startTimeEntryMs + (Number(blockNum) + 1) * timing.blockTimeMs;
  const timedRegistrations = [];
  const eligibleRegistrations = [];
  for (const registration of registrations) {
    const block = await chain.getBlock(registration.registeredBlock);
    const registeredTimeMs = Number(block?.timestamp) * 1000;
    if (!Number.isFinite(registeredTimeMs)) {
      throw new Error(`block ${blockNum}: applicantHash registration time is invalid at index ${registration.index}`);
    }
    const timed = { ...registration, registeredTimeMs };
    timedRegistrations.push(timed);
    if (registeredTimeMs < entryPeriodEnd) continue;
    eligibleRegistrations.push(timed);
  }

  const requestedRegistration = applicantRegistrationIndex === null
    ? null : timedRegistrations.find((registration) => registration.index === applicantRegistrationIndex);
  if (applicantRegistrationIndex !== null && !requestedRegistration) {
    throw emergencySelectionError(
      `block ${blockNum}: specified applicantHash registration index ${applicantRegistrationIndex} `
        + 'is not present in HashStorage history',
      [{
        checkId: 'emergency.applicantRegistrationOverrideRejected',
        what: `specified applicantHash registration index ${applicantRegistrationIndex} is not in history`,
        chain: { registrationCount, availableIndices: timedRegistrations.map((registration) => registration.index) },
        rebuilt: { requestedIndex: applicantRegistrationIndex },
        reason: 'an emergency override must name an on-chain applicantHash registration',
      }],
    );
  }
  if (requestedRegistration && requestedRegistration.registeredTimeMs < entryPeriodEnd) {
    throw emergencySelectionError(
      `block ${blockNum}: specified applicantHash registration index ${applicantRegistrationIndex} is not eligible: `
        + `${new Date(requestedRegistration.registeredTimeMs).toISOString()} is before entryPeriodEnd `
        + new Date(entryPeriodEnd).toISOString(),
      [{
        checkId: 'emergency.applicantRegistrationOverrideRejected',
        what: `specified applicantHash registration index ${applicantRegistrationIndex} is before entryPeriodEnd`,
        chain: applicantRegistrationMaterial(requestedRegistration),
        rebuilt: { entryPeriodEnd, entryPeriodEndIso: new Date(entryPeriodEnd).toISOString() },
        reason: 'the existing eligibility rule is unchanged; an early registration cannot be selected',
      }],
    );
  }
  if (normalizedApplicantRoot !== null) {
    const matchingHistory = timedRegistrations.filter((registration) => registration.hash === normalizedApplicantRoot);
    if (matchingHistory.length === 0) {
      throw emergencySelectionError(
        `block ${blockNum}: specified applicantHash root ${normalizedApplicantRoot} is not present in HashStorage history; `
          + 'register the correct root first, then rerun recovery',
        [{
          checkId: 'emergency.applicantRegistrationOverrideRejected',
          what: `specified applicantHash root ${normalizedApplicantRoot} is not in history`,
          chain: { registeredRoots: timedRegistrations.map(({ index: i, hash }) => ({ index: i, hash })) },
          rebuilt: { requestedRoot: normalizedApplicantRoot },
          reason: 'register the correct root first, then rerun recovery; unanchored roots are never accepted',
        }],
      );
    }
    if (!matchingHistory.some((registration) => registration.registeredTimeMs >= entryPeriodEnd)) {
      throw emergencySelectionError(
        `block ${blockNum}: specified applicantHash root ${normalizedApplicantRoot} exists only in registrations `
          + 'that are not eligible because they precede entryPeriodEnd',
        [{
          checkId: 'emergency.applicantRegistrationOverrideRejected',
          what: `specified applicantHash root ${normalizedApplicantRoot} has no eligible history row`,
          chain: { registrations: matchingHistory.map((registration) => applicantRegistrationMaterial(registration)) },
          rebuilt: { entryPeriodEnd, entryPeriodEndIso: new Date(entryPeriodEnd).toISOString() },
          reason: 'the existing eligibility rule is unchanged; an early registration cannot be selected',
        }],
      );
    }
  }

  const differences = [];
  const loadLogicalEntryChoices = async (key) => {
    const byLogical = new Map();
    let byteVariantCount = 0;
    for await (const candidate of jsonCandidates(sourceDir, index, key, differences)) {
      if (!Array.isArray(candidate.data)) continue;
      byteVariantCount++;
      const identifier = sha256(Buffer.from(JSON.stringify(candidate.data)));
      if (!byLogical.has(identifier)) byLogical.set(identifier, {
        row: candidate.row, bytes: candidate.bytes, identifier,
        hash: identifier,
      });
    }
    const collapsed = [...byLogical.values()];
    if (byteVariantCount > collapsed.length) {
      differences.push({
        checkId: 'emergency.applicantGenerationBytes',
        what: `saved byte generations collapse to the same applicant logical content: ${key}`,
        chain: { eligibleApplicantHashes: eligibleRegistrations.map((registration) => registration.hash) },
        rebuilt: { byteVariants: byteVariantCount, logicalVariants: collapsed.length },
        reason: 'info is projected to filename/number and entry files are compared as parsed arrays',
      });
    }
    return collapsed;
  };

  const loadInfoChoices = async function* (worker) {
    const key = `entries/block${blockNum}/info/${workerName(worker)}_info.json`;
    const filenamePattern = new RegExp(`^${workerName(worker)}_\\d+$`);
    const validInfo = ({ data }) => {
      if (!data || typeof data !== 'object' || Array.isArray(data) || !Array.isArray(data.entries)) {
        return false;
      }
      const filenames = new Set();
      for (const entry of data.entries) {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)
            || typeof entry.filename !== 'string'
            || !filenamePattern.test(entry.filename)
            || !Number.isSafeInteger(entry.number) || entry.number < 0
            || filenames.has(entry.filename)) {
          return false;
        }
        filenames.add(entry.filename);
      }
      return true;
    };
    const seenRows = new Set();
    const seenLogical = new Set();
    let byteVariants = 0;
    for (const row of rowsFor(index, key)) {
      const rowHash = String(row.sha256).toLowerCase();
      if (seenRows.has(rowHash)) { byteVariants++; continue; }
      seenRows.add(rowHash);
      let candidate;
      for await (const value of jsonCandidates(sourceDir,
        { objects: { [key]: [row] } }, key, differences)) { candidate = value; break; }
      if (!candidate) continue;
      const { data, bytes } = candidate;
      if (!validInfo(candidate)) {
        differences.push({
          checkId: 'emergency.applicantDiscardedGenerations',
          what: `info generations with a duplicate, non-string, malformed, or cross-worker filename were discarded: ${key}`,
          chain: { discarded: [{ generation: row.generation ?? null, sha256: row.sha256, bytes,
            valueType: Array.isArray(data) ? 'array' : typeof data,
            entryCount: Array.isArray(data?.entries) ? data.entries.length : null,
            entryTypes: Array.isArray(data?.entries) ? data.entries.reduce((counts, entry) => {
              const type = Array.isArray(entry) ? 'array' : typeof entry;
              counts[type] = (counts[type] || 0) + 1;
              return counts;
            }, Object.create(null)) : null }] },
          rebuilt: { requiredFilenamePrefix: `${workerName(worker)}_`,
            requiredShape: '{ filename: unique string, number: non-negative safe integer }' },
          reason: 'collect-worker writes each of its own worker-prefixed entry filenames once',
        });
        continue;
      }
      const projected = { entries: data.entries.map((entry) => ({
        filename: entry.filename, number: entry.number,
      })) };
      const identifier = sha256(Buffer.from(JSON.stringify(projected)));
      if (seenLogical.has(identifier)) { byteVariants++; continue; }
      seenLogical.add(identifier);
      yield { row, bytes, data: projected, identifier };
    }
    if (byteVariants > 0) differences.push({
      checkId: 'emergency.applicantGenerationBytes',
      what: `saved byte generations collapse to the same applicant logical content: ${key}`,
      chain: { eligibleApplicantHashes: eligibleRegistrations.map((registration) => registration.hash) },
      rebuilt: { byteVariants: byteVariants + seenLogical.size, logicalVariants: seenLogical.size },
      reason: 'info is projected to filename/number and entry files are compared as parsed arrays',
    });
  };

  const entryChoicesCache = new Map();
  let entryChoicesCacheBytes = 0;
  const loadEntryChoices = async (key) => {
    if (entryChoicesCache.has(key)) return entryChoicesCache.get(key);
    const candidates = await loadLogicalEntryChoices(key);
    const candidateBytes = candidates.reduce((sum, candidate) => sum + candidate.bytes, 0);
    if (entryChoicesCacheBytes + candidateBytes > 32 * 1024 * 1024) {
      entryChoicesCache.clear();
      entryChoicesCacheBytes = 0;
    }
    if (candidateBytes <= 32 * 1024 * 1024) {
      entryChoicesCache.set(key, candidates);
      entryChoicesCacheBytes += candidateBytes;
    }
    return candidates;
  };

  let candidateEvaluations = 0;
  // 主経路と fallback は同じ worker/info 候補の評価結果を共有する。予算所有者は
  // info 候補1本であり、別登録・別 intermediate は既に得た結果を検索するだけである。
  // 分岐・葉に加え、実際に行う entries/worker hash もこの予算へ数える。
  let totalWorkerCombinationVisits = 0;
  const entryHashBudgeted = new WeakSet();
  const workerEvaluationCache = new Map();
  const wantedWorkerHashes = Array.from({ length: WORKER_COUNT }, () => new Set());
  const evaluateWorkerOptions = async (worker) => {
    if (workerEvaluationCache.has(worker)) return workerEvaluationCache.get(worker);
    const evaluation = (async () => {
      const infoKey = `entries/block${blockNum}/info/${workerName(worker)}_info.json`;
      const options = [];
      const budgetExceeded = [];
      let optionLimitRecorded = false;
      for await (const infoCandidate of loadInfoChoices(worker)) {
        let infoCombinationVisits = 0;
        const consumeInfoBudget = () => {
          infoCombinationVisits++;
          totalWorkerCombinationVisits++;
          if (infoCombinationVisits > EMERGENCY_WORKER_COMBINATION_LIMIT) {
            const error = new Error('info candidate combination budget exceeded');
            error.code = 'EMERGENCY_INFO_COMBINATION_LIMIT';
            throw error;
          }
        };
        consumeInfoBudget();
        const entryKeys = infoCandidate.data.entries.map((entry) => (
          `entries/block${blockNum}/entries/${entry.filename}.json`
        ));
        const choicesByKey = new Map();
        let complete = true;
        for (const key of entryKeys) {
          const choices = await loadEntryChoices(key);
          if (choices.length === 0) { complete = false; break; }
          choicesByKey.set(key, choices);
        }
        if (!complete) continue;
        const entrySelection = new Map();
        const entriesByFilename = new Map();
        let selectedBytes = infoCandidate.bytes;
        let byteBudgetRecorded = false;
        const hashEntryCandidate = (candidate) => {
          if (!entryHashBudgeted.has(candidate)) {
            consumeInfoBudget();
            entryHashBudgeted.add(candidate);
          }
          return candidate.hash;
        };
        const visit = async (indexOfEntry) => {
          if (indexOfEntry < entryKeys.length) {
            const key = entryKeys[indexOfEntry];
            const filename = key.slice(key.lastIndexOf('/') + 1, -'.json'.length);
            for (const candidate of choicesByKey.get(key)) {
              consumeInfoBudget();
              entrySelection.set(key, candidate);
              entriesByFilename.set(filename, candidate);
              selectedBytes += candidate.bytes;
              await visit(indexOfEntry + 1);
              selectedBytes -= candidate.bytes;
            }
            entrySelection.delete(key);
            entriesByFilename.delete(filename);
            return;
          }
          consumeInfoBudget();
          if (selectedBytes > selectedByteLimit) {
            if (!byteBudgetRecorded) budgetExceeded.push({
              worker, infoGeneration: infoCandidate.row.generation ?? null,
              bytes: selectedBytes, limit: selectedByteLimit,
            });
            byteBudgetRecorded = true;
            return;
          }
          candidateEvaluations++;
          const entries = infoCandidate.data.entries.map((fileInfo) => applicantHashEntry(
            fileInfo,
            hashEntryCandidate(entriesByFilename.get(fileInfo.filename)),
          ));
          consumeInfoBudget();
          const hash = hashLikeBackend({ block_num: blockNum, status: 'success', entries });
          const identifiers = [
            [infoKey, infoCandidate.identifier],
            ...entryKeys.map((key) => [key, entrySelection.get(key).identifier]),
          ];
          if (options.length >= workerOptionLimit
              && !wantedWorkerHashes[worker].has(hash)) {
            if (!optionLimitRecorded) budgetExceeded.push({ worker, infoGeneration: infoCandidate.row.generation ?? null,
              limit: workerOptionLimit, reason: 'worker option count limit' });
            optionLimitRecorded = true;
            return;
          }
          options.push({
            hash,
            fingerprint: sha256(Buffer.from(JSON.stringify(identifiers))),
            rows: [
              { key: infoKey, row: infoCandidate.row },
              ...entryKeys.map((key) => ({ key, row: entrySelection.get(key).row })),
            ],
          });
        };
        try {
          await visit(0);
        } catch (error) {
          if (error?.code !== 'EMERGENCY_INFO_COMBINATION_LIMIT') throw error;
          budgetExceeded.push({
            worker,
            infoGeneration: infoCandidate.row.generation ?? null,
            visits: infoCombinationVisits,
            limit: EMERGENCY_WORKER_COMBINATION_LIMIT,
          });
        }
      }
      return { options, budgetExceeded };
    })();
    workerEvaluationCache.set(worker, evaluation);
    return evaluation;
  };
  const selectWorkerCombination = async (worker, wantedHash) => {
    const evaluated = await evaluateWorkerOptions(worker);
    const matches = evaluated.options.filter((option) => hashEq(option.hash, wantedHash));
    const first = matches[0] || null;
    if (first && matches.some((match) => match.fingerprint !== first.fingerprint)) {
      throw new Error(
        `block ${blockNum}: multiple conflicting info/entry generation combinations `
        + `match worker ${workerName(worker)} hash ${wantedHash}`,
      );
    }
    return { match: first, budgetExceeded: evaluated.budgetExceeded };
  };

  const intermediateKey = `entries/block${blockNum}/intermediate_hash.json`;
  const intermediateByRoot = new Map();
  for await (const candidate of jsonCandidates(sourceDir, index, intermediateKey, differences)) {
    const data = candidate.data;
    if (!(
      data && typeof data === 'object' && !Array.isArray(data)
      && data.block_num === Number(blockNum) && data.status === 'success'
      && Array.isArray(data.hash) && data.hash.length === WORKER_COUNT
      && data.hash.every((item, worker) => (
        item?.filename === `${workerName(worker)}_hash`
        && /^[0-9a-f]{64}$/i.test(String(item?.hash || ''))
      ))
    )) continue;
    const root = `0x${hashLikeBackend(candidate.data)}`.toLowerCase();
    if (!eligibleRegistrations.some((registration) => registration.hash === root)) continue;
    const prior = intermediateByRoot.get(root);
    if (prior) prior.count++;
    else intermediateByRoot.set(root, { first: candidate, count: 1 });
  }
  for (const [root, saved] of intermediateByRoot) {
    if (saved.count > 1) {
      differences.push({
        checkId: 'emergency.applicantIntermediateGenerations',
        what: `multiple saved intermediate generations authenticate the same applicant root: ${intermediateKey}`,
        chain: { applicantRoot: root },
        rebuilt: { savedGenerations: saved.count, selectedGeneration: saved.first.row.generation ?? null },
        reason: 'the intermediate file is self-authenticating; byte-only saved variants do not change worker hashes',
      });
    }
  }
  for (const [root, saved] of intermediateByRoot) {
    const candidate = saved.first;
    for (let worker = 0; worker < WORKER_COUNT; worker++) {
      wantedWorkerHashes[worker].add(candidate.data.hash[worker].hash);
    }
  }
  const reproducibleByIndex = new Map();
  const evaluationImpossibleByIndex = new Map();
  const markEvaluationImpossible = (registration, detail) => {
    const prior = evaluationImpossibleByIndex.get(registration.index) || [];
    prior.push(detail);
    evaluationImpossibleByIndex.set(registration.index, prior);
  };
  let intermediateAttempts = 0;
  for (const [root, saved] of intermediateByRoot) {
    const matchingRegistrations = eligibleRegistrations.filter((registration) => registration.hash === root);
    if (matchingRegistrations.length === 0) continue;
    for (const intermediate of [saved.first]) {
      intermediateAttempts++;
      const attemptVisitStart = totalWorkerCombinationVisits;
      const rows = [{ key: intermediateKey, row: intermediate.row }];
      const workerFingerprints = [];
      const budgetExceeded = [];
      let complete = true;
      for (let worker = 0; worker < WORKER_COUNT; worker++) {
        const workerResult = await selectWorkerCombination(worker, intermediate.data.hash[worker].hash);
        budgetExceeded.push(...workerResult.budgetExceeded);
        const selectedWorker = workerResult.match;
        if (!selectedWorker) { complete = false; break; }
        rows.push(...selectedWorker.rows);
        workerFingerprints.push(selectedWorker.fingerprint);
      }
      if (budgetExceeded.length > 0) {
        for (const registration of matchingRegistrations) markEvaluationImpossible(registration, {
          phase: 'intermediate-worker-linear',
          intermediateGeneration: intermediate.row?.generation ?? null,
          reason: '応募世代の組み合わせが多すぎて一意に決められない',
          budgetExceeded,
        });
      }
      if (!complete) continue;
      const candidate = {
        root,
        rows,
        fingerprint: sha256(Buffer.from(JSON.stringify(workerFingerprints))),
        registration: matchingRegistrations[0],
        registrationCount,
        entryPeriodEnd,
        differences,
        selectionStats: {
          // candidateEvaluations は葉の数（従来どおり・既存 pin が固定している）。
          // workerCombinationVisits は info 候補ごとにリセットした予算の合計。
          strategy: 'intermediate-worker-linear',
          candidateEvaluations,
          workerCombinationVisits: totalWorkerCombinationVisits - attemptVisitStart,
        },
        differencesAtMatch: [...differences],
      };
      for (const registration of matchingRegistrations) {
        reproducibleByIndex.set(registration.index, { ...candidate, registration });
      }
    }
  }

  const requestedRegistrations = applicantRegistrationIndex !== null
    ? eligibleRegistrations.filter((registration) => registration.index === applicantRegistrationIndex)
    : (normalizedApplicantRoot !== null
      ? eligibleRegistrations.filter((registration) => registration.hash === normalizedApplicantRoot)
      : []);
  const overrideAlreadyReproduced = requestedRegistrations.some((registration) => (
    reproducibleByIndex.has(registration.index)
  ));
  const fallbackTargets = overrideAlreadyReproduced
    ? []
    : (requestedRegistrations.length > 0 ? requestedRegistrations : eligibleRegistrations)
      .filter((registration) => (
        !reproducibleByIndex.has(registration.index)
        && !intermediateByRoot.has(registration.hash)
      ));

  if (overrideAlreadyReproduced) {
    const skipped = eligibleRegistrations.filter((registration) => !reproducibleByIndex.has(registration.index));
    if (skipped.length > 0) {
      differences.push({
        checkId: 'emergency.applicantDiscardedGenerations',
        what: 'fallback evaluation of non-selected applicant registrations was skipped after an explicit intermediate-path match',
        chain: { skipped: skipped.map((registration) => applicantRegistrationMaterial(registration)) },
        rebuilt: {
          selectedIndices: requestedRegistrations
            .filter((registration) => reproducibleByIndex.has(registration.index))
            .map((registration) => registration.index),
        },
        reason: 'the operator named a registration already reproduced through its authenticated intermediate root',
      });
    }
  }

  // fallback は worker ごとに候補 hash を作り、その後に対象登録ごとの予算で
  // 100 worker を組み合わせる。別登録の探索は同じカウンタを決して使わない。
  let totalFallbackCombinationVisits = 0;
  if (fallbackTargets.length > 0) {
    const fallbackWorkerOptions = [];
    const fallbackInfoBudgetExceeded = [];
    for (let worker = 0; worker < WORKER_COUNT; worker++) {
      const evaluated = await evaluateWorkerOptions(worker);
      fallbackWorkerOptions.push(evaluated.options);
      fallbackInfoBudgetExceeded.push(...evaluated.budgetExceeded);
    }

    for (const registration of fallbackTargets) {
      let fallbackCombinationVisits = 0;
      const consumeFallbackBudget = () => {
        fallbackCombinationVisits++;
        totalFallbackCombinationVisits++;
        if (fallbackCombinationVisits > EMERGENCY_FALLBACK_COMBINATION_LIMIT) {
          const error = new Error('registration fallback combination budget exceeded');
          error.code = 'EMERGENCY_FALLBACK_COMBINATION_LIMIT';
          throw error;
        }
      };
      const selection = new Array(WORKER_COUNT);
      let match = null;
      const visitWorkers = async (worker) => {
        if (worker < WORKER_COUNT) {
          for (const option of fallbackWorkerOptions[worker]) {
            consumeFallbackBudget();
            selection[worker] = option;
            await visitWorkers(worker + 1);
          }
          return;
        }
        consumeFallbackBudget();
        const hash = selection.map((option, workerIndex) => ({
          filename: `${workerName(workerIndex)}_hash`, hash: option.hash,
        }));
        const root = `0x${hashLikeBackend({ block_num: blockNum, status: 'success', hash })}`;
        if (!hashEq(root, registration.hash)) return;
        const fingerprint = sha256(Buffer.from(JSON.stringify(selection.map((option) => option.fingerprint))));
        if (match && match.fingerprint !== fingerprint) {
          throw new Error(
            `block ${blockNum}: multiple conflicting info/entry generation combinations `
            + `match HashStorage applicantHash registration ${registration.hash}`,
          );
        }
        if (!match) {
          match = {
            root,
            fingerprint,
            rows: selection.flatMap((option) => option.rows),
          };
        }
      };
      let registrationBudgetExceeded = false;
      try {
        if (fallbackWorkerOptions.every((options) => options.length > 0)) await visitWorkers(0);
      } catch (error) {
        if (error?.code !== 'EMERGENCY_FALLBACK_COMBINATION_LIMIT') throw error;
        registrationBudgetExceeded = true;
      }
      if (registrationBudgetExceeded || fallbackInfoBudgetExceeded.length > 0) {
        markEvaluationImpossible(registration, {
          phase: 'bounded-combination-fallback',
          reason: '評価不能（予算超過）',
          registrationCombinationVisits: fallbackCombinationVisits,
          registrationCombinationLimit: EMERGENCY_FALLBACK_COMBINATION_LIMIT,
          infoCandidatesOverLimit: fallbackInfoBudgetExceeded,
        });
        continue;
      }
      if (!match) continue;
      reproducibleByIndex.set(registration.index, {
        ...match,
        registration,
        registrationCount,
        entryPeriodEnd,
        differences,
        selectionStats: {
          strategy: 'bounded-combination-fallback',
          candidateEvaluations: fallbackCombinationVisits,
        },
        differencesAtMatch: [...differences],
      });
    }
  }

  for (const registration of eligibleRegistrations) {
    const impossible = evaluationImpossibleByIndex.get(registration.index);
    if (!impossible) continue;
    differences.push({
      checkId: 'emergency.applicantDiscardedGenerations',
      what: `applicant registration ${registration.index} has generation candidates that are evaluation-impossible because their budget was exceeded`,
      chain: applicantRegistrationMaterial(registration),
      rebuilt: { evaluation: '評価不能（予算超過）', attempts: impossible },
      reason: 'the budget belongs to this registration and info candidate; exhaustion is recorded instead of aborting other registrations',
    });
  }
  return finalizeApplicantRegistrationSelection({
    sourceDir, blockNum, registrationCount, entryPeriodEnd, eligibleRegistrations,
    reproducibleByIndex, applicantRegistrationIndex,
    normalizedApplicantRoot, evaluationImpossibleByIndex, selectionDifferences: differences,
    evaluationStats: {
      strategy: fallbackTargets.length > 0
        ? 'bounded-combination-fallback' : 'intermediate-worker-linear',
      eligibleRegistrationsEvaluated: eligibleRegistrations.length,
      intermediateAttempts,
      candidateEvaluations,
      workerCombinationVisits: totalWorkerCombinationVisits,
      fallbackCombinationVisits: totalFallbackCombinationVisits,
    },
  });
}

async function finalizeApplicantRegistrationSelection({
  sourceDir, blockNum, registrationCount, entryPeriodEnd, eligibleRegistrations,
  reproducibleByIndex, applicantRegistrationIndex, normalizedApplicantRoot,
  evaluationImpossibleByIndex = new Map(), selectionDifferences = [], evaluationStats,
}) {
  const candidates = [...reproducibleByIndex.values()]
    .sort((a, b) => a.registration.index - b.registration.index);
  const diagnosticByRoot = new Map();
  const requestedRoot = applicantRegistrationIndex !== null
    ? reproducibleByIndex.get(applicantRegistrationIndex)?.root
    : normalizedApplicantRoot;
  const requestedReproduced = candidates.some((candidate) => candidate.root === requestedRoot);
  for (const candidate of candidates) {
    if (requestedReproduced && candidate.root !== requestedRoot) continue;
    if (!diagnosticByRoot.has(candidate.root)) {
      diagnosticByRoot.set(candidate.root, await describeApplicantCandidate(sourceDir, candidate));
    }
    candidate.diagnostic = diagnosticByRoot.get(candidate.root);
  }
  const material = eligibleRegistrations.map((registration) => ({
    ...applicantRegistrationMaterial(
      registration, reproducibleByIndex.get(registration.index)?.diagnostic ?? null,
    ),
    evaluationImpossible: evaluationImpossibleByIndex.has(registration.index),
    evaluationIssues: evaluationImpossibleByIndex.get(registration.index) || [],
  }));
  const impossibleIndices = [...evaluationImpossibleByIndex.keys()].sort((a, b) => a - b);

  let selected = null;
  let selectionType = null;
  if (applicantRegistrationIndex !== null) {
    selectionType = 'index';
    selected = reproducibleByIndex.get(applicantRegistrationIndex) || null;
    if (!selected) {
      const issues = evaluationImpossibleByIndex.get(applicantRegistrationIndex) || [];
      const budgetReason = issues.length > 0 ? ' (評価不能：予算超過)' : '';
      throw emergencySelectionError(
        `block ${blockNum}: specified eligible applicantHash registration index ${applicantRegistrationIndex} `
          + `cannot be reproduced from any saved info/entry generation combination${budgetReason}`,
        [...selectionDifferences, {
          checkId: 'emergency.applicantRegistrationOverrideRejected',
          what: `specified eligible registration index ${applicantRegistrationIndex} is not reproducible`,
          chain: { eligibleRegistrations: material },
          rebuilt: { requestedIndex: applicantRegistrationIndex, evaluationStats, evaluationIssues: issues },
          reason: 'the selected on-chain registration must be reproducible from saved applicant generations',
        }],
      );
    }
  } else if (normalizedApplicantRoot !== null) {
    selectionType = 'root';
    selected = candidates.find((candidate) => candidate.registration.hash === normalizedApplicantRoot) || null;
    if (!selected) {
      const issues = eligibleRegistrations
        .filter((registration) => registration.hash === normalizedApplicantRoot)
        .flatMap((registration) => evaluationImpossibleByIndex.get(registration.index) || []);
      const budgetReason = issues.length > 0 ? ' (評価不能：予算超過)' : '';
      throw emergencySelectionError(
        `block ${blockNum}: specified eligible applicantHash root ${normalizedApplicantRoot} `
          + `cannot be reproduced from any saved info/entry generation combination${budgetReason}`,
        [...selectionDifferences, {
          checkId: 'emergency.applicantRegistrationOverrideRejected',
          what: `specified eligible root ${normalizedApplicantRoot} is not reproducible`,
          chain: { eligibleRegistrations: material },
          rebuilt: { requestedRoot: normalizedApplicantRoot, evaluationStats, evaluationIssues: issues },
          reason: 'the selected on-chain registration must be reproducible from saved applicant generations',
        }],
      );
    }
  } else if (impossibleIndices.length > 0) {
    const ambiguityDifference = {
      checkId: 'emergency.applicantRegistrationAmbiguous',
      what: 'one or more eligible applicantHash registrations could not be fully evaluated within their own budgets',
      chain: { eligibleRegistrations: material },
      rebuilt: {
        reproducibleIndices: candidates.map((candidate) => candidate.registration.index),
        evaluationImpossibleIndices: impossibleIndices,
        evaluationStats,
      },
      reason: '評価不能（予算超過）の登録があるため、指定なしの自動採用は fail-closed で停止する',
    };
    const mainBudgetExceeded = [...evaluationImpossibleByIndex.values()]
      .flat().some((issue) => issue.phase === 'intermediate-worker-linear');
    const prefix = mainBudgetExceeded
      ? `block ${blockNum}: 応募世代の組み合わせが多すぎて一意に決められない `
        + `(組み合わせ上限 ${EMERGENCY_WORKER_COMBINATION_LIMIT})。`
      : `block ${blockNum}: `;
    throw emergencySelectionError(
      `${prefix}評価不能（予算超過）の適格登録があるため自動採用できません。`
        + `適格登録: ${JSON.stringify(material)}`,
      [...selectionDifferences, ambiguityDifference],
    );
  } else if (candidates.length === 1) {
    [selected] = candidates;
  } else if (candidates.length === 0) {
    throw new Error(
      `block ${blockNum}: no saved info/entry generation combination matches an eligible HashStorage applicantHash registration`,
    );
  } else {
    const firstDifferences = candidates.slice(1).map((candidate) => ({
      leftIndex: candidates[0].registration.index,
      rightIndex: candidate.registration.index,
      ...(candidates[0].root === candidate.root ? {}
        : firstApplicantCandidateDifference(candidates[0].diagnostic, candidate.diagnostic)),
    }));
    const instruction = '正しい応募者データと整合する登録を決め、'
      + '--emergency-applicant-registration <INDEX> または --emergency-applicant-root <HASH> '
      + 'を指定して再実行してください';
    const ambiguityDifference = {
      checkId: 'emergency.applicantRegistrationAmbiguous',
      what: 'multiple eligible applicantHash registrations are reproducible from saved generations',
      chain: { eligibleRegistrations: material },
      rebuilt: {
        reproducibleIndices: candidates.map((candidate) => candidate.registration.index),
        firstDifferences,
        evaluationStats,
      },
      reason: instruction,
    };
    throw emergencySelectionError(
      `block ${blockNum}: 複数の適格な applicantHash 登録を保存世代から再現できます。\n`
        + `適格登録: ${JSON.stringify(material)}\n`
        + `候補差分: ${JSON.stringify(firstDifferences)}\n`
        + instruction,
      [...selectionDifferences, ambiguityDifference],
    );
  }

  const selectedDifferences = [...selectionDifferences];
  if (selectionType) {
    selectedDifferences.push({
      checkId: 'emergency.applicantRegistrationOverride',
      what: 'the operator explicitly selected one eligible reproducible applicantHash registration',
      chain: {
        selected: { index: selected.registration.index, root: selected.registration.hash },
        skipped: eligibleRegistrations
          .filter((registration) => registration.index !== selected.registration.index)
          .map((registration) => ({ index: registration.index, root: registration.hash })),
      },
      rebuilt: {
        specifiedBy: selectionType,
        specifiedValue: selectionType === 'index'
          ? applicantRegistrationIndex : normalizedApplicantRoot,
        applicantCount: selected.diagnostic.applicantCount,
        evaluationStats,
      },
      reason: 'operator selection is recorded as a material emergency difference for third-party review',
    });
  }
  const { differencesAtMatch: _ignored, diagnostic: _diagnostic, ...result } = selected;
  return { ...result, differences: selectedDifferences, evaluationStats };
}

export async function selectRosterManifestGeneration({ sourceDir, index, chain, blockNum }) {
  const key = `games/block${blockNum}/roster/manifest.json`;
  const rows = rowsFor(index, key);
  if (rows.length === 0) return null;
  const markerKey = keccak256(stringToHex(`bitcoinu:roster:${blockNum}`));
  const registration = await resolveRosterRegistration(chain, blockNum);
  const anchored = registration.row;
  if (!anchored?.hash) throw new Error(`${key}: canonical HashStorage roster manifest marker is absent`);
  const matching = [];
  for (const row of rows) {
    const bytes = await readRowBytes(sourceDir, row);
    try {
      const groupTexts = new Map();
      const manifest = JSON.parse(bytes.toString('utf8'));
      for (const group of manifest.groups) {
        const groupKey = `games/block${blockNum}/roster/group${group.groupId}.json`;
        const saved = rowsFor(index, groupKey).find((candidate) => hashEq(candidate.sha256, group.sha256));
        if (!saved) throw new Error(`saved ${groupKey} is absent`);
        groupTexts.set(group.groupId, (await readRowBytes(sourceDir, saved)).toString('utf8'));
      }
      const C = buildRosterMemberCommitment({ blockNum,
        manifestText: bytes.toString('utf8'), groupTexts }).C;
      if (hashEq(C, anchored.hash)) matching.push(row);
    } catch { /* This generation cannot reproduce the canonical C. */ }
  }
  if (matching.length === 0) {
    const row = rows[0];
    await readRowBytes(sourceDir, row);
    return {
      key, row, markerKey,
      difference: {
        checkId: 'check.stageC.rosterLiveAnchor',
        what: 'roster manifest marker does not select any saved generation',
        chain: { hash: anchored.hash, index: registration.index,
          updatedBlock: anchored.registeredBlock ?? null },
        rebuilt: { selectedSha256: row.sha256, selectionRule: 'earliest-observed-saved-generation' },
        // 🔴 周29（2026-09-22）: 旧文は「契約が履歴を持たない」と書いていたが、現物はもう持っている
        //    （HashStorage.otherRegistrationAt と otherRegistrationCount の追記履歴）。
        //    応募終了以後・チャット開始前の最後の登録と比べる。一致世代が無ければ
        //    最初の保存世代を差付きで代用し、緊急 Stage C が再構成との一致を照合する。
        reason: 'no saved generation matches the canonical pre-chat roster registration',
      },
    };
  }
  if (new Set(matching.map((row) => String(row.sha256).toLowerCase())).size !== 1) {
    throw new Error(`${key}: multiple conflicting generations match HashStorage roster manifest marker`);
  }
  return { key, row: matching[0], markerKey };
}

function isEmergencyStageABInput(key, blockNum) {
  const n = Number(blockNum);
  if (key === `entries/block${n}/game_selection.json`
      || key === `entries/block${n}/game_groups.json`
      || key === `games/block${n}/summary.json`
      || key === `games/block${n}/roster/manifest.json`
      || new RegExp(`^entries/block${n}/info/\\d{2}_info\\.json$`).test(key)
      || new RegExp(`^entries/block${n}/entries/\\d{2}_\\d+\\.json$`).test(key)) {
    return true;
  }
  if (n <= 0) return false;
  return key === `games/block${n - 1}/summary.json`
    || key === `verification/block${n - 1}/manifest.json`;
}

function isEmergencyRosterPayload(key, blockNum) {
  const n = Number(blockNum);
  return key === `games/block${n}/roster/index.json`
    || new RegExp(`^games/block${n}/roster/group\\d+\\.json$`).test(key);
}

function emergencySelectionError(message, differences) {
  const error = new Error(message);
  error.emergencyDifferences = [...(differences || [])];
  return error;
}

async function selectReadableManifestCandidates(sourceDir, rows, wantedHash = null,
  { emergencyLimits = false, evaluations = null, registeredHashes = null } = {}) {
  const candidates = [];
  for (const row of rows) {
    const declaredBytes = Number(row.bytes);
    try {
      if (emergencyLimits && (!Number.isSafeInteger(declaredBytes) || declaredBytes < 0
          || declaredBytes > GCP_GENERATION_BYTE_LIMIT)) throw new Error('individual row byte limit');
      const bytes = await readRowBytes(sourceDir, row);
      if (emergencyLimits && bytes.length > GCP_GENERATION_BYTE_LIMIT) {
        throw new Error('individual row byte limit');
      }
      let value;
      try { value = JSON.parse(bytes.toString('utf8')); } catch {
        if (emergencyLimits) throw new Error('unreadable saved generation');
        continue;
      }
      if (!value || typeof value !== 'object' || Array.isArray(value)) {
        if (emergencyLimits) throw new Error('unusable saved manifest structure');
        continue;
      }
      let coreHash;
      try { coreHash = manifestCoreHash(value); } catch (error) {
        if (emergencyLimits && error instanceof RangeError) throw new Error('JSON depth limit');
        throw error;
      }
      if (emergencyLimits && !jsonDepthWithinLimit(bytes, GCP_JSON_DEPTH_LIMIT)
          && !registeredHashes?.has(String(coreHash).toLowerCase())) {
        throw new Error('JSON depth limit');
      }
      if (wantedHash == null || hashEq(coreHash, wantedHash)) {
        candidates.push({ row, coreHash, bytes: bytes.length });
      }
    } catch (error) {
      if (!emergencyLimits) throw error;
      if (archiveIntegrityFailure(error)) throw archiveIntegrityError();
      evaluations?.push({ generation: row.generation, sha256: row.sha256,
        bytes: Number.isSafeInteger(declaredBytes) ? declaredBytes : null,
        reason: ['individual row byte limit', 'JSON depth limit',
          'unreadable saved generation', 'unusable saved manifest structure'].includes(error?.message)
          ? error.message : 'unreadable saved generation' });
    }
  }
  return candidates;
}

async function readSelectedManifest(sourceDir, candidate) {
  return JSON.parse((await readRowBytes(sourceDir, candidate.row)).toString('utf8'));
}

export async function readPreviousResultCandidateSummary(sourceDir, candidate) {
  return JSON.parse((await readRowBytes(sourceDir, candidate.summaryRow)).toString('utf8'));
}

function previousResultBudgetError(message, details) {
  const error = new Error(message);
  error.previousResultBudget = details;
  return error;
}

export async function verifyResultRegistrationRow(chain, blockNum, row, knownState = null) {
  if (!row?.fromResultLog || typeof chain.resultRegistrationAt !== 'function') return row;
  const state = knownState ?? await chain.resultRegistrationAt(blockNum, row.index);
  if (!hashEq(state?.hash, row.hash)
      || Number(state?.registeredBlock) !== Number(row.registeredBlock)
      || String(state?.signer).toLowerCase() !== String(row.signer).toLowerCase()
      || (row.registeredAt != null && Number(state?.registeredAt) !== Number(row.registeredAt))) {
    throw new Error(`block ${blockNum}: ResultHashRegistered log differs from state row ${row.index}`);
  }
  return { ...state, index: row.index };
}

// Failure path only: before concluding that no saved version reproduces the
// grouping, prove that log-based rows did not hide a state registration.
// Budget owner is this failed selection, not a later block or candidate.
export async function verifyResultHistoryOnFailure(chain, blockNum, history) {
  let reads = 0;
  for (const row of history?.rows || []) {
    if (!row?.fromResultLog) continue;
    reads++;
    await verifyResultRegistrationRow(chain, blockNum, row);
  }
  return { owner: 'this failed previous-result selection', used: reads, limit: null };
}

export async function findResultRegistrationAtGrouping(
  chain, blockNum, upperMs, includeOutsideWindow = false, entryEndMs = null,
) {
  let count = null;
  if (typeof chain.resultRegistrationCount === 'function') {
    count = Number(await chain.resultRegistrationCount(blockNum));
    if (!Number.isSafeInteger(count) || count < 0) {
      throw new Error(`invalid resultRegistrationCount(${blockNum}): ${count}`);
    }
    if (typeof chain.resultRegistrationAt === 'function') {
      const cache = new Map();
      let reads = 1; // resultRegistrationCount; binary search only
      const at = async (index) => {
        if (cache.has(index)) return cache.get(index);
        reads++;
        const row = { ...(await chain.resultRegistrationAt(blockNum, index)), index };
        cache.set(index, row);
        return row;
      };
      let low = 0;
      let high = count;
      while (low < high) {
        const mid = Math.floor((low + high) / 2);
        const row = await at(mid);
        const registeredAt = Number(row.registeredAt);
        if (!Number.isFinite(registeredAt)) throw new Error(`invalid registeredAt(${blockNum}, ${mid})`);
        if (registeredByGroupingUpperBound(row, upperMs)) low = mid + 1;
        else high = mid;
      }
      let lowerIndex = 0;
      if (!includeOutsideWindow && entryEndMs != null && count > 0) {
        // Keep the state value at entry end and later registrations. Earlier
        // versions were no longer current when grouping could begin.
        let before = 0;
        let after = count;
        while (before < after) {
          const mid = Math.floor((before + after) / 2);
          const row = await at(mid);
          const registeredAt = Number(row.registeredAt);
          if (!Number.isSafeInteger(registeredAt) || registeredAt < 0) {
            throw new Error(`invalid registeredAt(${blockNum}, ${mid})`);
          }
          if (registeredAt * 1000 <= entryEndMs) before = mid + 1;
          else after = mid;
        }
        lowerIndex = Math.max(0, before - 1);
      }
      const readCount = includeOutsideWindow ? count : low;
      let rows;
      let eventRows = null;
      if (readCount > 0 && typeof chain.resultHashEvents === 'function') {
        const first = await at(0);
        const last = await at(readCount - 1);
        const logs = await chain.resultHashEvents(blockNum, {
          fromBlock: BigInt(first.registeredBlock), toBlock: BigInt(last.registeredBlock),
        });
        eventRows = logs.length;
        rows = logs.filter((log) => Number(log.registrationCount) <= readCount)
          .map((log) => ({
            index: Number(log.registrationCount) - 1,
            hash: log.hash,
            registeredBlock: Number(log.updatedAt ?? log.evtBlock),
            registeredAt: null,
            signer: log.signer,
            fromResultLog: true,
          })).sort((a, b) => b.index - a.index);
        if (rows.length !== readCount || rows.some((row, position) => row.index !== readCount - 1 - position)
            || String(rows[0]?.hash).toLowerCase() !== String(last.hash).toLowerCase()) {
          throw new Error(`block ${blockNum}: ResultHashRegistered logs do not cover eligible history`);
        }
        rows[0].registeredAt = last.registeredAt;
        if (includeOutsideWindow) {
          rows[rows.length - 1].registeredAt = first.registeredAt;
          if (low > 0) rows[readCount - low].registeredAt = (await at(low - 1)).registeredAt;
        }
      } else {
        rows = [];
        for (let index = readCount - 1; index >= 0; index--) rows.push(await at(index));
      }
      if (includeOutsideWindow) {
        rows = [...rows.filter((row) => row.index < low),
          ...rows.filter((row) => row.index >= low).reverse()];
      } else if (lowerIndex > 0) {
        rows = rows.filter((row) => row.index >= lowerIndex);
      }
      const selected = rows[0] ? await verifyResultRegistrationRow(
        chain, blockNum, rows[0], rows[0].fromResultLog ? await at(rows[0].index) : null,
      ) : null;
      if (selected) rows[0] = selected;
      const current = count > 0 ? await at(count - 1) : null;
      return { count, rows, selected, current,
        excludedAfterGrouping: count - low,
        budget: { owner: 'this verification run: binary-search state reads plus chunked event-log requests',
          used: reads, limit: null, eventRows } };
    }
  }
  if (typeof chain.resultRegistrationHistory !== 'function') {
    throw new Error('result registration history is not available on this chain reader');
  }
  const history = await chain.resultRegistrationHistory(blockNum);
  const historyCount = Number(history?.count);
  if (!Number.isSafeInteger(historyCount) || historyCount < 0
      || !Array.isArray(history?.rows) || history.rows.length !== historyCount) {
    throw new Error(`invalid result registration history for block ${blockNum}`);
  }
  const preferredRows = [];
  const remainingRows = [];
  for (let i = 0; i < historyCount; i++) {
    const row = { ...history.rows[i], index: i };
    if (registeredByGroupingUpperBound(row, upperMs)) preferredRows.unshift(row);
    else if (includeOutsideWindow) remainingRows.push(row);
    else break;
  }
  let rows = [...preferredRows, ...remainingRows];
  if (!includeOutsideWindow && entryEndMs != null && rows.length > 0) {
    let lastAtEntry = -1;
    for (let i = 0; i < historyCount; i++) {
      if (Number(history.rows[i]?.registeredAt) * 1000 <= entryEndMs) lastAtEntry = i;
    }
    rows = rows.filter((row) => row.index >= Math.max(0, lastAtEntry));
  }
  const selected = rows[0] ?? null;
  return { count: historyCount, rows, selected,
    current: historyCount ? { ...history.rows[historyCount - 1], index: historyCount - 1 } : null,
    excludedAfterGrouping: historyCount - preferredRows.length,
    budget: { owner: 'in-memory history supplied by chain reader', used: 0, limit: null } };
}

// materialize-block の generation-index から、HashStorage の各履歴行に束縛された
// manifest → summary の候補を作る。通常 Stage B と緊急復旧で同じ選択材料を使う。
export async function loadPreviousResultVersionCandidates({
  sourceDir, index = null, chain, blockNum, includeOutsideWindow = false,
  groupingRosterHash = undefined, entranceUpperMs = null, emergencyLimits = false,
  recordedRow = null,
}) {
  const current = Number(blockNum);
  const previous = current - 1;
  if (previous < 0) {
    return {
      previous,
      history: { count: 0, rows: [] },
      currentMarker: null,
      currentLocation: null,
      manifestKey: null,
      summaryKey: null,
      candidates: [],
    };
  }
  const archive = index || await readJsonFile(sourceDir, '_observer/generation-index.json');
  if (archive?.kind !== 'r2-backup-observer-block-archive'
      || archive.complete !== true || Number(archive.blockNum) !== current) {
    throw new Error('observer generation index is incomplete or for a different block');
  }
  const manifestKey = `verification/block${previous}/manifest.json`;
  const summaryKey = `games/block${previous}/summary.json`;
  const manifestRows = rowsFor(archive, manifestKey);
  const summaryRows = rowsFor(archive, summaryKey);
  // The emergency GCP caller supplies its own roster anchor. Preserve that
  // path's selection and window order; the two-roster cap is for normal Stage B.
  const suppliedEmergencyRoster = emergencyLimits && groupingRosterHash !== undefined;
  const roster = suppliedEmergencyRoster ? null
    : await selectRosterManifestGeneration({ sourceDir, index: archive, chain, blockNum: current });
  const savedTime = await deriveGroupingUpperBound(chain, current);
  const entranceTime = includeOutsideWindow || groupingRosterHash === undefined ? null
    : await deriveGroupingUpperBound(chain, current);
  const entranceBoundMs = entranceTime
    ? Math.min(entranceTime.upperMs, entranceUpperMs ?? Infinity) : null;
  const groupingTime = !includeOutsideWindow && entranceTime
    ? { ...savedTime, upperMs: Math.min(savedTime.upperMs, entranceBoundMs),
      source: entranceBoundMs < savedTime.upperMs ? entranceTime.source : savedTime.source,
      entranceUpperMs: entranceTime.upperMs,
      savedUpperMs: savedTime.upperMs }
    : savedTime;
  const history = await findResultRegistrationAtGrouping(
    chain, previous, groupingTime.upperMs, includeOutsideWindow,
    includeOutsideWindow ? null : groupingTime.entryEndMs,
  );
  if (recordedRow !== null) {
    if (!emergencyLimits) throw new Error('recorded previous row is emergency-only');
    const selected = history.rows.find((row) => String(row.index) === String(recordedRow.index));
    if (!selected || String(selected.hash).toLowerCase() !== String(recordedRow.hash).toLowerCase()
        || String(selected.registeredBlock) !== String(recordedRow.registeredBlock)
        || (selected.registeredAt != null
          && String(selected.registeredAt) !== String(recordedRow.registeredAt))) {
      throw new Error(`block ${blockNum}: recorded previous registration is invalid or after grouping bound`);
    }
    history.rows = [selected];
    history.selected = selected;
  }
  const currentMarker = await chain.getResultHash(previous);
  const currentLocation = { currentIndex: history.current?.index ?? null,
    latestIndex: history.current?.index ?? null, matchingIndices: history.current ? [history.current.index] : [] };
  const manifestEvaluations = [];
  const readableManifests = await selectReadableManifestCandidates(sourceDir, manifestRows, null,
    { emergencyLimits, evaluations: manifestEvaluations,
      registeredHashes: emergencyLimits
        ? new Set(history.rows.map((row) => String(row.hash).toLowerCase())) : null });
  const manifestsByCore = new Map();
  for (const candidate of readableManifests) {
    const key = String(candidate.coreHash).toLowerCase();
    if (!manifestsByCore.has(key)) manifestsByCore.set(key, []);
    manifestsByCore.get(key).push(candidate);
  }
  const summariesByHash = new Map();
  for (const row of summaryRows) {
    const key = String(row.sha256 || '').replace(/^0x/i, '').toLowerCase();
    if (!summariesByHash.has(key)) summariesByHash.set(key, []);
    summariesByHash.get(key).push(row);
  }

  const candidates = [];
  const examinedHashes = new Set();
  let candidateStateReads = 0;
  for (const registration of history.rows) {
    const registrationHash = String(registration.hash || '').toLowerCase();
    if (examinedHashes.has(registrationHash)) continue;
    examinedHashes.add(registrationHash);
    const manifests = manifestsByCore.get(registrationHash) || [];
    // Only a distinct log hash with a saved manifest can become a candidate.
    // Verify that candidate before using the hash; decoy repetitions do not
    // spend another state read from this verification run's budget.
    if (manifests.length > 0) {
      if (registration.fromResultLog && typeof chain.resultRegistrationAt === 'function') candidateStateReads++;
      Object.assign(registration, await verifyResultRegistrationRow(chain, previous, registration));
    }
    if (manifests.length === 0) {
      candidates.push({ registration, status: 'manifest_generation_missing' });
      continue;
    }
    const manifest = manifests[0];
    const manifestValue = await readSelectedManifest(sourceDir, manifest);
    const declaredSummarySha256 = manifestValue?.files?.[summaryKey];
    if (typeof declaredSummarySha256 !== 'string') {
      candidates.push({
        registration,
        status: 'summary_not_declared',
        manifestRow: manifest.row,
        manifestVariants: manifests.length,
        declaredSummarySha256: declaredSummarySha256 ?? null,
      });
      continue;
    }
    const summaryMatches = summariesByHash.get(
      declaredSummarySha256.replace(/^0x/i, '').toLowerCase(),
    ) || [];
    if (summaryMatches.length === 0) {
      candidates.push({
        registration,
        status: 'summary_generation_missing',
        manifestRow: manifest.row,
        manifestVariants: manifests.length,
        declaredSummarySha256,
      });
      continue;
    }
    const summaryRow = summaryMatches[0];
    let summary;
    try {
      const declaredBytes = Number(summaryRow.bytes);
      if (emergencyLimits && (!Number.isSafeInteger(declaredBytes) || declaredBytes < 0
          || declaredBytes > GCP_GENERATION_BYTE_LIMIT)) throw new Error('individual row byte limit');
      const bytes = await readRowBytes(sourceDir, summaryRow);
      if (emergencyLimits && bytes.length > GCP_GENERATION_BYTE_LIMIT) {
        throw new Error('individual row byte limit');
      }
      // この summary は上の窓内チェーン登録の manifest が sha256 で束縛している。
      // バイト上限は保ち、非意味欄の深さだけでは正典候補を捨てない。
      summary = JSON.parse(bytes.toString('utf8'));
      if (!summary || typeof summary !== 'object' || Array.isArray(summary)) {
        throw new Error('summary is not a JSON object');
      }
    } catch (error) {
      if (emergencyLimits && archiveIntegrityFailure(error)) throw archiveIntegrityError();
      candidates.push({
        registration,
        status: 'summary_unreadable',
        manifestRow: manifest.row,
        manifestVariants: manifests.length,
        declaredSummarySha256,
        summaryRow,
        error: String(error?.message || error),
      });
      continue;
    }
    candidates.push({
      registration,
      status: 'ready',
      manifestRow: manifest.row,
      manifestVariants: manifests.length,
      declaredSummarySha256,
      summaryRow,
      summaryVariants: summaryMatches.length,
    });
  }
  return {
    previous,
    archive,
    groupingTime,
    rosterDifference: roster?.difference ?? null,
    rosterGenerationMissing: roster == null,
    history,
    currentMarker,
    currentLocation,
    manifestKey,
    summaryKey,
    manifestEvaluations,
    candidates,
    budgets: {
      history: history.budget,
      candidateState: { owner: 'this verification run: saved-manifest candidate log rows before dedupe',
        used: candidateStateReads, limit: null },
      manifests: {
        owner: `${manifestKey} observer generations`,
        used: manifestRows.length,
        limit: null,
        formerLimit: PREVIOUS_MANIFEST_GENERATION_LIMIT,
      },
      summaries: {
        owner: `${summaryKey} observer generations`,
        used: summaryRows.length,
        limit: null,
        formerLimit: PREVIOUS_SUMMARY_GENERATION_LIMIT,
      },
    },
  };
}

// Report every eligible registration row, including repeated hashes. The
// candidate loader evaluates a repeated core only once, but the alert must
// identify every on-chain index whose historical bytes are unavailable.
export function missingPreviousResultVersions(versionSet) {
  const statusByHash = new Map(versionSet.candidates.map((candidate) => [
    String(candidate.registration.hash).toLowerCase(), candidate.status,
  ]));
  return versionSet.history.rows.filter((row) =>
    ['manifest_generation_missing', 'summary_generation_missing'].includes(
      statusByHash.get(String(row.hash).toLowerCase()),
    )).map((row) => ({ index: row.index, hash: row.hash,
    status: statusByHash.get(String(row.hash).toLowerCase()) }));
}

function previousLossArchiveWhat(index) {
  if (Array.isArray(index?.laterSavedGenerations) && index.laterSavedGenerations.length > 0) {
    return 'the N summary used by N+1 grouping is absent from this --manifest archive; later saved N versions remain in the vault';
  }
  if (index?.lineageCheckBypassed === true) {
    return 'the N summary used by N+1 grouping is absent from this --manifest archive; later vault generations require separate inspection';
  }
  return 'the N summary used by N+1 grouping is absent from the observer archive';
}

async function computeMajorLangsFromSavedSummary(blockNum, summary) {
  const gm = withVendorLogging(() => new GameMasterDO({ storage: {} }, {}));
  gm.getR2Object = async (key) => (
    key === `games/block${Number(blockNum) - 1}/summary.json` ? summary : null
  );
  return withVendorLogging(() => gm.computeMajorLangs(blockNum));
}

function emergencyPublishedGroups(groups) {
  return groups.map((group) => ({
    groupId: group.groupId,
    lang: group.lang,
    mixed: group.mixed,
    memberCount: group.members.length,
    memberIds: group.members.map((member) => member.data?.uid || member.globalIndex),
  }));
}

// Only the chain-anchored pre-chat roster can authorize a declared grouping
// when the historical N summary bytes have been lost. The public group list
// alone is never sufficient.
export async function deriveGroupsFromCanonicalRoster({
  sourceDir, index, chain, blockNum, players, publishedGroups, canonical = undefined,
}) {
  let pins;
  if (canonical === undefined) {
    const roster = await selectRosterManifestGeneration({ sourceDir, index, chain, blockNum });
    if (!roster || roster.difference) throw new Error(`block ${blockNum}: canonical roster manifest is unavailable`);
    const bytes = await readRowBytes(sourceDir, roster.row);
    pins = rosterManifestPins(JSON.parse(bytes.toString('utf8')), blockNum, roster.key);
  } else {
    if (!canonical.registration?.row?.hash) {
      throw new Error(`block ${blockNum}: canonical roster manifest is unavailable`);
    }
    pins = canonical.pins ?? null;
  }
  const byId = new Map(players.map((player) => [String(player?.data?.uid), player]));
  const seen = new Set();
  const groups = [];
  if (!Array.isArray(publishedGroups) || (pins && publishedGroups.length !== pins.groupIds.length)) {
    throw new Error(`block ${blockNum}: published groups differ from the canonical roster`);
  }
  for (const published of publishedGroups) {
    const groupId = Number(published?.groupId);
    if ((pins && !pins.groupPins.has(groupId)) || !Array.isArray(published?.memberIds)
        || published.memberIds.length !== Number(published.memberCount)) {
      throw new Error(`block ${blockNum}: invalid canonical group ${groupId}`);
    }
    const members = published.memberIds.map((uid) => {
      const member = byId.get(String(uid));
      if (!member || seen.has(String(uid))) throw new Error(`block ${blockNum}: group member is absent or repeated`);
      seen.add(String(uid));
      return member;
    });
    const group = { groupId, lang: published.lang, mixed: published.mixed, members };
    if (pins && !hashEq(reconstructedRosterGroupSha256(blockNum, group), pins.groupPins.get(groupId))) {
      throw new Error(`block ${blockNum}: group ${groupId} differs from the chain-anchored roster`);
    }
    groups.push(group);
  }
  if (seen.size !== players.length
      || (pins && !hashEq(reconstructedRosterIndexSha256(groups), pins.indexSha256))) {
    throw new Error(`block ${blockNum}: group index differs from the chain-anchored roster`);
  }
  if (canonical !== undefined && !hashEq(
    buildRosterMemberCommitment({ blockNum,
      ...reconstructCanonicalRosterPayloads(blockNum, groups) }).C,
    canonical.registration.row.hash,
  )) {
    throw new Error(`block ${blockNum}: group index differs from the chain-anchored roster`);
  }
  return groups;
}

async function readCurrentGroupingEvidence({
  sourceDir, index, blockNum, currentManifest, markerLabel = 'result manifest marker',
}) {
  const selectionKey = `entries/block${blockNum}/game_selection.json`;
  const groupsKey = `entries/block${blockNum}/game_groups.json`;
  const groupsSha256 = currentManifest?.files?.[groupsKey];
  if (groupsSha256 == null) return null;
  const selectionSha256 = currentManifest?.files?.[selectionKey];
  if (typeof groupsSha256 !== 'string' || typeof selectionSha256 !== 'string') {
    throw new Error(`block ${blockNum}: current result manifest does not declare grouping inputs`);
  }
  const [selectionRow, groupsRow] = await Promise.all([
    selectRowByHash(sourceDir, rowsFor(index, selectionKey), selectionSha256, `${selectionKey} ${markerLabel}`),
    selectRowByHash(sourceDir, rowsFor(index, groupsKey), groupsSha256, `${groupsKey} ${markerLabel}`),
  ]);
  const [selectionBytes, groupsBytes] = await Promise.all([
    readRowBytes(sourceDir, selectionRow),
    readRowBytes(sourceDir, groupsRow),
  ]);
  const selection = JSON.parse(selectionBytes.toString('utf8'));
  const gameGroups = JSON.parse(groupsBytes.toString('utf8'));
  const summaryKey = `games/block${blockNum}/summary.json`;
  const summarySha256 = currentManifest?.files?.[summaryKey];
  const summaryRows = rowsFor(index, summaryKey);
  const summaryRow = typeof summarySha256 === 'string' && summaryRows.length > 0
    ? await selectRowByHash(sourceDir, rowsFor(index, summaryKey), summarySha256,
      `${summaryKey} ${markerLabel}`) : null;
  const summary = summaryRow
    ? JSON.parse((await readRowBytes(sourceDir, summaryRow)).toString('utf8')) : null;
  if (!Array.isArray(selection?.players) || !Array.isArray(gameGroups?.groups)) {
    throw new Error(`block ${blockNum}: saved grouping inputs have an invalid structure`);
  }
  const groupSeed = keccak256(concatHex([
    selection.randao,
    selection.applicantHash,
    stringToHex('group'),
  ]));
  return {
    selection,
    gameGroups,
    summary,
    groupSeed,
    selectionKey,
    selectionRow,
    groupsKey,
    groupsRow,
  };
}

function previousCandidateForReport(candidate) {
  return {
    index: candidate.registration?.index ?? null,
    hash: candidate.registration?.hash ?? null,
    registeredBlock: candidate.registration?.registeredBlock ?? null,
    registeredAt: candidate.registration?.registeredAt ?? null,
    signer: candidate.registration?.signer ?? null,
    status: candidate.status,
    manifestGeneration: candidate.manifestRow?.generation ?? null,
    summaryGeneration: candidate.summaryRow?.generation ?? null,
    ...(candidate.status === 'summary_unreadable' ? {
      summarySha256: candidate.summaryRow?.sha256 ?? null,
      summaryBytes: candidate.summaryRow?.bytes ?? null,
    } : {}),
    majorLangs: candidate.majorLangs ?? null,
    reproducesGroups: candidate.reproducesGroups === true,
    reason: candidate.reason ?? candidate.error ?? null,
  };
}

async function selectPreviousBlockInputsByCurrentMarker({
  sourceDir, index, chain, blockNum, differences,
}) {
  const previous = Number(blockNum) - 1;
  if (previous < 0) return null;
  const manifestKey = `verification/block${previous}/manifest.json`;
  const summaryKey = `games/block${previous}/summary.json`;
  const anchored = await chain.getResultHash(previous);
  const manifestEvaluations = [];
  const matching = anchored?.hash
    ? await selectReadableManifestCandidates(sourceDir, rowsFor(index, manifestKey), anchored.hash,
      { emergencyLimits: true, evaluations: manifestEvaluations,
        registeredHashes: new Set([String(anchored.hash).toLowerCase()]) })
    : [];
  if (manifestEvaluations.length > 0) differences.push({
    checkId: 'emergency.previousManifestGenerations', what: manifestKey,
    chain: { blockNum: previous, hash: anchored?.hash ?? null },
    rebuilt: { unusableCandidates: manifestEvaluations },
    reason: 'unusable saved manifest generations were not selected',
  });
  if (matching.length === 0) {
    const difference = {
      checkId: 'check.stageB.prevAnchor',
      what: anchored?.hash
        ? 'previous result manifest marker does not select any saved generation'
        : 'previous result manifest marker is absent',
      chain: { blockNum: previous, hash: anchored?.hash ?? null, updatedBlock: anchored?.updated ?? null },
      rebuilt: { savedManifestGenerations: rowsFor(index, manifestKey).length },
      reason: 'the operator can register the correct previous manifest core before rerunning recovery',
    };
    throw emergencySelectionError(
      `block ${previous}: チェーンの結果ハッシュが保存世代のどれとも一致しません。`
      + '正しい manifest core を登録してから再実行してください',
      [...differences, difference],
    );
  }
  if (new Set(matching.map((candidate) => candidate.row.sha256)).size > 1) {
    differences.push({
      checkId: 'emergency.previousManifestBytes',
      what: `multiple saved byte generations have the same previous manifest core: ${manifestKey}`,
      chain: { blockNum: previous, hash: anchored.hash, updatedBlock: anchored.updated ?? null },
      rebuilt: { byteVariants: new Set(matching.map((candidate) => candidate.row.sha256)).size },
      reason: 'fields outside manifestCore do not affect recomputation; the earliest saved generation is used',
    });
  }
  const selectedManifest = matching[0];
  const selectedManifestValue = await readSelectedManifest(sourceDir, selectedManifest);
  if (rowsFor(index, manifestKey).length > 1) {
    differences.push({
      checkId: 'emergency.previousManifestGenerations',
      what: `chain marker selected one previous manifest generation and discarded the others: ${manifestKey}`,
      chain: { blockNum: previous, hash: anchored.hash, updatedBlock: anchored.updated ?? null },
      rebuilt: {
        savedGenerations: rowsFor(index, manifestKey).length,
        matchingGenerations: matching.length,
        selectedGeneration: selectedManifest.row.generation ?? null,
      },
      reason: 'only the chain-selected previous manifest core can authorize the previous summary',
    });
  }
  const wantedSummaryHash = selectedManifestValue?.files?.[summaryKey];
  if (typeof wantedSummaryHash !== 'string') {
    const difference = {
      checkId: 'check.stageB.prevAnchor',
      what: 'chain-selected previous manifest does not declare the previous summary',
      chain: { blockNum: previous, hash: anchored.hash, updatedBlock: anchored.updated ?? null },
      rebuilt: { summaryKey, declaredSha256: wantedSummaryHash ?? null },
      reason: 'the operator can register a corrected previous manifest core before rerunning recovery',
    };
    throw emergencySelectionError(
      `${manifestKey}: chain-selected manifest does not declare ${summaryKey}`,
      [...differences, difference],
    );
  }
  let summaryRow;
  try {
    summaryRow = await selectRowByHash(
      sourceDir, rowsFor(index, summaryKey), wantedSummaryHash, `${summaryKey} previous manifest marker`,
    );
  } catch (error) {
    const difference = {
      checkId: 'check.stageB.prevAnchor',
      what: 'previous manifest summary hash does not select any saved generation',
      chain: { blockNum: previous, manifestCoreHash: anchored.hash, summarySha256: wantedSummaryHash },
      rebuilt: { savedSummaryGenerations: rowsFor(index, summaryKey).length },
      reason: 'the operator can restore the declared summary or register a corrected previous manifest core',
    };
    throw emergencySelectionError(error.message, [...differences, difference]);
  }
  if (rowsFor(index, summaryKey).length > 1) {
    differences.push({
      checkId: 'emergency.previousSummaryGenerations',
      what: `previous manifest selected one summary generation and discarded the others: ${summaryKey}`,
      chain: { blockNum: previous, manifestCoreHash: anchored.hash, summarySha256: wantedSummaryHash },
      rebuilt: {
        savedGenerations: rowsFor(index, summaryKey).length,
        selectedGeneration: summaryRow.generation ?? null,
      },
      reason: 'the previous manifest files hash is the authority for the summary bytes',
    });
  }
  // 🔴 周29 (c)（2026-09-22）: **選び方は変えない**（変えると固定一式のバイトが動く＝方式の変更）。
  //    いま何を選んでいるか（チェーンの現在値が追記履歴のどの行か）を**見えるようにするだけ**。
  //    履歴が読めないことは復旧を止めない。読めなかったことを記録する。
  let registration = {
    blockNum: previous,
    selectionRule: 'HashStorage.getResultHash current value (unchanged)',
    hash: anchored?.hash ?? null,
    updatedBlock: anchored?.updated ?? null,
    signer: anchored?.signer ?? null,
    registrationCount: null,
    currentIndex: null,
    matchingIndices: null,
    latestIndex: null,
    historyError: 'resultRegistrationHistory is not available on this chain reader',
  };
  if (typeof chain.resultRegistrationHistory === 'function') {
    try {
      const history = await chain.resultRegistrationHistory(previous);
      const located = locateCurrentResultRow(history, anchored);
      registration = {
        blockNum: previous,
        selectionRule: located.selectionRule,
        hash: anchored?.hash ?? null,
        updatedBlock: anchored?.updated ?? null,
        signer: anchored?.signer ?? null,
        registrationCount: located.registrationCount,
        currentIndex: located.currentIndex,
        matchingIndices: located.matchingIndices,
        latestIndex: located.latestIndex,
        historyError: null,
      };
    } catch (error) {
      registration = { ...registration, historyError: String(error?.message || error) };
    }
  }
  return {
    manifestKey,
    manifestRow: selectedManifest.row,
    summaryKey,
    summaryRow,
    registration,
  };
}

async function selectPreviousBlockInputs({
  sourceDir, index, chain, blockNum, currentManifest, differences,
  markerLabel = 'result manifest marker', canonicalRoster = undefined,
}) {
  const previous = Number(blockNum) - 1;
  if (previous < 0) return null;

  let groupingEvidence;
  try {
    groupingEvidence = await readCurrentGroupingEvidence({
      sourceDir, index, blockNum, currentManifest, markerLabel,
    });
  } catch (error) {
    const difference = {
      checkId: 'check.stageB.prevAnchor',
      what: 'the saved current-block grouping evidence is unavailable or invalid',
      chain: { blockNum: previous },
      rebuilt: { candidates: [], error: String(error?.message || error) },
      reason: 'the previous result version cannot be selected without reproducing the actual next-block grouping',
    };
    throw emergencySelectionError(error.message, [...differences, difference]);
  }

  // 0名／自動配布など game_groups が result manifest に無いブロックでは、主要言語は
  // グループを1件も動かさない。既存の現在目印による2ホップ選択をそのまま保つ。
  if (!groupingEvidence) {
    return selectPreviousBlockInputsByCurrentMarker({
      sourceDir, index, chain, blockNum, differences,
    });
  }
  const recordedRow = groupingEvidence.gameGroups.prevResultRegistration;
  if (recordedRow === undefined) {
    throw emergencySelectionError(`block ${blockNum}: game_groups.json lacks prevResultRegistration`, differences);
  }
  if (recordedRow?.status === 'none' && Object.keys(recordedRow).length === 1) {
    return selectPreviousBlockInputsByCurrentMarker({ sourceDir, index, chain, blockNum, differences });
  }
  if (!recordedRow || !/^(0|[1-9]\d*)$/.test(String(recordedRow.index ?? ''))
      || !/^[1-9]\d*$/.test(String(recordedRow.registeredBlock ?? ''))
      || !/^[1-9]\d*$/.test(String(recordedRow.registeredAt ?? ''))
      || !/^0x[0-9a-f]{64}$/.test(String(recordedRow.hash ?? ''))) {
    throw emergencySelectionError(`block ${blockNum}: invalid recorded previous registration`, differences);
  }
  // A missing N+1 summary cannot declare majorLangs. Keep the original
  // current-marker path and let Stage C report that missing input at its
  // original point, instead of turning it into a U-4 selection error.
  if (groupingEvidence.summary == null
      && rowsFor(index, `games/block${blockNum}/summary.json`).length === 0) {
    return selectPreviousBlockInputsByCurrentMarker({
      sourceDir, index, chain, blockNum, differences,
    });
  }

  let versionSet;
  try {
    versionSet = await loadPreviousResultVersionCandidates({
      sourceDir, index, chain, blockNum, includeOutsideWindow: false, emergencyLimits: true,
      recordedRow,
    });
  } catch (error) {
    const difference = {
      checkId: 'check.stageB.prevAnchor',
      what: 'previous result history or observer generations could not be evaluated within their owner budget',
      chain: { blockNum: previous },
      rebuilt: {
        candidates: [],
        budget: error.previousResultBudget ?? null,
        error: String(error?.message || error),
      },
      reason: 'provide a complete bounded materialize-block archive and a readable HashStorage history',
    };
    throw emergencySelectionError(error.message, [...differences, difference]);
  }
  if (versionSet.manifestEvaluations.length > 0) differences.push({
    checkId: 'emergency.previousManifestGenerations', what: versionSet.manifestKey,
    chain: { blockNum: previous },
    rebuilt: { unusableCandidates: versionSet.manifestEvaluations },
    reason: 'unusable saved manifest generations were not selected',
  });

  const evaluated = [];
  const gm = withVendorLogging(() => new GameMasterDO({ storage: {} }, {}));
  let evaluations = 0;
  const evaluatedHashes = new Map();
  for (const candidate of versionSet.candidates) {
    if (candidate.status !== 'ready') {
      evaluated.push(candidate);
      continue;
    }
    const hashKey = String(candidate.registration.hash).toLowerCase();
    if (evaluatedHashes.has(hashKey)) {
      evaluated.push({ ...candidate, ...evaluatedHashes.get(hashKey) });
      continue;
    }
    if (evaluations >= PREVIOUS_RESULT_EVALUATION_LIMIT) {
      const budget = { owner: 'this verification run: distinct saved previous-result versions evaluated',
        used: evaluations, limit: PREVIOUS_RESULT_EVALUATION_LIMIT };
      throw emergencySelectionError(
        `block ${previous}: saved previous-result evaluation budget exhausted`,
        [...differences, { checkId: 'check.stageB.prevAnchor', what: 'saved version evaluation budget exhausted',
          chain: { blockNum: previous }, rebuilt: { candidates: evaluated.map(previousCandidateForReport), budget },
          reason: 'no version is adopted before all eligible history rows are evaluated' }],
      );
    }
    evaluations++;
    try {
      const majorLangs = await computeMajorLangsFromSavedSummary(blockNum,
        await readPreviousResultCandidateSummary(sourceDir, candidate));
      const groups = await withVendorLogging(() => gm.formGroups(
        groupingEvidence.selection.players,
        groupingEvidence.groupSeed,
        majorLangs,
      ));
      const reproducesGroups = isDeepStrictEqual(
        emergencyPublishedGroups(groups),
        groupingEvidence.gameGroups.groups,
      ) && previousMajorLangsMatch(majorLangs, groupingEvidence.summary?.majorLangs);
      const outcome = {
        ...candidate,
        majorLangs,
        reproducesGroups,
        reason: reproducesGroups ? null
          : 'derived groups or majorLangs differ from the saved next-block grouping',
      };
      evaluated.push(outcome);
      evaluatedHashes.set(hashKey, { majorLangs, reproducesGroups, reason: outcome.reason });
    } catch (error) {
      const outcome = {
        ...candidate,
        status: 'evaluation_failed',
        reproducesGroups: false,
        reason: String(error?.message || error),
      };
      evaluated.push(outcome);
      evaluatedHashes.set(hashKey, { status: outcome.status, reproducesGroups: false, reason: outcome.reason });
    }
  }
  versionSet.budgets.evaluations = { owner: 'this verification run: distinct saved previous-result versions evaluated',
    used: evaluations, limit: PREVIOUS_RESULT_EVALUATION_LIMIT };
  const reproducing = evaluated.filter((candidate) => candidate.reproducesGroups === true);
  if (reproducing.length === 0) {
    const missingVersions = missingPreviousResultVersions(versionSet);
    if (missingVersions.length > 0
        && Array.isArray(groupingEvidence.summary?.majorLangs)) {
      let canonicalGroups;
      try {
        let canonical = canonicalRoster;
        if (canonical === undefined) {
          const registration = await resolveRosterRegistration(chain, blockNum);
          let pins = null;
          const saved = await selectRosterManifestGeneration({ sourceDir, index, chain, blockNum });
          if (saved && !saved.difference) {
            pins = rosterManifestPins(JSON.parse((await readRowBytes(sourceDir, saved.row)).toString('utf8')),
              blockNum, saved.key);
          }
          canonical = { registration, pins };
        }
        canonicalGroups = await deriveGroupsFromCanonicalRoster({
          sourceDir, index, chain, blockNum, canonical,
          players: groupingEvidence.selection.players,
          publishedGroups: groupingEvidence.gameGroups.groups,
        });
      } catch (error) {
        throw emergencySelectionError(error.message, [...differences, {
          checkId: 'emergency.previousSummaryLost',
          what: 'the saved grouping does not reproduce the canonical roster',
          chain: { blockNum: previous, missingVersions },
          rebuilt: { error: String(error?.message || error) },
          reason: 'the historical summary is absent and the canonical roster must still match',
        }]);
      }
      const declaredGroups = await withVendorLogging(() => gm.formGroups(
        groupingEvidence.selection.players, groupingEvidence.groupSeed,
        groupingEvidence.summary.majorLangs,
      ));
      if (!isDeepStrictEqual(emergencyPublishedGroups(declaredGroups),
        emergencyPublishedGroups(canonicalGroups))) {
        throw emergencySelectionError(
          `block ${blockNum}: declared major languages do not reproduce the chain-anchored groups`,
          differences,
        );
      }
      const savedMismatches = evaluated.filter((candidate) =>
        candidate.status === 'ready' && candidate.reproducesGroups !== true)
        .map((candidate) => ({ index: candidate.registration.index, hash: candidate.registration.hash }));
      differences.push({
        checkId: 'emergency.previousSummaryLost',
        what: previousLossArchiveWhat(index),
        chain: { blockNum: previous, groupingBlock: blockNum,
          missingVersions, savedMismatches,
          eligible: evaluated.map((candidate) => ({ index: candidate.registration.index,
            hash: candidate.registration.hash })) },
        rebuilt: { majorLangs: groupingEvidence.summary.majorLangs,
          groups: canonicalGroups.length, authority: 'chain-anchored canonical roster' },
        reason: savedMismatches.length > 0
          ? 'saved in-window versions do not reproduce grouping; unsaved in-window versions leave major languages unverifiable'
          : 'historical manifest or summary bytes are missing; major languages cannot be verified',
      });
      return { unverifiable: true, canonicalGroups, missingVersions, savedMismatches,
        majorLangs: groupingEvidence.summary.majorLangs };
    }
    versionSet.budgets.failureAudit = await verifyResultHistoryOnFailure(
      chain, previous, versionSet.history,
    );
    const difference = {
      checkId: 'check.stageB.prevAnchor',
      what: 'no previous result history row reproduces the actual next-block grouping',
      chain: {
        blockNum: previous,
        currentHash: versionSet.currentMarker?.hash ?? null,
        currentIndex: versionSet.currentLocation?.currentIndex ?? null,
        registrationCount: versionSet.history.count,
      },
      rebuilt: {
        candidates: evaluated.map(previousCandidateForReport),
        budgets: versionSet.budgets,
      },
      reason: 'restore the missing observer generations; do not substitute the current previous-block marker',
    };
    throw emergencySelectionError(
      `block ${previous}: no saved result version can reproduce block ${blockNum} grouping`,
      [...differences, difference],
    );
  }

  // Only versions current within the grouping window may explain N+1.
  const selected = reproducing[0];
  const selectedIndex = Number(selected.registration.index);
  Object.assign(selected.registration,
    await verifyResultRegistrationRow(chain, previous, selected.registration));
  if (recordedRow && (
      String(selected.registration.index) !== String(recordedRow.index)
      || String(selected.registration.hash).toLowerCase() !== String(recordedRow.hash).toLowerCase()
      || String(selected.registration.registeredBlock) !== String(recordedRow.registeredBlock)
      || String(selected.registration.registeredAt) !== String(recordedRow.registeredAt))) {
    throw emergencySelectionError(`block ${blockNum}: recorded previous row differs from verified chain row`, differences);
  }
  const currentIndex = versionSet.currentLocation?.currentIndex ?? null;
  if (selectedIndex !== currentIndex || versionSet.history.excludedAfterGrouping > 0) {
    differences.push({
      checkId: 'emergency.previousResultVersionSelected',
      what: 'the previous result history row that reproduces the actual next-block grouping was selected',
      chain: {
        blockNum: previous,
        currentHash: versionSet.currentMarker?.hash ?? null,
        currentIndex,
        registrationCount: versionSet.history.count,
        excludedAfterGrouping: versionSet.history.excludedAfterGrouping,
        upperMs: versionSet.groupingTime.upperMs,
        upperSource: versionSet.groupingTime.source,
        outsidePreferredWindow: false,
      },
      rebuilt: {
        selectedIndex,
        selectedHash: selected.registration.hash,
        selectedRegisteredBlock: selected.registration.registeredBlock ?? null,
        selectedRegisteredAt: selected.registration.registeredAt ?? null,
        selectedSigner: selected.registration.signer ?? null,
        majorLangs: selected.majorLangs,
        reproducingIndices: reproducing.map((candidate) => candidate.registration.index),
        manifestGeneration: selected.manifestRow.generation ?? null,
        summaryGeneration: selected.summaryRow.generation ?? null,
        budgets: versionSet.budgets,
      },
      reason: 'later registrations of the previous block do not change the grouping that already happened',
    });
  }
  if (selected.manifestVariants > 1) {
    differences.push({
      checkId: 'emergency.previousManifestBytes',
      what: `multiple saved byte generations have the selected previous manifest core: ${versionSet.manifestKey}`,
      chain: { blockNum: previous, hash: selected.registration.hash, selectedIndex },
      rebuilt: { byteVariants: selected.manifestVariants },
      reason: 'fields outside manifestCore do not affect recomputation; the earliest saved generation is used',
    });
  }
  if (rowsFor(index, versionSet.manifestKey).length > 1) {
    differences.push({
      checkId: 'emergency.previousManifestGenerations',
      what: `group reproduction selected one previous manifest generation: ${versionSet.manifestKey}`,
      chain: { blockNum: previous, hash: selected.registration.hash, selectedIndex },
      rebuilt: {
        savedGenerations: rowsFor(index, versionSet.manifestKey).length,
        selectedGeneration: selected.manifestRow.generation ?? null,
      },
      reason: 'the selected HashStorage history row binds the manifest core used by the actual grouping',
    });
  }
  if (rowsFor(index, versionSet.summaryKey).length > 1) {
    differences.push({
      checkId: 'emergency.previousSummaryGenerations',
      what: `the selected previous manifest picked one summary generation: ${versionSet.summaryKey}`,
      chain: {
        blockNum: previous,
        selectedIndex,
        manifestCoreHash: selected.registration.hash,
        summarySha256: selected.declaredSummarySha256,
      },
      rebuilt: {
        savedGenerations: rowsFor(index, versionSet.summaryKey).length,
        selectedGeneration: selected.summaryRow.generation ?? null,
      },
      reason: 'the selected historical manifest files hash is the authority for the summary bytes',
    });
  }

  return {
    manifestKey: versionSet.manifestKey,
    manifestRow: selected.manifestRow,
    summaryKey: versionSet.summaryKey,
    summaryRow: selected.summaryRow,
    registration: {
      blockNum: previous,
      selectionRule: recordedRow
        ? 'recorded game_groups.json HashStorage result row reproducing the next-block grouping'
        : 'latest in-window HashStorage result row whose saved manifest/summary reproduces the actual next-block grouping',
      hash: selected.registration.hash,
      updatedBlock: selected.registration.registeredBlock ?? null,
      registeredAt: selected.registration.registeredAt ?? null,
      upperMs: versionSet.groupingTime.upperMs,
      upperSource: versionSet.groupingTime.source,
      signer: selected.registration.signer ?? null,
      registrationCount: versionSet.history.count,
      selectedIndex,
      currentIndex,
      matchingIndices: versionSet.currentLocation?.matchingIndices ?? null,
      latestIndex: versionSet.currentLocation?.latestIndex ?? null,
      reproducingIndices: reproducing.map((candidate) => candidate.registration.index),
      majorLangs: selected.majorLangs,
      budgets: versionSet.budgets,
      historyError: null,
    },
  };
}

// 🔴 R28-H3-4-02（2026-09-20・緊急モード専用・ユーザー承認済みの方式変更）:
//    公開された Stage 3 manifest / witness は**権威ではなく、比較のための証跡**である。
//    読めない・消されている・宣言と合わない場合に選択を throw で落とすと、
//    「攻撃者が witness を1件消すだけで復旧が不可能になる」＝救済すべきまさにその場合に
//    緊急輸出が動かない。ここでは差分として記録し、選択を止めない。
//    採用する witness バイト列は verifyEmergencyStage3Witnesses が再計算で作る。
function stage3WitnessUnavailable(differences, { stage3ManifestKey, declaredSha256, what, rebuilt }) {
  differences.push({
    checkId: 'emergency.stage3WitnessUnavailable',
    what,
    chain: { stage3ManifestKey, declaredSha256: declaredSha256 ?? null },
    rebuilt: { ...rebuilt, adoption: 'rebuild the witness from the independent recomputation' },
    reason: 'the published Stage 3 artifacts are evidence only; the recomputed witness is adopted instead',
  });
}

async function selectStage3WitnessInputs({
  sourceDir, index, blockNum, fileMap, selected, declared, differences,
}) {
  const stage3ManifestKey = `verification/block${blockNum}/stage3/manifest.json`;
  if (!Object.hasOwn(declared, stage3ManifestKey)) {
    return { witnessKeys: [], stage3ManifestUsableForZkp: false };
  }
  const declaredSha256 = declared[stage3ManifestKey] ?? null;
  const unusable = (what, rebuilt = {}) => stage3WitnessUnavailable(
    differences, { stage3ManifestKey, declaredSha256, what, rebuilt },
  );
  const mapped = fileMap.get(stage3ManifestKey);
  if (!mapped) {
    unusable(`${stage3ManifestKey}: selected generation is unavailable`);
    return { witnessKeys: [], stage3ManifestUsableForZkp: false };
  }
  let manifest;
  try {
    const bytes = await fs.readFile(under(sourceDir, mapped));
    if (bytes.length > ZKP_INPUT_LIMITS.stage3ManifestBytes) {
      throw new Error(
        `selected Stage 3 manifest bytes ${bytes.length} > limit ${ZKP_INPUT_LIMITS.stage3ManifestBytes}`,
      );
    }
    const rawText = bytes.toString('utf8');
    manifest = validateStage3InputManifest(JSON.parse(rawText), { blockNum, rawText });
  } catch (error) {
    unusable(`${stage3ManifestKey}: selected generation is unusable for ZKP verification`, {
      error: error.message,
    });
    return { witnessKeys: [], stage3ManifestUsableForZkp: false };
  }
  const witnessKeys = [];
  const seenGroups = new Set();
  for (const group of manifest.groups) {
    const groupId = Number(group?.groupId);
    const expectedObject = `verification/block${blockNum}/stage3/group-${groupId}.json`;
    if (!Number.isSafeInteger(groupId) || groupId < 0 || seenGroups.has(groupId)
        || group?.object !== expectedObject || !/^[0-9a-f]{64}$/i.test(String(group?.sha256 || ''))) {
      unusable(`${stage3ManifestKey}: invalid witness declaration for group ${String(group?.groupId)}`, {
        groupId: group?.groupId ?? null,
      });
      continue;
    }
    seenGroups.add(groupId);
    let row;
    try {
      row = await selectRowByHash(
        sourceDir, rowsFor(index, expectedObject), group.sha256, `${expectedObject} Stage 3 manifest marker`,
      );
    } catch (error) {
      unusable(`${expectedObject}: no saved generation matches the declared witness`, {
        groupId, witnessSha256: group.sha256, error: error.message,
      });
      continue;
    }
    fileMap.set(expectedObject, row.savedFile);
    selected.push({ key: expectedObject, ...row, marker: 'stage3.manifest.groups' });
    witnessKeys.push(expectedObject);
    if (rowsFor(index, expectedObject).length > 1) {
      differences.push({
        checkId: 'emergency.stage3WitnessGenerations',
        what: `Stage 3 manifest selected one witness generation and discarded the others: ${expectedObject}`,
        chain: { stage3ManifestKey, declaredSha256: group.sha256 },
        rebuilt: {
          savedGenerations: rowsFor(index, expectedObject).length,
          selectedGeneration: row.generation ?? null,
        },
        reason: 'the selected Stage 3 manifest group hash picks the compared public copy;'
          + ' the adopted witness bytes come from the independent recomputation',
      });
    }
  }
  return { witnessKeys, stage3ManifestUsableForZkp: true };
}

// Every saved row owns its own byte budget. A bad row is recorded and skipped; it
// cannot spend a later honest row's allowance. There is no shared candidate count.
export const GCP_GENERATION_BYTE_LIMIT = 192 * 1024 * 1024;
// Each saved JSON row has its own budget. The smaller comparison limit applies
// only to rebuilt auto output; a decoy cannot consume another row's budget.
export const GCP_AUTO_COMPARISON_BYTE_LIMIT = 8 * 1024 * 1024;
export const GCP_JSON_DEPTH_LIMIT = 256;

function jsonDepthWithinLimit(bytes, limit) {
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (const byte of bytes) {
    if (quoted) {
      if (escaped) escaped = false;
      else if (byte === 0x5c) escaped = true;
      else if (byte === 0x22) quoted = false;
    } else if (byte === 0x22) quoted = true;
    else if (byte === 0x7b || byte === 0x5b) {
      if (++depth > limit) return false;
    } else if (byte === 0x7d || byte === 0x5d) depth--;
  }
  return true;
}

export async function* gcpCandidates(sourceDir, index, key, evaluations) {
  const autoComparison = /^games\/block\d+\/auto-results\.json$/.test(key);
  const byteLimit = autoComparison ? GCP_AUTO_COMPARISON_BYTE_LIMIT : GCP_GENERATION_BYTE_LIMIT;
  for (const row of rowsFor(index, key)) {
    const declaredBytes = Number(row.bytes);
    if (!Number.isSafeInteger(declaredBytes) || declaredBytes < 0 || declaredBytes > byteLimit) {
      evaluations.push({ generation: row.generation, sha256: row.sha256,
        bytes: Number.isSafeInteger(declaredBytes) ? declaredBytes : null, valueType: 'unparsed',
        observationOrdinal: row.observationOrdinal, reason: 'individual row byte limit' });
      continue;
    }
    try {
      const bytes = await readRowBytes(sourceDir, row);
      if (bytes.length > byteLimit) throw new Error('individual row byte limit');
      if (!jsonDepthWithinLimit(bytes, GCP_JSON_DEPTH_LIMIT)) throw new Error('JSON depth limit');
      const raw = bytes.toString('utf8');
      const data = key.endsWith('/summary.json')
        ? parseCanonicalJson(raw, key) : JSON.parse(raw);
      if (key.endsWith('/auto-results.json') && JSON.stringify(data) !== raw) {
        throw new Error('noncanonical comparison JSON');
      }
      yield { row, data, bytes: bytes.length };
    } catch (error) {
      evaluations.push({ generation: row.generation, sha256: row.sha256,
        bytes: declaredBytes,
        valueType: 'unparsed',
        observationOrdinal: row.observationOrdinal,
        reason: error?.canonicalJsonError ? 'noncanonical saved summary'
          : ['individual row byte limit', 'JSON depth limit', 'noncanonical comparison JSON']
            .includes(error?.message) ? error.message : 'unreadable saved generation' });
    }
  }
}

export function gcpUnevaluated(index, key, evaluations) {
  const examined = new Set(evaluations.map((item) => item.observationOrdinal));
  for (const row of rowsFor(index, key)) {
    if (examined.has(row.observationOrdinal)) continue;
    evaluations.push({ generation: row.generation, sha256: row.sha256,
      observationOrdinal: row.observationOrdinal, reason: 'not read after earliest match' });
  }
}

export async function selectGcpGroupGameInputs({ sourceDir, index, chain, blockNum, applicant, pins, differences }) {
  const n = Number(blockNum);
  const selectionKey = `entries/block${n}/game_selection.json`;
  const groupsKey = `entries/block${n}/game_groups.json`;
  const summaryKey = `games/block${n}/summary.json`;
  const timing = await chain.getTimingConstants();
  const entryEndMs = timing.startTimeEntryMs + (n + 1) * timing.blockTimeMs;
  const applicantRows = new Map(applicant.rows.map(({ key, row }) => [key, row]));
  const infos = [];
  const allEntryFiles = [];
  let totalEntries = 0;
  for (let worker = 0; worker < WORKER_COUNT; worker++) {
    const key = `entries/block${n}/info/${workerName(worker)}_info.json`;
    const row = applicantRows.get(key);
    if (!row) throw new Error(`${key}: applicantHash-selected info generation is unavailable`);
    const info = JSON.parse((await readRowBytes(sourceDir, row)).toString('utf8'));
    if (!Array.isArray(info?.entries)) throw new Error(`${key}: invalid selected info generation`);
    infos.push(info);
    for (const file of info.entries) {
      allEntryFiles.push({ filename: file.filename, number: file.number, start: totalEntries });
      totalEntries += file.number;
    }
  }
  const selectedCount = Math.min(totalEntries, Number(pins.gameMaxPlayers));
  // The applicant registration owns this recomputation budget. Saved selection
  // generations only spend their own read/parse budget; decoy generations never
  // repeat winner selection or reads of the applicantHash-selected entry files.
  const targetBlockNum = Number(applicant.registration.registeredBlock) + Number(pins.confirmationBlocks);
  const target = await chain.getBlock(targetBlockNum);
  const seed = keccak256(concat([String(target.mixHash), applicant.registration.hash]));
  const indices = await withVendorLogging(() => selectWinners(seed, totalEntries, selectedCount));
  const expected = [];
  const entryCache = new Map();
  for (const globalIndex of indices) {
    const file = allEntryFiles.find((entry) => globalIndex >= entry.start
      && globalIndex < entry.start + entry.number);
    if (!file) throw new Error(`winner index ${globalIndex} has no selected entry file`);
    const key = `entries/block${n}/entries/${file.filename}.json`;
    if (!entryCache.has(key)) {
      const row = applicantRows.get(key);
      if (!row) throw new Error(`${key}: applicantHash-selected entry file is unavailable`);
      entryCache.set(key, JSON.parse((await readRowBytes(sourceDir, row)).toString('utf8')));
    }
    const localIndex = globalIndex - file.start;
    expected.push({ globalIndex, localIndex, file: file.filename,
      data: entryCache.get(key)[localIndex] });
  }
  expected.sort((a, b) => a.globalIndex - b.globalIndex);
  const selectionEvaluations = [];
  let selection = null;
  for await (const candidate of gcpCandidates(sourceDir, index, selectionKey, selectionEvaluations)) {
    const sel = candidate.data;
    let reason = null;
    try {
      if (!sel || typeof sel !== 'object' || !Array.isArray(sel.players)
          || !hashEq(sel.applicantHash, applicant.registration.hash)
          || Number(sel.hashRegisteredBlock) !== Number(applicant.registration.registeredBlock)
          || Number(sel.confirmationBlocks) !== Number(pins.confirmationBlocks)
          || Number(sel.targetBlockNum) !== targetBlockNum
          || (sel.entryPeriodEnd != null && Number(sel.entryPeriodEnd) !== entryEndMs)
          || Number(sel.totalEntries) !== totalEntries || Number(sel.totalSelected) !== selectedCount
          || sel.players.length !== selectedCount) {
        reason = 'selection fields disagree with applicantHash registration, timing, or entry count';
      } else {
        if (!hashEq(sel.targetBlockHash, target.hash) || !hashEq(sel.randao, target.mixHash)) {
          reason = 'target block hash or RANDAO differs from chain';
        } else if (!isDeepStrictEqual(expected, sel.players)) reason = 'players differ from vendored selectWinners';
      }
    } catch (error) { reason = String(error?.message || error); }
    selectionEvaluations.push({ generation: candidate.row.generation, sha256: candidate.row.sha256,
      observationOrdinal: candidate.row.observationOrdinal,
      reason: reason || 'matches applicantHash and RANDAO recomputation' });
    if (!reason) { selection = candidate; break; }
  }
  if (!selection) {
    throw emergencySelectionError(`${selectionKey}: no saved generation reproduces Stage A/B`, [
      ...differences, { checkId: 'emergency.gcpSelectionCandidates', what: selectionKey,
        chain: { applicantHash: applicant.registration.hash },
        rebuilt: { candidates: selectionEvaluations }, reason: 'no candidate was guessed' },
    ]);
  }
  if (rowsFor(index, selectionKey).length > 1) {
    gcpUnevaluated(index, selectionKey, selectionEvaluations);
    differences.push({
      checkId: 'emergency.gcpSelectionGeneration', what: 'Stage A/B selected a saved game_selection generation',
      chain: { applicantHash: applicant.registration.hash },
      rebuilt: { selectedGeneration: selection.row.generation, candidates: selectionEvaluations },
      reason: 'the earliest saved generation that reproduces the chain anchors and player list was selected',
    });
  }

  if (selectedCount <= 2) {
    // One or two applicants are an auto distribution, with no game_groups or
    // Evidence timeline. Stage C independently checks deposits and the reward.
    const summaryEvaluations = [];
    let summary = null;
    for await (const candidate of gcpCandidates(sourceDir, index, summaryKey, summaryEvaluations)) {
      const value = candidate.data;
      let reason = selectedCount === 0
        ? 'summary kind or zero-entry fields differ from chain-selected applicants'
        : 'summary kind or auto-distribution players differ from chain-selected applicants';
      try {
        const group = value?.groups?.[0];
        if (selectedCount === 0) {
          if (zeroEntryNoGameSummaryShapeMatches({
            selectionPlayers: selection.data.players, published: value,
            rebuilt: buildZeroEntryNoGameSummary(n, value?.schemaVersion), blockNum: n,
          })) reason = null;
        } else if (value?.autoDistributed === true && value?.noGame !== true
            && Number.isSafeInteger(value?.blockNum) && value.blockNum === n
            && Number.isSafeInteger(value?.totalPlayers) && value.totalPlayers === selectedCount
            && Number.isSafeInteger(value?.totalGroups) && value.totalGroups === 0
            && Array.isArray(value?.groups) && value.groups.length === 1
            && group && typeof group === 'object' && !Array.isArray(group)
            && Number.isSafeInteger(group.group_id) && group.group_id === 0
            && Array.isArray(group.members)
            && group.members.every((member) => member && typeof member === 'object'
              && !Array.isArray(member))
            && isDeepStrictEqual(group.members.map((member) => member.userId),
              selection.data.players.map((player) => player.data?.uid))) reason = null;
      } catch { reason = 'unusable saved summary structure'; }
      summaryEvaluations.push({ generation: candidate.row.generation, sha256: candidate.row.sha256,
        bytes: Number(candidate.row.bytes),
        schemaVersionType: typeof value?.schemaVersion,
        observationOrdinal: candidate.row.observationOrdinal,
        reason: reason || (selectedCount === 0
          ? 'matches chain-selected zero-entry kind' : 'matches chain-selected auto-distribution players') });
      if (!reason) { summary = candidate; break; }
    }
    if (selectedCount === 0) {
      if (rowsFor(index, summaryKey).length > 1) {
        gcpUnevaluated(index, summaryKey, summaryEvaluations);
        differences.push({ checkId: 'emergency.gcpSummaryGeneration', what: summaryKey,
          chain: { selectedCount }, rebuilt: { selectedGeneration: null, candidates: summaryEvaluations },
          reason: 'saved zero-player summaries are comparison evidence only' });
      }
      return { kind: 'noGame', selectionKey, selection, groupsKey: null, groups: null,
        summaryKey, summary: null,
        syntheticSummary: buildZeroEntryNoGameSummary(n, 3, true), derivedGroups: [], timing };
    }
    const syntheticSummary = {
      schemaVersion: 3, blockNum: n, totalPlayers: selectedCount, totalGroups: 0, autoDistributed: true,
      resultLayout: 'auto-distribution-page-v1',
      groups: [{ detailKey: `games/block${n}/auto-results.json` }],
    };
    if (rowsFor(index, summaryKey).length > 1) {
      gcpUnevaluated(index, summaryKey, summaryEvaluations);
      differences.push({ checkId: 'emergency.gcpSummaryGeneration', what: summaryKey,
        chain: { selectedCount },
        rebuilt: { selectedGeneration: summary?.row.generation ?? null, candidates: summaryEvaluations },
        reason: 'saved auto summaries are comparison evidence only' });
    }
    if (rowsFor(index, summaryKey).length > 0) {
      differences.push({ checkId: 'emergency.gcpAutoSavedSummaryComparison', what: summaryKey,
        chain: { selectedCount },
        rebuilt: { authority: 'chain recomputation', savedGeneration: summary?.row.generation ?? null,
          savedSha256: summary?.row.sha256 ?? null,
          savedBytes: summary?.row.bytes ?? null,
          savedSchemaVersionType: summary ? typeof summary.data?.schemaVersion : null,
          savedSchemaVersionCanonical: summary?.data?.schemaVersion === 3,
          candidates: summaryEvaluations },
        reason: 'saved auto summary values cannot determine Stage C input; unusable generations are listed by hash' });
    }
    return { kind: 'autoDistribute', selectionKey, selection, groupsKey: null, groups: null,
      summaryKey, summary, syntheticSummary, derivedGroups: [], timing };
  }

  const groupSeed = keccak256(concatHex([
    selection.data.randao, selection.data.applicantHash, stringToHex('group'),
  ]));
  const rosterRegistration = n > 0 ? await resolveRosterRegistration(chain, n) : null;
  const rosterAnchor = rosterRegistration?.row ?? null;
  const rosterManifestKey = `games/block${n}/roster/manifest.json`;
  let pinnedRosterIndexSha256 = null;
  let selectedRosterManifest = null;
  let canonicalRosterPins = null;
  let attemptedRosterGenerations = 0;
  if (rosterAnchor) {
    for (const row of rowsFor(index, rosterManifestKey)) {
      attemptedRosterGenerations++;
      try {
        if (!Number.isSafeInteger(Number(row.bytes)) || Number(row.bytes) < 0
            || Number(row.bytes) > GCP_GENERATION_BYTE_LIMIT) continue;
        const bytes = await readRowBytes(sourceDir, row);
        if (bytes.length > GCP_GENERATION_BYTE_LIMIT
            || !jsonDepthWithinLimit(bytes, GCP_JSON_DEPTH_LIMIT)) continue;
        const manifestText = bytes.toString('utf8');
        const savedGroupTexts = new Map();
        const savedManifest = JSON.parse(manifestText);
        for (const group of savedManifest.groups) {
          const groupKey = `games/block${n}/roster/group${group.groupId}.json`;
          const saved = rowsFor(index, groupKey).find((candidate) => hashEq(candidate.sha256, group.sha256));
          if (!saved) throw new Error(`saved ${groupKey} is absent`);
          savedGroupTexts.set(group.groupId, (await readRowBytes(sourceDir, saved)).toString('utf8'));
        }
        if (!hashEq(buildRosterMemberCommitment({ blockNum: n,
          manifestText, groupTexts: savedGroupTexts }).C, rosterAnchor.hash)) continue;
        canonicalRosterPins = rosterManifestPins(
          JSON.parse(bytes.toString('utf8')), n, rosterManifestKey,
        );
        pinnedRosterIndexSha256 = canonicalRosterPins.indexSha256;
        selectedRosterManifest = { key: rosterManifestKey, row, origin: 'saved',
          markerKey: keccak256(stringToHex(`bitcoinu:roster:${n}`)) };
        break;
      } catch { /* An unusable saved manifest cannot pin a group generation. */ }
    }
  }
  if (n > 0 && !rosterAnchor?.hash) {
    throw emergencySelectionError(
      `${rosterManifestKey}: canonical roster index cannot be reproduced `
        + `(index=${rosterRegistration?.index ?? 'none'}, hash=${rosterAnchor?.hash ?? 'none'}, `
        + `generations=${attemptedRosterGenerations})`, differences,
    );
  }
  let previousVersions = null;
  if (n > 0) {
    try {
      previousVersions = await loadPreviousResultVersionCandidates({
        sourceDir, index, chain, blockNum: n, includeOutsideWindow: false,
        groupingRosterHash: rosterAnchor?.hash ?? false, emergencyLimits: true,
      });
    } catch (error) {
      if (archiveIntegrityFailure(error)) throw archiveIntegrityError();
      error.message += `; preserve the in-window block ${n - 1} version before retrying block ${n}`;
      throw error;
    }
  }
  if (previousVersions?.manifestEvaluations.length > 0) differences.push({
    checkId: 'emergency.previousManifestGenerations', what: previousVersions.manifestKey,
    chain: { blockNum: n - 1 },
    rebuilt: { unusableCandidates: previousVersions.manifestEvaluations },
    reason: 'unusable saved manifest generations were not selected',
  });
  const preferredMajorLangOptions = n === 0 ? [[]] : [];
  const missingVersions = previousVersions ? missingPreviousResultVersions(previousVersions) : [];
  const historicalSummaryMayBeLost = missingVersions.length > 0;
  const savedPreviousVersions = [];
  if (previousVersions) for (const candidate of previousVersions.candidates) {
    if (candidate.status !== 'ready') continue;
    try {
      const langs = await computeMajorLangsFromSavedSummary(n,
        await readPreviousResultCandidateSummary(sourceDir, candidate));
      savedPreviousVersions.push({ index: candidate.registration.index,
        hash: candidate.registration.hash, majorLangs: langs });
      if (!preferredMajorLangOptions.some((prior) => isDeepStrictEqual(prior, langs))) {
        preferredMajorLangOptions.push(langs);
      }
    } catch { /* The previous-version selector reports unusable rows. */ }
  }
  // N+1 の保存 summary が宣言する主要言語を先に確定する。同じ組に
  // なる別の majorLangs を、前ブロック履歴の新しさだけで選ばない。
  const chatForSummary = await chain.chatWindow(n);
  const entryEndForSummary = Math.round(entryEndMs / 1000);
  const graceForSummary = Number(chatForSummary.chatCloseAt ?? chatForSummary[1])
    - (entryEndForSummary + Math.round(timing.gamePeriodMs / 1000));
  const declaredTimesForSummary = computeDeclaredTimesMs({
    startTimeMs: timing.startTimeEntryMs, blockTimeMs: timing.blockTimeMs,
    gamePeriodMs: timing.gamePeriodMs, submitPeriodMs: timing.submitPeriodMs,
    confirmations: Number(pins.confirmationBlocks),
  }, n, graceForSummary);
  const timelineForSummary = declaredTimesForSummary && {
    graceSec: graceForSummary, chattingStart: declaredTimesForSummary.chattingStart,
    submittingStart: declaredTimesForSummary.submittingStart, closeAt: declaredTimesForSummary.closeAt,
    completedAt: declaredTimesForSummary.completedAt,
  };
  const declaredMajorLangOptions = [];
  const declaredMajorLangEvaluations = [];
  for await (const candidate of gcpCandidates(sourceDir, index, summaryKey,
    declaredMajorLangEvaluations)) {
    if (candidate.data?.noGame !== true && Array.isArray(candidate.data?.majorLangs)
        && isDeepStrictEqual(candidate.data?.timeline, timelineForSummary)) {
      const langs = candidate.data.majorLangs;
      if (langs.length > Math.floor(Number(pins.gameMaxPlayers) / 200)
          || !langs.every((lang) => typeof lang === 'string' && lang.length > 0
            && lang.length <= 32 && /^[A-Za-z0-9-]+$/.test(lang))) {
        declaredMajorLangEvaluations.push({ generation: candidate.row.generation,
          sha256: candidate.row.sha256, bytes: Number(candidate.row.bytes),
          observationOrdinal: candidate.row.observationOrdinal,
          reason: 'unusable declared majorLangs' });
        continue;
      }
      if (!declaredMajorLangOptions.some((prior) => isDeepStrictEqual(prior, langs))) {
        declaredMajorLangOptions.push(langs);
      }
    }
  }
  if (declaredMajorLangEvaluations.length > 0) differences.push({
    checkId: 'emergency.gcpSummaryGeneration', what: summaryKey,
    chain: { blockNum: n }, rebuilt: { unusableCandidates: declaredMajorLangEvaluations },
    reason: 'unusable declared majorLangs generations were not retained',
  });
  if (declaredMajorLangOptions.length === 0) {
    let observedNoGame = null;
    for await (const candidate of gcpCandidates(sourceDir, index, summaryKey, [])) {
      if (candidate.data?.noGame === true) { observedNoGame = candidate.data; break; }
    }
    const cause = observedNoGame
      ? `; ${summaryKey}.noGameReason=${String(observedNoGame.noGameReason ?? 'missing')}`
        + ` and .noGameCause=${String(observedNoGame.noGameCause ?? 'missing')}`
        + ' describe the writer\'s past timeline observation, which current chain state cannot reproduce'
      : '; no saved groupGame summary or independently preserved timeline cause is available';
    throw emergencySelectionError(
      `${summaryKey}: no saved groupGame summary matches chain timeline${cause}`, differences);
  }
  const groupingUpperMs = n === 0 ? null : previousVersions?.groupingTime.upperMs
    ?? (await deriveGroupingUpperBound(chain, n, undefined, rosterAnchor?.hash ?? false)).upperMs;
  const groupsEvaluations = [];
  const gm = withVendorLogging(() => new GameMasterDO({ storage: {} }, {}));
  const options = [];
  const addOption = (langs, stage) => {
    if (declaredMajorLangOptions.some((declared) => previousMajorLangsMatch(langs, declared))
        && !options.some((prior) => prior.stage === stage && isDeepStrictEqual(prior.langs, langs))) {
      options.push({ langs, stage });
    }
  };
  preferredMajorLangOptions.forEach((langs) => addOption(langs, 'in-window'));
  if (historicalSummaryMayBeLost) {
    declaredMajorLangOptions.forEach((langs) => addOption(langs, 'historical-summary-lost'));
  }
  if (pinnedRosterIndexSha256) options.sort((a, b) => (
    Number(a.stage === 'historical-summary-lost') - Number(b.stage === 'historical-summary-lost')
      || declaredMajorLangOptions.findIndex((declared) => previousMajorLangsMatch(a.langs, declared))
        - declaredMajorLangOptions.findIndex((declared) => previousMajorLangsMatch(b.langs, declared))
  ));
  const prepared = [];
  for (const option of options) {
    try {
      if (option.stage === 'historical-summary-lost') {
        const value = await withVendorLogging(() => gm.formGroups(selection.data.players, groupSeed, option.langs));
        prepared.push({ ...option, value, published: emergencyPublishedGroups(value), byLang: null,
          sizes: null, indexSha256: pinnedRosterIndexSha256 });
        continue;
      }
      const value = await withVendorLogging(() => gm.formGroups(selection.data.players, groupSeed, option.langs));
      const byLang = Object.create(null);
      const sizes = {};
      for (const group of value) {
        byLang[group.lang] = (byLang[group.lang] || 0) + 1;
        sizes[group.members.length] = (sizes[group.members.length] || 0) + 1;
      }
      prepared.push({ ...option, value, published: emergencyPublishedGroups(value),
        byLang: { ...byLang }, sizes,
        indexSha256: reconstructedRosterIndexSha256(value) });
    } catch { /* An unusable N version cannot reproduce saved groups. */ }
  }
  const selectionRule = n === 0 ? 'block-zero-observation-order' : 'canonical-chain-roster-index';
  let beforeReadyMatch = null;
  let afterReadyMatch = null;
  let beforeLostMatch = null;
  let afterLostMatch = null;
  // Budget owner: each saved game_groups generation pays for one read and one
  // byte/depth check. The chain roster registration and saved manifest generations
  // were read once above, outside this loop; only group candidates spend this loop's budget.
  const canonicalRoster = { registration: rosterRegistration, pins: canonicalRosterPins };
  if (prepared.length > 0) for await (const candidate of gcpCandidates(
    sourceDir, index, groupsKey, groupsEvaluations,
  )) {
    const { row, data: gg } = candidate;
    let canonicalLostGroups = null;
    if (historicalSummaryMayBeLost) {
      try {
        canonicalLostGroups = await deriveGroupsFromCanonicalRoster({
          sourceDir, index, chain, blockNum: n,
          canonical: canonicalRoster,
          players: selection.data.players, publishedGroups: gg?.groups,
        });
      } catch { /* This saved generation does not reproduce the canonical roster. */ }
    }
    const seenAtMs = Date.parse(String(row.firstSeenAt || row.observedAt || ''));
    const stage = n === 0 ? 'block-zero-observation-order'
      : pinnedRosterIndexSha256 ? 'roster-anchor'
      : Number.isFinite(seenAtMs) && seenAtMs <= groupingUpperMs
        ? 'first-seen-by-upper-bound' : 'after-upper-bound-or-unknown';
    let reason = 'no previous result version with declared majorLangs reproduces groups';
    let match = null;
    let rosterMismatch = false;
    try {
      if (!gg || typeof gg !== 'object' || Array.isArray(gg)
          || typeof gg.groupSeed !== 'string' || typeof gg.randao !== 'string'
          || typeof gg.applicantHash !== 'string') {
        throw new Error('unusable saved group structure');
      }
      for (const option of prepared) {
      const lostOption = option.stage === 'historical-summary-lost';
      const value = lostOption ? canonicalLostGroups : option.value;
      if (!value) continue;
      if (lostOption && !isDeepStrictEqual(
        emergencyPublishedGroups(option.value), emergencyPublishedGroups(value))) continue;
      const published = lostOption ? emergencyPublishedGroups(value) : option.published;
      const byLang = lostOption ? Object.fromEntries(
        [...new Set(value.map((group) => group.lang))].map((lang) =>
          [lang, value.filter((group) => group.lang === lang).length])) : option.byLang;
      const sizes = lostOption ? Object.fromEntries(
        [...new Set(value.map((group) => group.members.length))].map((size) =>
          [size, value.filter((group) => group.members.length === size).length])) : option.sizes;
      if (hashEq(gg?.groupSeed, groupSeed) && hashEq(gg?.randao, selection.data.randao)
            && hashEq(gg?.applicantHash, selection.data.applicantHash)
            && gg?.totalPlayers === selection.data.players.length
            && gg?.totalGroups === value.length
            && gg?.mixedGroups === value.filter((group) => group.mixed).length
            && isDeepStrictEqual(gg?.groups, published)
            && isDeepStrictEqual(gg?.groupsByLang, byLang)
            && isDeepStrictEqual(gg?.groupSizes, sizes)) {
        const candidateRoster = reconstructCanonicalRosterPayloads(n, value);
        if ((pinnedRosterIndexSha256
            && !hashEq(option.indexSha256, pinnedRosterIndexSha256))
            || (!pinnedRosterIndexSha256 && rosterAnchor && !hashEq(
              buildRosterMemberCommitment({ blockNum: n,
                manifestText: candidateRoster.manifestText,
                groupTexts: candidateRoster.groupTexts }).C, rosterAnchor.hash))) {
          rosterMismatch = true;
          continue;
        }
        match = { candidate, derivedGroups: value, majorLangs: option.langs,
          optionStage: option.stage, groupStage: stage,
          previousSummaryLost: lostOption, rosterPayloads: candidateRoster };
        reason = null;
        break;
      }
      reason = 'game_groups differs from vendored formGroups or chain-linked seed';
      }
    } catch { reason = 'unusable saved group structure'; }
    if (!match && rosterMismatch) {
      reason = 'reconstructed roster index differs from earliest chain roster manifest pin';
    }
    groupsEvaluations.push({ generation: row.generation, sha256: row.sha256,
      bytes: Number(row.bytes),
      observationOrdinal: row.observationOrdinal,
      firstSeenAtMs: Number.isFinite(seenAtMs) ? seenAtMs : null,
      selectionRule, stage, optionStage: match?.optionStage ?? null,
      reason: reason || 'matches Stage B groups and declared majorLangs' });
    if (!match) continue;
    if (stage === 'after-upper-bound-or-unknown') {
      if (match.previousSummaryLost) afterLostMatch ||= match;
      else afterReadyMatch ||= match;
    } else {
      if (match.previousSummaryLost) beforeLostMatch ||= match;
      else beforeReadyMatch ||= match;
      if (!pinnedRosterIndexSha256 && beforeReadyMatch) break;
    }
  }
  const chosen = beforeReadyMatch || afterReadyMatch || beforeLostMatch || afterLostMatch;
  if (chosen && !selectedRosterManifest && rosterAnchor) {
    selectedRosterManifest = { key: rosterManifestKey, origin: 'reconstructed',
      manifestText: chosen.rosterPayloads.manifestText };
    pinnedRosterIndexSha256 = sha256(Buffer.from(chosen.rosterPayloads.indexText));
    differences.push({
      checkId: 'emergency.rosterManifestReconstructed',
      what: 'no saved roster manifest generation matches the canonical registration',
      chain: { hash: rosterAnchor.hash, savedGenerations: attemptedRosterGenerations },
      rebuilt: { rosterC: buildRosterMemberCommitment({ blockNum: n,
        manifestText: chosen.rosterPayloads.manifestText,
        groupTexts: chosen.rosterPayloads.groupTexts }).C },
      reason: 'Stage B group bytes reproduce the canonical pre-chat roster registration',
    });
  }
  const groups = chosen?.candidate ?? null;
  const derivedGroups = chosen?.derivedGroups ?? null;
  const majorLangs = chosen?.majorLangs ?? null;
  if (chosen?.previousSummaryLost) differences.push({
    checkId: 'emergency.previousSummaryLost',
    what: previousLossArchiveWhat(index),
    chain: { blockNum: n - 1, groupingBlock: n, missingVersions,
      savedMismatches: savedPreviousVersions.map(({ index: versionIndex, hash }) =>
        ({ index: versionIndex, hash })),
      eligible: previousVersions.candidates.map((candidate) => ({
        index: candidate.registration.index, hash: candidate.registration.hash })) },
    rebuilt: { majorLangs, groups: derivedGroups.length,
      authority: 'chain-anchored canonical roster' },
    reason: savedPreviousVersions.length > 0
      ? 'saved in-window versions do not reproduce grouping; unsaved in-window versions leave major languages unverifiable'
      : 'historical manifest or summary bytes are missing; major languages cannot be verified',
  });
  const safeGroupEvaluations = () => groupsEvaluations.map((evaluation) => ({
    generation: Number.isSafeInteger(Number(evaluation.generation))
      ? Number(evaluation.generation) : null,
    sha256: evaluation.sha256,
    bytes: Number.isSafeInteger(Number(evaluation.bytes)) ? Number(evaluation.bytes) : null,
    firstSeenAtMs: evaluation.firstSeenAtMs ?? null,
    selectionRule: evaluation.selectionRule,
    stage: evaluation.stage,
    optionStage: evaluation.optionStage ?? null,
    reason: evaluation.reason,
  }));
  for (const evaluation of groupsEvaluations) {
    evaluation.selectionRule ??= selectionRule;
    evaluation.stage ??= 'unread-or-unusable';
  }
  if (!groups) {
    if (n > 0 && !pinnedRosterIndexSha256) {
      throw emergencySelectionError(
        `${rosterManifestKey}: canonical roster index cannot be reproduced `
        + `(index=${rosterRegistration?.index ?? 'none'}, hash=${rosterAnchor?.hash ?? 'none'}, `
        + `generations=${attemptedRosterGenerations})`, differences);
    }
    if (previousVersions) {
      previousVersions.budgets.failureAudit = await verifyResultHistoryOnFailure(
        chain, n - 1, previousVersions.history,
      );
    }
    if (prepared.length === 0) {
      for (const row of rowsFor(index, groupsKey)) {
        groupsEvaluations.push({ generation: row.generation, sha256: row.sha256,
          observationOrdinal: row.observationOrdinal, selectionRule,
          stage: 'not-read-no-declared-major-langs-option',
          reason: 'no previous result majorLangs option matches a saved N+1 declaration' });
      }
    } else {
      gcpUnevaluated(index, groupsKey, groupsEvaluations);
    }
    for (const evaluation of groupsEvaluations) {
      evaluation.selectionRule ??= selectionRule;
      evaluation.stage ??= 'unread-or-unusable';
    }
    throw emergencySelectionError(`${groupsKey}: no saved generation reproduces Stage B; `
    + 'a timeline no-game cause needs independently preserved evidence', [
    ...differences, { checkId: 'emergency.gcpGroupsCandidates', what: groupsKey,
      chain: { applicantHash: applicant.registration.hash, groupSeed },
      rebuilt: { selectionRule, candidates: safeGroupEvaluations() }, reason: 'no candidate was guessed' },
    ]);
  }
  gcpUnevaluated(index, groupsKey, groupsEvaluations);
  for (const evaluation of groupsEvaluations) {
    evaluation.selectionRule ??= selectionRule;
    evaluation.stage ??= 'not-read-after-earliest-match';
  }
  if (n === 0) {
    if (rowsFor(index, groupsKey).length > 1) differences.push({
      checkId: 'emergency.gcpGroupsGeneration', what: 'Stage B selected a saved game_groups generation',
      chain: { applicantHash: applicant.registration.hash, groupSeed },
      rebuilt: { selectedGeneration: groups.row.generation,
        candidates: safeGroupEvaluations().map(({ generation, sha256, firstSeenAtMs, reason }) => ({
          generation, sha256, firstSeenAtMs,
          reason: reason === 'matches Stage B groups and declared majorLangs'
            ? 'matches Stage B group recomputation' : reason,
        })) },
      reason: 'the earliest saved generation that reproduces vendored formGroups was selected',
    });
  } else {
    differences.push({
      checkId: 'emergency.gcpGroupsGeneration', what: 'Stage B selected a saved game_groups generation',
      chain: { applicantHash: applicant.registration.hash, groupSeed,
        rosterAnchorHash: rosterAnchor?.hash ?? null, rosterIndexSha256: pinnedRosterIndexSha256,
        groupingUpperMs },
      rebuilt: { selectedGeneration: groups.row.generation, selectionRule,
        selectedGroupStage: chosen.groupStage, selectedOptionStage: chosen.optionStage,
        candidates: safeGroupEvaluations() },
      reason: 'the canonical pre-chat roster registration pins the selected reconstructed roster index',
    });
  }

  const chat = await chain.chatWindow(n);
  const entryEndSec = Math.round(entryEndMs / 1000);
  const chatCloseAt = Number(chat.chatCloseAt ?? chat[1]);
  const graceSec = chatCloseAt - (entryEndSec + Math.round(timing.gamePeriodMs / 1000));
  const declared = computeDeclaredTimesMs({
    startTimeMs: timing.startTimeEntryMs, blockTimeMs: timing.blockTimeMs,
    gamePeriodMs: timing.gamePeriodMs, submitPeriodMs: timing.submitPeriodMs,
    confirmations: Number(pins.confirmationBlocks),
  }, n, graceSec);
  const timeline = declared && { graceSec, chattingStart: declared.chattingStart,
    submittingStart: declared.submittingStart, closeAt: declared.closeAt,
    completedAt: declared.completedAt };
  const summaryEvaluations = [];
  let summary = null;
  for await (const candidate of gcpCandidates(sourceDir, index, summaryKey, summaryEvaluations)) {
    const value = candidate.data;
    let reason = null;
    try {
      if (!timeline || value?.noGame === true || !isDeepStrictEqual(value?.timeline, timeline)
          || !isDeepStrictEqual(value?.majorLangs, majorLangs)
          || !Array.isArray(value?.groups) || value.groups.length !== derivedGroups.length) {
        reason = 'summary timeline, kind, major languages, or group count differs from chain/Stage B';
      } else if (!value.groups.every((group) => group && typeof group === 'object'
          && !Array.isArray(group) && Number.isSafeInteger(group.group_id)
          && Array.isArray(group.members) && group.members.every((member) => member
            && typeof member === 'object' && !Array.isArray(member)))) {
        reason = 'unusable saved summary structure';
      } else {
        const byId = new Map(value.groups.map((group) => [group.group_id, group]));
        for (const group of derivedGroups) {
          const ids = group.members.map((member) => member.data?.uid ?? null);
          if (!isDeepStrictEqual(byId.get(group.groupId)?.members?.map((member) => member.userId ?? null), ids)) {
            reason = `group${group.groupId} member order differs from Stage B`; break;
          }
        }
      }
    } catch { reason = 'unusable saved summary structure'; }
    summaryEvaluations.push({ generation: candidate.row.generation, sha256: candidate.row.sha256,
      bytes: Number(candidate.row.bytes),
      observationOrdinal: candidate.row.observationOrdinal,
      reason: reason || 'matches chain timeline and Stage B groups' });
    if (!reason) { summary = candidate; break; }
  }
  if (!summary) throw emergencySelectionError(
    `${summaryKey}: no saved groupGame summary matches chain and Stage B; `
      + 'a timeline no-game cause needs independently preserved evidence', [
    ...differences, { checkId: 'emergency.gcpSummaryCandidates', what: summaryKey,
      chain: { timeline }, rebuilt: { candidates: summaryEvaluations },
      reason: 'no candidate was guessed; a timeline no-game cause requires preserved evidence' },
  ]);
  if (rowsFor(index, summaryKey).length > 1) {
    gcpUnevaluated(index, summaryKey, summaryEvaluations);
    differences.push({
      checkId: 'emergency.gcpSummaryGeneration', what: 'chain timeline selected a saved summary generation',
      chain: { timeline }, rebuilt: { selectedGeneration: summary.row.generation, candidates: summaryEvaluations },
      reason: 'the earliest saved generation that matches Evidence windows and Stage B was selected',
    });
  }
  return { kind: 'groupGame', selectionKey, selection, groupsKey, groups, summaryKey, summary,
    majorLangs, derivedGroups, groupSeed, timing,
    roster: selectedRosterManifest, canonicalRoster,
    previousMajorLangsUnverifiable: chosen?.previousSummaryLost === true,
    previousMissingVersions: chosen?.previousSummaryLost ? missingVersions : [],
    previousSavedMismatches: chosen?.previousSummaryLost
      ? savedPreviousVersions.map(({ index: versionIndex, hash }) => ({ index: versionIndex, hash })) : [] };
}

async function resolveGcpGenerationMap({
  sourceDir, chain, blockNum, index, applicantRegistrationIndex, applicantRoot, pins,
}) {
  if (!pins) throw new Error('GCP authority requires verifier pins');
  if (rowsFor(index, `entries/block${blockNum}/game_selection.json`).length === 0) {
    throw new Error(`block ${blockNum}: GCP authority entrance requires a saved selection; `
      + 'selection was not saved, so the chain-selected applicant set cannot be reconstructed.');
  }
  const fileMap = new Map();
  const selected = [];
  const differences = [{
    checkId: 'emergency.resultManifestNotAuthoritative',
    what: 'the operator explicitly selected GCP backup and chain reconstruction',
    chain: { resultManifestSelection: 'unused' },
    rebuilt: { authority: 'gcp', blockNum },
    reason: 'the public result manifest is neither a generation selector nor an authority in this entrance',
  }];
  const add = (key, row, marker) => {
    fileMap.set(key, row.savedFile);
    selected.push({ key, ...row, marker });
  };
  let applicantRegistration = null;
  let applicantRegistrationCount = null;
  let applicantSelectionStats = null;
  let applicantEvaluationStats = null;
  const applicant = await selectApplicantGenerationCombination({
    sourceDir, index, chain, blockNum, applicantRegistrationIndex, applicantRoot,
  });
  for (const { key, row } of applicant.rows) add(key, row, 'HashStorage.applicantHash');
  applicantRegistration = applicant.registration;
  applicantRegistrationCount = applicant.registrationCount;
  applicantSelectionStats = applicant.selectionStats;
  applicantEvaluationStats = applicant.evaluationStats;
  differences.push(...(applicant.differences || []));

  const stageB = await selectGcpGroupGameInputs({
    sourceDir, index, chain, blockNum, applicant, pins, differences,
  });
  const roster = stageB.roster ?? null;
  if (roster?.row) {
    add(roster.key, roster.row, `HashStorage.otherHashes:${roster.markerKey}`);
  }
  add(stageB.selectionKey, stageB.selection.row, 'GCP.StageA-B.recomputed');
  if (stageB.groups) add(stageB.groupsKey, stageB.groups.row, 'GCP.StageB.recomputed');
  if (stageB.summary) add(stageB.summaryKey, stageB.summary.row, 'GCP.Evidence.timeline');

  // A group archive is a scoring input, so prefer the first complete saved
  // archive whose group identity and member order agree with verified Stage B.
  // Incomplete generations remain available to submission rescue via the
  // observer index but are not silently treated as a completed archive.
  for (const group of stageB.derivedGroups) {
    const key = `games/block${blockNum}/group${group.groupId}.json`;
    const evaluations = [];
    let picked = null;
    for await (const candidate of gcpCandidates(sourceDir, index, key, evaluations)) {
      const data = candidate.data;
      const memberIds = group.members.map((member) => member.data?.uid ?? null);
      let reason;
      try {
        reason = !Number.isSafeInteger(data?.meta?.blockNum)
          || data.meta.blockNum !== Number(blockNum)
          || !Number.isSafeInteger(data?.meta?.groupId)
          || data.meta.groupId !== Number(group.groupId)
          || !Array.isArray(data?.members)
          || !data.members.every((member) => member && typeof member === 'object'
            && !Array.isArray(member))
          || !isDeepStrictEqual(data.members.map((member) => member.uid ?? null), memberIds)
          || !Array.isArray(data?.messages) || !Array.isArray(data?.receipts)
          || !data?.archivedAt
          ? 'not a complete archive for the Stage B group' : null;
      } catch { reason = 'unusable saved group archive structure'; }
      evaluations.push({ generation: candidate.row.generation, sha256: candidate.row.sha256,
        bytes: Number(candidate.row.bytes),
        observationOrdinal: candidate.row.observationOrdinal,
        reason: reason || 'complete archive for the Stage B group' });
      if (!reason) { picked = candidate; break; }
    }
    if (picked) add(key, picked.row, 'GCP.StageB.groupArchive');
    if (rowsFor(index, key).length > 1 || (!picked && rowsFor(index, key).length > 0)) {
      gcpUnevaluated(index, key, evaluations);
      differences.push({
        checkId: 'emergency.gcpGroupArchiveGeneration', what: key,
        chain: { groupId: group.groupId },
        rebuilt: { selectedGeneration: picked?.row.generation ?? null, candidates: evaluations },
        reason: 'the earliest complete archive with the recomputed member order was selected',
      });
    }
  }

  let previousResultRegistration = null;
  if (Number(blockNum) > 0 && stageB.kind === 'groupGame') {
    let previous;
    try {
      previous = await selectPreviousBlockInputs({
        sourceDir, index, chain, blockNum,
        markerLabel: 'GCP recomputed grouping input',
        currentManifest: { files: {
          [stageB.selectionKey]: stageB.selection.row.sha256,
          [stageB.groupsKey]: stageB.groups.row.sha256,
          [stageB.summaryKey]: stageB.summary.row.sha256,
        } },
        differences, canonicalRoster: stageB.canonicalRoster,
      });
    } catch (error) {
      if (!archiveIntegrityFailure(error)) {
        error.message += `; preserve the in-window block ${Number(blockNum) - 1} version before retrying block ${blockNum}`;
      }
      throw error;
    }
    if (previous && !previous.unverifiable) {
      previousResultRegistration = previous.registration ?? null;
      add(previous.manifestKey, previous.manifestRow, 'HashStorage.previousResultHash');
      add(previous.summaryKey, previous.summaryRow, 'previousManifest.files');
    }
  }

  // These keys are rebuilt by Stage C or the writer. Saved copies are comparison
  // material only; choose the earliest copy usable by its consumer.
  const n = Number(blockNum);
  const wanted = (key) => key === `entries/block${n}/game_selection.json`
    || (stageB.kind === 'groupGame' && key === `entries/block${n}/game_groups.json`)
    || key === `games/block${n}/summary.json`
    || key === `games/block${n}/auto-results.json`
    || (stageB.kind === 'autoDistribute' && [1, 2].includes(stageB.selection?.data?.players?.length)
      && key === `games/block${n}/roster/group0.json`)
    || key === `merkle/block_${n}.json`
    || new RegExp(`^merkle/block_${n}/(?:index|leaves|levels)/`).test(key)
    || key === `verification/block${n}/stage3/manifest.json`;
  for (const key of Object.keys(index.objects || {}).sort()) {
    if (!wanted(key) || fileMap.has(key)) continue;
    const protectedComparison = key === `merkle/block_${n}.json`
      || key === `verification/block${n}/stage3/manifest.json`;
    const evaluations = [];
    let chosen = null;
    for await (const candidate of gcpCandidates(sourceDir, index, key, evaluations)) {
      const valueType = candidate.data === null ? 'null'
        : Array.isArray(candidate.data) ? 'array' : typeof candidate.data;
      let reason = null;
      if (protectedComparison) {
        if (valueType !== 'object' || candidate.bytes > r2LimitForKey(key)) {
          reason = 'unusable comparison copy structure or size';
        } else if (key === `merkle/block_${n}.json`) {
          try {
            // JSON objects can shadow toString and make the later root/amount
            // comparison throw before it can record a difference.
            if (['root', 'totalAmount', 'blockNum'].some((field) =>
              candidate.data[field] !== null && typeof candidate.data[field] === 'object')) {
              throw new Error('metadata value type');
            }
            // The vendored enumerator allocates before its 500-key check. More
            // than 2^19 leaves necessarily exceeds that budget; keep this
            // hostile comparison row from allocating a huge list first.
            if (Number(candidate.data.leafCount) > 2 ** 19) throw new Error('artifact count');
            merkleRebuildArtifactKeys(n, candidate.data);
          } catch { reason = 'unusable merkle reconstruction metadata'; }
        } else {
          try {
            const bytes = await readRowBytes(sourceDir, candidate.row);
            if (bytes.length > ZKP_INPUT_LIMITS.stage3ManifestBytes) throw new Error('size');
            validateStage3InputManifest(candidate.data, { blockNum: n, rawText: bytes.toString('utf8') });
          } catch { reason = 'unusable Stage 3 input manifest'; }
        }
      }
      if (reason) {
        evaluations.push({ generation: candidate.row.generation, sha256: candidate.row.sha256,
          bytes: candidate.bytes, valueType,
          observationOrdinal: candidate.row.observationOrdinal, reason });
        continue;
      }
      chosen = candidate;
      evaluations.push({ generation: candidate.row.generation, sha256: candidate.row.sha256,
        bytes: candidate.bytes, valueType,
        observationOrdinal: candidate.row.observationOrdinal, reason: 'readable comparison copy' });
      break;
    }
    if (chosen) add(key, chosen.row, 'GCP.saved-generation');
    if (rowsFor(index, key).length > 1
        || evaluations.some((item) => item.reason !== 'readable comparison copy')) {
      gcpUnevaluated(index, key, evaluations);
      const publicEvaluations = protectedComparison ? evaluations.map((item) => ({
        sha256: /^[0-9a-f]{64}$/i.test(String(item.sha256)) ? String(item.sha256).toLowerCase() : null,
        bytes: item.bytes != null && Number.isSafeInteger(Number(item.bytes)) && Number(item.bytes) >= 0
          ? Number(item.bytes) : null,
        valueType: ['object', 'array', 'null', 'string', 'number', 'boolean', 'unparsed']
          .includes(item.valueType) ? item.valueType : 'unparsed',
        reason: item.reason,
      })) : evaluations;
      differences.push({
        checkId: 'emergency.gcpComparisonGeneration', what: key,
        chain: { authority: 'Stage C recomputation' },
        rebuilt: protectedComparison
          ? { selectedSha256: chosen?.row.sha256 ?? null, candidates: publicEvaluations }
          : { selectedGeneration: chosen?.row.generation ?? null, candidates: publicEvaluations },
        reason: 'only a comparison copy is selected; reconstructed bytes determine the result',
      });
    }
  }
  const required = [
    `entries/block${n}/game_selection.json`,
  ];
  if (stageB.kind === 'groupGame') required.push(`entries/block${n}/game_groups.json`,
    `games/block${n}/summary.json`);
  for (const key of required) if (!fileMap.has(key)) throw new Error(`${key}: no saved GCP generation`);
  const timing = stageB.timing;
  const selectedManifest = {
    blockNum: n, algorithm: 'sha256',
    rules: {
      startTime: String(timing.startTimeEntryMs), blockTime: timing.blockTimeMs,
      periodDurations: { gamePeriod: timing.gamePeriodMs, submitPeriod: timing.submitPeriodMs },
      claimDataFormat: pins.claimDataFormat, evidence: null,
      ethereumHeaderRuleVersion: pins.ethereumHeaderRuleVersion,
      ethereumHeaderFork: pins.ethereumHeaderFork,
      confirmationBlocks: pins.confirmationBlocks,
    },
    files: Object.fromEntries(selected.filter(({ key }) => wanted(key)).map(({ key, sha256 }) => [key, sha256])),
  };
  if (stageB.syntheticSummary) {
    selectedManifest.files[stageB.summaryKey] = sha256(Buffer.from(JSON.stringify(stageB.syntheticSummary)));
  }
  if (roster) {
    const manifestText = roster.row
      ? (await readRowBytes(sourceDir, roster.row)).toString('utf8') : roster.manifestText;
    const rosterPins = rosterManifestPins(JSON.parse(manifestText), n, roster.key);
    selectedManifest.files[`games/block${n}/roster/index.json`] = rosterPins.indexSha256;
    for (const [groupId, sha] of rosterPins.groupPins) {
      selectedManifest.files[`games/block${n}/roster/group${groupId}.json`] = sha;
    }
  }
  const { witnessKeys, stage3ManifestUsableForZkp } = await selectStage3WitnessInputs({
    sourceDir, index, blockNum: n, fileMap, selected,
    declared: selectedManifest.files, differences,
  });
  // collector は core の後に manifestHash がある正典 writer 形を要求する。
  selectedManifest.manifestHash = manifestCoreHash(selectedManifest);
  return {
    authority: 'gcp', index, fileMap, selectedManifest, selected,
    syntheticSummary: stageB.syntheticSummary ?? null,
    applicantRegistration, applicantRegistrationCount, applicantSelectionStats, applicantEvaluationStats,
    previousResultRegistration, witnessKeys, stage3ManifestUsableForZkp,
    ...(stageB.previousMajorLangsUnverifiable ? {
      previousMajorLangsUnverifiable: {
        majorLangs: stageB.majorLangs, canonicalGroups: stageB.derivedGroups,
        missingVersions: stageB.previousMissingVersions,
        savedMismatches: stageB.previousSavedMismatches,
      },
    } : {}),
    chainResultMarker: await chain.getResultHash(n), differences,
  };
}

export async function resolveEmergencyGenerationMap({
  sourceDir, chain, blockNum,
  applicantRegistrationIndex = null, applicantRoot = null,
  authority = null, pins = null,
}) {
  const index = await readJsonFile(sourceDir, '_observer/generation-index.json');
  if (index?.kind !== 'r2-backup-observer-block-archive' || index.complete !== true
      || Number(index.blockNum) !== Number(blockNum)) {
    throw new Error('observer generation index is incomplete or for a different block');
  }
  if (authority === 'gcp') return resolveGcpGenerationMap({
    sourceDir, chain, blockNum, index, applicantRegistrationIndex, applicantRoot, pins,
  });
  const manifestKey = `verification/block${blockNum}/manifest.json`;
  const manifestRows = rowsFor(index, manifestKey);
  const anchored = await chain.getResultHash(blockNum);
  const manifestEvaluations = [];
  const manifestCandidates = await selectReadableManifestCandidates(sourceDir, manifestRows, null,
    { emergencyLimits: true, evaluations: manifestEvaluations,
      registeredHashes: anchored?.hash ? new Set([String(anchored.hash).toLowerCase()]) : null });
  const matchingManifests = anchored?.hash
    ? manifestCandidates.filter((candidate) => hashEq(candidate.coreHash, anchored.hash)) : [];
  if (manifestCandidates.length === 0) {
    throw new Error(`block ${blockNum}: no readable saved result manifest generation is available`);
  }
  const differences = [];
  if (manifestEvaluations.length > 0) differences.push({
    checkId: 'emergency.manifestGenerations', what: manifestKey,
    chain: { blockNum, hash: anchored?.hash ?? null },
    rebuilt: { unusableCandidates: manifestEvaluations },
    reason: 'unusable saved manifest generations were not selected',
  });
  // resultHash が見るのは manifest core だけ。createdAt 等だけが違う full bytes は
  // 再計算結果へ影響しないため、最初の保存世代を選び、bytes差は記録だけにする。
  if (matchingManifests.length > 0
      && new Set(matchingManifests.map((item) => item.row.sha256)).size !== 1) {
    differences.push({
      checkId: 'emergency.manifestBytes',
      what: 'multiple saved byte generations have the same result manifest core',
      chain: { hash: anchored.hash, updatedBlock: anchored.updated ?? null },
      rebuilt: { byteVariants: new Set(matchingManifests.map((item) => item.row.sha256)).size },
      reason: 'fields outside manifestCore do not affect recomputation; the earliest saved generation is used',
    });
  }
  if (manifestCandidates.length > matchingManifests.length && matchingManifests.length > 0) {
    differences.push({
      checkId: 'emergency.manifestGenerations',
      what: 'the chain result hash selected one manifest core and discarded other readable saved generations',
      chain: { hash: anchored.hash, updatedBlock: anchored.updated ?? null },
      rebuilt: {
        readableGenerations: manifestCandidates.length,
        matchingGenerations: matchingManifests.length,
      },
      reason: 'unmatched manifest generations are not scoring or file-selection authority',
    });
  }
  if (matchingManifests.length === 0) {
    const difference = {
      checkId: 'check.stageC.manifestAnchor',
      what: anchored?.hash
        ? 'result manifest marker does not select any saved generation'
        : 'result manifest marker is absent',
      chain: anchored?.hash
        ? { hash: anchored.hash, updatedBlock: anchored.updated ?? null }
        : { hash: null, updatedBlock: null },
      rebuilt: { savedManifestGenerations: manifestCandidates.length },
      reason: 'the operator can register the correct manifest core before rerunning recovery',
    };
    throw emergencySelectionError(
      `block ${blockNum}: チェーンの結果ハッシュが保存世代のどれとも一致しません。`
      + '正しい manifest core を登録してから再実行してください',
      [...differences, difference],
    );
  }
  const selectedManifest = matchingManifests[0];
  const selectedManifestValue = await readSelectedManifest(sourceDir, selectedManifest);
  const fileMap = new Map([[manifestKey, selectedManifest.row.savedFile]]);
  const selected = [{
    key: manifestKey,
    ...selectedManifest.row,
    marker: 'HashStorage.resultHash',
  }];
  const declared = selectedManifestValue.files || {};
  const speciallySelected = new Set();
  let applicantRegistration = null;
  let applicantRegistrationCount = null;
  let applicantSelectionStats = null;
  let applicantEvaluationStats = null;

  const objectKeys = Object.keys(index.objects || {});
  if (objectKeys.some((key) => isEmergencyApplicantInput(key, blockNum))
      || applicantRegistrationIndex !== null || applicantRoot !== null) {
    const applicant = await selectApplicantGenerationCombination({
      sourceDir, index, chain, blockNum, applicantRegistrationIndex, applicantRoot,
    });
    for (const { key, row } of applicant.rows) {
      fileMap.set(key, row.savedFile);
      selected.push({ key, ...row, marker: 'HashStorage.applicantHash' });
      speciallySelected.add(key);
    }
    applicantRegistration = applicant.registration;
    applicantRegistrationCount = applicant.registrationCount;
    applicantSelectionStats = applicant.selectionStats;
    applicantEvaluationStats = applicant.evaluationStats;
    differences.push(...(applicant.differences || []));
    const applicantSavedRows = objectKeys
      .filter((key) => isEmergencyApplicantInput(key, blockNum))
      .reduce((sum, key) => sum + rowsFor(index, key).length, 0);
    const applicantSelectedRows = applicant.rows
      .filter(({ key }) => isEmergencyApplicantInput(key, blockNum)).length;
    if (applicantSavedRows > applicantSelectedRows) {
      differences.push({
        checkId: 'emergency.applicantDiscardedGenerations',
        what: 'the applicant hash selected one logical input combination and discarded other saved generations',
        chain: { hash: applicant.registration.hash, registrationIndex: applicant.registration.index },
        rebuilt: { savedGenerations: applicantSavedRows, selectedGenerations: applicantSelectedRows },
        reason: 'unselected info/entry generations do not reproduce the eligible registered applicant root',
      });
    }
  }

  const roster = await selectRosterManifestGeneration({ sourceDir, index, chain, blockNum });
  if (roster) {
    fileMap.set(roster.key, roster.row.savedFile);
    selected.push({
      key: roster.key, ...roster.row,
      marker: `HashStorage.otherHashes:${roster.markerKey}`,
    });
    speciallySelected.add(roster.key);
    if (roster.difference) differences.push(roster.difference);
  }

  const previous = await selectPreviousBlockInputs({
    sourceDir, index, chain, blockNum, currentManifest: selectedManifestValue, differences,
  });
  let previousResultRegistration = null;
  if (previous) {
    previousResultRegistration = previous.registration ?? null;
    if (previous.unverifiable) {
      // No historical N bytes are copied into the fixed set. Stage B uses the
      // chain-pinned N+1 roster and the saved N+1 declaration instead.
    } else {
    for (const [key, row, marker] of [
      [previous.manifestKey, previous.manifestRow, 'HashStorage.previousResultHash'],
      [previous.summaryKey, previous.summaryRow, 'previousManifest.files'],
    ]) {
      fileMap.set(key, row.savedFile);
      selected.push({ key, ...row, marker });
      speciallySelected.add(key);
    }
    }
  }

  for (const [key, generations] of Object.entries(index.objects || {})) {
    safeRelative(key);
    if (key === manifestKey) continue;
    if (previous?.unverifiable && (key === `verification/block${Number(blockNum) - 1}/manifest.json`
        || key === `games/block${Number(blockNum) - 1}/summary.json`)) continue;
    if (speciallySelected.has(key) || isEmergencyApplicantInput(key, blockNum)) continue;
    // 🔴 R29-D-2-01（便 Z16）: roster payload の鍵・世代を公開 result manifest に
    //    決めさせない。必要な group 集合が Stage C で再計算された後、
    //    writeEmergencyResultSet がチェーン選択済み roster manifest の sha256 と
    //    再計算 group 集合を使って選ぶ。ここで manifest.files を権威に戻さないこと。
    // group0 は比較資料として最後の保存世代を読むが、公開 manifest に世代を
    // 決めさせない。採用バイトは Stage B selection から正準 writer が作り直す。
    if (isEmergencyRosterPayload(key, blockNum)) {
      if (key === `games/block${blockNum}/roster/group0.json`
          && Object.hasOwn(declared, `games/block${blockNum}/auto-results.json`)) {
        const row = rowsFor(index, key).at(-1);
        if (row) {
          fileMap.set(key, row.savedFile);
          selected.push({ key, ...row, marker: 'observer.latest-comparison' });
        }
      }
      continue;
    }
    if (Object.hasOwn(declared, key)) {
      const wanted = declared[key];
      if (wanted === null) {
        fileMap.set(key, null);
        if (key === `entries/block${blockNum}/game_groups.json` && generations.length > 0) {
          differences.push({
            checkId: 'emergency.declaredNullWithSavedGeneration',
            what: 'the result manifest declares game_groups absent although observer generations exist',
            chain: {
              key,
              declared: null,
              savedGenerations: generations.length,
              savedSha256: [...new Set(generations.map((row) => row.sha256))],
            },
            rebuilt: { selectedValue: null, useAsChatStartEvidence: false },
            reason: 'the null declaration controls file adoption; game_groups can exist before chat starts',
          });
        }
        continue;
      }
      let row;
      try {
        row = await selectRowByHash(sourceDir, generations, wanted, `${key} manifest marker`);
      } catch (error) {
        // 🔴 R29-A-3-02 ≡ R29-B-5-03（2026-09-21・便 W1 の未完了分）:
        //    W1 のコメント（この上の stage3WitnessUnavailable の注記）は逐語で
        //    「読めない・消されている・**宣言と合わない**場合に…差分として記録し、選択を止めない」
        //    と書いているが、この汎用ループは selectStage3WitnessInputs より**先に**走るので、
        //    「保存世代が1本以上あって宣言 sha256 と一致するものが無い」＝攻撃者が選べる側だけが
        //    ここで throw し、W1 の許容枝（`if (!mapped)`）へ到達できなかった。
        //    採用する Stage 3 入力 manifest は publishStage3InputManifest が再計算 pin から
        //    作り直す（公開版は _emergency/public/ へ退避）ので、fail-open にはならない。
        // 🔴 この救済は Stage 3 入力 manifest の鍵**だけ**に限る。他の宣言鍵
        //    （evidence-report / roster / game_selection / game_groups / summary / merkle / group 分冊）は
        //    固定一式へ逐語運搬されるか Stage A/B 再計算の入口なので、従来どおり throw する。
        if (key !== `verification/block${blockNum}/stage3/manifest.json`) throw error;
        stage3WitnessUnavailable(differences, {
          stage3ManifestKey: key,
          declaredSha256: wanted,
          what: `${key}: no saved generation matches the declared Stage 3 input manifest`,
          rebuilt: { savedGenerations: generations.length, error: error.message },
        });
        continue;
      }
      fileMap.set(key, row.savedFile);
      selected.push({ key, ...row, marker: 'manifest.files' });
      continue;
    }
    // manifest外で世代を固定するのは、Stage A/B の再計算入力と、別のHashStorage目印を
    // Stage Cで照合するlive roster manifestだけ。claim status等の可変表示物とlive snapshotは
    // 選択せず、提出rawは後段で全世代を検証する。
    if (!isEmergencyStageABInput(key, blockNum)) continue;
    const distinctHashes = [...new Set(generations.map((row) => String(row.sha256).toLowerCase()))];
    if (distinctHashes.length !== 1) {
      throw new Error(`${key}: no unique chain-marked generation (${distinctHashes.length} saved variants)`);
    }
    const row = await selectRowByHash(sourceDir, generations, distinctHashes[0], `${key} unique generation`);
    fileMap.set(key, row.savedFile);
    selected.push({ key, ...row, marker: 'unique-saved-generation' });
  }
  const { witnessKeys, stage3ManifestUsableForZkp } = await selectStage3WitnessInputs({
    sourceDir, index, blockNum, fileMap, selected, declared, differences,
  });
  return {
    index,
    fileMap,
    selectedManifest: selectedManifestValue,
    selected,
    applicantRegistration,
    applicantRegistrationCount,
    applicantSelectionStats,
    applicantEvaluationStats,
    // 前ブロックの現在行と、R30-U-4 で組を再現して採用した履歴行を報告へ運ぶ。
    previousResultRegistration,
    ...(previous?.unverifiable ? {
      previousMajorLangsUnverifiable: {
        majorLangs: previous.majorLangs, canonicalGroups: previous.canonicalGroups,
        missingVersions: previous.missingVersions,
        savedMismatches: previous.savedMismatches,
      },
    } : {}),
    witnessKeys,
    stage3ManifestUsableForZkp,
    chainResultMarker: anchored ?? null,
    differences,
  };
}

function memberGroups(groupsDerived) {
  return (groupsDerived || []).map((group) => ({
    group_id: Number(group.groupId),
    members: (group.members || []).map((member) => ({
      uid: member?.data?.uid,
      addr: member?.data?.addr,
      bAddr: member?.data?.bAddr,
      pubKey: member?.data?.pubKey,
    })),
  }));
}

export async function selectEmergencyServerSubmissions({
  sourceDir, index, blockNum, groupsDerived, validate = validateResultBundle,
}) {
  const membersIndex = buildMembersIndex(memberGroups(groupsDerived));
  const applicants = (groupsDerived || []).flatMap((group) => group.members || []);
  const archiveRows = [];
  const stage3WitnessPattern = new RegExp(`^verification/block${blockNum}/stage3/group-\\d+\\.json$`);
  const submissionSourcePattern = new RegExp(
    `^(?:live/block${blockNum}/group\\d+\\.submissions|games/block${blockNum}/group\\d+|verification/block${blockNum}/stage3/group-\\d+)\\.json$`,
  );
  for (const [key, rows] of Object.entries(index.objects || {})) {
    if (!submissionSourcePattern.test(key)) continue;
    for (const row of rows) archiveRows.push({ key, ...row });
  }
  archiveRows.sort((a, b) => (
    String(a.observationOrdinal || '').localeCompare(String(b.observationOrdinal || ''))
      || String(a.observedAt || '').localeCompare(String(b.observedAt || ''))
      || a.key.localeCompare(b.key) || Number(a.generation) - Number(b.generation)
  ));

  const selectedByUid = Object.create(null);
  const selectedRawHashes = new Map();
  const candidates = [];
  const contradictions = [];
  for (const row of archiveRows) {
    const bytes = await readRowBytes(sourceDir, row);
    let archive;
    try { archive = JSON.parse(bytes.toString('utf8')); }
    catch {
      candidates.push({ key: row.key, generation: row.generation, valid: false, reason: 'archive_json' });
      continue;
    }
    const invalidCounts = Object.create(null);
    const rowCandidates = [];
    const validationByRawHash = new Map();
    const seenMemberRaw = new Set();
    const rawSubmissions = stage3WitnessPattern.test(row.key)
      ? (function* () {
        if (!Array.isArray(archive?.submissions)) return;
        for (const submission of archive.submissions) yield [submission?.uid, submission?.rawPayload];
      })()
      : (function* () {
        const values = archive?.submissionsRaw;
        if (!values || typeof values !== 'object' || Array.isArray(values)) return;
        for (const uid in values) if (Object.hasOwn(values, uid)) yield [uid, values[uid]];
      })();
    for (const [uidHint, raw] of rawSubmissions) {
      const memberUid = String(uidHint);
      if (!Object.hasOwn(membersIndex.byUid, memberUid)) {
        invalidCounts.unknownMember = (invalidCounts.unknownMember || 0) + 1;
        continue;
      }
      const rawHash = typeof raw === 'string'
        ? sha256(Buffer.from(raw)) : sha256(Buffer.from(JSON.stringify({ type: typeof raw })));
      if (selectedRawHashes.get(memberUid) === rawHash) continue;
      const memberRawKey = `${memberUid}:${rawHash}`;
      if (seenMemberRaw.has(memberRawKey)) continue;
      seenMemberRaw.add(memberRawKey);
      let validation;
      if (validationByRawHash.has(rawHash)) validation = validationByRawHash.get(rawHash);
      else {
        // Saved WS submissions have no chain sender; bind them to their indexed
        // member address while the Evidence event path uses the real event sender.
        try { validation = await validate(raw, Number(blockNum), membersIndex,
          membersIndex.byUid[memberUid].addr); }
        catch { validation = { valid: false, reason: 'validation_error' }; }
        validationByRawHash.set(rawHash, validation);
      }
      const contradiction = await submissionContradictsGrouping(
        raw, Number(blockNum), validation, applicants, membersIndex.byUid[memberUid].addr,
      );
      if (contradiction?.uid === memberUid) {
        contradictions.push({ groupId: contradiction.groupId, sha256: rawHash });
        candidates.push({ valid: false, reason: 'compact_context_mismatch',
          contradictionGroupId: contradiction.groupId, sha256: rawHash });
      }
      const record = {
        uidHint: memberUid, key: row.key, generation: Number(row.generation),
        observationOrdinal: row.observationOrdinal || null, observedAt: row.observedAt || null,
        sha256: row.sha256, valid: validation?.valid === true,
        uid: validation?.uid == null ? null : String(validation.uid),
        groupId: validation?.groupId ?? null, reason: validation?.reason || null,
      };
      if (!record.valid || record.uid !== memberUid) {
        const reason = record.uid !== memberUid && record.valid ? 'uid_mismatch'
          : EMERGENCY_SUBMISSION_INVALID_REASONS.has(record.reason)
            ? record.reason : 'invalid_payload';
        invalidCounts[reason] = (invalidCounts[reason] || 0) + 1;
      } else rowCandidates.push(record);
      if (!record.valid || record.uid !== String(uidHint) || selectedByUid[record.uid]) continue;
      selectedByUid[record.uid] = { ...record, raw, bundle: validation.bundle };
      selectedRawHashes.set(memberUid, rawHash);
    }
    if (Object.keys(invalidCounts).length > 0) candidates.push({
      key: row.key, generation: Number(row.generation), valid: false,
      reason: Object.keys(invalidCounts).length === 1
        ? Object.keys(invalidCounts)[0] : 'invalid_submissions',
      counts: invalidCounts, sha256: row.sha256, bytes: bytes.length,
    });
    for (const candidate of rowCandidates) candidates.push(candidate);
  }
  return { selectedByUid, candidates, membersIndex, contradictions };
}

// timeline no-game の開始証拠は result manifest の外にあるため、緊急モードの
// fileMap へ選ばれない。見張り役の索引にある全保存世代を、HTTPへ落とさず検査する。
const emergencyArtifactRowsCache = new WeakMap();
export async function readEmergencyArtifactGenerations({ sourceDir, index, keys, offset = 0 }) {
  const result = new Map();
  const generationLimit = 16;
  const byteLimit = 8 * 1024 * 1024;
  const pageByteLimit = 8 * 1024 * 1024;
  let cached = index && typeof index === 'object' ? emergencyArtifactRowsCache.get(index) : null;
  if (!cached && index && typeof index === 'object') {
    cached = new Map();
    emergencyArtifactRowsCache.set(index, cached);
  }
  for (const key of keys) {
    const sourceRows = index?.objects?.[key];
    let rowCache = cached?.get(key);
    if (!rowCache || rowCache.sourceRows !== sourceRows || rowCache.length !== sourceRows?.length) {
      rowCache = { sourceRows, length: sourceRows?.length, rows: rowsFor(index, key) };
      cached?.set(key, rowCache);
    }
    const rows = rowCache.rows;
    const generations = [];
    let pageBytes = 0;
    for (const row of rows.slice(offset, offset + generationLimit)) {
      if (Number.isSafeInteger(Number(row.bytes)) && Number(row.bytes) > byteLimit) {
        generations.push({ row, data: null, error: 'archive_byte_limit' });
        continue;
      }
      try {
        const stat = await fs.stat(under(sourceDir, row.savedFile));
        if (stat.size > byteLimit) {
          generations.push({ row, data: null, error: 'archive_byte_limit' });
          continue;
        }
        if (generations.length > 0 && pageBytes + stat.size > pageByteLimit) break;
        pageBytes += stat.size;
        const bytes = await readRowBytes(sourceDir, row);
        if (bytes.length > byteLimit || !jsonDepthWithinLimit(bytes, GCP_JSON_DEPTH_LIMIT)) {
          generations.push({ row, data: null, error: bytes.length > byteLimit
            ? 'archive_byte_limit' : 'archive_depth_limit' });
          continue;
        }
        try {
          generations.push({ row, data: JSON.parse(bytes.toString('utf8')), error: null });
        } catch (error) {
          generations.push({ row, data: null, error: 'archive_json' });
        }
      } catch (error) {
        generations.push({ row, data: null, error: 'archive_read' });
      }
    }
    result.set(key, { present: rows.length > 0, generations,
      hasMore: rows.length > offset + generations.length });
  }
  return result;
}

// 緊急モードでも fail のまま輸出を止めない検査IDの全数（＝公開結果との食い違いとして記録し、
// 独立再計算した版を採用する対象）。載せてよいのは「公開物の申告そのもの」を見る検査だけである。
// 固定一式の verification/block{N}/manifest.json は publishVerificationManifest（この下の :1550）で
// **再生成**され、公開 manifest は逐語運搬ループ（:1458-1461。除外条件は :1459 の
// `key === manifestKey || Object.hasOwn(sourceManifestFiles, key)`）からも
// preservedPatterns（:1465-1471）からも外れる。
// だから公開側の申告が壊れていても、再生成物にも再計算結果にも伝わらない。
// 🔴 `check.stageC.rulesTiming` は同じ rules 欄でも**ここへ移してはならない**。
//    START_TIME / BLOCK_TIME / GAME_PERIOD / SUBMIT_PERIOD は makeMemoryGm の env を通って
//    再生成 manifest へ焼き込まれる＝公開申告の壊れが再計算結果へ伝播するからである。
//    一方 minChars/minMessages/maxChars/maxMessages/maxMsgChars（`check.stageC.rulesPins`）は、
//    R29-A-1b-01 / R29-D-2-04（2026-09-21）で env の源を公開 rules から **ctx.cfg.pins** へ移した。
//    🔴 これで番人の向きが変わった: vendored の assertGuestPinnedRules（game-master-DO.js:11679）が
//    突き合わせるのは『公開申告 ↔ 焼き込み値』ではなく『ctx.cfg.pins ↔ 焼き込み値』である。
//    つまり公開申告が何を言っても再生成物へは伝播せず（＝許容表に居てよい）、
//    検証器の pin を --config で焼き込み値から外したときは輸出が止まる（＝fail-closed を保つ）。
//    rulesTiming にその番人は無い。
// 🔴 この配列を触るときは block-verifier/test/q24-emergency-unit.mjs の
//    `expectedAllowedDifferenceChecks`（逐語一致）と件数 pin、および
//    test/v25-timeline-no-game-unit.mjs の件数 pin も同じ便で直すこと。
export const EMERGENCY_ALLOWED_DIFFERENCE_CHECKS = Object.freeze([
  // 固定応募の入口不整合は差として残す。採点は Nostr 鍵を読まず、応募集合は除外しない。
  'check.stageA.entryKeyIntegrity',
  'check.stageC.downloads',
  'check.stageC.groupMembersMatch',
  'check.stageC.groupMeta',
  'check.stageC.rulesPins',
  // 公開 manifest の申告のみ。再生成側は protocol をリテラル 2、blockRewardWei を
  // getBlockRewardWei(blockNum) の再計算で書く（この2値は env を1つも通らない）。
  'check.stageC.rulesReward',
  // 公開 manifest の申告のみ。再生成側の rules.evidence は DO storage の
  // evidence_reconciled_block{N}（チェーン由来の再計算値）から書く（env を通らない）。
  // 🔴 この ID の fail には枝が2つある。許容してよいのは (1) だけだが、(2) は別の検査が止める:
  //   (1) 公開 manifest の rules.evidence === null（申告落ち・results.js:1272-1277）← 許容する枝
  //   (2) TokenMining.evidence() が 0x0＝Evidence 未配線（results.js:1245-1252）。こちらは申告の話では
  //       ないが、同じ枝が evidenceFinality / evidenceCompleteness / archiveChainConsistency も
  //       同時に fail させ、3件とも許容表にも降格表にも無い（evidenceCompleteness は
  //       EMERGENCY_REQUIRED_CHECKS にも在る）ので輸出は止まる。
  //       🔴 **その3件のどれかを将来この表へ動かすと (2) の穴が開く。**
  // 🔴 (1) を許容すると、下流で2つの検査が静かに減る（結果値は動かないが検出力は減る）:
  //   - results.js:1298-1300 が `check.stageC.chatWindowDeclared` を fail ではなく **skip** にする
  //   - results.js:1482 の `if (!F.declaredDisabled)` が evidenceReportMatch の宣言件数照合を落とす。
  //     残る evidence-report.json 本体の照合（results.js:1492-1504）は declaredDisabled でも走り、
  //     evidenceReportMatch は許容表に無いので、そちらが唯一の敵対的検出層として輸出を止める。
  //     **この照合を「重複」として削らないこと。**
  'check.stageC.evidenceDeclaredDisabled',
  // 公開 manifest の申告のみ。rules.evidence.chatWindowMs も同じ再計算値から出る（env を通らない）。
  // チャット時間窓の実体は Evidence のチェーン値から別途導出するので検出力は落ちない。
  'check.stageC.chatWindowDeclared',
  'check.stageC.groupGameResultsMatch',
  'check.stageC.groupCanonicalTimelineMatch',
  'check.stageC.summaryGroupSet',
  'check.stageC.summaryMatch',
  'check.stageC.autoDistributeConsistent',
  'check.stageC.autoResultPage',
  // 自動配布の公開 group0 は比較資料。固定一式は Stage B の selection から再生成する。
  'check.stageC.autoRoster',
  'check.stageC.noGameSummary',
  'check.stageC.timelineNoGameSummary',
  'check.stageC.merkleRoot',
  'check.stageC.merkleTotals',
  // 公開 manifest の申告のみ。再生成側は vendored 定数 CLAIM_DATA_FORMAT を書く（env を通らない）。
  // 🔴 「請求データ本体は下の onchainClaimData が独立に見る」とは**書けない**。
  //    results.js:2590-2594 は claimDataFormat が fail のとき早期 return するので、
  //    `check.stageC.onchainClaimData` は pass とも fail とも**記録されない**（＝補償にならない）。
  //    それでも許容してよい理由は次の2点である:
  //      ① 固定一式の manifest は再生成側が CLAIM_DATA_FORMAT を書き直す（公開申告は運ばれない）
  //      ② 緊急輸出は `_emergency/claim-data-plan.json`（下の :1575）を再計算 summary と
  //         **再生成済み** manifest（capture.get(manifestKey)）から新規に作るので、
  //         事故当時のオンチェーン請求データを採用しない
  //    🔴 代償として、未記録の検査は `_emergency/differences.json` にも1行も残らない
  //       （差分台帳へ積むのは :1648 の「fail として記録された許容検査」だけ）。
  'check.stageC.claimDataFormat',
  'check.stageC.onchainClaimData',
  'check.stageC.evidenceSegmentBoundaries',
]);
const ALLOWED_PUBLIC_RESULT_FAILURES = new Set(EMERGENCY_ALLOWED_DIFFERENCE_CHECKS);

// 同じ入力を通常／緊急で評価したとき、failからwarnへ降格してよい検査IDの全数。
// 分岐側と輸出関門の実効許容集合をこの配列から導出し、暗黙の許容増加を防ぐ。
export const EMERGENCY_DOWNGRADABLE_CHECKS = Object.freeze([
  'check.stageC.futureAnchorsHash',
  'check.stageC.rosterLiveAnchor',
  'check.stageC.manifestAnchor',
  'check.stageC.rootSubmitted',
  'check.stageC.summaryCanonicalJson',
  'check.stageC.rootResubmitted',
  'check.stageC.rootSubmissionRules',
  'check.stageC.lifecycleReplayCurrent',
]);
const DOWNGRADABLE_CHECKS = new Set(EMERGENCY_DOWNGRADABLE_CHECKS);

export function isEmergencyCheckDowngradable(checkId, emergencyMode) {
  return Boolean(emergencyMode) && DOWNGRADABLE_CHECKS.has(checkId);
}

export const EMERGENCY_EFFECTIVE_DIFFERENCE_CHECKS = Object.freeze([
  ...new Set([...EMERGENCY_ALLOWED_DIFFERENCE_CHECKS, ...EMERGENCY_DOWNGRADABLE_CHECKS]),
]);

export const EMERGENCY_REQUIRED_CHECKS = Object.freeze({
  groupGame: Object.freeze([
    'check.stageA.rootMatch', 'check.stageB.playersMatch', 'check.stageB.groupsMatch',
    'check.stageC.evidenceCompleteness', 'check.stageC.depositVerification',
    'check.stageC.depositTableShape', 'check.stageC.scoring', 'check.stageC.merkleRebuild',
  ]),
  autoDistribute: Object.freeze([
    'check.stageA.rootMatch', 'check.stageB.playersMatch',
    'check.stageC.depositVerification', 'check.stageC.autoDistribute',
    'check.stageC.merkleRebuild',
  ]),
  noGame: Object.freeze([
    'check.stageA.rootMatch', 'check.stageB.playersMatch', 'check.stageC.merkleRebuild',
  ]),
  timelineNoGame: Object.freeze([
    'check.stageA.rootMatch', 'check.stageB.playersMatch',
    'check.stageC.timelineNoGameFinality', 'check.stageC.timelineNoGameEvidenceEmpty',
    'check.stageC.timelineNoGameChatNotStarted',
    'check.stageC.evidenceCompleteness', 'check.stageC.merkleRebuild',
  ]),
});

export function assertEmergencyVerificationGate(
  report, rebuild, { acceptRosterOnlyManifestFileListDifference = false } = {},
) {
  if (!rebuild?.rebuiltSummary || !Array.isArray(rebuild?.allGroupResults)) {
    throw new Error('emergency recomputation did not reach the complete scoring result');
  }
  const forbidden = report.list().filter((entry) => (
    entry.status === 'fail'
      && !ALLOWED_PUBLIC_RESULT_FAILURES.has(entry.id)
      && !(acceptRosterOnlyManifestFileListDifference
        && entry.id === 'check.stageC.manifestFileList')
  ));
  if (forbidden.length > 0) {
    throw new Error(`emergency export refused because verification failed: ${forbidden.map((e) => e.id).join(', ')}`);
  }
  const kind = rebuild.kind || 'groupGame';
  const required = EMERGENCY_REQUIRED_CHECKS[kind];
  if (!required) throw new Error(`emergency recomputation has an unknown result kind: ${kind}`);
  for (const id of required) {
    if (report.get(id)?.status !== 'pass') throw new Error(`emergency export requires ${id}=pass`);
  }
  return true;
}

function bytesOfJson(value) { return Buffer.from(JSON.stringify(value)); }
function hexOf(bytes) { return `0x${Buffer.from(bytes).toString('hex')}`; }

// ---------------------------------------------------------------
// Stage 3 witness（緊急モード専用・R28-H3-4-02）
// ---------------------------------------------------------------
// 🔴 2026-09-20・ユーザー承認済みの方式変更。信用の向きを反転させた。
//    旧実装（周27 の 64ded80d）は「公開 witness == 再計算入力」を要求し、違えば throw で
//    緊急輸出を丸ごと落としていた。緊急モードは最初から「再計算結果が公開結果と食い違う」
//    ことを前提にした**復旧手段**なので、これは救済すべきまさにその場合に動かない。
//    → **採用するのは再計算した witness**。公開版は差分として記録するだけにする。
//    throw を残すのは「再計算そのものができない」場合だけ（「できない」と「合わない」を分ける）。

// 採用する witness の群集合は、公開 manifest ではなく**再計算した summary**から導く。
// 平時 GM の canonicalGroupIdsFromFinalizedSummary（game-master-DO.js:9646-9651）と同じ規則。
// ここが公開 manifest 由来のままだと、攻撃者が宣言から1群落とすだけで
// publishStage3InputManifest の再利用枝（同 :11530-11547）が群集合不一致で止まる。
export function emergencyStage3WitnessGroupIds(rebuild) {
  if ((rebuild?.kind || 'groupGame') !== 'groupGame') return [];
  const summary = rebuild?.rebuiltSummary;
  if (!summary || summary.noGame === true || summary.autoDistributed === true) return [];
  const ids = (Array.isArray(summary.groups) ? summary.groups : []).map((group) => Number(group?.group_id));
  if (ids.some((id) => !Number.isSafeInteger(id) || id < 0) || new Set(ids).size !== ids.length) {
    throw new Error('emergency Stage 3 witness set cannot be derived: recomputed summary has invalid group ids');
  }
  return [...ids].sort((a, b) => a - b);
}

function safeGroupIds(values, label) {
  const ids = values.map((value) => Number(value));
  if (ids.some((id) => !Number.isSafeInteger(id) || id < 0)
      || new Set(ids).size !== ids.length) {
    throw new Error(`${label} has invalid or duplicate group ids`);
  }
  return [...ids].sort((a, b) => a - b);
}

function rosterManifestPins(manifest, blockNum, key) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)
      || Number(manifest.blockNum) !== Number(blockNum)
      || !/^[0-9a-f]{64}$/i.test(String(manifest.indexSha256 || ''))
      || !Array.isArray(manifest.groups)) {
    throw new Error(`${key}: chain-selected roster manifest has an invalid structure`);
  }
  const pins = new Map();
  for (const group of manifest.groups) {
    const groupId = Number(group?.groupId);
    if (!Number.isSafeInteger(groupId) || groupId < 0 || pins.has(groupId)
        || !/^[0-9a-f]{64}$/i.test(String(group?.sha256 || ''))) {
      throw new Error(`${key}: invalid or duplicate roster declaration for group ${String(group?.groupId)}`);
    }
    pins.set(groupId, String(group.sha256).toLowerCase());
  }
  return {
    indexSha256: String(manifest.indexSha256).toLowerCase(),
    groupPins: pins,
    groupIds: [...pins.keys()].sort((a, b) => a - b),
  };
}

function resultManifestRosterShape(files, blockNum) {
  const indexKey = `games/block${blockNum}/roster/index.json`;
  const pattern = new RegExp(`^games/block${blockNum}/roster/group(\\d+)\\.json$`);
  const keys = [];
  const groupKeys = [];
  for (const key of Object.keys(files || {})) {
    if (key === indexKey) {
      keys.push(key);
      continue;
    }
    const match = key.match(pattern);
    if (!match) continue;
    keys.push(key);
    groupKeys.push(match[1]);
  }
  return {
    indexDeclared: keys.includes(indexKey),
    keys,
    // 公開側は Number 化せず、group00・安全整数外・順序をそのまま証跡に残す。
    groupKeys,
  };
}

async function selectRosterPayloadRow({ source, key, declaredSha256 }) {
  const rows = rowsFor(source.index, key);
  if (rows.length === 0) {
    throw new Error(`${key}: required roster key has no saved generation in the backup`);
  }
  if (declaredSha256) {
    try {
      return {
        row: await selectRowByHash(
          source.sourceDir, rows, declaredSha256, `${key} chain-selected roster manifest declaration`,
        ),
        marker: 'rosterManifest.sha256',
      };
    } catch (error) {
      throw new Error(`${key}: required roster generation declared by the chain-selected roster manifest is unavailable (${error.message})`);
    }
  }

  // roster manifest から申告が落ちていても、再計算 group 集合がこの鍵を必要とする。
  // バックアップに論理的な候補が1本だけなら、その事実を差分に残して採る。
  // 2本以上なら正典 pin が無く選べないため、最初の世代へは倒さず停止する。
  const distinctHashes = [...new Set(rows.map((row) => String(row.sha256).toLowerCase()))];
  if (distinctHashes.length !== 1) {
    throw new Error(
      `${key}: chain-selected roster manifest has no sha256 declaration and `
      + `${distinctHashes.length} saved variants are ambiguous`,
    );
  }
  return {
    row: await selectRowByHash(
      source.sourceDir, rows, distinctHashes[0], `${key} unique saved roster generation`,
    ),
    marker: 'unique-saved-generation-without-roster-manifest-pin',
  };
}

async function materializeEmergencyRosterPayloads({ blockNum, rebuild, groupsDerived, source, capture,
  acceptedRoster = null }) {
  const adoptedGroupIds = emergencyStage3WitnessGroupIds(rebuild);
  if (adoptedGroupIds.length === 0) return {
    adoptedGroupIds, selected: [], publicRoster: null, rosterManifestGroupIds: [], requiredKeys: [],
  };

  if (!Array.isArray(groupsDerived)) {
    throw new Error('emergency roster key set cannot be derived: ctx.data.groupsDerived is unavailable');
  }
  const derivedGroupIds = safeGroupIds(
    groupsDerived.map((group) => group?.groupId), 'ctx.data.groupsDerived',
  );
  if (!isDeepStrictEqual(derivedGroupIds, adoptedGroupIds)) {
    throw new Error(
      `emergency roster key set cannot be derived: rebuiltSummary groups ${adoptedGroupIds.join(',')}`
      + ` disagree with groupsDerived ${derivedGroupIds.join(',')}`,
    );
  }

  const manifestKey = `games/block${blockNum}/roster/manifest.json`;
  const manifestMapped = source.fileMap.get(manifestKey);
  if (!acceptedRoster?.manifestText && !manifestMapped) {
    throw new Error(`${manifestKey}: chain-selected roster manifest generation is unavailable`);
  }
  let manifest;
  try {
    const manifestText = acceptedRoster?.manifestText
      ?? (await fs.readFile(under(source.sourceDir, manifestMapped))).toString('utf8');
    manifest = JSON.parse(manifestText);
    capture.set(manifestKey, Buffer.from(manifestText));
  } catch (error) {
    throw new Error(`${manifestKey}: chain-selected roster manifest is unreadable (${error.message})`);
  }
  const rosterPins = rosterManifestPins(manifest, blockNum, manifestKey);
  const publicRoster = resultManifestRosterShape(source.selectedManifest?.files || {}, blockNum);
  const indexKey = `games/block${blockNum}/roster/index.json`;
  const required = [
    [indexKey, rosterPins.indexSha256],
    ...adoptedGroupIds.map((groupId) => [
      `games/block${blockNum}/roster/group${groupId}.json`,
      rosterPins.groupPins.get(groupId) || null,
    ]),
  ];
  const selected = [];
  for (const [key, declaredSha256] of required) {
    let choice = null;
    try { choice = await selectRosterPayloadRow({ source, key, declaredSha256 }); }
    catch (error) {
      const groupId = Number(key.match(/\/group(\d+)\.json$/)?.[1]);
      const text = key === indexKey ? acceptedRoster?.indexText
        : acceptedRoster?.groupTexts?.get(groupId);
      const bytes = text == null ? null : Buffer.from(text);
      if (!declaredSha256 || !bytes || bytes.length > r2LimitForKey(key)
          || !hashEq(sha256(bytes), declaredSha256)) throw error;
      capture.set(key, bytes);
      const selection = { key, sha256: sha256(bytes), bytes: bytes.length,
        marker: 'reconstructed-roster-payload' };
      source.selected.push(selection);
      selected.push(selection);
      (source.differences ??= []).push({
        checkId: 'emergency.rosterPayloadReconstructed', what: key,
        chain: { declaredSha256 }, rebuilt: { sha256: selection.sha256 },
        reason: 'no saved generation matches the canonical roster manifest declaration',
      });
      continue;
    }
    const bytes = await readRowBytes(source.sourceDir, choice.row);
    capture.set(key, bytes);
    source.fileMap.set(key, choice.row.savedFile);
    const selection = { key, ...choice.row, marker: choice.marker };
    source.selected.push(selection);
    selected.push(selection);
  }

  return {
    adoptedGroupIds,
    selected,
    publicRoster,
    rosterManifestGroupIds: rosterPins.groupIds,
    requiredKeys: required.map(([key]) => key),
    rosterManifestKey: manifestKey,
  };
}

function isRosterOnlyManifestFileListDifference(sourceFiles, rebuiltFiles, blockNum) {
  const sourceKeys = Object.keys(sourceFiles || {});
  const rebuiltKeys = Object.keys(rebuiltFiles || {});
  if (isDeepStrictEqual(sourceKeys, rebuiltKeys)) return false;
  const keep = (key) => !isEmergencyRosterPayload(key, blockNum);
  return isDeepStrictEqual(sourceKeys.filter(keep), rebuiltKeys.filter(keep));
}

function uidIndexOf(list) {
  if (!Array.isArray(list)) return null;
  const map = new Map();
  for (const item of list) {
    const uid = item?.uid;
    if (typeof uid !== 'string' || map.has(uid)) return null;
    map.set(uid, item);
  }
  return map;
}

// 「並び順だけ」と「中身」を運用者が見分けられるようにする。R28-H3-4-02 の攻撃は
// 並び順を崩す形なので、この2つの区別自体に意味がある。突き合わせは uid をキーに行う。
function witnessShapeDiff(actual, expected) {
  const scalarsOf = (witness) => Object.fromEntries(
    Object.entries(witness || {}).filter(([key]) => key !== 'members' && key !== 'submissions'),
  );
  const left = scalarsOf(actual);
  const right = scalarsOf(expected);
  const differingFields = [...new Set([...Object.keys(left), ...Object.keys(right)])]
    .filter((key) => !isDeepStrictEqual(left[key], right[key])).sort();
  const differingUids = {};
  let comparable = true;
  let orderChanged = false;
  for (const field of ['members', 'submissions']) {
    const a = uidIndexOf(actual?.[field]);
    const b = uidIndexOf(expected?.[field]);
    if (!a || !b) { comparable = false; differingUids[field] = ['(not uid-keyed)']; continue; }
    const uids = [...new Set([...a.keys(), ...b.keys()])].filter((uid) => (
      !a.has(uid) || !b.has(uid) || !isDeepStrictEqual(a.get(uid), b.get(uid))
    ));
    differingUids[field] = uids.slice(0, 20);
    if (uids.length === 0 && [...a.keys()].join(',') !== [...b.keys()].join(',')) orderChanged = true;
  }
  const uidsEqual = comparable && Object.values(differingUids).every((uids) => uids.length === 0);
  return {
    orderOnly: uidsEqual && differingFields.length === 0 && orderChanged,
    differingFields,
    differingUids,
  };
}

// kind: identical / absent / unreadable / serializationOnly / orderOnly / content
export function classifyStage3WitnessDifference(publicBytes, expected, adoptedSha256) {
  if (!publicBytes) return { kind: 'absent', publicSha256: null, differingFields: [], differingUids: {} };
  const publicSha256 = sha256(publicBytes);
  if (publicSha256 === adoptedSha256) {
    return { kind: 'identical', publicSha256, differingFields: [], differingUids: {} };
  }
  let actual;
  try { actual = JSON.parse(publicBytes.toString('utf8')); }
  catch (error) {
    return {
      kind: 'unreadable', publicSha256, parseError: error.message, differingFields: [], differingUids: {},
    };
  }
  if (isDeepStrictEqual(actual, expected)) {
    return { kind: 'serializationOnly', publicSha256, differingFields: [], differingUids: {} };
  }
  const shape = witnessShapeDiff(actual, expected);
  return {
    kind: shape.orderOnly ? 'orderOnly' : 'content',
    publicSha256,
    differingFields: shape.differingFields,
    differingUids: shape.differingUids,
  };
}

function declaredStage3Pins(manifestBytes, blockNum, differences) {
  if (!manifestBytes) return null;
  const unusable = (what, rebuilt = {}) => {
    differences.push({
      checkId: 'emergency.stage3ManifestUnusable',
      what,
      chain: { key: `verification/block${blockNum}/stage3/manifest.json`, publicSha256: sha256(manifestBytes) },
      rebuilt: { ...rebuilt, adoption: 'rebuild the Stage 3 input manifest from the adopted witnesses' },
      reason: 'the published Stage 3 input manifest is evidence only; it does not select the adopted bytes',
    });
    return null;
  };
  let manifest;
  try { manifest = JSON.parse(manifestBytes.toString('utf8')); }
  catch (error) { return unusable('published Stage 3 input manifest is unreadable', { error: error.message }); }
  const groups = Array.isArray(manifest?.groups) ? manifest.groups : null;
  if (manifest?.schemaVersion !== 1 || manifest?.kind !== 'bitcoinu-stage3-input-manifest'
      || Number(manifest?.blockNum) !== Number(blockNum)
      || !groups || groups.length !== Number(manifest?.groupCount)) {
    return unusable('published Stage 3 input manifest is structurally invalid', {
      groupCount: manifest?.groupCount ?? null, groups: groups?.length ?? null,
    });
  }
  const pins = new Map();
  for (const group of groups) {
    const groupId = Number(group?.groupId);
    if (!Number.isSafeInteger(groupId) || groupId < 0 || pins.has(groupId)) continue;
    pins.set(groupId, {
      object: typeof group?.object === 'string' ? group.object : null,
      sha256: String(group?.sha256 || '').toLowerCase(),
    });
  }
  return pins;
}

export function verifyEmergencyStage3Witnesses({ blockNum, rebuild, groupArchives, capture }) {
  const N = Number(blockNum);
  const manifestKey = `verification/block${N}/stage3/manifest.json`;
  const differences = [];
  const groupIds = emergencyStage3WitnessGroupIds(rebuild);
  const declaredPins = declaredStage3Pins(capture.get(manifestKey) || null, N, differences);
  const d1ByGroup = new Map((rebuild?.d1Groups || []).map((row) => [Number(row.group_id), row]));
  const verifiedKeys = [];
  const pins = [];
  const adoptedKeys = new Set();
  for (const groupId of groupIds) {
    const key = `verification/block${N}/stage3/group-${groupId}.json`;
    const groupRow = d1ByGroup.get(groupId);
    const groupData = groupArchives?.get(groupId);
    // 🔴 ここだけは従来どおり止める: 再計算の材料が無い＝「できない」。
    if (!groupRow || !groupData || !rebuild?.verifiedDepositWei) {
      throw new Error(`emergency Stage 3 witness cannot be recomputed for group ${groupId}`);
    }
    let expected;
    try {
      expected = withVendorLogging(() => buildGroupWitness({
        groupRow: { ...groupRow, block_num: N, group_id: groupId },
        groupData,
        verifiedDepositWei: rebuild.verifiedDepositWei,
        chatWindow: rebuild.chatWindowMs ?? null,
      }));
    } catch (error) {
      throw new Error(`emergency Stage 3 witness cannot be recomputed for group ${groupId}: ${error.message}`);
    }
    // 本番 publishStage3GroupWitness（game-master-DO.js:11493-11504）と同じ直列化。
    const bytes = bytesOfJson(expected);
    const adoptedSha256 = sha256(bytes);
    const publicBytes = capture.get(key) || null;
    const classified = classifyStage3WitnessDifference(publicBytes, expected, adoptedSha256);
    if (classified.kind === 'identical') verifiedKeys.push(key);
    else {
      differences.push({
        checkId: 'emergency.stage3WitnessRecomputed',
        what: `Stage 3 witness was rebuilt from the independent recomputation: ${key} (${classified.kind})`,
        chain: {
          key,
          groupId,
          publicSha256: classified.publicSha256,
          declaredSha256: declaredPins?.get(groupId)?.sha256 ?? null,
        },
        rebuilt: {
          difference: classified.kind,
          orderOnly: classified.kind === 'orderOnly',
          sha256: adoptedSha256,
          differingFields: classified.differingFields,
          differingUids: classified.differingUids,
          ...(classified.parseError ? { parseError: classified.parseError } : {}),
        },
        reason: 'the recomputed Stage 3 input is adopted so recovery can proceed; the public copy is recorded',
      });
    }
    capture.set(key, bytes);
    adoptedKeys.add(key);
    pins.push({ groupId, object: key, sha256: adoptedSha256 });
  }
  // 再計算の群集合に無い公開 witness は固定一式から外す（順4 の run-stage3-gcp.sh が
  // 「manifest.jsonに載っていないwitnessがあります」で止まるため。行番号は変動するので文言で指す）。
  // バイト列は証跡として _emergency/public/ に残す。
  const witnessPattern = new RegExp(`^verification/block${N}/stage3/group-\\d+\\.json$`);
  for (const key of [...capture.keys()]) {
    if (!witnessPattern.test(key) || adoptedKeys.has(key)) continue;
    const publicBytes = capture.get(key);
    const publicCopy = `_emergency/public/${key}`;
    capture.delete(key);
    capture.set(publicCopy, publicBytes);
    differences.push({
      checkId: 'emergency.stage3WitnessDropped',
      what: `public Stage 3 witness is not part of the recomputed group set: ${key}`,
      chain: { key, publicSha256: sha256(publicBytes) },
      rebuilt: { adoptedGroupIds: groupIds, publicCopy },
      reason: 'the fixed set carries exactly the witnesses the recomputed summary declares',
    });
  }
  const declaredIds = declaredPins ? [...declaredPins.keys()].sort((a, b) => a - b) : null;
  const adoptedIds = pins.map((pin) => pin.groupId);
  const changedPins = pins.filter((pin) => declaredPins?.get(pin.groupId)?.sha256 !== pin.sha256)
    .map((pin) => pin.groupId);
  if (declaredPins && (!isDeepStrictEqual(declaredIds, adoptedIds) || changedPins.length > 0)) {
    differences.push({
      checkId: 'emergency.stage3ManifestRecomputed',
      what: `Stage 3 input manifest was rebuilt from the adopted witnesses: ${manifestKey}`,
      chain: { key: manifestKey, declaredGroupIds: declaredIds },
      rebuilt: { adoptedGroupIds: adoptedIds, changedGroupIds: changedPins },
      reason: 'order 4 verifies witness bytes against the manifest sha256, so the pins follow the adopted bytes',
    });
  }
  return {
    verified: verifiedKeys.length,
    keys: verifiedKeys,
    adopted: pins.length,
    adoptedKeys: [...adoptedKeys],
    pins,
    differences,
  };
}

function makeMemoryGm(
  sourceManifest, evidence, capture, d1Groups = [], stage3Pins = [], blockNum = null, pins = null,
) {
  const rules = sourceManifest.rules || {};
  // 🔴 R29-A-1b-01 / R29-D-2-04（2026-09-21）: 採点5値の env は**検証器の pin** が権威である。
  //    公開 manifest の rules から組むと、攻撃者が1値ずらすだけで vendored の
  //    assertGuestPinnedRules（game-master-DO.js:11679）が throw し、固定一式が0バイトになった。
  //    源を ctx.cfg.pins（通常モードの scoringThresholdsFromPins・stages/results.js:217 と同じ）へ
  //    揃えることで、採点値と再生成 manifest の宣言値が必ず一致する。
  //    pins を渡さない呼び出しは fail-closed で止める（公開 rules へは二度と落とさない）。
  if (!pins || !pins.chatCaps) {
    throw new Error('makeMemoryGm requires the verifier scoring pins (cfg.pins)');
  }
  const storageValues = new Map();
  // 平時 GM の publishStage3InputManifest（game-master-DO.js:11506-11562）が読む
  // score record と同じ形で、採用した witness の pin を置く。Stage 3 入力 manifest を
  // 写経せず**平時の書き手そのもの**に作らせるため。list はこの prefix だけを返し、
  // 他の prefix は従来どおり空＝緊急経路の既存の振る舞いを変えない。
  const listableValues = new Map();
  const pinBlockNum = blockNum ?? sourceManifest.blockNum;
  if (evidence !== undefined) {
    // 読む側は検証対象の真の N で読むため、書く側も真の N を優先する。
    // 公開 manifest の自称値を鍵にすると rules.evidence が無言で null になる。
    storageValues.set(`evidence_reconciled_block${pinBlockNum}`, evidence);
  }
  const storage = {
    get: async (key) => storageValues.get(key),
    put: async (key, value) => storageValues.set(key, value),
    delete: async (key) => storageValues.delete(key),
    list: async (options = {}) => {
      const prefix = String(options?.prefix ?? '');
      const out = new Map();
      for (const [key, value] of listableValues) if (key.startsWith(prefix)) out.set(key, value);
      return out;
    },
  };
  const env = {
    START_TIME: rules.startTime || '', BLOCK_TIME: String(rules.blockTime ?? ''),
    GAME_PERIOD: String(rules.periodDurations?.gamePeriod ?? ''),
    SUBMIT_PERIOD: String(rules.periodDurations?.submitPeriod ?? ''),
    // 🔴 採点5値だけは公開 rules ではなく検証器の pin から作る（上の R29-A-1b-01 / R29-D-2-04）。
    //    START_TIME / BLOCK_TIME / GAME_PERIOD / SUBMIT_PERIOD はここを通って再生成 manifest へ
    //    焼き込まれるので、rulesTiming の fail-closed を保つために公開 rules のままにする。
    GAME_MIN_CHARS: String(pins.minChars), GAME_MIN_MESSAGES: String(pins.minMessages),
    GAME_MAX_CHARS: String(pins.chatCaps.maxChars),
    GAME_MAX_MESSAGES: String(pins.chatCaps.maxMessages),
    GAME_MAX_MSG_CHARS: String(pins.chatCaps.maxMsgChars),
    R2_BUCKET: {
      get: async (key) => {
        const bytes = capture.get(key);
        return bytes ? {
          text: async () => bytes.toString('utf8'),
          etag: sha256(bytes),
        } : null;
      },
      put: async (key, value, options = {}) => {
        const bytes = Buffer.isBuffer(value) ? value : Buffer.from(String(value));
        const current = capture.get(key);
        const onlyIf = options.onlyIf || {};
        if (onlyIf.etagDoesNotMatch === '*' && current) return null;
        if (onlyIf.etagMatches && (!current || sha256(current) !== onlyIf.etagMatches)) return null;
        capture.set(key, bytes);
        return { etag: sha256(bytes) };
      },
    },
  };
  const gm = withVendorLogging(() => new GameMasterDO({ storage }, env));
  for (const pin of (stage3Pins || [])) {
    listableValues.set(gm.calcKey(pinBlockNum, 'score', pin.groupId), {
      groupId: pin.groupId, stage3: { object: pin.object, sha256: pin.sha256 },
    });
  }
  gm.putR2ObjectOrThrow = async (key, value) => { capture.set(key, bytesOfJson(value)); return true; };
  gm.putR2Object = async (key, value) => { capture.set(key, bytesOfJson(value)); return true; };
  gm.getR2Object = async (key) => {
    const bytes = capture.get(key);
    return bytes ? JSON.parse(bytes.toString('utf8')) : null;
  };
  gm.calcLoadGroups = async () => d1Groups;
  gm.sha256Hex = async (text) => sha256(Buffer.from(text));
  gm.registerResultHashOnChain = async () => ({ submitted: true, emergencyOffline: true });
  gm.finalizePublishedRootWithPipeline = async (_blockNum, detail) => ({
    ...detail.merkle,
    verification: detail.verification,
    submit: { submitted: true, emergencyOffline: true },
  });
  return gm;
}

async function immutableWrite(rootDir, relative, bytes) {
  const filename = under(rootDir, relative);
  await fs.mkdir(path.dirname(filename), { recursive: true });
  await fs.writeFile(filename, bytes, { flag: 'wx', mode: 0o440 });
}

async function fetchCurrentR2ManifestBytes(base, key) {
  const url = new URL(`${String(base).replace(/\/+$/, '')}/${key}`);
  url.searchParams.set('__observer', `preservation-${Date.now()}`);
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const response = await fetch(url, { method: 'GET', redirect: 'error', cache: 'no-store',
        headers: { 'cache-control': 'no-cache', pragma: 'no-cache' },
        signal: AbortSignal.timeout(60_000) });
      if (response.status === 404) return { bytes: null, url: url.toString(), sha256: null };
      if (!response.ok) {
        if ((response.status === 429 || (response.status >= 500 && response.status <= 599))
            && attempt < 3) {
          await new Promise(resolve => setTimeout(resolve, 500 * 2 ** (attempt - 1)));
          continue;
        }
        throw new Error(`HTTP ${response.status}`);
      }
      const limit = r2LimitForKey(key);
      const declared = Number(response.headers.get('content-length'));
      if (Number.isFinite(declared) && declared > limit) {
        await response.body?.cancel();
        throw new Error('current R2 response exceeds inspection limits');
      }
      const chunks = [];
      let size = 0;
      for await (const chunk of response.body || []) {
        size += chunk.length;
        if (size > limit) {
          await response.body?.cancel().catch(() => {});
          throw new Error('current R2 response exceeds inspection limits');
        }
        chunks.push(Buffer.from(chunk));
      }
      const bytes = Buffer.concat(chunks, size);
      return { bytes, url: url.toString(), sha256: sha256(bytes) };
    } catch (error) {
      if (attempt === 3 || /^HTTP \d+/.test(String(error?.message))) {
        const failure = new Error(`${key}: current R2 fetch failed at ${url}: ${String(error?.message || error)}`);
        failure.url = url.toString();
        throw failure;
      }
      await new Promise(resolve => setTimeout(resolve, 500 * 2 ** (attempt - 1)));
    }
  }
}

export async function inspectNextGroupingVersionPreservation({
  sourceDir, index, chain, blockNum, currentR2Dir = sourceDir,
  currentR2Bytes = undefined, currentR2Source = null, currentR2Fetch = null,
}) {
  const n = Number(blockNum);
  if (typeof chain?.otherRegistrationCount !== 'function') return null;
  const nextRosterKey = keccak256(stringToHex(`bitcoinu:roster:${n + 1}`));
  const nextRosterCount = await chain.otherRegistrationCount(nextRosterKey);
  if (nextRosterCount == null) {
    if (chain.isLegacyHashStorage?.() === true) {
      return { blockNum: n, groupingBlock: n + 1, unavailable: true,
        reason: 'legacy_hash_storage_has_no_history', mustPreserve: false, versions: [] };
    }
    throw new Error(`block ${n + 1}: N+1 roster history could not be read; retry before export`);
  }
  if (Number(nextRosterCount) === 0) return null;
  const roster = await resolveRosterRegistration(chain, n + 1);
  if (!roster?.row) return null; // N+1 grouping has not been committed.
  const time = await deriveGroupingUpperBound(chain, n + 1, undefined, roster.row.hash);
  const history = await findResultRegistrationAtGrouping(
    chain, n, time.upperMs, false, time.entryEndMs,
  );
  // This inspection is an emergency export hint. The live N+1 fixed key is
  // attacker-controlled during an incident, so it cannot narrow preservation.
  const nextGroupsKey = `entries/block${n + 1}/game_groups.json`;
  let nextGroupsBytes = null;
  let currentR2GroupingDifference = null;
  try {
    if (currentR2Fetch) {
      const fetched = await currentR2Fetch(nextGroupsKey);
      nextGroupsBytes = fetched && !Buffer.isBuffer(fetched) && 'bytes' in fetched
        ? fetched.bytes : fetched;
    } else {
      nextGroupsBytes = await fs.readFile(under(currentR2Dir, nextGroupsKey));
    }
  } catch (error) {
    if (error?.code !== 'ENOENT') currentR2GroupingDifference = {
      checkId: 'emergency.nextGroupingLiveRecord', key: nextGroupsKey,
      reason: 'live_grouping_read_failed', detail: String(error?.message || error),
    };
  }
  if (nextGroupsBytes) {
    try {
      const nextGroups = JSON.parse(Buffer.from(nextGroupsBytes).toString('utf8'));
      const row = nextGroups?.prevResultRegistration;
      if (row && row.status !== 'none') {
        const matching = history.rows.find((candidate) => String(candidate.index) === String(row.index));
        if (!matching || String(matching.hash).toLowerCase() !== String(row.hash).toLowerCase()
            || String(matching.registeredBlock) !== String(row.registeredBlock)
            || (matching.registeredAt != null && String(matching.registeredAt) !== String(row.registeredAt))) {
          currentR2GroupingDifference = {
            checkId: 'emergency.nextGroupingLiveRecord', key: nextGroupsKey,
            reason: 'recorded_previous_row_mismatch',
          };
        }
      }
    } catch (error) {
      currentR2GroupingDifference = {
        checkId: 'emergency.nextGroupingLiveRecord', key: nextGroupsKey,
        reason: 'invalid_live_grouping_json', detail: String(error?.message || error),
      };
    }
  }
  if (history.rows.length === 0) {
    return { blockNum: n, groupingBlock: n + 1, versions: [],
      mustPreserve: false, emptyWindow: true, currentR2GroupingDifference,
      reason: `block ${n} had no result registration at block ${n + 1} grouping` };
  }
  const manifestKey = `verification/block${n}/manifest.json`;
  const summaryKey = `games/block${n}/summary.json`;
  // The live R2 probe, when supplied, describes the current fixed key.
  // Otherwise a local fixed-key snapshot can describe the observer's last
  // observation. Neither is adopted as verification evidence.
  let currentR2Core = null;
  let currentR2Manifest = null;
  let currentR2SummarySha256 = null;
  let currentR2SummaryProbeFailed = false;
  let fixedBytes = currentR2Bytes;
  let currentR2ProbeError = null;
  const currentR2Responses = [];
  if (currentR2Fetch) {
    try {
      const fetched = await currentR2Fetch(manifestKey);
      fixedBytes = fetched && !Buffer.isBuffer(fetched) && 'bytes' in fetched
        ? fetched.bytes : fetched;
      if (fetched && !Buffer.isBuffer(fetched) && 'url' in fetched) {
        currentR2Responses.push({ key: manifestKey, url: fetched.url, sha256: fetched.sha256 });
      }
      currentR2Source = 'live public R2 fixed key';
    } catch (error) {
      if (error?.url) currentR2Responses.push({ key: manifestKey, url: error.url,
        sha256: null, error: String(error?.message || error) });
      currentR2ProbeError = String(error?.message || error);
      fixedBytes = null;
      currentR2Source = 'live public R2 unavailable';
    }
  }
  if (fixedBytes === undefined) {
    try {
      const currentPath = under(currentR2Dir, manifestKey);
      const stat = await fs.stat(currentPath);
      if (!stat.isFile() || stat.size > r2LimitForKey(manifestKey)) {
        throw new Error(`${manifestKey}: materialized fixed-key manifest exceeds inspection limits`);
      }
      fixedBytes = await fs.readFile(currentPath);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
  }
  if (fixedBytes) {
    try {
      if (fixedBytes.length > r2LimitForKey(manifestKey)) {
        throw new Error(`${manifestKey}: fixed-key manifest exceeds inspection limits`);
      }
      let value;
      try { value = JSON.parse(fixedBytes.toString('utf8')); } catch {
        throw new Error(`${manifestKey}: fixed-key manifest is not JSON`);
      }
      if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error(`${manifestKey}: fixed-key manifest is not an object`);
      }
      currentR2Core = manifestCoreHash(value);
      if (!jsonDepthWithinLimit(fixedBytes, GCP_JSON_DEPTH_LIMIT)
          && !history.rows.some((row) => hashEq(row.hash, currentR2Core))) {
        throw new Error(`${manifestKey}: fixed-key manifest exceeds inspection limits`);
      }
      currentR2Manifest = value;
    } catch (error) {
      if (currentR2Source !== 'live public R2 fixed key') throw error;
      currentR2ProbeError = String(error?.message || error);
      currentR2Source = 'live public R2 unreadable';
    }
  }
  // A fixed-key manifest does not prove that its declared summary still exists.
  // Inspect each key independently before requiring a new observer capture.
  {
    let summaryBytes = null;
    try {
      if (currentR2Fetch) {
        const fetched = await currentR2Fetch(summaryKey);
        summaryBytes = fetched && !Buffer.isBuffer(fetched) && 'bytes' in fetched
          ? fetched.bytes : fetched;
        if (fetched && !Buffer.isBuffer(fetched) && 'url' in fetched) {
          currentR2Responses.push({ key: summaryKey, url: fetched.url, sha256: fetched.sha256 });
        }
      }
      else {
        const summaryPath = under(currentR2Dir, summaryKey);
        const stat = await fs.stat(summaryPath);
        if (!stat.isFile() || stat.size > r2LimitForKey(summaryKey)) {
          throw new Error(`${summaryKey}: materialized fixed-key summary exceeds inspection limits`);
        }
        summaryBytes = await fs.readFile(summaryPath);
      }
      if (summaryBytes && summaryBytes.length <= r2LimitForKey(summaryKey)) {
        currentR2SummarySha256 = sha256(summaryBytes);
      }
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        if (error?.url) currentR2Responses.push({ key: summaryKey, url: error.url,
          sha256: null, error: String(error?.message || error) });
        currentR2ProbeError = String(error?.message || error);
        currentR2SummaryProbeFailed = true;
      }
    }
  }
  const laterRows = [];
  if (index?.lineageCheckBypassed === true && Array.isArray(index.laterSavedGenerations)) {
    for (const row of index.laterSavedGenerations) {
      if (![manifestKey, summaryKey].includes(row?.key)) continue;
      try {
        if (sha256(await readRowBytes(sourceDir, row)) === String(row.sha256).toLowerCase()) {
          laterRows.push(row);
        }
      } catch { /* An absent or changed copy cannot establish preservation. */ }
    }
  }
  const manifests = await selectReadableManifestCandidates(
    sourceDir, [...rowsFor(index, manifestKey), ...laterRows.filter(row => row.key === manifestKey)],
    null, { emergencyLimits: true,
      registeredHashes: new Set(history.rows.map((row) => String(row.hash).toLowerCase())) },
  );
  const byCore = new Map();
  for (const manifest of manifests) {
    const core = String(manifest.coreHash).toLowerCase();
    if (!byCore.has(core)) byCore.set(core, manifest);
  }
  const summaryRows = [...rowsFor(index, summaryKey),
    ...laterRows.filter(row => row.key === summaryKey)];
  const versions = [];
  const savedByCore = new Map();
  for (const registration of history.rows) {
    const core = String(registration.hash).toLowerCase();
    if (!savedByCore.has(core)) {
      const manifest = byCore.get(core) ?? null;
      const declared = manifest
        ? (await readSelectedManifest(sourceDir, manifest))?.files?.[summaryKey] : null;
      const summary = typeof declared === 'string'
        && summaryRows.some((row) => hashEq(row.sha256, declared))
        ? await selectRowByHash(sourceDir, summaryRows, declared,
          `${summaryKey} N+1 grouping version`) : null;
      savedByCore.set(core, {
        manifestGeneration: manifest?.row.generation ?? null,
        manifestSha256: manifest?.row.sha256 ?? null,
        summaryGeneration: summary?.generation ?? null,
        summarySha256: summary?.sha256 ?? null,
        declaredSummarySha256: typeof declared === 'string' ? declared : null,
        saved: Boolean(manifest && summary),
      });
    }
    const saved = savedByCore.get(core);
    const manifestInR2 = fixedBytes === undefined || (currentR2ProbeError && !currentR2Manifest)
      ? null : currentR2Core !== null && hashEq(registration.hash, currentR2Core);
    const declaredR2Summary = saved.declaredSummarySha256
      || (manifestInR2 === true ? currentR2Manifest?.files?.[summaryKey] : null);
    const summaryInR2 = currentR2SummaryProbeFailed
      ? null : currentR2SummarySha256 !== null && typeof declaredR2Summary === 'string'
        ? hashEq(declaredR2Summary, currentR2SummarySha256)
        : false;
    const missingInR2 = [
      ...(!saved.manifestSha256 && manifestInR2 === true ? ['manifest'] : []),
      ...(!saved.summarySha256 && summaryInR2 === true ? ['summary'] : []),
    ];
    versions.push({ index: registration.index, hash: registration.hash,
      ...saved, inR2: manifestInR2,
      manifestInR2, summaryInR2, missingInR2 });
  }
  const atRisk = versions.filter((row) => row.missingInR2.length > 0);
  for (const row of atRisk) {
    await verifyResultRegistrationRow(chain, n, history.rows.find((item) => item.index === row.index));
  }
  return {
    blockNum: n, groupingBlock: n + 1, currentR2Core,
    currentR2Source: currentR2Source || 'materialized fixed key from observer snapshot',
    currentR2ProbeError, currentR2GroupingDifference,
    versions, mustPreserve: atRisk.length > 0,
    ...(currentR2Responses.length > 0 ? { currentR2Responses } : {}),
  };
}

export async function writeEmergencyResultSet({ ctx, source, outputDir }) {
  const N = Number(ctx.blockNum);
  // 診断JSONだけを伏せる。正準writerの結果や保存した公開原文はbyte-exactのまま。
  const rpcUrls = configRpcUrls(ctx.cfg || {});
  const diagnosticBytes = (value) => Buffer.from(redactRpcText(bytesOfJson(value).toString('utf8'), rpcUrls));
  const out = path.resolve(outputDir);
  const existing = await fs.readdir(out).catch((error) => {
    if (error?.code === 'ENOENT') return [];
    throw error;
  });
  if (existing.length > 0) throw new Error(`emergency output directory must be empty: ${out}`);

  // Inspect all in-window versions before fixed-set bytes are written. Only
  // the version still at the fixed R2 key can be saved by another observation.
  const nextVersion = await inspectNextGroupingVersionPreservation({
    sourceDir: source.sourceDir, index: source.index, chain: ctx.chain, blockNum: N,
    currentR2Fetch: ctx.cfg?.emergencySource && ctx.cfg?.r2Base
      ? (key) => fetchCurrentR2ManifestBytes(ctx.cfg.r2Base, key) : null,
  });
  if (nextVersion) {
    if (nextVersion.currentR2GroupingDifference) {
      ctx.data.emergencyDifferences = [
        ...(ctx.data.emergencyDifferences || []), nextVersion.currentR2GroupingDifference,
      ];
    }
    if (nextVersion.currentR2ProbeError) {
      ctx.ui.println(`##NEXT_GROUPING_R2_PROBE_UNAVAILABLE ${JSON.stringify({
        blockNum: N, reason: nextVersion.currentR2ProbeError,
      })}`);
    }
    ctx.ui.println(`##NEXT_GROUPING_PREVIOUS_VERSION ${JSON.stringify(nextVersion)}`);
    ctx.report.fact('emergencyNextGroupingVersionPreservation', nextVersion);
    if (nextVersion.mustPreserve) {
      const rows = nextVersion.versions.filter((row) => row.missingInR2?.length > 0);
      throw new Error(`block ${N + 1}: the current R2 fixed keys still hold unsaved `
        + `in-window block ${N} version (${rows.map((row) =>
          `index=${row.index} hash=${row.hash} keys=${row.missingInR2.join('+')}`).join(', ')}). Stop before export or submission; `
        + 'run the observer manually to save the available keys, materialize a fresh archive, '
        + 'then retry.');
    }
  }

  const capture = new Map();
  const rebuild = ctx.data.emergencyRebuild;
  if (!rebuild && source.authority === 'gcp') {
    const failed = ctx.report.list().filter((entry) => entry.status === 'fail'
      && !ALLOWED_PUBLIC_RESULT_FAILURES.has(entry.id));
    if (failed.length) throw new Error(`emergency export refused because verification failed: ${failed
      .map((entry) => entry.id).join(', ')}`);
    assertEmergencyVerificationGate(ctx.report, rebuild);
    throw new Error('emergency export refused: Stage C did not reconstruct a result');
  }
  // timeline no-game の cause はチェーンから再計算できない。許可集合外なら、正準 writer が
  // throw して原因不明の0バイト出力になる前に、Stage C の専用 fail をそのまま表へ返す。
  if (rebuild?.kind === 'timelineNoGame' && rebuild.invalidNoGameCause === true) {
    assertEmergencyVerificationGate(ctx.report, rebuild);
  }
  // Stage A/B が必要とする応募・前ブロック等は result manifest の外にある。
  // 選択済み世代だけを固定一式へ含め、元の最新相対pathへはfallbackしない。
  const sourceManifestFiles = source.selectedManifest.files || {};
  const manifestKey = `verification/block${N}/manifest.json`;
  for (const [key, mapped] of source.fileMap) {
    if (key === manifestKey || Object.hasOwn(sourceManifestFiles, key) || mapped === null) continue;
    if (!capture.has(key)) capture.set(key, await fs.readFile(under(source.sourceDir, mapped)));
  }

  // 名簿の必要鍵は公開 result manifest ではなく、Stage C の再構成群集合と
  // チェーンの独立目印で選ばれた roster manifest から決める。保存世代が無い鍵だけ、
  // Stage C が正典行へ照合済みの再構成バイトを pin と突き合わせて固定一式へ入れる。
  const rosterSelection = await materializeEmergencyRosterPayloads({
    blockNum: N,
    rebuild,
    groupsDerived: ctx.data.groupsDerived,
    source,
    capture,
    acceptedRoster: ctx.data.emergencyRosterPayloads,
  });

  // 平時GMがmanifestへ載せるうち、再計算対象ではない固定入力だけを選択済み世代から置く。
  // group/summary/Merkle/auto-resultは必ず再計算側が生成したものを使う。
  const preservedPatterns = [
    new RegExp(`^entries/block${N}/game_(?:selection|groups)\\.json$`),
    ...(source.authority === 'gcp' ? [] : [
      new RegExp(`^verification/block${N}/evidence-report\\.json$`),
      new RegExp(`^games/block${N}/zkp/evidence-segments\\.json$`),
    ]),
    new RegExp(`^verification/block${N}/stage3/manifest\\.json$`),
    new RegExp(`^verification/block${N}/stage3/group-\\d+\\.json$`),
  ];
  for (const key of Object.keys(sourceManifestFiles)) {
    if (capture.has(key) || !preservedPatterns.some((pattern) => pattern.test(key))) continue;
    const mapped = source.fileMap.get(key);
    if (mapped) capture.set(key, await fs.readFile(under(source.sourceDir, mapped)));
  }
  // 再生成 manifest の確認深さは Stage B が照合した selection から導く。
  // 保存済み世代が無い GCP 経路でも、pin の固定値へ戻さない。
  const selectionKey = `entries/block${N}/game_selection.json`;
  if (!capture.has(selectionKey) && ctx.data.gameSelection) {
    capture.set(selectionKey, bytesOfJson(ctx.data.gameSelection));
  }
  // witness 本体は外側 result manifest の files には直接載らない。選択済みの
  // Stage 3 manifest が指した世代を**比較用に**読み込む（採用は下の再計算版）。
  for (const key of (source.witnessKeys || [])) {
    if (capture.has(key)) continue;
    const mapped = source.fileMap.get(key);
    if (mapped) capture.set(key, await fs.readFile(under(source.sourceDir, mapped)));
  }
  // 🔴 R28-H3-4-02: ここで capture の witness は**再計算版へ差し替わる**。
  //    公開版との差は differences へ回り、輸出は止まらない。
  const { differences: stage3WitnessDifferences, ...stage3WitnessVerification } = (
    verifyEmergencyStage3Witnesses({
      blockNum: N,
      rebuild,
      groupArchives: ctx.data.emergencyGroupArchives,
      capture,
    })
  );

  const gm = makeMemoryGm(
    source.selectedManifest, rebuild.evidence, capture, rebuild.d1Groups || [],
    stage3WitnessVerification.pins, N, ctx.cfg?.pins ?? null,
  );
  const writerCalls = [];
  if (source.authority === 'gcp' && ctx.data.emergencyEvidenceReport) {
    writerCalls.push('GameMasterDO.publishEvidenceReportIdempotent');
    await withVendorLogging(() => gm.publishEvidenceReportIdempotent(N, ctx.data.emergencyEvidenceReport));
  }
  const selectSavedEvidenceSegmentPin = async () => {
    const key = `games/block${N}/zkp/evidence-segments.json`;
    const evaluations = [];
    let saved = null;
    for await (const candidate of gcpCandidates(source.sourceDir, source.index, key, evaluations)) {
      saved = candidate;
      break;
    }
    if (saved) source.fileMap.set(key, saved.row.savedFile); // compare, never adopt, the saved bytes
    const savedVersion = saved?.data?.pinVersion;
    let usableSavedVersion = false;
    if (typeof savedVersion === 'string') {
      try { evidenceSegmentPrice(savedVersion); usableSavedVersion = true; }
      catch { /* An unknown saved version is a public difference, not an export blocker. */ }
    }
    return { key, saved, savedVersion, usableSavedVersion, evaluations };
  };
  const recordEvidenceSegmentPinFallback = ({ key, saved, savedVersion, usableSavedVersion, evaluations }) => {
    if (usableSavedVersion) return;
    ctx.report.fact?.('emergencyEvidenceSegmentPinFallback', {
      key, pinVersion: JSON.parse(capture.get(key).toString('utf8')).pinVersion,
      reason: saved ? 'saved artifact pinVersion is unusable; current price version used'
        : 'saved artifact generation unavailable; current price version used',
      ...(saved ? { savedPinVersion: savedVersion ?? null,
        savedSha256: saved.row.sha256 } : {}),
      evaluations,
    });
    if (saved) (source.differences ??= []).push({
      checkId: 'emergency.evidenceSegmentPinFallback',
      what: key,
      chain: { pinVersion: savedVersion ?? null, sha256: saved.row.sha256 },
      rebuilt: { pinVersion: CURRENT_EVIDENCE_SEGMENT_PIN_VERSION },
      reason: 'saved artifact pinVersion is unusable; the canonical artifact was reconstructed with the current price version',
    });
  };
  const pinSavedEmptyEvidenceSegment = async () => {
    if (source.authority !== 'gcp') return null;
    const selection = await selectSavedEvidenceSegmentPin();
    if (selection.usableSavedVersion) {
      await gm.storage.put(`auto:${N}:evidence_segment_pin`, selection.savedVersion);
    }
    return selection;
  };
  let merkle;
  let finalized;
  if (rebuild.kind === 'noGame' || rebuild.kind === 'timelineNoGame') {
    const evidenceSegmentPin = await pinSavedEmptyEvidenceSegment();
    // 0名とtimeline終端は、summary・claim status・空標識Merkle・manifestを一体で
    // 書く平時の正準入口そのものを呼ぶ。root txだけはメモリstubへ向ける。
    writerCalls.push('GameMasterDO.finalizeNoGameBlock');
    const result = await withVendorLogging(() => gm.finalizeNoGameBlock(N, {
      ...(rebuild.noGameMeta || {}),
      // 手元の固定一式を生成するだけなので、live D1 / ChatGameDO の後始末は対象外。
      // GM は厳密な true のときだけ cleanup を外し、本番経路はこの値を渡さない。
      offlineMaterialize: true,
    }));
    merkle = result?.merkle;
    finalized = result?.verification;
    if (evidenceSegmentPin) recordEvidenceSegmentPinFallback(evidenceSegmentPin);
  } else {
    capture.set(`games/block${N}/summary.json`, bytesOfJson(rebuild.rebuiltSummary));
    for (const [gid, archive] of (ctx.data.emergencyGroupArchives || new Map())) {
      capture.set(`games/block${N}/group${gid}.json`, bytesOfJson(archive));
    }
    if (rebuild.kind === 'autoDistribute') {
      if (Number(rebuild.rebuiltSummary?.schemaVersion || 1) >= 2 && !rebuild.autoResult) {
        throw new Error('canonical auto-distribution result page was not reconstructed');
      }
      const selectedPlayers = ctx.data.gameSelection?.players;
      if (!Array.isArray(selectedPlayers) || ![1, 2].includes(selectedPlayers.length)) {
        throw new Error('canonical auto-distribution group0 requires one or two selected rows');
      }
      writerCalls.push('GameMasterDO.publishAutoRosterFile');
      await withVendorLogging(() => gm.publishAutoRosterFile(N, selectedPlayers));
      if (rebuild.autoResult) {
        capture.set(`games/block${N}/auto-results.json`, bytesOfJson(rebuild.autoResult));
      }
      writerCalls.push(
        'GameMasterDO.publishInitialClaimOverlays',
        'GameMasterDO.publishInitialClaimStatus',
      );
      await withVendorLogging(() => gm.publishInitialClaimOverlays(N, rebuild.allGroupResults, rebuild.depositorResults || []));
      await withVendorLogging(() => gm.publishInitialClaimStatus(
        N,
        gm.buildInitialClaimStatus(rebuild.allGroupResults, rebuild.depositorResults || []),
      ));
      const evidenceSegmentPin = await pinSavedEmptyEvidenceSegment();
      writerCalls.push('GameMasterDO.publishEmptyEvidenceSegmentArtifact');
      await withVendorLogging(() => gm.publishEmptyEvidenceSegmentArtifact(N));
      if (evidenceSegmentPin) recordEvidenceSegmentPinFallback(evidenceSegmentPin);
    } else if (source.authority === 'gcp') {
      const evidenceSegmentPin = await selectSavedEvidenceSegmentPin();
      const frames = ctx.data.emergencyEvidenceSegmentFrames;
      if (!Array.isArray(frames) || frames.some(({ rawBytes }) => !Number.isSafeInteger(rawBytes))) {
        throw new Error('Stage C did not preserve all Evidence raw byte counts');
      }
      writerCalls.push('GameMasterDO.publishEvidenceSegmentArtifact');
      await withVendorLogging(() => gm.publishEvidenceSegmentArtifact(N, frames, {
        pinVersion: evidenceSegmentPin.usableSavedVersion
          ? evidenceSegmentPin.savedVersion : CURRENT_EVIDENCE_SEGMENT_PIN_VERSION,
      }));
      recordEvidenceSegmentPinFallback(evidenceSegmentPin);
    }

    writerCalls.push('GameMasterDO.publishMerkleTree');
    merkle = await withVendorLogging(() => gm.publishMerkleTree(N, rebuild.rebuiltSummary));
    if (!merkle?.ok) throw new Error(`canonical Merkle publication failed: ${merkle?.error || merkle?.reason}`);

    // filesの列挙・順序・必須判定・Stage 3 manifest再利用・rules生成は、写経せず
    // vendored平時GMの publishVerificationManifest() をそのままメモリ保存先へ向ける。
    const groupIds = rebuild.kind === 'autoDistribute' ? [] : (rebuild.rebuiltSummary?.groups || [])
      .map((group) => Number(group?.group_id)).sort((a, b) => a - b);
    if (groupIds.some((gid, index) => !Number.isSafeInteger(gid) || gid < 0
        || (index > 0 && groupIds[index - 1] === gid))) {
      throw new Error('recomputed summary has invalid or duplicate group ids');
    }
    writerCalls.push('GameMasterDO.publishVerificationManifest');
    finalized = await withVendorLogging(() => gm.publishVerificationManifest(N, groupIds));
  }
  if (!finalized?.ok) throw new Error(`canonical manifest finalization failed: ${finalized?.error}`);

  // R29-D-2b-04: 比較するオブジェクトではなく、固定一式へ実際に書く summary のバイト列を
  // 回路と同じ制限文法へ通す。JSON.stringify は 1.5 / 1e+21 も生成できるため、単なる
  // parse→stringify 往復では「JS は読むが Rust 回路は拒否する」固定一式を止められない。
  const summaryKey = `games/block${N}/summary.json`;
  const writtenSummaryBytes = capture.get(summaryKey);
  const writtenSummary = parseCanonicalJson(
    writtenSummaryBytes?.toString('utf8'),
    `${summaryKey} in the emergency fixed bundle`,
  );
  if (JSON.stringify(writtenSummary) !== JSON.stringify(rebuild.rebuiltSummary)) {
    throw new Error('canonical GM writer summary differs from the Stage C reconstruction');
  }
  const independentlyRecomputedRoot = ctx.report.get('check.stageC.merkleRoot')?.params?.recomputed
    || rebuild.factsMerkle?.root;
  if (!merkle?.ok || !independentlyRecomputedRoot || !hashEq(merkle.root, independentlyRecomputedRoot)) {
    throw new Error('canonical Merkle root does not match the Stage C recomputed-summary root');
  }
  const resultManifest = JSON.parse(capture.get(manifestKey).toString('utf8'));
  if (source.authority === 'gcp'
      && (ctx.data.emergencySource?.gcpHistoricalProofHash === true
        || ctx.data.emergencySource?.gcpUntraceableOldProof === true)
      && !hashEq(source.chainResultMarker?.hash, manifestCoreHash(resultManifest))) {
    throw new Error(`block ${N}: register the deterministic fixed result core `
      + `${manifestCoreHash(resultManifest)} in HashStorage, then rerun before replacing the proved root`);
  }
  const rebuiltRoster = resultManifestRosterShape(resultManifest.files || {}, N);
  const rosterDifference = rosterSelection.publicRoster
    && (!isDeepStrictEqual(rosterSelection.rosterManifestGroupIds, rosterSelection.adoptedGroupIds)
      || !isDeepStrictEqual(rosterSelection.publicRoster.keys, rebuiltRoster.keys))
    ? {
      checkId: 'emergency.rosterKeySetRecomputed',
      what: 'roster payload key declarations differ from the independently regenerated result manifest',
      chain: {
        rosterManifestKey: rosterSelection.rosterManifestKey,
        rosterManifestGroupIds: rosterSelection.rosterManifestGroupIds,
        resultManifestIndexDeclared: rosterSelection.publicRoster.indexDeclared,
        resultManifestGroupIds: rosterSelection.publicRoster.groupKeys,
        resultManifestRosterKeys: rosterSelection.publicRoster.keys,
      },
      rebuilt: {
        adoptedAuthority: 'rebuiltSummary.groups checked against ctx.data.groupsDerived',
        adoptedGroupIds: rosterSelection.adoptedGroupIds,
        requiredKeys: rosterSelection.requiredKeys,
        resultManifestRosterKeys: rebuiltRoster.keys,
      },
      reason: 'public roster keys are compared as raw ordered strings; the canonical regenerated manifest decides the adopted key list',
    }
    : null;
  const rosterOnlyManifestFileListDifference = isRosterOnlyManifestFileListDifference(
    sourceManifestFiles,
    resultManifest.files || {},
    N,
  );
  // check.stageC.manifestFileList は許容表へ移さない。固定一式をメモリ上で再生成し、
  // 差が名簿の必要鍵だけだと実証できたこの呼び出しに限って通す。
  assertEmergencyVerificationGate(ctx.report, rebuild, {
    acceptRosterOnlyManifestFileListDifference: rosterOnlyManifestFileListDifference,
  });

  const encoded = encodeClaimData(N, writtenSummary).bytes;
  const chunks = splitChunks(encoded, Number(resultManifest.rules.claimDataChunkBytes));
  const claimPlan = {
    schemaVersion: 1,
    format: resultManifest.rules.claimDataFormat,
    blockNum: N,
    chunkCount: chunks.length,
    chunksHex: chunks.map(hexOf),
    dataHash: chunkChainHash(chunks),
  };
  capture.set('_emergency/claim-data-plan.json', bytesOfJson(claimPlan));
  capture.set('_observer/generation-selection.json', bytesOfJson({
    schemaVersion: 1, blockNum: N, sourceRunId: source.index.sourceRunId,
    applicantRegistration: source.applicantRegistration ?? null,
    applicantRegistrationCount: source.applicantRegistrationCount ?? null,
    chainResultMarker: source.chainResultMarker ?? null,
    selected: source.selected,
  }));
  capture.set('_emergency/submission-selection.json', diagnosticBytes({
    schemaVersion: 1, blockNum: N,
    rule: 'evidence-min-seq-then-observer-first-valid',
    selected: Object.values(ctx.data.emergencyServerSubmissions || {}).map(({ raw, bundle, ...row }) => row),
    candidates: ctx.data.emergencySubmissionCandidates || [],
  }));
  capture.set('_emergency/writer-provenance.json', diagnosticBytes({
    schemaVersion: 1, blockNum: N, resultKind: rebuild.kind || 'groupGame',
    vendoredCanonicalCalls: writerCalls,
    stage3WitnessVerification,
  }));

  const publicDiffs = [];
  const diffs = [];
  for (const [key, bytes] of [...capture.entries()]) {
    if (!source.fileMap.has(key) || source.fileMap.get(key) === null) continue;
    const publicBytes = await fs.readFile(under(source.sourceDir, source.fileMap.get(key)));
    if (sha256(publicBytes) === sha256(bytes)) continue;
    const publicCopy = `_emergency/public/${key}`;
    capture.set(publicCopy, publicBytes);
    const comparison = classifyPublicArtifactDifference({
      key, manifestKey, recomputedBytes: bytes, publicBytes, publicCopy,
    });
    publicDiffs.push(comparison.difference);
    if (comparison.affectsResult) diffs.push(comparison.difference);
  }
  // 再計算後の正準files列から消えた旧結果分冊も、公開版の証跡としてのみ残す。
  for (const key of Object.keys(sourceManifestFiles)) {
    if (capture.has(key) || source.fileMap.get(key) == null) continue;
    const publicBytes = await fs.readFile(under(source.sourceDir, source.fileMap.get(key)));
    const publicCopy = `_emergency/public/${key}`;
    capture.set(publicCopy, publicBytes);
    const difference = {
      key, recomputedSha256: null, publicSha256: sha256(publicBytes), publicCopy,
    };
    publicDiffs.push(difference);
    diffs.push(difference);
  }
  const allowedCheckDiffs = ctx.report.list()
    .filter((entry) => entry.status === 'fail' && ALLOWED_PUBLIC_RESULT_FAILURES.has(entry.id))
    .map((entry) => ({ checkId: entry.id, status: entry.status, params: entry.params || {} }));
  capture.set('_emergency/public-differences.json', diagnosticBytes({
    schemaVersion: 1, blockNum: N, diffs: publicDiffs,
    ...(allowedCheckDiffs.length > 0 ? { checkDifferences: allowedCheckDiffs } : {}),
  }));

  // 🔴 便 X1 / Q-B（2026-09-21・ユーザー決定 (b')）: core 外の差を見出しへ出すための材料。
  //
  //   `classifyPublicArtifactDifference()` は result manifest について
  //   `affectsResult = !coreMatches` と判定する。core は {blockNum, algorithm, rules, files} で、
  //   `files` が全成果物の sha256 を持つので**中身の改竄は必ず core を動かす**。
  //   一方 **core の外だけ**を書き換えた場合（`createdAt` のほか、攻撃者が足した任意の欄）は
  //   `affectsResult: false` になり、終了コードは 0（`full`）のままになる。
  //   🔴 「どんな差でも4にする」は不可。再計算すれば `createdAt` は必ず変わるので、
  //      正常な復旧が毎回4になる（それを止めたのがユーザー決定 U-1）。
  //   ⇒ 判定（`affectsResult`）も終了コードの規則も**変えない**。
  //      記録に埋もれて対応者が気づかない、という一点だけを直す。
  //      `index.js` の `emitEmergencyNonResultDifferenceMarkers()` が、この配列を
  //      `##EMERGENCY_NONRESULT_DIFFERENCE` として見出しへ出す（終了コードには触れない）。
  const materialDifferences = new Set(diffs);
  const nonResultDifferences = publicDiffs.filter((difference) => !materialDifferences.has(difference));

  const emergencyDifferences = [
    ...(source.differences || []),
    ...(ctx.data.emergencyDifferences || []),
    ...(ctx.data.emergencySubmissionCandidates || [])
      .filter((candidate) => candidate?.counts)
      .map((candidate) => ({
        checkId: candidate.counts.unknownMember
          ? 'emergency.submissionSourceNonMemberEntries' : 'emergency.submissionInvalidEntries',
        what: 'archived submission entries were rejected before adoption',
        chain: { sourceKeySha256: sha256(Buffer.from(candidate.key)),
          generation: candidate.generation, sha256: candidate.sha256,
          bytes: candidate.bytes, valueType: 'object', counts: candidate.counts },
        rebuilt: { adoptedFromThisSummary: 0 },
        reason: 'only member uid hints with distinct validated raw can be adopted',
      })),
    ...(rosterDifference ? [rosterDifference] : []),
    // R28-H3-4-02: 公開 witness / Stage 3 manifest を採用せず再計算版へ差し替えた記録。
    ...stage3WitnessDifferences,
  ];
  for (const entry of allowedCheckDiffs) {
    emergencyDifferences.push({
      checkId: entry.checkId,
      what: 'public or existing result differs from the independently recomputed emergency result',
      chain: {
        resultManifestHash: source.chainResultMarker?.hash ?? null,
        existingMerkleRoot: ctx.data.emergencyChainRoot ?? null,
      },
      rebuilt: entry.params,
      reason: 'this check is in the fixed emergency public-result difference allowlist',
    });
  }
  for (const difference of diffs) {
    emergencyDifferences.push({
      checkId: 'emergency.publicArtifactBytes',
      what: `public artifact bytes differ: ${difference.key}`,
      chain: {
        resultManifestHash: source.chainResultMarker?.hash ?? null,
        declaredSha256: source.selectedManifest?.files?.[difference.key] ?? null,
        publicSha256: difference.publicSha256,
      },
      rebuilt: {
        sha256: difference.recomputedSha256,
        publicCopy: difference.publicCopy,
      },
      reason: 'the original public bytes are retained as incident evidence while canonical writers produce the replacement',
    });
  }
  const seenDifferences = new Set();
  const uniqueDifferences = emergencyDifferences.filter((difference) => {
    const fingerprint = JSON.stringify(difference);
    if (seenDifferences.has(fingerprint)) return false;
    seenDifferences.add(fingerprint);
    return true;
  });
  // 外へ返す診断だけを文字列にして伏せる。変更が無ければ参照・値の形もそのまま返す。
  const differencesJson = JSON.stringify(uniqueDifferences);
  const safeDifferencesJson = redactRpcText(differencesJson, rpcUrls);
  capture.set('_emergency/differences.json', diagnosticBytes({
    schemaVersion: 1,
    blockNum: N,
    differenceCount: uniqueDifferences.length,
    differences: uniqueDifferences,
  }));

  const inventory = [...capture.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([key, bytes]) => ({
    key, sha256: sha256(bytes), bytes: bytes.length,
  }));
  const core = {
    schemaVersion: 1,
    kind: 'bitcoinu-emergency-result-set',
    blockNum: N,
    sourceRunId: source.index.sourceRunId,
    resultManifestCoreSha256: manifestCoreHash(resultManifest),
    merkleRoot: merkle.root,
    claimData: { chunkCount: claimPlan.chunkCount, dataHash: claimPlan.dataHash },
    resultKind: rebuild.kind || 'groupGame',
    applicantRegistration: source.applicantRegistration ?? null,
    differenceCount: uniqueDifferences.length,
    differencesKey: '_emergency/differences.json',
    vendoredCanonicalCalls: writerCalls,
    files: inventory,
  };
  const bundleIndex = { ...core, coreSha256: sha256(bytesOfJson(core)), createdAt: new Date().toISOString(), complete: true };

  for (const [key, bytes] of capture) await immutableWrite(out, key, bytes);
  await immutableWrite(out, '_emergency/bundle-index.json', bytesOfJson(bundleIndex));
  return {
    outputDir: out,
    bundleIndex,
    resultManifest,
    claimPlan,
    diffs,
    differences: safeDifferencesJson === differencesJson ? uniqueDifferences : JSON.parse(safeDifferencesJson),
    // 便 X1 / Q-B: 結果に影響しない差（公開差分にはあるが `diffs` には無いもの）。
    // 🔴 `differences` とは別の配列にしておく。`categorizeEmergencyWrite()` も
    //    `##EMERGENCY_RESULT` も `differences` だけを見るので、終了コードは動かない。
    nonResultDifferences,
  };
}

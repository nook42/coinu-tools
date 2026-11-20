// Q24: observer generations -> emergency adoption -> fixed local reader/export gates.
import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { concat, concatHex, keccak256, stringToHex, toHex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  DEFAULTS, emergencyApplicantSelectionUsageError, loadConfig,
} from '../src/config.js';
import { hashLikeBackend } from '../src/json-utils.js';
import { createLocalR2 } from '../src/r2.js';
import { GameMasterDO } from '../vendor/workers/game_workers/game-master-DO.js';
import { buildRosterMemberCommitment } from '../vendor/workers/game_workers/lib/roster-member-root.js';
import { selectWinners } from '../vendor/workers/lottery_workers/select-winners.js';
import { computeDeclaredTimesMs } from '../vendor/workers/game_workers/lib/timeline-check.js';
import {
  calculateGroupResults, getBlockRewardWei,
} from '../vendor/workers/game_workers/lib/game-result-calculator.js';
import { buildGroupWitness } from '../vendor/workers/game_workers/lib/group-witness.js';
import {
  compactBytesToPayload, compactPayloadToBytes, encodeEvidenceCompactV1,
} from '../vendor/workers/game_workers/lib/evidence-compact-v1.js';
import { computeChatHashV2 } from '../vendor/workers/game_workers/lib/protocol-v2.js';
import {
  makePlayer, makeChatWsData, makeActionWsData, makeActionReceipt, makeReadReceipt,
  buildSubmissionPayload,
} from './players.mjs';
import { CHECK_INVENTORY } from '../src/check-inventory.js';
import { createChain } from '../src/chain.js';
import { selectAdoptedResults } from '../vendor/workers/game_workers/lib/evidence-reconciler.js';
import { evidenceSegmentArtifact } from '../vendor/workers/game_workers/lib/evidence-segment-plan.js';

const MUTATION_ARG = process.argv.find((arg) => (
  arg.startsWith('--t2-mutation=') || arg.startsWith('--r3-mutation=')
    || arg.startsWith('--u4-mutation=') || arg.startsWith('--v8-mutation=')
    || arg.startsWith('--w1-mutation=') || arg.startsWith('--p8b-mutation=')
    || arg.startsWith('--m11a-mutation=')
));
const MUTATION = MUTATION_ARG?.split('=')[1] || null;
const verifierRoot = path.resolve(import.meta.dirname, '..');
let mutationRoot = null;
let mutationTmpRoot = null;
let resultsModulePath = process.env.T1E_RESULTS_MODULE
  ? path.resolve(process.env.T1E_RESULTS_MODULE)
  : path.resolve(import.meta.dirname, '../src/stages/results.js');
let emergencyModulePath = process.env.T1C_EMERGENCY_MODULE
  ? path.resolve(process.env.T1C_EMERGENCY_MODULE)
  : path.resolve(import.meta.dirname, '../src/emergency.js');

if (MUTATION) {
  if (![
    'ignore-applicant-marker', 'reject-applicant-match',
    'u4-drop-prev-anchor', 'u4-authless-manifest', 'u4-byte-fingerprint',
    'u4-disable-intermediate', 'u4-drop-groupmeta-allow',
    'p6-current-prev-version',
    'v8-core-only-material', 'v8-zero-adopted-count',
    'w1-witness-strict-throw', 'w1-keep-public-witness', 'w1-drop-manifest-pins',
    'p8b-main-worker-budget', 'p8b-main-discard-match', 'p8b-no-override-shortcut',
    'p8b-fallback-shared-budget', 'p8b-fallback-overflow-unmarked',
    'p8b-roster-always', 'p8b-skipped-diff-drop', 'p8b-impossible-diff-drop',
    'p8b-disable-worker-cache', 'p8b-allow-duplicate-filenames', 'p8b-drop-hash-budget',
    'p8b-normal-no-game-layout', 'p8b-no-game-mismatch-one-sided',
    'm11a-major-length', 'm11a-major-regex', 'm11a-stage3-size', 'm11a-root-diagnostic',
    'm11a-manifest-integrity', 'm11a-zero-summary',
    'm11a-summary-integrity',
    'm11a-previous-limit-flag',
    'm11a-drop-count-diff', 'm11a-entry-declared-bytes', 'm11a-entry-stat',
    'm11a-no-option-cap', 'm11a-drop-wanted-exemption',
    'm11a-merkle-leaf-limit',
    'm11a-prev-summary-declared',
    'm11a-selected-byte-limit',
    'm11a-null-chat-evidence',
    'm11a-history-limit-flag', 'm11a-gcp-limit-flag',
    'm11a-current-marker-diff', 'm11a-history-diff', 'm11a-gcp-diff',
    'm11a-summary-report-sha', 'm11a-json-invalid-reason',
    'm11a-manifest-structure-reject',
    'm11a-worker-fingerprint', 'm11a-total-fingerprint',
  ].includes(MUTATION)) {
    throw new Error(`unknown emergency mutation: ${MUTATION}`);
  }
  mutationTmpRoot = path.resolve(verifierRoot, `../tmp/M11a/q24-${MUTATION}-${process.pid}`);
  mutationRoot = path.join(mutationTmpRoot, 'block-verifier');
  await fs.rm(mutationTmpRoot, { recursive: true, force: true });
  await fs.mkdir(path.join(mutationRoot, 'src/stages'), { recursive: true });
  // emergency.js の ../../Hardhat/... を、複製木でも repo と同じ相対位置に保つ。
  await fs.symlink(path.resolve(verifierRoot, '../Hardhat'), path.join(mutationTmpRoot, 'Hardhat'));
  await fs.writeFile(path.join(mutationRoot, 'package.json'), '{"type":"module"}\n');
  for (const entry of await fs.readdir(path.join(verifierRoot, 'src'), { withFileTypes: true })) {
    if (entry.name === 'emergency.js' || entry.name === 'stages') continue;
    await fs.symlink(path.join(verifierRoot, 'src', entry.name), path.join(mutationRoot, 'src', entry.name));
  }
  for (const entry of await fs.readdir(path.join(verifierRoot, 'src/stages'), { withFileTypes: true })) {
    if (entry.name === 'results.js') continue;
    await fs.symlink(
      path.join(verifierRoot, 'src/stages', entry.name),
      path.join(mutationRoot, 'src/stages', entry.name),
    );
  }
  await fs.symlink(path.join(verifierRoot, 'vendor'), path.join(mutationRoot, 'vendor'));

  const originalEmergency = await fs.readFile(path.join(verifierRoot, 'src/emergency.js'), 'utf8');
  const originalResults = await fs.readFile(path.join(verifierRoot, 'src/stages/results.js'), 'utf8');
  let mutatedEmergency = originalEmergency;
  let mutatedResults = originalResults;
  if (MUTATION === 'ignore-applicant-marker' || MUTATION === 'reject-applicant-match') {
    mutatedEmergency = mutatedEmergency.replace(
      'const matchingRegistrations = eligibleRegistrations.filter((registration) => registration.hash === root);',
      MUTATION === 'ignore-applicant-marker'
        ? 'const matchingRegistrations = eligibleRegistrations;'
        : 'const matchingRegistrations = [];',
    );
  } else if (MUTATION === 'u4-drop-prev-anchor') {
    mutatedEmergency = mutatedEmergency.replace(
      'const previous = await selectPreviousBlockInputs({\n'
        + '    sourceDir, index, chain, blockNum, currentManifest: selectedManifestValue, differences,\n'
        + '  });',
      'const previous = null;',
    );
  } else if (MUTATION === 'u4-authless-manifest') {
    mutatedEmergency = mutatedEmergency
      .replace('if (matchingManifests.length === 0) {', 'if (false && matchingManifests.length === 0) {')
      .replace(
        'const selectedManifest = matchingManifests[0];',
        'const selectedManifest = matchingManifests[0] || manifestCandidates[0];',
      );
  } else if (MUTATION === 'u4-byte-fingerprint') {
    mutatedEmergency = mutatedEmergency.replace(
      'if (byteVariantCount > collapsed.length) {',
      "if (byteVariantCount > collapsed.length) { throw new Error('mutant byte ambiguity');",
    );
  } else if (MUTATION === 'u4-disable-intermediate') {
    mutatedEmergency = mutatedEmergency.replace(
      'for (const [root, saved] of intermediateByRoot) {\n'
        + '    const matchingRegistrations = eligibleRegistrations.filter((registration) => registration.hash === root);',
      'for (const [root, saved] of []) {\n'
        + '    const matchingRegistrations = eligibleRegistrations.filter((registration) => registration.hash === root);',
    );
  } else if (MUTATION === 'p6-current-prev-version') {
    // R30-U-4 より前の「前ブロックの現在目印だけを採用する」選択へ戻す変異。
    mutatedEmergency = mutatedEmergency.replace(
      'const reproducing = evaluated.filter((candidate) => candidate.reproducesGroups === true);',
      'const reproducing = evaluated.filter((candidate) => candidate.reproducesGroups === true '
        + '&& candidate.registration?.index === versionSet.currentLocation?.currentIndex);',
    );
  } else if (MUTATION === 'w1-witness-strict-throw') {
    // R28-H3-4-02 の修正前の振る舞い（公開版と合わなければ輸出ごと落とす）へ戻す。
    mutatedEmergency = mutatedEmergency.replace(
      "    if (classified.kind === 'identical') verifiedKeys.push(key);\n    else {",
      "    if (classified.kind === 'identical') verifiedKeys.push(key);\n"
        + "    else if (classified.kind !== 'identical') {\n"
        + "      throw new Error(`emergency Stage 3 witness differs from recomputed scoring input: group ${groupId}`);\n"
        + '    } else {',
    );
  } else if (MUTATION === 'w1-keep-public-witness') {
    // 記録だけして採用は公開バイト列のまま、という「直っていない」実装。
    mutatedEmergency = mutatedEmergency.replace(
      '    capture.set(key, bytes);\n    adoptedKeys.add(key);',
      '    capture.set(key, publicBytes || bytes);\n    adoptedKeys.add(key);',
    );
  } else if (MUTATION === 'w1-drop-manifest-pins') {
    // Stage 3 入力 manifest を作り直さない（公開版の宣言sha256が残る）実装。
    mutatedEmergency = mutatedEmergency.replace(
      '    pins.push({ groupId, object: key, sha256: adoptedSha256 });',
      '    if (false) pins.push({ groupId, object: key, sha256: adoptedSha256 });',
    );
  } else if (MUTATION === 'u4-drop-groupmeta-allow') {
    mutatedEmergency = mutatedEmergency.replace(
      "  'check.stageC.groupMeta',",
      "  'check.stageC.groupMeta.mutated',",
    );
  } else if (MUTATION === 'v8-core-only-material') {
    mutatedEmergency = mutatedEmergency.replace(
      '    publicDiffs.push(comparison.difference);\n'
        + '    if (comparison.affectsResult) diffs.push(comparison.difference);',
      '    publicDiffs.push(comparison.difference);\n'
        + '    diffs.push(comparison.difference);',
    );
  } else if (MUTATION === 'v8-zero-adopted-count') {
    mutatedResults = mutatedResults.replace(
      '  return resultCount === 0 ? null : Object.keys(adoptedByUid || {}).length;',
      '  return Object.keys(adoptedByUid || {}).length;',
    );
  } else if (MUTATION === 'p8b-main-worker-budget') {
    mutatedEmergency = mutatedEmergency.replace(
      '      let optionLimitRecorded = false;\n      for await (const infoCandidate of loadInfoChoices(worker)) {\n        let infoCombinationVisits = 0;',
      '      let optionLimitRecorded = false;\n      let infoCombinationVisits = 0;\n      for await (const infoCandidate of loadInfoChoices(worker)) {',
    );
  } else if (MUTATION === 'p8b-main-discard-match') {
    mutatedEmergency = mutatedEmergency.replace(
      '    return { match: first, budgetExceeded: evaluated.budgetExceeded };',
      '    return { match: evaluated.budgetExceeded.length > 0 ? null : first, budgetExceeded: evaluated.budgetExceeded };',
    );
  } else if (MUTATION === 'p8b-no-override-shortcut') {
    mutatedEmergency = mutatedEmergency.replace(
      '  const fallbackTargets = overrideAlreadyReproduced\n'
        + '    ? []\n'
        + '    : (requestedRegistrations.length > 0 ? requestedRegistrations : eligibleRegistrations)\n'
        + '      .filter((registration) => (\n'
        + '        !reproducibleByIndex.has(registration.index)\n'
        + '        && !intermediateByRoot.has(registration.hash)\n'
        + '      ));',
      '  const fallbackTargets = eligibleRegistrations.filter((registration) => (\n'
        + '    !reproducibleByIndex.has(registration.index)\n'
        + '    && !intermediateByRoot.has(registration.hash)\n'
        + '  ));',
    );
  } else if (MUTATION === 'p8b-fallback-shared-budget') {
    mutatedEmergency = mutatedEmergency.replace(
      '    for (const registration of fallbackTargets) {\n      let fallbackCombinationVisits = 0;',
      '    let fallbackCombinationVisits = 0;\n    for (const registration of fallbackTargets) {',
    );
  } else if (MUTATION === 'p8b-fallback-overflow-unmarked') {
    mutatedEmergency = mutatedEmergency.replace(
      '      if (registrationBudgetExceeded || fallbackInfoBudgetExceeded.length > 0) {',
      '      if (registrationBudgetExceeded) {',
    );
  } else if (MUTATION === 'p8b-roster-always') {
    mutatedEmergency = mutatedEmergency.replace(
      '!isDeepStrictEqual(rosterSelection.rosterManifestGroupIds, rosterSelection.adoptedGroupIds)',
      'true || !isDeepStrictEqual(rosterSelection.rosterManifestGroupIds, rosterSelection.adoptedGroupIds)',
    );
  } else if (MUTATION === 'p8b-skipped-diff-drop') {
    mutatedEmergency = mutatedEmergency.replace(
      '  if (overrideAlreadyReproduced) {',
      '  if (false && overrideAlreadyReproduced) {',
    );
  } else if (MUTATION === 'p8b-impossible-diff-drop') {
    mutatedEmergency = mutatedEmergency.replace(
      '  for (const registration of eligibleRegistrations) {\n'
        + '    const impossible = evaluationImpossibleByIndex.get(registration.index);\n'
        + '    if (!impossible) continue;',
      '  for (const registration of []) {\n'
        + '    const impossible = evaluationImpossibleByIndex.get(registration.index);\n'
        + '    if (!impossible) continue;',
    );
  } else if (MUTATION === 'p8b-disable-worker-cache') {
    mutatedEmergency = mutatedEmergency.replace(
      '    if (workerEvaluationCache.has(worker)) return workerEvaluationCache.get(worker);',
      '    if (false && workerEvaluationCache.has(worker)) return workerEvaluationCache.get(worker);',
    );
  } else if (MUTATION === 'p8b-allow-duplicate-filenames') {
    mutatedEmergency = mutatedEmergency.replace(
      '            || filenames.has(entry.filename)) {',
      '            ) {',
    );
  } else if (MUTATION === 'p8b-drop-hash-budget') {
    mutatedEmergency = mutatedEmergency.replace(
      '            consumeInfoBudget();\n            entryHashBudgeted.add(candidate);',
      '            entryHashBudgeted.add(candidate);',
    );
  } else if (MUTATION === 'p8b-normal-no-game-layout') {
    mutatedResults = mutatedResults.replace(
      '    && (!emergencyMode || published?.claimLayout === rebuilt.claimLayout)',
      '    && published?.claimLayout === rebuilt.claimLayout',
    );
  } else if (MUTATION === 'p8b-no-game-mismatch-one-sided') {
    mutatedResults = mutatedResults.replace(
      '        && noGameKind && !okTl;',
      '        && S.timelineNoGame && !okTl;',
    );
  } else if (MUTATION === 'm11a-major-length') {
    mutatedEmergency = mutatedEmergency.replace('&& lang.length <= 32', '&& true');
  } else if (MUTATION === 'm11a-major-regex') {
    mutatedEmergency = mutatedEmergency.replace('&& /^[A-Za-z0-9-]+$/.test(lang)', '&& true');
  } else if (MUTATION === 'm11a-stage3-size') {
    mutatedEmergency = mutatedEmergency.replace(
      "if (bytes.length > ZKP_INPUT_LIMITS.stage3ManifestBytes) throw new Error('size');",
      "if (false) throw new Error('size');",
    );
  } else if (MUTATION === 'm11a-root-diagnostic') {
    mutatedEmergency = mutatedEmergency.replace(
      'if (requestedReproduced && candidate.root !== requestedRoot) continue;',
      'if (requestedRoot !== null && requestedRoot !== undefined && candidate.root !== requestedRoot) continue;',
    );
  } else if (MUTATION === 'm11a-manifest-integrity') {
    mutatedEmergency = mutatedEmergency.replace(
      'if (archiveIntegrityFailure(error)) throw archiveIntegrityError();',
      'if (false && archiveIntegrityFailure(error)) throw archiveIntegrityError();',
    );
  } else if (MUTATION === 'm11a-summary-integrity') {
    mutatedEmergency = mutatedEmergency.replace(
      'if (emergencyLimits && archiveIntegrityFailure(error)) throw archiveIntegrityError();',
      'if (false && archiveIntegrityFailure(error)) throw archiveIntegrityError();',
    );
  } else if (MUTATION === 'm11a-zero-summary') {
    mutatedEmergency = mutatedEmergency.replace(
      'if (selectedCount === 0) {\n          if (zeroEntryNoGameSummaryShapeMatches({',
      'if (false) {\n          if (zeroEntryNoGameSummaryShapeMatches({',
    );
  } else if (MUTATION === 'm11a-previous-limit-flag') {
    mutatedEmergency = mutatedEmergency.replace(
      '{ emergencyLimits: true, evaluations: manifestEvaluations })',
      '{ emergencyLimits: false, evaluations: manifestEvaluations })',
    );
  } else if (MUTATION === 'm11a-drop-count-diff') {
    mutatedEmergency = mutatedEmergency.replace(
      '.filter((candidate) => candidate?.counts)', '.filter(() => false)',
    );
  } else if (MUTATION === 'm11a-entry-declared-bytes') {
    mutatedEmergency = mutatedEmergency.replace(
      '|| declaredBytes > GCP_GENERATION_BYTE_LIMIT) {',
      ') {',
    );
  } else if (MUTATION === 'm11a-entry-stat') {
    mutatedEmergency = mutatedEmergency.replace(
      'if (stat.size > GCP_GENERATION_BYTE_LIMIT) {',
      'if (false && stat.size > GCP_GENERATION_BYTE_LIMIT) {',
    );
  } else if (MUTATION === 'm11a-no-option-cap') {
    mutatedEmergency = mutatedEmergency.replace(
      'if (options.length >= workerOptionLimit',
      'if (false && options.length >= workerOptionLimit',
    );
  } else if (MUTATION === 'm11a-drop-wanted-exemption') {
    mutatedEmergency = mutatedEmergency.replace(
      '&& !wantedWorkerHashes[worker].has(hash)) {',
      '&& true) {',
    );
  } else if (MUTATION === 'm11a-merkle-leaf-limit') {
    mutatedEmergency = mutatedEmergency.replace(
      "if (Number(candidate.data.leafCount) > 2 ** 19) throw new Error('artifact count');",
      "if (false) throw new Error('artifact count');",
    );
  } else if (MUTATION === 'm11a-prev-summary-declared') {
    mutatedEmergency = mutatedEmergency.replace(
      "const declaredBytes = Number(summaryRow.bytes);\n      if (emergencyLimits && (!Number.isSafeInteger(declaredBytes) || declaredBytes < 0\n          || declaredBytes > GCP_GENERATION_BYTE_LIMIT)) throw new Error('individual row byte limit');",
      "const declaredBytes = Number(summaryRow.bytes);\n      if (emergencyLimits && (!Number.isSafeInteger(declaredBytes) || declaredBytes < 0)) throw new Error('individual row byte limit');",
    );
  } else if (MUTATION === 'm11a-selected-byte-limit') {
    mutatedEmergency = mutatedEmergency.replace(
      'if (selectedBytes > selectedByteLimit) {',
      'if (false && selectedBytes > selectedByteLimit) {',
    );
  } else if (MUTATION === 'm11a-null-chat-evidence') {
    mutatedEmergency = mutatedEmergency.replace(
      'rebuilt: { selectedValue: null, useAsChatStartEvidence: false },',
      'rebuilt: { selectedValue: null, useAsChatStartEvidence: true },',
    );
  } else if (MUTATION === 'm11a-history-limit-flag') {
    mutatedEmergency = mutatedEmergency.replace(
      'sourceDir, index, chain, blockNum, includeOutsideWindow: true, emergencyLimits: true,',
      'sourceDir, index, chain, blockNum, includeOutsideWindow: true, emergencyLimits: false,',
    );
  } else if (MUTATION === 'm11a-gcp-limit-flag') {
    mutatedEmergency = mutatedEmergency.replace(
      'groupingRosterHash: rosterAnchor?.hash ?? false, emergencyLimits: true,',
      'groupingRosterHash: rosterAnchor?.hash ?? false, emergencyLimits: false,',
    );
  } else if (MUTATION === 'm11a-current-marker-diff') {
    mutatedEmergency = mutatedEmergency.replace(
      'if (manifestEvaluations.length > 0) differences.push({',
      'if (false && manifestEvaluations.length > 0) differences.push({',
    );
  } else if (MUTATION === 'm11a-history-diff') {
    mutatedEmergency = mutatedEmergency.replace(
      'if (versionSet.manifestEvaluations.length > 0) differences.push({',
      'if (false && versionSet.manifestEvaluations.length > 0) differences.push({',
    );
  } else if (MUTATION === 'm11a-gcp-diff') {
    mutatedEmergency = mutatedEmergency.replace(
      'if (previousVersions?.manifestEvaluations.length > 0) differences.push({',
      'if (false && previousVersions?.manifestEvaluations.length > 0) differences.push({',
    );
  } else if (MUTATION === 'm11a-summary-report-sha') {
    mutatedEmergency = mutatedEmergency.replace(
      'summarySha256: candidate.summaryRow?.sha256 ?? null,',
      'summarySha256: null,',
    );
  } else if (MUTATION === 'm11a-json-invalid-reason') {
    mutatedEmergency = mutatedEmergency.replace(
      "reject('invalid JSON', bytes.length);",
      "reject('unreadable generation', bytes.length);",
    );
  } else if (MUTATION === 'm11a-manifest-structure-reject') {
    mutatedEmergency = mutatedEmergency.replace(
      "if (emergencyLimits) throw new Error('unusable saved manifest structure');",
      'if (false) throw new Error(\'unusable saved manifest structure\');',
    );
  } else if (MUTATION === 'm11a-worker-fingerprint') {
    mutatedEmergency = mutatedEmergency.replace(
      'fingerprint: sha256(Buffer.from(JSON.stringify(identifiers))),',
      'fingerprint: JSON.stringify(identifiers),',
    );
  } else if (MUTATION === 'm11a-total-fingerprint') {
    mutatedEmergency = mutatedEmergency.replace(
      'fingerprint: sha256(Buffer.from(JSON.stringify(workerFingerprints))),',
      'fingerprint: JSON.stringify(workerFingerprints),',
    );
  }
  if (mutatedEmergency === originalEmergency && mutatedResults === originalResults) {
    throw new Error(`${MUTATION} mutation was not applied`);
  }
  await fs.writeFile(path.join(mutationRoot, 'src/emergency.js'), mutatedEmergency);
  await fs.writeFile(path.join(mutationRoot, 'src/stages/results.js'), mutatedResults);
  emergencyModulePath = path.join(mutationRoot, 'src/emergency.js');
  resultsModulePath = path.join(mutationRoot, 'src/stages/results.js');
}

const {
  checkManifest,
  classifyResultManifestAnchorForMode, classifyRosterAnchorForMode,
  EMERGENCY_RESULT_ANCHOR_DIFFERENCE_REASONS, EMERGENCY_ROSTER_ANCHOR_DIFFERENCE_REASONS,
  applyEmergencyGroupAuthority, checkTimelineNoGameEvidenceEmpty,
  buildMajorLangsMatchCheck,
  buildZeroEntryNoGameSummary,
  zeroEntryNoGameSummaryShapeMatches,
  recordMajorLangsMatchForMode,
  classifyManifestSelfConsistency,
  compareManifestRulesTimingMs,
  declaredAdoptedCountForVerification, emergencyAdoptedCountOf,
  canContinueEmergencyAfterDownloadIssues,
  classifyMissingGroupEvidence,
  inspectResultManifestAnchor, inspectRosterAnchor, mergeEmergencyServerSubmissions,
  submissionContradictsGrouping,
  recordGcpGroupingContradictions,
  routeMissingRootInStageC, run: runResults, scoringThresholdsFromPins,
  verifyMerkle, verifyTimeline, reconstructedRosterIndexSha256,
  reconstructCanonicalRosterPayloads,
  reconstructedRosterGroupSha256,
  recordEmergencyZkpMerkleMetadataDifference,
  MANIFEST_CORE_RETRY_INSTRUCTION,
  findGcpProofRegistration,
} = await import(`${pathToFileURL(resultsModulePath).href}?q24_results=${Date.now()}`);

const indexModulePath = process.env.T1C_INDEX_MODULE
  ? path.resolve(process.env.T1C_INDEX_MODULE)
  : path.resolve(import.meta.dirname, '../src/index.js');
const {
  categorize, categorizeEmergencyWrite, emitEmergencyDifferenceMarkers,
  emitEmergencyNonResultDifferenceMarkers,
  emitNonInteractiveOutcome, EXIT_CODE_OF,
} = await import(`${pathToFileURL(indexModulePath).href}?q24_index=${Date.now()}`);

// 便 X1 / Q-B の歯を「直す前」の index.js でも測れるようにする。
// 旧版にはこの出力関数が無いので、呼び出しで落とさずに 0 件として扱い、下の assert を赤にする。
const emitNonResultMarkers = typeof emitEmergencyNonResultDifferenceMarkers === 'function'
  ? emitEmergencyNonResultDifferenceMarkers
  : () => 0;
const NON_RESULT_MARKER = '##EMERGENCY_NONRESULT_DIFFERENCE';

const emergencyModule = await import(
  `${pathToFileURL(emergencyModulePath).href}?q24_emergency=${Date.now()}`
);
const {
  assertEmergencyVerificationGate, EMERGENCY_ALLOWED_DIFFERENCE_CHECKS,
  EMERGENCY_DOWNGRADABLE_CHECKS, EMERGENCY_EFFECTIVE_DIFFERENCE_CHECKS,
  EMERGENCY_FALLBACK_COMBINATION_LIMIT, EMERGENCY_WORKER_COMBINATION_LIMIT,
  EMERGENCY_REQUIRED_CHECKS,
  PREVIOUS_MANIFEST_GENERATION_LIMIT, PREVIOUS_RESULT_HISTORY_LIMIT,
  PREVIOUS_SUMMARY_GENERATION_LIMIT,
  classifyPublicArtifactDifference, manifestCoreHash, resolveEmergencyGenerationMap,
  gcpCandidates, gcpUnevaluated, GCP_GENERATION_BYTE_LIMIT,
  GCP_AUTO_COMPARISON_BYTE_LIMIT,
  isEmergencyCheckDowngradable, loadPreviousResultVersionCandidates,
  readPreviousResultCandidateSummary,
  findResultRegistrationAtGrouping,
  deriveGroupsFromCanonicalRoster, inspectNextGroupingVersionPreservation,
  selectGcpGroupGameInputs,
  selectApplicantGenerationCombination,
  selectEmergencyServerSubmissions, writeEmergencyResultSet,
  verifyEmergencyStage3Witnesses,
} = emergencyModule;

let passed = 0;
let failed = 0;
function ok(name, condition, detail = '') {
  if (condition) { passed++; console.log(`  ok: ${name}`); }
  else { failed++; console.error(`  FAIL: ${name}${detail ? ` — ${detail}` : ''}`); }
}
async function rejects(name, fn, pattern) {
  try { await fn(); ok(name, false, 'did not reject'); }
  catch (error) { ok(name, pattern.test(String(error?.message || error)), error?.message); }
}
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const m14dHighUidGroups = [
  { groupId: 1, members: [{ data: { uid: '999999999999999999' } }] },
  { groupId: 0, members: [{ data: { uid: '888888888888888888' } }] },
];
ok('M14d U-B: 2^32 以上の uid でも GM 呼び手と同じ groupId 昇順の index バイト',
  reconstructedRosterIndexSha256(m14dHighUidGroups)
    === digest(JSON.stringify({ '888888888888888888': 0, '999999999999999999': 1 })));
// P7b: explicit authority is opt-in; malformed invocations stop at usage.
const p7bCli = path.resolve(import.meta.dirname, '../src/index.js');
const p7bSpawn = (args) => spawnSync(process.execPath, [p7bCli, ...args], { encoding: 'utf8' });
const p7bDefault = loadConfig([]);
const p7bFlagged = loadConfig([
  '--emergency-source', '/tmp/p7b-source', '--emergency-out', '/tmp/p7b-out',
  '--emergency-authority=gcp',
]);
ok('P7b 省略時は権威指定がなく、明示指定だけ gcp になる',
  p7bDefault.emergencyAuthority === null && p7bFlagged.emergencyAuthority === 'gcp');
for (const [label, args] of [
  ['源なし', ['--emergency-authority=gcp']],
  ['未知の値', ['--emergency-authority=public', '--emergency-source', '/tmp/p7b-source',
    '--emergency-out', '/tmp/p7b-out']],
  ['値なし', ['--emergency-authority', '--emergency-source', '/tmp/p7b-source',
    '--emergency-out', '/tmp/p7b-out']],
]) {
  const result = p7bSpawn(args);
  ok(`P7b ${label}は usage 64`, result.status === 64
    && result.stderr.includes('--emergency-authority requires --emergency-source and the value gcp'),
  JSON.stringify({ status: result.status, stderr: result.stderr.slice(0, 180) }));
}
const taskTmp = path.resolve(process.env.M14D_TEST_TMP_ROOT ||
  path.resolve(import.meta.dirname, '../../tmp/M11a'), `q24-block-verifier-unit-${process.pid}`);
await fs.rm(taskTmp, { recursive: true, force: true });
await fs.mkdir(taskTmp, { recursive: true });

async function save(relative, text) {
  const filename = path.join(taskTmp, relative);
  await fs.mkdir(path.dirname(filename), { recursive: true });
  await fs.writeFile(filename, text);
  return { savedFile: relative, sha256: digest(Buffer.from(text)), bytes: Buffer.byteLength(text),
    observedAt: '2026-09-16T00:00:00.000Z' };
}

// P12b: decoys may add their own candidate reads, but cannot exhaust an
// honest generation's byte allowance or impose a shared candidate-count cap.
const p12bCandidateKey = 'entries/block4/game_selection.json';
const p12bCandidateRows = [{
  key: p12bCandidateKey, generation: 0, observationOrdinal: '00000000:00000000',
  sha256: '0'.repeat(64), savedFile: '_observer/generations/oversized.bin',
  bytes: GCP_GENERATION_BYTE_LIMIT + 1,
}];
for (let i = 1; i <= 25; i++) {
  const row = await save(`_observer/generations/p12b/selection-${i}.bin`,
    JSON.stringify({ uid: i === 25 ? 'honest' : `decoy-${i}` }));
  p12bCandidateRows.push({ ...row, bytes: Buffer.byteLength(JSON.stringify({
    uid: i === 25 ? 'honest' : `decoy-${i}`,
  })), key: p12bCandidateKey, generation: i,
    observationOrdinal: `00000000:${String(i).padStart(8, '0')}` });
}
const p12bCandidateIndex = { objects: { [p12bCandidateKey]: p12bCandidateRows } };
const p12bEvaluations = [];
let p12bChosen = null;
for await (const candidate of gcpCandidates(taskTmp, p12bCandidateIndex,
  p12bCandidateKey, p12bEvaluations)) {
  p12bEvaluations.push({ observationOrdinal: candidate.row.observationOrdinal,
    reason: candidate.data.uid === 'honest' ? 'match' : 'decoy' });
  if (candidate.data.uid === 'honest') { p12bChosen = candidate; break; }
}
gcpUnevaluated(p12bCandidateIndex, p12bCandidateKey, p12bEvaluations);
ok('P12b GCP候補: oversized囮＋24偽世代の後でも正直な世代を読み、候補ごとの予算を保つ',
  p12bChosen?.row.generation === 25
    && p12bEvaluations.length === 26
    && p12bEvaluations[0].reason === 'individual row byte limit'
    && p12bEvaluations.at(-1).reason === 'match');

const p15DeepValue = `${'['.repeat(12000)}0${']'.repeat(12000)}`;
for (const [label, key, raw] of [
  ['schema', 'games/block4/summary.json', `{"schemaVersion":${p15DeepValue}}`],
  ['extra', 'games/block4/summary.json', `{"schemaVersion":3,"extra":${p15DeepValue}}`],
  ['auto-page', 'games/block4/auto-results.json', `{"schemaVersion":3,"extra":${p15DeepValue}}`],
  ['noncanonical', 'games/block4/summary.json', '{"schemaVersion":2.5}'],
  ['auto-noncanonical', 'games/block4/auto-results.json', '{"schemaVersion":3, "extra":1}'],
]) {
  const bad = await save(`p15-candidates/${label}-bad.bin`, raw);
  const good = await save(`p15-candidates/${label}-good.bin`, '{"schemaVersion":3}');
  const index = { objects: { [key]: [
    { ...bad, generation: 1, bytes: Buffer.byteLength(raw),
      observationOrdinal: '00000001:00000000' },
    { ...good, generation: 2, bytes: 19,
      observationOrdinal: '00000002:00000000' },
  ] } };
  const evaluations = [];
  let selected = null;
  for await (const candidate of gcpCandidates(taskTmp, index, key, evaluations)) {
    selected = candidate;
    break;
  }
  ok(`P15: GCP ${label} の使えない保存版を記録して正直な次世代へ進む`,
    selected?.row.generation === 2 && evaluations[0]?.sha256 === bad.sha256
      && evaluations[0]?.reason === (label === 'noncanonical'
        ? 'noncanonical saved summary' : label === 'auto-noncanonical'
          ? 'noncanonical comparison JSON' : 'JSON depth limit'),
    JSON.stringify({ selected: selected?.row.generation, evaluations }));
}
const p15LargeAutoKey = 'games/block4/auto-results.json';
const p15LargeAutoGood = await save('p15-candidates/large-good.bin', '{"schemaVersion":3}');
const p15LargeAutoEvaluations = [];
let p15LargeAutoSelected = null;
for await (const candidate of gcpCandidates(taskTmp, { objects: { [p15LargeAutoKey]: [
  { generation: 1, observationOrdinal: '00000001:00000000',
    savedFile: 'p15-candidates/oversized-do-not-read.bin', sha256: '0'.repeat(64),
    bytes: GCP_AUTO_COMPARISON_BYTE_LIMIT + 1 },
  { ...p15LargeAutoGood, generation: 2, observationOrdinal: '00000002:00000000', bytes: 19 },
] } }, p15LargeAutoKey, p15LargeAutoEvaluations)) {
  p15LargeAutoSelected = candidate;
  break;
}
ok('P15: 保存auto-resultsの各行バイト上限は囮を読まず次の正直な行を妨げない',
  p15LargeAutoSelected?.row.generation === 2
    && p15LargeAutoEvaluations[0]?.reason === 'individual row byte limit',
  JSON.stringify(p15LargeAutoEvaluations));

async function withFixedNow(iso, fn) {
  const RealDate = globalThis.Date;
  const fixedMs = RealDate.parse(iso);
  globalThis.Date = class FixedDate extends RealDate {
    constructor(...args) { super(...(args.length ? args : [fixedMs])); }
    static now() { return fixedMs; }
  };
  try { return await fn(); } finally { globalThis.Date = RealDate; }
}

function applicantIntermediate(blockNum, infos, entriesByFilename) {
  const hashList = infos.map((info, workerIndex) => {
    const entries = info.entries.map(({ filename, number }) => ({
      filename,
      hash: hashLikeBackend(entriesByFilename.get(filename)),
      number,
    }));
    return {
      workerIndex,
      hash: hashLikeBackend({ block_num: blockNum, status: 'success', entries }),
    };
  });
  const hash = hashList.map(({ workerIndex, hash: workerHash }) => ({
    filename: `${String(workerIndex).padStart(2, '0')}_hash`,
    hash: workerHash,
  }));
  hash.sort((a, b) => a.filename.localeCompare(b.filename));
  return { block_num: blockNum, status: 'success', hash };
}

function applicantRoot(blockNum, infos, entriesByFilename) {
  return `0x${hashLikeBackend(applicantIntermediate(blockNum, infos, entriesByFilename))}`;
}

// Z11 変異検査用の旧定義。保管庫に旧rootと新rootの両中間世代を置き、
// 検証実装から number を落としたときだけ旧root側で2世代が衝突させる。
function legacyApplicantIntermediate(blockNum, infos, entriesByFilename) {
  const hashList = infos.map((info, workerIndex) => {
    const entries = info.entries.map(({ filename }) => ({
      filename,
      hash: hashLikeBackend(entriesByFilename.get(filename)),
    }));
    return {
      workerIndex,
      hash: hashLikeBackend({ block_num: blockNum, status: 'success', entries }),
    };
  });
  const hash = hashList.map(({ workerIndex, hash: workerHash }) => ({
    filename: `${String(workerIndex).padStart(2, '0')}_hash`,
    hash: workerHash,
  }));
  hash.sort((a, b) => a.filename.localeCompare(b.filename));
  return { block_num: blockNum, status: 'success', hash };
}

// U1: chain resultHash -> manifest generation -> manifest.files generation. Unmarked conflicts stop.
const selectionText = '{"applicantHash":"0x01"}';
const selectionRow = await save('_observer/generations/entries/selection/000001.bin', selectionText);
const manifest = {
  blockNum: 4, algorithm: 'sha256', rules: {},
  files: { 'entries/block4/game_selection.json': selectionRow.sha256 },
};
manifest.manifestHash = manifestCoreHash(manifest);
const manifestText = JSON.stringify(manifest);
const manifestRow = await save('_observer/generations/verification/manifest/000001.bin', manifestText);
const previousSummaryKey = 'games/block3/summary.json';
const previousManifestKey = 'verification/block3/manifest.json';
const previousSummaryText = '{"schemaVersion":2,"blockNum":3,"noGame":true,"majorLangs":[],"groups":[]}';
const previousSummaryRow = await save('_observer/generations/previous/summary-canonical.bin', previousSummaryText);
const previousManifest = {
  blockNum: 3, algorithm: 'sha256', rules: {},
  files: { [previousSummaryKey]: previousSummaryRow.sha256 },
};
const previousCore = manifestCoreHash(previousManifest);
const previousManifestRows = [];
const previousSummaryRows = [{
  ...previousSummaryRow, generation: 1, observationOrdinal: '00000000:00000010',
}];
for (let generation = 1; generation <= 4; generation++) {
  const row = await save(
    `_observer/generations/previous/manifest-${generation}.bin`,
    JSON.stringify({ ...previousManifest, createdAt: `2026-09-19T00:00:0${generation}.000Z` }),
  );
  previousManifestRows.push({
    ...row, generation, observationOrdinal: `00000000:0000001${generation}`,
  });
  if (generation > 1) {
    const summaryVariant = await save(
      `_observer/generations/previous/summary-extra-${generation}.bin`,
      JSON.stringify({ blockNum: 3, untrustedGeneration: generation }),
    );
    previousSummaryRows.push({
      ...summaryVariant, generation, observationOrdinal: `00000000:0000002${generation}`,
    });
  }
}
const index = {
  schemaVersion: 1, kind: 'r2-backup-observer-block-archive', blockNum: 4,
  sourceRunId: 'run-2', complete: true,
  objects: {
    'verification/block4/manifest.json': [{ ...manifestRow, generation: 1, observationOrdinal: '00000000:00000000' }],
    'entries/block4/game_selection.json': [{ ...selectionRow, generation: 1, observationOrdinal: '00000000:00000001' }],
    [previousManifestKey]: previousManifestRows,
    [previousSummaryKey]: previousSummaryRows,
  },
};
await save('_observer/generation-index.json', JSON.stringify(index));
const chain = {
  getResultHash: async (block) => ({ hash: Number(block) === 3 ? previousCore : manifest.manifestHash }),
};
const resolved = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
ok('U1 chain marker と manifest.files が選んだ保存世代だけを local map に載せる',
  resolved.fileMap.get('verification/block4/manifest.json') === manifestRow.savedFile
  && resolved.fileMap.get('entries/block4/game_selection.json') === selectionRow.savedFile);
ok('U4-C1 前ブロックのmanifest/summaryが平時どおり複数世代でも2ホップ目印で正世代を選ぶ',
  resolved.fileMap.get(previousManifestKey) === previousManifestRows[0].savedFile
  && resolved.fileMap.get(previousSummaryKey) === previousSummaryRow.savedFile
  && resolved.differences.some((difference) => difference.checkId === 'emergency.previousManifestBytes')
  && resolved.differences.some((difference) => difference.checkId === 'emergency.previousSummaryGenerations'));
console.log(`U4_C1_SELECTION prevManifest=${resolved.fileMap.get(previousManifestKey)} prevSummary=${resolved.fileMap.get(previousSummaryKey)} manifestGenerations=${previousManifestRows.length} summaryGenerations=${previousSummaryRows.length}`);
const m2DeepManifestRaw = '{"blockNum":4,"algorithm":"sha256","rules":'
  + '['.repeat(20000) + '0' + ']'.repeat(20000) + ',"files":{}}';
const m2DeepManifestRow = await save('_observer/generations/m2/deep-manifest.bin',
  m2DeepManifestRaw);
const m11aBadManifestRow = await save('_observer/generations/m11a/bad-manifest.bin', '[]');
const m2ManifestIndex = structuredClone(index);
m2ManifestIndex.objects['verification/block4/manifest.json'] = [
  { ...m11aBadManifestRow, generation: 0, observationOrdinal: '00000000:00000000' },
  { ...m2DeepManifestRow, generation: 0, observationOrdinal: '00000000:00000000' },
  { savedFile: '_observer/generations/m2/not-read-oversize.bin', sha256: '0'.repeat(64),
    bytes: 193 * 1024 * 1024, generation: 1, observationOrdinal: '00000000:00000001' },
  { ...manifestRow, generation: 2, observationOrdinal: '00000000:00000002' },
];
await save('_observer/generation-index.json', JSON.stringify(m2ManifestIndex));
const m2ManifestPicked = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
const m2ManifestDiscarded = m2ManifestPicked.differences.find((d) =>
  d.checkId === 'emergency.manifestGenerations' && d.rebuilt?.unusableCandidates);
ok('M2: 深い manifest と行バイト超過はそれぞれ記録し、正直な世代を採る',
  m2ManifestPicked.fileMap.get('verification/block4/manifest.json') === manifestRow.savedFile
  && m2ManifestDiscarded?.rebuilt?.unusableCandidates?.some((c) =>
      c.sha256 === m2DeepManifestRow.sha256 && c.reason === 'JSON depth limit')
    && m2ManifestDiscarded?.rebuilt?.unusableCandidates?.some((c) =>
      c.sha256 === m11aBadManifestRow.sha256 && c.reason === 'unusable saved manifest structure')
    && m2ManifestDiscarded?.rebuilt?.unusableCandidates?.some((c) =>
      c.sha256 === '0'.repeat(64) && c.reason === 'individual row byte limit'));
const n5CurrentDeepManifestRow = await save('_observer/generations/n5/current-deep-manifest.bin',
  JSON.stringify(manifest).replace(/}\s*$/, ',"nonsemantic":'
    + '['.repeat(300) + '0' + ']'.repeat(300) + '}'));
const n5CurrentDeepIndex = structuredClone(index);
n5CurrentDeepIndex.objects['verification/block4/manifest.json'] = [n5CurrentDeepManifestRow];
await save('_observer/generation-index.json', JSON.stringify(n5CurrentDeepIndex));
const n5CurrentDeepPicked = await resolveEmergencyGenerationMap({
  sourceDir: taskTmp, chain, blockNum: 4,
});
ok('R32-D-10-01: 現ブロックの登録 manifest の非意味欄は深さ300でも採る',
  n5CurrentDeepPicked.fileMap.get('verification/block4/manifest.json')
    === n5CurrentDeepManifestRow.savedFile);
await save('_observer/generation-index.json', JSON.stringify(index));
for (const [label, savedFile] of [
  ['sha256', m2DeepManifestRow.savedFile],
  ['missing', '_observer/generations/m11a-missing-manifest.bin'],
]) {
  const broken = structuredClone(index);
  broken.objects['verification/block4/manifest.json'] = [
    { ...manifestRow, savedFile, generation: 0 }, manifestRow,
  ];
  await save('_observer/generation-index.json', JSON.stringify(broken));
  await rejects(`M11a: ${label} の保存 manifest 事故は materialize-block の再取得を案内する`,
    () => resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 }),
    /materialize-block/);
}
const m11aPreviousDeepIndex = structuredClone(index);
m11aPreviousDeepIndex.objects[previousManifestKey].unshift({
  ...m2DeepManifestRow, generation: 0, observationOrdinal: '00000000:00000000',
});
await save('_observer/generation-index.json', JSON.stringify(m11aPreviousDeepIndex));
const m11aPreviousDeepPicked = await resolveEmergencyGenerationMap({
  sourceDir: taskTmp, chain, blockNum: 4,
});
ok('M11a: 既定の緊急経路も深い前ブロック manifest を外して正直な2鍵を採る',
  m11aPreviousDeepPicked.fileMap.get(previousManifestKey) === previousManifestRows[0].savedFile
  && m11aPreviousDeepPicked.differences.some((difference) =>
    difference.checkId === 'emergency.previousManifestGenerations'
      && difference.rebuilt?.unusableCandidates?.some((candidate) =>
        candidate.sha256 === m2DeepManifestRow.sha256 && candidate.reason === 'JSON depth limit')));
await save('_observer/generation-index.json', JSON.stringify(index));

// P5 / R30-A-4-04: manifest が game_groups を null と宣言していても、見張り役が
// 保存世代を持つ事実は消えない。採用は null のまま、差分だけを残す。
const p5NullGroupText = '{"groups":[{"groupId":0}]}';
const p5NullGroupRow = await save('_observer/generations/p5/game-groups.bin', p5NullGroupText);
const p5NullManifest = {
  blockNum: 0, algorithm: 'sha256', rules: {},
  files: { 'entries/block0/game_groups.json': null },
};
p5NullManifest.manifestHash = manifestCoreHash(p5NullManifest);
const p5NullManifestRow = await save(
  '_observer/generations/p5/manifest-null-game-groups.bin', JSON.stringify(p5NullManifest),
);
const p5NullSourceIndex = {
  schemaVersion: 1, kind: 'r2-backup-observer-block-archive', blockNum: 0,
  sourceRunId: 'p5-null', complete: true,
  objects: {
    'verification/block0/manifest.json': [{
      ...p5NullManifestRow, generation: 1, observationOrdinal: '00000000:00000000',
    }],
    'entries/block0/game_groups.json': [{
      ...p5NullGroupRow, generation: 1, observationOrdinal: '00000000:00000001',
    }],
  },
};
await save('_observer/generation-index.json', JSON.stringify(p5NullSourceIndex));
const p5NullResolved = await resolveEmergencyGenerationMap({
  sourceDir: taskTmp,
  chain: { getResultHash: async () => ({ hash: p5NullManifest.manifestHash, updated: 12 }) },
  blockNum: 0,
});
ok('P5 R30-A-4-04 宣言nullでもgame_groups保存世代の存在を差分に残し、採用値はnullを保つ',
  p5NullResolved.fileMap.get('entries/block0/game_groups.json') === null
  && p5NullResolved.differences.some((difference) => (
    difference.checkId === 'emergency.declaredNullWithSavedGeneration'
    && difference.chain?.key === 'entries/block0/game_groups.json'
    && difference.rebuilt?.useAsChatStartEvidence === false
  )), JSON.stringify(p5NullResolved.differences));
// 後続の既存 fixture が読む索引へ戻す。
await save('_observer/generation-index.json', JSON.stringify(index));
// ==================================================================
// 周29 (c)（2026-09-22）: 緊急モードの前ブロック入力選択が **履歴のどの行を選んだか** を残す。
// 🔴 選び方（HashStorage.getResultHash の現在値）は変えていない。見えるようにするだけ。
// ==================================================================
ok('周29 (c) 履歴 getter の無い読み手でも前ブロックの目印の記録を残し、読めなかったことを書く',
  resolved.previousResultRegistration?.blockNum === 3
  && resolved.previousResultRegistration?.hash === previousCore
  && resolved.previousResultRegistration?.currentIndex === null
  && typeof resolved.previousResultRegistration?.historyError === 'string'
  && resolved.previousResultRegistration.historyError.includes('resultRegistrationHistory'),
  JSON.stringify(resolved.previousResultRegistration));

chain.resultRegistrationHistory = async (block) => (Number(block) === 3
  ? {
    count: 2,
    rows: [
      { index: 0, hash: previousCore, registeredBlock: 40, registeredAt: 10, signer: `0x${'ab'.repeat(20)}` },
      { index: 1, hash: `0x${'5c'.repeat(32)}`, registeredBlock: 90, registeredAt: 20, signer: `0x${'ab'.repeat(20)}` },
    ],
  }
  : { count: 0, rows: [] });
const resolvedWithHistory = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
ok('周29 (c) 前ブロックの現在値が追記履歴のどの行かを名指す（現在値＝添字0・最新＝添字1）',
  resolvedWithHistory.previousResultRegistration?.currentIndex === 0
  && resolvedWithHistory.previousResultRegistration?.latestIndex === 1
  && resolvedWithHistory.previousResultRegistration?.registrationCount === 2
  && resolvedWithHistory.previousResultRegistration?.historyError === null
  && resolvedWithHistory.previousResultRegistration?.selectionRule
    === 'HashStorage.getResultHash current value (unchanged)',
  JSON.stringify(resolvedWithHistory.previousResultRegistration));
ok('周29 (c) 履歴を読んでも選ばれる前ブロックの世代と差の集合は1件も変わらない',
  resolvedWithHistory.fileMap.get(previousManifestKey) === resolved.fileMap.get(previousManifestKey)
  && resolvedWithHistory.fileMap.get(previousSummaryKey) === resolved.fileMap.get(previousSummaryKey)
  && JSON.stringify(resolvedWithHistory.differences.map((d) => d.checkId))
    === JSON.stringify(resolved.differences.map((d) => d.checkId)),
  JSON.stringify({
    withHistory: resolvedWithHistory.differences.map((d) => d.checkId),
    without: resolved.differences.map((d) => d.checkId),
  }));
delete chain.resultRegistrationHistory;

// ==================================================================
// P6 / R30-U-4 / R30-C-4-01:
// N+1 の正典の N は「N+1 の実際の組を再現する履歴行」。現在値へ戻さず、
// resultRegistrationAt の各行 → 保存 manifest → 保存 summary の2ホップで選ぶ。
// ==================================================================
const p6EmergencyDir = path.resolve(process.env.M14D_TEST_TMP_ROOT
  || path.resolve(import.meta.dirname, '../../tmp/M11a'),
`q24-previous-result-version-${process.pid}`);
await fs.rm(p6EmergencyDir, { recursive: true, force: true });
await fs.mkdir(p6EmergencyDir, { recursive: true });
async function p6Save(relative, value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  const filename = path.join(p6EmergencyDir, relative);
  await fs.mkdir(path.dirname(filename), { recursive: true });
  await fs.writeFile(filename, text);
  return {
    savedFile: relative,
    sha256: digest(Buffer.from(text)),
    bytes: Buffer.byteLength(text),
    observedAt: '2026-09-23T00:00:00.000Z',
  };
}
function p6CompletedSummary(blockNum, lang = 'ja', count = 200) {
  return {
    schemaVersion: 2,
    blockNum,
    majorLangs: [lang],
    groups: [{
      group_id: 0,
      status: 'completed',
      members: Array.from({ length: count }, (_, i) => ({
        userId: `prev-${lang}-${i}`, lang, is_disqualified: 0,
      })),
    }],
  };
}
const p6Block = 4;
const p6Prev = p6Block - 1;
const p6OldSummary = p6CompletedSummary(p6Prev);
const p6NewSummary = {
  schemaVersion: 2, blockNum: p6Prev, noGame: true, majorLangs: [], groups: [], totalGroups: 0,
};
const p6OldSummaryRow = await p6Save('old-summary.bin', p6OldSummary);
const p6NewSummaryRow = await p6Save('new-summary.bin', p6NewSummary);
const p6SummaryKey = `games/block${p6Prev}/summary.json`;
const p6ManifestKey = `verification/block${p6Prev}/manifest.json`;
const p6OldManifest = {
  blockNum: p6Prev, algorithm: 'sha256', rules: {}, files: { [p6SummaryKey]: p6OldSummaryRow.sha256 },
};
const p6NewManifest = {
  blockNum: p6Prev, algorithm: 'sha256', rules: {}, files: { [p6SummaryKey]: p6NewSummaryRow.sha256 },
};
const p6OldManifestRow = await p6Save('old-manifest.bin', p6OldManifest);
const p6NewManifestRow = await p6Save('new-manifest.bin', p6NewManifest);
const p6OldCore = manifestCoreHash(p6OldManifest);
const p6NewCore = manifestCoreHash(p6NewManifest);

const p6Players = Array.from({ length: 10 }, (_, i) => ({
  globalIndex: i,
  data: { uid: `p6-u${i}`, lang: i === 9 ? 'en' : 'ja',
    addr: `0x${(i + 1).toString(16).padStart(40, '0')}` },
}));
const p6Selection = {
  blockNum: p6Block,
  randao: `0x${'61'.repeat(32)}`,
  applicantHash: `0x${'62'.repeat(32)}`,
  players: p6Players,
};
const p6GroupSeed = keccak256(concatHex([
  p6Selection.randao, p6Selection.applicantHash, stringToHex('group'),
]));
const p6Gm = new GameMasterDO({ storage: {} }, {});
const p6ActualGroups = await p6Gm.formGroups(p6Players, p6GroupSeed, ['ja']);
const p6GameGroups = p6Gm.createGroupSummary(p6Block, p6ActualGroups, p6Selection);
p6GameGroups.prevResultRegistration = { index: '0', registeredBlock: '30',
  registeredAt: '300', hash: p6OldCore };
const p6SelectionRow = await p6Save('selection.bin', p6Selection);
const p6GameGroupsRow = await p6Save('game-groups.bin', p6GameGroups);
const p6CurrentSummaryRow = await p6Save('current-summary.bin', {
  blockNum: p6Block, majorLangs: ['ja'],
});
const p6CurrentManifest = {
  blockNum: p6Block,
  algorithm: 'sha256',
  rules: {},
  files: {
    [`entries/block${p6Block}/game_selection.json`]: p6SelectionRow.sha256,
    [`entries/block${p6Block}/game_groups.json`]: p6GameGroupsRow.sha256,
    [`games/block${p6Block}/summary.json`]: p6CurrentSummaryRow.sha256,
  },
};
p6CurrentManifest.manifestHash = manifestCoreHash(p6CurrentManifest);
const p6CurrentManifestRow = await p6Save('current-manifest.bin', p6CurrentManifest);
const p6Index = {
  schemaVersion: 1,
  kind: 'r2-backup-observer-block-archive',
  blockNum: p6Block,
  sourceRunId: 'p6-run',
  complete: true,
  objects: {
    [`verification/block${p6Block}/manifest.json`]: [{
      ...p6CurrentManifestRow, generation: 1, observationOrdinal: '00000001:00000000',
    }],
    [`entries/block${p6Block}/game_selection.json`]: [{
      ...p6SelectionRow, generation: 1, observationOrdinal: '00000001:00000001',
    }],
    [`entries/block${p6Block}/game_groups.json`]: [{
      ...p6GameGroupsRow, generation: 1, observationOrdinal: '00000001:00000002',
    }],
    [`games/block${p6Block}/summary.json`]: [{
      ...p6CurrentSummaryRow, generation: 1, observationOrdinal: '00000001:00000003',
    }],
    [p6ManifestKey]: [
      { ...p6OldManifestRow, generation: 1, observationOrdinal: '00000000:00000000' },
      { ...p6NewManifestRow, generation: 2, observationOrdinal: '00000002:00000000' },
    ],
    [p6SummaryKey]: [
      { ...p6OldSummaryRow, generation: 1, observationOrdinal: '00000000:00000001' },
      { ...p6NewSummaryRow, generation: 2, observationOrdinal: '00000002:00000001' },
    ],
  },
};
await fs.mkdir(path.join(p6EmergencyDir, '_observer'), { recursive: true });
await fs.writeFile(
  path.join(p6EmergencyDir, '_observer/generation-index.json'),
  JSON.stringify(p6Index),
);
const p6HistoryRows = [
  {
    index: 0, hash: p6OldCore, registeredBlock: 30, registeredAt: 300,
    signer: `0x${'a1'.repeat(20)}`,
  },
  {
    index: 1, hash: p6NewCore, registeredBlock: 40, registeredAt: 400,
    signer: `0x${'a2'.repeat(20)}`,
  },
];
function p6EmergencyChain(historyRows = p6HistoryRows) {
  return {
    getTimingConstants: async () => ({ startTimeEntryMs: 0, blockTimeMs: 1000, gamePeriodMs: 1000 }),
    currentGrace: async () => 320, // block 4 entryEnd=5s; chattingStart=325s
    getResultHash: async (block) => (Number(block) === p6Prev
      ? { hash: p6NewCore, updated: 40, signer: `0x${'a2'.repeat(20)}` }
      : { hash: p6CurrentManifest.manifestHash, updated: 50, signer: `0x${'a3'.repeat(20)}` }),
    resultRegistrationCount: async () => historyRows.length,
    resultRegistrationAt: async (_block, registrationIndex) => historyRows[registrationIndex],
    resultRegistrationHistory: async () => ({ count: historyRows.length, rows: historyRows }),
  };
}

const p6HistoricalResolved = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir,
  chain: p6EmergencyChain(),
  blockNum: p6Block,
});
const m11bDefaultRoster = { blockNum: p6Block,
  indexSha256: reconstructedRosterIndexSha256(p6ActualGroups),
  groups: p6ActualGroups.map((group) => ({ groupId: group.groupId,
    sha256: reconstructedRosterGroupSha256(p6Block, group) })),
};
const m11bDefaultRosterRow = await p6Save('m11b-roster.bin', m11bDefaultRoster);
const p6RosterPayloads = reconstructCanonicalRosterPayloads(p6Block, p6ActualGroups);
const m11bDefaultRosterHash = buildRosterMemberCommitment({ blockNum: p6Block,
  manifestText: JSON.stringify(m11bDefaultRoster), groupTexts: p6RosterPayloads.groupTexts }).C;
const m11bDefaultLostIndex = structuredClone(p6Index);
m11bDefaultLostIndex.objects[p6ManifestKey] = [p6Index.objects[p6ManifestKey][1]];
m11bDefaultLostIndex.objects[p6SummaryKey] = [p6Index.objects[p6SummaryKey][1]];
m11bDefaultLostIndex.objects[`games/block${p6Block}/roster/manifest.json`] = [m11bDefaultRosterRow];
await fs.writeFile(path.join(p6EmergencyDir, '_observer/generation-index.json'),
  JSON.stringify(m11bDefaultLostIndex));
const m11bDefaultLost = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir,
  chain: { ...p6EmergencyChain(), otherRegistrationCount: async () => 1,
    otherRegistrationAt: async () => ({ hash: m11bDefaultRosterHash,
      registeredBlock: 35, registeredAt: 320 }) },
  blockNum: p6Block,
});
ok('M11b UJ1: 既定の緊急入口も窓内 N 本文消失を差分化し、後登録 F を写さない',
  m11bDefaultLost.previousMajorLangsUnverifiable?.majorLangs?.join(',') === 'ja'
    && !m11bDefaultLost.fileMap.has(p6ManifestKey)
    && !m11bDefaultLost.fileMap.has(p6SummaryKey)
    && m11bDefaultLost.differences.some((difference) =>
      difference.checkId === 'emergency.previousSummaryLost'),
  JSON.stringify({ lost: m11bDefaultLost.previousMajorLangsUnverifiable,
    files: [...m11bDefaultLost.fileMap.keys()], differences: m11bDefaultLost.differences }));
const n5LostNoRosterIndex = structuredClone(m11bDefaultLostIndex);
delete n5LostNoRosterIndex.objects[`games/block${p6Block}/roster/manifest.json`];
await fs.writeFile(path.join(p6EmergencyDir, '_observer/generation-index.json'),
  JSON.stringify(n5LostNoRosterIndex));
const n5LostNoRosterChain = { ...p6EmergencyChain(), otherRegistrationCount: async () => 1,
  otherRegistrationAt: async () => ({ hash: m11bDefaultRosterHash,
    registeredBlock: 35, registeredAt: 320 }) };
const n5LostNoRoster = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir, chain: n5LostNoRosterChain, blockNum: p6Block,
}).catch((error) => error);
ok('N5 UJ1: 窓内版消失と名簿0世代でも正典 keccak が一致すれば差分つきで進む',
  !(n5LostNoRoster instanceof Error)
  && n5LostNoRoster.previousMajorLangsUnverifiable?.missingVersions?.length > 0
  && n5LostNoRoster.differences.some((difference) =>
    difference.checkId === 'emergency.previousSummaryLost'));
const n5LostWrongRoster = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir, blockNum: p6Block,
  chain: { ...n5LostNoRosterChain, otherRegistrationAt: async () => ({
    hash: `0x${'ee'.repeat(32)}`, registeredBlock: 35, registeredAt: 320,
  }) },
}).catch((error) => error);
ok('N5 UJ1: 消失と名簿 keccak 不一致は候補差分つきで止まる',
  n5LostWrongRoster instanceof Error
  && Array.isArray(n5LostWrongRoster.emergencyDifferences)
  && n5LostWrongRoster.emergencyDifferences.some((difference) =>
    difference.checkId === 'emergency.previousSummaryLost'));
const n5SummaryOnlyIndex = structuredClone(m11bDefaultLostIndex);
n5SummaryOnlyIndex.objects[p6ManifestKey] = [p6Index.objects[p6ManifestKey][0]];
n5SummaryOnlyIndex.objects[p6SummaryKey] = [];
await fs.writeFile(path.join(p6EmergencyDir, '_observer/generation-index.json'),
  JSON.stringify(n5SummaryOnlyIndex));
const n5SummaryOnly = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir, chain: n5LostNoRosterChain, blockNum: p6Block,
}).catch((error) => error);
ok('R32-C-1-04: 既定入口で manifest 保存・summary だけ欠落も消失差分へ入る',
  !(n5SummaryOnly instanceof Error)
  && n5SummaryOnly.previousMajorLangsUnverifiable?.missingVersions?.some((row) =>
    row.status === 'summary_generation_missing'));
await fs.writeFile(path.join(p6EmergencyDir, '_observer/generation-index.json'),
  JSON.stringify(m11bDefaultLostIndex));
const m14dFalseSummaryRow = await p6Save('m14d-false-declared-langs.bin', {
  blockNum: p6Block, majorLangs: [],
});
const m14dFalseCurrentManifest = { ...p6CurrentManifest,
  files: { ...p6CurrentManifest.files,
    [`games/block${p6Block}/summary.json`]: m14dFalseSummaryRow.sha256 } };
m14dFalseCurrentManifest.manifestHash = manifestCoreHash(m14dFalseCurrentManifest);
const m14dFalseCurrentManifestRow = await p6Save('m14d-false-current-manifest.bin',
  m14dFalseCurrentManifest);
const m14dFalseDefaultIndex = structuredClone(m11bDefaultLostIndex);
m14dFalseDefaultIndex.objects[`verification/block${p6Block}/manifest.json`] = [
  m14dFalseCurrentManifestRow,
];
m14dFalseDefaultIndex.objects[`games/block${p6Block}/summary.json`] = [
  m14dFalseSummaryRow,
];
await fs.writeFile(path.join(p6EmergencyDir, '_observer/generation-index.json'),
  JSON.stringify(m14dFalseDefaultIndex));
const m14dDefaultFalse = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir,
  chain: { ...p6EmergencyChain(),
    getResultHash: async (block) => Number(block) === p6Prev
      ? { hash: p6NewCore, updated: 40, signer: `0x${'a2'.repeat(20)}` }
      : { hash: m14dFalseCurrentManifest.manifestHash, updated: 50,
        signer: `0x${'a3'.repeat(20)}` },
    otherRegistrationCount: async () => 1,
    otherRegistrationAt: async () => ({ hash: m11bDefaultRosterHash,
      registeredBlock: 35, registeredAt: 320 }) },
  blockNum: p6Block,
}).catch((error) => error);
ok('M14d UJ1: 既定入口の消失枝も宣言主要言語で組を作り直して不一致を止める',
  m14dDefaultFalse instanceof Error
    && /declared major languages do not reproduce/.test(m14dDefaultFalse.message));
await fs.writeFile(path.join(p6EmergencyDir, '_observer/generation-index.json'),
  JSON.stringify(m11bDefaultLostIndex));
const m11cMixedIndex = structuredClone(m11bDefaultLostIndex);
m11cMixedIndex.objects[p6ManifestKey] = [p6Index.objects[p6ManifestKey][1]];
m11cMixedIndex.objects[p6SummaryKey] = [p6Index.objects[p6SummaryKey][1]];
const m11cMixedRows = [
  { ...p6HistoryRows[1], index: 0, registeredAt: 300 },
  { ...p6HistoryRows[0], index: 1, registeredAt: 320 },
];
await fs.writeFile(path.join(p6EmergencyDir, '_observer/generation-index.json'),
  JSON.stringify(m11cMixedIndex));
const m11cMixed = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir,
  chain: { ...p6EmergencyChain(m11cMixedRows), otherRegistrationCount: async () => 1,
    otherRegistrationAt: async () => ({ hash: m11bDefaultRosterHash,
      registeredBlock: 35, registeredAt: 320 }) },
  blockNum: p6Block,
}).catch((error) => error);
ok('M11c: 記録と異なる履歴行を持つ混在盤面は止まる',
  m11cMixed instanceof Error && /recorded previous/.test(m11cMixed.message),
  String(m11cMixed?.message));
await fs.writeFile(path.join(p6EmergencyDir, '_observer/generation-index.json'),
  JSON.stringify(p6Index));
const p6SuppliedRosterHash = `0x${'ac'.repeat(32)}`;
const p6EmergencySuppliedRoster = await loadPreviousResultVersionCandidates({
  sourceDir: p6EmergencyDir, index: p6Index, blockNum: p6Block,
  includeOutsideWindow: true, groupingRosterHash: p6SuppliedRosterHash,
  chain: {
    ...p6EmergencyChain(),
    getOtherHash: async () => { throw new Error('emergency supplied roster must bypass saved roster selection'); },
    otherRegistrationCount: async () => 1,
    otherRegistrationAt: async () => ({ hash: p6SuppliedRosterHash,
      registeredBlock: 35, registeredAt: 320 }),
    firstMatchingOtherRegistration: async (_key, _entryEnd, expectedHash) => (
      expectedHash === p6SuppliedRosterHash
        ? { hash: p6SuppliedRosterHash, registeredBlock: 35, registeredAt: 320, index: 0 }
        : null),
  },
});
ok('M1 緊急: 指定名簿hashは保存名簿の選択を迂回し窓外の並びを保つ',
  p6EmergencySuppliedRoster.groupingTime.upperMs === 320_000
    && p6EmergencySuppliedRoster.history.rows.map((row) => row.index).join(',') === '0,1',
  JSON.stringify({ upperMs: p6EmergencySuppliedRoster.groupingTime.upperMs,
    rows: p6EmergencySuppliedRoster.history.rows.map((row) => row.index) }));
const m2ReadyVersion = p6EmergencySuppliedRoster.candidates.find((candidate) =>
  candidate.status === 'ready');
ok('M2: 前ブロック候補は行だけを保持し、評価時に summary を再読込できる',
  m2ReadyVersion && !Object.hasOwn(m2ReadyVersion, 'summary')
    && !Object.hasOwn(m2ReadyVersion, 'manifest')
    && (await readPreviousResultCandidateSummary(p6EmergencyDir, m2ReadyVersion)).blockNum === p6Prev);
const m2PrevDeepRaw = '{"blockNum":3,"groups":[],"nonsemantic":'
  + '['.repeat(20000) + '0' + ']'.repeat(20000) + '}';
const m2PrevDeepRow = await p6Save('m2-prev-deep-summary.bin', m2PrevDeepRaw);
const m2PrevBigRow = { savedFile: 'm2-prev-oversize-not-read.bin', sha256: 'b'.repeat(64),
  bytes: 193 * 1024 * 1024, generation: 4, observationOrdinal: '00000004:00000000' };
const m2PrevDeepManifest = { blockNum: 3, algorithm: 'sha256', rules: {},
  files: { [p6SummaryKey]: m2PrevDeepRow.sha256 } };
const m2PrevBigManifest = { blockNum: 3, algorithm: 'sha256', rules: {},
  files: { [p6SummaryKey]: m2PrevBigRow.sha256 } };
const m2PrevDeepManifestRow = await p6Save('m2-prev-deep-manifest.bin', m2PrevDeepManifest);
const m2PrevBigManifestRow = await p6Save('m2-prev-big-manifest.bin', m2PrevBigManifest);
const m2PrevTooDeepManifestRow = await p6Save('m2-prev-too-deep-manifest.bin',
  '{"blockNum":3,"algorithm":"sha256","rules":'
  + '['.repeat(20000) + '0' + ']'.repeat(20000) + ',"files":{}}');
const m2PrevIndex = structuredClone(p6Index);
m2PrevIndex.objects[p6ManifestKey].push(
  { ...m2PrevDeepManifestRow, generation: 3, observationOrdinal: '00000003:00000000' },
  { ...m2PrevBigManifestRow, generation: 4, observationOrdinal: '00000004:00000000' },
  { ...m2PrevTooDeepManifestRow, generation: 0, observationOrdinal: '00000000:00000000' });
m2PrevIndex.objects[p6SummaryKey].push(
  { ...m2PrevDeepRow, generation: 3, observationOrdinal: '00000003:00000001' },
  m2PrevBigRow);
const m2PrevRows = [p6HistoryRows[0],
  { ...p6HistoryRows[0], index: 1, hash: manifestCoreHash(m2PrevDeepManifest), registeredAt: 305 },
  { ...p6HistoryRows[0], index: 2, hash: manifestCoreHash(m2PrevBigManifest), registeredAt: 310 },
  { ...p6HistoryRows[1], index: 3 }];
const m2PrevPicked = await loadPreviousResultVersionCandidates({
  sourceDir: p6EmergencyDir, index: m2PrevIndex, blockNum: p6Block,
  chain: p6EmergencyChain(m2PrevRows), includeOutsideWindow: true,
  groupingRosterHash: p6SuppliedRosterHash, emergencyLimits: true,
});
ok('R32-D-10-01: 錨付き前ブロック summary の深さは許し行バイト超過は外す',
  m2PrevPicked.manifestEvaluations.some((c) =>
    c.sha256 === m2PrevTooDeepManifestRow.sha256 && c.reason === 'JSON depth limit')
    && m2PrevPicked.candidates.some((c) => c.status === 'ready'
    && c.summaryRow?.sha256 === p6OldSummaryRow.sha256)
    && m2PrevPicked.candidates.some((c) => c.status === 'ready'
      && c.summaryRow?.sha256 === m2PrevDeepRow.sha256)
    && m2PrevPicked.candidates.some((c) => c.status === 'summary_unreadable'
      && c.summaryRow?.sha256 === m2PrevBigRow.sha256 && c.error === 'individual row byte limit'));
const n5Deep100kSummary = await p6Save('n5-prev-depth100k-summary.bin',
  '{"blockNum":3,"groups":[],"nonsemantic":' + '['.repeat(100000) + '0'
    + ']'.repeat(100000) + '}');
const n5Deep100kManifest = { blockNum: 3, algorithm: 'sha256', rules: {},
  files: { [p6SummaryKey]: n5Deep100kSummary.sha256 } };
const n5Deep100kManifestRow = await p6Save('n5-prev-depth100k-manifest.bin',
  JSON.stringify(n5Deep100kManifest).replace(/}\s*$/, ',"nonsemantic":'
    + '['.repeat(100000) + '0' + ']'.repeat(100000) + '}'));
const n5Deep100kIndex = structuredClone(p6Index);
n5Deep100kIndex.objects[p6ManifestKey].unshift(n5Deep100kManifestRow);
n5Deep100kIndex.objects[p6SummaryKey].unshift(n5Deep100kSummary);
const n5Deep100kRows = [{ ...p6HistoryRows[0], hash: manifestCoreHash(n5Deep100kManifest) }];
const n5Deep100kPicked = await loadPreviousResultVersionCandidates({
  sourceDir: p6EmergencyDir, index: n5Deep100kIndex, blockNum: p6Block,
  chain: p6EmergencyChain(n5Deep100kRows), emergencyLimits: true,
});
ok('R32-D-10-01: 深さ10万の非意味欄を持つ登録 manifest と summary は ready',
  n5Deep100kPicked.candidates.some((candidate) => candidate.status === 'ready'
    && candidate.summaryRow?.sha256 === n5Deep100kSummary.sha256));
const m11aBrokenPrevious = structuredClone(m2PrevIndex);
m11aBrokenPrevious.objects[p6ManifestKey][0].savedFile = m2PrevDeepRow.savedFile;
await rejects('M11a: 前ブロック manifest の sha256 事故も再取得を案内する',
  () => loadPreviousResultVersionCandidates({
    sourceDir: p6EmergencyDir, index: m11aBrokenPrevious, blockNum: p6Block,
    chain: p6EmergencyChain(m2PrevRows), includeOutsideWindow: true,
    groupingRosterHash: p6SuppliedRosterHash, emergencyLimits: true,
  }), /materialize-block/);
const m11aNormalBrokenManifest = structuredClone(p6Index);
m11aNormalBrokenManifest.objects[p6ManifestKey][0].savedFile = m2PrevDeepRow.savedFile;
await rejects('M11a: 通常の前ブロック manifest 読取は元の sha256 エラーを返す',
  () => loadPreviousResultVersionCandidates({
    sourceDir: p6EmergencyDir, index: m11aNormalBrokenManifest, blockNum: p6Block,
    chain: p6EmergencyChain(), includeOutsideWindow: true,
    groupingRosterHash: p6SuppliedRosterHash,
  }), /observer generation sha256 mismatch/);
const m11aBrokenSummary = structuredClone(p6Index);
m11aBrokenSummary.objects[p6SummaryKey][0].savedFile = m2PrevDeepRow.savedFile;
const m11aNormalSummary = await loadPreviousResultVersionCandidates({
  sourceDir: p6EmergencyDir, index: m11aBrokenSummary, blockNum: p6Block,
  chain: p6EmergencyChain(), includeOutsideWindow: true,
  groupingRosterHash: p6SuppliedRosterHash,
});
ok('M11a: 通常の前ブロック summary 読取は候補だけを unreadable にする',
  m11aNormalSummary.candidates.some((candidate) =>
    candidate.status === 'summary_unreadable'
      && /observer generation sha256 mismatch/.test(candidate.error)));
await rejects('M11a: 緊急の前ブロック summary 保存事故は再取得を案内する',
  () => loadPreviousResultVersionCandidates({
    sourceDir: p6EmergencyDir, index: m11aBrokenSummary, blockNum: p6Block,
    chain: p6EmergencyChain(), includeOutsideWindow: true,
    groupingRosterHash: p6SuppliedRosterHash, emergencyLimits: true,
  }), /materialize-block/);
await fs.writeFile(path.join(p6EmergencyDir, '_observer/generation-index.json'),
  JSON.stringify(m2PrevIndex));
const m11aHistoryDeepPicked = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir, chain: p6EmergencyChain(m2PrevRows), blockNum: p6Block,
});
ok('M11a: 履歴から前ブロック2鍵を選ぶ呼び元も深い manifest を外して差分を残す',
  m11aHistoryDeepPicked.fileMap.get(p6ManifestKey) === p6OldManifestRow.savedFile
  && m11aHistoryDeepPicked.differences.some((difference) =>
    difference.checkId === 'emergency.previousManifestGenerations'
      && difference.rebuilt?.unusableCandidates?.some((candidate) =>
        candidate.sha256 === m2PrevTooDeepManifestRow.sha256
        && candidate.reason === 'JSON depth limit')));
const m11aUnreadableOnly = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir,
  chain: p6EmergencyChain(m2PrevRows.slice(1, 3)), blockNum: p6Block,
}).catch((error) => error);
ok('M11a: 記録の行が履歴に無いなら未選択の読取不能候補を採らず止まる',
  m11aUnreadableOnly instanceof Error && /recorded previous/.test(m11aUnreadableOnly.message),
  String(m11aUnreadableOnly?.message));
await fs.writeFile(path.join(p6EmergencyDir, '_observer/generation-index.json'),
  JSON.stringify(p6Index));
ok('P6 R30-C-4-01 正: Nを組分け後に再登録しても、N+1の実際の組を再現する履歴行0を採る',
  p6HistoricalResolved.fileMap.get(p6ManifestKey) === p6OldManifestRow.savedFile
    && p6HistoricalResolved.fileMap.get(p6SummaryKey) === p6OldSummaryRow.savedFile
    && p6HistoricalResolved.previousResultRegistration?.selectedIndex === 0
    && p6HistoricalResolved.previousResultRegistration?.currentIndex === 1
    && p6HistoricalResolved.differences.some((difference) => (
      difference.checkId === 'emergency.previousResultVersionSelected'
        && difference.rebuilt?.selectedIndex === 0
        && difference.chain?.currentIndex === 1
    )),
  JSON.stringify({
    registration: p6HistoricalResolved.previousResultRegistration,
    differences: p6HistoricalResolved.differences,
  }));

const p12aEarlierReproducer = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir,
  chain: {
    ...p6EmergencyChain([p6HistoryRows[0], { ...p6HistoryRows[1], registeredAt: 120 }]),
    firstOtherRegistration: async () => ({ hash: `0x${'bb'.repeat(32)}`,
      registeredBlock: 30, registeredAt: 200 }),
  },
  blockNum: p6Block,
});
ok('P12a: 上限以前の最新行が別の組でも過去の再現行を選び直す',
  p12aEarlierReproducer.previousResultRegistration?.selectedIndex === 0
    && p12aEarlierReproducer.previousResultRegistration?.reproducingIndices?.includes(0)
    && p12aEarlierReproducer.differences.some((difference) => (
      difference.checkId === 'emergency.previousResultVersionSelected'
        && difference.rebuilt?.selectedIndex === 0
    )),
  JSON.stringify(p12aEarlierReproducer.previousResultRegistration));
const p12aDummies = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir,
  chain: {
    ...p6EmergencyChain([p6HistoryRows[0], ...Array.from({ length: 1_025 }, (_, i) => ({
      ...p6HistoryRows[1], index: i + 1, registeredAt: 120,
    }))]),
    firstOtherRegistration: async () => ({ hash: `0x${'bb'.repeat(32)}`,
      registeredBlock: 30, registeredAt: 200 }),
  },
  blockNum: p6Block,
});
ok('P12a: 上限以前の囮1025登録は正直な版の評価を妨げない',
  p12aDummies.previousResultRegistration?.selectedIndex === 0
    && p12aDummies.previousResultRegistration?.budgets?.evaluations?.used === 1,
  JSON.stringify(p12aDummies.previousResultRegistration?.budgets));

const p12aLargeHistory = await resolveEmergencyGenerationMap({
    sourceDir: p6EmergencyDir,
    chain: p6EmergencyChain(Array.from({ length: 8_193 }, (_, index) => ({
      ...p6HistoryRows[0], index,
    }))),
    blockNum: p6Block,
  });
ok('P13: 8193行の同一hashでも記録の行を採る',
  p12aLargeHistory.previousResultRegistration?.selectedIndex === 0
    && p12aLargeHistory.previousResultRegistration?.budgets?.evaluations?.used === 1,
  JSON.stringify(p12aLargeHistory.previousResultRegistration?.budgets));

for (const [label, decoyHash] of [
  ['same-hash', p6OldCore], ['junk-then-honest', `0x${'de'.repeat(32)}`],
]) {
  const rows = Array.from({ length: 20_000 }, (_, index) => ({
    index, hash: decoyHash, registeredBlock: 30, registeredAt: 100,
    signer: `0x${'a1'.repeat(20)}`,
  }));
  rows.push({ ...p6HistoryRows[0], index: rows.length, registeredAt: 200 });
  let stateReads = 0;
  let logReads = 0;
  const baseChain = p6EmergencyChain(rows);
  const chain = {
    ...baseChain,
    resultRegistrationAt: async (_block, index) => {
      stateReads++;
      return rows[index];
    },
    resultHashEvents: async () => {
      logReads++;
      return rows.map((row) => ({ hash: row.hash, updatedAt: row.registeredBlock,
        signer: row.signer, registrationCount: row.index + 1 }));
    },
  };
  await rejects(`P13: ${label} 20000行の囮で記録の行が違えば止まる`,
    () => resolveEmergencyGenerationMap({ sourceDir: p6EmergencyDir, chain, blockNum: p6Block }),
    /recorded previous/);
  ok(`P13: ${label} ログ照合の読取予算を維持する`, stateReads <= 30 && logReads === 1,
    JSON.stringify({ stateReads, logReads }));
}
{
  const rows = [
    { ...p6HistoryRows[0], index: 0 },
    { ...p6HistoryRows[1], index: 1 },
    { ...p6HistoryRows[1], index: 2, registeredAt: 500 },
  ];
  const logRows = rows.map((row) => ({ hash: row.hash,
    updatedAt: row.registeredBlock, signer: row.signer, registrationCount: row.index + 1 }));
  const honest = await resolveEmergencyGenerationMap({ sourceDir: p6EmergencyDir,
    chain: { ...p6EmergencyChain(rows), resultHashEvents: async () => logRows },
    blockNum: p6Block });
  ok('M9a: 複数hashの正直なログは保存された真の版を採る',
    honest.previousResultRegistration?.selectedIndex === 0);
  await rejects('M9a: 再現版が消えた失敗経路で非選択ログ行と状態の差を検出',
    () => resolveEmergencyGenerationMap({ sourceDir: p6EmergencyDir,
      chain: { ...p6EmergencyChain(rows), resultHashEvents: async () => logRows.map((row, index) =>
        index === 0 ? { ...row, hash: p6NewCore } : row) },
      blockNum: p6Block }),
    /differs from state row 0|do not cover eligible history/);
}
{
  const rows = Array.from({ length: 2_048 }, (_, index) => ({
    index, hash: `0x${(index + 1).toString(16).padStart(64, '0')}`,
    registeredBlock: 30, registeredAt: 100, signer: `0x${'a1'.repeat(20)}`,
  }));
  rows.push({ ...p6HistoryRows[0], index: rows.length, registeredAt: 200 });
  let stateReads = 0;
  const chain = { ...p6EmergencyChain(rows),
    resultRegistrationAt: async (_block, index) => { stateReads++; return rows[index]; },
    resultHashEvents: async () => rows.map((row) => ({ hash: row.hash,
      updatedAt: row.registeredBlock, signer: row.signer, registrationCount: row.index + 1 })),
  };
  await rejects('M9a: 異なる履歴行2048件でも記録との不一致を採らない',
    () => resolveEmergencyGenerationMap({ sourceDir: p6EmergencyDir, chain, blockNum: p6Block }),
    /recorded previous/);
  ok('M9a: 異なる履歴行2048件の状態読取予算を維持する', stateReads < 30,
    JSON.stringify({ stateReads }));
}

// LG1-LG4: event-log coverage and the chosen row's state binding are separate gates.
{
  const state = [100, 110, 200].map((registeredAt, index) => ({
    index, hash: `0x${String(index + 1).repeat(64)}`, registeredBlock: index + 10,
    registeredAt, signer: `0x${String(index + 1).repeat(40)}`,
  }));
  const logs = state.map((row) => ({ hash: row.hash, updatedAt: row.registeredBlock,
    signer: row.signer, registrationCount: row.index + 1 }));
  const probe = (events) => findResultRegistrationAtGrouping({
    resultRegistrationCount: async () => state.length,
    resultRegistrationAt: async (_block, index) => state[index],
    resultHashEvents: async () => events,
  }, 0, 150_000, true);
  const honest = await probe(logs);
  ok('LG 正: 完全なログと状態が一致すれば上限以前の最新行を採る',
    honest.selected?.index === 1 && honest.selected?.registeredAt === 110
      && honest.budget.eventRows === logs.length);
  const lowerBounded = await findResultRegistrationAtGrouping({
    resultRegistrationCount: async () => state.length,
    resultRegistrationAt: async (_block, index) => state[index],
    resultHashEvents: async () => logs,
  }, 0, 150_000, false, 115_000);
  ok('LG L1e/L2e: ログ経路でも応募終了時点の現在行より古い行を候補から外し時刻を埋める',
    lowerBounded.rows.length === 1 && lowerBounded.selected?.index === 1
      && lowerBounded.selected.registeredAt === 110);
  await rejects('LG1: ログ1行欠落は網羅検査で止まる',
    () => probe(logs.slice(1)), /do not cover eligible history/);
  await rejects('LG2: registrationCount のずれは網羅検査で止まる',
    () => probe(logs.map((row, index) => index === 1 ? { ...row, registrationCount: 1 } : row)),
    /do not cover eligible history/);
  await rejects('LG3: 最終行 hash の差し替えは網羅検査で止まる',
    () => probe(logs.map((row, index) => index === 2 ? { ...row, hash: `0x${'ee'.repeat(32)}` } : row)),
    /do not cover eligible history/);
  await rejects('LG4: 選択行 hash の差し替えは状態照合で止まる',
    () => probe(logs.map((row, index) => index === 1 ? { ...row, hash: `0x${'ee'.repeat(32)}` } : row)),
    /differs from state row/);
  await rejects('M9a LG4: 選択行 signer の差し替えは状態照合で止まる',
    () => probe(logs.map((row, index) => index === 1
      ? { ...row, signer: `0x${'ee'.repeat(20)}` } : row)),
    /differs from state row/);
  await rejects('M9a LG4: 選択行 registeredBlock の差し替えは状態照合で止まる',
    () => probe(logs.map((row, index) => index === 1
      ? { ...row, updatedAt: 99 } : row)),
    /differs from state row/);
  const boundaryState = [100, 130, 200].map((registeredAt, index) => ({
    ...state[index], registeredAt,
  }));
  const boundaryHistory = await findResultRegistrationAtGrouping({
    resultRegistrationCount: async () => boundaryState.length,
    resultRegistrationAt: async (_block, index) => boundaryState[index],
    resultHashEvents: async () => boundaryState.map((row) => ({ hash: row.hash,
      updatedAt: row.registeredBlock, signer: row.signer, registrationCount: row.index + 1 })),
  }, 0, 150_000, false, 130_000);
  ok('M9a LG: 応募終了ちょうどの行より前の旧版を候補から外す',
    boundaryHistory.rows.length === 1 && boundaryHistory.selected?.index === 1);
  const proofChain = (events) => ({
    resultRegistrationCount: async () => state.length,
    resultRegistrationAt: async (_block, index) => state[index],
    resultHashEvents: async () => events,
  });
  ok('LG GCP 正: 証明hashのログ行と状態が一致すれば添字を返す',
    await findGcpProofRegistration(proofChain(logs), 0, state[1].hash) === 1);
  ok('LG GCP 欠落: ログに無くても状態の逆順走査で登録行を見つける',
    await findGcpProofRegistration(proofChain(logs.filter((row) => row.hash !== state[1].hash)),
      0, state[1].hash) === 1);
  await rejects('LG GCP 偽ログ: 候補行のhashと状態が違えば止まる',
    () => findGcpProofRegistration(proofChain(logs.map((row, index) => index === 1
      ? { ...row, hash: state[0].hash } : row)), 0, state[0].hash),
    /differs from state row/);
}

const p6SameMajorManifest = {
  ...p6OldManifest,
  rules: { candidate: 'same-major-languages' },
};
const p6SameMajorManifestRow = await p6Save('same-major-manifest.bin', p6SameMajorManifest);
const p6SameMajorCore = manifestCoreHash(p6SameMajorManifest);
const p6SameMajorIndex = structuredClone(p6Index);
p6SameMajorIndex.objects[p6ManifestKey].push({
  ...p6SameMajorManifestRow,
  generation: 3,
  observationOrdinal: '00000001:00000003',
});
await fs.writeFile(
  path.join(p6EmergencyDir, '_observer/generation-index.json'),
  JSON.stringify(p6SameMajorIndex),
);
const p6SameMajorResolved = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir,
  chain: p6EmergencyChain([
    p6HistoryRows[0],
    {
      index: 1, hash: p6SameMajorCore, registeredBlock: 35, registeredAt: 310,
      signer: `0x${'a4'.repeat(20)}`,
    },
    { ...p6HistoryRows[1], index: 2 },
  ]),
  blockNum: p6Block,
});
const p6SameMajorDifference = p6SameMajorResolved.differences.find((difference) => (
  difference.checkId === 'emergency.previousResultVersionSelected'
));
ok('P6b: 締切前の同義候補があっても記録の行を採る',
  p6SameMajorResolved.previousResultRegistration?.selectedIndex === 0
    && JSON.stringify(p6SameMajorDifference?.rebuilt?.reproducingIndices) === '[0]'
    && p6SameMajorDifference?.chain?.upperMs === 325000
    && p6SameMajorDifference?.chain?.upperSource === 'chattingStart_fallback',
  JSON.stringify({
    registration: p6SameMajorResolved.previousResultRegistration,
    difference: p6SameMajorDifference,
  }));

const p12aAnchorChain = {
  ...p6EmergencyChain([
    p6HistoryRows[0],
    { index: 1, hash: p6SameMajorCore, registeredBlock: 35, registeredAt: 310,
      signer: `0x${'a4'.repeat(20)}` },
    { ...p6HistoryRows[1], index: 2 },
  ]),
  firstOtherRegistration: async () => ({ hash: `0x${'bb'.repeat(32)}`,
    registeredBlock: 34, registeredAt: 300 }),
};
const p12aAnchorResolved = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir, chain: p12aAnchorChain, blockNum: p6Block,
});
ok('P13: 保存された名簿世代が無い錨は上限に使わずchattingStartへ戻す',
  p12aAnchorResolved.previousResultRegistration?.selectedIndex === 0
    && p12aAnchorResolved.previousResultRegistration?.upperSource === 'chattingStart_fallback'
    && p12aAnchorResolved.previousResultRegistration?.upperMs === 325000,
  JSON.stringify(p12aAnchorResolved.previousResultRegistration));
const p12aEqualBoundary = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir,
  chain: { ...p12aAnchorChain, firstOtherRegistration: async () => ({
    hash: `0x${'bb'.repeat(32)}`, registeredBlock: 35, registeredAt: 310,
  }) }, blockNum: p6Block,
});
ok('P12a: 名簿錨時刻ちょうどの結果登録行があっても記録の行を採る',
  p12aEqualBoundary.previousResultRegistration?.selectedIndex === 0,
  JSON.stringify(p12aEqualBoundary.previousResultRegistration));

const p6OtherLangSummary = {
  ...p6OldSummary,
  groups: [
    ...p6OldSummary.groups,
    ...p6CompletedSummary(p6Prev, 'fr').groups.map((group) => ({ ...group, group_id: 1 })),
  ],
};
const p6OtherLangSummaryRow = await p6Save('other-lang-summary.bin', p6OtherLangSummary);
const p6OtherLangManifest = {
  ...p6OldManifest,
  rules: { candidate: 'different-major-languages' },
  files: { [p6SummaryKey]: p6OtherLangSummaryRow.sha256 },
};
const p6OtherLangManifestRow = await p6Save('other-lang-manifest.bin', p6OtherLangManifest);
const p6OtherLangCore = manifestCoreHash(p6OtherLangManifest);
const p6AmbiguousIndex = structuredClone(p6Index);
p6AmbiguousIndex.objects[p6ManifestKey].push({
  ...p6OtherLangManifestRow,
  generation: 3,
  observationOrdinal: '00000001:00000003',
});
p6AmbiguousIndex.objects[p6SummaryKey].push({
  ...p6OtherLangSummaryRow,
  generation: 3,
  observationOrdinal: '00000001:00000004',
});
await fs.writeFile(
  path.join(p6EmergencyDir, '_observer/generation-index.json'),
  JSON.stringify(p6AmbiguousIndex),
);
let p6AmbiguousResolved = null;
try {
  p6AmbiguousResolved = await resolveEmergencyGenerationMap({
    sourceDir: p6EmergencyDir,
    chain: p6EmergencyChain([
      p6HistoryRows[0],
      {
        index: 1, hash: p6OtherLangCore, registeredBlock: 35, registeredAt: 350,
        signer: `0x${'a5'.repeat(20)}`,
      },
      { ...p6HistoryRows[1], index: 2 },
    ]),
    blockNum: p6Block,
  });
} catch (error) { p6AmbiguousResolved = error; }
ok('P6b R30-U-4: 締切後の偽版が同じ組を再現しても正しいNを採る',
  p6AmbiguousResolved?.previousResultRegistration?.selectedIndex === 0
    && p6AmbiguousResolved?.differences?.some((difference) => (
      difference.checkId === 'emergency.previousResultVersionSelected'
        && difference.chain?.excludedAfterGrouping === 2
    )),
  JSON.stringify({
    registration: p6AmbiguousResolved?.previousResultRegistration,
    differences: p6AmbiguousResolved?.differences,
  }));
const p13SameGroupsOtherMajor = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir,
  chain: p6EmergencyChain([
    p6HistoryRows[0],
    { index: 1, hash: p6OtherLangCore, registeredBlock: 35, registeredAt: 310,
      signer: `0x${'a5'.repeat(20)}` },
    { ...p6HistoryRows[1], index: 2 },
  ]),
  blockNum: p6Block,
});
ok('P13: 同じ組でもN+1 summaryと主要言語が違う新しいNを採らない',
  p13SameGroupsOtherMajor.previousResultRegistration?.selectedIndex === 0
    && JSON.stringify(p13SameGroupsOtherMajor.previousResultRegistration?.majorLangs) === '["ja"]',
  JSON.stringify(p13SameGroupsOtherMajor.previousResultRegistration));
await fs.writeFile(
  path.join(p6EmergencyDir, '_observer/generation-index.json'),
  JSON.stringify(p6Index),
);

const p6DecoyRows = Array.from({ length: 96 }, (_, index) => ({
  index,
  hash: `0x${(index + 1).toString(16).padStart(64, '0')}`,
  registeredBlock: index + 1,
  registeredAt: index + 1,
  signer: `0x${'b1'.repeat(20)}`,
}));
const p6BudgetHistory = [
  ...p6DecoyRows,
  { ...p6HistoryRows[0], index: 96 },
  { ...p6HistoryRows[1], index: 97 },
];
await rejects('P6: 囮96登録の後の正直な行でも記録の行と違えば止まる',
  () => resolveEmergencyGenerationMap({
    sourceDir: p6EmergencyDir,
    chain: p6EmergencyChain(p6BudgetHistory),
    blockNum: p6Block,
  }), /recorded previous/);

let p6HistoryLarge = null;
let p6HistoryRowsRead = 0;
try {
  const rows = Array.from({ length: 1102 }, (_, index) => ({
    index, hash: index === 0 ? p6OldCore : p6NewCore,
    registeredAt: index === 0 ? 300 : 400 + index,
  }));
  p6HistoryLarge = await loadPreviousResultVersionCandidates({
    sourceDir: p6EmergencyDir,
    index: p6Index,
    blockNum: p6Block,
    chain: {
      getResultHash: p6EmergencyChain().getResultHash,
      getTimingConstants: p6EmergencyChain().getTimingConstants,
      currentGrace: p6EmergencyChain().currentGrace,
      resultRegistrationCount: async () => rows.length,
      resultRegistrationAt: async (_b, i) => { p6HistoryRowsRead++; return rows[i]; },
    },
  });
} catch (error) { p6HistoryLarge = error; }
ok('P6b R30-U-4: 1102行でも二分探索で締切前の正しい行を選ぶ',
  p6HistoryLarge?.candidates?.[0]?.registration?.index === 0
    && p6HistoryRowsRead < 20
    && p6HistoryLarge?.history?.excludedAfterGrouping === 1101,
  JSON.stringify({ read: p6HistoryRowsRead, selected: p6HistoryLarge?.candidates?.[0]?.registration,
    error: p6HistoryLarge?.message }));

for (const count of [1025, 1102]) {
  const historyRows = [p6HistoryRows[0],
    ...Array.from({ length: count - 2 }, (_, i) => ({
      index: i + 1, hash: `0x${(i + 1).toString(16).padStart(64, '0')}`,
      registeredBlock: 400 + i, registeredAt: 400 + i,
      signer: `0x${'b1'.repeat(20)}`,
    })),
    { ...p6HistoryRows[1], index: count - 1, registeredAt: 2000 }];
  let resolved = null;
  try {
    resolved = await resolveEmergencyGenerationMap({
      sourceDir: p6EmergencyDir, chain: p6EmergencyChain(historyRows), blockNum: p6Block,
    });
  } catch (error) { resolved = error; }
  ok(`P6b R30-U-4: 緊急固定一式は履歴${count}行でも正しいNを採る`,
    resolved?.previousResultRegistration?.selectedIndex === 0
      && resolved?.fileMap?.get(p6SummaryKey) === p6OldSummaryRow.savedFile
      && resolved?.differences?.some((difference) => (
        difference.checkId === 'emergency.previousResultVersionSelected'
          && difference.chain?.excludedAfterGrouping === count - 1
      )),
    JSON.stringify({ registration: resolved?.previousResultRegistration,
      error: resolved?.message }));
}

let p6NoBeforeDeadline = null;
try {
  p6NoBeforeDeadline = await resolveEmergencyGenerationMap({
    sourceDir: p6EmergencyDir,
    chain: p6EmergencyChain([
      { ...p6HistoryRows[0], registeredAt: 400 },
      { ...p6HistoryRows[1], registeredAt: 500 },
    ]),
    blockNum: p6Block,
  });
} catch (error) { p6NoBeforeDeadline = error; }
ok('M11b UJ1: 窓内に結果行が無ければ後から登録した F を採らない',
  p6NoBeforeDeadline instanceof Error
    && /recorded previous registration is invalid or after grouping bound/.test(p6NoBeforeDeadline.message),
  JSON.stringify({ message: p6NoBeforeDeadline?.message,
    registration: p6NoBeforeDeadline?.previousResultRegistration }));

// P14: production chain.js reader, saved roster hash, and both sides of the
// exact timestamp boundary. The old firstOtherRegistration mock cannot cover this.
const p14RosterKey = `games/block${p6Block}/roster/manifest.json`;
const p14RosterRow = await p6Save('p14-roster-manifest.bin', {
  blockNum: p6Block, indexSha256: 'ab'.repeat(32), groups: [],
});
const p14RosterHash = keccak256(await fs.readFile(path.join(p6EmergencyDir, p14RosterRow.savedFile)));
const p14Index = structuredClone(p6Index);
p14Index.objects[p14RosterKey] = [{ ...p14RosterRow, generation: 1,
  observationOrdinal: '00000003:00000000' }];
const p14LiveReader = createChain({ rpcUrls: ['http://127.0.0.1:1'], chainIdExpected: 31337,
  contracts: { hashStorage: `0x${'44'.repeat(20)}` } });
async function p14WindowCase(rosterRows, chattingStartSec, resultAtSec = 300) {
  const rosterKey = keccak256(stringToHex(`bitcoinu:roster:${p6Block}`));
  const calls = [];
  p14LiveReader.client.readContract = async ({ functionName, args }) => {
    calls.push({ functionName, args });
    if (functionName === 'otherRegistrationCount') return BigInt(rosterRows.length);
    if (functionName === 'otherRegistrationAt') {
      const row = rosterRows[Number(args[1])];
      return [row.hash, BigInt(row.block), BigInt(row.at)];
    }
    throw new Error(`unexpected chain getter ${functionName}`);
  };
  const chain = {
    ...p6EmergencyChain([{ ...p6HistoryRows[0], registeredAt: resultAtSec }]),
    getOtherHash: async () => ({ hash: p14RosterHash, updated: 99 }),
    currentGrace: async () => chattingStartSec - 5,
    otherRegistrationCount: p14LiveReader.otherRegistrationCount,
    otherRegistrationAt: p14LiveReader.otherRegistrationAt,
    firstMatchingOtherRegistration: p14LiveReader.firstMatchingOtherRegistration,
  };
  const versions = await loadPreviousResultVersionCandidates({
    sourceDir: p6EmergencyDir, index: p14Index, chain, blockNum: p6Block,
    includeOutsideWindow: true,
  });
  return { versions, calls, rosterKey };
}
const p14LateChat = await p14WindowCase([{ hash: p14RosterHash, block: 31, at: 305 }], 270)
  .catch((error) => error);
ok('M9a: 開始後だけの名簿登録は正典を作らず緊急の名簿選択を停止',
  p14LateChat instanceof Error && /canonical HashStorage roster manifest marker is absent/.test(p14LateChat.message));
const p14Preregistered = await p14WindowCase([
  { hash: p14RosterHash, block: 30, at: 260 },
  { hash: p14RosterHash, block: 32, at: 305 },
], 450);
ok('P14: 応募終了後の一致hash先回りでもNを窓外候補へ残す',
  p14Preregistered.versions.groupingTime.upperMs === 260000
    && p14Preregistered.versions.groupingTime.source === 'matching_roster_anchor_registration'
    && p14Preregistered.versions.candidates[0]?.status === 'ready'
    && p14Preregistered.versions.history.excludedAfterGrouping === 1,
  JSON.stringify(p14Preregistered.versions.groupingTime));
const p14Equal = await p14WindowCase([{ hash: p14RosterHash, block: 31, at: 300 }], 450);
ok('P14: 実chain readerの名簿錨時刻ちょうどの結果登録は優先窓へ含む',
  p14Equal.versions.groupingTime.upperMs === 300000
    && p14Equal.versions.history.excludedAfterGrouping === 0
    && p14Equal.versions.candidates[0]?.registration.index === 0,
  JSON.stringify(p14Equal.versions.groupingTime));
const p15WrongThenRight = await p14WindowCase([
  { hash: `0x${'ef'.repeat(32)}`, block: 30, at: 260 },
  { hash: p14RosterHash, block: 31, at: 300 },
], 450, 280);
ok('P15: 実chain readerは先行する別hashを飛ばして保存名簿hashの錨を選ぶ',
  p15WrongThenRight.versions.groupingTime.upperMs === 300000
    && p15WrongThenRight.versions.history.excludedAfterGrouping === 0,
  JSON.stringify(p15WrongThenRight.versions.groupingTime));
const p15AtEntryEnd = await p14WindowCase([
  { hash: p14RosterHash, block: 30, at: 5 },
  { hash: p14RosterHash, block: 31, at: 300 },
], 450, 280);
ok('P15: 実chain readerのearliestAt等号は最初の適格錨に含む',
  p15AtEntryEnd.versions.groupingTime.upperMs === 5000
    && p15AtEntryEnd.versions.history.excludedAfterGrouping === 1,
  JSON.stringify(p15AtEntryEnd.versions.groupingTime));
const p15BeforeEntryEnd = await p14WindowCase([
  { hash: p14RosterHash, block: 29, at: 4 },
  { hash: p14RosterHash, block: 31, at: 300 },
], 450, 280);
ok('P15: 実chain readerはearliestAtより前の一致錨を使わない',
  p15BeforeEntryEnd.versions.groupingTime.upperMs === 300000
    && p15BeforeEntryEnd.versions.history.excludedAfterGrouping === 0,
  JSON.stringify(p15BeforeEntryEnd.versions.groupingTime));

// A saved false group predates grouping, while the false N result is registered
// after it. The GCP entrance must exhaust all group generations with the honest
// in-window N before letting the late N version reproduce the false group.
const p15Block = 4;
const p15Prev = 3;
const p15Timing = { startTimeEntryMs: 0, blockTimeMs: 50_000,
  gamePeriodMs: 1000, submitPeriodMs: 1000 };
const p15Pins = { gameMaxPlayers: 2100, confirmationBlocks: 64 };
let p15Ordinal = 0;
async function p15Save(label, data) {
  const raw = typeof data === 'string' ? data : JSON.stringify(data);
  const row = await save(`p15-gcp/${label}.bin`, raw);
  return { ...row, bytes: Buffer.byteLength(raw), generation: ++p15Ordinal,
    observationOrdinal: `${String(p15Ordinal).padStart(8, '0')}:00000000` };
}
const p15Entries = Array.from({ length: 10 }, (_, i) => ({
  uid: `p15-u${i}`, lang: i === 9 ? 'en' : 'ja',
  addr: `0x${(i + 101).toString(16).padStart(40, '0')}`,
}));
const p15ApplicantRows = [];
for (let worker = 0; worker < 100; worker++) {
  const key = `entries/block4/info/${String(worker).padStart(2, '0')}_info.json`;
  p15ApplicantRows.push({ key, row: await p15Save(`info-${worker}`, {
    entries: worker === 0 ? [{ filename: 'p15-f0', number: 10 }] : [],
  }) });
}
p15ApplicantRows.push({ key: 'entries/block4/entries/p15-f0.json',
  row: await p15Save('entries', p15Entries) });
const p15ApplicantHash = `0x${'62'.repeat(32)}`;
const p15Target = { mixHash: `0x${'61'.repeat(32)}`, hash: `0x${'71'.repeat(32)}` };
const p15Indices = await selectWinners(keccak256(concat([p15Target.mixHash, p15ApplicantHash])), 10, 10);
const p15Players = p15Indices.map((globalIndex) => ({ globalIndex,
  localIndex: globalIndex, file: 'p15-f0', data: p15Entries[globalIndex] }))
  .sort((a, b) => a.globalIndex - b.globalIndex);
const p15Selection = { applicantHash: p15ApplicantHash, hashRegisteredBlock: 100,
  confirmationBlocks: 64, targetBlockNum: 164, entryPeriodEnd: 250000,
  totalEntries: 10, totalSelected: 10, targetBlockHash: p15Target.hash,
  randao: p15Target.mixHash, players: p15Players };
const p15PreviousSummaryKey = 'games/block3/summary.json';
const p15PreviousManifestKey = 'verification/block3/manifest.json';
const p15PrevSummary = (count) => ({ schemaVersion: 2, blockNum: p15Prev,
  groups: [{ group_id: 0, status: 'completed', members: Array.from({ length: count }, (_, i) => ({
    userId: `p15-old-${i}`, lang: 'ja', is_disqualified: 0,
  })) }] });
const p15HonestPrevious = await p15Save('previous-honest', p15PrevSummary(200));
const p15FalsePrevious = await p15Save('previous-false', p15PrevSummary(150));
const p15HonestManifest = { blockNum: p15Prev, algorithm: 'sha256', rules: {},
  files: { [p15PreviousSummaryKey]: p15HonestPrevious.sha256 } };
const p15FalseManifest = { blockNum: p15Prev, algorithm: 'sha256', rules: { fake: true },
  files: { [p15PreviousSummaryKey]: p15FalsePrevious.sha256 } };
const p15HonestManifestRow = await p15Save('manifest-honest', p15HonestManifest);
const p15FalseManifestRow = await p15Save('manifest-false', p15FalseManifest);
async function p15MajorLangs(summary) {
  const calculator = new GameMasterDO({ storage: {} }, {});
  calculator.getR2Object = async (key) => key === p15PreviousSummaryKey ? summary : null;
  return calculator.computeMajorLangs(p15Block);
}
const p15HonestLangs = await p15MajorLangs(p15PrevSummary(200));
const p15FalseLangs = await p15MajorLangs(p15PrevSummary(150));
const p15Gm = new GameMasterDO({ storage: {} }, {});
const p15GroupSeed = keccak256(concatHex([
  p15Selection.randao, p15Selection.applicantHash, stringToHex('group'),
]));
const p15HonestGroups = await p15Gm.formGroups(p15Players, p15GroupSeed, p15HonestLangs);
const p15FalseGroups = await p15Gm.formGroups(p15Players, p15GroupSeed, p15FalseLangs);
const p15HonestGroupRow = await p15Save('groups-honest',
  p15Gm.createGroupSummary(p15Block, p15HonestGroups, p15Selection));
const p15FalseGroupRow = await p15Save('groups-false',
  p15Gm.createGroupSummary(p15Block, p15FalseGroups, p15Selection));
const p15Declared = computeDeclaredTimesMs({ startTimeMs: 0, blockTimeMs: 50_000,
  gamePeriodMs: 1000, submitPeriodMs: 1000, confirmations: 64 }, p15Block, 20);
const p15Timeline = { graceSec: 20, chattingStart: p15Declared.chattingStart,
  submittingStart: p15Declared.submittingStart, closeAt: p15Declared.closeAt,
  completedAt: p15Declared.completedAt };
const p15CurrentSummary = (groups, langs) => ({
  ...p15Gm.buildBlockSummaryForR2(p15Block, groups, langs), majorLangs: langs,
  timeline: p15Timeline,
});
const p15HonestCurrentRow = await p15Save('summary-honest',
  p15CurrentSummary(p15HonestGroups, p15HonestLangs));
const p15FalseCurrentRow = await p15Save('summary-false',
  p15CurrentSummary(p15FalseGroups, p15FalseLangs));
const p15RosterPayloads = reconstructCanonicalRosterPayloads(p15Block, p15HonestGroups);
const p15RosterRow = await p15Save('roster', p15RosterPayloads.manifestText);
const p15RosterGroupRows = [];
for (const [groupId, groupText] of p15RosterPayloads.groupTexts) {
  p15RosterGroupRows.push([`games/block${p15Block}/roster/group${groupId}.json`,
    await p15Save(`roster-group-${groupId}`, groupText)]);
}
const p15RosterHash = buildRosterMemberCommitment({ blockNum: p15Block,
  manifestText: p15RosterPayloads.manifestText,
  groupTexts: p15RosterPayloads.groupTexts }).C;
const p15GcpIndex = { kind: 'r2-backup-observer-block-archive', complete: true,
  blockNum: p15Block, objects: {
    'entries/block4/game_selection.json': [await p15Save('selection', p15Selection)],
    'entries/block4/game_groups.json': [
      { ...p15FalseGroupRow, observationOrdinal: '00000001:00000000' },
      { ...p15HonestGroupRow, observationOrdinal: '00000002:00000000' },
    ],
    'games/block4/summary.json': [
      { ...p15HonestCurrentRow, observationOrdinal: '00000001:00000001' },
      { ...p15FalseCurrentRow, observationOrdinal: '00000003:00000000' },
    ],
    'games/block4/roster/manifest.json': [p15RosterRow],
    ...Object.fromEntries(p15RosterGroupRows.map(([key,row]) => [key,[row]])),
    [p15PreviousManifestKey]: [p15HonestManifestRow, p15FalseManifestRow],
    [p15PreviousSummaryKey]: [p15HonestPrevious, p15FalsePrevious],
  } };
const p15HonestCore = manifestCoreHash(p15HonestManifest);
const p15FalseCore = manifestCoreHash(p15FalseManifest);
async function p15GcpCase(rows, rosterAt, {
  candidateIndex = p15GcpIndex, anchorHash = p15RosterHash, noAnchor = false,
  rosterRows = null, metrics = null, rosterReadError = null,
} = {}) {
  const latest = rows.at(-1);
  const registrations = rosterRows ?? (noAnchor ? [] : [{ hash: anchorHash,
    registeredBlock: rosterAt, registeredAt: rosterAt }]);
  const chain = {
    getTimingConstants: async () => p15Timing,
    getBlock: async () => p15Target,
    chatWindow: async () => ({ chatOpenAt: 250, chatCloseAt: 271 }),
    currentGrace: async () => 20,
    getResultHash: async () => ({ hash: latest.hash, updated: latest.registeredBlock,
      signer: latest.signer }),
    resultRegistrationCount: async () => rows.length,
    resultRegistrationAt: async (_block, index) => rows[index],
    resultRegistrationHistory: async () => ({ count: rows.length, rows }),
    getOtherHash: async () => ({ hash: anchorHash, updated: rosterAt }),
    otherRegistrationCount: async () => { if (metrics) metrics.otherReads++;
      if (rosterReadError) throw rosterReadError;
      return registrations.length; },
    otherRegistrationAt: async (_key, index) => registrations[index],
    firstMatchingOtherRegistration: async () => noAnchor ? null : ({ hash: anchorHash,
      registeredBlock: rosterAt, registeredAt: rosterAt, index: 0 }),
  };
  const differences = [];
  const readFile = fs.readFile;
  const rosterFiles = new Set((candidateIndex.objects['games/block4/roster/manifest.json'] || [])
    .map((row) => path.resolve(taskTmp, row.savedFile)));
  if (metrics) fs.readFile = async (...args) => {
    if (rosterFiles.has(path.resolve(String(args[0])))) metrics.manifestReads++;
    return readFile(...args);
  };
  try {
    const result = await selectGcpGroupGameInputs({ sourceDir: taskTmp, index: candidateIndex,
      chain, blockNum: p15Block, applicant: { rows: p15ApplicantRows,
        registration: { hash: p15ApplicantHash, registeredBlock: 100, index: 0 } },
      pins: p15Pins, differences });
    return { ...result, differences };
  } finally { if (metrics) fs.readFile = readFile; }
}
const p15Signer = `0x${'a1'.repeat(20)}`;
const p15HistoryRow = (index, hash, registeredAt) => ({ index, hash, registeredAt,
  registeredBlock: registeredAt, signer: p15Signer });
const n5GcpNoRosterIndex = structuredClone(p15GcpIndex);
delete n5GcpNoRosterIndex.objects['games/block4/roster/manifest.json'];
const n5GcpCanonicalText = reconstructCanonicalRosterPayloads(p15Block, p15HonestGroups).manifestText;
const n5GcpNoRoster = await p15GcpCase([
  p15HistoryRow(0, p15HonestCore, 200),
], 255, { candidateIndex: n5GcpNoRosterIndex,
  anchorHash: p15RosterHash }).catch((error) => error);
ok('N5 GCP: 名簿0世代でも game_groups からの keccak 一致で正典 pin を採る',
  !(n5GcpNoRoster instanceof Error)
  && n5GcpNoRoster.roster?.origin === 'reconstructed'
  && n5GcpNoRoster.roster.manifestText === n5GcpCanonicalText);
const n5GcpRpcFailure = await p15GcpCase([
  p15HistoryRow(0, p15HonestCore, 200),
], 255, { candidateIndex: n5GcpNoRosterIndex,
  rosterReadError: Object.assign(new Error('RPC -32005'), { code: -32005 }),
}).catch((error) => error);
ok('N5 GCP: 名簿登録の RPC -32005 は timeline no-game に畳まず停止',
  n5GcpRpcFailure instanceof Error
  && /RPC -32005/.test(n5GcpRpcFailure.message)
  && !/timeline no-game/.test(n5GcpRpcFailure.message));
const n5GcpBrokenDecoyIndex = structuredClone(p15GcpIndex);
n5GcpBrokenDecoyIndex.objects['games/block4/roster/manifest.json'].unshift({
  ...p15RosterRow, savedFile: '_observer/generations/n5-broken-roster-decoy.bin',
  observationOrdinal: '00000000:00000000',
});
const n5GcpBrokenDecoy = await p15GcpCase([
  p15HistoryRow(0, p15HonestCore, 200),
], 255, { candidateIndex: n5GcpBrokenDecoyIndex }).catch((error) => error);
ok('R32-C-1b-04: GCP の非正典破損名簿世代は前ブロック選択を止めない',
  !(n5GcpBrokenDecoy instanceof Error)
  && n5GcpBrokenDecoy.groups?.row.sha256 === p15HonestGroupRow.sha256);
const m11aGcpDeepManifestRow = await p15Save('m11a-deep-previous-manifest',
  '{"blockNum":3,"algorithm":"sha256","rules":'
    + '['.repeat(20000) + '0' + ']'.repeat(20000) + ',"files":{}}');
const m11aGcpDeepIndex = structuredClone(p15GcpIndex);
m11aGcpDeepIndex.objects[p15PreviousManifestKey].unshift(m11aGcpDeepManifestRow);
const m11aGcpDeepPicked = await p15GcpCase([
  p15HistoryRow(0, p15HonestCore, 200),
], 255, { candidateIndex: m11aGcpDeepIndex });
ok('M11a: GCP入口の前ブロック履歴も深い manifest を外して差分を残す',
  m11aGcpDeepPicked.groups?.row.savedFile === p15HonestGroupRow.savedFile
    && m11aGcpDeepPicked.differences.some((difference) =>
      difference.checkId === 'emergency.previousManifestGenerations'
        && difference.rebuilt?.unusableCandidates?.some((candidate) =>
          candidate.sha256 === m11aGcpDeepManifestRow.sha256
          && candidate.reason === 'JSON depth limit')));
const p15EarlyFalse = await p15GcpCase([
  p15HistoryRow(0, p15HonestCore, 200), p15HistoryRow(1, p15FalseCore, 400),
], 255);
ok('P15: GCP は窓内の正直な組世代を窓外の偽版より先に採る',
  p15EarlyFalse.groups?.row.savedFile === p15HonestGroupRow.savedFile
    && JSON.stringify(p15EarlyFalse.majorLangs) === JSON.stringify(p15HonestLangs),
  JSON.stringify({ group: p15EarlyFalse.groups?.row.savedFile,
    majorLangs: p15EarlyFalse.majorLangs }));
const p15XHash = `0x${'ab'.repeat(32)}`;
const p15R31Last = await p15GcpCase([
  p15HistoryRow(0, p15HonestCore, 200), p15HistoryRow(1, p15FalseCore, 400),
], 255, { rosterRows: [
  { hash: p15XHash, registeredBlock: 255, registeredAt: 255 },
  { hash: p15RosterHash, registeredBlock: 260, registeredAt: 260 },
] });
ok('M9a: GCP入口はXの後のHを開始前正典として採る',
  p15R31Last.groups.row.savedFile === p15HonestGroupRow.savedFile
    && p15R31Last.differences.some((d) => d.checkId === 'emergency.gcpGroupsGeneration'
      && d.chain?.rosterAnchorHash === p15RosterHash));
const p15R31Missing = await p15GcpCase([
  p15HistoryRow(0, p15HonestCore, 200), p15HistoryRow(1, p15FalseCore, 400),
], 255, { rosterRows: [
  { hash: p15RosterHash, registeredBlock: 255, registeredAt: 255 },
  { hash: p15XHash, registeredBlock: 260, registeredAt: 260 },
] }).catch((error) => error);
ok('M9a: Hの後のXを保存世代から再現できなければGCP入口が停止する',
  p15R31Missing instanceof Error
    && /index=1.*hash=0xabab.*generations=1/.test(p15R31Missing.message));
const m11bPinnedRosterRow = await p15Save('m11b-pinned-roster', {
  blockNum: p15Block, indexSha256: reconstructedRosterIndexSha256(p15HonestGroups),
  groups: p15HonestGroups.map((group) => ({ groupId: group.groupId,
    sha256: reconstructedRosterGroupSha256(p15Block, group) })),
});
const m11bPinnedRosterHash = buildRosterMemberCommitment({ blockNum: p15Block,
  manifestText: await fs.readFile(path.join(taskTmp, m11bPinnedRosterRow.savedFile), 'utf8'),
  groupTexts: p15RosterPayloads.groupTexts }).C;
const m11bLostPreviousIndex = structuredClone(p15GcpIndex);
m11bLostPreviousIndex.objects['games/block4/roster/manifest.json'] = [m11bPinnedRosterRow];
m11bLostPreviousIndex.objects[p15PreviousManifestKey] = [];
m11bLostPreviousIndex.objects[p15PreviousSummaryKey] = [];
const m11bLostPrevious = await p15GcpCase([
  p15HistoryRow(0, p15HonestCore, 200), p15HistoryRow(1, p15FalseCore, 400),
], 255, { candidateIndex: m11bLostPreviousIndex, anchorHash: m11bPinnedRosterHash });
ok('M11b UJ1: 窓内の N summary が消失しても正典名簿と宣言言語で進み差分を残す',
  m11bLostPrevious.previousMajorLangsUnverifiable === true
    && m11bLostPrevious.groups?.row.sha256 === p15HonestGroupRow.sha256
    && isDeepStrictEqual(m11bLostPrevious.majorLangs, p15HonestLangs)
    && m11bLostPrevious.differences.some((difference) =>
      difference.checkId === 'emergency.previousSummaryLost'));
const n6J1LostIndex = { ...m11bLostPreviousIndex, lineageCheckBypassed: true,
  laterSavedGenerations: [{ key: p15PreviousManifestKey, ...p15HonestManifestRow }] };
const n6J1Lost = await p15GcpCase([
  p15HistoryRow(0, p15HonestCore, 200), p15HistoryRow(1, p15FalseCore, 400),
], 255, { candidateIndex: n6J1LostIndex, anchorHash: m11bPinnedRosterHash });
ok('N6 J1: GCP 消失差分は書き出しに無い版と後の保管庫の保存を区別する',
  n6J1Lost.previousMajorLangsUnverifiable === true
    && n6J1Lost.differences.some(difference =>
      difference.checkId === 'emergency.previousSummaryLost'
      && difference.what.includes('this --manifest archive')
      && difference.what.includes('later saved N versions')));
ok('N6 J1: 既定の消失差分の文面は変えない',
  m11bLostPrevious.differences.some(difference =>
    difference.checkId === 'emergency.previousSummaryLost'
    && difference.what === 'the N summary used by N+1 grouping is absent from the observer archive'));
const n5RosterBudgetIndex = structuredClone(m11bLostPreviousIndex);
for (let variant = 0; variant < 3; variant++) {
  const row = await p15Save(`n5-roster-decoy-${variant}`, {
    blockNum: p15Block, indexSha256: `${variant}`.padStart(64, '0'), groups: [],
  });
  n5RosterBudgetIndex.objects['games/block4/roster/manifest.json'].unshift(row);
}
const n5RosterReadsOne = { otherReads: 0, manifestReads: 0 };
await p15GcpCase([p15HistoryRow(0, p15HonestCore, 200)], 255, {
  candidateIndex: n5RosterBudgetIndex, anchorHash: m11bPinnedRosterHash,
  metrics: n5RosterReadsOne,
});
const n5ManyGroupsIndex = structuredClone(n5RosterBudgetIndex);
for (let variant = 0; variant < 5; variant++) {
  const row = await p15Save(`n5-decoy-groups-${variant}`,
    { ...p15Gm.createGroupSummary(p15Block, p15FalseGroups, p15Selection), decoy: variant });
  n5ManyGroupsIndex.objects['entries/block4/game_groups.json'].unshift({
    ...row, observationOrdinal: `00000000:0000000${variant}`,
  });
}
const n5RosterReadsMany = { otherReads: 0, manifestReads: 0 };
await p15GcpCase([p15HistoryRow(0, p15HonestCore, 200)], 255, {
  candidateIndex: n5ManyGroupsIndex, anchorHash: m11bPinnedRosterHash,
  metrics: n5RosterReadsMany,
});
console.log(`N5 roster reads: G=2,R=4 ${JSON.stringify(n5RosterReadsOne)}; `
  + `G=7,R=4 ${JSON.stringify(n5RosterReadsMany)}`);
ok('R32-C-1b-03: GCP 消失枝の名簿登録 RPC 回数は game_groups 世代数に比例しない',
  n5RosterReadsOne.otherReads > 0
  && n5RosterReadsMany.otherReads === n5RosterReadsOne.otherReads);
ok('R32-C-1b-03: GCP 消失枝の名簿 manifest 読取回数も game_groups 世代数に比例しない',
  n5RosterReadsOne.manifestReads > 0
  && n5RosterReadsMany.manifestReads === n5RosterReadsOne.manifestReads);
const n5GcpSummaryOnlyIndex = structuredClone(m11bLostPreviousIndex);
n5GcpSummaryOnlyIndex.objects[p15PreviousManifestKey] = [p15HonestManifestRow];
const n5GcpSummaryOnly = await p15GcpCase([
  p15HistoryRow(0, p15HonestCore, 200),
], 255, { candidateIndex: n5GcpSummaryOnlyIndex,
  anchorHash: m11bPinnedRosterHash }).catch((error) => error);
ok('R32-C-1-04: GCP 入口で manifest 保存・summary だけ欠落も消失差分へ入る',
  !(n5GcpSummaryOnly instanceof Error)
  && n5GcpSummaryOnly.previousMissingVersions?.some((row) =>
    row.status === 'summary_generation_missing'));
const m14dFalseDeclarationIndex = structuredClone(m11bLostPreviousIndex);
m14dFalseDeclarationIndex.objects['games/block4/summary.json'] = [
  await p15Save('m14d-false-major-langs',
    p15CurrentSummary(p15HonestGroups, p15FalseLangs)),
];
const m14dFalseDeclaration = await p15GcpCase([
  p15HistoryRow(0, p15HonestCore, 200), p15HistoryRow(1, p15FalseCore, 400),
], 255, { candidateIndex: m14dFalseDeclarationIndex,
  anchorHash: m11bPinnedRosterHash }).catch((error) => error);
ok('M14d UJ1: 消失枝でも宣言主要言語が正典名簿の組を再現しなければ停止',
  m14dFalseDeclaration instanceof Error
    && /no saved generation reproduces Stage B/.test(m14dFalseDeclaration.message));
const m11cGcpMixedIndex = structuredClone(m11bLostPreviousIndex);
m11cGcpMixedIndex.objects[p15PreviousManifestKey] = [p15FalseManifestRow];
m11cGcpMixedIndex.objects[p15PreviousSummaryKey] = [p15FalsePrevious];
const m11cGcpMixed = await p15GcpCase([
  p15HistoryRow(0, p15FalseCore, 250), p15HistoryRow(1, p15HonestCore, 252),
], 255, { candidateIndex: m11cGcpMixedIndex, anchorHash: m11bPinnedRosterHash })
  .catch((error) => error);
ok('M11c: GCP の混在盤面は欠落版を列挙して正典名簿で進む',
  !(m11cGcpMixed instanceof Error)
    && m11cGcpMixed.previousMajorLangsUnverifiable === true
    && m11cGcpMixed.previousSavedMismatches?.some((row) =>
      row.index === 0 && row.hash === p15FalseCore)
    && m11cGcpMixed.differences.some((difference) =>
      difference.checkId === 'emergency.previousSummaryLost'
      && difference.chain?.missingVersions?.some((row) =>
        row.index === 1 && row.hash === p15HonestCore)
      && difference.chain?.savedMismatches?.some((row) =>
        row.index === 0 && row.hash === p15FalseCore)));
const m11cGcpReadyIndex = structuredClone(m11bLostPreviousIndex);
m11cGcpReadyIndex.objects[p15PreviousManifestKey] = [p15HonestManifestRow];
m11cGcpReadyIndex.objects[p15PreviousSummaryKey] = [p15HonestPrevious];
const m11cGcpReady = await p15GcpCase([
  p15HistoryRow(0, p15FalseCore, 250), p15HistoryRow(1, p15HonestCore, 252),
], 255, { candidateIndex: m11cGcpReadyIndex, anchorHash: m11bPinnedRosterHash });
ok('M11c: GCP は保存済み再現版があれば別の欠落版で消失扱いにしない',
  m11cGcpReady.previousMajorLangsUnverifiable === false
    && !m11cGcpReady.differences.some((difference) =>
      difference.checkId === 'emergency.previousSummaryLost'));
const m11cGcpAllSaved = await p15GcpCase([
  p15HistoryRow(0, p15FalseCore, 250),
], 255, { candidateIndex: m11cGcpMixedIndex, anchorHash: m11bPinnedRosterHash })
  .catch((error) => error);
ok('M11c: GCP の保存済み不一致だけなら停止する',
  m11cGcpAllSaved instanceof Error
    && /no saved generation reproduces Stage B/.test(m11cGcpAllSaved.message));
const m11bBadRosterIndex = structuredClone(m11bLostPreviousIndex);
const m11bBadRosterGroups = structuredClone(p15HonestGroups);
m11bBadRosterGroups[0].members[0].data.uid = 'not-selected-member';
const m11bBadRosterPayloads = reconstructCanonicalRosterPayloads(p15Block, m11bBadRosterGroups);
const m11bBadRosterRow = await p15Save('m11b-bad-roster', m11bBadRosterPayloads.manifestText);
m11bBadRosterIndex.objects['games/block4/roster/manifest.json'] = [m11bBadRosterRow];
for (const [groupId, groupText] of m11bBadRosterPayloads.groupTexts) {
  m11bBadRosterIndex.objects[`games/block4/roster/group${groupId}.json`] = [
    await p15Save(`m11b-bad-roster-group-${groupId}`, groupText),
  ];
}
const m11bBadRosterHash = buildRosterMemberCommitment({ blockNum: p15Block,
  manifestText: m11bBadRosterPayloads.manifestText,
  groupTexts: m11bBadRosterPayloads.groupTexts }).C;
const m11bBadRoster = await p15GcpCase([
  p15HistoryRow(0, p15HonestCore, 200),
], 255, { candidateIndex: m11bBadRosterIndex, anchorHash: m11bBadRosterHash })
  .catch((error) => error);
ok('M11b UJ1: summary 消失でも正典名簿が組を裏づけなければ止まる',
  m11bBadRoster instanceof Error && /no saved generation reproduces Stage B/.test(m11bBadRoster.message),
  m11bBadRoster?.message);
const m11bPreserveSummary = await p15Save('m11b-preserve-summary', { blockNum: 4, groups: [] });
const m11bPreserveManifest = { blockNum: 4, algorithm: 'sha256', rules: {},
  files: { 'games/block4/summary.json': m11bPreserveSummary.sha256 } };
const m11bPreserveManifestRow = await p15Save('m11b-preserve-manifest', m11bPreserveManifest);
const m11bPreserveIndex = { objects: {
  'verification/block4/manifest.json': [m11bPreserveManifestRow],
  'games/block4/summary.json': [m11bPreserveSummary],
} };
const m11bPreserveHash = manifestCoreHash(m11bPreserveManifest);
const m11bNextRosterHash = `0x${'ab'.repeat(32)}`;
const m11bPreserveRows = [
  p15HistoryRow(0, m11bPreserveHash, 300),
  p15HistoryRow(1, p15FalseCore, 400),
];
const m11bPreserveChain = {
  getTimingConstants: async () => p15Timing,
  chatWindow: async () => ({ chatOpenAt: 300, chatCloseAt: 331 }),
  otherRegistrationCount: async () => 1,
  otherRegistrationAt: async () => ({ hash: m11bNextRosterHash,
    registeredBlock: 310, registeredAt: 310 }),
  resultRegistrationCount: async () => m11bPreserveRows.length,
  resultRegistrationAt: async (_block, row) => m11bPreserveRows[row],
};
const m11bPreserved = await inspectNextGroupingVersionPreservation({
  sourceDir: taskTmp, index: m11bPreserveIndex, chain: m11bPreserveChain, blockNum: 4,
});
ok('M11c: N+1 窓内版一覧は保存した2鍵の世代と添字・hashを示す',
  m11bPreserved?.versions?.length === 1
    && m11bPreserved.versions[0].saved === true
    && m11bPreserved.versions[0].index === 0
    && m11bPreserved.versions[0].hash === m11bPreserveHash
    && m11bPreserved.versions[0].manifestGeneration === m11bPreserveManifestRow.generation
    && m11bPreserved.versions[0].summaryGeneration === m11bPreserveSummary.generation);
const m11bUnpreservedIndex = structuredClone(m11bPreserveIndex);
m11bUnpreservedIndex.objects['games/block4/summary.json'] = [];
const m11bUnpreserved = await inspectNextGroupingVersionPreservation({
  sourceDir: taskTmp, index: m11bUnpreservedIndex, chain: m11bPreserveChain, blockNum: 4,
});
ok('M11c: 見張り役の N+1 用 summary が無い版を一覧で未保存と示す',
  m11bUnpreserved?.versions?.[0]?.saved === false
    && m11bUnpreserved.versions[0].index === 0);
const m11bEmptyOut = path.join(taskTmp, 'm11b-unpreserved-output');
await fs.mkdir(m11bEmptyOut, { recursive: true });
await fs.mkdir(path.join(taskTmp, 'verification/block4'), { recursive: true });
await fs.writeFile(path.join(taskTmp, 'verification/block4/manifest.json'),
  JSON.stringify(m11bPreserveManifest));
await fs.mkdir(path.join(taskTmp, 'games/block4'), { recursive: true });
await fs.writeFile(path.join(taskTmp, 'games/block4/summary.json'),
  JSON.stringify({ blockNum: 4, groups: [] }));
const m11bWriteBlocked = await writeEmergencyResultSet({
  ctx: { blockNum: 4, chain: m11bPreserveChain,
    report: { fact() {} }, ui: { println() {} }, data: {} },
  source: { sourceDir: taskTmp, index: m11bUnpreservedIndex }, outputDir: m11bEmptyOut,
}).catch((error) => error);
ok('M11c: R2 固定キーの窓内版が未保存なら書き出しの先頭で止める',
  m11bWriteBlocked instanceof Error
    && /run the observer manually/.test(m11bWriteBlocked.message)
    && (await fs.readdir(m11bEmptyOut)).length === 0);
await fs.rm(path.join(taskTmp, 'games/block4/summary.json'));
const m14dSummaryAlreadyLost = await inspectNextGroupingVersionPreservation({
  sourceDir: taskTmp, index: m11bUnpreservedIndex, chain: m11bPreserveChain, blockNum: 4,
});
ok('M14d UJ1: manifest が R2 に残っても summary が消失済みなら保存不能として進む',
  m14dSummaryAlreadyLost?.mustPreserve === false
    && m14dSummaryAlreadyLost.versions?.[0]?.manifestInR2 === true
    && m14dSummaryAlreadyLost.versions?.[0]?.summaryInR2 === false);
await fs.writeFile(path.join(taskTmp, 'verification/block4/manifest.json'),
  JSON.stringify({ ...m11bPreserveManifest, rules: { laterFixedSet: true } }));
const m11bR2LostLines = [];
const m11bR2LostFacts = [];
let m11bR2LostPrompted = false;
const m11bR2LostContinued = await writeEmergencyResultSet({
  ctx: { blockNum: 4, chain: m11bPreserveChain,
    report: { fact(...args) { m11bR2LostFacts.push(args); }, list: () => [] },
    ui: { println(line) { m11bR2LostLines.push(line); }, isInteractive: true,
      askYesNo: async (_key, _params, opts) => {
        m11bR2LostPrompted = opts.defaultValue === false;
        return true;
      } },
    data: {} },
  source: { sourceDir: taskTmp, index: m11bUnpreservedIndex, authority: 'gcp' },
  outputDir: m11bEmptyOut,
}).catch((error) => error);
ok('M11c: R2 固定キーに無い窓内版の欠落では上書き前停止も確認質問もしない',
  !m11bR2LostPrompted && m11bR2LostContinued instanceof Error
    && !/run the observer manually/.test(m11bR2LostContinued.message)
    && m11bR2LostLines.some((line) => line.startsWith('##NEXT_GROUPING_PREVIOUS_VERSION '))
    && !m11bR2LostLines.some((line) => line.startsWith('##NEXT_GROUPING_PREVIOUS_VERSION_R2_LOST '))
    && m11bR2LostFacts.some(([id, fact]) => id === 'emergencyNextGroupingVersionPreservation'
      && fact.versions?.[0]?.saved === false && fact.versions[0].inR2 === false)
    && (await fs.readdir(m11bEmptyOut)).length === 0);
await fs.rm(path.join(taskTmp, 'verification/block4/manifest.json'));
const m11cCurrentDir = path.join(taskTmp, 'm11c-r2-current');
await fs.mkdir(path.join(m11cCurrentDir, 'verification/block4'), { recursive: true });
const m11cUnobservedManifest = { ...m11bPreserveManifest, rules: { m11c: true } };
const m11cUnobservedCore = manifestCoreHash(m11cUnobservedManifest);
const m11cWindowRows = [
  p15HistoryRow(0, m11bPreserveHash, 300),
  p15HistoryRow(1, m11cUnobservedCore, 305),
];
const m11cWindowChain = { ...m11bPreserveChain,
  resultRegistrationCount: async () => m11cWindowRows.length,
  resultRegistrationAt: async (_block, row) => m11cWindowRows[row] };
await fs.writeFile(path.join(m11cCurrentDir, 'verification/block4/manifest.json'),
  JSON.stringify(m11cUnobservedManifest));
const m11cR2Unpreserved = await inspectNextGroupingVersionPreservation({
  sourceDir: taskTmp, index: m11bPreserveIndex, chain: m11cWindowChain,
  blockNum: 4, currentR2Dir: m11cCurrentDir,
});
ok('M11c: R2 固定キーの窓内版が未保存なら版一覧で印し上書き前に止める',
  m11cR2Unpreserved?.mustPreserve === true
    && m11cR2Unpreserved.versions?.some((row) => row.index === 1
      && row.hash === m11cUnobservedCore && row.saved === false && row.inR2 === true)
    && m11cR2Unpreserved.versions?.some((row) => row.index === 0
      && row.hash === m11bPreserveHash && row.saved === true && row.inR2 === false));
await fs.writeFile(path.join(m11cCurrentDir, 'verification/block4/manifest.json'),
  JSON.stringify(m11bPreserveManifest));
const m11cR2Other = await inspectNextGroupingVersionPreservation({
  sourceDir: taskTmp, index: m11bPreserveIndex, chain: m11cWindowChain,
  blockNum: 4, currentR2Dir: m11cCurrentDir,
});
ok('M11c: R2 に無い窓内版の欠落は表示だけで上書き前停止しない',
  m11cR2Other?.mustPreserve === false
    && m11cR2Other.versions?.some((row) => row.index === 1
      && row.saved === false && row.inR2 === false));

// WR-4-STOP-03: live N+1 game_groups.json is attacker-controlled during emergency export.
const wr4Rows = [p15HistoryRow(0, m11bPreserveHash, 300),
  p15HistoryRow(1, p15FalseCore, 305)];
const wr4Chain = { ...m11bPreserveChain,
  resultRegistrationCount: async () => wr4Rows.length,
  resultRegistrationAt: async (_block, row) => wr4Rows[row],
  getResultHash: async () => ({ hash: p15FalseCore, updated: 305 }) };
const wr4Record = (index) => ({ index: String(index),
  registeredBlock: String(wr4Rows[index].registeredBlock),
  registeredAt: String(wr4Rows[index].registeredAt), hash: wr4Rows[index].hash });
const wr4GroupsBytes = (record) => Buffer.from(JSON.stringify({ blockNum: 5,
  totalPlayers: 24, groups: [], prevResultRegistration: record }));
const wr4LiveFetch = (groups, manifest = null) => async (key) => ({
  bytes: key === 'entries/block5/game_groups.json' ? groups
    : key === 'verification/block4/manifest.json' ? manifest : null,
  url: `https://r2.example.invalid/${key}`, sha256: null,
});
async function wr4Inspect(groups, manifest = null) {
  return inspectNextGroupingVersionPreservation({ sourceDir: taskTmp,
    index: { objects: {} }, chain: wr4Chain, blockNum: 4,
    currentR2Fetch: wr4LiveFetch(groups, manifest),
  }).catch(error => error);
}
const wr4FalseRecord = wr4GroupsBytes({ index: '7', registeredBlock: '9',
  registeredAt: '9', hash: `0x${'99'.repeat(32)}` });
const wr4BrokenJson = Buffer.from('{"prevResultRegistration":');
for (const [label, bytes, reason] of [
  ['範囲外の偽記録', wr4FalseRecord, 'recorded_previous_row_mismatch'],
  ['壊れた JSON', wr4BrokenJson, 'invalid_live_grouping_json'],
]) {
  const inspected = await wr4Inspect(bytes);
  ok(`WR-4-STOP-03: 生きた R2 の${label}は例外にせず差分へ残す`,
    !(inspected instanceof Error)
      && inspected?.currentR2GroupingDifference?.checkId === 'emergency.nextGroupingLiveRecord'
      && inspected.currentR2GroupingDifference.reason === reason,
  inspected instanceof Error ? inspected.message : JSON.stringify(inspected?.currentR2GroupingDifference));

  const outputDir = path.join(taskTmp, `wr4-${reason}-output`);
  await fs.mkdir(outputDir, { recursive: true });
  const ctx = { blockNum: 4, chain: wr4Chain,
    cfg: { emergencySource: taskTmp, r2Base: 'https://r2.example.invalid' },
    report: { fact() {}, list: () => [] }, ui: { println() {} },
    data: { emergencyDifferences: [] } };
  const priorFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url) => String(url).includes('entries/block5/game_groups.json')
      ? new Response(bytes, { status: 200 }) : new Response(null, { status: 404 });
    await writeEmergencyResultSet({ ctx,
      source: { sourceDir: taskTmp, index: { objects: {} }, authority: 'gcp' },
      outputDir }).catch(() => {}); // 後段はこの盤の対象外。書出し前段の伝播を検査する。
  } finally { globalThis.fetch = priorFetch; }
  ok(`WR-4-STOP-03: 書出しは${label}を emergencyDifferences へ渡す`,
    ctx.data.emergencyDifferences.some((difference) =>
      difference.checkId === 'emergency.nextGroupingLiveRecord'
        && difference.reason === reason),
  JSON.stringify(ctx.data.emergencyDifferences));
}
const wr4LiveManifest = Buffer.from(JSON.stringify(m11bPreserveManifest));
const wr4OriginalRecord = await wr4Inspect(wr4GroupsBytes(wr4Record(0)), wr4LiveManifest);
const wr4RedirectedRecord = await wr4Inspect(wr4GroupsBytes(wr4Record(1)), wr4LiveManifest);
ok('WR-4-STOP-03: 記録を別の有効行へ向けても未保存の index 0 を保存対象に残す',
  !(wr4OriginalRecord instanceof Error) && !(wr4RedirectedRecord instanceof Error)
    && wr4OriginalRecord?.mustPreserve === true
    && wr4RedirectedRecord?.mustPreserve === true
    && wr4RedirectedRecord.versions.some((row) => row.index === 0
      && row.manifestInR2 === true && row.missingInR2.includes('manifest')),
  wr4RedirectedRecord instanceof Error ? wr4RedirectedRecord.message
    : JSON.stringify(wr4RedirectedRecord?.versions));

const n6SummaryKey = 'games/block4/summary.json';
const n6ManifestKey = 'verification/block4/manifest.json';
const n6SummaryBytes = await fs.readFile(path.join(taskTmp, m11bPreserveSummary.savedFile));
const n6ManifestBytes = Buffer.from(JSON.stringify(m11bPreserveManifest));
const n6UnservedIndex = { objects: { [n6ManifestKey]: [m11bPreserveManifestRow] } };
const n6LiveProbe = async ({ manifest = n6ManifestBytes, summary = n6SummaryBytes,
  manifestStatus = 200, summaryStatus = 200, index = n6UnservedIndex } = {}) => {
  const priorFetch = globalThis.fetch;
  const calls = [];
  let fact = null;
  const outputDir = path.join(taskTmp, `n6-live-${Math.random().toString(36).slice(2)}`);
  await fs.mkdir(outputDir, { recursive: true });
  globalThis.fetch = async (url, init) => {
    const value = String(url);
    calls.push({ url: value, init });
    const key = value.includes(n6ManifestKey) ? n6ManifestKey : n6SummaryKey;
    if (key === n6ManifestKey) return manifest == null || manifestStatus !== 200
      ? new Response(null, { status: manifest == null ? 404 : manifestStatus })
      : new Response(manifest, { status: 200 });
    return summaryStatus === 200 ? new Response(summary, { status: 200 })
      : new Response(null, { status: summaryStatus });
  };
  try {
    const outcome = await writeEmergencyResultSet({
      ctx: { blockNum: 4, chain: m11bPreserveChain,
        cfg: { emergencySource: taskTmp, r2Base: 'https://r2.example.test' },
        report: { fact(key, value) { if (key === 'emergencyNextGroupingVersionPreservation') fact = value; },
          list: () => [] }, ui: { println() {} }, data: {} },
      source: { sourceDir: taskTmp, index, authority: 'gcp' }, outputDir,
    }).catch(error => error);
    return { fact, calls, outcome };
  } finally { globalThis.fetch = priorFetch; }
};
const n6SummaryOnly = await n6LiveProbe();
ok('N6 live: 保存していない宣言 summary だけが R2 にあれば停止する',
  n6SummaryOnly.fact?.mustPreserve === true
    && n6SummaryOnly.fact.versions[0].missingInR2.includes('summary'));
const n6OtherSummary = await n6LiveProbe({ summary: Buffer.from('{"other":true}') });
ok('N6 live: 宣言と異なる summary は保存確認を通る',
  n6OtherSummary.fact?.mustPreserve === false
    && n6OtherSummary.fact.versions[0].summaryInR2 === false);
const n6SummaryUnavailable = await n6LiveProbe({ summaryStatus: 503 });
ok('N6 live: summary だけ 5xx は確認不能と鍵名を示す',
  n6SummaryUnavailable.fact?.versions[0].summaryInR2 === null
    && n6SummaryUnavailable.fact.currentR2ProbeError?.includes(n6SummaryKey));
const n6ManifestOther = await n6LiveProbe({ manifest: Buffer.from(JSON.stringify(m11cUnobservedManifest)) });
const n6ManifestGone = await n6LiveProbe({ manifest: null });
ok('N6 live: manifest が別版または 404 でも未保存の宣言 summary があれば停止する',
  [n6ManifestOther, n6ManifestGone].every(result => result.fact?.mustPreserve === true
    && result.fact.versions[0].missingInR2.includes('summary')));
const n6ReverseOther = await n6LiveProbe({ manifest: null,
  summary: Buffer.from('{"other":true}') });
ok('N6 live: manifest 404 と別本文 summary は通る',
  n6ReverseOther.fact?.mustPreserve === false
    && n6ReverseOther.fact.versions[0].summaryInR2 === false);
ok('N6 live: 各固定鍵を no-store・redirect 禁止・cache-bust で取得する',
  n6SummaryOnly.calls.length >= 2
    && n6SummaryOnly.calls.every(call => call.url.includes('__observer=')
      && call.init.redirect === 'error' && call.init.cache === 'no-store')
    && n6SummaryOnly.fact.currentR2Responses?.some(row => row.key === n6ManifestKey
      && row.url.includes('__observer=') && row.sha256 === digest(n6ManifestBytes))
    && n6SummaryOnly.fact.currentR2Responses?.some(row => row.key === n6SummaryKey
      && row.sha256 === digest(n6SummaryBytes)));
const n6Redirect = await n6LiveProbe({ manifestStatus: 302 });
ok('N6 live: redirect は取得不能として既存の inR2=null に落とす',
  n6Redirect.fact?.versions[0].inR2 === null
    && n6Redirect.fact.currentR2ProbeError?.includes(n6ManifestKey));
const n6ManifestUnavailableSummaryGone = await n6LiveProbe({ manifestStatus: 503,
  summaryStatus: 404 });
ok('N6 live: manifest 取得不能でも summary 404 は独立に不在と確かめる',
  n6ManifestUnavailableSummaryGone.fact?.versions[0].inR2 === null
    && n6ManifestUnavailableSummaryGone.fact.versions[0].summaryInR2 === false);
ok('N6 live: summary の 503 は有界3回だけ試す',
  n6SummaryUnavailable.calls.filter(call => call.url.includes(n6SummaryKey)).length === 3);
const n6J1Index = { objects: {}, lineageCheckBypassed: true,
  laterSavedGenerations: [
    { key: n6ManifestKey, ...m11bPreserveManifestRow },
    { key: n6SummaryKey, ...m11bPreserveSummary },
  ], laterSavedGenerationFailures: [] };
const n6J1Saved = await n6LiveProbe({ index: n6J1Index });
ok('N6 J1: 後の完走台帳から写した2鍵が一致すれば保存済みで進む',
  n6J1Saved.fact?.versions[0].saved === true && n6J1Saved.fact.mustPreserve === false);
const n6J1Missing = await n6LiveProbe({ index: { ...n6J1Index,
  laterSavedGenerations: [] } });
ok('N6 J1: 後の保存世代が無ければ止まる',
  n6J1Missing.fact?.mustPreserve === true);
const n6J1BadSha = await n6LiveProbe({ index: { ...n6J1Index,
  laterSavedGenerations: n6J1Index.laterSavedGenerations.map(row => ({ ...row,
    sha256: '0'.repeat(64) })) } });
ok('N6 J1: 後の保存世代のSHA-256が違えば止まる',
  n6J1BadSha.fact?.mustPreserve === true);
const n6J1Unknown = await n6LiveProbe({ index: { ...n6J1Index,
  laterSavedGenerations: [], laterSavedGenerationFailures: [{ phase: 'ledger_list' }] } });
ok('N6 J1: 後の台帳を確かめられなければ保存済みに数えず止まる',
  n6J1Unknown.fact?.mustPreserve === true);

const m14dEmptyWindowChain = { ...m11bPreserveChain,
  resultRegistrationCount: async () => 0,
  resultRegistrationAt: async () => { throw new Error('unexpected result row read'); } };
const n4LegacyNext = await inspectNextGroupingVersionPreservation({
  sourceDir: taskTmp, index: m11bPreserveIndex,
  chain: { ...m11bPreserveChain, isLegacyHashStorage: () => true,
    otherRegistrationCount: async () => null }, blockNum: 4,
});
ok('R32-A-4-04: 許可された旧版ではN+1履歴確認不能を明示して続行',
  n4LegacyNext?.unavailable === true
    && n4LegacyNext.reason === 'legacy_hash_storage_has_no_history'
    && n4LegacyNext.mustPreserve === false);
const n4UnlistedNext = await inspectNextGroupingVersionPreservation({
  sourceDir: taskTmp, index: m11bPreserveIndex,
  chain: { ...m11bPreserveChain, isLegacyHashStorage: () => false,
    otherRegistrationCount: async () => null }, blockNum: 4,
}).catch((error) => error);
ok('R32-A-4-04: 許可外のnullは書き出し前に停止',
  n4UnlistedNext instanceof Error && /N\+1 roster history/.test(n4UnlistedNext.message));
const n4LegacyLines = [];
const n4LegacyOut = path.join(taskTmp, 'n4-legacy-output');
await fs.mkdir(n4LegacyOut, { recursive: true });
await writeEmergencyResultSet({
  ctx: { blockNum: 4,
    chain: { ...m11bPreserveChain, isLegacyHashStorage: () => true,
      otherRegistrationCount: async () => null },
    report: { fact() {}, list: () => [] },
    ui: { println: (line) => n4LegacyLines.push(line) }, data: {} },
  source: { sourceDir: taskTmp, index: m11bPreserveIndex, authority: 'gcp' },
  outputDir: n4LegacyOut,
}).catch(() => {});
ok('R32-A-4-04: 旧版の書き出し前に確認不能の##行を出す',
  n4LegacyLines.some((line) => line.startsWith('##NEXT_GROUPING_PREVIOUS_VERSION ')
    && JSON.parse(line.slice('##NEXT_GROUPING_PREVIOUS_VERSION '.length)).reason
      === 'legacy_hash_storage_has_no_history'));
const m14dEmptyWindow = await inspectNextGroupingVersionPreservation({
  sourceDir: taskTmp, index: m11bPreserveIndex,
  chain: m14dEmptyWindowChain, blockNum: 4,
});
ok('M14d UJ1: N+1 組分け窓に N の登録が無ければ版一覧を空で返し書き出しを妨げない',
  m14dEmptyWindow?.emptyWindow === true
    && m14dEmptyWindow?.mustPreserve === false
    && m14dEmptyWindow?.versions?.length === 0);
const m14dEmptyLines = [];
const m14dEmptyFacts = [];
const m14dEmptyOut = path.join(taskTmp, 'm14d-empty-window-output');
await fs.mkdir(m14dEmptyOut, { recursive: true });
const m14dEmptyWrite = await writeEmergencyResultSet({
  ctx: { blockNum: 4, chain: m14dEmptyWindowChain,
    report: { fact(...args) { m14dEmptyFacts.push(args); }, list: () => [] },
    ui: { println(line) { m14dEmptyLines.push(line); } }, data: {} },
  source: { sourceDir: taskTmp, index: m11bPreserveIndex, authority: 'gcp' },
  outputDir: m14dEmptyOut,
}).catch((error) => error);
ok('M14d UJ1: 空窓は書き出し実経路の ## 行と fact に残して次段へ進む',
  m14dEmptyLines.some((line) => line.startsWith('##NEXT_GROUPING_PREVIOUS_VERSION ')
    && JSON.parse(line.slice('##NEXT_GROUPING_PREVIOUS_VERSION '.length)).emptyWindow === true)
    && m14dEmptyFacts.some(([id, value]) =>
      id === 'emergencyNextGroupingVersionPreservation' && value.emptyWindow === true)
    && (!m14dEmptyWrite || !/no in-window/.test(m14dEmptyWrite.message)));
const m11cLiveLines = [];
const m11cLiveFacts = [];
const m11cLiveCtx = { blockNum: 4, chain: m11cWindowChain,
  cfg: { emergencySource: taskTmp, r2Base: 'https://r2.example.invalid' },
  report: { fact(...args) { m11cLiveFacts.push(args); }, list: () => [] },
  ui: { println(line) { m11cLiveLines.push(line); } }, data: {} };
const originalFetch = globalThis.fetch;
const m11cLiveOut = path.join(taskTmp, 'm11c-live-output');
await fs.mkdir(m11cLiveOut, { recursive: true });
let m11cLiveBlocked;
let m11cLiveOther;
let m11cLiveUnavailable;
try {
  globalThis.fetch = async () => new Response(JSON.stringify(m11cUnobservedManifest));
  m11cLiveBlocked = await writeEmergencyResultSet({ ctx: m11cLiveCtx,
    source: { sourceDir: taskTmp, index: m11bPreserveIndex, authority: 'gcp' },
    outputDir: m11cLiveOut }).catch((error) => error);
  globalThis.fetch = async () => new Response(JSON.stringify(m11bPreserveManifest));
  m11cLiveOther = await writeEmergencyResultSet({ ctx: m11cLiveCtx,
    source: { sourceDir: taskTmp, index: m11bPreserveIndex, authority: 'gcp' },
    outputDir: m11cLiveOut }).catch((error) => error);
  globalThis.fetch = async () => { throw new Error('mock R2 unavailable'); };
  m11cLiveUnavailable = await writeEmergencyResultSet({ ctx: m11cLiveCtx,
    source: { sourceDir: taskTmp, index: m11bPreserveIndex, authority: 'gcp' },
    outputDir: m11cLiveOut }).catch((error) => error);
} finally {
  globalThis.fetch = originalFetch;
}
ok('M11c: 公開 R2 の現在版が未保存なら書き出し前に止める',
  m11cLiveBlocked instanceof Error
    && /run the observer manually/.test(m11cLiveBlocked.message)
    && m11cLiveFacts.some(([id, fact]) => id === 'emergencyNextGroupingVersionPreservation'
      && fact.currentR2Source === 'live public R2 fixed key' && fact.mustPreserve === true));
ok('M11c: 公開 R2 にない窓内版の欠落は上書き前停止しない',
  m11cLiveOther instanceof Error
    && !/run the observer manually/.test(m11cLiveOther.message)
    && m11cLiveFacts.some(([id, fact]) => id === 'emergencyNextGroupingVersionPreservation'
      && fact.currentR2Source === 'live public R2 fixed key' && fact.mustPreserve === false));
ok('M11c: 公開 R2 取得不能は明示アラートにし、未保存版と断定して停止しない',
  m11cLiveUnavailable instanceof Error
    && !/run the observer manually/.test(m11cLiveUnavailable.message)
    && m11cLiveLines.some((line) => line.startsWith('##NEXT_GROUPING_R2_PROBE_UNAVAILABLE '))
    && m11cLiveFacts.some(([id, fact]) => id === 'emergencyNextGroupingVersionPreservation'
      && fact.currentR2ProbeError?.includes('mock R2 unavailable')
      && fact.currentR2ProbeError?.includes('games/block4/summary.json')
      && fact.versions?.some((row) => row.index === 1 && row.inR2 === null))
    && (await fs.readdir(m11cLiveOut)).length === 0);
const p15LateOnly = await p15GcpCase([p15HistoryRow(0, p15HonestCore, 400)], 255)
  .catch((error) => error);
ok('M11b UJ1: GCP入口も窓外の後付け F を採らない',
  p15LateOnly instanceof Error && /no saved generation reproduces Stage B/.test(p15LateOnly.message),
  JSON.stringify({ message: p15LateOnly.message }));
const p16PreregRoster = await p15GcpCase([p15HistoryRow(0, p15HonestCore, 400)], 190)
  .catch((error) => error);
ok('M9a: 応募終了前だけの名簿は正典にならずGCP入口が停止する',
  p16PreregRoster instanceof Error && /index=none.*generations=0/.test(p16PreregRoster.message));
const p16K4 = await p15GcpCase([
  p15HistoryRow(0, p15FalseCore, 200), p15HistoryRow(1, p15HonestCore, 400),
], 255).catch((error) => error);
ok('M11b UJ1: 窓内の版が組を再現しなければ窓外の F へ逃げず止まる',
  p16K4 instanceof Error && /no saved generation reproduces Stage B/.test(p16K4.message));
const p16AnchoredIndex = structuredClone(p15GcpIndex);
p16AnchoredIndex.objects['entries/block4/game_groups.json'] = [
  { ...p15HonestGroupRow, observationOrdinal: '00000001:00000000',
    observedAt: new Date(254000).toISOString() },
  { ...p15FalseGroupRow, observationOrdinal: '00000002:00000000',
    observedAt: new Date(260000).toISOString() },
];
for (const [label, rows] of [
  ['B1/S1', [p15HistoryRow(0, p15FalseCore, 200), p15HistoryRow(1, p15HonestCore, 400)]],
  ['B4/S4', [p15HistoryRow(0, p15FalseCore, 260), p15HistoryRow(1, p15HonestCore, 300)]],
]) {
  const picked = await p15GcpCase(rows, 255, { candidateIndex: p16AnchoredIndex })
    .catch((error) => error);
  ok(`M11b UJ1: ${label} は窓外 F の主要言語で名簿を救わない`,
    picked instanceof Error && /no saved generation reproduces Stage B/.test(picked.message));
}
const p16B4SingleIndex = structuredClone(p16AnchoredIndex);
p16B4SingleIndex.objects['entries/block4/game_groups.json'] = [
  p16B4SingleIndex.objects['entries/block4/game_groups.json'][0],
];
const p16B4Single = await p15GcpCase([
  p15HistoryRow(0, p15FalseCore, 260), p15HistoryRow(1, p15HonestCore, 300),
], 255, { candidateIndex: p16B4SingleIndex }).catch((error) => error);
ok('M11b UJ1: B4c も窓外の版は採らない',
  p16B4Single instanceof Error
    && /no saved generation reproduces Stage B/.test(p16B4Single.message));
const p16NoDeclaredIndex = structuredClone(p16B4SingleIndex);
p16NoDeclaredIndex.objects['games/block4/summary.json'] = [p15HonestCurrentRow];
p16NoDeclaredIndex.objects['entries/block4/game_groups.json'][0].savedFile
  = 'p16-missing-group-file-that-must-not-be-read.bin';
let p16NoDeclaredError = null;
try {
  await p15GcpCase([p15HistoryRow(0, p15FalseCore, 200)], 255,
    { candidateIndex: p16NoDeclaredIndex });
} catch (error) { p16NoDeclaredError = error; }
ok('P16: 宣言 majorLangs と合う N option が無ければ組世代を読まず停止する',
  p16NoDeclaredError?.emergencyDifferences?.some((d) =>
    d.checkId === 'emergency.gcpGroupsCandidates'
      && d.rebuilt?.candidates?.[0]?.stage === 'not-read-no-declared-major-langs-option'));
const p16B9 = await p15GcpCase([
  p15HistoryRow(0, p15FalseCore, 190), p15HistoryRow(1, p15HonestCore, 200),
], 255);
ok('P16: B9/EF の先行偽組も名簿錨で外す',
  p16B9.groups.row.savedFile === p15HonestGroupRow.savedFile
    && isDeepStrictEqual(p16B9.majorLangs, p15HonestLangs));
const p16SamePrev = { schemaVersion: 2, blockNum: p15Prev,
  groups: [p15PrevSummary(200).groups[0], { group_id: 1, status: 'completed',
    members: Array.from({ length: 200 }, (_, i) => ({
      userId: `p16-fr-${i}`, lang: 'fr', is_disqualified: 0,
    })) }] };
const p16SameLangs = await p15MajorLangs(p16SamePrev);
const p16SameGroups = await p15Gm.formGroups(p15Players, p15GroupSeed, p16SameLangs);
const p16SameSummaryRow = await p15Save('summary-same-groups-other-langs',
  p15CurrentSummary(p16SameGroups, p16SameLangs));
const p16SamePrevRow = await p15Save('previous-same-groups-other-langs', p16SamePrev);
const p16SameManifest = { blockNum: p15Prev, algorithm: 'sha256', rules: { p16: true },
  files: { [p15PreviousSummaryKey]: p16SamePrevRow.sha256 } };
const p16SameManifestRow = await p15Save('manifest-same-groups-other-langs', p16SameManifest);
const p16B6Index = structuredClone(p15GcpIndex);
p16B6Index.objects[p15PreviousManifestKey].push(p16SameManifestRow);
p16B6Index.objects[p15PreviousSummaryKey].push(p16SamePrevRow);
p16B6Index.objects['entries/block4/game_groups.json'] = [p15HonestGroupRow];
p16B6Index.objects['games/block4/summary.json'].push(p16SameSummaryRow);
const p16B6 = await p15GcpCase([
  p15HistoryRow(0, manifestCoreHash(p16SameManifest), 200),
  p15HistoryRow(1, p15HonestCore, 400),
], 255, { candidateIndex: p16B6Index });
ok('M11b UJ1: B6 は同じ組でも窓内版から導いた majorLangs だけを選ぶ',
  isDeepStrictEqual(p16SameGroups.map((g) => g.members.map((m) => m.data.uid)),
    p15HonestGroups.map((g) => g.members.map((m) => m.data.uid)))
    && p16B6.groups.row.savedFile === p15HonestGroupRow.savedFile
    && isDeepStrictEqual(p16B6.majorLangs, p16SameLangs)
    && p16B6.summary.row.savedFile === p16SameSummaryRow.savedFile);
const p16FallbackIndex = structuredClone(p15GcpIndex);
p16FallbackIndex.objects['entries/block4/game_groups.json'] = [
  { ...p15FalseGroupRow, observationOrdinal: '00000001:00000000',
    observedAt: new Date(280000).toISOString() },
  { ...p15HonestGroupRow, observationOrdinal: '00000002:00000000',
    observedAt: new Date(260000).toISOString() },
];
const p16Fallback = await p15GcpCase([
  p15HistoryRow(0, p15FalseCore, 200), p15HistoryRow(1, p15HonestCore, 400),
], 255, { candidateIndex: p16FallbackIndex, noAnchor: true }).catch((error) => error);
ok('M9a: 正典名簿の無いGCP入口はfirstSeenAtで別の組を採らない',
  p16Fallback instanceof Error && /index=none.*generations=0/.test(p16Fallback.message));
// M2: a later malformed group must not erase the already found honest match,
// including the branch that scans generations seen after the upper bound.
const m2BadGroupRow = await p15Save('m2-bad-group', {
  ...p15Gm.createGroupSummary(p15Block, p15HonestGroups, p15Selection), groupSeed: {},
});
for (const [label, anchored] of [['anchor', true], ['after-upper-bound', false]]) {
  const candidateIndex = structuredClone(p15GcpIndex);
  candidateIndex.objects['entries/block4/game_groups.json'] = [
    { ...p15HonestGroupRow, observationOrdinal: '00000001:00000000',
      observedAt: new Date(280000).toISOString() },
    { ...m2BadGroupRow, observationOrdinal: '00000002:00000000',
      observedAt: new Date(281000).toISOString() },
  ];
  const picked = await p15GcpCase([p15HistoryRow(0, p15HonestCore, 200)], 255,
    { candidateIndex, noAnchor: !anchored }).catch((error) => error);
  if (!anchored) {
    ok('M9a: 名簿なしでは観測時刻の後続世代へ戻らず停止',
      picked instanceof Error && /index=none/.test(picked.message));
    continue;
  }
  const evaluation = picked.differences.find((d) => d.checkId === 'emergency.gcpGroupsGeneration');
  ok(`M2: ${label} の正直な組は後続の型ずれ世代でも採用される`,
    picked.groups?.row.sha256 === p15HonestGroupRow.sha256
      && evaluation?.rebuilt?.candidates?.some((c) => c.sha256 === m2BadGroupRow.sha256
        && c.reason === 'unusable saved group structure'));
}
const m2BadSummaryRow = await p15Save('m2-bad-summary', {
  ...p15CurrentSummary(p15HonestGroups, p15HonestLangs),
  groups: p15CurrentSummary(p15HonestGroups, p15HonestLangs).groups.map((group, i) =>
    i === 0 ? null : group),
});
const m2SummaryIndex = structuredClone(p15GcpIndex);
m2SummaryIndex.objects['games/block4/summary.json'] = [
  { ...m2BadSummaryRow, observationOrdinal: '00000000:00000000' }, p15HonestCurrentRow,
];
const m2SummaryPicked = await p15GcpCase([p15HistoryRow(0, p15HonestCore, 200)], 255,
  { candidateIndex: m2SummaryIndex });
ok('M2: 型ずれ groupGame summary の後の正直な世代を採る',
  m2SummaryPicked.summary?.row.sha256 === p15HonestCurrentRow.sha256
    && m2SummaryPicked.differences.some((d) => d.checkId === 'emergency.gcpSummaryGeneration'
      && d.rebuilt?.candidates?.some((c) => c.sha256 === m2BadSummaryRow.sha256
        && c.reason === 'unusable saved summary structure')),
  JSON.stringify(m2SummaryPicked.differences.filter((d) => d.checkId === 'emergency.gcpSummaryGeneration')));
const m2HugeMajorRow = await p15Save('m2-huge-major', {
  ...p15CurrentSummary(p15HonestGroups, p15HonestLangs),
  majorLangs: Array.from({ length: 1000 }, (_, i) => `lang${i}`),
});
const m2MajorIndex = structuredClone(p15GcpIndex);
m2MajorIndex.objects['games/block4/summary.json'] = [m2HugeMajorRow, p15HonestCurrentRow];
const m2MajorPicked = await p15GcpCase([p15HistoryRow(0, p15HonestCore, 200)], 255,
  { candidateIndex: m2MajorIndex });
ok('M2: 大量の宣言 majorLangs は候補に保持せず正直な世代を採る',
  m2MajorPicked.summary?.row.sha256 === p15HonestCurrentRow.sha256
    && m2MajorPicked.differences.some((d) => d.checkId === 'emergency.gcpSummaryGeneration'
      && d.rebuilt?.unusableCandidates?.some((c) => c.sha256 === m2HugeMajorRow.sha256
        && c.reason === 'unusable declared majorLangs')));
for (const [label, lang] of [['length', 'x'.repeat(33)], ['character', 'bad_lang']]) {
  const badRow = await p15Save(`m11a-major-${label}`, {
    ...p15CurrentSummary(p15HonestGroups, p15HonestLangs), majorLangs: [lang],
  });
  const candidateIndex = structuredClone(p15GcpIndex);
  candidateIndex.objects['games/block4/summary.json'] = [badRow, p15HonestCurrentRow];
  const picked = await p15GcpCase([p15HistoryRow(0, p15HonestCore, 200)], 255,
    { candidateIndex });
  ok(`M11a: majorLangs ${label} を外し正直な世代を採る`,
    picked.summary?.row.sha256 === p15HonestCurrentRow.sha256
      && picked.differences.some((difference) =>
        difference.rebuilt?.unusableCandidates?.some((candidate) =>
          candidate.sha256 === badRow.sha256 && candidate.reason === 'unusable declared majorLangs')));
}
const m2AutoIndices = await selectWinners(
  keccak256(concat([p15Target.mixHash, p15ApplicantHash])), 10, 2);
const m2AutoPlayers = m2AutoIndices.map((globalIndex) => ({ globalIndex,
  localIndex: globalIndex, file: 'p15-f0', data: p15Entries[globalIndex] }))
  .sort((a, b) => a.globalIndex - b.globalIndex);
const m2AutoSelection = { ...p15Selection, players: m2AutoPlayers, totalSelected: 2 };
const m2AutoSelectionRow = await p15Save('m2-auto-selection', m2AutoSelection);
const m2AutoBadRow = await p15Save('m2-auto-bad-summary', {
  blockNum: 4, autoDistributed: true, totalPlayers: 2, totalGroups: 0,
  groups: [{ group_id: 0, members: [null, null] }],
});
const m2AutoHonestRow = await p15Save('m2-auto-honest-summary', {
  blockNum: 4, autoDistributed: true, totalPlayers: 2, totalGroups: 0,
  groups: [{ group_id: 0, members: m2AutoPlayers.map((player) => ({ userId: player.data.uid })) }],
});
const m2AutoIndex = structuredClone(p15GcpIndex);
m2AutoIndex.objects['entries/block4/game_selection.json'] = [m2AutoSelectionRow];
m2AutoIndex.objects['games/block4/summary.json'] = [m2AutoBadRow, m2AutoHonestRow];
const m2AutoDifferences = [];
const m2AutoPicked = await selectGcpGroupGameInputs({ sourceDir: taskTmp, index: m2AutoIndex,
  chain: { getTimingConstants: async () => p15Timing, getBlock: async () => p15Target },
  blockNum: 4, applicant: { rows: p15ApplicantRows,
    registration: { hash: p15ApplicantHash, registeredBlock: 100, index: 0 } },
  pins: { ...p15Pins, gameMaxPlayers: 2 }, differences: m2AutoDifferences });
ok('M2: 自動配布の型ずれ summary を記録して正直な比較世代へ進む',
  m2AutoPicked.kind === 'autoDistribute'
    && m2AutoDifferences.some((d) => d.checkId === 'emergency.gcpSummaryGeneration'
      && d.rebuilt?.candidates?.some((c) => c.sha256 === m2AutoBadRow.sha256
        && c.reason === 'summary kind or auto-distribution players differ from chain-selected applicants')));
const m2ZeroInfoRow = await p15Save('m2-zero-info', { entries: [] });
const m2ZeroApplicantRows = p15ApplicantRows.map(({ key, row }) => ({ key,
  row: key === 'entries/block4/info/00_info.json' ? m2ZeroInfoRow : row }));
const m2ZeroSelectionRow = await p15Save('m2-zero-selection', {
  ...p15Selection, players: [], totalEntries: 0, totalSelected: 0,
});
const m2ZeroIndex = structuredClone(m2AutoIndex);
m2ZeroIndex.objects['entries/block4/game_selection.json'] = [m2ZeroSelectionRow];
const m2ZeroHonestRow = await p15Save('m2-zero-honest-summary',
  buildZeroEntryNoGameSummary(4, 3, true));
m2ZeroIndex.objects['games/block4/summary.json'] = [m2AutoBadRow, m2ZeroHonestRow];
const m2ZeroDifferences = [];
const m2ZeroPicked = await selectGcpGroupGameInputs({ sourceDir: taskTmp, index: m2ZeroIndex,
  chain: { getTimingConstants: async () => p15Timing, getBlock: async () => p15Target },
  blockNum: 4, applicant: { rows: m2ZeroApplicantRows,
    registration: { hash: p15ApplicantHash, registeredBlock: 100, index: 0 } },
  pins: { ...p15Pins, gameMaxPlayers: 2 }, differences: m2ZeroDifferences });
ok('M2: 0名の型ずれ summary を記録して合成 noGame へ進む',
  m2ZeroPicked.kind === 'noGame' && m2ZeroPicked.syntheticSummary?.noGame === true
    && m2ZeroDifferences.some((d) => d.checkId === 'emergency.gcpSummaryGeneration'
      && d.rebuilt?.candidates?.some((c) => c.sha256 === m2AutoBadRow.sha256
        && c.reason === 'summary kind or zero-entry fields differ from chain-selected applicants')
      && d.rebuilt?.candidates?.some((c) => c.sha256 === m2ZeroHonestRow.sha256
        && c.reason === 'matches chain-selected zero-entry kind')));
async function m2FullGcpArchive(count, n = 0) {
  const sourceDir = path.join(taskTmp, `m2-full-gcp-${n}-${count}`);
  await fs.mkdir(path.join(sourceDir, '_observer/generations'), { recursive: true });
  const objects = {};
  let ordinal = 0;
  const put = async (key, value) => {
    const raw = typeof value === 'string' ? value : JSON.stringify(value);
    const savedFile = `_observer/generations/${String(++ordinal).padStart(5, '0')}.bin`;
    await fs.writeFile(path.join(sourceDir, savedFile), raw);
    const row = { savedFile, sha256: digest(Buffer.from(raw)), bytes: Buffer.byteLength(raw),
      generation: ordinal, observationOrdinal: String(ordinal).padStart(8, '0') };
    (objects[key] ||= []).push(row);
    return row;
  };
  const entries = Array.from({ length: count }, (_, i) => ({ uid: `m2-u${i}`, lang: 'en',
    addr: `0x${String(i + 1).padStart(40, '0')}` }));
  const infos = Array.from({ length: 100 }, (_, worker) => ({
    entries: worker === 0 && count ? [{ filename: '00_0', number: count }] : [],
  }));
  for (let worker = 0; worker < 100; worker++) {
    await put(`entries/block${n}/info/${String(worker).padStart(2, '0')}_info.json`, infos[worker]);
  }
  if (count) await put(`entries/block${n}/entries/00_0.json`, entries);
  const root = `0x${hashLikeBackend(applicantIntermediate(n, infos,
    count ? new Map([['00_0', entries]]) : new Map()))}`;
  const target = { mixHash: p15Target.mixHash, hash: p15Target.hash };
  const players = entries.map((data, globalIndex) => ({ globalIndex, localIndex: globalIndex,
    file: '00_0', data }));
  const selection = { applicantHash: root, hashRegisteredBlock: 100,
    confirmationBlocks: 64, targetBlockNum: 164, entryPeriodEnd: 50_000 * (n + 1),
    totalEntries: count, totalSelected: count, targetBlockHash: target.hash,
    randao: target.mixHash, players };
  await put(`entries/block${n}/game_selection.json`, selection);
  const groupSeed = keccak256(concatHex([selection.randao, selection.applicantHash,
    stringToHex('group')]));
  let groups = [];
  if (count >= 3) {
    groups = await p15Gm.formGroups(players, groupSeed, []);
    const groupSummary = p15Gm.createGroupSummary(n, groups, selection);
    if (n > 0) groupSummary.prevResultRegistration = { status: 'none' };
    await put(`entries/block${n}/game_groups.json`, groupSummary);
    if (n > 0) {
      const roster = reconstructCanonicalRosterPayloads(n, groups);
      await put(`games/block${n}/roster/manifest.json`, roster.manifestText);
      for (const [groupId, groupText] of roster.groupTexts) {
        await put(`games/block${n}/roster/group${groupId}.json`, groupText);
      }
    }
    const declared = computeDeclaredTimesMs({ startTimeMs: 0, blockTimeMs: 50_000,
      gamePeriodMs: 1000, submitPeriodMs: 1000, confirmations: 64 }, n, 20);
    await put(`games/block${n}/summary.json`, {
      ...p15Gm.buildBlockSummaryForR2(n, groups, []), majorLangs: [],
      timeline: { graceSec: 20, chattingStart: declared.chattingStart,
        submittingStart: declared.submittingStart, closeAt: declared.closeAt,
        completedAt: declared.completedAt },
    });
  } else {
    await put(`games/block${n}/summary.json`, { blockNum: n, autoDistributed: true,
      totalPlayers: count, totalGroups: 0, groups: [{ group_id: 0, members: [] }] });
  }
  const index = { kind: 'r2-backup-observer-block-archive', complete: true,
    blockNum: n, objects };
  const rosterRow = objects[`games/block${n}/roster/manifest.json`]?.[0] ?? null;
  const rosterHash = rosterRow
    ? buildRosterMemberCommitment({ blockNum:n,
      manifestText:await fs.readFile(path.join(sourceDir, rosterRow.savedFile), 'utf8'),
      groupTexts:new Map(await Promise.all(groups.map(async group => [group.groupId,
        await fs.readFile(path.join(sourceDir,
          objects[`games/block${n}/roster/group${group.groupId}.json`][0].savedFile), 'utf8')]))),
    }).C : null;
  const chain = {
    applicantRegistrationCount: async () => 1,
    applicantRegistrationAt: async () => ({ hash: root, registeredBlock: 100, signer: '0x01' }),
    getTimingConstants: async () => p15Timing,
    getBlock: async (number) => ({ ...target, timestamp: Number(number) }),
    getResultHash: async () => ({ hash: null }),
    getOtherHash: async () => null,
    otherRegistrationCount: async () => rosterRow ? 1 : 0,
    otherRegistrationAt: async () => ({ hash: rosterHash,
      registeredBlock: 50 * (n + 1) + 10, registeredAt: 50 * (n + 1) + 10 }),
    currentGrace: async () => 20,
    chatWindow: async () => ({ chatCloseAt: 50 * (n + 1) + 21 }),
  };
  return { sourceDir, put, index, chain, groups, root };
}
const m2FullZero = await m2FullGcpArchive(0);
await m2FullZero.put('games/block0/roster/manifest.json', { invalid: true });
await fs.writeFile(path.join(m2FullZero.sourceDir, '_observer/generation-index.json'),
  JSON.stringify(m2FullZero.index));
const m2FullZeroPicked = await resolveEmergencyGenerationMap({ sourceDir: m2FullZero.sourceDir,
  chain: m2FullZero.chain, blockNum: 0, authority: 'gcp', pins: {
    ...p15Pins, claimDataFormat: 'chunked-v1',
  } });
ok('M2: 0名の GCP 入口はゴミ名簿を選ばず合成 manifest にも載せない',
  m2FullZeroPicked.syntheticSummary?.noGame === true
    && !m2FullZeroPicked.fileMap.has('games/block0/roster/manifest.json')
    && !Object.keys(m2FullZeroPicked.selectedManifest.files).some((key) => key.includes('/roster/')));
const m2FullGroup = await m2FullGcpArchive(3);
const m2GroupKey = 'games/block0/group0.json';
const m2Archive = { meta: { blockNum: 0, groupId: 0 },
  members: m2FullGroup.groups[0].members.map((member) => ({ uid: member.data.uid })),
  messages: [], receipts: [], gameResults: [], archivedAt: '2026-09-24T00:00:00.000Z' };
const m2BadArchiveRow = await m2FullGroup.put(m2GroupKey, {
  ...m2Archive, members: [null],
});
const m2HonestArchiveRow = await m2FullGroup.put(m2GroupKey, m2Archive);
await fs.writeFile(path.join(m2FullGroup.sourceDir, '_observer/generation-index.json'),
  JSON.stringify(m2FullGroup.index));
const m2ArchivePicked = await resolveEmergencyGenerationMap({ sourceDir: m2FullGroup.sourceDir,
  chain: m2FullGroup.chain, blockNum: 0, authority: 'gcp', pins: {
    ...p15Pins, claimDataFormat: 'chunked-v1',
  } });
ok('M2: 型ずれ群アーカイブを記録して正直な後続世代を採る',
  m2ArchivePicked.fileMap.get(m2GroupKey) === m2HonestArchiveRow.savedFile
    && m2ArchivePicked.differences.some((d) => d.checkId === 'emergency.gcpGroupArchiveGeneration'
      && d.rebuilt?.candidates?.some((c) => c.sha256 === m2BadArchiveRow.sha256
        && c.reason === 'not a complete archive for the Stage B group'
        && c.bytes === m2BadArchiveRow.bytes)));
const m3WrongOrderRow = await m2FullGroup.put(m2GroupKey, {
  ...m2Archive, members: [...m2Archive.members].reverse(),
});
const { gameResults: _m3UnusedGameResults, ...m3CompletedArchive } = m2Archive;
const m3CompletedRow = await m2FullGroup.put(m2GroupKey, m3CompletedArchive);
const m3BadMerkleKey = 'merkle/block_0.json';
const m3MetaSentinel = 'M3_UNTRUSTED_MERKLE_VALUE_SENTINEL';
const m3BadMerkleRow = await m2FullGroup.put(m3BadMerkleKey, {
  blockNum: m3MetaSentinel, root: m3MetaSentinel,
  totalAmount: m3MetaSentinel, leafCount: 2, proofDepth: 99,
});
const m3NullMerkleRow = await m2FullGroup.put(m3BadMerkleKey, null);
const m3WrongTypeMerkleRow = await m2FullGroup.put(m3BadMerkleKey, {
  root: { toString: 1 }, totalAmount: { toString: 1 },
  blockNum: { toString: 1 }, leafCount: 0,
});
const m3OversizeMerkleRow = await m2FullGroup.put(m3BadMerkleKey, {
  payload: 'x'.repeat(256 * 1024),
});
const m11aManyLeavesRow = await m2FullGroup.put(m3BadMerkleKey, {
  blockNum: 0, root: `0x${'12'.repeat(32)}`, totalAmount: '0',
  leafCount: 2 ** 19 + 1, proofDepth: 20,
});
const m3GoodMerkleRow = await m2FullGroup.put(m3BadMerkleKey, {
  blockNum: 0, root: `0x${'12'.repeat(32)}`, totalAmount: '0', leafCount: 0, proofDepth: 0,
});
const m3Stage3Key = 'verification/block0/stage3/manifest.json';
const m3NullStage3Row = await m2FullGroup.put(m3Stage3Key, null);
const m3WrongStage3Row = await m2FullGroup.put(m3Stage3Key, { kind: 'wrong' });
const m3OversizeStage3Row = await m2FullGroup.put(m3Stage3Key, {
  payload: 'x'.repeat(1024 * 1024),
});
const m11aLargeValidStage3Row = await m2FullGroup.put(m3Stage3Key, {
  schemaVersion: 1, kind: 'bitcoinu-stage3-input-manifest', blockNum: 0,
  groupCount: 0, groups: [], padding: 'x'.repeat(1024 * 1024),
});
const m3GoodStage3Row = await m2FullGroup.put(m3Stage3Key, {
  schemaVersion: 1, kind: 'bitcoinu-stage3-input-manifest', blockNum: 0,
  groupCount: 0, groups: [],
});
const m3Index = structuredClone(m2FullGroup.index);
m3Index.objects[m2GroupKey] = [m3WrongOrderRow, m3CompletedRow];
m3Index.objects[m3BadMerkleKey] = [m3BadMerkleRow, m3NullMerkleRow, m3WrongTypeMerkleRow,
  m3OversizeMerkleRow, m11aManyLeavesRow, m3GoodMerkleRow];
m3Index.objects[m3Stage3Key] = [m3NullStage3Row, m3WrongStage3Row,
  m3OversizeStage3Row, m11aLargeValidStage3Row, m3GoodStage3Row];
await fs.writeFile(path.join(m2FullGroup.sourceDir, '_observer/generation-index.json'),
  JSON.stringify(m3Index));
const m3Picked = await resolveEmergencyGenerationMap({ sourceDir: m2FullGroup.sourceDir,
  chain: m2FullGroup.chain, blockNum: 0, authority: 'gcp', pins: {
    ...p15Pins, claimDataFormat: 'chunked-v1',
  } });
ok('M3: 成員順の違う保存版を外し、gameResults の無い完了アーカイブを採る',
  m3Picked.fileMap.get(m2GroupKey) === m3CompletedRow.savedFile
    && m3Picked.differences.some((d) => d.checkId === 'emergency.gcpGroupArchiveGeneration'
      && d.rebuilt?.candidates?.some((c) => c.sha256 === m3WrongOrderRow.sha256
        && c.reason === 'not a complete archive for the Stage B group')));
ok('M3: 不整合・型ずれの比較資料を外し、正直な Merkle/Stage 3 世代を採る',
  m3Picked.fileMap.get(m3BadMerkleKey) === m3GoodMerkleRow.savedFile
    && m3Picked.fileMap.get(m3Stage3Key) === m3GoodStage3Row.savedFile
    && m3Picked.stage3ManifestUsableForZkp === true
    && m3Picked.differences.filter((d) => d.checkId === 'emergency.gcpComparisonGeneration')
      .length === 2
    && m3Picked.differences.filter((d) => d.checkId === 'emergency.gcpComparisonGeneration')
      .every((d) => d.rebuilt.candidates.every((c) =>
        Object.keys(c).sort().join(',') === 'bytes,reason,sha256,valueType'))
    && m3Picked.differences.some((d) => d.checkId === 'emergency.gcpComparisonGeneration'
      && d.rebuilt.candidates.some((c) => c.sha256 === m3OversizeMerkleRow.sha256
        && c.reason === 'unusable comparison copy structure or size')
      && d.rebuilt.candidates.some((c) => c.sha256 === m3NullMerkleRow.sha256
        && c.valueType === 'null')
      && d.rebuilt.candidates.some((c) => c.sha256 === m3WrongTypeMerkleRow.sha256
        && c.reason === 'unusable merkle reconstruction metadata')
      && d.rebuilt.candidates.some((c) => c.sha256 === m11aManyLeavesRow.sha256
        && c.reason === 'unusable merkle reconstruction metadata'))
    && m3Picked.differences.some((d) => d.checkId === 'emergency.gcpComparisonGeneration'
      && d.rebuilt.candidates.some((c) => c.sha256 === m3WrongStage3Row.sha256
        && c.reason === 'unusable Stage 3 input manifest')
      && d.rebuilt.candidates.some((c) => c.sha256 === m3OversizeStage3Row.sha256
        && c.reason === 'unusable Stage 3 input manifest')
      && d.rebuilt.candidates.some((c) => c.sha256 === m11aLargeValidStage3Row.sha256
        && c.reason === 'unusable Stage 3 input manifest'))
    && !JSON.stringify(m3Picked.differences).includes(m3MetaSentinel));
const m11aComparisonRows = m3Picked.differences
  .filter((d) => d.checkId === 'emergency.gcpComparisonGeneration')
  .flatMap((d) => d.rebuilt.candidates);
ok('M11a: 比較資料の公開評価は sha256・実バイト数・型だけを持つ',
  m11aComparisonRows.some((row) => row.sha256 === m11aManyLeavesRow.sha256
    && row.bytes === m11aManyLeavesRow.bytes && row.valueType === 'object')
  && m11aComparisonRows.some((row) => row.sha256 === m11aLargeValidStage3Row.sha256
    && row.bytes === m11aLargeValidStage3Row.bytes && row.valueType === 'object')
  && m11aComparisonRows.every((row) =>
    Object.keys(row).sort().join(',') === 'bytes,reason,sha256,valueType'));
const m3DifferenceLines = [];
emitEmergencyDifferenceMarkers({ println: (line) => m3DifferenceLines.push(String(line)) }, m3Picked);
ok('M3: GCP 比較資料の番兵値は緊急差分の ## 行に出ない',
  m3DifferenceLines.some((line) => line.startsWith('##EMERGENCY_DIFFERENCE '))
    && !m3DifferenceLines.join('\n').includes(m3MetaSentinel));
const m3WrongTypeIndex = structuredClone(m3Index);
m3WrongTypeIndex.objects[m3BadMerkleKey] = [m3WrongTypeMerkleRow, m3GoodMerkleRow];
await fs.writeFile(path.join(m2FullGroup.sourceDir, '_observer/generation-index.json'),
  JSON.stringify(m3WrongTypeIndex));
const m3WrongTypePicked = await resolveEmergencyGenerationMap({ sourceDir: m2FullGroup.sourceDir,
  chain: m2FullGroup.chain, blockNum: 0, authority: 'gcp', pins: {
    ...p15Pins, claimDataFormat: 'chunked-v1',
  } });
ok('M3: root 等の入れ子の型ずれだけでも先行 Merkle 世代を外す',
  m3WrongTypePicked.fileMap.get(m3BadMerkleKey) === m3GoodMerkleRow.savedFile);
const m3SingleBadIndex = structuredClone(m3Index);
m3SingleBadIndex.objects[m2GroupKey] = [m3WrongOrderRow];
await fs.writeFile(path.join(m2FullGroup.sourceDir, '_observer/generation-index.json'),
  JSON.stringify(m3SingleBadIndex));
const m3SingleBad = await resolveEmergencyGenerationMap({ sourceDir: m2FullGroup.sourceDir,
  chain: m2FullGroup.chain, blockNum: 0, authority: 'gcp', pins: {
    ...p15Pins, claimDataFormat: 'chunked-v1',
  } });
ok('M3: 唯一の群アーカイブを外した評価も差分に残す',
  !m3SingleBad.fileMap.has(m2GroupKey)
    && m3SingleBad.differences.some((d) => d.checkId === 'emergency.gcpGroupArchiveGeneration'
      && d.rebuilt?.selectedGeneration === null
      && d.rebuilt.candidates[0]?.sha256 === m3WrongOrderRow.sha256));
const m3N1 = await m2FullGcpArchive(3, 1);
const m3PrevSummaryKey = 'games/block0/summary.json';
const m3PrevManifestKey = 'verification/block0/manifest.json';
const m3PrevSummaryRow = await m3N1.put(m3PrevSummaryKey, {
  schemaVersion: 2, blockNum: 0, noGame: true, groups: [],
});
const m3PrevManifest = { blockNum: 0, algorithm: 'sha256', rules: {},
  files: { [m3PrevSummaryKey]: m3PrevSummaryRow.sha256 } };
const m3PrevManifestRow = await m3N1.put(m3PrevManifestKey, m3PrevManifest);
const m3PrevCore = manifestCoreHash(m3PrevManifest);
const m3N1ArchiveKey = 'games/block1/group0.json';
const m3N1Archive = { meta: { blockNum: 1, groupId: 0 },
  members: m3N1.groups[0].members.map((member) => ({ uid: member.data.uid })),
  messages: [], receipts: [], archivedAt: '2026-09-24T00:00:00.000Z' };
const m3N1WrongRow = await m3N1.put(m3N1ArchiveKey, {
  ...m3N1Archive, members: [...m3N1Archive.members].reverse(),
});
const m3N1HonestRow = await m3N1.put(m3N1ArchiveKey, m3N1Archive);
const m3N1Index = structuredClone(m3N1.index);
m3N1Index.objects[m3N1ArchiveKey] = [m3N1WrongRow, m3N1HonestRow];
await fs.writeFile(path.join(m3N1.sourceDir, '_observer/generation-index.json'),
  JSON.stringify(m3N1Index));
const m3N1Registration = { hash: m3PrevCore, registeredBlock: 100,
  registeredAt: 100, signer: `0x${'12'.repeat(20)}` };
const m3N1Chain = { ...m3N1.chain,
  getResultHash: async (block) => Number(block) === 0
    ? m3N1Registration : { hash: null },
  resultRegistrationCount: async () => 1,
  resultRegistrationAt: async () => m3N1Registration,
};
const m3N1Picked = await resolveEmergencyGenerationMap({ sourceDir: m3N1.sourceDir,
  chain: m3N1Chain, blockNum: 1, authority: 'gcp', pins: {
    ...p15Pins, claimDataFormat: 'chunked-v1',
  } });
ok('M3: N>=1 の GCP 入口は前ブロック2鍵と完了アーカイブを選ぶ',
  m3N1Picked.fileMap.get(m3PrevManifestKey) === m3PrevManifestRow.savedFile
    && m3N1Picked.fileMap.get(m3PrevSummaryKey) === m3PrevSummaryRow.savedFile
    && m3N1Picked.fileMap.get(m3N1ArchiveKey) === m3N1HonestRow.savedFile
    && m3N1Picked.differences.some((d) => d.checkId === 'emergency.gcpGroupArchiveGeneration'
      && d.rebuilt.candidates[0]?.sha256 === m3N1WrongRow.sha256));
const p16FirstSeenIndex = structuredClone(p16FallbackIndex);
p16FirstSeenIndex.objects['entries/block4/game_groups.json'][0].observedAt
  = new Date(250000).toISOString();
p16FirstSeenIndex.objects['entries/block4/game_groups.json'][0].firstSeenAt
  = new Date(280000).toISOString();
p16FirstSeenIndex.objects['entries/block4/game_groups.json'][1].observedAt
  = new Date(280000).toISOString();
p16FirstSeenIndex.objects['entries/block4/game_groups.json'][1].firstSeenAt
  = new Date(250000).toISOString();
const p16FirstSeen = await p15GcpCase([
  p15HistoryRow(0, p15FalseCore, 200), p15HistoryRow(1, p15HonestCore, 230),
], 255, { candidateIndex: p16FirstSeenIndex });
ok('M9a: 名簿索引pinがあれば観測時刻より索引を採る',
  p16FirstSeen.groups.row.savedFile === p15HonestGroupRow.savedFile
    && p16FirstSeen.differences.some((d) => d.checkId === 'emergency.gcpGroupsGeneration'
      && d.rebuilt?.selectedGroupStage === 'roster-anchor'));
const m9aHostileObservation = structuredClone(p16FirstSeenIndex);
m9aHostileObservation.objects['entries/block4/game_groups.json'][0].firstSeenAt = 'ATTACKER_CANARY';
const m9aHostilePicked = await p15GcpCase([
  p15HistoryRow(0, p15FalseCore, 200), p15HistoryRow(1, p15HonestCore, 230),
], 255, { candidateIndex: m9aHostileObservation });
ok('M9a: 観測時刻の攻撃者文字列をGCP差分へ写さない',
  m9aHostilePicked.groups.row.savedFile === p15HonestGroupRow.savedFile
    && !JSON.stringify(m9aHostilePicked.differences).includes('ATTACKER_CANARY'));
const p16MissingPinIndex = structuredClone(p16FallbackIndex);
p16MissingPinIndex.objects['entries/block4/game_groups.json'][1].observedAt
  = new Date(250000).toISOString();
const p16MissingPin = await p15GcpCase([
  p15HistoryRow(0, p15FalseCore, 200), p15HistoryRow(1, p15HonestCore, 400),
], 255, { candidateIndex: p16MissingPinIndex, anchorHash: `0x${'ee'.repeat(32)}` })
  .catch((error) => error);
ok('M9a: 正典manifestの保存世代が無ければ観測順へ戻らず停止',
  p16MissingPin instanceof Error
    && /index=0.*hash=0xeeee.*generations=1/.test(p16MissingPin.message));
const p16UnpinnedRosterRow = await p15Save('roster-no-index-pin',
  { blockNum: p15Block, groups: [] });
const p16UnpinnedIndex = structuredClone(p16MissingPinIndex);
p16UnpinnedIndex.objects['games/block4/roster/manifest.json'] = [p16UnpinnedRosterRow];
const p16Unpinned = await p15GcpCase([
  p15HistoryRow(0, p15FalseCore, 200), p15HistoryRow(1, p15HonestCore, 400),
], 255, { candidateIndex: p16UnpinnedIndex,
  anchorHash: keccak256(await fs.readFile(path.join(taskTmp, p16UnpinnedRosterRow.savedFile))) })
  .catch((error) => error);
ok('M9a: 正典manifestに索引pinが無ければ観測順へ戻らず停止',
  p16Unpinned instanceof Error && /index=0.*generations=1/.test(p16Unpinned.message));
const p14MissingCurrentSummary = structuredClone(p6Index);
delete p14MissingCurrentSummary.objects[`games/block${p6Block}/summary.json`];
await fs.writeFile(path.join(p6EmergencyDir, '_observer/generation-index.json'),
  JSON.stringify(p14MissingCurrentSummary));
const p14MissingSummaryResolved = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir, chain: p6EmergencyChain(), blockNum: p6Block,
});
ok('P14: N+1 summary保存無しはU-4選択へ入らず起点の現在目印経路へ戻す',
  p14MissingSummaryResolved.previousResultRegistration?.selectionRule
    === 'HashStorage.getResultHash current value (unchanged)'
    && !p14MissingSummaryResolved.fileMap.has(`games/block${p6Block}/summary.json`),
  JSON.stringify(p14MissingSummaryResolved.previousResultRegistration));
await fs.writeFile(path.join(p6EmergencyDir, '_observer/generation-index.json'), JSON.stringify(p6Index));
await fs.writeFile(path.join(p6EmergencyDir, '_observer/generation-index.json'),
  JSON.stringify(p6SameMajorIndex));
const p14InnerFalseOuterTrue = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir, blockNum: p6Block,
  chain: p6EmergencyChain([
    { ...p6HistoryRows[1], index: 0, registeredAt: 200 },
    { ...p6HistoryRows[0], index: 1, registeredAt: 400 },
    { index: 2, hash: p6SameMajorCore, registeredBlock: 50, registeredAt: 500,
      signer: `0x${'a4'.repeat(20)}` },
  ]),
}).catch((error) => error);
ok('M11b UJ1: 窓内の偽版が再現せず窓外の2版が再現しても採らない',
  p14InnerFalseOuterTrue instanceof Error
    && /recorded previous/.test(p14InnerFalseOuterTrue.message));
const p14PreferredStops = await resolveEmergencyGenerationMap({
  sourceDir: p6EmergencyDir, blockNum: p6Block,
  chain: p6EmergencyChain([
    { ...p6HistoryRows[0], index: 0, registeredAt: 300 },
    { ...p6HistoryRows[1], index: 1, registeredAt: 400 },
    { index: 2, hash: p6SameMajorCore, registeredBlock: 50, registeredAt: 500,
      signer: `0x${'a4'.repeat(20)}` },
  ]),
});
ok('P14: 窓内に再現版があれば窓外の保存版は評価予算を使わない',
  p14PreferredStops.previousResultRegistration?.selectedIndex === 0
    && p14PreferredStops.previousResultRegistration?.budgets?.evaluations?.used === 1,
  JSON.stringify(p14PreferredStops.previousResultRegistration?.budgets));
await fs.writeFile(path.join(p6EmergencyDir, '_observer/generation-index.json'), JSON.stringify(p6Index));

for (const [kind, key, limit] of [
  ['manifest', p6ManifestKey, PREVIOUS_MANIFEST_GENERATION_LIMIT],
  ['summary', p6SummaryKey, PREVIOUS_SUMMARY_GENERATION_LIMIT],
]) {
  const oversizedIndex = structuredClone(p6Index);
  oversizedIndex.objects[key] = Array.from(
    { length: limit + 1 },
    (_, generation) => ({
      ...(kind === 'manifest' ? p6OldManifestRow : p6OldSummaryRow),
      generation: generation + 1,
      observationOrdinal: `${String(generation).padStart(8, '0')}:00000000`,
    }),
  );
  let generationResult = null;
  try {
    generationResult = await loadPreviousResultVersionCandidates({
      sourceDir: p6EmergencyDir,
      index: oversizedIndex,
      chain: p6EmergencyChain(),
      blockNum: p6Block,
    });
  } catch (error) { generationResult = error; }
  ok(`P6b R30-U-4: ${kind}保存世代が2048件を超えても登録時点の版を選べる`,
    generationResult?.candidates?.[0]?.status === 'ready'
      && generationResult?.budgets?.[kind === 'manifest' ? 'manifests' : 'summaries']?.used === limit + 1,
    JSON.stringify({ status: generationResult?.candidates?.[0]?.status, error: generationResult?.message }));
}

const p6BrokenGroups = structuredClone(p6GameGroups);
p6BrokenGroups.groups[0].memberIds[0] = 'not-a-real-player';
const p6BrokenGroupsRow = await p6Save('game-groups-broken.bin', p6BrokenGroups);
p6Index.objects[`entries/block${p6Block}/game_groups.json`] = [{
  ...p6BrokenGroupsRow, generation: 2, observationOrdinal: '00000003:00000000',
}];
p6CurrentManifest.files[`entries/block${p6Block}/game_groups.json`] = p6BrokenGroupsRow.sha256;
p6CurrentManifest.manifestHash = manifestCoreHash(p6CurrentManifest);
const p6BrokenCurrentManifestRow = await p6Save('current-manifest-broken.bin', p6CurrentManifest);
p6Index.objects[`verification/block${p6Block}/manifest.json`] = [{
  ...p6BrokenCurrentManifestRow, generation: 2, observationOrdinal: '00000003:00000001',
}];
await fs.writeFile(
  path.join(p6EmergencyDir, '_observer/generation-index.json'),
  JSON.stringify(p6Index),
);
let p6NoCandidateError = null;
try {
  await resolveEmergencyGenerationMap({
    sourceDir: p6EmergencyDir,
    chain: p6EmergencyChain(),
    blockNum: p6Block,
  });
} catch (error) { p6NoCandidateError = error; }
ok('P6 R30-C-4-01 負: 実際の組を再現できるNの履歴候補が0件なら候補一覧つきで止まる',
  /reproduce|再現/.test(p6NoCandidateError?.message || '')
    && p6NoCandidateError?.emergencyDifferences?.some((difference) => (
      difference.checkId === 'check.stageB.prevAnchor'
        && Array.isArray(difference.rebuilt?.candidates)
        && difference.rebuilt.candidates.length === 1
        && difference.rebuilt.candidates[0].status === 'ready'
    )),
  JSON.stringify({
    message: p6NoCandidateError?.message,
    differences: p6NoCandidateError?.emergencyDifferences,
  }));


chain.getResultHash = async (block) => ({
  hash: Number(block) === 3 ? `0x${'39'.repeat(32)}` : manifest.manifestHash,
});
let previousMismatch = null;
try { await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 }); }
catch (error) { previousMismatch = error; }
ok('U4-C1 前ブロック目印に一致するmanifest世代が無ければ復旧方法と差を付けて停止する',
  /正しい manifest core を登録してから再実行してください/.test(previousMismatch?.message || '')
  && previousMismatch?.emergencyDifferences?.some((difference) => difference.checkId === 'check.stageB.prevAnchor'));

chain.getResultHash = async (block) => ({ hash: Number(block) === 3 ? previousCore : manifest.manifestHash });

chain.getResultHash = async () => null;
let missingResultMarkerError = null;
try { await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 }); }
catch (error) { missingResultMarkerError = error; }
ok('U4-C2 resultHash未登録なら無認証manifestを採らず、運営の次の一手を示して停止する',
  /正しい manifest core を登録してから再実行してください/.test(missingResultMarkerError?.message || '')
  && missingResultMarkerError?.emergencyDifferences?.some((difference) => (
    difference.what === 'result manifest marker is absent'
  )));
const resolvedWithoutResultMarker = { differences: missingResultMarkerError?.emergencyDifferences || [] };
chain.getResultHash = async () => ({ hash: `0x${'44'.repeat(32)}`, updated: 88 });
let unknownResultMarkerError = null;
try { await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 }); }
catch (error) { unknownResultMarkerError = error; }
ok('U4-C2 保存世代に無いresultHashでも無認証manifestを権威にせず停止する',
  /正しい manifest core を登録してから再実行してください/.test(unknownResultMarkerError?.message || '')
  && unknownResultMarkerError?.emergencyDifferences?.some((difference) => (
    difference.chain?.hash === `0x${'44'.repeat(32)}`
  )));
const resolvedWithUnknownResultMarker = {
  chainResultMarker: { hash: `0x${'44'.repeat(32)}`, updated: 88 },
  differences: unknownResultMarkerError?.emergencyDifferences || [],
};
chain.getResultHash = async (block) => ({
  hash: Number(block) === 3 ? previousCore : manifest.manifestHash,
  updated: 80,
});

const conflictingManifestRow = await save(
  '_observer/generations/verification/manifest/000002.bin',
  JSON.stringify({ ...manifest, createdAt: '2026-09-16T01:00:00.000Z' }),
);
index.objects['verification/block4/manifest.json'].push({
  ...conflictingManifestRow, generation: 2, observationOrdinal: '00000001:00000000',
});
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const resolvedEquivalentManifestBytes = await resolveEmergencyGenerationMap({
  sourceDir: taskTmp, chain, blockNum: 4,
});
ok('U4-C3 同じcoreで付加欄だけ違うmanifest世代はbytes差を記録して続ける',
  resolvedEquivalentManifestBytes.fileMap.get('verification/block4/manifest.json') === manifestRow.savedFile
  && resolvedEquivalentManifestBytes.differences.some((difference) => difference.checkId === 'emergency.manifestBytes'));
index.objects['verification/block4/manifest.json'].pop();
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));

index.objects['games/block4/claim-status.json'] = [
  { ...(await save('_observer/generations/claim-status/one.bin', '{"claimed":0}')), generation: 1, observationOrdinal: '1' },
  { ...(await save('_observer/generations/claim-status/two.bin', '{"claimed":1}')), generation: 2, observationOrdinal: '2' },
];
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const resolvedWithMutableStatus = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
ok('U1c 計算に使わずmanifestにも無い可変statusの複数世代は選択対象にしない',
  !resolvedWithMutableStatus.fileMap.has('games/block4/claim-status.json'));
delete index.objects['games/block4/claim-status.json'];

const honestInfos = Array.from({ length: 100 }, () => ({ entries: [] }));
honestInfos[0] = { entries: [{ filename: '00_1', number: 1 }] };
const honestEntries = new Map([['00_1', [{ uid: '10', addr: '0x10' }]]]);
const attackerEntries = [{ uid: '99', addr: '0x99' }];
const applicantHash = applicantRoot(4, honestInfos, honestEntries);
const attackerApplicantHash = applicantRoot(4, honestInfos, new Map([['00_1', attackerEntries]]));
let applicantRegistrations = [
  { hash: applicantHash, registeredBlock: 6, signer: '0xhonest' },
  { hash: attackerApplicantHash, registeredBlock: 7, signer: '0xattacker' },
];
chain.getApplicantHash = async () => ({ hash: attackerApplicantHash, updated: 7 });
chain.applicantRegistrationCount = async () => applicantRegistrations.length;
chain.applicantRegistrationAt = async (_blockNum, registrationIndex) => applicantRegistrations[registrationIndex];
chain.getTimingConstants = async () => ({ startTimeEntryMs: 0, blockTimeMs: 1000 });
chain.getBlock = async (blockNumber) => ({ timestamp: Number(blockNumber) });
for (let worker = 0; worker < 100; worker++) {
  const workerName = String(worker).padStart(2, '0');
  const infoText = JSON.stringify(honestInfos[worker]);
  const row = await save(`_observer/generations/info/${workerName}-honest.bin`, infoText);
  index.objects[`entries/block4/info/${workerName}_info.json`] = [
    { ...row, generation: 1, observationOrdinal: `00000100:${workerName}` },
  ];
}
const honestEntryRow = await save(
  '_observer/generations/entries/00_1-honest.bin', JSON.stringify(honestEntries.get('00_1')),
);
const attackerEntryRow = await save(
  '_observer/generations/entries/00_1-attacker.bin', JSON.stringify(attackerEntries),
);
index.objects['entries/block4/entries/00_1.json'] = [
  { ...honestEntryRow, generation: 1, observationOrdinal: '00000200:00000000' },
];
const honestIntermediateRow = await save(
  '_observer/generations/entries/intermediate-honest.bin',
  JSON.stringify(applicantIntermediate(4, honestInfos, honestEntries)),
);
const attackerIntermediateRow = await save(
  '_observer/generations/entries/intermediate-attacker.bin',
  JSON.stringify(applicantIntermediate(4, honestInfos, new Map([['00_1', attackerEntries]]))),
);
index.objects['entries/block4/intermediate_hash.json'] = [
  { ...honestIntermediateRow, generation: 1, observationOrdinal: '00000199:00000000' },
  { ...attackerIntermediateRow, generation: 2, observationOrdinal: '00000199:00000001' },
];
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const m11aEntryKey = 'entries/block4/entries/00_1.json';
const m11aOriginalEntryRows = index.objects[m11aEntryKey];
const m11aLargeRelative = '_observer/generations/entries/m11a-stat-large.bin';
await fs.writeFile(path.join(taskTmp, m11aLargeRelative), '');
await fs.truncate(path.join(taskTmp, m11aLargeRelative), GCP_GENERATION_BYTE_LIMIT + 1);
await fs.chmod(path.join(taskTmp, m11aLargeRelative), 0o000);
const m11aInvalidJsonRow = await save('_observer/generations/entries/m11a-invalid-json.bin', '{not-json');
index.objects[m11aEntryKey] = [
  { savedFile: '_observer/generations/entries/m11a-absent.bin',
    sha256: 'a'.repeat(64), bytes: GCP_GENERATION_BYTE_LIMIT + 1,
    generation: 0, observationOrdinal: '00000000:00000000' },
  { savedFile: m11aLargeRelative, sha256: 'b'.repeat(64), bytes: 1,
    generation: 0, observationOrdinal: '00000000:00000001' },
  { ...m11aInvalidJsonRow, generation: 0, observationOrdinal: '00000000:00000002' },
  ...m11aOriginalEntryRows,
];
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const m11aEntryGuarded = await resolveEmergencyGenerationMap({
  sourceDir: taskTmp, chain, blockNum: 4,
});
ok('M11a: entries の宣言・stat バイト関所は別世代の正直な応募 root を残す',
  m11aEntryGuarded.applicantRegistration?.hash === applicantHash.toLowerCase()
  && m11aEntryGuarded.differences.filter((difference) =>
    difference.checkId === 'emergency.applicantDiscardedGenerations'
      && difference.reason === 'individual row byte limit'
      && [GCP_GENERATION_BYTE_LIMIT + 1, 1].includes(difference.chain?.bytes)).length >= 2
  && m11aEntryGuarded.differences.some((difference) =>
    difference.checkId === 'emergency.applicantDiscardedGenerations'
      && difference.reason === 'invalid JSON'
      && difference.chain?.sha256 === m11aInvalidJsonRow.sha256));
index.objects[m11aEntryKey] = m11aOriginalEntryRows;
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const m11aOptionIndex = structuredClone(index);
const m11aInfoKey = 'entries/block4/info/00_info.json';
const m11aDecoyInfoRows = [];
for (const [i, filename] of ['00_2', '00_3', '00_4'].entries()) {
  const row = await save(`_observer/generations/info/m11a-option-${i}.bin`,
    JSON.stringify({ entries: [{ filename, number: 1 }] }));
  m11aDecoyInfoRows.push({ ...row, generation: i,
    observationOrdinal: `00000000:0000000${i}` });
  m11aOptionIndex.objects[`entries/block4/entries/${filename}.json`] = [attackerEntryRow];
}
m11aOptionIndex.objects[m11aInfoKey] = [...m11aDecoyInfoRows,
  { ...index.objects[m11aInfoKey][0], observationOrdinal: '00000000:00000003' }];
const m11aOptionSelected = await selectApplicantGenerationCombination({
  sourceDir: taskTmp, index: m11aOptionIndex, chain, blockNum: 4,
  applicantRoot: applicantHash, workerOptionLimit: 2,
});
const m11aExpectedWorkerFingerprints = honestInfos.map((info, worker) => {
  const infoKey = `entries/block4/info/${String(worker).padStart(2, '0')}_info.json`;
  const identifiers = [[infoKey, digest(Buffer.from(JSON.stringify(info)))]];
  for (const entry of info.entries) {
    const entryKey = `entries/block4/entries/${entry.filename}.json`;
    identifiers.push([entryKey, digest(Buffer.from(JSON.stringify(honestEntries.get(entry.filename))))]);
  }
  return digest(Buffer.from(JSON.stringify(identifiers)));
});
ok('M11a: worker 件数上限の囮3本の後でも intermediate が要求する正直な選択肢を残す',
  m11aOptionSelected.registration.hash === applicantHash.toLowerCase()
  && m11aOptionSelected.differences.some((difference) =>
    difference.checkId === 'emergency.applicantDiscardedGenerations'
    && difference.rebuilt?.attempts?.some((attempt) => attempt.budgetExceeded?.some((budget) =>
      budget.reason === 'worker option count limit' && budget.limit === 2))),
  JSON.stringify(m11aOptionSelected.differences));
ok('M11a: 採用した worker と全体の fingerprint は入力識別子の digest と一致する',
  m11aOptionSelected.fingerprint === digest(Buffer.from(JSON.stringify(m11aExpectedWorkerFingerprints))));
const m11aByteLimited = await selectApplicantGenerationCombination({
  sourceDir: taskTmp, index, chain, blockNum: 4,
  applicantRoot: applicantHash, selectedByteLimit: 5,
}).catch((error) => error);
const m11aByteAllowed = await selectApplicantGenerationCombination({
  sourceDir: taskTmp, index, chain, blockNum: 4,
  applicantRoot: applicantHash, selectedByteLimit: 1_000_000,
});
ok('M11a: 組の合計バイト関所は当該候補だけを評価不能にし上限内なら通す',
  m11aByteLimited instanceof Error
  && m11aByteLimited.emergencyDifferences?.some((difference) =>
    difference.checkId === 'emergency.applicantRegistrationOverrideRejected'
    && difference.rebuilt?.evaluationIssues?.some((issue) =>
      issue.budgetExceeded?.some((budget) => budget.limit === 5)))
  && m11aByteAllowed.registration.hash === applicantHash.toLowerCase());

// ==================================================================
// 🔴 便 Z11 / R29-A-3b-03 / R29-A-4b-01
// number だけが違う2世代のうち、新rootに合う1本だけを選ぶ。
// root 材料から number を落とす変異では旧root側に2本とも合い、
// worker 00 を一意に決められず赤になる。
// ==================================================================
const z11OriginalRegistrations = applicantRegistrations;
const z11InfoNumberOnlyRow = await save(
  '_observer/generations/info/00-z11-number-only.bin',
  JSON.stringify({ entries: [{ filename: '00_1', number: 777 }] }),
);
index.objects['entries/block4/info/00_info.json'].push({
  ...z11InfoNumberOnlyRow, generation: 4, observationOrdinal: '00000103:00000000',
});
const z11LegacyIntermediate = legacyApplicantIntermediate(4, honestInfos, honestEntries);
const z11LegacyIntermediateRow = await save(
  '_observer/generations/entries/intermediate-z11-legacy.bin',
  JSON.stringify(z11LegacyIntermediate),
);
index.objects['entries/block4/intermediate_hash.json'].push({
  ...z11LegacyIntermediateRow, generation: 4, observationOrdinal: '00000199:00000003',
});
const z11LegacyRoot = `0x${hashLikeBackend(z11LegacyIntermediate)}`;
applicantRegistrations = [
  { hash: z11LegacyRoot, registeredBlock: 6, signer: '0xlegacy' },
  { hash: applicantHash, registeredBlock: 7, signer: '0xnumber-bound' },
];
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const z11ResolvedNumberGeneration = await resolveEmergencyGenerationMap({
  sourceDir: taskTmp, chain, blockNum: 4,
});
ok('Z11 (c) number だけ違う2世代が保存されても、緊急復旧は登録済み applicantHash に合う1本を一意に選び完走する',
  z11ResolvedNumberGeneration.applicantRegistration.hash === applicantHash.toLowerCase()
    && z11ResolvedNumberGeneration.fileMap.get('entries/block4/info/00_info.json')
      === index.objects['entries/block4/info/00_info.json'][0].savedFile,
  JSON.stringify(z11ResolvedNumberGeneration.applicantRegistration));
applicantRegistrations = z11OriginalRegistrations;
index.objects['entries/block4/info/00_info.json'].pop();
index.objects['entries/block4/intermediate_hash.json'].pop();
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));

const resolvedSingleApplicant = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
ok('T2 最新ビューが別hashでも、保存データに一致する履歴登録を採る',
  resolvedSingleApplicant.fileMap.get('entries/block4/entries/00_1.json') === honestEntryRow.savedFile
  && resolvedSingleApplicant.applicantRegistration.index === 0
  && resolvedSingleApplicant.applicantRegistration.hash === applicantHash.toLowerCase());
ok('U4-C4 自己認証したintermediateからworker単位の線形選択を使う',
  resolvedSingleApplicant.applicantSelectionStats?.strategy === 'intermediate-worker-linear'
  && resolvedSingleApplicant.applicantSelectionStats.candidateEvaluations === 100,
  JSON.stringify(resolvedSingleApplicant.applicantSelectionStats));
ok('Z13 (f) 再現できる登録が1本だけなら指定なしの採用世代・登録・差分・従来統計は変更前の既定と同一である',
  resolvedSingleApplicant.fileMap.get('entries/block4/entries/00_1.json') === honestEntryRow.savedFile
  && resolvedSingleApplicant.applicantRegistration.index === 0
  && resolvedSingleApplicant.applicantRegistration.hash === applicantHash.toLowerCase()
  && resolvedSingleApplicant.applicantSelectionStats?.strategy === 'intermediate-worker-linear'
  && resolvedSingleApplicant.applicantSelectionStats?.candidateEvaluations === 100
  && !resolvedSingleApplicant.differences.some((difference) => (
    difference.checkId === 'emergency.applicantRegistrationOverride'
    || difference.checkId === 'emergency.applicantRegistrationAmbiguous'
  )),
  JSON.stringify({
    registration: resolvedSingleApplicant.applicantRegistration,
    stats: resolvedSingleApplicant.applicantSelectionStats,
    differences: resolvedSingleApplicant.differences,
  }));

// M4: hostile nesting is rejected per generation, so it cannot consume the honest input's budget.
const m4Deep = (depth) => `${'['.repeat(depth)}0${']'.repeat(depth)}`;
const m4EntryKey = 'entries/block4/entries/00_1.json';
const m4IntermediateKey = 'entries/block4/intermediate_hash.json';
const m4InfoKey = 'entries/block4/info/00_info.json';
const m4DeepEntry = await save('_observer/generations/entries/m4-deep-entry.bin', m4Deep(30000));
const m4HonestIntermediate = applicantIntermediate(4, honestInfos, honestEntries);
const m4DeepIntermediate = await save('_observer/generations/entries/m4-deep-intermediate.bin',
  `${JSON.stringify(m4HonestIntermediate).slice(0, -1)},"extra":${m4Deep(30000)}}`);
const m4DeepInfo = await save('_observer/generations/info/m4-deep-info.bin',
  `{"entries":[{"filename":${m4Deep(30000)},"number":1}]}`);
index.objects[m4EntryKey].push({ ...m4DeepEntry, generation: 30, observationOrdinal: '00000230:00000000' });
index.objects[m4IntermediateKey].push({ ...m4DeepIntermediate, generation: 30, observationOrdinal: '00000231:00000000' });
index.objects[m4InfoKey].push({ ...m4DeepInfo, generation: 30, observationOrdinal: '00000232:00000000' });
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const m4DeepResolved = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
ok('M4: 深さ30000のentries／intermediate／info世代を各自で外し正直な応募者を採る',
  m4DeepResolved.applicantRegistration.hash === resolvedSingleApplicant.applicantRegistration.hash
  && m4DeepResolved.differences.filter((difference) => (
    difference.reason === 'JSON depth limit'
  )).length === 3);
ok('M4: 深いfilenameの生値を差分へ写さずJSON書き出しが完走する',
  JSON.stringify(m4DeepResolved.differences).length < 20000
  && !JSON.stringify(m4DeepResolved.differences).includes('[[[[['));
index.objects[m4EntryKey].pop();
index.objects[m4IntermediateKey].pop();
index.objects[m4InfoKey].pop();
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));

const m4Depth5000 = await save('_observer/generations/entries/m4-depth5000.bin', m4Deep(5000));
index.objects[m4EntryKey].push({ ...m4Depth5000, generation: 32,
  observationOrdinal: '00000234:00000000' });
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const m4Depth5000Resolved = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
ok('M4: 深さ5000の対照世代があっても正直な世代を同じrootで採る',
  m4Depth5000Resolved.applicantRegistration.hash === resolvedSingleApplicant.applicantRegistration.hash);
index.objects[m4EntryKey].pop();
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));

const m4ShallowMalformedInfo = await save('_observer/generations/info/m4-malformed-info.bin',
  JSON.stringify({ entries: [{ filename: { nested: ['untrusted'] }, number: 1 }] }));
index.objects[m4InfoKey].push({ ...m4ShallowMalformedInfo, generation: 31,
  observationOrdinal: '00000233:00000000' });
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const m4MalformedResolved = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
const m4Discarded = m4MalformedResolved.differences.find((difference) => (
  difference.chain?.discarded?.some((item) => item.generation === 31)
));
ok('M4: 形の悪いinfoは型と件数だけを差分へ残す',
  m4Discarded?.chain.discarded[0].entryTypes?.object === 1
  && !JSON.stringify(m4Discarded).includes('untrusted'));
index.objects[m4InfoKey].pop();
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));

index.objects['entries/block4/entries/00_1.json'].push(
  { ...attackerEntryRow, generation: 2, observationOrdinal: '00000201:00000000' },
);
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
let z13AmbiguityError = null;
try {
  await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
} catch (error) { z13AmbiguityError = error; }
const z13AmbiguityDifference = z13AmbiguityError?.emergencyDifferences?.find(
  (difference) => difference.checkId === 'emergency.applicantRegistrationAmbiguous',
);
const z13AmbiguityMaterial = z13AmbiguityDifference?.chain?.eligibleRegistrations || [];
const z13FirstCandidateDifference = z13AmbiguityDifference?.rebuilt?.firstDifferences?.[0];
ok('Z13 (a) 再現できる適格登録が2本あると拒否し、両方の root・登録ブロック・応募者総数・最初に食い違うワーカーとファイルを出す',
  z13AmbiguityError !== null
  && z13AmbiguityMaterial.length === 2
  && z13AmbiguityMaterial[0].hash === applicantHash.toLowerCase()
  && z13AmbiguityMaterial[1].hash === attackerApplicantHash.toLowerCase()
  && z13AmbiguityMaterial[0].registeredBlock === 6
  && z13AmbiguityMaterial[1].registeredBlock === 7
  && z13AmbiguityMaterial.every((registration) => (
    registration.applicantCount === 1
    && /caller-supplied/.test(registration.signerWarning)
  ))
  && z13FirstCandidateDifference?.worker === 0
  && z13FirstCandidateDifference?.filename === '00_1.json'
  && z13FirstCandidateDifference?.leftRows === 1
  && z13FirstCandidateDifference?.rightRows === 1
  && z13AmbiguityDifference?.rebuilt?.evaluationStats?.eligibleRegistrationsEvaluated === 2
  && /--emergency-applicant-registration <INDEX>/.test(z13AmbiguityError.message)
  && /--emergency-applicant-root <HASH>/.test(z13AmbiguityError.message),
  JSON.stringify({ message: z13AmbiguityError?.message, difference: z13AmbiguityDifference }));

const z13IndexSelected = await resolveEmergencyGenerationMap({
  sourceDir: taskTmp, chain, blockNum: 4, applicantRegistrationIndex: 1,
});
ok('Z13 (b) 添字を指定すると、添字が小さい方ではなく指定した方の応募者世代が採用される',
  z13IndexSelected.applicantRegistration.index === 1
  && z13IndexSelected.applicantRegistration.hash === attackerApplicantHash.toLowerCase()
  && z13IndexSelected.fileMap.get('entries/block4/entries/00_1.json') === attackerEntryRow.savedFile,
  JSON.stringify(z13IndexSelected.applicantRegistration));

const z13RootSelected = await resolveEmergencyGenerationMap({
  sourceDir: taskTmp, chain, blockNum: 4, applicantRoot: attackerApplicantHash.toUpperCase().replace('0X', '0x'),
});
ok('Z13 (c) root を指定しても添字指定と同じ応募者世代が採用される',
  z13RootSelected.applicantRegistration.index === z13IndexSelected.applicantRegistration.index
  && z13RootSelected.applicantRegistration.hash === z13IndexSelected.applicantRegistration.hash
  && z13RootSelected.fileMap.get('entries/block4/entries/00_1.json')
    === z13IndexSelected.fileMap.get('entries/block4/entries/00_1.json'),
  JSON.stringify(z13RootSelected.applicantRegistration));

const z13OverrideDifferences = z13IndexSelected.differences.filter(
  (difference) => difference.checkId === 'emergency.applicantRegistrationOverride',
);
const z13OverrideCategory = categorizeEmergencyWrite({ differences: z13IndexSelected.differences }, {});
ok('Z13 (d) 指定を使うと専用差分が1件積まれ、飛ばした添字と root が載り、終了コードは4になる',
  z13OverrideDifferences.length === 1
  && z13OverrideDifferences[0].rebuilt?.specifiedBy === 'index'
  && z13OverrideDifferences[0].chain?.selected?.index === 1
  && z13OverrideDifferences[0].chain?.selected?.root === attackerApplicantHash.toLowerCase()
  && z13OverrideDifferences[0].chain?.skipped?.length === 1
  && z13OverrideDifferences[0].chain.skipped[0].index === 0
  && z13OverrideDifferences[0].chain.skipped[0].root === applicantHash.toLowerCase()
  && z13OverrideCategory === 'emergency_with_differences'
  && EXIT_CODE_OF[z13OverrideCategory] === 4,
  JSON.stringify(z13OverrideDifferences));

const z13ResolvedApplicant = z13IndexSelected;

const z13OneRegistration = applicantRegistrations;
applicantRegistrations = [{ hash: applicantHash, registeredBlock: 6, signer: '0xone' }];
const z13WorkOneStart = performance.now();
const z13WorkOne = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
const z13WorkOneElapsedMs = performance.now() - z13WorkOneStart;
applicantRegistrations = Array.from({ length: 4 }, (_, indexOfRegistration) => ({
  hash: applicantHash, registeredBlock: 6 + indexOfRegistration, signer: `0xrepeat${indexOfRegistration}`,
}));
const z13WorkFourStart = performance.now();
let z13WorkFourError = null;
try {
  await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
} catch (error) { z13WorkFourError = error; }
const z13WorkFourElapsedMs = performance.now() - z13WorkFourStart;
const z13WorkFourStats = z13WorkFourError?.emergencyDifferences?.find(
  (difference) => difference.checkId === 'emergency.applicantRegistrationAmbiguous',
)?.rebuilt?.evaluationStats;
ok('P8b P3: 適格登録4本でも同じ応募候補の評価結果を再利用し、候補評価総数は1本分のまま',
  z13WorkFourStats?.eligibleRegistrationsEvaluated === 4
  && z13WorkFourStats?.intermediateAttempts === 1
  && z13WorkFourStats?.candidateEvaluations === z13WorkOne.applicantEvaluationStats.candidateEvaluations
  && z13WorkFourStats?.workerCombinationVisits === z13WorkOne.applicantEvaluationStats.workerCombinationVisits,
  JSON.stringify({ one: z13WorkOne.applicantEvaluationStats, four: z13WorkFourStats }));
console.log(`Z13_WORK_FACTOR registrations=4 baselineEvaluations=${z13WorkOne.applicantEvaluationStats.candidateEvaluations} totalEvaluations=${z13WorkFourStats?.candidateEvaluations} factor=${(z13WorkFourStats?.candidateEvaluations / z13WorkOne.applicantEvaluationStats.candidateEvaluations).toFixed(3)} baselineElapsedMs=${z13WorkOneElapsedMs.toFixed(3)} totalElapsedMs=${z13WorkFourElapsedMs.toFixed(3)} elapsedFactor=${(z13WorkFourElapsedMs / z13WorkOneElapsedMs).toFixed(3)}`);
applicantRegistrations = z13OneRegistration;

const z13UnknownRoot = `0x${'fe'.repeat(32)}`;
await rejects('Z13 (e-1) 履歴に無い root は、まず正しい root を登録せよという理由で止まる',
  () => resolveEmergencyGenerationMap({
    sourceDir: taskTmp, chain, blockNum: 4, applicantRoot: z13UnknownRoot,
  }),
  /root .* is not present in HashStorage history; register the correct root first/);

const z13BeforeInvalidOverrides = applicantRegistrations;
applicantRegistrations = [
  { hash: applicantHash, registeredBlock: 1, signer: '0xearly' },
  { hash: attackerApplicantHash, registeredBlock: 6, signer: '0xeligible' },
];
await rejects('Z13 (e-2) 適格でない添字は、登録時刻が entryPeriodEnd より前という理由で止まる',
  () => resolveEmergencyGenerationMap({
    sourceDir: taskTmp, chain, blockNum: 4, applicantRegistrationIndex: 0,
  }),
  /registration index 0 is not eligible: .* is before entryPeriodEnd/);

applicantRegistrations = [
  ...z13BeforeInvalidOverrides,
  { hash: `0x${'ff'.repeat(32)}`, registeredBlock: 8, signer: '0xunreproducible' },
];
await rejects('Z13 (e-3) 適格だが保存世代から再現できない指定は、その添字を名指しして止まる',
  () => resolveEmergencyGenerationMap({
    sourceDir: taskTmp, chain, blockNum: 4, applicantRegistrationIndex: 2,
  }),
  /registration index 2 cannot be reproduced from any saved info\/entry generation combination/);
const m11aRootError = await resolveEmergencyGenerationMap({
  sourceDir: taskTmp, chain, blockNum: 4, applicantRoot: `0x${'ff'.repeat(32)}`,
}).catch((error) => error);
const m11aRootMaterial = m11aRootError?.emergencyDifferences?.find((difference) =>
  difference.checkId === 'emergency.applicantRegistrationOverrideRejected')
  ?.chain?.eligibleRegistrations;
ok('M11a: 再現不能 root の拒否差分も、他の再現可能な登録の診断を保持する',
  m11aRootMaterial?.length === 3
    && m11aRootMaterial[0].reproducible === true
    && m11aRootMaterial[1].reproducible === true
    && m11aRootMaterial[2].reproducible === false);
applicantRegistrations = z13BeforeInvalidOverrides;

const cliEntryForZ13 = path.resolve(import.meta.dirname, '../src/index.js');
const z13BothFlags = spawnSync(process.execPath, [
  cliEntryForZ13,
  '--emergency-source', taskTmp, '--emergency-out', path.join(taskTmp, 'unused-z13-out'),
  '--emergency-applicant-registration', '1', '--emergency-applicant-root', attackerApplicantHash,
  '--block', '-1', '--non-interactive', '--lang', 'en',
], { encoding: 'utf8' });
const z13BothUsageError = emergencyApplicantSelectionUsageError(loadConfig([
  '--emergency-source', taskTmp,
  '--emergency-applicant-registration', '1', '--emergency-applicant-root', attackerApplicantHash,
]));
ok('Z13 (e-4) 添字と root の同時指定は、どちらが効くか曖昧という usage エラーで止まる',
  z13BothFlags.status === 64
  && z13BothUsageError?.includes('cannot be used together')
  && z13BothFlags.stderr.includes('cannot be used together'),
  JSON.stringify({ status: z13BothFlags.status, stderr: z13BothFlags.stderr }));

const z13WithoutSource = spawnSync(process.execPath, [
  cliEntryForZ13, '--emergency-applicant-registration', '1',
  '--block', '-1', '--non-interactive', '--lang', 'en',
], { encoding: 'utf8' });
const z13WithoutSourceUsageError = emergencyApplicantSelectionUsageError(loadConfig([
  '--emergency-applicant-registration', '1',
]));
ok('Z13 (e-5) --emergency-source 無しの指定は、緊急入力が必要という usage エラーで止まる',
  z13WithoutSource.status === 64
  && z13WithoutSourceUsageError?.includes('requires --emergency-source')
  && z13WithoutSource.stderr.includes('requires --emergency-source'),
  JSON.stringify({ status: z13WithoutSource.status, stderr: z13WithoutSource.stderr }));

const z13Help = spawnSync(process.execPath, [cliEntryForZ13, '--help'], { encoding: 'utf8' });
ok('Z13 CLI の --help は添字指定と root 指定の両方を表示する',
  z13Help.status === 0
  && z13Help.stdout.includes('--emergency-applicant-registration INDEX')
  && z13Help.stdout.includes('--emergency-applicant-root HASH'));

const resolvedApplicant = z13ResolvedApplicant;

applicantRegistrations = [
  { hash: applicantHash, registeredBlock: 1, signer: '0xearly' },
  { hash: attackerApplicantHash, registeredBlock: 6, signer: '0xfirst-eligible' },
];
const resolvedFirstEligible = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
ok('T2 適格フィルタは締切前の一致を飛ばし、締切後の再現可能な1本を固定する',
  resolvedFirstEligible.fileMap.get('entries/block4/entries/00_1.json') === attackerEntryRow.savedFile
  && resolvedFirstEligible.applicantRegistration.index === 1
  && resolvedFirstEligible.applicantRegistration.registeredBlock === 6);

const originalApplicantRegistrations = applicantRegistrations;
applicantRegistrations = [{ hash: `0x${'ff'.repeat(32)}`, registeredBlock: 6, signer: '0xnone' }];
await rejects('T2 どのinfo/entry組も応募者履歴のどれにも一致しなければ停止する',
  () => resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 }),
  /no saved info\/entry generation combination matches an eligible HashStorage applicantHash registration/);
applicantRegistrations = originalApplicantRegistrations;

const conflictingInfo = JSON.stringify({
  entries: honestInfos[0].entries,
  observedMetadata: 'different bytes ignored by the Stage A root projection',
});
const conflictingInfoRow = await save('_observer/generations/info/00-conflicting.bin', conflictingInfo);
index.objects['entries/block4/info/00_info.json'].push({
  ...conflictingInfoRow, generation: 2, observationOrdinal: '00000101:00000000',
});
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const resolvedEquivalentInfoBytes = await resolveEmergencyGenerationMap({
  sourceDir: taskTmp, chain, blockNum: 4,
});
ok('U4-C3 info付加欄だけが違う世代は論理射影が同じなので差を記録して続ける',
  resolvedEquivalentInfoBytes.fileMap.get('entries/block4/info/00_info.json')
    === index.objects['entries/block4/info/00_info.json'][0].savedFile
  && resolvedEquivalentInfoBytes.differences.some((difference) => (
    difference.checkId === 'emergency.applicantGenerationBytes'
  )));
index.objects['entries/block4/info/00_info.json'].pop();

const logicalConflictRow = await save(
  '_observer/generations/info/00-logical-conflict.bin',
  JSON.stringify({ entries: [{ filename: '00_1', number: 2 }] }),
);
index.objects['entries/block4/info/00_info.json'].push({
  ...logicalConflictRow, generation: 3, observationOrdinal: '00000102:00000000',
});
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const resolvedDifferentNumber = await resolveEmergencyGenerationMap({
  sourceDir: taskTmp, chain, blockNum: 4,
});
ok('U4-C3/Z11 numberの論理内容が違う info は同じworker目印に一致せず、登録rootの世代を選ぶ',
  resolvedDifferentNumber.fileMap.get('entries/block4/info/00_info.json')
    === index.objects['entries/block4/info/00_info.json'][0].savedFile);
index.objects['entries/block4/info/00_info.json'].pop();

const linearNoiseRows = [];
for (let generation = 0; generation < 20; generation++) {
  const row = await save(
    `_observer/generations/entries/00_1-linear-${generation}.bin`,
    JSON.stringify([{ uid: `noise-${generation}`, addr: `0x${generation}` }]),
  );
  linearNoiseRows.push({
    ...row, generation: generation + 10, observationOrdinal: `00000210:${String(generation).padStart(8, '0')}`,
  });
}
index.objects['entries/block4/entries/00_1.json'].push(...linearNoiseRows);
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const linearStart = performance.now();
const resolvedWithTwentyEntryGenerations = await resolveEmergencyGenerationMap({
  sourceDir: taskTmp, chain, blockNum: 4,
});
const linearElapsedMs = performance.now() - linearStart;
ok('U4-C4 応募世代を20本足してもworker単位の候補評価は20件だけ増え、正世代を選ぶ',
  resolvedWithTwentyEntryGenerations.applicantSelectionStats?.strategy === 'intermediate-worker-linear'
  && resolvedWithTwentyEntryGenerations.applicantSelectionStats.candidateEvaluations
    === resolvedFirstEligible.applicantSelectionStats.candidateEvaluations + 20
  && resolvedWithTwentyEntryGenerations.fileMap.get('entries/block4/entries/00_1.json')
    === attackerEntryRow.savedFile
  && resolvedWithTwentyEntryGenerations.differences.some((difference) => (
    difference.checkId === 'emergency.applicantDiscardedGenerations'
  )),
  JSON.stringify({
    base: resolvedFirstEligible.applicantSelectionStats,
    with20: resolvedWithTwentyEntryGenerations.applicantSelectionStats,
    elapsedMs: Number(linearElapsedMs.toFixed(3)),
  }));
console.log(`U4_C4_LINEAR baseEvaluations=${resolvedFirstEligible.applicantSelectionStats?.candidateEvaluations} noisyEvaluations=${resolvedWithTwentyEntryGenerations.applicantSelectionStats?.candidateEvaluations} addedGenerations=${linearNoiseRows.length} elapsedMs=${linearElapsedMs.toFixed(3)}`);
index.objects['entries/block4/entries/00_1.json'].splice(-linearNoiseRows.length);

const savedIntermediateRows = index.objects['entries/block4/intermediate_hash.json'];
delete index.objects['entries/block4/intermediate_hash.json'];
const fallbackNoiseKeys = [];
for (let worker = 0; worker < 10; worker++) {
  const key = `entries/block4/info/${String(worker).padStart(2, '0')}_info.json`;
  const row = await save(
    `_observer/generations/info/${String(worker).padStart(2, '0')}-fallback-noise.bin`,
    JSON.stringify({ entries: [{ filename: `invalid-${worker}`, number: worker }] }),
  );
  index.objects[key].push({ ...row, generation: 99, observationOrdinal: `00000999:${worker}` });
  fallbackNoiseKeys.push(key);
}
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
let invalidFallbackResolved = null;
let invalidFallbackError = null;
try {
  invalidFallbackResolved = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
} catch (error) { invalidFallbackError = error; }
ok('P3 R30-D-1-01 形式外 filename の info 世代は fallback の予算を食わず、差分1行に落として正しい登録を採る',
  invalidFallbackResolved?.applicantRegistration?.index === 1
  && invalidFallbackResolved.differences.some((difference) => (
    difference.checkId === 'emergency.applicantDiscardedGenerations'
    && /filename/.test(difference.what)
  )),
  String(invalidFallbackError?.message || ''));
for (const key of fallbackNoiseKeys) index.objects[key].pop();
index.objects['entries/block4/intermediate_hash.json'] = savedIntermediateRows;

// ==================================================================
// 🔴 便 Z5 / R29-A-4b-02（2026-09-21）
//   主経路（intermediate から worker 単位に解く側）には組み合わせ上限が無く、
//   worker 00 の info を1本置き直して他 worker の応募ファイル名まで宣言させるだけで
//   葉が 2^E に増える（filename は /^\d{2}_\d+$/ しか見ず、自 worker の接頭辞に縛られない）。
//   両方向を全数で測る。止まる: T-a 上限超過は専用の文言で断る ／ T-c 文言は fallback と別物。
//   通る: T-b 正常形は据え置きの評価数で完走 ／ T-d 分岐ノードも予算を食う。
// ==================================================================
const z5AmplifyFilenames = Array.from({ length: 16 }, (_, i) => `00_${i + 1}`);
const z5AmplifyKeys = [];
for (const filename of z5AmplifyFilenames.slice(1)) {
  const key = `entries/block4/entries/${filename}.json`;
  const rowA = await save(
    `_observer/generations/entries/${filename}-z5a.bin`, JSON.stringify([{ uid: `z5a-${filename}` }]),
  );
  const rowB = await save(
    `_observer/generations/entries/${filename}-z5b.bin`, JSON.stringify([{ uid: `z5b-${filename}` }]),
  );
  index.objects[key] = [
    { ...rowA, generation: 1, observationOrdinal: `00000400:${filename}` },
    { ...rowB, generation: 2, observationOrdinal: `00000401:${filename}` },
  ];
  z5AmplifyKeys.push(key);
}

// P8b: 同じ info 候補は登録ごとに歩き直さず、1回の評価結果を全登録で共有する。
const z13BudgetOriginalRegistrations = applicantRegistrations;
const z13BudgetInfoRow = await save(
  '_observer/generations/info/00-z13-budget-decoy.bin',
  JSON.stringify({
    entries: z5AmplifyFilenames.slice(0, 11).map((filename, i) => ({ filename, number: i + 1 })),
  }),
);
index.objects['entries/block4/info/00_info.json'].push({
  ...z13BudgetInfoRow, generation: 40, observationOrdinal: '00000400:z13-budget',
});
const z13BudgetIntermediate = structuredClone(applicantIntermediate(4, honestInfos, honestEntries));
z13BudgetIntermediate.hash[0].hash = 'fe'.repeat(32);
const z13BudgetIntermediateRow = await save(
  '_observer/generations/entries/intermediate-z13-budget.bin',
  JSON.stringify(z13BudgetIntermediate),
);
index.objects['entries/block4/intermediate_hash.json'].push({
  ...z13BudgetIntermediateRow, generation: 40, observationOrdinal: '00000400:z13-budget-intermediate',
});
const z13BudgetDecoyRoot = `0x${hashLikeBackend(z13BudgetIntermediate)}`;
applicantRegistrations = [
  { hash: z13BudgetDecoyRoot, registeredBlock: 6, signer: '0xdecoy0' },
  { hash: z13BudgetDecoyRoot, registeredBlock: 7, signer: '0xdecoy1' },
  { hash: attackerApplicantHash, registeredBlock: 8, signer: '0xcorrect' },
];
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const z13BudgetStart = performance.now();
let z13BudgetResolved = null;
let z13BudgetError = null;
try {
  z13BudgetResolved = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
} catch (error) { z13BudgetError = error; }
const z13BudgetElapsedMs = performance.now() - z13BudgetStart;
ok('P8b P3: 囮の再登録を増やしても応募候補の探索量は1回分で、正しい3本目を見つける',
  z13BudgetResolved?.applicantRegistration.index === 2
  && z13BudgetResolved?.applicantRegistration.hash === attackerApplicantHash.toLowerCase()
  && z13BudgetResolved.applicantEvaluationStats?.eligibleRegistrationsEvaluated === 3
  && z13BudgetResolved.applicantEvaluationStats?.intermediateAttempts === 2
  && z13BudgetResolved.applicantEvaluationStats?.workerCombinationVisits
    < EMERGENCY_WORKER_COMBINATION_LIMIT,
  JSON.stringify({ stats: z13BudgetResolved?.applicantEvaluationStats, error: z13BudgetError?.message }));
console.log(`Z13_BUDGET_RESET registrations=3 totalWorkerVisits=${z13BudgetResolved?.applicantEvaluationStats?.workerCombinationVisits ?? 'ERROR'} perRegistrationLimit=${EMERGENCY_WORKER_COMBINATION_LIMIT} elapsedMs=${z13BudgetElapsedMs.toFixed(3)}`);
applicantRegistrations = z13BudgetOriginalRegistrations;
index.objects['entries/block4/info/00_info.json'].pop();
index.objects['entries/block4/intermediate_hash.json'].pop();

// T-b 通る側: 保管庫に増幅用の世代が在っても、info が宣言しない限り評価数は据え置き。
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const z5Baseline = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
ok('Z5 R29-A-4b-02 T-b 正常形は据え置きの評価数で完走し、予算は分岐ノードぶんだけ多く消費する',
  z5Baseline.applicantSelectionStats?.strategy === 'intermediate-worker-linear'
  && z5Baseline.applicantSelectionStats.candidateEvaluations
    === resolvedFirstEligible.applicantSelectionStats.candidateEvaluations
  && z5Baseline.applicantSelectionStats.workerCombinationVisits
    > z5Baseline.applicantSelectionStats.candidateEvaluations
  && z5Baseline.applicantSelectionStats.workerCombinationVisits
    < EMERGENCY_WORKER_COMBINATION_LIMIT,
  JSON.stringify(z5Baseline.applicantSelectionStats));
console.log(`Z5_A4B02_BASELINE ${JSON.stringify(z5Baseline.applicantSelectionStats)}`);

// T-a 止まる側: worker 00 の info を1本足して16ファイル名を宣言させると葉が 2^16 になる。
const z5AmplifyInfoRow = await save(
  '_observer/generations/info/00-z5-amplify.bin',
  JSON.stringify({
    entries: z5AmplifyFilenames.map((filename, i) => ({ filename, number: i + 1 })),
  }),
);
index.objects['entries/block4/info/00_info.json'].push({
  ...z5AmplifyInfoRow, generation: 4, observationOrdinal: '00000402:00000000',
});
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
let z5AmplifyMessage = '';
await rejects('Z5 R29-A-4b-02 T-a 主経路でも組み合わせ上限を超えたら専用の文言で断る',
  async () => {
    try {
      return await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
    } catch (error) { z5AmplifyMessage = String(error?.message || ''); throw error; }
  },
  new RegExp(`応募世代の組み合わせが多すぎて一意に決められない.*${EMERGENCY_WORKER_COMBINATION_LIMIT}`));

// 重い囮infoを先頭へ動かす。予算をworker全体で共有する変異なら、その後の正直な
// info候補を評価できない。さらに、別候補のoverflowを理由に既発見matchを捨てる変異も赤になる。
const p8bAmplifyRow = index.objects['entries/block4/info/00_info.json'].pop();
const p8bAmplifyOriginalOrdinal = p8bAmplifyRow.observationOrdinal;
p8bAmplifyRow.observationOrdinal = '00000000:00000000';
index.objects['entries/block4/info/00_info.json'].unshift(p8bAmplifyRow);
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
let p8bMainMatchAfterOverflow = null;
let p8bMainMatchAfterOverflowError = null;
try {
  p8bMainMatchAfterOverflow = await resolveEmergencyGenerationMap({
    sourceDir: taskTmp, chain, blockNum: 4, applicantRegistrationIndex: 1,
  });
} catch (error) { p8bMainMatchAfterOverflowError = error; }
ok('P8b P3: 主経路の予算はinfo候補ごとで、重い囮候補の後でも正直な候補を評価できる',
  p8bMainMatchAfterOverflow?.applicantRegistration?.index === 1,
  String(p8bMainMatchAfterOverflowError?.message || ''));
ok('P8b P3: 別info候補がoverflowしても、既に再現した指定登録の一致は捨てない',
  p8bMainMatchAfterOverflow?.applicantRegistration?.index === 1
  && p8bMainMatchAfterOverflow?.differences?.some((difference) => (
    difference.checkId === 'emergency.applicantDiscardedGenerations'
    && /evaluation-impossible/.test(difference.what)
  )), String(p8bMainMatchAfterOverflowError?.message || ''));
index.objects['entries/block4/info/00_info.json'].shift();
p8bAmplifyRow.observationOrdinal = p8bAmplifyOriginalOrdinal;
index.objects['entries/block4/info/00_info.json'].push(p8bAmplifyRow);
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));

// 🔴 統括（2026-09-22・便 Z5 が作った回帰の歯）: 予算は**適格登録ごとにリセット**する。
//    ブロック全体で1つにすると、攻撃者が囮の適格登録を並べるだけで正直な登録の探索ぶんまで
//    食い潰され、すぐ解ける保管庫が「復旧不能」になる（反証役の実測: 囮25本で恒久停止・
//    便 Z5 以前のコードは同じ盤面で正しく復旧していた）。
//    この歯は「ブロック全体で1つ」へ戻す変異で赤になる。
const z5EmergencySource = await fs.readFile(new URL('../src/emergency.js', import.meta.url), 'utf8');
ok('P3 R30-A-2-02 主経路の予算は info 候補ごとで、filename は自 worker 接頭辞へ束縛される',
  (() => {
    const src = z5EmergencySource;
    const perInfoBudget = /for await \(const infoCandidate of loadInfoChoices\(worker\)\) \{[\s\S]{0,500}?let infoCombinationVisits = 0;/.test(src);
    const typedFilename = /typeof entry\.filename !== 'string'/.test(src);
    const ownWorkerPrefix = /workerName\(worker\)[\s\S]{0,160}?filename/.test(src);
    return perInfoBudget && typedFilename && ownWorkerPrefix;
  })());

// T-c 文言の区別: fallback（中間ファイルが無い）の断り文と取り違えさせない。
ok('Z5 R29-A-4b-02 T-c 主経路の停止文言はfallbackの「中間ファイルが無い」と一致しない',
  z5AmplifyMessage.includes('中間ファイルが無いため緊急復旧できない') === false
  && z5AmplifyMessage.includes('応募世代の組み合わせが多すぎて一意に決められない') === true
  && EMERGENCY_WORKER_COMBINATION_LIMIT !== undefined
  && EMERGENCY_FALLBACK_COMBINATION_LIMIT !== undefined,
  z5AmplifyMessage);
index.objects['entries/block4/info/00_info.json'].pop();

// T-d 分岐ノードも数えること: 葉が2つしか無くても深い宣言は予算を食う。
const z5NarrowKeys = [];
for (const filename of z5AmplifyFilenames.slice(1)) {
  const key = `entries/block4/entries/${filename}.json`;
  index.objects[key] = [index.objects[key][0]];   // 各1世代＝葉は増えない
  z5NarrowKeys.push(key);
}
index.objects['entries/block4/info/00_info.json'].push({
  ...z5AmplifyInfoRow, generation: 5, observationOrdinal: '00000403:00000000',
});
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const z5Narrow = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
const z5NarrowDelta = z5Narrow.applicantSelectionStats.workerCombinationVisits
  - z5Baseline.applicantSelectionStats.workerCombinationVisits;
const z5NarrowLeafDelta = z5Narrow.applicantSelectionStats.candidateEvaluations
  - z5Baseline.applicantSelectionStats.candidateEvaluations;
// P8bでは分岐・葉に加え、実際のentry hashとworker hashも同じ予算へ数える。
// 葉だけを数えると2だが、全仕事量は52である。
ok('P8b P3: 葉が2つでも分岐と実ハッシュの仕事量を応募候補の予算へ数える',
  z5NarrowLeafDelta === 2 && z5NarrowDelta === 52,
  JSON.stringify({ z5NarrowLeafDelta, z5NarrowDelta, stats: z5Narrow.applicantSelectionStats }));
console.log(`Z5_A4B02_NARROW leafDelta=${z5NarrowLeafDelta} budgetDelta=${z5NarrowDelta}`);
index.objects['entries/block4/info/00_info.json'].pop();
for (const key of z5AmplifyKeys) delete index.objects[key];
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));

// ==================================================================
// 🔴 便 P3 / R30-A-2-01, A-2-02, A-5-02, D-1-01, D-5-01
//   - filename は文字列＋自 worker 接頭辞だけを候補にする。
//   - 主経路は info 候補ごと、fallback は登録ごとに独立予算を持つ。
//   - 予算超過を別登録へ伝播させず、指定なしの評価不能だけは fail-closed を維持する。
// ==================================================================
const p3OriginalRegistrations = applicantRegistrations;

const p3PoisonedInfoRow = await save(
  '_observer/generations/info/00-p3-array-filename.bin',
  JSON.stringify({ entries: [{ filename: ['00_1'], number: 1 }] }),
);
index.objects['entries/block4/info/00_info.json'].push({
  ...p3PoisonedInfoRow, generation: 80, observationOrdinal: '00000800:00000000',
});
applicantRegistrations = [{ hash: attackerApplicantHash, registeredBlock: 7, signer: '0xp3-honest' }];
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
let p3TypedResolved = null;
let p3TypedError = null;
try {
  p3TypedResolved = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
} catch (error) { p3TypedError = error; }
const p3TypedDifferences = p3TypedResolved?.differences?.filter((difference) => (
  difference.checkId === 'emergency.applicantDiscardedGenerations'
  && /filename/.test(difference.what)
)) || [];
ok('P3 R30-D-1-01 filename を配列で包んだ info 世代は TypeError にせず落とし、差分を1行残す',
  p3TypedResolved?.applicantRegistration?.hash === attackerApplicantHash.toLowerCase()
  && p3TypedDifferences.length === 1,
  JSON.stringify({ error: p3TypedError?.message, differences: p3TypedDifferences }));
index.objects['entries/block4/info/00_info.json'].pop();

const p8bDuplicateFilenameInfoRow = await save(
  '_observer/generations/info/00-p8b-duplicate-filename.bin',
  JSON.stringify({ entries: [
    { filename: '00_1', number: 1 },
    { filename: '00_1', number: 1 },
  ] }),
);
index.objects['entries/block4/info/00_info.json'].push({
  ...p8bDuplicateFilenameInfoRow, generation: 81, observationOrdinal: '00000801:00000000',
});
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
let p8bDuplicateResolved = null;
let p8bDuplicateError = null;
try {
  p8bDuplicateResolved = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
} catch (error) { p8bDuplicateError = error; }
ok('P8b P3: 同じ自worker filenameを重複宣言したinfo世代は不正として差分へ落とし、評価から外す',
  p8bDuplicateResolved?.applicantRegistration?.hash === attackerApplicantHash.toLowerCase()
  && p8bDuplicateResolved.differences.some((difference) => (
    difference.checkId === 'emergency.applicantDiscardedGenerations'
    && /duplicate/.test(difference.what)
    && /unique string/.test(difference.rebuilt?.requiredShape || '')
  )), String(p8bDuplicateError?.message || ''));
index.objects['entries/block4/info/00_info.json'].pop();

const p3CrossWorkerKeys = [];
for (let worker = 1; worker <= 12; worker++) {
  const filename = `${String(worker).padStart(2, '0')}_0`;
  const key = `entries/block4/entries/${filename}.json`;
  const rowA = await save(
    `_observer/generations/entries/${filename}-p3-cross-a.bin`,
    JSON.stringify([{ uid: `p3-cross-a-${filename}` }]),
  );
  const rowB = await save(
    `_observer/generations/entries/${filename}-p3-cross-b.bin`,
    JSON.stringify([{ uid: `p3-cross-b-${filename}` }]),
  );
  index.objects[key] = [
    { ...rowA, generation: 1, observationOrdinal: `00000801:${filename}` },
    { ...rowB, generation: 2, observationOrdinal: `00000802:${filename}` },
  ];
  p3CrossWorkerKeys.push(key);
}
const p3CrossWorkerInfoRow = await save(
  '_observer/generations/info/00-p3-cross-worker.bin',
  JSON.stringify({
    entries: p3CrossWorkerKeys.map((key) => ({
      filename: key.slice(key.lastIndexOf('/') + 1, -'.json'.length), number: 1,
    })),
  }),
);
index.objects['entries/block4/info/00_info.json'].push({
  ...p3CrossWorkerInfoRow, generation: 81, observationOrdinal: '00000803:00000000',
});
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
let p3CrossWorkerResolved = null;
let p3CrossWorkerError = null;
try {
  p3CrossWorkerResolved = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
} catch (error) { p3CrossWorkerError = error; }
ok('P3 R30-A-2-02 他 worker の応募ファイルを名指す info 世代は、正直な登録の予算を食わず自動採用を妨げない',
  p3CrossWorkerResolved?.applicantRegistration?.hash === attackerApplicantHash.toLowerCase()
  && p3CrossWorkerResolved.differences.some((difference) => (
    difference.checkId === 'emergency.applicantDiscardedGenerations'
    && /filename/.test(difference.what)
  )),
  String(p3CrossWorkerError?.message || ''));
index.objects['entries/block4/info/00_info.json'].pop();
for (const key of p3CrossWorkerKeys) delete index.objects[key];

async function buildP3FallbackArchive(label, variantWorkers, { includeIntermediate = true } = {}) {
  const sourceDir = path.join(taskTmp, `p3-fallback-${label}`);
  await fs.mkdir(path.join(sourceDir, '_observer/generations'), { recursive: true });
  const objects = {};
  const infos = [];
  const entries = new Map();
  let sequence = 0;
  const put = async (key, value, generation = 1) => {
    const bytes = Buffer.from(JSON.stringify(value));
    const savedFile = `_observer/generations/${String(sequence++).padStart(6, '0')}.bin`;
    await fs.writeFile(path.join(sourceDir, savedFile), bytes);
    const row = {
      savedFile, sha256: digest(bytes), bytes: bytes.length, generation,
      observationOrdinal: `${String(sequence).padStart(8, '0')}:00000000`,
    };
    (objects[key] ||= []).push(row);
    return row;
  };
  for (let worker = 0; worker < 100; worker++) {
    const name = String(worker).padStart(2, '0');
    const declared = [];
    for (let fileIndex = 0; fileIndex < 2; fileIndex++) {
      const filename = `${name}_${fileIndex}`;
      const rows = [{ uid: `p3-${worker}-${fileIndex}` }];
      entries.set(filename, rows);
      declared.push({ filename, number: rows.length });
      await put(`entries/block0/entries/${filename}.json`, rows);
      if (fileIndex === 0 && worker < variantWorkers) {
        await put(`entries/block0/entries/${filename}.json`, [{ uid: `p3-alt-${worker}` }], 2);
      }
    }
    const info = { entries: declared };
    infos.push(info);
    await put(`entries/block0/info/${name}_info.json`, info);
  }
  const intermediate = applicantIntermediate(0, infos, entries);
  const honestRoot = `0x${hashLikeBackend(intermediate)}`;
  const alternateEntries = new Map(entries);
  for (let worker = 0; worker < variantWorkers; worker++) {
    alternateEntries.set(`${String(worker).padStart(2, '0')}_0`, [{ uid: `p3-alt-${worker}` }]);
  }
  const alternateRoot = `0x${hashLikeBackend(applicantIntermediate(0, infos, alternateEntries))}`;
  if (includeIntermediate) await put('entries/block0/intermediate_hash.json', intermediate);
  const resultManifest = { blockNum: 0, algorithm: 'sha256', rules: {}, files: {} };
  await put('verification/block0/manifest.json', resultManifest);
  await fs.writeFile(path.join(sourceDir, '_observer/generation-index.json'), JSON.stringify({
    schemaVersion: 1, kind: 'r2-backup-observer-block-archive', complete: true,
    blockNum: 0, sourceRunId: `p3-${label}`, objects,
  }));
  const decoyRoot = `0x${'de'.repeat(32)}`;
  const makeChain = (registrations) => ({
    getResultHash: async () => ({ hash: manifestCoreHash(resultManifest), updated: 1 }),
    applicantRegistrationCount: async () => registrations.length,
    applicantRegistrationAt: async (_blockNum, registrationIndex) => registrations[registrationIndex],
    getTimingConstants: async () => ({ startTimeEntryMs: 0, blockTimeMs: 1000 }),
    getBlock: async (registeredBlock) => ({ timestamp: Number(registeredBlock) }),
    getOtherHash: async () => null,
  });
  return { sourceDir, honestRoot, alternateRoot, decoyRoot, makeChain };
}

const p3Fallback6 = await buildP3FallbackArchive('six', 6);
const p3Fallback6Registrations = [
  { hash: p3Fallback6.honestRoot, registeredBlock: 5, signer: '0xhonest' },
  { hash: p3Fallback6.decoyRoot, registeredBlock: 6, signer: '0xdecoy' },
];
let p3Fallback6Auto = null;
let p3Fallback6AutoError = null;
try {
  p3Fallback6Auto = await resolveEmergencyGenerationMap({
    sourceDir: p3Fallback6.sourceDir,
    chain: p3Fallback6.makeChain(p3Fallback6Registrations),
    blockNum: 0,
  });
} catch (error) { p3Fallback6AutoError = error; }
ok('P3 R30-A-2-01/A-5-02 囮登録1本と別世代6 worker が在っても、正直な intermediate 登録を自動採用できる',
  p3Fallback6Auto?.applicantRegistration?.index === 0
  && p3Fallback6Auto?.applicantRegistration?.hash === p3Fallback6.honestRoot.toLowerCase(),
  String(p3Fallback6AutoError?.message || ''));

let p3Fallback6Named = null;
let p3Fallback6NamedError = null;
try {
  p3Fallback6Named = await resolveEmergencyGenerationMap({
    sourceDir: p3Fallback6.sourceDir,
    chain: p3Fallback6.makeChain(p3Fallback6Registrations),
    blockNum: 0,
    applicantRegistrationIndex: 0,
  });
} catch (error) { p3Fallback6NamedError = error; }
ok('P3 R30-A-2-01/D-5-01 正直な intermediate 登録を名指しすれば、囮の fallback を省いて採用できる',
  p3Fallback6Named?.applicantRegistration?.index === 0
  && p3Fallback6Named?.differences?.some((difference) => (
    difference.checkId === 'emergency.applicantRegistrationOverride'
  ))
  && p3Fallback6Named?.differences?.some((difference) => (
    difference.checkId === 'emergency.applicantDiscardedGenerations'
    && /fallback evaluation.*was skipped/.test(difference.what)
  ))
  && p3Fallback6Named?.applicantEvaluationStats?.fallbackCombinationVisits === 0,
  String(p3Fallback6NamedError?.message || ''));

const p8bFallbackShared = await buildP3FallbackArchive(
  'p8b-shared-registration-budget', 6, { includeIntermediate: false },
);
let p8bFallbackSharedError = null;
try {
  await resolveEmergencyGenerationMap({
    sourceDir: p8bFallbackShared.sourceDir,
    chain: p8bFallbackShared.makeChain([
      { hash: p8bFallbackShared.honestRoot, registeredBlock: 5, signer: '0xfirst' },
      { hash: p8bFallbackShared.alternateRoot, registeredBlock: 6, signer: '0xsecond' },
    ]),
    blockNum: 0,
  });
} catch (error) { p8bFallbackSharedError = error; }
const p8bFallbackAmbiguity = p8bFallbackSharedError?.emergencyDifferences?.find((difference) => (
  difference.checkId === 'emergency.applicantRegistrationAmbiguous'
));
ok('P8b P3: fallbackの組合せ予算は登録ごとに独立し、2登録とも再現候補として残る',
  p8bFallbackAmbiguity?.rebuilt?.reproducibleIndices?.join(',') === '0,1'
  && p8bFallbackAmbiguity.rebuilt.evaluationImpossibleIndices === undefined
  && p8bFallbackAmbiguity.rebuilt.evaluationStats.fallbackCombinationVisits
    > EMERGENCY_FALLBACK_COMBINATION_LIMIT,
  String(p8bFallbackSharedError?.message || ''));

// 450個の異なるfilenameを持ち、先頭だけ22世代あるinfo。分岐＋葉だけなら上限内だが、
// 実際のentries/worker hashを数えると上限を超える。単一世代keyは同じ保存bytesを参照する。
const p8bHashBudgetDir = path.join(taskTmp, 'p8b-fallback-info-hash-budget');
await fs.mkdir(path.join(p8bHashBudgetDir, '_observer/generations'), { recursive: true });
const p8bHashObjects = {};
const p8bHashEmptyRaw = '[]';
const p8bHashEmptySaved = '_observer/generations/empty-array.bin';
await fs.writeFile(path.join(p8bHashBudgetDir, p8bHashEmptySaved), p8bHashEmptyRaw);
const p8bHashEmptyRow = {
  savedFile: p8bHashEmptySaved,
  sha256: digest(Buffer.from(p8bHashEmptyRaw)),
  bytes: Buffer.byteLength(p8bHashEmptyRaw),
  generation: 1,
  observationOrdinal: '00000001:00000000',
};
const p8bHashInfos = Array.from({ length: 100 }, () => ({ entries: [] }));
const p8bHashEntries = new Map();
p8bHashInfos[0] = {
  entries: Array.from({ length: 450 }, (_, fileIndex) => ({
    filename: `00_${fileIndex}`,
    number: 0,
  })),
};
for (const entry of p8bHashInfos[0].entries) {
  p8bHashEntries.set(entry.filename, []);
  p8bHashObjects[`entries/block0/entries/${entry.filename}.json`] = [p8bHashEmptyRow];
}
let p8bHashSequence = 2;
const p8bHashFirstKey = 'entries/block0/entries/00_0.json';
for (let variant = 1; variant < 22; variant++) {
  const raw = JSON.stringify([{ uid: `p8b-hash-variant-${variant}` }]);
  const savedFile = `_observer/generations/hash-variant-${String(variant).padStart(2, '0')}.bin`;
  await fs.writeFile(path.join(p8bHashBudgetDir, savedFile), raw);
  p8bHashObjects[p8bHashFirstKey].push({
    savedFile,
    sha256: digest(Buffer.from(raw)),
    bytes: Buffer.byteLength(raw),
    generation: variant + 1,
    observationOrdinal: `${String(variant + 1).padStart(8, '0')}:00000000`,
  });
}
const p8bHashPut = async (key, value) => {
  const raw = JSON.stringify(value);
  const savedFile = `_observer/generations/${String(p8bHashSequence++).padStart(6, '0')}.bin`;
  await fs.writeFile(path.join(p8bHashBudgetDir, savedFile), raw);
  p8bHashObjects[key] = [{
    savedFile,
    sha256: digest(Buffer.from(raw)),
    bytes: Buffer.byteLength(raw),
    generation: 1,
    observationOrdinal: `${String(p8bHashSequence).padStart(8, '0')}:00000000`,
  }];
};
for (let worker = 0; worker < 100; worker++) {
  await p8bHashPut(
    `entries/block0/info/${String(worker).padStart(2, '0')}_info.json`,
    p8bHashInfos[worker],
  );
}
const p8bHashManifest = { blockNum: 0, algorithm: 'sha256', rules: {}, files: {} };
await p8bHashPut('verification/block0/manifest.json', p8bHashManifest);
await fs.writeFile(path.join(p8bHashBudgetDir, '_observer/generation-index.json'), JSON.stringify({
  schemaVersion: 1,
  kind: 'r2-backup-observer-block-archive',
  complete: true,
  blockNum: 0,
  sourceRunId: 'p8b-hash-budget',
  objects: p8bHashObjects,
}));
const p8bHashRoot = applicantRoot(0, p8bHashInfos, p8bHashEntries);
const p8bHashChain = {
  getResultHash: async () => ({ hash: manifestCoreHash(p8bHashManifest), updated: 1 }),
  applicantRegistrationCount: async () => 1,
  applicantRegistrationAt: async () => ({
    hash: p8bHashRoot, registeredBlock: 5, signer: '0xp8b-hash-budget',
  }),
  getTimingConstants: async () => ({ startTimeEntryMs: 0, blockTimeMs: 1000 }),
  getBlock: async (registeredBlock) => ({ timestamp: Number(registeredBlock) }),
  getOtherHash: async () => null,
};
let p8bHashBudgetError = null;
let p8bHashBudgetResolved = null;
try {
  p8bHashBudgetResolved = await resolveEmergencyGenerationMap({
    sourceDir: p8bHashBudgetDir, chain: p8bHashChain, blockNum: 0,
  });
} catch (error) { p8bHashBudgetError = error; }
ok('P8b P3: fallback infoの実ハッシュ仕事量が上限を超えた登録は採用せず、評価不能行を必ず残す',
  p8bHashBudgetResolved === null
  && /評価不能.*予算超過/.test(String(p8bHashBudgetError?.message || ''))
  && p8bHashBudgetError?.emergencyDifferences?.some((difference) => (
    difference.checkId === 'emergency.applicantDiscardedGenerations'
    && /registration 0 has generation candidates that are evaluation-impossible/.test(difference.what)
    && difference.rebuilt?.attempts?.some((attempt) => (
      attempt.phase === 'bounded-combination-fallback'
      && attempt.infoCandidatesOverLimit?.length === 1
    ))
  )), String(p8bHashBudgetError?.message || ''));

await rejects('P3 R30-D-5-01 囮登録を名指しすると、その登録を再現できない理由を示して停止する',
  () => resolveEmergencyGenerationMap({
    sourceDir: p3Fallback6.sourceDir,
    chain: p3Fallback6.makeChain(p3Fallback6Registrations),
    blockNum: 0,
    applicantRegistrationIndex: 1,
  }),
  /specified eligible applicantHash registration index 1 cannot be reproduced/);
await rejects('P3 R30-A-5-02 intermediate の無い登録だけで本当に再現できなければ従来どおり fail-closed',
  () => resolveEmergencyGenerationMap({
    sourceDir: p3Fallback6.sourceDir,
    chain: p3Fallback6.makeChain([p3Fallback6Registrations[1]]),
    blockNum: 0,
  }),
  /no saved info\/entry generation combination matches an eligible HashStorage applicantHash registration/);

const p3Fallback14 = await buildP3FallbackArchive('fourteen', 14);
const p3Fallback14Registrations = [
  { hash: p3Fallback14.honestRoot, registeredBlock: 5, signer: '0xhonest' },
  { hash: p3Fallback14.decoyRoot, registeredBlock: 6, signer: '0xdecoy' },
];
let p3Fallback14Error = null;
try {
  await resolveEmergencyGenerationMap({
    sourceDir: p3Fallback14.sourceDir,
    chain: p3Fallback14.makeChain(p3Fallback14Registrations),
    blockNum: 0,
  });
} catch (error) { p3Fallback14Error = error; }
ok('P3 R30-A-2-01 指定なしで囮登録の評価が予算超過なら、材料を並べて自動採用を fail-closed に止める',
  /評価不能.*予算超過/.test(String(p3Fallback14Error?.message || ''))
  && p3Fallback14Error?.emergencyDifferences?.some((difference) => (
    difference.checkId === 'emergency.applicantRegistrationAmbiguous'
    && difference.rebuilt?.evaluationImpossibleIndices?.includes(1)
  ))
  && p3Fallback14Error?.emergencyDifferences?.some((difference) => (
    difference.checkId === 'emergency.applicantDiscardedGenerations'
    && /registration 1 has generation candidates that are evaluation-impossible/.test(difference.what)
    && difference.rebuilt?.attempts?.some((attempt) => (
      attempt.phase === 'bounded-combination-fallback'
      && attempt.reason === '評価不能（予算超過）'
    ))
  )),
  String(p3Fallback14Error?.message || ''));
let p3Fallback14Named = null;
let p3Fallback14NamedError = null;
try {
  p3Fallback14Named = await resolveEmergencyGenerationMap({
    sourceDir: p3Fallback14.sourceDir,
    chain: p3Fallback14.makeChain(p3Fallback14Registrations),
    blockNum: 0,
    applicantRegistrationIndex: 0,
  });
} catch (error) { p3Fallback14NamedError = error; }
ok('P3 R30-A-2-01 指定済みの正直な intermediate 登録は、囮の予算超過に巻き込まれない',
  p3Fallback14Named?.applicantRegistration?.index === 0
  && p3Fallback14Named?.differences?.some((difference) => (
    difference.checkId === 'emergency.applicantDiscardedGenerations'
    && /fallback evaluation.*was skipped/.test(difference.what)
  )),
  String(p3Fallback14NamedError?.message || ''));
let p3Fallback14NamedRoot = null;
let p3Fallback14NamedRootError = null;
try {
  p3Fallback14NamedRoot = await resolveEmergencyGenerationMap({
    sourceDir: p3Fallback14.sourceDir,
    chain: p3Fallback14.makeChain(p3Fallback14Registrations),
    blockNum: 0,
    applicantRoot: p3Fallback14.honestRoot,
  });
} catch (error) { p3Fallback14NamedRootError = error; }
ok('P3 R30-A-2-01 root 指定でも正直な intermediate 登録は、囮の予算超過に巻き込まれない',
  p3Fallback14NamedRoot?.applicantRegistration?.index === 0
  && p3Fallback14NamedRoot?.applicantRegistration?.hash === p3Fallback14.honestRoot.toLowerCase(),
  String(p3Fallback14NamedRootError?.message || ''));
await rejects('P3 R30-D-5-01 予算超過する囮を名指しすると、評価不能の理由を示して停止する',
  () => resolveEmergencyGenerationMap({
    sourceDir: p3Fallback14.sourceDir,
    chain: p3Fallback14.makeChain(p3Fallback14Registrations),
    blockNum: 0,
    applicantRegistrationIndex: 1,
  }),
  /specified eligible applicantHash registration index 1 cannot be reproduced.*予算超過/s);
await rejects('P3 R30-D-5-01 予算超過する囮は root 指定でも、評価不能の理由を示して停止する',
  () => resolveEmergencyGenerationMap({
    sourceDir: p3Fallback14.sourceDir,
    chain: p3Fallback14.makeChain(p3Fallback14Registrations),
    blockNum: 0,
    applicantRoot: p3Fallback14.decoyRoot,
  }),
  /specified eligible applicantHash root .* cannot be reproduced.*予算超過/s);

applicantRegistrations = p3OriginalRegistrations;
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));

const rosterHonest = p15RosterPayloads.manifestText;
const rosterAttacker = JSON.stringify({ ...JSON.parse(rosterHonest), attackerVariant: true });
const rosterHonestRow = await save('_observer/generations/roster/honest.bin', rosterHonest);
const rosterAttackerRow = await save('_observer/generations/roster/attacker.bin', rosterAttacker);
for (const [groupId, groupText] of p15RosterPayloads.groupTexts) {
  index.objects[`games/block4/roster/group${groupId}.json`] = [
    await save(`_observer/generations/roster/group-${groupId}.bin`, groupText),
  ];
}
index.objects['games/block4/roster/manifest.json'] = [
  { ...rosterHonestRow, generation: 1, observationOrdinal: '00000300:00000000' },
  { ...rosterAttackerRow, generation: 2, observationOrdinal: '00000301:00000000' },
];
chain.getOtherHash = async () => ({ hash: p15RosterHash, updated: 101 });
chain.getTimingConstants = async () => ({ startTimeEntryMs: 0, blockTimeMs: 1000,
  gamePeriodMs: 1000 });
chain.currentGrace = async () => 320;
chain.otherRegistrationCount = async () => 2;
chain.otherRegistrationAt = async (_key, registrationIndex) => registrationIndex === 0
  ? { hash: p15RosterHash, registeredBlock: 101, registeredAt: 101 }
  : { hash: `0x${'55'.repeat(32)}`, registeredBlock: 330, registeredAt: 330 };
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const resolvedRoster = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
ok('R3-I1 roster manifestは複数世代でもHashStorage目印に一致する世代を採る',
  resolvedRoster.fileMap.get('games/block4/roster/manifest.json') === rosterHonestRow.savedFile);

chain.getOtherHash = async () => ({ hash: `0x${'55'.repeat(32)}`, updated: 330 });
const resolvedOverwrittenRoster = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
ok('M9a: 開始以後の現在値上書きは無視して開始前の保存世代を採る',
  resolvedOverwrittenRoster.fileMap.get('games/block4/roster/manifest.json') === rosterHonestRow.savedFile
  && !resolvedOverwrittenRoster.differences.some((difference) =>
    difference.checkId === 'check.stageC.rosterLiveAnchor'));
chain.otherRegistrationAt = async (_key, registrationIndex) => registrationIndex === 0
  ? { hash: `0x${'77'.repeat(32)}`, registeredBlock: 101, registeredAt: 101 }
  : { hash: `0x${'55'.repeat(32)}`, registeredBlock: 330, registeredAt: 330 };
for (const rows of [
  [index.objects['games/block4/roster/manifest.json'][0],
    index.objects['games/block4/roster/manifest.json'][1]],
  [index.objects['games/block4/roster/manifest.json'][1],
    index.objects['games/block4/roster/manifest.json'][0]],
]) {
  index.objects['games/block4/roster/manifest.json'] = rows.map((row, ordinal) => ({
    ...row, observationOrdinal: `00000400:0000000${ordinal}`,
  }));
  await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
  const chosen = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
  ok('R32-D-2c-02: 正典に一致しない保存2世代は rows[0] と selectedSha256 を揃える',
    chosen.fileMap.get('games/block4/roster/manifest.json') === rows[0].savedFile
    && chosen.differences.some((difference) => difference.checkId === 'check.stageC.rosterLiveAnchor'
      && difference.rebuilt?.selectedSha256 === rows[0].sha256
      && difference.rebuilt?.selectionRule === 'earliest-observed-saved-generation'));
}

delete index.objects['games/block4/roster/manifest.json'];
delete chain.getTimingConstants;
delete chain.currentGrace;
delete chain.otherRegistrationCount;
delete chain.otherRegistrationAt;
for (const key of Object.keys(index.objects)) {
  if (/^entries\/block4\/(?:info|entries)\//.test(key)) delete index.objects[key];
}
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));

// U4-C6: result manifest -> Stage 3 manifest -> witness の2ホップ選択と再計算入力照合。
const originalCurrentManifestRows = index.objects['verification/block4/manifest.json'];
const witnessMember = {
  uid: '10', addr: `0x${'10'.repeat(20)}`,
  bAddr: JSON.stringify({ address: `0x${'20'.repeat(20)}` }),
  depIds: JSON.stringify({ ids: [] }), lang: 'ja', globalIndex: 0,
  name: null, img: null, verified: false,
};
const witnessGroupRow = { group_id: 0, members: JSON.stringify([witnessMember]) };
const witnessGroupData = {
  meta: { blockNum: 4, groupId: 0 }, members: [witnessMember],
  submissions: {}, submissionsRaw: {}, messages: [], receipts: [], actions: {},
};
const witnessVerifiedDepositWei = { '10': '0' };
const stage3Witness = buildGroupWitness({
  groupRow: { ...witnessGroupRow, block_num: 4 },
  groupData: witnessGroupData,
  verifiedDepositWei: witnessVerifiedDepositWei,
  chatWindow: null,
});
const stage3WitnessKey = 'verification/block4/stage3/group-0.json';
const stage3WitnessRow = await save(
  '_observer/generations/stage3/group-0.bin', JSON.stringify(stage3Witness),
);
const stage3WitnessAttackerRow = await save(
  '_observer/generations/stage3/group-0-attacker.bin', JSON.stringify({ ...stage3Witness, groupId: 9 }),
);
const stage3ManifestForWitness = {
  schemaVersion: 1, kind: 'bitcoinu-stage3-input-manifest', blockNum: 4,
  groupCount: 1,
  groups: [{ groupId: 0, object: stage3WitnessKey, sha256: stage3WitnessRow.sha256 }],
};
const stage3ManifestRow = await save(
  '_observer/generations/stage3/manifest.bin', JSON.stringify(stage3ManifestForWitness),
);
const manifestWithWitness = {
  ...manifest,
  files: {
    ...manifest.files,
    'verification/block4/stage3/manifest.json': stage3ManifestRow.sha256,
  },
};
manifestWithWitness.manifestHash = manifestCoreHash(manifestWithWitness);
const manifestWithWitnessRow = await save(
  '_observer/generations/verification/manifest-with-witness.bin', JSON.stringify(manifestWithWitness),
);
index.objects['verification/block4/manifest.json'] = [{
  ...manifestWithWitnessRow, generation: 8, observationOrdinal: '00000800:00000000',
}];
index.objects['verification/block4/stage3/manifest.json'] = [{
  ...stage3ManifestRow, generation: 1, observationOrdinal: '00000801:00000000',
}];
index.objects[stage3WitnessKey] = [{
  ...stage3WitnessRow, generation: 1, observationOrdinal: '00000802:00000000',
}, {
  ...stage3WitnessAttackerRow, generation: 2, observationOrdinal: '00000803:00000000',
}];
chain.getResultHash = async (block) => ({
  hash: Number(block) === 3 ? previousCore : manifestWithWitness.manifestHash,
});
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const resolvedWitness = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
ok('P5 R30-A-1-02 正準で上限内のStage 3 manifestだけはZKP入力へ渡せる印になる',
  resolvedWitness.stage3ManifestUsableForZkp === true);

const p5Stage3OuterRows = index.objects['verification/block4/manifest.json'];
const p5Stage3InputRows = index.objects['verification/block4/stage3/manifest.json'];
async function resolveP5UnusableStage3(label, raw) {
  const row = await save(`_observer/generations/p5/stage3-${label}.bin`, raw);
  const outer = {
    ...manifestWithWitness,
    files: {
      ...manifestWithWitness.files,
      'verification/block4/stage3/manifest.json': row.sha256,
    },
  };
  outer.manifestHash = manifestCoreHash(outer);
  const outerRow = await save(
    `_observer/generations/p5/manifest-stage3-${label}.bin`, JSON.stringify(outer),
  );
  index.objects['verification/block4/manifest.json'] = [{
    ...outerRow, generation: 20, observationOrdinal: '00000900:00000000',
  }];
  index.objects['verification/block4/stage3/manifest.json'] = [{
    ...row, generation: 20, observationOrdinal: '00000900:00000001',
  }];
  chain.getResultHash = async (block) => ({
    hash: Number(block) === 3 ? previousCore : outer.manifestHash,
  });
  await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
  return resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
}
const p5Stage3Structural = await resolveP5UnusableStage3('structural', '{}');
const p5Stage3Noncanonical = await resolveP5UnusableStage3(
  'noncanonical', `${JSON.stringify(stage3ManifestForWitness)}\n`,
);
const p5Stage3Oversize = await resolveP5UnusableStage3(
  'oversize', JSON.stringify({ ...stage3ManifestForWitness, padding: 'x'.repeat(1024 * 1024) }),
);
ok('P5 R30-A-1-02 構造不正・非正準・1MiB超過の公開Stage 3 manifestをunusableとしてZKP入力から外す',
  [p5Stage3Structural, p5Stage3Noncanonical, p5Stage3Oversize].every((selection) => (
    selection.stage3ManifestUsableForZkp === false
    && selection.differences.some((difference) => (
      difference.checkId === 'emergency.stage3WitnessUnavailable'
    ))
  )), JSON.stringify([
    p5Stage3Structural.stage3ManifestUsableForZkp,
    p5Stage3Noncanonical.stage3ManifestUsableForZkp,
    p5Stage3Oversize.stage3ManifestUsableForZkp,
  ]));
index.objects['verification/block4/manifest.json'] = p5Stage3OuterRows;
index.objects['verification/block4/stage3/manifest.json'] = p5Stage3InputRows;
chain.getResultHash = async (block) => ({
  hash: Number(block) === 3 ? previousCore : manifestWithWitness.manifestHash,
});
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));

// ==================================================================
// 🔴 W1 / R28-H3-4-02（2026-09-20・ユーザー承認済みの方式変更）
//   緊急モードは「公開 witness と一致するか」を要求するのをやめ、
//   **再計算した witness を採用**して、公開版との差は記録に回す。
//   止まるのは「再計算そのものができない」場合だけ（できない ≠ 合わない）。
//   ここは両方向を全数で測る:
//     通る: ①一致 ②並び順だけ ③中身 ④公開版なし ⑤群集合から外れた公開 witness
//     止まる: ⑥再計算の材料が無い
// ==================================================================
const witnessMemberB = {
  ...witnessMember, uid: '11', addr: `0x${'11'.repeat(20)}`,
  bAddr: JSON.stringify({ address: `0x${'21'.repeat(20)}` }), globalIndex: 1,
};
const witnessPairRow = { group_id: 0, members: JSON.stringify([witnessMember, witnessMemberB]) };
const witnessPairDeposits = { '10': '0', '11': '0' };
const stage3PairWitness = buildGroupWitness({
  groupRow: { ...witnessPairRow, block_num: 4 },
  groupData: witnessGroupData,
  verifiedDepositWei: witnessPairDeposits,
  chatWindow: null,
});
// 本番 publishStage3GroupWitness（game-master-DO.js:11493-11504）と同じ直列化。
const stage3PairBytes = Buffer.from(JSON.stringify(stage3PairWitness));
const stage3PairManifest = {
  schemaVersion: 1, kind: 'bitcoinu-stage3-input-manifest', blockNum: 4,
  groupCount: 1,
  groups: [{ groupId: 0, object: stage3WitnessKey, sha256: digest(stage3PairBytes) }],
};
const orderOnlyWitnessBytes = Buffer.from(JSON.stringify({
  ...stage3PairWitness, members: [...stage3PairWitness.members].reverse(),
}));
const contentWitnessBytes = Buffer.from(JSON.stringify({
  ...stage3PairWitness,
  members: stage3PairWitness.members.map((member) => (
    member.uid === '11' ? { ...member, depositWei: '1' } : member
  )),
}));
const witnessRebuild = (overrides = {}) => ({
  kind: 'groupGame',
  rebuiltSummary: { blockNum: 4, groups: [{ group_id: 0 }] },
  d1Groups: [witnessPairRow],
  verifiedDepositWei: witnessPairDeposits,
  chatWindowMs: null,
  ...overrides,
});
// 「例外にならない」ことを暗黙のクラッシュではなく**検査される条件**にする。
// （修正前の実装に戻す mutation ではここが threw になり、各歯が FAIL として出る）
function runWitnessAdoption(publicWitnessBytes, {
  manifest = stage3PairManifest, extraCapture = [], groupArchives = new Map([[0, witnessGroupData]]),
} = {}) {
  const capture = new Map();
  if (manifest) {
    capture.set('verification/block4/stage3/manifest.json', Buffer.from(JSON.stringify(manifest)));
  }
  if (publicWitnessBytes) capture.set(stage3WitnessKey, publicWitnessBytes);
  for (const [key, bytes] of extraCapture) capture.set(key, bytes);
  try {
    const verification = verifyEmergencyStage3Witnesses({
      blockNum: 4, rebuild: witnessRebuild(), groupArchives, capture,
    });
    return { capture, verification, threw: null };
  } catch (error) {
    return { capture, verification: { verified: 0, keys: [], adopted: 0, pins: [], differences: [] }, threw: error };
  }
}
const recomputedDiffOf = (verification) => verification.differences.find((difference) => (
  difference.checkId === 'emergency.stage3WitnessRecomputed'
));

const identicalAdoption = runWitnessAdoption(stage3PairBytes);
ok('W1 ① 公開witnessが再計算版と同じなら差分は出ず、固定一式は再計算版のバイト列',
  identicalAdoption.threw === null
  && resolvedWitness.fileMap.get(stage3WitnessKey) === stage3WitnessRow.savedFile
  && resolvedWitness.differences.some((difference) => (
    difference.checkId === 'emergency.stage3WitnessGenerations'
  ))
  && identicalAdoption.verification.verified === 1
  && identicalAdoption.verification.keys[0] === stage3WitnessKey
  && identicalAdoption.verification.adopted === 1
  && recomputedDiffOf(identicalAdoption.verification) === undefined
  && identicalAdoption.capture.get(stage3WitnessKey).equals(stage3PairBytes)
  && identicalAdoption.verification.pins[0].sha256 === digest(stage3PairBytes));

const orderOnlyAdoption = runWitnessAdoption(orderOnlyWitnessBytes);
const orderOnlyDiff = recomputedDiffOf(orderOnlyAdoption.verification);
ok('W1 ② 公開witnessが並び順だけ違う: 例外にならず「並び順だけ」と残り、採用は再計算版',
  orderOnlyAdoption.threw === null
  && orderOnlyDiff?.rebuilt.difference === 'orderOnly'
  && orderOnlyDiff.rebuilt.orderOnly === true
  && orderOnlyDiff.chain.publicSha256 === digest(orderOnlyWitnessBytes)
  && orderOnlyDiff.rebuilt.sha256 === digest(stage3PairBytes)
  && orderOnlyDiff.rebuilt.differingUids.members.length === 0
  && orderOnlyAdoption.capture.get(stage3WitnessKey).equals(stage3PairBytes)
  && orderOnlyAdoption.verification.verified === 0,
  JSON.stringify(orderOnlyDiff));

const contentAdoption = runWitnessAdoption(contentWitnessBytes);
const contentDiff = recomputedDiffOf(contentAdoption.verification);
ok('W1 ③ 公開witnessの中身が違う: 例外にならず「中身」と残り、採用は再計算版',
  contentAdoption.threw === null
  && contentDiff?.rebuilt.difference === 'content'
  && contentDiff.rebuilt.orderOnly === false
  && contentDiff.rebuilt.differingUids.members.includes('11')
  && contentDiff.chain.publicSha256 === digest(contentWitnessBytes)
  && contentAdoption.capture.get(stage3WitnessKey).equals(stage3PairBytes),
  JSON.stringify(contentDiff));

const absentAdoption = runWitnessAdoption(null);
const absentDiff = recomputedDiffOf(absentAdoption.verification);
ok('W1 ④ 公開witnessが消されていても例外にならず、差分を残して再計算版を採用する',
  absentAdoption.threw === null
  && absentDiff?.rebuilt.difference === 'absent'
  && absentDiff.chain.publicSha256 === null
  && absentDiff.rebuilt.sha256 === digest(stage3PairBytes)
  && absentAdoption.capture.get(stage3WitnessKey).equals(stage3PairBytes),
  JSON.stringify(absentDiff));

// ⑤ 再計算の群集合に無い公開 witness は固定一式から外す（順4 の run-stage3-gcp.sh が
//    「manifest.jsonに載っていないwitnessがあります」で止まるため）。
const strayKey = 'verification/block4/stage3/group-9.json';
const strayBytes = Buffer.from(JSON.stringify({ ...stage3PairWitness, groupId: 9 }));
const strayAdoption = runWitnessAdoption(stage3PairBytes, { extraCapture: [[strayKey, strayBytes]] });
const strayDiff = strayAdoption.verification.differences.find((difference) => (
  difference.checkId === 'emergency.stage3WitnessDropped'
));
ok('W1 ⑤ 再計算の群集合に無い公開witnessは固定一式から外し、証跡だけ残す',
  strayAdoption.threw === null
  && strayDiff?.chain.key === strayKey
  && strayAdoption.capture.has(strayKey) === false
  && strayAdoption.capture.get(`_emergency/public/${strayKey}`).equals(strayBytes));

// ⑥ 宣言sha256が古い公開 manifest は、採用した witness の sha256 で作り直す差分を残す。
const staleManifestAdoption = runWitnessAdoption(contentWitnessBytes, {
  manifest: {
    ...stage3PairManifest,
    groups: [{ groupId: 0, object: stage3WitnessKey, sha256: digest(contentWitnessBytes) }],
  },
});
const staleManifestDiff = staleManifestAdoption.verification.differences.find((difference) => (
  difference.checkId === 'emergency.stage3ManifestRecomputed'
));
ok('W1 ⑥ 公開Stage 3 manifestの宣言が採用版と違えば、作り直しとして差分に残る',
  staleManifestAdoption.threw === null
  && staleManifestDiff?.rebuilt.changedGroupIds.includes(0)
  && staleManifestDiff.chain.declaredGroupIds.includes(0));

// ⑦ 読めない公開 manifest でも止まらない（採用は再計算版）。
const brokenManifestAdoption = runWitnessAdoption(stage3PairBytes, { manifest: null, extraCapture: [
  ['verification/block4/stage3/manifest.json', Buffer.from('{not json')],
] });
ok('W1 ⑦ 公開Stage 3 manifestが読めなくても輸出は止まらず、差分として残る',
  brokenManifestAdoption.threw === null
  && brokenManifestAdoption.verification.differences.some((difference) => (
    difference.checkId === 'emergency.stage3ManifestUnusable'
  ))
  && brokenManifestAdoption.capture.get(stage3WitnessKey).equals(stage3PairBytes));

// ⑧ 止まる側: 再計算そのものができない（アーカイブが無い）ときは従来どおり落とす。
await rejects('W1 ⑧ 再計算の材料が無いときは従来どおり止まる（「できない」と「合わない」を分ける）',
  async () => verifyEmergencyStage3Witnesses({
    blockNum: 4, rebuild: witnessRebuild(), groupArchives: new Map(), capture: new Map(),
  }),
  /cannot be recomputed for group 0/);
await rejects('W1 ⑧ verifiedDepositWei が無いときも従来どおり止まる',
  async () => verifyEmergencyStage3Witnesses({
    blockNum: 4,
    rebuild: witnessRebuild({ verifiedDepositWei: null }),
    groupArchives: new Map([[0, witnessGroupData]]),
    capture: new Map(),
  }),
  /cannot be recomputed for group 0/);

// ⑨ 公開 witness が保存世代から消えていても、選択段は止まらず差分だけを残す。
const witnessRowsBackup = index.objects[stage3WitnessKey];
delete index.objects[stage3WitnessKey];
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const resolvedMissingWitness = await resolveEmergencyGenerationMap({
  sourceDir: taskTmp, chain, blockNum: 4,
});
ok('W1 ⑨ 宣言されたwitness世代が消えていても選択段は止まらず、差分として残る',
  resolvedMissingWitness.witnessKeys.length === 0
  && resolvedMissingWitness.differences.some((difference) => (
    difference.checkId === 'emergency.stage3WitnessUnavailable'
    && /no saved generation matches the declared witness/.test(difference.what)
  )));
index.objects[stage3WitnessKey] = witnessRowsBackup;
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));

// ==================================================================
// 🔴 便 Z5 / R29-A-3-02 ≡ R29-B-5-03（2026-09-21・便 W1 の未完了分）
//   汎用の宣言ループ（emergency.js の `if (Object.hasOwn(declared, key))`）は
//   selectStage3WitnessInputs より**先に**走るので、
//   「保存世代が1本以上あって宣言 sha256 と一致するものが無い」＝攻撃者が選べる側は
//   W1 の許容枝へ到達できず素の throw（exit 3・固定一式0バイト）になっていた。
//   Stage 3 入力 manifest の鍵**だけ**を差分にして選択を続ける。
//   両方向を全数で測る。通る: E1 宣言と合わない世代だけでも完走し差分が残る。
//   止まる: E2 他の宣言鍵は従来どおり throw。据え置き: E3 正版があれば差分は出ない。
// ==================================================================
const z5Stage3DeclKey = 'verification/block4/stage3/manifest.json';
const z5Stage3HonestRows = index.objects[z5Stage3DeclKey];
const z5Stage3MismatchRow = await save(
  '_observer/generations/stage3/manifest-declaration-mismatch.bin',
  JSON.stringify({ ...stage3ManifestForWitness, groupCount: 0, groups: [] }),
);

// E1 通る側: 宣言 sha256 と一致する保存世代が1本も無い（別世代だけが在る）。
index.objects[z5Stage3DeclKey] = [{
  ...z5Stage3MismatchRow, generation: 5, observationOrdinal: '00000804:00000000',
}];
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
let z5DeclMismatchError = null;
const z5DeclMismatch = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 })
  .catch((error) => { z5DeclMismatchError = error; return null; });
ok('Z5 R29-A-3-02/B-5-03 E1 宣言と合わない世代だけのStage 3入力manifestは選択段を止めず、差分として残る',
  z5DeclMismatch !== null
  && z5DeclMismatch.fileMap.has(z5Stage3DeclKey) === false
  && z5DeclMismatch.witnessKeys.length === 0
  && z5DeclMismatch.differences.some((difference) => (
    difference.checkId === 'emergency.stage3WitnessUnavailable'
    && /no saved generation matches the declared Stage 3 input manifest/.test(difference.what)
  )),
  String(z5DeclMismatchError?.message || ''));
console.log(`Z5_A302_DIFFS ${JSON.stringify((z5DeclMismatch?.differences || [])
  .filter((d) => d.checkId === 'emergency.stage3WitnessUnavailable').map((d) => d.what))}`);

// E2 止まる側: 他の宣言鍵（固定一式へ逐語運搬される側）は従来どおり throw する。
const z5SelectionKey = 'entries/block4/game_selection.json';
const z5SelectionHonestRows = index.objects[z5SelectionKey];
const z5SelectionMismatchRow = await save(
  '_observer/generations/entries/selection/declaration-mismatch.bin',
  '{"applicantHash":"0x02"}',
);
index.objects[z5SelectionKey] = [{
  ...z5SelectionMismatchRow, generation: 5, observationOrdinal: '00000805:00000000',
}];
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
await rejects('Z5 R29-A-3-02/B-5-03 E2 Stage 3入力manifest以外の宣言鍵は宣言と合わなければ従来どおり止まる',
  () => resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 }),
  /entries\/block4\/game_selection\.json manifest marker: no saved generation matches/);
index.objects[z5SelectionKey] = z5SelectionHonestRows;

// E3 据え置き: 宣言と一致する保存世代が在るときは差分を積まず、その世代を固定する。
index.objects[z5Stage3DeclKey] = z5Stage3HonestRows;
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));
const z5DeclHonest = await resolveEmergencyGenerationMap({ sourceDir: taskTmp, chain, blockNum: 4 });
ok('Z5 R29-A-3-02/B-5-03 E3 宣言と一致する保存世代が在れば差分は出ず、その世代を固定する',
  z5DeclHonest.fileMap.get(z5Stage3DeclKey) === stage3ManifestRow.savedFile
  && z5DeclHonest.differences.some((difference) => (
    difference.checkId === 'emergency.stage3WitnessUnavailable'
  )) === false);

index.objects['verification/block4/manifest.json'] = originalCurrentManifestRows;
delete index.objects['verification/block4/stage3/manifest.json'];
delete index.objects[stage3WitnessKey];
chain.getResultHash = async (block) => ({ hash: Number(block) === 3 ? previousCore : manifest.manifestHash });
await fs.writeFile(path.join(taskTmp, '_observer/generation-index.json'), JSON.stringify(index));

// U2: local adapter never falls through to fetch/network.
const r2 = createLocalR2({ artifactDir: taskTmp }, {}, 4, { rootDir: taskTmp, fileMap: resolved.fileMap });
const localSelection = await r2.fetchJson('entries/block4/game_selection.json');
ok('U2 通常R2インターフェースの読取先を固定一式へ切り替えられる',
  localSelection.raw === selectionText && localSelection.source === 'artifact-directory');
ok('U2b 固定一式に無いキーはネットワークへ落ちず null', await r2.fetchJson('missing.json') === null);

// U3: first valid observer version wins; signature-only-looking but core-invalid row is rejected.
const gen1 = await save('_observer/generations/live/g1.bin', JSON.stringify({ submissionsRaw: { '10': 'signature-ok-core-bad' } }));
const gen2 = await save('_observer/generations/live/g2.bin', JSON.stringify({ submissionsRaw: { '10': 'first-valid' } }));
const gen3 = await save('_observer/generations/group/g3.bin', JSON.stringify({ submissionsRaw: { '10': 'last-valid' } }));
const candidateIndex = {
  objects: {
    'live/block4/group0.submissions.json': [
      { ...gen1, generation: 1, observationOrdinal: '00000000:00000000' },
      { ...gen2, generation: 2, observationOrdinal: '00000001:00000000' },
    ],
    'games/block4/group0.json': [
      { ...gen3, generation: 3, observationOrdinal: '00000002:00000000' },
    ],
  },
};
const validations = [];
const chosen = await selectEmergencyServerSubmissions({
  sourceDir: taskTmp, index: candidateIndex, blockNum: 4,
  groupsDerived: [{ groupId: 0, members: [{ data: { uid: '10', addr: '0x1' } }] }],
  validate: async (raw) => {
    validations.push(raw);
    if (raw === 'signature-ok-core-bad') return { valid: false, reason: 'chathash_mismatch' };
    return { valid: true, uid: '10', groupId: 0, bundle: { raw } };
  },
});
ok('U3 全候補を完全検証入口へ通し、署名だけ通りそうな不整合版を採らない',
  validations.length === 3 && chosen.candidates[0].reason === 'chathash_mismatch');
ok('U3 mutation: 最後の保存版でなく最初の有効保存版を採る',
  chosen.selectedByUid['10'].raw === 'first-valid' && chosen.selectedByUid['10'].raw !== 'last-valid');
const m11aInvalidSelected = await selectEmergencyServerSubmissions({
  sourceDir: taskTmp,
  index: { objects: { 'live/block4/group0.submissions.json': [
    { ...gen2, generation: 1, observationOrdinal: '00000000:00000000' },
  ] } }, blockNum: 4,
  groupsDerived: [{ groupId: 0, members: [{ data: { uid: '10', addr: '0x1' } }] }],
  validate: async () => ({ valid: false, reason: 'attacker_reason_value' }),
});
const m11aMismatchSelected = await selectEmergencyServerSubmissions({
  sourceDir: taskTmp,
  index: { objects: { 'live/block4/group0.submissions.json': [
    { ...gen2, generation: 1, observationOrdinal: '00000000:00000000' },
  ] } }, blockNum: 4,
  groupsDerived: [{ groupId: 0, members: [{ data: { uid: '10', addr: '0x1' } }] }],
  validate: async () => ({ valid: true, uid: '11', groupId: 0, bundle: {} }),
});
ok('M11a: 不明な無効理由は定数へ畳み、uid 不一致は採用しない',
  m11aInvalidSelected.candidates[0]?.counts?.invalid_payload === 1
  && !JSON.stringify(m11aInvalidSelected.candidates).includes('attacker_reason_value')
  && m11aMismatchSelected.candidates[0]?.counts?.uid_mismatch === 1
  && Object.keys(m11aMismatchSelected.selectedByUid).length === 0);

const m4Unknown = Object.fromEntries(Array.from({ length: 50_000 }, (_, i) => [`outsider-${i}`, 'junk']));
m4Unknown['10'] = 'first-valid';
const m4BulkRow = await save('_observer/generations/live/m4-many-unknown.bin',
  JSON.stringify({ submissionsRaw: m4Unknown }));
let m4ValidationCalls = 0;
const m4BulkSelected = await selectEmergencyServerSubmissions({
  sourceDir: taskTmp, blockNum: 4,
  index: { objects: { 'live/block4/group0.submissions.json': [
    { ...m4BulkRow, generation: 1, observationOrdinal: '00000000:00000000' },
    { ...gen2, generation: 2, observationOrdinal: '00000001:00000000' },
  ] } },
  groupsDerived: [{ groupId: 0, members: [{ data: { uid: '10', addr: '0x1' } }] }],
  validate: async (raw) => { m4ValidationCalls++; return { valid: true, uid: '10', groupId: 0, bundle: { raw } }; },
});
ok('M4: 5万件の無効uidは世代ごとに件数1行へ畳み、正直なrawだけを採る',
  m4BulkSelected.candidates.length === 2
  && m4BulkSelected.candidates[0].counts?.unknownMember === 50_000
  && m4BulkSelected.selectedByUid['10']?.raw === 'first-valid'
  && m4ValidationCalls === 1);
const m4EmergencySource = await fs.readFile(emergencyModulePath, 'utf8');
ok('M4: 無効uidの件数は候補だけでなく緊急差分にも鍵hash・世代単位で載る',
  m4EmergencySource.includes("'emergency.submissionSourceNonMemberEntries'")
  && m4EmergencySource.includes('sourceKeySha256: sha256(Buffer.from(candidate.key))')
  && m4EmergencySource.includes('counts: candidate.counts'));
ok('M4: 葉・全体fingerprintは内容連結でなくdigest、worker選択肢は件数で有界',
  m4EmergencySource.includes('fingerprint: sha256(Buffer.from(JSON.stringify(identifiers)))')
  && m4EmergencySource.includes('fingerprint: sha256(Buffer.from(JSON.stringify(workerFingerprints)))')
  && m4EmergencySource.includes('options.length >= workerOptionLimit')
  && !m4EmergencySource.includes('options.push({\n            hash,\n            fingerprint: JSON.stringify(logical)'));
const m4MillionRowEquivalent = Array.from({ length: 100 }, (_, worker) => (
  createHash('sha256').update(`${worker}:10000-rows`).digest('hex')
));
const m4MillionFingerprint = createHash('sha256')
  .update(JSON.stringify(m4MillionRowEquivalent)).digest('hex');
ok('M4: 100万行相当の100 worker識別子列も固定長digestとなり文字列長上限へ近づかない',
  m4MillionFingerprint.length === 64
  && JSON.stringify(m4MillionRowEquivalent).length < 10_000
  && m4EmergencySource.includes('fingerprint: sha256(Buffer.from(JSON.stringify(workerFingerprints)))'));

// U4: valid Evidence min seq wins and is never replaced by the server candidate.
const adopted = selectAdoptedResults([
  { seq: 9, txHash: 'late', raw: 'chain-late', validation: { valid: true, uid: '10', groupId: 0, bundle: {} } },
  { seq: 2, txHash: 'first', raw: 'chain-first', validation: { valid: true, uid: '10', groupId: 0, bundle: {} } },
]);
ok('U4 mutation: Evidence は seq最大でなく最小の有効提出を採る', adopted.adoptedByUid['10'].seq === 2);
const groupData = {
  members: [{ uid: '10' }, { uid: '11' }],
  submissionsRaw: { '10': 'chain-first', '11': 'untrusted-latest' }, submissions: {},
};
mergeEmergencyServerSubmissions(
  { adoptedByUid: { '10': adopted.adoptedByUid['10'] } }, groupData,
  { '10': { raw: 'server-must-not-win' }, '11': { raw: 'observer-first-valid' } },
);
ok('U4b mutation: サーバー版をEvidenceより優先しない',
  groupData.submissionsRaw['10'] === 'chain-first' && groupData.submissionsRaw['11'] === 'observer-first-valid');

// Y1 / R29-A-1c-01, R29-A-1c-02:
// 群アーカイブ2綴りが無くても、保存済み Stage 3 witness の rawPayload を
// 同じ完全検証入口へ通して採点入力へ戻す。既存2綴りの観測順・先勝ちと
// Evidence 優先は変えない。
const y1BlockNum = 4;
const y1GroupId = 0;
const y1Uid = 'y1-user-10';
const y1Wallet = privateKeyToAccount(`0x${'31'.repeat(32)}`);
const y1SignAccount = privateKeyToAccount(`0x${'32'.repeat(32)}`);
const y1Member = {
  uid: y1Uid,
  addr: y1Wallet.address,
  bAddr: { address: y1SignAccount.address, pubKey: y1SignAccount.publicKey,
    nostrPubkey: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' },
  depIds: JSON.stringify({ deposit: '10000000000000000', ids: ['7'] }),
};
const y1Members = [y1Member];
const y1VerifiedDepositWei = { [y1Uid]: '10000000000000000' };
async function y1Payload(submittedAt, compactGroupId = y1GroupId) {
  const encryptedActions = { votes: {}, reports: {}, observed: { votes: {}, reports: {}, receipts: [] } };
  const encryptedDataHash = keccak256(toHex(JSON.stringify(encryptedActions)));
  const bundle = {
    uid: y1Uid,
    encryptKey: `0x${'33'.repeat(32)}`,
    chatHash: computeChatHashV2([], y1BlockNum, compactGroupId),
    submittedAt,
    encryptedDataHash,
    depositIds: ['7'],
    encryptedActions,
    messages: [],
  };
  const dataString = JSON.stringify({
    blockNum: y1BlockNum, uid: bundle.uid, encryptKey: bundle.encryptKey,
    chatHash: bundle.chatHash, submittedAt: bundle.submittedAt,
    encryptedDataHash: bundle.encryptedDataHash, depositIds: bundle.depositIds,
  });
  bundle.signature = await y1Wallet.signMessage({ message: dataString });
  return compactBytesToPayload(encodeEvidenceCompactV1(bundle, {
    blockNum: y1BlockNum, groupId: compactGroupId,
    memberUids: y1Members.map((member) => member.uid), entryDepositIds: ['7'],
  }));
}
function y1Stage3Witness(rawPayload) {
  return buildGroupWitness({
    groupRow: {
      block_num: y1BlockNum, group_id: y1GroupId, members: JSON.stringify(y1Members),
    },
    groupData: {
      meta: { blockNum: y1BlockNum, groupId: y1GroupId }, members: y1Members,
      submissions: { [y1Uid]: {} }, submissionsRaw: { [y1Uid]: rawPayload },
    },
    verifiedDepositWei: y1VerifiedDepositWei,
    chatWindow: null,
  });
}
const y1Raw = await y1Payload(1_750_000_000_000);
const y1WitnessKey = `verification/block${y1BlockNum}/stage3/group-${y1GroupId}.json`;
const y1WitnessRow = await save(
  '_observer/generations/y1/stage3-group-0.bin', JSON.stringify(y1Stage3Witness(y1Raw)),
);
const y1WitnessOnlyIndex = { objects: { [y1WitnessKey]: [{
  ...y1WitnessRow, generation: 1, observationOrdinal: '00002000:00000000',
}] } };
const y1GroupsDerived = [{
  groupId: y1GroupId,
  members: y1Members.map((member) => ({ data: member })),
}];
const y1Selected = await selectEmergencyServerSubmissions({
  sourceDir: taskTmp, index: y1WitnessOnlyIndex, blockNum: y1BlockNum,
  groupsDerived: y1GroupsDerived,
});
// P1C-06: 緊急経路は窓なしでサーバー保存物を選び直す。採点は
// results.js の calculateGroupResults(…, S.chatWindowMs) で宣言窓を掛ける。
// （この盤面は fixture の宣言窓で直接呼び、results.js の窓の配線は縛らない。）
const priority18 = JSON.parse(await fs.readFile(path.resolve(verifierRoot,
  '../crates/scoring-core/tests/fixtures/priority18.json'), 'utf8'));
const emergencyPriorityCase = priority18.cases.find((row) => row.name === 'outside-e-window');
const emergencyPriorityMembers = emergencyPriorityCase.raw.members.map((m) => ({
  uid: m.uid, addr: m.walletAddress,
  bAddr: JSON.stringify({ address: m.blockAddress }), depIds: JSON.stringify({ ids: m.depositIds }),
}));
const emergencyPriorityPayload = compactBytesToPayload(encodeEvidenceCompactV1(
  emergencyPriorityCase.bundles.alice, {
    blockNum: emergencyPriorityCase.raw.blockNum,
    groupId: emergencyPriorityCase.raw.groupId,
    memberUids: emergencyPriorityMembers.map((m) => m.uid),
  }));
const emergencyPriorityKey = `live/block${emergencyPriorityCase.raw.blockNum}/group${emergencyPriorityCase.raw.groupId}.submissions.json`;
const emergencyPriorityRow = await save('priority18-outside-e-window.bin',
  JSON.stringify({ submissionsRaw: { alice: emergencyPriorityPayload } }));
const emergencyPrioritySelected = await selectEmergencyServerSubmissions({
  sourceDir: taskTmp,
  index: { objects: { [emergencyPriorityKey]: [emergencyPriorityRow] } },
  blockNum: emergencyPriorityCase.raw.blockNum,
  groupsDerived: [{ groupId: emergencyPriorityCase.raw.groupId,
    members: emergencyPriorityMembers.map((member) => ({ data: member })) }],
});
const emergencyPriorityScore = await calculateGroupResults({
  members: emergencyPriorityMembers,
  submissions: { alice: emergencyPrioritySelected.selectedByUid.alice?.bundle },
  meta: { blockNum: emergencyPriorityCase.raw.blockNum, groupId: emergencyPriorityCase.raw.groupId },
  verifiedDepositWei: Object.fromEntries(emergencyPriorityCase.raw.members.map((m) => [m.uid, m.depositWei])),
}, emergencyPriorityCase.raw.minChars, emergencyPriorityCase.raw.minMessages,
emergencyPriorityCase.caps, emergencyPriorityCase.chatWindow);
ok('P1C-06 緊急経路は窓外 E の保存束を選び直し、宣言窓（fixture）で invalid_signature',
  emergencyPrioritySelected.selectedByUid.alice?.valid === true
  && emergencyPriorityScore.results.find((r) => r.uid === 'alice')?.disqualifyReason === 'invalid_signature');
const y1ContradictoryRaw = await y1Payload(1_750_000_000_000, 1);
const y1ContradictoryRow = await save('_observer/generations/y1/contradictory-live.bin',
  JSON.stringify({ submissionsRaw: { [y1Uid]: y1ContradictoryRaw } }));
const y1Contradictory = await selectEmergencyServerSubmissions({
  sourceDir: taskTmp,
  index: { objects: { [`live/block${y1BlockNum}/group0.submissions.json`]: [y1ContradictoryRow] } },
  blockNum: y1BlockNum, groupsDerived: y1GroupsDerived,
});
ok('M9a: 矛盾するcompact枠の保全提出をwarn材料だけにし採用しない',
  y1Selected.contradictions.length === 0
    && y1Contradictory.contradictions.length === 1
    && y1Contradictory.contradictions[0].groupId === 1
    && Object.keys(y1Contradictory.selectedByUid).length === 0);
const y1Contradiction = await submissionContradictsGrouping(
  y1ContradictoryRaw, y1BlockNum, { reason: 'compact_context_mismatch' }, y1Members, y1Members[0].addr,
);
const y1HonestContradiction = await submissionContradictsGrouping(
  y1Raw, y1BlockNum, { valid: true }, y1Members, y1Members[0].addr,
);
const { createReport: y1MakeReport } = await import('../src/report.js');
const y1WarnReport = y1MakeReport();
y1WarnReport.check('check.stageC.evidenceContradictsGrouping', 'warn',
  { count: 1, submissions: [{ seq: 1, groupId: y1Contradiction?.groupId }] });
ok('M9a: 矛盾する真正提出だけが検出されても##RESULTはfullを保つ',
  y1Contradiction?.groupId === 1 && y1HonestContradiction === null
    && categorize({ report: y1WarnReport, fatal: false, stopped: false }) === 'full');
const y1GcpContext = { blockNum: y1BlockNum, data: {
  emergencySource: { authority: 'gcp' },
  emergencySubmissionCandidates: y1Contradictory.candidates,
} };
const y1GcpCount = recordGcpGroupingContradictions(y1GcpContext);
ok('M9a: GCP差分は矛盾の件数・groupId・hashだけを運び停止しない',
  y1GcpCount === 1
    && y1GcpContext.data.emergencyDifferences?.[0]?.checkId
      === 'emergency.gcpEvidenceContradictsGrouping'
    && y1GcpContext.data.emergencyDifferences[0].rebuilt.submissions[0].groupId === 1
    && y1GcpContext.data.emergencyDifferences[0].rebuilt.submissions[0].sha256
      === digest(Buffer.from(y1ContradictoryRaw))
    && !JSON.stringify(y1GcpContext.data.emergencyDifferences).includes(y1Uid));
const p5MissingGroupRescued = classifyMissingGroupEvidence(
  new Set([y1GroupId]), {}, y1Selected.selectedByUid,
);
const p5MissingGroupStillMissing = classifyMissingGroupEvidence(
  new Set([y1GroupId]), {}, {
    [y1Uid]: { ...y1Selected.selectedByUid[y1Uid], valid: false },
    outsider: { uid: 'outsider', groupId: 9, valid: true },
  },
);
ok('P5 R30-A-3-05/A-5-01 欠落群は同群memberの完全検証済み保全提出だけで救済される',
  p5MissingGroupRescued.unrescued.length === 0
  && p5MissingGroupRescued.groups[0]?.preserved === 1
  && p5MissingGroupStillMissing.unrescued.length === 1,
  JSON.stringify({ rescued: p5MissingGroupRescued, rejected: p5MissingGroupStillMissing }));
const m11bEmptyWithGame = classifyMissingGroupEvidence(new Set([y1GroupId]), {}, {
  outsider: { uid: 'outsider', groupId: 9, valid: true },
}, 'saved_other_group_record_or_submission');
const m11bNoGameEvidence = classifyMissingGroupEvidence(new Set([y1GroupId]), {}, {
  outsider: { uid: 'outsider', groupId: 9, valid: true },
});
ok('M11b J3: 他組のゲーム実施証拠がある緊急時だけ提出0の組を空組へ通す',
  m11bEmptyWithGame.unrescued.length === 0
    && m11bEmptyWithGame.groups[0]?.emptyGroup === true
    && m11bNoGameEvidence.unrescued.length === 1);
// J3 の実配線を results.run() まで通す。group1 の archive を欠かし、
// group0 の錨付き保存物だけをゲーム実施の証拠として切り替える。
const m14dJ3Players = Array.from({ length: 6 }, (_, i) => ({
  globalIndex: i, localIndex: i, file: '00_0',
  data: { uid: String(20000001 + i), addr: `0x${'aa'.repeat(20)}`,
    bAddr: null, lang: 'ja', depIds: '[]', name: null, img: null, verified: false },
}));
const m14dJ3Groups = [0, 1].map((groupId) => ({ groupId,
  members: m14dJ3Players.slice(groupId * 3, groupId * 3 + 3) }));
const m14dJ3Archive = { meta: { blockNum: 0, groupId: 0 },
  members: m14dJ3Groups[0].members.map((m) => ({
    uid: m.data.uid, addr: m.data.addr, bAddr: m.data.bAddr,
    lang: m.data.lang, depIds: m.data.depIds, globalIndex: m.globalIndex,
    name: null, img: null, verified: false,
  })), messages: [], submissions: {}, submissionsRaw: {} };
const m14dJ3ArchiveRaw = JSON.stringify(m14dJ3Archive);
const m14dJ3ArchiveRow = await save('m14d-j3-group0.bin', m14dJ3ArchiveRaw);
const m14dJ3Manifest = { blockNum: 0, algorithm: 'sha256', rules: { evidence: null },
  files: { 'games/block0/group0.json': digest(m14dJ3ArchiveRaw) } };
const m14dJ3Files = {
  'entries/block0/game_selection.json': { blockNum: 0, players: m14dJ3Players,
    hashRegisteredBlock: 100, targetBlockNum: 164, confirmationBlocks: 64 },
  'entries/block0/game_groups.json': { blockNum: 0, groups: [] },
  'games/block0/summary.json': { blockNum: 0, groups: [
    { group_id: 0, members: [] }, { group_id: 1, members: [] },
  ] },
  'games/block0/group0.json': m14dJ3Archive,
  'merkle/block_0.json': { blockNum: 0, root: `0x${'ab'.repeat(32)}`, items: [] },
  'verification/block0/manifest.json': m14dJ3Manifest,
};
const m14dJ3EntryEnd = 1700003600;
async function m14dRunJ3(withEvidence, emergencyMode = true) {
  const report = y1MakeReport();
  const files = m14dJ3Files;
  const ctx = {
    blockNum: 0, report, ui: { t: (id) => id, println() {}, warn() {} },
    cfg: { ...DEFAULTS, contracts: { ...DEFAULTS.contracts,
      ethLock: `0x${'11'.repeat(20)}`, evidence: `0x${'22'.repeat(20)}` } },
    data: { groupsDerived: m14dJ3Groups, gameSelection: { players: m14dJ3Players,
      hashRegisteredBlock: 100, targetBlockNum: 164, confirmationBlocks: 64 },
      ...(emergencyMode ? { emergencyServerSubmissions: {}, emergencySource: {
        sourceDir: taskTmp, index: { objects: withEvidence
          ? { 'games/block0/group0.json': [m14dJ3ArchiveRow] } : {} },
        chainResultMarker: { hash: manifestCoreHash(m14dJ3Manifest) },
      } } : {}) },
    chain: {
      blockStates: async () => ({ root: `0x${'ab'.repeat(32)}`,
        verificationStartedAt: 1700006200 }),
      getTimingConstants: async () => ({ startTimeEntryMs: 1700000000000,
        blockTimeMs: 3600000, gamePeriodMs: 1800000,
        submitPeriodMs: 600000, invariantOk: true }),
      ethLockAddress: async () => `0x${'11'.repeat(20)}`,
      evidenceAddress: async () => `0x${'22'.repeat(20)}`,
      // Stage C の採否に必要な、応募終了後・開始前の正典名簿登録。
      // 欠落組の証拠判定を試す3盤面すべてで同じ正直な登録を使う。
      currentGrace: async () => 100,
      otherRegistrationCount: async () => 1,
      otherRegistrationAt: async () => ({
        hash: keccak256(stringToHex('m14d-j3-canonical-roster')),
        registeredBlock: 10, registeredAt: m14dJ3EntryEnd + 1,
      }),
      getResultHash: async () => ({ hash: manifestCoreHash(m14dJ3Manifest), updated: 1 }),
      resultRegistrationCount: async () => 1,
      latest: async () => ({ number: 1000n }),
      getBlock: async () => ({ number: 936n, timestamp: 1900000000n,
        hash: `0x${'cd'.repeat(32)}`, mixHash: `0x${'ef'.repeat(32)}` }),
      resultCount: async () => 0,
      resultWindow: async () => ({ openAt: m14dJ3EntryEnd + 1900,
        closeAt: m14dJ3EntryEnd + 2500 }),
      chatWindow: async () => ({ chatOpenAt: m14dJ3EntryEnd,
        chatCloseAt: m14dJ3EntryEnd + 1900 }),
      findBlockByTimestamp: async () => 900n,
      merkleRootEvents: async () => [],
      verificationPeriod: async () => 600,
      claimPeriod: async () => 10800,
      client: { readContract: async () => { throw new Error('unexpected deposit read'); } },
    },
    r2: { fetchJson: async (key) => key in files
      ? { data: files[key], raw: JSON.stringify(files[key]) } : null,
      refetch: async () => null, exists: async () => false,
      setDefaultReuse() {}, releaseRaw() {}, release() {} },
  };
  let error = null;
  try { await runResults(ctx); } catch (caught) { error = caught; }
  return { ctx, report, error };
}
const m14dJ3WithEvidence = await m14dRunJ3(true);
const m14dJ3NoEvidence = await m14dRunJ3(false);
const m14dJ3Normal = await m14dRunJ3(false, false);
ok('M14d J3: results.run は他組の錨付き保存物で欠落組を空組採点し差分を残す',
  !m14dJ3WithEvidence.error
    && m14dJ3WithEvidence.ctx.data.emergencyDifferences?.some((d) =>
      d.checkId === 'emergency.missingGroupWithoutSubmissions')
    && m14dJ3WithEvidence.report.get('check.stageC.scoring')?.status === 'pass',
  JSON.stringify({ error: m14dJ3WithEvidence.error?.message,
    scoring: m14dJ3WithEvidence.report.get('check.stageC.scoring'),
    differences: m14dJ3WithEvidence.ctx.data.emergencyDifferences }));
ok('M14d J3: results.run はゲーム実施の証拠が無ければ欠落組で止まる',
  m14dJ3NoEvidence.report.get('check.stageC.scoring')?.status === 'fail'
    && !m14dJ3NoEvidence.ctx.data.emergencyDifferences?.some((d) =>
      d.checkId === 'emergency.missingGroupWithoutSubmissions'),
  JSON.stringify({ error: m14dJ3NoEvidence.error?.message,
    scoring: m14dJ3NoEvidence.report.get('check.stageC.scoring') }));
ok('M14d 通常: 欠落組の失敗文に緊急限定の preserved submission を出さない',
  m14dJ3Normal.report.get('check.stageC.scoring')?.status === 'fail'
    && !m14dJ3Normal.report.get('check.stageC.scoring')?.params?.failures
      ?.includes('preserved submission'));
const y1ScoringData = {
  meta: { blockNum: y1BlockNum, groupId: y1GroupId }, members: y1Members,
  submissionsRaw: {}, submissions: {}, verifiedDepositWei: y1VerifiedDepositWei,
};
mergeEmergencyServerSubmissions({ adoptedByUid: {} }, y1ScoringData, y1Selected.selectedByUid);
GameMasterDO.prototype.deriveSubmissionsFromRaw.call({}, y1ScoringData, y1GroupId);
const y1Scored = await calculateGroupResults(y1ScoringData, 0, 0, {}, null);
ok('Y1 正a: 群アーカイブ2綴りが無くてもStage 3 witnessのrawPayloadが採点入力へ入る',
  y1Selected.selectedByUid[y1Uid]?.raw === y1Raw
  && y1ScoringData.submissions[y1Uid]?.uid === y1Uid
  && y1Scored.results[0]?.isDisqualified === false,
  JSON.stringify({
    selected: Object.keys(y1Selected.selectedByUid),
    submissions: Object.keys(y1ScoringData.submissions),
    result: y1Scored.results[0],
  }));

const y1CorruptBytes = compactPayloadToBytes(y1Raw);
const y1SignatureBytes = Buffer.from(y1Stage3Witness(y1Raw).submissions[0].signature.slice(2), 'hex');
const y1SignatureAt = Buffer.from(y1CorruptBytes).indexOf(y1SignatureBytes);
if (y1SignatureAt < 0) throw new Error('Y1 compact payloadの外側署名位置を特定できません');
y1CorruptBytes[y1SignatureAt] ^= 0x01;
const y1CorruptRaw = compactBytesToPayload(y1CorruptBytes);
const y1CorruptWitnessRow = await save(
  '_observer/generations/y1/stage3-group-0-corrupt.bin',
  JSON.stringify(y1Stage3Witness(y1CorruptRaw)),
);
const y1CorruptSelected = await selectEmergencyServerSubmissions({
  sourceDir: taskTmp,
  index: { objects: { [y1WitnessKey]: [{
    ...y1CorruptWitnessRow, generation: 1, observationOrdinal: '00002001:00000000',
  }] } },
  blockNum: y1BlockNum, groupsDerived: y1GroupsDerived,
});
ok('Y1 負: witnessのrawPayload署名を1バイト壊すと完全検証で弾かれ採用されない',
  !y1CorruptSelected.selectedByUid[y1Uid]
  && y1CorruptSelected.candidates.length === 1
  && y1CorruptSelected.candidates[0].counts?.invalid_signature === 1
  && y1CorruptSelected.candidates[0].valid === false
  && y1CorruptSelected.candidates[0].reason === 'invalid_signature',
  JSON.stringify(y1CorruptSelected.candidates));

const y1LateWitnessRow = await save(
  '_observer/generations/y1/stage3-late.bin',
  JSON.stringify({ submissions: [{ uid: '10', rawPayload: 'witness-valid' }] }),
);
const y1ExistingPlusWitnessIndex = {
  objects: {
    ...candidateIndex.objects,
    ['verification/block4/stage3/group-0.json']: [{
      ...y1LateWitnessRow, generation: 4, observationOrdinal: '00000003:00000000',
    }],
  },
};
const y1ValidationOrder = [];
const y1ExistingPlusWitness = await selectEmergencyServerSubmissions({
  sourceDir: taskTmp, index: y1ExistingPlusWitnessIndex, blockNum: 4,
  groupsDerived: [{ groupId: 0, members: [{ data: { uid: '10', addr: '0x1' } }] }],
  validate: async (raw) => {
    y1ValidationOrder.push(raw);
    if (raw === 'signature-ok-core-bad') return { valid: false, reason: 'chathash_mismatch' };
    return { valid: true, uid: '10', groupId: 0, bundle: { raw } };
  },
});
ok('Y1 退行: 既存2綴りの採用物と観測順はStage 3 witnessを源へ足しても従来と同一',
  y1ExistingPlusWitness.selectedByUid['10']?.raw === chosen.selectedByUid['10']?.raw
  && JSON.stringify(y1ValidationOrder) === JSON.stringify([
    'signature-ok-core-bad', 'first-valid', 'last-valid', 'witness-valid',
  ])
  && JSON.stringify(y1ExistingPlusWitness.candidates.slice(0, 3).map((record) => (
    [record.key, record.generation, record.valid, record.reason]
  ))) === JSON.stringify(chosen.candidates.map((record) => (
    [record.key, record.generation, record.valid, record.reason]
  ))),
  JSON.stringify({ selected: y1ExistingPlusWitness.selectedByUid['10'], order: y1ValidationOrder }));

const y1AlternateRaw = await y1Payload(1_750_000_000_001);
const y1AlternateWitnessRow = await save(
  '_observer/generations/y1/stage3-alternate.bin', JSON.stringify(y1Stage3Witness(y1AlternateRaw)),
);
const y1AlternateSelected = await selectEmergencyServerSubmissions({
  sourceDir: taskTmp,
  index: { objects: { [y1WitnessKey]: [{
    ...y1AlternateWitnessRow, generation: 1, observationOrdinal: '00002002:00000000',
  }] } },
  blockNum: y1BlockNum, groupsDerived: y1GroupsDerived,
});
const y1EvidenceData = {
  meta: { blockNum: y1BlockNum, groupId: y1GroupId }, members: y1Members,
  submissionsRaw: { [y1Uid]: y1Raw }, submissions: { [y1Uid]: {} },
};
mergeEmergencyServerSubmissions(
  { adoptedByUid: { [y1Uid]: { raw: y1Raw, seq: 1 } } },
  y1EvidenceData, y1AlternateSelected.selectedByUid,
);
GameMasterDO.prototype.deriveSubmissionsFromRaw.call({}, y1EvidenceData, y1GroupId);
ok('Y1 負: Evidence採用済みuidはwitnessに別rawPayloadが在ってもEvidence側を維持する',
  y1AlternateSelected.selectedByUid[y1Uid]?.raw === y1AlternateRaw
  && y1AlternateRaw !== y1Raw
  && y1EvidenceData.submissionsRaw[y1Uid] === y1Raw
  && y1EvidenceData.submissions[y1Uid]?.submittedAt === 1_750_000_000_000,
  JSON.stringify({
    witnessSelected: y1AlternateSelected.selectedByUid[y1Uid]?.raw === y1AlternateRaw,
    evidenceKept: y1EvidenceData.submissionsRaw[y1Uid] === y1Raw,
  }));

// Y1 正b / R29-A-1c-01 の実害そのもの:
// 1人群は `game-result-calculator.js` の `if (members.length === 1)`（検証スキップ）へ落ちるので、
// 正a の `isDisqualified === false` は「no_submit が立たない」ことの証明にはならない。
// ここは本番と同じ3人群・実署名・実ECIES・実受領証明で、群アーカイブ2綴りが索引に無く
// Evidence が1人分だけある盤面を作り、残り2人が **no_submit で0点にならない**ことを測る
// （0点になると山分けの分母が縮み、ブロックの他の全員の取り分が本来より増える＝S1 の芯）。
const y1bBlockNum = 4;
const y1bGroupId = 0;
const y1bPlayers = [];
for (let i = 0; i < 3; i++) {
  y1bPlayers.push(await makePlayer({
    uid: `2100${i}001`, lang: 'ja', blockNum: y1bBlockNum, keyIndex: 40 + i,
  }));
}
const y1bMembers = y1bPlayers.map((player, i) => ({
  uid: player.uid, addr: player.addr, bAddr: player.bAddrString, lang: 'ja',
  depIds: JSON.stringify({ deposit: '10000000000000000', ids: [String(7 + i)] }),
  globalIndex: i, name: null, img: null, verified: false,
}));
const y1bMemberUids = y1bPlayers.map((player) => player.uid);
const y1bVerifiedDepositWei = Object.fromEntries(y1bMemberUids.map((uid) => [uid, '10000000000000000']));
let y1bTs = 1_750_000_000_000;
const y1bMessages = [];
for (let round = 0; round < 8; round++) {
  for (const player of y1bPlayers) {
    y1bMessages.push({
      uid: player.uid,
      ...(await makeChatWsData(
        player, y1bBlockNum, y1bGroupId,
        `y1b-${round}-${player.uid}`.padEnd(120, 'x'), y1bTs += 1000,
      )),
    });
  }
}
const y1bReceipts = [];
for (let i = 0; i < y1bPlayers.length; i++) {
  const readReceipt = await makeReadReceipt(
    y1bPlayers[(i + 1) % y1bPlayers.length], y1bPlayers[i].uid, y1bMessages,
    y1bBlockNum, y1bGroupId, y1bTs += 1000,
  );
  if (readReceipt) y1bReceipts.push({ ...readReceipt, _seq: y1bReceipts.length });
}
const y1bVotes = {};
for (let i = 0; i < y1bPlayers.length; i++) {
  const voteAction = await makeActionWsData(
    y1bPlayers[i], 'vote', { targetUid: y1bPlayers[(i + 1) % y1bPlayers.length].uid },
    y1bBlockNum, y1bGroupId, y1bTs += 1000,
  );
  y1bVotes[y1bPlayers[i].uid] = voteAction;
  y1bReceipts.push({
    ...(await makeActionReceipt(
      y1bPlayers[(i + 2) % y1bPlayers.length], y1bPlayers[i].uid, 'vote', voteAction,
      y1bBlockNum, y1bGroupId, y1bTs += 1000,
    )),
    _seq: y1bReceipts.length,
  });
}
const y1bRaw = {};
for (let i = 0; i < y1bPlayers.length; i++) {
  const built = await buildSubmissionPayload(y1bPlayers[i], {
    blockNum: y1bBlockNum, groupId: y1bGroupId, serverMessages: y1bMessages,
    serverVotes: y1bVotes, serverReports: {}, receipts: y1bReceipts,
    submittedAt: y1bTs + 10_000 + i, depositIds: JSON.parse(y1bMembers[i].depIds).ids,
    memberUids: y1bMemberUids,
  });
  y1bRaw[y1bPlayers[i].uid] = built.payload;
}
// 平時に実アーカイブから作られた公開 witness は全員分の rawPayload を持つ（group-witness.js の
// `parseSubmissions` が submissionsRaw の compact 文字列をそのまま載せる）。
const y1bWitnessRow = await save(
  '_observer/generations/y1/stage3-group-0-3p.bin',
  JSON.stringify(buildGroupWitness({
    groupRow: {
      block_num: y1bBlockNum, group_id: y1bGroupId, members: JSON.stringify(y1bMembers),
    },
    groupData: {
      meta: { blockNum: y1bBlockNum, groupId: y1bGroupId }, members: y1bMembers,
      submissions: Object.fromEntries(y1bMemberUids.map((uid) => [uid, {}])),
      submissionsRaw: { ...y1bRaw },
    },
    verifiedDepositWei: y1bVerifiedDepositWei,
    chatWindow: null,
  })),
);
const y1bSelected = await selectEmergencyServerSubmissions({
  sourceDir: taskTmp,
  index: { objects: { [`verification/block${y1bBlockNum}/stage3/group-${y1bGroupId}.json`]: [{
    ...y1bWitnessRow, generation: 1, observationOrdinal: '00002003:00000000',
  }] } },
  blockNum: y1bBlockNum,
  groupsDerived: [{ groupId: y1bGroupId, members: y1bMembers.map((member) => ({ data: member })) }],
});
// results.js の合成アーカイブ（`submissionsRaw: {}`）へ Evidence 1件だけが入った状態。
const y1bEvidenceUid = y1bPlayers[0].uid;
const y1bData = {
  meta: { blockNum: y1bBlockNum, groupId: y1bGroupId }, members: y1bMembers,
  submissions: { [y1bEvidenceUid]: {} },
  submissionsRaw: { [y1bEvidenceUid]: y1bRaw[y1bEvidenceUid] },
  verifiedDepositWei: y1bVerifiedDepositWei,
};
mergeEmergencyServerSubmissions(
  { adoptedByUid: { [y1bEvidenceUid]: { raw: y1bRaw[y1bEvidenceUid], seq: 1 } } },
  y1bData, y1bSelected.selectedByUid,
);
GameMasterDO.prototype.deriveSubmissionsFromRaw.call({}, y1bData, y1bGroupId);
const y1bScored = await calculateGroupResults(y1bData, 0, 0, {}, null);
ok('Y1 正b: Evidence 1件の3人群でwitness由来の他2名がno_submit失格せず分母が縮まない',
  y1bScored.results.length === 3
  && y1bScored.results.every((row) => row.isDisqualified === false && row.totalPoints === 20)
  && y1bMemberUids.every((uid) => y1bData.submissions[uid]?.uid === uid)
  && y1bMemberUids.filter((uid) => uid !== y1bEvidenceUid)
    .every((uid) => y1bSelected.selectedByUid[uid]?.raw === y1bRaw[uid])
  && y1bData.submissionsRaw[y1bEvidenceUid] === y1bRaw[y1bEvidenceUid],
  JSON.stringify(y1bScored.results.map((row) => ({
    uid: row.uid, dq: row.isDisqualified, reason: row.disqualifyReason, total: row.totalPoints,
  }))));

// U5: no output gate when any non-public-comparison verification failed.
const baseChecks = new Map([
  ['check.stageA.rootMatch', 'pass'], ['check.stageB.playersMatch', 'pass'],
  ['check.stageB.groupsMatch', 'pass'], ['check.stageC.evidenceCompleteness', 'pass'],
  ['check.stageC.depositVerification', 'pass'], ['check.stageC.depositTableShape', 'pass'],
  ['check.stageC.scoring', 'fail'], ['check.stageC.merkleRebuild', 'pass'],
]);
const checkParams = new Map();
const report = {
  list: () => [...baseChecks].map(([id, status]) => ({ id, status, params: checkParams.get(id) || {} })),
  get: (id) => baseChecks.has(id) ? { status: baseChecks.get(id), params: checkParams.get(id) || {} } : null,
};
await rejects('U5 mutation: 全検査不合格でも書き出す実装をゲートが拒否する',
  async () => assertEmergencyVerificationGate(report, {
    kind: 'groupGame', rebuiltSummary: {}, allGroupResults: [],
  }),
  /verification failed: check.stageC.scoring/);
const p5InvalidCauseOutput = path.join(taskTmp, 'p5-invalid-no-game-cause-output');
await fs.mkdir(p5InvalidCauseOutput, { recursive: true });
const p5InvalidCauseReport = {
  list: () => [{
    id: 'check.stageC.timelineNoGameFinality',
    status: 'fail',
    params: {
      reason: 'invalid_no_game_cause',
      instruction: MANIFEST_CORE_RETRY_INSTRUCTION,
    },
  }],
  get: (id) => (id === 'check.stageC.timelineNoGameFinality'
    ? { status: 'fail', params: { reason: 'invalid_no_game_cause' } }
    : null),
};
await rejects('P5 R30-A-4-03 許可外noGameCauseは正準writerへ入る前に専用failで停止する',
  () => writeEmergencyResultSet({
    ctx: {
      blockNum: 4,
      report: p5InvalidCauseReport,
      data: {
        emergencyRebuild: {
          kind: 'timelineNoGame', invalidNoGameCause: true,
          rebuiltSummary: {}, allGroupResults: [],
        },
      },
    },
    source: {},
    outputDir: p5InvalidCauseOutput,
  }),
  /check\.stageC\.timelineNoGameFinality/);
ok('P5 R30-A-4-03 許可外noGameCauseの停止時は出力を1バイトも作らない',
  (await fs.readdir(p5InvalidCauseOutput)).length === 0);
baseChecks.set('check.stageC.scoring', 'pass');
baseChecks.set('check.stageC.summaryGroupSet', 'fail');
baseChecks.set('check.stageC.merkleTotals', 'fail');
ok('U5b 公開summary/Merkleだけの食い違いは差分保存のため許し、再計算検査のFAILは許さない',
  assertEmergencyVerificationGate(report, {
    kind: 'groupGame', rebuiltSummary: {}, allGroupResults: [],
  }) === true);
baseChecks.delete('check.stageC.summaryGroupSet');
baseChecks.delete('check.stageC.merkleTotals');

const specialChecks = new Map([
  ['check.stageA.rootMatch', 'pass'], ['check.stageB.playersMatch', 'pass'],
  ['check.stageC.depositVerification', 'pass'], ['check.stageC.autoDistribute', 'pass'],
  ['check.stageC.timelineNoGameFinality', 'pass'],
  ['check.stageC.timelineNoGameEvidenceEmpty', 'pass'],
  ['check.stageC.timelineNoGameChatNotStarted', 'pass'],
  ['check.stageC.evidenceCompleteness', 'pass'], ['check.stageC.merkleRebuild', 'pass'],
]);
const specialReport = {
  list: () => [...specialChecks].map(([id, status]) => ({ id, status, params: {} })),
  get: (id) => specialChecks.has(id) ? { status: specialChecks.get(id), params: {} } : null,
};
ok('U5c autoDistribute は通常ゲーム専用のgroups/scoring検査を要求せず専用全検査で開く',
  assertEmergencyVerificationGate(specialReport, {
    kind: 'autoDistribute', rebuiltSummary: {}, allGroupResults: [],
  }) === true);
ok('U5d timeline no-game は安全ブロックfinality・Evidence 0件の専用検査で開く',
  assertEmergencyVerificationGate(specialReport, {
    kind: 'timelineNoGame', rebuiltSummary: {}, allGroupResults: [],
  }) === true);
specialChecks.set('check.stageC.timelineNoGameFinality', 'fail');
await rejects('U5e mutation: timeline no-gameで安全ブロックfinalityを使わなければ拒否する',
  async () => assertEmergencyVerificationGate(specialReport, {
    kind: 'timelineNoGame', rebuiltSummary: {}, allGroupResults: [],
  }), /timelineNoGameFinality/);
specialChecks.set('check.stageC.timelineNoGameFinality', 'pass');

// U4: fail許可19件に、実際のfail→warn降格7件を足した26件が実効集合。
// 🔴 便 Z1（2026-09-21・ユーザー承認）で公開 manifest の申告だけを見る4件を許可側へ移した
//    （rulesReward / evidenceDeclaredDisabled / chatWindowDeclared / claimDataFormat）。
//    rulesTiming は env 経由で再生成 manifest へ焼き込まれるので**移していない**。
const expectedAllowedDifferenceChecks = [
  'check.stageA.entryKeyIntegrity',
  'check.stageC.downloads',
  'check.stageC.groupMembersMatch',
  'check.stageC.groupMeta',
  'check.stageC.rulesPins',
  'check.stageC.rulesReward',
  'check.stageC.evidenceDeclaredDisabled',
  'check.stageC.chatWindowDeclared',
  'check.stageC.groupGameResultsMatch',
  'check.stageC.groupCanonicalTimelineMatch',
  'check.stageC.summaryGroupSet',
  'check.stageC.summaryMatch',
  'check.stageC.autoDistributeConsistent',
  'check.stageC.autoResultPage',
  'check.stageC.autoRoster',
  'check.stageC.noGameSummary',
  'check.stageC.timelineNoGameSummary',
  'check.stageC.merkleRoot',
  'check.stageC.merkleTotals',
  'check.stageC.claimDataFormat',
  'check.stageC.onchainClaimData',
  'check.stageC.evidenceSegmentBoundaries',
];
const expectedDowngradableChecks = [
  'check.stageC.futureAnchorsHash',
  'check.stageC.rosterLiveAnchor',
  'check.stageC.manifestAnchor',
  'check.stageC.rootSubmitted',
  'check.stageC.summaryCanonicalJson',
  'check.stageC.rootResubmitted',
  'check.stageC.rootSubmissionRules',
  'check.stageC.lifecycleReplayCurrent',
];
ok('T1d 緊急の降格配列は件数だけでなくIDと順序を完全一致で固定する',
  JSON.stringify(EMERGENCY_DOWNGRADABLE_CHECKS) === JSON.stringify(expectedDowngradableChecks));
ok('U4-C2/C7 緊急の実効許容集合は22+8=30件で固定され、全件CHECK_INVENTORYに存在する',
  JSON.stringify(EMERGENCY_ALLOWED_DIFFERENCE_CHECKS) === JSON.stringify(expectedAllowedDifferenceChecks)
  && EMERGENCY_DOWNGRADABLE_CHECKS.length === 8
  && EMERGENCY_EFFECTIVE_DIFFERENCE_CHECKS.length === 30
  && EMERGENCY_EFFECTIVE_DIFFERENCE_CHECKS.every((id) => CHECK_INVENTORY.includes(id)));
const fixedThresholds = scoringThresholdsFromPins(DEFAULTS);
ok('U4-C2 manifest rulesを採点権威にせずcfg.pinsの閾値だけを使う',
  fixedThresholds.minChars === DEFAULTS.pins.minChars
  && fixedThresholds.minMessages === DEFAULTS.pins.minMessages
  && JSON.stringify(fixedThresholds.chatCaps) === JSON.stringify(DEFAULTS.pins.chatCaps));
const publicGroupInput = {
  members: [{ uid: 'public-untrusted' }],
  meta: { blockNum: 999, groupId: 999, extra: 'retained-nonscoring-field' },
};
const fixedRoster = [{ uid: 'chain-fixed' }];
const emergencyAuthorityInput = structuredClone(publicGroupInput);
applyEmergencyGroupAuthority(
  { blockNum: 4, data: { emergencySource: { kind: 'unit' } } },
  { d1Groups: [{ group_id: 0, members: JSON.stringify(fixedRoster) }] },
  emergencyAuthorityInput,
  0,
);
const normalAuthorityInput = structuredClone(publicGroupInput);
applyEmergencyGroupAuthority(
  { blockNum: 4, data: {} },
  { d1Groups: [{ group_id: 0, members: JSON.stringify(fixedRoster) }] },
  normalAuthorityInput,
  0,
);
ok('U4-C7 緊急再計算だけはmembers/metaをチェーン固定の再構成名簿へ替え、通常入力は不変',
  JSON.stringify(emergencyAuthorityInput.members) === JSON.stringify(fixedRoster)
  && emergencyAuthorityInput.meta.blockNum === 4 && emergencyAuthorityInput.meta.groupId === 0
  && JSON.stringify(normalAuthorityInput) === JSON.stringify(publicGroupInput));
const c7GateChecks = new Map([
  ['check.stageA.rootMatch', 'pass'], ['check.stageB.playersMatch', 'pass'],
  ['check.stageB.groupsMatch', 'pass'], ['check.stageC.evidenceCompleteness', 'pass'],
  ['check.stageC.depositVerification', 'pass'], ['check.stageC.depositTableShape', 'pass'],
  ['check.stageC.scoring', 'pass'], ['check.stageC.merkleRebuild', 'pass'],
  ['check.stageC.downloads', 'fail'], ['check.stageC.groupMembersMatch', 'fail'],
  ['check.stageC.groupMeta', 'fail'],
]);
const c7GateReport = {
  list: () => [...c7GateChecks].map(([id, status]) => ({ id, status, params: {} })),
  get: (id) => c7GateChecks.has(id) ? { status: c7GateChecks.get(id), params: {} } : null,
};
ok('U4-C7 公開group書庫・members・metaの3差だけでは緊急輸出を止めない',
  assertEmergencyVerificationGate(c7GateReport, {
    kind: 'groupGame', rebuiltSummary: {}, allGroupResults: [],
  }) === true);
c7GateChecks.set('check.stageA.entryKeyIntegrity', 'fail');
ok('S3C14b 入口の鍵不整合だけなら緊急の書き出し関門を通る',
  assertEmergencyVerificationGate(c7GateReport, {
    kind: 'groupGame', rebuiltSummary: {}, allGroupResults: [],
  }) === true);
c7GateChecks.delete('check.stageA.entryKeyIntegrity');
// 🔴 便 Z1（2026-09-21）: この歯の芯は「許容表に無い fail は輸出を拒否する」。
//    rulesReward は許容表へ移ったので、芯を残すため **いまも許容表に無い** IDへ当て直す。
ok('Z1 当て直し先は許容表にも降格表にも無く、CHECK_INVENTORY には在る',
  !EMERGENCY_ALLOWED_DIFFERENCE_CHECKS.includes('check.stageC.rosterKeys')
  && !EMERGENCY_DOWNGRADABLE_CHECKS.includes('check.stageC.rosterKeys')
  && CHECK_INVENTORY.includes('check.stageC.rosterKeys'));
c7GateChecks.set('check.stageC.rosterKeys', 'fail');
await rejects('U4-C7 許可表にも降格表にも無い fail は従来どおり緊急輸出を止める',
  async () => assertEmergencyVerificationGate(c7GateReport, {
    kind: 'groupGame', rebuiltSummary: {}, allGroupResults: [],
  }),
  /verification failed: check\.stageC\.rosterKeys/);
c7GateChecks.delete('check.stageC.rosterKeys');

// 🔴 便 Z1: 移した4件は「その1件だけが fail」でも輸出を止めない。まとめず1件ずつ実測する。
for (const movedId of [
  'check.stageC.rulesReward',
  'check.stageC.evidenceDeclaredDisabled',
  'check.stageC.chatWindowDeclared',
  'check.stageC.claimDataFormat',
]) {
  c7GateChecks.set(movedId, 'fail');
  let opened = false;
  let detail = '';
  try {
    opened = assertEmergencyVerificationGate(c7GateReport, {
      kind: 'groupGame', rebuiltSummary: {}, allGroupResults: [],
    }) === true;
  } catch (error) { detail = String(error?.message || error); }
  c7GateChecks.delete(movedId);
  // 🔴 件名は逐語で正しくする: c7GateChecks には許容済みの3件（downloads / groupMembersMatch /
  //    groupMeta）が fail のまま残っているので「単独 fail」ではない。測っている芯は
  //    「許容済みの fail 集合へこの ID を1件足しても関門が throw しない」である。
  ok(`Z1 公開manifestの申告のみの差 ${movedId} を許容済みfailへ1件足しても緊急輸出を止めない`, opened, detail);
}

// 🔴 便 Z1（逆向きの歯）: rulesTiming は同じ rules 欄でも移せない。START_TIME / BLOCK_TIME /
//    GAME_PERIOD / SUBMIT_PERIOD は makeMemoryGm の env を通って再生成 manifest へ焼き込まれる。
//    将来うっかり許容表へ移したらこの歯が赤になる。
c7GateChecks.set('check.stageC.rulesTiming', 'fail');
await rejects('Z1 rulesTiming は移していない＝単独failでも従来どおり輸出を拒否する',
  async () => assertEmergencyVerificationGate(c7GateReport, {
    kind: 'groupGame', rebuiltSummary: {}, allGroupResults: [],
  }),
  /verification failed: check\.stageC\.rulesTiming/);
c7GateChecks.delete('check.stageC.rulesTiming');
const statusForEmergencyMode = (id, emergencyMode) => (
  isEmergencyCheckDowngradable(id, emergencyMode) ? 'warn' : 'fail'
);
const actuallyDowngraded = CHECK_INVENTORY.filter((id) => (
  statusForEmergencyMode(id, false) !== statusForEmergencyMode(id, true)
));
ok('T1c 同じFAIL入力の通常/緊急statusが食い違うID集合は固定降格配列と完全一致する',
  actuallyDowngraded.every((id) => EMERGENCY_DOWNGRADABLE_CHECKS.includes(id))
  && JSON.stringify(actuallyDowngraded) === JSON.stringify(
    CHECK_INVENTORY.filter((id) => EMERGENCY_DOWNGRADABLE_CHECKS.includes(id))
  ));

// T1d A8: 同じ公開summary再構築失敗を実際のMerkle検査へ通し、mode差分を実行結果から取る。
// merkleRebuildは独立再計算summaryを常に見てpass、公開summary側は別ID merkleRootでfailする。
async function executeMerkleMode(emergencyMode, authority = null) {
  const checks = new Map();
  const root = `0x${'42'.repeat(32)}`;
  const report = {
    check: (id, status, params = {}) => checks.set(id, { status, params }),
    get: (id) => checks.get(id) || null,
    // この対照は履歴能力の制限なし。実reportのfact読取APIを明示する。
    getFact: () => undefined,
  };
  const ctx = {
    blockNum: 4,
    report,
    ui: { t: (id) => id, warn: () => {} },
    data: emergencyMode ? { emergencySource: { kind: 'unit', authority } } : {},
    cfg: { pins: { claimDataFormat: 'bitcoinu-claimdata/3' } },
    chain: {},
  };
  const S = {
    files: {
      summary: { data: { source: 'published-invalid' } },
      merkle: authority === 'gcp'
        ? { raw: JSON.stringify({ root: m3MetaSentinel, totalAmount: m3MetaSentinel,
          blockNum: m3MetaSentinel }), data: { root: m3MetaSentinel,
          totalAmount: m3MetaSentinel, blockNum: m3MetaSentinel } }
        : { data: { root, leafCount: 1, totalAmount: '1' } },
      manifest: { data: { rules: { claimDataFormat: 'invalid-for-early-return' } } },
    },
    rebuiltSummary: { source: 'independent-valid' },
    blockState: { root },
    anomalies: [],
    emergencyRootMissing: false,
  };
  const gm = {
    collectClaimEntriesFromSummary: (_blockNum, summary) => {
      if (summary?.source === 'published-invalid') throw new Error('published summary rejected');
      return [{ key: 'independent' }];
    },
    buildMerkleTree: () => ({ root, leafCount: 1, totalAmount: '1' }),
  };
  await verifyMerkle(ctx, S, gm);
  return checks;
}
const normalMerkleChecks = await executeMerkleMode(false);
const emergencyMerkleChecks = await executeMerkleMode(true);
const m3GcpMerkleChecks = await executeMerkleMode(true, 'gcp');
ok('M11a: 通常と既定緊急の Merkle 公開値は従来の root と totalAmount のまま',
  [normalMerkleChecks, emergencyMerkleChecks].every((checks) =>
    checks.get('check.stageC.merkleRoot')?.params?.published === `0x${'42'.repeat(32)}`
      && checks.get('check.stageC.merkleTotals')?.params?.declared === '1'));
const m11aZkpMerkleS = {
  files: { merkle: { raw: JSON.stringify({ blockNum: 4, root: `0x${'ab'.repeat(32)}` }),
    data: { blockNum: 4, root: `0x${'ab'.repeat(32)}` } } },
  blockState: { root: `0x${'42'.repeat(32)}` },
};
const m11aZkpDefaultCtx = { blockNum: 4,
  data: { emergencySource: {}, emergencyDifferences: [] } };
const m11aZkpGcpCtx = { blockNum: 4,
  data: { emergencySource: { authority: 'gcp' }, emergencyDifferences: [] } };
recordEmergencyZkpMerkleMetadataDifference(m11aZkpDefaultCtx, m11aZkpMerkleS);
recordEmergencyZkpMerkleMetadataDifference(m11aZkpGcpCtx, m11aZkpMerkleS);
ok('M11a: ZKP Merkle 差分の公開 root は既定緊急だけに残り GCP は記述子になる',
  m11aZkpDefaultCtx.data.emergencyDifferences[0]?.params?.publishedRoot === `0x${'ab'.repeat(32)}`
  && m11aZkpGcpCtx.data.emergencyDifferences[0]?.params?.savedMerkleMeta?.sha256
    === digest(Buffer.from(m11aZkpMerkleS.files.merkle.raw))
  && !Object.hasOwn(m11aZkpGcpCtx.data.emergencyDifferences[0]?.params || {}, 'publishedRoot'));
ok('M3: GCP Merkle の check params は保存 root/totalAmount/blockNum の値を写さない',
  !JSON.stringify([...m3GcpMerkleChecks]).includes(m3MetaSentinel)
    && m3GcpMerkleChecks.get('check.stageC.merkleRoot')?.params?.published?.sha256
    && m3GcpMerkleChecks.get('check.stageC.merkleTotals')?.params?.declared?.bytes > 0);
const merkleModeDiff = [...new Set([...normalMerkleChecks.keys(), ...emergencyMerkleChecks.keys()])]
  .filter((id) => normalMerkleChecks.get(id)?.status !== emergencyMerkleChecks.get(id)?.status);
ok('T1d 実Merkle検査でmerkleRebuildは通常/緊急とも独立木pass、公開側はmerkleRoot fail',
  normalMerkleChecks.get('check.stageC.merkleRebuild')?.status === 'pass'
  && emergencyMerkleChecks.get('check.stageC.merkleRebuild')?.status === 'pass'
  && normalMerkleChecks.get('check.stageC.merkleRoot')?.status === 'fail'
  && emergencyMerkleChecks.get('check.stageC.merkleRoot')?.status === 'fail');
ok('T1d 実検査結果から取ったmode差分に配列外IDが無い',
  merkleModeDiff.every((id) => EMERGENCY_DOWNGRADABLE_CHECKS.includes(id)),
  `diff=${JSON.stringify(merkleModeDiff)}`);

// T1e B8: verifyMerkle 1関数だけでは、manifest/timeline側に配列外のmode分岐が
// 混入しても緑のままになる。実関数へ同一fixtureを2モードで入れ、実status差分の和集合を見る。
const modeReport = () => {
  const checks = new Map();
  return {
    checks,
    api: {
      check: (id, status, params = {}) => checks.set(id, { status, params }),
      fact: () => {},
      get: (id) => checks.get(id) || null,
      list: () => [...checks].map(([id, value]) => ({ id, ...value })),
      hasFail: () => [...checks.values()].some((entry) => entry.status === 'fail'),
    },
  };
};

const rulesTimingChain = {
  startTimeEntryMs: 1_000_000,
  blockTimeMs: 100_000,
  gamePeriodMs: 30_000,
  submitPeriodMs: 20_000,
};
const matchingRulesTiming = {
  startTime: String(rulesTimingChain.startTimeEntryMs),
  blockTime: rulesTimingChain.blockTimeMs,
  periodDurations: {
    gamePeriod: rulesTimingChain.gamePeriodMs,
    submitPeriod: rulesTimingChain.submitPeriodMs,
  },
};

async function executeManifestMode(emergencyMode, rules = {}) {
  const { checks, api: report } = modeReport();
  const manifestData = { blockNum: 4, algorithm: 'sha256', rules, files: {} };
  manifestData.manifestHash = manifestCoreHash(manifestData);
  const ctx = {
    blockNum: 4, report,
    ui: { t: (id) => id, println: () => {} },
    data: emergencyMode ? { emergencySource: { kind: 'unit' } } : {},
    cfg: DEFAULTS,
    chain: {
      getResultHash: async () => ({ hash: `0x${'91'.repeat(32)}`, updated: 1 }),
      resultRegistrationCount: async () => 1,
    },
    r2: { release: () => {} },
  };
  const S = {
    files: {
      manifest: { data: manifestData }, summary: null, merkle: null,
      selection: null, gameGroups: null, evidenceReport: null, stage3Manifest: null,
      autoResult: null, rosterIndex: null, groups: new Map(), rosters: new Map(),
    },
    groupIds: [], auto: false,
    blockState: { root: `0x${'00'.repeat(32)}`, verificationStartedAt: 10 },
    anomalies: [], precheckedHashes: new Map(),
  };
  await checkManifest(ctx, S, rulesTimingChain);
  return checks;
}

const matchingRulesTimingChecks = await executeManifestMode(false, matchingRulesTiming);
ok('Z9 rulesTiming 健全系: 公開timing 4値とチェーンimmutableのms値が完全一致すればpass',
  matchingRulesTimingChecks.get('check.stageC.rulesTiming')?.status === 'pass',
  JSON.stringify(matchingRulesTimingChecks.get('check.stageC.rulesTiming')));

const timingMutations = [
  ['startTime', 'START_TIME', (rules, delta) => ({
    ...rules, startTime: String(Number(rules.startTime) + delta),
  })],
  ['blockTime', 'BLOCK_TIME', (rules, delta) => ({
    ...rules, blockTime: rules.blockTime + delta,
  })],
  ['gamePeriod', 'GAME_PERIOD', (rules, delta) => ({
    ...rules,
    periodDurations: { ...rules.periodDurations, gamePeriod: rules.periodDurations.gamePeriod + delta },
  })],
  ['submitPeriod', 'SUBMIT_PERIOD', (rules, delta) => ({
    ...rules,
    periodDurations: { ...rules.periodDurations, submitPeriod: rules.periodDurations.submitPeriod + delta },
  })],
];
for (const [field, mismatchLabel, mutate] of timingMutations) {
  const results = [];
  for (const delta of [-499, 499]) {
    const direct = compareManifestRulesTimingMs(mutate(matchingRulesTiming, delta), rulesTimingChain);
    const checks = await executeManifestMode(false, mutate(matchingRulesTiming, delta));
    results.push(
      direct.length === 1
      && direct[0].startsWith(`${mismatchLabel}:`)
      && checks.get('check.stageC.rulesTiming')?.status === 'fail'
      && String(checks.get('check.stageC.rulesTiming')?.params?.mismatches).startsWith(`${mismatchLabel}:`),
    );
  }
  ok(`Z9 rulesTiming ${field}: -499msと+499msをそれぞれcheck.stageC.rulesTimingのfailで検出する`,
    results.every(Boolean), JSON.stringify(results));
}

async function executeTimelineMode(emergencyMode, timelineMode = 'matching', resultKind = 'groupGame',
  rosterOverride = null) {
  const lateRoster = timelineMode === 'late-roster' || timelineMode.startsWith('rereg-')
    || timelineMode === 'history-pre-entry-only' || rosterOverride !== null;
  const legacyAt = timelineMode === 'legacy-late' ? 100
    : timelineMode === 'legacy-pre-entry' ? 99 : null;
  const { checks, api: report } = modeReport();
  const timelineDerivedRoster = [{ groupId: 0, members: [{ globalIndex: 0, data: {
    uid: 'timeline-u', addr: `0x${'11'.repeat(20)}`,
    bAddr: JSON.stringify({ address: `0x${'22'.repeat(20)}`,
      pubKey: '04' + 'ab'.repeat(64), nostrPubkey: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' }),
    depIds: JSON.stringify({ ids: ['1'] }), lang: 'en', verified: false,
  } }] }];
  const timelinePayloads = reconstructCanonicalRosterPayloads(0, timelineDerivedRoster);
  const rosterGroupText = timelinePayloads.groupTexts.get(0);
  const rosterGroupPath = path.join(taskTmp, 'timeline-roster-group.json');
  await fs.writeFile(rosterGroupPath, rosterGroupText);
  const rosterRaw = timelinePayloads.manifestText;
  const roster = JSON.parse(rosterRaw);
  const rosterC = buildRosterMemberCommitment({ blockNum: 0, manifestText: rosterRaw,
    groupTexts: new Map([[0, rosterGroupText]]) }).C;
  const ctx = {
    blockNum: 0, report,
    ui: { t: lateRoster ? (await import('../src/i18n.js')).t('ja') : (id) => id,
      warn: () => {}, println: () => {} },
    data: emergencyMode ? { emergencySource: { kind: 'unit' },
      groupsDerived: rosterOverride?.derived ?? (resultKind === 'groupGame' ? timelineDerivedRoster : []) }
      : { groupsDerived: rosterOverride?.derived ?? (resultKind === 'groupGame' ? timelineDerivedRoster : []) },
    cfg: DEFAULTS,
    r2: { release: () => {} },
    chain: {
      getOtherHash: async () => ({ hash: rosterC, updated: 1 }),
      getBlock: async () => ({ timestamp: legacyAt ?? 50 }),
      latest: async () => ({ number: 1000n }),
      findBlockByTimestamp: async () => 0n,
      merkleRootEvents: async () => [],
      verificationExtendedEvents: async () => [],
      merkleRootInvalidatedEvents: async () => [],
      verificationPeriod: async () => 10,
      claimPeriod: async () => 10,
      getBlockLifecycle: async () => ({
        mode: 0, merkleRoot: `0x${'00'.repeat(32)}`,
        verificationStartedAt: 10, verificationEndsAt: 20, claimEndsAt: 30, stage: 2,
      }),
    },
  };
  if (lateRoster && timelineMode !== 'history-pre-entry-only') {
    const canonicalHash = rosterC;
    const rows = timelineMode === 'late-roster'
      ? [{ hash: canonicalHash, registeredBlock: 1, registeredAt: 100 },
        { hash: `0x${'91'.repeat(32)}`, registeredBlock: 2, registeredAt: 102 }]
      : [{ hash: timelineMode === 'rereg-different' ? `0x${'91'.repeat(32)}` : canonicalHash,
        registeredBlock: 1, registeredAt: 100 },
        { hash: timelineMode === 'rereg-different' ? canonicalHash : `0x${'91'.repeat(32)}`,
          registeredBlock: 2, registeredAt: 100 },
        ...(timelineMode === 'rereg-same'
          ? [{ hash: canonicalHash, registeredBlock: 3, registeredAt: 100 }] : [])];
    ctx.chain.otherRegistrationCount = async () => rows.length;
    ctx.chain.otherRegistrationAt = async (_key, index) => rows[Number(index)];
  } else if (timelineMode === 'history-pre-entry-only') {
    ctx.chain.otherRegistrationCount = async () => 1;
    ctx.chain.otherRegistrationAt = async () => ({ hash: rosterC,
      registeredBlock: 1, registeredAt: 99 });
  }
  if (rosterOverride) {
    ctx.chain.otherRegistrationCount = async () => 1;
    ctx.chain.otherRegistrationAt = async () => ({ hash: rosterOverride.hash,
      registeredBlock: 1, registeredAt: 100 });
  }
  const matchingTimeline = {
    graceSec: lateRoster ? 1 : 0,
    chattingStart: lateRoster ? 101_000 : 100_000,
    submittingStart: lateRoster ? 201_000 : 200_000,
    closeAt: lateRoster ? 301_000 : 300_000,
    completedAt: lateRoster ? 1_099_000 : 1_098_000,
  };
  const resultFlags = {
    groupGame: { auto: false, noGame: false, timelineNoGame: false },
    autoDistribute: { auto: true, noGame: false, timelineNoGame: false },
    noGame: { auto: false, noGame: true, timelineNoGame: false },
    timelineNoGame: { auto: false, noGame: false, timelineNoGame: true },
  }[resultKind];
  if (!resultFlags) throw new Error(`unknown timeline result kind: ${resultKind}`);
  const summaryBase = resultKind === 'autoDistribute'
    ? { autoDistributed: true }
    : (resultKind === 'groupGame' ? {} : {
      noGame: true,
      ...(resultKind === 'timelineNoGame' ? { noGameReason: 'timeline_unverified' } : {}),
    });
  const S = {
    chatWindow: { chatOpenAt: 100, chatCloseAt: lateRoster ? 201 : 200 },
    resultWindow: { closeAt: lateRoster ? 301 : 300 },
    groupIds: resultKind === 'groupGame' ? [0] : [], ...resultFlags,
    blockState: { root: `0x${'00'.repeat(32)}`, verificationStartedAt: 10 },
    files: {
      summary: {
        data: timelineMode === 'missing'
          ? summaryBase : {
            ...summaryBase,
            timeline: timelineMode === 'null'
              ? null
              : (timelineMode === 'mismatch' ? { ...matchingTimeline, closeAt: 300_001 } : matchingTimeline),
          },
      },
      rosterManifest: rosterOverride ? rosterOverride.live : { data: roster, raw: rosterRaw },
      rosters: rosterOverride ? new Map() : new Map([[0, { path: rosterGroupPath }]]),
    },
    precheckedHashes: rosterOverride ? new Map() : new Map([
      ['games/block0/roster/index.json', { actualHash: roster.indexSha256 }],
      ['games/block0/roster/group0.json', { actualHash: roster.groups[0].sha256 }],
    ]),
    anomalies: [], emergencyRootMissing: true,
  };
  await verifyTimeline(ctx, S, {
    startTimeEntryMs: 0, blockTimeMs: 100_000,
    gamePeriodMs: 100_000, submitPeriodMs: 100_000,
  });
  checks.emergencyDifferences = ctx.data.emergencyDifferences || [];
  checks.emergencyRosterPayloads = ctx.data.emergencyRosterPayloads ?? null;
  return checks;
}

const n5DerivedRoster = [{ groupId: 0, members: [
  { globalIndex: 0, data: { uid: '4294967295', addr: '0x1111111111111111111111111111111111111111',
    bAddr: JSON.stringify({ address: '0x2222222222222222222222222222222222222222',
      pubKey: '04' + 'ab'.repeat(64),
      nostrPubkey: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' }),
    depIds: JSON.stringify({ ids: ['1'] }), lang: 'en', verified: false } },
] }];
const n5Payloads = reconstructCanonicalRosterPayloads(0, n5DerivedRoster);
const n5CanonicalHash = buildRosterMemberCommitment({ blockNum: 0,
  manifestText: n5Payloads.manifestText, groupTexts: n5Payloads.groupTexts }).C;
for (const [label, live] of [
  ['0世代', null],
  ['variant世代', { raw: JSON.stringify({ ...JSON.parse(n5Payloads.manifestText), variant: true }),
    data: { ...JSON.parse(n5Payloads.manifestText), variant: true } }],
]) {
  const emergency = await executeTimelineMode(true, 'matching', 'groupGame', {
    derived: n5DerivedRoster, hash: n5CanonicalHash, live,
  });
  const normal = await executeTimelineMode(false, 'matching', 'groupGame', {
    derived: n5DerivedRoster, hash: n5CanonicalHash, live,
  });
  ok(`N5 ${label}: 緊急は正典 keccak 一致で採用し通常は従来の fail`,
    emergency.get('check.stageC.rosterLiveAnchor')?.status !== 'fail'
    && emergency.emergencyRosterPayloads?.manifestText === n5Payloads.manifestText
    && emergency.emergencyDifferences.some((difference) =>
      difference.checkId === 'emergency.rosterManifestReconstructed'
      && difference.rebuilt?.rosterC === n5CanonicalHash)
    && normal.get('check.stageC.rosterLiveAnchor')?.status === 'fail');
}
const n5WrongDerived = structuredClone(n5DerivedRoster);
n5WrongDerived[0].members[0].data.uid = 'changed';
const n5Wrong = await executeTimelineMode(true, 'matching', 'groupGame', {
  derived: n5WrongDerived, hash: n5CanonicalHash, live: null,
});
ok('N5 誤った組: 再構成 keccak が正典と違えば fail',
  n5Wrong.get('check.stageC.rosterLiveAnchor')?.status === 'fail'
  && !n5Wrong.emergencyRosterPayloads);

const m14dLateRosterChecks = await executeTimelineMode(false, 'late-roster');
for (const [mode, phase] of [['legacy-pre-entry', 'before_entry_end'],
  ['legacy-late', 'at_or_after_chattingStart']]) {
  const normal = await executeTimelineMode(false, mode);
  const emergency = await executeTimelineMode(true, mode);
  const anchor = normal.get('check.stageC.rosterLiveAnchor');
  ok(`R32-B-4-05/06: ${mode}は通常fail・逆の不採用警告なし・事実のphaseあり`,
    anchor?.status === 'fail'
      && !String(anchor.params?.warnings).includes('採用していません')
      && anchor.params?.registrationPhase === phase
      && anchor.params?.preEntryCount === (phase === 'before_entry_end' ? 1 : 0));
  ok(`R32-D-2-07: ${mode}は緊急の差分化を維持`,
    emergency.get('check.stageC.rosterLiveAnchor')?.status === 'warn');
}
const n4HistoryPre = await executeTimelineMode(false, 'history-pre-entry-only');
ok('R32-B-4-06: 履歴つきの応募終了前だけの登録はfailで件数を示す',
  n4HistoryPre.get('check.stageC.rosterLiveAnchor')?.status === 'fail'
    && n4HistoryPre.get('check.stageC.rosterLiveAnchor')?.params?.preEntryCount === 1,
  JSON.stringify(n4HistoryPre.get('check.stageC.rosterLiveAnchor')));
for (const [mode, status] of [['rereg-different', 'warn'], ['rereg-same', 'pass']]) {
  const checks = await executeTimelineMode(false, mode);
  ok(`R32-B-4-03: verifyTimeline実経路の${mode}は${status}`, 
    checks.get('check.stageC.rosterReregistration')?.status === status
      && checks.get('check.stageC.rosterLiveAnchor')?.status === 'pass',
    JSON.stringify([...checks].filter(([id]) => id.startsWith('check.stageC.roster'))));
}
ok('M14d U-B: 開始後の登録は通常 rosterLiveAnchor=warn、件数と不採用を日本語で示す',
  m14dLateRosterChecks.get('check.stageC.rosterLiveAnchor')?.status === 'warn'
    && m14dLateRosterChecks.get('check.stageC.rosterLiveAnchor')?.params?.lateRegistrations === 1
    && m14dLateRosterChecks.get('check.stageC.rosterLiveAnchor')?.params?.warnings
      ?.includes('チャット開始以後の名簿登録1件は採用していません'));
const { t: m14dT } = await import('../src/i18n.js');
ok('M14d U-B: 開始後の登録の不採用は英・中でも件数付き',
  m14dT('en')('stageC.rosterLateRegistrations', { count: 1 }).includes('ignored')
    && m14dT('zh')('stageC.rosterLateRegistrations', { count: 1 }).includes('未采用'));

const z12EmergencyMissingTimeline = await executeTimelineMode(true, 'missing');
const z12MissingTimelineCheck = z12EmergencyMissingTimeline.get('check.stageC.timelineMatch');
const z12TimelineGateReportOf = (timelineCheck, resultKind = 'groupGame') => {
  const checks = new Map(
    EMERGENCY_REQUIRED_CHECKS[resultKind].map((id) => [id, { status: 'pass', params: {} }]),
  );
  checks.set('check.stageC.timelineMatch', timelineCheck);
  return {
    list: () => [...checks].map(([id, entry]) => ({ id, ...entry })),
    get: (id) => checks.get(id) || null,
  };
};
let z12TimelineGateError = null;
try {
  assertEmergencyVerificationGate(z12TimelineGateReportOf(z12MissingTimelineCheck), {
    kind: 'groupGame', rebuiltSummary: {}, allGroupResults: [],
  });
} catch (error) { z12TimelineGateError = error; }
ok('Z12 (a) 緊急モードで timeline キーが無い summary は輸出を拒否し、params に「正しい manifest core を登録してから再実行してください」の指示が載る',
  z12MissingTimelineCheck?.status === 'fail'
  && z12MissingTimelineCheck.params?.reason === 'not_published_emergency'
  && z12MissingTimelineCheck.params?.instruction === MANIFEST_CORE_RETRY_INSTRUCTION
  && /verification failed: check\.stageC\.timelineMatch/.test(String(z12TimelineGateError?.message)),
  JSON.stringify({ check: z12MissingTimelineCheck, gateError: z12TimelineGateError?.message }));

const z19NoGameKinds = ['autoDistribute', 'noGame', 'timelineNoGame'];
const z19EmergencyNoTimeline = await Promise.all(z19NoGameKinds.map(async (resultKind) => {
  const timelineCheck = (await executeTimelineMode(true, 'missing', resultKind))
    .get('check.stageC.timelineMatch');
  let gateError = null;
  try {
    assertEmergencyVerificationGate(z12TimelineGateReportOf(timelineCheck, resultKind), {
      kind: resultKind, rebuiltSummary: {}, allGroupResults: [],
    });
  } catch (error) { gateError = error; }
  return { resultKind, timelineCheck, gateError };
}));
ok('Z19 (a) no-game の3種は summary に timeline が無くても緊急輸出が完走する',
  z19EmergencyNoTimeline.every(({ timelineCheck, gateError }) => (
    timelineCheck?.status === 'skip'
    && timelineCheck.params?.reason === 'not_published_no_game'
    && gateError === null
  )),
  JSON.stringify(z19EmergencyNoTimeline.map(({ resultKind, timelineCheck, gateError }) => ({
    resultKind, timelineCheck, gateError: gateError?.message || null,
  }))));

ok('Z19 (b) ゲーム有り summary に timeline が無ければ緊急輸出は従来どおり拒否する',
  z12MissingTimelineCheck?.status === 'fail'
  && /verification failed: check\.stageC\.timelineMatch/.test(String(z12TimelineGateError?.message)),
  JSON.stringify({ check: z12MissingTimelineCheck, gateError: z12TimelineGateError?.message }));

const z19NormalNoTimeline = await Promise.all(z19NoGameKinds.map(async (resultKind) => ({
  resultKind,
  timelineCheck: (await executeTimelineMode(false, 'missing', resultKind))
    .get('check.stageC.timelineMatch'),
})));
ok('Z19 (c) 通常モードの auto / 0名 / timeline no-game は timeline 無しを従来どおり skip する',
  z19NormalNoTimeline.every(({ timelineCheck }) => (
    timelineCheck?.status === 'skip' && timelineCheck.params?.reason === 'not_published'
  )), JSON.stringify(z19NormalNoTimeline));

const p5EmergencyNullNoGame = await Promise.all(z19NoGameKinds.map(async (resultKind) => ({
  resultKind,
  checks: await executeTimelineMode(true, 'null', resultKind),
})));
ok('P5 R30-A-4-02 緊急no-game 3種の公開timeline=nullは差分を残してskipする',
  p5EmergencyNullNoGame.every(({ checks }) => (
    checks.get('check.stageC.timelineMatch')?.status === 'skip'
    && checks.emergencyDifferences.some((difference) => (
      difference.checkId === 'check.stageC.timelineMatch'
    ))
  )), JSON.stringify(p5EmergencyNullNoGame.map(({ resultKind, checks }) => ({
    resultKind,
    check: checks.get('check.stageC.timelineMatch'),
    differences: checks.emergencyDifferences,
  }))));

const p5TimelineNoGameMismatch = await executeTimelineMode(true, 'mismatch', 'timelineNoGame');
const p5OrdinaryNoGameMismatch = await executeTimelineMode(true, 'mismatch', 'noGame');
const p5AutoNoGameMismatch = await executeTimelineMode(true, 'mismatch', 'autoDistribute');
const p5GameNull = await executeTimelineMode(true, 'null', 'groupGame');
const p5NormalTimelineNoGameNull = await executeTimelineMode(false, 'null', 'timelineNoGame');
ok('P8b P5 R30-A-4-02 緊急no-game 3種は値不一致も差分skip、ゲーム枝と通常モードはfailを保つ',
  p5TimelineNoGameMismatch.get('check.stageC.timelineMatch')?.status === 'skip'
  && p5TimelineNoGameMismatch.emergencyDifferences.filter((difference) => (
    difference.checkId === 'check.stageC.timelineMatch'
  )).length === 1
  && p5OrdinaryNoGameMismatch.get('check.stageC.timelineMatch')?.status === 'skip'
  && p5OrdinaryNoGameMismatch.emergencyDifferences.filter((difference) => (
    difference.checkId === 'check.stageC.timelineMatch'
  )).length === 1
  && p5AutoNoGameMismatch.get('check.stageC.timelineMatch')?.status === 'skip'
  && p5AutoNoGameMismatch.emergencyDifferences.filter((difference) => (
    difference.checkId === 'check.stageC.timelineMatch'
  )).length === 1
  && p5GameNull.get('check.stageC.timelineMatch')?.status === 'fail'
  && p5NormalTimelineNoGameNull.get('check.stageC.timelineMatch')?.status === 'fail',
  JSON.stringify({
    timelineNoGame: p5TimelineNoGameMismatch.get('check.stageC.timelineMatch'),
    ordinaryNoGame: p5OrdinaryNoGameMismatch.get('check.stageC.timelineMatch'),
    autoNoGame: p5AutoNoGameMismatch.get('check.stageC.timelineMatch'),
    game: p5GameNull.get('check.stageC.timelineMatch'),
    normal: p5NormalTimelineNoGameNull.get('check.stageC.timelineMatch'),
  }));

// P5以前の通常0名 no-game shape check は claimLayout を条件にしていなかった。
// 同じ入力のstatus列・##RESULT・終了コードを、その旧真理値で固定する。
const p8bNormalNoGameTruthTable = [];
for (const claimLayout of [undefined, 'wrong-layout', 'group-overlays-v1']) {
  const rebuilt = buildZeroEntryNoGameSummary(4, 3, false);
  const published = { ...rebuilt };
  if (claimLayout === undefined) delete published.claimLayout;
  else published.claimLayout = claimLayout;
  const shapeOk = zeroEntryNoGameSummaryShapeMatches({
    selectionPlayers: [], published, rebuilt, blockNum: 4,
    gameGroups: null, autoResult: null, emergencyMode: false,
  });
  const entries = [
    { id: 'check.stageC.noGameSummary', status: shapeOk ? 'pass' : 'fail', params: {} },
    {
      id: 'check.stageC.summaryMatch',
      status: JSON.stringify(published) === JSON.stringify(rebuilt) ? 'pass' : 'fail',
      params: {},
    },
  ];
  const report = {
    list: () => entries,
    hasFail: () => entries.some((entry) => entry.status === 'fail'),
  };
  const ui = { lines: [], println(line) { this.lines.push(String(line)); } };
  const emitted = emitNonInteractiveOutcome(ui, { fatal: false, stopped: false, report }, null);
  p8bNormalNoGameTruthTable.push({
    claimLayout,
    statuses: entries.map((entry) => `${entry.id}=${entry.status}`),
    result: ui.lines.find((line) => line.startsWith('##RESULT ')),
    exitCode: emitted.exitCode,
  });
}
ok('P8b P5: 通常0名no-gameはP5以前と同じくclaimLayoutをshape条件にせず、status/##RESULT/exitを保つ',
  p8bNormalNoGameTruthTable.every((row) => row.statuses[0] === 'check.stageC.noGameSummary=pass')
  && p8bNormalNoGameTruthTable.slice(0, 2).every((row) => (
    row.statuses[1] === 'check.stageC.summaryMatch=fail'
    && row.result === '##RESULT fail' && row.exitCode === 2
  ))
  && p8bNormalNoGameTruthTable[2].statuses[1] === 'check.stageC.summaryMatch=pass'
  && p8bNormalNoGameTruthTable[2].result === '##RESULT full'
  && p8bNormalNoGameTruthTable[2].exitCode === 0,
  JSON.stringify(p8bNormalNoGameTruthTable));
const p8bEmergencyNoGameRebuilt = buildZeroEntryNoGameSummary(4, 3, true);
const p8bEmergencyNoGameMissingLayout = { ...p8bEmergencyNoGameRebuilt };
delete p8bEmergencyNoGameMissingLayout.claimLayout;
ok('P8b P5: claimLayoutの厳密条件は緊急0名no-gameの枝だけで実際に効く',
  zeroEntryNoGameSummaryShapeMatches({
    selectionPlayers: [], published: p8bEmergencyNoGameRebuilt,
    rebuilt: p8bEmergencyNoGameRebuilt, blockNum: 4,
    gameGroups: null, autoResult: null, emergencyMode: true,
  }) === true
  && zeroEntryNoGameSummaryShapeMatches({
    selectionPlayers: [], published: p8bEmergencyNoGameMissingLayout,
    rebuilt: p8bEmergencyNoGameRebuilt, blockNum: 4,
    gameGroups: null, autoResult: null, emergencyMode: true,
  }) === false);

const z12NormalMissingTimeline = (await executeTimelineMode(false, 'missing'))
  .get('check.stageC.timelineMatch');
ok('Z12 (b) 通常モードでは timeline キーが無いブロックは従来どおり skip である',
  z12NormalMissingTimeline?.status === 'skip'
  && z12NormalMissingTimeline.params?.reason === 'not_published',
  JSON.stringify(z12NormalMissingTimeline));

const z12EmergencyMatchingTimeline = (await executeTimelineMode(true, 'matching'))
  .get('check.stageC.timelineMatch');
ok('Z12 (c) 緊急モードで timeline が在って一致するときは従来どおり pass で完走する',
  z12EmergencyMatchingTimeline?.status === 'pass'
  && assertEmergencyVerificationGate(z12TimelineGateReportOf(z12EmergencyMatchingTimeline), {
    kind: 'groupGame', rebuiltSummary: {}, allGroupResults: [],
  }) === true,
  JSON.stringify(z12EmergencyMatchingTimeline));

const z12MajorLangsTruthTable = [
  { published: [], derived: [], expected: 'pass' },
  { published: ['ja'], derived: ['ja'], expected: 'pass' },
  { published: [], derived: ['ja'], expected: 'fail' },
  { published: undefined, derived: [], expected: 'fail' },
  { published: null, derived: [], expected: 'fail' },
  { published: undefined, derived: undefined, expected: 'pass' },
];
const z12MajorLangsTruthResults = z12MajorLangsTruthTable.map((entry) => ({
  ...entry,
  actual: buildMajorLangsMatchCheck(entry.published, entry.derived),
}));
ok('Z12 (d) majorLangsMatch の status は①②で1つも変わっていない（真偽表）',
  z12MajorLangsTruthResults.every(({ expected, actual }) => (
    actual.status === expected
    && actual.params.instruction === MANIFEST_CORE_RETRY_INSTRUCTION
  )),
  JSON.stringify(z12MajorLangsTruthResults));

const p5EmergencyZeroSummary = buildZeroEntryNoGameSummary(4, 2, true);
const p5NormalZeroSummary = buildZeroEntryNoGameSummary(4, 2, false);
ok('P5 R30-A-6-02 応募0件の緊急再構築も公開v2に追随せずschemaVersion 3＋claimLayoutへ固定',
  p5EmergencyZeroSummary.schemaVersion === 3
  && p5EmergencyZeroSummary.claimLayout === 'group-overlays-v1'
  && p5NormalZeroSummary.schemaVersion === 2
  && p5NormalZeroSummary.claimLayout === undefined,
  JSON.stringify({ emergency: p5EmergencyZeroSummary, normal: p5NormalZeroSummary }));

const p5MajorLangReport = modeReport();
const p5MajorLangCtx = {
  report: p5MajorLangReport.api,
  data: { emergencySource: { kind: 'p5-unit' }, emergencyDifferences: [] },
};
recordMajorLangsMatchForMode(p5MajorLangCtx, ['attacker-lang'], [], {
  emergencyZeroEntryNoGame: true,
});
const p5MajorLangNormal = modeReport();
recordMajorLangsMatchForMode({ report: p5MajorLangNormal.api, data: {} }, ['attacker-lang'], [], {
  emergencyZeroEntryNoGame: true,
});
ok('P5 R30-A-4-02 緊急0名no-gameのmajorLangs不一致だけを差分skipにし通常モードはfailを保つ',
  p5MajorLangReport.checks.get('check.stageC.majorLangsMatch')?.status === 'skip'
  && p5MajorLangCtx.data.emergencyDifferences.filter((difference) => (
    difference.checkId === 'check.stageC.majorLangsMatch'
  )).length === 1
  && p5MajorLangNormal.checks.get('check.stageC.majorLangsMatch')?.status === 'fail',
  JSON.stringify({
    emergency: p5MajorLangReport.checks.get('check.stageC.majorLangsMatch'),
    normal: p5MajorLangNormal.checks.get('check.stageC.majorLangsMatch'),
    differences: p5MajorLangCtx.data.emergencyDifferences,
  }));

const z12RequiredChecks = Object.values(EMERGENCY_REQUIRED_CHECKS).flat();
const z12PolicyTables = [
  ...EMERGENCY_ALLOWED_DIFFERENCE_CHECKS,
  ...EMERGENCY_DOWNGRADABLE_CHECKS,
  ...z12RequiredChecks,
];
ok('Z12 (e) 許容表・降格表・必須表に timelineMatch / majorLangsMatch が入っていない',
  !z12PolicyTables.includes('check.stageC.timelineMatch')
  && !z12PolicyTables.includes('check.stageC.majorLangsMatch'));
ok('Z12 ③ summaryMatch は許容表だけに在り、降格表・必須表には入っていない',
  EMERGENCY_ALLOWED_DIFFERENCE_CHECKS.includes('check.stageC.summaryMatch')
  && !EMERGENCY_DOWNGRADABLE_CHECKS.includes('check.stageC.summaryMatch')
  && !z12RequiredChecks.includes('check.stageC.summaryMatch'));

async function executeMissingRootMode(emergencyMode) {
  const { checks, api: report } = modeReport();
  const ctx = {
    blockNum: 4, report, ui: { t: (id) => id, println: () => {} },
    data: emergencyMode
      ? { emergencySource: { kind: 'unit' }, emergencyDifferences: [] } : {},
  };
  await routeMissingRootInStageC(ctx, { timelineNoGame: false }, {
    root: `0x${'00'.repeat(32)}`, verificationStartedAt: 0,
  });
  return checks;
}

async function executeSummaryCanonicalMode(emergencyMode) {
  const { checks, api: report } = modeReport();
  const root = `0x${'42'.repeat(32)}`;
  const ethLock = `0x${'43'.repeat(20)}`;
  const values = new Map([
    ['entries/block4/game_selection.json', { data: { blockNum: 4, players: [] }, raw: '{"blockNum":4,"players":[]}' }],
    ['games/block4/summary.json', { data: { schemaVersion: 3 }, raw: '{\n  "schemaVersion": 3\n}' }],
    ['merkle/block_4.json', { data: { root, leafCount: 0, totalAmount: '0' }, raw: JSON.stringify({ root, leafCount: 0, totalAmount: '0' }) }],
    ['verification/block4/manifest.json', { data: { blockNum: 4, files: {}, rules: {} }, raw: '{"blockNum":4,"files":{},"rules":{}}' }],
  ]);
  const ctx = {
    blockNum: 4,
    report,
    ui: { t: (id) => id, warn: () => {}, println: () => {} },
    data: {
      noGame: true,
      zkInfo: { blockState: { root, verificationStartedAt: 10, zkEpochPlusOne: 0, proofAttachedAt: 0 } },
      ...(emergencyMode ? { emergencySource: { kind: 'unit' }, emergencyDifferences: [] } : {}),
    },
    cfg: { ...DEFAULTS, contracts: { ...DEFAULTS.contracts, ethLock } },
    chain: {
      getTimingConstants: async () => ({
        startTimeEntryMs: 0, blockTimeMs: 100_000,
        gamePeriodMs: 100_000, submitPeriodMs: 100_000, invariantOk: true,
      }),
      ethLockAddress: async () => ethLock,
    },
    r2: {
      fetchJson: async (key) => values.get(key) || null,
      releaseRaw: () => {}, release: () => {},
    },
  };
  try { await runResults(ctx); } catch { /* 後続検査は本fixtureの対象外 */ }
  return new Map([['check.stageC.summaryCanonicalJson', checks.get('check.stageC.summaryCanonicalJson')]]);
}

{
  const checks = new Map();
  const ctx = { report: { check: (id, status) => checks.set(id, status) } };
  const noEvidence = checkTimelineNoGameEvidenceEmpty(ctx, {
    resultCount: 1, adoptedByUid: {},
  });
  ok('T1f timeline no-game Evidence非空はfalseを返す', noEvidence === false);
  ok('T1f timeline no-game Evidence非空は実検査をFAILにする',
    checks.get('check.stageC.timelineNoGameEvidenceEmpty') === 'fail');
  const resultsSource = await fs.readFile(resultsModulePath, 'utf8');
  ok('T1f Stage C はnoEvidenceの戻り値を受けて終端判定へ渡す',
    resultsSource.includes('const noEvidence = checkTimelineNoGameEvidenceEmpty(ctx, S);')
      && resultsSource.includes('if (!schemaOk || !noEvidence)'));
}

const normalManifestChecks = await executeManifestMode(false);
const emergencyManifestChecks = await executeManifestMode(true);
const normalTimelineChecks = await executeTimelineMode(false);
const emergencyTimelineChecks = await executeTimelineMode(true);
const normalMissingRootChecks = await executeMissingRootMode(false);
const emergencyMissingRootChecks = await executeMissingRootMode(true);
const normalCanonicalChecks = await executeSummaryCanonicalMode(false);
const emergencyCanonicalChecks = await executeSummaryCanonicalMode(true);
const actualModeDiff = (normal, emergency) => (
  [...new Set([...normal.keys(), ...emergency.keys()])]
    .filter((id) => normal.get(id)?.status !== emergency.get(id)?.status)
);
const allActualModeDiff = [...new Set([
  ...merkleModeDiff,
  ...actualModeDiff(normalManifestChecks, emergencyManifestChecks),
  ...actualModeDiff(normalTimelineChecks, emergencyTimelineChecks),
  ...actualModeDiff(normalMissingRootChecks, emergencyMissingRootChecks),
  ...actualModeDiff(normalCanonicalChecks, emergencyCanonicalChecks),
])];
ok('T1e 実checkManifestは同じanchor不一致を通常FAIL・緊急WARNで判定する',
  normalManifestChecks.get('check.stageC.manifestAnchor')?.status === 'fail'
  && emergencyManifestChecks.get('check.stageC.manifestAnchor')?.status === 'warn');
ok('T1e 実verifyTimelineは同じroster不一致を通常FAIL・緊急WARNで判定する',
  normalTimelineChecks.get('check.stageC.rosterLiveAnchor')?.status === 'fail'
  && emergencyTimelineChecks.get('check.stageC.rosterLiveAnchor')?.status === 'warn');
for (const id of [
  'check.stageC.rootResubmitted',
  'check.stageC.rootSubmissionRules',
  'check.stageC.lifecycleReplayCurrent',
]) {
  ok(`T1f 実verifyTimelineは${id}を通常FAIL・緊急WARNで判定する`,
    normalTimelineChecks.get(id)?.status === 'fail'
      && emergencyTimelineChecks.get(id)?.status === 'warn');
}
ok('T1g 実root不在分岐は通常SKIP・緊急WARNで判定する',
  normalMissingRootChecks.get('check.stageC.rootSubmitted')?.status === 'skip'
    && emergencyMissingRootChecks.get('check.stageC.rootSubmitted')?.status === 'warn');
ok('T1g 実runは同じ非正準summaryを通常FAIL・緊急WARNで判定する',
  normalCanonicalChecks.get('check.stageC.summaryCanonicalJson')?.status === 'fail'
    && emergencyCanonicalChecks.get('check.stageC.summaryCanonicalJson')?.status === 'warn');
ok('T1e 実検査群のmode差分集合は降格配列の部分集合（K13 は別の合成盤）',
  allActualModeDiff.length === EMERGENCY_DOWNGRADABLE_CHECKS.length - 1
    && allActualModeDiff.every((id) => EMERGENCY_DOWNGRADABLE_CHECKS.includes(id))
    && !allActualModeDiff.includes('check.stageC.futureAnchorsHash')
    && isEmergencyCheckDowngradable('check.stageC.futureAnchorsHash', true)
    && !isEmergencyCheckDowngradable('check.stageC.futureAnchorsHash', false),
  `diff=${JSON.stringify(allActualModeDiff)}`);
console.log(`T1G_D7_OK modeDiff=${JSON.stringify(allActualModeDiff)}`);

// ------------------------------------------------------------------
// 🔴 便 X1 / Q-A（2026-09-21・ユーザー決定 (a)）: 登録回数の増加を「事故差」に数えない。
//
// `Hardhat/bitcoinu/contracts/HashStorage.sol` の `registerResultHash` の直前のコメントは
// 逐語で次のとおり:
//   「resultHash は何度でも上書き可能（障害時の再計算・再登録に対応）だが、
//     登録回数は単調増加カウンタに記録され改ざんできない（差し替えの可視化）。」
// ＝回数カウンタは**可視化**のためのものであって、違反の印ではない。
// さらに緊急復旧の手順書は再登録を必須にしているので、正しく復旧すると必ず回数が2以上になり、
// 必ず「事故差あり」＝終了コード4 になってしまう。
//
// 🔴 値の正しさは `check.stageC.manifestAnchor` が見ている（`inspectResultManifestAnchor` が
//    チェーンの hash と再計算した core を突き合わせる）。回数側は二重計上だった。
// 🔴 だから外すのは `recordEmergencyDifference()` の呼び出しだけで、
//    `warn` と `S.anomalies` への記録は残す。`skip` / `pass` の枝も変えない。
// ------------------------------------------------------------------
async function executeReregistrationMode({
  emergencyMode = false, regCount = 1, anchorMatches = true,
} = {}) {
  const { checks, api: report } = modeReport();
  const manifestData = { blockNum: 4, algorithm: 'sha256', rules: {}, files: {} };
  manifestData.manifestHash = manifestCoreHash(manifestData);
  const ctx = {
    blockNum: 4, report,
    ui: { t: (id) => id, println: () => {} },
    data: emergencyMode
      ? { emergencySource: { kind: 'unit' }, emergencyDifferences: [] } : {},
    cfg: DEFAULTS,
    chain: {
      getResultHash: async () => ({
        hash: anchorMatches ? manifestData.manifestHash : `0x${'91'.repeat(32)}`,
        updated: 1,
      }),
      // アンカー登録時刻 5 < root 提出 10 ＝ 正当な時点コミットメント。
      getBlock: async () => ({ timestamp: 5 }),
      resultRegistrationCount: async () => {
        if (regCount === 'throws') throw new Error('RPC unavailable');
        return regCount;
      },
    },
    r2: { release: () => {} },
  };
  const S = {
    files: {
      manifest: { data: manifestData }, summary: null, merkle: null,
      selection: null, gameGroups: null, evidenceReport: null, stage3Manifest: null,
      autoResult: null, rosterIndex: null, groups: new Map(), rosters: new Map(),
    },
    groupIds: [], auto: false,
    blockState: { root: `0x${'00'.repeat(32)}`, verificationStartedAt: 10 },
    anomalies: [], precheckedHashes: new Map(),
  };
  await checkManifest(ctx, S, {
    startTimeEntryMs: 0, blockTimeMs: 100_000, gamePeriodMs: 100_000, submitPeriodMs: 100_000,
  });
  return {
    checks,
    reregistration: checks.get('check.stageC.resultReregistration'),
    anchor: checks.get('check.stageC.manifestAnchor'),
    differences: ctx.data.emergencyDifferences ?? null,
    anomalies: S.anomalies,
  };
}

{
  // このfixtureはmanifestのrules宣言が空なので check.stageC.rulesPins 由来の差が常に1件出る。
  // 数えるのは「登録回数」と「値（manifestAnchor）」の2つだけなので、id で絞って測る。
  const idsOf = (differences) => (differences || []).map((entry) => entry.checkId).sort();
  const countOf = (differences, id) => (differences || []).filter((e) => e.checkId === id).length;
  const REREG = 'check.stageC.resultReregistration';
  const ANCHOR = 'check.stageC.manifestAnchor';

  const cleanEmergency = await executeReregistrationMode({ emergencyMode: true, regCount: 2 });
  const single = await executeReregistrationMode({ emergencyMode: true, regCount: 1 });
  ok('X1 Q-A ① 回数 > 1 は warn のまま（fail にしない・可視化は続ける）',
    cleanEmergency.reregistration?.status === 'warn'
      && cleanEmergency.reregistration?.params?.count === 2
      && cleanEmergency.anomalies.filter((a) => a === 'stageC.anomaly.reregistered').length === 1,
    JSON.stringify({ check: cleanEmergency.reregistration, anomalies: cleanEmergency.anomalies }));
  ok('X1 Q-A ② 緊急モードでも回数では差分が1件も増えない',
    countOf(cleanEmergency.differences, REREG) === 0
      && cleanEmergency.anchor?.status === 'pass'
      && JSON.stringify(idsOf(cleanEmergency.differences)) === JSON.stringify(idsOf(single.differences)),
    JSON.stringify({
      count2: idsOf(cleanEmergency.differences), count1: idsOf(single.differences),
      anchor: cleanEmergency.anchor?.status,
    }));

  const cleanNormal = await executeReregistrationMode({ emergencyMode: false, regCount: 2 });
  ok('X1 Q-A ② 通常モードの判定は前と同じ（warn・差分の入れ物は作らない）',
    cleanNormal.reregistration?.status === 'warn'
      && cleanNormal.reregistration?.params?.count === 2
      && cleanNormal.differences === null
      && JSON.stringify([...cleanNormal.checks.keys()]) === JSON.stringify([...cleanEmergency.checks.keys()]),
    JSON.stringify({ check: cleanNormal.reregistration, differences: cleanNormal.differences }));

  // 🔴 ③ 検出力の歯: 値が食い違うケースでは、いまも差分が1件記録される。
  //    これが無いと「回数を数えなくした分だけ検出力が落ちた」ことになる。
  const valueMismatch = await executeReregistrationMode({
    emergencyMode: true, regCount: 2, anchorMatches: false,
  });
  const anchorDifference = (valueMismatch.differences || []).find((e) => e.checkId === ANCHOR);
  ok('X1 Q-A ③ 検出力: 値が食い違えば manifestAnchor 側で差分がいまも1件記録される',
    countOf(valueMismatch.differences, ANCHOR) === 1
      && anchorDifference?.chain?.reason === 'hash_mismatch'
      && valueMismatch.anchor?.status === 'warn'
      && valueMismatch.reregistration?.status === 'warn'
      && countOf(valueMismatch.differences, REREG) === 0,
    JSON.stringify(idsOf(valueMismatch.differences)));
  ok('X1 Q-A ③ 検出力: 通常モードなら同じ食い違いは いまも fail（第三者の検証は緩めない）',
    (await executeReregistrationMode({ emergencyMode: false, regCount: 2, anchorMatches: false }))
      .anchor?.status === 'fail');

  const unreadable = await executeReregistrationMode({ emergencyMode: true, regCount: 'throws' });
  ok('X1 Q-A ④ pass（1回きり）と skip（読めない）の枝は1件も変わっていない',
    single.reregistration?.status === 'pass'
      && single.reregistration?.params?.count === 1
      && countOf(single.differences, REREG) === 0
      && unreadable.reregistration?.status === 'skip'
      && unreadable.reregistration?.params?.reason === 'unreadable'
      && unreadable.reregistration?.status !== 'pass',
    JSON.stringify({ single: single.reregistration, unreadable: unreadable.reregistration }));
  console.log(
    `X1_QA_RESULT count2RerisgDiffs=${countOf(cleanEmergency.differences, REREG)} `
    + `count2Ids=${JSON.stringify(idsOf(cleanEmergency.differences))} `
    + `count1Ids=${JSON.stringify(idsOf(single.differences))} `
    + `valueMismatchIds=${JSON.stringify(idsOf(valueMismatch.differences))}`,
  );
}
let unlistedFailureRejected = true;
for (const id of CHECK_INVENTORY.filter((candidate) => !EMERGENCY_ALLOWED_DIFFERENCE_CHECKS.includes(candidate))) {
  const statuses = new Map([...baseChecks].map(([checkId]) => [checkId, 'pass']));
  statuses.set(id, 'fail');
  const inventoryReport = {
    list: () => [...statuses].map(([checkId, status]) => ({ id: checkId, status, params: {} })),
    get: (checkId) => statuses.has(checkId) ? { status: statuses.get(checkId), params: {} } : null,
  };
  try {
    assertEmergencyVerificationGate(inventoryReport, {
      kind: 'groupGame', rebuiltSummary: {}, allGroupResults: [],
    });
    unlistedFailureRejected = false;
    break;
  } catch {
    // expected: every failed check outside the fixed allowlist closes the export gate
  }
}
ok('T2 CHECK_INVENTORY全件との総当たりで、許可表に無いFAILは1件も降格しない',
  unlistedFailureRejected);
const expectedRequired = {
  groupGame: [
    'check.stageA.rootMatch', 'check.stageB.playersMatch', 'check.stageB.groupsMatch',
    'check.stageC.evidenceCompleteness', 'check.stageC.depositVerification',
    'check.stageC.depositTableShape', 'check.stageC.scoring', 'check.stageC.merkleRebuild',
  ],
  autoDistribute: [
    'check.stageA.rootMatch', 'check.stageB.playersMatch',
    'check.stageC.depositVerification', 'check.stageC.autoDistribute',
    'check.stageC.merkleRebuild',
  ],
  noGame: [
    'check.stageA.rootMatch', 'check.stageB.playersMatch', 'check.stageC.merkleRebuild',
  ],
  timelineNoGame: [
    'check.stageA.rootMatch', 'check.stageB.playersMatch',
    'check.stageC.timelineNoGameFinality', 'check.stageC.timelineNoGameEvidenceEmpty',
    'check.stageC.timelineNoGameChatNotStarted',
    'check.stageC.evidenceCompleteness', 'check.stageC.merkleRebuild',
  ],
};
ok('T2 必須検査は現物の全4種を完全一致で固定し、通常ゲームの実数8件を減らさない',
  JSON.stringify(EMERGENCY_REQUIRED_CHECKS) === JSON.stringify(expectedRequired)
  && Object.values(EMERGENCY_REQUIRED_CHECKS).flat().every((id) => CHECK_INVENTORY.includes(id)));

const resultsSource = await fs.readFile(
  process.env.T1C_RESULTS_SOURCE
    ? path.resolve(process.env.T1C_RESULTS_SOURCE)
    : path.resolve(import.meta.dirname, '../src/stages/results.js'),
  'utf8',
);
const rosterPolicyCalls = [...resultsSource.matchAll(
  /classifyRosterAnchorForMode\(\s*anchorInspection\.failures,\s*anchorInspection\.warnings,\s*Boolean\(ctx\.data\.emergencySource\),\s*\)/g,
)];
const manifestPolicyCalls = [...resultsSource.matchAll(
  /classifyResultManifestAnchorForMode\(\s*anchorInspection,\s*Boolean\(ctx\.data\.emergencySource\),\s*\)/g,
)];
ok('T1c roster/result降格は各1実引数だけがBoolean(emergencySource)を直接渡す',
  rosterPolicyCalls.length === 1 && manifestPolicyCalls.length === 1,
  `roster=${rosterPolicyCalls.length} manifest=${manifestPolicyCalls.length}`);

const lateRosterRaw = '{"blockNum":4,"groups":[]}';
const lateRosterInspection = await inspectRosterAnchor({
  getOtherHash: async () => ({ hash: keccak256(Buffer.from(lateRosterRaw)), updated: 9 }),
  getBlock: async () => ({ timestamp: 10 }),
}, { blockNum: 4, raw: lateRosterRaw, entryEndMs: 0, chattingStartMs: 5000 });
const normalRosterDecision = classifyRosterAnchorForMode(
  lateRosterInspection.failures, lateRosterInspection.warnings, false,
);
const emergencyRosterDecision = classifyRosterAnchorForMode(
  lateRosterInspection.failures, lateRosterInspection.warnings, true,
);
ok('T2 同一fixtureで通常モードは従来どおりFAIL、緊急モードだけ回復不能差としてWARN',
  normalRosterDecision.status === 'fail'
  && normalRosterDecision.failures.length === 1
  && emergencyRosterDecision.status === 'warn'
  && emergencyRosterDecision.accepted.length === 1
  && /ordinary third-party verification remains failed/.test(emergencyRosterDecision.warnings.at(-1)));
const normalLateOutcome = {
  fatal: false, stopped: false,
  report: { hasFail: () => normalRosterDecision.status === 'fail' },
};
ok('T2 正常hashでも登録時刻が遅い通常モード負例は##RESULT fail相当・exit 2',
  categorize(normalLateOutcome) === 'fail' && EXIT_CODE_OF.fail === 2);
const unregisteredRosterInspection = await inspectRosterAnchor({
  getOtherHash: async () => null,
}, { blockNum: 4, raw: lateRosterRaw, entryEndMs: 0, chattingStartMs: 5000 });
const normalUnregisteredRoster = classifyRosterAnchorForMode(
  unregisteredRosterInspection.failures, unregisteredRosterInspection.warnings, false,
);
const emergencyUnregisteredRoster = classifyRosterAnchorForMode(
  unregisteredRosterInspection.failures, unregisteredRosterInspection.warnings, true,
);
ok('T1c 名簿目印未登録は通常FAIL・緊急WARNで差1件として採用される',
  unregisteredRosterInspection.failures.length === 1
  && normalUnregisteredRoster.status === 'fail' && normalUnregisteredRoster.accepted.length === 0
  && emergencyUnregisteredRoster.status === 'warn' && emergencyUnregisteredRoster.accepted.length === 1);
ok('T1c rosterで緊急降格できる理由は未登録・上書き不一致・遅延登録の3件だけ',
  JSON.stringify(EMERGENCY_ROSTER_ANCHOR_DIFFERENCE_REASONS) === JSON.stringify([
    'on-chain roster hash is unregistered',
    'published roster manifest bytes do not match the on-chain hash',
    'on-chain roster hash was registered at or after chattingStart',
  ]));
const lateResultInspection = await inspectResultManifestAnchor({
  getBlock: async () => ({ timestamp: 20 }),
}, { hash: `0x${'aa'.repeat(32)}`, updated: 12 }, `0x${'aa'.repeat(32)}`, 10);
const normalResultDecision = classifyResultManifestAnchorForMode(lateResultInspection, false);
const emergencyResultDecision = classifyResultManifestAnchorForMode(lateResultInspection, true);
ok('T2 result manifestがroot後登録の同一fixtureは通常FAIL、緊急だけWARN',
  lateResultInspection.reason === 'anchored_after_root_submission'
  && normalResultDecision.status === 'fail'
  && normalResultDecision.accepted === false
  && emergencyResultDecision.status === 'warn'
  && emergencyResultDecision.accepted === true);
ok('T2 result manifestで緊急降格できる理由は決定済み4件だけ',
  JSON.stringify(EMERGENCY_RESULT_ANCHOR_DIFFERENCE_REASONS) === JSON.stringify([
    'not_anchored', 'hash_mismatch', 'root_submission_time_unavailable',
    'anchored_after_root_submission',
  ]));
ok('T2 差0件はfull/exit0、差1件はemergency_with_differences/exit4',
  categorizeEmergencyWrite({ differences: [] }, normalLateOutcome) === 'full'
  && EXIT_CODE_OF.full === 0
  && categorizeEmergencyWrite({ differences: [{}] }, normalLateOutcome) === 'emergency_with_differences'
  && EXIT_CODE_OF.emergency_with_differences === 4);

{
  const makeUi = () => {
    const lines = [];
    return { lines, println: (line) => lines.push(String(line)) };
  };
  const outcome = { fatal: false, stopped: false, report: { list: () => [], hasFail: () => false } };
  const difference = { checkId: 'check.stageC.rootSubmitted', what: 'root missing' };
  const withDiff = { differences: [difference] };
  const uiDiff = makeUi();
  emitEmergencyDifferenceMarkers(uiDiff, withDiff);
  const emittedDiff = emitNonInteractiveOutcome(uiDiff, outcome, withDiff);
  ok('T1c 差1件は3種の機械印と終了状態4を出す',
    uiDiff.lines.some((line) => line === `##EMERGENCY_DIFFERENCE ${JSON.stringify(difference)}`)
    && uiDiff.lines.includes('##RESULT emergency_with_differences')
    && uiDiff.lines.includes('##EMERGENCY_RESULT with_differences')
    && emittedDiff.exitCode === 4);

  const uiFull = makeUi();
  emitEmergencyDifferenceMarkers(uiFull, { differences: [] });
  const emittedFull = emitNonInteractiveOutcome(uiFull, outcome, { differences: [] });
  ok('T1c 差0件はdifference印なし・full印・終了状態0を出す',
    !uiFull.lines.some((line) => line.startsWith('##EMERGENCY_DIFFERENCE '))
    && uiFull.lines.includes('##RESULT full')
    && uiFull.lines.includes('##EMERGENCY_RESULT full')
    && emittedFull.exitCode === 0);
  console.log('T1C_CASE_OK emergency-output diff1=exit4 diff0=exit0');
}

// U6: successful export includes non-manifest Stage A input and derives a fresh canonical file list.
for (const key of baseChecks.keys()) baseChecks.set(key, 'pass');
const stage3Key = 'verification/block4/stage3/manifest.json';
const infoKey = 'entries/block4/info/00_info.json';
const obsoleteKey = 'merkle/block_4/levels/99/0.json';
const stage3 = Buffer.from(JSON.stringify({
  schemaVersion: 1, kind: 'bitcoinu-stage3-input-manifest', blockNum: 4,
  groupCount: 0, groups: [],
}));
const info = Buffer.from('{"entries":[]}');
const obsolete = Buffer.from('{"obsolete":true}');
await fs.mkdir(path.join(taskTmp, '_source'), { recursive: true });
await fs.writeFile(path.join(taskTmp, '_source/stage3.bin'), stage3);
await fs.writeFile(path.join(taskTmp, '_source/info.bin'), info);
await fs.writeFile(path.join(taskTmp, '_source/obsolete.bin'), obsolete);
const noGameSummary = {
  schemaVersion: 3, blockNum: 4, blockReward: getBlockRewardWei(4).toString(), totalPlayers: 0, totalGroups: 0,
  noGame: true, majorLangs: [], groups: [],
  claimStatusKey: 'games/block4/claim-status.json', claimLayout: 'group-overlays-v1',
  noGameReason: 'zero_entries',
};
const wr3NoGameSelection = { blockNum: 4, players: [], hashRegisteredBlock: 100,
  targetBlockNum: 164, confirmationBlocks: 64 };
baseChecks.set('check.stageC.merkleRoot', 'fail');
checkParams.set('check.stageC.merkleRoot', {
  recomputed: '0x1f06c2896619bc4054f4f3de8dcee35acde9cacc632ef5184140e3e329c59383',
});
const selectedManifest = {
  blockNum: 4, algorithm: 'sha256',
  rules: {
    minChars: DEFAULTS.pins.minChars, minMessages: DEFAULTS.pins.minMessages,
    maxChars: DEFAULTS.pins.chatCaps.maxChars,
    maxMessages: DEFAULTS.pins.chatCaps.maxMessages,
    maxMsgChars: DEFAULTS.pins.chatCaps.maxMsgChars,
    periodDurations: { gamePeriod: 60_000, submitPeriod: 60_000 },
    startTime: null, blockTime: null,
  },
  files: { [stage3Key]: digest(stage3), [obsoleteKey]: digest(obsolete) },
};
const outputDir = path.join(taskTmp, 'export');
const originalFinalizeNoGameBlock = GameMasterDO.prototype.finalizeNoGameBlock;
let canonicalNoGameWriterCalls = 0;
let canonicalNoGameMeta = null;
GameMasterDO.prototype.finalizeNoGameBlock = async function (...args) {
  canonicalNoGameWriterCalls++;
  canonicalNoGameMeta = args[1];
  return originalFinalizeNoGameBlock.apply(this, args);
};
let written;
try {
  written = await writeEmergencyResultSet({
  ctx: {
    blockNum: 4, report, cfg: DEFAULTS,
    data: {
      gameSelection: wr3NoGameSelection,
      emergencyRebuild: {
        kind: 'noGame',
        rebuiltSummary: noGameSummary, allGroupResults: [], evidence: {
          resultCount: null, adoptedCount: null, chatWindowMs: null,
        },
        noGameMeta: { reason: 'zero_entries' },
      },
      emergencyGroupArchives: new Map(), emergencyServerSubmissions: {},
      emergencySubmissionCandidates: [],
      emergencyDifferences: [
        {
          checkId: 'check.stageC.manifestAnchor',
          what: 'result manifest was registered after root submission',
          chain: { reason: 'anchored_after_root_submission', updatedTimestamp: 20, rootSubmittedAt: 10 },
          rebuilt: { manifestCoreHash: manifest.manifestHash },
        },
        {
          checkId: 'check.stageC.summaryCanonicalJson',
          what: 'published summary is not canonical minified JSON',
          chain: { declaredSha256: 'public-dirty-summary' },
          rebuilt: { action: 'serialize the independently recomputed summary with JSON.stringify' },
        },
        {
          checkId: 'check.stageC.rootSubmitted',
          what: 'existing Merkle root is absent',
          chain: { root: null },
          rebuilt: { action: 'derive a fresh Merkle root from the independently recomputed summary' },
        },
      ],
    },
  },
  source: {
    sourceDir: taskTmp, selectedManifest, selected: [], index: { sourceRunId: 'unit-run' },
    applicantRegistration: resolvedApplicant.applicantRegistration,
    applicantRegistrationCount: resolvedApplicant.applicantRegistrationCount,
    chainResultMarker: resolvedWithUnknownResultMarker.chainResultMarker,
    differences: [
      ...resolvedWithoutResultMarker.differences,
      ...resolvedWithUnknownResultMarker.differences,
      ...m3Picked.differences,
    ],
    fileMap: new Map([
      [stage3Key, '_source/stage3.bin'], [infoKey, '_source/info.bin'],
      [obsoleteKey, '_source/obsolete.bin'],
    ]),
  },
  outputDir,
  });
} finally {
  GameMasterDO.prototype.finalizeNoGameBlock = originalFinalizeNoGameBlock;
}
const writtenManifest = JSON.parse(await fs.readFile(path.join(outputDir, 'verification/block4/manifest.json')));
const writtenIndex = JSON.parse(await fs.readFile(path.join(outputDir, '_emergency/bundle-index.json')));
const writtenDifferences = JSON.parse(await fs.readFile(path.join(outputDir, '_emergency/differences.json')));
ok('M3: 保存 Merkle 比較資料の番兵値は書き出した差分 JSON に出ない',
  writtenDifferences.differences.some((difference) =>
    difference.checkId === 'emergency.gcpComparisonGeneration')
    && !JSON.stringify(writtenDifferences).includes(m3MetaSentinel));
const writerProvenance = JSON.parse(await fs.readFile(path.join(outputDir, '_emergency/writer-provenance.json')));
ok('U6 特殊ブロックでも平時GMのfinalizeNoGameBlockを実呼出しして固定一式を作る',
  written.bundleIndex.complete === true
  && canonicalNoGameWriterCalls === 1
  && canonicalNoGameMeta?.offlineMaterialize === true
  && writerProvenance.vendoredCanonicalCalls.includes('GameMasterDO.finalizeNoGameBlock')
  && writtenManifest.files[stage3Key] === digest(stage3)
  && !Object.hasOwn(writtenManifest.files, obsoleteKey)
  && writtenIndex.files.some((item) => item.key === infoKey && item.sha256 === digest(info))
  && writtenIndex.files.some((item) => item.key === 'games/block4/claim-status.json')
  && writtenIndex.files.some((item) => item.key === `_emergency/public/${obsoleteKey}`)
  && writtenIndex.applicantRegistration.index === resolvedApplicant.applicantRegistration.index
  && writtenIndex.differenceCount === writtenDifferences.differences.length
  && ['check.stageC.manifestAnchor', 'check.stageC.summaryCanonicalJson', 'check.stageC.rootSubmitted']
    .every((checkId) => writtenDifferences.differences.some((difference) => difference.checkId === checkId))
  && writtenDifferences.differences.every((difference) => (
    Object.hasOwn(difference, 'what')
    && Object.hasOwn(difference, 'chain')
    && Object.hasOwn(difference, 'rebuilt')
  )));
ok('T2 resultHash未登録・保存外・root後登録、root無し、非正準summaryの差を抱えて固定一式まで完走',
  written.bundleIndex.complete === true
  && writtenDifferences.differences.some((difference) => difference.what === 'result manifest marker is absent')
  && writtenDifferences.differences.some((difference) => difference.what === 'result manifest marker does not select any saved generation')
  && writtenDifferences.differences.some((difference) => difference.what === 'result manifest was registered after root submission')
  && writtenDifferences.differences.some((difference) => difference.what === 'existing Merkle root is absent')
  && writtenDifferences.differences.some((difference) => difference.what === 'published summary is not canonical minified JSON'));

// V8: public manifest bytes are material only when manifestCore differs. Full-byte evidence remains retained.
ok('V8 Y5 resultCount=0だけ緊急adoptedCountをnullにし、1件以上は従来の数値を保つ',
  emergencyAdoptedCountOf(0, {}) === null
  && emergencyAdoptedCountOf(2, { alice: {}, bob: {} }) === 2);
ok('V8 Y6 通常モードはresultCount=0に限りadoptedCount null/0の両方を0件として許容する',
  declaredAdoptedCountForVerification({ resultCount: 0, adoptedCount: null }) === 0
  && declaredAdoptedCountForVerification({ resultCount: 0, adoptedCount: 0 }) === 0
  && declaredAdoptedCountForVerification({ resultCount: 1, adoptedCount: null }) === null
  && declaredAdoptedCountForVerification({ resultCount: 1, adoptedCount: 0 }) === 0);

baseChecks.set('check.stageC.merkleRoot', 'pass');
const v8ManifestKey = 'verification/block4/manifest.json';
const v8SummaryKey = 'games/block4/summary.json';
const v8FixedIso = '2026-09-20T12:34:56.000Z';
const v8CleanRebuild = () => ({
  kind: 'noGame',
  rebuiltSummary: noGameSummary,
  allGroupResults: [],
  depositorResults: [],
  evidence: {
    resultCount: 0,
    adoptedCount: emergencyAdoptedCountOf(0, {}),
    chatWindowMs: null,
  },
  noGameMeta: { reason: 'zero_entries' },
});
const v8CleanCtx = () => ({
  blockNum: 4,
  report,
  cfg: DEFAULTS,
  data: {
    gameSelection: wr3NoGameSelection,
    emergencyRebuild: v8CleanRebuild(),
    emergencyGroupArchives: new Map(),
    emergencyServerSubmissions: {},
    emergencySubmissionCandidates: [],
    emergencyDifferences: [],
  },
});
const v8SeedDir = path.join(taskTmp, 'v8-seed');
const v8Seed = await withFixedNow(v8FixedIso, () => writeEmergencyResultSet({
  ctx: v8CleanCtx(),
  source: {
    sourceDir: taskTmp,
    selectedManifest,
    selected: [],
    index: { sourceRunId: 'v8-unit' },
    fileMap: new Map([
      [stage3Key, '_source/stage3.bin'],
      [infoKey, '_source/info.bin'],
    ]),
  },
  outputDir: v8SeedDir,
}));
const m11aCountCtx = v8CleanCtx();
m11aCountCtx.data.emergencySubmissionCandidates = [
  { key: 'live/block4/group0.submissions.json', generation: 2, sha256: 'a'.repeat(64),
    bytes: 24, counts: { unknownMember: 3 } },
  { key: 'verification/block4/stage3/group-0.json', generation: 3, sha256: 'b'.repeat(64),
    bytes: 48, counts: { invalid_payload: 2 } },
];
const m11aCountDir = path.join(taskTmp, 'm11a-count-export');
await withFixedNow(v8FixedIso, () => writeEmergencyResultSet({
  ctx: m11aCountCtx,
  source: { sourceDir: taskTmp, selectedManifest, selected: [],
    index: { sourceRunId: 'm11a-unit' },
    fileMap: new Map([[stage3Key, '_source/stage3.bin'], [infoKey, '_source/info.bin']]) },
  outputDir: m11aCountDir,
}));
const m11aCountDiffs = JSON.parse(await fs.readFile(
  path.join(m11aCountDir, '_emergency/differences.json'), 'utf8'));
ok('M11a: 保存提出の非メンバーと無効rawの件数が鍵hash・世代とともに差分へ出る',
  m11aCountDiffs.differences?.some((d) => d.checkId === 'emergency.submissionSourceNonMemberEntries'
    && d.chain.sourceKeySha256 === digest(Buffer.from('live/block4/group0.submissions.json'))
    && d.chain.generation === 2 && d.chain.counts.unknownMember === 3)
  && m11aCountDiffs.differences?.some((d) => d.checkId === 'emergency.submissionInvalidEntries'
    && d.chain.generation === 3 && d.chain.counts.invalid_payload === 2));
const v8SeedManifestBytes = await fs.readFile(path.join(v8SeedDir, v8ManifestKey));
const v8SeedManifest = JSON.parse(v8SeedManifestBytes);
const v8SeedSummaryBytes = await fs.readFile(path.join(v8SeedDir, v8SummaryKey));
const m3GcpWriterSource = (marker) => ({
  authority: 'gcp', chainResultMarker: { hash: marker },
  sourceDir: taskTmp, selectedManifest, selected: [],
  index: { sourceRunId: 'm3-unit' },
  fileMap: new Map([[stage3Key, '_source/stage3.bin'], [infoKey, '_source/info.bin']]),
});
const m3GcpWriterCtx = () => {
  const ctx = v8CleanCtx();
  ctx.data.emergencySource = { authority: 'gcp', gcpHistoricalProofHash: true };
  return ctx;
};
const m3WrongMarkerDir = path.join(taskTmp, 'm3-gcp-writer-wrong');
await rejects('M3: 旧証明付き GCP 書き出しは現在目印が再計算 core と違えば停止',
  () => withFixedNow(v8FixedIso, () => writeEmergencyResultSet({
    ctx: m3GcpWriterCtx(), source: m3GcpWriterSource(`0x${'ee'.repeat(32)}`),
    outputDir: m3WrongMarkerDir,
  })), /register the deterministic fixed result core/);
ok('M3: 目印不一致の停止では固定一式を1ファイルも書かない',
  (await fs.readdir(m3WrongMarkerDir).catch(() => [])).length === 0);
const m3RightMarkerDir = path.join(taskTmp, 'm3-gcp-writer-right');
const m3RightMarkerWritten = await withFixedNow(v8FixedIso, () => writeEmergencyResultSet({
  ctx: m3GcpWriterCtx(), source: m3GcpWriterSource(manifestCoreHash(v8SeedManifest)),
  outputDir: m3RightMarkerDir,
}));
ok('M3: 旧証明付きでも現在目印が再計算 core と同じなら書き出す',
  m3RightMarkerWritten.bundleIndex.complete === true
    && (await fs.readFile(path.join(m3RightMarkerDir, v8ManifestKey), 'utf8'))
      === v8SeedManifestBytes.toString('utf8'));
const n7WrittenCore = manifestCoreHash(v8SeedManifest);
const n7SyntheticCore = manifestCoreHash(selectedManifest);
ok('N7 J2 GCP: collector の合成 core と GM 書き出し core は別の値',
  n7WrittenCore !== n7SyntheticCore);
const n7GcpJ2Ctx = () => {
  const ctx = v8CleanCtx();
  ctx.data.emergencySource = { authority: 'gcp', gcpUntraceableOldProof: true };
  return ctx;
};
const n7BeforeDir = path.join(taskTmp, 'n7-j2-before-registration');
let n7BeforeError = null;
try {
  await withFixedNow(v8FixedIso, () => writeEmergencyResultSet({
    ctx: n7GcpJ2Ctx(), source: m3GcpWriterSource(n7SyntheticCore),
    outputDir: n7BeforeDir,
  }));
} catch (error) { n7BeforeError = error; }
ok('N7 J2 GCP: 合成 core を目印にしても書き出し core を表示し、1ファイルも書かない',
  String(n7BeforeError?.message).includes(n7WrittenCore)
    && (await fs.readdir(n7BeforeDir).catch(() => [])).length === 0,
  n7BeforeError?.message);
const n7AttackerDir = path.join(taskTmp, 'n7-j2-attacker-marker');
let n7AttackerError = null;
try {
  await withFixedNow(v8FixedIso, () => writeEmergencyResultSet({
    ctx: n7GcpJ2Ctx(), source: m3GcpWriterSource(`0x${'aa'.repeat(32)}`),
    outputDir: n7AttackerDir,
  }));
} catch (error) { n7AttackerError = error; }
ok('N7 J2 GCP: 攻撃者目印でも書き出し core を表示して停止',
  String(n7AttackerError?.message).includes(n7WrittenCore)
    && (await fs.readdir(n7AttackerDir).catch(() => [])).length === 0,
  n7AttackerError?.message);
const n7AfterDir = path.join(taskTmp, 'n7-j2-after-registration');
const n7AfterWritten = await withFixedNow(v8FixedIso, () => writeEmergencyResultSet({
  ctx: n7GcpJ2Ctx(), source: m3GcpWriterSource(n7WrittenCore),
  outputDir: n7AfterDir,
}));
ok('N7 J2 GCP: 書き出し core の登録後は固定一式を完走する',
  n7AfterWritten.bundleIndex.complete === true
    && (await fs.readFile(path.join(n7AfterDir, v8ManifestKey), 'utf8'))
      === v8SeedManifestBytes.toString('utf8'));

// ==================================================================
// 🔴 便 Z10 / R29-A-3b-01（2026-09-22）
//   manifestHash は manifestCore 外の自称ラベル。緊急時はこの脚だけを差分化する。
//   blockNum / algorithm は従来どおり fail-closed、通常モードは旧3脚ANDと同じ。
// ==================================================================
async function runZ10ManifestCheck({ emergencyMode, blockNum = 4, algorithm = 'sha256', badLabel = false }) {
  const manifestData = { ...v8SeedManifest, blockNum, algorithm };
  const computedManifestCoreHash = manifestCoreHash(manifestData);
  manifestData.manifestHash = badLabel ? `0x${'f1'.repeat(32)}` : computedManifestCoreHash;
  const { checks, api: manifestReport } = modeReport();
  const ctx = {
    blockNum: 4,
    report: manifestReport,
    ui: { t: (id) => id, println: () => {} },
    data: emergencyMode ? { emergencySource: { kind: 'z10-unit' } } : {},
    cfg: DEFAULTS,
    chain: {
      getResultHash: async () => ({ hash: computedManifestCoreHash, updated: 1 }),
      getBlock: async () => ({ timestamp: 1 }),
      resultRegistrationCount: async () => 1,
    },
    r2: { release: () => {}, refetch: async () => null },
  };
  const S = {
    files: {
      manifest: { data: manifestData }, summary: null, merkle: null,
      selection: null, gameGroups: null, evidenceReport: null, stage3Manifest: null,
      autoResult: null, rosterIndex: null, groups: new Map(), rosters: new Map(),
    },
    groupIds: [], auto: false,
    blockState: { root: `0x${'00'.repeat(32)}`, verificationStartedAt: 10 },
    anomalies: [],
    // この歯が測るのは manifest 自身の3脚。manifest.files の全バイトは前段で照合済みとする。
    precheckedHashes: new Map(
      Object.keys(manifestData.files || {}).map((key) => [key, { bad: false, parked: false }]),
    ),
  };
  await checkManifest(ctx, S, {
    startTimeEntryMs: Number(manifestData.rules.startTime),
    blockTimeMs: Number(manifestData.rules.blockTime),
    gamePeriodMs: Number(manifestData.rules.periodDurations?.gamePeriod),
    submitPeriodMs: Number(manifestData.rules.periodDurations?.submitPeriod),
  });
  return { checks, ctx, manifestData, computedManifestCoreHash };
}

const z10EmergencyBadLabel = await runZ10ManifestCheck({ emergencyMode: true, badLabel: true });
const z10Difference = z10EmergencyBadLabel.ctx.data.emergencyDifferences?.filter(
  (difference) => difference.checkId === 'check.stageC.manifestSelfConsistent',
) || [];
const z10GateReport = (entry) => ({
  list: () => [{ id: 'check.stageC.manifestSelfConsistent', ...entry }],
  get: (id) => (id === 'check.stageC.manifestSelfConsistent'
    ? entry
    : (id === 'check.stageC.merkleRoot'
      ? { status: 'pass', params: { recomputed: v8Seed.bundleIndex.merkleRoot } }
      : (EMERGENCY_REQUIRED_CHECKS.noGame.includes(id) ? { status: 'pass', params: {} } : null))),
});
const z10ExportDir = path.join(taskTmp, 'z10-manifest-hash-label-export');
const z10ExportCtx = v8CleanCtx();
z10ExportCtx.report = z10GateReport(
  z10EmergencyBadLabel.checks.get('check.stageC.manifestSelfConsistent'),
);
z10ExportCtx.data.emergencyDifferences = [...z10Difference];
let z10Export = null;
let z10ExportError = null;
try {
  z10Export = await withFixedNow(v8FixedIso, () => writeEmergencyResultSet({
    ctx: z10ExportCtx,
    source: {
      sourceDir: taskTmp,
      selectedManifest: z10EmergencyBadLabel.manifestData,
      selected: [],
      index: { sourceRunId: 'z10-unit' },
      fileMap: new Map([
        [stage3Key, '_source/stage3.bin'],
        [infoKey, '_source/info.bin'],
      ]),
    },
    outputDir: z10ExportDir,
  }));
} catch (error) { z10ExportError = error; }
const z10WrittenDifferences = z10Export
  ? JSON.parse(await fs.readFile(path.join(z10ExportDir, '_emergency/differences.json'), 'utf8')).differences
  : [];
ok('Z10 (a) 自称 manifestHash だけを壊した公開 manifest でも緊急輸出が完走し、差分1件のparamsに自称値と計算値を残す',
  z10EmergencyBadLabel.checks.get('check.stageC.manifestSelfConsistent')?.status === 'warn'
  && z10Export?.bundleIndex?.complete === true
  && z10WrittenDifferences.length === 1
  && z10WrittenDifferences[0]?.params?.declaredManifestHash
    === z10EmergencyBadLabel.manifestData.manifestHash
  && z10WrittenDifferences[0]?.params?.computedManifestCoreHash
    === z10EmergencyBadLabel.computedManifestCoreHash,
  String(z10ExportError?.message || JSON.stringify(z10WrittenDifferences)));

const z10BadBlock = await runZ10ManifestCheck({ emergencyMode: true, blockNum: 5 });
await rejects('Z10 (b) manifest.blockNum を N と違う値にすると従来どおり緊急輸出を拒否する',
  () => assertEmergencyVerificationGate(
    z10GateReport(z10BadBlock.checks.get('check.stageC.manifestSelfConsistent')),
    { kind: 'noGame', rebuiltSummary: {}, allGroupResults: [] },
  ),
  /verification failed: check\.stageC\.manifestSelfConsistent/);

const z10BadAlgorithm = await runZ10ManifestCheck({ emergencyMode: true, algorithm: 'sha512' });
await rejects("Z10 (c) manifest.algorithm を 'sha256' 以外にすると従来どおり緊急輸出を拒否する",
  () => assertEmergencyVerificationGate(
    z10GateReport(z10BadAlgorithm.checks.get('check.stageC.manifestSelfConsistent')),
    { kind: 'noGame', rebuiltSummary: {}, allGroupResults: [] },
  ),
  /verification failed: check\.stageC\.manifestSelfConsistent/);

// 通常モードの3脚を全8組合せで測る。旧式の AND が pass の1組だけ full/0、残りはfail/2。
const z10NormalTruthTable = [];
for (const manifestHashLabelMatches of [false, true]) {
  for (const blockNumMatches of [false, true]) {
    for (const algorithmMatches of [false, true]) {
      const classified = classifyManifestSelfConsistency({
        coreHash: `0x${'a1'.repeat(32)}`,
        declaredManifestHash: manifestHashLabelMatches
          ? `0x${'a1'.repeat(32)}` : `0x${'b2'.repeat(32)}`,
        expectedBlockNum: 4,
        declaredBlockNum: blockNumMatches ? 4 : 5,
        declaredAlgorithm: algorithmMatches ? 'sha256' : 'sha512',
        emergencyMode: false,
      });
      const oneEntry = { id: 'check.stageC.manifestSelfConsistent', status: classified.status, params: {} };
      const oneReport = {
        list: () => [oneEntry],
        hasFail: () => oneEntry.status === 'fail',
      };
      const ui = { lines: [], println(line) { this.lines.push(String(line)); } };
      const emitted = emitNonInteractiveOutcome(ui, {
        fatal: false, stopped: false, report: oneReport,
      }, null);
      const legacyPass = manifestHashLabelMatches && blockNumMatches && algorithmMatches;
      z10NormalTruthTable.push(
        classified.status === (legacyPass ? 'pass' : 'fail')
        && ui.lines.includes(`##RESULT ${legacyPass ? 'full' : 'fail'}`)
        && emitted.exitCode === (legacyPass ? 0 : 2),
      );
    }
  }
}
const z10NormalBadLabel = await runZ10ManifestCheck({ emergencyMode: false, badLabel: true });
ok('Z10 (d) 通常モードの3脚全8組合せは従来どおりの##RESULT/終了コードを保ち、自称 manifestHash 不一致を検出する',
  z10NormalTruthTable.length === 8
  && z10NormalTruthTable.every(Boolean)
  && z10NormalBadLabel.checks.get('check.stageC.manifestSelfConsistent')?.status === 'fail'
  && (z10NormalBadLabel.ctx.data.emergencyDifferences || []).length === 0);

// ==================================================================
// 🔴 便 Z6 / R29-CEN-05 / R29-A-3b-01（2026-09-22）
//   Evidence のメモリ保存鍵は検証対象の真の N を優先する。
//   公開 manifest の自称 blockNum が N と違う場合と、同じ正常系を別々に書き出す。
// ==================================================================
const z6EvidenceValues = {
  resultCount: 3,
  adoptedCount: 2,
  chatWindowMs: { startMs: 1_000, endMs: 2_000 },
};
async function runZ6EvidenceKeyExport(label, publicBlockNum) {
  const output = path.join(taskTmp, `z6-evidence-${label}`);
  const ctx = v8CleanCtx();
  ctx.data.emergencyRebuild.evidence = {
    ...z6EvidenceValues,
    chatWindowMs: { ...z6EvidenceValues.chatWindowMs },
  };
  await withFixedNow(v8FixedIso, () => writeEmergencyResultSet({
    ctx,
    source: {
      sourceDir: taskTmp,
      selectedManifest: { ...selectedManifest, blockNum: publicBlockNum },
      selected: [],
      index: { sourceRunId: `z6-${label}` },
      fileMap: new Map([
        [stage3Key, '_source/stage3.bin'],
        [infoKey, '_source/info.bin'],
      ]),
    },
    outputDir: output,
  }));
  return JSON.parse(await fs.readFile(path.join(output, v8ManifestKey), 'utf8')).rules.evidence;
}

const z6MismatchedEvidence = await runZ6EvidenceKeyExport('mismatched-block', 999);
ok('Z6 公開manifestのblockNumが検証対象Nと違っても再生成manifestのrules.evidenceは3項目の実値を保つ',
  z6MismatchedEvidence.resultCount === z6EvidenceValues.resultCount
  && z6MismatchedEvidence.adoptedCount === z6EvidenceValues.adoptedCount
  && JSON.stringify(z6MismatchedEvidence.chatWindowMs) === JSON.stringify(z6EvidenceValues.chatWindowMs));

const z6MatchingEvidence = await runZ6EvidenceKeyExport('matching-block', 4);
ok('Z6 公開manifestのblockNumが検証対象Nと同じ正常系でも再生成manifestのrules.evidenceは従来どおり3項目の実値を保つ',
  z6MatchingEvidence.resultCount === z6EvidenceValues.resultCount
  && z6MatchingEvidence.adoptedCount === z6EvidenceValues.adoptedCount
  && JSON.stringify(z6MatchingEvidence.chatWindowMs) === JSON.stringify(z6EvidenceValues.chatWindowMs));

async function runV8PublicVariant(label, publicManifest, publicSummaryBytes = v8SeedSummaryBytes,
  reportOverride = null) {
  const publicBase = `_v8-public/${label}`;
  await fs.mkdir(path.join(taskTmp, publicBase), { recursive: true });
  await fs.writeFile(path.join(taskTmp, publicBase, 'manifest.json'), JSON.stringify(publicManifest));
  await fs.writeFile(path.join(taskTmp, publicBase, 'summary.json'), publicSummaryBytes);
  const output = path.join(taskTmp, `v8-output-${label}`);
  const ctx = v8CleanCtx();
  if (reportOverride) ctx.report = reportOverride;
  const result = await withFixedNow(v8FixedIso, () => writeEmergencyResultSet({
    ctx,
    source: {
      sourceDir: taskTmp,
      selectedManifest: v8SeedManifest,
      selected: [],
      index: { sourceRunId: 'v8-unit' },
      fileMap: new Map([
        [stage3Key, '_source/stage3.bin'],
        [infoKey, '_source/info.bin'],
        [v8ManifestKey, `${publicBase}/manifest.json`],
        [v8SummaryKey, `${publicBase}/summary.json`],
      ]),
    },
    outputDir: output,
  }));
  const publicDifferences = JSON.parse(await fs.readFile(
    path.join(output, '_emergency/public-differences.json'),
  ));
  return { result, publicDifferences, output };
}

const v8Exact = await runV8PublicVariant('exact', v8SeedManifest);
const entryIntegrityFailure = { id: 'check.stageA.entryKeyIntegrity', status: 'fail',
  params: { count: 1, first: 'entries/block4/entries/00_0.json#0: invalid nostrPubkey' } };
const entryIntegrityReport = {
  list: () => [...report.list(), entryIntegrityFailure],
  get: (id) => id === entryIntegrityFailure.id
    ? { status: 'fail', params: entryIntegrityFailure.params } : report.get(id),
};
const v8EntryFailure = await runV8PublicVariant(
  'entry-key-integrity', v8SeedManifest, v8SeedSummaryBytes, entryIntegrityReport,
);
ok('S3C14b 応募鍵の FAIL だけなら実際に書き出し、公開差と結果差の双方に記録',
  v8EntryFailure.result.bundleIndex.complete === true
  && v8EntryFailure.publicDifferences.checkDifferences?.some((difference) =>
    difference.checkId === entryIntegrityFailure.id && difference.params.count === 1)
  && v8EntryFailure.result.differences.some((difference) =>
    difference.checkId === entryIntegrityFailure.id));
const v8ExactUi = { lines: [], println(line) { this.lines.push(String(line)); } };
const v8Outcome = { fatal: false, stopped: false, report: { list: () => [], hasFail: () => false } };
const v8ExactEmitted = emitNonInteractiveOutcome(v8ExactUi, v8Outcome, v8Exact.result);
ok('V8 Y1 改竄も時計ずれも無い公開入力はdifferences 0件・full・exit 0',
  v8Seed.differences.length === 0
  && v8Exact.result.diffs.length === 0
  && v8Exact.result.differences.length === 0
  && v8Exact.publicDifferences.diffs.length === 0
  && v8ExactUi.lines.includes('##EMERGENCY_RESULT full')
  && v8ExactEmitted.category === 'full'
  && v8ExactEmitted.exitCode === 0);
console.log(`V8_Y1_RESULT ${v8ExactUi.lines.find((line) => line.startsWith('##EMERGENCY_RESULT '))} exit=${v8ExactEmitted.exitCode}`);

const v8CreatedAtManifest = { ...v8SeedManifest, createdAt: '2026-09-20T12:34:57.000Z' };
const v8CreatedAt = await runV8PublicVariant('created-at-only', v8CreatedAtManifest);
const v8CreatedAtRecord = v8CreatedAt.publicDifferences.diffs.find(
  (difference) => difference.key === v8ManifestKey,
);
ok('V8 Y2 createdAtだけの差は公開差分とpublic copyに残るが結果差には入らない',
  v8CreatedAtRecord?.coreMatches === true
  && JSON.stringify(v8CreatedAtRecord.differingFields) === JSON.stringify(['createdAt'])
  && v8CreatedAt.result.diffs.length === 0
  && v8CreatedAt.result.differences.length === 0
  && await fs.stat(path.join(v8CreatedAt.output, v8CreatedAtRecord.publicCopy)).then(() => true));
console.log(`V8_Y2_RESULT publicDiffs=${v8CreatedAt.publicDifferences.diffs.length} materialDiffs=${v8CreatedAt.result.differences.length} fields=${v8CreatedAtRecord?.differingFields?.join(',')}`);

// ------------------------------------------------------------------
// 🔴 便 X1 / Q-B（2026-09-21・ユーザー決定 (b')）: core 外の差を見出しへ出す。
//
// `classifyPublicArtifactDifference()` は result manifest について
// `affectsResult = !coreMatches` と判定する。core は {blockNum, algorithm, rules, files} で、
// `files` が全成果物の sha256 を持つので**中身の改竄は必ず core を動かす**。
// ところが **core の外だけ**を書き換えた場合（`createdAt` のほか、攻撃者が足した任意の欄）は
// `affectsResult: false` になり、終了コードが 0（`full`）のままになる。
// 差自体は `_emergency/public-differences.json` へ必ず記録されるが、
// **見出しに出ないので対応者が気づかず、第三者告知の引き金が引かれない**。
//
// 🔴 「どんな差でも4にする」は不可（再計算すれば `createdAt` は必ず変わるので、正常な復旧が
//    毎回4になる。それを止めたのがユーザー決定 U-1）。
// ⇒ `affectsResult` の判定も終了コードの規則も変えず、**見出しに出す**一点だけを直す。
// ------------------------------------------------------------------
const makeMarkerUi = () => ({ lines: [], println(line) { this.lines.push(String(line)); } });
const countLines = (ui, prefix) => ui.lines.filter((line) => line.startsWith(prefix)).length;
// run-release-gate.mjs:856 が既存の印を抜き出す規則そのもの。新しい印がこれに当たらないこと。
const RELEASE_GATE_DIFFERENCE_PATTERN = /^##EMERGENCY_DIFFERENCE\s+(.+)$/gm;

{
  const ui = makeMarkerUi();
  const nonResultCount = emitNonResultMarkers(ui, v8CreatedAt.result);
  emitEmergencyDifferenceMarkers(ui, v8CreatedAt.result);
  const emitted = emitNonInteractiveOutcome(ui, v8Outcome, v8CreatedAt.result);
  const markerLine = ui.lines.find((line) => line.startsWith(`${NON_RESULT_MARKER} `));
  ok('X1 Q-B ① core 外だけの差（createdAt）は見出しへ出るが、終了コードは 0 のまま',
    nonResultCount === 1
      && markerLine === `${NON_RESULT_MARKER} ${JSON.stringify(v8CreatedAtRecord)}`
      && ui.lines.includes('##RESULT full')
      && ui.lines.includes('##EMERGENCY_RESULT full')
      && emitted.category === 'full'
      && emitted.exitCode === 0,
    JSON.stringify({ nonResultCount, markerLine, exitCode: emitted.exitCode }));
  ok('X1 Q-B ① 見出しの印から鍵名・differingFields・公開版と採用版の sha256 が読める',
    typeof markerLine === 'string'
      && markerLine.includes(v8ManifestKey)
      && markerLine.includes('"differingFields":["createdAt"]')
      && markerLine.includes(`"publicSha256":"${v8CreatedAtRecord.publicSha256}"`)
      && markerLine.includes(`"recomputedSha256":"${v8CreatedAtRecord.recomputedSha256}"`)
      && v8CreatedAtRecord.publicSha256 !== v8CreatedAtRecord.recomputedSha256,
    String(markerLine));
  ok('X1 Q-B ① 対応者向けの要約行も1行出る（終了状態が変わらないことを明記する）',
    ui.lines.some((line) => (
      line.startsWith('Emergency non-result differences: 1 ')
        && line.includes(v8ManifestKey)
        && line.includes('_emergency/public-differences.json')
        && line.includes('the exit status is unchanged')
    )),
    JSON.stringify(ui.lines));
  ok('X1 Q-B ① 既存の3つの印の意味と件数は変わっていない（##EMERGENCY_DIFFERENCE は0件）',
    countLines(ui, '##EMERGENCY_DIFFERENCE ') === 0
      && countLines(ui, '##RESULT ') === 1
      && countLines(ui, '##EMERGENCY_RESULT ') === 1,
    JSON.stringify(ui.lines.filter((line) => line.startsWith('##'))));
  ok('X1 Q-B ① 新しい印は既存の印の抽出規則（run-release-gate.mjs）に当たらない',
    [...ui.lines.join('\n').matchAll(RELEASE_GATE_DIFFERENCE_PATTERN)].length === 0,
    JSON.stringify(ui.lines.filter((line) => line.startsWith('##'))));
  console.log(
    `X1_QB_CREATEDAT nonResult=${nonResultCount} exit=${emitted.exitCode} `
    + `result=${ui.lines.find((line) => line.startsWith('##RESULT '))}`,
  );
}

// core の外へ攻撃者が欄を足した形（createdAt ＋ 任意の欄）。core は動かないので終了コードは 0。
{
  const injected = {
    ...v8SeedManifest,
    createdAt: '2026-09-21T00:00:00.000Z',
    operatorNote: 'injected outside manifestCore',
  };
  const measured = await runV8PublicVariant('core-external-injected-field', injected);
  const record = measured.publicDifferences.diffs.find((d) => d.key === v8ManifestKey);
  const ui = makeMarkerUi();
  const nonResultCount = emitNonResultMarkers(ui, measured.result);
  emitEmergencyDifferenceMarkers(ui, measured.result);
  const emitted = emitNonInteractiveOutcome(ui, v8Outcome, measured.result);
  const markerLine = ui.lines.find((line) => line.startsWith(`${NON_RESULT_MARKER} `));
  ok('X1 Q-B ② 攻撃者が core の外へ足した欄も見出しへ出て、終了コードは 0 のまま',
    record?.coreMatches === true
      && JSON.stringify([...record.differingFields].sort())
        === JSON.stringify(['createdAt', 'operatorNote'])
      && measured.result.differences.length === 0
      && nonResultCount === 1
      && typeof markerLine === 'string'
      && markerLine.includes('operatorNote')
      && markerLine.includes('createdAt')
      && emitted.category === 'full'
      && emitted.exitCode === 0,
    JSON.stringify({ record, markerLine, exitCode: emitted.exitCode }));
  console.log(
    `X1_QB_INJECTED fields=${record?.differingFields?.join(',')} `
    + `nonResult=${nonResultCount} exit=${emitted.exitCode}`,
  );
}

// 緊急モードでないとき（emergencyWritten が無いとき）は1行も出さない。
{
  const ui = makeMarkerUi();
  ok('X1 Q-B ③ 通常検証（緊急固定一式を書かない）では新しい印を1行も出さない',
    emitNonResultMarkers(ui, null) === 0
      && emitNonResultMarkers(ui, { differences: [] }) === 0
      && emitNonResultMarkers(ui, { differences: [], nonResultDifferences: [] }) === 0
      && ui.lines.length === 0,
    JSON.stringify(ui.lines));
}

const v8CoreVariants = new Map([
  ['blockNum', { ...v8SeedManifest, blockNum: v8SeedManifest.blockNum + 1 }],
  ['algorithm', { ...v8SeedManifest, algorithm: 'sha256-v8-mutated' }],
  ['rules', { ...v8SeedManifest, rules: { ...v8SeedManifest.rules, v8Mutation: true } }],
  ['files', {
    ...v8SeedManifest,
    files: { ...v8SeedManifest.files, [stage3Key]: '0'.repeat(64) },
  }],
]);
for (const [field, variant] of v8CoreVariants) {
  const measured = await runV8PublicVariant(`core-${field}`, variant);
  const record = measured.publicDifferences.diffs.find((difference) => difference.key === v8ManifestKey);
  const ui = { lines: [], println(line) { this.lines.push(String(line)); } };
  const emitted = emitNonInteractiveOutcome(ui, v8Outcome, measured.result);
  ok(`V8 Y3 manifestCore.${field}の1変異はwith_differences・exit 4`,
    record?.coreMatches === false
    && record?.differingFields?.some((pathName) => (
      pathName === field || pathName.startsWith(`${field}.`)
    ))
    && measured.result.diffs.length === 1
    && measured.result.differences.some((difference) => (
      difference.checkId === 'emergency.publicArtifactBytes'
      && difference.what.endsWith(v8ManifestKey)
    ))
    && ui.lines.includes('##EMERGENCY_RESULT with_differences')
    && emitted.category === 'emergency_with_differences'
    && emitted.exitCode === 4);
  // 便 X1 / Q-B ④: core が違う差は従来どおり ##EMERGENCY_DIFFERENCE と終了コード4 のまま。
  // 新しい印は1行も出ない（結果に影響する差なので「結果に影響しない差」ではない）。
  const markerUi = makeMarkerUi();
  const nonResultCount = emitNonResultMarkers(markerUi, measured.result);
  emitEmergencyDifferenceMarkers(markerUi, measured.result);
  const markerEmitted = emitNonInteractiveOutcome(markerUi, v8Outcome, measured.result);
  ok(`X1 Q-B ④ manifestCore.${field}の差は従来どおり##EMERGENCY_DIFFERENCE・exit 4（新しい印は0件）`,
    nonResultCount === 0
      && countLines(markerUi, `${NON_RESULT_MARKER} `) === 0
      && countLines(markerUi, '##EMERGENCY_DIFFERENCE ') === 1
      && countLines(markerUi, '##RESULT ') === 1
      && countLines(markerUi, '##EMERGENCY_RESULT ') === 1
      && markerUi.lines.includes('##RESULT emergency_with_differences')
      && markerEmitted.exitCode === 4,
    JSON.stringify(markerUi.lines.filter((line) => line.startsWith('##'))));
  console.log(`V8_Y3_RESULT field=${field} ${ui.lines.find((line) => line.startsWith('##EMERGENCY_RESULT '))} exit=${emitted.exitCode}`);
}

const v8SummaryDifference = await runV8PublicVariant(
  'summary-byte-difference',
  v8SeedManifest,
  Buffer.concat([v8SeedSummaryBytes, Buffer.from('\n')]),
);
const v8SummaryRecord = v8SummaryDifference.publicDifferences.diffs.find(
  (difference) => difference.key === v8SummaryKey,
);
const v8SummaryUi = { lines: [], println(line) { this.lines.push(String(line)); } };
const v8SummaryEmitted = emitNonInteractiveOutcome(v8SummaryUi, v8Outcome, v8SummaryDifference.result);
const v8OtherKeys = [
  v8SummaryKey,
  '_emergency/claim-data-plan.json',
  'verification/block4/stage3/group-0.json',
  'games/block4/group0.json',
];
const v8OtherKeyClassifications = v8OtherKeys.map((key) => classifyPublicArtifactDifference({
  key,
  manifestKey: v8ManifestKey,
  recomputedBytes: Buffer.from('a'),
  publicBytes: Buffer.from('b'),
  publicCopy: `_emergency/public/${key}`,
}));
ok('V8 Y4 manifest以外のsummary/claim data/witness/group pageは全て従来どおり結果差',
  v8SummaryRecord?.key === v8SummaryKey
  && !Object.hasOwn(v8SummaryRecord, 'coreMatches')
  && v8SummaryDifference.result.diffs.length === 1
  && v8SummaryDifference.result.differences.some((difference) => difference.what.endsWith(v8SummaryKey))
  && v8OtherKeyClassifications.every((comparison) => comparison.affectsResult === true)
  && v8SummaryUi.lines.includes('##EMERGENCY_RESULT with_differences')
  && v8SummaryEmitted.exitCode === 4);
console.log(`V8_Y4_RESULT key=${v8SummaryKey} ${v8SummaryUi.lines.find((line) => line.startsWith('##EMERGENCY_RESULT '))} exit=${v8SummaryEmitted.exitCode}`);

ok('V8 Y7 緊急固定一式のmanifestHashは同じ入力を平時writerが焼くmanifestCoreHashと一致',
  v8SeedManifest.rules.evidence.resultCount === 0
  && v8SeedManifest.rules.evidence.adoptedCount === null
  && v8SeedManifest.manifestHash === manifestCoreHash(v8SeedManifest)
  && v8Seed.bundleIndex.resultManifestCoreSha256 === v8SeedManifest.manifestHash);
console.log(`V8_Y7_RESULT adoptedCount=${v8SeedManifest.rules.evidence.adoptedCount} manifestHash=${v8SeedManifest.manifestHash}`);

await fs.writeFile(path.join(outputDir, 'undeclared.json'), '{}');
const fixedR2 = createLocalR2({ artifactDir: outputDir }, {}, 4, { rootDir: outputDir });
await rejects('U6b bundle index一覧外のローカルファイルも固定一式として読まない',
  () => fixedR2.fetchJson('undeclared.json'), /not declared in bundle index/);

const timelineFinality = {
  schemaVersion: 1,
  evidenceContract: `0x${'12'.repeat(20)}`,
  safeBlockNumber: '100', safeTimestamp: 500,
  resultOpenAt: 200, resultCloseAt: 300, resultCount: 0,
};
const timelineSummary = {
  schemaVersion: 3, blockNum: 4, blockReward: getBlockRewardWei(4).toString(),
  totalPlayers: 3, totalGroups: 0, noGame: true, majorLangs: [], groups: [],
  claimStatusKey: 'games/block4/claim-status.json', claimLayout: 'group-overlays-v1',
  noGameReason: 'timeline_unverified', noGameCause: 'chain_unreadable',
  noGameFinality: timelineFinality,
};
const timelineOutputDir = path.join(taskTmp, 'timeline-export');
let timelineWriterCalls = 0;
let timelineWriterMeta = null;
GameMasterDO.prototype.finalizeNoGameBlock = async function (...args) {
  timelineWriterCalls++;
  timelineWriterMeta = args[1];
  return originalFinalizeNoGameBlock.apply(this, args);
};
let timelineWritten;
try {
  timelineWritten = await writeEmergencyResultSet({
    ctx: {
      blockNum: 4, report: specialReport, cfg: DEFAULTS,
      data: {
        gameSelection: wr3NoGameSelection,
        emergencyRebuild: {
          kind: 'timelineNoGame', rebuiltSummary: timelineSummary, allGroupResults: [],
          evidence: {
            resultCount: 0,
            adoptedCount: emergencyAdoptedCountOf(0, {}),
            chatWindowMs: null,
          },
          noGameMeta: {
            reason: 'timeline_unverified', cause: 'chain_unreadable', totalPlayers: 3,
            chainFinality: {
              ...timelineFinality,
              chatOpenAt: 100, chatCloseAt: 190, confirmations: 64,
            },
          },
          factsMerkle: { root: '0x1f06c2896619bc4054f4f3de8dcee35acde9cacc632ef5184140e3e329c59383' },
        },
        emergencyGroupArchives: new Map(), emergencyServerSubmissions: {},
        emergencySubmissionCandidates: [],
      },
    },
    source: {
      sourceDir: taskTmp, selectedManifest, selected: [], index: { sourceRunId: 'unit-run' },
      fileMap: new Map([
        [stage3Key, '_source/stage3.bin'], [infoKey, '_source/info.bin'],
        [obsoleteKey, '_source/obsolete.bin'],
      ]),
    },
    outputDir: timelineOutputDir,
  });
} finally {
  GameMasterDO.prototype.finalizeNoGameBlock = originalFinalizeNoGameBlock;
}
const timelineProvenance = JSON.parse(await fs.readFile(
  path.join(timelineOutputDir, '_emergency/writer-provenance.json'),
));
const timelineWrittenSummary = JSON.parse(await fs.readFile(
  path.join(timelineOutputDir, 'games/block4/summary.json'),
));
ok('U6c timeline no-gameも平時GM writerでsummary/evidence/空Merkle/manifestを書き出す',
  timelineWriterCalls === 1
  && timelineWriterMeta?.offlineMaterialize === true
  && timelineWritten.bundleIndex.resultKind === 'timelineNoGame'
  && timelineProvenance.vendoredCanonicalCalls.includes('GameMasterDO.finalizeNoGameBlock')
  && !Object.hasOwn(timelineWrittenSummary, 'noGameCleanup')
  && await fs.stat(path.join(timelineOutputDir, 'verification/block4/evidence-report.json')).then(() => true));

// WR-PRICE-1-FIX1: each empty writer recovers the historical pin from a saved
// observer generation, even though the memory GM has no public R2 artifact.
const pricePinKey = 'games/block4/zkp/evidence-segments.json';
const historicalEmptyBytes = JSON.stringify(evidenceSegmentArtifact([], 'pre-g7-placeholder-1'));
const historicalEmptyRow = await save('_observer/generations/price-old-empty.json', historicalEmptyBytes);
const pricePinSource = (row = historicalEmptyRow) => ({
  authority: 'gcp', sourceDir: taskTmp, selectedManifest, selected: [],
  index: { sourceRunId: 'price-pin-unit', objects: { [pricePinKey]: [row] } },
  fileMap: new Map([[stage3Key, '_source/stage3.bin'], [infoKey, '_source/info.bin']]),
});
const pricePinTimelineCtx = () => ({
  blockNum: 4, report: specialReport, cfg: DEFAULTS,
  data: {
    gameSelection: wr3NoGameSelection,
    emergencyRebuild: {
      kind: 'timelineNoGame', rebuiltSummary: timelineSummary, allGroupResults: [],
      evidence: { resultCount: 0, adoptedCount: null, chatWindowMs: null },
      noGameMeta: { reason: 'timeline_unverified', cause: 'chain_unreadable', totalPlayers: 3,
        chainFinality: { ...timelineFinality, chatOpenAt: 100, chatCloseAt: 190, confirmations: 64 } },
      factsMerkle: { root: '0x1f06c2896619bc4054f4f3de8dcee35acde9cacc632ef5184140e3e329c59383' },
    },
    emergencyGroupArchives: new Map(), emergencyServerSubmissions: {},
    emergencySubmissionCandidates: [],
  },
});
const pricePinAutoCtx = () => {
  const ctx = v8CleanCtx();
  ctx.report = {
    list: () => [...report.list(), { id: 'check.stageC.autoDistribute', status: 'pass', params: {} }],
    get: (id) => id === 'check.stageC.autoDistribute'
      ? { status: 'pass', params: {} } : report.get(id),
  };
  ctx.data.gameSelection = { ...wr3NoGameSelection, players: [m2AutoPlayers[0]] };
  ctx.data.emergencyRebuild = {
    kind: 'autoDistribute',
    rebuiltSummary: { schemaVersion: 1, blockNum: 4, blockReward: getBlockRewardWei(4).toString(),
      totalPlayers: 1, totalGroups: 0, autoDistributed: true, majorLangs: [], groups: [],
      claimStatusKey: 'games/block4/claim-status.json', claimLayout: 'group-overlays-v1' },
    allGroupResults: [], depositorResults: [],
    evidence: { resultCount: 0, adoptedCount: null, chatWindowMs: null },
  };
  return ctx;
};
for (const [kind, makeCtx] of [
  ['noGame', v8CleanCtx], ['timelineNoGame', pricePinTimelineCtx],
  ['autoDistribute', pricePinAutoCtx],
]) {
  const outputDir = path.join(taskTmp, `price-pin-${kind}`);
  const result = await withFixedNow(v8FixedIso, () => writeEmergencyResultSet({
    ctx: makeCtx(), source: pricePinSource(), outputDir,
  }));
  const rebuiltBytes = await fs.readFile(path.join(outputDir, pricePinKey), 'utf8');
  ok(`WR-PRICE-1-FIX1 ${kind}: 保存した旧版の空artifactをバイト一致で再現`,
    result.bundleIndex.complete === true && rebuiltBytes === historicalEmptyBytes);
}
ok('WR-PRICE-1-FIX1: 保存artifactが無ければ従来の現行版を使う',
  (await fs.readFile(path.join(m3RightMarkerDir, pricePinKey), 'utf8'))
    === JSON.stringify(evidenceSegmentArtifact([])));
const unusableEmptyRow = await save('_observer/generations/price-unknown-empty.json',
  JSON.stringify({ ...JSON.parse(historicalEmptyBytes), pinVersion: 'future-unknown' }));
const missingPinRow = await save('_observer/generations/price-missing-pin.json', '{}');
const numericPinRow = await save('_observer/generations/price-numeric-pin.json',
  JSON.stringify({ pinVersion: 7 }));
const pricePinFallbackRun = async (kind, makeCtx, row, label) => {
  const facts = [];
  const ctx = makeCtx();
  ctx.report = { ...ctx.report, fact: (name, value) => facts.push({ name, value }) };
  const source = pricePinSource(Array.isArray(row) ? row[0] : row ?? historicalEmptyRow);
  if (Array.isArray(row)) source.index.objects[pricePinKey] = row;
  if (row === null) source.index.objects[pricePinKey] = [];
  const outputDir = path.join(taskTmp, `price-pin-fallback-${kind}-${label}`);
  const result = await withFixedNow(v8FixedIso, () => writeEmergencyResultSet({
    ctx, source, outputDir,
  }));
  const bytes = await fs.readFile(path.join(outputDir, pricePinKey), 'utf8');
  const fact = facts.find((item) => item.name === 'emergencyEvidenceSegmentPinFallback')?.value;
  return { result, bytes, fact, source };
};
for (const [kind, makeCtx] of [
  ['noGame', v8CleanCtx], ['timelineNoGame', pricePinTimelineCtx],
  ['autoDistribute', pricePinAutoCtx],
]) {
  for (const [label, row, savedVersion] of [
    ['unknown', unusableEmptyRow, 'future-unknown'],
    ['missing', missingPinRow, null],
    ['numeric', numericPinRow, 7],
  ]) {
    const run = await pricePinFallbackRun(kind, makeCtx, row, label);
    ok(`WR-PRICE-1-FIX3 ${kind}: ${label} の保存版を記録して現行版で書き出す`,
      run.result.bundleIndex.complete === true
      && run.bytes === JSON.stringify(evidenceSegmentArtifact([]))
      && run.fact?.reason === 'saved artifact pinVersion is unusable; current price version used'
      && run.fact?.pinVersion === 'g7-1'
      && run.fact?.savedPinVersion === savedVersion
      && run.fact?.savedSha256 === row.sha256
      && Array.isArray(run.fact?.evaluations)
      && run.source.differences?.some((difference) => (
        difference.checkId === 'emergency.evidenceSegmentPinFallback'
        && difference.chain.pinVersion === savedVersion
        && difference.chain.sha256 === row.sha256
      )));
  }
}
const pricePinNoGeneration = await pricePinFallbackRun('noGame', v8CleanCtx, null, 'none');
ok('WR-PRICE-1-FIX3: 保存世代なしの空枝も通常枝と同じ評価記録を出す',
  pricePinNoGeneration.fact?.reason === 'saved artifact generation unavailable; current price version used'
  && Array.isArray(pricePinNoGeneration.fact?.evaluations)
  && pricePinNoGeneration.fact.evaluations.length === 0
  && !Object.hasOwn(pricePinNoGeneration.fact, 'savedSha256'));
const unreadablePinRow = await save('_observer/generations/price-unreadable-pin.json', '{');
const pricePinLaterGeneration = await pricePinFallbackRun(
  'noGame', v8CleanCtx, [unreadablePinRow, unusableEmptyRow], 'later-unknown');
ok('WR-PRICE-1-FIX3: 壊れたJSONを飛ばして後の版を採った評価もfactに残す',
  pricePinLaterGeneration.fact?.savedSha256 === unusableEmptyRow.sha256
  && pricePinLaterGeneration.fact?.evaluations?.length === 1
  && pricePinLaterGeneration.fact.evaluations[0].sha256 === unreadablePinRow.sha256
  && pricePinLaterGeneration.fact.evaluations[0].reason === 'unreadable saved generation');

// 特殊ブロックの書き手を緊急側の写経へ戻す退行を検出する mutation tooth。
// vendored writer を故障注入しても出力できる実装なら、この試験は赤になる。
GameMasterDO.prototype.finalizeNoGameBlock = async function () {
  throw new Error('Q30_CANONICAL_SPECIAL_WRITER_CALLED');
};
try {
  await rejects('U6d mutation: 特殊ブロックで平時GM writerを通らない実装を拒否する',
    () => writeEmergencyResultSet({
      ctx: {
        blockNum: 4, report, cfg: DEFAULTS,
        data: {
          emergencyRebuild: {
            kind: 'noGame', rebuiltSummary: noGameSummary, allGroupResults: [],
            evidence: { resultCount: null, adoptedCount: null, chatWindowMs: null },
            noGameMeta: { reason: 'zero_entries' },
          },
          emergencyGroupArchives: new Map(), emergencyServerSubmissions: {},
          emergencySubmissionCandidates: [],
        },
      },
      source: {
        sourceDir: taskTmp, selectedManifest, selected: [], index: { sourceRunId: 'unit-run' },
        fileMap: new Map([
          [stage3Key, '_source/stage3.bin'], [infoKey, '_source/info.bin'],
          [obsoleteKey, '_source/obsolete.bin'],
        ]),
      },
      outputDir: path.join(taskTmp, 'mutation-special-writer-bypass'),
    }),
    /Q30_CANONICAL_SPECIAL_WRITER_CALLED/);
} finally {
  GameMasterDO.prototype.finalizeNoGameBlock = originalFinalizeNoGameBlock;
}

// ==================================================================
// 🔴 W1 / R28-H3-4-02 e2e（群ゲーム）:
//   公開 witness が並び順だけ崩されていても輸出は完走し、固定一式の witness と
//   Stage 3 入力 manifest は**再計算版**になる。順4（scripts/zkp-prover/run-stage3-gcp.sh の
//   「${filename}のSHA-256が一致しません」枝）は manifest の宣言 sha256 と witness の実バイトを厳格照合するので、
//   その一致を「書き出した実ファイル」で測る。
// ==================================================================
const w1PublicWitnessBytes = orderOnlyWitnessBytes;
const w1PublicStage3Manifest = Buffer.from(JSON.stringify({
  schemaVersion: 1, kind: 'bitcoinu-stage3-input-manifest', blockNum: 4,
  groupCount: 1,
  groups: [{ groupId: 0, object: stage3WitnessKey, sha256: digest(w1PublicWitnessBytes) }],
}));
await fs.writeFile(path.join(taskTmp, '_source/w1-stage3-manifest.bin'), w1PublicStage3Manifest);
await fs.writeFile(path.join(taskTmp, '_source/w1-stage3-group0.bin'), w1PublicWitnessBytes);
const w1RosterManifestKey = 'games/block4/roster/manifest.json';
const w1RosterIndexKey = 'games/block4/roster/index.json';
const w1RosterGroup0Key = 'games/block4/roster/group0.json';
const w1GroupsDerived = [{ groupId: 0, members: [witnessMember, witnessMemberB]
  .map((data, globalIndex) => ({ globalIndex, data })) }];
const w1GameSelection = { ...wr3NoGameSelection,
  players: w1GroupsDerived[0].members };
const w1RosterIndexBytes = Buffer.from(JSON.stringify({ 10: 0, 11: 0 }));
const w1RosterGroup0Bytes = Buffer.from(reconstructCanonicalRosterPayloads(4, w1GroupsDerived)
  .groupTexts.get(0));
const w1RosterManifestBytes = Buffer.from(JSON.stringify({
  blockNum: 4,
  indexSha256: digest(w1RosterIndexBytes),
  groups: [{ groupId: 0, sha256: digest(w1RosterGroup0Bytes) }],
}));
const w1RosterIndexRow = {
  ...await save('_observer/generations/w1-roster-index.bin', w1RosterIndexBytes),
  generation: 1, observationOrdinal: '00009000:00000000',
};
const w1RosterGroup0Row = {
  ...await save('_observer/generations/w1-roster-group0.bin', w1RosterGroup0Bytes),
  generation: 1, observationOrdinal: '00009001:00000000',
};
const w1RosterManifestRow = {
  ...await save('_observer/generations/w1-roster-manifest.bin', w1RosterManifestBytes),
  generation: 1, observationOrdinal: '00009002:00000000',
};
const w1EvidenceSegmentKey = 'games/block4/zkp/evidence-segments.json';
const w1EvidenceSegmentBytes = Buffer.from(JSON.stringify(evidenceSegmentArtifact([
  { seq: 1, rawBytes: 100 }, { seq: 2, rawBytes: 100 },
])));
await fs.writeFile(path.join(taskTmp, '_source/w1-evidence-segments.bin'), w1EvidenceSegmentBytes);
const w1RosterSource = ({ files, witnessKeys = [], fileMap = [], objects = {} }) => ({
  sourceDir: taskTmp,
  selected: [],
  index: {
    sourceRunId: 'unit-run',
    objects: {
      [w1RosterIndexKey]: [w1RosterIndexRow],
      [w1RosterGroup0Key]: [w1RosterGroup0Row],
      ...objects,
    },
  },
  selectedManifest: { ...selectedManifest, files: {
    ...files, [w1EvidenceSegmentKey]: digest(w1EvidenceSegmentBytes),
  } },
  witnessKeys,
  fileMap: new Map([
    [w1RosterManifestKey, w1RosterManifestRow.savedFile],
    [w1EvidenceSegmentKey, '_source/w1-evidence-segments.bin'],
    ...fileMap,
  ]),
});
const w1Summary = {
  schemaVersion: 3, blockNum: 4, blockReward: getBlockRewardWei(4).toString(),
  totalPlayers: 2, totalGroups: 1, majorLangs: [],
  claimStatusKey: 'games/block4/claim-status.json', claimLayout: 'group-overlays-v1',
  groups: [{
    group_id: 0, status: 'completed', lang: 'ja', mixed: false, total_points: 0,
    members: [
      { userId: '10', address: witnessMember.addr, total_points: 0, btcu_reward: '0', is_disqualified: true },
      { userId: '11', address: witnessMemberB.addr, total_points: 0, btcu_reward: '0', is_disqualified: true },
    ],
  }],
};
const w1OutputDir = path.join(taskTmp, 'w1-groupgame-export');
const w1RpcPrivacyUrl = 'https://rpc.example.test/v2/FAKE-S2F-DIAGNOSTIC-KEY';
const w1RpcDiagnosticRow = { checkId: 's2f.rpcPrivacy', reason: `fake RPC failure: ${w1RpcPrivacyUrl}; Docs: https://viem.sh/docs/contract/readContract; R2: https://r2.bitcoinu.org/games/block4/summary.json` };
let w1WriteError = null;
const w1WriteOptions = {
  ctx: {
    blockNum: 4, report, cfg: { ...DEFAULTS, rpcUrls: [w1RpcPrivacyUrl] },
    data: {
      emergencyDifferences: [w1RpcDiagnosticRow],
      emergencyRebuild: {
        kind: 'groupGame',
        rebuiltSummary: w1Summary,
        allGroupResults: [],
        depositorResults: [],
        d1Groups: [witnessPairRow],
        verifiedDepositWei: witnessPairDeposits,
        chatWindowMs: null,
        factsMerkle: null,
        evidence: { resultCount: 2, adoptedCount: 2, chatWindowMs: null },
      },
      emergencyGroupArchives: new Map([[0, witnessGroupData]]),
      emergencyServerSubmissions: {},
      emergencySubmissionCandidates: [],
      groupsDerived: w1GroupsDerived,
      gameSelection: w1GameSelection,
    },
  },
  source: w1RosterSource({
    files: { [stage3Key]: digest(w1PublicStage3Manifest) },
    witnessKeys: [stage3WitnessKey],
    fileMap: [
      [stage3Key, '_source/w1-stage3-manifest.bin'],
      [stage3WitnessKey, '_source/w1-stage3-group0.bin'],
    ],
  }),
  outputDir: w1OutputDir,
};
const w1Written = await (async () => { try { return await writeEmergencyResultSet(w1WriteOptions);
} catch (error) { w1WriteError = error; return null; } })();
const readIfWritten = async (relative) => (
  w1Written ? fs.readFile(path.join(w1OutputDir, relative)).catch(() => Buffer.alloc(0)) : Buffer.alloc(0)
);
const w1RpcDiagnostic = (await readIfWritten('_emergency/differences.json')).toString('utf8');
ok('S2F-TOOLS RPC の鍵を緊急結果の診断JSONと返却する差分に残さない',
  w1RpcDiagnostic.includes('https://rpc.example.test/…')
  && !w1RpcDiagnostic.includes('FAKE-S2F-DIAGNOSTIC-KEY')
  && !JSON.stringify(w1Written?.differences).includes('FAKE-S2F-DIAGNOSTIC-KEY'));
ok('FIX1A 診断でも Docs/R2 の path を保持し、内部の差分を変更しない',
  w1RpcDiagnostic.includes('https://viem.sh/docs/contract/readContract')
  && w1RpcDiagnostic.includes('https://r2.bitcoinu.org/games/block4/summary.json')
  && w1RpcDiagnosticRow.reason.includes(w1RpcPrivacyUrl));
// RF-03: 4つの実ファイルの各経路に鍵つき文字列を入れ、書いた後にparseする。
// writerの呼出名は通常は固定文だけなので、収集する配列に偽の診断を注入して出口を試す。
const rf3Dir = path.join(taskTmp, 'rf3-diagnostic-boundaries');
const rf3KeyUrl = 'https://rpc.example.test/structural-key';
const rf3Params = { error: w1RpcPrivacyUrl, nested: JSON.stringify({ error: w1RpcPrivacyUrl }),
  [rf3KeyUrl]: 'registered key redacted after serialization', count: 1, enabled: false };
const rf3Options = {
  ...w1WriteOptions, outputDir: rf3Dir,
  ctx: { ...w1WriteOptions.ctx,
    cfg: { ...DEFAULTS, rpcUrls: [w1RpcPrivacyUrl, rf3KeyUrl] },
    report: { ...report, list: () => [...report.list(),
      { id: 'check.stageC.rulesPins', status: 'fail', params: rf3Params }] },
    data: { ...w1WriteOptions.ctx.data,
      emergencyServerSubmissions: { 10: { reason: w1RpcPrivacyUrl } },
      emergencySubmissionCandidates: [{ reason: w1RpcPrivacyUrl }],
    },
  },
};
const rf3Push = Array.prototype.push;
let rf3Written;
try {
  Array.prototype.push = function (...values) {
    if (values.includes('GameMasterDO.publishMerkleTree')) rf3Push.call(values, w1RpcPrivacyUrl);
    return rf3Push.apply(this, values);
  };
  rf3Written = await writeEmergencyResultSet(rf3Options);
} finally { Array.prototype.push = rf3Push; }
for (const file of ['public-differences', 'submission-selection', 'writer-provenance', 'differences']) {
  const bytes = await fs.readFile(path.join(rf3Dir, `_emergency/${file}.json`), 'utf8');
  const parsed = JSON.parse(bytes);
  ok(`RF-03 ${file} の文字列値を伏せ、書いたJSONをparseできる`,
    bytes.includes('https://rpc.example.test/…') && !bytes.includes('FAKE-S2F-DIAGNOSTIC-KEY')
      && parsed.schemaVersion === 1 && parsed.blockNum === 4);
  if (file === 'public-differences') {
    const params = parsed.checkDifferences.find((row) => row.params?.['https://rpc.example.test/…'])?.params || {};
    ok('FIX1C 診断JSONの登録URLの鍵も伏せ、数値・真偽値を保持する',
      params['https://rpc.example.test/…'] === 'registered key redacted after serialization' && params.count === 1 && params.enabled === false
      && JSON.parse(params.nested).error === 'https://rpc.example.test/…');
  }
}
ok('RF-03 診断の内部入力を変更しない', rf3Params.error === w1RpcPrivacyUrl
  && rf3Options.ctx.data.emergencySubmissionCandidates[0].reason === w1RpcPrivacyUrl
  && !JSON.stringify(rf3Written.differences).includes('FAKE-S2F-DIAGNOSTIC-KEY'));
// RB-03: 公開manifestの rules.protocol が深い配列でも、HEADと同じ書き手で診断を出す。
// Stage Cが残す許容checkの値をそのまま渡し、秘密の有無の両方を通す。
for (const depth of [3000, 4000, 6000]) for (const secret of [false, true]) {
  const protocol = JSON.parse('['.repeat(depth) + ']'.repeat(depth));
  const params = { protocol, blockRewardWei: '1', expected: '2', ...(secret ? { error: w1RpcPrivacyUrl } : {}) };
  const deepDir = path.join(taskTmp, `rb03-deep-${depth}-${secret}`);
  let saved, error;
  try {
    saved = await writeEmergencyResultSet({
      ...w1WriteOptions, outputDir: deepDir,
      ctx: { ...w1WriteOptions.ctx,
        cfg: { ...DEFAULTS, rpcUrls: secret ? [w1RpcPrivacyUrl] : [], rpcPresets: [], customRpcs: [] },
        report: { ...report, list: () => [...report.list(), { id: 'check.stageC.rulesReward', status: 'fail', params }] },
        data: { ...w1WriteOptions.ctx.data, emergencyDifferences: [] },
      },
    });
  } catch (caught) { error = caught; }
  ok(`RB-03 深さ${depth} secret=${secret} の緊急診断を書きexit 4に分類する`,
    !error && saved?.bundleIndex.complete === true
      && EXIT_CODE_OF[categorizeEmergencyWrite(saved)] === 4);
  if (saved) {
    const bytes = await fs.readFile(path.join(deepDir, '_emergency/public-differences.json'), 'utf8');
    const parsed = JSON.parse(bytes);
    const row = parsed.checkDifferences.find((row) => row.checkId === 'check.stageC.rulesReward' || row.id === 'check.stageC.rulesReward');
    ok(`RB-03 深さ${depth} secret=${secret} のJSONがparseでき、入力は参照のまま`,
      Array.isArray(row?.params?.protocol) && params.protocol === protocol
        && (!secret || !bytes.includes('FAKE-S2F-DIAGNOSTIC-KEY')));
  }
}
const w1WrittenWitness = await readIfWritten(stage3WitnessKey);
const w1WrittenStage3Bytes = await readIfWritten(stage3Key);
const w1WrittenStage3 = w1Written ? JSON.parse(w1WrittenStage3Bytes.toString('utf8')) : {};
const w1ResultManifest = w1Written
  ? JSON.parse((await readIfWritten('verification/block4/manifest.json')).toString('utf8'))
  : { files: {} };
const w1WrittenEvidenceSegment = await readIfWritten(w1EvidenceSegmentKey);
ok('WR-5 W1 保存世代の Evidence 区間 artifact を固定一式と K6 files に載せる',
  w1WrittenEvidenceSegment.equals(w1EvidenceSegmentBytes)
  && w1ResultManifest.files[w1EvidenceSegmentKey] === digest(w1EvidenceSegmentBytes));
const w1PinFacts = [];
const w1PinSource = w1RosterSource({
  files: { [stage3Key]: digest(w1PublicStage3Manifest) },
  witnessKeys: [stage3WitnessKey],
  fileMap: [
    [stage3Key, '_source/w1-stage3-manifest.bin'],
    [stage3WitnessKey, '_source/w1-stage3-group0.bin'],
  ],
  objects: { [w1EvidenceSegmentKey]: [unusableEmptyRow] },
});
w1PinSource.authority = 'gcp';
const w1PinOutputDir = path.join(taskTmp, 'w1-price-pin-fallback');
const w1PinWritten = await writeEmergencyResultSet({
  ctx: {
    blockNum: 4,
    report: { ...report, fact: (name, value) => w1PinFacts.push({ name, value }) },
    cfg: DEFAULTS,
    data: {
      emergencyRebuild: {
        kind: 'groupGame', rebuiltSummary: w1Summary, allGroupResults: [],
        depositorResults: [], d1Groups: [witnessPairRow],
        verifiedDepositWei: witnessPairDeposits, chatWindowMs: null, factsMerkle: null,
        evidence: { resultCount: 2, adoptedCount: 2, chatWindowMs: null },
      },
      emergencyGroupArchives: new Map([[0, witnessGroupData]]),
      emergencyServerSubmissions: {}, emergencySubmissionCandidates: [],
      emergencyEvidenceSegmentFrames: [{ seq: 1, rawBytes: 100 }, { seq: 2, rawBytes: 100 }],
      groupsDerived: w1GroupsDerived, gameSelection: w1GameSelection,
    },
  },
  source: w1PinSource,
  outputDir: w1PinOutputDir,
});
const w1PinFact = w1PinFacts.find((item) =>
  item.name === 'emergencyEvidenceSegmentPinFallback')?.value;
const emptyPinFact = (await pricePinFallbackRun('noGame', v8CleanCtx,
  unusableEmptyRow, 'same-as-normal')).fact;
ok('WR-PRICE-1-FIX3: 通常ゲームと空枝は同じ保存入力から同じfallback factを出す',
  w1PinWritten.bundleIndex.complete === true
  && isDeepStrictEqual(w1PinFact, emptyPinFact)
  && w1PinSource.differences?.some((difference) => (
    difference.checkId === 'emergency.evidenceSegmentPinFallback'
    && difference.chain.sha256 === unusableEmptyRow.sha256
  )));
ok('W1 e2e 公開witnessが崩れていても輸出は完走し、固定一式のwitnessは再計算版になる',
  w1Written?.bundleIndex.complete === true
  && w1WrittenWitness.equals(stage3PairBytes)
  && w1WrittenWitness.equals(w1PublicWitnessBytes) === false,
  String(w1WriteError?.message || ''));
ok('W1 e2e 固定一式のStage 3 manifestのsha256は、採用したwitnessの実バイトと一致する',
  w1WrittenStage3.kind === 'bitcoinu-stage3-input-manifest'
  && w1WrittenStage3.groupCount === 1
  && w1WrittenStage3.groups[0].groupId === 0
  && w1WrittenStage3.groups[0].object === stage3WitnessKey
  && w1WrittenStage3.groups[0].sha256 === digest(w1WrittenWitness)
  && w1ResultManifest.files[stage3Key] === digest(w1WrittenStage3Bytes),
  JSON.stringify(w1WrittenStage3.groups));
const w1DifferenceLines = [];
emitEmergencyDifferenceMarkers({ println: (line) => w1DifferenceLines.push(line) }, w1Written);
const w1RecomputedMarker = w1DifferenceLines.find((line) => (
  line.startsWith('##EMERGENCY_DIFFERENCE ') && line.includes('emergency.stage3WitnessRecomputed')
));
ok('W1 e2e 差は##EMERGENCY_DIFFERENCEに「並び順だけ」として出て、終了状態は差分あり',
  Boolean(w1RecomputedMarker)
  && /"difference":"orderOnly"/.test(w1RecomputedMarker)
  && categorizeEmergencyWrite(w1Written, null) === 'emergency_with_differences'
  && EXIT_CODE_OF.emergency_with_differences === 4
  && Boolean(w1Written?.differences.some((difference) => (
    difference.checkId === 'emergency.stage3ManifestRecomputed'
  ))));
const w1PublicCopy = await readIfWritten(`_emergency/public/${stage3WitnessKey}`);
ok('W1 e2e 公開版のwitnessバイト列は証跡として固定一式に残る',
  w1PublicCopy.equals(w1PublicWitnessBytes)
  && Boolean(w1Written?.differences.some((difference) => (
    difference.checkId === 'emergency.publicArtifactBytes'
    && difference.what.includes(stage3WitnessKey)
  ))));

// W1 e2e（最強形）: 攻撃者が witness を**消した**場合でも固定一式は完成する。
//   R28-H3-4-02 の「消すだけで復旧が不可能になる」がここで閉じる。
const w1DeletedOutputDir = path.join(taskTmp, 'w1-deleted-witness-export');
let w1DeletedError = null;
const w1DeletedWritten = await (async () => {
  try {
    return await writeEmergencyResultSet({
      ctx: {
        blockNum: 4, report, cfg: DEFAULTS,
        data: {
          emergencyRebuild: {
            kind: 'groupGame',
            rebuiltSummary: w1Summary,
            allGroupResults: [],
            depositorResults: [],
            d1Groups: [witnessPairRow],
            verifiedDepositWei: witnessPairDeposits,
            chatWindowMs: null,
            factsMerkle: null,
            evidence: { resultCount: 2, adoptedCount: 2, chatWindowMs: null },
          },
          emergencyGroupArchives: new Map([[0, witnessGroupData]]),
          emergencyServerSubmissions: {},
          emergencySubmissionCandidates: [],
          groupsDerived: w1GroupsDerived,
          gameSelection: w1GameSelection,
        },
      },
      source: w1RosterSource({
        files: {},
        witnessKeys: [],
      }),
      outputDir: w1DeletedOutputDir,
    });
  } catch (error) { w1DeletedError = error; return null; }
})();
const w1DeletedWitness = w1DeletedWritten
  ? await fs.readFile(path.join(w1DeletedOutputDir, stage3WitnessKey)).catch(() => Buffer.alloc(0))
  : Buffer.alloc(0);
const w1DeletedStage3 = w1DeletedWritten
  ? JSON.parse(await fs.readFile(path.join(w1DeletedOutputDir, stage3Key), 'utf8').catch(() => '{}'))
  : {};
ok('W1 e2e 公開witnessが消されていても固定一式は完成し、witnessとmanifestは再計算版で整合する',
  w1DeletedWritten?.bundleIndex.complete === true
  && w1DeletedWitness.equals(stage3PairBytes)
  && w1DeletedStage3.groups?.[0]?.sha256 === digest(w1DeletedWitness)
  && w1DeletedWritten.differences.some((difference) => (
    difference.checkId === 'emergency.stage3WitnessRecomputed'
    && difference.rebuilt.difference === 'absent'
  )),
  String(w1DeletedError?.message || ''));

await rejects(
  'R29-D-2b-04: 固定一式の summary 実バイトが回路の正準文法を外れると輸出を拒否する',
  async () => writeEmergencyResultSet({
    ctx: {
      blockNum: 4, report, cfg: DEFAULTS,
      data: {
        emergencyRebuild: {
          kind: 'groupGame',
          rebuiltSummary: {
            ...structuredClone(w1Summary),
            groups: [{ ...structuredClone(w1Summary.groups[0]), lang: 1.5 }],
          },
          allGroupResults: [], depositorResults: [], d1Groups: [witnessPairRow],
          verifiedDepositWei: witnessPairDeposits, chatWindowMs: null, factsMerkle: null,
          evidence: { resultCount: 2, adoptedCount: 2, chatWindowMs: null },
        },
        emergencyGroupArchives: new Map([[0, witnessGroupData]]),
        emergencyServerSubmissions: {}, emergencySubmissionCandidates: [],
        groupsDerived: w1GroupsDerived,
        gameSelection: w1GameSelection,
      },
    },
    source: w1RosterSource({
      files: { [stage3Key]: digest(w1PublicStage3Manifest) },
      witnessKeys: [stage3WitnessKey],
      fileMap: [
        [stage3Key, '_source/w1-stage3-manifest.bin'],
        [stage3WitnessKey, '_source/w1-stage3-group0.bin'],
      ],
    }),
    outputDir: path.join(taskTmp, 'z8-noncanonical-fixed-summary'),
  }),
  /summary\.json in the emergency fixed bundle.*restricted grammar/s,
);

// ==================================================================
// 🔴 便 Z16 / R29-D-2-01（2026-09-22）
//   名簿payloadの必要鍵は公開 result manifest の files ではなく、再計算した群集合と
//   独立のチェーン目印で選ばれた roster manifest から決める。保存世代が無い鍵は
//   Stage C の正典 pin と一致した再構成 payload bytes を運ぶ。
// ==================================================================
const z16Stage3ManifestSaved = path.relative(taskTmp, path.join(w1OutputDir, stage3Key));
const z16Stage3WitnessSaved = path.relative(taskTmp, path.join(w1OutputDir, stage3WitnessKey));
const z16Ctx = (gateReport) => ({
  blockNum: 4,
  report: gateReport,
  cfg: DEFAULTS,
  data: {
    gameSelection: w1GameSelection,
    emergencyRebuild: {
      kind: 'groupGame',
      rebuiltSummary: structuredClone(w1Summary),
      allGroupResults: [],
      depositorResults: [],
      d1Groups: [witnessPairRow],
      verifiedDepositWei: witnessPairDeposits,
      chatWindowMs: null,
      factsMerkle: null,
      evidence: { resultCount: 2, adoptedCount: 2, chatWindowMs: null },
    },
    emergencyGroupArchives: new Map([[0, witnessGroupData]]),
    emergencyServerSubmissions: {},
    emergencySubmissionCandidates: [],
    groupsDerived: structuredClone(w1GroupsDerived),
  },
});
const z16Report = ({ manifestFileList = 'pass' } = {}) => {
  const checks = new Map(baseChecks);
  checks.set('check.stageC.manifestFileList', manifestFileList);
  return {
    list: () => [...checks].map(([id, status]) => ({
      id, status, params: checkParams.get(id) || {},
    })),
    get: (id) => (checks.has(id)
      ? { status: checks.get(id), params: checkParams.get(id) || {} }
      : null),
  };
};
const z16Source = ({ files, objects = {} }) => w1RosterSource({
  files,
  witnessKeys: [stage3WitnessKey],
  fileMap: [
    [stage3Key, z16Stage3ManifestSaved],
    [stage3WitnessKey, z16Stage3WitnessSaved],
  ],
  objects,
});

const p8bHonestRosterWritten = await writeEmergencyResultSet({
  ctx: z16Ctx(z16Report()),
  source: z16Source({ files: structuredClone(w1ResultManifest.files) }),
  outputDir: path.join(taskTmp, 'p8b-honest-roster-no-difference'),
});
ok('P8b P3: 公開名簿鍵が再生成側と一致する正常形ではroster差分を常時出力しない',
  p8bHonestRosterWritten.bundleIndex.complete === true
  && p8bHonestRosterWritten.differences.every((difference) => (
    difference.checkId !== 'emergency.rosterKeySetRecomputed'
  )), JSON.stringify(p8bHonestRosterWritten.differences));

// (a) 公開 result manifest から実在 group0 の申告だけを落とす。
const z16MissingRosterFilesA = structuredClone(w1ResultManifest.files);
delete z16MissingRosterFilesA[w1RosterGroup0Key];
const z16AOutputDir = path.join(taskTmp, 'z16-a-public-roster-omission');
let z16AWritten = null;
let z16AError = null;
try {
  z16AWritten = await writeEmergencyResultSet({
    ctx: z16Ctx(z16Report({ manifestFileList: 'fail' })),
    source: z16Source({ files: z16MissingRosterFilesA }),
    outputDir: z16AOutputDir,
  });
} catch (error) { z16AError = error; }
const z16AGroupBytes = z16AWritten
  ? await fs.readFile(path.join(z16AOutputDir, w1RosterGroup0Key)).catch(() => Buffer.alloc(0))
  : Buffer.alloc(0);
ok('Z16 (a) 公開 manifest が1群の名簿の申告を落としていても、その名簿が固定一式へ入り輸出が完走する',
  z16AWritten?.bundleIndex.complete === true
  && z16AGroupBytes.equals(w1RosterGroup0Bytes)
  && z16AWritten.resultManifest.files[w1RosterGroup0Key] === digest(w1RosterGroup0Bytes),
  String(z16AError?.message || ''));

// (b) 公開 result manifest だけへ架空 group9 を足し、backup にも攻撃者bytesを置く。
const z16PhantomKey = 'games/block4/roster/group9.json';
const z16PhantomBytes = Buffer.from('{"blockNum":4,"groupId":9,"members":[]}');
const z16PhantomRow = {
  ...await save('_observer/generations/z16-roster-group9-phantom.bin', z16PhantomBytes),
  generation: 1, observationOrdinal: '00009003:00000000',
};
const z16PhantomFiles = structuredClone(w1ResultManifest.files);
z16PhantomFiles[z16PhantomKey] = digest(z16PhantomBytes);
const z16BOutputDir = path.join(taskTmp, 'z16-b-public-phantom-roster');
let z16BWritten = null;
let z16BError = null;
try {
  z16BWritten = await writeEmergencyResultSet({
    ctx: z16Ctx(z16Report({ manifestFileList: 'fail' })),
    source: z16Source({
      files: z16PhantomFiles,
      objects: { [z16PhantomKey]: [z16PhantomRow] },
    }),
    outputDir: z16BOutputDir,
  });
} catch (error) { z16BError = error; }
const z16BPhantomExists = await fs.stat(path.join(z16BOutputDir, z16PhantomKey))
  .then(() => true).catch(() => false);
ok('Z16 (b) 公開 manifest が実在しない群の名簿を申告していても、その鍵は固定一式へ入らない',
  z16BWritten?.bundleIndex.complete === true
  && z16BPhantomExists === false
  && Object.hasOwn(z16BWritten.resultManifest.files, z16PhantomKey) === false,
  String(z16BError?.message || ''));

// (c) 再計算側が必要とする group0 の全保存世代を消す。
const n5WrittenPayloads = reconstructCanonicalRosterPayloads(4, w1GroupsDerived);
const n5WriteCtx = z16Ctx(z16Report({ manifestFileList: 'fail' }));
n5WriteCtx.data.emergencyRosterPayloads = { ...n5WrittenPayloads, origin: 'reconstructed' };
const n5MissingSource = z16Source({
  files: z16MissingRosterFilesA,
  objects: { [w1RosterGroup0Key]: [], [w1RosterIndexKey]: [] },
});
n5MissingSource.fileMap.delete(w1RosterManifestKey);
const n5MissingOutput = path.join(taskTmp, 'n5-roster-payload-rebuilt');
const n5MissingWritten = await writeEmergencyResultSet({
  ctx: n5WriteCtx, source: n5MissingSource, outputDir: n5MissingOutput,
}).catch((error) => error);
ok('N5 Z16 (c) 正: 正典 manifest・index・group が未保存でも pin 一致の再構成で完走',
  n5MissingWritten?.bundleIndex?.complete === true
  && (await fs.readFile(path.join(n5MissingOutput, w1RosterManifestKey))).toString('utf8')
    === n5WrittenPayloads.manifestText
  && (await fs.readFile(path.join(n5MissingOutput, w1RosterIndexKey))).toString('utf8')
    === n5WrittenPayloads.indexText
  && (await fs.readFile(path.join(n5MissingOutput, w1RosterGroup0Key))).toString('utf8')
    === n5WrittenPayloads.groupTexts.get(0)
  && n5MissingWritten.differences.filter((difference) =>
    difference.checkId === 'emergency.rosterPayloadReconstructed').length === 2,
  String(n5MissingWritten?.message || ''));
const n5VariantManifestBytes = Buffer.from(JSON.stringify({
  ...JSON.parse(n5WrittenPayloads.manifestText), variant: true,
}));
const n5VariantManifestRow = await save('_observer/generations/n5-roster-variant.bin',
  n5VariantManifestBytes);
const n5VariantSource = z16Source({ files: z16MissingRosterFilesA,
  objects: { [w1RosterIndexKey]: [], [w1RosterGroup0Key]: [] } });
n5VariantSource.fileMap.set(w1RosterManifestKey, n5VariantManifestRow.savedFile);
const n5VariantOutput = path.join(taskTmp, 'n5-roster-variant-public-copy');
const n5VariantCtx = z16Ctx(z16Report({ manifestFileList: 'fail' }));
n5VariantCtx.data.emergencyRosterPayloads = { ...n5WrittenPayloads, origin: 'reconstructed' };
const n5VariantWritten = await writeEmergencyResultSet({
  ctx: n5VariantCtx, source: n5VariantSource, outputDir: n5VariantOutput,
}).catch((error) => error);
ok('N5 名簿 variant: 固定鍵は正典バイト、公開 variant は _emergency/public へ退避',
  n5VariantWritten?.bundleIndex?.complete === true
  && (await fs.readFile(path.join(n5VariantOutput, w1RosterManifestKey))).toString('utf8')
    === n5WrittenPayloads.manifestText
  && (await fs.readFile(path.join(n5VariantOutput, '_emergency/public', w1RosterManifestKey)))
    .equals(n5VariantManifestBytes),
  String(n5VariantWritten?.message || ''));
const n5BadIndexCtx = z16Ctx(z16Report({ manifestFileList: 'fail' }));
n5BadIndexCtx.data.emergencyRosterPayloads = { ...n5WrittenPayloads, indexText: '{}' };
await rejects('N5 Z16 (c) 負: 再構成 index が manifest pin と違えば従来の文言で停止',
  () => writeEmergencyResultSet({
    ctx: n5BadIndexCtx,
    source: z16Source({ files: z16MissingRosterFilesA,
      objects: { [w1RosterIndexKey]: [] } }),
    outputDir: path.join(taskTmp, 'n5-roster-index-pin-mismatch'),
  }), /games\/block4\/roster\/index\.json: required roster key has no saved generation in the backup/);
const n5BadGroupCtx = z16Ctx(z16Report({ manifestFileList: 'fail' }));
n5BadGroupCtx.data.emergencyRosterPayloads = { ...n5WrittenPayloads,
  groupTexts: new Map([[0, '{}']]) };
await rejects('N5 Z16 (c) 負: 再構成 group が manifest pin と違えば従来の文言で停止',
  () => writeEmergencyResultSet({
    ctx: n5BadGroupCtx,
    source: z16Source({ files: z16MissingRosterFilesA,
      objects: { [w1RosterGroup0Key]: [] } }),
    outputDir: path.join(taskTmp, 'n5-roster-group-pin-mismatch'),
  }), /games\/block4\/roster\/group0\.json: required roster key has no saved generation in the backup/);
await rejects(
  'N5 Z16 (c) 負: 採用済み再構成も無い必要鍵は従来の文言で止まる',
  () => writeEmergencyResultSet({
    ctx: z16Ctx(z16Report({ manifestFileList: 'fail' })),
    source: z16Source({
      files: z16MissingRosterFilesA,
      objects: { [w1RosterGroup0Key]: [] },
    }),
    outputDir: path.join(taskTmp, 'z16-c-required-roster-missing'),
  }),
  /games\/block4\/roster\/group0\.json: required roster key has no saved generation in the backup/,
);

// (d) (a) とは別の輸出で、群集合の採用元と両側の差を1行に固定する。
const z16DWritten = await writeEmergencyResultSet({
  ctx: z16Ctx(z16Report({ manifestFileList: 'fail' })),
  source: z16Source({ files: z16MissingRosterFilesA }),
  outputDir: path.join(taskTmp, 'z16-d-roster-key-difference'),
});
const z16DRosterDifferences = z16DWritten.differences.filter((difference) => (
  difference.checkId === 'emergency.rosterKeySetRecomputed'
));
ok('Z16 (d) 公開 manifest の申告と再計算側の群集合が食い違うとき、差分が1行残りどちらを採ったか分かる',
  z16DRosterDifferences.length === 1
  && z16DRosterDifferences[0].chain.resultManifestGroupIds.join(',') === ''
  && z16DRosterDifferences[0].rebuilt.adoptedGroupIds.join(',') === '0'
  && z16DRosterDifferences[0].rebuilt.adoptedAuthority
    === 'rebuiltSummary.groups checked against ctx.data.groupsDerived');

const z16RosterKeys = [w1RosterIndexKey, w1RosterGroup0Key];
const z16NonRosterEntries = Object.entries(w1ResultManifest.files).filter(([key]) => (
  !z16RosterKeys.includes(key)
));
const z16RosterValues = new Map(z16RosterKeys.map((key) => [key, w1ResultManifest.files[key]]));
const p3RosterShapeCases = [
  {
    label: 'group00',
    keys: [w1RosterIndexKey, w1RosterGroup0Key, 'games/block4/roster/group00.json'],
  },
  {
    label: 'huge',
    keys: [w1RosterIndexKey, w1RosterGroup0Key, 'games/block4/roster/group99999999999999999999.json'],
  },
  {
    label: 'order',
    keys: [w1RosterGroup0Key, w1RosterIndexKey],
  },
];
for (const rosterCase of p3RosterShapeCases) {
  const files = Object.fromEntries([
    ...z16NonRosterEntries,
    ...rosterCase.keys.map((key) => [key, z16RosterValues.get(key) || 'ab'.repeat(32)]),
  ]);
  let written = null;
  let writeError = null;
  try {
    written = await writeEmergencyResultSet({
      ctx: z16Ctx(z16Report({ manifestFileList: 'fail' })),
      source: z16Source({ files }),
      outputDir: path.join(taskTmp, `p3-roster-${rosterCase.label}`),
    });
  } catch (error) { writeError = error; }
  const rosterDifferences = written?.differences?.filter((difference) => (
    difference.checkId === 'emergency.rosterKeySetRecomputed'
  )) || [];
  ok(`P3 R30-A-3-03/D-3-03 公開名簿鍵 ${rosterCase.label} は完走し、生の順序つき鍵列を差分1行へ残す`,
    written?.bundleIndex?.complete === true
    && rosterDifferences.length === 1
    && JSON.stringify(rosterDifferences[0].chain.resultManifestRosterKeys)
      === JSON.stringify(rosterCase.keys)
    && JSON.stringify(rosterDifferences[0].rebuilt.resultManifestRosterKeys)
      === JSON.stringify(z16RosterKeys),
    String(writeError?.message || ''));
}

// (e) 便 W1 の退避枝そのものを独立に再測定する。
const z16EWitness = runWitnessAdoption(stage3PairBytes, {
  extraCapture: [[strayKey, strayBytes]],
});
ok('Z16 (e) Stage 3 group witness の扱い（便 W1 の再計算側優先・公開版の _emergency/public/ 退避）がこの便の前後で変わっていない',
  z16EWitness.threw === null
  && z16EWitness.capture.has(strayKey) === false
  && z16EWitness.capture.get(`_emergency/public/${strayKey}`).equals(strayBytes)
  && z16EWitness.verification.differences.some((difference) => (
    difference.checkId === 'emergency.stage3WitnessDropped'
  )));

// (f) 先頭に攻撃者世代を置いても、roster manifest のsha256に一致する2本目を採る。
const z16WrongGroupBytes = Buffer.from('{"blockNum":4,"groupId":0,"members":[]}');
const z16WrongGroupRow = {
  ...await save('_observer/generations/z16-roster-group0-wrong-first.bin', z16WrongGroupBytes),
  generation: 0, observationOrdinal: '00000001:00000000',
};
const z16FSource = z16Source({
  files: structuredClone(w1ResultManifest.files),
  objects: { [w1RosterGroup0Key]: [z16WrongGroupRow, w1RosterGroup0Row] },
});
const z16FOutputDir = path.join(taskTmp, 'z16-f-roster-generation-pin');
const z16FWritten = await writeEmergencyResultSet({
  ctx: z16Ctx(z16Report()),
  source: z16FSource,
  outputDir: z16FOutputDir,
});
const z16FGroupBytes = await fs.readFile(path.join(z16FOutputDir, w1RosterGroup0Key));
const z16FSelection = z16FSource.selected.find((item) => item.key === w1RosterGroup0Key);
const z16UnpinnedRosterManifestBytes = Buffer.from(JSON.stringify({
  blockNum: 4,
  indexSha256: digest(w1RosterIndexBytes),
  groups: [],
}));
const z16UnpinnedRosterManifestRow = await save(
  '_observer/generations/z16-roster-manifest-without-group-pin.bin',
  z16UnpinnedRosterManifestBytes,
);
const z16AmbiguousSource = z16Source({
  files: structuredClone(w1ResultManifest.files),
  objects: { [w1RosterGroup0Key]: [z16WrongGroupRow, w1RosterGroup0Row] },
});
z16AmbiguousSource.fileMap.set(w1RosterManifestKey, z16UnpinnedRosterManifestRow.savedFile);
let z16AmbiguousError = null;
try {
  await writeEmergencyResultSet({
    ctx: z16Ctx(z16Report()),
    source: z16AmbiguousSource,
    outputDir: path.join(taskTmp, 'z16-f-roster-generation-ambiguous'),
  });
} catch (error) { z16AmbiguousError = error; }
ok('Z16 (f) 複数世代があるときに黙って最初を採らず、チェーンに錨のある宣言に一致する世代を採る',
  z16FWritten.bundleIndex.complete === true
  && z16FGroupBytes.equals(w1RosterGroup0Bytes)
  && z16FGroupBytes.equals(z16WrongGroupBytes) === false
  && z16FSelection?.savedFile === w1RosterGroup0Row.savedFile
  && z16FSelection?.marker === 'rosterManifest.sha256'
  && /games\/block4\/roster\/group0\.json: chain-selected roster manifest has no sha256 declaration and 2 saved variants are ambiguous/
    .test(String(z16AmbiguousError?.message || '')));

// ==================================================================
// 🔴 便 Z17（2026-09-22）
//   Z16 が追加した manifestFileList の名簿限定例外を、名簿以外の鍵差や別IDへ
//   広げられないようにする。関門が fail のまま通すID集合も全数で pin する。
// ==================================================================

// (a) 名簿 group0 の申告を落としたうえで、再生成側に無い非名簿鍵を公開側だけへ足す。
// 名簿差が同時に在るので、絞り込みを無条件 true にするとこの輸出は通ってしまう。
const z17ExtraNonRosterKey = 'games/block4/attacker-extra.json';
const z17ExtraNonRosterFiles = structuredClone(w1ResultManifest.files);
delete z17ExtraNonRosterFiles[w1RosterGroup0Key];
z17ExtraNonRosterFiles[z17ExtraNonRosterKey] = 'ab'.repeat(32);
await rejects(
  'Z17 (a) 名簿鍵の差と同時に非名簿鍵が公開 manifest に多い manifestFileList=fail は輸出を拒否する',
  () => writeEmergencyResultSet({
    ctx: z16Ctx(z16Report({ manifestFileList: 'fail' })),
    source: z16Source({ files: z17ExtraNonRosterFiles }),
    outputDir: path.join(taskTmp, 'z17-a-extra-non-roster-key'),
  }),
  /verification failed: check\.stageC\.manifestFileList/,
);

// (b) 名簿 group0 の申告と、再生成される非名簿 summary の申告を同時に落とす。
// こちらも名簿差だけを見れば例外候補だが、非名簿鍵が足りないので通してはならない。
const z17MissingNonRosterKey = 'games/block4/summary.json';
const z17MissingNonRosterFiles = structuredClone(w1ResultManifest.files);
delete z17MissingNonRosterFiles[w1RosterGroup0Key];
delete z17MissingNonRosterFiles[z17MissingNonRosterKey];
await rejects(
  'Z17 (b) 名簿鍵の差と同時に非名簿鍵が公開 manifest に足りない manifestFileList=fail は輸出を拒否する',
  () => writeEmergencyResultSet({
    ctx: z16Ctx(z16Report({ manifestFileList: 'fail' })),
    source: z16Source({ files: z17MissingNonRosterFiles }),
    outputDir: path.join(taskTmp, 'z17-b-missing-non-roster-key'),
  }),
  /verification failed: check\.stageC\.manifestFileList/,
);

// (c) boolean の例外口が開いていても、別IDの fail は従来どおり関門を閉じる。
const z17OtherIdChecks = new Map(
  EMERGENCY_REQUIRED_CHECKS.groupGame.map((id) => [id, 'pass']),
);
z17OtherIdChecks.set('check.stageC.rosterKeys', 'fail');
const z17OtherIdReport = {
  list: () => [...z17OtherIdChecks].map(([id, status]) => ({ id, status, params: {} })),
  get: (id) => (z17OtherIdChecks.has(id)
    ? { status: z17OtherIdChecks.get(id), params: {} }
    : null),
};
await rejects(
  'Z17 (c) 名簿限定例外が有効でも manifestFileList 以外の fail は輸出を拒否する',
  () => assertEmergencyVerificationGate(z17OtherIdReport, {
    kind: 'groupGame', rebuiltSummary: {}, allGroupResults: [],
  }, { acceptRosterOnlyManifestFileListDifference: true }),
  /verification failed: check\.stageC\.rosterKeys/,
);

// (d) 3つの表に現れない「4つ目の許容口」も、CHECK_INVENTORY 全件との総当たりで数える。
// 例外なしは固定許容表だけ、例外ありはそこへ manifestFileList だけを足した集合でなければならない。
function z17AcceptedFailedIds(acceptRosterOnlyManifestFileListDifference) {
  const accepted = [];
  for (const candidateId of CHECK_INVENTORY) {
    const checks = new Map(EMERGENCY_REQUIRED_CHECKS.groupGame.map((id) => [id, 'pass']));
    checks.set(candidateId, 'fail');
    const candidateReport = {
      list: () => [...checks].map(([id, status]) => ({ id, status, params: {} })),
      get: (id) => (checks.has(id) ? { status: checks.get(id), params: {} } : null),
    };
    try {
      assertEmergencyVerificationGate(candidateReport, {
        kind: 'groupGame', rebuiltSummary: {}, allGroupResults: [],
      }, { acceptRosterOnlyManifestFileListDifference });
      accepted.push(candidateId);
    } catch {
      // expected for every failed check outside the exact fail-through set
    }
  }
  return accepted;
}
const z17AcceptedWithoutRosterException = z17AcceptedFailedIds(false);
const z17AcceptedWithRosterException = z17AcceptedFailedIds(true);
const z17ExpectedWithoutRosterException = CHECK_INVENTORY.filter((id) => (
  EMERGENCY_ALLOWED_DIFFERENCE_CHECKS.includes(id)
));
const z17ExpectedWithRosterException = CHECK_INVENTORY.filter((id) => (
  EMERGENCY_ALLOWED_DIFFERENCE_CHECKS.includes(id)
  || id === 'check.stageC.manifestFileList'
));
ok('Z17 (d) assertEmergencyVerificationGate が fail のまま通す id 集合は許容表＋manifestFileList（例外有効時のみ）と完全一致する',
  JSON.stringify(z17AcceptedWithoutRosterException)
    === JSON.stringify(z17ExpectedWithoutRosterException)
  && JSON.stringify(z17AcceptedWithRosterException)
    === JSON.stringify(z17ExpectedWithRosterException)
  && z17AcceptedWithoutRosterException.includes('check.stageC.manifestFileList') === false
  && z17AcceptedWithRosterException.includes('check.stageC.manifestFileList') === true,
  JSON.stringify({
    without: z17AcceptedWithoutRosterException,
    with: z17AcceptedWithRosterException,
  }));

// ==================================================================
// 🔴 便 Z5 / R29-A-1b-01 ≡ R29-D-2-04（2026-09-21）
//   固定一式 writer へ渡す採点5値の env（GAME_MIN_CHARS / GAME_MIN_MESSAGES /
//   GAME_MAX_CHARS / GAME_MAX_MESSAGES / GAME_MAX_MSG_CHARS）は、
//   公開 manifest の rules ではなく**検証器の pin（ctx.cfg.pins）**から作る。
//   両方向を全数で測る。通る: ①公開 rules が5値とも逸脱していても輸出が完走し、
//   再生成 manifest は pin 値を宣言する ④env を通らない rules 欄の逸脱は従来どおり完走。
//   止まる: ②検証器の pin をゲスト焼き込み値から外すと輸出が止まる（fail-closed 維持）
//   ③timing 4値は pin へ寄せていない＝公開 rules のまま運ばれ、rulesTiming は許容表の外。
// ==================================================================
const z5PinsWith = (overrides = {}, capOverrides = {}) => ({
  ...DEFAULTS,
  pins: {
    ...DEFAULTS.pins,
    ...overrides,
    chatCaps: { ...DEFAULTS.pins.chatCaps, ...capOverrides },
  },
});
async function runZ5Export(label, { manifest, cfg = DEFAULTS }) {
  const output = path.join(taskTmp, `z5-output-${label}`);
  const ctx = v8CleanCtx();
  ctx.cfg = cfg;
  const result = await withFixedNow(v8FixedIso, () => writeEmergencyResultSet({
    ctx,
    source: {
      sourceDir: taskTmp,
      selectedManifest: manifest,
      selected: [],
      index: { sourceRunId: 'z5-unit' },
      fileMap: new Map([
        [stage3Key, '_source/stage3.bin'],
        [infoKey, '_source/info.bin'],
      ]),
    },
    outputDir: output,
  }));
  const writtenRules = JSON.parse(
    await fs.readFile(path.join(output, v8ManifestKey), 'utf8'),
  ).rules;
  return { result, output, writtenRules };
}

// ① 通る側: 公開 rules の採点5値が1つずつ pin から外れていても輸出は完走し、
//    再生成 manifest は pin 値を宣言する。
const z5DeviantScoringManifest = {
  ...selectedManifest,
  rules: {
    ...selectedManifest.rules,
    minChars: DEFAULTS.pins.minChars + 1,
    minMessages: DEFAULTS.pins.minMessages + 1,
    maxChars: DEFAULTS.pins.chatCaps.maxChars + 1,
    maxMessages: DEFAULTS.pins.chatCaps.maxMessages + 1,
    maxMsgChars: DEFAULTS.pins.chatCaps.maxMsgChars + 1,
  },
};
let z5DeviantError = null;
const z5Deviant = await runZ5Export('deviant-scoring', { manifest: z5DeviantScoringManifest })
  .catch((error) => { z5DeviantError = error; return null; });
ok('Z5 R29-A-1b-01/D-2-04 ① 公開rulesの採点5値が全て逸脱していても輸出は完走し、再生成manifestはpin値を宣言する',
  z5Deviant?.result.bundleIndex.complete === true
  && z5Deviant.writtenRules.minChars === DEFAULTS.pins.minChars
  && z5Deviant.writtenRules.minMessages === DEFAULTS.pins.minMessages
  && z5Deviant.writtenRules.maxChars === DEFAULTS.pins.chatCaps.maxChars
  && z5Deviant.writtenRules.maxMessages === DEFAULTS.pins.chatCaps.maxMessages
  && z5Deviant.writtenRules.maxMsgChars === DEFAULTS.pins.chatCaps.maxMsgChars,
  String(z5DeviantError?.message || JSON.stringify(z5Deviant?.writtenRules)));

// ② 止まる側（fail-closed の保存）: 検証器の pin をゲスト焼き込み値から外すと、
//    vendored の assertGuestPinnedRules が throw し固定一式は書かれない。
//    🔴 旧実装（env を公開 rules から作る）ではこの入力が**緑のまま通ってしまう**。
const z5BadPinOutput = path.join(taskTmp, 'z5-output-bad-pin');
await rejects('Z5 R29-A-1b-01/D-2-04 ② 検証器のpinがゲスト焼き込み値と食い違えば輸出は止まる',
  () => runZ5Export('bad-pin', {
    manifest: selectedManifest,
    cfg: z5PinsWith({ minChars: DEFAULTS.pins.minChars + 1 }),
  }),
  /\[calc\] scoring thresholds disagree/);
ok('Z5 R29-A-1b-01/D-2-04 ② 止まったとき再生成manifestは1バイトも書かれない',
  await fs.stat(path.join(z5BadPinOutput, v8ManifestKey)).then(() => false).catch(() => true));

// ③ 逆向き: timing 4値は pin へ寄せていない＝公開 rules のまま再生成 manifest へ運ばれ、
//    `check.stageC.rulesTiming` は許容表の外なので食い違えば輸出が拒否される。
const z5TimingManifest = {
  ...selectedManifest,
  rules: {
    ...selectedManifest.rules,
    startTime: '1234567',
    blockTime: 987_000,
    periodDurations: {
      ...selectedManifest.rules.periodDurations,
      gamePeriod: 65_499,
      submitPeriod: 54_501,
    },
  },
};
let z5TimingError = null;
const z5Timing = await runZ5Export('timing', { manifest: z5TimingManifest })
  .catch((error) => { z5TimingError = error; return null; });
ok('Z5 R29-A-1b-01 ③ timing 4値はpinへ寄せていない: startTime/blockTime/gamePeriod/submitPeriodの4値が公開rulesのまま再生成manifestへ載る',
  z5Timing?.writtenRules.startTime === '1234567'
  && z5Timing.writtenRules.blockTime === 987_000
  && z5Timing.writtenRules.periodDurations?.gamePeriod === 65_499
  && z5Timing.writtenRules.periodDurations?.submitPeriod === 54_501
  && EMERGENCY_ALLOWED_DIFFERENCE_CHECKS.includes('check.stageC.rulesTiming') === false,
  String(z5TimingError?.message || JSON.stringify(z5Timing?.writtenRules)));
const z5TimingReportChecks = new Map(baseChecks);
z5TimingReportChecks.set('check.stageC.rulesTiming', 'fail');
await rejects('Z5 R29-A-1b-01 ③ rulesTimingがfailなら従来どおり輸出を拒否する',
  async () => assertEmergencyVerificationGate({
    list: () => [...z5TimingReportChecks].map(([id, status]) => ({ id, status })),
    get: (id) => ({ status: z5TimingReportChecks.get(id) }),
  }, { kind: 'noGame', rebuiltSummary: {}, allGroupResults: [] }),
  /emergency export refused because verification failed: check\.stageC\.rulesTiming/);

// ④ R29-D-2-04: `check.stageC.rulesPins` が見る17項目のうち env を通らない欄
//    （maxReports 等）は、修正の前後どちらでも輸出が完走し定数で宣言される。
const z5NonEnvManifest = {
  ...selectedManifest,
  rules: { ...selectedManifest.rules, maxReports: DEFAULTS.pins.maxReports + 1 },
};
let z5NonEnvError = null;
const z5NonEnv = await runZ5Export('non-env-rule', { manifest: z5NonEnvManifest })
  .catch((error) => { z5NonEnvError = error; return null; });
ok('Z5 R29-D-2-04 ④ envを通らないrules欄（maxReports）の逸脱は輸出を止めず、再生成側は定数で宣言する',
  z5NonEnv?.result.bundleIndex.complete === true
  && z5NonEnv.writtenRules.maxReports === DEFAULTS.pins.maxReports,
  String(z5NonEnvError?.message || JSON.stringify(z5NonEnv?.writtenRules)));

// ==================================================================
// 🔴 便 Z5 / R29-B-5b-02（2026-09-21・緊急モード限定・1鍵限定）
//   便 W1 が「公開 Stage 3 manifest は権威ではなく証跡」にした結果、その鍵は
//   固定一式の fileMap から落ちうる。下流の全件照合がそれを FAIL にすると、
//   輸出関門（assertEmergencyVerificationGate）が拒否して固定一式が0バイトになる。
//   両方向を全数で測る。通る: R1 緊急モードの当該1鍵は warn ＋差分1件。
//   止まる: R2 通常モードは据え置き FAIL ／ R3 緊急でも他の宣言鍵は FAIL
//          ／ R4 関門は warn を通し fail を拒む。
// 🔴 注記: R1 は `check.stageC.manifestFiles` に**新しいモード差**を作る。
//   降格配列（EMERGENCY_DOWNGRADABLE_CHECKS）にも許容配列にも1件も足していないので、
//   上の T1e「実検査群のmode差分集合は降格配列の部分集合」は
//   **その fixture の範囲でしか成り立たなくなった**。R3 がその境界（当該1鍵だけ）を固定する。
// ==================================================================
const z5Stage3ManifestKey = 'verification/block4/stage3/manifest.json';
async function executeZ5ManifestMode(emergencyMode, declaredKey) {
  const { checks, api: report } = modeReport();
  const manifestData = {
    blockNum: 4, algorithm: 'sha256', rules: {}, files: { [declaredKey]: 'aa'.repeat(32) },
  };
  manifestData.manifestHash = manifestCoreHash(manifestData);
  const ctx = {
    blockNum: 4, report,
    ui: { t: (id) => id, println: () => {} },
    data: emergencyMode ? { emergencySource: { kind: 'unit' } } : {},
    cfg: DEFAULTS,
    chain: {
      getResultHash: async () => ({ hash: `0x${'91'.repeat(32)}`, updated: 1 }),
      resultRegistrationCount: async () => 1,
    },
    // 取得不能（raw==null）を測る盤面なので、再取得も必ず空を返す。
    r2: { release: () => {}, refetch: async () => null, fetchJson: async () => null },
  };
  const S = {
    files: {
      manifest: { data: manifestData }, summary: null, merkle: null,
      selection: null, gameGroups: null, evidenceReport: null, stage3Manifest: null,
      autoResult: null, rosterIndex: null, groups: new Map(), rosters: new Map(),
    },
    groupIds: [], auto: false,
    blockState: { root: `0x${'00'.repeat(32)}`, verificationStartedAt: 10 },
    anomalies: [], precheckedHashes: new Map(),
  };
  await checkManifest(ctx, S, {
    startTimeEntryMs: 0, blockTimeMs: 100_000, gamePeriodMs: 100_000, submitPeriodMs: 100_000,
  });
  return { checks, ctx, S };
}

// R1 通る側
const z5EmergencyStage3 = await executeZ5ManifestMode(true, z5Stage3ManifestKey);
ok('Z5 R29-B-5b-02 R1 緊急モードでStage 3入力manifestが取得不能ならWARN＋差分1件になる',
  z5EmergencyStage3.checks.get('check.stageC.manifestFiles')?.status === 'warn'
  && /^unavailable\/reconstructed: .*stage3\/manifest\.json/.test(
    z5EmergencyStage3.checks.get('check.stageC.manifestFiles')?.params?.failures || '',
  )
  && (z5EmergencyStage3.ctx.data.emergencyDifferences || []).filter((difference) => (
    difference.checkId === 'emergency.stage3WitnessUnavailable'
  )).length === 1,
  JSON.stringify(z5EmergencyStage3.checks.get('check.stageC.manifestFiles')));

// R2 止まる側（通常モードは1ミリも変えない）
const z5NormalStage3 = await executeZ5ManifestMode(false, z5Stage3ManifestKey);
ok('Z5 R29-B-5b-02 R2 通常モードは同じ入力を従来どおりFAILにする',
  z5NormalStage3.checks.get('check.stageC.manifestFiles')?.status === 'fail'
  && (z5NormalStage3.ctx.data.emergencyDifferences || []).length === 0,
  JSON.stringify(z5NormalStage3.checks.get('check.stageC.manifestFiles')));

// R3 止まる側（緊急でも他の宣言鍵は据え置き）
const z5EmergencyOther = await executeZ5ManifestMode(true, 'verification/block4/evidence-report.json');
ok('Z5 R29-B-5b-02 R3 緊急モードでもStage 3入力manifest以外の宣言鍵はFAILのまま',
  z5EmergencyOther.checks.get('check.stageC.manifestFiles')?.status === 'fail',
  JSON.stringify(z5EmergencyOther.checks.get('check.stageC.manifestFiles')));

ok('R29-D-2-02: 緊急固定一式が再生成する鍵だけは downloads の早期停止を越え、公開バイト運搬鍵は越えない',
  canContinueEmergencyAfterDownloadIssues(4, true, [
    'games/block4/group0.json',
    'games/block4/auto-results.json: invalid JSON',
    'merkle/block_4/index/a.json',
    'merkle/block_4/leaves/0.json',
    'merkle/block_4/levels/0/0.json: unavailable',
  ]) === true
  && canContinueEmergencyAfterDownloadIssues(4, false, ['games/block4/auto-results.json']) === false
  && canContinueEmergencyAfterDownloadIssues(4, true, ['entries/block4/game_selection.json']) === false
  && canContinueEmergencyAfterDownloadIssues(4, true, ['verification/block4/evidence-report.json']) === false
  && canContinueEmergencyAfterDownloadIssues(4, true, ['verification/block4/manifest.json']) === false
  && canContinueEmergencyAfterDownloadIssues(4, true, ['merkle/block_4.json']) === false);

const z8RegeneratedKey = 'merkle/block_4/leaves/0.json';
const z8EmergencyRegenerated = await executeZ5ManifestMode(true, z8RegeneratedKey);
const z8NormalRegenerated = await executeZ5ManifestMode(false, z8RegeneratedKey);
ok('R29-D-2-02: 宣言済みの再生成Merkle分冊が1世代も無くても緊急時だけmanifest照合を差分化する',
  z8EmergencyRegenerated.checks.get('check.stageC.manifestFiles')?.status === 'warn'
  && (z8EmergencyRegenerated.ctx.data.emergencyDifferences || []).some((difference) => (
    difference.checkId === 'check.stageC.downloads'
    && difference.chain?.key === z8RegeneratedKey
  ))
  && z8NormalRegenerated.checks.get('check.stageC.manifestFiles')?.status === 'fail',
  JSON.stringify({
    emergency: z8EmergencyRegenerated.checks.get('check.stageC.manifestFiles'),
    normal: z8NormalRegenerated.checks.get('check.stageC.manifestFiles'),
  }));

// R4 関門の両方向
const z5GateReport = (status) => ({
  list: () => [{ id: 'check.stageC.manifestFiles', status }],
  get: (id) => (EMERGENCY_REQUIRED_CHECKS.noGame.includes(id)
    ? { status: 'pass' }
    : { status: id === 'check.stageC.manifestFiles' ? status : 'pass' }),
});
const z5GateRebuild = { kind: 'noGame', rebuiltSummary: {}, allGroupResults: [] };
ok('Z5 R29-B-5b-02 R4 関門はmanifestFiles=warnを通す',
  assertEmergencyVerificationGate(z5GateReport('warn'), z5GateRebuild) === true);
await rejects('Z5 R29-B-5b-02 R4 関門はmanifestFiles=failを従来どおり拒む',
  async () => assertEmergencyVerificationGate(z5GateReport('fail'), z5GateRebuild),
  /emergency export refused because verification failed: check\.stageC\.manifestFiles/);
ok('Z5 R29-B-5b-02 R4 manifestFilesは許容集合にも降格集合にも入れていない',
  EMERGENCY_ALLOWED_DIFFERENCE_CHECKS.includes('check.stageC.manifestFiles') === false
  && EMERGENCY_DOWNGRADABLE_CHECKS.includes('check.stageC.manifestFiles') === false
  && EMERGENCY_ALLOWED_DIFFERENCE_CHECKS.length === 22
  && EMERGENCY_EFFECTIVE_DIFFERENCE_CHECKS.length === 30);

// ==================================================================
// T34/T3: 事故告知で使う取得先フラグ --source-base（取得先だけを差し替える）
//   両方向を全数で測る。通る: ①別の場所から取って完走 ②既定は従来どおり
//   ③--config と併用でも取得先は --source-base が勝つ ④前ブロックの2鍵を含めた
//   公開用の書き出しから N>=1 が完走。止まる: ⑤チェーンの目印と食い違えば従来どおり不合格
//   ⑥前ブロックの2鍵が欠けた書き出しでは N>=1 が止まる ⑦契約アドレス・chainId・pin は変わらない
// ==================================================================
if (process.env.U4_SKIP_LOCAL_SERVER !== '1') {
  const { loadConfig } = await import('../src/config.js');
  const { createR2 } = await import('../src/r2.js');
  const { startR2Server } = await import('./r2-server.mjs');
  const { run: runGroupingStage } = await import('../src/stages/grouping.js');
  const { createReport: makeReport } = await import('../src/report.js');
  const { sha256HexOfString } = await import('../src/json-utils.js');
  const { concatHex, keccak256: keccak, stringToHex } = await import('viem');
  const { materializeBase } = await import('../../tools/r2-backup-observer/src/observer.mjs');
  const { LocalAppendOnlyStore } = await import('../../tools/r2-backup-observer/src/storage.mjs');

  const pins = (cfg) => JSON.stringify(cfg.pins);
  const contracts = (cfg) => JSON.stringify(cfg.contracts);
  const baseline = loadConfig([]);

  // ② 既定（フラグ無し）は従来どおり
  ok('T3 ② 既定の取得先は同梱の r2Base のまま',
    baseline.r2Base === DEFAULTS.r2Base && baseline.sourceBase === null, baseline.r2Base);

  // ① 取得先だけを差し替える＋URL 末尾スラッシュを吸収する
  const flagged = loadConfig(['--source-base', 'http://127.0.0.1:1/incident/base///']);
  ok('T3 ① --source-base は r2Base だけを差し替え、末尾スラッシュを吸収する',
    flagged.r2Base === 'http://127.0.0.1:1/incident/base'
      && flagged.sourceBase === 'http://127.0.0.1:1/incident/base',
    JSON.stringify({ r2Base: flagged.r2Base, sourceBase: flagged.sourceBase }));

  // ⑦ 契約アドレス・chainId・pin は --source-base では変えられない
  ok('T3 ⑦ --source-base は契約アドレス・chainId・pin を1つも変えない',
    contracts(flagged) === contracts(baseline)
      && pins(flagged) === pins(baseline)
      && flagged.chainIdExpected === baseline.chainIdExpected
      && flagged.dataDir === baseline.dataDir,
    JSON.stringify({ contracts: contracts(flagged), chainId: flagged.chainIdExpected }));

  // ③ --config と併用しても取得先は --source-base が勝つ（config の他の上書きは生きる）
  const cfgFile = path.join(taskTmp, 'source-base-override.json');
  await fs.writeFile(cfgFile, JSON.stringify({
    r2Base: 'https://config.example.invalid/from-config',
    contracts: { hashStorage: `0x${'a1'.repeat(20)}` },
    chainIdExpected: 31337,
  }));
  const bothCwd = process.cwd();
  process.chdir(taskTmp);
  const both = loadConfig(['--config', 'source-base-override.json', '--source-base', 'http://127.0.0.1:1/announced']);
  const configOnly = loadConfig(['--config', 'source-base-override.json']);
  process.chdir(bothCwd);
  ok('T3 ③ --config と併用でも取得先は --source-base が勝ち、他の上書きは config のまま',
    both.r2Base === 'http://127.0.0.1:1/announced'
      && configOnly.r2Base === 'https://config.example.invalid/from-config'
      && both.contracts.hashStorage === `0x${'a1'.repeat(20)}`
      && both.chainIdExpected === 31337,
    JSON.stringify({ both: both.r2Base, configOnly: configOnly.r2Base }));

  // 排他規則: ローカルだけを読む2モードとは併用できない（usage エラー・exit 64）
  const cliEntry = path.resolve(import.meta.dirname, '../src/index.js');
  const spawnCli = (args) => spawnSync(process.execPath, [cliEntry, ...args], { encoding: 'utf8' });
  const withArtifactDir = spawnCli([
    '--source-base', 'http://127.0.0.1:1/x', '--artifact-dir', taskTmp,
    '--block', '0', '--non-interactive', '--lang', 'en',
  ]);
  const withEmergency = spawnCli([
    '--source-base', 'http://127.0.0.1:1/x', '--emergency-source', taskTmp,
    '--emergency-out', path.join(taskTmp, 'never'), '--block', '0', '--non-interactive', '--lang', 'en',
  ]);
  ok('T3 排他: --source-base と --artifact-dir / --emergency-source の併用は exit 64',
    withArtifactDir.status === 64 && withEmergency.status === 64
      && withArtifactDir.stderr.includes('--source-base cannot be combined')
      && withEmergency.stderr.includes('--source-base cannot be combined'),
    JSON.stringify({ a: withArtifactDir.status, e: withEmergency.status }));
  const help = spawnCli(['--help']);
  ok('T3 --help に取得先フラグと排他規則が出る',
    help.status === 0 && help.stdout.includes('--source-base URL')
      && help.stdout.includes('cannot\n                       be combined with --artifact-dir or --emergency-source'),
    help.stdout.slice(0, 200));

  // ---- ①④⑤⑥: 見張り役の公開用書き出し → HTTP → --source-base で Stage B を実走 ----
  const prev = 0;
  const N1 = 1;
  const prevSummary = {
    schemaVersion: 2, blockNum: prev, noGame: true, majorLangs: [], groups: [], totalGroups: 0,
  };
  const prevSummaryRaw = JSON.stringify(prevSummary);
  const prevManifest = {
    blockNum: prev,
    algorithm: 'keccak256-merkle',
    rules: { minChars: 500 },
    files: { [`games/block${prev}/summary.json`]: sha256HexOfString(prevSummaryRaw) },
  };
  const prevManifestRaw = JSON.stringify(prevManifest);
  const prevCore = `0x${sha256HexOfString(JSON.stringify({
    blockNum: prevManifest.blockNum, algorithm: prevManifest.algorithm,
    rules: prevManifest.rules, files: prevManifest.files,
  }))}`;

  const players = [0, 1, 2].map((index) => ({
    globalIndex: index, data: { uid: `u${index}`, lang: ['ja', 'en', 'fr'][index] },
  }));
  const selection = {
    blockNum: N1, randao: `0x${'51'.repeat(32)}`, applicantHash: `0x${'52'.repeat(32)}`, players,
  };
  const groupSeed = keccak(concatHex([selection.randao, selection.applicantHash, stringToHex('group')]));
  const gmForBase = new GameMasterDO({ storage: {} }, {});
  const derivedGroups = await gmForBase.formGroups(players, groupSeed, []);
  const gameGroups = gmForBase.createGroupSummary(N1, derivedGroups, selection);
  const currentSummary = {
    schemaVersion: 2,
    blockNum: N1,
    groups: derivedGroups.map((group) => ({
      group_id: group.groupId,
      members: group.members.map((member) => ({ userId: member.data.uid })),
    })),
  };

  const published = new Map([
    [`games/block${N1}/summary.json`, Buffer.from(JSON.stringify(currentSummary))],
    [`entries/block${N1}/game_groups.json`, Buffer.from(JSON.stringify(gameGroups))],
    [`games/block${prev}/summary.json`, Buffer.from(prevSummaryRaw)],
    [`verification/block${prev}/manifest.json`, Buffer.from(prevManifestRaw)],
  ]);
  const sourceStore = {
    async getBytes(name) { return published.get(String(name).replace(/^_versions\//, '')) ?? null; },
  };
  const latestStateFor = (keys) => keys.map((key, index) => ({
    key,
    blockNum: key.includes(`block${prev}/`) ? prev : N1,
    generation: 1,
    sha256: digest(published.get(key)),
    versionObject: `_versions/${key}`,
    storageGeneration: String(index + 1),
  }));
  const runManifestFor = (keys) => ({
    kind: 'r2-backup-observer-run', runId: 'run-t3', completedAt: '2026-09-18T00:00:00.000Z',
    lineageSequence: 1, latestState: latestStateFor(keys),
  });

  async function materializeAndServe(label, keys) {
    const outDir = path.join(taskTmp, `base-${label}`);
    await fs.mkdir(outDir, { recursive: true });
    const result = await materializeBase({
      store: sourceStore,
      sourceStore,
      destinationStore: new LocalAppendOnlyStore(outDir),
      prefix: 'observer/v1',
      runManifest: runManifestFor(keys),
      blockNum: N1,
      baseId: `incident-${label}`,
    });
    const served = await startR2Server({
      rootDir: path.join(outDir, 'observer/v1/bases', `incident-${label}`), port: 0,
    });
    return { result, served, outDir };
  }

  async function runStageBFrom({ baseUrl, anchorHash }) {
    const cfg = loadConfig(['--source-base', baseUrl]);
    cfg.dataDir = path.join(taskTmp, `data-${Math.random().toString(36).slice(2)}`);
    const lines = [];
    const ui = {
      t: (id) => id, println: (s = '') => lines.push(String(s)), warn: (s = '') => lines.push(`warn:${s}`),
    };
    const report = makeReport();
    const r2 = createR2(cfg, ui, N1);
    const ctx = {
      cfg, blockNum: N1, report, ui, r2,
      data: { gameSelection: selection, players, reuseFiles: false },
      chain: { getResultHash: async () => ({ hash: anchorHash, updated: 1 }) },
    };
    const outcome = await runGroupingStage(ctx);
    return {
      lines, report, stop: outcome.stop,
      checks: report.list().map((entry) => `${entry.id}=${entry.status}`),
    };
  }

  const allKeys = [...published.keys()];
  const withPrev = await materializeAndServe('withprev', allKeys);
  const withoutPrev = await materializeAndServe(
    'noprev', allKeys.filter((key) => !key.includes(`block${prev}/`)),
  );
  try {
    // ④ 前ブロックの2鍵を含めた公開用の書き出し → N>=1 の Stage B が完走する
    const good = await runStageBFrom({ baseUrl: withPrev.served.baseUrl, anchorHash: prevCore });
    ok('T3 ④ 前ブロックの2鍵つき公開用書き出しから N>=1 の Stage B が完走する',
      good.stop === false
        && good.checks.includes('check.stageB.prevAnchor=pass')
        && good.checks.includes('check.stageB.groupsMatch=pass')
        && good.checks.includes('check.stageB.summaryStructure=pass'),
      JSON.stringify(good.checks));
    // ① 取得は実際に --source-base の場所から行われている
    ok('T3 ① 取得は --source-base で指した場所から行われる',
      withPrev.result.previousBlockKeys.included.length === 2
        && withPrev.served.baseUrl.startsWith('http://127.0.0.1:'),
      JSON.stringify(withPrev.result.previousBlockKeys));
    // ⑤ 同じ取得先でも、チェーンの目印と食い違えば従来どおり不合格になる
    const mismatched = await runStageBFrom({
      baseUrl: withPrev.served.baseUrl, anchorHash: `0x${'ee'.repeat(32)}`,
    });
    ok('T3 ⑤ 取得先を替えてもチェーンの目印と食い違えば従来どおり prevAnchor は不合格',
      mismatched.checks.includes('check.stageB.prevAnchor=fail')
        && mismatched.lines.some((line) => line.startsWith('##UNVERIFIED_PREV_INPUT')),
      JSON.stringify(mismatched.checks));
    // ⑥ 前ブロックの2鍵が欠けた書き出しでは N>=1 が止まる（いまの形の再現）
    const missing = await runStageBFrom({ baseUrl: withoutPrev.served.baseUrl, anchorHash: prevCore });
    ok('T3 ⑥ 前ブロックの2鍵が欠けた書き出しでは N>=1 が止まる',
      missing.stop === true && missing.checks.includes('check.stageB.majorLangs=fail')
        && withoutPrev.result.previousBlockKeys.missing.length === 2,
      JSON.stringify({ checks: missing.checks, missing: withoutPrev.result.previousBlockKeys }));
  } finally {
    withPrev.served.stop();
    withoutPrev.served.stop();
  }
} else {
  console.log('  skip: T34/T3 localhost 待受を U4 限定実行で省略');
}

await fs.rm(taskTmp, { recursive: true, force: true });
await fs.rm(p6EmergencyDir, { recursive: true, force: true });
if (mutationTmpRoot) await fs.rm(mutationTmpRoot, { recursive: true, force: true });
console.log(`\nQ24 emergency unit: ${passed} passed, ${failed} failed`);
if (failed) process.exit(1);

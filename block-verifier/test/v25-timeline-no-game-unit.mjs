// V25-03: timeline_unverified は一時的な RPC/DO 障害だけでは確定せず、
// confirmation-safe block で resultWindow 終了後かつ Evidence resultCount=0 を
// 第三者検証器が再読取できた場合だけ正当な no-game とする。

import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

import { categorize } from '../src/index.js';
import { loadConfig } from '../src/config.js';
import { createReport, messageId } from '../src/report.js';
import { sha256HexOfString } from '../src/json-utils.js';
import { run as runGrouping } from '../src/stages/grouping.js';
import * as baseResultsModule from '../src/stages/results.js';
import {
  EMERGENCY_ALLOWED_DIFFERENCE_CHECKS,
  EMERGENCY_DOWNGRADABLE_CHECKS,
  EMERGENCY_REQUIRED_CHECKS,
  assertEmergencyVerificationGate,
  manifestCoreHash,
  readEmergencyArtifactGenerations as baseReadEmergencyArtifactGenerations,
} from '../src/emergency.js';
import {
  calculateGroupResults, getBlockRewardWei,
} from '../vendor/workers/game_workers/lib/game-result-calculator.js';
import { chatSignStringV2 } from '../vendor/workers/game_workers/lib/protocol-v2.js';
import { GameMasterDO } from '../vendor/workers/game_workers/game-master-DO.js';
import { buildRosterMemberCommitment } from '../vendor/workers/game_workers/lib/roster-member-root.js';
import {
  TIMELINE_NO_GAME_ROOT_STATE,
  adminCommitRootSubmissionDeadline,
  classifyTimelineNoGameRoot,
} from '../vendor/workers/game_workers/lib/block-lifecycle.js';
import { TIMELINE_NO_GAME_CAUSES } from '../vendor/workers/game_workers/lib/timeline-check.js';
import { concatHex, keccak256, stringToHex } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

const N = 0;
const EVIDENCE = `0x${'12'.repeat(20)}`;
const ETH_LOCK = `0x${'13'.repeat(20)}`; // R26-C4
const EXPECTED_TIMELINE_NO_GAME_CAUSES = [
  'chain_unreadable',
  'env_chain_mismatch',
  'grouping_anchor_unreadable',
  'previous_block_not_ready',
  'previous_block_anchor_pending',
];
const ZERO_ROOT = `0x${'0'.repeat(64)}`;
const SENTINEL_ROOT = `0x${'ab'.repeat(32)}`;
const VERIFICATION_PERIOD_SEC = 100;
const ROOT_DEADLINE = adminCommitRootSubmissionDeadline(900, VERIFICATION_PERIOD_SEC);
const MUTATION = process.argv.find((arg) => arg.startsWith('--mutation='))?.split('=')[1] || null;
let mutationRoot = null;

let resultsModule = baseResultsModule;
if (process.env.T1C_RESULTS_MODULE) {
  resultsModule = await import(
    `${pathToFileURL(path.resolve(process.env.T1C_RESULTS_MODULE)).href}?t1c_results=${Date.now()}`
  );
}
let rootOmissionVerifier = resultsModule.verifyTimelineNoGameRootOmission;
let readEmergencyArtifactGenerations = baseReadEmergencyArtifactGenerations;
let rootPresentChatVerifier = resultsModule.verifyTimelineNoGameRootPresentChatGate;
let finalityVerifier = resultsModule.verifyTimelineNoGameFinality;
let missingRootRouter = resultsModule.routeMissingRootInStageC;
let evidenceEmptyChecker = resultsModule.checkTimelineNoGameEvidenceEmpty;
let resultsRunner = resultsModule.run;
if (MUTATION) {
  if (![
    'bypass-finality', 'ignore-chat-evidence', 'null-game-groups', 'reject-chat-absence',
    'u4-trust-unsigned-emergency', 'p8b-unknown-live-existence', 'p8b-known-presence-drop',
    'm11a-trust-invalid-signature', 'm11a-skip-archive-shape',
    'm11a-skip-declared-sha', 'm11a-scan-unknown-group',
    'm11a-reader-declared', 'm11a-reader-stat', 'm11a-reader-depth', 'm11a-reader-page',
    'm11a-live-slice', 'm11a-note-dedupe',
  ].includes(MUTATION)) {
    throw new Error(`unknown mutation: ${MUTATION}`);
  }
  // 実ファイルは変えず、tmp/M11a 内へ results.js だけを変異したモジュール木を作る。
  // その他の src/vendor は実物へのsymlinkなので、読み先を本番と揃えた歯の確認になる。
  const verifierRoot = path.resolve(import.meta.dirname, '..');
  mutationRoot = path.resolve(verifierRoot, `../tmp/M11a/v25-${MUTATION}-${process.pid}`);
  await fs.rm(mutationRoot, { recursive: true, force: true });
  await fs.mkdir(path.join(mutationRoot, 'src/stages'), { recursive: true });
  await fs.writeFile(path.join(mutationRoot, 'package.json'), '{"type":"module"}\n');
  for (const entry of await fs.readdir(path.join(verifierRoot, 'src'), { withFileTypes: true })) {
    if (entry.name === 'stages' || entry.name === 'emergency.js') continue;
    await fs.symlink(path.join(verifierRoot, 'src', entry.name), path.join(mutationRoot, 'src', entry.name));
  }
  for (const entry of await fs.readdir(path.join(verifierRoot, 'src/stages'), { withFileTypes: true })) {
    if (entry.name === 'results.js') continue;
    await fs.symlink(path.join(verifierRoot, 'src/stages', entry.name), path.join(mutationRoot, 'src/stages', entry.name));
  }
  await fs.symlink(path.join(verifierRoot, 'vendor'), path.join(mutationRoot, 'vendor'));
  await fs.symlink(path.resolve(verifierRoot, '../Hardhat'),
    path.resolve(mutationRoot, '../Hardhat')).catch((error) => {
    if (error.code !== 'EEXIST') throw error;
  });
  const original = await fs.readFile(path.join(verifierRoot, 'src/stages/results.js'), 'utf8');
  const originalEmergency = await fs.readFile(path.join(verifierRoot, 'src/emergency.js'), 'utf8');
  let mutated = original;
  let mutatedEmergency = originalEmergency;
  if (MUTATION === 'bypass-finality') {
    mutated = mutated.replace(
      'const schemaOk = await verifyTimelineNoGameFinality(ctx, S);',
      'const schemaOk = true; S.timelineNoGameCanonical = { authoritative: { resultCloseAt: 900, resultCount: 0 } };',
    );
  } else if (MUTATION === 'ignore-chat-evidence') {
    mutated = mutated.replace(
      'const chatNotStarted = chatArtifacts.gameGroupsValid\n'
        + '    && chatArtifacts.evidenceKeys.length === 0\n'
        + '    && chatArtifacts.inspectionErrors.length === 0;',
      'const chatNotStarted = chatArtifacts.gameGroupsValid;',
    );
  } else if (MUTATION === 'reject-chat-absence') {
    mutated = mutated.replace(
      'const chatNotStarted = chatArtifacts.gameGroupsValid\n'
        + '    && chatArtifacts.evidenceKeys.length === 0\n'
        + '    && chatArtifacts.inspectionErrors.length === 0;',
      'const chatNotStarted = false && chatArtifacts.gameGroupsValid\n'
        + '    && chatArtifacts.evidenceKeys.length === 0\n'
        + '    && chatArtifacts.inspectionErrors.length === 0;',
    );
  } else if (MUTATION === 'u4-trust-unsigned-emergency') {
    mutated = mutated.replace(
      'else if (timelineNoGameLiveSnapshotShowsStarted({ data: generation.data }) === true) {',
      'else if (timelineNoGameLiveSnapshotShowsStarted({ data: generation.data }) === true) {\n'
        + '            evidenceKeys.add(`${key} mutant-unsigned-fields`);',
    );
  } else if (MUTATION === 'null-game-groups') {
    mutated = mutated.replace('gameGroups: gameGroupsResponse,', 'gameGroups: null,');
  } else if (MUTATION === 'p8b-unknown-live-existence') {
    mutated = mutated.replace(
      '  const evidenceKeys = new Set();',
      "  const evidenceKeys = new Set();\n  if (!knownGroups && indexedKeys.some((key) => key.startsWith(`live/block${N}/group`))) evidenceKeys.add('mutant-index-only');",
    );
  } else if (MUTATION === 'p8b-known-presence-drop') {
    mutated = mutated.replace(
      '  const evidenceKeys = new Set();',
      "  const evidenceKeys = new Set();\n  if (knownGroups && keys.some((key) => key.startsWith(`games/block${N}/group`))) evidenceKeys.add('mutant-index-only');",
    );
  } else if (MUTATION === 'm11a-trust-invalid-signature') {
    mutated = mutated.replace(
      'if (await verifyMessage({\n        address: bAddr.address,',
      'if (true || await verifyMessage({\n        address: bAddr.address,',
    );
  } else if (MUTATION === 'm11a-skip-archive-shape') {
    mutated = mutated.replace('if (shapeValid && typeof declared === \'string\'',
      'if (typeof declared === \'string\'');
  } else if (MUTATION === 'm11a-skip-declared-sha') {
    mutated = mutated.replace(
      "&& declared.replace(/^0x/i, '').toLowerCase() === String(generation.row.sha256).toLowerCase()) {",
      '&& true) {',
    );
  } else if (MUTATION === 'm11a-scan-unknown-group') {
    mutated = mutated.replace('  const keys = knownGroups ? groupIds.flatMap((groupId) => [',
      '  const keys = false ? groupIds.flatMap((groupId) => [');
  } else if (MUTATION === 'm11a-live-slice') {
    mutated = mutated.replace('snapshot.messages.slice(0, 1_000)',
      'snapshot.messages.slice(0, 1_001)');
  } else if (MUTATION === 'm11a-note-dedupe') {
    mutated = mutated.replace(
      'if (prior) { prior.rebuilt.ignoredGenerations++; return; }',
      'if (prior) { prior.rebuilt.ignoredGenerations++; }',
    );
  } else if (MUTATION === 'm11a-reader-declared') {
    mutatedEmergency = mutatedEmergency.replace(
      'if (Number.isSafeInteger(Number(row.bytes)) && Number(row.bytes) > byteLimit) {',
      'if (false) {',
    );
  } else if (MUTATION === 'm11a-reader-stat') {
    mutatedEmergency = mutatedEmergency.replace('if (stat.size > byteLimit) {', 'if (false && stat.size > byteLimit) {');
  } else if (MUTATION === 'm11a-reader-depth') {
    mutatedEmergency = mutatedEmergency.replace(
      'if (bytes.length > byteLimit || !jsonDepthWithinLimit(bytes, GCP_JSON_DEPTH_LIMIT)) {',
      'if (bytes.length > byteLimit) {',
    );
  } else if (MUTATION === 'm11a-reader-page') {
    mutatedEmergency = mutatedEmergency.replace('const generationLimit = 16;', 'const generationLimit = 17;');
  }
  if (mutated === original && mutatedEmergency === originalEmergency) {
    throw new Error(`${MUTATION} mutation was not applied`);
  }
  await fs.writeFile(path.join(mutationRoot, 'src/stages/results.js'), mutated);
  await fs.writeFile(path.join(mutationRoot, 'src/emergency.js'), mutatedEmergency);
  resultsModule = await import(
    `${pathToFileURL(path.join(mutationRoot, 'src/stages/results.js')).href}?mutation=${Date.now()}`
  );
  const emergencyModule = await import(
    `${pathToFileURL(path.join(mutationRoot, 'src/emergency.js')).href}?mutation=${Date.now()}`
  );
  readEmergencyArtifactGenerations = emergencyModule.readEmergencyArtifactGenerations;
  rootOmissionVerifier = resultsModule.verifyTimelineNoGameRootOmission;
  rootPresentChatVerifier = resultsModule.verifyTimelineNoGameRootPresentChatGate;
  finalityVerifier = resultsModule.verifyTimelineNoGameFinality;
  missingRootRouter = resultsModule.routeMissingRootInStageC;
  evidenceEmptyChecker = resultsModule.checkTimelineNoGameEvidenceEmpty;
  resultsRunner = resultsModule.run;
}

function makePublished(overrides = {}) {
  const noGameFinality = {
    schemaVersion: 1,
    evidenceContract: EVIDENCE,
    safeBlockNumber: '100',
    safeTimestamp: 1_000,
    resultOpenAt: 800,
    resultCloseAt: 900,
    resultCount: 0,
    ...(overrides.noGameFinality || {}),
  };
  return {
    schemaVersion: 2,
    blockNum: N,
    blockReward: getBlockRewardWei(N).toString(),
    totalPlayers: 3,
    totalGroups: 0,
    noGame: true,
    majorLangs: [],
    groups: [],
    claimStatusKey: 'games/block0/claim-status.json',
    noGameReason: 'timeline_unverified',
    noGameCause: 'chain_unreadable',
    noGameFinality,
    ...overrides,
    noGameFinality,
  };
}

async function runCase({
  published = makePublished(), resultCount = 0, latest = 200n, emergencyMode = false,
} = {}) {
  const checks = [];
  const report = { check: (id, status, details) => checks.push({ id, status, details }) };
  const ctx = {
    blockNum: N,
    cfg: { pins: { confirmationBlocks: 64 } },
    data: {
      gameSelection: { players: [{}, {}, {}] },
      ...(emergencyMode ? {
        emergencySource: { kind: 'p5-unit' },
        emergencyServerSubmissions: {},
        emergencyDifferences: [],
      } : {}),
    },
    report,
    ui: { println() {}, t: (id) => id },
    chain: {
      latest: async () => ({ number: latest }),
      findBlockByTimestamp: async () => 90,
      getBlock: async (number) => ({ number, timestamp: 1_000n }),
      resultWindow: async () => ({ openAt: 800n, closeAt: 900n }),
      chatWindow: async () => ({ chatOpenAt: 500n, chatCloseAt: 700n }),
      resultCount: async () => BigInt(resultCount),
      evidenceAddress: async () => EVIDENCE,
      ethLockAddress: async () => ETH_LOCK, // R26-C4
    },
  };
  const S = {
    files: { summary: { data: published, raw: JSON.stringify(published) }, gameGroups: null },
    anomalies: [],
  };
  const ok = await finalityVerifier(ctx, S);
  return { ok, checks, S, ctx };
}

async function runRootlessCase({
  published = makePublished(),
  resultCount = 0,
  latestNumber = 200n,
  nowSec = ROOT_DEADLINE + 1,
  selectedPlayers = 3,
  safeTimestamp = 1_000n,
  gameGroups = null,
  groupResult = false,
  liveSubmissions = false,
  liveSnapshot = null,
  roster = false,
} = {}) {
  const report = createReport();
  const ctx = {
    blockNum: N,
    cfg: { pins: { confirmationBlocks: 64 } },
    data: {
      gameSelection: { players: Array.from({ length: selectedPlayers }, () => ({})) },
    },
    report,
    ui: { println() {}, t: (id) => id },
    r2: {
      fetchJson: async (key) => {
        if (key === `games/block${N}/summary.json`) {
          return { data: published, raw: JSON.stringify(published) };
        }
        if (key === `entries/block${N}/game_groups.json`) {
          return gameGroups ? { data: gameGroups, raw: JSON.stringify(gameGroups) } : null;
        }
        if (key === `games/block${N}/group0.json` && groupResult) {
          return { data: { group_id: 0, status: 'completed' }, raw: '{"group_id":0,"status":"completed"}' };
        }
        if (key === `live/block${N}/group0.submissions.json` && liveSubmissions) {
          return { data: { groupId: 0, submissions: [] }, raw: '{"groupId":0,"submissions":[]}' };
        }
        if (key === `live/block${N}/group0.json` && liveSnapshot) {
          return { data: liveSnapshot, raw: JSON.stringify(liveSnapshot) };
        }
        if (key === `games/block${N}/roster/group0.json` && roster) {
          return { data: { blockNum: N, groupId: 0, members: ['a', 'b', 'c'] } };
        }
        return null;
      },
    },
    chain: {
      latest: async () => ({ number: latestNumber, timestamp: BigInt(nowSec) }),
      findBlockByTimestamp: async () => 90,
      getBlock: async (number) => ({ number, timestamp: safeTimestamp }),
      resultWindow: async () => ({ openAt: 800n, closeAt: 900n }),
      resultCount: async () => BigInt(resultCount),
      evidenceAddress: async () => EVIDENCE,
      verificationPeriod: async () => VERIFICATION_PERIOD_SEC,
    },
  };
  const S = {
    timelineNoGame: true,
    anomalies: [],
    zkInfo: { currentProofRequired: true },
  };
  const result = await rootOmissionVerifier(ctx, S);
  const category = categorize({ fatal: false, report, stopped: result.stop });
  const exitCode = { full: 0, partial: 1, fail: 2, fatal: 3 }[category];
  return { result, report, category, exitCode };
}

async function runStageCRootlessMode(emergencyMode) {
  const published = makePublished();
  const report = createReport();
  const fetchedKeys = [];
  const ctx = {
    blockNum: N,
    cfg: { pins: { confirmationBlocks: 64 }, contracts: { ethLock: ETH_LOCK } },
    data: {
      timelineNoGame: true,
      gameSelection: { players: [{}, {}, {}] },
      zkInfo: {
        kind: 'no_root', currentProofRequired: false,
        blockState: { root: ZERO_ROOT, verificationStartedAt: 0, zkEpochPlusOne: 0, proofAttachedAt: 0 },
      },
      ...(emergencyMode ? {
        emergencySource: { sourceDir: '/unused', index: { objects: {} } },
        emergencyDifferences: [], emergencyServerSubmissions: {}, groupsDerived: [],
      } : {}),
    },
    report,
    ui: { println() {}, warn() {}, t: (id) => id },
    r2: {
      async fetchJson(key) {
        fetchedKeys.push(key);
        if (key === `games/block${N}/summary.json`) {
          return { data: published, raw: JSON.stringify(published) };
        }
        if (key === `entries/block${N}/game_groups.json`) return null;
        return null;
      },
      async list() { return []; },
      releaseRaw() {},
    },
    chain: {
      latest: async () => ({ number: 200n, timestamp: BigInt(ROOT_DEADLINE + 1) }),
      findBlockByTimestamp: async () => 90,
      getBlock: async (number) => ({ number, timestamp: 1_000n }),
      resultWindow: async () => ({ openAt: 800n, closeAt: 900n }),
      chatWindow: async () => ({ chatOpenAt: 500n, chatCloseAt: 700n }),
      resultCount: async () => 0n,
      evidenceAddress: async () => EVIDENCE,
      ethLockAddress: async () => ETH_LOCK,
      verificationPeriod: async () => VERIFICATION_PERIOD_SEC,
      getTimingConstants: async () => ({
        startTimeEntryMs: 0, blockTimeMs: 3_600_000,
        gamePeriodMs: 1_800_000, submitPeriodMs: 600_000, invariantOk: true,
      }),
    },
  };
  const result = await resultsRunner(ctx);
  const category = categorize({ fatal: false, report, stopped: result.stop });
  return {
    result, report, fetchedKeys, category,
    exitCode: { full: 0, partial: 1, fail: 2, fatal: 3 }[category],
  };
}

async function runRootPresentChatCheck({
  gameGroups = VALID_GAME_GROUPS,
  groupResult = false,
  liveSubmissions = false,
  liveSnapshot = null,
  emergencySource = null,
  emergencySubmissionCandidates = [],
  emergencyGroupsDerived = [{ groupId: 0 }],
  emergencySelectionPlayers = [],
  manifestFiles = null,
} = {}) {
  const report = createReport();
  const emergencyManifest = manifestFiles
    ? { blockNum: N, algorithm: 'sha256', rules: {}, files: manifestFiles } : null;
  const ctx = {
    blockNum: N,
    data: {
      reuseFiles: false,
      zkInfo: { blockState: { root: `0x${'ab'.repeat(32)}` } },
      ...(emergencySource ? {
        emergencySource,
        emergencySubmissionCandidates,
        groupsDerived: emergencyGroupsDerived,
        gameSelection: { players: emergencySelectionPlayers },
      } : {}),
    },
    report,
    r2: {
      fetchJson: async (key) => {
        if (key === `games/block${N}/group0.json` && groupResult) {
          return { data: { group_id: 0, status: 'completed' }, raw: '{"group_id":0,"status":"completed"}' };
        }
        if (key === `live/block${N}/group0.submissions.json` && liveSubmissions) {
          return { data: { groupId: 0, submissionsRaw: {} }, raw: '{"groupId":0,"submissionsRaw":{}}' };
        }
        if (key === `live/block${N}/group0.json` && liveSnapshot) {
          return { data: liveSnapshot, raw: JSON.stringify(liveSnapshot) };
        }
        return null;
      },
    },
  };
  const S = {
    files: {
      gameGroups: gameGroups ? { data: gameGroups, raw: JSON.stringify(gameGroups) } : null,
      ...(emergencyManifest ? { manifest: { data: emergencyManifest } } : {}),
    },
  };
  const result = await rootPresentChatVerifier(ctx, S);
  return { result, report, ctx };
}

const VALID_GAME_GROUPS = {
  totalGroups: 1,
  groups: [{ groupId: 0, memberIds: ['a', 'b', 'c'] }],
};

async function runTimelineGroupingMismatch() {
  const players = [0, 1, 2].map((index) => ({
    globalIndex: index,
    data: { uid: `u${index}`, lang: ['ja', 'en', 'fr'][index] },
  }));
  const selection = {
    blockNum: N,
    randao: `0x${'31'.repeat(32)}`,
    applicantHash: `0x${'32'.repeat(32)}`,
    players,
  };
  const groupSeed = keccak256(concatHex([
    selection.randao,
    selection.applicantHash,
    stringToHex('group'),
  ]));
  const gm = new GameMasterDO({ storage: {} }, {});
  const groups = await gm.formGroups(players, groupSeed, []);
  const gameGroups = gm.createGroupSummary(N, groups, selection);
  gameGroups.groups[0].memberIds = ['not', 'the', 'selection'];
  const report = createReport();
  const result = await runGrouping({
    blockNum: N,
    data: { gameSelection: selection, players },
    report,
    ui: { println() {}, t: (id) => id },
    r2: {
      fetchJson: async (key) => {
        if (key === `games/block${N}/summary.json`) {
          const summary = makePublished();
          return { data: summary, raw: JSON.stringify(summary) };
        }
        if (key === `entries/block${N}/game_groups.json`) {
          return { data: gameGroups, raw: JSON.stringify(gameGroups) };
        }
        return null;
      },
    },
  });
  const category = categorize({ fatal: false, report, stopped: result.stop });
  return { report, category, exitCode: { full: 0, partial: 1, fail: 2, fatal: 3 }[category] };
}

async function materializePublishedTimelineNoGame() {
  const values = new Map();
  const storage = {
    get: async (key) => values.get(key),
    put: async (key, value) => values.set(key, value),
    delete: async (key) => values.delete(key),
    list: async ({ prefix } = {}) => new Map(
      [...values].filter(([key]) => !prefix || key.startsWith(prefix)),
    ),
    deleteAlarm: async () => {},
  };
  const rows = [{ block_num: N, group_id: 0, status: 'waiting' }];
  const db = {
    prepare(sql) {
      const normalized = sql.replace(/\s+/g, ' ').trim();
      return {
        bind(...args) {
          return {
            async all() {
              if (normalized.includes('GROUP BY status')) {
                const counts = new Map();
                for (const row of rows) counts.set(row.status, (counts.get(row.status) || 0) + 1);
                return { results: [...counts].map(([status, cnt]) => ({ status, cnt })) };
              }
              return { results: rows.map(({ group_id, status }) => ({ group_id, status })) };
            },
            async run() {
              if (normalized.startsWith('UPDATE game_groups SET status = ?')) {
                for (const row of rows) {
                  row.status = args[0];
                  row.completed_at = args[1];
                }
              }
              return { success: true };
            },
          };
        },
      };
    },
  };
  const resetIds = [];
  const gm = Object.create(GameMasterDO.prototype);
  gm.storage = storage;
  gm.state = { storage };
  gm.env = {
    EVIDENCE_CONTRACT_ADDRESS: EVIDENCE,
    BITCOINU_DATA: db,
    CHAT_GAME_DO: {
      idFromName: (name) => name,
      get: (id) => ({ fetch: async () => {
        resetIds.push(id);
        return new Response('{}', { status: 200 });
      } }),
    },
  };
  const published = new Map();
  gm.renewGroupingLease = async () => {};
  gm.getR2Text = async (key) => published.has(key) ? JSON.stringify(published.get(key)) : null;
  gm.putR2ObjectOrThrow = async (key, value) => { published.set(key, structuredClone(value)); return true; };
  gm.publishInitialClaimStatus = async () => {};
  gm.publishMerkleTree = async () => ({ ok: true, root: SENTINEL_ROOT, leafCount: 0 });
  gm.publishVerificationManifest = async () => ({ ok: true });
  gm.clearVerificationPublishFailure = async () => {};
  gm.finalizePublishedRootWithPipeline = async () => ({ ok: true });
  await gm.finalizeNoGameBlock(N, {
    reason: 'timeline_unverified', cause: 'chain_unreadable', totalPlayers: 3,
    chainFinality: {
      evidenceContract: EVIDENCE,
      safeBlockNumber: '100', safeTimestamp: 1_000,
      resultOpenAt: 800, resultCloseAt: 900, resultCount: 0,
      chatOpenAt: 500, chatCloseAt: 700, confirmations: 64,
    },
  });
  return {
    summary: published.get(`games/block${N}/summary.json`),
    cleanup: await storage.get(`timeline_no_game_cleanup_block${N}`),
    rows,
    resetIds,
  };
}

let passed = 0;
let failed = 0;
function check(name, condition, detail = '') {
  if (condition) { passed++; console.log(`  ok: ${name}`); }
  else { failed++; console.error(`  FAIL: ${name}${detail ? ` — ${detail}` : ''}`); }
}

// ------------------------------------------------------------------
// T34/T4 §3: 前ブロックの照合が fail のとき、そこから導いた主要言語とグループ分けの結果に
// 「未検証の前ブロック入力から導いた」印が付くこと。両方向（通る側・止まる側）を全数で測り、
// 印を足しても pass/fail と終了状態が1件も変わらないことを同じ入力で確かめる。
// 歯の確認用に、grouping.js だけを差し替えたモジュール木を T34_GROUPING_MODULE で指せる。
// ------------------------------------------------------------------
let groupingRunner = runGrouping;
if (process.env.T34_GROUPING_MODULE) {
  ({ run: groupingRunner } = await import(
    `${pathToFileURL(path.resolve(process.env.T34_GROUPING_MODULE)).href}?t34_grouping=${Date.now()}`
  ));
}

// 便 W4（2026-09-20）: 引数を増やした。既定は従来どおり「block1・前ブロックの目印は1回きり・通常モード」。
//   blockNum   … 検証対象ブロック（0 を渡すと「前ブロックが無い」枝）
//   regCount   … ctx.chain.resultRegistrationCount(prev) の返す回数。
//                'throws' = 読取が失敗する / 'missing' = 読み手そのものが無い
//   emergency  … ctx.data.emergencySource を置いて緊急モードにする
async function runPrevAnchorGrouping({
  anchorMatches = true, blockNum = 1, regCount = 1, emergency = false,
  // 周29 (c)（2026-09-22）: 前ブロックの目印が追記履歴のどの行かを報告へ残す部分の入力。
  // 既定は履歴 getter の無い読み手（従来の chain スタブと同じ）。
  resultHistory = null,
  historyForGrouping = null,
  emergencySelected = null,
} = {}) {
  const N1 = blockNum;
  const prev = N1 - 1;
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
    globalIndex: index,
    data: { uid: `u${index}`, lang: ['ja', 'en', 'fr'][index] },
  }));
  const selection = {
    blockNum: N1,
    randao: `0x${'41'.repeat(32)}`,
    applicantHash: `0x${'42'.repeat(32)}`,
    players,
  };
  const groupSeed = keccak256(concatHex([
    selection.randao, selection.applicantHash, stringToHex('group'),
  ]));
  const gm = new GameMasterDO({ storage: {} }, {});
  const groups = await gm.formGroups(players, groupSeed, []);
  const gameGroups = gm.createGroupSummary(N1, groups, selection);
  const summary = {
    schemaVersion: 2,
    blockNum: N1,
    groups: groups.map((group) => ({
      group_id: group.groupId,
      members: group.members.map((member) => ({ userId: member.data.uid })),
    })),
  };

  const lines = [];
  const report = createReport();
  const jsonRes = (value, raw) => ({ data: value, raw: raw ?? JSON.stringify(value) });
  const r2 = {
    fetchJson: async (key) => {
      if (key === `games/block${N1}/summary.json`) return jsonRes(summary);
      if (key === `entries/block${N1}/game_groups.json`) return jsonRes(gameGroups);
      if (prev >= 0 && key === `games/block${prev}/summary.json`) return jsonRes(prevSummary, prevSummaryRaw);
      if (prev >= 0 && key === `verification/block${prev}/manifest.json`) return jsonRes(prevManifest, prevManifestRaw);
      return null;
    },
  };
  const chain = {
    getResultHash: async () => ({
      hash: anchorMatches ? prevCore : `0x${'ee'.repeat(32)}`,
      updated: historyForGrouping?.at(-1)?.registeredBlock ?? 1,
      signer: `0x${'ab'.repeat(20)}`,
    }),
  };
  if (regCount !== 'missing') {
    chain.resultRegistrationCount = async () => {
      if (regCount === 'throws') throw new Error('RPC unavailable');
      return regCount;
    };
  }
  if (resultHistory) {
    chain.resultRegistrationHistory = async () => {
      if (resultHistory === 'throws') throw new Error('history unavailable');
      return resultHistory;
    };
  }
  if (historyForGrouping) {
    const rows = historyForGrouping.map((row) => ({ ...row,
      hash: row.hash === 'published' ? prevCore : row.hash }));
    chain.getTimingConstants = async () => ({ startTimeEntryMs: 0,
      blockTimeMs: 1000, gamePeriodMs: 1000 });
    chain.currentGrace = async () => 148;
    chain.resultRegistrationCount = async () => rows.length;
    chain.resultRegistrationAt = async (_block, index) => rows[index];
  }
  const ctx = {
    blockNum: N1,
    data: {
      gameSelection: selection,
      players,
      ...(emergency
        ? { emergencySource: { sourceDir: '/unused', index: { objects: {} },
          ...(emergencySelected ? { previousResultRegistration: emergencySelected } : {}) },
          emergencyDifferences: [] }
        : {}),
    },
    report,
    ui: { println: (s = '') => lines.push(String(s)), t: (id) => id },
    r2,
    chain,
  };
  const result = await groupingRunner(ctx);
  const category = categorize({ fatal: false, report, stopped: result.stop });
  return {
    report, category, lines, ctx, stop: result.stop,
    checks: report.list().map((entry) => `${entry.id}=${entry.status}`),
    marker: lines.filter((line) => line.startsWith('##UNVERIFIED_PREV_INPUT')),
    fact: report.getFact('groupingPrevInputUnverified') ?? null,
    reregistration: report.get('check.stageB.prevResultReregistration'),
    markerRow: report.getFact('stageB.prevResultMarkerRow') ?? null,
    differences: ctx.data.emergencyDifferences ?? null,
  };
}

// P6 / R30-U-4: 通常 Stage B は、現在の N で組を再現できない場合だけ
// N+1 の公開 summary.majorLangs を試し、複数登録なら任意の observer-source で旧版を検証する。
const p6StageBRoot = path.resolve(
  import.meta.dirname, `../../tmp/M11a/v25-stage-b-${process.pid}`,
);
// R31-U-B/D: only the canonical pre-chat registration selects the manifest.
{
  const rawX = JSON.stringify({ blockNum: 0, generation: 'X' });
  const rawH = JSON.stringify({ blockNum: 0, generation: 'H' });
  const hashX = keccak256(stringToHex(rawX));
  const hashH = keccak256(stringToHex(rawH));
  const history = [
    { hash: hashH, registeredBlock: 10, registeredAt: 120 },
    { hash: hashX, registeredBlock: 11, registeredAt: 150 },
    { hash: hashH, registeredBlock: 12, registeredAt: 200 },
  ];
  const chain = { otherRegistrationCount: async () => history.length,
    otherRegistrationAt: async (_key, index) => history[index] };
  const inspected = await baseResultsModule.inspectRosterAnchor(chain, {
    blockNum: 0, raw: rawX, entryEndMs: 100_000, chattingStartMs: 200_000,
  });
  const rereg = baseResultsModule.rosterReregistrationCheck(inspected.registration);
  check('M9a: 開始前の最後Xを採り、Hからのやり直しをwarnで示す',
    inspected.failures.length === 0 && inspected.registration.index === 1
      && inspected.registration.lateCount === 1 && rereg.status === 'warn'
      && rereg.params.firstIndex === 0 && rereg.params.canonicalIndex === 1
      && rereg.params.firstHash === hashH && rereg.params.canonicalHash === hashX);
  history.splice(0, history.length, { hash: hashX, registeredBlock: 10, registeredAt: 120 },
    { hash: hashH, registeredBlock: 11, registeredAt: 150 },
    { hash: hashX, registeredBlock: 12, registeredAt: 200 });
  const changed = await baseResultsModule.inspectRosterAnchor(chain, {
    blockNum: 0, raw: rawH, entryEndMs: 100_000, chattingStartMs: 200_000,
  });
  check('M9a: Xの後HならHを正典とし、開始ちょうどの上書きを無視する',
    changed.failures.length === 0 && changed.registration.index === 1
      && changed.registration.lateCount === 1
      && baseResultsModule.rosterReregistrationCheck(changed.registration).status === 'warn');
  history.splice(0, history.length, { hash: hashH, registeredBlock: 11, registeredAt: 150 },
    { hash: hashX, registeredBlock: 12, registeredAt: 200 });
  const lateOnly = await baseResultsModule.inspectRosterAnchor(chain, {
    blockNum: 0, raw: rawH, entryEndMs: 100_000, chattingStartMs: 200_000,
  });
  check('M9a: 開始以後だけの上書きはfailも再登録warnも出さない',
    lateOnly.failures.length === 0 && lateOnly.registration.lateCount === 1
      && baseResultsModule.rosterReregistrationCheck(lateOnly.registration).status === 'pass');
}

await fs.rm(p6StageBRoot, { recursive: true, force: true });
if (mutationRoot) await fs.rm(mutationRoot, { recursive: true, force: true });
await fs.mkdir(p6StageBRoot, { recursive: true });
const p6Digest = (text) => createHash('sha256').update(text).digest('hex');
async function p6Write(relative, value) {
  const raw = typeof value === 'string' ? value : JSON.stringify(value);
  const file = path.join(p6StageBRoot, relative);
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, raw);
  return { savedFile: relative, sha256: p6Digest(raw), observedAt: '2026-09-23T00:00:00.000Z' };
}
const p6N = 1;
const p6Prev = 0;
const p6OldPrevSummary = {
  schemaVersion: 2,
  blockNum: p6Prev,
  majorLangs: ['ja'],
  groups: [{
    group_id: 0,
    status: 'completed',
    members: Array.from({ length: 200 }, (_, index) => ({
      userId: `p6-prev-${index}`, lang: 'ja', is_disqualified: 0,
    })),
  }],
};
const p6NewPrevSummary = {
  schemaVersion: 2, blockNum: p6Prev, noGame: true, majorLangs: [], groups: [], totalGroups: 0,
};
const p6ThirdPrevSummary = { schemaVersion: 2, blockNum: p6Prev, majorLangs: ['en'],
  groups: [{ group_id: 0, status: 'completed', members: Array.from({ length: 200 }, (_, index) => ({
    userId: `p6-third-${index}`, lang: 'en', is_disqualified: 0,
  })) }] };
const p6OldPrevRaw = JSON.stringify(p6OldPrevSummary);
const p6NewPrevRaw = JSON.stringify(p6NewPrevSummary);
const p6ThirdPrevRaw = JSON.stringify(p6ThirdPrevSummary);
const p6PrevSummaryKey = `games/block${p6Prev}/summary.json`;
const p6PrevManifestKey = `verification/block${p6Prev}/manifest.json`;
const p6OldPrevManifest = {
  blockNum: p6Prev,
  algorithm: 'keccak256-merkle',
  rules: { minChars: 500 },
  files: { [p6PrevSummaryKey]: sha256HexOfString(p6OldPrevRaw) },
};
const p6NewPrevManifest = {
  blockNum: p6Prev,
  algorithm: 'keccak256-merkle',
  rules: { minChars: 500 },
  files: { [p6PrevSummaryKey]: sha256HexOfString(p6NewPrevRaw) },
};
const p6ThirdPrevManifest = { ...p6OldPrevManifest,
  files: { [p6PrevSummaryKey]: sha256HexOfString(p6ThirdPrevRaw) } };
const p6SameMajorPrevManifest = { ...p6OldPrevManifest, rules: { minChars: 500, variant: 2 } };
const p6CoreOf = (manifest) => `0x${sha256HexOfString(JSON.stringify({
  blockNum: manifest.blockNum,
  algorithm: manifest.algorithm,
  rules: manifest.rules,
  files: manifest.files,
}))}`;
const p6OldPrevCore = p6CoreOf(p6OldPrevManifest);
const p6NewPrevCore = p6CoreOf(p6NewPrevManifest);
const p6ThirdPrevCore = p6CoreOf(p6ThirdPrevManifest);
const p6SameMajorPrevCore = p6CoreOf(p6SameMajorPrevManifest);
const p6OldPrevSummaryRow = await p6Write('old-summary.bin', p6OldPrevRaw);
const p6NewPrevSummaryRow = await p6Write('new-summary.bin', p6NewPrevRaw);
const p6OldPrevManifestRow = await p6Write('old-manifest.bin', p6OldPrevManifest);
const p6NewPrevManifestRow = await p6Write('new-manifest.bin', p6NewPrevManifest);
const p6ThirdPrevSummaryRow = await p6Write('third-summary.bin', p6ThirdPrevRaw);
const p6ThirdPrevManifestRow = await p6Write('third-manifest.bin', p6ThirdPrevManifest);
const p6SavedRosterRaw = JSON.stringify({ blockNum: p6N, testRoster: 'saved' });
const p6SavedRosterRow = await p6Write('saved-roster.bin', p6SavedRosterRaw);
const p6SavedRosterHash = keccak256(stringToHex(p6SavedRosterRaw));
const p6ObserverIndex = {
  schemaVersion: 1,
  kind: 'r2-backup-observer-block-archive',
  blockNum: p6N,
  sourceRunId: 'p6-v25',
  complete: true,
  objects: {
    [p6PrevManifestKey]: [
      { ...p6OldPrevManifestRow, generation: 1, observationOrdinal: '00000001:00000000' },
      { ...p6NewPrevManifestRow, generation: 2, observationOrdinal: '00000002:00000000' },
      { ...p6ThirdPrevManifestRow, generation: 3, observationOrdinal: '00000003:00000000' },
    ],
    [p6PrevSummaryKey]: [
      { ...p6OldPrevSummaryRow, generation: 1, observationOrdinal: '00000001:00000001' },
      { ...p6NewPrevSummaryRow, generation: 2, observationOrdinal: '00000002:00000001' },
      { ...p6ThirdPrevSummaryRow, generation: 3, observationOrdinal: '00000003:00000001' },
    ],
  },
};
await fs.mkdir(path.join(p6StageBRoot, '_observer'), { recursive: true });
await fs.writeFile(
  path.join(p6StageBRoot, '_observer/generation-index.json'),
  JSON.stringify(p6ObserverIndex),
);
const p6History = [
  {
    index: 0, hash: p6OldPrevCore, registeredBlock: 10, registeredAt: 100,
    signer: `0x${'c1'.repeat(20)}`,
  },
  {
    index: 1, hash: p6NewPrevCore, registeredBlock: 20, registeredAt: 200,
    signer: `0x${'c2'.repeat(20)}`,
  },
];

async function runP6StageB({
  caseKey = null,
  observerSource = null,
  history = p6History,
  groupedWith = ['ja'],
  declaredMajorLangs = groupedWith,
  r2Prev = 'new',
  prevSummaryPresent = true,
  rosterAnchorAt = null,
  entryEndSec = 2,
  rosterFetchThrows = false,
  observerIndex = p6ObserverIndex,
  savedRosterAt = null,
  savedRosterMarkerHash = p6SavedRosterHash,
  emergencySource = null,
  resultLogs = null,
} = {}) {
  await fs.writeFile(path.join(p6StageBRoot, '_observer/generation-index.json'),
    JSON.stringify(observerIndex));
  const players = Array.from({ length: 10 }, (_, index) => ({
    globalIndex: index,
    data: { uid: `p6-u${index}`, lang: index === 9 ? 'en' : 'ja',
      addr: `0x${(index + 1).toString(16).padStart(40, '0')}` },
  }));
  const selection = {
    blockNum: p6N,
    randao: `0x${'71'.repeat(32)}`,
    applicantHash: `0x${'72'.repeat(32)}`,
    players,
  };
  const groupSeed = keccak256(concatHex([
    selection.randao, selection.applicantHash, stringToHex('group'),
  ]));
  const gm = new GameMasterDO({ storage: {} }, {});
  const groups = await gm.formGroups(players, groupSeed, groupedWith);
  const gameGroups = gm.createGroupSummary(p6N, groups, selection);
  const summary = {
    schemaVersion: 2,
    blockNum: p6N,
    majorLangs: declaredMajorLangs,
    groups: groups.map((group) => ({
      group_id: group.groupId,
      members: group.members.map((member) => ({ userId: member.data.uid })),
    })),
  };
  const report = createReport();
  const lines = [];
  const jsonRes = (data, raw = JSON.stringify(data)) => ({ data, raw });
  const rosterPayloads = baseResultsModule.reconstructCanonicalRosterPayloads(p6N, groups);
  const rosterRaw = rosterPayloads.manifestText;
  const rosterManifest = JSON.parse(rosterRaw);
  const rosterC = buildRosterMemberCommitment({ blockNum: p6N,
    manifestText: rosterRaw, groupTexts: rosterPayloads.groupTexts }).C;
  const rosterRows = [
    ...(rosterAnchorAt == null ? [] : [{ hash: rosterC,
      registeredBlock: 12, registeredAt: rosterAnchorAt }]),
    ...(savedRosterAt == null ? [] : [{ hash: savedRosterMarkerHash,
      registeredBlock: 13, registeredAt: savedRosterAt }]),
  ].sort((a, b) => a.registeredAt - b.registeredAt);
  const previous = r2Prev === 'old'
    ? { summary: p6OldPrevSummary, raw: p6OldPrevRaw, manifest: p6OldPrevManifest }
    : r2Prev === 'same'
      ? { summary: p6OldPrevSummary, raw: p6OldPrevRaw, manifest: p6SameMajorPrevManifest }
    : r2Prev === 'third'
      ? { summary: p6ThirdPrevSummary, raw: p6ThirdPrevRaw, manifest: p6ThirdPrevManifest }
      : { summary: p6NewPrevSummary, raw: p6NewPrevRaw, manifest: p6NewPrevManifest };
  const ctx = {
    cfg: { observerSource },
    blockNum: p6N,
    data: { gameSelection: selection, players, reuseFiles: false,
      ...(emergencySource ? { emergencySource } : {}) },
    report,
    ui: { println: (line = '') => lines.push(String(line)), t: (id) => id },
    r2: {
      fetchJson: async (key) => {
        if (key === `games/block${p6N}/summary.json`) return jsonRes(summary);
        if (key === `entries/block${p6N}/game_groups.json`) return jsonRes(gameGroups);
        if (key === `games/block${p6N}/roster/manifest.json` && rosterAnchorAt != null) {
          if (rosterFetchThrows) throw new Error('roster fetch unavailable');
          return jsonRes(rosterManifest, rosterRaw);
        }
        if (key === p6PrevSummaryKey) return prevSummaryPresent
          ? jsonRes(previous.summary, previous.raw) : null;
        if (key === p6PrevManifestKey) {
          return jsonRes(previous.manifest, JSON.stringify(previous.manifest));
        }
        return null;
      },
    },
    chain: {
      getTimingConstants: async () => ({ startTimeEntryMs: (entryEndSec - 2) * 1000,
        blockTimeMs: 1000, gamePeriodMs: 1000 }),
      currentGrace: async () => 150 - entryEndSec, // chattingStart=150s
      otherRegistrationCount: async () => rosterRows.length,
      otherRegistrationAt: async (_key, index) => rosterRows[index],
      ...(rosterAnchorAt == null ? {} : { firstOtherRegistration: async () => ({
        hash: rosterC, registeredBlock: 12, registeredAt: rosterAnchorAt,
      }) }),
      ...(savedRosterAt == null ? {} : {
        getOtherHash: async () => ({ hash: savedRosterMarkerHash, updated: 12 }),
        firstMatchingOtherRegistration: async (_key, _earliestAt, expectedHash) => {
          const r2Hash = rosterC;
          if (expectedHash === r2Hash && rosterAnchorAt != null) return {
            hash: r2Hash, registeredBlock: 12, registeredAt: rosterAnchorAt, index: 0,
          };
          if (expectedHash === p6SavedRosterHash) return {
            hash: p6SavedRosterHash, registeredBlock: 13, registeredAt: savedRosterAt, index: 1,
          };
          return null;
        },
      }),
      getResultHash: async () => ({
        hash: history.at(-1)?.hash ?? p6NewPrevCore,
        updated: history.at(-1)?.registeredBlock ?? 20, signer: `0x${'c2'.repeat(20)}`,
      }),
      resultRegistrationCount: async () => history.length,
      resultRegistrationAt: async (_block, index) => history[index],
      resultRegistrationHistory: async () => ({ count: history.length, rows: history }),
      ...(resultLogs == null ? {} : { resultHashEvents: async () => resultLogs }),
    },
  };
  const result = await groupingRunner(ctx);
  const category = categorize({ fatal: false, report, stopped: result.stop });
  if (caseKey) console.log(`M1_PROBE ${JSON.stringify({ key: caseKey, category,
    prevAnchor: report.get('check.stageB.prevAnchor')?.status ?? null,
    majorLangs: report.get('check.stageB.majorLangs')?.status ?? null,
    groupsMatch: report.get('check.stageB.groupsMatch')?.status ?? null,
    stop: result.stop, hashLines: lines.filter((line) => line.startsWith('##')) })}`);
  return {
    ctx,
    report,
    result,
    lines,
    category,
    checks: report.list().map((entry) => `${entry.id}=${entry.status}`),
  };
}

// 直す前の grouping.js が同じ2入力で出していた判定（統括が tmp/T34 で実測して固定した値）。
// 印を足した後もこの2列から1件もずれないことを、この試験が pin する。
// 便 W4（2026-09-20）: prevAnchor の隣に check.stageB.prevResultReregistration が1本増えた。
// 既定の入力（目印の登録は1回きり）では pass で、他の8件の判定は1件も動かない。
const PREV_ANCHOR_CHECKS_VERIFIED = [
  'check.stageB.groupsPresent=pass', 'check.stageB.groupSeed=pass',
  'check.stageB.prevAnchor=pass', 'check.stageB.prevResultReregistration=pass',
  'check.stageB.majorLangs=pass',
  'check.stageB.groupCount=pass', 'check.stageB.groupsMatch=pass',
  'check.stageB.groupStats=pass', 'check.stageB.summaryStructure=pass',
];
const PREV_ANCHOR_CHECKS_UNVERIFIED = [
  'check.stageB.groupsPresent=pass', 'check.stageB.groupSeed=pass',
  'check.stageB.prevAnchor=fail', 'check.stageB.prevResultReregistration=pass',
  'check.stageB.majorLangs=pass',
  'check.stageB.groupCount=pass', 'check.stageB.groupsMatch=pass',
  'check.stageB.groupStats=pass', 'check.stageB.summaryStructure=pass',
];

{
  const okRun = await runPrevAnchorGrouping({ anchorMatches: true });
  check('T4 §3 通る側: 前ブロックの照合が通れば印は付かない',
    okRun.marker.length === 0 && okRun.fact === null && okRun.ctx.data.groupingPrevUnverified === undefined,
    JSON.stringify({ marker: okRun.marker, fact: okRun.fact }));
  check('T4 §3 通る側: 判定は prevAnchor=pass の全数一致・停止しない',
    JSON.stringify(okRun.checks) === JSON.stringify(PREV_ANCHOR_CHECKS_VERIFIED)
      && okRun.stop === false && okRun.category === 'full',
    JSON.stringify({ checks: okRun.checks, stop: okRun.stop, category: okRun.category }));

  const badRun = await runPrevAnchorGrouping({ anchorMatches: false });
  check('T4 §3 止まる側: 前ブロックの照合が落ちれば印が付く（主要言語とグループ分けの両方）',
    badRun.marker.length === 1
      && badRun.marker[0].includes('block=1 prev=0 where=majorLangsAndGrouping')
      && badRun.fact?.derivedFrom === 'unverified_previous_block_input'
      && badRun.fact?.groups === 1
      && Array.isArray(badRun.fact?.majorLangs)
      && badRun.fact.failures.some((reason) => reason.includes('manifest core sha256')),
    JSON.stringify({ marker: badRun.marker, fact: badRun.fact }));
  check('T4 §3 止まる側: 印を足しても判定と終了状態は前と同じ（prevAnchor=fail の1件だけが赤）',
    JSON.stringify(badRun.checks) === JSON.stringify(PREV_ANCHOR_CHECKS_UNVERIFIED)
      && badRun.stop === false && badRun.category === 'fail',
    JSON.stringify({ checks: badRun.checks, stop: badRun.stop, category: badRun.category }));
  check('M1 B-4-03: 承認外の改竄は起点の失敗文をfactと##行に保つ',
    badRun.report.get('check.stageB.prevAnchor')?.params?.failures
      === 'manifest core sha256 != getResultHash(0)'
      && badRun.fact?.failures?.[0] === 'manifest core sha256 != getResultHash(0)'
      && badRun.marker[0]?.includes('manifest core sha256 != getResultHash(0)'),
    JSON.stringify({ params: badRun.report.get('check.stageB.prevAnchor')?.params,
      fact: badRun.fact, marker: badRun.marker }));
  const d4History = [
    { index: 0, hash: 'published', registeredBlock: 1, registeredAt: 100,
      signer: `0x${'ab'.repeat(20)}` },
    { index: 1, hash: `0x${'ee'.repeat(32)}`, registeredBlock: 2, registeredAt: 120,
      signer: `0x${'ab'.repeat(20)}` },
  ];
  const d4 = await runPrevAnchorGrouping({ anchorMatches: false, regCount: 2,
    historyForGrouping: d4History });
  check('M1 D-4-04: 現在目印が組分け前なら古いmanifestの履歴例外を開かない',
    d4.report.get('check.stageB.prevAnchor')?.status === 'fail' && d4.category === 'fail',
    JSON.stringify({ checks: d4.checks, category: d4.category }));
  const d4Emergency = await runPrevAnchorGrouping({ anchorMatches: false, regCount: 2,
    historyForGrouping: d4History, emergency: true,
    emergencySelected: { selectedIndex: 1, hash: `0x${'ee'.repeat(32)}` } });
  check('M1 D-4-04: 緊急selectedIndexがあってもcore不一致ならfail',
    d4Emergency.report.get('check.stageB.prevAnchor')?.status === 'fail'
      && d4Emergency.category === 'fail',
    JSON.stringify({ checks: d4Emergency.checks, category: d4Emergency.category }));
  check('T4 §3 両方向: 印は検査を1件も増減させない（id 列が両方向で同一）',
    JSON.stringify(okRun.checks.map((entry) => entry.split('=')[0]))
      === JSON.stringify(badRun.checks.map((entry) => entry.split('=')[0]))
      && okRun.checks.every((entry) => !entry.includes('Unverified')),
    JSON.stringify({ ok: okRun.checks, bad: badRun.checks }));
}

{
  const cfgWithoutSource = loadConfig([]);
  const cfgWithSource = loadConfig(['--observer-source', 'tmp/P6/materialized-block']);
  const cfgWithEquals = loadConfig(['--observer-source=tmp/P6/materialized-block']);
  check('P6 --observer-source は任意で、省略時null・指定時cwd基準の絶対パスになる',
    cfgWithoutSource.observerSource === null
      && cfgWithSource.observerSource === path.resolve('tmp/P6/materialized-block')
      && cfgWithEquals.observerSource === cfgWithSource.observerSource,
    JSON.stringify({
      omitted: cfgWithoutSource.observerSource,
      spaced: cfgWithSource.observerSource,
      equals: cfgWithEquals.observerSource,
    }));

  const withObserver = await runP6StageB({ observerSource: p6StageBRoot });
  check('P6 通常/保存物あり: 旧版Nがsummary.majorLangsと実際の組を再現すればStage Bはpass',
    withObserver.report.get('check.stageB.majorLangs')?.status === 'pass'
      && withObserver.report.get('check.stageB.groupsMatch')?.status === 'pass'
      && withObserver.report.getFact('stageB.previousResultVersion')?.selectedIndex === 0
      && withObserver.report.getFact('stageB.previousResultVersion')?.currentIndex === 1
      && withObserver.category === 'full',
    JSON.stringify({
      checks: withObserver.checks,
      fact: withObserver.report.getFact('stageB.previousResultVersion'),
      category: withObserver.category,
    }));

  const withoutObserver = await runP6StageB({ caseKey: 'U4A' });
  check('P6 通常/保存物なし: 複数登録なら主要言語はwarnだが公開majorLangsで組は必ず検証する',
    withoutObserver.report.get('check.stageB.majorLangs')?.status === 'warn'
      && withoutObserver.report.get('check.stageB.groupsMatch')?.status === 'pass'
      && withoutObserver.lines.some((line) => (
        line.includes('--observer-source') && line.includes('registered again')
      ))
      && withoutObserver.category === 'full',
    JSON.stringify({
      checks: withoutObserver.checks,
      lines: withoutObserver.lines,
      category: withoutObserver.category,
    }));

  const unchangedWrong = await runP6StageB({ caseKey: 'NM-D', history: [p6History[1]] });
  check('P6b B5: 登録1行の誤申告は P6 前の検査列・fail を保つ',
    unchangedWrong.report.get('check.stageB.majorLangs')?.status === 'pass'
      && unchangedWrong.report.get('check.stageB.groupsMatch')?.status === 'fail'
      && unchangedWrong.report.get('check.stageB.groupCount')?.status === 'fail'
      && unchangedWrong.report.get('check.stageB.groupStats')?.status === 'fail'
      && unchangedWrong.report.get('check.stageB.summaryStructure')?.status === 'fail'
      && unchangedWrong.category === 'fail',
    JSON.stringify({ checks: unchangedWrong.checks, category: unchangedWrong.category }));

  const sameHashTwice = await runP6StageB({ caseKey: 'NM-E', history: [
    { ...p6History[1], index: 0, registeredAt: 100 }, { ...p6History[1], index: 1 },
  ] });
  check('P6b B1: 同じhashの2回登録は例外に入らずP6前のfailと検査列',
    JSON.stringify(sameHashTwice.checks.filter((s) => !s.includes('prevResultReregistration')))
      === JSON.stringify(unchangedWrong.checks.filter((s) => !s.includes('prevResultReregistration')))
      && sameHashTwice.category === 'fail' && sameHashTwice.result.stop === false,
    JSON.stringify({ checks: sameHashTwice.checks, category: sameHashTwice.category }));
  const sameHashWithObserver = await runP6StageB({
    history: [{ ...p6History[1], index: 0, registeredAt: 100 },
      { ...p6History[1], index: 1 }], observerSource: p6StageBRoot,
  });
  check('P6b B1: observer指定でも同hashの再登録は例外に入らない',
    JSON.stringify(sameHashWithObserver.checks) === JSON.stringify(sameHashTwice.checks)
      && sameHashWithObserver.category === 'fail',
    JSON.stringify({ checks: sameHashWithObserver.checks, category: sameHashWithObserver.category }));

  const changedBeforeGrouping = await runP6StageB({
    history: [{ ...p6History[0], registeredAt: 100 },
      { ...p6History[1], registeredAt: 120 }],
  });
  check('P6b: 異なるhashでも締切前の再登録なら従来のfail',
    changedBeforeGrouping.report.get('check.stageB.majorLangs')?.status === 'pass'
      && changedBeforeGrouping.report.get('check.stageB.groupsMatch')?.status === 'fail'
      && changedBeforeGrouping.category === 'fail',
    JSON.stringify({ checks: changedBeforeGrouping.checks, category: changedBeforeGrouping.category }));

  const changedDuringGrace = await runP6StageB({ rosterAnchorAt: 110,
    history: [{ ...p6History[0], registeredAt: 100 }, { ...p6History[1], registeredAt: 120 }],
  });
  check('P12a: 名簿錨の後かつchattingStart前の異hash再登録はU-4例外へ入る',
    changedDuringGrace.report.get('check.stageB.majorLangs')?.status === 'warn'
      && changedDuringGrace.report.get('check.stageB.groupsMatch')?.status === 'pass',
    JSON.stringify({ checks: changedDuringGrace.checks, category: changedDuringGrace.category }));

  const preRegisteredRoster = await runP6StageB({ rosterAnchorAt: 1,
    history: [{ ...p6History[0], registeredAt: 100 }, { ...p6History[1], registeredAt: 120 }],
  });
  check('P13: 応募終了前の名簿錨はU-4例外を開かず、組分け前の変更はfail',
    preRegisteredRoster.category === 'fail'
      && preRegisteredRoster.report.get('check.stageB.groupsMatch')?.status === 'fail',
    JSON.stringify({ checks: preRegisteredRoster.checks, category: preRegisteredRoster.category }));

  const missingSummary = await runP6StageB({ caseKey: 'NM-G',
    history: [{ ...p6History[1], index: 0, registeredAt: 100 },
      { ...p6History[1], index: 1 }], prevSummaryPresent: false,
  });
  check('P6b B3: summary欠落と同hash再登録でも従来のstop',
    missingSummary.result.stop === true
      && missingSummary.report.get('check.stageB.majorLangs')?.status === 'fail'
      && missingSummary.report.getFact('stageB.previousResultVersion') === undefined,
    JSON.stringify({ checks: missingSummary.checks, stop: missingSummary.result.stop }));
  const singleMissingSummary = await runP6StageB({
    history: [{ ...p6History[1], index: 0, registeredAt: 100 }], prevSummaryPresent: false,
  });
  check('P6b B3b: summary欠落と登録1行でも従来のstop',
    singleMissingSummary.result.stop === true
      && singleMissingSummary.report.get('check.stageB.majorLangs')?.status === 'fail',
    JSON.stringify({ checks: singleMissingSummary.checks, stop: singleMissingSummary.result.stop }));

  const changedMissingSummary = await runP6StageB({ caseKey: 'U4I', prevSummaryPresent: false });
  check('P6b: 組分け後の変更でも旧summaryが無くobserverも無ければ従来どおりstop',
    changedMissingSummary.result.stop === true
      && changedMissingSummary.report.get('check.stageB.majorLangs')?.status === 'fail',
    JSON.stringify({ checks: changedMissingSummary.checks, stop: changedMissingSummary.result.stop }));
  const verifiedMissingSummary = await runP6StageB({
    prevSummaryPresent: false, observerSource: p6StageBRoot,
  });
  check('P6b: 同じ欠落でもobserverが締切時点の旧版を検証すればpass',
    verifiedMissingSummary.result.stop === false
      && verifiedMissingSummary.report.get('check.stageB.majorLangs')?.status === 'pass'
      && verifiedMissingSummary.report.get('check.stageB.groupsMatch')?.status === 'pass',
    JSON.stringify({ checks: verifiedMissingSummary.checks, stop: verifiedMissingSummary.result.stop }));

  const markerOnly = await runP6StageB({ caseKey: 'U4B', r2Prev: 'old' });
  check('P6b R30-C-4-02: 目印だけ動いたR2旧版は締切時点の行でprevAnchorを照合',
    markerOnly.report.get('check.stageB.prevAnchor')?.status === 'pass'
      && markerOnly.report.getFact('stageB.prevAnchorTarget')?.selectedIndex === 0
      && markerOnly.category === 'full',
    JSON.stringify({ checks: markerOnly.checks, fact: markerOnly.report.getFact('stageB.prevAnchorTarget') }));
  const sameMajor = await runP6StageB({ caseKey: 'U4C', r2Prev: 'same', history: [
    p6History[0], { ...p6History[1], hash: p6SameMajorPrevCore },
  ] });
  check('M1 U4C: coreが変わっても主要言語と実際の組が同じならfull',
    sameMajor.category === 'full', JSON.stringify(sameMajor.checks));
  const emergencyHistoricalAnchor = await runP6StageB({ r2Prev: 'old',
    emergencySource: { previousResultRegistration: { selectedIndex: 0, hash: p6OldPrevCore,
      registeredAt: 100, upperMs: 150000, upperSource: 'chattingStart_fallback' } },
  });
  check('P12a: 緊急選択した旧版はStage B prevAnchorも同じ登録行と照合して通る',
    emergencyHistoricalAnchor.report.get('check.stageB.prevAnchor')?.status === 'pass'
      && emergencyHistoricalAnchor.report.getFact('stageB.prevAnchorTarget')?.selectedIndex === 0
      && emergencyHistoricalAnchor.lines.some((line) => line.includes('##PREV_ANCHOR_TARGET')),
    JSON.stringify({ checks: emergencyHistoricalAnchor.checks,
      fact: emergencyHistoricalAnchor.report.getFact('stageB.prevAnchorTarget') }));
  check('P12a: 履歴照合だけ専用の事実どおりのpass文言を選び、現在目印は従来文言',
    messageId({ id: 'check.stageB.prevAnchor', status: 'pass',
      params: emergencyHistoricalAnchor.report.get('check.stageB.prevAnchor')?.params })
      === 'stageB.prevAnchorHistorical'
      && messageId({ id: 'check.stageB.prevAnchor', status: 'pass',
        params: unchangedWrong.report.get('check.stageB.prevAnchor')?.params })
        === 'check.stageB.prevAnchor');

  const postOnly = await runP6StageB({
    history: [{ ...p6History[1], index: 0, registeredAt: 100 },
      { ...p6History[0], index: 1, registeredAt: 200 },
      { ...p6History[1], index: 2, registeredAt: 250 }],
    observerSource: p6StageBRoot,
  });
  check('P6b B7: 宣言を導く保存版が締切後にしか登録されなければobserver付きでもfail',
    postOnly.report.get('check.stageB.majorLangs')?.status === 'pass'
      && postOnly.report.get('check.stageB.groupsMatch')?.status === 'fail'
      && postOnly.category === 'fail',
    JSON.stringify({ checks: postOnly.checks, category: postOnly.category }));

  const noMatchingObserver = await runP6StageB({
    caseKey: 'U4H',
    history: [{ ...p6History[1], index: 0, registeredAt: 100 },
      { ...p6History[0], index: 1, registeredAt: 200 }],
    r2Prev: 'old', observerSource: p6StageBRoot,
    groupedWith: ['fr'], declaredMajorLangs: ['fr'],
  });
  check('P6b 負: 締切時点の保存版が宣言majorLangsを導かなければobserverでもfail',
    noMatchingObserver.report.get('check.stageB.majorLangs')?.status === 'fail'
      && noMatchingObserver.report.getFact('stageB.previousResultVersion')?.selectedIndex === null
      && noMatchingObserver.category === 'fail',
    JSON.stringify({ checks: noMatchingObserver.checks, category: noMatchingObserver.category }));
  const m11bPlayers = Array.from({ length: 10 }, (_, index) => ({
    globalIndex: index,
    data: { uid: `p6-u${index}`, lang: index === 9 ? 'en' : 'ja',
      addr: `0x${(index + 1).toString(16).padStart(40, '0')}` },
  }));
  const m11bSeed = keccak256(concatHex([
    `0x${'71'.repeat(32)}`, `0x${'72'.repeat(32)}`, stringToHex('group'),
  ]));
  const m11bGroups = await new GameMasterDO({ storage: {} }, {})
    .formGroups(m11bPlayers, m11bSeed, ['ja']);
  const m11bRoster = baseResultsModule.reconstructCanonicalRosterPayloads(p6N, m11bGroups);
  const m11bRosterRow = await p6Write('m11b-roster.bin', m11bRoster.manifestText);
  const m11bRosterHash = buildRosterMemberCommitment({ blockNum: p6N,
    manifestText: m11bRoster.manifestText, groupTexts: m11bRoster.groupTexts }).C;
  const m11bLostIndex = structuredClone(p6ObserverIndex);
  m11bLostIndex.objects[p6PrevManifestKey] = [p6NewPrevManifestRow];
  m11bLostIndex.objects[p6PrevSummaryKey] = [p6NewPrevSummaryRow];
  m11bLostIndex.objects[`games/block${p6N}/roster/manifest.json`] = [m11bRosterRow];
  for (const [groupId, text] of m11bRoster.groupTexts) {
    m11bLostIndex.objects[`games/block${p6N}/roster/group${groupId}.json`] = [
      await p6Write(`m11b-roster-group-${groupId}.bin`, text),
    ];
  }
  const m11bNormalLost = await runP6StageB({ observerSource: p6StageBRoot,
    observerIndex: m11bLostIndex, savedRosterAt: 120,
    savedRosterMarkerHash: m11bRosterHash });
  check('M11b UJ1: 通常検証は窓内 N summary 消失を warn と文面で示し正典名簿で進む',
    m11bNormalLost.report.get('check.stageB.majorLangs')?.status === 'warn'
      && m11bNormalLost.report.get('check.stageB.groupsMatch')?.status === 'pass'
      && m11bNormalLost.lines.some((line) => line.startsWith('##PREVIOUS_SUMMARY_LOST'))
      && m11bNormalLost.category === 'full',
    JSON.stringify({ checks: m11bNormalLost.checks, lines: m11bNormalLost.lines }));
  const r32SummaryOnlyMissingIndex = structuredClone(m11bLostIndex);
  r32SummaryOnlyMissingIndex.objects[p6PrevManifestKey] = [p6OldPrevManifestRow];
  r32SummaryOnlyMissingIndex.objects[p6PrevSummaryKey] = [];
  const r32SummaryOnlyMissing = await runP6StageB({ observerSource: p6StageBRoot,
    observerIndex: r32SummaryOnlyMissingIndex, savedRosterAt: 120,
    savedRosterMarkerHash: m11bRosterHash });
  check('R32-C-1-04: 通常モードで前ブロック manifest 保存・summary だけ欠落は消失 warn',
    r32SummaryOnlyMissing.report.get('check.stageB.majorLangs')?.status === 'warn'
      && r32SummaryOnlyMissing.report.getFact('stageB.previousResultVersion')?.missingVersions
        ?.some((row) => row.status === 'summary_generation_missing')
      && r32SummaryOnlyMissing.lines.some((line) =>
        line.startsWith('##PREVIOUS_SUMMARY_LOST')));
  const r32SummaryOnlyNoRosterIndex = structuredClone(r32SummaryOnlyMissingIndex);
  r32SummaryOnlyNoRosterIndex.objects[`games/block${p6N}/roster/manifest.json`] = [];
  const r32SummaryOnlyNoRoster = await runP6StageB({ observerSource: p6StageBRoot,
    observerIndex: r32SummaryOnlyNoRosterIndex, savedRosterAt: 120,
    savedRosterMarkerHash: m11bRosterHash });
  check('R32-C-1-02: 同じ summary だけ消失でも通常モードは正典名簿の保存無しなら fail',
    r32SummaryOnlyNoRoster.report.get('check.stageB.majorLangs')?.status === 'fail'
      && !r32SummaryOnlyNoRoster.lines.some((line) =>
        line.startsWith('##PREVIOUS_SUMMARY_LOST')));
  const m11cMixedGroups = await new GameMasterDO({ storage: {} }, {})
    .formGroups(m11bPlayers, m11bSeed, []);
  const m11cMixedRoster = baseResultsModule.reconstructCanonicalRosterPayloads(p6N, m11cMixedGroups);
  const m11cMixedRosterRow = await p6Write('m11c-roster.bin', m11cMixedRoster.manifestText);
  const m11cMixedRosterHash = buildRosterMemberCommitment({ blockNum: p6N,
    manifestText: m11cMixedRoster.manifestText, groupTexts: m11cMixedRoster.groupTexts }).C;
  const m11cMixedIndex = structuredClone(p6ObserverIndex);
  m11cMixedIndex.objects[p6PrevManifestKey] = [p6OldPrevManifestRow];
  m11cMixedIndex.objects[p6PrevSummaryKey] = [p6OldPrevSummaryRow];
  m11cMixedIndex.objects[`games/block${p6N}/roster/manifest.json`] = [m11cMixedRosterRow];
  for (const [groupId, text] of m11cMixedRoster.groupTexts) {
    m11cMixedIndex.objects[`games/block${p6N}/roster/group${groupId}.json`] = [
      await p6Write(`m11c-roster-group-${groupId}.bin`, text),
    ];
  }
  const m11cHistory = [
    { ...p6History[0], registeredAt: 100 },
    { ...p6History[1], registeredAt: 120 },
    { ...p6History[1], index: 2, hash: p6ThirdPrevCore, registeredAt: 200 },
  ];
  const m11cNormalMixed = await runP6StageB({ observerSource: p6StageBRoot,
    observerIndex: m11cMixedIndex, savedRosterAt: 120,
    savedRosterMarkerHash: m11cMixedRosterHash, history: m11cHistory,
    r2Prev: 'third', groupedWith: [], declaredMajorLangs: [] });
  check('M11c: 通常検証も保存済み不一致と欠落が混じれば warn と欠落添字・hash を出す',
    m11cNormalMixed.report.get('check.stageB.majorLangs')?.status === 'warn'
      && m11cNormalMixed.category === 'full'
      && m11cNormalMixed.report.getFact('stageB.previousResultVersion')?.missingVersions
        ?.some((row) => row.index === 1 && row.hash === p6NewPrevCore)
      && m11cNormalMixed.report.getFact('stageB.previousResultVersion')?.savedMismatches
        ?.some((row) => row.index === 0 && row.hash === p6OldPrevCore)
      && m11cNormalMixed.lines.some((line) =>
        line.startsWith('##PREVIOUS_SUMMARY_LOST')
          && line.includes(p6NewPrevCore) && line.includes(p6OldPrevCore)));
  const m11cReadyIndex = structuredClone(m11cMixedIndex);
  m11cReadyIndex.objects[`games/block${p6N}/roster/manifest.json`] = [m11bRosterRow];
  const m11cReady = await runP6StageB({ observerSource: p6StageBRoot,
    observerIndex: m11cReadyIndex, savedRosterAt: 120,
    savedRosterMarkerHash: m11bRosterHash, history: m11cHistory,
    r2Prev: 'third', groupedWith: ['ja'], declaredMajorLangs: ['ja'] });
  check('M11c: 通常検証は保存済み再現版を採り、別の欠落版だけで警告しない',
    m11cReady.report.get('check.stageB.majorLangs')?.status === 'pass'
      && m11cReady.report.getFact('stageB.previousResultVersion')?.selectedIndex === 0
      && !m11cReady.lines.some((line) => line.startsWith('##PREVIOUS_SUMMARY_LOST')));
  const m11cFrGroups = await new GameMasterDO({ storage: {} }, {})
    .formGroups(m11bPlayers, m11bSeed, ['fr']);
  const m11cFrRoster = { blockNum: p6N,
    indexSha256: baseResultsModule.reconstructedRosterIndexSha256(m11cFrGroups),
    groups: m11cFrGroups.map((group) => ({ groupId: group.groupId,
      sha256: baseResultsModule.reconstructedRosterGroupSha256(p6N, group) })),
  };
  const m11cFrRosterRow = await p6Write('m11c-fr-roster.bin', m11cFrRoster);
  const m11cAllSavedIndex = structuredClone(p6ObserverIndex);
  m11cAllSavedIndex.objects[`games/block${p6N}/roster/manifest.json`] = [m11cFrRosterRow];
  const m11cAllSaved = await runP6StageB({ observerSource: p6StageBRoot,
    observerIndex: m11cAllSavedIndex, savedRosterAt: 120,
    savedRosterMarkerHash: keccak256(stringToHex(JSON.stringify(m11cFrRoster))),
    history: m11cHistory, r2Prev: 'third', groupedWith: ['fr'], declaredMajorLangs: ['fr'] });
  check('M11c: 窓内版が全部保存されても再現しなければ通常検証は fail',
    m11cAllSaved.report.get('check.stageB.majorLangs')?.status === 'fail'
      && m11cAllSaved.category === 'fail');
  const aba = await runP6StageB({ caseKey: 'NM-F', r2Prev: 'old', history: [
    p6History[0], { ...p6History[1], registeredAt: 120 },
    { ...p6History[0], index: 2, registeredAt: 200 },
  ] });
  check('M1 NM-F: ABA再登録で公開旧版と現在値が一致すればfull',
    aba.category === 'full', JSON.stringify(aba.checks));

  const ordinary = await runP6StageB({
    history: [p6History[1]], groupedWith: [], declaredMajorLangs: [],
  });
  check('P6 通常/従来盤面: フラグ省略かつ現在のNで組を再現できる盤面は判定列と終了状態が不変',
    JSON.stringify(ordinary.checks) === JSON.stringify(PREV_ANCHOR_CHECKS_VERIFIED)
      && ordinary.report.getFact('stageB.previousResultVersion') === undefined
      && ordinary.category === 'full'
      && ordinary.result.stop === false,
    JSON.stringify({ checks: ordinary.checks, category: ordinary.category }));
}

// M1: 承認された組分け後の変更と、窓の外で旧版を拾う盤面を対で固定する。
{
  const third = { ...p6History[1], index: 2, hash: p6ThirdPrevCore,
    registeredBlock: 30, registeredAt: 200 };
  const verdict = (run) => ({ prevAnchor: run.report.get('check.stageB.prevAnchor')?.status,
    majorLangs: run.report.get('check.stageB.majorLangs')?.status,
    category: run.category });
  const d = await runP6StageB({ r2Prev: 'old', history: [p6History[0],
    { ...p6History[1], registeredAt: 120 }, { ...p6History[1], index: 2, registeredAt: 200 }] });
  check('M1 D: 上限以前の最新行と現在値が同じなら旧行を拾わずfail',
    verdict(d).prevAnchor === 'fail' && d.category === 'fail', JSON.stringify(verdict(d)));
  const dPrime = await runP6StageB({ r2Prev: 'old', observerSource: p6StageBRoot,
    history: [p6History[0],
    { ...p6History[1], registeredAt: 120 }, { ...p6History[1], index: 2, registeredAt: 200 }],
  });
  check('M1 D′: 同じhashの再登録でも旧行例外を開かない',
    verdict(dPrime).prevAnchor === 'fail' && dPrime.category === 'fail', JSON.stringify(verdict(dPrime)));
  const u4b = await runP6StageB({ r2Prev: 'old' });
  check('M1 U4B: 組分け後の異hash再登録なら旧行を採ってfull',
    verdict(u4b).prevAnchor === 'pass' && u4b.category === 'full', JSON.stringify(verdict(u4b)));

  const l1 = await runP6StageB({ caseKey: 'L1', r2Prev: 'old', entryEndSec: 130,
    history: [p6History[0], { ...p6History[1], registeredAt: 120 }, third] });
  check('M1 L1: 応募終了より前に上書きされた旧版はprevAnchorに採らない',
    verdict(l1).prevAnchor === 'fail' && l1.category === 'fail', JSON.stringify(verdict(l1)));
  const l1w = await runP6StageB({ r2Prev: 'old', entryEndSec: 130,
    history: [{ ...p6History[0], registeredAt: 130 }, { ...p6History[1], registeredAt: 140 }, third] });
  check('M1 L1w: 応募終了ちょうどの現在版は候補に残す',
    verdict(l1w).prevAnchor === 'pass' && l1w.category === 'full', JSON.stringify(verdict(l1w)));
  const l3 = await runP6StageB({ caseKey: 'L3', r2Prev: 'old', entryEndSec: 130,
    rosterAnchorAt: 140,
    history: [p6History[0], { ...p6History[1], registeredAt: 120 }, third] });
  check('M1 L3: 応募終了後の一致名簿錨があっても古い版は採らない',
    verdict(l3).prevAnchor === 'fail' && l3.category === 'fail', JSON.stringify(verdict(l3)));
  const n1 = await runP6StageB({ r2Prev: 'old', history: [p6History[0],
    { ...p6History[1], registeredAt: 120 }] });
  check('M1 N1: 上限以前だけの再登録は旧版prevAnchorを開かない',
    verdict(n1).prevAnchor === 'fail' && n1.category === 'fail', JSON.stringify(verdict(n1)));
  const n2 = await runP6StageB({ r2Prev: 'old', history: [p6History[1],
    { ...p6History[0], index: 1, registeredAt: 200 }, third] });
  check('M1 N2: 旧版が上限後だけならprevAnchorを開かない',
    verdict(n2).prevAnchor === 'fail' && n2.category === 'fail', JSON.stringify(verdict(n2)));
  const n3 = await runP6StageB({ r2Prev: 'old' });
  check('M1 N3: 上限以前の旧版から組分け後に変更した場合だけfull',
    verdict(n3).prevAnchor === 'pass' && n3.category === 'full', JSON.stringify(verdict(n3)));

  const d3 = await runP6StageB({ caseKey: 'D-3-01', r2Prev: 'old', groupedWith: [], declaredMajorLangs: [],
    rosterAnchorAt: 110, history: [p6History[0], { ...p6History[1], registeredAt: 120 }] });
  check('M1 D-3-01: 先回り名簿錨と組分け前の変更で履歴prevAnchorと宣言主要言語を併用しない',
    verdict(d3).prevAnchor === 'pass' && verdict(d3).majorLangs !== 'warn'
      && d3.category === 'fail', JSON.stringify(verdict(d3)));
  const d3History = [p6History[0], { ...p6History[1], registeredAt: 120 }];
  const d3Observer = await runP6StageB({ caseKey: 'D-3-01-observer-no-roster',
    observerSource: p6StageBRoot, r2Prev: 'old', groupedWith: [],
    declaredMajorLangs: [], rosterAnchorAt: 110, history: d3History });
  check('M1 D-3-01: observerに名簿世代がなくても先回りの組はfail',
    d3Observer.category === 'fail', JSON.stringify(verdict(d3Observer)));
  const d3RosterIndex = structuredClone(p6ObserverIndex);
  d3RosterIndex.objects[`games/block${p6N}/roster/manifest.json`] = [{
    ...p6SavedRosterRow, generation: 1, observationOrdinal: '00000001:00000002',
  }];
  const d3Roster = await runP6StageB({ caseKey: 'D-3-01-observer-roster',
    observerSource: p6StageBRoot, observerIndex: d3RosterIndex,
    savedRosterAt: 140, rosterAnchorAt: 110, r2Prev: 'old',
    groupedWith: [], declaredMajorLangs: [], history: d3History });
  check('M1 D-3-01: observerに名簿世代があっても先回りの組はfail',
    d3Roster.category === 'fail', JSON.stringify(verdict(d3Roster)));

  const unreadableRoster = await runP6StageB({ rosterAnchorAt: 110,
    rosterFetchThrows: true, history: [p6History[0], { ...p6History[1], registeredAt: 120 }] });
  check('M1 B-1-01: R2名簿取得失敗なら例外へ入らずfactに理由を残す',
    unreadableRoster.category === 'fail'
      && String(unreadableRoster.report.getFact('stageB.previousResultVersionSearch')?.error)
        .includes('roster fetch unavailable'),
    JSON.stringify({ verdict: verdict(unreadableRoster),
      search: unreadableRoster.report.getFact('stageB.previousResultVersionSearch') }));
  const unreadablePrevAnchor = await runP6StageB({ r2Prev: 'old', rosterAnchorAt: 110,
    rosterFetchThrows: true });
  check('M1 B-4c-04: prevAnchor側の名簿読取失敗もfactに残し起点の失敗文を保つ',
    unreadablePrevAnchor.report.get('check.stageB.prevAnchor')?.status === 'fail'
      && unreadablePrevAnchor.report.get('check.stageB.prevAnchor')?.params?.failures
        === 'manifest core sha256 != getResultHash(0)'
      && String(unreadablePrevAnchor.report.getFact('stageB.previousResultVersionSearch')?.error)
        .includes('roster fetch unavailable'),
    JSON.stringify({ verdict: verdict(unreadablePrevAnchor),
      search: unreadablePrevAnchor.report.getFact('stageB.previousResultVersionSearch') }));

  const l2 = await runP6StageB({ caseKey: 'L2', observerSource: p6StageBRoot, r2Prev: 'third',
    groupedWith: ['ja'], declaredMajorLangs: ['ja'], entryEndSec: 130,
    history: [p6History[0], { ...p6History[1], registeredAt: 120 }, third] });
  check('M1 L2: 応募終了前に上書きされた旧版をobserver候補へ入れない',
    verdict(l2).majorLangs === 'fail' && l2.category === 'fail', JSON.stringify(verdict(l2)));
  const w1 = await runP6StageB({ observerSource: p6StageBRoot, r2Prev: 'third',
    groupedWith: ['ja'], declaredMajorLangs: ['ja'],
    history: [{ ...p6History[1], index: 0, registeredAt: 100 },
      { ...p6History[0], index: 1, registeredAt: 160 }, third] });
  check('M1 W1: 上限後だけの宣言版はobserverでも採らない',
    verdict(w1).majorLangs === 'fail' && w1.category === 'fail', JSON.stringify(verdict(w1)));
  const w2 = await runP6StageB({ observerSource: p6StageBRoot, r2Prev: 'third', rosterAnchorAt: 110,
    groupedWith: ['ja'], declaredMajorLangs: ['ja'],
    history: [{ ...p6History[1], index: 0, registeredAt: 100 },
      { ...p6History[0], index: 1, registeredAt: 120 }, third] });
  check('M1 W2: 名簿錨の後・chattingStart前だけの宣言版は採らない',
    verdict(w2).majorLangs === 'fail' && w2.category === 'fail', JSON.stringify(verdict(w2)));
  const incomplete = structuredClone(p6ObserverIndex);
  incomplete.complete = false;
  const e7 = await runP6StageB({ observerSource: p6StageBRoot, observerIndex: incomplete });
  check('M1 E7: complete:false の保存索引は使わない',
    verdict(e7).majorLangs === 'fail' && e7.category === 'fail', JSON.stringify(verdict(e7)));
  const unreadable = structuredClone(p6ObserverIndex);
  unreadable.objects[p6PrevManifestKey][0].sha256 = '0'.repeat(64);
  const g12 = await runP6StageB({ observerSource: p6StageBRoot, observerIndex: unreadable });
  check('M1 G12: 保存manifestのsha不一致は版評価を止める',
    verdict(g12).majorLangs === 'fail' && g12.category === 'fail', JSON.stringify(verdict(g12)));

  const rosterIndex = structuredClone(p6ObserverIndex);
  rosterIndex.objects[`games/block${p6N}/roster/manifest.json`] = [{
    ...p6SavedRosterRow, generation: 1, observationOrdinal: '00000001:00000002',
  }];
  const sHistory = [{ ...p6History[1], index: 0, registeredAt: 100 },
    { ...p6History[0], index: 1, registeredAt: 120 }, third];
  for (const [label, index, markerHash] of [
    ['S1', rosterIndex, p6SavedRosterHash],
    ['S2', rosterIndex, `0x${'ff'.repeat(32)}`],
    ['S3', p6ObserverIndex, p6SavedRosterHash],
  ]) {
    const run = await runP6StageB({ observerSource: p6StageBRoot, observerIndex: index,
      r2Prev: 'third',
      rosterAnchorAt: 110, savedRosterAt: 140, savedRosterMarkerHash: markerHash,
      groupedWith: ['ja'], declaredMajorLangs: ['ja'], history: sHistory });
    const search = run.report.getFact('stageB.previousResultVersionSearch');
    check(`M9a ${label}: 開始前最後の登録が上限を決める`,
      verdict(run).majorLangs === 'pass' && run.category === 'full'
        && search?.effectiveUpperMs === 140_000
        && run.report.getFact('stageB.previousResultVersion')?.upperSource
          === 'matching_roster_anchor_registration',
      JSON.stringify({ verdict: verdict(run), search }));
    if (label === 'S2') check('M1 S2: 名簿目印との差はfactに残す',
      search?.rosterDifference?.checkId === 'check.stageC.rosterLiveAnchor', JSON.stringify(search));
    if (label === 'S3') check('M1 S3: 保存名簿行の欠落はfactに残す',
      search?.rosterGenerationMissing === true, JSON.stringify(search));
  }
  const sPlus = await runP6StageB({ observerSource: p6StageBRoot, observerIndex: rosterIndex,
    r2Prev: 'third',
    rosterAnchorAt: 110, savedRosterAt: 140, groupedWith: ['ja'], declaredMajorLangs: ['ja'],
    history: [p6History[0], third] });
  check('M1 S1+: 入口と保存名簿の両上限以内の正直な版は通す',
    verdict(sPlus).majorLangs === 'pass' && sPlus.category === 'full', JSON.stringify(verdict(sPlus)));

  const loggedHistory = [p6History[0], { ...third, index: 1, registeredAt: 120 },
    { ...p6History[1], index: 2, registeredAt: 200 }];
  const honestLogs = loggedHistory.map((row) => ({ hash: row.hash,
    updatedAt: row.registeredBlock, signer: row.signer, registrationCount: row.index + 1 }));
  const honestLogged = await runP6StageB({ r2Prev: 'old', history: loggedHistory,
    resultLogs: honestLogs });
  check('M9a: 非先頭の正直な結果ログは旧版manifestとの照合を通す',
    honestLogged.report.get('check.stageB.prevAnchor')?.status === 'pass');
  const hiddenLogged = await runP6StageB({ r2Prev: 'old', history: loggedHistory,
    resultLogs: honestLogs.map((row, index) => index === 0
      ? { ...row, hash: third.hash } : row) });
  check('M9a: 非先頭ログのhash差し替えは状態照合で検出する',
    hiddenLogged.report.get('check.stageB.prevAnchor')?.status === 'fail'
      && String(hiddenLogged.report.getFact('stageB.previousResultVersionSearch')?.error)
        .includes('differs from state row 0'));
}

// ------------------------------------------------------------------
// 便 W4（2026-09-20）から続く、前ブロックの再登録の可視化。
// R30-U-4 後の正しさは履歴版の2ホップと実際の組の再現が検査する。
// このカウンタは代用ではなく、履歴版が必要な盤面を必ず報告する可視化として固定する。
// 🔴 正常な再集計や復旧でも回数は増えるため、warn であって fail ではない。
// ------------------------------------------------------------------
{
  const single = await runPrevAnchorGrouping({ regCount: 1 });
  check('W4 ① 前ブロックの目印が1回きりなら pass',
    single.reregistration?.status === 'pass'
      && single.reregistration?.params?.count === 1
      && single.reregistration?.params?.prev === 0
      && single.reregistration?.params?.updated === 1
      && single.reregistration?.params?.signer === `0x${'ab'.repeat(20)}`,
    JSON.stringify(single.reregistration));

  const replacedPlain = await runPrevAnchorGrouping({ regCount: 3 });
  check('W4 ② 目印が差し替えられていれば warn（fail にしない）',
    replacedPlain.reregistration?.status === 'warn'
      && replacedPlain.reregistration?.params?.count === 3
      && replacedPlain.report.hasFail() === false,
    JSON.stringify(replacedPlain.reregistration));
  check('W4 ② warn なので通常モードの結論と終了状態は動かない（full / stop=false）',
    replacedPlain.category === 'full' && replacedPlain.stop === false,
    JSON.stringify({ category: replacedPlain.category, stop: replacedPlain.stop }));
  check('W4 ② warn は読み手向けの1行も出す',
    replacedPlain.lines.includes('stageB.prevResultReregistered'),
    JSON.stringify(replacedPlain.lines.slice(-4)));
  check('W4 ② 通常モードでは差分を積まない（緊急固定一式の外に漏らさない）',
    replacedPlain.differences === null,
    JSON.stringify(replacedPlain.differences));

  // ------------------------------------------------------------------
  // 🔴 便 X1 / Q-A（2026-09-21・ユーザー決定 (a)）
  //
  // 登録回数の増加を「事故差」に数えない。`HashStorage.registerResultHash` の直前のコメントは
  // 逐語で「resultHash は何度でも上書き可能（障害時の再計算・再登録に対応）だが、
  // 登録回数は単調増加カウンタに記録され改ざんできない（差し替えの可視化）。」であり、
  // 回数は**可視化**のためのもので違反の印ではない。緊急復旧の手順書は再登録を必須にしている
  // ので、正しく復旧すると必ず回数が2以上になり、必ず「事故差あり」＝終了コード4 になる。
  //
  // 🔴 だから外すのは差分の記録だけで、`warn` と読み手向けの1行は残す（可視化は続ける）。
  // 🔴 値の正しさは `check.stageB.prevAnchor` が見ており、その fail は
  //    `EMERGENCY_ALLOWED_DIFFERENCE_CHECKS` に無いので緊急輸出そのものを止める。
  //    ＝検出力は落ちていない。それを下の「④ 検出力」で全数に測る。
  // ------------------------------------------------------------------
  const replacedEmergency = await runPrevAnchorGrouping({ regCount: 3, emergency: true });
  check('X1 Q-A ② 緊急モードでも登録回数では差分が1件も増えない',
    (replacedEmergency.differences || []).length === 0,
    JSON.stringify(replacedEmergency.differences));
  check('X1 Q-A ② それでも warn と読み手向けの1行は残る（可視化は続く）',
    replacedEmergency.reregistration?.status === 'warn'
      && replacedEmergency.reregistration?.params?.count === 3
      && replacedEmergency.reregistration?.params?.reason === 'reregistered'
      && replacedEmergency.lines.includes('stageB.prevResultReregistered'),
    JSON.stringify({
      check: replacedEmergency.reregistration,
      printed: replacedEmergency.lines.includes('stageB.prevResultReregistered'),
    }));
  check('W4 ② 緊急モードでも fail は1件も増えない',
    replacedEmergency.report.hasFail() === false
      && replacedEmergency.reregistration?.status === 'warn',
    JSON.stringify(replacedEmergency.checks));
  check('X1 Q-A ② 通常モードと緊急モードで判定の全数列が同一（回数では1件も動かない）',
    JSON.stringify(replacedPlain.checks) === JSON.stringify(replacedEmergency.checks),
    JSON.stringify({ plain: replacedPlain.checks, emergency: replacedEmergency.checks }));

  // 🔴 ④ 検出力の歯: 値が食い違うケースでは、いまも止まる。
  //    差分1件どころか、緊急輸出の関門（assertEmergencyVerificationGate）が拒否する。
  //    この歯が無いと便は失敗（検出力を落としていないことの証拠になっていない）。
  const valueMismatchEmergency = await runPrevAnchorGrouping({
    anchorMatches: false, regCount: 3, emergency: true,
  });
  check('X1 Q-A ④ 検出力: 前ブロックの値が食い違えば prevAnchor は いまも fail',
    valueMismatchEmergency.report.get('check.stageB.prevAnchor')?.status === 'fail'
      && valueMismatchEmergency.report.hasFail() === true,
    JSON.stringify(valueMismatchEmergency.checks));
  check('X1 Q-A ④ 検出力: prevAnchor は許容集合に無いので緊急輸出そのものが拒否される',
    !EMERGENCY_ALLOWED_DIFFERENCE_CHECKS.includes('check.stageB.prevAnchor')
      && (() => {
        try {
          assertEmergencyVerificationGate(valueMismatchEmergency.report, {
            kind: 'groupGame', rebuiltSummary: {}, allGroupResults: [],
          });
          return false;
        } catch (error) {
          return String(error?.message || error).includes('check.stageB.prevAnchor');
        }
      })(),
    JSON.stringify(valueMismatchEmergency.checks));

  const throwing = await runPrevAnchorGrouping({ regCount: 'throws' });
  check('W4 ③ 読取が失敗したら skip（🔴 pass に化けない）',
    throwing.reregistration?.status === 'skip'
      && throwing.reregistration?.params?.reason === 'unreadable'
      && throwing.reregistration?.status !== 'pass',
    JSON.stringify(throwing.reregistration));
  const noReader = await runPrevAnchorGrouping({ regCount: 'missing' });
  check('W4 ③ 読み手そのものが無くても skip（🔴 pass に化けない）',
    noReader.reregistration?.status === 'skip'
      && noReader.reregistration?.params?.reason === 'unreadable',
    JSON.stringify(noReader.reregistration));
  const unregistered = await runPrevAnchorGrouping({ regCount: 0 });
  check('W4 ③ 1度も登録されていなければ skip（「1回きり」を名乗らない）',
    unregistered.reregistration?.status === 'skip'
      && unregistered.reregistration?.params?.reason === 'unregistered',
    JSON.stringify(unregistered.reregistration));

  const genesis = await runPrevAnchorGrouping({ blockNum: 0 });
  check('W4 ④ ブロック0（前ブロックが無い）は skip',
    genesis.reregistration?.status === 'skip'
      && genesis.reregistration?.params?.reason === 'no_previous_block'
      && genesis.stop === false,
    JSON.stringify({ check: genesis.reregistration, stop: genesis.stop }));

  // ==================================================================
  // 周29 (c)（2026-09-22）: 前ブロックの目印読みが**履歴のどの行を選んだか**を報告へ残す。
  // 🔴 選び方（現在値）は変えていない。この3件はそれを両方向で固定する。
  // ==================================================================
  {
    const prevCoreOf = (run) => run.report.get('check.stageB.prevAnchor')?.params ?? null;
    const twoRowHistory = {
      count: 2,
      rows: [
        { index: 0, hash: `0x${'ee'.repeat(32)}`, registeredBlock: 1, registeredAt: 10, signer: `0x${'ab'.repeat(20)}` },
        { index: 1, hash: `0x${'77'.repeat(32)}`, registeredBlock: 9, registeredAt: 20, signer: `0x${'ab'.repeat(20)}` },
      ],
    };
    // anchorMatches:false のとき chain.getResultHash は hash=0xee..ee / updated=1 を返す（:566-570）。
    const located = await runPrevAnchorGrouping({ anchorMatches: false, resultHistory: twoRowHistory });
    check('周29 (c) 前ブロックの目印が追記履歴のどの行かを fact に残す（現在値＝添字0、最新＝添字1）',
      located.markerRow?.currentIndex === 0
        && located.markerRow?.latestIndex === 1
        && located.markerRow?.registrationCount === 2
        && located.markerRow?.selectionRule === 'HashStorage.getResultHash current value (unchanged)'
        && located.markerRow?.historyError === null,
      JSON.stringify(located.markerRow));

    const noHistory = await runPrevAnchorGrouping({ anchorMatches: false });
    check('周29 (c) 履歴 getter の無い読み手では historyError を残し、黙って空にしない',
      typeof noHistory.markerRow?.historyError === 'string'
        && noHistory.markerRow.historyError.includes('resultRegistrationHistory')
        && noHistory.markerRow.currentIndex === null,
      JSON.stringify(noHistory.markerRow));

    const throwing = await runPrevAnchorGrouping({ anchorMatches: false, resultHistory: 'throws' });
    check('周29 (c) 履歴が読めなくても prevAnchor / prevResultReregistration の判定は1件も動かない',
      throwing.markerRow?.historyError === 'history unavailable'
        && JSON.stringify(throwing.checks) === JSON.stringify(PREV_ANCHOR_CHECKS_UNVERIFIED)
        && JSON.stringify(located.checks) === JSON.stringify(PREV_ANCHOR_CHECKS_UNVERIFIED)
        && JSON.stringify(prevCoreOf(throwing)) === JSON.stringify(prevCoreOf(located)),
      JSON.stringify({ throwing: throwing.checks, located: located.checks }));
  }

  const W4_ID = 'check.stageB.prevResultReregistration';
  check('W4 ⑤ 新しい検査 ID は許容集合にも格下げ集合にも必須集合にも入っていない',
    !EMERGENCY_ALLOWED_DIFFERENCE_CHECKS.includes(W4_ID)
      && !EMERGENCY_DOWNGRADABLE_CHECKS.includes(W4_ID)
      && !Object.values(EMERGENCY_REQUIRED_CHECKS).flat().includes(W4_ID),
    JSON.stringify({
      allowed: EMERGENCY_ALLOWED_DIFFERENCE_CHECKS.length,
      downgradable: EMERGENCY_DOWNGRADABLE_CHECKS.length,
    }));
  // 🔴 便 Z1 の4件に、便 S3C14b の entryKeyIntegrity を追加して許可20件。
  //    配線の便 WR-3-FIX1（75291f46）が当選1〜2名の公開 group0 の欠落・改ざんでも緊急の書き出しを
  //    進めるため check.stageC.autoRoster を足して許可21件。
  //    WR-15 の区間境界を許容差へ、K13 を降格へ1件ずつ追加。必須4種は不変。
  check('W4 ⑤ 3つの集合の件数は許可22 / 降格8 / 必須4種で固定されている',
    EMERGENCY_ALLOWED_DIFFERENCE_CHECKS.length === 22
      && EMERGENCY_DOWNGRADABLE_CHECKS.length === 8
      && Object.keys(EMERGENCY_REQUIRED_CHECKS).length === 4
      && Object.values(EMERGENCY_REQUIRED_CHECKS).flat().length === 8 + 5 + 3 + 7,
    JSON.stringify({
      allowed: EMERGENCY_ALLOWED_DIFFERENCE_CHECKS.length,
      downgradable: EMERGENCY_DOWNGRADABLE_CHECKS.length,
      requiredKinds: Object.keys(EMERGENCY_REQUIRED_CHECKS),
      requiredTotal: Object.values(EMERGENCY_REQUIRED_CHECKS).flat().length,
    }));
}

check('GameMaster と verifier は timeline no-game 原因の単一台帳を共有',
  JSON.stringify(GameMasterDO.TIMELINE_NO_GAME_CAUSES) === JSON.stringify(TIMELINE_NO_GAME_CAUSES));
check('timeline no-game 原因の単一台帳は正規の5原因を過不足なく持つ',
  JSON.stringify(TIMELINE_NO_GAME_CAUSES) === JSON.stringify(EXPECTED_TIMELINE_NO_GAME_CAUSES));

// T1c G9: 緊急＋timeline no-game＋root不在は、平時のroot省略終端より先に
// 緊急再構築へ入りつつ、timeline固有の3必須検査を通って輸出関門まで到達する。
{
  const published = makePublished();
  const report = createReport();
  const ctx = {
    blockNum: N,
    cfg: { pins: { confirmationBlocks: 64 } },
    data: {
      emergencySource: { sourceDir: '/unused', index: { objects: {} } },
      emergencyDifferences: [], emergencyServerSubmissions: {},
      groupsDerived: [], gameSelection: { players: [{}, {}, {}] },
    },
    report,
    ui: { println() {}, t: (id) => id },
    r2: { fetchJson: async () => null },
    chain: {
      latest: async () => ({ number: 200n, timestamp: 1_000n }),
      findBlockByTimestamp: async () => 90,
      getBlock: async (number) => ({ number, timestamp: 1_000n }),
      resultWindow: async () => ({ openAt: 800n, closeAt: 900n }),
      resultCount: async () => 0n,
      evidenceAddress: async () => EVIDENCE,
    },
  };
  const S = {
    timelineNoGame: true, anomalies: [], resultCount: 0, adoptedByUid: {},
    files: { summary: { data: published, raw: JSON.stringify(published) }, gameGroups: null },
    factsMerkle: { root: SENTINEL_ROOT },
  };
  const routed = await missingRootRouter(ctx, S, {
    root: ZERO_ROOT, verificationStartedAt: 0, zkEpochPlusOne: 0,
  }, ZERO_ROOT);
  await finalityVerifier(ctx, S);
  await rootPresentChatVerifier(ctx, S);
  evidenceEmptyChecker(ctx, S);
  for (const id of [
    'check.stageA.rootMatch', 'check.stageB.playersMatch',
    'check.stageC.evidenceCompleteness', 'check.stageC.merkleRebuild',
  ]) report.check(id, 'pass', { fixture: 't1c-g9' });
  let gatePassed = true;
  try {
    assertEmergencyVerificationGate(report, {
      kind: 'timelineNoGame', rebuiltSummary: published, allGroupResults: [],
    });
  } catch (error) {
    gatePassed = false;
  }
  check('T1c G9 緊急root不在はemergency分岐で継続しrootSubmitted=WARN・差1件',
    routed.branch === 'emergency_rebuild' && routed.stop === false
      && report.get('check.stageC.rootSubmitted')?.status === 'warn'
      && ctx.data.emergencyDifferences.length === 1,
    JSON.stringify({ routed, differences: ctx.data.emergencyDifferences }));
  check('T1c G9 timeline no-gameの3必須検査がPASSし輸出関門を通る',
    ['check.stageC.timelineNoGameFinality', 'check.stageC.timelineNoGameEvidenceEmpty',
      'check.stageC.timelineNoGameChatNotStarted']
      .every((id) => report.get(id)?.status === 'pass') && gatePassed,
    JSON.stringify(report.list()));

  const resultsSource = await fs.readFile(
    process.env.T1C_RESULTS_MODULE
      ? path.resolve(process.env.T1C_RESULTS_MODULE)
      : path.resolve(import.meta.dirname, '../src/stages/results.js'),
    'utf8',
  );
  const routeStart = resultsSource.indexOf('export async function routeMissingRootInStageC');
  const routeEnd = resultsSource.indexOf('\nexport ', routeStart + 10);
  const routeSource = resultsSource.slice(routeStart, routeEnd);
  check('T1c G9 分岐順はemergency_rebuildがtimeline_no_game_omissionより先',
    routeSource.indexOf("'check.stageC.rootSubmitted'") >= 0
      && routeSource.indexOf("'check.stageC.rootSubmitted'") < routeSource.indexOf('if (S.timelineNoGame)'),
    routeSource);
  console.log('T1C_CASE_OK emergency-timeline-rootless required=3 rootSubmitted=warn differences=1 gate=pass');
}

// T1g D1: run() の分岐自体を両方向で固定する。通常の正直なroot省略はここで終端し、
// 緊急再構築だけが後続のStage Cへ進む。
{
  const normal = await runStageCRootlessMode(false);
  // 🔴 周29 (b)（2026-09-22）: recordZkpState に check.stageC.zkPrevRegistrationWitness の skip が
  //    1本増えたので 13 → 14。WR-15 の新ID 2本の skip で14 → 16。
  //    SUMMARY-ZKP-FIX1 の verifier照合の skip で16 → 17。
  //    status の内訳（FAIL 0）と終了状態は動いていない。
  check('T1g D1 通常timeline no-gameの健全なroot省略は17検査・FAIL 0・exit 0',
    normal.report.list().length === 17
      && normal.report.get('check.stageC.zkVerifierIdentity')?.status === 'skip'
      && normal.report.get('check.stageC.zkVerifierIdentity')?.params.reason === 'timeline_no_game_root_omission'
      && normal.report.list().filter((row) => row.status === 'fail').length === 0
      && normal.category === 'full' && normal.exitCode === 0
      && normal.fetchedKeys.length === 2,
    JSON.stringify({ checks: normal.report.list(), fetchedKeys: normal.fetchedKeys }));

  const emergency = await runStageCRootlessMode(true);
  check('T1g D1 緊急再構築だけはroot不在後もStage Cを続行する',
    emergency.report.get('check.stageC.rootSubmitted')?.status === 'warn'
      && emergency.report.get('check.stageC.downloads')?.status === 'fail'
      && emergency.fetchedKeys.length > 2,
    JSON.stringify({ checks: emergency.report.list(), fetchedKeys: emergency.fetchedKeys }));
  console.log('T1G_D1_OK normal=17/fail0/exit0 emergency=continued');
}

// Q46: 共通分類の全組合せ。通常ブロックと zero_entries は root の有無にかかわらず
// timeline no-game 専用の緩和へ入らないことも同じ表で固定する。
const classificationRows = [
  {
    name: 'timeline/期限前/rootなし',
    summary: makePublished(), chainRoot: ZERO_ROOT, nowSec: ROOT_DEADLINE - 1,
    verification: { safeResultWindowClosed: true, evidenceResultCount: 0, selectedPlayerCount: 3, chatStartEvidenceAbsent: true },
    expected: TIMELINE_NO_GAME_ROOT_STATE.OMISSION_PENDING,
  },
  {
    name: 'timeline/期限ちょうど/rootなし',
    summary: makePublished(), chainRoot: ZERO_ROOT, nowSec: ROOT_DEADLINE,
    verification: { safeResultWindowClosed: true, evidenceResultCount: 0, selectedPlayerCount: 3, chatStartEvidenceAbsent: true },
    expected: TIMELINE_NO_GAME_ROOT_STATE.OMISSION_PENDING,
  },
  {
    name: 'timeline/期限後/rootなし',
    summary: makePublished(), chainRoot: ZERO_ROOT, nowSec: ROOT_DEADLINE + 1,
    verification: { safeResultWindowClosed: true, evidenceResultCount: 0, selectedPlayerCount: 3, chatStartEvidenceAbsent: true },
    expected: TIMELINE_NO_GAME_ROOT_STATE.OMITTED_TERMINAL,
  },
  {
    name: 'timeline/rootあり（shadow期の手動提出）',
    summary: makePublished(), chainRoot: SENTINEL_ROOT, nowSec: ROOT_DEADLINE + 1,
    expected: TIMELINE_NO_GAME_ROOT_STATE.ROOT_SUBMITTED,
  },
  {
    name: 'zero_entries/rootなし',
    summary: { noGame: true, noGameReason: 'zero_entries' }, chainRoot: ZERO_ROOT,
    nowSec: ROOT_DEADLINE + 1, expected: TIMELINE_NO_GAME_ROOT_STATE.NOT_TIMELINE_NO_GAME,
  },
  {
    name: 'zero_entries/rootあり',
    summary: { noGame: true, noGameReason: 'zero_entries' }, chainRoot: SENTINEL_ROOT,
    nowSec: ROOT_DEADLINE + 1, expected: TIMELINE_NO_GAME_ROOT_STATE.NOT_TIMELINE_NO_GAME,
  },
  {
    name: '通常/rootなし',
    summary: { noGame: false }, chainRoot: ZERO_ROOT, nowSec: ROOT_DEADLINE + 1,
    expected: TIMELINE_NO_GAME_ROOT_STATE.NOT_TIMELINE_NO_GAME,
  },
  {
    name: '通常/rootあり',
    summary: { noGame: false }, chainRoot: SENTINEL_ROOT, nowSec: ROOT_DEADLINE + 1,
    expected: TIMELINE_NO_GAME_ROOT_STATE.NOT_TIMELINE_NO_GAME,
  },
];
for (const row of classificationRows) {
  const actual = classifyTimelineNoGameRoot({
    summary: row.summary,
    chainRoot: row.chainRoot,
    rootSubmissionDeadlineSec: ROOT_DEADLINE,
    nowSec: row.nowSec,
    proofRequired: true,
    verification: row.verification,
  });
  check(`Q46 共通分類: ${row.name} => ${row.expected}`, actual.state === row.expected, JSON.stringify(actual));
}
{
  const actual = classifyTimelineNoGameRoot({
    summary: makePublished(), chainRoot: ZERO_ROOT,
    rootSubmissionDeadlineSec: ROOT_DEADLINE, nowSec: ROOT_DEADLINE + 1,
  });
  check('Q51 summaryの名乗りだけはlabel_onlyで省略根拠にならない',
    actual.basisStrength === 'label_only' && actual.expectedRootOmission === false,
    JSON.stringify(actual));
}
for (const cause of EXPECTED_TIMELINE_NO_GAME_CAUSES) {
  const r = await runCase({ published: makePublished({ noGameCause: cause }) });
  check(`安全ブロックで許可原因 ${cause} の正式summaryを受理`,
    r.ok
      && r.checks.some((c) => c.id === 'check.stageC.timelineNoGameFinality' && c.status === 'pass')
      && r.checks.some((c) => c.id === 'check.stageC.timelineNoGameSummary' && c.status === 'pass'),
    JSON.stringify(r));
}
{
  const r = await runCase({ resultCount: 1 });
  check('Evidence が1件でもあれば no-game を拒否', !r.ok);
}
{
  const r = await runCase({ latest: 150n });
  check('confirmation-safe でない宣言ブロックを拒否', !r.ok);
}
{
  const r = await runCase({ published: makePublished({ noGameCause: 'unknown_cause' }) });
  check('許可されていない障害原因を拒否', !r.ok);
}
{
  const r = await runCase({
    published: makePublished({ schemaVersion: 2 }), emergencyMode: true,
  });
  check('P5 R30-A-6-02 緊急timeline no-game再構築は公開v2でもschemaVersion 3＋claimLayoutへ固定',
    r.S.timelineNoGameCanonical?.rebuilt?.schemaVersion === 3
      && r.S.timelineNoGameCanonical?.rebuilt?.claimLayout === 'group-overlays-v1'
      && r.checks.some((entry) => (
        entry.id === 'check.stageC.timelineNoGameSummary' && entry.status === 'fail'
      )), JSON.stringify({ canonical: r.S.timelineNoGameCanonical, checks: r.checks }));
}
{
  const r = await runCase({
    published: makePublished({ noGameCause: 'attacker_chosen' }), emergencyMode: true,
  });
  const finalityCheck = r.checks.find((entry) => entry.id === 'check.stageC.timelineNoGameFinality');
  check('P5 R30-A-4-03 許可外noGameCauseはwriter前に専用理由と復旧指示を伴うfailへする',
    r.ok === false
      && finalityCheck?.status === 'fail'
      && finalityCheck?.details?.reason === 'invalid_no_game_cause'
      && /manifest core/.test(String(finalityCheck?.details?.instruction || ''))
      && r.S.timelineNoGameCanonical?.invalidNoGameCause === true,
    JSON.stringify({ finalityCheck, canonical: r.S.timelineNoGameCanonical }));
}
{
  const r = await runCase({ published: makePublished({ noGameFinality: { safeTimestamp: 899 } }) });
  check('resultWindow終了前のsafe timestampを拒否', !r.ok);
}

// Q46: root=0 のときも専用 finality 検査へ到達し、期限と検査結果で exit を分ける。
{
  const r = await runRootlessCase();
  check('Q46 期限後・全検査合格はrootなし終端（exit 0）',
    r.category === 'full' && r.exitCode === 0
      && r.report.get('check.stageC.rootSubmitted')?.status === 'pass'
      && r.report.getFact('stageC.timelineNoGameRoot')?.state
        === TIMELINE_NO_GAME_ROOT_STATE.OMITTED_TERMINAL,
    JSON.stringify({ category: r.category, checks: r.report.list() }));
}
{
  const actual = await materializePublishedTimelineNoGame();
  const r = await runRootlessCase({
    published: actual.summary,
    gameGroups: VALID_GAME_GROUPS,
  });
  check('Q52 GMの実finalize出力はcleanup完了後も公開summaryへnoGameCleanupを足さない',
    actual.cleanup?.status === 'completed'
      && actual.rows.every((row) => row.status === 'invalidated_no_game')
      && actual.resetIds.length === 1
      && !Object.hasOwn(actual.summary, 'noGameCleanup'),
    JSON.stringify(actual));
  check('Q52 GMの実finalize出力をtimeline no-game検査へ渡すと期限後full（exit 0）',
    r.category === 'full' && r.exitCode === 0
      && r.report.get('check.stageC.timelineNoGameSummary')?.status === 'pass',
    JSON.stringify(r.report.list()));
}
{
  const r = await runRootlessCase({ gameGroups: VALID_GAME_GROUPS, roster: true });
  check('Q51 game_groups/rosterはあるがチャット開始証拠が無い正直な期限後ブロックはfull（exit 0）',
    r.category === 'full' && r.exitCode === 0
      && r.report.get('check.stageC.timelineNoGameChatNotStarted')?.status === 'pass',
    JSON.stringify(r.report.list()));
}
{
  const r = await runRootPresentChatCheck();
  check('R3 rootありtimeline no-gameは開始証拠が無ければChatNotStartedをPASS',
    r.result.chatNotStarted === true
      && r.report.get('check.stageC.timelineNoGameChatNotStarted')?.status === 'pass'
      && r.result.chatArtifacts.evidenceKeys.length === 0
      && r.ctx.data.stopReason !== 'fail',
    JSON.stringify(r.report.list()));
}
{
  const r = await runRootPresentChatCheck({ groupResult: true });
  check('R3 rootありtimeline no-gameでも完了済みgroup結果があればFAIL',
    r.result.chatNotStarted === false
      && r.report.get('check.stageC.timelineNoGameChatNotStarted')?.status === 'fail'
      && r.result.chatArtifacts.evidenceKeys.length > 0
      && r.ctx.data.stopReason === 'fail',
    JSON.stringify(r.report.list()));
}
{
  const emergencyDir = path.resolve(
    import.meta.dirname,
    `../../tmp/M11a/v25-emergency-unknown-groups-${process.pid}`,
  );
  await fs.rm(emergencyDir, { recursive: true, force: true });
  const relative = '_observer/generations/p5/unknown-group-artifact.bin';
  const raw = '{}';
  await fs.mkdir(path.dirname(path.join(emergencyDir, relative)), { recursive: true });
  await fs.writeFile(path.join(emergencyDir, relative), raw);
  const row = {
    savedFile: relative,
    sha256: createHash('sha256').update(raw).digest('hex'),
    generation: 1,
    observationOrdinal: '00000000:00000000',
  };
  const keys = [
    `games/block${N}/group7.json`,
    `live/block${N}/group7.submissions.json`,
    `live/block${N}/group7.json`,
  ];
  const outcomes = [];
  for (const key of keys) {
    outcomes.push(await runRootPresentChatCheck({
      gameGroups: null,
      emergencyGroupsDerived: null,
      emergencySource: { sourceDir: emergencyDir, index: { objects: { [key]: [row] } } },
    }));
  }
  const empty = await runRootPresentChatCheck({
    gameGroups: null,
    emergencyGroupsDerived: null,
    emergencySource: { sourceDir: emergencyDir, index: { objects: {} } },
  });
  check('M4: 群不明の空archive／提出写しは存在だけで開始証拠に数えない',
    outcomes.slice(0, 2).every((outcome) => (
      outcome.result.chatNotStarted === true
      && outcome.result.chatArtifacts.evidenceKeys.length === 0
      && outcome.ctx.data.stopReason !== 'fail'
    )), JSON.stringify(outcomes.map((outcome) => outcome.result.chatArtifacts)));
  check('P8b P5: 群不明のlive群ファイルは存在だけでは開始証拠に数えない',
    outcomes[2].result.chatNotStarted === true
      && outcomes[2].result.chatArtifacts.evidenceKeys.length === 0
      && outcomes[2].ctx.data.stopReason !== 'fail',
    JSON.stringify(outcomes[2].result.chatArtifacts));
  check('P5 R30-A-4-04 群不明かつ索引にも開始証拠が無い正直な盤面はPASSを保つ',
    empty.result.chatNotStarted === true
      && empty.result.chatArtifacts.evidenceKeys.length === 0
      && empty.ctx.data.stopReason !== 'fail',
    JSON.stringify(empty.result.chatArtifacts));
  await fs.rm(emergencyDir, { recursive: true, force: true });
}
{
  const emergencyDir = path.resolve(
    import.meta.dirname,
    `../../tmp/M11a/v25-emergency-chat-artifacts-${process.pid}`,
  );
  await fs.rm(emergencyDir, { recursive: true, force: true });
  const relative = '_observer/generations/live/group0-chatting.bin';
  const filename = path.join(emergencyDir, relative);
  const raw = JSON.stringify({ phase: 'chatting', messages: [] });
  await fs.mkdir(path.dirname(filename), { recursive: true });
  await fs.writeFile(filename, raw);
  const emergencySource = {
    sourceDir: emergencyDir,
    index: {
      objects: {
        [`live/block${N}/group0.json`]: [{
          savedFile: relative,
          sha256: createHash('sha256').update(raw).digest('hex'),
          generation: 1,
          observationOrdinal: '00000000:00000000',
        }],
      },
    },
  };
  const r = await runRootPresentChatCheck({ emergencySource });
  check('U4-C5 緊急rootありは無署名phaseだけのlive世代を差として記録し、開始証拠に数えない',
    r.result.chatNotStarted === true
      && r.report.get('check.stageC.timelineNoGameChatNotStarted')?.status === 'pass'
      && r.ctx.data.stopReason !== 'fail'
      && r.ctx.data.emergencyDifferences?.some((difference) => (
        difference.what.includes('unsigned live snapshot fields')
      )),
    JSON.stringify({ checks: r.report.list(), differences: r.ctx.data.emergencyDifferences }));
  await fs.rm(emergencyDir, { recursive: true, force: true });
}
{
  const emergencyDir = path.resolve(
    import.meta.dirname,
    `../../tmp/M11a/v25-emergency-known-groups-${process.pid}`,
  );
  await fs.rm(emergencyDir, { recursive: true, force: true });
  const relative = '_observer/generations/p8b/known-group-artifact.bin';
  const raw = '{}';
  await fs.mkdir(path.dirname(path.join(emergencyDir, relative)), { recursive: true });
  await fs.writeFile(path.join(emergencyDir, relative), raw);
  const row = {
    savedFile: relative,
    sha256: createHash('sha256').update(raw).digest('hex'),
    generation: 1,
    observationOrdinal: '00000000:00000000',
  };
  const archive = await runRootPresentChatCheck({
    emergencySource: {
      sourceDir: emergencyDir,
      index: { objects: { [`games/block${N}/group0.json`]: [row] } },
    },
  });
  const submissions = await runRootPresentChatCheck({
    emergencySource: {
      sourceDir: emergencyDir,
      index: { objects: { [`live/block${N}/group0.submissions.json`]: [row] } },
    },
  });
  check('M4: 群既知の空archiveと提出写しも存在だけで開始証拠に数えない',
    [archive, submissions].every((outcome) => (
      outcome.result.chatNotStarted === true
      && outcome.result.chatArtifacts.evidenceKeys.length === 0
      && outcome.ctx.data.stopReason !== 'fail'
    )), JSON.stringify([archive.result.chatArtifacts, submissions.result.chatArtifacts]));
  const anchoredRaw = JSON.stringify({
    meta: { blockNum: N, groupId: 0 }, members: [], messages: [],
  });
  const anchoredRelative = '_observer/generations/p8b/anchored-group.bin';
  await fs.writeFile(path.join(emergencyDir, anchoredRelative), anchoredRaw);
  const anchoredHash = createHash('sha256').update(anchoredRaw).digest('hex');
  const anchoredKey = `games/block${N}/group0.json`;
  const anchored = await runRootPresentChatCheck({
    gameGroups: { groups: [{ groupId: 7 }], totalGroups: 1 },
    emergencyGroupsDerived: [{ groupId: 0 }],
    emergencySource: { sourceDir: emergencyDir, index: { objects: {
      [anchoredKey]: [{ ...row, savedFile: anchoredRelative, sha256: anchoredHash }],
    } }, chainResultMarker: { hash: manifestCoreHash({
      blockNum: N, algorithm: 'sha256', rules: {}, files: { [anchoredKey]: anchoredHash },
    }) } },
    manifestFiles: { [anchoredKey]: anchoredHash },
  });
  check('M4: manifest宣言shaに錨づいた構造ある群archiveは開始証拠になり、群集合はgroupsDerivedに従う',
    anchored.result.chatNotStarted === false
    && JSON.stringify(anchored.result.chatArtifacts.groupIds) === '[0]'
    && anchored.result.chatArtifacts.evidenceKeys.length === 1,
    JSON.stringify(anchored.result.chatArtifacts));
  async function malformedAnchoredArchive(label, data, declaredHash = null) {
    const rawData = JSON.stringify(data);
    const relativeData = `_observer/generations/p8b/m11a-${label}.bin`;
    await fs.writeFile(path.join(emergencyDir, relativeData), rawData);
    const actualHash = createHash('sha256').update(rawData).digest('hex');
    const declared = declaredHash || actualHash;
    return runRootPresentChatCheck({
      emergencyGroupsDerived: [{ groupId: 0 }],
      emergencySource: { sourceDir: emergencyDir, index: { objects: {
        [anchoredKey]: [{ ...row, savedFile: relativeData, sha256: actualHash }],
      } }, chainResultMarker: { hash: manifestCoreHash({
        blockNum: N, algorithm: 'sha256', rules: {}, files: { [anchoredKey]: declared },
      }) } },
      manifestFiles: { [anchoredKey]: declared },
    });
  }
  for (const [label, data, declared] of [
    ['sha', { meta: { blockNum: N, groupId: 0 }, members: [], messages: [] }, 'ff'.repeat(32)],
    ['group-id', { meta: { blockNum: N, groupId: 7 }, members: [], messages: [] }, null],
    ['messages', { meta: { blockNum: N, groupId: 0 }, members: [] }, null],
  ]) {
    const outcome = await malformedAnchoredArchive(label, data, declared);
    check(`M11a: 錨つき群archive ${label} 不一致は開始証拠にならない`,
      outcome.result.chatNotStarted === true
        && outcome.result.chatArtifacts.evidenceKeys.length === 0);
  }
  const unknownKey = `games/block${N}/group7.json`;
  const unknownRaw = JSON.stringify({
    meta: { blockNum: N, groupId: 7 }, members: [], messages: [],
  });
  const unknownRelative = '_observer/generations/p8b/m11a-unknown-group.bin';
  await fs.writeFile(path.join(emergencyDir, unknownRelative), unknownRaw);
  const unknownHash = createHash('sha256').update(unknownRaw).digest('hex');
  const unknown = await runRootPresentChatCheck({
    emergencyGroupsDerived: [{ groupId: 0 }],
    emergencySource: { sourceDir: emergencyDir, index: { objects: {
      [unknownKey]: [{ ...row, savedFile: unknownRelative, sha256: unknownHash }],
    } }, chainResultMarker: { hash: manifestCoreHash({
      blockNum: N, algorithm: 'sha256', rules: {}, files: { [unknownKey]: unknownHash },
    }) } },
    manifestFiles: { [unknownKey]: unknownHash },
  });
  check('M11a: 既知群の外にある群archiveは開始証拠にならない',
    unknown.result.chatNotStarted === true && unknown.result.chatArtifacts.evidenceKeys.length === 0);
  const unanchored = await runRootPresentChatCheck({
    emergencySource: { sourceDir: emergencyDir, authority: 'gcp',
      chainResultMarker: { hash: `0x${'00'.repeat(32)}` }, index: { objects: {
        [anchoredKey]: [{ ...row, savedFile: anchoredRelative, sha256: anchoredHash }],
      } } },
    manifestFiles: { [anchoredKey]: anchoredHash },
  });
  check('M4: GCP合成manifestのsha宣言だけでは群archiveを開始証拠にしない',
    unanchored.result.chatNotStarted === true
    && unanchored.result.chatArtifacts.evidenceKeys.length === 0,
    JSON.stringify(unanchored.result.chatArtifacts));
  await fs.rm(emergencyDir, { recursive: true, force: true });
}
{
  const r = await runRootPresentChatCheck({
    emergencySource: { sourceDir: path.resolve(import.meta.dirname, '../../tmp/M11a'), index: { objects: {} } },
    emergencySubmissionCandidates: [{
      key: `live/block${N}/group0.submissions.json`, uid: 'a', valid: true,
    }],
  });
  check('R3 緊急rootありは完全検証済みの保存提出も開始証拠に数えてFAIL',
    r.result.chatNotStarted === false
      && r.report.get('check.stageC.timelineNoGameChatNotStarted')?.status === 'fail'
      && r.ctx.data.stopReason === 'fail',
    JSON.stringify(r.report.list()));
  const invalid = await runRootPresentChatCheck({
    emergencySource: { sourceDir: path.resolve(import.meta.dirname, '../../tmp/M11a'), index: { objects: {} } },
    emergencySubmissionCandidates: [{ valid: false, key: `live/block${N}/group0.submissions.json` }],
  });
  check('M4: valid:false の保存提出は開始証拠にならない',
    invalid.result.chatNotStarted === true && invalid.result.chatArtifacts.evidenceKeys.length === 0);
}
{
  const r = await runRootPresentChatCheck({
    emergencySource: {
      sourceDir: path.resolve(import.meta.dirname, '../../tmp/M11a'),
      index: {
        objects: {
          [`live/block${N}/group0.json`]: [{
            savedFile: 'missing-live-generation.bin',
            sha256: '00'.repeat(32),
            generation: 1,
            observationOrdinal: '00000000:00000000',
          }],
        },
      },
    },
  });
  check('U4-C5 緊急rootありは読めない保存世代を差に留め、開始証拠に格上げしない',
    r.result.chatNotStarted === true
      && r.report.get('check.stageC.timelineNoGameChatNotStarted')?.status === 'pass'
      && r.ctx.data.stopReason !== 'fail'
      && r.ctx.data.emergencyDifferences?.some((difference) => (
        difference.what.includes('unreadable archived chat generation')
      )),
    JSON.stringify({ checks: r.report.list(), differences: r.ctx.data.emergencyDifferences }));
}
{
  const emergencyDir = path.resolve(
    import.meta.dirname,
    `../../tmp/M11a/v25-emergency-signed-chat-${process.pid}`,
  );
  await fs.rm(emergencyDir, { recursive: true, force: true });
  const signer = privateKeyToAccount(`0x${'41'.repeat(32)}`);
  const timestamp = 1_700_000_000_000;
  const text = 'chat started';
  const message = {
    uid: 'a', text, timestamp,
    signature: await signer.signMessage({
      message: chatSignStringV2(N, 0, 'a', text, timestamp),
    }),
  };
  const relative = '_observer/generations/live/group0-signed.bin';
  const filename = path.join(emergencyDir, relative);
  const raw = JSON.stringify({ phase: 'waiting', messages: [message] });
  await fs.mkdir(path.dirname(filename), { recursive: true });
  await fs.writeFile(filename, raw);
  const emergencySource = {
    sourceDir: emergencyDir,
    index: {
      objects: {
        [`live/block${N}/group0.json`]: [{
          savedFile: relative,
          sha256: createHash('sha256').update(raw).digest('hex'),
          generation: 1,
          observationOrdinal: '00000000:00000000',
        }],
      },
    },
  };
  const r = await runRootPresentChatCheck({
    emergencySource,
    emergencySelectionPlayers: [{ data: { uid: 'a', bAddr: JSON.stringify({ address: signer.address }) } }],
    emergencyGroupsDerived: [{
      groupId: 0,
      members: [{ data: { uid: 'a', bAddr: JSON.stringify({ address: signer.address }) } }],
    }],
  });
  check('U4-C5 緊急rootありは署名検証済みメッセージを開始証拠に数えてFAIL',
    r.result.chatNotStarted === false
      && r.report.get('check.stageC.timelineNoGameChatNotStarted')?.status === 'fail'
      && r.result.chatArtifacts.evidenceKeys.some((key) => key.includes(' signedMessages=1'))
      && r.ctx.data.stopReason === 'fail',
    JSON.stringify({ checks: r.report.list(), artifacts: r.result.chatArtifacts }));
  const wrongSigner = privateKeyToAccount(`0x${'42'.repeat(32)}`);
  const forgedRaw = JSON.stringify({ phase: 'waiting', messages: [{
    ...message,
    signature: await wrongSigner.signMessage({
      message: chatSignStringV2(N, 0, 'a', text, timestamp),
    }),
  }] });
  const forgedRelative = '_observer/generations/live/m11a-wrong-signature.bin';
  await fs.writeFile(path.join(emergencyDir, forgedRelative), forgedRaw);
  const forged = await runRootPresentChatCheck({
    emergencySource: { sourceDir: emergencyDir, index: { objects: {
      [`live/block${N}/group0.json`]: [{
        savedFile: forgedRelative,
        sha256: createHash('sha256').update(forgedRaw).digest('hex'),
        generation: 1, observationOrdinal: '00000000:00000000',
      }],
    } } },
    emergencySelectionPlayers: [{ data: { uid: 'a', bAddr: JSON.stringify({ address: signer.address }) } }],
    emergencyGroupsDerived: [{ groupId: 0 }],
  });
  check('M11a: 別鍵の署名を載せた live 発言は開始証拠にならない',
    forged.result.chatNotStarted === true && forged.result.chatArtifacts.evidenceKeys.length === 0);
  const lateSignedRaw = JSON.stringify({ phase: 'waiting', messages: [
    ...Array.from({ length: 1_000 }, () => ({ uid: 'a', text: 'unsigned', timestamp,
      signature: 'invalid' })), message,
  ] });
  const lateSignedRelative = '_observer/generations/live/m11a-late-signed.bin';
  await fs.writeFile(path.join(emergencyDir, lateSignedRelative), lateSignedRaw);
  const lateSigned = await runRootPresentChatCheck({
    emergencySource: { sourceDir: emergencyDir, index: { objects: {
      [`live/block${N}/group0.json`]: [{ savedFile: lateSignedRelative,
        sha256: createHash('sha256').update(lateSignedRaw).digest('hex'), generation: 1 }],
    } } },
    emergencySelectionPlayers: [{ data: { uid: 'a', bAddr: JSON.stringify({ address: signer.address }) } }],
  });
  check('M11a: live 発言の署名検証は先頭1000件に限る',
    lateSigned.result.chatNotStarted === true && lateSigned.result.chatArtifacts.evidenceKeys.length === 0);
  const unknownSigned = await runRootPresentChatCheck({
    gameGroups: null, emergencyGroupsDerived: null, emergencySource,
    emergencySelectionPlayers: [{ data: { uid: 'a', bAddr: JSON.stringify({ address: signer.address }) } }],
  });
  check('M4: 群不明でもStage B選出者の署名済みlive発言は開始証拠になる',
    unknownSigned.result.chatNotStarted === false
    && unknownSigned.result.chatArtifacts.evidenceKeys.length === 1,
    JSON.stringify(unknownSigned.result.chatArtifacts));
  const emptyRelative = '_observer/generations/live/m4-empty.bin';
  await fs.writeFile(path.join(emergencyDir, emptyRelative), '{}');
  const paged = await runRootPresentChatCheck({
    gameGroups: null, emergencyGroupsDerived: null,
    emergencySelectionPlayers: [{ data: { uid: 'a', bAddr: JSON.stringify({ address: signer.address }) } }],
    emergencySource: { sourceDir: emergencyDir, index: { objects: {
      [`live/block${N}/group0.json`]: [
        ...Array.from({ length: 256 }, (_, i) => ({
          savedFile: emptyRelative, sha256: createHash('sha256').update('{}').digest('hex'),
          generation: i + 1, observationOrdinal: String(i + 1).padStart(8, '0'),
        })),
        { ...emergencySource.index.objects[`live/block${N}/group0.json`][0],
          generation: 257, observationOrdinal: '00000257' },
      ],
    } } },
  });
  check('M4: 256世代の後にある署名済みlive発言もページ送りで検査する',
    paged.result.chatNotStarted === false && paged.result.chatArtifacts.evidenceKeys.length === 1,
    JSON.stringify(paged.result.chatArtifacts));

  const largeRelative = '_observer/generations/live/m4-large.bin';
  const largeRaw = JSON.stringify({ blob: 'x'.repeat(6 * 1024 * 1024) });
  await fs.writeFile(path.join(emergencyDir, largeRelative), largeRaw);
  const largeHash = createHash('sha256').update(largeRaw).digest('hex');
  const largeKey = `live/block${N}/group0.json`;
  const largeIndex = { objects: { [largeKey]: Array.from({ length: 3 }, (_, i) => ({
    savedFile: largeRelative, sha256: largeHash, bytes: Buffer.byteLength(largeRaw),
    generation: i + 1, observationOrdinal: String(i + 1).padStart(8, '0'),
  })) } };
  const largeFirst = (await readEmergencyArtifactGenerations({
    sourceDir: emergencyDir, index: largeIndex, keys: [largeKey],
  })).get(largeKey);
  const largeSecond = (await readEmergencyArtifactGenerations({
    sourceDir: emergencyDir, index: largeIndex, keys: [largeKey], offset: 1,
  })).get(largeKey);
  check('M4: live写しのページは合計バイト数で区切り後続世代へ進む',
    largeFirst.generations.length === 1 && largeFirst.hasMore === true
    && largeSecond.generations.length === 1 && largeSecond.hasMore === true);

  const depthRaw = '['.repeat(300) + '0' + ']'.repeat(300);
  const depthRelative = '_observer/generations/live/m11a-deep.bin';
  await fs.writeFile(path.join(emergencyDir, depthRelative), depthRaw);
  const statRelative = '_observer/generations/live/m11a-stat-large.bin';
  await fs.writeFile(path.join(emergencyDir, statRelative), '');
  await fs.truncate(path.join(emergencyDir, statRelative), 9 * 1024 * 1024);
  await fs.chmod(path.join(emergencyDir, statRelative), 0o000);
  const guardIndex = { objects: { [largeKey]: [
    { savedFile: '_observer/generations/live/m11a-absent.bin',
      sha256: '0'.repeat(64), bytes: 9 * 1024 * 1024, generation: 1 },
    { savedFile: statRelative, sha256: '0'.repeat(64), bytes: 1, generation: 2 },
    { savedFile: depthRelative, sha256: createHash('sha256').update(depthRaw).digest('hex'),
      bytes: Buffer.byteLength(depthRaw), generation: 3 },
    { savedFile: emptyRelative, sha256: createHash('sha256').update('{}').digest('hex'),
      bytes: 2, generation: 4 },
  ] } };
  const guarded = (await readEmergencyArtifactGenerations({
    sourceDir: emergencyDir, index: guardIndex, keys: [largeKey],
  })).get(largeKey);
  check('M11a: live 世代の宣言・stat・深さの各関所は悪い世代だけを外す',
    guarded.generations.map((item) => item.error).join(',')
      === 'archive_byte_limit,archive_byte_limit,archive_depth_limit,'
    && guarded.generations[3].data && Object.keys(guarded.generations[3].data).length === 0);
  const pageIndex = { objects: { [largeKey]: Array.from({ length: 17 }, (_, i) => ({
    savedFile: emptyRelative, sha256: createHash('sha256').update('{}').digest('hex'),
    bytes: 2, generation: i + 1, observationOrdinal: String(i + 1).padStart(8, '0'),
  })) } };
  const firstPage = (await readEmergencyArtifactGenerations({
    sourceDir: emergencyDir, index: pageIndex, keys: [largeKey],
  })).get(largeKey);
  const lastPage = (await readEmergencyArtifactGenerations({
    sourceDir: emergencyDir, index: pageIndex, keys: [largeKey], offset: 16,
  })).get(largeKey);
  check('M11a: live 写し17世代は16世代と1世代の2ページで読む',
    firstPage.generations.length === 16 && firstPage.hasMore === true
    && lastPage.generations.length === 1 && lastPage.hasMore === false);
  const invalidRelative = '_observer/generations/live/m11a-invalid.bin';
  await fs.writeFile(path.join(emergencyDir, invalidRelative), '{');
  const ignoredIndex = { objects: { [largeKey]: Array.from({ length: 17 }, (_, i) => ({
    savedFile: invalidRelative, sha256: createHash('sha256').update('{').digest('hex'),
    bytes: 1, generation: i + 1, observationOrdinal: String(i + 1).padStart(8, '0'),
  })) } };
  const ignored = await runRootPresentChatCheck({
    gameGroups: null, emergencyGroupsDerived: null,
    emergencySource: { sourceDir: emergencyDir, index: ignoredIndex },
  });
  const ignoredNotes = ignored.ctx.data.emergencyDifferences?.filter((difference) =>
    difference.what === 'unreadable archived chat generation is ignored') || [];
  check('M11a: 同じ読取不能理由の17世代は差分1件と件数17へまとめる',
    ignored.result.chatNotStarted === true && ignoredNotes.length === 1
    && ignoredNotes[0].rebuilt.ignoredGenerations === 17);

  const members = ['a', 'b', 'c'].map((uid, index) => ({
    uid,
    addr: `0x${String(index + 1).padStart(40, '0')}`,
    bAddr: JSON.stringify({ address: signer.address }),
    depIds: JSON.stringify({ deposit: '10000000000000000' }),
  }));
  const baseGroupData = {
    members,
    meta: { blockNum: N, groupId: 0 },
    submissions: {},
    submissionsRaw: {},
    verifiedDepositWei: Object.fromEntries(members.map(({ uid }) => [uid, '10000000000000000'])),
  };
  const withoutChat = await calculateGroupResults(structuredClone(baseGroupData), 500, 20, {});
  const withSignedButUnsubmittedChat = await calculateGroupResults({
    ...structuredClone(baseGroupData),
    messages: [message],
  }, 500, 20, {});
  check('U4-C5 チャットは始まったが誰も提出しない場合は全員失格・配布なしで結果不変',
    JSON.stringify(withSignedButUnsubmittedChat) === JSON.stringify(withoutChat)
      && withSignedButUnsubmittedChat.results.length === 3
      && withSignedButUnsubmittedChat.results.every((row) => (
        row.isDisqualified === true
          && row.disqualifyReason === 'no_submit'
          && row.totalPoints === 0
      )),
    JSON.stringify({ withoutChat, withSignedButUnsubmittedChat }));
  await fs.rm(emergencyDir, { recursive: true, force: true });
}
{
  const r = await runRootlessCase({ gameGroups: VALID_GAME_GROUPS, nowSec: ROOT_DEADLINE });
  check('Q51 game_groupsはあるがチャット開始証拠が無い正直な期限内ブロックはpartial（exit 1）',
    r.category === 'partial' && r.exitCode === 1,
    JSON.stringify(r.report.list()));
}
{
  const r = await runRootlessCase({ gameGroups: VALID_GAME_GROUPS, groupResult: true });
  check('Q51 group結果があればtimeline no-game root省略をFAIL（exit 2）',
    r.category === 'fail' && r.exitCode === 2
      && r.report.get('check.stageC.timelineNoGameChatNotStarted')?.status === 'fail',
    JSON.stringify(r.report.list()));
}
{
  const r = await runRootlessCase({ gameGroups: VALID_GAME_GROUPS, liveSubmissions: true });
  check('Q51 live submissionsがあればtimeline no-game root省略をFAIL（exit 2）',
    r.category === 'fail' && r.exitCode === 2
      && r.report.get('check.stageC.timelineNoGameChatNotStarted')?.status === 'fail',
    JSON.stringify(r.report.list()));
}
{
  const r = await runRootlessCase({
    gameGroups: VALID_GAME_GROUPS,
    liveSnapshot: {
      phase: 'waiting', messages: [], charCounts: { a: 0 }, messageCounts: { a: 0 },
      phaseTimestamps: { waitingAt: '2026-09-17T00:00:00.000Z' },
      actions: { votes: {}, reports: {} }, receipts: [], submittedUids: [], gameSkipped: null,
    },
  });
  check('Q51 空のwaiting live snapshotはチャット開始証拠に数えない（exit 0）',
    r.category === 'full' && r.exitCode === 0,
    JSON.stringify(r.report.list()));
}
{
  const r = await runRootlessCase({
    gameGroups: VALID_GAME_GROUPS,
    liveSnapshot: { phase: 'chatting', messages: [], phaseTimestamps: { chattingAt: 1 } },
  });
  check('Q51 chatting live snapshotはtimeline no-game root省略をFAIL（exit 2）',
    r.category === 'fail' && r.exitCode === 2
      && r.report.get('check.stageC.timelineNoGameChatNotStarted')?.status === 'fail',
    JSON.stringify(r.report.list()));
}
{
  const r = await runTimelineGroupingMismatch();
  check('Q51 timeline no-gameでもgame_groupsを再導出し構成不一致をFAIL（exit 2）',
    r.category === 'fail' && r.exitCode === 2
      && r.report.get('check.stageB.groupsMatch')?.status === 'fail',
    JSON.stringify(r.report.list()));
}
{
  const r = await runRootlessCase({ nowSec: ROOT_DEADLINE });
  check('Q46 期限内（等号を含む）はroot省略予定のpartial（exit 1）',
    r.category === 'partial' && r.exitCode === 1
      && r.report.get('check.stageC.rootSubmitted')?.params?.reason === 'timeline_no_game_deadline_open',
    JSON.stringify({ category: r.category, checks: r.report.list() }));
}
{
  const r = await runRootlessCase({ resultCount: 1 });
  check('Q46 Evidence resultCount≠0 はFAIL（exit 2）',
    r.category === 'fail' && r.exitCode === 2,
    JSON.stringify(r.report.list()));
}
{
  const r = await runRootlessCase({ safeTimestamp: 899n });
  check('Q46 結果窓がsafe blockで閉じていなければFAIL（exit 2）',
    r.category === 'fail' && r.exitCode === 2,
    JSON.stringify(r.report.list()));
}
{
  const r = await runRootlessCase({ selectedPlayers: 4 });
  check('Q46 Stage B再導出人数とsummaryが不一致ならFAIL（exit 2）',
    r.category === 'fail' && r.exitCode === 2,
    JSON.stringify(r.report.list()));
}
{
  const r = await runRootlessCase({
    published: makePublished({ groups: [{ group_id: 1 }], totalGroups: 1 }),
  });
  check('Q46 timeline summaryの形が崩れていればFAIL（exit 2）',
    r.category === 'fail' && r.exitCode === 2,
    JSON.stringify(r.report.list()));
}
{
  const r = await runRootlessCase({ resultCount: 1 });
  check('Q46 結果提出がある通常ゲームをtimeline no-gameと名乗ってもFAIL',
    r.category === 'fail'
      && r.report.get('check.stageC.timelineNoGameEvidenceEmpty')?.status === 'fail',
    JSON.stringify(r.report.list()));
}

await fs.rm(p6StageBRoot, { recursive: true, force: true });
console.log('');
if (failed) {
  console.error(`v25-timeline-no-game-unit: ${failed} FAILED (${passed} passed)`);
  process.exit(1);
}
console.log(`v25-timeline-no-game-unit: ALL PASSED (${passed} checks)`);

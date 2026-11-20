// VTL-01: 選出後に game_groups が欠けても、空の探索集合を未開始の証明にしない。
import assert from 'node:assert/strict';
import { categorize } from '../src/index.js';
import { createReport } from '../src/report.js';
import { hashLikeBackend } from '../src/json-utils.js';
import { run as runSelection } from '../src/stages/selection.js';
import { run as runGrouping } from '../src/stages/grouping.js';
import {
  run as runResults,
  verifyTimelineNoGameRootOmission,
  verifyTimelineNoGameRootPresentChatGate,
} from '../src/stages/results.js';
import { getBlockRewardWei } from '../vendor/workers/game_workers/lib/game-result-calculator.js';
import { adminCommitRootSubmissionDeadline } from '../vendor/workers/game_workers/lib/block-lifecycle.js';

const N = 7;
const EVIDENCE = `0x${'12'.repeat(20)}`;
const selection = { blockNum: N, players: [{}, {}, {}] };
const groups = { groups: [{ groupId: 7 }], totalGroups: 1 };
const afterDeadline = BigInt(adminCommitRootSubmissionDeadline(900, 100) + 1);
const summary = {
  schemaVersion: 2,
  blockNum: N,
  blockReward: getBlockRewardWei(N).toString(),
  totalPlayers: 3,
  totalGroups: 0,
  noGame: true,
  majorLangs: [],
  groups: [],
  claimStatusKey: `games/block${N}/claim-status.json`,
  noGameReason: 'timeline_unverified',
  noGameCause: 'chain_unreadable',
  noGameFinality: {
    schemaVersion: 1,
    evidenceContract: EVIDENCE,
    safeBlockNumber: '136',
    safeTimestamp: 1000,
    resultOpenAt: 800,
    resultCloseAt: 900,
    resultCount: 0,
  },
};

function json(data) { return { data, raw: JSON.stringify(data) }; }

async function runCase({ selectionRecord = null, groupRecord = null,
  selectionThrows = false, groupThrows = false,
  stageBVerified = selectionRecord !== null,
  rosterRegistration = 'legacy', summaryData = summary,
  liveSnapshot = { phase: 'chatting', phaseTimestamps: { chattingAt: 1 } } } = {}) {
  const report = createReport();
  if (stageBVerified) report.check('check.stageB.playersMatch', 'pass', { count: 3 });
  const fetched = [];
  const ctx = {
    blockNum: N,
    cfg: { pins: { confirmationBlocks: 64 } },
    data: { gameSelection: selection },
    report,
    r2: {
      async fetchJson(key) {
        fetched.push(key);
        if (key === `games/block${N}/summary.json`) return json(summaryData);
        if (key === `entries/block${N}/game_groups.json`) {
          if (groupThrows) throw new Error('groups read failed');
          return groupRecord;
        }
        if (key === `entries/block${N}/game_selection.json`) {
          if (selectionThrows) throw new Error('selection read failed');
          return selectionRecord;
        }
        if (key === `live/block${N}/group7.json`) {
          return json(liveSnapshot);
        }
        return null;
      },
    },
    chain: {
      latest: async () => ({ number: 200n, timestamp: afterDeadline }),
      findBlockByTimestamp: async () => 90,
      getBlock: async () => ({ timestamp: 1000n }),
      resultWindow: async () => ({ openAt: 800n, closeAt: 900n }),
      resultCount: async () => 0n,
      evidenceAddress: async () => EVIDENCE,
      verificationPeriod: async () => 100,
      getTimingConstants: async () => ({ startTimeEntryMs: 0, blockTimeMs: 62_500,
        gamePeriodMs: 200_000 }),
      currentGrace: async () => 100,
      ...(rosterRegistration === 'legacy' ? {} : {
        otherRegistrationCount: async () => {
          if (rosterRegistration === 'unreadable') throw new Error('roster RPC unavailable');
          return rosterRegistration === 'present' ? 1 : 0;
        },
        otherRegistrationAt: async () => ({ hash: `0x${'34'.repeat(32)}`,
          registeredBlock: 80, registeredAt: 550 }),
      }),
    },
  };
  const S = { anomalies: [], zkInfo: { currentProofRequired: true } };
  const result = await verifyTimelineNoGameRootOmission(ctx, S);
  return { report, fetched, ctx, result,
    category: categorize({ fatal: false, report, stopped: result.stop }) };
}

const attack = await runCase({ selectionRecord: json(selection) });
assert.equal(attack.report.get('check.stageC.timelineNoGameChatNotStarted').status, 'warn');
assert.equal(attack.report.get('check.stageC.rootSubmitted').status, 'warn');
assert.equal(attack.category, 'partial');
assert.equal(attack.result.stop, true);
assert.equal(attack.fetched.includes(`live/block${N}/group7.json`), false);
console.log('VTL-01 A: 選出後・組一覧なし・開始済み live・no-game は未検証: PASS');

const registeredAttack = await runCase({ selectionRecord: json(selection), rosterRegistration: 'present' });
assert.equal(registeredAttack.report.get('check.stageC.timelineNoGameChatNotStarted').status, 'warn');
assert.equal(registeredAttack.report.get('check.stageC.rootSubmitted').status, 'warn');
assert.equal(registeredAttack.category, 'partial');
console.log('FIX3 N1-b: 開始前登録あり・組一覧なしは VTL-01 の warn を維持: PASS');

const unreadableRoster = await runCase({ selectionRecord: json(selection), rosterRegistration: 'unreadable' });
assert.equal(unreadableRoster.report.get('check.stageC.timelineNoGameChatNotStarted').status, 'warn');
assert.equal(unreadableRoster.report.get('check.stageC.rootSubmitted').status, 'warn');
assert.equal(unreadableRoster.category, 'partial');
console.log('FIX3 N1-c: 名簿登録の読取不能は warn: PASS');

const schemaFailureWithWarn = await runCase({ selectionRecord: json(selection),
  rosterRegistration: 'unreadable', summaryData: { ...summary, noGameFinality: null } });
assert.equal(schemaFailureWithWarn.report.get('check.stageC.timelineNoGameChatNotStarted').status, 'warn');
assert.equal(schemaFailureWithWarn.report.get('check.stageC.timelineNoGameFinality').status, 'fail');
assert.equal(schemaFailureWithWarn.report.get('check.stageC.rootSubmitted').status, 'fail');
assert.equal(schemaFailureWithWarn.report.get('check.stageC.rootSubmitted').params.reason,
  'timeline_no_game_finality_failed');
console.log('FIX3 N8: chat 未検証と finality schema 失敗の重畳は finality を理由にする: PASS');

const beforeSelection = await runCase();
assert.equal(beforeSelection.report.get('check.stageC.timelineNoGameChatNotStarted').status, 'pass');
assert.equal(beforeSelection.report.get('check.stageC.rootSubmitted').status, 'pass');
assert.equal(beforeSelection.category, 'full');
console.log('VTL-01 B: 選出前・記録なしの正直な no-game は従来どおり: PASS');

const honestGroups = await runCase({ selectionRecord: json(selection), groupRecord: json(groups) });
assert.equal(honestGroups.report.get('check.stageC.timelineNoGameChatNotStarted').status, 'fail');
assert.equal(honestGroups.category, 'fail');
assert.equal(honestGroups.fetched.includes(`live/block${N}/group7.json`), true);
console.log('VTL-01 C1: 組一覧がある開始済み live の既存 FAIL は維持: PASS');

const honestWaiting = await runCase({ selectionRecord: json(selection), groupRecord: json(groups),
  liveSnapshot: { phase: 'waiting', messages: [] } });
assert.equal(honestWaiting.report.get('check.stageC.timelineNoGameChatNotStarted').status, 'pass');
assert.equal(honestWaiting.report.get('check.stageC.rootSubmitted').status, 'pass');
assert.equal(honestWaiting.category, 'full');
const waitingReport = createReport();
const waitingCtx = {
  blockNum: N, data: { gameSelection: selection }, report: waitingReport,
  r2: { fetchJson: async (key) => key === `live/block${N}/group7.json`
    ? json({ phase: 'waiting', messages: [] }) : null },
};
const waiting = await verifyTimelineNoGameRootPresentChatGate(waitingCtx, {
  files: { gameGroups: json(groups) },
});
assert.equal(waiting.chatStatus, 'pass');
assert.equal(waitingReport.get('check.stageC.timelineNoGameChatNotStarted').status, 'pass');
assert.equal(waitingCtx.data.stopReason, undefined);
console.log('VTL-01 C2: 組一覧がある未開始の正直なブロックは PASS: PASS');

const unreadableGroups = await runCase({ selectionRecord: json(selection),
  groupRecord: { data: null, parseError: 'invalid JSON' } });
assert.equal(unreadableGroups.report.get('check.stageC.timelineNoGameChatNotStarted').status, 'warn');
assert.equal(unreadableGroups.category, 'partial');
const groupsReadError = await runCase({ selectionRecord: json(selection), groupThrows: true });
assert.equal(groupsReadError.report.get('check.stageC.timelineNoGameChatNotStarted').status, 'warn');
assert.equal(groupsReadError.category, 'partial');
const unreadableSelection = await runCase({ selectionRecord: { data: null, parseError: 'invalid JSON' } });
assert.equal(unreadableSelection.report.get('check.stageC.timelineNoGameChatNotStarted').status, 'warn');
const disappearedSelection = await runCase({ stageBVerified: true });
assert.equal(disappearedSelection.report.get('check.stageC.timelineNoGameChatNotStarted').status, 'warn');
const readError = await runCase({ selectionThrows: true, stageBVerified: true });
assert.equal(readError.report.get('check.stageC.timelineNoGameChatNotStarted').status, 'warn');
console.log('VTL-01 D: 組一覧・選出記録の読取失敗は未検証: PASS');

const rootPresentReport = createReport();
rootPresentReport.check('check.stageB.playersMatch', 'pass', { count: 3 });
const rootPresentCtx = {
  blockNum: N, data: { gameSelection: selection }, report: rootPresentReport,
  r2: { fetchJson: async (key) => key.endsWith('/game_selection.json') ? json(selection) : null },
};
const rootPresent = await verifyTimelineNoGameRootPresentChatGate(rootPresentCtx, {
  files: { gameGroups: null },
});
assert.equal(rootPresent.chatStatus, 'warn');
assert.equal(rootPresentCtx.data.stopReason, 'not_ready');
console.log('VTL-01 E: root ありの共通ゲートも未検証: PASS');

// CLI と同じ Stage B-1 → B-2 → C の入口を通す。組分け前に止まった
// previous_block_not_ready の公開物には live がなく、名簿履歴も空である。
const entries = [{ uid: 'alice' }, { uid: 'bob' }, { uid: 'carol' }];
const applicantHash = `0x${'56'.repeat(32)}`;
const randao = `0x${'78'.repeat(32)}`;
const targetBlockHash = `0x${'9a'.repeat(32)}`;
const cliSelection = {
  blockNum: N, hashRegisteredBlock: 6, applicantHash,
  confirmationBlocks: 64, targetBlockNum: 70,
  entryPeriodEnd: 500_000, targetBlockHash, randao,
  totalEntries: entries.length, totalSelected: entries.length,
  players: entries.map((data, index) => ({ globalIndex: index, localIndex: index,
    file: 'entries-0', data })),
};
const cliSummary = { ...summary, noGameCause: 'previous_block_not_ready' };
const cliReport = createReport();
const cliFetched = [];
const cliCtx = {
  blockNum: N,
  cfg: { pins: { confirmationBlocks: 64, gameMaxPlayers: 2100 } },
  report: cliReport,
  data: {
    applicantHash, registeredBlock: 6, entryPeriodEnd: 500_000,
    entriesTotal: entries.length,
    infos: Array.from({ length: 100 }, (_, index) => ({
      entries: index === 0 ? [{ filename: 'entries-0', number: entries.length }] : [],
    })),
    entryFileHashes: new Map([['entries-0', hashLikeBackend(entries)]]),
    zkInfo: { kind: 'no_root', currentProofRequired: true,
      blockState: { root: `0x${'0'.repeat(64)}`, verificationStartedAt: 0,
        zkEpochPlusOne: 0, proofAttachedAt: 0 } },
  },
  ui: { t: (key) => key, println() {}, warn() {} },
  r2: {
    async fetchJson(key) {
      cliFetched.push(key);
      if (key === `entries/block${N}/game_selection.json`) return json(cliSelection);
      if (key === `entries/block${N}/entries/entries-0.json`) return json(entries);
      if (key === `games/block${N}/summary.json`) return json(cliSummary);
      return null;
    },
    async refetch(key) { return this.fetchJson(key); },
    release() {},
  },
  chain: {
    async getBlock(number) {
      return Number(number) === 70
        ? { hash: targetBlockHash, mixHash: randao, timestamp: 500n }
        : { timestamp: 1000n };
    },
    latest: async () => ({ number: 200n, timestamp: afterDeadline }),
    findBlockByTimestamp: async () => 90,
    resultWindow: async () => ({ openAt: 800n, closeAt: 900n }),
    resultCount: async () => 0n,
    evidenceAddress: async () => EVIDENCE,
    verificationPeriod: async () => 100,
    getTimingConstants: async () => ({ startTimeEntryMs: 0, blockTimeMs: 62_500,
      gamePeriodMs: 200_000 }),
    currentGrace: async () => 100,
    otherRegistrationCount: async () => 0,
    otherRegistrationAt: async () => { throw new Error('no roster row'); },
  },
};
assert.equal((await runSelection(cliCtx)).stop, false);
assert.equal(cliReport.get('check.stageB.playersMatch').status, 'pass');
assert.equal((await runGrouping(cliCtx)).stop, false);
assert.equal(cliCtx.data.timelineNoGame, true);
const cliResult = await runResults(cliCtx);
assert.equal(cliResult.stop, false);
assert.equal(cliReport.get('check.stageC.timelineNoGameChatNotStarted').status, 'pass');
assert.equal(cliReport.get('check.stageC.rootSubmitted').status, 'pass');
assert.equal(categorize({ fatal: false, report: cliReport, stopped: cliResult.stop }), 'full');
assert.equal(cliFetched.some((key) => key.startsWith(`live/block${N}/`)), false);
console.log('FIX3 N1-a: 通常 Stage B → C の選出後・組分け前 no-game は full: PASS');

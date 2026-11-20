import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { hexToBytes } from 'viem';
import { makeWireG6Boards } from '../../Hardhat/bitcoinu/scripts/lib/make-wire-g6-boards.mjs';
import { downloadArtifacts, reconstructCanonicalRosterPayloads,
  autoRosterTextFromSelection, buildZeroEntryNoGameSummary, run as runResults } from '../src/stages/results.js';
import { createReport } from '../src/report.js';
import { DEFAULTS } from '../src/config.js';
import { GameMasterDO } from '../vendor/workers/game_workers/game-master-DO.js';
import { deriveGroupSeed } from '../vendor/workers/game_workers/lib/grouping-integrity.js';
import { buildRosterMemberCommitment } from '../vendor/workers/game_workers/lib/roster-member-root.js';
import { concatChunks, decodeClaimData, encodeClaimData, claimEntriesFromClaimData } from '../vendor/workers/game_workers/lib/claim-data-codec.js';
import { byteEqual, sha256HexOfString } from '../src/json-utils.js';
import { manifestCoreOf } from '../src/emergency.js';

const tmp = await mkdtemp(path.join(os.tmpdir(), 'wr17e-stage-c-'));
const readLane = async (lane, key) => (await readFile(path.join(lane, key))).toString();
function mutate(item, raw) {
  const value = JSON.parse(raw);
  if (item === 'manifest') value.algorithm = `${value.algorithm}-changed`;
  else if (item === 'summary') value.blockNum += 1;
  else if (item.startsWith('roster-')) value.groupId += 1;
  else value.meta.blockNum += 1;
  return JSON.stringify(value);
}
function manifestCore(raw) {
  return JSON.stringify(manifestCoreOf(JSON.parse(raw)));
}
function artifactMatches(item, bundled, publicRaw) {
  return byteEqual(bundled, item === 'manifest' ? manifestCore(publicRaw) : publicRaw);
}
const claimLeaves = (chunks) => claimEntriesFromClaimData(decodeClaimData(concatChunks(chunks.map(hexToBytes))));
const rootMatches = (gm, blockNum, leaves, declaredRoot) => gm.buildMerkleTree(blockNum, leaves).root === declaredRoot;
let checked = 0;

async function compareBoard(board) {
  const { laneDir: lane, r2Data } = board;
  const manifest = JSON.parse(await readLane(lane, 'lane-manifest.json'));
  const N = manifest.blockNum;
  const selection = JSON.parse(r2Data.get(`entries/block${N}/game_selection.json`));
  const gm = new GameMasterDO({ storage: {} }, {});
  const groups = selection.players.length >= 3
    ? await gm.formGroups(selection.players, deriveGroupSeed(selection.randao, manifest.anchors.applicantHash), []) : [];
  const observed = new Map();
  const sourceFor = (data, readings) => ({
    async fetchJson(key) {
      const bytes = data.get(key);
      if (!bytes) return null;
      const raw = bytes.toString();
      readings.set(key, raw);
      return { data: JSON.parse(raw), raw, path: key };
    },
    async refetch(key) { return this.fetchJson(key); },
    release() {}, releaseRaw() {},
  });
  const r2 = sourceFor(r2Data, observed);
  const S = { auto: selection.players.length > 0 && selection.players.length < 3,
    noGame: selection.players.length === 0, timelineNoGame: false,
    corrupt: [], missing: [], precheckedHashes: new Map() };
  const ctx = { blockNum: N, data: { gameSelection: selection }, r2,
    ui: { t: (key) => key, println() {} } };
  await downloadArtifacts(ctx, groups.map((g) => g.groupId), S);
  assert.deepEqual(S.missing, [], `${board.name}: missing public artifact`);
  assert.deepEqual(S.corrupt, [], `${board.name}: corrupt public artifact`);

  const pairs = new Map([
    ['summary', ['k6/summary.json', `games/block${N}/summary.json`]],
    ['manifest', ['k6/manifest-core.json', `verification/block${N}/manifest.json`]],
  ]);
  for (const group of groups) {
    pairs.set(`roster-${group.groupId}`, [`k6/roster/group${group.groupId}.json`, `games/block${N}/roster/group${group.groupId}.json`]);
    pairs.set(`archive-${group.groupId}`, [`k6/group${group.groupId}.json`, `games/block${N}/group${group.groupId}.json`]);
  }
  if (S.auto) pairs.set('roster-0', ['k6/roster/group0.json', `games/block${N}/roster/group0.json`]);
  for (const [item, [laneKey, publicKey]] of pairs) {
    const bundled = await readLane(lane, laneKey);
    const seen = observed.get(publicKey);
    assert(seen != null, `${board.name}: Stage C did not fetch ${publicKey}`);
    assert.equal(artifactMatches(item, bundled, seen), true, `${board.name}: ${item}`);
    const canonicalRoster = item.startsWith('roster-')
      ? (groups.length
        ? reconstructCanonicalRosterPayloads(N, groups).groupTexts.get(Number(item.slice(7)))
        : autoRosterTextFromSelection(N, selection.players)) : null;
    if (canonicalRoster != null) assert.equal(byteEqual(bundled, canonicalRoster), true,
      `${board.name}: ${item} independently rebuilt`);
    const file = path.join(lane, laneKey);
    try {
      await writeFile(file, mutate(item, bundled));
      assert.equal(artifactMatches(item, await readLane(lane, laneKey), seen), false,
        `${board.name}: ${item} bundle-side mutation`);
      if (canonicalRoster != null) assert.equal(byteEqual(await readLane(lane, laneKey), canonicalRoster), false,
        `${board.name}: ${item} bundle differs from rebuilt roster`);
    } finally {
      await writeFile(file, bundled);
    }
    const mutatedR2 = new Map(r2Data);
    mutatedR2.set(publicKey, Buffer.from(mutate(item, seen)));
    const mutatedObserved = new Map();
    const mutatedS = { auto: S.auto, noGame: S.noGame, timelineNoGame: false,
      corrupt: [], missing: [], precheckedHashes: new Map() };
    await downloadArtifacts({ ...ctx, r2: sourceFor(mutatedR2, mutatedObserved) },
      groups.map((g) => g.groupId), mutatedS);
    const changedPublic = mutatedObserved.get(publicKey);
    assert(changedPublic != null, `${board.name}: ${item} mutated public file was not read`);
    assert.equal(artifactMatches(item, bundled, changedPublic), false,
      `${board.name}: ${item} public-side mutation`);
    if (canonicalRoster != null) assert.equal(byteEqual(changedPublic, canonicalRoster), false,
      `${board.name}: ${item} public differs from rebuilt roster`);
    checked++;
  }
  if (S.noGame) {
    assert.deepEqual(S.files.summary.data, buildZeroEntryNoGameSummary(N, S.files.summary.data.schemaVersion));
  }
  if (S.auto) {
    assert.equal(autoRosterTextFromSelection(N, selection.players), await readLane(lane, 'k6/roster/group0.json'));
  }
  if (groups.length) {
    const rosters = reconstructCanonicalRosterPayloads(N, groups);
    assert.equal(rosters.manifestText, observed.get(`games/block${N}/roster/manifest.json`));
    for (const [gid, text] of rosters.groupTexts) {
      assert.equal(text, await readLane(lane, `k6/roster/group${gid}.json`));
      assert.deepEqual(S.files.groups.get(gid).data.meta,
        JSON.parse(await readLane(lane, `k6/group${gid}.json`)).meta);
    }
  }
  const final = JSON.parse(await readLane(lane, 'final/input.json'));
  const fromBundle = claimLeaves(final.claimChunks);
  const fromPublic = gm.collectClaimEntriesFromSummary(N, S.files.summary.data);
  assert.deepEqual(fromBundle, fromPublic, `${board.name}: claim leaves`);
  const tree = gm.buildMerkleTree(N, fromPublic);
  assert.equal(rootMatches(gm, N, fromPublic, manifest.anchors.merkleRoot), true, `${board.name}: claim root`);
  assert.equal(rootMatches(gm, N, fromPublic, S.files.merkle.data.root), true, `${board.name}: merkle metadata`);
  if (fromPublic.length) {
    const changedSummary = structuredClone(S.files.summary.data);
    const member = changedSummary.groups.flatMap((g) => g.members || [])
      .find((m) => BigInt(m.full_btcu_reward || 0) > 0n);
    assert(member, `${board.name}: claimable member`);
    member.full_btcu_reward = '0';
    assert.notDeepEqual(gm.collectClaimEntriesFromSummary(N, changedSummary), fromBundle,
      `${board.name}: public summary claim mutation`);
    const validChangedClaim = encodeClaimData(N, changedSummary).bytes;
    const changedBundleChunks = [`0x${Buffer.from(validChangedClaim).toString('hex')}`];
    assert.notDeepEqual(claimLeaves(changedBundleChunks), fromPublic,
      `${board.name}: valid bundle claim content mutation`);
  }
  const changedManifest = structuredClone(manifest);
  changedManifest.anchors.merkleRoot = `${tree.root.slice(0, -1)}${tree.root.at(-1) === '0' ? '1' : '0'}`;
  const manifestFile = path.join(lane, 'lane-manifest.json');
  const originalManifest = await readFile(manifestFile);
  try {
    await writeFile(manifestFile, JSON.stringify(changedManifest));
    assert.equal(rootMatches(gm, N, fromPublic,
      JSON.parse(await readLane(lane, 'lane-manifest.json')).anchors.merkleRoot), false,
      `${board.name}: bundle root mutation`);
  } finally {
    await writeFile(manifestFile, originalManifest);
  }
  const changedMerkle = structuredClone(S.files.merkle.data);
  changedMerkle.root = changedManifest.anchors.merkleRoot;
  assert.equal(rootMatches(gm, N, fromPublic, changedMerkle.root), false,
    `${board.name}: public merkle mutation`);
  console.log(`WR17E_STAGE_C ${board.name} block=${N} pass`);
}

async function compareFullNormalBoard(board, corruptMembers = false) {
  const N = board.board.blockNum;
  const r2Data = new Map(board.r2Data);
  const readPublic = (key) => JSON.parse(r2Data.get(key).toString());
  const gm = new GameMasterDO({ storage: {} }, {});
  const summaryKey = `games/block${N}/summary.json`;
  const summary = readPublic(summaryKey);
  assert(summary.timeline, 'generator must publish the declared timeline');
  assert.equal(await readLane(board.laneDir, 'k6/summary.json'), r2Data.get(summaryKey).toString(),
    'full Stage C uses the collected summary bytes');
  const manifest = readPublic(`verification/block${N}/manifest.json`);
  assert.equal(manifest.files[summaryKey], sha256HexOfString(r2Data.get(summaryKey).toString()),
    'generator manifest closes the same summary');
  if (corruptMembers) {
    const groupKey = `games/block${N}/group0.json`;
    const archive = readPublic(groupKey);
    archive.members = archive.members.map(({ globalIndex, ...rest }) => ({ ...rest, globalIndex }));
    const archiveRaw = JSON.stringify(archive);
    r2Data.set(groupKey, Buffer.from(archiveRaw));
    manifest.files[groupKey] = sha256HexOfString(archiveRaw);
  }
  if (corruptMembers) {
    manifest.manifestHash = `0x${sha256HexOfString(JSON.stringify(manifestCoreOf(manifest)))}`;
    r2Data.set(`verification/block${N}/manifest.json`, Buffer.from(JSON.stringify(manifest)));
  }
  const selection = readPublic(`entries/block${N}/game_selection.json`);
  const merkleRoot = readPublic(`merkle/block_${N}.json`).root;
  const laneManifest = JSON.parse(await readLane(board.laneDir, 'lane-manifest.json'));
  const groupsDerived = await gm.formGroups(selection.players,
    deriveGroupSeed(selection.randao, laneManifest.anchors.applicantHash), []);
  const deposits = new Map(groupsDerived.flatMap((group) => group.members.flatMap((player) =>
    JSON.parse(player.data.depIds).deposits.map((deposit) =>
      [String(deposit.id), { ...deposit, idTo: player.data.uid, owner: player.data.addr }]))));
  const rosterManifestText = r2Data.get(`games/block${N}/roster/manifest.json`).toString();
  const groupTexts = new Map(groupsDerived.map((group) =>
    [group.groupId, r2Data.get(`games/block${N}/roster/group${group.groupId}.json`).toString()]));
  const rosterHash = buildRosterMemberCommitment({
    blockNum: N, manifestText: rosterManifestText, groupTexts,
  }).C;
  const entryEnd = 2_000_000_000 + (N + 1) * 1000;
  const chatClose = entryEnd + 200;
  const resultClose = chatClose + 100;
  const ETH_LOCK = `0x${'bb'.repeat(20)}`;
  const EVIDENCE = `0x${'cc'.repeat(20)}`;
  const HASH_STORAGE = `0x${'dd'.repeat(20)}`;
  const cacheDir = path.join(tmp, 'full-stage-c-cache');
  const r2 = {
    baseDir: cacheDir,
    async fetchJson(key) {
      const bytes = r2Data.get(key);
      if (!bytes) return null;
      const file = path.join(cacheDir, key);
      await mkdir(path.dirname(file), { recursive: true });
      await writeFile(file, bytes);
      const raw = bytes.toString();
      return { data: JSON.parse(raw), raw, path: file };
    },
    async refetch(key) { return this.fetchJson(key); },
    async exists(key) { return r2Data.has(key); },
    release() {}, releaseRaw() {},
  };
  await mkdir(cacheDir, { recursive: true });
  const chain = {
    client: {
      async getLogs() { return []; },
      async readContract({ functionName, args }) {
        if (functionName !== 'getLock') throw new Error(`unexpected read: ${functionName}`);
        const deposit = deposits.get(String(args[0]));
        assert(deposit, `missing deposit ${args[0]}`);
        return {
          amount: BigInt(deposit.amount), idFrom: deposit.idFrom, idTo: deposit.idTo,
          unlockTime: BigInt(deposit.unlockTime), lockOwnerAddress: deposit.owner,
          unlocked: false,
        };
      },
    },
    async blockStates() {
      return { root: merkleRoot, verificationStartedAt: resultClose + 10,
        zkEpochPlusOne: 0, proofAttachedAt: 0 };
    },
    async proofRequired() { return false; },
    async ethLockAddress() { return ETH_LOCK; },
    async evidenceAddress() { return EVIDENCE; },
    async getTimingConstants() {
      return { startTimeEntryMs: 2_000_000_000_000, blockTimeMs: 1_000_000,
        gamePeriodMs: 100_000, submitPeriodMs: 100_000, invariantOk: true };
    },
    async getResultHash() { return { hash: manifest.manifestHash, updated: 900 }; },
    async resultRegistrationCount() { return 1; },
    async getBlock(number) {
      return { timestamp: BigInt(Number(number) === 900 ? resultClose + 5 : resultClose + 1000),
        number: BigInt(number), hash: `0x${'44'.repeat(32)}`, mixHash: `0x${'55'.repeat(32)}` };
    },
    async latest() { return { number: 1000n }; },
    async resultWindow() { return { openAt: chatClose, closeAt: resultClose }; },
    async chatWindow() { return { chatOpenAt: entryEnd, chatCloseAt: chatClose }; },
    async currentGrace() { return 100; },
    async otherRegistrationCount() { return 1; },
    async otherRegistrationAt() {
      return { hash: rosterHash, registeredBlock: 120, registeredAt: entryEnd + 5 };
    },
    async resultCount() { return 0; },
    async evidenceAcc() { return `0x${'00'.repeat(32)}`; },
    async findBlockByTimestamp() { return 400n; },
    async merkleRootEvents() { return [{ root: merkleRoot, timestamp: resultClose + 10,
      blockNumber: 901n, transactionIndex: 0, logIndex: 0,
      transactionHash: `0x${'66'.repeat(32)}` }]; },
    async getBlockLifecycle() { return { mode: 0, merkleRoot,
      verificationStartedAt: resultClose + 10,
      verificationEndsAt: resultClose + 610, claimEndsAt: resultClose + 11410,
      stage: 1 }; },
    async verificationPeriod() { return 600; },
    async claimPeriod() { return 10800; },
  };
  const report = createReport();
  const ctx = {
    cfg: { lang: 'ja', pins: DEFAULTS.pins,
      contracts: { ethLock: ETH_LOCK, evidence: EVIDENCE, hashStorage: HASH_STORAGE } },
    chain, r2, report, blockNum: N,
    ui: { println() {}, warn() {}, t: (key) => key },
    data: { autoDistribute: false, noGame: false, groupsDerived, gameSelection: selection,
      reuseFiles: false, majorLangs: [] },
  };
  await runResults(ctx);
  assert.equal(ctx.data.stopReason, undefined, 'full Stage C stopped');
  assert.deepEqual(report.list().filter((check) => check.id.startsWith('check.stageC.')
    && check.status === 'fail').map((check) => check.id),
  corruptMembers ? ['check.stageC.groupMembersMatch'] : [], 'full Stage C failure set');
  for (const id of ['downloads', 'manifestSelfConsistent', 'manifestAnchor',
    'rosterCommitment', 'evidenceReportMatch', 'scoring', 'summaryMatch',
    'groupGameResultsMatch', 'groupCanonicalTimelineMatch', 'merkleRoot']) {
    const check = report.get(`check.stageC.${id}`);
    assert.equal(check?.status, 'pass', `${id}: ${JSON.stringify(check)}`);
  }
  console.log(`WR17E_STAGE_C_FULL_${corruptMembers ? 'MEMBER_ORDER_REJECTED' : 'OK'} normal-4p block=1`);
}

try {
  const block0 = await makeWireG6Boards(path.join(tmp, 'block0'), { boards: ['zero-entries', 'auto-one'] });
  const block1 = await makeWireG6Boards(path.join(tmp, 'block1'), { boards: ['normal-4p', 'normal-evidence-identical'], blockNum: 1 });
  for (const board of [...block0, ...block1]) await compareBoard(board);
  await compareFullNormalBoard(block1.find((board) => board.name === 'normal-4p'));
  await compareFullNormalBoard(block1.find((board) => board.name === 'normal-4p'), true);
  console.log(`WR17E_STAGE_C_OK boards=${block0.length + block1.length} itemPairs=${checked}`);
} finally {
  await rm(tmp, { recursive: true, force: true });
}

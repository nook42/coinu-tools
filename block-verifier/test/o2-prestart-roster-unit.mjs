import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { keccak256, stringToHex } from 'viem';
import { GameMasterDO } from '../../workers/game_workers/game-master-DO.js';
import { calculateGroupResults } from '../../workers/game_workers/lib/game-result-calculator.js';
import { rosterAnchorKey, evaluateRosterSubmissionEligibility,
  selectCanonicalRosterRegistration, adoptedForRoster, applyRosterSubmissionGate,
} from '../../workers/game_workers/lib/roster-anchor-rule.js';
import { resolveRosterSubmissionEligibility, mergeEmergencyServerSubmissions } from '../src/stages/results.js';

const N = 0;
const entryEnd = 1000;
const chattingStart = 1100;
const close = 1200;
const now = 1400;
const manifest = JSON.stringify({ blockNum: N, indexSha256: 'x', groups: [] });
const hash = keccak256(stringToHex(manifest));
const legacyAddress = '0xd2c8a3be50d9a158bd579a26a346f54cfb93426d';
const modernAddress = `0x${'22'.repeat(20)}`;
const evidenceAddress = `0x${'11'.repeat(20)}`;
const row = (registeredAt, rowHash = hash) => ({
  hash: rowHash, registeredBlock: 50, registeredAt,
});
const store = () => {
  const values = new Map();
  return { values,
    get: async (key) => values.get(key),
    put: async (key, value) => {
      if (key && typeof key === 'object') {
        for (const [name, item] of Object.entries(key)) values.set(name, item);
      } else values.set(key, value);
    },
    delete: async (key) => {
      for (const name of Array.isArray(key) ? key : [key]) values.delete(name);
    },
    list: async ({ prefix } = {}) => new Map([...values].filter(([key]) => key.startsWith(prefix || ''))),
  };
};
function gmFor(rows, { legacy = false, graceFails = false, historyFails = false, timeFails = false,
  manifestText = manifest, manifestFails = false } = {}) {
  const gm = Object.create(GameMasterDO.prototype);
  gm.storage = store();
  gm.env = {
    EVIDENCE_CONTRACT_ADDRESS: evidenceAddress,
    HASH_STORAGE_CONTRACT_ADDRESS: legacy ? legacyAddress : modernAddress,
    CONFIRMATION_BLOCKS: '64',
  };
  let segmentArtifact = null;
  gm.getR2Text = async (key) => {
    if (key.endsWith('/evidence-segments.json')) return segmentArtifact;
    if (manifestFails) throw new Error('roster manifest R2 read failed');
    return manifestText;
  };
  gm.putR2ObjectOrThrow = async (key, value) => {
    assert.equal(key, `games/block${N}/zkp/evidence-segments.json`);
    segmentArtifact = JSON.stringify(value);
  };
  const legacyError = Object.assign(new Error('getter reverted'), {
    walk: (predicate) => predicate({ name: 'ContractFunctionRevertedError' }),
  });
  let failingGrace = graceFails;
  let failingHistory = historyFails;
  let failingTime = timeFails;
  const client = {
    getBlock: async ({ blockNumber } = {}) => {
      if (failingTime) throw new Error('chain clock RPC unavailable');
      return blockNumber == null
        ? { number: 1000n, timestamp: BigInt(now) }
        : { number: blockNumber,
          timestamp: BigInt(blockNumber === 50n ? rows.at(-1).registeredAt : now) };
    },
    readContract: async ({ functionName, args }) => {
      if (functionName === 'resultWindow') return [1200n, 1300n];
      if (functionName === 'chatWindow') return [BigInt(entryEnd), BigInt(close)];
      if (functionName === 'currentGrace') {
        if (failingGrace) throw new Error('grace RPC unavailable');
        return 100n;
      }
      if (functionName === 'otherRegistrationCount') {
        if (legacy) throw legacyError;
        if (failingHistory) throw new Error('history RPC unavailable');
        return BigInt(rows.length);
      }
      if (functionName === 'otherRegistrationAt') {
        const selected = rows[Number(args[1])];
        return [selected.hash, BigInt(selected.registeredBlock), BigInt(selected.registeredAt)];
      }
      if (functionName === 'getOtherHash') return rows.length
        ? [rows.at(-1).hash, BigInt(rows.at(-1).registeredBlock)] : [`0x${'0'.repeat(64)}`, 0n];
      if (functionName === 'resultCount') return 0n;
      throw new Error(`unexpected ${functionName}`);
    },
  };
  gm.createReadOnlyClient = () => client;
  gm.publishEvidenceReportIdempotent = async (_n, report) => { gm.report = report; };
  gm.calcStoreAdopted = async (_n, adopted) => { gm.adopted = adopted; };
  return { gm, client, recover: () => {
    failingGrace = false; failingHistory = false; failingTime = false;
  } };
}
function verifierChain(rows, { legacy = false, graceFails = false } = {}) {
  return {
    getTimingConstants: async () => ({ startTimeEntryMs: 0, blockTimeMs: 1_000_000 }),
    currentGrace: async () => {
      if (graceFails) throw new Error('grace RPC unavailable');
      return 100;
    },
    otherRegistrationCount: async () => legacy ? null : rows.length,
    otherRegistrationAt: async (_key, index) => rows[index],
    getOtherHash: async () => rows.length
      ? { hash: rows.at(-1).hash, updated: rows.at(-1).registeredBlock } : null,
    getBlock: async () => ({ timestamp: rows.at(-1)?.registeredAt ?? 0 }),
  };
}
const decideBoth = async (rows, opts = {}) => {
  const { gm, client } = gmFor(rows, opts);
  const writer = await gm.calcRosterSubmissionEligibility(N, client, 936n, BigInt(now),
    BigInt(entryEnd), BigInt(close));
  const verifier = await resolveRosterSubmissionEligibility(
    verifierChain(rows, opts), N, now, entryEnd,
  );
  assert.deepEqual(verifier, writer);
  return writer;
};

// T1/T8: late-only Evidence is not adopted. The shared scorer sees no submissions.
const late = await decideBoth([row(chattingStart + 1)]);
assert.equal(late.accepted, false);
assert.equal(late.reason, 'no_prestart_canonical_roster');
assert.equal(late.registrationIndex, null);
assert.equal(late.chattingStart, chattingStart);
const adopted = [{ uid: 'a', seq: 1 }, { uid: 'b', seq: 2 }];
assert.deepEqual(adoptedForRoster(adopted, late), []);

// T2/T8: WS raw and parsed values are both excluded before scoring.
const data = { meta: { blockNum: N, groupId: 0 },
  members: [{ uid: 'a' }, { uid: 'b' }, { uid: 'c' }],
  submissionsRaw: { a: 'raw-a', b: 'raw-b' },
  submissions: { a: { uid: 'a' }, b: { uid: 'b' } }, evidenceSources: { a: { seq: 1 } },
};
applyRosterSubmissionGate(data, late);
assert.equal(Object.keys(data.submissionsRaw).length, 0);
assert.equal(Object.keys(data.submissions).length, 0);
const { results: zero } = await calculateGroupResults(data, 500, 20,
  { maxChars: 10000, maxMessages: 100, maxMsgChars: 1000 },
  { startMs: 0, endMs: 2_000_000 });
assert.equal(zero.reduce((sum, member) => sum + Number(member.totalPoints || 0), 0), 0);
assert.ok(zero.every((member) => member.disqualifyReason === 'no_submit'));
const emergencyData = { members: data.members, submissionsRaw: {}, submissions: {} };
mergeEmergencyServerSubmissions({ adoptedByUid: {} }, emergencyData,
  { a: { raw: 'raw-a' }, b: { raw: 'raw-b' } });
assert.equal(Object.keys(emergencyData.submissionsRaw).length, 2);
applyRosterSubmissionGate(emergencyData, late);
assert.equal(Object.keys(emergencyData.submissionsRaw).length, 0);

// T3/T4: a canonical prestart row keeps the exact objects and adopted set.
const good = await decideBoth([row(chattingStart - 1)]);
assert.equal(good.accepted, true);
assert.equal(good.registrationIndex, 0);
assert.equal(adoptedForRoster(adopted, good), adopted);
const unchanged = { submissionsRaw: { a: 'raw-a' }, submissions: { a: { uid: 'a' } } };
assert.equal(applyRosterSubmissionGate(unchanged, good), unchanged);
assert.equal(unchanged.submissionsRaw.a, 'raw-a');

// T5: legacy current-value comparison follows the official client and verifier.
const legacy = await decideBoth([row(chattingStart + 1)], { legacy: true });
assert.equal(legacy.accepted, true);
assert.equal(legacy.legacy, true);

// T9: loss or read failure of the current R2 object cannot discard honest submissions.
for (const opts of [{ manifestText: null }, { manifestFails: true }]) {
  const selected = await decideBoth([row(chattingStart - 1)], opts);
  assert.equal(selected.accepted, true, selected.reason);
  assert.equal(adoptedForRoster(adopted, selected), adopted);
  const scoringInput = { submissionsRaw: { a: 'raw-a' }, submissions: { a: { uid: 'a' } } };
  assert.equal(applyRosterSubmissionGate(scoringInput, selected), scoringInput);
  assert.equal(scoringInput.submissionsRaw.a, 'raw-a');
  const { gm } = gmFor([row(chattingStart - 1)], opts);
  const progress = await gm.calcEvidenceUnit(N, { stage: 'evidence', cursor: 0 });
  assert.equal(progress.stage, 'depids');
  assert.equal(progress.rosterSubmission.accepted, true);
}

// T7: a later public manifest generation cannot change prestart registration eligibility.
const mismatch = await decideBoth([row(chattingStart - 1)], { manifestText: `${manifest} ` });
assert.equal(mismatch.accepted, true);
assert.equal(mismatch.reason, null);

// T6: first read failure stops at evidence, creates a visible marker, then recovers.
for (const [opts, reason] of [
  [{ graceFails: true }, /grace RPC unavailable/],
  [{ historyFails: true }, /history RPC unavailable/],
  [{ timeFails: true }, /chain clock RPC unavailable/],
]) {
  const recovering = gmFor([row(chattingStart - 1)], opts);
  const progress = { stage: 'evidence', cursor: 0 };
  await assert.rejects(recovering.gm.calcEvidenceUnit(N, progress), reason);
  assert.equal(progress.stage, 'evidence');
  assert.ok(recovering.gm.storage.values.has('roster_submission_read_failed_block0'));
  const lifecycle = await recovering.gm.collectLifecycleBlockers();
  assert.ok(lifecycle.blockers.some((blocker) => blocker.kind === 'roster_submission_read_failed'));
  recovering.recover();
  await recovering.gm.calcEvidenceUnit(N, progress);
  assert.equal(progress.stage, 'depids');
  assert.equal(progress.rosterSubmission.accepted, true);
  assert.equal(recovering.gm.storage.values.has('roster_submission_read_failed_block0'), false);
}

// Current implementations, not copied algorithms, must call the shared gate on both routes.
const gmSource = readFileSync(new URL('../../workers/game_workers/game-master-DO.js', import.meta.url), 'utf8');
const verifierSource = readFileSync(new URL('../src/stages/results.js', import.meta.url), 'utf8');
assert.match(gmSource, /adoptedForRoster\(finalAdopted, progress\.rosterSubmission\)/);
assert.match(gmSource, /adoptedCount: scoringAdopted\.length/);
assert.match(gmSource, /applyRosterSubmissionGate\(data, progress\.rosterSubmission\)/);
assert.match(gmSource, /blockers: rosterReadFailed \? \[\{/);
assert.match(verifierSource, /adoptedForRoster\(adoptedByUid, S\.rosterSubmission\)/);
assert.match(verifierSource, /applyRosterSubmissionGate\(data, S\.rosterSubmission\)/);
assert.equal(rosterAnchorKey(N).length, 66);
console.log('o2-prestart-roster-unit: ALL PASSED (T1-T9)');

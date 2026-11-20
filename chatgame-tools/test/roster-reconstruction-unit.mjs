// V25-03: ChatGameDO / roster cache が無くても、オンチェーンに束縛された
// game_selection から同じ formGroups を再実行して復元できることを検証する。
// キャッシュが存在する場合は権威入力にせず、再現結果との完全一致だけを許す。

import { LEGACY_HASH_STORAGE_ALLOWLIST as COLLECTOR_LEGACY_HASH_STORAGE_ALLOWLIST } from '../../Hardhat/bitcoinu/scripts/lib/collect-zkp-input.mjs';
import { GameMasterDO } from '../vendor/workers/game_workers/game-master-DO.js';
import { ChatGameDO } from '../vendor/workers/game_workers/chat-game-DO.js';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { keccak256, concatHex, stringToHex } from 'viem';
import { buildRosterMemberCommitment } from '../vendor/workers/game_workers/lib/roster-member-root.js';
import { openReadReceiptPause } from '../vendor/src/utils/read-receipt-pause.js';
import { separatorPoint } from '../vendor/src/utils/priorityEvidence.js';
import { INITIAL_FUTURE_CLOCK_WARNING } from '../vendor/src/utils/chainClock.js';
import { loadReportGrounds, mergeReportGroundMaps } from '../vendor/src/utils/reportGround.js';

const moduleTarget = (environmentName, normalUrl) => (
  process.env[environmentName]
    ? (process.env[environmentName].startsWith('data:')
      ? process.env[environmentName]
      : pathToFileURL(path.resolve(process.env[environmentName])).href)
    : normalUrl.href
);
const {
  HASH_STORAGE_ABI,
  readChatWindow,
  readResultRegistrationHistoryHead,
  readResultRegistrationHashesMatch,
  readCanonicalRosterRegistration,
  readSelectionAnchors,
} = await import(moduleTarget('P8A_CHAIN_MODULE', new URL('../src/common/chain.js', import.meta.url)));
const {
  fetchRoster,
  LEGACY_HASH_STORAGE_ALLOWLIST,
  resolveAnchoredRosterFromSelection,
  buildRecomputedRosterManifest,
  pollRecoveryRosterAtStart,
  finalRosterHashMatches,
  verifyLiveRosterAnchor,
  readCanonicalRosterEvidence,
} = await import(moduleTarget('P8A_DISCOVERY_MODULE', new URL('../src/recovery/discovery.js', import.meta.url)));
const { t, hasTranslation } = await import(
  moduleTarget('P8A_I18N_MODULE', new URL('../src/common/i18n.js', import.meta.url))
);
const { formatRosterIntegrityWarning, rosterFallbackWarningKey, formatLateRosterWarning } = await import(
  moduleTarget('P8A_ROSTER_WARNING_MODULE', new URL('../src/recovery/roster-warning.js', import.meta.url))
);

const BLOCK = 0;
const HASH = `0x${'11'.repeat(32)}`;
const LATEST_HASH = `0x${'99'.repeat(32)}`;
const RANDAO = `0x${'22'.repeat(32)}`;
const TARGET_HASH = `0x${'33'.repeat(32)}`;
const BASE = 'https://r2.invalid';
const GROUP_SEED = '0xcb27bd75ea487f225bbda823a24f550ce6aafc69eb3d24b48c2f1425c57792b3';

let passed = 0;
let failed = 0;
function check(name, condition, detail = '') {
  if (condition) { passed++; console.log(`  ok: ${name}`); }
  else { failed++; console.error(`  FAIL: ${name}${detail ? ` — ${detail}` : ''}`); }
}

const players = Array.from({ length: 3 }, (_, i) => ({
  globalIndex: i,
  data: {
    uid: `u${i + 1}`,
    addr: `0x${String(i + 1).padStart(40, '0')}`,
    bAddr: JSON.stringify({
      address: `0x${String(i + 11).padStart(40, '0')}`,
      pubKey: `0x04${String(i + 21).padStart(128, '0')}`,
      nostrPubkey: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    }),
    depIds: JSON.stringify({ ids: [`d${i + 1}`] }),
    lang: i === 0 ? 'ja' : 'en',
    name: `user-${i + 1}`,
    img: null,
    verified: true,
  },
}));

const selection = {
  blockNum: BLOCK,
  applicantHash: HASH,
  hashRegisteredBlock: 100,
  confirmationBlocks: 64,
  targetBlockNum: 164,
  targetBlockHash: TARGET_HASH,
  randao: RANDAO,
  totalEntries: 3,
  totalSelected: 3,
  players,
};

const objects = new Map([[`${BASE}/entries/block0/game_selection.json`, selection]]);
const publishedGroups = {
  blockNum: BLOCK,
  totalPlayers: 3,
  totalGroups: 1,
  groupSeed: GROUP_SEED,
  groups: [{
    groupId: 0, lang: 'mixed', mixed: true, memberCount: 3, memberIds: ['u3', 'u2', 'u1'],
  }],
};
objects.set(`${BASE}/entries/block0/game_groups.json`, publishedGroups);
for (let i = 0; i < 100; i++) {
  objects.set(`${BASE}/entries/block0/info/${String(i).padStart(2, '0')}_info.json`, {
    entries: i === 0 ? [{ filename: '00_0', number: 3 }] : [],
  });
}

const originalFetch = globalThis.fetch;
const fetchDelays = new Map();
const fetchedUrls = [];
globalThis.fetch = async (url) => {
  const key = String(url);
  fetchedUrls.push(key);
  const delayMs = fetchDelays.get(key) || 0;
  if (delayMs > 0) await new Promise((resolve) => setTimeout(resolve, delayMs));
  const value = objects.get(key);
  if (value === undefined) return new Response('not found', { status: 404 });
  return new Response(JSON.stringify(value), { status: 200, headers: { 'content-type': 'application/json' } });
};

const rosterAnchors = new Map();
const legacyGetterError = { walk: (predicate) => predicate({ name: 'ContractFunctionRevertedError' }) };
const snapshotAt = (timestamp = 1400n) => ({
  getBlockNumber: async () => 200n,
  getBlock: async ({ blockNumber }) => ({ number: blockNumber, timestamp }),
});
const client = {
  getBlockNumber: async () => 200n,
  getBlock: async ({ blockNumber }) => {
    if (blockNumber === 200n) return { timestamp: 1400n };
    if (blockNumber !== 164n) throw new Error(`unexpected target block ${blockNumber}`);
    return { hash: TARGET_HASH, mixHash: RANDAO };
  },
  readContract: async ({ functionName, args = [] }) => {
    if (functionName === 'otherRegistrationCount') throw legacyGetterError;
    if (functionName !== 'getOtherHash') throw new Error(`unexpected roster getter ${functionName}`);
    const anchoredHash = rosterAnchors.get(String(args[0]).toLowerCase());
    return anchoredHash
      ? [anchoredHash, 123n]
      : [`0x${'00'.repeat(32)}`, 0n];
  },
};
const contracts = { hashStorage: LEGACY_HASH_STORAGE_ALLOWLIST[0], evidence: `0x${'55'.repeat(20)}` };
let integrityCalls = 0;
const integrityResumeFrom = [];
const registrationWarnings = [];
const options = {
  client,
  contracts,
  confirmationBlocks: 64,
  selectionAnchorsReader: async (_client, _contracts, _blockNum, _confirmations, receivedSelection) => ({
    applicantHash: LATEST_HASH,
    applicantUpdatedBlock: 101,
    registrationCount: 2,
    selectionRegistered: JSON.stringify(receivedSelection) === JSON.stringify(selection),
    legacyFallback: false,
    randaoEthBlockNumber: 164,
    randaoBlockHash: TARGET_HASH,
  }),
  selectionIntegrityVerifier: async ({ selectionData, committedTotal, resumeFrom = 0, wallBudgetMs }) => {
    integrityCalls++;
    integrityResumeFrom.push(resumeFrom);
    if (JSON.stringify(selectionData) !== JSON.stringify(selection) || committedTotal !== 3) {
      throw new Error('integrity verifier input mismatch');
    }
    if (!Number.isFinite(wallBudgetMs) || wallBudgetMs <= 0) {
      throw new Error(`finite wall budget was not forwarded: ${wallBudgetMs}`);
    }
    // 本番の verifier と同じ resumable 例外を2回返す。復元側はカーソルを
    // 引き継いで同じ検査を再開し、最後の成功まで到達しなければならない。
    if (resumeFrom < 2) {
      const error = new Error(`synthetic wall budget exhausted at ${resumeFrom}`);
      error.resumable = true;
      error.selectionResumeFrom = resumeFrom + 1;
      throw error;
    }
  },
  onWarning: (warning) => registrationWarnings.push(warning),
};

const initialGm = new GameMasterDO({ storage: {} }, {});
const initialGroups = await initialGm.formGroups(players, GROUP_SEED, []);
const initialManifest = await buildRecomputedRosterManifest(0, initialGroups);
// GM の D1 writer を実行し、JSON 往復した行から独立に manifest を組み立てる。
const d1Rows = [];
const d1 = { prepare: (sql) => ({ bind: (...args) => ({
  all: async () => sql.includes('COUNT(*)') ? { results: [{ cnt: 0 }] } : { results: d1Rows },
  run: async () => ({}),
  sql, args,
}) }), batch: async (statements) => {
  for (const statement of statements) d1Rows.push({ group_id: statement.args[1],
    members: JSON.parse(JSON.stringify(statement.args[4])) });
} };
const d1Storage = new Map();
const d1Gm = new GameMasterDO({ storage: {
  delete: async (key) => d1Storage.delete(key),
  put: async (key, value) => d1Storage.set(key, value),
} }, { BITCOINU_DATA: d1 });
await d1Gm.writeGroupsToD1(0, initialGroups);
check('D1 writer は全組の書き込み後に完了印を残す',
  d1Storage.get('grouping_d1_complete_block0')?.totalGroups === initialGroups.length);
const d1IndexText = JSON.stringify(d1Gm.buildRosterIndex(d1Rows));
const d1Sha = async (value) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))]
  .map((byte) => byte.toString(16).padStart(2, '0')).join('');
const d1ManifestGroups = [];
for (const row of d1Rows) {
  let groupText = null;
  const writer = { env: { R2_BUCKET: { put: async (_key, text) => { groupText = text; } } },
    storage: { put: async () => {} }, recordDependencyOutcome: () => {} };
  const sha256 = await ChatGameDO.prototype.publishRosterFile.call(writer, 0, row.group_id, JSON.parse(row.members));
  check('D1 writer の JSON 往復行の group sha は実ファイルと一致', sha256 === await d1Sha(groupText));
  d1ManifestGroups.push({ groupId: Number(row.group_id), sha256 });
}
const d1ManifestText = JSON.stringify({ blockNum: 0, indexSha256: await d1Sha(d1IndexText), groups: d1ManifestGroups });
check('D1 writer の行形から作る名簿 manifest は復元側とバイト一致',
  d1ManifestText === initialManifest.manifestText);
let rosterSequence = [
  { rosterAnchorStatus: 'provisional', rosterObservedAtMs: 190000, rosterAnchorHash: HASH, groupId: 0 },
  { rosterAnchorStatus: 'unavailable', reason: 'temporary' },
  { rosterAnchorStatus: 'canonical', rosterObservedAtMs: 201000, rosterAnchorHash: LATEST_HASH, groupId: 1 },
];
const rosterObservations = [];
const finalRoster = await pollRecoveryRosterAtStart(async () => rosterSequence.shift(), () => 200000, {
  wait: async () => {}, onObservation: (value) => rosterObservations.push(value.rosterAnchorStatus),
});
check('復元は暫定・一過性失敗を越え、開始後の X の組を採る',
  finalRoster.rosterAnchorHash === LATEST_HASH && finalRoster.groupId === 1
    && rosterObservations.join(',') === 'provisional,unavailable,canonical');
let initialReads = 0;
const afterInitialFailure = await pollRecoveryRosterAtStart(async () => {
  if (++initialReads === 1) throw new Error('temporary first read failure');
  return { rosterAnchorStatus: 'canonical', rosterObservedAtMs: 201000,
    rosterAnchorHash: LATEST_HASH, groupId: 1 };
}, () => 200000, { wait: async () => {} });
check('復元は最初の名簿読取が失敗しても再試行して X で起動',
  initialReads === 2 && afterInitialFailure.groupId === 1);
let absentReads = 0;
let absentAtStart = null;
try {
  await pollRecoveryRosterAtStart(async () => {
    absentReads++;
    return { rosterAnchorStatus: 'none', rosterObservedAtMs: 300000 };
  }, () => 200000, { getChatCloseAtMs: () => 300000,
    shouldContinue: () => absentReads < 3, wait: async () => {} });
} catch (error) { absentAtStart = error; }
check('正典行なしは chatCloseAt に達してから停止する',
  absentReads === 1 && absentAtStart?.code === 'canonical_roster_anchor_absent');
let pendingReads = 0;
const afterPending = await pollRecoveryRosterAtStart(async () => {
  pendingReads++;
  return pendingReads < 3
    ? { rosterAnchorStatus: 'none', rosterObservedAtMs: 190000 }
    : { rosterAnchorStatus: 'canonical', rosterObservedAtMs: 201000,
      rosterAnchorHash: HASH, groupId: 0 };
}, () => 200000, { getChatCloseAtMs: () => 300000, wait: async () => {} });
check('開始前の未登録は確定待ちで、登録後に起動する',
  pendingReads === 3 && afterPending?.groupId === 0);
let lateLandReads = 0;
let lateLandStart = 200000;
const lateLand = await pollRecoveryRosterAtStart(async () => {
  lateLandReads++;
  if (lateLandReads === 2) lateLandStart = 250000;
  return lateLandReads < 3
    ? { rosterAnchorStatus: 'none', rosterObservedAtMs: 201000,
      chattingStartMs: lateLandReads === 1 ? 200000 : 250000,
      chatCloseAtMs: lateLandReads === 1 ? 300000 : 350000 }
    : { rosterAnchorStatus: 'canonical', rosterAnchorHash: LATEST_HASH,
      rosterObservedAtMs: 251000, chattingStartMs: 250000,
      chatCloseAtMs: 350000, groupId: 1 };
}, () => lateLandStart, { wait: async () => {} });
check('旧開始後・延長着地前の未登録も確定待ちから延長後に起動する',
  lateLandReads === 3 && lateLand.groupId === 1);
for (const code of ['recomputed_roster_anchor_mismatch', 'roster_reconstruction_unavailable',
  'published_game_groups_mismatch']) {
  let reads = 0; let terminal = null;
  try {
    await pollRecoveryRosterAtStart(async () => {
      reads++;
      throw Object.assign(new Error(code), { code,
        warningKey: code === 'published_game_groups_mismatch' ? 'recovery.warn.rosterReconstructionStop.unknown' : undefined });
    }, () => 200000, { shouldContinue: () => reads < 3, wait: async () => {} });
  } catch (error) { terminal = error; }
  check(`恒久の ${code} は再構成を1回で止める`,
    reads === 1 && terminal?.code === code);
}
let unselectedReads = 0;
const unselected = await pollRecoveryRosterAtStart(async () => {
  unselectedReads++;
  return { rosterAnchorStatus: 'canonical', rosterObservedAtMs: 201000,
    rosterAnchorHash: HASH, groupId: null, reason: 'uid_not_selected' };
}, () => 200000, { shouldContinue: () => unselectedReads < 3, wait: async () => {} });
check('uid_not_selected は1回で待機を抜ける',
  unselectedReads === 1 && unselected?.reason === 'uid_not_selected');
rosterSequence = [{ rosterAnchorStatus: 'canonical', rosterObservedAtMs: 201000, rosterAnchorHash: HASH }];
let normalReads = 0;
check('復元の平時は開始後の確定行で即起動',
  (await pollRecoveryRosterAtStart(async () => { normalReads++; return rosterSequence.shift(); },
    () => 200000, { wait: async () => {} })).rosterAnchorHash === HASH
    && normalReads === 1);
let extendedStart = 200000;
rosterSequence = [
  { rosterAnchorStatus: 'canonical', rosterObservedAtMs: 201000, rosterAnchorHash: HASH },
  { rosterAnchorStatus: 'provisional', rosterObservedAtMs: 202000, rosterAnchorHash: HASH },
  { rosterAnchorStatus: 'canonical', rosterObservedAtMs: 251000, rosterAnchorHash: LATEST_HASH },
];
const afterGrace = await pollRecoveryRosterAtStart(async () => {
  const value = rosterSequence.shift();
  if (value?.rosterObservedAtMs === 201000) extendedStart = 250000;
  return value;
}, () => extendedStart, { wait: async () => {} });
check('grace 延長中は旧開始を終点とせず、延長後の X で停止',
  afterGrace.rosterAnchorHash === LATEST_HASH && finalRosterHashMatches(afterGrace, HASH, extendedStart) === false);
check('正典 hash が不変の grace 延長は継続可能',
  finalRosterHashMatches({ ...afterGrace, rosterAnchorHash: HASH }, HASH, extendedStart));
check('再確認が暫定・開始前なら同じ hash でも採らない',
  !finalRosterHashMatches({ ...afterGrace, rosterAnchorStatus: 'provisional' }, HASH, extendedStart)
    && !finalRosterHashMatches({ ...afterGrace, rosterObservedAtMs: 249000, rosterAnchorHash: HASH }, HASH, extendedStart));
const recoveryAppSource = await readFile(process.env.P8A_APP_SOURCE
  || new URL('../src/recovery/app.js', import.meta.url), 'utf8');
check('復元 UI は暫定中に鍵・relay を作らず、最終行の後で起動',
  /state\.rosterPaused = true;\s*state\.rosterInvalid = false;/.test(recoveryAppSource)
    && /roster = await waitForFinalRoster\(\);/.test(recoveryAppSource)
    && recoveryAppSource.indexOf('roster = await waitForFinalRoster()')
      < recoveryAppSource.indexOf('state.identity = await deriveBlockIdentity')
    && recoveryAppSource.indexOf('roster = await waitForFinalRoster()')
      < recoveryAppSource.indexOf('state.groupId = roster.groupId'));
check('Sign & load の最初の名簿読取も再試行ループ内',
  /let roster;\s*try \{\s*roster = await waitForFinalRoster\(\);/.test(recoveryAppSource));
check('開始変更は名簿 hash を再照合し、変化したら relay を止める',
  /if \(\(startChanged \|\| \(state\.rosterPaused && state\.rosterCheckCount === 0\)\) && state\.rosterAnchorHash\)/.test(recoveryAppSource)
    && /finalRosterHashMatches\(roster, state\.rosterAnchorHash, state\.timeline\.chattingStart\)/.test(recoveryAppSource)
    && /function stopForChangedRoster\(\)[\s\S]*?state\.relay\?\.stop\(\)/.test(recoveryAppSource));
check('提出の組立前と送信直前の双方で現在の hash を照合',
  /async function reconstructAndSubmit\(\)[\s\S]*?if \(!await confirmCurrentRosterHash\(\)\) return;/.test(recoveryAppSource)
    && /if \(!rosterReady\(\) \|\| !await confirmCurrentRosterHash\(\) \|\| !rosterReady\(\)\) return;\s*const res = await submitResultOnChain/.test(recoveryAppSource));
check('保留中は発言・投票・密告・受領証明の署名入口を閉じる',
  ['sendChat(text)'].every((signature) =>
    recoveryAppSource.includes(`async function ${signature} {\n  if (!rosterReady()) return;`))
    && /async function sendReport\(targetUid\) \{\s*const warningAccepted = state\.reportWarningAccepted;\s*state\.reportWarningAccepted = false;\s*if \(!rosterReady\(\)\) return;/.test(recoveryAppSource)
    && /async function sendVote\(targetUid\) \{\s*const warningAccepted = state\.voteWarningAccepted;\s*state\.voteWarningAccepted = false;\s*if \(!rosterReady\(\)\) return;/.test(recoveryAppSource)
    && /async function issueActionReceipt\(actorUid, actionType, action\) \{\s*if \(!rosterReady\(\) \|\| !state\.identity \|\| !state\.relay/.test(recoveryAppSource)
    && /const receipt = \{ receiverUid: state\.uid, actionHash, timestamp, signature \};\s*if \(!rosterReady\(\)\)/.test(recoveryAppSource)
    && /async function issueReadReceiptBatch\(\{ signal, known, tickCorrection = recoveryClock\.getClockCorrection\(\) \} = \{\}\) \{\s*if \(signal\?\.aborted\) return;\s*if \(!rosterReady\(\)/.test(recoveryAppSource));
check('提出バンドルとトリムのウォレット署名も保留中は拒む',
  /signWallet: guardedWalletSigner/.test(recoveryAppSource)
    && /signMessage: guardedWalletSigner/.test(recoveryAppSource)
    && /signReceiptAggregate: recoverySignReceiptAggregate/.test(recoveryAppSource)
    && /async function recoverySignReceiptAggregate\(message\) \{\s*if \(!rosterReady\(\)\)/.test(recoveryAppSource));
check('復元 UI の保留・再読込文面は英日中で実文',
  ['en', 'ja', 'zh'].every((lang) => ['recovery.warn.rosterProvisional',
    'recovery.warn.rosterRechecking', 'recovery.warn.rosterChanged'].every((key) => hasTranslation(lang, key))));

// app の実関門を抽出実行する。コメント・正規表現の綴りだけでは通らない。
const appSlice = (start, end) => {
  const from = recoveryAppSource.indexOf(start);
  const to = recoveryAppSource.indexOf(end, from + start.length);
  if (from < 0 || to < 0) throw new Error(`app function missing: ${start}`);
  return recoveryAppSource.slice(from, to);
};
const appGateSource = [
  appSlice('function rosterReady()', 'async function refreshEvidenceSenderCount()'),
  appSlice('function stopForChangedRoster()', 'function rosterFetchOptions('),
  appSlice('async function waitForFinalRoster', 'function showPersistenceWarning('),
  appSlice('async function refreshTimeline(', 'function currentPhase()'),
  appSlice('async function confirmCurrentRosterHash()', '// --- 提出（結果窓） ---'),
  appSlice('async function reconstructAndSubmit()', '// ============================================================\n// レンダリング'),
].join('\n');
function appGateHarness({ anchors, timelines, initialHash = HASH, maxR2Reads = 0,
  blockedKey = 'game_selection.json', matchCurrentAnchor = false,
  r2Rosters = [], r2Failures = 0, r2Error = null, verifiedRosters = new Map() } = {}) {
  let chainReads = 0; let r2Reads = 0; let submitCount = 0; let relayStops = 0;
  let builtFromReceipts = false;
  let bundleRosterConfirmed = null;
  let bundleChatWindow = null;
  const hiddenKeys = new Set();
  let hiddenCalls = 0;
  let bundleHiddenKeys = null;
  let pollChecks = 0;
  const waits = [];
  let currentAnchor = null;
  const logs = [];
  const initialTimeline = { chattingStart: 200000, chatCloseAt: 300000, graceSec: 0 };
  const state = {
    cfg: { contracts: { evidence: contracts.evidence }, pins: { chatCaps: {} } },
    blockNum: 1, uid: 'u1', address: '0x123', provider: {},
    identity: { signKey: HASH, encryptKey: HASH },
    members: [{ uid: 'u1', depIds: JSON.stringify({ ids: [] }) }],
    relay: { stop: () => { relayStops++; }, getMessages: () => [] },
    timeline: initialTimeline, _client: { waitForTransactionReceipt: async () => ({ status: 'success' }) },
    rosterAnchorHash: initialHash, rosterPaused: false, rosterInvalid: false,
    rosterCheckCount: 0, verifiedRosters, rosterWaitCancelled: false,
    rosterProofReady: true,
    myVote: null, myVotePrev: [], myReports: [], observedActions: {}, receipts: {}, intent: {},
    tr: (key) => key,
  };
  const anchorRows = [...anchors];
  const timelineRows = [...(timelines || [initialTimeline])];
  const roster = { rosterAnchorHash: HASH, rosterAnchorStatus: 'provisional',
    rosterObservedAtMs: 190000, groupId: 0, members: state.members };
  const bindings = {
    state, loadReportGrounds, mergeReportGroundMaps, usableRecoveryLock: () => null,
    renderClockModal: () => {}, makeTimeReadClient: () => ({ getBlock: async () => ({ timestamp: 0n }) }),
    DEFAULTS: { rpcPresets: [] }, clientNow: () => Date.now(), separatorPoint, checkClock: async () => {},
    recoveryClock: { getClockCorrection: () => 0 }, observeOtherSessionItem: () => {},
    considerRecoveryFuture: () => {},
    PartialReadReceiptTracker: class {},
    ReceiptWarnings: class {},
    readGameTimelineMs: async () => timelineRows.length > 1 ? timelineRows.shift() : timelineRows[0],
    readCanonicalRosterEvidence: async () => {
      chainReads++;
      const row = anchorRows.length > 1 ? anchorRows.shift() : anchorRows[0];
      if (row instanceof Error) throw row;
      currentAnchor = row;
      return row;
    },
    warnLateRoster: () => {},
    fetchCurrentRoster: async () => {
      r2Reads++;
      if (r2Error) throw r2Error;
      if (r2Reads <= r2Failures) throw new Error(`R2 403 ${blockedKey}`);
      if (r2Reads > maxR2Reads) throw new Error(`R2 403 ${blockedKey}`);
      if (r2Rosters.length) return r2Rosters.shift();
      return matchCurrentAnchor ? { ...roster, rosterAnchorHash: currentAnchor.rosterAnchorHash } : roster;
    },
    pollRecoveryRosterAtStart: (fetchCurrent, getStart, opts) =>
      pollRecoveryRosterAtStart(fetchCurrent, getStart, { ...opts,
        shouldContinue: () => opts.shouldContinue() && ++pollChecks < 30,
        wait: async (ms) => { waits.push(ms); } }),
    showRosterIntegrityWarning: (message) => logs.push(message),
    log: (message) => logs.push(message),
    renderGame: () => {}, clearProvisionalRosterWarning: () => {},
    pollLiveSnapshot: async () => {}, LIVE_SNAPSHOT_POLL_MS: 30000,
    finalRosterHashMatches,
    setTimeout: () => {},
    makeSigner: () => async () => 'signature',
    makeWalletClient: () => ({}),
    buildSubmissionBundle: async (args) => {
      builtFromReceipts = Array.isArray(args.receipts) && args.receipts.length === Object.values(state.receipts).length
        && !Object.hasOwn(args, 'selectedReadReceipts');
      bundleRosterConfirmed = args.rosterConfirmed;
      bundleChatWindow = args.chatWindow;
      bundleHiddenKeys = args.hiddenMessageKeys;
      return { payload: 'payload' };
    },
    selfVerifyIntent: () => ({}),
    chatWindowMsFromTimeline: () => [200000, 300000],
    submissionChatWindow: () => [200000, 300000],
    recoveryOvercapHiddenKeys: () => { hiddenCalls++; return hiddenKeys; },
    recoveryAdmittedReceipts: () => Object.values(state.receipts),
    recoveryShownKeys: () => new Set(),
    recoveryShownMemory: { identity: null, keys: new Set(), savedKeys: new Set(), timer: null },
    overcapHiddenMemo: null,
    submissionChatCloseAt: () => 300000,
    planOnChainTrim: async () => null,
    submitResultOnChain: async () => { submitCount++; return { hash: HASH, byteLength: 7 }; },
    saveRecoveryEvidencePayload: () => true,
    isRecoveryEvidencePayloadPersistent: () => true,
    isRecoveryRosterProofPersistent: () => true,
    showVolatileRescueWarning: () => logs.push('volatile rescue'),
    $: () => null, document: { querySelector: () => null },
    localStorage: { setItem: () => {} }, saveOnchainTx: () => {},
    privateKeyToAccount: () => ({}), canonicalizeSignature: (value) => value,
    signTrimmedPayload: async () => '', describeTrimPlan: () => [],
    EVIDENCE_MAX_DATA_BYTES: 100000, window: { confirm: () => true },
    recoveryPressFieldWindow: async () => ({ kind: 'current' }),
    recoveryGuaranteePressing: false,
    recoveryGuaranteeScheduler: { cancel() {} }, scheduleRecoveryGuarantee() {},
    syncRecoverySubmitButtons() {},
  };
  const gates = new Function(...Object.keys(bindings),
    `${appGateSource}\nreturn { rosterReady, stopForChangedRoster, waitForFinalRoster, refreshTimeline, confirmCurrentRosterHash, reconstructAndSubmit };`)(
    ...Object.values(bindings));
  return { state, gates, logs, waits,
    counts: () => ({ chainReads, r2Reads, submitCount, relayStops, builtFromReceipts,
      bundleRosterConfirmed, bundleChatWindow, hiddenCalls, hiddenKeys, bundleHiddenKeys }) };
}
const canonicalAt = (hash = HASH, chattingStartMs = 200000, observedAtMs = 201000) => ({
  rosterAnchorStatus: 'canonical', rosterAnchorHash: hash,
  rosterObservedAtMs: observedAtMs, chattingStartMs,
  chatCloseAtMs: chattingStartMs + 100000, lateCount: 0,
});
const submittedWithoutR2 = appGateHarness({ anchors: [canonicalAt()], maxR2Reads: 0 });
await submittedWithoutR2.gates.reconstructAndSubmit();
check('復元の提出は受理済みの state.receipts から bundle を組み立てる',
  submittedWithoutR2.counts().builtFromReceipts);
check('復元の隠す集合は同じ参照で bundle に渡る',
  submittedWithoutR2.counts().hiddenCalls === 1
    && submittedWithoutR2.counts().bundleHiddenKeys === submittedWithoutR2.counts().hiddenKeys);
const operatorSubmission = appGateHarness({ anchors: [canonicalAt()], maxR2Reads: 0 });
operatorSubmission.state.cfg.operatorRpc = 'https://operator.example';
await operatorSubmission.gates.reconstructAndSubmit();
check('運営ノードを選んでも確定名簿と窓で最優先欄の準備を渡す',
  operatorSubmission.counts().bundleRosterConfirmed === true
    && JSON.stringify(operatorSubmission.counts().bundleChatWindow) === JSON.stringify([200000, 300000])
    && operatorSubmission.counts().submitCount === 1);
check('R2 の再読取が403でも組立前・送信直前のチェーン再照合で提出できる',
  submittedWithoutR2.counts().submitCount === 1
    && submittedWithoutR2.counts().r2Reads === 0
    && submittedWithoutR2.counts().chainReads === 2,
  JSON.stringify(submittedWithoutR2.counts()));
for (const blockedKey of ['game_selection.json', 'info/00_info.json',
  'entries/00_0.json', 'roster/manifest.json']) {
  const held = appGateHarness({ anchors: [canonicalAt()], maxR2Reads: 0, blockedKey });
  await held.gates.reconstructAndSubmit();
  check(`再照合中に ${blockedKey} が403でも既検証hashで提出`,
    held.counts().submitCount === 1 && held.counts().r2Reads === 0);
}
const preStart = appGateHarness({ initialHash: null, maxR2Reads: 1,
  anchors: [{ ...canonicalAt(), rosterAnchorStatus: 'provisional', rosterObservedAtMs: 190000 },
    canonicalAt()] });
const afterBoundary = await preStart.gates.waitForFinalRoster();
check('開始前に検証した hash は開始境界で R2 を再読せず鍵導出へ渡す',
  afterBoundary?.groupId === 0 && preStart.counts().r2Reads === 1
    && preStart.counts().chainReads === 2,
  JSON.stringify(preStart.counts()));
const preStartChanged = appGateHarness({ initialHash: null, maxR2Reads: 2,
  matchCurrentAnchor: true,
  anchors: [{ ...canonicalAt(HASH), rosterAnchorStatus: 'provisional', rosterObservedAtMs: 190000 },
    { ...canonicalAt(LATEST_HASH), rosterAnchorStatus: 'provisional', rosterObservedAtMs: 191000 },
    canonicalAt(LATEST_HASH)] });
const changedBeforeStart = await preStartChanged.gates.waitForFinalRoster();
check('開始前に正典 hash が変われば新 hash を1回検証し、境界では再読しない',
  changedBeforeStart?.rosterAnchorHash === LATEST_HASH
    && preStartChanged.counts().r2Reads === 2
    && preStartChanged.counts().chainReads === 3);
const cancelledWait = appGateHarness({ anchors: [canonicalAt()] });
cancelledWait.state.rosterWaitCancelled = true;
check('利用者の中止は待機ループを抜け、鍵・R2 を読まない',
  await cancelledWait.gates.waitForFinalRoster() === null
    && cancelledWait.counts().chainReads === 0
    && cancelledWait.counts().r2Reads === 0);
const extendedTimeline = { chattingStart: 201000, chatCloseAt: 301000, graceSec: 1 };
const extended = appGateHarness({ anchors: [canonicalAt(HASH, 201000, 201001)],
  timelines: [extendedTimeline] });
await extended.gates.refreshTimeline();
check('チャット中の grace +1秒でも同じ hash は署名可能へ戻り R2 は読まない',
  extended.gates.rosterReady() && extended.counts().r2Reads === 0
    && extended.counts().chainReads === 1,
  JSON.stringify(extended.counts()));
const changed = appGateHarness({ anchors: [canonicalAt(LATEST_HASH, 201000, 201001)],
  timelines: [extendedTimeline] });
await changed.gates.refreshTimeline();
const refreshInvalid = changed.state.rosterInvalid;
const refreshRelayStops = changed.counts().relayStops;
await changed.gates.reconstructAndSubmit();
check('開始後の正典 hash 変化は relay を止めて提出しない',
  refreshInvalid && refreshRelayStops === 1
    && changed.counts().submitCount === 0 && changed.counts().r2Reads === 0,
  JSON.stringify(changed.counts()));
const transient = appGateHarness({ anchors: [Object.assign(new Error('temporary -32603'), { code: -32603 }),
  canonicalAt()] });
await transient.gates.reconstructAndSubmit();
check('一過性 -32603 の後はラッチせず再読込なしで提出できる',
  transient.counts().submitCount === 1 && transient.counts().r2Reads === 0
    && transient.state.rosterInvalid === false,
  JSON.stringify(transient.counts()));
const staleStart = appGateHarness({ anchors: [canonicalAt(HASH, 200000, 201001),
  canonicalAt(HASH, 201000, 201002)], timelines: [extendedTimeline] });
const fresh = await staleStart.gates.waitForFinalRoster();
check('延長前の固定ブロックの行は開始が一致するまで読み直す',
  fresh?.chattingStartMs === 201000 && staleStart.counts().chainReads === 2);
const invalidFlag = appGateHarness({ anchors: [canonicalAt()] });
invalidFlag.state.rosterInvalid = true;
check('rosterReady は invalid 旗だけでも鍵・提出を閉じる',
  invalidFlag.gates.rosterReady() === false);
const mismatchBeforeSubmit = appGateHarness({ anchors: [canonicalAt(LATEST_HASH)] });
const mismatchAllowed = await mismatchBeforeSubmit.gates.confirmCurrentRosterHash();
check('提出前の正典 hash 不一致は false と latch を返す',
  mismatchAllowed === false && mismatchBeforeSubmit.state.rosterInvalid
    && mismatchBeforeSubmit.counts().relayStops === 1);
const abortRead = Object.assign(new Error('history read failed'), { warningKey: 'roster_history_failed' });
const confirmReadFailure = appGateHarness({ anchors: [abortRead] });
const confirmAllowed = await confirmReadFailure.gates.confirmCurrentRosterHash();
check('A06: 提出前のチェーン読取失敗は提出を許さず latch もしない',
  confirmAllowed === false && !confirmReadFailure.state.rosterInvalid
    && confirmReadFailure.counts().relayStops === 0);
const staleCancelAtSubmit = appGateHarness({ anchors: [canonicalAt()] });
staleCancelAtSubmit.state.rosterWaitCancelled = true;
await staleCancelAtSubmit.gates.reconstructAndSubmit();
check('提出前の再照合は古い利用者中止旗に影響されず同じ hash を提出',
  staleCancelAtSubmit.counts().submitCount === 1
    && !staleCancelAtSubmit.state.rosterInvalid && staleCancelAtSubmit.counts().relayStops === 0);
const refreshReadFailure = appGateHarness({ anchors: [abortRead],
  timelines: [extendedTimeline] });
await refreshReadFailure.gates.refreshTimeline();
check('A10: 延長時の再照合が未確認なら保留旗を下ろさない',
  refreshReadFailure.state.rosterPaused && !refreshReadFailure.gates.rosterReady()
    && !refreshReadFailure.state.rosterInvalid);
const staleCancelAtRefresh = appGateHarness({ anchors: [canonicalAt(HASH, 201000, 201001)],
  timelines: [extendedTimeline] });
staleCancelAtRefresh.state.rosterWaitCancelled = true;
await staleCancelAtRefresh.gates.refreshTimeline();
check('延長時の再照合は古い利用者中止旗に影響されず同じ hash で再開',
  staleCancelAtRefresh.gates.rosterReady() && !staleCancelAtRefresh.state.rosterInvalid
    && staleCancelAtRefresh.counts().relayStops === 0);
const innerAnchor = appGateHarness({ initialHash: null, maxR2Reads: 2,
  anchors: [canonicalAt(LATEST_HASH)],
  r2Rosters: [
    { rosterAnchorHash: HASH, groupId: 1, members: [{ uid: 'u1' }] },
    { rosterAnchorHash: LATEST_HASH, groupId: 2, members: [{ uid: 'u1' }] },
  ] });
const innerResult = await innerAnchor.gates.waitForFinalRoster();
check('内側 H1 と外側 H2 が食い違う回は捨て、再構成した H2 の組を採る',
  innerResult?.rosterAnchorHash === LATEST_HASH && innerResult?.groupId === 2
    && innerAnchor.counts().r2Reads === 2 && innerAnchor.waits.join(',') === '1000',
  JSON.stringify({ result: innerResult?.groupId, ...innerAnchor.counts() }));
const unscopedKey = `1:${HASH.toLowerCase()}`;
const crossUidCache = appGateHarness({ initialHash: null, maxR2Reads: 1,
  anchors: [canonicalAt()],
  verifiedRosters: new Map([[unscopedKey,
    { rosterAnchorHash: HASH, groupId: 99, members: [{ uid: 'u2' }] }]]),
  r2Rosters: [{ rosterAnchorHash: HASH, groupId: 1, members: [{ uid: 'u1' }] }] });
const ownRoster = await crossUidCache.gates.waitForFinalRoster();
check('A08: 別 uid の検証済み組を同じ hash の鍵へ流用しない',
  ownRoster?.groupId === 1 && crossUidCache.counts().r2Reads === 1);
const retry = appGateHarness({ initialHash: null, maxR2Reads: 6, r2Failures: 5,
  anchors: [canonicalAt()], matchCurrentAnchor: true });
const afterRetry = await retry.gates.waitForFinalRoster();
check('未検証 hash の R2 読取失敗は上限付きの間隔で全再構成を再試行',
  afterRetry?.groupId === 0 && retry.waits.join(',') === '1000,2000,4000,8000,16000'
    && retry.counts().r2Reads === 6,
  JSON.stringify({ waits: retry.waits, ...retry.counts() }));
for (const code of ['recomputed_roster_anchor_mismatch', 'roster_reconstruction_unavailable']) {
  const terminal = appGateHarness({ initialHash: null, anchors: [canonicalAt()],
    r2Error: Object.assign(new Error(code), { code }) });
  let thrown = null;
  try { await terminal.gates.waitForFinalRoster(); } catch (error) { thrown = error; }
  check(`未検証 hash の恒久 ${code} は1回で中止`,
    thrown?.code === code && terminal.counts().r2Reads === 1 && terminal.waits.length === 0);
}
const nextRetry = appGateHarness({ initialHash: null, maxR2Reads: 2, r2Failures: 1,
  anchors: [canonicalAt()], matchCurrentAnchor: true });
await nextRetry.gates.waitForFinalRoster();
check('R2 成功後の次の待機は初回 1 秒から再開', nextRetry.waits.join(',') === '1000');
const retryError = () => Object.assign(new Error('temporary R2 failure'),
  { rosterReconstructionRetry: true });
let resetReads = 0;
const resetWaits = [];
await pollRecoveryRosterAtStart(async () => {
  resetReads++;
  if (resetReads === 1 || resetReads === 3) throw retryError();
  return resetReads === 2
    ? { ...canonicalAt(), rosterAnchorStatus: 'provisional', rosterObservedAtMs: 190000 }
    : canonicalAt();
}, () => 200000, { wait: async (ms) => { resetWaits.push(ms); } });
check('R2 の成功した観測を挟むと再構成失敗の待ちは 1 秒へ戻る',
  resetWaits.join(',') === '1000,1000,1000');
let cappedReads = 0;
const cappedWaits = [];
await pollRecoveryRosterAtStart(async () => {
  if (++cappedReads <= 7) throw retryError();
  return canonicalAt();
}, () => 200000, { wait: async (ms) => { cappedWaits.push(ms); } });
check('R2 の連続失敗の待ちは 30 秒を超えない',
  cappedWaits.join(',') === '1000,2000,4000,8000,16000,30000,30000');
let chainFailureReads = 0;
const chainFailureWaits = [];
await pollRecoveryRosterAtStart(async () => {
  if (++chainFailureReads <= 2) throw new Error('temporary chain read failure');
  return canonicalAt();
}, () => 200000, { wait: async (ms) => { chainFailureWaits.push(ms); } });
check('チェーンだけの一過性の待ちは従来どおり 1 秒',
  chainFailureWaits.join(',') === '1000,1000');

const lateWarningSource = appSlice('function warnLateRoster(', 'function rosterReady()');
const lateBox = { textContent: '' };
const lateMessages = [];
const lateState = { rosterLateCount: 0, tr: t('ja') };
const warnLate = new Function('state', '$', 'formatLateRosterWarning',
  'showRosterIntegrityWarning', 'log', `${lateWarningSource}\nreturn warnLateRoster;`)(
  lateState, () => lateBox, formatLateRosterWarning,
  (message) => { lateBox.textContent = message; }, (message) => lateMessages.push(message));
warnLate(0);
check('開始後の登録0件なら警告しない', lateMessages.length === 0 && lateBox.textContent === '');
warnLate(2);
check('開始後の登録を無視した件数を警告する',
  lateMessages.length === 1 && lateMessages[0].includes('2 件')
    && lateBox.textContent.includes('2 件'));

const deriveGateSource = appSlice('async function deriveAndLoad()', '// summary.json から表示専用メタ');
async function deriveGateIdentityCalls(rosterStartMs) {
  let identityCalls = 0;
  const button = { disabled: false, parentElement: { append: () => {} } };
  const state = { cfg: { contracts: { evidence: contracts.evidence }, pins: {} },
    blockNum: 1, provider: null, address: '0x123', rosterLateCount: 0,
    verifiedRosters: new Map(), tr: (key) => key, receiptWarningIdentity: 'old-game',
    clockWarning: { warning: { direction: 'late', stage: 'band' }, fullShown: true, reshowUsed: true } };
  const bindings = {
    state, loadReportGrounds, INITIAL_FUTURE_CLOCK_WARNING,
    recoveryGuaranteePressing: 0, recoveryDeriving: false,
    $: (id) => id === 'derive-btn' ? button : { value: 'u1' },
    renderClockModal: () => {},
    makeTimeReadClient: () => ({ getBlock: async () => ({ timestamp: 0n }) }),
    DEFAULTS: { rpcPresets: [] }, clientNow: () => Date.now(),
    PartialReadReceiptTracker: class {},
    ReceiptWarnings: class {},
    el: () => ({ remove: () => {} }), log: () => {},
    getWalletTransportIfMainnet: async () => null,
    makeR4Client: () => ({ getChainId: async () => 1, unagreedCount: () => 0 }), resolveRpcUrls: () => [],
    makeRecoveryAgreementState: () => ({ approved: new Set(), voterUrls: [], unagreed: 0,
      recordNoAgreement() {}, approve() {}, choose() {}, dismiss() {},
      staleBlock: { subscribe: () => () => {}, get: () => null } }),
    renderRecoveryNodePrompt: () => {}, renderStaleBlockBand: () => {}, readUntilAgreed: (read) => read(),
    readTimingConstants: async () => ({ invariantOk: true }),
    readGameTimelineMs: async () => ({ chattingStart: 200000, chatCloseAt: 300000 }),
    priorRecoveryStorageBlocks: () => [], clearFinalizedRecoveryBlockKeys: () => {},
    waitForFinalRoster: async () => ({ ...canonicalAt(HASH, rosterStartMs),
      groupId: 0, members: [{ uid: 'u1' }], liveRosterCrossChecked: true,
      rosterProof: { C: HASH, walletAddress: '0x123', proof: [], manifestHash: HASH } }),
    finalRosterHashMatches, clearProvisionalRosterWarning: () => {},
    showRosterIntegrityWarning: () => {}, warnLateRoster: () => {},
    enrichMembersFromSummary: async () => {}, makeSigner: () => ({}),
    configureRecoveryBlockKeyDomain: () => {},
    deriveBlockIdentity: async () => { identityCalls++; return { signKey: HASH }; },
    saveRecoveryRosterProof: () => true,
    isRecoveryRosterProofPersistent: () => true,
    showVolatileRescueWarning: () => {},
    refreshEvidenceSenderCount: async () => {}, setInterval: () => 0,
    startRecoveryLockPoints: () => {},
    saveConfirmedChatWindow: () => {}, localStorage: { setItem: () => {} },
    chatWindowMsFromTimeline: () => ({ startMs: 200000, endMs: 300000 }),
    deriveP2PKeys: () => { throw new Error('after identity'); },
    canStartRecoveryP2P: () => true,
    receiptDisplayMemo: null, provableMessagesMemo: null,
    recoveryShownMemory: { identity: null, keys: new Set(), savedKeys: new Set(), timer: null },
  };
  const derive = new Function(...Object.keys(bindings),
    `${deriveGateSource}\nreturn deriveAndLoad;`)(...Object.values(bindings));
  try { await derive(); } catch (error) {
    if (error.message !== 'after identity') throw error;
  }
  return { identityCalls, clockWarning: state.clockWarning };
}
check('deriveAndLoad の終点は古い開始の行では鍵を導出しない',
  (await deriveGateIdentityCalls(199000)).identityCalls === 0);
const newGame = await deriveGateIdentityCalls(200000);
check('deriveAndLoad の終点は一致する開始の行なら鍵導出へ進む',
  newGame.identityCalls === 1);
check('C3c: 復元の新しいゲームは帯と全画面の回数を初期に戻す',
  newGame.clockWarning?.warning === null && newGame.clockWarning?.fullShown === false
    && newGame.clockWarning?.reshowUsed === false);
async function loadWithCancelDuringSignature(initialCancelled = false, clickDuringSignature = true,
  p2pValid = true) {
  let cancelButton;
  let removedAtSignature = false;
  let submissions = 0;
  let relayStops = 0;
  let relayStarts = 0;
  let rememberedAtConfirmedWindow = 0;
  const logs = [];
  let r2Reads = 0;
  const button = { disabled: false, parentElement: { append: (value) => { cancelButton = value; } } };
  const state = {
    cfg: { contracts: { evidence: contracts.evidence }, pins: { chatCaps: {} }, r2Base: BASE },
    blockNum: 1, uid: null, address: '0x123', provider: {}, identity: null, relay: null,
    timeline: null, rosterAnchorHash: null, rosterPaused: false, rosterInvalid: false,
    rosterCheckCount: 0, verifiedRosters: new Map(), rosterWaitCancelled: initialCancelled,
    rosterProofReady: false,
    rosterLateCount: 0, myVote: null, myVotePrev: [], myReports: [], observedActions: {},
    receipts: {}, intent: {}, tr: (key) => key,
  };
  const anchor = canonicalAt();
  const bindings = {
    state, loadReportGrounds, mergeReportGroundMaps, INITIAL_FUTURE_CLOCK_WARNING: { warning: null, fullShown: false },
    renderClockModal: () => {}, makeTimeReadClient: () => ({ getBlock: async () => ({ timestamp: 0n }) }),
    considerRecoveryFuture: () => {},
    DEFAULTS: { rpcPresets: [] }, clientNow: () => Date.now(), separatorPoint, checkClock: async () => {},
    PartialReadReceiptTracker: class {},
    ReceiptWarnings: class {},
    $: (id) => id === 'derive-btn' ? button : id === 'uid-select'
      ? { value: 'u1' } : { style: {}, textContent: '' },
    el: (_, props) => ({ ...props, removed: false, remove() { this.removed = true; } }),
    getWalletTransportIfMainnet: async () => null,
    makeR4Client: () => ({ getChainId: async () => 1, unagreedCount: () => 0,
      waitForTransactionReceipt: async () => ({ status: 'success' }) }),
    makeRecoveryAgreementState: () => ({ approved: new Set(), voterUrls: [], unagreed: 0,
      recordNoAgreement() {}, approve() {}, choose() {}, dismiss() {},
      staleBlock: { subscribe: () => () => {}, get: () => null } }),
    renderRecoveryNodePrompt: () => {}, renderStaleBlockBand: () => {}, readUntilAgreed: (read) => read(),
    resolveRpcUrls: () => [],
    readTimingConstants: async () => ({ invariantOk: true, evidenceStartTimeSec: 1n }),
    readGameTimelineMs: async () => ({ chattingStart: 200000, chatCloseAt: 300000, graceSec: 0 }),
    priorRecoveryStorageBlocks: () => [], clearFinalizedRecoveryBlockKeys: () => {},
    readCanonicalRosterEvidence: async () => anchor,
    fetchCurrentRoster: async () => { r2Reads++; return { rosterAnchorHash: HASH, groupId: 0,
      members: [{ uid: 'u1', depIds: JSON.stringify({ ids: [] }) }],
      rosterProof: { C: HASH, walletAddress: '0x123', proof: [], manifestHash: HASH },
      source: 'anchored_roster', liveRosterCrossChecked: true }; },
    pollRecoveryRosterAtStart: (f, g, opts) => pollRecoveryRosterAtStart(f, g, {
      ...opts, wait: async () => {},
    }),
    finalRosterHashMatches, log: (message) => logs.push(message), showRosterIntegrityWarning: () => {},
    clearProvisionalRosterWarning: () => {}, warnLateRoster: () => {},
    enrichMembersFromSummary: async () => {}, makeSigner: () => async () => 'signature',
    configureRecoveryBlockKeyDomain: () => {},
    deriveBlockIdentity: async () => {
      removedAtSignature = cancelButton.removed;
      if (clickDuringSignature && !cancelButton.removed) cancelButton.onclick();
      return { signKey: HASH, encryptKey: HASH };
    },
    deriveP2PKeys: () => ({}),
    canStartRecoveryP2P: () => p2pValid,
    localStorage: { getItem: () => null, setItem: () => {} },
    saveRecoveryRosterProof: () => true,
    isRecoveryRosterProofPersistent: () => true,
    showVolatileRescueWarning: () => {},
    refreshEvidenceSenderCount: async () => {},
    startRecoveryLockPoints: () => {},
    RecoveryRelay: class {
      constructor() { this.futureMarks = { discard: () => false }; }
      async start() { relayStarts++; } stop() { relayStops++; }
      async verifyStoredReceipts() {}
      getRelayActionsRaw() { return {}; } getReceipts() { return []; } getMessages() { return []; }
    },
    renderGame: () => {}, handleSelfAction: () => {}, handleObservedActions: () => {},
    reopenReadReceiptPause: () => {},
    openReadReceiptPause,
    pollLiveSnapshot: async () => {}, LIVE_SNAPSHOT_POLL_MS: 30000,
    mergeReceipts: () => {}, setInterval: () => 0, clearInterval: () => {},
    setTimeout: () => 0, currentPhase: () => 'submitting',
    issueReadReceiptBatch: () => {}, READ_RECEIPT_BATCH_MS: 1000,
    recoveryClock: { getClockCorrection: () => 0 }, observeOtherSessionItem: () => {},
    setupActivityTracking: () => {}, timerText: () => '', relayStatusClass: () => '',
    relayStatusText: () => '', updateUnreadCountdowns: () => {},
    makeWalletClient: () => ({}), buildSubmissionBundle: async () => ({ payload: 'payload' }),
    usableRecoveryLock: () => null,
    selectedReadReceiptsForDisplay: () => [],
    receiptDisplayMemo: null, provableMessagesMemo: null,
    selfVerifyIntent: () => null, chatWindowMsFromTimeline: () => [200000, 300000],
    submissionChatWindow: () => [200000, 300000],
    recoveryOvercapHiddenKeys: () => new Set(), overcapHiddenMemo: null,
    recoveryAdmittedReceipts: () => Object.values(state.receipts),
    recoveryShownKeys: () => new Set(),
    recoveryShownMemory: { identity: null, keys: new Set(), savedKeys: new Set(), timer: null },
    submissionChatCloseAt: () => 300000,
    saveConfirmedChatWindow: () => {},
    saveRecoveryEvidencePayload: () => true,
    isRecoveryEvidencePayloadPersistent: () => true,
    planOnChainTrim: async () => null,
    submitResultOnChain: async () => { submissions++; return { hash: HASH, byteLength: 7 }; },
    document: { querySelector: () => null }, saveOnchainTx: () => {},
    privateKeyToAccount: () => ({}), canonicalizeSignature: (value) => value,
    signTrimmedPayload: async () => '', describeTrimPlan: () => [],
    EVIDENCE_MAX_DATA_BYTES: 100000, window: { confirm: () => true },
    recoveryPressFieldWindow: async () => ({ kind: 'current' }),
    recoveryGuaranteePressing: false, recoveryDeriving: false,
    recoveryGuaranteeScheduler: { cancel() {} }, scheduleRecoveryGuarantee() {},
    syncRecoverySubmitButtons() {},
  };
  const gates = new Function(...Object.keys(bindings),
    `${appGateSource}\n${deriveGateSource}\nreturn { deriveAndLoad, reconstructAndSubmit, refreshTimeline, rosterReady };`)(
    ...Object.values(bindings));
  await gates.deriveAndLoad();
  const readyAfterLoad = gates.rosterReady();
  await gates.reconstructAndSubmit();
  return { state, removedAtSignature, readyAfterLoad, submissions, relayStops, relayStarts,
    rememberedAtConfirmedWindow, logs, r2Reads };
}
const clickedAfterWait = await loadWithCancelDuringSignature();
const selfWithoutP2P = await loadWithCancelDuringSignature(false, false, false);
check('復元は本人の名簿鍵欠落で P2P なしを警告し、リレーなしで WS/Evidence の提出へ進む',
  selfWithoutP2P.relayStarts === 0
    && selfWithoutP2P.logs.some((line) => line.includes('P2P なし'))
    && selfWithoutP2P.readyAfterLoad && selfWithoutP2P.submissions === 1);
check('待機後は中止口を外し、署名中のクリックから提出前照合へ旗が残らない',
  clickedAfterWait.removedAtSignature && clickedAfterWait.readyAfterLoad
    && !clickedAfterWait.state.rosterWaitCancelled && !clickedAfterWait.state.rosterInvalid
    && clickedAfterWait.submissions === 1 && clickedAfterWait.relayStops === 0
    && clickedAfterWait.r2Reads === 1,
  JSON.stringify({ removed: clickedAfterWait.removedAtSignature,
    cancelled: clickedAfterWait.state.rosterWaitCancelled,
    submissions: clickedAfterWait.submissions, relayStops: clickedAfterWait.relayStops }));
const restartedWait = await loadWithCancelDuringSignature(true, false);
check('前回の中止旗は次の Sign & load の開始時に戻り、正しい名簿は通る',
  restartedWait.readyAfterLoad && restartedWait.submissions === 1
    && !restartedWait.state.rosterWaitCancelled);
rosterAnchors.set(keccak256(stringToHex('bitcoinu:roster:0')).toLowerCase(), initialManifest.hash);

try {
  const reconstructed = await fetchRoster(BASE, BLOCK, 'u2', options);
  check('roster/index と roster/group が無くても group を復元',
    reconstructed.groupId === 0 && reconstructed.members?.length === 3,
    JSON.stringify(reconstructed));
  check('復元結果は正典 hash と一致した committed_selection 由来',
    reconstructed.source === 'committed_selection'
      && reconstructed.recomputedRosterFallbackReason === 'canonical_manifest_match', JSON.stringify(reconstructed));
  const legacyRecomputedWarning = formatRosterIntegrityWarning(reconstructed, t('ja'));
  check('M9b: 旧HashStorageの再計算では現在値照合とmanifest一致をともに表示',
    legacyRecomputedWarning.includes('旧 HashStorage')
      && legacyRecomputedWarning.includes('現在のハッシュと一致')
      && !legacyRecomputedWarning.includes('正典ハッシュと一致'), legacyRecomputedWarning);
  const expectedNormalMembers = [players[2], players[1], players[0]].map((player) => {
    const bAddr = JSON.parse(player.data.bAddr);
    return {
      uid: player.data.uid,
      addr: player.data.addr,
      bAddr: { address: bAddr.address, pubKey: bAddr.pubKey, nostrPubkey: bAddr.nostrPubkey },
      depIds: player.data.depIds,
      lang: player.data.lang,
      globalIndex: player.globalIndex,
      name: player.data.name,
      img: player.data.img,
      verified: player.data.verified,
    };
  });
  const expectedNormal = {
    groupId: 0,
    members: expectedNormalMembers,
    reason: null,
    source: 'committed_selection',
    rosterProof: reconstructed.rosterProof,
    recomputedRosterFallback: true,
    recomputedRosterFallbackReason: 'canonical_manifest_match',
    recomputedRosterFallbackDetail: null,
    recomputedRosterFallbackAnchorError: 'anchored_roster_manifest_unavailable',
    rosterAnchorStatus: 'legacy',
    majorLangs: [],
    groupSeed: GROUP_SEED,
    rosterAnchorHash: initialManifest.hash,
    rosterObservedAtMs: 1400000,
    lateCount: 0,
  };
  check('名簿ファイル欠落時は正典hashと一致する再計算組を返す',
    JSON.stringify(reconstructed) === JSON.stringify(expectedNormal),
    JSON.stringify(reconstructed));
  check('selection integrity の resumable 例外をカーソル付きで最後まで再開',
    integrityCalls === 3 && integrityResumeFrom.join(',') === '0,1,2',
    `calls=${integrityCalls} resumeFrom=${integrityResumeFrom.join(',')}`);
  // HEAD「P12a block0: 公開groupsと錨名簿の両方が使えなくてもselectionから再計算して起動」:
  // R31-U-B では正典 manifest hash の一致が起動条件。不一致側も同じ入口で止める。
  objects.delete(`${BASE}/entries/block0/game_groups.json`);
  const blockZeroFallbackOptions = {
    ...options,
    rosterRegistrationReader: async () => ({ status: 'canonical', index: 0,
      row: { hash: initialManifest.hash, registeredBlock: 123, registeredAt: 1100 } }),
    anchoredRosterResolver: async () => { throw new Error('live anchored roster is unavailable'); },
    onWarning: () => {},
  };
  let blockZeroPositive = null;
  let blockZeroPositiveError = null;
  try { blockZeroPositive = await fetchRoster(BASE, 0, 'u2', blockZeroFallbackOptions); }
  catch (error) { blockZeroPositiveError = error; }
  check('M9c P12a block0 正: 公開groups・錨名簿欠落でも正典hash一致なら起動',
    blockZeroPositive?.source === 'committed_selection'
      && blockZeroPositive.groupId === 0
      && JSON.stringify(blockZeroPositive.members) === JSON.stringify(expectedNormalMembers)
      && blockZeroPositive.recomputedRosterFallbackReason === 'canonical_manifest_match',
    JSON.stringify(blockZeroPositive) || blockZeroPositiveError?.message || 'did not start');
  let blockZeroNegative = null;
  try {
    await fetchRoster(BASE, 0, 'u2', { ...blockZeroFallbackOptions,
      rosterRegistrationReader: async () => ({ status: 'canonical', index: 0,
        row: { hash: `0x${'ff'.repeat(32)}`, registeredBlock: 123, registeredAt: 1100 } }),
    });
  } catch (error) { blockZeroNegative = error; }
  check('M9c P12a block0 負: 公開groups・錨名簿欠落で正典hash不一致なら停止',
    blockZeroNegative?.code === 'recomputed_roster_anchor_mismatch',
    blockZeroNegative?.message || 'did not stop');
  objects.set(`${BASE}/entries/block0/game_groups.json`, publishedGroups);
  check('registrationCount > 1 は停止せず警告して復元を続行',
    registrationWarnings.length === 1
      && registrationWarnings[0].code === 'applicantHashRegistrationCount'
      && registrationWarnings[0].registrationCount === 2
      && registrationWarnings[0].selectionDiffersFromLatest === true,
    JSON.stringify(registrationWarnings));
  check('recovery_selection_registered_not_latest: 履歴membership=trueなら最新と違っても復元を続行',
    reconstructed.groupId === 0
      && registrationWarnings[0]?.selectionRegisteredBlock === selection.hashRegisteredBlock
      && registrationWarnings[0]?.latestRegisteredBlock === 101,
    JSON.stringify(registrationWarnings));
  for (const lang of ['en', 'ja', 'zh']) {
    const warningText = t(lang)('recovery.warn.applicantHashRegistrationCount', { registrationCount: 2 });
    check(`registrationCount 警告は ${lang} カタログで表示可能`,
      warningText.includes('2') && warningText !== 'recovery.warn.applicantHashRegistrationCount',
      warningText);
  }

  let missingRegistrationError = null;
  try {
    await fetchRoster(BASE, BLOCK, 'u2', {
      ...options,
      selectionAnchorsReader: async () => ({
        applicantHash: LATEST_HASH,
        applicantUpdatedBlock: 101,
        registrationCount: 2,
        selectionRegistered: false,
        legacyFallback: false,
        randaoEthBlockNumber: 164,
        randaoBlockHash: TARGET_HASH,
      }),
      onWarning: () => {},
    });
  } catch (error) {
    missingRegistrationError = error;
  }
  check('neg_recovery_selection_not_registered: 履歴membership=falseならthrow',
    /not present in HashStorage history/.test(missingRegistrationError?.message || ''),
    missingRegistrationError?.message || 'did not throw');

  check('legacy_allowlist_latest: 復元側の定数はcollector exportの1件と一致',
    LEGACY_HASH_STORAGE_ALLOWLIST.length === 1
      && JSON.stringify(LEGACY_HASH_STORAGE_ALLOWLIST)
        === JSON.stringify(COLLECTOR_LEGACY_HASH_STORAGE_ALLOWLIST));
  const legacyCalls = [];
  const legacyAnchors = await readSelectionAnchors({
    readContract: async ({ functionName }) => {
      legacyCalls.push(functionName);
      if (functionName === 'getApplicantHash') return [HASH, 100n, contracts.hashStorage];
      if (functionName === 'registrationCount') return 2n;
      if (functionName === 'blockHashOf') return TARGET_HASH;
      throw new Error(`unexpected legacy getter ${functionName}`);
    },
  }, {
    hashStorage: LEGACY_HASH_STORAGE_ALLOWLIST[0],
    evidence: contracts.evidence,
  }, BLOCK, 64, selection, { legacyHashStorage: true });
  check('legacy_allowlist_latest: 旧契約はmembership getterを呼ばず最新値で判定',
    legacyAnchors.legacyFallback === true
      && legacyAnchors.selectionRegistered === true
      && !legacyCalls.includes('isApplicantRegistered'),
    JSON.stringify({ legacyAnchors, legacyCalls }));

  // 周23 統括の追補: fetchRoster は契約のアドレスから旧契約の判定を作って reader へ渡す
  // （許可リスト外は false・許可リストの1件は大小文字を問わず true）。
  const forwardedLegacyFlags = [];
  const flagReader = async (_client, _contracts, _blockNum, _confirmations, _selection, flags) => {
    forwardedLegacyFlags.push(flags?.legacyHashStorage);
    return {
      applicantHash: HASH,
      applicantUpdatedBlock: 100,
      registrationCount: 1,
      selectionRegistered: true,
      legacyFallback: flags?.legacyHashStorage === true,
      randaoEthBlockNumber: 164,
      randaoBlockHash: TARGET_HASH,
    };
  };
  await fetchRoster(BASE, BLOCK, 'u2', { ...options,
    contracts: { ...contracts, hashStorage: `0x${'44'.repeat(20)}` },
    selectionAnchorsReader: flagReader,
    rosterRegistrationReader: async () => ({ status: 'legacy',
      row: { hash: initialManifest.hash, registeredBlock: 123 }, observedAtMs: 1400000 }),
    onWarning: () => {} });
  await fetchRoster(BASE, BLOCK, 'u2', {
    ...options,
    contracts: { ...contracts, hashStorage: `0x${LEGACY_HASH_STORAGE_ALLOWLIST[0].slice(2).toUpperCase()}` },
    selectionAnchorsReader: flagReader,
    onWarning: () => {},
  });
  check('legacy_flag_forwarded_by_address: 許可リスト外は false・許可リストの1件は大小文字を問わず true',
    forwardedLegacyFlags.length === 2
      && forwardedLegacyFlags[0] === false
      && forwardedLegacyFlags[1] === true,
    JSON.stringify(forwardedLegacyFlags));

  // 周23 統括の追補: 現行契約で selection が最新と違う登録を指すとき、RANDAO の目標は
  // 最新（101）ではなく selection の登録（100）+64 から作り、その高さの blockHashOf を読む。
  const historyCalls = [];
  const historyAnchors = await readSelectionAnchors({
    readContract: async ({ functionName, args = [] }) => {
      historyCalls.push({ functionName, args: args.map(String) });
      if (functionName === 'getApplicantHash') return [LATEST_HASH, 101n, contracts.hashStorage];
      if (functionName === 'registrationCount') return 2n;
      if (functionName === 'isApplicantRegistered') {
        return BigInt(args[1]) === 100n && String(args[2]).toLowerCase() === HASH;
      }
      if (functionName === 'blockHashOf') return TARGET_HASH;
      throw new Error(`unexpected getter ${functionName}`);
    },
  }, contracts, BLOCK, 64, selection);
  check('recovery_randao_target_from_selection: RANDAO目標は最新でなくselectionの登録+64',
    historyAnchors.selectionRegistered === true
      && historyAnchors.legacyFallback === false
      && historyAnchors.randaoEthBlockNumber === 164
      && historyCalls.some((call) => call.functionName === 'blockHashOf' && call.args[0] === '164'),
    JSON.stringify({ historyAnchors, historyCalls }));

  const resultCountAbi = HASH_STORAGE_ABI.find((item) => item.name === 'resultRegistrationCount');
  const resultAtAbi = HASH_STORAGE_ABI.find((item) => item.name === 'resultRegistrationAt');
  check('P8a 結果履歴ABI: count と registeredAt を含む row getter を宣言',
    resultCountAbi?.outputs?.[0]?.type === 'uint256'
      && resultAtAbi?.inputs?.[1]?.type === 'uint256'
      && resultAtAbi?.outputs?.[2]?.name === 'registeredAt'
      && resultAtAbi?.outputs?.[2]?.type === 'uint256');
  const otherAtAbi = HASH_STORAGE_ABI.find((item) => item.name === 'otherRegistrationAt');
  const otherCountAbi = HASH_STORAGE_ABI.find((item) => item.name === 'otherRegistrationCount');
  const canonicalCalls = [];
  const canonicalOther = await readCanonicalRosterRegistration({
    ...snapshotAt(1300n),
    readContract: async (request) => {
      canonicalCalls.push(request);
      if (request.functionName === 'otherRegistrationCount') return 2n;
      if (request.functionName === 'otherRegistrationAt') {
        return [request.args[1] === 0n ? LATEST_HASH : HASH, 777n,
          request.args[1] === 0n ? 1000n : 1100n];
      }
      throw new Error(`unexpected ${request.functionName}`);
    },
  }, contracts.hashStorage, contracts.evidence, 1, {
    nowMs: 1300_000,
    chatWindowReader: async () => ({ chatOpenAt: 900, chattingStart: 1200 }),
  });
  check('M9b: 名簿錨の履歴を共有selectorで開始前の最後の行へ絞る',
    otherCountAbi?.outputs?.[0]?.type === 'uint256'
      && otherAtAbi?.outputs?.[2]?.name === 'registeredAt'
      && canonicalOther.row.registeredAt === 1100
      && canonicalOther.row.hash === HASH.toLowerCase()
      && canonicalCalls.some((call) => call.args?.[1] === 0n)
      && canonicalCalls.every((call) => call.blockNumber === 200n));
  const stabilityReadCalls = [];
  const stabilityReaderClient = {
    readContract: async (request) => {
      stabilityReadCalls.push({ functionName: request.functionName, args: (request.args || []).map(String) });
      if (request.functionName === 'resultRegistrationCount') return 2n;
      if (request.functionName === 'resultRegistrationAt') {
        return [HASH, 777n, 888n, contracts.hashStorage];
      }
      if (request.functionName === 'getResultHash') return [HASH, 777n, contracts.hashStorage];
      if (request.functionName === 'chatWindow') return [999n, 1999n];
      if (request.functionName === 'GAME_PERIOD') return 900n;
      throw new Error(`unexpected stability getter ${request.functionName}`);
    },
  };
  const historyHead = await readResultRegistrationHistoryHead(
    stabilityReaderClient, contracts.hashStorage, 0,
  );
  const chatWindow = await readChatWindow(stabilityReaderClient, contracts.evidence, 1);
  check('P8a 結果履歴reader: Nの最終行とN+1のchatWindowを正しい添字で読む',
    historyHead.count === 2
      && historyHead.latest.index === 1
      && historyHead.latest.registeredAt === 888
      && historyHead.current.hash === HASH
      && chatWindow.chatOpenAt === 999
      && chatWindow.chattingStart === 1099
      && stabilityReadCalls.some((call) => (
        call.functionName === 'resultRegistrationAt' && call.args.join(',') === '0,1'
      ))
      && stabilityReadCalls.some((call) => (
        call.functionName === 'chatWindow' && call.args.join(',') === '1'
      )),
    JSON.stringify({ historyHead, chatWindow, stabilityReadCalls }));

  let getterError = null;
  try {
    await readSelectionAnchors({
      readContract: async ({ functionName }) => {
        if (functionName === 'getApplicantHash') return [HASH, 100n, contracts.hashStorage];
        if (functionName === 'registrationCount') return 1n;
        if (functionName === 'isApplicantRegistered') throw new Error('getter unavailable');
        if (functionName === 'blockHashOf') return TARGET_HASH;
        throw new Error(`unexpected getter ${functionName}`);
      },
    }, contracts, BLOCK, 64, selection);
  } catch (error) {
    getterError = error;
  }
  check('許可リスト外で履歴getterを読めなければthrow',
    /registration getter is unavailable/.test(getterError?.message || ''),
    getterError?.message || 'did not throw');

  // R3-14 / T-22: fetchRoster の chain 付き実行経路そのものを通す。
  // 依存を注入して、bare `client` 参照の回帰と live 名簿による上書きを同時に防ぐ。
  const committedMembers = structuredClone(reconstructed.members);
  const reconstructStub = async ({ client: receivedClient }) => {
    if (receivedClient !== client) throw new Error('stub client was not forwarded');
    return { groupId: 0, members: structuredClone(committedMembers), reason: null, source: 'committed_selection' };
  };
  const publicMembers = committedMembers.map((member) => ({
    uid: member.uid,
    walletAddress: member.addr,
    blockAddress: member.bAddr.address,
    pubKey: member.bAddr.pubKey,
    nostrPubkey: member.bAddr.nostrPubkey,
    depositIds: JSON.parse(member.depIds).ids,
    lang: member.lang,
    globalIndex: member.globalIndex,
    depositWei: '0',
    depositVerified: member.verified === true,
  }));
  const throughFetchRoster = (liveRosterVerifier) => fetchRoster(BASE, BLOCK, 'u2', {
    client, contracts, rosterReconstructor: reconstructStub, liveRosterVerifier,
  });

  const liveMatch = await throughFetchRoster(async ({ client: receivedClient }) => {
    if (receivedClient !== client) throw new Error('live verifier did not receive options.client');
    return { status: 'verified', members: publicMembers, updated: 123 };
  });
  check('T-22 正常系で committed_selection を権威として維持',
    liveMatch.source === 'committed_selection' && liveMatch.liveRosterCrossChecked === true
      && liveMatch.rosterMismatchCommitted === false);

  const mismatchedPublic = structuredClone(publicMembers);
  mismatchedPublic[0].pubKey = '0x04deadbeef';
  const liveMismatch = await throughFetchRoster(async () => ({
    status: 'verified', members: mismatchedPublic, updated: 124,
  }));
  check('T-22 live 不一致を検出しても commit 済み members を上書きしない',
    liveMismatch.rosterMismatchCommitted === true
      && JSON.stringify(liveMismatch.members) === JSON.stringify(committedMembers));
  const nostrMismatchPublic = structuredClone(publicMembers);
  nostrMismatchPublic[0].nostrPubkey = 'ab'.repeat(32);
  const nostrMismatch = await throughFetchRoster(async () => ({
    status: 'verified', members: nostrMismatchPublic, updated: 125,
  }));
  check('T-22 Nostr 鍵のすり替えも commit 済み名簿との不一致にする',
    nostrMismatch.rosterMismatchCommitted === true
      && JSON.stringify(nostrMismatch.members) === JSON.stringify(committedMembers));

  const liveUnavailable = await throughFetchRoster(async () => ({
    status: 'unavailable', reason: 'temporary rpc failure',
  }));
  check('T-22 live unavailable は commit 済み members で fail-open',
    liveUnavailable.source === 'committed_selection'
      && JSON.stringify(liveUnavailable.members) === JSON.stringify(committedMembers)
      && liveUnavailable.reason === 'temporary rpc failure');

  const sha256Hex = async (text) => {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
    return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  };
  const installAnchoredRosterGroups = async (blockNum, groupDefs, {
    indexOverride = undefined,
    includeIndexSha256 = true,
  } = {}) => {
    const groups = [];
    const groupTexts = new Map();
    const rosterIndex = Object.create(null);
    for (const { groupId, members } of groupDefs) {
      const roster = { blockNum, groupId, members };
      const rosterText = JSON.stringify(roster);
      groupTexts.set(groupId, rosterText);
      groups.push({ groupId, sha256: await sha256Hex(rosterText) });
      objects.set(`${BASE}/games/block${blockNum}/roster/group${groupId}.json`, roster);
      for (const member of members) rosterIndex[String(member.uid)] = groupId;
    }
    const effectiveIndex = indexOverride === undefined ? rosterIndex : indexOverride;
    const indexText = JSON.stringify(effectiveIndex);
    objects.set(`${BASE}/games/block${blockNum}/roster/index.json`, effectiveIndex);
    const manifest = {
      blockNum,
      ...(includeIndexSha256 ? { indexSha256: await sha256Hex(indexText) } : {}),
      groups,
    };
    const manifestText = JSON.stringify(manifest);
    objects.set(`${BASE}/games/block${blockNum}/roster/manifest.json`, manifest);
    const anchorKey = keccak256(stringToHex(`bitcoinu:roster:${blockNum}`)).toLowerCase();
    rosterAnchors.set(anchorKey, buildRosterMemberCommitment({ blockNum, manifestText, groupTexts }).C.toLowerCase());
    return anchorKey;
  };
  const installAnchoredRoster = (blockNum, groupId, members, settings = {}) => (
    installAnchoredRosterGroups(blockNum, [{ groupId, members }], settings)
  );

  // 1. N の現在値が N+1 の組分け後に変わっても、再計算せず錨つき名簿を採る。
  const selectionBlock1 = { ...structuredClone(selection), blockNum: 1 };
  objects.set(`${BASE}/entries/block1/game_selection.json`, selectionBlock1);
  for (let i = 0; i < 100; i++) {
    objects.set(`${BASE}/entries/block1/info/${String(i).padStart(2, '0')}_info.json`, {
      entries: i === 0 ? [{ filename: '00_0', number: 3 }] : [],
    });
  }
  await installAnchoredRosterGroups(1, [
    { groupId: 9, members: publicMembers.slice(2) },
    { groupId: 7, members: publicMembers.slice(0, 2) },
  ]);
  const fallbackIntegrityVerifier = async ({ selectionData, committedTotal }) => {
    if (selectionData.blockNum !== 1 || committedTotal !== 3) {
      throw new Error('fallback selection integrity input mismatch');
    }
  };
  const changedPrevious = await fetchRoster(BASE, 1, 'u2', {
    ...options,
    selectionAnchorsReader: async () => ({
      applicantHash: LATEST_HASH,
      applicantUpdatedBlock: 101,
      registrationCount: 2,
      selectionRegistered: true,
      legacyFallback: false,
      randaoEthBlockNumber: 164,
      randaoBlockHash: TARGET_HASH,
    }),
    selectionIntegrityVerifier: fallbackIntegrityVerifier,
    previousSummaryVerifier: async () => {
      const error = new Error('previous block 0 manifest does not match on-chain resultHash');
      error.code = 'previous_summary_anchor_mismatch';
      throw error;
    },
  });
  const expectedChangedPreviousMembers = [players[2], players[1]].map((player) => {
    const bAddr = JSON.parse(player.data.bAddr);
    return {
      uid: player.data.uid,
      addr: player.data.addr,
      bAddr: { address: bAddr.address, pubKey: bAddr.pubKey, nostrPubkey: bAddr.nostrPubkey },
      depIds: player.data.depIds,
      lang: player.data.lang,
      globalIndex: player.globalIndex,
      name: player.data.name,
      img: player.data.img,
      verified: player.data.verified,
    };
  });
  check('正: N が組分け後に変わっても錨つき名簿の正しい組で起動',
    changedPrevious.groupId === 7
      && changedPrevious.source === 'anchored_roster'
      && changedPrevious.anchoredRosterFallback === true
      && changedPrevious.rosterAnchorStatus === 'legacy'
      && JSON.stringify(changedPrevious.members) === JSON.stringify(expectedChangedPreviousMembers),
    JSON.stringify(changedPrevious));

  const unavailablePrevious = await fetchRoster(BASE, 1, 'u2', {
    ...options,
    selectionAnchorsReader: async () => ({
      applicantHash: LATEST_HASH,
      applicantUpdatedBlock: 101,
      registrationCount: 2,
      selectionRegistered: true,
      legacyFallback: false,
      randaoEthBlockNumber: 164,
      randaoBlockHash: TARGET_HASH,
    }),
    selectionIntegrityVerifier: fallbackIntegrityVerifier,
  });
  check('M9b: 錨つき名簿が読めるときは前ブロック成果物がなくてもその組を使う',
    unavailablePrevious.source === 'anchored_roster' && unavailablePrevious.groupId === 7,
    JSON.stringify(unavailablePrevious));

  // 2. game_groups.json の 404/5xx/JSON不正は null に潰れても再計算組を採らない。
  objects.delete(`${BASE}/entries/block0/game_groups.json`);
  await installAnchoredRoster(0, 4, publicMembers);
  const unavailablePublished = await fetchRoster(BASE, 0, 'u2', options);
  check('正: game_groups.json が読めないとき錨つき名簿の組を採用',
    unavailablePublished.groupId === 4
      && unavailablePublished.source === 'anchored_roster',
    JSON.stringify(unavailablePublished));

  // 再計算結果と公開 game_groups.json が食い違う場合も同じ限定経路へ入る。
  objects.set(`${BASE}/entries/block0/game_groups.json`, {
    ...structuredClone(publishedGroups),
    groups: [{
      ...publishedGroups.groups[0], memberIds: ['u1', 'u2', 'u3'],
    }],
  });
  await installAnchoredRoster(0, 8, publicMembers);
  const mismatchedPublished = await fetchRoster(BASE, 0, 'u2', options);
  check('正: 再計算組と game_groups.json が食い違うときも錨つき名簿の組を採用',
    mismatchedPublished.groupId === 8
      && mismatchedPublished.source === 'anchored_roster',
    JSON.stringify(mismatchedPublished));

  // 3. manifest/group の暗号学的検証が通っても、selection にいない人の追加・差し替えは止める。
  const substitutedMembers = structuredClone(publicMembers);
  substitutedMembers[0].uid = 'attacker';
  await installAnchoredRoster(0, 5, substitutedMembers);
  let selectionMismatchError = null;
  try {
    await resolveAnchoredRosterFromSelection({
      r2Base: BASE, blockNum: 0, uid: 'u2', client, hashStorage: contracts.hashStorage, evidence: contracts.evidence,
      selection,
    });
  } catch (error) { selectionMismatchError = error; }
  check('負: 錨つき名簿への人の追加・差し替えは selection 全体照合で停止',
    /index uid set does not match the verified selection/.test(selectionMismatchError?.message || ''),
    selectionMismatchError?.message || 'did not throw');

  const changedFieldMembers = structuredClone(publicMembers);
  changedFieldMembers[0].pubKey = '04evil';
  await installAnchoredRosterGroups(0, [
    { groupId: 10, members: changedFieldMembers.slice(2) },
    { groupId: 9, members: changedFieldMembers.slice(0, 2) },
  ]);
  let changedFieldError = null;
  try {
    await resolveAnchoredRosterFromSelection({
      r2Base: BASE, blockNum: 0, uid: 'u2', client, hashStorage: contracts.hashStorage, evidence: contracts.evidence,
      selection,
    });
  } catch (error) { changedFieldError = error; }
  check('負: 対象組の wallet・blockAddress・pubKey・depositIds の差し替えは停止',
    /member u3 differs from the verified selection: pubKey/.test(changedFieldError?.message || ''),
    changedFieldError?.message || 'did not throw');
  const changedNostrMembers = structuredClone(publicMembers);
  changedNostrMembers[0].nostrPubkey = 'ab'.repeat(32);
  await installAnchoredRosterGroups(0, [
    { groupId: 10, members: changedNostrMembers.slice(2) },
    { groupId: 9, members: changedNostrMembers.slice(0, 2) },
  ]);
  let changedNostrError = null;
  try {
    await resolveAnchoredRosterFromSelection({
      r2Base: BASE, blockNum: 0, uid: 'u2', client, hashStorage: contracts.hashStorage, evidence: contracts.evidence,
      selection,
    });
  } catch (error) { changedNostrError = error; }
  check('負: 錨つき名簿の Nostr 鍵の差し替えは停止',
    /member u3 differs from the verified selection: nostrPubkey/.test(changedNostrError?.message || ''),
    changedNostrError?.message || 'did not throw');
  for (const [field, value] of [
    ['lang', 'fr'], ['globalIndex', 99], ['depositWei', '1'], ['depositVerified', false],
  ]) {
    const changed = structuredClone(publicMembers);
    changed[0][field] = value;
    await installAnchoredRosterGroups(0, [
      { groupId: 10, members: changed.slice(2) },
      { groupId: 9, members: changed.slice(0, 2) },
    ]);
    let error = null;
    try {
      await resolveAnchoredRosterFromSelection({ r2Base: BASE, blockNum: 0, uid: 'u2',
        client, hashStorage: contracts.hashStorage, evidence: contracts.evidence, selection });
    } catch (cause) { error = cause; }
    check(`負: 錨つき名簿の ${field} の差し替えは停止`,
      error?.message?.includes(`member u3 differs from the verified selection: ${field}`),
      error?.message || 'did not throw');
  }

  // P8a M7: index と group を一緒に作り直して人を消しても、selection の uid 集合との差で止まる。
  const deletedMembers = publicMembers.slice(0, 2);
  await installAnchoredRoster(0, 11, deletedMembers);
  let deletedMemberError = null;
  try {
    await resolveAnchoredRosterFromSelection({
      r2Base: BASE, blockNum: 0, uid: 'u2', client, hashStorage: contracts.hashStorage, evidence: contracts.evidence,
      selection,
    });
  } catch (error) { deletedMemberError = error; }
  check('P8a M7 負: index と対象組から当選者を1人消しても selection 全体照合で停止',
    /index uid set does not match the verified selection/.test(deletedMemberError?.message || ''),
    deletedMemberError?.message || 'did not throw');

  // P8a M9: chain錨はmanifestを守り、manifestのsha256は対象group rawを守る。
  await installAnchoredRoster(0, 12, publicMembers);
  const tamperedGroup = structuredClone(objects.get(`${BASE}/games/block0/roster/group12.json`));
  tamperedGroup.members[0].walletAddress = `0x${'ee'.repeat(20)}`;
  objects.set(`${BASE}/games/block0/roster/group12.json`, tamperedGroup);
  let groupShaError = null;
  try {
    await resolveAnchoredRosterFromSelection({
      r2Base: BASE, blockNum: 0, uid: 'u2', client, hashStorage: contracts.hashStorage, evidence: contracts.evidence,
      selection,
    });
  } catch (error) { groupShaError = error; }
  check('P8a M9 負: 対象group rawのsha256がmanifestと違えば停止',
    /group 12 sha256 mismatch/.test(groupShaError?.message || ''),
    groupShaError?.message || 'did not throw');

  // P8a M13: 人数より多いgroup entryを持つmanifestはindex読取前に拒否する。
  await installAnchoredRosterGroups(0, [
    { groupId: 20, members: [publicMembers[0]] },
    { groupId: 21, members: [publicMembers[1]] },
    { groupId: 22, members: [publicMembers[2]] },
    { groupId: 23, members: [] },
  ]);
  let excessGroupsError = null;
  try {
    await resolveAnchoredRosterFromSelection({
      r2Base: BASE, blockNum: 0, uid: 'u2', client, hashStorage: contracts.hashStorage, evidence: contracts.evidence,
      selection,
    });
  } catch (error) { excessGroupsError = error; }
  check('P8a M13 負: manifestのgroup数がselection人数を超えれば停止',
    /group count exceeds the verified selection/.test(excessGroupsError?.message || ''),
    excessGroupsError?.message || 'did not throw');

  // 3本を各30ms、期限50msで読む。全体は90ms超でも、各リクエストが期限内なら通る。
  await installAnchoredRosterGroups(0, [
    { groupId: 31, members: [publicMembers[2]] },
    { groupId: 30, members: publicMembers.slice(0, 2) },
  ]);
  const boundedPaths = [
    `${BASE}/games/block0/roster/manifest.json`,
    `${BASE}/games/block0/roster/index.json`,
    `${BASE}/games/block0/roster/group31.json`,
    `${BASE}/games/block0/roster/group30.json`,
  ];
  for (const path of boundedPaths) fetchDelays.set(path, 30);
  fetchedUrls.length = 0;
  const perRequestBudgetRoster = await resolveAnchoredRosterFromSelection({
    r2Base: BASE, blockNum: 0, uid: 'u2', client, hashStorage: contracts.hashStorage, evidence: contracts.evidence,
    selection, timeoutMs: 50,
  });
  for (const path of boundedPaths) fetchDelays.delete(path);
  const rosterReads = fetchedUrls.filter((url) => url.includes('/games/block0/roster/'));
  check('P8a recovery_blocked: 期限は各リクエストに掛かり、C の全組を読む',
    perRequestBudgetRoster.groupId === 30
      && rosterReads.length === boundedPaths.length
      && boundedPaths.every((path) => rosterReads.includes(path)),
    JSON.stringify({ perRequestBudgetRoster, rosterReads }));

  await installAnchoredRosterGroups(0, [
    { groupId: 41, members: [publicMembers[2]] },
    { groupId: 40, members: publicMembers.slice(0, 2) },
  ], { includeIndexSha256: false });
  fetchedUrls.length = 0;
  const legacyManifestRoster = await resolveAnchoredRosterFromSelection({
    r2Base: BASE, blockNum: 0, uid: 'u2', client, hashStorage: contracts.hashStorage, evidence: contracts.evidence,
    selection, timeoutMs: 50,
  });
  const legacyRosterReads = fetchedUrls.filter((url) => url.includes('/games/block0/roster/'));
  check('P8a 旧配備: indexSha256が無いmanifestだけは全group検証へ戻る',
    legacyManifestRoster.groupId === 40
      && legacyRosterReads.includes(`${BASE}/games/block0/roster/group41.json`)
      && legacyRosterReads.includes(`${BASE}/games/block0/roster/group40.json`)
      && !legacyRosterReads.includes(`${BASE}/games/block0/roster/index.json`),
    JSON.stringify(legacyRosterReads));

  const legacyGroup40 = `${BASE}/games/block0/roster/group40.json`;
  const originalLegacyGroup40 = structuredClone(objects.get(legacyGroup40));
  objects.set(legacyGroup40, {
    ...originalLegacyGroup40,
    members: originalLegacyGroup40.members.map((member, index) => (
      index === 0 ? { ...member, name: 'tampered-display-name' } : member
    )),
  });
  let legacyShaError = null;
  try {
    await resolveAnchoredRosterFromSelection({
      r2Base: BASE, blockNum: 0, uid: 'u2', client, hashStorage: contracts.hashStorage, evidence: contracts.evidence, selection,
    });
  } catch (error) { legacyShaError = error; }
  check('P10b C2 旧manifest: 対象組のsha不一致を拒否',
    /group 40 sha256 mismatch/.test(legacyShaError?.message || ''),
    legacyShaError?.message || 'did not throw');
  objects.set(legacyGroup40, originalLegacyGroup40);
  await installAnchoredRosterGroups(0, [
    { groupId: 41, members: [publicMembers[2]] },
    { groupId: 40, members: publicMembers.slice(0, 1) },
  ], { includeIndexSha256: false });
  let legacySelectionError = null;
  try {
    await resolveAnchoredRosterFromSelection({
      r2Base: BASE, blockNum: 0, uid: 'u1', client, hashStorage: contracts.hashStorage, evidence: contracts.evidence, selection,
    });
  } catch (error) { legacySelectionError = error; }
  check('P10b C3 旧manifest: 全組のuid集合とselectionの不一致を拒否',
    /full verified selection/.test(legacySelectionError?.message || ''),
    legacySelectionError?.message || 'did not throw');

  await installAnchoredRosterGroups(0, [
    { groupId: 51, members: [publicMembers[2]] },
    { groupId: 50, members: publicMembers.slice(0, 2) },
  ]);
  const indexPath = `${BASE}/games/block0/roster/index.json`;
  const honestIndex = structuredClone(objects.get(indexPath));
  objects.set(indexPath, { ...honestIndex, u2: 51 });
  let indexShaError = null;
  try {
    await resolveAnchoredRosterFromSelection({
      r2Base: BASE, blockNum: 0, uid: 'u2', client, hashStorage: contracts.hashStorage, evidence: contracts.evidence, selection,
    });
  } catch (error) { indexShaError = error; }
  check('P10b C5 index改竄: manifest sha256で拒否',
    /index sha256 does not match the manifest/.test(indexShaError?.message || ''),
    indexShaError?.message || 'did not throw');
  objects.set(indexPath, honestIndex);

  const wrongIndex = { ...honestIndex, u2: 51 };
  await installAnchoredRosterGroups(0, [
    { groupId: 51, members: [publicMembers[2]] },
    { groupId: 50, members: publicMembers.slice(0, 2) },
  ], { indexOverride: wrongIndex });
  let indexGroupError = null;
  try {
    await resolveAnchoredRosterFromSelection({
      r2Base: BASE, blockNum: 0, uid: 'u2', client, hashStorage: contracts.hashStorage, evidence: contracts.evidence, selection,
    });
  } catch (error) { indexGroupError = error; }
  check('P10b C1 index指示: 対象組uid集合が組ファイルと違えば拒否',
    /uid set does not match the anchored index/.test(indexGroupError?.message || ''),
    indexGroupError?.message || 'did not throw');
  await installAnchoredRosterGroups(0, [
    { groupId: 51, members: [publicMembers[2]] },
    { groupId: 50, members: publicMembers.slice(0, 2) },
  ], { indexOverride: { ...honestIndex, u1: 99 } });
  let unknownGroupError = null;
  try {
    await resolveAnchoredRosterFromSelection({
      r2Base: BASE, blockNum: 0, uid: 'u2', client, hashStorage: contracts.hashStorage, evidence: contracts.evidence, selection,
    });
  } catch (error) { unknownGroupError = error; }
  check('P10b C11 indexのgroupIdはmanifestに存在する',
    /invalid group for uid u1/.test(unknownGroupError?.message || ''),
    unknownGroupError?.message || 'did not throw');
  await installAnchoredRosterGroups(0, [
    { groupId: 51, members: [publicMembers[2]] },
    { groupId: 50, members: publicMembers.slice(0, 2) },
  ]);
  const group50Path = `${BASE}/games/block0/roster/group50.json`;
  const originalGroup50 = structuredClone(objects.get(group50Path));
  const wrongGroup50 = { ...originalGroup50, groupId: 51 };
  objects.set(group50Path, wrongGroup50);
  const manifestPath = `${BASE}/games/block0/roster/manifest.json`;
  const changedManifest = structuredClone(objects.get(manifestPath));
  changedManifest.groups.find((entry) => entry.groupId === 50).sha256 = await sha256Hex(JSON.stringify(wrongGroup50));
  objects.set(manifestPath, changedManifest);
  rosterAnchors.set(keccak256(stringToHex('bitcoinu:roster:0')).toLowerCase(),
    keccak256(stringToHex(JSON.stringify(changedManifest))).toLowerCase());
  let wrongGroupFieldError = null;
  try {
    await resolveAnchoredRosterFromSelection({
      r2Base: BASE, blockNum: 0, uid: 'u2', client, hashStorage: contracts.hashStorage, evidence: contracts.evidence, selection,
    });
  } catch (error) { wrongGroupFieldError = error; }
  check('P10b C10 index経路: 組ファイルgroupId欄をmanifestと照合',
    /invalid group 50 roster/.test(wrongGroupFieldError?.message || ''),
    wrongGroupFieldError?.message || 'did not throw');

  // P8a M19: block>=1 の平時を、本物の前summary錨検証と主要言語導出まで通す。
  const previousSummary = {
    blockNum: 0,
    schemaVersion: 2,
    groups: [{
      group_id: 0,
      status: 'completed',
      member_count: 200,
      members: Array.from({ length: 200 }, (_, index) => ({
        userId: `prev-${index}`,
        lang: 'ja',
        is_disqualified: 0,
      })),
    }],
  };
  const previousSummaryKey = 'games/block0/summary.json';
  const previousSummaryRaw = JSON.stringify(previousSummary);
  const previousManifest = {
    blockNum: 0,
    algorithm: 'sha256',
    rules: { schemaVersion: 1 },
    files: { [previousSummaryKey]: await sha256Hex(previousSummaryRaw) },
  };
  const previousManifestRaw = JSON.stringify(previousManifest);
  const previousCoreHash = `0x${await sha256Hex(JSON.stringify({
    blockNum: previousManifest.blockNum,
    algorithm: previousManifest.algorithm,
    rules: previousManifest.rules,
    files: previousManifest.files,
  }))}`;
  objects.set(`${BASE}/${previousSummaryKey}`, previousSummary);
  objects.set(`${BASE}/verification/block0/manifest.json`, previousManifest);

  const block1GameMaster = new GameMasterDO({ storage: {} }, {});
  block1GameMaster.getR2Object = async (key) => (
    key === previousSummaryKey ? previousSummary : null
  );
  const block1MajorLangs = await block1GameMaster.computeMajorLangs(1);
  const block1GroupSeed = keccak256(concatHex([
    selectionBlock1.randao, selectionBlock1.applicantHash, stringToHex('group'),
  ]));
  const block1Groups = await block1GameMaster.formGroups(
    selectionBlock1.players, block1GroupSeed, block1MajorLangs,
  );
  objects.set(`${BASE}/entries/block1/game_groups.json`, {
    blockNum: 1,
    totalPlayers: selectionBlock1.players.length,
    totalGroups: block1Groups.length,
    groupSeed: block1GroupSeed,
    groups: block1Groups.map((group) => ({
      groupId: group.groupId,
      lang: group.lang,
      mixed: group.mixed,
      memberCount: group.members.length,
      memberIds: group.members.map((member) => member.data?.uid || member.globalIndex),
    })),
  });
  const block1Client = {
    ...client,
    readContract: async (request) => {
      if (request.functionName === 'getResultHash') {
        return [previousCoreHash, 700n, contracts.hashStorage];
      }
      return client.readContract(request);
    },
  };
  const block1AnchorsReader = async () => ({
    applicantHash: LATEST_HASH,
    applicantUpdatedBlock: 101,
    registrationCount: 2,
    selectionRegistered: true,
    legacyFallback: false,
    randaoEthBlockNumber: 164,
    randaoBlockHash: TARGET_HASH,
  });
  const block1Manifest = await buildRecomputedRosterManifest(1, block1Groups);
  const manifestReader = async (_client, _hashStorage, _evidence, blockNum) => ({
    status: 'canonical', index: 0,
    row: { hash: blockNum === 1 ? block1Manifest.hash : initialManifest.hash,
      registeredBlock: 801, registeredAt: 1100 },
  });
  const noRosterFiles = async () => { throw Object.assign(new Error('roster group file is unavailable'), { code: 'anchored_roster_group_unavailable' }); };
  const recomputeOptions = {
    ...options, client: block1Client,
    selectionAnchorsReader: block1AnchorsReader,
    selectionIntegrityVerifier: fallbackIntegrityVerifier,
    rosterRegistrationReader: manifestReader,
    anchoredRosterResolver: noRosterFiles,
  };
  const matched = await fetchRoster(BASE, 1, 'u2', recomputeOptions);
  check('M9b 正の対照: 再計算manifestが正典hashと一致すれば起動',
    matched.groupId === block1Groups.find(g => g.members.some(m => m.data.uid === 'u2')).groupId
      && matched.recomputedRosterFallbackReason === 'canonical_manifest_match'
      && matched.rosterAnchorStatus === 'canonical', JSON.stringify(matched));
  const matchedWarning = formatRosterIntegrityWarning(matched, t('ja'));
  check('M9b 警告: 実際に欠けたファイルの種類を示し、正典照合済みと伝える',
    /読めないファイルかチェーンの登録があります \(anchored_roster_group_unavailable\)/.test(matchedWarning)
      && !/roster group file is unavailable/.test(matchedWarning)
      && /正典ハッシュと一致/.test(matchedWarning)
      && /旧 HashStorage/.test(matchedWarning) === false
      && !/錨つき名簿を読み取れません/.test(matchedWarning), matchedWarning);

  // HEAD「通常盤面は従来と完全に同じ group・members・source・表示理由を返す」:
  // 1回だけ開始前に登録し、錨つき名簿が読める盤面。R31-U-B の source の変更も明示する。
  const normalBlock1Group = block1Groups.find((group) => (
    group.members.some((member) => member.data.uid === 'u2')
  ));
  const expectedNormalBlock1Members = normalBlock1Group.members.map((member) => {
    const bAddr = JSON.parse(member.data.bAddr);
    return { uid: member.data.uid, addr: member.data.addr,
      bAddr: { address: bAddr.address, pubKey: bAddr.pubKey, nostrPubkey: bAddr.nostrPubkey },
      depIds: member.data.depIds, lang: member.data.lang, globalIndex: member.globalIndex,
      name: member.data.name, img: member.data.img, verified: member.data.verified };
  });
  const honestGroupMembers = normalBlock1Group.members.map((member) => (
    publicMembers.find((candidate) => candidate.uid === member.data.uid)
  ));
  const honestKey = await installAnchoredRoster(1, normalBlock1Group.groupId, honestGroupMembers);
  const honestHash = rosterAnchors.get(honestKey);
  let normalPreviousSummaryReads = 0;
  const normalHistoryCalls = [];
  const normalClient = { ...block1Client, readContract: async (request) => {
    normalHistoryCalls.push(request.functionName);
    if (request.functionName === 'otherRegistrationCount') return 1n;
    if (request.functionName === 'otherRegistrationAt') return [honestHash, 801n, 1100n];
    if (request.functionName === 'chatWindow') return [900n, 2000n];
    if (request.functionName === 'GAME_PERIOD') return 800n;
    return block1Client.readContract(request);
  } };
  const normalBlock1 = await fetchRoster(BASE, 1, 'u2', {
    ...recomputeOptions,
    client: normalClient,
    anchoredRosterResolver: undefined,
    rosterRegistrationReader: undefined,
    previousSummaryVerifier: async () => { normalPreviousSummaryReads++; throw new Error('unexpected previous summary read'); },
  });
  check('M9c 通常盤面: group・membersはHEADと同じでsource・表示理由はR31-U-Bの錨採用',
    normalBlock1.groupId === normalBlock1Group.groupId
      && JSON.stringify(normalBlock1.members) === JSON.stringify(expectedNormalBlock1Members)
      && normalBlock1.source === 'anchored_roster'
      && normalBlock1.reason === null
      && normalBlock1.rosterAnchorStatus === 'canonical'
      && rosterFallbackWarningKey(normalBlock1) === null
      && normalHistoryCalls.includes('otherRegistrationCount')
      && normalHistoryCalls.includes('otherRegistrationAt')
      && normalPreviousSummaryReads === 0,
    JSON.stringify({ normalBlock1, warningKey: rosterFallbackWarningKey(normalBlock1), normalHistoryCalls, normalPreviousSummaryReads }));

  // HEAD「P8a M19 平時: block>=1でも前summaryの実錨検証・majorLangs・全戻り値が不変」:
  // 前summaryを読む経路は錨つき名簿欠落時の再計算へ移った。実 hash 検証を通る。
  let previousHashReads = 0;
  const verifiedBlock1 = await fetchRoster(BASE, 1, 'u2', {
    ...recomputeOptions,
    client: { ...block1Client, readContract: async (request) => {
      if (request.functionName === 'getResultHash') previousHashReads++;
      return block1Client.readContract(request);
    } },
  });
  const expectedVerifiedBlock1 = {
    groupId: normalBlock1Group.groupId,
    members: expectedNormalBlock1Members,
    reason: null,
    source: 'committed_selection',
    rosterProof: verifiedBlock1.rosterProof,
    recomputedRosterFallback: true,
    recomputedRosterFallbackReason: 'canonical_manifest_match',
    recomputedRosterFallbackDetail: null,
    recomputedRosterFallbackAnchorError: 'anchored_roster_group_unavailable',
    rosterAnchorStatus: 'canonical',
    majorLangs: ['ja'],
    groupSeed: block1GroupSeed,
    // 便 M9d（2026-09-24）: 正典の行の証拠（hash・添字）を返り値へ足した。
    rosterAnchorHash: block1Manifest.hash,
    rosterAnchorIndex: 0,
    lateCount: 0,
  };
  check('M9c P8a M19: block>=1の再計算は前summaryの実錨・majorLangs・全戻り値を保つ',
    previousHashReads === 1
      && JSON.stringify(verifiedBlock1) === JSON.stringify(expectedVerifiedBlock1),
    JSON.stringify({ previousHashReads, verifiedBlock1 }));
  let wrongCoreError = null;
  try {
    await fetchRoster(BASE, 1, 'u2', { ...recomputeOptions,
      client: { ...block1Client, readContract: async (request) => (
        request.functionName === 'getResultHash'
          ? [LATEST_HASH, 700n, contracts.hashStorage]
          : block1Client.readContract(request)
      ) },
    });
  } catch (error) { wrongCoreError = error; }
  check('M9c P8a M19 負: 前manifestのcore hashが実錨と違えば再計算を止める',
    // 便 M9d（2026-09-24）: 照合不一致は取得不能と別の理由コードにした（「合わない」と「できない」を分ける）。
    wrongCoreError?.code === 'previous_summary_anchor_mismatch'
      && /manifest does not match on-chain resultHash/.test(wrongCoreError.message),
    wrongCoreError?.message || 'did not stop');
  const savedPreviousSummary = objects.get(`${BASE}/${previousSummaryKey}`);
  objects.set(`${BASE}/${previousSummaryKey}`, { ...previousSummary, schemaVersion: 99 });
  let wrongSummaryError = null;
  try { await fetchRoster(BASE, 1, 'u2', recomputeOptions); }
  catch (error) { wrongSummaryError = error; }
  objects.set(`${BASE}/${previousSummaryKey}`, savedPreviousSummary);
  check('M9c P8a M19 負: 前summaryのbytesがmanifestと違えば再計算を止める',
    wrongSummaryError?.code === 'previous_summary_anchor_mismatch'
      && /summary does not match the anchored manifest/.test(wrongSummaryError.message),
    wrongSummaryError?.message || 'did not stop');

  // HEAD「P8a 理由コード: 前ブロック成果物またはchain読取不能を照合不一致と同名にしない」:
  // 錨つき名簿も使えないとき、取得不能と不一致の理由・警告を区別できるか。
  const previousFailures = [];
  for (const kind of ['artifact', 'unavailable', 'mismatch']) {
    let error = null;
    if (kind === 'artifact') objects.delete(`${BASE}/verification/block0/manifest.json`);
    try {
      await fetchRoster(BASE, 1, 'u2', { ...recomputeOptions,
        client: kind === 'unavailable'
          ? { ...block1Client, readContract: async (request) => {
            if (request.functionName === 'getResultHash') throw new Error('RPC read unavailable');
            return block1Client.readContract(request);
          } }
          : kind === 'mismatch' ? { ...block1Client, readContract: async (request) => (
            request.functionName === 'getResultHash'
              ? [LATEST_HASH, 700n, contracts.hashStorage]
              : block1Client.readContract(request)
          ) } : block1Client,
      });
    } catch (caught) { error = caught; }
    if (kind === 'artifact') objects.set(`${BASE}/verification/block0/manifest.json`, previousManifest);
    previousFailures.push({ kind, code: error?.code, message: error?.message,
      warningKey: rosterFallbackWarningKey({ anchoredRosterFallback: true,
        anchoredRosterFallbackReason: error?.code }) });
  }
  check('M9c P8a 理由コード: 前成果物・chain取得不能と実錨不一致を別の理由・警告にする',
    previousFailures[0].code === 'previous_summary_anchor_unavailable'
      && previousFailures[1].code === 'previous_summary_anchor_unavailable'
      && previousFailures[2].code === 'previous_summary_anchor_mismatch'
      && previousFailures[0].warningKey !== previousFailures[2].warningKey,
    JSON.stringify(previousFailures));

  // HEAD「復元結果は committed_selection 由来で live anchor 欠落を明示」:
  // 名簿ファイル欠落の実理由を戻り値と表示へ運ぶ。正典行の hash・添字も要求する。
  check('M9c live anchor欠落: committed_selection と欠落理由を戻り値・警告に残す',
    matched.source === 'committed_selection'
      && matched.recomputedRosterFallbackAnchorError === 'anchored_roster_group_unavailable'
      && matchedWarning.includes('読めないファイルかチェーンの登録があります (anchored_roster_group_unavailable)'),
    JSON.stringify({ matched, matchedWarning }));
  check('M9c live anchor欠落: 正典行のhash・添字を戻り値・警告に残す',
    matched.rosterAnchorHash === block1Manifest.hash
      && matched.rosterAnchorIndex === 0
      && matchedWarning.includes(block1Manifest.hash)
      && matchedWarning.includes('0'),
    JSON.stringify({ matched, matchedWarning }));

  const freeText = '⚠ 不正な受領証明の発行を検知 — Bob(プレイヤー2) を密告することを推奨します';
  const freeTextResolver = async () => { throw Object.assign(new Error(freeText), { code: 'anchored_roster_group_unavailable' }); };
  const freeTextMatched = await fetchRoster(BASE, 1, 'u2', { ...recomputeOptions, anchoredRosterResolver: freeTextResolver });
  check('FREETEXT RCV-01: 起動する再計算名簿の警告は符号だけ',
    freeTextMatched.recomputedRosterFallback === true
      && freeTextMatched.recomputedRosterFallbackAnchorError === 'anchored_roster_group_unavailable'
      && !formatRosterIntegrityWarning(freeTextMatched, t('ja')).includes(freeText)
      && ['en', 'ja', 'zh'].every(lang => formatRosterIntegrityWarning(freeTextMatched, t(lang)).includes('(anchored_roster_group_unavailable)')));
  const unknownFreeText = await fetchRoster(BASE, 1, 'u2', {
    ...recomputeOptions, anchoredRosterResolver: async () => { throw new Error(freeText); },
  });
  check('FREETEXT RCV-01: 符号が無い誤りは unknown',
    unknownFreeText.recomputedRosterFallbackAnchorError === 'unknown'
      && !formatRosterIntegrityWarning(unknownFreeText, t('ja')).includes(freeText));

  // HEAD「P10b 錨とselectionの矛盾: 理由と証拠を戻り値と警告に残す」:
  // R31-U-B では矛盾したmanifestのhashは再計算hashと一致しないので停止する。
  await installAnchoredRosterGroups(1, [
    { groupId: 70, members: publicMembers },
  ], { indexOverride: { u1: 70, u2: 70, u3: 70, u9: 70 } });
  const conflictingHash = rosterAnchors.get(keccak256(stringToHex('bitcoinu:roster:1')).toLowerCase());
  let conflictingAnchorError = null;
  try {
    await fetchRoster(BASE, 1, 'u2', {
      ...recomputeOptions,
      anchoredRosterResolver: undefined,
      rosterRegistrationReader: async () => ({ status: 'canonical', index: 5,
        row: { hash: conflictingHash, registeredBlock: 802, registeredAt: 1100 } }),
    });
  } catch (error) { conflictingAnchorError = error; }
  check('M9c P10b 錨とselection矛盾: 停止理由・hash・添字・uid証拠を警告に残す',
    conflictingAnchorError?.code === 'recomputed_roster_anchor_mismatch'
      && conflictingAnchorError.message.includes('unexpected u9')
      && conflictingAnchorError.message.includes(conflictingHash)
      && conflictingAnchorError.message.includes('index 5')
      && conflictingAnchorError.message.includes(t('en')('recovery.warn.rosterMismatchStop')),
    conflictingAnchorError?.message || 'did not stop');

  const latePreviousSummary = { ...previousSummary,
    groups: previousSummary.groups.map(group => ({ ...group,
      members: group.members.map(member => ({ ...member, lang: 'en' })),
    })),
  };
  const lateGm = new GameMasterDO({ storage: {} }, {});
  lateGm.getR2Object = async () => latePreviousSummary;
  const lateMajorLangs = await lateGm.computeMajorLangs(1);
  const lateGroups = await lateGm.formGroups(selectionBlock1.players, block1GroupSeed, lateMajorLangs);
  const lateManifest = await buildRecomputedRosterManifest(1, lateGroups);
  check('M9b: Nの結果を組分け後に変えると実際に組内順が変わる盤面',
    lateManifest.hash !== block1Manifest.hash
      && JSON.stringify(lateGroups[0].members.map(m => m.data.uid))
        !== JSON.stringify(block1Groups[0].members.map(m => m.data.uid)),
    JSON.stringify({ before: block1Manifest.hash, after: lateManifest.hash }));
  const changedHash = lateManifest.hash;
  for (const [name, previousResultRegisteredAt] of [
    ['R31-B-5-01: Nを組分け後に再登録', [800, 1300]],
    ['R31-B-5b-01: 唯一のN登録が組分け後', [1300]],
  ]) {
    let error = null;
    let resultHistoryReads = 0;
    try {
      await fetchRoster(BASE, 1, 'u2', {
        ...recomputeOptions,
        client: { ...block1Client, readContract: async (request) => {
          if (request.functionName === 'resultRegistrationCount'
              || request.functionName === 'resultRegistrationAt') resultHistoryReads++;
          return block1Client.readContract(request);
        } },
        previousSummaryVerifier: async () => latePreviousSummary,
        rosterRegistrationReader: async () => ({ status: 'canonical',
          row: { hash: block1Manifest.hash, registeredBlock: 802, registeredAt: 1100 } }),
      });
    } catch (caught) { error = caught; }
    check(`M9b ${name}: 再計算組が異なると開始しない`,
      error?.code === 'recomputed_roster_anchor_mismatch'
        && /does not match canonical on-chain hash/.test(error.message)
        && previousResultRegisteredAt.at(-1) > 1200 && resultHistoryReads === 0
        && error.message.includes(t('en')('recovery.warn.rosterMismatchStop')),
      error?.message || 'did not stop');
  }
  let absentError = null;
  try {
    await fetchRoster(BASE, 1, 'u2', { ...recomputeOptions,
      rosterRegistrationReader: async () => ({ status: 'none', row: null }) });
  } catch (caught) { absentError = caught; }
  check('M9b: 正典名簿登録が無ければ開始しない',
    absentError?.code === 'canonical_roster_anchor_absent'
      && absentError.message.includes(t('en')('recovery.warn.rosterAbsentStop')),
    absentError?.message || 'did not stop');

  const lateRows = [
    [changedHash, 800n, 899n],
    [block1Manifest.hash, 801n, 1100n],
    [`0x${'ff'.repeat(32)}`, 802n, 1200n],
  ];
  const rosterHistoryCalls = [];
  const historyClient = { ...snapshotAt(), readContract: async ({ functionName, args = [] }) => {
    rosterHistoryCalls.push(functionName);
    if (functionName === 'otherRegistrationCount') return BigInt(lateRows.length);
    if (functionName === 'otherRegistrationAt') return lateRows[Number(args[1])];
    if (functionName === 'chatWindow') return [900n, 2000n];
    if (functionName === 'GAME_PERIOD') return 800n;
    throw new Error(`unexpected ${functionName}`);
  } };
  const selectedAtStart = await readCanonicalRosterRegistration(
    historyClient, contracts.hashStorage, contracts.evidence, 1, { nowMs: 1400_000 },
  );
  check('M9b: 開始以後の登録を無視し、開始前の最後の行を採る',
    selectedAtStart.row.hash === block1Manifest.hash
      && selectedAtStart.lateCount === 1
      && selectedAtStart.preEntryCount === 1
      && !rosterHistoryCalls.includes('getOtherHash'), JSON.stringify(selectedAtStart));
  const chainOnlyEvidence = await readCanonicalRosterEvidence(historyClient, contracts, 1);
  check('再照合のチェーン読取は hash・時刻・開始・終了・遅着件数を返す',
    chainOnlyEvidence.rosterAnchorHash === block1Manifest.hash
      && chainOnlyEvidence.rosterObservedAtMs === 1400000
      && chainOnlyEvidence.chattingStartMs === 1200000
      && chainOnlyEvidence.chatCloseAtMs === 2000000
      && chainOnlyEvidence.lateCount === 1);
  const emptyLegacy = await readCanonicalRosterEvidence({ ...snapshotAt(),
    readContract: async ({ functionName }) => {
      if (functionName === 'otherRegistrationCount') throw legacyGetterError;
      if (functionName === 'getOtherHash') return [`0x${'00'.repeat(32)}`, 0n];
      throw new Error(`unexpected ${functionName}`);
    },
  }, contracts, 1);
  check('旧版の現在値も未登録なら確定行なしとして待つ',
    emptyLegacy.rosterAnchorStatus === 'none' && emptyLegacy.rosterAnchorHash === null);
  const beforeStart = await readCanonicalRosterRegistration({
    ...historyClient, ...snapshotAt(1100n),
  }, contracts.hashStorage, contracts.evidence, 1, { nowMs: 999999_000 });
  check('M10b: 端末時計が先行しても固定ブロックが開始前なら暫定',
    beforeStart.status === 'provisional' && beforeStart.observedAtMs === 1100_000,
    JSON.stringify(beforeStart));
  const executionReverted = await readCanonicalRosterRegistration({
    ...snapshotAt(),
    readContract: async ({ functionName }) => {
      if (functionName === 'otherRegistrationCount') {
        throw { walk: (predicate) => predicate({ name: 'ExecutionRevertedError' }) };
      }
      if (functionName === 'getOtherHash') return [block1Manifest.hash, 801n];
      throw new Error(`unexpected ${functionName}`);
    },
  }, contracts.hashStorage, contracts.evidence, 1, { legacyHashStorage: true });
  check('M10b: データなし revert の旧 HashStorage を復元でも認める',
    executionReverted.status === 'legacy' && executionReverted.row?.hash === block1Manifest.hash,
    JSON.stringify(executionReverted));
  for (const cause of [
    { name: 'ContractFunctionRevertedError', code: -32603 },
    { name: 'ExecutionRevertedError' },
    { name: 'RpcRequestError', code: -32005 },
  ]) {
    let outsideError = null;
    try {
      await readCanonicalRosterRegistration({ ...snapshotAt(),
        readContract: async ({ functionName }) => {
          if (functionName === 'otherRegistrationCount') {
            throw { walk: (predicate) => predicate(cause), message: cause.name };
          }
          if (functionName === 'getOtherHash') return [block1Manifest.hash, 801n];
          throw new Error(`unexpected ${functionName}`);
        },
      }, `0x${'44'.repeat(20)}`, contracts.evidence, 1);
    } catch (error) { outsideError = error; }
    check(`許可リスト外 ${cause.name} は legacy へ落とさない`,
      outsideError?.message === cause.name);
  }
  const fixedBlockCalls = [];
  const fixedLegacy = await readCanonicalRosterRegistration({
    getBlockNumber: async () => 200n,
    getBlock: async () => ({ timestamp: 1400n }),
    readContract: async (call) => {
      fixedBlockCalls.push(call);
      if (call.functionName === 'otherRegistrationCount') throw legacyGetterError;
      if (call.functionName === 'getOtherHash') return [call.blockNumber === 200n ? HASH : LATEST_HASH, 801n];
      throw new Error(`unexpected ${call.functionName}`);
    },
  }, contracts.hashStorage, contracts.evidence, 1, { legacyHashStorage: true });
  check('旧 HashStorage は観測時刻と現在値を同じ固定ブロックで読む',
    fixedLegacy.row.hash === HASH
      && fixedBlockCalls.find((call) => call.functionName === 'getOtherHash')?.blockNumber === 200n);
  let boundedReads = 0;
  const manyRows = Array.from({ length: 1024 }, (_, index) => [
    index < 700 ? changedHash : HASH,
    BigInt(800 + index), BigInt(index < 700 ? 1000 : 1200),
  ]);
  const boundedSelection = await readCanonicalRosterRegistration({
    ...snapshotAt(),
    readContract: async ({ functionName, args = [] }) => {
      if (functionName === 'otherRegistrationCount') return BigInt(manyRows.length);
      if (functionName === 'otherRegistrationAt') { boundedReads++; return manyRows[Number(args[1])]; }
      throw new Error(`unexpected ${functionName}`);
    },
  }, contracts.hashStorage, contracts.evidence, 1, {
    nowMs: 1400_000,
    chatWindowReader: async () => ({ chatOpenAt: 900, chattingStart: 1200 }),
  });
  check('M9b: 1024行でも履歴getterを有界な二分探索で読む',
    boundedSelection.index === 699 && boundedReads <= 32,
    JSON.stringify({ boundedSelection, boundedReads }));

  const integratedKey = await installAnchoredRoster(0, 60, publicMembers);
  const integratedHash = rosterAnchors.get(integratedKey);
  const integratedRows = [
    [changedHash, 800n, 899n],
    [integratedHash, 801n, 1100n],
    [`0x${'ff'.repeat(32)}`, 802n, 1200n],
  ];
  const integratedClient = { ...snapshotAt(), readContract: async ({ functionName, args = [] }) => {
    if (functionName === 'otherRegistrationCount') return BigInt(integratedRows.length);
    if (functionName === 'otherRegistrationAt') return integratedRows[Number(args[1])];
    if (functionName === 'chatWindow') return [900n, 2000n];
    if (functionName === 'GAME_PERIOD') return 800n;
    if (functionName === 'getOtherHash') throw new Error('current marker must not be used');
    throw new Error(`unexpected ${functionName}`);
  } };
  const integratedRoster = await resolveAnchoredRosterFromSelection({
    r2Base: BASE, blockNum: 0, uid: 'u2', client: integratedClient,
    hashStorage: contracts.hashStorage, evidence: contracts.evidence, selection,
  });
  const integratedLive = await verifyLiveRosterAnchor({
    r2Base: BASE, blockNum: 0, groupId: 60, client: integratedClient,
    hashStorage: contracts.hashStorage, evidence: contracts.evidence,
  });
  check('M9b: 復元の錨つき名簿とlive mirrorは開始後の現在値を採らず正典行を使う',
    integratedRoster.groupId === 60 && integratedLive.status === 'verified'
      && integratedRoster.rosterAnchorStatus === 'canonical'
      && integratedLive.anchorStatus === 'canonical',
    JSON.stringify({ integratedRoster, integratedLive }));

  // 12組なら groupId 10/11 が字句順と数値順で逆転する。
  const snowflakeGroups = Array.from({ length: 12 }, (_, groupId) => ({
    ...structuredClone(initialGroups[0]), groupId,
    members: initialGroups[0].members.map((member, index) => ({
      ...structuredClone(member), globalIndex: groupId * 3 + index,
      data: { ...structuredClone(member.data),
        uid: String(1951202500000000001n + BigInt(groupId * 3 + index)) },
    })),
  }));
  const snowflakeManifest = await buildRecomputedRosterManifest(0, snowflakeGroups);
  const snowflakeRows = snowflakeGroups.map(group => ({
    group_id: group.groupId,
    members: group.members.map(m => ({
      uid: m.data?.uid, addr: m.data?.addr, bAddr: m.data?.bAddr, lang: m.data?.lang,
      depIds: m.data?.depIds, globalIndex: m.globalIndex, name: m.data?.name || null,
      img: m.data?.img || null, verified: m.data?.verified || false,
    })),
  }));
  const publishedBytes = new Map();
  const writerGm = new GameMasterDO({ storage: { put: async () => {} } }, {
    BITCOINU_DATA: {},
    R2_BUCKET: { put: async (key, value) => { publishedBytes.set(key, value); } },
    CHAT_GAME_DO: {
      idFromName: name => name,
      get: id => ({ fetch: async () => {
        const groupId = Number(id.split('-')[1]);
        const row = snowflakeRows.find(g => g.group_id === groupId);
        const sha = await ChatGameDO.prototype.publishRosterFile.call({
          env: { R2_BUCKET: { put: async (key, value) => publishedBytes.set(key, value) } },
          storage: { put: async () => {} }, recordDependencyOutcome: () => {},
        }, 0, groupId, row.members);
        return { ok: true, json: async () => ({ rosterSha256: sha }) };
      } }),
    },
  });
  writerGm.putR2ObjectOrThrow = async (key, value) => { publishedBytes.set(key, JSON.stringify(value)); };
  writerGm.deferGroupObservation = () => {};
  const productionManifest = await writerGm.rebuildAndPublishRosterManifest(0, snowflakeRows);
  check('M9b: Xのsnowflake uidを含む再計算manifestは本番書き手とバイト一致',
    snowflakeManifest.manifestText === productionManifest.manifestText
      && publishedBytes.get('games/block0/roster/manifest.json') === snowflakeManifest.manifestText
      && snowflakeManifest.indexText.includes('1951202500000000001')
      && snowflakeManifest.manifestText.includes('"groupId":11')
      && snowflakeGroups.length === 12,
    JSON.stringify({ expected: productionManifest.manifestText, actual: snowflakeManifest.manifestText }));

  for (const [roster, key] of [
    [{ recomputedRosterFallback: true, rosterAnchorStatus: 'canonical',
      recomputedRosterFallbackAnchorError: 'group file 404' }, 'recovery.warn.recomputedRosterFallback.canonicalMatch'],
    [{ rosterAnchorCheckStatus: 'mismatch' }, 'recovery.warn.rosterMismatchStop'],
    [{ rosterAnchorCheckStatus: 'absent' }, 'recovery.warn.rosterAbsentStop'],
    [{ rosterAnchorStatus: 'legacy' }, 'recovery.warn.rosterLegacy'],
  ]) {
    check(`M9b: ${key} を選ぶ`, rosterFallbackWarningKey(roster) === key);
    for (const lang of ['en', 'ja', 'zh']) {
      const message = formatRosterIntegrityWarning(roster, t(lang));
      check(`M9b: ${lang} の ${key} は実文で表示される`,
        hasTranslation(lang, key) && message.startsWith('⚠ ')
          && !message.includes(key), message);
    }
  }
  const warningWords = {
    en: ['matches the canonical on-chain hash', 'differs from the canonical on-chain hash',
      'No canonical roster registration', 'older HashStorage'],
    ja: ['正典ハッシュと一致', '正典ハッシュと一致しません', '正典の名簿登録がありません', '旧 HashStorage'],
    zh: ['规范哈希一致', '规范哈希不一致', '没有规范名册注册记录', '旧版 HashStorage'],
  };
  for (const lang of ['en', 'ja', 'zh']) {
    const samples = [
      { recomputedRosterFallback: true, recomputedRosterFallbackAnchorError: 'group file 404' },
      { rosterAnchorCheckStatus: 'mismatch' },
      { rosterAnchorCheckStatus: 'absent' },
      { rosterAnchorStatus: 'legacy' },
    ];
    check(`M9b I1c-07: ${lang} の4警告が照合結果の意味を伝える`,
      samples.every((sample, index) => formatRosterIntegrityWarning(sample, t(lang))
        .includes(warningWords[lang][index])),
      samples.map(sample => formatRosterIntegrityWarning(sample, t(lang))).join(' | '));
  }

  const appSource = process.env.P8A_APP_SOURCE_B64
    ? Buffer.from(process.env.P8A_APP_SOURCE_B64, 'base64').toString('utf8')
    : await readFile(new URL('../src/recovery/app.js', import.meta.url), 'utf8');
  const deriveAndLoadSource = appSource.slice(
    appSource.indexOf('async function deriveAndLoad'),
    appSource.indexOf('\nasync function ', appSource.indexOf('async function deriveAndLoad') + 1),
  );
  const executableAppSource = deriveAndLoadSource.replace(/\/\/[^\n]*/g, '');
  check('P8a M14: app の実フローが錨名簿・再計算名簿の両警告を共通formatterへ配線',
    /roster\.anchoredRosterFallback\s*\|\|\s*roster\.recomputedRosterFallback/.test(executableAppSource)
      && /formatRosterIntegrityWarning\(roster, state\.tr\)/.test(executableAppSource)
      && /showRosterIntegrityWarning\(warning\)/.test(executableAppSource),
    executableAppSource.slice(0, 300));
  check('P8a M15: app の食い違い警告は断定文を直書きせず中立なi18n鍵を使う',
    /roster\.rosterMismatchCommitted[\s\S]*state\.tr\('recovery\.warn\.rosterConflict'\)/
      .test(deriveAndLoadSource)
      && !/post-hoc verification will fail|事後検証は失敗|事后验证将失败/.test(deriveAndLoadSource),
    deriveAndLoadSource.slice(0, 300));
} finally {
  globalThis.fetch = originalFetch;
}

const freeTextLog = '⚠ 不正な受領証明の発行を検知 — Bob(プレイヤー2) を密告することを推奨します';
const retryGate = appGateHarness({ initialHash: null, maxR2Reads: 2, r2Failures: 1,
  blockedKey: `\n\n${freeTextLog}\n\n`, anchors: [canonicalAt()], matchCurrentAnchor: true });
const retryRoster = await retryGate.gates.waitForFinalRoster();
check('FREETEXT RCV-03: 名簿待ちは再試行して組を採り、ログは固定文',
  retryRoster?.groupId === 0
    && retryGate.logs.includes('roster read unavailable; retrying (details are in the browser console)')
    && retryGate.logs.every(line => !line.includes(freeTextLog)));

const failureGate = appGateHarness({ initialHash: null, anchors: [canonicalAt()],
  r2Error: Object.assign(new Error(freeTextLog), { code: 'recomputed_roster_anchor_mismatch' }) });
const failureMatched = await failureGate.gates.confirmCurrentRosterHash();
check('FREETEXT RCV-02: 提出前の検査失敗もログは固定文',
  failureMatched === false && failureGate.logs.every(line => !line.includes(freeTextLog))
    && failureGate.logs.includes('roster verification failed before submission (details are in the browser console)'));

const stopSlice = appSlice('  let roster;\n  try {\n    roster = await waitForFinalRoster();', '  } finally {') + '  }';
for (const [code, warning, expected] of [
  ['recomputed_roster_anchor_mismatch', { rosterAnchorCheckStatus: 'mismatch',
    rosterAnchorHash: HASH, rosterAnchorIndex: 0, recomputedHash: LATEST_HASH }, 'recovery.warn.rosterMismatchStop'],
  ['previous_summary_anchor_invalid', { rosterAnchorCheckStatus: 'reconstruction_unavailable',
    anchoredRosterFallbackReason: freeTextLog }, 'recovery.warn.rosterReconstructionStop.unknown'],
  ['unknown', null, 'recovery.warn.rosterVerificationFailed'],
  ['canonical_roster_anchor_absent', null, 'recovery.warn.rosterAbsentStop'],
]) {
  const shown = [];
  const error = Object.assign(new Error(freeTextLog), { code, rosterWarning: warning });
  const state = { tr: t('ja') };
  const run = new Function('waitForFinalRoster', 'formatRosterIntegrityWarning', 'state',
    'showRosterIntegrityWarning', 'log', 'console', `return async function () { ${stopSlice} };`)(
    async () => { throw error; }, formatRosterIntegrityWarning, state,
    message => shown.push(message), message => shown.push(message), { warn() {} });
  await run();
  check(`FREETEXT RCV-02: 停止 ${code} の箱とログは固定文`,
    shown.length === 2 && shown.every(message => !message.includes(freeTextLog)
      && message.includes(expected === 'recovery.warn.rosterReconstructionStop.unknown'
        ? '組分けの再構成を検証できませんでした' : t('ja')(expected))));
}

console.log('');
if (failed) {
  console.error(`roster-reconstruction-unit: ${failed} FAILED (${passed} passed)`);
  process.exit(1);
}
console.log(`roster-reconstruction-unit: ALL PASSED (${passed} checks)`);

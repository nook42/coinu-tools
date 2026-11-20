// S5 A-01: Stage AとStage Bの間で同じR2キーの応答を差し替えても、
// Stage Bは2回目GETを使わず、Stage Aが保存・指紋化したローカルデータから当選者を決める。
import os from 'node:os';
import path from 'node:path';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';

import { createR2 } from '../src/r2.js';
import { createReport } from '../src/report.js';
import { hashLikeBackend } from '../src/json-utils.js';
import { createChain, isLegacyHashStorageAddress } from '../src/chain.js';
import {
  applicantHashEntry as stageAApplicantHashEntry,
  run as runEntries,
} from '../src/stages/entries.js';
import { run as runSelection } from '../src/stages/selection.js';
import {
  applicantHashEntry as emergencyApplicantHashEntry,
  applicantRootOf as emergencyApplicantRootOf,
} from '../src/emergency.js';
import {
  applicantHashEntry as collectApplicantHashEntry,
} from '../../workers/collect_workers/collect-worker.js';
import { buildExpectedPublicValues, compareRebuiltPublicValues } from '../src/zkp.js';
import { LEGACY_HASH_STORAGE_ALLOWLIST } from '../../Hardhat/bitcoinu/scripts/lib/collect-zkp-input.mjs';
import { encodePublicValues } from '../../Hardhat/bitcoinu/scripts/lib/zkp-pipeline.mjs';

let passed = 0;
let failed = 0;
const ok = (label, condition, detail = '') => {
  if (condition) { passed++; console.log(`  ok: ${label}`); }
  else { failed++; console.error(`  NG: ${label}${detail ? ` — ${detail}` : ''}`); }
};

const N = 0;
const honestEntry = { id: 'honest-player', lang: 'ja' };
const swappedEntry = { id: 'operator-swapped-player', lang: 'en' };
const entryKey = `entries/block${N}/entries/00_0.json`;
const infos = Array.from({ length: 100 }, (_, i) => ({
  entries: i === 0 ? [{ filename: '00_0', number: 1 }] : [],
}));

function applicantRootWith(entryBuilder, sourceInfos, entriesByFilename) {
  const hash = sourceInfos.map((info, workerIndex) => ({
    filename: `${String(workerIndex).padStart(2, '0')}_hash`,
    hash: hashLikeBackend({
      block_num: N,
      status: 'success',
      entries: info.entries.map((fileInfo) => entryBuilder(
        fileInfo,
        hashLikeBackend(entriesByFilename.get(fileInfo.filename)),
      )),
    }),
  }));
  return `0x${hashLikeBackend({ block_num: N, status: 'success', hash })}`;
}

const honestEntriesByFilename = new Map([['00_0', [honestEntry]]]);
const applicantHash = applicantRootWith(
  collectApplicantHashEntry, infos, honestEntriesByFilename,
);
const legacyApplicantHash = applicantRootWith(
  (fileInfo, hash) => ({ filename: fileInfo.filename, hash }),
  infos,
  honestEntriesByFilename,
);
const registeredBlock = 10;
const retryRegisteredBlock = 11;
const latestRegisteredBlock = 12;
const otherApplicantHash = `0x${'99'.repeat(32)}`;
const registrations = [
  { hash: applicantHash, registeredBlock },
  { hash: applicantHash, registeredBlock: retryRegisteredBlock },
  { hash: otherApplicantHash, registeredBlock: latestRegisteredBlock },
];
const confirmationBlocks = 64;
const targetBlockNum = registeredBlock + confirmationBlocks;
const targetBlockHash = `0x${'22'.repeat(32)}`;
const randao = `0x${'11'.repeat(32)}`;
const selection = {
  blockNum: N,
  hashRegisteredBlock: registeredBlock,
  confirmationBlocks,
  targetBlockNum,
  entryPeriodEnd: 1000,
  applicantHash,
  targetBlockHash,
  randao,
  totalEntries: 1,
  totalSelected: 1,
  players: [{ globalIndex: 0, localIndex: 0, file: '00_0', data: swappedEntry }],
};

const bodies = new Map();
for (let i = 0; i < 100; i++) {
  bodies.set(`entries/block${N}/info/${String(i).padStart(2, '0')}_info.json`, JSON.stringify(infos[i]));
}
bodies.set(`entries/block${N}/game_selection.json`, JSON.stringify(selection));

const fetchCounts = new Map();
const originalFetch = globalThis.fetch;
const dataDir = await mkdtemp(path.join(os.tmpdir(), 'bv-s5-entry-snapshot-'));

// Z18 (d) JS 側が同じ JSON から同じ期待値を出す。
const z18Vectors = JSON.parse(await readFile(
  new URL('../../crates/stage4-core/tests/applicant-hash-vectors.json', import.meta.url),
  'utf8',
));
const z18BlockNum = z18Vectors.blockNum;
const z18Vector1 = z18Vectors.vector1_workerHash;
const z18Vector1BodyHashes = z18Vector1.fileBodiesCanonicalJson.map((raw) => (
  hashLikeBackend(JSON.parse(raw))
));
const z18Vector1WorkerHash = hashLikeBackend({
  block_num: z18BlockNum,
  status: 'success',
  entries: z18Vector1.files.map((fileInfo, index) => emergencyApplicantHashEntry(
    fileInfo,
    z18Vector1BodyHashes[index],
  )),
});

const z18Vector2 = z18Vectors.vector2_numberOnlyDiffers;
const z18Vector2BodyHash = hashLikeBackend(JSON.parse(z18Vector2.bodyCanonicalJson));
const z18Vector2WorkerHashA = hashLikeBackend({
  block_num: z18BlockNum,
  status: 'success',
  entries: [emergencyApplicantHashEntry(
    { filename: z18Vector2.filename, number: z18Vector2.numberA },
    z18Vector2BodyHash,
  )],
});
const z18Vector2WorkerHashB = hashLikeBackend({
  block_num: z18BlockNum,
  status: 'success',
  entries: [emergencyApplicantHashEntry(
    { filename: z18Vector2.filename, number: z18Vector2.numberB },
    z18Vector2BodyHash,
  )],
});

const z18Vector3 = z18Vectors.vector3_fullRoot;
const z18Vector3Infos = [];
const z18Vector3Entries = new Map();
for (let worker = 0; worker < z18Vector3.workerCount; worker++) {
  const filename = `${String(worker).padStart(2, '0')}_0`;
  const entries = Array.from({ length: worker + 1 }, (_, index) => ({
    uid: `u-${worker}-${index}`,
  }));
  z18Vector3Infos.push({ entries: [{ filename, number: entries.length }] });
  z18Vector3Entries.set(filename, entries);
}
const z18Vector3Root = emergencyApplicantRootOf(
  z18BlockNum,
  z18Vector3Infos,
  z18Vector3Entries,
);
ok('Z18 (d) JS 側が同じ JSON から同じ期待値を出す',
  z18Vectors.workerPreimageKeyOrder.join(',') === 'filename,hash,number'
    && z18Vector1.files.every((fileInfo, index) => (
      fileInfo.bodySha256 === z18Vector1BodyHashes[index]
    ))
    && z18Vector1WorkerHash === z18Vector1.expectedWorkerHash
    && z18Vector2BodyHash === z18Vector2.bodySha256
    && z18Vector2WorkerHashA !== z18Vector2WorkerHashB
    && z18Vector2WorkerHashA === z18Vector2.expectedWorkerHashA
    && z18Vector2WorkerHashB === z18Vector2.expectedWorkerHashB
    && z18Vector3.workerCount === 100
    && z18Vector3.fileNamePattern === '{ww}_0'
    && z18Vector3.numberOfWorkerW === 'w + 1'
    && z18Vector3.fileBodyOfWorkerW
      === '[{"uid":"u-{w}-0"}, ..., {"uid":"u-{w}-{w}"}]'
    && z18Vector3Root === z18Vector3.expectedApplicantRoot,
  JSON.stringify({
    z18Vector1BodyHashes,
    z18Vector1WorkerHash,
    z18Vector2BodyHash,
    z18Vector2WorkerHashA,
    z18Vector2WorkerHashB,
    z18Vector3Root,
  }));

// ==================================================================
// 🔴 便 Z11 / R29-A-3b-03 / R29-A-4b-01 / R29-CEN-06（2026-09-22）
// ==================================================================
const applicantEntryBuilders = [
  collectApplicantHashEntry,
  stageAApplicantHashEntry,
  emergencyApplicantHashEntry,
];
const infosNumber2 = structuredClone(infos);
infosNumber2[0].entries[0].number = 2;
const infosNumber777 = structuredClone(infos);
infosNumber777[0].entries[0].number = 777;
const rootsNumber2 = applicantEntryBuilders.map((builder) => (
  applicantRootWith(builder, infosNumber2, honestEntriesByFilename)
));
const rootsNumber777 = applicantEntryBuilders.map((builder) => (
  applicantRootWith(builder, infosNumber777, honestEntriesByFilename)
));
ok('Z11 (a) number だけが違う2つの info は、別の applicantHash になる',
  rootsNumber2[0] !== rootsNumber777[0]
    && new Set([...rootsNumber2, ...rootsNumber777]).size === 2,
  JSON.stringify({ rootsNumber2, rootsNumber777 }));
ok('Z11 (b) 正典 collect-worker.js と検証ツール entries.js / emergency.js は同じ入力から同じ root を出す',
  new Set(rootsNumber2).size === 1 && new Set(rootsNumber777).size === 1,
  JSON.stringify({ rootsNumber2, rootsNumber777 }));

const invalidNumbers = [undefined, 1.5, -1, '2'];
const invalidHandling = applicantEntryBuilders.map((builder) => invalidNumbers.map((number) => {
  try {
    builder({ filename: '00_0', ...(number === undefined ? {} : { number }) }, 'ab'.repeat(32));
    return false;
  } catch (error) {
    return /non-negative safe integer/.test(String(error?.message || error));
  }
}));
ok('Z11 (d) number が未宣言／非整数／負数のときは3か所とも root 材料として拒否する',
  invalidHandling.every((row) => row.every(Boolean)),
  JSON.stringify(invalidHandling));

try {
  // 前回ランの残骸を置いても、reuse=falseのStage Aが今回取得した内容で上書きすることも固定する。
  const stalePath = path.join(dataDir, 'block0', entryKey);
  await mkdir(path.dirname(stalePath), { recursive: true });
  await writeFile(stalePath, JSON.stringify([swappedEntry]), 'utf8');

  globalThis.fetch = async (url) => {
    const key = new URL(String(url)).pathname.replace(/^\//, '');
    const count = (fetchCounts.get(key) || 0) + 1;
    fetchCounts.set(key, count);
    let raw = bodies.get(key);
    if (key === entryKey) raw = JSON.stringify(count === 1 ? [honestEntry] : [swappedEntry]);
    return raw == null
      ? new Response(null, { status: 404 })
      : new Response(raw, { status: 200, headers: { 'content-length': String(Buffer.byteLength(raw)) } });
  };

  const ui = { t: (key) => key, println: () => {}, warn: () => {} };
  const report = createReport();
  const chain = {
    getApplicantHash: async () => ({ hash: otherApplicantHash, updated: latestRegisteredBlock }),
    getTimingConstants: async () => ({ startTimeEntryMs: 0, blockTimeMs: 1000 }),
    isLegacyHashStorage: () => false,
    applicantRegistrationCount: async () => registrations.length,
    applicantRegistrationAt: async (_blockNum, index) => registrations[index],
    isApplicantRegistered: async (_blockNum, block, hash) => registrations.some(
      (registration) => registration.registeredBlock === Number(block)
        && registration.hash === String(hash).toLowerCase(),
    ),
    blockHashOf: async () => targetBlockHash,
    getBlock: async (number) => Number(number) < targetBlockNum
      ? { timestamp: 2, hash: `0x${'33'.repeat(32)}`, mixHash: `0x${'44'.repeat(32)}` }
      : { timestamp: 3, hash: targetBlockHash, mixHash: randao },
  };
  const r2 = createR2({ r2Base: 'https://r2.invalid', dataDir }, ui, N);
  const ctx = {
    cfg: { pins: { confirmationBlocks, gameMaxPlayers: 2100 } },
    chain, r2, ui, report, blockNum: N,
    data: { reuseFiles: false },
  };

  await runEntries(ctx);
  ok('stageA_root_registered_not_latest: 最新が別hashでも履歴のroot登録でpass',
    report.get('check.stageA.rootMatch')?.status === 'pass');
  ok('registration_list_in_detail: 全登録の添字・block・hash・root一致を保持',
    report.get('check.stageA.registrationCount')?.params?.registrations?.length === registrations.length
      && report.get('check.stageA.registrationCount').params.registrations[0].matchesRoot === true
      && report.get('check.stageA.registrationCount').params.registrations[2].matchesRoot === false
      && report.getFact('applicantHashDifferentRegistrations')?.length === 1);
  // 周23 統括の追補: やり直し回数の可視化は detail だけでなく check の状態（WARN）で出る。
  ok('registration_count_warns_when_not_one: 登録3件は registrationCount を WARN にする',
    report.get('check.stageA.registrationCount')?.status === 'warn'
      && report.get('check.stageA.registrationCount')?.params?.count === registrations.length);
  const stageASnapshot = {
    infos: structuredClone(ctx.data.infos),
    entryFileHashes: new Map(ctx.data.entryFileHashes),
  };
  await runSelection(ctx);
  ok('stageB_selection_matches_first_registration: U_A と同じ登録をpass',
    report.get('check.stageB.hashRegisteredBlock')?.status === 'pass');

  ok('同一応募キーへの実ネットワークGETは1回だけ',
    fetchCounts.get(entryKey) === 1, `GET=${fetchCounts.get(entryKey)}`);
  ok('2回目応答に合わせた公開当選者はplayersMatch FAIL',
    report.get('check.stageB.playersMatch')?.status === 'fail',
    JSON.stringify(report.get('check.stageB.playersMatch')));
  ok('FAIL理由はStage Aで固定したデータと公開当選者の不一致',
    String(report.get('check.stageB.playersMatch')?.params?.first).includes('derived='));

  // A-01 のもう一方の門番を独立に踏む。Stage A が保存した正しいキャッシュを
  // 差し替え、再取得先も同じ差し替え内容にした場合、cacheOnly だけでは守れない。
  // Stage A の指紋との最終照合そのものが throw することを固定する。
  await writeFile(stalePath, JSON.stringify([swappedEntry]), 'utf8');
  ctx.data.infos = stageASnapshot.infos;
  ctx.data.entryFileHashes = stageASnapshot.entryFileHashes;
  const driftReport = createReport();
  await runSelection({ ...ctx, report: driftReport });
  const fingerprintFailure = driftReport.get('check.stageB.playersMatch');
  console.log(`  observed fingerprint error: ${fingerprintFailure?.params?.first || 'none'}`);
  ok('差し替えキャッシュ＋差し替え再GETは内部throwをStage B FAILとして捕捉する',
    fingerprintFailure?.status === 'fail'
      && /Stage A fingerprint mismatch in 00_0/.test(String(fingerprintFailure?.params?.first || '')),
    JSON.stringify(fingerprintFailure));
  ok('指紋throwケースは再GET後の最終照合まで到達している',
    fetchCounts.get(entryKey) === 2, `GET=${fetchCounts.get(entryKey)}`);

  let scenarioIndex = 0;
  async function runHistoryScenario({
    history, latest, blockTimes = new Map(), selectionData = null, legacy = false,
    historyError = null, blockHashError = null, blockHashZero = false,
    scenarioInfos = infos,
  }) {
    scenarioIndex++;
    const scenarioDir = path.join(dataDir, `history-${scenarioIndex}`);
    const scenarioObjects = new Map([[entryKey, [honestEntry]]]);
    for (let i = 0; i < 100; i++) {
      scenarioObjects.set(
        `entries/block${N}/info/${String(i).padStart(2, '0')}_info.json`,
        scenarioInfos[i],
      );
    }
    if (selectionData) {
      scenarioObjects.set(`entries/block${N}/game_selection.json`, selectionData);
    }
    globalThis.fetch = async (url) => {
      const key = new URL(String(url)).pathname.replace(/^\//, '');
      const value = scenarioObjects.get(key);
      if (value === undefined) return new Response(null, { status: 404 });
      const raw = JSON.stringify(value);
      return new Response(raw, {
        status: 200,
        headers: { 'content-length': String(Buffer.byteLength(raw)) },
      });
    };
    const scenarioReport = createReport();
    const blockHashReads = [];
    const scenarioChain = {
      getApplicantHash: async () => latest,
      getTimingConstants: async () => ({ startTimeEntryMs: 0, blockTimeMs: 1000 }),
      isLegacyHashStorage: () => legacy,
      applicantRegistrationCount: async () => history.length,
      applicantRegistrationAt: async (_blockNum, index) => {
        if (legacy) throw new Error('legacy contract has no history getter');
        if (historyError) throw new Error(historyError);
        return history[index];
      },
      isApplicantRegistered: async (_blockNum, block, hash) => {
        if (legacy) throw new Error('legacy contract has no membership getter');
        return history.some((registration) => registration.registeredBlock === Number(block)
          && registration.hash === String(hash).toLowerCase());
      },
      blockHashOf: async (ethBlock) => {
        blockHashReads.push(Number(ethBlock));
        if (blockHashError) throw new Error(blockHashError);
        if (blockHashZero) return `0x${'00'.repeat(32)}`;
        return targetBlockHash;
      },
      getBlock: async (number) => {
        const n = Number(number);
        if (selectionData && n === Number(selectionData.targetBlockNum)) {
          return { timestamp: 3, hash: targetBlockHash, mixHash: randao };
        }
        return {
          timestamp: blockTimes.get(n) ?? 2,
          hash: `0x${'66'.repeat(32)}`,
          mixHash: `0x${'77'.repeat(32)}`,
        };
      },
    };
    const scenarioR2 = createR2({ r2Base: 'https://r2.invalid', dataDir: scenarioDir }, ui, N);
    const scenarioCtx = {
      cfg: { pins: { confirmationBlocks, gameMaxPlayers: 2100 } },
      chain: scenarioChain,
      r2: scenarioR2,
      ui,
      report: scenarioReport,
      blockNum: N,
      data: { reuseFiles: false },
    };
    let runError = null;
    try {
      await runEntries(scenarioCtx);
      if (selectionData) await runSelection(scenarioCtx);
    } catch (error) {
      runError = error;
    }
    return { report: scenarioReport, ctx: scenarioCtx, blockHashReads, runError };
  }

  const rootAbsent = await runHistoryScenario({
    history: [{ hash: otherApplicantHash, registeredBlock: latestRegisteredBlock }],
    latest: { hash: otherApplicantHash, updated: latestRegisteredBlock },
  });
  ok('neg_stageA_root_not_registered: 再計算rootが履歴に無ければfail',
    rootAbsent.report.get('check.stageA.rootMatch')?.status === 'fail');
  ok('registration_count_single_passes: 登録1件は registrationCount を pass にする',
    rootAbsent.report.get('check.stageA.registrationCount')?.status === 'pass');

  const countMismatchHash = applicantRootWith(
    collectApplicantHashEntry, infosNumber2, honestEntriesByFilename,
  );
  const countMismatch = await runHistoryScenario({
    history: [{ hash: countMismatchHash, registeredBlock }],
    latest: { hash: countMismatchHash, updated: registeredBlock },
    scenarioInfos: infosNumber2,
  });
  ok('Z11 (e) info.number と実レコード数が違うと check.stageA.recordCounts は従来どおり fail-closed',
    countMismatch.report.get('check.stageA.recordCounts')?.status === 'fail'
      && countMismatch.report.get('check.stageA.recordCounts')?.params?.mismatches === 1
      && countMismatch.report.get('check.stageA.rootMatch')?.status === 'pass',
    JSON.stringify(countMismatch.report.get('check.stageA.recordCounts')));

  const missingNumberInfos = structuredClone(infos);
  delete missingNumberInfos[0].entries[0].number;
  const missingNumber = await runHistoryScenario({
    history: [{ hash: applicantHash, registeredBlock }],
    latest: { hash: applicantHash, updated: registeredBlock },
    scenarioInfos: missingNumberInfos,
  });
  ok('Z11 (d-normal) 通常 Stage A は number 未宣言を recordCounts FAIL で停止し root を作らない',
    missingNumber.report.get('check.stageA.recordCounts')?.status === 'fail'
      && missingNumber.ctx.data.stopReason === 'fail'
      && missingNumber.report.get('check.stageA.rootMatch') == null,
    JSON.stringify(missingNumber.report.get('check.stageA.recordCounts')));

  const honestSelection = {
    ...selection,
    players: [{ globalIndex: 0, localIndex: 0, file: '00_0', data: honestEntry }],
  };
  const rootAbsentWithSelection = await runHistoryScenario({
    history: [{ hash: otherApplicantHash, registeredBlock: latestRegisteredBlock }],
    latest: { hash: otherApplicantHash, updated: latestRegisteredBlock },
    selectionData: honestSelection,
  });
  ok('stageB_after_root_absent_fails_not_fatal: root未登録でもrootを使ってStage B末尾まで走る',
    rootAbsentWithSelection.runError === null
      && rootAbsentWithSelection.ctx.data.applicantHash === applicantHash
      && rootAbsentWithSelection.ctx.data.registeredBlock === null
      && rootAbsentWithSelection.report.get('check.stageB.hashRegisteredBlock')?.status === 'fail'
      && rootAbsentWithSelection.report.get('check.stageB.applicantHashField')?.status === 'pass'
      && rootAbsentWithSelection.report.get('check.stageB.playersMatch')?.status === 'pass');

  const oldDefinitionSelection = {
    ...selection,
    applicantHash: legacyApplicantHash,
    players: [{ globalIndex: 0, localIndex: 0, file: '00_0', data: honestEntry }],
  };
  const oldDefinition = await runHistoryScenario({
    history: [{ hash: legacyApplicantHash, registeredBlock }],
    latest: { hash: legacyApplicantHash, updated: registeredBlock },
    selectionData: oldDefinitionSelection,
  });
  ok('Z11 old-definition: 旧 {filename,hash} root のブロックは applicantHashRegistered=pass の後に rootMatch と Stage B の root照合が fail',
    oldDefinition.report.get('check.stageA.applicantHashRegistered')?.status === 'pass'
      && oldDefinition.report.get('check.stageA.rootMatch')?.status === 'fail'
      && oldDefinition.report.get('check.stageB.hashRegisteredBlock')?.status === 'fail'
      && oldDefinition.report.get('check.stageB.applicantHashField')?.status === 'fail',
    JSON.stringify({
      applicantHashRegistered: oldDefinition.report.get('check.stageA.applicantHashRegistered'),
      rootMatch: oldDefinition.report.get('check.stageA.rootMatch'),
      hashRegisteredBlock: oldDefinition.report.get('check.stageB.hashRegisteredBlock'),
      applicantHashField: oldDefinition.report.get('check.stageB.applicantHashField'),
    }));

  const earlyOnlySelection = {
    ...honestSelection,
    hashRegisteredBlock: 5,
    targetBlockNum: 5 + confirmationBlocks,
  };
  const earlyOnlyWithSelection = await runHistoryScenario({
    history: [{ hash: applicantHash, registeredBlock: 5 }],
    latest: { hash: applicantHash, updated: 5 },
    blockTimes: new Map([[5, 0]]),
    selectionData: earlyOnlySelection,
  });
  ok('stageB_after_early_freeze_only_fails_not_fatal: 締切前の一致登録だけでもStage B末尾まで走る',
    earlyOnlyWithSelection.runError === null
      && earlyOnlyWithSelection.ctx.data.applicantHash === applicantHash
      && earlyOnlyWithSelection.ctx.data.registeredBlock === null
      && earlyOnlyWithSelection.report.get('check.stageB.hashRegisteredBlock')?.status === 'fail'
      && earlyOnlyWithSelection.report.get('check.stageB.applicantHashField')?.status === 'pass'
      && earlyOnlyWithSelection.report.get('check.stageB.playersMatch')?.status === 'pass');
  // 周23 統括の追補（T10 の変異で見つけた穴）: U_A 無しの理由を2種に分け、null 分岐の membership も実値で出す。
  ok('stageA_fail_reason_distinguishes_absent_and_early_freeze: 未登録と締切前だけを別の reason にする',
    rootAbsentWithSelection.report.get('check.stageA.rootMatch')?.params?.reason === 'no_matching_registration_at_or_after_entry_deadline'
      && earlyOnlyWithSelection.report.get('check.stageA.rootMatch')?.params?.reason === 'first_matching_registration_before_entry_deadline');
  ok('stageB_null_branch_membership_is_read: U_A 無しでも selection の組の membership を実値で出す',
    rootAbsentWithSelection.report.get('check.stageB.hashRegisteredBlock')?.params?.membership === false
      && earlyOnlyWithSelection.report.get('check.stageB.hashRegisteredBlock')?.params?.membership === true);

  // 周23 統括の追補: 最新が再計算 root と同じでも、許可リスト外で履歴 getter が読めなければ
  // 最新値へ黙って逃げず FAIL で止まる（履歴の一覧＝やり直しの可視化を失わない）。
  const historyUnavailable = await runHistoryScenario({
    history: registrations,
    latest: { hash: applicantHash, updated: registeredBlock },
    historyError: 'execution reverted: function selector was not recognized',
  });
  ok('neg_stageA_history_unavailable_fails: 許可リスト外で履歴getterが読めなければ最新値へ逃げずfail',
    historyUnavailable.report.get('check.stageA.rootMatch')?.status === 'fail'
      && historyUnavailable.report.get('check.stageA.earlyFreeze')?.status === 'fail'
      && historyUnavailable.ctx.data.stopReason === 'fail');

  const earlyRoot = await runHistoryScenario({
    history: [
      { hash: applicantHash, registeredBlock: 5 },
      { hash: applicantHash, registeredBlock },
    ],
    latest: { hash: applicantHash, updated: registeredBlock },
    blockTimes: new Map([[5, 0], [registeredBlock, 2]]),
  });
  ok('stageA_early_freeze_uses_first_root_registration: U_Aは締切後でも最初のroot登録が早ければfail',
    earlyRoot.report.get('check.stageA.rootMatch')?.status === 'pass'
      && earlyRoot.ctx.data.registeredBlock === registeredBlock
      && earlyRoot.report.get('check.stageA.earlyFreeze')?.status === 'fail');

  const laterRegisteredSelection = {
    ...selection,
    hashRegisteredBlock: retryRegisteredBlock,
    targetBlockNum: retryRegisteredBlock + confirmationBlocks,
    players: [{ globalIndex: 0, localIndex: 0, file: '00_0', data: honestEntry }],
  };
  const laterRegistered = await runHistoryScenario({
    history: registrations,
    latest: { hash: otherApplicantHash, updated: latestRegisteredBlock },
    selectionData: laterRegisteredSelection,
  });
  ok('stageB_selection_other_registration_warns: U_A以外の実在する同root登録はwarn',
    laterRegistered.report.get('check.stageB.hashRegisteredBlock')?.status === 'warn'
      && laterRegistered.report.get('check.stageB.applicantHashField')?.status === 'pass'
      && laterRegistered.report.get('check.stageB.targetBlockNum')?.status === 'pass');
  const laterRegistrationDetail = laterRegistered.report.get('check.stageB.hashRegisteredBlock')?.params;
  const anchorUnavailable = await runHistoryScenario({
    history: registrations,
    latest: { hash: otherApplicantHash, updated: latestRegisteredBlock },
    selectionData: laterRegisteredSelection,
    blockHashError: 'archive read unavailable',
  });
  const anchorUnavailableDetail = anchorUnavailable.report.get('check.stageB.hashRegisteredBlock')?.params;
  ok('stageB_warn_detail_ua_target_anchored: WARNにU_AのRANDAO対象とEvidence固定状態を載せる',
    laterRegistrationDetail?.uaRandaoTargetBlock === targetBlockNum
      && laterRegistrationDetail?.uaRandaoTargetAnchored === true
      && laterRegistrationDetail?.uaRandaoTargetHash === targetBlockHash
      && laterRegistered.blockHashReads.includes(targetBlockNum)
      && anchorUnavailable.report.get('check.stageB.hashRegisteredBlock')?.status === 'warn'
      && anchorUnavailableDetail?.uaRandaoTargetBlock === targetBlockNum
      && anchorUnavailableDetail?.uaRandaoTargetAnchored === 'unavailable'
      && anchorUnavailableDetail?.uaRandaoTargetHash === 'unavailable'
      && /archive read unavailable/.test(anchorUnavailableDetail?.uaRandaoTargetError || ''));
  // 周23 統括の追補（T10 の変異で見つけた穴）: U_A の RANDAO が Evidence に未固定なら false と出す
  // （窓切れからの復旧＝便 T9 と、ただのやり直しを見分ける手がかり）。判定は WARN のまま。
  const anchorMissing = await runHistoryScenario({
    history: registrations,
    latest: { hash: otherApplicantHash, updated: latestRegisteredBlock },
    selectionData: laterRegisteredSelection,
    blockHashZero: true,
  });
  const anchorMissingDetail = anchorMissing.report.get('check.stageB.hashRegisteredBlock')?.params;
  ok('stageB_warn_detail_ua_target_unanchored: U_A の RANDAO が未固定なら uaRandaoTargetAnchored=false',
    anchorMissing.report.get('check.stageB.hashRegisteredBlock')?.status === 'warn'
      && anchorMissingDetail?.uaRandaoTargetBlock === targetBlockNum
      && anchorMissingDetail?.uaRandaoTargetAnchored === false);

  const unregisteredSelection = {
    ...laterRegisteredSelection,
    hashRegisteredBlock: 13,
    targetBlockNum: 13 + confirmationBlocks,
  };
  const unregistered = await runHistoryScenario({
    history: registrations,
    latest: { hash: otherApplicantHash, updated: latestRegisteredBlock },
    selectionData: unregisteredSelection,
  });
  ok('neg_stageB_selection_not_registered: selectionの組が履歴に無ければfail',
    unregistered.report.get('check.stageB.hashRegisteredBlock')?.status === 'fail');

  const legacyAddress = LEGACY_HASH_STORAGE_ALLOWLIST[0];
  const legacySelection = {
    ...selection,
    hashRegisteredBlock: latestRegisteredBlock,
    targetBlockNum: latestRegisteredBlock + confirmationBlocks,
    players: [{ globalIndex: 0, localIndex: 0, file: '00_0', data: honestEntry }],
  };
  const legacy = await runHistoryScenario({
    history: [
      { hash: otherApplicantHash, registeredBlock },
      { hash: applicantHash, registeredBlock: latestRegisteredBlock },
    ],
    latest: { hash: applicantHash, updated: latestRegisteredBlock },
    selectionData: legacySelection,
    legacy: isLegacyHashStorageAddress(legacyAddress),
  });
  ok('legacy_allowlist_latest: collectorの許可リスト1件だけは履歴getterなしで最新値を使う',
    LEGACY_HASH_STORAGE_ALLOWLIST.length === 1
      && isLegacyHashStorageAddress(legacyAddress)
      && legacy.report.get('check.stageA.rootMatch')?.status === 'pass'
      && legacy.report.get('check.stageB.hashRegisteredBlock')?.status === 'pass');
  // 周23 統括の追補: 旧契約は最新値だけで判定するので、最新と違う登録を指す selection は FAIL。
  const legacyStale = await runHistoryScenario({
    history: [
      { hash: applicantHash, registeredBlock },
      { hash: applicantHash, registeredBlock: latestRegisteredBlock },
    ],
    latest: { hash: applicantHash, updated: latestRegisteredBlock },
    selectionData: {
      ...legacySelection,
      hashRegisteredBlock: registeredBlock,
      targetBlockNum: registeredBlock + confirmationBlocks,
    },
    legacy: true,
  });
  ok('neg_legacy_selection_not_latest_fails: 旧契約で最新と違う登録を指すselectionはfail',
    legacyStale.report.get('check.stageA.rootMatch')?.status === 'pass'
      && legacyStale.report.get('check.stageB.hashRegisteredBlock')?.status === 'fail');
  // 周23 統括の追補: createChain の旧契約判定は設定の契約アドレスだけで決まる（構築は通信しない）。
  const chainFor = (hashStorage) => createChain({
    rpcUrls: ['http://127.0.0.1:9'], chainIdExpected: 31337, contracts: { hashStorage },
  });
  ok('legacy_wrapper_uses_contract_address: createChainの旧契約判定は許可リストの1件だけ真',
    chainFor(`0x${legacyAddress.slice(2).toUpperCase()}`).isLegacyHashStorage() === true
      && chainFor(`0x${'30'.repeat(20)}`).isLegacyHashStorage() === false);

  const zeroHash = `0x${'00'.repeat(32)}`;
  const zkpCollected = {
    input: {
      blockNum: N,
      evidenceAcc: zeroHash,
      entryAcc: zeroHash,
      randaoBlockHash: targetBlockHash,
      prevResultManifestHash: zeroHash,
      applicantHash: selection.applicantHash,
      applicantHashUpdatedBlock: selection.hashRegisteredBlock,
      evidenceGraceSec: 0,
      randaoEthBlockNumber: selection.targetBlockNum,
      deploymentParamsHash: zeroHash,
      futureAnchorsHash: zeroHash,
      // 便 C30F1b: 便 C30F1 で PV は15語。この盤面に名簿の登録は無いので15語目は 0。
      rosterManifestHash: zeroHash,
    },
    claimDataHash: zeroHash,
    merkleRoot: zeroHash,
    resultManifestHash: zeroHash,
  };
  const zkpPublicValues = encodePublicValues(buildExpectedPublicValues(zkpCollected));
  const zkpCompared = compareRebuiltPublicValues(zkpPublicValues, zkpCollected);
  const zkpWrongHash = compareRebuiltPublicValues(zkpPublicValues, {
    ...zkpCollected,
    input: { ...zkpCollected.input, applicantHash: otherApplicantHash },
  });
  const zkpWrongBlock = compareRebuiltPublicValues(zkpPublicValues, {
    ...zkpCollected,
    input: { ...zkpCollected.input, applicantHashUpdatedBlock: retryRegisteredBlock },
  });
  ok('ZKP語8/語9はselectionのapplicantHash/hashRegisteredBlockと一致し、不一致は検出',
    zkpCompared.ok
      && zkpCompared.actual.applicantHash === selection.applicantHash
      && zkpCompared.actual.applicantHashUpdatedBlock === BigInt(selection.hashRegisteredBlock)
      && zkpWrongHash.mismatches.some((item) => item.name === 'applicantHash')
      && zkpWrongBlock.mismatches.some((item) => item.name === 'applicantHashUpdatedBlock'));
  const zkpWrongRoster = compareRebuiltPublicValues(zkpPublicValues, {
    ...zkpCollected,
    input: { ...zkpCollected.input, rosterManifestHash: otherApplicantHash },
  });
  ok('ZKP語15（rosterManifestHash）も再計算の照合に入り、不一致は検出（便 C30F1b）',
    zkpCompared.actual.rosterManifestHash === zeroHash
      && zkpWrongRoster.ok === false
      && zkpWrongRoster.mismatches.some((item) => item.name === 'rosterManifestHash'));

  const missingCacheR2 = createR2({ r2Base: 'https://r2.invalid', dataDir }, ui, 99);
  const before = [...fetchCounts.values()].reduce((sum, n) => sum + n, 0);
  const missing = await missingCacheR2.fetchJson('entries/block99/entries/00_0.json', {
    reuse: true,
    cacheOnly: true,
  });
  const after = [...fetchCounts.values()].reduce((sum, n) => sum + n, 0);
  ok('cacheOnlyの欠落はネットワークへフォールバックしない', missing === null && after === before);
} finally {
  globalThis.fetch = originalFetch;
  await rm(dataDir, { recursive: true, force: true });
}

console.log(`\ns5-entry-snapshot-unit: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);

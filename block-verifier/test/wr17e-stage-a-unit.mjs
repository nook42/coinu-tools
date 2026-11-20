import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { makeWireLaneFixtures } from '../../Hardhat/bitcoinu/scripts/lib/make-wire-lane-fixtures.mjs';
import { makeWireG6Boards } from '../../Hardhat/bitcoinu/scripts/lib/make-wire-g6-boards.mjs';
import { run as runStageA } from '../src/stages/entries.js';
import { hashLikeBackend } from '../src/json-utils.js';
import { createReport } from '../src/report.js';
import { t } from '../src/i18n.js';

const sha = (bytes) => `0x${createHash('sha256').update(bytes).digest('hex')}`;
const tmp = await mkdtemp(path.join(os.tmpdir(), 'wr17e-stage-a-'));
let passed = 0;

async function exercise(name, lane, r2Data) {
  const manifest = JSON.parse(await readFile(path.join(lane, 'lane-manifest.json')));
  const descriptors = JSON.parse(await readFile(path.join(lane, 'stage4/files.json'))).files;
  // The public half comes from the writer's R2 image, independently of stage4/files.json.
  const publicFiles = new Map([...r2Data].map(([key, bytes]) => [key, bytes.toString()]));
  for (const d of descriptors) {
    const bytes = await readFile(path.join(lane, d.path));
    assert.equal(sha(bytes), d.sha256, `${name}: collector file digest`);
  }
  const run = async (files, hash = manifest.anchors.applicantHash) => {
    const report = createReport();
    const ctx = {
      cfg: {}, blockNum: manifest.blockNum, report,
      ui: { t: t('ja'), println() {} }, data: { reuseFiles: false },
      r2: { async fetchJson(key) { const raw = files.get(key); return raw == null ? null : { data: JSON.parse(raw), raw }; }, release() {} },
      chain: {
        isLegacyHashStorage: () => false,
        getApplicantHash: async () => ({ hash, updated: 100 }),
        getTimingConstants: async () => ({ startTimeEntryMs: 0, blockTimeMs: 1000 }),
        applicantRegistrationCount: async () => 1,
        applicantRegistrationAt: async () => ({ hash, registeredBlock: 100 }),
        getBlock: async () => ({ timestamp: 1000000 }),
      },
    };
    await runStageA(ctx);
    return ctx;
  };
  const positive = await run(publicFiles);
  assert.equal(positive.report.get('check.stageA.recordCounts')?.status, 'pass', name);
  assert.equal(positive.report.get('check.stageA.rootMatch')?.status, 'pass', name);
  assert.equal(positive.data.applicantHash, manifest.anchors.applicantHash, name);
  const rebuilt = positive.data.infos.flatMap((info, worker) => info.entries.map((entry) => ({
    worker, filename: entry.filename, hash: positive.data.entryFileHashes.get(entry.filename),
    rows: entry.number,
  })));
  const compareFileList = (bundleList, publicList) => assert.deepEqual(
    bundleList.map(({ worker, filename }) => ({ worker, filename })),
    publicList.map(({ worker, filename }) => ({ worker, filename })),
    `${name}: collector file order and worker must match Stage A`);
  compareFileList(descriptors, rebuilt);
  for (let i = 0; i < descriptors.length; i++) {
    const d = descriptors[i];
    assert.equal(`0x${rebuilt[i].hash}`, d.sha256, `${name}: file ${i} hash`);
    assert.equal(rebuilt[i].rows, JSON.parse(publicFiles.get(`entries/block${manifest.blockNum}/entries/${d.filename}.json`)).length);
  }
  assert.equal(positive.data.entriesTotal, descriptors.reduce((sum, d) => sum +
    JSON.parse(publicFiles.get(`entries/block${manifest.blockNum}/entries/${d.filename}.json`)).length, 0));
  if (name === 'multi-worker-files') {
    assert(descriptors.length >= 2 && new Set(descriptors.map((d) => d.worker)).size >= 2);
    assert.throws(() => compareFileList(descriptors.toReversed(), rebuilt), /file order and worker/);
    const moved = structuredClone(descriptors);
    moved[0].worker = descriptors[1].worker;
    assert.throws(() => compareFileList(moved, rebuilt), /file order and worker/);
    const shifted = new Map(publicFiles);
    const first = descriptors[0], second = descriptors[1];
    const infoKey = (w) => `entries/block${manifest.blockNum}/info/${String(w).padStart(2, '0')}_info.json`;
    const a = JSON.parse(shifted.get(infoKey(first.worker)));
    const b = JSON.parse(shifted.get(infoKey(second.worker)));
    [a.entries[0], b.entries[0]] = [b.entries[0], a.entries[0]];
    shifted.set(infoKey(first.worker), JSON.stringify(a));
    shifted.set(infoKey(second.worker), JSON.stringify(b));
    const swappedPublic = await run(shifted);
    assert.equal(swappedPublic.report.get('check.stageA.rootMatch')?.status, 'fail');
    const swappedList = swappedPublic.data.infos.flatMap((info, worker) => info.entries.map((entry) =>
      ({ worker, filename: entry.filename })));
    assert.throws(() => compareFileList(descriptors, swappedList), /file order and worker/);
    // The empty-branch rule only applies when the total is zero. Keep a zero-row
    // descriptor beside real rows and close K8 around that exact public image.
    const withZeroFile = new Map(publicFiles);
    const zeroName = '00_1';
    withZeroFile.set(`entries/block${manifest.blockNum}/entries/${zeroName}.json`, '[]');
    const zeroInfo = JSON.parse(withZeroFile.get(infoKey(0)));
    zeroInfo.entries.push({ filename: zeroName, number: 0 });
    withZeroFile.set(infoKey(0), JSON.stringify(zeroInfo));
    const hashes = Array.from({ length: 100 }, (_, worker) => ({
      filename: `${String(worker).padStart(2, '0')}_hash`,
      hash: hashLikeBackend({ block_num: manifest.blockNum, status: 'success',
        entries: JSON.parse(withZeroFile.get(infoKey(worker))).entries.map((entry) => ({
          filename: entry.filename,
          hash: hashLikeBackend(JSON.parse(withZeroFile.get(
            `entries/block${manifest.blockNum}/entries/${entry.filename}.json`))),
          number: entry.number,
        })) }),
    }));
    const closedRoot = `0x${hashLikeBackend({ block_num: manifest.blockNum, status: 'success', hash: hashes })}`;
    const rangeControl = await run(withZeroFile, closedRoot);
    assert.equal(rangeControl.report.get('check.stageA.rootMatch')?.status, 'pass');
    assert.equal(rangeControl.report.get('check.stageA.recordCounts')?.status, 'pass');
    assert(rangeControl.data.entriesTotal > 0);
  }
  if (descriptors.length) {
    const d = descriptors[0];
    const key = `entries/block${manifest.blockNum}/entries/${d.filename}.json`;
    const publicMutation = new Map(publicFiles);
    const changed = JSON.parse(publicFiles.get(key));
    changed[0].name = 'WR17E altered';
    publicMutation.set(key, JSON.stringify(changed));
    const changedPublic = await run(publicMutation);
    assert.equal(changedPublic.report.get('check.stageA.rootMatch')?.status, 'fail', `${name}: public mutation`);
    assert.notEqual(changedPublic.data.entryFileHashes.get(d.filename), rebuilt[0].hash);
    const bundleFile = path.join(lane, d.path);
    const originalBundle = await readFile(bundleFile);
    try {
      await writeFile(bundleFile, JSON.stringify(changed));
      assert.notEqual(sha(await readFile(bundleFile)), `0x${rebuilt[0].hash}`,
        `${name}: bundle-side mutation`);
    } finally {
      await writeFile(bundleFile, originalBundle);
    }
  } else {
    assert.equal(positive.data.zeroEntries, true, `${name}: honest empty branch`);
    const contaminated = new Map(publicFiles);
    contaminated.set(`entries/block${manifest.blockNum}/info/00_info.json`, JSON.stringify({ entries: [{ filename: '00_0', number: 0 }] }));
    contaminated.set(`entries/block${manifest.blockNum}/entries/00_0.json`, '[]');
    const workerHashes = Array.from({ length: 100 }, (_, i) => ({
      filename: `${String(i).padStart(2, '0')}_hash`,
      hash: hashLikeBackend({ block_num: manifest.blockNum, status: 'success', entries: i === 0
        ? [{ filename: '00_0', hash: hashLikeBackend([]), number: 0 }] : [] }),
    }));
    const closedRoot = `0x${hashLikeBackend({ block_num: manifest.blockNum, status: 'success', hash: workerHashes })}`;
    const bad = await run(contaminated, closedRoot);
    assert.equal(bad.report.get('check.stageA.rootMatch')?.status, 'pass', 'closed K8 control');
    assert.equal(bad.report.get('check.stageA.recordCounts')?.status, 'fail', 'row-zero descriptor rejected');
    assert.match(bad.report.get('check.stageA.recordCounts').params.first, /ファイル記述子/);
  }
  passed++;
  console.log(`WR17E_STAGE_A ${name} pass`);
}

try {
  const defaultNames = ['normal', 'normal-k14-leading-zero', 'auto-one', 'zero-entries', 'normal-block1'];
  const defaultR2 = new Map();
  await makeWireLaneFixtures(path.join(tmp, 'default'), { names: defaultNames,
    mutateBoard: ({ name, r2 }) => defaultR2.set(name, new Map(r2)) });
  for (const name of defaultNames) await exercise(name, path.join(tmp, 'default', name), defaultR2.get(name));
  const g6 = await makeWireG6Boards(path.join(tmp, 'g6'), { boards: ['normal-4p'] });
  await exercise('normal-4p', g6[0].laneDir, g6[0].r2Data);
  const multi = await makeWireG6Boards(path.join(tmp, 'multi'), { boards: ['normal-4p'],
    mutatePreimage: (material) => { material.entryRows.forEach((row, i) => { row.collectWorker = i < 2 ? 0 : 1; }); } });
  await exercise('multi-worker-files', multi[0].laneDir, multi[0].r2Data);
  assert.equal(passed, 7);
  console.log(`WR17E_STAGE_A_OK boards=${passed}`);
} finally {
  await rm(tmp, { recursive: true, force: true });
}

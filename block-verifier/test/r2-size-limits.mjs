// R8-F1: R2サイズ上限の全読取経路と「正常最大を止めない」byte実測。
// 実行: node block-verifier/test/r2-size-limits.mjs
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { createR2, R2_LIMITS, r2LimitKind } from '../src/r2.js';
import { validateResultBundle } from '../vendor/workers/game_workers/lib/evidence-reconciler.js';
import { planOnChainTrim } from '../../src/utils/evidence.js';
import {
  makeMaxSubmissionFixture,
  makeServerLimitBoundaryFixture,
} from
  '../../workers/game_workers/script/test-calculator/_max-submission-fixture.mjs';
import {
  SERVER_MAX_DECODED_BYTES,
  SERVER_MAX_WIRE_BYTES,
} from '../../workers/game_workers/lib/submission-limits.js';

let passed = 0, failed = 0;
const ok = (label, cond, detail = '') => {
  if (cond) { passed++; console.log('  ok: ' + label); }
  else { failed++; console.error('  NG: ' + label + (detail ? ' — ' + detail : '')); }
};
const MiB = 1024 * 1024;
const GiB = 1024 * MiB;
const EVIDENCE_MAX_DATA_BYTES = 130000; // Evidence.sol MAX_DATA_BYTES
const bytes = (v) => Buffer.byteLength(typeof v === 'string' ? v : JSON.stringify(v), 'utf8');
const jsonAt = (n) => JSON.stringify({ p: 'x'.repeat(n - 8) });

const bodies = new Map([
  ['/games/block0/group0.json', jsonAt(1024)],
  ['/games/block0/group1.json', jsonAt(1025)],
  ['/games/block0/group2.json', jsonAt(1025)],
  ['/games/block0/group3.json', JSON.stringify({ ok: true })],
  ['/games/block0/group4.json', jsonAt(800)],
  ['/games/block0/group5.json', jsonAt(800)],
]);
for (let i = 6; i < 16; i++) bodies.set(`/games/block0/group${i}.json`, jsonAt(800));
const server = http.createServer((req, res) => {
  const body = bodies.get(req.url);
  if (body == null) { res.writeHead(404); res.end(); return; }
  res.setHeader('content-type', 'application/json');
  if (req.url === '/games/block0/group2.json') {
    res.write(body.slice(0, 700));
    res.end(body.slice(700));
  } else {
    res.setHeader('content-length', String(bytes(body)));
    res.end(body);
  }
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const baseUrl = 'http://127.0.0.1:' + server.address().port;
const ui = { t: (_k, p) => p?.error || _k, warn: () => {} };

console.log('--- 1. network / stream / reuse cache / refetch / cumulative ---');
try {
  const dataDir = await mkdtemp(path.join(os.tmpdir(), 'bv-r2-limit-'));
  const limits = { ...R2_LIMITS, groupArchive: 1024, gameBlockTotal: 16 * 1024 };
  const r2 = createR2({ r2Base: baseUrl, dataDir }, ui, 0, { limits });
  ok('ちょうど上限は受理', (await r2.fetchJson('games/block0/group0.json'))?.data?.p?.length === 1016);
  const early = await r2.fetchJson('games/block0/group1.json');
  ok('Content-Lengthで上限+1を拒否', !!early?.sizeError && early.sizeSource === 'content-length', early?.sizeError);
  const streamed = await r2.fetchJson('games/block0/group2.json');
  ok('Content-Length無しでも実ストリームで拒否', !!streamed?.sizeError && streamed.sizeSource === 'stream', streamed?.sizeError);

  const cachePath = path.join(dataDir, 'block0/games/block0/group3.json');
  await mkdir(path.dirname(cachePath), { recursive: true });
  await writeFile(cachePath, jsonAt(1025));
  const reused = await r2.fetchJson('games/block0/group3.json', { reuse: true });
  ok('過大reuse cacheを捨て正常なR2を再取得', reused?.data?.ok === true);
  const refreshed = await r2.refetch('games/block0/group1.json');
  ok('refetchにも同じ上限', !!refreshed?.sizeError && refreshed.sizeSource === 'content-length');

  const cumulative = createR2(
    { r2Base: baseUrl, dataDir: await mkdtemp(path.join(os.tmpdir(), 'bv-r2-total-')) },
    ui, 0, { limits: { ...limits, gameBlockTotal: 1500 } }
  );
  ok('累積上限の1本目は受理', !!(await cumulative.fetchJson('games/block0/group4.json'))?.data);
  const overTotal = await cumulative.fetchJson('games/block0/group5.json');
  ok('ゲーム成果物のブロック累積上限を拒否', overTotal?.sizeScope === 'game-block-total', overTotal?.sizeError);

  const cacheLimited = createR2(
    { r2Base: baseUrl, dataDir: await mkdtemp(path.join(os.tmpdir(), 'bv-r2-cache-')) },
    ui, 0, { limits: { ...limits, gameBlockTotal: 10 * 1024, cacheGameBytes: 1000 } }
  );
  const ca = await cacheLimited.fetchJson('games/block0/group4.json');
  const cb = await cacheLimited.fetchJson('games/block0/group5.json');
  ok('cache予算超過でも検証は止めない', !!ca?.data && !!cb?.data);
  ok('cache予算超過分だけ保存を省略', ca.path != null && cb.path == null);

  const cacheConcurrent = createR2(
    { r2Base: baseUrl, dataDir: await mkdtemp(path.join(os.tmpdir(), 'bv-r2-cache-race-')) },
    ui, 0, { limits: { ...limits, gameBlockTotal: 20 * 1024, cacheGameBytes: 1000 } }
  );
  const concurrent = await Promise.all(
    Array.from({ length: 10 }, (_, i) => cacheConcurrent.fetchJson(`games/block0/group${i + 6}.json`))
  );
  ok('10並列でも全ファイルの検証は継続', concurrent.every(v => !!v?.data));
  ok('10並列でもcache予算を突破しない',
    concurrent.filter(v => v.path != null).length === 1
      && cacheConcurrent.stats().cacheBytes.game <= 1000,
    JSON.stringify(cacheConcurrent.stats()));
} finally {
  await new Promise((resolve) => server.close(resolve));
}

console.log('\n--- 2. 2100人・正準最大530組を覆う保守的byte上界 ---');
const uid = (i) => String(2000000000000000000n + BigInt(i));
const sig = '0x' + 'ab'.repeat(65);
const ref = '0x' + 'ab'.repeat(16);
const hash32 = '0x' + 'cd'.repeat(32);
const encrypted = 'ab'.repeat(225);
const uids = Array.from({ length: 5 }, (_, i) => uid(i));
const deposits = Array.from({ length: 10 }, (_, i) => ({
  id: String(i + 1).padStart(78, '9'), idFrom: uid(i), amount: '10000000000000000000',
  depositerAddress: '0x' + 'ab'.repeat(20), unlockTime: 4294967295,
  name: '界'.repeat(50), img: 'https://pbs.twimg.com/' + 'x'.repeat(100),
}));
const depIds = JSON.stringify({
  deposit: '10000000000000000000', ids: deposits.map(d => d.id), deposits,
});
const member = (u, i = 0) => ({
  uid: u, addr: '0x' + 'ab'.repeat(20),
  bAddr: JSON.stringify({ address: '0x' + 'cd'.repeat(20), pubKey: '0x04' + 'ef'.repeat(64),
    nostrPubkey: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798' }),
  lang: 'x'.repeat(32), depIds, name: '界'.repeat(50),
  img: 'https://pbs.twimg.com/' + 'x'.repeat(100), verified: true, globalIndex: 2095 + i,
});
const members = uids.map(member);
const messages = [];
for (const u of uids) for (let i = 0; i < 100; i++) messages.push({
  type: 'chat', blockNum: 999999, groupId: 419, uid: u,
  text: '界'.repeat(50), timestamp: 9007199254740000 - i, signature: sig,
});
const readReceipts = [];
for (const receiverUid of uids) for (const senderUid of uids) if (receiverUid !== senderUid) {
  for (let i = 0; i < 100; i++) readReceipts.push({
    receiverUid, senderUid, msgRefs: [ref], timestamp: 9007199254740000 - i, signature: sig,
  });
}
const actionReceipts = [];
for (const receiverUid of uids) for (let i = 0; i < 400; i++) actionReceipts.push({
  receiverUid, actionHash: hash32, timestamp: 9007199254740000 - i, signature: sig,
});
const receipts = readReceipts.concat(actionReceipts);
const action = { encrypted, signature: sig, timestamp: 9007199254740000 };
const snapshot = {
  votes: Object.fromEntries(uids.map(u => [u, action])),
  reports: Object.fromEntries(uids.map(u => [u, [action, action]])),
  observed: { votes: {}, reports: {}, receipts: receipts.slice(0, 4000) },
};
const submissions = Object.create(null), submissionsRaw = Object.create(null);
for (const u of uids) {
  const bundle = {
    uid: u, encryptKey: '0x' + 'aa'.repeat(32), chatHash: hash32, signature: sig,
    submittedAt: 9007199254740000, encryptedDataHash: hash32,
    depositIds: deposits.map(d => d.id), encryptedActions: snapshot, messages,
  };
  submissions[u] = bundle;
  submissionsRaw[u] = JSON.stringify(bundle);
}
const canonicalTimeline = messages.map(m => ({ type: 'chat', uid: m.uid, text: m.text, timestamp: m.timestamp }))
  .concat(uids.map((u, i) => ({ type: 'vote', uid: u, targetUid: uids[(i + 1) % 5], timestamp: 9007199254740000 })))
  .concat(uids.flatMap((u, i) => [0, 1].map(j => ({
    type: 'report', uid: u, targetUid: uids[(i + j + 1) % 5], timestamp: 9007199254740000 + j,
  }))));
const gameResults = uids.map(u => ({
  userId: u, role: 'player', deposit_id: null, address: '0x' + 'ab'.repeat(20),
  btcu_reward: '1'.repeat(40), deposit_to: null,
  deposit_points: 316, bonus_points: 400, total_points: 716,
  is_disqualified: 0, disqualify_reason: null, report_gain_points: 200,
  vote_target_uid: uids[0], report_target_uids: JSON.stringify(uids.slice(0, 2)),
  voted_by_uids: JSON.stringify(uids.slice(0, 4)),
}));
const groupArchive = {
  meta: { blockNum: 999999, groupId: 419 }, members,
  messages: messages.map(({ type, blockNum, groupId, ...m }) => m), receipts,
  charCounts: Object.fromEntries(uids.map(u => [u, 10000])),
  phaseTimestamps: { waiting: 9007199254740000, chatting: 9007199254740000, submitting: 9007199254740000, completed: 9007199254740000 },
  submissions, submissionsRaw, reports: {}, votes: {}, gameSkipped: null,
  archivedAt: '2026-08-11T00:00:00.000Z', canonicalTimeline, gameResults,
};
const groupBytes = bytes(groupArchive);
const maxClaimed = { time: 9007199254740991, txHash: '0x' + 'ab'.repeat(32) };
const groupClaimOverlay = {
  schemaVersion: 1,
  blockNum: 9007199254740991,
  groupId: 419,
  claims: [
    ...Array.from({ length: 5 }, (_, i) => ({
      role: 'player', id: String(20000000000000000000n + BigInt(i)), claimed: maxClaimed,
    })),
    ...Array.from({ length: 50 }, (_, i) => ({
      role: 'depositor', id: String(i + 1).padStart(78, '9'), claimed: maxClaimed,
    })),
  ],
};
const groupClaimOverlayBytes = bytes(groupClaimOverlay);

// Round 21以後の正常入力は「2 MiBまで伸ばした任意JSON」ではない。
// このR2境界では正準500 messages / 2,060 receipt factsの既存fixtureを再利用し、
// server wire/decoded上限、構造・外側署名・chatHash・snapshotHashと
// Evidence 130,000 byte未満への決定的trimを通ることを先に証明する。
const maxFixture = await makeMaxSubmissionFixture();
const serverBoundaryFixture = await makeServerLimitBoundaryFixture();
const maxRaw = JSON.stringify(maxFixture.bundle);
const maxRosterUids = maxFixture.players.map(player => player.uid);
const maxMembersIndex = {
  byUid: Object.fromEntries(maxFixture.players.map(player => [player.uid, {
    uid: player.uid,
    addr: player.wallet.address,
    bAddr: JSON.stringify({ address: player.sign.address }),
    groupId: maxFixture.context.groupId,
    depIds: { ids: player.depositIds },
    memberUids: maxRosterUids,
  }])),
};
const maxChecked = await validateResultBundle(
  maxFixture.payload, maxFixture.context.blockNum, maxMembersIndex, maxFixture.submitter.wallet.address,
);
const maxTrim = await planOnChainTrim(maxFixture.payload, maxFixture.submitter.uid, {
  blockNum: maxFixture.context.blockNum,
  groupId: maxFixture.context.groupId,
});
const evidenceBundlesValid = maxChecked.valid === true && maxTrim?.impossible !== true;
const evidenceInvalidReasons = evidenceBundlesValid
  ? []
  : [maxChecked.reason || maxTrim?.reason || 'unknown'];

// group archiveのparsed/raw二重保存を5人全員が最大形だった場合へ保守的に外挿する。
// 値は同じ正準bundleを複製するが、uid/signatureのバイト長は全員同じなのでbyte上界は変わらない。
const evidenceSubmissions = Object.create(null);
const evidenceSubmissionsRaw = Object.create(null);
for (const u of uids) {
  evidenceSubmissions[u] = structuredClone(maxFixture.bundle);
  evidenceSubmissionsRaw[u] = maxRaw;
}
const evidenceMaxGroupArchive = {
  ...groupArchive,
  submissions: evidenceSubmissions,
  submissionsRaw: evidenceSubmissionsRaw,
  evidenceSources: Object.fromEntries(uids.map(u => [u, { source: 'chain', seq: 999999 }])),
};
const evidenceMaxGroupBytes = bytes(evidenceMaxGroupArchive);

const selectionShell = {
  blockNum: 999999, hashRegisteredBlock: 99999999, confirmationBlocks: 64,
  entryPeriodEnd: 9007199254740000, targetBlockNum: 99999999,
  targetBlockHash: hash32, randao: hash32, mainnetBlockNumber: 99999999,
  applicantHash: hash32, totalEntries: 999999999, totalSelected: 2100,
  players: [], createdAt: '2026-08-11T00:00:00.000Z',
};
let selectionBytes = bytes(selectionShell);
for (let i = 0; i < 2100; i++) {
  if (i) selectionBytes++;
  selectionBytes += bytes({
    globalIndex: i, localIndex: i % 5000,
    file: String(i % 100).padStart(2, '0') + '_' + Math.floor(i / 5000),
    data: member(uid(i), i),
  });
}

const summaryShell = {
  schemaVersion: 3, blockNum: 999999, majorLangs: ['x'.repeat(32)],
  timeline: { entryStart: 9007199254740000, entryEnd: 9007199254740000, gameStart: 9007199254740000, gameEnd: 9007199254740000, submitEnd: 9007199254740000 },
  groups: [], blockReward: '1'.repeat(40), resultLayout: 'group-artifacts-v1',
  claimStatusKey: 'games/block999999/claim-status.json',
  claimLayout: 'group-overlays-v1',
};
let summaryBytes = bytes(summaryShell);
let summaryMemberIndex = 0;
for (let g = 0; g < 530; g++) {
  const rows = [], depositorRows = [];
  const groupSize = g < 20 ? 3 : 4;
  for (let j = 0; j < groupSize; j++) {
    const u = uid(summaryMemberIndex++);
    rows.push({
      userId: u, address: '0x' + 'ab'.repeat(20), lang: 'x'.repeat(32), total_points: 716,
      is_disqualified: 0, full_btcu_reward: '1'.repeat(40),
    });
    for (let k = 0; k < 10; k++) depositorRows.push({
      playerUid: u, depositId: '9'.repeat(78),
    });
  }
  if (g) summaryBytes++;
  summaryBytes += bytes({
    group_id: g, lang: 'mixed', member_count: 5, status: 'completed',
    total_points: 3580, detailKey: `games/block999999/group${g}.json`,
    claimOverlayKey: `games/block999999/claim-status/group${g}.json`,
    members: rows, depositor_results: depositorRows,
  });
}

const entryWorstBytes = bytes(member(uid(0)));
if (summaryMemberIndex !== 2100) throw new Error(`canonical maximum roster mismatch: ${summaryMemberIndex}`);
// 530ページすべてを5人組最大ページとして数える保守上界。実際の正準分布は
// 3人組×20＋4人組×510なので、このモデルは正規到達値を過小評価しない。
const modeledGameTotal = selectionBytes + summaryBytes
  + (evidenceMaxGroupBytes + groupClaimOverlayBytes) * 530 + 64 * MiB;
console.log('  entry row          ' + entryWorstBytes.toLocaleString() + ' B');
console.log('  game_selection     ' + selectionBytes.toLocaleString() + ' B / cap ' + R2_LIMITS.selection.toLocaleString() + ' B');
console.log('  summary            ' + summaryBytes.toLocaleString() + ' B / cap ' + R2_LIMITS.summary.toLocaleString() + ' B');
console.log('  group archive      ' + groupBytes.toLocaleString() + ' B / cap ' + R2_LIMITS.groupArchive.toLocaleString() + ' B');
console.log('  group + Evidence   ' + evidenceMaxGroupBytes.toLocaleString() + ' B / cap ' + R2_LIMITS.groupArchive.toLocaleString() + ' B');
console.log('  group claim overlay ' + groupClaimOverlayBytes.toLocaleString() + ' B / cap ' + R2_LIMITS.groupClaimOverlay.toLocaleString() + ' B');
console.log('  Evidence compact   ' + maxTrim.afterBytes.toLocaleString() + ' B / contract cap < ' + EVIDENCE_MAX_DATA_BYTES.toLocaleString() + ' B');
console.log('  block total model  ' + (modeledGameTotal / GiB).toFixed(2) + ' GiB / cap ' + (R2_LIMITS.gameBlockTotal / GiB).toFixed(2) + ' GiB');
ok('entry chunk: writer 4 MiB + 最大1行が5 MiB内', 4 * MiB + entryWorstBytes < R2_LIMITS.entryChunk);
ok('2100人 selection は96 MiB内', selectionBytes < R2_LIMITS.selection);
ok('2100人×10 deposits のlean summaryは8 MiB内', summaryBytes < R2_LIMITS.summary);
ok('5人組の通常クライアント最大 group は48 MiB内', groupBytes < R2_LIMITS.groupArchive);
ok('正準最大decoded submission×5人を採用したgroupも48 MiB内',
  evidenceMaxGroupBytes < R2_LIMITS.groupArchive);
ok('最大幅ID×55行のgroup claim overlayは実測11,922 bytesで16 KiB内',
  groupClaimOverlayBytes === 11922 && groupClaimOverlayBytes < R2_LIMITS.groupClaimOverlay,
  `bytes=${groupClaimOverlayBytes}`);
ok('group claim overlay keyはunknownでなく専用種別へ分類',
  r2LimitKind('games/block999999/claim-status/group419.json') === 'groupClaimOverlay');
ok('Evidence最大fixtureはserver compact/decoded上限を通る',
  maxFixture.compactBytes.length < SERVER_MAX_WIRE_BYTES
    && bytes(maxRaw) < SERVER_MAX_DECODED_BYTES);
ok('v6 server枠を使うfixtureは旧境界を越えて現行上限を通る',
  serverBoundaryFixture.wireBytes > 294_912
    && serverBoundaryFixture.decodedBytes > 1_245_184
    && serverBoundaryFixture.wireBytes < SERVER_MAX_WIRE_BYTES
    && serverBoundaryFixture.decodedBytes < SERVER_MAX_DECODED_BYTES,
  JSON.stringify({
    wireBytes: serverBoundaryFixture.wireBytes,
    decodedBytes: serverBoundaryFixture.decodedBytes,
    serverMaxWireBytes: SERVER_MAX_WIRE_BYTES,
    serverMaxDecodedBytes: SERVER_MAX_DECODED_BYTES,
  }));
ok('Evidence最大fixtureはtrim後にコントラクト上限未満',
  maxTrim.afterBytes < EVIDENCE_MAX_DATA_BYTES);
ok('Evidence最大fixtureは署名・chatHash・snapshotHash検証を通って採用可能',
  evidenceBundlesValid, evidenceInvalidReasons.join(', '));
ok('正準最大530組を5人組Evidence最大で包んだ保守上界も24 GiB累積内',
  modeledGameTotal < R2_LIMITS.gameBlockTotal);
ok('48 MiBを1バイト超えるpadding mockはgroup上限外',
  bytes({ padding: 'x'.repeat(48 * MiB) }) > R2_LIMITS.groupArchive);

console.log('\nr2-size-limits: ' + passed + ' passed, ' + failed + ' failed');
if (failed) process.exitCode = 1;

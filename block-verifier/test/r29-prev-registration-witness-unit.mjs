// 周29（2026-09-22）: 証明が名乗った前ブロックの登録行が「グループ分けの時点で現在値だった行」かを
// 見張り役の記録で見る検査（check.stageC.zkPrevRegistrationWitness）の歯。
//
// 🔴 この検査は **fail を返さない**。ユーザーの規則（「N+1 の主要言語は N+1 のグループ分けの時点の
//    N の配布を正典として扱う。それ以降に N の配布が変更しても反映しない」）が、
//    その時点の登録が攻撃者のものであっても許容すると決めているため、
//    仕事は「止める」ことではなく「後から積まれた行が使われたことを見せる」ことである。
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { encodeFunctionData } from 'viem';

import { decodeProofPrevRegistrationIndex } from '../src/zkp.js';
import {
  PREV_REGISTRATION_SENTINEL,
  collectObserverChainSnapshots,
  judgePrevRegistrationWitness,
  locateCurrentResultRow,
  readObserverChainSnapshots,
  selectObserverResultWitness,
} from '../src/prev-registration-witness.js';
import * as baseResultsModule from '../src/stages/results.js';
import {
  PREV_REGISTRATION_SENTINEL as CANON_SENTINEL,
  TOKEN_MINING_ABI as CANON_TOKEN_MINING_ABI,
} from '../../Hardhat/bitcoinu/scripts/lib/zkp-pipeline.mjs';
import { CHECK_INVENTORY } from '../src/check-inventory.js';
import { SUPPORTED_LANGS, t } from '../src/i18n.js';
import { createReport } from '../src/report.js';

let p8bMutationRoot = null;
let resultsModule = baseResultsModule;
const P8B_MUTATION = process.argv.find((arg) => arg.startsWith('--p8b-mutation='))?.split('=')[1] || null;
if (P8B_MUTATION) {
  if (P8B_MUTATION !== 'outer-prev-registration-index') {
    throw new Error(`unknown P8b witness mutation: ${P8B_MUTATION}`);
  }
  const verifierRoot = resolve(import.meta.dirname, '..');
  p8bMutationRoot = resolve(verifierRoot, `../tmp/P8b/r29-${P8B_MUTATION}-${process.pid}`);
  await fs.rm(p8bMutationRoot, { recursive: true, force: true });
  await fs.mkdir(join(p8bMutationRoot, 'src/stages'), { recursive: true });
  await fs.writeFile(join(p8bMutationRoot, 'package.json'), '{"type":"module"}\n');
  for (const entry of await fs.readdir(join(verifierRoot, 'src'), { withFileTypes: true })) {
    if (entry.name === 'stages') continue;
    await fs.symlink(join(verifierRoot, 'src', entry.name), join(p8bMutationRoot, 'src', entry.name));
  }
  for (const entry of await fs.readdir(join(verifierRoot, 'src/stages'), { withFileTypes: true })) {
    if (entry.name === 'results.js') continue;
    await fs.symlink(
      join(verifierRoot, 'src/stages', entry.name),
      join(p8bMutationRoot, 'src/stages', entry.name),
    );
  }
  await fs.symlink(join(verifierRoot, 'vendor'), join(p8bMutationRoot, 'vendor'));
  const canonical = await fs.readFile(join(verifierRoot, 'src/stages/results.js'), 'utf8');
  const mutated = canonical.replace(
    "  if (typeof resolvedSubmission?.prevRegistrationIndex === 'bigint') {",
    "  if (false && typeof resolvedSubmission?.prevRegistrationIndex === 'bigint') {",
  );
  if (mutated === canonical) throw new Error('outer-prev-registration-index mutation was not applied');
  const mutatedPath = join(p8bMutationRoot, 'src/stages/results.js');
  await fs.writeFile(mutatedPath, mutated);
  resultsModule = await import(`${pathToFileURL(mutatedPath).href}?p8b=${Date.now()}`);
}
const {
  recordZkpState, verifyPrevRegistrationWitness, verifyZkpSubmission,
} = resultsModule;

let passed = 0;
let failed = 0;
const ok = (label, condition, detail = '') => {
  if (condition) { passed++; console.log(`  ok: ${label}`); }
  else { failed++; console.error(`  NG: ${label}${detail ? ` — ${detail}` : ''}`); }
};

const CHECK_ID = 'check.stageC.zkPrevRegistrationWitness';
const dir = mkdtempSync(join(tmpdir(), 'bv-r29-prev-witness-'));

// ------------------------------------------------------------------
// 1) calldata 第7引数の読み取り
// ------------------------------------------------------------------
const SUBMIT_7 = [{
  name: 'submitMerkleRootWithProof', type: 'function', stateMutability: 'nonpayable',
  inputs: [
    { name: 'blockNum', type: 'uint256' }, { name: 'root', type: 'bytes32' },
    { name: 'expectedVerifier', type: 'address' }, { name: 'expectedVkey', type: 'bytes32' },
    { name: 'publicValues', type: 'bytes' }, { name: 'proofBytes', type: 'bytes' },
    { name: 'prevRegistrationIndex', type: 'uint256' },
  ], outputs: [],
}];
const ATTACH_7 = [{
  name: 'attachProofToMerkleRoot', type: 'function', stateMutability: 'nonpayable',
  inputs: [
    { name: 'blockNum', type: 'uint256' }, { name: 'expectedVerifier', type: 'address' },
    { name: 'expectedVkey', type: 'bytes32' }, { name: 'publicValues', type: 'bytes' },
    { name: 'proofBytes', type: 'bytes' }, { name: 'prevRegistrationIndex', type: 'uint256' },
  ], outputs: [],
}];
const SUBMIT_6 = [{
  name: 'submitMerkleRootWithProof', type: 'function', stateMutability: 'nonpayable',
  inputs: [
    { name: 'blockNum', type: 'uint256' }, { name: 'root', type: 'bytes32' },
    { name: 'expectedVerifier', type: 'address' }, { name: 'expectedVkey', type: 'bytes32' },
    { name: 'publicValues', type: 'bytes' }, { name: 'proofBytes', type: 'bytes' },
  ], outputs: [],
}];

const ROOT = `0x${'11'.repeat(32)}`;
const VKEY = `0x${'22'.repeat(32)}`;
const VERIFIER = `0x${'33'.repeat(20)}`;
const submitCalldata = (index) => encodeFunctionData({
  abi: SUBMIT_7, functionName: 'submitMerkleRootWithProof',
  args: [7n, ROOT, VERIFIER, VKEY, '0xaa', '0xbb', index],
});

ok('decodeProofPrevRegistrationIndex が submitMerkleRootWithProof の第7引数を読む',
  (() => {
    const out = decodeProofPrevRegistrationIndex(submitCalldata(3n));
    return out.ok === true && out.functionName === 'submitMerkleRootWithProof'
      && out.prevRegistrationIndex === 3n;
  })());

ok('decodeProofPrevRegistrationIndex が attachProofToMerkleRoot の第6引数を読む',
  (() => {
    const out = decodeProofPrevRegistrationIndex(encodeFunctionData({
      abi: ATTACH_7, functionName: 'attachProofToMerkleRoot',
      args: [7n, VERIFIER, VKEY, '0xaa', '0xbb', PREV_REGISTRATION_SENTINEL],
    }));
    return out.ok === true && out.functionName === 'attachProofToMerkleRoot'
      && out.prevRegistrationIndex === PREV_REGISTRATION_SENTINEL;
  })());

ok('第7引数の無い旧6引数 calldata は 0 を返さず ok:false になる',
  (() => {
    const out = decodeProofPrevRegistrationIndex(encodeFunctionData({
      abi: SUBMIT_6, functionName: 'submitMerkleRootWithProof',
      args: [7n, ROOT, VERIFIER, VKEY, '0xaa', '0xbb'],
    }));
    return out.ok === false && out.reason === 'calldata_without_prev_registration_index'
      && out.prevRegistrationIndex === undefined;
  })());

// 🔴 この検査は正典の共有 ABI（zkp-pipeline.mjs の TOKEN_MINING_ABI）で calldata を復号する。
//    共有 ABI が第7引数を落としたらこの2件が赤になり、検査が黙って skip へ落ちたことが分かる。
ok('共有 TOKEN_MINING_ABI は両関数の最後の入力として prevRegistrationIndex(uint256) を宣言している',
  ['submitMerkleRootWithProof', 'attachProofToMerkleRoot'].every((name) => {
    const item = CANON_TOKEN_MINING_ABI.find((entry) => entry.name === name);
    const last = item?.inputs?.[item.inputs.length - 1];
    return last?.name === 'prevRegistrationIndex' && last?.type === 'uint256';
  }),
  JSON.stringify(CANON_TOKEN_MINING_ABI
    .filter((entry) => ['submitMerkleRootWithProof', 'attachProofToMerkleRoot'].includes(entry.name))
    .map((entry) => entry.inputs.map((input) => input.name))));

ok('番兵は正典（zkp-pipeline.mjs）の PREV_REGISTRATION_SENTINEL と type(uint256).max に一致する',
  PREV_REGISTRATION_SENTINEL === CANON_SENTINEL
  && PREV_REGISTRATION_SENTINEL === (1n << 256n) - 1n,
  JSON.stringify({ mine: String(PREV_REGISTRATION_SENTINEL), canon: String(CANON_SENTINEL) }));

// ------------------------------------------------------------------
// 2) 見張り役の書き出しの読み取り
// ------------------------------------------------------------------
const snapshot = (readAt, hash, updated, count) => ({
  blockNum: 6, status: 'ok', readAt, observedBlock: 900,
  resultRegistrationCount: count,
  resultHash: hash == null ? null : { hash, updated, signer: `0x${'44'.repeat(20)}` },
});
const HONEST = `0x${'ab'.repeat(32)}`;
const LATER = `0x${'cd'.repeat(32)}`;

ok('collectObserverChainSnapshots は run manifest の chainSnapshots を取り出し、壊れた行を rejected に残す',
  (() => {
    const out = collectObserverChainSnapshots([
      { runId: 'r1', chainSnapshots: [snapshot('2026-09-01T00:00:00.000Z', HONEST, 100, 1), null] },
      { runId: 'r2', notAManifest: true },
    ]);
    return out.manifestCount === 1 && out.snapshots.length === 1
      && out.snapshots[0].runId === 'r1'
      && out.snapshots[0].resultHash.hash === HONEST
      && out.rejected.length === 2
      && out.rejected.some((row) => row.reason === 'no_chainSnapshots_array')
      && out.rejected.some((row) => row.reason === 'not_an_object');
  })());

ok('readObserverChainSnapshots は未設定を not_configured で返し、黙って空の成功にしない',
  (() => {
    const out = readObserverChainSnapshots(null);
    return out.ok === false && out.reason === 'not_configured' && out.snapshots.length === 0;
  })());

const manifestDir = join(dir, 'runs');
mkdirSync(manifestDir, { recursive: true });
writeFileSync(join(manifestDir, '000001.json'), JSON.stringify({
  runId: 'r1',
  chainSnapshots: [
    snapshot('2026-09-01T00:00:00.000Z', HONEST, 100, 1),
    { blockNum: 7, status: 'ok', readAt: '2026-09-01T00:00:00.000Z', resultHash: null },
  ],
}));
writeFileSync(join(manifestDir, '000002.json'), JSON.stringify({
  runId: 'r2',
  chainSnapshots: [snapshot('2026-09-03T00:00:00.000Z', LATER, 300, 2)],
}));
writeFileSync(join(manifestDir, 'broken.json'), '{not json');

ok('readObserverChainSnapshots はディレクトリの *.json を全部読み、壊れたファイルを rejected に残す',
  (() => {
    const out = readObserverChainSnapshots(manifestDir);
    return out.ok === true && out.manifestCount === 2 && out.files.length === 3
      && out.snapshots.length === 3
      && out.rejected.some((row) => String(row.reason).startsWith('parse_failed'));
  })());

// ------------------------------------------------------------------
// 3) 証人の選び方
// ------------------------------------------------------------------
const ENTRY_END_MS = Date.parse('2026-09-01T12:00:00.000Z');
const DEADLINE_MS = Date.parse('2026-09-02T00:00:00.000Z');
const snapshots = collectObserverChainSnapshots([{
  runId: 'r', chainSnapshots: [
    snapshot('2026-09-01T00:00:00.000Z', HONEST, 100, 1),
    snapshot('2026-09-01T23:30:00.000Z', HONEST, 100, 1),
    snapshot('2026-09-03T00:00:00.000Z', LATER, 300, 2),
  ],
}]).snapshots;

ok('selectObserverResultWitness はグループ分け締切以前の最後の記録を選び、締切後の記録を採らない',
  (() => {
    const out = selectObserverResultWitness({
      snapshots, prevBlockNum: 6, entryEndMs: ENTRY_END_MS, groupingDeadlineMs: DEADLINE_MS,
    });
    return out.ok === true
      && out.witness.readAt === '2026-09-01T23:30:00.000Z'
      && out.witness.resultHash.hash === HONEST
      && out.consideredCount === 3 && out.eligibleCount === 2
      && out.inGraceWindowCount === 1 && out.distinctHashesInGraceWindow === 1;
  })());

ok('締切以前の記録が1件も無ければ no_snapshot_at_or_before_grouping_deadline で ok:false',
  (() => {
    const out = selectObserverResultWitness({
      snapshots, prevBlockNum: 6, entryEndMs: ENTRY_END_MS,
      groupingDeadlineMs: Date.parse('2026-08-01T00:00:00.000Z'),
    });
    return out.ok === false && out.reason === 'no_snapshot_at_or_before_grouping_deadline'
      && out.witness === null;
  })());

// ------------------------------------------------------------------
// 4) 判定（pass / warn / 番兵）
// ------------------------------------------------------------------
const history = {
  count: 2,
  rows: [
    { index: 0, hash: HONEST, registeredBlock: 100, registeredAt: 1_756_000_000, signer: `0x${'44'.repeat(20)}` },
    { index: 1, hash: LATER, registeredBlock: 300, registeredAt: 1_757_000_000, signer: `0x${'44'.repeat(20)}` },
  ],
};
const witnessAtGrouping = {
  readAt: '2026-09-01T23:30:00.000Z', observedBlock: 900,
  resultRegistrationCount: 1, resultHash: { hash: HONEST, updated: 100, signer: `0x${'44'.repeat(20)}` },
};

ok('judgePrevRegistrationWitness はグループ分け時点の現在値と同じ行を名乗った証明を pass にする',
  (() => {
    const out = judgePrevRegistrationWitness({ claimedIndex: 0n, history, witness: witnessAtGrouping });
    return out.status === 'pass' && out.mismatches.length === 0 && out.claimedRow.index === 0;
  })());

ok('judgePrevRegistrationWitness は後から積まれた行を名乗った証明を warn にする（fail にしない）',
  (() => {
    const out = judgePrevRegistrationWitness({ claimedIndex: 1n, history, witness: witnessAtGrouping });
    return out.status === 'warn' && out.mismatches.length === 2
      && out.mismatches.some((m) => m.includes('!= the value current at grouping time'))
      && out.mismatches.some((m) => m.includes('registeredBlock 300'));
  })());

ok('judgePrevRegistrationWitness は履歴の外の添字を warn にする',
  (() => {
    const out = judgePrevRegistrationWitness({ claimedIndex: 9n, history, witness: witnessAtGrouping });
    return out.status === 'warn' && out.claimedRow === null
      && out.mismatches[0].includes('outside the chain history');
  })());

ok('番兵は履歴0件かつ見張り役も0件のときだけ pass',
  (() => {
    const out = judgePrevRegistrationWitness({
      claimedIndex: PREV_REGISTRATION_SENTINEL,
      history: { count: 0, rows: [] },
      witness: { resultRegistrationCount: 0, resultHash: null, readAt: 'x' },
    });
    return out.status === 'pass' && out.sentinel === true && out.mismatches.length === 0;
  })());

ok('番兵なのに見張り役が登録を記録していれば warn',
  (() => {
    const out = judgePrevRegistrationWitness({
      claimedIndex: PREV_REGISTRATION_SENTINEL, history, witness: witnessAtGrouping,
    });
    return out.status === 'warn' && out.sentinel === true && out.mismatches.length === 3;
  })());

ok('locateCurrentResultRow は現在値がどの行かを名指すが、選び方は現在値のまま',
  (() => {
    const out = locateCurrentResultRow(history, { hash: HONEST, updated: 100 });
    return out.currentIndex === 0 && out.latestIndex === 1 && out.registrationCount === 2
      && out.selectionRule === 'HashStorage.getResultHash current value (unchanged)';
  })());

// ------------------------------------------------------------------
// 5) 検査本体の3方向（warn / pass / skip）
// ------------------------------------------------------------------
function makeCtx({ observerManifest, claimedIndex, historyRows, txThrows = false }) {
  const report = createReport();
  return {
    report,
    blockNum: 7,
    cfg: { observerManifest },
    chain: {
      client: {
        getTransaction: async () => {
          if (txThrows) throw new Error('rpc refused');
          return { input: submitCalldata(claimedIndex) };
        },
      },
      resultRegistrationHistory: async () => ({
        count: historyRows.length, rows: historyRows,
      }),
      getTimingConstants: async () => ({
        // 応募終了 = START_TIME + (N+1)*BLOCK_TIME = ENTRY_END_MS
        startTimeEntryMs: ENTRY_END_MS - 8 * 86_400_000,
        blockTimeMs: 86_400_000,
        gamePeriodMs: 86_400_000,
      }),
      // grace 12h → chattingStart = ENTRY_END_MS + 12h = DEADLINE_MS
      currentGrace: async () => 43_200,
    },
  };
}
const S = {};
const witnessManifest = join(dir, 'witness.json');
writeFileSync(witnessManifest, JSON.stringify({
  runId: 'r',
  // 🔴 統括（2026-09-22）: 判定の時刻基準は grace ではなく**観測された事実**である。
  //    見張り役が N のグループ分け成果物を最初に見た時刻（firstSeenAt）を締切にする。
  //    grace は admin が最大4日動かせるので基準にならない（契約側のカット規則を外したのと同じ理由）。
  records: [
    { key: 'entries/block7/game_groups.json', blockNum: 7, firstSeenAt: '2026-09-02T00:00:00.000Z' },
  ],
  chainSnapshots: [
    snapshot('2026-09-01T23:30:00.000Z', HONEST, 100, 1),
    snapshot('2026-09-03T00:00:00.000Z', LATER, 300, 2),
  ],
}));
// 観測記録が無い書き出し（＝判定できないので skip になることを測る）
const witnessNoObs = join(dir, 'witness-no-observation.json');
writeFileSync(witnessNoObs, JSON.stringify({
  runId: 'r', chainSnapshots: [snapshot('2026-09-01T23:30:00.000Z', HONEST, 100, 1)],
}));

{
  const ctx = makeCtx({ observerManifest: witnessManifest, claimedIndex: 0n, historyRows: history.rows });
  await verifyPrevRegistrationWitness(ctx, S, { txHash: `0x${'99'.repeat(32)}` });
  const entry = ctx.report.get(CHECK_ID);
  ok('検査本体: グループ分け時点の現在値の行を名乗った証明は pass',
    entry?.status === 'pass' && entry.params.claimedIndex === '0'
      && entry.params.witnessReadAt === '2026-09-01T23:30:00.000Z'
      && entry.params.snapshotsAtOrBeforeGrouping === 1,
    JSON.stringify(entry));
}

{
  const ctx = makeCtx({ observerManifest: witnessManifest, claimedIndex: 1n, historyRows: history.rows });
  await verifyPrevRegistrationWitness(ctx, S, { txHash: `0x${'99'.repeat(32)}` });
  const entry = ctx.report.get(CHECK_ID);
  ok('検査本体: グループ分けの後に積まれた行を名乗った証明は warn（fail ではない）',
    entry?.status === 'warn' && entry.params.claimedIndex === '1'
      && Array.isArray(entry.params.mismatches) && entry.params.mismatches.length === 2,
    JSON.stringify(entry));
}

{
  let outerTransactionReads = 0;
  const ctx = makeCtx({ observerManifest: witnessManifest, claimedIndex: 0n, historyRows: history.rows });
  ctx.chain.client.getTransaction = async () => {
    outerTransactionReads++;
    throw new Error('outer relay calldata must not be decoded by the witness');
  };
  await verifyPrevRegistrationWitness(
    ctx,
    S,
    { txHash: `0x${'99'.repeat(32)}` },
    {
      route: 'internal',
      prevRegistrationIndex: 1n,
      call: { functionName: 'attachProofToMerkleRoot' },
    },
  );
  const entry = ctx.report.get(CHECK_ID);
  ok('P8b U-6: 中継証明の証人は外側tx.inputを再読せず、P8aが解決した内側prevRegistrationIndexを使う',
    outerTransactionReads === 0
      && entry?.status === 'warn'
      && entry.params.claimedIndex === '1',
    JSON.stringify({ outerTransactionReads, entry }));
}

{
  const ctx = makeCtx({ observerManifest: null, claimedIndex: 0n, historyRows: history.rows });
  await verifyPrevRegistrationWitness(ctx, S, { txHash: `0x${'99'.repeat(32)}` });
  const entry = ctx.report.get(CHECK_ID);
  ok('検査本体: 見張り役の記録が無いときは skip で、読めなかったことを params に残す',
    entry?.status === 'skip' && entry.params.reason === 'observer_record_unavailable'
      && entry.params.observerReason === 'not_configured'
      && entry.params.observerPath === null
      && entry.params.claimedIndex === '0',
    JSON.stringify(entry));
}

{
  const stale = join(dir, 'stale.json');
  writeFileSync(stale, JSON.stringify({
    runId: 'r',
    records: [
      { key: 'entries/block7/game_groups.json', blockNum: 7, firstSeenAt: '2026-09-02T00:00:00.000Z' },
    ],
    chainSnapshots: [snapshot('2026-09-03T00:00:00.000Z', LATER, 300, 2)],
  }));
  const ctx = makeCtx({ observerManifest: stale, claimedIndex: 0n, historyRows: history.rows });
  await verifyPrevRegistrationWitness(ctx, S, { txHash: `0x${'99'.repeat(32)}` });
  const entry = ctx.report.get(CHECK_ID);
  ok('検査本体: 締切以前の記録が無いときも skip で、理由を params に残す',
    entry?.status === 'skip' && entry.params.reason === 'observer_record_unavailable'
      && entry.params.observerReason === 'no_snapshot_at_or_before_grouping_deadline'
      && entry.params.snapshotsAtOrBeforeGrouping === 0,
    JSON.stringify(entry));
}

{
  // 観測記録が無いときは grace で代用せず skip する。
  const ctx = makeCtx({ observerManifest: witnessNoObs, claimedIndex: 0n, historyRows: history.rows });
  await verifyPrevRegistrationWitness(ctx, S, { txHash: `0x${'99'.repeat(32)}` });
  const entry = ctx.report.get(CHECK_ID);
  ok('検査本体: グループ分けの観測記録が無いときは grace で代用せず skip する',
    entry?.status === 'skip' && entry.params.reason === 'grouping_observation_unavailable',
    JSON.stringify(entry));
}

for (const getter of ['getTimingConstants', 'currentGrace']) {
  const ctx = makeCtx({ observerManifest: witnessManifest, claimedIndex: 0n, historyRows: history.rows });
  ctx.chain[getter] = async () => { throw new Error(`P14 ${getter} unavailable`); };
  await verifyPrevRegistrationWitness(ctx, S, { txHash: `0x${'99'.repeat(32)}` });
  const entry = ctx.report.get(CHECK_ID);
  ok(`P14: ${getter} の読取失敗は起点どおり grouping_deadline_unavailable で skip`,
    entry?.status === 'skip' && entry.params.reason === 'grouping_deadline_unavailable'
      && String(entry.params.error).includes(`P14 ${getter} unavailable`), JSON.stringify(entry));
}

{
  const ctx = makeCtx({ observerManifest: witnessManifest, claimedIndex: 0n, historyRows: history.rows });
  let calls = 0;
  ctx.chain.currentGrace = async () => { calls++; throw new Error('currentGrace unavailable'); };
  const window = { chatCloseAt: Math.round(ENTRY_END_MS / 1000) + 43_200 + 86_400 };
  await verifyPrevRegistrationWitness(ctx, { chatWindow: window },
    { txHash: `0x${'99'.repeat(32)}` });
  const entry = ctx.report.get(CHECK_ID);
  ok('R32-D-1-02: 宣言chatWindowがある証人はcurrentGrace障害でも判定を続ける',
    entry?.status !== 'skip' && calls === 0, JSON.stringify({ entry, calls }));
}

{
  const ctx = makeCtx({
    observerManifest: witnessManifest, claimedIndex: 0n, historyRows: history.rows, txThrows: true,
  });
  await verifyPrevRegistrationWitness(ctx, S, { txHash: `0x${'99'.repeat(32)}` });
  const entry = ctx.report.get(CHECK_ID);
  ok('検査本体: 提出 tx が読めないときは skip（pass にしない）',
    entry?.status === 'skip' && entry.params.reason === 'proof_tx_unavailable', JSON.stringify(entry));
}

{
  const ctx = makeCtx({ observerManifest: witnessManifest, claimedIndex: 0n, historyRows: history.rows });
  ctx.blockNum = 0;
  await verifyPrevRegistrationWitness(ctx, S, { txHash: `0x${'99'.repeat(32)}` });
  const entry = ctx.report.get(CHECK_ID);
  ok('検査本体: ブロック0は前ブロックが無いので skip',
    entry?.status === 'skip' && entry.params.reason === 'no_previous_block', JSON.stringify(entry));
}

// ------------------------------------------------------------------
// 6) 既存の判定・結論を動かしていないこと
// ------------------------------------------------------------------
ok('新しい検査 ID は CHECK_INVENTORY に在る', CHECK_INVENTORY.includes(CHECK_ID));

for (const lang of SUPPORTED_LANGS) {
  const translate = t(lang);
  const text = translate(CHECK_ID, {
    claimedIndex: '1', registrationCount: 2, witnessReadAt: 'X', groupingDeadlineIso: 'Y', mismatches: 'Z',
  });
  ok(`${lang}: 新しい検査の文言が用意されていて、キー名のまま出ない`,
    text !== CHECK_ID && !text.includes('{claimedIndex}') && text.includes('1'));
}

{
  // 通常モードの結論は warn では動かない（fail だけが止める）。
  const report = createReport();
  for (const id of CHECK_INVENTORY) report.check(id, 'pass');
  report.check('check.stageA.registrationCount', 'pass', { count: 1 });
  report.check(CHECK_ID, 'warn', { mismatches: ['x'] });
  for (const [name, value] of [
    ['hashRegisteredTime', '2026-09-04T00:00:00.000Z'], ['totalEntries', 4], ['applicantHash', '0xabc'],
    ['hashRegisteredBlock', 100], ['totalSelected', 4], ['targetBlockNum', 123],
    ['targetBlockTime', '2026-09-05T00:00:00.000Z'], ['totalGroups', 1],
    ['stageC.blockReward', '1000000000000000000'], ['stageC.playerCount', 4],
    ['stageC.groupCount', 1], ['stageC.disqualifiedCount', 0],
    ['stageC.verificationStartedAt', { iso: '2026-09-05T01:00:00.000Z' }],
    ['stageC.verificationEndsAt', { iso: '2026-09-09T01:00:00.000Z' }],
    ['stageC.claimWindow', { endIso: '2026-10-19T01:00:00.000Z' }],
  ]) report.fact(name, value);
  const translate = t('en');
  const lines = [];
  report.renderSummary({ t: translate, println: (line = '') => lines.push(String(line)) },
    { blockNum: 7, data: {}, r2: { baseDir: '/tmp/block7' } });
  const rendered = lines.join('\n');
  ok('新しい検査が warn でも①②③の結論は従来どおり出る（止めるのではなく見せる）',
    rendered.includes(translate('conclusion.entries', {
      block: 7, time: '2026-09-04T00:00:00.000Z', total: 4, hash: '0xabc', ethBlock: 100, folder: '/tmp/block7',
    }))
    && rendered.includes(translate('conclusion.selection', {
      block: 7, selected: 4, total: 4, targetBlock: 123,
      time: '2026-09-05T00:00:00.000Z', groups: 1, count: 1,
    }))
    && rendered.includes(translate('conclusion.results', {
      block: 7, reward: '1.00', players: 4, groups: 1, dq: 0,
      rootTime: '2026-09-05T01:00:00.000Z', verEnd: '2026-09-09T01:00:00.000Z',
      claimEnd: '2026-10-19T01:00:00.000Z',
    })));
}

// ------------------------------------------------------------------
// 6b) 配線そのもの: kind='proof' を verifyZkpSubmission へ実際に通し、
//     reportへ検査が載ること／証明が無い3経路でも必ず記録されること。
//     🔴 ソース本文grepでは呼出しを不到達にする変異を捕まえられないため、実行結果だけを見る。
// ------------------------------------------------------------------
{
  const ctx = makeCtx({
    observerManifest: witnessManifest, claimedIndex: 0n, historyRows: history.rows,
  });
  ctx.cfg = { observerManifest: witnessManifest, r2Base: 'https://mock.invalid', pins: { confirmationBlocks: 64 } };
  ctx.chain.contracts = { tokenMining: `0x${'55'.repeat(20)}` };
  ctx.chain.rpcUrl = 'https://rpc.invalid';
  const proofS = {
    zkInfo: {
      kind: 'proof', currentProofRequired: true,
      epoch: { index: 0, verifier: VERIFIER, vkey: VKEY, guestSourceHash: `0x${'66'.repeat(32)}` },
    },
    files: {
      summary: { data: {}, raw: '{}' },
      manifest: { data: { files: {} }, raw: '{}' },
      merkle: null, selection: null, stage3Manifest: null,
    },
    rebuiltSummary: null,
    blockState: { root: ROOT },
    anomalies: [],
  };
  await verifyZkpSubmission(ctx, proofS, { txHash: `0x${'99'.repeat(32)}` });
  const entry = ctx.report.get(CHECK_ID);
  ok("verifyZkpSubmission は kind='proof' の実行経路でcheck.stageC.zkPrevRegistrationWitnessをreportへ載せる",
    entry?.status === 'pass' && entry.params.claimedIndex === '0'
      && entry.params.witnessHash === HONEST,
    JSON.stringify(entry));
}

for (const [label, zkInfo, expectedReason] of [
  ['shadow', { kind: 'shadow', currentProofRequired: false }, 'shadow_no_proof'],
  ['no_root', { kind: 'no_root', currentProofRequired: false }, 'no_root'],
  ['unavailable', { kind: 'unavailable', currentProofRequired: false, error: 'x' }, 'zk_state_unavailable'],
]) {
  const report = createReport();
  recordZkpState({ report }, { anomalies: [], timelineNoGame: false }, zkInfo);
  const entry = report.get(CHECK_ID);
  ok(`証明が無い経路 ${label} でも新しい検査は skip として必ず記録される`,
    entry?.status === 'skip' && entry.params.reason === expectedReason, JSON.stringify(entry));
  const identity = report.get('check.stageC.zkVerifierIdentity');
  ok(`verifierの照合も ${label} では同じ理由のskip`,
    identity?.status === 'skip' && identity.params.reason === expectedReason, JSON.stringify(identity));
}

// ------------------------------------------------------------------
// 7) --observer-manifest の配線（渡さなければ null ＝ 検査は skip へ落ちる）
// ------------------------------------------------------------------
{
  const { loadConfig } = await import('../src/config.js');
  ok('--observer-manifest を渡さなければ cfg.observerManifest は null のまま',
    loadConfig([]).observerManifest === null);
  ok('--observer-manifest FILE は cwd 基準の絶対パスへ解決される',
    loadConfig(['--observer-manifest', 'runs/000001.json']).observerManifest
      === join(process.cwd(), 'runs/000001.json'));
  ok('--observer-manifest=FILE の等号形も同じ絶対パスへ解決される',
    loadConfig(['--observer-manifest=runs/000001.json']).observerManifest
      === join(process.cwd(), 'runs/000001.json'));
}

rmSync(dir, { recursive: true, force: true });
if (p8bMutationRoot) await fs.rm(p8bMutationRoot, { recursive: true, force: true });

console.log(`\nR29 prev-registration witness unit: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);

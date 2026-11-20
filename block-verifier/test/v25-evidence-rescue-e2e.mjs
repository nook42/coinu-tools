// V25-03: ChatGameDO/R2 cacheを失っても、正式Evidenceから通常採点・BTCu配分・
// Merkle提出まで完走し、さらにgroup archiveが配信不能でも第三者検証器が
// on-chain commitmentと同じ結果を独立再現できることを固定するE2E。
// C の原像である公開 roster group は残し、失う cache は index に限定する。
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  DEFAULT_SCENARIO,
  generateFixture,
  verifyFixtureInternalConsistency,
} from './gen-fixture.mjs';
import { runTool, writeToolConfig } from './e2e.mjs';
import { startR2Server } from './r2-server.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
const outDir = resolve(process.env.V25_RESCUE_OUT_DIR || resolve(__dir, 'out/v25-evidence-rescue'));
const CHAIN_PORT = Number(process.env.V25_RESCUE_CHAIN_PORT || 8563);
const R2_PORT = Number(process.env.V25_RESCUE_R2_PORT || 8793);

let fixture = null;
let server = null;
let failed = false;

function check(value, label) {
  console.log(`  ${value ? 'ok' : 'NG'}: ${label}`);
  if (!value) failed = true;
}

try {
  const scenario = {
    name: 'v25-evidence-rescue',
    blockNum: 0,
    players: DEFAULT_SCENARIO.players,
    externalDepositors: DEFAULT_SCENARIO.externalDepositors,
    evidenceRescue: true,
    // グループごとに1人だけを正式Evidenceへ載せる。残りはDO消失後にno_submitとなり、
    // 「提出者だけ救済」ではなく全rosterを通常規則で集計する境界を同時に検査する。
    gamePlan(groupRows) {
      const submitters = groupRows.map((g) => g.members[0].uid);
      return {
        evidence: {
          chain: submitters,
          censorServer: submitters,
          tamperServer: [],
          garbage: 0,
        },
      };
    },
  };

  console.log('V25-03 E2E step 1: production pipeline with ChatGameDO loss');
  fixture = await generateFixture({ port: CHAIN_PORT, outDir, scenario });

  const consistency = await verifyFixtureInternalConsistency({
    r2Dir: fixture.r2Dir,
    chainInfo: fixture.chainInfo,
  });
  check(consistency.passed, 'generated rescue result is internally consistent with local chain');

  const info = fixture.chainInfo;
  const rosterManifest = JSON.parse(readFileSync(join(fixture.r2Dir,
    'games/block0/roster/manifest.json'), 'utf8'));
  check(rosterManifest.groups.length === info.groups.length
    && rosterManifest.groups.every((group) => existsSync(join(fixture.r2Dir,
      `games/block0/roster/group${group.groupId}.json`))),
  'every C-committed roster group remains publicly readable after the DO loss');
  const rescuedUids = info.meta.evidence.missing;
  const summary = JSON.parse(readFileSync(join(fixture.r2Dir, 'games/block0/summary.json'), 'utf8'));
  const merkle = JSON.parse(readFileSync(join(fixture.r2Dir, 'merkle/block_0.json'), 'utf8'));
  const allMembers = summary.groups.flatMap((g) => g.members);
  for (const uid of rescuedUids) {
    const member = allMembers.find((m) => m.userId === uid);
    check(member && member.is_disqualified === 0, `formal Evidence submitter ${uid} remains eligible`);
    check(member && BigInt(member.full_btcu_reward) > 0n, `formal Evidence submitter ${uid} receives BTCu`);
  }
  const noSubmitMembers = allMembers.filter((m) => !rescuedUids.includes(m.userId));
  check(noSubmitMembers.length > 0, 'committed roster includes members without formal Evidence');
  check(noSubmitMembers.every((m) => m.is_disqualified === 1 && BigInt(m.full_btcu_reward) === 0n),
    'members without formal Evidence are disqualified with zero player reward');
  check(merkle.leafCount > 0 && BigInt(merkle.totalAmount) > 0n,
    'normal non-empty Merkle allocation is generated and submitted');
  check(!existsSync(join(fixture.r2Dir, 'games/block0/roster/index.json')),
    'roster cache is absent during aggregation');

  const noSubmitReasons = new Map();
  for (const group of info.groups) {
    const key = join(fixture.r2Dir, `games/block0/group${group.groupId}.json`);
    const archive = JSON.parse(readFileSync(key, 'utf8'));
    check(archive.evidenceRescue?.schemaVersion === 1,
      `group${group.groupId} was reconstructed from committed grouping`);
    for (const row of (archive.gameResults || [])) {
      if (row.role === 'player' && !rescuedUids.includes(row.userId)) {
        noSubmitReasons.set(row.userId, row.disqualify_reason || '');
      }
    }
    // 集計後の配信障害も再現する。manifestは既に元bytesをcommit済みなので、
    // verifierはavailabilityを警告しつつEvidence＋commitから同じ結果を再計算する。
    rmSync(key, { force: true });
  }
  check(noSubmitMembers.every((m) => noSubmitReasons.get(m.userId)?.split(',').includes('no_submit')),
    'group detail records the normal no_submit reason for every non-Evidence member');

  console.log('V25-03 E2E step 2: verifier reconstruction without group archives/roster index cache');
  server = await startR2Server({ rootDir: fixture.r2Dir, port: R2_PORT });
  const configPath = writeToolConfig({
    outDir,
    chainInfo: info,
    r2BaseUrl: server.baseUrl,
    dataDir: join(outDir, 'verifier-data'),
  });
  const run = await runTool({ configPath, blockNum: 0 });
  if (run.stdout) console.log(run.stdout);
  if (run.stderr) console.error(run.stderr);
  check(run.code === 0, `verifier exits 0 after independent rescue replay (got ${run.code})`);
  check(run.stdout.includes('##RESULT full'), 'verifier reports a full verification');
  check(run.stdout.includes('##CHECK check.stageC.summaryMatch pass'), 'verifier reproduces summary');
  check(run.stdout.includes('##CHECK check.stageC.merkleRoot pass'), 'verifier reproduces on-chain Merkle root');
  check(run.stdout.includes('##CHECK check.stageC.manifestFiles warn'),
    'unavailable reconstructible archives are surfaced as an availability warning');
} catch (error) {
  failed = true;
  console.error(error?.stack || error);
} finally {
  try { server?.stop(); } catch {}
  try { fixture?.stop(); } catch {}
}

console.log(failed ? 'V25-03 evidence rescue E2E: FAIL' : 'V25-03 evidence rescue E2E: PASS');
process.exit(failed ? 1 : 0);

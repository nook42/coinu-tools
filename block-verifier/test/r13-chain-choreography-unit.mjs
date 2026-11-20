// Round 13 C8-01: chain fixture の時刻振り付けを、TCP listenerなしで固定する回帰単体。
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { keccak256, stringToHex } from 'viem';
import { TIMING, timingDerived } from './chain-setup.mjs';
import {
  DEFAULT_MUTATION_R2_PORT,
  mutationR2PortForCase,
  reanchorManifest,
} from './mutations.mjs';
import { inspectResultManifestAnchor, inspectRosterAnchor } from '../src/stages/results.js';

let failed = 0;
const ok = (condition, label) => {
  if (condition) console.log(`ok: ${label}`);
  else { console.error(`NG: ${label}`); failed++ }
};

// 通常anchorは applicant hash後の64確認＋後続処理を見込んでも宣言開始前。
const D = timingDerived(TIMING, 0);
const rosterRaw = JSON.stringify({ blockNum: 0, groups: [] });
const rosterResult = await inspectRosterAnchor({
  async getOtherHash() {
    return { hash: keccak256(stringToHex(rosterRaw)), updated: 95 };
  },
  async getBlock() { return { timestamp: BigInt(D.entryEnd + 68) }; },
}, {
  key: keccak256(stringToHex('bitcoinu:roster:0')),
  raw: rosterRaw,
  chattingStartMs: D.chattingStart * 1000,
});
ok(TIMING.GRACE === 120, 'fixture grace は120秒');
ok(TIMING.GAME_PERIOD + TIMING.SUBMIT_PERIOD + TIMING.GRACE <= TIMING.BLOCK_TIME,
  'Evidence の期間不変量を維持');
ok(rosterResult.failures.length === 0, '通常roster anchorはchattingStartより前');
ok(DEFAULT_MUTATION_R2_PORT === 0
  && mutationR2PortForCase(DEFAULT_MUTATION_R2_PORT, 0) === 0
  && mutationR2PortForCase(DEFAULT_MUTATION_R2_PORT, 24) === 0,
'mutations既定R2 portは全caseでOS採番（並列suiteと固定port衝突しない）');
ok(mutationR2PortForCase(9000, 3) === 9003,
'明示R2 port指定時だけ従来のcase offsetを維持');

// reanchorManifest 本体を依存注入で実行し、anchor→1秒後root再提出→confirmations の順を固定。
const dir = mkdtempSync(join(tmpdir(), 'bitcoinu-r13-choreography-'));
try {
  const manifestDir = join(dir, 'verification/block0');
  mkdirSync(manifestDir, { recursive: true });
  writeFileSync(join(manifestDir, 'manifest.json'), JSON.stringify({
    blockNum: 0,
    algorithm: 'sha256',
    rules: {},
    files: {},
    manifestHash: '0x' + '00'.repeat(32),
  }));

  const calls = [];
  const anchorTimestamp = 1798762400;
  const chainInfo = {
    blockNum: 0,
    rpcUrl: 'http://127.0.0.1:8547',
    merkleRoot: '0x' + '34'.repeat(32),
    contracts: {
      hashStorage: '0x' + '11'.repeat(20),
      tokenMining: '0x' + '22'.repeat(20),
    },
  };
  let computedManifestHash = null;
  await reanchorManifest(dir, chainInfo, {
    makeClientsFn() {
      return {
        account: { address: '0x' + '33'.repeat(20) },
        publicClient: {
          async getBlock() { return { timestamp: BigInt(anchorTimestamp) }; },
        },
      };
    },
    async writeFn(_clients, _contract, functionName, args) {
      calls.push(functionName);
      if (functionName === 'registerResultHash') {
        computedManifestHash = args[1];
        return { blockNumber: 123n };
      }
      ok(args[1] === chainInfo.merkleRoot, 'root再提出はgreen fixtureと同じ正規root');
      return { blockNumber: 124n };
    },
    async setNextTimestampFn(_rpcUrl, timestamp) { calls.push(`timestamp:${timestamp}`); },
    async mineManyFn(_rpcUrl, count, interval) { calls.push(`mine:${count}:${interval}`); },
  });

  ok(JSON.stringify(calls) === JSON.stringify([
    'registerResultHash',
    `timestamp:${anchorTimestamp + 1}`,
    'submitMerkleRoot',
    `mine:${TIMING.CONFIRMATION_BLOCKS + 2}:1`,
  ]), 'manifest anchor→root時計更新→確認採掘の順序');

  const rootClockRefreshed = calls.includes('submitMerkleRoot');
  const verificationStartedAt = rootClockRefreshed ? anchorTimestamp + 1 : anchorTimestamp - 100;
  const anchorInspection = await inspectResultManifestAnchor({
    async getBlock() { return { timestamp: BigInt(anchorTimestamp) }; },
  }, { hash: computedManifestHash, updated: 123 }, computedManifestHash, verificationStartedAt);
  ok(anchorInspection.status === 'pass'
    && anchorInspection.reason === 'anchored_before_root_submission',
  '再アンカーは更新後verificationStartedAtより前としてPASS');
} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log(failed === 0 ? 'r13-chain-choreography-unit: ALL PASSED' : `${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);

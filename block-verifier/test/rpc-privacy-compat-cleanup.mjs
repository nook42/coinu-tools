// compatが失敗する経路でも、既定はOS一時領域を消し、明示時だけ証跡を残す。
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
const script = resolve(process.argv[2] || join(import.meta.dirname, 'rpc-privacy-compat.mjs'));
const work = mkdtempSync(join(tmpdir(), 'rpc-compat-cleanup-test-'));
try {
  for (const retain of [false, true]) {
    const env = { ...process.env, PATH: work };
    delete env.RPC_PRIVACY_EVIDENCE_DIR;
    if (retain) env.RPC_PRIVACY_EVIDENCE_DIR = work;
    const result = spawnSync(process.execPath, [script], { cwd: work, env, encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status, 1, 'gitが無い失敗経路を通す');
    const evidence = result.stdout.match(/^Evidence: (.+)$/m)?.[1];
    assert.ok(evidence, '試験の一時領域を識別する');
    try {
      assert.equal(existsSync(evidence), retain, '既定は失敗時も消し、環境変数の明示時だけ残す');
      assert.ok(evidence.startsWith(resolve(retain ? work : tmpdir()) + '/'), '既定はOS一時領域に書く');
    } finally { rmSync(evidence, { recursive: true, force: true }); }
  }
} finally { rmSync(work, { recursive: true, force: true }); }
console.log('RB-05 compat cleanup: PASS (OS temp, failure cleanup, explicit evidence retention)');

// e2e.mjs — フルパイプライン:
//   ①ローカルチェーン＋フィクスチャ生成（本番コード実行） → ②ハーネス内部整合性検証
//   → ③ローカルR2サーバー起動 → ④検証ツール本体を非対話モードで実行 → exit 0 を PASS 判定
//
//   node block-verifier/test/e2e.mjs [--port 8547] [--r2-port 8788] [--out DIR] [--skip-tool]
//     [--disable-coordinator-alarm]  # 負の対: pendingのまま終了させ、exit 1とintent状態を要求
//
// ツール本体（block-verifier/src/index.js）が未完成の間は ④ を SKIP し、①〜③ のみで
// exit code を決める（ハーネスが今すぐ証明できる範囲）。④ のアサーションは
// 「=== TOOL ASSERTIONS ===」節に隔離してあり、統合者はツール完成後にそのまま回せる。
import { spawn } from 'node:child_process';
import { existsSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateFixture, verifyFixtureInternalConsistency } from './gen-fixture.mjs';
import { startR2Server } from './r2-server.mjs';

const __dir = dirname(fileURLToPath(import.meta.url));
export const TOOL_ENTRY = resolve(__dir, '../src/index.js');

// ツール完成判定: foundation 3点（index/i18n/report）が揃ってから実行する。
// （現時点の src/index.js は旧 p2p-verifier スケルトンで、存在チェックだけだと
//   module-not-found の偽FAILになるため。統合者は --run-tool で強制実行できる）
export function toolLooksComplete() {
  return ['index.js', 'i18n.js', 'report.js']
    .every(f => existsSync(resolve(__dir, '../src', f)));
}

// 検証ツールを非対話モードで1回実行（CONTRACT.md のフラグ仕様）。
// mutations.mjs からも再利用する。
export function runTool({ configPath, blockNum = 0, cwd = resolve(__dir, '..') }) {
  if (process.env.E2E_IN_PROCESS === '1') {
    return import('./fix1-in-process.mjs').then(({ runInProcessTool }) => runInProcessTool({ configPath, blockNum }));
  }
  return new Promise((res) => {
    const proc = spawn(process.execPath, [
      TOOL_ENTRY,
      '--non-interactive', '--lang', 'en', '--block', String(blockNum), '--yes',
      '--config', configPath,
    ], { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    proc.stdout.on('data', d => { stdout += d; });
    proc.stderr.on('data', d => { stderr += d; });
    proc.on('exit', code => res({ code, stdout, stderr }));
  });
}

export function writeToolConfig({ outDir, chainInfo, r2BaseUrl, dataDir }) {
  rmSync(dataDir, { recursive: true, force: true });
  mkdirSync(dataDir, { recursive: true });
  const cfg = {
    chainIdExpected: chainInfo.chainId,
    rpcUrls: [chainInfo.rpcUrl],
    r2Base: r2BaseUrl,
    dataDir,
    contracts: {
      hashStorage: chainInfo.contracts.hashStorage,
      tokenMining: chainInfo.contracts.tokenMining,
      evidence: chainInfo.contracts.evidence,
      ethLock: chainInfo.contracts.ethLock,
      ethStake: chainInfo.contracts.ethStake,
    },
  };
  const p = join(outDir, 'verifier-config.json');
  writeFileSync(p, JSON.stringify(cfg, null, 2));
  return p;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const args = process.argv.slice(2);
  const argOf = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
  const port = parseInt(argOf('--port', '8547'));
  const r2Port = parseInt(argOf('--r2-port', '8788'));
  const outDir = resolve(argOf('--out', resolve(__dir, 'out/fixture')));
  const skipTool = args.includes('--skip-tool');
  const disableCoordinatorAlarm = args.includes('--disable-coordinator-alarm');

  let exitCode = 0;
  let fx = null;
  let r2srv = null;
  try {
    // ── ① フィクスチャ生成（本番コード実行・ローカルチェーンにアンカー） ──
    console.log('═'.repeat(60));
    console.log('E2E step 1: generate fixture (production code, local chain)');
    console.log('═'.repeat(60));
    fx = await generateFixture({
      port,
      outDir,
      scenario: disableCoordinatorAlarm
        ? { name: 'coordinator-alarm-disabled', coordinatorAlarmMode: 'disabled' }
        : null,
    });

    // ── ② ハーネス内部整合性（生成物 ⇔ チェーンの独立照合） ──
    console.log('═'.repeat(60));
    console.log('E2E step 2: internal consistency (files ⇔ chain)');
    console.log('═'.repeat(60));
    const consistency = await verifyFixtureInternalConsistency({ r2Dir: fx.r2Dir, chainInfo: fx.chainInfo });
    if (!consistency.passed) {
      console.error(`internal consistency FAILED: ${consistency.failures.length} failure(s)`);
      exitCode = 1;
    }
    // 追加（生成側の知識を使う byte 照合）: アーカイブの submissionsRaw が
    // クライアントが構築した正規バンドルのバイト列と完全一致すること。
    // 検閲/改ざんされた2名はチェーン版（=同じ正規バイト列）が復元されているはず。
    {
      const { readFileSync } = await import('node:fs');
      for (const uid of [fx.chainInfo.evidence.identicalUid, fx.chainInfo.evidence.censoredUid, fx.chainInfo.evidence.tamperedUid]) {
        const g = fx.chainInfo.groups.find(x => x.memberUids.includes(uid));
        const arch = JSON.parse(readFileSync(join(fx.r2Dir, `games/block0/group${g.groupId}.json`), 'utf8'));
        const same = arch.submissionsRaw?.[uid] === fx.payloads[uid];
        console.log(`  ${same ? 'ok' : 'NG'}: archive submissionsRaw[${uid}] byte-equal to canonical client payload`);
        if (!same) exitCode = 1;
      }
    }

    // ── ③ ローカルR2サーバー ──
    console.log('═'.repeat(60));
    console.log('E2E step 3: local R2 server');
    console.log('═'.repeat(60));
    r2srv = await startR2Server({ rootDir: fx.r2Dir, port: r2Port });
    console.log(`serving fixture R2 at ${r2srv.baseUrl}`);
    // 疎通スモーク: ツールが最初に読む選出ファイル
    const smoke = await fetch(`${r2srv.baseUrl}/entries/block0/game_selection.json`);
    if (!smoke.ok) { console.error('R2 server smoke test failed'); exitCode = 1; }

    // ═════════════════════════════════════════════════════════
    // === TOOL ASSERTIONS ===（検証ツール本体の統合ポイント）
    // ツール（block-verifier/src/index.js）完成後は、この節が本番のE2E判定になる:
    //   green fixture に対して exit 0（全ステージ PASS）を要求する。
    // ツール未完成（エントリ不在）or --skip-tool の間は SKIP（exit code に影響しない）。
    // ═════════════════════════════════════════════════════════
    console.log('═'.repeat(60));
    console.log('E2E step 4: run verifier tool (non-interactive)');
    console.log('═'.repeat(60));
    if (skipTool) {
      console.log('SKIP: --skip-tool specified');
    } else if (!toolLooksComplete() && !args.includes('--run-tool')) {
      console.log(`SKIP: tool not complete yet (need src/{index,i18n,report}.js) — integrator runs this after they land (or force with --run-tool)`);
    } else {
      const configPath = writeToolConfig({
        outDir, chainInfo: fx.chainInfo, r2BaseUrl: r2srv.baseUrl,
        dataDir: join(outDir, 'verifier-data'),
      });
      const run = await runTool({ configPath, blockNum: 0 });
      console.log(run.stdout);
      if (run.stderr) console.error(run.stderr);
      if (run.code !== 0) {
        console.error(`TOOL ASSERTION FAILED: expected exit 0 on green fixture, got ${run.code}`);
        exitCode = 1;
      } else {
        console.log('tool exit 0 on green fixture: OK');
      }
    }
  } catch (e) {
    console.error('E2E fatal:', e);
    exitCode = 1;
  } finally {
    try { r2srv?.stop(); } catch {}
    try { fx?.stop(); } catch {}
  }

  console.log('═'.repeat(60));
  console.log(exitCode === 0 ? 'E2E: PASS' : 'E2E: FAIL');
  console.log('═'.repeat(60));
  process.exit(exitCode);
}

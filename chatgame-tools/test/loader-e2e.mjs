// test/loader-e2e.mjs — ローダーの Hardhat ローカル E2E（buildHash 契約の実登録→照合）
//
// block-verifier のハーネス（chain-setup / r2-server）を再利用。
// ① hardhat node 起動＋一式デプロイ（HashStorage は buildHash API 込み）
// ② 擬似 out/ を生成→ gen-manifest で manifest+buildHash → registerBuildHash 実登録
// ③ ローカル静的サーバーで out/ を配信 → runLoaderVerification が green
// ④ mutation: ファイル改変→FILE_HASH_MISMATCH / manifest改変→MANIFEST_HASH_MISMATCH /
//              未登録→NO_HASH_REGISTERED / 配信欠落→FETCH_FAIL / 再登録→REREGISTERED warn
//
// 実行: node test/loader-e2e.mjs   （##CHECK/##RESULT 形式で機械可読出力）

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startNode, deployContracts, makeClients, write } from '../../block-verifier/test/chain-setup.mjs';
import { startR2Server } from '../../block-verifier/test/r2-server.mjs';
import { generateManifestForDir } from '../build/gen-manifest.mjs';
import { runLoaderVerification } from '../src/loader/loader.js';
import { LoaderStatus } from '../src/loader/verify-core.js';
import { manifestPreimage, normalizeBuildVersion } from '../src/common/manifest.js';

const checks = [];
function check(id, cond) { checks.push({ id, status: cond ? 'pass' : 'fail' }); console.log(`  ${cond ? 'ok' : 'NG'}: ${id}`); }

function makeFakeOut() {
  const dir = mkdtempSync(join(tmpdir(), 'cgt-out-'));
  mkdirSync(join(dir, '_next/static/chunks'), { recursive: true });
  mkdirSync(join(dir, 'game'), { recursive: true });
  mkdirSync(join(dir, 'locales/en'), { recursive: true });
  writeFileSync(join(dir, 'index.html'), '<!doctype html><html><head></head><body>root</body></html>');
  writeFileSync(join(dir, '404.html'), '<!doctype html>404');
  mkdirSync(join(dir, '404'), { recursive: true });
  writeFileSync(join(dir, '404/index.html'), '<!doctype html>404b');
  writeFileSync(join(dir, 'game/index.html'), '<!doctype html>game');
  writeFileSync(join(dir, '_next/static/chunks/main-abc123.js'), 'console.log("app")');
  writeFileSync(join(dir, '_next/static/chunks/framework-def456.js'), 'console.log("fw")');
  writeFileSync(join(dir, 'locales/en/game_en.json'), JSON.stringify({ hello: 'world' }));
  writeFileSync(join(dir, '.DS_Store'), 'junk'); // 除外される
  return dir;
}

async function main() {
  // R26: Numberへ丸めず10進文字列のまま原像へ入れ、契約と同じ範囲を強制する。
  const maxBuildVersion = '9007199254740991';
  check('loader.build_version.max_exact',
    normalizeBuildVersion(maxBuildVersion) === maxBuildVersion
    && manifestPreimage(maxBuildVersion, {}).includes(`buildVersion=${maxBuildVersion}|`));
  for (const [id, value] of [
    ['zero_rejected', '0'],
    ['above_max_rejected', '9007199254740992'],
    ['unsafe_number_rejected', 9007199254740992],
  ]) {
    let rejected = false;
    try { normalizeBuildVersion(value); } catch { rejected = true; }
    check(`loader.build_version.${id}`, rejected);
  }

  console.log('[loader-e2e] starting hardhat node…');
  const node = await startNode({ port: 8549 });
  let r2 = null;
  const cleanups = [() => node.stop()];
  try {
    const { hashStorage, clients } = await deployContracts(node.rpcUrl);
    const deployer = makeClients(node.rpcUrl); // account #0 = admin
    const BUILD_VERSION = 1;

    // 擬似 out/ + manifest
    const outDir = makeFakeOut();
    cleanups.push(() => rmSync(outDir, { recursive: true, force: true }));
    const { manifest } = generateManifestForDir(outDir, BUILD_VERSION, { commit: 'testcommit' });
    writeFileSync(join(outDir, 'build-manifest.json'), JSON.stringify(manifest), 'utf8');
    console.log(`[loader-e2e] buildHash=${manifest.buildHash} files=${manifest.fileCount}`);

    // 静的配信（out/ を運営配信元に見立てる）
    r2 = await startR2Server({ rootDir: outDir, port: 8790 });
    cleanups.push(() => r2.stop());

    // 共通 cfg
    const baseCfg = {
      chainIdExpected: 31337,
      rpcUrls: [node.rpcUrl],
      bundleOrigin: r2.baseUrl,
      manifestPath: '/build-manifest.json',
      contracts: { hashStorage: hashStorage.address },
      rpcPresets: [{ name: 'local', url: node.rpcUrl }],
    };
    const opts = () => ({ useWallet: false, makeClient: () => makeClients(node.rpcUrl).publicClient });

    // ④-pre: 未登録 → NO_HASH_REGISTERED
    {
      const r = await runLoaderVerification(baseCfg, opts());
      check('loader.no_hash_before_register', r.status === LoaderStatus.NO_HASH_REGISTERED);
    }

    // ② registerBuildHash 実登録
    await write(deployer, hashStorage, 'registerBuildHash', [
      BigInt(BUILD_VERSION), manifest.buildHash, deployer.account.address,
    ]);
    console.log('[loader-e2e] registered buildHash on-chain');

    // ③ green
    {
      const r = await runLoaderVerification(baseCfg, opts());
      check('loader.green', r.status === LoaderStatus.OK);
      check('loader.green.no_warn', r.status === LoaderStatus.OK && (!r.warns || r.warns.length === 0));
      check('loader.green.buildVersion', r.buildVersion === String(BUILD_VERSION));
    }

    // ④-a: ファイル1バイト改変 → FILE_HASH_MISMATCH
    {
      const badPath = '/_next/static/chunks/main-abc123.js';
      writeFileSync(join(outDir, badPath.slice(1)), 'console.log("app") // tampered');
      const r = await runLoaderVerification(baseCfg, opts());
      check('loader.file_tamper', r.status === LoaderStatus.FILE_HASH_MISMATCH && r.count >= 1);
      // 復旧
      writeFileSync(join(outDir, badPath.slice(1)), 'console.log("app")');
    }

    // ④-b: manifest 改変（file hash を書き換え） → MANIFEST_HASH_MISMATCH（第1層で落ちる）
    {
      const tampered = structuredClone(manifest);
      tampered.files['/index.html'] = '0'.repeat(64);
      writeFileSync(join(outDir, 'build-manifest.json'), JSON.stringify(tampered), 'utf8');
      const r = await runLoaderVerification(baseCfg, opts());
      check('loader.manifest_tamper', r.status === LoaderStatus.MANIFEST_HASH_MISMATCH);
      writeFileSync(join(outDir, 'build-manifest.json'), JSON.stringify(manifest), 'utf8');
    }

    // ④-c: 配信欠落（manifest にあるファイルが 404） → FETCH_FAIL
    {
      rmSync(join(outDir, 'game/index.html'));
      const r = await runLoaderVerification(baseCfg, opts());
      check('loader.withheld_file', r.status === LoaderStatus.FETCH_FAIL);
      writeFileSync(join(outDir, 'game/index.html'), '<!doctype html>game');
    }

    // ④-d: 同一 buildVersion を再登録（別内容でも同一hashで）→ REREGISTERED warn（FAILにはしない）
    {
      await write(deployer, hashStorage, 'registerBuildHash', [
        BigInt(BUILD_VERSION), manifest.buildHash, deployer.account.address,
      ]);
      const r = await runLoaderVerification(baseCfg, opts());
      check('loader.reregistered_warn', r.status === LoaderStatus.OK && r.warns?.some((w) => w.code === 'REREGISTERED'));
    }

    void clients;
  } finally {
    for (const c of cleanups.reverse()) { try { await c(); } catch { /* noop */ } }
  }

  // 機械可読出力
  console.log('');
  for (const c of checks) console.log(`##CHECK ${c.id} ${c.status}`);
  const anyFail = checks.some((c) => c.status === 'fail');
  console.log(`##RESULT ${anyFail ? 'fail' : 'full'}`);
  process.exit(anyFail ? 2 : 0);
}

main().catch((e) => { console.error('[loader-e2e] fatal:', e); console.log('##RESULT fatal'); process.exit(3); });

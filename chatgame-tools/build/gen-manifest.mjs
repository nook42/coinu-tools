#!/usr/bin/env node
// gen-manifest.mjs — ビルド出力ディレクトリから build-manifest.json と buildHash を生成する。
// E3-01/E3-02: 実在CLI契約と、出力JSONの決定性をこの生成器で一元管理する。
//
// 使い方:
//   node build/gen-manifest.mjs --dir ../out [--build-version 1] [--commit <sha>] [--no-write]
//
// - 対象 = --dir 配下の全ファイル（.DS_Store と build-manifest.json 自身を除外）
// - manifest.json は --dir 直下 /build-manifest.json として書き込む（＝配信物と一緒にデプロイされる。
//   自身は files に含まれない）
// - production build は BUILD_VERSION（または --build-version）を必須とする。
//   ローカルbuildだけは開発を止めないため version 1 を既定にする。
// - buildHash（bytes32）を stdout に出す。チェーン登録は契約バッチ時にユーザーが実行:
//     HashStorage.registerBuildHash(buildVersion, buildHash, signerAddress)
// - ルート package.json の postbuild から呼び、配信対象 out/ に必ず同梱する。

import { readdirSync, readFileSync, writeFileSync, statSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, join, relative, sep } from 'node:path';
import { execSync } from 'node:child_process';
import {
  buildManifestObject, isExcludedPath, normalizeBuildVersion, normalizeManifestPath,
} from '../src/common/manifest.js';

function parseArgs(argv) {
  const flags = { dir: null, buildVersion: null, commit: null, write: true };
  for (let i = 0; i < argv.length; i++) {
    let arg = argv[i];
    let value = null;
    const eq = arg.indexOf('=');
    if (eq !== -1) { value = arg.slice(eq + 1); arg = arg.slice(0, eq); }
    const next = () => value !== null ? value : argv[++i];
    switch (arg) {
      case '--dir': flags.dir = next(); break;
      case '--build-version': flags.buildVersion = next(); break;
      case '--commit': flags.commit = next(); break;
      case '--no-write': flags.write = false; break;
      default: throw new Error(`unknown flag: ${arg}`);
    }
  }
  if (!flags.dir) throw new Error('usage: gen-manifest.mjs --dir <out dir> [--build-version <N>] [--commit sha] [--no-write]');
  const release = !!(process.env.CF_PAGES || process.env.RELEASE);
  const requestedVersion = flags.buildVersion ?? process.env.BUILD_VERSION ?? (release ? null : '1');
  if (requestedVersion == null) {
    throw new Error('BUILD_VERSION is required for production builds; set it to the release number registered in HashStorage');
  }
  try { flags.buildVersion = normalizeBuildVersion(requestedVersion); }
  catch { throw new Error('--build-version must be an integer from 1 through 9007199254740991'); }
  return flags;
}

function* walk(dir) {
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) yield* walk(p);
    else if (st.isFile()) yield p;
  }
}

export function generateManifestForDir(dir, buildVersion, { commit = null, builtAt = null } = {}) {
  const root = resolve(dir);
  if (!existsSync(root)) throw new Error(`dir not found: ${root}`);
  const discoveredFiles = {};
  let excluded = 0;
  for (const abs of walk(root)) {
    const rel = relative(root, abs).split(sep).join('/');
    const path = normalizeManifestPath(rel);
    if (isExcludedPath(path)) { excluded++; continue; }
    discoveredFiles[path] = createHash('sha256').update(readFileSync(abs)).digest('hex');
  }
  if (Object.keys(discoveredFiles).length === 0) throw new Error(`no files found under ${root}`);
  // JSONのバイト列も再現可能にする。buildHashの原像だけでなくfilesの挿入順も固定する。
  const files = Object.fromEntries(
    Object.keys(discoveredFiles).sort().map((path) => [path, discoveredFiles[path]]),
  );
  const manifest = buildManifestObject({ buildVersion, files, commit, builtAt });
  return { manifest, excluded };
}

// CLI
if (import.meta.url === `file://${process.argv[1]}`) {
  const flags = parseArgs(process.argv.slice(2));
  let commit = flags.commit;
  if (!commit) {
    try { commit = execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim(); } catch { commit = null; }
  }
  // builtAt は渡さない。実行時計を配信manifestへ入れると同一入力のJSONバイトが変わる。
  const { manifest, excluded } = generateManifestForDir(flags.dir, flags.buildVersion, { commit });
  if (flags.write) {
    const outPath = join(resolve(flags.dir), 'build-manifest.json');
    writeFileSync(outPath, JSON.stringify(manifest), 'utf8'); // minified（R2/配信JSONの慣行に合わせる）
    console.log(`manifest written: ${outPath}`);
  }
  console.log(`files: ${manifest.fileCount} (excluded: ${excluded})`);
  console.log(`buildVersion: ${manifest.buildVersion}`);
  console.log(`buildHash: ${manifest.buildHash}`);
  console.log('');
  console.log('register on-chain (at contract batch time):');
  console.log(`  HashStorage.registerBuildHash(${manifest.buildVersion}, "${manifest.buildHash}", <signerAddress>)`);
}

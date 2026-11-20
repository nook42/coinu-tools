#!/usr/bin/env node
// verify-determinism.mjs — D4: 同一ソース→同一 out/ を二重ビルドで実証する（DESIGN.md §6）。
//
// 手順:
//   1) 本体を BUILD_ID 固定でビルド → out/ を退避（build-A）
//   2) もう一度ビルド → out/ を退避（build-B）
//   3) build-A / build-B を全ファイル byte-diff。差分ゼロなら決定論成立。
//      差分があれば「どのファイルのどこが」を出力し手順書に記録する。
//
// 前提（本体リポジトリ変更・要ユーザー承認・DESIGN §6/§8）:
//   - next.config.js に `generateBuildId: async () => process.env.BUILD_ID || null`（未設定時は現挙動）
//   - 本番 NEXT_PUBLIC_* をコミット済みの値で固定（.env.production 等）
//   これらが未適用の場合、本スクリプトは buildId 差（dir名＋__NEXT_DATA__）を必ず検出して失敗する
//   ＝「まだ決定論化されていない」ことの検出器として機能する。
//
// 使い方:
//   BUILD_ID=<git sha 等> node chatgame-tools/build/verify-determinism.mjs [--keep]
//   （linux-x64/Node20 の Docker 等、正準環境で実行するのが本番一致の前提）

import { spawnSync } from 'node:child_process';
import { cpSync, rmSync, mkdirSync, existsSync, readdirSync, statSync, readFileSync } from 'node:fs';
import { resolve, dirname, join, relative, sep } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../..');
const outDir = resolve(repoRoot, 'out');
const workDir = resolve(here, '../.determinism');
const keep = process.argv.includes('--keep');
const BUILD_ID = process.env.BUILD_ID || null;

function run(label) {
  console.log(`[verify-determinism] building (${label})… BUILD_ID=${BUILD_ID || '(unset)'}`);
  const r = spawnSync('npm', ['run', 'build'], { cwd: repoRoot, stdio: 'inherit', env: { ...process.env, BUILD_ID: BUILD_ID || '' } });
  if (r.status !== 0) { console.error('build failed'); process.exit(1); }
}

function snapshot(dest) {
  rmSync(dest, { recursive: true, force: true });
  cpSync(outDir, dest, { recursive: true });
}

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    if (name === '.DS_Store') continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p); else yield p;
  }
}
function hashTree(dir) {
  const map = {};
  for (const abs of walk(dir)) map[relative(dir, abs).split(sep).join('/')] = createHash('sha256').update(readFileSync(abs)).digest('hex');
  return map;
}

function main() {
  if (!existsSync(join(repoRoot, 'next.config.js'))) { console.error('run from monorepo (next.config.js not found)'); process.exit(1); }
  mkdirSync(workDir, { recursive: true });
  const a = join(workDir, 'build-A');
  const b = join(workDir, 'build-B');

  run('A'); snapshot(a);
  run('B'); snapshot(b);

  const ha = hashTree(a);
  const hb = hashTree(b);
  const paths = [...new Set([...Object.keys(ha), ...Object.keys(hb)])].sort();
  const diffs = [];
  for (const p of paths) {
    if (ha[p] !== hb[p]) diffs.push(p);
  }

  console.log('');
  console.log(`files A=${Object.keys(ha).length} B=${Object.keys(hb).length}`);
  if (diffs.length === 0) {
    console.log('##DETERMINISM full  (0 differing files — same source → same bytes)');
  } else {
    console.log(`##DETERMINISM fail  (${diffs.length} differing files):`);
    for (const p of diffs.slice(0, 50)) {
      const which = ha[p] == null ? 'only-in-B' : hb[p] == null ? 'only-in-A' : 'bytes-differ';
      console.log(`  ${which}  ${p}`);
    }
    if (diffs.length > 50) console.log(`  … and ${diffs.length - 50} more`);
    console.log('\nHint: unset BUILD_ID or missing next.config generateBuildId → buildId dir/__NEXT_DATA__ differ.');
    console.log('Record remaining diffs in chatgame-tools/BUILD_DETERMINISM.md and gate each (DESIGN §6).');
  }
  if (!keep) rmSync(workDir, { recursive: true, force: true });
  process.exit(diffs.length ? 2 : 0);
}

main();

#!/usr/bin/env node
// bundle.mjs — 静的アプリを esbuild でバンドルして dist/ に出す（ツール自身の配布物）。
//
// 生成物:
//   dist/index.html        ← loader UI（src/loader/index.html）
//   dist/loader.bundle.js  ← loader エントリ（src/loader/app.js）
//   dist/recovery.html     ← recovery UI（src/recovery/index.html を recovery.html 名で）
//   dist/recovery.bundle.js← recovery エントリ（src/recovery/app.js）
//   dist/sw.js             ← 検証ServiceWorker（src/loader/sw.js・依存なし）
//   dist/build-info.json   ← バンドルのハッシュ ＋ **ビルド時点の全入力の指紋**
//                            （ツール自身の再現確認用・チェーン錨とは別）
//
// 🔴 R-6（2026-08-09・ラウンド21）: `build-info.json` は長く `files`（dist 実体のハッシュ）
//    だけを書いていた。これでは「dist の中身が壊れていないか」しか言えず、
//    **「ソース（vendor/）は新しいのにビルドが古い」**を誰も検知できなかった
//    （`scripts/check-vendor-sync.mjs` に `dist` の参照が 0 件だった）。
//    実際 P-2026-0842（暗号文の固定長パディング）でソースだけが進み、配信済みの
//    `recovery.bundle.js` はパディング無しの暗号文を作る状態になっていた
//    （正典が長さを強制した瞬間、そのクライアントの投票／密告は無言で無効化される）。
//    → ビルド時の `vendor/` の sha256 集合をここに焼き、`check-vendor-sync` が
//      **現在の vendor/** と突き合わせて赤にする。Round 6 B-4 では同じ検査を
//      `src/` にも広げ、復元アプリ自身のソースだけ進んだ古い配信物も検出する。
//    ⚠️ `files` を dist 実体と比べるだけでは不足（ソース更新後にビルドしなければ
//      dist も build-info も動かないので、両方古いまま整合してしまう）。
//
// eciesjs は CJS・relay.js は process.env を読む → esbuild の define/CJS 解決で吸収。
// 依存はピン済み（package.json）。誰でも `npm run bundle` で再現し dist をdiffできる（ツール透明性）。

import { build } from 'esbuild';
import { mkdirSync, copyFileSync, writeFileSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, dirname, join, relative, isAbsolute, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const dist = resolve(root, 'dist');
const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

const define = {
  // relay.js が読む NEXT_PUBLIC_*。既定 10000ms を焼き込む（config で上書きは別途）。
  'process.env.NEXT_PUBLIC_P2P_QUIESCENCE_MS': '"10000"',
  // relaySinceSec() が読む START_TIME は復元クライアントでは未定義（過去ゲーム全履歴を復元する
  // ため since カットオフを効かせない）。定義しないと process 未定義で参照が throw するが、
  // relaySinceSec 側の try/catch が捕捉して 0（フィルタ無効）に落とすので define は不要。
  'process.env.NODE_ENV': '"production"',
};

const BUNDLE_ENTRIES = [
  ['src/loader/app.js', 'loader.bundle.js'],
  ['src/recovery/app.js', 'recovery.bundle.js'],
];

async function bundleEntry(entry, outfile, { write = true, logLevel = 'info' } = {}) {
  return build({
    absWorkingDir: root,
    entryPoints: [resolve(root, entry)],
    outfile: resolve(dist, outfile),
    bundle: true,
    write,
    metafile: true,
    format: 'iife',
    platform: 'browser',
    target: ['es2022'],
    define,
    legalComments: 'none',
    minify: false, // 監査容易性のため未minify（再現ビルドで差分を追いやすい）
    logLevel,
  });
}

// esbuild が実際に bundle へ取り込んだ入力の指紋。node_modules の推移依存を含む集合は
// metafile.inputs からのみ導き、package.json の手書き一覧を別の正典にしない。
export function digestBundleInputs(metafiles, readInput = (abs) => readFileSync(abs)) {
  const inputFiles = new Map();
  for (const metafile of metafiles) {
    for (const input of Object.keys(metafile?.inputs || {})) {
      const abs = isAbsolute(input) ? input : resolve(root, input);
      const rel = relative(root, abs).split(sep).join('/');
      if (rel === '..' || rel.startsWith('../')) {
        throw new Error(`bundle input escapes chatgame-tools: ${input}`);
      }
      inputFiles.set(rel, abs);
    }
  }
  const rows = [...inputFiles].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([rel, abs]) => [rel, createHash('sha256').update(readInput(abs, rel)).digest('hex')]);
  const lines = rows.map(([rel, hash]) => `${rel} ${hash}`);
  return {
    count: rows.length,
    digest: createHash('sha256').update(lines.join('\n')).digest('hex'),
    files: Object.fromEntries(rows),
  };
}

// check-vendor-sync からも同じ bundler 設定を使う。write:false なので dist は変更しない。
export async function collectBundleInputDigest(readInput = (abs) => readFileSync(abs)) {
  const results = await Promise.all(BUNDLE_ENTRIES.map(([entry, outfile]) =>
    bundleEntry(entry, outfile, { write: false, logLevel: 'silent' })));
  return digestBundleInputs(results.map((result) => result.metafile), readInput);
}

// vendor/ ツリー全体の指紋（相対パス昇順の "path sha256" 行を連結して sha256）。
// 🔴 **同じ関数を `scripts/check-vendor-sync.mjs` にも置いてある**（片方だけ変えたら
//    突き合わせが必ず失敗するので、変えるときは両方・byte 同一に保つこと）。
export function digestVendorTree(vendorRoot) {
  const rel = [];
  const walk = (dir, prefix) => {
    for (const name of readdirSync(dir).sort()) {
      const abs = join(dir, name);
      const key = prefix ? `${prefix}/${name}` : name;
      if (statSync(abs).isDirectory()) walk(abs, key);
      else rel.push([key, createHash('sha256').update(readFileSync(abs)).digest('hex')]);
    }
  };
  walk(vendorRoot, '');
  const lines = rel.map(([k, h]) => `${k} ${h}`);
  return {
    count: rel.length,
    digest: createHash('sha256').update(lines.join('\n')).digest('hex'),
    files: Object.fromEntries(rel),
  };
}

async function main() {
  mkdirSync(dist, { recursive: true });
  const bundleResults = [];
  for (const [entry, outfile] of BUNDLE_ENTRIES) {
    bundleResults.push(await bundleEntry(entry, outfile));
  }
  // SW（依存なし・生JSをそのままコピー。IIFE 化不要）
  copyFileSync(resolve(root, 'src/loader/sw.js'), resolve(dist, 'sw.js'));
  // HTML
  copyFileSync(resolve(root, 'src/loader/index.html'), resolve(dist, 'index.html'));
  copyFileSync(resolve(root, 'src/recovery/index.html'), resolve(dist, 'recovery.html'));

  // build-info（ツール自身のハッシュ。第三者が再現・diff するための指紋）
  const files = readdirSync(dist).filter((f) => f !== 'build-info.json').sort();
  const hashes = {};
  for (const f of files) hashes[f] = createHash('sha256').update(readFileSync(join(dist, f))).digest('hex');
  // R-6: ビルド時点の vendor/ の指紋。`check-vendor-sync` が現在の vendor/ と突き合わせる。
  const vendorDigest = digestVendorTree(resolve(root, 'vendor'));
  const sourceDigest = digestVendorTree(resolve(root, 'src'));
  const bundleInputDigest = digestBundleInputs(bundleResults.map((result) => result.metafile));
  // ルート config.js は src/ にも vendor/ にも無く、契約アドレス（鍵導出ドメインと提出先）を持つ。
  const configDigest = {
    'config.js': createHash('sha256').update(readFileSync(resolve(root, 'config.js'))).digest('hex'),
  };
  writeFileSync(resolve(dist, 'build-info.json'),
    JSON.stringify({
      files: hashes,
      vendor: vendorDigest,
      source: sourceDigest,
      config: configDigest,
      bundleInputs: bundleInputDigest,
    }, null, 2));
  console.log('\ndist/ contents:');
  for (const f of files) console.log(`  ${hashes[f].slice(0, 12)}  ${f}`);
  console.log(`\nvendor/ at build time: ${vendorDigest.count} file(s) digest=${vendorDigest.digest.slice(0, 12)}`);
  console.log(`src/ at build time: ${sourceDigest.count} file(s) digest=${sourceDigest.digest.slice(0, 12)}`);
  console.log(`config.js at build time: ${configDigest['config.js'].slice(0, 12)}`);
  console.log(`bundle inputs at build time: ${bundleInputDigest.count} file(s) digest=${bundleInputDigest.digest.slice(0, 12)}`);
  console.log('\nbundle: done');
}

if (isMain) main().catch((e) => { console.error('bundle failed:', e); process.exit(1); });

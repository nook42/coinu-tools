// K-S5-002: オフライン proof 生成（`--proof`）の回帰テスト
// 実行: node test/offline-proof.mjs   ※ 先に test/gen-fixture.mjs でフィクスチャを作っておくこと
//
// ⚠️ 位置づけ（2026-07-31 ユーザー判断）:
//   当初は「利用者がローカルに持つ summary.json を請求の保険にする」案（①）だったが、
//   **オンチェーン公開（②・docs/ONCHAIN_CLAIM_DATA_SPEC.md）が上位互換**のため①は取り下げた。
//   このモジュールは残す — ②の実装で**取得元をチェーンに差し替えるだけ**で再利用できるため。
//
// 守りたい性質:
//   1. **ネットワークに一切触れずに** proof を再構築できる（データさえあれば運営に依存しない）
//   2. 生成した proof が **実際にコントラクトの検証を通る**（root へ収束する）
//   3. proof の計算は正典 `merkleProofFor` を使う（別実装だと root と食い違いうる）
import { keccak256, encodeAbiParameters, concatHex } from 'viem';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { rebuildTreeFromLocalSummary, summaryPathFor } from '../src/proof.js';

const assert = (c, l) => { if (!c) { console.error('  NG:', l); process.exitCode = 1; } else console.log('  ok:', l); };
const here = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = resolve(process.env.E2E_FIXTURE_DATA_DIR || resolve(here, 'out/fixture/verifier-data'));
const BLOCK = 0;

console.log('K-S5-002 offline proof tests');
console.log('');

if (!existsSync(summaryPathFor({ dataDir: DATA_DIR }, BLOCK))) {
  console.error('  SKIP: fixture not found — run `node test/gen-fixture.mjs` first');
  process.exit(0);
}

// OpenZeppelin MerkleProof.verify と同じ計算（TokenMining.sol が使うもの）
function rootFromProof(blockNum, key, to, amount, proof) {
  const inner = keccak256(encodeAbiParameters(
    [{ type: 'uint256' }, { type: 'string' }, { type: 'address' }, { type: 'uint256' }],
    [BigInt(blockNum), key, to, BigInt(amount)],
  ));
  let h = keccak256(inner);
  for (const p of proof) h = h < p ? keccak256(concatHex([h, p])) : keccak256(concatHex([p, h]));
  return h;
}

console.log('[ネットワークに触れずに summary.json だけから木を再構築できる]');
let built;
{
  // fetch を潰しておく: 触ったら即座に失敗する（「オフラインで動く」を実測で担保）
  const origFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('network access is not allowed in --proof mode'); };
  try {
    built = await rebuildTreeFromLocalSummary({ dataDir: DATA_DIR }, BLOCK);
    assert(true, 'fetch を禁止した状態でも再構築できた');
  } catch (e) {
    assert(false, `オフライン再構築に失敗: ${e.message}`);
    process.exit(1);
  } finally {
    globalThis.fetch = origFetch;
  }
  assert(built.tree.leafCount > 0, `葉が1件以上ある (${built.tree.leafCount})`);
  assert(/^0x[0-9a-f]{64}$/.test(built.tree.root), `root が32バイト (${built.tree.root})`);
}

console.log('');
console.log('[生成した proof が全件、コントラクトと同じ計算で root へ収束する]');
{
  const { merkleProofFor } = await import('../vendor/workers/game_workers/game-master-DO.js');
  const { tree } = built;
  let checked = 0;
  for (const m of tree.leavesMeta) {
    const proof = merkleProofFor(tree.layers, m.index);
    const got = rootFromProof(BLOCK, m.key, m.to, m.amount, proof);
    if (got !== tree.root) {
      assert(false, `${m.key}: root 不一致 (${got})`);
      break;
    }
    checked++;
  }
  assert(checked === tree.leavesMeta.length,
    `全 ${tree.leavesMeta.length} 件の proof が root へ収束（＝実際に請求できる）`);
}

console.log('');
console.log('[再構築した root は公開 merkle メタと一致する（オンチェーン root と同じ値）]');
{
  const metaPath = resolve(DATA_DIR, `block${BLOCK}`, `merkle/block_${BLOCK}.json`);
  if (existsSync(metaPath)) {
    const meta = JSON.parse(readFileSync(metaPath, 'utf8'));
    assert(meta.root === built.tree.root,
      `公開メタの root と一致 (${meta.root === built.tree.root ? 'ok' : meta.root + ' vs ' + built.tree.root})`);
    assert(Number(meta.leafCount) === built.tree.leafCount, '葉の数も一致');
  } else {
    console.log('  (skip: 公開 merkle メタがフィクスチャに無い)');
  }
}

console.log('');
console.log('[summary.json が無ければ「まず検証を走らせて」と案内する]');
{
  let err = null;
  try { await rebuildTreeFromLocalSummary({ dataDir: '/nonexistent-dir-for-test' }, BLOCK); }
  catch (e) { err = e; }
  assert(err && err.missingPath, '欠落を missingPath 付きで報告する（案内文を出し分けるため）');
}

console.log('');
console.log('[配線: proof は正典の計算を使い、独自実装していない]');
{
  const src = readFileSync(resolve(here, '../src/proof.js'), 'utf8');
  assert(/import \{ GameMasterDO, merkleProofFor \}/.test(src), '正典から merkleProofFor を import');
  assert(src.includes('merkleProofFor(tree.layers, meta.index)'), '正典の計算をそのまま呼ぶ');
  assert(!/for \(let l = 0; l < layers\.length/.test(src), 'proof 計算を自前実装していない');
  // オフラインであること: ネットワーク層のモジュールを import していない。
  // （コメント中の言及は許す。**実際の import と呼び出し**だけを見る）
  const code = src.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
  assert(!/from '\.\/(r2|chain)\.js'/.test(code), 'r2.js / chain.js を import していない');
  assert(!/\bfetchJson\s*\(|\bfetch\s*\(/.test(code), 'ネットワーク取得を呼んでいない');
  const idx = readFileSync(resolve(here, '../src/index.js'), 'utf8');
  const at = idx.indexOf("cfg.flags?.proof");
  const setup = idx.indexOf('const chain = await setupChain');
  assert(at > 0 && at < setup, '--proof の分岐が RPC 接続より前にある（オフラインで完結）');
}

console.log('');
if (process.exitCode) console.log('FAILED');
else console.log('All offline-proof tests passed.');

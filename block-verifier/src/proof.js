// block-verifier/src/proof.js
//
// K-S5-002（2026-07-31）: **運営が止まっても自力で請求できる**ようにするためのオフライン proof 生成。
//
// 背景:
//   COINU の請求は `TokenMining.claim(blockNum, key, to, amount, proof[])` で、proof（兄弟ハッシュ列）が要る。
//   オンチェーンにあるのは root（32バイト）だけで、そこから proof を逆算することはできない。
//   通常は claim-worker が R2 の配信キャッシュから proof を組み立てて配る。
//   → **運営が R2 を消す／サーバーを止めると、未請求の報酬は請求できないまま請求期間が終わる。**
//
// ここでの解決:
//   Merkle の葉に必要な3要素（key / to / amount）は **`summary.json` だけ**から得られる
//   （正典 `collectClaimEntriesFromSummary`）。`leaves/` `levels/` `index/` は配信を速くするための
//   サーバー側キャッシュにすぎず、請求には要らない。
//   そして本ツールは検証のたびに summary.json を `data/block{N}/` へ保存している。
//   つまり **一度でも検証を走らせた人は、すでに請求に必要な全データを手元に持っている。**
//
//   このモードは RPC にも R2 にも接続せず、ローカルの summary.json だけで proof を再構築する。
//   正典の `buildMerkleTree` をそのまま使うので、オンチェーンの root と必ず一致する。

import { withVendorLogging } from './vendor-logging.js';
import fs from 'node:fs/promises';
import path from 'node:path';
import { GameMasterDO, merkleProofFor } from '../vendor/workers/game_workers/game-master-DO.js';
import {
  decodeClaimData, claimEntriesFromClaimData, concatChunks,
} from '../vendor/workers/game_workers/lib/claim-data-codec.js';
import { fetchClaimDataFromChain } from './claim-data.js';

/** ローカルキャッシュ上の summary.json の場所（r2.js の cachePathFor と同じ規則） */
export function summaryPathFor(cfg, blockNum) {
  return path.resolve(cfg.dataDir, `block${blockNum}`, `games/block${blockNum}/summary.json`);
}

/**
 * ローカルの summary.json から Merkle 木を組み直す。
 * ネットワークには一切アクセスしない（運営が止まっていても動くことが要件）。
 */
export async function rebuildTreeFromLocalSummary(cfg, blockNum) {
  const p = summaryPathFor(cfg, blockNum);
  let raw;
  try {
    raw = await fs.readFile(p, 'utf8');
  } catch {
    const err = new Error(`summary.json not found: ${p}`);
    err.missingPath = p;
    throw err;
  }
  const summary = JSON.parse(raw);
  // 環境変数は木の構築に使われない（葉は summary の中身だけで決まる）ので最小で足りる。
  const gm = withVendorLogging(() => new GameMasterDO({ storage: {} }, {}));
  const entries = withVendorLogging(() => gm.collectClaimEntriesFromSummary(blockNum, summary));
  if (entries.length === 0) {
    const err = new Error(`block ${blockNum} has no claimable entries (all disqualified / zero reward)`);
    err.empty = true;
    throw err;
  }
  const tree = withVendorLogging(() => gm.buildMerkleTree(blockNum, entries));
  return { tree, entries, summaryPath: p };
}

/**
 * チェーンに載った請求データから木を組み直す（K-S5-002・**主経路**）。
 *
 * 「運営が止まっている」のが前提の機能なので、運営のサーバー（R2）ではなく
 * チェーンを第一の取得元にする。必要なのは RPC 1本だけ。
 */
export async function rebuildTreeFromChain(cfg, ui, blockNum) {
  const { createChain } = await import('./chain.js');
  const chain = createChain(cfg, ui);
  const fetched = await fetchClaimDataFromChain(chain, ui, blockNum);
  if (!fetched.available) {
    const err = new Error(`on-chain claim data unavailable: ${fetched.reason}`);
    err.unavailable = fetched.reason;
    throw err;
  }
  // bitcoinu-claimdata/3 で非圧縮化。チャンクを連結すればそのまま blob。
  const decoded = decodeClaimData(concatChunks(fetched.chunks));
  if (Number(decoded.blockNum) !== Number(blockNum)) {
    throw new Error(`on-chain payload is for block ${decoded.blockNum}, not ${blockNum}`);
  }
  // ★ 請求データ自己完結化（2026-08-01）: **EthLock を1件も読まない。**
  //   受取アドレスと個別配当額は葉から外れ、請求時に契約が EthLock から読む。
  //   したがって「運営が止まっていて RPC も過去ログを拒否する」最悪の状況でも、
  //   請求データのチャンクさえ取れれば proof を組める（RPC 1本・eth_call だけ）。
  const gm = withVendorLogging(() => new GameMasterDO({ storage: {} }, {}));
  const entries = claimEntriesFromClaimData(decoded);
  if (entries.length === 0) {
    const err = new Error(`block ${blockNum} has no claimable entries (all disqualified / zero reward)`);
    err.empty = true;
    throw err;
  }
  return { tree: withVendorLogging(() => gm.buildMerkleTree(blockNum, entries)), entries, source: 'chain', chain };
}

/** key の部分一致で候補を絞る（uid だけ覚えている利用者のため） */
function matchEntries(entries, needle) {
  if (!needle) return entries;
  const q = String(needle).toLowerCase();
  return entries.filter((e) => e.key.toLowerCase().includes(q));
}

/**
 * `--proof` モードの本体。
 * @returns {number} プロセス終了コード
 */
export async function runProofMode(cfg, ui, { blockNum, key }) {
  ui.println(ui.t('proof.header', { block: blockNum }));

  // 取得元は **チェーン優先・ローカルキャッシュ フォールバック**（仕様書 §6.3）。
  // チェーンには「root がある ⟹ 請求データも同じチェーン上にある」が構造的に保証されているので、
  // 事前に検証ツールを走らせていなかった人でも RPC さえあれば proof を作れる。
  let built = null;
  let chainError = null;
  try {
    built = await rebuildTreeFromChain(cfg, ui, blockNum);
  } catch (e) {
    if (e.empty) { ui.warn(ui.t('proof.noEntries', { block: blockNum })); return 1; }
    chainError = e.message;
    ui.warn(ui.t('proof.chainFallback', { error: e.message }));
  }

  if (!built) {
    try {
      built = await rebuildTreeFromLocalSummary(cfg, blockNum);
    } catch (e) {
      if (e.missingPath) {
        ui.warn(ui.t('proof.summaryMissing', { path: e.missingPath, block: blockNum }));
        return 3;
      }
      if (e.empty) {
        ui.warn(ui.t('proof.noEntries', { block: blockNum }));
        return 1;
      }
      ui.warn(ui.t('proof.rebuildFailed', { error: chainError ? `${chainError} / ${e.message}` : e.message }));
      return 3;
    }
  }

  const { tree, entries, summaryPath, source } = built;
  ui.println(ui.t('proof.rebuilt', {
    path: source === 'chain' ? '(on-chain claim data)' : summaryPath,
    root: tree.root, count: String(tree.leafCount),
  }));
  ui.println('');

  const hits = matchEntries(entries, key);
  if (hits.length === 0) {
    ui.warn(ui.t('proof.keyNotFound', { key: String(key) }));
    return 1;
  }
  // key 未指定 or 候補が多い場合は一覧だけ出す（誤って巨大出力を出さない）
  if (!key || hits.length > 20) {
    ui.println(ui.t('proof.listHint', { count: String(hits.length) }));
    for (const e of hits.slice(0, 20)) ui.println(`  ${e.key}`);
    if (hits.length > 20) ui.println(`  … (${hits.length - 20} more)`);
    return 0;
  }

  for (const e of hits) {
    // 葉の index は leavesMeta が権威（entries と同順だが、取り違えを避けるため meta から引く）
    const meta = tree.leavesMeta.find((m) => m.key === e.key);
    if (!meta) { ui.warn(ui.t('proof.keyNotFound', { key: e.key })); continue; }
    // proof の計算は正典の merkleProofFor をそのまま使う（別実装だと root と食い違いうる）
    const proof = merkleProofFor(tree.layers, meta.index);
    ui.println(ui.t('proof.entryHeader', { key: e.key }));
    ui.println(`  blockNum : ${blockNum}`);
    ui.println(`  key      : ${e.key}`);
    if (isDepositorLeaf(meta)) {
      // ★ ロック所有者葉は to=address(0) なので **claim() では必ず revert する**
      //   （TokenMining `require(to != address(0), "Invalid recipient")`）。
      //   claimLockReward は setHash ではなく**集合そのもの**を calldata で要求するが、
      //   setHash は一方向なので鍵からは復元できない。ここで必ず印字する。
      ui.println(`  gid      : ${meta.gid}`);
      ui.println(`  uid      : ${meta.uid}`);
      ui.println(`  lockRewardTotal : ${meta.amount}`);
      ui.println(`  lockIds : ${JSON.stringify(meta.depositIds)}`);
      ui.println(`  proof    : ${JSON.stringify(proof)}`);
      ui.println('');
      ui.println(ui.t('proof.howToClaimDepositor'));
    } else {
      ui.println(`  to       : ${meta.to}`);
      ui.println(`  amount   : ${meta.amount}`);
      ui.println(`  proof    : ${JSON.stringify(proof)}`);
    }
    ui.println('');
  }
  ui.println(ui.t('proof.howToClaim', { root: tree.root }));
  return 0;
}

/** ロック所有者葉（プレイヤー単位・複数形 `_lock_owners_`）か。記帳用の単数形とは別物。 */
function isDepositorLeaf(meta) {
  return Array.isArray(meta?.depositIds) && /_lock_owners_/.test(String(meta.key));
}

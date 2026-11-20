// claim-data.js — チェーンに載った請求データを取り出す（K-S5-002）
//
// 取得の道順（どちらも実チェーンで実測確認済み・仕様書 §3.2）:
//   経路A  eth_getLogs({fromBlock: B, toBlock: B})
//          → 照会範囲が常に1ブロックなので、getLogs の**範囲**上限（merkle.io の 1k 等）に掛からない
//   経路B  eth_getBlockByNumber(B, true) の tx.input を ABI デコード
//          → **getLogs そのもの**を拒否する RPC（publicnode の 403）でも通る
//
// B（チャンクの eth ブロック番号）は契約 storage にあり、**データを載せたのと同じ tx で**
// 書かれている。tx ハッシュは EVM 内から取得できず別 tx 登録になるため採用していない
// （別 tx だと「root がある ⟹ 在り処もチェーン上にある」の保証が崩れる）。
//
// 完全性は契約が積算した連鎖ハッシュ（claimDataOf.dataHash）で確かめる。
// 宣言値ではなく実際に載ったバイト列だけから決まるので、
// 「宣言と違う中身を載せる」ことはできない。

import { ArchiveUnavailableError } from './archive.js';
import { parseAbiItem, decodeFunctionData, keccak256, encodePacked, toHex } from 'viem';

export const CLAIM_DATA_PUBLISHED_EVENT = parseAbiItem(
  'event ClaimDataPublished(uint256 indexed blockNum, uint32 indexed chunkIndex, uint32 totalChunks, bytes32 runningHash, bytes data)'
);

export const PUBLISH_CLAIM_DATA_ABI = [{
  type: 'function', name: 'publishClaimData', stateMutability: 'nonpayable',
  inputs: [
    { name: 'blockNum', type: 'uint256' }, { name: 'chunkIndex', type: 'uint32' },
    { name: 'totalChunks', type: 'uint32' }, { name: 'data', type: 'bytes' },
  ], outputs: [],
}];

export const CLAIM_DATA_VIEW_ABI = [
  {
    type: 'function', name: 'claimDataOf', stateMutability: 'view',
    inputs: [{ name: '', type: 'uint256' }],
    outputs: [
      { name: 'dataHash', type: 'bytes32' }, { name: 'chunks', type: 'uint32' }, { name: 'received', type: 'uint32' },
    ],
  },
  {
    type: 'function', name: 'getClaimDataBlocks', stateMutability: 'view',
    inputs: [{ name: 'blockNum', type: 'uint256' }], outputs: [{ name: '', type: 'uint64[]' }],
  },
];

function hexToBytes(hex) {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

/** 契約と同じ連鎖ハッシュ: H0 = bytes32(0)、全チャンクで H = keccak(H_prev || keccak(chunk)) */
export function runningHashOf(chunks) {
  let h = `0x${'00'.repeat(32)}`;
  for (const c of chunks) {
    const leaf = keccak256(toHex(c));
    h = keccak256(encodePacked(['bytes32', 'bytes32'], [h, leaf]));
  }
  return h;
}

/**
 * ブロック N の請求データをチェーンから取り出す。
 *
 * @returns {Promise<{available:boolean, reason?:string, chunks?:Uint8Array[], dataHash?:string, routes?:string[]}>}
 *   available:false は「取れなかった」であって「不正」ではない（呼び出し側は skip 注記にする）。
 */
export async function fetchClaimDataFromChain(chain, ui, blockNum) {
  const address = chain.contracts.tokenMining;
  const client = chain.client;

  // ---- ① 何チャンクあるか・どのブロックにあるかを storage から読む ----
  let ref, blocks;
  try {
    const r = await client.readContract({
      address, abi: CLAIM_DATA_VIEW_ABI, functionName: 'claimDataOf', args: [BigInt(blockNum)],
    });
    ref = Array.isArray(r)
      ? { dataHash: r[0], chunks: Number(r[1]), received: Number(r[2]) }
      : { dataHash: r.dataHash, chunks: Number(r.chunks), received: Number(r.received) };
    blocks = (await client.readContract({
      address, abi: CLAIM_DATA_VIEW_ABI, functionName: 'getClaimDataBlocks', args: [BigInt(blockNum)],
    })).map((b) => BigInt(b));
  } catch (e) {
    // 旧 TokenMining（この機能より前にデプロイされたもの）はこの関数を持たない
    return { available: false, reason: `claim_data_view_unavailable: ${e.shortMessage || e.message}` };
  }

  if (!ref.chunks || ref.received !== ref.chunks) {
    return { available: false, reason: 'not_published', ref };
  }
  if (blocks.length !== ref.chunks) {
    return { available: false, reason: `chunk_block_count_mismatch: ${blocks.length} != ${ref.chunks}` };
  }

  if (ui) ui.println(ui.t('claimData.fetching', { block: String(blockNum), chunks: String(ref.chunks) }));

  // ---- ② チャンクを1つずつ取る（経路A → だめなら経路B）----
  const chunks = [];
  const routes = [];
  for (let i = 0; i < ref.chunks; i++) {
    const at = blocks[i];
    let data = null;
    let blockError = null;

    // 経路A: 1ブロック範囲の getLogs
    try {
      const logs = await client.getLogs({
        address, event: CLAIM_DATA_PUBLISHED_EVENT,
        args: { blockNum: BigInt(blockNum), chunkIndex: i },
        fromBlock: at, toBlock: at,
      });
      if (logs.length > 0) {
        data = logs[logs.length - 1].args.data;
        routes.push('logs');
        if (ui) ui.println(ui.t('claimData.viaLogs', { i: String(i), block: String(at) }));
      }
    } catch { /* 経路B へ */ }

    // 経路B: ブロック本体の tx.input（getLogs を一切使わない）
    if (data === null) {
      try {
        const blk = await client.getBlock({ blockNumber: at, includeTransactions: true });
        for (const tx of blk.transactions) {
          if (!tx.to || tx.to.toLowerCase() !== address.toLowerCase()) continue;
          let decoded;
          try { decoded = decodeFunctionData({ abi: PUBLISH_CLAIM_DATA_ABI, data: tx.input }); }
          catch { continue; }
          const [bn, ci, , d] = decoded.args;
          if (Number(bn) !== Number(blockNum) || Number(ci) !== i) continue;
          // revert した tx もブロック本体と calldata には残る。成功 receipt だけを採用し、
          // 取得失敗も fail-closed で無視する。break せず最後の成功一致を勝たせる。
          let receipt;
          try { receipt = await client.getTransactionReceipt({ hash: tx.hash }); }
          catch { continue; }
          if (receipt?.status !== 'success') continue;
          data = d;
        }
        if (data !== null) {
          routes.push('block');
          if (ui) ui.println(ui.t('claimData.viaBlock', { i: String(i), block: String(at) }));
        }
      } catch (error) { if (error instanceof ArchiveUnavailableError) blockError = error; }
    }

    if (data === null) {
      return { available: false, reason: `chunk_${i}_unfetchable_at_block_${at}`,
        ...(blockError ? { unavailableError: blockError } : {}) };
    }
    chunks.push(hexToBytes(data));
  }

  // ---- ③ 完全性: 契約が積算した連鎖ハッシュと一致するか ----
  const recomputed = runningHashOf(chunks);
  if (recomputed.toLowerCase() !== String(ref.dataHash).toLowerCase()) {
    // これは「取れなかった」ではなく**不正**（載っているバイト列が state と食い違う）
    const err = new Error(`claim data hash mismatch: recomputed ${recomputed} != on-chain ${ref.dataHash}`);
    err.integrityFailure = true;
    throw err;
  }

  return { available: true, chunks, dataHash: ref.dataHash, routes, ref };
}

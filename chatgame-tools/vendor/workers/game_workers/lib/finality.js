// finality.js — 「チェーン上で確定した」境界を読む（K-S5-005）
//
// なぜ必要か:
//   イベント取り込みは長らく `head - 12` を「確定」とみなしてきた。しかし
//   **12確認は経験則であって確定ではない**。Ethereum の確定（finality）は
//   2エポック＝64〜96スロット（約13〜15分）かかる。
//   そのため「ここまでは揃っている」と記録したカーソルが、後から覆りうる。
//
//   さらに実害は「取りこぼし」だけではない。Alchemy の Webhook は 0 confirmations で
//   飛んでくるため、**チェーンから消えたイベントを反映したまま**になりうる。
//   取り込みカーソル（単調増加・減らない）はこれを検知できない。
//
// どう使うか:
//   確定ブロック番号 F を基準に、
//     ・evt_block <= F  … 二度と変わらない。凍結してよい
//     ・evt_block >  F  … 連番が揃っていてもチェーンを見に行く（消滅・差し替えを検知する）
//   と扱う。

/// `finalized` タグに対応していない RPC 向けのフォールバック段数。
/// 2エポック（64スロット）＋余裕。確定より必ず「古い側」に倒れるので安全側。
export const FINALITY_FALLBACK_LAG = 96;

// reorg 再検査の候補は「現在の確定境界より上か」ではなく、canonical receipt を
// 一度確認済みかで選ぶ。claim / donation が同じ規則からずれないための共有 SQL 断片。
export const CANONICAL_UNVERIFIED_SQL = 'canonical_verified_at IS NULL';

// GM の Evidence 読取は fallback の最初の成功値を採用しない。各 URL に別の
// publicClient を作り、同じ finalized 祖先の hash を確認してから値を照合する。
export const RPC_QUORUM_ALERT_AFTER_MS = 30 * 60 * 1000;

function quorumError(message) {
  const error = new Error(`[rpc-quorum] ${message}`);
  error.code = 'rpc_quorum_unavailable';
  return error;
}

// 単一 RPC の getlogs-adaptive と同じ範囲超過の文言を拾う。ただし割当切れは
// 範囲を狭めても解消しないので、コード -32005 だけでは範囲超過としない。
function logRejectionKind(error) {
  let cause = error;
  let rangeTooLarge = false;
  let rateLimited = false;
  for (let depth = 0; cause && depth < 8; depth++, cause = cause.cause) {
    const message = `${cause.message || ''} ${cause.shortMessage || ''} ${cause.details || ''}`.toLowerCase();
    if (/rate.?limit|too many requests|requests per second|throttl|quota|compute units|\b429\b/.test(message)
        || cause.code === 429 || cause.status === 429) rateLimited = true;
    if (/too many results|query returned more than|log response size exceeded|response size exceeded|query timeout exceeded|range is too large|block range too large|exceeds the limit|limit exceeded/.test(message)
        || (/more than/.test(message) && /results/.test(message)) || cause.code === -32602) rangeTooLarge = true;
  }
  return rateLimited ? 'rate_limit' : rangeTooLarge ? 'range_too_large' : 'other';
}

const sameHash = (a, b) => typeof a === 'string' && /^0x[0-9a-f]{64}$/i.test(a)
  && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();
const canonicalValue = (value) => JSON.stringify(value, (_, item) => {
  if (typeof item === 'bigint') return item.toString();
  if (typeof item === 'string' && /^0x[0-9a-f]*$/i.test(item)) return item.toLowerCase();
  return item;
});

function uniqueQuorum(rows, label) {
  const groups = new Map();
  for (const row of rows) {
    const key = canonicalValue(row.value);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(row);
  }
  const ranked = [...groups.values()].sort((a, b) => b.length - a.length);
  if (!ranked[0] || ranked[0].length < 2 || ranked[1]?.length === ranked[0].length) {
    throw quorumError(`${label} disagrees or fewer than two RPCs answered`);
  }
  return ranked[0];
}

/** 2本以上が同じ鎖と答える最も新しい共通高を選び、hash も2本以上で照合する。 */
async function readMatchingBlock(clients, blockTag, pinned = null) {
  if (!Array.isArray(clients) || clients.length < 2) throw quorumError('two independent RPC clients are required');
  const settled = await Promise.allSettled(clients.map((client) => client.getBlock({ blockTag })));
  const available = settled.map((row, index) => row.status === 'fulfilled'
    && row.value?.number != null && sameHash(row.value.hash, row.value.hash)
    ? { index, number: BigInt(row.value.number) } : null).filter(Boolean);
  if (available.length < 2) throw quorumError(`fewer than two ${blockTag} RPC answers`);
  const heights = available.map((row) => row.number).sort((a, b) => a > b ? -1 : a < b ? 1 : 0);
  const candidates = pinned ? [BigInt(pinned.number)]
    : [...new Set(heights.map(String))].map(BigInt).filter((height) =>
      available.filter((row) => row.number >= height).length >= 2);
  for (const number of candidates) {
    const eligible = available.filter((row) => row.number >= number);
    if (eligible.length < 2) continue;
    const reads = await Promise.allSettled(eligible.map((row) => clients[row.index].getBlock({ blockNumber: number })));
    const rows = reads.flatMap((result, offset) => {
      const value = result.status === 'fulfilled' ? result.value : null;
      if (!value || value.number == null || BigInt(value.number) !== number || !sameHash(value.hash, value.hash)
          || value.timestamp == null) return [];
      if (pinned?.hash && !sameHash(value.hash, pinned.hash)) return [];
      return [{ index: eligible[offset].index,
        value: { hash: String(value.hash).toLowerCase(), timestamp: BigInt(value.timestamp).toString() } }];
    });
    try {
      const chosen = uniqueQuorum(rows, `block hash/timestamp at ${number}`);
      return { number, hash: chosen[0].value.hash, timestamp: BigInt(chosen[0].value.timestamp),
        memberIndexes: chosen.map((row) => row.index) };
    } catch { /* より古い共通高を試す。pin 指定時は次候補がない。 */ }
  }
  throw quorumError(`block hash/timestamp has no matching ${blockTag} pair`);
}

/** 2本以上で一致する finalized block。 */
export async function readMatchingFinalizedBlock(clients, pinned = null) {
  return readMatchingBlock(clients, 'finalized', pinned);
}

/** 未確定登録の診断だけに使う、2本以上で一致する最新共通 block。 */
export async function readMatchingHeadBlock(clients, pinned = null) {
  return readMatchingBlock(clients, 'latest', pinned);
}

/** EIP-1898 の blockHash 指定 eth_call。応答2本以上の完全一致だけを採る。 */
export async function readMatchingContractAtHash(clients, block, call, codec) {
  const data = codec.encodeFunctionData({ abi: call.abi, functionName: call.functionName, args: call.args || [] });
  const indexes = block.memberIndexes || clients.map((_, index) => index);
  const settled = await Promise.allSettled(indexes.map(async (index) => {
      const client = clients[index];
      const raw = await client.request({ method: 'eth_call', params: [
        { to: call.address, data }, { blockHash: block.hash, requireCanonical: true },
      ] });
      return codec.decodeFunctionResult({ abi: call.abi, functionName: call.functionName, data: raw });
    }));
  const rows = settled.flatMap((result, offset) => result.status === 'fulfilled'
    ? [{ index: indexes[offset], value: result.value }] : []);
  if (rows.length === 0) {
    const missingGetter = (error) => {
      let cause = error;
      for (let depth = 0; cause && depth < 8; depth++, cause = cause.cause) {
        if (['ContractFunctionRevertedError', 'ContractFunctionZeroDataError',
          'ExecutionRevertedError', 'AbiDecodingZeroDataError'].includes(cause.name)) return true;
        if (/function selector was not recognized|returned no data|execution reverted/i
          .test(String(cause.message || ''))) return true;
      }
      return false;
    };
    if (settled.filter((result) => result.status === 'rejected' && missingGetter(result.reason)).length >= 2) {
      const error = quorumError(`${call.functionName} getter missing at ${block.hash}`);
      error.missingGetterQuorum = true;
      throw error;
    }
  }
  return uniqueQuorum(rows, `${call.functionName} at ${block.hash}`)[0].value;
}

/** 範囲ログは RPC 仕様上 blockHash filter と併用できないため、両応答と各ログの鎖 hash を照合する。 */
export async function readMatchingLogs(clients, block, fetchLogs) {
  const indexes = block.memberIndexes || clients.map((_, index) => index);
  const settled = await Promise.allSettled(indexes.map(async (index) => fetchLogs(clients[index])));
  const rows = [];
  for (const [offset, result] of settled.entries()) {
    if (result.status !== 'fulfilled' || !Array.isArray(result.value)) continue;
    const index = indexes[offset];
    const logs = result.value;
    const byNumber = new Map();
    let valid = true;
    for (const log of logs) {
      if (!Number.isSafeInteger(log.evtBlock) || log.evtBlock < 0
          || BigInt(log.evtBlock) > block.number || !log.blockHash) {
        valid = false; break;
      }
      const key = String(log.evtBlock);
      if (!byNumber.has(key)) byNumber.set(key, []);
      byNumber.get(key).push(log.blockHash);
    }
    if (!valid) continue;
    for (const [number, hashes] of byNumber) {
      let chainBlock;
      try { chainBlock = await clients[index].getBlock({ blockNumber: BigInt(number) }); }
      catch { valid = false; break; }
      if (hashes.some((hash) => !sameHash(hash, chainBlock?.hash))) {
        valid = false; break;
      }
    }
    if (valid) rows.push({ index, value: [...logs].sort((a, b) =>
      a.evtBlock - b.evtBlock || a.logIndex - b.logIndex || a.seq - b.seq) });
  }
  let chosen;
  try { chosen = uniqueQuorum(rows, `logs below ${block.hash}`); }
  catch (error) {
    const reasons = settled.map((result, offset) => {
      if (result.status === 'rejected') return `${indexes[offset]}:${logRejectionKind(result.reason)}`;
      return `${indexes[offset]}:${rows.some((row) => row.index === indexes[offset]) ? 'read' : 'invalid'}`;
    });
    const noQuorum = quorumError(`logs below ${block.hash}: ${reasons.join(', ')}; ${error.message}`);
    noQuorum.logRangeTooLarge = reasons.some((reason) => reason.endsWith(':range_too_large'));
    throw noQuorum;
  }
  await readMatchingFinalizedBlock(clients, block);
  return chosen[0].value;
}

/**
 * 確定済みブロック番号を返す。
 *
 * `eth_getBlockByNumber("finalized")` は 2022 年の Merge 以降どのクライアントも持つが、
 * 一部の公開 RPC は拒否する。その場合は `head - 96` に落とす（確定より古い側なので、
 * 「まだ確定していないものを確定扱いする」ことはない＝安全側に倒れる）。
 *
 * @returns {Promise<{number:number, source:'finalized'|'fallback'}>}
 */
export async function readFinalizedBlockNumber(provider, log) {
  try {
    // provider.send は ethers v5 / v6 どちらにもある（getBlock('finalized') は v6 のみ）
    const blk = await provider.send('eth_getBlockByNumber', ['finalized', false]);
    if (blk && blk.number != null) {
      const n = Number(BigInt(blk.number));
      if (Number.isFinite(n) && n > 0) return { number: n, source: 'finalized' };
    }
    log?.(`finalized block tag returned no usable number — falling back to head-${FINALITY_FALLBACK_LAG}`);
  } catch (e) {
    log?.(`finalized block tag unsupported by this RPC (${e?.message || e}) — falling back to head-${FINALITY_FALLBACK_LAG}`);
  }
  const head = Number(await provider.getBlockNumber());
  return { number: Math.max(0, head - FINALITY_FALLBACK_LAG), source: 'fallback' };
}

/**
 * 「この記録はもう巻き戻しを判定してよいか」。
 *
 * receipt が取れないことを即「消えた」と断定すると、**まだ採掘直後で RPC に伝播して
 * いないだけ**のものを誤って消してしまう。そこで2つの猶予のどちらかを満たすことを求める:
 *   ① 記録した eth ブロックが判っていて、そこから settleLag ブロック以上進んでいる
 *   ② eth ブロックが不明（旧 webhook 由来）なら、記帳から minAgeMs 以上経っている
 *
 * @param {{evtBlock:number|null, ingestedAt:number|null}} row
 * @param {{head:number, nowMs:number, settleLag?:number, minAgeMs?:number}} ctx
 */
export function isSettleableForRollback(row, { head, nowMs, settleLag = 12, minAgeMs = 10 * 60 * 1000 }) {
  if (Number.isFinite(row.evtBlock) && row.evtBlock > 0) {
    return head - row.evtBlock >= settleLag;
  }
  if (Number.isFinite(row.ingestedAt) && row.ingestedAt > 0) {
    return nowMs - row.ingestedAt >= minAgeMs;
  }
  return false; // 判断材料が無いものは触らない
}

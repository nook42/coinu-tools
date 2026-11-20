// getlogs-adaptive.js — 応答が大きすぎたら範囲を半分にして取り直す（K-S5-008）
//
// なぜ必要か:
//   イベントの取り込みは固定幅（例: 10,000 eth ブロック）で `eth_getLogs` を呼んでいた。
//   その範囲に入るイベントが多すぎると、RPC 提供元は結果を返さずエラーにする
//   （典型: 「10,000 件を超えました。範囲を狭めてください」）。
//   ところが旧実装は**幅を固定したまま**あきらめてカーソルを進めず終了する。
//   次の巡回でも同じ範囲を同じ幅で聞くので同じように失敗し、**永久に自己復旧しない**。
//
//   止まるのは「請求の反映」ではなく**完全性の検証機構**である。
//   取りこぼし・隠蔽を機械的に検知する唯一の仕組みが、黙って停止する。
//
//   本番想定（プレイヤー 2,100人・4日ブロック）で計算すると、
//   **1人あたりの支援者が約13人を超えたところで折れる**
//   （10,000件 × 3チャンク ÷ 2,100人 ≒ 13.3）。応募時の登録上限は50人なので、
//   人気が出れば通常運用で踏む。
//
// 何をするか:
//   「多すぎる」と言われたら範囲を半分にして再試行する。1ブロック幅まで割っても
//   駄目なら、それは範囲の問題ではないので throw する（黙って飛ばさない）。

/// 「範囲が広すぎる／結果が多すぎる」系のエラーか。提供元ごとに文言が違うので広めに拾う。
/// 判定を誤って**通信障害を「多すぎる」と誤認**しても、範囲を狭めて再試行するだけで
/// 害は無い（逆向きの誤認＝多すぎるのを通信障害と見なすと、旧実装と同じ永久停止になる）。
export function isRangeTooLargeError(e) {
  const msg = `${e?.message || ''} ${e?.shortMessage || ''} ${e?.details || ''}`.toLowerCase();
  if (!msg.trim()) return false;
  return (
    msg.includes('more than') && msg.includes('results') ||
    msg.includes('query returned more than') ||
    msg.includes('too many results') ||
    msg.includes('log response size exceeded') ||
    msg.includes('response size exceeded') ||
    msg.includes('query timeout exceeded') ||
    msg.includes('range is too large') ||
    msg.includes('block range too large') ||
    msg.includes('exceeds the limit') ||
    msg.includes('limit exceeded') ||
    e?.code === -32602 || e?.code === -32005
  );
}

/**
 * [fromBlock, toBlock] のログを取得する。応答過大なら範囲を二分して取り直す。
 *
 * @param {(from:number,to:number)=>Promise<Array>} fetchLogs 範囲を受けてログ配列を返す関数
 * @param {number} fromBlock
 * @param {number} toBlock
 * @param {{log?:Function, onSplit?:Function}} opts
 * @returns {Promise<Array>} 昇順に連結したログ
 */
export async function getLogsAdaptive(fetchLogs, fromBlock, toBlock, opts = {}) {
  const log = opts.log || (() => {});
  const out = [];

  // 明示スタックで再帰を避ける（深く割れてもスタックを消費しない）
  const stack = [[fromBlock, toBlock]];
  while (stack.length > 0) {
    const [from, to] = stack.pop();
    if (from > to) continue;
    try {
      const logs = await fetchLogs(from, to);
      out.push(...logs);
    } catch (e) {
      const { left, right, mid } = splitLogRangeOrThrow(e, from, to);
      log(`[getlogs] range ${from}-${to} too large — splitting into ${from}-${mid} / ${right[0]}-${to}`);
      opts.onSplit?.(from, to, mid);
      stack.push(right, left);      // 後入れ先出しなので前半を先に処理
    }
  }
  // 分割順に依らず eth ブロック昇順・同一ブロック内は logIndex 昇順にそろえる
  out.sort((a, b) => {
    const ab = Number(a.blockNumber ?? 0), bb = Number(b.blockNumber ?? 0);
    if (ab !== bb) return ab - bb;
    return Number(a.logIndex ?? a.index ?? 0) - Number(b.logIndex ?? b.index ?? 0);
  });
  return out;
}

/**
 * 応答過大エラーなら [from,to] を半分に割る。通信障害はそのまま投げ直す。
 *
 * 分割回数に上限を置かないのは意図的。範囲は整数ブロックの有限集合で、分割のたびに
 * 必ず狭くなるため、停止性は `from === to` が担保する。旧 `maxSplits=64` は深さではなく
 * 累計分割数だったため、広い範囲の多数の枝が応答過大になると1ブロックへ到達する前に
 * 打ち切っていた。請求・投げ銭・Evidence の3経路はこの同じ分割規則を使う。
 *
 * Number / BigInt の両方を受け付ける。戻り値は入力と同じ型。
 */
export function splitLogRangeOrThrow(error, from, to) {
  if (!isRangeTooLargeError(error)) throw error;
  if (from === to) {
    throw new Error(`[getlogs] block ${from} alone exceeds the provider limit: ${error?.message || error}`);
  }
  const isBigInt = typeof from === 'bigint' || typeof to === 'bigint';
  const mid = isBigInt
    ? (BigInt(from) + BigInt(to)) / 2n
    : Math.floor((Number(from) + Number(to)) / 2);
  const one = isBigInt ? 1n : 1;
  return {
    left: [from, mid],
    right: [mid + one, to],
    mid,
  };
}

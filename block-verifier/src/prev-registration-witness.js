// block-verifier/src/prev-registration-witness.js
//
// 「証明が名乗った前ブロックの登録行は、**このブロックのグループ分けの時点で現在値だった行**か」
// を第三者に見せるための純関数群。
//
// 🔴 なぜ契約ではなくここで判定するのか（2026-09-22・ユーザー決定）:
//   `TokenMining._checkAnchors` は `prevRegistrationIndex` について3つしか見ない
//   （①添字が範囲内 ②その行の hash が word7 と一致 ③番兵は履歴0件のときだけ）。
//   **時刻を1つも使わない**。基準になりうる grace は admin が `Evidence.extendGrace` で
//   動かせるので、契約が「正しい時点」を決めることはできない。
//
// 🔴 ユーザーが決めた規則:
//   「N+1 の主要言語は、**N+1 のグループ分けの時点**における N ブロックの配布を正典として扱い、
//     それに基づいて決定する。つまりそれ以降に N の配布が変更しても反映しない。」
//   ⇒ その時点の N の summary が攻撃者の登録であっても、それに基づいて主要言語を決めることを
//     **許容する**。したがってここの仕事は **止めることではなく、後から積まれた行が
//     使われたことを見せること**である。判定は `warn` までで、`fail` にしない。
//
// 判定の材料は**見張り役（tools/r2-backup-observer）の書き出し**である。
//   `readChainSnapshot` が 30 分ごとに `{blockNum, status, readAt, observedBlock,
//    resultRegistrationCount, resultHash:{hash,updated,signer}}` を run manifest の
//   `chainSnapshots` 配列（observer.mjs:949 で作り :1134 で push、:1233 で manifest へ）
//   へ残している。この `readAt` は**攻撃者に動かせない**時計なので、grace を伸ばされても
//   「グループ分けの時点で何が現在値だったか」の証人になる。
//   （チェーン側の `registeredAt` も読めるが、こちらは grace を動かされると意味が変わるので
//     判定には使わず、報告の付随情報として並べるだけにする。）

import fs from 'node:fs';
import path from 'node:path';

// TokenMining の番兵（`type(uint256).max`）。履歴0件のときだけ許される。
export const PREV_REGISTRATION_SENTINEL = (1n << 256n) - 1n;

function toMs(value) {
  if (typeof value !== 'string' || value === '') return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

function lowerHash(value) {
  return typeof value === 'string' ? value.toLowerCase() : null;
}

/**
 * run manifest（1本／配列）から chainSnapshots 行を取り出す。
 * 🔴 読めなかったものを黙って捨てない。`rejected` に理由を残す（呼び出し側が skip の params へ載せる）。
 */
export function collectObserverChainSnapshots(payloads) {
  const snapshots = [];
  const records = [];
  const rejected = [];
  let manifestCount = 0;
  const visit = (value, where) => {
    if (Array.isArray(value)) {
      value.forEach((item, index) => visit(item, `${where}[${index}]`));
      return;
    }
    if (!value || typeof value !== 'object') {
      rejected.push({ where, reason: 'not_an_object' });
      return;
    }
    if (!Array.isArray(value.chainSnapshots)) {
      rejected.push({ where, reason: 'no_chainSnapshots_array' });
      return;
    }
    manifestCount++;
    // 🔴 統括（2026-09-22）: 判定の時刻基準は grace ではなく**観測された事実**に取るので、
    //    鍵ごとの firstSeenAt（run manifest の records）も集める。
    for (const row of (Array.isArray(value.records) ? value.records : [])) {
      if (!row || typeof row !== 'object' || typeof row.key !== 'string') continue;
      records.push({
        key: row.key,
        blockNum: Number.isFinite(Number(row.blockNum)) ? Number(row.blockNum) : null,
        firstSeenAt: typeof row.firstSeenAt === 'string' ? row.firstSeenAt : null,
        fetchedAt: typeof row.fetchedAt === 'string' ? row.fetchedAt : null,
      });
    }
    for (const [index, row] of value.chainSnapshots.entries()) {
      if (!row || typeof row !== 'object') {
        rejected.push({ where: `${where}.chainSnapshots[${index}]`, reason: 'not_an_object' });
        continue;
      }
      snapshots.push({
        source: where,
        runId: typeof value.runId === 'string' ? value.runId : null,
        blockNum: Number(row.blockNum),
        status: typeof row.status === 'string' ? row.status : null,
        readAt: typeof row.readAt === 'string' ? row.readAt : null,
        readAtMs: toMs(row.readAt),
        observedBlock: Number.isFinite(Number(row.observedBlock)) ? Number(row.observedBlock) : null,
        resultRegistrationCount: Number.isFinite(Number(row.resultRegistrationCount))
          ? Number(row.resultRegistrationCount) : null,
        resultHash: row.resultHash && typeof row.resultHash === 'object'
          ? {
            hash: lowerHash(row.resultHash.hash),
            updated: Number.isFinite(Number(row.resultHash.updated)) ? Number(row.resultHash.updated) : null,
            signer: typeof row.resultHash.signer === 'string' ? row.resultHash.signer : null,
          }
          : null,
      });
    }
  };
  visit(payloads, 'input');
  return { snapshots, manifestCount, rejected, records };
}

/**
 * 見張り役の書き出しを読む。`target` はファイル1本でも、`*.json` を並べたディレクトリでもよい。
 * 🔴 読めないことを pass にしない。`{ ok:false, reason }` を返して呼び出し側に skip させる。
 */
export function readObserverChainSnapshots(target, { fsImpl = fs } = {}) {
  if (typeof target !== 'string' || target === '') {
    return { ok: false, reason: 'not_configured', files: [], snapshots: [], records: [], manifestCount: 0, rejected: [] };
  }
  let stat;
  try { stat = fsImpl.statSync(target); }
  catch (error) {
    return {
      ok: false, reason: 'unreadable', error: String(error?.message || error),
      files: [], snapshots: [], records: [], manifestCount: 0, rejected: [],
    };
  }
  let files;
  if (stat.isDirectory()) {
    let names;
    try { names = fsImpl.readdirSync(target); }
    catch (error) {
      return {
        ok: false, reason: 'unreadable', error: String(error?.message || error),
        files: [], snapshots: [], records: [], manifestCount: 0, rejected: [],
      };
    }
    files = names.filter((name) => name.endsWith('.json')).sort().map((name) => path.join(target, name));
  } else {
    files = [target];
  }
  if (files.length === 0) {
    return { ok: false, reason: 'no_json_files', files: [], snapshots: [], records: [], manifestCount: 0, rejected: [] };
  }
  const payloads = [];
  const rejected = [];
  for (const file of files) {
    let parsed;
    try { parsed = JSON.parse(fsImpl.readFileSync(file, 'utf8')); }
    catch (error) { rejected.push({ where: file, reason: `parse_failed: ${String(error?.message || error)}` }); continue; }
    payloads.push({ file, parsed });
  }
  const collected = collectObserverChainSnapshots(
    payloads.map(({ file, parsed }) => (Array.isArray(parsed)
      ? parsed.map((item) => ({ ...item, __file: file }))
      : { ...parsed, __file: file })),
  );
  const out = {
    ok: collected.manifestCount > 0,
    reason: collected.manifestCount > 0 ? null : 'no_run_manifest_with_chainSnapshots',
    files,
    snapshots: collected.snapshots,
    records: collected.records,
    manifestCount: collected.manifestCount,
    rejected: [...rejected, ...collected.rejected],
  };
  return out;
}

/**
 * 前ブロック `prevBlockNum` について、グループ分け締切（= chattingStart）**以前**に見張り役が
 * 記録した最後の現在値を選ぶ。grace 窓の中の記録が何件あり、値が割れていないかも数える。
 */
// 🔴 統括（2026-09-22）: 「グループ分けの時点」を **grace から作ってはならない。**
//    grace（`Evidence.currentGrace`）は admin が最大 BLOCK_TIME（本番4日）まで単調増加させられるので、
//    同じ盤面で grace を伸ばすだけで「後から積まれた行」が warn → pass に変わる
//    （周29 の反証が実測）。これは契約側のカット規則を外した理由とまったく同じ誤りである
//    （正典 `docs/external-audit/stage4-review/R28_SEVERITY.md` §9-2）。
//    ⇒ 基準は**観測された事実**に取る: 見張り役が N のグループ分けの成果物
//    （`entries/block{N}/game_groups.json`）を**最初に見た時刻** `firstSeenAt`
//    （`tools/r2-backup-observer/src/observer.mjs:299`）。運営に動かせない。
//    見つからなければ **skip**（grace で代用しない）。
export function groupingObservedAtMs(records, blockNum) {
  const key = `entries/block${Number(blockNum)}/game_groups.json`;
  const rows = (Array.isArray(records) ? records : [])
    .filter((row) => String(row?.key) === key)
    .map((row) => Date.parse(String(row?.firstSeenAt || row?.fetchedAt || '')))
    .filter((ms) => Number.isFinite(ms));
  if (rows.length === 0) return null;
  return Math.min(...rows);
}

export function selectObserverResultWitness({
  snapshots, prevBlockNum, entryEndMs, groupingDeadlineMs,
}) {
  const rows = (Array.isArray(snapshots) ? snapshots : [])
    .filter((row) => Number(row?.blockNum) === Number(prevBlockNum))
    .filter((row) => row?.status === 'ok')
    .filter((row) => Number.isFinite(row?.readAtMs))
    .sort((a, b) => a.readAtMs - b.readAtMs);
  const eligible = Number.isFinite(groupingDeadlineMs)
    ? rows.filter((row) => row.readAtMs <= groupingDeadlineMs)
    : [];
  const inGrace = Number.isFinite(entryEndMs) && Number.isFinite(groupingDeadlineMs)
    ? rows.filter((row) => row.readAtMs >= entryEndMs && row.readAtMs <= groupingDeadlineMs)
    : [];
  const distinctInGrace = new Set(inGrace.map((row) => row.resultHash?.hash ?? 'unregistered')).size;
  const stats = {
    consideredCount: rows.length,
    eligibleCount: eligible.length,
    inGraceWindowCount: inGrace.length,
    distinctHashesInGraceWindow: inGrace.length === 0 ? 0 : distinctInGrace,
  };
  if (!Number.isFinite(groupingDeadlineMs)) {
    return { ok: false, reason: 'grouping_deadline_unavailable', witness: null, ...stats };
  }
  if (eligible.length === 0) {
    return { ok: false, reason: 'no_snapshot_at_or_before_grouping_deadline', witness: null, ...stats };
  }
  return { ok: true, reason: null, witness: eligible[eligible.length - 1], ...stats };
}

/**
 * 名乗った添字 × チェーンの履歴 × 見張り役の証人 を突き合わせる。
 * 🔴 戻す status は `pass` か `warn` だけ。`fail` は返さない（ユーザー決定で許容する規則だから）。
 */
export function judgePrevRegistrationWitness({ claimedIndex, history, witness }) {
  const mismatches = [];
  const sentinel = claimedIndex != null && BigInt(claimedIndex) === PREV_REGISTRATION_SENTINEL;
  const count = Number(history?.count);
  const rows = Array.isArray(history?.rows) ? history.rows : [];
  const observedCount = witness?.resultRegistrationCount ?? null;
  const observedHash = witness?.resultHash?.hash ?? null;
  const observedUpdated = witness?.resultHash?.updated ?? null;

  if (sentinel) {
    if (count !== 0) mismatches.push(`sentinel claimed but the chain history now holds ${count} row(s)`);
    if (observedCount != null && observedCount !== 0) {
      mismatches.push(`sentinel claimed but the observer recorded ${observedCount} registration(s) at grouping time`);
    }
    if (observedHash != null) {
      mismatches.push(`sentinel claimed but the observer recorded a current result hash at grouping time (${observedHash})`);
    }
    return {
      status: mismatches.length === 0 ? 'pass' : 'warn',
      sentinel: true, claimedRow: null, mismatches,
    };
  }

  const index = Number(claimedIndex);
  if (!Number.isSafeInteger(index) || index < 0) {
    return {
      status: 'warn', sentinel: false, claimedRow: null,
      mismatches: [`claimed prevRegistrationIndex is not a usable index: ${String(claimedIndex)}`],
    };
  }
  const claimedRow = rows.find((row) => Number(row?.index) === index) ?? null;
  if (!claimedRow) {
    return {
      status: 'warn', sentinel: false, claimedRow: null,
      mismatches: [`claimed prevRegistrationIndex ${index} is outside the chain history (count=${count})`],
    };
  }
  if (observedHash == null) {
    mismatches.push(`the observer recorded no registered result hash at grouping time, but index ${index} was claimed`);
  } else if (lowerHash(claimedRow.hash) !== observedHash) {
    mismatches.push(
      `claimed row ${index} hash ${lowerHash(claimedRow.hash)} != the value current at grouping time ${observedHash}`,
    );
  }
  if (observedUpdated != null && Number(claimedRow.registeredBlock) !== Number(observedUpdated)) {
    mismatches.push(
      `claimed row ${index} registeredBlock ${claimedRow.registeredBlock}`
      + ` != the registration block current at grouping time ${observedUpdated}`,
    );
  }
  return {
    status: mismatches.length === 0 ? 'pass' : 'warn',
    sentinel: false,
    claimedRow,
    mismatches,
  };
}

/**
 * チェーンの現在値（getResultHash）が履歴のどの行に当たるかを求める。
 * 🔴 **選び方は変えない。** 今どの行を選んでいるかを見えるようにするだけ（周29 (c)）。
 */
export function locateCurrentResultRow(history, current) {
  const rows = Array.isArray(history?.rows) ? history.rows : [];
  const hash = lowerHash(current?.hash);
  const updated = Number.isFinite(Number(current?.updated)) ? Number(current.updated) : null;
  const matches = rows.filter((row) => lowerHash(row.hash) === hash
    && (updated == null || Number(row.registeredBlock) === updated));
  return {
    registrationCount: Number(history?.count ?? rows.length),
    // 現在値は必ず「最後に登録された行」なので、一致が複数あれば最大の添字が現在値の行。
    currentIndex: matches.length === 0 ? null : Math.max(...matches.map((row) => Number(row.index))),
    matchingIndices: matches.map((row) => Number(row.index)),
    latestIndex: rows.length === 0 ? null : Math.max(...rows.map((row) => Number(row.index))),
    selectionRule: 'HashStorage.getResultHash current value (unchanged)',
  };
}

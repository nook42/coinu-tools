// deposit-ledger.js — EthLock のデポジット台帳を取得する（K-S5-002）
//
// 🔻 **現在このモジュールはどの検査からも呼ばれていない**（2026-08-01・請求データ自己完結化）。
//    デポッターの葉から受取アドレスと個別配当額が外れ、木の再現が請求データ blob の
//    純関数になったため、`verifyOnchainClaimData` / `rebuildTreeFromChain` の双方から
//    台帳依存が消えた（それが本改修の主目的そのもの）。
//    残してあるのは、SPEC §8 の L1（適格集合からの除外）を「受容」から
//    「独立検出」へ格上げする場合の土台になるため:
//      `ETHLocked` を1掃き → idTo でグループ化 → 適格条件で絞り込み →
//      blob の `groups[].members[].depositIds` と突き合わせて欠落を FAIL にする。
//    ⚠️ 使う前に必ず ABI と適格条件を契約と突き合わせ直すこと。
//    ⚠️ 現状の L1 検出は `verifyDepositsOnChainForUids` → `mirrorRewardSplit` →
//       `compareSummary`（`check.stageC.summaryMatch`）の経路が担っている。そちらを消さないこと。
//
// なぜ必要か:
//   請求データのオンチェーン公開（決定②）はデポッターの受取アドレスと按分の重みを
//   載せない。どちらも depositId から EthLock を読めば分かるからである。
//   現行製品上限は満員ブロック21,000件（2,100人×10）で、`getLock` を1件ずつ呼ぶより
//   イベント1掃き＋欠落分だけの個別補完が安定する。旧50件上限の105,000件は履歴値。
//
// どう解決するか（実測で確認済み）:
//   `ETHLocked` イベントには lockOwner / idFrom / idTo / amount / unlockTime が
//   すべて載っている。ログを1掃きすれば全件を1リクエストで復元できる。
//   hardhat 上の実 EthLock で 600 件を突合したところ **不一致0・欠落0**。
//   （`withdrawn` だけログに無いが、適格判定 calcFilterEligibleDeposits は
//     idTo / unlockTime / amount>0 / depositerAddress しか見ないので影響しない）
//
//   ログに現れなかった depositId だけを `getLock` で個別に埋める。
//   必要な id 集合は既知なので、**RPC の検閲・欠落は「埋められない」＝失敗として現れる**
//   （黙って欠けた台帳のまま進むことはない）。
//
// RPC が過去ログを丸ごと拒否する場合（publicnode の 403 等）:
//   ログ0件 → 全件が個別読取に落ちる。空振りで長時間待たせないよう
//   cfg.depositCallFallbackMax で上限を切り、超えたら案内を出して停止する。

import fs from 'node:fs/promises';
import path from 'node:path';
import { parseAbiItem, getAddress } from 'viem';

// 2026-08-01: idFrom/idTo は uint256（X ユーザーIDの数値）、表示用 JSON は profileFrom/profileTo。
// ⚠️ 署名が変わると topic0 が変わり、**ログが1件もデコードできないまま0件が返る**（例外は出ない）。
const DEPOSITED_EVENT = parseAbiItem(
  'event ETHLocked(uint256 indexed lockId, address indexed lockOwner, uint256 idFrom, uint256 idTo, string profileFrom, string profileTo, uint256 amount, uint256 unlockTime)'
);

// パリティ検査（ethlock-abi-parity-test.mjs）が artifact と突き合わせるため export する。
export const ETH_LOCK_GET_DEPOSIT_ABI = [{
  type: 'function', name: 'getLock', stateMutability: 'view',
  inputs: [{ name: 'lockId', type: 'uint256' }],
  outputs: [{
    // ⚠️ セレクタ 0xd68f4dd1 は戻り値の構造体を変えても不変。ずれていても eth_call は成功し続け、
    //    スロットだけずれて**黙って誤読**する。EthLock.sol の struct と完全一致させること。
    type: 'tuple', components: [
      { name: 'lockOwnerAddress', type: 'address' },
      { name: 'idFrom', type: 'uint256' },
      { name: 'idTo', type: 'uint256' },
      { name: 'profileFrom', type: 'string' },
      { name: 'profileTo', type: 'string' },
      { name: 'amount', type: 'uint256' },
      { name: 'unlockTime', type: 'uint256' },
      { name: 'unlocked', type: 'bool' },
    ],
  }],
}];

const READ_CONCURRENCY = 10; // 正典 calcFetchDepositsFromChain と同じ

/** ローカルキャッシュの場所。amount は不変・イベントは追記のみなので追記型で安全。 */
function cachePathFor(cfg) {
  return path.resolve(cfg.dataDir, 'ethlock-deposits.json');
}

/// キャッシュのスキーマ版数。**フィールド構成を変えたら必ず上げること。**
/// 契約アドレスだけで無効化していると、アドレス据え置きの再デプロイや
/// フィールド構成変更のときに旧スキーマを読み続ける（インベントリ 21/35）。
const LEDGER_CACHE_SCHEMA = 2;   // 2 = uint256 idFrom/idTo ＋ profileFrom/profileTo

async function loadCache(cfg) {
  try {
    const raw = await fs.readFile(cachePathFor(cfg), 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed?.schema !== LEDGER_CACHE_SCHEMA) return null;   // 旧スキーマは破棄
    if (parsed?.contract && parsed?.deposits) return parsed;
  } catch { /* 無ければ作る */ }
  return null;
}

async function saveCache(cfg, data) {
  try {
    const p = cachePathFor(cfg);
    await fs.mkdir(path.dirname(p), { recursive: true });
    await fs.writeFile(p, JSON.stringify(data));
  } catch { /* キャッシュの失敗は無害化（次回また取り直すだけ） */ }
}

/**
 * 必要な depositId 集合ぶんの台帳を作る。
 *
 * @param {object} chain   createChain の戻り（client / contracts / getLogsChunked）
 * @param {object} cfg
 * @param {object} ui      i18n（案内文の出力用。省略可）
 * @param {string[]} requiredIds 10進文字列の depositId
 * @returns {Promise<Map<string, {idFrom:string, idTo:string, depositerAddress:string, amount:bigint, unlockTime:bigint}>>}
 */
export async function buildDepositLedger(chain, cfg, ui, requiredIds) {
  const ethLock = getAddress(chain.contracts.ethLock);
  const need = new Set(requiredIds.map(String));
  const ledger = new Map();

  // ---- ① ローカルキャッシュ（前回までに確定したぶん） ----
  const cache = await loadCache(cfg);
  let scannedTo = 0n;
  if (cache && getAddress(cache.contract) === ethLock) {
    scannedTo = BigInt(cache.scannedToBlock || 0);
    for (const [id, d] of Object.entries(cache.deposits)) {
      if (!need.has(id)) continue;
      ledger.set(id, {
        idFrom: d.idFrom, idTo: d.idTo,
        depositerAddress: getAddress(d.depositerAddress),
        amount: BigInt(d.amount), unlockTime: BigInt(d.unlockTime),
      });
    }
  }

  // ---- ② ETHLocked ログ1掃き（差分のみ） ----
  const head = await chain.latest();
  const headNum = BigInt(head.number ?? head);
  let logsOk = false;
  const fresh = {};
  if (ledger.size < need.size || scannedTo < headNum) {
    try {
      const logs = await chain.getLogsChunked({
        address: ethLock, event: DEPOSITED_EVENT,
        fromBlock: scannedTo, toBlock: headNum,
      });
      for (const log of logs) {
        const id = String(log.args.lockId);
        const rec = {
          idFrom: log.args.idFrom, idTo: log.args.idTo,
          depositerAddress: getAddress(log.args.lockOwner),
          amount: log.args.amount, unlockTime: log.args.unlockTime,
        };
        fresh[id] = {
          idFrom: rec.idFrom, idTo: rec.idTo, depositerAddress: rec.depositerAddress,
          amount: rec.amount.toString(), unlockTime: rec.unlockTime.toString(),
        };
        if (need.has(id)) ledger.set(id, rec);
      }
      logsOk = true;
    } catch (e) {
      // ログが取れない RPC はある（publicnode の 403 等）。個別読取へ落とす。
      if (ui) ui.warn(ui.t('deposit.logsUnavailable', { error: e.shortMessage || e.message }));
    }
  } else {
    logsOk = true;
  }

  // ---- ③ ログに現れなかったぶんだけ個別読取 ----
  const missing = [...need].filter((id) => !ledger.has(id));
  if (missing.length > cfg.depositCallFallbackMax) {
    const err = new Error(
      `deposit ledger: ${missing.length} individual getLock reads required `
      + `(limit ${cfg.depositCallFallbackMax}) — the selected RPC cannot serve historical logs`
    );
    err.rpcLimitExceeded = { needed: missing.length, limit: cfg.depositCallFallbackMax };
    throw err;
  }
  if (missing.length > 0) {
    if (ui) ui.println(ui.t('deposit.fillingGaps', { count: String(missing.length) }));
    for (let i = 0; i < missing.length; i += READ_CONCURRENCY) {
      const batch = missing.slice(i, i + READ_CONCURRENCY);
      const res = await Promise.all(batch.map(async (id) => {
        const d = await chain.client.readContract({
          address: ethLock, abi: ETH_LOCK_GET_DEPOSIT_ABI,
          functionName: 'getLock', args: [BigInt(id)],
        });
        return [id, d];
      }));
      for (const [id, d] of res) {
        if (!d || !d.lockOwnerAddress || BigInt(d.amount) === 0n) continue; // 非存在
        const rec = {
          idFrom: d.idFrom, idTo: d.idTo,
          depositerAddress: getAddress(d.lockOwnerAddress),
          amount: BigInt(d.amount), unlockTime: BigInt(d.unlockTime),
        };
        ledger.set(id, rec);
        fresh[id] = {
          idFrom: rec.idFrom, idTo: rec.idTo, depositerAddress: rec.depositerAddress,
          amount: rec.amount.toString(), unlockTime: rec.unlockTime.toString(),
        };
      }
    }
  }

  // ---- ④ キャッシュ更新（ログ掃きが成功したときだけ scannedToBlock を進める） ----
  if (Object.keys(fresh).length > 0 || logsOk) {
    const merged = { ...(cache && getAddress(cache.contract) === ethLock ? cache.deposits : {}), ...fresh };
    await saveCache(cfg, {
      contract: ethLock,
      scannedToBlock: logsOk ? headNum.toString() : String(scannedTo),
      deposits: merged,
    });
  }

  return ledger;
}

export { DEPOSITED_EVENT };

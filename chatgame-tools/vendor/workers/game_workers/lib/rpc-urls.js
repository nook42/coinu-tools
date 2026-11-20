// workers/game_workers/lib/rpc-urls.js
//
// S3-008（2026-07-29）: RPC エンドポイントの一覧を1箇所で組み立てる。
//
// 背景:
//   従来は `ETHEREUM_MAINNET_RPC_URL` / `_BACKUP` / `_BACKUP2` の **3つ固定**で、
//   4本目を足すにはワーカー6ファイルのコードを書き換える必要があった。
//   S3-008 の対処方針では「チェーン照合ができない間はゲームを開始しない」ため、
//   **RPC の可用性がブロックの進行に直結する**。障害時に運用側が即座に
//   プロバイダを追加できることが要件になった（2026-07-29 ユーザー要望）。
//
// 使い方（環境変数）:
//   ETHEREUM_MAINNET_RPC_URLS = "https://a.example/x, https://b.example/y"   ← 本数無制限
//   ETHEREUM_MAINNET_RPC_URL        （従来・後方互換）
//   ETHEREUM_MAINNET_RPC_URL_BACKUP （従来・後方互換）
//   ETHEREUM_MAINNET_RPC_URL_BACKUP2（従来・後方互換）
//
//   優先順は「複数指定 → 従来の3つ」。重複は先に出たものを残して除去する。
//   カンマ・改行・空白区切りのどれでも受け付ける（運用時のコピペ事故を減らす）。
//
// D-05（2026-09-26 ユーザー決定・R33-B-2-01）: 読み取りの順と送信の順を分ける。
//   読み取り（rpcReadUrlsFromEnv）: URLS → _URL_BACKUP → _URL → _URL_BACKUP2
//     GM・抽選・収集・応募・入金の監視の読み取りはこの順（記録上 _BACKUP＝Infura を先に使う）。
//   送信（rpcUrlsFromEnv・従来の順のまま）: URLS → _URL → _URL_BACKUP → _URL_BACKUP2
//     送信係（workers/admin_tx_coordinator）は送信と同じ接続で nonce・receipt も読むのでこの順。
//     送信係の外で tx を直接送る lottery-DO の RANDAO アンカー（anchorSelectionBlockHashOnChain と
//     そのチェーン定義 resolveEthChain）もこの順のまま。
//   URLS（運用で足す明示の上書き）はどちらの順でも先頭。正本は
//   docs/external-audit/stage4-review/round33/STAGE3_CARRYOVER_DECISIONS.md の D-05。
import { rpcProviderCount } from './rpc-independence.js';

/** 複数指定用の env 名（ここを増やしたいときはこの1箇所だけ見ればよい） */
export const RPC_LIST_ENV = 'ETHEREUM_MAINNET_RPC_URLS';
/** 従来の単体 env 名＝送信の順（後方互換・この順で後ろに連結する） */
export const RPC_SINGLE_ENVS = [
  'ETHEREUM_MAINNET_RPC_URL',
  'ETHEREUM_MAINNET_RPC_URL_BACKUP',
  'ETHEREUM_MAINNET_RPC_URL_BACKUP2',
];
/** 読み取りの順の単体 env 名（D-05・この順で URLS の後ろに連結する） */
export const RPC_READ_SINGLE_ENVS = [
  'ETHEREUM_MAINNET_RPC_URL_BACKUP',
  'ETHEREUM_MAINNET_RPC_URL',
  'ETHEREUM_MAINNET_RPC_URL_BACKUP2',
];

const looksLikeHttpUrl = (s) => {
  if (!/^https?:\/\/[^\s]+$/i.test(s)) return false;
  try {
    const parsed = new URL(s);
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && !!parsed.hostname;
  } catch { return false; }
};

// env から { url, env名 } の一覧を作る（重複排除済み・指定順）。warn=false は形式違反を黙って落とす。
function rpcEntriesFromEnv(env, singleEnvs, opts = {}) {
  const { requireHttp = true, warn = true } = opts;
  const out = [];
  const seen = new Set();
  const push = (raw, source) => {
    if (typeof raw !== 'string') return;
    const url = raw.trim().replace(/[,\s]+$/, '');
    if (!url) return;
    if (requireHttp && !looksLikeHttpUrl(url)) {
      if (warn) console.warn(`[rpc] ignoring malformed RPC URL entry: ${url.slice(0, 32)}…`);
      return;
    }
    if (seen.has(url)) return;
    seen.add(url);
    out.push({ url, source });
  };

  // ① 複数指定（カンマ / 改行 / 空白区切り）
  for (const part of String(env?.[RPC_LIST_ENV] || '').split(/[,\n\r\s]+/)) push(part, RPC_LIST_ENV);
  // ② 従来の3つ（後方互換・呼び手が選んだ順）
  for (const name of singleEnvs) push(env?.[name], name);

  return out;
}

/**
 * env から RPC URL の一覧を**送信の順**で作る（送信係と、送信係の外で tx を直接送る箇所だけが使う）。
 * @param {object} env
 * @param {{ requireHttp?: boolean }} opts requireHttp=false にすると形式検査を省く（既存挙動互換）
 * @returns {string[]} 重複排除済み・指定順
 */
export function rpcUrlsFromEnv(env, opts = {}) {
  return rpcEntriesFromEnv(env, RPC_SINGLE_ENVS, opts).map((entry) => entry.url);
}

/**
 * env から RPC URL の一覧を**読み取りの順**（D-05）で作る。送信しないワーカーの読み取りはこちら。
 * @param {object} env
 * @param {{ requireHttp?: boolean }} opts requireHttp=false にすると形式検査を省く（既存挙動互換）
 * @returns {string[]} 重複排除済み・指定順
 */
export function rpcReadUrlsFromEnv(env, opts = {}) {
  return rpcEntriesFromEnv(env, RPC_READ_SINGLE_ENVS, opts).map((entry) => entry.url);
}

// ホスト名だけ（path / query / userinfo は落とす）
const rpcHostOf = (u) => { try { const x = new URL(u); return x.hostname; } catch { return 'invalid'; } };

/** 一覧の中身を出さずに構成だけログ・監視へ出す（URL には API キーが入るため） */
export function describeRpcConfig(env) {
  const read = rpcEntriesFromEnv(env, RPC_READ_SINGLE_ENVS);
  const send = rpcEntriesFromEnv(env, RPC_SINGLE_ENVS, { warn: false });
  return {
    count: read.length,
    independentProviders: rpcProviderCount(read.map((entry) => entry.url)),
    // hosts は読み取りの順（この関数の呼び手＝GM はこの順で読む）。env 名つきの両方の順は下の2欄。
    hosts: read.map((entry) => rpcHostOf(entry.url)),
    readOrder: read.map((entry) => ({ env: entry.source, host: rpcHostOf(entry.url) })),
    sendOrder: send.map((entry) => ({ env: entry.source, host: rpcHostOf(entry.url) })),
    listEnvUsed: !!String(env?.[RPC_LIST_ENV] || '').trim(),
  };
}

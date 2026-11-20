// chatgame-tools/config.js
// 設定の既定値。block-verifier/src/config.js と同じ流儀（DEFAULTS < 保存済み設定 < 明示上書き）。
// タイミング定数（START_TIME/BLOCK_TIME/GAME_PERIOD/SUBMIT_PERIOD/grace）はここに置かない — チェーンの getter が正。
// workers/.env の値をデフォルトに埋め込むことは禁止。

import { VERIFIED_BUNDLE_ORIGIN, requireVerifiedBundleOrigin } from './src/loader/verify-core.js';

export const DEFAULTS = {
  chainIdExpected: 1,

  // 独立公開RPCプリセット（鍵不要・運営管理外・法域分散）。ローダーもこの一覧を表示する。
  // ローダーは運営RPCを一切使わない（照合前に運営RPCを信じない）。
  // S3R4-U-RPC1: 復元は注入ウォレット、または固定 S の2本以上の一致で窓・名簿・時刻を読む。
  // 利用者が足した rpcUrls は復元の読みに使わない。運営 RPC は公開が全部無答のときだけ。
  // 2026-10-10 の実測で 1rpc は無答、flashbots は eth_call を拒否したため外し、
  // 公式の INDEPENDENT_RPCS と同じ Tenderly・dRPC を足した。配布前に生存を再測定する（Q22）。
  // ⚠️ 採用条件は「**CORS 許可あり**・鍵不要・運営管理外」。復元クライアントはブラウザで動くので、
  //    CORS を返さない RPC は選択肢に置くだけ無駄（選んだ利用者が原因不明の失敗を踏む）。
  //    2026-08-05 実測で差し替え:
  //      llamarpc       … CORS ヘッダ無し（ブラウザからは恒久的に使用不可）
  //      cloudflare-eth … eth_blockNumber が -32046 で応答不可
  //    （block-verifier は 2026-07-12 の実機テストで同じ2つを既に削除していたが、
  //      こちらに反映されていなかった）
  rpcPresets: [
    { name: 'publicnode', url: 'https://ethereum-rpc.publicnode.com' },
    { name: 'tenderly', url: 'https://gateway.tenderly.co/public/mainnet' },
    { name: 'drpc', url: 'https://eth.drpc.org' },
  ],

  // 運営RPC（復元クライアントの最終手段のみ。ローダーでは使用しない）
  // 非推奨: ここ（か localStorage の chatgameToolsConfig.operatorRpc）に置くと、ウォレットも公開ノードも答えない読みで、そのつど知らせずにこの値を使う＝運営を信頼することになり、運営への依存を生む。置いた端末では復元の画面の Contracts in use の枠に毎回示す（S3R6-CARRY-OPTRUST・便 DISP6）。
  operatorRpc: null,

  r2Base: 'https://r2.bitcoinu.org',

  // 本体サイトのオリジン（メンバーカードのプロフィールリンク /user?id= の飛び先）
  siteOrigin: 'https://bitcoinu.org',

  // Turnstile 隔離フレームのオリジン（K-S6-001/K-S6-009・2026-07-28）。
  // 検証済みアプリの CSP に frame-src として渡す。**本体の NEXT_PUBLIC_TURNSTILE_FRAME_ORIGIN と
  // 同じ値でなければ、検証経由の応募だけが黙って失敗する。**
  turnstileFrameOrigin: 'https://verify.bitcoinu.org',

  // I1-03: ローダーが照合対象バンドルを取得する配信元。
  // Pages / pages.dev は functions/_middleware.js がbuildHashの外側で応答を差し替えられるため使わない。
  // 公開R2 bucket直結の専用prefixへ分離し、manifestのチェーン錨＋全ファイルsha256照合を維持する。
  bundleOrigin: VERIFIED_BUNDLE_ORIGIN,
  manifestPath: '/build-manifest.json',

  // 契約再デプロイバッチ（2026-11-20）後の mainnet アドレス。
  // この HashStorage は buildHash API（registerBuildHash/getBuildHash/latestBuildVersion）を持つ。
  // （出典: Hardhat/bitcoinu/deployment-info-TokenMining-mainnet.json / .env.local）
  contracts: {
    hashStorage: '0xc8845F3De44839765cfD4278110fcc576FC5D9D0',
    tokenMining: '0x65E28cd031a63DFeb4aCD9f921938aFb6faBFC2c',
    evidence: '0x4EaFd0Eb6EA539A58b8CDbd5b8761F731CcD01a8',
    ethLock: '0x44B0A97C560A96793B532c1157f373b27D8e73bf',
  },


  // 公開ルール定数のピン値（復元挙動・表示に使い、check-vendor-sync が正典と照合する）。
  // 採点は vendored コードが権威。
  pins: {
    gameMaxPlayers: 2100,
    minChars: 500,
    minMessages: 20,
    chatCaps: { maxChars: 10000, maxMessages: 100, maxMsgChars: 1000 },
    maxReports: 2,
    confirmationBlocks: 64,
  },
};

// 数値をここへ写さず、pin を置かない理由だけを宣言する。
// check-vendor-sync は DEFAULTS.pins とこの台帳の重複・理由欠落を検査する。
export const PIN_OMISSIONS = Object.freeze({
  clockSkewAllowMs: Object.freeze({
    status: 'canonical-direct',
    reason: '復元クライアントは vendored protocol-v2.js の chatWindowMsFromTimeline を直接使うため、別の数値 pin を持たない',
  }),
  quiescenceMs: Object.freeze({
    status: 'no-canonical-counterpart',
    reason: 'WS 非接続の復元クライアントには沈静化表示ゲートの実装がなく、提出バンドル・採点にも適用しない',
  }),
});

// localStorage キー（ツール独自設定。ゲームデータ側のキーは正典 relay.js / game.js の形式に従う）
export const TOOL_CONFIG_KEY = 'chatgameToolsConfig';

// 保存可能な上書きキー（ユーザー設定 UI / テストの注入面）
export function applyOverrides(cfg, src) {
  if (!src || typeof src !== 'object') return cfg;
  if (Number.isFinite(src.chainIdExpected)) cfg.chainIdExpected = Number(src.chainIdExpected);
  if (typeof src.r2Base === 'string' && src.r2Base) cfg.r2Base = src.r2Base.replace(/\/+$/, '');
  if (typeof src.siteOrigin === 'string' && src.siteOrigin) cfg.siteOrigin = src.siteOrigin.replace(/\/+$/, '');
  if (typeof src.bundleOrigin === 'string' && src.bundleOrigin) {
    cfg.bundleOrigin = requireVerifiedBundleOrigin(src.bundleOrigin);
  }
  if (typeof src.manifestPath === 'string' && src.manifestPath) cfg.manifestPath = src.manifestPath;
  if (Array.isArray(src.rpcUrls) && src.rpcUrls.length) cfg.rpcUrls = src.rpcUrls.slice();
  if (typeof src.operatorRpc === 'string') cfg.operatorRpc = src.operatorRpc || null;
  if (typeof src.lang === 'string' && src.lang) cfg.lang = src.lang;
  if (src.contracts && typeof src.contracts === 'object') {
    for (const k of ['hashStorage', 'tokenMining', 'evidence', 'ethLock']) {
      if (typeof src.contracts[k] === 'string' && src.contracts[k]) cfg.contracts[k] = src.contracts[k];
    }
  }
  return cfg;
}

export function loadConfig(overrides = null) {
  const cfg = structuredClone(DEFAULTS);
  cfg.rpcUrls = null; // null = 未選択（UIがRPC選択を促す。非対話はプリセット全部で fallback）
  cfg.lang = null;
  // ブラウザでは localStorage の保存済み設定を反映（Node では無視）
  try {
    if (typeof localStorage !== 'undefined') {
      const saved = localStorage.getItem(TOOL_CONFIG_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        // I1-03: 旧版が保存したpages.dev値は移行時に無視する。その他の利用者設定は維持する。
        delete parsed.bundleOrigin;
        applyOverrides(cfg, parsed);
      }
    }
  } catch { /* broken saved config は無視 */ }
  if (overrides) applyOverrides(cfg, overrides);
  cfg.bundleOrigin = requireVerifiedBundleOrigin(cfg.bundleOrigin);
  return cfg;
}

export function saveConfig(partial) {
  if (typeof localStorage === 'undefined') return;
  let current = {};
  try { current = JSON.parse(localStorage.getItem(TOOL_CONFIG_KEY) || '{}'); } catch { /* reset */ }
  const next = { ...current };
  delete next.bundleOrigin;
  for (const k of ['rpcUrls', 'lang', 'r2Base', 'siteOrigin', 'operatorRpc', 'contracts']) {
    if (partial?.[k] !== undefined) next[k] = partial[k];
  }
  localStorage.setItem(TOOL_CONFIG_KEY, JSON.stringify(next));
}

export function resolveRpcUrls(cfg) {
  if (Array.isArray(cfg.rpcUrls) && cfg.rpcUrls.length) return cfg.rpcUrls;
  return cfg.rpcPresets.map((p) => p.url);
}

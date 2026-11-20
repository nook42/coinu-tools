// src/loader/loader.js — ローダーのオーケストレーション（DESIGN.md §3.1）
// チェーン読取 → manifest取得 → 第1層(keccak) → 第2層(全ファイルsha256) → 一致時のみSW起動。
// UI から呼ばれる純粋寄りのドライバ（fetch と client を注入可能にしテスト容易化）。

import { makeLoaderClient, getWalletTransportIfMainnet, readLatestBuildHash } from '../common/chain.js';
import {
  LoaderStatus, verifyManifestAgainstChain, verifyAllFiles, buildCspHeader, classifyHttpFailure,
} from './verify-core.js';
import { fetchBounded } from '../common/bounded-fetch.js';

// fetch を注入可能に（テストではローカル配信元へ差し替え）
async function defaultFetchBytes(bundleOrigin, manifestPath) {
  return fetchBounded(`${bundleOrigin}${manifestPath}`, { cache: 'no-store', redirect: 'error' }, {
    label: `bundle file ${manifestPath}`,
    read: async (res) => {
      if (!res.ok) return { ok: false, status: res.status };
      return { ok: true, status: 200, bytes: new Uint8Array(await res.arrayBuffer()) };
    },
  });
}

async function defaultFetchJson(url) {
  return fetchBounded(url, { cache: 'no-store', redirect: 'error' }, {
    label: `loader manifest ${url}`,
    read: (res) => {
      if (!res.ok) { const e = new Error(`http ${res.status}`); e.httpStatus = res.status; throw e; }
      return res.json();
    },
  });
}

// メイン検証フロー。deps はテスト注入用。
export async function runLoaderVerification(cfg, {
  onStage = null,
  useWallet = true,
  makeClient = null,
  fetchJson = defaultFetchJson,
  fetchBytes = null,
} = {}) {
  const stage = (s, extra) => { if (onStage) onStage(s, extra); };

  // 1) チェーン読取（独立RPCのみ・運営RPCは使わない）
  stage('reading');
  let chainRead;
  try {
    const walletTransport = useWallet ? await getWalletTransportIfMainnet(cfg.chainIdExpected) : null;
    const client = makeClient
      ? makeClient()
      : makeLoaderClient({ rpcUrls: resolveLoaderRpcs(cfg), chainIdExpected: cfg.chainIdExpected, walletTransport });
    chainRead = await readLatestBuildHash(client, cfg.contracts.hashStorage);
  } catch (e) {
    return { status: LoaderStatus.RPC_FAIL, error: String(e?.message || e) };
  }
  if (!chainRead) return { status: LoaderStatus.NO_HASH_REGISTERED };

  // 2) manifest 取得（運営イミュータブル配信元から）
  stage('fetching');
  const manifestUrl = `${cfg.bundleOrigin}${cfg.manifestPath}`;
  let manifest;
  try {
    manifest = await fetchJson(manifestUrl);
  } catch (e) {
    const status = e.httpStatus === 503 ? LoaderStatus.MAINTENANCE : LoaderStatus.FETCH_FAIL;
    return { status, error: `manifest fetch: ${String(e?.message || e)}` };
  }

  // 3) 第1層: manifest ⇔ チェーン錨
  const l1 = verifyManifestAgainstChain(manifest, chainRead);
  if (l1.status !== LoaderStatus.OK) return { ...l1, chainRead };

  // 4) 第2層: 全ファイル sha256 照合
  const doFetchBytes = fetchBytes || ((p) => defaultFetchBytes(cfg.bundleOrigin, p));
  const l2 = await verifyAllFiles(manifest, doFetchBytes, {
    onProgress: (done, total, path) => stage('verifying', { done, total, path }),
  });
  if (l2.failures.length) {
    // 失敗の代表分類（file mismatch を最優先で報告・攻撃の疑いが最も強い）
    const mism = l2.failures.filter((f) => f.status === LoaderStatus.FILE_HASH_MISMATCH);
    if (mism.length) return { status: LoaderStatus.FILE_HASH_MISMATCH, count: mism.length, failures: mism, chainRead, buildVersion: l1.buildVersion };
    const rep = l2.failures[0];
    return { status: rep.status, failures: l2.failures, chainRead, buildVersion: l1.buildVersion };
  }

  return { status: LoaderStatus.OK, buildVersion: l1.buildVersion, warns: l1.warns, manifest, chainRead };
}

// ローダーは運営RPCを含めない（config.operatorRpc は復元クライアント専用）
export function resolveLoaderRpcs(cfg) {
  if (Array.isArray(cfg.rpcUrls) && cfg.rpcUrls.length) return cfg.rpcUrls;
  return cfg.rpcPresets.map((p) => p.url);
}

// 検証成功後: SW を登録し、検証済み manifest を注入して、検証アプリ入口へナビゲート。
// swPath/appEntry はホスティング（オリジンルート）に合わせて渡す。
export async function launchVerifiedApp(cfg, manifest, { swPath = '/sw.js', appEntry = '/', connectExtra = null } = {}) {
  if (!('serviceWorker' in navigator)) throw new Error('ServiceWorker unsupported in this browser');
  const reg = await navigator.serviceWorker.register(swPath, { scope: '/' });
  await navigator.serviceWorker.ready;
  const sw = reg.active || reg.waiting || reg.installing;
  if (!sw) throw new Error('service worker did not activate');

  const csp = buildCspHeader({
    connectExtra: connectExtra || defaultConnectExtra(cfg),
    // K-S6-009: Turnstile 隔離フレーム（別オリジン）の埋め込みを許可する。
    // script-src は 'self' のまま＝外部スクリプトは実行させない（K-S6-001）。
    frameExtra: [cfg.turnstileFrameOrigin].filter(Boolean),
  });
  await new Promise((resolve, reject) => {
    const ch = new MessageChannel();
    const timer = setTimeout(() => reject(new Error('SW did not confirm manifest install')), 5000);
    navigator.serviceWorker.addEventListener('message', function onMsg(ev) {
      if (ev.data?.type === 'MANIFEST_INSTALLED') {
        clearTimeout(timer);
        navigator.serviceWorker.removeEventListener('message', onMsg);
        resolve(ev.data);
      }
    });
    sw.postMessage({ type: 'INSTALL_MANIFEST', manifest, bundleOrigin: cfg.bundleOrigin, csp }, [ch.port2]);
  });

  // 検証アプリへナビゲート（以降 SW が全アセットを検証配信）
  window.location.assign(appEntry);
}

function defaultConnectExtra(cfg) {
  const list = [];
  if (cfg.r2Base) list.push(cfg.r2Base);
  // 運営worker・RPC・Nostrリレー・WalletConnect はアプリ動作に必要（データ面。script実行は 'self' に限定）
  list.push('https://*.workers.dev', 'wss://*', 'https://*');
  return list;
}

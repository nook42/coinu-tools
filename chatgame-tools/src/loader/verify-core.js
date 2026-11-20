// src/loader/verify-core.js — ローダー照合の純粋ロジック（ブラウザ/Node 両用・E2Eの主対象）
//
// 2層照合（DESIGN.md §3.2）:
//   第1層: manifest.json の files から preimage を再構成 → keccak256 == on-chain buildHash
//   第2層: 各ファイルの生バイト sha256 == files[path]
// 失敗分類（DESIGN.md §1 / §3.1）:
//   NO_HASH_REGISTERED / RPC_FAIL / FETCH_FAIL / MAINTENANCE / MANIFEST_INVALID /
//   MANIFEST_HASH_MISMATCH / FILE_HASH_MISMATCH / NOT_IN_MANIFEST
// WARN: REREGISTERED（buildRegistrationCount > 1 = ビルド差し替えの公開痕跡）
// E3-03/E12-04: production postbuild がmanifestを同梱し、未登録・版/hash不一致は
// この第1層がfail-closedにする。registerBuildHash tx 自体は承認済み運用バッチの責務。

import {
  validateManifestShape, manifestPreimage, computeBuildHash, normalizeBuildVersion, sha256Hex,
} from '../common/manifest.js';

// I1-03: 検証対象バイトは Pages Functions が介在する pages.dev から取らない。
// r2.bitcoinu.org は公開bucket直結であり、`frontend` prefixを静的ビルド専用にする。
// この値は config.js が既定値・保存値・明示overrideの全経路で強制する。
export const VERIFIED_BUNDLE_ORIGIN = 'https://r2.bitcoinu.org/frontend';

export function requireVerifiedBundleOrigin(value) {
  let parsed;
  try { parsed = new URL(String(value)); }
  catch { throw new Error('bundleOrigin must be the direct verified static origin'); }
  const normalizedPath = parsed.pathname.replace(/\/+$/, '') || '/';
  if (parsed.protocol !== 'https:'
      || parsed.username || parsed.password || parsed.port
      || parsed.hostname !== 'r2.bitcoinu.org'
      || normalizedPath !== '/frontend'
      || parsed.search || parsed.hash) {
    throw new Error('bundleOrigin must be https://r2.bitcoinu.org/frontend (Pages Functions are not trusted for verified bytes)');
  }
  return VERIFIED_BUNDLE_ORIGIN;
}

export const LoaderStatus = Object.freeze({
  OK: 'OK',
  NO_HASH_REGISTERED: 'NO_HASH_REGISTERED',
  RPC_FAIL: 'RPC_FAIL',
  FETCH_FAIL: 'FETCH_FAIL',
  MAINTENANCE: 'MAINTENANCE',
  MANIFEST_INVALID: 'MANIFEST_INVALID',
  MANIFEST_HASH_MISMATCH: 'MANIFEST_HASH_MISMATCH',
  FILE_HASH_MISMATCH: 'FILE_HASH_MISMATCH',
  NOT_IN_MANIFEST: 'NOT_IN_MANIFEST',
});

// メンテナンス応答の判別: functions/_middleware.js は MAINTENANCE_MODE=true で
// あらゆる応答を 503 のメンテナンスHTMLに差し替える。改竄と区別して案内する（攻撃断定はしない）。
export function classifyHttpFailure(status) {
  if (status === 503) return LoaderStatus.MAINTENANCE;
  return LoaderStatus.FETCH_FAIL;
}

// 第1層: チェーン錨と manifest の照合。
// chainRead = { buildVersion, hash, updatedBlock, signer, registrationCount } | null（未登録）
export function verifyManifestAgainstChain(manifest, chainRead) {
  if (!chainRead) return { status: LoaderStatus.NO_HASH_REGISTERED };
  const problems = validateManifestShape(manifest);
  if (problems.length) return { status: LoaderStatus.MANIFEST_INVALID, problems };
  if (normalizeBuildVersion(manifest.buildVersion) !== normalizeBuildVersion(chainRead.buildVersion)) {
    return {
      status: LoaderStatus.MANIFEST_HASH_MISMATCH,
      detail: `buildVersion mismatch: manifest=${manifest.buildVersion} chain=${chainRead.buildVersion}`,
    };
  }
  const computed = computeBuildHash(manifest.buildVersion, manifest.files);
  if (computed.toLowerCase() !== String(chainRead.hash).toLowerCase()) {
    return {
      status: LoaderStatus.MANIFEST_HASH_MISMATCH,
      detail: `computed=${computed} chain=${chainRead.hash}`,
      preimageLength: manifestPreimage(manifest.buildVersion, manifest.files).length,
    };
  }
  const warns = [];
  if (chainRead.registrationCount != null && BigInt(chainRead.registrationCount) > 1n) {
    // 差し替えは onlyAdmin に可能だが count は単調増加＝公開痕跡。FAILにはしない（正当な再登録もある）。
    warns.push({ code: 'REREGISTERED', registrationCount: String(chainRead.registrationCount) });
  }
  return { status: LoaderStatus.OK, buildVersion: normalizeBuildVersion(manifest.buildVersion), computed, warns };
}

// URL パス → manifest パス解決。
// trailingSlash:true の静的エクスポート: '/' → '/index.html'、'/game/' → '/game/index.html'。
// '/game'（スラ無し）は '/game/index.html' → '/game.html' の順で試す（CF Pages の解決に合わせ広めに）。
export function candidateManifestPaths(urlPath) {
  const p = urlPath.split('?')[0].split('#')[0];
  if (p.endsWith('/')) return [`${p}index.html`];
  const out = [p];
  const last = p.split('/').pop();
  if (!last.includes('.')) {
    out.push(`${p}/index.html`, `${p}.html`);
  }
  return out;
}

export function resolveManifestPath(manifestFiles, urlPath) {
  for (const cand of candidateManifestPaths(urlPath)) {
    if (Object.prototype.hasOwnProperty.call(manifestFiles, cand)) return cand;
  }
  return null;
}

// 第2層: 1ファイルの検証。bytes は配信元から取得した生バイト。
export async function verifyFileBytes(manifestFiles, manifestPath, bytes) {
  const expected = manifestFiles[manifestPath];
  if (!expected) return { status: LoaderStatus.NOT_IN_MANIFEST, path: manifestPath };
  const actual = await sha256Hex(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
  if (actual !== expected) {
    return { status: LoaderStatus.FILE_HASH_MISMATCH, path: manifestPath, expected, actual };
  }
  return { status: LoaderStatus.OK, path: manifestPath };
}

// 全ファイル一括検証（ローダーE2E・mutationテストの主経路。SWは要求時に同じ verifyFileBytes を使う）
// fetchBytes: async (manifestPath) => { ok, status, bytes } — テストでは差し替え可能
export async function verifyAllFiles(manifest, fetchBytes, { onProgress = null } = {}) {
  const paths = Object.keys(manifest.files).sort();
  const failures = [];
  let done = 0;
  for (const path of paths) {
    let res;
    try {
      res = await fetchBytes(path);
    } catch (e) {
      failures.push({ status: LoaderStatus.FETCH_FAIL, path, error: String(e?.message || e) });
      continue;
    }
    if (!res.ok) {
      failures.push({ status: classifyHttpFailure(res.status), path, httpStatus: res.status });
      continue;
    }
    const v = await verifyFileBytes(manifest.files, path, res.bytes);
    if (v.status !== LoaderStatus.OK) failures.push(v);
    done++;
    if (onProgress) onProgress(done, paths.length, path);
  }
  return { total: paths.length, verified: done - failures.filter((f) => f.status === LoaderStatus.FILE_HASH_MISMATCH).length, failures };
}

// CSP（SWが検証済みHTML応答に注入する。GitHub Pages はヘッダ不可 → SW応答で付与。DESIGN §3.1）
// connectExtra: 運営worker・RPC・リレー等の許可リスト（config から）
// frameExtra:   埋め込みを許す別オリジン（Turnstile 隔離フレーム等）
//
// K-S6-009 是正（2026-07-28）: 応募には Turnstile が必要だが、本 CSP は `script-src 'self'` なので
// 外部スクリプトを直接読み込む旧実装は必ず弾かれ、**検証済みクライアントから応募できなかった**。
// 「CSP に challenges.cloudflare.com を足す」修正は K-S6-001（外部スクリプトが signKey を読める）を
// 再発させるので不可。Turnstile を**別オリジンの iframe**へ隔離した（turnstile-frame/）ことで、
// **`script-src 'self'` を一切緩めずに** frame-src を1つ許可するだけで応募できるようになった。
export function buildCspHeader({ connectExtra = [], frameExtra = [] } = {}) {
  const connect = ["'self'", ...connectExtra].join(' ');
  const frame = ["'self'", ...frameExtra].join(' ');
  return [
    "default-src 'self'",
    // __NEXT_DATA__ 等のインラインscriptのため unsafe-inline を script に限り許容（将来 per-hash 化）
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    'font-src https://fonts.gstatic.com data:',
    "img-src 'self' data: https:",
    `connect-src ${connect}`,
    `frame-src ${frame}`,
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'self'",
  ].join('; ');
}

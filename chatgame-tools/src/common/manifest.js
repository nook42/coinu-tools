// src/common/manifest.js — build manifest / buildHash の凍結仕様（DESIGN.md §3.2）
//
// ここが「配信バンドル ⇔ チェーン錨」を結ぶ唯一の式。生成（build/gen-manifest.mjs）と
// 照合（loader）の両方が本モジュールを使う（式の写し2枚は分岐事故のもと）。
//
// 対象      = 配信ディレクトリ out/ の全ファイル（.DS_Store と manifest 自身を除外）。
//             Pages Functions（functions/）は out/ 外なので、このbuildHashの保護対象ではない（E12-12）。
// path      = out/ からの POSIX 相対パスに先頭 '/' を付与（=ブラウザが要求する URL パス）
// files[p]  = sha256hex(生バイト)（小文字hex・0xなし）
// preimage  = `bitcoinu-build-manifest/v1|buildVersion=${N}|algorithm=sha256|`
//             + sortedPaths.map(p => `${p}:${files[p]}`).join('|')   // sort = JS既定（コードユニット昇順）
// buildHash = keccak256(utf8(preimage))                               // ← HashStorage.registerBuildHash の bytes32
//
// manifest.json は files を運ぶ入れ物にすぎない: 照合側は必ず preimage を再構成して
// keccak を取り直す（manifest の キー順・整形・追加メタデータに依存しない）。

import { keccak_256 } from '@noble/hashes/sha3';

export const MANIFEST_SCHEMA = 'bitcoinu-build-manifest/v1';
export const MANIFEST_ALGORITHM = 'sha256';
export const MAX_BUILD_VERSION = 9007199254740991n; // HashStorage.registerBuildHash と同値（2^53-1）

// 生成・照合の両方で共通の除外規則
export const EXCLUDED_BASENAMES = ['.DS_Store'];
export const MANIFEST_BASENAME = 'build-manifest.json';

const utf8 = (s) => new TextEncoder().encode(s);
const bytesToHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

export function isExcludedPath(path) {
  const base = path.split('/').pop();
  return EXCLUDED_BASENAMES.includes(base) || base === MANIFEST_BASENAME;
}

// path 正規化: POSIX 区切り・先頭 '/' 必須・'.'/'..' 不可
export function normalizeManifestPath(path) {
  if (typeof path !== 'string' || !path) throw new Error(`invalid manifest path: ${path}`);
  const p = path.startsWith('/') ? path : `/${path}`;
  if (p.includes('\\') || p.split('/').some((seg) => seg === '.' || seg === '..')) {
    throw new Error(`invalid manifest path: ${path}`);
  }
  return p;
}

// buildVersion は Number を経由させない。uint256 の10進表現を BigInt で検証し、
// 原像と manifest には丸めのない10進文字列を使う（既存の安全整数域では同じ文字列）。
export function normalizeBuildVersion(buildVersion) {
  let value;
  if (typeof buildVersion === 'number') {
    if (!Number.isSafeInteger(buildVersion)) {
      throw new Error(`invalid buildVersion: ${buildVersion}`);
    }
    value = BigInt(buildVersion);
  } else if (typeof buildVersion === 'bigint') {
    value = buildVersion;
  } else if (typeof buildVersion === 'string' && /^(0|[1-9]\d*)$/.test(buildVersion)) {
    value = BigInt(buildVersion);
  } else {
    throw new Error(`invalid buildVersion: ${buildVersion}`);
  }
  if (value <= 0n || value > MAX_BUILD_VERSION) {
    throw new Error(`invalid buildVersion: ${buildVersion}`);
  }
  return value.toString();
}

export function manifestPreimage(buildVersion, files) {
  const v = normalizeBuildVersion(buildVersion);
  const sorted = Object.keys(files).sort(); // JS既定 = UTF-16 コードユニット昇順（localeCompare禁止）
  for (const p of sorted) {
    if (!p.startsWith('/')) throw new Error(`manifest path must start with '/': ${p}`);
    const h = files[p];
    if (typeof h !== 'string' || !/^[0-9a-f]{64}$/.test(h)) {
      throw new Error(`invalid sha256 for ${p}: ${h}`);
    }
  }
  return (
    `${MANIFEST_SCHEMA}|buildVersion=${v}|algorithm=${MANIFEST_ALGORITHM}|` +
    sorted.map((p) => `${p}:${files[p]}`).join('|')
  );
}

// buildHash（bytes32・0x付き小文字hex）
export function computeBuildHash(buildVersion, files) {
  return `0x${bytesToHex(keccak_256(utf8(manifestPreimage(buildVersion, files))))}`;
}

// sha256（照合側・生成側共通。WebCrypto があれば使い、無ければ @noble にフォールバック）
export async function sha256Hex(bytes) {
  if (globalThis.crypto?.subtle) {
    const buf = await globalThis.crypto.subtle.digest('SHA-256', bytes);
    return bytesToHex(new Uint8Array(buf));
  }
  const { sha256 } = await import('@noble/hashes/sha256');
  return bytesToHex(sha256(bytes));
}

// manifest.json の構造検証（照合側の入口。buildHash は含まれていても信用せず再計算する）
export function validateManifestShape(m) {
  const problems = [];
  if (!m || typeof m !== 'object') return ['manifest is not an object'];
  if (m.schema !== MANIFEST_SCHEMA) problems.push(`schema mismatch: ${m.schema}`);
  if (m.algorithm !== MANIFEST_ALGORITHM) problems.push(`algorithm mismatch: ${m.algorithm}`);
  try { normalizeBuildVersion(m.buildVersion); }
  catch { problems.push(`invalid buildVersion: ${m.buildVersion}`); }
  if (!m.files || typeof m.files !== 'object' || Array.isArray(m.files)) {
    problems.push('files map missing');
  } else {
    for (const [p, h] of Object.entries(m.files)) {
      if (!p.startsWith('/')) { problems.push(`path without leading '/': ${p}`); break; }
      if (typeof h !== 'string' || !/^[0-9a-f]{64}$/.test(h)) { problems.push(`bad sha256 for ${p}`); break; }
      if (isExcludedPath(p)) { problems.push(`excluded path present in manifest: ${p}`); break; }
    }
    if (Number(m.fileCount) !== Object.keys(m.files).length) {
      problems.push(`fileCount mismatch: ${m.fileCount} != ${Object.keys(m.files).length}`);
    }
  }
  return problems;
}

// manifest.json の組み立て（生成側）。buildHash はメタ情報として同梱するが照合の根拠にはしない。
export function buildManifestObject({ buildVersion, files, commit = null, builtAt = null }) {
  const normalizedBuildVersion = normalizeBuildVersion(buildVersion);
  const buildHash = computeBuildHash(normalizedBuildVersion, files);
  return {
    schema: MANIFEST_SCHEMA,
    buildVersion: normalizedBuildVersion,
    algorithm: MANIFEST_ALGORITHM,
    commit,
    builtAt,
    fileCount: Object.keys(files).length,
    buildHash,
    files,
  };
}

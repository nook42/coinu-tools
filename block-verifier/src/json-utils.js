// block-verifier/src/json-utils.js
// byte-exact 原則の中核プリミティブ。
// バックエンドのハッシュ規約 = 「SHA-256 over UTF-8 of JSON.stringify(parse(bytes))」
// （collect-worker.js calculateHash / collect-DO.js / game-master-DO.js sha256Hex と同一）。
// キーのソートや正規化ライブラリは使わない — 挿入順のまま素の JSON.stringify。

import { createHash } from 'node:crypto';

// SHA-256（UTF-8）→ 64桁小文字hex（0xなし）。Workers の crypto.subtle 実装と同値。
export function sha256HexOfString(s) {
  return createHash('sha256').update(Buffer.from(s, 'utf8')).digest('hex');
}

// バックエンドの calculateHash と同じ: parse済みオブジェクトを stringify してから SHA-256
export function hashLikeBackend(parsedObj) {
  return sha256HexOfString(JSON.stringify(parsedObj));
}

// 生バイト（文字列 / Uint8Array / Buffer）の完全一致
export function byteEqual(rawA, rawB) {
  if (typeof rawA === 'string' && typeof rawB === 'string') return rawA === rawB;
  const a = typeof rawA === 'string' ? Buffer.from(rawA, 'utf8') : Buffer.from(rawA);
  const b = typeof rawB === 'string' ? Buffer.from(rawB, 'utf8') : Buffer.from(rawB);
  return a.length === b.length && a.equals(b);
}

// 再シリアライズ後の文字列比較（JSON構造の正準等価）
export function canonicalEqual(objA, objB) {
  return JSON.stringify(objA) === JSON.stringify(objB);
}

// 表示用の時刻フォーマット: 実行マシンのローカル時刻 "YYYY-MM-DD HH:mm:ss"。
// /block ページ（src/utils/mypageUtils.js formatDate）と同じローカル時刻表示に秒を加えた形式。
// 表示専用 — ハッシュ・照合対象のデータには使わないこと。
export function displayTime(input) {
  const d = new Date(input);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

// 実行マシンのタイムゾーンオフセット表記: "UTC+09:00" / "UTC-05:00" / "UTC+00:00"
export function tzOffsetLabel() {
  const offMin = -new Date().getTimezoneOffset();
  const sign = offMin >= 0 ? '+' : '-';
  const abs = Math.abs(offMin);
  const pad = (n) => String(n).padStart(2, '0');
  return `UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`;
}

const MAX_DIFFS = 200;
const VALUE_PREVIEW_CHARS = 120;

function previewValue(v) {
  if (v === undefined) return '(absent)';
  let s;
  try {
    s = JSON.stringify(v);
  } catch {
    s = String(v);
  }
  if (s === undefined) s = String(v);
  return s.length > VALUE_PREVIEW_CHARS ? s.slice(0, VALUE_PREVIEW_CHARS) + '…' : s;
}

// ignore パターン照合: ドット区切りセグメント・'*' は1セグメントの任意一致。
// パターンが diff パスの先頭に一致（prefix）した時点で ignore（サブツリーごと中立化）。
// 例: 'updatedAt', 'groups.*.members.*.claimed'
function isIgnored(segments, ignorePatterns) {
  for (const pattern of ignorePatterns) {
    const pseg = String(pattern).split('.');
    if (pseg.length > segments.length) continue;
    let ok = true;
    for (let i = 0; i < pseg.length; i++) {
      if (pseg[i] !== '*' && pseg[i] !== String(segments[i])) { ok = false; break; }
    }
    if (ok) return true;
  }
  return false;
}

function typeOf(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v;
}

// objA / objB の差分パス一覧（可読形式）。
// 戻り: [{ path, a, b, kind }] — kind: 'changed'|'missing_a'|'missing_b'|'type'
//   path は 'groups.0.members.2.claimed' 形式（配列indexは数値セグメント）。
//   a/b は短縮プレビュー文字列。ignore で可変フィールド（claimed/updatedAt等）を中立化する。
export function diffPaths(objA, objB, { ignore = [] } = {}) {
  const diffs = [];

  function walk(a, b, segments) {
    if (diffs.length >= MAX_DIFFS) return;
    if (segments.length && isIgnored(segments, ignore)) return;

    const pathStr = segments.join('.');
    if (a === undefined && b === undefined) return;
    if (a === undefined) { diffs.push({ path: pathStr, a: previewValue(a), b: previewValue(b), kind: 'missing_a' }); return; }
    if (b === undefined) { diffs.push({ path: pathStr, a: previewValue(a), b: previewValue(b), kind: 'missing_b' }); return; }

    const ta = typeOf(a);
    const tb = typeOf(b);
    if (ta !== tb) { diffs.push({ path: pathStr, a: previewValue(a), b: previewValue(b), kind: 'type' }); return; }

    if (ta === 'array') {
      const len = Math.max(a.length, b.length);
      for (let i = 0; i < len; i++) walk(a[i], b[i], [...segments, i]);
      return;
    }
    if (ta === 'object') {
      const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
      for (const k of keys) walk(a[k], b[k], [...segments, k]);
      return;
    }
    if (a !== b) diffs.push({ path: pathStr, a: previewValue(a), b: previewValue(b), kind: 'changed' });
  }

  walk(objA, objB, []);
  return diffs;
}

// diffPaths の結果を1行ずつの可読文字列に整形
export function formatDiffs(diffs) {
  return diffs.map((d) => `${d.path || '(root)'}: ${d.a} != ${d.b} [${d.kind}]`);
}

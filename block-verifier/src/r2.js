// block-verifier/src/r2.js
// 公開R2（https://r2.bitcoinu.org）からのダウンロード＋ローカルキャッシュ。
// キャッシュ: ${dataDir}/block{N}/${key}（キーのパス構造をそのまま保存）。
// raw はダウンロードした生バイト（UTF-8文字列）— byte照合はこの raw を使う。
// 再利用（reuse）の可否はメインループが一括で決める（ctx.data.reuseFiles →
// setDefaultReuse() か fetchJson(key, {reuse}) で伝える）。

import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { decodeUtf8, InvalidUtf8Error } from './utf8.js';

const KiB = 1024;
const MiB = 1024 * KiB;
const GiB = 1024 * MiB;
const MAX_ATTEMPTS = 3;
const RETRY_WAIT_MS = 1500;

// R8-F1（2026-08-11）: 正常最大を実データ形状から測って決めたR2上限。
//
// 最大寄りの正常モデル（test/r2-size-limits.mjs が同じ形を毎回 byte 計測）:
//   game_selection.json は最大 2100人 × 10 deposits（R15-F1）。
//   summary.json は claim/ZKP 用の lean index で、表示詳細は分割成果物へ置く。
//   group{G}.json        testで実測（5人・チャット/受領証明最大に加え、Evidenceから
//                        正当に採用可能な生2 MiB提出×5人を parsed/raw の両形で保存）
//   claim-status/group{G}.json は最大5人×各10 deposits、uid 20桁・deposit ID 78桁・
//                        全55行claimed済みで11,922 bytes（test/r2-size-limits.mjs）。
// selection はメンバー応募情報を保持するため大きい一方、lean summary は最大形でも
// 数MiBに収まる。group は「通常クライアント」だけで測ると24 MiB未満になるが、
// Evidence採用分を含めると24 MiBを超え得るため、
// その実測値に余裕を加えた48 MiBとする。R8の24 MiB padding mockを止めるためだけに
// 24 MiBへ置くと正常な自己救済経路を拒否するので、その値は採用しない。
//
// 応募者「総数」には2100人上限が無いので、entries全体に固定累積上限をかけてはいけない。
// 代わりに writer の4 MiB chunkへ1レコード分の余裕を足した5 MiBを1ファイル上限とし、
// Stage Aが逐次hash・破棄する。厳密に2100人上限があるゲーム成果物だけ、Evidence最大を
// 420組すべてに適用したモデルにも余裕を持つブロック合計24 GiBを強制する。
export const R2_LIMITS = Object.freeze({
  unknown: 4 * MiB,
  entryInfo: 32 * MiB,
  entryChunk: 5 * MiB,
  selection: 96 * MiB,
  gameGroups: 4 * MiB,
  summary: 8 * MiB,
  groupArchive: 48 * MiB,
  autoResultPage: 4 * MiB,
  groupClaimOverlay: 16 * KiB,
  rosterIndex: 1 * MiB,
  rosterGroup: 256 * KiB,
  rosterManifest: 256 * KiB,
  manifest: 2 * MiB,
  stage3Manifest: 4 * MiB,
  evidenceReport: 16 * MiB,
  merkleMeta: 256 * KiB,
  gameBlockTotal: 24 * GiB,
  // キャッシュは検証を止める上限ではない。超えた分は保存せず検証自体は続ける。
  cacheEntryBytes: 512 * MiB,
  cacheGameBytes: 24 * GiB,
  cacheEssentialBytes: 256 * MiB,
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const byteLength = (raw) => Buffer.byteLength(raw, 'utf8');

export class R2SizeLimitError extends Error {
  constructor(key, limit, actual, source, scope = 'file') {
    super(`R2 ${scope} size limit exceeded: ${key} (${actual} bytes > ${limit} bytes; source=${source})`);
    this.name = 'R2SizeLimitError';
    this.code = 'R2_SIZE_LIMIT';
    this.key = key;
    this.limit = limit;
    this.actual = actual;
    this.source = source;
    this.scope = scope;
  }
}

export function r2LimitKind(key) {
  const k = String(key);
  if (/^entries\/block\d+\/info\/\d{2}_info\.json$/.test(k)) return 'entryInfo';
  if (/^entries\/block\d+\/entries\/\d{2}_\d+\.json$/.test(k)) return 'entryChunk';
  if (/^entries\/block\d+\/game_selection\.json$/.test(k)) return 'selection';
  if (/^entries\/block\d+\/game_groups\.json$/.test(k)) return 'gameGroups';
  if (/^games\/block-?\d+\/summary\.json$/.test(k)) return 'summary';
  if (/^games\/block\d+\/group\d+\.json$/.test(k)) return 'groupArchive';
  if (/^games\/block\d+\/auto-results\.json$/.test(k)) return 'autoResultPage';
  if (/^games\/block\d+\/claim-status\/group\d+\.json$/.test(k)) return 'groupClaimOverlay';
  if (/^games\/block\d+\/roster\/index\.json$/.test(k)) return 'rosterIndex';
  if (/^games\/block\d+\/roster\/group\d+\.json$/.test(k)) return 'rosterGroup';
  if (/^games\/block\d+\/roster\/manifest\.json$/.test(k)) return 'rosterManifest';
  if (/^verification\/block-?\d+\/manifest\.json$/.test(k)) return 'manifest';
  if (/^verification\/block\d+\/stage3\/manifest\.json$/.test(k)) return 'stage3Manifest';
  if (/^verification\/block\d+\/evidence-report\.json$/.test(k)) return 'evidenceReport';
  if (/^merkle\/block_-?\d+\.json$/.test(k)) return 'merkleMeta';
  return 'unknown';
}

export function r2LimitForKey(key, limits = R2_LIMITS) {
  return limits[r2LimitKind(key)] ?? limits.unknown;
}

function isGameBudgetKey(key) {
  const kind = r2LimitKind(key);
  return !['entryInfo', 'entryChunk', 'unknown'].includes(kind);
}

function cacheClassForKey(key) {
  const kind = r2LimitKind(key);
  if (kind === 'entryChunk') return 'entry';
  if (kind === 'groupArchive' || kind === 'groupClaimOverlay') return 'game';
  return 'essential';
}

export function createR2(cfg, ui, blockNum, options = {}) {
  const limits = options.limits || R2_LIMITS;
  const base = String(cfg.r2Base).replace(/\/+$/, '');
  const baseDir = path.resolve(cfg.dataDir, `block${blockNum}`);
  const memo = new Map(); // 同一セッション内の再取得抑止（404 の null も記憶）
  const logicalBytes = new Map(); // 同じキーのreuse/refetchを二重計上しない
  const cacheBytes = { entry: 0, game: 0, essential: 0 };
  let cacheUsagePromise = null;
  let gameBlockBytes = 0;
  let defaultReuse = false;
  let cacheWarned = false;

  // G9: パストラバーサル防止 — 解決後のパスが必ず baseDir 配下であること
  //（キーは公開データ由来（info の filename 等）なので信頼しない）。
  function cachePathFor(key) {
    const p = path.resolve(baseDir, String(key));
    if (p !== baseDir && !p.startsWith(baseDir + path.sep)) {
      throw new Error(`R2 key escapes the cache directory: ${key}`);
    }
    return p;
  }

  function sizeErrorEntry(error, pathValue = null) {
    return {
      data: undefined,
      raw: undefined,
      path: pathValue,
      sizeError: error.message,
      sizeLimit: error.limit,
      sizeActual: error.actual,
      sizeSource: error.source,
      sizeScope: error.scope,
    };
  }

  function accountLogicalBytes(key, bytes, source) {
    if (!isGameBudgetKey(key)) return;
    const prev = logicalBytes.get(key) || 0;
    const next = gameBlockBytes - prev + bytes;
    if (next > limits.gameBlockTotal) {
      throw new R2SizeLimitError(key, limits.gameBlockTotal, next, source, 'game-block-total');
    }
    logicalBytes.set(key, bytes);
    gameBlockBytes = next;
  }

  async function readHandleCapped(handle, key, limit, source) {
    const stat = await handle.stat();
    if (stat.size > limit) throw new R2SizeLimitError(key, limit, stat.size, source);
    const chunks = [];
    let total = 0;
    for await (const chunk of handle.createReadStream()) {
      total += chunk.length;
      if (total > limit) throw new R2SizeLimitError(key, limit, total, source);
      chunks.push(chunk);
    }
    return decodeUtf8(Buffer.concat(chunks, total), `R2 key ${key}`);
  }

  async function readCache(key) {
    const p = cachePathFor(key);
    let handle;
    try {
      handle = await fs.open(p, 'r');
      return await readHandleCapped(handle, key, r2LimitForKey(key, limits), 'cache');
    } catch (e) {
      if (e instanceof R2SizeLimitError || e instanceof InvalidUtf8Error) throw e;
      return null;
    } finally {
      await handle?.close().catch(() => {});
    }
  }

  async function scanCacheDir(dir, rel = '') {
    let entries;
    try { entries = await fs.readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const ent of entries) {
      const child = path.join(dir, ent.name);
      const childRel = rel ? `${rel}/${ent.name}` : ent.name;
      if (ent.isDirectory()) await scanCacheDir(child, childRel);
      else if (ent.isFile()) {
        const st = await fs.stat(child).catch(() => null);
        if (st) cacheBytes[cacheClassForKey(childRel)] += st.size;
      }
    }
  }

  async function ensureCacheUsage() {
    // Stage Aは10並列で到達する。booleanを先に立てるだけだと、2本目以降がscan完了前に
    // 予算0として書き始めるため、初期scan自体を共有Promiseにして全員が待つ。
    if (!cacheUsagePromise) cacheUsagePromise = scanCacheDir(baseDir);
    await cacheUsagePromise;
  }

  async function writeCache(key, raw) {
    await ensureCacheUsage();
    const p = cachePathFor(key);
    const bytes = byteLength(raw);
    const cls = cacheClassForKey(key);
    const cap = cls === 'entry' ? limits.cacheEntryBytes
      : cls === 'game' ? limits.cacheGameBytes : limits.cacheEssentialBytes;
    const old = await fs.stat(p).catch(() => null);
    const projected = cacheBytes[cls] - (old?.size || 0) + bytes;
    if (projected > cap) {
      if (!cacheWarned) {
        cacheWarned = true;
        ui.warn?.(`R2 cache budget reached; verification continues without caching additional files (${cls}: ${projected} > ${cap} bytes)`);
      }
      return null;
    }
    // `await writeFile` の後で加算すると並列呼出しが全員同じ残量を見て予算を突破する。
    // JSの同期区間で先に予約し、I/O失敗時だけ差分を戻す。
    const delta = bytes - (old?.size || 0);
    cacheBytes[cls] = projected;
    try {
      await fs.mkdir(path.dirname(p), { recursive: true });
      await fs.writeFile(p, raw, 'utf8');
      return p;
    } catch (e) {
      cacheBytes[cls] -= delta;
      throw e;
    }
  }

  async function responseTextCapped(res, key, limit) {
    const lengthHeader = res.headers.get('content-length');
    if (lengthHeader != null && /^\d+$/.test(lengthHeader.trim())) {
      const declared = Number(lengthHeader);
      if (Number.isSafeInteger(declared) && declared > limit) {
        await res.body?.cancel().catch(() => {});
        throw new R2SizeLimitError(key, limit, declared, 'content-length');
      }
    }
    if (!res.body) return '';
    const chunks = [];
    let total = 0;
    for await (const chunk of res.body) {
      const b = Buffer.from(chunk);
      total += b.length;
      if (total > limit) {
        await res.body?.cancel().catch(() => {});
        throw new R2SizeLimitError(key, limit, total, 'stream');
      }
      chunks.push(b);
    }
    return decodeUtf8(Buffer.concat(chunks, total), `R2 key ${key}`);
  }

  // HTTP GET（404→null / その他エラーはリトライ後 throw）。戻り: 生テキスト or null。
  async function httpGetText(key) {
    const url = `${base}/${key}`;
    const limit = r2LimitForKey(key, limits);
    let lastErr = null;
    let lastStatus = null;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        const res = await fetch(url);
        if (res.status === 404) return null;
        if (!res.ok) {
          lastStatus = res.status;
          lastErr = new Error(`HTTP ${res.status}`);
        } else {
          const raw = await responseTextCapped(res, key, limit);
          accountLogicalBytes(key, byteLength(raw), 'network');
          return raw;
        }
      } catch (e) {
        // サイズ超過は再試行しても同じで、再試行自体がDoS増幅になるため即終了。
        if (e instanceof R2SizeLimitError || e instanceof InvalidUtf8Error) throw e;
        lastErr = e;
      }
      if (attempt < MAX_ATTEMPTS) {
        ui.warn(ui.t('r2.retryWarn', { key, attempt, max: MAX_ATTEMPTS, error: lastErr?.message || String(lastErr) }));
        await sleep(RETRY_WAIT_MS * attempt);
      }
    }
    throw new Error(ui.t('r2.fetchFailed', { key, max: MAX_ATTEMPTS, error: lastStatus != null ? `HTTP ${lastStatus}` : (lastErr?.message || String(lastErr)) }));
  }

  // 🔴 F-6（2026-08-08・ラウンド20 判断不要-6）: **壊れた公開データで throw しない。**
  // parse失敗は呼び出し側の既存FAIL分岐へ合流させる。
  function parseOrMark(key, raw) {
    try {
      return { data: JSON.parse(raw) };
    } catch (e) {
      return { data: undefined, parseError: `R2 JSON parse failed: ${key}: ${e.message}` };
    }
  }

  // key を取得して {data, raw, path} を返す。404 は null。
  // cacheOnly=true はローカルキャッシュだけを読み、欠落時もネットワークへフォールバックしない。
  // Stage Aで指紋を取った応募チャンクをStage Bが同じローカル保存物から読むために使う。
  // JSON不正／サイズ超過は marker を返し、公開データのFAILとして扱わせる（fatalにしない）。
  async function fetchJson(key, opts = {}) {
    if (memo.has(key)) return memo.get(key);
    const reuse = opts.reuse ?? defaultReuse;

    if (reuse) {
      try {
        const cached = await readCache(key);
        if (cached !== null) {
          accountLogicalBytes(key, byteLength(cached), 'cache');
          const { data, parseError } = parseOrMark(key, cached);
          const entry = { data, raw: cached, path: cachePathFor(key), ...(parseError ? { parseError } : {}) };
          memo.set(key, entry);
          return entry;
        }
      } catch (e) {
        if (!(e instanceof R2SizeLimitError)) throw e;
        if (opts.cacheOnly) return sizeErrorEntry(e, cachePathFor(key));
        // 古い／細工されたローカルキャッシュだけが超過している場合は、公開R2を取り直す。
        ui.warn?.(e.message);
      }
    }

    if (opts.cacheOnly) return null;

    let raw;
    try {
      raw = await httpGetText(key);
    } catch (e) {
      if (!(e instanceof R2SizeLimitError)) throw e;
      const entry = sizeErrorEntry(e);
      memo.set(key, entry);
      return entry;
    }
    if (raw === null) {
      memo.set(key, null);
      return null;
    }
    const { data, parseError } = parseOrMark(key, raw);
    const p = await writeCache(key, raw);
    const entry = { data, raw, path: p, ...(parseError ? { parseError } : {}) };
    memo.set(key, entry);
    return entry;
  }

  // キャッシュ・memo を無視して必ずR2から取り直し、キャッシュと memo を最新で上書きする。
  async function refetch(key) {
    let raw;
    try {
      raw = await httpGetText(key);
    } catch (e) {
      if (!(e instanceof R2SizeLimitError)) throw e;
      const entry = sizeErrorEntry(e);
      memo.set(key, entry);
      return entry;
    }
    if (raw === null) {
      memo.set(key, null);
      return null;
    }
    const { data, parseError } = parseOrMark(key, raw);
    const p = await writeCache(key, raw);
    const entry = { data, raw, path: p, ...(parseError ? { parseError } : {}) };
    memo.set(key, entry);
    return entry;
  }

  // 呼び出し側が parsed data を別に保持した後、巨大raw/memoを明示的に解放する。
  function releaseRaw(key) {
    const entry = memo.get(key);
    if (entry && typeof entry === 'object') entry.raw = undefined;
  }
  function release(key) { memo.delete(key); }

  // 存在確認（HEAD。405/501 はGETフォールバックだが本文は即cancel）。404→false。
  async function exists(key) {
    if (memo.has(key)) return memo.get(key) !== null;
    if (defaultReuse) {
      try {
        const cached = await readCache(key);
        if (cached !== null) return true;
      } catch (e) {
        if (!(e instanceof R2SizeLimitError)) throw e;
      }
    }
    const url = `${base}/${key}`;
    let lastErr = null;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        let res = await fetch(url, { method: 'HEAD' });
        if (res.status === 405 || res.status === 501) res = await fetch(url);
        if (res.status === 404) { await res.body?.cancel().catch(() => {}); return false; }
        if (res.ok) { await res.body?.cancel().catch(() => {}); return true; }
        await res.body?.cancel().catch(() => {});
        lastErr = new Error(`HTTP ${res.status}`);
      } catch (e) {
        lastErr = e;
      }
      if (attempt < MAX_ATTEMPTS) {
        ui.warn(ui.t('r2.retryWarn', { key, attempt, max: MAX_ATTEMPTS, error: lastErr?.message || String(lastErr) }));
        await sleep(RETRY_WAIT_MS * attempt);
      }
    }
    throw new Error(ui.t('r2.fetchFailed', { key, max: MAX_ATTEMPTS, error: lastErr?.message || String(lastErr) }));
  }

  function setDefaultReuse(v) { defaultReuse = !!v; }

  return {
    fetchJson, refetch, exists, release, releaseRaw, setDefaultReuse,
    baseDir, blockNum,
    stats: () => ({ gameBlockBytes, cacheBytes: { ...cacheBytes }, memoEntries: memo.size }),
  };
}

function safeArtifactPath(rootDir, key) {
  const text = String(key || '');
  if (!text || text.startsWith('/') || text.includes('\\') || text.includes('..')
      || !/^[A-Za-z0-9._/-]+$/.test(text)) {
    throw new Error(`unsafe local artifact key: ${JSON.stringify(key)}`);
  }
  const root = path.resolve(rootDir);
  const target = path.resolve(root, text);
  if (!target.startsWith(`${root}${path.sep}`)) throw new Error(`artifact key escaped local root: ${text}`);
  return target;
}

// Cloudflare/R2 を一切読まない固定一式用アダプタ。通常の Stage A〜C が使う R2
// インターフェースと同じ形を保ち、refetch も同じ手元バイト列を再読する。
export function createLocalR2(cfg, ui, blockNum, options = {}) {
  const rootDir = path.resolve(options.rootDir || cfg.artifactDir || '');
  if (!options.rootDir && !cfg.artifactDir) throw new Error('local artifact directory is required');
  const limits = options.limits || R2_LIMITS;
  const memo = new Map();
  let gameBlockBytes = 0;
  const logical = new Map();
  const fileMap = options.fileMap instanceof Map ? options.fileMap : null;
  const inventoryPromise = (async () => {
    let raw;
    try { raw = await fs.readFile(safeArtifactPath(rootDir, '_emergency/bundle-index.json'), 'utf8'); }
    catch (error) { if (error?.code === 'ENOENT') return null; throw error; }
    const index = JSON.parse(raw);
    if (index?.kind !== 'bitcoinu-emergency-result-set' || index.complete !== true
        || Number(index.blockNum) !== Number(blockNum) || !Array.isArray(index.files)) {
      throw new Error('local emergency bundle index is incomplete or for a different block');
    }
    const { coreSha256, createdAt: _createdAt, complete: _complete, ...core } = index;
    const actualCore = createHash('sha256').update(JSON.stringify(core)).digest('hex');
    if (actualCore !== coreSha256) throw new Error('local emergency bundle index core sha256 mismatch');
    return new Map(index.files.map((item) => [item.key, item]));
  })();

  async function readEntry(key, { fresh = false } = {}) {
    if (!fresh && memo.has(key)) return memo.get(key);
    const mappedKey = fileMap ? (fileMap.has(key) ? fileMap.get(key) : null) : key;
    if (mappedKey === null) { memo.set(key, null); return null; }
    const filename = safeArtifactPath(rootDir, mappedKey);
    let bytes;
    try { bytes = await fs.readFile(filename); }
    catch (error) {
      if (error?.code === 'ENOENT') { memo.set(key, null); return null; }
      throw error;
    }
    const inventory = await inventoryPromise;
    const listed = inventory?.get(key);
    if (inventory && !listed) {
      throw new Error(`local emergency artifact is not declared in bundle index: ${key}`);
    }
    if (listed) {
      const actual = createHash('sha256').update(bytes).digest('hex');
      if (actual !== listed.sha256 || bytes.length !== Number(listed.bytes)) {
        throw new Error(`local emergency artifact sha256/size mismatch: ${key}`);
      }
    }
    const limit = r2LimitForKey(key, limits);
    if (bytes.length > limit) {
      const error = new R2SizeLimitError(key, limit, bytes.length, 'artifact-directory');
      const entry = { data: undefined, raw: undefined, path: filename, sizeError: error.message };
      memo.set(key, entry);
      return entry;
    }
    if (isGameBudgetKey(key)) {
      const prior = logical.get(key) || 0;
      const projected = gameBlockBytes - prior + bytes.length;
      if (projected > limits.gameBlockTotal) {
        const error = new R2SizeLimitError(key, limits.gameBlockTotal, projected, 'artifact-directory', 'block');
        const entry = { data: undefined, raw: undefined, path: filename, sizeError: error.message };
        memo.set(key, entry);
        return entry;
      }
      logical.set(key, bytes.length);
      gameBlockBytes = projected;
    }
    let raw;
    try { raw = decodeUtf8(bytes, `local artifact ${key}`); }
    catch (error) {
      const entry = { data: undefined, raw: undefined, path: filename, parseError: error.message };
      memo.set(key, entry);
      return entry;
    }
    let data;
    let parseError;
    try { data = JSON.parse(raw); }
    catch (error) { parseError = `local artifact JSON parse failed: ${key}: ${error.message}`; }
    const entry = { data, raw, path: filename, source: 'artifact-directory', ...(parseError ? { parseError } : {}) };
    memo.set(key, entry);
    return entry;
  }

  return {
    fetchJson: (key) => readEntry(key),
    refetch: (key) => readEntry(key, { fresh: true }),
    exists: async (key) => {
      const mappedKey = fileMap ? (fileMap.has(key) ? fileMap.get(key) : null) : key;
      if (mappedKey === null) return false;
      try { await fs.access(safeArtifactPath(rootDir, mappedKey)); return true; }
      catch (error) { if (error?.code === 'ENOENT') return false; throw error; }
    },
    release: (key) => memo.delete(key),
    releaseRaw: (key) => { const entry = memo.get(key); if (entry) entry.raw = undefined; },
    setDefaultReuse: () => {},
    baseDir: rootDir,
    blockNum,
    stats: () => ({ gameBlockBytes, cacheBytes: { entry: 0, game: 0, essential: 0 }, memoEntries: memo.size }),
  };
}

import { createPublicClient, http } from 'viem';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { createReadStream, createWriteStream, rmSync } from 'node:fs';
import { mkdtemp, open, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { rosterAnchorKey, selectCanonicalRosterRegistration } from '../../../../workers/game_workers/lib/roster-anchor-rule.js';
import { buildRosterMemberCommitment } from '../../../../workers/game_workers/lib/roster-member-root.js';
import {
  ANCHOR_PROVIDER_ABI,
  CLAIM_DATA_EVENT_ABI,
  CONFIRMATION_BLOCKS,
  EVIDENCE_ABI,
  HASH_STORAGE_ABI,
  PREV_REGISTRATION_SENTINEL,
  TOKEN_MINING_ABI,
  ZERO_ADDRESS,
  ZERO_HASH,
  chunkChainHash,
  extractManifestCore,
  recoverClaimDataChunks,
  requireAddress,
  requireBlockNum,
  requireBytes32,
  sha256Hex,
  toJsonNumber,
  tupleValue,
} from './zkp-pipeline.mjs';

export const ZKP_INPUT_LIMITS = Object.freeze({
  manifestBytes: 8 * 1024 * 1024,
  selectionBytes: 96 * 1024 * 1024,
  stage3ManifestBytes: 1024 * 1024,
  stage3WitnessManifestBytes: 256 * 1024,
  stage3WitnessBytesPerGroup: 64 * 1024 * 1024,
  stage3WitnessBytesTotal: 16 * 1024 * 1024 * 1024,
  stage3Groups: 530,
  rosterManifestBytes: 256 * 1024,
  rosterGroupBytes: 1024 * 1024,
  rosterGroups: 700,
  summaryBytes: 8 * 1024 * 1024,
  merkleBytes: 16 * 1024 * 1024,
  totalR2Bytes: 113 * 1024 * 1024 + 256 * 1024,
  claimChunks: 8192,
  serializedBytes: 16 * 1024 * 1024,
});

function artifactMismatchError(message) {
  const error = new Error(message);
  error.zkpArtifactMismatch = true;
  return error;
}

export function parseRecordedPreviousRegistration(gameGroups, { blockNum } = {}) {
  if (blockNum === 0) return null;
  if (!gameGroups || gameGroups.blockNum !== blockNum) {
    throw artifactMismatchError(`block ${blockNum} game_groups.json is missing or inconsistent`);
  }
  const row = gameGroups.prevResultRegistration;
  if (row?.status === 'none' && Object.keys(row).length === 1) return null;
  if (!row || typeof row !== 'object' || Array.isArray(row)
      || !/^(0|[1-9]\d*)$/.test(String(row.index ?? ''))
      || !/^[1-9]\d*$/.test(String(row.registeredBlock ?? ''))
      || !/^[1-9]\d*$/.test(String(row.registeredAt ?? ''))
      || !/^0x[0-9a-f]{64}$/.test(String(row.hash ?? ''))) {
    throw artifactMismatchError(`block ${blockNum} has invalid prevResultRegistration`);
  }
  return row;
}

function markStage3ArtifactInvalid(error) {
  error.zkpArtifactInvalid = true;
  return error;
}

function chainAnchorMismatchError(message) {
  const error = artifactMismatchError(message);
  error.zkpChainAnchorMismatch = true;
  return error;
}

function safeArtifactPath(rootDir, key) {
  const relative = String(key || '');
  if (!relative || relative.startsWith('/') || relative.includes('\\') || relative.includes('..')
      || !/^[A-Za-z0-9._/-]+$/.test(relative)) {
    throw new Error(`固定一式の相対pathが不正です: ${JSON.stringify(key)}`);
  }
  const root = path.resolve(rootDir);
  const resolved = path.resolve(root, relative);
  if (!resolved.startsWith(`${root}${path.sep}`)) throw new Error(`固定一式の外を参照しました: ${relative}`);
  return resolved;
}

/** Q24: B が作った完全な固定一式だけを読む fetch。HTTP への fallback は持たない。 */
export function createArtifactDirectoryFetch(artifactDir, { blockNum = null } = {}) {
  const root = path.resolve(artifactDir);
  const inventoryPromise = (async () => {
    const index = JSON.parse(await readFile(safeArtifactPath(root, '_emergency/bundle-index.json'), 'utf8'));
    if (index?.kind !== 'bitcoinu-emergency-result-set' || index.complete !== true
        || !Array.isArray(index.files)
        || (blockNum != null && Number(index.blockNum) !== Number(blockNum))) {
      throw new Error('緊急固定一式のbundle indexが未完成、またはblockNumが不一致です');
    }
    const { coreSha256, createdAt: _createdAt, complete: _complete, ...core } = index;
    const actualCore = createHash('sha256').update(JSON.stringify(core)).digest('hex');
    if (actualCore !== coreSha256) {
      throw artifactMismatchError('緊急固定一式のbundle index core sha256が不一致です');
    }
    return { index, files: new Map(index.files.map((item) => [item.key, item])) };
  })();
  return async function artifactFetch(url) {
    const prefix = 'artifact://q24/';
    const text = String(url);
    if (!text.startsWith(prefix)) throw new Error(`固定一式モードが外部URLを拒否しました: ${text}`);
    const key = decodeURIComponent(text.slice(prefix.length));
    const { files } = await inventoryPromise;
    const declared = files.get(key);
    if (!declared) return new Response(null, { status: 404 });
    let bytes;
    try { bytes = await readFile(safeArtifactPath(root, key)); }
    catch (error) { if (error?.code === 'ENOENT') return new Response(null, { status: 404 }); throw error; }
    const actual = createHash('sha256').update(bytes).digest('hex');
    if (actual !== declared.sha256 || bytes.length !== Number(declared.bytes)) {
      throw artifactMismatchError(`緊急固定一式のsha256/size不一致: ${key}`);
    }
    return new Response(bytes, {
      status: 200,
      headers: { 'content-type': 'application/json', 'content-length': String(bytes.length) },
    });
  };
}

export async function fetchRawBounded(fetchImpl, base, key, maxBytes, { sinkPath = null } = {}) {
  const url = `${base.replace(/\/$/, '')}/${key}`;
  const response = await fetchImpl(url, { headers: { accept: 'application/json' } });
  if (!response.ok) {
    const error = new Error(`R2 ${key}: HTTP ${response.status}`);
    if (response.status === 404) error.zkpArtifactMissing = true;
    else error.zkpArtifactFetchError = true;
    throw error;
  }
  const declared = response.headers?.get?.('content-length');
  const declaredBytes = declared == null ? null : Number(declared);
  if (declaredBytes != null && (!Number.isSafeInteger(declaredBytes) || declaredBytes < 0)) {
    throw new Error(`R2 ${key}: Content-Length が不正です`);
  }
  if (declaredBytes != null && declaredBytes > maxBytes) {
    throw new Error(`R2 ${key}: Content-Length ${declaredBytes} > limit ${maxBytes}`);
  }
  const chunks = sinkPath ? null : [];
  const hash = createHash('sha256');
  const sink = sinkPath ? createWriteStream(sinkPath, { flags: 'wx' }) : null;
  // 検証上限超過でdestroyした後に、既にkernelへ渡ったwriteが遅れてERR_STREAM_DESTROYEDを
  // emitしてもunhandledにしない。実際の書込失敗は下の一時listener／finish待機がthrowする。
  if (sink) sink.on('error', () => {});
  const writeSink = (value) => new Promise((resolve, reject) => {
    if (!sink) return resolve();
    const onError = (error) => { sink.off('drain', onDrain); reject(error); };
    const onDrain = () => { sink.off('error', onError); resolve(); };
    sink.once('error', onError);
    if (sink.write(value)) { sink.off('error', onError); resolve(); }
    else sink.once('drain', onDrain);
  });
  let total = 0;
  try {
    if (response.body?.getReader) {
      const reader = response.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel().catch(() => {});
          throw new Error(`R2 ${key}: actual bytes ${total} > limit ${maxBytes}`);
        }
        const chunk = Buffer.from(value);
        hash.update(chunk);
        if (sink) await writeSink(chunk);
        else chunks.push(chunk);
      }
    } else {
      const one = Buffer.from(await response.arrayBuffer());
      total = one.length;
      if (total > maxBytes) throw new Error(`R2 ${key}: actual bytes ${total} > limit ${maxBytes}`);
      hash.update(one);
      if (sink) await writeSink(one);
      else chunks.push(one);
    }
    if (declaredBytes != null && total !== declaredBytes) {
      throw new Error(`R2 ${key}: truncated/length mismatch declared=${declaredBytes} actual=${total}`);
    }
    if (!total) throw new Error(`R2 ${key}: 空ファイルです`);
    if (sink) {
      const finished = once(sink, 'finish');
      sink.end();
      await finished;
    }
    return {
      url,
      bytes: chunks ? Buffer.concat(chunks, total) : null,
      path: sinkPath,
      byteLength: total,
      sha256: `0x${hash.digest('hex')}`,
    };
  } catch (error) {
    if (sink && !sink.destroyed) sink.destroy();
    throw error;
  }
}

function bytesToHexIncremental(bytes, chunkBytes = 1024 * 1024) {
  const parts = ['0x'];
  for (let offset = 0; offset < bytes.length; offset += chunkBytes) {
    parts.push(bytes.subarray(offset, Math.min(offset + chunkBytes, bytes.length)).toString('hex'));
  }
  return parts.join('');
}

function parseJson(bytes, label) {
  try { return JSON.parse(bytes.toString('utf8')); }
  catch (error) { throw new Error(`${label} のJSONが不正です: ${error.message}`); }
}

export const LEGACY_HASH_STORAGE_ALLOWLIST = Object.freeze([
  '0xd2c8a3be50d9a158bd579a26a346f54cfb93426d',
]);
const LEGACY_HASH_STORAGE_SET = new Set(LEGACY_HASH_STORAGE_ALLOWLIST);

function selectionRegistration(selection) {
  const value = selection.hashRegisteredBlock;
  if (value !== undefined && value !== null && (!Number.isSafeInteger(value) || value < 0)) {
    throw new Error('game_selection.json のhashRegisteredBlockが不正です');
  }
  const registeredBlock = value == null ? 0n : BigInt(value);
  const applicantHash = selection.applicantHash == null
    ? ZERO_HASH
    : requireBytes32(selection.applicantHash, 'game_selection.json applicantHash');
  if ((registeredBlock === 0n) !== (applicantHash === ZERO_HASH)) {
    throw new Error('game_selection.json のapplicantHash/hashRegisteredBlockの番兵値が一致しません');
  }
  return { applicantHash, registeredBlock, sentinel: registeredBlock === 0n };
}

/** manifestでbyte固定された抽選登録を読み、同じsnapshotのHashStorage履歴と照合する。 */
export async function readApplicantRegistrationForProof({
  fetchImpl,
  r2Base,
  manifest,
  readAt,
  hashStorage: hashStorageRaw,
  blockNum: blockNumRaw,
}) {
  const blockNum = requireBlockNum(blockNumRaw);
  const bn = BigInt(blockNum);
  const hashStorage = requireAddress(hashStorageRaw, 'HashStorage');
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)
      || !Number.isSafeInteger(manifest.blockNum) || manifest.blockNum !== blockNum) {
    throw new Error('manifest.json のblockNumが指定ブロックと一致しません');
  }
  const selectionKey = `entries/block${blockNum}/game_selection.json`;
  const files = manifest.files;
  if (!files || typeof files !== 'object' || Array.isArray(files)
      || !Object.prototype.hasOwnProperty.call(files, selectionKey)) {
    throw new Error(`manifest に ${selectionKey} がありません`);
  }
  const declaredHash = String(files[selectionKey]);
  if (!/^(?:0x)?[0-9a-fA-F]{64}$/.test(declaredHash)) {
    throw new Error(`manifest内game_selection sha256が不正です: ${declaredHash}`);
  }
  const selectionFile = await fetchRawBounded(
    fetchImpl, r2Base, selectionKey, ZKP_INPUT_LIMITS.selectionBytes,
  );
  const actualHash = selectionFile.sha256.slice(2);
  if (declaredHash.toLowerCase().replace(/^0x/, '') !== actualHash) {
    throw artifactMismatchError(`manifest内game_selection sha256不一致: declared=${declaredHash} actual=${actualHash}`);
  }
  const selection = parseJson(selectionFile.bytes, 'game_selection.json');
  if (!selection || typeof selection !== 'object' || Array.isArray(selection)
      || !Number.isSafeInteger(selection.blockNum) || selection.blockNum !== blockNum) {
    throw new Error('game_selection.json のblockNumが指定ブロックと一致しません');
  }
  const selected = selectionRegistration(selection);

  if (LEGACY_HASH_STORAGE_SET.has(hashStorage.toLowerCase())) {
    const latest = await readAt({
      address: hashStorage, abi: HASH_STORAGE_ABI, functionName: 'applicantHashes', args: [bn],
    });
    const applicantHash = requireBytes32(tupleValue(latest, 0, 'hash'), 'HashStorage.applicantHashes.hash');
    const applicantHashUpdatedBlock = BigInt(tupleValue(latest, 1, 'updated'));
    return {
      applicantHash,
      applicantHashUpdatedBlock,
      selection,
      selectionFile,
      legacyFallback: true,
    };
  }

  let registrationCount;
  try {
    registrationCount = BigInt(await readAt({
      address: hashStorage, abi: HASH_STORAGE_ABI, functionName: 'registrationCount', args: [bn],
    }));
  } catch (error) {
    throw new Error(`HashStorage ${hashStorage} の登録履歴getterを読めません`, { cause: error });
  }
  if (registrationCount < 0n) throw new Error('HashStorage.registrationCountが不正です');
  if (registrationCount === 0n) {
    if (!selected.sentinel) {
      throw new Error('登録0件のgame_selection.jsonはapplicantHash/hashRegisteredBlockが番兵値である必要があります');
    }
    return {
      applicantHash: ZERO_HASH,
      applicantHashUpdatedBlock: 0n,
      registrationCount,
      selection,
      selectionFile,
      legacyFallback: false,
    };
  }

  if (selected.sentinel) {
    throw new Error('登録済みのgame_selection.jsonにapplicantHash/hashRegisteredBlockがありません');
  }
  const applicantHash = selected.applicantHash;
  const applicantHashUpdatedBlock = selected.registeredBlock;
  let registered;
  try {
    registered = await readAt({
      address: hashStorage,
      abi: HASH_STORAGE_ABI,
      functionName: 'isApplicantRegistered',
      args: [bn, applicantHashUpdatedBlock, applicantHash],
    });
  } catch (error) {
    throw new Error(`HashStorage ${hashStorage} の登録履歴getterを読めません`, { cause: error });
  }
  if (registered !== true) {
    throw new Error(
      `game_selection.json の登録がHashStorage履歴にありません: block=${blockNum} registeredBlock=${applicantHashUpdatedBlock}`,
    );
  }
  return {
    applicantHash,
    applicantHashUpdatedBlock,
    registrationCount,
    selection,
    selectionFile,
    legacyFallback: false,
  };
}

function invalidNamedPrevRegistrationError(message) {
  const error = new Error(message);
  error.zkpInvalidPrevRegistration = true;
  return error;
}

/**
 * word7（`prevResultManifestHash`）を **名乗る登録の行**から作り、同時にその**添字**を返す。
 *
 * ユーザーの逐語（2026-09-22）:
 *   「私が提案したのは、「ZKP提出者が一致するハッシュの履歴中のインデックスをTokenMiningにZKPとともに引数で渡す」です。」
 *   「つまり、NブロックのZKP提出で指定されてるインデックスのハッシュを使えば良いわけです。」
 * **最新行を名乗る**のは統括の実装方針である。名乗る行の選び方は Stage 4 配線の
 * 必須条件として持ち越した（R30-U-2）。省略時はこの既定を変えず、履歴の最終行を名乗る。
 * `namedPrevRegistrationIndex` は、既に提出された証明が名乗った行を検証側で再現するときだけ使う。
 *
 * 契約の word7 照合は次の3点だけで時刻を使わない（TokenMining._checkAnchors の prevResultManifestHash 照合）:
 *   ① 添字が範囲内（`prevRegistrationIndex < resultRegistrationCount(N-1)`）
 *   ② その行のハッシュが word7 と一致
 *   ③ 番兵（`type(uint256).max`）は履歴0件のときだけ
 *
 * 旧 HashStorage（`LEGACY_HASH_STORAGE_ALLOWLIST`）には結果側の履歴getterが無い。
 * その場合だけ word7 は現在値へフォールバックし、**添字は `null`** を返す。
 * `null` では7引数 calldata を組めない＝旧契約相手に証明付き提出はできない（fail-closed）。
 */
export async function readPrevResultRegistrationForProof({
  readAt,
  hashStorage: hashStorageRaw,
  blockNum: blockNumRaw,
  namedPrevRegistrationIndex = undefined,
}) {
  const blockNum = requireBlockNum(blockNumRaw);
  const hashStorage = requireAddress(hashStorageRaw, 'HashStorage');
  const hasNamedPrevRegistrationIndex = namedPrevRegistrationIndex !== undefined;
  if (hasNamedPrevRegistrationIndex
      && (typeof namedPrevRegistrationIndex !== 'bigint'
        || namedPrevRegistrationIndex < 0n
        || namedPrevRegistrationIndex > PREV_REGISTRATION_SENTINEL)) {
    throw invalidNamedPrevRegistrationError(
      'namedPrevRegistrationIndex は uint256 bigint である必要があります',
    );
  }
  // ブロック0は前ブロックが無い。契約は `if (blockNum > 0)` で履歴を読まず prev=0 で束縛する
  // （TokenMining._checkAnchors）。オフチェーンは番兵を名乗る。
  if (blockNum === 0) {
    return {
      prevResultManifestHash: ZERO_HASH,
      prevRegistrationIndex: PREV_REGISTRATION_SENTINEL,
      prevRegistrationCount: 0n,
      legacyFallback: false,
    };
  }
  const prevBlock = BigInt(blockNum - 1);
  if (LEGACY_HASH_STORAGE_SET.has(hashStorage.toLowerCase())) {
    const latest = await readAt({
      address: hashStorage, abi: HASH_STORAGE_ABI, functionName: 'resultHashes', args: [prevBlock],
    });
    return {
      prevResultManifestHash: requireBytes32(
        tupleValue(latest, 0, 'hash'), 'HashStorage.resultHashes.hash',
      ),
      prevRegistrationIndex: null,
      prevRegistrationCount: null,
      legacyFallback: true,
    };
  }
  let count;
  try {
    count = BigInt(await readAt({
      address: hashStorage, abi: HASH_STORAGE_ABI, functionName: 'resultRegistrationCount', args: [prevBlock],
    }));
  } catch (error) {
    // 🔴 統括（2026-09-22）: 履歴 getter が無い契約の扱いは **allowlist に載るアドレスだけ**に限る。
    //    載っていないアドレスで getter が無いのは「アドレスが違う」か「敵対的な配備」なので
    //    **止める**（fail-closed）。allowlist に載る旧契約だけ現在値へ落とす。
    //    🔴 落としても fail-open ではない: prevRegistrationIndex を null で返すので呼び出し側が
    //    添字を組めず、契約へ7引数で出す段で必ず止まる。
    if (!LEGACY_HASH_STORAGE_ALLOWLIST.includes(String(hashStorage).toLowerCase())) {
      throw new Error(`HashStorage ${hashStorage} の結果登録履歴getterを読めません`, { cause: error });
    }
    const latestOnly = await readAt({
      address: hashStorage, abi: HASH_STORAGE_ABI, functionName: 'resultHashes', args: [prevBlock],
    });
    return {
      prevResultManifestHash: requireBytes32(
        tupleValue(latestOnly, 0, 'hash'), 'HashStorage.resultHashes.hash',
      ),
      prevRegistrationIndex: null,
      prevRegistrationCount: null,
      legacyFallback: true,
      legacyReason: `HashStorage ${hashStorage} の結果登録履歴getterを読めません: ${String(error?.message || error)}`,
    };
  }
  if (count < 0n) throw new Error('HashStorage.resultRegistrationCountが不正です');
  if (count === 0n) {
    if (hasNamedPrevRegistrationIndex
        && namedPrevRegistrationIndex !== PREV_REGISTRATION_SENTINEL) {
      throw invalidNamedPrevRegistrationError(
        `名乗った前ブロック結果登録の添字が範囲外です: block=${blockNum - 1}`
        + ` index=${namedPrevRegistrationIndex} count=0`,
      );
    }
    const latest = await readAt({
      address: hashStorage, abi: HASH_STORAGE_ABI, functionName: 'resultHashes', args: [prevBlock],
    });
    const latestHash = requireBytes32(
      tupleValue(latest, 0, 'hash'), 'HashStorage.resultHashes.hash',
    ).toLowerCase();
    let latestUpdated;
    try { latestUpdated = BigInt(tupleValue(latest, 1, 'updated')); }
    catch { throw new Error('HashStorage.resultHashes.updatedが不正です'); }
    if (latestUpdated < 0n) throw new Error('HashStorage.resultHashes.updatedが不正です');
    if (latestHash !== ZERO_HASH || latestUpdated !== 0n) {
      throw new Error(
        `HashStorage 結果登録履歴は0件ですが最新ビューが非ゼロです: block=${blockNum - 1}`
        + ` hash=${latestHash} updated=${latestUpdated} — 0履歴の番兵を名乗りません`,
      );
    }
    return {
      prevResultManifestHash: ZERO_HASH,
      prevRegistrationIndex: PREV_REGISTRATION_SENTINEL,
      prevRegistrationCount: 0n,
      legacyFallback: false,
    };
  }
  if (hasNamedPrevRegistrationIndex && namedPrevRegistrationIndex === PREV_REGISTRATION_SENTINEL) {
    throw invalidNamedPrevRegistrationError(
      `前ブロック結果登録が${count}件あるため番兵を名乗れません: block=${blockNum - 1}`,
    );
  }
  const prevRegistrationIndex = hasNamedPrevRegistrationIndex
    ? namedPrevRegistrationIndex
    : count - 1n;
  if (prevRegistrationIndex >= count) {
    throw invalidNamedPrevRegistrationError(
      `名乗った前ブロック結果登録の添字が範囲外です: block=${blockNum - 1}`
      + ` index=${prevRegistrationIndex} count=${count}`,
    );
  }
  let row;
  try {
    row = await readAt({
      address: hashStorage,
      abi: HASH_STORAGE_ABI,
      functionName: 'resultRegistrationAt',
      args: [prevBlock, prevRegistrationIndex],
    });
  } catch (error) {
    // 🔴 統括（2026-09-22）: 履歴 getter が無い契約の扱いは **allowlist に載るアドレスだけ**に限る。
    //    載っていないアドレスで getter が無いのは「アドレスが違う」か「敵対的な配備」なので
    //    **止める**（fail-closed）。allowlist に載る旧契約だけ現在値へ落とす。
    //    🔴 落としても fail-open ではない: prevRegistrationIndex を null で返すので呼び出し側が
    //    添字を組めず、契約へ7引数で出す段で必ず止まる。
    if (!LEGACY_HASH_STORAGE_ALLOWLIST.includes(String(hashStorage).toLowerCase())) {
      throw new Error(`HashStorage ${hashStorage} の結果登録履歴getterを読めません`, { cause: error });
    }
    const latestOnly = await readAt({
      address: hashStorage, abi: HASH_STORAGE_ABI, functionName: 'resultHashes', args: [prevBlock],
    });
    return {
      prevResultManifestHash: requireBytes32(
        tupleValue(latestOnly, 0, 'hash'), 'HashStorage.resultHashes.hash',
      ),
      prevRegistrationIndex: null,
      prevRegistrationCount: null,
      legacyFallback: true,
      legacyReason: `HashStorage ${hashStorage} の結果登録履歴getterを読めません: ${String(error?.message || error)}`,
    };
  }
  const prevResultManifestHash = requireBytes32(
    tupleValue(row, 0, 'hash'), 'HashStorage.resultRegistrationAt.hash',
  );
  const registeredBlock = BigInt(tupleValue(row, 1, 'registeredBlock'));
  const registeredAt = BigInt(tupleValue(row, 2, 'registeredAt'));
  if (prevRegistrationIndex === count - 1n) {
    // `registerResultHash` は同じ呼び出しで `_resultRegistrations[bn][count]` と
    // `resultHashes[bn]` の両方を書いてから count++ する（HashStorage.registerResultHash）ので、
    // 履歴の最終行は最新ビューと必ず一致する。ずれたら読取が別snapshotを跨いでいる。
    // 任意引数を省略した従来経路と、最新行を明示した経路はこの検査まで同一である。
    const latest = await readAt({
      address: hashStorage, abi: HASH_STORAGE_ABI, functionName: 'resultHashes', args: [prevBlock],
    });
    const latestHash = String(tupleValue(latest, 0, 'hash')).toLowerCase();
    if (latestHash !== prevResultManifestHash) {
      throw new Error(
        `HashStorage 結果登録履歴の最終行が最新ビューと一致しません: block=${blockNum - 1}`
        + ` index=${prevRegistrationIndex} history=${prevResultManifestHash} latest=${latestHash}`,
      );
    }
  }
  return { prevResultManifestHash, prevRegistrationIndex, prevRegistrationCount: count,
    registeredBlock, registeredAt, legacyFallback: false };
}

export function validateStage3InputManifest(manifest, { blockNum, rawText = null } = {}) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)
      || manifest.schemaVersion !== 1 || manifest.kind !== 'bitcoinu-stage3-input-manifest') {
    throw new Error('Stage 3 input manifest のschema/kindが不正です');
  }
  if (Number(manifest.blockNum) !== Number(blockNum)) {
    throw new Error('Stage 3 input manifest のblockNumが一致しません');
  }
  if (!Number.isInteger(manifest.groupCount) || manifest.groupCount < 0 || manifest.groupCount > 530
      || !Array.isArray(manifest.groups) || manifest.groups.length !== manifest.groupCount) {
    throw new Error('Stage 3 input manifest のgroupCountは0..530でgroups件数と一致する必要があります');
  }
  for (const [index, group] of manifest.groups.entries()) {
    const groupId = group?.groupId;
    const expectedObject = `verification/block${blockNum}/stage3/group-${groupId}.json`;
    if (groupId !== index) {
      throw new Error(`Stage 3 input manifest groups[${index}].groupIdは${index}である必要があります`);
    }
    if (group.object !== expectedObject || !/^[0-9a-f]{64}$/.test(String(group.sha256 || ''))) {
      throw new Error(`Stage 3 input manifest groups[${index}]のobject/sha256が不正です`);
    }
  }
  if (rawText !== null && JSON.stringify(manifest) !== rawText) {
    throw artifactMismatchError('Stage 3 input manifest が正準 minified JSON.stringify ではありません');
  }
  return manifest;
}

export function parseStage3WitnessManifest(bytes, blockNumRaw) {
  const blockNum = requireBlockNum(blockNumRaw);
  const manifest = parseJson(Buffer.from(bytes), 'Stage 3 witness manifest');
  if (manifest?.schemaVersion !== 1 || Number(manifest.blockNum) !== blockNum) {
    throw new Error('Stage 3 witness manifest のschemaVersion/blockNumが不正です');
  }
  if (!Number.isSafeInteger(manifest.groupCount)
      || manifest.groupCount < 0 || manifest.groupCount > ZKP_INPUT_LIMITS.stage3Groups
      || !Array.isArray(manifest.files) || manifest.files.length !== manifest.groupCount) {
    throw new Error('Stage 3 witness manifest のgroupCount/filesが不正です');
  }
  let totalBytes = 0;
  const files = manifest.files.map((file, index) => {
    const groupId = file?.groupId;
    const byteLength = Number(file?.bytes);
    const expectedKey = `zkp/block${blockNum}/group-${groupId}.json`;
    if (groupId !== index
        || file?.key !== expectedKey || !/^[0-9a-f]{64}$/.test(String(file?.sha256 || ''))
        || !Number.isSafeInteger(byteLength) || byteLength <= 0
        || byteLength > ZKP_INPUT_LIMITS.stage3WitnessBytesPerGroup) {
      throw new Error(`Stage 3 witness manifest files[${index}] が不正です`);
    }
    totalBytes += byteLength;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > ZKP_INPUT_LIMITS.stage3WitnessBytesTotal) {
      throw new Error(`Stage 3 witness 合計bytes ${totalBytes} > limit ${ZKP_INPUT_LIMITS.stage3WitnessBytesTotal}`);
    }
    return { groupId, key: file.key, sha256: file.sha256, bytes: byteLength };
  });
  return { schemaVersion: 1, blockNum, groupCount: files.length, files, totalBytes };
}

async function readClaimDataLogs(client, tokenMining, blockNum, blockNumbers) {
  const unique = [...new Set(blockNumbers.map((value) => BigInt(value).toString()))];
  const batches = await Promise.all(unique.map((number) => client.getContractEvents({
    address: tokenMining,
    abi: CLAIM_DATA_EVENT_ABI,
    eventName: 'ClaimDataPublished',
    args: { blockNum: BigInt(blockNum) },
    fromBlock: BigInt(number),
    toBlock: BigInt(number),
    strict: true,
  })));
  return batches.flat();
}

export function serializeZkpInput(input) {
  return Buffer.from(JSON.stringify(input));
}

export function zkpInputHash(input) {
  return sha256Hex(serializeZkpInput(input));
}

async function summaryBlockNumFromCanonicalPrefix(filePath) {
  const handle = await open(filePath, 'r');
  try {
    const prefix = Buffer.alloc(64 * 1024);
    const { bytesRead } = await handle.read(prefix, 0, prefix.length, 0);
    const text = prefix.subarray(0, bytesRead).toString('utf8');
    const match = /^\{(?:"schemaVersion":(?:0|[1-9]\d*),)?"blockNum":(0|[1-9]\d*)(?:,|\})/.exec(text);
    if (!match) {
      throw artifactMismatchError('summary.json の先頭が正準schemaVersion/blockNum順ではありません');
    }
    return Number(match[1]);
  } finally {
    await handle.close();
  }
}

async function writePart(stream, value) {
  if (stream.write(value)) return;
  await once(stream, 'drain');
}

// summary bytesをメモリ上の巨大hex文字列へせず、同じ一時ファイルからhex化→hash→uploadする。
export async function serializeZkpInputToFile({ prefixFields, summaryPath, tailFields, outPath, maxBytes }) {
  const output = createWriteStream(outPath, { flags: 'wx' });
  // maxBytes超過時の意図的destroyとpending writeの競合をunhandled errorにしない。
  // 通常のI/O errorはwritePartまたはfinish待機から呼び出し元へ伝播する。
  output.on('error', () => {});
  const hash = createHash('sha256');
  let bytes = 0;
  const emit = async (value) => {
    const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
    bytes += chunk.length;
    if (bytes > maxBytes) throw new Error(`serialized ZKP input ${bytes} > limit ${maxBytes}`);
    hash.update(chunk);
    await writePart(output, chunk);
  };
  try {
    const prefixJson = JSON.stringify({ ...prefixFields, summaryHex: '__SUMMARY_HEX__' });
    const marker = '"__SUMMARY_HEX__"';
    const at = prefixJson.indexOf(marker);
    await emit(`${prefixJson.slice(0, at)}"0x`);
    for await (const chunk of createReadStream(summaryPath, { highWaterMark: 1024 * 1024 })) {
      await emit(Buffer.from(chunk).toString('hex'));
    }
    const tailJson = JSON.stringify(tailFields);
    await emit(`"${tailJson === '{}' ? '}' : `,${tailJson.slice(1)}`}`);
    const finished = once(output, 'finish');
    output.end();
    await finished;
    return { path: outPath, byteLength: bytes, sha256: `0x${hash.digest('hex')}` };
  } catch (error) {
    output.destroy();
    throw error;
  }
}

/**
 * Z2 CLI と G2 Cloud Run が共有する収集コア。入力は public RPC と public R2 のみ。
 * signer・秘密鍵・R2 credential を受け取る引数自体を持たない。
 */
/// R31-U-C: 正典名簿を共有規則で履歴から再計算し、契約 view とも突き合わせる。
export async function readCanonicalRosterHash({ readAt, evidence, hashStorage, blockNum, graceSec }) {
  const bn = BigInt(requireBlockNum(blockNum));
  const entryEnd = BigInt(await readAt({
    address: evidence, abi: EVIDENCE_ABI, functionName: 'scheduledGameStart', args: [bn],
  }));
  const start = entryEnd + BigInt(graceSec);
  const key = rosterAnchorKey(blockNum);
  const count = await readAt({
    address: hashStorage, abi: HASH_STORAGE_ABI, functionName: 'otherRegistrationCount', args: [key],
  });
  const selected = await selectCanonicalRosterRegistration({
    count: Number(count), entryEndSec: Number(entryEnd), chattingStartSec: Number(start), nowSec: Number(start),
    at: async (index) => {
      const row = await readAt({
        address: hashStorage, abi: HASH_STORAGE_ABI, functionName: 'otherRegistrationAt',
        args: [key, BigInt(index)],
      });
      return {
        hash: tupleValue(row, 0, 'hash'),
        registeredBlock: Number(tupleValue(row, 1, 'registeredBlock')),
        registeredAt: Number(tupleValue(row, 2, 'registeredAt')),
      };
    },
  });
  const hash = selected.row?.hash ?? ZERO_HASH;
  const view = await readAt({
    address: hashStorage, abi: HASH_STORAGE_ABI, functionName: 'rosterLastIn',
    args: [bn, entryEnd, start],
  });
  if (String(tupleValue(view, 1, 'hash')).toLowerCase() !== hash.toLowerCase()) {
    throw new Error('HashStorage.rosterLastIn と追記履歴の正典名簿が不一致です');
  }
  return hash;
}

/** 組分けが採用できた前ブロックの登録行の時刻上限（秒）。 */
export async function deriveGroupingUpperBoundForProof({
  readAt, evidence, hashStorage, blockNum, graceSec = null, rosterHash = null,
}) {
  const bn = BigInt(requireBlockNum(blockNum));
  const entryEnd = BigInt(await readAt({
    address: evidence, abi: EVIDENCE_ABI, functionName: 'scheduledGameStart', args: [bn],
  }));
  const grace = graceSec == null ? BigInt(await readAt({
    address: evidence, abi: EVIDENCE_ABI, functionName: 'currentGrace', args: [bn],
  })) : BigInt(graceSec);
  const chattingStart = entryEnd + grace;
  const canonicalHash = rosterHash ?? await readCanonicalRosterHash({
    readAt, evidence, hashStorage, blockNum, graceSec: grace,
  });
  if (String(canonicalHash).toLowerCase() === ZERO_HASH) return chattingStart;
  const key = rosterAnchorKey(blockNum);
  const count = BigInt(await readAt({
    address: hashStorage, abi: HASH_STORAGE_ABI, functionName: 'otherRegistrationCount', args: [key],
  }));
  for (let index = 0n; index < count; index++) {
    const row = await readAt({
      address: hashStorage, abi: HASH_STORAGE_ABI, functionName: 'otherRegistrationAt', args: [key, index],
    });
    const at = BigInt(tupleValue(row, 2, 'registeredAt'));
    if (at < entryEnd) continue;
    if (at >= chattingStart) break;
    if (String(tupleValue(row, 0, 'hash')).toLowerCase() === String(canonicalHash).toLowerCase()) {
      return at;
    }
  }
  return chattingStart;
}

export function assertRecordedPreviousRegistrationByGroupingUpperBound(row, upperSec) {
  if (!row || !/^[1-9]\d*$/.test(String(row.registeredAt ?? ''))
      || BigInt(row.registeredAt) > BigInt(upperSec)) {
    throw artifactMismatchError('recorded previous registration is after grouping upper bound');
  }
}

/** 公開名簿の全実バイトから C を再計算し、チェーンの正典登録値と照合する。 */
export async function collectRosterCommitmentForProof({
  fetchImpl, r2Base, blockNum, manifest, rosterManifestHash,
}) {
  // 登録値 0 の経路では公開名簿が存在しない。guest の JSON 入力には
  // 空の名簿を渡し、再構成した group file があれば guest の集合照合で拒否する。
  let rosterManifestText = JSON.stringify({ blockNum, groups: [] });
  let rosterInputBytes = 0;
  if (String(rosterManifestHash).toLowerCase() !== ZERO_HASH) {
    const rosterKey = `games/block${blockNum}/roster/manifest.json`;
    const rosterFile = await fetchRawBounded(
      fetchImpl, r2Base, rosterKey, ZKP_INPUT_LIMITS.rosterManifestBytes,
    );
    rosterManifestText = rosterFile.bytes.toString('utf8');
    if (!Buffer.from(rosterManifestText).equals(rosterFile.bytes)) {
      throw artifactMismatchError('roster manifest の UTF-8 が不正です');
    }
    const rosterManifest = parseJson(rosterFile.bytes, 'roster manifest');
    if (!Array.isArray(rosterManifest?.groups)
        || rosterManifest.groups.length > ZKP_INPUT_LIMITS.rosterGroups) {
      throw artifactMismatchError('roster manifest の group 数が不正です');
    }
    const indexKey = `games/block${blockNum}/roster/index.json`;
    const indexFile = await fetchRawBounded(fetchImpl, r2Base, indexKey, ZKP_INPUT_LIMITS.rosterManifestBytes);
    const indexHash = indexFile.sha256.slice(2);
    if (String(rosterManifest.indexSha256).toLowerCase() !== indexHash
        || String(manifest.files?.[indexKey]).toLowerCase().replace(/^0x/, '') !== indexHash) {
      throw artifactMismatchError('roster index sha256 が不一致です');
    }
    const groupTexts = new Map();
    rosterInputBytes = rosterFile.byteLength + indexFile.byteLength;
    for (const group of rosterManifest.groups) {
      const groupId = group?.groupId;
      if (!Number.isSafeInteger(groupId) || groupId < 0) {
        throw artifactMismatchError('roster manifest の groupId が不正です');
      }
      const key = `games/block${blockNum}/roster/group${groupId}.json`;
      const file = await fetchRawBounded(fetchImpl, r2Base, key, ZKP_INPUT_LIMITS.rosterGroupBytes);
      const declared = manifest.files?.[key];
      if (typeof declared !== 'string' || declared.toLowerCase().replace(/^0x/, '') !== file.sha256.slice(2)) {
        throw artifactMismatchError(`result manifest と ${key} の sha256 が不一致です`);
      }
      const text = file.bytes.toString('utf8');
      if (!Buffer.from(text).equals(file.bytes)) throw artifactMismatchError(`${key} の UTF-8 が不正です`);
      groupTexts.set(groupId, text);
      rosterInputBytes += file.byteLength;
    }
    let commitment;
    try {
      commitment = buildRosterMemberCommitment({ blockNum, manifestText: rosterManifestText, groupTexts });
    } catch (error) {
      throw artifactMismatchError(`roster member commitment 再計算失敗: ${error.message}`);
    }
    if (!commitment.C || commitment.C.toLowerCase() !== String(rosterManifestHash).toLowerCase()) {
      throw chainAnchorMismatchError(`正典名簿 C 不一致: chain=${rosterManifestHash} R2=${commitment.C}`);
    }
  }
  return { rosterManifestText, rosterInputBytes };
}

export async function collectZkpInput({
  rpcUrl,
  tokenMining: tokenMiningRaw,
  blockNum: blockNumRaw,
  r2Base = 'https://r2.bitcoinu.org',
  fetchImpl = globalThis.fetch,
  artifactDir = null,
  client: suppliedClient = null,
  streaming = false,
  stage3Witnesses = false,
  inputProvenance = null,
  namedPrevRegistrationIndex = undefined,
  skipGroupingRecord = false,
  confirmationBlocks = CONFIRMATION_BLOCKS,
}) {
  if (typeof rpcUrl !== 'string' || !rpcUrl) throw new Error('rpcUrl が必要です');
  const blockNum = requireBlockNum(blockNumRaw);
  if (artifactDir) {
    fetchImpl = createArtifactDirectoryFetch(artifactDir, { blockNum });
    r2Base = 'artifact://q24';
    inputProvenance = {
      ...(inputProvenance && typeof inputProvenance === 'object' ? inputProvenance : {}),
      artifactDirectory: path.resolve(artifactDir),
      networkArtifactFetch: false,
    };
  }
  if (typeof fetchImpl !== 'function') throw new Error('fetch が利用できません');
  const tokenMining = requireAddress(tokenMiningRaw, 'TokenMining');
  const client = suppliedClient || createPublicClient({ transport: http(rpcUrl) });
  const snapshot = await client.getBlock();
  const snapshotBlock = snapshot.number;
  const readAt = (request) => client.readContract({ ...request, blockNumber: snapshotBlock });
  const bn = BigInt(blockNum);

  const [evidenceRaw, hashStorageRaw, currentAnchorRaw, pendingAnchorRaw, pendingEta, claimRef, claimBlocks] = await Promise.all([
    readAt({ address: tokenMining, abi: TOKEN_MINING_ABI, functionName: 'evidence' }),
    readAt({ address: tokenMining, abi: TOKEN_MINING_ABI, functionName: 'hashStorage' }),
    readAt({ address: tokenMining, abi: TOKEN_MINING_ABI, functionName: 'anchorProvider' }),
    readAt({ address: tokenMining, abi: TOKEN_MINING_ABI, functionName: 'pendingAnchorProvider' }),
    readAt({ address: tokenMining, abi: TOKEN_MINING_ABI, functionName: 'pendingVkeyEta' }),
    readAt({ address: tokenMining, abi: TOKEN_MINING_ABI, functionName: 'claimDataOf', args: [bn] }),
    readAt({ address: tokenMining, abi: TOKEN_MINING_ABI, functionName: 'getClaimDataBlocks', args: [bn] }),
  ]);
  const evidence = requireAddress(evidenceRaw, 'Evidence');
  const hashStorage = requireAddress(hashStorageRaw, 'HashStorage');
  const pendingDue = pendingEta !== 0n && snapshot.timestamp >= pendingEta;
  const anchorProvider = requireAddress(
    pendingDue ? pendingAnchorRaw : currentAnchorRaw,
    pendingDue ? 'effective pendingAnchorProvider' : 'anchorProvider',
    { allowZero: true },
  );
  const claimDataHash = tupleValue(claimRef, 0, 'dataHash');
  const claimChunks = Number(tupleValue(claimRef, 1, 'chunks'));
  const claimReceived = Number(tupleValue(claimRef, 2, 'received'));
  if (claimChunks <= 0 || claimReceived !== claimChunks) {
    throw new Error(`claimDataOf[${blockNum}] が未完成です: received=${claimReceived}/${claimChunks}`);
  }
  if (claimChunks > ZKP_INPUT_LIMITS.claimChunks) {
    throw new Error(`claim chunks ${claimChunks} > limit ${ZKP_INPUT_LIMITS.claimChunks}`);
  }
  if (claimBlocks.length !== claimChunks) {
    throw new Error(`getClaimDataBlocks=${claimBlocks.length}件 / claimDataOf.chunks=${claimChunks}件で不一致です`);
  }

  const tempDir = streaming ? await mkdtemp(path.join(tmpdir(), 'bitcoinu-zkp-input-')) : null;
  const summaryPath = tempDir ? path.join(tempDir, 'summary.json') : null;
  try {
  const stage3ManifestKey = `verification/block${blockNum}/stage3/manifest.json`;
  const [manifestFile, stage3ManifestFile, summaryFile, merkleFile, stage3WitnessManifestFile] = await Promise.all([
    fetchRawBounded(fetchImpl, r2Base, `verification/block${blockNum}/manifest.json`, ZKP_INPUT_LIMITS.manifestBytes),
    fetchRawBounded(fetchImpl, r2Base, stage3ManifestKey, ZKP_INPUT_LIMITS.stage3ManifestBytes)
      .catch((error) => {
        const message = String(error?.message || error);
        if (!error?.zkpArtifactMissing && !error?.zkpArtifactFetchError
            && !error?.zkpArtifactMismatch && message.startsWith(`R2 ${stage3ManifestKey}:`)) {
          markStage3ArtifactInvalid(error);
        }
        throw error;
      }),
    fetchRawBounded(fetchImpl, r2Base, `games/block${blockNum}/summary.json`, ZKP_INPUT_LIMITS.summaryBytes,
      summaryPath ? { sinkPath: summaryPath } : undefined),
    fetchRawBounded(fetchImpl, r2Base, `merkle/block_${blockNum}.json`, ZKP_INPUT_LIMITS.merkleBytes),
    stage3Witnesses
      ? fetchRawBounded(fetchImpl, r2Base, `zkp/block${blockNum}/manifest.json`,
          ZKP_INPUT_LIMITS.stage3WitnessManifestBytes)
      : Promise.resolve(null),
  ]);
  const baseR2Bytes = manifestFile.byteLength + stage3ManifestFile.byteLength
    + summaryFile.byteLength + merkleFile.byteLength
    + (stage3WitnessManifestFile?.byteLength || 0);
  const manifest = parseJson(manifestFile.bytes, 'manifest.json');
  const stage3ManifestText = stage3ManifestFile.bytes.toString('utf8');
  let stage3Manifest;
  try {
    stage3Manifest = validateStage3InputManifest(
      parseJson(stage3ManifestFile.bytes, 'Stage 3 input manifest'),
      { blockNum, rawText: stage3ManifestText },
    );
  } catch (error) {
    if (!error?.zkpArtifactMismatch) markStage3ArtifactInvalid(error);
    throw error;
  }
  const summary = parseJson(summaryFile.bytes || await readFile(summaryFile.path), 'summary.json');
  const summaryBlockNum = summary ? Number(summary.blockNum) : await summaryBlockNumFromCanonicalPrefix(summaryFile.path);
  // 集計後の schemaVersion 3 summary には totalPlayers が無い。受理済み証明の
  // Stage C 再現は名乗った行を使い、運営の組分け記録を権威にしない。
  const needsGroupingRecord = blockNum > 0 && !skipGroupingRecord
    && summary?.autoDistributed !== true && Array.isArray(summary?.groups)
    && summary.groups.length > 0;
  const gameGroupsFile = needsGroupingRecord
    ? await fetchRawBounded(fetchImpl, r2Base, `entries/block${blockNum}/game_groups.json`, 2 * 1024 * 1024)
    : null;
  let recordedPrevious = null;
  if (gameGroupsFile) {
    const gameGroups = parseJson(gameGroupsFile.bytes, 'game_groups.json');
    if (!Array.isArray(gameGroups?.groups) || gameGroups.groups.length === 0
        || gameGroups.groups.length !== summary.groups.length) {
      throw artifactMismatchError(`block ${blockNum} game_groups.json groups are inconsistent`);
    }
    recordedPrevious = parseRecordedPreviousRegistration(gameGroups, { blockNum });
  }
  if (recordedPrevious && namedPrevRegistrationIndex !== undefined
      && namedPrevRegistrationIndex !== BigInt(recordedPrevious.index)) {
    throw artifactMismatchError('named previous registration differs from game_groups.json');
  }
  const merkle = parseJson(merkleFile.bytes, 'merkle metadata');
  if (Number(manifest.blockNum) !== blockNum || summaryBlockNum !== blockNum || Number(merkle.blockNum) !== blockNum) {
    throw new Error('R2成果物のblockNumが指定ブロックと一致しません');
  }
  const merkleRoot = String(merkle.root || '').toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(merkleRoot) || merkleRoot === ZERO_HASH) {
    throw new Error(`merkle/block_${blockNum}.json のrootが不正です`);
  }
  const stage3WitnessManifest = stage3WitnessManifestFile
    ? parseStage3WitnessManifest(stage3WitnessManifestFile.bytes, blockNum)
    : null;

  const manifestCore = extractManifestCore(manifestFile.bytes);
  const resultManifestHashFromBytes = sha256Hex(manifestCore);
  // R29-A-3b-01: manifest.manifestHash は core 外の自称ラベルなので、ZKP入力の権威にしない。
  // 採用する値は manifestCore 生バイトの sha256 であり、下の HashStorage.resultHashes 照合は
  // 従来どおり残す。したがって自称欄だけでは収集を止められず、チェーン不一致は止まる。
  const summaryKey = `games/block${blockNum}/summary.json`;
  if (gameGroupsFile) {
    const groupKey = `entries/block${blockNum}/game_groups.json`;
    const declaredGroupHash = String(manifest.files?.[groupKey] ?? '').toLowerCase().replace(/^0x/, '');
    if (declaredGroupHash !== gameGroupsFile.sha256.slice(2)) {
      throw artifactMismatchError(`manifest内game_groups sha256不一致: declared=${declaredGroupHash} actual=${gameGroupsFile.sha256}`);
    }
  }
  const declaredSummaryHash = manifest.files?.[summaryKey];
  const summaryHash = summaryFile.sha256.slice(2);
  if (String(declaredSummaryHash).toLowerCase().replace(/^0x/, '') !== summaryHash) {
    throw artifactMismatchError(`manifest内summary sha256不一致: declared=${declaredSummaryHash} actual=${summaryHash}`);
  }
  const stage3ManifestSha256 = stage3ManifestFile.sha256.slice(2);
  const declaredStage3ManifestHash = manifest.files?.[stage3ManifestKey];
  if (String(declaredStage3ManifestHash).toLowerCase().replace(/^0x/, '') !== stage3ManifestSha256) {
    throw artifactMismatchError(
      `manifest内Stage 3 input manifest sha256不一致: declared=${declaredStage3ManifestHash} actual=${stage3ManifestSha256}`,
    );
  }
  const applicantRegistration = await readApplicantRegistrationForProof({
    fetchImpl, r2Base, manifest, readAt, hashStorage, blockNum,
  });
  const totalR2Bytes = baseR2Bytes + applicantRegistration.selectionFile.byteLength;
  if (totalR2Bytes > ZKP_INPUT_LIMITS.totalR2Bytes) {
    throw new Error(`R2 input bytes ${totalR2Bytes} > limit ${ZKP_INPUT_LIMITS.totalR2Bytes}`);
  }

  const claimLogs = await readClaimDataLogs(client, tokenMining, blockNum, claimBlocks);
  const chunksHex = recoverClaimDataChunks(claimLogs, claimBlocks, claimDataHash, claimChunks);
  const rebuiltClaimHash = chunkChainHash(chunksHex);
  if (rebuiltClaimHash.toLowerCase() !== String(claimDataHash).toLowerCase()) {
    throw new Error(`ClaimData連鎖keccak不一致: chain=${claimDataHash} actual=${rebuiltClaimHash}`);
  }

  const [evidenceAcc, entryAcc, storedResult, prevRegistration, deploymentParamsHash, futureAnchorsHash] = await Promise.all([
    readAt({ address: evidence, abi: EVIDENCE_ABI, functionName: 'evidenceAcc', args: [bn] }),
    readAt({ address: evidence, abi: EVIDENCE_ABI, functionName: 'entryAcc', args: [bn] }),
    readAt({ address: hashStorage, abi: HASH_STORAGE_ABI, functionName: 'resultHashes', args: [bn] }),
    // word7 は現在値ではなく「名乗る登録の行」から作る。添字も同時に出す。
    readPrevResultRegistrationForProof({
      readAt, hashStorage, blockNum,
      namedPrevRegistrationIndex: recordedPrevious
        ? BigInt(recordedPrevious.index) : namedPrevRegistrationIndex,
    }),
    readAt({ address: tokenMining, abi: TOKEN_MINING_ABI, functionName: 'deploymentParamsHash', args: [bn] }),
    anchorProvider.toLowerCase() === ZERO_ADDRESS
      ? Promise.resolve(ZERO_HASH)
      : readAt({ address: anchorProvider, abi: ANCHOR_PROVIDER_ABI, functionName: 'anchorsHash', args: [bn] }),
  ]);
  const evidenceGraceSec = await readAt({
    address: evidence, abi: EVIDENCE_ABI, functionName: 'currentGrace', args: [bn],
  });
  if (blockNum > 0 && prevRegistration.prevRegistrationCount === 0n
      && namedPrevRegistrationIndex === undefined) {
    throw new Error(`block ${blockNum}: previous result registration is pending`);
  }
  if (recordedPrevious && (
      prevRegistration.prevRegistrationIndex !== BigInt(recordedPrevious.index)
      || prevRegistration.prevResultManifestHash.toLowerCase() !== recordedPrevious.hash
      || prevRegistration.registeredBlock !== BigInt(recordedPrevious.registeredBlock)
      || prevRegistration.registeredAt !== BigInt(recordedPrevious.registeredAt))) {
    throw artifactMismatchError('recorded previous registration differs from HashStorage row');
  }
  if (recordedPrevious) {
    const upperSec = await deriveGroupingUpperBoundForProof({
      readAt, evidence, hashStorage, blockNum, graceSec: evidenceGraceSec,
    });
    assertRecordedPreviousRegistrationByGroupingUpperBound(recordedPrevious, upperSec);
  }
  const rosterManifestHash = await readCanonicalRosterHash({
    readAt, evidence, hashStorage, blockNum, graceSec: evidenceGraceSec,
  });
  const { rosterManifestText, rosterInputBytes } = await collectRosterCommitmentForProof({
    fetchImpl, r2Base, blockNum, manifest, rosterManifestHash,
  });
  if (totalR2Bytes + rosterInputBytes > ZKP_INPUT_LIMITS.totalR2Bytes) {
    throw new Error(`R2 input bytes ${totalR2Bytes + rosterInputBytes} > limit ${ZKP_INPUT_LIMITS.totalR2Bytes}`);
  }
  const { applicantHash, applicantHashUpdatedBlock } = applicantRegistration;
  const randaoEthBlockNumber = applicantHashUpdatedBlock + BigInt(confirmationBlocks);
  const randaoBlockHash = await readAt({
    address: evidence, abi: EVIDENCE_ABI, functionName: 'blockHashOf', args: [randaoEthBlockNumber],
  });
  if (String(randaoBlockHash).toLowerCase() === ZERO_HASH) {
    throw new Error(`Evidence.blockHashOf(${randaoEthBlockNumber}) が未アンカーです`);
  }
  const resultManifestHash = tupleValue(storedResult, 0, 'hash');
  if (String(resultManifestHash).toLowerCase() !== resultManifestHashFromBytes) {
    throw chainAnchorMismatchError(`HashStorage.resultHashes不一致: chain=${resultManifestHash} R2=${resultManifestHashFromBytes}`);
  }

  const prefixFields = {
    schemaVersion: 1,
    blockNum,
    chunksHex,
    manifestCoreHex: bytesToHexIncremental(manifestCore),
  };
  const tailFields = {
    evidenceAcc,
    entryAcc,
    randaoBlockHash,
    prevResultManifestHash: prevRegistration.prevResultManifestHash,
    applicantHash,
    applicantHashUpdatedBlock: toJsonNumber(applicantHashUpdatedBlock, 'applicantHashUpdatedBlock'),
    evidenceGraceSec: toJsonNumber(evidenceGraceSec, 'evidenceGraceSec'),
    randaoEthBlockNumber: toJsonNumber(randaoEthBlockNumber, 'randaoEthBlockNumber'),
    deploymentParamsHash,
    futureAnchorsHash,
    rosterManifestHash,
    rosterManifestText,
    ...(inputProvenance && typeof inputProvenance === 'object' ? { inputProvenance } : {}),
  };
  const input = streaming
    ? { ...prefixFields, ...tailFields }
    : { ...prefixFields, summaryHex: bytesToHexIncremental(summaryFile.bytes), ...tailFields };
  const serializedInput = streaming
    ? await serializeZkpInputToFile({
        prefixFields, summaryPath: summaryFile.path, tailFields,
        outPath: path.join(tempDir, 'input.json'), maxBytes: ZKP_INPUT_LIMITS.serializedBytes,
      })
    : serializeZkpInput(input);
  if (!streaming && serializedInput.length > ZKP_INPUT_LIMITS.serializedBytes) {
    throw new Error(`serialized ZKP input ${serializedInput.length} > limit ${ZKP_INPUT_LIMITS.serializedBytes}`);
  }
  const result = {
    input,
    serializedInput,
    inputHash: streaming ? serializedInput.sha256 : sha256Hex(serializedInput),
    snapshotBlock: snapshotBlock.toString(),
    pendingVkeyEta: pendingEta.toString(),
    pendingDue,
    merkleRoot,
    claimDataHash: String(claimDataHash).toLowerCase(),
    resultManifestHash: resultManifestHashFromBytes,
    // 🔴 `input`（＝証明へ渡す15語のもと）には入れない。これは契約の**第7引数**であって
    //    PV の語ではないので、ここへ足すと serializedInput / inputHash が動いてしまう。
    //    旧 HashStorage は結果登録履歴getterを持たないので null（＝7引数提出は不可）。
    prevRegistrationIndex: prevRegistration.prevRegistrationIndex === null
      ? null : prevRegistration.prevRegistrationIndex.toString(),
    prevRegistrationCount: prevRegistration.prevRegistrationCount === null
      ? null : prevRegistration.prevRegistrationCount.toString(),
    prevRegistrationLegacyFallback: prevRegistration.legacyFallback === true,
    prevRegistration: prevRegistration.prevRegistrationIndex === null ? null : {
      index: prevRegistration.prevRegistrationIndex.toString(),
      registeredBlock: prevRegistration.registeredBlock?.toString() ?? '0',
      registeredAt: prevRegistration.registeredAt?.toString() ?? '0',
      hash: prevRegistration.prevResultManifestHash.toLowerCase(),
    },
    summaryHash: `0x${summaryHash}`,
    stage3: {
      manifestObject: stage3ManifestKey,
      manifestSha256: stage3ManifestSha256,
      manifestText: stage3ManifestText,
      groupCount: stage3Manifest.groupCount,
    },
    urls: {
      manifest: manifestFile.url, selection: applicantRegistration.selectionFile.url,
      stage3Manifest: stage3ManifestFile.url,
      summary: summaryFile.url, merkle: merkleFile.url,
    },
    ...(stage3WitnessManifestFile ? {
      stage3Witnesses: {
        manifestBytes: stage3WitnessManifestFile.bytes,
        manifestHash: stage3WitnessManifestFile.sha256,
        manifestUrl: stage3WitnessManifestFile.url,
        groupCount: stage3WitnessManifest.groupCount,
        totalBytes: stage3WitnessManifest.totalBytes,
        r2Base: r2Base.replace(/\/$/, ''),
      },
    } : {}),
  };
  if (streaming) result.cleanup = () => rmSync(tempDir, { recursive: true, force: true });
  return result;
  } catch (error) {
    if (tempDir) rmSync(tempDir, { recursive: true, force: true });
    throw error;
  }
}

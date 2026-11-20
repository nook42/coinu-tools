// block-verifier/test/zkp-unit.mjs
// メニュー②（ZKPシステムのコード整合性）の純粋関数の回帰テスト。チェーン不要・数秒で終わる。
//
// ここで守っているもの:
//  - ブロック範囲の畳み込み（「ブロック 0-12 では…」という結論文の根拠）
//  - 公開パッケージの展開（**SP1 イメージタグが欠けると第三者は再現ビルドできない**）
//  - 世代の振り分け（未提出ブロックを範囲に混ぜない・証明なしを -1 に分ける）

import fs from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  buildExpectedPublicValues,
  collectBlockEpochs,
  collectGuestSource,
  compareRebuiltPublicValues,
  describeZkpCollectionFailure,
  decodeProofPrevRegistrationIndex,
  decodeProofSubmissionCalldata,
  formatRanges,
  formatWireGuestRebuildCommands,
  GUEST_SOURCE_LIMITS,
  guestSourceChainHash,
  inspectBlockZkpState,
  inspectProofEnvelope,
  inspectProofSubmission,
  ZKP_COLLECTION_FAILURE_CAUSES,
  ZKP_BLOCK_READ_CONCURRENCY,
  joinGuestSourceChunks,
  recoverGuestSourceChunks,
  runZkpMode,
  unpackGuestSource,
  validateGuestSourcePath,
  writeGuestSourceSafely,
  ZKP_PROOF_FORMAT,
} from '../src/zkp.js';
import { encodeFunctionData, toHex } from 'viem';
import {
  chunkChainHash,
  encodePublicValues,
  PREV_REGISTRATION_SENTINEL,
  TOKEN_MINING_ABI,
} from '../../Hardhat/bitcoinu/scripts/lib/zkp-pipeline.mjs';
import {
  fetchRawBounded,
  validateStage3InputManifest,
} from '../../Hardhat/bitcoinu/scripts/lib/collect-zkp-input.mjs';
import { recordZkpState, resolveCurrentProofAttachment, selectZkpSummaryRaw } from '../src/stages/results.js';
import { buildRosterMemberCommitment } from '../vendor/workers/game_workers/lib/roster-member-root.js';
import { ZKP_EXPECTED } from '../vendor/workers/game_workers/lib/zkp-protocol.js';
import {
  GUEST_SOURCE_V2_HEADER,
  compressGuestSourceV2,
  packGuestSource,
  SP1_IMAGE,
} from '../../crates/pack-guest-source.mjs';
import { WIRE_GUESTS } from '../src/wiring-vkeys.js';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const CRATES_ROOT = path.join(REPO_ROOT, 'crates');

let pass = 0, fail = 0;
const eq = (a, b, n) => {
  if (JSON.stringify(a) === JSON.stringify(b)) { pass++; console.log(`  ✅ ${n}`); }
  else { fail++; console.log(`  ❌ ${n}\n     got=${JSON.stringify(a)}\n     want=${JSON.stringify(b)}`); }
};
const throws = (fn, pattern, n) => {
  try { fn(); fail++; console.log(`  ❌ ${n}\n     did not throw`); }
  catch (error) {
    if (pattern.test(error.message)) { pass++; console.log(`  ✅ ${n}`); }
    else { fail++; console.log(`  ❌ ${n}\n     ${error.message}`); }
  }
};

console.log('=== formatRanges ===');
eq(formatRanges([0, 1, 2, 3]), '0-3', '連続は範囲に畳む');
eq(formatRanges([0, 1, 2, 5, 6]), '0-2, 5-6', '飛びは分割する');
eq(formatRanges([7]), '7', '単独');
eq(formatRanges([]), '-', '空');
eq(formatRanges([3, 1, 2]), '1-3', '順不同でも正しい');

console.log('=== unpackGuestSource ===');
const files = [{ path: 'a/b.rs', content: 'fn main(){}\n' }, { path: 'c.toml', content: '[package]\n' }];
let pkg = `bitcoinu-guest-source/1\nsp1-image\t${SP1_IMAGE}\n`;
for (const f of files) pkg += `file\t${f.path}\t${Buffer.byteLength(f.content)}\n${f.content}\n`;
const u = unpackGuestSource(toHex(Buffer.from(pkg, 'utf8')));
eq(u.magic, 'bitcoinu-guest-source/1', 'マジック');
eq(u.formatVersion, 1, 'v1非圧縮を後方互換で展開');
eq(u.sp1Image, SP1_IMAGE, 'SP1 imageはdigest固定');
eq(u.files.map((f) => f.path), ['a/b.rs', 'c.toml'], 'ファイル一覧');
eq(u.files.map((f) => f.content), files.map((f) => f.content), '本文がバイト一致');

const v2pkg = compressGuestSourceV2(Buffer.from(pkg, 'utf8'));
const u2 = unpackGuestSource(toHex(v2pkg));
eq(v2pkg.subarray(0, GUEST_SOURCE_V2_HEADER.length).toString('utf8'), GUEST_SOURCE_V2_HEADER, 'v2平文ヘッダが自己記述');
eq(u2.magic, 'bitcoinu-guest-source/2', 'v2マジック');
eq(u2.codec, 'brotli', 'v2 codecはBrotli');
eq(u2.innerMagic, 'bitcoinu-guest-source/1', 'Brotli本文は従来v1 payload');
eq(u2.files.map((f) => f.content), files.map((f) => f.content), 'v2圧縮経路でも本文がバイト一致');
throws(
  () => unpackGuestSource(toHex(Buffer.from('bitcoinu-guest-source/99\tbrotli\ninvalid', 'utf8'))),
  /unsupported guest source format/,
  '未知versionはfail-closed',
);
throws(
  () => unpackGuestSource(toHex(Buffer.from('bitcoinu-guest-source/2\tgzip\ninvalid', 'utf8'))),
  /unsupported guest source codec/,
  '未知codecはfail-closed',
);
throws(
  () => unpackGuestSource(toHex(Buffer.from('bitcoinu-guest-source/2\tbrotli\ninvalid', 'utf8'))),
  /invalid brotli payload/,
  '壊れたBrotli本文はfail-closed',
);

// 🔴 実際に踏んだバグの回帰: ヘッダの長さは**バイト数**だが JS の文字列インデックスは
//    UTF-16 単位。日本語コメント入りの Rust ソースで**静かに途中で切れて**
//    12ファイル中2ファイルしか復元されなかった（エラーは出なかった）。
const jaFiles = [
  { path: 'x.rs', content: '// 日本語のコメント\nfn a(){}\n' },
  { path: 'y.rs', content: '// もう一つ 🎯 絵文字も\nfn b(){}\n' },
  { path: 'z.rs', content: 'fn c(){}\n' },
];
let jaPkg = `bitcoinu-guest-source/1\nsp1-image\t${SP1_IMAGE}\n`;
for (const f of jaFiles) jaPkg += `file\t${f.path}\t${Buffer.byteLength(f.content)}\n${f.content}\n`;
const ju = unpackGuestSource(toHex(Buffer.from(jaPkg, 'utf8')));
eq(ju.files.length, 3, '非ASCIIを含んでもファイル数が欠けない');
eq(ju.files.map((f) => f.path), jaFiles.map((f) => f.path), '非ASCII: パス一覧');
eq(ju.files.map((f) => f.content), jaFiles.map((f) => f.content), '非ASCII: 本文が1バイトも欠けない');
const ju2 = unpackGuestSource(toHex(compressGuestSourceV2(Buffer.from(jaPkg, 'utf8'))));
eq(ju2.files.length, 3, 'v2 Brotli: 非ASCIIを含んでもファイル数が欠けない');
eq(ju2.files.map((f) => f.path), jaFiles.map((f) => f.path), 'v2 Brotli: 非ASCIIのパス一覧');
eq(ju2.files.map((f) => f.content), jaFiles.map((f) => f.content), 'v2 Brotli: 日本語・絵文字本文が1バイトも欠けない');

const makeV1 = (entries, image = SP1_IMAGE) => {
  const parts = [Buffer.from(`bitcoinu-guest-source/1\nsp1-image\t${image}\n`, 'utf8')];
  for (const entry of entries) {
    const body = Buffer.isBuffer(entry.body) ? entry.body : Buffer.from(entry.body || '', 'utf8');
    parts.push(Buffer.from(`file\t${entry.path}\t${body.length}\n`, 'utf8'), body, Buffer.from('\n'));
  }
  return Buffer.concat(parts);
};
const unpackV1 = (entries, image) => unpackGuestSource(toHex(makeV1(entries, image)));

console.log('=== V25-05 malicious guest source rejection ===');
for (const [badPath, label] of [
  ['../escape.rs', '.. segment'], ['/tmp/escape.rs', 'absolute path'], ['a\\b.rs', 'backslash'],
  ['a//b.rs', 'empty segment'], ['a/./b.rs', 'dot segment'], ['a/../b.rs', 'nested dotdot'],
  [`a\0b.rs`, 'NUL'],
]) {
  throws(() => unpackV1([{ path: badPath, body: 'x' }]), /path|segment|NUL|backslash|absolute/i, `${label}を拒否`);
}
throws(() => unpackV1([{ path: 'a.rs', body: 'x' }, { path: 'a.rs', body: 'y' }]), /duplicate/, '重複pathを拒否');
throws(() => unpackV1([{ path: 'a', body: 'x' }, { path: 'a/b.rs', body: 'y' }]), /prefix conflict/, 'file→directoryのprefix衝突を拒否');
throws(() => unpackV1([{ path: 'a/b.rs', body: 'x' }, { path: 'a', body: 'y' }]), /prefix conflict/, 'directory→fileのprefix衝突を拒否');
throws(() => unpackV1([{ path: 'x.rs', body: 'x' }], 'ghcr.io/succinctlabs/sp1:v6.3.1'), /sha256 digest/, 'tagだけのimageを拒否');
throws(() => unpackV1([{ path: 'x.rs', body: 'x' }], `evil.example/sp1@sha256:${'0'.repeat(64)}`), /sha256 digest/, '別registryを拒否');
const wireForCommands = unpackGuestSource(toHex(packGuestSource(CRATES_ROOT).bytes));
throws(() => formatWireGuestRebuildCommands('/tmp/x', `${SP1_IMAGE}\nfile\tpwn\t0`, wireForCommands.files), /sha256 digest/, 'image内改行を拒否');
throws(() => unpackV1([{ path: 'x.rs', body: 'x' }], `${SP1_IMAGE};touch /tmp/pwn`), /sha256 digest/, 'image内shell metacharacterを拒否');

const maxPath = 'p'.repeat(GUEST_SOURCE_LIMITS.pathBytes);
eq(validateGuestSourcePath(maxPath), maxPath, 'path上限ちょうどを受理');
throws(() => validateGuestSourcePath(`${maxPath}p`), /path exceeds/, 'path上限+1を拒否');
const exactHeader = Buffer.concat([
  Buffer.from(`bitcoinu-guest-source/1\nsp1-image\t${SP1_IMAGE}\n`),
  Buffer.from('x'.repeat(GUEST_SOURCE_LIMITS.headerBytes)), Buffer.from('\n'),
]);
throws(() => unpackGuestSource(toHex(exactHeader)), /unknown header/, 'header上限ちょうどは長さ検査を通過');
const overHeader = Buffer.concat([
  Buffer.from(`bitcoinu-guest-source/1\nsp1-image\t${SP1_IMAGE}\n`),
  Buffer.from('x'.repeat(GUEST_SOURCE_LIMITS.headerBytes + 1)), Buffer.from('\n'),
]);
throws(() => unpackGuestSource(toHex(overHeader)), /header exceeds/, 'header上限+1を拒否');

const exactFilePkg = compressGuestSourceV2(makeV1([{ path: 'large.bin', body: Buffer.alloc(GUEST_SOURCE_LIMITS.fileBytes) }]));
eq(unpackGuestSource(toHex(exactFilePkg)).files[0].bytes.length, GUEST_SOURCE_LIMITS.fileBytes, 'file単体上限ちょうどを受理');
const overFilePkg = compressGuestSourceV2(makeV1([{ path: 'large.bin', body: Buffer.alloc(GUEST_SOURCE_LIMITS.fileBytes + 1) }]));
throws(() => unpackGuestSource(toHex(overFilePkg)), /file .* exceeds/, 'file単体上限+1を拒否');

const exactCount = Array.from({ length: GUEST_SOURCE_LIMITS.files }, (_, index) => ({ path: `f${index}`, body: '' }));
eq(unpackV1(exactCount).files.length, GUEST_SOURCE_LIMITS.files, 'file数上限ちょうどを受理');
throws(() => unpackV1([...exactCount, { path: 'overflow', body: '' }]), /file count exceeds/, 'file数上限+1を拒否');

const payloadAt = (target) => {
  const entries = [0, 1, 2, 3].map((index) => ({ path: `big${index}`, body: Buffer.alloc(index < 3 ? GUEST_SOURCE_LIMITS.fileBytes : 0) }));
  for (let tries = 0; tries < 8; tries++) {
    const current = makeV1(entries).length;
    if (current === target) return makeV1(entries);
    const next = entries[3].body.length + target - current;
    if (next < 0 || next > GUEST_SOURCE_LIMITS.fileBytes) throw new Error('test payload cannot reach target');
    entries[3].body = Buffer.alloc(next);
  }
  throw new Error('test payload length did not converge');
};
const exactPayload = payloadAt(GUEST_SOURCE_LIMITS.payloadBytes);
eq(unpackGuestSource(toHex(compressGuestSourceV2(exactPayload))).payloadBytes, GUEST_SOURCE_LIMITS.payloadBytes, '展開総量上限ちょうどを受理');
const bombPayload = payloadAt(GUEST_SOURCE_LIMITS.payloadBytes + 1);
throws(() => unpackGuestSource(toHex(compressGuestSourceV2(bombPayload))), /payload exceeds/, '高圧縮の展開総量上限+1をOOM前に拒否');

const packageAtLimit = Buffer.concat([
  Buffer.from(GUEST_SOURCE_V2_HEADER),
  Buffer.alloc(GUEST_SOURCE_LIMITS.packageBytes - Buffer.byteLength(GUEST_SOURCE_V2_HEADER)),
]);
throws(() => unpackGuestSource(toHex(packageAtLimit)), /invalid brotli payload/, 'package上限ちょうどは長さ検査を通過');
throws(() => unpackGuestSource(toHex(Buffer.concat([packageAtLimit, Buffer.from([0])]))), /package exceeds/, 'package上限+1を展開前に拒否');

console.log('=== V25-05 safe output and command ===');
const t44Tmp = new URL('../../tmp/T4-4/', import.meta.url).pathname;
fs.mkdirSync(t44Tmp, { recursive: true });
const tmpRoot = fs.mkdtempSync(path.join(t44Tmp, 'bitcoinu-zkp-safe-'));
const envPaths = new Set();
try {
  const saved = writeGuestSourceSafely(wireForCommands, tmpRoot, 'normal-output');
  const rebuildCommands = formatWireGuestRebuildCommands(saved, SP1_IMAGE, wireForCommands.files);
  for (const command of rebuildCommands) envPaths.add(command.envPath);
  eq(rebuildCommands.length, 12, '配線の全guestに12本の命令を出す');
  eq(rebuildCommands.every((command) => command.build.startsWith('docker run --rm --platform linux/amd64')), true,
    'rebuild commandはDockerの中でbuildする');
  eq(rebuildCommands.every((command) => command.build.includes(`${saved}:/root/program:ro`)), true,
    'rebuild commandは束の親を読み取り専用で載せる');
  eq(rebuildCommands.every((command) => command.build.includes(`${saved}/${command.crate}/target:/root/program/${command.crate}/target`)), true,
    'rebuild commandはtargetを別の書ける載せ口にする');
  throws(() => formatWireGuestRebuildCommands('/tmp/source:bad', SP1_IMAGE, wireForCommands.files),
    /cannot be mounted/, 'mount区切りのcolonを拒否');
  throws(() => formatWireGuestRebuildCommands('/tmp/source,bad', SP1_IMAGE, wireForCommands.files),
    /cannot be mounted/, 'mount区切りのcommaを拒否');
  throws(() => formatWireGuestRebuildCommands('/tmp/source', `ghcr.io/succinctlabs/sp1@sha256:${'0'.repeat(64)}`,
    wireForCommands.files), /no captured rebuild parameters/, '未知imageの固定値を推測しない');
  throws(() => formatWireGuestRebuildCommands('/tmp/x', 'ghcr.io/succinctlabs/sp1:v6.3.1', wireForCommands.files),
    /sha256 digest/, 'command生成でもtag-only imageを拒否');
  eq(fs.readFileSync(path.join(saved, wireForCommands.files[0].path)).equals(wireForCommands.files[0].bytes), true,
    '正規packageをbyte-exactで書き出す');
  throws(() => writeGuestSourceSafely(wireForCommands, tmpRoot, 'normal-output'), /already exists/, '既存directoryへ上書きしない');
  fs.writeFileSync(path.join(tmpRoot, 'existing-file'), 'keep');
  throws(() => writeGuestSourceSafely(wireForCommands, tmpRoot, 'existing-file'), /already exists/, '既存fileへ上書きしない');
  fs.symlinkSync(saved, path.join(tmpRoot, 'existing-link'));
  throws(() => writeGuestSourceSafely(wireForCommands, tmpRoot, 'existing-link'), /already exists/, '既存symlinkを辿らない');
  fs.symlinkSync(path.join(tmpRoot, 'missing'), path.join(tmpRoot, 'dangling-link'));
  throws(() => writeGuestSourceSafely(wireForCommands, tmpRoot, 'dangling-link'), /already exists/,
    'dangling symlinkにも上書きしない');
  const partialFiles = wireForCommands.files.map((file) => ({ ...file }));
  const lateFile = partialFiles.at(-1);
  let reads = 0;
  const bytes = lateFile.bytes;
  Object.defineProperty(lateFile, 'bytes', { get() { return ++reads === 1 ? bytes : (() => { throw new Error('injected late write failure'); })(); } });
  throws(() => writeGuestSourceSafely({ ...wireForCommands, files: partialFiles }, tmpRoot, 'partial-output'),
    /injected late write failure/, '門を通った後の途中失敗をfail-closedにする');
  eq(fs.existsSync(path.join(tmpRoot, 'partial-output')), false, '途中失敗で最終出力先を残さない');
  eq(fs.readdirSync(tmpRoot).some((name) => name.startsWith('.zkp-guest-source-tmp-')), false,
    '途中失敗でtemporary directoryを残さない');
  const quoted = formatWireGuestRebuildCommands(`/tmp/guest source'; touch pwn; #`, SP1_IMAGE, wireForCommands.files);
  for (const command of quoted) envPaths.add(command.envPath);
  eq(quoted.every((command) => command.build.includes(`'"'"'`)), true, 'rebuild commandはクォートもshell escapeする');
  eq(quoted.every((command) => command.build.includes(SP1_IMAGE)), true, 'rebuild実行はSP1 imageのdigestを固定');
} finally {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
  for (const envPath of envPaths) fs.rmSync(envPath, { force: true });
}

console.log('=== guest source chunks ===');
const sourceChunks = ['0x616263', '0x646566', '0xe697a5e69cace8aa9e'];
const sourceHash = guestSourceChainHash(sourceChunks);
eq(joinGuestSourceChunks(sourceChunks, sourceHash), '0x616263646566e697a5e69cace8aa9e', 'チャンクを元バイト列へ結合');
throws(
  () => joinGuestSourceChunks(['0x616263', '0x646567', sourceChunks[2]], sourceHash),
  /hash mismatch/,
  '1 byte改変を最終hashで拒否',
);
const sourceBlocks = [100n, 101n, 102n];
const sourceLogs = sourceChunks.map((data, index) => ({
  blockNumber: sourceBlocks[index],
  logIndex: 0,
  args: {
    guestSourceHash: sourceHash,
    chunkIndex: index,
    totalChunks: sourceChunks.length,
    runningHash: guestSourceChainHash(sourceChunks.slice(0, index + 1)),
    data,
  },
}));
const recovered = recoverGuestSourceChunks(sourceLogs, sourceBlocks, sourceHash, sourceChunks.length);
eq(recovered?.source, joinGuestSourceChunks(sourceChunks, sourceHash), 'block locatorとイベント列から復元');
eq(
  recoverGuestSourceChunks(
    sourceLogs.map((log, index) => index === 1 ? { ...log, args: { ...log.args, data: '0x646567' } } : log),
    sourceBlocks,
    sourceHash,
    sourceChunks.length,
  ),
  null,
  'イベント本文1 byte改変はrunningHash不一致で拒否',
);
eq(recoverGuestSourceChunks(sourceLogs, [100n, 102n, 101n], sourceHash, 3), null, 'locator順序改変を拒否');

const fakeSourceChain = {
  contracts: { tokenMining: '0x0000000000000000000000000000000000000001' },
  client: {
    readContract: async ({ functionName, args }) => {
      if (functionName === 'guestSourceOf') return [sourceHash, 3, 3];
      if (functionName === 'guestSourceBlocks') return sourceBlocks[Number(args[1])];
      throw new Error(`unexpected read: ${functionName}`);
    },
  },
  getLogsChunked: async ({ fromBlock }) => sourceLogs.filter((log) => log.blockNumber === fromBlock),
};
eq((await collectGuestSource(fakeSourceChain, sourceHash))?.source, recovered.source, 'state→block→eventを通した復元');
const incompleteSourceChain = {
  ...fakeSourceChain,
  client: { readContract: async ({ functionName }) => functionName === 'guestSourceOf' ? [sourceHash, 3, 2] : 0n },
};
eq(await collectGuestSource(incompleteSourceChain, sourceHash), null, '未完成stateはイベントを読まず拒否');

const onchainVkey = `0x${'11'.repeat(32)}`;
const pinnedVkey = `0x${'22'.repeat(32)}`;
const mismatchSource = toHex(Buffer.from(pkg, 'utf8'));
const mismatchSourceHash = guestSourceChainHash([mismatchSource]);
const mismatchChain = {
  contracts: { tokenMining: '0x0000000000000000000000000000000000000001' },
  pendingVkeyProposal: async () => ({ pending: false }),
  vkeyEpochs: async () => [{
    index: 0,
    verifier: ZKP_EXPECTED.verifier, // verifier は本物にして、ピン留めの不一致だけで終了コード2になることを確かめる
    vkey: onchainVkey,
    guestSourceHash: mismatchSourceHash,
    activatedAt: 0,
  }],
  proofRequired: async () => false,
  blockStates: async () => ({ root: `0x${'00'.repeat(32)}`, zkEpochPlusOne: 0 }),
  client: {
    readContract: async ({ functionName }) => {
      if (functionName === 'guestSourceOf') return [mismatchSourceHash, 1, 1];
      if (functionName === 'guestSourceBlocks') return 500n;
      throw new Error(`unexpected read: ${functionName}`);
    },
  },
  getLogsChunked: async () => [{
    blockNumber: 500n,
    logIndex: 0,
    args: {
      guestSourceHash: mismatchSourceHash,
      chunkIndex: 0,
      totalChunks: 1,
      runningHash: mismatchSourceHash,
      data: mismatchSource,
    },
  }],
};
const silentUi = {
  println: () => {},
  warn: () => {},
  t: (key) => key,
};
const mismatchDataDir = fs.mkdtempSync(path.join(t44Tmp, 'bitcoinu-zkp-mismatch-'));
try {
  eq(
    await runZkpMode(
      { zkScanMaxBlock: 0, zkVkey: pinnedVkey, dataDir: mismatchDataDir },
      mismatchChain,
      silentUi,
      { isInteractive: false },
    ),
    2,
    'ピン留めvkey不一致はexit 2',
  );
} finally {
  fs.rmSync(mismatchDataDir, { recursive: true, force: true });
}

console.log('=== actual compressed package round trip ===');
const actualPackage = packGuestSource();
const actualChunkHex = actualPackage.chunks.map((chunk) => toHex(chunk));
const actualJoined = joinGuestSourceChunks(actualChunkHex, actualPackage.guestSourceHash);
const actualUnpacked = unpackGuestSource(actualJoined);
eq(actualPackage.bytes.length < GUEST_SOURCE_LIMITS.packageBytes, true, '現物v2 packageは圧縮上限内');
eq(actualPackage.uncompressedBytes.length < GUEST_SOURCE_LIMITS.payloadBytes, true, '現物v1 payloadは展開上限内');
eq(actualPackage.chunks.length <= 16, true, '現物v2 packageはオンチェーン16 chunks上限内');
eq(actualUnpacked.payloadBytes, actualPackage.uncompressedBytes.length, '展開後payload長が圧縮前と一致');
eq(actualUnpacked.files.map((f) => f.path), actualPackage.files, '現物filesの順序・pathが一致');
const byteDiffs = actualUnpacked.files
  .filter((file) => !file.bytes.equals(fs.readFileSync(path.join(CRATES_ROOT, file.path))))
  .map((file) => file.path);
eq(byteDiffs, [], 'pack→圧縮→分割→復元→展開が全fileでbyte-exact');

console.log('=== collectBlockEpochs ===');
const table = {
  0: { root: '0x' + '0'.repeat(64), zkEpochPlusOne: 0 }, // 未提出
  1: { root: '0xaa', zkEpochPlusOne: 0 },                // 証明なし
  2: { root: '0xbb', zkEpochPlusOne: 0 },                // 証明なし
  3: { root: '0xcc', zkEpochPlusOne: 1 },                // 世代0
  4: { root: '0xdd', zkEpochPlusOne: 1 },                // 世代0
  5: { root: '0xee', zkEpochPlusOne: 2 },                // 世代1
};
const fakeChain = {
  blockStates: async (n) => table[n] ?? { root: '0x' + '0'.repeat(64), zkEpochPlusOne: 0 },
};
const m = await collectBlockEpochs(fakeChain, 6);
eq(formatRanges(m.get(-1)), '1-2', '証明なしのブロック範囲');
eq(formatRanges(m.get(0)), '3-4', '世代0 のブロック範囲');
eq(formatRanges(m.get(1)), '5', '世代1 のブロック範囲');
eq(m.has(2), false, '未提出ブロックは範囲に入らない');

const unavailableMap = await collectBlockEpochs({
  blockStates: async (n) => {
    if (n === 1) throw new Error('RPC rate limited');
    if (n === 2) return { root: '0xaa', zkEpochPlusOne: undefined };
    return { root: '0x' + '0'.repeat(64), zkEpochPlusOne: 0 };
  },
}, 2);
eq(unavailableMap.unavailable.map(({ blockNum }) => blockNum), [1, 2],
  'RPC取得不能とlegacy不完全stateを証明なしへ混ぜずunavailableへ分離');
eq(unavailableMap.get(-1), undefined, '未確認ブロックをshadowと断定しない');

const scanWarnings = [];
const incompleteScanExit = await runZkpMode(
  { zkScanMaxBlock: 1 },
  {
    vkeyEpochs: async () => [],
    pendingVkeyProposal: async () => ({ pending: false }),
    proofRequired: async () => false,
    blockStates: async (n) => {
      if (n === 1) throw new Error('RPC rate limited');
      return { root: '0x' + '0'.repeat(64), zkEpochPlusOne: 0 };
    },
  },
  { println() {}, warn: (message) => scanWarnings.push(message), t: (key) => key },
  { isInteractive: false },
);
eq(incompleteScanExit, 1, '走査取得不能は成功exit 0にしない');
eq(scanWarnings, ['zk.blockScanUnavailable'], '取得不能を専用のunavailable警告で表示');

let activeBlockReads = 0;
let peakBlockReads = 0;
let totalBlockReads = 0;
const scaleMap = await collectBlockEpochs({
  blockStates: async () => {
    totalBlockReads++;
    activeBlockReads++;
    peakBlockReads = Math.max(peakBlockReads, activeBlockReads);
    await new Promise((resolve) => setImmediate(resolve));
    activeBlockReads--;
    return { root: '0x' + '0'.repeat(64), zkEpochPlusOne: 0 };
  },
}, 363);
eq(totalBlockReads, 364, '本番364 blockを欠落なく走査');
eq(peakBlockReads, ZKP_BLOCK_READ_CONCURRENCY, 'blockStates読取を有界並列unitへ分割');
eq(scaleMap.unsubmitted.length, 364, 'root未提出はunsubmittedへ全件分離');

console.log('=== block ZKP state classification ===');
const epochFixture = {
  index: 4,
  verifier: '0x1111111111111111111111111111111111111111',
  vkey: `0x${'22'.repeat(32)}`,
  guestSourceHash: `0x${'33'.repeat(32)}`,
};
const proofState = await inspectBlockZkpState({
  blockStates: async () => ({ root: `0x${'44'.repeat(32)}`, zkEpochPlusOne: 5 }),
  proofRequired: async () => true,
  vkeyEpoch: async (index) => ({ ...epochFixture, index }),
}, 9);
eq(proofState.kind, 'proof', '証明付きblockをproofに分類');
eq(proofState.epoch, epochFixture, '記録済みindex+1から対象の1世代だけを読む');
eq(proofState.currentProofRequired, true, 'proofRequiredの現在値を別途保持');

const shadowState = await inspectBlockZkpState({
  blockStates: async () => ({ root: `0x${'55'.repeat(32)}`, zkEpochPlusOne: 0 }),
  proofRequired: async () => false,
}, 9);
eq(shadowState.kind, 'shadow', 'epochPlusOne=0は正常なshadow証明なし');
eq(shadowState.currentProofRequired, false, 'shadowでもproofRequired現在値を表示できる');
const shadowChecks = new Map();
recordZkpState({ report: { check: (id, status) => shadowChecks.set(id, status) } }, { anomalies: [] }, shadowState);
eq([...shadowChecks.values()].includes('fail'), false, 'shadow証明なしはStage Cで偽FAILにならない');
eq(shadowChecks.get('check.stageC.zkProofFormat'), 'skip', 'shadowのproof外形検査は理由付きskip');

const settingUnavailable = await inspectBlockZkpState({
  blockStates: async () => ({ root: `0x${'66'.repeat(32)}`, zkEpochPlusOne: 0 }),
  proofRequired: async () => { throw new Error('RPC denied'); },
}, 9);
eq(settingUnavailable.kind, 'shadow', 'proofRequired取得不能を証明状態そのものと混同しない');
eq(settingUnavailable.currentProofRequired, null, '取得不能の現在値をfalseへfail-openしない');

const stateUnavailable = await inspectBlockZkpState({
  blockStates: async () => { throw new Error('archive state unavailable'); },
  proofRequired: async () => false,
}, 9);
eq(stateUnavailable.kind, 'unavailable', 'block state取得不能はshadowと別分類');
const unavailableChecks = new Map();
recordZkpState({ report: { check: (id, status) => unavailableChecks.set(id, status) } }, { anomalies: [] }, stateUnavailable);
eq(unavailableChecks.get('check.stageC.zkProofStatus'), 'fail', '取得不能はshadow扱いでpassしない');

console.log('=== Z14 ZKP collection failure causes ===');
let missingArtifactError = null;
try {
  await fetchRawBounded(
    async () => new Response(null, { status: 404 }),
    'https://r2.invalid', 'verification/block9/stage3/manifest.json', 1024,
  );
} catch (error) { missingArtifactError = error; }
let nonMissingHttpError = null;
try {
  await fetchRawBounded(
    async () => new Response(null, { status: 503 }),
    'https://r2.invalid', 'verification/block9/stage3/manifest.json', 1024,
  );
} catch (error) { nonMissingHttpError = error; }
eq(
  [
    missingArtifactError?.zkpArtifactMissing,
    nonMissingHttpError?.zkpArtifactMissing ?? false,
    describeZkpCollectionFailure(nonMissingHttpError, 999).cause,
  ],
  [true, false, ZKP_COLLECTION_FAILURE_CAUSES.artifactFetchError],
  'Z14 HTTP 404だけが取得不能印を持ち、その他の HTTP 障害は別原因で fail-closed になる',
);

let nonCanonicalManifestError = null;
const canonicalStage3Manifest = {
  schemaVersion: 1,
  kind: 'bitcoinu-stage3-input-manifest',
  blockNum: 9,
  groupCount: 0,
  groups: [],
};
try {
  validateStage3InputManifest(canonicalStage3Manifest, {
    blockNum: 9,
    rawText: `${JSON.stringify(canonicalStage3Manifest)}\n`,
  });
} catch (error) { nonCanonicalManifestError = error; }
eq(
  nonCanonicalManifestError?.zkpArtifactMismatch,
  true,
  'Z14 正準JSON不一致は構造化した改竄印を持つ',
);

const markedMismatch = new Error('manifest内Stage 3 input manifest sha256不一致');
markedMismatch.zkpArtifactMismatch = true;
const collectionFailures = [
  describeZkpCollectionFailure(missingArtifactError, 999),
  describeZkpCollectionFailure(markedMismatch, 999),
  describeZkpCollectionFailure(new Error('historical state unavailable'), 999),
];
eq(
  collectionFailures.map(({ cause }) => cause),
  [
    ZKP_COLLECTION_FAILURE_CAUSES.artifactMissing,
    ZKP_COLLECTION_FAILURE_CAUSES.artifactMismatch,
    ZKP_COLLECTION_FAILURE_CAUSES.rpcUnavailable,
  ],
  'Z14 取得不能・改竄・RPC障害を機械可読の3原因に分ける',
);
eq(
  [
    collectionFailures[0].error.includes('artifact is unavailable')
      && !collectionFailures[0].error.includes('archive-capable RPC'),
    collectionFailures[1].error.includes('failed sha256 or canonical JSON validation')
      && !collectionFailures[1].error.includes('archive-capable RPC'),
    collectionFailures[2].error.includes('archive-capable RPC'),
  ],
  [true, true, true],
  'Z14 原因別のエラー文は取得不能・改竄・RPC障害を取り違えない',
);

const syntheticRoot = `0x${'ab'.repeat(32)}`;
const syntheticZero = `0x${'00'.repeat(32)}`;
const syntheticPublicValues = encodePublicValues({
  blockNum: 9n,
  claimDataHash: syntheticZero,
  merkleRoot: syntheticRoot,
  evidenceAcc: syntheticZero,
  entryAcc: syntheticZero,
  randaoBlockHash: syntheticZero,
  resultManifestHash: syntheticZero,
  prevResultManifestHash: syntheticZero,
  applicantHash: syntheticZero,
  applicantHashUpdatedBlock: 0n,
  evidenceGraceSec: 0n,
  randaoEthBlockNumber: 0n,
  deploymentParamsHash: syntheticZero,
  futureAnchorsHash: syntheticZero,
  rosterManifestHash: syntheticZero,
});
const syntheticProof = `${ZKP_PROOF_FORMAT.selector}${'00'.repeat(ZKP_PROOF_FORMAT.proofBytes - 4)}`;
eq(
  inspectProofEnvelope({
    proofBytes: syntheticProof,
    publicValues: syntheticPublicValues,
    blockNum: 9,
    root: syntheticRoot,
  }).ok,
  true,
  'Z14 zkProofFormat のstatusを決めるオンチェーン証明外形検査は従来どおりpassする',
);

// ------------------------------------------------------------------
// 証明提出 calldata の組み立て（周29・第7引数 prevRegistrationIndex）
//
// 🔴 この下の fixture 依存節（履歴 Groth16 proof が不在なら process.exit する）でも
//    calldata を組むが、fixture はリポジトリ非同梱なので**その節は普段1行も走らない**。
//    そこで組み立ては下の2つの helper へ集約し、helper 自体を fixture ゲートの**手前**で
//    1回測る。helper が6引数へ戻れば viem が AbiEncodingLengthMismatchError を投げるので、
//    fixture が無い環境でも arity の後退がこの3件の赤として見える。
// ------------------------------------------------------------------
const encodeSubmitWithProof = ({
  blockNum, root, verifier, vkey, publicValues, proofBytes, prevRegistrationIndex,
}) => encodeFunctionData({
  abi: TOKEN_MINING_ABI,
  functionName: 'submitMerkleRootWithProof',
  args: [BigInt(blockNum), root, verifier, vkey, publicValues, proofBytes,
    BigInt(prevRegistrationIndex)],
});
const encodeAttachProof = ({
  blockNum, verifier, vkey, publicValues, proofBytes, prevRegistrationIndex,
}) => encodeFunctionData({
  abi: TOKEN_MINING_ABI,
  functionName: 'attachProofToMerkleRoot',
  args: [BigInt(blockNum), verifier, vkey, publicValues, proofBytes,
    BigInt(prevRegistrationIndex)],
});

console.log('=== proof submission calldata arity (prevRegistrationIndex) ===');
const arityVerifier = '0x0000000000000000000000000000000000000011';
const arityVkey = `0x${'12'.repeat(32)}`;
const arityRoot = `0x${'ab'.repeat(32)}`;
const aritySubmit = encodeSubmitWithProof({
  blockNum: 7, root: arityRoot, verifier: arityVerifier, vkey: arityVkey,
  publicValues: '0xaa', proofBytes: '0xbb', prevRegistrationIndex: 3n,
});
const arityDecodedSubmit = decodeProofSubmissionCalldata(aritySubmit);
eq([arityDecodedSubmit.functionName, arityDecodedSubmit.blockNum.toString(), arityDecodedSubmit.root,
  arityDecodedSubmit.expectedVerifier, arityDecodedSubmit.expectedVkey,
  arityDecodedSubmit.publicValues, arityDecodedSubmit.proofBytes],
['submitMerkleRootWithProof', '7', arityRoot, arityVerifier, arityVkey, '0xaa', '0xbb'],
'zkp-unitのsubmit calldata helperが7引数で組み、先頭6引数を復号し直せる');
eq(String(decodeProofPrevRegistrationIndex(aritySubmit).prevRegistrationIndex), '3',
  'zkp-unitのsubmit calldata helperが第7引数prevRegistrationIndexを載せる');
const arityAttach = encodeAttachProof({
  blockNum: 7, verifier: arityVerifier, vkey: arityVkey,
  publicValues: '0xaa', proofBytes: '0xbb', prevRegistrationIndex: PREV_REGISTRATION_SENTINEL,
});
eq([decodeProofSubmissionCalldata(arityAttach).functionName,
  String(decodeProofPrevRegistrationIndex(arityAttach).prevRegistrationIndex)],
['attachProofToMerkleRoot', String(PREV_REGISTRATION_SENTINEL)],
'zkp-unitのattach calldata helperが6引数目に番兵を載せられる');

// ── C31-11（便 C30F1c）: fixture に依存しない、証明付きの Stage C 経路 ──────────────
// 共有 collectZkpInput が名簿（PV の15語目）を HashStorage の追記履歴から共有規則で再計算し、
// rosterLastIn の view とも突き合わせる経路を、合成の proof bytes（外形だけ正しい）で両方向に回す。
// 実 proof の暗号検証は block-verifier の外（TokenMining が verifier で行う）なので、ここは外形と PV の照合だけ。
console.log('=== C31-11 fixture-independent proof-attached Stage C path (roster word 14) ===');
const stage2 = JSON.parse(fs.readFileSync(
  path.join(CRATES_ROOT, 'scoring-core/tests/fixtures/stage2.json'), 'utf8'));
const s1 = stage2.cases.find((entry) => entry.name === 'S1');
const zero = `0x${'00'.repeat(32)}`;
const collectedFixture = {
  input: {
    blockNum: s1.blockNum,
    evidenceAcc: zero,
    entryAcc: zero,
    randaoBlockHash: zero,
    prevResultManifestHash: zero,
    applicantHash: zero,
    applicantHashUpdatedBlock: 0,
    evidenceGraceSec: 0,
    randaoEthBlockNumber: 0,
    deploymentParamsHash: zero,
    futureAnchorsHash: zero,
    rosterManifestHash: zero,
  },
  claimDataHash: '0xc033504142ec70756fd7f27ecf5b3ec308cfb4bde3152e653df8c280813b1c87',
  merkleRoot: s1.root,
  resultManifestHash: s1.resultManifestHash,
};
eq(buildExpectedPublicValues(collectedFixture).merkleRoot, s1.root, '共有入力のrootを期待PVへ写像');

const expectedVerifier = '0x0000000000000000000000000000000000000011';
const expectedVkey = `0x${'12'.repeat(32)}`;
const tokenMining = '0x0000000000000000000000000000000000000001';
const evidence = '0x0000000000000000000000000000000000000002';
const hashStorage = '0x0000000000000000000000000000000000000003';
const zeroAddress = '0x0000000000000000000000000000000000000000';
const summaryRaw = Buffer.from(s1.summaryHex.slice(2), 'hex').toString('utf8');
const manifestCoreRaw = Buffer.from(s1.manifestCoreHex.slice(2), 'hex').toString('utf8');
const manifestRaw = `${manifestCoreRaw.slice(0, -1)},"manifestHash":"${s1.resultManifestHash}"}`;
const merkleRaw = JSON.stringify({ blockNum: s1.blockNum, root: s1.root });
const claimChunk = s1.chunksHex[0];
const claimHash = chunkChainHash([claimChunk]);
const currentRandaoBlockHash = `0x${'34'.repeat(32)}`;
// 共有 collector は Stage 3 input manifest（verification/block{N}/stage3/manifest.json）と
// 抽選の登録（entries/block{N}/game_selection.json）も必須で読み、結果 manifest の files に
// その sha256 が載っていることを照合する（S1 の manifest には無い）。Stage C 経路の歯は、
// S1 の files に空の Stage 3 manifest と登録0件（番兵）の選出を足した結果 manifest を使う。
const selectionRaw = JSON.stringify({ blockNum: s1.blockNum, players: [] });
const rosterIndexRaw = JSON.stringify({ zkpFixture: 0 });
const rosterGroupRaw = JSON.stringify({ blockNum: s1.blockNum, groupId: 0,
  members: [{ uid: 'zkpFixture', walletAddress: `0x${'11'.repeat(20)}` }] });
const rosterIndexKey = `games/block${s1.blockNum}/roster/index.json`;
const rosterGroupKey = `games/block${s1.blockNum}/roster/group0.json`;
const stage3ManifestRaw = JSON.stringify({
  schemaVersion: 1, kind: 'bitcoinu-stage3-input-manifest', blockNum: s1.blockNum, groupCount: 0, groups: [],
});
const sha256Of = (text) => createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
const stageCManifestCoreObject = JSON.parse(manifestCoreRaw);
stageCManifestCoreObject.files = {
  ...stageCManifestCoreObject.files,
  [`verification/block${s1.blockNum}/stage3/manifest.json`]: sha256Of(stage3ManifestRaw),
  [`entries/block${s1.blockNum}/game_selection.json`]: sha256Of(selectionRaw),
  [rosterIndexKey]: sha256Of(rosterIndexRaw),
  [rosterGroupKey]: sha256Of(rosterGroupRaw),
};
const stageCManifestCoreRaw = JSON.stringify(stageCManifestCoreObject);
const stageCResultManifestHash = `0x${sha256Of(stageCManifestCoreRaw)}`;
const stageCManifestRaw = `${stageCManifestCoreRaw.slice(0, -1)},"manifestHash":"${stageCResultManifestHash}"}`;
const stageCArtifacts = {
  manifest: stageCManifestRaw, summary: summaryRaw, merkle: merkleRaw, stage3Manifest: stage3ManifestRaw,
  selection: selectionRaw,
};
// 名簿の窓 [応募終了, 応募終了 + grace)。grace が 0 だと共有規則が窓を拒否するので本番と同じ正の値にする。
const STAGE_C_ENTRY_END = 1_799_000_000;
const STAGE_C_GRACE = 7200;
const stageCCollected = (rosterManifestHash) => ({
  ...collectedFixture,
  input: {
    ...collectedFixture.input,
    randaoBlockHash: currentRandaoBlockHash,
    randaoEthBlockNumber: 64,
    evidenceGraceSec: STAGE_C_GRACE,
    rosterManifestHash,
  },
  claimDataHash: claimHash,
  resultManifestHash: stageCResultManifestHash,
});
// HashStorage.rosterLastIn と同じ規則（registeredAt < to の最後の行が from 以上ならその hash）。
const rosterLastInOf = (rows, from, to) => {
  const last = rows.filter((row) => row.at < to).at(-1);
  return last && last.at >= from ? [true, last.hash] : [false, zero];
};
const makeProofChain = ({ input, rosterRows = [], rosterView = null }) => ({
  rosterManifestText: rosterRows.at(-1)?.hash === ROSTER_B ? rosterManifestB : rosterManifestA,
  rpcUrl: 'http://independent-rpc.invalid',
  contracts: { tokenMining },
  client: {
    getTransaction: async () => ({ to: tokenMining, input }),
    getBlock: async ({ blockNumber }) => ({ number: blockNumber, timestamp: 1_800_000_000n }),
    readContract: async ({ functionName, args }) => {
      if (functionName === 'evidence') return evidence;
      if (functionName === 'hashStorage') return hashStorage;
      if (functionName === 'anchorProvider' || functionName === 'pendingAnchorProvider') return zeroAddress;
      if (functionName === 'pendingVkeyEta') return 0n;
      if (functionName === 'claimDataOf') return [claimHash, 1, 1];
      if (functionName === 'getClaimDataBlocks') return [99n];
      if (functionName === 'evidenceAcc' || functionName === 'entryAcc'
        || functionName === 'deploymentParamsHash') return zero;
      if (functionName === 'blockHashOf') return currentRandaoBlockHash;
      if (functionName === 'applicantHashes') return [zero, 0n, zeroAddress];
      if (functionName === 'registrationCount') return 0n;
      if (functionName === 'resultHashes') return [stageCResultManifestHash, 1n, zeroAddress];
      if (functionName === 'currentGrace') return BigInt(STAGE_C_GRACE);
      // C30F1 で collector が読むようになった名簿の読み取り（readCanonicalRosterHash）。
      if (functionName === 'scheduledGameStart') return BigInt(STAGE_C_ENTRY_END);
      if (functionName === 'otherRegistrationCount') return BigInt(rosterRows.length);
      if (functionName === 'otherRegistrationAt') {
        const row = rosterRows[Number(args[1])];
        return [row.hash, BigInt(row.block), BigInt(row.at)];
      }
      if (functionName === 'rosterLastIn') {
        return rosterView ?? rosterLastInOf(rosterRows, Number(args[1]), Number(args[2]));
      }
      throw new Error(`unexpected readContract ${functionName}`);
    },
  },
  getLogsChunked: async () => [{
    blockNumber: 99n,
    logIndex: 0,
    args: {
      blockNum: 0n,
      chunkIndex: 0,
      totalChunks: 1,
      runningHash: claimHash,
      data: claimChunk,
    },
  }],
});
const inspectStageC = (chain, txHash = `0x${'77'.repeat(32)}`) => inspectProofSubmission({
  chain,
  blockNum: s1.blockNum,
  root: s1.root,
  event: { txHash, evtBlock: 100 },
  epoch: { verifier: expectedVerifier, vkey: expectedVkey },
  artifacts: { ...stageCArtifacts, rosterManifest: chain.rosterManifestText,
    rosterIndex: rosterIndexRaw, rosterGroups: new Map([[0, rosterGroupRaw]]) },
  r2Base: 'https://r2.bitcoinu.org',
});
const syntheticProofBytes = `${ZKP_PROOF_FORMAT.selector}${'00'.repeat(ZKP_PROOF_FORMAT.proofBytes - 4)}`;
const syntheticSubmit = (publicValues) => encodeSubmitWithProof({
  blockNum: s1.blockNum, root: s1.root, verifier: expectedVerifier, vkey: expectedVkey,
  publicValues, proofBytes: syntheticProofBytes, prevRegistrationIndex: 0n,
});
const syntheticAttach = (publicValues) => encodeAttachProof({
  blockNum: s1.blockNum, verifier: expectedVerifier, vkey: expectedVkey,
  publicValues, proofBytes: syntheticProofBytes, prevRegistrationIndex: 0n,
});
const rosterManifestA = JSON.stringify({ blockNum: s1.blockNum,
  indexSha256: sha256Of(rosterIndexRaw), groups: [{ groupId: 0, sha256: sha256Of(rosterGroupRaw) }] });
const rosterManifestB = JSON.stringify({ blockNum: s1.blockNum,
  indexSha256: sha256Of(rosterIndexRaw), groups: [{ groupId: 0, sha256: sha256Of(rosterGroupRaw) }], revision: 2 });
const rosterGroupTexts = new Map([[0, rosterGroupRaw]]);
const ROSTER_A = buildRosterMemberCommitment({ blockNum: s1.blockNum,
  manifestText: rosterManifestA, groupTexts: rosterGroupTexts }).C;
const ROSTER_B = buildRosterMemberCommitment({ blockNum: s1.blockNum,
  manifestText: rosterManifestB, groupTexts: rosterGroupTexts }).C;
const inWindow = STAGE_C_ENTRY_END + 100;
const pvWithRoster = (hash) => encodePublicValues(buildExpectedPublicValues(stageCCollected(hash)));
{
  const rows = [{ hash: ROSTER_A, block: 90, at: inWindow }];
  const passSubmit = await inspectStageC(makeProofChain({ input: syntheticSubmit(pvWithRoster(ROSTER_A)), rosterRows: rows }));
  eq([passSubmit.format.status, passSubmit.publicValues.status], ['pass', 'pass'],
    'C31-11 窓内の非ゼロ名簿を15語目に載せた証明付き提出は Stage C で再計算と一致');
  const passAttach = await inspectStageC(makeProofChain({ input: syntheticAttach(pvWithRoster(ROSTER_A)), rosterRows: rows }));
  eq([passAttach.format.status, passAttach.publicValues.status], ['pass', 'pass'],
    'C31-11 事後添付でも非ゼロ名簿の15語目を再計算できる');
  const zeroWord = await inspectStageC(makeProofChain({ input: syntheticSubmit(pvWithRoster(zero)), rosterRows: rows }));
  eq([zeroWord.format.status, zeroWord.publicValues.status], ['pass', 'fail'],
    'C31-11 窓内に名簿があるのに15語目が0の証明を拒否');
  eq((zeroWord.publicValues.mismatches || []).map((row) => row.name), ['rosterManifestHash'],
    'C31-11 不一致は15語目（rosterManifestHash）だけ');
  const otherWord = await inspectStageC(makeProofChain({ input: syntheticSubmit(pvWithRoster(ROSTER_B)), rosterRows: rows }));
  eq(otherWord.publicValues.status, 'fail', 'C31-11 別の名簿 hash を名乗る15語目を拒否');
}
{
  // 窓の最後の行が後から別 hash に置き換わった（窓内の2行目）: 正典は最後の行。
  const rows = [{ hash: ROSTER_A, block: 90, at: inWindow }, { hash: ROSTER_B, block: 91, at: inWindow + 50 }];
  const stale = await inspectStageC(makeProofChain({ input: syntheticSubmit(pvWithRoster(ROSTER_A)), rosterRows: rows }));
  eq(stale.publicValues.status, 'fail', 'C31-11 窓内の最後の行でない名簿を名乗る15語目を拒否');
  const latest = await inspectStageC(makeProofChain({ input: syntheticSubmit(pvWithRoster(ROSTER_B)), rosterRows: rows }));
  eq(latest.publicValues.status, 'pass', 'C31-11 窓内の最後の行を名乗る15語目は通る');
}
{
  // 開始以後に着地した行は窓の外（案 U の anchor_late と同じ境界）。正典は0。
  const rows = [{ hash: ROSTER_A, block: 95, at: STAGE_C_ENTRY_END + STAGE_C_GRACE }];
  const outside = await inspectStageC(makeProofChain({ input: syntheticSubmit(pvWithRoster(ROSTER_A)), rosterRows: rows }));
  eq(outside.publicValues.status, 'fail', 'C31-11 開始以後に着地した名簿を名乗る15語目を拒否');
  const zeroOk = await inspectStageC(makeProofChain({ input: syntheticSubmit(pvWithRoster(zero)), rosterRows: rows }));
  eq(zeroOk.publicValues.status, 'pass', 'C31-11 窓内に行が無ければ15語目は0で通る');
}
{
  // 追記履歴と契約の view が食い違えば、collector は再計算を拒否する（黙って片方を採らない）。
  const rows = [{ hash: ROSTER_A, block: 90, at: inWindow }];
  const split = await inspectStageC(makeProofChain({
    input: syntheticSubmit(pvWithRoster(ROSTER_A)), rosterRows: rows, rosterView: [true, ROSTER_B],
  }));
  eq(split.publicValues.status === 'pass', false, 'C31-11 追記履歴と rosterLastIn の食い違いでは再計算を通さない');
}

console.log('=== actual Groth16 proof envelope / public values ===');
// 履歴 fixture の場所は既定のまま。ZKP_UNIT_COLD_PROOF_FIXTURE は検証用の差し替え口（C31-11）。
const coldProofPath = process.env.ZKP_UNIT_COLD_PROOF_FIXTURE
  ? path.resolve(process.env.ZKP_UNIT_COLD_PROOF_FIXTURE)
  : path.join(REPO_ROOT, 'scripts/zkp-prover/results/g1-20260809-180558-52143/cold-proof.json');
// D4-05: この履歴fixtureはリポジトリ非同梱で、ローカルproveして補ってはならない。
// ENOENTを未処理throwにすると、ここより前のassert失敗も最終fail集計へ届かず同じ赤に
// 潰れる。fixture不在そのものを明示的な1失敗として確定し、前段の合否と一緒に終了する。
if (!fs.existsSync(coldProofPath)) {
  fail++;
  console.log(`  ❌ 履歴Groth16 proof fixtureが不在（基準赤を維持）\n     path=${coldProofPath}`);
  console.log('  SKIP fixture依存の後段34 assertions（prove / vkey生成は実行しない）');
  console.log(`\n${pass} passed / ${fail} failed`);
  process.exit(1);
}
const coldProof = JSON.parse(fs.readFileSync(coldProofPath, 'utf8'));
const actualEnvelope = inspectProofEnvelope({
  proofBytes: coldProof.proofBytes,
  publicValues: coldProof.publicValues,
  blockNum: coldProof.blockNum,
  root: coldProof.merkleRoot,
});
eq(actualEnvelope.ok, false, '旧14語の実Groth16 proof fixtureは新契約の外形で拒否');
eq(actualEnvelope.selector, '0x4388a21c', '実proof selectorを検査');
eq(actualEnvelope.proofLength, 356, '実proofは356 bytes');
eq(actualEnvelope.publicValuesLength, 448, '実public valuesは448 bytes（14語）');
eq(ZKP_PROOF_FORMAT.publicValueWords, 15, '検査定数は15語');

const badSelector = inspectProofEnvelope({
  proofBytes: `0x4388a21d${coldProof.proofBytes.slice(10)}`,
  publicValues: coldProof.publicValues,
  blockNum: coldProof.blockNum,
  root: coldProof.merkleRoot,
});
eq(badSelector.ok, false, 'selector 1 byte改変を拒否');
const shortProof = inspectProofEnvelope({
  proofBytes: coldProof.proofBytes.slice(0, -2),
  publicValues: coldProof.publicValues,
  blockNum: coldProof.blockNum,
  root: coldProof.merkleRoot,
});
eq(shortProof.ok, false, 'proof 1 byte欠落を拒否');
const shortPv = inspectProofEnvelope({
  proofBytes: coldProof.proofBytes,
  publicValues: coldProof.publicValues.slice(0, -2),
  blockNum: coldProof.blockNum,
  root: coldProof.merkleRoot,
});
eq(shortPv.ok, false, 'public values 1 byte欠落を拒否');

// cold proofはstage2.jsonのS1から作られた。proof JSON自身のdecoded値ではなく、
// 独立fixtureから旧ゲストの14語を再現し、新契約の15語外形では拒否する。
const expectedFifteen = encodePublicValues(buildExpectedPublicValues(collectedFixture));
eq(coldProof.publicValues, expectedFifteen.slice(0, 2 + 448 * 2),
  '旧ゲストの14語は独立fixtureと一致');
// 🔴 C31-11: compareRebuiltPublicValues は内部の decodePublicValues が 480 バイト以外を throw する。
//    448 バイトの旧14語は ok:false ではなく decode の段で拒否される（スクリプトごと落とさない）。
throws(() => compareRebuiltPublicValues(coldProof.publicValues, collectedFixture),
  /32 bytes × 15語/, '旧14語の実proofは新契約の15語比較（decode）で拒否');
const pvLast = coldProof.publicValues.slice(-2) === '00' ? '01' : '00';
const mutatedPv = `${coldProof.publicValues.slice(0, -2)}${pvLast}`;
throws(() => compareRebuiltPublicValues(mutatedPv, collectedFixture),
  /32 bytes × 15語/, 'public values 1 byte改変も15語比較（decode）で拒否');
const mutatedFifteen = `${expectedFifteen.slice(0, -2)}${expectedFifteen.slice(-2) === '00' ? '01' : '00'}`;
eq(compareRebuiltPublicValues(mutatedFifteen, collectedFixture).ok, false,
  '15語の public values の1 byte改変を15語比較で拒否');

const proofCalldata = encodeSubmitWithProof({
  blockNum: coldProof.blockNum, root: coldProof.merkleRoot,
  verifier: expectedVerifier, vkey: expectedVkey,
  publicValues: coldProof.publicValues, proofBytes: coldProof.proofBytes,
  prevRegistrationIndex: 0n,
});
const decodedCall = decodeProofSubmissionCalldata(proofCalldata);
eq(decodedCall.blockNum.toString(), String(coldProof.blockNum), '実proofを含む提出calldataのblockNumを復号');
eq(decodedCall.root, coldProof.merkleRoot, '実proofを含む提出calldataのrootを復号');
eq(decodedCall.proofBytes, coldProof.proofBytes, '実proof bytesをcalldataからbyte-exactに復号');
eq(decodedCall.expectedVerifier, expectedVerifier, '初回提出calldataの期待verifierを復号');
eq(decodedCall.expectedVkey, expectedVkey, '初回提出calldataの期待vkeyを復号');
const attachCalldata = encodeAttachProof({
  blockNum: coldProof.blockNum, verifier: expectedVerifier, vkey: expectedVkey,
  publicValues: coldProof.publicValues, proofBytes: coldProof.proofBytes,
  prevRegistrationIndex: 0n,
});
const decodedAttach = decodeProofSubmissionCalldata(attachCalldata);
eq(decodedAttach.functionName, 'attachProofToMerkleRoot', '事後添付calldataを識別');
eq(decodedAttach.root, null, '事後添付rootはPVと既存stateから検査するためcalldata直値なし');
eq(decodedAttach.expectedVerifier, expectedVerifier, '事後添付calldataの期待verifierを復号');

console.log('=== V25-01 proof attachment event identity ===');
const attachmentRootEvent = {
  root: coldProof.merkleRoot, timestamp: 1_800_000_000,
  txHash: `0x${'11'.repeat(32)}`, evtBlock: 100, transactionIndex: 2, logIndex: 4,
};
const attachmentEvent = (overrides = {}) => ({
  root: coldProof.merkleRoot, epochIndex: 3, timestamp: 1_800_000_000,
  txHash: attachmentRootEvent.txHash, evtBlock: 100, transactionIndex: 2, logIndex: 5,
  ...overrides,
});
const resolvedSameTx = resolveCurrentProofAttachment({
  rootEvent: attachmentRootEvent, attachmentEvents: [attachmentEvent()],
  currentRoot: coldProof.merkleRoot, epochIndex: 3, proofAttachedAt: 1_800_000_000,
});
eq(resolvedSameTx.ok && resolvedSameTx.kind, 'simultaneous', '同一txHashのroot＋proofだけをsimultaneousと判定');
const resolvedSameBlockOtherTx = resolveCurrentProofAttachment({
  rootEvent: attachmentRootEvent,
  attachmentEvents: [attachmentEvent({ txHash: `0x${'22'.repeat(32)}`, transactionIndex: 3, logIndex: 0 })],
  currentRoot: coldProof.merkleRoot, epochIndex: 3, proofAttachedAt: 1_800_000_000,
});
eq(resolvedSameBlockOtherTx.ok && resolvedSameBlockOtherTx.kind, 'post_commit', '同一block・同一timestampでも別txはpost-commit');
const resolvedLaterBlock = resolveCurrentProofAttachment({
  rootEvent: attachmentRootEvent,
  attachmentEvents: [attachmentEvent({ txHash: `0x${'33'.repeat(32)}`, evtBlock: 101, transactionIndex: 0, logIndex: 0, timestamp: 1_800_000_012 })],
  currentRoot: coldProof.merkleRoot, epochIndex: 3, proofAttachedAt: 1_800_000_012,
});
eq(resolvedLaterBlock.ok && resolvedLaterBlock.kind, 'post_commit', '別blockのproof添付はpost-commit');
eq(resolveCurrentProofAttachment({ rootEvent: attachmentRootEvent, attachmentEvents: [], currentRoot: coldProof.merkleRoot,
  epochIndex: 3, proofAttachedAt: 1_800_000_000 }).ok, false, 'attachment event欠落を拒否');
eq(resolveCurrentProofAttachment({ rootEvent: attachmentRootEvent, attachmentEvents: [attachmentEvent(), attachmentEvent({ logIndex: 6 })],
  currentRoot: coldProof.merkleRoot, epochIndex: 3, proofAttachedAt: 1_800_000_000 }).ok, false, '重複attachment eventを拒否');
eq(resolveCurrentProofAttachment({ rootEvent: attachmentRootEvent, attachmentEvents: [attachmentEvent({ root: `0x${'44'.repeat(32)}` })],
  currentRoot: coldProof.merkleRoot, epochIndex: 3, proofAttachedAt: 1_800_000_000 }).ok, false, '別root attachmentを拒否');
eq(resolveCurrentProofAttachment({ rootEvent: attachmentRootEvent, attachmentEvents: [attachmentEvent({ epochIndex: 4 })],
  currentRoot: coldProof.merkleRoot, epochIndex: 3, proofAttachedAt: 1_800_000_000 }).ok, false, '別epoch attachmentを拒否');

// 共有collectZkpInputまで含めた証明付きStage C経路（実proofの bytes を使う版）。ネットワークは使わず、
// S1の独立fixtureとそのオンチェーン対応値を公開RPC/R2と同じinterfaceで供給する。名簿は未登録（15語目0）。
const currentPublicValues = encodePublicValues(buildExpectedPublicValues(stageCCollected(zero)));
const currentProofCalldata = encodeSubmitWithProof({
  blockNum: coldProof.blockNum, root: coldProof.merkleRoot,
  verifier: expectedVerifier, vkey: expectedVkey,
  publicValues: currentPublicValues, proofBytes: coldProof.proofBytes,
  prevRegistrationIndex: 0n,
});
const currentAttachCalldata = encodeAttachProof({
  blockNum: coldProof.blockNum, verifier: expectedVerifier, vkey: expectedVkey,
  publicValues: currentPublicValues, proofBytes: coldProof.proofBytes,
  prevRegistrationIndex: 0n,
});
const postClaimSummary = JSON.parse(summaryRaw);
postClaimSummary.groups[0].members[0].claimed = { time: '2030-01-01T00:00:00.000Z', txHash: `0x${'88'.repeat(32)}` };
const selectedSummary = selectZkpSummaryRaw({
  publishedRaw: JSON.stringify(postClaimSummary),
  rebuiltSummary: JSON.parse(summaryRaw),
  manifest: JSON.parse(manifestRaw),
  blockNum: 0,
});
eq(selectedSummary.source, 'rebuilt', 'claim後の可変summaryではmanifest一致する独立再構築bytesを選ぶ');
eq(selectedSummary.raw, summaryRaw, 'ZKP入力へ渡す再構築summaryはmanifest固定の元bytesと一致');
const fakeProofChain = makeProofChain({ input: currentProofCalldata });
const integrated = await inspectProofSubmission({
  chain: fakeProofChain,
  blockNum: coldProof.blockNum,
  root: coldProof.merkleRoot,
  event: { txHash: `0x${'77'.repeat(32)}`, evtBlock: 100 },
  epoch: { verifier: expectedVerifier, vkey: expectedVkey },
  artifacts: stageCArtifacts,
  r2Base: 'https://r2.bitcoinu.org',
});
eq(integrated.format.status, 'pass', '証明付き提出txの外形をStage C経路で検査');
eq(integrated.publicValues.status, 'pass', '共有collectZkpInputで15語を再計算するStage C経路が成功');

const integratedAttach = await inspectProofSubmission({
  chain: {
    ...fakeProofChain,
    client: { ...fakeProofChain.client, getTransaction: async () => ({ to: tokenMining, input: currentAttachCalldata }) },
  },
  blockNum: coldProof.blockNum,
  root: coldProof.merkleRoot,
  event: { txHash: `0x${'66'.repeat(32)}`, evtBlock: 101 },
  epoch: { verifier: expectedVerifier, vkey: expectedVkey },
  artifacts: stageCArtifacts,
  r2Base: 'https://r2.bitcoinu.org',
});
eq(integratedAttach.format.status, 'pass', '事後添付txも同じproof外形検査を通る');
eq(integratedAttach.publicValues.status, 'pass', '事後添付時点の履歴stateで15語を再構築できる');

const wrongRootCalldata = encodeSubmitWithProof({
  blockNum: coldProof.blockNum, root: `0x${'99'.repeat(32)}`,
  verifier: expectedVerifier, vkey: expectedVkey,
  publicValues: coldProof.publicValues, proofBytes: coldProof.proofBytes,
  prevRegistrationIndex: 0n,
});
const calldataMismatch = await inspectProofSubmission({
  chain: {
    ...fakeProofChain,
    client: { ...fakeProofChain.client, getTransaction: async () => ({ to: tokenMining, input: wrongRootCalldata }) },
  },
  blockNum: coldProof.blockNum,
  root: coldProof.merkleRoot,
  event: { txHash: `0x${'55'.repeat(32)}`, evtBlock: 101 },
  epoch: { verifier: expectedVerifier, vkey: expectedVkey },
  artifacts: stageCArtifacts,
  r2Base: 'https://r2.bitcoinu.org',
});
eq(calldataMismatch.format.status, 'fail', 'attachmentがtransactionのcalldataの別rootを拒否');

console.log(`\n${pass} passed / ${fail} failed`);
process.exit(fail ? 1 : 0);

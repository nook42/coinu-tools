// canonical.mjs — 正典（本番）コードの Node 取り込み一元化。
//
// 原則: フィクスチャ生成物は全て本番コードの実行結果とする（DESIGN.md §1/§5）。
// ここは block-verifier/vendor ではなく workers/ の正典を直接 import する
// （vendor は検証ツール側の写像。フィクスチャは「サーバー側の実装そのもの」で作る）。
//
// ethers 解決フック: root node_modules の ethers は CF-workers フォーク（5.4.6 モノレポ形態）で、
// package.json の main がESM解決できない。collect-DO.js / lottery-DO.js のモジュールトップ
// `import { ethers } from 'ethers'` を実ビルド（packages/ethers/lib/index.js, CJS）へ向ける。
import { registerHooks } from 'node:module';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dir = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(__dir, '..', '..');

const ETHERS_ENTRY = pathToFileURL(
  resolve(REPO_ROOT, 'node_modules/ethers/packages/ethers/lib/index.js')
).href;

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'ethers') {
      return { url: ETHERS_ENTRY, shortCircuit: true };
    }
    return nextResolve(specifier, context);
  },
});

// フック登録後に動的 import（静的 import だとフック前に解決されてしまう）
const gmMod = await import(pathToFileURL(resolve(REPO_ROOT, 'workers/game_workers/game-master-DO.js')).href);
const cgMod = await import(pathToFileURL(resolve(REPO_ROOT, 'workers/game_workers/chat-game-DO.js')).href);
const lotMod = await import(pathToFileURL(resolve(REPO_ROOT, 'workers/lottery_workers/lottery-DO.js')).href);
const colMod = await import(pathToFileURL(resolve(REPO_ROOT, 'workers/collect_workers/collect-DO.js')).href);
const protoMod = await import(pathToFileURL(resolve(REPO_ROOT, 'workers/game_workers/lib/protocol-v2.js')).href);
const calcMod = await import(pathToFileURL(resolve(REPO_ROOT, 'workers/game_workers/lib/game-result-calculator.js')).href);
const charMod = await import(pathToFileURL(resolve(REPO_ROOT, 'workers/game_workers/lib/char-counter.js')).href);
const compactMod = await import(pathToFileURL(resolve(REPO_ROOT, 'workers/game_workers/lib/evidence-compact-v1.js')).href);
const limitsMod = await import(pathToFileURL(resolve(REPO_ROOT, 'workers/game_workers/lib/submission-limits.js')).href);

export const GameMasterDO = gmMod.GameMasterDO;
export const ChatGameDO = cgMod.ChatGameDO;
export const LotteryDO = lotMod.LotteryDO;
export const getConfirmationBlocks = lotMod.getConfirmationBlocks;
export const CollectDO = colMod.CollectDO;
export const {
  chatSignStringV2, actionSignStringV2, actionHashV2,
  receiptSignString, readReceiptSignString,
  computeChatHashV2, computeMsgKeyV2, msgRefOf,
  buildRealTargets, selectBundleReceipts, receiptMaxRefsPerReceipt,
  buildMsgKeyGetter, canonicalComparatorV2,
  // P-2026-0842: 投票・密告の平文は固定長パディングが必須（正典が暗号文長を強制する）
  padActionPlaintext, isCanonicalActionCiphertext, ACTION_CIPHERTEXT_HEX_LEN,
} = protoMod;
export const {
  getBlockRewardWei, calculateDepositPoints, parseDepositWei, receiptCanonCmp,
} = calcMod;
export const { applyChatCaps, countHalfWidthChars, GUEST_PINNED_RULES } = charMod;
export const {
  aggregateSelfReceipts,
  encodeEvidenceCompactV1,
  decodeSubmissionPayloadString,
  filterReceiptsToCarriedTargets,
  limitCarriedReceiptFacts,
  compactBytesToPayload,
  compactPayloadToBytes,
} = compactMod;
export const { normalizeActionSnapshotForSubmission } = limitsMod;

// collect-worker.js / collect-DO.js の calculateHash（同一実装、collect-worker.js:194-202 /
// collect-DO.js:1197-1205）。CollectDO.prototype.calculateHash は this 非依存なのでそのまま正典実行する。
export const collectCalculateHash = (data) => CollectDO.prototype.calculateHash.call(null, data);

// collect-DO.js:1375-1392 createIntermediateHash（純関数）を正典実行
export const createIntermediateHash = (blockNum, hashList) =>
  CollectDO.prototype.createIntermediateHash.call(null, blockNum, hashList);

// collect-DO.js:1395-1403 createRootHash（this.calculateHash のみ使用）を正典実行
export const createRootHash = (blockNum, intermediate) =>
  CollectDO.prototype.createRootHash.call(
    { calculateHash: CollectDO.prototype.calculateHash }, blockNum, intermediate);

// collect-DO.js:1331-1372 readWorkerHashFiles（A5 全100ワーカー完全性込み）を
// env.R2_BUCKET スタブ束縛で正典実行
export const readWorkerHashFiles = (r2Bucket, blockNum) =>
  CollectDO.prototype.readWorkerHashFiles.call(
    { env: { R2_BUCKET: r2Bucket }, calculateHash: CollectDO.prototype.calculateHash }, blockNum);

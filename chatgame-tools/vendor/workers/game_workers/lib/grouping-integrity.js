// workers/game_workers/lib/grouping-integrity.js
//
// グループ分け結果（game_groups.json / summary.json / D1 game_groups）の完全性検査。
//
// 背景（内部レビュー P-2026-0816 / 2026-08-07）:
//   選出には**内側のゲート**がある（`verifySelectionIntegrity` が公開値から当選者行を丸ごと
//   再構築して照合する）のに、**グループ分けには何も無かった**。
//   `formGroups` は startGrouping で一度だけ走り、その戻り値がそのまま
//     writeGroupsToD1 → createGroupSummary → buildBlockSummaryForR2
//   へ流れ、**出力を再計算して照合するコードがサーバー側に存在しなかった**。
//   その結果:
//     ・共謀者を1グループに集約する
//     ・標的を単独グループへ隔離する
//     ・summary.json のメンバー順だけ入れ替える（＝タブー/正準順序の基準を動かす）
//     ・groupId を付け替える
//     ・totalGroups を水増しする
//   のいずれも、D1・`game_groups.json`・`summary.json` が**揃って一貫した嘘**になり、
//   検出は第三者が `block-verifier` を回した時だけだった。
//
// 🔴 この層が捕まえるもの／捕まえないもの:
//   `formGroups` は決定論的なので、同じ入力で再実行すれば必ず同じ結果になる。
//   したがってこの層が捕まえるのは「**正直に計算した後の差し替え**」であって、
//   **`formGroups` 自体の改竄ではない**。コードそのものを書き換える攻撃は
//   「vendor 同期 ＋ block-verifier の独立再現」が担当する層である（設計どおり）。
//
// 🔴 再実行の入力のうち、何が権威に縛られていて、何が縛られていないか:
//
//   | 入力 | 権威への束縛 | 束縛している場所 |
//   |---|---|---|
//   | `players` | ✅ 縛られている | 直前の `verifySelectionIntegrity`（同一呼び出し内）が info ファイル＋entries データファイルから当選者行を再構築して全フィールド照合する |
//   | `groupSeed` | ✅ 縛られている | 本モジュールが `randao ‖ applicantHash ‖ "group"` から**独立に再導出**して照合（block-verifier `stages/grouping.js:74` と同一） |
//   | `majorLangs` | ✅ 縛られている | 前ブロック成果物を**アンカー検証つきの読み手**で読み直し、`computeMajorLangs` を再実行して照合（下記④） |
//   | `randao` / `applicantHash` | ⚠️ **縛られていない** | 正典側にはオンチェーン RANDAO / `applicantHash` との照合が無い（形式検査のみ）。これは block-verifier の Stage A/B-1 が担当する層で、本モジュールの守備範囲外 |
//   | グループメンバーの `data` 実体 | ⚠️ **部分的** | `formGroups` の戻り値のメンバーは `players[]` と**同一オブジェクト参照**なので、両方を同時に書き換える攻撃はここでは見えない（`verifySelectionIntegrity` が R2 と突き合わせた後の in-memory 改変）。構造（誰がどのグループか）の差し替えは全部捕まる |
//
// 検証ツール（block-verifier/src/stages/grouping.js）との対応:
//   | ツールの検査 | 本モジュール |
//   |---|---|
//   | `check.stageB.groupSeed`        | ② groupSeed の独立再導出＋照合 |
//   | `check.stageB.groupsMatch`      | ④ 再実行結果と groupId/lang/mixed/memberIds を厳密一致 |
//   | `check.stageB.groupCount`       | ⑤ totalGroups == 実配列長 == 再現数 |
//   | `check.stageB.groupStats`       | ⑥ groupsByLang / mixedGroups / groupSizes の再計算 |
//   | `check.stageB.summaryStructure` | ⑦ summary.json のメンバー順が再現結果と一致 |
//   | `check.stageB.prevAnchor`       | ③ 前ブロック成果物を manifest ＋ getResultHash(N-1) でアンカー検証 |
//
// 規則版数のピン:
//   `block-verifier/src/config.js` の `pins` には `selectionIntegrityRule` の pin が**無い**
//   （検証ツールは正典を import せず独立再実装しているため、版数を突き合わせる意味がない）。
//   `GROUPING_INTEGRITY_RULE_VERSION` も同じ扱いで pin を足さない。
//   版数は「正典側の検査規則が変わったこと」をログ・進捗データに残すためのもの。
//
// 実行コスト（M系 Mac 実測・2,100人／524グループ／主要言語2つ／前ブロック 1,800 人分の summary）:
//   本検査ぜんぶで **52 ms**（内訳: `formGroups` 再実行 ≈47 ms ＋ 照合・sha256・clone ≈5 ms）。
//   初回の `formGroups` 自体が 53 ms なので、グループ分けの所要時間は実質2倍になるだけ。
//   `deterministicRandom` の SHA-256 が O(P) 回走るだけで、1呼び出しの予算
//   （CALC_WALL_BUDGET_MS = 18,000 ms）に対して3桁小さい。
//   → 選出照合（`verifySelectionIntegrity`）のような resumable yield は**不要**
//     （＝進捗カーソルも既存の再開機構への追加配線も要らない）。
//   追加の I/O は前ブロックの manifest / summary の R2 読取と `resultHashes(N-1)` の
//   RPC 読取1回のみ（`computeMajorLangs` の再実行分と合わせて R2 読取 2〜3 回）。

import { keccak256, concatHex, stringToHex } from 'viem';

// 規則版数（変更したら検証ツール側の期待値も更新すること）
//   1 … 再実行照合（groupSeed / majorLangs / groups / game_groups.json / summary.json）
//       ＋ 前ブロック成果物のオンチェーンアンカー検証
//   2 … Q-5（2026-08-08）: `computeMajorLangs` の `game_selection.json` フォールバックを削除。
//       前ブロックの入力は `summary.json` の1本だけになり、読んだ前ブロック成果物は
//       **例外なく**アンカー検証の対象になった（未宣言＝逸脱）
export const GROUPING_INTEGRITY_RULE_VERSION = 2;

const HEX32 = /^0x[0-9a-fA-F]{64}$/;

// 正準等価（block-verifier src/json-utils.js canonicalEqual と同一規則）。
// キーのソートはしない — バックエンドのハッシュ規約と同じ素の JSON.stringify 比較。
const canonicalEqual = (a, b) => JSON.stringify(a) === JSON.stringify(b);

const brief = (v, n = 200) => {
  const s = JSON.stringify(v);
  return s === undefined ? String(v) : (s.length > n ? `${s.slice(0, n)}…` : s);
};

/**
 * グループ分けシードの導出: groupSeed = keccak256(randao ‖ applicantHash ‖ "group")
 *
 * game-master-DO.js:187 の `deriveGroupSeed` と**同一バイト列**を返す独立実装。
 * わざと import せずに書き写しているのは、「呼び出し側が使ったのと同じ関数」で
 * 再導出しても照合にならないため（selection-integrity.js の `deriveSelectionSeed` と同じ方針）。
 */
export function deriveGroupSeed(randao, applicantHash) {
  return keccak256(concatHex([randao, applicantHash, stringToHex('group')]));
}

/** sha256 の16進表記（game-master-DO.sha256Hex / block-verifier sha256HexOfString と同一） */
export async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * `createGroupSummary`（game-master-DO.js:7596-7602）の groups 欄と同形。
 * ⚠️ 正典 writer の**手書きミラー**。writer 側を変えたらここも変えること
 *    （変え忘れたら本検査が落ちる＝fail-closed に倒れるので、無言の乖離にはならない）。
 *    `m.data?.uid || m.globalIndex` の `||`（`??` ではない）も writer どおり。
 */
export function publishedGroupShape(groups) {
  return groups.map((g) => ({
    groupId: g.groupId,
    lang: g.lang,
    mixed: g.mixed,
    memberCount: g.members.length,
    memberIds: g.members.map((m) => m.data?.uid || m.globalIndex),
  }));
}

/** `countGroupsByLang`（game-master-DO.js:7608-7615）のミラー */
export function countGroupsByLang(groups) {
  // P-2026-0823: 正典（game-master-DO.js `countGroupsByLang`）と同じく `Object.create(null)`。
  // lang は `constructor` / `__proto__` になりうるため、素の `{}` だと件数が壊れる。
  const counts = Object.create(null);
  for (const group of groups) {
    const lang = group.lang;
    counts[lang] = (counts[lang] || 0) + 1;
  }
  return counts;
}

/** `getGroupSizeDistribution`（game-master-DO.js:7618-7625）のミラー */
export function groupSizeDistribution(groups) {
  const distribution = {};
  for (const group of groups) {
    const size = group.members.length;
    distribution[size] = (distribution[size] || 0) + 1;
  }
  return distribution;
}

/**
 * `computeMajorLangs` が読む前ブロック成果物に、アンカー検証を挟む読み手を作る。
 *
 * block-verifier/src/stages/grouping.js:101-150（`ensurePrevAnchor` / `fetchPrevVerified`）の
 * 規則をそのまま正典側へ持ち込む:
 *   ・前ブロックの `verification/block{N-1}/manifest.json` の **core**（blockNum/algorithm/rules/files）を
 *     再ハッシュし、`HashStorage.resultHashes(N-1)` と一致することを確かめる
 *   ・読んだアーティファクトの sha256 が manifest の申告値と一致することを確かめる
 *   ・`games/block{N-1}/summary.json` が公開されているのに manifest / アンカーが無い＝**検証不能** → 失敗
 *   ・🔴 Q-5（2026-08-08）: 免除は**ひとつも無い**。`computeMajorLangs` が読んだ前ブロック成果物は
 *     すべてアンカー検証の対象で、manifest に宣言が無ければ失敗する。
 *     旧実装にあった `game_selection.json` フォールバックへの免除は、フォールバック自体を
 *     `computeMajorLangs` から削除したうえで撤去した（ツール側 `stages/grouping.js` も同じ）
 *
 * ⚠️ 既知の運用上の注意（drift）:
 *   `games/block{N-1}/summary.json` は **manifest 発行後にも書き換わる**。
 *   listen-worker が請求のたびに `claimed` を CAS で patch するため（listen_workers/src/index_new.js:953）。
 *   本番パラメータでは「ブロック N のグループ分け」＝応募終了 +2h は、
 *   「ブロック N-1 の請求期間開始」＝結果確定 + 検証期間4日 よりも**約50時間早い**ので、
 *   通常はここで請求 patch を踏まない。踏んだ場合は sha256 不一致で fail-closed になるので、
 *   運用は見張り役の chain marker が選ぶ世代の manifest / summary を2鍵とも戻して解消する。
 *   marker が honest と立証できない場合は再アンカーせず、緊急復旧の A-2 へ戻る。
 */
function createAnchoredPrevReader({ blockNum, readText, getResultHash, anchorRequired, fail, failUnavailable, failPending }) {
  const prev = blockNum - 1;
  const manifestKey = `verification/block${prev}/manifest.json`;

  const state = { init: false, manifest: null, anchored: null, coreChecked: false };
  const verified = [];
  let readCount = 0;

  async function readR2Text(key) {
    try {
      return await readText(key);
    } catch (e) {
      // R2 の一過性読取失敗だけを、チェーン読取失敗と同じ既存の再試行受け皿へ倒す。
      // JSON/ハッシュ/値の不一致はこの印を持たないので、恒久的な完全性違反のまま扱う。
      if (e?.r2ReadUnavailable) {
        failUnavailable(
          `cannot read R2 object ${key} — refusing to group while the previous block's ` +
          `artifacts are temporarily unavailable: ${e?.message || e}`
        );
      }
      throw e;
    }
  }

  async function ensureAnchor() {
    if (state.init) return;
    state.init = true;

    let anchored = null;
    try {
      anchored = await getResultHash(prev);
    } catch (e) {
      // チェーンが読めない＝**照合できない**。恒久失敗ではなく再試行に倒す（S3-008 と同じ扱い）。
      failUnavailable(
        `cannot read HashStorage.resultHashes(${prev}) — refusing to group without verifying the ` +
        `previous block's artifacts (majorLangs is derived from them): ${e?.shortMessage || e?.message || e}`
      );
    }
    state.anchored = (anchored && Number(anchored.updated) !== 0) ? anchored : null;

    const manifestText = await readR2Text(manifestKey);
    if (manifestText != null) {
      let m;
      try { m = JSON.parse(manifestText); } catch (e) {
        fail(`${manifestKey} is not valid JSON (${e.message})`);
      }
      state.manifest = m;
    }
  }

  async function verifyAnchoredFile(key, text) {
    await ensureAnchor();

    // 🔴 Q-5（2026-08-08・ユーザー確定）: **`key === summaryKey` 以外への免除を削除した。**
    //    旧実装は「summary 不在時の `game_selection.json` フォールバックは manifest 未発行だから
    //    アンカー必須にしない」という免除を持っていた。そのフォールバック自体を
    //    `computeMajorLangs` から消した（`game-master-DO.js` の該当箇所を参照）ので、
    //    ここへ来るキーは**必ず manifest がアンカーしているべきもの**しかない。
    //    免除を残すと「新しく読むようになったファイルが黙って無検証で通る」枠が残る。
    if (!state.anchored) {
      failPending(
        `${key} is published but its on-chain anchor is not verifiable ` +
        `(manifest=${state.manifest ? 'present' : 'missing'}, ` +
        `resultHashes(${prev})=${state.anchored ? 'set' : 'unset'}) — ` +
        `do not re-anchor; restore ${manifestKey} and games/block${prev}/summary.json to the ` +
        `generations selected by the observer's chain marker only if that marker is proven honest, ` +
        `otherwise return to emergency recovery rule A-2`
      );
    }
    if (!state.manifest) {
      fail(
        `${key} is published but its on-chain anchor is not verifiable ` +
        `(manifest=missing, resultHashes(${prev})=set) — ` +
        `restore verification/block${prev}/manifest.json before grouping block ${blockNum}`
      );
    }

    if (!state.coreChecked) {
      state.coreChecked = true;
      const m = state.manifest;
      const coreHash = '0x' + await sha256Hex(JSON.stringify({
        blockNum: m.blockNum, algorithm: m.algorithm, rules: m.rules, files: m.files,
      }));
      state.coreOk = coreHash === String(state.anchored.hash).toLowerCase();
      if (!state.coreOk) {
        fail(
          `${manifestKey} core sha256 ${coreHash} != on-chain resultHashes(${prev}) ` +
          `${String(state.anchored.hash).toLowerCase()} — the previous block's published artifacts ` +
          `do not match what is anchored on-chain`
        );
      }
    }

    // Q-5: 宣言が無いキーも免除しない（未宣言＝逸脱）。
    const declared = state.manifest.files?.[key];
    if (declared == null) {
      fail(`${manifestKey} does not declare a sha256 for ${key} (cannot anchor the majorLangs input)`);
    }
    const actual = await sha256Hex(text);
    if (actual !== declared) {
      fail(
        `${key} sha256 ${actual} != anchored manifest value ${declared} — ` +
        `the previous block's public artifact changed after it was anchored; do not re-anchor the ` +
        `changed public bytes — restore ${manifestKey} and ${key} to the generations selected by ` +
        `the observer's chain marker only if that marker is proven honest, otherwise return to ` +
        `emergency recovery rule A-2`
      );
    }
    verified.push(key);
  }

  // `computeMajorLangs` が呼ぶ `getR2Object` の差し替え先
  const read = async (key) => {
    const text = await readR2Text(key);
    if (text == null) return null;
    let parsed;
    try { parsed = JSON.parse(text); } catch (e) {
      // 正典 getR2Object は parse 失敗を null に潰す（＝黙って「前ブロック結果なし」へ倒れる）。
      // ここは fail-closed にする（壊れた前ブロック結果で majorLangs を決めさせない）。
      fail(`${key} is not valid JSON (${e.message})`);
    }
    // 🔴 Q-5（2026-08-08）: **鍵の allowlist をやめ、読んだものは全部アンカー検証する。**
    //    旧実装は `summaryKey || selectionKey` の2つだけを検証対象にしていたので、
    //    `computeMajorLangs` が新しい前ブロック成果物を読むようになった瞬間、
    //    その入力は**黙って無検証で通る**（まさに `game_selection.json` がそうだった）。
    if (blockNum > 0) {
      readCount++;
      if (anchorRequired) await verifyAnchoredFile(key, text);
    }
    return parsed;
  };

  const summarize = () => {
    if (blockNum === 0) return { status: 'skipped', reason: 'genesis_block', prevBlock: null, verified: [] };
    if (!anchorRequired) {
      return { status: 'not_configured', reason: 'HASH_STORAGE_CONTRACT_ADDRESS unset', prevBlock: prev, verified: [] };
    }
    if (readCount === 0) {
      return { status: 'skipped', reason: 'no_prev_artifacts_read', prevBlock: prev, verified: [] };
    }
    if (verified.length === 0) {
      return { status: 'skipped', reason: 'prev_block_has_no_anchored_artifacts', prevBlock: prev, verified: [] };
    }
    return { status: 'verified', prevBlock: prev, verified: [...verified] };
  };

  return { read, summarize };
}

/**
 * timeline no-game の checkpoint を再開する直前に、前ブロックの chain marker と
 * manifest / summary の2鍵がまだ同じ世代を指すことを再確認する。
 * grouping 本体と同じ読み手を使い、片方でも読めない／一致しない間は fail-closed で止める。
 */
export async function verifyPreviousBlockArtifacts({
  blockNum, readText, getResultHash, anchorRequired = false,
}) {
  const makeError = (msg) => {
    const error = new Error(`previous block integrity (block ${blockNum}): ${msg}`);
    error.previousBlockIntegrity = true;
    return error;
  };
  const fail = (msg) => { throw makeError(msg); };
  const failUnavailable = (msg) => {
    const error = makeError(msg);
    error.groupingAnchorUnavailable = true;
    throw error;
  };
  const failPending = (msg) => {
    const error = makeError(msg);
    error.groupingDependencyPending = true;
    throw error;
  };

  if (!Number.isInteger(blockNum) || blockNum < 0) {
    fail(`blockNum must be a non-negative integer (got ${brief(blockNum)})`);
  }
  if (blockNum === 0) {
    return { status: 'skipped', reason: 'genesis_block', prevBlock: null, verified: [] };
  }
  if (typeof readText !== 'function') fail('readText is required');
  if (!anchorRequired) {
    failUnavailable('HashStorage chain marker is not configured; refusing to resume no-game finalization');
  }
  if (typeof getResultHash !== 'function') fail('getResultHash is required');

  const prev = blockNum - 1;
  const manifestKey = `verification/block${prev}/manifest.json`;
  const summaryKey = `games/block${prev}/summary.json`;
  const reader = createAnchoredPrevReader({
    blockNum, readText, getResultHash, anchorRequired, fail, failUnavailable, failPending,
  });
  const summary = await reader.read(summaryKey);
  if (summary == null) {
    failPending(
      `${summaryKey} is unavailable — restore ${manifestKey} and ${summaryKey} to the generations ` +
      `selected by the observer's chain marker before resuming no-game finalization`
    );
  }
  const result = reader.summarize();
  if (result.status !== 'verified') {
    fail(`previous block artifacts were not verified (${result.status}: ${result.reason || 'unknown'})`);
  }
  return result;
}

/**
 * グループ分け結果の完全性検査。違反は throw（fail-closed）。
 *
 * `verifySelectionIntegrity` と同型で、`writeGroupsToD1` の**直前**に置く。
 *
 * @param {object}   args
 * @param {number}   args.blockNum         - 対象ブロック番号
 * @param {object[]} args.players          - 権威的な当選者配列（verifySelectionIntegrity 済み）
 * @param {string}   args.randao           - game_selection.json の randao
 * @param {string}   args.applicantHash    - game_selection.json の applicantHash
 * @param {string}   args.usedGroupSeed    - 実際に formGroups へ渡した seed
 * @param {string[]} args.usedMajorLangs   - 実際に formGroups へ渡した majorLangs
 * @param {object[]} args.groups           - formGroups の出力（これから D1/R2 へ書く現物）
 * @param {object}   args.groupSummary     - createGroupSummary の出力（game_groups.json 本文）
 * @param {object}   args.blockSummary     - buildBlockSummaryForR2 の出力（summary.json 本文）
 * @param {Function} args.formGroups       - async (players, seed, majorLangs) => groups（独立再実行）
 * @param {Function} args.recomputeMajorLangs - async (readVerified) => string[]
 * @param {Function} args.readText         - async (key) => string|null（R2 の生テキスト）
 * @param {Function} args.getResultHash    - async (n) => {hash, updated}（読めなければ throw）
 * @param {boolean}  args.anchorRequired   - HashStorage が設定済みか（未設定なら③をスキップ）
 * @param {Function} [args.clock]          - 時刻源（テスト用）
 * @returns {Promise<{ruleVersion:number, groupSeed:string, majorLangs:string[],
 *                    groupCount:number, playerCount:number, prevAnchor:object, elapsedMs:number}>}
 */
export async function verifyGroupingIntegrity({
  blockNum, players, randao, applicantHash,
  usedGroupSeed, usedMajorLangs, groups, groupSummary, blockSummary,
  formGroups, recomputeMajorLangs,
  readText, getResultHash, anchorRequired = false,
  clock = () => Date.now(),
}) {
  const startedAt = clock();
  const fail = (msg) => { throw new Error(`grouping integrity (block ${blockNum}): ${msg}`); };
  const failUnavailable = (msg) => {
    const err = new Error(`grouping integrity (block ${blockNum}): ${msg}`);
    // 「照合できていない＝ゲームを開始しない」。恒久失敗（park）ではなく再試行に倒す。
    err.groupingAnchorUnavailable = true;
    throw err;
  };
  const failPending = (msg) => {
    const err = new Error(`grouping integrity (block ${blockNum}): ${msg}`);
    // summary は見えているが manifest / on-chain anchor がまだ揃っていない。
    // 内容不一致とは違い、直前ブロックの非同期commit完了で解消する依存待ち。
    err.groupingDependencyPending = true;
    throw err;
  };

  // --- 0. 引数の前提 ---
  if (!Number.isInteger(blockNum) || blockNum < 0) fail(`blockNum must be a non-negative integer (got ${brief(blockNum)})`);
  if (!Array.isArray(players)) fail('players is not an array');
  if (!Array.isArray(groups)) fail('groups is not an array');
  if (typeof formGroups !== 'function') fail('formGroups is required (the whole point is an independent re-run)');
  if (typeof recomputeMajorLangs !== 'function') fail('recomputeMajorLangs is required (majorLangs must be re-derived from anchored artifacts)');
  if (typeof readText !== 'function') fail('readText is required');
  if (anchorRequired && typeof getResultHash !== 'function') fail('getResultHash is required when the HashStorage contract is configured');

  // --- 1. シード素材の形式 ---
  //     ※ オンチェーン RANDAO / applicantHash との照合は正典側に無い（block-verifier Stage A/B-1 の担当）。
  if (!HEX32.test(String(randao || ''))) fail('randao is not a 0x-prefixed 32-byte hex string');
  if (!HEX32.test(String(applicantHash || ''))) fail('applicantHash is not a 0x-prefixed 32-byte hex string');

  // --- 2. groupSeed の独立再導出 ---
  const groupSeed = deriveGroupSeed(randao, applicantHash);
  if (String(usedGroupSeed).toLowerCase() !== groupSeed) {
    fail(`groupSeed mismatch: used=${brief(usedGroupSeed)}, recomputed=${groupSeed}`);
  }

  // --- 3. majorLangs の再導出（前ブロック成果物はアンカー検証つきで読む） ---
  const prevReader = createAnchoredPrevReader({
    blockNum, readText, getResultHash, anchorRequired, fail, failUnavailable, failPending,
  });
  let majorLangs;
  try {
    majorLangs = await recomputeMajorLangs(prevReader.read);
  } catch (e) {
    if (e?.groupingAnchorUnavailable || e?.groupingDependencyPending) throw e;
    if (String(e?.message || '').startsWith(`grouping integrity (block ${blockNum}):`)) throw e;
    fail(`recomputing majorLangs failed: ${e?.message || e}`);
  }
  if (!Array.isArray(majorLangs)) fail(`recomputed majorLangs is not an array (${brief(majorLangs)})`);
  if (!canonicalEqual(majorLangs, usedMajorLangs)) {
    fail(`majorLangs mismatch: used=${brief(usedMajorLangs)}, recomputed=${brief(majorLangs)}`);
  }
  const prevAnchor = prevReader.summarize();

  // --- 4. formGroups の独立再実行 ---
  //     入力は権威的な players の**ディープコピー**（初回実行の出力とオブジェクト参照を共有させない）。
  const derived = await formGroups(JSON.parse(JSON.stringify(players)), groupSeed, majorLangs);
  if (!Array.isArray(derived)) fail('re-run formGroups did not return an array');

  // 4a. グループ数
  if (derived.length !== groups.length) {
    fail(`group count mismatch: written=${groups.length}, recomputed=${derived.length}`);
  }

  // 4b. groupId / lang / mixed / メンバーの uid 列（順序込み）
  const shapeDerived = publishedGroupShape(derived);
  const shapeWritten = publishedGroupShape(groups);
  for (let i = 0; i < shapeDerived.length; i++) {
    if (!canonicalEqual(shapeWritten[i], shapeDerived[i])) {
      fail(
        `group #${i} mismatch: written=${brief(shapeWritten[i])}, recomputed=${brief(shapeDerived[i])} ` +
        `(a group was re-formed after formGroups ran)`
      );
    }
  }

  // 4c. 分割の完全性（全員がちょうど1回・余分な uid が無い）
  const authoritative = new Map();
  for (let i = 0; i < players.length; i++) {
    const uid = players[i]?.data?.uid;
    if (uid === undefined || uid === null || uid === '') fail(`authoritative player #${i} has no data.uid`);
    const key = String(uid);
    if (authoritative.has(key)) fail(`duplicate uid ${key} in the authoritative player list at #${i}`);
    authoritative.set(key, players[i]);
  }
  const placed = new Set();
  for (const g of groups) {
    if (!g || !Array.isArray(g.members)) fail(`group ${brief(g?.groupId)} has no members array`);
    for (const m of g.members) {
      const key = String(m?.data?.uid);
      if (!authoritative.has(key)) fail(`group ${g.groupId} contains uid ${key} which is not an authoritative winner`);
      if (placed.has(key)) fail(`uid ${key} appears in more than one group (group ${g.groupId})`);
      placed.add(key);
      // メンバー行そのものが当選者行と同一であること（プロフィール・言語・デポジットの差し替え）
      const p = authoritative.get(key);
      if (!canonicalEqual(m.data, p.data)) {
        fail(`group ${g.groupId} member ${key}: data differs from the authoritative winner row`);
      }
      if (m.globalIndex !== p.globalIndex) {
        fail(`group ${g.groupId} member ${key}: globalIndex ${brief(m.globalIndex)} != authoritative ${brief(p.globalIndex)}`);
      }
    }
  }
  if (placed.size !== authoritative.size) {
    const missing = [...authoritative.keys()].filter((k) => !placed.has(k));
    fail(`${missing.length} winner(s) are not in any group (first: ${missing[0]})`);
  }

  // --- 5. game_groups.json（createGroupSummary の出力）との照合 ---
  if (groupSummary !== undefined && groupSummary !== null) {
    if (typeof groupSummary !== 'object') fail('groupSummary is not an object');
    if (Number(groupSummary.blockNum) !== blockNum) fail(`game_groups.json blockNum mismatch: ${brief(groupSummary.blockNum)}`);
    if (groupSummary.totalPlayers !== players.length) {
      fail(`game_groups.json totalPlayers mismatch: file=${brief(groupSummary.totalPlayers)}, authoritative=${players.length}`);
    }
    if (groupSummary.totalGroups !== derived.length) {
      fail(`game_groups.json totalGroups mismatch: file=${brief(groupSummary.totalGroups)}, recomputed=${derived.length}`);
    }
    const listed = Array.isArray(groupSummary.groups) ? groupSummary.groups : null;
    if (!listed) fail('game_groups.json has no groups array');
    if (listed.length !== derived.length) {
      fail(`game_groups.json groups length ${listed.length} != totalGroups/recomputed ${derived.length}`);
    }
    if (String(groupSummary.randao).toLowerCase() !== String(randao).toLowerCase()
      || String(groupSummary.applicantHash).toLowerCase() !== String(applicantHash).toLowerCase()) {
      fail('game_groups.json randao/applicantHash differ from the verified selection data');
    }
    if (String(groupSummary.groupSeed).toLowerCase() !== groupSeed) {
      fail(`game_groups.json groupSeed mismatch: file=${brief(groupSummary.groupSeed)}, recomputed=${groupSeed}`);
    }
    for (let i = 0; i < derived.length; i++) {
      if (!canonicalEqual(listed[i], shapeDerived[i])) {
        fail(`game_groups.json group #${i} mismatch: file=${brief(listed[i])}, recomputed=${brief(shapeDerived[i])}`);
      }
    }
    // 統計欄（groupsByLang / mixedGroups / groupSizes）
    const byLang = countGroupsByLang(derived);
    const sizes = groupSizeDistribution(derived);
    const mixed = derived.filter((g) => g.mixed).length;
    if (!canonicalEqual(groupSummary.groupsByLang, byLang)) {
      fail(`game_groups.json groupsByLang mismatch: file=${brief(groupSummary.groupsByLang)}, recomputed=${brief(byLang)}`);
    }
    if (groupSummary.mixedGroups !== mixed) {
      fail(`game_groups.json mixedGroups mismatch: file=${brief(groupSummary.mixedGroups)}, recomputed=${mixed}`);
    }
    if (!canonicalEqual(groupSummary.groupSizes, sizes)) {
      fail(`game_groups.json groupSizes mismatch: file=${brief(groupSummary.groupSizes)}, recomputed=${brief(sizes)}`);
    }
  }

  // --- 6. summary.json（buildBlockSummaryForR2 の出力）との照合 ---
  //     block.js が実際に描くのはこちら。game_groups.json だけ合っていても意味がない。
  if (blockSummary !== undefined && blockSummary !== null) {
    if (typeof blockSummary !== 'object') fail('blockSummary is not an object');
    if (Number(blockSummary.blockNum) !== blockNum) fail(`summary.json blockNum mismatch: ${brief(blockSummary.blockNum)}`);
    if (!canonicalEqual(blockSummary.majorLangs || [], majorLangs)) {
      fail(`summary.json majorLangs mismatch: file=${brief(blockSummary.majorLangs)}, recomputed=${brief(majorLangs)}`);
    }
    const sumGroups = Array.isArray(blockSummary.groups) ? blockSummary.groups : null;
    if (!sumGroups) fail('summary.json has no groups array');
    if (sumGroups.length !== derived.length) {
      fail(`summary.json groups length ${sumGroups.length} != recomputed ${derived.length}`);
    }
    const byId = new Map();
    for (const g of sumGroups) {
      if (byId.has(g?.group_id)) fail(`summary.json has a duplicate group_id ${brief(g?.group_id)}`);
      byId.set(g?.group_id, g);
    }
    for (const g of derived) {
      const sg = byId.get(g.groupId);
      if (!sg) fail(`summary.json is missing group_id ${g.groupId}`);
      // buildBlockSummaryForR2:7414 / buildBlockSummaryWithResults:7528 と同じ写像（uid → userId）
      const expectedIds = g.members.map((m) => m.data?.uid ?? null);
      const actualIds = Array.isArray(sg.members) ? sg.members.map((m) => m.userId ?? null) : null;
      if (!canonicalEqual(actualIds, expectedIds)) {
        fail(
          `summary.json group ${g.groupId} member order mismatch: ` +
          `file=${brief(actualIds)}, recomputed=${brief(expectedIds)}`
        );
      }
      if (sg.member_count !== g.members.length) {
        fail(`summary.json group ${g.groupId} member_count=${brief(sg.member_count)} but has ${g.members.length} members`);
      }
    }
  }

  return {
    ruleVersion: GROUPING_INTEGRITY_RULE_VERSION,
    groupSeed,
    majorLangs,
    groupCount: derived.length,
    playerCount: players.length,
    prevAnchor,
    elapsedMs: clock() - startedAt,
  };
}

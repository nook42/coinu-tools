// workers/game_workers/lib/selection-integrity.js
//
// 選出データ（entries/block{N}/game_selection.json）の完全性検査。
//
// 背景（外部監査 S3-001）:
//   GameMasterDO は grouping の入力として R2 の game_selection.json を「存在するか」
//   「players が空でないか」だけ見て採用していた。R2 は運営が完全に掌握しているため、
//   lottery が正規の当選者を書いた後・grouping が走る前に players を差し替えれば、
//   運営アカウントだけを当選者にできた（1〜2名にすれば自動配布でブロック報酬を総取り）。
//
// 背景の追補（外部レビュー P-2026-0815 / 2026-08-07）:
//   規則版数1は **globalIndex と uid 一意性しか照合していなかった**。当選 index 集合は
//   正しいまま `localIndex` / `file` / `data`（uid・depositPoints など）だけを差し替えると
//   素通りし、「当選 index は正規のまま当選者そのものを別人にすり替える」ことができた。
//   実測での再現: N=3 / maxPlayers=2 の正規当選 index [1,2] を残したまま
//   localIndex=[99,98] / file=[data99.json,data98.json] / uid=attacker-A,B /
//   depositPoints=999999 に差し替えても selectedCount=2 で受理された。
//   depositPoints はポイント比例の按分に直結するため、これだけで報酬を総取りできる。
//
// ここでの方針:
//   「サーバー（＝運営）が嘘をつけない」ための多層防御の1枚として、GameMasterDO 自身が
//   公開値だけから当選者行を**丸ごと再構築**し、game_selection.json と突き合わせる。
//
//   selectionSeed = keccak256(randao ‖ applicantHash)       … lottery-DO.deriveSelectionSeed と同一
//   expected      = selectWinners(seed, N, min(N, maxPlayers)) … 正典の決定的抽選（vendor 同期対象）
//   N（応募総数）は game_selection.json の申告値ではなく、**呼び出し側が
//   100 個の info ファイルから数え直した実件数**（committedTotal）を権威にする。
//   → 申告値だけを信じると「N も players も同時に書き換える」で素通りするため。
//
//   さらに当選者行そのものを、権威的な info ファイル＋データファイルから再構築する
//   （lottery-DO.js collectWinnerData / block-verifier src/stages/selection.js buildPlayers と同一規則）:
//     ① info ファイルだけで決まる欄 … globalIndex → (file, localIndex) の対応
//     ② データファイルを読んで決まる欄 … data（正準等価 = JSON.stringify 同値）
//   ①はデータファイルを読まずに検査できるので必ず先に行い、②のためにデータファイルを読む。
//
// 実行予算（S3-007 の resumable yield と同じ考え方）:
//   ②は当選者を含むデータファイルを全部読む必要があり、最大構成では 1 回の呼び出しの
//   予算に収まらない可能性がある。walk はファイル単位で中断でき、`wallBudgetMs` を
//   使い切ったら `err.resumable = true` / `err.selectionResumeFrom` を付けて throw する。
//   呼び出し側（game-master-DO.startGrouping）はカーソルを進捗に保存し、既存の
//   「resumable な予算切れ → 1秒後に自動再開」の経路に乗せる。
//
// 残る限界（意図的・block-verifier が担当）:
//   運営が entries データファイル・info ファイル・applicantHash を**一貫して**作り直した場合は
//   ここでは検出できない。これは applicantHash のオンチェーン登録時刻まで見ないと判別できず、
//   block-verifier の Stage A/B（applicantHash 照合・早期凍結検出）が担当する層である。
//   本モジュールは「オンチェーン値を据え置いたまま R2 だけ差し替える」経路を塞ぐ。
//   また再開カーソルは DO storage 上にあり、これは「コード自体の改変」と同じ信頼領域
//   （＝R2 差し替えより一段強い攻撃）なので、本モジュールの守備範囲ではない。

import { keccak256, concatHex } from 'viem';
import { selectWinners } from './select-winners.js';

// 規則版数（変更したら検証ツール側の期待値も更新すること）
//   1 … globalIndex 集合 ＋ uid 一意性のみ
//   2 … 当選者行を info／データファイルから再構築し localIndex / file / data まで全件照合
export const SELECTION_INTEGRITY_RULE_VERSION = 2;

// 1回の呼び出しでデータファイル走査に使ってよい実時間予算。
// CALC_WALL_BUDGET_MS（game-master-DO.js:93 = 18000）と同じ桁の保守値。
export const SELECTION_VERIFY_WALL_BUDGET_MS = 15000;

const HEX32 = /^0x[0-9a-fA-F]{64}$/;

/**
 * 抽選シードの導出: keccak256(randao ‖ applicantHash)
 * lottery-DO.js deriveSelectionSeed（ethers 実装）とバイト列が一致する viem 実装。
 */
export function deriveSelectionSeed(randao, applicantHash) {
  return keccak256(concatHex([randao, applicantHash]));
}

const isNonNegInt = (v) => Number.isInteger(v) && v >= 0;

// info.entries[].filename の正準形。collect-worker.js:475,506 が作る形は
//   `${paddedWorkerIndex}_${entriesFileIndex}`  例: "07_0" / "99_12"
// これ以外は存在しない。
//
// 🔴 内部レビュー⑥（2026-08-07）: 正典側にこの検査が無かった。
//   検証ツール block-verifier/src/stages/entries.js:100 は同じ正規表現を強制し、
//   外れたら即 FAIL で停止する（G9・パストラバーサル／キー偽装防止）のに、
//   正典 buildEntryLayout は「空でない文字列」しか見ておらず、その値が
//     readEntryFile: (filename) => getR2Object(`entries/block${N}/entries/${filename}.json`)
//   で **そのまま R2 キーへ内挿**されていた。R2 のキーは平坦文字列なので
//   ディレクトリ traversal は解決しないが、
//     ① 「権威」として突き合わせるデータファイル自体を info 側から任意キーへ向けられる
//     ② 検証ツールが FAIL する形の filename を正典が受理する
//        ＝ **正典は成立したのに第三者検証が永久に通らないブロック**を作れる
//   という2点が残る。→ 検証ツールと**同一の正規表現**を正典側にも置く。
//   （両者が同じ形しか受け付けないことが「正典＝検証可能」の前提）
const ENTRY_FILENAME_RE = /^\d{2}_\d+$/;

// 正準等価（block-verifier src/json-utils.js canonicalEqual と同一規則）。
// キーのソートはしない — バックエンドのハッシュ規約と同じ素の JSON.stringify 比較。
const canonicalEqual = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/**
 * 100 個の info ファイルから「グローバル index → データファイル」のレイアウトを復元する。
 * lottery-DO.js collectWinnerData:1029-1090 の走査順（infoIndex 昇順 → info.entries 配列順）と同一。
 * 欠損・型不正は throw（無言スキップは index 対応をズラす＝別人が当選者になる）。
 *
 * @returns {{filename:string, number:number, start:number, end:number}[]}
 */
export function buildEntryLayout({ infos, category = 'entries', committedTotal, fail }) {
  const bail = fail || ((m) => { throw new Error(`selection integrity: ${m}`); });
  if (!Array.isArray(infos) || infos.length !== 100) {
    bail(`infos must be an array of 100 info objects (got ${Array.isArray(infos) ? `length ${infos.length}` : typeof infos})`);
  }
  const layout = [];
  let cursor = 0;
  for (let infoIndex = 0; infoIndex < 100; infoIndex++) {
    const infoData = infos[infoIndex];
    if (!infoData || typeof infoData !== 'object') {
      bail(`info file #${String(infoIndex).padStart(2, '0')} is missing or not an object`);
    }
    const categoryData = infoData[category];
    if (!Array.isArray(categoryData)) {
      bail(`info file #${String(infoIndex).padStart(2, '0')} has no "${category}" array`);
    }
    for (const fileInfo of categoryData) {
      const filename = fileInfo?.filename;
      const number = fileInfo?.number;
      if (typeof filename !== 'string' || filename === '') {
        bail(`info file #${String(infoIndex).padStart(2, '0')} has a data file entry with no filename`);
      }
      // 内部レビュー⑥（2026-08-07）: 正準形以外は即 bail（block-verifier stages/entries.js と同一規則）。
      if (!ENTRY_FILENAME_RE.test(filename)) {
        bail(`info file #${String(infoIndex).padStart(2, '0')} has a non-canonical filename "${filename}" (expected \\d{2}_\\d+)`);
      }
      if (!isNonNegInt(number)) {
        bail(`info file #${String(infoIndex).padStart(2, '0')} entry ${filename} has a non-integer "number" (${number})`);
      }
      layout.push({ filename, number, start: cursor, end: cursor + number - 1 });
      cursor += number;
    }
  }
  if (isNonNegInt(committedTotal) && cursor !== committedTotal) {
    bail(`entry layout total ${cursor} != committedTotal ${committedTotal} (info files and the recount disagree)`);
  }
  return layout;
}

/**
 * game_selection.json の完全性検査。違反は throw（fail-closed）。
 *
 * @param {object}   args
 * @param {number}   args.blockNum        - 対象ブロック番号
 * @param {object}   args.selectionData   - R2 から読んだ game_selection.json
 * @param {number}   args.committedTotal  - 100 info ファイルから数え直した応募総数（N の権威）
 * @param {number}   args.maxPlayers      - GAME_MAX_PLAYERS（選出人数の上限）
 * @param {object[]} args.infos           - 100 個の info ファイル（infoIndex 昇順・欠損不可）
 * @param {Function} args.readEntryFile   - async (filename) => 配列 | null（entries データファイル）
 * @param {string}  [args.category]       - データカテゴリ（既定 'entries'）
 * @param {number}  [args.resumeFrom]     - 再開するレイアウト位置（前回の予算切れの続き）
 * @param {number}  [args.wallBudgetMs]   - データファイル走査の実時間予算
 * @param {Function}[args.onFileVerified] - async ({filesRead, playersVerified, ...}) => void（リース延長フック）
 * @param {Function}[args.clock]          - 時刻源（テスト用）
 * @returns {Promise<{selectedCount:number, seed:string, ruleVersion:number,
 *                    filesRead:number, playersVerified:number}>}
 */
export async function verifySelectionIntegrity({
  blockNum, selectionData, committedTotal, maxPlayers,
  infos, readEntryFile, category = 'entries',
  resumeFrom = 0,
  wallBudgetMs = SELECTION_VERIFY_WALL_BUDGET_MS,
  onFileVerified,
  clock = () => Date.now(),
}) {
  const fail = (msg) => { throw new Error(`selection integrity (block ${blockNum}): ${msg}`); };

  if (!selectionData || typeof selectionData !== 'object') fail('selectionData is not an object');
  if (!isNonNegInt(committedTotal)) fail(`committedTotal must be a non-negative integer (got ${committedTotal})`);
  if (!Number.isInteger(maxPlayers) || maxPlayers <= 0) fail(`maxPlayers must be a positive integer (got ${maxPlayers})`);
  // P-2026-0815: データファイルの読み手が無いと data 欄を照合できない＝すり替えが通る。
  // 「引数を渡さなければ弱い検査になる」逃げ道を残さないため、無条件で必須にする。
  if (typeof readEntryFile !== 'function') {
    fail('readEntryFile is required (entry data files are the authority for player rows)');
  }

  // --- 1. ブロック番号 / シード素材 ---
  if (Number(selectionData.blockNum) !== Number(blockNum)) {
    fail(`blockNum mismatch: file=${selectionData.blockNum}`);
  }
  if (!HEX32.test(String(selectionData.randao || ''))) fail('randao is not a 0x-prefixed 32-byte hex string');
  if (!HEX32.test(String(selectionData.applicantHash || ''))) fail('applicantHash is not a 0x-prefixed 32-byte hex string');

  // --- 2. N は info ファイル実件数が権威（申告値との不一致は fail-closed） ---
  if (selectionData.totalEntries !== committedTotal) {
    fail(`totalEntries mismatch: file=${selectionData.totalEntries}, committed entry files=${committedTotal}`);
  }

  // --- 3. 件数（lottery-DO.js executeLottery と同じ式） ---
  const selectedCount = Math.min(committedTotal, maxPlayers);
  const players = selectionData.players;
  if (!Array.isArray(players)) fail('players is not an array');
  if (players.length !== selectedCount) {
    fail(`players.length mismatch: file=${players.length}, expected=${selectedCount} (min(${committedTotal}, ${maxPlayers}))`);
  }
  if (selectionData.totalSelected !== selectedCount) {
    fail(`totalSelected mismatch: file=${selectionData.totalSelected}, expected=${selectedCount}`);
  }

  // --- 4. 当選 index 集合の再現（順序・重複・欠落をまとめて封じる） ---
  const seed = deriveSelectionSeed(selectionData.randao, selectionData.applicantHash);
  const expected = await selectWinners(seed, committedTotal, selectedCount);
  if (expected.length !== players.length) {
    fail(`recomputed winner count ${expected.length} != players ${players.length}`);
  }
  for (let i = 0; i < expected.length; i++) {
    const g = players[i]?.globalIndex;
    if (g !== expected[i]) {
      fail(`globalIndex mismatch at #${i}: file=${g}, recomputed=${expected[i]}`);
    }
  }

  // --- 5. uid 一意性（同一人物の複数グループ所属・roster 欠落を封じる） ---
  const seen = new Set();
  for (let i = 0; i < players.length; i++) {
    const uid = players[i]?.data?.uid;
    if (uid === undefined || uid === null || uid === '') fail(`player #${i} has no data.uid`);
    const key = String(uid);
    if (seen.has(key)) fail(`duplicate uid ${key} at player #${i}`);
    seen.add(key);
  }

  // --- 6. 権威的な info ファイルから index レイアウトを復元 ---
  //     （globalIndex → どのデータファイルの何行目か が、ここで公開値と独立に決まる）
  const layout = buildEntryLayout({ infos, category, committedTotal, fail });

  // --- 7. 当選者行の再構築＋全フィールド照合 ---
  //     lottery-DO.js collectWinnerData と同じ走査（レイアウト順にそのファイル内の当選者を拾う）。
  //     expected は昇順・layout の range も昇順連続なので、位置 k の当選者は players[k] に対応する
  //     （k の対応は step 4 の globalIndex 全件一致で既に確定している）。
  const resumeIndex = isNonNegInt(resumeFrom) ? Math.min(resumeFrom, layout.length) : 0;
  const startedAt = clock();
  let filesRead = 0;
  let playersVerified = 0;
  let wi = 0;

  for (let fi = 0; fi < layout.length; fi++) {
    const f = layout[fi];
    const from = wi;
    while (wi < expected.length && expected[wi] <= f.end) wi++;
    const count = wi - from;
    if (count === 0) continue;

    // 前回の呼び出しで照合済みの区間（予算切れ再開）。index 対応を保つため walk 自体は続ける。
    if (fi < resumeIndex) { playersVerified += count; continue; }

    // ①: info ファイルだけで決まる欄（データファイルを読まずに判る差し替えを先に落とす）
    for (let k = from; k < wi; k++) {
      const localIndex = expected[k] - f.start;
      const p = players[k];
      if (p?.file !== f.filename) {
        fail(`file mismatch at #${k} (globalIndex ${expected[k]}): published=${JSON.stringify(p?.file)}, recomputed=${JSON.stringify(f.filename)}`);
      }
      if (p?.localIndex !== localIndex) {
        fail(`localIndex mismatch at #${k} (globalIndex ${expected[k]}, ${f.filename}): published=${p?.localIndex}, recomputed=${localIndex}`);
      }
    }

    // ②: data 欄（権威的なデータファイルの当該行と正準等価か）
    const fileData = await readEntryFile(f.filename);
    filesRead++;
    if (!fileData || !Array.isArray(fileData)) {
      fail(`missing or invalid data file: ${f.filename}`);
    }
    if (fileData.length !== f.number) {
      fail(`record count mismatch in ${f.filename}: info says ${f.number}, file has ${fileData.length}`);
    }
    for (let k = from; k < wi; k++) {
      const localIndex = expected[k] - f.start;
      if (localIndex < 0 || localIndex >= fileData.length) {
        fail(`winner index ${expected[k]} out of range in ${f.filename} (local ${localIndex}, length ${fileData.length})`);
      }
      if (!canonicalEqual(fileData[localIndex], players[k].data)) {
        fail(`data mismatch at #${k} (globalIndex ${expected[k]}, ${f.filename}#${localIndex}): published uid=${JSON.stringify(players[k]?.data?.uid)}, authoritative uid=${JSON.stringify(fileData[localIndex]?.uid)}`);
      }
      playersVerified++;
    }

    if (onFileVerified) {
      await onFileVerified({ blockNum, layoutIndex: fi, filename: f.filename, filesRead, playersVerified, totalPlayers: players.length });
    }

    // 予算切れ = 続きがあるだけ。カーソルを添えて resumable に降りる（S3-007 と同じ扱い）。
    if (wi < expected.length && (clock() - startedAt) >= wallBudgetMs) {
      const err = new Error(
        `selection integrity (block ${blockNum}): wall budget exhausted after ${filesRead} data files ` +
        `(${playersVerified}/${players.length} winners verified) — resuming from layout #${fi + 1}`
      );
      err.resumable = true;
      err.selectionResumeFrom = fi + 1;
      err.selectionPlayersVerified = playersVerified;
      throw err;
    }
  }

  if (wi !== expected.length) {
    fail(`winner walk consumed ${wi} of ${expected.length} winners (entry layout does not cover every winner index)`);
  }
  if (playersVerified !== players.length) {
    fail(`verified ${playersVerified} of ${players.length} player rows`);
  }

  return {
    selectedCount, seed,
    ruleVersion: SELECTION_INTEGRITY_RULE_VERSION,
    filesRead, playersVerified,
  };
}

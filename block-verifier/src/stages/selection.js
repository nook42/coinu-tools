// Stage B-1: 抽選（参加者選出）の検証
//
// 正典（byte-exact 写像元）:
//   - workers/lottery_workers/lottery-DO.js:566-583 (entryPeriodEnd / deriveSelectionSeed)
//   - workers/lottery_workers/lottery-DO.js:639-771 (executeLottery / game_selection.json writer)
//   - workers/lottery_workers/lottery-DO.js:779-863 (selectWinners → vendor 抽出を実行)
//   - workers/lottery_workers/lottery-DO.js:925-1028 (countCommittedEntries / collectWinnerData)
// F-L5: 抽選の modulo bias は受容済み。vendored selectWinners をそのまま実行して再現する。
import { withVendorLogging } from '../vendor-logging.js';
import { keccak256, concat } from 'viem';
import { canonicalEqual, displayTime, hashLikeBackend } from '../json-utils.js';
import { selectWinners } from '../../vendor/workers/lottery_workers/select-winners.js';

const DL_CONCURRENCY = 10;

async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) || 1 }, worker));
  return results;
}

// collectWinnerData (lottery-DO.js:951-1028) の写し: 当選 index → info ファイル順の
// グローバル index 走査 → エントリーレコード解決。Stage Aは全応募者を逐次hashして
// 破棄するため、ここでは当選indexを含むファイルだけStage Aが保存したローカルキャッシュから
// 再読込し、Stage Aの指紋とも照合する。保存不能時の再取得も指紋一致を必須にする。
async function buildPlayers(r2, blockNum, infos, winnerIndices, stageAHashes) {
  if (winnerIndices.length === 0) return [];
  const winners = [];
  const jobs = [];
  let currentIndex = 0;
  for (let infoIndex = 0; infoIndex < 100; infoIndex++) {
    const infoData = infos[infoIndex];
    for (const fileInfo of infoData.entries) {
      const fileStartIndex = currentIndex;
      const fileEndIndex = currentIndex + fileInfo.number - 1;
      const winnersInThisFile = winnerIndices.filter(
        (index) => index >= fileStartIndex && index <= fileEndIndex
      );
      if (winnersInThisFile.length > 0) {
        jobs.push({ fileInfo, fileStartIndex, winnersInThisFile });
      }
      currentIndex += fileInfo.number;
    }
  }

  await mapLimit(jobs, DL_CONCURRENCY, async ({ fileInfo, fileStartIndex, winnersInThisFile }) => {
    const key = `entries/block${blockNum}/entries/${fileInfo.filename}.json`;
    const expectedHash = stageAHashes?.get(fileInfo.filename);
    let res = await r2.fetchJson(key, { reuse: true, cacheOnly: true });
    try {
      let fileData = res?.data;
      let actualHash = Array.isArray(fileData) ? await hashLikeBackend(fileData) : null;
      // キャッシュ予算超過や前回ランの残骸でStage Aの指紋と一致する保存物が無い場合だけ
      // R2を取り直す。その場合も指紋一致を必須にするため、2回目応答だけで当選者は変わらない。
      if (!Array.isArray(fileData) || !expectedHash || actualHash !== expectedHash) {
        res = await r2.refetch(key);
        fileData = res?.data;
        actualHash = Array.isArray(fileData) ? await hashLikeBackend(fileData) : null;
      }
      if (!fileData || !Array.isArray(fileData)) {
        throw new Error(`Missing or invalid data file: ${fileInfo.filename}${res?.sizeError ? ` (${res.sizeError})` : ''}`);
      }
      if (fileData.length !== fileInfo.number) {
        throw new Error(`Record count mismatch in ${fileInfo.filename}: info says ${fileInfo.number}, file has ${fileData.length}`);
      }
      if (!expectedHash || actualHash !== expectedHash) {
        throw new Error(`Stage A fingerprint mismatch in ${fileInfo.filename}: expected ${expectedHash || '(missing)'}, got ${actualHash}`);
      }
      for (const winnerIndex of winnersInThisFile) {
        const localIndex = winnerIndex - fileStartIndex;
        if (localIndex < 0 || localIndex >= fileData.length) {
          throw new Error(`Winner index ${winnerIndex} out of range in ${fileInfo.filename}`);
        }
        winners.push({
          globalIndex: winnerIndex,
          localIndex,
          file: fileInfo.filename,
          data: fileData[localIndex],
        });
      }
    } finally {
      r2.release?.(key);
    }
  });
  return winners.sort((a, b) => a.globalIndex - b.globalIndex);
}

export async function run(ctx) {
  const { cfg, chain, r2, ui, report, blockNum: N } = ctx;
  const fetchOpts = { reuse: ctx.data.reuseFiles };

  ui.section?.();
  ui.println(ui.t('stageB.selStart', { n: N }));

  // --- 1. game_selection.json（無し = 抽選未実施 → ここで終了） ---
  const selRes = await r2.fetchJson(`entries/block${N}/game_selection.json`, fetchOpts);
  if (!selRes) {
    report.check('check.stageB.selectionPresent', 'skip', { n: N });
    ui.println(ui.t('stageB.noSelection', { n: N }));
    ctx.data.stopReason = 'not_ready';
    return { stop: true };
  }
  if (!selRes.data || typeof selRes.data !== 'object') {
    report.check('check.stageB.selectionPresent', 'fail', {
      n: N,
      reason: selRes.sizeError || selRes.parseError || 'selection is not a JSON object',
    });
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }
  const sel = selRes.data;
  ctx.data.gameSelection = sel;
  report.check('check.stageB.selectionPresent', 'pass', { n: N });

  const chainHash = ctx.data.applicantHash;
  const registeredBlock = ctx.data.registeredBlock;
  const pinnedConfirmation = Number(cfg.pins?.confirmationBlocks ?? 64);

  // --- 2. 整合検査（DESIGN §3 B-2） ---
  // hashRegisteredBlock は原則として Stage A が履歴から選んだ U_A（root と同じ締切後の
  // 最初の登録）。別ブロックでも selection の (block,hash) が実在する登録なら WARN、
  // 履歴に無ければ FAIL。旧 HashStorage の許可リスト対象だけは最新値比較を維持する。
  if (registeredBlock == null) {
    let membership = ctx.data.legacyHashStorage ? 'legacy-latest-only' : false;
    let membershipError = null;
    if (!ctx.data.legacyHashStorage) {
      try {
        membership = await chain.isApplicantRegistered(N, sel.hashRegisteredBlock, sel.applicantHash);
      } catch (error) {
        membership = 'unavailable';
        membershipError = error?.message || String(error);
      }
    }
    report.check('check.stageB.hashRegisteredBlock', 'fail', {
      file: sel.hashRegisteredBlock,
      onchain: null,
      membership,
      reason: 'stageA_has_no_eligible_root_registration',
      ...(membershipError ? { error: `registration membership unavailable: ${membershipError}` } : {}),
    });
  } else if (sel.hashRegisteredBlock === registeredBlock) {
    report.check('check.stageB.hashRegisteredBlock', 'pass', {
      file: sel.hashRegisteredBlock, onchain: registeredBlock, membership: true,
    });
  } else if (ctx.data.legacyHashStorage) {
    report.check('check.stageB.hashRegisteredBlock', 'fail', {
      file: sel.hashRegisteredBlock, onchain: registeredBlock, membership: 'legacy-latest-only',
    });
  } else {
    let registered = false;
    let membershipError = null;
    try {
      registered = await chain.isApplicantRegistered(N, sel.hashRegisteredBlock, sel.applicantHash);
    } catch (error) {
      membershipError = error?.message || String(error);
    }
    const membershipDetail = {};
    if (registered) {
      const uaRandaoTargetBlock = Number(registeredBlock) + pinnedConfirmation;
      let uaRandaoTargetAnchored = 'unavailable';
      let uaRandaoTargetHash = 'unavailable';
      let uaRandaoTargetError = null;
      try {
        if (typeof chain.blockHashOf !== 'function') throw new Error('Evidence.blockHashOf getter unavailable');
        uaRandaoTargetHash = String(await chain.blockHashOf(uaRandaoTargetBlock)).toLowerCase();
        uaRandaoTargetAnchored = !/^0x0{64}$/.test(uaRandaoTargetHash);
      } catch (error) {
        uaRandaoTargetError = error?.message || String(error);
      }
      Object.assign(membershipDetail, {
        uaRandaoTargetBlock,
        uaRandaoTargetAnchored,
        uaRandaoTargetHash,
        ...(uaRandaoTargetError ? { uaRandaoTargetError } : {}),
      });
    }
    report.check('check.stageB.hashRegisteredBlock', registered ? 'warn' : 'fail', {
      file: sel.hashRegisteredBlock,
      onchain: registeredBlock,
      membership: registered,
      ...membershipDetail,
      ...(membershipError ? { error: `registration membership unavailable: ${membershipError}` } : {}),
    });
  }

  // confirmationBlocks == ピン値（G2a: 逸脱 = RANDAO ターゲット grinding → FAIL。
  // 正当な定数変更は --config の pins.confirmationBlocks 上書きで明示承認する運用 — README参照）
  if (sel.confirmationBlocks === pinnedConfirmation) {
    report.check('check.stageB.confirmationBlocks', 'pass', { file: sel.confirmationBlocks, pinned: pinnedConfirmation });
  } else {
    report.check('check.stageB.confirmationBlocks', 'fail', { file: sel.confirmationBlocks, pinned: pinnedConfirmation });
  }

  // targetBlockNum == hashRegisteredBlock + confirmationBlocks（等式）
  const expectedTarget = Number(sel.hashRegisteredBlock) + Number(sel.confirmationBlocks);
  if (sel.targetBlockNum === expectedTarget) {
    report.check('check.stageB.targetBlockNum', 'pass', { file: sel.targetBlockNum, expected: expectedTarget });
  } else {
    report.check('check.stageB.targetBlockNum', 'fail', { file: sel.targetBlockNum, expected: expectedTarget });
  }
  report.fact('targetBlockNum', sel.targetBlockNum);

  // entryPeriodEnd フィールド == 公式値（null = lottery 実行時 env 未設定 → WARN）
  const computedEnd = ctx.data.entryPeriodEnd;
  if (sel.entryPeriodEnd === null || sel.entryPeriodEnd === undefined) {
    report.check('check.stageB.entryPeriodEndField', 'warn', { file: 'null', computed: displayTime(computedEnd) });
  } else if (Number(sel.entryPeriodEnd) === computedEnd) {
    report.check('check.stageB.entryPeriodEndField', 'pass', { file: displayTime(Number(sel.entryPeriodEnd)), computed: displayTime(computedEnd) });
  } else {
    report.check('check.stageB.entryPeriodEndField', 'fail', { file: String(sel.entryPeriodEnd), computed: displayTime(computedEnd) });
  }

  // applicantHash フィールド == Stage A が応募データから再計算した root R
  if (String(sel.applicantHash).toLowerCase() === chainHash) {
    report.check('check.stageB.applicantHashField', 'pass', { file: sel.applicantHash, onchain: chainHash });
  } else {
    report.check('check.stageB.applicantHashField', 'fail', { file: sel.applicantHash, onchain: chainHash });
  }

  // --- 3. targetBlock のブロックハッシュ / RANDAO(mixHash) をチェーンと照合 ---
  const targetBlock = await chain.getBlock(Number(sel.targetBlockNum));
  const chainBlockHash = String(targetBlock.hash).toLowerCase();
  const chainRandao = String(targetBlock.mixHash).toLowerCase();
  report.fact('targetBlockTime', displayTime(Number(targetBlock.timestamp) * 1000));
  if (String(sel.targetBlockHash).toLowerCase() === chainBlockHash) {
    report.check('check.stageB.targetBlockHash', 'pass', { file: sel.targetBlockHash, onchain: chainBlockHash });
  } else {
    report.check('check.stageB.targetBlockHash', 'fail', { file: sel.targetBlockHash, onchain: chainBlockHash });
  }
  if (String(sel.randao).toLowerCase() === chainRandao) {
    report.check('check.stageB.randao', 'pass', { file: sel.randao, onchain: chainRandao });
  } else {
    report.check('check.stageB.randao', 'fail', { file: sel.randao, onchain: chainRandao });
  }
  report.fact('randao', chainRandao);

  // --- 4. selectionSeed = keccak256(randao ‖ applicantHash)（lottery-DO.js:581-583 と同一バイト列） ---
  const selectionSeed = keccak256(concat([chainRandao, chainHash]));
  ctx.data.selectionSeed = selectionSeed;
  report.fact('selectionSeed', selectionSeed);
  ui.println(ui.t('stageB.seedDerived', { seed: selectionSeed }));

  // --- 5. totalEntries の独立検算（Stage A でデータファイル実件数から集計済み） ---
  const totalEntries = ctx.data.entriesTotal;
  if (sel.totalEntries === totalEntries) {
    report.check('check.stageB.totalEntries', 'pass', { file: sel.totalEntries, recomputed: totalEntries });
  } else {
    report.check('check.stageB.totalEntries', 'fail', { file: sel.totalEntries, recomputed: totalEntries });
  }

  // --- 6. vendored selectWinners で当選 index を再現 → players 全件照合 ---
  // 選出人数キャップ。config の gameMaxPlayers は check-vendor-sync.mjs が
  // game-master-DO / lottery-DO の GAME_MAX_PLAYERS へ機械束縛する。
  const maxPlayers = Number(cfg.pins.gameMaxPlayers);
  const selectedCount = Math.min(totalEntries, maxPlayers);
  const publishedCount = Array.isArray(sel.players) ? sel.players.length : -1;
  if (sel.totalSelected === selectedCount && publishedCount === selectedCount) {
    report.check('check.stageB.totalSelected', 'pass', { file: sel.totalSelected, players: publishedCount, expected: selectedCount });
  } else {
    report.check('check.stageB.totalSelected', 'fail', { file: sel.totalSelected, players: publishedCount, expected: selectedCount });
  }

  ui.println(ui.t('stageB.runningLottery', { total: totalEntries, count: selectedCount }));
  const selectedIndices = await withVendorLogging(() => selectWinners(selectionSeed, totalEntries, selectedCount));
  let derivedPlayers;
  try {
    derivedPlayers = await buildPlayers(r2, N, ctx.data.infos, selectedIndices, ctx.data.entryFileHashes);
  } catch (e) {
    report.check('check.stageB.playersMatch', 'fail', {
      count: publishedCount,
      mismatches: selectedCount,
      first: e?.message || String(e),
    });
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }

  const published = Array.isArray(sel.players) ? sel.players : [];
  let mismatches = 0;
  let firstMismatch = null;
  const compareLen = Math.max(derivedPlayers.length, published.length);
  for (let i = 0; i < compareLen; i++) {
    const d = derivedPlayers[i];
    const p = published[i];
    const ok = d && p
      && d.globalIndex === p.globalIndex
      && d.localIndex === p.localIndex
      && d.file === p.file
      && canonicalEqual(d.data, p.data);
    if (!ok) {
      mismatches++;
      if (firstMismatch === null) {
        firstMismatch = `#${i} derived=${d ? `g${d.globalIndex}/${d.file}` : '(none)'} published=${p ? `g${p.globalIndex}/${p.file}` : '(none)'}`;
      }
    }
  }
  if (mismatches === 0 && derivedPlayers.length === published.length) {
    report.check('check.stageB.playersMatch', 'pass', { count: published.length, mismatches: 0, first: '-' });
  } else {
    report.check('check.stageB.playersMatch', 'fail', { count: published.length, mismatches, first: firstMismatch ?? '-' });
  }
  report.fact('totalSelected', published.length);

  // 照合済みの公開 players をそのまま下流（grouping / Stage C）の入力にする（本番と同一経路）
  ctx.data.players = published;
  // 応募者全体の索引はここ以降不要。最大応募規模でもheapを選出2100人へ戻す。
  ctx.data.infos = null;
  ctx.data.entryFileHashes = null;

  // --- 7. ゲーム有無の分岐（game-master-DO startGrouping:1734-1766 の判定を写す） ---
  if (published.length === 0) {
    // 0名: grouping は noGame summary＋空ツリー標識root＋manifestを確定する。
    // grouping計算だけをスキップし、Stage Cでその全成果物を検証する（R22-F3）。
    ctx.data.noGame = true;
    ui.println(ui.t('stageB.noPlayers', { n: N }));
    return { stop: false };
  }
  if (published.length <= 2) {
    // 1〜2名: ゲーム無し・自動配布。grouping はスキップし Stage C が autoDistribute 経路を検証
    ctx.data.autoDistribute = true;
    ui.println(ui.t('stageB.autoDistribute', { n: published.length }));
  }

  return { stop: false };
}

// Stage B-2: グループ分けの検証
//
// 正典（byte-exact 写像元）:
//   - workers/game_workers/game-master-DO.js:28-51 (deriveGroupSeed / normalizeLang / deterministicRandom)
//   - workers/game_workers/game-master-DO.js:3538-3768 (computeMajorLangs / formGroups 一式)
//   - workers/game_workers/game-master-DO.js:10270-10314
//     (createGroupSummary / countGroupsByLang / getGroupSizeDistribution = game_groups.json writer)
// computeMajorLangs / formGroups は vendored GameMasterDO（本物のコード）を直接実行する。
import { withVendorLogging } from '../vendor-logging.js';
import { keccak256, concatHex, stringToHex } from 'viem';
import { canonicalEqual, sha256HexOfString } from '../json-utils.js';
import { findResultRegistrationAtGrouping, loadPreviousResultVersionCandidates,
  readPreviousResultCandidateSummary, deriveGroupsFromCanonicalRoster,
  PREVIOUS_RESULT_EVALUATION_LIMIT, previousMajorLangsMatch,
  verifyResultRegistrationRow, verifyResultHistoryOnFailure,
  missingPreviousResultVersions } from '../emergency.js';
import { deriveGroupingUpperBound, registeredByGroupingUpperBound } from './results.js';
import { locateCurrentResultRow } from '../prev-registration-witness.js';
// 🔴 便 X1 / Q-A（2026-09-21）: 前ブロックの登録回数は差分に数えなくなったので、
//    このモジュールから `recordEmergencyDifference`（stages/results.js）への依存は無くなった。
//    差分記録を再び足すときは、対象ブロック側（checkResultReregistration）と
//    必ず同じ便でそろえる（片方だけ直すと設計が割れる）。
import { GameMasterDO } from '../../vendor/workers/game_workers/game-master-DO.js';

// createGroupSummary 内の groups 写像（game-master-DO.js:10281-10287）と同形の公開グループ配列を再構成
// （memberIds の `m.data?.uid || m.globalIndex` フォールバックも正典どおり写す）
function toPublishedShape(groups) {
  return groups.map((g) => ({
    groupId: g.groupId,
    lang: g.lang,
    mixed: g.mixed,
    memberCount: g.members.length,
    memberIds: g.members.map((m) => m.data?.uid || m.globalIndex),
  }));
}

// countGroupsByLang（game-master-DO.js:10293-10303）の写し
function countGroupsByLang(groups) {
  const counts = Object.create(null);
  for (const group of groups) {
    const lang = group.lang;
    counts[lang] = (counts[lang] || 0) + 1;
  }
  return counts;
}

// getGroupSizeDistribution（game-master-DO.js:10307-10313）の写し
function getGroupSizeDistribution(groups) {
  const distribution = {};
  for (const group of groups) {
    const size = group.members.length;
    distribution[size] = (distribution[size] || 0) + 1;
  }
  return distribution;
}

export async function run(ctx) {
  const { r2, ui, report, blockNum: N } = ctx;
  const fetchOpts = { reuse: ctx.data.reuseFiles };

  // 0名noGameブロック: groupは存在しない。Stage CがnoGame成果物と標識rootを検証する。
  if (ctx.data.noGame) {
    report.check('check.stageB.groupingSkippedNoGame', 'skip', { n: N });
    ui.println(ui.t('stageB.groupingSkippedNoGame', { n: N }));
    return { stop: false };
  }

  // 1〜2名の自動配布ブロック: グループは存在しない（Stage C が autoDistribute 経路を検証）
  if (ctx.data.autoDistribute) {
    report.check('check.stageB.groupingSkippedAuto', 'skip', { n: N });
    ui.println(ui.t('stageB.groupingSkippedAuto', { n: N }));
    return { stop: false };
  }

  // V25-03/Q51: timeline照合失敗の終端は、0名ブロックとは別schemaで Stage C が
  // safe-chain Evidence resultCount=0 を直接検査する。ただし timeline 不照合は
  // group 公開後・ChatGameDO 初期化前にも起こり得るため、summary の名乗りだけで
  // grouping 再現を飛ばさない。game_groups があれば通常ブロックと同じ再導出へ進む。
  const terminalSummary = await r2.fetchJson(`games/block${N}/summary.json`, fetchOpts);
  if (terminalSummary?.data?.noGame === true
      && terminalSummary.data.noGameReason === 'timeline_unverified') {
    ctx.data.timelineNoGame = true;
  }

  // Stage B は抽選と一括表示（=== ヘッダーは selection.js 側の stageB.selStart のみ）

  // --- 1. game_groups.json（無し = グループ分け未実施 → ここで終了） ---
  const ggRes = await r2.fetchJson(`entries/block${N}/game_groups.json`, fetchOpts);
  if (!ggRes) {
    if (ctx.data.timelineNoGame) {
      ctx.data.timelineNoGameGameGroups = null;
      report.check('check.stageB.groupingSkippedTimelineNoGame', 'skip', { n: N });
      ui.println(ui.t('stageB.groupingSkippedTimelineNoGame', { n: N }));
      return { stop: false };
    }
    report.check('check.stageB.groupsPresent', 'skip', { n: N });
    ui.println(ui.t('stageB.noGroups', { n: N }));
    ctx.data.stopReason = 'not_ready';
    return { stop: true };
  }
  if (!ggRes.data || typeof ggRes.data !== 'object') {
    report.check('check.stageB.groupsPresent', 'fail', {
      n: N,
      reason: ggRes.sizeError || ggRes.parseError || 'game_groups is not a JSON object',
    });
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }
  const gg = ggRes.data;
  if (ctx.data.timelineNoGame) ctx.data.timelineNoGameGameGroups = ggRes;
  report.check('check.stageB.groupsPresent', 'pass', { n: N });

  const sel = ctx.data.gameSelection;
  const players = ctx.data.players;

  // --- 2. groupSeed = keccak256(randao ‖ applicantHash ‖ "group")（game-master-DO.js:31-33） ---
  // 本番と同じく game_selection.json の randao / applicantHash を入力にする
  //（両フィールドは Stage B-1 でオンチェーン値と照合済み）
  const groupSeed = keccak256(concatHex([sel.randao, sel.applicantHash, stringToHex('group')]));
  ctx.data.groupSeed = groupSeed;
  report.fact('groupSeed', groupSeed);
  ui.println(ui.t('stageB.groupSeedDerived', { seed: groupSeed }));
  const seedOk = String(gg.groupSeed).toLowerCase() === groupSeed
    && String(gg.randao).toLowerCase() === String(sel.randao).toLowerCase()
    && String(gg.applicantHash).toLowerCase() === String(sel.applicantHash).toLowerCase();
  if (seedOk) {
    report.check('check.stageB.groupSeed', 'pass', { file: gg.groupSeed, derived: groupSeed });
  } else {
    report.check('check.stageB.groupSeed', 'fail', { file: gg.groupSeed, derived: groupSeed });
  }

  // --- 3. vendored GameMasterDO（本物のコード）で majorLangs / formGroups を再現 ---
  const gm = withVendorLogging(() => new GameMasterDO({ storage: {} }, {}));

  // G7: computeMajorLangs が読む前ブロック（N-1）アーティファクト（`games/block{N-1}/summary.json`）は、
  // 返す前に前ブロックの manifest（verification/block{N-1}/manifest.json）＋
  // HashStorage.getResultHash(N-1) でアンカー検証する。
  //
  // 🔴 Q-5（2026-08-08・ユーザー確定）: 旧実装には `entries/block{N-1}/game_selection.json` への
  //    フォールバック経路があり、そこだけ「manifest 未発行だから」という理由でアンカー検証を
  //    **免除**していた（skip）。正典 `computeMajorLangs` からフォールバックそのものを削除し、
  //    ここでも免除を撤去する。ZKP（Stage 4）と検証ツールは独立した2層防御なので、
  //    片方だけ塞いでも「N箇所のうち1箇所」にしかならない。
  //    前ブロックの入力は `summary.json` の1本だけ。読んだのに検証できなければ **FAIL**。
  const prev = N - 1;
  const prevSummaryKey = `games/block${prev}/summary.json`;
  const prevState = {
    init: false,
    manifest: null,
    anchored: null,
    coreOk: false,
    summarySeen: false,
    registrationCount: null,
  };
  const prevVerified = [];
  const prevFailures = [];
  let historicalPrevAnchor = false;
  let groupingHistoryPromise = null;
  const groupingHistory = () => {
    if (!groupingHistoryPromise) groupingHistoryPromise = (async () => {
      // Keep the existing public-roster read failure visible to the Stage B
      // history exception; its bytes no longer choose the chain registration.
      await ctx.r2.fetchJson(`games/block${N}/roster/manifest.json`, fetchOpts);
      const time = await deriveGroupingUpperBound(ctx.chain, N);
      const history = await findResultRegistrationAtGrouping(
        ctx.chain, prev, time.upperMs, false, time.entryEndMs,
      );
      const marker = await ctx.chain.getResultHash(prev);
      const changedAfterGrouping = Boolean(history.current && marker
        && String(history.current.hash).toLowerCase() === String(marker.hash).toLowerCase()
        && Number(history.current.registeredBlock) === Number(marker.updated)
        && !registeredByGroupingUpperBound(history.current, time.upperMs)
        && history.selected
        && String(history.selected.hash).toLowerCase() !== String(marker.hash).toLowerCase());
      return { ...history, ...time, changedAfterGrouping, marker, rosterHash: time.rosterHash ?? null };
    })();
    return groupingHistoryPromise;
  };

  async function ensurePrevAnchor() {
    if (prevState.init) return;
    prevState.init = true;
    const mRes = await ctx.r2.fetchJson(`verification/block${prev}/manifest.json`, fetchOpts).catch(() => null);
    let anchored = null;
    try { anchored = await ctx.chain.getResultHash(prev); } catch { anchored = null; }
    prevState.anchored = (anchored && Number(anchored.updated) !== 0) ? anchored : null;
    if (mRes?.data && typeof mRes.data === 'object' && prevState.anchored) {
      const m = mRes.data;
      // manifest core の再ハッシュ（publishVerificationManifest :2877-2878 と同一の決定的 core）
      const coreHash = '0x' + sha256HexOfString(JSON.stringify({
        blockNum: m.blockNum, algorithm: m.algorithm, rules: m.rules, files: m.files,
      }));
      prevState.coreOk = coreHash === String(prevState.anchored.hash).toLowerCase();
      prevState.manifest = m;
      if (prevState.coreOk) {
        report.fact('stageB.prevAnchorTarget', {
          target: 'HashStorage.getResultHash_current_value',
          selectedIndex: null,
          selectedHash: prevState.anchored.hash,
          selectedRegisteredBlock: prevState.anchored.updated,
          currentHash: prevState.anchored.hash,
        });
      }
      const emergencySelected = ctx.data.emergencySource?.previousResultRegistration;
      if (!prevState.coreOk && emergencySelected?.selectedIndex != null
          && coreHash === String(emergencySelected.hash).toLowerCase()) {
        prevState.coreOk = true;
        const target = {
          target: 'emergency_selected_previous_result_registration',
          selectedIndex: emergencySelected.selectedIndex,
          selectedHash: emergencySelected.hash,
          selectedRegisteredAt: emergencySelected.registeredAt ?? null,
          upperMs: emergencySelected.upperMs ?? null,
          upperSource: emergencySelected.upperSource ?? null,
          currentHash: prevState.anchored.hash,
        };
        report.fact('stageB.prevAnchorTarget', target);
        ui.println(`##PREV_ANCHOR_TARGET ${JSON.stringify(target)}`);
      }
      if (!prevState.coreOk && !ctx.data.emergencySource) {
        try {
          const atGrouping = await groupingHistory();
          const matchingRow = atGrouping.changedAfterGrouping
            ? atGrouping.rows.find((row) => coreHash === String(row.hash).toLowerCase()) : null;
          if (atGrouping.changedAfterGrouping && !matchingRow) {
            await verifyResultHistoryOnFailure(ctx.chain, prev, atGrouping);
          }
          if (matchingRow) {
            Object.assign(matchingRow,
              await verifyResultRegistrationRow(ctx.chain, prev, matchingRow));
            prevState.coreOk = true;
            historicalPrevAnchor = true;
            const target = {
              target: 'eligible_registration_matching_published_manifest',
              selectedIndex: matchingRow.index,
              selectedHash: matchingRow.hash,
              selectedRegisteredAt: matchingRow.registeredAt,
              upperMs: atGrouping.upperMs,
              upperSource: atGrouping.source,
              currentHash: atGrouping.marker?.hash ?? null,
            };
            report.fact('stageB.prevAnchorTarget', target);
            ui.println(`##PREV_ANCHOR_TARGET ${JSON.stringify(target)}`);
          }
        } catch (error) {
          report.fact('stageB.previousResultVersionSearch', {
            error: String(error?.message || error), budget: error?.previousResultBudget ?? null,
          });
        }
      }
      if (!prevState.coreOk) {
        prevFailures.push(`manifest core sha256 != getResultHash(${prev})`);
      }
    }
  }

  async function fetchPrevVerified(key) {
    const res = await ctx.r2.fetchJson(key, fetchOpts);
    if (key === prevSummaryKey) prevState.summarySeen = res != null;
    if (!res) return null; // アーティファクト不存在 = computeMajorLangs 側の []/throw 経路に委ねる
    if (!res.data || typeof res.data !== 'object') {
      prevFailures.push(`${key}: ${res.sizeError || res.parseError || 'invalid JSON object'}`);
      return null;
    }
    await ensurePrevAnchor();
    if (!prevState.manifest || !prevState.anchored) {
      // Q-5: 免除なし。読めたのにアンカー検証できない前ブロック成果物は FAIL。
      prevFailures.push(`${key}: prev manifest / on-chain anchor unavailable`);
      return res.data;
    }
    if (prevState.coreOk) {
      const declared = prevState.manifest.files?.[key];
      if (declared != null && sha256HexOfString(res.raw) === declared) {
        prevVerified.push(key);
      } else {
        prevFailures.push(`${key}: sha256 mismatch vs anchored manifest`);
      }
    }
    return res.data;
  }

  // R2 読取を公開バケット経由に差し替え（script/test-grouping/run.mjs の前例）＋前ブロック分はアンカー検証。
  // Q-5: 鍵の allowlist を持たない。前ブロック（block{N-1}）配下のキーは**全部**検証経路へ通す
  //      （新しい入力を読むようになったときに黙って無検証で通る枠を残さない）。
  const prevKeyRe = new RegExp(`(^|/)block_?${prev}(/|\\.json$)`);
  gm.getR2Object = async (key) => {
    if (N > 0 && prevKeyRe.test(key)) return fetchPrevVerified(key);
    return (await ctx.r2.fetchJson(key, fetchOpts))?.data ?? null;
  };

  // 便 W4（2026-09-20）から続く、前ブロックの再登録の可視化。
  // R30-U-4 後は、履歴版の manifest → summary →実際の組の再現が正しさを検査する。
  // このカウンタはその代用ではなく、再登録を可視化する。限定分岐の入口は
  // 応募終了時点の現在値以降で、組分け上限以前の最新行と現在の目印の hash の相違で決める。
  // 🔴 fail にしない。正常な再集計や復旧でも回数は増えるため、回数自体は違反ではない。
  // 🔴 読めないときは skip（reason: 'unreadable'）。pass にしない
  //    （このプロジェクトの既知の失敗型「失敗を成功扱い」を作らない）。
  // 🔴 この検査 ID は EMERGENCY_ALLOWED_DIFFERENCE_CHECKS / EMERGENCY_DOWNGRADABLE_CHECKS /
  //    EMERGENCY_REQUIRED_CHECKS のどれにも入れない（warn なので入れる必要が無く、
  //    入れれば意味が反転する）。
  async function recordPrevResultReregistration() {
    if (N === 0) {
      report.check('check.stageB.prevResultReregistration', 'skip', { prev: '-', count: '-', updated: '-', signer: '-', reason: 'no_previous_block' });
      return;
    }
    let count = null;
    try {
      count = Number(await ctx.chain.resultRegistrationCount(prev));
    } catch {
      count = null;
    }
    prevState.registrationCount = count;
    if (count == null || !Number.isFinite(count)) {
      report.check('check.stageB.prevResultReregistration', 'skip', { prev, count: '-', updated: '-', signer: '-', reason: 'unreadable' });
      return;
    }
    // 目印の登録時刻・登録者は報告用の付随情報。
    // 🔴 ensurePrevAnchor() は呼ばない（呼ぶと prevFailures を増やし得て、
    //    check.stageB.prevAnchor の通常モードの判定が動いてしまう）。
    //    既に読んである場合だけ使い、無ければ独立に1回読む。
    let anchored = prevState.anchored;
    if (!anchored) {
      try { anchored = await ctx.chain.getResultHash(prev); } catch { anchored = null; }
    }
    const updated = anchored?.updated ?? null;
    const signer = anchored?.signer ?? null;
    // 🔴 便 X1 / Q-A: `anchored.hash` は差分の中だけで使っていた。差分を外したので読まない。
    //    報告（report.check の params）の中身は1件も変えていない。
    if (count === 0) {
      // 前ブロックの結果ハッシュが1度も登録されていない（差し替えではない）。
      // 「1回きり」を名乗れないので pass にはしない。
      report.check('check.stageB.prevResultReregistration', 'skip', { prev, count, updated, signer, reason: 'unregistered' });
      return;
    }
    // 🔴 便 X1 / Q-A（2026-09-21・ユーザー決定 (a)）: 対象ブロック側
    //    （`checkResultReregistration()`・`stages/results.js`）と同じにそろえる。
    //    `HashStorage.registerResultHash` の直前のコメントは逐語で
    //    「resultHash は何度でも上書き可能（障害時の再計算・再登録に対応）だが、
    //      登録回数は単調増加カウンタに記録され改ざんできない（差し替えの可視化）。」
    //    ＝回数は**可視化**のためのもので、違反の印ではない。緊急復旧は再登録を必須にしている
    //    ので、正しく復旧すると必ず回数が2以上になり、必ず「事故差あり」になってしまう。
    //    現在値の正しさは `check.stageB.prevAnchor`、R30-U-4 の履歴版は
    //    `loadPreviousResultVersionCandidates()` の2ホップと組の再現が検査する。
    //    回数の `warn` と読み手向けの1行は従来どおり残す。
    //    🔴 片方だけ直すと設計が割れるので、対象ブロック側と同じ便で同じにそろえてある。
    if (count > 1) {
      report.check('check.stageB.prevResultReregistration', 'warn', { prev, count, updated, signer, reason: 'reregistered' });
      ui.println(ui.t('stageB.prevResultReregistered', { prev, count }));
      return;
    }
    report.check('check.stageB.prevResultReregistration', 'pass', { prev, count, updated, signer, reason: '-' });
  }

  // 🔴 周29 (c)（2026-09-22）: 前ブロックの目印読み（`ensurePrevAnchor` の `getResultHash(prev)`）が
  //    **履歴のどの行を指すか**を報告へ残す。
  //    R30-U-4 後もこの fact は「現在値の所在」のままで、履歴版を採用した事実は
  //    `stageB.previousResultVersion` の別 fact に残す。`report.check` は追加しない。
  //    履歴が読めなくても既存の判定は動かさない（try/catch で閉じ、読めなかったことを fact へ書く）。
  async function recordPrevResultMarkerRow() {
    if (N === 0) return;
    // 項の並びは履歴が読めた場合と読めなかった場合で同じにする（欠けた項を undefined にしない）。
    const base = {
      prev,
      selectionRule: 'HashStorage.getResultHash current value (unchanged)',
      hash: prevState.anchored?.hash ?? null,
      updatedBlock: prevState.anchored?.updated ?? null,
      signer: prevState.anchored?.signer ?? null,
      registrationCount: null,
      currentIndex: null,
      matchingIndices: null,
      latestIndex: null,
    };
    if (typeof ctx.chain.resultRegistrationHistory !== 'function') {
      report.fact('stageB.prevResultMarkerRow', {
        ...base, historyError: 'resultRegistrationHistory is not available on this chain reader',
      });
      return;
    }
    try {
      const history = await ctx.chain.resultRegistrationHistory(prev);
      const located = locateCurrentResultRow(history, prevState.anchored);
      report.fact('stageB.prevResultMarkerRow', { ...base, ...located, historyError: null });
      const target = report.getFact('stageB.prevAnchorTarget');
      if (target?.target === 'HashStorage.getResultHash_current_value') {
        const row = history.rows?.[located.currentIndex];
        report.fact('stageB.prevAnchorTarget', {
          ...target,
          selectedIndex: located.currentIndex ?? null,
          selectedHash: row?.hash ?? target.selectedHash,
          selectedRegisteredBlock: row?.registeredBlock ?? target.selectedRegisteredBlock,
          selectedRegisteredAt: row?.registeredAt ?? null,
        });
      }
    } catch (error) {
      report.fact('stageB.prevResultMarkerRow', { ...base, historyError: String(error?.message || error) });
    }
  }

  async function recordPrevAnchor() {
    if (N === 0) {
      report.check('check.stageB.prevAnchor', 'skip', { prev: '-', files: 0, failures: '-' });
    } else if (prevFailures.length > 0) {
      report.check('check.stageB.prevAnchor', 'fail', { prev, files: prevVerified.length, failures: prevFailures.join('; ') });
    } else if (prevVerified.length > 0) {
      const target = report.getFact('stageB.prevAnchorTarget');
      const historical = target && target.target !== 'HashStorage.getResultHash_current_value';
      report.check('check.stageB.prevAnchor', 'pass', {
        prev, files: prevVerified.length, failures: '-',
        ...(historical ? { anchorTarget: 'history', selectedIndex: target.selectedIndex } : {}),
      });
    } else {
      // 前ブロックにアンカー対象アーティファクトが無い（majorLangs=[] 経路）
      report.check('check.stageB.prevAnchor', 'skip', { prev, files: 0, failures: '-' });
    }
    await recordPrevResultReregistration();
    await recordPrevResultMarkerRow();
  }

  // T4 §3（2026-09-18）: 前ブロックの照合が fail でも、fetchPrevVerified は取得したバイト列を
  // そのまま返す（:172・:182）。判定は fail-closed（check.stageB.prevAnchor が fail）だが、
  // **値は fail-open** で、主要言語とその先のグループ分けはその未検証のバイト列から導かれる。
  // 🔴 制御の流れは変えない（通常モードの判定と終了状態を1件も動かさないため）。
  //    報告の側だけに「未検証の前ブロック入力から導いた」印を足す。
  //    印は i18n に依存しない1行（##UNVERIFIED_PREV_INPUT）と fact の2か所へ出す。
  function markUnverifiedPrevInput(where, extra = {}) {
    if (N === 0 || prevFailures.length === 0) return false;
    const mark = {
      derivedFrom: 'unverified_previous_block_input',
      where,
      prev,
      prevSummaryKey,
      prevSummarySeen: prevState.summarySeen,
      verifiedFiles: prevVerified.length,
      failures: prevFailures.slice(),
      ...extra,
    };
    ctx.data.groupingPrevUnverified = mark;
    report.fact('groupingPrevInputUnverified', mark);
    ui.println(
      `##UNVERIFIED_PREV_INPUT block=${N} prev=${prev} where=${where} `
      + `majorLangs=${JSON.stringify(mark.majorLangs ?? null)} `
      + `groups=${mark.groups ?? '-'} failures=${JSON.stringify(prevFailures)}`,
    );
    return true;
  }

  const publishedGroups = Array.isArray(gg.groups) ? gg.groups : [];
  const lostPrevious = ctx.data.emergencySource?.previousMajorLangsUnverifiable ?? null;
  let majorLangs = null;
  let currentMajorLangError = null;
  if (lostPrevious) {
    majorLangs = lostPrevious.majorLangs;
  } else {
    try {
      majorLangs = await withVendorLogging(() => gm.computeMajorLangs(N));
    } catch (e) {
      const msg = String(e?.message ?? e);
      if (!msg.includes('MAJOR_LANG_PREV_NOT_READY')) throw e;
      currentMajorLangError = msg;
    }
  }
  await recordPrevAnchor();

  let derived = lostPrevious?.canonicalGroups ?? (majorLangs === null
    ? null
    : await withVendorLogging(() => gm.formGroups(players, groupSeed, majorLangs)));
  const currentGroupsMatch = derived !== null
    && canonicalEqual(toPublishedShape(derived), publishedGroups);
  let majorLangStatus = lostPrevious ? 'warn' : 'pass';
  let majorLangReason = lostPrevious ? 'previous_summary_lost' : '-';
  const announcePreviousSummaryLoss = (langs, missingVersions = [], savedMismatches = [], archive = null) => {
    const label = JSON.stringify(langs);
    const missing = JSON.stringify(missingVersions);
    const j1Note = archive?.lineageCheckBypassed === true
      || (Array.isArray(archive?.laterSavedGenerations) && archive.laterSavedGenerations.length > 0)
      ? ' note="この--manifest書き出しに無い。保管庫の後の保存世代を確認"' : '';
    ui.println(`##PREVIOUS_SUMMARY_LOST block=${N} prev=${prev} majorLangs=${label} missingVersions=${missing} savedMismatches=${JSON.stringify(savedMismatches)}${j1Note}`);
    ui.println(ui.t('stageB.previousSummaryLost', { block: N, prev, langs: label, missing }));
    if (savedMismatches.length > 0) ui.println(ui.t('stageB.previousSavedMismatch', {
      saved: JSON.stringify(savedMismatches), missing,
    }));
  };
  if (lostPrevious) announcePreviousSummaryLoss(majorLangs, lostPrevious.missingVersions,
    lostPrevious.savedMismatches);

  // R30-U-4（通常モードで承認された唯一の例外）:
  // 現在の N からの再導出が実際の組と食い違う場合だけ、N+1 の公開 summary が宣言した
  // majorLangs で組を必ず再現する。応募終了時点の現在行以降・組分け上限以前の最新行が
  // 現在の目印と異なるときだけ履歴版を試す。公開 N manifest を履歴行例外で認めたなら、
  // 宣言主要言語の別例外は重ねない。保存世代は --observer-source で完全検証する。
  const declaredMajorLangs = Array.isArray(terminalSummary?.data?.majorLangs)
    && terminalSummary.data.majorLangs.every((lang) => typeof lang === 'string')
    ? terminalSummary.data.majorLangs.slice()
    : null;
  let declaredDerived = null;
  let declaredGroupsMatch = false;
  if (!currentGroupsMatch && !ctx.data.emergencySource && declaredMajorLangs !== null) {
    try {
      declaredDerived = await withVendorLogging(() => gm.formGroups(players, groupSeed, declaredMajorLangs));
      declaredGroupsMatch = canonicalEqual(toPublishedShape(declaredDerived), publishedGroups);
    } catch {
      declaredDerived = null;
      declaredGroupsMatch = false;
    }
  }

  if (!currentGroupsMatch && declaredGroupsMatch && !historicalPrevAnchor) {
    let atGrouping = null;
    try { atGrouping = await groupingHistory(); } catch (error) {
      // 例外へは入らず従来の判定を維持。RPC 予算切れなどの理由は fact に残す。
      report.fact('stageB.previousResultVersionSearch', {
        error: String(error?.message || error), budget: error?.previousResultBudget ?? null,
      });
    }
    if (atGrouping?.changedAfterGrouping) {
      const observerSource = ctx.cfg?.observerSource || null;
      if (!observerSource) {
        if (majorLangs !== null) {
          majorLangs = declaredMajorLangs;
          derived = declaredDerived;
          majorLangStatus = 'warn';
          majorLangReason = 'previous result was registered again after grouping; verify the saved version with --observer-source';
          ui.println(
            `##OBSERVER_SOURCE_REQUIRED block=${N} prev=${prev} `
            + 'previous result was registered again after grouping; '
            + 'verify the old manifest/summary generations with --observer-source',
          );
        }
      } else {
        try {
          const versions = await loadPreviousResultVersionCandidates({
            sourceDir: observerSource,
            chain: ctx.chain,
            blockNum: N,
            groupingRosterHash: atGrouping.rosterHash,
            entranceUpperMs: atGrouping.upperMs,
          });
          report.fact('stageB.previousResultVersionSearch', {
            entranceUpperMs: atGrouping.upperMs,
            savedUpperMs: versions.groupingTime.savedUpperMs ?? versions.groupingTime.upperMs,
            effectiveUpperMs: versions.groupingTime.upperMs,
            rosterDifference: versions.rosterDifference,
            rosterGenerationMissing: versions.rosterGenerationMissing,
          });
          const matching = [];
          const failedCandidates = [];
          const majorByHash = new Map();
          let evaluations = 0;
          for (const candidate of versions.candidates) {
            if (candidate.status !== 'ready') {
              failedCandidates.push({
                index: candidate.registration?.index ?? null,
                status: candidate.status,
              });
              continue;
            }
            try {
              const hashKey = String(candidate.registration.hash).toLowerCase();
              let candidateMajorLangs = majorByHash.get(hashKey);
              if (candidateMajorLangs === undefined) {
                if (evaluations >= PREVIOUS_RESULT_EVALUATION_LIMIT) {
                  const error = new Error('saved previous-result evaluation budget exhausted');
                  error.previousResultBudget = {
                    owner: 'this verification run: distinct saved previous-result versions evaluated',
                    used: evaluations, limit: PREVIOUS_RESULT_EVALUATION_LIMIT,
                  };
                  throw error;
                }
                evaluations++;
                const candidateGm = withVendorLogging(() => new GameMasterDO({ storage: {} }, {}));
                candidateGm.getR2Object = async (key) => (
                  key === prevSummaryKey
                    ? await readPreviousResultCandidateSummary(observerSource, candidate) : null
                );
                candidateMajorLangs = await withVendorLogging(() => candidateGm.computeMajorLangs(N));
                majorByHash.set(hashKey, candidateMajorLangs);
              }
              if (previousMajorLangsMatch(candidateMajorLangs, declaredMajorLangs)) {
                matching.push({ candidate, candidateMajorLangs });
              }
            } catch (error) {
              if (error.previousResultBudget) throw error;
              failedCandidates.push({
                index: candidate.registration?.index ?? null,
                status: 'evaluation_failed',
                reason: String(error?.message || error),
              });
            }
          }
          versions.budgets.evaluations = {
            owner: 'this verification run: distinct saved previous-result versions evaluated',
            used: evaluations, limit: PREVIOUS_RESULT_EVALUATION_LIMIT,
          };
          if (matching.length === 0) {
            const missingVersions = missingPreviousResultVersions(versions);
            const historicalBytesLost = missingVersions.length > 0;
            const savedMismatches = versions.candidates.filter((candidate) =>
              candidate.status === 'ready')
              .map((candidate) => ({ index: candidate.registration.index,
                hash: candidate.registration.hash }));
            if (historicalBytesLost) {
              const canonicalGroups = await deriveGroupsFromCanonicalRoster({
                sourceDir: observerSource, index: versions.archive, chain: ctx.chain,
                blockNum: N, players, publishedGroups,
              });
              if (!canonicalEqual(toPublishedShape(canonicalGroups), toPublishedShape(declaredDerived))) {
                throw new Error('declared groups differ from the chain-anchored roster');
              }
              majorLangs = declaredMajorLangs;
              derived = canonicalGroups;
              majorLangStatus = 'warn';
              majorLangReason = 'previous_summary_lost';
              announcePreviousSummaryLoss(majorLangs, missingVersions, savedMismatches,
                versions.archive);
            } else {
              versions.budgets.failureAudit = await verifyResultHistoryOnFailure(
                ctx.chain, prev, versions.history,
              );
              majorLangStatus = 'fail';
              majorLangReason = 'observer source has no registered previous result version that derives the declared major languages';
            }
            report.fact('stageB.previousResultVersion', {
              source: observerSource,
              selectedIndex: null,
              currentIndex: versions.currentLocation?.currentIndex ?? null,
              declaredMajorLangs,
              failedCandidates,
              lost: historicalBytesLost,
              missingVersions,
              savedMismatches,
              budgets: versions.budgets,
            });
          } else {
            const selected = matching[0].candidate;
            Object.assign(selected.registration,
              await verifyResultRegistrationRow(ctx.chain, prev, selected.registration));
            majorLangs = declaredMajorLangs;
            derived = declaredDerived;
            majorLangStatus = 'pass';
            majorLangReason = '-';
            const selectedVersion = {
              source: observerSource,
              selectionRule: 'latest eligible registration whose saved version derives summary.majorLangs and reproduces game_groups',
              selectedIndex: selected.registration.index,
              selectedHash: selected.registration.hash,
              selectedRegisteredBlock: selected.registration.registeredBlock ?? null,
              selectedRegisteredAt: selected.registration.registeredAt ?? null,
              upperMs: versions.groupingTime.upperMs,
              upperSource: versions.groupingTime.source,
              selectedSigner: selected.registration.signer ?? null,
              currentIndex: versions.currentLocation?.currentIndex ?? null,
              currentHash: versions.currentMarker?.hash ?? null,
              matchingIndices: matching.map((item) => item.candidate.registration.index),
              manifestGeneration: selected.manifestRow.generation ?? null,
              summaryGeneration: selected.summaryRow.generation ?? null,
              majorLangs: selected.majorLangs ?? declaredMajorLangs,
              budgets: versions.budgets,
            };
            report.fact('stageB.previousResultVersion', selectedVersion);
            ui.println(`##PREVIOUS_RESULT_VERSION ${JSON.stringify(selectedVersion)}`);
          }
        } catch (error) {
          majorLangStatus = 'fail';
          majorLangReason = `observer source could not verify the previous result version: ${String(error?.message || error)}`;
          report.fact('stageB.previousResultVersion', {
            source: observerSource,
            selectedIndex: null,
            currentIndex: null,
            declaredMajorLangs,
            error: String(error?.message || error),
            budget: error?.previousResultBudget ?? null,
          });
        }
      }
    }
  }

  if (majorLangs === null || derived === null) {
    // 前ブロックが未公開で、かつ observer で締切時点の旧版を検証できた枝にも
    // 入らなかった盤面は従来どおりここで停止する。
    markUnverifiedPrevInput('majorLangsPrevNotReady');
    report.check('check.stageB.majorLangs', 'fail', {
      langs: '-', prev: N - 1, reason: currentMajorLangError,
    });
    ui.println(ui.t('stageB.majorLangsPrevNotReady', { prev: N - 1 }));
    ctx.data.stopReason = 'fail';
    return { stop: true };
  }

  ctx.data.majorLangs = majorLangs;
  const majorLangLabel = majorLangs.length > 0 ? majorLangs.join(', ') : '(none)';
  report.fact('majorLangs', majorLangLabel);
  report.check('check.stageB.majorLangs', majorLangStatus, {
    langs: majorLangLabel,
    prev: N - 1,
    reason: majorLangReason,
  });
  ui.println(ui.t('stageB.majorLangsComputed', { langs: majorLangLabel }));

  ui.println(ui.t('stageB.runningFormGroups', { players: players.length }));
  ctx.data.groupsDerived = derived;
  // 主要言語が変われば人員・グループ数・group id が総入れ替えになるので、印は
  // majorLangs だけでなく、そこから導いたグループ分けの結果にも掛かる。
  markUnverifiedPrevInput('majorLangsAndGrouping', {
    majorLangs: majorLangs.slice(),
    groups: derived.length,
  });

  // --- 4. 公開 game_groups.json と全件照合 ---

  // グループ数・総プレイヤー数
  if (gg.totalGroups === derived.length && publishedGroups.length === derived.length && gg.totalPlayers === players.length) {
    report.check('check.stageB.groupCount', 'pass', {
      file: gg.totalGroups,
      listed: publishedGroups.length,
      derived: derived.length,
      filePlayers: gg.totalPlayers,
      players: players.length,
    });
  } else {
    report.check('check.stageB.groupCount', 'fail', {
      file: gg.totalGroups,
      listed: publishedGroups.length,
      derived: derived.length,
      filePlayers: gg.totalPlayers,
      players: players.length,
    });
  }
  report.fact('totalGroups', derived.length);

  // 各グループの lang / mixed / メンバーID順（＝タブーrotationの基準となる正準順序）
  const expectedGroups = toPublishedShape(derived);
  if (canonicalEqual(expectedGroups, publishedGroups)) {
    report.check('check.stageB.groupsMatch', 'pass', { count: derived.length, index: -1, expected: '-', actual: '-' });
  } else {
    let firstDiff = null;
    const len = Math.max(expectedGroups.length, publishedGroups.length);
    for (let i = 0; i < len && firstDiff === null; i++) {
      if (!canonicalEqual(expectedGroups[i] ?? null, publishedGroups[i] ?? null)) {
        firstDiff = {
          index: i,
          expected: JSON.stringify(expectedGroups[i] ?? null).slice(0, 200),
          actual: JSON.stringify(publishedGroups[i] ?? null).slice(0, 200),
        };
      }
    }
    report.check('check.stageB.groupsMatch', 'fail', {
      count: derived.length,
      index: firstDiff?.index ?? -1,
      expected: firstDiff?.expected ?? '-',
      actual: firstDiff?.actual ?? '-',
    });
  }

  // 統計フィールド（groupsByLang / mixedGroups / groupSizes）の再計算照合
  const statsOk = canonicalEqual(countGroupsByLang(derived), gg.groupsByLang)
    && gg.mixedGroups === derived.filter((g) => g.mixed).length
    && canonicalEqual(getGroupSizeDistribution(derived), gg.groupSizes);
  if (statsOk) {
    report.check('check.stageB.groupStats', 'pass', {
      byLang: JSON.stringify(gg.groupsByLang),
      sizes: JSON.stringify(gg.groupSizes),
      mixed: gg.mixedGroups,
    });
  } else {
    report.check('check.stageB.groupStats', 'fail', {
      byLang: JSON.stringify(gg.groupsByLang),
      sizes: JSON.stringify(gg.groupSizes),
      mixed: gg.mixedGroups,
    });
  }

  // timeline no-game の専用 summary は groups=[] が正準形であり、グループ形成直後の
  // 通常 summary と一致させてはいけない。game_groups 自体の再導出は上で完了している。
  if (ctx.data.timelineNoGame) {
    report.check('check.stageB.summaryStructure', 'skip', {
      count: derived.length,
      mismatches: 0,
      first: 'timeline_no_game_summary_has_no_groups',
    });
    return { stop: false };
  }

  // --- 5. summary.json（/block ページの配信データ）のグループ構成照合 ---
  // ユーザーが実際に見るのは games/block{N}/summary.json（src/pages/block.js:139）であり、
  // game_groups.json との一致だけでは「ページに表示されるメンバーリスト」の保証にならない。
  // そこで summary.json のグループ構成（group_id の集合・各グループのメンバーIDとその順序）を
  // 再現結果と直接照合する。summary はグループ形成直後に書かれ（buildBlockSummaryForR2:1809）、
  // 結果確定時に buildBlockSummaryWithResults で上書きされるが、どちらも構成は同一であるべき。
  // グループ配列の並び順は結果版で D1 行順の観測値になるため（Stage C summaryGroupSet と同方針）
  // group_id 対応の集合一致で照合し、グループ内メンバー順序はタブーrotationの正準順序として
  // 厳密一致を要求する。得点・報酬などの結果フィールドは Stage C（summaryMatch）が検証する。
  ui.println(ui.t('stageB.summaryChecking'));
  const sumRes = await r2.fetchJson(`games/block${N}/summary.json`, fetchOpts);
  const sumGroups = Array.isArray(sumRes?.data?.groups) ? sumRes.data.groups : null;
  if (!sumGroups) {
    report.check('check.stageB.summaryStructure', 'fail',
      { count: derived.length, mismatches: 1, first: `games/block${N}/summary.json missing or invalid` });
  } else {
    const byId = new Map();
    for (const g of sumGroups) if (!byId.has(g.group_id)) byId.set(g.group_id, g);
    let mismatches = 0;
    let first = null;
    const note = (s) => { mismatches++; if (first === null) first = s; };
    if (sumGroups.length !== derived.length) note(`groups: summary=${sumGroups.length} derived=${derived.length}`);
    if (byId.size !== sumGroups.length) note('duplicate group_id in summary.json');
    for (const g of derived) {
      const sg = byId.get(g.groupId);
      if (!sg) { note(`group${g.groupId}: missing in summary.json`); continue; }
      // buildBlockSummaryForR2:3840 / buildBlockSummaryWithResults:3910 と同じ写像（uid → userId）
      const expectedIds = g.members.map((m) => m.data?.uid ?? null);
      const actualIds = Array.isArray(sg.members) ? sg.members.map((m) => m.userId ?? null) : null;
      if (!canonicalEqual(actualIds, expectedIds)) {
        note(`group${g.groupId}: memberIds expected=${JSON.stringify(expectedIds)} actual=${JSON.stringify(actualIds)}`);
      }
    }
    report.check('check.stageB.summaryStructure', mismatches === 0 ? 'pass' : 'fail',
      { count: derived.length, mismatches, first: first ?? '-' });
  }

  return { stop: false };
}

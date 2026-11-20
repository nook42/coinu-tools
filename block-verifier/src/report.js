// block-verifier/src/report.js
// ステージ結果（check）とファクト（fact）の蓄積 ＋ 最終まとめ（DESIGN §3 まとめ／ユーザーフロー8）。
// check(id, status, params): status = 'pass'|'warn'|'fail'|'skip'。id は i18n キーと同一。
// renderSummary(ui, ctx): 途中終了でも到達分を平易な番号付き結論として必ず表示する。

import { tzOffsetLabel } from './json-utils.js';
import { CHECK_INVENTORY } from './check-inventory.js';
import { VERIFICATION_AREAS } from './verification-areas.js';
import { conciseRpcText, ArchiveUnavailableError, LOCK_DEPENDENT_CHECKS } from './archive.js';

// 出力用の投影のみ。report に蓄積した検証データは書き換えない。
export function displayParams(params, translate) {
  if (!params || typeof params !== 'object') return params;
  // details.current.error等も同じerror欄の投影を通す。検証値・元の参照は変更しない。
  const copy = Array.isArray(params) ? [] : {};
  const seen = new Map([[params, copy]]);
  const pending = [[params, copy]];
  let changed = false;
  while (pending.length) {
    const [source, target] = pending.pop();
    for (const [key, value] of Object.entries(source)) {
      let shown = value;
      if (/^(?:error|.*Error)$/.test(key) && (typeof value === 'string' || value instanceof Error)) {
        shown = conciseRpcText(value, translate);
        changed ||= shown !== value;
      } else if (value && typeof value === 'object' && (Array.isArray(value) || Object.getPrototypeOf(value) === Object.prototype)) {
        if (!seen.has(value)) {
          seen.set(value, Array.isArray(value) ? [] : {});
          pending.push([value, seen.get(value)]);
        }
        shown = seen.get(value);
      }
      Object.defineProperty(target, key, { value: shown, enumerable: true, writable: true, configurable: true });
    }
  }
  return changed ? copy : params;
}

// 段全体の成否を、検査対象ごとの確認範囲と混同しない。本番パラメータ不一致も別掲する。
export function verificationCoverage(report) {
  const checks = report.list();
  const noGame = report.getFact?.('stageC.noGame') === true;
  const timelineNoGame = report.getFact?.('stageC.timelineNoGame') === true;
  const globalFailure = checks.some((e) => e.status === 'fail'
    && e.id.startsWith('check.system.') && e.id !== 'check.system.productionParams');
  const nonGame = !timelineNoGame && (noGame || report.getFact?.('stageC.autoDistributed') === true);
  const coverage = VERIFICATION_AREAS.map(({ area, matches, required, complete, notApplicable: areaNotApplicable }) => {
    const entries = checks.filter((e) => matches.test(e.id));
    const failed = globalFailure || entries.some((e) => e.status === 'fail');
    const archive = entries.some((e) => e.reason === 'archive_unavailable');
    // 自動配布・応募0件ではEvidenceの期間検査を実施しない。履歴の到達条件は残す。
    const prerequisites = required.filter((id) =>
      !(area === 'timeline' && nonGame && id === 'check.stageC.timelineWindows'));
    if (area === 'scoring') prerequisites.push(noGame || timelineNoGame
      ? `check.stageC.${timelineNoGame ? 'timelineNoGameSummary' : 'noGameSummary'}`
      : 'check.stageC.depositVerification');
    const verified = !failed && !archive
      && (!complete || complete(report))
      && prerequisites.every((id) => report.get(id)?.status === 'pass');
    // 対象なしは、確定した分岐と実行結果の両方で判断。失敗/読取不能を対象なしに隠さない。
    const notApplicable = !failed && !archive && (
      (area === 'adminHistory' && report.getFact?.('system.audit')?.adminHistoryChecked === false && entries.length === 0)
      || (area === 'locks' && (noGame || timelineNoGame))
      || (area === 'grouping' && ['NoGame', 'TimelineNoGame', 'Auto'].some((mode) =>
        report.get(`check.stageB.groupingSkipped${mode}`)?.status === 'skip'))
      || (area === 'evidence' && nonGame
        && !entries.some((e) => !['check.stageC.evidenceSegmentBoundaries'].includes(e.id)))
      || (area === 'timeline' && nonGame
        && report.get('check.stageC.timelineWindows')?.status === 'skip'
        && areaNotApplicable(report, entries))
      || (['proofPublicValues', 'proofHistory'].includes(area) && ['shadow', 'no_root'].includes(
        report.get('check.stageC.zkProofStatus')?.params?.kind))
    );
    const warning = area === 'adminHistory' && entries.some((e) => e.status === 'warn');
    return { area, verified, notApplicable, reason: failed ? 'failed' : archive ? 'archiveUnavailable'
      : warning ? 'rpcRequestFailed' : 'stopped' };
  });
  return coverage;
}

// wei 文字列 → BTCu 表示（block.js formatReward と同趣旨の丸め。表示専用）
function weiToBtcu(wei) {
  try {
    if (wei == null) return '-';
    const v = Number(BigInt(wei)) / 1e18;
    if (!Number.isFinite(v)) return String(wei);
    return v >= 10 ? Math.round(v).toLocaleString('en-US') : v.toPrecision(3);
  } catch {
    return String(wei);
  }
}

// fail/warn/skip 行に生パラメータを添える（テンプレートが拾わない詳細の取りこぼし防止）
function paramsSuffix(params, maxLength = 300, redactText = String) {
  if (!params || typeof params !== 'object' || Object.keys(params).length === 0) return '';
  let s;
  try { s = JSON.stringify(params); } catch { s = String(params); }
  s = redactText(s);
  if (Number.isFinite(maxLength) && s.length > maxLength) s = s.slice(0, maxLength) + '…';
  return `\n      ${s}`;
}

// applicantHash の追記履歴に同じ値しかないか、異なる値への差し替えがあるかを表示用に分類する。
// 判定材料は Stage A がチェーンの getter から全件読んだ registrations の hash だけに限定する。
export function registrationHistoryKind(entry) {
  const count = Number(entry?.params?.count);
  const registrations = entry?.params?.registrations;
  if (!Number.isSafeInteger(count) || count < 2 || !Array.isArray(registrations)
      || registrations.length !== count) return 'unknown';
  const hashes = registrations.map((registration) => registration?.hash);
  if (hashes.some((hash) => typeof hash !== 'string' || hash.length === 0)) return 'unknown';
  return new Set(hashes.map((hash) => hash.toLowerCase())).size === 1 ? 'same' : 'different';
}

function repeatedRegistrationMessageId(base, entry) {
  const kind = registrationHistoryKind(entry);
  if (kind === 'same') return `${base}Same`;
  if (kind === 'different') return `${base}Different`;
  return base;
}

// check id は増やさず、状態・理由に応じて表示文だけを選ぶ。
// ステージ判定行と最終まとめの双方が必ずこの関数を通す。
export function messageId(entry) {
  if (entry.status === 'skip' && entry.reason === 'archive_unavailable') return 'reason.archiveUnavailable';
  if (entry.id === 'check.stageB.prevAnchor' && entry.status === 'pass'
      && entry.params?.anchorTarget === 'history') {
    return 'stageB.prevAnchorHistorical';
  }
  if (entry.id === 'check.stageA.rootMatch' && entry.status === 'fail') {
    if (entry.params?.reason === 'no_matching_registration_at_or_after_entry_deadline') {
      return 'stageA.rootMatchFail.noMatchingAfterDeadline';
    }
    if (entry.params?.reason === 'first_matching_registration_before_entry_deadline') {
      return 'stageA.rootMatchFail.firstMatchingBeforeDeadline';
    }
    if (entry.params?.reason === 'registration_history_unavailable') {
      return 'stageA.rootMatchFail.historyUnavailable';
    }
  }
  if (entry.id === 'check.stageA.registrationCount' && entry.status === 'warn') {
    if (entry.params?.legacyLatestOnly === true) return 'stageA.registrationCountLegacyLatestOnly';
    if (entry.params?.count === 'unavailable') return 'stageA.registrationCountUnavailable';
    return repeatedRegistrationMessageId('check.stageA.registrationCountWarn', entry);
  }
  if (entry.id === 'check.stageC.rootSubmitted') {
    if (entry.params?.reason === 'expected_timeline_no_game_omission') {
      return 'check.stageC.rootOmissionExpected';
    }
    if (entry.params?.reason === 'timeline_no_game_deadline_open') {
      return 'check.stageC.rootOmissionPending';
    }
    if (entry.params?.reason === 'timeline_no_game_deadline_unavailable') {
      return 'check.stageC.rootOmissionDeadlineUnavailable';
    }
  }
  return entry.id;
}

export function stageVerdictIssues(report, key, before) {
  const news = report.list().slice(before);
  const failurePrefixes = key === 'A'
    ? ['check.system.', 'check.stageA.']
    : key === 'B'
      ? ['check.system.', 'check.stageA.', 'check.stageB.']
      : ['check.system.', 'check.stageA.', 'check.stageB.', 'check.stageC.'];
  return {
    firstFail: report.list().find((e) => e.status === 'fail'
      && failurePrefixes.some((prefix) => e.id.startsWith(prefix))) ?? null,
    firstWarn: news.find((e) => e.status === 'warn') ?? null,
    firstSkip: news.find((e) => e.status === 'skip'
      && e.params?.reason !== 'timeline_no_game_root_omission') ?? null,
  };
}

export function createReport() {
  const order = [];                 // 記録順の id 一覧
  const checks = new Map();         // id -> { status, params }
  const facts = new Map();          // name -> value

  function check(id, status, params = {}) {
    const error = facts.get('stageC.lockStateError') || facts.get('stageC.resultStateError');
    const dependent = error instanceof ArchiveUnavailableError && (LOCK_DEPENDENT_CHECKS.has(id)
      || (id === 'check.stageC.depositVerification' && facts.get('stageC.lockStateError')));
    // 独立した入力破損は FAIL のまま。比較結果と前提不足は params の外に保存する。
    const inputFailed = status === 'fail' && [
      'check.stageC.scoring', 'check.stageC.autoDistribute', 'check.stageC.depositTableShape', 'check.stageC.depositVerification',
    ].includes(id);
    const metadata = dependent && !inputFailed
      ? { reason: 'archive_unavailable', prerequisite: facts.get('stageC.lockStateError') ? 'K11_lock_state' : 'Evidence_state',
        ...(id === 'check.stageC.depositVerification' ? {}
          : ['check.stageC.summaryMatch', 'check.stageC.summaryByteExact', 'check.stageC.groupGameResultsMatch', 'check.stageC.autoResultPage'].includes(id)
            ? { comparisonStatus: status } : { calculationStatus: status }) } : {};
    if (dependent && !inputFailed) status = 'skip';
    if (!checks.has(id)) order.push(id);
    checks.set(id, { status, params, ...metadata });
  }

  function unverified(id, error, params = {}, metadata = {}) {
    if (!(error instanceof ArchiveUnavailableError)) throw error;
    check(id, 'skip', params);
    Object.assign(checks.get(id), metadata, { reason: 'archive_unavailable' });
  }

  function fact(name, value) {
    facts.set(name, value);
  }

  function get(id) {
    return checks.get(id) ?? null;
  }

  function getFact(name) {
    return facts.get(name);
  }

  function list() {
    return order.map((id) => ({ id, ...checks.get(id) }));
  }

  function hasFail() {
    return list().some((e) => e.status === 'fail');
  }

  // ------------------------------------------------------------
  // 最終まとめ:
  //   ① エントリー固定（フォルダ位置・登録時刻つき）
  //   ② 当選者＋グループ分け = ブロックXのRANDAO由来（運営裁量なし）
  //   ③ 署名付き提出からのルール準拠採点・merkle root 提出・請求期間
  // 途中終了時は「確認できたこと」と「まだ確認できないこと＋理由」を分けて表示。
  // ------------------------------------------------------------
  function renderSummary(ui, ctx) {
    const sep = '='.repeat(60);
    const t = ui.t;
    const st = (id) => checks.get(id)?.status ?? null;
    const f = (name) => facts.get(name);
    const anyFail = (prefix) =>
      list().some((e) => e.id.startsWith(prefix) && e.status === 'fail');
    // 下流の断定は、その段だけでなく前提となる上流検査とシステム配線にも依存する。
    // main.fatalは処理の中断。到達前に完了した検査へ失敗を伝播させない。
    const systemFailed = list().some((e) => e.status === 'fail' && e.id.startsWith('check.system.')
      && e.id !== 'check.system.productionParams');
    const stageAFailed = anyFail('check.stageA.');
    const stageBFailed = anyFail('check.stageB.');
    const stageCFailed = anyFail('check.stageC.');

    ui.println('');
    ui.println('');
    ui.println('');
    ui.println(sep);
    ui.println(t('summary.title', { block: ctx.blockNum }));
    const comparisons = list().filter((e) => e.comparisonStatus === 'fail');
    if (comparisons.length) ui.println(t('summary.comparisonMismatch', {
      checks: comparisons.map((e) => e.id).join(', '),
    }));
    ui.println(sep);
    ui.println('');
    ui.println(t('main.tzNotice', { tz: tzOffsetLabel() }));
    ui.println('');

    const summaryUrls = {
      blockUrl: `https://bitcoinu.org/block/?n=${ctx.blockNum}`,
      entriesUrl: `${(ctx.cfg?.r2Base ?? 'https://r2.bitcoinu.org').replace(/\/+$/, '')}/entries/block${ctx.blockNum}/`,
    };
    const coverage = verificationCoverage({ list, get, getFact });
    const covered = (area) => coverage.find((row) => row.area === area)?.verified === true;
    // 応募0件でも正典はnoGame成果物と標識rootまで確定するため、Stage B/Cの結論を表示する。
    const noEntries = f('totalEntries') === 0 && st('check.stageA.rootMatch') === 'pass';
    const stageCNoGame = f('stageC.noGame') === true;
    const timelineNoGame = f('stageC.timelineNoGame') === true;
    const noGame = stageCNoGame || ctx.data?.noGame === true;

    // ②の文の選択を共有し、領域行だけが②より強く断定しないようにする。
    function selectionConclusionMessage() {
      const gate = st('check.stageB.selectionPresent');
      const registrationEntry = checks.get('check.stageA.registrationCount');
      const repeatedRegistration = registrationEntry?.status === 'warn'
        && Number.isSafeInteger(Number(registrationEntry?.params?.count))
        && Number(registrationEntry.params.count) >= 2;
      const auto = ctx.data?.autoDistribute === true
        || st('check.stageB.groupingSkippedAuto') === 'skip';
      const unverified = (reason) => ({ key: 'notVerified.selection', reason });
      if (systemFailed || stageAFailed || stageBFailed
          || (stageCNoGame && stageCFailed)) return unverified('failed');
      if (gate === null) return unverified(noEntries ? 'noEntries' : 'stopped');
      if (gate === 'skip') return unverified('notReady');
      if (!covered('selection')) return unverified('stopped');
      if (timelineNoGame) return { key: 'conclusion.selectionTimelineNoGame' };
      if (noGame) return { key: 'conclusion.selectionNoGame' };
      if (auto) return { key: repeatedRegistration
        ? repeatedRegistrationMessageId('conclusion.selectionAutoRegistrationWarning', registrationEntry)
        : 'conclusion.selectionAuto' };
      if (st('check.stageB.groupsPresent') === 'skip') return { key: repeatedRegistration
        ? repeatedRegistrationMessageId('conclusion.selectionOnlyRegistrationWarning', registrationEntry)
        : 'conclusion.selectionOnly' };
      if (covered('grouping')) return { key: repeatedRegistration
        ? repeatedRegistrationMessageId('conclusion.selectionRegistrationWarning', registrationEntry)
        : 'conclusion.selection' };
      return unverified('stopped');
    }
    const selectionMessage = selectionConclusionMessage();
    function canGuarantee(area) {
      if (area === 'adminHistory' && getFact('system.audit')?.donateChecked !== true) return false;
      if (area === 'proofHistory' && st('check.stageC.zkVerifierIdentity') !== 'pass') return false;
      // createR2 と同じ取得元の分岐。手元の写しでは公開URLについて断定しない。
      // 再反証 G-1b: 公式以外の取得元（--source-base・別の r2Base）でも公式の頁について断定しない。
      const officialR2 = String(ctx.cfg?.r2Base ?? 'https://r2.bitcoinu.org').replace(/\/+$/, '') === 'https://r2.bitcoinu.org';
      const publicR2 = !ctx.cfg?.artifactDir && !ctx.cfg?.emergencySource && !ctx.cfg?.sourceBase && officialR2;
      if (!publicR2 && ['entries', 'selection', 'grouping', 'resultFiles', 'scoring', 'publicMerkle'].includes(area)) return false;
      const { matches, required } = VERIFICATION_AREAS.find((row) => row.area === area);
      if (list().some((entry) => matches.test(entry.id) && entry.status !== 'pass')) return false;
      if (!required.every((id) => st(id) === 'pass')) return false;
      if (area === 'entries' && st('check.stageB.playersMatch') !== 'pass') return false;
      // Lean N12-a: 記録の順序に頼らず、root の提出の規則の合格を保証の文の条件にする。
      if (area === 'timeline' && st('check.stageC.rootSubmissionRules') !== 'pass') return false;
      if (['selection', 'grouping'].includes(area) && selectionMessage.key !== 'conclusion.selection') return false;
      return true;
    }
    for (const verified of [true, false]) {
      ui.println(t(verified ? 'summary.coverageVerified' : 'summary.coverageUnverified'));
      const rows = coverage.filter((row) => !row.notApplicable && row.verified === verified);
      if (rows.length === 0) ui.println(`  ${t('summary.coverageNone')}`);
      for (const row of rows) ui.println(`  ${t(`summary.area.${row.area}`)}: ${t(
        verified ? (canGuarantee(row.area) ? `summary.guarantee.${row.area}` : 'summary.areaVerified') : 'summary.areaUnverified',
        verified ? summaryUrls : { reason: t(`reason.${row.reason}`) },
      )}`);
      ui.println('');
    }
    const notApplicable = coverage.filter((row) => row.notApplicable);
    if (notApplicable.length > 0) {
      ui.println(t('summary.coverageNotApplicable'));
      for (const row of notApplicable) ui.println(`  ${t(`summary.area.${row.area}`)}: ${t('summary.areaNotApplicable')}`);
      ui.println('');
    }
    const unrun = CHECK_INVENTORY.filter((id) => !checks.has(id));
    const counts = { pass: 0, warn: 0, fail: 0, skip: 0, unrun: unrun.length };
    for (const e of list()) if (counts[e.status] != null) counts[e.status]++;
    ui.println(t('summary.counts', counts));

    // --- FAIL と通知すべき WARN だけを詳細表示（検査レコード・件数はそのまま） ---
    const fails = list().filter((e) => e.status === 'fail');
    const warns = list().filter((e) => e.status === 'warn' && e.reason !== 'archive_unavailable');
    // 語ごとの確認範囲・未検証理由・食い違いを300字の切り詰めで消さない。
    const proofWordDetailLimit = (e) => e.id === 'check.stageC.zkPublicValues'
      && Array.isArray(e.params?.verifiedWords) ? Infinity : 300;
    if (fails.length > 0) {
      ui.println('');
      ui.println(t('summary.failsHeader'));
      for (const e of fails) {
        const params = displayParams(e.params, t);
        ui.println(`  ✗ ${t(messageId(e), params)}${paramsSuffix(params, proofWordDetailLimit(e), ui.redactText)}`);
      }
    }
    if (warns.length > 0) {
      ui.println('');
      ui.println(t('summary.warnsHeader'));
      for (const e of warns) {
        // applicantHash の再登録警告は全履歴の一覧そのものが監査材料なので省略しない。
        const detailLimit = e.id === 'check.stageA.registrationCount' ? Infinity : 300;
        const params = displayParams(e.params, t);
        ui.println(`  ⚠ ${t(messageId(e), params)}${paramsSuffix(params, detailLimit, ui.redactText)}`);
      }
    }

    // --- Stage C が翻訳済み文字列として蓄積したアノマリー ---
    const anomalies = f('stageC.anomalies');
    if (Array.isArray(anomalies) && anomalies.length > 0) {
      ui.println('');
      ui.println(t('summary.anomaliesHeader'));
      for (const a of anomalies) ui.println(`  ! ${a}`);
    }

    const conclusions = [];
    const pending = [];

    // ── ⓪ ZKP の有無とチェーン上の値への結び付き ──────
    // 冒頭で取得した状態を優先し、配布のない root 省略の終端では表示しない。
    if (!(timelineNoGame && f('stageC.timelineNoGameRoot')?.state === 'omitted_terminal')) {
      const kind = ctx.data?.zkInfo == null
        ? checks.get('check.stageC.zkProofStatus')?.params?.kind : ctx.data.zkInfo.kind;
      const zkPending = (reason) => pending.push(t('notVerified.zk', { reason: t(`reason.${reason}`) }));
      if (kind == null) {
        zkPending('stopped');
      } else if (systemFailed) {
        zkPending('failed');
      } else if (kind === 'unavailable') {
        zkPending('failed');
      } else if (kind === 'no_root') {
        zkPending('notReady');
      } else if (kind === 'shadow') {
        conclusions.push(t('conclusion.zkShadow', { block: ctx.blockNum }));
      } else if (kind === 'proof') {
        // 証人の通常の skip は履歴の保証文を抑えるが、⓪には verified だけを求める。
        if (st('check.stageC.zkVerifierIdentity') === 'fail') {
          pending.push(t('notVerified.zkVerifier'));
        } else if (st('check.stageC.merkleRoot') === 'fail'
            || st('check.stageC.evidenceReportMatch') === 'fail') {
          if (covered('proofPublicValues') && canGuarantee('proofPublicValues')) {
            pending.push(t('notVerified.zkRootMismatch'));
          } else {
            pending.push(t('notVerified.zkProof', { reason: t(
              st('check.stageC.futureAnchorsHash') === 'fail'
                ? 'reason.proofRootProviderMismatch' : 'reason.proofRootMismatch',
              { provider: ctx.data?.futureAnchorCheck?.provider ?? 'unavailable' },
            ) }));
          }
        } else if (covered('proofPublicValues') && canGuarantee('proofPublicValues') && covered('proofHistory')) {
          conclusions.push(t('conclusion.zkProof', { block: ctx.blockNum }));
        } else {
          const publicValues = coverage.find((row) => row.area === 'proofPublicValues');
          const history = coverage.find((row) => row.area === 'proofHistory');
          const reason = !publicValues.verified ? publicValues.reason
            : !canGuarantee('proofPublicValues') ? 'failed' : history.reason;
          const key = publicValues.verified && canGuarantee('proofPublicValues')
            ? 'notVerified.zkProofHistory' : 'notVerified.zkProof';
          pending.push(t(key, { reason: t(`reason.${reason}`) }));
        }
      } else {
        zkPending('failed');
      }
    }

    // ── ① エントリー固定 ─────────────────────────────
    {
      const gate = st('check.stageA.applicantHashRegistered');
      if (gate === null) {
        pending.push(t('notVerified.entries', { reason: t('reason.stopped') }));
      } else if (gate === 'skip') {
        pending.push(t('notVerified.entries', { reason: t('reason.notReady') }));
      } else if (st('check.stageA.infoComplete') === 'skip') {
        // 応募データがまだ公開/集計されていない（100個すべて欠落）= 未完了ゲート
        pending.push(t('notVerified.entries', { reason: t('reason.notReady') }));
      } else if (systemFailed || anyFail('check.stageA.')) {
        pending.push(t('notVerified.entries', { reason: t('reason.failed') }));
      } else if (st('check.stageA.rootMatch') !== 'pass' || st('check.stageA.earlyFreeze') !== 'pass') {
        pending.push(t('notVerified.entries', { reason: t('reason.stopped') }));
      } else if (covered('entries')) {
        conclusions.push(t('conclusion.entries', {
          block: ctx.blockNum,
          time: f('hashRegisteredTime'),
          total: f('totalEntries'),
          hash: f('applicantHash'),
          ethBlock: f('hashRegisteredBlock'),
          folder: ctx.r2?.baseDir ?? '-',
        }));
      }
    }

    // ── ② 抽選＋グループ分け ─────────────────────────
    {
      const params = {
        block: ctx.blockNum,
        selected: f('totalSelected'),
        total: f('totalEntries'),
        targetBlock: f('targetBlockNum'),
        time: f('targetBlockTime'),
        groups: f('totalGroups'),
        count: checks.get('check.stageA.registrationCount')?.params?.count ?? '-',
      };
      if (selectionMessage.reason) {
        pending.push(t(selectionMessage.key, { reason: t(`reason.${selectionMessage.reason}`) }));
      } else {
        conclusions.push(t(selectionMessage.key, params));
      }
    }

    // ── ③ 採点・報酬・オンチェーン確定 ────────────────
    {
      const gate = st('check.stageC.rootSubmitted');
      const auto = f('stageC.autoDistributed') === true;
      const params = {
        block: ctx.blockNum,
        reward: weiToBtcu(f('stageC.blockReward')),
        players: f('stageC.playerCount'),
        groups: f('stageC.groupCount'),
        dq: f('stageC.disqualifiedCount'),
        rootTime: f('stageC.verificationStartedAt')?.iso,
        verEnd: f('stageC.verificationEndsAt')?.iso,
        claimEnd: f('stageC.claimWindow')?.endIso,
        rootDeadline: Number.isSafeInteger(Number(f('stageC.timelineNoGameRoot')?.rootSubmissionDeadlineSec))
          ? new Date(Number(f('stageC.timelineNoGameRoot').rootSubmissionDeadlineSec) * 1000).toISOString()
          : '-',
      };
      const stageCFails = list().filter((e) => e.id.startsWith('check.stageC.') && e.status === 'fail');
      const onlyStageCFail = (id) => stageCFails.length === 1 && stageCFails[0].id === id;
      const commitmentWarnings = [
        'check.stageC.manifestAnchor',
        'check.stageC.resultReregistration',
        'check.stageC.manifestFiles',
      ].filter((id) => st(id) === 'warn');
      if (f('stageC.lockStateUnchecked') || f('stageC.resultStateError')
          || list().some((e) => e.id.startsWith('check.stageC.') && e.status === 'skip'
            && e.reason === 'archive_unavailable')) {
        pending.push(t('notVerified.results', { reason: t('reason.archiveUnavailable') }));
      } else if (systemFailed || stageAFailed || stageBFailed) {
        pending.push(t('notVerified.results', { reason: t('reason.failed') }));
      } else if (gate === null) {
        pending.push(t('notVerified.results', { reason: t(noEntries ? 'reason.noEntries' : 'reason.stopped') }));
      } else if (gate === 'skip') {
        pending.push(t('notVerified.results', { reason: t('reason.notReady') }));
      } else if (onlyStageCFail('check.stageC.rosterLiveAnchor')) {
        // E5-03: rosterだけのFAILを汎用文へ潰さず、何を確認できなかったかを明示する。
        pending.push(t('notVerified.results', { reason: t('reason.rosterAnchorFailed') }));
      } else if (onlyStageCFail('check.stageC.rosterCommitment')) {
        pending.push(t('notVerified.results', { reason: t('reason.rosterCommitmentFailed') }));
      } else if (onlyStageCFail('check.stageC.manifestAnchor')) {
        pending.push(t('notVerified.results', { reason: t('reason.manifestAnchorFailed') }));
      } else if (ctx.data?.zkInfo?.kind === 'proof'
          && (st('check.stageC.merkleRoot') === 'fail'
            || st('check.stageC.evidenceReportMatch') === 'fail')) {
        pending.push(t('notVerified.results', { reason: t(
          st('check.stageC.futureAnchorsHash') === 'fail'
            ? 'reason.proofRootProviderMismatch' : 'reason.proofRootMismatch',
          { provider: ctx.data?.futureAnchorCheck?.provider ?? 'unavailable' },
        ) }));
      } else if (anyFail('check.stageC.')) {
        pending.push(t('notVerified.results', { reason: t('reason.failed') }));
      } else if (st('check.main.fatal') !== null && !covered('timeline')) {
        pending.push(t('notVerified.results', { reason: t('reason.stopped') }));
      } else if (timelineNoGame
          && f('stageC.timelineNoGameRoot')?.state === 'omitted_terminal') {
        conclusions.push(t('conclusion.resultsTimelineNoGameRootOmitted', params));
      } else if (!covered('scoring') || !covered('publicMerkle')) {
        pending.push(t('notVerified.results', { reason: t('reason.stopped') }));
      } else if (st('check.stageC.onchainClaimData') !== 'pass') {
        // 請求データ自己完結化（2026-08-01）: root が出ている以上、契約 submitMerkleRoot が
        // 「請求データ全チャンク受領」を require しているので、請求データは**必ず存在する**。
        // したがって pass 以外（skip 含む）は「保険が検査できていない」ことを意味する。
        // 旧実装は skip を fail 扱いにしなかったため、請求データ検証が無検査のまま
        // 「検証OK」と表示される経路があった。
        pending.push(t('notVerified.results', { reason: t('reason.claimDataUnchecked') }));
      } else if (commitmentWarnings.length > 0) {
        // E11-01/E11-03: 配信欠落・未/再アンカーを個別WARNとして表示するだけで
        // 「検証OK」の結論へ落とすと、時点コミットメント未成立を利用者が見落とす。
        pending.push(t('notVerified.results', {
          reason: t('reason.resultCommitmentWarning', { checks: commitmentWarnings.join(', ') }),
        }));
      } else {
        const key = timelineNoGame ? 'conclusion.resultsTimelineNoGame'
          : (noGame ? 'conclusion.resultsNoGame'
          : (auto ? 'conclusion.resultsAuto'
            : (st('check.stageC.rosterLiveAnchor') === 'warn'
              ? 'conclusion.resultsRosterAnchorWarning'
              : 'conclusion.results')));
        conclusions.push(t(key, params));
      }
    }

    if (conclusions.length > 0) {
      ui.println('');
      ui.println(t('summary.conclusionsHeader'));
      for (const c of conclusions) {
        ui.println('');
        ui.println(`  ${c}`);
      }
    }
    if (pending.length > 0) {
      ui.println('');
      ui.println(t('summary.notVerifiedHeader'));
      for (const p of pending) ui.println(`  ${p}`);
    }
    ui.println('');
    ui.println(t('summary.folder', { path: ctx.r2?.baseDir ?? '-' }));
    ui.println(sep);
  }

  return { check, unverified, fact, get, getFact, list, hasFail, renderSummary };
}

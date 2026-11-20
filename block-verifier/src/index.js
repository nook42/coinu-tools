#!/usr/bin/env node
// block-verifier/src/index.js
// 対話メインループ（DESIGN §2）: 言語選択 → RPC選択（保存・chainId確認）→
// ブロック番号 → block{N}/ 再利用確認 → Stage A/B/C 実行 → まとめ → ループ。
// 非対話モード: --lang --rpc --block --reuse --yes --config。1パスで終了。
// 終了コード（G4）: 0 = Stage C まで自然完走し FAIL 無し / 1 = FAIL 無しだが前提未検証、または正当な
// 未完了ゲートで停止（not-ready）/ 2 = FAIL あり / 3 = fatal（例外・設定エラー）/
// 64 = usage エラー。非対話モードでは最終まとめの後に機械可読行
// 「##CHECK <id> <status>」と「##RESULT full|partial|fail|fatal|emergency_with_differences」を stdout に出す。

import fs from 'node:fs';
import { configRpcUrls, displayRpcUrl, INVALID_RPC_URL, redactRpcText } from './rpc-privacy.js';
import { fileURLToPath } from 'node:url';
import {
  emergencyApplicantSelectionUsageError, loadConfig, parseArgv, saveConfig,
} from './config.js';
import { createChain } from './chain.js';
import { conciseRpcText, ArchiveUnavailableError } from './archive.js';
import { createLocalR2, createR2 } from './r2.js';
import { createPrompts } from './prompts.js';
import { createReport, displayParams, messageId, stageVerdictIssues } from './report.js';
import { t as makeTranslator, SUPPORTED_LANGS } from './i18n.js';
import { tzOffsetLabel } from './json-utils.js';
import { publicnodeExplanation } from './verification-areas.js';
import { parseEntryUid, runEntriesReusable, runSelectionReusable, verifyOwnEntry } from './entry-membership.js';
import { run as runGrouping } from './stages/grouping.js';
import { run as runResults } from './stages/results.js';
import { inspectBlockZkpState } from './zkp.js';
import { visibleTerminalText } from './wiring-vkeys.js';
import { auditFutureAnchorProviders } from './future-anchor.js';
import { applyVerifiedTokenDisplay } from './token-display.js';
import {
  resolveEmergencyGenerationMap, selectEmergencyServerSubmissions, writeEmergencyResultSet,
} from './emergency.js';

const SEP = '='.repeat(60);
// 最上位 fatal でも、現在の実行で与えられたRPCだけを伏せる。対話での追加も同じ参照。
let activeRpcConfig = {};

const USAGE = `COINU independent block verifier
usage: bitcoinu-verify [options]
  --lang en|ja|zh      UI language (skips the language prompt)
  --rpc URL            Ethereum RPC URL (repeatable; skips the RPC prompt)
  --block N            COINU block number to verify (required in non-interactive mode)
  --reuse              reuse previously downloaded files in data/block{N}/
                       (without it, non-interactive mode always downloads fresh)
  --yes                assume default answers (implies non-interactive)
  --non-interactive    never prompt; prints machine-readable ##CHECK / ##RESULT lines
  --config FILE        JSON overrides (contracts / r2Base / dataDir / chainIdExpected / rpcUrls / pins)
  --source-base URL    download the public artifacts from this base URL instead of the built-in one.
                       It changes ONLY the download location: contract addresses, chain ID, pins and
                       every on-chain cross-check stay exactly as built in, so nothing gets weaker.
                       Trailing slashes are ignored. It wins over r2Base from --config, and it cannot
                       be combined with --artifact-dir or --emergency-source (usage error, exit 64):
                       those two read local files only, so a source URL would silently do nothing.
                       (--artifact-dir and --emergency-source together keep their existing behaviour:
                       the emergency source wins.)
  --artifact-dir DIR   read every public artifact from this fixed local directory; never contact R2
  --observer-source DIR  optional materialize-block archive with all saved generations; Stage B reads
                       it only when the current previous-block result cannot reproduce the actual groups
  --emergency-source DIR  observer block archive; recompute emergency results from all saved generations
  --emergency-out DIR     write the verified emergency result set here (requires --emergency-source)
  --emergency-authority=gcp  explicitly reconstruct a group game without result manifest authority
  --emergency-applicant-registration INDEX
                       select one eligible, reproducible applicantHash history index (emergency only)
  --emergency-applicant-root HASH
                       select one eligible, reproducible applicantHash root (emergency only)
  --proof              OFFLINE mode: rebuild proofs from the summary.json already in
                       data/block{N}/ and print what claim() needs. No network access.
                       Works even if the operator's servers are gone. Requires --block.
  --key KEY            with --proof: the claim key (substring match is allowed)
  --help               show this help
exit codes:
  0   completed through Stage C with no FAIL
  1   no FAIL, but prerequisites are unverified or a legitimate not-ready gate stopped the run
  2   one or more checks FAILED
  3   fatal error (stage exception / configuration error)
  4   emergency result set written with material differences
  64  usage error (missing/invalid --block etc.)`;

// ---------------------------------------------------------------
// ui オブジェクト（CONTRACT: t / println / warn / askYesNo / askChoice / askInput / isInteractive）
// ---------------------------------------------------------------
export function makeUi(translate, prompts, cfg = {}) {
  const safe = (value) => redactRpcText(value, configRpcUrls(cfg));
  return {
    t: translate,
    redactText: safe,
    println: (s = '') => process.stdout.write(safe(s) + '\n'),
    // 動作の文脈が変わる所の区切り（空行・--------・空行）。対話のときだけ出す（機械可読の出力は変えない）。
    section: (title = '') => {
      if (cfg.nonInteractive) return;
      process.stdout.write('\n--------\n\n');
      if (title) process.stdout.write(`【${safe(title)}】\n`);
    },
    warn: (s = '') => process.stderr.write(`⚠ ${safe(s)}\n`),
    askYesNo: (key, params = {}, opts = {}) =>
      prompts.yesNo(translate(key, params), { defaultValue: opts.defaultValue ?? true }),
    askChoice: (key, items, opts = {}) =>
      prompts.choice(translate(key, opts.params ?? {}), items, opts),
    askInput: (key, opts = {}) =>
      prompts.text(translate(key, opts.params ?? {}), opts),
    isInteractive: prompts.isInteractive,
  };
}

// ---------------------------------------------------------------
// 1. 言語選択（--lang があればスキップ。保存済み言語は既定値として提示）
//    言語決定前なので選択プロンプト自体は3言語併記のリテラル。
// ---------------------------------------------------------------
async function selectLanguage(cfg, prompts) {
  const flagLang = cfg.flags?.lang;
  if (flagLang) return SUPPORTED_LANGS.includes(flagLang) ? flagLang : 'en';
  const saved = SUPPORTED_LANGS.includes(cfg.lang) ? cfg.lang : null;
  if (cfg.nonInteractive) return saved || 'en';
  const items = ['English', '日本語', '中文'];
  const defaultIndex = saved ? SUPPORTED_LANGS.indexOf(saved) : 0;
  process.stdout.write('【Language / 言語選択 / 语言】\n');
  const idx = await prompts.choice(
    'Select your language / 言語を選択してください / 请选择语言:',
    items,
    { defaultIndex },
  );
  return SUPPORTED_LANGS[idx];
}

// ---------------------------------------------------------------
// 2. RPC選択＋接続テスト（chainId を cfg.chainIdExpected と照合）
// ---------------------------------------------------------------
export async function tryConnect(cfg, ui, urls) {
  cfg.rpcUrls = urls;
  const chain = createChain(cfg, ui);
  ui.println(ui.t('main.rpcConnecting', { url: urls.map(displayRpcUrl).join(', ') }));
  try {
    const id = await chain.chainId();
    if (id !== cfg.chainIdExpected) {
      ui.warn(ui.t('main.rpcChainMismatch', { actual: id, expected: cfg.chainIdExpected }));
      return null;
    }
    ui.println(ui.t('main.rpcConnected', { chainId: id }));
    for (const url of urls) {
      const node = urls.length === 1 ? chain : createChain({ ...cfg, rpcUrls: [url] }, ui);
      await node.probeArchive();
    }
    return chain;
  } catch (e) {
    // URLとして読めない候補の文だけを伏せる。有効な候補のHTTPエラーは残す。
    const invalid = urls.filter((url) => displayRpcUrl(url) === INVALID_RPC_URL);
    let error = e?.message || String(e);
    const invalidFailure = invalid.length > 0 && (invalid.length === urls.length || invalid.some((url) => e?.url === url
      || (typeof e?.walk === 'function' && e.walk((cause) => cause?.url === url))));
    if (invalidFailure) error = INVALID_RPC_URL;
    ui.warn(ui.t('main.rpcConnectFailed', { error: conciseRpcText(error, ui.t) }));
    return null;
  }
}

export function providerRpcUrl(provider, key) {
  const base = provider === 'alchemy' ? 'https://eth-mainnet.g.alchemy.com/v2/'
    : provider === 'infura' ? 'https://mainnet.infura.io/v3/' : null;
  if (!base || !key.trim()) throw new Error('invalid RPC provider/key');
  return base + encodeURIComponent(key.trim());
}

export async function setupChain(cfg, ui, prompts, connect = tryConnect) {
  const fromFlag = (cfg.flags?.rpc?.length ?? 0) > 0;
  const preset = Array.isArray(cfg.rpcUrls) && cfg.rpcUrls.length > 0;
  if (preset || cfg.nonInteractive) {
    ui.section?.(ui.t('main.sectionNode'));
    const chain = await connect(cfg, ui, preset ? cfg.rpcUrls : cfg.rpcPresets.map((p) => p.url));
    if (chain) return chain;
    if (cfg.nonInteractive || fromFlag) process.exit(3);
  }
  for (;;) {
    ui.section(ui.t('main.sectionNode'));
    const idx = await prompts.choice(ui.t('main.rpcPrompt'), [
      ui.t('main.rpcPublicnode'), ui.t('main.rpcAlchemy'), ui.t('main.rpcInfura'), ui.t('main.rpcCustomOption'),
    ], { defaultIndex: 0 });
    let url;
    if (idx === 0) {
      ui.section(ui.t('main.publicnodeTitle'));
      for (const line of publicnodeExplanation(ui.t)) ui.println(line);
      const next = await prompts.choice(ui.t('main.publicnodePrompt'), [
        ui.t('main.publicnodeContinue'), ui.t('main.publicnodeReselect'),
      ], { defaultIndex: 0 });
      if (next === 1) continue;
      url = cfg.rpcPresets[0].url;
    } else if (idx === 1 || idx === 2) {
      ui.section(ui.t('main.sectionApiKey'));
      const key = await prompts.text(ui.t('main.rpcApiKey', { provider: idx === 1 ? 'Alchemy' : 'Infura' }), { secret: true });
      if (!key.trim()) continue;
      url = providerRpcUrl(idx === 1 ? 'alchemy' : 'infura', key);
    } else {
      ui.section(ui.t('main.sectionCustomRpc'));
      // 保存済みの独自URLも、伏せた表示から選べる。最初の一覧は常に4択。
      const saved = cfg.customRpcs || [];
      if (saved.length) {
        const pick = await prompts.choice(ui.t('main.rpcCustomPrompt'), [
          ...saved.map(displayRpcUrl), ui.t('main.rpcCustomOption'),
        ], { defaultIndex: saved.length });
        if (pick < saved.length) url = saved[pick];
      }
      if (!url) url = (await prompts.text(ui.t('main.rpcCustomUrl'), { secret: true })).trim();
      if (!url) continue;
      if (!saved.includes(url)) {
        cfg.customRpcs = [...saved, url];
        const savedPath = saveConfig({ customRpcs: cfg.customRpcs }, cfg.savedConfigPath);
        ui.println(ui.t('main.rpcCustomSaved', { path: savedPath }));
      }
    }
    const chain = await connect(cfg, ui, [url]);
    if (chain) return chain;
  }
}

// ---------------------------------------------------------------
// 3-5. 1ブロック分の検証パス: 再利用確認 → ステージ実行（{stop} 尊重）→ まとめ
// ---------------------------------------------------------------
export async function verifyOneBlock(cfg, chain, ui, blockNum, { entrySessions = null } = {}) {
  const report = createReport();
  let emergencySource = null;
  if (cfg.emergencySource) {
    emergencySource = await resolveEmergencyGenerationMap({
      sourceDir: cfg.emergencySource, chain, blockNum,
      applicantRegistrationIndex: cfg.emergencyApplicantRegistration === null
        ? null : Number(cfg.emergencyApplicantRegistration),
      applicantRoot: cfg.emergencyApplicantRoot,
      authority: cfg.emergencyAuthority,
      pins: cfg.pins,
    });
    emergencySource.sourceDir = cfg.emergencySource;
  }
  const r2 = emergencySource
    ? createLocalR2(cfg, ui, blockNum, { rootDir: cfg.emergencySource, fileMap: emergencySource.fileMap })
    : cfg.artifactDir
      ? createLocalR2(cfg, ui, blockNum, { rootDir: cfg.artifactDir })
      : createR2(cfg, ui, blockNum);
  if (emergencySource?.authority === 'gcp') {
    const fetchJson = r2.fetchJson.bind(r2);
    r2.fetchJson = async (key, options) => {
      if (key === `verification/block${blockNum}/manifest.json`) {
        return { data: emergencySource.selectedManifest, raw: JSON.stringify(emergencySource.selectedManifest) };
      }
      if (key === `games/block${blockNum}/summary.json` && emergencySource.syntheticSummary) {
        return { data: emergencySource.syntheticSummary,
          raw: JSON.stringify(emergencySource.syntheticSummary) };
      }
      return fetchJson(key, options);
    };
  }
  // T3: 取得先を差し替えて走ったことを、i18n に依存しない1行として出しておく
  //（事故告知どおりの場所を読んだことを、第三者が出力だけで示せるようにする）。
  if (cfg.sourceBase) {
    report.fact('sourceBase', cfg.sourceBase);
    ui.println(`##SOURCE_BASE ${cfg.sourceBase}`);
  }

  // block{N}/ フォルダ再利用確認。
  // G13: 非対話モードでは --reuse 明示時のみ再利用（無指定はフレッシュダウンロード・プロンプトしない）。
  let reuse = false;
  if (fs.existsSync(r2.baseDir)) {
    if (cfg.nonInteractive) {
      reuse = !!cfg.reuse;
    } else {
      reuse = cfg.reuse ? true : await ui.askYesNo('main.folderReuse', { path: r2.baseDir });
    }
  }
  r2.setDefaultReuse(reuse);

  // ctx（CONTRACT どおり）
  const ctx = {
    cfg, chain, r2, ui, report, blockNum,
    data: { reuseFiles: reuse, ...(emergencySource ? { emergencySource } : {}) },
  };
  if (emergencySource?.applicantRegistration) {
    report.fact('emergencyApplicantRegistration', emergencySource.applicantRegistration);
  }
  // 周29 (c)（2026-09-22）: 前ブロックの結果目印が HashStorage の追記履歴のどの行だったかを残す。
  // 選び方（現在値）は変えていない。何を選んだかを見えるようにするだけ。
  if (emergencySource?.previousResultRegistration) {
    report.fact('emergencyPreviousResultRegistration', emergencySource.previousResultRegistration);
  }

  ui.println('');
  ui.println(SEP);
  ui.println(ui.t('main.runningBlock', { block: blockNum }));
  ui.println(SEP);

  // 時刻表示のタイムゾーン注記（displayTime はマシンのローカル時刻で表示する。
  // 後続の空白行はステージループ側が出す）
  ui.println('');
  ui.println(ui.t('main.tzNotice', { tz: tzOffsetLabel() }));

  // R26 決定0/8: 構築時の配線を第三者として逆参照し、権限変更は採点FAILと
  // 混同せず目立つWARN/factとして告知する。
  if (typeof chain.systemAudit === 'function') {
    try {
      const audit = await chain.systemAudit();
      applyVerifiedTokenDisplay(ui.t, audit.wiring.token);
      const wiringChecks = [
        ['check.system.evidenceWiring', audit.wiring.evidence],
        ['check.system.evidenceHashStorage', audit.wiring.evidenceHashStorage],
        ['check.system.evidenceSenderLimit', audit.wiring.evidenceSenderLimit],
        ['check.system.evidenceEntryRemoved', audit.wiring.evidenceEntryRemoved],
        ['check.system.evidenceEntryAccZero', audit.wiring.evidenceEntryAccZero],
        ['check.system.evidenceStartPastTolerance', audit.wiring.evidenceStartPastTolerance],
        ['check.system.ethLockWiring', audit.wiring.ethLock],
        ['check.system.ethStakeTiming', audit.wiring.ethStakeTiming],
        ['check.system.ethStakeAddress', audit.wiring.ethStake],
        ['check.system.maxBlockNum', audit.wiring.maxBlockNum],
        ['check.system.hashStorageWiring', audit.wiring.hashStorage],
        ['check.system.authoritySeparation', audit.wiring.authoritySeparation],
        ['check.system.tokenSupply', audit.wiring.token],
      ];
      for (const [id, result] of wiringChecks) {
        report.check(id, result.ok ? 'pass' : 'fail', result);
      }
      if (audit.production.applicable) {
        report.check('check.system.productionParams', audit.production.ok ? 'pass' : 'fail', audit.production);
      }
      report.fact('system.audit', audit);
      ui.println(ui.t('fact.system.tokenMiningBalance', {
        balance: audit.wiring.token.tokenMiningBalance,
        totalSupply: audit.wiring.token.totalSupply,
      }));
      if (audit.pendingSuperAdmin.length) {
        report.check('fact.system.pendingSuperAdmin', 'warn', {
          proposals: audit.pendingSuperAdmin.map((p) =>
            `${p.contract}: ${p.to} / ETA ${p.eta}`).join('; '),
        });
      }
      if (audit.ethStakeSwitch.announced) {
        report.check('fact.system.ethStakeFromBlockSet', 'warn', audit.ethStakeSwitch);
      }
      if (audit.pendingVkey.pending) {
        report.check('fact.system.pendingVkey', 'warn', audit.pendingVkey);
      }
      if (audit.adminChanges.length) {
        report.check('fact.system.adminRotation', 'warn', {
          authorities: audit.adminChanges.map((item) =>
            `${item.contract}: ${item.oldAdmin} -> ${item.newAdmin} @ block ${item.blockNumber}`).join('; '),
        });
      }
      if (audit.superAdminChanges.length) {
        report.check('fact.system.superAdminRotation', 'warn', {
          authorities: audit.superAdminChanges.map((item) =>
            `${item.contract}: ${item.oldSuperAdmin} -> ${item.newSuperAdmin} @ block ${item.blockNumber}`).join('; '),
        });
      }
      if (audit.adminChangeError) {
        if (audit.adminChangeArchiveErrors?.length) {
          report.unverified('fact.system.adminRotationUnavailable', audit.adminChangeArchiveErrors[0],
            { error: audit.adminChangeError }, { status: 'warn' });
        } else report.check('fact.system.adminRotationUnavailable', 'warn', { error: audit.adminChangeError });
      }
      if (audit.donateChanges.length) {
        const last = audit.donateChanges[audit.donateChanges.length - 1];
        report.check('fact.system.donateSuperAdminChanges', 'warn', {
          count: audit.donateChanges.length,
          last: `${last.oldSuperAdmin} -> ${last.newSuperAdmin} @ block ${last.blockNumber}`,
        });
      }
      if (audit.donateAdminChanges.length) {
        const last = audit.donateAdminChanges[audit.donateAdminChanges.length - 1];
        report.check('fact.system.donateAdminChanges', 'warn', {
          count: audit.donateAdminChanges.length,
          last: `${last.oldAdmin} -> ${last.newAdmin} @ block ${last.blockNumber}`,
        });
      }
      if (audit.donateEventError) {
        if (audit.donateEventArchiveError instanceof ArchiveUnavailableError) {
          report.unverified('fact.system.donateEventUnavailable', audit.donateEventArchiveError,
            { error: audit.donateEventError }, { status: 'warn' });
        } else report.check('fact.system.donateEventUnavailable', 'warn', { error: audit.donateEventError });
      }
    } catch (e) {
      report.check('check.system.auditUnavailable', 'fail', { error: e?.message || String(e) });
    }
  }

  if (chain.client?.getBlockNumber && chain.client?.readContract && chain.client?.getCode) {
    try {
      const anchors = await auditFutureAnchorProviders(chain);
      if (anchors.current.status === 'unwired') {
        report.check('fact.system.futureAnchorUnwired', 'warn', anchors.current);
      }
      if (anchors.pending) {
        report.check('fact.system.pendingAnchorProvider', anchors.pending.status === 'fail' ? 'fail'
          : anchors.pending.status === 'unwired' ? 'warn' : 'pass', anchors.pending);
      }
      report.check('check.system.futureAnchorProvider',
        anchors.current.status === 'fail' || anchors.pending?.status === 'fail' ? 'fail'
          : anchors.current.status === 'unwired' ? 'skip' : 'pass',
      { current: anchors.current.status, pending: anchors.pending?.status ?? 'none', details: anchors });
    } catch (error) {
      report.check('check.system.futureAnchorProvider', 'fail', { error: String(error.message || error) });
    }
  } else {
    report.check('check.system.futureAnchorProvider', 'skip', { reason: 'provider_audit_client_unavailable' });
  }

  // ⓪ 参考情報: このブロックの root は ZKP 付きで提出されたか（shadow 期間なら証明なし）。
  //    検証そのものではなく**前提の提示**。証明なしなら「正しさはこの再実行検証だけに
  //    依拠する」ことを先に伝えておく必要がある。
  //    取得不能を shadow と混同しない。Stage C でも同じ結果を検査項目として使う。
  ui.println('');
  const zkInfo = await inspectBlockZkpState(chain, blockNum);
  ctx.data.zkInfo = zkInfo;
  const required = zkInfo.currentProofRequired == null
    ? ui.t('zk.currentRequirementUnknown')
    : (zkInfo.currentProofRequired ? ui.t('zk.enforcementOn') : ui.t('zk.enforcementOff'));
  if (zkInfo.kind === 'no_root') {
    ui.println(ui.t('zk.blockZkNoRoot', { required }));
  } else if (zkInfo.kind === 'proof') {
    ui.println(ui.t('zk.blockZkProof', {
      i: zkInfo.epoch.index,
      verifier: zkInfo.epoch.verifier,
      vkey: zkInfo.epoch.vkey,
      source: zkInfo.epoch.guestSourceHash,
      required,
    }));
  } else if (zkInfo.kind === 'shadow') {
    ui.println(ui.t('zk.blockZkNone', { required }));
  } else {
    ui.warn(ui.t('zk.blockZkUnavailable', { error: conciseRpcText(zkInfo.error, ui.t), required }));
    report.check('check.stageC.zkProofStatus', 'fail', {
      kind: zkInfo.kind,
      epoch: null,
      currentProofRequired: zkInfo.currentProofRequired,
      error: zkInfo.error || 'ZKP state unavailable',
    });
  }

  // entries → (selection+grouping = Stage B 一括) → results。
  // autoDistribute は grouping が自らスキップし、results が自動配布経路を検証する。
  // 各ステージは正当な未完了ゲート停止時に ctx.data.stopReason='not_ready'、
  // FAIL 起因の停止時に 'fail' を設定する（G4 の終了コード判定に使う）。
  // 表示: 最初のステージの前に空行1行・ステージの切り替わりは空行2行、終了時に ✅/❌/⚠ の検証結果行を出す。
  // Stage B は抽選→グループ分けを1ステージとして実行し、抽選の検証にFAILが出た時点で
  // グループ分けへ進まず停止する（結果はStage B全体の1行で表示）。
  const runStageB = async () => {
    const beforeSel = report.list().length;
    const resSel = await runSelectionReusable(ctx, entrySessions);
    if (resSel?.stop) return resSel;
    if (report.list().slice(beforeSel).some((e) => e.status === 'fail')) {
      ctx.data.stopReason = 'fail';
      return { stop: true };
    }
    const beforeGrp = report.list().length;
    const resGrp = await runGrouping(ctx);
    if (resGrp?.stop) return resGrp;
    if (report.list().slice(beforeGrp).some((e) => e.status === 'fail')) {
      ctx.data.stopReason = 'fail';
      return { stop: true };
    }
    if (emergencySource) {
      const selected = await selectEmergencyServerSubmissions({
        sourceDir: cfg.emergencySource,
        index: emergencySource.index,
        blockNum,
        groupsDerived: ctx.data.groupsDerived,
      });
      ctx.data.emergencyServerSubmissions = selected.selectedByUid;
      ctx.data.emergencySubmissionCandidates = selected.candidates;
    }
    return { stop: false };
  };
  const stages = [
    { run: (stageCtx) => runEntriesReusable(stageCtx, entrySessions), key: 'A' },
    { run: runStageB, key: 'B' },
    { run: runResults, key: 'C' },
  ];
  let stopped = false;
  let fatal = false;
  try {
    for (let si = 0; si < stages.length; si++) {
      const stage = stages[si];
      ui.println('');
      if (si > 0) ui.println('');
      const before = report.list().length;
      const res = await stage.run(ctx);
      printStageVerdict(ui, report, ctx, stage.key, before, res);
      if (res?.stop) { stopped = true; break; }
    }
  } catch (e) {
    if (e instanceof ArchiveUnavailableError) {
      stopped = true;
      ctx.data.stopReason = 'not_ready';
      report.unverified('check.main.fatal', e, { reason: 'archive_unavailable' });
      ui.warn(ui.t('reason.archiveUnavailable'));
    } else {
      // 予期しないエラーでも到達分のまとめは必ず出す（G4: fatal は check.main.fatal で可視化・exit 3）
      fatal = true;
      report.check('check.main.fatal', 'fail', { error: e?.message || String(e) });
      ui.warn(ui.t('main.fatal', { error: conciseRpcText(e?.message || String(e), ui.t) }));
      if (process.env.DEBUG) ui.warn(e?.stack || '');
    }
  }

  report.renderSummary(ui, ctx);
  return { report, stopped, stopReason: ctx.data.stopReason ?? null, fatal, ctx };
}

// 各ステージ終了時の検証結果行（✅=一致 / ❌=問題あり / ⚠=未完了・一部のみ）。
// 上流FAILと、そのステージ実行中に記録されたWARN/SKIPも判定へ含める。
function printStageVerdict(ui, report, ctx, key, before, res) {
  const t = ui.t;
  const label = t(`verdict.label.${key}`);
  let icon;
  let text;
  const { firstFail, firstWarn, firstSkip } = stageVerdictIssues(report, key, before);
  if (firstFail) {
    icon = '❌';
    text = t('verdict.fail', { first: t(messageId(firstFail), displayParams(firstFail.params, t)) });
  } else if (res?.stop && !res?.verifiedStop) {
    // FAILなしの停止 = 正当な未完了ゲート（not_ready）。
    // verifiedStop（応募0件等: ステージ自体は検証成功のまま終端）は ✅ 表示で停止する。
    icon = '⚠';
    text = t('verdict.notReady');
  } else if (firstWarn) {
    icon = '⚠';
    text = t('verdict.warn', { first: t(messageId(firstWarn), displayParams(firstWarn.params, t)) });
  } else if (firstSkip) {
    icon = '⚠';
    text = t('verdict.skip', { first: t(messageId(firstSkip), displayParams(firstSkip.params, t)) });
  } else {
    icon = '✅';
    const passKey = key === 'B' && ctx.data?.noGame === true
      ? 'verdict.pass.BNoGame'
      : key === 'B' && ctx.data?.autoDistribute === true
        ? 'verdict.pass.BAuto'
        : `verdict.pass.${key}`;
    text = t(passKey, {
      total: report.getFact('totalEntries'),
      selected: report.getFact('totalSelected'),
      groups: report.getFact('totalGroups'),
      time: report.getFact('hashRegisteredTime'),
    });
  }
  ui.println('');
  ui.println(t('verdict.line', { icon, label, text }));
}

// G4: 通常検証 → full|partial|fail|fatal。緊急固定一式に差があれば専用状態を上書きする。
export function categorize(outcome) {
  if (outcome.fatal) return 'fatal';
  if (outcome.report.hasFail()) return 'fail';
  if (outcome.report.list().some((e) => e.reason === 'archive_unavailable')) return 'partial';
  if (outcome.stopped) return 'partial'; // FAIL 無しの正当な not-ready 停止
  return 'full';
}

export function categorizeEmergencyWrite(emergencyWritten, outcome) {
  if (!emergencyWritten) return categorize(outcome);
  return emergencyWritten.differences?.length > 0 ? 'emergency_with_differences' : 'full';
}

export const EXIT_CODE_OF = {
  full: 0,
  partial: 1,
  fail: 2,
  fatal: 3,
  emergency_with_differences: 4,
};

export function emitEmergencyDifferenceMarkers(ui, emergencyWritten) {
  if (!emergencyWritten) return 0;
  const differences = Array.isArray(emergencyWritten.differences) ? emergencyWritten.differences : [];
  for (const difference of differences) {
    ui.println(`##EMERGENCY_DIFFERENCE ${JSON.stringify(difference)}`);
  }
  return differences.length;
}

// 🔴 便 X1 / Q-B（2026-09-21・ユーザー決定 (b')）: core 外の差を見出しへ出す。
//
//   `_emergency/public-differences.json` には core 外だけの差も必ず載るが、記録を開かない限り
//   対応者の目に入らず、第三者告知の引き金が引かれなかった。ここで見出しへ出す。
//
//   🔴 終了コードは変えない。`categorizeEmergencyWrite()` も `##RESULT` も
//      `##EMERGENCY_RESULT` も `emergencyWritten.differences`（＝結果に影響する差）だけを見る。
//      core 外だけの差は従来どおり `full` / 0 のままである。
//   🔴 既存の `##EMERGENCY_DIFFERENCE` と取り違えられない別の印にする。
//      既存の印は「結果に影響する差」を意味し、終了コード4 と結びついている。
//      `run-release-gate.mjs` の `/^##EMERGENCY_DIFFERENCE\s+(.+)$/gm` にも当たらない
//      （`##EMERGENCY_NONRESULT_DIFFERENCE` は `##EMERGENCY_DIFFERENCE ` で始まらない）。
//   🔴 緊急モード限定。`emergencyWritten` が無い通常検証では1行も出ない。
//
//   1件ごとの JSON は、鍵名（`key`）・`differingFields`・公開版の sha256（`publicSha256`）・
//   採用版の sha256（`recomputedSha256`）・保全した公開版の置き場（`publicCopy`）を運ぶ。
export function emitEmergencyNonResultDifferenceMarkers(ui, emergencyWritten) {
  if (!emergencyWritten) return 0;
  const nonResult = Array.isArray(emergencyWritten.nonResultDifferences)
    ? emergencyWritten.nonResultDifferences : [];
  if (nonResult.length === 0) return 0;
  for (const difference of nonResult) {
    ui.println(`##EMERGENCY_NONRESULT_DIFFERENCE ${JSON.stringify(difference)}`);
  }
  // 機械印を読まない対応者のための1行（終了状態が 0 のままであることを明記する）。
  ui.println(
    `Emergency non-result differences: ${nonResult.length} `
    + `(${nonResult.map((difference) => difference.key).join(', ')}) `
    + '— recorded in _emergency/public-differences.json; the exit status is unchanged. '
    + 'Review each one and decide whether the incident must be disclosed.',
  );
  return nonResult.length;
}

export function emitNonInteractiveOutcome(ui, outcome, emergencyWritten) {
  for (const entry of outcome.report.list()) {
    ui.println(`##CHECK ${entry.id} ${entry.status}`);
    if (entry.comparisonStatus) ui.println(`##COMPARISON ${entry.id} ${entry.comparisonStatus} ${entry.reason}`);
  }
  const category = categorizeEmergencyWrite(emergencyWritten, outcome);
  ui.println(`##RESULT ${category}`);
  if (emergencyWritten) {
    ui.println(`##EMERGENCY_RESULT ${emergencyWritten.differences.length > 0 ? 'with_differences' : 'full'}`);
  }
  return { category, exitCode: EXIT_CODE_OF[category] };
}

// ---------------------------------------------------------------
// main
// ---------------------------------------------------------------
export async function main() {
  const argv = process.argv.slice(2);
  if (argv.includes('--help') || argv.includes('-h')) {
    process.stdout.write(USAGE + '\n');
    return;
  }

  activeRpcConfig = { rpcUrls: parseArgv(argv).rpc };
  const cfg = loadConfig(argv);
  activeRpcConfig = cfg;

  if ((cfg.emergencySource && !cfg.emergencyOut) || (!cfg.emergencySource && cfg.emergencyOut)) {
    process.stderr.write(USAGE + '\n');
    process.stderr.write('--emergency-source and --emergency-out must be provided together\n');
    process.exit(64);
  }
  if (cfg.emergencyAuthority !== null
      && (cfg.emergencyAuthority !== 'gcp' || !cfg.emergencySource)) {
    process.stderr.write('--emergency-authority requires --emergency-source and the value gcp\n');
    process.exit(64);
  }

  const applicantSelectionUsageError = emergencyApplicantSelectionUsageError(cfg);
  if (applicantSelectionUsageError) {
    process.stderr.write(USAGE + '\n');
    process.stderr.write(`${applicantSelectionUsageError}\n`);
    process.exit(64);
  }

  // T3（2026-09-18）: --source-base は取得先の差し替えなので、ローカルだけを読む2モードとは
  // 両立しない。黙ってどちらかを勝たせると「告知された場所を検証した」と誤解できるため、
  // 使い方の誤りとして止める（exit 64）。この検査は --source-base を渡したときだけ働き、
  // 既存の組み合わせ（--artifact-dir と --emergency-source の同時指定＝緊急モードが勝つ）の
  // 挙動と終了状態は変えない。
  if (cfg.sourceBase && (cfg.artifactDir || cfg.emergencySource)) {
    process.stderr.write(USAGE + '\n');
    process.stderr.write('--source-base cannot be combined with --artifact-dir or --emergency-source\n');
    process.exit(64);
  }

  // G4: usage エラー → exit 64
  //（--block が NaN/負/非整数、非対話モードでの --block 欠落）
  const flagBlock = cfg.flags?.block;
  if (flagBlock !== null && (!Number.isInteger(flagBlock) || flagBlock < 0)) {
    process.stderr.write(USAGE + '\n');
    process.stderr.write(`invalid --block value\n`);
    process.exit(64);
  }
  if (cfg.nonInteractive && cfg.blockNum == null) {
    process.stderr.write(USAGE + '\n');
    process.stderr.write('missing --block N (required in non-interactive mode)\n');
    process.exit(64);
  }

  const prompts = createPrompts({ nonInteractive: cfg.nonInteractive });

  try {
    // 1. 言語
    const lang = await selectLanguage(cfg, prompts);
    const translate = makeTranslator(lang);
    const ui = makeUi(translate, prompts, cfg);
    if (!cfg.nonInteractive && lang !== cfg.lang) saveConfig({ lang }, cfg.savedConfigPath);
    cfg.lang = lang;

    // K-S5-002: オフライン proof 生成。**RPC にも R2 にも触れずに**ここで完結させる
    //（運営が止まっている状況で使うものなので、ネットワークに依存してはならない）。
    if (cfg.flags?.proof) {
      if (cfg.blockNum == null) {
        process.stderr.write(USAGE + '\n');
        process.stderr.write('missing --block N (required with --proof)\n');
        process.exit(64);
      }
      const { runProofMode } = await import('./proof.js');
      process.exit(await runProofMode(cfg, ui, { blockNum: cfg.blockNum, key: cfg.flags.key }));
    }

    // 2. RPC（毎回選択・独自RPC追加分のみ永続化）＋ chainId 確認
    const chain = await setupChain(cfg, ui, prompts);

    // 2b. G12: 4コントラクト全てにコードがデプロイされていること（誤アドレス/誤ネットワーク検出）
    //
    // 🔴 Q-4（2026-08-08）: **Evidence だけは同梱 config ではなくチェーンから引く。**
    //    `TokenMining.evidence` は set-once（`TokenMining.evidence` / TokenMining.setEvidence）なので、
    //    運営が後から差し替えられない権威がチェーン上にある。同梱 config の値は
    //    契約再デプロイのたびに古くなる（既知の運用罠）ので、ここで固まると
    //    「設定が古いだけ」で exit 3 の fatal になってしまう。
    // Donate はタイムロック無しのイベント告知だけに使う補助契約。ローカルfixtureには
    // デプロイされないため、致命的なコード存在ゲートは中核4契約だけに課す。
    const contractEntries = Object.entries(cfg.contracts)
      .filter(([k]) => k !== 'donate')
      .map(([k, v]) => [k, v]);
    try {
      const onchainEvidence = await chain.evidenceAddress();
      const i = contractEntries.findIndex(([k]) => k === 'evidence');
      if (i >= 0 && onchainEvidence) contractEntries[i] = ['evidence (TokenMining.evidence())', onchainEvidence];
    } catch { /* 読めなければ従来どおり config の値で検査する */ }
    const codes = await Promise.all(contractEntries.map(([, addr]) => chain.getCode(addr).catch(() => null)));
    for (let i = 0; i < contractEntries.length; i++) {
      if (!codes[i] || codes[i] === '0x') {
        ui.warn(ui.t('main.contractCodeMissing', { name: contractEntries[i][0], address: contractEntries[i][1] }));
        process.exit(3); // 設定エラー＝fatal 扱い
      }
    }

    // 3-6. ブロックループ
    let worstExit = 0;
    let blockNum = cfg.blockNum;
    const entrySessions = new Map();
    for (;;) {
      let mode = 0;
      if (!cfg.nonInteractive && blockNum == null) {
        ui.section(ui.t('main.sectionMenu'));
        mode = await prompts.choice(ui.t('main.menuPrompt'), [
          ui.t('main.menuReplay'), ui.t('main.menuZkp'), ui.t('main.menuOwnEntry'),
        ], { defaultIndex: 0 });
        if (mode === 1) {
          const { runZkpMode } = await import('./zkp.js');
          worstExit = Math.max(worstExit, await runZkpMode(cfg, chain, ui, prompts));
          continue;
        }
      }
      if (mode === 2) {
        ui.section(ui.t('entry.sectionUid'));
        let uid;
        while (!uid) {
          uid = parseEntryUid(await ui.askInput('entry.uidPrompt'));
          if (!uid) ui.println(ui.t('entry.invalidUid'));
        }
        ui.section(ui.t('main.sectionBlock'));
        const number = await prompts.number(ui.t('main.blockPrompt'), { min: 0, integer: true });
        const r2 = cfg.artifactDir ? createLocalR2(cfg, ui, number, { rootDir: cfg.artifactDir }) : createR2(cfg, ui, number);
        r2.setDefaultReuse(true);
        const ctx = { cfg, chain, ui, r2, blockNum: number, report: createReport(), data: { reuseFiles: true } };
        const result = await verifyOwnEntry(ctx, uid, entrySessions);
        worstExit = Math.max(worstExit, ctx.report.hasFail() ? 2 : !result.verified || !result.complete ? 1 : 0);
        ui.section(ui.t('main.sectionNext'));
        if (!await ui.askYesNo('main.returnMenu', {}, { defaultValue: true })) break;
        continue;
      }
      if (blockNum == null) {
        ui.section(ui.t('main.sectionBlock'));
        blockNum = await prompts.number(ui.t('main.blockPrompt'), { min: 0, integer: true });
      }
      if (!Number.isInteger(blockNum) || blockNum < 0) { blockNum = null; continue; }

      const outcome = await verifyOneBlock(cfg, chain, ui, blockNum, { entrySessions: cfg.nonInteractive ? null : entrySessions });
      let emergencyWritten = null;
      if (cfg.emergencySource) {
        emergencyWritten = await writeEmergencyResultSet({
          ctx: outcome.ctx,
          source: outcome.ctx.data.emergencySource,
          outputDir: cfg.emergencyOut,
        });
        ui.println(`Emergency result set: ${emergencyWritten.outputDir}`);
        ui.println(`Emergency manifest core: ${emergencyWritten.bundleIndex.resultManifestCoreSha256}`);
        ui.println(`Emergency Merkle root: ${emergencyWritten.bundleIndex.merkleRoot}`);
        emitEmergencyDifferenceMarkers(ui, emergencyWritten);
        // 便 X1 / Q-B: 結果に影響しない差も見出しへ出す（終了コードには影響しない）。
        emitEmergencyNonResultDifferenceMarkers(ui, emergencyWritten);
      }
      const category = categorizeEmergencyWrite(emergencyWritten, outcome);
      worstExit = Math.max(worstExit, EXIT_CODE_OF[category]);

      blockNum = null; // 2周目以降は必ず入力を求める

      if (cfg.nonInteractive) {
        // G4: 機械可読出力（テストが解析する・i18n 非依存）
        const emitted = emitNonInteractiveOutcome(ui, outcome, emergencyWritten);
        process.exitCode = emitted.exitCode;
        break;
      }
      ui.section(ui.t('main.sectionNext'));
      const again = await ui.askYesNo('main.returnMenu', {}, { defaultValue: true });
      if (!again) break;
    }

    if (!cfg.nonInteractive) process.exitCode = worstExit;
    ui.println(ui.t('main.bye'));
  } finally {
    prompts.close();
  }
}

// 統合試験は Hardhat の in-process provider と同じプロセスから verifyOneBlock を呼ぶ。
// CLI として起動された時だけ main を実行し、import 時に RPC 選択や process.exit を副作用として
// 発生させない。通常の bin/`node src/index.js` の挙動は従来どおり。
let isDirectExecution = false;
if (process.argv[1]) {
  try {
    // npm/bin のsymlink経由でもCLI本体と同じ実体なら起動する。
    isDirectExecution = fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url));
  } catch { /* argv[1] が消えた特殊なimport環境では副作用を起こさない */ }
}
if (isDirectExecution) {
  main().catch((e) => {
    // 予期しない例外（stdin EOF・RPC 断など）= fatal → exit 3（G4）
    const diagnostic = process.env.DEBUG ? (e?.stack || e)
      : conciseRpcText(e?.stack || e, makeTranslator(activeRpcConfig.lang || 'en'));
    const safe = redactRpcText(diagnostic, configRpcUrls(activeRpcConfig));
    process.stderr.write(`${visibleTerminalText(safe)}\n`);
    process.exit(3);
  });
}

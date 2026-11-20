// block-verifier/src/config.js
// 設定の解決: DEFAULTS < verifier-config.json（保存済みRPC選択等） < --config FILE < CLIフラグ。
// タイミング定数（START_TIME/BLOCK_TIME/TERM1-3）はここに置かない — チェーンの getter が正
// （chain.js getTimingConstants()）。workers/.env の値をデフォルトに埋め込むことは禁止。

import fs from 'node:fs';
import path from 'node:path';

export const SAVED_CONFIG_FILE = 'verifier-config.json';

export const DEFAULTS = {
  chainIdExpected: 1,

  // 独立公開RPCプリセット（鍵不要・運営管理外）。ユーザーが選択 or カスタムURL追加。
  // llamarpc/drpc/cloudflare-eth は実機テストで接続不良のため削除（2026-07-12 ユーザーテスト）。
  rpcPresets: [
    { name: 'publicnode', url: 'https://ethereum-rpc.publicnode.com' },
  ],

  r2Base: 'https://r2.bitcoinu.org',
  dataDir: './data',

  // 契約再デプロイバッチ（2026-11-20）後の mainnet アドレス。
  // （出典: Hardhat/bitcoinu/deployment-info-TokenMining-mainnet.json / .env.local）
  contracts: {
    hashStorage: '0xc8845F3De44839765cfD4278110fcc576FC5D9D0',
    tokenMining: '0x65E28cd031a63DFeb4aCD9f921938aFb6faBFC2c',
    evidence: '0x4EaFd0Eb6EA539A58b8CDbd5b8761F731CcD01a8',
    ethLock: '0x44B0A97C560A96793B532c1157f373b27D8e73bf',
    ethStake: '0xe68D7Ae57D8DDA21c7915C47903075a9386b7269',
    donate: '0x3278206C3A6097100Dfb3B973EfEfA371609091b',
  },

  // ZKP の vkey ピン値（2026-08-04）。
  // 「本ツールが公開された時点のオンチェーン値」を焼き込んでおき、実行時の値と突き合わせる。
  // ⚠️ 一致は「差し替えられていない」ことしか言わない。**このソースからこの vkey が出るか**は
  //    再現ビルドでしか確かめられず、それは Docker + SP1 が要るので任意手順（src/zkp.js ③）。
  // 登録前の試験配備とは不一致になる。配線 FINAL の登録後にチェーン値と照合する。
  zkVkey: '0x00382340c4efdab8b43e1574f19fe2c6a1062723cc15b9f8676cca50b0394801',

  // 公開ルール定数のピン値（manifest.rules / game_selection.json との照合基準）。
  // 採点・抽選に影響するピンの逸脱は FAIL（正当な定数変更は --config の pins 上書きで明示承認する運用）。
  pins: {
    minChars: 500,
    minMessages: 20,
    chatCaps: { maxChars: 10000, maxMessages: 100, maxMsgChars: 1000 },
    maxReports: 2,
    receiptFreshWindowMs: 600000, // v3.3: 受領証明のリアルタイム窓（±10分）
    minDepositWei: '10000000000000000', // 0.01 ETH（manifest.rules.minDepositWei の照合基準）
    // K-S4-002: 1人あたりの合計上限（製品仕様）。EthLock は1口あたりしか縛らないので、
    // 「合計 10 ETH 超の応募が採点に混ざっていないか」はこのピンで検知する
    maxDepositWei: '10000000000000000000', // 10 ETH
    confirmationBlocks: 64,
    ethereumHeaderRuleVersion: 1,
    ethereumHeaderFork: 'osaka',
    clockSkewAllowMs: 120000,
    // GAME_MAX_PLAYERS（選出人数キャップ）。check-vendor-sync.mjs が
    // game-master-DO / lottery-DO の正典定数へ機械束縛する。
    gameMaxPlayers: 2100,
    // K-S2-003: 適格条件で不可視文字を除外する規則の版数
    // （char-counter.js VISIBLE_CHARS_RULE_VERSION。範囲表を変えたら双方を上げる）
    // v2（2026-08-05・P-2026-0811 #6）: 不可視文字表の取りこぼし 3,762 コードポイントを補った。
    // 🔴 2026-08-06 に**この pin だけ 1 のまま取り残されていた**のを是正した
    //    （正典は 2・simulation が check.stageC.rulesPins で全滅していた）。
    visibleCharsRule: 3,
    // 歴史的な45鍵の形を保つ。v5の採点はこの最小既読数を使わない。
    // （protocol-v2.js REPORT_MIN_READ_RECEIPTS / REPORT_ELIGIBILITY_RULE_VERSION）
    reportMinReadReceipts: 5,
    // v5（2026-10-03・S3FIX-A501-VOTE）: 標的の確定した投票より後だけ有効。
    reportEligibilityRule: 5,
    // 案B: 既読受領証明の参照バイト数（protocol-v2.js MSG_REF_BYTES）
    msgRefBytes: 16,
    // Q-S2-001: 受領証明の分量上限（protocol-v2.js）
    receiptMaxActionsPerPairBase: 10,
    receiptMaxActionsPerPair: 10,
    receiptMaxRefsPerReceipt: 100,
    // K-S6-002: 観測発信の上限と、受領証明・観測発信の受理規則の版数（protocol-v2.js）。
    // 「実在する対象をカバーしない受領証明は数えない」＋「(提出者,発信者) ペアごとの上限」。
    // 数え方を変えたら双方（正典と本pin）を更新する
    maxObservedActionsPerActor: 10,
    // v3（2026-08-05・P-2026-0805/0806/0808）: 投票・密告の正典を union へ（条件4 廃止・
    // 検証⑥(b) 廃止）／投票の対象矛盾は失格にせず正準順序の先頭1件を採用／
    // 候補収集を検証→登録の順に・切り詰めと枠消費を正準順序に・窓フィルタを追加／
    // 正典が扱う値の型検査を追加。
    // v2（2026-08-05・A-1〜A-3）: 署名は 0x+130桁hex の文字列のみ受理。
    // v4（2026-08-06・P-2026-0811）: 行動受領証明のペア枠キーに **type** を追加／
    // 受領証明の**受理時**に鮮度（±10分）を課す／`messages[].receipts` 分岐を削除／
    // chatHash 自己整合の手前に messages 要素の型ゲート／名簿の fail-closed 検査／
    // 既読受領証明の msgRefs を署名対象と同じ compareHexAsc 順に整列してから走査。
    // 詳細は docs/external-audit/STAGE3C_CANON_TIGHTENING.md
    // v6（2026-08-07・P-2026-0813）: 整列の**単位**を「提出物内」から
    // **全提出物をまとめた1本の正準順序**へ（末尾のタイブレーカは提出者 uid）。
    // v15（2026-10-01・S3FIX-Q1R）: 採点の上限選別は最早の既読時刻だけで比較し、同点は正準順。
    // v16（2026-10-03・S3FIX-E5-01 (d)）: 密告の枠は最初の数える受領証明の時刻順。
    // v17（2026-10-07・S3R4-U11-V17・未配備、v18で置換）: 各有効な提出物の会話の証拠（回の頭20とそれぞれの直前の発言）を上限より先に正典へ入れる。
    // v18（2026-10-08・S3R4-U-PRIORITY）: E の和集合と E′ の既読を先に採り、残りは最早既読順。
    receiptAcceptanceRule: 18,
    // v8（S3R4-U-PRIORITY）: E と E′ の形と独立上限。
    submissionLimitsVersion: 8,
    // P1a-i-2: EVC1 magic のまま frame version 2 と hasPriority を運ぶ。
    evidenceCompactFormat: 'bitcoinu-evidence-compact/2',
    maxDepositIds: 10,
    maxMessagesPerPlayer: 100,
    maxMessagesTotal: 500,
    maxMessageChars: 1000,
    maxMessageCharsPerPlayer: 10000,
    maxPriorityOwnMessages: 20,
    maxPriorityOtherMessages: 20,
    maxPriorityReceipts: 40,
    maxAcceptedVotesPerPlayer: 1,
    maxAcceptedReportsPerPlayer: 2,
    maxReceiptFacts: 2400,
    maxSelfAggregateTargets: 480,
    serverMaxSubmissionWireBytes: 442368,
    serverMaxSubmissionDecodedBytes: 2097152,
    evidenceMaxDataBytesExclusive: 130000,
    // K-S5-002: 請求データのオンチェーン公開フォーマット（lib/claim-data-codec.js の
    // CLAIM_DATA_FORMAT / TokenMining.MAX_CLAIM_DATA_BYTES）。宣言がこれと違えば
    // 「知らない形式を読んで通す」ことになるので FAIL させる
    // /3（2026-08-01）で **gzip をやめた**（ZKP Stage 1 の回路から DEFLATE を消すため）。
    // 並びは /2 と同一で、変わったのは圧縮の有無とマジック（BCD2→BCD3）だけ
    claimDataFormat: 'bitcoinu-claimdata/3',
    claimDataChunkBytes: 98304,
    // 請求データ自己完結化（2026-08-01・SPEC §7-3）: デポッター按分の端数規則と葉の形式。
    // manifest.rules の同名キーと**厳密**照合する（未宣言も逸脱）。
    //   depositorRounding  … 'floor-truncate' = 全員切り捨て・端数（最大 N−1 wei）は未配布
    //   depositorLeafFormat… デポッター葉はプレイヤー単位1枚:
    //                        key={N}_{gid}_lock_owners_{uid}_{setHash} / to=0x0 / amount=配分合計
    depositorRounding: 'floor-truncate',
    depositorLeafFormat: 'bitcoinu-lock-owner-leaf/3',
  },

  // K-S5-002: EthLock 台帳（src/deposit-ledger.js）の個別読取フォールバック上限。
  // ⚠️ 請求データ自己完結化（2026-08-01）以降、この台帳は**どの検査からも呼ばれていない**
  //    （葉が blob の純関数になり、木の再現に EthLock が不要になったため）。
  //    残してある理由と再利用時の注意は deposit-ledger.js 冒頭に書いてある。
  depositCallFallbackMax: 2000,
};

// ---------------------------------------------------------------
// CLI フラグ解析
//   --config FILE / --rpc URL（複数可） / --lang xx / --block N
//   --reuse / --yes / --non-interactive / --source-base URL
//   --observer-manifest PATH（見張り役の run manifest ファイル or ディレクトリ）
//   --observer-source DIR（materialize-block が書いた全保存世代。通常 Stage B の任意入力）
//   "--flag value" と "--flag=value" の両形式を受ける。
// ---------------------------------------------------------------
export function parseArgv(argv) {
  const flags = {
    rpc: [], config: null, lang: null, block: null, reuse: false, yes: false,
    nonInteractive: false, proof: false, key: null, artifactDir: null,
    emergencySource: null, emergencyOut: null, emergencyAuthority: null,
    emergencyApplicantRegistration: null, emergencyApplicantRoot: null,
    sourceBase: null,
    observerManifest: null, observerSource: null, _unknown: [],
  };
  for (let i = 0; i < argv.length; i++) {
    let arg = argv[i];
    if (!arg.startsWith('--')) { flags._unknown.push(arg); continue; }
    let value = null;
    const eq = arg.indexOf('=');
    if (eq !== -1) { value = arg.slice(eq + 1); arg = arg.slice(0, eq); }
    const next = () => {
      if (value !== null) return value;
      if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) return argv[++i];
      return null;
    };
    switch (arg) {
      case '--config': flags.config = next(); break;
      case '--rpc': { const v = next(); if (v) flags.rpc.push(v); break; }
      case '--lang': flags.lang = next(); break;
      case '--block': { const v = next(); flags.block = v == null ? null : Number(v); break; }
      case '--reuse': flags.reuse = true; break;
      case '--yes': flags.yes = true; break;
      case '--non-interactive': flags.nonInteractive = true; break;
      // K-S5-002: オフライン proof 生成（運営が止まっても自力請求できるようにする）
      case '--proof': flags.proof = true; break;
      case '--key': flags.key = next(); break;
      case '--artifact-dir': flags.artifactDir = next(); break;
      case '--emergency-source': flags.emergencySource = next(); break;
      case '--emergency-out': flags.emergencyOut = next(); break;
      case '--emergency-authority': flags.emergencyAuthority = next() ?? ''; break;
      case '--emergency-applicant-registration': {
        const v = next(); flags.emergencyApplicantRegistration = v === null ? '' : v; break;
      }
      case '--emergency-applicant-root': {
        const v = next(); flags.emergencyApplicantRoot = v === null ? '' : v; break;
      }
      // T3（2026-09-18・ユーザー決定）: 事故告知で使う「取得先だけ」の差し替え。
      // cfg.r2Base 以外（契約アドレス・chainId・pins・dataDir）には一切触れない。
      // --config を告知文に書かせないための最小の入口なので、ここで増やさない。
      case '--source-base': flags.sourceBase = next(); break;
      // 周29（2026-09-22）: 見張り役（tools/r2-backup-observer）が書いた run manifest。
      // ファイル1本でも、`*.json` を並べたディレクトリでもよい。
      // `chainSnapshots` の `readAt` が「グループ分けの時点で何が現在値だったか」の証人になる。
      // 渡さなければ該当検査は skip（黙って pass にはしない）。
      case '--observer-manifest': flags.observerManifest = next(); break;
      // R30-U-4: run manifest（観測時刻の証人）とは別の、全保存世代を持つ block archive。
      // 通常 Stage B が「現在の N では N+1 の組を再現できない」場合にだけ読む。
      case '--observer-source': flags.observerSource = next(); break;
      default: flags._unknown.push(arg);
    }
  }
  return flags;
}

function readJsonIfExists(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (e) {
    throw new Error(`config read failed: ${filePath}: ${e.message}`);
  }
}

// --config JSON / verifier-config.json から上書きを許すキー
function applyOverrides(cfg, src) {
  if (!src || typeof src !== 'object') return;
  if (Number.isFinite(src.chainIdExpected)) cfg.chainIdExpected = Number(src.chainIdExpected);
  if (typeof src.r2Base === 'string' && src.r2Base) cfg.r2Base = src.r2Base.replace(/\/+$/, '');
  if (typeof src.dataDir === 'string' && src.dataDir) cfg.dataDir = src.dataDir;
  if (Array.isArray(src.rpcUrls) && src.rpcUrls.length) cfg.rpcUrls = src.rpcUrls.slice();
  if (Array.isArray(src.customRpcs)) cfg.customRpcs = src.customRpcs.filter((u) => typeof u === 'string' && u).slice();
  if (typeof src.lang === 'string' && src.lang) cfg.lang = src.lang;
  if (src.contracts && typeof src.contracts === 'object') {
    for (const k of ['hashStorage', 'tokenMining', 'evidence', 'ethLock', 'ethStake', 'donate']) {
      if (typeof src.contracts[k] === 'string' && src.contracts[k]) cfg.contracts[k] = src.contracts[k];
    }
  }
  if (src.pins && typeof src.pins === 'object') {
    const { chatCaps, ...rest } = src.pins;
    Object.assign(cfg.pins, rest);
    if (chatCaps && typeof chatCaps === 'object') Object.assign(cfg.pins.chatCaps, chatCaps);
  }
}

// argv（既定は process.argv.slice(2)）→ 解決済み cfg
export function loadConfig(argv = process.argv.slice(2)) {
  const flags = parseArgv(argv);
  const cfg = structuredClone(DEFAULTS);

  cfg.rpcUrls = null;   // null = 未選択（メインループが毎回RPC選択を促す）
  cfg.customRpcs = [];  // ユーザーが追加した独自RPC URL（これだけ永続化・選択肢に出す）
  cfg.lang = null;

  // 1) 保存済み設定（言語・追加した独自RPCのみ。RPCの「選択」は毎回行うため rpcUrls は復元しない）
  const savedPath = path.resolve(process.cwd(), SAVED_CONFIG_FILE);
  const saved = readJsonIfExists(savedPath);
  if (saved && typeof saved === 'object') {
    if (typeof saved.lang === 'string' && saved.lang) cfg.lang = saved.lang;
    if (Array.isArray(saved.customRpcs)) cfg.customRpcs = saved.customRpcs.filter((u) => typeof u === 'string' && u).slice();
  }

  // 2) --config FILE（Hardhat/fixtureテスト用の全面上書き）
  if (flags.config) {
    const overridePath = path.resolve(process.cwd(), flags.config);
    const override = readJsonIfExists(overridePath);
    if (override == null) throw new Error(`config file not found: ${overridePath}`);
    applyOverrides(cfg, override);
  }

  // 3) CLIフラグ（最優先）
  if (flags.rpc.length) cfg.rpcUrls = flags.rpc.slice();
  if (flags.lang) cfg.lang = flags.lang;
  // --source-base は 2) の --config より後に当てるので、告知の1行が config に上書きされない。
  // 差し替えるのは取得先（r2Base）だけ。末尾スラッシュの有無は吸収する。
  cfg.sourceBase = null;
  if (typeof flags.sourceBase === 'string' && flags.sourceBase) {
    cfg.sourceBase = flags.sourceBase.replace(/\/+$/, '');
    cfg.r2Base = cfg.sourceBase;
  }

  cfg.blockNum = Number.isFinite(flags.block) ? flags.block : null;
  cfg.reuse = flags.reuse;
  cfg.yes = flags.yes;
  cfg.nonInteractive = flags.nonInteractive || flags.yes; // --yes は非対話としても扱う
  cfg.artifactDir = flags.artifactDir ? path.resolve(process.cwd(), flags.artifactDir) : null;
  cfg.emergencySource = flags.emergencySource ? path.resolve(process.cwd(), flags.emergencySource) : null;
  cfg.emergencyOut = flags.emergencyOut ? path.resolve(process.cwd(), flags.emergencyOut) : null;
  cfg.emergencyAuthority = flags.emergencyAuthority;
  cfg.emergencyApplicantRegistration = flags.emergencyApplicantRegistration;
  cfg.emergencyApplicantRoot = flags.emergencyApplicantRoot;
  cfg.observerManifest = flags.observerManifest
    ? path.resolve(process.cwd(), flags.observerManifest) : null;
  cfg.observerSource = flags.observerSource
    ? path.resolve(process.cwd(), flags.observerSource) : null;
  cfg.savedConfigPath = savedPath;
  cfg.flags = flags;
  return cfg;
}

// 応募者登録の選択は緊急復旧入力にだけ意味がある。履歴への所属・適格時刻・
// 保存世代からの再現可否は emergency.js がチェーンと保管庫を読んで検査する。
export function emergencyApplicantSelectionUsageError(cfg) {
  const hasIndex = cfg.emergencyApplicantRegistration !== null;
  const hasRoot = cfg.emergencyApplicantRoot !== null;
  if (hasIndex && hasRoot) {
    return '--emergency-applicant-registration and --emergency-applicant-root cannot be used together';
  }
  if ((hasIndex || hasRoot) && !cfg.emergencySource) {
    return '--emergency-applicant-registration/--emergency-applicant-root requires --emergency-source';
  }
  if (hasIndex && !/^(?:0|[1-9]\d*)$/.test(String(cfg.emergencyApplicantRegistration))) {
    return '--emergency-applicant-registration must be a non-negative integer';
  }
  if (hasRoot && !/^0x[0-9a-fA-F]{64}$/.test(String(cfg.emergencyApplicantRoot))) {
    return '--emergency-applicant-root must be a 0x-prefixed 32-byte hash';
  }
  return null;
}

// RPC未選択時のフォールバック（非対話モード等）: プリセット全部で fallback 構成
export function resolveRpcUrls(cfg) {
  if (Array.isArray(cfg.rpcUrls) && cfg.rpcUrls.length) return cfg.rpcUrls;
  return cfg.rpcPresets.map((p) => p.url);
}

// 言語・追加した独自RPCのみ verifier-config.json に永続化する。
// RPCの「選択」は毎回行う仕様のため rpcUrls は保存しない（旧バージョンが書いた rpcUrls キーも破棄）。
export function saveConfig(partial, filePath = null) {
  const target = filePath || path.resolve(process.cwd(), SAVED_CONFIG_FILE);
  const current = readJsonIfExists(target) || {};
  const next = {};
  const lang = (typeof partial?.lang === 'string' && partial.lang) ? partial.lang : current.lang;
  if (typeof lang === 'string' && lang) next.lang = lang;
  const customRpcs = Array.isArray(partial?.customRpcs) ? partial.customRpcs : current.customRpcs;
  if (Array.isArray(customRpcs)) {
    const cleaned = customRpcs.filter((u) => typeof u === 'string' && u);
    if (cleaned.length) next.customRpcs = cleaned;
  }
  fs.writeFileSync(target, JSON.stringify(next, null, 2) + '\n', 'utf8');
  return target;
}
